/*
 * PROJECT : VIREO
 * FILE    : config.c
 * AUTHOR  : bitofux
 * DATE    : 2026-09-25
 * BRIEF   : 此模块负责：
 * -- 实现默认配置和配置对象验证
 * -- 解析有界配置文字并应用显式环境覆盖
 * -- 加载配置文件，处理错误诊断和文件资源清理
 * -- 成功时提交完整配置，失败时保持主要输出
 *
 * IMPLEMENTATION :
 * -- 配置候选对象与调用者输出分离，全部检查成功后才提交
 * -- 字符串复制到配置对象自身的有界数组，不保存输入指针
 * -- 数字转换和单位换算执行严格语法、溢出及字段范围检查
 * -- 环境覆盖由调用者显式提供，不读取或修改进程环境
 * -- 文件加载保存底层错误原因，并在返回前恢复调用前的 errno
 * -- 不依赖日志模块，不打印诊断，不创建配置所描述的运行时资源
 */

#include <vireo/base/config.h>

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <vireo/base/checked.h>
#include <vireo/base/result.h>

/**
 * @brief 将配置错误对象恢复为无错误状态
 *
 * issue、source 和 field 设置为各自的 NONE；
 * line、entry_index 和 system_errno 设置为 0。
 *
 * @param[out] out_error
 *     要清空的诊断对象；允许为 NULL。
 *     非 NULL 时，必须指向生命周期内的可写对象，
 *     调用者保留该对象的所有权。
 *
 * @note 输出规则：out_error 非 NULL 时覆盖全部诊断成员，
 *       不保留上一次调用的错误信息；
 *       out_error 为 NULL 时不执行任何操作。
 * @note 所有权：不接管对象，不分配或释放内存。
 * @note 生命周期：只在调用期间借用 out_error，不保存指针。
 * @note 线程安全：不使用共享可变状态；
 *       对同一诊断对象的访问需要调用者同步。
 * @note errno：不读取、不保存且不修改 errno。
 * @note 范围边界：不验证配置或其他参数，
 *       不表示外层操作已经成功，不承诺结构体填充字节的值；
 *       只供当前源文件内部使用。
 */
static void vireo_config_error_clear(vireo_config_error_t *out_error) {
    if (out_error == NULL) {
        return;
    }

    out_error->issue = VIREO_CONFIG_ISSUE_NONE;
    out_error->source = VIREO_CONFIG_SOURCE_NONE;
    out_error->field = VIREO_CONFIG_FIELD_NONE;
    out_error->line = 0U;
    out_error->entry_index = 0U;
    out_error->system_errno = 0;
}

/**
 * @brief 将一份完整错误诊断写入配置错误对象
 *
 * 覆盖全部诊断成员，避免保留此前错误的位置或系统错误值。
 * 诊断内容是否与实际失败一致，由调用者保证。
 *
 * @param[out] out_error
 *     要写入的诊断对象；允许为 NULL。
 *     非 NULL 时，必须指向生命周期内的可写对象，
 *     调用者保留该对象的所有权。
 *
 * @param[in] issue
 *     已定义且非 NONE 的具体错误类别。
 *
 * @param[in] source
 *     已定义的错误来源；
 *     无法归属来源的调用参数错误允许使用 NONE。
 *
 * @param[in] field
 *     已定义的相关字段；
 *     无法识别或不涉及具体字段时使用 NONE。
 *
 * @param[in] line
 *     配置文字行号，从 1 开始；
 *     不适用或无法定位时传入 0。
 *
 * @param[in] entry_index
 *     环境覆盖列表中的位置，从 1 开始；
 *     不适用或无法定位时传入 0。
 *
 * @param[in] system_errno
 *     调用者已经保存的文件操作错误值；
 *     非文件操作错误或没有可用系统错误值时传入 0。
 *
 * @note 前置条件：调用者保证各诊断参数的含义相互一致；
 *       本函数不验证枚举值、来源与位置之间的关系。
 * @note 输出规则：out_error 非 NULL 时覆盖全部诊断成员；
 *       out_error 为 NULL 时不执行任何操作。
 * @note 所有权：不接管对象，不分配或释放内存。
 * @note 生命周期：只在调用期间借用 out_error，不保存指针。
 * @note 线程安全：不使用共享可变状态；
 *       对同一诊断对象的访问需要调用者同步。
 * @note errno：不读取、不保存且不修改 errno；
 *       system_errno 是按值传入的普通整数。
 * @note 范围边界：不发现错误，不选择公共函数返回码，
 *       不决定错误优先级，也不自动保留已有诊断；
 *       只供当前源文件内部使用。
 */
static void vireo_config_error_set(vireo_config_error_t *out_error, vireo_config_issue_t issue,
                                   vireo_config_source_t source, vireo_config_field_t field,
                                   size_t line, size_t entry_index, int system_errno) {
    if (out_error == NULL) {
        return;
    }

    out_error->issue = issue;
    out_error->source = source;
    out_error->field = field;
    out_error->line = line;
    out_error->entry_index = entry_index;
    out_error->system_errno = system_errno;
}

/**
 * @brief 判断一个字符是否为配置语法允许裁剪的水平空白
 *
 * 只接受 ASCII 空格和水平制表符，
 * 不把换行、回车或其他控制字符视为可裁剪空白。
 *
 * @param[in] character
 *     要检查的单个字符，按值传入。
 *
 * @retval true
 *     character 是空格或水平制表符。
 *
 * @retval false
 *     character 是其他字符。
 *
 * @note 副作用：不修改任何调用者对象，不分配或释放内存。
 * @note 生命周期：参数按值传递，不借用或保存指针。
 * @note 线程安全：不访问共享可变状态，可以并发调用。
 * @note errno：不读取、不保存且不修改 errno。
 * @note 范围边界：不裁剪字符串，不识别行边界，
 *       不判断该字符在当前字段中是否合法；
 *       只供当前源文件内部使用。
 */
static bool vireo_config_is_horizontal_space(char character) {
    return character == ' ' || character == '\t';
}

/**
 * @brief 裁剪输入片段两端的水平空白，返回调整后的下标
 *
 * 输入片段使用半开区间 [*begin, *end) 表示。
 * 只跳过两端的空格和水平制表符，不修改原始输入，
 * 不删除片段内部的字符，也不写入 NUL 终止符。
 *
 * @param[in] text
 *     下标所相对的只读输入区域；
 *     非空片段必须位于有效的可读区域内。
 *     text 为 NULL 时，*begin 和 *end 必须均为 0。
 *
 * @param[in,out] begin
 *     非空、可读写的起始下标指针；
 *     调用前满足 *begin <= *end。
 *     返回时指向裁剪后片段的第一个字符位置。
 *
 * @param[in,out] end
 *     非空、可读写的尾后下标指针；
 *     返回时表示裁剪后片段的尾后位置。
 *     全为空白或原本为空时，返回的 *begin == *end。
 *
 * @note 前置条件：调用者保证输入范围有效；
 *       begin 和 end 必须指向两个互不重叠的 size_t 对象，
 *       且不得与 text 指向的输入存储重叠。
 * @note 输出规则：只修改两个下标对象，不修改 text；
 *       全为空白时，两个下标均等于调用前的 *end。
 * @note 所有权：不接管输入或下标对象，不分配或释放内存。
 * @note 生命周期：只在调用期间借用参数，不保存指针。
 * @note 线程安全：不使用共享可变状态；
 *       输入在调用期间不得被修改，下标对象需要独占访问。
 * @note errno：不读取、不保存且不修改 errno。
 * @note 范围边界：不验证参数或实际缓冲区容量，
 *       不识别行边界，不判断裁剪后的键或值是否合法；
 *       只供当前源文件内部使用。
 */
static void vireo_config_trim_horizontal_space(char const *text, size_t *begin, size_t *end) {
    size_t first = *begin;
    size_t last = *end;

    while (first < last && vireo_config_is_horizontal_space(text[first])) {
        ++first;
    }

    while (first < last && vireo_config_is_horizontal_space(text[last - 1U])) {
        --last;
    }

    *begin = first;
    *end = last;
}

/**
 * @brief 判断输入片段是否与固定字符串完全相同
 *
 * 比较区分大小写，要求长度和每个字符均相同。
 * 输入片段不要求 NUL 终止；
 * literal 必须是有效的 NUL 终止字符串。
 *
 * @param[in] text
 *     只读输入片段；
 *     text_size 为 0 时允许为 NULL，
 *     否则必须指向至少 text_size 个可读字节。
 *
 * @param[in] text_size
 *     输入片段的字节数，不包含片段之外的任何终止符。
 *
 * @param[in] literal
 *     非空指针，指向有效的只读 NUL 终止字符串；
 *     允许指向空字符串。
 *
 * @retval true
 *     片段长度与 literal 的内容长度相同，
 *     且对应字符全部相同。
 *
 * @retval false
 *     长度不同，或者存在不同的字符。
 *
 * @note 前置条件：调用者保证输入区域和 literal 有效；
 *       本函数不执行参数有效性检查。
 * @note 输出保持：不修改输入片段或固定字符串。
 * @note 所有权：不接管任何存储，不分配或释放内存。
 * @note 生命周期：只在调用期间借用指针，不保存指针。
 * @note 线程安全：不使用共享可变状态；
 *       输入在调用期间不得被其他线程修改。
 * @note errno：不读取、不保存且不修改 errno。
 * @note 范围边界：不裁剪空白，不转换大小写，
 *       不判断字段是否受支持，也不写入错误诊断；
 *       只供当前源文件内部使用。
 */
static bool vireo_config_span_equals_literal(char const *text, size_t text_size,
                                             char const *literal) {
    for (size_t index = 0; index < text_size; ++index) {
        if (literal[index] == '\0' || text[index] != literal[index]) {
            return false;
        }
    }

    return literal[text_size] == '\0';
}

/**
 * @brief 在有界字符区域内查找 NUL，并返回其前面的字节数
 *
 * 只检查 text[0, capacity) 范围。
 * 找到第一个 NUL 时，将它的下标写入 out_length；
 * 范围内没有 NUL 时返回 false，并保持 out_length 原值。
 *
 * @param[in] text
 *     只读字符区域；
 *     capacity 非零时，必须指向至少 capacity 个可读字节。
 *     capacity 为 0 时允许为 NULL。
 *
 * @param[in] capacity
 *     允许检查的区域字节数，包含可能的 NUL 终止符位置；
 *     不是字符串内容的最大长度。
 *
 * @param[out] out_length
 *     非空、可写的长度输出指针；
 *     成功时接收第一个 NUL 之前的字节数，不包含 NUL。
 *     输出对象不得与输入区域重叠。
 *
 * @retval true
 *     在指定范围内找到 NUL，已提交字符串长度。
 *
 * @retval false
 *     指定范围内没有 NUL，或者 capacity 为 0；
 *     out_length 保持原值。
 *
 * @note 前置条件：调用者保证输入区域和输出对象有效；
 *       本函数不检查非空指针的真实有效性或实际分配容量。
 * @note 输出保持：不修改输入区域；
 *       只有成功时才写入 out_length。
 * @note 所有权：不接管任何对象，不分配或释放内存。
 * @note 生命周期：只在调用期间借用指针，不保存指针。
 * @note 线程安全：不使用共享可变状态；
 *       输入在调用期间不得被修改，输出对象需要独占访问。
 * @note errno：不读取、不保存且不修改 errno。
 * @note 范围边界：不检查 UTF-8、路径内容或字段范围，
 *       不裁剪空白，不写入错误诊断；
 *       只供当前源文件内部使用。
 */
static bool vireo_config_bounded_string_length(char const *text, size_t capacity,
                                               size_t *out_length) {
    for (size_t index = 0; index < capacity; ++index) {
        if (text[index] == '\0') {
            *out_length = index;
            return true;
        }
    }

    return false;
}

/**
 * @brief 将完整的无符号十进制数字片段解析为 uint64_t
 *
 * 输入必须包含至少一个 ASCII 十进制数字。
 * 允许前导零，始终按十进制解释；
 * 拒绝正负号、空白、小数点、单位和其他非数字内容。
 *
 * @param[in] text
 *     只读输入片段，不要求 NUL 终止；
 *     text_size 为 0 时允许为 NULL，
 *     否则必须指向至少 text_size 个可读字节。
 *
 * @param[in] text_size
 *     输入片段的字节数；
 *     本函数不执行配置值总长度上限检查。
 *
 * @param[out] out_value
 *     非空、可写的数值输出指针；
 *     输出对象不得与输入区域重叠。
 *
 * @retval VIREO_OK
 *     整个片段均为十进制数字，数值可以由 uint64_t 表示，
 *     已将完整结果写入 out_value。
 *
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     输入片段为空，或者在处理过程中遇到非数字字符。
 *
 * @retval VIREO_RESULT_OVERFLOW
 *     十进制累积过程中，乘法或加法结果无法由 uint64_t 表示。
 *
 * @note 前置条件：调用者保证输入区域和输出对象有效；
 *       本函数不检查非空指针的真实有效性。
 * @note 输出保持：不修改输入；任何失败均保持 out_value 原值。
 * @note 所有权：不接管任何对象，不分配或释放内存。
 * @note 生命周期：只在调用期间借用参数，不保存指针。
 * @note 线程安全：不使用共享可变状态；
 *       输入在调用期间不得被修改，输出对象需要独占访问。
 * @note errno：不读取、不保存且不修改 errno。
 * @note 范围边界：不裁剪空白，不处理单位，
 *       不检查端口、线程数等字段范围，不写入错误诊断。
 *       按输入顺序处理，遇错立即返回；
 *       不承诺多个错误同时存在时的完整诊断优先级。
 *       只供当前源文件内部使用。
 */
static vireo_result_t vireo_config_parse_u64_decimal(char const *text, size_t text_size,
                                                     uint64_t *out_value) {
    if (text_size == 0U) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }

    uint64_t value = UINT64_C(0);

    for (size_t index = 0; index < text_size; ++index) {
        char const character = text[index];

        if (character < '0' || character > '9') {
            return VIREO_RESULT_INVALID_ARGUMENT;
        }

        uint64_t const digit = (uint64_t)(character - '0');

        uint64_t multiplied;
        vireo_result_t result = vireo_checked_u64_mul(value, UINT64_C(10), &multiplied);
        if (result != VIREO_OK) {
            return result;
        }

        uint64_t next_value;
        result = vireo_checked_u64_add(multiplied, digit, &next_value);
        if (result != VIREO_OK) {
            return result;
        }

        value = next_value;
    }

    *out_value = value;

    return VIREO_OK;
}

/**
 * @brief 将完整的布尔值片段解析为 bool
 *
 * 只接受精确的小写 true 或 false。
 * 输入片段不要求 NUL 终止，不裁剪任何空白。
 *
 * @param[in] text
 *     只读输入片段；
 *     text_size 为 0 时允许为 NULL，
 *     否则必须指向至少 text_size 个可读字节。
 *
 * @param[in] text_size
 *     输入片段的字节数，不包含片段之外的终止符。
 *
 * @param[out] out_value
 *     非空、可写的布尔值输出指针；
 *     输出对象不得与输入区域重叠。
 *
 * @retval VIREO_OK
 *     输入恰好为 true 或 false，已提交对应的布尔值。
 *
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     输入为空，或者不与 true、false 中的任意一个完全相同。
 *
 * @note 前置条件：调用者保证输入区域和输出对象有效；
 *       本函数不执行指针有效性检查。
 * @note 输出保持：不修改输入；
 *       只有成功时才写入 out_value，失败时保持其原值。
 * @note 所有权：不接管任何对象，不分配或释放内存。
 * @note 生命周期：只在调用期间借用参数，不保存指针。
 * @note 线程安全：不使用共享可变状态；
 *       输入在调用期间不得被修改，输出对象需要独占访问。
 * @note errno：不读取、不保存且不修改 errno。
 * @note 范围边界：不裁剪空白，不转换大小写，
 *       不接受数字或其他布尔值别名，
 *       不识别配置字段，不写入错误诊断；
 *       只供当前源文件内部使用。
 */
static vireo_result_t vireo_config_parse_boolean(char const *text, size_t text_size,
                                                 bool *out_value) {
    if (vireo_config_span_equals_literal(text, text_size, "true")) {
        *out_value = true;
        return VIREO_OK;
    }

    if (vireo_config_span_equals_literal(text, text_size, "false")) {
        *out_value = false;
        return VIREO_OK;
    }

    return VIREO_RESULT_INVALID_ARGUMENT;
}

/**
 * @brief 将带可选大小单位的十进制片段解析为字节数
 *
 * 输入必须以一个或多个 ASCII 十进制数字开始，
 * 后面允许紧接 B、KiB、MiB 或 GiB；
 * 没有后缀时按字节解释。
 * 允许前导零，单位区分大小写，数字与单位之间不得有空白。
 *
 * @param[in] text
 *     只读输入片段，不要求 NUL 终止；
 *     text_size 为 0 时允许为 NULL，
 *     否则必须指向至少 text_size 个可读字节。
 *
 * @param[in] text_size
 *     输入片段的字节数；
 *     本函数不执行配置值总长度上限检查。
 *
 * @param[out] out_bytes
 *     非空、可写的字节数输出指针；
 *     输出对象不得与输入区域重叠。
 *
 * @retval VIREO_OK
 *     数字和单位语法合法，换算结果可以由 uint64_t 表示，
 *     已将字节数写入 out_bytes。
 *
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     输入为空、缺少起始数字，
 *     或数字之后的内容不是允许的完整单位后缀。
 *
 * @retval VIREO_RESULT_OVERFLOW
 *     十进制数字累积或单位换算结果超出 uint64_t 范围。
 *
 * @note 前置条件：调用者保证输入区域和输出对象有效；
 *       本函数不执行指针有效性检查。
 * @note 输出保持：不修改输入；
 *       只有成功时才写入 out_bytes，失败时保持其原值。
 * @note 所有权：不接管任何对象，不分配或释放内存。
 * @note 生命周期：只在调用期间借用参数，不保存指针。
 * @note 线程安全：不使用共享可变状态；
 *       输入在调用期间不得被修改，输出对象需要独占访问。
 * @note errno：不读取、不保存且不修改 errno。
 * @note 范围边界：不裁剪空白，不接受小数、正负号或其他单位，
 *       不检查具体配置字段的允许范围，不写入错误诊断；
 *       不承诺多个错误同时存在时的完整诊断优先级；
 *       只供当前源文件内部使用。
 */
static vireo_result_t vireo_config_parse_size_bytes(char const *text, size_t text_size,
                                                    uint64_t *out_bytes) {
    size_t digit_count = 0U;

    while (digit_count < text_size && text[digit_count] >= '0' && text[digit_count] <= '9') {
        ++digit_count;
    }

    if (digit_count == 0U) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }

    char const *suffix = text + digit_count;
    size_t const suffix_size = text_size - digit_count;

    uint64_t multiplier;

    if (suffix_size == 0U || vireo_config_span_equals_literal(suffix, suffix_size, "B")) {
        multiplier = UINT64_C(1);
    } else if (vireo_config_span_equals_literal(suffix, suffix_size, "KiB")) {
        multiplier = UINT64_C(1024);
    } else if (vireo_config_span_equals_literal(suffix, suffix_size, "MiB")) {
        multiplier = UINT64_C(1048576);
    } else if (vireo_config_span_equals_literal(suffix, suffix_size, "GiB")) {
        multiplier = UINT64_C(1073741824);
    } else {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }

    uint64_t value;
    vireo_result_t result = vireo_config_parse_u64_decimal(text, digit_count, &value);
    if (result != VIREO_OK) {
        return result;
    }

    uint64_t bytes;
    result = vireo_checked_u64_mul(value, multiplier, &bytes);
    if (result != VIREO_OK) {
        return result;
    }

    *out_bytes = bytes;

    return VIREO_OK;
}

/**
 * @brief 将带可选时长单位的十进制片段解析为毫秒数
 *
 * 输入必须以一个或多个 ASCII 十进制数字开始，
 * 后面允许紧接 ms、s 或 m；
 * 没有后缀时按毫秒解释。
 * 允许前导零，单位区分大小写，数字与单位之间不得有空白。
 *
 * @param[in] text
 *     只读输入片段，不要求 NUL 终止；
 *     text_size 为 0 时允许为 NULL，
 *     否则必须指向至少 text_size 个可读字节。
 *
 * @param[in] text_size
 *     输入片段的字节数；
 *     本函数不执行配置值总长度上限检查。
 *
 * @param[out] out_milliseconds
 *     非空、可写的毫秒数输出指针；
 *     输出对象不得与输入区域重叠。
 *
 * @retval VIREO_OK
 *     数字和单位语法合法，换算结果可以由 uint64_t 表示，
 *     已将毫秒数写入 out_milliseconds。
 *
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     输入为空、缺少起始数字，
 *     或数字之后的内容不是允许的完整单位后缀。
 *
 * @retval VIREO_RESULT_OVERFLOW
 *     十进制数字累积或单位换算结果超出 uint64_t 范围。
 *
 * @note 前置条件：调用者保证输入区域和输出对象有效；
 *       本函数不执行指针有效性检查。
 * @note 输出保持：不修改输入；
 *       只有成功时才写入 out_milliseconds，失败时保持其原值。
 * @note 所有权：不接管任何对象，不分配或释放内存。
 * @note 生命周期：只在调用期间借用参数，不保存指针。
 * @note 线程安全：不使用共享可变状态；
 *       输入在调用期间不得被修改，输出对象需要独占访问。
 * @note errno：不读取、不保存且不修改 errno。
 * @note 范围边界：不裁剪空白，不接受小数、正负号或其他单位，
 *       不检查具体配置字段的允许范围，不写入错误诊断，
 *       不读取时钟，不创建或操作计时器；
 *       不承诺多个错误同时存在时的完整诊断优先级；
 *       只供当前源文件内部使用。
 */
static vireo_result_t vireo_config_parse_duration_ms(char const *text, size_t text_size,
                                                     uint64_t *out_milliseconds) {
    size_t digit_count = 0U;

    while (digit_count < text_size && text[digit_count] >= '0' && text[digit_count] <= '9') {
        ++digit_count;
    }

    if (digit_count == 0U) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }

    char const *suffix = text + digit_count;
    size_t const suffix_size = text_size - digit_count;

    uint64_t multiplier;

    if (suffix_size == 0U || vireo_config_span_equals_literal(suffix, suffix_size, "ms")) {
        multiplier = UINT64_C(1);
    } else if (vireo_config_span_equals_literal(suffix, suffix_size, "s")) {
        multiplier = UINT64_C(1000);
    } else if (vireo_config_span_equals_literal(suffix, suffix_size, "m")) {
        multiplier = UINT64_C(60000);
    } else {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }

    uint64_t value;
    vireo_result_t result = vireo_config_parse_u64_decimal(text, digit_count, &value);
    if (result != VIREO_OK) {
        return result;
    }

    uint64_t milliseconds;
    result = vireo_checked_u64_mul(value, multiplier, &milliseconds);
    if (result != VIREO_OK) {
        return result;
    }

    *out_milliseconds = milliseconds;

    return VIREO_OK;
}

/**
 * @brief 检查输入片段是否为本模块允许的数字 IPv4 地址
 *
 * 地址必须由四段十进制数字组成，段之间使用 '.' 分隔。
 * 每段包含一到三个数字，数值必须位于 0..255；
 * 除单独的 0 外，不允许前导零。
 * 输入片段必须恰好包含完整地址，不接受其他前后缀。
 *
 * @param[in] text
 *     只读输入片段，不要求 NUL 终止；
 *     text_size 为 0 时允许为 NULL，
 *     否则必须指向至少 text_size 个可读字节。
 *
 * @param[in] text_size
 *     输入片段的字节数，不包含片段之外的终止符。
 *
 * @retval true
 *     整个片段符合上述数字 IPv4 格式。
 *
 * @retval false
 *     输入为空，段数、分隔符、数字格式或数值范围不符合要求，
 *     或者完整地址之后仍有其他内容。
 *
 * @note 前置条件：调用者保证输入区域有效；
 *       本函数不执行指针有效性检查。
 * @note 输出保持：不修改输入区域。
 * @note 所有权：不接管输入，不分配或释放内存。
 * @note 生命周期：只在调用期间借用 text，不保存指针。
 * @note 线程安全：不使用共享可变状态；
 *       输入在调用期间不得被其他线程修改。
 * @note errno：不读取、不保存且不修改 errno。
 * @note 范围边界：不裁剪空白，不解析主机名、IPv6 或端口，
 *       不输出二进制地址，不检查地址是否属于本机、
 *       是否适合实际监听或是否可达，不执行网络操作，
 *       不写入错误诊断；只供当前源文件内部使用。
 */
static bool vireo_config_ipv4_is_valid(char const *text, size_t text_size) {
    size_t offset = 0U;

    for (size_t part = 0U; part < 4U; ++part) {
        size_t const begin = offset;
        size_t digit_count = 0U;
        uint32_t value = UINT32_C(0);

        while (offset < text_size && text[offset] >= '0' && text[offset] <= '9') {
            if (digit_count == 3U) {
                return false;
            }

            uint32_t const digit = (uint32_t)(text[offset] - '0');

            value = value * UINT32_C(10) + digit;

            ++digit_count;
            ++offset;
        }

        if (digit_count == 0U) {
            return false;
        }

        if (digit_count > 1U && text[begin] == '0') {
            return false;
        }

        if (value > UINT32_C(255)) {
            return false;
        }

        if (part < 3U) {
            if (offset == text_size || text[offset] != '.') {
                return false;
            }

            ++offset;
        }
    }

    return offset == text_size;
}

/**
 * @brief 检查路径片段是否满足配置路径的基本内容约束
 *
 * 路径必须非空，且首字节为 '/'。
 * 内容不得包含 ASCII 控制字节 0x00..0x1F 或 DEL（0x7F）。
 * 输入片段不要求 NUL 终止。
 *
 * @param[in] text
 *     只读路径片段；
 *     text_size 为 0 时允许为 NULL，
 *     否则必须指向至少 text_size 个可读字节。
 *
 * @param[in] text_size
 *     路径内容的字节数，不包含片段之外的终止符。
 *
 * @retval true
 *     路径非空、以 '/' 开头，
 *     且内容不含上述禁止的字节。
 *
 * @retval false
 *     路径为空、不以 '/' 开头，
 *     或包含上述禁止的字节。
 *
 * @note 前置条件：调用者保证输入区域有效；
 *       本函数不执行指针有效性检查。
 * @note 输出保持：不修改输入区域。
 * @note 所有权：不接管输入，不分配或释放内存。
 * @note 生命周期：只在调用期间借用 text，不保存指针。
 * @note 线程安全：不使用共享可变状态；
 *       输入在调用期间不得被其他线程修改。
 * @note errno：不读取、不保存且不修改 errno。
 * @note 范围边界：不检查配置路径长度上限，不裁剪空白，
 *       不验证 UTF-8，不展开变量或波浪号，
 *       不执行路径规范化、符号链接解析或文件系统访问，
 *       不证明路径存在、可访问、指向目录或位于安全根目录，
 *       不写入错误诊断；只供当前源文件内部使用。
 */
static bool vireo_config_path_is_valid(char const *text, size_t text_size) {
    if (text_size == 0U) {
        return false;
    }

    if (text[0] != '/') {
        return false;
    }

    for (size_t index = 0U; index < text_size; ++index) {
        unsigned char const byte = (unsigned char)text[index];

        if (byte <= 0x1FU || byte == 0x7FU) {
            return false;
        }
    }

    return true;
}

/**
 * @brief 根据配置文字中的完整键名查找对应字段
 *
 * 仅识别本模块支持的九个配置键名。
 * 比较区分大小写，要求片段与键名完整相同；
 * 不裁剪空白，不接受环境变量名称或其他别名。
 *
 * @param[in] text
 *     只读键名片段，不要求 NUL 终止；
 *     text_size 为 0 时允许为 NULL，
 *     否则必须指向至少 text_size 个可读字节。
 *
 * @param[in] text_size
 *     键名片段的字节数，不包含片段之外的终止符。
 *
 * @return
 *     识别成功时返回对应的非 NONE 字段枚举；
 *     空片段或未识别的键名返回 VIREO_CONFIG_FIELD_NONE。
 *
 * @retval VIREO_CONFIG_FIELD_NONE
 *     输入为空，或者不是受支持的完整配置键名。
 *
 * @note 前置条件：调用者保证输入区域有效；
 *       本函数不执行指针有效性检查。
 * @note 输出保持：不修改输入区域或任何配置对象。
 * @note 所有权：不接管输入，不分配或释放内存。
 * @note 生命周期：只在调用期间借用 text，不保存指针。
 * @note 线程安全：不使用共享可变状态；
 *       输入在调用期间不得被其他线程修改。
 * @note errno：不读取、不保存且不修改 errno。
 * @note 范围边界：不查找 '='，不裁剪空白，不解析字段值，
 *       不检查重复键，不识别环境变量名称，
 *       不区分空键与未知键的外层错误诊断；
 *       只供当前源文件内部使用。
 */
static vireo_config_field_t vireo_config_field_from_key(char const *text, size_t text_size) {
    if (vireo_config_span_equals_literal(text, text_size, "listen_address")) {
        return VIREO_CONFIG_FIELD_LISTEN_ADDRESS;
    }

    if (vireo_config_span_equals_literal(text, text_size, "listen_port")) {
        return VIREO_CONFIG_FIELD_LISTEN_PORT;
    }

    if (vireo_config_span_equals_literal(text, text_size, "max_connections")) {
        return VIREO_CONFIG_FIELD_MAX_CONNECTIONS;
    }

    if (vireo_config_span_equals_literal(text, text_size, "worker_count")) {
        return VIREO_CONFIG_FIELD_WORKER_COUNT;
    }

    if (vireo_config_span_equals_literal(text, text_size, "idle_timeout")) {
        return VIREO_CONFIG_FIELD_IDLE_TIMEOUT;
    }

    if (vireo_config_span_equals_literal(text, text_size, "log_to_stderr")) {
        return VIREO_CONFIG_FIELD_LOG_TO_STDERR;
    }

    if (vireo_config_span_equals_literal(text, text_size, "log_max_file_size")) {
        return VIREO_CONFIG_FIELD_LOG_MAX_FILE_SIZE;
    }

    if (vireo_config_span_equals_literal(text, text_size, "data_dir")) {
        return VIREO_CONFIG_FIELD_DATA_DIR;
    }

    if (vireo_config_span_equals_literal(text, text_size, "log_dir")) {
        return VIREO_CONFIG_FIELD_LOG_DIR;
    }

    return VIREO_CONFIG_FIELD_NONE;
}

/**
 * @brief 根据完整的环境覆盖名称查找对应配置字段
 *
 * 仅识别本模块支持的九个环境覆盖名称。
 * 比较区分大小写，要求片段与名称完整相同；
 * 不裁剪空白，不接受配置文字键名或其他别名。
 *
 * @param[in] text
 *     只读环境名称片段，不要求 NUL 终止；
 *     text_size 为 0 时允许为 NULL，
 *     否则必须指向至少 text_size 个可读字节。
 *
 * @param[in] text_size
 *     环境名称片段的字节数，不包含片段之外的终止符。
 *
 * @return
 *     识别成功时返回对应的非 NONE 字段枚举；
 *     空片段或未识别的名称返回 VIREO_CONFIG_FIELD_NONE。
 *
 * @retval VIREO_CONFIG_FIELD_NONE
 *     输入为空，或者不是受支持的完整环境覆盖名称。
 *
 * @note 前置条件：调用者保证输入区域有效；
 *       本函数不执行指针有效性检查。
 * @note 输出保持：不修改输入区域或任何配置对象。
 * @note 所有权：不接管输入，不分配或释放内存。
 * @note 生命周期：只在调用期间借用 text，不保存指针。
 * @note 线程安全：不使用共享可变状态；
 *       输入在调用期间不得被其他线程修改。
 * @note errno：不读取、不保存且不修改 errno。
 * @note 范围边界：不读取或修改进程环境，不拆分 NAME=VALUE，
 *       不裁剪空白，不解析字段值，不检查重复项，
 *       不识别配置文字键名，不写入错误诊断；
 *       只供当前源文件内部使用。
 */
static vireo_config_field_t vireo_config_field_from_environment_name(char const *text,
                                                                     size_t text_size) {
    if (vireo_config_span_equals_literal(text, text_size, "VIREO_LISTEN_ADDRESS")) {
        return VIREO_CONFIG_FIELD_LISTEN_ADDRESS;
    }

    if (vireo_config_span_equals_literal(text, text_size, "VIREO_LISTEN_PORT")) {
        return VIREO_CONFIG_FIELD_LISTEN_PORT;
    }

    if (vireo_config_span_equals_literal(text, text_size, "VIREO_MAX_CONNECTIONS")) {
        return VIREO_CONFIG_FIELD_MAX_CONNECTIONS;
    }

    if (vireo_config_span_equals_literal(text, text_size, "VIREO_WORKER_COUNT")) {
        return VIREO_CONFIG_FIELD_WORKER_COUNT;
    }

    if (vireo_config_span_equals_literal(text, text_size, "VIREO_IDLE_TIMEOUT")) {
        return VIREO_CONFIG_FIELD_IDLE_TIMEOUT;
    }

    if (vireo_config_span_equals_literal(text, text_size, "VIREO_LOG_TO_STDERR")) {
        return VIREO_CONFIG_FIELD_LOG_TO_STDERR;
    }

    if (vireo_config_span_equals_literal(text, text_size, "VIREO_LOG_MAX_FILE_SIZE")) {
        return VIREO_CONFIG_FIELD_LOG_MAX_FILE_SIZE;
    }

    if (vireo_config_span_equals_literal(text, text_size, "VIREO_DATA_DIR")) {
        return VIREO_CONFIG_FIELD_DATA_DIR;
    }

    if (vireo_config_span_equals_literal(text, text_size, "VIREO_LOG_DIR")) {
        return VIREO_CONFIG_FIELD_LOG_DIR;
    }

    return VIREO_CONFIG_FIELD_NONE;
}

/**
 * @brief 将文字片段复制到目标数组，并追加 NUL 终止符
 *
 * 目标容量必须同时容纳全部片段内容和一个 NUL 字节。
 * 容量不足时返回范围错误，不进行截断，不修改目标区域。
 *
 * @param[in] text
 *     只读输入片段，不要求 NUL 终止；
 *     text_size 为 0 时允许为 NULL，
 *     否则必须指向至少 text_size 个可读字节。
 *     调用者保证片段内部不含 NUL，并已满足对应字段的内容约束。
 *
 * @param[in] text_size
 *     要复制的内容字节数，不包含结尾的 NUL。
 *
 * @param[out] destination
 *     非空目标指针；
 *     capacity 非零时，必须指向至少 capacity 个可写字节。
 *     目标区域不得与输入区域重叠。
 *
 * @param[in] capacity
 *     目标数组的总容量，包含 NUL 终止符所需的位置。
 *
 * @retval VIREO_OK
 *     已复制全部内容，并在 destination[text_size] 写入 NUL。
 *
 * @retval VIREO_RESULT_RANGE
 *     目标容量不足以容纳全部内容和 NUL；
 *     目标区域保持原值。
 *
 * @note 前置条件：调用者保证输入、目标区域和内容约束有效；
 *       本函数不执行指针有效性、区域重叠或内容合法性检查。
 * @note 输出规则：成功时只写入 text_size 个内容字节和一个 NUL；
 *       不修改目标数组中更后面的字节。
 *       失败时不修改目标区域。
 * @note 所有权：不接管输入或目标数组，不分配或释放内存。
 * @note 生命周期：只在调用期间借用指针，不保存指针；
 *       成功后目标数组中的副本不依赖输入区域的生命周期。
 * @note 线程安全：不使用共享可变状态；
 *       输入在调用期间不得被修改，目标区域需要独占访问。
 * @note errno：不读取、不保存且不修改 errno。
 * @note 范围边界：不裁剪空白，不验证地址、路径或 UTF-8，
 *       不检查配置值的独立长度上限，不静默截断，
 *       不清零目标数组的剩余容量，不写入错误诊断；
 *       只供当前源文件内部使用。
 */
static vireo_result_t vireo_config_copy_span(char const *text, size_t text_size, char *destination,
                                             size_t capacity) {
    if (text_size >= capacity) {
        return VIREO_RESULT_RANGE;
    }

    if (text_size != 0U) {
        memcpy(destination, text, text_size);
    }

    destination[text_size] = '\0';

    return VIREO_OK;
}

/**
 * @brief 解析一个已识别字段的值，并在成功时更新候选配置
 *
 * 输入片段应已由调用者裁剪两端的水平空白。
 * 本函数检查空值、长度、控制字节、字段语法和数值范围，
 * 成功后只更新指定字段。
 *
 * @param[in,out] candidate
 *     非空、可写的候选配置对象；
 *     被访问的成员必须具有确定值。
 *     成功时更新指定字段，失败时保持所有成员原值。
 *
 * @param[in] field
 *     已由名称识别得到的非 NONE 字段枚举。
 *
 * @param[in] text
 *     已裁剪两端水平空白的只读值片段，不要求 NUL 终止；
 *     text_size 为 0 时允许为 NULL，
 *     否则必须指向至少 text_size 个可读字节。
 *
 * @param[in] text_size
 *     裁剪后的值片段字节数。
 *
 * @param[out] out_issue
 *     非空、可写的问题类别输出；
 *     进入函数时重置为 NONE，失败时接收具体问题类别。
 *
 * @retval VIREO_OK
 *     值满足指定字段要求，已更新候选配置中的对应字段；
 *     out_issue 为 NONE。
 *
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     值为空、包含禁止的控制字节、字段语法不合法，
 *     或 field 不是受支持的字段。
 *
 * @retval VIREO_RESULT_RANGE
 *     值过长、目标字符串容量不足，
 *     或解析后的数值超出字段允许范围。
 *
 * @retval VIREO_RESULT_OVERFLOW
 *     十进制累积或单位换算超过 uint64_t 的表示范围。
 *
 * @note 前置条件：调用者保证输入和输出对象有效；
 *       candidate、out_issue 和输入区域不得重叠。
 *       本函数不执行指针有效性或区域重叠检查。
 * @note 输出保持：失败时不修改 candidate；
 *       out_issue 会被重置并可能更新。
 *       字符串成功赋值时不清零终止符之后的剩余容量。
 * @note 所有权：不接管任何对象，不分配或释放内存；
 *       字符串内容复制到 candidate 自身的数组中。
 * @note 生命周期：只在调用期间借用输入，不保存输入指针。
 * @note 线程安全：不使用共享可变状态；
 *       输入在调用期间不得被修改，输出对象需要独占访问。
 * @note errno：不读取、不保存且不修改 errno。
 * @note 范围边界：不识别名称，不裁剪空白，不检查重复字段，
 *       不填写错误来源或位置，不验证整份配置，
 *       不提交公共接口的最终输出，不初始化运行时资源；
 *       只供当前源文件内部使用。
 */
static vireo_result_t vireo_config_assign_field(vireo_config_t *candidate,
                                                vireo_config_field_t field, char const *text,
                                                size_t text_size, vireo_config_issue_t *out_issue) {
    *out_issue = VIREO_CONFIG_ISSUE_NONE;

    if (text_size == 0U) {
        *out_issue = VIREO_CONFIG_ISSUE_EMPTY_VALUE;
        return VIREO_RESULT_INVALID_ARGUMENT;
    }

    if (text_size > (size_t)VIREO_CONFIG_MAX_VALUE_SIZE) {
        *out_issue = VIREO_CONFIG_ISSUE_VALUE_TOO_LONG;
        return VIREO_RESULT_RANGE;
    }

    for (size_t index = 0U; index < text_size; ++index) {
        unsigned char const byte = (unsigned char)text[index];

        if (byte <= 0x1FU || byte == 0x7FU) {
            *out_issue = VIREO_CONFIG_ISSUE_INVALID_CHARACTER;
            return VIREO_RESULT_INVALID_ARGUMENT;
        }
    }

    uint64_t value;
    uint64_t minimum;
    uint64_t maximum;
    vireo_result_t result;
    vireo_config_issue_t syntax_issue = VIREO_CONFIG_ISSUE_INVALID_INTEGER;

    switch (field) {
        case VIREO_CONFIG_FIELD_LISTEN_ADDRESS: {
            if (!vireo_config_ipv4_is_valid(text, text_size)) {
                *out_issue = VIREO_CONFIG_ISSUE_INVALID_ADDRESS;
                return VIREO_RESULT_INVALID_ARGUMENT;
            }

            result = vireo_config_copy_span(text, text_size, candidate->listen_address,
                                            sizeof(candidate->listen_address));
            if (result != VIREO_OK) {
                *out_issue = VIREO_CONFIG_ISSUE_VALUE_TOO_LONG;
            }

            return result;
        }

        case VIREO_CONFIG_FIELD_DATA_DIR:
        case VIREO_CONFIG_FIELD_LOG_DIR: {
            if (!vireo_config_path_is_valid(text, text_size)) {
                *out_issue = VIREO_CONFIG_ISSUE_INVALID_PATH;
                return VIREO_RESULT_INVALID_ARGUMENT;
            }

            char *destination;
            size_t capacity;

            if (field == VIREO_CONFIG_FIELD_DATA_DIR) {
                destination = candidate->data_dir;
                capacity = sizeof(candidate->data_dir);
            } else {
                destination = candidate->log_dir;
                capacity = sizeof(candidate->log_dir);
            }

            result = vireo_config_copy_span(text, text_size, destination, capacity);
            if (result != VIREO_OK) {
                *out_issue = VIREO_CONFIG_ISSUE_VALUE_TOO_LONG;
            }

            return result;
        }

        case VIREO_CONFIG_FIELD_LOG_TO_STDERR: {
            bool enabled;

            result = vireo_config_parse_boolean(text, text_size, &enabled);
            if (result != VIREO_OK) {
                *out_issue = VIREO_CONFIG_ISSUE_INVALID_BOOLEAN;
                return result;
            }

            candidate->log_to_stderr = enabled;
            return VIREO_OK;
        }

        case VIREO_CONFIG_FIELD_LISTEN_PORT:
            minimum = VIREO_CONFIG_MIN_LISTEN_PORT;
            maximum = VIREO_CONFIG_MAX_LISTEN_PORT;
            result = vireo_config_parse_u64_decimal(text, text_size, &value);
            break;

        case VIREO_CONFIG_FIELD_MAX_CONNECTIONS:
            minimum = VIREO_CONFIG_MIN_MAX_CONNECTIONS;
            maximum = VIREO_CONFIG_MAX_MAX_CONNECTIONS;
            result = vireo_config_parse_u64_decimal(text, text_size, &value);
            break;

        case VIREO_CONFIG_FIELD_WORKER_COUNT:
            minimum = VIREO_CONFIG_MIN_WORKER_COUNT;
            maximum = VIREO_CONFIG_MAX_WORKER_COUNT;
            result = vireo_config_parse_u64_decimal(text, text_size, &value);
            break;

        case VIREO_CONFIG_FIELD_IDLE_TIMEOUT:
            minimum = VIREO_CONFIG_MIN_IDLE_TIMEOUT_MS;
            maximum = VIREO_CONFIG_MAX_IDLE_TIMEOUT_MS;
            syntax_issue = VIREO_CONFIG_ISSUE_INVALID_UNIT;
            result = vireo_config_parse_duration_ms(text, text_size, &value);
            break;

        case VIREO_CONFIG_FIELD_LOG_MAX_FILE_SIZE:
            minimum = VIREO_CONFIG_MIN_LOG_FILE_SIZE_BYTES;
            maximum = VIREO_CONFIG_MAX_LOG_FILE_SIZE_BYTES;
            syntax_issue = VIREO_CONFIG_ISSUE_INVALID_UNIT;
            result = vireo_config_parse_size_bytes(text, text_size, &value);
            break;

        default:
            *out_issue = VIREO_CONFIG_ISSUE_INVALID_ARGUMENT;
            return VIREO_RESULT_INVALID_ARGUMENT;
    }

    if (result != VIREO_OK) {
        if (result == VIREO_RESULT_OVERFLOW) {
            *out_issue = VIREO_CONFIG_ISSUE_NUMERIC_OVERFLOW;
        } else {
            *out_issue = syntax_issue;
        }

        return result;
    }

    if (value < minimum || value > maximum) {
        *out_issue = VIREO_CONFIG_ISSUE_VALUE_OUT_OF_RANGE;
        return VIREO_RESULT_RANGE;
    }

    /* 数值已通过字段范围检查，以下窄化转换不会丢失数值 */
    switch (field) {
        case VIREO_CONFIG_FIELD_LISTEN_PORT:
            candidate->listen_port = (uint16_t)value;
            break;

        case VIREO_CONFIG_FIELD_MAX_CONNECTIONS:
            candidate->max_connections = (uint32_t)value;
            break;

        case VIREO_CONFIG_FIELD_WORKER_COUNT:
            candidate->worker_count = (uint32_t)value;
            break;

        case VIREO_CONFIG_FIELD_IDLE_TIMEOUT:
            candidate->idle_timeout_ms = value;
            break;

        case VIREO_CONFIG_FIELD_LOG_MAX_FILE_SIZE:
            candidate->log_max_file_size_bytes = value;
            break;

        default:
            *out_issue = VIREO_CONFIG_ISSUE_INVALID_ARGUMENT;
            return VIREO_RESULT_INVALID_ARGUMENT;
    }

    return VIREO_OK;
}

/**
 * @brief 解析一行配置文字，并在成功时更新候选配置和字段记录
 *
 * 输入不包含结尾的 LF 或 CRLF。
 * 空行、纯水平空白行和整行 '#' 注释不更新配置。
 * 普通配置行使用第一个 '=' 分隔键和值，
 * 裁剪两端水平空白后识别字段并检查其值。
 *
 * @param[in,out] candidate
 *     非空、可写的候选配置对象；
 *     已有成员必须具有确定值。
 *     普通配置行成功时更新对应字段，失败时保持原值。
 *
 * @param[in] text
 *     只读单行片段，不要求 NUL 终止；
 *     text_size 为 0 时允许为 NULL，
 *     否则必须指向至少 text_size 个可读字节。
 *     合法的行结束符应由外层去除；片段中的 CR 或 LF 将被拒绝。
 *
 * @param[in] text_size
 *     单行内容的字节数，不包含结尾的 LF 或 CRLF。
 *
 * @param[in] line
 *     当前行在配置文字中的行号，从 1 开始。
 *
 * @param[in,out] seen_fields
 *     非空、可读写的已处理字段位集合。
 *     外层在每次完整文字解析开始时初始化为 0，
 *     随后在各行之间保留本函数更新后的值。
 *
 * @param[out] out_error
 *     非空、可写的完整诊断对象；
 *     进入函数时清空，失败时填写 TEXT 来源和当前行号。
 *
 * @retval VIREO_OK
 *     空行或注释已跳过，或者配置行已成功应用；
 *     诊断为无错误状态。
 *
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     行内含禁止的字符、缺少分隔符、键为空、
 *     键未知或重复，或者字段值语法不合法。
 *
 * @retval VIREO_RESULT_RANGE
 *     单行或值过长，或者字段值超出允许范围。
 *
 * @retval VIREO_RESULT_OVERFLOW
 *     字段值的十进制累积或单位换算发生溢出。
 *
 * @note 前置条件：调用者保证所有对象和输入区域有效；
 *       可写对象之间、可写对象与输入区域不得重叠。
 *       本函数不执行指针有效性检查。
 * @note 输出保持：失败时不修改 candidate 和 seen_fields；
 *       out_error 会被重置并更新。
 *       空行和注释成功时也不修改 candidate 和 seen_fields。
 * @note 所有权：不接管任何对象，不分配或释放内存。
 * @note 生命周期：只在调用期间借用输入，不保存输入指针。
 * @note 线程安全：不使用共享可变状态；
 *       输入在调用期间不得被修改，输出对象需要独占访问。
 * @note errno：不读取、不保存且不修改 errno。
 * @note 范围边界：不拆分整份文字，不检查输入总长度，
 *       不处理文件 I/O 或环境覆盖，不验证完整候选配置，
 *       不提交公共接口的最终输出。
 *       字段位映射依赖当前有效字段枚举连续取值 1..9；
 *       只供当前源文件内部使用。
 */
static vireo_result_t vireo_config_parse_line(vireo_config_t *candidate, char const *text,
                                              size_t text_size, size_t line, uint32_t *seen_fields,
                                              vireo_config_error_t *out_error) {
    vireo_config_error_clear(out_error);

    if (text_size > (size_t)VIREO_CONFIG_MAX_LINE_SIZE) {
        vireo_config_error_set(out_error, VIREO_CONFIG_ISSUE_LINE_TOO_LONG,
                               VIREO_CONFIG_SOURCE_TEXT, VIREO_CONFIG_FIELD_NONE, line, 0U, 0);
        return VIREO_RESULT_RANGE;
    }

    for (size_t index = 0U; index < text_size; ++index) {
        unsigned char const byte = (unsigned char)text[index];

        if ((byte <= 0x1FU && byte != 0x09U) || byte == 0x7FU) {
            vireo_config_error_set(out_error, VIREO_CONFIG_ISSUE_INVALID_CHARACTER,
                                   VIREO_CONFIG_SOURCE_TEXT, VIREO_CONFIG_FIELD_NONE, line, 0U, 0);
            return VIREO_RESULT_INVALID_ARGUMENT;
        }
    }

    size_t begin = 0U;
    size_t end = text_size;
    vireo_config_trim_horizontal_space(text, &begin, &end);

    if (begin == end) {
        return VIREO_OK;
    }

    if (text[begin] == '#') {
        return VIREO_OK;
    }

    size_t separator = begin;
    while (separator < end && text[separator] != '=') {
        ++separator;
    }

    if (separator == end) {
        vireo_config_error_set(out_error, VIREO_CONFIG_ISSUE_MISSING_SEPARATOR,
                               VIREO_CONFIG_SOURCE_TEXT, VIREO_CONFIG_FIELD_NONE, line, 0U, 0);
        return VIREO_RESULT_INVALID_ARGUMENT;
    }

    size_t key_begin = begin;
    size_t key_end = separator;
    vireo_config_trim_horizontal_space(text, &key_begin, &key_end);

    if (key_begin == key_end) {
        vireo_config_error_set(out_error, VIREO_CONFIG_ISSUE_EMPTY_KEY, VIREO_CONFIG_SOURCE_TEXT,
                               VIREO_CONFIG_FIELD_NONE, line, 0U, 0);
        return VIREO_RESULT_INVALID_ARGUMENT;
    }

    vireo_config_field_t const field =
        vireo_config_field_from_key(text + key_begin, key_end - key_begin);

    if (field == VIREO_CONFIG_FIELD_NONE) {
        vireo_config_error_set(out_error, VIREO_CONFIG_ISSUE_UNKNOWN_KEY, VIREO_CONFIG_SOURCE_TEXT,
                               VIREO_CONFIG_FIELD_NONE, line, 0U, 0);
        return VIREO_RESULT_INVALID_ARGUMENT;
    }

    /* field 已由名称识别限定为当前的有效字段值 1..9 */
    uint32_t const field_mask = UINT32_C(1) << ((unsigned int)field - 1U);

    if ((*seen_fields & field_mask) != UINT32_C(0)) {
        vireo_config_error_set(out_error, VIREO_CONFIG_ISSUE_DUPLICATE_KEY,
                               VIREO_CONFIG_SOURCE_TEXT, field, line, 0U, 0);
        return VIREO_RESULT_INVALID_ARGUMENT;
    }

    size_t value_begin = separator + 1U;
    size_t value_end = end;
    vireo_config_trim_horizontal_space(text, &value_begin, &value_end);

    vireo_config_issue_t issue = VIREO_CONFIG_ISSUE_NONE;
    vireo_result_t const result = vireo_config_assign_field(candidate, field, text + value_begin,
                                                            value_end - value_begin, &issue);

    if (result != VIREO_OK) {
        vireo_config_error_set(out_error, issue, VIREO_CONFIG_SOURCE_TEXT, field, line, 0U, 0);
        return result;
    }

    *seen_fields |= field_mask;

    return VIREO_OK;
}

/* 生成完整默认配置；检查输出指针后一次性提交所有成员 */
vireo_result_t vireo_config_defaults(vireo_config_t *out_config) {
    if (out_config == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }

    vireo_config_t const defaults = {
        .listen_address = VIREO_CONFIG_DEFAULT_LISTEN_ADDRESS,
        .listen_port = VIREO_CONFIG_DEFAULT_LISTEN_PORT,
        .max_connections = VIREO_CONFIG_DEFAULT_MAX_CONNECTIONS,
        .worker_count = VIREO_CONFIG_DEFAULT_WORKER_COUNT,
        .idle_timeout_ms = VIREO_CONFIG_DEFAULT_IDLE_TIMEOUT_MS,
        .log_to_stderr = VIREO_CONFIG_DEFAULT_LOG_TO_STDERR,
        .log_max_file_size_bytes = VIREO_CONFIG_DEFAULT_LOG_FILE_SIZE_BYTES,
        .data_dir = VIREO_CONFIG_DEFAULT_DATA_DIR,
        .log_dir = VIREO_CONFIG_DEFAULT_LOG_DIR,
    };

    *out_config = defaults;

    return VIREO_OK;
}

/* 验证已有配置对象；只读取配置，失败时填写对应字段的诊断 */
vireo_result_t vireo_config_validate(vireo_config_t const *config,
                                     vireo_config_error_t *out_error) {
    vireo_config_error_clear(out_error);

    if (config == NULL || out_error == NULL) {
        vireo_config_error_set(out_error, VIREO_CONFIG_ISSUE_INVALID_ARGUMENT,
                               VIREO_CONFIG_SOURCE_NONE, VIREO_CONFIG_FIELD_NONE, 0U, 0U, 0);
        return VIREO_RESULT_INVALID_ARGUMENT;
    }

    size_t length;

    if (!vireo_config_bounded_string_length(config->listen_address, sizeof(config->listen_address),
                                            &length)) {
        vireo_config_error_set(out_error, VIREO_CONFIG_ISSUE_VALUE_TOO_LONG,
                               VIREO_CONFIG_SOURCE_CONFIG, VIREO_CONFIG_FIELD_LISTEN_ADDRESS, 0U,
                               0U, 0);
        return VIREO_RESULT_RANGE;
    }

    if (!vireo_config_ipv4_is_valid(config->listen_address, length)) {
        vireo_config_error_set(out_error, VIREO_CONFIG_ISSUE_INVALID_ADDRESS,
                               VIREO_CONFIG_SOURCE_CONFIG, VIREO_CONFIG_FIELD_LISTEN_ADDRESS, 0U,
                               0U, 0);
        return VIREO_RESULT_INVALID_ARGUMENT;
    }

    /* 当前端口上限为 UINT16_MAX，成员类型已保证不会超过该上限 */
    if (config->listen_port < VIREO_CONFIG_MIN_LISTEN_PORT) {
        vireo_config_error_set(out_error, VIREO_CONFIG_ISSUE_VALUE_OUT_OF_RANGE,
                               VIREO_CONFIG_SOURCE_CONFIG, VIREO_CONFIG_FIELD_LISTEN_PORT, 0U, 0U,
                               0);
        return VIREO_RESULT_RANGE;
    }

    if (config->max_connections < VIREO_CONFIG_MIN_MAX_CONNECTIONS ||
        config->max_connections > VIREO_CONFIG_MAX_MAX_CONNECTIONS) {
        vireo_config_error_set(out_error, VIREO_CONFIG_ISSUE_VALUE_OUT_OF_RANGE,
                               VIREO_CONFIG_SOURCE_CONFIG, VIREO_CONFIG_FIELD_MAX_CONNECTIONS, 0U,
                               0U, 0);
        return VIREO_RESULT_RANGE;
    }

    if (config->worker_count < VIREO_CONFIG_MIN_WORKER_COUNT ||
        config->worker_count > VIREO_CONFIG_MAX_WORKER_COUNT) {
        vireo_config_error_set(out_error, VIREO_CONFIG_ISSUE_VALUE_OUT_OF_RANGE,
                               VIREO_CONFIG_SOURCE_CONFIG, VIREO_CONFIG_FIELD_WORKER_COUNT, 0U, 0U,
                               0);
        return VIREO_RESULT_RANGE;
    }

    if (config->idle_timeout_ms < VIREO_CONFIG_MIN_IDLE_TIMEOUT_MS ||
        config->idle_timeout_ms > VIREO_CONFIG_MAX_IDLE_TIMEOUT_MS) {
        vireo_config_error_set(out_error, VIREO_CONFIG_ISSUE_VALUE_OUT_OF_RANGE,
                               VIREO_CONFIG_SOURCE_CONFIG, VIREO_CONFIG_FIELD_IDLE_TIMEOUT, 0U, 0U,
                               0);
        return VIREO_RESULT_RANGE;
    }

    /* 有效 bool 对象表示由调用者保证，true 和 false 均为合法配置值 */

    if (config->log_max_file_size_bytes < VIREO_CONFIG_MIN_LOG_FILE_SIZE_BYTES ||
        config->log_max_file_size_bytes > VIREO_CONFIG_MAX_LOG_FILE_SIZE_BYTES) {
        vireo_config_error_set(out_error, VIREO_CONFIG_ISSUE_VALUE_OUT_OF_RANGE,
                               VIREO_CONFIG_SOURCE_CONFIG, VIREO_CONFIG_FIELD_LOG_MAX_FILE_SIZE, 0U,
                               0U, 0);
        return VIREO_RESULT_RANGE;
    }

    if (!vireo_config_bounded_string_length(config->data_dir, sizeof(config->data_dir), &length)) {
        vireo_config_error_set(out_error, VIREO_CONFIG_ISSUE_VALUE_TOO_LONG,
                               VIREO_CONFIG_SOURCE_CONFIG, VIREO_CONFIG_FIELD_DATA_DIR, 0U, 0U, 0);
        return VIREO_RESULT_RANGE;
    }

    if (!vireo_config_path_is_valid(config->data_dir, length)) {
        vireo_config_error_set(out_error, VIREO_CONFIG_ISSUE_INVALID_PATH,
                               VIREO_CONFIG_SOURCE_CONFIG, VIREO_CONFIG_FIELD_DATA_DIR, 0U, 0U, 0);
        return VIREO_RESULT_INVALID_ARGUMENT;
    }

    if (!vireo_config_bounded_string_length(config->log_dir, sizeof(config->log_dir), &length)) {
        vireo_config_error_set(out_error, VIREO_CONFIG_ISSUE_VALUE_TOO_LONG,
                               VIREO_CONFIG_SOURCE_CONFIG, VIREO_CONFIG_FIELD_LOG_DIR, 0U, 0U, 0);
        return VIREO_RESULT_RANGE;
    }

    if (!vireo_config_path_is_valid(config->log_dir, length)) {
        vireo_config_error_set(out_error, VIREO_CONFIG_ISSUE_INVALID_PATH,
                               VIREO_CONFIG_SOURCE_CONFIG, VIREO_CONFIG_FIELD_LOG_DIR, 0U, 0U, 0);
        return VIREO_RESULT_INVALID_ARGUMENT;
    }

    return VIREO_OK;
}

/* 在基础配置上解析完整文字；全部检查成功后才提交候选配置 */
vireo_result_t vireo_config_parse_text(vireo_config_t const *base, char const *text,
                                       size_t text_size, vireo_config_t *out_config,
                                       vireo_config_error_t *out_error) {
    vireo_config_error_clear(out_error);

    if (base == NULL || out_config == NULL || out_error == NULL ||
        (text == NULL && text_size != 0U)) {
        vireo_config_error_set(out_error, VIREO_CONFIG_ISSUE_INVALID_ARGUMENT,
                               VIREO_CONFIG_SOURCE_NONE, VIREO_CONFIG_FIELD_NONE, 0U, 0U, 0);
        return VIREO_RESULT_INVALID_ARGUMENT;
    }

    vireo_result_t result = vireo_config_validate(base, out_error);
    if (result != VIREO_OK) {
        return result;
    }

    if (text_size > (size_t)VIREO_CONFIG_MAX_TEXT_SIZE) {
        vireo_config_error_set(out_error, VIREO_CONFIG_ISSUE_TEXT_TOO_LARGE,
                               VIREO_CONFIG_SOURCE_TEXT, VIREO_CONFIG_FIELD_NONE, 0U, 0U, 0);
        return VIREO_RESULT_RANGE;
    }

    vireo_config_t candidate = *base;
    uint32_t seen_fields = UINT32_C(0);
    size_t offset = 0U;
    size_t line = 1U;

    while (offset < text_size) {
        size_t const line_begin = offset;

        /* 找到 LF，或者到达输入结尾；不要求输入以 NUL 终止 */
        while (offset < text_size && text[offset] != '\n') {
            ++offset;
        }

        size_t line_end = offset;

        /* 只去掉紧邻 LF 的 CR；裸 CR 留给单行检查拒绝 */
        if (offset < text_size && line_end > line_begin && text[line_end - 1U] == '\r') {
            --line_end;
        }

        result = vireo_config_parse_line(&candidate, text + line_begin, line_end - line_begin, line,
                                         &seen_fields, out_error);
        if (result != VIREO_OK) {
            return result;
        }

        if (offset < text_size) {
            ++offset;
        }

        ++line;
    }

    result = vireo_config_validate(&candidate, out_error);
    if (result != VIREO_OK) {
        return result;
    }

    *out_config = candidate;

    return VIREO_OK;
}

/* 应用显式环境覆盖；全部检查成功后才提交候选配置 */
vireo_result_t vireo_config_apply_environment(vireo_config_t const *base,
                                              vireo_config_environment_t const *environment,
                                              size_t environment_count, vireo_config_t *out_config,
                                              vireo_config_error_t *out_error) {
    vireo_config_error_clear(out_error);

    if (base == NULL || out_config == NULL || out_error == NULL ||
        (environment == NULL && environment_count != 0U)) {
        vireo_config_error_set(out_error, VIREO_CONFIG_ISSUE_INVALID_ARGUMENT,
                               VIREO_CONFIG_SOURCE_NONE, VIREO_CONFIG_FIELD_NONE, 0U, 0U, 0);
        return VIREO_RESULT_INVALID_ARGUMENT;
    }

    vireo_result_t result = vireo_config_validate(base, out_error);
    if (result != VIREO_OK) {
        return result;
    }

    if (environment_count > (size_t)VIREO_CONFIG_MAX_ENVIRONMENT_ITEMS) {
        vireo_config_error_set(out_error, VIREO_CONFIG_ISSUE_TOO_MANY_ENVIRONMENT_ITEMS,
                               VIREO_CONFIG_SOURCE_ENVIRONMENT, VIREO_CONFIG_FIELD_NONE, 0U, 0U, 0);
        return VIREO_RESULT_RANGE;
    }

    vireo_config_t candidate = *base;
    uint32_t seen_fields = UINT32_C(0);

    for (size_t index = 0U; index < environment_count; ++index) {
        vireo_config_environment_t const *entry = &environment[index];
        size_t const entry_index = index + 1U;

        if (entry->name == NULL || entry->value == NULL) {
            vireo_config_error_set(out_error, VIREO_CONFIG_ISSUE_INVALID_ARGUMENT,
                                   VIREO_CONFIG_SOURCE_ENVIRONMENT, VIREO_CONFIG_FIELD_NONE, 0U,
                                   entry_index, 0);
            return VIREO_RESULT_INVALID_ARGUMENT;
        }

        vireo_config_field_t const field =
            vireo_config_field_from_environment_name(entry->name, strlen(entry->name));

        if (field == VIREO_CONFIG_FIELD_NONE) {
            vireo_config_error_set(out_error, VIREO_CONFIG_ISSUE_UNKNOWN_ENVIRONMENT,
                                   VIREO_CONFIG_SOURCE_ENVIRONMENT, VIREO_CONFIG_FIELD_NONE, 0U,
                                   entry_index, 0);
            return VIREO_RESULT_INVALID_ARGUMENT;
        }

        /* field 已由名称识别限定为当前的有效字段值 1..9 */
        uint32_t const field_mask = UINT32_C(1) << ((unsigned int)field - 1U);

        if ((seen_fields & field_mask) != UINT32_C(0)) {
            vireo_config_error_set(out_error, VIREO_CONFIG_ISSUE_DUPLICATE_ENVIRONMENT,
                                   VIREO_CONFIG_SOURCE_ENVIRONMENT, field, 0U, entry_index, 0);
            return VIREO_RESULT_INVALID_ARGUMENT;
        }

        size_t value_begin = 0U;
        size_t value_end = strlen(entry->value);
        vireo_config_trim_horizontal_space(entry->value, &value_begin, &value_end);

        vireo_config_issue_t issue = VIREO_CONFIG_ISSUE_NONE;
        result = vireo_config_assign_field(&candidate, field, entry->value + value_begin,
                                           value_end - value_begin, &issue);
        if (result != VIREO_OK) {
            vireo_config_error_set(out_error, issue, VIREO_CONFIG_SOURCE_ENVIRONMENT, field, 0U,
                                   entry_index, 0);
            return result;
        }

        seen_fields |= field_mask;
    }

    result = vireo_config_validate(&candidate, out_error);
    if (result != VIREO_OK) {
        return result;
    }

    *out_config = candidate;

    return VIREO_OK;
}

/* 按来源顺序加载配置；清理文件资源，并在返回前恢复调用前的 errno */
vireo_result_t vireo_config_load(char const *file_path,
                                 vireo_config_environment_t const *environment,
                                 size_t environment_count, vireo_config_t *out_config,
                                 vireo_config_error_t *out_error) {
    int const saved_errno = errno;
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;

    vireo_config_error_clear(out_error);

    if (out_config == NULL || out_error == NULL ||
        (environment == NULL && environment_count != 0U) ||
        (file_path != NULL && file_path[0] == '\0')) {
        vireo_config_error_set(out_error, VIREO_CONFIG_ISSUE_INVALID_ARGUMENT,
                               VIREO_CONFIG_SOURCE_NONE, VIREO_CONFIG_FIELD_NONE, 0U, 0U, 0);
        goto finish;
    }

    vireo_config_t candidate;
    vireo_config_t next;

    result = vireo_config_defaults(&candidate);
    if (result != VIREO_OK) {
        goto finish;
    }

    if (file_path != NULL) {
        /* 多读一个字节用于区分恰好达到上限与实际超限 */
        char text[(size_t)VIREO_CONFIG_MAX_TEXT_SIZE + 1U];

        errno = 0;
        FILE *file = fopen(file_path, "rb");
        if (file == NULL) {
            int const open_errno = errno;

            vireo_config_error_set(out_error, VIREO_CONFIG_ISSUE_FILE_OPEN_FAILED,
                                   VIREO_CONFIG_SOURCE_FILE, VIREO_CONFIG_FIELD_NONE, 0U, 0U,
                                   open_errno);

            result = open_errno == ENOENT ? VIREO_RESULT_NOT_FOUND : VIREO_RESULT_IO;
            goto finish;
        }

        errno = 0;
        size_t const text_size = fread(text, 1U, sizeof(text), file);
        int const read_errno = errno;

        if (ferror(file) != 0) {
            vireo_config_error_set(out_error, VIREO_CONFIG_ISSUE_FILE_READ_FAILED,
                                   VIREO_CONFIG_SOURCE_FILE, VIREO_CONFIG_FIELD_NONE, 0U, 0U,
                                   read_errno);
            result = VIREO_RESULT_IO;
        } else if (text_size > (size_t)VIREO_CONFIG_MAX_TEXT_SIZE) {
            vireo_config_error_set(out_error, VIREO_CONFIG_ISSUE_TEXT_TOO_LARGE,
                                   VIREO_CONFIG_SOURCE_TEXT, VIREO_CONFIG_FIELD_NONE, 0U, 0U, 0);
            result = VIREO_RESULT_RANGE;
        } else {
            result = vireo_config_parse_text(&candidate, text, text_size, &next, out_error);
        }

        /* 无论读取或解析是否成功，已打开的流都必须关闭 */
        errno = 0;
        int const close_result = fclose(file);
        int const close_errno = errno;

        /* 关闭错误不得覆盖已经记录的读取、长度或解析错误 */
        if (close_result != 0 && result == VIREO_OK) {
            vireo_config_error_set(out_error, VIREO_CONFIG_ISSUE_FILE_CLOSE_FAILED,
                                   VIREO_CONFIG_SOURCE_FILE, VIREO_CONFIG_FIELD_NONE, 0U, 0U,
                                   close_errno);
            result = VIREO_RESULT_IO;
        }

        if (result != VIREO_OK) {
            goto finish;
        }

        candidate = next;
    }

    result = vireo_config_apply_environment(&candidate, environment, environment_count, &next,
                                            out_error);
    if (result != VIREO_OK) {
        goto finish;
    }

    result = vireo_config_validate(&next, out_error);
    if (result != VIREO_OK) {
        goto finish;
    }

    *out_config = next;

finish:
    errno = saved_errno;
    return result;
}
