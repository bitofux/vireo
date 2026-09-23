/*
 * PROJECT : VIREO
 * FILE    : tlv.c
 * AUTHOR  : bitofux
 * DATE    : 2026-09-08
 * BRIEF   : 实现 TLV 显式编解码与通用 schema 验证
 *
 * -- 宿主语义对象与 wire byte buffer 分离
 * -- 多字节整数通过私有 big-endian helper 显式读写
 * -- 不动态分配，不执行 I/O，不修改 errno
 */

#include <vireo/protocol/tlv.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <vireo/base/checked.h>
#include <vireo/base/result.h>

/**
 * @brief 把宿主语义 uint16_t 编码为两个 big-endian 字节
 *
 * 高八位写入 wire[0]，低八位写入 wire[1]。
 *
 * @param[out] wire
 *     指向至少两个可写字节的非空指针；
 *     调用者保留底层缓冲区的所有权。
 *
 * @param[in] value
 *     要编码的宿主语义 uint16_t 数值。
 *
 * @note 前置条件：调用者必须先保证 wire 非 NULL，
 *       并且从 wire 开始至少有两个字节可写。
 * @note 所有权：不接管 wire 指向的存储，不分配或释放内存。
 * @note 生命周期：只在调用期间借用 wire，不保存指针。
 * @note 线程安全：不使用共享可变全局状态；
 *       对重叠输出区域的并发访问需要调用者同步。
 * @note errno：本函数不读取、不保存且不修改 errno。
 * @note 范围边界：不执行参数或容量检查，不更新 writer 状态，
 *       不解释字段含义；只供当前源文件内部使用。
 */
static void vireo_tlv_write_u16_be(uint8_t *wire, uint16_t value) {
    wire[0] = (uint8_t)(value >> 8U);
    wire[1] = (uint8_t)value;
}

/**
 * @brief 把宿主语义 uint32_t 编码为四个 big-endian 字节
 *
 * 从最高有效字节到最低有效字节，
 * 依次写入 wire[0]、wire[1]、wire[2] 和 wire[3]。
 *
 * @param[out] wire
 *     指向至少四个可写字节的非空指针；
 *     调用者保留底层缓冲区的所有权。
 *
 * @param[in] value
 *     要编码的宿主语义 uint32_t 数值。
 *
 * @note 前置条件：调用者必须先保证 wire 非 NULL，
 *       并且从 wire 开始至少有四个字节可写。
 * @note 所有权：不接管 wire 指向的存储，不分配或释放内存。
 * @note 生命周期：只在调用期间借用 wire，不保存指针。
 * @note 线程安全：不使用共享可变全局状态；
 *       对重叠输出区域的并发访问需要调用者同步。
 * @note errno：本函数不读取、不保存且不修改 errno。
 * @note 范围边界：不执行参数或容量检查，不更新 writer 状态，
 *       不解释字段含义；只供当前源文件内部使用。
 */
static void vireo_tlv_write_u32_be(uint8_t *wire, uint32_t value) {
    wire[0] = (uint8_t)(value >> 24U);
    wire[1] = (uint8_t)(value >> 16U);
    wire[2] = (uint8_t)(value >> 8U);
    wire[3] = (uint8_t)value;
}

/**
 * @brief 把宿主语义 uint64_t 编码为八个 big-endian 字节
 *
 * 从最高有效字节到最低有效字节，
 * 依次写入 wire[0] 到 wire[7]。
 *
 * @param[out] wire
 *     指向至少八个可写字节的非空指针；
 *     调用者保留底层缓冲区的所有权。
 *
 * @param[in] value
 *     要编码的宿主语义 uint64_t 数值。
 *
 * @note 前置条件：调用者必须先保证 wire 非 NULL，
 *       并且从 wire 开始至少有八个字节可写。
 * @note 所有权：不接管 wire 指向的存储，不分配或释放内存。
 * @note 生命周期：只在调用期间借用 wire，不保存指针。
 * @note 线程安全：不使用共享可变全局状态；
 *       对重叠输出区域的并发访问需要调用者同步。
 * @note errno：本函数不读取、不保存且不修改 errno。
 * @note 范围边界：不执行参数或容量检查，不更新 writer 状态，
 *       不解释字段含义；只供当前源文件内部使用。
 */
static void vireo_tlv_write_u64_be(uint8_t *wire, uint64_t value) {
    wire[0] = (uint8_t)(value >> 56U);
    wire[1] = (uint8_t)(value >> 48U);
    wire[2] = (uint8_t)(value >> 40U);
    wire[3] = (uint8_t)(value >> 32U);
    wire[4] = (uint8_t)(value >> 24U);
    wire[5] = (uint8_t)(value >> 16U);
    wire[6] = (uint8_t)(value >> 8U);
    wire[7] = (uint8_t)value;
}

/**
 * @brief 从两个 big-endian 字节解码宿主语义 uint16_t
 *
 * wire[0] 作为结果的高八位，
 * wire[1] 作为结果的低八位。
 *
 * @param[in] wire
 *     指向至少两个可读字节的非空指针；
 *     调用者保留底层输入区域的所有权。
 *
 * @return
 *     两个 big-endian 字节表示的宿主语义 uint16_t 数值。
 *
 * @note 前置条件：调用者必须先保证 wire 非 NULL，
 *       并且从 wire 开始至少有两个字节可读。
 * @note 所有权：不接管 wire 指向的存储，不分配或释放内存。
 * @note 生命周期：只在调用期间借用 wire，不保存指针。
 * @note 线程安全：不使用共享可变全局状态；
 *       输入区域在调用期间不得被其他线程修改。
 * @note errno：本函数不读取、不保存且不修改 errno。
 * @note 范围边界：不执行参数或长度检查，不推进 reader，
 *       不解释字段含义；只供当前源文件内部使用。
 */
static uint16_t vireo_tlv_read_u16_be(uint8_t const *wire) {
    uint16_t const high = (uint16_t)((uint16_t)wire[0] << 8U);
    uint16_t const low = (uint16_t)wire[1];

    return (uint16_t)(high | low);
}

/**
 * @brief 从四个 big-endian 字节解码宿主语义 uint32_t
 *
 * wire[0] 作为结果的最高有效字节，
 * wire[3] 作为结果的最低有效字节。
 *
 * @param[in] wire
 *     指向至少四个可读字节的非空指针；
 *     调用者保留底层输入区域的所有权。
 *
 * @return
 *     四个 big-endian 字节表示的宿主语义 uint32_t 数值。
 *
 * @note 前置条件：调用者必须先保证 wire 非 NULL，
 *       并且从 wire 开始至少有四个字节可读。
 * @note 所有权：不接管 wire 指向的存储，不分配或释放内存。
 * @note 生命周期：只在调用期间借用 wire，不保存指针。
 * @note 线程安全：不使用共享可变全局状态；
 *       输入区域在调用期间不得被其他线程修改。
 * @note errno：本函数不读取、不保存且不修改 errno。
 * @note 范围边界：不执行参数或长度检查，不推进 reader，
 *       不解释字段含义；只供当前源文件内部使用。
 */
static uint32_t vireo_tlv_read_u32_be(uint8_t const *wire) {
    uint32_t const byte0 = (uint32_t)wire[0] << 24U;
    uint32_t const byte1 = (uint32_t)wire[1] << 16U;
    uint32_t const byte2 = (uint32_t)wire[2] << 8U;
    uint32_t const byte3 = (uint32_t)wire[3];

    return byte0 | byte1 | byte2 | byte3;
}

/**
 * @brief 从八个 big-endian 字节解码宿主语义 uint64_t
 *
 * wire[0] 作为结果的最高有效字节，
 * wire[7] 作为结果的最低有效字节。
 *
 * @param[in] wire
 *     指向至少八个可读字节的非空指针；
 *     调用者保留底层输入区域的所有权。
 *
 * @return
 *     八个 big-endian 字节表示的宿主语义 uint64_t 数值。
 *
 * @note 前置条件：调用者必须先保证 wire 非 NULL，
 *       并且从 wire 开始至少有八个字节可读。
 * @note 所有权：不接管 wire 指向的存储，不分配或释放内存。
 * @note 生命周期：只在调用期间借用 wire，不保存指针。
 * @note 线程安全：不使用共享可变全局状态；
 *       输入区域在调用期间不得被其他线程修改。
 * @note errno：本函数不读取、不保存且不修改 errno。
 * @note 范围边界：不执行参数或长度检查，不推进 reader，
 *       不解释字段含义；只供当前源文件内部使用。
 */
static uint64_t vireo_tlv_read_u64_be(uint8_t const *wire) {
    uint64_t const byte0 = (uint64_t)wire[0] << 56U;
    uint64_t const byte1 = (uint64_t)wire[1] << 48U;
    uint64_t const byte2 = (uint64_t)wire[2] << 40U;
    uint64_t const byte3 = (uint64_t)wire[3] << 32U;
    uint64_t const byte4 = (uint64_t)wire[4] << 24U;
    uint64_t const byte5 = (uint64_t)wire[5] << 16U;
    uint64_t const byte6 = (uint64_t)wire[6] << 8U;
    uint64_t const byte7 = (uint64_t)wire[7];

    return (uint64_t)(byte0 | byte1 | byte2 | byte3 | byte4 | byte5 | byte6 | byte7);
}

/**
 * @brief 检查 TLV writer 是否满足可检查的基本状态约束
 *
 * 有效状态要求：
 * -- writer 非 NULL；
 * -- used 不超过 capacity；
 * -- data 为 NULL 时，capacity 必须为 0。
 *
 * @param[in] writer
 *     要检查的只读 writer 指针；允许为 NULL。
 *     非 NULL 时，必须指向生命周期内的可读对象，
 *     且其成员已经具有确定值。
 *
 * @retval true
 *     writer 满足上述基本状态约束。
 *
 * @retval false
 *     writer 为 NULL，used 大于 capacity，
 *     或者 capacity 非零但 data 为 NULL。
 *
 * @note 输出保持：不修改 writer 或底层缓冲区。
 * @note 所有权：不接管 writer 或底层缓冲区的所有权。
 * @note 生命周期：只在调用期间借用 writer，不保存指针。
 * @note 线程安全：不使用共享可变全局状态；
 *       writer 成员在调用期间不得被其他线程修改。
 * @note errno：本函数不读取、不保存且不修改 errno。
 * @note 范围边界：不验证非空指针的真实有效性或实际分配容量，
 *       不验证初始化历史、已写入内容或本次追加操作；
 *       只供当前源文件内部使用。
 */
static bool vireo_tlv_writer_is_valid(vireo_tlv_writer_t const *writer) {
    if (writer == NULL) {
        return false;
    }

    if (writer->used > writer->capacity) {
        return false;
    }

    if (writer->data == NULL && writer->capacity != 0U) {
        return false;
    }

    return true;
}

/**
 * @brief 检查 TLV reader 是否满足可检查的基本状态约束
 *
 * 有效状态要求：
 * -- reader 非 NULL；
 * -- offset 不超过 size；
 * -- data 为 NULL 时，size 必须为 0。
 *
 * @param[in] reader
 *     要检查的只读 reader 指针；允许为 NULL。
 *     非 NULL 时，必须指向生命周期内的可读对象，
 *     且其成员已经具有确定值。
 *
 * @retval true
 *     reader 满足上述基本状态约束。
 *
 * @retval false
 *     reader 为 NULL，offset 大于 size，
 *     或者 size 非零但 data 为 NULL。
 *
 * @note 输出保持：不修改 reader 或底层输入区域。
 * @note 所有权：不接管 reader 或底层输入区域的所有权。
 * @note 生命周期：只在调用期间借用 reader，不保存指针。
 * @note 线程安全：不使用共享可变全局状态；
 *       reader 成员在调用期间不得被其他线程修改。
 * @note errno：本函数不读取、不保存且不修改 errno。
 * @note 范围边界：不验证非空指针的真实有效性或实际输入长度，
 *       不验证初始化历史、TLV 内容或是否到达输入结尾；
 *       只供当前源文件内部使用。
 */
static bool vireo_tlv_reader_is_valid(vireo_tlv_reader_t const *reader) {
    if (reader == NULL) {
        return false;
    }

    if (reader->offset > reader->size) {
        return false;
    }

    if (reader->data == NULL && reader->size != 0U) {
        return false;
    }

    return true;
}

/**
 * @brief 判断一个字节是否具有 UTF-8 续字节格式
 *
 * UTF-8 续字节的最高两位必须为二进制 10，
 * 对应字节值范围为 0x80 到 0xBF。
 *
 * @param[in] byte
 *     要检查的单个字节，按值传入。
 *
 * @retval true
 *     byte 的最高两位为二进制 10。
 *
 * @retval false
 *     byte 的最高两位不是二进制 10。
 *
 * @note 副作用：不修改任何调用者对象，不分配或释放内存。
 * @note 生命周期：参数按值传递，不借用或保存任何指针。
 * @note 线程安全：不访问共享可变状态，可以并发调用。
 * @note errno：本函数不读取、不保存且不修改 errno。
 * @note 范围边界：只检查单个字节的格式，
 *       不验证它所在的位置或整个 UTF-8 序列的合法性；
 *       只供当前源文件内部使用。
 */
static bool vireo_tlv_utf8_is_continuation(uint8_t byte) {
    return (byte & UINT8_C(0xC0)) == UINT8_C(0x80);
}

/**
 * @brief 检查一段字节是否构成合法的 UTF-8 编码
 *
 * 按照首字节确定当前编码的字节数，
 * 检查续字节格式，并拒绝过长编码、代理码点编码
 * 和超过 U+10FFFF 的编码。
 *
 * @param[in] data
 *     要检查的只读字节区域；
 *     size 为 0 时允许为 NULL。
 *
 * @param[in] size
 *     要检查的字节数，不是字符数量。
 *
 * @retval true
 *     整段字节构成合法的 UTF-8 编码；
 *     空字节区域也返回 true。
 *
 * @retval false
 *     存在非法首字节、缺失或非法续字节，
 *     或者存在 UTF-8 不允许的编码。
 *
 * @note 前置条件：size 非零时，data 必须非 NULL，
 *       并指向至少 size 个可读字节；
 *       本函数不检查指针的真实有效性。
 * @note 输出保持：不修改输入区域。
 * @note 所有权：不接管输入区域，不分配或释放内存。
 * @note 生命周期：只在调用期间借用 data，不保存指针。
 * @note 线程安全：不使用共享可变全局状态；
 *       输入区域在调用期间不得被其他线程修改。
 * @note errno：本函数不读取、不保存且不修改 errno。
 * @note 范围边界：不检查名称约束，不执行 Unicode 规范化，
 *       不检查 TLV 字段类型或业务长度限制；
 *       只供当前源文件内部使用。
 */
static bool vireo_tlv_utf8_is_valid(uint8_t const *data, size_t size) {
    size_t offset = 0;

    while (offset < size) {
        uint8_t const first = data[offset];

        /* 单字节编码：0xxxxxxx */
        if (first <= UINT8_C(0x7F)) {
            offset += 1U;
            continue;
        }

        /* 两字节编码：110xxxxx 10xxxxxx */
        if (first >= UINT8_C(0xC2) && first <= UINT8_C(0xDF)) {
            if (size - offset < 2U) {
                return false;
            }

            if (!vireo_tlv_utf8_is_continuation(data[offset + 1U])) {
                return false;
            }

            offset += 2U;
            continue;
        }

        /* 三字节编码：1110xxxx 10xxxxxx 10xxxxxx */
        if (first >= UINT8_C(0xE0) && first <= UINT8_C(0xEF)) {
            if (size - offset < 3U) {
                return false;
            }

            if (!vireo_tlv_utf8_is_continuation(data[offset + 1U]) ||
                !vireo_tlv_utf8_is_continuation(data[offset + 2U])) {
                return false;
            }

            /* E0 后的第二字节不能小于 A0：拒绝过长编码 */
            if (first == UINT8_C(0xE0) && data[offset + 1U] < UINT8_C(0xA0)) {
                return false;
            }

            /* ED 后的第二字节不能大于 9F：拒绝代理码点 */
            if (first == UINT8_C(0xED) && data[offset + 1U] > UINT8_C(0x9F)) {
                return false;
            }

            offset += 3U;
            continue;
        }

        /* 四字节编码：11110xxx 10xxxxxx 10xxxxxx 10xxxxxx */
        if (first >= UINT8_C(0xF0) && first <= UINT8_C(0xF4)) {
            if (size - offset < 4U) {
                return false;
            }

            if (!vireo_tlv_utf8_is_continuation(data[offset + 1U]) ||
                !vireo_tlv_utf8_is_continuation(data[offset + 2U]) ||
                !vireo_tlv_utf8_is_continuation(data[offset + 3U])) {
                return false;
            }

            /* F0 后的第二字节不能小于 90：拒绝过长编码 */
            if (first == UINT8_C(0xF0) && data[offset + 1U] < UINT8_C(0x90)) {
                return false;
            }

            /* F4 后的第二字节不能大于 8F：不得超过 U+10FFFF */
            if (first == UINT8_C(0xF4) && data[offset + 1U] > UINT8_C(0x8F)) {
                return false;
            }

            offset += 4U;
            continue;
        }

        /* 不属于任何合法首字节范围 */
        return false;
    }

    return true;
}

/**
 * @brief 在合法 UTF-8 的前提下检查名称内容约束
 *
 * 名称不得为空，不得是 "." 或 ".."，
 * 不得包含 '/'、U+0000、U+0001..U+001F
 * 或 U+007F..U+009F。
 *
 * @param[in] data
 *     已通过完整 UTF-8 验证的只读字节区域；
 *     size 为 0 时允许为 NULL。
 *
 * @param[in] size
 *     名称的字节数，不是字符数量。
 *
 * @retval true
 *     在输入满足前置条件的情况下，名称满足上述内容约束。
 *
 * @retval false
 *     名称为空，是 "." 或 ".."，
 *     或包含不允许的内容。
 *
 * @note 前置条件：输入必须已经通过完整 UTF-8 验证；
 *       size 非零时，data 必须非 NULL，
 *       并指向至少 size 个可读字节。
 * @note 输出保持：不修改输入区域。
 * @note 所有权：不接管输入区域，不分配或释放内存。
 * @note 生命周期：只在调用期间借用 data，不保存指针。
 * @note 线程安全：不使用共享可变全局状态；
 *       输入区域在调用期间不得被其他线程修改。
 * @note errno：本函数不读取、不保存且不修改 errno。
 * @note 范围边界：不重复验证 UTF-8，不解析路径，
 *       不执行 Unicode 规范化，不检查业务长度上限、
 *       名称是否存在或访问权限；只供当前源文件内部使用。
 */
static bool vireo_tlv_name_is_valid(uint8_t const *data, size_t size) {
    if (size == 0U) {
        return false;
    }

    /* 只拒绝完整名称 "." 和 ".."，不禁止普通名称包含点 */
    if (size == 1U && data[0] == UINT8_C(0x2E)) {
        return false;
    }

    if (size == 2U && data[0] == UINT8_C(0x2E) && data[1] == UINT8_C(0x2E)) {
        return false;
    }

    for (size_t offset = 0; offset < size; ++offset) {
        uint8_t const byte = data[offset];

        /* 拒绝NUL、ASCII 控制字符、DEL 和斜杠 */
        if (byte <= UINT8_C(0x1F) || byte == UINT8_C(0x7F) || byte == UINT8_C(0x2F)) {
            return false;
        }

        /* U+0080..U+009F 的 UTF-8 编码为 C2 80..C2 9F */
        if (byte == UINT8_C(0xC2) && size - offset >= 2U) {
            uint8_t const next = data[offset + 1U];

            if (next >= UINT8_C(0x80) && next <= UINT8_C(0x9F)) {
                return false;
            }
        }
    }

    return true;
}

/**
 * @brief 检查 TLV 规则表是否满足基本配置约束
 *
 * 每条规则必须满足 min_length <= max_length，
 * value_kind 必须是已定义的类别，
 * 且同一规则表中的 type 必须唯一。
 *
 * @param[in] rules
 *     要检查的只读规则数组；
 *     rule_count 为 0 时允许为 NULL。
 *
 * @param[in] rule_count
 *     rules 中的规则数量，不是数组的字节数。
 *
 * @retval true
 *     规则表满足上述配置约束；
 *     空规则表也返回 true。
 *
 * @retval false
 *     rule_count 非零但 rules 为 NULL，
 *     或存在长度范围错误、无效 value_kind、
 *     重复 type。
 *
 * @note 前置条件：rule_count 非零且 rules 非 NULL 时，
 *       rules 必须指向至少 rule_count 个生命周期内的可读规则对象，
 *       且被读取的成员已经具有确定值。
 * @note 输出保持：不修改规则数组。
 * @note 所有权：不接管规则数组，不分配或释放内存。
 * @note 生命周期：只在调用期间借用 rules，不保存指针。
 * @note 线程安全：不使用共享可变全局状态；
 *       规则数组在调用期间不得被其他线程修改。
 * @note errno：本函数不读取、不保存且不修改 errno。
 * @note 范围边界：不解析 TLV，不验证实际 value，
 *       不检查字段出现次数、业务注册表、未知字段策略
 *       或 seen 工作空间；只供当前源文件内部使用。
 */
static bool vireo_tlv_rules_are_valid(vireo_tlv_rule_t const *rules, size_t rule_count) {
    if (rule_count != 0U && rules == NULL) {
        return false;
    }

    for (size_t index = 0; index < rule_count; ++index) {
        vireo_tlv_rule_t const *rule = &rules[index];

        if (rule->min_length > rule->max_length) {
            return false;
        }

        switch (rule->value_kind) {
            case VIREO_TLV_VALUE_BYTES:
            case VIREO_TLV_VALUE_U16:
            case VIREO_TLV_VALUE_U32:
            case VIREO_TLV_VALUE_U64:
            case VIREO_TLV_VALUE_UTF8:
            case VIREO_TLV_VALUE_NAME:
                break;
            default:
                return false;
        }

        /* 当前规则只与前面的规则比较，检查 type 是否重复 */
        for (size_t previous = 0; previous < index; previous++) {
            if (rules[previous].type == rule->type) {
                return false;
            }
        }
    }

    return true;
}

/**
 * @brief 根据字段 type 查找对应规则的数组下标
 *
 * 按规则数组顺序查找。
 * 找到时返回对应下标，未找到时返回 rule_count。
 *
 * @param[in] rules
 *     已通过规则表配置检查的只读规则数组；
 *     rule_count 为 0 时允许为 NULL。
 *
 * @param[in] rule_count
 *     rules 中的规则数量，不是数组的字节数。
 *
 * @param[in] type
 *     要查找的宿主语义字段编号。
 *
 * @return
 *     找到时返回 [0, rule_count) 范围内的数组下标；
 *     未找到时返回 rule_count。
 *
 * @note 前置条件：规则表必须已经通过配置检查；
 *       rule_count 非零时，rules 必须指向至少 rule_count 个
 *       生命周期内的可读规则对象。
 * @note 输出保持：不修改规则数组。
 * @note 所有权：不接管规则数组，不分配或释放内存。
 * @note 生命周期：只在调用期间借用 rules，不保存指针。
 * @note 线程安全：不使用共享可变全局状态；
 *       规则数组在调用期间不得被其他线程修改。
 * @note errno：本函数不读取、不保存且不修改 errno。
 * @note 范围边界：不重复验证规则表，不解析 TLV，
 *       不检查 value，不修改 seen，
 *       不决定未知字段的处理策略；只供当前源文件内部使用。
 */
static size_t vireo_tlv_find_rule_index(vireo_tlv_rule_t const *rules, size_t rule_count,
                                        vireo_tlv_type_t type) {
    for (size_t index = 0; index < rule_count; ++index) {
        if (rules[index].type == type) {
            return index;
        }
    }

    return rule_count;
}

/**
 * @brief 按单条规则检查一个 TLV value 的长度和内容
 *
 * 先检查 value 长度是否位于规则的闭区间内，
 * 再按 value_kind 检查固定整数宽度、UTF-8 或名称内容。
 * NAME 必须先通过 UTF-8 检查，再检查名称约束。
 *
 * @param[in] rule
 *     已通过规则表配置检查的非空规则指针；
 *     调用者已经确认该规则对应 view->type。
 *
 * @param[in] view
 *     指向完整 TLV 字段视图的非空指针；
 *     length 非零时，value 必须指向至少 length 个可读字节。
 *     length 为 0 时，value 允许为 NULL。
 *
 * @retval VIREO_TLV_ISSUE_NONE
 *     value 满足规则的长度和内容要求。
 *
 * @retval VIREO_TLV_ISSUE_INVALID_LENGTH
 *     value 长度不在规则区间内，
 *     或不满足整数类别的固定字节数要求。
 *
 * @retval VIREO_TLV_ISSUE_INVALID_UTF8
 *     UTF8 或 NAME 类别的 value 不是合法 UTF-8。
 *
 * @retval VIREO_TLV_ISSUE_INVALID_NAME
 *     NAME 类别的 value 已通过 UTF-8 检查，
 *     但违反名称内容约束。
 *
 * @note 前置条件：rule 和 view 必须指向生命周期内的可读对象，
 *       且其成员具有确定值；规则配置、字段对应关系
 *       和 value 区域完整性由调用者先行保证。
 * @note 输出保持：不修改规则、视图或底层 value 区域。
 * @note 所有权：不接管任何对象，不分配或释放内存。
 * @note 生命周期：只在调用期间借用参数，不保存指针。
 * @note 线程安全：不使用共享可变全局状态；
 *       规则、视图和底层输入在调用期间不得被其他线程修改。
 * @note errno：本函数不读取、不保存且不修改 errno。
 * @note 范围边界：不重复验证规则表，不解析 TLV，
 *       不检查字段重复或缺失，不修改 seen，
 *       不解码整数值，也不验证业务数值范围；
 *       只供当前源文件内部使用。
 */
static vireo_tlv_issue_t vireo_tlv_value_validate(vireo_tlv_rule_t const *rule,
                                                  vireo_tlv_view_t const *view) {
    if (view->length < (size_t)rule->min_length || view->length > (size_t)rule->max_length) {
        return VIREO_TLV_ISSUE_INVALID_LENGTH;
    }

    switch (rule->value_kind) {
        case VIREO_TLV_VALUE_BYTES:
            return VIREO_TLV_ISSUE_NONE;
        case VIREO_TLV_VALUE_U16:
            if (view->length != 2U) {
                return VIREO_TLV_ISSUE_INVALID_LENGTH;
            }
            return VIREO_TLV_ISSUE_NONE;
        case VIREO_TLV_VALUE_U32:
            if (view->length != 4U) {
                return VIREO_TLV_ISSUE_INVALID_LENGTH;
            }
            return VIREO_TLV_ISSUE_NONE;
        case VIREO_TLV_VALUE_U64:
            if (view->length != 8U) {
                return VIREO_TLV_ISSUE_INVALID_LENGTH;
            }
            return VIREO_TLV_ISSUE_NONE;
        case VIREO_TLV_VALUE_UTF8:
            if (!vireo_tlv_utf8_is_valid(view->value, view->length)) {
                return VIREO_TLV_ISSUE_INVALID_UTF8;
            }
            return VIREO_TLV_ISSUE_NONE;
        case VIREO_TLV_VALUE_NAME:
            if (!vireo_tlv_utf8_is_valid(view->value, view->length)) {
                return VIREO_TLV_ISSUE_INVALID_UTF8;
            }
            if (!vireo_tlv_name_is_valid(view->value, view->length)) {
                return VIREO_TLV_ISSUE_INVALID_NAME;
            }
            return VIREO_TLV_ISSUE_NONE;
        default:
            return VIREO_TLV_ISSUE_INVALID_LENGTH;
    }
}

/* 初始化 TLV writer；只设置状态，不修改底层缓冲区 */
vireo_result_t vireo_tlv_writer_init(vireo_tlv_writer_t *out_writer, uint8_t *data,
                                     size_t capacity) {
    if (out_writer == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }

    if (data == NULL && capacity != 0U) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }

    out_writer->data = data;
    out_writer->capacity = capacity;
    out_writer->used = 0U;

    return VIREO_OK;
}

/* 向 writer 追加完整tlv；所有失败检查均在修改输出之前完成 */
vireo_result_t vireo_tlv_writer_put(vireo_tlv_writer_t *writer, vireo_tlv_type_t type,
                                    const uint8_t *value, size_t value_size) {
    if (!vireo_tlv_writer_is_valid(writer)) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }

    if (value == NULL && value_size != 0U) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }

    if (value_size > (size_t)VIREO_TLV_MAX_VALUE_SIZE) {
        return VIREO_RESULT_RANGE;
    }

    size_t tlv_size;
    vireo_result_t result =
        vireo_checked_size_add((size_t)VIREO_TLV_HEADER_SIZE, value_size, &tlv_size);
    if (result != VIREO_OK) {
        return result;
    }

    size_t new_used;
    result = vireo_checked_size_add(writer->used, tlv_size, &new_used);
    if (result != VIREO_OK) {
        return result;
    }

    if (new_used > writer->capacity) {
        return VIREO_RESULT_RANGE;
    }

    /* 从这里开始不再返回失败；容量检查通过后才计算写入位置 */
    uint8_t *wire = writer->data + writer->used;

    vireo_tlv_write_u16_be(wire + VIREO_TLV_TYPE_OFFSET, type);
    vireo_tlv_write_u16_be(wire + VIREO_TLV_LENGTH_OFFSET, (uint16_t)value_size);

    if (value_size != 0U) {
        memcpy(wire + VIREO_TLV_HEADER_SIZE, value, value_size);
    }

    writer->used = new_used;

    return VIREO_OK;
}

/* 将 uint16_t 编码为两个大端字节，再追加完整 TLV */
vireo_result_t vireo_tlv_writer_put_u16(vireo_tlv_writer_t *writer, vireo_tlv_type_t type,
                                        uint16_t value) {
    uint8_t encoded[2];

    vireo_tlv_write_u16_be(encoded, value);

    return vireo_tlv_writer_put(writer, type, encoded, sizeof(encoded));
}

/* 将 uint32_t 编码为四个大端字节，再追加完整 TLV */
vireo_result_t vireo_tlv_writer_put_u32(vireo_tlv_writer_t *writer, vireo_tlv_type_t type,
                                        uint32_t value) {
    uint8_t encoded[4];

    vireo_tlv_write_u32_be(encoded, value);

    return vireo_tlv_writer_put(writer, type, encoded, sizeof(encoded));
}

/* 将 uint64_t 编码为八个大端字节，再追加完整 TLV */
vireo_result_t vireo_tlv_writer_put_u64(vireo_tlv_writer_t *writer, vireo_tlv_type_t type,
                                        uint64_t value) {
    uint8_t encoded[8];

    vireo_tlv_write_u64_be(encoded, value);

    return vireo_tlv_writer_put(writer, type, encoded, sizeof(encoded));
}

/* 初始化 TLV reader；只设置状态，不解析或修改输入区域 */
vireo_result_t vireo_tlv_reader_init(vireo_tlv_reader_t *out_reader, const uint8_t *data,
                                     size_t size) {
    if (out_reader == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }

    if (data == NULL && size != 0U) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }

    out_reader->data = data;
    out_reader->size = size;
    out_reader->offset = 0U;

    return VIREO_OK;
}

/* 读取下一条完整 TLV；成功后才提交视图并推进 reader */
vireo_result_t vireo_tlv_reader_next(vireo_tlv_reader_t *reader, vireo_tlv_view_t *out_view,
                                     vireo_tlv_issue_t *out_issue) {
    if (out_issue != NULL) {
        *out_issue = VIREO_TLV_ISSUE_NONE;
    }

    if (out_view == NULL || out_issue == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }

    if (!vireo_tlv_reader_is_valid(reader)) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }

    if (reader->offset == reader->size) {
        return VIREO_RESULT_NOT_FOUND;
    }

    size_t const remaining = reader->size - reader->offset;
    if (remaining < (size_t)VIREO_TLV_HEADER_SIZE) {
        *out_issue = VIREO_TLV_ISSUE_TRUNCATED_HEADER;
        return VIREO_RESULT_PROTOCOL;
    }

    uint8_t const *wire = reader->data + reader->offset;

    size_t const value_size = (size_t)vireo_tlv_read_u16_be(wire + VIREO_TLV_LENGTH_OFFSET);

    if (value_size > remaining - (size_t)VIREO_TLV_HEADER_SIZE) {
        *out_issue = VIREO_TLV_ISSUE_TRUNCATED_VALUE;
        return VIREO_RESULT_PROTOCOL;
    }

    vireo_tlv_view_t const view = {
        .type = vireo_tlv_read_u16_be(wire + (size_t)VIREO_TLV_TYPE_OFFSET),
        .length = value_size,
        .value = wire + VIREO_TLV_HEADER_SIZE};

    /* 确认了整条 TLV 位于剩余输入内，以下加法不会超过 size */
    size_t const next_offset = reader->offset + (size_t)VIREO_TLV_HEADER_SIZE + value_size;

    *out_view = view;
    reader->offset = next_offset;

    return VIREO_OK;
}

/* 从 view 的两个大端 value 字节解码 uint16_t */
vireo_result_t vireo_tlv_view_read_u16(vireo_tlv_view_t const *view, uint16_t *out_value) {
    if (view == NULL || out_value == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }

    if (view->value == NULL && view->length != 0U) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }

    if (view->length != 2U) {
        return VIREO_RESULT_PROTOCOL;
    }

    *out_value = vireo_tlv_read_u16_be(view->value);

    return VIREO_OK;
}

/* 从 view 的四个大端 value 字节解码 uint32_t */
vireo_result_t vireo_tlv_view_read_u32(vireo_tlv_view_t const *view, uint32_t *out_value) {
    if (view == NULL || out_value == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }

    if (view->value == NULL && view->length != 0U) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }

    if (view->length != 4U) {
        return VIREO_RESULT_PROTOCOL;
    }

    *out_value = vireo_tlv_read_u32_be(view->value);

    return VIREO_OK;
}

/* 从 view 的八个大端 value 字节解码 uint64_t */
vireo_result_t vireo_tlv_view_read_u64(vireo_tlv_view_t const *view, uint64_t *out_value) {
    if (view == NULL || out_value == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }

    if (view->value == NULL && view->length != 0U) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }

    if (view->length != 8U) {
        return VIREO_RESULT_PROTOCOL;
    }

    *out_value = vireo_tlv_read_u64_be(view->value);

    return VIREO_OK;
}

/* 按规则表验证完整 TLV 输入；先检查配置，再解析并验证字段 */
vireo_result_t vireo_tlv_schema_validate(uint8_t const *data, size_t size,
                                         vireo_tlv_rule_t const *rules, size_t rule_count,
                                         vireo_tlv_unknown_policy_t unknown_policy, uint8_t *seen,
                                         size_t seen_capacity, vireo_tlv_issue_t *out_issue) {
    if (out_issue != NULL) {
        *out_issue = VIREO_TLV_ISSUE_NONE;
    }

    if (out_issue == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }

    if (data == NULL && size != 0U) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }

    if (rule_count != 0U && (rules == NULL || seen == NULL)) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }

    if (unknown_policy != VIREO_TLV_UNKNOWN_REJECT && unknown_policy != VIREO_TLV_UNKNOWN_SKIP) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }

    if (seen_capacity < rule_count) {
        return VIREO_RESULT_RANGE;
    }

    if (!vireo_tlv_rules_are_valid(rules, rule_count)) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }

    if (rule_count != 0U) {
        memset(seen, 0, rule_count);
    }

    vireo_tlv_reader_t reader;
    vireo_result_t result = vireo_tlv_reader_init(&reader, data, size);
    if (result != VIREO_OK) {
        return result;
    }

    for (;;) {
        vireo_tlv_view_t view;

        result = vireo_tlv_reader_next(&reader, &view, out_issue);

        if (result == VIREO_RESULT_NOT_FOUND) {
            break;
        }

        if (result != VIREO_OK) {
            return result;
        }

        size_t const rule_index = vireo_tlv_find_rule_index(rules, rule_count, view.type);

        if (rule_index == rule_count) {
            if (unknown_policy == VIREO_TLV_UNKNOWN_REJECT) {
                *out_issue = VIREO_TLV_ISSUE_UNKNOWN_TYPE;
                return VIREO_RESULT_PROTOCOL;
            }

            continue;
        }

        vireo_tlv_rule_t const *rule = &rules[rule_index];

        if (seen[rule_index] != 0U && !rule->repeatable) {
            *out_issue = VIREO_TLV_ISSUE_DUPLICATE_FIELD;
            return VIREO_RESULT_PROTOCOL;
        }

        vireo_tlv_issue_t const issue = vireo_tlv_value_validate(rule, &view);

        if (issue != VIREO_TLV_ISSUE_NONE) {
            *out_issue = issue;
            return VIREO_RESULT_PROTOCOL;
        }

        seen[rule_index] = UINT8_C(1);
    }

    /* 只有完整解析结束后，才能判断必填字段是否缺失 */
    for (size_t index = 0; index < rule_count; ++index) {
        if (rules[index].required && seen[index] == 0U) {
            *out_issue = VIREO_TLV_ISSUE_MISSING_REQUIRED_FIELD;
            return VIREO_RESULT_PROTOCOL;
        }
    }

    return VIREO_OK;
}
