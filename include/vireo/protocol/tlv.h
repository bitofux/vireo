/*
 * PROJECT : VIREO
 * FILE    : tlv.h
 * AUTHOR  : bitofux
 * DATE    : 2026-09-08
 * BRIEF   : vireo TLV 显式编解码与通用 schema 验证
 *
 * -- wire 格式为 type:u16 | len:u16 | value:len bytes
 * -- type、len 和整数 value 使用 big-endian
 * -- writer 使用调用者提供的有界缓冲区
 * -- reader 返回借用视图，不复制 value
 * -- schema 检查必填、重复、长度、内容和未知字段策略
 * -- 不动态分配，不执行 I/O，不修改 errno
 */

#ifndef VIREO_PROTOCOL_TLV_H
#define VIREO_PROTOCOL_TLV_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <vireo/base/result.h>

/* TLV wire header 中 type 字段的起始 offset。 */
#define VIREO_TLV_TYPE_OFFSET UINT32_C(0)

/* TLV wire header 中 len 字段的起始 offset。 */
#define VIREO_TLV_LENGTH_OFFSET UINT32_C(2)

/* type 和 len 各占两个字节，固定 header 共四个字节。 */
#define VIREO_TLV_HEADER_SIZE UINT32_C(4)

/* len 为无符号 16 位整数，仅计算 value 的字节数。 */
#define VIREO_TLV_MAX_VALUE_SIZE UINT32_C(65535)

/*
 * 公共约定：
 *
 * -- 以下结构体均为宿主语义对象，不是 wire 布局。
 * -- 禁止直接发送结构体或依赖结构体 padding 进行编解码。
 * -- 缓冲区和对象均由调用者创建、持有和销毁。
 * -- 非空指针必须指向有效对象，声明的长度必须符合真实对象边界。
 * -- 本模块不能判断任意非空指针是否指向有效存储。
 *
 * 借用与别名：
 *
 * -- reader、writer 和 view 可以保存借用指针，但不释放底层存储。
 * -- 借用期间，调用者必须保证底层存储有效。
 * -- 除返回的 view 引用输入区域外，可写输出对象不得与输入区域
 *    或其他可写对象重叠。
 * -- writer 对象不得位于其底层输出缓冲区内。
 * -- writer_put 的 value 区域不得与 writer 底层缓冲区重叠。
 *
 * 线程安全：
 *
 * -- 本模块不使用共享可变全局状态。
 * -- 独立对象和互不冲突的缓冲区可以并发使用。
 * -- 同一 writer、reader 或工作空间的并发访问由调用者同步。
 * -- 只读输入在调用期间不得被其他线程修改。
 */

/**
 * @brief TLV 字段编号的宿主语义类型
 *
 * wire 中的 type 使用两个 big-endian 字节表示。
 * 此 typedef 只规定编号的表示类型，不分配具体业务字段编号。
 */
typedef uint16_t vireo_tlv_type_t;

/**
 * @brief 描述 TLV 解析或 schema 验证发现的具体问题
 *
 * 本枚举只用于进程内部诊断，不是 wire 字段或响应状态码，
 * 不可以直接序列化或强制转换为协议响应状态。
 */
typedef enum vireo_tlv_issue {
    VIREO_TLV_ISSUE_NONE = 0,
    /**< 未发现 TLV 问题。 */

    VIREO_TLV_ISSUE_TRUNCATED_HEADER = 1,
    /**< 输入末尾不足四个字节，无法组成完整 TLV header。 */

    VIREO_TLV_ISSUE_TRUNCATED_VALUE = 2,
    /**< 剩余输入不足以容纳 len 声明的完整 value。 */

    VIREO_TLV_ISSUE_UNKNOWN_TYPE = 3,
    /**< type 不在当前规则表中，且未知字段策略为拒绝。 */

    VIREO_TLV_ISSUE_INVALID_LENGTH = 4,
    /**< value 长度不满足范围或固定整数宽度要求。 */

    VIREO_TLV_ISSUE_DUPLICATE_FIELD = 5,
    /**< 不允许重复的字段出现了多次。 */

    VIREO_TLV_ISSUE_MISSING_REQUIRED_FIELD = 6,
    /**< 完整解析结束后，仍有必填字段未出现。 */

    VIREO_TLV_ISSUE_INVALID_UTF8 = 7,
    /**< value 不是完整、合法的 UTF-8 字节序列。 */

    VIREO_TLV_ISSUE_INVALID_NAME = 8
    /**< value 是合法 UTF-8，但违反名称规则。 */
} vireo_tlv_issue_t;

/**
 * @brief 当前 schema 遇到未登记字段时的处理策略
 *
 * 未登记表示 type 不在当前规则表中，
 * 不表示整个协议一定没有定义过这个 type。
 */
typedef enum vireo_tlv_unknown_policy {
    VIREO_TLV_UNKNOWN_REJECT = 0,
    /**< 拒绝不在当前规则表中的字段 */

    VIREO_TLV_UNKNOWN_SKIP = 1,
    /**< 跳过未知字段的内容检查，但仍要求 TLV 结构完整 */
} vireo_tlv_unknown_policy_t;

/**
 * @brief schema 对 value 采用的内容检查方式
 *
 * 本枚举属于宿主侧验证规则，不进入 wire。
 * value_kind 的要求与规则中的长度范围必须同时满足。
 */
typedef enum vireo_tlv_value_kind {
    VIREO_TLV_VALUE_BYTES = 0,
    /**< 原始字节，只检查长度范围，不解释内容 */

    VIREO_TLV_VALUE_U16 = 1,
    /**< 无符号大端整数，value 必须恰好为两个字节 */

    VIREO_TLV_VALUE_U32 = 2,
    /**< 无符号大端整数，value 必须恰好为四个字节 */

    VIREO_TLV_VALUE_U64 = 3,
    /**< 无符号大端整数，value 必须恰好为八个字节 */

    VIREO_TLV_VALUE_UTF8 = 4,
    /**< 完整、合法的 UTF-8；此类别本身不禁止 U+0000 */

    VIREO_TLV_VALUE_NAME = 5,
    /**< 合法 UTF-8，并且满足下述名称规则 */
} vireo_tlv_value_kind_t;

/*
 * UTF-8 与名称规则：
 *
 * -- UTF-8 检查拒绝截断、非法起始字节、非法续字节、
 *    过长编码、surrogate 编码和大于 U+10FFFF 的值。
 * -- 空字节序列属于合法 UTF-8；是否允许为空由长度规则决定。
 *
 * NAME 在合法 UTF-8 的基础上还要求：
 *
 * -- 不为空；
 * -- 不是 "." 或 ".."；
 * -- 不包含 '/'；
 * -- 不包含 U+0000；
 * -- 不包含 U+0001..U+001F；
 * -- 不包含 U+007F..U+009F。
 *
 * NAME 不执行 Unicode 规范化，不查询文件系统，
 * 不检查名称是否存在，也不检查访问权限。
 */

/**
 * @brief 使用调用者缓冲区的有界 TLV writer
 *
 * 必须通过 vireo_tlv_writer_init() 初始化。
 * 初始化后，调用者可以读取成员，但不得直接修改成员。
 *
 * 有效状态要求：
 * -- used <= capacity；
 * -- data 为 NULL 时，capacity 必须为 0。
 */
typedef struct vireo_tlv_writer {
    uint8_t *data;
    /**< 借用的可写缓冲区，不拥有该存储 */

    size_t capacity;
    /**< 缓冲区总容量，以字节为单位 */

    size_t used;
    /**< 已经成功写入的字节数，也是下一条 TLV 的写入起始位置 */
} vireo_tlv_writer_t;

/**
 * @brief 使用调用者输入区域的有界 TLV reader
 *
 * 必须通过 vireo_tlv_reader_init() 初始化。
 * 初始化后，调用者可以读取成员，但不得直接修改成员。
 *
 * 有效状态要求：
 * -- offset <= size；
 * -- data 为 NULL 时，size 必须为 0。
 */
typedef struct vireo_tlv_reader {
    uint8_t const *data;
    /**< 借用的只读 TLV 输入区域，不拥有该存储 */

    size_t size;
    /**< 输入区域总字节数 */

    size_t offset;
    /**< 下一条 TLV 的读取位置 */
} vireo_tlv_reader_t;

/**
 * @brief 单个 TLV 字段的宿主语义借用视图
 *
 * value 引用原始输入中的字节，不进行复制，也不拥有该存储。
 * length 不包含四字节 TLV header。
 *
 * @note length 为 0 时不得解引用 value。
 * @note value 不保证以 NUL 结尾，不能直接当作 C 字符串使用。
 * @note reader 前进不会使已有 view 自动失效；
 *       原始输入被释放、失效或覆盖后，该 view 不再可用。
 */
typedef struct vireo_tlv_view {
    vireo_tlv_type_t type;
    /**< 解码后的宿主语义字段编号 */

    uint8_t const *value;
    /**< 指向输入区域内的 value，不拥有该存储 */

    size_t length;
    /**< value 字节数，由 reader 生成时不超过 65535 */
} vireo_tlv_view_t;

/**
 * @brief 一种 TLV 字段的 schema 规则
 *
 * 同一规则表中的 type 必须唯一。
 * min_length 和 max_length 均包含端点，且 min_length <= max_length。
 *
 * required 与 repeatable 分别表达两个独立约束：
 *
 * -- 非必填、不可重复：允许出现 0 或 1 次；
 * -- 必填、不可重复：必须恰好出现 1 次；
 * -- 非必填、可重复：允许出现 0 次或多次；
 * -- 必填、可重复：必须至少出现 1 次。
 *
 * @note 可重复字段的每次出现都必须独立满足长度和内容规则。
 * @note 整数类别通常将 min_length 与 max_length
 *       都设置为对应的 2、4 或 8。
 */
typedef struct vireo_tlv_rule {
    vireo_tlv_type_t type;
    /**< 此规则对应的字段编号 */

    uint16_t min_length;
    /**< 单次 value 的最小字节数，包含端点 */

    uint16_t max_length;
    /**< 单次 value 的最大字节数，包含端点 */

    vireo_tlv_value_kind_t value_kind;
    /**< value 的内容检查方式 */

    bool required;
    /**< 是否要求至少出现一次 */

    bool repeatable;
    /**< 是否允许出现多次 */
} vireo_tlv_rule_t;

/**
 * @brief 使用调用者提供的缓冲区初始化 TLV writer
 *
 * 成功时保存 data 和 capacity，并将 used 设置为 0。
 * 本函数只初始化 writer，不清空底层缓冲区。
 *
 * @param[out] out_writer
 *     接收初始化结果的非空指针；调用者保留所有权。
 *
 * @param[in] data
 *     writer 后续使用的可写缓冲区。
 *     capacity 为 0 时允许为 NULL；
 *     capacity 大于 0 时必须指向至少 capacity 个可写字节。
 *     本函数只保存指针，不修改该区域。
 *
 * @param[in] capacity
 *     data 指向的缓冲区容量，以字节为单位。
 *
 * @retval VIREO_OK
 *     初始化成功，out_writer->used 为 0。
 *
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     out_writer 为 NULL，或者 capacity 大于 0 但 data 为 NULL。
 *
 * @note 输出保持：失败时不修改 *out_writer；
 *       无论成功或失败，本函数都不修改底层缓冲区。
 * @note 所有权：不接管 out_writer 或 data 的所有权。
 * @note 生命周期：成功后 writer 保存 data 的借用指针；
 *       后续使用 writer 时，底层缓冲区必须保持有效。
 * @note 别名约束：out_writer 对象不得与底层缓冲区重叠。
 * @note 线程安全：不使用共享可变全局状态；
 *       同一 writer 的并发访问需要调用者同步。
 * @note errno：本函数不读取、不保存且不修改 errno。
 * @note 范围边界：不编码 TLV，不验证字段编号或 schema。
 */
vireo_result_t vireo_tlv_writer_init(vireo_tlv_writer_t *out_writer, uint8_t *data,
                                     size_t capacity);

/**
 * @brief 向 writer 追加一条完整 TLV
 *
 * type 和 value_size 被显式编码为两个 big-endian u16 字段，
 * 随后复制 value_size 个 value 字节。
 * 单条 TLV 的总字节数为四字节 header 加 value_size。
 *
 * @param[in,out] writer
 *     已初始化的非空 writer。
 *     成功时修改底层缓冲区并增加 used。
 *
 * @param[in] type
 *     要编码的宿主语义字段编号。
 *     本函数不要求该编号出现在某个业务注册表中。
 *
 * @param[in] value
 *     要复制的只读 value 字节区域。
 *     value_size 为 0 时允许为 NULL；
 *     value_size 大于 0 时必须指向至少 value_size 个可读字节。
 *
 * @param[in] value_size
 *     value 的实际字节数，不包含 TLV header；
 *     必须不超过 VIREO_TLV_MAX_VALUE_SIZE。
 *
 * @retval VIREO_OK
 *     完整 TLV 已写入，writer->used 已增加相应字节数。
 *
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     writer 为 NULL，writer 状态无效，
 *     或者 value_size 大于 0 但 value 为 NULL。
 *
 * @retval VIREO_RESULT_RANGE
 *     value_size 超过单个 value 的硬上限，
 *     或者 writer 剩余容量不足。
 *
 * @retval VIREO_RESULT_OVERFLOW
 *     需要计算的长度无法由 size_t 表示。
 *
 * @note 输出保持：失败时 writer 状态和整个底层缓冲区保持不变。
 * @note 所有权：不接管 writer、底层缓冲区或 value 的所有权。
 * @note 生命周期：不保存 value 指针；成功时 value 字节已经复制。
 *       writer 对底层缓冲区的既有借用关系保持不变。
 * @note 别名约束：value 区域不得与 writer 底层缓冲区重叠；
 *       writer 对象不得位于该缓冲区内。
 * @note 线程安全：不使用共享可变全局状态；
 *       同一 writer 或底层缓冲区的并发修改需要调用者同步。
 * @note errno：本函数不读取、不保存且不修改 errno。
 * @note 范围边界：不解释 value，不验证 schema，不计算 CRC，
 *       不检查整帧 body 硬上限。
 */
vireo_result_t vireo_tlv_writer_put(vireo_tlv_writer_t *writer, vireo_tlv_type_t type,
                                    uint8_t const *value, size_t value_size);

/**
 * @brief 将宿主语义 uint16_t 编码为 big-endian value 并追加 TLV
 *
 * 生成的 value 长度为两个字节，整条 TLV 长度为六个字节。
 *
 * @param[in,out] writer
 *     已初始化的非空 writer；成功时追加 TLV 并增加 used。
 *
 * @param[in] type
 *     要编码的宿主语义字段编号。
 *
 * @param[in] value
 *     要编码的宿主语义 uint16_t 数值。
 *
 * @retval VIREO_OK
 *     TLV 已完整追加。
 *
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     writer 为 NULL 或 writer 状态无效。
 *
 * @retval VIREO_RESULT_RANGE
 *     writer 剩余容量不足。
 *
 * @retval VIREO_RESULT_OVERFLOW
 *     需要计算的长度无法由 size_t 表示。
 *
 * @note 输出保持：失败时 writer 状态和整个底层缓冲区保持不变。
 * @note 所有权：不接管 writer 或底层缓冲区的所有权。
 * @note 生命周期：不增加新的外部指针借用；
 *       writer 的底层缓冲区必须保持有效。
 * @note 线程安全：同一 writer 或底层缓冲区的并发修改
 *       需要调用者同步。
 * @note errno：本函数不读取、不保存且不修改 errno。
 * @note 范围边界：不检查 type 在业务上是否对应 uint16_t。
 */
vireo_result_t vireo_tlv_writer_put_u16(vireo_tlv_writer_t *writer, vireo_tlv_type_t type,
                                        uint16_t value);

/**
 * @brief 将宿主语义 uint32_t 编码为 big-endian value 并追加 TLV
 *
 * 生成的 value 长度为四个字节，整条 TLV 长度为八个字节。
 *
 * @param[in,out] writer
 *     已初始化的非空 writer；成功时追加 TLV 并增加 used。
 *
 * @param[in] type
 *     要编码的宿主语义字段编号。
 *
 * @param[in] value
 *     要编码的宿主语义 uint32_t 数值。
 *
 * @retval VIREO_OK
 *     TLV 已完整追加。
 *
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     writer 为 NULL 或 writer 状态无效。
 *
 * @retval VIREO_RESULT_RANGE
 *     writer 剩余容量不足。
 *
 * @retval VIREO_RESULT_OVERFLOW
 *     需要计算的长度无法由 size_t 表示。
 *
 * @note 输出保持：失败时 writer 状态和整个底层缓冲区保持不变。
 * @note 所有权：不接管 writer 或底层缓冲区的所有权。
 * @note 生命周期：不增加新的外部指针借用；
 *       writer 的底层缓冲区必须保持有效。
 * @note 线程安全：同一 writer 或底层缓冲区的并发修改
 *       需要调用者同步。
 * @note errno：本函数不读取、不保存且不修改 errno。
 * @note 范围边界：不检查 type 在业务上是否对应 uint32_t。
 */
vireo_result_t vireo_tlv_writer_put_u32(vireo_tlv_writer_t *writer, vireo_tlv_type_t type,
                                        uint32_t value);

/**
 * @brief 将宿主语义 uint64_t 编码为 big-endian value 并追加 TLV
 *
 * 生成的 value 长度为八个字节，整条 TLV 长度为十二个字节。
 *
 * @param[in,out] writer
 *     已初始化的非空 writer；成功时追加 TLV 并增加 used。
 *
 * @param[in] type
 *     要编码的宿主语义字段编号。
 *
 * @param[in] value
 *     要编码的宿主语义 uint64_t 数值。
 *
 * @retval VIREO_OK
 *     TLV 已完整追加。
 *
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     writer 为 NULL 或 writer 状态无效。
 *
 * @retval VIREO_RESULT_RANGE
 *     writer 剩余容量不足。
 *
 * @retval VIREO_RESULT_OVERFLOW
 *     需要计算的长度无法由 size_t 表示。
 *
 * @note 输出保持：失败时 writer 状态和整个底层缓冲区保持不变。
 * @note 所有权：不接管 writer 或底层缓冲区的所有权。
 * @note 生命周期：不增加新的外部指针借用；
 *       writer 的底层缓冲区必须保持有效。
 * @note 线程安全：同一 writer 或底层缓冲区的并发修改
 *       需要调用者同步。
 * @note errno：本函数不读取、不保存且不修改 errno。
 * @note 范围边界：不检查 type 在业务上是否对应 uint64_t。
 */
vireo_result_t vireo_tlv_writer_put_u64(vireo_tlv_writer_t *writer, vireo_tlv_type_t type,
                                        uint64_t value);

/**
 * @brief 使用调用者提供的只读输入区域初始化 TLV reader
 *
 * 成功时保存 data 和 size，并将 offset 设置为 0。
 * 本函数不提前扫描或验证输入中的 TLV。
 *
 * @param[out] out_reader
 *     接收初始化结果的非空指针；调用者保留所有权。
 *
 * @param[in] data
 *     只读 TLV 输入区域。
 *     size 为 0 时允许为 NULL；
 *     size 大于 0 时必须指向至少 size 个可读字节。
 *
 * @param[in] size
 *     输入区域总字节数。
 *
 * @retval VIREO_OK
 *     初始化成功，out_reader->offset 为 0。
 *
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     out_reader 为 NULL，或者 size 大于 0 但 data 为 NULL。
 *
 * @note 输出保持：失败时不修改 *out_reader。
 * @note 所有权：不接管 out_reader 或 data 的所有权。
 * @note 生命周期：成功后 reader 保存 data 的借用指针；
 *       后续读取期间，输入存储必须保持有效且内容不变。
 * @note 别名约束：out_reader 对象不得与输入区域重叠。
 * @note 线程安全：不使用共享可变全局状态；
 *       同一 reader 的并发访问需要调用者同步。
 * @note errno：本函数不读取、不保存且不修改 errno。
 * @note 范围边界：初始化成功不代表输入具有合法 TLV 结构，
 *       也不代表输入满足任何 schema。
 */
vireo_result_t vireo_tlv_reader_init(vireo_tlv_reader_t *out_reader, uint8_t const *data,
                                     size_t size);

/**
 * @brief 读取下一条完整 TLV，并返回其宿主语义借用视图
 *
 * 本函数验证四字节 TLV header 和 len 声明的 value 是否完整。
 * 只有成功读出完整 TLV 后，才提交 view 并推进 reader->offset。
 *
 * @param[in,out] reader
 *     已初始化的非空 reader。
 *     成功读取时，offset 前进四字节 header 加 value 长度。
 *
 * @param[out] out_view
 *     接收当前 TLV 借用视图的非空指针。
 *     只有返回 VIREO_OK 时才写入。
 *
 * @param[out] out_issue
 *     接收具体 TLV 问题的非空指针。
 *     只要该指针非 NULL，函数在检查其他参数前先写入 NONE。
 *
 * @retval VIREO_OK
 *     成功读取一条完整 TLV；
 *     *out_view 已提交，reader 已推进，*out_issue 为 NONE。
 *
 * @retval VIREO_RESULT_NOT_FOUND
 *     reader->offset 恰好等于 reader->size，没有下一条 TLV。
 *     这是正常遍历结束，不是协议错误；*out_issue 为 NONE。
 *
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     reader、out_view 或 out_issue 为 NULL，
 *     或者 reader 状态无效。
 *
 * @retval VIREO_RESULT_PROTOCOL
 *     剩余输入不足四字节 header，issue 为 TRUNCATED_HEADER；
 *     或者 value 不完整，issue 为 TRUNCATED_VALUE。
 *
 * @note 输出保持：返回值不是 VIREO_OK 时，
 *       reader 状态和 *out_view 保持不变；
 *       out_issue 按上述诊断规则写入。
 * @note 所有权：不接管 reader、out_view、out_issue
 *       或输入区域的所有权。
 * @note 生命周期：成功后的 out_view->value 借用原始输入；
 *       使用 view 期间，输入存储必须保持有效且内容不变。
 * @note 完整消费：仅 offset == size 表示正常结束；
 *       残缺的尾部 header 或 value 不能当作正常结束。
 * @note 线程安全：同一 reader 的并发访问需要调用者同步；
 *       输入不得被其他线程并发修改。
 * @note errno：本函数不读取、不保存且不修改 errno。
 * @note 范围边界：不检查字段是否必填、重复或未知，
 *       不解释 value 内容，不验证 CRC。
 */
vireo_result_t vireo_tlv_reader_next(vireo_tlv_reader_t *reader, vireo_tlv_view_t *out_view,
                                     vireo_tlv_issue_t *out_issue);

/**
 * @brief 从 TLV view 的两个 big-endian value 字节解码 uint16_t
 *
 * @param[in] view
 *     要读取的非空只读视图。
 *     length 非零时，value 必须非 NULL，
 *     并指向至少 length 个可读字节。
 *
 * @param[out] out_value
 *     接收宿主语义 uint16_t 数值的非空指针。
 *     只有返回 VIREO_OK 时才写入。
 *
 * @retval VIREO_OK
 *     解码成功，*out_value 已写入宿主语义数值。
 *
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     view 或 out_value 为 NULL，
 *     或者 view->length 非零但 view->value 为 NULL。
 *
 * @retval VIREO_RESULT_PROTOCOL
 *     view->length 不等于 2。
 *
 * @note 输出保持：失败时不修改 *out_value。
 * @note 所有权：不接管 view、value 存储或 out_value 的所有权。
 * @note 生命周期：只在调用期间借用，不保存任何指针。
 * @note 检查顺序：先检查必需指针，再检查固定 value 长度。
 * @note 线程安全：只读输入可以共享；
 *       输出写入或输入的并发修改需要调用者同步。
 * @note errno：本函数不读取、不保存且不修改 errno。
 * @note 范围边界：不检查 view->type，不验证业务数值范围。
 */
vireo_result_t vireo_tlv_view_read_u16(vireo_tlv_view_t const *view, uint16_t *out_value);

/**
 * @brief 从 TLV view 的四个 big-endian value 字节解码 uint32_t
 *
 * @param[in] view
 *     要读取的非空只读视图。
 *     length 非零时，value 必须非 NULL，
 *     并指向至少 length 个可读字节。
 *
 * @param[out] out_value
 *     接收宿主语义 uint32_t 数值的非空指针。
 *     只有返回 VIREO_OK 时才写入。
 *
 * @retval VIREO_OK
 *     解码成功，*out_value 已写入宿主语义数值。
 *
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     view 或 out_value 为 NULL，
 *     或者 view->length 非零但 view->value 为 NULL。
 *
 * @retval VIREO_RESULT_PROTOCOL
 *     view->length 不等于 4。
 *
 * @note 输出保持：失败时不修改 *out_value。
 * @note 所有权：不接管 view、value 存储或 out_value 的所有权。
 * @note 生命周期：只在调用期间借用，不保存任何指针。
 * @note 检查顺序：先检查必需指针，再检查固定 value 长度。
 * @note 线程安全：只读输入可以共享；
 *       输出写入或输入的并发修改需要调用者同步。
 * @note errno：本函数不读取、不保存且不修改 errno。
 * @note 范围边界：不检查 view->type，不验证业务数值范围。
 */
vireo_result_t vireo_tlv_view_read_u32(vireo_tlv_view_t const *view, uint32_t *out_value);

/**
 * @brief 从 TLV view 的八个 big-endian value 字节解码 uint64_t
 *
 * @param[in] view
 *     要读取的非空只读视图。
 *     length 非零时，value 必须非 NULL，
 *     并指向至少 length 个可读字节。
 *
 * @param[out] out_value
 *     接收宿主语义 uint64_t 数值的非空指针。
 *     只有返回 VIREO_OK 时才写入。
 *
 * @retval VIREO_OK
 *     解码成功，*out_value 已写入宿主语义数值。
 *
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     view 或 out_value 为 NULL，
 *     或者 view->length 非零但 view->value 为 NULL。
 *
 * @retval VIREO_RESULT_PROTOCOL
 *     view->length 不等于 8。
 *
 * @note 输出保持：失败时不修改 *out_value。
 * @note 所有权：不接管 view、value 存储或 out_value 的所有权。
 * @note 生命周期：只在调用期间借用，不保存任何指针。
 * @note 检查顺序：先检查必需指针，再检查固定 value 长度。
 * @note 线程安全：只读输入可以共享；
 *       输出写入或输入的并发修改需要调用者同步。
 * @note errno：本函数不读取、不保存且不修改 errno。
 * @note 范围边界：不检查 view->type，不验证业务数值范围。
 */
vireo_result_t vireo_tlv_view_read_u64(vireo_tlv_view_t const *view, uint64_t *out_value);

/**
 * @brief 按调用者提供的 schema 验证完整 TLV 输入区域
 *
 * 本函数完整解析输入，并验证：
 *
 * -- 未知字段是否允许跳过；
 * -- 不可重复字段是否出现多次；
 * -- 每次 value 长度是否满足规则；
 * -- value 是否满足整数宽度、UTF-8 或名称规则；
 * -- 完整解析结束后，所有必填字段是否都已出现。
 *
 * @param[in] data
 *     只读 TLV 输入区域。
 *     size 为 0 时允许为 NULL；
 *     size 大于 0 时必须指向至少 size 个可读字节。
 *
 * @param[in] size
 *     输入区域的实际字节数。
 *     返回 VIREO_OK 时保证恰好消费整个区域。
 *
 * @param[in] rules
 *     只读规则数组。
 *     rule_count 为 0 时允许为 NULL；
 *     rule_count 大于 0 时必须指向至少 rule_count 个规则对象。
 *     同一规则表中的 type 必须唯一。
 *
 * @param[in] rule_count
 *     rules 中的规则数量，不是规则数组的字节数。
 *
 * @param[in] unknown_policy
 *     当前规则表未登记字段的处理策略；
 *     必须为 VIREO_TLV_UNKNOWN_REJECT 或 VIREO_TLV_UNKNOWN_SKIP。
 *
 * @param[out] seen
 *     调用者提供的临时可写工作空间。
 *     rule_count 大于 0 时必须非 NULL，
 *     并指向至少 seen_capacity 个可写字节。
 *     rule_count 为 0 时允许为 NULL。
 *     本函数不读取其初始内容，内部使用前会初始化所需区域。
 *
 * @param[in] seen_capacity
 *     seen 工作空间的容量，以字节为单位；
 *     必须至少为 rule_count，每条规则使用一个字节。
 *
 * @param[out] out_issue
 *     接收具体 TLV/schema 问题的非空指针。
 *     只要该指针非 NULL，函数在检查其他参数前先写入 NONE。
 *
 * @retval VIREO_OK
 *     完整消费输入，所有规则通过，*out_issue 为 NONE。
 *
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需指针为空，unknown_policy 或 value_kind 无效，
 *     规则的 min_length 大于 max_length，
 *     或者规则表中存在重复 type。
 *
 * @retval VIREO_RESULT_RANGE
 *     seen_capacity 小于 rule_count；
 *     *out_issue 为 NONE。
 *
 * @retval VIREO_RESULT_PROTOCOL
 *     输入违反 TLV 结构或 schema 规则，
 *     *out_issue 指明第一个检测到的问题。
 *
 * @note 检查顺序：先检查参数、工作空间容量和规则表配置，
 *       再按 wire 顺序解析。对已知字段依次检查重复、
 *       长度和内容；完整解析后按规则表顺序检查必填字段。
 * @note 未知字段：SKIP 只跳过未知字段的 schema 检查；
 *       未知字段仍必须具有完整 header 和完整 value。
 * @note 内容诊断：整数宽度错误报告 INVALID_LENGTH；
 *       UTF8 或 NAME 的 UTF-8 非法报告 INVALID_UTF8；
 *       NAME 在 UTF-8 合法后违反名称限制报告 INVALID_NAME。
 * @note 输出保持：seen 是临时工作空间，不是解析结果；
 *       失败时不保证 seen 的前 rule_count 字节保持不变。
 *       seen_capacity 超过 rule_count 的尾部始终不修改。
 * @note out_issue：参数错误或工作空间容量错误时为 NONE；
 *       协议错误时写入具体问题；成功时为 NONE。
 * @note 所有权：不接管任何输入、输出或工作空间的所有权，
 *       不动态分配或释放内存。
 * @note 生命周期：只在调用期间借用，不保存任何参数指针。
 * @note 别名约束：seen、out_issue、输入区域和规则数组
 *       之间不得存在涉及写入的重叠。
 * @note 线程安全：独立工作空间和输出对象可以并发使用；
 *       输入和规则表在调用期间不得被其他线程修改。
 * @note errno：本函数不读取、不保存且不修改 errno。
 * @note 范围边界：不验证 frame header 或 CRC，
 *       不建立命令与规则表的映射，不执行认证、权限、
 *       配额或数据库检查，也不记录字段内容。
 */
vireo_result_t vireo_tlv_schema_validate(uint8_t const *data, size_t size,
                                         vireo_tlv_rule_t const *rules, size_t rule_count,
                                         vireo_tlv_unknown_policy_t unknown_policy, uint8_t *seen,
                                         size_t seen_capacity, vireo_tlv_issue_t *out_issue);

#endif  // VIREO_PROTOCOL_TLV_H
