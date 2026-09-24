/*
 * PROJECT : VIREO
 * FILE    : chunk.h
 * AUTHOR  : bitofux
 * DATE    : 2026-09-24
 * BRIEF   : 此模块负责：
 * -- 定义 vireo v1 chunk body 的固定 wire 布局
 * -- 显式编码完整 chunk body，解码为宿主语义元数据与借用视图
 * -- 验证固定长度、协议硬上限、body 长度一致性和区间加法溢出
 * -- 计算并验证只覆盖原始 data 的 CRC-32C
 *
 * -- 本模块只搬运 BLAKE3 摘要字段，不计算或验证 BLAKE3
 * -- 本模块不拥有缓冲区，不动态分配，不执行 I/O
 */

#ifndef VIREO_PROTOCOL_CHUNK_H
#define VIREO_PROTOCOL_CHUNK_H

#include <stddef.h>
#include <stdint.h>

#include <vireo/base/result.h>
#include <vireo/protocol/protocol.h>

/** vireo v1 chunk 固定元数据长度，单位为字节 */
#define VIREO_CHUNK_HEADER_SIZE UINT32_C(56)

/** chunk 携带的 BLAKE3 摘要长度，单位为原始字节，不是文本字符数 */
#define VIREO_CHUNK_BLAKE3_SIZE UINT32_C(32)

/**
 * 单个 chunk 原始 data 的协议硬上限，单位为字节
 *
 * 外层 body 同时容纳固定元数据和原始 data
 * 命令或传输协商可以采用更小的上限
 */
#define VIREO_CHUNK_MAX_DATA_SIZE (VIREO_PROTOCOL_MAX_BODY_SIZE - VIREO_CHUNK_HEADER_SIZE)

/*
 * 以下 offset 均相对于 chunk body 的起点，
 * 不包含外层 32 字节 frame header。
 */

/** chunk_index 字段的 wire offset。 */
#define VIREO_CHUNK_INDEX_OFFSET UINT32_C(0)

/** chunk_header_len 字段的 wire offset。 */
#define VIREO_CHUNK_HEADER_LENGTH_OFFSET UINT32_C(4)

/** 文件 offset 字段的 wire offset。 */
#define VIREO_CHUNK_FILE_OFFSET_OFFSET UINT32_C(8)

/** data_len 字段的 wire offset。 */
#define VIREO_CHUNK_DATA_LENGTH_OFFSET UINT32_C(16)

/** data CRC-32C 字段的 wire offset。 */
#define VIREO_CHUNK_CRC32C_OFFSET UINT32_C(20)

/** BLAKE3 摘要字段的 wire offset。 */
#define VIREO_CHUNK_BLAKE3_OFFSET UINT32_C(24)

/** 原始 data 的起始 wire offset。 */
#define VIREO_CHUNK_DATA_OFFSET VIREO_CHUNK_HEADER_SIZE

/** chunk_index 字段的 wire 字节数。 */
#define VIREO_CHUNK_INDEX_SIZE UINT32_C(4)

/** chunk_header_len 字段的 wire 字节数。 */
#define VIREO_CHUNK_HEADER_LENGTH_SIZE UINT32_C(4)

/** 文件 offset 字段的 wire 字节数。 */
#define VIREO_CHUNK_FILE_OFFSET_SIZE UINT32_C(8)

/** data_len 字段的 wire 字节数。 */
#define VIREO_CHUNK_DATA_LENGTH_SIZE UINT32_C(4)

/** data CRC-32C 字段的 wire 字节数。 */
#define VIREO_CHUNK_CRC32C_SIZE UINT32_C(4)

/**
 * @brief 描述 chunk 编解码或 CRC 验证发现的具体协议问题
 *
 * vireo_result_t 表示总体结果分类，
 * vireo_chunk_issue_t 表示检测到的具体 chunk 协议问题。
 *
 * @note 本枚举只用于进程内部诊断，不是 wire 字段。
 * @note 不得直接序列化，或强制转换为 vireo_status_t。
 * @note 同时存在多个问题时，只保证报告一个已检测问题。
 */
typedef enum vireo_chunk_issue {
    VIREO_CHUNK_ISSUE_NONE = 0,
    /**< 未发现具体 chunk 协议问题 */

    VIREO_CHUNK_ISSUE_TRUNCATED_HEADER = 1,
    /**< 完整 body 不足固定 56 字节元数据长度 */

    VIREO_CHUNK_ISSUE_INVALID_HEADER_LENGTH = 2,
    /**< wire 中的 chunk_header_len 不是固定值 56 */

    VIREO_CHUNK_ISSUE_BODY_TOO_LARGE = 3,
    /**< 完整 body 超过 VIREO_PROTOCOL_MAX_BODY_SIZE */

    VIREO_CHUNK_ISSUE_DATA_TOO_LARGE = 4,
    /**< wire 中的 data_len 超过 VIREO_CHUNK_MAX_DATA_SIZE */

    VIREO_CHUNK_ISSUE_BODY_LENGTH_MISMATCH = 5,
    /**< body 实际长度不等于固定元数据长度加 data_len */

    VIREO_CHUNK_ISSUE_RANGE_OVERFLOW = 6,
    /**< 文件 offset 加 data_len 的数学结果无法由 uint64_t 表示 */

    VIREO_CHUNK_ISSUE_CRC_MISMATCH = 7,
    /**< 原始 data 的计算 CRC-32C 与元数据携带值不一致 */
} vireo_chunk_issue_t;

/**
 * @brief 保存宿主语义的 chunk 元数据
 *
 * 多字节整数均为宿主语义数值。
 * blake3 保存 32 个原始摘要字节，不进行整数字节序转换。
 *
 * 固定 chunk_header_len 不重复保存：
 * 编码时自动写入 56，解码时验证该固定值。
 *
 * @note data_len 的协议有效范围为
 *       [0, VIREO_CHUNK_MAX_DATA_SIZE]。
 * @note 有效文件区间要求 offset + data_len 可由 uint64_t 表示；
 *       是否超过真实文件总长由持有文件信息的调用层验证。
 * @note chunk_index 与 offset 的对应关系由 manifest 或传输规则决定。
 * @note 本结构体不包含指针，不拥有任何外部存储。
 * @note sizeof 本结构体不代表 wire 长度；
 *       禁止直接复制本结构体作为 wire 元数据。
 */
typedef struct vireo_chunk_header {
    uint32_t chunk_index;
    /**< 数据块编号，通用模块不限制其与传输顺序的关系 */

    uint64_t offset;
    /**< 原始 data 在文件中的起始位置，单位为字节 */

    uint32_t data_len;
    /**< 原始 data 字节数，不包含固定 56 字节元数据 */

    uint32_t crc32c;
    /**< 只覆盖原始 data 的宿主语义 CRC-32C 数值 */

    uint8_t blake3[VIREO_CHUNK_BLAKE3_SIZE];
    /**< 原始 data 的 32 字节 BLAKE3 摘要，本模块不验证其内容 */
} vireo_chunk_header_t;

/**
 * @brief 描述一条 chunk 的宿主语义元数据与借用式 data 视图
 *
 * header 按值保存元数据；
 * data 借用调用者持有的原始数据区域。
 * data 的字节数由 header.data_len 表示。
 *
 * @note 解码成功时，data 指向输入 body 的 offset 56。
 * @note 解码空 data 时，data 指向 body 末尾，不得解引用。
 * @note 调用者自行构造视图时，data_len 为 0 允许 data 为 NULL。
 * @note 复制本结构体只复制元数据和指针，不复制原始 data。
 * @note 原始数据区域失效后不得使用 data；
 *       区域被覆盖后不能继续将其解释为原来的 chunk 内容。
 * @note 不得通过 data 修改或释放底层区域；
 *       底层存储始终由其原所有者管理。
 */
typedef struct vireo_chunk_view {
    vireo_chunk_header_t header;
    /**< 已转换为宿主语义的 chunk 元数据 */

    uint8_t const *data;
    /**< 原始 data 的借用地址，不拥有该存储 */
} vireo_chunk_view_t;

/**
 * @brief 计算只覆盖原始 data 的 CRC-32C
 *
 * 使用初始寄存器 0xFFFFFFFF、
 * reflected polynomial 0x82F63B78 和最终按位取反。
 * 空 data 的结果为 0。
 *
 * @param[in] data
 *     原始数据的只读借用地址。
 *     data_size 为 0 时允许为 NULL。
 *     长度在允许范围内且非零时，
 *     必须指向至少 data_size 个可读字节。
 *
 * @param[in] data_size
 *     原始数据的字节数；
 *     不得超过 VIREO_CHUNK_MAX_DATA_SIZE。
 *     超过硬上限时在读取数据前返回范围错误。
 *
 * @param[out] out_crc32c
 *     接收宿主语义 CRC-32C 数值的非空可写指针。
 *     只有成功时写入；调用者保留所有权。
 *
 * @retval VIREO_OK
 *     计算成功，结果已写入 *out_crc32c。
 *
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     out_crc32c 为 NULL，
 *     或 data_size 非零但 data 为 NULL。
 *
 * @retval VIREO_RESULT_RANGE
 *     data_size 超过 VIREO_CHUNK_MAX_DATA_SIZE。
 *
 * @note 输出保持：失败时不修改 *out_crc32c。
 * @note 所有权：不接管输入或输出对象，不分配或释放内存。
 * @note 生命周期：只在调用期间借用参数，不在内部保存指针。
 * @note 不重叠：out_crc32c 对象不得与输入 data 区域重叠。
 * @note 线程安全：不访问共享可变全局状态；
 *       输入在调用期间不得被并发修改，共享输出由调用者同步。
 * @note errno：不读取、不保存且不修改 errno。
 * @note 范围边界：不包含 chunk 元数据或外层 frame header，
 *       不验证元数据、BLAKE3 或文件范围。
 */
vireo_result_t vireo_chunk_data_crc32c_calculate(uint8_t const *data, size_t data_size,
                                                 uint32_t *out_crc32c);

/**
 * @brief 将宿主语义元数据和原始 data 编码为完整 chunk body
 *
 * 按固定 offset 显式编码多字节整数，
 * 自动写入 chunk_header_len = 56，
 * 复制 32 字节摘要和原始 data。
 *
 * header->crc32c 与 header->blake3 按当前值编码，
 * 不在本函数中重新计算或验证。
 *
 * @param[in] header
 *     要编码的非空只读元数据指针。
 *     data_len 必须等于 data_size，且不超过 chunk 硬上限。
 *     offset 加 data_len 必须能够由 uint64_t 表示。
 *
 * @param[in] data
 *     原始数据的只读借用地址。
 *     data_size 为 0 时允许为 NULL；
 *     非零时必须指向至少 data_size 个可读字节。
 *
 * @param[in] data_size
 *     调用者提供的原始数据字节数。
 *     必须等于 header->data_len，
 *     且不得超过 VIREO_CHUNK_MAX_DATA_SIZE。
 *
 * @param[out] body
 *     接收完整 chunk body 的非空输出缓冲区。
 *     必须具有至少 body_capacity 个可写字节。
 *     调用者保留所有权。
 *
 * @param[in] body_capacity
 *     输出缓冲区的可写容量，单位为字节。
 *     必须足以容纳 VIREO_CHUNK_HEADER_SIZE + data_size。
 *
 * @param[out] out_body_size
 *     接收实际编码字节数的非空可写指针。
 *     成功时写入 VIREO_CHUNK_HEADER_SIZE + data_size。
 *
 * @retval VIREO_OK
 *     完整 body 已写入，实际长度已写入 *out_body_size。
 *     超出实际编码长度的输出缓冲区尾部保持不变。
 *
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     header、body 或 out_body_size 为 NULL，
 *     或 data_size 非零但 data 为 NULL。
 *
 * @retval VIREO_RESULT_RANGE
 *     data_size 或 header->data_len 超过 chunk 硬上限，
 *     两者不相等，或 body_capacity 不足。
 *
 * @retval VIREO_RESULT_OVERFLOW
 *     总输出长度无法由 size_t 表示，
 *     或 offset 加 data_len 无法由 uint64_t 表示。
 *
 * @note 输出保持：全部失败检查在写入前完成；
 *       失败时 body 的全部字节和 *out_body_size 保持不变。
 * @note 所有权：不接管任何对象，不分配或释放内存。
 * @note 生命周期：只在调用期间借用输入，不在内部保存指针。
 * @note 不重叠：body 区域和 out_body_size 对象互不重叠，
 *       且均不得与 header 对象或输入 data 区域重叠；
 *       本函数不支持原地编码。
 * @note 线程安全：不访问共享可变全局状态；
 *       输入在调用期间不得被并发修改，共享输出由调用者同步。
 * @note errno：不读取、不保存且不修改 errno。
 * @note 范围边界：不编码外层 frame header，
 *       不验证 CRC、BLAKE3、协商块大小、manifest、
 *       文件总长、任务状态或重复块。
 */
vireo_result_t vireo_chunk_body_encode(vireo_chunk_header_t const *header, uint8_t const *data,
                                       size_t data_size, uint8_t *body, size_t body_capacity,
                                       size_t *out_body_size);

/**
 * @brief 验证一条完整 chunk body 的结构并输出借用视图
 *
 * 检查 body 硬上限、固定元数据完整性、
 * chunk_header_len、data_len 硬上限、
 * body 长度一致性和文件区间加法溢出。
 *
 * body_size 表示一条完整 body 的实际字节数，
 * 不是缓冲区容量，也不是尚未收齐的网络输入长度。
 * 不足或多出的字节均按该完整 body 的结构错误处理。
 *
 * @param[in] body
 *     包含一条完整 chunk body 的非空只读借用地址。
 *     body_size 不超过协议硬上限时，
 *     必须指向至少 body_size 个可读字节。
 *     body_size 超过硬上限时在读取 body 前拒绝。
 *
 * @param[in] body_size
 *     完整 chunk body 的实际字节数，不包含外层 frame header。
 *     成功时必须严格等于固定 56 字节加 wire 中的 data_len。
 *
 * @param[out] out_view
 *     接收解码结果的非空可写指针。
 *     只有成功时提交完整视图。
 *     元数据按值复制，data 借用输入 body 内部的区域。
 *
 * @param[out] out_issue
 *     接收具体诊断的非空可写指针。
 *     只要此指针非 NULL，检查其他参数前先写入 NONE；
 *     发现协议问题时再写入具体 issue。
 *
 * @retval VIREO_OK
 *     body 结构检查通过，*out_view 已写入，
 *     *out_issue 为 VIREO_CHUNK_ISSUE_NONE。
 *
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     body、out_view 或 out_issue 为 NULL。
 *
 * @retval VIREO_RESULT_PROTOCOL
 *     body 超过硬上限、元数据截断、固定长度字段错误、
 *     data_len 超过硬上限、body 长度不一致，
 *     或文件区间末端无法由 uint64_t 表示。
 *     *out_issue 给出一个检测到的具体问题。
 *
 * @note 输出保持：失败时不修改 *out_view；out_issue 允许修改。
 * @note 所有权：不接管 body 或输出对象，不分配或释放内存。
 * @note 生命周期：输出视图的 data 借用输入 body。
 *       使用该指针期间，底层存储必须持续有效；
 *       若内容被覆盖，不能继续作为原来的 chunk 使用。
 *       本模块不在内部保存指针。
 * @note 空数据：data_len 为 0 时允许结构解码成功；
 *       输出 data 指向 body 末尾，不得解引用。
 * @note 不重叠：out_view 和 out_issue 对象互不重叠，
 *       且均不得与输入 body 区域重叠。
 * @note 线程安全：不访问共享可变全局状态；
 *       输入在调用期间不得被并发修改，共享输出由调用者同步。
 * @note errno：不读取、不保存且不修改 errno。
 * @note 范围边界：不验证 CRC-32C、BLAKE3、外层 header、
 *       command/flags、协商块大小、manifest 或真实文件总长。
 *       不接收网络数据，也不把截断解释为等待更多数据。
 */
vireo_result_t vireo_chunk_body_decode(uint8_t const *body, size_t body_size,
                                       vireo_chunk_view_t *out_view,
                                       vireo_chunk_issue_t *out_issue);

/**
 * @brief 验证 chunk 视图中的原始 data 是否匹配携带的 CRC-32C
 *
 * 使用 data 与 header.data_len 重新计算 CRC-32C，
 * 并与 header.crc32c 的宿主语义数值比较。
 *
 * 视图可以来自 body_decode，也可以由调用者按合同构造。
 * 本函数只验证 data CRC，不重新检查完整 body 结构。
 *
 * @param[in] view
 *     要验证的非空只读视图指针。
 *     header.data_len 不得超过 VIREO_CHUNK_MAX_DATA_SIZE。
 *     长度非零且在允许范围内时，
 *     data 必须指向至少 header.data_len 个可读字节。
 *     长度为 0 时 data 允许为 NULL。
 *
 * @param[out] out_issue
 *     接收具体诊断的非空可写指针。
 *     只要此指针非 NULL，检查其他参数前先写入 NONE。
 *     CRC 不一致时写入 VIREO_CHUNK_ISSUE_CRC_MISMATCH。
 *
 * @retval VIREO_OK
 *     计算结果与 header.crc32c 一致，
 *     *out_issue 为 VIREO_CHUNK_ISSUE_NONE。
 *
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     view 或 out_issue 为 NULL，
 *     或 header.data_len 非零但 data 为 NULL。
 *
 * @retval VIREO_RESULT_RANGE
 *     调用者提供的 header.data_len 超过 chunk 硬上限；
 *     在读取 data 前拒绝，*out_issue 保持 NONE。
 *
 * @retval VIREO_RESULT_PROTOCOL
 *     原始 data 的 CRC-32C 与 header.crc32c 不一致，
 *     *out_issue 为 VIREO_CHUNK_ISSUE_CRC_MISMATCH。
 *
 * @note 输出保持：不修改 view 或原始 data；out_issue 允许修改。
 * @note 所有权：不接管任何对象，不分配或释放内存。
 * @note 生命周期：只在调用期间借用视图及数据，不在内部保存指针。
 * @note 不重叠：out_issue 对象不得与 view 对象或 data 区域重叠。
 * @note 线程安全：不访问共享可变全局状态；
 *       视图及 data 在调用期间不得被并发修改，
 *       共享诊断输出由调用者同步。
 * @note errno：不读取、不保存且不修改 errno。
 * @note 范围边界：不验证 BLAKE3、index/offset 关系、
 *       文件区间、任务状态、重复块或外层 frame CRC。
 */
vireo_result_t vireo_chunk_data_crc32c_verify(vireo_chunk_view_t const *view,
                                              vireo_chunk_issue_t *out_issue);

#endif  // VIREO_PROTOCOL_CHUNK_H
