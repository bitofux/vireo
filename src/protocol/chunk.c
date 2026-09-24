/*
 * PROJECT : VIREO
 * FILE    : chunk.c
 * AUTHOR  : bitofux
 * DATE    : 2026-09-24
 * BRIEF   : 此模块负责：
 * -- 按固定 offset 显式编码和解码 vireo v1 chunk body
 * -- 验证固定长度、协议硬上限、body 长度一致性和区间加法溢出
 * -- 计算并验证只覆盖原始 data 的 CRC-32C
 *
 * -- 宿主语义结构体与 wire byte buffer 完全分离
 * -- 所有多字节 wire 整数字段使用显式 big-endian helper
 * -- 本模块只搬运 BLAKE3 摘要字段，不计算或验证 BLAKE3
 * -- 本模块不动态分配，不执行 I/O，不修改 errno
 *
 */

#include <vireo/protocol/chunk.h>

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <vireo/base/checked.h>
#include <vireo/base/result.h>

#define VIREO_CHUNK_CRC32C_REFLECTED_POLYNOMIAL UINT32_C(0x82F63B78)

/**
 * @brief 把宿主语义 uint32_t 编码为四个 big-endian 字节
 *
 * 从最高有效字节到最低有效字节，
 * 依次写入 wire[0] 到 wire[3]。
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
 * @note 范围边界：不执行参数或容量检查，不验证字段含义，
 *       不计算 CRC，也不提交完整 body 的输出长度；
 *       只供当前源文件内部使用。
 */
static void vireo_chunk_write_u32_be(uint8_t *wire, uint32_t value) {
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
 * @note 范围边界：不执行参数或容量检查，不验证文件位置，
 *       不检查区间加法，也不提交完整 body 的输出长度；
 *       只供当前源文件内部使用。
 */
static void vireo_chunk_write_u64_be(uint8_t *wire, uint64_t value) {
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
 * @note 输出保持：不修改输入区域。
 * @note 所有权：不接管 wire 指向的存储，不分配或释放内存。
 * @note 生命周期：只在调用期间借用 wire，不保存指针。
 * @note 线程安全：不使用共享可变全局状态；
 *       输入区域在调用期间不得被其他线程修改。
 * @note errno：本函数不读取、不保存且不修改 errno。
 * @note 范围边界：不执行参数或长度检查，不验证字段含义，
 *       不读取原始 data，也不提交完整 chunk 视图；
 *       只供当前源文件内部使用。
 */
static uint32_t vireo_chunk_read_u32_be(uint8_t const *wire) {
    uint32_t const byte0 = (uint32_t)wire[0] << 24U;
    uint32_t const byte1 = (uint32_t)wire[1] << 16U;
    uint32_t const byte2 = (uint32_t)wire[2] << 8U;
    uint32_t const byte3 = (uint32_t)wire[3];

    return (uint32_t)(byte0 | byte1 | byte2 | byte3);
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
 * @note 输出保持：不修改输入区域。
 * @note 所有权：不接管 wire 指向的存储，不分配或释放内存。
 * @note 生命周期：只在调用期间借用 wire，不保存指针。
 * @note 线程安全：不使用共享可变全局状态；
 *       输入区域在调用期间不得被其他线程修改。
 * @note errno：本函数不读取、不保存且不修改 errno。
 * @note 范围边界：不执行参数或长度检查，不验证文件位置，
 *       不检查区间加法，也不提交完整 chunk 视图；
 *       只供当前源文件内部使用。
 */
static uint64_t vireo_chunk_read_u64_be(uint8_t const *wire) {
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
 * @brief 使用一段字节继续更新 reflected CRC-32C 寄存器
 *
 * 本函数不设置初始值，也不执行最终按位取反。
 * 调用者提供当前寄存器值，并接收更新后的寄存器值。
 *
 * @param[in] crc
 *     当前 CRC-32C 寄存器值，按值传入。
 *
 * @param[in] data
 *     要处理的只读字节区域；
 *     data_size 为 0 时允许为 NULL。
 *
 * @param[in] data_size
 *     要处理的字节数。
 *
 * @return
 *     处理完整个字节区域后的 CRC-32C 寄存器值；
 *     data_size 为 0 时原样返回传入的 crc。
 *
 * @note 前置条件：data_size 非零时，data 必须非 NULL，
 *       并指向至少 data_size 个可读字节。
 * @note 输出保持：不修改输入区域；crc 按值传入，
 *       调用者通过返回值接收新的状态。
 * @note 所有权：不接管输入区域，不分配或释放内存。
 * @note 生命周期：只在调用期间借用 data，不保存指针。
 * @note 线程安全：不使用共享可变全局状态；
 *       输入区域在调用期间不得被其他线程修改。
 * @note errno：本函数不读取、不保存且不修改 errno。
 * @note 范围边界：不执行参数或长度上限检查，
 *       不设置初始值，不执行最终按位取反，
 *       不解析 chunk 元数据，也不比较携带的 CRC；
 *       只供当前源文件内部使用。
 */
static uint32_t vireo_chunk_crc32c_update(uint32_t crc, uint8_t const *data, size_t data_size) {
    for (size_t byte_index = 0; byte_index < data_size; ++byte_index) {
        crc ^= (uint32_t)data[byte_index];

        for (size_t bit_index = 0; bit_index < 8U; ++bit_index) {
            uint32_t const mask = UINT32_C(0) - (crc & UINT32_C(1));

            crc = (crc >> 1U) ^ (VIREO_CHUNK_CRC32C_REFLECTED_POLYNOMIAL & mask);
        }
    }

    return crc;
}

/* 计算原始 data 的 CRC-32C；参数检查通过后计算，成功时提交输出 */
vireo_result_t vireo_chunk_data_crc32c_calculate(uint8_t const *data, size_t data_size,
                                                 uint32_t *out_crc32c) {
    if (out_crc32c == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }

    if (data == NULL && data_size != 0U) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }

    if (data_size > (size_t)VIREO_CHUNK_MAX_DATA_SIZE) {
        return VIREO_RESULT_RANGE;
    }

    uint32_t const crc = vireo_chunk_crc32c_update(UINT32_C(0xFFFFFFFF), data, data_size);

    *out_crc32c = (uint32_t)~crc;

    return VIREO_OK;
}

/* 编码完整 chunk body；所有失败检查均在修改输出之前完成 */
vireo_result_t vireo_chunk_body_encode(vireo_chunk_header_t const *header, uint8_t const *data,
                                       size_t data_size, uint8_t *body, size_t body_capacity,
                                       size_t *out_body_size) {
    if (header == NULL || body == NULL || out_body_size == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }

    if (data == NULL && data_size != 0U) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }

    if (data_size > (size_t)VIREO_CHUNK_MAX_DATA_SIZE ||
        header->data_len > VIREO_CHUNK_MAX_DATA_SIZE) {
        return VIREO_RESULT_RANGE;
    }

    if (data_size != (size_t)header->data_len) {
        return VIREO_RESULT_RANGE;
    }

    size_t body_size;
    vireo_result_t result =
        vireo_checked_size_add((size_t)VIREO_CHUNK_HEADER_SIZE, data_size, &body_size);
    if (result != VIREO_OK) {
        return result;
    }

    uint64_t end_offset;
    result = vireo_checked_u64_add(header->offset, (uint64_t)header->data_len, &end_offset);
    if (result != VIREO_OK) {
        return result;
    }

    /* 只验证区间终点可表示，不将终点写入wire */
    (void)end_offset;

    if (body_size > body_capacity) {
        return VIREO_RESULT_RANGE;
    }

    vireo_chunk_write_u32_be(body + VIREO_CHUNK_INDEX_OFFSET, header->chunk_index);
    vireo_chunk_write_u32_be(body + VIREO_CHUNK_HEADER_LENGTH_OFFSET, VIREO_CHUNK_HEADER_SIZE);
    vireo_chunk_write_u64_be(body + VIREO_CHUNK_FILE_OFFSET_OFFSET, header->offset);
    vireo_chunk_write_u32_be(body + VIREO_CHUNK_DATA_LENGTH_OFFSET, header->data_len);
    vireo_chunk_write_u32_be(body + VIREO_CHUNK_CRC32C_OFFSET, header->crc32c);

    memcpy(body + VIREO_CHUNK_BLAKE3_OFFSET, header->blake3, sizeof(header->blake3));

    if (data_size != 0U) {
        memcpy(body + VIREO_CHUNK_DATA_OFFSET, data, data_size);
    }

    *out_body_size = body_size;

    return VIREO_OK;
}

/* 解码完整 chunk body；结构检查成功后才提交借用视图 */
vireo_result_t vireo_chunk_body_decode(uint8_t const *body, size_t body_size,
                                       vireo_chunk_view_t *out_view,
                                       vireo_chunk_issue_t *out_issue) {
    if (out_issue != NULL) {
        *out_issue = VIREO_CHUNK_ISSUE_NONE;
    }

    if (body == NULL || out_view == NULL || out_issue == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }

    if (body_size > (size_t)VIREO_PROTOCOL_MAX_BODY_SIZE) {
        *out_issue = VIREO_CHUNK_ISSUE_BODY_TOO_LARGE;
        return VIREO_RESULT_PROTOCOL;
    }

    if (body_size < (size_t)VIREO_CHUNK_HEADER_SIZE) {
        *out_issue = VIREO_CHUNK_ISSUE_TRUNCATED_HEADER;
        return VIREO_RESULT_PROTOCOL;
    }

    if (vireo_chunk_read_u32_be(body + VIREO_CHUNK_HEADER_LENGTH_OFFSET) !=
        VIREO_CHUNK_HEADER_SIZE) {
        *out_issue = VIREO_CHUNK_ISSUE_INVALID_HEADER_LENGTH;
        return VIREO_RESULT_PROTOCOL;
    }

    vireo_chunk_view_t view;

    view.header.chunk_index = vireo_chunk_read_u32_be(body + VIREO_CHUNK_INDEX_OFFSET);
    view.header.offset = vireo_chunk_read_u64_be(body + VIREO_CHUNK_FILE_OFFSET_OFFSET);
    view.header.data_len = vireo_chunk_read_u32_be(body + VIREO_CHUNK_DATA_LENGTH_OFFSET);

    if (view.header.data_len > VIREO_CHUNK_MAX_DATA_SIZE) {
        *out_issue = VIREO_CHUNK_ISSUE_DATA_TOO_LARGE;
        return VIREO_RESULT_PROTOCOL;
    }

    /* 已确认 body 至少包含固定元数据，使用减法比较原始数据长度 */
    if ((size_t)view.header.data_len != body_size - (size_t)VIREO_CHUNK_HEADER_SIZE) {
        *out_issue = VIREO_CHUNK_ISSUE_BODY_LENGTH_MISMATCH;
        return VIREO_RESULT_PROTOCOL;
    }

    uint64_t end_offset;
    vireo_result_t const result =
        vireo_checked_u64_add(view.header.offset, (uint64_t)view.header.data_len, &end_offset);
    if (result != VIREO_OK) {
        *out_issue = VIREO_CHUNK_ISSUE_RANGE_OVERFLOW;
        return VIREO_RESULT_PROTOCOL;
    }

    /* 只验证区间终点可表示，不将终点保存在视图中 */
    (void)end_offset;

    view.header.crc32c = vireo_chunk_read_u32_be(body + VIREO_CHUNK_CRC32C_OFFSET);

    memcpy(view.header.blake3, body + VIREO_CHUNK_BLAKE3_OFFSET, sizeof(view.header.blake3));

    view.data = body + VIREO_CHUNK_DATA_OFFSET;

    *out_view = view;

    return VIREO_OK;
}

/* 验证原始 data 的 CRC-32C；不修改视图或输入数据 */
vireo_result_t vireo_chunk_data_crc32c_verify(vireo_chunk_view_t const *view,
                                              vireo_chunk_issue_t *out_issue) {
    if (out_issue != NULL) {
        *out_issue = VIREO_CHUNK_ISSUE_NONE;
    }

    if (view == NULL || out_issue == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }

    uint32_t calculated_crc32c;
    vireo_result_t const result = vireo_chunk_data_crc32c_calculate(
        view->data, (size_t)view->header.data_len, &calculated_crc32c);
    if (result != VIREO_OK) {
        return result;
    }

    if (calculated_crc32c != view->header.crc32c) {
        *out_issue = VIREO_CHUNK_ISSUE_CRC_MISMATCH;
        return VIREO_RESULT_PROTOCOL;
    }

    return VIREO_OK;
}
