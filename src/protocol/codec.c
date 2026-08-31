/*
 * PROJECT : VIREO
 * FILE    : codec.c
 * AUTHOR  : bitofux
 * DATE    : 2026-08-21
 * BRIEF   : 当前模块负责
 * -- 按照固定 offset 显式编码和解码 vireo v1 wire header
 * -- 验证固定 framing 与请求、响应基础语义
 * -- 计算并验证每帧 CRC-32C
 *
 * -- 宿主语义结构体与 wire byte buffer 完全分离
 * -- 所有多字节 wire 字段使用显式 big-endian helper
 * -- encode 和 decode 先写局部临时对象，成功后再提交调用者输出
 * -- CRC-32C 使用 reflected polynomial 0x82F63B78
 * -- 本模块不动态分配，不执行 I/O，不保存调用者指针
 */

#include <vireo/protocol/codec.h>

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <vireo/base/checked.h>
#include <vireo/base/result.h>
#include <vireo/protocol/protocol.h>

#define VIREO_PROTOCOL_CRC32C_REFLECTED_POLYNOMIAL UINT32_C(0x82F63B78)

/**
 * @brief 把宿主语义 uint16_t 编码为两个 big-endian 字节
 *
 * @param[out] wire 指向至少两个可写字节的非空指针；
 * @param[in] value 要编码的宿主语义 uint16_t
 *
 * @note 调用者负责保证 wire 指向至少两个可写字节
 * @note 本函数只供当前源文件内部使用
 */
static void vireo_protocol_write_u16_be(uint8_t *wire, uint16_t value) {
    wire[0] = (uint8_t)(value >> 8U);
    wire[1] = (uint8_t)(value);
}

/**
 * @brief 把宿主语义 uint32_t 编码为四个 big-endian 字节
 *
 * @param[out] wire 指向至少四个可写字节的非空指针；调用者保留所有权
 * @param[in] value 要编码的宿主语义 uint32_t
 *
 * @note 调用者负责保证 wire 指向至少四个可写字节
 * @note 本函数只供当前源文件内部使用
 */
static void vireo_protocol_write_u32_be(uint8_t *wire, uint32_t value) {
    wire[0] = (uint8_t)(value >> 24U);
    wire[1] = (uint8_t)(value >> 16U);
    wire[2] = (uint8_t)(value >> 8U);
    wire[3] = (uint8_t)(value);
}

/**
 * @brief 从两个 big-endian 字节解码宿主语义 uint16_t
 *
 * @param[in] wire 指向至少两个可读字节的非空指针
 *
 * @return 解码后的宿主语义 uint16_t
 *
 * @note 调用者负责保证 wire 指向至少两个可读字节
 * @note 本函数只供当前源文件内部使用
 */
static uint16_t vireo_protocol_read_u16_be(uint8_t const *wire) {
    uint16_t const high = (uint16_t)((uint16_t)wire[0] << 8U);
    uint16_t const low = (uint16_t)((uint16_t)wire[1]);

    return (uint16_t)(high | low);
}

/**
 * @brief 从四个 big-endian 字节解码宿主语义 uint32_t
 *
 * @param[in] wire 指向至少四个可读字节的非空指针
 *
 * @return 解码后的宿主语义 uint32_t
 *
 * @note 调用者负责保证 wire 指向至少四个可读字节
 * @note 本函数只供当前源文件内部使用
 */
static uint32_t vireo_protocol_read_u32_be(uint8_t const *wire) {
    uint32_t const byte1 = (uint32_t)((uint32_t)wire[0] << 24U);
    uint32_t const byte2 = (uint32_t)((uint32_t)wire[1] << 16U);
    uint32_t const byte3 = (uint32_t)((uint32_t)wire[2] << 8U);
    uint32_t const byte4 = (uint32_t)((uint32_t)wire[3]);

    return (uint32_t)(byte1 | byte2 | byte3 | byte4);
}

/**
 * @brief 使用一段字节继续更新 reflected CRC-32C 寄存器
 *
 * 本函数不执行初始值设置或最终按位取反。调用者负责提供当前寄存器值，
 * 因此可以依次更新 header prefix 和 body，而不需要拼接新缓冲区。
 *
 * @param[in] crc 当前 CRC-32C 寄存器值
 * @param[in] data 要处理的只读字节区域；data_size 为 0 时允许为 NULL
 * @param[in] data_size 要处理的字节数
 *
 * @return 处理完整个字节区域后的 CRC-32C 寄存器值
 *
 * @note 本函数只供当前源文件内部使用
 */
static uint32_t vireo_protocol_crc32c_update(uint32_t crc, uint8_t const *data, size_t data_size) {
    size_t byte_index;
    for (byte_index = 0; byte_index < data_size; ++byte_index) {
        size_t bit_index;

        crc ^= (uint32_t)data[byte_index];

        for (bit_index = 0; bit_index < 8U; ++bit_index) {
            uint32_t const mask = UINT32_C(0) - (crc & UINT32_C(1));

            crc = (crc >> 1U) ^ (VIREO_PROTOCOL_CRC32C_REFLECTED_POLYNOMIAL & mask);
        }
    }

    return crc;
}

/* 将宿主语义结构体显式编码为 32字节 big-endian wire header */
vireo_result_t vireo_protocol_header_encode(const vireo_protocol_header_t *header, uint8_t *wire,
                                            size_t wire_capacity) {
    /*
     * 在局部使用 wire buffer 完成全部字段编码
     * 最后一次提交，以保持失败时调用者输出不变
     * 不影响 wire
     */
    uint8_t encoded[VIREO_PROTOCOL_HEADER_SIZE];

    if (header == NULL || wire == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }

    if (wire_capacity < (size_t)VIREO_PROTOCOL_HEADER_SIZE) {
        return VIREO_RESULT_RANGE;
    }

    if (header->body_len > VIREO_PROTOCOL_MAX_BODY_SIZE) {
        return VIREO_RESULT_RANGE;
    }

    // 将 4 字节的 magic 编码到临时 encoded wire buffer 0 offset
    vireo_protocol_write_u32_be(encoded + VIREO_PROTOCOL_MAGIC_OFFSET, VIREO_PROTOCOL_MAGIC_VALUE);

    // version 和 header_len 都是单字节字段，不需要多字节字节序转换
    encoded[VIREO_PROTOCOL_VERSION_OFFSET] = VIREO_PROTOCOL_VERSION;
    encoded[VIREO_PROTOCOL_HEADER_LENGTH_OFFSET] = VIREO_PROTOCOL_HEADER_SIZE;

    // 2 字节的 command 编码到 encoded wire buffer 6 offset
    vireo_protocol_write_u16_be(encoded + VIREO_PROTOCOL_COMMAND_OFFSET, header->command);

    // 2 字节的 flags 编码到 encoded wire buffer 8 offset
    vireo_protocol_write_u16_be(encoded + VIREO_PROTOCOL_FLAGS_OFFSET, header->flags);

    // 2 字节的 status 编码到 encoded wire buffer 10 offset
    vireo_protocol_write_u16_be(encoded + VIREO_PROTOCOL_STATUS_OFFSET, header->status);

    // 4 字节的 body_len 编码到 encoded wire buffer 12 offset
    vireo_protocol_write_u32_be(encoded + VIREO_PROTOCOL_BODY_LENGTH_OFFSET, header->body_len);

    // 4 字节的 sequence 编码到 encoded wire buffer 16 offset
    vireo_protocol_write_u32_be(encoded + VIREO_PROTOCOL_SEQUENCE_OFFSET, header->sequence);

    // 4 字节的 session_handle 编码到 encode wire buffer 20 offset
    vireo_protocol_write_u32_be(encoded + VIREO_PROTOCOL_SESSION_HANDLE_OFFSET,
                                header->session_handle);

    // 4 字节的 task_handle 编码到 encoded wire buffer 24 offset
    vireo_protocol_write_u32_be(encoded + VIREO_PROTOCOL_TASK_HANDLE_OFFSET, header->task_handle);

    // 4 字节的 crc32c 编码到 encoded wire buffer 28 offset
    vireo_protocol_write_u32_be(encoded + VIREO_PROTOCOL_CRC32C_OFFSET, header->crc32c);

    // 编码完毕，将临时 wire buffer encoded 字节级拷贝到 wire
    memcpy(wire, encoded, sizeof(encoded));

    return VIREO_OK;
}

/* 将 32 字节 wire header 显式解码为宿主语义结构体 */
vireo_result_t vireo_protocol_header_decode(const uint8_t *wire, size_t wire_size,
                                            vireo_protocol_header_t *out_header,
                                            vireo_protocol_codec_issue_t *out_issue) {
    /*
     * 局部使用 header 完成完整解码
     * 解码成功之后再写入 out_header
     */
    vireo_protocol_header_t header;

    if (out_issue != NULL) {
        *out_issue = VIREO_PROTOCOL_CODEC_ISSUE_NONE;
    }

    if (wire == NULL || out_header == NULL || out_issue == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }

    if (wire_size < (size_t)VIREO_PROTOCOL_HEADER_SIZE) {
        return VIREO_RESULT_RANGE;
    }

    if (vireo_protocol_read_u32_be(wire + VIREO_PROTOCOL_MAGIC_OFFSET) !=
        VIREO_PROTOCOL_MAGIC_VALUE) {
        *out_issue = VIREO_PROTOCOL_CODEC_ISSUE_INVALID_MAGIC;

        return VIREO_RESULT_PROTOCOL;
    }

    /* version 和 header_len 都是单字节字段，无需进行多字节字节序转换 */
    if (wire[VIREO_PROTOCOL_VERSION_OFFSET] != VIREO_PROTOCOL_VERSION) {
        *out_issue = VIREO_PROTOCOL_CODEC_ISSUE_VERSION_MISMATCH;

        return VIREO_RESULT_PROTOCOL;
    }
    if (wire[VIREO_PROTOCOL_HEADER_LENGTH_OFFSET] != VIREO_PROTOCOL_HEADER_SIZE) {
        *out_issue = VIREO_PROTOCOL_CODEC_ISSUE_INVALID_HEADER_LENGTH;

        return VIREO_RESULT_PROTOCOL;
    }

    header.command = vireo_protocol_read_u16_be(wire + VIREO_PROTOCOL_COMMAND_OFFSET);

    header.flags = vireo_protocol_read_u16_be(wire + VIREO_PROTOCOL_FLAGS_OFFSET);

    header.status = vireo_protocol_read_u16_be(wire + VIREO_PROTOCOL_STATUS_OFFSET);

    header.body_len = vireo_protocol_read_u32_be(wire + VIREO_PROTOCOL_BODY_LENGTH_OFFSET);
    if (header.body_len > VIREO_PROTOCOL_MAX_BODY_SIZE) {
        *out_issue = VIREO_PROTOCOL_CODEC_ISSUE_BODY_TOO_LARGE;

        return VIREO_RESULT_PROTOCOL;
    }

    header.sequence = vireo_protocol_read_u32_be(wire + VIREO_PROTOCOL_SEQUENCE_OFFSET);

    header.session_handle = vireo_protocol_read_u32_be(wire + VIREO_PROTOCOL_SESSION_HANDLE_OFFSET);

    header.task_handle = vireo_protocol_read_u32_be(wire + VIREO_PROTOCOL_TASK_HANDLE_OFFSET);

    header.crc32c = vireo_protocol_read_u32_be(wire + VIREO_PROTOCOL_CRC32C_OFFSET);

    *out_header = header;

    return VIREO_OK;
}

/* 请求 header 基础语义验证 */
vireo_result_t vireo_protocol_request_header_validate(const vireo_protocol_header_t *header,
                                                      vireo_protocol_codec_issue_t *out_issue) {
    if (out_issue != NULL) {
        *out_issue = VIREO_PROTOCOL_CODEC_ISSUE_NONE;
    }

    if (header == NULL || out_issue == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }

    if (header->body_len > VIREO_PROTOCOL_MAX_BODY_SIZE) {
        *out_issue = VIREO_PROTOCOL_CODEC_ISSUE_BODY_TOO_LARGE;
        return VIREO_RESULT_PROTOCOL;
    }

    if (vireo_protocol_flags_have_unknown_bits(header->flags)) {
        *out_issue = VIREO_PROTOCOL_CODEC_ISSUE_UNKNOWN_FLAGS;
        return VIREO_RESULT_PROTOCOL;
    }

    if (vireo_command_is_reserved(header->command)) {
        *out_issue = VIREO_PROTOCOL_CODEC_ISSUE_RESERVED_COMMAND;
        return VIREO_RESULT_PROTOCOL;
    }

    if (!vireo_command_is_known(header->command)) {
        *out_issue = VIREO_PROTOCOL_CODEC_ISSUE_UNKNOWN_COMMAND;
        return VIREO_RESULT_PROTOCOL;
    }

    if (header->sequence == VIREO_PROTOCOL_SEQUENCE_NONE) {
        *out_issue = VIREO_PROTOCOL_CODEC_ISSUE_INVALID_SEQUENCE;
        return VIREO_RESULT_PROTOCOL;
    }

    if ((header->flags & VIREO_PROTOCOL_FLAG_RESPONSE) != UINT16_C(0)) {
        *out_issue = VIREO_PROTOCOL_CODEC_ISSUE_REQUEST_HAS_RESPONSE_FLAG;
        return VIREO_RESULT_PROTOCOL;
    }

    if ((header->flags & VIREO_PROTOCOL_FLAG_MORE) != UINT16_C(0)) {
        *out_issue = VIREO_PROTOCOL_CODEC_ISSUE_REQUEST_HAS_MORE_FLAG;
        return VIREO_RESULT_PROTOCOL;
    }

    if (header->status != VIREO_PROTOCOL_REQUEST_STATUS) {
        *out_issue = VIREO_PROTOCOL_CODEC_ISSUE_INVALID_REQUEST_STATUS;
        return VIREO_RESULT_PROTOCOL;
    }

    return VIREO_OK;
}

/* 响应 header 基础语义验证 */
vireo_result_t vireo_protocol_response_header_validate(const vireo_protocol_header_t *header,
                                                       vireo_protocol_codec_issue_t *out_issue) {
    if (out_issue != NULL) {
        *out_issue = VIREO_PROTOCOL_CODEC_ISSUE_NONE;
    }

    if (header == NULL || out_issue == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }

    if (header->body_len > VIREO_PROTOCOL_MAX_BODY_SIZE) {
        *out_issue = VIREO_PROTOCOL_CODEC_ISSUE_BODY_TOO_LARGE;
        return VIREO_RESULT_PROTOCOL;
    }

    if (vireo_protocol_flags_have_unknown_bits(header->flags)) {
        *out_issue = VIREO_PROTOCOL_CODEC_ISSUE_UNKNOWN_FLAGS;
        return VIREO_RESULT_PROTOCOL;
    }

    if (vireo_command_is_reserved(header->command)) {
        *out_issue = VIREO_PROTOCOL_CODEC_ISSUE_RESERVED_COMMAND;
        return VIREO_RESULT_PROTOCOL;
    }

    if (!vireo_command_is_known(header->command)) {
        *out_issue = VIREO_PROTOCOL_CODEC_ISSUE_UNKNOWN_COMMAND;
        return VIREO_RESULT_PROTOCOL;
    }

    if (header->sequence == VIREO_PROTOCOL_SEQUENCE_NONE) {
        *out_issue = VIREO_PROTOCOL_CODEC_ISSUE_INVALID_SEQUENCE;
        return VIREO_RESULT_PROTOCOL;
    }

    if ((header->flags & VIREO_PROTOCOL_FLAG_RESPONSE) == UINT16_C(0)) {
        *out_issue = VIREO_PROTOCOL_CODEC_ISSUE_RESPONSE_MISSING_RESPONSE_FLAG;
        return VIREO_RESULT_PROTOCOL;
    }

    if (!vireo_status_is_known(header->status)) {
        *out_issue = VIREO_PROTOCOL_CODEC_ISSUE_UNKNOWN_RESPONSE_STATUS;
        return VIREO_RESULT_PROTOCOL;
    }

    return VIREO_OK;
}

/* 计算当前 frame 的 CRC-32C */
vireo_result_t vireo_protocol_frame_crc32c_calculate(const uint8_t *wire, size_t wire_size,
                                                     const uint8_t *body, size_t body_size,
                                                     uint32_t *out_crc32c) {
    if (wire == NULL || out_crc32c == NULL || (body == NULL && body_size != 0)) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }

    if (wire_size < (size_t)VIREO_PROTOCOL_HEADER_SIZE) {
        return VIREO_RESULT_RANGE;
    }

    if (body_size > (size_t)VIREO_PROTOCOL_MAX_BODY_SIZE) {
        return VIREO_RESULT_RANGE;
    }

    /*
     * 获取当前 wire 中的 body_size
     * 主要是为了判断其与当前形式参数中的 body_size 是否一致
     */
    uint32_t wire_body_size = vireo_protocol_read_u32_be(wire + VIREO_PROTOCOL_BODY_LENGTH_OFFSET);

    if ((size_t)wire_body_size != body_size) {
        return VIREO_RESULT_RANGE;
    }

    uint32_t crc32c = UINT32_C(0xFFFFFFFF);
    crc32c = vireo_protocol_crc32c_update(crc32c, wire, (size_t)VIREO_PROTOCOL_CRC32C_OFFSET);

    crc32c = vireo_protocol_crc32c_update(crc32c, body, body_size);

    crc32c = ~crc32c;

    *out_crc32c = crc32c;

    return VIREO_OK;
}

/* 验证 wire header 中携带的 CRC-32C */
vireo_result_t vireo_protocol_frame_crc32c_verify(const uint8_t *wire, size_t wire_size,
                                                  const uint8_t *body, size_t body_size,
                                                  vireo_protocol_codec_issue_t *out_issue) {
    if (out_issue != NULL) {
        *out_issue = VIREO_PROTOCOL_CODEC_ISSUE_NONE;
    }

    if (wire == NULL || out_issue == NULL || (body == NULL && body_size != (size_t)0)) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }

    if (wire_size < (size_t)VIREO_PROTOCOL_HEADER_SIZE) {
        return VIREO_RESULT_RANGE;
    }

    if (body_size > (size_t)VIREO_PROTOCOL_MAX_BODY_SIZE) {
        return VIREO_RESULT_RANGE;
    }

    uint32_t wire_body_size = vireo_protocol_read_u32_be(wire + VIREO_PROTOCOL_BODY_LENGTH_OFFSET);

    if ((size_t)wire_body_size != body_size) {
        *out_issue = VIREO_PROTOCOL_CODEC_ISSUE_BODY_LENGTH_MISMATCH;
        return VIREO_RESULT_RANGE;
    }

    // 重新计算 crc32c
    uint32_t calculated_crc32c;
    vireo_result_t result =
        vireo_protocol_frame_crc32c_calculate(wire, wire_size, body, body_size, &calculated_crc32c);

    if (result != VIREO_OK) {
        return result;
    }

    uint32_t wire_crc32c = vireo_protocol_read_u32_be(wire + VIREO_PROTOCOL_CRC32C_OFFSET);

    if (calculated_crc32c != wire_crc32c) {
        *out_issue = VIREO_PROTOCOL_CODEC_ISSUE_CRC_MISMATCH;
        return VIREO_RESULT_PROTOCOL;
    }

    return VIREO_OK;
}
