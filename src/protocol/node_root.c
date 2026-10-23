/*
 * PROJECT : VIREO
 * FILE    : node_root.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-22
 * BRIEF   : NODE_ROOT固定长度完整帧；有界验证后才发布独立值或CRC帧。
 * IMPLEMENTATION : 仅局部状态，无分配/I/O；基础header规则先于命令schema。
 */
#include <vireo/protocol/node_root.h>
#include <vireo/protocol/codec.h>
#include <vireo/protocol/tlv.h>
#include <errno.h>
#include <string.h>

static vireo_tlv_rule_t const root_rule = {
    VIREO_NODE_ROOT_TLV_NODE_ID, 8, 8, VIREO_TLV_VALUE_U64, true, false
};

/* 命令状态子集；根缺失不是普通NOT_FOUND。 */
static bool status_allowed(vireo_status_t status) {
    switch (status) {
    case VIREO_STATUS_OK:
    case VIREO_STATUS_BAD_REQUEST:
    case VIREO_STATUS_UNSUPPORTED:
    case VIREO_STATUS_CRC_MISMATCH:
    case VIREO_STATUS_BODY_TOO_LARGE:
    case VIREO_STATUS_INVALID_FLAGS:
    case VIREO_STATUS_DUPLICATE_REQUEST:
    case VIREO_STATUS_RATE_LIMITED:
    case VIREO_STATUS_UNAUTHORIZED:
    case VIREO_STATUS_BUSY:
    case VIREO_STATUS_INTERNAL_ERROR:
    case VIREO_STATUS_TIMEOUT:
    case VIREO_STATUS_OVERLOADED:
    case VIREO_STATUS_UNAVAILABLE:
        return true;
    default:
        return false;
    }
}

static vireo_result_t finish(vireo_result_t result, int saved_errno) {
    errno = saved_errno;
    return result;
}

/**
 * @brief 发布本地拒绝类别，保持业务输出由上层负责
 * @param[out] issue 必需独立诊断，仅借至返回。
 * @param[in] value 本次已确定的去敏类别。
 * @retval VIREO_RESULT_PROTOCOL 已写诊断，无其他副作用。
 * @note 不持有地址，无资源或共享状态，不修改errno。
 */
static vireo_result_t reject(vireo_node_root_issue_t *issue, vireo_node_root_issue_t value) {
    *issue = value;
    return VIREO_RESULT_PROTOCOL;
}

/**
 * @brief 先有界长度，再公共头/包络/CRC；不扫描TLV
 * @param[in] wire 必需稳定的size字节区，只借至返回。
 * @param[in] size 真实输入长度；超过命令上限时不读取任何输入字节。
 * @param[in] response 是否使用响应方向规则。
 * @param[out] header 必需局部暂存，失败可改变，不是业务发布对象。
 * @param[out] issue 必需独立诊断，失败写检测阶段。
 * @retval VIREO_OK 可安全扫描声明body，精确长度与CRC有效。
 * @retval VIREO_RESULT_PROTOCOL 长度、头、包络或CRC非法。
 * @note 所有地址有效互不重叠，仅借用；无分配/I/O/锁或认证。
 */
static vireo_result_t envelope(unsigned char const *wire, size_t size, bool response,
    vireo_protocol_header_t *header, vireo_node_root_issue_t *issue) {
    if (size < VIREO_PROTOCOL_HEADER_SIZE)
        return reject(issue, VIREO_NODE_ROOT_ISSUE_HEADER);
    if (size > (response ? VIREO_NODE_ROOT_RESPONSE_FRAME_MAX : VIREO_NODE_ROOT_REQUEST_FRAME_SIZE))
        return reject(issue, VIREO_NODE_ROOT_ISSUE_ENVELOPE);

    vireo_protocol_codec_issue_t base_issue;
    if (vireo_protocol_header_decode(wire, size, header, &base_issue) != VIREO_OK ||
        (response ? vireo_protocol_response_header_validate(header, &base_issue) :
                    vireo_protocol_request_header_validate(header, &base_issue)) != VIREO_OK)
        return reject(issue, VIREO_NODE_ROOT_ISSUE_HEADER);

    if (header->command != VIREO_COMMAND_NODE_ROOT || header->task_handle != 0 ||
        header->flags != (response ? VIREO_PROTOCOL_FLAG_RESPONSE : 0) ||
        size != (size_t)VIREO_PROTOCOL_HEADER_SIZE + header->body_len ||
        (response ? (!status_allowed(header->status) ||
            (header->status == VIREO_STATUS_OK ? header->session_handle == 0 :
                (header->session_handle != 0 || header->body_len != 0))) : header->body_len != 0))
        return reject(issue, VIREO_NODE_ROOT_ISSUE_ENVELOPE);

    if (vireo_protocol_frame_crc32c_verify(wire, VIREO_PROTOCOL_HEADER_SIZE,
            wire + VIREO_PROTOCOL_HEADER_SIZE, header->body_len, &base_issue) != VIREO_OK)
        return reject(issue, VIREO_NODE_ROOT_ISSUE_CRC);
    return VIREO_OK;
}

/**
 * @brief 对局部完整body计算CRC，全部成功才一次写外部帧/长度
 * @param[in,out] header 必需局部包头，CRC会被计算结果覆盖。
 * @param[in,out] frame 必需局部size字节暂存，body已构造。
 * @param[in] size 32或44，header.body_len与其匹配。
 * @param[out] wire 必需独立输出，caller已核真实容量不少于size。
 * @param[out] out_size 必需独立长度地址，成功才写。
 * @retval VIREO_OK 完整CRC帧已复制，输出长度已发布。
 * @return 其余为codec意外错误，外部wire/out_size保持。
 * @note 所有指针仅借至返回；无动态owner、I/O、锁或共享状态。
 */
static vireo_result_t publish(vireo_protocol_header_t *header, unsigned char *frame,
    size_t size, unsigned char *wire, size_t *out_size) {
    vireo_result_t result = vireo_protocol_header_encode(header, frame, VIREO_PROTOCOL_HEADER_SIZE);
    if (result == VIREO_OK)
        result = vireo_protocol_frame_crc32c_calculate(frame, VIREO_PROTOCOL_HEADER_SIZE,
            frame + VIREO_PROTOCOL_HEADER_SIZE, size - VIREO_PROTOCOL_HEADER_SIZE, &header->crc32c);
    if (result == VIREO_OK)
        result = vireo_protocol_header_encode(header, frame, VIREO_PROTOCOL_HEADER_SIZE);
    if (result == VIREO_OK) {
        memcpy(wire, frame, size);
        *out_size = size;
    }
    return result;
}

vireo_result_t vireo_node_root_request_encode(vireo_node_root_request_t const *value,
    unsigned char *wire, size_t capacity, size_t *out_size) {
    int const saved_errno = errno;
    if (value == NULL || wire == NULL || out_size == NULL || value->sequence == 0)
        return finish(VIREO_RESULT_INVALID_ARGUMENT, saved_errno);
    if (capacity < VIREO_NODE_ROOT_REQUEST_FRAME_SIZE)
        return finish(VIREO_RESULT_RANGE, saved_errno);
    unsigned char frame[VIREO_NODE_ROOT_REQUEST_FRAME_SIZE];
    vireo_protocol_header_t header = {.command = VIREO_COMMAND_NODE_ROOT,
        .sequence = value->sequence, .session_handle = value->session_handle};
    return finish(publish(&header, frame, sizeof frame, wire, out_size), saved_errno);
}

vireo_result_t vireo_node_root_request_decode(unsigned char const *wire, size_t wire_size,
    vireo_node_root_request_t *out, vireo_node_root_issue_t *issue) {
    int const saved_errno = errno;
    if (issue != NULL) *issue = VIREO_NODE_ROOT_ISSUE_NONE;
    if (wire == NULL || out == NULL || issue == NULL)
        return finish(VIREO_RESULT_INVALID_ARGUMENT, saved_errno);
    vireo_protocol_header_t header;
    vireo_result_t const result = envelope(wire, wire_size, false, &header, issue);
    if (result != VIREO_OK) return finish(result, saved_errno);
    vireo_node_root_request_t const next = {
        .sequence = header.sequence, .session_handle = header.session_handle
    };
    *out = next;
    return finish(VIREO_OK, saved_errno);
}

vireo_result_t vireo_node_root_response_encode(vireo_node_root_response_t const *value,
    unsigned char *wire, size_t capacity, size_t *out_size) {
    int const saved_errno = errno;
    if (value == NULL || wire == NULL || out_size == NULL || value->sequence == 0 ||
        !status_allowed(value->status) || (value->status == VIREO_STATUS_OK ?
            (value->session_handle == 0 || value->root_node_id == 0) :
            (value->session_handle != 0 || value->root_node_id != 0)))
        return finish(VIREO_RESULT_INVALID_ARGUMENT, saved_errno);
    size_t const body = value->status == VIREO_STATUS_OK ? VIREO_NODE_ROOT_RESPONSE_BODY_MAX : 0;
    size_t const size = VIREO_PROTOCOL_HEADER_SIZE + body;
    if (capacity < size) return finish(VIREO_RESULT_RANGE, saved_errno);
    unsigned char frame[VIREO_NODE_ROOT_RESPONSE_FRAME_MAX];
    vireo_result_t result = VIREO_OK;
    if (body != 0) {
        vireo_tlv_writer_t writer;
        result = vireo_tlv_writer_init(&writer, frame + VIREO_PROTOCOL_HEADER_SIZE, body);
        if (result == VIREO_OK)
            result = vireo_tlv_writer_put_u64(&writer, VIREO_NODE_ROOT_TLV_NODE_ID, value->root_node_id);
    }
    vireo_protocol_header_t header = {.command = VIREO_COMMAND_NODE_ROOT,
        .flags = VIREO_PROTOCOL_FLAG_RESPONSE, .status = value->status, .body_len = (uint32_t)body,
        .sequence = value->sequence, .session_handle = value->session_handle};
    if (result == VIREO_OK) result = publish(&header, frame, size, wire, out_size);
    return finish(result, saved_errno);
}

vireo_result_t vireo_node_root_response_decode(unsigned char const *wire, size_t wire_size,
    vireo_node_root_response_t *out, vireo_node_root_issue_t *issue) {
    int const saved_errno = errno;
    if (issue != NULL) *issue = VIREO_NODE_ROOT_ISSUE_NONE;
    if (wire == NULL || out == NULL || issue == NULL)
        return finish(VIREO_RESULT_INVALID_ARGUMENT, saved_errno);
    vireo_protocol_header_t header;
    vireo_result_t const result = envelope(wire, wire_size, true, &header, issue);
    if (result != VIREO_OK) return finish(result, saved_errno);
    vireo_node_root_response_t next = {
        .status = header.status, .sequence = header.sequence, .session_handle = header.session_handle
    };
    if (header.status == VIREO_STATUS_OK) {
        unsigned char seen[1];
        vireo_tlv_issue_t field_issue;
        unsigned char const *body = wire + VIREO_PROTOCOL_HEADER_SIZE;
        if (vireo_tlv_schema_validate(body, header.body_len, &root_rule, 1,
                VIREO_TLV_UNKNOWN_REJECT, seen, sizeof seen, &field_issue) != VIREO_OK)
            return finish(reject(issue, VIREO_NODE_ROOT_ISSUE_FIELDS), saved_errno);
        vireo_tlv_reader_t reader;
        vireo_tlv_view_t field;
        if (vireo_tlv_reader_init(&reader, body, header.body_len) != VIREO_OK ||
            vireo_tlv_reader_next(&reader, &field, &field_issue) != VIREO_OK ||
            vireo_tlv_view_read_u64(&field, &next.root_node_id) != VIREO_OK)
            return finish(reject(issue, VIREO_NODE_ROOT_ISSUE_FIELDS), saved_errno);
        if (next.root_node_id == 0)
            return finish(reject(issue, VIREO_NODE_ROOT_ISSUE_VALUE), saved_errno);
    }
    *out = next;
    return finish(VIREO_OK, saved_errno);
}
