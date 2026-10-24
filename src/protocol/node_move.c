/*
 * PROJECT : VIREO; FILE : node_move.c;
 * AUTHOR : bitofux; DATE : 2026-10-24;
 * BRIEF : NODE_MOVE纯完整帧codec；只借用公开codec/TLV，不执行移动事务。
 */
#include <vireo/protocol/node_move.h>
#include <vireo/protocol/codec.h>
#include <vireo/protocol/tlv.h>
#include <errno.h>
#include <string.h>

/* NAME复用既有UTF-8/单段规则，不在协议层添加NFC转换。 */
static vireo_tlv_rule_t const request_rules[] = {
    {VIREO_NODE_MOVE_TLV_NODE_ID, 8, 8, VIREO_TLV_VALUE_U64, true, false},
    {VIREO_NODE_MOVE_TLV_IDEMPOTENCY_KEY, 16, 16, VIREO_TLV_VALUE_BYTES, true, false},
    {VIREO_NODE_MOVE_TLV_NEW_PARENT_ID, 8, 8, VIREO_TLV_VALUE_U64, true, false},
    {VIREO_NODE_MOVE_TLV_NEW_NAME, 1, 255, VIREO_TLV_VALUE_NAME, true, false}
};
static vireo_tlv_rule_t const response_rules[] = {
    {VIREO_NODE_MOVE_TLV_NODE_ID, 8, 8, VIREO_TLV_VALUE_U64, true, false},
    {VIREO_NODE_MOVE_TLV_IDEMPOTENCY_KEY, 16, 16, VIREO_TLV_VALUE_BYTES, true, false}
};

/**
 * @brief 判断固定宽度逻辑键是否全零
 * @param[in] key 借用的16字节有效只读区，不保存指针。
 * @return 全部字节为零返回true，否则false。
 * @note 不读取结构体padding，不修改输入或errno，无外部资源。
 */
static bool key_zero(unsigned char const *key) {
    for (size_t i = 0; i < VIREO_NODE_MOVE_KEY_SIZE; ++i)
        if (key[i] != 0) return false;
    return true;
}

/** @brief 只接受本命令19种已注册状态，不把内部rc强转上wire。 */
static bool status_allowed(vireo_status_t status) {
    switch (status) {
    case VIREO_STATUS_OK: case VIREO_STATUS_BAD_REQUEST: case VIREO_STATUS_UNSUPPORTED:
    case VIREO_STATUS_CRC_MISMATCH: case VIREO_STATUS_BODY_TOO_LARGE:
    case VIREO_STATUS_INVALID_FLAGS: case VIREO_STATUS_DUPLICATE_REQUEST:
    case VIREO_STATUS_RATE_LIMITED: case VIREO_STATUS_UNAUTHORIZED: case VIREO_STATUS_NOT_FOUND:
    case VIREO_STATUS_FORBIDDEN: case VIREO_STATUS_INVALID_PATH: case VIREO_STATUS_CONFLICT:
    case VIREO_STATUS_BUSY: case VIREO_STATUS_INTERNAL_ERROR: case VIREO_STATUS_DB_ERROR:
    case VIREO_STATUS_TIMEOUT: case VIREO_STATUS_OVERLOADED: case VIREO_STATUS_UNAVAILABLE:
        return true;
    default: return false;
    }
}

/** @brief 保存入口errno并返回已有rc，不接管资源。 */
static vireo_result_t finish(vireo_result_t rc, int saved) {
    errno = saved;
    return rc;
}

/** @brief 必需独立issue发布本地拒绝类别；业务out保持。 */
static vireo_result_t reject(vireo_node_move_issue_t *issue, vireo_node_move_issue_t value) {
    *issue = value;
    return VIREO_RESULT_PROTOCOL;
}

/**
 * @brief 在局部帧完成CRC后一次发布完整输出
 * @param[in,out] h 有效独立局部头，body_len等于size-32，更新crc32c。
 * @param[in,out] frame 至少size字节局部帧，32字节后的body已完整编码。
 * @param[in] size 本次完整帧长，至少32且不超过局部数组容量。
 * @param[out] wire 至少size字节独立可写区，caller已核容量，失败保持。
 * @param[out] out_size 必需独立输出地址，完整成功才发布长度。
 * @return 沿公开codec返回值，不发布任何半帧。
 * @note 全部地址短借至返回，frame/h为调用者私有临时区，无分配或借用逸出。
 */
static vireo_result_t publish(vireo_protocol_header_t *h, unsigned char *frame, size_t size,
                              unsigned char *wire, size_t *out_size) {
    vireo_result_t rc = vireo_protocol_header_encode(h, frame, 32);
    if (rc == VIREO_OK)
        rc = vireo_protocol_frame_crc32c_calculate(frame, 32, frame + 32, size - 32, &h->crc32c);
    if (rc == VIREO_OK) rc = vireo_protocol_header_encode(h, frame, 32);
    if (rc == VIREO_OK) { memcpy(wire, frame, size); *out_size = size; }
    return rc;
}

/**
 * @brief 验证固定TLV规则并区分名字取值和字段结构诊断
 * @param[in] body 借用size字节有效只读body。
 * @param[in] size 已通过包络或编码长度约束的body字节数。
 * @param[in] response true选择成功响应两字段，否则请求四字段。
 * @param[out] issue 必需独立局部诊断，仅失败时写VALUE或FIELDS。
 * @return 沿schema原rc；UTF-8/NAME错误归VALUE，其余失败归FIELDS。
 * @note 固定seen工作区，规则全只读，不保存输入，不分配，不执行NFC。
 */
static vireo_result_t schema(unsigned char const *body, size_t size, bool response,
                             vireo_node_move_issue_t *issue) {
    unsigned char seen[4];
    vireo_tlv_issue_t ti;
    vireo_result_t rc = vireo_tlv_schema_validate(body, size,
        response ? response_rules : request_rules, response ? 2U : 4U,
        VIREO_TLV_UNKNOWN_REJECT, seen, sizeof seen, &ti);
    if (rc != VIREO_OK) {
        *issue = ti == VIREO_TLV_ISSUE_INVALID_UTF8 || ti == VIREO_TLV_ISSUE_INVALID_NAME ?
            VIREO_NODE_MOVE_ISSUE_VALUE : VIREO_NODE_MOVE_ISSUE_FIELDS;
    }
    return rc;
}

vireo_result_t vireo_node_move_request_encode(vireo_node_move_request_t const *value,
    unsigned char *wire, size_t capacity, size_t *out_size) {
    int const saved = errno;
    if (value == NULL || wire == NULL || out_size == NULL || value->sequence == 0 ||
        value->node_id == 0 || value->new_parent_id == 0 || value->new_name_length == 0 ||
        value->new_name_length > VIREO_NODE_MOVE_NAME_CAPACITY || key_zero(value->idempotency_key))
        return finish(VIREO_RESULT_INVALID_ARGUMENT, saved);
    /* 先在固定局部帧验证NAME，再检查caller容量；非法值优先于RANGE。 */
    size_t const body = 48 + value->new_name_length;
    unsigned char frame[VIREO_NODE_MOVE_REQUEST_FRAME_MAX];
    vireo_tlv_writer_t w;
    vireo_result_t rc = vireo_tlv_writer_init(&w, frame + 32, body);
    if (rc == VIREO_OK) rc = vireo_tlv_writer_put_u64(&w, VIREO_NODE_MOVE_TLV_NODE_ID, value->node_id);
    if (rc == VIREO_OK) rc = vireo_tlv_writer_put(&w, VIREO_NODE_MOVE_TLV_IDEMPOTENCY_KEY,
                                               value->idempotency_key, VIREO_NODE_MOVE_KEY_SIZE);
    if (rc == VIREO_OK) rc = vireo_tlv_writer_put_u64(&w, VIREO_NODE_MOVE_TLV_NEW_PARENT_ID, value->new_parent_id);
    if (rc == VIREO_OK) rc = vireo_tlv_writer_put(&w, VIREO_NODE_MOVE_TLV_NEW_NAME, value->new_name, value->new_name_length);
    vireo_node_move_issue_t issue;
    if (rc == VIREO_OK) {
        rc = schema(frame + 32, body, false, &issue);
        if (rc == VIREO_RESULT_PROTOCOL) rc = VIREO_RESULT_INVALID_ARGUMENT;
    }
    if (rc != VIREO_OK) return finish(rc, saved);
    if (capacity < 32 + body) return finish(VIREO_RESULT_RANGE, saved);
    vireo_protocol_header_t h = {.command = VIREO_COMMAND_NODE_MOVE, .body_len = (uint32_t)body,
        .sequence = value->sequence, .session_handle = value->session_handle};
    return finish(publish(&h, frame, 32 + body, wire, out_size), saved);
}

/**
 * @brief 校验实际有界长度、头、命令包络和CRC
 * @param[in] wire 必需稳定只读size字节区域，借用至返回。
 * @param[in] size 实际长度，先拒绝越界，再读取公共头或body。
 * @param[in] response true要求精确响应flags/状态/handle/body关系。
 * @param[out] h 必需独立局部头，可被基础解析部分修改，失败不发布业务out。
 * @param[out] issue 必需独立诊断，失败写HEADER/ENVELOPE/CRC。
 * @return 校验通过返回OK，否则PROTOCOL；不证明可信身份或事务事实。
 * @note 先核32+body_len精确相等才扫描body，所有地址不保存，无分配/I/O。
 */
static vireo_result_t envelope(unsigned char const *wire, size_t size, bool response,
                               vireo_protocol_header_t *h, vireo_node_move_issue_t *issue) {
    if (size < 32) return reject(issue, VIREO_NODE_MOVE_ISSUE_HEADER);
    if (response ? (size != 32 && size != VIREO_NODE_MOVE_RESPONSE_FRAME_MAX) :
        (size < VIREO_NODE_MOVE_REQUEST_FRAME_MIN || size > VIREO_NODE_MOVE_REQUEST_FRAME_MAX))
        return reject(issue, VIREO_NODE_MOVE_ISSUE_ENVELOPE);
    vireo_protocol_codec_issue_t ci;
    if (vireo_protocol_header_decode(wire, size, h, &ci) != VIREO_OK ||
        (response ? vireo_protocol_response_header_validate(h, &ci) :
                    vireo_protocol_request_header_validate(h, &ci)) != VIREO_OK)
        return reject(issue, VIREO_NODE_MOVE_ISSUE_HEADER);
    if (h->command != VIREO_COMMAND_NODE_MOVE || h->task_handle != 0 ||
        h->flags != (response ? VIREO_PROTOCOL_FLAG_RESPONSE : 0) ||
        size != (size_t)32 + h->body_len ||
        (response && (!status_allowed(h->status) ||
            (h->status == VIREO_STATUS_OK ?
                (h->session_handle == 0 || h->body_len != VIREO_NODE_MOVE_RESPONSE_BODY_SIZE) :
                (h->session_handle != 0 || h->body_len != 0)))))
        return reject(issue, VIREO_NODE_MOVE_ISSUE_ENVELOPE);
    if (vireo_protocol_frame_crc32c_verify(wire, 32, wire + 32, h->body_len, &ci) != VIREO_OK)
        return reject(issue, VIREO_NODE_MOVE_ISSUE_CRC);
    return VIREO_OK;
}

/**
 * @brief 从已通过固定schema的body复制请求字段
 * @param[in] body 借用size字节完整且已验证的请求body。
 * @param[in] size 已验证的49..303字节长度。
 * @param[in,out] next 必需独立局部请求，caller已清零并写关联号，失败可部分修改。
 * @return 读取成功返回OK，否则沿reader/view原rc或未知字段PROTOCOL。
 * @note NAME长度/键宽度依赖前置schema；不直接发布caller out，不保留借用。
 */
static vireo_result_t read_request(unsigned char const *body, size_t size,
                                  vireo_node_move_request_t *next) {
    vireo_tlv_reader_t r;
    vireo_result_t rc = vireo_tlv_reader_init(&r, body, size);
    while (rc == VIREO_OK && r.offset < r.size) {
        vireo_tlv_view_t f; vireo_tlv_issue_t ti;
        rc = vireo_tlv_reader_next(&r, &f, &ti);
        if (rc != VIREO_OK) break;
        switch (f.type) {
        case VIREO_NODE_MOVE_TLV_NODE_ID: rc = vireo_tlv_view_read_u64(&f, &next->node_id); break;
        case VIREO_NODE_MOVE_TLV_NEW_PARENT_ID: rc = vireo_tlv_view_read_u64(&f, &next->new_parent_id); break;
        case VIREO_NODE_MOVE_TLV_NEW_NAME:
            next->new_name_length = f.length; memcpy(next->new_name, f.value, f.length); break;
        case VIREO_NODE_MOVE_TLV_IDEMPOTENCY_KEY:
            memcpy(next->idempotency_key, f.value, VIREO_NODE_MOVE_KEY_SIZE); break;
        default: return VIREO_RESULT_PROTOCOL;
        }
    }
    return rc;
}

vireo_result_t vireo_node_move_request_decode(unsigned char const *wire, size_t wire_size,
    vireo_node_move_request_t *out, vireo_node_move_issue_t *issue) {
    int const saved = errno;
    if (issue != NULL) *issue = VIREO_NODE_MOVE_ISSUE_NONE;
    if (wire == NULL || out == NULL || issue == NULL) return finish(VIREO_RESULT_INVALID_ARGUMENT, saved);
    vireo_protocol_header_t h;
    vireo_result_t rc = envelope(wire, wire_size, false, &h, issue);
    if (rc != VIREO_OK) return finish(rc, saved);
    rc = schema(wire + 32, h.body_len, false, issue);
    if (rc != VIREO_OK) return finish(VIREO_RESULT_PROTOCOL, saved);
    vireo_node_move_request_t next;
    memset(&next, 0, sizeof next);
    next.sequence = h.sequence; next.session_handle = h.session_handle;
    if (read_request(wire + 32, h.body_len, &next) != VIREO_OK)
        return finish(reject(issue, VIREO_NODE_MOVE_ISSUE_FIELDS), saved);
    if (next.node_id == 0 || next.new_parent_id == 0 || key_zero(next.idempotency_key))
        return finish(reject(issue, VIREO_NODE_MOVE_ISSUE_VALUE), saved);
    memcpy(out, &next, sizeof next);
    return finish(VIREO_OK, saved);
}

vireo_result_t vireo_node_move_response_encode(vireo_node_move_response_t const *value,
    unsigned char *wire, size_t capacity, size_t *out_size) {
    int const saved = errno;
    if (value == NULL || wire == NULL || out_size == NULL || value->sequence == 0 ||
        !status_allowed(value->status) || (value->status == VIREO_STATUS_OK ?
            (value->session_handle == 0 || value->node_id == 0 || key_zero(value->idempotency_key)) :
            (value->session_handle != 0 || value->node_id != 0 || !key_zero(value->idempotency_key))))
        return finish(VIREO_RESULT_INVALID_ARGUMENT, saved);
    size_t const body = value->status == VIREO_STATUS_OK ? VIREO_NODE_MOVE_RESPONSE_BODY_SIZE : 0;
    if (capacity < 32 + body) return finish(VIREO_RESULT_RANGE, saved);
    unsigned char frame[VIREO_NODE_MOVE_RESPONSE_FRAME_MAX];
    vireo_result_t rc = VIREO_OK;
    if (body != 0) {
        vireo_tlv_writer_t w;
        rc = vireo_tlv_writer_init(&w, frame + 32, body);
        if (rc == VIREO_OK) rc = vireo_tlv_writer_put_u64(&w, VIREO_NODE_MOVE_TLV_NODE_ID, value->node_id);
        if (rc == VIREO_OK) rc = vireo_tlv_writer_put(&w, VIREO_NODE_MOVE_TLV_IDEMPOTENCY_KEY,
                                                   value->idempotency_key, VIREO_NODE_MOVE_KEY_SIZE);
    }
    vireo_protocol_header_t h = {.command = VIREO_COMMAND_NODE_MOVE,
        .flags = VIREO_PROTOCOL_FLAG_RESPONSE, .status = value->status, .body_len = (uint32_t)body,
        .sequence = value->sequence, .session_handle = value->session_handle};
    if (rc == VIREO_OK) rc = publish(&h, frame, 32 + body, wire, out_size);
    return finish(rc, saved);
}

vireo_result_t vireo_node_move_response_decode(unsigned char const *wire, size_t wire_size,
    vireo_node_move_response_t *out, vireo_node_move_issue_t *issue) {
    int const saved = errno;
    if (issue != NULL) *issue = VIREO_NODE_MOVE_ISSUE_NONE;
    if (wire == NULL || out == NULL || issue == NULL) return finish(VIREO_RESULT_INVALID_ARGUMENT, saved);
    vireo_protocol_header_t h;
    vireo_result_t rc = envelope(wire, wire_size, true, &h, issue);
    if (rc != VIREO_OK) return finish(rc, saved);
    vireo_node_move_response_t next;
    memset(&next, 0, sizeof next);
    next.status = h.status; next.sequence = h.sequence; next.session_handle = h.session_handle;
    if (h.status == VIREO_STATUS_OK) {
        rc = schema(wire + 32, h.body_len, true, issue);
        if (rc != VIREO_OK) return finish(VIREO_RESULT_PROTOCOL, saved);
        vireo_tlv_reader_t r;
        rc = vireo_tlv_reader_init(&r, wire + 32, h.body_len);
        while (rc == VIREO_OK && r.offset < r.size) {
            vireo_tlv_view_t f; vireo_tlv_issue_t ti;
            rc = vireo_tlv_reader_next(&r, &f, &ti);
            if (rc != VIREO_OK) break;
            if (f.type == VIREO_NODE_MOVE_TLV_NODE_ID) rc = vireo_tlv_view_read_u64(&f, &next.node_id);
            else memcpy(next.idempotency_key, f.value, VIREO_NODE_MOVE_KEY_SIZE);
        }
        if (rc != VIREO_OK) return finish(reject(issue, VIREO_NODE_MOVE_ISSUE_FIELDS), saved);
        if (next.node_id == 0 || key_zero(next.idempotency_key))
            return finish(reject(issue, VIREO_NODE_MOVE_ISSUE_VALUE), saved);
    }
    memcpy(out, &next, sizeof next);
    return finish(VIREO_OK, saved);
}
