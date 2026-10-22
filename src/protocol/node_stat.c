/* NODE_STAT命令级完整帧；只复用公开codec/TLV，不持有外部资源。 */
#include <vireo/protocol/node_stat.h>
#include <vireo/protocol/codec.h>
#include <vireo/protocol/tlv.h>
#include <errno.h>
#include <string.h>

/* 固定schema：NAME按原始字节读取；字段存在性另作节点关系校验。 */
static vireo_tlv_rule_t const rules[] = {
    {0x0401, 8, 8, VIREO_TLV_VALUE_U64, true, false},
    {0x0402, 8, 8, VIREO_TLV_VALUE_U64, false, false},
    {0x0403, 0, 255, VIREO_TLV_VALUE_BYTES, true, false},
    {0x0404, 2, 2, VIREO_TLV_VALUE_U16, true, false},
    {0x0405, 8, 8, VIREO_TLV_VALUE_U64, true, false},
    {0x0406, 8, 8, VIREO_TLV_VALUE_U64, true, false},
    {0x0407, 8, 8, VIREO_TLV_VALUE_U64, true, false},
    {0x0408, 32, 32, VIREO_TLV_VALUE_BYTES, false, false}
};

/** @brief 借用n字节有效只读区；检查每字节为零，不读取结构体padding。 */
static bool zero_bytes(unsigned char const *p, size_t n) {
    for (size_t i = 0; i < n; ++i) if (p[i] != 0) return false;
    return true;
}

/** @brief 仅判断本命令明确允许的wire状态；不映射内部业务rc。 */
static bool status_allowed(vireo_status_t status) {
    switch (status) {
    case VIREO_STATUS_OK: case VIREO_STATUS_BAD_REQUEST: case VIREO_STATUS_UNSUPPORTED:
    case VIREO_STATUS_CRC_MISMATCH: case VIREO_STATUS_BODY_TOO_LARGE:
    case VIREO_STATUS_INVALID_FLAGS: case VIREO_STATUS_DUPLICATE_REQUEST:
    case VIREO_STATUS_RATE_LIMITED: case VIREO_STATUS_UNAUTHORIZED: case VIREO_STATUS_NOT_FOUND:
    case VIREO_STATUS_BUSY: case VIREO_STATUS_INTERNAL_ERROR: case VIREO_STATUS_TIMEOUT:
    case VIREO_STATUS_OVERLOADED: case VIREO_STATUS_UNAVAILABLE: return true;
    default: return false;
    }
}

/** @brief 借用有效metadata；只检查成员，失败无修改，无外部资源。 */
static bool metadata_zero(vireo_node_stat_metadata_t const *m) {
    return m->node_id == 0 && !m->has_parent && m->parent_id == 0 &&
        m->name_length == 0 && zero_bytes(m->name, sizeof m->name) && m->type == 0 &&
        m->size == 0 && m->created_at_ms == 0 && m->updated_at_ms == 0 &&
        !m->has_object_hash && zero_bytes(m->object_hash, sizeof m->object_hash);
}

/** @brief 借用有效metadata；校验根/父/名字/类型/hash关系，不检查授权或祖先。 */
static bool metadata_valid(vireo_node_stat_metadata_t const *m) {
    if (m->node_id == 0 || m->name_length > sizeof m->name ||
        m->updated_at_ms < m->created_at_ms) return false;
    if (m->has_parent) {
        if (m->parent_id == 0 || m->name_length == 0) return false;
    } else if (m->parent_id != 0 || m->name_length != 0 || m->type != VIREO_NODE_STAT_DIRECTORY)
        return false;
    for (size_t i = 0; i < m->name_length; ++i)
        if (m->name[i] == 0 || m->name[i] == '/') return false;
    if ((m->name_length == 1 && m->name[0] == '.') ||
        (m->name_length == 2 && m->name[0] == '.' && m->name[1] == '.')) return false;
    if (m->type == VIREO_NODE_STAT_DIRECTORY)
        return m->size == 0 && !m->has_object_hash && zero_bytes(m->object_hash, 32);
    return m->type == VIREO_NODE_STAT_FILE && m->has_object_hash;
}

/** @brief 保持调用入口errno，返回已有rc；无资源/输出所有权变化。 */
static vireo_result_t finish(vireo_result_t rc, int saved_errno) {
    errno = saved_errno;
    return rc;
}

/** @brief 借用必需issue并发布本地拒绝类别；out值由上层保持。 */
static vireo_result_t reject(vireo_node_stat_issue_t *issue, vireo_node_stat_issue_t value) {
    *issue = value;
    return VIREO_RESULT_PROTOCOL;
}

/** @brief 借用局部帧和头，完成CRC后一次发布；调用前保证capacity容纳size。 */
static vireo_result_t publish(vireo_protocol_header_t *h, unsigned char *frame, size_t size,
                              unsigned char *wire, size_t *out_size) {
    vireo_result_t rc = vireo_protocol_header_encode(h, frame, 32);
    if (rc == VIREO_OK) rc = vireo_protocol_frame_crc32c_calculate(frame, 32, frame + 32,
                                                                size - 32, &h->crc32c);
    if (rc == VIREO_OK) rc = vireo_protocol_header_encode(h, frame, 32);
    if (rc == VIREO_OK) { memcpy(wire, frame, size); *out_size = size; }
    return rc;
}

vireo_result_t vireo_node_stat_request_encode(vireo_node_stat_request_t const *value,
    unsigned char *wire, size_t capacity, size_t *out_size) {
    int const saved = errno;
    if (value == NULL || wire == NULL || out_size == NULL || value->sequence == 0 || value->node_id == 0)
        return finish(VIREO_RESULT_INVALID_ARGUMENT, saved);
    if (capacity < VIREO_NODE_STAT_REQUEST_FRAME_SIZE) return finish(VIREO_RESULT_RANGE, saved);
    unsigned char frame[44];
    vireo_tlv_writer_t w;
    vireo_result_t rc = vireo_tlv_writer_init(&w, frame + 32, 12);
    if (rc == VIREO_OK) rc = vireo_tlv_writer_put_u64(&w, VIREO_NODE_STAT_TLV_NODE_ID, value->node_id);
    vireo_protocol_header_t h = {.command = VIREO_COMMAND_NODE_STAT, .body_len = 12,
        .sequence = value->sequence, .session_handle = value->session_handle};
    if (rc == VIREO_OK) rc = publish(&h, frame, sizeof frame, wire, out_size);
    return finish(rc, saved);
}

/** @brief 校验有界完整帧，再扫描CRC；h/issue必需独立有效，失败不发布业务值。 */
static vireo_result_t envelope(unsigned char const *wire, size_t size, bool response,
                               vireo_protocol_header_t *h, vireo_node_stat_issue_t *issue) {
    vireo_protocol_codec_issue_t ci;
    if (vireo_protocol_header_decode(wire, size, h, &ci) != VIREO_OK ||
        (response ? vireo_protocol_response_header_validate(h, &ci) :
                    vireo_protocol_request_header_validate(h, &ci)) != VIREO_OK)
        return reject(issue, VIREO_NODE_STAT_ISSUE_HEADER);
    if (h->command != VIREO_COMMAND_NODE_STAT || h->task_handle != 0 ||
        h->flags != (response ? VIREO_PROTOCOL_FLAG_RESPONSE : 0) ||
        (response ? (!status_allowed(h->status) ||
            (h->status == VIREO_STATUS_OK ? h->session_handle == 0 :
                (h->session_handle != 0 || h->body_len != 0)) ||
            h->body_len > VIREO_NODE_STAT_RESPONSE_BODY_MAX) : h->body_len != 12) ||
        size != (size_t)32 + h->body_len)
        return reject(issue, VIREO_NODE_STAT_ISSUE_ENVELOPE);
    if (vireo_protocol_frame_crc32c_verify(wire, 32, wire + 32, h->body_len, &ci) != VIREO_OK)
        return reject(issue, VIREO_NODE_STAT_ISSUE_CRC);
    return VIREO_OK;
}

vireo_result_t vireo_node_stat_request_decode(unsigned char const *wire, size_t wire_size,
    vireo_node_stat_request_t *out, vireo_node_stat_issue_t *issue) {
    int const saved = errno;
    if (issue != NULL) *issue = VIREO_NODE_STAT_ISSUE_NONE;
    if (wire == NULL || out == NULL || issue == NULL) return finish(VIREO_RESULT_INVALID_ARGUMENT, saved);
    vireo_protocol_header_t h;
    vireo_result_t rc = envelope(wire, wire_size, false, &h, issue);
    if (rc != VIREO_OK) return finish(rc, saved);
    unsigned char seen[1]; vireo_tlv_issue_t ti;
    if (vireo_tlv_schema_validate(wire + 32, 12, rules, 1, VIREO_TLV_UNKNOWN_REJECT,
                                   seen, sizeof seen, &ti) != VIREO_OK)
        return finish(reject(issue, VIREO_NODE_STAT_ISSUE_FIELDS), saved);
    vireo_tlv_reader_t r; vireo_tlv_view_t f;
    vireo_node_stat_request_t next = {.sequence = h.sequence, .session_handle = h.session_handle};
    if (vireo_tlv_reader_init(&r, wire + 32, 12) != VIREO_OK ||
        vireo_tlv_reader_next(&r, &f, &ti) != VIREO_OK ||
        vireo_tlv_view_read_u64(&f, &next.node_id) != VIREO_OK)
        return finish(reject(issue, VIREO_NODE_STAT_ISSUE_FIELDS), saved);
    if (next.node_id == 0) return finish(reject(issue, VIREO_NODE_STAT_ISSUE_VALUE), saved);
    *out = next;
    return finish(VIREO_OK, saved);
}

vireo_result_t vireo_node_stat_response_encode(vireo_node_stat_response_t const *value,
    unsigned char *wire, size_t capacity, size_t *out_size) {
    int const saved = errno;
    if (value == NULL || wire == NULL || out_size == NULL || value->sequence == 0 ||
        !status_allowed(value->status) || (value->status == VIREO_STATUS_OK ?
            (value->session_handle == 0 || !metadata_valid(&value->metadata)) :
            (value->session_handle != 0 || !metadata_zero(&value->metadata))))
        return finish(VIREO_RESULT_INVALID_ARGUMENT, saved);
    vireo_node_stat_metadata_t const *m = &value->metadata;
    size_t const body = value->status == VIREO_STATUS_OK ?
        58 + m->name_length + (m->has_parent ? 12U : 0U) + (m->has_object_hash ? 36U : 0U) : 0;
    if (capacity < 32 + body) return finish(VIREO_RESULT_RANGE, saved);
    unsigned char frame[393]; vireo_tlv_writer_t w;
    vireo_result_t rc = vireo_tlv_writer_init(&w, frame + 32, body);
    /* 只写局部帧；每一步失败均沿原rc退出，不发布半帧。 */
#define PUT(call) do { if (rc == VIREO_OK) rc = (call); } while (0)
    if (body != 0) {
        PUT(vireo_tlv_writer_put_u64(&w, VIREO_NODE_STAT_TLV_NODE_ID, m->node_id));
        if (m->has_parent) PUT(vireo_tlv_writer_put_u64(&w, VIREO_NODE_STAT_TLV_PARENT_ID, m->parent_id));
        PUT(vireo_tlv_writer_put(&w, VIREO_NODE_STAT_TLV_NAME_BYTES, m->name, m->name_length));
        PUT(vireo_tlv_writer_put_u16(&w, VIREO_NODE_STAT_TLV_NODE_TYPE, m->type));
        PUT(vireo_tlv_writer_put_u64(&w, VIREO_NODE_STAT_TLV_SIZE, m->size));
        PUT(vireo_tlv_writer_put_u64(&w, VIREO_NODE_STAT_TLV_CREATED_AT_MS, m->created_at_ms));
        PUT(vireo_tlv_writer_put_u64(&w, VIREO_NODE_STAT_TLV_UPDATED_AT_MS, m->updated_at_ms));
        if (m->has_object_hash) PUT(vireo_tlv_writer_put(&w, VIREO_NODE_STAT_TLV_OBJECT_HASH, m->object_hash, 32));
    }
#undef PUT
    vireo_protocol_header_t h = {.command = VIREO_COMMAND_NODE_STAT,
        .flags = VIREO_PROTOCOL_FLAG_RESPONSE, .status = value->status, .body_len = (uint32_t)body,
        .sequence = value->sequence, .session_handle = value->session_handle};
    if (rc == VIREO_OK) rc = publish(&h, frame, 32 + body, wire, out_size);
    return finish(rc, saved);
}

/** @brief 借用已校验schema的body，向局部metadata复制字段；无借用逸出。 */
static vireo_result_t read_metadata(unsigned char const *body, size_t size, vireo_node_stat_metadata_t *m) {
    vireo_tlv_reader_t r;
    vireo_result_t rc = vireo_tlv_reader_init(&r, body, size);
    if (rc != VIREO_OK) return rc;
    while (r.offset < r.size) {
        vireo_tlv_view_t f; vireo_tlv_issue_t ti;
        rc = vireo_tlv_reader_next(&r, &f, &ti);
        if (rc != VIREO_OK) return rc;
        switch (f.type) {
        case VIREO_NODE_STAT_TLV_NODE_ID: rc = vireo_tlv_view_read_u64(&f, &m->node_id); break;
        case VIREO_NODE_STAT_TLV_PARENT_ID:
            m->has_parent = true; rc = vireo_tlv_view_read_u64(&f, &m->parent_id); break;
        case VIREO_NODE_STAT_TLV_NAME_BYTES:
            m->name_length = f.length; memcpy(m->name, f.value, f.length); break;
        case VIREO_NODE_STAT_TLV_NODE_TYPE: rc = vireo_tlv_view_read_u16(&f, &m->type); break;
        case VIREO_NODE_STAT_TLV_SIZE: rc = vireo_tlv_view_read_u64(&f, &m->size); break;
        case VIREO_NODE_STAT_TLV_CREATED_AT_MS: rc = vireo_tlv_view_read_u64(&f, &m->created_at_ms); break;
        case VIREO_NODE_STAT_TLV_UPDATED_AT_MS: rc = vireo_tlv_view_read_u64(&f, &m->updated_at_ms); break;
        case VIREO_NODE_STAT_TLV_OBJECT_HASH:
            m->has_object_hash = true; memcpy(m->object_hash, f.value, 32); break;
        default: return VIREO_RESULT_PROTOCOL;
        }
        if (rc != VIREO_OK) return rc;
    }
    return VIREO_OK;
}

vireo_result_t vireo_node_stat_response_decode(unsigned char const *wire, size_t wire_size,
    vireo_node_stat_response_t *out, vireo_node_stat_issue_t *issue) {
    int const saved = errno;
    if (issue != NULL) *issue = VIREO_NODE_STAT_ISSUE_NONE;
    if (wire == NULL || out == NULL || issue == NULL) return finish(VIREO_RESULT_INVALID_ARGUMENT, saved);
    vireo_protocol_header_t h;
    vireo_result_t rc = envelope(wire, wire_size, true, &h, issue);
    if (rc != VIREO_OK) return finish(rc, saved);
    vireo_node_stat_response_t next = {.status = h.status, .sequence = h.sequence, .session_handle = h.session_handle};
    if (h.status == VIREO_STATUS_OK) {
        unsigned char seen[8]; vireo_tlv_issue_t ti;
        if (vireo_tlv_schema_validate(wire + 32, h.body_len, rules, 8, VIREO_TLV_UNKNOWN_REJECT,
                                       seen, sizeof seen, &ti) != VIREO_OK ||
            read_metadata(wire + 32, h.body_len, &next.metadata) != VIREO_OK)
            return finish(reject(issue, VIREO_NODE_STAT_ISSUE_FIELDS), saved);
        if (!metadata_valid(&next.metadata)) return finish(reject(issue, VIREO_NODE_STAT_ISSUE_VALUE), saved);
    }
    *out = next;
    return finish(VIREO_OK, saved);
}
