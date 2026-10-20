#include <vireo/protocol/auth_request.h>

#include <errno.h>
#include <stdbool.h>
#include <vireo/protocol/codec.h>
#include <vireo/protocol/tlv.h>

/* 规则是 wire 边界的独立检查；protocol 不反向依赖 service。 */
static vireo_tlv_rule_t const rules[] = {
    {.type = VIREO_AUTH_TLV_USERNAME, .min_length = 3, .max_length = 32,
     .value_kind = VIREO_TLV_VALUE_BYTES, .required = true, .repeatable = false},
    {.type = VIREO_AUTH_TLV_PASSWORD, .min_length = 8, .max_length = 64,
     .value_kind = VIREO_TLV_VALUE_BYTES, .required = true, .repeatable = false},
    {.type = VIREO_AUTH_TLV_DEVICE, .min_length = 16, .max_length = 16,
     .value_kind = VIREO_TLV_VALUE_BYTES, .required = true, .repeatable = false}
};

static vireo_result_t reject(vireo_auth_request_issue_t *issue,
                             vireo_auth_request_issue_t value, int saved_errno) {
    *issue = value;
    errno = saved_errno;
    return VIREO_RESULT_PROTOCOL;
}

vireo_result_t vireo_auth_request_decode(uint8_t const *wire, size_t wire_size,
                                       vireo_auth_request_view_t *out_view,
                                       vireo_auth_request_issue_t *out_issue) {
    int const saved_errno = errno;
    if (out_issue != NULL)
        *out_issue = VIREO_AUTH_REQUEST_ISSUE_NONE;
    if (wire == NULL || out_view == NULL || out_issue == NULL) {
        errno = saved_errno;
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    vireo_protocol_header_t header;
    vireo_protocol_codec_issue_t codec_issue;
    if (vireo_protocol_header_decode(wire, wire_size, &header, &codec_issue) != VIREO_OK ||
        vireo_protocol_request_header_validate(&header, &codec_issue) != VIREO_OK)
        return reject(out_issue, VIREO_AUTH_REQUEST_ISSUE_HEADER, saved_errno);
    bool const login = header.command == VIREO_COMMAND_LOGIN;
    bool const resume = header.command == VIREO_COMMAND_SESSION_RESUME;
    bool const logout = header.command == VIREO_COMMAND_LOGOUT;
    size_t const max_body = login ? VIREO_AUTH_LOGIN_BODY_MAX : resume ? VIREO_AUTH_RESUME_BODY_MAX :
        logout ? 0 : VIREO_AUTH_REGISTER_BODY_MAX;
    /* 先核有界 body_len 再加32；既防溢出，也不扫描攻击者给的大 body。 */
    if ((!login && !resume && !logout && header.command != VIREO_COMMAND_REGISTER) || header.flags != 0 ||
        (logout ? header.session_handle == 0 : header.session_handle != 0) || header.task_handle != 0 || header.body_len > max_body ||
        wire_size != (size_t)VIREO_PROTOCOL_HEADER_SIZE + header.body_len)
        return reject(out_issue, VIREO_AUTH_REQUEST_ISSUE_ENVELOPE, saved_errno);
    uint8_t const *body = wire + VIREO_PROTOCOL_HEADER_SIZE;
    if (vireo_protocol_frame_crc32c_verify(wire, VIREO_PROTOCOL_HEADER_SIZE,
                                          body, header.body_len, &codec_issue) != VIREO_OK)
        return reject(out_issue, VIREO_AUTH_REQUEST_ISSUE_CRC, saved_errno);
    uint8_t seen[3];
    vireo_tlv_issue_t tlv_issue;
    vireo_tlv_rule_t const token_rule = {.type=VIREO_AUTH_TLV_SESSION_TOKEN,.min_length=32,.max_length=32,
        .value_kind=VIREO_TLV_VALUE_BYTES,.required=true,.repeatable=false};
    if (!logout && vireo_tlv_schema_validate(body, header.body_len, resume ? &token_rule : rules, resume ? 1U : login ? 3U : 2U,
                                  VIREO_TLV_UNKNOWN_REJECT, seen, sizeof(seen),
                                  &tlv_issue) != VIREO_OK)
        return reject(out_issue, VIREO_AUTH_REQUEST_ISSUE_FIELDS, saved_errno);
    vireo_auth_request_view_t next = {0};
    next.command = header.command;
    next.sequence = header.sequence;
    next.session_handle = header.session_handle;
    vireo_tlv_reader_t reader;
    if (vireo_tlv_reader_init(&reader, body, header.body_len) != VIREO_OK)
        return reject(out_issue, VIREO_AUTH_REQUEST_ISSUE_FIELDS, saved_errno);
    while (reader.offset < reader.size) {
        vireo_tlv_view_t field;
        if (vireo_tlv_reader_next(&reader, &field, &tlv_issue) != VIREO_OK)
            return reject(out_issue, VIREO_AUTH_REQUEST_ISSUE_FIELDS, saved_errno);
        if (field.type == VIREO_AUTH_TLV_USERNAME) {
            next.username = field.value;
            next.username_size = field.length;
        } else if (field.type == VIREO_AUTH_TLV_PASSWORD) {
            next.password = field.value;
            next.password_size = field.length;
        } else if (field.type == VIREO_AUTH_TLV_SESSION_TOKEN) {
            next.token = field.value;
        } else {
            next.device = field.value;
        }
    }
    for (size_t i = 0; i < next.username_size; ++i) {
        uint8_t const c = next.username[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') || c == '_'))
            return reject(out_issue, VIREO_AUTH_REQUEST_ISSUE_USERNAME, saved_errno);
    }
    for (size_t i = 0; i < next.password_size; ++i)
        if (next.password[i] < UINT8_C(0x21) || next.password[i] > UINT8_C(0x7e))
            return reject(out_issue, VIREO_AUTH_REQUEST_ISSUE_PASSWORD, saved_errno);
    *out_view = next;
    errno = saved_errno;
    return VIREO_OK;
}
