/* PROJECT: VIREO; FILE: auth_response.c; AUTHOR: bitofux; DATE: 2026-10-20. */
#include <vireo/protocol/auth_response.h>
#include <vireo/protocol/codec.h>
#include <vireo/protocol/tlv.h>
#include <vireo/base/secure_clear.h>
#include <errno.h>
#include <string.h>

static bool token_zero(unsigned char const token[32])
{ unsigned char bits = 0; for (size_t i = 0; i < 32; ++i) bits |= token[i]; return bits == 0; }
static bool valid(vireo_auth_response_t const *v)
{
    if ((v->command != VIREO_COMMAND_REGISTER && v->command != VIREO_COMMAND_LOGIN &&
         v->command != VIREO_COMMAND_SESSION_RESUME && v->command != VIREO_COMMAND_LOGOUT) ||
        v->sequence == 0 || !vireo_status_is_known(v->status)) return false;
    if (v->status != VIREO_STATUS_OK || v->command == VIREO_COMMAND_LOGOUT) return v->session_handle == 0 && v->user_id == 0 &&
        v->root_node_id == 0 && v->issued_at_ms == 0 && v->expires_at_ms == 0 && token_zero(v->token);
    if (v->user_id == 0) return false;
    if (v->command == VIREO_COMMAND_REGISTER) return v->session_handle == 0 && v->root_node_id != 0 &&
        v->issued_at_ms == 0 && v->expires_at_ms == 0 && token_zero(v->token);
    return v->session_handle != 0 && v->root_node_id == 0 && v->expires_at_ms > v->issued_at_ms &&
        (v->command == VIREO_COMMAND_LOGIN || token_zero(v->token));
}
static uint64_t get64(unsigned char const *p)
{ uint64_t v = 0; for (size_t i = 0; i < 8; ++i) v = (v << 8) | p[i]; return v; }

vireo_result_t vireo_auth_response_encode(vireo_auth_response_t const *v,
    unsigned char *wire, size_t capacity, size_t *out_size)
{
    int const saved_errno = errno; unsigned char local[104] = {0};
    vireo_result_t rc = VIREO_RESULT_INVALID_ARGUMENT;
    if (v == NULL || wire == NULL || out_size == NULL || !valid(v)) goto done;
    size_t const n = v->status != VIREO_STATUS_OK || v->command == VIREO_COMMAND_LOGOUT ? 32 :
        v->command == VIREO_COMMAND_REGISTER ? 56 : v->command == VIREO_COMMAND_SESSION_RESUME ? 68 : 104;
    rc = VIREO_RESULT_RANGE; if (capacity < n) goto done;
    vireo_tlv_writer_t w;
    rc = vireo_tlv_writer_init(&w, local + 32, 72); if (rc != VIREO_OK) goto done;
    if (v->status == VIREO_STATUS_OK && v->command != VIREO_COMMAND_LOGOUT) {
        rc = vireo_tlv_writer_put_u64(&w, VIREO_AUTH_RESPONSE_USER_ID, v->user_id); if (rc != VIREO_OK) goto done;
        if (v->command == VIREO_COMMAND_REGISTER) {
            rc = vireo_tlv_writer_put_u64(&w, VIREO_AUTH_RESPONSE_ROOT_NODE_ID, v->root_node_id); if (rc != VIREO_OK) goto done;
        } else {
            if (v->command == VIREO_COMMAND_LOGIN) {
                rc = vireo_tlv_writer_put(&w, VIREO_AUTH_RESPONSE_TOKEN, v->token, sizeof(v->token)); if (rc != VIREO_OK) goto done;
            }
            rc = vireo_tlv_writer_put_u64(&w, VIREO_AUTH_RESPONSE_ISSUED_AT_MS, v->issued_at_ms); if (rc != VIREO_OK) goto done;
            rc = vireo_tlv_writer_put_u64(&w, VIREO_AUTH_RESPONSE_EXPIRES_AT_MS, v->expires_at_ms); if (rc != VIREO_OK) goto done;
        }
    }
    vireo_protocol_header_t h = {.command = v->command, .sequence = v->sequence,
        .status = v->status, .flags = VIREO_PROTOCOL_FLAG_RESPONSE,
        .session_handle = v->session_handle, .body_len = (uint32_t)w.used};
    vireo_protocol_codec_issue_t issue;
    rc = vireo_protocol_response_header_validate(&h, &issue); if (rc != VIREO_OK) goto done;
    rc = vireo_protocol_header_encode(&h, local, 32); if (rc != VIREO_OK) goto done;
    rc = vireo_protocol_frame_crc32c_calculate(local, 32, local + 32, w.used, &h.crc32c); if (rc != VIREO_OK) goto done;
    rc = vireo_protocol_header_encode(&h, local, 32); if (rc != VIREO_OK) goto done;
    memcpy(wire, local, n); *out_size = n;
done:
    (void)vireo_secure_clear(local, sizeof(local)); errno = saved_errno; return rc;
}

vireo_result_t vireo_auth_response_decode(unsigned char const *wire, size_t size, vireo_auth_response_t *out)
{
    int const saved_errno = errno; vireo_auth_response_t v = {0};
    vireo_result_t rc = VIREO_RESULT_INVALID_ARGUMENT;
    if (wire == NULL || out == NULL) goto done;
    rc = VIREO_RESULT_PROTOCOL;
    if (size < 32 || size > 104) goto done;
    vireo_protocol_header_t h; vireo_protocol_codec_issue_t issue;
    if (vireo_protocol_header_decode(wire, size, &h, &issue) != VIREO_OK ||
        vireo_protocol_response_header_validate(&h, &issue) != VIREO_OK ||
        h.flags != VIREO_PROTOCOL_FLAG_RESPONSE || h.task_handle != 0 || h.body_len != size - 32 ||
        (h.command != VIREO_COMMAND_REGISTER && h.command != VIREO_COMMAND_LOGIN &&
         h.command != VIREO_COMMAND_LOGOUT && h.command != VIREO_COMMAND_SESSION_RESUME) ||
        vireo_protocol_frame_crc32c_verify(wire, 32, wire + 32, h.body_len, &issue) != VIREO_OK) goto done;
    v.command = h.command; v.status = h.status; v.sequence = h.sequence; v.session_handle = h.session_handle;
    if (h.status != VIREO_STATUS_OK || h.command == VIREO_COMMAND_LOGOUT) { if (h.body_len != 0) goto done; }
    else {
        vireo_tlv_reader_t reader; vireo_tlv_issue_t ti;
        if (vireo_tlv_reader_init(&reader, wire + 32, h.body_len) != VIREO_OK) goto done;
        unsigned seen = 0;
        while (reader.offset < reader.size) {
            vireo_tlv_view_t f;
            if (vireo_tlv_reader_next(&reader, &f, &ti) != VIREO_OK || f.type == 0 || f.type > 5) goto done;
            unsigned const bit = 1U << f.type;
            if ((seen & bit) != 0) goto done;
            seen |= bit;
            if (f.type == VIREO_AUTH_RESPONSE_TOKEN) {
                if (f.length != 32) goto done;
                memcpy(v.token, f.value, 32);
            } else {
                if (f.length != 8) goto done;
                uint64_t const number = get64(f.value);
                if (f.type == VIREO_AUTH_RESPONSE_USER_ID) v.user_id = number;
                else if (f.type == VIREO_AUTH_RESPONSE_ROOT_NODE_ID) v.root_node_id = number;
                else if (f.type == VIREO_AUTH_RESPONSE_ISSUED_AT_MS) v.issued_at_ms = number;
                else v.expires_at_ms = number;
            }
        }
        if (seen != (h.command == VIREO_COMMAND_REGISTER ? 6U : h.command == VIREO_COMMAND_LOGIN ? 58U : 50U)) goto done;
    }
    if (!valid(&v)) goto done;
    *out = v; rc = VIREO_OK;
done:
    (void)vireo_auth_response_clear(&v); errno = saved_errno; return rc;
}
vireo_result_t vireo_auth_response_clear(vireo_auth_response_t *v)
{ return v == NULL ? VIREO_RESULT_INVALID_ARGUMENT : vireo_secure_clear(v, sizeof(*v)); }
