/* 公共接口集成：协议和service政策一致，task自有字节不依赖原帧。 */
#include <vireo/protocol/auth_request.h>
#include <vireo/protocol/codec.h>
#include <vireo/protocol/tlv.h>
#include <vireo/service/auth_password.h>
#include <vireo/service/auth_username.h>
#include <vireo/thread/task.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>

_Static_assert(VIREO_AUTH_REQUEST_USERNAME_MIN == VIREO_AUTH_USERNAME_MIN_LENGTH, "username min drift");
_Static_assert(VIREO_AUTH_REQUEST_USERNAME_MAX == VIREO_AUTH_USERNAME_MAX_LENGTH, "username max drift");
_Static_assert(VIREO_AUTH_REQUEST_PASSWORD_MIN == VIREO_AUTH_PASSWORD_MIN_BYTES, "password min drift");
_Static_assert(VIREO_AUTH_REQUEST_PASSWORD_MAX == VIREO_AUTH_PASSWORD_MAX_BYTES, "password max drift");

static size_t make(uint8_t *wire, unsigned byte, bool password, bool login) {
    uint8_t u[3] = {'A','b','_'}, p[8]; memset(p, 'a', sizeof(p));
    if (password) p[0] = (uint8_t)byte; else u[0] = (uint8_t)byte;
    uint8_t device[16] = {0}; vireo_tlv_writer_t w;
    assert(vireo_tlv_writer_init(&w, wire + 32, 124) == VIREO_OK);
    assert(vireo_tlv_writer_put(&w, 1, u, sizeof(u)) == VIREO_OK);
    assert(vireo_tlv_writer_put(&w, 2, p, sizeof(p)) == VIREO_OK);
    if (login) assert(vireo_tlv_writer_put(&w, 3, device, sizeof(device)) == VIREO_OK);
    vireo_protocol_header_t h = {0}; h.command = login ? VIREO_COMMAND_LOGIN : VIREO_COMMAND_REGISTER;
    h.sequence = 7; h.body_len = (uint32_t)w.used;
    assert(vireo_protocol_header_encode(&h, wire, 32) == VIREO_OK);
    assert(vireo_protocol_frame_crc32c_calculate(wire, 32, wire + 32, w.used, &h.crc32c) == VIREO_OK);
    assert(vireo_protocol_header_encode(&h, wire, 32) == VIREO_OK);
    return 32 + w.used;
}

int main(void) {
    uint8_t wire[156]; vireo_auth_request_view_t v; vireo_auth_request_issue_t issue;
    unsigned policies = 0;
    for (unsigned login = 0; login < 2; ++login)
        for (unsigned field = 0; field < 2; ++field)
            for (unsigned byte = 0; byte < 256; ++byte) {
                size_t const n = make(wire, byte, field != 0, login != 0);
                vireo_result_t const parsed = vireo_auth_request_decode(wire, n, &v, &issue);
                vireo_auth_username_t name;
                vireo_result_t const service = field ? vireo_auth_password_validate(wire + 43, 8) :
                    vireo_auth_username_prepare((char const *)wire + 36, 3, &name);
                assert((parsed == VIREO_OK) == (service == VIREO_OK)); ++policies;
            }
    size_t const n = make(wire, 'a', true, true);
    vireo_task_route_t route; vireo_task_metadata_t meta; vireo_task_t *task = NULL;
    assert(vireo_task_route_make(1, 0, 1, 7, &route) == VIREO_OK);
    assert(vireo_task_metadata_make(route, 1, VIREO_COMMAND_LOGIN, 100, &meta) == VIREO_OK);
    assert(vireo_task_create_copy(meta, wire, n, 4096, &task) == VIREO_OK);
    memset(wire, 0, sizeof(wire)); /* 原frame已失效，worker只重解自有task。 */
    vireo_task_payload_view_t payload;
    assert(vireo_task_borrow_payload(task, &payload) == VIREO_OK);
    assert(payload.data != wire && payload.size == n);
    assert(vireo_auth_request_decode(payload.data, payload.size, &v, &issue) == VIREO_OK);
    assert(v.username == payload.data + 36 && v.password == payload.data + 43);
    vireo_auth_username_t name;
    assert(vireo_auth_username_prepare((char const *)v.username, v.username_size, &name) == VIREO_OK);
    assert(memcmp(name.username, "Ab_", 3) == 0 && memcmp(name.key, "ab_", 3) == 0);
    assert(vireo_auth_password_validate(v.password, v.password_size) == VIREO_OK);
    assert(vireo_task_destroy(&task) == VIREO_OK && task == NULL);
    printf("auth_request_input: %u policy comparisons; owning-task borrowed lifetime passed\n", policies);
    return 0;
}
