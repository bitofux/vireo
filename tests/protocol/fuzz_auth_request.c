/* 有界专项入口，不加入常规CTest；仅使用公开协议接口。 */
#include <vireo/protocol/auth_request.h>
#include <vireo/protocol/codec.h>
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>

int LLVMFuzzerTestOneInput(uint8_t const *data, size_t size);

static void check(uint8_t const *data, size_t size) {
    vireo_auth_request_view_t v;
    unsigned char old[sizeof(v)];
    memset(&v, 0xa5, sizeof(v)); memcpy(old, &v, sizeof(v));
    vireo_auth_request_issue_t issue = VIREO_AUTH_REQUEST_ISSUE_PASSWORD;
    errno = EDOM;
    vireo_result_t const result = vireo_auth_request_decode(data, size, &v, &issue);
    assert(errno == EDOM);
    if (result != VIREO_OK) {
        assert(result == VIREO_RESULT_PROTOCOL);
        assert(issue != VIREO_AUTH_REQUEST_ISSUE_NONE);
        assert(memcmp(old, &v, sizeof(v)) == 0);
        return;
    }
    assert(issue == VIREO_AUTH_REQUEST_ISSUE_NONE && v.sequence != 0);
    if(v.command==VIREO_COMMAND_LOGOUT || v.command==VIREO_COMMAND_SESSION_RESUME) {
        assert(!v.username && !v.password && !v.device && !v.username_size && !v.password_size);
        if(v.command==VIREO_COMMAND_LOGOUT) assert(size==32 && v.session_handle && !v.token);
        else assert(size==68 && !v.session_handle && v.token==data+36);
        return;
    }
    assert(v.username_size >= 3 && v.username_size <= 32);
    assert(v.password_size >= 8 && v.password_size <= 64);
    assert((uintptr_t)v.username >= (uintptr_t)data + 32);
    assert((uintptr_t)v.username <= (uintptr_t)data + size - v.username_size);
    assert((uintptr_t)v.password >= (uintptr_t)data + 32);
    assert((uintptr_t)v.password <= (uintptr_t)data + size - v.password_size);
    for (size_t i = 0; i < v.username_size; ++i) {
        unsigned const c = v.username[i];
        assert((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
               (c >= '0' && c <= '9') || c == '_');
    }
    for (size_t i = 0; i < v.password_size; ++i)
        assert(v.password[i] >= 0x21 && v.password[i] <= 0x7e);
    if (v.command == VIREO_COMMAND_REGISTER) assert(v.device == NULL);
    else {
        assert(v.command == VIREO_COMMAND_LOGIN);
        assert((uintptr_t)v.device >= (uintptr_t)data + 32);
        assert((uintptr_t)v.device <= (uintptr_t)data + size - 16);
    }
}

int LLVMFuzzerTestOneInput(uint8_t const *data, size_t size) {
    if (size > 512) return 0;
    check(data, size); /* 原始wire通道覆盖header/flags/handles/CRC拒绝。 */
    if (size >= 32) {
        uint8_t repaired[512];
        memcpy(repaired, data, size);
        vireo_protocol_header_t h = {0};
        h.command = (vireo_command_t)(VIREO_COMMAND_REGISTER+(data[7]&3U));
        if(h.command==VIREO_COMMAND_LOGOUT) h.session_handle=1;
        h.sequence = 1; h.body_len = (uint32_t)(size - 32);
        assert(vireo_protocol_header_encode(&h, repaired, 32) == VIREO_OK);
        assert(vireo_protocol_frame_crc32c_calculate(repaired, 32, repaired + 32, size - 32,
                                                    &h.crc32c) == VIREO_OK);
        assert(vireo_protocol_header_encode(&h, repaired, 32) == VIREO_OK);
        check(repaired, size); /* 穿透外层CRC，覆盖schema和字符检查。 */
    }
    return 0;
}
