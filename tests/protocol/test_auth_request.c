#include <vireo/protocol/auth_request.h>
#include <vireo/protocol/codec.h>
#include <vireo/protocol/tlv.h>
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static unsigned checks;
#define CHECK(expr) do { ++checks; assert(expr); } while (0)

static void seal(uint8_t *wire, size_t n, vireo_command_t command) {
    assert(n >= 32 && n <= 512);
    vireo_protocol_header_t h = {0};
    h.command = command;
    h.sequence = 1;
    h.body_len = (uint32_t)(n - 32);
    assert(vireo_protocol_header_encode(&h, wire, 32) == VIREO_OK);
    assert(vireo_protocol_frame_crc32c_calculate(wire, 32, wire + 32, n - 32,
                                                &h.crc32c) == VIREO_OK);
    assert(vireo_protocol_header_encode(&h, wire, 32) == VIREO_OK);
}

static void reseal(uint8_t *wire, size_t n) {
    uint32_t crc = 0;
    assert(vireo_protocol_frame_crc32c_calculate(wire, 32, wire + 32, n - 32, &crc) == VIREO_OK);
    wire[28] = (uint8_t)(crc >> 24U); wire[29] = (uint8_t)(crc >> 16U);
    wire[30] = (uint8_t)(crc >> 8U); wire[31] = (uint8_t)crc;
}

static size_t frame(uint8_t *wire, bool login, uint8_t const *u, size_t un,
                    uint8_t const *p, size_t pn, size_t dn, bool reverse) {
    uint8_t device[32] = {0};
    vireo_tlv_writer_t w;
    assert(vireo_tlv_writer_init(&w, wire + 32, 480) == VIREO_OK);
    if (reverse && login)
        assert(vireo_tlv_writer_put(&w, 3, device, dn) == VIREO_OK);
    if (reverse)
        assert(vireo_tlv_writer_put(&w, 2, p, pn) == VIREO_OK);
    assert(vireo_tlv_writer_put(&w, 1, u, un) == VIREO_OK);
    if (!reverse)
        assert(vireo_tlv_writer_put(&w, 2, p, pn) == VIREO_OK);
    if (!reverse && login)
        assert(vireo_tlv_writer_put(&w, 3, device, dn) == VIREO_OK);
    seal(wire, 32 + w.used, login ? VIREO_COMMAND_LOGIN : VIREO_COMMAND_REGISTER);
    return 32 + w.used;
}

static void expect(uint8_t const *wire, size_t n, vireo_result_t result,
                   vireo_auth_request_issue_t issue) {
    vireo_auth_request_view_t view;
    unsigned char before[sizeof(view)];
    memset(&view, 0xa5, sizeof(view));
    memcpy(before, &view, sizeof(view));
    vireo_auth_request_issue_t found = VIREO_AUTH_REQUEST_ISSUE_PASSWORD;
    errno = EDOM;
    CHECK(vireo_auth_request_decode(wire, n, &view, &found) == result);
    CHECK(errno == EDOM);
    CHECK(found == issue);
    if (result != VIREO_OK)
        CHECK(memcmp(before, &view, sizeof(view)) == 0);
    else {
        CHECK(view.username >= wire + 32 && view.username + view.username_size <= wire + n);
        CHECK(view.password >= wire + 32 && view.password + view.password_size <= wire + n);
        CHECK(view.sequence == 1);
        CHECK((view.command == VIREO_COMMAND_REGISTER && view.device == NULL) ||
              (view.command == VIREO_COMMAND_LOGIN && view.device >= wire + 32 &&
               view.device + 16 <= wire + n));
    }
}

/* 固定向量由独立Python struct+bitwise CRC生成；不调用被测codec生成。 */
static uint8_t const golden[] = {
    0x56, 0x49, 0x52, 0x45, 0x01, 0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x53, 0x3f, 0x51, 0xde, 0x00, 0x01, 0x00, 0x03, 0x41, 0x62, 0x5f, 0x00, 0x02, 0x00, 0x08, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68
};

static void session_commands(void) {
    uint8_t wire[512]={0}; vireo_auth_request_view_t v,old;
    vireo_auth_request_issue_t issue;
    for(unsigned length=0;length<=33;++length) {
        wire[32]=0; wire[33]=4; wire[34]=0; wire[35]=(uint8_t)length;
        memset(wire+36,0xa5,length); seal(wire,36+length,VIREO_COMMAND_SESSION_RESUME);
        memset(&old,0x5a,sizeof old); v=old; errno=EDOM;
        CHECK(vireo_auth_request_decode(wire,36+length,&v,&issue)==(length==32?VIREO_OK:VIREO_RESULT_PROTOCOL));
        CHECK(errno==EDOM);
        if(length==32) CHECK(v.token==wire+36 && !v.username && !v.password && !v.device && !v.session_handle);
        else CHECK(!memcmp(&old,&v,sizeof v));
    }
    wire[35]=32; seal(wire,68,VIREO_COMMAND_SESSION_RESUME);
    for(size_t n=0;n<68;++n) CHECK(vireo_auth_request_decode(wire,n,&v,&issue)==VIREO_RESULT_PROTOCOL);
    wire[33]=3; reseal(wire,68); CHECK(vireo_auth_request_decode(wire,68,&v,&issue)==VIREO_RESULT_PROTOCOL);
    seal(wire,32,VIREO_COMMAND_LOGOUT);
    CHECK(vireo_auth_request_decode(wire,32,&v,&issue)==VIREO_RESULT_PROTOCOL);
    wire[23]=7; reseal(wire,32);
    CHECK(vireo_auth_request_decode(wire,32,&v,&issue)==VIREO_OK);
    CHECK(v.session_handle==7 && !v.username && !v.password && !v.device && !v.token);
    seal(wire,36,VIREO_COMMAND_LOGOUT); wire[23]=7; reseal(wire,36);
    CHECK(vireo_auth_request_decode(wire,36,&v,&issue)==VIREO_RESULT_PROTOCOL);
}
int main(void) {
    session_commands();
    uint8_t wire[512] = {0}, base[512];
    uint8_t u[40], p[80];
    memset(u, 'A', sizeof(u)); memset(p, 'a', sizeof(p));
    expect(golden, sizeof(golden), VIREO_OK, VIREO_AUTH_REQUEST_ISSUE_NONE);
    vireo_auth_request_view_t out = {0};
    vireo_auth_request_issue_t issue;
    CHECK(vireo_auth_request_decode(golden, sizeof(golden), &out, &issue) == VIREO_OK);
    CHECK(out.username == golden + 36 && out.password == golden + 43);
    CHECK(memcmp(out.username, "Ab_", 3) == 0 && out.password_size == 8);
    for (unsigned login = 0; login < 2; ++login) {
        for (unsigned rev = 0; rev < 2; ++rev) {
            size_t const n = frame(wire, login != 0, u, 32, p, 64, 16, rev != 0);
            CHECK(n == (login ? 156U : 136U));
            expect(wire, n, VIREO_OK, VIREO_AUTH_REQUEST_ISSUE_NONE);
        }
        for (size_t un = 0; un <= 33; ++un) {
            size_t const n = frame(wire, login != 0, u, un, p, 8, 16, false);
            bool const ok = un >= 3 && un <= 32;
            expect(wire, n, ok ? VIREO_OK : VIREO_RESULT_PROTOCOL,
                   ok ? VIREO_AUTH_REQUEST_ISSUE_NONE : VIREO_AUTH_REQUEST_ISSUE_FIELDS);
        }
        for (size_t pn = 0; pn <= 65; ++pn) {
            size_t const n = frame(wire, login != 0, u, 3, p, pn, 16, false);
            bool const ok = pn >= 8 && pn <= 64;
            expect(wire, n, ok ? VIREO_OK : VIREO_RESULT_PROTOCOL,
                   ok ? VIREO_AUTH_REQUEST_ISSUE_NONE : VIREO_AUTH_REQUEST_ISSUE_FIELDS);
        }
        for (unsigned byte = 0; byte < 256; ++byte) {
            p[0] = (uint8_t)byte;
            size_t n = frame(wire, login != 0, u, 3, p, 8, 16, false);
            bool ok = byte >= 0x21 && byte <= 0x7e;
            expect(wire, n, ok ? VIREO_OK : VIREO_RESULT_PROTOCOL,
                   ok ? VIREO_AUTH_REQUEST_ISSUE_NONE : VIREO_AUTH_REQUEST_ISSUE_PASSWORD);
            p[0] = 'a'; u[0] = (uint8_t)byte;
            n = frame(wire, login != 0, u, 3, p, 8, 16, false);
            ok = (byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') ||
                 (byte >= '0' && byte <= '9') || byte == '_';
            expect(wire, n, ok ? VIREO_OK : VIREO_RESULT_PROTOCOL,
                   ok ? VIREO_AUTH_REQUEST_ISSUE_NONE : VIREO_AUTH_REQUEST_ISSUE_USERNAME);
            u[0] = 'A';
        }
    }
    size_t n = frame(base, true, u, 3, p, 8, 16, false);
    for (unsigned byte = 0; byte < 256; ++byte) {
        memcpy(wire, base, n); memset(wire + n - 16, (int)byte, 16); reseal(wire, n);
        expect(wire, n, VIREO_OK, VIREO_AUTH_REQUEST_ISSUE_NONE);
    }
    for (size_t dn = 0; dn <= 17; ++dn) {
        size_t const len = frame(wire, true, u, 3, p, 8, dn, false);
        expect(wire, len, dn == 16 ? VIREO_OK : VIREO_RESULT_PROTOCOL,
               dn == 16 ? VIREO_AUTH_REQUEST_ISSUE_NONE : VIREO_AUTH_REQUEST_ISSUE_FIELDS);
    }
    /* 逐个截断，在完整header之后更新body_len和CRC以真正测试TLV截断。 */
    for (size_t k = 0; k < n; ++k) {
        memcpy(wire, base, n);
        expect(wire, k, VIREO_RESULT_PROTOCOL, k < 32 ? VIREO_AUTH_REQUEST_ISSUE_HEADER :
               VIREO_AUTH_REQUEST_ISSUE_ENVELOPE);
        if (k >= 32) {
            seal(wire, k, VIREO_COMMAND_LOGIN);
            expect(wire, k, VIREO_RESULT_PROTOCOL, VIREO_AUTH_REQUEST_ISSUE_FIELDS);
        }
    }
    /* 各字段遗漏、复制、未知type、伪造len；均携带有效CRC。 */
    size_t const starts[] = {32, 39, 51}, lengths[] = {7, 12, 20};
    for (size_t i = 0; i < 3; ++i) {
        memcpy(wire, base, n);
        memmove(wire + starts[i], wire + starts[i] + lengths[i], n - starts[i] - lengths[i]);
        seal(wire, n - lengths[i], VIREO_COMMAND_LOGIN);
        expect(wire, n - lengths[i], VIREO_RESULT_PROTOCOL, VIREO_AUTH_REQUEST_ISSUE_FIELDS);
        memcpy(wire, base, n); memcpy(wire + n, base + starts[i], lengths[i]);
        seal(wire, n + lengths[i], VIREO_COMMAND_LOGIN);
        expect(wire, n + lengths[i], VIREO_RESULT_PROTOCOL, VIREO_AUTH_REQUEST_ISSUE_FIELDS);
        memcpy(wire, base, n); wire[starts[i]] = 0xee; reseal(wire, n);
        expect(wire, n, VIREO_RESULT_PROTOCOL, VIREO_AUTH_REQUEST_ISSUE_FIELDS);
        memcpy(wire, base, n); wire[starts[i] + 2] = 0xff; reseal(wire, n);
        expect(wire, n, VIREO_RESULT_PROTOCOL, VIREO_AUTH_REQUEST_ISSUE_FIELDS);
    }
    memcpy(wire, base, n); wire[n] = 0; expect(wire, n + 1, VIREO_RESULT_PROTOCOL, VIREO_AUTH_REQUEST_ISSUE_ENVELOPE);
    seal(wire, n, VIREO_COMMAND_REGISTER); /* REGISTER禁止携带DEVICE。 */
    expect(wire, n, VIREO_RESULT_PROTOCOL, VIREO_AUTH_REQUEST_ISSUE_FIELDS);
    seal(wire, n, VIREO_COMMAND_PING);
    expect(wire, n, VIREO_RESULT_PROTOCOL, VIREO_AUTH_REQUEST_ISSUE_ENVELOPE);
    for (unsigned bit = 0; bit < 16; ++bit) {
        memcpy(wire, base, n); uint16_t const flag = (uint16_t)(UINT16_C(1) << bit);
        wire[8] = (uint8_t)(flag >> 8U); wire[9] = (uint8_t)flag; reseal(wire, n);
        CHECK(vireo_auth_request_decode(wire, n, &out, &issue) == VIREO_RESULT_PROTOCOL);
        CHECK(issue == VIREO_AUTH_REQUEST_ISSUE_HEADER || issue == VIREO_AUTH_REQUEST_ISSUE_ENVELOPE);
    }
    for (size_t offset = 20; offset < 28; ++offset) {
        memcpy(wire, base, n); wire[offset] = 1; reseal(wire, n);
        expect(wire, n, VIREO_RESULT_PROTOCOL, VIREO_AUTH_REQUEST_ISSUE_ENVELOPE);
    }
    size_t const bad_header[] = {0, 4, 5, 10};
    for (size_t i = 0; i < sizeof(bad_header)/sizeof(bad_header[0]); ++i) {
        memcpy(wire, base, n); wire[bad_header[i]] ^= 0x80; reseal(wire, n);
        expect(wire, n, VIREO_RESULT_PROTOCOL, VIREO_AUTH_REQUEST_ISSUE_HEADER);
    }
    memcpy(wire, base, n); memset(wire + 16, 0, 4); reseal(wire, n);
    expect(wire, n, VIREO_RESULT_PROTOCOL, VIREO_AUTH_REQUEST_ISSUE_HEADER);
    memcpy(wire, base, n); wire[n - 1] ^= 1;
    expect(wire, n, VIREO_RESULT_PROTOCOL, VIREO_AUTH_REQUEST_ISSUE_CRC);
    memcpy(wire, base, n); wire[28] ^= 1;
    expect(wire, n, VIREO_RESULT_PROTOCOL, VIREO_AUTH_REQUEST_ISSUE_CRC);
    memset(wire, 0, sizeof(wire)); seal(wire, 157, VIREO_COMMAND_LOGIN);
    expect(wire, 157, VIREO_RESULT_PROTOCOL, VIREO_AUTH_REQUEST_ISSUE_ENVELOPE);
    seal(wire, 137, VIREO_COMMAND_REGISTER);
    expect(wire, 137, VIREO_RESULT_PROTOCOL, VIREO_AUTH_REQUEST_ISSUE_ENVELOPE);
    expect(NULL, 0, VIREO_RESULT_INVALID_ARGUMENT, VIREO_AUTH_REQUEST_ISSUE_NONE);
    issue = VIREO_AUTH_REQUEST_ISSUE_PASSWORD; errno = EDOM;
    CHECK(vireo_auth_request_decode(base, n, NULL, &issue) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(issue == VIREO_AUTH_REQUEST_ISSUE_NONE && errno == EDOM);
    unsigned char saved[sizeof(out)]; memset(&out, 0xa5, sizeof(out)); memcpy(saved, &out, sizeof(out));
    CHECK(vireo_auth_request_decode(base, n, &out, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(memcmp(saved, &out, sizeof(out)) == 0 && errno == EDOM);
    printf("auth_request: %u executed checks\n", checks);
    return 0;
}
