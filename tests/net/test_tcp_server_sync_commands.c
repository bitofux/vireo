/*
- PROJECT : VIREO
- FILE    : test_tcp_server_sync_commands.c
- AUTHOR  : bitofux
- DATE    : 2026-10-07
- BRIEF   : 此模块负责：
- -- 诊断wire黄金值、固定缓存边界与原handler合同
- -- 公开TCP闭环、业务拒绝与真实部分进度
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <vireo/net/sync_commands.h>
#include <vireo/protocol/codec.h>
#include <vireo/protocol/tlv.h>

static unsigned failures, groups;
#define CHECK(c)                                                    \
    do {                                                            \
        if (!(c)) {                                                 \
            fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #c); \
            ++failures;                                             \
        }                                                           \
    } while (0)
#define REQUIRE(c)                                                          \
    do {                                                                    \
        if (!(c)) {                                                         \
            fprintf(stderr, "fixture %s:%d: %s\n", __FILE__, __LINE__, #c); \
            exit(EXIT_FAILURE);                                             \
        }                                                                   \
    } while (0)

static unsigned fd_count(void) {
    DIR *d = opendir("/proc/self/fd");
    REQUIRE(d != NULL);
    unsigned count = 0;
    struct dirent *entry;
    while ((entry = readdir(d)) != NULL)
        if (entry->d_name[0] != '.')
            ++count;
    REQUIRE(closedir(d) == 0);
    return count;
}
static vireo_tcp_server_sync_context_t cache(void) {
    vireo_tcp_server_sync_context_t c;
    uint8_t const version[] = "0.1.0";
    errno = EDOM;
    REQUIRE(vireo_tcp_server_sync_context_init(version, sizeof(version) - 1, &c) == VIREO_OK);
    CHECK(errno == EDOM);
    return c;
}
/* 先真实编码/CRC，再获取host header；负用例另改变基础语义以检查防御出口。 */
static size_t wire(uint8_t *out, vireo_protocol_header_t h, uint8_t const *body, size_t size) {
    REQUIRE(size <= 64);
    h.body_len = (uint32_t)size;
    REQUIRE(vireo_protocol_header_encode(&h, out, 32) == VIREO_OK);
    REQUIRE(vireo_protocol_frame_crc32c_calculate(out, 32, body, size, &h.crc32c) == VIREO_OK);
    REQUIRE(vireo_protocol_header_encode(&h, out, 32) == VIREO_OK);
    if (size)
        memcpy(out + 32, body, size);
    return 32 + size;
}
static vireo_connection_frame_view_t frame(vireo_protocol_header_t h, uint8_t const *body,
                                           size_t size) {
    uint8_t encoded[96];
    size_t n = wire(encoded, h, body, size);
    vireo_protocol_codec_issue_t issue;
    REQUIRE(vireo_protocol_header_decode(encoded, 32, &h, &issue) == VIREO_OK);
    REQUIRE(vireo_protocol_frame_crc32c_verify(encoded, 32, body, size, &issue) == VIREO_OK);
    return (vireo_connection_frame_view_t){h, body, size, n};
}
static vireo_result_t call(vireo_connection_frame_view_t const *r, uint8_t *body, size_t cap,
                           vireo_tcp_server_reply_t *reply, vireo_tcp_server_sync_context_t *c) {
    errno = EDOM;
    vireo_result_t result = vireo_tcp_server_handle_sync_command(r, body, cap, reply, c);
    CHECK(errno == EDOM);
    return result;
}
static void verify_info(uint8_t const *p, size_t size, uint8_t const *version,
                        size_t version_size) {
    vireo_tlv_rule_t const rules[] = {
        {VIREO_SYNC_TLV_PROTOCOL_VERSION, 2, 2, VIREO_TLV_VALUE_U16, true, false},
        {VIREO_SYNC_TLV_SERVER_VERSION, 1, 64, VIREO_TLV_VALUE_UTF8, true, false},
        {VIREO_SYNC_TLV_SUPPORTED_COMMANDS, 4, 4, VIREO_TLV_VALUE_BYTES, true, false}};
    uint8_t seen[3];
    vireo_tlv_issue_t issue;
    CHECK(vireo_tlv_schema_validate(p, size, rules, 3, VIREO_TLV_UNKNOWN_REJECT, seen, 3, &issue) ==
          VIREO_OK);
    vireo_tlv_reader_t reader;
    vireo_tlv_view_t v;
    uint16_t protocol;
    REQUIRE(vireo_tlv_reader_init(&reader, p, size) == VIREO_OK);
    REQUIRE(vireo_tlv_reader_next(&reader, &v, &issue) == VIREO_OK);
    CHECK(v.type == UINT16_C(0xF001) && vireo_tlv_view_read_u16(&v, &protocol) == VIREO_OK &&
          protocol == 1);
    REQUIRE(vireo_tlv_reader_next(&reader, &v, &issue) == VIREO_OK);
    CHECK(v.type == UINT16_C(0xF002) && v.length == version_size &&
          memcmp(v.value, version, version_size) == 0);
    REQUIRE(vireo_tlv_reader_next(&reader, &v, &issue) == VIREO_OK);
    REQUIRE(v.type == UINT16_C(0xF003) && v.length == 4);
    vireo_tlv_view_t const first = {v.type, v.value, 2};
    vireo_tlv_view_t const second = {v.type, v.value + 2, 2};
    uint16_t ping, info;
    CHECK(vireo_tlv_view_read_u16(&first, &ping) == VIREO_OK && ping == VIREO_COMMAND_PING);
    CHECK(vireo_tlv_view_read_u16(&second, &info) == VIREO_OK && info == VIREO_COMMAND_SERVER_INFO);
    CHECK(vireo_tlv_reader_next(&reader, &v, &issue) == VIREO_RESULT_NOT_FOUND &&
          reader.offset == size);
}
static void cache_golden_and_bounds(void) {
    ++groups;
    vireo_tcp_server_sync_context_t c = cache();
    uint8_t const golden[] = {0xf0, 1,   0,   2,    0, 1, 0xf0, 2, 0, 5, '0', '.',
                              '1',  '.', '0', 0xf0, 3, 0, 4,    0, 1, 0, 2};
    CHECK(c.server_info_body_size == sizeof(golden) &&
          memcmp(c.server_info_body, golden, sizeof(golden)) == 0);
    verify_info(c.server_info_body, c.server_info_body_size, (uint8_t const *)"0.1.0", 5);
    for (size_t n = 1; n <= 64; n += 63) {
        uint8_t version[64];
        memset(version, 'A', sizeof(version));
        version[n - 1] = '~';
        errno = EDOM;
        REQUIRE(vireo_tcp_server_sync_context_init(version, n, &c) == VIREO_OK);
        CHECK(errno == EDOM && c.server_info_body_size == 18 + n);
        verify_info(c.server_info_body, c.server_info_body_size, version, n);
        version[0] = '!'; /* 输入版本不再被借用，改变它不影响cache。 */
        CHECK(c.server_info_body[10] == (n == 1 ? '~' : 'A'));
    }
}
static void init_rejections(void) {
    ++groups;
    vireo_tcp_server_sync_context_t c = cache();
    unsigned char old[sizeof(c)];
    memcpy(old, &c, sizeof(c));
    uint8_t version[65];
    memset(version, 'A', sizeof(version));
    for (unsigned k = 0; k < 7; ++k) {
        uint8_t const invalid[] = {0, 0x20, 0x7f, 0x80};
        if (k >= 3)
            version[0] = invalid[k - 3];
        errno = EDOM;
        vireo_result_t r = vireo_tcp_server_sync_context_init(k == 0 ? NULL : version,
                                                              k == 1   ? 0
                                                              : k == 2 ? 65
                                                                       : 1,
                                                              &c);
        CHECK(r == (k == 2 ? VIREO_RESULT_RANGE : VIREO_RESULT_INVALID_ARGUMENT) && errno == EDOM &&
              memcmp(old, &c, sizeof(c)) == 0);
    }
    CHECK(vireo_tcp_server_sync_context_init(version, 1, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
}
static void normal_handler(bool info) {
    ++groups;
    vireo_tcp_server_sync_context_t c = cache();
    vireo_tcp_server_sync_context_t const old = c;
    vireo_connection_frame_view_t r = frame(
        (vireo_protocol_header_t){.command = info ? VIREO_COMMAND_SERVER_INFO : VIREO_COMMAND_PING,
                                  .sequence = 11},
        NULL, 0);
    uint8_t output[82];
    memset(output, 0xa5, sizeof(output));
    vireo_tcp_server_reply_t reply = {VIREO_STATUS_UNAUTHORIZED, 99, 7, 8};
    REQUIRE(call(&r, info ? output : NULL, info ? c.server_info_body_size : 0, &reply, &c) ==
            VIREO_OK);
    CHECK(reply.status == VIREO_STATUS_OK && reply.body_size == (info ? 23u : 0u) &&
          reply.session_handle == 0 && reply.task_handle == 0);
    if (info) {
        CHECK(memcmp(output, c.server_info_body, 23) == 0);
        verify_info(output, 23, (uint8_t const *)"0.1.0", 5);
    }
    for (size_t k = reply.body_size; k < sizeof(output); ++k)
        CHECK(output[k] == 0xa5);
    CHECK(c.server_info_body_size == old.server_info_body_size &&
          memcmp(c.server_info_body, old.server_info_body, 82) == 0);
}
static void business_rejections(vireo_command_t command) {
    ++groups;
    vireo_tcp_server_sync_context_t c = cache();
    uint8_t const byte = 0x42;
    uint8_t output[82];
    for (unsigned k = 0; k < 5; ++k) {
        vireo_protocol_header_t h = {.command = command,
                                     .sequence = 15,
                                     .flags = k == 0 ? VIREO_PROTOCOL_FLAG_NEED_ACK : 0,
                                     .session_handle = k <= 1 ? 1 : 0,
                                     .task_handle = k <= 2 ? 1 : 0};
        vireo_connection_frame_view_t r = frame(h, k <= 3 ? &byte : NULL, k <= 3 ? 1 : 0);
        memset(output, 0xa5, sizeof(output));
        vireo_tcp_server_reply_t reply = {VIREO_STATUS_OK, 99, 7, 8};
        REQUIRE(call(&r, output, sizeof(output), &reply, &c) == VIREO_OK);
        CHECK(reply.status == (k == 0   ? VIREO_STATUS_INVALID_FLAGS
                               : k == 4 ? VIREO_STATUS_OK
                                        : VIREO_STATUS_BAD_REQUEST) &&
              reply.session_handle == 0 && reply.task_handle == 0);
        if (k != 4) {
            CHECK(reply.body_size == 0);
            for (size_t j = 0; j < sizeof(output); ++j)
                CHECK(output[j] == 0xa5);
        }
    }
}
static void local_rejections(void) {
    ++groups;
    vireo_tcp_server_sync_context_t c = cache();
    vireo_connection_frame_view_t r = frame(
        (vireo_protocol_header_t){.command = VIREO_COMMAND_SERVER_INFO, .sequence = 18}, NULL, 0);
    uint8_t output[82];
    memset(output, 0xa5, sizeof(output));
    vireo_tcp_server_reply_t const old = {VIREO_STATUS_UNAUTHORIZED, 99, 7, 8};
    for (unsigned k = 0; k < 8; ++k) {
        vireo_tcp_server_reply_t reply = old;
        vireo_connection_frame_view_t request = r;
        vireo_tcp_server_sync_context_t context = c;
        if (k == 4)
            context.server_info_body_size = 0;
        if (k == 5)
            ++request.wire_size;
        if (k == 6)
            request.header.command = UINT16_C(0x7777);
        if (k == 7)
            request.header.sequence = 0;
        vireo_result_t got = call(k == 0 ? NULL : &request, k == 1 ? NULL : output,
                                  k == 2 ? 22 : sizeof(output), k == 3 ? NULL : &reply, &context);
        CHECK(got == (k == 2   ? VIREO_RESULT_RANGE
                      : k >= 6 ? VIREO_RESULT_PROTOCOL
                               : VIREO_RESULT_INVALID_ARGUMENT));
        CHECK(reply.status == old.status && reply.body_size == old.body_size &&
              reply.session_handle == old.session_handle && reply.task_handle == old.task_handle);
        for (size_t j = 0; j < sizeof(output); ++j)
            CHECK(output[j] == 0xa5);
    }
    vireo_tcp_server_reply_t reply = old;
    CHECK(call(&r, output, sizeof(output), &reply, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
}
static void known_unsupported(void) {
    ++groups;
    vireo_tcp_server_sync_context_t c = cache();
    uint8_t const value = 0x42;
    vireo_connection_frame_view_t r = frame(
        (vireo_protocol_header_t){
            .command = VIREO_COMMAND_LOGIN, .sequence = 19, .session_handle = 42},
        &value, 1);
    vireo_tcp_server_reply_t reply;
    REQUIRE(call(&r, NULL, 0, &reply, &c) == VIREO_OK);
    CHECK(reply.status == VIREO_STATUS_UNSUPPORTED && reply.body_size == 0 &&
          reply.session_handle == 0 && reply.task_handle == 0);
}

typedef struct fixture {
    vireo_tcp_server_t *server;
    vireo_connection_pool_lease_t lease;
    int peer;
} fixture_t;
static void start(fixture_t *f) {
    *f = (fixture_t){0};
    vireo_tcp_server_options_t const options = {2, 4, 1048576, 8192};
    REQUIRE(vireo_tcp_server_create(&options, &f->server, NULL) == VIREO_OK);
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    REQUIRE(fd >= 0);
    struct sockaddr_in address = {.sin_family = AF_INET,
                                  .sin_addr = {.s_addr = htonl(INADDR_LOOPBACK)}};
    REQUIRE(bind(fd, (struct sockaddr *)&address, (socklen_t)sizeof(address)) == 0 &&
            listen(fd, 8) == 0);
    socklen_t length = (socklen_t)sizeof(address);
    REQUIRE(getsockname(fd, (struct sockaddr *)&address, &length) == 0);
    vireo_acceptor_t *acceptor = NULL;
    vireo_acceptor_options_t const ao = {4096};
    REQUIRE(vireo_acceptor_create(&ao, &fd, &acceptor, NULL) == VIREO_OK && fd == -1);
    REQUIRE(vireo_tcp_server_adopt_listener(f->server, &acceptor, NULL) == VIREO_OK &&
            acceptor == NULL);
    REQUIRE(vireo_tcp_server_bind_listener(f->server, true, NULL) == VIREO_OK);
    f->peer = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    REQUIRE(f->peer >= 0);
    struct timeval timeout = {2, 0};
    REQUIRE(setsockopt(f->peer, SOL_SOCKET, SO_RCVTIMEO, &timeout, (socklen_t)sizeof(timeout)) ==
            0);
    REQUIRE(connect(f->peer, (struct sockaddr *)&address, length) == 0);
    vireo_connection_options_t const co = {256, 256, 512};
    vireo_tcp_server_admit_budget_t const budget = {1, 4};
    vireo_tcp_server_admit_info_t admitted;
    REQUIRE(vireo_tcp_server_admit_batch(f->server, &co, &budget, &f->lease, 1, &admitted, NULL) ==
                VIREO_OK &&
            admitted.admitted_count == 1);
    vireo_connection_flow_options_t const flow = {96, 95, 192, 64, 192};
    REQUIRE(vireo_tcp_server_client_flow_configure(f->server, f->lease, &flow, NULL) == VIREO_OK);
}
static void end(fixture_t *f) {
    REQUIRE(vireo_tcp_server_release_client(f->server, &f->lease, NULL) == VIREO_OK);
    REQUIRE(close(f->peer) == 0);
    REQUIRE(vireo_tcp_server_destroy(&f->server, NULL) == VIREO_OK && f->server == NULL);
}
static void transmit(fixture_t *f, uint8_t const *p, size_t n) {
    size_t sent = 0;
    while (sent < n) {
        ssize_t got = send(f->peer, p + sent, n - sent, MSG_NOSIGNAL);
        REQUIRE(got > 0);
        sent += (size_t)got;
    }
}
static void read_exact(int fd, uint8_t *p, size_t n) {
    size_t have = 0;
    while (have < n) {
        ssize_t got = recv(fd, p + have, n - have, 0);
        REQUIRE(got > 0);
        have += (size_t)got;
    }
}
static void response(fixture_t *f, vireo_command_t command, uint32_t sequence,
                     vireo_status_t status, uint8_t const *version, size_t version_size) {
    uint8_t encoded[32], body[82];
    vireo_protocol_header_t h;
    vireo_protocol_codec_issue_t issue;
    read_exact(f->peer, encoded, 32);
    REQUIRE(vireo_protocol_header_decode(encoded, 32, &h, &issue) == VIREO_OK &&
            h.body_len <= sizeof(body));
    read_exact(f->peer, body, h.body_len);
    CHECK(vireo_protocol_response_header_validate(&h, &issue) == VIREO_OK && h.command == command &&
          h.sequence == sequence && h.status == status && h.flags == VIREO_PROTOCOL_FLAG_RESPONSE &&
          h.session_handle == 0 && h.task_handle == 0);
    CHECK(vireo_protocol_frame_crc32c_verify(encoded, 32, h.body_len ? body : NULL, h.body_len,
                                             &issue) == VIREO_OK);
    if (command == VIREO_COMMAND_SERVER_INFO && status == VIREO_STATUS_OK)
        verify_info(body, h.body_len, version, version_size);
    else
        CHECK(h.body_len == 0);
}
static void tcp_rounds_and_shared_cache(void) {
    ++groups;
    fixture_t f, other;
    start(&f);
    start(&other);
    vireo_tcp_server_sync_context_t c = cache();
    uint8_t bytes[96];
    wire(bytes, (vireo_protocol_header_t){.command = VIREO_COMMAND_PING, .sequence = 1}, NULL, 0);
    wire(bytes + 32, (vireo_protocol_header_t){.command = VIREO_COMMAND_SERVER_INFO, .sequence = 2},
         NULL, 0);
    wire(bytes + 64, (vireo_protocol_header_t){.command = VIREO_COMMAND_PING, .sequence = 3}, NULL,
         0);
    transmit(&f, bytes, sizeof(bytes));
    transmit(&other, bytes + 32, 32);
    vireo_tcp_server_process_options_t const options = {96, 114};
    vireo_tcp_server_drive_budget_t const budget = {{256, 8}, {1, 192, 228}, {256, 8}};
    vireo_tcp_server_round_budget_t const round = {1};
    vireo_tcp_server_round_info_t i;
    vireo_tcp_server_turn_result_t turn;
    uint8_t workspace[114];
    for (unsigned k = 0; k < 3; ++k) {
        errno = EDOM;
        REQUIRE(vireo_tcp_server_run_once(f.server, 100, &options, &budget, &round, workspace,
                                          sizeof(workspace), vireo_tcp_server_handle_sync_command,
                                          &c, &turn, 1, &i, NULL) == VIREO_OK);
        CHECK(errno == EDOM && i.turn_count == 1 && turn.info.process.handler_calls == 1);
        response(&f, k == 1 ? VIREO_COMMAND_SERVER_INFO : VIREO_COMMAND_PING, k + 1,
                 VIREO_STATUS_OK, (uint8_t const *)"0.1.0", 5);
    }
    REQUIRE(vireo_tcp_server_run_once(other.server, 100, &options, &budget, &round, workspace,
                                      sizeof(workspace), vireo_tcp_server_handle_sync_command, &c,
                                      &turn, 1, &i, NULL) == VIREO_OK &&
            i.turn_count == 1);
    response(&other, VIREO_COMMAND_SERVER_INFO, 2, VIREO_STATUS_OK, (uint8_t const *)"0.1.0", 5);
    end(&f);
    end(&other);
}
static void tcp_business_status(void) {
    ++groups;
    fixture_t f;
    start(&f);
    vireo_tcp_server_sync_context_t c = cache();
    vireo_tcp_server_process_options_t const o = {96, 114};
    vireo_tcp_server_drive_budget_t const b = {{256, 8}, {1, 192, 228}, {256, 8}};
    for (unsigned k = 0; k < 4; ++k) {
        uint8_t encoded[33];
        uint8_t const value = 0x41;
        vireo_command_t const cmd = k == 3   ? VIREO_COMMAND_LOGIN
                                    : k == 2 ? VIREO_COMMAND_SERVER_INFO
                                             : VIREO_COMMAND_PING;
        size_t n =
            wire(encoded,
                 (vireo_protocol_header_t){.command = cmd,
                                           .sequence = 20 + k,
                                           .flags = k == 0 ? VIREO_PROTOCOL_FLAG_NEED_ACK : 0,
                                           .session_handle = k == 1 ? 1 : 0},
                 k == 2 ? &value : NULL, k == 2 ? 1 : 0);
        transmit(&f, encoded, n);
        uint8_t workspace[114];
        vireo_tcp_server_drive_info_t i;
        REQUIRE(vireo_tcp_server_client_drive(
                    f.server, f.lease, &o, &b, workspace, sizeof(workspace),
                    vireo_tcp_server_handle_sync_command, &c, &i, NULL) == VIREO_OK);
        CHECK(i.process.handler_calls == 1);
        response(&f, cmd, 20 + k,
                 k == 0   ? VIREO_STATUS_INVALID_FLAGS
                 : k == 3 ? VIREO_STATUS_UNSUPPORTED
                          : VIREO_STATUS_BAD_REQUEST,
                 NULL, 0);
    }
    end(&f);
}
static void tcp_space_recovery_and_maximum(void) {
    ++groups;
    fixture_t f;
    start(&f);
    vireo_tcp_server_sync_context_t c = cache();
    uint8_t encoded[32];
    wire(encoded, (vireo_protocol_header_t){.command = VIREO_COMMAND_SERVER_INFO, .sequence = 30},
         NULL, 0);
    transmit(&f, encoded, 32);
    vireo_tcp_server_drive_budget_t const b = {{256, 8}, {2, 192, 228}, {256, 8}};
    vireo_tcp_server_process_options_t o = {96, 54};
    uint8_t workspace[114];
    memset(workspace, 0xa5, sizeof(workspace));
    vireo_tcp_server_drive_info_t i;
    vireo_tcp_server_drive_error_t e;
    errno = EDOM;
    CHECK(vireo_tcp_server_client_drive(f.server, f.lease, &o, &b, workspace, sizeof(workspace),
                                        vireo_tcp_server_handle_sync_command, &c, &i,
                                        &e) == VIREO_RESULT_RANGE &&
          errno == EDOM);
    CHECK(i.process.handler_calls == 1 && i.process.consumed_requests == 0);
    CHECK(e.primary_stage == VIREO_TCP_SERVER_DRIVE_PROCESS &&
          e.primary_error.primary.stage == VIREO_TCP_SERVER_CLIENT_HANDLER &&
          e.primary_error.primary.handler_result == VIREO_RESULT_RANGE &&
          e.sync_result == VIREO_OK);
    uint8_t const *borrow;
    size_t size;
    REQUIRE(vireo_tcp_server_client_read_peek(f.server, f.lease, &borrow, &size, NULL) ==
                VIREO_OK &&
            size == 32);
    for (size_t k = 0; k < sizeof(workspace); ++k)
        CHECK(workspace[k] == 0xa5);
    o.max_response_frame_bytes = 114;
    REQUIRE(vireo_tcp_server_client_drive(f.server, f.lease, &o, &b, workspace, sizeof(workspace),
                                          vireo_tcp_server_handle_sync_command, &c, &i,
                                          NULL) == VIREO_OK);
    response(&f, VIREO_COMMAND_SERVER_INFO, 30, VIREO_STATUS_OK, (uint8_t const *)"0.1.0", 5);
    uint8_t version[64];
    memset(version, 'V', sizeof(version));
    REQUIRE(vireo_tcp_server_sync_context_init(version, sizeof(version), &c) == VIREO_OK);
    wire(encoded, (vireo_protocol_header_t){.command = VIREO_COMMAND_SERVER_INFO, .sequence = 31},
         NULL, 0);
    transmit(&f, encoded, 32);
    REQUIRE(vireo_tcp_server_client_drive(f.server, f.lease, &o, &b, workspace, sizeof(workspace),
                                          vireo_tcp_server_handle_sync_command, &c, &i,
                                          NULL) == VIREO_OK);
    response(&f, VIREO_COMMAND_SERVER_INFO, 31, VIREO_STATUS_OK, version, 64);
    end(&f);
}
static void tcp_unknown_after_prefix(void) {
    ++groups;
    fixture_t f;
    start(&f);
    vireo_tcp_server_sync_context_t c = cache();
    uint8_t encoded[96];
    wire(encoded, (vireo_protocol_header_t){.command = VIREO_COMMAND_PING, .sequence = 40}, NULL,
         0);
    wire(encoded + 32,
         (vireo_protocol_header_t){.command = VIREO_COMMAND_SERVER_INFO, .sequence = 41}, NULL, 0);
    wire(encoded + 64, (vireo_protocol_header_t){.command = UINT16_C(0x7777), .sequence = 42}, NULL,
         0);
    transmit(&f, encoded, sizeof(encoded));
    vireo_tcp_server_process_options_t const o = {96, 55};
    vireo_tcp_server_drive_budget_t const b = {{256, 8}, {3, 288, 165}, {256, 8}};
    uint8_t workspace[55];
    vireo_tcp_server_drive_info_t i;
    vireo_tcp_server_drive_error_t e;
    CHECK(vireo_tcp_server_client_drive(f.server, f.lease, &o, &b, workspace, sizeof(workspace),
                                        vireo_tcp_server_handle_sync_command, &c, &i,
                                        &e) == VIREO_RESULT_PROTOCOL);
    CHECK(i.process.handler_calls == 2 && i.process.consumed_requests == 2);
    CHECK(e.primary_stage == VIREO_TCP_SERVER_DRIVE_PROCESS &&
          e.primary_error.primary.stage == VIREO_TCP_SERVER_CLIENT_FRAMES_PEEK &&
          e.primary_error.primary.frame_error.codec_issue ==
              VIREO_PROTOCOL_CODEC_ISSUE_UNKNOWN_COMMAND &&
          e.sync_result == VIREO_OK);
    vireo_tcp_server_client_info_t ci;
    REQUIRE(vireo_tcp_server_client_inspect(f.server, f.lease, &ci) == VIREO_OK);
    CHECK(ci.connection_info.read_buffer.readable_size == 32 &&
          ci.connection_info.write_buffer.readable_size == 87 &&
          ci.connection_info.close_state == VIREO_CONNECTION_CLOSE_OPEN);
    vireo_connection_send_info_t sent;
    REQUIRE(vireo_tcp_server_client_send(f.server, f.lease, &b.send, &sent, NULL) == VIREO_OK &&
            sent.sent_bytes == 87);
    response(&f, VIREO_COMMAND_PING, 40, VIREO_STATUS_OK, NULL, 0);
    response(&f, VIREO_COMMAND_SERVER_INFO, 41, VIREO_STATUS_OK, (uint8_t const *)"0.1.0", 5);
    end(&f);
}
int main(void) {
    unsigned const before = fd_count();
    cache_golden_and_bounds();
    init_rejections();
    normal_handler(false);
    normal_handler(true);
    business_rejections(VIREO_COMMAND_PING);
    business_rejections(VIREO_COMMAND_SERVER_INFO);
    local_rejections();
    known_unsupported();
    tcp_rounds_and_shared_cache();
    tcp_business_status();
    tcp_space_recovery_and_maximum();
    tcp_unknown_after_prefix();
    unsigned const after = fd_count();
    CHECK(before == after);
    printf("tcp_server sync commands: %u groups, %u failures, fd %u -> %u\n", groups, failures,
           before, after);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
