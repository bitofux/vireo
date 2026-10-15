/*
 * PROJECT : VIREO
 * FILE    : test_completion_response_enqueue.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-14
 * BRIEF   : 单帧 wire/真实 FIFO 与水位/交付失败前缀，本层隔离故障
 */
#define _GNU_SOURCE
#include "completion_response_internal.h"
#include <vireo/net/notifier_server.h>
#include <vireo/net/notifier_server_dispatch.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #c); exit(1); } } while (0)
#define EXPECT(call, result) do { errno = EDOM; CHECK((call) == (result)); CHECK(errno == EDOM); } while (0)
_Static_assert(VIREO_COMPLETION_RESPONSE_NONE == 0 && VIREO_COMPLETION_RESPONSE_ENQUEUE == 9 &&
    VIREO_COMPLETION_RESPONSE_REFRESH == 10 && VIREO_COMPLETION_RESPONSE_MAX_FRAME_BYTES == 16777248,
    "independent stages and byte bound");

/** 本组独占公开资源，不保存 foreign private 或裸 connection。 */
typedef struct fixture {
    vireo_tcp_server_t *server; /**< 真实 server owner，显式预留辅助容量 1。 */
    vireo_connection_pool_lease_t client; /**< 当前完整客户租约数值，不保活。 */
    int peer; /**< 对端 fd owner，-1 为空。 */
    struct sockaddr_in address; /**< listener 实际 loopback 地址，供新客户复用槽位。 */
    vireo_inflight_store_t *store; /**< 容量 8 的真实登记表 owner。 */
    vireo_completion_t *completion; /**< 当前独立结果 owner，cleanup 配对清理。 */
} fixture_t;
static vireo_connection_options_t const connection_options = {256, 128, 384};
static vireo_connection_flow_options_t const flow = {128, 127, 128, 32, 96};
/* 字节向量只验基础 envelope，不冒 NODE_STAT/上传等业务 schema 已实现。 */
static vireo_completion_response_descriptor_t const descriptor = {VIREO_COMMAND_NODE_STAT, 0, 0, 0};
static vireo_tcp_server_process_options_t const process = {128, 128};
static vireo_tcp_server_drive_budget_t const drive = {{512, 8}, {2, 256, 256}, {512, 8}};
static vireo_tcp_server_round_budget_t const round_budget = {1};

static size_t fds(void) {
    DIR *dir = opendir("/proc/self/fd"); CHECK(dir != NULL); size_t n = 0;
    struct dirent *entry; while ((entry = readdir(dir)) != NULL) if (entry->d_name[0] != '.') ++n;
    CHECK(closedir(dir) == 0); return n;
}
static void add_client(fixture_t *f) {
    f->peer = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0); CHECK(f->peer >= 0);
    CHECK(connect(f->peer, (struct sockaddr *)&f->address, sizeof f->address) == 0);
    vireo_tcp_server_admit_budget_t const budget = {1, 2}; vireo_tcp_server_admit_info_t info;
    EXPECT(vireo_tcp_server_admit_batch(f->server, &connection_options, &budget,
        &f->client, 1, &info, NULL), VIREO_OK); CHECK(info.admitted_count == 1);
    EXPECT(vireo_tcp_server_client_flow_configure(f->server, f->client, &flow, NULL), VIREO_OK);
}
static void setup(fixture_t *f) {
    *f = (fixture_t){.peer = -1}; vireo_tcp_server_options_t const options = {1, 2, 1048576, 1024};
    EXPECT(vireo_tcp_server_create_with_auxiliary_capacity(&options, 1, &f->server, NULL), VIREO_OK);
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0); CHECK(fd >= 0);
    f->address = (struct sockaddr_in){.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    CHECK(bind(fd, (struct sockaddr *)&f->address, sizeof f->address) == 0 && listen(fd, 4) == 0);
    socklen_t length = sizeof f->address; CHECK(getsockname(fd, (struct sockaddr *)&f->address, &length) == 0);
    vireo_acceptor_t *listener = NULL; vireo_acceptor_options_t const listener_options = {4096};
    EXPECT(vireo_acceptor_create(&listener_options, &fd, &listener, NULL), VIREO_OK);
    EXPECT(vireo_tcp_server_adopt_listener(f->server, &listener, NULL), VIREO_OK);
    add_client(f); EXPECT(vireo_tcp_server_bind_listener(f->server, true, NULL), VIREO_OK);
    vireo_tcp_server_admission_options_t const admission = {connection_options, flow};
    EXPECT(vireo_tcp_server_admission_configure(f->server, &admission, NULL), VIREO_OK);
    vireo_inflight_store_options_t const store_options = {8, 65536};
    EXPECT(vireo_inflight_store_create(&store_options, &f->store), VIREO_OK);
}
static vireo_tcp_server_client_info_t state(fixture_t *f) {
    vireo_tcp_server_client_info_t info;
    EXPECT(vireo_tcp_server_client_inspect(f->server, f->client, &info), VIREO_OK); return info;
}
static void record_count(fixture_t *f, size_t count) {
    vireo_inflight_store_info_t info; EXPECT(vireo_inflight_store_inspect(f->store, &info), VIREO_OK);
    CHECK(info.count == count);
}
static void discard(fixture_t *f) {
    if (f->completion == NULL) return;
    vireo_completion_info_t info; EXPECT(vireo_completion_inspect(f->completion, &info), VIREO_OK);
    vireo_task_metadata_t ended;
    vireo_result_t const result = vireo_inflight_store_take(f->store, info.metadata.request, &ended, NULL);
    CHECK(result == VIREO_OK || result == VIREO_RESULT_NOT_FOUND);
    EXPECT(vireo_completion_destroy(&f->completion), VIREO_OK);
}
static void prepare(fixture_t *f, uint8_t const *body, size_t size, uint32_t sequence) {
    discard(f); vireo_task_metadata_t request;
    EXPECT(vireo_inflight_metadata_make_next(f->server, f->client, sequence, 9, UINT64_MAX, &request, NULL), VIREO_OK);
    EXPECT(vireo_inflight_store_register(f->store, f->server, request, NULL), VIREO_OK);
    vireo_completion_metadata_t metadata;
    EXPECT(vireo_completion_metadata_make(request, VIREO_RESULT_DATABASE, VIREO_STATUS_INTERNAL_ERROR, &metadata), VIREO_OK);
    EXPECT(vireo_completion_create_copy(metadata, body, size, 65536, &f->completion), VIREO_OK);
}
static vireo_inflight_completion_match_t matching(fixture_t *f) {
    vireo_inflight_completion_match_t match;
    EXPECT(vireo_inflight_store_check_completion(f->store, f->server, f->completion, &match, NULL), VIREO_OK); return match;
}
static void cleanup(fixture_t *f) {
    discard(f); EXPECT(vireo_inflight_store_destroy(&f->store), VIREO_OK);
    if (f->client.pool_id != 0) EXPECT(vireo_tcp_server_release_client(f->server, &f->client, NULL), VIREO_OK);
    if (f->peer >= 0) CHECK(close(f->peer) == 0);
    EXPECT(vireo_tcp_server_destroy(&f->server, NULL), VIREO_OK);
}
static vireo_completion_response_report_t call(fixture_t *f, vireo_inflight_completion_match_t match,
    vireo_completion_response_descriptor_t desc, size_t budget, uint8_t *work, size_t size, vireo_result_t result) {
    vireo_completion_response_report_t report; memset(&report, 0xa5, sizeof report);
    EXPECT(vireo_completion_response_enqueue(f->server, f->completion, match, desc, budget, work, size, &report), result);
    return report;
}
static void no_commit(vireo_completion_response_report_t p) {
    CHECK(!p.enqueue_called && !p.enqueued && !p.refresh_called);
}
static vireo_result_t handler(vireo_connection_frame_view_t const *q, uint8_t *bytes, size_t size,
    vireo_tcp_server_reply_t *reply, void *context) {
    (void)q; (void)bytes; (void)size; (void)reply; (void)context;
    CHECK(false); return VIREO_RESULT_INTERNAL; /* 对端未发请求，不冒完整请求入口接线。 */
}
static void serve(fixture_t *f, int timeout) {
    uint8_t work[128]; vireo_tcp_server_turn_result_t turns[1]; vireo_connection_pool_lease_t clients[1] = {0};
    vireo_tcp_server_serve_options_t const options = {timeout, process, drive, round_budget, {1, 4}};
    vireo_tcp_server_serve_info_t info;
    EXPECT(vireo_tcp_server_serve_once(f->server, &options, work, sizeof work, handler, NULL,
        turns, 1, clients, 1, &info, NULL), VIREO_OK);
}
static void read_peer(fixture_t *f, uint8_t *bytes, size_t size) {
    size_t have = 0;
    for (unsigned attempts = 0; have < size && attempts < 8; ++attempts) {
        struct pollfd p = {.fd = f->peer, .events = POLLIN}; CHECK(poll(&p, 1, 2000) == 1 && (p.revents & POLLIN));
        ssize_t const n = recv(f->peer, bytes + have, size - have, MSG_DONTWAIT); CHECK(n > 0); have += (size_t)n;
    }
    CHECK(have == size);
}
static void send_direct(fixture_t *f, size_t bytes) {
    vireo_connection_send_budget_t const budget = {bytes, 8}; vireo_connection_send_info_t info;
    EXPECT(vireo_tcp_server_client_send(f->server, f->client, &budget, &info, NULL), VIREO_OK);
    CHECK(info.sent_bytes == bytes); EXPECT(vireo_tcp_server_client_flow_refresh(f->server, f->client, NULL), VIREO_OK);
}
static void wire_is(uint8_t const *wire, size_t size, vireo_completion_response_descriptor_t desc,
    vireo_task_metadata_t request, uint8_t const *body, size_t body_size) {
    CHECK(size == 32 + body_size && memcmp(wire, "VIRE", 4) == 0 && wire[4] == 1 && wire[5] == 32);
    vireo_protocol_codec_issue_t issue;
    vireo_protocol_header_t h; EXPECT(vireo_protocol_header_decode(wire, size, &h, &issue), VIREO_OK);
    CHECK(h.command == desc.command && h.flags == (VIREO_PROTOCOL_FLAG_RESPONSE | desc.extra_flags) &&
        h.status == VIREO_STATUS_INTERNAL_ERROR && h.body_len == body_size &&
        h.sequence == request.route.request_sequence && h.session_handle == desc.session_handle && h.task_handle == desc.task_handle);
    EXPECT(vireo_protocol_response_header_validate(&h, &issue), VIREO_OK);
    EXPECT(vireo_protocol_frame_crc32c_verify(wire, 32, wire + 32, body_size, &issue), VIREO_OK);
    if (body_size != 0) CHECK(memcmp(wire + 32, body, body_size) == 0);
}
static void wire_body(void) {
    fixture_t f; setup(&f); uint8_t const body[] = {0, 255, 42}; prepare(&f, body, sizeof body, 0x12345678);
    vireo_inflight_completion_match_t const match = matching(&f); uint8_t work[128], wire[128];
    vireo_completion_payload_view_t before, after;
    EXPECT(vireo_completion_borrow_payload(f.completion, &before), VIREO_OK);
    vireo_completion_response_report_t const p = call(&f, match, descriptor, 128, work, sizeof work, VIREO_OK);
    CHECK(p.stage == 0 && p.frame_bytes == 35 && p.frame_encoded && p.enqueue_called && p.enqueued && p.refresh_called);
    CHECK(state(&f).connection_info.write_buffer.readable_size == 35 &&
        (state(&f).connection_info.loop_interests & VIREO_EPOLL_INTEREST_WRITE));
    EXPECT(vireo_completion_borrow_payload(f.completion, &after), VIREO_OK);
    CHECK(before.data == after.data && before.size == after.size && memcmp(after.data, body, 3) == 0); record_count(&f, 1);
    memset(work, 0xa5, sizeof work); serve(&f, 500); CHECK(state(&f).connection_info.write_buffer.readable_size == 0);
    read_peer(&f, wire, 35); wire_is(wire, 35, descriptor, match.metadata, body, sizeof body); cleanup(&f);
}
static void empty_body(void) {
    fixture_t f; setup(&f); prepare(&f, NULL, 0, 1); uint8_t work[32], wire[32];
    vireo_inflight_completion_match_t const match = matching(&f);
    vireo_completion_response_report_t const p = call(&f, match, descriptor, 32, work, sizeof work, VIREO_OK);
    CHECK(p.frame_bytes == 32 && p.enqueued); send_direct(&f, 32); read_peer(&f, wire, sizeof wire);
    wire_is(wire, sizeof wire, descriptor, match.metadata, NULL, 0); cleanup(&f);
}
static void descriptor_fields(void) {
    fixture_t f; setup(&f); prepare(&f, NULL, 0, UINT32_MAX); uint8_t work[128];
    vireo_completion_response_descriptor_t const desc = {VIREO_COMMAND_UPLOAD_INIT, VIREO_PROTOCOL_FLAG_LONG_COMMAND,
        UINT32_C(0x10203040), UINT32_MAX};
    vireo_inflight_completion_match_t const match = matching(&f);
    (void)call(&f, match, desc, 128, work, sizeof work, VIREO_OK);
    wire_is(work, 32, desc, match.metadata, NULL, 0); cleanup(&f);
}
static void exact_frame_cap(void) {
    fixture_t f; setup(&f); uint8_t body[96] = {0}; for (size_t k = 0; k < sizeof body; ++k) body[k] = (uint8_t)k;
    prepare(&f, body, sizeof body, 2); uint8_t work[128], wire[128]; vireo_inflight_completion_match_t const match = matching(&f);
    vireo_completion_response_report_t const p = call(&f, match, descriptor, 128, work, sizeof work, VIREO_OK);
    CHECK(p.frame_bytes == 128 && p.enqueued); send_direct(&f, 128); read_peer(&f, wire, sizeof wire);
    wire_is(wire, sizeof wire, descriptor, match.metadata, body, sizeof body); cleanup(&f);
}
static void short_frame_cap(void) {
    fixture_t f; setup(&f); uint8_t body[33] = {0}, work[64]; prepare(&f, body, sizeof body, 3);
    memset(work, 0xa5, sizeof work); uint8_t saved[64]; memcpy(saved, work, sizeof saved);
    vireo_completion_response_report_t const p = call(&f, matching(&f), descriptor, 64, work, sizeof work, VIREO_RESULT_RANGE);
    CHECK(p.stage == VIREO_COMPLETION_RESPONSE_CHECK_FRAME && p.frame_bytes == 65 && !p.frame_encoded);
    no_commit(p); CHECK(!memcmp(work, saved, sizeof saved) && !state(&f).connection_info.write_buffer.readable_size); cleanup(&f);
}
static void write_capacity_range(void) {
    fixture_t f; setup(&f); uint8_t body[97] = {0}, work[160]; prepare(&f, body, sizeof body, 4);
    vireo_completion_response_report_t const p = call(&f, matching(&f), descriptor, 160, work, sizeof work, VIREO_RESULT_RANGE);
    CHECK(p.frame_bytes == 129 && p.stage == VIREO_COMPLETION_RESPONSE_CHECK_FRAME); no_commit(p); cleanup(&f);
}
static void queue_busy_atomic(void) {
    fixture_t f; setup(&f); prepare(&f, NULL, 0, 5); uint8_t fill[128], wire[128], work[128]; memset(fill, 0x6b, sizeof fill);
    EXPECT(vireo_tcp_server_client_write_enqueue(f.server, f.client, fill, sizeof fill, NULL), VIREO_OK);
    vireo_completion_response_report_t const p = call(&f, matching(&f), descriptor, 128, work, sizeof work, VIREO_RESULT_BUSY);
    CHECK(p.stage == VIREO_COMPLETION_RESPONSE_ENQUEUE && p.frame_encoded && p.enqueue_called && !p.enqueued && !p.refresh_called);
    CHECK(state(&f).connection_info.write_buffer.readable_size == 128); send_direct(&f, 128); read_peer(&f, wire, 128);
    CHECK(!memcmp(fill, wire, 128)); record_count(&f, 1); cleanup(&f);
}
static void flow_pressure_fifo(void) {
    fixture_t f; setup(&f); uint8_t body[64]; memset(body, 0x42, sizeof body); prepare(&f, body, sizeof body, 6);
    vireo_inflight_completion_match_t const first = matching(&f); uint8_t work[128], wire[128];
    (void)call(&f, first, descriptor, 128, work, sizeof work, VIREO_OK);
    vireo_tcp_server_client_info_t info = state(&f); CHECK(info.connection_info.write_pressure &&
        !(info.connection_info.loop_interests & VIREO_EPOLL_INTEREST_READ));
    send_direct(&f, 64); info = state(&f); CHECK(info.connection_info.write_buffer.readable_size == 32 &&
        !info.connection_info.write_pressure && (info.connection_info.loop_interests & VIREO_EPOLL_INTEREST_READ));
    prepare(&f, NULL, 0, 7); vireo_inflight_completion_match_t const second = matching(&f);
    (void)call(&f, second, descriptor, 128, work, sizeof work, VIREO_OK);
    serve(&f, 500); read_peer(&f, wire, 128);
    wire_is(wire, 96, descriptor, first.metadata, body, sizeof body);
    wire_is(wire + 96, 32, descriptor, second.metadata, NULL, 0); cleanup(&f);
}
static void stop_reject(void) {
    fixture_t f; setup(&f); prepare(&f, NULL, 0, 8); vireo_inflight_completion_match_t const match = matching(&f);
    EXPECT(vireo_tcp_server_request_stop(f.server, NULL), VIREO_OK); uint8_t work[128];
    vireo_completion_response_report_t const p = call(&f, match, descriptor, 128, work, sizeof work, VIREO_RESULT_CANCELLED);
    CHECK(p.stage == VIREO_COMPLETION_RESPONSE_CHECK_SERVER); no_commit(p); cleanup(&f);
}
static void closing_reject(void) {
    fixture_t f; setup(&f); prepare(&f, NULL, 0, 9); vireo_inflight_completion_match_t const match = matching(&f);
    uint8_t work[128], byte = 1; EXPECT(vireo_tcp_server_client_write_enqueue(f.server, f.client, &byte, 1, NULL), VIREO_OK);
    EXPECT(vireo_tcp_server_client_request_close(f.server, f.client, VIREO_CONNECTION_CLOSE_MODE_DRAIN,
        VIREO_CONNECTION_CLOSE_REASON_SERVER_STOP, NULL), VIREO_OK);
    CHECK(state(&f).connection_info.close_state == VIREO_CONNECTION_CLOSE_DRAINING);
    vireo_completion_response_report_t p = call(&f, match, descriptor, 128, work, sizeof work, VIREO_RESULT_BUSY);
    no_commit(p); CHECK(state(&f).connection_info.write_buffer.readable_size == 1);
    EXPECT(vireo_tcp_server_client_request_close(f.server, f.client, VIREO_CONNECTION_CLOSE_MODE_IMMEDIATE,
        VIREO_CONNECTION_CLOSE_REASON_SERVER_STOP, NULL), VIREO_OK);
    p = call(&f, match, descriptor, 128, work, sizeof work, VIREO_RESULT_BUSY); no_commit(p); cleanup(&f);
}
static void flow_disabled(void) {
    fixture_t f; setup(&f); prepare(&f, NULL, 0, 10); uint8_t work[128]; vireo_inflight_completion_match_t const match = matching(&f);
    EXPECT(vireo_tcp_server_client_flow_disable(f.server, f.client, NULL), VIREO_OK);
    vireo_completion_response_report_t const p = call(&f, match, descriptor, 128, work, sizeof work, VIREO_RESULT_NOT_FOUND);
    CHECK(p.stage == VIREO_COMPLETION_RESPONSE_CHECK_CLIENT); no_commit(p); cleanup(&f);
}
static void stale_and_reused(void) {
    fixture_t f; setup(&f); prepare(&f, NULL, 0, 11); uint8_t work[128]; vireo_inflight_completion_match_t const match = matching(&f);
    size_t const slot = f.client.slot_index; uint64_t const generation = f.client.generation;
    EXPECT(vireo_tcp_server_release_client(f.server, &f.client, NULL), VIREO_OK); CHECK(close(f.peer) == 0); f.peer = -1;
    no_commit(call(&f, match, descriptor, 128, work, sizeof work, VIREO_RESULT_NOT_FOUND));
    add_client(&f); CHECK(f.client.slot_index == slot && f.client.generation != generation);
    no_commit(call(&f, match, descriptor, 128, work, sizeof work, VIREO_RESULT_NOT_FOUND));
    CHECK(!state(&f).connection_info.write_buffer.readable_size); cleanup(&f);
}
static void cross_owner(void) {
    fixture_t f, other; setup(&f); setup(&other); prepare(&f, NULL, 0, 12); uint8_t work[128];
    vireo_completion_response_report_t p;
    EXPECT(vireo_completion_response_enqueue(other.server, f.completion, matching(&f), descriptor,
        128, work, sizeof work, &p), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(p.stage == VIREO_COMPLETION_RESPONSE_CHECK_CLIENT); no_commit(p); cleanup(&f); cleanup(&other);
}
static void match_mismatch(void) {
    fixture_t f; setup(&f); prepare(&f, NULL, 0, 13); uint8_t work[128]; vireo_inflight_completion_match_t const match = matching(&f);
    for (unsigned k = 0; k < 9; ++k) {
        vireo_inflight_completion_match_t bad = match;
        switch (k) {
            case 0: ++bad.metadata.route.client_owner_id; break;
            case 1: ++bad.metadata.route.client_slot_index; break;
            case 2: ++bad.metadata.route.client_generation; break;
            case 3: ++bad.metadata.route.request_sequence; break;
            case 4: ++bad.metadata.request_instance_id; break;
            case 5: ++bad.metadata.operation; break;
            case 6: --bad.metadata.deadline_ns; break;
            case 7: bad.metadata.request_instance_id = 0; break;
            default: bad.close_state = (vireo_connection_close_state_t)99; break;
        }
        vireo_completion_response_report_t const p = call(&f, bad, descriptor, 128, work, sizeof work, VIREO_RESULT_INVALID_ARGUMENT);
        CHECK(p.stage == VIREO_COMPLETION_RESPONSE_CHECK_MATCH); no_commit(p);
    }
    record_count(&f, 1); CHECK(!state(&f).connection_info.write_buffer.readable_size); cleanup(&f);
}
static void invalid_flags_commands(void) {
    fixture_t f; setup(&f); prepare(&f, NULL, 0, 14); uint8_t work[128]; vireo_inflight_completion_match_t const match = matching(&f);
    vireo_completion_response_descriptor_t desc = descriptor; desc.extra_flags = VIREO_PROTOCOL_FLAG_MORE;
    no_commit(call(&f, match, desc, 128, work, sizeof work, VIREO_RESULT_INVALID_ARGUMENT));
    desc = descriptor; desc.command = UINT16_MAX;
    vireo_completion_response_report_t p = call(&f, match, desc, 128, work, sizeof work, VIREO_RESULT_PROTOCOL);
    CHECK(p.codec_issue == VIREO_PROTOCOL_CODEC_ISSUE_UNKNOWN_COMMAND && !p.frame_encoded); no_commit(p);
    desc.command = VIREO_COMMAND_STORAGE_PUT_RESERVED_FIRST;
    p = call(&f, match, desc, 128, work, sizeof work, VIREO_RESULT_PROTOCOL);
    CHECK(p.codec_issue == VIREO_PROTOCOL_CODEC_ISSUE_RESERVED_COMMAND); no_commit(p); cleanup(&f);
}
static void basic_ranges(void) {
    fixture_t f; setup(&f); prepare(&f, NULL, 0, 15); uint8_t work[128]; vireo_inflight_completion_match_t const match = matching(&f);
    no_commit(call(&f, match, descriptor, 0, work, sizeof work, VIREO_RESULT_RANGE));
    no_commit(call(&f, match, descriptor, 31, work, sizeof work, VIREO_RESULT_RANGE));
    no_commit(call(&f, match, descriptor, VIREO_COMPLETION_RESPONSE_MAX_FRAME_BYTES + 1, work, sizeof work, VIREO_RESULT_RANGE));
    no_commit(call(&f, match, descriptor, 128, work, 127, VIREO_RESULT_RANGE));
    vireo_completion_response_report_t p;
    EXPECT(vireo_completion_response_enqueue(NULL, f.completion, match, descriptor, 128, work, sizeof work, &p), VIREO_RESULT_INVALID_ARGUMENT); no_commit(p);
    EXPECT(vireo_completion_response_enqueue(f.server, NULL, match, descriptor, 128, work, sizeof work, &p), VIREO_RESULT_INVALID_ARGUMENT); no_commit(p);
    EXPECT(vireo_completion_response_enqueue(f.server, f.completion, match, descriptor, 128, NULL, sizeof work, &p), VIREO_RESULT_INVALID_ARGUMENT); no_commit(p);
    EXPECT(vireo_completion_response_enqueue(f.server, f.completion, match, descriptor, 128, work, sizeof work, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    cleanup(&f);
}

/** 本层故障模型只替换两public边界，不声称原内核MOD失败。 */
typedef struct model {
    bool fail_enqueue; /**< 提交前拒绝，队列保持。 */
    bool fail_refresh; /**< 已入队后刷新拒绝，原字节保留。 */
    unsigned enqueue_calls; /**< 原边界桥接次数，从0累计。 */
    unsigned refresh_calls; /**< 原边界桥接次数，从0累计。 */
} model_t;
static vireo_result_t enqueue_model(void *context, vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, uint8_t const *bytes, size_t size, vireo_tcp_server_client_error_t *error) {
    model_t *m = context; ++m->enqueue_calls; errno = ENOSPC;
    if (m->fail_enqueue) {
        *error = (vireo_tcp_server_client_error_t){.primary.stage = VIREO_TCP_SERVER_CLIENT_WRITE_ENQUEUE};
        return VIREO_RESULT_INTERNAL;
    }
    return vireo_tcp_server_client_write_enqueue(server, client, bytes, size, error);
}
static vireo_result_t refresh_model(void *context, vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, vireo_tcp_server_client_error_t *error) {
    model_t *m = context; ++m->refresh_calls; errno = ENOSPC;
    if (m->fail_refresh) {
        *error = (vireo_tcp_server_client_error_t){.primary.stage = VIREO_TCP_SERVER_CLIENT_FLOW_REFRESH,
            .primary.loop_error = {.stage = VIREO_CONNECTION_LOOP_STAGE_FLOW_REFRESH,
                .loop_error = {.stage = VIREO_EVENT_LOOP_STAGE_MOD, .epoll_error = {VIREO_EPOLL_STAGE_MOD, EIO}}}};
        return VIREO_RESULT_IO;
    }
    return vireo_tcp_server_client_flow_refresh(server, client, error);
}
static vireo_completion_response_ops_t const ops = {enqueue_model, refresh_model};
static vireo_completion_response_report_t modeled(fixture_t *f, model_t *m, vireo_result_t result) {
    uint8_t work[128]; vireo_completion_response_report_t p;
    EXPECT(vireo_completion_response_with_ops(f->server, f->completion, matching(f), descriptor,
        128, work, sizeof work, &p, &ops, m), result); return p;
}
static void enqueue_fault(void) {
    fixture_t f; setup(&f); prepare(&f, NULL, 0, 16); model_t m = {.fail_enqueue = true};
    vireo_completion_response_report_t const p = modeled(&f, &m, VIREO_RESULT_INTERNAL);
    CHECK(p.frame_encoded && p.enqueue_called && !p.enqueued && !p.refresh_called && m.enqueue_calls == 1 && !m.refresh_calls &&
        p.client_error.primary.stage == VIREO_TCP_SERVER_CLIENT_WRITE_ENQUEUE);
    CHECK(!state(&f).connection_info.write_buffer.readable_size); cleanup(&f);
}
static void refresh_fault(void) {
    fixture_t f; setup(&f); prepare(&f, NULL, 0, 17); model_t m = {.fail_refresh = true};
    vireo_completion_response_report_t const p = modeled(&f, &m, VIREO_RESULT_IO);
    CHECK(p.enqueued && p.refresh_called && p.stage == VIREO_COMPLETION_RESPONSE_REFRESH &&
        p.client_error.primary.loop_error.loop_error.epoll_error.system_errno == EIO && m.enqueue_calls == 1 && m.refresh_calls == 1);
    CHECK(state(&f).connection_info.write_buffer.readable_size == 32);
    EXPECT(vireo_tcp_server_client_flow_refresh(f.server, f.client, NULL), VIREO_OK); serve(&f, 500);
    CHECK(!state(&f).connection_info.write_buffer.readable_size); cleanup(&f);
}
static void bad_ops(void) {
    fixture_t f; setup(&f); prepare(&f, NULL, 0, 18); uint8_t work[128]; vireo_completion_response_report_t p;
    vireo_completion_response_ops_t missing = ops; missing.enqueue = NULL;
    EXPECT(vireo_completion_response_with_ops(f.server, f.completion, matching(&f), descriptor,
        128, work, sizeof work, &p, &missing, NULL), VIREO_RESULT_INVALID_ARGUMENT); no_commit(p);
    missing = ops; missing.refresh = NULL;
    EXPECT(vireo_completion_response_with_ops(f.server, f.completion, matching(&f), descriptor,
        128, work, sizeof work, &p, &missing, NULL), VIREO_RESULT_INVALID_ARGUMENT); no_commit(p);
    EXPECT(vireo_completion_response_with_ops(f.server, f.completion, matching(&f), descriptor,
        128, work, sizeof work, &p, NULL, NULL), VIREO_RESULT_INVALID_ARGUMENT); no_commit(p); cleanup(&f);
}

/** 原deliver回调的短借装配，保存值报告，不保存借用completion指针。 */
typedef struct delivery {
    fixture_t *fixture; /**< 本组server/登记表短借。 */
    uint8_t workspace[128]; /**< 独立固定scratch，回调返回仍由caller拥有。 */
    vireo_completion_response_report_t report; /**< 原入队/刷新报告按值保存。 */
    vireo_completion_response_ops_t const *ops; /**< 可空本层模型表短借，NULL走真实public默认。 */
    model_t *model; /**< 可空本层模型短借，与report独立。 */
    unsigned calls; /**< 同步交付次数，初0。 */
} delivery_t;
static vireo_result_t deliver(void *context, vireo_completion_t const *completion, vireo_inflight_completion_match_t match) {
    delivery_t *d = context; ++d->calls; vireo_task_metadata_t absent;
    EXPECT(vireo_inflight_store_get(d->fixture->store, match.metadata, &absent, NULL), VIREO_RESULT_NOT_FOUND);
    if (d->ops != NULL) return vireo_completion_response_with_ops(d->fixture->server, completion, match,
        descriptor, 128, d->workspace, sizeof d->workspace, &d->report, d->ops, d->model);
    return vireo_completion_response_enqueue(d->fixture->server, completion, match, descriptor,
        128, d->workspace, sizeof d->workspace, &d->report);
}
static void consume_success(void) {
    fixture_t f; setup(&f); prepare(&f, NULL, 0, 19); delivery_t d = {.fixture = &f};
    vireo_inflight_completion_consume_report_t p;
    EXPECT(vireo_inflight_store_consume_completion(f.store, f.server, &f.completion, deliver, &d, &p), VIREO_OK);
    CHECK(!f.completion && p.record_consumed && p.completion_consumed && d.calls == 1 && d.report.enqueued); record_count(&f, 0);
    uint8_t wire[32]; serve(&f, 500); read_peer(&f, wire, sizeof wire); wire_is(wire, sizeof wire, descriptor, p.match.metadata, NULL, 0);
    cleanup(&f);
}
static void consume_busy_recovery(void) {
    fixture_t f; setup(&f); prepare(&f, NULL, 0, 20); delivery_t d = {.fixture = &f}; uint8_t fill[128] = {0}, wire[128];
    EXPECT(vireo_tcp_server_client_write_enqueue(f.server, f.client, fill, sizeof fill, NULL), VIREO_OK);
    vireo_inflight_completion_consume_report_t p;
    EXPECT(vireo_inflight_store_consume_completion(f.store, f.server, &f.completion, deliver, &d, &p), VIREO_RESULT_BUSY);
    CHECK(f.completion && p.record_consumed && !p.destroy_called && d.calls == 1 && !d.report.enqueued); record_count(&f, 0);
    send_direct(&f, 128); read_peer(&f, wire, 128);
    /* 直接恢复助手，不重入已结束登记的消费入口。 */
    (void)call(&f, p.match, descriptor, 128, d.workspace, sizeof d.workspace, VIREO_OK);
    EXPECT(vireo_completion_destroy(&f.completion), VIREO_OK); serve(&f, 500); read_peer(&f, wire, 32);
    wire_is(wire, 32, descriptor, p.match.metadata, NULL, 0); CHECK(d.calls == 1); cleanup(&f);
}
static void consume_refresh_recovery(void) {
    fixture_t f; setup(&f); prepare(&f, NULL, 0, 21); model_t m = {.fail_refresh = true};
    delivery_t d = {.fixture = &f, .ops = &ops, .model = &m}; vireo_inflight_completion_consume_report_t p;
    EXPECT(vireo_inflight_store_consume_completion(f.store, f.server, &f.completion, deliver, &d, &p), VIREO_RESULT_IO);
    CHECK(f.completion && p.record_consumed && d.report.enqueued && d.calls == 1 && m.enqueue_calls == 1); record_count(&f, 0);
    /* 已入队只恢复刷新，不再次编码/入队或重放callback。 */
    EXPECT(vireo_tcp_server_client_flow_refresh(f.server, f.client, NULL), VIREO_OK);
    EXPECT(vireo_completion_destroy(&f.completion), VIREO_OK); uint8_t wire[32]; serve(&f, 500); read_peer(&f, wire, sizeof wire);
    wire_is(wire, sizeof wire, descriptor, p.match.metadata, NULL, 0); CHECK(m.enqueue_calls == 1); cleanup(&f);
}
static void notifier_service_delivery(void) {
    fixture_t f; setup(&f); prepare(&f, NULL, 0, 22); delivery_t d = {.fixture = &f};
    vireo_inflight_completion_match_t const original = matching(&f);
    vireo_completion_queue_t *queue = NULL; vireo_completion_queue_options_t const qo = {2, 65536};
    EXPECT(vireo_completion_queue_create(&qo, &queue), VIREO_OK); vireo_notifier_t *notifier = NULL;
    vireo_notifier_options_t const no = {4096}; EXPECT(vireo_notifier_create(&no, &notifier, NULL), VIREO_OK);
    vireo_event_loop_handle_t handle = {0}; EXPECT(vireo_notifier_server_register(f.server, notifier, &handle, NULL), VIREO_OK);
    vireo_completion_queue_transfer_report_t pushed;
    EXPECT(vireo_completion_queue_try_push(queue, &f.completion, &pushed), VIREO_OK); CHECK(!f.completion && pushed.transferred);
    vireo_notifier_notify_outcome_t outcome; EXPECT(vireo_notifier_notify(notifier, &outcome, NULL), VIREO_OK);
    serve(&f, 500); vireo_completion_t *remaining = NULL; vireo_notifier_server_dispatch_report_t p;
    EXPECT(vireo_notifier_server_dispatch_ready(f.server, handle, notifier, f.store, queue,
        2, deliver, &d, &remaining, &p), VIREO_OK);
    CHECK(p.ready_taken && !remaining && p.dispatch_report.drain_report.delivered == 1 && d.report.enqueued); record_count(&f, 0);
    serve(&f, 500); uint8_t wire[32]; read_peer(&f, wire, sizeof wire);
    wire_is(wire, sizeof wire, descriptor, original.metadata, NULL, 0);
    EXPECT(vireo_notifier_server_unregister(f.server, &handle, NULL), VIREO_OK);
    EXPECT(vireo_notifier_destroy(&notifier, NULL), VIREO_OK); EXPECT(vireo_completion_queue_destroy(&queue), VIREO_OK); cleanup(&f);
}
int main(void) {
    CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL) == 0);
    void (*const cases[])(void) = {wire_body, empty_body, descriptor_fields, exact_frame_cap, short_frame_cap,
        write_capacity_range, queue_busy_atomic, flow_pressure_fifo, stop_reject, closing_reject,
        flow_disabled, stale_and_reused, cross_owner, match_mismatch, invalid_flags_commands, basic_ranges,
        enqueue_fault, refresh_fault, bad_ops, consume_success, consume_busy_recovery, consume_refresh_recovery, notifier_service_delivery};
    for (size_t k = 0; k < sizeof cases / sizeof cases[0]; ++k) { size_t n = fds(); cases[k](); CHECK(fds() == n); }
    puts("completion response enqueue: 23 groups passed"); return 0;
}
