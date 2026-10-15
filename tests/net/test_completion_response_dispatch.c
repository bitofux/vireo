/*
 * PROJECT : VIREO
 * FILE    : test_completion_response_dispatch.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-14
 * BRIEF   : 保守预算/真实多批续提示与响应/真实前缀及本层故障
 */
#define _GNU_SOURCE
#include "completion_response_dispatch_internal.h"
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

static void cleanup(fixture_t *f) {
    discard(f); EXPECT(vireo_inflight_store_destroy(&f->store), VIREO_OK);
    if (f->client.pool_id != 0) EXPECT(vireo_tcp_server_release_client(f->server, &f->client, NULL), VIREO_OK);
    if (f->peer >= 0) CHECK(close(f->peer) == 0);
    EXPECT(vireo_tcp_server_destroy(&f->server, NULL), VIREO_OK);
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

/** 本组真实批次资源；结果只在 queue 或 f.completion 之一拥有。 */
typedef struct batch {
    fixture_t f; /**< 原公开 server/客户/登记表及失败残留 owner。 */
    vireo_completion_queue_t *queue; /**< 固定容量 8 的完成队列 owner。 */
    vireo_notifier_t *notifier; /**< 真实 eventfd owner。 */
    vireo_event_loop_handle_t handle; /**< 本辅助登记完整身份，只是数值。 */
    vireo_task_metadata_t requests[8]; /**< 原元数据值快照，按提交顺序供 wire 核验。 */
    size_t pushed; /**< 本组成功提交累计条数，最多 8。 */
    uint8_t workspace[128]; /**< 独立 scratch，逐项复用且不自动扩容。 */
} batch_t;

/** 只保存描述输入和回调计数，不保存任何借用资源指针。 */
typedef struct resolver {
    size_t calls; /**< 同步调用数，从 0 起。 */
    size_t fail_at; /**< 本组故障调用序号，0 表示无模型拒绝。 */
    vireo_result_t failure; /**< 指定回调原错误。 */
    vireo_completion_response_descriptor_t desc; /**< 完整按值原 wire 关联。 */
} resolver_t;

static vireo_result_t resolve(void *context, vireo_completion_t const *completion,
    vireo_inflight_completion_match_t match, vireo_completion_response_descriptor_t *out) {
    CHECK(completion != NULL && out != NULL && match.metadata.request_instance_id != 0);
    resolver_t *r = context;
    errno = ERANGE;
    if (r == NULL) { *out = descriptor; return VIREO_OK; }
    ++r->calls;
    if (r->calls == r->fail_at) return r->failure;
    *out = r->desc; return VIREO_OK;
}
static resolver_t resolution(void) {
    return (resolver_t){.desc = descriptor};
}
static void batch_setup(batch_t *b) {
    *b = (batch_t){0}; setup(&b->f);
    vireo_completion_queue_options_t const qo = {8, 65536};
    EXPECT(vireo_completion_queue_create(&qo, &b->queue), VIREO_OK);
    vireo_notifier_options_t const no = {4096};
    EXPECT(vireo_notifier_create(&no, &b->notifier, NULL), VIREO_OK);
    EXPECT(vireo_notifier_server_register(b->f.server, b->notifier, &b->handle, NULL), VIREO_OK);
}
static void push(batch_t *b, uint8_t const *body, size_t size) {
    CHECK(b->pushed < 8);
    prepare(&b->f, body, size, (uint32_t)(b->pushed + 1));
    vireo_completion_info_t info;
    EXPECT(vireo_completion_inspect(b->f.completion, &info), VIREO_OK);
    b->requests[b->pushed++] = info.metadata.request;
    vireo_completion_queue_transfer_report_t report;
    EXPECT(vireo_completion_queue_try_push(b->queue, &b->f.completion, &report), VIREO_OK);
    CHECK(report.transferred && b->f.completion == NULL);
}
static void queue_count(batch_t *b, size_t count) {
    vireo_completion_queue_info_t info;
    EXPECT(vireo_completion_queue_inspect(b->queue, &info), VIREO_OK); CHECK(info.count == count);
}
static void ready(batch_t *b) {
    vireo_notifier_notify_outcome_t outcome;
    EXPECT(vireo_notifier_notify(b->notifier, &outcome, NULL), VIREO_OK); serve(&b->f, 500);
}
static vireo_completion_response_dispatch_report_t run(batch_t *b, size_t items,
    size_t frame, size_t bytes, resolver_t *r, vireo_result_t result) {
    vireo_completion_response_dispatch_report_t report; memset(&report, 0xa5, sizeof report);
    EXPECT(vireo_completion_response_dispatch_ready(b->f.server, b->handle, b->notifier,
        b->f.store, b->queue, items, frame, bytes, b->workspace, sizeof b->workspace,
        resolve, r, &b->f.completion, &report), result);
    return report;
}
static void batch_cleanup(batch_t *b) {
    discard(&b->f);
    for (;;) {
        vireo_completion_queue_transfer_report_t p;
        vireo_result_t const result = vireo_completion_queue_try_pop(b->queue, &b->f.completion, &p);
        CHECK(result == VIREO_OK || result == VIREO_RESULT_NOT_FOUND || result == VIREO_RESULT_CANCELLED);
        if (result != VIREO_OK) break;
        CHECK(p.transferred); discard(&b->f);
    }
    record_count(&b->f, 0);
    EXPECT(vireo_notifier_server_unregister(b->f.server, &b->handle, NULL), VIREO_OK);
    EXPECT(vireo_notifier_destroy(&b->notifier, NULL), VIREO_OK);
    EXPECT(vireo_completion_queue_destroy(&b->queue), VIREO_OK); cleanup(&b->f);
}
static vireo_inflight_completion_consume_report_t consumed(vireo_completion_response_dispatch_report_t p) {
    return p.dispatch_report.dispatch_report.drain_report.consume_report;
}
static void no_work(vireo_completion_response_dispatch_report_t p) {
    CHECK(!p.dispatch_called && p.resolve_calls == 0 && p.response_calls == 0 &&
        p.enqueued_responses == 0 && p.enqueued_bytes == 0);
}

static void two_frames_and_empty(void) {
    batch_t b; batch_setup(&b); uint8_t const body[] = {0, 255, 42};
    push(&b, body, 3); push(&b, NULL, 0); ready(&b); resolver_t r = resolution();
    r.desc.session_handle = 0x10203040; r.desc.task_handle = UINT32_MAX;
    vireo_completion_response_dispatch_report_t p = run(&b, 8, 128, 512, &r, VIREO_OK);
    CHECK(p.stage == 0 && p.effective_max_items == 4 && p.reserved_frame_bytes == 512 &&
        p.resolve_calls == 2 && p.response_calls == 2 && p.enqueued_responses == 2 && p.enqueued_bytes == 67 &&
        p.last_response_called && p.last_response_report.frame_bytes == 32 && p.last_response_report.enqueued);
    vireo_inflight_completion_drain_report_t const d = p.dispatch_report.dispatch_report.drain_report;
    CHECK(d.pop_calls == 3 && d.finished == 2 && d.stop_reason == VIREO_INFLIGHT_COMPLETION_DRAIN_EMPTY &&
        !d.last_item_consume_called && !d.consume_report.delivery_called && !p.dispatch_report.dispatch_report.renotify_called);
    record_count(&b.f, 0); queue_count(&b, 0); CHECK(!b.f.completion);
    memset(b.workspace, 0xa5, sizeof b.workspace); serve(&b.f, 500); uint8_t wire[67]; read_peer(&b.f, wire, sizeof wire);
    wire_is(wire, 35, r.desc, b.requests[0], body, 3);
    wire_is(wire + 35, 32, r.desc, b.requests[1], NULL, 0); batch_cleanup(&b);
}
static void multi_batch_conservative(void) {
    batch_t b; batch_setup(&b); for (unsigned i = 0; i < 5; ++i) push(&b, NULL, 0);
    ready(&b); resolver_t r = resolution();
    for (size_t turn = 0; turn < 3; ++turn) {
        size_t const n = turn < 2 ? 2 : 1;
        vireo_completion_response_dispatch_report_t const p = run(&b, 8, 128, 256, &r, VIREO_OK);
        CHECK(p.effective_max_items == 2 && p.reserved_frame_bytes == 256 && p.enqueued_responses == n &&
            p.enqueued_bytes == 32 * n && p.enqueued_bytes < p.reserved_frame_bytes && !b.f.completion);
        CHECK(p.dispatch_report.dispatch_report.renotify_called == (turn < 2));
        record_count(&b.f, turn < 2 ? 5 - (turn + 1) * 2 : 0);
        queue_count(&b, turn < 2 ? 5 - (turn + 1) * 2 : 0);
        serve(&b.f, 500); uint8_t wire[64]; read_peer(&b.f, wire, n * 32);
        for (size_t j = 0; j < n; ++j) wire_is(wire + j * 32, 32, descriptor, b.requests[turn * 2 + j], NULL, 0);
    }
    CHECK(r.calls == 5); batch_cleanup(&b);
}
static void item_limit_and_exact_frame(void) {
    batch_t b; batch_setup(&b); uint8_t body[96] = {0}; push(&b, body, sizeof body); push(&b, NULL, 0); ready(&b);
    vireo_completion_response_dispatch_report_t const p = run(&b, 1, 128, 512, NULL, VIREO_OK);
    CHECK(p.effective_max_items == 1 && p.reserved_frame_bytes == 128 && p.enqueued_bytes == 128 &&
        p.enqueued_responses == 1 && p.dispatch_report.dispatch_report.renotify_called);
    record_count(&b.f, 1); queue_count(&b, 1); serve(&b.f, 500); uint8_t wire[128]; read_peer(&b.f, wire, sizeof wire);
    wire_is(wire, sizeof wire, descriptor, b.requests[0], body, sizeof body); batch_cleanup(&b);
}
static void quotient_remainder(void) {
    batch_t b; batch_setup(&b); uint8_t body[8] = {0}; push(&b, body, 8); push(&b, NULL, 0); ready(&b);
    vireo_completion_response_dispatch_report_t const p = run(&b, 8, 64, 127, NULL, VIREO_OK);
    CHECK(p.effective_max_items == 1 && p.reserved_frame_bytes == 64 && p.enqueued_bytes == 40);
    record_count(&b.f, 1); queue_count(&b, 1); batch_cleanup(&b);
}
static void late_item_uses_opportunity(void) {
    batch_t b; batch_setup(&b); push(&b, NULL, 0); push(&b, NULL, 0);
    vireo_task_metadata_t ended; EXPECT(vireo_inflight_store_take(b.f.store, b.requests[0], &ended, NULL), VIREO_OK);
    ready(&b); resolver_t r = resolution();
    vireo_completion_response_dispatch_report_t p = run(&b, 8, 128, 128, &r, VIREO_OK);
    CHECK(p.resolve_calls == 0 && p.enqueued_bytes == 0 && p.effective_max_items == 1 &&
        p.dispatch_report.dispatch_report.drain_report.late_cleaned == 1 && p.dispatch_report.dispatch_report.renotify_called);
    queue_count(&b, 1); record_count(&b.f, 1); serve(&b.f, 500);
    p = run(&b, 8, 128, 256, &r, VIREO_OK); CHECK(p.enqueued_responses == 1 && r.calls == 1);
    record_count(&b.f, 0); batch_cleanup(&b);
}
static void reused_client_late(void) {
    batch_t b; batch_setup(&b); push(&b, NULL, 0);
    vireo_connection_pool_lease_t const old = b.f.client;
    EXPECT(vireo_tcp_server_release_client(b.f.server, &b.f.client, NULL), VIREO_OK);
    CHECK(close(b.f.peer) == 0); b.f.peer = -1; add_client(&b.f);
    CHECK(b.f.client.slot_index == old.slot_index && b.f.client.generation != old.generation);
    ready(&b); resolver_t r = resolution();
    vireo_completion_response_dispatch_report_t const p = run(&b, 8, 128, 256, &r, VIREO_OK);
    CHECK(p.resolve_calls == 0 && p.enqueued_bytes == 0 && p.dispatch_report.dispatch_report.drain_report.late_cleaned == 1);
    CHECK(!state(&b.f).connection_info.write_buffer.readable_size); record_count(&b.f, 0); batch_cleanup(&b);
}
static void resolver_failure_prefix(void) {
    batch_t b; batch_setup(&b); for (unsigned i = 0; i < 3; ++i) push(&b, NULL, 0); ready(&b);
    resolver_t r = resolution(); r.fail_at = 2; r.failure = VIREO_RESULT_DATABASE;
    vireo_completion_response_dispatch_report_t const p = run(&b, 8, 128, 512, &r, VIREO_RESULT_DATABASE);
    CHECK(p.stage == VIREO_COMPLETION_RESPONSE_DISPATCH_RESOLVE_DESCRIPTOR && p.resolve_calls == 2 &&
        p.response_calls == 1 && p.enqueued_responses == 1 && p.enqueued_bytes == 32 &&
        !p.last_response_called && !p.last_response_report.enqueued && p.last_response_report.frame_bytes == 0 &&
        p.last_resolve_result == VIREO_RESULT_DATABASE && b.f.completion && consumed(p).record_consumed);
    record_count(&b.f, 1); queue_count(&b, 1); CHECK(!p.dispatch_report.dispatch_report.renotify_called);
    discard(&b.f); ready(&b); uint8_t wire[32]; read_peer(&b.f, wire, 32);
    wire_is(wire, 32, descriptor, b.requests[0], NULL, 0);
    r.fail_at = 0; (void)run(&b, 8, 128, 256, &r, VIREO_OK);
    serve(&b.f, 500); read_peer(&b.f, wire, 32); wire_is(wire, 32, descriptor, b.requests[2], NULL, 0); batch_cleanup(&b);
}
static void unsupported_descriptor(void) {
    batch_t b; batch_setup(&b); push(&b, NULL, 0); ready(&b); resolver_t r = resolution();
    r.desc.extra_flags = VIREO_PROTOCOL_FLAG_MORE;
    vireo_completion_response_dispatch_report_t const p = run(&b, 8, 128, 256, &r, VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(p.stage == VIREO_COMPLETION_RESPONSE_DISPATCH_ENQUEUE_RESPONSE && p.last_response_called &&
        p.response_calls == 1 && p.enqueued_bytes == 0 && b.f.completion && consumed(p).record_consumed);
    record_count(&b.f, 0); batch_cleanup(&b);
}
static void fifo_full_direct_recovery(void) {
    batch_t b; batch_setup(&b); push(&b, NULL, 0); ready(&b);
    uint8_t fill[128] = {0}, wire[128];
    EXPECT(vireo_tcp_server_client_write_enqueue(b.f.server, b.f.client, fill, sizeof fill, NULL), VIREO_OK);
    vireo_completion_response_dispatch_report_t const p = run(&b, 8, 128, 256, NULL, VIREO_RESULT_BUSY);
    CHECK(p.stage == VIREO_COMPLETION_RESPONSE_DISPATCH_ENQUEUE_RESPONSE && p.enqueued_bytes == 0 &&
        p.last_response_report.enqueue_called && !p.last_response_report.enqueued &&
        b.f.completion && consumed(p).record_consumed);
    record_count(&b.f, 0); send_direct(&b.f, 128); read_peer(&b.f, wire, 128); CHECK(!memcmp(wire, fill, 128));
    vireo_completion_response_report_t response;
    EXPECT(vireo_completion_response_enqueue(b.f.server, b.f.completion, consumed(p).match,
        descriptor, 128, b.workspace, sizeof b.workspace, &response), VIREO_OK);
    EXPECT(vireo_completion_destroy(&b.f.completion), VIREO_OK); serve(&b.f, 500); read_peer(&b.f, wire, 32);
    wire_is(wire, 32, descriptor, b.requests[0], NULL, 0); batch_cleanup(&b);
}
static void oversized_response(void) {
    batch_t b; batch_setup(&b); uint8_t body[97] = {0}; push(&b, body, sizeof body); ready(&b);
    vireo_completion_response_dispatch_report_t const p = run(&b, 8, 128, 256, NULL, VIREO_RESULT_RANGE);
    CHECK(p.enqueued_bytes == 0 && p.last_response_report.frame_bytes == 129 && b.f.completion && consumed(p).record_consumed);
    record_count(&b.f, 0); batch_cleanup(&b);
}
static void pre_stopped_untouched(void) {
    batch_t b; batch_setup(&b); push(&b, NULL, 0); ready(&b);
    EXPECT(vireo_tcp_server_request_stop(b.f.server, NULL), VIREO_OK);
    vireo_completion_response_dispatch_report_t const p = run(&b, 8, 128, 256, NULL, VIREO_RESULT_CANCELLED);
    no_work(p); CHECK(p.stage == VIREO_COMPLETION_RESPONSE_DISPATCH_CHECK_SERVER);
    vireo_tcp_server_auxiliary_event_t event;
    EXPECT(vireo_tcp_server_auxiliary_read_take_ready(b.f.server, &event, NULL), VIREO_OK);
    CHECK(event.handle.token == b.handle.token && (event.events & VIREO_EPOLL_EVENT_READ));
    uint64_t count; EXPECT(vireo_notifier_consume(b.notifier, &count, NULL), VIREO_OK); CHECK(count == 1);
    queue_count(&b, 1); record_count(&b.f, 1); batch_cleanup(&b);
}
static void no_ready_or_empty_hint(void) {
    batch_t b; batch_setup(&b); push(&b, NULL, 0);
    vireo_completion_response_dispatch_report_t p = run(&b, 8, 128, 256, NULL, VIREO_OK);
    CHECK(p.dispatch_called && !p.dispatch_report.ready_taken && !p.resolve_calls); queue_count(&b, 1); record_count(&b.f, 1);
    ready(&b); uint64_t count; EXPECT(vireo_notifier_consume(b.notifier, &count, NULL), VIREO_OK); CHECK(count == 1);
    p = run(&b, 8, 128, 256, NULL, VIREO_OK);
    CHECK(p.dispatch_report.dispatch_report.notification_count == 0 && p.enqueued_responses == 1);
    batch_cleanup(&b);
}
static void closed_empty_passthrough(void) {
    batch_t b; batch_setup(&b); vireo_completion_queue_close_report_t close_report;
    EXPECT(vireo_completion_queue_close(b.queue, &close_report), VIREO_OK); ready(&b);
    vireo_completion_response_dispatch_report_t const p = run(&b, 8, 128, 256, NULL, VIREO_RESULT_CANCELLED);
    CHECK(p.stage == VIREO_COMPLETION_RESPONSE_DISPATCH_DISPATCH_READY && !p.resolve_calls && !b.f.completion &&
        p.dispatch_report.dispatch_report.drain_result == VIREO_RESULT_CANCELLED);
    batch_cleanup(&b);
}

/** 仅本层公开依赖故障模型，不读取任何外模块私有状态。 */
typedef struct model {
    bool inspect_fail; /**< 观测拒绝，不消费。 */
    bool stop_before_dispatch; /**< 观测后公开停止，原 take 后助手将拒绝。 */
    bool response_failure; /**< 真实助手成功后改发后段 IO 报告，非真实内核 MOD 失败。 */
    bool renotify_failure; /**< 原批次成功后改发续提示 IO 模型，非真实 eventfd 失败。 */
    bool dispatch_busy; /**< 原分发未调用即报告未转移 BUSY。 */
    size_t inspections; /**< 本组实际模型观测次数。 */
} model_t;
static vireo_result_t inspect_model(void *context, vireo_tcp_server_t const *server, vireo_tcp_server_info_t *info) {
    model_t *m = context; ++m->inspections;
    if (m->inspect_fail) { errno = EIO; return VIREO_RESULT_INTERNAL; }
    return vireo_tcp_server_inspect(server, info);
}
static vireo_result_t dispatch_model(void *ops_context, vireo_tcp_server_t *server,
    vireo_event_loop_handle_t handle, vireo_notifier_t *notifier, vireo_inflight_store_t *store,
    vireo_completion_queue_t *queue, size_t items, vireo_inflight_completion_deliver_fn deliver,
    void *context, vireo_completion_t **remaining, vireo_notifier_server_dispatch_report_t *report) {
    model_t *m = ops_context;
    if (m->dispatch_busy) { *report = (vireo_notifier_server_dispatch_report_t){.stage = VIREO_NOTIFIER_SERVER_DISPATCH_TAKE_READY,
        .ready_called = true}; return VIREO_RESULT_BUSY; }
    if (m->stop_before_dispatch) EXPECT(vireo_tcp_server_request_stop(server, NULL), VIREO_OK);
    vireo_result_t const result = vireo_notifier_server_dispatch_ready(server, handle, notifier, store, queue,
        items, deliver, context, remaining, report);
    if (m->renotify_failure && result == VIREO_OK) {
        CHECK(report->dispatch_report.renotify_called);
        report->stage = VIREO_NOTIFIER_SERVER_DISPATCH_DISPATCH;
        report->dispatch_result = VIREO_RESULT_IO;
        report->dispatch_report.stage = VIREO_NOTIFIER_COMPLETION_RENOTIFY;
        report->dispatch_report.renotify_result = VIREO_RESULT_IO;
        report->dispatch_report.renotify_error = (vireo_notifier_error_t){VIREO_NOTIFIER_STAGE_NOTIFY, EIO};
        return VIREO_RESULT_IO;
    }
    return result;
}
static vireo_result_t response_model(void *context, vireo_tcp_server_t *server,
    vireo_completion_t const *completion, vireo_inflight_completion_match_t match,
    vireo_completion_response_descriptor_t desc, size_t frame, uint8_t *work, size_t size,
    vireo_completion_response_report_t *report) {
    model_t *m = context;
    vireo_result_t const result = vireo_completion_response_enqueue(server, completion, match, desc, frame, work, size, report);
    if (m->response_failure && result == VIREO_OK) {
        report->stage = VIREO_COMPLETION_RESPONSE_REFRESH;
        report->client_error = (vireo_tcp_server_client_error_t){.primary.stage = VIREO_TCP_SERVER_CLIENT_FLOW_REFRESH,
            .primary.loop_error = {.stage = VIREO_CONNECTION_LOOP_STAGE_FLOW_REFRESH,
                .loop_error = {.stage = VIREO_EVENT_LOOP_STAGE_MOD, .epoll_error = {VIREO_EPOLL_STAGE_MOD, EIO}}}};
        return VIREO_RESULT_IO; /* 模型发布后段错误，真实已提交字节保持；不冒真实 MOD 故障。 */
    }
    return result;
}
static vireo_completion_response_dispatch_ops_t const ops = {inspect_model, dispatch_model, response_model};
static vireo_completion_response_dispatch_report_t modeled(batch_t *b, model_t *m, size_t items, vireo_result_t result) {
    vireo_completion_response_dispatch_report_t p;
    EXPECT(vireo_completion_response_dispatch_with_ops(b->f.server, b->handle, b->notifier, b->f.store,
        b->queue, items, 128, 256, b->workspace, sizeof b->workspace, resolve, NULL,
        &b->f.completion, &p, &ops, m), result); return p;
}
static void inspect_and_dispatch_failures(void) {
    batch_t b; batch_setup(&b); push(&b, NULL, 0); ready(&b); model_t m = {.inspect_fail = true};
    vireo_completion_response_dispatch_report_t p = modeled(&b, &m, 8, VIREO_RESULT_INTERNAL);
    no_work(p); CHECK(p.stage == VIREO_COMPLETION_RESPONSE_DISPATCH_CHECK_SERVER && m.inspections == 1);
    m = (model_t){.dispatch_busy = true}; p = modeled(&b, &m, 8, VIREO_RESULT_BUSY);
    CHECK(p.dispatch_called && p.stage == VIREO_COMPLETION_RESPONSE_DISPATCH_DISPATCH_READY && !p.resolve_calls);
    queue_count(&b, 1); record_count(&b.f, 1); batch_cleanup(&b);
}
static void post_sample_stop(void) {
    batch_t b; batch_setup(&b); push(&b, NULL, 0); ready(&b); model_t m = {.stop_before_dispatch = true};
    vireo_completion_response_dispatch_report_t const p = modeled(&b, &m, 8, VIREO_RESULT_CANCELLED);
    CHECK(p.stage == VIREO_COMPLETION_RESPONSE_DISPATCH_ENQUEUE_RESPONSE && b.f.completion &&
        consumed(p).record_consumed && p.response_calls == 1 && p.enqueued_bytes == 0 &&
        p.last_response_report.stage == VIREO_COMPLETION_RESPONSE_CHECK_SERVER);
    record_count(&b.f, 0); batch_cleanup(&b);
}
static void committed_response_error(void) {
    batch_t b; batch_setup(&b); push(&b, NULL, 0); ready(&b); model_t m = {.response_failure = true};
    vireo_completion_response_dispatch_report_t const p = modeled(&b, &m, 8, VIREO_RESULT_IO);
    CHECK(p.stage == VIREO_COMPLETION_RESPONSE_DISPATCH_ENQUEUE_RESPONSE && p.enqueued_responses == 1 &&
        p.enqueued_bytes == 32 && p.last_response_report.enqueued && p.last_response_report.refresh_called &&
        p.last_response_result == VIREO_RESULT_IO && b.f.completion && consumed(p).record_consumed &&
        p.dispatch_report.dispatch_report.drain_report.delivered == 0);
    CHECK(p.last_response_report.client_error.primary.loop_error.loop_error.epoll_error.system_errno == EIO);
    record_count(&b.f, 0);
    EXPECT(vireo_tcp_server_client_flow_refresh(b.f.server, b.f.client, NULL), VIREO_OK);
    EXPECT(vireo_completion_destroy(&b.f.completion), VIREO_OK); serve(&b.f, 500);
    uint8_t wire[32]; read_peer(&b.f, wire, 32); wire_is(wire, 32, descriptor, b.requests[0], NULL, 0);
    CHECK(state(&b.f).connection_info.write_buffer.readable_size == 0); batch_cleanup(&b);
}
static void renotify_error_preserves_response(void) {
    batch_t b; batch_setup(&b); push(&b, NULL, 0); push(&b, NULL, 0); ready(&b);
    model_t m = {.renotify_failure = true};
    vireo_completion_response_dispatch_report_t const p = modeled(&b, &m, 1, VIREO_RESULT_IO);
    CHECK(p.stage == VIREO_COMPLETION_RESPONSE_DISPATCH_DISPATCH_READY && p.enqueued_bytes == 32 &&
        p.enqueued_responses == 1 && p.last_response_result == VIREO_OK && !b.f.completion &&
        p.dispatch_report.dispatch_report.drain_result == VIREO_OK &&
        p.dispatch_report.dispatch_report.renotify_result == VIREO_RESULT_IO);
    record_count(&b.f, 1); queue_count(&b, 1); batch_cleanup(&b);
}
static void basic_shapes_and_ranges(void) {
    batch_t b; batch_setup(&b); vireo_completion_response_dispatch_report_t p;
    vireo_event_loop_handle_t saved = b.handle;
    b.handle = (vireo_event_loop_handle_t){0}; p = run(&b, 8, 128, 256, NULL, VIREO_RESULT_NOT_FOUND); no_work(p);
    b.handle = (vireo_event_loop_handle_t){saved.loop_id, 0}; p = run(&b, 8, 128, 256, NULL, VIREO_RESULT_INVALID_ARGUMENT); no_work(p);
    b.handle = (vireo_event_loop_handle_t){0, saved.token}; p = run(&b, 8, 128, 256, NULL, VIREO_RESULT_INVALID_ARGUMENT); no_work(p); b.handle = saved;
    size_t const invalid[][3] = {{0,128,256},{8,128,0},{65537,128,256},{8,31,256},
        {8,16777249,67108864},{8,128,67108865},{8,128,127},{8,129,256},{SIZE_MAX,128,256}};
    for (size_t i = 0; i < sizeof invalid / sizeof invalid[0]; ++i) {
        p = run(&b, invalid[i][0], invalid[i][1], invalid[i][2], NULL,
            i < 2 ? VIREO_RESULT_INVALID_ARGUMENT : VIREO_RESULT_RANGE); no_work(p);
    }
    p = run(&b, 65536, 32, 67108864, NULL, VIREO_OK);
    CHECK(p.effective_max_items == 65536 && p.reserved_frame_bytes == 2097152 && !p.resolve_calls);
    p = run(&b, 8, 32, 32, NULL, VIREO_OK);
    CHECK(p.effective_max_items == 1 && p.reserved_frame_bytes == 32 && !p.resolve_calls);
    batch_cleanup(&b);
}
static void null_addresses_and_bad_ops(void) {
    batch_t b; batch_setup(&b); vireo_completion_response_dispatch_report_t p;
    model_t m = {0};
    for (unsigned bad = 0; bad < 13; ++bad) {
        vireo_completion_response_dispatch_ops_t missing = ops;
        if (bad == 9) missing.inspect = NULL;
        if (bad == 10) missing.dispatch = NULL;
        if (bad == 11) missing.response = NULL;
        memset(&p, 0xa5, sizeof p);
        EXPECT(vireo_completion_response_dispatch_with_ops(bad == 0 ? NULL : b.f.server, b.handle,
            bad == 1 ? NULL : b.notifier, bad == 2 ? NULL : b.f.store, bad == 3 ? NULL : b.queue,
            8, 128, 256, bad == 4 ? NULL : b.workspace, sizeof b.workspace, bad == 5 ? NULL : resolve, NULL,
            bad == 6 ? NULL : &b.f.completion, bad == 7 ? NULL : &p,
            bad == 8 ? NULL : &missing, &m), bad == 12 ? VIREO_OK : VIREO_RESULT_INVALID_ARGUMENT);
        if (bad != 7 && bad != 12) no_work(p);
    }
    push(&b, NULL, 0);
    vireo_completion_queue_transfer_report_t taken;
    EXPECT(vireo_completion_queue_try_pop(b.queue, &b.f.completion, &taken), VIREO_OK);
    vireo_completion_t *original = b.f.completion;
    p = run(&b, 8, 128, 256, NULL, VIREO_RESULT_INVALID_ARGUMENT); no_work(p); CHECK(b.f.completion == original);
    batch_cleanup(&b);
}
int main(void) {
    CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL) == 0);
    _Static_assert(VIREO_COMPLETION_RESPONSE_DISPATCH_MAX_BATCH_BYTES == 67108864 &&
        VIREO_COMPLETION_RESPONSE_DISPATCH_CHECK_SERVER == 1 &&
        VIREO_COMPLETION_RESPONSE_DISPATCH_ENQUEUE_RESPONSE == 4, "explicit independent bounds/stages");
    void (*const cases[])(void) = {two_frames_and_empty, multi_batch_conservative, item_limit_and_exact_frame,
        quotient_remainder, late_item_uses_opportunity, reused_client_late, resolver_failure_prefix,
        unsupported_descriptor, fifo_full_direct_recovery, oversized_response, pre_stopped_untouched,
        no_ready_or_empty_hint, closed_empty_passthrough, inspect_and_dispatch_failures, post_sample_stop,
        committed_response_error, renotify_error_preserves_response, basic_shapes_and_ranges, null_addresses_and_bad_ops};
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; ++i) { size_t before = fds(); cases[i](); CHECK(fds() == before); }
    puts("completion response dispatch: 19 groups passed"); return 0;
}
