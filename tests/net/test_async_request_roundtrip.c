/*
 * PROJECT : VIREO
 * FILE    : test_async_request_roundtrip.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-14
 * BRIEF   : 既有公开接口的显式无业务异步请求到响应闭环
 */
#define _GNU_SOURCE
#include <vireo/net/async_request_head.h>
#include <vireo/net/completion_response_dispatch.h>
#include <vireo/net/notifier_server.h>
#include <vireo/thread/completion_publish.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); abort(); } } while (0)
#define EXPECT(x, y) do { errno = EDOM; vireo_result_t const result_ = (x); CHECK(result_ == (y) && errno == EDOM); } while (0)
#define LIMIT 1000000U

/** Reactor独占的真实TCP及登记资源，绝不发布给worker。 */
typedef struct fixture {
    vireo_tcp_server_t *server; /**< 唯一server owner，显式预留1辅助登记。 */
    vireo_connection_pool_lease_t client; /**< 当前完整租约，归还后清零。 */
    int peer; /**< TCP对端唯一fd，-1为空。 */
    struct sockaddr_in address; /**< 临时loopback端点，供同槽新代接入。 */
    vireo_inflight_store_t *store; /**< 容量8登记owner，销毁前必须清空。 */
} fixture_t;
/** 每个成功输入的独立数值账本，只由Reactor读写，不保活客户。 */
typedef struct entry {
    bool valid; /**< 仅确认task移交后登记此测试项。 */
    vireo_task_metadata_t metadata; /**< 完整route/instance/op/deadline原值。 */
    vireo_completion_response_descriptor_t descriptor; /**< 原wire四字段，不由operation猜测。 */
    unsigned int resolves; /**< 本项实际描述回调次数，恢复不重放此回调。 */
} entry_t;
/** pool长期借用此固定测试context；无server、客户指针或网络fd。 */
typedef struct worker {
    vireo_completion_queue_t *outputs; /**< manager唯一拥有的结果队列，借至pool销毁。 */
    vireo_notifier_t *notifier; /**< 借至所有producer结束，使用公开notify。 */
    bool hold_first; /**< 启动前固定，tag1读标签后、解析头和完整body前停驻。 */
    pthread_barrier_t entered; /**< tag1与manager会合，确认已领取。 */
    pthread_barrier_t release; /**< manager允许tag1继续，不抢占执行。 */
    atomic_uint published; /**< helper返回后累加，非join或客户端已收到证明。 */
    atomic_uint seen[9]; /**< 每tag实际执行次数，查重复worker工作。 */
    vireo_completion_publish_report_t reports[9]; /**< 每tag独立写，manager仅join后读。 */
} worker_t;
/** 本组Reactor拥有的组合及失败残留；worker只借上面context。 */
typedef struct world {
    fixture_t f; /**< 真实网络/登记资源根。 */
    vireo_task_queue_t *tasks; /**< 专用固定task queue owner，pool长期借用。 */
    vireo_thread_pool_t *pool; /**< 固定线程owner，manager串行管理。 */
    vireo_completion_queue_t *outputs; /**< 单consumer结果queue owner。 */
    vireo_notifier_t *notifier; /**< eventfd owner，必须先结束注册借用。 */
    vireo_event_loop_handle_t handle; /**< 当前完整辅助登记身份，不拥有fd。 */
    worker_t worker; /**< 原位barrier/atomic及worker长借context。 */
    entry_t entries[9]; /**< 成功输入的原wire/请求纯值账本，tag1..8。 */
    unsigned int resolve_order[16]; /**< 实际描述回调顺序，不等实际发送成功。 */
    size_t resolve_count; /**< resolve_order有效前缀，最多16。 */
    unsigned int fail_tag; /**< 0无拒绝；指定测试caller描述函数返回IO。 */
    vireo_async_request_pending_t pending; /**< 当前客户唯一pending，成功消费清零。 */
    vireo_completion_t *remaining; /**< 失败时单项未销毁结果owner，初NULL。 */
    uint8_t scratch[64]; /**< 单帧响应scratch，失败可改，非长期消息存储。 */
} world_t;
static vireo_connection_options_t const connection = {128, 128, 256};
static vireo_connection_flow_options_t const flow = {128, 127, 128, 32, 96};
/* 固定golden字节独立于worker的变换循环；不是业务body schema。 */
static uint8_t const expected[9][3] = {{0}, {0x5B,0x5A,0xFF}, {0x58,0x5A,0xFF},
 {0x59,0x5A,0xFF}, {0x5E,0x5A,0xFF}, {0x5F,0x5A,0xFF}, {0x5C,0x5A,0xFF},
 {0x5D,0x5A,0xFF}, {0x52,0x5A,0xFF}};
static void meet(pthread_barrier_t *barrier) {
    int const result = pthread_barrier_wait(barrier); CHECK(result == 0 || result == PTHREAD_BARRIER_SERIAL_THREAD);
}
static bool same(vireo_task_metadata_t a, vireo_task_metadata_t b) {
    bool equal; EXPECT(vireo_task_metadata_same_request(a, b, &equal), VIREO_OK);
    return equal && a.operation == b.operation && a.deadline_ns == b.deadline_ns;
}
static vireo_result_t execute(void *context, vireo_task_t const *task) {
    worker_t *w = context; vireo_task_payload_view_t view; EXPECT(vireo_task_borrow_payload(task, &view), VIREO_OK);
    CHECK(view.size == 35); unsigned int const tag = view.data[32]; CHECK(tag >= 1 && tag <= 8);
    CHECK(atomic_fetch_add_explicit(&w->seen[tag], 1, memory_order_relaxed) == 0);
    if (w->hold_first && tag == 1) { meet(&w->entered); meet(&w->release); }
    vireo_protocol_header_t header; vireo_protocol_codec_issue_t issue;
    EXPECT(vireo_protocol_header_decode(view.data, view.size, &header, &issue), VIREO_OK);
    EXPECT(vireo_protocol_request_header_validate(&header, &issue), VIREO_OK);
    EXPECT(vireo_protocol_frame_crc32c_verify(view.data, 32, view.data + 32, 3, &issue), VIREO_OK);
    CHECK(header.body_len == 3 && view.data[33] == 0 && view.data[34] == 0xA5);
    uint8_t response[3]; for (size_t i = 0; i < 3; ++i) response[i] = (uint8_t)(view.data[32 + i] ^ 0x5A);
    vireo_completion_t *remaining = NULL;
    EXPECT(vireo_completion_copy_wait_publish(task, VIREO_OK, VIREO_STATUS_OK, response, sizeof response,
        4096, w->outputs, w->notifier, &remaining, &w->reports[tag]), VIREO_OK);
    CHECK(remaining == NULL); memset(response, 255, sizeof response);
    (void)atomic_fetch_add_explicit(&w->published, 1, memory_order_release); return VIREO_OK;
}
static void add_client(fixture_t *f) {
    CHECK(f->peer == -1 && f->client.pool_id == 0);
    f->peer = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0); CHECK(f->peer >= 0);
    CHECK(connect(f->peer, (struct sockaddr *)&f->address, sizeof f->address) == 0);
    vireo_tcp_server_admit_budget_t const budget = {1, 2}; vireo_tcp_server_admit_info_t info;
    EXPECT(vireo_tcp_server_admit_batch(f->server, &connection, &budget, &f->client, 1, &info, NULL), VIREO_OK);
    CHECK(info.admitted_count == 1); EXPECT(vireo_tcp_server_client_flow_configure(f->server, f->client, &flow, NULL), VIREO_OK);
}
static void prepare(world_t *w, size_t workers, size_t task_capacity, size_t output_capacity, bool hold) {
    *w = (world_t){.f.peer = -1}; w->worker.hold_first = hold;
    vireo_tcp_server_options_t const so = {1, 2, 1048576, 1024};
    EXPECT(vireo_tcp_server_create_with_auxiliary_capacity(&so, 1, &w->f.server, NULL), VIREO_OK);
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0); CHECK(fd >= 0);
    w->f.address = (struct sockaddr_in){.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    CHECK(bind(fd, (struct sockaddr *)&w->f.address, sizeof w->f.address) == 0 && listen(fd, 4) == 0);
    socklen_t length = sizeof w->f.address; CHECK(getsockname(fd, (struct sockaddr *)&w->f.address, &length) == 0);
    vireo_acceptor_t *listener = NULL; vireo_acceptor_options_t const ao = {4096};
    EXPECT(vireo_acceptor_create(&ao, &fd, &listener, NULL), VIREO_OK);
    EXPECT(vireo_tcp_server_adopt_listener(w->f.server, &listener, NULL), VIREO_OK);
    add_client(&w->f); EXPECT(vireo_tcp_server_bind_listener(w->f.server, true, NULL), VIREO_OK);
    vireo_tcp_server_admission_options_t const admission = {connection, flow};
    EXPECT(vireo_tcp_server_admission_configure(w->f.server, &admission, NULL), VIREO_OK);
    vireo_inflight_store_options_t const io = {8, 65536}; EXPECT(vireo_inflight_store_create(&io, &w->f.store), VIREO_OK);
    vireo_task_queue_options_t const tq = {task_capacity, 65536}; vireo_completion_queue_options_t const cq = {output_capacity, 65536};
    vireo_notifier_options_t const no = {4096}; vireo_thread_pool_options_t const po = {workers, 65536};
    EXPECT(vireo_task_queue_create(&tq, &w->tasks), VIREO_OK); EXPECT(vireo_task_queue_prepare_wait(w->tasks), VIREO_OK);
    EXPECT(vireo_completion_queue_create(&cq, &w->outputs), VIREO_OK); EXPECT(vireo_completion_queue_prepare_wait(w->outputs), VIREO_OK);
    EXPECT(vireo_notifier_create(&no, &w->notifier, NULL), VIREO_OK);
    EXPECT(vireo_notifier_server_register(w->f.server, w->notifier, &w->handle, NULL), VIREO_OK);
    w->worker.outputs = w->outputs; w->worker.notifier = w->notifier; atomic_init(&w->worker.published, 0);
    for (size_t i = 0; i < 9; ++i) atomic_init(&w->worker.seen[i], 0);
    CHECK(pthread_barrier_init(&w->worker.entered, NULL, 2) == 0 && pthread_barrier_init(&w->worker.release, NULL, 2) == 0);
    EXPECT(vireo_thread_pool_create(&po, &w->pool), VIREO_OK);
    vireo_thread_pool_configuration_t const config = {w->tasks, execute, &w->worker};
    EXPECT(vireo_thread_pool_configure(w->pool, &config, NULL), VIREO_OK);
    vireo_thread_pool_report_t report; EXPECT(vireo_thread_pool_start(w->pool, &report), VIREO_OK);
    EXPECT(vireo_thread_pool_enable_execution(w->pool, &report), VIREO_OK);
}
static vireo_protocol_header_t encode(uint8_t *wire, unsigned int tag, uint32_t sequence) {
    CHECK(tag >= 1 && tag <= 8);
    vireo_protocol_header_t h = {.command = tag == 2 ? VIREO_COMMAND_UPLOAD_STATUS : VIREO_COMMAND_NODE_STAT,
      .flags = tag == 2 ? VIREO_PROTOCOL_FLAG_LONG_COMMAND : 0, .body_len = 3, .sequence = sequence,
      .session_handle = 0x12345600U + tag, .task_handle = 0x99887700U + tag};
    wire[32] = (uint8_t)tag; wire[33] = 0; wire[34] = 0xA5;
    EXPECT(vireo_protocol_header_encode(&h, wire, 32), VIREO_OK);
    EXPECT(vireo_protocol_frame_crc32c_calculate(wire, 32, wire + 32, 3, &h.crc32c), VIREO_OK);
    EXPECT(vireo_protocol_header_encode(&h, wire, 32), VIREO_OK); return h;
}
static void load(world_t *w, uint8_t const *wire) {
    size_t sent = 0; while (sent < 35) { ssize_t n = send(w->f.peer, wire + sent, 35 - sent, MSG_NOSIGNAL); CHECK(n > 0); sent += (size_t)n; }
    vireo_connection_receive_budget_t const budget = {128, 8};
    for (size_t i = 0; i < LIMIT; ++i) {
        vireo_connection_receive_info_t info; EXPECT(vireo_tcp_server_client_receive(w->f.server, w->f.client, &budget, &info, NULL), VIREO_OK);
        uint8_t const *bytes; size_t size; EXPECT(vireo_tcp_server_client_read_peek(w->f.server, w->f.client, &bytes, &size, NULL), VIREO_OK);
        if (size == 35) { CHECK(!memcmp(bytes, wire, 35)); return; } CHECK(size < 35); sched_yield();
    }
    CHECK(false);
}
static vireo_result_t try_head(world_t *w, vireo_async_request_head_report_t *report) {
    vireo_task_t *remaining = NULL; errno = EDOM;
    vireo_result_t result = vireo_async_request_submit_read_head(w->f.server, w->f.client, w->f.store,
        w->pool, 64, 4096, 8, 9, UINT64_MAX, NULL, &w->pending, &remaining, report);
    CHECK(errno == EDOM);
    if (!report->submit_report.task_transferred) {
        CHECK(!report->submit_report.submit_report.record_retained && w->pending.frame_bytes == 0);
        EXPECT(vireo_task_destroy(&remaining), VIREO_OK);
    } else { CHECK(remaining == NULL && result == VIREO_OK && w->pending.frame_bytes == 0); }
    return result;
}
static void book(world_t *w, unsigned int tag, vireo_protocol_header_t h, vireo_async_request_head_report_t report) {
    CHECK(!w->entries[tag].valid && report.submit_report.task_transferred && report.consume_called && report.consume_result == VIREO_OK);
    vireo_task_metadata_t metadata = report.submit_report.metadata;
    CHECK(metadata.route.request_sequence == h.sequence && metadata.route.client_owner_id == w->f.client.pool_id &&
          metadata.route.client_slot_index == w->f.client.slot_index && metadata.route.client_generation == w->f.client.generation);
    w->entries[tag] = (entry_t){.valid = true, .metadata = metadata,
      .descriptor = {h.command, h.flags, h.session_handle, h.task_handle}};
    uint8_t const *bytes; size_t size; EXPECT(vireo_tcp_server_client_read_peek(w->f.server, w->f.client, &bytes, &size, NULL), VIREO_OK); CHECK(size == 0);
    EXPECT(vireo_tcp_server_client_flow_refresh(w->f.server, w->f.client, NULL), VIREO_OK);
}
static void submit_existing(world_t *w, unsigned int tag, vireo_protocol_header_t h) {
    for (size_t i = 0; i < LIMIT; ++i) {
        vireo_async_request_head_report_t report; vireo_result_t result = try_head(w, &report);
        if (report.submit_report.task_transferred) { book(w, tag, h, report); return; }
        CHECK(result == VIREO_RESULT_BUSY); sched_yield();
    }
    CHECK(false);
}
static void submit(world_t *w, unsigned int tag, uint32_t sequence) {
    uint8_t wire[35]; vireo_protocol_header_t h = encode(wire, tag, sequence); load(w, wire); submit_existing(w, tag, h); memset(wire, 255, sizeof wire);
}
static void published(world_t *w, unsigned int count) {
    for (size_t i = 0; i < LIMIT; ++i) { if (atomic_load_explicit(&w->worker.published, memory_order_acquire) >= count) return; sched_yield(); }
    CHECK(false);
}
static vireo_result_t sync_guard(vireo_connection_frame_view_t const *request, uint8_t *body,
    size_t capacity, vireo_tcp_server_reply_t *reply, void *context) {
    (void)request; (void)body; (void)capacity; (void)reply; (void)context;
    CHECK(false); return VIREO_RESULT_INTERNAL; /* 异步源必须先显式交接/consume，不能同步造响应。 */
}
static void serve(world_t *w) {
    uint8_t workspace[128]; vireo_tcp_server_turn_result_t turns[1]; vireo_connection_pool_lease_t clients[1] = {0};
    vireo_tcp_server_serve_options_t const options = {10, {128,128}, {{128,8},{2,256,256},{128,8}}, {1}, {1,4}};
    vireo_tcp_server_serve_info_t info;
    EXPECT(vireo_tcp_server_serve_once(w->f.server, &options, workspace, sizeof workspace, sync_guard, NULL,
        turns, 1, clients, 1, &info, NULL), VIREO_OK); CHECK(info.admission.admitted_count == 0);
}
static vireo_result_t resolve(void *context, vireo_completion_t const *completion,
    vireo_inflight_completion_match_t match, vireo_completion_response_descriptor_t *descriptor) {
    world_t *w = context; vireo_completion_info_t info; EXPECT(vireo_completion_inspect(completion, &info), VIREO_OK);
    CHECK(same(info.metadata.request, match.metadata));
    for (unsigned int tag = 1; tag <= 8; ++tag) if (w->entries[tag].valid && same(w->entries[tag].metadata, match.metadata)) {
        CHECK(w->resolve_count < 16); w->resolve_order[w->resolve_count++] = tag; ++w->entries[tag].resolves;
        if (w->fail_tag == tag) return VIREO_RESULT_IO;
        *descriptor = w->entries[tag].descriptor; return VIREO_OK;
    }
    CHECK(false); return VIREO_RESULT_NOT_FOUND;
}
static vireo_completion_response_dispatch_report_t dispatch(world_t *w, size_t items, vireo_result_t expected_result) {
    vireo_completion_response_dispatch_report_t report;
    EXPECT(vireo_completion_response_dispatch_ready(w->f.server, w->handle, w->notifier, w->f.store, w->outputs,
        items, 64, items * 64, w->scratch, sizeof w->scratch, resolve, w, &w->remaining, &report), expected_result);
    return report;
}
static vireo_completion_response_dispatch_report_t pump(world_t *w, size_t items, size_t finished) {
    for (size_t i = 0; i < 100; ++i) {
        serve(w); vireo_completion_response_dispatch_report_t report = dispatch(w, items, VIREO_OK);
        if (report.dispatch_report.dispatch_report.drain_report.finished == finished) { CHECK(report.dispatch_report.ready_taken); return report; }
        CHECK(!report.dispatch_report.ready_taken || report.dispatch_report.dispatch_report.drain_report.finished == 0);
    }
    CHECK(false); return (vireo_completion_response_dispatch_report_t){0};
}
static void flush(world_t *w) {
    for (size_t i = 0; i < 100; ++i) {
        vireo_tcp_server_client_info_t info; EXPECT(vireo_tcp_server_client_inspect(w->f.server, w->f.client, &info), VIREO_OK);
        if (info.connection_info.write_buffer.readable_size == 0) return;
        serve(w);
    }
    CHECK(false);
}
static void read_peer(world_t *w, uint8_t *bytes, size_t size) {
    size_t received = 0;
    for (size_t i = 0; received < size && i < 8; ++i) {
        struct pollfd p = {.fd = w->f.peer, .events = POLLIN}; CHECK(poll(&p, 1, 1000) == 1 && (p.revents & POLLIN));
        ssize_t n = recv(w->f.peer, bytes + received, size - received, MSG_DONTWAIT); CHECK(n > 0); received += (size_t)n;
    }
    CHECK(received == size);
}
static void no_bytes(world_t *w) {
    uint8_t byte; CHECK(recv(w->f.peer, &byte, 1, MSG_DONTWAIT) == -1 && (errno == EAGAIN || errno == EWOULDBLOCK));
}
static void wire_is(world_t *w, uint8_t const *wire, unsigned int tag) {
    entry_t const *entry = &w->entries[tag]; CHECK(entry->valid && !memcmp(wire, "VIRE", 4) && wire[4] == 1 && wire[5] == 32);
    vireo_protocol_header_t h; vireo_protocol_codec_issue_t issue;
    EXPECT(vireo_protocol_header_decode(wire, 35, &h, &issue), VIREO_OK);
    CHECK(h.command == entry->descriptor.command && h.flags == (VIREO_PROTOCOL_FLAG_RESPONSE | entry->descriptor.extra_flags) &&
      h.status == VIREO_STATUS_OK && h.sequence == entry->metadata.route.request_sequence && h.body_len == 3 &&
      h.session_handle == entry->descriptor.session_handle && h.task_handle == entry->descriptor.task_handle && !memcmp(wire + 32, expected[tag], 3));
    EXPECT(vireo_protocol_response_header_validate(&h, &issue), VIREO_OK);
    EXPECT(vireo_protocol_frame_crc32c_verify(wire, 32, wire + 32, 3, &issue), VIREO_OK);
}
static void receive_response(world_t *w, unsigned int tag) {
    flush(w); uint8_t wire[35]; read_peer(w, wire, sizeof wire); wire_is(w, wire, tag); no_bytes(w);
}
static void counts(world_t *w, size_t records, size_t queued) {
    vireo_inflight_store_info_t info; EXPECT(vireo_inflight_store_inspect(w->f.store, &info), VIREO_OK); CHECK(info.count == records);
    vireo_completion_queue_info_t qi; bool observed = false;
    for (size_t i = 0; i < LIMIT; ++i) {
        vireo_result_t result = vireo_completion_queue_inspect(w->outputs, &qi);
        if (result == VIREO_OK) { observed = true; break; } CHECK(result == VIREO_RESULT_BUSY); sched_yield();
    }
    CHECK(observed && qi.count == queued);
}
static void cleanup(world_t *w) {
    CHECK(w->remaining == NULL && w->pending.frame_bytes == 0); counts(w, 0, 0);
    vireo_task_queue_close_report_t close_report; bool closed = false;
    for (size_t i = 0; i < LIMIT; ++i) {
        vireo_result_t result = vireo_task_queue_close(w->tasks, VIREO_TASK_QUEUE_DRAIN, &close_report);
        if (result == VIREO_OK) { closed = true; break; } CHECK(result == VIREO_RESULT_BUSY); sched_yield();
    }
    CHECK(closed); vireo_thread_pool_report_t report; vireo_result_t joined = VIREO_RESULT_BUSY;
    for (size_t i = 0; i < LIMIT && joined == VIREO_RESULT_BUSY; ++i) { joined = vireo_thread_pool_stop_and_join(w->pool, &report); if (joined == VIREO_RESULT_BUSY) sched_yield(); }
    CHECK(joined == VIREO_OK && report.created_count == report.joined_count);
    for (unsigned int tag = 1; tag <= 8; ++tag) if (w->entries[tag].valid) {
        CHECK(atomic_load(&w->worker.seen[tag]) == 1 && w->worker.reports[tag].completion_transferred &&
              same(w->worker.reports[tag].request_metadata, w->entries[tag].metadata));
    }
    /* 成功join后无条件最后drain，不把hint0或计数0当producer结束。 */
    uint64_t hints; EXPECT(vireo_notifier_consume(w->notifier, &hints, NULL), VIREO_OK);
    vireo_completion_queue_close_report_t cr; EXPECT(vireo_completion_queue_close(w->outputs, &cr), VIREO_OK);
    vireo_completion_t *owner = NULL; vireo_completion_queue_transfer_report_t qr;
    EXPECT(vireo_completion_queue_try_pop(w->outputs, &owner, &qr), VIREO_RESULT_CANCELLED); CHECK(!qr.transferred && owner == NULL);
    EXPECT(vireo_thread_pool_destroy(&w->pool), VIREO_OK); EXPECT(vireo_task_queue_destroy(&w->tasks), VIREO_OK);
    CHECK(pthread_barrier_destroy(&w->worker.entered) == 0 && pthread_barrier_destroy(&w->worker.release) == 0);
    EXPECT(vireo_notifier_server_unregister(w->f.server, &w->handle, NULL), VIREO_OK);
    EXPECT(vireo_completion_queue_destroy(&w->outputs), VIREO_OK); EXPECT(vireo_notifier_destroy(&w->notifier, NULL), VIREO_OK);
    EXPECT(vireo_inflight_store_destroy(&w->f.store), VIREO_OK);
    EXPECT(vireo_tcp_server_release_client(w->f.server, &w->f.client, NULL), VIREO_OK); CHECK(close(w->f.peer) == 0);
    EXPECT(vireo_tcp_server_destroy(&w->f.server, NULL), VIREO_OK);
}
static void ready(world_t *w) {
    for (size_t i = 0; i < 100; ++i) {
        serve(w); vireo_tcp_server_info_t info; EXPECT(vireo_tcp_server_inspect(w->f.server, &info), VIREO_OK);
        if (info.auxiliary_pending_events != 0) { CHECK(info.auxiliary_pending_events == VIREO_EPOLL_EVENT_READ); return; }
    }
    CHECK(false);
}
static vireo_inflight_completion_consume_report_t consumed(vireo_completion_response_dispatch_report_t p) {
    return p.dispatch_report.dispatch_report.drain_report.consume_report;
}
static void recover(world_t *w, vireo_completion_response_dispatch_report_t p, unsigned int tag) {
    CHECK(w->remaining && consumed(p).record_consumed && !p.last_response_report.enqueued);
    vireo_completion_response_report_t report;
    EXPECT(vireo_completion_response_enqueue(w->f.server, w->remaining, consumed(p).match,
      w->entries[tag].descriptor, 64, w->scratch, sizeof w->scratch, &report), VIREO_OK);
    CHECK(report.enqueued && report.refresh_called); EXPECT(vireo_completion_destroy(&w->remaining), VIREO_OK);
    CHECK(w->entries[tag].resolves == 1); receive_response(w, tag);
}
static void single_roundtrip(void) {
    world_t w; prepare(&w, 1, 1, 1, false); submit(&w, 1, 101); published(&w, 1);
    vireo_completion_response_dispatch_report_t p = pump(&w, 8, 1);
    CHECK(p.enqueued_responses == 1 && p.enqueued_bytes == 35 && w.entries[1].resolves == 1 && w.remaining == NULL);
    receive_response(&w, 1); counts(&w, 0, 0); cleanup(&w);
}
static void out_of_order(void) {
    world_t w; prepare(&w, 2, 2, 1, true); submit(&w, 1, 101); meet(&w.worker.entered);
    submit(&w, 2, 102); published(&w, 1);
    vireo_completion_response_dispatch_report_t p = pump(&w, 1, 1);
    CHECK(p.enqueued_responses == 1 && w.resolve_order[0] == 2); receive_response(&w, 2);
    counts(&w, 1, 0); meet(&w.worker.release); published(&w, 2);
    p = pump(&w, 1, 1); CHECK(p.enqueued_responses == 1 && w.resolve_order[1] == 1);
    receive_response(&w, 1); counts(&w, 0, 0); cleanup(&w);
}
static void budget_reschedules(void) {
    world_t w; prepare(&w, 2, 4, 4, false);
    for (unsigned int tag = 1; tag <= 3; ++tag) submit(&w, tag, 100U + tag);
    published(&w, 3); counts(&w, 3, 3);
    for (size_t turn = 0; turn < 3; ++turn) {
        vireo_completion_response_dispatch_report_t p = pump(&w, 1, 1);
        CHECK(p.effective_max_items == 1 && p.reserved_frame_bytes == 64 && p.enqueued_responses == 1 &&
          p.dispatch_report.dispatch_report.drain_report.pop_calls == 1 && p.dispatch_report.dispatch_report.renotify_called);
        CHECK(w.resolve_count == turn + 1); receive_response(&w, w.resolve_order[turn]); counts(&w, 2 - turn, 2 - turn);
    }
    /* 三个预算轮均真实取到LT READ；没有由测试手工补notify。 */
    cleanup(&w);
}
static void client_reused(void) {
    world_t w; prepare(&w, 1, 2, 2, true); submit(&w, 1, 101); meet(&w.worker.entered);
    vireo_connection_pool_lease_t const old = w.f.client;
    EXPECT(vireo_tcp_server_release_client(w.f.server, &w.f.client, NULL), VIREO_OK);
    CHECK(close(w.f.peer) == 0); w.f.peer = -1; add_client(&w.f);
    CHECK(w.f.client.pool_id == old.pool_id && w.f.client.slot_index == old.slot_index && w.f.client.generation != old.generation);
    meet(&w.worker.release); published(&w, 1);
    vireo_completion_response_dispatch_report_t p = pump(&w, 1, 1);
    CHECK(consumed(p).disposition == VIREO_INFLIGHT_COMPLETION_CLIENT_GONE && p.resolve_calls == 0 && p.enqueued_responses == 0);
    no_bytes(&w); counts(&w, 0, 0);
    /* 同slot和同sequence不足以接受旧结果，新generation/instance必须独立。 */
    submit(&w, 2, 101); published(&w, 2); p = pump(&w, 1, 1);
    CHECK(p.enqueued_responses == 1 && w.entries[1].resolves == 0 && w.entries[2].resolves == 1 &&
      w.entries[1].metadata.request_instance_id != w.entries[2].metadata.request_instance_id);
    receive_response(&w, 2); cleanup(&w);
}
static void request_ended(void) {
    world_t w; prepare(&w, 1, 1, 1, true); submit(&w, 1, 101); meet(&w.worker.entered);
    vireo_task_metadata_t snapshot; EXPECT(vireo_inflight_store_take(w.f.store, w.entries[1].metadata, &snapshot, NULL), VIREO_OK);
    CHECK(same(snapshot, w.entries[1].metadata)); meet(&w.worker.release); published(&w, 1);
    vireo_completion_response_dispatch_report_t p = pump(&w, 1, 1);
    CHECK(consumed(p).disposition == VIREO_INFLIGHT_COMPLETION_REQUEST_GONE && p.resolve_calls == 0 && !w.remaining);
    no_bytes(&w); cleanup(&w);
}
static void task_full_keeps_source(void) {
    world_t w; prepare(&w, 1, 1, 3, true); submit(&w, 1, 101); meet(&w.worker.entered); submit(&w, 2, 102);
    vireo_task_queue_info_t qi; EXPECT(vireo_task_queue_inspect(w.tasks, &qi), VIREO_OK); CHECK(qi.count == 1);
    uint8_t wire[35]; vireo_protocol_header_t h = encode(wire, 3, 103); load(&w, wire);
    vireo_async_request_head_report_t report; CHECK(try_head(&w, &report) == VIREO_RESULT_BUSY &&
      !report.submit_report.task_transferred && !report.consume_called && w.pending.frame_bytes == 0);
    uint8_t const *bytes; size_t size; EXPECT(vireo_tcp_server_client_read_peek(w.f.server, w.f.client, &bytes, &size, NULL), VIREO_OK);
    CHECK(size == sizeof wire && !memcmp(bytes, wire, size)); counts(&w, 2, 0);
    /* 未转移拒绝只保源；不能让同步serve先处理该源。worker先腾task槽，再同源重试。 */
    meet(&w.worker.release); published(&w, 2); submit_existing(&w, 3, h); published(&w, 3);
    vireo_completion_response_dispatch_report_t p = pump(&w, 3, 3); CHECK(p.enqueued_responses == 3 && p.enqueued_bytes == 105);
    flush(&w); uint8_t received[105]; read_peer(&w, received, sizeof received);
    CHECK(w.resolve_count == 3);
    for (size_t i = 0; i < 3; ++i) wire_is(&w, received + i * 35, w.resolve_order[i]);
    no_bytes(&w); cleanup(&w);
}
static void response_full_recovery(void) {
    world_t w; prepare(&w, 1, 1, 1, false); submit(&w, 1, 101); published(&w, 1); ready(&w);
    /* 先捕获真实辅助READ，再填发送区；中间不serve，不让WRITE就绪提前腾空。 */
    uint8_t filler[128] = {0}; vireo_protocol_header_t h = {.command = VIREO_COMMAND_NODE_STAT,
      .flags = VIREO_PROTOCOL_FLAG_RESPONSE, .status = VIREO_STATUS_OK, .body_len = 96, .sequence = 999};
    EXPECT(vireo_protocol_header_encode(&h, filler, 32), VIREO_OK);
    EXPECT(vireo_protocol_frame_crc32c_calculate(filler, 32, filler + 32, 96, &h.crc32c), VIREO_OK);
    EXPECT(vireo_protocol_header_encode(&h, filler, 32), VIREO_OK);
    EXPECT(vireo_tcp_server_client_write_enqueue(w.f.server, w.f.client, filler, sizeof filler, NULL), VIREO_OK);
    EXPECT(vireo_tcp_server_client_flow_refresh(w.f.server, w.f.client, NULL), VIREO_OK);
    vireo_completion_response_dispatch_report_t p = dispatch(&w, 1, VIREO_RESULT_BUSY);
    CHECK(w.remaining && consumed(p).record_consumed && p.last_response_called && !p.last_response_report.enqueued && p.enqueued_bytes == 0);
    counts(&w, 0, 0);
    vireo_connection_send_budget_t const sb = {128, 8}; vireo_connection_send_info_t info;
    EXPECT(vireo_tcp_server_client_send(w.f.server, w.f.client, &sb, &info, NULL), VIREO_OK); CHECK(info.sent_bytes == sizeof filler);
    EXPECT(vireo_tcp_server_client_flow_refresh(w.f.server, w.f.client, NULL), VIREO_OK);
    uint8_t received[128]; read_peer(&w, received, sizeof received); CHECK(!memcmp(received, filler, sizeof filler));
    recover(&w, p, 1); cleanup(&w);
}
static void description_error_recovery(void) {
    world_t w; prepare(&w, 1, 1, 1, false); submit(&w, 1, 101); published(&w, 1); ready(&w); w.fail_tag = 1;
    vireo_completion_response_dispatch_report_t p = dispatch(&w, 1, VIREO_RESULT_IO);
    CHECK(w.remaining && consumed(p).record_consumed && !p.last_response_called && p.enqueued_responses == 0 && p.last_resolve_result == VIREO_RESULT_IO);
    no_bytes(&w); counts(&w, 0, 0); w.fail_tag = 0; recover(&w, p, 1); cleanup(&w);
}
static size_t fds(void) {
    DIR *dir = opendir("/proc/self/fd"); CHECK(dir); size_t count = 0; struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) if (entry->d_name[0] != '.') ++count;
    CHECK(closedir(dir) == 0); return count;
}
int main(void) {
    int old_state; CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &old_state) == 0);
    void (*const cases[])(void) = {single_roundtrip, out_of_order, budget_reschedules, client_reused,
      request_ended, task_full_keeps_source, response_full_recovery, description_error_recovery};
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; ++i) { size_t const before = fds(); cases[i](); CHECK(fds() == before); }
    puts("async request roundtrip: 8 groups passed"); return 0;
}
