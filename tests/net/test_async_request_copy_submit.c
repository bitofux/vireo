/*
 * PROJECT : VIREO
 * FILE    : test_async_request_copy_submit.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-13
 * BRIEF   : 完整wire副本、真实worker交接与源未消费、独立失败报告
 */
#define _GNU_SOURCE
#include "async_request_internal.h"
#include <arpa/inet.h>
#include <errno.h>
#include <dirent.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define CHECK(expr) do { if (!(expr)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #expr); exit(1); } } while (0)
_Static_assert(VIREO_INFLIGHT_SUBMIT_NONE == 0 && VIREO_INFLIGHT_SUBMIT_INSPECT_TASK == 1 &&
 VIREO_INFLIGHT_SUBMIT_REGISTER_REQUEST == 2 && VIREO_INFLIGHT_SUBMIT_SUBMIT_TASK == 3, "submit stages");
_Static_assert(VIREO_INFLIGHT_ISSUE_INSTANCE == 7 && VIREO_THREAD_POOL_SUBMIT_STAGE_SUBMIT_QUEUE == 2,
 "old stages held");

/** 测试独占的真实 loopback 资源；只通过公开合同访问。 */
typedef struct fixture {
    vireo_tcp_server_t *server;           /**< 本客户及 listener 的资源根。 */
    vireo_tcp_server_t *other_server;     /**< 独立拥有域，用于跨域拒绝。 */
    vireo_connection_pool_lease_t client; /**< 当前客户值，归还后清零。 */
    int peer;                            /**< caller 的 TCP 对端，-1 为空。 */
    int listener_fd;                     /**< 构造期间 owner fd，转移后 -1。 */
    vireo_acceptor_t *listener;           /**< 构造期 owner，收纳后 NULL。 */
    struct sockaddr_in address;          /**< loopback 数值端点，供重接客户。 */
} fixture_t;

static bool add_client(fixture_t *f) {
    CHECK(f->peer == -1 && f->client.pool_id == 0);
    f->peer = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    CHECK(f->peer >= 0);
    CHECK(connect(f->peer, (struct sockaddr const *)&f->address, sizeof f->address) == 0);
    vireo_connection_options_t const options = {64, 64, 128};
    vireo_tcp_server_admit_budget_t const budget = {1, 1};
    vireo_tcp_server_admit_info_t info;
    CHECK(vireo_tcp_server_admit_batch(f->server, &options, &budget, &f->client, 1,
                                       &info, NULL) == VIREO_OK);
    CHECK(info.admitted_count == 1 && info.accepted_count == 1);
    return true;
}

static bool setup_capacity(fixture_t *f, size_t capacity) {
    *f = (fixture_t){.peer = -1, .listener_fd = -1};
    vireo_tcp_server_options_t const options = {capacity, 2, VIREO_TCP_SERVER_MAX_MEMORY, 256};
    CHECK(vireo_tcp_server_create(&options, &f->server, NULL) == VIREO_OK);
    CHECK(vireo_tcp_server_create(&options, &f->other_server, NULL) == VIREO_OK);
    f->listener_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    CHECK(f->listener_fd >= 0);
    f->address.sin_family = AF_INET;
    f->address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(bind(f->listener_fd, (struct sockaddr const *)&f->address, sizeof f->address) == 0);
    CHECK(listen(f->listener_fd, 4) == 0);
    socklen_t length = sizeof f->address;
    CHECK(getsockname(f->listener_fd, (struct sockaddr *)&f->address, &length) == 0);
    CHECK(length == sizeof f->address);
    vireo_acceptor_options_t const listener_options = {VIREO_ACCEPTOR_MAX_MEMORY};
    CHECK(vireo_acceptor_create(&listener_options, &f->listener_fd, &f->listener, NULL) == VIREO_OK);
    CHECK(vireo_tcp_server_adopt_listener(f->server, &f->listener, NULL) == VIREO_OK);
    return add_client(f);
}

static bool setup(fixture_t *f) {
    return setup_capacity(f, 1);
}

static bool release_client(fixture_t *f) {
    CHECK(vireo_tcp_server_release_client(f->server, &f->client, NULL) == VIREO_OK);
    CHECK(f->client.pool_id == 0 && f->client.slot_index == 0 && f->client.generation == 0);
    CHECK(close(f->peer) == 0);
    f->peer = -1;
    return true;
}

static bool cleanup(fixture_t *f) {
    if (f->client.pool_id != 0) CHECK(release_client(f));
    if (f->peer >= 0) CHECK(close(f->peer) == 0);
    if (f->listener_fd >= 0) CHECK(close(f->listener_fd) == 0);
    CHECK(vireo_acceptor_destroy(&f->listener, NULL) == VIREO_OK);
    CHECK(vireo_tcp_server_destroy(&f->server, NULL) == VIREO_OK);
    CHECK(vireo_tcp_server_destroy(&f->other_server, NULL) == VIREO_OK);
    CHECK(f->server == NULL && f->other_server == NULL);
    return true;
}

#define EXPECT(call, result) do { errno = EDOM; CHECK((call) == (result)); CHECK(errno == EDOM); } while (0)

/** 单 worker 独立账本，不借用任何网络对象。 */
typedef struct runner {
    vireo_thread_pool_t *pool; /**< manager 唯一拥有，join 后销毁。 */
    vireo_task_queue_t *queue; /**< 专用 queue owner，池借至销毁。 */
    pthread_barrier_t entered; /**< 首项已领取后与 manager 会合。 */
    pthread_barrier_t released; /**< manager 消费/改写源后放行读取副本。 */
    bool hold_first; /**< 启动前固定，sequence1在读payload前停驻。 */
    atomic_uint calls; /**< 实际执行条数，初0。 */
    atomic_uint cancelled; /**< 观察到取消条数，初0。 */
    uint8_t expected[16][64]; /**< 每seq独立预期wire，提交前写，由queue发布。 */
    size_t expected_sizes[16]; /**< 对应有效字节，最大64。 */
    vireo_task_metadata_t seen[16]; /**< worker写，manager仅join后读。 */
} runner_t;
static void meet(pthread_barrier_t *b) {
    int const result = pthread_barrier_wait(b); CHECK(result == 0 || result == PTHREAD_BARRIER_SERIAL_THREAD);
}
static vireo_result_t execute(void *context, vireo_task_t const *task) {
    runner_t *r = context; vireo_task_info_t info;
    CHECK(vireo_task_inspect(task, &info) == VIREO_OK);
    uint32_t const seq = info.metadata.route.request_sequence;
    CHECK(seq > 0 && seq < 16 && info.metadata.operation == 9);
    if (r->hold_first && seq == 1) { meet(&r->entered); meet(&r->released); }
    vireo_task_payload_view_t view; CHECK(vireo_task_borrow_payload(task, &view) == VIREO_OK);
    CHECK(view.size == r->expected_sizes[seq] && !memcmp(view.data, r->expected[seq], view.size));
    vireo_protocol_header_t h; vireo_protocol_codec_issue_t issue;
    CHECK(vireo_protocol_header_decode(view.data, view.size, &h, &issue) == VIREO_OK);
    CHECK(vireo_protocol_request_header_validate(&h, &issue) == VIREO_OK);
    CHECK(vireo_protocol_frame_crc32c_verify(view.data, 32, view.data + 32, view.size - 32, &issue) == VIREO_OK);
    CHECK(h.sequence == seq && h.command == VIREO_COMMAND_NODE_STAT && h.session_handle == 0x10203040 && h.task_handle == UINT32_MAX);
    bool requested; CHECK(vireo_task_is_cancel_requested(task, &requested) == VIREO_OK);
    r->seen[seq] = info.metadata;
    if (requested) (void)atomic_fetch_add(&r->cancelled, 1);
    (void)atomic_fetch_add(&r->calls, 1); errno = EIO; return VIREO_OK;
}
static void prepare_runner(runner_t *r, bool hold) {
    *r = (runner_t){.hold_first = hold}; atomic_init(&r->calls, 0); atomic_init(&r->cancelled, 0);
    CHECK(pthread_barrier_init(&r->entered, NULL, 2) == 0 && pthread_barrier_init(&r->released, NULL, 2) == 0);
    vireo_task_queue_options_t const qo = {1, 65536}; vireo_thread_pool_options_t const po = {1, 65536};
    EXPECT(vireo_task_queue_create(&qo, &r->queue), VIREO_OK);
    EXPECT(vireo_task_queue_prepare_wait(r->queue), VIREO_OK);
    EXPECT(vireo_thread_pool_create(&po, &r->pool), VIREO_OK);
    vireo_thread_pool_configuration_t const config = {r->queue, execute, r};
    EXPECT(vireo_thread_pool_configure(r->pool, &config, NULL), VIREO_OK);
}
static void start_runner(runner_t *r) {
    vireo_thread_pool_report_t p; EXPECT(vireo_thread_pool_start(r->pool, &p), VIREO_OK);
    EXPECT(vireo_thread_pool_enable_execution(r->pool, &p), VIREO_OK);
}
static void end_runner(runner_t *r, bool started) {
    if (started) {
        vireo_task_queue_close_report_t close; bool done = false;
        /* 仅caller测试管理的有限竞争重试，产品入口不重试。 */
        for (size_t i = 0; i < 100000; ++i) {
            vireo_result_t result = vireo_task_queue_close(r->queue, VIREO_TASK_QUEUE_DRAIN, &close);
            if (result == VIREO_OK) { done = true; break; }
            CHECK(result == VIREO_RESULT_BUSY && !close.changed); sched_yield();
        }
        CHECK(done); vireo_thread_pool_report_t report;
        vireo_result_t result = VIREO_RESULT_BUSY;
        for (size_t i = 0; i < 100000 && result == VIREO_RESULT_BUSY; ++i) {
            result = vireo_thread_pool_stop_and_join(r->pool, &report);
            if (result == VIREO_RESULT_BUSY) sched_yield();
        }
        CHECK(result == VIREO_OK);
    }
    EXPECT(vireo_thread_pool_destroy(&r->pool), VIREO_OK);
    EXPECT(vireo_task_queue_destroy(&r->queue), VIREO_OK);
    CHECK(pthread_barrier_destroy(&r->entered) == 0 && pthread_barrier_destroy(&r->released) == 0);
}

/** 本组拥有的网络/队列资源及恢复值，不向worker传此对象。 */
typedef struct world {
    fixture_t f; /**< 真实网络owner，仅manager使用。 */
    runner_t r; /**< 独立worker账本/owner。 */
    vireo_inflight_store_t *store; /**< 容量4，显式清完历史记录后销毁。 */
    vireo_task_t *remaining; /**< 本调用交回的唯一新task owner，初NULL。 */
    uint8_t wire[64]; /**< 本组编码的原字节值，不是网络借用。 */
    size_t wire_size; /**< 实际单帧长度，32..64。 */
    uint8_t const *input; /**< 原public read_peek短借，receive/consume后失效。 */
    size_t input_size; /**< 当前public read_peek字节数。 */
    vireo_task_metadata_t history[32]; /**< 本组已发号元数据值，供显式take清理。 */
    size_t histories; /**< 有效history前缀，最多32。 */
    bool started; /**< manager是否成功启动/放行过pool。 */
} world_t;
static size_t fds(void) {
    DIR *d = opendir("/proc/self/fd"); CHECK(d); size_t n = 0; struct dirent *ent;
    while ((ent = readdir(d)) != NULL) if (ent->d_name[0] != '.') ++n;
    CHECK(closedir(d) == 0); return n;
}
static void make_wire(uint8_t *wire, uint32_t sequence, size_t body_size) {
    CHECK(body_size <= 32);
    vireo_protocol_header_t h = {.command = VIREO_COMMAND_NODE_STAT, .body_len = (uint32_t)body_size,
        .sequence = sequence, .session_handle = 0x10203040, .task_handle = UINT32_MAX};
    for (size_t i = 0; i < body_size; ++i) wire[32 + i] = (uint8_t)(sequence + (uint32_t)i);
    EXPECT(vireo_protocol_header_encode(&h, wire, 32), VIREO_OK);
    EXPECT(vireo_protocol_frame_crc32c_calculate(wire, 32, wire + 32, body_size, &h.crc32c), VIREO_OK);
    EXPECT(vireo_protocol_header_encode(&h, wire, 32), VIREO_OK);
}
static void load(world_t *w, uint32_t sequence, size_t body_size) {
    make_wire(w->wire, sequence, body_size); w->wire_size = 32 + body_size;
    size_t sent = 0;
    while (sent < w->wire_size) {
        ssize_t n = send(w->f.peer, w->wire + sent, w->wire_size - sent, MSG_NOSIGNAL); CHECK(n > 0); sent += (size_t)n;
    }
    vireo_connection_receive_budget_t const rb = {64, 8};
    bool got = false;
    for (size_t attempt = 0; attempt < 10000; ++attempt) {
        vireo_connection_receive_info_t info;
        EXPECT(vireo_tcp_server_client_receive(w->f.server, w->f.client, &rb, &info, NULL), VIREO_OK);
        EXPECT(vireo_tcp_server_client_read_peek(w->f.server, w->f.client, &w->input, &w->input_size, NULL), VIREO_OK);
        if (w->input_size == w->wire_size) { got = true; break; }
        CHECK(w->input_size < w->wire_size); sched_yield();
    }
    CHECK(got && !memcmp(w->input, w->wire, w->wire_size));
    vireo_connection_frame_options_t const fo = {VIREO_CONNECTION_FRAME_REQUEST, 64};
    vireo_connection_frame_budget_t const fb = {1, 64}; vireo_connection_frame_view_t frame;
    vireo_connection_frame_info_t info;
    EXPECT(vireo_tcp_server_client_frames_peek(w->f.server, w->f.client, &fo, &fb, &frame, 1, &info, NULL), VIREO_OK);
    CHECK(info.frame_count == 1 && frame.wire_size == w->wire_size && frame.header.sequence == sequence);
    if (sequence < 16) { memcpy(w->r.expected[sequence], w->wire, w->wire_size); w->r.expected_sizes[sequence] = w->wire_size; }
}
static void consume_source(world_t *w) {
    EXPECT(vireo_tcp_server_client_read_consume(w->f.server, w->f.client, w->input_size, NULL), VIREO_OK);
    w->input = NULL; w->input_size = 0;
}
static void world_setup(world_t *w, bool hold) {
    *w = (world_t){0}; CHECK(setup(&w->f)); prepare_runner(&w->r, hold);
    vireo_inflight_store_options_t const so = {4, 65536};
    EXPECT(vireo_inflight_store_create(&so, &w->store), VIREO_OK); load(w, 1, 3);
}
static void remember(world_t *w, vireo_task_metadata_t metadata) {
    CHECK(w->histories < 32); w->history[w->histories++] = metadata;
}
static void count(world_t *w, size_t n) {
    vireo_inflight_store_info_t info; EXPECT(vireo_inflight_store_inspect(w->store, &info), VIREO_OK); CHECK(info.count == n);
}
static void world_cleanup(world_t *w) {
    EXPECT(vireo_task_destroy(&w->remaining), VIREO_OK);
    end_runner(&w->r, w->started);
    for (size_t i = 0; i < w->histories; ++i) {
        vireo_task_metadata_t old;
        vireo_result_t result = vireo_inflight_store_take(w->store, w->history[i], &old, NULL);
        CHECK(result == VIREO_OK || result == VIREO_RESULT_NOT_FOUND);
    }
    count(w, 0); EXPECT(vireo_inflight_store_destroy(&w->store), VIREO_OK); CHECK(cleanup(&w->f));
}
static vireo_async_request_report_t call(world_t *w, uint8_t const *data, size_t size, size_t cap,
    size_t budget, size_t limit, vireo_task_cancel_t *cancel, vireo_result_t result) {
    vireo_async_request_report_t p; memset(&p, 0xa5, sizeof p);
    EXPECT(vireo_async_request_copy_try_submit(w->f.server, w->f.client, w->store, w->r.pool,
        data, size, cap, budget, limit, 9, UINT64_MAX, cancel, &w->remaining, &p), result);
    if (p.metadata_created) remember(w, p.metadata);
    return p;
}
static vireo_async_request_report_t ordinary(world_t *w, vireo_result_t result) {
    return call(w, w->input, w->input_size, 64, 4096, 4, NULL, result);
}
static void unchanged_source(world_t *w) {
    uint8_t const *p; size_t size;
    EXPECT(vireo_tcp_server_client_read_peek(w->f.server, w->f.client, &p, &size, NULL), VIREO_OK);
    CHECK(p == w->input && size == w->input_size && !memcmp(p, w->wire, size));
}
static void payload_is(world_t *w) {
    vireo_task_payload_view_t view; EXPECT(vireo_task_borrow_payload(w->remaining, &view), VIREO_OK);
    CHECK(view.size == w->wire_size && view.data != w->input && !memcmp(view.data, w->wire, view.size));
}
static vireo_async_request_report_t submit_accept(world_t *w, vireo_task_cancel_t *cancel) {
    vireo_async_request_report_t p;
    errno = EDOM;
    vireo_result_t result = vireo_async_request_copy_try_submit(w->f.server, w->f.client, w->store,
        w->r.pool, w->input, w->input_size, 64, 4096, 4, 9, UINT64_MAX, cancel, &w->remaining, &p);
    CHECK(errno == EDOM && (result == VIREO_OK || result == VIREO_RESULT_BUSY));
    CHECK(p.task_created && p.input_validated && p.metadata_created); remember(w, p.metadata);
    if (result == VIREO_RESULT_BUSY) {
        CHECK(!p.task_transferred && p.task_retained && p.submit_report.rollback_called &&
            p.submit_report.rollback_result == VIREO_OK);
        /* 本组caller恢复同一新task，不重新构造/发号，原p保初始真实快照不篡改。 */
        for (size_t i = 0; i < 100000 && result == VIREO_RESULT_BUSY; ++i) {
            vireo_inflight_submit_report_t retry;
            result = vireo_inflight_store_try_submit(w->store, w->f.server, w->r.pool, 4, &w->remaining, &retry);
            if (result == VIREO_RESULT_BUSY) { CHECK(!retry.pool_report.queue_report.transferred); sched_yield(); }
        }
        CHECK(result == VIREO_OK);
    }
    CHECK(w->remaining == NULL); return p;
}

static void network_copy_after_consume(void) {
    world_t w; world_setup(&w, true); start_runner(&w.r); w.started = true;
    vireo_async_request_report_t const p = submit_accept(&w, NULL); meet(&w.r.entered);
    CHECK(p.frame_bytes == 35 && p.metadata.route.request_sequence == 1 && p.metadata.operation == 9 &&
        p.metadata.deadline_ns == UINT64_MAX); unchanged_source(&w); count(&w, 1);
    consume_source(&w); load(&w, 2, 16); meet(&w.r.released);
    end_runner(&w.r, true); w.started = false;
    CHECK(atomic_load(&w.r.calls) == 1 && w.r.seen[1].request_instance_id == p.metadata.request_instance_id);
    /* 已销毁runner不能再由world_cleanup重复销毁。 */
    for (size_t i = 0; i < w.histories; ++i) { vireo_task_metadata_t old;
        EXPECT(vireo_inflight_store_take(w.store, w.history[i], &old, NULL), VIREO_OK); }
    EXPECT(vireo_inflight_store_destroy(&w.store), VIREO_OK); CHECK(cleanup(&w.f));
}
static void empty_full_frame(void) {
    world_t w; world_setup(&w, false); consume_source(&w); load(&w, 1, 0);
    vireo_async_request_report_t const p = ordinary(&w, VIREO_RESULT_NOT_FOUND);
    CHECK(p.input_validated && p.frame_bytes == 32 && p.task_created && p.task_retained && !p.task_transferred &&
        p.submit_report.rollback_called && p.submit_report.rollback_result == VIREO_OK);
    payload_is(&w); unchanged_source(&w); count(&w, 0); world_cleanup(&w);
}
static void unstarted_refund_and_copy(void) {
    world_t w; world_setup(&w, false);
    vireo_async_request_report_t const p = ordinary(&w, VIREO_RESULT_NOT_FOUND);
    CHECK(p.stage == VIREO_ASYNC_REQUEST_SUBMIT && p.metadata_created && p.task_created && p.submit_called &&
        p.task_retained && p.submit_report.registration_committed && !p.submit_report.record_retained);
    payload_is(&w); unchanged_source(&w);
    consume_source(&w); load(&w, 2, 16);
    vireo_task_payload_view_t view; EXPECT(vireo_task_borrow_payload(w.remaining, &view), VIREO_OK);
    CHECK(view.size == 35 && !memcmp(view.data, w.r.expected[1], 35)); world_cleanup(&w);
}
static void allocation_boundaries(void) {
    world_t w; world_setup(&w, false);
    vireo_async_request_report_t p = call(&w, w.input, w.input_size, 64, 1, 4, NULL, VIREO_RESULT_RANGE);
    CHECK(p.input_validated && p.metadata_created && !p.task_created && !p.submit_called && !w.remaining &&
        p.stage == VIREO_ASYNC_REQUEST_CREATE_TASK); count(&w, 0); unchanged_source(&w);
    uint64_t old_id = p.metadata.request_instance_id;
    p = call(&w, w.input, w.input_size, VIREO_ASYNC_REQUEST_MAX_FRAME_BYTES, 67108865, 4, NULL, VIREO_RESULT_RANGE);
    CHECK(p.metadata_created && p.metadata.request_instance_id > old_id && !p.task_created && !w.remaining);
    p = call(&w, w.input, w.input_size, VIREO_ASYNC_REQUEST_MAX_FRAME_BYTES, 67108864, 4, NULL, VIREO_RESULT_NOT_FOUND);
    CHECK(p.task_retained); payload_is(&w);
    EXPECT(vireo_task_destroy(&w.remaining), VIREO_OK);
    EXPECT(vireo_async_request_copy_try_submit(w.f.server, w.f.client, w.store, w.r.pool,
        w.input, w.input_size, 64, 4096, 4, 9, 0, NULL, &w.remaining, &p), VIREO_RESULT_NOT_FOUND);
    remember(&w, p.metadata); CHECK(p.metadata_created && p.metadata.deadline_ns == 0 && p.task_retained);
    world_cleanup(&w);
}
static void corrupt_frames(void) {
    world_t w; world_setup(&w, false); uint8_t bad[64];
    size_t const offsets[] = {0, 4, 5, 12, 28, 32};
    vireo_protocol_codec_issue_t const expected[] = {VIREO_PROTOCOL_CODEC_ISSUE_INVALID_MAGIC,
        VIREO_PROTOCOL_CODEC_ISSUE_VERSION_MISMATCH,VIREO_PROTOCOL_CODEC_ISSUE_INVALID_HEADER_LENGTH,
        VIREO_PROTOCOL_CODEC_ISSUE_BODY_TOO_LARGE,VIREO_PROTOCOL_CODEC_ISSUE_CRC_MISMATCH,VIREO_PROTOCOL_CODEC_ISSUE_CRC_MISMATCH};
    for (size_t i = 0; i < sizeof offsets / sizeof offsets[0]; ++i) {
        memcpy(bad, w.wire, w.wire_size); bad[offsets[i]] ^= 1;
        vireo_async_request_report_t const p = call(&w, bad, w.wire_size, 64, 4096, 4, NULL, VIREO_RESULT_PROTOCOL);
        CHECK(p.stage == VIREO_ASYNC_REQUEST_CHECK_FRAME && p.codec_issue == expected[i] &&
            !p.input_validated && !p.metadata_created && !p.task_created && !w.remaining);
    }
    count(&w, 0); unchanged_source(&w); world_cleanup(&w);
}
static void exact_frame_and_request_semantics(void) {
    world_t w; world_setup(&w, false); uint8_t bad[64]; memcpy(bad, w.wire, w.wire_size); bad[w.wire_size] = 0;
    vireo_async_request_report_t p = call(&w, bad, w.wire_size + 1, 64, 4096, 4, NULL, VIREO_RESULT_PROTOCOL);
    CHECK(p.codec_issue == VIREO_PROTOCOL_CODEC_ISSUE_BODY_LENGTH_MISMATCH && !p.input_validated);
    p = call(&w, bad, 34, 64, 4096, 4, NULL, VIREO_RESULT_PROTOCOL);
    CHECK(p.codec_issue == VIREO_PROTOCOL_CODEC_ISSUE_BODY_LENGTH_MISMATCH);
    size_t const offsets[] = {9, 9, 7, 6, 19, 11};
    uint8_t const values[] = {VIREO_PROTOCOL_FLAG_RESPONSE,VIREO_PROTOCOL_FLAG_MORE,0xfe,0xff,0,1};
    for (size_t i = 0; i < sizeof offsets / sizeof offsets[0]; ++i) {
        memcpy(bad, w.wire, w.wire_size); bad[offsets[i]] = values[i];
        p = call(&w, bad, w.wire_size, 64, 4096, 4, NULL, VIREO_RESULT_PROTOCOL);
        CHECK(!p.input_validated && !p.metadata_created && p.stage == VIREO_ASYNC_REQUEST_CHECK_FRAME);
    }
    world_cleanup(&w);
}
static void stale_cross_and_range(void) {
    world_t w; world_setup(&w, false); vireo_connection_pool_lease_t const current = w.f.client;
    w.f.client.generation += 1;
    vireo_async_request_report_t p = ordinary(&w, VIREO_RESULT_NOT_FOUND);
    CHECK(p.input_validated && !p.metadata_created && p.stage == VIREO_ASYNC_REQUEST_MAKE_METADATA);
    w.f.client = current; w.f.client.slot_index = SIZE_MAX; p = ordinary(&w, VIREO_RESULT_RANGE);
    CHECK(p.input_validated && !p.metadata_created);
    w.f.client = current; vireo_tcp_server_t *server = w.f.server; w.f.server = w.f.other_server;
    p = ordinary(&w, VIREO_RESULT_INVALID_ARGUMENT); CHECK(!p.metadata_created); w.f.server = server;
    w.f.client = (vireo_connection_pool_lease_t){0}; p = ordinary(&w, VIREO_RESULT_NOT_FOUND); CHECK(!p.metadata_created);
    w.f.client = current; world_cleanup(&w);
}
static void closing_and_stopped(void) {
    world_t w; world_setup(&w, false);
    EXPECT(vireo_tcp_server_client_request_close(w.f.server, w.f.client, VIREO_CONNECTION_CLOSE_MODE_DRAIN,
        VIREO_CONNECTION_CLOSE_REASON_SERVER_STOP, NULL), VIREO_OK);
    vireo_async_request_report_t p = ordinary(&w, VIREO_RESULT_BUSY);
    CHECK(p.metadata_created && p.task_created && p.task_retained && !p.submit_report.registration_committed);
    EXPECT(vireo_task_destroy(&w.remaining), VIREO_OK);
    EXPECT(vireo_tcp_server_request_stop(w.f.server, NULL), VIREO_OK);
    p = ordinary(&w, VIREO_RESULT_CANCELLED);
    CHECK(p.metadata_created && p.task_retained && !p.task_transferred); unchanged_source(&w); count(&w, 0); world_cleanup(&w);
}
static void duplicates_and_client_limits(void) {
    world_t w; world_setup(&w, false); vireo_task_metadata_t original;
    EXPECT(vireo_inflight_metadata_make_next(w.f.server, w.f.client, 1, 9, 0, &original, NULL), VIREO_OK);
    EXPECT(vireo_inflight_store_register(w.store, w.f.server, original, NULL), VIREO_OK); remember(&w, original);
    vireo_async_request_report_t p = ordinary(&w, VIREO_RESULT_BUSY);
    CHECK(p.metadata.request_instance_id != original.request_instance_id && p.task_retained && !p.submit_report.registration_committed);
    EXPECT(vireo_task_destroy(&w.remaining), VIREO_OK); consume_source(&w); load(&w, 2, 3);
    p = call(&w, w.input, w.input_size, 64, 4096, 1, NULL, VIREO_RESULT_BUSY);
    CHECK(p.task_retained && !p.submit_report.registration_committed); EXPECT(vireo_task_destroy(&w.remaining), VIREO_OK);
    p = call(&w, w.input, w.input_size, 64, 4096, 5, NULL, VIREO_RESULT_RANGE);
    CHECK(p.task_retained && !p.submit_report.registration_committed); count(&w, 1); world_cleanup(&w);
}
static void real_queue_full_refund(void) {
    world_t w; world_setup(&w, true); start_runner(&w.r); w.started = true;
    (void)submit_accept(&w, NULL); meet(&w.r.entered); consume_source(&w); load(&w, 2, 3);
    vireo_async_request_report_t const second = ordinary(&w, VIREO_OK); CHECK(second.task_transferred);
    consume_source(&w); load(&w, 3, 3);
    vireo_async_request_report_t const third = ordinary(&w, VIREO_RESULT_BUSY);
    CHECK(third.task_retained && !third.task_transferred && third.submit_report.rollback_called &&
        third.submit_report.rollback_result == VIREO_OK && !third.submit_report.record_retained);
    count(&w, 2); unchanged_source(&w); payload_is(&w); meet(&w.r.released); world_cleanup(&w);
    CHECK(atomic_load(&w.r.calls) == 2);
}
static void cancel_reference_lifetime(void) {
    world_t w; world_setup(&w, true); start_runner(&w.r); w.started = true;
    vireo_task_cancel_t *cancel = NULL; EXPECT(vireo_task_cancel_create(4096, &cancel), VIREO_OK);
    EXPECT(vireo_task_cancel_request(cancel), VIREO_OK);
    vireo_async_request_report_t const p = submit_accept(&w, cancel); meet(&w.r.entered);
    EXPECT(vireo_task_cancel_destroy(&cancel), VIREO_OK);
    vireo_task_cancel_t *from_table = NULL;
    EXPECT(vireo_inflight_store_retain_cancel(w.store, p.metadata, &from_table, NULL), VIREO_OK);
    bool requested; EXPECT(vireo_task_cancel_is_requested(from_table, &requested), VIREO_OK); CHECK(requested);
    EXPECT(vireo_task_cancel_destroy(&from_table), VIREO_OK);
    vireo_task_metadata_t ended; EXPECT(vireo_inflight_store_take(w.store, p.metadata, &ended, NULL), VIREO_OK);
    count(&w, 0); consume_source(&w); load(&w, 2, 0); meet(&w.r.released); world_cleanup(&w);
    CHECK(atomic_load(&w.r.cancelled) == 1 && atomic_load(&w.r.calls) == 1);
}

/** 本层公开依赖模型，绝不改原私有对象。 */
typedef struct model {
    unsigned mode; /**< 1发行拒绝、2复制NO_MEMORY、3已转移报错、4真实登记退款失败模型。 */
    size_t metadata_calls; /**< 实际元数据seam调用数。 */
    size_t copy_calls; /**< 实际复制seam调用数。 */
    size_t submit_calls; /**< 实际提交seam调用数。 */
} model_t;
static vireo_result_t metadata_model(void *context, vireo_tcp_server_t const *server,
    vireo_connection_pool_lease_t client, uint32_t sequence, uint32_t op, uint64_t deadline,
    vireo_task_metadata_t *metadata, vireo_inflight_stage_t *stage) {
    model_t *m = context; ++m->metadata_calls; errno = EIO;
    if (m->mode == 1) { *stage = VIREO_INFLIGHT_ISSUE_INSTANCE; return VIREO_RESULT_BUSY; }
    return vireo_inflight_metadata_make_next(server, client, sequence, op, deadline, metadata, stage);
}
static vireo_result_t copy_model(void *context, vireo_task_metadata_t metadata, void const *data,
    size_t size, size_t budget, vireo_task_cancel_t *cancel, vireo_task_t **out) {
    model_t *m = context; ++m->copy_calls; errno = ENOMEM;
    if (m->mode == 2) return VIREO_RESULT_NO_MEMORY;
    return cancel == NULL ? vireo_task_create_copy(metadata, data, size, budget, out) :
        vireo_task_create_copy_with_cancel(metadata, data, size, budget, cancel, out);
}
static vireo_result_t submit_model(void *context, vireo_inflight_store_t *store,
    vireo_tcp_server_t const *server, vireo_thread_pool_t *pool, size_t limit,
    vireo_task_t **owner, vireo_inflight_submit_report_t *report) {
    model_t *m = context; ++m->submit_calls;
    if (m->mode == 4) {
        vireo_task_info_t info; EXPECT(vireo_task_inspect(*owner, &info), VIREO_OK);
        EXPECT(vireo_inflight_store_register_task_limited(store, server, *owner, limit, NULL), VIREO_OK);
        *report = (vireo_inflight_submit_report_t){.stage = VIREO_INFLIGHT_SUBMIT_SUBMIT_TASK,
            .metadata = info.metadata, .task_inspected = true, .registration_committed = true, .record_retained = true,
            .submit_called = true, .rollback_called = true, .rollback_result = VIREO_RESULT_INTERNAL,
            .inflight_stage = VIREO_INFLIGHT_RELEASE_CANCEL};
        return VIREO_RESULT_BUSY; /* 实际登记保留；模型拒绝退款，非真实同步故障。 */
    }
    vireo_result_t result = vireo_inflight_store_try_submit(store, server, pool, limit, owner, report);
    if (m->mode == 3 && result == VIREO_OK) {
        report->stage = VIREO_INFLIGHT_SUBMIT_SUBMIT_TASK;
        report->pool_report.stage = VIREO_THREAD_POOL_SUBMIT_STAGE_SUBMIT_QUEUE;
        report->pool_report.queue_report.stage = VIREO_TASK_QUEUE_STAGE_UNLOCK;
        report->pool_report.queue_report.pthread_error = EIO;
        return VIREO_RESULT_INTERNAL;
    }
    return result;
}
static vireo_async_request_ops_t const ops = {metadata_model, copy_model, submit_model};
static vireo_async_request_report_t modeled(world_t *w, model_t *m, vireo_result_t result) {
    vireo_async_request_report_t p;
    EXPECT(vireo_async_request_with_ops(w->f.server, w->f.client, w->store, w->r.pool, w->input,
        w->input_size, 64, 4096, 4, 9, UINT64_MAX, NULL, &w->remaining, &p, &ops, m), result);
    if (p.metadata_created) remember(w, p.metadata);
    return p;
}
static void metadata_and_copy_failure_models(void) {
    world_t w; world_setup(&w, false); model_t m = {.mode = 1};
    vireo_async_request_report_t p = modeled(&w, &m, VIREO_RESULT_BUSY);
    CHECK(p.input_validated && !p.metadata_created && !w.remaining && m.metadata_calls == 1 && !m.copy_calls &&
        p.inflight_stage == VIREO_INFLIGHT_ISSUE_INSTANCE);
    m = (model_t){.mode = 2}; p = modeled(&w, &m, VIREO_RESULT_NO_MEMORY);
    CHECK(p.metadata_created && !p.task_created && !w.remaining && m.copy_calls == 1 && !m.submit_calls &&
        p.stage == VIREO_ASYNC_REQUEST_CREATE_TASK); unchanged_source(&w); world_cleanup(&w);
}
static void retained_record_failure_model(void) {
    world_t w; world_setup(&w, false); model_t m = {.mode = 4};
    vireo_async_request_report_t const p = modeled(&w, &m, VIREO_RESULT_BUSY);
    CHECK(p.task_retained && !p.task_transferred && p.submit_report.record_retained &&
        p.submit_report.rollback_called && p.submit_report.rollback_result == VIREO_RESULT_INTERNAL &&
        m.submit_calls == 1); count(&w, 1); payload_is(&w); unchanged_source(&w); world_cleanup(&w);
}
static void transferred_error_model(void) {
    world_t w; world_setup(&w, true); start_runner(&w.r); w.started = true;
    (void)submit_accept(&w, NULL); meet(&w.r.entered); consume_source(&w); load(&w, 2, 3);
    model_t m = {.mode = 3}; vireo_async_request_report_t const p = modeled(&w, &m, VIREO_RESULT_INTERNAL);
    CHECK(p.task_transferred && !p.task_retained && !w.remaining && p.task_created &&
        p.submit_report.record_retained && !p.submit_report.rollback_called &&
        p.submit_report.pool_report.queue_report.pthread_error == EIO && m.submit_calls == 1);
    count(&w, 2); unchanged_source(&w); meet(&w.r.released); world_cleanup(&w); CHECK(atomic_load(&w.r.calls) == 2);
}
static void required_addresses_and_ranges(void) {
    world_t w; world_setup(&w, false); vireo_async_request_report_t p; model_t m = {0};
    for (unsigned bad = 0; bad < 12; ++bad) {
        vireo_async_request_ops_t table = ops;
        if (bad == 8) table.metadata = NULL;
        if (bad == 9) table.copy = NULL;
        if (bad == 10) table.submit = NULL;
        memset(&p, 0xa5, sizeof p);
        EXPECT(vireo_async_request_with_ops(bad == 0 ? NULL : w.f.server, w.f.client,
            bad == 1 ? NULL : w.store, bad == 2 ? NULL : w.r.pool, bad == 3 ? NULL : w.input,
            w.input_size, 64, 4096, 4, 9, UINT64_MAX, NULL, bad == 4 ? NULL : &w.remaining,
            bad == 5 ? NULL : &p, bad == 6 ? NULL : &table, &m),
            bad == 7 || bad == 11 ? VIREO_RESULT_NOT_FOUND : VIREO_RESULT_INVALID_ARGUMENT);
        if (bad != 5 && p.metadata_created) remember(&w, p.metadata);
        if (bad == 7 || bad == 11) EXPECT(vireo_task_destroy(&w.remaining), VIREO_OK);
        else if (bad != 5) CHECK(!p.input_validated && !p.task_created && p.stage == 0);
    }
    size_t const invalid[][2] = {{0,35},{31,35},{16777249,35},{64,0},{64,31},{34,35},{64,SIZE_MAX}};
    for (size_t i = 0; i < sizeof invalid / sizeof invalid[0]; ++i) {
        p = call(&w, w.input, invalid[i][1], invalid[i][0], 4096, 4, NULL, VIREO_RESULT_RANGE);
        CHECK(!p.input_validated && !p.metadata_created);
    }
    p = call(&w, w.input, w.input_size, 64, 0, 4, NULL, VIREO_RESULT_INVALID_ARGUMENT); CHECK(!p.task_created);
    p = call(&w, w.input, w.input_size, 64, 4096, 0, NULL, VIREO_RESULT_INVALID_ARGUMENT); CHECK(!p.task_created);
    EXPECT(vireo_async_request_copy_try_submit(w.f.server, w.f.client, w.store, w.r.pool, w.input, w.input_size,
        64, 4096, 4, 0, 0, NULL, &w.remaining, &p), VIREO_RESULT_INVALID_ARGUMENT); CHECK(!p.task_created);
    (void)ordinary(&w, VIREO_RESULT_NOT_FOUND); vireo_task_t *original = w.remaining;
    p = ordinary(&w, VIREO_RESULT_INVALID_ARGUMENT); CHECK(w.remaining == original && !p.task_created);
    unchanged_source(&w); world_cleanup(&w);
}
int main(void) {
    CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL) == 0);
    _Static_assert(VIREO_ASYNC_REQUEST_MAX_FRAME_BYTES == 16777248 && VIREO_ASYNC_REQUEST_SUBMIT == 4,
        "independent explicit frame/stage contract");
    void (*const groups[])(void) = {network_copy_after_consume, empty_full_frame, unstarted_refund_and_copy,
        allocation_boundaries, corrupt_frames, exact_frame_and_request_semantics, stale_cross_and_range,
        closing_and_stopped, duplicates_and_client_limits, real_queue_full_refund, cancel_reference_lifetime,
        metadata_and_copy_failure_models, retained_record_failure_model, transferred_error_model, required_addresses_and_ranges};
    for (size_t i = 0; i < sizeof groups / sizeof groups[0]; ++i) { size_t n = fds(); groups[i](); CHECK(fds() == n); }
    puts("async request copy submit: 15 groups passed"); return 0;
}

