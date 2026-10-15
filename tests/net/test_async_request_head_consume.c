/*
 * PROJECT : VIREO
 * FILE    : test_async_request_head_consume.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-13
 * BRIEF   : 真实首帧消费、pending防重、仅恢复与真实主次失败进度
 */
#define _GNU_SOURCE
#include "async_request_head_internal.h"
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
    vireo_async_request_pending_t pending; /**< 同客户唯一待消费值，初全逻辑零。 */
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

/** 本层公开边界故障账本；不改任何foreign private或原同步对象。 */
typedef struct model {
    vireo_result_t consume_failure; /**< 非OK时原consume拒绝模型，读区保持。 */
    bool submit_failure_after_transfer; /**< 真移交后改报INTERNAL/EIO，非真实锁损坏。 */
    bool frames_failure; /**< frames依赖INTERNAL模型。 */
    bool read_failure; /**< read依赖INTERNAL模型。 */
    bool short_read; /**< 成功read输出异常短长度模型，核本层防御。 */
    size_t frames_calls; /**< 本组实际frames seam次数。 */
    size_t read_calls; /**< 本组实际read seam次数。 */
    size_t submit_calls; /**< 本组实际031-01 seam次数。 */
    size_t consume_calls; /**< 本组实际consume seam次数。 */
    vireo_async_request_pending_t *pending; /**< caller值短借，核consume前已写义务。 */
} model_t;
static vireo_result_t frames_model(void *context, vireo_tcp_server_t const *server,
    vireo_connection_pool_lease_t client, vireo_connection_frame_options_t const *options,
    vireo_connection_frame_budget_t const *budget, vireo_connection_frame_view_t *views,
    size_t capacity, vireo_connection_frame_info_t *info, vireo_tcp_server_client_error_t *error) {
    model_t *m = context; ++m->frames_calls; CHECK(budget->max_messages == 1 && capacity == 1);
    errno = EIO;
    if (m->frames_failure) { *info = (vireo_connection_frame_info_t){0};
        *error = (vireo_tcp_server_client_error_t){.primary.stage = VIREO_TCP_SERVER_CLIENT_FRAMES_PEEK};
        return VIREO_RESULT_INTERNAL; }
    return vireo_tcp_server_client_frames_peek(server, client, options, budget, views, capacity, info, error);
}
static vireo_result_t read_model(void *context, vireo_tcp_server_t const *server,
    vireo_connection_pool_lease_t client, uint8_t const **data, size_t *size, vireo_tcp_server_client_error_t *error) {
    model_t *m = context; ++m->read_calls; errno = EIO;
    if (m->read_failure) { *error = (vireo_tcp_server_client_error_t){.primary.stage = VIREO_TCP_SERVER_CLIENT_READ_PEEK};
        return VIREO_RESULT_INTERNAL; }
    vireo_result_t result = vireo_tcp_server_client_read_peek(server, client, data, size, error);
    if (m->short_read && result == VIREO_OK) *size = 1;
    return result;
}
static vireo_result_t submit_model(void *context, vireo_tcp_server_t const *server,
    vireo_connection_pool_lease_t client, vireo_inflight_store_t *store, vireo_thread_pool_t *pool,
    uint8_t const *data, size_t size, size_t cap, size_t allocation, size_t limit, uint32_t operation,
    uint64_t deadline, vireo_task_cancel_t *cancel, vireo_task_t **owner, vireo_async_request_report_t *report) {
    model_t *m = context; ++m->submit_calls;
    vireo_result_t result = vireo_async_request_copy_try_submit(server, client, store, pool, data, size,
        cap, allocation, limit, operation, deadline, cancel, owner, report);
    if (m->submit_failure_after_transfer && result == VIREO_OK) {
        report->stage = VIREO_ASYNC_REQUEST_SUBMIT;
        report->submit_report.stage = VIREO_INFLIGHT_SUBMIT_SUBMIT_TASK;
        report->submit_report.pool_report.stage = VIREO_THREAD_POOL_SUBMIT_STAGE_SUBMIT_QUEUE;
        report->submit_report.pool_report.queue_report.stage = VIREO_TASK_QUEUE_STAGE_UNLOCK;
        report->submit_report.pool_report.queue_report.pthread_error = EIO;
        return VIREO_RESULT_INTERNAL;
    }
    return result;
}
static vireo_result_t consume_model(void *context, vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, size_t size, vireo_tcp_server_client_error_t *error) {
    model_t *m = context; ++m->consume_calls;
    CHECK(m->pending != NULL && m->pending->frame_bytes == size && m->pending->metadata.request_instance_id != 0);
    errno = EIO;
    if (m->consume_failure != VIREO_OK) {
        *error = (vireo_tcp_server_client_error_t){.primary.stage = VIREO_TCP_SERVER_CLIENT_READ_CONSUME};
        return m->consume_failure;
    }
    return vireo_tcp_server_client_read_consume(server, client, size, error);
}
static vireo_async_request_head_ops_t const ops = {frames_model, read_model, submit_model, consume_model};
static void track(world_t *w, vireo_async_request_head_report_t p) {
    if (p.submit_called && p.submit_report.metadata_created && p.submit_report.submit_report.record_retained)
        remember(w, p.submit_report.metadata);
}
static vireo_async_request_head_report_t head(world_t *w, model_t *m, size_t cap,
    size_t allocation, size_t limit, vireo_task_cancel_t *cancel, vireo_result_t expected) {
    vireo_async_request_head_report_t p; memset(&p, 0xa5, sizeof p);
    if (m != NULL) {
        m->pending = &w->pending;
        EXPECT(vireo_async_request_head_with_ops(w->f.server, w->f.client, w->store, w->r.pool,
            cap, allocation, limit, 9, UINT64_MAX, cancel, &w->pending, &w->remaining, &p, &ops, m), expected);
    } else EXPECT(vireo_async_request_submit_read_head(w->f.server, w->f.client, w->store, w->r.pool,
        cap, allocation, limit, 9, UINT64_MAX, cancel, &w->pending, &w->remaining, &p), expected);
    track(w, p); return p;
}
static vireo_async_request_head_report_t resume(world_t *w, model_t *m, vireo_result_t expected) {
    vireo_async_request_head_report_t p;
    if (m != NULL) {
        m->pending = &w->pending;
        EXPECT(vireo_async_request_resume_with_ops(w->f.server, &w->pending, &p, &ops, m), expected);
    } else EXPECT(vireo_async_request_resume_consume(w->f.server, &w->pending, &p), expected);
    return p;
}
static vireo_async_request_head_report_t transfer_first(world_t *w, model_t *m,
    vireo_task_cancel_t *cancel, vireo_result_t expected) {
    /* 仅测试caller对未移交且退款成功的BUSY有限重试；已经移交绝不重做。 */
    for (size_t i = 0; i < 100000; ++i) {
        vireo_async_request_head_report_t p; errno = EDOM;
        vireo_result_t result;
        if (m != NULL) { m->pending = &w->pending;
            result = vireo_async_request_head_with_ops(w->f.server, w->f.client, w->store, w->r.pool,
                64, 4096, 4, 9, UINT64_MAX, cancel, &w->pending, &w->remaining, &p, &ops, m);
        } else result = vireo_async_request_submit_read_head(w->f.server, w->f.client, w->store, w->r.pool,
            64, 4096, 4, 9, UINT64_MAX, cancel, &w->pending, &w->remaining, &p);
        CHECK(errno == EDOM);
        if (p.submit_report.task_transferred) { CHECK(result == expected); track(w, p); return p; }
        CHECK(result == VIREO_RESULT_BUSY && p.submit_report.task_created && w->remaining != NULL &&
            p.submit_report.submit_report.rollback_called && p.submit_report.submit_report.rollback_result == VIREO_OK &&
            !p.consume_called && w->pending.frame_bytes == 0);
        EXPECT(vireo_task_destroy(&w->remaining), VIREO_OK); sched_yield();
    }
    CHECK(false); return (vireo_async_request_head_report_t){0};
}
static size_t readable(world_t *w) {
    uint8_t const *data; size_t size;
    EXPECT(vireo_tcp_server_client_read_peek(w->f.server, w->f.client, &data, &size, NULL), VIREO_OK);
    return size;
}
static void source_is(world_t *w, uint8_t const *expected, size_t n) {
    uint8_t const *data; size_t size;
    EXPECT(vireo_tcp_server_client_read_peek(w->f.server, w->f.client, &data, &size, NULL), VIREO_OK);
    CHECK(size == n); if (n) CHECK(!memcmp(data, expected, n));
}
static void append(world_t *w, uint8_t const *bytes, size_t n, size_t total) {
    size_t sent = 0;
    while (sent < n) { ssize_t s = send(w->f.peer, bytes + sent, n - sent, MSG_NOSIGNAL); CHECK(s > 0); sent += (size_t)s; }
    vireo_connection_receive_budget_t budget = {64, 8}; bool got = false;
    for (size_t i = 0; i < 10000; ++i) {
        vireo_connection_receive_info_t info;
        EXPECT(vireo_tcp_server_client_receive(w->f.server, w->f.client, &budget, &info, NULL), VIREO_OK);
        if (readable(w) == total) { got = true; break; }
        CHECK(readable(w) < total); sched_yield();
    }
    CHECK(got);
}
static void start_world(world_t *w) { start_runner(&w->r); w->started = true; }
static void observe_eof(world_t *w) {
    vireo_connection_receive_budget_t const budget = {64, 8};
    for (size_t i = 0; i < 10000; ++i) {
        vireo_connection_receive_info_t info;
        EXPECT(vireo_tcp_server_client_receive(w->f.server,w->f.client,&budget,&info,NULL),VIREO_OK);
        if (info.stop_reason == VIREO_CONNECTION_RECEIVE_STOP_EOF) return;
        CHECK(info.stop_reason == VIREO_CONNECTION_RECEIVE_STOP_WOULD_BLOCK); sched_yield();
    }
    CHECK(false);
}
static void no_submission(vireo_async_request_head_report_t p) {
    CHECK(!p.submit_called && !p.pending_committed && !p.consume_called);
}

static void success_single_consumed(void) {
    world_t w; world_setup(&w, true); start_world(&w);
    vireo_async_request_head_report_t p = transfer_first(&w, NULL, NULL, VIREO_OK); meet(&w.r.entered);
    CHECK(p.frame_found && p.frame_bytes == 35 && p.read_peek_called && p.pending_committed &&
        p.consume_called && p.consume_result == VIREO_OK && !p.pending_retained && w.pending.frame_bytes == 0);
    CHECK(p.pending_snapshot.metadata.request_instance_id == p.submit_report.metadata.request_instance_id);
    count(&w, 1); CHECK(readable(&w) == 0);
    p = head(&w, NULL, 64, 4096, 4, NULL, VIREO_OK); no_submission(p); CHECK(!p.frame_found);
    p = resume(&w, NULL, VIREO_RESULT_NOT_FOUND); no_submission(p);
    meet(&w.r.released); world_cleanup(&w); CHECK(atomic_load(&w.r.calls) == 1);
}
static void two_frames_one_at_time(void) {
    world_t w; world_setup(&w, true); consume_source(&w);
    uint8_t frames[64]; make_wire(frames, 1, 0); make_wire(frames + 32, 2, 0);
    memcpy(w.r.expected[1], frames, 32); w.r.expected_sizes[1] = 32;
    memcpy(w.r.expected[2], frames + 32, 32); w.r.expected_sizes[2] = 32;
    append(&w, frames, 64, 64); start_world(&w);
    vireo_async_request_head_report_t p = transfer_first(&w, NULL, NULL, VIREO_OK); meet(&w.r.entered);
    CHECK(p.frame_bytes == 32 && p.frame_info.frame_count == 1); source_is(&w, frames + 32, 32); count(&w, 1);
    p = head(&w, NULL, 64, 4096, 4, NULL, VIREO_OK); CHECK(p.submit_report.task_transferred && p.frame_bytes == 32);
    CHECK(readable(&w) == 0); count(&w, 2); meet(&w.r.released); world_cleanup(&w); CHECK(atomic_load(&w.r.calls) == 2);
}
static void half_tail_preserved(void) {
    world_t w; world_setup(&w, true); uint8_t next[35]; make_wire(next, 2, 3);
    memcpy(w.r.expected[2], next, 35); w.r.expected_sizes[2] = 35;
    append(&w, next, 5, 40); start_world(&w);
    vireo_async_request_head_report_t p = transfer_first(&w, NULL, NULL, VIREO_OK); meet(&w.r.entered);
    CHECK(p.frame_bytes == 35); source_is(&w, next, 5);
    p = head(&w, NULL, 64, 4096, 4, NULL, VIREO_OK); no_submission(p); CHECK(!p.frame_found);
    append(&w, next + 5, 30, 35); p = head(&w, NULL, 64, 4096, 4, NULL, VIREO_OK);
    CHECK(p.submit_report.task_transferred && readable(&w) == 0); count(&w, 2);
    meet(&w.r.released); world_cleanup(&w); CHECK(atomic_load(&w.r.calls) == 2);
}
static void empty_and_empty_eof(void) {
    world_t w; world_setup(&w, false); consume_source(&w);
    vireo_async_request_head_report_t p = head(&w, NULL, 64, 4096, 4, NULL, VIREO_OK);
    no_submission(p); CHECK(p.frame_peek_called && p.frame_info.stop_reason == VIREO_CONNECTION_FRAME_STOP_NEED_MORE);
    CHECK(shutdown(w.f.peer, SHUT_WR) == 0); observe_eof(&w);
    p = head(&w, NULL, 64, 4096, 4, NULL, VIREO_OK);
    no_submission(p); CHECK(p.frame_info.stop_reason == VIREO_CONNECTION_FRAME_STOP_EOF); world_cleanup(&w);
}
static void partial_header_and_body(void) {
    world_t w; world_setup(&w, false); consume_source(&w);
    append(&w, w.wire, 7, 7);
    vireo_async_request_head_report_t p = head(&w, NULL, 64, 4096, 4, NULL, VIREO_OK); no_submission(p);
    source_is(&w, w.wire, 7); append(&w, w.wire + 7, 26, 33);
    p = head(&w, NULL, 64, 4096, 4, NULL, VIREO_OK); no_submission(p); source_is(&w, w.wire, 33);
    append(&w, w.wire + 33, 2, 35);
    p = head(&w, NULL, 64, 4096, 4, NULL, VIREO_RESULT_NOT_FOUND);
    CHECK(p.frame_found && p.submit_called && !p.consume_called && w.remaining); source_is(&w, w.wire, 35); world_cleanup(&w);
}
static void protocol_and_truncated_eof(void) {
    world_t w; world_setup(&w, false); consume_source(&w); uint8_t bad[35]; memcpy(bad, w.wire, 35); bad[34] ^= 1;
    append(&w, bad, 35, 35); vireo_async_request_head_report_t p = head(&w, NULL, 64, 4096, 4, NULL, VIREO_RESULT_PROTOCOL);
    no_submission(p); source_is(&w, bad, 35); count(&w, 0); world_cleanup(&w);
    world_setup(&w, false); consume_source(&w); append(&w, w.wire, 7, 7); CHECK(shutdown(w.f.peer, SHUT_WR) == 0);
    observe_eof(&w);
    p = head(&w, NULL, 64, 4096, 4, NULL, VIREO_RESULT_PROTOCOL); no_submission(p); CHECK(!w.pending.frame_bytes); world_cleanup(&w);
}
static void untransferred_preserves_source(void) {
    world_t w; world_setup(&w, false);
    vireo_async_request_head_report_t p = head(&w, NULL, 64, 4096, 4, NULL, VIREO_RESULT_NOT_FOUND);
    CHECK(p.submit_called && p.submit_result == VIREO_RESULT_NOT_FOUND && w.remaining && !p.consume_called &&
        !p.pending_committed && !p.pending_retained && !w.pending.frame_bytes);
    CHECK(p.submit_report.submit_report.rollback_called && p.submit_report.submit_report.rollback_result == VIREO_OK);
    source_is(&w, w.wire, 35); count(&w, 0); world_cleanup(&w);
}
static void gate_survives_ended_record(void) {
    world_t w; world_setup(&w, true); start_world(&w); model_t m = {.consume_failure = VIREO_RESULT_BUSY};
    vireo_async_request_head_report_t p = transfer_first(&w, &m, NULL, VIREO_RESULT_BUSY); meet(&w.r.entered);
    CHECK(p.stage == VIREO_ASYNC_REQUEST_HEAD_CONSUME && p.pending_committed && p.pending_retained && m.consume_calls == 1);
    uint64_t const id = w.pending.metadata.request_instance_id;
    vireo_task_metadata_t ended; EXPECT(vireo_inflight_store_take(w.store, w.pending.metadata, &ended, NULL), VIREO_OK); count(&w, 0);
    size_t const frames = m.frames_calls, submits = m.submit_calls, reads = m.read_calls;
    p = head(&w, &m, 64, 4096, 4, NULL, VIREO_RESULT_BUSY);
    CHECK(p.stage == VIREO_ASYNC_REQUEST_HEAD_CHECK_PENDING && p.pending_retained && !p.frame_peek_called &&
        !p.submit_called && !p.consume_called && m.frames_calls == frames && m.read_calls == reads && m.submit_calls == submits);
    source_is(&w, w.wire, 35); CHECK(w.pending.metadata.request_instance_id == id);
    m.consume_failure = VIREO_OK; p = resume(&w, &m, VIREO_OK);
    CHECK(p.consume_called && !p.submit_called && !p.frame_peek_called && !p.pending_committed &&
        !p.pending_retained && p.pending_snapshot.metadata.request_instance_id == id && m.submit_calls == submits);
    CHECK(!w.pending.frame_bytes && readable(&w) == 0);
    p = resume(&w, &m, VIREO_RESULT_NOT_FOUND); CHECK(!p.consume_called && m.consume_calls == 2);
    meet(&w.r.released); world_cleanup(&w); CHECK(atomic_load(&w.r.calls) == 1);
}
static void repeated_resume_errors(void) {
    world_t w; world_setup(&w, true); start_world(&w); model_t m = {.consume_failure = VIREO_RESULT_BUSY};
    (void)transfer_first(&w, &m, NULL, VIREO_RESULT_BUSY); meet(&w.r.entered);
    vireo_async_request_pending_t saved; memcpy(&saved, &w.pending, sizeof saved);
    size_t const submits = m.submit_calls;
    vireo_async_request_head_report_t p = resume(&w, &m, VIREO_RESULT_BUSY);
    CHECK(p.pending_retained && !memcmp(&saved, &w.pending, sizeof saved) && m.submit_calls == submits);
    m.consume_failure = VIREO_RESULT_INTERNAL; p = resume(&w, &m, VIREO_RESULT_INTERNAL);
    CHECK(p.stage == VIREO_ASYNC_REQUEST_HEAD_CONSUME && p.consume_error.primary.stage == VIREO_TCP_SERVER_CLIENT_READ_CONSUME &&
        !memcmp(&saved, &w.pending, sizeof saved)); source_is(&w, w.wire, 35);
    m.consume_failure = VIREO_OK; (void)resume(&w, &m, VIREO_OK);
    CHECK(readable(&w) == 0); meet(&w.r.released); world_cleanup(&w);
}
static void transferred_error_still_consumes(void) {
    world_t w; world_setup(&w, true); start_world(&w); model_t m = {.submit_failure_after_transfer = true};
    vireo_async_request_head_report_t const p = transfer_first(&w, &m, NULL, VIREO_RESULT_INTERNAL); meet(&w.r.entered);
    CHECK(p.stage == VIREO_ASYNC_REQUEST_HEAD_SUBMIT && p.submit_result == VIREO_RESULT_INTERNAL &&
        p.submit_report.task_transferred && p.consume_result == VIREO_OK && p.pending_committed && !p.pending_retained &&
        m.consume_calls == 1 && !w.remaining && !w.pending.frame_bytes);
    CHECK(p.submit_report.submit_report.pool_report.queue_report.pthread_error == EIO);
    count(&w, 1); CHECK(readable(&w) == 0); meet(&w.r.released); world_cleanup(&w);
}
static void dual_error_priority(void) {
    world_t w; world_setup(&w, true); start_world(&w);
    model_t m = {.submit_failure_after_transfer = true, .consume_failure = VIREO_RESULT_BUSY};
    vireo_async_request_head_report_t p = transfer_first(&w, &m, NULL, VIREO_RESULT_INTERNAL); meet(&w.r.entered);
    CHECK(p.submit_result == VIREO_RESULT_INTERNAL && p.consume_result == VIREO_RESULT_BUSY &&
        p.pending_retained && p.stage == VIREO_ASYNC_REQUEST_HEAD_SUBMIT && w.pending.frame_bytes == 35);
    count(&w, 1); size_t const submits = m.submit_calls;
    m.consume_failure = VIREO_OK; p = resume(&w, &m, VIREO_OK);
    CHECK(!p.submit_called && m.submit_calls == submits && readable(&w) == 0); meet(&w.r.released); world_cleanup(&w);
}
static void stopped_closing_resume(void) {
    world_t w; world_setup(&w, true); start_world(&w); model_t m = {.consume_failure = VIREO_RESULT_BUSY};
    (void)transfer_first(&w, &m, NULL, VIREO_RESULT_BUSY); meet(&w.r.entered);
    EXPECT(vireo_tcp_server_client_request_close(w.f.server, w.f.client, VIREO_CONNECTION_CLOSE_MODE_DRAIN,
        VIREO_CONNECTION_CLOSE_REASON_SERVER_STOP, NULL), VIREO_OK);
    EXPECT(vireo_tcp_server_request_stop(w.f.server, NULL), VIREO_OK);
    vireo_async_request_head_report_t const p = resume(&w, NULL, VIREO_OK);
    CHECK(p.consume_called && !p.submit_called && !w.pending.frame_bytes && readable(&w) == 0);
    meet(&w.r.released); world_cleanup(&w);
}
static void gone_client_pending_kept(void) {
    world_t w; world_setup(&w, true); start_world(&w); model_t m = {.consume_failure = VIREO_RESULT_BUSY};
    (void)transfer_first(&w, &m, NULL, VIREO_RESULT_BUSY); meet(&w.r.entered);
    vireo_async_request_pending_t saved; memcpy(&saved, &w.pending, sizeof saved);
    /* 负向身份实验：明确结束旧客户后，pending纯值仍不可自动当已消费/用于新代。 */
    CHECK(release_client(&w.f)); w.input = NULL; w.input_size = 0; CHECK(add_client(&w.f));
    CHECK(w.f.client.generation != saved.metadata.route.client_generation);
    vireo_async_request_head_report_t p = resume(&w, NULL, VIREO_RESULT_NOT_FOUND);
    CHECK(p.pending_retained && !memcmp(&saved, &w.pending, sizeof saved) && readable(&w) == 0);
    p = head(&w, &m, 64, 4096, 4, NULL, VIREO_RESULT_BUSY); CHECK(!p.frame_peek_called && !p.submit_called);
    /* caller已确认旧client归还，保saved审计值后显式弃置；不是自动消费成功。 */
    w.pending = (vireo_async_request_pending_t){0}; meet(&w.r.released); world_cleanup(&w);
}
static void budget_and_admission_rejections(void) {
    world_t w; world_setup(&w, false);
    vireo_async_request_head_report_t p = head(&w, NULL, 64, 1, 4, NULL, VIREO_RESULT_RANGE);
    CHECK(p.submit_called && !p.consume_called && !w.remaining && !w.pending.frame_bytes); source_is(&w, w.wire, 35);
    EXPECT(vireo_tcp_server_request_stop(w.f.server, NULL), VIREO_OK);
    p = head(&w, NULL, 64, 4096, 4, NULL, VIREO_RESULT_CANCELLED);
    CHECK(p.submit_report.task_created && w.remaining && !p.consume_called && !w.pending.frame_bytes); world_cleanup(&w);
}
static void frame_and_flow_limits(void) {
    world_t w; world_setup(&w, false);
    vireo_async_request_head_report_t p = head(&w, NULL, 128, 4096, 4, NULL, VIREO_RESULT_RANGE);
    no_submission(p); CHECK(p.stage == VIREO_ASYNC_REQUEST_HEAD_PEEK_FRAME);
    vireo_connection_flow_options_t const flow = {32, 31, 64, 16, 48};
    EXPECT(vireo_tcp_server_client_flow_configure(w.f.server, w.f.client, &flow, NULL), VIREO_OK);
    p = head(&w, NULL, 64, 4096, 4, NULL, VIREO_RESULT_RANGE); no_submission(p);
    p = head(&w, NULL, 32, 4096, 4, NULL, VIREO_RESULT_PROTOCOL); no_submission(p);
    source_is(&w, w.wire, 35); world_cleanup(&w);
}
static void optional_cancel(void) {
    world_t w; world_setup(&w, true); start_world(&w); vireo_task_cancel_t *cancel = NULL;
    EXPECT(vireo_task_cancel_create(4096, &cancel), VIREO_OK); EXPECT(vireo_task_cancel_request(cancel), VIREO_OK);
    vireo_async_request_head_report_t const p = transfer_first(&w, NULL, cancel, VIREO_OK); meet(&w.r.entered);
    CHECK(p.submit_report.task_transferred && !w.pending.frame_bytes && readable(&w) == 0);
    EXPECT(vireo_task_cancel_destroy(&cancel), VIREO_OK);
    vireo_task_metadata_t ended; EXPECT(vireo_inflight_store_take(w.store, p.submit_report.metadata, &ended, NULL), VIREO_OK);
    meet(&w.r.released); world_cleanup(&w); CHECK(atomic_load(&w.r.cancelled) == 1);
}
static void peek_dependency_faults(void) {
    world_t w; world_setup(&w, false); model_t m = {.frames_failure = true};
    vireo_async_request_head_report_t p = head(&w, &m, 64, 4096, 4, NULL, VIREO_RESULT_INTERNAL);
    CHECK(p.frame_peek_called && !p.read_peek_called && p.stage == VIREO_ASYNC_REQUEST_HEAD_PEEK_FRAME && !m.submit_calls);
    m = (model_t){.read_failure = true}; p = head(&w, &m, 64, 4096, 4, NULL, VIREO_RESULT_INTERNAL);
    CHECK(p.frame_found && p.read_peek_called && p.stage == VIREO_ASYNC_REQUEST_HEAD_PEEK_BYTES && !m.submit_calls);
    m = (model_t){.short_read = true}; p = head(&w, &m, 64, 4096, 4, NULL, VIREO_RESULT_INTERNAL);
    CHECK(p.frame_found && !p.submit_called && !p.consume_called); source_is(&w, w.wire, 35); world_cleanup(&w);
}
static void pending_shapes_and_basic_arguments(void) {
    world_t w; world_setup(&w, false); model_t m = {.pending = &w.pending}; vireo_async_request_head_report_t p;
    vireo_task_metadata_t meta; EXPECT(vireo_inflight_metadata_make_next(w.f.server, w.f.client, 1, 9, 0, &meta, NULL), VIREO_OK);
    vireo_async_request_pending_t const bad[] = {{.metadata={.route={0}},.frame_bytes=32},{meta,0},{meta,31},{meta,16777249},
        {{.route = {1,0,1,1},.request_instance_id=1,.operation=0},35},{{.deadline_ns=1},0}};
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; ++i) {
        memcpy(&w.pending, &bad[i], sizeof w.pending);
        vireo_async_request_pending_t saved; memcpy(&saved, &w.pending, sizeof saved);
        p = head(&w, &m, 64, 4096, 4, NULL, VIREO_RESULT_INVALID_ARGUMENT); no_submission(p); CHECK(!p.frame_peek_called);
        p = resume(&w, &m, VIREO_RESULT_INVALID_ARGUMENT); CHECK(!p.consume_called && !memcmp(&saved, &w.pending, sizeof saved));
    }
    w.pending = (vireo_async_request_pending_t){0};
    for (unsigned bad_arg = 0; bad_arg < 12; ++bad_arg) {
        vireo_async_request_head_ops_t table = ops;
        if (bad_arg == 8) table.frames = NULL;
        if (bad_arg == 9) table.read = NULL;
        if (bad_arg == 10) table.submit = NULL;
        if (bad_arg == 11) table.consume = NULL;
        EXPECT(vireo_async_request_head_with_ops(bad_arg == 0 ? NULL : w.f.server, w.f.client,
            bad_arg == 1 ? NULL : w.store, bad_arg == 2 ? NULL : w.r.pool, 64, 4096, 4, 9, 0, NULL,
            bad_arg == 3 ? NULL : &w.pending, bad_arg == 4 ? NULL : &w.remaining,
            bad_arg == 5 ? NULL : &p, bad_arg == 6 ? NULL : &table, &m),
            bad_arg == 7 ? VIREO_RESULT_NOT_FOUND : VIREO_RESULT_INVALID_ARGUMENT);
        if (bad_arg == 7) EXPECT(vireo_task_destroy(&w.remaining), VIREO_OK);
    }
    size_t const caps[] = {0,31,16777249,SIZE_MAX};
    for (size_t i = 0; i < sizeof caps / sizeof caps[0]; ++i) {
        p = head(&w, &m, caps[i], 4096, 4, NULL, VIREO_RESULT_RANGE); CHECK(!p.frame_peek_called);
    }
    p = head(&w, &m, 64, 0, 4, NULL, VIREO_RESULT_INVALID_ARGUMENT); CHECK(!p.frame_peek_called);
    p = head(&w, &m, 64, 4096, 0, NULL, VIREO_RESULT_INVALID_ARGUMENT); CHECK(!p.frame_peek_called);
    EXPECT(vireo_async_request_submit_read_head(w.f.server,w.f.client,w.store,w.r.pool,64,4096,4,0,0,NULL,
        &w.pending,&w.remaining,&p), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_async_request_resume_consume(NULL,&w.pending,&p),VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_async_request_resume_consume(w.f.server,NULL,&p),VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_async_request_resume_consume(w.f.server,&w.pending,NULL),VIREO_RESULT_INVALID_ARGUMENT);
    p = head(&w, NULL, 64, 4096, 4, NULL, VIREO_RESULT_NOT_FOUND);
    vireo_task_t *saved_task = w.remaining;
    p = head(&w, NULL, 64, 4096, 4, NULL, VIREO_RESULT_INVALID_ARGUMENT); CHECK(w.remaining == saved_task && !p.frame_peek_called);
    world_cleanup(&w);
}
int main(void) {
    CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL) == 0);
    _Static_assert(VIREO_ASYNC_REQUEST_HEAD_CHECK_PENDING == 1 && VIREO_ASYNC_REQUEST_HEAD_CONSUME == 5,
        "independent stages");
    void (*const groups[])(void) = {success_single_consumed,two_frames_one_at_time,half_tail_preserved,empty_and_empty_eof,
        partial_header_and_body,protocol_and_truncated_eof,untransferred_preserves_source,gate_survives_ended_record,
        repeated_resume_errors,transferred_error_still_consumes,dual_error_priority,stopped_closing_resume,
        gone_client_pending_kept,budget_and_admission_rejections,frame_and_flow_limits,optional_cancel,
        peek_dependency_faults,pending_shapes_and_basic_arguments};
    for (size_t i = 0; i < sizeof groups / sizeof groups[0]; ++i) { size_t n = fds(); groups[i](); CHECK(fds() == n); }
    puts("async request head consume: 18 groups passed"); return 0;
}
