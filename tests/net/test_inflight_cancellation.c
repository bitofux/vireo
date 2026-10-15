/*
 * PROJECT : VIREO
 * FILE    : test_inflight_cancellation.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-13
 * BRIEF   : 表/task/caller 独立取消引用、提交退款与真实寿命
 */
#define _GNU_SOURCE
#include "net/inflight_submit_internal.h"
#include "net/inflight_cancel_internal.h"
#include <arpa/inet.h>
#include <errno.h>
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

/** 测试 worker 只持有独立任务与本地同步账本，绝不借 Reactor 资源。 */
typedef struct runner {
    vireo_thread_pool_t *pool; /**< manager 唯一拥有，join 后销毁。 */
    vireo_task_queue_t *queue; /**< 独立专用 owner，pool 销毁后释放。 */
    pthread_barrier_t entered; /**< 第一项已被领取的两方会合。 */
    pthread_barrier_t released; /**< manager 验证满/关闭后允许回调返回。 */
    bool hold_first; /**< 启动前固定；sequence 1 使用两方屏障。 */
    atomic_uint calls; /**< worker 实际执行条数，原子更新。 */
    atomic_uint cancelled; /**< worker 实际看到取消请求的条数。 */
    vireo_task_metadata_t seen[16]; /**< 单 worker 各 sequence 元数据，仅 join 后读。 */
} runner_t;

/** 仅 manager 短借的编排依赖模型，不触碰 pool/queue 的私有布局。 */
typedef struct trace {
    size_t submit_calls; /**< 本次实际提交适配次数。 */
    size_t take_calls; /**< 本次实际撤销适配次数。 */
    int mode; /**< 0 真实、1 未转移拒绝、2/3 真实转移后 WAKE/UNLOCK 模型。 */
    vireo_result_t rejection; /**< mode1 主返回，保持源。 */
    vireo_result_t take_error; /**< 非 OK 时一次撤销拒绝，保持真实表。 */
} trace_t;

static void meet(pthread_barrier_t *barrier) {
    int const result = pthread_barrier_wait(barrier);
    CHECK(result == 0 || result == PTHREAD_BARRIER_SERIAL_THREAD);
}

static vireo_result_t execute(void *context, vireo_task_t const *task) {
    runner_t *r = context;
    vireo_task_info_t info;
    vireo_task_payload_view_t view;
    CHECK(vireo_task_inspect(task, &info) == VIREO_OK);
    unsigned const seq = info.metadata.route.request_sequence;
    CHECK(seq > 0 && seq < 16 && info.metadata.operation == 9);
    CHECK(vireo_task_borrow_payload(task, &view) == VIREO_OK);
    CHECK(view.size == 3 && view.data[0] == (unsigned char)seq && view.data[1] == 0 && view.data[2] == 255);
    r->seen[seq] = info.metadata;
    (void)atomic_fetch_add(&r->calls, 1);
    if (r->hold_first && seq == 1) { meet(&r->entered); meet(&r->released); }
    bool requested = false;
    CHECK(vireo_task_is_cancel_requested(task, &requested) == VIREO_OK);
    if (requested) (void)atomic_fetch_add(&r->cancelled, 1);
    errno = EIO;
    return VIREO_OK;
}

static void prepare(runner_t *r, bool hold, size_t capacity) {
    *r = (runner_t){.hold_first = hold};
    atomic_init(&r->calls, 0); atomic_init(&r->cancelled, 0);
    CHECK(pthread_barrier_init(&r->entered, NULL, 2) == 0);
    CHECK(pthread_barrier_init(&r->released, NULL, 2) == 0);
    vireo_task_queue_options_t const q = {capacity, 65536};
    vireo_thread_pool_options_t const p = {1, 65536};
    CHECK(vireo_task_queue_create(&q, &r->queue) == VIREO_OK);
    CHECK(vireo_task_queue_prepare_wait(r->queue) == VIREO_OK);
    CHECK(vireo_thread_pool_create(&p, &r->pool) == VIREO_OK);
    vireo_thread_pool_configuration_t const c = {r->queue, execute, r};
    CHECK(vireo_thread_pool_configure(r->pool, &c, NULL) == VIREO_OK);
}

static void start(runner_t *r) {
    vireo_thread_pool_report_t report;
    CHECK(vireo_thread_pool_start(r->pool, &report) == VIREO_OK);
    CHECK(vireo_thread_pool_enable_execution(r->pool, &report) == VIREO_OK);
}

/** caller 明确选择的有限重试，仅用于测试管理竞争，不属于产品入口。 */
static void close_queue(runner_t *r, vireo_task_queue_state_t mode) {
    vireo_task_queue_close_report_t report;
    for (size_t i = 0; i < 100000; ++i) {
        vireo_result_t const result = vireo_task_queue_close(r->queue, mode, &report);
        if (result == VIREO_OK) return;
        CHECK(result == VIREO_RESULT_BUSY && !report.changed);
        sched_yield();
    }
    CHECK(false);
}

static void finish_runner(runner_t *r, bool started) {
    if (started) {
        close_queue(r, VIREO_TASK_QUEUE_DRAIN);
        vireo_thread_pool_report_t report;
        vireo_result_t result = VIREO_RESULT_BUSY;
        for (size_t i = 0; i < 100000 && result == VIREO_RESULT_BUSY; ++i) {
            result = vireo_thread_pool_stop_and_join(r->pool, &report);
            if (result == VIREO_RESULT_BUSY) sched_yield();
        }
        CHECK(result == VIREO_OK);
    }
    CHECK(vireo_thread_pool_destroy(&r->pool) == VIREO_OK);
    CHECK(vireo_task_queue_destroy(&r->queue) == VIREO_OK);
    CHECK(pthread_barrier_destroy(&r->entered) == 0);
    CHECK(pthread_barrier_destroy(&r->released) == 0);
}

static vireo_inflight_store_t *store_create(size_t capacity) {
    vireo_inflight_store_t *store = NULL;
    vireo_inflight_store_options_t const options = {capacity, 65536};
    CHECK(vireo_inflight_store_create(&options, &store) == VIREO_OK);
    return store;
}

static vireo_task_t *task_create(fixture_t *f, unsigned seq, uint64_t deadline,
    vireo_task_cancel_t *cancel, vireo_task_metadata_t *metadata) {
    CHECK(vireo_inflight_metadata_make_next(f->server, f->client, seq, 9, deadline, metadata, NULL) == VIREO_OK);
    unsigned char data[] = {(unsigned char)seq, 0, 255};
    vireo_task_t *task = NULL;
    CHECK((cancel == NULL ? vireo_task_create_copy(*metadata, data, sizeof data, 65536, &task) :
        vireo_task_create_copy_with_cancel(*metadata, data, sizeof data, 65536, cancel, &task)) == VIREO_OK);
    data[0] = 99;
    return task;
}

static bool same(vireo_task_metadata_t a, vireo_task_metadata_t b) {
    return a.route.client_owner_id == b.route.client_owner_id &&
        a.route.client_slot_index == b.route.client_slot_index &&
        a.route.client_generation == b.route.client_generation &&
        a.route.request_sequence == b.route.request_sequence &&
        a.request_instance_id == b.request_instance_id && a.operation == b.operation && a.deadline_ns == b.deadline_ns;
}

static void count_is(vireo_inflight_store_t *store, size_t count) {
    vireo_inflight_store_info_t info;
    CHECK(vireo_inflight_store_inspect(store, &info) == VIREO_OK && info.count == count);
}

static void remove_record(vireo_inflight_store_t *store, vireo_task_metadata_t key) {
    vireo_task_metadata_t record;
    CHECK(vireo_inflight_store_get(store, key, &record, NULL) == VIREO_OK && same(record, key));
    CHECK(vireo_inflight_store_take(store, key, &record, NULL) == VIREO_OK && same(record, key));
}

static vireo_result_t submit_model(void *context, vireo_thread_pool_t *pool,
    vireo_task_t **owner, vireo_thread_pool_submit_report_t *report) {
    trace_t *t = context;
    ++t->submit_calls;
    errno = ENOSPC;
    if (t->mode == 1) {
        *report = (vireo_thread_pool_submit_report_t){VIREO_THREAD_POOL_SUBMIT_STAGE_CHECK_POOL, false, {0}};
        return t->rejection;
    }
    vireo_result_t result = vireo_thread_pool_try_submit(pool, owner, report);
    if (result == VIREO_OK && (t->mode == 2 || t->mode == 3)) {
        report->stage = VIREO_THREAD_POOL_SUBMIT_STAGE_SUBMIT_QUEUE;
        report->queue_report.stage = t->mode == 2 ? VIREO_TASK_QUEUE_STAGE_WAKE : VIREO_TASK_QUEUE_STAGE_UNLOCK;
        report->queue_report.pthread_error = EIO;
        return VIREO_RESULT_INTERNAL;
    }
    return result;
}

static vireo_result_t take_model(void *context, vireo_inflight_store_t *store,
    vireo_task_metadata_t key, vireo_task_metadata_t *out, vireo_inflight_stage_t *stage) {
    trace_t *t = context;
    ++t->take_calls;
    errno = ENOMEM;
    if (t->take_error != VIREO_OK) { *stage = VIREO_INFLIGHT_CHECK_RECORD; return t->take_error; }
    return vireo_inflight_store_take(store, key, out, stage);
}

static vireo_result_t call(fixture_t *f, runner_t *r, vireo_inflight_store_t *store,
    size_t limit, vireo_task_t **task, trace_t *trace, vireo_inflight_submit_report_t *report) {
    errno = EDOM;
    vireo_result_t result;
    if (trace != NULL) {
        vireo_inflight_submit_operations_t const ops = {trace, submit_model, take_model};
        result = vireo_inflight_store_try_submit_with_operations(store, f->server, r->pool,
            limit, task, &ops, report);
    } else result = vireo_inflight_store_try_submit(store, f->server, r->pool, limit, task, report);
    CHECK(errno == EDOM);
    return result;
}

/** caller 重试只针对原任务未转移且本次登记已退款的 BUSY。 */
static vireo_result_t call_until_not_busy(fixture_t *f, runner_t *r, vireo_inflight_store_t *store,
    vireo_task_t **task, trace_t *trace, vireo_inflight_submit_report_t *report) {
    for (size_t i = 0; i < 100000; ++i) {
        vireo_result_t result = call(f, r, store, 8, task, trace, report);
        if (result != VIREO_RESULT_BUSY) return result;
        CHECK(*task != NULL && !report->pool_report.queue_report.transferred &&
            report->rollback_called && report->rollback_result == VIREO_OK && !report->record_retained);
        sched_yield();
    }
    CHECK(false); return VIREO_RESULT_INTERNAL;
}

_Static_assert(VIREO_INFLIGHT_RETAIN_CANCEL == 8 && VIREO_INFLIGHT_RELEASE_CANCEL == 9,
    "new cancellation stages");

/** 本核心引用耗尽模型，脚本只由 manager 使用，不修改共享状态私有计数。 */
typedef struct retain_trace {
    size_t task_calls; /**< 实际 task retain 适配次数。 */
    size_t cancel_calls; /**< 实际状态 retain 适配次数。 */
    bool fail_task; /**< true 注入 OVERFLOW，保持任务、表与输出。 */
    bool fail_cancel; /**< true 注入 OVERFLOW，保持表份及输出。 */
} retain_trace_t;

static vireo_result_t retain_task_model(void *context, vireo_task_t const *task,
    vireo_task_cancel_t **out) {
    retain_trace_t *t = context; ++t->task_calls; errno = ENOMEM;
    return t->fail_task ? VIREO_RESULT_OVERFLOW : vireo_task_retain_cancel(task, out);
}

static vireo_result_t retain_cancel_model(void *context, vireo_task_cancel_t *cancel,
    vireo_task_cancel_t **out) {
    retain_trace_t *t = context; ++t->cancel_calls; errno = ENOSPC;
    return t->fail_cancel ? VIREO_RESULT_OVERFLOW : vireo_task_cancel_retain(cancel, out);
}

static void register_is(fixture_t *f, vireo_inflight_store_t *store,
    vireo_task_t *task, size_t limit, vireo_result_t expected, vireo_inflight_stage_t expected_stage) {
    vireo_inflight_stage_t stage = VIREO_INFLIGHT_MAKE_ROUTE; errno = EDOM;
    CHECK(vireo_inflight_store_register_task_limited(store, f->server, task, limit, &stage) == expected);
    CHECK(errno == EDOM && stage == expected_stage);
}

static void retain_is(vireo_inflight_store_t *store, vireo_task_metadata_t key,
    vireo_task_cancel_t **owner, vireo_result_t expected, vireo_inflight_stage_t expected_stage) {
    vireo_inflight_stage_t stage = VIREO_INFLIGHT_MAKE_ROUTE;
    unsigned char before[sizeof *owner]; memcpy(before, owner, sizeof *owner);
    errno = EDOM;
    CHECK(vireo_inflight_store_retain_cancel(store, key, owner, &stage) == expected);
    CHECK(errno == EDOM && stage == expected_stage);
    if (expected != VIREO_OK) CHECK(memcmp(before, owner, sizeof *owner) == 0);
}

static bool optional_and_numeric(void) {
    fixture_t f; CHECK(setup(&f)); vireo_inflight_store_t *store = store_create(8);
    vireo_task_metadata_t a, b;
    vireo_task_t *ta = task_create(&f, 1, 0, NULL, &a);
    register_is(&f, store, ta, 8, VIREO_OK, VIREO_INFLIGHT_NONE);
    vireo_task_cancel_t *ref = NULL;
    retain_is(store, a, &ref, VIREO_RESULT_NOT_FOUND, VIREO_INFLIGHT_RETAIN_CANCEL);
    CHECK(vireo_task_destroy(&ta) == VIREO_OK); remove_record(store, a);
    vireo_task_cancel_t *cancel = NULL; CHECK(vireo_task_cancel_create(65536, &cancel) == VIREO_OK);
    vireo_task_t *tb = task_create(&f, 2, UINT64_MAX, cancel, &b);
    CHECK(vireo_inflight_store_register_limited(store, f.server, b, 8, NULL) == VIREO_OK);
    retain_is(store, b, &ref, VIREO_RESULT_NOT_FOUND, VIREO_INFLIGHT_RETAIN_CANCEL);
    remove_record(store, b);
    CHECK(vireo_inflight_store_register(store, f.server, b, NULL) == VIREO_OK);
    retain_is(store, b, &ref, VIREO_RESULT_NOT_FOUND, VIREO_INFLIGHT_RETAIN_CANCEL);
    CHECK(vireo_task_destroy(&tb) == VIREO_OK && vireo_task_cancel_destroy(&cancel) == VIREO_OK);
    remove_record(store, b); count_is(store, 0);
    CHECK(vireo_inflight_store_destroy(&store) == VIREO_OK); return cleanup(&f);
}

static bool last_table_reference(void) {
    fixture_t f; CHECK(setup(&f)); vireo_inflight_store_t *store = store_create(8);
    vireo_task_cancel_t *cancel = NULL; CHECK(vireo_task_cancel_create(65536, &cancel) == VIREO_OK);
    vireo_task_metadata_t key; vireo_task_t *task = task_create(&f, 1, 0, cancel, &key);
    register_is(&f, store, task, 8, VIREO_OK, VIREO_INFLIGHT_NONE);
    CHECK(vireo_task_cancel_destroy(&cancel) == VIREO_OK && vireo_task_destroy(&task) == VIREO_OK);
    CHECK(vireo_inflight_store_destroy(&store) == VIREO_RESULT_BUSY && store != NULL);
    CHECK(release_client(&f));
    vireo_task_metadata_t changed = key; changed.operation = 123; changed.deadline_ns = UINT64_MAX;
    vireo_task_cancel_t *ref = NULL;
    retain_is(store, changed, &ref, VIREO_OK, VIREO_INFLIGHT_NONE);
    bool requested = true; CHECK(vireo_task_cancel_is_requested(ref, &requested) == VIREO_OK && !requested);
    remove_record(store, key);
    vireo_task_cancel_t *missing = NULL;
    retain_is(store, key, &missing, VIREO_RESULT_NOT_FOUND, VIREO_INFLIGHT_CHECK_RECORD);
    CHECK(vireo_inflight_store_destroy(&store) == VIREO_OK);
    CHECK(vireo_task_cancel_request(ref) == VIREO_OK);
    CHECK(vireo_task_cancel_is_requested(ref, &requested) == VIREO_OK && requested);
    CHECK(vireo_task_cancel_destroy(&ref) == VIREO_OK && ref == NULL); return cleanup(&f);
}

static bool take_does_not_cancel(void) {
    fixture_t f; CHECK(setup(&f)); vireo_inflight_store_t *store = store_create(8);
    vireo_task_cancel_t *cancel = NULL; CHECK(vireo_task_cancel_create(65536, &cancel) == VIREO_OK);
    vireo_task_metadata_t key; vireo_task_t *task = task_create(&f, 1, UINT64_MAX, cancel, &key);
    register_is(&f, store, task, 8, VIREO_OK, VIREO_INFLIGHT_NONE);
    CHECK(vireo_task_cancel_destroy(&cancel) == VIREO_OK);
    remove_record(store, key); CHECK(vireo_inflight_store_destroy(&store) == VIREO_OK);
    bool requested = true; CHECK(vireo_task_is_cancel_requested(task, &requested) == VIREO_OK && !requested);
    vireo_task_cancel_t *task_ref = NULL; CHECK(vireo_task_retain_cancel(task, &task_ref) == VIREO_OK);
    CHECK(vireo_task_destroy(&task) == VIREO_OK);
    CHECK(vireo_task_cancel_request(task_ref) == VIREO_OK);
    CHECK(vireo_task_cancel_is_requested(task_ref, &requested) == VIREO_OK && requested);
    CHECK(vireo_task_cancel_destroy(&task_ref) == VIREO_OK); return cleanup(&f);
}

static bool basic_and_output_priority(void) {
    fixture_t f; CHECK(setup(&f)); vireo_inflight_store_t *store = store_create(8);
    vireo_task_cancel_t *cancel = NULL; CHECK(vireo_task_cancel_create(65536, &cancel) == VIREO_OK);
    vireo_task_metadata_t key; vireo_task_t *task = task_create(&f, 1, 0, cancel, &key);
    for (unsigned i = 0; i < 4; ++i) {
        vireo_inflight_stage_t stage = VIREO_INFLIGHT_RETAIN_CANCEL; errno = EDOM;
        CHECK(vireo_inflight_store_register_task_limited(i == 0 ? NULL : store,
            i == 1 ? NULL : f.server, i == 2 ? NULL : task, i == 3 ? 0 : 8, &stage)
            == VIREO_RESULT_INVALID_ARGUMENT && errno == EDOM && stage == VIREO_INFLIGHT_NONE);
    }
    vireo_task_cancel_t *ref = NULL;
    retain_is(NULL, key, &ref, VIREO_RESULT_INVALID_ARGUMENT, VIREO_INFLIGHT_NONE);
    retain_is(store, (vireo_task_metadata_t){0}, &ref, VIREO_RESULT_INVALID_ARGUMENT, VIREO_INFLIGHT_CHECK_METADATA);
    retain_is(store, key, &ref, VIREO_RESULT_NOT_FOUND, VIREO_INFLIGHT_CHECK_RECORD);
    retain_is(store, (vireo_task_metadata_t){0}, &cancel, VIREO_RESULT_INVALID_ARGUMENT, VIREO_INFLIGHT_NONE);
    vireo_inflight_stage_t stage = VIREO_INFLIGHT_CHECK_RECORD; errno = EDOM;
    CHECK(vireo_inflight_store_retain_cancel(store, key, NULL, &stage) == VIREO_RESULT_INVALID_ARGUMENT &&
        errno == EDOM && stage == VIREO_INFLIGHT_NONE);
    register_is(&f, store, task, 9, VIREO_RESULT_RANGE, VIREO_INFLIGHT_CHECK_RECORD);
    count_is(store, 0);
    CHECK(vireo_inflight_store_register_task_limited(store, f.server, task, 8, NULL) == VIREO_OK);
    CHECK(vireo_inflight_store_retain_cancel(store, key, &ref, NULL) == VIREO_OK);
    CHECK(vireo_task_cancel_destroy(&ref) == VIREO_OK); remove_record(store, key);
    CHECK(vireo_task_destroy(&task) == VIREO_OK && vireo_task_cancel_destroy(&cancel) == VIREO_OK &&
        vireo_inflight_store_destroy(&store) == VIREO_OK); return cleanup(&f);
}

static bool admission_before_retaining(void) {
    fixture_t f; CHECK(setup(&f)); vireo_inflight_store_t *store = store_create(1);
    vireo_task_cancel_t *cancel = NULL; CHECK(vireo_task_cancel_create(65536, &cancel) == VIREO_OK);
    vireo_task_metadata_t a, b; vireo_task_t *ta = task_create(&f, 1, 0, cancel, &a);
    vireo_task_t *tb = task_create(&f, 2, 0, cancel, &b);
    retain_trace_t t = {.fail_task = true};
    vireo_inflight_cancel_operations_t const ops = {&t, retain_task_model, retain_cancel_model};
    vireo_inflight_stage_t stage; errno = EDOM;
    CHECK(vireo_inflight_store_register_task_limited_with_operations(store, f.server, ta, 1, &ops, &stage)
        == VIREO_RESULT_OVERFLOW && errno == EDOM && stage == VIREO_INFLIGHT_RETAIN_CANCEL);
    CHECK(t.task_calls == 1); count_is(store, 0);
    register_is(&f, store, ta, 1, VIREO_OK, VIREO_INFLIGHT_NONE);
    CHECK(vireo_inflight_store_register_task_limited_with_operations(store, f.server, ta, 1, &ops, &stage)
        == VIREO_RESULT_BUSY && stage == VIREO_INFLIGHT_CHECK_RECORD);
    CHECK(vireo_inflight_store_register_task_limited_with_operations(store, f.server, tb, 1, &ops, &stage)
        == VIREO_RESULT_BUSY && stage == VIREO_INFLIGHT_CHECK_RECORD);
    CHECK(vireo_inflight_store_register_task_limited_with_operations(store, f.server, tb, 2, &ops, &stage)
        == VIREO_RESULT_RANGE && stage == VIREO_INFLIGHT_CHECK_RECORD);
    CHECK(vireo_tcp_server_request_stop(f.server, NULL) == VIREO_OK);
    CHECK(vireo_inflight_store_register_task_limited_with_operations(store, f.server, tb, 1, &ops, &stage)
        == VIREO_RESULT_CANCELLED && stage == VIREO_INFLIGHT_CHECK_SERVER);
    CHECK(vireo_inflight_store_register_task_limited_with_operations(store, f.other_server, tb, 1, &ops, &stage)
        == VIREO_RESULT_INVALID_ARGUMENT && stage == VIREO_INFLIGHT_CHECK_CLIENT);
    CHECK(t.task_calls == 1 && t.cancel_calls == 0); remove_record(store, a);
    CHECK(vireo_task_destroy(&ta) == VIREO_OK && vireo_task_destroy(&tb) == VIREO_OK &&
        vireo_task_cancel_destroy(&cancel) == VIREO_OK && vireo_inflight_store_destroy(&store) == VIREO_OK);
    return cleanup(&f);
}

static bool retained_output_overflow_and_seam(void) {
    fixture_t f; CHECK(setup(&f)); vireo_inflight_store_t *store = store_create(8);
    vireo_task_cancel_t *cancel = NULL; CHECK(vireo_task_cancel_create(65536, &cancel) == VIREO_OK);
    vireo_task_metadata_t key; vireo_task_t *task = task_create(&f, 1, 0, cancel, &key);
    register_is(&f, store, task, 8, VIREO_OK, VIREO_INFLIGHT_NONE);
    retain_trace_t t = {.fail_cancel = true};
    vireo_inflight_cancel_operations_t const ops = {&t, retain_task_model, retain_cancel_model};
    vireo_task_cancel_t *ref = NULL; vireo_inflight_stage_t stage; errno = EDOM;
    CHECK(vireo_inflight_store_retain_cancel_with_operations(store, key, &ref, &ops, &stage)
        == VIREO_RESULT_OVERFLOW && errno == EDOM && ref == NULL && stage == VIREO_INFLIGHT_RETAIN_CANCEL);
    CHECK(t.task_calls == 0 && t.cancel_calls == 1); count_is(store, 1);
    for (unsigned i = 0; i < 3; ++i) {
        vireo_inflight_cancel_operations_t bad = ops;
        if (i == 1) bad.retain_task = NULL;
        if (i == 2) bad.retain_cancel = NULL;
        errno = EDOM;
        CHECK(vireo_inflight_store_register_task_limited_with_operations(store, f.server, task, 8,
            i == 0 ? NULL : &bad, &stage) == VIREO_RESULT_INVALID_ARGUMENT && errno == EDOM && stage == VIREO_INFLIGHT_NONE);
        CHECK(vireo_inflight_store_retain_cancel_with_operations(store, key, &ref,
            i == 0 ? NULL : &bad, &stage) == VIREO_RESULT_INVALID_ARGUMENT && errno == EDOM && ref == NULL && stage == VIREO_INFLIGHT_NONE);
    }
    retain_is(store, key, &ref, VIREO_OK, VIREO_INFLIGHT_NONE);
    remove_record(store, key); CHECK(vireo_task_destroy(&task) == VIREO_OK && vireo_task_cancel_destroy(&cancel) == VIREO_OK);
    bool requested = true; CHECK(vireo_task_cancel_is_requested(ref, &requested) == VIREO_OK && !requested);
    CHECK(vireo_task_cancel_destroy(&ref) == VIREO_OK && vireo_inflight_store_destroy(&store) == VIREO_OK);
    return cleanup(&f);
}

static bool budget_and_slot_reuse(void) {
    fixture_t f; CHECK(setup(&f)); vireo_inflight_store_t *store = store_create(1);
    vireo_inflight_store_info_t info; CHECK(vireo_inflight_store_inspect(store, &info) == VIREO_OK);
    CHECK(vireo_inflight_store_destroy(&store) == VIREO_OK);
    vireo_inflight_store_options_t options = {1, info.allocated_bytes - 1};
    CHECK(vireo_inflight_store_create(&options, &store) == VIREO_RESULT_RANGE && store == NULL);
    options.max_memory_bytes = info.allocated_bytes;
    CHECK(vireo_inflight_store_create(&options, &store) == VIREO_OK);
    vireo_task_cancel_t *cancel = NULL; CHECK(vireo_task_cancel_create(65536, &cancel) == VIREO_OK);
    vireo_task_metadata_t a, b; vireo_task_t *ta = task_create(&f, 1, 0, cancel, &a);
    register_is(&f, store, ta, 1, VIREO_OK, VIREO_INFLIGHT_NONE); remove_record(store, a);
    CHECK(vireo_task_destroy(&ta) == VIREO_OK && vireo_task_cancel_destroy(&cancel) == VIREO_OK);
    vireo_task_t *tb = task_create(&f, 2, UINT64_MAX, NULL, &b);
    register_is(&f, store, tb, 1, VIREO_OK, VIREO_INFLIGHT_NONE);
    vireo_task_cancel_t *ref = NULL;
    retain_is(store, b, &ref, VIREO_RESULT_NOT_FOUND, VIREO_INFLIGHT_RETAIN_CANCEL);
    remove_record(store, b); CHECK(vireo_task_destroy(&tb) == VIREO_OK && vireo_inflight_store_destroy(&store) == VIREO_OK);
    return cleanup(&f);
}

static bool real_worker_cancellation(void) {
    fixture_t f; CHECK(setup(&f)); runner_t r; prepare(&r, true, 1); start(&r);
    vireo_inflight_store_t *store = store_create(8);
    vireo_task_cancel_t *cancel = NULL; CHECK(vireo_task_cancel_create(65536, &cancel) == VIREO_OK);
    vireo_task_metadata_t key; vireo_task_t *task = task_create(&f, 1, 0, cancel, &key);
    CHECK(vireo_task_cancel_destroy(&cancel) == VIREO_OK);
    vireo_inflight_submit_report_t report;
    CHECK(call_until_not_busy(&f, &r, store, &task, NULL, &report) == VIREO_OK && task == NULL && report.record_retained);
    meet(&r.entered);
    vireo_task_cancel_t *ref = NULL;
    retain_is(store, report.metadata, &ref, VIREO_OK, VIREO_INFLIGHT_NONE);
    CHECK(vireo_task_cancel_request(ref) == VIREO_OK);
    remove_record(store, key); count_is(store, 0);
    CHECK(vireo_inflight_store_destroy(&store) == VIREO_OK);
    meet(&r.released); finish_runner(&r, true);
    CHECK(atomic_load(&r.calls) == 1 && atomic_load(&r.cancelled) == 1 && same(r.seen[1], key));
    bool requested = false; CHECK(vireo_task_cancel_is_requested(ref, &requested) == VIREO_OK && requested);
    CHECK(vireo_task_cancel_destroy(&ref) == VIREO_OK); return cleanup(&f);
}

static bool submission_refund_ownership(void) {
    fixture_t f; CHECK(setup(&f)); runner_t r; prepare(&r, false, 1);
    vireo_inflight_store_t *store = store_create(8);
    vireo_task_cancel_t *cancel = NULL; CHECK(vireo_task_cancel_create(65536, &cancel) == VIREO_OK);
    vireo_task_metadata_t key; vireo_task_t *task = task_create(&f, 1, 0, cancel, &key), *original = task;
    CHECK(vireo_task_cancel_destroy(&cancel) == VIREO_OK);
    trace_t trace = {.mode = 1, .rejection = VIREO_RESULT_BUSY};
    vireo_inflight_submit_report_t report;
    CHECK(call(&f, &r, store, 8, &task, &trace, &report) == VIREO_RESULT_BUSY && task == original);
    CHECK(report.rollback_called && !report.record_retained && trace.submit_calls == 1 && trace.take_calls == 1);
    vireo_task_cancel_t *ref = NULL;
    retain_is(store, key, &ref, VIREO_RESULT_NOT_FOUND, VIREO_INFLIGHT_CHECK_RECORD);
    bool requested = true; CHECK(vireo_task_is_cancel_requested(task, &requested) == VIREO_OK && !requested);
    trace.take_error = VIREO_RESULT_INTERNAL;
    CHECK(call(&f, &r, store, 8, &task, &trace, &report) == VIREO_RESULT_BUSY && task == original);
    CHECK(report.record_retained && report.rollback_result == VIREO_RESULT_INTERNAL);
    retain_is(store, key, &ref, VIREO_OK, VIREO_INFLIGHT_NONE);
    CHECK(vireo_task_cancel_request(ref) == VIREO_OK);
    CHECK(vireo_task_is_cancel_requested(task, &requested) == VIREO_OK && requested);
    remove_record(store, key); CHECK(vireo_task_destroy(&task) == VIREO_OK);
    CHECK(vireo_task_cancel_is_requested(ref, &requested) == VIREO_OK && requested);
    CHECK(vireo_task_cancel_destroy(&ref) == VIREO_OK && vireo_inflight_store_destroy(&store) == VIREO_OK);
    finish_runner(&r, false); return cleanup(&f);
}

static bool transferred_error_preserves_reference(void) {
    for (int mode = 2; mode <= 3; ++mode) {
        fixture_t f; CHECK(setup(&f)); runner_t r; prepare(&r, false, 1); start(&r);
        vireo_inflight_store_t *store = store_create(8);
        vireo_task_cancel_t *cancel = NULL; CHECK(vireo_task_cancel_create(65536, &cancel) == VIREO_OK);
        vireo_task_metadata_t key; vireo_task_t *task = task_create(&f, 1, UINT64_MAX, cancel, &key);
        CHECK(vireo_task_cancel_destroy(&cancel) == VIREO_OK);
        trace_t trace = {.mode = mode}; vireo_inflight_submit_report_t report;
        CHECK(call_until_not_busy(&f, &r, store, &task, &trace, &report) == VIREO_RESULT_INTERNAL);
        CHECK(task == NULL && report.record_retained && !report.rollback_called && report.pool_report.queue_report.transferred);
        CHECK(trace.take_calls == trace.submit_calls - 1);
        finish_runner(&r, true); CHECK(atomic_load(&r.calls) == 1);
        vireo_task_cancel_t *ref = NULL; retain_is(store, key, &ref, VIREO_OK, VIREO_INFLIGHT_NONE);
        remove_record(store, key); CHECK(vireo_inflight_store_destroy(&store) == VIREO_OK);
        bool requested = true; CHECK(vireo_task_cancel_is_requested(ref, &requested) == VIREO_OK && !requested);
        CHECK(vireo_task_cancel_request(ref) == VIREO_OK && vireo_task_cancel_destroy(&ref) == VIREO_OK); CHECK(cleanup(&f));
    }
    return true;
}

int main(void) {
    int old_cancel; CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &old_cancel) == 0);
    struct { char const *name; bool (*run)(void); } const tests[] = {
        {"optional_and_numeric", optional_and_numeric},
        {"last_table_reference", last_table_reference},
        {"take_does_not_cancel", take_does_not_cancel},
        {"basic_and_output_priority", basic_and_output_priority},
        {"admission_before_retaining", admission_before_retaining},
        {"retained_output_overflow_and_seam", retained_output_overflow_and_seam},
        {"budget_and_slot_reuse", budget_and_slot_reuse},
        {"real_worker_cancellation", real_worker_cancellation},
        {"submission_refund_ownership", submission_refund_ownership},
        {"transferred_error_preserves_reference", transferred_error_preserves_reference}
    };
    for (size_t i = 0; i < sizeof tests / sizeof tests[0]; ++i) {
        CHECK(tests[i].run()); printf("[PASS] %s\n", tests[i].name);
    }
    CHECK(pthread_setcancelstate(old_cancel, NULL) == 0); printf("10 groups passed\n"); return 0;
}
