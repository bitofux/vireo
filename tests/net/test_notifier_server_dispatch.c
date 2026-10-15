/*
 * PROJECT : VIREO
 * FILE    : test_notifier_server_dispatch.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-14
 * BRIEF   : 真实服务安全窗口/有界完成消费/续提示及本层失败前缀
 */
#define _GNU_SOURCE
#include <vireo/net/notifier_server.h>
#include "notifier_server_dispatch_internal.h"
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define CHECK(c) do { if (!(c)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #c); exit(1); } } while (0)
#define EXPECT(call, expected) do { errno = EDOM; CHECK((call) == (expected)); CHECK(errno == EDOM); } while (0)
_Static_assert(VIREO_NOTIFIER_SERVER_DISPATCH_NONE == 0 &&
    VIREO_NOTIFIER_SERVER_DISPATCH_TAKE_READY == 1 &&
    VIREO_NOTIFIER_SERVER_DISPATCH_CHECK_READY == 2 &&
    VIREO_NOTIFIER_SERVER_DISPATCH_DISPATCH == 3, "independent stages");

/** 独占公开资源 owner，关闭注册借用后才 destroy notifier。 */
typedef struct fixture {
    vireo_tcp_server_t *server; /**< 当前客户及 listener 的资源根 owner。 */
    vireo_connection_pool_lease_t client; /**< 当前客户数值身份，不保活。 */
    int peer; /**< caller 对端 owner，-1 为空。 */
    vireo_completion_queue_t *queue; /**< 真实完成队列 owner，cleanup 先收回余项。 */
    vireo_inflight_store_t *store; /**< 真实在途表 owner，cleanup 先退所有剩余记录。 */
    vireo_notifier_t *notifier; /**< 提示 fd 唯一 owner。 */
    vireo_event_loop_handle_t handle; /**< READ 注册身份，成功 DEL 清空。 */
} fixture_t;

/** 单 Reactor 交付记录，不保存借用 completion 指针。 */
typedef struct delivery_context {
    vireo_inflight_store_t *store; /**< 原表短借，检查先退登记。 */
    size_t calls; /**< 实际交付次数，本测试最多八次。 */
    uint32_t seen[8]; /**< 按值保存标签，检查 FIFO/不重放。 */
    uint32_t fail_sequence; /**< 非零标签选择真实回调失败。 */
    vireo_result_t fail_result; /**< 该次回调返回原错误。 */
} delivery_context_t;

static size_t fd_count(void) {
    DIR *d = opendir("/proc/self/fd"); CHECK(d != NULL); int const own = dirfd(d);
    size_t n = 0; struct dirent *entry;
    while ((entry = readdir(d)) != NULL) {
        if (entry->d_name[0] == '.') continue;
        char *end; long const fd = strtol(entry->d_name, &end, 10); CHECK(*end == '\0');
        if (fd != own) ++n;
    }
    CHECK(closedir(d) == 0); return n;
}

static void setup(fixture_t *f) {
    *f = (fixture_t){.peer = -1};
    vireo_tcp_server_options_t const server_options = {1, 2, VIREO_TCP_SERVER_MAX_MEMORY, 256};
    EXPECT(vireo_tcp_server_create_with_auxiliary_capacity(&server_options, 1, &f->server, NULL), VIREO_OK);
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0); CHECK(fd >= 0);
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    CHECK(bind(fd, (struct sockaddr const *)&address, sizeof address) == 0 && listen(fd, 4) == 0);
    socklen_t length = sizeof address; CHECK(getsockname(fd, (struct sockaddr *)&address, &length) == 0);
    vireo_acceptor_t *listener = NULL; vireo_acceptor_options_t const listener_options = {VIREO_ACCEPTOR_MAX_MEMORY};
    EXPECT(vireo_acceptor_create(&listener_options, &fd, &listener, NULL), VIREO_OK);
    EXPECT(vireo_tcp_server_adopt_listener(f->server, &listener, NULL), VIREO_OK); CHECK(fd == -1 && listener == NULL);
    f->peer = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0); CHECK(f->peer >= 0);
    CHECK(connect(f->peer, (struct sockaddr const *)&address, sizeof address) == 0);
    vireo_connection_options_t const connection_options = {64, 64, 128};
    vireo_tcp_server_admit_budget_t const admit_budget = {1, 1}; vireo_tcp_server_admit_info_t admitted;
    EXPECT(vireo_tcp_server_admit_batch(f->server, &connection_options, &admit_budget,
        &f->client, 1, &admitted, NULL), VIREO_OK); CHECK(admitted.admitted_count == 1);
    vireo_inflight_store_options_t const store_options = {8, 65536};
    EXPECT(vireo_inflight_store_create(&store_options, &f->store), VIREO_OK);
    vireo_completion_queue_options_t const queue_options = {8, VIREO_COMPLETION_QUEUE_MAX_ALLOCATION_BYTES};
    EXPECT(vireo_completion_queue_create(&queue_options, &f->queue), VIREO_OK);
    vireo_notifier_options_t const notifier_options = {4096};
    EXPECT(vireo_notifier_create(&notifier_options, &f->notifier, NULL), VIREO_OK);
    EXPECT(vireo_notifier_server_register(f->server, f->notifier, &f->handle, NULL), VIREO_OK);
    EXPECT(vireo_tcp_server_bind_listener(f->server, true, NULL), VIREO_OK);
    vireo_tcp_server_admission_options_t const policy = {{64, 64, 128}, {48, 47, 48, 16, 48}};
    EXPECT(vireo_tcp_server_admission_configure(f->server, &policy, NULL), VIREO_OK);
}

static vireo_task_metadata_t request_make(fixture_t *f, uint32_t sequence) {
    vireo_task_metadata_t request;
    EXPECT(vireo_inflight_metadata_make_next(f->server, f->client, sequence, 9, UINT64_MAX,
        &request, NULL), VIREO_OK); return request;
}

static vireo_completion_t *completion_make(vireo_task_metadata_t request) {
    vireo_completion_metadata_t metadata;
    EXPECT(vireo_completion_metadata_make(request, VIREO_RESULT_DATABASE, VIREO_STATUS_INTERNAL_ERROR,
        &metadata), VIREO_OK);
    unsigned char const payload[] = {0, 255, 42}; vireo_completion_t *owner = NULL;
    EXPECT(vireo_completion_create_copy(metadata, payload, sizeof payload, 65536, &owner), VIREO_OK);
    return owner;
}

static void notify(fixture_t *f) {
    vireo_notifier_notify_outcome_t outcome;
    EXPECT(vireo_notifier_notify(f->notifier, &outcome, NULL), VIREO_OK);
    CHECK(outcome == VIREO_NOTIFIER_NOTIFY_INCREMENTED);
}

static void publish(fixture_t *f, uint32_t sequence, bool record, bool hint) {
    vireo_task_metadata_t const request = request_make(f, sequence);
    if (record) EXPECT(vireo_inflight_store_register(f->store, f->server, request, NULL), VIREO_OK);
    vireo_completion_t *owner = completion_make(request); vireo_completion_queue_transfer_report_t report;
    EXPECT(vireo_completion_queue_try_push(f->queue, &owner, &report), VIREO_OK);
    CHECK(owner == NULL && report.transferred); if (hint) notify(f);
}

static void discard(fixture_t *f, vireo_completion_t **owner) {
    CHECK(*owner != NULL); vireo_completion_info_t info; EXPECT(vireo_completion_inspect(*owner, &info), VIREO_OK);
    vireo_task_metadata_t record;
    vireo_result_t result = vireo_inflight_store_take(f->store, info.metadata.request, &record, NULL);
    CHECK(result == VIREO_OK || result == VIREO_RESULT_NOT_FOUND);
    EXPECT(vireo_completion_destroy(owner), VIREO_OK); CHECK(*owner == NULL);
}

static void cleanup(fixture_t *f) {
    if (f->handle.loop_id != 0) EXPECT(vireo_notifier_server_unregister(f->server, &f->handle, NULL), VIREO_OK);
    for (;;) {
        vireo_completion_t *owner = NULL; vireo_completion_queue_transfer_report_t report;
        vireo_result_t result = vireo_completion_queue_try_pop(f->queue, &owner, &report);
        if (result == VIREO_RESULT_NOT_FOUND || result == VIREO_RESULT_CANCELLED) break;
        CHECK(result == VIREO_OK && report.transferred); discard(f, &owner);
    }
    EXPECT(vireo_completion_queue_destroy(&f->queue), VIREO_OK);
    EXPECT(vireo_inflight_store_destroy(&f->store), VIREO_OK);
    EXPECT(vireo_notifier_destroy(&f->notifier, NULL), VIREO_OK);
    if (f->client.pool_id != 0) EXPECT(vireo_tcp_server_release_client(f->server, &f->client, NULL), VIREO_OK);
    CHECK(close(f->peer) == 0); f->peer = -1;
    EXPECT(vireo_tcp_server_destroy(&f->server, NULL), VIREO_OK);
}

static void counts(fixture_t *f, size_t queued, size_t registered) {
    vireo_completion_queue_info_t q; vireo_inflight_store_info_t s;
    EXPECT(vireo_completion_queue_inspect(f->queue, &q), VIREO_OK);
    EXPECT(vireo_inflight_store_inspect(f->store, &s), VIREO_OK); CHECK(q.count == queued && s.count == registered);
}

static vireo_result_t deliver(void *context, vireo_completion_t const *completion,
    vireo_inflight_completion_match_t match) {
    vireo_completion_payload_view_t view;
    EXPECT(vireo_completion_borrow_payload(completion, &view), VIREO_OK);
    CHECK(view.size == 3 && view.data[0] == 0 && view.data[1] == 255 && view.data[2] == 42);
    if (context == NULL) return VIREO_OK;
    delivery_context_t *d = context; CHECK(d->calls < 8); d->seen[d->calls++] = match.metadata.route.request_sequence;
    vireo_task_metadata_t missing;
    EXPECT(vireo_inflight_store_get(d->store, match.metadata, &missing, NULL), VIREO_RESULT_NOT_FOUND);
    errno = ENOSPC;
    return match.metadata.route.request_sequence == d->fail_sequence ? d->fail_result : VIREO_OK;
}


static vireo_tcp_server_process_options_t const process = {48, 48};
static vireo_tcp_server_drive_budget_t const drive = {{SIZE_MAX, 8}, {2, 96, 96}, {SIZE_MAX, 8}};
static vireo_tcp_server_round_budget_t const round_budget = {1};

static vireo_result_t handler(vireo_connection_frame_view_t const *q, uint8_t *bytes,
    size_t capacity, vireo_tcp_server_reply_t *reply, void *ctx) {
    (void)q; (void)bytes; (void)capacity; (void)reply; (void)ctx;
    CHECK(false); return VIREO_RESULT_INTERNAL; /* 对端没有发送帧，业务不应被调用。 */
}
static void serve(fixture_t *f, int timeout) {
    vireo_tcp_server_serve_options_t const o = {timeout, process, drive, round_budget, {1, 4}};
    uint8_t workspace[48]; vireo_tcp_server_turn_result_t turns[1];
    vireo_connection_pool_lease_t clients[1] = {0}; vireo_tcp_server_serve_info_t info;
    EXPECT(vireo_tcp_server_serve_once(f->server, &o, workspace, sizeof workspace,
        handler, NULL, turns, 1, clients, 1, &info, NULL), VIREO_OK);
}
static vireo_notifier_server_dispatch_report_t invoke(fixture_t *f, size_t budget,
    delivery_context_t *d, vireo_completion_t **remaining, vireo_result_t expected) {
    vireo_notifier_server_dispatch_report_t report; memset(&report, 0xa5, sizeof report);
    EXPECT(vireo_notifier_server_dispatch_ready(f->server, f->handle, f->notifier,
        f->store, f->queue, budget, deliver, d, remaining, &report), expected);
    return report;
}
static void idle(vireo_notifier_server_dispatch_report_t p) {
    CHECK(!p.ready_taken && !p.dispatch_called && p.ready_event.events == 0 &&
        p.dispatch_result == VIREO_OK && !p.dispatch_report.consume_called &&
        !p.dispatch_report.drain_called && !p.dispatch_report.renotify_called);
}
static void no_ready(void) {
    fixture_t f; setup(&f); publish(&f, 1, true, false); vireo_completion_t *remaining = NULL;
    vireo_notifier_server_dispatch_report_t p = invoke(&f, 4, NULL, &remaining, VIREO_OK);
    CHECK(p.ready_called && p.stage == VIREO_NOTIFIER_SERVER_DISPATCH_NONE); idle(p);
    counts(&f, 1, 1); notify(&f); serve(&f, 500);
    p = invoke(&f, 4, NULL, &remaining, VIREO_OK);
    CHECK(p.ready_taken && p.dispatch_called && p.dispatch_report.drain_report.finished == 1);
    cleanup(&f);
}
static void unbound_idle(void) {
    fixture_t f; setup(&f); vireo_event_loop_handle_t const old = f.handle;
    EXPECT(vireo_notifier_server_unregister(f.server, &f.handle, NULL), VIREO_OK);
    vireo_completion_t *remaining = NULL; vireo_notifier_server_dispatch_report_t p;
    EXPECT(vireo_notifier_server_dispatch_ready(f.server, old, f.notifier, f.store, f.queue,
        4, deliver, NULL, &remaining, &p), VIREO_OK);
    CHECK(p.ready_called); idle(p); cleanup(&f);
}
static void full_batch(void) {
    fixture_t f; setup(&f); for (uint32_t i = 1; i <= 3; ++i) publish(&f, i, true, true);
    serve(&f, 500); delivery_context_t d = {.store = f.store}; vireo_completion_t *remaining = NULL;
    vireo_notifier_server_dispatch_report_t p = invoke(&f, 8, &d, &remaining, VIREO_OK);
    CHECK(p.ready_taken && p.ready_event.handle.loop_id == f.handle.loop_id &&
        p.ready_event.handle.token == f.handle.token && p.ready_event.events == VIREO_EPOLL_EVENT_READ &&
        p.dispatch_called && p.dispatch_report.notification_count == 3 &&
        p.dispatch_report.drain_report.finished == 3 && !p.dispatch_report.renotify_called && !remaining);
    CHECK(d.calls == 3 && d.seen[0] == 1 && d.seen[1] == 2 && d.seen[2] == 3);
    counts(&f, 0, 0); cleanup(&f);
}
static void budget_renotify(void) {
    fixture_t f; setup(&f); for (uint32_t i = 1; i <= 5; ++i) publish(&f, i, true, false);
    notify(&f); delivery_context_t d = {.store = f.store}; vireo_completion_t *remaining = NULL;
    for (size_t k = 0; k < 3; ++k) {
        serve(&f, 500); vireo_notifier_server_dispatch_report_t p = invoke(&f, 2, &d, &remaining, VIREO_OK);
        CHECK(p.ready_taken && p.dispatch_report.notification_count == 1);
        if (k < 2) CHECK(p.dispatch_report.renotify_called &&
            p.dispatch_report.drain_report.stop_reason == VIREO_INFLIGHT_COMPLETION_DRAIN_BUDGET);
        else CHECK(!p.dispatch_report.renotify_called &&
            p.dispatch_report.drain_report.stop_reason == VIREO_INFLIGHT_COMPLETION_DRAIN_EMPTY);
    }
    CHECK(d.calls == 5); for (size_t k = 0; k < 5; ++k) CHECK(d.seen[k] == k + 1);
    serve(&f, 0); vireo_notifier_server_dispatch_report_t const p = invoke(&f, 2, &d, &remaining, VIREO_OK);
    idle(p); counts(&f, 0, 0); cleanup(&f);
}
static void zero_count(void) {
    fixture_t f; setup(&f); publish(&f, 1, true, false); notify(&f); serve(&f, 500);
    uint64_t count; EXPECT(vireo_notifier_consume(f.notifier, &count, NULL), VIREO_OK); CHECK(count == 1);
    vireo_completion_t *remaining = NULL;
    vireo_notifier_server_dispatch_report_t const p = invoke(&f, 4, NULL, &remaining, VIREO_OK);
    CHECK(p.ready_taken && p.dispatch_report.notification_count == 0 &&
        p.dispatch_report.drain_report.finished == 1); cleanup(&f);
}
static void excess_hints(void) {
    fixture_t f; setup(&f); notify(&f); notify(&f); serve(&f, 500); vireo_completion_t *remaining = NULL;
    vireo_notifier_server_dispatch_report_t const p = invoke(&f, 4, NULL, &remaining, VIREO_OK);
    CHECK(p.ready_taken && p.dispatch_report.notification_count == 2 &&
        p.dispatch_report.drain_report.received == 0 && !p.dispatch_report.renotify_called); cleanup(&f);
}
static void mismatch(fixture_t *f, vireo_event_loop_handle_t expected) {
    publish(f, 1, true, true); serve(f, 500); vireo_completion_t *remaining = NULL;
    vireo_notifier_server_dispatch_report_t p;
    EXPECT(vireo_notifier_server_dispatch_ready(f->server, expected, f->notifier, f->store,
        f->queue, 4, deliver, NULL, &remaining, &p), VIREO_RESULT_NOT_FOUND);
    CHECK(p.stage == VIREO_NOTIFIER_SERVER_DISPATCH_CHECK_READY && p.ready_taken && !p.dispatch_called);
    CHECK(p.ready_event.handle.loop_id == f->handle.loop_id && p.ready_event.handle.token == f->handle.token);
    vireo_tcp_server_info_t info; EXPECT(vireo_tcp_server_inspect(f->server, &info), VIREO_OK);
    CHECK(info.auxiliary_pending_events == 0); counts(f, 1, 1);
    uint64_t count; EXPECT(vireo_notifier_consume(f->notifier, &count, NULL), VIREO_OK); CHECK(count == 1);
    /* caller 明确补调度：不是自动恢复已取走的标记。 */
    notify(f); serve(f, 500); (void)invoke(f, 4, NULL, &remaining, VIREO_OK);
}
static void old_registration(void) {
    fixture_t f; setup(&f); vireo_event_loop_handle_t const old = f.handle;
    EXPECT(vireo_notifier_server_unregister(f.server, &f.handle, NULL), VIREO_OK);
    EXPECT(vireo_notifier_server_register(f.server, f.notifier, &f.handle, NULL), VIREO_OK);
    CHECK(old.token != f.handle.token); mismatch(&f, old); cleanup(&f);
}
static void other_server(void) {
    fixture_t f, other; setup(&f); setup(&other); mismatch(&f, other.handle); cleanup(&f); cleanup(&other);
}
static void callback_failure(void) {
    fixture_t f; setup(&f); for (uint32_t i = 1; i <= 3; ++i) publish(&f, i, true, false);
    notify(&f); serve(&f, 500);
    delivery_context_t d = {.store = f.store, .fail_sequence = 2, .fail_result = VIREO_RESULT_BUSY};
    vireo_completion_t *remaining = NULL;
    vireo_notifier_server_dispatch_report_t const p = invoke(&f, 8, &d, &remaining, VIREO_RESULT_BUSY);
    CHECK(p.stage == VIREO_NOTIFIER_SERVER_DISPATCH_DISPATCH && p.ready_taken && p.dispatch_called &&
        p.dispatch_report.stage == VIREO_NOTIFIER_COMPLETION_DRAIN && !p.dispatch_report.renotify_called &&
        p.dispatch_report.drain_report.received == 2 && p.dispatch_report.drain_report.finished == 1 &&
        p.dispatch_report.drain_report.consume_report.record_consumed && remaining != NULL && d.calls == 2);
    counts(&f, 1, 1); discard(&f, &remaining);
    /* 显式恢复旧入口，避免把已结束登记的结果重交付。 */
    vireo_notifier_completion_report_t recovered;
    EXPECT(vireo_notifier_completion_consume_and_drain(f.notifier, f.store, f.server, f.queue,
        8, deliver, &d, &remaining, &recovered), VIREO_OK);
    CHECK(d.calls == 3 && d.seen[2] == 3 && recovered.notification_count == 0);
    counts(&f, 0, 0); cleanup(&f);
}
static void closed_queue(void) {
    fixture_t f; setup(&f); vireo_completion_queue_close_report_t close_report;
    EXPECT(vireo_completion_queue_close(f.queue, &close_report), VIREO_OK); notify(&f); serve(&f, 500);
    vireo_completion_t *remaining = NULL;
    vireo_notifier_server_dispatch_report_t const p = invoke(&f, 4, NULL, &remaining, VIREO_RESULT_CANCELLED);
    CHECK(p.ready_taken && p.dispatch_called && !p.dispatch_report.renotify_called && !remaining); cleanup(&f);
}
static void stopped_old_ready(void) {
    fixture_t f; setup(&f); publish(&f, 1, true, true); serve(&f, 500);
    EXPECT(vireo_tcp_server_request_stop(f.server, NULL), VIREO_OK); vireo_completion_t *remaining = NULL;
    vireo_notifier_server_dispatch_report_t const p = invoke(&f, 4, NULL, &remaining, VIREO_OK);
    CHECK(p.ready_taken && p.dispatch_report.drain_report.finished == 1);
    notify(&f); serve(&f, 0); idle(invoke(&f, 4, NULL, &remaining, VIREO_OK));
    uint64_t count; EXPECT(vireo_notifier_consume(f.notifier, &count, NULL), VIREO_OK); CHECK(count == 1); cleanup(&f);
}

/** 只借本组资源和交付账本到实际 run 返回。 */
typedef struct observer_context {
    fixture_t *fixture; /**< 本组资源短借，不保活。 */
    delivery_context_t *delivery; /**< 本组交付账本短借，observer 更新。 */
} observer_context_t;
static void observer(vireo_tcp_server_t *server, vireo_result_t result,
    vireo_tcp_server_serve_info_t const *info, vireo_tcp_server_turn_result_t const *turns,
    vireo_connection_pool_lease_t const *clients, vireo_tcp_server_serve_error_t const *error, void *context) {
    (void)info; (void)turns; (void)clients; (void)error;
    observer_context_t *o = context; CHECK(server == o->fixture->server && result == VIREO_OK);
    vireo_tcp_server_info_t state; EXPECT(vireo_tcp_server_inspect(server, &state), VIREO_OK);
    CHECK(state.running_active && !state.serving_active && !state.scheduling_active);
    vireo_completion_t *remaining = NULL;
    vireo_notifier_server_dispatch_report_t const p = invoke(o->fixture, 4, o->delivery, &remaining, VIREO_OK);
    CHECK(p.ready_taken && p.dispatch_report.drain_report.finished == 1 && !remaining);
    EXPECT(vireo_tcp_server_request_stop(server, NULL), VIREO_OK);
}
static void observer_window(void) {
    fixture_t f; setup(&f); publish(&f, 1, true, true); delivery_context_t d = {.store = f.store};
    observer_context_t context = {&f, &d}; vireo_tcp_server_run_options_t const o = {process, drive, round_budget, {1, 4}};
    uint8_t workspace[48]; vireo_tcp_server_turn_result_t turns[1]; vireo_connection_pool_lease_t clients[1] = {0};
    EXPECT(vireo_tcp_server_run(f.server, &o, workspace, sizeof workspace, handler, NULL,
        turns, 1, clients, 1, observer, &context, NULL), VIREO_OK);
    CHECK(d.calls == 1); cleanup(&f);
}
static void *producer(void *context) {
    CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL) == 0);
    fixture_t *f = context; vireo_notifier_notify_outcome_t outcome;
    EXPECT(vireo_notifier_notify(f->notifier, &outcome, NULL), VIREO_OK); return NULL;
}
static void threaded_wakeup(void) {
    fixture_t f; setup(&f); publish(&f, 1, true, false); pthread_t thread;
    CHECK(pthread_create(&thread, NULL, producer, &f) == 0); serve(&f, 500);
    vireo_completion_t *remaining = NULL;
    vireo_notifier_server_dispatch_report_t const p = invoke(&f, 4, NULL, &remaining, VIREO_OK);
    CHECK(p.ready_taken && p.dispatch_report.drain_report.finished == 1);
    CHECK(pthread_join(thread, NULL) == 0); cleanup(&f);
}

/** 本层公开依赖模型，原资源只借至本组结束，不伪造原内核故障。 */
typedef struct model {
    vireo_result_t take_result; /**< 模型拒绝类别，OK 时实际公开 take。 */
    uint32_t events; /**< 非 READ 替换实际返回副本，非原内核事件实证。 */
    vireo_result_t dispatch_result; /**< 非 OK 选择消费前模型拒绝。 */
    unsigned take_calls; /**< 本层实际 take 桥接调用次数。 */
    unsigned dispatch_calls; /**< 本层实际 dispatch 桥接调用次数。 */
} model_t;
static vireo_result_t take_model(void *context, vireo_tcp_server_t *server,
    vireo_tcp_server_auxiliary_event_t *event, vireo_tcp_server_auxiliary_error_t *error) {
    model_t *m = context; ++m->take_calls; errno = ENOSPC;
    if (m->take_result != VIREO_OK) {
        *error = (vireo_tcp_server_auxiliary_error_t){.stage = VIREO_TCP_SERVER_AUXILIARY_CHECK_BINDING};
        return m->take_result;
    }
    vireo_result_t result = vireo_tcp_server_auxiliary_read_take_ready(server, event, error);
    if (result == VIREO_OK && m->events != VIREO_EPOLL_EVENT_READ) event->events = m->events;
    return result;
}
static vireo_result_t dispatch_model(void *ops_context, vireo_notifier_t *notifier,
    vireo_inflight_store_t *store, vireo_tcp_server_t const *server, vireo_completion_queue_t *queue,
    size_t budget, vireo_inflight_completion_deliver_fn callback, void *context,
    vireo_completion_t **remaining, vireo_notifier_completion_report_t *report) {
    model_t *m = ops_context; ++m->dispatch_calls; errno = ENOSPC;
    if (m->dispatch_result != VIREO_OK) {
        *report = (vireo_notifier_completion_report_t){.stage = VIREO_NOTIFIER_COMPLETION_CONSUME_HINT,
            .consume_called = true, .consume_error = {VIREO_NOTIFIER_STAGE_CONSUME, EINTR}};
        return m->dispatch_result;
    }
    return vireo_notifier_completion_consume_and_drain(notifier, store, server, queue,
        budget, callback, context, remaining, report);
}
static vireo_notifier_server_dispatch_ops_t const ops = {take_model, dispatch_model};
static vireo_notifier_server_dispatch_report_t modeled(fixture_t *f, model_t *m,
    vireo_event_loop_handle_t h, size_t budget, vireo_result_t result) {
    vireo_completion_t *remaining = NULL; vireo_notifier_server_dispatch_report_t p;
    memset(&p, 0xa5, sizeof p);
    EXPECT(vireo_notifier_server_dispatch_with_ops(f->server, h, f->notifier, f->store, f->queue,
        budget, deliver, NULL, &remaining, &p, &ops, m), result); CHECK(!remaining); return p;
}
static void take_errors(void) {
    fixture_t f; setup(&f); model_t m = {.take_result = VIREO_RESULT_BUSY};
    vireo_notifier_server_dispatch_report_t p = modeled(&f, &m, f.handle, 4, VIREO_RESULT_BUSY);
    CHECK(p.ready_called && p.stage == VIREO_NOTIFIER_SERVER_DISPATCH_TAKE_READY &&
        p.ready_error.stage == VIREO_TCP_SERVER_AUXILIARY_CHECK_BINDING); idle(p);
    m.take_result = VIREO_RESULT_IO; p = modeled(&f, &m, f.handle, 4, VIREO_RESULT_IO); idle(p);
    m.take_result = VIREO_RESULT_NOT_FOUND; p = modeled(&f, &m, f.handle, 4, VIREO_OK);
    CHECK(p.stage == VIREO_NOTIFIER_SERVER_DISPATCH_NONE && m.take_calls == 3 && !m.dispatch_calls); idle(p);
    cleanup(&f);
}
static void event_errors(void) {
    fixture_t f; setup(&f); model_t m = {0};
    uint32_t const events[] = {VIREO_EPOLL_EVENT_ERROR, VIREO_EPOLL_EVENT_HANGUP,
        VIREO_EPOLL_EVENT_READ | VIREO_EPOLL_EVENT_ERROR | VIREO_EPOLL_EVENT_HANGUP, 0, UINT32_C(0x80000000)};
    for (size_t k = 0; k < sizeof events / sizeof events[0]; ++k) {
        notify(&f); serve(&f, 500); m.events = events[k];
        vireo_notifier_server_dispatch_report_t const p = modeled(&f, &m, f.handle, 4,
            k < 3 ? VIREO_RESULT_IO : VIREO_RESULT_INTERNAL);
        CHECK(p.ready_taken && !p.dispatch_called && p.ready_event.events == events[k] &&
            p.stage == VIREO_NOTIFIER_SERVER_DISPATCH_CHECK_READY);
        uint64_t count; EXPECT(vireo_notifier_consume(f.notifier, &count, NULL), VIREO_OK); CHECK(count == 1);
    }
    CHECK(m.take_calls == 5 && !m.dispatch_calls); cleanup(&f);
}
static void dispatch_error(void) {
    fixture_t f; setup(&f); notify(&f); serve(&f, 500);
    model_t m = {.events = VIREO_EPOLL_EVENT_READ, .dispatch_result = VIREO_RESULT_IO};
    vireo_notifier_server_dispatch_report_t const p = modeled(&f, &m, f.handle, 4, VIREO_RESULT_IO);
    CHECK(p.ready_taken && p.dispatch_called && p.dispatch_result == VIREO_RESULT_IO &&
        p.stage == VIREO_NOTIFIER_SERVER_DISPATCH_DISPATCH &&
        p.dispatch_report.consume_error.system_errno == EINTR && !p.dispatch_report.drain_called);
    uint64_t count; EXPECT(vireo_notifier_consume(f.notifier, &count, NULL), VIREO_OK); CHECK(count == 1); cleanup(&f);
}
static void basic_and_shape(void) {
    fixture_t f; setup(&f); model_t m = {0};
    vireo_notifier_server_dispatch_report_t p = modeled(&f, &m, f.handle, 0, VIREO_RESULT_INVALID_ARGUMENT);
    idle(p); CHECK(!p.ready_called);
    p = modeled(&f, &m, f.handle, 65537, VIREO_RESULT_RANGE); idle(p);
    p = modeled(&f, &m, (vireo_event_loop_handle_t){0}, 4, VIREO_RESULT_NOT_FOUND); idle(p);
    p = modeled(&f, &m, (vireo_event_loop_handle_t){f.handle.loop_id, 0}, 4, VIREO_RESULT_INVALID_ARGUMENT); idle(p);
    p = modeled(&f, &m, (vireo_event_loop_handle_t){0, f.handle.token}, 4, VIREO_RESULT_INVALID_ARGUMENT); idle(p);
    vireo_completion_t *remaining = completion_make(request_make(&f, 1)); vireo_completion_t *saved = remaining;
    EXPECT(vireo_notifier_server_dispatch_with_ops(f.server, f.handle, f.notifier, f.store, f.queue,
        4, deliver, NULL, &remaining, &p, &ops, &m), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(remaining == saved); idle(p); EXPECT(vireo_completion_destroy(&remaining), VIREO_OK);
    EXPECT(vireo_notifier_server_dispatch_ready(NULL, f.handle, f.notifier, f.store, f.queue,
        4, deliver, NULL, &remaining, &p), VIREO_RESULT_INVALID_ARGUMENT); idle(p);
    EXPECT(vireo_notifier_server_dispatch_ready(f.server, f.handle, f.notifier, f.store, f.queue,
        4, NULL, NULL, &remaining, &p), VIREO_RESULT_INVALID_ARGUMENT); idle(p);
    EXPECT(vireo_notifier_server_dispatch_ready(f.server, f.handle, f.notifier, f.store, f.queue,
        4, deliver, NULL, NULL, &p), VIREO_RESULT_INVALID_ARGUMENT); idle(p);
    EXPECT(vireo_notifier_server_dispatch_ready(f.server, f.handle, f.notifier, f.store, f.queue,
        4, deliver, NULL, &remaining, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(!m.take_calls && !m.dispatch_calls); cleanup(&f);
}
static void bad_seams(void) {
    fixture_t f; setup(&f); vireo_completion_t *remaining = NULL; vireo_notifier_server_dispatch_report_t p;
    vireo_notifier_server_dispatch_ops_t missing = ops; missing.take = NULL;
    EXPECT(vireo_notifier_server_dispatch_with_ops(f.server, f.handle, f.notifier, f.store, f.queue,
        4, deliver, NULL, &remaining, &p, &missing, NULL), VIREO_RESULT_INVALID_ARGUMENT); idle(p);
    missing = ops; missing.dispatch = NULL;
    EXPECT(vireo_notifier_server_dispatch_with_ops(f.server, f.handle, f.notifier, f.store, f.queue,
        4, deliver, NULL, &remaining, &p, &missing, NULL), VIREO_RESULT_INVALID_ARGUMENT); idle(p);
    EXPECT(vireo_notifier_server_dispatch_with_ops(f.server, f.handle, f.notifier, f.store, f.queue,
        4, deliver, NULL, &remaining, &p, NULL, NULL), VIREO_RESULT_INVALID_ARGUMENT); idle(p); cleanup(&f);
}
int main(void) {
    CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL) == 0);
    void (*const cases[])(void) = {no_ready, unbound_idle, full_batch, budget_renotify, zero_count,
        excess_hints, old_registration, other_server, callback_failure, closed_queue, stopped_old_ready,
        observer_window, threaded_wakeup, take_errors, event_errors, dispatch_error, basic_and_shape, bad_seams};
    for (size_t k = 0; k < sizeof cases / sizeof cases[0]; ++k) {
        size_t const n = fd_count(); cases[k](); CHECK(fd_count() == n);
    }
    puts("notifier server dispatch: 18 groups passed"); return 0;
}
