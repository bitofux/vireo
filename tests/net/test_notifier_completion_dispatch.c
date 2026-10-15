/*
 * PROJECT : VIREO
 * FILE    : test_notifier_completion_dispatch.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-13
 * BRIEF   : 真实提示/有界队列/后轮 READ 与本层故障前缀
 */
#define _GNU_SOURCE
#include <vireo/net/notifier_completion.h>
#include <vireo/net/notifier_loop.h>
#include "notifier_completion_internal.h"
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
_Static_assert(VIREO_NOTIFIER_COMPLETION_NONE == 0 && VIREO_NOTIFIER_COMPLETION_CONSUME_HINT == 1 &&
    VIREO_NOTIFIER_COMPLETION_DRAIN == 2 && VIREO_NOTIFIER_COMPLETION_RENOTIFY == 3, "independent stages");

/** 独占公开资源 owner，关闭注册借用后才 destroy notifier。 */
typedef struct fixture {
    vireo_tcp_server_t *server; /**< 当前客户及 listener 的资源根 owner。 */
    vireo_connection_pool_lease_t client; /**< 当前客户数值身份，不保活。 */
    int peer; /**< caller 对端 owner，-1 为空。 */
    vireo_completion_queue_t *queue; /**< 真实完成队列 owner，cleanup 先收回余项。 */
    vireo_inflight_store_t *store; /**< 真实在途表 owner，cleanup 先退所有剩余记录。 */
    vireo_notifier_t *notifier; /**< 提示 fd 唯一 owner。 */
    vireo_event_loop_t *loop; /**< 独立公开 loop owner，不是 server 私有 loop。 */
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
    EXPECT(vireo_tcp_server_create(&server_options, &f->server, NULL), VIREO_OK);
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
    vireo_event_loop_options_t const loop_options = {4, VIREO_EVENT_LOOP_MAX_MEMORY, 2};
    EXPECT(vireo_event_loop_create(&loop_options, &f->loop, NULL), VIREO_OK);
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
    if (f->handle.loop_id != 0) EXPECT(vireo_notifier_loop_unregister(f->loop, &f->handle, NULL), VIREO_OK);
    for (;;) {
        vireo_completion_t *owner = NULL; vireo_completion_queue_transfer_report_t report;
        vireo_result_t result = vireo_completion_queue_try_pop(f->queue, &owner, &report);
        if (result == VIREO_RESULT_NOT_FOUND || result == VIREO_RESULT_CANCELLED) break;
        CHECK(result == VIREO_OK && report.transferred); discard(f, &owner);
    }
    EXPECT(vireo_completion_queue_destroy(&f->queue), VIREO_OK);
    EXPECT(vireo_inflight_store_destroy(&f->store), VIREO_OK);
    EXPECT(vireo_event_loop_destroy(&f->loop, NULL), VIREO_OK);
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

static vireo_notifier_completion_report_t invoke(fixture_t *f, size_t budget, delivery_context_t *d,
    vireo_completion_t **remaining, vireo_result_t expected) {
    vireo_notifier_completion_report_t report; memset(&report, 0xa5, sizeof report);
    EXPECT(vireo_notifier_completion_consume_and_drain(f->notifier, f->store, f->server,
        f->queue, budget, deliver, d, remaining, &report), expected); return report;
}

static void not_started(vireo_notifier_completion_report_t report) {
    CHECK(report.stage == VIREO_NOTIFIER_COMPLETION_NONE && !report.consume_called && report.notification_count == 0 &&
        report.consume_error.stage == 0 && report.consume_error.system_errno == 0 && !report.drain_called &&
        report.drain_result == VIREO_OK && report.drain_report.pop_calls == 0 && !report.renotify_needed &&
        !report.renotify_called && report.renotify_result == VIREO_OK && report.renotify_outcome == 0 &&
        report.renotify_error.stage == 0 && report.renotify_error.system_errno == 0);
}

static void empty_zero(void) {
    fixture_t f; setup(&f); vireo_completion_t *remaining = NULL;
    vireo_notifier_completion_report_t report = invoke(&f, 4, NULL, &remaining, VIREO_OK);
    CHECK(report.consume_called && report.notification_count == 0 && report.drain_called &&
        report.drain_result == VIREO_OK && report.drain_report.stop_reason == VIREO_INFLIGHT_COMPLETION_DRAIN_EMPTY &&
        report.drain_report.pop_calls == 1 && !report.renotify_called && remaining == NULL);
    counts(&f, 0, 0); cleanup(&f);
}

static void excess_hints_empty_queue(void) {
    fixture_t f; setup(&f); for (unsigned i = 0; i < 5; ++i) notify(&f);
    vireo_completion_t *remaining = NULL; vireo_notifier_completion_report_t report = invoke(&f, 4, NULL, &remaining, VIREO_OK);
    CHECK(report.notification_count == 5 && report.drain_report.received == 0 &&
        report.drain_report.stop_reason == VIREO_INFLIGHT_COMPLETION_DRAIN_EMPTY && !report.renotify_called);
    uint64_t count; EXPECT(vireo_notifier_consume(f.notifier, &count, NULL), VIREO_OK); CHECK(count == 0); cleanup(&f);
}

static void zero_hint_still_drains(void) {
    fixture_t f; setup(&f); for (uint32_t i = 1; i <= 3; ++i) publish(&f, i, true, false);
    delivery_context_t d = {.store = f.store}; vireo_completion_t *remaining = NULL;
    vireo_notifier_completion_report_t report = invoke(&f, 8, &d, &remaining, VIREO_OK);
    CHECK(report.notification_count == 0 && report.drain_report.finished == 3 && report.drain_report.delivered == 3 &&
        report.drain_report.pop_calls == 4 && d.calls == 3 && !report.renotify_called);
    for (uint32_t i = 0; i < 3; ++i) CHECK(d.seen[i] == i + 1);
    counts(&f, 0, 0); cleanup(&f);
}

/** caller 的 void 回调上下文，返回码/报告存于 caller，不是 loop 自动诊断。 */
typedef struct dispatch_context {
    fixture_t *fixture; /**< 存活资源短借，注册借用结束前不释放。 */
    size_t budget; /**< 当前单批条预算。 */
    delivery_context_t *delivery; /**< 可空交付账本短借。 */
    vireo_completion_t *remaining; /**< 失败转出的真实唯一 owner，由 caller 显式恢复。 */
    vireo_notifier_completion_report_t report; /**< 最近一次新入口报告。 */
    vireo_result_t result; /**< 最近一次新入口返回，不传播到 void loop 返回。 */
    size_t calls; /**< 实际 READ 回调次数。 */
} dispatch_context_t;

static void ready(vireo_event_loop_t *loop, vireo_event_loop_handle_t handle,
    int fd, uint32_t events, void *context) {
    dispatch_context_t *d = context; fixture_t *f = d->fixture;
    CHECK(loop == f->loop && handle.loop_id == f->handle.loop_id && handle.token == f->handle.token);
    vireo_notifier_info_t info; EXPECT(vireo_notifier_inspect(f->notifier, &info), VIREO_OK);
    CHECK(fd == info.fd && (events & VIREO_EPOLL_EVENT_READ) != 0 && d->remaining == NULL); ++d->calls;
    d->result = vireo_notifier_completion_consume_and_drain(f->notifier, f->store, f->server,
        f->queue, d->budget, deliver, d->delivery, &d->remaining, &d->report);
    errno = ENOSPC;
}

static size_t run(fixture_t *f, int timeout_ms) {
    vireo_event_loop_run_info_t info;
    EXPECT(vireo_event_loop_run_once(f->loop, timeout_ms, &info, NULL), VIREO_OK); return info.dispatched_count;
}

static void budget_lt_successive_rounds(void) {
    fixture_t f; setup(&f); delivery_context_t d = {.store = f.store};
    dispatch_context_t c = {.fixture = &f, .budget = 2, .delivery = &d};
    EXPECT(vireo_notifier_loop_register(f.loop, f.notifier, ready, &c, &f.handle, NULL), VIREO_OK);
    for (uint32_t i = 1; i <= 5; ++i) publish(&f, i, true, true);
    CHECK(run(&f, 0) == 1 && c.calls == 1 && c.result == VIREO_OK && c.report.notification_count == 5);
    CHECK(c.report.drain_report.finished == 2 && c.report.renotify_needed && c.report.renotify_called &&
        c.report.renotify_result == VIREO_OK && c.report.renotify_outcome == VIREO_NOTIFIER_NOTIFY_INCREMENTED);
    counts(&f, 3, 3);
    CHECK(run(&f, 0) == 1 && c.calls == 2 && c.result == VIREO_OK && c.report.notification_count == 1);
    CHECK(c.report.drain_report.finished == 2 && c.report.renotify_called); counts(&f, 1, 1);
    CHECK(run(&f, 0) == 1 && c.calls == 3 && c.result == VIREO_OK && c.report.notification_count == 1);
    CHECK(c.report.drain_report.finished == 1 && !c.report.renotify_called && c.remaining == NULL);
    CHECK(run(&f, 0) == 0 && d.calls == 5); for (uint32_t i = 0; i < 5; ++i) CHECK(d.seen[i] == i + 1);
    counts(&f, 0, 0); cleanup(&f);
}

static void exact_budget_extra_empty_round(void) {
    fixture_t f; setup(&f); delivery_context_t d = {.store = f.store};
    dispatch_context_t c = {.fixture = &f, .budget = 2, .delivery = &d};
    EXPECT(vireo_notifier_loop_register(f.loop, f.notifier, ready, &c, &f.handle, NULL), VIREO_OK);
    publish(&f, 1, true, true); publish(&f, 2, true, true);
    CHECK(run(&f, 0) == 1 && c.report.drain_report.pop_calls == 2 && c.report.renotify_needed);
    counts(&f, 0, 0);
    CHECK(run(&f, 0) == 1 && c.report.notification_count == 1 &&
        c.report.drain_report.stop_reason == VIREO_INFLIGHT_COMPLETION_DRAIN_EMPTY && !c.report.renotify_called);
    CHECK(run(&f, 0) == 0 && c.calls == 2 && d.calls == 2); cleanup(&f);
}

static void late_request_cleaned(void) {
    fixture_t f; setup(&f); publish(&f, 1, false, true); vireo_completion_t *remaining = NULL;
    delivery_context_t d = {.store = f.store}; vireo_notifier_completion_report_t report = invoke(&f, 4, &d, &remaining, VIREO_OK);
    CHECK(report.drain_report.finished == 1 && report.drain_report.late_cleaned == 1 && d.calls == 0 && remaining == NULL);
    counts(&f, 0, 0); cleanup(&f);
}

static void late_client_cleaned(void) {
    fixture_t f; setup(&f); publish(&f, 1, true, true);
    EXPECT(vireo_tcp_server_release_client(f.server, &f.client, NULL), VIREO_OK);
    vireo_completion_t *remaining = NULL; delivery_context_t d = {.store = f.store};
    vireo_notifier_completion_report_t report = invoke(&f, 4, &d, &remaining, VIREO_OK);
    CHECK(report.drain_report.late_cleaned == 1 && report.drain_report.finished == 1 && d.calls == 0);
    counts(&f, 0, 0); cleanup(&f);
}

static void callback_error_retains_owner(void) {
    fixture_t f; setup(&f); publish(&f, 1, true, true); publish(&f, 2, true, true);
    delivery_context_t d = {.store = f.store, .fail_sequence = 1, .fail_result = VIREO_RESULT_DATABASE};
    vireo_completion_t *remaining = NULL; vireo_notifier_completion_report_t report = invoke(&f, 4, &d, &remaining, VIREO_RESULT_DATABASE);
    CHECK(report.stage == VIREO_NOTIFIER_COMPLETION_DRAIN && report.drain_result == VIREO_RESULT_DATABASE &&
        report.drain_report.stage == VIREO_INFLIGHT_COMPLETION_DRAIN_CONSUME && report.drain_report.received == 1 &&
        report.drain_report.finished == 0 && report.drain_report.consume_report.record_consumed && remaining != NULL &&
        !report.renotify_called && d.calls == 1);
    counts(&f, 1, 1); discard(&f, &remaining); /* caller 明确处理失败 owner，不重放。 */
    report = invoke(&f, 4, &d, &remaining, VIREO_OK); CHECK(report.notification_count == 0 && d.calls == 2);
    counts(&f, 0, 0); cleanup(&f);
}

static void callback_busy_not_renotified(void) {
    fixture_t f; setup(&f); publish(&f, 1, true, true);
    delivery_context_t d = {.store = f.store, .fail_sequence = 1, .fail_result = VIREO_RESULT_BUSY};
    vireo_completion_t *remaining = NULL; vireo_notifier_completion_report_t report = invoke(&f, 4, &d, &remaining, VIREO_RESULT_BUSY);
    CHECK(report.stage == VIREO_NOTIFIER_COMPLETION_DRAIN && !report.renotify_needed && !report.renotify_called && remaining != NULL);
    discard(&f, &remaining); counts(&f, 0, 0); cleanup(&f);
}

static void closed_queue_retains_cancelled(void) {
    fixture_t f; setup(&f); notify(&f); vireo_completion_queue_close_report_t closed;
    EXPECT(vireo_completion_queue_close(f.queue, &closed), VIREO_OK);
    vireo_completion_t *remaining = NULL; vireo_notifier_completion_report_t report = invoke(&f, 4, NULL, &remaining, VIREO_RESULT_CANCELLED);
    CHECK(report.consume_called && report.notification_count == 1 && report.drain_called &&
        report.drain_result == VIREO_RESULT_CANCELLED && !report.renotify_called && remaining == NULL); cleanup(&f);
}

/** 本层故障模型，原依赖布局不读取；FORWARD 仍走真实公开入口。 */
typedef enum drain_model { MODEL_FORWARD = 0, MODEL_BUSY_POP = 1, MODEL_TRANSFER_ERROR = 2 } drain_model_t;
typedef struct model_context {
    size_t consume_calls; /**< 实际 seam 消费调用数。 */
    size_t drain_calls; /**< 实际 seam 排空调用数。 */
    size_t notify_calls; /**< 实际 seam 补提示调用数。 */
    vireo_result_t hint_result; /**< 非 OK 在真实 consume 前模型拒绝。 */
    drain_model_t drain_mode; /**< 前置 BUSY 或真实转移后错误报告模型。 */
    vireo_result_t notify_result; /**< 非 OK 在真实 notify 前模型拒绝。 */
    bool hint_max; /**< 消费成功后模型 MAX 输出，不冒内核溢出实验。 */
    bool already_pending; /**< 模型原 EAGAIN 成功结果，不冒真实饱和。 */
} model_context_t;

static vireo_result_t consume_model(void *context, vireo_notifier_t *notifier,
    uint64_t *count, vireo_notifier_error_t *error) {
    model_context_t *m = context; ++m->consume_calls; errno = EFAULT;
    if (m->hint_result != VIREO_OK) {
        *error = (vireo_notifier_error_t){VIREO_NOTIFIER_STAGE_CONSUME, EINTR}; return m->hint_result;
    }
    vireo_result_t result = vireo_notifier_consume(notifier, count, error);
    if (result == VIREO_OK && m->hint_max) *count = UINT64_MAX;
    return result;
}

static vireo_result_t drain_model_call(void *context, vireo_inflight_store_t *store,
    vireo_tcp_server_t const *server, vireo_completion_queue_t *queue, size_t max_items,
    vireo_inflight_completion_deliver_fn callback, void *delivery_context,
    vireo_completion_t **remaining, vireo_inflight_completion_drain_report_t *report) {
    model_context_t *m = context; ++m->drain_calls; errno = EFAULT;
    if (m->drain_mode == MODEL_BUSY_POP) {
        *report = (vireo_inflight_completion_drain_report_t){.stage = VIREO_INFLIGHT_COMPLETION_DRAIN_POP,
            .stop_reason = VIREO_INFLIGHT_COMPLETION_DRAIN_ERROR, .pop_calls = 1,
            .queue_report = {VIREO_COMPLETION_QUEUE_TRANSFER_LOCK, false, EBUSY}};
        return VIREO_RESULT_BUSY;
    }
    if (m->drain_mode == MODEL_TRANSFER_ERROR) {
        vireo_completion_queue_transfer_report_t transfer;
        vireo_result_t result = vireo_completion_queue_try_pop(queue, remaining, &transfer);
        CHECK(result == VIREO_OK && transfer.transferred && *remaining != NULL);
        transfer.stage = VIREO_COMPLETION_QUEUE_TRANSFER_UNLOCK; transfer.pthread_error = EINVAL;
        *report = (vireo_inflight_completion_drain_report_t){.stage = VIREO_INFLIGHT_COMPLETION_DRAIN_POP,
            .stop_reason = VIREO_INFLIGHT_COMPLETION_DRAIN_ERROR, .pop_calls = 1, .received = 1,
            .queue_report = transfer}; return VIREO_RESULT_INTERNAL;
    }
    return vireo_inflight_store_drain_completions(store, server, queue, max_items,
        callback, delivery_context, remaining, report);
}

static vireo_result_t notify_model(void *context, vireo_notifier_t *notifier,
    vireo_notifier_notify_outcome_t *outcome, vireo_notifier_error_t *error) {
    model_context_t *m = context; ++m->notify_calls; errno = EFAULT;
    if (m->notify_result != VIREO_OK) {
        *error = (vireo_notifier_error_t){VIREO_NOTIFIER_STAGE_NOTIFY, EINTR}; return m->notify_result;
    }
    if (m->already_pending) { *outcome = VIREO_NOTIFIER_NOTIFY_ALREADY_PENDING; *error = (vireo_notifier_error_t){0}; return VIREO_OK; }
    return vireo_notifier_notify(notifier, outcome, error);
}
static vireo_notifier_completion_ops_t const model_ops = {consume_model, drain_model_call, notify_model};

static vireo_notifier_completion_report_t invoke_model(fixture_t *f, size_t budget,
    delivery_context_t *d, vireo_completion_t **remaining, model_context_t *model, vireo_result_t expected) {
    vireo_notifier_completion_report_t report; memset(&report, 0xa5, sizeof report);
    EXPECT(vireo_notifier_completion_with_ops(f->notifier, f->store, f->server, f->queue, budget,
        deliver, d, remaining, &report, &model_ops, model), expected); return report;
}

static void consume_error_no_drain(void) {
    fixture_t f; setup(&f); publish(&f, 1, true, true); model_context_t m = {.hint_result = VIREO_RESULT_IO};
    vireo_completion_t *remaining = NULL; vireo_notifier_completion_report_t report = invoke_model(&f, 4, NULL, &remaining, &m, VIREO_RESULT_IO);
    CHECK(report.stage == VIREO_NOTIFIER_COMPLETION_CONSUME_HINT && report.consume_called && !report.drain_called &&
        !report.renotify_called && report.consume_error.system_errno == EINTR && report.notification_count == 0 &&
        m.consume_calls == 1 && m.drain_calls == 0 && m.notify_calls == 0 && remaining == NULL);
    counts(&f, 1, 1); uint64_t count; EXPECT(vireo_notifier_consume(f.notifier, &count, NULL), VIREO_OK); CHECK(count == 1); cleanup(&f);
}

static void pop_busy_renotified(void) {
    fixture_t f; setup(&f); publish(&f, 1, true, true); model_context_t m = {.drain_mode = MODEL_BUSY_POP};
    vireo_completion_t *remaining = NULL; vireo_notifier_completion_report_t report = invoke_model(&f, 4, NULL, &remaining, &m, VIREO_RESULT_BUSY);
    CHECK(report.stage == VIREO_NOTIFIER_COMPLETION_DRAIN && report.drain_result == VIREO_RESULT_BUSY &&
        report.renotify_needed && report.renotify_called && report.renotify_result == VIREO_OK &&
        report.drain_report.queue_report.pthread_error == EBUSY && m.consume_calls == 1 && m.drain_calls == 1 && m.notify_calls == 1);
    counts(&f, 1, 1); uint64_t count; EXPECT(vireo_notifier_consume(f.notifier, &count, NULL), VIREO_OK); CHECK(count == 1); cleanup(&f);
}

static void busy_primary_notify_error_secondary(void) {
    fixture_t f; setup(&f); publish(&f, 1, true, true);
    model_context_t m = {.drain_mode = MODEL_BUSY_POP, .notify_result = VIREO_RESULT_IO}; vireo_completion_t *remaining = NULL;
    vireo_notifier_completion_report_t report = invoke_model(&f, 4, NULL, &remaining, &m, VIREO_RESULT_BUSY);
    CHECK(report.stage == VIREO_NOTIFIER_COMPLETION_DRAIN && report.drain_result == VIREO_RESULT_BUSY &&
        report.renotify_called && report.renotify_result == VIREO_RESULT_IO && report.renotify_error.system_errno == EINTR &&
        report.drain_report.queue_report.pthread_error == EBUSY && m.notify_calls == 1); counts(&f, 1, 1); cleanup(&f);
}

static void budget_notify_error_preserves_progress(void) {
    fixture_t f; setup(&f); publish(&f, 1, true, true); publish(&f, 2, true, true);
    model_context_t m = {.notify_result = VIREO_RESULT_IO}; delivery_context_t d = {.store = f.store};
    vireo_completion_t *remaining = NULL; vireo_notifier_completion_report_t report = invoke_model(&f, 1, &d, &remaining, &m, VIREO_RESULT_IO);
    CHECK(report.stage == VIREO_NOTIFIER_COMPLETION_RENOTIFY && report.drain_result == VIREO_OK &&
        report.drain_report.finished == 1 && report.drain_report.delivered == 1 && d.calls == 1 &&
        report.renotify_called && report.renotify_result == VIREO_RESULT_IO && report.renotify_error.system_errno == EINTR &&
        m.consume_calls == 1 && m.drain_calls == 1 && m.notify_calls == 1 && remaining == NULL);
    counts(&f, 1, 1); uint64_t count; EXPECT(vireo_notifier_consume(f.notifier, &count, NULL), VIREO_OK); CHECK(count == 0);
    /* caller 明确恢复为立即再调度，不能盲等已丢失的提示；不重放标签1。 */
    report = invoke(&f, 4, &d, &remaining, VIREO_OK); CHECK(report.notification_count == 0 && d.calls == 2 && d.seen[1] == 2);
    counts(&f, 0, 0); cleanup(&f);
}

static void transferred_error_keeps_owner(void) {
    fixture_t f; setup(&f); publish(&f, 1, true, true); model_context_t m = {.drain_mode = MODEL_TRANSFER_ERROR};
    vireo_completion_t *remaining = NULL; vireo_notifier_completion_report_t report = invoke_model(&f, 4, NULL, &remaining, &m, VIREO_RESULT_INTERNAL);
    CHECK(report.stage == VIREO_NOTIFIER_COMPLETION_DRAIN && report.drain_report.received == 1 &&
        report.drain_report.queue_report.transferred && !report.drain_report.last_item_consume_called &&
        !report.renotify_called && remaining != NULL && m.notify_calls == 0); counts(&f, 0, 1);
    discard(&f, &remaining); counts(&f, 0, 0); cleanup(&f);
}

static void max_hint_is_not_item_budget(void) {
    fixture_t f; setup(&f); publish(&f, 1, true, false); model_context_t m = {.hint_max = true};
    vireo_completion_t *remaining = NULL; vireo_notifier_completion_report_t report = invoke_model(&f, 4, NULL, &remaining, &m, VIREO_OK);
    CHECK(report.notification_count == UINT64_MAX && report.drain_report.finished == 1 &&
        report.drain_report.pop_calls == 2 && !report.renotify_called); counts(&f, 0, 0); cleanup(&f);
}

static void already_pending_model_is_ok(void) {
    fixture_t f; setup(&f); publish(&f, 1, true, true); model_context_t m = {.already_pending = true};
    vireo_completion_t *remaining = NULL; vireo_notifier_completion_report_t report = invoke_model(&f, 1, NULL, &remaining, &m, VIREO_OK);
    CHECK(report.stage == VIREO_NOTIFIER_COMPLETION_NONE && report.renotify_needed && report.renotify_called &&
        report.renotify_outcome == VIREO_NOTIFIER_NOTIFY_ALREADY_PENDING && report.renotify_result == VIREO_OK &&
        m.notify_calls == 1); counts(&f, 0, 0); cleanup(&f);
}

static void basic_validation_before_consumption(void) {
    fixture_t f; setup(&f); publish(&f, 1, true, true);
    for (unsigned i = 0; i < 9; ++i) {
        vireo_completion_t *remaining = NULL; vireo_notifier_completion_report_t report; memset(&report, 0xa5, sizeof report);
        EXPECT(vireo_notifier_completion_consume_and_drain(i == 0 ? NULL : f.notifier,
            i == 1 ? NULL : f.store, i == 2 ? NULL : f.server, i == 3 ? NULL : f.queue,
            i == 7 ? 0 : (i == 8 ? VIREO_INFLIGHT_COMPLETION_DRAIN_MAX_ITEMS + 1 : 4),
            i == 4 ? NULL : deliver, NULL, i == 5 ? NULL : &remaining, i == 6 ? NULL : &report),
            i == 8 ? VIREO_RESULT_RANGE : VIREO_RESULT_INVALID_ARGUMENT);
        if (i != 6) not_started(report);
        CHECK(remaining == NULL); counts(&f, 1, 1);
    }
    uint64_t count; EXPECT(vireo_notifier_consume(f.notifier, &count, NULL), VIREO_OK); CHECK(count == 1); cleanup(&f);
}

static void nonempty_remaining_held(void) {
    fixture_t f; setup(&f); notify(&f); vireo_completion_t *remaining = completion_make(request_make(&f, 1));
    vireo_completion_t *const original = remaining; vireo_notifier_completion_report_t report;
    EXPECT(vireo_notifier_completion_consume_and_drain(f.notifier, f.store, f.server, f.queue, 4,
        deliver, NULL, &remaining, &report), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(remaining == original); not_started(report); discard(&f, &remaining);
    uint64_t count; EXPECT(vireo_notifier_consume(f.notifier, &count, NULL), VIREO_OK); CHECK(count == 1); cleanup(&f);
}

static void missing_ops_no_calls(void) {
    fixture_t f; setup(&f); model_context_t m = {0}; notify(&f);
    for (unsigned i = 0; i < 4; ++i) {
        vireo_notifier_completion_ops_t ops = model_ops;
        if (i == 1) ops.consume = NULL;
        if (i == 2) ops.drain = NULL;
        if (i == 3) ops.notify = NULL;
        vireo_completion_t *remaining = NULL; vireo_notifier_completion_report_t report;
        EXPECT(vireo_notifier_completion_with_ops(f.notifier, f.store, f.server, f.queue, 4,
            deliver, NULL, &remaining, &report, i == 0 ? NULL : &ops, &m), VIREO_RESULT_INVALID_ARGUMENT);
        not_started(report); CHECK(m.consume_calls == 0 && m.drain_calls == 0 && m.notify_calls == 0);
    }
    uint64_t count; EXPECT(vireo_notifier_consume(f.notifier, &count, NULL), VIREO_OK); CHECK(count == 1); cleanup(&f);
}

static void void_callback_keeps_caller_error(void) {
    fixture_t f; setup(&f); publish(&f, 1, true, true);
    delivery_context_t d = {.store = f.store, .fail_sequence = 1, .fail_result = VIREO_RESULT_DATABASE};
    dispatch_context_t c = {.fixture = &f, .budget = 4, .delivery = &d};
    EXPECT(vireo_notifier_loop_register(f.loop, f.notifier, ready, &c, &f.handle, NULL), VIREO_OK);
    CHECK(run(&f, 0) == 1 && c.result == VIREO_RESULT_DATABASE && c.remaining != NULL &&
        c.report.stage == VIREO_NOTIFIER_COMPLETION_DRAIN); discard(&f, &c.remaining);
    counts(&f, 0, 0); cleanup(&f);
}

/** worker 仅短借queue/notifier和拥有completion，不接触server/表/loop/客户fd。 */
typedef struct producer_context {
    vireo_completion_queue_t *queue; /**< 公开队列借用，到join后结束。 */
    vireo_notifier_t *notifier; /**< 公开提示对象借用，到join后结束。 */
    vireo_completion_t *owner; /**< worker 私有源owner，成功转移清空。 */
    vireo_result_t push_result; /**< 原提交结果，主线程仅join后读取。 */
    vireo_completion_queue_transfer_report_t push_report; /**< 真实转移报告，仅join后读。 */
    vireo_result_t notify_result; /**< 真实转移后notify结果，仅join后读。 */
} producer_context_t;

static void *produce(void *context) {
    producer_context_t *p = context; CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL) == 0);
    for (;;) {
        p->push_result = vireo_completion_queue_try_push(p->queue, &p->owner, &p->push_report);
        if (p->push_result != VIREO_RESULT_BUSY || p->push_report.transferred) break;
        CHECK(p->push_report.stage == VIREO_COMPLETION_QUEUE_TRANSFER_LOCK); sched_yield();
    }
    if (p->push_report.transferred) {
        vireo_notifier_notify_outcome_t outcome; p->notify_result = vireo_notifier_notify(p->notifier, &outcome, NULL);
    }
    return NULL;
}

static void producer_notification_and_reactor(void) {
    fixture_t f; setup(&f); vireo_task_metadata_t const request = request_make(&f, 1);
    EXPECT(vireo_inflight_store_register(f.store, f.server, request, NULL), VIREO_OK);
    producer_context_t p = {.queue = f.queue, .notifier = f.notifier, .owner = completion_make(request)};
    delivery_context_t d = {.store = f.store}; dispatch_context_t c = {.fixture = &f, .budget = 4, .delivery = &d};
    EXPECT(vireo_notifier_loop_register(f.loop, f.notifier, ready, &c, &f.handle, NULL), VIREO_OK);
    pthread_t thread; CHECK(pthread_create(&thread, NULL, produce, &p) == 0);
    CHECK(run(&f, 1000) == 1); CHECK(pthread_join(thread, NULL) == 0);
    CHECK(p.push_result == VIREO_OK && p.push_report.transferred && p.owner == NULL && p.notify_result == VIREO_OK);
    /* Reactor 若在producer解锁前try_pop，允许真实BUSY；补提示由下一轮处理。 */
    if (c.result == VIREO_RESULT_BUSY) { CHECK(c.report.renotify_called); CHECK(run(&f, 0) == 1); }
    CHECK(c.result == VIREO_OK && d.calls == 1 && c.remaining == NULL); counts(&f, 0, 0); cleanup(&f);
}

int main(void) {
    int previous; CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previous) == 0);
    struct test_case { char const *name; void (*run)(void); } const cases[] = {
        {"empty_zero", empty_zero}, {"excess_hints_empty_queue", excess_hints_empty_queue},
        {"zero_hint_still_drains", zero_hint_still_drains}, {"budget_lt_successive_rounds", budget_lt_successive_rounds},
        {"exact_budget_extra_empty_round", exact_budget_extra_empty_round}, {"late_request_cleaned", late_request_cleaned},
        {"late_client_cleaned", late_client_cleaned}, {"callback_error_retains_owner", callback_error_retains_owner},
        {"callback_busy_not_renotified", callback_busy_not_renotified}, {"closed_queue_retains_cancelled", closed_queue_retains_cancelled},
        {"consume_error_no_drain", consume_error_no_drain}, {"pop_busy_renotified", pop_busy_renotified},
        {"busy_primary_notify_error_secondary", busy_primary_notify_error_secondary},
        {"budget_notify_error_preserves_progress", budget_notify_error_preserves_progress},
        {"transferred_error_keeps_owner", transferred_error_keeps_owner}, {"max_hint_is_not_item_budget", max_hint_is_not_item_budget},
        {"already_pending_model_is_ok", already_pending_model_is_ok}, {"basic_validation_before_consumption", basic_validation_before_consumption},
        {"nonempty_remaining_held", nonempty_remaining_held}, {"missing_ops_no_calls", missing_ops_no_calls},
        {"void_callback_keeps_caller_error", void_callback_keeps_caller_error},
        {"producer_notification_and_reactor", producer_notification_and_reactor}
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
        size_t const before = fd_count(); cases[i].run(); CHECK(fd_count() == before); printf("PASS %s\n", cases[i].name);
    }
    printf("notifier completion dispatch: %zu groups passed\n", sizeof cases / sizeof cases[0]);
    CHECK(pthread_setcancelstate(previous, NULL) == 0); return 0;
}
