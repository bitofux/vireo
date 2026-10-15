/*
 * PROJECT : VIREO
 * FILE    : test_inflight_completion_drain.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-13
 * BRIEF   : 有界批次、残留结果所有权、真实前缀与并发腾空间
 */
#define _GNU_SOURCE
#include <vireo/net/inflight_completion_drain.h>
#include "inflight_completion_drain_internal.h"
#include <vireo/thread/completion_queue.h>
#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define CHECK(expr) do { if (!(expr)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #expr); exit(1); } } while (0)
_Static_assert(VIREO_INFLIGHT_NONE == 0 && VIREO_INFLIGHT_CHECK_CLIENT == 1 &&
    VIREO_INFLIGHT_MAKE_ROUTE == 2 && VIREO_INFLIGHT_MAKE_METADATA == 3 &&
    VIREO_INFLIGHT_CHECK_METADATA == 4 && VIREO_INFLIGHT_CHECK_SERVER == 5 &&
    VIREO_INFLIGHT_CHECK_RECORD == 6 && VIREO_INFLIGHT_ISSUE_INSTANCE == 7 &&
    VIREO_INFLIGHT_RETAIN_CANCEL == 8 && VIREO_INFLIGHT_RELEASE_CANCEL == 9 &&
    VIREO_INFLIGHT_CHECK_COMPLETION == 10 && VIREO_INFLIGHT_MATCH_RECORD == 11,
    "inflight stages are append-only");

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

static bool same(vireo_task_metadata_t a, vireo_task_metadata_t b) {
    return a.route.client_owner_id == b.route.client_owner_id &&
        a.route.client_slot_index == b.route.client_slot_index &&
        a.route.client_generation == b.route.client_generation &&
        a.route.request_sequence == b.route.request_sequence &&
        a.request_instance_id == b.request_instance_id &&
        a.operation == b.operation && a.deadline_ns == b.deadline_ns;
}

static vireo_inflight_store_t *store_create(size_t capacity) {
    vireo_inflight_store_t *store = NULL;
    vireo_inflight_store_options_t const options = {capacity, 65536};
    CHECK(vireo_inflight_store_create(&options, &store) == VIREO_OK);
    return store;
}

static vireo_task_metadata_t metadata_make(fixture_t *f, uint32_t sequence, uint64_t deadline) {
    vireo_task_metadata_t metadata;
    CHECK(vireo_inflight_metadata_make_next(f->server, f->client, sequence, 9, deadline,
        &metadata, NULL) == VIREO_OK);
    return metadata;
}

static vireo_completion_t *completion_create(vireo_task_metadata_t request, vireo_result_t result) {
    vireo_completion_metadata_t metadata;
    CHECK(vireo_completion_metadata_make(request, result, VIREO_STATUS_INTERNAL_ERROR,
        &metadata) == VIREO_OK);
    unsigned char bytes[] = {0, 255, 42};
    vireo_completion_t *completion = NULL;
    CHECK(vireo_completion_create_copy(metadata, bytes, sizeof bytes, 65536, &completion) == VIREO_OK);
    bytes[2] = 99;
    return completion;
}

static void register_record(vireo_inflight_store_t *store, fixture_t *f, vireo_task_metadata_t request) {
    CHECK(vireo_inflight_store_register(store, f->server, request, NULL) == VIREO_OK);
}

static void take_record(vireo_inflight_store_t *store, vireo_task_metadata_t request) {
    vireo_task_metadata_t record;
    CHECK(vireo_inflight_store_take(store, request, &record, NULL) == VIREO_OK && same(record, request));
}

static void count_is(vireo_inflight_store_t *store, size_t expected) {
    vireo_inflight_store_info_t info;
    CHECK(vireo_inflight_store_inspect(store, &info) == VIREO_OK && info.count == expected);
}

_Static_assert(VIREO_INFLIGHT_COMPLETION_DRAIN_NONE == 0 &&
    VIREO_INFLIGHT_COMPLETION_DRAIN_POP == 1 && VIREO_INFLIGHT_COMPLETION_DRAIN_CONSUME == 2,
    "independent batch stages");
_Static_assert(VIREO_INFLIGHT_COMPLETION_DRAIN_NOT_STARTED == 0 &&
    VIREO_INFLIGHT_COMPLETION_DRAIN_EMPTY == 1 && VIREO_INFLIGHT_COMPLETION_DRAIN_BUDGET == 2 &&
    VIREO_INFLIGHT_COMPLETION_DRAIN_ERROR == 3, "batch stop reasons");

/** Reactor 独占账本，callback 只短借结果，保存的均为独立值。 */
typedef struct delivery_context {
    vireo_inflight_store_t *store; /**< 原表短借，检查先退额。 */
    vireo_tcp_server_t *server; /**< 仅新请求登记用的资源根短借。 */
    vireo_task_metadata_t seen[8]; /**< 实际回调顺序的独立快照，本测试最多八次。 */
    size_t calls; /**< Reactor 串行调用次数，0..8。 */
    uint32_t fail_sequence; /**< 非零时该标签真实返回 fail_result；0 不注入。 */
    vireo_result_t fail_result; /**< 本次真实回调选择的失败类。 */
    bool spawn; /**< 第一次回调显式登记同标签新实例。 */
    vireo_task_metadata_t spawned; /**< 新登记快照，caller 后续显式取出清理。 */
} delivery_context_t;

static vireo_result_t deliver(void *context, vireo_completion_t const *completion,
    vireo_inflight_completion_match_t match) {
    if (context == NULL) return VIREO_OK;
    delivery_context_t *d = context;
    CHECK(d->calls < sizeof d->seen / sizeof d->seen[0]);
    d->seen[d->calls++] = match.metadata;
    CHECK(match.close_state == VIREO_CONNECTION_CLOSE_OPEN);
    vireo_task_metadata_t missing;
    CHECK(vireo_inflight_store_get(d->store, match.metadata, &missing, NULL) == VIREO_RESULT_NOT_FOUND);
    vireo_completion_info_t info;
    vireo_completion_payload_view_t view;
    CHECK(vireo_completion_inspect(completion, &info) == VIREO_OK && same(info.metadata.request, match.metadata));
    CHECK(vireo_completion_borrow_payload(completion, &view) == VIREO_OK && view.size == 3);
    CHECK(view.data[0] == 0 && view.data[1] == 255 && view.data[2] == 42);
    if (d->spawn && d->calls == 1) {
        vireo_connection_pool_lease_t const client = {match.metadata.route.client_owner_id,
            match.metadata.route.client_slot_index, match.metadata.route.client_generation};
        CHECK(vireo_inflight_metadata_make_next(d->server, client, match.metadata.route.request_sequence,
            match.metadata.operation, match.metadata.deadline_ns, &d->spawned, NULL) == VIREO_OK);
        CHECK(d->spawned.request_instance_id != match.metadata.request_instance_id);
        CHECK(vireo_inflight_store_register(d->store, d->server, d->spawned, NULL) == VIREO_OK);
    }
    errno = ENOSPC;
    return match.metadata.route.request_sequence == d->fail_sequence ? d->fail_result : VIREO_OK;
}

static vireo_completion_queue_t *queue_create(size_t capacity) {
    vireo_completion_queue_t *queue = NULL;
    vireo_completion_queue_options_t const options = {capacity, VIREO_COMPLETION_QUEUE_MAX_ALLOCATION_BYTES};
    CHECK(vireo_completion_queue_create(&options, &queue) == VIREO_OK);
    return queue;
}

static void enqueue(vireo_completion_queue_t *queue, vireo_task_metadata_t request) {
    vireo_completion_t *completion = completion_create(request, VIREO_RESULT_DATABASE);
    vireo_completion_queue_transfer_report_t report;
    CHECK(vireo_completion_queue_try_push(queue, &completion, &report) == VIREO_OK);
    CHECK(report.transferred && completion == NULL);
}

static void queue_count_is(vireo_completion_queue_t *queue, size_t count) {
    vireo_completion_queue_info_t info;
    CHECK(vireo_completion_queue_inspect(queue, &info) == VIREO_OK && info.count == count);
}

static void close_queue(vireo_completion_queue_t *queue) {
    vireo_completion_queue_close_report_t report;
    CHECK(vireo_completion_queue_close(queue, &report) == VIREO_OK);
}

static vireo_inflight_completion_drain_report_t drain_is(fixture_t *f, vireo_inflight_store_t *store,
    vireo_completion_queue_t *queue, size_t budget, delivery_context_t *d,
    vireo_completion_t **remaining, vireo_result_t expected) {
    vireo_inflight_completion_drain_report_t report;
    memset(&report, 0xa5, sizeof report);
    errno = EDOM;
    CHECK(vireo_inflight_store_drain_completions(store, f->server, queue, budget,
        deliver, d, remaining, &report) == expected);
    CHECK(errno == EDOM && report.pop_calls <= budget && report.received <= report.pop_calls &&
        report.finished <= report.received && report.late_cleaned <= report.finished &&
        report.delivered <= report.received);
    return report;
}

static void empty_tail_is(vireo_inflight_completion_drain_report_t report) {
    CHECK(!report.last_item_consume_called && !report.queue_report.transferred &&
        report.queue_report.stage == VIREO_COMPLETION_QUEUE_TRANSFER_NONE && report.queue_report.pthread_error == 0);
    CHECK(report.consume_report.stage == VIREO_INFLIGHT_CONSUME_NONE &&
        report.consume_report.disposition == VIREO_INFLIGHT_COMPLETION_NONE &&
        !report.consume_report.completion_inspected && !report.consume_report.delivery_called &&
        !report.consume_report.record_consumed && !report.consume_report.destroy_called &&
        !report.consume_report.completion_consumed && report.consume_report.completion_metadata.request.request_instance_id == 0);
}

static void not_started_is(vireo_inflight_completion_drain_report_t report) {
    CHECK(report.stage == VIREO_INFLIGHT_COMPLETION_DRAIN_NONE &&
        report.stop_reason == VIREO_INFLIGHT_COMPLETION_DRAIN_NOT_STARTED && report.pop_calls == 0 &&
        report.received == 0 && report.finished == 0 && report.delivered == 0 && report.late_cleaned == 0);
    empty_tail_is(report);
}

static bool open_empty_reset(void) {
    fixture_t f; CHECK(setup(&f));
    vireo_inflight_store_t *store = store_create(1);
    vireo_completion_queue_t *queue = queue_create(1);
    vireo_completion_t *remaining = NULL;
    vireo_inflight_completion_drain_report_t const report = drain_is(&f, store, queue, 3, NULL, &remaining, VIREO_OK);
    CHECK(report.stage == VIREO_INFLIGHT_COMPLETION_DRAIN_NONE &&
        report.stop_reason == VIREO_INFLIGHT_COMPLETION_DRAIN_EMPTY && report.pop_calls == 1 &&
        report.received == 0 && report.finished == 0 && remaining == NULL);
    empty_tail_is(report);
    CHECK(vireo_completion_queue_destroy(&queue) == VIREO_OK && vireo_inflight_store_destroy(&store) == VIREO_OK);
    return cleanup(&f);
}

static bool budget_fifo_resume(void) {
    fixture_t f; CHECK(setup(&f));
    vireo_inflight_store_t *store = store_create(3);
    vireo_completion_queue_t *queue = queue_create(3);
    vireo_task_metadata_t requests[3];
    for (unsigned i = 0; i < 3; ++i) { requests[i] = metadata_make(&f, i + 1, UINT64_MAX); register_record(store, &f, requests[i]); enqueue(queue, requests[i]); }
    delivery_context_t d = {.store = store, .server = f.server};
    vireo_completion_t *remaining = NULL;
    for (size_t i = 0; i < 2; ++i) {
        vireo_inflight_completion_drain_report_t const report = drain_is(&f, store, queue, 1, &d, &remaining, VIREO_OK);
        CHECK(report.stop_reason == VIREO_INFLIGHT_COMPLETION_DRAIN_BUDGET && report.pop_calls == 1 &&
            report.received == 1 && report.finished == 1 && report.delivered == 1 && report.late_cleaned == 0 &&
            report.last_item_consume_called && same(report.consume_report.match.metadata, requests[i]) && remaining == NULL);
        count_is(store, 2 - i); queue_count_is(queue, 2 - i);
    }
    vireo_inflight_completion_drain_report_t const last = drain_is(&f, store, queue, 3, &d, &remaining, VIREO_OK);
    CHECK(last.stop_reason == VIREO_INFLIGHT_COMPLETION_DRAIN_EMPTY && last.pop_calls == 2 &&
        last.received == 1 && last.finished == 1 && last.delivered == 1 && last.late_cleaned == 0);
    empty_tail_is(last);
    CHECK(d.calls == 3); for (unsigned i = 0; i < 3; ++i) CHECK(same(d.seen[i], requests[i]));
    CHECK(vireo_completion_queue_destroy(&queue) == VIREO_OK && vireo_inflight_store_destroy(&store) == VIREO_OK);
    return cleanup(&f);
}

static bool exact_budget_no_probe(void) {
    fixture_t f; CHECK(setup(&f));
    vireo_inflight_store_t *store = store_create(1);
    vireo_completion_queue_t *queue = queue_create(1);
    vireo_task_metadata_t const request = metadata_make(&f, 1, 0);
    enqueue(queue, request);
    vireo_completion_t *remaining = NULL;
    vireo_inflight_completion_drain_report_t report = drain_is(&f, store, queue, 1, NULL, &remaining, VIREO_OK);
    CHECK(report.stop_reason == VIREO_INFLIGHT_COMPLETION_DRAIN_BUDGET && report.pop_calls == 1 &&
        report.received == 1 && report.finished == 1 && report.late_cleaned == 1 && report.delivered == 0);
    report = drain_is(&f, store, queue, 1, NULL, &remaining, VIREO_OK);
    CHECK(report.stop_reason == VIREO_INFLIGHT_COMPLETION_DRAIN_EMPTY && report.pop_calls == 1 && report.received == 0);
    CHECK(vireo_completion_queue_destroy(&queue) == VIREO_OK && vireo_inflight_store_destroy(&store) == VIREO_OK);
    return cleanup(&f);
}

static bool maximum_budget(void) {
    fixture_t f; CHECK(setup(&f));
    vireo_inflight_store_t *store = store_create(1);
    size_t const maximum = VIREO_INFLIGHT_COMPLETION_DRAIN_MAX_ITEMS;
    vireo_completion_queue_t *queue = queue_create(maximum);
    vireo_task_metadata_t const old = metadata_make(&f, 1, 0);
    /* 合法重复旧结果，每份 owner 独立；不反复登记同一个活跃请求。 */
    for (size_t i = 0; i < maximum; ++i) enqueue(queue, old);
    vireo_completion_t *remaining = NULL;
    vireo_inflight_completion_drain_report_t const report = drain_is(&f, store, queue, maximum, NULL, &remaining, VIREO_OK);
    CHECK(report.stop_reason == VIREO_INFLIGHT_COMPLETION_DRAIN_BUDGET && report.pop_calls == maximum &&
        report.received == maximum && report.finished == maximum && report.late_cleaned == maximum && report.delivered == 0);
    queue_count_is(queue, 0);
    CHECK(vireo_completion_queue_destroy(&queue) == VIREO_OK && vireo_inflight_store_destroy(&store) == VIREO_OK);
    return cleanup(&f);
}

static bool basic_priority(void) {
    fixture_t f; CHECK(setup(&f));
    vireo_inflight_store_t *store = store_create(1);
    vireo_completion_queue_t *queue = queue_create(1);
    vireo_task_metadata_t const request = metadata_make(&f, 1, 100);
    register_record(store, &f, request); enqueue(queue, request);
    vireo_completion_t *remaining = NULL;
    for (unsigned i = 0; i < 8; ++i) {
        vireo_inflight_completion_drain_report_t report;
        memset(&report, 0xa5, sizeof report); errno = EIO;
        CHECK(vireo_inflight_store_drain_completions(i == 0 ? NULL : store, i == 1 ? NULL : f.server,
            i == 2 ? NULL : queue, i == 3 ? 0 : 1, i == 4 ? NULL : deliver, NULL,
            i == 5 ? NULL : &remaining, i == 6 ? NULL : &report) == (i == 7 ? VIREO_OK : VIREO_RESULT_INVALID_ARGUMENT));
        CHECK(errno == EIO && remaining == NULL);
        if (i < 6) not_started_is(report);
    }
    count_is(store, 0); queue_count_is(queue, 0);
    remaining = completion_create(request, VIREO_OK); vireo_completion_t *before = remaining;
    vireo_inflight_completion_drain_report_t report = drain_is(&f, store, queue,
        VIREO_INFLIGHT_COMPLETION_DRAIN_MAX_ITEMS + 1, NULL, &remaining, VIREO_RESULT_INVALID_ARGUMENT);
    not_started_is(report); CHECK(remaining == before);
    CHECK(vireo_completion_destroy(&remaining) == VIREO_OK);
    report = drain_is(&f, store, queue, VIREO_INFLIGHT_COMPLETION_DRAIN_MAX_ITEMS + 1,
        NULL, &remaining, VIREO_RESULT_RANGE); not_started_is(report);
    CHECK(vireo_completion_queue_destroy(&queue) == VIREO_OK && vireo_inflight_store_destroy(&store) == VIREO_OK);
    return cleanup(&f);
}

static bool nullable_context_business_result(void) {
    fixture_t f; CHECK(setup(&f)); vireo_inflight_store_t *store = store_create(1);
    vireo_completion_queue_t *queue = queue_create(1); vireo_completion_t *remaining = NULL;
    vireo_task_metadata_t const request = metadata_make(&f, 1, UINT64_MAX);
    register_record(store, &f, request); enqueue(queue, request);
    vireo_inflight_completion_drain_report_t const report = drain_is(&f, store, queue, 1, NULL, &remaining, VIREO_OK);
    CHECK(report.delivered == 1 && report.finished == 1 && report.late_cleaned == 0 &&
        report.consume_report.completion_metadata.result == VIREO_RESULT_DATABASE && remaining == NULL);
    CHECK(vireo_completion_queue_destroy(&queue) == VIREO_OK && vireo_inflight_store_destroy(&store) == VIREO_OK);
    return cleanup(&f);
}

static bool closed_results_and_empty(void) {
    fixture_t f; CHECK(setup(&f)); vireo_inflight_store_t *store = store_create(2);
    vireo_completion_queue_t *queue = queue_create(2); vireo_completion_t *remaining = NULL;
    for (uint32_t i = 1; i <= 2; ++i) { vireo_task_metadata_t request = metadata_make(&f, i, 0); register_record(store, &f, request); enqueue(queue, request); }
    close_queue(queue); delivery_context_t d = {.store = store};
    vireo_inflight_completion_drain_report_t report = drain_is(&f, store, queue, 3, &d, &remaining, VIREO_RESULT_CANCELLED);
    CHECK(report.stage == VIREO_INFLIGHT_COMPLETION_DRAIN_POP && report.stop_reason == VIREO_INFLIGHT_COMPLETION_DRAIN_ERROR &&
        report.pop_calls == 3 && report.received == 2 && report.finished == 2 && report.delivered == 2 && remaining == NULL && d.calls == 2);
    empty_tail_is(report);
    report = drain_is(&f, store, queue, 1, NULL, &remaining, VIREO_RESULT_CANCELLED);
    CHECK(report.finished == 0 && report.pop_calls == 1); empty_tail_is(report);
    CHECK(vireo_completion_queue_destroy(&queue) == VIREO_OK && vireo_inflight_store_destroy(&store) == VIREO_OK);
    return cleanup(&f);
}

static bool callback_error_prefix(void) {
    fixture_t f; CHECK(setup(&f)); vireo_inflight_store_t *store = store_create(3);
    vireo_completion_queue_t *queue = queue_create(3); vireo_completion_t *remaining = NULL;
    vireo_task_metadata_t requests[3];
    for (unsigned i = 0; i < 3; ++i) { requests[i] = metadata_make(&f, i + 1, 100); register_record(store, &f, requests[i]); enqueue(queue, requests[i]); }
    delivery_context_t d = {.store = store, .fail_sequence = 2, .fail_result = VIREO_RESULT_IO};
    vireo_inflight_completion_drain_report_t report = drain_is(&f, store, queue, 3, &d, &remaining, VIREO_RESULT_IO);
    CHECK(report.stage == VIREO_INFLIGHT_COMPLETION_DRAIN_CONSUME && report.stop_reason == VIREO_INFLIGHT_COMPLETION_DRAIN_ERROR &&
        report.pop_calls == 2 && report.received == 2 && report.finished == 1 && report.delivered == 1 && report.late_cleaned == 0 &&
        report.last_item_consume_called && report.queue_report.transferred && report.consume_report.record_consumed &&
        report.consume_report.delivery_called && report.consume_report.delivery_result == VIREO_RESULT_IO &&
        !report.consume_report.destroy_called && !report.consume_report.completion_consumed && remaining != NULL && d.calls == 2);
    vireo_completion_info_t info; CHECK(vireo_completion_inspect(remaining, &info) == VIREO_OK && same(info.metadata.request, requests[1]));
    count_is(store, 1); queue_count_is(queue, 1);
    vireo_completion_t *before = remaining;
    report = drain_is(&f, store, queue, 3, &d, &remaining, VIREO_RESULT_INVALID_ARGUMENT);
    not_started_is(report); CHECK(remaining == before && d.calls == 2);
    CHECK(vireo_completion_destroy(&remaining) == VIREO_OK); d.fail_sequence = 0;
    report = drain_is(&f, store, queue, 3, &d, &remaining, VIREO_OK);
    CHECK(report.finished == 1 && d.calls == 3 && same(d.seen[2], requests[2]));
    CHECK(vireo_completion_queue_destroy(&queue) == VIREO_OK && vireo_inflight_store_destroy(&store) == VIREO_OK);
    return cleanup(&f);
}

static bool callback_notfound_is_error(void) {
    fixture_t f; CHECK(setup(&f)); vireo_inflight_store_t *store = store_create(1);
    vireo_completion_queue_t *queue = queue_create(1); vireo_completion_t *remaining = NULL;
    vireo_task_metadata_t request = metadata_make(&f, 1, 0); register_record(store, &f, request); enqueue(queue, request);
    delivery_context_t d = {.store = store, .fail_sequence = 1, .fail_result = VIREO_RESULT_NOT_FOUND};
    vireo_inflight_completion_drain_report_t const report = drain_is(&f, store, queue, 2, &d, &remaining, VIREO_RESULT_NOT_FOUND);
    CHECK(report.stage == VIREO_INFLIGHT_COMPLETION_DRAIN_CONSUME && report.stop_reason == VIREO_INFLIGHT_COMPLETION_DRAIN_ERROR &&
        report.pop_calls == 1 && report.received == 1 && report.finished == 0 && report.delivered == 0 && remaining != NULL);
    CHECK(vireo_completion_destroy(&remaining) == VIREO_OK);
    CHECK(vireo_completion_queue_destroy(&queue) == VIREO_OK && vireo_inflight_store_destroy(&store) == VIREO_OK);
    return cleanup(&f);
}

static bool mixed_client_generation_history(void) {
    fixture_t f; CHECK(setup(&f)); vireo_inflight_store_t *store = store_create(3);
    vireo_completion_queue_t *queue = queue_create(3); vireo_completion_t *remaining = NULL;
    vireo_task_metadata_t old = metadata_make(&f, 1, 0), missing = metadata_make(&f, 2, 0);
    register_record(store, &f, old); enqueue(queue, old); enqueue(queue, missing);
    CHECK(release_client(&f) && add_client(&f));
    vireo_task_metadata_t current = metadata_make(&f, 1, 0);
    CHECK(old.route.client_slot_index == current.route.client_slot_index && old.route.client_generation != current.route.client_generation);
    register_record(store, &f, current); enqueue(queue, current);
    delivery_context_t d = {.store = store};
    vireo_inflight_completion_drain_report_t const report = drain_is(&f, store, queue, 3, &d, &remaining, VIREO_OK);
    CHECK(report.finished == 3 && report.received == 3 && report.delivered == 1 && report.late_cleaned == 2 &&
        d.calls == 1 && same(d.seen[0], current) && report.last_item_consume_called &&
        report.consume_report.disposition == VIREO_INFLIGHT_COMPLETION_MATCHED);
    count_is(store, 0); CHECK(vireo_completion_queue_destroy(&queue) == VIREO_OK && vireo_inflight_store_destroy(&store) == VIREO_OK);
    return cleanup(&f);
}

static bool snapshot_error_after_prefix(void) {
    fixture_t f; CHECK(setup(&f)); vireo_inflight_store_t *store = store_create(3);
    vireo_completion_queue_t *queue = queue_create(3); vireo_completion_t *remaining = NULL;
    vireo_task_metadata_t requests[3];
    for (unsigned i = 0; i < 3; ++i) { requests[i] = metadata_make(&f, i + 1, 0); register_record(store, &f, requests[i]); vireo_task_metadata_t changed = requests[i]; if (i == 1) changed.deadline_ns = 1; enqueue(queue, changed); }
    delivery_context_t d = {.store = store};
    vireo_inflight_completion_drain_report_t report = drain_is(&f, store, queue, 3, &d, &remaining, VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(report.finished == 1 && report.received == 2 && report.pop_calls == 2 && report.delivered == 1 &&
        report.consume_report.inflight_stage == VIREO_INFLIGHT_MATCH_RECORD && !report.consume_report.record_consumed && remaining != NULL);
    count_is(store, 2); queue_count_is(queue, 1);
    CHECK(vireo_completion_destroy(&remaining) == VIREO_OK); take_record(store, requests[1]);
    report = drain_is(&f, store, queue, 2, &d, &remaining, VIREO_OK); CHECK(report.finished == 1 && d.calls == 2);
    CHECK(vireo_completion_queue_destroy(&queue) == VIREO_OK && vireo_inflight_store_destroy(&store) == VIREO_OK);
    return cleanup(&f);
}

static bool cross_domain_failure(void) {
    fixture_t f; CHECK(setup(&f)); vireo_inflight_store_t *store = store_create(1);
    vireo_completion_queue_t *queue = queue_create(1); vireo_completion_t *remaining = NULL;
    vireo_task_metadata_t const request = metadata_make(&f, 1, 0); register_record(store, &f, request); enqueue(queue, request);
    vireo_tcp_server_t *original = f.server; f.server = f.other_server;
    vireo_inflight_completion_drain_report_t const report = drain_is(&f, store, queue, 1, NULL, &remaining, VIREO_RESULT_INVALID_ARGUMENT);
    f.server = original;
    CHECK(report.received == 1 && report.finished == 0 && !report.consume_report.record_consumed &&
        report.consume_report.inflight_stage == VIREO_INFLIGHT_CHECK_CLIENT && remaining != NULL);
    count_is(store, 1); CHECK(vireo_completion_destroy(&remaining) == VIREO_OK); take_record(store, request);
    CHECK(vireo_completion_queue_destroy(&queue) == VIREO_OK && vireo_inflight_store_destroy(&store) == VIREO_OK);
    return cleanup(&f);
}

static bool callback_new_request_survives(void) {
    fixture_t f; CHECK(setup(&f)); vireo_inflight_store_t *store = store_create(2);
    vireo_completion_queue_t *queue = queue_create(1); vireo_completion_t *remaining = NULL;
    vireo_task_metadata_t const request = metadata_make(&f, 1, 0); register_record(store, &f, request); enqueue(queue, request);
    delivery_context_t d = {.store = store, .server = f.server, .spawn = true};
    vireo_inflight_completion_drain_report_t const report = drain_is(&f, store, queue, 2, &d, &remaining, VIREO_OK);
    CHECK(report.finished == 1 && report.delivered == 1 && d.calls == 1 &&
        report.stop_reason == VIREO_INFLIGHT_COMPLETION_DRAIN_EMPTY);
    count_is(store, 1); take_record(store, d.spawned);
    CHECK(vireo_completion_queue_destroy(&queue) == VIREO_OK && vireo_inflight_store_destroy(&store) == VIREO_OK);
    return cleanup(&f);
}

/** 本接线层隔离依赖报告；进度取自真实公开调用，额外错误只是模型。 */
typedef struct fault_context {
    size_t pop_calls; /**< seam 已调用次数，不是批次业务累计。 */
    size_t consume_calls; /**< 单项 seam 已调用次数。 */
    size_t fail_pop_call; /**< 非零时注入该次领取报告。 */
    size_t fail_consume_call; /**< 非零时注入该次消费报告。 */
    bool after_progress; /**< true 先执行真实依赖，再模拟返回失败。 */
    vireo_result_t error; /**< 本层模拟的原返回类别。 */
    vireo_completion_queue_transfer_stage_t queue_stage; /**< 领取诊断阶段模型。 */
    int pthread_error; /**< 领取诊断原因模型，不宣称内核真的报错。 */
} fault_context_t;

static vireo_result_t pop_fault(void *context, vireo_completion_queue_t *queue,
    vireo_completion_t **owner, vireo_completion_queue_transfer_report_t *report) {
    fault_context_t *f = context;
    ++f->pop_calls;
    if (f->pop_calls != f->fail_pop_call) return vireo_completion_queue_try_pop(queue, owner, report);
    if (f->after_progress) CHECK(vireo_completion_queue_try_pop(queue, owner, report) == VIREO_OK);
    else *report = (vireo_completion_queue_transfer_report_t){0};
    report->stage = f->queue_stage;
    report->pthread_error = f->pthread_error;
    errno = EFAULT;
    return f->error;
}

static vireo_result_t consume_fault(void *context, vireo_inflight_store_t *store,
    vireo_tcp_server_t const *server, vireo_completion_t **owner,
    vireo_inflight_completion_deliver_fn callback, void *callback_context,
    vireo_inflight_completion_consume_report_t *report) {
    fault_context_t *f = context;
    ++f->consume_calls;
    if (f->consume_calls != f->fail_consume_call)
        return vireo_inflight_store_consume_completion(store, server, owner, callback, callback_context, report);
    if (f->after_progress) {
        CHECK(vireo_inflight_store_consume_completion(store, server, owner, callback, callback_context, report) == VIREO_OK);
        report->stage = VIREO_INFLIGHT_CONSUME_DESTROY;
        report->destroy_result = f->error;
    } else {
        *report = (vireo_inflight_completion_consume_report_t){0};
        report->stage = VIREO_INFLIGHT_CONSUME_CHECK_MATCH;
    }
    errno = EFAULT;
    return f->error;
}

static vireo_inflight_completion_drain_ops_t const fault_ops = {pop_fault, consume_fault};

static vireo_inflight_completion_drain_report_t fault_drain(fixture_t *f,
    vireo_inflight_store_t *store, vireo_completion_queue_t *queue, delivery_context_t *d,
    vireo_completion_t **remaining, fault_context_t *fault, vireo_result_t expected) {
    vireo_inflight_completion_drain_report_t report;
    memset(&report, 0xa5, sizeof report); errno = EDOM;
    CHECK(vireo_inflight_completion_drain_with_ops(store, f->server, queue, 3,
        deliver, d, remaining, &report, &fault_ops, fault) == expected && errno == EDOM);
    return report;
}

static bool pop_failure_before_transfer_prefix(void) {
    fixture_t f; CHECK(setup(&f)); vireo_inflight_store_t *store = store_create(2);
    vireo_completion_queue_t *queue = queue_create(2); vireo_completion_t *remaining = NULL;
    for (uint32_t i = 1; i <= 2; ++i) { vireo_task_metadata_t request = metadata_make(&f, i, 0); register_record(store, &f, request); enqueue(queue, request); }
    delivery_context_t d = {.store = store};
    fault_context_t fault = {.fail_pop_call = 2, .error = VIREO_RESULT_BUSY,
        .queue_stage = VIREO_COMPLETION_QUEUE_TRANSFER_LOCK, .pthread_error = EBUSY};
    vireo_inflight_completion_drain_report_t report = fault_drain(&f, store, queue, &d, &remaining, &fault, VIREO_RESULT_BUSY);
    CHECK(report.stage == VIREO_INFLIGHT_COMPLETION_DRAIN_POP && report.pop_calls == 2 &&
        report.received == 1 && report.finished == 1 && report.delivered == 1 &&
        !report.last_item_consume_called && !report.queue_report.transferred &&
        report.queue_report.pthread_error == EBUSY && report.consume_report.stage == 0 && remaining == NULL);
    count_is(store, 1); queue_count_is(queue, 1);
    report = drain_is(&f, store, queue, 2, &d, &remaining, VIREO_OK); CHECK(report.finished == 1 && d.calls == 2);
    CHECK(vireo_completion_queue_destroy(&queue) == VIREO_OK && vireo_inflight_store_destroy(&store) == VIREO_OK);
    return cleanup(&f);
}

static bool pop_failure_after_transfer(void) {
    fixture_t f; CHECK(setup(&f)); vireo_inflight_store_t *store = store_create(2);
    vireo_completion_queue_t *queue = queue_create(2); vireo_completion_t *remaining = NULL;
    for (uint32_t i = 1; i <= 2; ++i) { vireo_task_metadata_t request = metadata_make(&f, i, 0); register_record(store, &f, request); enqueue(queue, request); }
    delivery_context_t d = {.store = store};
    fault_context_t fault = {.fail_pop_call = 1, .after_progress = true, .error = VIREO_RESULT_INTERNAL,
        .queue_stage = VIREO_COMPLETION_QUEUE_TRANSFER_UNLOCK, .pthread_error = EINVAL};
    vireo_inflight_completion_drain_report_t report = fault_drain(&f, store, queue, &d, &remaining, &fault, VIREO_RESULT_INTERNAL);
    CHECK(report.received == 1 && report.finished == 0 && report.pop_calls == 1 &&
        report.queue_report.transferred && !report.last_item_consume_called && fault.consume_calls == 0 && remaining != NULL);
    count_is(store, 2); queue_count_is(queue, 1);
    vireo_inflight_completion_consume_report_t consume;
    CHECK(vireo_inflight_store_consume_completion(store, f.server, &remaining, deliver, &d, &consume) == VIREO_OK);
    CHECK(remaining == NULL && consume.record_consumed);
    report = drain_is(&f, store, queue, 2, &d, &remaining, VIREO_OK); CHECK(report.finished == 1 && d.calls == 2);
    CHECK(vireo_completion_queue_destroy(&queue) == VIREO_OK && vireo_inflight_store_destroy(&store) == VIREO_OK);
    return cleanup(&f);
}

static bool consume_failure_before_progress(void) {
    fixture_t f; CHECK(setup(&f)); vireo_inflight_store_t *store = store_create(1);
    vireo_completion_queue_t *queue = queue_create(1); vireo_completion_t *remaining = NULL;
    vireo_task_metadata_t const request = metadata_make(&f, 1, 0); register_record(store, &f, request); enqueue(queue, request);
    fault_context_t fault = {.fail_consume_call = 1, .error = VIREO_RESULT_IO};
    vireo_inflight_completion_drain_report_t const report = fault_drain(&f, store, queue, NULL, &remaining, &fault, VIREO_RESULT_IO);
    CHECK(report.stage == VIREO_INFLIGHT_COMPLETION_DRAIN_CONSUME && report.received == 1 &&
        report.finished == 0 && report.delivered == 0 && report.last_item_consume_called && remaining != NULL);
    count_is(store, 1); queue_count_is(queue, 0);
    CHECK(vireo_completion_destroy(&remaining) == VIREO_OK); take_record(store, request);
    CHECK(vireo_completion_queue_destroy(&queue) == VIREO_OK && vireo_inflight_store_destroy(&store) == VIREO_OK);
    return cleanup(&f);
}

static bool consume_failure_after_consumed(void) {
    fixture_t f; CHECK(setup(&f)); vireo_inflight_store_t *store = store_create(1);
    vireo_completion_queue_t *queue = queue_create(1); vireo_completion_t *remaining = NULL;
    vireo_task_metadata_t const request = metadata_make(&f, 1, 0); register_record(store, &f, request); enqueue(queue, request);
    delivery_context_t d = {.store = store};
    fault_context_t fault = {.fail_consume_call = 1, .after_progress = true, .error = VIREO_RESULT_IO};
    vireo_inflight_completion_drain_report_t const report = fault_drain(&f, store, queue, &d, &remaining, &fault, VIREO_RESULT_IO);
    CHECK(report.received == 1 && report.finished == 0 && report.delivered == 1 && report.late_cleaned == 0 &&
        report.consume_report.record_consumed && report.consume_report.completion_consumed &&
        report.consume_report.destroy_result == VIREO_RESULT_IO && remaining == NULL && d.calls == 1);
    count_is(store, 0); queue_count_is(queue, 0);
    CHECK(vireo_completion_queue_destroy(&queue) == VIREO_OK && vireo_inflight_store_destroy(&store) == VIREO_OK);
    return cleanup(&f);
}

static bool invalid_ops_no_attempt(void) {
    fixture_t f; CHECK(setup(&f)); vireo_inflight_store_t *store = store_create(1);
    vireo_completion_queue_t *queue = queue_create(1); vireo_completion_t *remaining = NULL;
    for (unsigned i = 0; i < 3; ++i) {
        vireo_inflight_completion_drain_ops_t ops = fault_ops;
        if (i == 1) ops.pop = NULL;
        if (i == 2) ops.consume = NULL;
        vireo_inflight_completion_drain_report_t report; memset(&report, 0xa5, sizeof report); errno = ERANGE;
        CHECK(vireo_inflight_completion_drain_with_ops(store, f.server, queue, 1, deliver, NULL,
            &remaining, &report, i == 0 ? NULL : &ops, NULL) == VIREO_RESULT_INVALID_ARGUMENT && errno == ERANGE);
        not_started_is(report); CHECK(remaining == NULL);
    }
    CHECK(vireo_completion_queue_destroy(&queue) == VIREO_OK && vireo_inflight_store_destroy(&store) == VIREO_OK);
    return cleanup(&f);
}

static bool cancelled_is_not_empty(void) {
    fixture_t f; CHECK(setup(&f)); vireo_inflight_store_t *store = store_create(1);
    vireo_completion_queue_t *queue = queue_create(1); vireo_completion_t *remaining = NULL;
    fault_context_t fault = {.fail_pop_call = 1, .error = VIREO_RESULT_CANCELLED};
    vireo_inflight_completion_drain_report_t const report = fault_drain(&f, store, queue, NULL, &remaining, &fault, VIREO_RESULT_CANCELLED);
    CHECK(report.stop_reason == VIREO_INFLIGHT_COMPLETION_DRAIN_ERROR && report.pop_calls == 1 &&
        report.received == 0 && !report.last_item_consume_called && remaining == NULL);
    CHECK(vireo_completion_queue_destroy(&queue) == VIREO_OK && vireo_inflight_store_destroy(&store) == VIREO_OK);
    return cleanup(&f);
}

/** producer 不访问 server/store；元数据为启动前复制值。 */
typedef struct producer_context {
    vireo_completion_queue_t *queue; /**< 稳定借用的 prepared capacity=1 队列。 */
    vireo_task_metadata_t requests[3]; /**< 三个既有登记的独立元数据。 */
    pthread_barrier_t first_full; /**< 两参与者首项提交同步，join 后销毁。 */
} producer_context_t;

static void *produce(void *context) {
    producer_context_t *p = context;
    CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL) == 0);
    for (size_t i = 0; i < 3; ++i) {
        vireo_completion_t *owner = completion_create(p->requests[i], VIREO_OK);
        vireo_completion_queue_transfer_report_t report;
        CHECK(vireo_completion_queue_wait_push(p->queue, &owner, &report) == VIREO_OK && report.transferred && owner == NULL);
        if (i == 0) { int const r = pthread_barrier_wait(&p->first_full); CHECK(r == 0 || r == PTHREAD_BARRIER_SERIAL_THREAD); }
    }
    return NULL;
}

static bool producer_capacity_one_draining(void) {
    fixture_t f; CHECK(setup(&f)); vireo_inflight_store_t *store = store_create(3);
    vireo_completion_queue_t *queue = queue_create(1); vireo_completion_t *remaining = NULL;
    CHECK(vireo_completion_queue_prepare_wait(queue) == VIREO_OK);
    producer_context_t p = {.queue = queue};
    for (uint32_t i = 0; i < 3; ++i) { p.requests[i] = metadata_make(&f, i + 1, 0); register_record(store, &f, p.requests[i]); }
    CHECK(pthread_barrier_init(&p.first_full, NULL, 2) == 0);
    pthread_t thread; CHECK(pthread_create(&thread, NULL, produce, &p) == 0);
    int const barrier = pthread_barrier_wait(&p.first_full); CHECK(barrier == 0 || barrier == PTHREAD_BARRIER_SERIAL_THREAD);
    delivery_context_t d = {.store = store}; size_t finished = 0;
    for (size_t attempts = 0; finished < 3 && attempts < 100000; ++attempts) {
        vireo_inflight_completion_drain_report_t report; errno = EDOM;
        vireo_result_t const r = vireo_inflight_store_drain_completions(store, f.server, queue,
            1, deliver, &d, &remaining, &report);
        CHECK(errno == EDOM && remaining == NULL && report.pop_calls == 1);
        CHECK(r == VIREO_OK || r == VIREO_RESULT_BUSY);
        if (r == VIREO_OK) { CHECK(report.finished <= 1 && report.delivered == report.finished); finished += report.finished; }
        else CHECK(report.finished == 0 && !report.queue_report.transferred);
        sched_yield();
    }
    CHECK(finished == 3 && d.calls == 3);
    CHECK(pthread_join(thread, NULL) == 0 && pthread_barrier_destroy(&p.first_full) == 0);
    for (size_t i = 0; i < 3; ++i) CHECK(same(d.seen[i], p.requests[i]));
    close_queue(queue);
    vireo_inflight_completion_drain_report_t const report = drain_is(&f, store, queue, 1, &d, &remaining, VIREO_RESULT_CANCELLED);
    CHECK(report.finished == 0 && report.stop_reason == VIREO_INFLIGHT_COMPLETION_DRAIN_ERROR);
    count_is(store, 0); queue_count_is(queue, 0);
    CHECK(vireo_completion_queue_destroy(&queue) == VIREO_OK && vireo_inflight_store_destroy(&store) == VIREO_OK);
    return cleanup(&f);
}

int main(void) {
    int old_cancel; CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &old_cancel) == 0);
    struct test_case { char const *name; bool (*run)(void); } const cases[] = {
        {"open_empty_reset", open_empty_reset}, {"budget_fifo_resume", budget_fifo_resume},
        {"exact_budget_no_probe", exact_budget_no_probe}, {"maximum_budget", maximum_budget},
        {"basic_priority", basic_priority}, {"nullable_context_business_result", nullable_context_business_result},
        {"closed_results_and_empty", closed_results_and_empty}, {"callback_error_prefix", callback_error_prefix},
        {"callback_notfound_is_error", callback_notfound_is_error},
        {"mixed_client_generation_history", mixed_client_generation_history},
        {"snapshot_error_after_prefix", snapshot_error_after_prefix}, {"cross_domain_failure", cross_domain_failure},
        {"callback_new_request_survives", callback_new_request_survives},
        {"pop_failure_before_transfer_prefix", pop_failure_before_transfer_prefix},
        {"pop_failure_after_transfer", pop_failure_after_transfer},
        {"consume_failure_before_progress", consume_failure_before_progress},
        {"consume_failure_after_consumed", consume_failure_after_consumed},
        {"invalid_ops_no_attempt", invalid_ops_no_attempt}, {"cancelled_is_not_empty", cancelled_is_not_empty},
        {"producer_capacity_one_draining", producer_capacity_one_draining}
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; ++i) { CHECK(cases[i].run()); printf("PASS %s\n", cases[i].name); }
    printf("inflight completion drain: %zu groups passed\n", sizeof cases / sizeof cases[0]);
    CHECK(pthread_setcancelstate(old_cancel, NULL) == 0);
    return 0;
}
