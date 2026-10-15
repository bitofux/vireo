/*
 * PROJECT : VIREO
 * FILE    : test_inflight_completion_consume.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-13
 * BRIEF   : 单项交付、真实失败前缀及迟到历史记录配对清理
 */
#define _GNU_SOURCE
#include <vireo/net/inflight_completion.h>
#include <vireo/net/inflight_submit.h>
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
    CHECK(vireo_inflight_store_register_limited(store, f->server, request, 2, NULL) == VIREO_OK);
}

static void take_record(vireo_inflight_store_t *store, vireo_task_metadata_t request) {
    vireo_task_metadata_t record;
    CHECK(vireo_inflight_store_take(store, request, &record, NULL) == VIREO_OK && same(record, request));
}

static void count_is(vireo_inflight_store_t *store, size_t expected) {
    vireo_inflight_store_info_t info;
    CHECK(vireo_inflight_store_inspect(store, &info) == VIREO_OK && info.count == expected);
}

_Static_assert(VIREO_INFLIGHT_CONSUME_NONE == 0 && VIREO_INFLIGHT_CONSUME_INSPECT == 1 &&
    VIREO_INFLIGHT_CONSUME_CHECK_MATCH == 2 && VIREO_INFLIGHT_CONSUME_CHECK_RECORD == 3 &&
    VIREO_INFLIGHT_CONSUME_TAKE_RECORD == 4 && VIREO_INFLIGHT_CONSUME_DELIVER == 5 &&
    VIREO_INFLIGHT_CONSUME_DESTROY == 6, "new consume stages");

/** Reactor 侧同步交付账本，结果只借一次，必要字节在借用内复制。 */
typedef struct delivery_context {
    vireo_inflight_store_t *store; /**< caller 长借，回调只查原记录或登记新实例。 */
    vireo_tcp_server_t *server; /**< caller 长借，只有 spawn_new 时公开构造新请求。 */
    vireo_task_metadata_t expected; /**< 本次预期原完整快照，不保活。 */
    vireo_connection_close_state_t expected_state; /**< 预期核验时关闭阶段。 */
    vireo_result_t return_value; /**< 真实回调返回，用于失败前缀验证。 */
    size_t calls; /**< Reactor 串行累计回调条数。 */
    bool spawn_new; /**< 为真时同 sequence 登记新 instance。 */
    vireo_task_metadata_t spawned; /**< 回调新登记的独立快照，供显式清理。 */
    unsigned char bytes[3]; /**< 借用内复制的独立响应，结果销毁后仍可读。 */
} delivery_context_t;

static vireo_result_t deliver(void *context, vireo_completion_t const *completion,
    vireo_inflight_completion_match_t match) {
    if (context == NULL) return VIREO_OK;
    delivery_context_t *d = context;
    ++d->calls;
    CHECK(same(match.metadata, d->expected) && match.close_state == d->expected_state);
    vireo_task_metadata_t missing;
    CHECK(vireo_inflight_store_get(d->store, d->expected, &missing, NULL) == VIREO_RESULT_NOT_FOUND);
    vireo_completion_info_t info;
    vireo_completion_payload_view_t view;
    CHECK(vireo_completion_inspect(completion, &info) == VIREO_OK && same(info.metadata.request, d->expected));
    CHECK(vireo_completion_borrow_payload(completion, &view) == VIREO_OK && view.size == 3);
    memcpy(d->bytes, view.data, sizeof d->bytes);
    CHECK(d->bytes[0] == 0 && d->bytes[1] == 255 && d->bytes[2] == 42);
    if (d->spawn_new) {
        vireo_connection_pool_lease_t const client = {d->expected.route.client_owner_id,
            d->expected.route.client_slot_index, d->expected.route.client_generation};
        CHECK(vireo_inflight_metadata_make_next(d->server, client, d->expected.route.request_sequence,
            d->expected.operation, d->expected.deadline_ns, &d->spawned, NULL) == VIREO_OK);
        CHECK(d->spawned.request_instance_id != d->expected.request_instance_id);
        CHECK(vireo_inflight_store_register_limited(d->store, d->server, d->spawned, 2, NULL) == VIREO_OK);
    }
    errno = ENOSPC;
    return d->return_value;
}

static delivery_context_t context_make(vireo_inflight_store_t *store, fixture_t *f,
    vireo_task_metadata_t request) {
    return (delivery_context_t){.store = store, .server = f->server, .expected = request,
        .expected_state = VIREO_CONNECTION_CLOSE_OPEN};
}

static void empty_report_is(vireo_inflight_completion_consume_report_t report) {
    CHECK(report.stage == VIREO_INFLIGHT_CONSUME_NONE && report.disposition == VIREO_INFLIGHT_COMPLETION_NONE);
    CHECK(!report.completion_inspected && !report.record_consumed && !report.delivery_called &&
        !report.destroy_called && !report.completion_consumed && report.delivery_result == VIREO_OK &&
        report.destroy_result == VIREO_OK && report.inflight_stage == VIREO_INFLIGHT_NONE);
    CHECK(report.completion_metadata.request.route.client_owner_id == 0 &&
        report.completion_metadata.request.route.client_slot_index == 0 &&
        report.completion_metadata.request.route.client_generation == 0 &&
        report.completion_metadata.request.route.request_sequence == 0 &&
        report.completion_metadata.request.request_instance_id == 0 &&
        report.completion_metadata.request.operation == 0 &&
        report.completion_metadata.request.deadline_ns == 0);
}

static vireo_inflight_completion_consume_report_t consume_is(vireo_inflight_store_t *store,
    fixture_t *f, vireo_completion_t **owner, delivery_context_t *context, vireo_result_t expected) {
    vireo_completion_t *before = *owner;
    vireo_completion_info_t info;
    CHECK(vireo_completion_inspect(before, &info) == VIREO_OK);
    vireo_inflight_completion_consume_report_t report;
    memset(&report, 0xa5, sizeof report);
    errno = EDOM;
    CHECK(vireo_inflight_store_consume_completion(store, f->server, owner, deliver, context, &report) == expected);
    CHECK(errno == EDOM && report.completion_inspected && same(report.completion_metadata.request, info.metadata.request));
    CHECK(report.completion_metadata.result == info.metadata.result &&
        report.completion_metadata.suggested_status == info.metadata.suggested_status);
    CHECK(report.completion_consumed == (*owner == NULL));
    if (*owner != NULL) {
        CHECK(*owner == before);
        vireo_completion_info_t after;
        CHECK(vireo_completion_inspect(*owner, &after) == VIREO_OK && same(info.metadata.request, after.metadata.request));
        vireo_completion_payload_view_t view;
        CHECK(vireo_completion_borrow_payload(*owner, &view) == VIREO_OK && view.size == 3);
        CHECK(view.data[0] == 0 && view.data[1] == 255 && view.data[2] == 42);
    }
    return report;
}

static void successful_report_is(vireo_inflight_completion_consume_report_t report,
    vireo_inflight_completion_disposition_t disposition, bool record_consumed) {
    CHECK(report.stage == VIREO_INFLIGHT_CONSUME_NONE && report.disposition == disposition);
    CHECK(report.record_consumed == record_consumed && report.destroy_called && report.completion_consumed &&
        report.destroy_result == VIREO_OK && report.delivery_result == VIREO_OK);
    CHECK(report.delivery_called == (disposition == VIREO_INFLIGHT_COMPLETION_MATCHED));
}

static bool normal_delivery_and_snapshot(void) {
    fixture_t f; CHECK(setup(&f));
    vireo_inflight_store_t *store = store_create(2);
    vireo_task_metadata_t const request = metadata_make(&f, 1, 100);
    register_record(store, &f, request);
    vireo_completion_t *completion = completion_create(request, VIREO_OK);
    delivery_context_t d = context_make(store, &f, request);
    vireo_inflight_completion_consume_report_t const report = consume_is(store, &f, &completion, &d, VIREO_OK);
    successful_report_is(report, VIREO_INFLIGHT_COMPLETION_MATCHED, true);
    CHECK(d.calls == 1 && report.inflight_stage == VIREO_INFLIGHT_NONE && same(report.match.metadata, request));
    count_is(store, 0);
    CHECK(vireo_inflight_store_destroy(&store) == VIREO_OK);
    CHECK(cleanup(&f));
    CHECK(same(report.completion_metadata.request, request) && d.bytes[2] == 42);
    return true;
}

static bool business_failure_delivered(void) {
    fixture_t f; CHECK(setup(&f));
    vireo_inflight_store_t *store = store_create(2);
    vireo_result_t const results[] = {VIREO_RESULT_DATABASE, VIREO_RESULT_CANCELLED, VIREO_RESULT_TIMEOUT};
    for (size_t i = 0; i < sizeof results / sizeof results[0]; ++i) {
        vireo_task_metadata_t const request = metadata_make(&f, 2, 0);
        register_record(store, &f, request);
        vireo_completion_t *completion = completion_create(request, results[i]);
        delivery_context_t d = context_make(store, &f, request);
        vireo_inflight_completion_consume_report_t const report = consume_is(store, &f, &completion, &d, VIREO_OK);
        successful_report_is(report, VIREO_INFLIGHT_COMPLETION_MATCHED, true);
        CHECK(d.calls == 1 && report.completion_metadata.result == results[i]);
    }
    CHECK(vireo_inflight_store_destroy(&store) == VIREO_OK);
    return cleanup(&f);
}

static bool basic_precedence_and_report(void) {
    fixture_t f; CHECK(setup(&f));
    vireo_inflight_store_t *store = store_create(2);
    vireo_task_metadata_t const request = metadata_make(&f, 3, 100);
    register_record(store, &f, request);
    vireo_completion_t *completion = completion_create(request, VIREO_OK);
    vireo_completion_t *before = completion;
    delivery_context_t d = context_make(store, &f, request);
    for (unsigned i = 0; i < 5; ++i) {
        vireo_inflight_completion_consume_report_t report;
        memset(&report, 0xa5, sizeof report);
        errno = EIO;
        CHECK(vireo_inflight_store_consume_completion(i == 0 ? NULL : store,
            i == 1 ? NULL : f.server, i == 2 ? NULL : &completion,
            i == 3 ? NULL : deliver, &d, i == 4 ? NULL : &report) == VIREO_RESULT_INVALID_ARGUMENT);
        CHECK(errno == EIO && completion == before && d.calls == 0);
        if (i != 4) empty_report_is(report);
        count_is(store, 1);
    }
    vireo_completion_t *empty = NULL;
    vireo_inflight_completion_consume_report_t report;
    CHECK(vireo_inflight_store_consume_completion(store, f.server, &empty, NULL, NULL, &report) == VIREO_RESULT_INVALID_ARGUMENT);
    empty_report_is(report);
    CHECK(vireo_inflight_store_consume_completion(store, f.server, &empty, deliver, &d, &report) == VIREO_RESULT_NOT_FOUND);
    empty_report_is(report);
    successful_report_is(consume_is(store, &f, &completion, NULL, VIREO_OK), VIREO_INFLIGHT_COMPLETION_MATCHED, true);
    CHECK(vireo_inflight_store_consume_completion(store, f.server, &completion, deliver, &d, &report) == VIREO_RESULT_NOT_FOUND);
    empty_report_is(report);
    CHECK(d.calls == 0 && vireo_inflight_store_destroy(&store) == VIREO_OK);
    return cleanup(&f);
}

static bool callback_failure_retains_owner(void) {
    fixture_t f; CHECK(setup(&f));
    vireo_inflight_store_t *store = store_create(2);
    vireo_task_metadata_t const request = metadata_make(&f, 4, UINT64_MAX);
    register_record(store, &f, request);
    vireo_completion_t *completion = completion_create(request, VIREO_OK);
    delivery_context_t d = context_make(store, &f, request); d.return_value = VIREO_RESULT_IO;
    vireo_inflight_completion_consume_report_t report = consume_is(store, &f, &completion, &d, VIREO_RESULT_IO);
    CHECK(report.stage == VIREO_INFLIGHT_CONSUME_DELIVER && report.record_consumed && report.delivery_called);
    CHECK(report.disposition == VIREO_INFLIGHT_COMPLETION_MATCHED && report.delivery_result == VIREO_RESULT_IO);
    CHECK(!report.destroy_called && !report.completion_consumed && report.destroy_result == VIREO_OK && d.calls == 1);
    count_is(store, 0);
    /* caller 明确再调用作迟到清理，不会重放失败交付。 */
    report = consume_is(store, &f, &completion, &d, VIREO_OK);
    successful_report_is(report, VIREO_INFLIGHT_COMPLETION_REQUEST_GONE, false);
    CHECK(d.calls == 1 && report.inflight_stage == VIREO_INFLIGHT_CHECK_RECORD);
    CHECK(vireo_inflight_store_destroy(&store) == VIREO_OK);
    return cleanup(&f);
}

static bool missing_request_cleanup(void) {
    fixture_t f; CHECK(setup(&f));
    vireo_inflight_store_t *store = store_create(2);
    vireo_task_metadata_t const request = metadata_make(&f, 5, 1);
    register_record(store, &f, request); take_record(store, request);
    vireo_completion_t *completion = completion_create(request, VIREO_OK);
    delivery_context_t d = context_make(store, &f, request);
    vireo_inflight_completion_consume_report_t const report = consume_is(store, &f, &completion, &d, VIREO_OK);
    successful_report_is(report, VIREO_INFLIGHT_COMPLETION_REQUEST_GONE, false);
    CHECK(d.calls == 0 && report.inflight_stage == VIREO_INFLIGHT_CHECK_RECORD);
    CHECK(vireo_inflight_store_destroy(&store) == VIREO_OK);
    return cleanup(&f);
}

static bool sequence_reuse_cleanup(void) {
    fixture_t f; CHECK(setup(&f));
    vireo_inflight_store_t *store = store_create(2);
    vireo_task_metadata_t const old = metadata_make(&f, 6, 0);
    register_record(store, &f, old); take_record(store, old);
    vireo_task_metadata_t const current = metadata_make(&f, 6, 0);
    register_record(store, &f, current);
    vireo_completion_t *completion = completion_create(old, VIREO_OK);
    delivery_context_t d = context_make(store, &f, old);
    successful_report_is(consume_is(store, &f, &completion, &d, VIREO_OK), VIREO_INFLIGHT_COMPLETION_REQUEST_GONE, false);
    count_is(store, 1); CHECK(d.calls == 0);
    take_record(store, current);
    CHECK(vireo_inflight_store_destroy(&store) == VIREO_OK);
    return cleanup(&f);
}

static bool client_gone_history_cleanup(void) {
    fixture_t f; CHECK(setup(&f));
    vireo_inflight_store_t *store = store_create(2);
    vireo_task_metadata_t const request = metadata_make(&f, 7, 100);
    register_record(store, &f, request);
    vireo_completion_t *completion = completion_create(request, VIREO_OK);
    delivery_context_t d = context_make(store, &f, request);
    CHECK(release_client(&f));
    vireo_inflight_completion_consume_report_t const report = consume_is(store, &f, &completion, &d, VIREO_OK);
    successful_report_is(report, VIREO_INFLIGHT_COMPLETION_CLIENT_GONE, true);
    CHECK(d.calls == 0 && report.inflight_stage == VIREO_INFLIGHT_CHECK_CLIENT);
    count_is(store, 0);
    CHECK(vireo_inflight_store_destroy(&store) == VIREO_OK);
    return cleanup(&f);
}

static bool client_gone_no_history(void) {
    fixture_t f; CHECK(setup(&f));
    vireo_inflight_store_t *store = store_create(2);
    vireo_task_metadata_t const request = metadata_make(&f, 8, 100);
    vireo_completion_t *completion = completion_create(request, VIREO_OK);
    delivery_context_t d = context_make(store, &f, request);
    CHECK(release_client(&f));
    vireo_inflight_completion_consume_report_t const report = consume_is(store, &f, &completion, &d, VIREO_OK);
    successful_report_is(report, VIREO_INFLIGHT_COMPLETION_CLIENT_GONE, false);
    CHECK(d.calls == 0 && report.inflight_stage == VIREO_INFLIGHT_CHECK_CLIENT);
    CHECK(vireo_inflight_store_destroy(&store) == VIREO_OK);
    return cleanup(&f);
}

static bool client_slot_reuse_cleanup(void) {
    fixture_t f; CHECK(setup(&f));
    vireo_inflight_store_t *store = store_create(2);
    vireo_task_metadata_t const old = metadata_make(&f, 9, 100);
    register_record(store, &f, old);
    CHECK(release_client(&f) && add_client(&f));
    vireo_task_metadata_t current = metadata_make(&f, 9, 100);
    CHECK(current.route.client_slot_index == old.route.client_slot_index &&
        current.route.client_generation != old.route.client_generation);
    current.request_instance_id = old.request_instance_id;
    register_record(store, &f, current);
    vireo_completion_t *completion = completion_create(old, VIREO_OK);
    delivery_context_t d = context_make(store, &f, old);
    successful_report_is(consume_is(store, &f, &completion, &d, VIREO_OK), VIREO_INFLIGHT_COMPLETION_CLIENT_GONE, true);
    CHECK(d.calls == 0); count_is(store, 1);
    completion = completion_create(current, VIREO_OK); d.expected = current;
    successful_report_is(consume_is(store, &f, &completion, &d, VIREO_OK), VIREO_INFLIGHT_COMPLETION_MATCHED, true);
    CHECK(d.calls == 1 && vireo_inflight_store_destroy(&store) == VIREO_OK);
    return cleanup(&f);
}

static bool snapshot_errors_and_cross_owner(void) {
    fixture_t f; CHECK(setup(&f));
    vireo_inflight_store_t *store = store_create(2);
    vireo_task_metadata_t const request = metadata_make(&f, 10, 100);
    register_record(store, &f, request);
    delivery_context_t d = context_make(store, &f, request);
    for (unsigned i = 0; i < 4; ++i) {
        vireo_task_metadata_t changed = request;
        if (i == 0) changed.operation = 10;
        if (i == 1) changed.deadline_ns = 101;
        if (i == 2) changed.route.client_slot_index = SIZE_MAX;
        vireo_completion_t *completion = completion_create(changed, VIREO_OK);
        vireo_tcp_server_t *original_server = f.server;
        if (i == 3) f.server = f.other_server;
        vireo_inflight_completion_consume_report_t const report = consume_is(store, &f, &completion, &d,
            i == 2 ? VIREO_RESULT_RANGE : VIREO_RESULT_INVALID_ARGUMENT);
        f.server = original_server;
        CHECK(report.stage == VIREO_INFLIGHT_CONSUME_CHECK_MATCH && !report.record_consumed &&
            !report.delivery_called && !report.destroy_called && report.disposition == VIREO_INFLIGHT_COMPLETION_NONE);
        CHECK(report.inflight_stage == (i < 2 ? VIREO_INFLIGHT_MATCH_RECORD : VIREO_INFLIGHT_CHECK_CLIENT));
        count_is(store, 1); CHECK(d.calls == 0);
        CHECK(vireo_completion_destroy(&completion) == VIREO_OK);
    }
    take_record(store, request);
    CHECK(vireo_inflight_store_destroy(&store) == VIREO_OK);
    return cleanup(&f);
}

static bool dead_client_snapshot_error(void) {
    fixture_t f; CHECK(setup(&f));
    vireo_inflight_store_t *store = store_create(2);
    vireo_task_metadata_t const request = metadata_make(&f, 11, UINT64_MAX);
    register_record(store, &f, request);
    CHECK(release_client(&f));
    delivery_context_t d = context_make(store, &f, request);
    for (unsigned i = 0; i < 2; ++i) {
        vireo_task_metadata_t changed = request;
        if (i == 0) changed.operation = 10;
        else changed.deadline_ns = 0;
        vireo_completion_t *completion = completion_create(changed, VIREO_OK);
        vireo_inflight_completion_consume_report_t const report = consume_is(store, &f, &completion, &d,
            VIREO_RESULT_INVALID_ARGUMENT);
        CHECK(report.stage == VIREO_INFLIGHT_CONSUME_CHECK_RECORD &&
            report.disposition == VIREO_INFLIGHT_COMPLETION_CLIENT_GONE &&
            report.inflight_stage == VIREO_INFLIGHT_MATCH_RECORD && !report.record_consumed &&
            !report.delivery_called && !report.destroy_called && d.calls == 0);
        count_is(store, 1);
        CHECK(vireo_completion_destroy(&completion) == VIREO_OK);
    }
    take_record(store, request);
    CHECK(vireo_inflight_store_destroy(&store) == VIREO_OK);
    return cleanup(&f);
}

static bool closing_stop_and_deadlines(void) {
    for (unsigned i = 0; i < 3; ++i) {
        fixture_t f; CHECK(setup(&f));
        vireo_inflight_store_t *store = store_create(2);
        vireo_task_metadata_t const request = metadata_make(&f, 12, i == 0 ? 0 : UINT64_MAX);
        register_record(store, &f, request);
        delivery_context_t d = context_make(store, &f, request);
        if (i != 0) {
            unsigned char const byte = 1;
            CHECK(vireo_tcp_server_client_write_enqueue(f.server, f.client, &byte, 1, NULL) == VIREO_OK);
            CHECK(vireo_tcp_server_client_request_close(f.server, f.client,
                i == 1 ? VIREO_CONNECTION_CLOSE_MODE_DRAIN : VIREO_CONNECTION_CLOSE_MODE_IMMEDIATE,
                VIREO_CONNECTION_CLOSE_REASON_APPLICATION, NULL) == VIREO_OK);
            d.expected_state = i == 1 ? VIREO_CONNECTION_CLOSE_DRAINING : VIREO_CONNECTION_CLOSE_READY;
        }
        CHECK(vireo_tcp_server_request_stop(f.server, NULL) == VIREO_OK);
        vireo_completion_t *completion = completion_create(request, VIREO_OK);
        successful_report_is(consume_is(store, &f, &completion, &d, VIREO_OK), VIREO_INFLIGHT_COMPLETION_MATCHED, true);
        CHECK(d.calls == 1 && vireo_inflight_store_destroy(&store) == VIREO_OK);
        CHECK(cleanup(&f));
    }
    return true;
}

static bool cancel_reference_release(void) {
    for (unsigned i = 0; i < 2; ++i) {
        fixture_t f; CHECK(setup(&f));
        vireo_inflight_store_t *store = store_create(2);
        vireo_task_metadata_t const request = metadata_make(&f, 13, 0);
        vireo_task_cancel_t *cancel = NULL, *probe = NULL;
        CHECK(vireo_task_cancel_create(65536, &cancel) == VIREO_OK);
        vireo_task_t *task = NULL;
        CHECK(vireo_task_create_copy_with_cancel(request, NULL, 0, 65536, cancel, &task) == VIREO_OK);
        CHECK(vireo_inflight_store_register_task_limited(store, f.server, task, 2, NULL) == VIREO_OK);
        CHECK(vireo_inflight_store_retain_cancel(store, request, &probe, NULL) == VIREO_OK);
        CHECK(vireo_task_destroy(&task) == VIREO_OK && vireo_task_cancel_destroy(&cancel) == VIREO_OK);
        if (i == 1) CHECK(release_client(&f));
        vireo_completion_t *completion = completion_create(request, VIREO_OK);
        delivery_context_t d = context_make(store, &f, request);
        successful_report_is(consume_is(store, &f, &completion, &d, VIREO_OK),
            i == 0 ? VIREO_INFLIGHT_COMPLETION_MATCHED : VIREO_INFLIGHT_COMPLETION_CLIENT_GONE, true);
        CHECK(d.calls == (i == 0 ? 1u : 0u));
        bool requested = true;
        CHECK(vireo_task_cancel_is_requested(probe, &requested) == VIREO_OK && !requested);
        CHECK(vireo_inflight_store_destroy(&store) == VIREO_OK);
        CHECK(vireo_task_cancel_is_requested(probe, &requested) == VIREO_OK && !requested);
        CHECK(vireo_task_cancel_destroy(&probe) == VIREO_OK);
        CHECK(cleanup(&f));
    }
    return true;
}

static bool callback_new_record_survives(void) {
    fixture_t f; CHECK(setup(&f));
    vireo_inflight_store_t *store = store_create(2);
    vireo_task_metadata_t const request = metadata_make(&f, 14, 100);
    register_record(store, &f, request);
    vireo_completion_t *completion = completion_create(request, VIREO_OK);
    delivery_context_t d = context_make(store, &f, request); d.spawn_new = true;
    successful_report_is(consume_is(store, &f, &completion, &d, VIREO_OK), VIREO_INFLIGHT_COMPLETION_MATCHED, true);
    CHECK(d.calls == 1); count_is(store, 1);
    take_record(store, d.spawned);
    CHECK(vireo_inflight_store_destroy(&store) == VIREO_OK);
    return cleanup(&f);
}


/** 两 worker 只短借 task，独立构造并公开发布结果，不见 server/store/fd。 */
typedef struct worker_context {
    vireo_completion_queue_t *results; /**< manager 长借的结果队列，join 后才销毁。 */
    pthread_barrier_t second_published; /**< 两 worker 会合，保证第二项先成功入队。 */
} worker_context_t;

static void meet(pthread_barrier_t *barrier) {
    int const result = pthread_barrier_wait(barrier);
    CHECK(result == 0 || result == PTHREAD_BARRIER_SERIAL_THREAD);
}

static vireo_result_t execute(void *context, vireo_task_t const *task) {
    worker_context_t *w = context;
    vireo_task_info_t info;
    CHECK(vireo_task_inspect(task, &info) == VIREO_OK);
    uint32_t const sequence = info.metadata.route.request_sequence;
    CHECK(sequence == 1 || sequence == 2);
    if (sequence == 1) meet(&w->second_published);
    vireo_completion_t *completion = completion_create(info.metadata,
        sequence == 1 ? VIREO_OK : VIREO_RESULT_DATABASE);
    vireo_completion_queue_transfer_report_t report;
    CHECK(vireo_completion_queue_wait_push(w->results, &completion, &report) == VIREO_OK);
    CHECK(report.transferred && completion == NULL);
    if (sequence == 2) meet(&w->second_published);
    return VIREO_OK;
}

/** 仅测试 manager 明确选择有上限的竞争重试，生产入口仍只调用一次。 */
static void submit_until_transferred(vireo_inflight_store_t *store, fixture_t *f,
    vireo_thread_pool_t *pool, vireo_task_t **task) {
    for (size_t i = 0; i < 100000; ++i) {
        vireo_inflight_submit_report_t report;
        vireo_result_t const result = vireo_inflight_store_try_submit(store, f->server, pool, 2, task, &report);
        if (result == VIREO_OK) { CHECK(*task == NULL && report.record_retained); return; }
        CHECK(result == VIREO_RESULT_BUSY && *task != NULL && !report.record_retained);
        sched_yield();
    }
    CHECK(false);
}

static bool real_workers_consumption(void) {
    fixture_t f; CHECK(setup(&f));
    vireo_inflight_store_t *store = store_create(2);
    worker_context_t w = {0};
    CHECK(pthread_barrier_init(&w.second_published, NULL, 2) == 0);
    vireo_completion_queue_options_t const co = {2, 65536};
    CHECK(vireo_completion_queue_create(&co, &w.results) == VIREO_OK);
    CHECK(vireo_completion_queue_prepare_wait(w.results) == VIREO_OK);
    vireo_task_queue_t *queue = NULL;
    vireo_task_queue_options_t const qo = {2, 65536};
    CHECK(vireo_task_queue_create(&qo, &queue) == VIREO_OK && vireo_task_queue_prepare_wait(queue) == VIREO_OK);
    vireo_thread_pool_t *pool = NULL;
    vireo_thread_pool_options_t const po = {2, 65536};
    CHECK(vireo_thread_pool_create(&po, &pool) == VIREO_OK);
    vireo_thread_pool_configuration_t const configuration = {queue, execute, &w};
    CHECK(vireo_thread_pool_configure(pool, &configuration, NULL) == VIREO_OK);
    vireo_thread_pool_report_t report;
    CHECK(vireo_thread_pool_start(pool, &report) == VIREO_OK);
    CHECK(vireo_thread_pool_enable_execution(pool, &report) == VIREO_OK);
    vireo_task_metadata_t requests[2];
    for (unsigned i = 0; i < 2; ++i) {
        requests[i] = metadata_make(&f, i + 1, UINT64_MAX);
        vireo_task_t *task = NULL;
        CHECK(vireo_task_create_copy(requests[i], NULL, 0, 65536, &task) == VIREO_OK);
        submit_until_transferred(store, &f, pool, &task);
    }
    bool closed = false;
    for (size_t i = 0; i < 100000; ++i) {
        vireo_task_queue_close_report_t close_report;
        vireo_result_t const result = vireo_task_queue_close(queue, VIREO_TASK_QUEUE_DRAIN, &close_report);
        if (result == VIREO_OK) { closed = true; break; }
        CHECK(result == VIREO_RESULT_BUSY && !close_report.changed);
        sched_yield();
    }
    CHECK(closed);
    bool joined = false;
    for (size_t i = 0; i < 100000; ++i) {
        vireo_result_t const result = vireo_thread_pool_stop_and_join(pool, &report);
        if (result == VIREO_OK) { joined = true; break; }
        CHECK(result == VIREO_RESULT_BUSY);
        sched_yield();
    }
    CHECK(joined);
    for (size_t i = 0; i < 2; ++i) {
        vireo_thread_pool_worker_result_t worker;
        CHECK(vireo_thread_pool_inspect_worker_result(pool, i, &worker) == VIREO_OK && worker.result == VIREO_OK);
    }
    count_is(store, 2);
    take_record(store, requests[0]);
    for (unsigned i = 0; i < 2; ++i) {
        vireo_completion_t *completion = NULL;
        vireo_completion_queue_transfer_report_t transfer;
        CHECK(vireo_completion_queue_try_pop(w.results, &completion, &transfer) == VIREO_OK && transfer.transferred);
        vireo_completion_info_t info;
        CHECK(vireo_completion_inspect(completion, &info) == VIREO_OK);
        unsigned const index = i == 0 ? 1 : 0;
        CHECK(same(info.metadata.request, requests[index]));
        delivery_context_t d = context_make(store, &f, requests[index]);
        vireo_inflight_completion_consume_report_t const consumed = consume_is(store, &f, &completion, &d, VIREO_OK);
        successful_report_is(consumed, i == 0 ? VIREO_INFLIGHT_COMPLETION_MATCHED :
            VIREO_INFLIGHT_COMPLETION_REQUEST_GONE, i == 0);
        CHECK(d.calls == (i == 0 ? 1u : 0u) && completion == NULL);
        count_is(store, 0);
    }
    count_is(store, 0);
    CHECK(vireo_thread_pool_destroy(&pool) == VIREO_OK && vireo_task_queue_destroy(&queue) == VIREO_OK);
    CHECK(vireo_completion_queue_destroy(&w.results) == VIREO_OK);
    CHECK(pthread_barrier_destroy(&w.second_published) == 0);
    CHECK(vireo_inflight_store_destroy(&store) == VIREO_OK);
    return cleanup(&f);
}

int main(void) {
    int previous_cancel_state = 0;
    CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previous_cancel_state) == 0);
    struct { char const *name; bool (*run)(void); } const cases[] = {
        {"normal_delivery_and_snapshot", normal_delivery_and_snapshot},
        {"business_failure_delivered", business_failure_delivered},
        {"basic_precedence_and_report", basic_precedence_and_report},
        {"callback_failure_retains_owner", callback_failure_retains_owner},
        {"missing_request_cleanup", missing_request_cleanup},
        {"sequence_reuse_cleanup", sequence_reuse_cleanup},
        {"client_gone_history_cleanup", client_gone_history_cleanup},
        {"client_gone_no_history", client_gone_no_history},
        {"client_slot_reuse_cleanup", client_slot_reuse_cleanup},
        {"snapshot_errors_and_cross_owner", snapshot_errors_and_cross_owner},
        {"dead_client_snapshot_error", dead_client_snapshot_error},
        {"closing_stop_and_deadlines", closing_stop_and_deadlines},
        {"cancel_reference_release", cancel_reference_release},
        {"callback_new_record_survives", callback_new_record_survives},
        {"real_workers_consumption", real_workers_consumption}
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
        CHECK(cases[i].run()); printf("[PASS] %s\n", cases[i].name);
    }
    printf("inflight completion consume: 15 groups passed\n");
    CHECK(pthread_setcancelstate(previous_cancel_state, NULL) == 0);
    return 0;
}
