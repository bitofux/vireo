/*
 * PROJECT : VIREO
 * FILE    : test_inflight_completion.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-13
 * BRIEF   : 当前客户与在途请求双核验、迟到复用和真实乱序完成
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

/** 失败主输出逐字节保持；成功反复核验也不消费 completion、登记或 payload。 */
static void check_is(vireo_inflight_store_t *store, vireo_tcp_server_t *server,
    vireo_completion_t *completion, vireo_result_t expected, vireo_inflight_stage_t expected_stage,
    vireo_task_metadata_t request, vireo_connection_close_state_t state) {
    vireo_inflight_store_info_t before, after;
    vireo_completion_info_t cbefore, cafter;
    vireo_completion_payload_view_t vb, va;
    CHECK(vireo_inflight_store_inspect(store, &before) == VIREO_OK);
    CHECK(vireo_completion_inspect(completion, &cbefore) == VIREO_OK);
    CHECK(vireo_completion_borrow_payload(completion, &vb) == VIREO_OK);
    vireo_inflight_completion_match_t match;
    memset(&match, 0xa5, sizeof match);
    unsigned char saved[sizeof match];
    memcpy(saved, &match, sizeof match);
    vireo_inflight_stage_t stage = VIREO_INFLIGHT_CHECK_SERVER;
    errno = EDOM;
    CHECK(vireo_inflight_store_check_completion(store, server, completion, &match, &stage) == expected);
    CHECK(errno == EDOM && stage == expected_stage);
    if (expected == VIREO_OK) CHECK(same(match.metadata, request) && match.close_state == state);
    else CHECK(memcmp(&match, saved, sizeof match) == 0);
    CHECK(vireo_inflight_store_inspect(store, &after) == VIREO_OK);
    CHECK(before.capacity == after.capacity && before.count == after.count &&
        before.allocated_bytes == after.allocated_bytes && before.max_memory_bytes == after.max_memory_bytes);
    CHECK(vireo_completion_inspect(completion, &cafter) == VIREO_OK);
    CHECK(same(cbefore.metadata.request, cafter.metadata.request) &&
        cbefore.metadata.result == cafter.metadata.result &&
        cbefore.metadata.suggested_status == cafter.metadata.suggested_status &&
        cbefore.payload_size == cafter.payload_size && cbefore.allocated_bytes == cafter.allocated_bytes);
    CHECK(vireo_completion_borrow_payload(completion, &va) == VIREO_OK);
    CHECK(vb.data == va.data && vb.size == va.size && va.size == 3 &&
        va.data[0] == 0 && va.data[1] == 255 && va.data[2] == 42);
}

static bool match_and_repeat(void) {
    fixture_t f; CHECK(setup(&f));
    vireo_inflight_store_t *store = store_create(2);
    vireo_task_metadata_t const request = metadata_make(&f, 1, 100);
    register_record(store, &f, request);
    vireo_completion_t *completion = completion_create(request, VIREO_OK);
    for (unsigned i = 0; i < 3; ++i)
        check_is(store, f.server, completion, VIREO_OK, VIREO_INFLIGHT_NONE,
            request, VIREO_CONNECTION_CLOSE_OPEN);
    count_is(store, 1);
    CHECK(vireo_inflight_store_destroy(&store) == VIREO_RESULT_BUSY && store != NULL);
    take_record(store, request);
    CHECK(vireo_completion_destroy(&completion) == VIREO_OK && completion == NULL);
    CHECK(vireo_inflight_store_destroy(&store) == VIREO_OK);
    return cleanup(&f);
}

static bool work_failure_is_metadata(void) {
    fixture_t f; CHECK(setup(&f));
    vireo_inflight_store_t *store = store_create(2);
    vireo_task_metadata_t const request = metadata_make(&f, 2, 0);
    register_record(store, &f, request);
    vireo_result_t const results[] = {VIREO_RESULT_DATABASE, VIREO_RESULT_CANCELLED, VIREO_RESULT_TIMEOUT};
    for (size_t i = 0; i < sizeof results / sizeof results[0]; ++i) {
        vireo_completion_t *completion = completion_create(request, results[i]);
        check_is(store, f.server, completion, VIREO_OK, VIREO_INFLIGHT_NONE,
            request, VIREO_CONNECTION_CLOSE_OPEN);
        vireo_completion_metadata_t metadata;
        CHECK(vireo_completion_metadata_make(request, results[i], VIREO_STATUS_OK, &metadata) == VIREO_OK);
        vireo_completion_t *other = NULL;
        CHECK(vireo_completion_create_copy(metadata, NULL, 0, 65536, &other) == VIREO_OK);
        vireo_inflight_completion_match_t match;
        CHECK(vireo_inflight_store_check_completion(store, f.server, other, &match, NULL) == VIREO_OK);
        CHECK(same(match.metadata, request));
        CHECK(vireo_completion_destroy(&other) == VIREO_OK);
        CHECK(vireo_completion_destroy(&completion) == VIREO_OK);
    }
    take_record(store, request);
    CHECK(vireo_inflight_store_destroy(&store) == VIREO_OK);
    return cleanup(&f);
}

static bool basic_output_priority(void) {
    fixture_t f; CHECK(setup(&f));
    vireo_inflight_store_t *store = store_create(2);
    vireo_task_metadata_t const request = metadata_make(&f, 3, 1);
    register_record(store, &f, request);
    vireo_completion_t *completion = completion_create(request, VIREO_OK);
    vireo_inflight_completion_match_t match;
    memset(&match, 0x5a, sizeof match);
    unsigned char saved[sizeof match]; memcpy(saved, &match, sizeof match);
    for (unsigned i = 0; i < 4; ++i) {
        vireo_inflight_stage_t stage = VIREO_INFLIGHT_MATCH_RECORD;
        errno = ENOSPC;
        CHECK(vireo_inflight_store_check_completion(i == 0 ? NULL : store,
            i == 1 ? NULL : f.server, i == 2 ? NULL : completion,
            i == 3 ? NULL : &match, &stage) == VIREO_RESULT_INVALID_ARGUMENT);
        CHECK(errno == ENOSPC && stage == VIREO_INFLIGHT_NONE && memcmp(saved, &match, sizeof match) == 0);
    }
    CHECK(vireo_inflight_store_check_completion(NULL, NULL, NULL, NULL, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    errno = EIO;
    CHECK(vireo_inflight_store_check_completion(store, f.server, completion, &match, NULL) == VIREO_OK);
    CHECK(errno == EIO && same(match.metadata, request));
    take_record(store, request);
    CHECK(vireo_inflight_store_check_completion(store, f.server, completion, NULL, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_completion_destroy(&completion) == VIREO_OK);
    CHECK(vireo_inflight_store_destroy(&store) == VIREO_OK);
    return cleanup(&f);
}

static bool snapshot_mismatch(void) {
    fixture_t f; CHECK(setup(&f));
    vireo_inflight_store_t *store = store_create(2);
    vireo_task_metadata_t const request = metadata_make(&f, 4, UINT64_MAX);
    register_record(store, &f, request);
    for (unsigned i = 0; i < 2; ++i) {
        vireo_task_metadata_t changed = request;
        if (i == 0) changed.operation = 10;
        else changed.deadline_ns = 0;
        vireo_completion_t *completion = completion_create(changed, VIREO_OK);
        vireo_task_metadata_t found;
        CHECK(vireo_inflight_store_get(store, changed, &found, NULL) == VIREO_OK && same(found, request));
        check_is(store, f.server, completion, VIREO_RESULT_INVALID_ARGUMENT,
            VIREO_INFLIGHT_MATCH_RECORD, request, VIREO_CONNECTION_CLOSE_OPEN);
        CHECK(vireo_completion_destroy(&completion) == VIREO_OK);
    }
    take_record(store, request);
    CHECK(vireo_inflight_store_destroy(&store) == VIREO_OK);
    return cleanup(&f);
}

static bool missing_identity_fields(void) {
    fixture_t f; CHECK(setup(&f));
    vireo_inflight_store_t *store = store_create(2);
    vireo_task_metadata_t const request = metadata_make(&f, 5, 100);
    register_record(store, &f, request);
    for (unsigned i = 0; i < 2; ++i) {
        vireo_task_metadata_t changed = request;
        if (i == 0) changed.route.request_sequence += 1;
        else changed.request_instance_id += 1;
        vireo_completion_t *completion = completion_create(changed, VIREO_OK);
        check_is(store, f.server, completion, VIREO_RESULT_NOT_FOUND,
            VIREO_INFLIGHT_CHECK_RECORD, request, VIREO_CONNECTION_CLOSE_OPEN);
        CHECK(vireo_completion_destroy(&completion) == VIREO_OK);
    }
    take_record(store, request);
    CHECK(vireo_inflight_store_destroy(&store) == VIREO_OK);
    return cleanup(&f);
}

static bool finished_request(void) {
    fixture_t f; CHECK(setup(&f));
    vireo_inflight_store_t *store = store_create(2);
    vireo_task_metadata_t const request = metadata_make(&f, 6, 50);
    register_record(store, &f, request);
    vireo_completion_t *completion = completion_create(request, VIREO_OK);
    take_record(store, request);
    vireo_connection_close_state_t state;
    CHECK(vireo_inflight_check_client(f.server, request, &state, NULL) == VIREO_OK);
    check_is(store, f.server, completion, VIREO_RESULT_NOT_FOUND,
        VIREO_INFLIGHT_CHECK_RECORD, request, VIREO_CONNECTION_CLOSE_OPEN);
    count_is(store, 0);
    CHECK(vireo_inflight_store_destroy(&store) == VIREO_OK);
    /* caller 的结果拥有者超过表寿命，显式清理；产品检查不承担这步。 */
    CHECK(vireo_completion_destroy(&completion) == VIREO_OK);
    return cleanup(&f);
}

static bool sequence_reuse(void) {
    fixture_t f; CHECK(setup(&f));
    vireo_inflight_store_t *store = store_create(2);
    vireo_task_metadata_t const old = metadata_make(&f, 7, 0);
    register_record(store, &f, old);
    vireo_completion_t *late = completion_create(old, VIREO_OK);
    take_record(store, old);
    vireo_task_metadata_t const current = metadata_make(&f, 7, 0);
    CHECK(current.request_instance_id != old.request_instance_id);
    register_record(store, &f, current);
    vireo_completion_t *completion = completion_create(current, VIREO_OK);
    check_is(store, f.server, late, VIREO_RESULT_NOT_FOUND,
        VIREO_INFLIGHT_CHECK_RECORD, old, VIREO_CONNECTION_CLOSE_OPEN);
    check_is(store, f.server, completion, VIREO_OK, VIREO_INFLIGHT_NONE,
        current, VIREO_CONNECTION_CLOSE_OPEN);
    take_record(store, current);
    CHECK(vireo_completion_destroy(&late) == VIREO_OK && vireo_completion_destroy(&completion) == VIREO_OK);
    CHECK(vireo_inflight_store_destroy(&store) == VIREO_OK);
    return cleanup(&f);
}

static bool client_gone_and_slot_reuse(void) {
    fixture_t f; CHECK(setup(&f));
    vireo_inflight_store_t *store = store_create(2);
    vireo_task_metadata_t const old = metadata_make(&f, 8, 100);
    register_record(store, &f, old);
    vireo_completion_t *late = completion_create(old, VIREO_OK);
    CHECK(release_client(&f));
    check_is(store, f.server, late, VIREO_RESULT_NOT_FOUND,
        VIREO_INFLIGHT_CHECK_CLIENT, old, VIREO_CONNECTION_CLOSE_OPEN);
    count_is(store, 1);
    CHECK(add_client(&f));
    vireo_task_metadata_t current = metadata_make(&f, 8, 100);
    CHECK(current.route.client_slot_index == old.route.client_slot_index &&
        current.route.client_generation != old.route.client_generation);
    /* 不同客户代允许数值 instance 相同，完整客户租约仍区分它们。 */
    current.request_instance_id = old.request_instance_id;
    register_record(store, &f, current);
    vireo_completion_t *completion = completion_create(current, VIREO_OK);
    check_is(store, f.server, late, VIREO_RESULT_NOT_FOUND,
        VIREO_INFLIGHT_CHECK_CLIENT, old, VIREO_CONNECTION_CLOSE_OPEN);
    check_is(store, f.server, completion, VIREO_OK, VIREO_INFLIGHT_NONE,
        current, VIREO_CONNECTION_CLOSE_OPEN);
    take_record(store, old); take_record(store, current);
    CHECK(vireo_completion_destroy(&late) == VIREO_OK && vireo_completion_destroy(&completion) == VIREO_OK);
    CHECK(vireo_inflight_store_destroy(&store) == VIREO_OK);
    return cleanup(&f);
}

static bool client_errors_and_priority(void) {
    fixture_t f; CHECK(setup_capacity(&f, 2));
    vireo_inflight_store_t *store = store_create(2);
    vireo_task_metadata_t const request = metadata_make(&f, 9, 100);
    vireo_completion_t *completion = completion_create(request, VIREO_OK);
    check_is(store, f.other_server, completion, VIREO_RESULT_INVALID_ARGUMENT,
        VIREO_INFLIGHT_CHECK_CLIENT, request, VIREO_CONNECTION_CLOSE_OPEN);
    vireo_task_metadata_t beyond = request; beyond.route.client_slot_index = SIZE_MAX;
    vireo_completion_t *bad_slot = completion_create(beyond, VIREO_OK);
    check_is(store, f.server, bad_slot, VIREO_RESULT_RANGE,
        VIREO_INFLIGHT_CHECK_CLIENT, request, VIREO_CONNECTION_CLOSE_OPEN);
    vireo_task_metadata_t empty_slot = request;
    empty_slot.route.client_slot_index = f.client.slot_index == 0 ? 1 : 0;
    vireo_completion_t *absent = completion_create(empty_slot, VIREO_OK);
    check_is(store, f.server, absent, VIREO_RESULT_NOT_FOUND,
        VIREO_INFLIGHT_CHECK_CLIENT, request, VIREO_CONNECTION_CLOSE_OPEN);
    check_is(store, f.server, completion, VIREO_RESULT_NOT_FOUND,
        VIREO_INFLIGHT_CHECK_RECORD, request, VIREO_CONNECTION_CLOSE_OPEN);
    CHECK(vireo_completion_destroy(&absent) == VIREO_OK && vireo_completion_destroy(&bad_slot) == VIREO_OK);
    CHECK(vireo_completion_destroy(&completion) == VIREO_OK);
    CHECK(vireo_inflight_store_destroy(&store) == VIREO_OK);
    return cleanup(&f);
}

static bool closing_and_stop(void) {
    fixture_t f; CHECK(setup(&f));
    vireo_inflight_store_t *store = store_create(2);
    vireo_task_metadata_t const request = metadata_make(&f, 10, 100);
    register_record(store, &f, request);
    vireo_completion_t *completion = completion_create(request, VIREO_OK);
    CHECK(vireo_tcp_server_request_stop(f.server, NULL) == VIREO_OK);
    check_is(store, f.server, completion, VIREO_OK, VIREO_INFLIGHT_NONE,
        request, VIREO_CONNECTION_CLOSE_OPEN);
    unsigned char const byte = 1;
    CHECK(vireo_tcp_server_client_write_enqueue(f.server, f.client, &byte, 1, NULL) == VIREO_OK);
    CHECK(vireo_tcp_server_client_request_close(f.server, f.client, VIREO_CONNECTION_CLOSE_MODE_DRAIN,
        VIREO_CONNECTION_CLOSE_REASON_APPLICATION, NULL) == VIREO_OK);
    check_is(store, f.server, completion, VIREO_OK, VIREO_INFLIGHT_NONE,
        request, VIREO_CONNECTION_CLOSE_DRAINING);
    CHECK(vireo_tcp_server_client_request_close(f.server, f.client, VIREO_CONNECTION_CLOSE_MODE_IMMEDIATE,
        VIREO_CONNECTION_CLOSE_REASON_APPLICATION, NULL) == VIREO_OK);
    check_is(store, f.server, completion, VIREO_OK, VIREO_INFLIGHT_NONE,
        request, VIREO_CONNECTION_CLOSE_READY);
    take_record(store, request);
    CHECK(vireo_completion_destroy(&completion) == VIREO_OK);
    CHECK(vireo_inflight_store_destroy(&store) == VIREO_OK);
    return cleanup(&f);
}

static bool finite_deadlines_and_cancel_reference(void) {
    fixture_t f; CHECK(setup(&f));
    vireo_inflight_store_t *store = store_create(2);
    vireo_task_cancel_t *cancel = NULL;
    CHECK(vireo_task_cancel_create(65536, &cancel) == VIREO_OK);
    uint64_t const deadlines[] = {0, UINT64_MAX};
    for (size_t i = 0; i < sizeof deadlines / sizeof deadlines[0]; ++i) {
        vireo_task_metadata_t const request = metadata_make(&f, 11, deadlines[i]);
        vireo_task_t *task = NULL;
        CHECK(vireo_task_create_copy_with_cancel(request, NULL, 0, 65536, cancel, &task) == VIREO_OK);
        CHECK(vireo_inflight_store_register_task_limited(store, f.server, task, 2, NULL) == VIREO_OK);
        CHECK(vireo_task_destroy(&task) == VIREO_OK);
        CHECK(vireo_task_cancel_request(cancel) == VIREO_OK);
        vireo_completion_t *completion = completion_create(request, VIREO_RESULT_CANCELLED);
        check_is(store, f.server, completion, VIREO_OK, VIREO_INFLIGHT_NONE,
            request, VIREO_CONNECTION_CLOSE_OPEN);
        vireo_task_cancel_t *retained = NULL;
        CHECK(vireo_inflight_store_retain_cancel(store, request, &retained, NULL) == VIREO_OK);
        bool requested = false;
        CHECK(vireo_task_cancel_is_requested(retained, &requested) == VIREO_OK && requested);
        take_record(store, request);
        CHECK(vireo_task_cancel_is_requested(retained, &requested) == VIREO_OK && requested);
        CHECK(vireo_task_cancel_destroy(&retained) == VIREO_OK);
        CHECK(vireo_completion_destroy(&completion) == VIREO_OK);
    }
    CHECK(vireo_task_cancel_destroy(&cancel) == VIREO_OK);
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

static bool real_workers_out_of_order(void) {
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
    for (unsigned i = 0; i < 2; ++i) {
        vireo_completion_t *completion = NULL;
        vireo_completion_queue_transfer_report_t transfer;
        CHECK(vireo_completion_queue_try_pop(w.results, &completion, &transfer) == VIREO_OK && transfer.transferred);
        vireo_completion_info_t info;
        CHECK(vireo_completion_inspect(completion, &info) == VIREO_OK);
        unsigned const index = i == 0 ? 1 : 0;
        CHECK(same(info.metadata.request, requests[index]));
        check_is(store, f.server, completion, VIREO_OK, VIREO_INFLIGHT_NONE,
            requests[index], VIREO_CONNECTION_CLOSE_OPEN);
        take_record(store, requests[index]);
        check_is(store, f.server, completion, VIREO_RESULT_NOT_FOUND, VIREO_INFLIGHT_CHECK_RECORD,
            requests[index], VIREO_CONNECTION_CLOSE_OPEN);
        CHECK(vireo_completion_destroy(&completion) == VIREO_OK);
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
        {"match_and_repeat", match_and_repeat},
        {"work_failure_is_metadata", work_failure_is_metadata},
        {"basic_output_priority", basic_output_priority},
        {"snapshot_mismatch", snapshot_mismatch},
        {"missing_identity_fields", missing_identity_fields},
        {"finished_request", finished_request},
        {"sequence_reuse", sequence_reuse},
        {"client_gone_and_slot_reuse", client_gone_and_slot_reuse},
        {"client_errors_and_priority", client_errors_and_priority},
        {"closing_and_stop", closing_and_stop},
        {"finite_deadlines_and_cancel_reference", finite_deadlines_and_cancel_reference},
        {"real_workers_out_of_order", real_workers_out_of_order}
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
        CHECK(cases[i].run()); printf("[PASS] %s\n", cases[i].name);
    }
    printf("inflight completion: 12 groups passed\n");
    CHECK(pthread_setcancelstate(previous_cancel_state, NULL) == 0);
    return 0;
}

