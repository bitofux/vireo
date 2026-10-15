/*
 * PROJECT : VIREO
 * FILE    : test_inflight_instance.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-13
 * BRIEF   : 真实客户自动发行、历史隔离、MAX耗尽与一次CAS真实竞争
 */
#define _GNU_SOURCE
#include <vireo/net/inflight_store.h>
#include "net/inflight_instance_internal.h"

#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define CHECK(expr) do { if (!(expr)) { \
    fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #expr); return false; \
} } while (0)

_Static_assert(VIREO_INFLIGHT_NONE == 0 && VIREO_INFLIGHT_CHECK_CLIENT == 1 &&
    VIREO_INFLIGHT_MAKE_ROUTE == 2 && VIREO_INFLIGHT_MAKE_METADATA == 3 &&
    VIREO_INFLIGHT_CHECK_METADATA == 4 && VIREO_INFLIGHT_CHECK_SERVER == 5 &&
    VIREO_INFLIGHT_CHECK_RECORD == 6 && VIREO_INFLIGHT_ISSUE_INSTANCE == 7,
    "existing stages must remain stable");

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

static bool setup(fixture_t *f) {
    *f = (fixture_t){.peer = -1, .listener_fd = -1};
    vireo_tcp_server_options_t const options = {1, 2, VIREO_TCP_SERVER_MAX_MEMORY, 128};
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


/** 本测试短借的 CAS 场景状态；发行器本身仍使用真实 C11 原子。 */
typedef struct compare_context {
    size_t calls; /**< 本轮 compare 次数，核验没有内部循环。 */
    bool race;    /**< 为 true 时先提交另一个合法发行值，再执行本调用 CAS。 */
} compare_context_t;

/** 一次合法竞争真实提交后原 expected 必须失败；errno 扰动核验入口恢复。 */
static bool compare(void *context, _Atomic(uint64_t) *counter,
                    uint64_t *expected, uint64_t desired) {
    compare_context_t *c = context;
    if (c != NULL) {
        ++c->calls;
        if (c->race) {
            uint64_t competitor = *expected;
            if (!atomic_compare_exchange_strong_explicit(counter, &competitor, desired,
                memory_order_relaxed, memory_order_relaxed)) return false;
        }
    }
    errno = ENOSPC;
    return atomic_compare_exchange_strong_explicit(counter, expected, desired,
        memory_order_relaxed, memory_order_relaxed);
}

/** 初始化自己的隔离对象；绝不访问或重置生产静态发行器。 */
static void issuer_init(vireo_inflight_instance_issuer_t *issuer, uint64_t last,
                         compare_context_t *context) {
    atomic_init(&issuer->last_issued, last);
    issuer->compare_exchange = compare;
    issuer->context = context;
}

static bool next(fixture_t *f, uint64_t deadline, vireo_task_metadata_t *out) {
    vireo_inflight_stage_t stage = VIREO_INFLIGHT_CHECK_CLIENT;
    errno = EDOM;
    CHECK(vireo_inflight_metadata_make_next(f->server, f->client, 7, 9, deadline,
        out, &stage) == VIREO_OK);
    CHECK(errno == EDOM && stage == VIREO_INFLIGHT_NONE);
    CHECK(out->route.client_owner_id == f->client.pool_id);
    CHECK(out->route.client_slot_index == f->client.slot_index);
    CHECK(out->route.client_generation == f->client.generation);
    CHECK(out->route.request_sequence == 7 && out->operation == 9 && out->deadline_ns == deadline);
    return true;
}

/** 耗尽发行器也必须先报参数或真实客户错，失败输出全字节保持且不调用CAS。 */
static bool bridge_fails(vireo_tcp_server_t const *server, vireo_connection_pool_lease_t client,
    uint32_t sequence, uint32_t operation, vireo_result_t expected,
    vireo_inflight_stage_t expected_stage) {
    compare_context_t c = {0};
    vireo_inflight_instance_issuer_t issuer;
    issuer_init(&issuer, UINT64_MAX, &c);
    vireo_task_metadata_t out;
    unsigned char before[sizeof out];
    memset(&out, 0xa5, sizeof out); memcpy(before, &out, sizeof out);
    vireo_inflight_stage_t stage = VIREO_INFLIGHT_CHECK_RECORD;
    errno = EDOM;
    CHECK(vireo_inflight_metadata_make_next_with_issuer(&issuer, server, client, sequence,
        operation, UINT64_MAX, &out, &stage) == expected);
    CHECK(stage == expected_stage && errno == EDOM);
    CHECK(memcmp(before, &out, sizeof out) == 0 && c.calls == 0);
    errno = ERANGE;
    CHECK(vireo_inflight_metadata_make_next_with_issuer(&issuer, server, client, sequence,
        operation, 0, &out, NULL) == expected);
    CHECK(errno == ERANGE && memcmp(before, &out, sizeof out) == 0 && c.calls == 0);
    CHECK(atomic_load(&issuer.last_issued) == UINT64_MAX);
    return true;
}

/** 首个公开调用从1开始，原有纯值字段及有限期限完全保留。 */
static bool first_and_mapping(void) {
    fixture_t f; CHECK(setup(&f));
    vireo_task_metadata_t a, b;
    memset(&a, 0xa5, sizeof a);
    CHECK(next(&f, 0, &a) && a.request_instance_id == 1);
    CHECK(next(&f, UINT64_MAX, &b) && b.request_instance_id == 2);
    bool same = true;
    CHECK(vireo_task_metadata_same_request(a, b, &same) == VIREO_OK && !same);
    vireo_inflight_stage_t stage = VIREO_INFLIGHT_ISSUE_INSTANCE;
    errno = ERANGE;
    CHECK(vireo_inflight_metadata_make_next(f.server, f.client, UINT32_MAX, UINT32_MAX,
        0, &b, &stage) == VIREO_OK);
    CHECK(errno == ERANGE && stage == VIREO_INFLIGHT_NONE && b.request_instance_id == 3);
    CHECK(b.route.request_sequence == UINT32_MAX && b.operation == UINT32_MAX && b.deadline_ns == 0);
    return cleanup(&f);
}

static bool public_basic_errors(void) {
    fixture_t f; CHECK(setup(&f));
    vireo_task_metadata_t a, b; CHECK(next(&f, 0, &a));
    vireo_inflight_stage_t stage = VIREO_INFLIGHT_ISSUE_INSTANCE;
    errno = EDOM;
    CHECK(vireo_inflight_metadata_make_next(f.server, f.client, 7, 9, 0, NULL,
        &stage) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(errno == EDOM && stage == VIREO_INFLIGHT_NONE);
    vireo_task_metadata_t out; unsigned char saved[sizeof out];
    memset(&out, 0x5a, sizeof out); memcpy(saved, &out, sizeof out);
    CHECK(vireo_inflight_metadata_make_next(NULL, f.client, 7, 9, 0, &out,
        &stage) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(stage == VIREO_INFLIGHT_NONE && errno == EDOM && memcmp(saved, &out, sizeof out) == 0);
    CHECK(vireo_inflight_metadata_make_next(f.server, f.client, 0, 9, 0, &out,
        NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_inflight_metadata_make_next(f.server, f.client, 7, 0, 0, &out,
        NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(errno == EDOM && memcmp(saved, &out, sizeof out) == 0);
    CHECK(next(&f, 0, &b) && b.request_instance_id == a.request_instance_id + 1);
    return cleanup(&f);
}

static bool validation_before_exhaustion(void) {
    fixture_t f; CHECK(setup(&f));
    CHECK(bridge_fails(NULL, f.client, 7, 9, VIREO_RESULT_INVALID_ARGUMENT, VIREO_INFLIGHT_NONE));
    CHECK(bridge_fails(f.server, f.client, 0, 9, VIREO_RESULT_INVALID_ARGUMENT, VIREO_INFLIGHT_NONE));
    CHECK(bridge_fails(f.server, f.client, 7, 0, VIREO_RESULT_INVALID_ARGUMENT, VIREO_INFLIGHT_NONE));
    CHECK(bridge_fails(f.server, (vireo_connection_pool_lease_t){0}, 0, 9,
        VIREO_RESULT_INVALID_ARGUMENT, VIREO_INFLIGHT_NONE));
    CHECK(bridge_fails(f.server, (vireo_connection_pool_lease_t){0}, 7, 9,
        VIREO_RESULT_NOT_FOUND, VIREO_INFLIGHT_CHECK_CLIENT));
    vireo_connection_pool_lease_t bad = f.client; bad.pool_id = 0;
    CHECK(bridge_fails(f.server, bad, 7, 9, VIREO_RESULT_INVALID_ARGUMENT, VIREO_INFLIGHT_NONE));
    bad = f.client; bad.generation = 0;
    CHECK(bridge_fails(f.server, bad, 7, 9, VIREO_RESULT_INVALID_ARGUMENT, VIREO_INFLIGHT_NONE));
    CHECK(bridge_fails(f.other_server, f.client, 7, 9,
        VIREO_RESULT_INVALID_ARGUMENT, VIREO_INFLIGHT_CHECK_CLIENT));
    bad = f.client; bad.slot_index = SIZE_MAX;
    CHECK(bridge_fails(f.server, bad, 7, 9, VIREO_RESULT_RANGE, VIREO_INFLIGHT_CHECK_CLIENT));
    bad = f.client; bad.generation = UINT64_MAX;
    CHECK(bridge_fails(f.server, bad, 7, 9, VIREO_RESULT_NOT_FOUND, VIREO_INFLIGHT_CHECK_CLIENT));
    return cleanup(&f);
}

static bool isolated_max_and_no_reset(void) {
    fixture_t f; CHECK(setup(&f));
    compare_context_t c = {0};
    vireo_inflight_instance_issuer_t issuer; issuer_init(&issuer, UINT64_MAX - 1, &c);
    vireo_task_metadata_t out;
    vireo_inflight_stage_t stage = VIREO_INFLIGHT_CHECK_RECORD;
    errno = EDOM;
    CHECK(vireo_inflight_metadata_make_next_with_issuer(&issuer, f.server, f.client, 7, 9,
        UINT64_MAX, &out, &stage) == VIREO_OK);
    CHECK(errno == EDOM && stage == VIREO_INFLIGHT_NONE && out.request_instance_id == UINT64_MAX);
    CHECK(out.deadline_ns == UINT64_MAX && c.calls == 1 && atomic_load(&issuer.last_issued) == UINT64_MAX);
    unsigned char before[sizeof out]; memcpy(before, &out, sizeof out);
    for (size_t i = 0; i < 2; ++i) {
        stage = VIREO_INFLIGHT_NONE; errno = ERANGE;
        CHECK(vireo_inflight_metadata_make_next_with_issuer(&issuer, f.server, f.client, 7, 9,
            0, &out, &stage) == VIREO_RESULT_OVERFLOW);
        CHECK(errno == ERANGE && stage == VIREO_INFLIGHT_ISSUE_INSTANCE);
        CHECK(c.calls == 1 && memcmp(before, &out, sizeof out) == 0);
        CHECK(atomic_load(&issuer.last_issued) == UINT64_MAX);
    }
    /* 隔离MAX测试不影响生产发行器后续正常单调进度。 */
    CHECK(next(&f, 0, &out) && out.request_instance_id != 0);
    return cleanup(&f);
}

static bool one_real_competing_commit(void) {
    fixture_t f; CHECK(setup(&f));
    compare_context_t c = {.race = true};
    vireo_inflight_instance_issuer_t issuer; issuer_init(&issuer, 40, &c);
    vireo_task_metadata_t out; unsigned char saved[sizeof out];
    memset(&out, 0xa5, sizeof out); memcpy(saved, &out, sizeof out);
    vireo_inflight_stage_t stage = VIREO_INFLIGHT_NONE; errno = EDOM;
    CHECK(vireo_inflight_metadata_make_next_with_issuer(&issuer, f.server, f.client, 7, 9,
        0, &out, &stage) == VIREO_RESULT_BUSY);
    CHECK(errno == EDOM && stage == VIREO_INFLIGHT_ISSUE_INSTANCE && c.calls == 1);
    CHECK(atomic_load(&issuer.last_issued) == 41 && memcmp(saved, &out, sizeof out) == 0);
    c.race = false;
    CHECK(vireo_inflight_metadata_make_next_with_issuer(&issuer, f.server, f.client, 7, 9,
        0, &out, NULL) == VIREO_OK);
    CHECK(out.request_instance_id == 42 && c.calls == 2 && errno == EDOM);
    return cleanup(&f);
}

static bool last_value_lost_race(void) {
    fixture_t f; CHECK(setup(&f));
    compare_context_t c = {.race = true};
    vireo_inflight_instance_issuer_t issuer; issuer_init(&issuer, UINT64_MAX - 1, &c);
    vireo_task_metadata_t out; unsigned char before[sizeof out];
    memset(&out, 0x5a, sizeof out); memcpy(before, &out, sizeof out);
    vireo_inflight_stage_t stage = VIREO_INFLIGHT_NONE; errno = ERANGE;
    CHECK(vireo_inflight_metadata_make_next_with_issuer(&issuer, f.server, f.client, 7, 9,
        0, &out, &stage) == VIREO_RESULT_BUSY);
    CHECK(c.calls == 1 && atomic_load(&issuer.last_issued) == UINT64_MAX);
    CHECK(stage == VIREO_INFLIGHT_ISSUE_INSTANCE && errno == ERANGE);
    CHECK(vireo_inflight_metadata_make_next_with_issuer(&issuer, f.server, f.client, 7, 9,
        0, &out, NULL) == VIREO_RESULT_OVERFLOW);
    CHECK(c.calls == 1 && errno == ERANGE && memcmp(before, &out, sizeof out) == 0);
    return cleanup(&f);
}

static bool no_refund_and_recreated_store(void) {
    fixture_t f; CHECK(setup(&f));
    vireo_inflight_store_t *store = NULL;
    vireo_inflight_store_options_t const options = {1, VIREO_INFLIGHT_STORE_MAX_ALLOCATION_BYTES};
    CHECK(vireo_inflight_store_create(&options, &store) == VIREO_OK);
    vireo_task_metadata_t a, rejected, b, saved;
    CHECK(next(&f, 0, &a));
    CHECK(vireo_inflight_store_register_limited(store, f.server, a, 1, NULL) == VIREO_OK);
    CHECK(next(&f, UINT64_MAX, &rejected) && rejected.request_instance_id == a.request_instance_id + 1);
    CHECK(vireo_inflight_store_register_limited(store, f.server, rejected, 1, NULL) == VIREO_RESULT_BUSY);
    CHECK(vireo_inflight_store_take(store, a, &saved, NULL) == VIREO_OK);
    CHECK(saved.request_instance_id == a.request_instance_id);
    CHECK(next(&f, 0, &b) && b.request_instance_id == rejected.request_instance_id + 1);
    CHECK(vireo_inflight_store_register_limited(store, f.server, b, 1, NULL) == VIREO_OK);
    CHECK(vireo_inflight_store_get(store, a, &saved, NULL) == VIREO_RESULT_NOT_FOUND);
    CHECK(vireo_inflight_store_get(store, rejected, &saved, NULL) == VIREO_RESULT_NOT_FOUND);
    CHECK(vireo_inflight_store_take(store, b, &saved, NULL) == VIREO_OK);
    CHECK(vireo_inflight_store_destroy(&store) == VIREO_OK && store == NULL);
    CHECK(vireo_inflight_store_create(&options, &store) == VIREO_OK);
    CHECK(next(&f, UINT64_MAX, &a) && a.request_instance_id == b.request_instance_id + 1);
    CHECK(vireo_inflight_store_register_limited(store, f.server, a, 1, NULL) == VIREO_OK);
    CHECK(vireo_inflight_store_get(store, b, &saved, NULL) == VIREO_RESULT_NOT_FOUND);
    CHECK(vireo_inflight_store_take(store, a, &saved, NULL) == VIREO_OK);
    CHECK(vireo_inflight_store_destroy(&store) == VIREO_OK);
    return cleanup(&f);
}

static bool slot_reuse_issuance(void) {
    fixture_t f; CHECK(setup(&f));
    vireo_task_metadata_t old, current; CHECK(next(&f, 0, &old));
    vireo_connection_pool_lease_t const lease = f.client;
    CHECK(release_client(&f)); CHECK(add_client(&f));
    CHECK(f.client.pool_id == lease.pool_id && f.client.slot_index == lease.slot_index);
    CHECK(f.client.generation != lease.generation);
    CHECK(bridge_fails(f.server, lease, 7, 9, VIREO_RESULT_NOT_FOUND, VIREO_INFLIGHT_CHECK_CLIENT));
    CHECK(next(&f, UINT64_MAX, &current));
    CHECK(current.request_instance_id == old.request_instance_id + 1);
    bool same = true;
    CHECK(vireo_task_metadata_same_request(old, current, &same) == VIREO_OK && !same);
    return cleanup(&f);
}

static bool closing_and_stopped_issuance(void) {
    fixture_t f; CHECK(setup(&f));
    unsigned char const byte = 0x42;
    CHECK(vireo_tcp_server_client_write_enqueue(f.server, f.client, &byte, 1, NULL) == VIREO_OK);
    CHECK(vireo_tcp_server_client_request_close(f.server, f.client, VIREO_CONNECTION_CLOSE_MODE_DRAIN,
        VIREO_CONNECTION_CLOSE_REASON_APPLICATION, NULL) == VIREO_OK);
    vireo_task_metadata_t metadata; CHECK(next(&f, 0, &metadata));
    vireo_connection_close_state_t state;
    CHECK(vireo_inflight_check_client(f.server, metadata, &state, NULL) == VIREO_OK);
    CHECK(state == VIREO_CONNECTION_CLOSE_DRAINING);
    vireo_inflight_store_t *store = NULL;
    vireo_inflight_store_options_t const options = {1, VIREO_INFLIGHT_STORE_MAX_ALLOCATION_BYTES};
    CHECK(vireo_inflight_store_create(&options, &store) == VIREO_OK);
    CHECK(vireo_inflight_store_register(store, f.server, metadata, NULL) == VIREO_RESULT_BUSY);
    CHECK(vireo_tcp_server_request_stop(f.server, NULL) == VIREO_OK);
    CHECK(vireo_tcp_server_client_request_close(f.server, f.client, VIREO_CONNECTION_CLOSE_MODE_IMMEDIATE,
        VIREO_CONNECTION_CLOSE_REASON_APPLICATION, NULL) == VIREO_OK);
    CHECK(next(&f, UINT64_MAX, &metadata));
    CHECK(vireo_inflight_check_client(f.server, metadata, &state, NULL) == VIREO_OK);
    CHECK(state == VIREO_CONNECTION_CLOSE_READY);
    CHECK(vireo_inflight_store_register(store, f.server, metadata, NULL) == VIREO_RESULT_CANCELLED);
    CHECK(vireo_inflight_store_destroy(&store) == VIREO_OK);
    return cleanup(&f);
}

static bool resources_and_old_make(void) {
    fixture_t f; CHECK(setup(&f));
    vireo_tcp_server_info_t before, after;
    vireo_tcp_server_client_info_t client_before, client_after;
    CHECK(vireo_tcp_server_inspect(f.server, &before) == VIREO_OK);
    CHECK(vireo_tcp_server_client_inspect(f.server, f.client, &client_before) == VIREO_OK);
    vireo_task_metadata_t a, b; CHECK(next(&f, 0, &a));
    CHECK(next(&f, UINT64_MAX, &b));
    CHECK(vireo_tcp_server_inspect(f.server, &after) == VIREO_OK);
    CHECK(vireo_tcp_server_client_inspect(f.server, f.client, &client_after) == VIREO_OK);
    CHECK(before.connection_count == after.connection_count && before.registered_connections == after.registered_connections);
    CHECK(before.available_connections == after.available_connections && before.pending_clients == after.pending_clients);
    CHECK(before.allocation_bytes == after.allocation_bytes && before.buffer_capacity_bytes == after.buffer_capacity_bytes);
    CHECK(client_before.queued == client_after.queued && client_before.pending_events == client_after.pending_events);
    CHECK(client_before.connection_info.close_state == client_after.connection_info.close_state);
    CHECK(client_before.connection_info.loop_interests == client_after.connection_info.loop_interests);
    CHECK(client_before.connection_info.read_buffer.readable_size == client_after.connection_info.read_buffer.readable_size);
    CHECK(client_before.connection_info.write_buffer.readable_size == client_after.connection_info.write_buffer.readable_size);
    CHECK(release_client(&f)); CHECK(add_client(&f));
    /* 另一个完整客户生命期只用手工来源，旧入口仍按caller实例原值构造。 */
    errno = EDOM;
    CHECK(vireo_inflight_metadata_make(f.server, f.client, 7, UINT64_MAX, 9, 0, &a, NULL) == VIREO_OK);
    CHECK(errno == EDOM && a.request_instance_id == UINT64_MAX);
    return cleanup(&f);
}

static bool seam_basic_errors(void) {
    fixture_t f; CHECK(setup(&f));
    vireo_inflight_instance_issuer_t issuer; issuer_init(&issuer, 0, NULL);
    vireo_task_metadata_t out; unsigned char saved[sizeof out];
    memset(&out, 0xa5, sizeof out); memcpy(saved, &out, sizeof out);
    vireo_inflight_stage_t stage = VIREO_INFLIGHT_ISSUE_INSTANCE; errno = EDOM;
    CHECK(vireo_inflight_metadata_make_next_with_issuer(NULL, f.server, f.client, 7, 9, 0,
        &out, &stage) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(stage == VIREO_INFLIGHT_NONE && errno == EDOM);
    CHECK(vireo_inflight_metadata_make_next_with_issuer(&issuer, f.server, f.client, 7, 9, 0,
        NULL, &stage) == VIREO_RESULT_INVALID_ARGUMENT);
    issuer.compare_exchange = NULL;
    CHECK(vireo_inflight_metadata_make_next_with_issuer(&issuer, f.server, f.client, 7, 9, 0,
        &out, &stage) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(stage == VIREO_INFLIGHT_NONE && errno == EDOM && memcmp(saved, &out, sizeof out) == 0);
    CHECK(atomic_load(&issuer.last_issued) == 0);
    return cleanup(&f);
}

/** 每个native线程独占一个server及输出；仅数值issuer共享。 */
typedef struct worker_context {
    fixture_t *fixture; /**< main发布的独立fixture，只借到join，其他线程不访问。 */
    vireo_inflight_instance_issuer_t *issuer; /**< 共享存活发行器，last只原子读写。 */
    uint64_t values[64]; /**< 此线程成功输出的独立实例数组。 */
    size_t count; /**< 成功条数，join后由main读取。 */
    size_t busy; /**< 单次竞争拒绝数，不内部重试。 */
    bool okay; /**< 此线程输出/errno/stage校验结果，join后可读。 */
} worker_context_t;

static void *issue_worker(void *context) {
    worker_context_t *w = context;
    w->okay = true;
    for (size_t i = 0; i < 64; ++i) {
        vireo_task_metadata_t out; unsigned char saved[sizeof out];
        memset(&out, 0xa5, sizeof out); memcpy(saved, &out, sizeof out);
        vireo_inflight_stage_t stage = VIREO_INFLIGHT_NONE; errno = EDOM;
        vireo_result_t result = vireo_inflight_metadata_make_next_with_issuer(w->issuer,
            w->fixture->server, w->fixture->client, 7, 9, 0, &out, &stage);
        if (result == VIREO_OK) {
            w->values[w->count++] = out.request_instance_id;
            if (out.request_instance_id == 0 || stage != VIREO_INFLIGHT_NONE ||
                out.route.client_owner_id != w->fixture->client.pool_id ||
                out.route.client_slot_index != w->fixture->client.slot_index ||
                out.route.client_generation != w->fixture->client.generation ||
                out.route.request_sequence != 7 || out.operation != 9 || out.deadline_ns != 0) w->okay = false;
        } else if (result == VIREO_RESULT_BUSY) {
            ++w->busy;
            if (stage != VIREO_INFLIGHT_ISSUE_INSTANCE || memcmp(saved, &out, sizeof out) != 0) w->okay = false;
        } else w->okay = false;
        if (errno != EDOM) w->okay = false;
    }
    return NULL;
}

/** 固定256次尝试，不保证出现所有竞争时序；确定性竞争由单独seam组覆盖。 */
static bool independent_reactors_unique(void) {
    fixture_t fixtures[4]; worker_context_t contexts[4] = {0}; pthread_t threads[4];
    vireo_inflight_instance_issuer_t issuer; issuer_init(&issuer, 0, NULL);
    for (size_t i = 0; i < 4; ++i) CHECK(setup(&fixtures[i]));
    for (size_t i = 0; i < 4; ++i) {
        contexts[i].fixture = &fixtures[i]; contexts[i].issuer = &issuer;
        CHECK(pthread_create(&threads[i], NULL, issue_worker, &contexts[i]) == 0);
    }
    for (size_t i = 0; i < 4; ++i) CHECK(pthread_join(threads[i], NULL) == 0);
    bool seen[257] = {false}; size_t total = 0;
    for (size_t i = 0; i < 4; ++i) {
        CHECK(contexts[i].okay && contexts[i].count + contexts[i].busy == 64);
        total += contexts[i].count;
        for (size_t j = 0; j < contexts[i].count; ++j) {
            uint64_t const value = contexts[i].values[j];
            CHECK(value >= 1 && value <= 256 && !seen[(size_t)value]);
            seen[(size_t)value] = true;
        }
    }
    CHECK(total > 0 && atomic_load(&issuer.last_issued) == total);
    for (size_t i = 1; i <= total; ++i) CHECK(seen[i]);
    printf("isolated issuer: %zu successes, %zu BUSY, atomic lock-free=%d\n",
        total, (size_t)256 - total, atomic_is_lock_free(&issuer.last_issued) ? 1 : 0);
    for (size_t i = 0; i < 4; ++i) CHECK(cleanup(&fixtures[i]));
    return true;
}

/** 测试调度表，不拥有产品资源。 */
typedef struct test_case {
    char const *name; /**< 静态组名，用于实际输出定位。 */
    bool (*run)(void); /**< 同步组入口，完成自己的资源清理。 */
} test_case_t;

int main(void) {
    test_case_t const cases[] = {
        {"first_and_mapping", first_and_mapping}, {"public_basic_errors", public_basic_errors},
        {"validation_before_exhaustion", validation_before_exhaustion},
        {"isolated_max_and_no_reset", isolated_max_and_no_reset},
        {"one_real_competing_commit", one_real_competing_commit},
        {"last_value_lost_race", last_value_lost_race},
        {"no_refund_and_recreated_store", no_refund_and_recreated_store},
        {"slot_reuse_issuance", slot_reuse_issuance},
        {"closing_and_stopped_issuance", closing_and_stopped_issuance},
        {"resources_and_old_make", resources_and_old_make},
        {"seam_basic_errors", seam_basic_errors},
        {"independent_reactors_unique", independent_reactors_unique}
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
        if (!cases[i].run()) { fprintf(stderr, "FAIL %s\n", cases[i].name); return 1; }
        printf("PASS %s\n", cases[i].name);
    }
    printf("inflight instance: %zu groups passed\n", sizeof cases / sizeof cases[0]);
    return 0;
}
