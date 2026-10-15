/*
 * PROJECT : VIREO
 * FILE    : test_inflight_store_records.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-13
 * BRIEF   : 真实请求登记、历史取出、准入顺序与完整失败保持
 */
#define _GNU_SOURCE
#include <vireo/net/inflight_store.h>

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

_Static_assert(VIREO_INFLIGHT_NONE == 0 && VIREO_INFLIGHT_CHECK_CLIENT == 1 &&
    VIREO_INFLIGHT_MAKE_ROUTE == 2 && VIREO_INFLIGHT_MAKE_METADATA == 3 &&
    VIREO_INFLIGHT_CHECK_METADATA == 4 && VIREO_INFLIGHT_CHECK_SERVER == 5 &&
    VIREO_INFLIGHT_CHECK_RECORD == 6, "inflight diagnostic stage values");

#define CHECK(expr) do { if (!(expr)) { \
    fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #expr); return false; \
} } while (0)

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

/** 通过公开桥接产生测试值；不伪造当前客户或读取其他核心私有布局。 */
static bool make(fixture_t *f, uint32_t sequence, uint64_t instance,
    uint32_t operation, uint64_t deadline, vireo_task_metadata_t *out) {
    errno = EDOM;
    CHECK(vireo_inflight_metadata_make(f->server, f->client, sequence, instance,
        operation, deadline, out, NULL) == VIREO_OK);
    CHECK(errno == EDOM);
    return true;
}

/** 成功只比较逻辑字段，padding 不属于成功合同。 */
static bool same_value(vireo_task_metadata_t a, vireo_task_metadata_t b) {
    return a.route.client_owner_id == b.route.client_owner_id &&
        a.route.client_slot_index == b.route.client_slot_index &&
        a.route.client_generation == b.route.client_generation &&
        a.route.request_sequence == b.route.request_sequence &&
        a.request_instance_id == b.request_instance_id &&
        a.operation == b.operation && a.deadline_ns == b.deadline_ns;
}

/** 创建显式容量的公共表，不使用布局或分配 seam。 */
static bool create(size_t capacity, vireo_inflight_store_t **owner) {
    vireo_inflight_store_options_t const options = {
        capacity, VIREO_INFLIGHT_STORE_MAX_ALLOCATION_BYTES
    };
    errno = EDOM;
    CHECK(vireo_inflight_store_create(&options, owner) == VIREO_OK && errno == EDOM);
    return true;
}

/** 按公开快照检查真实登记数及固定容量。 */
static bool count_is(vireo_inflight_store_t const *store, size_t expected) {
    vireo_inflight_store_info_t info;
    errno = EDOM;
    CHECK(vireo_inflight_store_inspect(store, &info) == VIREO_OK && errno == EDOM);
    CHECK(info.count == expected && info.count <= info.capacity);
    return true;
}

/** 每次调用都检查结果、覆盖的阶段与 errno；失败还检查原登记数。 */
static bool register_is(vireo_inflight_store_t *store, vireo_tcp_server_t const *server,
    vireo_task_metadata_t metadata, vireo_result_t expected, vireo_inflight_stage_t detail) {
    vireo_inflight_store_info_t before, after;
    CHECK(vireo_inflight_store_inspect(store, &before) == VIREO_OK);
    vireo_inflight_stage_t stage = VIREO_INFLIGHT_MAKE_ROUTE;
    errno = E2BIG;
    CHECK(vireo_inflight_store_register(store, server, metadata, &stage) == expected);
    CHECK(errno == E2BIG && stage == detail);
    CHECK(vireo_inflight_store_inspect(store, &after) == VIREO_OK);
    CHECK(before.capacity == after.capacity && before.allocated_bytes == after.allocated_bytes &&
        before.max_memory_bytes == after.max_memory_bytes);
    CHECK(after.count == before.count + (expected == VIREO_OK ? 1U : 0U));
    return true;
}

/** 失败输出按全部字节核对；get 和 take 都必须保持表的四字段快照。 */
static bool lookup_fails(vireo_inflight_store_t *store, vireo_task_metadata_t key,
    vireo_result_t expected, vireo_inflight_stage_t detail) {
    vireo_task_metadata_t out;
    unsigned char before[sizeof out];
    memset(&out, 0xa5, sizeof out);
    memcpy(before, &out, sizeof out);
    vireo_inflight_store_info_t info_before, info_after;
    CHECK(vireo_inflight_store_inspect(store, &info_before) == VIREO_OK);
    for (size_t take = 0; take < 2; ++take) {
        vireo_inflight_stage_t stage = VIREO_INFLIGHT_MAKE_METADATA;
        errno = ERANGE;
        vireo_result_t const result = take == 0 ?
            vireo_inflight_store_get(store, key, &out, &stage) :
            vireo_inflight_store_take(store, key, &out, &stage);
        CHECK(result == expected && errno == ERANGE && stage == detail);
        CHECK(memcmp(before, &out, sizeof out) == 0);
        errno = E2BIG;
        vireo_result_t const no_stage = take == 0 ?
            vireo_inflight_store_get(store, key, &out, NULL) :
            vireo_inflight_store_take(store, key, &out, NULL);
        CHECK(no_stage == expected && errno == E2BIG && memcmp(before, &out, sizeof out) == 0);
    }
    CHECK(vireo_inflight_store_inspect(store, &info_after) == VIREO_OK);
    CHECK(info_before.capacity == info_after.capacity && info_before.count == info_after.count &&
        info_before.allocated_bytes == info_after.allocated_bytes &&
        info_before.max_memory_bytes == info_after.max_memory_bytes);
    return true;
}

/** get 与 take 成功都返回原值；take 不表示任务或客户已结束。 */
static bool lookup_is(vireo_inflight_store_t *store, vireo_task_metadata_t key,
    vireo_task_metadata_t expected, bool take) {
    vireo_task_metadata_t out;
    memset(&out, 0xa5, sizeof out);
    vireo_inflight_stage_t stage = VIREO_INFLIGHT_CHECK_METADATA;
    errno = E2BIG;
    vireo_result_t const result = take ? vireo_inflight_store_take(store, key, &out, &stage) :
        vireo_inflight_store_get(store, key, &out, &stage);
    CHECK(result == VIREO_OK && errno == E2BIG && stage == VIREO_INFLIGHT_NONE);
    CHECK(same_value(out, expected));
    return true;
}

static bool records_lifecycle(void) {
    fixture_t f;
    CHECK(setup(&f));
    vireo_inflight_store_t *store = NULL;
    CHECK(create(3, &store) && count_is(store, 0));
    vireo_task_metadata_t a;
    CHECK(make(&f, 7, 400, 9, 1, &a));
    CHECK(register_is(store, f.server, a, VIREO_OK, VIREO_INFLIGHT_NONE));
    CHECK(count_is(store, 1) && lookup_is(store, a, a, false));
    vireo_inflight_store_t *original = store;
    errno = E2BIG;
    CHECK(vireo_inflight_store_destroy(&store) == VIREO_RESULT_BUSY);
    CHECK(errno == E2BIG && store == original && count_is(store, 1));
    CHECK(lookup_is(store, a, a, false) && lookup_is(store, a, a, true));
    CHECK(count_is(store, 0));
    CHECK(lookup_fails(store, a, VIREO_RESULT_NOT_FOUND, VIREO_INFLIGHT_CHECK_RECORD));
    errno = E2BIG;
    CHECK(vireo_inflight_store_destroy(&store) == VIREO_OK && store == NULL && errno == E2BIG);
    CHECK(vireo_inflight_store_destroy(&store) == VIREO_OK && errno == E2BIG);
    return cleanup(&f);
}

static bool original_snapshot(void) {
    fixture_t f;
    CHECK(setup(&f));
    vireo_inflight_store_t *store = NULL;
    CHECK(create(1, &store));
    vireo_task_metadata_t a, out;
    CHECK(make(&f, 7, 400, 9, 0, &a));
    CHECK(vireo_inflight_store_register(store, f.server, a, NULL) == VIREO_OK);
    vireo_task_metadata_t key = a;
    key.operation = UINT32_MAX; key.deadline_ns = UINT64_MAX;
    CHECK(lookup_is(store, key, a, false) && count_is(store, 1));
    errno = ERANGE;
    CHECK(vireo_inflight_store_get(store, key, &out, NULL) == VIREO_OK && errno == ERANGE);
    CHECK(same_value(out, a));
    CHECK(vireo_inflight_store_take(store, key, &out, NULL) == VIREO_OK && errno == ERANGE);
    CHECK(same_value(out, a) && count_is(store, 0));
    CHECK(vireo_inflight_store_destroy(&store) == VIREO_OK);
    return cleanup(&f);
}

static bool full_and_sequence_reuse(void) {
    fixture_t f;
    CHECK(setup(&f));
    vireo_inflight_store_t *store = NULL;
    CHECK(create(1, &store));
    vireo_task_metadata_t a, b;
    CHECK(make(&f, 7, 400, 9, 0, &a) && make(&f, 8, 401, 9, UINT64_MAX, &b));
    CHECK(register_is(store, f.server, a, VIREO_OK, VIREO_INFLIGHT_NONE));
    CHECK(register_is(store, f.server, b, VIREO_RESULT_BUSY, VIREO_INFLIGHT_CHECK_RECORD));
    CHECK(lookup_is(store, a, a, false) && lookup_is(store, a, a, true));
    b.route.request_sequence = a.route.request_sequence;
    CHECK(register_is(store, f.server, b, VIREO_OK, VIREO_INFLIGHT_NONE));
    CHECK(lookup_fails(store, a, VIREO_RESULT_NOT_FOUND, VIREO_INFLIGHT_CHECK_RECORD));
    CHECK(lookup_is(store, b, b, true));
    CHECK(vireo_inflight_store_destroy(&store) == VIREO_OK);
    return cleanup(&f);
}

/** 空洞出现后仍须扫描后面的冲突，不能遇空槽就提交。 */
static bool active_conflicts_and_holes(void) {
    fixture_t f;
    CHECK(setup(&f));
    vireo_inflight_store_t *store = NULL;
    CHECK(create(3, &store));
    vireo_task_metadata_t a, b, c;
    CHECK(make(&f, 7, 400, 9, 0, &a) && make(&f, 8, 401, 10, 1, &b));
    CHECK(make(&f, 9, 402, 11, UINT64_MAX, &c));
    CHECK(register_is(store, f.server, a, VIREO_OK, VIREO_INFLIGHT_NONE));
    CHECK(register_is(store, f.server, b, VIREO_OK, VIREO_INFLIGHT_NONE));
    CHECK(lookup_is(store, a, a, true));
    vireo_task_metadata_t conflict = b;
    conflict.operation = UINT32_MAX; conflict.deadline_ns = UINT64_MAX;
    CHECK(register_is(store, f.server, conflict, VIREO_RESULT_BUSY, VIREO_INFLIGHT_CHECK_RECORD));
    conflict.request_instance_id = 403;
    CHECK(register_is(store, f.server, conflict, VIREO_RESULT_BUSY, VIREO_INFLIGHT_CHECK_RECORD));
    conflict = b; conflict.route.request_sequence = 10;
    CHECK(register_is(store, f.server, conflict, VIREO_RESULT_BUSY, VIREO_INFLIGHT_CHECK_RECORD));
    CHECK(lookup_is(store, b, b, false) && count_is(store, 1));
    CHECK(register_is(store, f.server, c, VIREO_OK, VIREO_INFLIGHT_NONE));
    CHECK(lookup_is(store, c, c, true) && lookup_is(store, b, b, true));
    CHECK(vireo_inflight_store_destroy(&store) == VIREO_OK);
    return cleanup(&f);
}

static bool basic_errors(void) {
    fixture_t f;
    CHECK(setup(&f));
    vireo_inflight_store_t *store = NULL;
    CHECK(create(1, &store));
    vireo_task_metadata_t a, out;
    CHECK(make(&f, 7, 400, 9, 0, &a));
    memset(&out, 0xa5, sizeof out);
    unsigned char before[sizeof out]; memcpy(before, &out, sizeof out);
    vireo_inflight_stage_t stage = VIREO_INFLIGHT_CHECK_RECORD;
    errno = E2BIG;
    CHECK(vireo_inflight_store_register(NULL, f.server, a, &stage) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(stage == VIREO_INFLIGHT_NONE && errno == E2BIG);
    CHECK(register_is(store, NULL, a, VIREO_RESULT_INVALID_ARGUMENT, VIREO_INFLIGHT_NONE));
    CHECK(vireo_inflight_store_get(NULL, a, &out, &stage) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(stage == VIREO_INFLIGHT_NONE && memcmp(before, &out, sizeof out) == 0 && errno == E2BIG);
    CHECK(vireo_inflight_store_take(NULL, a, &out, &stage) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(stage == VIREO_INFLIGHT_NONE && memcmp(before, &out, sizeof out) == 0 && errno == E2BIG);
    CHECK(vireo_inflight_store_get(store, (vireo_task_metadata_t){0}, NULL, &stage) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(stage == VIREO_INFLIGHT_NONE && errno == E2BIG);
    CHECK(vireo_inflight_store_take(store, (vireo_task_metadata_t){0}, NULL, &stage) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(stage == VIREO_INFLIGHT_NONE && errno == E2BIG && count_is(store, 0));
    CHECK(vireo_inflight_store_destroy(&store) == VIREO_OK);
    return cleanup(&f);
}

/** 无效形态优先于当前客户、停止和满表；失败保留原记录。 */
static bool metadata_errors(void) {
    fixture_t f;
    CHECK(setup(&f));
    vireo_inflight_store_t *store = NULL;
    CHECK(create(1, &store));
    vireo_task_metadata_t a;
    CHECK(make(&f, 7, 400, 9, 0, &a));
    CHECK(register_is(store, f.server, a, VIREO_OK, VIREO_INFLIGHT_NONE));
    CHECK(vireo_tcp_server_request_stop(f.server, NULL) == VIREO_OK);
    vireo_task_metadata_t bad[6];
    for (size_t i = 0; i < 6; ++i) bad[i] = a;
    bad[0] = (vireo_task_metadata_t){0};
    bad[1].route.client_owner_id = 0; bad[2].route.client_generation = 0;
    bad[3].route.request_sequence = 0; bad[4].request_instance_id = 0; bad[5].operation = 0;
    for (size_t i = 0; i < 6; ++i) {
        CHECK(register_is(store, f.server, bad[i], VIREO_RESULT_INVALID_ARGUMENT, VIREO_INFLIGHT_CHECK_METADATA));
        CHECK(lookup_fails(store, bad[i], VIREO_RESULT_INVALID_ARGUMENT, VIREO_INFLIGHT_CHECK_METADATA));
        CHECK(lookup_is(store, a, a, false));
    }
    CHECK(lookup_is(store, a, a, true));
    CHECK(vireo_inflight_store_destroy(&store) == VIREO_OK);
    return cleanup(&f);
}

/** 客户身份拒绝先于停止或容量；查询数值键不查询当前客户。 */
static bool identity_errors(void) {
    fixture_t f;
    CHECK(setup(&f));
    vireo_inflight_store_t *store = NULL;
    CHECK(create(1, &store));
    vireo_task_metadata_t a;
    CHECK(make(&f, 7, 400, 9, 0, &a));
    CHECK(register_is(store, f.server, a, VIREO_OK, VIREO_INFLIGHT_NONE));
    CHECK(vireo_tcp_server_request_stop(f.server, NULL) == VIREO_OK);
    CHECK(register_is(store, f.other_server, a, VIREO_RESULT_INVALID_ARGUMENT, VIREO_INFLIGHT_CHECK_CLIENT));
    vireo_task_metadata_t bad = a; bad.route.client_slot_index = SIZE_MAX;
    CHECK(register_is(store, f.server, bad, VIREO_RESULT_RANGE, VIREO_INFLIGHT_CHECK_CLIENT));
    CHECK(lookup_fails(store, bad, VIREO_RESULT_NOT_FOUND, VIREO_INFLIGHT_CHECK_RECORD));
    bad = a; bad.route.client_generation = a.route.client_generation + 1;
    CHECK(register_is(store, f.server, bad, VIREO_RESULT_NOT_FOUND, VIREO_INFLIGHT_CHECK_CLIENT));
    CHECK(lookup_fails(store, bad, VIREO_RESULT_NOT_FOUND, VIREO_INFLIGHT_CHECK_RECORD));
    bad = a; ++bad.route.request_sequence;
    CHECK(lookup_fails(store, bad, VIREO_RESULT_NOT_FOUND, VIREO_INFLIGHT_CHECK_RECORD));
    bad = a; ++bad.request_instance_id;
    CHECK(lookup_fails(store, bad, VIREO_RESULT_NOT_FOUND, VIREO_INFLIGHT_CHECK_RECORD));
    CHECK(lookup_is(store, a, a, true));
    CHECK(vireo_inflight_store_destroy(&store) == VIREO_OK);
    return cleanup(&f);
}

static bool closing_and_stop_order(void) {
    fixture_t f;
    CHECK(setup(&f));
    vireo_inflight_store_t *store = NULL;
    CHECK(create(1, &store));
    vireo_task_metadata_t a, b;
    CHECK(make(&f, 7, 400, 9, 0, &a) && make(&f, 8, 401, 9, 1, &b));
    CHECK(register_is(store, f.server, a, VIREO_OK, VIREO_INFLIGHT_NONE));
    uint8_t const byte = 0x5a;
    CHECK(vireo_tcp_server_client_write_enqueue(f.server, f.client, &byte, 1, NULL) == VIREO_OK);
    CHECK(vireo_tcp_server_client_request_close(f.server, f.client, VIREO_CONNECTION_CLOSE_MODE_DRAIN,
        VIREO_CONNECTION_CLOSE_REASON_APPLICATION, NULL) == VIREO_OK);
    vireo_connection_close_state_t state;
    CHECK(vireo_inflight_check_client(f.server, b, &state, NULL) == VIREO_OK && state == VIREO_CONNECTION_CLOSE_DRAINING);
    CHECK(register_is(store, f.server, b, VIREO_RESULT_BUSY, VIREO_INFLIGHT_CHECK_CLIENT));
    CHECK(vireo_tcp_server_client_request_close(f.server, f.client, VIREO_CONNECTION_CLOSE_MODE_IMMEDIATE,
        VIREO_CONNECTION_CLOSE_REASON_APPLICATION, NULL) == VIREO_OK);
    CHECK(vireo_inflight_check_client(f.server, b, &state, NULL) == VIREO_OK && state == VIREO_CONNECTION_CLOSE_READY);
    CHECK(register_is(store, f.server, b, VIREO_RESULT_BUSY, VIREO_INFLIGHT_CHECK_CLIENT));
    CHECK(vireo_tcp_server_request_stop(f.server, NULL) == VIREO_OK);
    CHECK(register_is(store, f.server, b, VIREO_RESULT_CANCELLED, VIREO_INFLIGHT_CHECK_SERVER));
    CHECK(lookup_is(store, a, a, false) && lookup_is(store, a, a, true));
    CHECK(vireo_inflight_store_destroy(&store) == VIREO_OK);
    return cleanup(&f);
}

static bool stopped_open_client(void) {
    fixture_t f;
    CHECK(setup(&f));
    vireo_inflight_store_t *store = NULL;
    CHECK(create(3, &store));
    vireo_task_metadata_t a, b;
    CHECK(make(&f, 7, 400, 9, 0, &a) && make(&f, 8, 401, 9, UINT64_MAX, &b));
    CHECK(register_is(store, f.server, a, VIREO_OK, VIREO_INFLIGHT_NONE));
    CHECK(vireo_tcp_server_request_stop(f.server, NULL) == VIREO_OK);
    CHECK(register_is(store, f.server, b, VIREO_RESULT_CANCELLED, VIREO_INFLIGHT_CHECK_SERVER));
    CHECK(lookup_is(store, a, a, true) && count_is(store, 0));
    CHECK(vireo_inflight_store_destroy(&store) == VIREO_OK);
    return cleanup(&f);
}

/** 真实归还/重接复用同槽；旧代记录不阻止新代相同标签。 */
static bool historical_records_and_slot_reuse(void) {
    fixture_t f;
    CHECK(setup(&f));
    vireo_inflight_store_t *store = NULL;
    CHECK(create(3, &store));
    vireo_task_metadata_t old, current;
    CHECK(make(&f, 7, 400, 9, 0, &old));
    CHECK(register_is(store, f.server, old, VIREO_OK, VIREO_INFLIGHT_NONE));
    CHECK(release_client(&f));
    CHECK(register_is(store, f.server, old, VIREO_RESULT_NOT_FOUND, VIREO_INFLIGHT_CHECK_CLIENT));
    CHECK(lookup_is(store, old, old, false));
    CHECK(add_client(&f) && make(&f, 7, 400, 10, UINT64_MAX, &current));
    CHECK(old.route.client_slot_index == current.route.client_slot_index);
    CHECK(old.route.client_owner_id == current.route.client_owner_id &&
        old.route.client_generation != current.route.client_generation);
    CHECK(register_is(store, f.server, current, VIREO_OK, VIREO_INFLIGHT_NONE));
    CHECK(lookup_is(store, old, old, true) && count_is(store, 1));
    CHECK(lookup_fails(store, old, VIREO_RESULT_NOT_FOUND, VIREO_INFLIGHT_CHECK_RECORD));
    CHECK(lookup_is(store, current, current, false));
    CHECK(release_client(&f) && cleanup(&f));
    CHECK(lookup_is(store, current, current, true) && count_is(store, 0));
    CHECK(vireo_inflight_store_destroy(&store) == VIREO_OK);
    return true;
}

static bool separate_client_owners(void) {
    fixture_t a, b;
    CHECK(setup(&a) && setup(&b));
    vireo_inflight_store_t *store = NULL;
    CHECK(create(3, &store));
    vireo_task_metadata_t left, right;
    CHECK(make(&a, 7, 400, 9, 0, &left) && make(&b, 7, 400, 10, 1, &right));
    CHECK(left.route.client_owner_id != right.route.client_owner_id);
    CHECK(register_is(store, a.server, left, VIREO_OK, VIREO_INFLIGHT_NONE));
    CHECK(register_is(store, b.server, right, VIREO_OK, VIREO_INFLIGHT_NONE));
    CHECK(count_is(store, 2) && lookup_is(store, left, left, true));
    CHECK(lookup_is(store, right, right, true));
    CHECK(vireo_inflight_store_destroy(&store) == VIREO_OK);
    CHECK(cleanup(&a));
    return cleanup(&b);
}

/** 同池不同客户也可以使用相同 sequence/instance，槽号属于完整身份。 */
static bool separate_client_slots(void) {
    fixture_t f;
    CHECK(setup_capacity(&f, 2));
    fixture_t second = {
        .server = f.server, .peer = -1, .listener_fd = -1, .address = f.address
    };
    CHECK(add_client(&second));
    vireo_inflight_store_t *store = NULL;
    CHECK(create(3, &store));
    vireo_task_metadata_t a, b;
    CHECK(make(&f, 7, 400, 9, 0, &a) && make(&second, 7, 400, 10, 1, &b));
    CHECK(a.route.client_owner_id == b.route.client_owner_id &&
        a.route.client_slot_index != b.route.client_slot_index);
    CHECK(register_is(store, f.server, a, VIREO_OK, VIREO_INFLIGHT_NONE));
    CHECK(register_is(store, f.server, b, VIREO_OK, VIREO_INFLIGHT_NONE));
    CHECK(count_is(store, 2) && lookup_is(store, a, a, true));
    CHECK(lookup_is(store, b, b, true));
    CHECK(vireo_inflight_store_destroy(&store) == VIREO_OK);
    CHECK(release_client(&second));
    return cleanup(&f);
}

/** 最大容器上的有限扫描及数值边界，不是性能或负载验证。 */
static bool numeric_and_capacity_boundaries(void) {
    fixture_t f;
    CHECK(setup(&f));
    vireo_inflight_store_t *store = NULL;
    CHECK(create(VIREO_INFLIGHT_STORE_MAX_CAPACITY, &store));
    vireo_task_metadata_t a, b;
    CHECK(make(&f, UINT32_MAX, UINT64_MAX, UINT32_MAX, 0, &a));
    CHECK(make(&f, 1, 1, 1, UINT64_MAX, &b));
    CHECK(register_is(store, f.server, a, VIREO_OK, VIREO_INFLIGHT_NONE));
    CHECK(register_is(store, f.server, b, VIREO_OK, VIREO_INFLIGHT_NONE));
    CHECK(lookup_is(store, a, a, false) && lookup_is(store, b, b, false));
    CHECK(lookup_is(store, a, a, true) && lookup_is(store, b, b, true));
    CHECK(lookup_fails(store, a, VIREO_RESULT_NOT_FOUND, VIREO_INFLIGHT_CHECK_RECORD));
    CHECK(vireo_inflight_store_destroy(&store) == VIREO_OK);
    return cleanup(&f);
}

/** 数值登记不改变客户的收发/关闭/网络注册或资源预算。 */
static bool external_resources_unchanged(void) {
    fixture_t f;
    CHECK(setup(&f));
    vireo_inflight_store_t *store = NULL;
    CHECK(create(3, &store));
    vireo_tcp_server_info_t before, after;
    vireo_tcp_server_client_info_t client_before, client_after;
    CHECK(vireo_tcp_server_inspect(f.server, &before) == VIREO_OK);
    CHECK(vireo_tcp_server_client_inspect(f.server, f.client, &client_before) == VIREO_OK);
    vireo_task_metadata_t a, b;
    CHECK(make(&f, 7, 400, 9, 0, &a) && make(&f, 8, 401, 10, 1, &b));
    CHECK(register_is(store, f.server, a, VIREO_OK, VIREO_INFLIGHT_NONE));
    CHECK(register_is(store, f.server, b, VIREO_OK, VIREO_INFLIGHT_NONE));
    CHECK(register_is(store, f.server, a, VIREO_RESULT_BUSY, VIREO_INFLIGHT_CHECK_RECORD));
    CHECK(lookup_is(store, a, a, false));
    CHECK(lookup_is(store, a, a, true) && lookup_is(store, b, b, true));
    CHECK(vireo_tcp_server_inspect(f.server, &after) == VIREO_OK);
    CHECK(vireo_tcp_server_client_inspect(f.server, f.client, &client_after) == VIREO_OK);
    CHECK(before.connection_count == after.connection_count && before.registered_connections == after.registered_connections);
    CHECK(before.available_connections == after.available_connections && before.pending_clients == after.pending_clients);
    CHECK(before.allocation_bytes == after.allocation_bytes && before.buffer_capacity_bytes == after.buffer_capacity_bytes);
    CHECK(before.stop_requested == after.stop_requested && before.listener_owned == after.listener_owned);
    CHECK(client_before.queued == client_after.queued && client_before.pending_events == client_after.pending_events);
    CHECK(client_before.connection_info.close_state == client_after.connection_info.close_state);
    CHECK(client_before.connection_info.loop_interests == client_after.connection_info.loop_interests);
    CHECK(client_before.connection_info.read_buffer.readable_size == client_after.connection_info.read_buffer.readable_size);
    CHECK(client_before.connection_info.write_buffer.readable_size == client_after.connection_info.write_buffer.readable_size);
    CHECK(vireo_inflight_store_destroy(&store) == VIREO_OK);
    return cleanup(&f);
}

/** 测试调度值，不拥有产品资源。 */
typedef struct test_case {
    char const *name; /**< 静态名称，仅定位实际失败组。 */
    bool (*run)(void); /**< 同步执行并完成自身资源清理的组入口。 */
} test_case_t;

int main(void) {
    test_case_t const cases[] = {
        {"records_lifecycle", records_lifecycle}, {"original_snapshot", original_snapshot},
        {"full_and_sequence_reuse", full_and_sequence_reuse},
        {"active_conflicts_and_holes", active_conflicts_and_holes},
        {"basic_errors", basic_errors}, {"metadata_errors", metadata_errors},
        {"identity_errors", identity_errors}, {"closing_and_stop_order", closing_and_stop_order},
        {"stopped_open_client", stopped_open_client},
        {"historical_records_and_slot_reuse", historical_records_and_slot_reuse},
        {"separate_client_owners", separate_client_owners},
        {"separate_client_slots", separate_client_slots},
        {"numeric_and_capacity_boundaries", numeric_and_capacity_boundaries},
        {"external_resources_unchanged", external_resources_unchanged}
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
        if (!cases[i].run()) { fprintf(stderr, "FAIL %s\n", cases[i].name); return 1; }
        printf("PASS %s\n", cases[i].name);
    }
    printf("inflight records: %zu groups passed\n", sizeof cases / sizeof cases[0]);
    return 0;
}
