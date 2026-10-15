/*
 * PROJECT : VIREO
 * FILE    : test_inflight_store_client_limits.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-13
 * BRIEF   : 每客户历史计数、显式限额准入与真实名额保持
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

/** 限额调用核对真实总数/预算与阶段；失败保持登记数量。 */
static bool limited_is(vireo_inflight_store_t *store, vireo_tcp_server_t const *server,
    vireo_task_metadata_t metadata, size_t limit, vireo_result_t expected,
    vireo_inflight_stage_t detail) {
    vireo_inflight_store_info_t before, after;
    CHECK(vireo_inflight_store_inspect(store, &before) == VIREO_OK);
    vireo_inflight_stage_t stage = VIREO_INFLIGHT_MAKE_ROUTE;
    errno = E2BIG;
    CHECK(vireo_inflight_store_register_limited(store, server, metadata, limit, &stage) == expected);
    CHECK(errno == E2BIG && stage == detail);
    CHECK(vireo_inflight_store_inspect(store, &after) == VIREO_OK);
    CHECK(before.capacity == after.capacity && before.allocated_bytes == after.allocated_bytes &&
        before.max_memory_bytes == after.max_memory_bytes);
    CHECK(after.count == before.count + (expected == VIREO_OK ? 1U : 0U));
    if (expected != VIREO_OK) {
        errno = ERANGE;
        CHECK(vireo_inflight_store_register_limited(store, server, metadata, limit, NULL) == expected);
        CHECK(errno == ERANGE);
        CHECK(vireo_inflight_store_inspect(store, &after) == VIREO_OK && after.count == before.count);
    }
    return true;
}

/** 数值观测允许覆盖已有值；可空诊断与 errno 均核验。 */
static bool client_count_is(vireo_inflight_store_t const *store,
    vireo_connection_pool_lease_t client, size_t expected) {
    size_t out = SIZE_MAX;
    vireo_inflight_stage_t stage = VIREO_INFLIGHT_CHECK_CLIENT;
    errno = E2BIG;
    CHECK(vireo_inflight_store_count_client(store, client, &out, &stage) == VIREO_OK);
    CHECK(errno == E2BIG && stage == VIREO_INFLIGHT_NONE && out == expected);
    out = SIZE_MAX;
    errno = ERANGE;
    CHECK(vireo_inflight_store_count_client(store, client, &out, NULL) == VIREO_OK);
    CHECK(errno == ERANGE && out == expected);
    return true;
}

/** 失败计数输出按全部字节比较，记录数及固定申请账本不变。 */
static bool client_count_fails(vireo_inflight_store_t const *store,
    vireo_connection_pool_lease_t client, vireo_result_t expected) {
    vireo_inflight_store_info_t info_before = {0};
    if (store != NULL) CHECK(vireo_inflight_store_inspect(store, &info_before) == VIREO_OK);
    size_t out = SIZE_MAX;
    unsigned char before[sizeof out]; memcpy(before, &out, sizeof out);
    vireo_inflight_stage_t stage = VIREO_INFLIGHT_CHECK_RECORD;
    errno = ESPIPE;
    CHECK(vireo_inflight_store_count_client(store, client, &out, &stage) == expected);
    CHECK(errno == ESPIPE && stage == VIREO_INFLIGHT_NONE && memcmp(before, &out, sizeof out) == 0);
    errno = E2BIG;
    CHECK(vireo_inflight_store_count_client(store, client, &out, NULL) == expected);
    CHECK(errno == E2BIG && memcmp(before, &out, sizeof out) == 0);
    if (store != NULL) {
        vireo_inflight_store_info_t after;
        CHECK(vireo_inflight_store_inspect(store, &after) == VIREO_OK);
        CHECK(after.capacity == info_before.capacity && after.count == info_before.count &&
            after.allocated_bytes == info_before.allocated_bytes &&
            after.max_memory_bytes == info_before.max_memory_bytes);
    }
    return true;
}

/** 查询不退款；取出才退一条，成功按逻辑字段比原值。 */
static bool record_is(vireo_inflight_store_t *store, vireo_task_metadata_t metadata, bool take) {
    vireo_task_metadata_t out;
    vireo_inflight_stage_t stage = VIREO_INFLIGHT_CHECK_METADATA;
    errno = E2BIG;
    vireo_result_t const result = take ? vireo_inflight_store_take(store, metadata, &out, &stage) :
        vireo_inflight_store_get(store, metadata, &out, &stage);
    CHECK(result == VIREO_OK && errno == E2BIG && stage == VIREO_INFLIGHT_NONE);
    CHECK(same_value(out, metadata));
    return true;
}

static bool limit_and_refund(void) {
    fixture_t f;
    CHECK(setup(&f));
    vireo_inflight_store_t *store = NULL;
    CHECK(create(3, &store) && client_count_is(store, f.client, 0));
    vireo_task_metadata_t a, b, c;
    CHECK(make(&f, 7, 400, 9, 0, &a) && make(&f, 8, 401, 10, 1, &b));
    CHECK(make(&f, 9, 402, 11, UINT64_MAX, &c));
    CHECK(limited_is(store, f.server, a, 2, VIREO_OK, VIREO_INFLIGHT_NONE));
    CHECK(limited_is(store, f.server, b, 2, VIREO_OK, VIREO_INFLIGHT_NONE));
    CHECK(client_count_is(store, f.client, 2) && count_is(store, 2));
    CHECK(limited_is(store, f.server, c, 2, VIREO_RESULT_BUSY, VIREO_INFLIGHT_CHECK_RECORD));
    CHECK(record_is(store, a, false) && record_is(store, b, false));
    CHECK(client_count_is(store, f.client, 2));
    CHECK(record_is(store, a, true) && client_count_is(store, f.client, 1));
    CHECK(limited_is(store, f.server, c, 2, VIREO_OK, VIREO_INFLIGHT_NONE));
    CHECK(client_count_is(store, f.client, 2));
    CHECK(record_is(store, b, true) && record_is(store, c, true));
    CHECK(client_count_is(store, f.client, 0) && count_is(store, 0));
    CHECK(vireo_inflight_store_destroy(&store) == VIREO_OK);
    return cleanup(&f);
}

/** 限额是每调用参数，原入口不冻结策略，也不暗中改为客户上限。 */
static bool per_call_policy_and_original_register(void) {
    fixture_t f;
    CHECK(setup(&f));
    vireo_inflight_store_t *store = NULL;
    CHECK(create(3, &store));
    vireo_task_metadata_t a, b, c;
    CHECK(make(&f, 7, 400, 9, 0, &a) && make(&f, 8, 401, 9, 0, &b));
    CHECK(make(&f, 9, 402, 9, 0, &c));
    CHECK(limited_is(store, f.server, a, 1, VIREO_OK, VIREO_INFLIGHT_NONE));
    CHECK(limited_is(store, f.server, b, 1, VIREO_RESULT_BUSY, VIREO_INFLIGHT_CHECK_RECORD));
    errno = E2BIG;
    CHECK(vireo_inflight_store_register(store, f.server, b, NULL) == VIREO_OK && errno == E2BIG);
    CHECK(client_count_is(store, f.client, 2));
    CHECK(limited_is(store, f.server, c, 1, VIREO_RESULT_BUSY, VIREO_INFLIGHT_CHECK_RECORD));
    CHECK(limited_is(store, f.server, c, 2, VIREO_RESULT_BUSY, VIREO_INFLIGHT_CHECK_RECORD));
    errno = ERANGE;
    CHECK(vireo_inflight_store_register_limited(store, f.server, c, 3, NULL) == VIREO_OK);
    CHECK(errno == ERANGE && client_count_is(store, f.client, 3));
    CHECK(record_is(store, a, true) && record_is(store, b, true) && record_is(store, c, true));
    CHECK(vireo_inflight_store_destroy(&store) == VIREO_OK);
    return cleanup(&f);
}

static bool separate_client_slots(void) {
    fixture_t f;
    CHECK(setup_capacity(&f, 2));
    fixture_t second = {.server = f.server, .peer = -1, .listener_fd = -1, .address = f.address};
    CHECK(add_client(&second));
    vireo_inflight_store_t *store = NULL;
    CHECK(create(3, &store));
    vireo_task_metadata_t a, b, next;
    CHECK(make(&f, 7, 400, 9, 0, &a) && make(&second, 7, 400, 9, 0, &b));
    CHECK(a.route.client_slot_index != b.route.client_slot_index);
    CHECK(limited_is(store, f.server, a, 1, VIREO_OK, VIREO_INFLIGHT_NONE));
    CHECK(limited_is(store, f.server, b, 1, VIREO_OK, VIREO_INFLIGHT_NONE));
    CHECK(client_count_is(store, f.client, 1) && client_count_is(store, second.client, 1));
    CHECK(make(&f, 8, 401, 9, 0, &next));
    CHECK(limited_is(store, f.server, next, 1, VIREO_RESULT_BUSY, VIREO_INFLIGHT_CHECK_RECORD));
    CHECK(record_is(store, a, true) && client_count_is(store, second.client, 1));
    CHECK(record_is(store, b, true));
    CHECK(vireo_inflight_store_destroy(&store) == VIREO_OK);
    /* B 自身尚无登记，但 A 占满全表时 B 仍须被全表容量拒绝。 */
    CHECK(create(1, &store));
    CHECK(limited_is(store, f.server, a, 1, VIREO_OK, VIREO_INFLIGHT_NONE));
    CHECK(limited_is(store, f.server, b, 1, VIREO_RESULT_BUSY, VIREO_INFLIGHT_CHECK_RECORD));
    CHECK(client_count_is(store, f.client, 1) && client_count_is(store, second.client, 0));
    CHECK(record_is(store, a, true));
    CHECK(limited_is(store, f.server, b, 1, VIREO_OK, VIREO_INFLIGHT_NONE));
    CHECK(record_is(store, b, true) && vireo_inflight_store_destroy(&store) == VIREO_OK);
    CHECK(release_client(&second));
    return cleanup(&f);
}

static bool separate_client_owners(void) {
    fixture_t a, b;
    CHECK(setup(&a) && setup(&b));
    vireo_inflight_store_t *store = NULL;
    CHECK(create(3, &store));
    vireo_task_metadata_t left, right;
    CHECK(make(&a, 7, 400, 9, 0, &left) && make(&b, 7, 400, 9, 0, &right));
    CHECK(left.route.client_owner_id != right.route.client_owner_id);
    CHECK(limited_is(store, a.server, left, 1, VIREO_OK, VIREO_INFLIGHT_NONE));
    CHECK(limited_is(store, b.server, right, 1, VIREO_OK, VIREO_INFLIGHT_NONE));
    CHECK(client_count_is(store, a.client, 1) && client_count_is(store, b.client, 1));
    CHECK(record_is(store, left, true) && client_count_is(store, b.client, 1));
    CHECK(record_is(store, right, true) && vireo_inflight_store_destroy(&store) == VIREO_OK);
    CHECK(cleanup(&a));
    return cleanup(&b);
}

/** 新代与旧代各计一项；取出旧代不会退款给新代。 */
static bool slot_reuse_and_historical_count(void) {
    fixture_t f;
    CHECK(setup(&f));
    vireo_inflight_store_t *store = NULL;
    CHECK(create(3, &store));
    vireo_task_metadata_t old, current, next;
    vireo_connection_pool_lease_t const old_client = f.client;
    CHECK(make(&f, 7, 400, 9, 0, &old));
    CHECK(limited_is(store, f.server, old, 1, VIREO_OK, VIREO_INFLIGHT_NONE));
    CHECK(release_client(&f) && client_count_is(store, old_client, 1));
    CHECK(limited_is(store, f.server, old, 1, VIREO_RESULT_NOT_FOUND, VIREO_INFLIGHT_CHECK_CLIENT));
    CHECK(add_client(&f));
    CHECK(f.client.slot_index == old_client.slot_index && f.client.generation != old_client.generation);
    CHECK(client_count_is(store, f.client, 0));
    CHECK(make(&f, 7, 400, 9, 0, &current) && make(&f, 8, 401, 9, 0, &next));
    CHECK(limited_is(store, f.server, current, 1, VIREO_OK, VIREO_INFLIGHT_NONE));
    CHECK(client_count_is(store, old_client, 1) && client_count_is(store, f.client, 1));
    CHECK(limited_is(store, f.server, next, 1, VIREO_RESULT_BUSY, VIREO_INFLIGHT_CHECK_RECORD));
    CHECK(record_is(store, old, true) && client_count_is(store, old_client, 0));
    CHECK(client_count_is(store, f.client, 1));
    vireo_connection_pool_lease_t const current_client = f.client;
    CHECK(release_client(&f) && cleanup(&f));
    CHECK(client_count_is(store, current_client, 1) && record_is(store, current, true));
    CHECK(client_count_is(store, current_client, 0) && vireo_inflight_store_destroy(&store) == VIREO_OK);
    return true;
}

static bool closing_and_stopped(void) {
    fixture_t f;
    CHECK(setup(&f));
    vireo_inflight_store_t *store = NULL;
    CHECK(create(3, &store));
    vireo_task_metadata_t a, b;
    CHECK(make(&f, 7, 400, 9, 0, &a) && make(&f, 8, 401, 9, UINT64_MAX, &b));
    CHECK(limited_is(store, f.server, a, 1, VIREO_OK, VIREO_INFLIGHT_NONE));
    uint8_t const byte = 0x5a;
    CHECK(vireo_tcp_server_client_write_enqueue(f.server, f.client, &byte, 1, NULL) == VIREO_OK);
    CHECK(vireo_tcp_server_client_request_close(f.server, f.client, VIREO_CONNECTION_CLOSE_MODE_DRAIN,
        VIREO_CONNECTION_CLOSE_REASON_APPLICATION, NULL) == VIREO_OK);
    CHECK(limited_is(store, f.server, b, 1, VIREO_RESULT_BUSY, VIREO_INFLIGHT_CHECK_CLIENT));
    CHECK(client_count_is(store, f.client, 1));
    CHECK(vireo_tcp_server_client_request_close(f.server, f.client, VIREO_CONNECTION_CLOSE_MODE_IMMEDIATE,
        VIREO_CONNECTION_CLOSE_REASON_APPLICATION, NULL) == VIREO_OK);
    CHECK(limited_is(store, f.server, b, 1, VIREO_RESULT_BUSY, VIREO_INFLIGHT_CHECK_CLIENT));
    CHECK(vireo_tcp_server_request_stop(f.server, NULL) == VIREO_OK);
    CHECK(limited_is(store, f.server, b, 1, VIREO_RESULT_CANCELLED, VIREO_INFLIGHT_CHECK_SERVER));
    CHECK(client_count_is(store, f.client, 1) && record_is(store, a, true));
    CHECK(client_count_is(store, f.client, 0) && vireo_inflight_store_destroy(&store) == VIREO_OK);
    return cleanup(&f);
}

static bool limited_basic_and_range_priority(void) {
    fixture_t f;
    CHECK(setup(&f));
    vireo_inflight_store_t *store = NULL;
    CHECK(create(1, &store));
    vireo_task_metadata_t a;
    CHECK(make(&f, 7, 400, 9, 0, &a));
    vireo_inflight_stage_t stage = VIREO_INFLIGHT_CHECK_CLIENT;
    errno = E2BIG;
    CHECK(vireo_inflight_store_register_limited(NULL, f.server, a, 1, &stage) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(errno == E2BIG && stage == VIREO_INFLIGHT_NONE);
    CHECK(limited_is(store, NULL, a, 1, VIREO_RESULT_INVALID_ARGUMENT, VIREO_INFLIGHT_NONE));
    CHECK(limited_is(store, f.server, a, 0, VIREO_RESULT_INVALID_ARGUMENT, VIREO_INFLIGHT_NONE));
    CHECK(limited_is(store, f.server, (vireo_task_metadata_t){0}, 0,
        VIREO_RESULT_INVALID_ARGUMENT, VIREO_INFLIGHT_NONE));
    CHECK(limited_is(store, f.server, a, 2, VIREO_RESULT_RANGE, VIREO_INFLIGHT_CHECK_RECORD));
    CHECK(limited_is(store, f.server, a, SIZE_MAX, VIREO_RESULT_RANGE, VIREO_INFLIGHT_CHECK_RECORD));
    CHECK(limited_is(store, f.server, (vireo_task_metadata_t){0}, SIZE_MAX,
        VIREO_RESULT_INVALID_ARGUMENT, VIREO_INFLIGHT_CHECK_METADATA));
    CHECK(limited_is(store, f.server, a, 1, VIREO_OK, VIREO_INFLIGHT_NONE));
    CHECK(vireo_tcp_server_request_stop(f.server, NULL) == VIREO_OK);
    CHECK(limited_is(store, f.server, a, 2, VIREO_RESULT_RANGE, VIREO_INFLIGHT_CHECK_RECORD));
    CHECK(limited_is(store, f.other_server, a, 2, VIREO_RESULT_RANGE, VIREO_INFLIGHT_CHECK_RECORD));
    CHECK(record_is(store, a, true) && vireo_inflight_store_destroy(&store) == VIREO_OK);
    return cleanup(&f);
}

static bool count_shape_and_null_errors(void) {
    fixture_t f;
    CHECK(setup(&f));
    vireo_inflight_store_t *store = NULL;
    CHECK(create(1, &store));
    vireo_task_metadata_t metadata;
    CHECK(make(&f, 7, 400, 9, 0, &metadata));
    CHECK(limited_is(store, f.server, metadata, 1, VIREO_OK, VIREO_INFLIGHT_NONE));
    CHECK(client_count_fails(NULL, f.client, VIREO_RESULT_INVALID_ARGUMENT));
    vireo_inflight_stage_t stage = VIREO_INFLIGHT_CHECK_CLIENT;
    errno = E2BIG;
    CHECK(vireo_inflight_store_count_client(store, (vireo_connection_pool_lease_t){0}, NULL,
        &stage) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(errno == E2BIG && stage == VIREO_INFLIGHT_NONE);
    CHECK(client_count_fails(store, (vireo_connection_pool_lease_t){0}, VIREO_RESULT_NOT_FOUND));
    vireo_connection_pool_lease_t bad = f.client; bad.pool_id = 0;
    CHECK(client_count_fails(store, bad, VIREO_RESULT_INVALID_ARGUMENT));
    bad = f.client; bad.generation = 0;
    CHECK(client_count_fails(store, bad, VIREO_RESULT_INVALID_ARGUMENT));
    bad = (vireo_connection_pool_lease_t){0, 1, 0};
    CHECK(client_count_fails(store, bad, VIREO_RESULT_INVALID_ARGUMENT));
    CHECK(client_count_is(store, f.client, 1) && count_is(store, 1));
    CHECK(record_is(store, metadata, false) && record_is(store, metadata, true));
    CHECK(vireo_inflight_store_destroy(&store) == VIREO_OK);
    return cleanup(&f);
}

/** 数值计数不查客户容量；真实准入错误先于停止与客户限额。 */
static bool identity_and_metadata_priority(void) {
    fixture_t f;
    CHECK(setup(&f));
    vireo_inflight_store_t *store = NULL;
    CHECK(create(1, &store));
    vireo_task_metadata_t a;
    CHECK(make(&f, 7, 400, 9, 0, &a));
    CHECK(limited_is(store, f.server, a, 1, VIREO_OK, VIREO_INFLIGHT_NONE));
    CHECK(vireo_tcp_server_request_stop(f.server, NULL) == VIREO_OK);
    CHECK(limited_is(store, f.server, a, 1, VIREO_RESULT_CANCELLED, VIREO_INFLIGHT_CHECK_SERVER));
    CHECK(limited_is(store, f.other_server, a, 1, VIREO_RESULT_INVALID_ARGUMENT, VIREO_INFLIGHT_CHECK_CLIENT));
    vireo_task_metadata_t bad = a; bad.route.client_slot_index = SIZE_MAX;
    CHECK(limited_is(store, f.server, bad, 1, VIREO_RESULT_RANGE, VIREO_INFLIGHT_CHECK_CLIENT));
    CHECK(client_count_is(store, (vireo_connection_pool_lease_t){f.client.pool_id, SIZE_MAX, f.client.generation}, 0));
    bad = a; ++bad.route.client_generation;
    CHECK(limited_is(store, f.server, bad, 1, VIREO_RESULT_NOT_FOUND, VIREO_INFLIGHT_CHECK_CLIENT));
    vireo_task_metadata_t invalid[6];
    for (size_t i = 0; i < 6; ++i) invalid[i] = a;
    invalid[0] = (vireo_task_metadata_t){0}; invalid[1].route.client_owner_id = 0;
    invalid[2].route.client_generation = 0; invalid[3].route.request_sequence = 0;
    invalid[4].request_instance_id = 0; invalid[5].operation = 0;
    for (size_t i = 0; i < 6; ++i)
        CHECK(limited_is(store, f.server, invalid[i], SIZE_MAX, VIREO_RESULT_INVALID_ARGUMENT,
            VIREO_INFLIGHT_CHECK_METADATA));
    CHECK(client_count_is(store, f.client, 1) && record_is(store, a, true));
    CHECK(vireo_inflight_store_destroy(&store) == VIREO_OK);
    return cleanup(&f);
}

static bool conflicts_and_full_table(void) {
    fixture_t f;
    CHECK(setup(&f));
    vireo_inflight_store_t *store = NULL;
    CHECK(create(3, &store));
    vireo_task_metadata_t a, b, c;
    CHECK(make(&f, 7, 400, 9, 0, &a) && make(&f, 8, 401, 9, 0, &b));
    CHECK(make(&f, 9, 402, 9, 0, &c));
    CHECK(limited_is(store, f.server, a, 3, VIREO_OK, VIREO_INFLIGHT_NONE));
    CHECK(limited_is(store, f.server, b, 3, VIREO_OK, VIREO_INFLIGHT_NONE));
    CHECK(record_is(store, a, true));
    vireo_task_metadata_t conflict = b; conflict.request_instance_id = 403;
    CHECK(limited_is(store, f.server, conflict, 3, VIREO_RESULT_BUSY, VIREO_INFLIGHT_CHECK_RECORD));
    conflict = b; conflict.route.request_sequence = 10;
    CHECK(limited_is(store, f.server, conflict, 3, VIREO_RESULT_BUSY, VIREO_INFLIGHT_CHECK_RECORD));
    CHECK(record_is(store, b, false) && client_count_is(store, f.client, 1));
    CHECK(limited_is(store, f.server, c, 3, VIREO_OK, VIREO_INFLIGHT_NONE));
    a.request_instance_id = 404;
    CHECK(limited_is(store, f.server, a, 3, VIREO_OK, VIREO_INFLIGHT_NONE));
    vireo_task_metadata_t next;
    CHECK(make(&f, 10, 405, 9, 0, &next));
    CHECK(limited_is(store, f.server, next, 3, VIREO_RESULT_BUSY, VIREO_INFLIGHT_CHECK_RECORD));
    CHECK(client_count_is(store, f.client, 3));
    CHECK(record_is(store, a, true) && record_is(store, b, true) && record_is(store, c, true));
    CHECK(vireo_inflight_store_destroy(&store) == VIREO_OK);
    return cleanup(&f);
}

static bool finite_numbers_and_capacity(void) {
    fixture_t f;
    CHECK(setup(&f));
    vireo_inflight_store_t *store = NULL;
    CHECK(create(VIREO_INFLIGHT_STORE_MAX_CAPACITY, &store));
    CHECK(client_count_is(store, (vireo_connection_pool_lease_t){UINT64_MAX, SIZE_MAX, UINT64_MAX}, 0));
    vireo_task_metadata_t a, b;
    CHECK(make(&f, UINT32_MAX, UINT64_MAX, UINT32_MAX, 0, &a));
    CHECK(make(&f, 1, 1, 1, UINT64_MAX, &b));
    CHECK(limited_is(store, f.server, a, VIREO_INFLIGHT_STORE_MAX_CAPACITY, VIREO_OK, VIREO_INFLIGHT_NONE));
    CHECK(limited_is(store, f.server, b, VIREO_INFLIGHT_STORE_MAX_CAPACITY, VIREO_OK, VIREO_INFLIGHT_NONE));
    CHECK(client_count_is(store, f.client, 2));
    CHECK(record_is(store, a, true) && record_is(store, b, true));
    CHECK(vireo_inflight_store_destroy(&store) == VIREO_OK);
    return cleanup(&f);
}

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
    CHECK(make(&f, 7, 400, 9, 0, &a) && make(&f, 8, 401, 9, 0, &b));
    CHECK(limited_is(store, f.server, a, 1, VIREO_OK, VIREO_INFLIGHT_NONE));
    CHECK(limited_is(store, f.server, b, 1, VIREO_RESULT_BUSY, VIREO_INFLIGHT_CHECK_RECORD));
    CHECK(client_count_is(store, f.client, 1) && record_is(store, a, true));
    CHECK(client_count_is(store, f.client, 0));
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

/** 测试调度纯值，不拥有产品资源。 */
typedef struct test_case {
    char const *name; /**< 静态组名，仅成功输出和失败定位。 */
    bool (*run)(void); /**< 同步组入口，完成自身公开资源清理。 */
} test_case_t;

int main(void) {
    test_case_t const cases[] = {
        {"limit_and_refund", limit_and_refund},
        {"per_call_policy_and_original_register", per_call_policy_and_original_register},
        {"separate_client_slots", separate_client_slots}, {"separate_client_owners", separate_client_owners},
        {"slot_reuse_and_historical_count", slot_reuse_and_historical_count},
        {"closing_and_stopped", closing_and_stopped},
        {"limited_basic_and_range_priority", limited_basic_and_range_priority},
        {"count_shape_and_null_errors", count_shape_and_null_errors},
        {"identity_and_metadata_priority", identity_and_metadata_priority},
        {"conflicts_and_full_table", conflicts_and_full_table},
        {"finite_numbers_and_capacity", finite_numbers_and_capacity},
        {"external_resources_unchanged", external_resources_unchanged}
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
        if (!cases[i].run()) { fprintf(stderr, "FAIL %s\n", cases[i].name); return 1; }
        printf("PASS %s\n", cases[i].name);
    }
    printf("inflight client limits: %zu groups passed\n", sizeof cases / sizeof cases[0]);
    return 0;
}
