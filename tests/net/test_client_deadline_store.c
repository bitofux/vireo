/*
 * PROJECT : VIREO
 * FILE    : test_client_deadline_store.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-10
 * BRIEF   : 此模块负责：
 * -- 验证固定容量数值记录保存、按完整身份查询及显式转出
 * -- 只依赖已采用公开合同，保持资源、输出与 errno 的既有边界
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vireo/net/timer_loop_dispatch.h>
#include <vireo/timer/wheel_shutdown.h>
#include "net/client_deadline_store_internal.h"

#define CHECK(expr)                                                    \
    do {                                                               \
        if (!(expr)) {                                                 \
            fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #expr); \
            return false;                                              \
        }                                                              \
    } while (0)

/** 本项真实 TCP 与公开资源 fixture；只借本层 own private 申请测试入口。 */
typedef struct fixture {
    vireo_tcp_server_t *server;       /**< 拥有两个当前客户及 listener。 */
    vireo_tcp_server_t *other_server; /**< 独立空 pool，用于跨所属拒绝。 */
    vireo_timer_wheel_t *wheel;       /**< 拥有本轮，通常容量二，复用测试改一。 */
    vireo_timer_wheel_t *other_wheel; /**< 独立 owner，容量二。 */
    vireo_timer_wheel_t *unprepared;  /**< 独立未准备轮。 */
    vireo_client_deadline_store_t *store;     /**< 本表唯一 owner，通常容量三。 */
    vireo_connection_pool_lease_t clients[2]; /**< 当前两个客户，归还后清零。 */
    int peers[2]; /**< 各客户的 caller TCP 对端 fd，-1 为空。 */
    vireo_client_deadline_binding_t
        bindings[4]; /**< 前二属 wheel、后二属 other_wheel；记录或历史值。 */
    int listener_fd; /**< 构造期原 socket owner，转移后 -1。 */
    vireo_acceptor_t *listener; /**< 构造期 owner，server 收纳后 NULL。 */
    struct sockaddr_in address; /**< loopback 临时端点，复用客户时再连接。 */
} fixture_t;

static bool add_client(fixture_t *f, size_t i) {
    f->peers[i] = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    CHECK(f->peers[i] >= 0);
    CHECK(connect(f->peers[i], (struct sockaddr const *)&f->address, sizeof f->address) == 0);
    vireo_connection_options_t const options = {64, 64, 128};
    vireo_tcp_server_admit_budget_t const budget = {1, 1};
    vireo_tcp_server_admit_info_t info;
    CHECK(vireo_tcp_server_admit_batch(f->server, &options, &budget, &f->clients[i], 1, &info,
                                       NULL) == VIREO_OK);
    CHECK(info.admitted_count == 1 && info.accepted_count == 1);
    return true;
}

static bool setup(fixture_t *f) {
    memset(f, 0, sizeof *f);
    f->peers[0] = -1;
    f->peers[1] = -1;
    f->listener_fd = -1;
    vireo_tcp_server_options_t const options = {2, 3, VIREO_TCP_SERVER_MAX_MEMORY, 256};
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
    CHECK(vireo_acceptor_create(&listener_options, &f->listener_fd, &f->listener, NULL) ==
          VIREO_OK);
    CHECK(vireo_tcp_server_adopt_listener(f->server, &f->listener, NULL) == VIREO_OK);
    CHECK(add_client(f, 0) && add_client(f, 1));
    vireo_timer_wheel_options_t const wheel_options = {{100, 10, 4}, VIREO_TIMER_WHEEL_MAX_MEMORY};
    vireo_timer_wheel_registry_options_t const registry = {2,
                                                           VIREO_TIMER_WHEEL_REGISTRY_MAX_MEMORY};
    CHECK(vireo_timer_wheel_create(&wheel_options, &f->wheel) == VIREO_OK);
    CHECK(vireo_timer_wheel_create(&wheel_options, &f->other_wheel) == VIREO_OK);
    CHECK(vireo_timer_wheel_create(&wheel_options, &f->unprepared) == VIREO_OK);
    CHECK(vireo_timer_wheel_prepare(f->wheel, &registry) == VIREO_OK);
    CHECK(vireo_timer_wheel_prepare(f->other_wheel, &registry) == VIREO_OK);
    vireo_client_deadline_store_options_t const store_options = {
        3, VIREO_CLIENT_DEADLINE_STORE_MAX_MEMORY};
    CHECK(vireo_client_deadline_store_create(&store_options, &f->store) == VIREO_OK);
    return true;
}

static bool cleanup(fixture_t *f) {
    for (size_t i = 0; i < 4; ++i) {
        if (f->bindings[i].timer.owner_id != 0) {
            vireo_client_deadline_binding_t record;
            if (f->store != NULL) {
                vireo_result_t const r =
                    vireo_client_deadline_store_withdraw(f->store, f->bindings[i].timer, &record);
                CHECK(r == VIREO_OK || r == VIREO_RESULT_NOT_FOUND);
            }
            vireo_timer_wheel_t *wheel = i < 2 ? f->wheel : f->other_wheel;
            vireo_result_t const r = vireo_client_deadline_cancel(wheel, &f->bindings[i], NULL);
            CHECK(r == VIREO_OK || r == VIREO_RESULT_NOT_FOUND);
        }
    }
    CHECK(vireo_client_deadline_store_destroy(&f->store) == VIREO_OK);
    CHECK(vireo_timer_wheel_destroy(&f->wheel) == VIREO_OK);
    CHECK(vireo_timer_wheel_destroy(&f->other_wheel) == VIREO_OK);
    CHECK(vireo_timer_wheel_destroy(&f->unprepared) == VIREO_OK);
    for (size_t i = 0; i < 2; ++i) {
        if (f->clients[i].pool_id != 0)
            CHECK(vireo_tcp_server_release_client(f->server, &f->clients[i], NULL) == VIREO_OK);
        if (f->peers[i] >= 0) {
            CHECK(close(f->peers[i]) == 0);
            f->peers[i] = -1;
        }
    }
    if (f->listener_fd >= 0)
        CHECK(close(f->listener_fd) == 0);
    CHECK(vireo_acceptor_destroy(&f->listener, NULL) == VIREO_OK);
    CHECK(vireo_tcp_server_destroy(&f->server, NULL) == VIREO_OK);
    CHECK(vireo_tcp_server_destroy(&f->other_server, NULL) == VIREO_OK);
    return true;
}

static bool same_timer(vireo_timer_handle_t a, vireo_timer_handle_t b) {
    return a.owner_id == b.owner_id && a.slot_index == b.slot_index && a.generation == b.generation;
}
static bool same_binding(vireo_client_deadline_binding_t a, vireo_client_deadline_binding_t b) {
    return same_timer(a.timer, b.timer) && a.client.pool_id == b.client.pool_id &&
           a.client.slot_index == b.client.slot_index && a.client.generation == b.client.generation;
}
static bool count_is(fixture_t *f, size_t count) {
    vireo_client_deadline_store_info_t info;
    errno = EDOM;
    CHECK(vireo_client_deadline_store_inspect(f->store, &info) == VIREO_OK && errno == EDOM);
    CHECK(info.count == count && info.count <= info.capacity &&
          info.allocation_bytes <= info.max_memory_bytes);
    return true;
}
static bool replace_store(fixture_t *f, size_t capacity) {
    CHECK(vireo_client_deadline_store_destroy(&f->store) == VIREO_OK);
    vireo_client_deadline_store_options_t const options = {capacity,
                                                           VIREO_CLIENT_DEADLINE_STORE_MAX_MEMORY};
    CHECK(vireo_client_deadline_store_create(&options, &f->store) == VIREO_OK);
    return true;
}
static bool register_at(fixture_t *f, size_t index, size_t client, vireo_monotonic_ns_t now,
                        vireo_monotonic_ns_t deadline) {
    vireo_timer_wheel_t *wheel = index < 2 ? f->wheel : f->other_wheel;
    errno = EDOM;
    CHECK(vireo_client_deadline_register(f->server, wheel, f->clients[client], now, deadline,
                                         &f->bindings[index], NULL) == VIREO_OK);
    CHECK(errno == EDOM);
    return true;
}
static bool save_at(fixture_t *f, size_t index) {
    vireo_client_deadline_stage_t stage = VIREO_CLIENT_DEADLINE_MATCH_TIMER;
    errno = EDOM;
    CHECK(vireo_client_deadline_store_save(f->store, f->server,
                                           index < 2 ? f->wheel : f->other_wheel,
                                           f->bindings[index], &stage) == VIREO_OK);
    CHECK(stage == VIREO_CLIENT_DEADLINE_NONE && errno == EDOM);
    vireo_client_deadline_binding_t found;
    CHECK(vireo_client_deadline_store_find(f->store, f->bindings[index].timer, &found) == VIREO_OK);
    CHECK(same_binding(found, f->bindings[index]));
    return true;
}
static bool advance_to(vireo_timer_wheel_t *wheel, vireo_monotonic_ns_t now) {
    vireo_timer_wheel_advance_report_t report;
    CHECK(vireo_timer_wheel_advance(wheel, now, (vireo_timer_wheel_advance_budget_t){16, 16},
                                    &report) == VIREO_OK);
    CHECK(report.progress.caught_up);
    return true;
}

/** 失败时验证本表完整申请字节及外部轮公开登记状态均保持。 */
static bool save_fails(fixture_t *f, vireo_client_deadline_store_t *store,
                       vireo_tcp_server_t const *server, vireo_timer_wheel_t const *wheel,
                       vireo_client_deadline_binding_t binding, vireo_result_t expected,
                       vireo_client_deadline_stage_t expected_stage) {
    vireo_client_deadline_store_info_t info;
    CHECK(vireo_client_deadline_store_inspect(f->store, &info) == VIREO_OK);
    unsigned char *bytes = malloc(info.allocation_bytes);
    CHECK(bytes != NULL);
    memcpy(bytes, f->store, info.allocation_bytes);
    vireo_timer_wheel_registry_info_t before = {0}, after = {0};
    if (wheel != NULL)
        CHECK(vireo_timer_wheel_registry_inspect(wheel, &before) == VIREO_OK);
    vireo_client_deadline_stage_t stage = VIREO_CLIENT_DEADLINE_CANCEL_TIMER;
    errno = ENOSPC;
    vireo_result_t const r =
        vireo_client_deadline_store_save(store, server, wheel, binding, &stage);
    bool const preserved = memcmp(bytes, f->store, info.allocation_bytes) == 0;
    free(bytes);
    CHECK(r == expected && stage == expected_stage && errno == ENOSPC && preserved);
    if (wheel != NULL) {
        CHECK(vireo_timer_wheel_registry_inspect(wheel, &after) == VIREO_OK);
        CHECK(before.prepared == after.prepared && before.capacity == after.capacity &&
              before.active_count == after.active_count &&
              before.available_count == after.available_count &&
              before.allocation_bytes == after.allocation_bytes &&
              before.max_memory_bytes == after.max_memory_bytes);
    }
    errno = ERANGE;
    CHECK(vireo_client_deadline_store_save(store, server, wheel, binding, NULL) == expected &&
          errno == ERANGE);
    return true;
}

/** 三个数值取出入口共用失败断言，整输出字节及表保持。 */
static bool query_fails(fixture_t *f, vireo_timer_handle_t key, vireo_result_t expected) {
    vireo_client_deadline_binding_t out;
    unsigned char bytes[sizeof out];
    memset(&out, 0xa5, sizeof out);
    memcpy(bytes, &out, sizeof bytes);
    vireo_client_deadline_store_info_t before, after;
    CHECK(vireo_client_deadline_store_inspect(f->store, &before) == VIREO_OK);
    errno = EDOM;
    CHECK(vireo_client_deadline_store_find(f->store, key, &out) == expected && errno == EDOM);
    CHECK(memcmp(bytes, &out, sizeof bytes) == 0);
    CHECK(vireo_client_deadline_store_withdraw(f->store, key, &out) == expected && errno == EDOM);
    CHECK(memcmp(bytes, &out, sizeof bytes) == 0);
    vireo_timer_wheel_expired_t const invalid_or_missing = {key, {0}};
    CHECK(vireo_client_deadline_store_take_expired(f->store, &invalid_or_missing, &out) ==
              expected &&
          errno == EDOM);
    CHECK(memcmp(bytes, &out, sizeof bytes) == 0);
    CHECK(vireo_client_deadline_store_inspect(f->store, &after) == VIREO_OK);
    CHECK(before.count == after.count && before.capacity == after.capacity &&
          before.allocation_bytes == after.allocation_bytes &&
          before.max_memory_bytes == after.max_memory_bytes);
    return true;
}

static bool test_resource_contract(fixture_t *f) {
    vireo_client_deadline_store_t *owner = NULL;
    vireo_client_deadline_store_options_t options = {1, VIREO_CLIENT_DEADLINE_STORE_MAX_MEMORY};
    errno = EDOM;
    CHECK(vireo_client_deadline_store_create(NULL, &owner) == VIREO_RESULT_INVALID_ARGUMENT &&
          owner == NULL);
    CHECK(vireo_client_deadline_store_create(&options, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_client_deadline_store_create(&options, &f->store) == VIREO_RESULT_INVALID_ARGUMENT);
    options.capacity = 0;
    CHECK(vireo_client_deadline_store_create(&options, &owner) == VIREO_RESULT_INVALID_ARGUMENT);
    options.capacity = 1;
    options.max_memory_bytes = 0;
    CHECK(vireo_client_deadline_store_create(&options, &owner) == VIREO_RESULT_INVALID_ARGUMENT);
    options.capacity = SIZE_MAX;
    options.max_memory_bytes = VIREO_CLIENT_DEADLINE_STORE_MAX_MEMORY;
    CHECK(vireo_client_deadline_store_create(&options, &owner) == VIREO_RESULT_OVERFLOW &&
          owner == NULL);
    options.capacity = SIZE_MAX / sizeof(vireo_client_deadline_binding_t);
    CHECK(vireo_client_deadline_store_create(&options, &owner) == VIREO_RESULT_OVERFLOW &&
          owner == NULL);
    options.capacity = VIREO_CLIENT_DEADLINE_STORE_MAX_CAPACITY + 1;
    CHECK(vireo_client_deadline_store_create(&options, &owner) == VIREO_RESULT_RANGE &&
          owner == NULL);
    options.capacity = 1;
    options.max_memory_bytes = VIREO_CLIENT_DEADLINE_STORE_MAX_MEMORY + 1;
    CHECK(vireo_client_deadline_store_create(&options, &owner) == VIREO_RESULT_RANGE &&
          owner == NULL);
    options.max_memory_bytes = 1;
    CHECK(vireo_client_deadline_store_create(&options, &owner) == VIREO_RESULT_RANGE &&
          owner == NULL && errno == EDOM);
    CHECK(vireo_client_deadline_store_destroy(NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_client_deadline_store_destroy(&owner) == VIREO_OK && errno == EDOM);
    vireo_client_deadline_store_info_t info, copy;
    memset(&info, 0xa5, sizeof info);
    memcpy(&copy, &info, sizeof info);
    CHECK(vireo_client_deadline_store_inspect(NULL, &info) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(memcmp(&info, &copy, sizeof info) == 0);
    CHECK(vireo_client_deadline_store_inspect(f->store, NULL) == VIREO_RESULT_INVALID_ARGUMENT &&
          errno == EDOM);
    return true;
}

static bool test_exact_budget(fixture_t *f) {
    vireo_client_deadline_store_info_t info;
    CHECK(vireo_client_deadline_store_inspect(f->store, &info) == VIREO_OK);
    size_t const actual = info.allocation_bytes;
    CHECK(vireo_client_deadline_store_destroy(&f->store) == VIREO_OK);
    vireo_client_deadline_store_options_t options = {3, actual - 1};
    CHECK(vireo_client_deadline_store_create(&options, &f->store) == VIREO_RESULT_RANGE &&
          f->store == NULL);
    options.max_memory_bytes = actual;
    errno = EILSEQ;
    CHECK(vireo_client_deadline_store_create(&options, &f->store) == VIREO_OK && errno == EILSEQ);
    CHECK(vireo_client_deadline_store_inspect(f->store, &info) == VIREO_OK);
    CHECK(info.allocation_bytes == actual && info.max_memory_bytes == actual);
    return true;
}

static bool test_max_capacity(fixture_t *f) {
    CHECK(replace_store(f, VIREO_CLIENT_DEADLINE_STORE_MAX_CAPACITY));
    CHECK(count_is(f, 0));
    CHECK(query_fails(f, (vireo_timer_handle_t){UINT64_MAX, SIZE_MAX, UINT64_MAX},
                      VIREO_RESULT_NOT_FOUND));
    CHECK(register_at(f, 0, 0, 100, 110) && save_at(f, 0) && count_is(f, 1));
    return true;
}

/** 单点申请探针；成功内存仍由标准 malloc/free 管理。 */
typedef struct allocation_probe {
    size_t calls; /**< 本层真实申请调用数。 */
    size_t bytes; /**< 最近请求字节，不是 RSS。 */
    bool fail;    /**< 本次是否模拟 NULL 申请结果。 */
} allocation_probe_t;
static void *probe_allocate(size_t bytes, void *context) {
    allocation_probe_t *p = context;
    ++p->calls;
    p->bytes = bytes;
    errno = ENOMEM;
    return p->fail ? NULL : malloc(bytes);
}
static bool test_allocation_failure(fixture_t *f) {
    (void)f;
    allocation_probe_t probe = {0, 0, true};
    vireo_client_deadline_store_t *owner = NULL;
    vireo_client_deadline_store_options_t options = {2, VIREO_CLIENT_DEADLINE_STORE_MAX_MEMORY};
    errno = EILSEQ;
    CHECK(vireo_client_deadline_store_create_runtime(&options, &owner, NULL, &probe) ==
          VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(probe.calls == 0 && owner == NULL);
    options.max_memory_bytes = 1;
    CHECK(vireo_client_deadline_store_create_runtime(&options, &owner, probe_allocate, &probe) ==
          VIREO_RESULT_RANGE);
    CHECK(probe.calls == 0 && owner == NULL && errno == EILSEQ);
    options.max_memory_bytes = VIREO_CLIENT_DEADLINE_STORE_MAX_MEMORY;
    CHECK(vireo_client_deadline_store_create_runtime(&options, &owner, probe_allocate, &probe) ==
          VIREO_RESULT_NO_MEMORY);
    CHECK(probe.calls == 1 && probe.bytes > 0 && owner == NULL && errno == EILSEQ);
    probe.fail = false;
    CHECK(vireo_client_deadline_store_create_runtime(&options, &owner, probe_allocate, &probe) ==
          VIREO_OK);
    vireo_client_deadline_store_info_t info;
    CHECK(vireo_client_deadline_store_inspect(owner, &info) == VIREO_OK);
    CHECK(probe.calls == 2 && probe.bytes == info.allocation_bytes && info.count == 0 &&
          errno == EILSEQ);
    CHECK(vireo_client_deadline_store_destroy(&owner) == VIREO_OK && owner == NULL &&
          errno == EILSEQ);
    return true;
}

static bool test_two_clients(fixture_t *f) {
    CHECK(register_at(f, 0, 0, 100, 110) && register_at(f, 1, 1, 100, 120));
    CHECK(save_at(f, 0) && save_at(f, 1) && count_is(f, 2));
    CHECK(f->clients[0].slot_index != f->clients[1].slot_index);
    vireo_client_deadline_binding_t out;
    errno = EDOM;
    CHECK(vireo_client_deadline_store_withdraw(f->store, f->bindings[0].timer, &out) == VIREO_OK &&
          errno == EDOM);
    CHECK(same_binding(out, f->bindings[0]) && count_is(f, 1));
    CHECK(save_at(f, 0) && count_is(f, 2));
    return true;
}

static bool test_same_client_multiple(fixture_t *f) {
    CHECK(register_at(f, 0, 0, 100, 110) && register_at(f, 1, 0, 100, 120));
    CHECK(save_at(f, 0));
    errno = EILSEQ;
    CHECK(vireo_client_deadline_store_save(f->store, f->server, f->wheel, f->bindings[1], NULL) ==
              VIREO_OK &&
          errno == EILSEQ);
    CHECK(count_is(f, 2));
    CHECK(!same_timer(f->bindings[0].timer, f->bindings[1].timer));
    return true;
}

static bool test_save_shapes(fixture_t *f) {
    CHECK(register_at(f, 0, 0, 100, 110));
    vireo_client_deadline_binding_t b = f->bindings[0];
    CHECK(save_fails(f, NULL, f->server, f->wheel, b, VIREO_RESULT_INVALID_ARGUMENT,
                     VIREO_CLIENT_DEADLINE_NONE));
    CHECK(save_fails(f, f->store, NULL, f->wheel, b, VIREO_RESULT_INVALID_ARGUMENT,
                     VIREO_CLIENT_DEADLINE_NONE));
    CHECK(save_fails(f, f->store, f->server, NULL, b, VIREO_RESULT_INVALID_ARGUMENT,
                     VIREO_CLIENT_DEADLINE_NONE));
    b = (vireo_client_deadline_binding_t){0};
    CHECK(save_fails(f, f->store, f->server, f->wheel, b, VIREO_RESULT_NOT_FOUND,
                     VIREO_CLIENT_DEADLINE_NONE));
    b = f->bindings[0];
    b.client = (vireo_connection_pool_lease_t){0};
    CHECK(save_fails(f, f->store, f->server, f->wheel, b, VIREO_RESULT_INVALID_ARGUMENT,
                     VIREO_CLIENT_DEADLINE_NONE));
    b = f->bindings[0];
    b.timer = (vireo_timer_handle_t){0};
    CHECK(save_fails(f, f->store, f->server, f->wheel, b, VIREO_RESULT_INVALID_ARGUMENT,
                     VIREO_CLIENT_DEADLINE_NONE));
    b = f->bindings[0];
    b.client.pool_id = 0;
    CHECK(save_fails(f, f->store, f->server, f->wheel, b, VIREO_RESULT_INVALID_ARGUMENT,
                     VIREO_CLIENT_DEADLINE_NONE));
    b = f->bindings[0];
    b.client.generation = 0;
    CHECK(save_fails(f, f->store, f->server, f->wheel, b, VIREO_RESULT_INVALID_ARGUMENT,
                     VIREO_CLIENT_DEADLINE_NONE));
    b = f->bindings[0];
    b.timer.owner_id = 0;
    CHECK(save_fails(f, f->store, f->server, f->wheel, b, VIREO_RESULT_INVALID_ARGUMENT,
                     VIREO_CLIENT_DEADLINE_NONE));
    b = f->bindings[0];
    b.timer.generation = 0;
    CHECK(save_fails(f, f->store, f->server, f->wheel, b, VIREO_RESULT_INVALID_ARGUMENT,
                     VIREO_CLIENT_DEADLINE_NONE));
    return true;
}

static bool test_duplicate_priority(fixture_t *f) {
    CHECK(register_at(f, 0, 0, 100, 110) && save_at(f, 0));
    vireo_client_deadline_binding_t b = f->bindings[0];
    b.client = f->clients[1];
    CHECK(save_fails(f, f->store, f->server, f->wheel, b, VIREO_RESULT_BUSY,
                     VIREO_CLIENT_DEADLINE_NONE));
    CHECK(save_fails(f, f->store, f->other_server, f->unprepared, b, VIREO_RESULT_BUSY,
                     VIREO_CLIENT_DEADLINE_NONE));
    vireo_client_deadline_binding_t found;
    CHECK(vireo_client_deadline_store_find(f->store, f->bindings[0].timer, &found) == VIREO_OK);
    CHECK(same_binding(found, f->bindings[0]) && count_is(f, 1));
    return true;
}

static bool test_full_table_recovery(fixture_t *f) {
    CHECK(replace_store(f, 1));
    CHECK(register_at(f, 0, 0, 100, 110) && register_at(f, 1, 1, 100, 120) && save_at(f, 0));
    unsigned char before[sizeof f->bindings[1]];
    memcpy(before, &f->bindings[1], sizeof before);
    CHECK(save_fails(f, f->store, f->other_server, f->unprepared, f->bindings[1], VIREO_RESULT_BUSY,
                     VIREO_CLIENT_DEADLINE_NONE));
    CHECK(memcmp(before, &f->bindings[1], sizeof before) == 0);
    vireo_timer_wheel_timer_info_t timer;
    CHECK(vireo_timer_wheel_get(f->wheel, f->bindings[1].timer, &timer) == VIREO_OK);
    CHECK(vireo_client_deadline_cancel(f->wheel, &f->bindings[1], NULL) == VIREO_OK);
    CHECK(count_is(f, 1));
    vireo_client_deadline_binding_t out;
    CHECK(vireo_client_deadline_store_withdraw(f->store, f->bindings[0].timer, &out) == VIREO_OK);
    CHECK(vireo_client_deadline_cancel(f->wheel, &out, NULL) == VIREO_OK && count_is(f, 0));
    f->bindings[0] = (vireo_client_deadline_binding_t){0};
    CHECK(register_at(f, 1, 1, 100, 120) && save_at(f, 1));
    return true;
}

static bool test_client_dependencies(fixture_t *f) {
    CHECK(register_at(f, 0, 0, 100, 110));
    CHECK(save_fails(f, f->store, f->other_server, f->wheel, f->bindings[0],
                     VIREO_RESULT_INVALID_ARGUMENT, VIREO_CLIENT_DEADLINE_CHECK_CLIENT));
    vireo_client_deadline_binding_t b = f->bindings[0];
    b.client.slot_index = SIZE_MAX;
    CHECK(save_fails(f, f->store, f->server, f->wheel, b, VIREO_RESULT_RANGE,
                     VIREO_CLIENT_DEADLINE_CHECK_CLIENT));
    CHECK(vireo_tcp_server_release_client(f->server, &f->clients[0], NULL) == VIREO_OK);
    CHECK(close(f->peers[0]) == 0);
    f->peers[0] = -1;
    CHECK(add_client(f, 0));
    CHECK(f->clients[0].slot_index == f->bindings[0].client.slot_index &&
          f->clients[0].generation != f->bindings[0].client.generation);
    CHECK(save_fails(f, f->store, f->server, f->unprepared, f->bindings[0], VIREO_RESULT_NOT_FOUND,
                     VIREO_CLIENT_DEADLINE_CHECK_CLIENT));
    return true;
}

static bool test_timer_dependencies(fixture_t *f) {
    CHECK(register_at(f, 0, 0, 100, 110));
    CHECK(save_fails(f, f->store, f->server, f->other_wheel, f->bindings[0],
                     VIREO_RESULT_INVALID_ARGUMENT, VIREO_CLIENT_DEADLINE_CHECK_TIMER));
    CHECK(save_fails(f, f->store, f->server, f->unprepared, f->bindings[0], VIREO_RESULT_NOT_FOUND,
                     VIREO_CLIENT_DEADLINE_CHECK_TIMER));
    vireo_client_deadline_binding_t b = f->bindings[0];
    b.timer.slot_index = SIZE_MAX;
    CHECK(save_fails(f, f->store, f->server, f->wheel, b, VIREO_RESULT_RANGE,
                     VIREO_CLIENT_DEADLINE_CHECK_TIMER));
    b = f->bindings[0];
    b.timer.generation = UINT64_MAX;
    CHECK(save_fails(f, f->store, f->server, f->wheel, b, VIREO_RESULT_NOT_FOUND,
                     VIREO_CLIENT_DEADLINE_CHECK_TIMER));
    b = f->bindings[0];
    CHECK(vireo_client_deadline_cancel(f->wheel, &f->bindings[0], NULL) == VIREO_OK);
    CHECK(save_fails(f, f->store, f->server, f->wheel, b, VIREO_RESULT_NOT_FOUND,
                     VIREO_CLIENT_DEADLINE_CHECK_TIMER));
    return true;
}

static bool test_stopped_and_closing(fixture_t *f) {
    CHECK(register_at(f, 0, 0, 100, 110));
    CHECK(vireo_tcp_server_client_request_close(
              f->server, f->clients[0], VIREO_CONNECTION_CLOSE_MODE_IMMEDIATE,
              VIREO_CONNECTION_CLOSE_REASON_APPLICATION, NULL) == VIREO_OK);
    CHECK(vireo_timer_wheel_shutdown_begin(f->wheel) == VIREO_OK);
    CHECK(save_at(f, 0));
    vireo_client_deadline_binding_t const original = f->bindings[0];
    CHECK(vireo_client_deadline_cancel(f->wheel, &f->bindings[0], NULL) == VIREO_OK);
    vireo_client_deadline_store_info_t info;
    CHECK(vireo_client_deadline_store_inspect(f->store, &info) == VIREO_OK && info.count == 1);
    /* 保存的历史副本不受取消影响，cleanup 用副本键撤回。 */
    vireo_client_deadline_binding_t out;
    vireo_timer_handle_t const key = original.timer;
    CHECK(vireo_client_deadline_store_withdraw(f->store, key, &out) == VIREO_OK && count_is(f, 0));
    return true;
}

static bool test_query_contract(fixture_t *f) {
    CHECK(register_at(f, 0, 0, 100, 110) && save_at(f, 0));
    CHECK(query_fails(f, (vireo_timer_handle_t){0}, VIREO_RESULT_NOT_FOUND));
    CHECK(query_fails(f, (vireo_timer_handle_t){0, 1, 0}, VIREO_RESULT_INVALID_ARGUMENT));
    CHECK(query_fails(f, (vireo_timer_handle_t){1, 0, 0}, VIREO_RESULT_INVALID_ARGUMENT));
    vireo_timer_handle_t key = f->bindings[0].timer;
    key.generation = UINT64_MAX;
    CHECK(query_fails(f, key, VIREO_RESULT_NOT_FOUND));
    key = f->bindings[0].timer;
    key.slot_index = SIZE_MAX;
    CHECK(query_fails(f, key, VIREO_RESULT_NOT_FOUND));
    key = (vireo_timer_handle_t){UINT64_MAX, SIZE_MAX, UINT64_MAX};
    CHECK(query_fails(f, key, VIREO_RESULT_NOT_FOUND));
    vireo_client_deadline_binding_t out, copy;
    memset(&out, 0xa5, sizeof out);
    memcpy(&copy, &out, sizeof copy);
    errno = EDOM;
    CHECK(vireo_client_deadline_store_find(NULL, key, &out) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_client_deadline_store_withdraw(NULL, key, &out) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_client_deadline_store_take_expired(f->store, NULL, &out) ==
          VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(memcmp(&out, &copy, sizeof out) == 0 && errno == EDOM);
    vireo_timer_wheel_expired_t const event = {key, {0}};
    CHECK(vireo_client_deadline_store_take_expired(NULL, &event, &out) ==
          VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_client_deadline_store_find(f->store, key, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_client_deadline_store_withdraw(f->store, key, NULL) ==
          VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_client_deadline_store_take_expired(f->store, &event, NULL) ==
          VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(errno == EDOM && count_is(f, 1));
    return true;
}

static bool test_withdraw_preserves_timer(fixture_t *f) {
    CHECK(register_at(f, 0, 0, 100, 110) && save_at(f, 0));
    vireo_client_deadline_binding_t out;
    CHECK(vireo_client_deadline_store_withdraw(f->store, f->bindings[0].timer, &out) == VIREO_OK);
    CHECK(count_is(f, 0) && same_binding(out, f->bindings[0]));
    vireo_timer_wheel_timer_info_t info;
    CHECK(vireo_timer_wheel_get(f->wheel, out.timer, &info) == VIREO_OK);
    unsigned char bytes[sizeof out];
    memcpy(bytes, &out, sizeof bytes);
    CHECK(vireo_client_deadline_cancel(f->other_wheel, &out, NULL) ==
          VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(memcmp(bytes, &out, sizeof bytes) == 0 && count_is(f, 0));
    CHECK(vireo_client_deadline_cancel(f->wheel, &out, NULL) == VIREO_OK);
    f->bindings[0] = (vireo_client_deadline_binding_t){0};
    return true;
}

static bool test_lookup_after_unregister(fixture_t *f) {
    CHECK(register_at(f, 0, 0, 100, 110) && save_at(f, 0));
    vireo_client_deadline_binding_t original = f->bindings[0];
    CHECK(vireo_client_deadline_cancel(f->wheel, &f->bindings[0], NULL) == VIREO_OK);
    vireo_client_deadline_binding_t found;
    CHECK(vireo_client_deadline_store_find(f->store, original.timer, &found) == VIREO_OK);
    CHECK(same_binding(found, original));
    CHECK(vireo_client_deadline_store_withdraw(f->store, original.timer, &found) == VIREO_OK &&
          count_is(f, 0));
    return true;
}

static bool test_same_slot_new_generation(fixture_t *f) {
    CHECK(vireo_timer_wheel_destroy(&f->wheel) == VIREO_OK);
    vireo_timer_wheel_options_t const options = {{100, 10, 4}, VIREO_TIMER_WHEEL_MAX_MEMORY};
    vireo_timer_wheel_registry_options_t const registry = {1,
                                                           VIREO_TIMER_WHEEL_REGISTRY_MAX_MEMORY};
    CHECK(vireo_timer_wheel_create(&options, &f->wheel) == VIREO_OK &&
          vireo_timer_wheel_prepare(f->wheel, &registry) == VIREO_OK);
    CHECK(register_at(f, 0, 0, 100, 110) && save_at(f, 0) && advance_to(f->wheel, 110));
    vireo_timer_wheel_expired_t expired;
    CHECK(vireo_timer_wheel_take_expired(f->wheel, &expired) == VIREO_OK);
    CHECK(register_at(f, 1, 1, 110, 120));
    CHECK(f->bindings[0].timer.slot_index == f->bindings[1].timer.slot_index &&
          f->bindings[0].timer.owner_id == f->bindings[1].timer.owner_id &&
          f->bindings[0].timer.generation != f->bindings[1].timer.generation);
    CHECK(save_at(f, 1) && count_is(f, 2));
    vireo_client_deadline_binding_t out;
    CHECK(vireo_client_deadline_store_find(f->store, expired.handle, &out) == VIREO_OK &&
          same_binding(out, f->bindings[0]));
    errno = EILSEQ;
    CHECK(vireo_client_deadline_store_take_expired(f->store, &expired, &out) == VIREO_OK &&
          errno == EILSEQ);
    CHECK(same_binding(out, f->bindings[0]) && count_is(f, 1));
    CHECK(query_fails(f, expired.handle, VIREO_RESULT_NOT_FOUND));
    CHECK(vireo_client_deadline_store_find(f->store, f->bindings[1].timer, &out) == VIREO_OK &&
          same_binding(out, f->bindings[1]));
    vireo_timer_wheel_timer_info_t info;
    CHECK(vireo_timer_wheel_get(f->wheel, f->bindings[1].timer, &info) == VIREO_OK &&
          info.deadline_ns == 120);
    return true;
}

static bool test_different_owners(fixture_t *f) {
    CHECK(register_at(f, 0, 0, 100, 110) && register_at(f, 2, 1, 100, 110));
    CHECK(f->bindings[0].timer.slot_index == f->bindings[2].timer.slot_index &&
          f->bindings[0].timer.generation == f->bindings[2].timer.generation &&
          f->bindings[0].timer.owner_id != f->bindings[2].timer.owner_id);
    CHECK(save_at(f, 0) && save_at(f, 2) && count_is(f, 2));
    CHECK(advance_to(f->wheel, 110));
    vireo_timer_wheel_expired_t event;
    CHECK(vireo_timer_wheel_take_expired(f->wheel, &event) == VIREO_OK);
    vireo_client_deadline_binding_t out;
    CHECK(vireo_client_deadline_store_take_expired(f->store, &event, &out) == VIREO_OK &&
          same_binding(out, f->bindings[0]));
    CHECK(vireo_client_deadline_store_find(f->store, f->bindings[2].timer, &out) == VIREO_OK &&
          same_binding(out, f->bindings[2]));
    return true;
}

/** 到期交付的短借探针；取出和客户核验是两个独立成功点。 */
typedef struct delivery_probe {
    fixture_t *fixture; /**< 借用完整 fixture 至同步 dispatch 返回。 */
    size_t calls;       /**< 实际交付次数，受外层条数预算限制。 */
    size_t taken;       /**< 本表成功转出次数，后续客户失败不回滚。 */
    vireo_client_deadline_binding_t bindings[2]; /**< 成功转出的持久数值副本，最多二项。 */
    vireo_client_deadline_stage_t stage;         /**< 最后一次客户核验阶段。 */
    vireo_tcp_server_client_info_t client_info; /**< 成功客户快照；失败保留原字节。 */
} delivery_probe_t;
static vireo_result_t deliver(vireo_timer_wheel_expired_t const *event, void *context) {
    delivery_probe_t *p = context;
    ++p->calls;
    if (p->taken >= 2)
        return VIREO_RESULT_INTERNAL;
    vireo_result_t result =
        vireo_client_deadline_store_take_expired(p->fixture->store, event, &p->bindings[p->taken]);
    if (result != VIREO_OK)
        return result;
    ++p->taken;
    result = vireo_client_deadline_check_expired(p->fixture->server, p->bindings[p->taken - 1],
                                                 event, &p->client_info, &p->stage);
    errno = ENOSPC; /* dispatch 须恢复入口 errno，即使回调修改。 */
    return result;
}
static bool test_dispatch_two_clients(fixture_t *f) {
    CHECK(register_at(f, 0, 0, 100, 110) && register_at(f, 1, 1, 100, 110));
    CHECK(save_at(f, 0) && save_at(f, 1) && advance_to(f->wheel, 110));
    delivery_probe_t probe = {0};
    probe.fixture = f;
    vireo_timer_loop_dispatch_report_t report;
    errno = EDOM;
    CHECK(vireo_timer_loop_dispatch(f->wheel, 1, deliver, &probe, &report) == VIREO_OK &&
          errno == EDOM);
    CHECK(report.consumed_count == 1 && report.delivered_count == 1 && !report.has_failed_delivery);
    CHECK(probe.calls == 1 && probe.taken == 1 && count_is(f, 1));
    CHECK(vireo_timer_loop_dispatch(f->wheel, 1, deliver, &probe, &report) == VIREO_OK);
    CHECK(report.consumed_count == 1 && report.delivered_count == 1 && probe.calls == 2 &&
          probe.taken == 2 && count_is(f, 0));
    CHECK(!same_timer(probe.bindings[0].timer, probe.bindings[1].timer));
    CHECK((same_binding(probe.bindings[0], f->bindings[0]) &&
           same_binding(probe.bindings[1], f->bindings[1])) ||
          (same_binding(probe.bindings[0], f->bindings[1]) &&
           same_binding(probe.bindings[1], f->bindings[0])));
    CHECK(probe.stage == VIREO_CLIENT_DEADLINE_NONE &&
          probe.client_info.connection_info.close_state == VIREO_CONNECTION_CLOSE_OPEN);
    return true;
}

static bool test_dispatch_stale_client(fixture_t *f) {
    CHECK(register_at(f, 0, 0, 100, 110) && save_at(f, 0));
    CHECK(vireo_tcp_server_release_client(f->server, &f->clients[0], NULL) == VIREO_OK);
    CHECK(close(f->peers[0]) == 0);
    f->peers[0] = -1;
    CHECK(add_client(f, 0));
    CHECK(f->clients[0].slot_index == f->bindings[0].client.slot_index &&
          f->clients[0].generation != f->bindings[0].client.generation);
    CHECK(advance_to(f->wheel, 110));
    delivery_probe_t probe = {0};
    probe.fixture = f;
    memset(&probe.client_info, 0xa5, sizeof probe.client_info);
    unsigned char bytes[sizeof probe.client_info];
    memcpy(bytes, &probe.client_info, sizeof bytes);
    vireo_timer_loop_dispatch_report_t report;
    errno = EDOM;
    CHECK(vireo_timer_loop_dispatch(f->wheel, 1, deliver, &probe, &report) ==
              VIREO_RESULT_NOT_FOUND &&
          errno == EDOM);
    CHECK(report.stage == VIREO_TIMER_LOOP_DISPATCH_STAGE_DELIVER && report.consumed_count == 1 &&
          report.delivered_count == 0 && report.has_failed_delivery &&
          same_timer(report.failed_delivery.handle, f->bindings[0].timer));
    CHECK(probe.calls == 1 && probe.taken == 1 && same_binding(probe.bindings[0], f->bindings[0]));
    CHECK(probe.stage == VIREO_CLIENT_DEADLINE_CHECK_CLIENT &&
          memcmp(bytes, &probe.client_info, sizeof bytes) == 0 && count_is(f, 0));
    vireo_tcp_server_client_info_t current;
    CHECK(vireo_tcp_server_client_inspect(f->server, f->clients[0], &current) == VIREO_OK);
    CHECK(current.connection_info.close_state == VIREO_CONNECTION_CLOSE_OPEN);
    CHECK(query_fails(f, report.failed_delivery.handle, VIREO_RESULT_NOT_FOUND));
    unsigned char record[sizeof probe.bindings[0]];
    memcpy(record, &probe.bindings[0], sizeof record);
    CHECK(vireo_client_deadline_cancel(f->wheel, &probe.bindings[0], NULL) ==
          VIREO_RESULT_NOT_FOUND);
    CHECK(memcmp(record, &probe.bindings[0], sizeof record) == 0);
    return true;
}

static bool test_dispatch_missing_record(fixture_t *f) {
    CHECK(register_at(f, 0, 0, 100, 110) && register_at(f, 2, 1, 100, 120) && save_at(f, 2));
    CHECK(advance_to(f->wheel, 110));
    delivery_probe_t probe = {0};
    probe.fixture = f;
    memset(&probe.bindings[0], 0xa5, sizeof probe.bindings[0]);
    unsigned char bytes[sizeof probe.bindings[0]];
    memcpy(bytes, &probe.bindings[0], sizeof bytes);
    vireo_timer_loop_dispatch_report_t report;
    CHECK(vireo_timer_loop_dispatch(f->wheel, 1, deliver, &probe, &report) ==
          VIREO_RESULT_NOT_FOUND);
    CHECK(report.stage == VIREO_TIMER_LOOP_DISPATCH_STAGE_DELIVER && report.consumed_count == 1 &&
          report.delivered_count == 0 && report.has_failed_delivery &&
          same_timer(report.failed_delivery.handle, f->bindings[0].timer));
    CHECK(probe.calls == 1 && probe.taken == 0 &&
          memcmp(bytes, &probe.bindings[0], sizeof bytes) == 0 && count_is(f, 1));
    vireo_client_deadline_binding_t found;
    CHECK(vireo_client_deadline_store_find(f->store, f->bindings[2].timer, &found) == VIREO_OK &&
          same_binding(found, f->bindings[2]));
    return true;
}

static bool test_destroy_busy(fixture_t *f) {
    CHECK(register_at(f, 0, 0, 100, 110) && save_at(f, 0));
    vireo_client_deadline_store_t *before = f->store;
    errno = EDOM;
    CHECK(vireo_client_deadline_store_destroy(&f->store) == VIREO_RESULT_BUSY &&
          f->store == before && errno == EDOM);
    CHECK(count_is(f, 1));
    vireo_client_deadline_binding_t out;
    CHECK(vireo_client_deadline_store_withdraw(f->store, f->bindings[0].timer, &out) == VIREO_OK);
    CHECK(vireo_client_deadline_store_destroy(&f->store) == VIREO_OK && f->store == NULL);
    CHECK(vireo_client_deadline_store_destroy(&f->store) == VIREO_OK);
    vireo_timer_wheel_timer_info_t timer;
    CHECK(vireo_timer_wheel_get(f->wheel, out.timer, &timer) == VIREO_OK);
    return true;
}

static bool test_shutdown_record_withdraw(fixture_t *f) {
    CHECK(register_at(f, 0, 0, 100, 120) && register_at(f, 1, 1, 100, 130));
    CHECK(save_at(f, 0) && save_at(f, 1));
    CHECK(vireo_timer_wheel_shutdown_begin(f->wheel) == VIREO_OK);
    vireo_timer_wheel_shutdown_report_t report;
    CHECK(vireo_timer_wheel_shutdown_step(f->wheel, 16, &report) == VIREO_OK);
    CHECK(report.has_cancelled && report.remaining_count == 1 && !report.finished);
    vireo_client_deadline_binding_t out;
    CHECK(vireo_client_deadline_store_withdraw(f->store, report.cancelled.handle, &out) ==
          VIREO_OK);
    CHECK(same_timer(out.timer, report.cancelled.handle) && count_is(f, 1));
    CHECK(same_binding(out, f->bindings[0]) || same_binding(out, f->bindings[1]));
    CHECK(query_fails(f, report.cancelled.handle, VIREO_RESULT_NOT_FOUND));
    return true;
}

/** 独立场景索引，无资源或请求状态。 */
typedef struct test_case {
    char const *name;         /**< 静态场景名。 */
    bool (*run)(fixture_t *); /**< 同步场景函数，返回真实断言结果。 */
} test_case_t;
int main(void) {
    test_case_t const cases[] = {
        {"resource contract", test_resource_contract},
        {"exact byte budget", test_exact_budget},
        {"maximum capacity", test_max_capacity},
        {"single allocation failure", test_allocation_failure},
        {"two actual clients", test_two_clients},
        {"same client multiple timers", test_same_client_multiple},
        {"save shapes and nulls", test_save_shapes},
        {"duplicate before dependencies", test_duplicate_priority},
        {"full table caller recovery", test_full_table_recovery},
        {"current client dependencies", test_client_dependencies},
        {"current timer dependencies", test_timer_dependencies},
        {"stopped wheel and closing client", test_stopped_and_closing},
        {"query error and whole output", test_query_contract},
        {"withdraw then cancel failure", test_withdraw_preserves_timer},
        {"lookup historical cancelled timer", test_lookup_after_unregister},
        {"same slot old and new generation", test_same_slot_new_generation},
        {"different timer owners", test_different_owners},
        {"bounded dispatch two clients", test_dispatch_two_clients},
        {"dispatch stale client partial progress", test_dispatch_stale_client},
        {"dispatch missing binding", test_dispatch_missing_record},
        {"destroy busy and timer independence", test_destroy_busy},
        {"shutdown cancellation record withdrawal", test_shutdown_record_withdraw}};
    size_t failed = 0;
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
        fixture_t fixture;
        bool const ready = setup(&fixture);
        bool const passed = ready && cases[i].run(&fixture);
        bool const cleaned = cleanup(&fixture);
        bool const ok = passed && cleaned;
        printf("%s: %s\n", cases[i].name, ok ? "PASS" : "FAIL");
        if (!ok)
            ++failed;
    }
    printf("%zu groups, %zu failed\n", sizeof cases / sizeof cases[0], failed);
    return failed == 0 ? 0 : 1;
}
