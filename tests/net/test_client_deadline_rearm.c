/*
 * PROJECT : VIREO
 * FILE    : test_client_deadline_rearm.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-10
 * BRIEF   : 此模块负责：
 * -- 验证核验当前客户后显式重排并保持 timer 身份
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
#include <vireo/net/client_deadline_store.h>
#include <vireo/net/timer_loop_dispatch.h>
#include <vireo/timer/wheel_shutdown.h>

#define CHECK(expr)                                                    \
    do {                                                               \
        if (!(expr)) {                                                 \
            fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #expr); \
            return false;                                              \
        }                                                              \
    } while (0)

/** 本项真实 TCP 与公开资源 fixture；全部使用 public 合同。 */
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

static bool same_info(vireo_timer_wheel_timer_info_t a, vireo_timer_wheel_timer_info_t b) {
    return a.deadline_ns == b.deadline_ns && a.due_tick == b.due_tick &&
           a.bucket_index == b.bucket_index;
}
static bool same_progress(vireo_timer_wheel_progress_t a, vireo_timer_wheel_progress_t b) {
    return a.latest_now_ns == b.latest_now_ns && a.target_tick == b.target_tick &&
           a.completed_tick == b.completed_tick && a.processing == b.processing &&
           a.ready_count == b.ready_count && a.caught_up == b.caught_up;
}
static bool same_registry(vireo_timer_wheel_registry_info_t a,
                          vireo_timer_wheel_registry_info_t b) {
    return a.prepared == b.prepared && a.capacity == b.capacity &&
           a.active_count == b.active_count && a.available_count == b.available_count &&
           a.allocation_bytes == b.allocation_bytes && a.max_memory_bytes == b.max_memory_bytes;
}

/** 仅通过公开观测核对所有已知 timer、记录及两轮进度，绝不读取 opaque 字节。 */
static bool rearm_fails(fixture_t *f, vireo_tcp_server_t const *server, vireo_timer_wheel_t *wheel,
                        vireo_client_deadline_binding_t binding, uint64_t now, uint64_t deadline,
                        vireo_result_t expected, vireo_client_deadline_stage_t expected_stage) {
    vireo_timer_wheel_t *wheels[3] = {f->wheel, f->other_wheel, f->unprepared};
    vireo_timer_wheel_registry_info_t registry[3];
    vireo_timer_wheel_progress_t progress[2];
    for (size_t i = 0; i < 3; ++i)
        CHECK(vireo_timer_wheel_registry_inspect(wheels[i], &registry[i]) == VIREO_OK);
    for (size_t i = 0; i < 2; ++i)
        CHECK(vireo_timer_wheel_progress_inspect(wheels[i], &progress[i]) == VIREO_OK);
    vireo_timer_wheel_timer_info_t timers[4];
    vireo_result_t timer_results[4], record_results[4];
    vireo_client_deadline_binding_t records[4];
    for (size_t i = 0; i < 4; ++i) {
        timer_results[i] =
            vireo_timer_wheel_get(wheels[i < 2 ? 0 : 1], f->bindings[i].timer, &timers[i]);
        record_results[i] =
            vireo_client_deadline_store_find(f->store, f->bindings[i].timer, &records[i]);
    }
    vireo_client_deadline_store_info_t store;
    CHECK(vireo_client_deadline_store_inspect(f->store, &store) == VIREO_OK);
    unsigned char binding_bytes[sizeof binding];
    memcpy(binding_bytes, &binding, sizeof binding);
    for (size_t pass = 0; pass < 2; ++pass) {
        vireo_client_deadline_stage_t stage = VIREO_CLIENT_DEADLINE_CANCEL_TIMER;
        errno = pass == 0 ? ENOSPC : ERANGE;
        int const saved = errno;
        CHECK(vireo_client_deadline_rearm(server, wheel, binding, now, deadline,
                                          pass == 0 ? &stage : NULL) == expected);
        CHECK(errno == saved && (pass != 0 || stage == expected_stage));
        CHECK(memcmp(binding_bytes, &binding, sizeof binding) == 0);
        for (size_t i = 0; i < 3; ++i) {
            vireo_timer_wheel_registry_info_t after;
            CHECK(vireo_timer_wheel_registry_inspect(wheels[i], &after) == VIREO_OK);
            CHECK(same_registry(registry[i], after));
        }
        for (size_t i = 0; i < 2; ++i) {
            vireo_timer_wheel_progress_t after;
            CHECK(vireo_timer_wheel_progress_inspect(wheels[i], &after) == VIREO_OK);
            CHECK(same_progress(progress[i], after));
        }
        for (size_t i = 0; i < 4; ++i) {
            vireo_timer_wheel_timer_info_t after;
            vireo_client_deadline_binding_t record;
            CHECK(vireo_timer_wheel_get(wheels[i < 2 ? 0 : 1], f->bindings[i].timer, &after) ==
                  timer_results[i]);
            if (timer_results[i] == VIREO_OK)
                CHECK(same_info(timers[i], after));
            CHECK(vireo_client_deadline_store_find(f->store, f->bindings[i].timer, &record) ==
                  record_results[i]);
            if (record_results[i] == VIREO_OK)
                CHECK(same_binding(records[i], record));
        }
        vireo_client_deadline_store_info_t after;
        CHECK(vireo_client_deadline_store_inspect(f->store, &after) == VIREO_OK);
        CHECK(store.capacity == after.capacity && store.count == after.count &&
              store.allocation_bytes == after.allocation_bytes &&
              store.max_memory_bytes == after.max_memory_bytes);
    }
    return true;
}

static bool rearm_ok(fixture_t *f, size_t index, uint64_t now, uint64_t deadline, uint64_t tick,
                     uint64_t bucket) {
    vireo_client_deadline_binding_t const before = f->bindings[index];
    vireo_timer_wheel_t *wheel = index < 2 ? f->wheel : f->other_wheel;
    vireo_timer_wheel_registry_info_t registry, after;
    CHECK(vireo_timer_wheel_registry_inspect(wheel, &registry) == VIREO_OK);
    vireo_client_deadline_binding_t record;
    vireo_result_t const stored = vireo_client_deadline_store_find(f->store, before.timer, &record);
    vireo_client_deadline_stage_t stage = VIREO_CLIENT_DEADLINE_CANCEL_TIMER;
    errno = EDOM;
    CHECK(vireo_client_deadline_rearm(f->server, wheel, before, now, deadline, &stage) == VIREO_OK);
    CHECK(stage == VIREO_CLIENT_DEADLINE_NONE && errno == EDOM);
    CHECK(same_binding(before, f->bindings[index]));
    vireo_timer_wheel_timer_info_t info;
    CHECK(vireo_timer_wheel_get(wheel, before.timer, &info) == VIREO_OK);
    CHECK(info.deadline_ns == deadline && info.due_tick == tick && info.bucket_index == bucket);
    CHECK(vireo_timer_wheel_registry_inspect(wheel, &after) == VIREO_OK);
    CHECK(same_registry(registry, after));
    vireo_client_deadline_binding_t found;
    CHECK(vireo_client_deadline_store_find(f->store, before.timer, &found) == stored);
    if (stored == VIREO_OK)
        CHECK(same_binding(record, found));
    return true;
}

static bool test_enum(fixture_t *f) {
    (void)f;
    CHECK(VIREO_CLIENT_DEADLINE_NONE == 0 && VIREO_CLIENT_DEADLINE_CHECK_CLIENT == 1 &&
          VIREO_CLIENT_DEADLINE_CHECK_TIMER == 2 && VIREO_CLIENT_DEADLINE_MATCH_TIMER == 3 &&
          VIREO_CLIENT_DEADLINE_REGISTER_TIMER == 4 && VIREO_CLIENT_DEADLINE_CANCEL_TIMER == 5 &&
          VIREO_CLIENT_DEADLINE_REARM_TIMER == 6);
    return true;
}
static bool test_future(fixture_t *f) {
    CHECK(register_at(f, 0, 0, 100, 110) && save_at(f, 0));
    CHECK(rearm_ok(f, 0, 101, 151, 6, 2) && count_is(f, 1));
    CHECK(advance_to(f->wheel, 110));
    vireo_timer_wheel_expired_t event;
    CHECK(vireo_timer_wheel_take_expired(f->wheel, &event) == VIREO_RESULT_NOT_FOUND);
    return true;
}
static bool test_shortening(fixture_t *f) {
    CHECK(register_at(f, 0, 0, 100, 190) && save_at(f, 0));
    CHECK(rearm_ok(f, 0, 101, 111, 2, 2));
    CHECK(advance_to(f->wheel, 119));
    vireo_timer_wheel_expired_t event;
    CHECK(vireo_timer_wheel_take_expired(f->wheel, &event) == VIREO_RESULT_NOT_FOUND);
    CHECK(advance_to(f->wheel, 120));
    CHECK(vireo_timer_wheel_take_expired(f->wheel, &event) == VIREO_OK);
    CHECK(same_timer(event.handle, f->bindings[0].timer) && event.timer.deadline_ns == 111 &&
          event.timer.due_tick == 2 && event.timer.bucket_index == 2);
    return true;
}
static bool test_nulls_shapes(fixture_t *f) {
    CHECK(register_at(f, 0, 0, 100, 110) && save_at(f, 0));
    vireo_client_deadline_binding_t b = f->bindings[0];
    CHECK(rearm_fails(f, NULL, f->wheel, b, 100, 120, VIREO_RESULT_INVALID_ARGUMENT, 0));
    CHECK(rearm_fails(f, f->server, NULL, b, 100, 120, VIREO_RESULT_INVALID_ARGUMENT, 0));
    CHECK(rearm_fails(f, f->server, f->wheel, (vireo_client_deadline_binding_t){0}, 100, 120,
                      VIREO_RESULT_NOT_FOUND, 0));
    b.client = (vireo_connection_pool_lease_t){0};
    CHECK(rearm_fails(f, f->server, f->wheel, b, 100, 120, VIREO_RESULT_INVALID_ARGUMENT, 0));
    b = f->bindings[0];
    b.timer = (vireo_timer_handle_t){0};
    CHECK(rearm_fails(f, f->server, f->wheel, b, 100, 120, VIREO_RESULT_INVALID_ARGUMENT, 0));
    b = f->bindings[0];
    b.client.pool_id = 0;
    CHECK(rearm_fails(f, f->server, f->wheel, b, 100, 120, VIREO_RESULT_INVALID_ARGUMENT, 0));
    b = f->bindings[0];
    b.client.generation = 0;
    CHECK(rearm_fails(f, f->server, f->wheel, b, 100, 120, VIREO_RESULT_INVALID_ARGUMENT, 0));
    b = f->bindings[0];
    b.timer.owner_id = 0;
    CHECK(rearm_fails(f, f->server, f->wheel, b, 100, 120, VIREO_RESULT_INVALID_ARGUMENT, 0));
    b = f->bindings[0];
    b.timer.generation = 0;
    CHECK(rearm_fails(f, f->server, f->wheel, b, 100, 120, VIREO_RESULT_INVALID_ARGUMENT, 0));
    b = (vireo_client_deadline_binding_t){0};
    b.timer.slot_index = SIZE_MAX;
    CHECK(rearm_fails(f, f->server, f->wheel, b, 100, 120, VIREO_RESULT_INVALID_ARGUMENT, 0));
    return true;
}
static bool test_client_dependencies(fixture_t *f) {
    CHECK(register_at(f, 0, 0, 100, 110) && save_at(f, 0));
    CHECK(rearm_fails(f, f->other_server, f->unprepared, f->bindings[0], 0, 0,
                      VIREO_RESULT_INVALID_ARGUMENT, VIREO_CLIENT_DEADLINE_CHECK_CLIENT));
    vireo_client_deadline_binding_t b = f->bindings[0];
    b.client.slot_index = 2;
    CHECK(rearm_fails(f, f->server, f->wheel, b, 0, 0, VIREO_RESULT_RANGE,
                      VIREO_CLIENT_DEADLINE_CHECK_CLIENT));
    CHECK(vireo_tcp_server_release_client(f->server, &f->clients[0], NULL) == VIREO_OK);
    CHECK(vireo_timer_wheel_shutdown_begin(f->wheel) == VIREO_OK);
    CHECK(rearm_fails(f, f->server, f->wheel, f->bindings[0], 0, 0, VIREO_RESULT_NOT_FOUND,
                      VIREO_CLIENT_DEADLINE_CHECK_CLIENT));
    return true;
}
static bool test_timer_dependencies(fixture_t *f) {
    CHECK(register_at(f, 0, 0, 100, 110) && save_at(f, 0));
    CHECK(rearm_fails(f, f->server, f->unprepared, f->bindings[0], 0, 0, VIREO_RESULT_NOT_FOUND,
                      VIREO_CLIENT_DEADLINE_REARM_TIMER));
    CHECK(rearm_fails(f, f->server, f->other_wheel, f->bindings[0], 0, 0,
                      VIREO_RESULT_INVALID_ARGUMENT, VIREO_CLIENT_DEADLINE_REARM_TIMER));
    vireo_client_deadline_binding_t b = f->bindings[0];
    b.timer.slot_index = 2;
    CHECK(rearm_fails(f, f->server, f->wheel, b, 0, 0, VIREO_RESULT_RANGE,
                      VIREO_CLIENT_DEADLINE_REARM_TIMER));
    ++b.timer.generation;
    b.timer.slot_index = f->bindings[0].timer.slot_index;
    CHECK(rearm_fails(f, f->server, f->wheel, b, 0, 0, VIREO_RESULT_NOT_FOUND,
                      VIREO_CLIENT_DEADLINE_REARM_TIMER));
    return true;
}
static bool test_time_errors(fixture_t *f) {
    CHECK(register_at(f, 0, 0, 100, 150) && save_at(f, 0));
    CHECK(rearm_fails(f, f->server, f->wheel, f->bindings[0], 99, 150, VIREO_RESULT_RANGE, 6));
    CHECK(rearm_fails(f, f->server, f->wheel, f->bindings[0], 110, 110, VIREO_RESULT_TIMEOUT, 6));
    CHECK(rearm_fails(f, f->server, f->wheel, f->bindings[0], 110, 100, VIREO_RESULT_TIMEOUT, 6));
    CHECK(rearm_fails(f, f->server, f->wheel, f->bindings[0], 110, UINT64_MAX,
                      VIREO_RESULT_OVERFLOW, 6));
    return true;
}
static bool test_stop(fixture_t *f) {
    CHECK(register_at(f, 0, 0, 100, 150) && save_at(f, 0));
    CHECK(vireo_timer_wheel_shutdown_begin(f->wheel) == VIREO_OK);
    CHECK(rearm_fails(f, f->server, f->wheel, f->bindings[0], 99, UINT64_MAX,
                      VIREO_RESULT_CANCELLED, 6));
    vireo_client_deadline_binding_t b = f->bindings[0];
    ++b.timer.generation;
    CHECK(rearm_fails(f, f->server, f->wheel, b, 99, UINT64_MAX, VIREO_RESULT_NOT_FOUND, 6));
    return true;
}
static bool test_ready_withdraw(fixture_t *f) {
    CHECK(register_at(f, 0, 0, 100, 110) && save_at(f, 0) && advance_to(f->wheel, 110));
    vireo_timer_wheel_progress_t p, after;
    CHECK(vireo_timer_wheel_progress_inspect(f->wheel, &p) == VIREO_OK && p.ready_count == 1);
    CHECK(rearm_ok(f, 0, 110, 130, 3, 3));
    CHECK(vireo_timer_wheel_progress_inspect(f->wheel, &after) == VIREO_OK);
    CHECK(after.ready_count == 0 && after.latest_now_ns == p.latest_now_ns &&
          after.target_tick == p.target_tick && after.completed_tick == p.completed_tick);
    vireo_timer_wheel_expired_t event;
    CHECK(vireo_timer_wheel_take_expired(f->wheel, &event) == VIREO_RESULT_NOT_FOUND);
    CHECK(advance_to(f->wheel, 130));
    CHECK(vireo_timer_wheel_take_expired(f->wheel, &event) == VIREO_OK);
    CHECK(same_timer(event.handle, f->bindings[0].timer) && event.timer.deadline_ns == 130);
    return true;
}
static bool test_ready_failure(fixture_t *f) {
    CHECK(register_at(f, 0, 0, 100, 110) && save_at(f, 0) && advance_to(f->wheel, 110));
    CHECK(rearm_fails(f, f->server, f->wheel, f->bindings[0], 110, 110, VIREO_RESULT_TIMEOUT, 6));
    CHECK(rearm_fails(f, f->server, f->wheel, f->bindings[0], 110, UINT64_MAX,
                      VIREO_RESULT_OVERFLOW, 6));
    vireo_timer_wheel_expired_t event;
    CHECK(vireo_timer_wheel_take_expired(f->wheel, &event) == VIREO_OK);
    CHECK(same_timer(event.handle, f->bindings[0].timer) && event.timer.deadline_ns == 110);
    return true;
}
static bool test_elapsed_active(fixture_t *f) {
    CHECK(register_at(f, 0, 0, 100, 110) && save_at(f, 0));
    CHECK(rearm_ok(f, 0, 120, 130, 3, 3));
    CHECK(advance_to(f->wheel, 120));
    vireo_timer_wheel_expired_t event;
    CHECK(vireo_timer_wheel_take_expired(f->wheel, &event) == VIREO_RESULT_NOT_FOUND);
    return true;
}
static bool test_taken(fixture_t *f) {
    CHECK(register_at(f, 0, 0, 100, 110) && save_at(f, 0) && advance_to(f->wheel, 110));
    vireo_timer_wheel_expired_t event;
    CHECK(vireo_timer_wheel_take_expired(f->wheel, &event) == VIREO_OK);
    CHECK(rearm_fails(f, f->server, f->wheel, f->bindings[0], 110, 130, VIREO_RESULT_NOT_FOUND, 6));
    vireo_client_deadline_binding_t b;
    CHECK(vireo_client_deadline_store_find(f->store, event.handle, &b) == VIREO_OK);
    CHECK(same_binding(b, f->bindings[0]));
    return true;
}
static bool test_cancelled_reuse(fixture_t *f) {
    CHECK(vireo_timer_wheel_destroy(&f->wheel) == VIREO_OK);
    vireo_timer_wheel_options_t const options = {{100, 10, 4}, VIREO_TIMER_WHEEL_MAX_MEMORY};
    vireo_timer_wheel_registry_options_t const registry = {1,
                                                           VIREO_TIMER_WHEEL_REGISTRY_MAX_MEMORY};
    CHECK(vireo_timer_wheel_create(&options, &f->wheel) == VIREO_OK);
    CHECK(vireo_timer_wheel_prepare(f->wheel, &registry) == VIREO_OK);
    CHECK(register_at(f, 0, 0, 100, 110) && save_at(f, 0));
    vireo_client_deadline_binding_t cancelled = f->bindings[0];
    CHECK(vireo_client_deadline_cancel(f->wheel, &cancelled, NULL) == VIREO_OK);
    CHECK(register_at(f, 1, 1, 100, 120) && save_at(f, 1));
    CHECK(f->bindings[0].timer.slot_index == f->bindings[1].timer.slot_index &&
          f->bindings[1].timer.generation == f->bindings[0].timer.generation + 1);
    CHECK(rearm_fails(f, f->server, f->wheel, f->bindings[0], 100, 130, VIREO_RESULT_NOT_FOUND, 6));
    CHECK(rearm_ok(f, 1, 100, 130, 3, 3) && count_is(f, 2));
    return true;
}
static bool test_pending(fixture_t *f) {
    CHECK(register_at(f, 0, 0, 100, 110) && register_at(f, 1, 1, 100, 110));
    CHECK(save_at(f, 0) && save_at(f, 1));
    vireo_timer_wheel_advance_report_t report;
    CHECK(vireo_timer_wheel_advance(f->wheel, 110, (vireo_timer_wheel_advance_budget_t){1, 1},
                                    &report) == VIREO_OK);
    CHECK(report.progress.processing && report.progress.ready_count == 1 &&
          !report.progress.caught_up);
    CHECK(rearm_ok(f, 0, 110, 130, 3, 3) && rearm_ok(f, 1, 110, 130, 3, 3));
    CHECK(vireo_timer_wheel_advance(f->wheel, 110, (vireo_timer_wheel_advance_budget_t){1, 1},
                                    &report) == VIREO_OK);
    CHECK(report.progress.caught_up && report.nodes_examined == 0 &&
          report.progress.ready_count == 0);
    CHECK(advance_to(f->wheel, 130));
    vireo_timer_wheel_expired_t a, b;
    CHECK(vireo_timer_wheel_take_expired(f->wheel, &a) == VIREO_OK);
    CHECK(vireo_timer_wheel_take_expired(f->wheel, &b) == VIREO_OK);
    CHECK(!same_timer(a.handle, b.handle) && a.timer.deadline_ns == 130 &&
          b.timer.deadline_ns == 130);
    return true;
}
static bool test_closing(fixture_t *f) {
    CHECK(register_at(f, 0, 0, 100, 110) && save_at(f, 0));
    CHECK(vireo_tcp_server_client_request_close(
              f->server, f->clients[0], VIREO_CONNECTION_CLOSE_MODE_IMMEDIATE,
              VIREO_CONNECTION_CLOSE_REASON_APPLICATION, NULL) == VIREO_OK);
    CHECK(rearm_ok(f, 0, 100, 120, 2, 2));
    vireo_tcp_server_client_info_t info;
    CHECK(vireo_tcp_server_client_inspect(f->server, f->clients[0], &info) == VIREO_OK);
    CHECK(info.connection_info.close_state == VIREO_CONNECTION_CLOSE_READY &&
          info.connection_info.close_reason == VIREO_CONNECTION_CLOSE_REASON_APPLICATION);
    return true;
}
static bool test_table_independent(fixture_t *f) {
    CHECK(register_at(f, 0, 0, 100, 110) && save_at(f, 0));
    vireo_client_deadline_binding_t transferred;
    CHECK(vireo_client_deadline_store_withdraw(f->store, f->bindings[0].timer, &transferred) ==
          VIREO_OK);
    CHECK(same_binding(transferred, f->bindings[0]) && count_is(f, 0));
    errno = EDOM;
    CHECK(vireo_client_deadline_rearm(f->server, f->wheel, transferred, 100, 120, NULL) ==
          VIREO_OK);
    CHECK(errno == EDOM && count_is(f, 0));
    CHECK(save_at(f, 0));
    return true;
}
static bool test_full_identity(fixture_t *f) {
    CHECK(register_at(f, 0, 0, 100, 110) && register_at(f, 1, 0, 100, 150));
    CHECK(save_at(f, 0) && save_at(f, 1));
    CHECK(rearm_ok(f, 0, 100, 130, 3, 3));
    vireo_timer_wheel_timer_info_t second;
    CHECK(vireo_timer_wheel_get(f->wheel, f->bindings[1].timer, &second) == VIREO_OK);
    CHECK(second.deadline_ns == 150 && count_is(f, 2));
    vireo_client_deadline_binding_t cancelled = f->bindings[0];
    uint64_t const generation = f->bindings[1].timer.generation;
    CHECK(vireo_client_deadline_cancel(f->wheel, &cancelled, NULL) == VIREO_OK);
    CHECK(register_at(f, 2, 1, 100, 120)); /* 独立 owner，不参与本轮发序。 */
    vireo_timer_handle_t next = {0};
    CHECK(vireo_timer_wheel_register(f->wheel, 100, 140, &next) == VIREO_OK);
    CHECK(next.generation == generation + 1);
    CHECK(vireo_timer_wheel_cancel(f->wheel, &next) == VIREO_OK);
    return true;
}

/** 同步链路证据；不执行业务关闭，通知地址不保存。 */
typedef struct delivery_probe {
    fixture_t *fixture;                /**< 短借到 dispatch 返回，不保活。 */
    size_t calls;                      /**< 真实回调次数。 */
    vireo_timer_wheel_expired_t event; /**< 完整历史值副本。 */
} delivery_probe_t;
static vireo_result_t deliver(vireo_timer_wheel_expired_t const *event, void *context) {
    delivery_probe_t *p = context;
    ++p->calls;
    p->event = *event;
    vireo_client_deadline_binding_t binding;
    vireo_result_t result =
        vireo_client_deadline_store_take_expired(p->fixture->store, event, &binding);
    if (result != VIREO_OK)
        return result;
    vireo_tcp_server_client_info_t info;
    result = vireo_client_deadline_check_expired(p->fixture->server, binding, event, &info, NULL);
    errno = ENOSPC;
    return result;
}
static bool test_chain(fixture_t *f) {
    CHECK(register_at(f, 0, 0, 100, 110) && save_at(f, 0));
    CHECK(rearm_ok(f, 0, 101, 121, 3, 3));
    CHECK(advance_to(f->wheel, 110));
    delivery_probe_t probe = {0};
    probe.fixture = f;
    vireo_timer_loop_dispatch_report_t report;
    CHECK(vireo_timer_loop_dispatch(f->wheel, 1, deliver, &probe, &report) == VIREO_OK);
    CHECK(probe.calls == 0 && report.consumed_count == 0 && count_is(f, 1));
    CHECK(advance_to(f->wheel, 130));
    errno = EDOM;
    CHECK(vireo_timer_loop_dispatch(f->wheel, 1, deliver, &probe, &report) == VIREO_OK);
    CHECK(errno == EDOM && report.stage == VIREO_TIMER_LOOP_DISPATCH_STAGE_NONE &&
          report.consumed_count == 1 && report.delivered_count == 1 && !report.has_failed_delivery);
    CHECK(probe.calls == 1 && same_timer(probe.event.handle, f->bindings[0].timer) &&
          probe.event.timer.deadline_ns == 121 && probe.event.timer.due_tick == 3 &&
          count_is(f, 0));
    vireo_tcp_server_client_info_t info;
    CHECK(vireo_tcp_server_client_inspect(f->server, f->clients[0], &info) == VIREO_OK);
    CHECK(info.connection_info.close_state == VIREO_CONNECTION_CLOSE_OPEN);
    return true;
}
static bool test_max_finite(fixture_t *f) {
    CHECK(vireo_timer_wheel_destroy(&f->wheel) == VIREO_OK);
    vireo_timer_wheel_options_t const options = {{0, 1, 2}, VIREO_TIMER_WHEEL_MAX_MEMORY};
    vireo_timer_wheel_registry_options_t const registry = {1,
                                                           VIREO_TIMER_WHEEL_REGISTRY_MAX_MEMORY};
    CHECK(vireo_timer_wheel_create(&options, &f->wheel) == VIREO_OK);
    CHECK(vireo_timer_wheel_prepare(f->wheel, &registry) == VIREO_OK);
    CHECK(register_at(f, 0, 0, UINT64_MAX - 2, UINT64_MAX - 1) && save_at(f, 0));
    CHECK(rearm_ok(f, 0, UINT64_MAX - 1, UINT64_MAX, UINT64_MAX, 1));
    return true;
}
static bool test_client_reuse(fixture_t *f) {
    CHECK(register_at(f, 0, 0, 100, 110) && save_at(f, 0));
    vireo_connection_pool_lease_t const old = f->clients[0];
    CHECK(vireo_tcp_server_release_client(f->server, &f->clients[0], NULL) == VIREO_OK);
    CHECK(close(f->peers[0]) == 0);
    f->peers[0] = -1;
    CHECK(add_client(f, 0));
    CHECK(old.slot_index == f->clients[0].slot_index && old.generation != f->clients[0].generation);
    CHECK(rearm_fails(f, f->server, f->wheel, f->bindings[0], 100, 130, VIREO_RESULT_NOT_FOUND,
                      VIREO_CLIENT_DEADLINE_CHECK_CLIENT));
    CHECK(register_at(f, 1, 0, 100, 140) && save_at(f, 1));
    CHECK(rearm_ok(f, 1, 100, 150, 5, 1) && count_is(f, 2));
    return true;
}
static bool test_other_owner(fixture_t *f) {
    CHECK(register_at(f, 0, 0, 100, 110) && register_at(f, 2, 1, 100, 120));
    CHECK(save_at(f, 0) && save_at(f, 2));
    CHECK(rearm_ok(f, 2, 100, 140, 4, 0));
    vireo_timer_wheel_timer_info_t info;
    CHECK(vireo_timer_wheel_get(f->wheel, f->bindings[0].timer, &info) == VIREO_OK);
    CHECK(info.deadline_ns == 110 && count_is(f, 2));
    return true;
}

/** 场景索引，既不保存业务资源，也不是生产调度。 */
typedef struct test_case {
    char const *name;         /**< 静态场景名。 */
    bool (*run)(fixture_t *); /**< 同步断言入口。 */
} test_case_t;
int main(void) {
    test_case_t const cases[] = {{"stable diagnostic numbers", test_enum},
                                 {"future rearm preserves identity and table", test_future},
                                 {"shortening and upward boundary", test_shortening},
                                 {"nulls and binding shapes", test_nulls_shapes},
                                 {"client dependency priority", test_client_dependencies},
                                 {"timer dependency priority", test_timer_dependencies},
                                 {"checked time errors preserve deadlines", test_time_errors},
                                 {"identity before stop before time", test_stop},
                                 {"ready notification withdrawn", test_ready_withdraw},
                                 {"failed ready rearm preserves notification", test_ready_failure},
                                 {"elapsed active timer explicitly rearmed", test_elapsed_active},
                                 {"taken timer cannot revive", test_taken},
                                 {"cancelled same slot old generation", test_cancelled_reuse},
                                 {"pending and ready rearm during bounded advance", test_pending},
                                 {"current closing client", test_closing},
                                 {"table membership is independent", test_table_independent},
                                 {"full wheel and same client multiple timers", test_full_identity},
                                 {"actual client registration to bounded delivery", test_chain},
                                 {"maximum is finite without overflow", test_max_finite},
                                 {"client slot reuse rejects old lease", test_client_reuse},
                                 {"different owner unaffected", test_other_owner}};
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
