/*
 * PROJECT : VIREO
 * FILE    : test_client_deadline_idle.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-10
 * BRIEF   : 此模块负责：
 * -- 验证根据实际传输字节刷新显式空闲期限
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
#include <vireo/base/clock.h>
#include <vireo/net/client_deadline_idle.h>
#include <vireo/net/client_deadline_store.h>
#include <vireo/timer/wheel_shutdown.h>

#define CHECK(expr)                                                    \
    do {                                                               \
        if (!(expr)) {                                                 \
            fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #expr); \
            return false;                                              \
        }                                                              \
    } while (0)
#define CALL(expr, expected)         \
    do {                             \
        errno = EDOM;                \
        CHECK((expr) == (expected)); \
        CHECK(errno == EDOM);        \
    } while (0)

/** 真实 loopback 客户与独立公开轮，时间算例显式使用合成域。 */
typedef struct fixture {
    vireo_tcp_server_t *server;               /**< 拥有当前客户与 listener。 */
    vireo_tcp_server_t *other_server;         /**< 独立 pool，核验跨所属拒绝。 */
    vireo_timer_wheel_t *wheel;               /**< 正常已 prepare 的容量二轮。 */
    vireo_timer_wheel_t *other_wheel;         /**< 独立 timer owner。 */
    vireo_timer_wheel_t *unprepared;          /**< 尚未 prepare，核验拒绝。 */
    vireo_client_deadline_store_t *store;     /**< 独立数值反查表，不拥有 timer。 */
    vireo_connection_pool_lease_t clients[2]; /**< 当前客户租约，归还清零。 */
    int peers[2];                             /**< caller 对端 socket owner，-1 为空。 */
    vireo_client_deadline_idle_t idles[2];    /**< caller 记录，取消清整个值。 */
    int listener_fd;                          /**< 创建期 socket owner，转移后 -1。 */
    vireo_acceptor_t *listener;               /**< 创建期 acceptor owner，收纳后 NULL。 */
    struct sockaddr_in address;               /**< loopback 临时接入端点。 */
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
    for (size_t i = 0; i < 2; ++i) {
        if (f->idles[i].binding.timer.owner_id != 0) {
            vireo_client_deadline_binding_t record;
            vireo_result_t r =
                vireo_client_deadline_store_withdraw(f->store, f->idles[i].binding.timer, &record);
            CHECK(r == VIREO_OK || r == VIREO_RESULT_NOT_FOUND);
            r = vireo_client_deadline_idle_cancel(f->wheel, &f->idles[i], NULL);
            CHECK(r == VIREO_OK || r == VIREO_RESULT_NOT_FOUND);
            f->idles[i] = (vireo_client_deadline_idle_t){0};
        }
    }
    CHECK(vireo_client_deadline_store_destroy(&f->store) == VIREO_OK);
    CHECK(vireo_timer_wheel_destroy(&f->wheel) == VIREO_OK);
    CHECK(vireo_timer_wheel_destroy(&f->other_wheel) == VIREO_OK);
    CHECK(vireo_timer_wheel_destroy(&f->unprepared) == VIREO_OK);
    for (size_t i = 0; i < 2; ++i) {
        if (f->clients[i].pool_id != 0)
            CHECK(vireo_tcp_server_release_client(f->server, &f->clients[i], NULL) == VIREO_OK);
        if (f->peers[i] >= 0)
            CHECK(close(f->peers[i]) == 0);
    }
    if (f->listener_fd >= 0)
        CHECK(close(f->listener_fd) == 0);
    CHECK(vireo_acceptor_destroy(&f->listener, NULL) == VIREO_OK);
    CHECK(vireo_tcp_server_destroy(&f->server, NULL) == VIREO_OK);
    CHECK(vireo_tcp_server_destroy(&f->other_server, NULL) == VIREO_OK);
    return true;
}
static bool start(fixture_t *f, size_t i, uint64_t now, uint64_t interval) {
    vireo_client_deadline_stage_t stage = VIREO_CLIENT_DEADLINE_MATCH_TIMER;
    CALL(vireo_client_deadline_idle_start(f->server, f->wheel, f->clients[i], now, interval,
                                          &f->idles[i], &stage),
         VIREO_OK);
    CHECK(stage == VIREO_CLIENT_DEADLINE_NONE);
    return true;
}
static bool timer_is(fixture_t *f, size_t i, uint64_t deadline) {
    vireo_timer_wheel_timer_info_t info;
    CALL(vireo_timer_wheel_get(f->wheel, f->idles[i].binding.timer, &info), VIREO_OK);
    CHECK(info.deadline_ns == deadline);
    return true;
}
static bool advance(vireo_timer_wheel_t *wheel, uint64_t now) {
    vireo_timer_wheel_advance_report_t report;
    CALL(vireo_timer_wheel_advance(wheel, now, (vireo_timer_wheel_advance_budget_t){32, 32},
                                   &report),
         VIREO_OK);
    CHECK(report.progress.caught_up);
    return true;
}
static bool reset_wheel(fixture_t *f, uint64_t origin, uint64_t tick) {
    CHECK(vireo_timer_wheel_destroy(&f->wheel) == VIREO_OK);
    vireo_timer_wheel_options_t const options = {{origin, tick, 4}, VIREO_TIMER_WHEEL_MAX_MEMORY};
    vireo_timer_wheel_registry_options_t const registry = {2,
                                                           VIREO_TIMER_WHEEL_REGISTRY_MAX_MEMORY};
    CHECK(vireo_timer_wheel_create(&options, &f->wheel) == VIREO_OK);
    CHECK(vireo_timer_wheel_prepare(f->wheel, &registry) == VIREO_OK);
    return true;
}
static bool same_timer_info(vireo_timer_wheel_timer_info_t a, vireo_timer_wheel_timer_info_t b) {
    return a.deadline_ns == b.deadline_ns && a.due_tick == b.due_tick &&
           a.bucket_index == b.bucket_index;
}
/** 失败与无活动不动：核对完整记录字节、公开 timer、容量与推进快照；同时检验可空诊断。 */
static bool unchanged_refresh(fixture_t *f, vireo_tcp_server_t const *server,
                              vireo_timer_wheel_t *wheel, vireo_client_deadline_idle_t const *idle,
                              uint64_t now, size_t received, size_t sent, vireo_result_t expected,
                              vireo_client_deadline_stage_t stage) {
    unsigned char bytes[sizeof *idle];
    memcpy(bytes, idle, sizeof bytes);
    vireo_timer_wheel_registry_info_t registry;
    vireo_timer_wheel_progress_t progress;
    vireo_timer_wheel_timer_info_t timer;
    CHECK(vireo_timer_wheel_registry_inspect(f->wheel, &registry) == VIREO_OK);
    CHECK(vireo_timer_wheel_progress_inspect(f->wheel, &progress) == VIREO_OK);
    vireo_result_t const timer_result =
        vireo_timer_wheel_get(f->wheel, idle->binding.timer, &timer);
    for (size_t pass = 0; pass < 2; ++pass) {
        vireo_client_deadline_stage_t diagnostic = VIREO_CLIENT_DEADLINE_MATCH_TIMER;
        CALL(vireo_client_deadline_idle_refresh(server, wheel, idle, now, received, sent,
                                                pass == 0 ? &diagnostic : NULL),
             expected);
        CHECK(pass != 0 || diagnostic == stage);
        CHECK(memcmp(bytes, idle, sizeof bytes) == 0);
        vireo_timer_wheel_registry_info_t after;
        vireo_timer_wheel_progress_t p;
        vireo_timer_wheel_timer_info_t t;
        CHECK(vireo_timer_wheel_registry_inspect(f->wheel, &after) == VIREO_OK);
        CHECK(after.prepared == registry.prepared && after.capacity == registry.capacity &&
              after.active_count == registry.active_count &&
              after.available_count == registry.available_count &&
              after.allocation_bytes == registry.allocation_bytes &&
              after.max_memory_bytes == registry.max_memory_bytes);
        CHECK(vireo_timer_wheel_progress_inspect(f->wheel, &p) == VIREO_OK);
        CHECK(p.latest_now_ns == progress.latest_now_ns && p.target_tick == progress.target_tick &&
              p.completed_tick == progress.completed_tick && p.processing == progress.processing &&
              p.ready_count == progress.ready_count && p.caught_up == progress.caught_up);
        CHECK(vireo_timer_wheel_get(f->wheel, idle->binding.timer, &t) == timer_result);
        CHECK(timer_result != VIREO_OK || same_timer_info(timer, t));
    }
    return true;
}
static bool start_fails(fixture_t *f, vireo_tcp_server_t const *server, vireo_timer_wheel_t *wheel,
                        vireo_connection_pool_lease_t client, uint64_t now, uint64_t interval,
                        vireo_result_t expected, vireo_client_deadline_stage_t expected_stage) {
    vireo_client_deadline_idle_t idle;
    memset(&idle, 0, sizeof idle);
    unsigned char before[sizeof idle];
    memcpy(before, &idle, sizeof before);
    vireo_timer_wheel_registry_info_t registry;
    CHECK(vireo_timer_wheel_registry_inspect(f->wheel, &registry) == VIREO_OK);
    for (size_t pass = 0; pass < 2; ++pass) {
        vireo_client_deadline_stage_t stage = VIREO_CLIENT_DEADLINE_MATCH_TIMER;
        CALL(vireo_client_deadline_idle_start(server, wheel, client, now, interval, &idle,
                                              pass == 0 ? &stage : NULL),
             expected);
        CHECK(pass != 0 || stage == expected_stage);
        CHECK(memcmp(before, &idle, sizeof before) == 0);
        vireo_timer_wheel_registry_info_t after;
        CHECK(vireo_timer_wheel_registry_inspect(f->wheel, &after) == VIREO_OK);
        CHECK(after.active_count == registry.active_count &&
              after.available_count == registry.available_count);
    }
    return true;
}

static bool test_start_cancel(fixture_t *f) {
    CHECK(VIREO_CLIENT_DEADLINE_NONE == 0 && VIREO_CLIENT_DEADLINE_RELEASE_CLIENT == 9 &&
          VIREO_CLIENT_DEADLINE_CHECK_IDLE_STATE == 10 &&
          VIREO_CLIENT_DEADLINE_CHECK_IDLE_TIME == 11);
    CHECK(start(f, 0, 120, 51) && timer_is(f, 0, 171));
    vireo_timer_wheel_timer_info_t info;
    CHECK(vireo_timer_wheel_get(f->wheel, f->idles[0].binding.timer, &info) == VIREO_OK);
    CHECK(info.due_tick == 8 && info.bucket_index == 0 && f->idles[0].idle_timeout_ns == 51);
    vireo_client_deadline_idle_t copy = f->idles[0];
    vireo_client_deadline_stage_t stage = VIREO_CLIENT_DEADLINE_MATCH_TIMER;
    CALL(vireo_client_deadline_idle_cancel(f->wheel, &f->idles[0], &stage), VIREO_OK);
    CHECK(stage == VIREO_CLIENT_DEADLINE_NONE && f->idles[0].idle_timeout_ns == 0 &&
          f->idles[0].binding.client.pool_id == 0 && f->idles[0].binding.timer.owner_id == 0);
    CHECK(copy.binding.timer.owner_id != 0);
    CALL(vireo_timer_wheel_get(f->wheel, copy.binding.timer, &info), VIREO_RESULT_NOT_FOUND);
    vireo_tcp_server_client_info_t client;
    CHECK(vireo_tcp_server_client_inspect(f->server, f->clients[0], &client) == VIREO_OK);
    CHECK(client.connection_info.close_state == VIREO_CONNECTION_CLOSE_OPEN);
    return true;
}
static bool test_start_basic(fixture_t *f) {
    CHECK(start_fails(f, NULL, f->wheel, f->clients[0], 120, 50, VIREO_RESULT_INVALID_ARGUMENT,
                      VIREO_CLIENT_DEADLINE_NONE));
    CHECK(start_fails(f, f->server, NULL, f->clients[0], 120, 50, VIREO_RESULT_INVALID_ARGUMENT,
                      VIREO_CLIENT_DEADLINE_NONE));
    CHECK(start_fails(f, f->server, f->wheel, f->clients[0], 120, 0, VIREO_RESULT_INVALID_ARGUMENT,
                      VIREO_CLIENT_DEADLINE_NONE));
    CHECK(start_fails(f, f->server, f->wheel, (vireo_connection_pool_lease_t){0}, 120, 50,
                      VIREO_RESULT_NOT_FOUND, VIREO_CLIENT_DEADLINE_NONE));
    CALL(vireo_client_deadline_idle_start(f->server, f->wheel, f->clients[0], 120, 50, NULL, NULL),
         VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(start(f, 0, 120, 50));
    unsigned char copy[sizeof f->idles[0]];
    memcpy(copy, &f->idles[0], sizeof copy);
    CALL(vireo_client_deadline_idle_start(f->server, f->wheel, f->clients[0], 120, 50, &f->idles[0],
                                          NULL),
         VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(memcmp(copy, &f->idles[0], sizeof copy) == 0);
    return true;
}
static bool test_basic_refresh_cancel(fixture_t *f) {
    CHECK(start(f, 0, 120, 50));
    CHECK(unchanged_refresh(f, NULL, f->wheel, &f->idles[0], 121, 1, 0,
                            VIREO_RESULT_INVALID_ARGUMENT, VIREO_CLIENT_DEADLINE_NONE));
    CHECK(unchanged_refresh(f, f->server, NULL, &f->idles[0], 121, 1, 0,
                            VIREO_RESULT_INVALID_ARGUMENT, VIREO_CLIENT_DEADLINE_NONE));
    vireo_client_deadline_stage_t stage = VIREO_CLIENT_DEADLINE_MATCH_TIMER;
    CALL(vireo_client_deadline_idle_refresh(f->server, f->wheel, NULL, 121, 1, 0, &stage),
         VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(stage == VIREO_CLIENT_DEADLINE_NONE);
    CALL(vireo_client_deadline_idle_cancel(f->wheel, NULL, &stage), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(stage == VIREO_CLIENT_DEADLINE_NONE);
    CALL(vireo_client_deadline_idle_cancel(NULL, &f->idles[0], &stage),
         VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(stage == VIREO_CLIENT_DEADLINE_NONE && timer_is(f, 0, 170));
    vireo_client_deadline_idle_t empty = {0};
    CHECK(unchanged_refresh(f, f->server, f->wheel, &empty, 121, 1, 0, VIREO_RESULT_NOT_FOUND,
                            VIREO_CLIENT_DEADLINE_NONE));
    CALL(vireo_client_deadline_idle_cancel(f->wheel, &empty, &stage), VIREO_RESULT_NOT_FOUND);
    CHECK(stage == VIREO_CLIENT_DEADLINE_NONE);
    return true;
}
static bool test_shapes(fixture_t *f) {
    CHECK(start(f, 0, 120, 50));
    for (size_t i = 0; i < 5; ++i) {
        vireo_client_deadline_idle_t bad = f->idles[0];
        if (i == 0)
            bad.binding.client = (vireo_connection_pool_lease_t){0};
        if (i == 1)
            bad.binding.timer = (vireo_timer_handle_t){0};
        if (i == 2)
            bad.idle_timeout_ns = 0;
        if (i == 3)
            bad.binding.client.generation = 0;
        if (i == 4)
            bad.binding.timer.owner_id = 0;
        CHECK(unchanged_refresh(f, f->server, f->wheel, &bad, 121, 1, 0,
                                VIREO_RESULT_INVALID_ARGUMENT, VIREO_CLIENT_DEADLINE_NONE));
        unsigned char before[sizeof bad];
        memcpy(before, &bad, sizeof before);
        CALL(vireo_client_deadline_idle_cancel(f->wheel, &bad, NULL),
             VIREO_RESULT_INVALID_ARGUMENT);
        CHECK(memcmp(before, &bad, sizeof before) == 0);
    }
    return true;
}
static bool test_ready(fixture_t *f) {
    CHECK(start(f, 0, 120, 50));
    CHECK(vireo_tcp_server_client_request_close(
              f->server, f->clients[0], VIREO_CONNECTION_CLOSE_MODE_IMMEDIATE,
              VIREO_CONNECTION_CLOSE_REASON_APPLICATION, NULL) == VIREO_OK);
    CHECK(start_fails(f, f->server, f->wheel, f->clients[0], 120, 50, VIREO_RESULT_BUSY,
                      VIREO_CLIENT_DEADLINE_CHECK_IDLE_STATE));
    CHECK(unchanged_refresh(f, f->server, f->wheel, &f->idles[0], 121, 1, 0, VIREO_RESULT_BUSY,
                            VIREO_CLIENT_DEADLINE_CHECK_IDLE_STATE));
    CALL(vireo_client_deadline_idle_cancel(f->wheel, &f->idles[0], NULL), VIREO_OK);
    return true;
}
static bool test_draining(fixture_t *f) {
    CHECK(start(f, 0, 120, 50));
    uint8_t const bytes[] = {1, 2, 3};
    CHECK(vireo_tcp_server_client_write_enqueue(f->server, f->clients[0], bytes, sizeof bytes,
                                                NULL) == VIREO_OK);
    CHECK(vireo_tcp_server_client_request_close(
              f->server, f->clients[0], VIREO_CONNECTION_CLOSE_MODE_DRAIN,
              VIREO_CONNECTION_CLOSE_REASON_APPLICATION, NULL) == VIREO_OK);
    vireo_tcp_server_client_info_t info;
    CHECK(vireo_tcp_server_client_inspect(f->server, f->clients[0], &info) == VIREO_OK);
    CHECK(info.connection_info.close_state == VIREO_CONNECTION_CLOSE_DRAINING);
    CHECK(start_fails(f, f->server, f->wheel, f->clients[0], 120, 50, VIREO_RESULT_BUSY,
                      VIREO_CLIENT_DEADLINE_CHECK_IDLE_STATE));
    CHECK(unchanged_refresh(f, f->server, f->wheel, &f->idles[0], 121, 0, 1, VIREO_RESULT_BUSY,
                            VIREO_CLIENT_DEADLINE_CHECK_IDLE_STATE));
    return true;
}
static bool test_clients(fixture_t *f) {
    CHECK(start(f, 0, 120, 50));
    CHECK(unchanged_refresh(f, f->other_server, f->wheel, &f->idles[0], 121, 1, 0,
                            VIREO_RESULT_INVALID_ARGUMENT, VIREO_CLIENT_DEADLINE_CHECK_CLIENT));
    vireo_client_deadline_idle_t bad = f->idles[0];
    bad.binding.client.slot_index = SIZE_MAX;
    CHECK(unchanged_refresh(f, f->server, f->wheel, &bad, 121, 1, 0, VIREO_RESULT_RANGE,
                            VIREO_CLIENT_DEADLINE_CHECK_CLIENT));
    CHECK(start_fails(f, f->server, f->wheel, bad.binding.client, 120, 50, VIREO_RESULT_RANGE,
                      VIREO_CLIENT_DEADLINE_CHECK_CLIENT));
    bad = f->idles[0];
    ++bad.binding.client.generation;
    CHECK(unchanged_refresh(f, f->server, f->wheel, &bad, 121, 1, 0, VIREO_RESULT_NOT_FOUND,
                            VIREO_CLIENT_DEADLINE_CHECK_CLIENT));
    return true;
}
static bool test_timers(fixture_t *f) {
    CHECK(start(f, 0, 120, 50));
    CHECK(unchanged_refresh(f, f->server, f->other_wheel, &f->idles[0], 121, 1, 0,
                            VIREO_RESULT_INVALID_ARGUMENT, VIREO_CLIENT_DEADLINE_CHECK_TIMER));
    vireo_client_deadline_idle_t bad = f->idles[0];
    bad.binding.timer.slot_index = SIZE_MAX;
    CHECK(unchanged_refresh(f, f->server, f->wheel, &bad, 121, 1, 0, VIREO_RESULT_RANGE,
                            VIREO_CLIENT_DEADLINE_CHECK_TIMER));
    bad = f->idles[0];
    ++bad.binding.timer.generation;
    CHECK(unchanged_refresh(f, f->server, f->wheel, &bad, 121, 1, 0, VIREO_RESULT_NOT_FOUND,
                            VIREO_CLIENT_DEADLINE_CHECK_TIMER));
    CHECK(unchanged_refresh(f, f->server, f->unprepared, &f->idles[0], 121, 1, 0,
                            VIREO_RESULT_NOT_FOUND, VIREO_CLIENT_DEADLINE_CHECK_TIMER));
    return true;
}
static bool test_stop(fixture_t *f) {
    CHECK(start_fails(f, f->server, f->unprepared, f->clients[0], 120, 50, VIREO_RESULT_NOT_FOUND,
                      VIREO_CLIENT_DEADLINE_CHECK_TIMER));
    CHECK(start(f, 0, 120, 50));
    CHECK(vireo_timer_wheel_shutdown_begin(f->wheel) == VIREO_OK);
    CHECK(start_fails(f, f->server, f->wheel, f->clients[1], 0, UINT64_MAX, VIREO_RESULT_CANCELLED,
                      VIREO_CLIENT_DEADLINE_CHECK_TIMER));
    CHECK(unchanged_refresh(f, f->server, f->wheel, &f->idles[0], 0, 0, 0, VIREO_RESULT_CANCELLED,
                            VIREO_CLIENT_DEADLINE_CHECK_TIMER));
    CALL(vireo_client_deadline_idle_cancel(f->wheel, &f->idles[0], NULL), VIREO_OK);
    return true;
}
static bool test_time_regression(fixture_t *f) {
    CHECK(start_fails(f, f->server, f->wheel, f->clients[0], 99, 50, VIREO_RESULT_RANGE,
                      VIREO_CLIENT_DEADLINE_CHECK_IDLE_TIME));
    CHECK(start(f, 0, 120, 50));
    CHECK(unchanged_refresh(f, f->server, f->wheel, &f->idles[0], 119, 1, 0, VIREO_RESULT_RANGE,
                            VIREO_CLIENT_DEADLINE_CHECK_IDLE_TIME));
    CHECK(advance(f->wheel, 140));
    CHECK(unchanged_refresh(f, f->server, f->wheel, &f->idles[0], 139, 1, 0, VIREO_RESULT_RANGE,
                            VIREO_CLIENT_DEADLINE_CHECK_IDLE_TIME));
    CHECK(start_fails(f, f->server, f->wheel, f->clients[1], 139, 50, VIREO_RESULT_RANGE,
                      VIREO_CLIENT_DEADLINE_CHECK_IDLE_TIME));
    CALL(vireo_client_deadline_idle_refresh(f->server, f->wheel, &f->idles[0], 140, 1, 0, NULL),
         VIREO_OK);
    CHECK(timer_is(f, 0, 190));
    CHECK(unchanged_refresh(f, f->server, f->wheel, &f->idles[0], 139, 0, 1, VIREO_RESULT_RANGE,
                            VIREO_CLIENT_DEADLINE_CHECK_IDLE_TIME));
    return true;
}
static bool test_zero_activity(fixture_t *f) {
    CHECK(start(f, 0, 120, 50));
    CHECK(unchanged_refresh(f, f->server, f->wheel, &f->idles[0], 169, 0, 0, VIREO_OK,
                            VIREO_CLIENT_DEADLINE_NONE));
    CHECK(unchanged_refresh(f, f->server, f->wheel, &f->idles[0], 119, 0, 0, VIREO_RESULT_RANGE,
                            VIREO_CLIENT_DEADLINE_CHECK_IDLE_TIME));
    CHECK(unchanged_refresh(f, f->server, f->wheel, &f->idles[0], 170, 0, 0, VIREO_RESULT_TIMEOUT,
                            VIREO_CLIENT_DEADLINE_CHECK_IDLE_TIME));
    return true;
}
static bool test_timeout_ready(fixture_t *f) {
    CHECK(start(f, 0, 120, 51));
    CHECK(unchanged_refresh(f, f->server, f->wheel, &f->idles[0], 171, 1, 0, VIREO_RESULT_TIMEOUT,
                            VIREO_CLIENT_DEADLINE_CHECK_IDLE_TIME));
    CHECK(advance(f->wheel, 180));
    CHECK(unchanged_refresh(f, f->server, f->wheel, &f->idles[0], 180, 1, 0, VIREO_RESULT_TIMEOUT,
                            VIREO_CLIENT_DEADLINE_CHECK_IDLE_TIME));
    vireo_timer_wheel_expired_t expired;
    CHECK(vireo_timer_wheel_take_expired(f->wheel, &expired) == VIREO_OK);
    CHECK(expired.timer.deadline_ns == 171);
    CHECK(unchanged_refresh(f, f->server, f->wheel, &f->idles[0], 181, 1, 0, VIREO_RESULT_NOT_FOUND,
                            VIREO_CLIENT_DEADLINE_CHECK_TIMER));
    return true;
}
static bool test_full_table_identity(fixture_t *f) {
    CHECK(start(f, 0, 120, 50) && start(f, 1, 120, 50));
    CHECK(vireo_client_deadline_store_save(f->store, f->server, f->wheel, f->idles[0].binding,
                                           NULL) == VIREO_OK);
    unsigned char record[sizeof f->idles[0]];
    memcpy(record, &f->idles[0], sizeof record);
    CALL(vireo_client_deadline_idle_refresh(f->server, f->wheel, &f->idles[0], 130, SIZE_MAX,
                                            SIZE_MAX, NULL),
         VIREO_OK);
    CHECK(timer_is(f, 0, 180) && memcmp(record, &f->idles[0], sizeof record) == 0);
    vireo_client_deadline_binding_t found;
    CHECK(vireo_client_deadline_store_find(f->store, f->idles[0].binding.timer, &found) ==
          VIREO_OK);
    CHECK(found.timer.generation == f->idles[0].binding.timer.generation);
    vireo_client_deadline_store_info_t info;
    CHECK(vireo_client_deadline_store_inspect(f->store, &info) == VIREO_OK && info.count == 1);
    CHECK(start_fails(f, f->server, f->wheel, f->clients[0], 130, 50, VIREO_RESULT_BUSY,
                      VIREO_CLIENT_DEADLINE_REGISTER_TIMER));
    return true;
}
static bool test_released_cancel(fixture_t *f) {
    CHECK(start(f, 0, 120, 50));
    CHECK(vireo_tcp_server_release_client(f->server, &f->clients[0], NULL) == VIREO_OK);
    CHECK(unchanged_refresh(f, f->server, f->wheel, &f->idles[0], 121, 1, 0, VIREO_RESULT_NOT_FOUND,
                            VIREO_CLIENT_DEADLINE_CHECK_CLIENT));
    CALL(vireo_client_deadline_idle_cancel(f->wheel, &f->idles[0], NULL), VIREO_OK);
    return true;
}
static bool test_stale_cancel(fixture_t *f) {
    CHECK(start(f, 0, 120, 50));
    vireo_timer_handle_t handle = f->idles[0].binding.timer;
    CHECK(vireo_timer_wheel_cancel(f->wheel, &handle) == VIREO_OK);
    unsigned char record[sizeof f->idles[0]];
    memcpy(record, &f->idles[0], sizeof record);
    vireo_client_deadline_stage_t stage = VIREO_CLIENT_DEADLINE_NONE;
    CALL(vireo_client_deadline_idle_cancel(f->wheel, &f->idles[0], &stage), VIREO_RESULT_NOT_FOUND);
    CHECK(stage == VIREO_CLIENT_DEADLINE_CANCEL_TIMER &&
          memcmp(record, &f->idles[0], sizeof record) == 0);
    CHECK(start(f, 1, 120, 50));
    CHECK(unchanged_refresh(f, f->server, f->wheel, &f->idles[0], 121, 1, 0, VIREO_RESULT_NOT_FOUND,
                            VIREO_CLIENT_DEADLINE_CHECK_TIMER));
    return true;
}
static bool test_maximum_finite(fixture_t *f) {
    CHECK(reset_wheel(f, 0, 1) && start(f, 0, 0, UINT64_MAX) && timer_is(f, 0, UINT64_MAX));
    CALL(vireo_client_deadline_idle_refresh(f->server, f->wheel, &f->idles[0], 0, 1, 0, NULL),
         VIREO_OK);
    CHECK(unchanged_refresh(f, f->server, f->wheel, &f->idles[0], 1, 1, 0, VIREO_RESULT_OVERFLOW,
                            VIREO_CLIENT_DEADLINE_CHECK_IDLE_TIME));
    CHECK(unchanged_refresh(f, f->server, f->wheel, &f->idles[0], UINT64_MAX, 0, 0,
                            VIREO_RESULT_TIMEOUT, VIREO_CLIENT_DEADLINE_CHECK_IDLE_TIME));
    return true;
}
static bool test_start_overflow(fixture_t *f) {
    CHECK(start_fails(f, f->server, f->wheel, f->clients[0], 120, UINT64_MAX, VIREO_RESULT_OVERFLOW,
                      VIREO_CLIENT_DEADLINE_CHECK_IDLE_TIME));
    CHECK(reset_wheel(f, UINT64_MAX - 10, 6));
    CHECK(start_fails(f, f->server, f->wheel, f->clients[0], UINT64_MAX - 10, 7,
                      VIREO_RESULT_OVERFLOW, VIREO_CLIENT_DEADLINE_REGISTER_TIMER));
    return true;
}
static bool test_rearm_overflow(fixture_t *f) {
    CHECK(reset_wheel(f, UINT64_MAX - 10, 6) && start(f, 0, UINT64_MAX - 10, 5));
    CHECK(unchanged_refresh(f, f->server, f->wheel, &f->idles[0], UINT64_MAX - 6, 0, 1,
                            VIREO_RESULT_OVERFLOW, VIREO_CLIENT_DEADLINE_REARM_TIMER));
    CHECK(timer_is(f, 0, UINT64_MAX - 5));
    return true;
}
static bool test_bad_interval(fixture_t *f) {
    CHECK(start(f, 0, 120, 50));
    vireo_client_deadline_idle_t bad = f->idles[0];
    bad.idle_timeout_ns = 171;
    CHECK(unchanged_refresh(f, f->server, f->wheel, &bad, 121, 1, 0, VIREO_RESULT_INVALID_ARGUMENT,
                            VIREO_CLIENT_DEADLINE_CHECK_IDLE_TIME));
    return true;
}
static bool test_actual_bytes(fixture_t *f) {
    uint64_t now;
    CHECK(vireo_clock_monotonic_now(&now, NULL) == VIREO_OK);
    CHECK(reset_wheel(f, now, UINT64_C(10000000)) && start(f, 0, now, UINT64_C(3000000000)));
    vireo_client_deadline_idle_t const original = f->idles[0];
    uint8_t const bytes[] = {1, 2, 3};
    CHECK(send(f->peers[0], bytes, sizeof bytes, MSG_NOSIGNAL) == (ssize_t)sizeof bytes);
    vireo_connection_receive_budget_t const receive_budget = {64, 4};
    vireo_connection_receive_info_t receive;
    CHECK(vireo_tcp_server_client_receive(f->server, f->clients[0], &receive_budget, &receive,
                                          NULL) == VIREO_OK);
    CHECK(receive.received_bytes == sizeof bytes);
    CHECK(vireo_clock_monotonic_now(&now, NULL) == VIREO_OK);
    CALL(vireo_client_deadline_idle_refresh(f->server, f->wheel, &f->idles[0], now,
                                            receive.received_bytes, 0, NULL),
         VIREO_OK);
    CHECK(timer_is(f, 0, now + original.idle_timeout_ns));
    CHECK(vireo_tcp_server_client_read_consume(f->server, f->clients[0], sizeof bytes, NULL) ==
          VIREO_OK);
    CHECK(vireo_tcp_server_client_receive(f->server, f->clients[0], &receive_budget, &receive,
                                          NULL) == VIREO_OK);
    CHECK(receive.received_bytes == 0 &&
          receive.stop_reason == VIREO_CONNECTION_RECEIVE_STOP_WOULD_BLOCK);
    CHECK(vireo_clock_monotonic_now(&now, NULL) == VIREO_OK);
    CHECK(unchanged_refresh(f, f->server, f->wheel, &f->idles[0], now, receive.received_bytes, 0,
                            VIREO_OK, VIREO_CLIENT_DEADLINE_NONE));
    CHECK(vireo_tcp_server_client_write_enqueue(f->server, f->clients[0], bytes, sizeof bytes,
                                                NULL) == VIREO_OK);
    CHECK(unchanged_refresh(f, f->server, f->wheel, &f->idles[0], now, 0, 0, VIREO_OK,
                            VIREO_CLIENT_DEADLINE_NONE));
    vireo_connection_send_budget_t const send_budget = {64, 4};
    vireo_connection_send_info_t sent;
    CHECK(vireo_tcp_server_client_send(f->server, f->clients[0], &send_budget, &sent, NULL) ==
          VIREO_OK);
    CHECK(sent.sent_bytes == sizeof bytes);
    CHECK(vireo_clock_monotonic_now(&now, NULL) == VIREO_OK);
    CALL(vireo_client_deadline_idle_refresh(f->server, f->wheel, &f->idles[0], now, 0,
                                            sent.sent_bytes, NULL),
         VIREO_OK);
    CHECK(timer_is(f, 0, now + original.idle_timeout_ns));
    CHECK(f->idles[0].binding.timer.generation == original.binding.timer.generation);
    uint8_t read_bytes[3];
    CHECK(recv(f->peers[0], read_bytes, sizeof read_bytes, MSG_DONTWAIT) ==
          (ssize_t)sizeof read_bytes);
    CHECK(memcmp(bytes, read_bytes, sizeof bytes) == 0);
    return true;
}
static bool test_expiry_chain(fixture_t *f) {
    CHECK(start(f, 0, 120, 50));
    CALL(vireo_client_deadline_idle_refresh(f->server, f->wheel, &f->idles[0], 130, 1, 0, NULL),
         VIREO_OK);
    CHECK(advance(f->wheel, 180));
    vireo_timer_wheel_expired_t expired;
    CHECK(vireo_timer_wheel_take_expired(f->wheel, &expired) == VIREO_OK);
    vireo_tcp_server_client_info_t info;
    CHECK(vireo_client_deadline_check_expired(f->server, f->idles[0].binding, &expired, &info,
                                              NULL) == VIREO_OK);
    CHECK(info.connection_info.close_state == VIREO_CONNECTION_CLOSE_OPEN);
    vireo_client_deadline_close_error_t error;
    CHECK(vireo_client_deadline_request_close_expired(
              f->server, f->idles[0].binding, &expired, VIREO_CONNECTION_CLOSE_MODE_IMMEDIATE,
              VIREO_CONNECTION_CLOSE_REASON_APPLICATION, &error) == VIREO_OK);
    vireo_client_deadline_release_report_t report;
    CHECK(vireo_client_deadline_release_ready_expired(f->server, &f->idles[0].binding, &expired,
                                                      &report) == VIREO_OK);
    CHECK(report.client_consumed && report.release_called &&
          f->idles[0].binding.client.pool_id == 0);
    /* 已消费后 caller 清完整 idle，旧 clients 副本仍由 caller 显式结束。 */
    f->idles[0] = (vireo_client_deadline_idle_t){0};
    f->clients[0] = (vireo_connection_pool_lease_t){0};
    return true;
}

/** 仅测试驱动，无产品回调或保存的业务状态。 */
typedef struct test_case {
    char const *name;         /**< 静态场景名，输出真实组结果。 */
    bool (*run)(fixture_t *); /**< 同步公开 fixture 场景入口。 */
} test_case_t;
int main(void) {
    test_case_t const cases[] = {
        {"start cancel and stable stages", test_start_cancel},
        {"start basic errors keep output", test_start_basic},
        {"refresh cancel nulls and empty", test_basic_refresh_cancel},
        {"half empty malformed records", test_shapes},
        {"READY rejects start refresh", test_ready},
        {"DRAINING rejects start refresh", test_draining},
        {"client currentness and owner", test_clients},
        {"timer currentness and owner", test_timers},
        {"prepare stop before time cancel allowed", test_stop},
        {"fresh sample and activity regression", test_time_regression},
        {"zero progress never renews", test_zero_activity},
        {"exact expiry cannot revive ready or taken", test_timeout_ready},
        {"full wheel refresh keeps table key", test_full_table_identity},
        {"released customer can cancel", test_released_cancel},
        {"stale cancellation is not success", test_stale_cancel},
        {"zero origin maximum finite deadline", test_maximum_finite},
        {"start addition and quantization overflow", test_start_overflow},
        {"rearm quantization overflow preserves original", test_rearm_overflow},
        {"malformed interval checked before subtraction", test_bad_interval},
        {"real partial bytes EAGAIN enqueue and send", test_actual_bytes},
        {"idle expiry explicit close release chain", test_expiry_chain},
    };
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
