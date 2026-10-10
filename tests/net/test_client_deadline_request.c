/*
 * PROJECT : VIREO
 * FILE    : test_client_deadline_request.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-10
 * BRIEF   : 此模块负责：
 * -- 验证显式请求固定总期限登记、查询及取消
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
#include <vireo/net/client_deadline_request.h>
#include <vireo/net/client_deadline_store.h>
#include <vireo/protocol/codec.h>
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
    vireo_tcp_server_t *server;                  /**< 拥有当前客户与 listener。 */
    vireo_tcp_server_t *other_server;            /**< 独立 pool，核验跨所属拒绝。 */
    vireo_timer_wheel_t *wheel;                  /**< 正常已 prepare 的容量二轮。 */
    vireo_timer_wheel_t *other_wheel;            /**< 独立 timer owner。 */
    vireo_timer_wheel_t *unprepared;             /**< 尚未 prepare，核验拒绝。 */
    vireo_client_deadline_store_t *store;        /**< 独立数值反查表，不拥有 timer。 */
    vireo_connection_pool_lease_t clients[2];    /**< 当前客户租约，归还清零。 */
    int peers[2];                                /**< caller 对端 socket owner，-1 为空。 */
    vireo_client_deadline_request_t requests[2]; /**< caller 请求记录，取消清整个值。 */
    int listener_fd;                             /**< 创建期 socket owner，转移后 -1。 */
    vireo_acceptor_t *listener; /**< 创建期 acceptor owner，收纳后 NULL。 */
    struct sockaddr_in address; /**< loopback 临时接入端点。 */
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
        if (f->requests[i].binding.timer.owner_id != 0) {
            vireo_client_deadline_binding_t record;
            vireo_result_t r = vireo_client_deadline_store_withdraw(
                f->store, f->requests[i].binding.timer, &record);
            CHECK(r == VIREO_OK || r == VIREO_RESULT_NOT_FOUND);
            r = vireo_client_deadline_request_cancel(f->wheel, &f->requests[i], NULL);
            CHECK(r == VIREO_OK || r == VIREO_RESULT_NOT_FOUND);
            f->requests[i] = (vireo_client_deadline_request_t){0};
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
static bool advance(vireo_timer_wheel_t *wheel, uint64_t now) {
    vireo_timer_wheel_advance_report_t report;
    CALL(vireo_timer_wheel_advance(wheel, now, (vireo_timer_wheel_advance_budget_t){32, 32},
                                   &report),
         VIREO_OK);
    CHECK(report.progress.caught_up);
    return true;
}
static bool reset_wheel_capacity(fixture_t *f, uint64_t origin, uint64_t tick, size_t capacity) {
    CHECK(vireo_timer_wheel_destroy(&f->wheel) == VIREO_OK);
    vireo_timer_wheel_options_t const options = {{origin, tick, 4}, VIREO_TIMER_WHEEL_MAX_MEMORY};
    vireo_timer_wheel_registry_options_t const registry = {capacity,
                                                           VIREO_TIMER_WHEEL_REGISTRY_MAX_MEMORY};
    CHECK(vireo_timer_wheel_create(&options, &f->wheel) == VIREO_OK);
    CHECK(vireo_timer_wheel_prepare(f->wheel, &registry) == VIREO_OK);
    return true;
}
static bool reset_wheel(fixture_t *f, uint64_t origin, uint64_t tick) {
    return reset_wheel_capacity(f, origin, tick, 2);
}
static bool same_timer_info(vireo_timer_wheel_timer_info_t a, vireo_timer_wheel_timer_info_t b) {
    return a.deadline_ns == b.deadline_ns && a.due_tick == b.due_tick &&
           a.bucket_index == b.bucket_index;
}

static bool start(fixture_t *f, size_t i, uint32_t sequence, uint64_t now, uint64_t interval) {
    vireo_client_deadline_request_stage_t stage = VIREO_CLIENT_DEADLINE_REQUEST_CANCEL_TIMER;
    CALL(vireo_client_deadline_request_start(f->server, f->wheel, f->clients[i], sequence, now,
                                             interval, &f->requests[i], &stage),
         VIREO_OK);
    CHECK(stage == VIREO_CLIENT_DEADLINE_REQUEST_NONE);
    return true;
}
/** 全查询不动记录／timer／进度／资源；失败 bool 全字节保持，可空诊断行为一致。 */
static bool query(fixture_t *f, vireo_tcp_server_t const *server, vireo_timer_wheel_t const *wheel,
                  vireo_client_deadline_request_t const *request, uint64_t now,
                  vireo_result_t expected, vireo_client_deadline_request_stage_t expected_stage,
                  bool expired) {
    unsigned char bytes[sizeof *request];
    memcpy(bytes, request, sizeof bytes);
    vireo_timer_wheel_timer_info_t timer;
    vireo_result_t const timer_result =
        vireo_timer_wheel_get(f->wheel, request->binding.timer, &timer);
    vireo_timer_wheel_registry_info_t registry;
    vireo_timer_wheel_progress_t progress;
    CHECK(vireo_timer_wheel_registry_inspect(f->wheel, &registry) == VIREO_OK);
    CHECK(vireo_timer_wheel_progress_inspect(f->wheel, &progress) == VIREO_OK);
    for (size_t pass = 0; pass < 2; ++pass) {
        bool output = pass == 0;
        unsigned char before[sizeof output];
        memcpy(before, &output, sizeof before);
        vireo_client_deadline_request_stage_t stage = VIREO_CLIENT_DEADLINE_REQUEST_CANCEL_TIMER;
        CALL(vireo_client_deadline_request_check(server, wheel, request, now, &output,
                                                 pass == 0 ? &stage : NULL),
             expected);
        CHECK(pass != 0 || stage == expected_stage);
        CHECK(expected != VIREO_OK || output == expired);
        CHECK(expected == VIREO_OK || memcmp(before, &output, sizeof output) == 0);
        CHECK(memcmp(bytes, request, sizeof bytes) == 0);
        vireo_timer_wheel_timer_info_t t;
        CHECK(vireo_timer_wheel_get(f->wheel, request->binding.timer, &t) == timer_result);
        CHECK(timer_result != VIREO_OK || same_timer_info(timer, t));
        vireo_timer_wheel_registry_info_t a;
        CHECK(vireo_timer_wheel_registry_inspect(f->wheel, &a) == VIREO_OK);
        CHECK(a.capacity == registry.capacity && a.active_count == registry.active_count &&
              a.available_count == registry.available_count &&
              a.allocation_bytes == registry.allocation_bytes &&
              a.max_memory_bytes == registry.max_memory_bytes && a.prepared == registry.prepared);
        vireo_timer_wheel_progress_t b;
        CHECK(vireo_timer_wheel_progress_inspect(f->wheel, &b) == VIREO_OK);
        CHECK(b.latest_now_ns == progress.latest_now_ns && b.target_tick == progress.target_tick &&
              b.completed_tick == progress.completed_tick && b.processing == progress.processing &&
              b.ready_count == progress.ready_count && b.caught_up == progress.caught_up);
    }
    return true;
}
static bool start_fails(fixture_t *f, vireo_tcp_server_t const *server, vireo_timer_wheel_t *wheel,
                        vireo_connection_pool_lease_t client, uint32_t sequence, uint64_t now,
                        uint64_t interval, vireo_result_t expected,
                        vireo_client_deadline_request_stage_t expected_stage) {
    vireo_client_deadline_request_t request;
    memset(&request, 0, sizeof request);
    unsigned char before[sizeof request];
    memcpy(before, &request, sizeof before);
    vireo_timer_wheel_registry_info_t registry;
    CHECK(vireo_timer_wheel_registry_inspect(f->wheel, &registry) == VIREO_OK);
    for (size_t pass = 0; pass < 2; ++pass) {
        vireo_client_deadline_request_stage_t stage = VIREO_CLIENT_DEADLINE_REQUEST_CANCEL_TIMER;
        CALL(vireo_client_deadline_request_start(server, wheel, client, sequence, now, interval,
                                                 &request, pass == 0 ? &stage : NULL),
             expected);
        CHECK(pass != 0 || stage == expected_stage);
        CHECK(memcmp(before, &request, sizeof before) == 0);
        vireo_timer_wheel_registry_info_t after;
        CHECK(vireo_timer_wheel_registry_inspect(f->wheel, &after) == VIREO_OK);
        CHECK(after.active_count == registry.active_count &&
              after.available_count == registry.available_count);
    }
    return true;
}
static bool cancel_fails(vireo_timer_wheel_t *wheel, vireo_client_deadline_request_t *request,
                         vireo_result_t expected,
                         vireo_client_deadline_request_stage_t expected_stage) {
    unsigned char before[sizeof *request];
    memcpy(before, request, sizeof before);
    for (size_t pass = 0; pass < 2; ++pass) {
        vireo_client_deadline_request_stage_t stage = VIREO_CLIENT_DEADLINE_REQUEST_CHECK_TIME;
        CALL(vireo_client_deadline_request_cancel(wheel, request, pass == 0 ? &stage : NULL),
             expected);
        CHECK(pass != 0 || stage == expected_stage);
        CHECK(memcmp(before, request, sizeof before) == 0);
    }
    return true;
}
static bool test_basic_chain(fixture_t *f) {
    CHECK(start(f, 0, 7, 120, 51));
    CHECK(f->requests[0].request_sequence == 7 && f->requests[0].started_ns == 120 &&
          f->requests[0].deadline_ns == 171);
    CHECK(query(f, f->server, f->wheel, &f->requests[0], 120, VIREO_OK,
                VIREO_CLIENT_DEADLINE_REQUEST_NONE, false));
    CHECK(query(f, f->server, f->wheel, &f->requests[0], 170, VIREO_OK,
                VIREO_CLIENT_DEADLINE_REQUEST_NONE, false));
    CHECK(query(f, f->server, f->wheel, &f->requests[0], 171, VIREO_OK,
                VIREO_CLIENT_DEADLINE_REQUEST_NONE, true));
    vireo_client_deadline_request_t copy = f->requests[0];
    vireo_client_deadline_request_stage_t stage;
    CALL(vireo_client_deadline_request_cancel(f->wheel, &f->requests[0], &stage), VIREO_OK);
    CHECK(stage == VIREO_CLIENT_DEADLINE_REQUEST_NONE && f->requests[0].request_sequence == 0 &&
          f->requests[0].started_ns == 0 && f->requests[0].deadline_ns == 0 &&
          f->requests[0].binding.client.pool_id == 0 && f->requests[0].binding.timer.owner_id == 0);
    CHECK(query(f, f->server, f->wheel, &copy, 171, VIREO_RESULT_NOT_FOUND,
                VIREO_CLIENT_DEADLINE_REQUEST_CHECK_TIMER, false));
    return true;
}
static bool test_start_parameters(fixture_t *f) {
    CHECK(start_fails(f, NULL, f->wheel, f->clients[0], 7, 120, 50, VIREO_RESULT_INVALID_ARGUMENT,
                      VIREO_CLIENT_DEADLINE_REQUEST_NONE));
    CHECK(start_fails(f, f->server, NULL, f->clients[0], 7, 120, 50, VIREO_RESULT_INVALID_ARGUMENT,
                      VIREO_CLIENT_DEADLINE_REQUEST_NONE));
    CHECK(start_fails(f, f->server, f->wheel, f->clients[0], 0, 120, 50,
                      VIREO_RESULT_INVALID_ARGUMENT, VIREO_CLIENT_DEADLINE_REQUEST_NONE));
    CHECK(start_fails(f, f->server, f->wheel, f->clients[0], 7, 120, 0,
                      VIREO_RESULT_INVALID_ARGUMENT, VIREO_CLIENT_DEADLINE_REQUEST_NONE));
    CHECK(start_fails(f, f->server, f->wheel, (vireo_connection_pool_lease_t){0}, 7, 120, 50,
                      VIREO_RESULT_NOT_FOUND, VIREO_CLIENT_DEADLINE_REQUEST_NONE));
    vireo_connection_pool_lease_t bad = f->clients[0];
    bad.generation = 0;
    CHECK(start_fails(f, f->server, f->wheel, bad, 7, 120, 50, VIREO_RESULT_INVALID_ARGUMENT,
                      VIREO_CLIENT_DEADLINE_REQUEST_NONE));
    vireo_client_deadline_request_stage_t stage = VIREO_CLIENT_DEADLINE_REQUEST_CHECK_TIME;
    CALL(vireo_client_deadline_request_start(f->server, f->wheel, f->clients[0], 7, 120, 50, NULL,
                                             &stage),
         VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(stage == VIREO_CLIENT_DEADLINE_REQUEST_NONE);
    return true;
}
static bool test_nonempty_output(fixture_t *f) {
    CHECK(start(f, 0, 7, 120, 50));
    unsigned char before[sizeof f->requests[0]];
    memcpy(before, &f->requests[0], sizeof before);
    CALL(vireo_client_deadline_request_start(f->server, f->wheel, f->clients[0], 8, 130, 50,
                                             &f->requests[0], NULL),
         VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(memcmp(before, &f->requests[0], sizeof before) == 0);
    return true;
}
static bool test_query_null(fixture_t *f) {
    CHECK(start(f, 0, 7, 120, 50));
    CHECK(query(f, NULL, f->wheel, &f->requests[0], 130, VIREO_RESULT_INVALID_ARGUMENT,
                VIREO_CLIENT_DEADLINE_REQUEST_NONE, false));
    CHECK(query(f, f->server, NULL, &f->requests[0], 130, VIREO_RESULT_INVALID_ARGUMENT,
                VIREO_CLIENT_DEADLINE_REQUEST_NONE, false));
    bool output = true;
    vireo_client_deadline_request_stage_t stage = VIREO_CLIENT_DEADLINE_REQUEST_CHECK_TIME;
    CALL(vireo_client_deadline_request_check(f->server, f->wheel, NULL, 130, &output, &stage),
         VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(output && stage == VIREO_CLIENT_DEADLINE_REQUEST_NONE);
    CALL(vireo_client_deadline_request_check(f->server, f->wheel, &f->requests[0], 130, NULL,
                                             &stage),
         VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(stage == VIREO_CLIENT_DEADLINE_REQUEST_NONE);
    CALL(vireo_client_deadline_request_cancel(f->wheel, NULL, &stage),
         VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(stage == VIREO_CLIENT_DEADLINE_REQUEST_NONE);
    CHECK(cancel_fails(NULL, &f->requests[0], VIREO_RESULT_INVALID_ARGUMENT,
                       VIREO_CLIENT_DEADLINE_REQUEST_NONE));
    return true;
}
static bool test_shapes(fixture_t *f) {
    CHECK(start(f, 0, 7, 120, 50));
    vireo_client_deadline_request_t empty = {0};
    CHECK(query(f, f->server, f->wheel, &empty, 130, VIREO_RESULT_NOT_FOUND,
                VIREO_CLIENT_DEADLINE_REQUEST_NONE, false));
    CHECK(
        cancel_fails(f->wheel, &empty, VIREO_RESULT_NOT_FOUND, VIREO_CLIENT_DEADLINE_REQUEST_NONE));
    for (size_t i = 0; i < 8; ++i) {
        vireo_client_deadline_request_t bad = f->requests[0];
        if (i == 0)
            bad.binding.client = (vireo_connection_pool_lease_t){0};
        if (i == 1)
            bad.binding.timer = (vireo_timer_handle_t){0};
        if (i == 2)
            bad.request_sequence = 0;
        if (i == 3)
            bad.started_ns = bad.deadline_ns;
        if (i == 4)
            bad.started_ns = bad.deadline_ns + 1;
        if (i == 5)
            bad.binding.client.generation = 0;
        if (i == 6)
            bad.binding.timer.generation = 0;
        if (i == 7) {
            bad = empty;
            bad.deadline_ns = 1;
        }
        CHECK(query(f, f->server, f->wheel, &bad, 130, VIREO_RESULT_INVALID_ARGUMENT,
                    VIREO_CLIENT_DEADLINE_REQUEST_NONE, false));
        CHECK(cancel_fails(f->wheel, &bad, VIREO_RESULT_INVALID_ARGUMENT,
                           VIREO_CLIENT_DEADLINE_REQUEST_NONE));
    }
    return true;
}
static bool test_client_identity(fixture_t *f) {
    CHECK(start(f, 0, 7, 120, 50));
    CHECK(query(f, f->other_server, f->wheel, &f->requests[0], 130, VIREO_RESULT_INVALID_ARGUMENT,
                VIREO_CLIENT_DEADLINE_REQUEST_CHECK_CLIENT, false));
    CHECK(start_fails(f, f->other_server, f->wheel, f->clients[0], 7, 120, 50,
                      VIREO_RESULT_INVALID_ARGUMENT, VIREO_CLIENT_DEADLINE_REQUEST_CHECK_CLIENT));
    vireo_client_deadline_request_t bad = f->requests[0];
    bad.binding.client.slot_index = SIZE_MAX;
    CHECK(query(f, f->server, f->wheel, &bad, 130, VIREO_RESULT_RANGE,
                VIREO_CLIENT_DEADLINE_REQUEST_CHECK_CLIENT, false));
    CHECK(start_fails(f, f->server, f->wheel, bad.binding.client, 7, 120, 50, VIREO_RESULT_RANGE,
                      VIREO_CLIENT_DEADLINE_REQUEST_CHECK_CLIENT));
    bad = f->requests[0];
    ++bad.binding.client.generation;
    CHECK(query(f, f->server, f->wheel, &bad, 130, VIREO_RESULT_NOT_FOUND,
                VIREO_CLIENT_DEADLINE_REQUEST_CHECK_CLIENT, false));
    return true;
}
static bool test_timer_identity(fixture_t *f) {
    CHECK(start(f, 0, 7, 120, 50));
    CHECK(query(f, f->server, f->other_wheel, &f->requests[0], 130, VIREO_RESULT_INVALID_ARGUMENT,
                VIREO_CLIENT_DEADLINE_REQUEST_CHECK_TIMER, false));
    vireo_client_deadline_request_t bad = f->requests[0];
    bad.binding.timer.slot_index = SIZE_MAX;
    CHECK(query(f, f->server, f->wheel, &bad, 130, VIREO_RESULT_RANGE,
                VIREO_CLIENT_DEADLINE_REQUEST_CHECK_TIMER, false));
    CHECK(cancel_fails(f->wheel, &bad, VIREO_RESULT_RANGE,
                       VIREO_CLIENT_DEADLINE_REQUEST_CANCEL_TIMER));
    bad = f->requests[0];
    ++bad.binding.timer.generation;
    CHECK(query(f, f->server, f->wheel, &bad, 130, VIREO_RESULT_NOT_FOUND,
                VIREO_CLIENT_DEADLINE_REQUEST_CHECK_TIMER, false));
    CHECK(cancel_fails(f->other_wheel, &f->requests[0], VIREO_RESULT_INVALID_ARGUMENT,
                       VIREO_CLIENT_DEADLINE_REQUEST_CANCEL_TIMER));
    CHECK(query(f, f->server, f->unprepared, &f->requests[0], 130, VIREO_RESULT_NOT_FOUND,
                VIREO_CLIENT_DEADLINE_REQUEST_CHECK_TIMER, false));
    return true;
}
static bool test_fresh_times(fixture_t *f) {
    CHECK(start_fails(f, f->server, f->wheel, f->clients[0], 7, 99, 50, VIREO_RESULT_RANGE,
                      VIREO_CLIENT_DEADLINE_REQUEST_CHECK_TIME));
    CHECK(start(f, 0, 7, 120, 50));
    CHECK(query(f, f->server, f->wheel, &f->requests[0], 119, VIREO_RESULT_RANGE,
                VIREO_CLIENT_DEADLINE_REQUEST_CHECK_TIME, false));
    CHECK(advance(f->wheel, 140));
    CHECK(query(f, f->server, f->wheel, &f->requests[0], 139, VIREO_RESULT_RANGE,
                VIREO_CLIENT_DEADLINE_REQUEST_CHECK_TIME, false));
    CHECK(start_fails(f, f->server, f->wheel, f->clients[1], 7, 139, 50, VIREO_RESULT_RANGE,
                      VIREO_CLIENT_DEADLINE_REQUEST_CHECK_TIME));
    CHECK(query(f, f->server, f->wheel, &f->requests[0], 140, VIREO_OK,
                VIREO_CLIENT_DEADLINE_REQUEST_NONE, false));
    return true;
}
static bool test_ready(fixture_t *f) {
    CHECK(start(f, 0, 7, 120, 50));
    CHECK(vireo_tcp_server_client_request_close(
              f->server, f->clients[0], VIREO_CONNECTION_CLOSE_MODE_IMMEDIATE,
              VIREO_CONNECTION_CLOSE_REASON_APPLICATION, NULL) == VIREO_OK);
    CHECK(start_fails(f, f->server, f->wheel, f->clients[0], 7, 120, 50, VIREO_RESULT_BUSY,
                      VIREO_CLIENT_DEADLINE_REQUEST_CHECK_OPEN));
    CHECK(query(f, f->server, f->wheel, &f->requests[0], 170, VIREO_OK,
                VIREO_CLIENT_DEADLINE_REQUEST_NONE, true));
    return true;
}
static bool test_draining(fixture_t *f) {
    CHECK(start(f, 0, 7, 120, 50));
    uint8_t const byte = 42;
    CHECK(vireo_tcp_server_client_write_enqueue(f->server, f->clients[0], &byte, 1, NULL) ==
          VIREO_OK);
    CHECK(vireo_tcp_server_client_request_close(
              f->server, f->clients[0], VIREO_CONNECTION_CLOSE_MODE_DRAIN,
              VIREO_CONNECTION_CLOSE_REASON_APPLICATION, NULL) == VIREO_OK);
    CHECK(start_fails(f, f->server, f->wheel, f->clients[0], 7, 120, 50, VIREO_RESULT_BUSY,
                      VIREO_CLIENT_DEADLINE_REQUEST_CHECK_OPEN));
    CHECK(query(f, f->server, f->wheel, &f->requests[0], 170, VIREO_OK,
                VIREO_CLIENT_DEADLINE_REQUEST_NONE, true));
    return true;
}
static bool test_prepare_stop(fixture_t *f) {
    CHECK(start_fails(f, f->server, f->unprepared, f->clients[0], 7, 120, 50,
                      VIREO_RESULT_NOT_FOUND, VIREO_CLIENT_DEADLINE_REQUEST_CHECK_TIMER));
    CHECK(start(f, 0, 7, 120, 50));
    CHECK(vireo_timer_wheel_shutdown_begin(f->wheel) == VIREO_OK);
    CHECK(start_fails(f, f->server, f->wheel, f->clients[1], 7, 0, UINT64_MAX,
                      VIREO_RESULT_CANCELLED, VIREO_CLIENT_DEADLINE_REQUEST_CHECK_TIMER));
    CHECK(query(f, f->server, f->wheel, &f->requests[0], 170, VIREO_OK,
                VIREO_CLIENT_DEADLINE_REQUEST_NONE, true));
    CALL(vireo_client_deadline_request_cancel(f->wheel, &f->requests[0], NULL), VIREO_OK);
    return true;
}
static bool test_ready_taken(fixture_t *f) {
    CHECK(start(f, 0, 7, 120, 51));
    CHECK(query(f, f->server, f->wheel, &f->requests[0], 171, VIREO_OK,
                VIREO_CLIENT_DEADLINE_REQUEST_NONE, true));
    CHECK(advance(f->wheel, 180));
    CHECK(query(f, f->server, f->wheel, &f->requests[0], 180, VIREO_OK,
                VIREO_CLIENT_DEADLINE_REQUEST_NONE, true));
    vireo_timer_wheel_expired_t expired;
    CHECK(vireo_timer_wheel_take_expired(f->wheel, &expired) == VIREO_OK);
    CHECK(expired.timer.deadline_ns == f->requests[0].deadline_ns);
    vireo_tcp_server_client_info_t client;
    CHECK(vireo_client_deadline_check_expired(f->server, f->requests[0].binding, &expired, &client,
                                              NULL) == VIREO_OK);
    CHECK(client.connection_info.close_state == VIREO_CONNECTION_CLOSE_OPEN);
    CHECK(query(f, f->server, f->wheel, &f->requests[0], 180, VIREO_RESULT_NOT_FOUND,
                VIREO_CLIENT_DEADLINE_REQUEST_CHECK_TIMER, false));
    CHECK(cancel_fails(f->wheel, &f->requests[0], VIREO_RESULT_NOT_FOUND,
                       VIREO_CLIENT_DEADLINE_REQUEST_CANCEL_TIMER));
    return true;
}
static bool test_bypass_rearm(fixture_t *f) {
    CHECK(start(f, 0, 7, 120, 50));
    CHECK(vireo_timer_wheel_rearm(f->wheel, f->requests[0].binding.timer, 130, 200) == VIREO_OK);
    CHECK(query(f, f->server, f->wheel, &f->requests[0], 170, VIREO_RESULT_INVALID_ARGUMENT,
                VIREO_CLIENT_DEADLINE_REQUEST_CHECK_TIMER, false));
    CALL(vireo_client_deadline_request_cancel(f->wheel, &f->requests[0], NULL), VIREO_OK);
    return true;
}
static bool test_record_snapshot(fixture_t *f) {
    CHECK(start(f, 0, 7, 120, 50));
    vireo_client_deadline_request_t bad = f->requests[0];
    ++bad.deadline_ns;
    CHECK(query(f, f->server, f->wheel, &bad, 170, VIREO_RESULT_INVALID_ARGUMENT,
                VIREO_CLIENT_DEADLINE_REQUEST_CHECK_TIMER, false));
    CHECK(query(f, f->server, f->wheel, &f->requests[0], 170, VIREO_OK,
                VIREO_CLIENT_DEADLINE_REQUEST_NONE, true));
    return true;
}
static bool test_full_repeated_sequence(fixture_t *f) {
    CHECK(start(f, 0, 7, 120, 50));
    CALL(vireo_client_deadline_request_start(f->server, f->wheel, f->clients[0], 7, 120, 60,
                                             &f->requests[1], NULL),
         VIREO_OK);
    bool equal = true;
    CHECK(vireo_timer_handle_equal(f->requests[0].binding.timer, f->requests[1].binding.timer,
                                   &equal) == VIREO_OK &&
          !equal);
    CHECK(start_fails(f, f->server, f->wheel, f->clients[0], 7, 120, 50, VIREO_RESULT_BUSY,
                      VIREO_CLIENT_DEADLINE_REQUEST_REGISTER_TIMER));
    CHECK(query(f, f->server, f->wheel, &f->requests[0], 170, VIREO_OK,
                VIREO_CLIENT_DEADLINE_REQUEST_NONE, true));
    CHECK(query(f, f->server, f->wheel, &f->requests[1], 170, VIREO_OK,
                VIREO_CLIENT_DEADLINE_REQUEST_NONE, false));
    return true;
}
static bool test_release_cancel(fixture_t *f) {
    CHECK(start(f, 0, 7, 120, 50));
    vireo_connection_pool_lease_t const old_client = f->clients[0];
    CHECK(vireo_tcp_server_release_client(f->server, &f->clients[0], NULL) == VIREO_OK);
    CHECK(query(f, f->server, f->wheel, &f->requests[0], 170, VIREO_RESULT_NOT_FOUND,
                VIREO_CLIENT_DEADLINE_REQUEST_CHECK_CLIENT, false));
    CHECK(close(f->peers[0]) == 0);
    f->peers[0] = -1;
    CHECK(add_client(f, 0));
    CHECK(old_client.slot_index == f->clients[0].slot_index &&
          old_client.generation != f->clients[0].generation);
    CHECK(query(f, f->server, f->wheel, &f->requests[0], 170, VIREO_RESULT_NOT_FOUND,
                VIREO_CLIENT_DEADLINE_REQUEST_CHECK_CLIENT, false));
    CALL(vireo_client_deadline_request_cancel(f->wheel, &f->requests[0], NULL), VIREO_OK);
    return true;
}
static bool test_stale_reuse(fixture_t *f) {
    /* 容量一强制物理槽复用，不假定公开 acquire 的空槽选择顺序。 */
    CHECK(reset_wheel_capacity(f, 100, 10, 1));
    CHECK(start(f, 0, 7, 120, 50));
    vireo_timer_handle_t old_handle = f->requests[0].binding.timer;
    CHECK(vireo_timer_wheel_cancel(f->wheel, &old_handle) == VIREO_OK);
    CHECK(start(f, 1, 7, 120, 50));
    CHECK(f->requests[0].binding.timer.slot_index == f->requests[1].binding.timer.slot_index &&
          f->requests[0].binding.timer.generation != f->requests[1].binding.timer.generation);
    CHECK(cancel_fails(f->wheel, &f->requests[0], VIREO_RESULT_NOT_FOUND,
                       VIREO_CLIENT_DEADLINE_REQUEST_CANCEL_TIMER));
    CHECK(query(f, f->server, f->wheel, &f->requests[1], 170, VIREO_OK,
                VIREO_CLIENT_DEADLINE_REQUEST_NONE, true));
    return true;
}
static bool test_max_finite(fixture_t *f) {
    CHECK(reset_wheel(f, 0, 1) && start(f, 0, UINT32_MAX, 0, UINT64_MAX));
    CHECK(f->requests[0].deadline_ns == UINT64_MAX);
    CHECK(query(f, f->server, f->wheel, &f->requests[0], 0, VIREO_OK,
                VIREO_CLIENT_DEADLINE_REQUEST_NONE, false));
    CHECK(query(f, f->server, f->wheel, &f->requests[0], UINT64_MAX, VIREO_OK,
                VIREO_CLIENT_DEADLINE_REQUEST_NONE, true));
    return true;
}
static bool test_overflow(fixture_t *f) {
    CHECK(start_fails(f, f->server, f->wheel, f->clients[0], 7, 120, UINT64_MAX,
                      VIREO_RESULT_OVERFLOW, VIREO_CLIENT_DEADLINE_REQUEST_CHECK_TIME));
    CHECK(start_fails(f, f->server, f->wheel, f->clients[0], 7, UINT64_MAX, 1,
                      VIREO_RESULT_OVERFLOW, VIREO_CLIENT_DEADLINE_REQUEST_CHECK_TIME));
    CHECK(reset_wheel(f, UINT64_MAX - 10, 6));
    CHECK(start_fails(f, f->server, f->wheel, f->clients[0], 7, UINT64_MAX - 10, 7,
                      VIREO_RESULT_OVERFLOW, VIREO_CLIENT_DEADLINE_REQUEST_REGISTER_TIMER));
    return true;
}
/** 真实TCP已校验请求取得sequence，fresh MONOTONIC起点；idle传输活动不改变request快照或轮期限。 */
static bool test_actual_request_idle(fixture_t *f) {
    uint8_t wire[32];
    vireo_protocol_header_t header = {.command = VIREO_COMMAND_PING, .sequence = 7};
    CHECK(vireo_protocol_header_encode(&header, wire, sizeof wire) == VIREO_OK);
    CHECK(vireo_protocol_frame_crc32c_calculate(wire, sizeof wire, NULL, 0, &header.crc32c) ==
          VIREO_OK);
    CHECK(vireo_protocol_header_encode(&header, wire, sizeof wire) == VIREO_OK);
    CHECK(send(f->peers[0], wire, sizeof wire, MSG_NOSIGNAL) == (ssize_t)sizeof wire);
    vireo_connection_receive_budget_t const budget = {64, 4};
    vireo_connection_receive_info_t received;
    CHECK(vireo_tcp_server_client_receive(f->server, f->clients[0], &budget, &received, NULL) ==
          VIREO_OK);
    CHECK(received.received_bytes == sizeof wire);
    vireo_connection_frame_options_t const options = {VIREO_CONNECTION_FRAME_REQUEST, 64};
    vireo_connection_frame_budget_t const frames_budget = {1, 64};
    vireo_connection_frame_view_t view;
    vireo_connection_frame_info_t frames;
    CHECK(vireo_tcp_server_client_frames_peek(f->server, f->clients[0], &options, &frames_budget,
                                              &view, 1, &frames, NULL) == VIREO_OK);
    CHECK(frames.frame_count == 1 && view.header.sequence == 7);
    uint64_t now;
    CHECK(vireo_clock_monotonic_now(&now, NULL) == VIREO_OK);
    CHECK(reset_wheel(f, now, UINT64_C(10000000)) &&
          start(f, 0, view.header.sequence, now, UINT64_C(3000000000)));
    CHECK(vireo_client_deadline_store_save(f->store, f->server, f->wheel, f->requests[0].binding,
                                           NULL) == VIREO_OK);
    CHECK(vireo_tcp_server_client_read_consume(f->server, f->clients[0], sizeof wire, NULL) ==
          VIREO_OK);
    vireo_client_deadline_idle_t idle = {0};
    CHECK(vireo_client_deadline_idle_start(f->server, f->wheel, f->clients[0], now,
                                           UINT64_C(3000000000), &idle, NULL) == VIREO_OK);
    uint64_t const original_deadline = f->requests[0].deadline_ns;
    uint8_t const byte = 42;
    CHECK(send(f->peers[0], &byte, 1, MSG_NOSIGNAL) == 1);
    CHECK(vireo_tcp_server_client_receive(f->server, f->clients[0], &budget, &received, NULL) ==
          VIREO_OK);
    CHECK(received.received_bytes == 1);
    CHECK(vireo_clock_monotonic_now(&now, NULL) == VIREO_OK);
    CHECK(vireo_client_deadline_idle_refresh(f->server, f->wheel, &idle, now,
                                             received.received_bytes, 0, NULL) == VIREO_OK);
    CHECK(query(f, f->server, f->wheel, &f->requests[0], now, VIREO_OK,
                VIREO_CLIENT_DEADLINE_REQUEST_NONE, false));
    vireo_timer_wheel_timer_info_t info;
    CHECK(vireo_timer_wheel_get(f->wheel, f->requests[0].binding.timer, &info) == VIREO_OK &&
          info.deadline_ns == original_deadline);
    CHECK(f->requests[0].deadline_ns == original_deadline);
    CHECK(vireo_timer_wheel_get(f->wheel, idle.binding.timer, &info) == VIREO_OK &&
          info.deadline_ns == now + idle.idle_timeout_ns);
    vireo_client_deadline_binding_t found;
    CHECK(vireo_client_deadline_store_find(f->store, f->requests[0].binding.timer, &found) ==
          VIREO_OK);
    CHECK(found.timer.generation == f->requests[0].binding.timer.generation);
    CALL(vireo_client_deadline_idle_cancel(f->wheel, &idle, NULL), VIREO_OK);
    return true;
}
/** 场景表仅测试驱动，非产品callback或持久状态。 */
typedef struct test_case {
    char const *name;         /**< 静态组名，进程内存活，无申请。 */
    bool (*run)(fixture_t *); /**< 短借fixture的同步断言入口。 */
} test_case_t;
int main(void) {
    test_case_t const cases[] = {
        {"fixed total deadline check cancel chain", test_basic_chain},
        {"start null zero tag and duration", test_start_parameters},
        {"nonempty output preserved", test_nonempty_output},
        {"query cancel null and errno", test_query_null},
        {"empty malformed and invalid time interval", test_shapes},
        {"client current generation owner range", test_client_identity},
        {"timer current generation owner range", test_timer_identity},
        {"beginning and wheel sample regression", test_fresh_times},
        {"READY still query but cannot start", test_ready},
        {"DRAINING still query but cannot start", test_draining},
        {"prepare stop query and cancellation", test_prepare_stop},
        {"precise expiry ready historical taken", test_ready_taken},
        {"bypass rearm fixed mismatch rejected", test_bypass_rearm},
        {"edited snapshot never silently accepted", test_record_snapshot},
        {"full wheel same sequence distinct timers", test_full_repeated_sequence},
        {"released customer timer cleanup", test_release_cancel},
        {"same slot old generation cancel failure", test_stale_reuse},
        {"zero beginning maximum finite point and tag", test_max_finite},
        {"addition and upward boundary overflow", test_overflow},
        {"verified TCP request idle activity independent", test_actual_request_idle},
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
