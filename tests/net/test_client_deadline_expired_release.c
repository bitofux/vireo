/*
 * PROJECT : VIREO
 * FILE    : test_client_deadline_expired_release.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-10
 * BRIEF   : 此模块负责：
 * -- 验证当前 READY 客户单次归还及按消费事实清绑定
 * -- 只依赖已采用公开合同，保持资源、输出与 errno 的既有边界
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vireo/net/client_deadline_store.h>
#include <vireo/net/timer_loop_dispatch.h>
#include <vireo/timer/wheel_shutdown.h>
#include "net/client_deadline_expired_release_internal.h"

#define CHECK(expr)                                                    \
    do {                                                               \
        if (!(expr)) {                                                 \
            fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #expr); \
            return false;                                              \
        }                                                              \
    } while (0)

/** 本项真实 TCP 与公开资源 fixture；全部使用 public 合同。 */
typedef struct fixture {
    vireo_tcp_server_t *server;               /**< 拥有两个当前客户及 listener。 */
    vireo_tcp_server_t *other_server;         /**< 独立空 pool，用于跨所属拒绝。 */
    vireo_timer_wheel_t *wheel;               /**< 拥有本轮，固定准备容量二。 */
    vireo_timer_wheel_t *other_wheel;         /**< 独立 owner，容量二。 */
    vireo_timer_wheel_t *unprepared;          /**< 独立未准备轮。 */
    vireo_client_deadline_store_t *store;     /**< 本表唯一 owner，固定容量三。 */
    vireo_connection_pool_lease_t clients[2]; /**< 当前两个客户，归还后清零。 */
    int peers[2]; /**< 各客户的 caller TCP 对端 fd，-1 为空。 */
    vireo_client_deadline_binding_t
        bindings[4]; /**< 前二属 wheel、后二属 other_wheel；记录或历史值。 */
    vireo_timer_wheel_expired_t expired[4]; /**< 真实领取的历史通知值，不保活。 */
    int listener_fd;                        /**< 构造期原 socket owner，转移后 -1。 */
    vireo_acceptor_t *listener;             /**< 构造期 owner，server 收纳后 NULL。 */
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
        vireo_timer_handle_t key = f->bindings[i].timer;
        if (key.owner_id == 0)
            key = f->expired[i].handle;
        if (key.owner_id != 0 && f->store != NULL) {
            vireo_client_deadline_binding_t record;
            vireo_result_t r = vireo_client_deadline_store_withdraw(f->store, key, &record);
            CHECK(r == VIREO_OK || r == VIREO_RESULT_NOT_FOUND);
        }
        if (f->bindings[i].timer.owner_id != 0) {
            vireo_result_t r = vireo_client_deadline_cancel(i < 2 ? f->wheel : f->other_wheel,
                                                            &f->bindings[i], NULL);
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

static bool same_client_info(vireo_tcp_server_client_info_t const *a,
                             vireo_tcp_server_client_info_t const *b) {
#define FIELD(name) CHECK(a->name == b->name)
    FIELD(last_events);
    FIELD(queued);
    FIELD(pending_events);
    FIELD(connection_info.read_buffer.capacity);
    FIELD(connection_info.read_buffer.readable_size);
    FIELD(connection_info.read_buffer.tail_space);
    FIELD(connection_info.write_buffer.capacity);
    FIELD(connection_info.write_buffer.readable_size);
    FIELD(connection_info.write_buffer.tail_space);
    FIELD(connection_info.buffer_capacity_bytes);
    FIELD(connection_info.max_buffer_bytes);
    FIELD(connection_info.read_eof);
    FIELD(connection_info.loop_attached);
    FIELD(connection_info.loop_interests);
    FIELD(connection_info.callback_active);
    FIELD(connection_info.flow_enabled);
    FIELD(connection_info.read_pressure);
    FIELD(connection_info.write_pressure);
    FIELD(connection_info.flow_options.max_frame_bytes);
    FIELD(connection_info.flow_options.read_low);
    FIELD(connection_info.flow_options.read_high);
    FIELD(connection_info.flow_options.write_low);
    FIELD(connection_info.flow_options.write_high);
    FIELD(connection_info.close_state);
    FIELD(connection_info.close_mode);
    FIELD(connection_info.close_reason);
#undef FIELD
    return true;
}

static bool same_error(vireo_tcp_server_client_error_t a, vireo_tcp_server_client_error_t b) {
    return a.primary.stage == b.primary.stage &&
           a.primary.acceptor_error.stage == b.primary.acceptor_error.stage &&
           a.primary.acceptor_error.system_errno == b.primary.acceptor_error.system_errno &&
           a.primary.connection_error.stage == b.primary.connection_error.stage &&
           a.primary.connection_error.system_errno == b.primary.connection_error.system_errno &&
           a.primary.pool_error.stage == b.primary.pool_error.stage &&
           a.primary.pool_error.connection_error.stage ==
               b.primary.pool_error.connection_error.stage &&
           a.primary.pool_error.connection_error.system_errno ==
               b.primary.pool_error.connection_error.system_errno &&
           a.primary.loop_error.stage == b.primary.loop_error.stage &&
           a.primary.loop_error.loop_error.stage == b.primary.loop_error.loop_error.stage &&
           a.primary.loop_error.loop_error.epoll_error.stage ==
               b.primary.loop_error.loop_error.epoll_error.stage &&
           a.primary.loop_error.loop_error.epoll_error.system_errno ==
               b.primary.loop_error.loop_error.epoll_error.system_errno &&
           a.primary.loop_error.loop_error.system_errno ==
               b.primary.loop_error.loop_error.system_errno &&
           a.primary.system_errno == b.primary.system_errno &&
           a.primary.frame_error.issue == b.primary.frame_error.issue &&
           a.primary.frame_error.codec_issue == b.primary.frame_error.codec_issue &&
           a.primary.handler_result == b.primary.handler_result &&
           a.primary.response_codec_issue == b.primary.response_codec_issue &&
           a.cleanup_result == b.cleanup_result && a.cleanup.stage == b.cleanup.stage &&
           a.cleanup.acceptor_error.stage == b.cleanup.acceptor_error.stage &&
           a.cleanup.acceptor_error.system_errno == b.cleanup.acceptor_error.system_errno &&
           a.cleanup.connection_error.stage == b.cleanup.connection_error.stage &&
           a.cleanup.connection_error.system_errno == b.cleanup.connection_error.system_errno &&
           a.cleanup.pool_error.stage == b.cleanup.pool_error.stage &&
           a.cleanup.pool_error.connection_error.stage ==
               b.cleanup.pool_error.connection_error.stage &&
           a.cleanup.pool_error.connection_error.system_errno ==
               b.cleanup.pool_error.connection_error.system_errno &&
           a.cleanup.loop_error.stage == b.cleanup.loop_error.stage &&
           a.cleanup.loop_error.loop_error.stage == b.cleanup.loop_error.loop_error.stage &&
           a.cleanup.loop_error.loop_error.epoll_error.stage ==
               b.cleanup.loop_error.loop_error.epoll_error.stage &&
           a.cleanup.loop_error.loop_error.epoll_error.system_errno ==
               b.cleanup.loop_error.loop_error.epoll_error.system_errno &&
           a.cleanup.loop_error.loop_error.system_errno ==
               b.cleanup.loop_error.loop_error.system_errno &&
           a.cleanup.system_errno == b.cleanup.system_errno &&
           a.cleanup.frame_error.issue == b.cleanup.frame_error.issue &&
           a.cleanup.frame_error.codec_issue == b.cleanup.frame_error.codec_issue &&
           a.cleanup.handler_result == b.cleanup.handler_result &&
           a.cleanup.response_codec_issue == b.cleanup.response_codec_issue;
}

static bool expire_at(fixture_t *f, size_t index, size_t client, uint64_t deadline) {
    CHECK(register_at(f, index, client, 100, deadline) && save_at(f, index));
    vireo_timer_wheel_t *wheel = index < 2 ? f->wheel : f->other_wheel;
    CHECK(advance_to(wheel, deadline));
    CHECK(vireo_timer_wheel_take_expired(wheel, &f->expired[index]) == VIREO_OK);
    CHECK(same_timer(f->expired[index].handle, f->bindings[index].timer));
    return true;
}

#define IMMEDIATE VIREO_CONNECTION_CLOSE_MODE_IMMEDIATE
#define DRAIN VIREO_CONNECTION_CLOSE_MODE_DRAIN
#define APPLICATION VIREO_CONNECTION_CLOSE_REASON_APPLICATION

static bool close_at(fixture_t *f, size_t index, vireo_connection_close_mode_t mode) {
    CHECK(vireo_client_deadline_request_close_expired(f->server, f->bindings[index],
                                                      &f->expired[index], mode, APPLICATION,
                                                      NULL) == VIREO_OK);
    return true;
}
static bool consumed_client(fixture_t *f, vireo_connection_pool_lease_t old) {
    vireo_tcp_server_client_info_t info;
    CHECK(vireo_tcp_server_client_inspect(f->server, old, &info) == VIREO_RESULT_NOT_FOUND);
    for (size_t i = 0; i < 2; ++i)
        if (f->clients[i].pool_id == old.pool_id && f->clients[i].slot_index == old.slot_index &&
            f->clients[i].generation == old.generation)
            f->clients[i] = (vireo_connection_pool_lease_t){0};
    return true;
}
static bool release_ok(fixture_t *f, size_t index) {
    vireo_client_deadline_binding_t const before = f->bindings[index], empty = {0};
    unsigned char bytes[sizeof f->expired[index]];
    memcpy(bytes, &f->expired[index], sizeof bytes);
    vireo_client_deadline_release_report_t report;
    memset(&report, 0xa5, sizeof report);
    vireo_tcp_server_client_error_t const zero = {0};
    errno = ENOSPC;
    CHECK(vireo_client_deadline_release_ready_expired(f->server, &f->bindings[index],
                                                      &f->expired[index], &report) == VIREO_OK &&
          errno == ENOSPC);
    CHECK(report.stage == VIREO_CLIENT_DEADLINE_NONE && report.release_called &&
          report.client_consumed && same_error(report.client_error, zero));
    CHECK(same_binding(f->bindings[index], empty) &&
          memcmp(bytes, &f->expired[index], sizeof bytes) == 0);
    CHECK(consumed_client(f, before.client));
    vireo_client_deadline_binding_t record;
    CHECK(vireo_client_deadline_store_find(f->store, before.timer, &record) == VIREO_OK &&
          same_binding(record, before));
    return true;
}

/** 前置拒绝只观察公开快照、记录、轮进度和 caller 输入，不读取 opaque 存储。 */
static bool refuse(fixture_t *f, vireo_tcp_server_t *server,
                   vireo_client_deadline_binding_t *binding,
                   vireo_timer_wheel_expired_t const *event, vireo_result_t result,
                   vireo_client_deadline_stage_t stage) {
    vireo_tcp_server_client_info_t before[2], after;
    for (size_t i = 0; i < 2; ++i)
        CHECK(vireo_tcp_server_client_inspect(f->server, f->clients[i], &before[i]) == VIREO_OK);
    unsigned char binding_bytes[sizeof *binding], event_bytes[sizeof *event];
    if (binding != NULL)
        memcpy(binding_bytes, binding, sizeof *binding);
    if (event != NULL)
        memcpy(event_bytes, event, sizeof *event);
    vireo_client_deadline_store_info_t store_before, store_after;
    CHECK(vireo_client_deadline_store_inspect(f->store, &store_before) == VIREO_OK);
    vireo_timer_wheel_progress_t progress_before, progress_after;
    CHECK(vireo_timer_wheel_progress_inspect(f->wheel, &progress_before) == VIREO_OK);
    for (size_t pass = 0; pass < 2; ++pass) {
        vireo_client_deadline_release_report_t report;
        memset(&report, pass == 0 ? 0xa5 : 0x5a, sizeof report);
        vireo_tcp_server_client_error_t const zero = {0};
        errno = ERANGE;
        CHECK(vireo_client_deadline_release_ready_expired(server, binding, event, &report) ==
                  result &&
              errno == ERANGE);
        CHECK(report.stage == stage && !report.release_called && !report.client_consumed &&
              same_error(report.client_error, zero));
        CHECK(binding == NULL || memcmp(binding_bytes, binding, sizeof *binding) == 0);
        CHECK(event == NULL || memcmp(event_bytes, event, sizeof *event) == 0);
        for (size_t i = 0; i < 2; ++i) {
            CHECK(vireo_tcp_server_client_inspect(f->server, f->clients[i], &after) == VIREO_OK);
            CHECK(same_client_info(&before[i], &after));
        }
        CHECK(vireo_client_deadline_store_inspect(f->store, &store_after) == VIREO_OK);
        CHECK(store_before.count == store_after.count &&
              store_before.capacity == store_after.capacity &&
              store_before.allocation_bytes == store_after.allocation_bytes &&
              store_before.max_memory_bytes == store_after.max_memory_bytes);
        CHECK(vireo_timer_wheel_progress_inspect(f->wheel, &progress_after) == VIREO_OK);
        CHECK(progress_before.latest_now_ns == progress_after.latest_now_ns &&
              progress_before.target_tick == progress_after.target_tick &&
              progress_before.completed_tick == progress_after.completed_tick &&
              progress_before.processing == progress_after.processing &&
              progress_before.ready_count == progress_after.ready_count &&
              progress_before.caught_up == progress_after.caught_up);
        for (size_t i = 0; i < 4; ++i)
            if (f->bindings[i].timer.owner_id != 0) {
                vireo_client_deadline_binding_t record;
                CHECK(vireo_client_deadline_store_find(f->store, f->bindings[i].timer, &record) ==
                          VIREO_OK &&
                      same_binding(record, f->bindings[i]));
            }
    }
    return true;
}
static bool enum_stability(fixture_t *f) {
    (void)f;
    CHECK(
        VIREO_CLIENT_DEADLINE_NONE == 0 && VIREO_CLIENT_DEADLINE_CHECK_CLIENT == 1 &&
        VIREO_CLIENT_DEADLINE_CHECK_TIMER == 2 && VIREO_CLIENT_DEADLINE_MATCH_TIMER == 3 &&
        VIREO_CLIENT_DEADLINE_REGISTER_TIMER == 4 && VIREO_CLIENT_DEADLINE_CANCEL_TIMER == 5 &&
        VIREO_CLIENT_DEADLINE_REARM_TIMER == 6 && VIREO_CLIENT_DEADLINE_REQUEST_CLOSE_CLIENT == 7 &&
        VIREO_CLIENT_DEADLINE_CHECK_READY_CLIENT == 8 && VIREO_CLIENT_DEADLINE_RELEASE_CLIENT == 9);
    return true;
}
static bool immediate_release(fixture_t *f) {
    CHECK(expire_at(f, 0, 0, 110) && close_at(f, 0, IMMEDIATE));
    vireo_connection_pool_lease_t old = f->clients[0];
    CHECK(release_ok(f, 0) && count_is(f, 1));
    CHECK(close(f->peers[0]) == 0);
    f->peers[0] = -1;
    CHECK(add_client(f, 0));
    CHECK(f->clients[0].slot_index == old.slot_index && f->clients[0].generation != old.generation);
    return true;
}
static bool empty_drain(fixture_t *f) {
    CHECK(expire_at(f, 0, 0, 110) && close_at(f, 0, DRAIN) && release_ok(f, 0));
    return true;
}
static bool open_busy(fixture_t *f) {
    CHECK(expire_at(f, 0, 0, 110));
    CHECK(refuse(f, f->server, &f->bindings[0], &f->expired[0], VIREO_RESULT_BUSY,
                 VIREO_CLIENT_DEADLINE_CHECK_READY_CLIENT));
    return true;
}
static bool draining_busy(fixture_t *f) {
    uint8_t const bytes[] = {1, 2, 3, 4};
    CHECK(vireo_tcp_server_client_write_enqueue(f->server, f->clients[0], bytes, 4, NULL) ==
          VIREO_OK);
    CHECK(expire_at(f, 0, 0, 110) && close_at(f, 0, DRAIN));
    CHECK(refuse(f, f->server, &f->bindings[0], &f->expired[0], VIREO_RESULT_BUSY,
                 VIREO_CLIENT_DEADLINE_CHECK_READY_CLIENT));
    return true;
}
static bool drain_send_refresh(fixture_t *f) {
    uint8_t const bytes[] = {1, 2, 3, 4};
    CHECK(vireo_tcp_server_client_write_enqueue(f->server, f->clients[0], bytes, 4, NULL) ==
          VIREO_OK);
    CHECK(expire_at(f, 0, 0, 110) && close_at(f, 0, DRAIN));
    vireo_connection_send_budget_t const budget = {4, 1};
    vireo_connection_send_info_t info;
    CHECK(vireo_tcp_server_client_send(f->server, f->clients[0], &budget, &info, NULL) ==
              VIREO_OK &&
          info.sent_bytes == 4);
    struct pollfd ready = {f->peers[0], POLLIN, 0};
    CHECK(poll(&ready, 1, 1000) == 1 && (ready.revents & POLLIN) != 0);
    uint8_t received[4];
    CHECK(recv(f->peers[0], received, 4, MSG_DONTWAIT) == 4 && memcmp(bytes, received, 4) == 0);
    CHECK(refuse(f, f->server, &f->bindings[0], &f->expired[0], VIREO_RESULT_BUSY,
                 VIREO_CLIENT_DEADLINE_CHECK_READY_CLIENT));
    CHECK(vireo_tcp_server_client_close_refresh(f->server, f->clients[0], NULL) == VIREO_OK &&
          release_ok(f, 0));
    return true;
}
static bool basic_null(fixture_t *f) {
    CHECK(expire_at(f, 0, 0, 110) && close_at(f, 0, IMMEDIATE));
    CHECK(refuse(f, NULL, &f->bindings[0], &f->expired[0], VIREO_RESULT_INVALID_ARGUMENT,
                 VIREO_CLIENT_DEADLINE_NONE));
    CHECK(refuse(f, f->server, NULL, &f->expired[0], VIREO_RESULT_INVALID_ARGUMENT,
                 VIREO_CLIENT_DEADLINE_NONE));
    CHECK(refuse(f, f->server, &f->bindings[0], NULL, VIREO_RESULT_INVALID_ARGUMENT,
                 VIREO_CLIENT_DEADLINE_NONE));
    return true;
}
static bool missing_report(fixture_t *f) {
    CHECK(expire_at(f, 0, 0, 110) && close_at(f, 0, IMMEDIATE));
    vireo_client_deadline_binding_t old = f->bindings[0];
    vireo_tcp_server_client_info_t before, after;
    CHECK(vireo_tcp_server_client_inspect(f->server, f->clients[0], &before) == VIREO_OK);
    errno = EDOM;
    CHECK(vireo_client_deadline_release_ready_expired(f->server, &f->bindings[0], &f->expired[0],
                                                      NULL) == VIREO_RESULT_INVALID_ARGUMENT &&
          errno == EDOM && same_binding(old, f->bindings[0]));
    CHECK(vireo_tcp_server_client_inspect(f->server, f->clients[0], &after) == VIREO_OK &&
          same_client_info(&before, &after));
    return true;
}
static bool empty_binding(fixture_t *f) {
    CHECK(expire_at(f, 0, 0, 110));
    vireo_client_deadline_binding_t b = {0};
    CHECK(refuse(f, f->server, &b, &f->expired[0], VIREO_RESULT_NOT_FOUND,
                 VIREO_CLIENT_DEADLINE_NONE));
    return true;
}
static bool malformed_binding(fixture_t *f) {
    CHECK(expire_at(f, 0, 0, 110));
    for (size_t i = 0; i < 4; ++i) {
        vireo_client_deadline_binding_t b = f->bindings[0];
        if (i == 0)
            b.client.generation = 0;
        if (i == 1)
            b.timer.generation = 0;
        if (i == 2)
            b.client = (vireo_connection_pool_lease_t){0};
        if (i == 3)
            b.timer = (vireo_timer_handle_t){0};
        CHECK(refuse(f, f->server, &b, &f->expired[0], VIREO_RESULT_INVALID_ARGUMENT,
                     VIREO_CLIENT_DEADLINE_NONE));
    }
    return true;
}
static bool malformed_event(fixture_t *f) {
    CHECK(expire_at(f, 0, 0, 110));
    vireo_timer_wheel_expired_t e = {0};
    CHECK(refuse(f, f->server, &f->bindings[0], &e, VIREO_RESULT_NOT_FOUND,
                 VIREO_CLIENT_DEADLINE_NONE));
    e = f->expired[0];
    e.handle.generation = 0;
    CHECK(refuse(f, f->server, &f->bindings[0], &e, VIREO_RESULT_INVALID_ARGUMENT,
                 VIREO_CLIENT_DEADLINE_NONE));
    return true;
}
static bool full_history_match(fixture_t *f) {
    CHECK(expire_at(f, 0, 0, 110));
    for (size_t i = 0; i < 3; ++i) {
        vireo_client_deadline_binding_t b = f->bindings[0];
        if (i == 0) {
            ++b.timer.owner_id;
            ++b.client.generation;
        }
        if (i == 1)
            ++b.timer.slot_index;
        if (i == 2)
            ++b.timer.generation;
        CHECK(refuse(f, f->server, &b, &f->expired[0], VIREO_RESULT_NOT_FOUND,
                     VIREO_CLIENT_DEADLINE_MATCH_TIMER));
    }
    return true;
}
static bool cross_pool(fixture_t *f) {
    CHECK(expire_at(f, 0, 0, 110));
    CHECK(refuse(f, f->other_server, &f->bindings[0], &f->expired[0], VIREO_RESULT_INVALID_ARGUMENT,
                 VIREO_CLIENT_DEADLINE_CHECK_CLIENT));
    return true;
}
static bool slot_range(fixture_t *f) {
    CHECK(expire_at(f, 0, 0, 110));
    vireo_client_deadline_binding_t b = f->bindings[0];
    b.client.slot_index = 2;
    CHECK(refuse(f, f->server, &b, &f->expired[0], VIREO_RESULT_RANGE,
                 VIREO_CLIENT_DEADLINE_CHECK_CLIENT));
    return true;
}
static bool old_client_reused(fixture_t *f) {
    CHECK(expire_at(f, 0, 0, 110) && close_at(f, 0, IMMEDIATE));
    vireo_connection_pool_lease_t old = f->clients[0];
    CHECK(vireo_tcp_server_release_client(f->server, &f->clients[0], NULL) == VIREO_OK);
    CHECK(close(f->peers[0]) == 0);
    f->peers[0] = -1;
    CHECK(add_client(f, 0));
    CHECK(old.slot_index == f->clients[0].slot_index && old.generation != f->clients[0].generation);
    CHECK(refuse(f, f->server, &f->bindings[0], &f->expired[0], VIREO_RESULT_NOT_FOUND,
                 VIREO_CLIENT_DEADLINE_CHECK_CLIENT));
    return true;
}
static bool repeat_consumed(fixture_t *f) {
    CHECK(expire_at(f, 0, 0, 110) && close_at(f, 0, IMMEDIATE));
    vireo_client_deadline_binding_t old = f->bindings[0];
    CHECK(release_ok(f, 0));
    vireo_client_deadline_release_report_t report;
    errno = EDOM;
    CHECK(vireo_client_deadline_release_ready_expired(f->server, &f->bindings[0], &f->expired[0],
                                                      &report) == VIREO_RESULT_NOT_FOUND &&
          errno == EDOM && !report.release_called && !report.client_consumed);
    CHECK(vireo_client_deadline_release_ready_expired(f->server, &old, &f->expired[0], &report) ==
              VIREO_RESULT_NOT_FOUND &&
          report.stage == VIREO_CLIENT_DEADLINE_CHECK_CLIENT && !report.release_called &&
          old.client.pool_id != 0);
    return true;
}
static bool withdrawn_record(fixture_t *f) {
    CHECK(expire_at(f, 0, 0, 110) && close_at(f, 0, IMMEDIATE));
    vireo_client_deadline_binding_t b, empty = {0};
    CHECK(vireo_client_deadline_store_take_expired(f->store, &f->expired[0], &b) == VIREO_OK);
    vireo_connection_pool_lease_t old = b.client;
    vireo_client_deadline_release_report_t report;
    CHECK(vireo_client_deadline_release_ready_expired(f->server, &b, &f->expired[0], &report) ==
              VIREO_OK &&
          report.client_consumed && same_binding(b, empty));
    CHECK(consumed_client(f, old) && count_is(f, 0));
    return true;
}
static bool other_timer_untouched(fixture_t *f) {
    CHECK(register_at(f, 0, 0, 100, 110) && save_at(f, 0) && register_at(f, 1, 0, 100, 120) &&
          save_at(f, 1));
    CHECK(advance_to(f->wheel, 110) &&
          vireo_timer_wheel_take_expired(f->wheel, &f->expired[0]) == VIREO_OK);
    CHECK(close_at(f, 0, IMMEDIATE) && release_ok(f, 0));
    vireo_timer_wheel_timer_info_t info;
    CHECK(vireo_timer_wheel_get(f->wheel, f->bindings[1].timer, &info) == VIREO_OK &&
          info.deadline_ns == 120);
    CHECK(advance_to(f->wheel, 120) &&
          vireo_timer_wheel_take_expired(f->wheel, &f->expired[1]) == VIREO_OK);
    vireo_client_deadline_release_report_t report;
    CHECK(vireo_client_deadline_release_ready_expired(f->server, &f->bindings[1], &f->expired[1],
                                                      &report) == VIREO_RESULT_NOT_FOUND &&
          !report.release_called && report.stage == VIREO_CLIENT_DEADLINE_CHECK_CLIENT);
    CHECK(count_is(f, 2));
    return true;
}
static bool wheel_stopped(fixture_t *f) {
    CHECK(expire_at(f, 0, 0, 110) && close_at(f, 0, IMMEDIATE));
    CHECK(vireo_timer_wheel_shutdown_begin(f->wheel) == VIREO_OK && release_ok(f, 0));
    return true;
}
static bool server_stopped(fixture_t *f) {
    CHECK(expire_at(f, 0, 0, 110) && close_at(f, 0, IMMEDIATE));
    CHECK(vireo_tcp_server_request_stop(f->server, NULL) == VIREO_OK && release_ok(f, 0));
    return true;
}

/** 本层返回模拟；consume 时先实际成功 release，非真实内核 close 故障。 */
typedef struct fault_probe {
    size_t calls;          /**< 实际归还依赖次数，初零。 */
    bool consume;          /**< true 先执行真实成功归还；false 模拟未消费拒绝。 */
    vireo_result_t result; /**< 模拟原分类，包含 IO／BUSY／未知值。 */
    vireo_tcp_server_client_error_t error; /**< 完整模拟原诊断副本。 */
} fault_probe_t;
static vireo_result_t injected_release(vireo_tcp_server_t *server,
                                       vireo_connection_pool_lease_t *client,
                                       vireo_tcp_server_client_error_t *error, void *context) {
    fault_probe_t *p = context;
    ++p->calls;
    if (p->consume) {
        vireo_result_t r = vireo_tcp_server_release_client(server, client, error);
        if (r != VIREO_OK)
            return r;
    }
    *error = p->error;
    errno = EPIPE;
    return p->result;
}
static fault_probe_t fault(bool consume, vireo_result_t result) {
    fault_probe_t p = {0};
    p.consume = consume;
    p.result = result;
    p.error.primary.stage =
        consume ? VIREO_TCP_SERVER_CLIENT_RELEASE : VIREO_TCP_SERVER_CLIENT_DETACH;
    if (consume) {
        p.error.primary.pool_error.stage = VIREO_CONNECTION_POOL_OPERATION_DESTROY_CONNECTION;
        p.error.primary.pool_error.connection_error.stage = VIREO_CONNECTION_STAGE_CLOSE_SOCKET;
        p.error.primary.pool_error.connection_error.system_errno = EIO;
    } else {
        p.error.primary.loop_error.stage = VIREO_CONNECTION_LOOP_STAGE_DETACH;
        p.error.primary.loop_error.loop_error.stage = VIREO_EVENT_LOOP_STAGE_DEL;
        p.error.primary.loop_error.loop_error.epoll_error.stage = VIREO_EPOLL_STAGE_DEL;
        p.error.primary.loop_error.loop_error.epoll_error.system_errno = EBADF;
    }
    p.error.cleanup_result = VIREO_RESULT_IO;
    p.error.cleanup.stage = VIREO_TCP_SERVER_CLIENT_RELEASE;
    p.error.cleanup.system_errno = ENOSPC;
    return p;
}
static bool injected(fixture_t *f, bool consume, vireo_result_t result) {
    CHECK(expire_at(f, 0, 0, 110) && close_at(f, 0, IMMEDIATE));
    vireo_client_deadline_binding_t old = f->bindings[0], empty = {0};
    vireo_tcp_server_client_info_t before, after;
    CHECK(vireo_tcp_server_client_inspect(f->server, old.client, &before) == VIREO_OK);
    fault_probe_t p = fault(consume, result);
    vireo_client_deadline_release_report_t report;
    errno = ERANGE;
    CHECK(vireo_client_deadline_release_ready_expired_runtime(f->server, &f->bindings[0],
                                                              &f->expired[0], &report,
                                                              injected_release, &p) == result &&
          errno == ERANGE);
    CHECK(p.calls == 1 && report.release_called && report.client_consumed == consume &&
          report.stage == VIREO_CLIENT_DEADLINE_RELEASE_CLIENT &&
          same_error(report.client_error, p.error));
    CHECK(same_binding(f->bindings[0], consume ? empty : old));
    if (consume)
        CHECK(consumed_client(f, old.client));
    else {
        CHECK(vireo_tcp_server_client_inspect(f->server, old.client, &after) == VIREO_OK &&
              same_client_info(&before, &after));
    }
    vireo_client_deadline_binding_t record;
    CHECK(vireo_client_deadline_store_find(f->store, old.timer, &record) == VIREO_OK &&
          same_binding(record, old));
    return true;
}
static bool unconsumed_io(fixture_t *f) {
    return injected(f, false, VIREO_RESULT_IO);
}
static bool consumed_io(fixture_t *f) {
    return injected(f, true, VIREO_RESULT_IO);
}
static bool original_unknown(fixture_t *f) {
    return injected(f, false, (vireo_result_t)12345);
}
static bool seam_priority(fixture_t *f) {
    CHECK(expire_at(f, 0, 0, 110));
    fault_probe_t p = fault(false, VIREO_RESULT_BUSY);
    vireo_client_deadline_release_report_t report;
    vireo_client_deadline_binding_t b = f->bindings[0];
    ++b.timer.generation;
    CHECK(vireo_client_deadline_release_ready_expired_runtime(f->server, &b, &f->expired[0],
                                                              &report, injected_release,
                                                              &p) == VIREO_RESULT_NOT_FOUND &&
          p.calls == 0 && !report.release_called);
    CHECK(vireo_client_deadline_release_ready_expired_runtime(
              f->server, &f->bindings[0], &f->expired[0], &report, injected_release, &p) ==
              VIREO_RESULT_BUSY &&
          p.calls == 0 && report.stage == VIREO_CLIENT_DEADLINE_CHECK_READY_CLIENT);
    CHECK(close_at(f, 0, IMMEDIATE));
    CHECK(vireo_client_deadline_release_ready_expired_runtime(f->server, &f->bindings[0],
                                                              &f->expired[0], &report, NULL, &p) ==
              VIREO_RESULT_INVALID_ARGUMENT &&
          p.calls == 0);
    CHECK(vireo_client_deadline_release_ready_expired_runtime(
              f->server, &f->bindings[0], &f->expired[0], NULL, injected_release, &p) ==
              VIREO_RESULT_INVALID_ARGUMENT &&
          p.calls == 0);
    CHECK(vireo_client_deadline_release_ready_expired_runtime(
              f->server, &f->bindings[0], &f->expired[0], &report, injected_release, &p) ==
              VIREO_RESULT_BUSY &&
          p.calls == 1 && report.release_called && !report.client_consumed);
    return true;
}

/** 真实有界dispatch链的 caller 报告与数值保存，不保存通知地址。 */
typedef struct delivery_probe {
    fixture_t *fixture;                          /**< 当前 fixture 同步短借。 */
    size_t calls;                                /**< 实际 callback 次数。 */
    size_t taken;                                /**< 已从表取出数量。 */
    size_t consumed;                             /**< 已消费客户数量，错误时也计。 */
    vireo_client_deadline_binding_t bindings[2]; /**< caller 转出值，消费后按本项清空。 */
    vireo_client_deadline_release_report_t report; /**< 最后一次归还完整报告。 */
    bool inject_failure; /**< true 只启用自身 seam 的消费 IO 模拟。 */
    bool close_first;    /**< 测试显式先用021-05请求关闭；已closing场景false。 */
} delivery_probe_t;
static vireo_result_t deliver(vireo_timer_wheel_expired_t const *event, void *context) {
    delivery_probe_t *p = context;
    fixture_t *f = p->fixture;
    ++p->calls;
    if (p->taken >= 2)
        return VIREO_RESULT_RANGE;
    vireo_client_deadline_binding_t *binding = &p->bindings[p->taken];
    vireo_result_t r = vireo_client_deadline_store_take_expired(f->store, event, binding);
    if (r != VIREO_OK)
        return r;
    ++p->taken;
    vireo_connection_pool_lease_t old = binding->client;
    if (p->close_first) {
        r = vireo_client_deadline_request_close_expired(f->server, *binding, event, IMMEDIATE,
                                                        APPLICATION, NULL);
        if (r != VIREO_OK)
            return r;
    }
    if (p->inject_failure) {
        fault_probe_t faulted = fault(true, VIREO_RESULT_IO);
        r = vireo_client_deadline_release_ready_expired_runtime(
            f->server, binding, event, &p->report, injected_release, &faulted);
    } else
        r = vireo_client_deadline_release_ready_expired(f->server, binding, event, &p->report);
    if (p->report.client_consumed) {
        ++p->consumed;
        if (!consumed_client(f, old))
            return VIREO_RESULT_INTERNAL;
    }
    return r;
}
static bool bounded_dispatch(fixture_t *f) {
    CHECK(register_at(f, 0, 0, 100, 110) && save_at(f, 0) && register_at(f, 1, 1, 100, 110) &&
          save_at(f, 1) && advance_to(f->wheel, 110));
    delivery_probe_t p = {0};
    p.fixture = f;
    p.close_first = true;
    for (size_t i = 0; i < 2; ++i) {
        vireo_timer_loop_dispatch_report_t report;
        errno = EDOM;
        CHECK(vireo_timer_loop_dispatch(f->wheel, 1, deliver, &p, &report) == VIREO_OK &&
              errno == EDOM);
        CHECK(report.consumed_count == 1 && report.delivered_count == 1 && p.calls == i + 1 &&
              p.taken == i + 1 && p.consumed == i + 1 && p.report.client_consumed &&
              count_is(f, 1 - i));
    }
    return true;
}
static bool failed_dispatch(fixture_t *f, bool stale) {
    CHECK(register_at(f, 0, 0, 100, 110) && save_at(f, 0) && advance_to(f->wheel, 110));
    if (stale) {
        CHECK(vireo_tcp_server_client_request_close(f->server, f->clients[0], IMMEDIATE,
                                                    APPLICATION, NULL) == VIREO_OK);
        CHECK(vireo_tcp_server_release_client(f->server, &f->clients[0], NULL) == VIREO_OK);
        CHECK(close(f->peers[0]) == 0);
        f->peers[0] = -1;
        CHECK(add_client(f, 0));
    }
    delivery_probe_t p = {0};
    p.fixture = f;
    p.inject_failure = !stale;
    p.close_first = !stale;
    vireo_timer_loop_dispatch_report_t report;
    errno = EDOM;
    CHECK(vireo_timer_loop_dispatch(f->wheel, 1, deliver, &p, &report) ==
              (stale ? VIREO_RESULT_NOT_FOUND : VIREO_RESULT_IO) &&
          errno == EDOM);
    CHECK(report.consumed_count == 1 && report.delivered_count == 0 && report.has_failed_delivery &&
          report.stage == VIREO_TIMER_LOOP_DISPATCH_STAGE_DELIVER &&
          same_timer(report.failed_delivery.handle, f->bindings[0].timer));
    CHECK(p.calls == 1 && p.taken == 1 && p.consumed == (stale ? 0u : 1u) &&
          p.report.client_consumed == !stale && p.report.release_called == !stale &&
          count_is(f, 0));
    CHECK(p.report.stage ==
          (stale ? VIREO_CLIENT_DEADLINE_CHECK_CLIENT : VIREO_CLIENT_DEADLINE_RELEASE_CLIENT));
    vireo_client_deadline_binding_t const empty = {0};
    CHECK(same_binding(p.bindings[0], stale ? f->bindings[0] : empty));
    if (stale) {
        vireo_tcp_server_client_info_t info;
        CHECK(vireo_tcp_server_client_inspect(f->server, f->clients[0], &info) == VIREO_OK &&
              info.connection_info.close_state == VIREO_CONNECTION_CLOSE_OPEN);
    }
    return true;
}
static bool dispatch_consumed_error(fixture_t *f) {
    return failed_dispatch(f, false);
}
static bool dispatch_stale(fixture_t *f) {
    return failed_dispatch(f, true);
}
typedef struct test_case {
    char const *name;         /**< 静态场景名，不拥有字符串。 */
    bool (*run)(fixture_t *); /**< 同步断言入口，短借 fixture。 */
} test_case_t;
int main(void) {
    test_case_t const cases[] = {{"enum stability", enum_stability},
                                 {"immediate consumption and reuse", immediate_release},
                                 {"empty drain ready", empty_drain},
                                 {"open refuses release", open_busy},
                                 {"draining preserves queue", draining_busy},
                                 {"drain send refresh release", drain_send_refresh},
                                 {"basic null addresses", basic_null},
                                 {"mandatory report", missing_report},
                                 {"empty binding", empty_binding},
                                 {"half empty and malformed binding", malformed_binding},
                                 {"empty and malformed event", malformed_event},
                                 {"full historical match priority", full_history_match},
                                 {"cross pool", cross_pool},
                                 {"slot range", slot_range},
                                 {"old client reused", old_client_reused},
                                 {"consumed repeated not found", repeat_consumed},
                                 {"withdrawn record", withdrawn_record},
                                 {"other timer stays active", other_timer_untouched},
                                 {"stopped wheel", wheel_stopped},
                                 {"stopped server", server_stopped},
                                 {"simulated unconsumed IO", unconsumed_io},
                                 {"simulated consumed IO", consumed_io},
                                 {"original unknown result", original_unknown},
                                 {"seam priority and once only", seam_priority},
                                 {"bounded dispatch full chain", bounded_dispatch},
                                 {"dispatch consumption despite error", dispatch_consumed_error},
                                 {"dispatch stale no rollback", dispatch_stale}};
    size_t failed = 0;
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
        fixture_t f;
        bool ok = setup(&f);
        if (ok)
            ok = cases[i].run(&f);
        bool cleaned = cleanup(&f);
        ok = ok && cleaned;
        printf("%s: %s\n", cases[i].name, ok ? "PASS" : "FAIL");
        if (!ok)
            ++failed;
    }
    printf("%zu groups, %zu failed\n", sizeof cases / sizeof cases[0], failed);
    return failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
