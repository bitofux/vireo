/*
 * PROJECT : VIREO
 * FILE    : test_client_deadline_expired_close.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-10
 * BRIEF   : 此模块负责：
 * -- 验证历史到期匹配后显式单次关闭并保留部分失败诊断
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
#include "net/client_deadline_expired_close_internal.h"

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
    vireo_timer_wheel_t *wheel;       /**< 拥有本轮，固定准备容量二。 */
    vireo_timer_wheel_t *other_wheel; /**< 独立 owner，容量二。 */
    vireo_timer_wheel_t *unprepared;  /**< 独立未准备轮。 */
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

static bool close_ok(fixture_t *f, size_t index, vireo_connection_close_mode_t mode,
                     vireo_connection_close_reason_t reason) {
    vireo_client_deadline_close_error_t error;
    memset(&error, 0xa5, sizeof error);
    vireo_tcp_server_client_error_t const zero = {0};
    errno = ENOSPC;
    CHECK(vireo_client_deadline_request_close_expired(
              f->server, f->bindings[index], &f->expired[index], mode, reason, &error) == VIREO_OK);
    CHECK(errno == ENOSPC && error.stage == VIREO_CLIENT_DEADLINE_NONE && error.close_called);
    CHECK(same_error(error.client_error, zero));
    vireo_client_deadline_binding_t found;
    CHECK(vireo_client_deadline_store_find(f->store, f->bindings[index].timer, &found) == VIREO_OK);
    CHECK(same_binding(found, f->bindings[index]));
    vireo_timer_wheel_timer_info_t timer;
    CHECK(vireo_timer_wheel_get(index < 2 ? f->wheel : f->other_wheel, f->bindings[index].timer,
                                &timer) == VIREO_RESULT_NOT_FOUND);
    return true;
}

/** 前置拒绝须保持全部公开客户快照、caller 值和表，不读取 opaque 字节。 */
static bool rejected(fixture_t *f, vireo_tcp_server_t *server,
                     vireo_client_deadline_binding_t binding,
                     vireo_timer_wheel_expired_t const *event, vireo_connection_close_mode_t mode,
                     vireo_connection_close_reason_t reason, vireo_result_t result,
                     vireo_client_deadline_stage_t stage) {
    vireo_tcp_server_client_info_t before[2], after;
    for (size_t i = 0; i < 2; ++i)
        CHECK(vireo_tcp_server_client_inspect(f->server, f->clients[i], &before[i]) == VIREO_OK);
    unsigned char bytes[sizeof binding], event_bytes[sizeof *event];
    memcpy(bytes, &binding, sizeof binding);
    if (event != NULL)
        memcpy(event_bytes, event, sizeof *event);
    vireo_client_deadline_store_info_t store_before, store_after;
    CHECK(vireo_client_deadline_store_inspect(f->store, &store_before) == VIREO_OK);
    for (size_t pass = 0; pass < 2; ++pass) {
        vireo_client_deadline_close_error_t error;
        memset(&error, 0xa5, sizeof error);
        vireo_tcp_server_client_error_t const zero = {0};
        errno = ERANGE;
        CHECK(vireo_client_deadline_request_close_expired(server, binding, event, mode, reason,
                                                          pass == 0 ? &error : NULL) == result &&
              errno == ERANGE);
        CHECK(pass != 0 || (error.stage == stage && !error.close_called &&
                            same_error(error.client_error, zero)));
        CHECK(memcmp(bytes, &binding, sizeof binding) == 0);
        CHECK(event == NULL || memcmp(event_bytes, event, sizeof *event) == 0);
        for (size_t i = 0; i < 2; ++i) {
            CHECK(vireo_tcp_server_client_inspect(f->server, f->clients[i], &after) == VIREO_OK);
            CHECK(same_client_info(&before[i], &after));
        }
        CHECK(vireo_client_deadline_store_inspect(f->store, &store_after) == VIREO_OK);
        CHECK(store_before.capacity == store_after.capacity &&
              store_before.count == store_after.count &&
              store_before.allocation_bytes == store_after.allocation_bytes &&
              store_before.max_memory_bytes == store_after.max_memory_bytes);
        for (size_t i = 0; i < 4; ++i) {
            if (f->bindings[i].timer.owner_id != 0) {
                vireo_client_deadline_binding_t found;
                CHECK(vireo_client_deadline_store_find(f->store, f->bindings[i].timer, &found) ==
                      VIREO_OK);
                CHECK(same_binding(found, f->bindings[i]));
            }
        }
    }
    return true;
}

#define IMMEDIATE VIREO_CONNECTION_CLOSE_MODE_IMMEDIATE
#define DRAIN VIREO_CONNECTION_CLOSE_MODE_DRAIN
#define APPLICATION VIREO_CONNECTION_CLOSE_REASON_APPLICATION
#define REFUSE(s, b, e, m, r, result, stage) CHECK(rejected(f, s, b, e, m, r, result, stage))

static bool enum_stability(fixture_t *f) {
    (void)f;
    CHECK(VIREO_CLIENT_DEADLINE_NONE == 0 && VIREO_CLIENT_DEADLINE_CHECK_CLIENT == 1 &&
          VIREO_CLIENT_DEADLINE_CHECK_TIMER == 2 && VIREO_CLIENT_DEADLINE_MATCH_TIMER == 3 &&
          VIREO_CLIENT_DEADLINE_REGISTER_TIMER == 4 && VIREO_CLIENT_DEADLINE_CANCEL_TIMER == 5 &&
          VIREO_CLIENT_DEADLINE_REARM_TIMER == 6 &&
          VIREO_CLIENT_DEADLINE_REQUEST_CLOSE_CLIENT == 7);
    return true;
}
static bool immediate_owned(fixture_t *f) {
    CHECK(expire_at(f, 0, 0, 110) && close_ok(f, 0, IMMEDIATE, APPLICATION));
    vireo_tcp_server_client_info_t info;
    CHECK(vireo_tcp_server_client_inspect(f->server, f->clients[0], &info) == VIREO_OK);
    CHECK(info.connection_info.close_state == VIREO_CONNECTION_CLOSE_READY &&
          info.connection_info.buffer_capacity_bytes == 128 && info.connection_info.loop_attached);
    CHECK(vireo_tcp_server_client_inspect(f->server, f->clients[1], &info) == VIREO_OK);
    CHECK(info.connection_info.close_state == VIREO_CONNECTION_CLOSE_OPEN);
    CHECK(count_is(f, 1));
    vireo_connection_pool_lease_t old = f->clients[0];
    CHECK(vireo_tcp_server_release_client(f->server, &f->clients[0], NULL) == VIREO_OK);
    CHECK(vireo_tcp_server_client_inspect(f->server, old, &info) == VIREO_RESULT_NOT_FOUND);
    return true;
}
static bool drain_send_refresh(fixture_t *f) {
    uint8_t const message[] = {'b', 'y', 'e', '!'};
    CHECK(vireo_tcp_server_client_write_enqueue(f->server, f->clients[0], message, sizeof message,
                                                NULL) == VIREO_OK);
    CHECK(expire_at(f, 0, 0, 110) && close_ok(f, 0, DRAIN, APPLICATION));
    vireo_tcp_server_client_info_t info;
    CHECK(vireo_tcp_server_client_inspect(f->server, f->clients[0], &info) == VIREO_OK);
    CHECK(info.connection_info.close_state == VIREO_CONNECTION_CLOSE_DRAINING &&
          info.connection_info.write_buffer.readable_size == 4);
    vireo_connection_send_budget_t const budget = {4, 1};
    vireo_connection_send_info_t sent;
    CHECK(vireo_tcp_server_client_send(f->server, f->clients[0], &budget, &sent, NULL) == VIREO_OK);
    CHECK(sent.sent_bytes == 4 && sent.send_calls == 1);
    struct pollfd peer_ready = {f->peers[0], POLLIN, 0};
    CHECK(poll(&peer_ready, 1, 1000) == 1 && (peer_ready.revents & POLLIN) != 0);
    uint8_t received[4];
    CHECK(recv(f->peers[0], received, sizeof received, MSG_DONTWAIT) == 4);
    CHECK(memcmp(message, received, 4) == 0);
    CHECK(vireo_tcp_server_client_inspect(f->server, f->clients[0], &info) == VIREO_OK);
    CHECK(info.connection_info.close_state == VIREO_CONNECTION_CLOSE_DRAINING);
    CHECK(vireo_tcp_server_client_close_refresh(f->server, f->clients[0], NULL) == VIREO_OK);
    CHECK(vireo_tcp_server_client_inspect(f->server, f->clients[0], &info) == VIREO_OK);
    CHECK(info.connection_info.close_state == VIREO_CONNECTION_CLOSE_READY);
    return true;
}
static bool drain_empty(fixture_t *f) {
    CHECK(expire_at(f, 0, 0, 110) && close_ok(f, 0, DRAIN, APPLICATION));
    vireo_tcp_server_client_info_t info;
    CHECK(vireo_tcp_server_client_inspect(f->server, f->clients[0], &info) == VIREO_OK);
    CHECK(info.connection_info.close_state == VIREO_CONNECTION_CLOSE_READY);
    return true;
}
static bool basic_addresses(fixture_t *f) {
    CHECK(expire_at(f, 0, 0, 110));
    REFUSE(NULL, f->bindings[0], &f->expired[0], IMMEDIATE, APPLICATION,
           VIREO_RESULT_INVALID_ARGUMENT, VIREO_CLIENT_DEADLINE_NONE);
    REFUSE(f->server, f->bindings[0], NULL, IMMEDIATE, APPLICATION, VIREO_RESULT_INVALID_ARGUMENT,
           VIREO_CLIENT_DEADLINE_NONE);
    return true;
}
static bool invalid_modes(fixture_t *f) {
    CHECK(expire_at(f, 0, 0, 110));
    vireo_client_deadline_binding_t const empty = {0};
    REFUSE(f->server, empty, &f->expired[0], VIREO_CONNECTION_CLOSE_MODE_NONE, APPLICATION,
           VIREO_RESULT_INVALID_ARGUMENT, VIREO_CLIENT_DEADLINE_NONE);
    int const modes[] = {0, 3, -1};
    for (size_t i = 0; i < 3; ++i)
        REFUSE(f->server, f->bindings[0], &f->expired[0], (vireo_connection_close_mode_t)modes[i],
               APPLICATION, VIREO_RESULT_INVALID_ARGUMENT, VIREO_CLIENT_DEADLINE_NONE);
    return true;
}
static bool invalid_reasons(fixture_t *f) {
    CHECK(expire_at(f, 0, 0, 110));
    int const reasons[] = {0, 7, -1};
    for (size_t i = 0; i < 3; ++i)
        REFUSE(f->server, f->bindings[0], &f->expired[0], IMMEDIATE,
               (vireo_connection_close_reason_t)reasons[i], VIREO_RESULT_INVALID_ARGUMENT,
               VIREO_CLIENT_DEADLINE_NONE);
    return true;
}
static bool malformed_bindings(fixture_t *f) {
    CHECK(expire_at(f, 0, 0, 110));
    vireo_client_deadline_binding_t b = {0};
    REFUSE(f->server, b, &f->expired[0], IMMEDIATE, APPLICATION, VIREO_RESULT_NOT_FOUND,
           VIREO_CLIENT_DEADLINE_NONE);
    b = f->bindings[0];
    b.client.generation = 0;
    REFUSE(f->server, b, &f->expired[0], IMMEDIATE, APPLICATION, VIREO_RESULT_INVALID_ARGUMENT,
           VIREO_CLIENT_DEADLINE_NONE);
    b = f->bindings[0];
    b.timer.generation = 0;
    REFUSE(f->server, b, &f->expired[0], IMMEDIATE, APPLICATION, VIREO_RESULT_INVALID_ARGUMENT,
           VIREO_CLIENT_DEADLINE_NONE);
    b = f->bindings[0];
    b.client = (vireo_connection_pool_lease_t){0};
    REFUSE(f->server, b, &f->expired[0], IMMEDIATE, APPLICATION, VIREO_RESULT_INVALID_ARGUMENT,
           VIREO_CLIENT_DEADLINE_NONE);
    b = f->bindings[0];
    b.timer = (vireo_timer_handle_t){0};
    REFUSE(f->server, b, &f->expired[0], IMMEDIATE, APPLICATION, VIREO_RESULT_INVALID_ARGUMENT,
           VIREO_CLIENT_DEADLINE_NONE);
    return true;
}
static bool malformed_events(fixture_t *f) {
    CHECK(expire_at(f, 0, 0, 110));
    vireo_timer_wheel_expired_t e = {0};
    REFUSE(f->server, f->bindings[0], &e, IMMEDIATE, APPLICATION, VIREO_RESULT_NOT_FOUND,
           VIREO_CLIENT_DEADLINE_NONE);
    e = f->expired[0];
    e.handle.owner_id = 0;
    REFUSE(f->server, f->bindings[0], &e, IMMEDIATE, APPLICATION, VIREO_RESULT_INVALID_ARGUMENT,
           VIREO_CLIENT_DEADLINE_NONE);
    return true;
}
static bool full_timer_match(fixture_t *f) {
    CHECK(expire_at(f, 0, 0, 110));
    for (size_t i = 0; i < 3; ++i) {
        vireo_client_deadline_binding_t b = f->bindings[0];
        if (i == 0) {
            ++b.timer.owner_id;
            ++b.client.generation; /* 证明历史匹配先于旧客户拒绝。 */
        }
        if (i == 1)
            ++b.timer.slot_index;
        if (i == 2)
            ++b.timer.generation;
        REFUSE(f->server, b, &f->expired[0], IMMEDIATE, APPLICATION, VIREO_RESULT_NOT_FOUND,
               VIREO_CLIENT_DEADLINE_MATCH_TIMER);
    }
    return true;
}
static bool foreign_client(fixture_t *f) {
    CHECK(expire_at(f, 0, 0, 110));
    REFUSE(f->other_server, f->bindings[0], &f->expired[0], IMMEDIATE, APPLICATION,
           VIREO_RESULT_INVALID_ARGUMENT, VIREO_CLIENT_DEADLINE_CHECK_CLIENT);
    return true;
}
static bool client_slot_range(fixture_t *f) {
    CHECK(expire_at(f, 0, 0, 110));
    vireo_client_deadline_binding_t b = f->bindings[0];
    b.client.slot_index = 2;
    REFUSE(f->server, b, &f->expired[0], IMMEDIATE, APPLICATION, VIREO_RESULT_RANGE,
           VIREO_CLIENT_DEADLINE_CHECK_CLIENT);
    return true;
}
static bool old_client_reused(fixture_t *f) {
    CHECK(expire_at(f, 0, 0, 110));
    vireo_connection_pool_lease_t old = f->clients[0];
    CHECK(vireo_tcp_server_release_client(f->server, &f->clients[0], NULL) == VIREO_OK);
    CHECK(close(f->peers[0]) == 0);
    f->peers[0] = -1;
    CHECK(add_client(f, 0));
    CHECK(old.slot_index == f->clients[0].slot_index && old.generation != f->clients[0].generation);
    REFUSE(f->server, f->bindings[0], &f->expired[0], IMMEDIATE, APPLICATION,
           VIREO_RESULT_NOT_FOUND, VIREO_CLIENT_DEADLINE_CHECK_CLIENT);
    return true;
}
static bool repeat_and_reasons(fixture_t *f) {
    CHECK(expire_at(f, 0, 0, 110));
    for (int i = 1; i <= 6; ++i)
        CHECK(close_ok(f, 0, IMMEDIATE, (vireo_connection_close_reason_t)i));
    vireo_tcp_server_client_info_t info;
    CHECK(vireo_tcp_server_client_inspect(f->server, f->clients[0], &info) == VIREO_OK);
    CHECK(info.connection_info.close_reason == APPLICATION);
    return true;
}
static bool upgrade(fixture_t *f) {
    uint8_t const data = 1;
    CHECK(vireo_tcp_server_client_write_enqueue(f->server, f->clients[0], &data, 1, NULL) ==
          VIREO_OK);
    CHECK(expire_at(f, 0, 0, 110) && close_ok(f, 0, DRAIN, APPLICATION));
    CHECK(close_ok(f, 0, IMMEDIATE, VIREO_CONNECTION_CLOSE_REASON_IO));
    vireo_tcp_server_client_info_t info;
    CHECK(vireo_tcp_server_client_inspect(f->server, f->clients[0], &info) == VIREO_OK);
    CHECK(info.connection_info.close_state == VIREO_CONNECTION_CLOSE_READY &&
          info.connection_info.close_reason == APPLICATION &&
          info.connection_info.write_buffer.readable_size == 1);
    return true;
}
static bool reverse_busy(fixture_t *f) {
    CHECK(expire_at(f, 0, 0, 110) && close_ok(f, 0, IMMEDIATE, APPLICATION));
    vireo_tcp_server_client_info_t before, after;
    CHECK(vireo_tcp_server_client_inspect(f->server, f->clients[0], &before) == VIREO_OK);
    vireo_tcp_server_client_error_t native;
    CHECK(vireo_tcp_server_client_request_close(f->server, f->clients[0], DRAIN, APPLICATION,
                                                &native) == VIREO_RESULT_BUSY);
    for (size_t i = 0; i < 2; ++i) {
        vireo_client_deadline_close_error_t error;
        errno = EDOM;
        CHECK(vireo_client_deadline_request_close_expired(
                  f->server, f->bindings[0], &f->expired[0], DRAIN, APPLICATION,
                  i == 0 ? &error : NULL) == VIREO_RESULT_BUSY &&
              errno == EDOM);
        CHECK(i != 0 || (error.stage == VIREO_CLIENT_DEADLINE_REQUEST_CLOSE_CLIENT &&
                         error.close_called && same_error(error.client_error, native)));
    }
    CHECK(vireo_tcp_server_client_inspect(f->server, f->clients[0], &after) == VIREO_OK);
    CHECK(same_client_info(&before, &after) && count_is(f, 1));
    return true;
}
static bool withdrawn_record(fixture_t *f) {
    CHECK(expire_at(f, 0, 0, 110));
    vireo_client_deadline_binding_t binding;
    CHECK(vireo_client_deadline_store_take_expired(f->store, &f->expired[0], &binding) == VIREO_OK);
    CHECK(same_binding(binding, f->bindings[0]) && count_is(f, 0));
    errno = EDOM;
    CHECK(vireo_client_deadline_request_close_expired(f->server, binding, &f->expired[0], IMMEDIATE,
                                                      APPLICATION, NULL) == VIREO_OK &&
          errno == EDOM);
    CHECK(count_is(f, 0));
    return true;
}
static bool another_timer_untouched(fixture_t *f) {
    CHECK(register_at(f, 0, 0, 100, 110) && save_at(f, 0));
    CHECK(register_at(f, 1, 0, 100, 120) && save_at(f, 1));
    CHECK(advance_to(f->wheel, 110));
    CHECK(vireo_timer_wheel_take_expired(f->wheel, &f->expired[0]) == VIREO_OK);
    CHECK(same_timer(f->expired[0].handle, f->bindings[0].timer));
    CHECK(close_ok(f, 0, IMMEDIATE, APPLICATION));
    vireo_timer_wheel_timer_info_t timer;
    CHECK(vireo_timer_wheel_get(f->wheel, f->bindings[1].timer, &timer) == VIREO_OK &&
          timer.deadline_ns == 120);
    CHECK(advance_to(f->wheel, 120));
    CHECK(vireo_timer_wheel_take_expired(f->wheel, &f->expired[1]) == VIREO_OK);
    CHECK(same_timer(f->expired[1].handle, f->bindings[1].timer));
    CHECK(close_ok(f, 1, IMMEDIATE, APPLICATION) && count_is(f, 2));
    return true;
}
static bool stopped_wheel(fixture_t *f) {
    CHECK(register_at(f, 0, 0, 100, 110) && save_at(f, 0) && advance_to(f->wheel, 110));
    CHECK(vireo_timer_wheel_shutdown_begin(f->wheel) == VIREO_OK);
    CHECK(vireo_timer_wheel_take_expired(f->wheel, &f->expired[0]) == VIREO_OK);
    CHECK(close_ok(f, 0, IMMEDIATE, APPLICATION));
    return true;
}
static bool borrowed_read(fixture_t *f) {
    uint8_t const bytes[] = {1, 2, 3, 4};
    CHECK(send(f->peers[0], bytes, 4, MSG_NOSIGNAL) == 4);
    vireo_connection_receive_budget_t const budget = {4, 1};
    vireo_connection_receive_info_t info;
    CHECK(vireo_tcp_server_client_receive(f->server, f->clients[0], &budget, &info, NULL) ==
              VIREO_OK &&
          info.received_bytes == 4);
    uint8_t const *borrow;
    size_t size;
    CHECK(vireo_tcp_server_client_read_peek(f->server, f->clients[0], &borrow, &size, NULL) ==
              VIREO_OK &&
          size == 4);
    CHECK(expire_at(f, 0, 0, 110) && close_ok(f, 0, IMMEDIATE, APPLICATION));
    CHECK(memcmp(borrow, bytes, 4) == 0);
    uint8_t const *after;
    size_t after_size;
    CHECK(vireo_tcp_server_client_read_peek(f->server, f->clients[0], &after, &after_size, NULL) ==
              VIREO_OK &&
          after == borrow && after_size == size);
    return true;
}

/** 自有 seam 的同步诊断探针；模拟返回值，不冒充真实 MOD syscall 故障。 */
typedef struct fault_probe {
    size_t calls;          /**< 实际依赖调用次数，初零。 */
    bool commit;           /**< 为 true 时先实际请求关闭，再注入失败。 */
    vireo_result_t result; /**< 要原样透传的模拟分类。 */
    vireo_tcp_server_client_error_t error; /**< 要原样透传的完整模拟诊断值。 */
} fault_probe_t;
static vireo_result_t injected_close(vireo_tcp_server_t *server,
                                     vireo_connection_pool_lease_t client,
                                     vireo_connection_close_mode_t mode,
                                     vireo_connection_close_reason_t reason,
                                     vireo_tcp_server_client_error_t *error, void *context) {
    fault_probe_t *p = context;
    ++p->calls;
    if (p->commit) {
        vireo_result_t r =
            vireo_tcp_server_client_request_close(server, client, mode, reason, NULL);
        if (r != VIREO_OK)
            return r;
    }
    *error = p->error;
    errno = EPIPE;
    return p->result;
}
static fault_probe_t io_probe(void) {
    fault_probe_t p = {0};
    p.commit = true;
    p.result = VIREO_RESULT_IO;
    p.error.primary.stage = VIREO_TCP_SERVER_CLIENT_REQUEST_CLOSE;
    p.error.primary.loop_error.stage = VIREO_CONNECTION_LOOP_STAGE_REQUEST_CLOSE;
    p.error.primary.loop_error.loop_error.stage = VIREO_EVENT_LOOP_STAGE_MOD;
    p.error.primary.loop_error.loop_error.epoll_error.stage = VIREO_EPOLL_STAGE_MOD;
    p.error.primary.loop_error.loop_error.epoll_error.system_errno = EBADF;
    p.error.cleanup_result = VIREO_RESULT_IO;
    p.error.cleanup.stage = VIREO_TCP_SERVER_CLIENT_DETACH;
    p.error.cleanup.loop_error.stage = VIREO_CONNECTION_LOOP_STAGE_DETACH;
    p.error.cleanup.loop_error.loop_error.stage = VIREO_EVENT_LOOP_STAGE_DEL;
    p.error.cleanup.loop_error.loop_error.epoll_error.stage = VIREO_EPOLL_STAGE_DEL;
    p.error.cleanup.loop_error.loop_error.epoll_error.system_errno = ENOENT;
    return p;
}
static bool injected_partial(fixture_t *f) {
    CHECK(expire_at(f, 0, 0, 110));
    fault_probe_t p = io_probe();
    vireo_client_deadline_close_error_t error;
    errno = ENOSPC;
    CHECK(vireo_client_deadline_request_close_expired_runtime(
              f->server, f->bindings[0], &f->expired[0], IMMEDIATE, APPLICATION, &error,
              injected_close, &p) == VIREO_RESULT_IO &&
          errno == ENOSPC);
    CHECK(p.calls == 1 && error.close_called &&
          error.stage == VIREO_CLIENT_DEADLINE_REQUEST_CLOSE_CLIENT &&
          same_error(error.client_error, p.error));
    vireo_tcp_server_client_info_t info;
    CHECK(vireo_tcp_server_client_inspect(f->server, f->clients[0], &info) == VIREO_OK &&
          info.connection_info.close_state == VIREO_CONNECTION_CLOSE_READY);
    vireo_client_deadline_binding_t found;
    CHECK(vireo_client_deadline_store_find(f->store, f->bindings[0].timer, &found) == VIREO_OK &&
          same_binding(found, f->bindings[0]));
    CHECK(vireo_tcp_server_client_close_refresh(f->server, f->clients[0], NULL) == VIREO_OK);
    CHECK(vireo_tcp_server_release_client(f->server, &f->clients[0], NULL) == VIREO_OK);
    return true;
}
static bool seam_priority(fixture_t *f) {
    CHECK(expire_at(f, 0, 0, 110));
    fault_probe_t p = io_probe();
    vireo_client_deadline_close_error_t error;
    vireo_client_deadline_binding_t b = f->bindings[0];
    ++b.timer.generation;
    CHECK(vireo_client_deadline_request_close_expired_runtime(
              f->server, b, &f->expired[0], IMMEDIATE, APPLICATION, &error, injected_close, &p) ==
              VIREO_RESULT_NOT_FOUND &&
          p.calls == 0 && !error.close_called);
    CHECK(vireo_client_deadline_request_close_expired_runtime(
              f->server, f->bindings[0], &f->expired[0], IMMEDIATE, APPLICATION, &error, NULL,
              &p) == VIREO_RESULT_INVALID_ARGUMENT &&
          p.calls == 0 && !error.close_called);
    p.commit = false;
    p.result = (vireo_result_t)12345;
    errno = ERANGE;
    CHECK(vireo_client_deadline_request_close_expired_runtime(
              f->server, f->bindings[0], &f->expired[0], IMMEDIATE, APPLICATION, &error,
              injected_close, &p) == (vireo_result_t)12345 &&
          errno == ERANGE && p.calls == 1 && same_error(error.client_error, p.error));
    return true;
}

/** dispatch 同步短借 context；保存数值，不保存通知地址。 */
typedef struct delivery_probe {
    fixture_t *fixture;                          /**< 当前 fixture 短借，不保活。 */
    size_t calls;                                /**< 真实 callback 调用次数。 */
    size_t taken;                                /**< 成功从记录表取出的数量。 */
    vireo_client_deadline_binding_t bindings[2]; /**< caller 保存已转出的历史绑定。 */
    vireo_client_deadline_close_error_t error;   /**< 最后一次关闭诊断。 */
    vireo_connection_close_mode_t mode;          /**< caller 显式关闭模式。 */
    vireo_connection_close_reason_t reason;      /**< caller 显式关闭理由。 */
    bool inject_failure; /**< 仅测试启用自身 seam 模拟部分失败。 */
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
    if (p->inject_failure) {
        fault_probe_t fault = io_probe();
        return vireo_client_deadline_request_close_expired_runtime(
            f->server, *binding, event, p->mode, p->reason, &p->error, injected_close, &fault);
    }
    return vireo_client_deadline_request_close_expired(f->server, *binding, event, p->mode,
                                                       p->reason, &p->error);
}
static bool dispatch_bounded(fixture_t *f) {
    CHECK(register_at(f, 0, 0, 100, 110) && save_at(f, 0));
    CHECK(register_at(f, 1, 1, 100, 110) && save_at(f, 1) && advance_to(f->wheel, 110));
    delivery_probe_t p = {0};
    p.fixture = f;
    p.mode = IMMEDIATE;
    p.reason = APPLICATION;
    for (size_t i = 0; i < 2; ++i) {
        vireo_timer_loop_dispatch_report_t report;
        errno = EDOM;
        CHECK(vireo_timer_loop_dispatch(f->wheel, 1, deliver, &p, &report) == VIREO_OK &&
              errno == EDOM);
        CHECK(report.consumed_count == 1 && report.delivered_count == 1 &&
              !report.has_failed_delivery && p.calls == i + 1 && p.taken == i + 1);
        CHECK(count_is(f, 1 - i));
    }
    CHECK(!same_timer(p.bindings[0].timer, p.bindings[1].timer));
    for (size_t i = 0; i < 2; ++i) {
        vireo_tcp_server_client_info_t info;
        CHECK(vireo_tcp_server_client_inspect(f->server, f->clients[i], &info) == VIREO_OK &&
              info.connection_info.close_state == VIREO_CONNECTION_CLOSE_READY);
    }
    return true;
}
static bool dispatch_failure(fixture_t *f, bool stale) {
    CHECK(register_at(f, 0, 0, 100, 110) && save_at(f, 0) && advance_to(f->wheel, 110));
    if (stale) {
        CHECK(vireo_tcp_server_release_client(f->server, &f->clients[0], NULL) == VIREO_OK);
        CHECK(close(f->peers[0]) == 0);
        f->peers[0] = -1;
        CHECK(add_client(f, 0));
    }
    delivery_probe_t p = {0};
    p.fixture = f;
    p.mode = IMMEDIATE;
    p.reason = APPLICATION;
    p.inject_failure = !stale;
    vireo_timer_loop_dispatch_report_t report;
    errno = EDOM;
    CHECK(vireo_timer_loop_dispatch(f->wheel, 2, deliver, &p, &report) ==
              (stale ? VIREO_RESULT_NOT_FOUND : VIREO_RESULT_IO) &&
          errno == EDOM);
    CHECK(report.consumed_count == 1 && report.delivered_count == 0 && report.has_failed_delivery &&
          report.stage == VIREO_TIMER_LOOP_DISPATCH_STAGE_DELIVER);
    CHECK(p.calls == 1 && p.taken == 1 && same_binding(p.bindings[0], f->bindings[0]) &&
          same_timer(report.failed_delivery.handle, f->bindings[0].timer) && count_is(f, 0));
    CHECK(p.error.close_called == !stale &&
          p.error.stage == (stale ? VIREO_CLIENT_DEADLINE_CHECK_CLIENT
                                  : VIREO_CLIENT_DEADLINE_REQUEST_CLOSE_CLIENT));
    vireo_tcp_server_client_info_t info;
    CHECK(vireo_tcp_server_client_inspect(f->server, f->clients[0], &info) == VIREO_OK);
    CHECK(info.connection_info.close_state ==
          (stale ? VIREO_CONNECTION_CLOSE_OPEN : VIREO_CONNECTION_CLOSE_READY));
    vireo_timer_wheel_timer_info_t timer;
    CHECK(vireo_timer_wheel_get(f->wheel, f->bindings[0].timer, &timer) == VIREO_RESULT_NOT_FOUND);
    return true;
}
static bool dispatch_stale(fixture_t *f) {
    return dispatch_failure(f, true);
}
static bool dispatch_partial(fixture_t *f) {
    return dispatch_failure(f, false);
}

typedef struct test_case {
    char const *name;         /**< 静态场景名，不拥有字符串。 */
    bool (*run)(fixture_t *); /**< 同步断言入口，短借 fixture。 */
} test_case_t;
int main(void) {
    test_case_t const cases[] = {{"enum stability", enum_stability},
                                 {"immediate remains owned", immediate_owned},
                                 {"drain send refresh", drain_send_refresh},
                                 {"empty drain ready", drain_empty},
                                 {"basic addresses", basic_addresses},
                                 {"invalid modes", invalid_modes},
                                 {"invalid reasons", invalid_reasons},
                                 {"malformed bindings", malformed_bindings},
                                 {"malformed events", malformed_events},
                                 {"full timer match", full_timer_match},
                                 {"foreign client", foreign_client},
                                 {"client slot range", client_slot_range},
                                 {"old client reused", old_client_reused},
                                 {"repeat and six reasons", repeat_and_reasons},
                                 {"drain upgrade", upgrade},
                                 {"reverse busy raw diagnostic", reverse_busy},
                                 {"withdrawn record", withdrawn_record},
                                 {"another timer untouched", another_timer_untouched},
                                 {"stopped wheel history", stopped_wheel},
                                 {"read borrow preserved", borrowed_read},
                                 {"injected partial diagnostic", injected_partial},
                                 {"seam priority and raw result", seam_priority},
                                 {"bounded dispatch", dispatch_bounded},
                                 {"dispatch stale no rollback", dispatch_stale},
                                 {"dispatch partial no rollback", dispatch_partial}};
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
