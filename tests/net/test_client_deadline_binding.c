/*
 * PROJECT : VIREO
 * FILE    : test_client_deadline_binding.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-09
 * BRIEF   : 此模块负责：
 * -- 验证完整客户与 timer 的当前核验及历史身份匹配
 * -- 只依赖已采用公开合同，保持资源、输出与 errno 的既有边界
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vireo/net/client_deadline.h>
#include <vireo/net/timer_loop_dispatch.h>
#include <vireo/timer/wheel_shutdown.h>

#define CHECK(expr)                                                    \
    do {                                                               \
        if (!(expr)) {                                                 \
            fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #expr); \
            return false;                                              \
        }                                                              \
    } while (0)

/** 真实 loopback 客户与公开轮的测试 owner；没有私有对象借用。 */
typedef struct fixture {
    vireo_tcp_server_t *server;           /**< 本客户的唯一 server owner。 */
    vireo_tcp_server_t *other_server;     /**< 空的不同 pool，用于跨所属核验。 */
    vireo_timer_wheel_t *wheel;           /**< 本 timer 的唯一轮 owner，固定容量一。 */
    vireo_timer_wheel_t *other_wheel;     /**< 不同 owner 的准备轮。 */
    vireo_timer_wheel_t *unprepared;      /**< 未 prepare 轮，用于原分类检查。 */
    vireo_connection_pool_lease_t client; /**< 当前客户租约，归还清零。 */
    vireo_timer_handle_t timer; /**< 当前或已领取历史 timer，清理只尝试公开取消。 */
    vireo_timer_handle_t other_timer; /**< 不同轮的登记，独立归还。 */
    int peer;                         /**< caller 拥有的真实 TCP 对端 fd，-1 为空。 */
    int listener_fd;                  /**< 构造期间 caller listener fd；转移后 -1。 */
    vireo_acceptor_t *listener;       /**< 构造期间 acceptor owner；server 收纳后 NULL。 */
    struct sockaddr_in address; /**< 已分配的 loopback 端点值，供复用后重新连接。 */
} fixture_t;

static bool add_client(fixture_t *f) {
    f->peer = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    CHECK(f->peer >= 0);
    CHECK(connect(f->peer, (struct sockaddr const *)&f->address, sizeof f->address) == 0);
    vireo_connection_options_t const connection = {64, 64, 128};
    vireo_tcp_server_admit_budget_t const budget = {1, 1};
    vireo_tcp_server_admit_info_t info;
    CHECK(vireo_tcp_server_admit_batch(f->server, &connection, &budget, &f->client, 1, &info,
                                       NULL) == VIREO_OK);
    CHECK(info.admitted_count == 1 && info.accepted_count == 1);
    return true;
}

static bool setup(fixture_t *f) {
    memset(f, 0, sizeof *f);
    f->peer = -1;
    f->listener_fd = -1;
    vireo_tcp_server_options_t const server_options = {1, 2, VIREO_TCP_SERVER_MAX_MEMORY, 128};
    CHECK(vireo_tcp_server_create(&server_options, &f->server, NULL) == VIREO_OK);
    CHECK(vireo_tcp_server_create(&server_options, &f->other_server, NULL) == VIREO_OK);
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
    CHECK(add_client(f));
    vireo_timer_wheel_options_t const wheel_options = {{100, 10, 4}, VIREO_TIMER_WHEEL_MAX_MEMORY};
    vireo_timer_wheel_registry_options_t const registry = {1,
                                                           VIREO_TIMER_WHEEL_REGISTRY_MAX_MEMORY};
    CHECK(vireo_timer_wheel_create(&wheel_options, &f->wheel) == VIREO_OK);
    CHECK(vireo_timer_wheel_create(&wheel_options, &f->other_wheel) == VIREO_OK);
    CHECK(vireo_timer_wheel_create(&wheel_options, &f->unprepared) == VIREO_OK);
    CHECK(vireo_timer_wheel_prepare(f->wheel, &registry) == VIREO_OK);
    CHECK(vireo_timer_wheel_prepare(f->other_wheel, &registry) == VIREO_OK);
    CHECK(vireo_timer_wheel_register(f->wheel, 100, 110, &f->timer) == VIREO_OK);
    CHECK(vireo_timer_wheel_register(f->other_wheel, 100, 110, &f->other_timer) == VIREO_OK);
    return true;
}

static bool cleanup(fixture_t *f) {
    if (f->server != NULL && f->client.pool_id != 0) {
        CHECK(vireo_tcp_server_release_client(f->server, &f->client, NULL) == VIREO_OK);
    }
    if (f->peer >= 0) {
        CHECK(close(f->peer) == 0);
        f->peer = -1;
    }
    if (f->listener_fd >= 0) {
        CHECK(close(f->listener_fd) == 0);
        f->listener_fd = -1;
    }
    CHECK(vireo_acceptor_destroy(&f->listener, NULL) == VIREO_OK);
    if (f->wheel != NULL && f->timer.owner_id != 0) {
        vireo_result_t const result = vireo_timer_wheel_cancel(f->wheel, &f->timer);
        CHECK(result == VIREO_OK || result == VIREO_RESULT_NOT_FOUND);
    }
    if (f->other_wheel != NULL && f->other_timer.owner_id != 0) {
        CHECK(vireo_timer_wheel_cancel(f->other_wheel, &f->other_timer) == VIREO_OK);
    }
    CHECK(vireo_timer_wheel_destroy(&f->wheel) == VIREO_OK);
    CHECK(vireo_timer_wheel_destroy(&f->other_wheel) == VIREO_OK);
    CHECK(vireo_timer_wheel_destroy(&f->unprepared) == VIREO_OK);
    CHECK(vireo_tcp_server_destroy(&f->server, NULL) == VIREO_OK);
    CHECK(vireo_tcp_server_destroy(&f->other_server, NULL) == VIREO_OK);
    return true;
}

static bool same_client(vireo_connection_pool_lease_t a, vireo_connection_pool_lease_t b) {
    return a.pool_id == b.pool_id && a.slot_index == b.slot_index && a.generation == b.generation;
}

static bool same_timer(vireo_timer_handle_t a, vireo_timer_handle_t b) {
    return a.owner_id == b.owner_id && a.slot_index == b.slot_index && a.generation == b.generation;
}

/** 不比较成功快照 padding；逐项核对全部公开客户状态（含嵌套 buffer/flow）。 */
static bool same_info(vireo_tcp_server_client_info_t const *a,
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

static bool make_fails(vireo_tcp_server_t const *server, vireo_timer_wheel_t const *wheel,
                       vireo_connection_pool_lease_t client, vireo_timer_handle_t timer,
                       vireo_result_t result, vireo_client_deadline_stage_t expected_stage) {
    vireo_client_deadline_binding_t out;
    unsigned char before[sizeof out];
    memset(&out, 0xa5, sizeof out);
    memcpy(before, &out, sizeof out);
    vireo_client_deadline_stage_t stage = VIREO_CLIENT_DEADLINE_MATCH_TIMER;
    errno = EDOM;
    CHECK(vireo_client_deadline_make(server, wheel, client, timer, &out, &stage) == result);
    CHECK(errno == EDOM && stage == expected_stage && memcmp(before, &out, sizeof out) == 0);
    errno = ERANGE;
    CHECK(vireo_client_deadline_make(server, wheel, client, timer, &out, NULL) == result);
    CHECK(errno == ERANGE && memcmp(before, &out, sizeof out) == 0);
    return true;
}

static bool check_fails(vireo_tcp_server_t const *server, vireo_client_deadline_binding_t binding,
                        vireo_timer_wheel_expired_t const *expired, vireo_result_t result,
                        vireo_client_deadline_stage_t expected_stage) {
    vireo_tcp_server_client_info_t out;
    unsigned char before[sizeof out];
    memset(&out, 0xa5, sizeof out);
    memcpy(before, &out, sizeof out);
    vireo_client_deadline_stage_t stage = VIREO_CLIENT_DEADLINE_CHECK_TIMER;
    errno = EDOM;
    CHECK(vireo_client_deadline_check_expired(server, binding, expired, &out, &stage) == result);
    CHECK(errno == EDOM && stage == expected_stage && memcmp(before, &out, sizeof out) == 0);
    errno = ERANGE;
    CHECK(vireo_client_deadline_check_expired(server, binding, expired, &out, NULL) == result);
    CHECK(errno == ERANGE && memcmp(before, &out, sizeof out) == 0);
    return true;
}

static bool make_binding(fixture_t *f, vireo_client_deadline_binding_t *out) {
    vireo_client_deadline_stage_t stage = VIREO_CLIENT_DEADLINE_CHECK_TIMER;
    errno = EDOM;
    CHECK(vireo_client_deadline_make(f->server, f->wheel, f->client, f->timer, out, &stage) ==
          VIREO_OK);
    CHECK(errno == EDOM && stage == VIREO_CLIENT_DEADLINE_NONE);
    CHECK(same_client(out->client, f->client) && same_timer(out->timer, f->timer));
    return true;
}

static bool discover(fixture_t *f, vireo_monotonic_ns_t now) {
    vireo_timer_wheel_advance_report_t report;
    CHECK(vireo_timer_wheel_advance(f->wheel, now, (vireo_timer_wheel_advance_budget_t){4, 1},
                                    &report) == VIREO_OK);
    CHECK(report.progress.caught_up && report.progress.ready_count == 1);
    return true;
}

static bool expire(fixture_t *f, vireo_monotonic_ns_t now, vireo_timer_wheel_expired_t *out) {
    CHECK(discover(f, now));
    CHECK(vireo_timer_wheel_take_expired(f->wheel, out) == VIREO_OK);
    CHECK(same_timer(out->handle, f->timer));
    return true;
}

static bool check_success(fixture_t *f, vireo_client_deadline_binding_t binding,
                          vireo_timer_wheel_expired_t const *expired) {
    vireo_tcp_server_client_info_t expected, out;
    CHECK(vireo_tcp_server_client_inspect(f->server, binding.client, &expected) == VIREO_OK);
    vireo_client_deadline_stage_t stage = VIREO_CLIENT_DEADLINE_CHECK_TIMER;
    errno = EDOM;
    CHECK(vireo_client_deadline_check_expired(f->server, binding, expired, &out, &stage) ==
          VIREO_OK);
    CHECK(errno == EDOM && stage == VIREO_CLIENT_DEADLINE_NONE && same_info(&expected, &out));
    errno = ERANGE;
    CHECK(vireo_client_deadline_check_expired(f->server, binding, expired, &out, NULL) == VIREO_OK);
    CHECK(errno == ERANGE && same_info(&expected, &out));
    return true;
}

static bool test_current_readonly(fixture_t *f) {
    vireo_timer_wheel_registry_info_t before, after;
    vireo_timer_wheel_progress_t progress_before, progress_after;
    vireo_tcp_server_client_info_t client_before, client_after;
    CHECK(vireo_timer_wheel_registry_inspect(f->wheel, &before) == VIREO_OK);
    CHECK(vireo_timer_wheel_progress_inspect(f->wheel, &progress_before) == VIREO_OK);
    CHECK(vireo_tcp_server_client_inspect(f->server, f->client, &client_before) == VIREO_OK);
    vireo_client_deadline_binding_t binding;
    memset(&binding, 0xa5, sizeof binding);
    CHECK(make_binding(f, &binding));
    CHECK(vireo_client_deadline_make(f->server, f->wheel, f->client, f->timer, &binding, NULL) ==
          VIREO_OK);
    CHECK(vireo_timer_wheel_registry_inspect(f->wheel, &after) == VIREO_OK);
    CHECK(before.active_count == 1 && after.active_count == 1 &&
          before.available_count == after.available_count);
    CHECK(vireo_timer_wheel_progress_inspect(f->wheel, &progress_after) == VIREO_OK);
    CHECK(progress_before.latest_now_ns == progress_after.latest_now_ns &&
          progress_before.completed_tick == progress_after.completed_tick &&
          progress_after.ready_count == 0);
    CHECK(vireo_tcp_server_client_inspect(f->server, f->client, &client_after) == VIREO_OK);
    CHECK(same_info(&client_before, &client_after));
    return true;
}

static bool test_make_null(fixture_t *f) {
    CHECK(make_fails(NULL, f->wheel, f->client, f->timer, VIREO_RESULT_INVALID_ARGUMENT,
                     VIREO_CLIENT_DEADLINE_NONE));
    CHECK(make_fails(f->server, NULL, f->client, f->timer, VIREO_RESULT_INVALID_ARGUMENT,
                     VIREO_CLIENT_DEADLINE_NONE));
    vireo_client_deadline_stage_t stage = VIREO_CLIENT_DEADLINE_CHECK_CLIENT;
    errno = EDOM;
    CHECK(vireo_client_deadline_make(f->server, f->wheel, f->client, f->timer, NULL, &stage) ==
          VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(errno == EDOM && stage == VIREO_CLIENT_DEADLINE_NONE);
    return true;
}

static bool test_make_shape_empty(fixture_t *f) {
    vireo_connection_pool_lease_t const bad_clients[] = {{0, 1, 0}, {0, 0, 1}, {1, 0, 0}};
    vireo_timer_handle_t const bad_timers[] = {{0, 1, 0}, {0, 0, 1}, {1, 0, 0}};
    for (size_t i = 0; i < sizeof bad_clients / sizeof bad_clients[0]; ++i) {
        CHECK(make_fails(f->server, f->wheel, bad_clients[i], f->timer,
                         VIREO_RESULT_INVALID_ARGUMENT, VIREO_CLIENT_DEADLINE_NONE));
        CHECK(make_fails(f->server, f->wheel, f->client, bad_timers[i],
                         VIREO_RESULT_INVALID_ARGUMENT, VIREO_CLIENT_DEADLINE_NONE));
        CHECK(make_fails(f->server, f->wheel, (vireo_connection_pool_lease_t){0}, bad_timers[i],
                         VIREO_RESULT_INVALID_ARGUMENT, VIREO_CLIENT_DEADLINE_NONE));
    }
    CHECK(make_fails(f->server, f->wheel, (vireo_connection_pool_lease_t){0}, f->timer,
                     VIREO_RESULT_NOT_FOUND, VIREO_CLIENT_DEADLINE_NONE));
    CHECK(make_fails(f->server, f->wheel, f->client, (vireo_timer_handle_t){0},
                     VIREO_RESULT_NOT_FOUND, VIREO_CLIENT_DEADLINE_NONE));
    return true;
}

static bool test_make_client_errors(fixture_t *f) {
    CHECK(make_fails(f->other_server, f->wheel, f->client, f->timer, VIREO_RESULT_INVALID_ARGUMENT,
                     VIREO_CLIENT_DEADLINE_CHECK_CLIENT));
    vireo_connection_pool_lease_t bad = f->client;
    bad.slot_index = SIZE_MAX;
    CHECK(make_fails(f->server, f->wheel, bad, f->timer, VIREO_RESULT_RANGE,
                     VIREO_CLIENT_DEADLINE_CHECK_CLIENT));
    bad = f->client;
    bad.generation = UINT64_MAX;
    CHECK(make_fails(f->server, f->wheel, bad, f->timer, VIREO_RESULT_NOT_FOUND,
                     VIREO_CLIENT_DEADLINE_CHECK_CLIENT));
    return true;
}

static bool test_make_timer_errors(fixture_t *f) {
    CHECK(make_fails(f->server, f->other_wheel, f->client, f->timer, VIREO_RESULT_INVALID_ARGUMENT,
                     VIREO_CLIENT_DEADLINE_CHECK_TIMER));
    CHECK(make_fails(f->server, f->unprepared, f->client, f->timer, VIREO_RESULT_NOT_FOUND,
                     VIREO_CLIENT_DEADLINE_CHECK_TIMER));
    vireo_timer_handle_t bad = f->timer;
    bad.slot_index = SIZE_MAX;
    CHECK(make_fails(f->server, f->wheel, f->client, bad, VIREO_RESULT_RANGE,
                     VIREO_CLIENT_DEADLINE_CHECK_TIMER));
    bad = f->timer;
    bad.generation = UINT64_MAX;
    CHECK(make_fails(f->server, f->wheel, f->client, bad, VIREO_RESULT_NOT_FOUND,
                     VIREO_CLIENT_DEADLINE_CHECK_TIMER));
    vireo_timer_handle_t old = f->timer;
    CHECK(vireo_timer_wheel_cancel(f->wheel, &f->timer) == VIREO_OK);
    CHECK(make_fails(f->server, f->wheel, f->client, old, VIREO_RESULT_NOT_FOUND,
                     VIREO_CLIENT_DEADLINE_CHECK_TIMER));
    return true;
}

static bool test_historical_current(fixture_t *f) {
    vireo_client_deadline_binding_t binding;
    vireo_timer_wheel_expired_t expired;
    CHECK(make_binding(f, &binding));
    CHECK(expire(f, 110, &expired));
    vireo_timer_wheel_timer_info_t timer_info;
    CHECK(vireo_timer_wheel_get(f->wheel, binding.timer, &timer_info) == VIREO_RESULT_NOT_FOUND);
    CHECK(check_success(f, binding, &expired));
    CHECK(make_fails(f->server, f->wheel, binding.client, binding.timer, VIREO_RESULT_NOT_FOUND,
                     VIREO_CLIENT_DEADLINE_CHECK_TIMER));
    CHECK(same_client(binding.client, f->client) && same_timer(binding.timer, expired.handle));
    return true;
}

static bool test_check_null(fixture_t *f) {
    vireo_client_deadline_binding_t binding;
    vireo_timer_wheel_expired_t expired;
    CHECK(make_binding(f, &binding));
    CHECK(expire(f, 110, &expired));
    CHECK(check_fails(NULL, binding, &expired, VIREO_RESULT_INVALID_ARGUMENT,
                      VIREO_CLIENT_DEADLINE_NONE));
    CHECK(check_fails(f->server, binding, NULL, VIREO_RESULT_INVALID_ARGUMENT,
                      VIREO_CLIENT_DEADLINE_NONE));
    vireo_client_deadline_stage_t stage = VIREO_CLIENT_DEADLINE_CHECK_TIMER;
    errno = EDOM;
    CHECK(vireo_client_deadline_check_expired(f->server, binding, &expired, NULL, &stage) ==
          VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(errno == EDOM && stage == VIREO_CLIENT_DEADLINE_NONE);
    return true;
}

static bool test_check_shape_empty(fixture_t *f) {
    vireo_client_deadline_binding_t binding;
    vireo_timer_wheel_expired_t expired;
    CHECK(make_binding(f, &binding));
    CHECK(expire(f, 110, &expired));
    CHECK(check_fails(f->server, (vireo_client_deadline_binding_t){0}, &expired,
                      VIREO_RESULT_NOT_FOUND, VIREO_CLIENT_DEADLINE_NONE));
    vireo_client_deadline_binding_t bad = binding;
    bad.client = (vireo_connection_pool_lease_t){0};
    CHECK(check_fails(f->server, bad, &expired, VIREO_RESULT_INVALID_ARGUMENT,
                      VIREO_CLIENT_DEADLINE_NONE));
    bad = binding;
    bad.timer = (vireo_timer_handle_t){0};
    CHECK(check_fails(f->server, bad, &expired, VIREO_RESULT_INVALID_ARGUMENT,
                      VIREO_CLIENT_DEADLINE_NONE));
    bad = binding;
    bad.client.generation = 0;
    CHECK(check_fails(f->server, bad, &expired, VIREO_RESULT_INVALID_ARGUMENT,
                      VIREO_CLIENT_DEADLINE_NONE));
    bad = binding;
    bad.timer.owner_id = 0;
    CHECK(check_fails(f->server, bad, &expired, VIREO_RESULT_INVALID_ARGUMENT,
                      VIREO_CLIENT_DEADLINE_NONE));
    expired.handle = (vireo_timer_handle_t){0};
    CHECK(check_fails(f->server, binding, &expired, VIREO_RESULT_NOT_FOUND,
                      VIREO_CLIENT_DEADLINE_NONE));
    expired.handle.generation = 1;
    CHECK(check_fails(f->server, binding, &expired, VIREO_RESULT_INVALID_ARGUMENT,
                      VIREO_CLIENT_DEADLINE_NONE));
    CHECK(check_fails(f->server, (vireo_client_deadline_binding_t){0}, &expired,
                      VIREO_RESULT_INVALID_ARGUMENT, VIREO_CLIENT_DEADLINE_NONE));
    return true;
}

/** 数值负例故意改 handle，仅验证拒绝；不把它当可信到期或来源认证。 */
static bool test_timer_mismatch(fixture_t *f) {
    vireo_client_deadline_binding_t binding;
    vireo_timer_wheel_expired_t expired;
    CHECK(make_binding(f, &binding));
    CHECK(expire(f, 110, &expired));
    vireo_client_deadline_binding_t bad = binding;
    bad.timer.owner_id = f->other_timer.owner_id;
    CHECK(check_fails(f->server, bad, &expired, VIREO_RESULT_NOT_FOUND,
                      VIREO_CLIENT_DEADLINE_MATCH_TIMER));
    bad = binding;
    bad.timer.slot_index = SIZE_MAX;
    CHECK(check_fails(f->server, bad, &expired, VIREO_RESULT_NOT_FOUND,
                      VIREO_CLIENT_DEADLINE_MATCH_TIMER));
    bad = binding;
    bad.timer.generation = UINT64_MAX;
    CHECK(check_fails(f->other_server, bad, &expired, VIREO_RESULT_NOT_FOUND,
                      VIREO_CLIENT_DEADLINE_MATCH_TIMER));
    CHECK(check_success(f, binding, &expired));
    return true;
}

static bool test_check_client_errors(fixture_t *f) {
    vireo_client_deadline_binding_t binding;
    vireo_timer_wheel_expired_t expired;
    CHECK(make_binding(f, &binding));
    CHECK(expire(f, 110, &expired));
    CHECK(check_fails(f->other_server, binding, &expired, VIREO_RESULT_INVALID_ARGUMENT,
                      VIREO_CLIENT_DEADLINE_CHECK_CLIENT));
    vireo_client_deadline_binding_t bad = binding;
    bad.client.slot_index = SIZE_MAX;
    CHECK(check_fails(f->server, bad, &expired, VIREO_RESULT_RANGE,
                      VIREO_CLIENT_DEADLINE_CHECK_CLIENT));
    bad = binding;
    bad.client.generation = UINT64_MAX;
    CHECK(check_fails(f->server, bad, &expired, VIREO_RESULT_NOT_FOUND,
                      VIREO_CLIENT_DEADLINE_CHECK_CLIENT));
    return true;
}

static bool test_timer_slot_reuse(fixture_t *f) {
    vireo_client_deadline_binding_t old, current;
    vireo_timer_wheel_expired_t first, second;
    CHECK(make_binding(f, &old));
    CHECK(expire(f, 110, &first));
    f->timer = (vireo_timer_handle_t){0};
    CHECK(vireo_timer_wheel_register(f->wheel, 110, 120, &f->timer) == VIREO_OK);
    CHECK(f->timer.owner_id == old.timer.owner_id && f->timer.slot_index == old.timer.slot_index &&
          f->timer.generation != old.timer.generation);
    CHECK(make_binding(f, &current));
    CHECK(check_fails(f->server, current, &first, VIREO_RESULT_NOT_FOUND,
                      VIREO_CLIENT_DEADLINE_MATCH_TIMER));
    CHECK(check_success(f, old, &first));
    CHECK(expire(f, 120, &second));
    CHECK(check_fails(f->server, old, &second, VIREO_RESULT_NOT_FOUND,
                      VIREO_CLIENT_DEADLINE_MATCH_TIMER));
    CHECK(check_success(f, current, &second));
    return true;
}

static bool test_client_slot_reuse(fixture_t *f) {
    vireo_client_deadline_binding_t old, current;
    vireo_timer_wheel_expired_t first, second;
    CHECK(make_binding(f, &old));
    CHECK(expire(f, 110, &first));
    CHECK(vireo_tcp_server_release_client(f->server, &f->client, NULL) == VIREO_OK);
    CHECK(close(f->peer) == 0);
    f->peer = -1;
    CHECK(make_fails(f->server, f->wheel, old.client, old.timer, VIREO_RESULT_NOT_FOUND,
                     VIREO_CLIENT_DEADLINE_CHECK_CLIENT));
    CHECK(add_client(f));
    CHECK(f->client.pool_id == old.client.pool_id &&
          f->client.slot_index == old.client.slot_index &&
          f->client.generation != old.client.generation);
    CHECK(check_fails(f->server, old, &first, VIREO_RESULT_NOT_FOUND,
                      VIREO_CLIENT_DEADLINE_CHECK_CLIENT));
    vireo_tcp_server_client_info_t info;
    CHECK(vireo_tcp_server_client_inspect(f->server, f->client, &info) == VIREO_OK);
    CHECK(info.connection_info.close_state == VIREO_CONNECTION_CLOSE_OPEN);
    f->timer = (vireo_timer_handle_t){0};
    CHECK(vireo_timer_wheel_register(f->wheel, 110, 120, &f->timer) == VIREO_OK);
    CHECK(make_binding(f, &current));
    CHECK(expire(f, 120, &second));
    CHECK(check_success(f, current, &second));
    return true;
}

static bool test_closing_stopped(fixture_t *f) {
    CHECK(vireo_tcp_server_client_request_close(
              f->server, f->client, VIREO_CONNECTION_CLOSE_MODE_IMMEDIATE,
              VIREO_CONNECTION_CLOSE_REASON_APPLICATION, NULL) == VIREO_OK);
    CHECK(discover(f, 110));
    CHECK(vireo_timer_wheel_shutdown_begin(f->wheel) == VIREO_OK);
    vireo_client_deadline_binding_t binding;
    CHECK(make_binding(f, &binding));
    vireo_timer_wheel_expired_t expired;
    CHECK(vireo_timer_wheel_take_expired(f->wheel, &expired) == VIREO_OK);
    CHECK(check_success(f, binding, &expired));
    vireo_tcp_server_client_info_t info;
    CHECK(vireo_tcp_server_client_inspect(f->server, f->client, &info) == VIREO_OK);
    CHECK(info.connection_info.close_state == VIREO_CONNECTION_CLOSE_READY);
    return true;
}

/** dispatch 的短借测试上下文；回调只做本项只读核验，不执行业务动作。 */
typedef struct delivery_probe {
    vireo_tcp_server_t *server;                 /**< 短借至 dispatch 返回，不拥有。 */
    vireo_client_deadline_binding_t binding;    /**< 本次预先构造的普通数值关联。 */
    size_t calls;                               /**< 实际回调次数。 */
    vireo_client_deadline_stage_t stage;        /**< 本项核验独立诊断。 */
    vireo_tcp_server_client_info_t client_info; /**< 核验成功才提交的公开快照。 */
} delivery_probe_t;

static vireo_result_t deliver(vireo_timer_wheel_expired_t const *expired, void *context) {
    delivery_probe_t *p = context;
    ++p->calls;
    return vireo_client_deadline_check_expired(p->server, p->binding, expired, &p->client_info,
                                               &p->stage);
}

static bool test_dispatch_success(fixture_t *f) {
    delivery_probe_t p = {0};
    p.server = f->server;
    CHECK(make_binding(f, &p.binding));
    CHECK(discover(f, 110));
    vireo_timer_loop_dispatch_report_t report;
    errno = EDOM;
    CHECK(vireo_timer_loop_dispatch(f->wheel, 1, deliver, &p, &report) == VIREO_OK);
    CHECK(errno == EDOM && p.calls == 1 && p.stage == VIREO_CLIENT_DEADLINE_NONE);
    CHECK(report.consumed_count == 1 && report.delivered_count == 1 && !report.has_failed_delivery);
    CHECK(p.client_info.connection_info.close_state == VIREO_CONNECTION_CLOSE_OPEN);
    vireo_tcp_server_client_info_t current;
    CHECK(vireo_tcp_server_client_inspect(f->server, f->client, &current) == VIREO_OK);
    CHECK(same_info(&current, &p.client_info));
    return true;
}

static bool test_dispatch_stale(fixture_t *f) {
    delivery_probe_t p = {0};
    p.server = f->server;
    CHECK(make_binding(f, &p.binding));
    CHECK(discover(f, 110));
    CHECK(vireo_tcp_server_release_client(f->server, &f->client, NULL) == VIREO_OK);
    CHECK(close(f->peer) == 0);
    f->peer = -1;
    CHECK(add_client(f));
    unsigned char before[sizeof p.client_info];
    memset(&p.client_info, 0xa5, sizeof p.client_info);
    memcpy(before, &p.client_info, sizeof before);
    vireo_timer_loop_dispatch_report_t report;
    errno = EDOM;
    CHECK(vireo_timer_loop_dispatch(f->wheel, 1, deliver, &p, &report) == VIREO_RESULT_NOT_FOUND);
    CHECK(errno == EDOM && p.calls == 1 && p.stage == VIREO_CLIENT_DEADLINE_CHECK_CLIENT);
    CHECK(report.stage == VIREO_TIMER_LOOP_DISPATCH_STAGE_DELIVER && report.consumed_count == 1 &&
          report.delivered_count == 0 && report.has_failed_delivery);
    CHECK(same_timer(report.failed_delivery.handle, p.binding.timer));
    CHECK(memcmp(before, &p.client_info, sizeof before) == 0);
    vireo_tcp_server_client_info_t current;
    CHECK(vireo_tcp_server_client_inspect(f->server, f->client, &current) == VIREO_OK);
    CHECK(current.connection_info.close_state == VIREO_CONNECTION_CLOSE_OPEN);
    vireo_timer_wheel_registry_info_t info;
    CHECK(vireo_timer_wheel_registry_inspect(f->wheel, &info) == VIREO_OK &&
          info.active_count == 0);
    return true;
}

typedef struct test_case {
    char const *name;         /**< 结果中显示的真实场景名。 */
    bool (*run)(fixture_t *); /**< 用公开 fixture 执行该场景，不保存借用。 */
} test_case_t;

int main(void) {
    test_case_t const cases[] = {{"current readonly", test_current_readonly},
                                 {"make null", test_make_null},
                                 {"make shape/empty", test_make_shape_empty},
                                 {"make client errors", test_make_client_errors},
                                 {"make timer errors", test_make_timer_errors},
                                 {"historical/current", test_historical_current},
                                 {"check null", test_check_null},
                                 {"check shape/empty", test_check_shape_empty},
                                 {"timer mismatch", test_timer_mismatch},
                                 {"check client errors", test_check_client_errors},
                                 {"timer slot reuse", test_timer_slot_reuse},
                                 {"client slot reuse", test_client_slot_reuse},
                                 {"closing/stopped", test_closing_stopped},
                                 {"dispatch success", test_dispatch_success},
                                 {"dispatch stale", test_dispatch_stale}};
    size_t failed = 0;
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
        fixture_t f;
        bool passed = setup(&f);
        if (passed) {
            passed = cases[i].run(&f);
        }
        if (!cleanup(&f)) {
            passed = false;
        }
        printf("%s: %s\n", cases[i].name, passed ? "PASS" : "FAIL");
        if (!passed) {
            ++failed;
        }
    }
    printf("15 groups, %zu failed\n", failed);
    return failed == 0 ? 0 : 1;
}
