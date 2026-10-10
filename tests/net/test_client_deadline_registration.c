/*
 * PROJECT : VIREO
 * FILE    : test_client_deadline_registration.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-10
 * BRIEF   : 此模块负责：
 * -- 验证客户核验、未来 timer 登记与显式取消
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
    vireo_tcp_server_t *server;       /**< 本客户的唯一 server owner。 */
    vireo_tcp_server_t *other_server; /**< 空的不同 pool，用于跨所属核验。 */
    vireo_timer_wheel_t *wheel;       /**< 本 timer 的唯一轮 owner，固定容量一。 */
    vireo_timer_wheel_t *other_wheel; /**< 不同 owner 的准备轮。 */
    vireo_timer_wheel_t *unprepared; /**< 未 prepare 轮；极限值场景可显式替换并 prepare。 */
    vireo_connection_pool_lease_t client; /**< 当前客户租约，归还清零。 */
    vireo_timer_handle_t timer; /**< 当前或已领取历史 timer，清理只尝试公开取消。 */
    vireo_timer_handle_t extra_timer; /**< 同轮第二项，证明没有每客户唯一限制。 */
    vireo_timer_handle_t special_timer; /**< 极限纳秒几何测试轮的独立登记。 */
    vireo_timer_handle_t other_timer;   /**< 不同轮的登记，独立归还。 */
    int peer;                           /**< caller 拥有的真实 TCP 对端 fd，-1 为空。 */
    int listener_fd;                    /**< 构造期间 caller listener fd；转移后 -1。 */
    vireo_acceptor_t *listener; /**< 构造期间 acceptor owner；server 收纳后 NULL。 */
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
    vireo_timer_wheel_registry_options_t const other_registry = {
        2, VIREO_TIMER_WHEEL_REGISTRY_MAX_MEMORY};
    CHECK(vireo_timer_wheel_prepare(f->other_wheel, &other_registry) == VIREO_OK);
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
        vireo_result_t const result = vireo_timer_wheel_cancel(f->other_wheel, &f->other_timer);
        CHECK(result == VIREO_OK || result == VIREO_RESULT_NOT_FOUND);
    }
    if (f->extra_timer.owner_id != 0) {
        vireo_result_t const result = vireo_timer_wheel_cancel(f->other_wheel, &f->extra_timer);
        CHECK(result == VIREO_OK || result == VIREO_RESULT_NOT_FOUND);
    }
    if (f->special_timer.owner_id != 0) {
        vireo_result_t const result = vireo_timer_wheel_cancel(f->unprepared, &f->special_timer);
        CHECK(result == VIREO_OK || result == VIREO_RESULT_NOT_FOUND);
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

static bool empty_binding(vireo_client_deadline_binding_t b) {
    return b.client.pool_id == 0 && b.client.slot_index == 0 && b.client.generation == 0 &&
           b.timer.owner_id == 0 && b.timer.slot_index == 0 && b.timer.generation == 0;
}

/** 将 padding 留为既有模式，只把六个逻辑身份数值设空。 */
static void empty_output(vireo_client_deadline_binding_t *b) {
    memset(b, 0xa5, sizeof *b);
    b->client.pool_id = 0;
    b->client.slot_index = 0;
    b->client.generation = 0;
    b->timer.owner_id = 0;
    b->timer.slot_index = 0;
    b->timer.generation = 0;
}

static bool state(vireo_timer_wheel_t const *wheel, vireo_timer_wheel_registry_info_t *registry,
                  vireo_timer_wheel_progress_t *progress) {
    *registry = (vireo_timer_wheel_registry_info_t){0};
    *progress = (vireo_timer_wheel_progress_t){0};
    if (wheel != NULL) {
        CHECK(vireo_timer_wheel_registry_inspect(wheel, registry) == VIREO_OK);
        if (registry->prepared) {
            CHECK(vireo_timer_wheel_progress_inspect(wheel, progress) == VIREO_OK);
        }
    }
    return true;
}

static bool same_state(vireo_timer_wheel_registry_info_t const *a,
                       vireo_timer_wheel_registry_info_t const *b,
                       vireo_timer_wheel_progress_t const *p,
                       vireo_timer_wheel_progress_t const *q) {
    CHECK(a->prepared == b->prepared && a->capacity == b->capacity &&
          a->active_count == b->active_count && a->available_count == b->available_count &&
          a->allocation_bytes == b->allocation_bytes && a->max_memory_bytes == b->max_memory_bytes);
    CHECK(p->latest_now_ns == q->latest_now_ns && p->target_tick == q->target_tick &&
          p->completed_tick == q->completed_tick && p->processing == q->processing &&
          p->ready_count == q->ready_count && p->caught_up == q->caught_up);
    return true;
}

static bool register_fails(vireo_tcp_server_t const *server, vireo_timer_wheel_t *wheel,
                           vireo_connection_pool_lease_t client, vireo_monotonic_ns_t now,
                           vireo_monotonic_ns_t deadline, vireo_client_deadline_binding_t *binding,
                           vireo_result_t expected, vireo_client_deadline_stage_t expected_stage) {
    unsigned char before[sizeof *binding];
    memcpy(before, binding, sizeof before);
    vireo_timer_wheel_registry_info_t a, b;
    vireo_timer_wheel_progress_t p, q;
    CHECK(state(wheel, &a, &p));
    vireo_client_deadline_stage_t stage = VIREO_CLIENT_DEADLINE_MATCH_TIMER;
    errno = EDOM;
    CHECK(vireo_client_deadline_register(server, wheel, client, now, deadline, binding, &stage) ==
          expected);
    CHECK(errno == EDOM && stage == expected_stage && memcmp(before, binding, sizeof before) == 0);
    CHECK(state(wheel, &b, &q) && same_state(&a, &b, &p, &q));
    errno = ERANGE;
    CHECK(vireo_client_deadline_register(server, wheel, client, now, deadline, binding, NULL) ==
          expected);
    CHECK(errno == ERANGE && memcmp(before, binding, sizeof before) == 0);
    CHECK(state(wheel, &b, &q) && same_state(&a, &b, &p, &q));
    return true;
}

static bool cancel_fails(vireo_timer_wheel_t *wheel, vireo_client_deadline_binding_t *binding,
                         vireo_result_t expected, vireo_client_deadline_stage_t expected_stage) {
    unsigned char before[sizeof *binding];
    memcpy(before, binding, sizeof before);
    vireo_timer_wheel_registry_info_t a, b;
    vireo_timer_wheel_progress_t p, q;
    CHECK(state(wheel, &a, &p));
    vireo_client_deadline_stage_t stage = VIREO_CLIENT_DEADLINE_CHECK_CLIENT;
    errno = EDOM;
    CHECK(vireo_client_deadline_cancel(wheel, binding, &stage) == expected);
    CHECK(errno == EDOM && stage == expected_stage && memcmp(before, binding, sizeof before) == 0);
    CHECK(state(wheel, &b, &q) && same_state(&a, &b, &p, &q));
    errno = ERANGE;
    CHECK(vireo_client_deadline_cancel(wheel, binding, NULL) == expected);
    CHECK(errno == ERANGE && memcmp(before, binding, sizeof before) == 0);
    CHECK(state(wheel, &b, &q) && same_state(&a, &b, &p, &q));
    return true;
}

static bool register_ok(fixture_t *f, vireo_monotonic_ns_t now, vireo_monotonic_ns_t deadline,
                        vireo_client_deadline_binding_t *binding) {
    vireo_client_deadline_stage_t stage = VIREO_CLIENT_DEADLINE_CANCEL_TIMER;
    errno = EDOM;
    vireo_result_t const result = vireo_client_deadline_register(f->server, f->wheel, f->client,
                                                                 now, deadline, binding, &stage);
    if (result == VIREO_OK) {
        f->timer = binding->timer;
    }
    CHECK(result == VIREO_OK && errno == EDOM && stage == VIREO_CLIENT_DEADLINE_NONE);
    CHECK(same_client(binding->client, f->client) && same_timer(binding->timer, f->timer));
    return true;
}

static bool cancel_ok(vireo_timer_wheel_t *wheel, vireo_client_deadline_binding_t *binding) {
    vireo_client_deadline_stage_t stage = VIREO_CLIENT_DEADLINE_REGISTER_TIMER;
    errno = EDOM;
    CHECK(vireo_client_deadline_cancel(wheel, binding, &stage) == VIREO_OK);
    CHECK(errno == EDOM && stage == VIREO_CLIENT_DEADLINE_NONE && empty_binding(*binding));
    return true;
}

static bool discover(fixture_t *f) {
    vireo_timer_wheel_advance_report_t report;
    CHECK(vireo_timer_wheel_advance(f->wheel, 110, (vireo_timer_wheel_advance_budget_t){4, 1},
                                    &report) == VIREO_OK);
    CHECK(report.progress.caught_up && report.progress.ready_count == 1);
    return true;
}

static bool test_register_cancel(fixture_t *f) {
    vireo_client_deadline_binding_t b;
    empty_output(&b);
    CHECK(register_ok(f, 100, 111, &b));
    vireo_timer_wheel_timer_info_t info;
    CHECK(vireo_timer_wheel_get(f->wheel, b.timer, &info) == VIREO_OK);
    CHECK(info.deadline_ns == 111 && info.due_tick == 2 && info.bucket_index == 2);
    vireo_client_deadline_binding_t observed;
    CHECK(vireo_client_deadline_make(f->server, f->wheel, f->client, b.timer, &observed, NULL) ==
          VIREO_OK);
    CHECK(same_client(observed.client, b.client) && same_timer(observed.timer, b.timer));
    vireo_timer_handle_t old = b.timer;
    CHECK(cancel_ok(f->wheel, &b));
    CHECK(vireo_timer_wheel_get(f->wheel, old, &info) == VIREO_RESULT_NOT_FOUND);
    vireo_timer_wheel_registry_info_t registry;
    CHECK(vireo_timer_wheel_registry_inspect(f->wheel, &registry) == VIREO_OK);
    CHECK(registry.active_count == 0 && registry.available_count == 1);
    errno = ERANGE;
    CHECK(vireo_client_deadline_register(f->server, f->wheel, f->client, 100, 110, &b, NULL) ==
          VIREO_OK);
    f->timer = b.timer;
    CHECK(errno == ERANGE);
    CHECK(vireo_client_deadline_cancel(f->wheel, &b, NULL) == VIREO_OK);
    CHECK(errno == ERANGE && empty_binding(b));
    return true;
}

static bool test_register_null(fixture_t *f) {
    vireo_client_deadline_binding_t b;
    empty_output(&b);
    CHECK(register_fails(NULL, f->wheel, f->client, 100, 110, &b, VIREO_RESULT_INVALID_ARGUMENT,
                         VIREO_CLIENT_DEADLINE_NONE));
    CHECK(register_fails(f->server, NULL, f->client, 100, 110, &b, VIREO_RESULT_INVALID_ARGUMENT,
                         VIREO_CLIENT_DEADLINE_NONE));
    vireo_client_deadline_stage_t stage = VIREO_CLIENT_DEADLINE_CHECK_TIMER;
    errno = EDOM;
    CHECK(vireo_client_deadline_register(f->server, f->wheel, f->client, 100, 110, NULL, &stage) ==
          VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(errno == EDOM && stage == VIREO_CLIENT_DEADLINE_NONE);
    return true;
}

static bool test_register_shape_empty(fixture_t *f) {
    vireo_client_deadline_binding_t b;
    empty_output(&b);
    vireo_connection_pool_lease_t const clients[] = {{0, 1, 0}, {0, 0, 1}, {1, 0, 0}};
    for (size_t i = 0; i < sizeof clients / sizeof clients[0]; ++i) {
        CHECK(register_fails(f->server, f->wheel, clients[i], 100, 110, &b,
                             VIREO_RESULT_INVALID_ARGUMENT, VIREO_CLIENT_DEADLINE_NONE));
    }
    CHECK(register_fails(f->server, f->wheel, (vireo_connection_pool_lease_t){0}, 100, 110, &b,
                         VIREO_RESULT_NOT_FOUND, VIREO_CLIENT_DEADLINE_NONE));
    return true;
}

static bool test_nonempty_keeps_timer(fixture_t *f) {
    vireo_client_deadline_binding_t b = {0};
    CHECK(register_ok(f, 100, 110, &b));
    CHECK(register_fails(f->server, f->wheel, f->client, 100, 120, &b,
                         VIREO_RESULT_INVALID_ARGUMENT, VIREO_CLIENT_DEADLINE_NONE));
    vireo_client_deadline_binding_t bad = b;
    bad.client = (vireo_connection_pool_lease_t){0};
    CHECK(register_fails(f->server, f->wheel, f->client, 100, 120, &bad,
                         VIREO_RESULT_INVALID_ARGUMENT, VIREO_CLIENT_DEADLINE_NONE));
    bad = b;
    bad.timer = (vireo_timer_handle_t){0};
    CHECK(register_fails(f->server, f->wheel, f->client, 100, 120, &bad,
                         VIREO_RESULT_INVALID_ARGUMENT, VIREO_CLIENT_DEADLINE_NONE));
    bad = b;
    bad.timer.generation = 0;
    CHECK(register_fails(f->server, f->wheel, f->client, 100, 120, &bad,
                         VIREO_RESULT_INVALID_ARGUMENT, VIREO_CLIENT_DEADLINE_NONE));
    vireo_timer_wheel_timer_info_t info;
    CHECK(vireo_timer_wheel_get(f->wheel, b.timer, &info) == VIREO_OK && info.deadline_ns == 110);
    return true;
}

static bool test_client_rejections(fixture_t *f) {
    vireo_client_deadline_binding_t b;
    empty_output(&b);
    CHECK(register_fails(f->other_server, f->wheel, f->client, 100, 110, &b,
                         VIREO_RESULT_INVALID_ARGUMENT, VIREO_CLIENT_DEADLINE_CHECK_CLIENT));
    vireo_connection_pool_lease_t bad = f->client;
    bad.slot_index = SIZE_MAX;
    CHECK(register_fails(f->server, f->wheel, bad, 100, 110, &b, VIREO_RESULT_RANGE,
                         VIREO_CLIENT_DEADLINE_CHECK_CLIENT));
    bad = f->client;
    bad.generation = UINT64_MAX;
    CHECK(register_fails(f->server, f->unprepared, bad, 100, 110, &b, VIREO_RESULT_NOT_FOUND,
                         VIREO_CLIENT_DEADLINE_CHECK_CLIENT));
    return true;
}

static bool test_wheel_state(fixture_t *f) {
    vireo_client_deadline_binding_t b;
    empty_output(&b);
    CHECK(register_fails(f->server, f->unprepared, f->client, 99, 0, &b, VIREO_RESULT_NOT_FOUND,
                         VIREO_CLIENT_DEADLINE_REGISTER_TIMER));
    CHECK(vireo_timer_wheel_shutdown_begin(f->wheel) == VIREO_OK);
    CHECK(register_fails(f->server, f->wheel, f->client, 99, 0, &b, VIREO_RESULT_CANCELLED,
                         VIREO_CLIENT_DEADLINE_REGISTER_TIMER));
    return true;
}

static bool test_time_errors(fixture_t *f) {
    vireo_client_deadline_binding_t b;
    empty_output(&b);
    CHECK(register_fails(f->server, f->wheel, f->client, 99, 110, &b, VIREO_RESULT_RANGE,
                         VIREO_CLIENT_DEADLINE_REGISTER_TIMER));
    CHECK(register_fails(f->server, f->wheel, f->client, 100, 100, &b, VIREO_RESULT_TIMEOUT,
                         VIREO_CLIENT_DEADLINE_REGISTER_TIMER));
    CHECK(register_fails(f->server, f->wheel, f->client, 100, 0, &b, VIREO_RESULT_TIMEOUT,
                         VIREO_CLIENT_DEADLINE_REGISTER_TIMER));
    CHECK(register_fails(f->server, f->wheel, f->client, UINT64_MAX, UINT64_MAX, &b,
                         VIREO_RESULT_TIMEOUT, VIREO_CLIENT_DEADLINE_REGISTER_TIMER));
    CHECK(register_fails(f->server, f->wheel, f->client, 100, UINT64_MAX, &b, VIREO_RESULT_OVERFLOW,
                         VIREO_CLIENT_DEADLINE_REGISTER_TIMER));
    return true;
}

static bool test_finite_max(fixture_t *f) {
    CHECK(vireo_timer_wheel_destroy(&f->unprepared) == VIREO_OK);
    vireo_timer_wheel_options_t const options = {{0, 1, 2}, VIREO_TIMER_WHEEL_MAX_MEMORY};
    vireo_timer_wheel_registry_options_t const registry = {1,
                                                           VIREO_TIMER_WHEEL_REGISTRY_MAX_MEMORY};
    CHECK(vireo_timer_wheel_create(&options, &f->unprepared) == VIREO_OK);
    CHECK(vireo_timer_wheel_prepare(f->unprepared, &registry) == VIREO_OK);
    vireo_client_deadline_binding_t b = {0};
    vireo_client_deadline_stage_t stage = VIREO_CLIENT_DEADLINE_CANCEL_TIMER;
    errno = EDOM;
    vireo_result_t const result = vireo_client_deadline_register(
        f->server, f->unprepared, f->client, UINT64_MAX - 1, UINT64_MAX, &b, &stage);
    if (result == VIREO_OK) {
        f->special_timer = b.timer;
    }
    CHECK(result == VIREO_OK && errno == EDOM && stage == VIREO_CLIENT_DEADLINE_NONE);
    vireo_timer_wheel_timer_info_t info;
    CHECK(vireo_timer_wheel_get(f->unprepared, b.timer, &info) == VIREO_OK);
    CHECK(info.deadline_ns == UINT64_MAX && info.due_tick == UINT64_MAX && info.bucket_index == 1);
    CHECK(cancel_ok(f->unprepared, &b));
    return true;
}

static bool test_full_wheel(fixture_t *f) {
    vireo_client_deadline_binding_t first = {0}, second;
    CHECK(register_ok(f, 100, 110, &first));
    empty_output(&second);
    CHECK(register_fails(f->server, f->wheel, f->client, 100, 120, &second, VIREO_RESULT_BUSY,
                         VIREO_CLIENT_DEADLINE_REGISTER_TIMER));
    vireo_timer_wheel_timer_info_t info;
    CHECK(vireo_timer_wheel_get(f->wheel, first.timer, &info) == VIREO_OK &&
          info.deadline_ns == 110);
    CHECK(cancel_ok(f->wheel, &first));
    CHECK(register_ok(f, 100, 120, &second));
    return true;
}

static bool test_multiple_bindings(fixture_t *f) {
    vireo_client_deadline_binding_t first = {0}, second = {0};
    vireo_result_t result = vireo_client_deadline_register(f->server, f->other_wheel, f->client,
                                                           100, 110, &first, NULL);
    if (result == VIREO_OK) {
        f->other_timer = first.timer;
    }
    CHECK(result == VIREO_OK);
    result = vireo_client_deadline_register(f->server, f->other_wheel, f->client, 100, 120, &second,
                                            NULL);
    if (result == VIREO_OK) {
        f->extra_timer = second.timer;
    }
    CHECK(result == VIREO_OK && same_client(first.client, second.client) &&
          !same_timer(first.timer, second.timer));
    vireo_timer_wheel_registry_info_t info;
    CHECK(vireo_timer_wheel_registry_inspect(f->other_wheel, &info) == VIREO_OK &&
          info.active_count == 2);
    CHECK(cancel_ok(f->other_wheel, &first));
    CHECK(cancel_ok(f->other_wheel, &second));
    return true;
}

static bool test_cancel_basic(fixture_t *f) {
    vireo_client_deadline_binding_t b = {0};
    CHECK(cancel_fails(f->wheel, &b, VIREO_RESULT_NOT_FOUND, VIREO_CLIENT_DEADLINE_NONE));
    CHECK(register_ok(f, 100, 110, &b));
    CHECK(cancel_fails(NULL, &b, VIREO_RESULT_INVALID_ARGUMENT, VIREO_CLIENT_DEADLINE_NONE));
    vireo_client_deadline_stage_t stage = VIREO_CLIENT_DEADLINE_REGISTER_TIMER;
    errno = EDOM;
    CHECK(vireo_client_deadline_cancel(f->wheel, NULL, &stage) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(errno == EDOM && stage == VIREO_CLIENT_DEADLINE_NONE);
    vireo_client_deadline_binding_t bad = b;
    bad.client = (vireo_connection_pool_lease_t){0};
    CHECK(cancel_fails(f->wheel, &bad, VIREO_RESULT_INVALID_ARGUMENT, VIREO_CLIENT_DEADLINE_NONE));
    bad = b;
    bad.timer = (vireo_timer_handle_t){0};
    CHECK(cancel_fails(f->wheel, &bad, VIREO_RESULT_INVALID_ARGUMENT, VIREO_CLIENT_DEADLINE_NONE));
    bad = b;
    bad.client.generation = 0;
    CHECK(cancel_fails(f->wheel, &bad, VIREO_RESULT_INVALID_ARGUMENT, VIREO_CLIENT_DEADLINE_NONE));
    bad = b;
    bad.timer.owner_id = 0;
    CHECK(cancel_fails(f->wheel, &bad, VIREO_RESULT_INVALID_ARGUMENT, VIREO_CLIENT_DEADLINE_NONE));
    return true;
}

static bool test_cancel_identity(fixture_t *f) {
    vireo_client_deadline_binding_t b = {0};
    CHECK(register_ok(f, 100, 110, &b));
    CHECK(cancel_fails(f->other_wheel, &b, VIREO_RESULT_INVALID_ARGUMENT,
                       VIREO_CLIENT_DEADLINE_CANCEL_TIMER));
    CHECK(cancel_fails(f->unprepared, &b, VIREO_RESULT_NOT_FOUND,
                       VIREO_CLIENT_DEADLINE_CANCEL_TIMER));
    vireo_client_deadline_binding_t bad = b;
    bad.timer.slot_index = SIZE_MAX;
    CHECK(cancel_fails(f->wheel, &bad, VIREO_RESULT_RANGE, VIREO_CLIENT_DEADLINE_CANCEL_TIMER));
    bad = b;
    bad.timer.generation = UINT64_MAX;
    CHECK(cancel_fails(f->wheel, &bad, VIREO_RESULT_NOT_FOUND, VIREO_CLIENT_DEADLINE_CANCEL_TIMER));
    CHECK(cancel_ok(f->wheel, &b));
    return true;
}

static bool test_duplicate_cancel(fixture_t *f) {
    vireo_client_deadline_binding_t b = {0};
    CHECK(register_ok(f, 100, 110, &b));
    vireo_client_deadline_binding_t copy = b;
    CHECK(cancel_ok(f->wheel, &b));
    CHECK(
        cancel_fails(f->wheel, &copy, VIREO_RESULT_NOT_FOUND, VIREO_CLIENT_DEADLINE_CANCEL_TIMER));
    return true;
}

static bool test_after_take(fixture_t *f) {
    vireo_client_deadline_binding_t b = {0};
    CHECK(register_ok(f, 100, 110, &b));
    CHECK(discover(f));
    vireo_timer_wheel_expired_t expired;
    CHECK(vireo_timer_wheel_take_expired(f->wheel, &expired) == VIREO_OK);
    CHECK(same_timer(expired.handle, b.timer));
    CHECK(cancel_fails(f->wheel, &b, VIREO_RESULT_NOT_FOUND, VIREO_CLIENT_DEADLINE_CANCEL_TIMER));
    vireo_tcp_server_client_info_t out, expected;
    CHECK(vireo_tcp_server_client_inspect(f->server, f->client, &expected) == VIREO_OK);
    CHECK(vireo_client_deadline_check_expired(f->server, b, &expired, &out, NULL) == VIREO_OK);
    CHECK(same_info(&out, &expected));
    /* 已拿到并匹配可信历史值后，caller 的数值账可显式清零；这不操作轮资源。 */
    b = (vireo_client_deadline_binding_t){0};
    CHECK(register_ok(f, 110, 120, &b));
    return true;
}

static bool test_after_release_stop(fixture_t *f) {
    vireo_client_deadline_binding_t b = {0};
    CHECK(register_ok(f, 100, 110, &b));
    CHECK(vireo_tcp_server_release_client(f->server, &f->client, NULL) == VIREO_OK);
    CHECK(vireo_timer_wheel_shutdown_begin(f->wheel) == VIREO_OK);
    CHECK(cancel_ok(f->wheel, &b));
    return true;
}

static bool test_closing_client(fixture_t *f) {
    CHECK(vireo_tcp_server_client_request_close(
              f->server, f->client, VIREO_CONNECTION_CLOSE_MODE_IMMEDIATE,
              VIREO_CONNECTION_CLOSE_REASON_APPLICATION, NULL) == VIREO_OK);
    vireo_client_deadline_binding_t b = {0};
    CHECK(register_ok(f, 100, 110, &b));
    CHECK(cancel_ok(f->wheel, &b));
    vireo_tcp_server_client_info_t info;
    CHECK(vireo_tcp_server_client_inspect(f->server, f->client, &info) == VIREO_OK);
    CHECK(info.connection_info.close_state == VIREO_CONNECTION_CLOSE_READY &&
          info.connection_info.close_reason == VIREO_CONNECTION_CLOSE_REASON_APPLICATION);
    return true;
}

static bool test_timer_reuse(fixture_t *f) {
    vireo_client_deadline_binding_t b = {0};
    CHECK(register_ok(f, 100, 110, &b));
    vireo_client_deadline_binding_t old = b;
    CHECK(cancel_ok(f->wheel, &b));
    CHECK(register_ok(f, 100, 120, &b));
    CHECK(old.timer.owner_id == b.timer.owner_id && old.timer.slot_index == b.timer.slot_index &&
          old.timer.generation != b.timer.generation);
    CHECK(cancel_fails(f->wheel, &old, VIREO_RESULT_NOT_FOUND, VIREO_CLIENT_DEADLINE_CANCEL_TIMER));
    vireo_timer_wheel_timer_info_t info;
    CHECK(vireo_timer_wheel_get(f->wheel, b.timer, &info) == VIREO_OK && info.deadline_ns == 120);
    return true;
}

static bool test_client_reuse(fixture_t *f) {
    vireo_client_deadline_binding_t b = {0};
    CHECK(register_ok(f, 100, 110, &b));
    vireo_connection_pool_lease_t old = f->client;
    CHECK(vireo_tcp_server_release_client(f->server, &f->client, NULL) == VIREO_OK);
    CHECK(close(f->peer) == 0);
    f->peer = -1;
    CHECK(add_client(f));
    CHECK(old.pool_id == f->client.pool_id && old.slot_index == f->client.slot_index &&
          old.generation != f->client.generation);
    vireo_client_deadline_binding_t next;
    empty_output(&next);
    CHECK(register_fails(f->server, f->wheel, old, 100, 120, &next, VIREO_RESULT_NOT_FOUND,
                         VIREO_CLIENT_DEADLINE_CHECK_CLIENT));
    CHECK(cancel_ok(f->wheel, &b));
    CHECK(register_ok(f, 100, 120, &next));
    vireo_tcp_server_client_info_t info;
    CHECK(vireo_tcp_server_client_inspect(f->server, f->client, &info) == VIREO_OK &&
          info.connection_info.close_state == VIREO_CONNECTION_CLOSE_OPEN);
    return true;
}

static bool test_ready_cancel(fixture_t *f) {
    vireo_client_deadline_binding_t b = {0};
    CHECK(register_ok(f, 100, 110, &b));
    CHECK(discover(f));
    CHECK(cancel_ok(f->wheel, &b));
    vireo_timer_wheel_progress_t progress;
    CHECK(vireo_timer_wheel_progress_inspect(f->wheel, &progress) == VIREO_OK &&
          progress.ready_count == 0);
    vireo_timer_wheel_expired_t out;
    CHECK(vireo_timer_wheel_take_expired(f->wheel, &out) == VIREO_RESULT_NOT_FOUND);
    return true;
}

/** 本项同步交付测试上下文；不拥有借用 server，也不执行业务关闭。 */
typedef struct delivery_probe {
    vireo_tcp_server_t *server;                 /**< dispatch 返回前有效的短借。 */
    vireo_client_deadline_binding_t binding;    /**< 本register真实产生的完整关联值。 */
    size_t calls;                               /**< 实际有界回调次数。 */
    vireo_client_deadline_stage_t stage;        /**< 当前客户核验阶段。 */
    vireo_tcp_server_client_info_t client_info; /**< 成功快照或失败保持的原值。 */
} delivery_probe_t;

static vireo_result_t deliver(vireo_timer_wheel_expired_t const *expired, void *context) {
    delivery_probe_t *p = context;
    ++p->calls;
    return vireo_client_deadline_check_expired(p->server, p->binding, expired, &p->client_info,
                                               &p->stage);
}

static bool test_dispatch_live(fixture_t *f) {
    delivery_probe_t p = {0};
    p.server = f->server;
    CHECK(register_ok(f, 100, 110, &p.binding));
    CHECK(discover(f));
    vireo_timer_loop_dispatch_report_t report;
    errno = EDOM;
    CHECK(vireo_timer_loop_dispatch(f->wheel, 1, deliver, &p, &report) == VIREO_OK);
    CHECK(errno == EDOM && p.calls == 1 && p.stage == VIREO_CLIENT_DEADLINE_NONE &&
          report.consumed_count == 1 && report.delivered_count == 1 && !report.has_failed_delivery);
    CHECK(p.client_info.connection_info.close_state == VIREO_CONNECTION_CLOSE_OPEN);
    CHECK(cancel_fails(f->wheel, &p.binding, VIREO_RESULT_NOT_FOUND,
                       VIREO_CLIENT_DEADLINE_CANCEL_TIMER));
    return true;
}

static bool test_dispatch_stale(fixture_t *f) {
    delivery_probe_t p = {0};
    p.server = f->server;
    CHECK(register_ok(f, 100, 110, &p.binding));
    CHECK(discover(f));
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
          report.delivered_count == 0 && report.has_failed_delivery &&
          same_timer(report.failed_delivery.handle, p.binding.timer));
    CHECK(memcmp(before, &p.client_info, sizeof before) == 0);
    CHECK(cancel_fails(f->wheel, &p.binding, VIREO_RESULT_NOT_FOUND,
                       VIREO_CLIENT_DEADLINE_CANCEL_TIMER));
    vireo_tcp_server_client_info_t info;
    CHECK(vireo_tcp_server_client_inspect(f->server, f->client, &info) == VIREO_OK &&
          info.connection_info.close_state == VIREO_CONNECTION_CLOSE_OPEN);
    return true;
}

typedef struct test_case {
    char const *name;         /**< 实际场景结果名。 */
    bool (*run)(fixture_t *); /**< 只短借资源夹具的场景函数。 */
} test_case_t;

int main(void) {
    test_case_t const cases[] = {{"register/cancel", test_register_cancel},
                                 {"register null", test_register_null},
                                 {"register shape/empty", test_register_shape_empty},
                                 {"nonempty retains timer", test_nonempty_keeps_timer},
                                 {"client rejections", test_client_rejections},
                                 {"wheel state priority", test_wheel_state},
                                 {"time errors", test_time_errors},
                                 {"finite MAX", test_finite_max},
                                 {"full wheel", test_full_wheel},
                                 {"multiple bindings", test_multiple_bindings},
                                 {"cancel basic", test_cancel_basic},
                                 {"cancel identity", test_cancel_identity},
                                 {"duplicate cancel", test_duplicate_cancel},
                                 {"after take", test_after_take},
                                 {"after release/stop", test_after_release_stop},
                                 {"closing client", test_closing_client},
                                 {"timer reuse", test_timer_reuse},
                                 {"client reuse", test_client_reuse},
                                 {"ready cancel", test_ready_cancel},
                                 {"dispatch live", test_dispatch_live},
                                 {"dispatch stale", test_dispatch_stale}};
    size_t failed = 0;
    size_t const count = sizeof cases / sizeof cases[0];
    for (size_t i = 0; i < count; ++i) {
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
    printf("%zu groups, %zu failed\n", count, failed);
    return failed == 0 ? 0 : 1;
}
