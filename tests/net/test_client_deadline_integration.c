/*
 * PROJECT : VIREO
 * FILE    : test_client_deadline_integration.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-10
 * BRIEF   : 此模块负责：
 * -- 验证真实网络与时间通知的公开组合链验证
 * -- 只依赖已采用公开合同，保持资源、输出与 errno 的既有边界
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vireo/net/client_deadline_store.h>
#include <vireo/net/timer_loop.h>
#include <vireo/net/timer_loop_dispatch.h>
#include <vireo/protocol/codec.h>
#include <vireo/timer/wheel_shutdown.h>

#define CHECK(e)                                                    \
    do {                                                            \
        if (!(e)) {                                                 \
            fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #e); \
            return false;                                           \
        }                                                           \
    } while (0)

/** 测试资源根；两个客户、四个登记、两个表记录均为显式固定容量。 */
typedef struct fixture {
    vireo_tcp_server_t *server; /**< 拥有监听、内部 loop、客户池；测试销毁。 */
    vireo_timer_wheel_t *wheel; /**< 已 prepare 的唯一轮 owner，测试销毁。 */
    vireo_client_deadline_store_t *store; /**< 固定数值表 owner，不拥有 timer。 */
    vireo_connection_pool_lease_t clients[2]; /**< 当前租约副本，实际消费后显式清零。 */
    int peers[2];                             /**< 测试对端 fd owner，-1 为空。 */
    vireo_client_deadline_binding_t bindings[4]; /**< caller 保存的完整关联或历史值。 */
    vireo_timer_handle_t keys[4]; /**< 登记时原键，供清理历史表，不授予当前控制权。 */
    struct sockaddr_in address;    /**< 回环临时端口，仅测试连接时使用。 */
    int listener_fd;               /**< 构造期 socket owner，转移后 -1。 */
    vireo_acceptor_t *listener;    /**< 构造期 owner，server 收纳后 NULL。 */
    vireo_monotonic_ns_t origin;   /**< 实际 CLOCK_MONOTONIC 起点，单位 ns。 */
    size_t handler_calls;          /**< 本 fixture 同步调用数，不是业务提交数。 */
    vireo_result_t handler_result; /**< 测试明确的应用返回，非内核错误注入。 */
} fixture_t;

/** 单次真实成功组合的观察值，不发布为产品 API／事务报告。 */
typedef struct round_trace {
    vireo_monotonic_ns_t before; /**< 等待规划前真实采样，ns。 */
    vireo_timer_loop_wait_plan_t plan; /**< 原四字段计划，server 可因客户待办缩短等待。 */
    vireo_tcp_server_serve_info_t service; /**< 原网络服务轮真实进度，含新客户准入。 */
    vireo_monotonic_ns_t after;            /**< 服务返回后真实采样，ns。 */
    vireo_timer_wheel_advance_report_t advance; /**< 本次双预算推进，不消费通知。 */
} round_trace_t;

static bool sample(vireo_monotonic_ns_t *now) {
    errno = EDOM;
    CHECK(vireo_clock_monotonic_now(now, NULL) == VIREO_OK && errno == EDOM);
    return true;
}

/** 只处理正常请求的零 body 响应；失败值供真实服务错误传播场景使用。 */
static vireo_result_t handler(vireo_connection_frame_view_t const *request, uint8_t *body,
                              size_t capacity, vireo_tcp_server_reply_t *reply, void *context) {
    fixture_t *f = context;
    (void)request;
    (void)body;
    (void)capacity;
    ++f->handler_calls;
    reply->body_size = 0;
    return f->handler_result;
}

static vireo_tcp_server_serve_options_t serve_options(int timeout) {
    return (vireo_tcp_server_serve_options_t){.timeout_ms = timeout,
                                              .process = {96, 96},
                                              .drive = {{256, 4}, {2, 192, 192}, {128, 4}},
                                              .round = {2},
                                              .admit = {2, 4}};
}

/** 测试 caller：先给网络一次机会，再推进；通知消费由测试另行显式调用。 */
static bool step(fixture_t *f, int cap, vireo_timer_wheel_advance_budget_t budget,
                 round_trace_t *trace) {
    CHECK(sample(&trace->before));
    errno = EDOM;
    CHECK(vireo_timer_loop_plan_wait(f->wheel, trace->before, cap, &trace->plan) == VIREO_OK);
    CHECK(errno == EDOM && trace->plan.timeout_ms >= 0 && trace->plan.timeout_ms <= cap);
    vireo_tcp_server_serve_options_t const options = serve_options(trace->plan.timeout_ms);
    uint8_t workspace[96];
    vireo_tcp_server_turn_result_t turns[2];
    vireo_connection_pool_lease_t admitted[2] = {0};
    CHECK(vireo_tcp_server_serve_once(f->server, &options, workspace, sizeof workspace, handler, f,
                                      turns, 2, admitted, 2, &trace->service, NULL) == VIREO_OK);
    CHECK(errno == EDOM && trace->service.round.turn_count <= 2);
    CHECK(trace->service.round.effective_timeout_ms <= trace->plan.timeout_ms);
    for (size_t i = 0; i < trace->service.admission.admitted_count; ++i) {
        size_t slot = 0;
        while (slot < 2 && f->clients[slot].pool_id != 0)
            ++slot;
        CHECK(slot < 2);
        f->clients[slot] = admitted[i];
    }
    CHECK(sample(&trace->after) && trace->after >= trace->before);
    CHECK(vireo_timer_wheel_advance(f->wheel, trace->after, budget, &trace->advance) == VIREO_OK);
    CHECK(errno == EDOM && trace->advance.ticks_started <= budget.max_ticks &&
          trace->advance.nodes_examined <= budget.max_nodes);
    return true;
}

static bool setup(fixture_t *f) {
    *f = (fixture_t){.peers = {-1, -1}, .listener_fd = -1};
    vireo_tcp_server_options_t const options = {2, 3, VIREO_TCP_SERVER_MAX_MEMORY, 768};
    CHECK(vireo_tcp_server_create(&options, &f->server, NULL) == VIREO_OK);
    f->listener_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    CHECK(f->listener_fd >= 0);
    f->address.sin_family = AF_INET;
    f->address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(bind(f->listener_fd, (struct sockaddr const *)&f->address, sizeof f->address) == 0);
    CHECK(listen(f->listener_fd, 4) == 0);
    socklen_t length = sizeof f->address;
    CHECK(getsockname(f->listener_fd, (struct sockaddr *)&f->address, &length) == 0);
    vireo_acceptor_options_t const listener_options = {VIREO_ACCEPTOR_MAX_MEMORY};
    CHECK(vireo_acceptor_create(&listener_options, &f->listener_fd, &f->listener, NULL) ==
          VIREO_OK);
    CHECK(vireo_tcp_server_adopt_listener(f->server, &f->listener, NULL) == VIREO_OK);
    CHECK(vireo_tcp_server_bind_listener(f->server, true, NULL) == VIREO_OK);
    vireo_tcp_server_admission_options_t const admission = {{256, 128, 384}, {96, 95, 192, 32, 96}};
    CHECK(vireo_tcp_server_admission_configure(f->server, &admission, NULL) == VIREO_OK);
    CHECK(sample(&f->origin));
    vireo_timer_wheel_options_t const wheel = {{f->origin, UINT64_C(10000000), 8},
                                               VIREO_TIMER_WHEEL_MAX_MEMORY};
    vireo_timer_wheel_registry_options_t const registry = {4,
                                                           VIREO_TIMER_WHEEL_REGISTRY_MAX_MEMORY};
    CHECK(vireo_timer_wheel_create(&wheel, &f->wheel) == VIREO_OK);
    CHECK(vireo_timer_wheel_prepare(f->wheel, &registry) == VIREO_OK);
    vireo_client_deadline_store_options_t const store = {2, VIREO_CLIENT_DEADLINE_STORE_MAX_MEMORY};
    CHECK(vireo_client_deadline_store_create(&store, &f->store) == VIREO_OK);
    return true;
}

static bool connect_peer(fixture_t *f, size_t i) {
    CHECK(f->peers[i] == -1 && f->clients[i].pool_id == 0);
    f->peers[i] = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    CHECK(f->peers[i] >= 0);
    CHECK(connect(f->peers[i], (struct sockaddr const *)&f->address, sizeof f->address) == 0);
    round_trace_t trace;
    for (size_t n = 0; n < 64 && f->clients[i].pool_id == 0; ++n)
        CHECK(step(f, 20, (vireo_timer_wheel_advance_budget_t){16, 16}, &trace));
    CHECK(f->clients[i].pool_id != 0);
    return true;
}

static bool same_timer(vireo_timer_handle_t a, vireo_timer_handle_t b) {
    return a.owner_id == b.owner_id && a.slot_index == b.slot_index && a.generation == b.generation;
}

static bool register_timer(fixture_t *f, size_t i, size_t client, uint64_t milliseconds,
                           bool save) {
    vireo_monotonic_ns_t now, deadline;
    vireo_duration_ns_t duration;
    CHECK(sample(&now));
    CHECK(vireo_clock_duration_from_ms(milliseconds, &duration) == VIREO_OK);
    CHECK(vireo_clock_deadline_after(now, duration, &deadline) == VIREO_OK);
    CHECK(vireo_client_deadline_register(f->server, f->wheel, f->clients[client], now, deadline,
                                         &f->bindings[i], NULL) == VIREO_OK);
    f->keys[i] = f->bindings[i].timer;
    if (save)
        CHECK(vireo_client_deadline_store_save(f->store, f->server, f->wheel, f->bindings[i],
                                               NULL) == VIREO_OK);
    CHECK(errno == EDOM);
    return true;
}

static bool wait_ready(fixture_t *f, size_t count) {
    vireo_monotonic_ns_t start, limit;
    CHECK(sample(&start));
    CHECK(vireo_clock_deadline_after(start, UINT64_C(3000000000), &limit) == VIREO_OK);
    for (size_t i = 0; i < 256; ++i) {
        round_trace_t trace;
        CHECK(step(f, 20, (vireo_timer_wheel_advance_budget_t){16, 16}, &trace));
        if (trace.advance.progress.ready_count >= count)
            return true;
        CHECK(trace.after < limit);
    }
    CHECK(false);
    return false;
}

static bool counts(fixture_t *f, size_t clients, size_t timers, size_t records) {
    vireo_tcp_server_info_t server;
    vireo_timer_wheel_registry_info_t wheel;
    vireo_client_deadline_store_info_t store;
    CHECK(vireo_tcp_server_inspect(f->server, &server) == VIREO_OK);
    CHECK(vireo_timer_wheel_registry_inspect(f->wheel, &wheel) == VIREO_OK);
    CHECK(vireo_client_deadline_store_inspect(f->store, &store) == VIREO_OK);
    CHECK(server.connection_count == clients && wheel.active_count == timers &&
          store.count == records);
    CHECK(server.buffer_capacity_bytes == clients * 384);
    return true;
}

/** 回调只作至多一次小表转出与客户动作，不采样／推进／等待或递归消费。 */
typedef struct delivery_context {
    fixture_t *fixture;           /**< 短借资源根，callback 返回前存活。 */
    bool act;                     /**< 此场景是否明确选择 IMMEDIATE 再 READY 归还。 */
    vireo_result_t forced_result; /**< 表转出后的测试应用失败，非内核故障。 */
    size_t calls;                 /**< 本上下文调用数，条数预算受 dispatch 约束。 */
    vireo_client_deadline_binding_t taken; /**< 已转出的 caller 数值记录，失败时保管。 */
    vireo_timer_wheel_expired_t history; /**< 通知值副本，不保存 callback 地址。 */
    vireo_client_deadline_release_report_t release; /**< 一次实际归还的原消费报告。 */
} delivery_context_t;

static vireo_result_t deliver(vireo_timer_wheel_expired_t const *event, void *context) {
    delivery_context_t *d = context;
    fixture_t *f = d->fixture;
    ++d->calls;
    d->history = *event;
    vireo_result_t result = vireo_client_deadline_store_take_expired(f->store, event, &d->taken);
    if (result != VIREO_OK || d->forced_result != VIREO_OK)
        return result != VIREO_OK ? result : d->forced_result;
    if (!d->act)
        return VIREO_OK;
    result = vireo_client_deadline_request_close_expired(
        f->server, d->taken, event, VIREO_CONNECTION_CLOSE_MODE_IMMEDIATE,
        VIREO_CONNECTION_CLOSE_REASON_APPLICATION, NULL);
    if (result != VIREO_OK)
        return result;
    vireo_connection_pool_lease_t const original = d->taken.client;
    result = vireo_client_deadline_release_ready_expired(f->server, &d->taken, event, &d->release);
    if (d->release.client_consumed) {
        for (size_t i = 0; i < 2; ++i)
            if (f->clients[i].pool_id == original.pool_id &&
                f->clients[i].slot_index == original.slot_index &&
                f->clients[i].generation == original.generation)
                f->clients[i] = (vireo_connection_pool_lease_t){0};
    }
    return result;
}

static bool withdraw_cancel(fixture_t *f, size_t i) {
    vireo_client_deadline_binding_t record;
    CHECK(vireo_client_deadline_store_withdraw(f->store, f->keys[i], &record) == VIREO_OK);
    CHECK(vireo_client_deadline_cancel(f->wheel, &f->bindings[i], NULL) == VIREO_OK);
    return true;
}

static bool cleanup(fixture_t *f) {
    for (size_t i = 0; i < 4; ++i) {
        if (f->keys[i].owner_id != 0 && f->store != NULL) {
            vireo_client_deadline_binding_t record;
            vireo_result_t result =
                vireo_client_deadline_store_withdraw(f->store, f->keys[i], &record);
            CHECK(result == VIREO_OK || result == VIREO_RESULT_NOT_FOUND);
            if (f->wheel != NULL) {
                result = vireo_timer_wheel_cancel(f->wheel, &f->keys[i]);
                CHECK(result == VIREO_OK || result == VIREO_RESULT_NOT_FOUND);
            }
        }
    }
    CHECK(vireo_client_deadline_store_destroy(&f->store) == VIREO_OK);
    CHECK(vireo_timer_wheel_destroy(&f->wheel) == VIREO_OK);
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
    return true;
}

static bool real_deadline_chain(fixture_t *f) {
    CHECK(connect_peer(f, 0) && register_timer(f, 0, 0, 20, true));
    CHECK(wait_ready(f, 1));
    vireo_timer_wheel_timer_info_t timer;
    CHECK(vireo_timer_wheel_get(f->wheel, f->keys[0], &timer) == VIREO_OK);
    vireo_monotonic_ns_t boundary;
    vireo_timer_wheel_geometry_t const geometry = {f->origin, UINT64_C(10000000), 8};
    CHECK(vireo_timer_wheel_tick_time(geometry, timer.due_tick, &boundary) == VIREO_OK);
    vireo_timer_wheel_progress_t progress;
    CHECK(vireo_timer_wheel_progress_inspect(f->wheel, &progress) == VIREO_OK);
    CHECK(progress.latest_now_ns >= boundary && boundary >= timer.deadline_ns);
    delivery_context_t d = {.fixture = f, .act = true};
    vireo_timer_loop_dispatch_report_t report;
    errno = EDOM;
    CHECK(vireo_timer_loop_dispatch(f->wheel, 1, deliver, &d, &report) == VIREO_OK &&
          errno == EDOM);
    CHECK(d.calls == 1 && report.consumed_count == 1 && report.delivered_count == 1);
    CHECK(d.release.release_called && d.release.client_consumed && d.taken.timer.owner_id == 0);
    CHECK(vireo_timer_wheel_get(f->wheel, f->keys[0], &timer) == VIREO_RESULT_NOT_FOUND);
    CHECK(counts(f, 0, 0, 0));
    return true;
}

static bool send_request(fixture_t *f, size_t i) {
    uint8_t wire[32];
    vireo_protocol_header_t h = {.command = VIREO_COMMAND_PING, .sequence = 7};
    CHECK(vireo_protocol_header_encode(&h, wire, sizeof wire) == VIREO_OK);
    CHECK(vireo_protocol_frame_crc32c_calculate(wire, sizeof wire, NULL, 0, &h.crc32c) == VIREO_OK);
    CHECK(vireo_protocol_header_encode(&h, wire, sizeof wire) == VIREO_OK);
    CHECK(send(f->peers[i], wire, sizeof wire, MSG_NOSIGNAL) == (ssize_t)sizeof wire);
    return true;
}

static bool receive_reply(fixture_t *f, size_t i) {
    uint8_t wire[32];
    size_t size = 0;
    for (size_t n = 0; n < 32 && size < sizeof wire; ++n) {
        struct pollfd p = {.fd = f->peers[i], .events = POLLIN};
        CHECK(poll(&p, 1, 1000) == 1 && (p.revents & POLLIN) != 0);
        ssize_t got = recv(f->peers[i], wire + size, sizeof wire - size, 0);
        CHECK(got > 0);
        size += (size_t)got;
    }
    CHECK(size == sizeof wire);
    vireo_protocol_header_t header;
    vireo_protocol_codec_issue_t issue;
    CHECK(vireo_protocol_header_decode(wire, sizeof wire, &header, &issue) == VIREO_OK);
    CHECK(header.sequence == 7 && header.command == VIREO_COMMAND_PING && header.body_len == 0);
    CHECK((header.flags & VIREO_PROTOCOL_FLAG_RESPONSE) != 0);
    CHECK(vireo_protocol_frame_crc32c_verify(wire, sizeof wire, NULL, 0, &issue) == VIREO_OK);
    return true;
}

static bool service_and_rearm(fixture_t *f) {
    CHECK(connect_peer(f, 0) && register_timer(f, 0, 0, 10000, true) && send_request(f, 0));
    round_trace_t trace;
    for (size_t i = 0; i < 64 && f->handler_calls == 0; ++i)
        CHECK(step(f, 20, (vireo_timer_wheel_advance_budget_t){16, 16}, &trace));
    CHECK(f->handler_calls == 1 && receive_reply(f, 0));
    vireo_monotonic_ns_t now, deadline;
    CHECK(sample(&now));
    CHECK(vireo_clock_deadline_after(now, UINT64_C(20000000000), &deadline) == VIREO_OK);
    CHECK(vireo_client_deadline_rearm(f->server, f->wheel, f->bindings[0], now, deadline, NULL) ==
          VIREO_OK);
    CHECK(same_timer(f->bindings[0].timer, f->keys[0]));
    vireo_client_deadline_binding_t record;
    CHECK(vireo_client_deadline_store_find(f->store, f->keys[0], &record) == VIREO_OK);
    CHECK(same_timer(record.timer, f->keys[0]));
    CHECK(withdraw_cancel(f, 0) && counts(f, 1, 0, 0));
    return true;
}

static bool debt_still_services_network(fixture_t *f) {
    CHECK(connect_peer(f, 0) && register_timer(f, 0, 0, 10000, true));
    CHECK(poll(NULL, 0, 60) == 0); /* 回调外有限等待，仅建立真实时间进度债。 */
    CHECK(send_request(f, 0));
    round_trace_t trace;
    CHECK(step(f, 20, (vireo_timer_wheel_advance_budget_t){1, 1}, &trace));
    CHECK(trace.plan.timer_work_pending && trace.plan.timeout_ms == 0);
    CHECK(trace.service.round.effective_timeout_ms == 0 && trace.service.round.turn_count == 1);
    CHECK(f->handler_calls == 1 && !trace.advance.progress.caught_up);
    CHECK(receive_reply(f, 0) && withdraw_cancel(f, 0));
    return true;
}

static bool save_failure_compensation(fixture_t *f) {
    CHECK(connect_peer(f, 0));
    CHECK(register_timer(f, 0, 0, 10000, true) && register_timer(f, 1, 0, 10000, true));
    CHECK(register_timer(f, 2, 0, 10000, false));
    vireo_client_deadline_binding_t const original = f->bindings[2];
    errno = EDOM;
    CHECK(vireo_client_deadline_store_save(f->store, f->server, f->wheel, original, NULL) ==
          VIREO_RESULT_BUSY);
    CHECK(errno == EDOM && counts(f, 1, 3, 2));
    vireo_timer_wheel_timer_info_t timer;
    CHECK(vireo_timer_wheel_get(f->wheel, original.timer, &timer) == VIREO_OK);
    CHECK(same_timer(f->bindings[2].timer, original.timer));
    CHECK(vireo_client_deadline_cancel(f->wheel, &f->bindings[2], NULL) == VIREO_OK);
    CHECK(counts(f, 1, 2, 2));
    CHECK(withdraw_cancel(f, 0) && withdraw_cancel(f, 1));
    return true;
}

static bool ready_rearm_cancel(fixture_t *f) {
    CHECK(connect_peer(f, 0) && register_timer(f, 0, 0, 20, true) &&
          register_timer(f, 1, 0, 20, true));
    CHECK(wait_ready(f, 2));
    vireo_monotonic_ns_t now, deadline;
    CHECK(sample(&now));
    CHECK(vireo_clock_deadline_after(now, UINT64_C(10000000000), &deadline) == VIREO_OK);
    CHECK(vireo_client_deadline_rearm(f->server, f->wheel, f->bindings[0], now, deadline, NULL) ==
          VIREO_OK);
    vireo_timer_wheel_progress_t progress;
    CHECK(vireo_timer_wheel_progress_inspect(f->wheel, &progress) == VIREO_OK &&
          progress.ready_count == 1);
    CHECK(withdraw_cancel(f, 1));
    delivery_context_t d = {.fixture = f};
    vireo_timer_loop_dispatch_report_t report;
    CHECK(vireo_timer_loop_dispatch(f->wheel, 1, deliver, &d, &report) == VIREO_OK);
    CHECK(report.consumed_count == 0 && d.calls == 0);
    CHECK(same_timer(f->bindings[0].timer, f->keys[0]) && counts(f, 1, 1, 1));
    CHECK(withdraw_cancel(f, 0));
    return true;
}

static bool stale_client_after_real_expiry(fixture_t *f) {
    CHECK(connect_peer(f, 0) && register_timer(f, 0, 0, 20, true) && wait_ready(f, 1));
    delivery_context_t d = {.fixture = f};
    vireo_timer_loop_dispatch_report_t report;
    CHECK(vireo_timer_loop_dispatch(f->wheel, 1, deliver, &d, &report) == VIREO_OK);
    vireo_connection_pool_lease_t const old = f->clients[0];
    CHECK(vireo_tcp_server_release_client(f->server, &f->clients[0], NULL) == VIREO_OK);
    CHECK(close(f->peers[0]) == 0);
    f->peers[0] = -1;
    CHECK(connect_peer(f, 0));
    CHECK(f->clients[0].slot_index == old.slot_index && f->clients[0].generation != old.generation);
    vireo_client_deadline_close_error_t error;
    errno = EDOM;
    CHECK(vireo_client_deadline_request_close_expired(
              f->server, d.taken, &d.history, VIREO_CONNECTION_CLOSE_MODE_IMMEDIATE,
              VIREO_CONNECTION_CLOSE_REASON_APPLICATION, &error) == VIREO_RESULT_NOT_FOUND);
    CHECK(errno == EDOM && !error.close_called &&
          error.stage == VIREO_CLIENT_DEADLINE_CHECK_CLIENT);
    vireo_tcp_server_client_info_t info;
    CHECK(vireo_tcp_server_client_inspect(f->server, f->clients[0], &info) == VIREO_OK);
    CHECK(info.connection_info.close_state == VIREO_CONNECTION_CLOSE_OPEN && counts(f, 1, 0, 0));
    return true;
}

static bool failed_delivery_keeps_transfer(fixture_t *f) {
    CHECK(connect_peer(f, 0) && register_timer(f, 0, 0, 20, true) && wait_ready(f, 1));
    delivery_context_t d = {.fixture = f, .forced_result = VIREO_RESULT_PROTOCOL};
    vireo_timer_loop_dispatch_report_t report;
    errno = EDOM;
    CHECK(vireo_timer_loop_dispatch(f->wheel, 1, deliver, &d, &report) == VIREO_RESULT_PROTOCOL);
    CHECK(errno == EDOM && report.stage == VIREO_TIMER_LOOP_DISPATCH_STAGE_DELIVER &&
          report.consumed_count == 1 && report.delivered_count == 0 && report.has_failed_delivery);
    CHECK(same_timer(report.failed_delivery.handle, d.taken.timer) && counts(f, 1, 0, 0));
    vireo_client_deadline_binding_t record;
    CHECK(vireo_client_deadline_store_find(f->store, d.taken.timer, &record) ==
          VIREO_RESULT_NOT_FOUND);
    CHECK(vireo_client_deadline_request_close_expired(
              f->server, d.taken, &d.history, VIREO_CONNECTION_CLOSE_MODE_IMMEDIATE,
              VIREO_CONNECTION_CLOSE_REASON_APPLICATION, NULL) == VIREO_OK);
    CHECK(vireo_client_deadline_release_ready_expired(f->server, &d.taken, &d.history,
                                                      &d.release) == VIREO_OK);
    CHECK(d.release.client_consumed);
    f->clients[0] = (vireo_connection_pool_lease_t){0};
    CHECK(counts(f, 0, 0, 0));
    return true;
}

static bool independent_shutdown(fixture_t *f) {
    CHECK(connect_peer(f, 0) && connect_peer(f, 1));
    CHECK(register_timer(f, 0, 0, 20, true) && register_timer(f, 1, 1, 10000, true));
    CHECK(wait_ready(f, 1) && vireo_timer_wheel_shutdown_begin(f->wheel) == VIREO_OK);
    vireo_timer_loop_wait_plan_t plan = {17, true, true, 19};
    vireo_timer_loop_wait_plan_t const before = plan;
    vireo_monotonic_ns_t now;
    CHECK(sample(&now));
    CHECK(vireo_timer_loop_plan_wait(f->wheel, now, 20, &plan) == VIREO_RESULT_CANCELLED);
    CHECK(plan.timeout_ms == before.timeout_ms &&
          plan.timer_work_pending == before.timer_work_pending &&
          plan.has_tick_deadline == before.has_tick_deadline &&
          plan.tick_deadline_ns == before.tick_deadline_ns);
    delivery_context_t d = {.fixture = f, .act = true};
    vireo_timer_loop_dispatch_report_t dispatch;
    CHECK(vireo_timer_loop_dispatch(f->wheel, 1, deliver, &d, &dispatch) == VIREO_OK);
    CHECK(dispatch.consumed_count == 1 && counts(f, 1, 1, 1));
    bool finished = false;
    size_t cancelled = 0;
    for (size_t i = 0; i < 4 && !finished; ++i) {
        vireo_timer_wheel_shutdown_report_t report;
        CHECK(vireo_timer_wheel_shutdown_step(f->wheel, 1, &report) == VIREO_OK);
        CHECK(report.scanned_slots <= 1);
        if (report.has_cancelled) {
            vireo_client_deadline_binding_t record;
            CHECK(same_timer(report.cancelled.handle, f->keys[1]));
            CHECK(vireo_client_deadline_store_withdraw(f->store, report.cancelled.handle,
                                                       &record) == VIREO_OK);
            ++cancelled;
        }
        finished = report.finished;
    }
    CHECK(finished && cancelled == 1 && counts(f, 1, 0, 0));
    CHECK(vireo_tcp_server_request_stop(f->server, NULL) == VIREO_OK);
    CHECK(counts(f, 1, 0, 0));
    vireo_tcp_server_shutdown_budget_t const budget = {2};
    vireo_tcp_server_shutdown_result_t results[2];
    vireo_tcp_server_shutdown_info_t info;
    CHECK(vireo_tcp_server_shutdown_batch(f->server, &budget, results, 2, &info, NULL) == VIREO_OK);
    CHECK(info.remaining_clients == 0 && info.released_clients == 1);
    f->clients[1] = (vireo_connection_pool_lease_t){0};
    CHECK(counts(f, 0, 0, 0));
    return true;
}

static bool service_failure_is_not_timer_rollback(fixture_t *f) {
    CHECK(connect_peer(f, 0) && register_timer(f, 0, 0, 10000, true) && send_request(f, 0));
    f->handler_result = VIREO_RESULT_PROTOCOL;
    uint8_t workspace[96];
    vireo_tcp_server_turn_result_t turns[2];
    vireo_connection_pool_lease_t admitted[2] = {0};
    vireo_tcp_server_serve_info_t info;
    vireo_tcp_server_serve_error_t error;
    vireo_result_t result = VIREO_OK;
    vireo_tcp_server_serve_options_t const options = serve_options(20);
    for (size_t i = 0; i < 64 && f->handler_calls == 0; ++i) {
        errno = EDOM;
        result = vireo_tcp_server_serve_once(f->server, &options, workspace, sizeof workspace,
                                             handler, f, turns, 2, admitted, 2, &info, &error);
        CHECK(errno == EDOM && (result == VIREO_OK || result == VIREO_RESULT_PROTOCOL));
    }
    CHECK(f->handler_calls == 1 && result == VIREO_RESULT_PROTOCOL);
    CHECK(error.stage == VIREO_TCP_SERVER_SERVE_ROUND && info.round.turn_count == 1 &&
          info.round.failed_count == 1);
    CHECK(counts(f, 1, 1, 1));
    vireo_tcp_server_client_info_t client;
    CHECK(vireo_tcp_server_client_inspect(f->server, f->clients[0], &client) == VIREO_OK);
    CHECK(client.connection_info.read_buffer.readable_size == 32 &&
          client.connection_info.close_state == VIREO_CONNECTION_CLOSE_OPEN);
    f->handler_result = VIREO_OK;
    CHECK(vireo_tcp_server_schedule_client(f->server, f->clients[0], NULL) == VIREO_OK);
    round_trace_t trace;
    CHECK(step(f, 20, (vireo_timer_wheel_advance_budget_t){16, 16}, &trace));
    CHECK(f->handler_calls == 2 && receive_reply(f, 0));
    CHECK(withdraw_cancel(f, 0));
    return true;
}

/** 注册表仅测试入口，不参与产品数据结构。 */
typedef struct test_case {
    char const *name;         /**< 静态场景标签，仅打印，不拥有。 */
    bool (*run)(fixture_t *); /**< 独立 setup 后同步测试，不保存 fixture。 */
} test_case_t;

int main(void) {
    test_case_t const cases[] = {
        {"real CLOCK_MONOTONIC deadline to customer consumption", real_deadline_chain},
        {"TCP request service with stable rearm and explicit cancellation", service_and_rearm},
        {"timer debt still grants a bounded network turn", debt_still_services_network},
        {"full record table requires caller timer compensation", save_failure_compensation},
        {"ready rearm and cancellation withdraw discovered notifications", ready_rearm_cancel},
        {"late history cannot close reused customer slot", stale_client_after_real_expiry},
        {"failed delivery keeps transferred history for explicit recovery",
         failed_delivery_keeps_transfer},
        {"ready delivery and future cancellation during independent shutdown",
         independent_shutdown},
        {"handler failure retains request and timer without automatic replay",
         service_failure_is_not_timer_rollback}};
    size_t failed = 0;
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
        fixture_t f;
        bool ok = setup(&f);
        if (ok)
            ok = cases[i].run(&f);
        if (!cleanup(&f))
            ok = false;
        printf("%s: %s\n", cases[i].name, ok ? "PASS" : "FAIL");
        if (!ok)
            ++failed;
    }
    printf("9 groups, %zu failed\n", failed);
    return failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
