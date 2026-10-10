/*
 * PROJECT : VIREO
 * FILE    : test_client_deadline_serve.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-10
 * BRIEF   : 此模块负责：
 * -- 验证公开双采样、等待规划、有限服务及有界推进
 * -- 只依赖已采用公开合同，保持资源、输出与 errno 的既有边界
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vireo/protocol/codec.h>
#include <vireo/timer/wheel_shutdown.h>
#include "net/client_deadline_serve_internal.h"

#define CHECK(e)                                                    \
    do {                                                            \
        if (!(e)) {                                                 \
            fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #e); \
            return false;                                           \
        }                                                           \
    } while (0)

/** 每场景拥有的真实资源，全部通过公开入口构造和释放。 */
typedef struct fixture {
    vireo_tcp_server_t *server;  /**< 唯一 server owner，包含真实监听/客户。 */
    vireo_timer_wheel_t *wheel;  /**< 唯一 prepare 轮 owner，独立收尾。 */
    vireo_monotonic_ns_t origin; /**< 实际采样的单调起点，ns。 */
    struct sockaddr_in address;  /**< 回环临时端口，仅用于连接对端。 */
    int listener_fd;             /**< 构造期 fd owner，转移后 -1。 */
    vireo_acceptor_t *listener;  /**< 构造期 owner，收纳后 NULL。 */
    int peers[2]; /**< 测试对端 fd owner，-1 为空，清理时各关闭一次。 */
    vireo_connection_pool_lease_t client; /**< 已准入当前客户数值副本，不保活。 */
    size_t handler_calls;          /**< 实际同步调用次数，不是事务成功数。 */
    vireo_result_t handler_result; /**< 明确应用返回值，不模拟内核故障。 */
    bool stop_wheel;               /**< handler 是否请求公开 begin 停止轮。 */
} fixture_t;

/** 一次调用的独立借用区域；数组尾部用于检查真实前缀边界。 */
typedef struct call_io {
    vireo_tcp_server_serve_options_t options; /**< 原选项，timeout 默认 0。 */
    uint8_t workspace[96];                    /**< 独立响应整帧区，单位字节。 */
    vireo_tcp_server_turn_result_t turns[2]; /**< 原逐客户值数组，仅真实前缀可写。 */
    vireo_connection_pool_lease_t clients[2]; /**< 有效入口前缀逻辑空，新客户仍 owned 于 server。 */
    vireo_client_deadline_serve_report_t report; /**< 每路径发布的产品报告。 */
} call_io_t;

/** 本层 clock 测试缝，网络服务仍为公开真实 server。 */
typedef struct clock_probe {
    size_t calls; /**< 实际采样调用数，最多二次，验证早失败停止。 */
    vireo_monotonic_ns_t times[2]; /**< 两次显式合成同域值，不冒真实 clock 观察。 */
    vireo_result_t results[2];     /**< 两次明确失败或成功分类。 */
    int errors[2]; /**< 读取失败的模拟系统原因，非实际 clock_gettime 失败。 */
} clock_probe_t;

static vireo_result_t handler(vireo_connection_frame_view_t const *request, uint8_t *body,
                              size_t capacity, vireo_tcp_server_reply_t *reply, void *context) {
    fixture_t *f = context;
    (void)request;
    (void)body;
    (void)capacity;
    ++f->handler_calls;
    reply->body_size = 0;
    if (f->stop_wheel) {
        vireo_result_t result = vireo_timer_wheel_shutdown_begin(f->wheel);
        if (result != VIREO_OK)
            return result;
    }
    return f->handler_result;
}

static vireo_result_t fake_clock(vireo_monotonic_ns_t *now, vireo_clock_error_t *error,
                                 void *context) {
    clock_probe_t *p = context;
    size_t const i = p->calls++;
    errno = EIO; /* 明确检查编排恢复入口 errno。 */
    if (i >= 2)
        return VIREO_RESULT_INTERNAL;
    *error = (vireo_clock_error_t){0};
    if (p->results[i] != VIREO_OK) {
        error->stage = VIREO_CLOCK_STAGE_READ;
        error->system_errno = p->errors[i];
        return p->results[i]; /* 遵公开 clock 失败保持时间输出。 */
    }
    *now = p->times[i];
    return VIREO_OK;
}

static call_io_t io_new(void) {
    call_io_t io = {.options = {.timeout_ms = 0,
                                .process = {96, 96},
                                .drive = {{256, 4}, {2, 192, 192}, {128, 4}},
                                .round = {2},
                                .admit = {2, 4}}};
    memset(io.workspace, 0x71, sizeof io.workspace);
    memset(io.turns, 0x72, sizeof io.turns);
    memset(&io.report, 0x73, sizeof io.report);
    return io;
}

static vireo_result_t call(fixture_t *f, call_io_t *io, vireo_timer_wheel_advance_budget_t budget,
                           clock_probe_t *probe) {
    errno = EDOM;
    if (probe != NULL) {
        vireo_client_deadline_serve_runtime_t const runtime = {fake_clock, probe};
        return vireo_client_deadline_serve_once_runtime(
            f->server, f->wheel, &io->options, budget, io->workspace, sizeof io->workspace, handler,
            f, io->turns, 2, io->clients, 2, &io->report, &runtime);
    }
    return vireo_client_deadline_serve_once(f->server, f->wheel, &io->options, budget,
                                            io->workspace, sizeof io->workspace, handler, f,
                                            io->turns, 2, io->clients, 2, &io->report);
}

static bool wheel_replace(fixture_t *f, uint64_t origin, uint64_t tick, bool prepare) {
    CHECK(vireo_timer_wheel_destroy(&f->wheel) == VIREO_OK);
    vireo_timer_wheel_options_t const options = {{origin, tick, 8}, VIREO_TIMER_WHEEL_MAX_MEMORY};
    CHECK(vireo_timer_wheel_create(&options, &f->wheel) == VIREO_OK);
    if (prepare) {
        vireo_timer_wheel_registry_options_t const registry = {
            4, VIREO_TIMER_WHEEL_REGISTRY_MAX_MEMORY};
        CHECK(vireo_timer_wheel_prepare(f->wheel, &registry) == VIREO_OK);
    }
    f->origin = origin;
    return true;
}

static bool setup(fixture_t *f) {
    *f = (fixture_t){.listener_fd = -1, .peers = {-1, -1}};
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
    vireo_acceptor_options_t const acceptor = {VIREO_ACCEPTOR_MAX_MEMORY};
    CHECK(vireo_acceptor_create(&acceptor, &f->listener_fd, &f->listener, NULL) == VIREO_OK);
    CHECK(vireo_tcp_server_adopt_listener(f->server, &f->listener, NULL) == VIREO_OK);
    CHECK(vireo_tcp_server_bind_listener(f->server, true, NULL) == VIREO_OK);
    vireo_tcp_server_admission_options_t const admission = {{256, 128, 384}, {96, 95, 192, 32, 96}};
    CHECK(vireo_tcp_server_admission_configure(f->server, &admission, NULL) == VIREO_OK);
    uint64_t now;
    CHECK(vireo_clock_monotonic_now(&now, NULL) == VIREO_OK);
    CHECK(wheel_replace(f, now, UINT64_C(10000000), true));
    return true;
}

static bool cleanup(fixture_t *f) {
    if (f->wheel != NULL) {
        vireo_timer_wheel_registry_info_t registry;
        CHECK(vireo_timer_wheel_registry_inspect(f->wheel, &registry) == VIREO_OK);
        if (registry.prepared) {
            CHECK(vireo_timer_wheel_shutdown_begin(f->wheel) == VIREO_OK);
            bool finished = false;
            for (size_t i = 0; i < 5 && !finished; ++i) {
                vireo_timer_wheel_shutdown_report_t report;
                CHECK(vireo_timer_wheel_shutdown_step(f->wheel, 4, &report) == VIREO_OK);
                finished = report.finished;
            }
            CHECK(finished);
        }
        CHECK(vireo_timer_wheel_destroy(&f->wheel) == VIREO_OK);
    }
    if (f->server != NULL) {
        CHECK(vireo_tcp_server_request_stop(f->server, NULL) == VIREO_OK);
        vireo_tcp_server_shutdown_budget_t const budget = {2};
        bool finished = false;
        for (size_t i = 0; i < 3 && !finished; ++i) {
            vireo_tcp_server_shutdown_result_t results[2];
            vireo_tcp_server_shutdown_info_t info;
            CHECK(vireo_tcp_server_shutdown_batch(f->server, &budget, results, 2, &info, NULL) ==
                  VIREO_OK);
            finished = info.remaining_clients == 0;
        }
        CHECK(finished && vireo_tcp_server_destroy(&f->server, NULL) == VIREO_OK);
    }
    for (size_t i = 0; i < 2; ++i)
        if (f->peers[i] >= 0)
            CHECK(close(f->peers[i]) == 0);
    if (f->listener_fd >= 0)
        CHECK(close(f->listener_fd) == 0);
    CHECK(vireo_acceptor_destroy(&f->listener, NULL) == VIREO_OK);
    return true;
}

static bool peer_open(fixture_t *f, size_t i) {
    f->peers[i] = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    CHECK(f->peers[i] >= 0);
    CHECK(connect(f->peers[i], (struct sockaddr const *)&f->address, sizeof f->address) == 0);
    return true;
}

static bool admit_client(fixture_t *f) {
    CHECK(peer_open(f, 0));
    for (size_t i = 0; i < 64 && f->client.pool_id == 0; ++i) {
        call_io_t io = io_new();
        io.options.timeout_ms = 20;
        CHECK(call(f, &io, (vireo_timer_wheel_advance_budget_t){16, 16}, NULL) == VIREO_OK);
        CHECK(errno == EDOM && io.report.serve_info.admission.admitted_count <= 1);
        if (io.report.serve_info.admission.admitted_count == 1)
            f->client = io.clients[0];
    }
    CHECK(f->client.pool_id != 0);
    return true;
}

static bool request_send(fixture_t *f) {
    uint8_t wire[32];
    vireo_protocol_header_t header = {.command = VIREO_COMMAND_PING, .sequence = 7};
    CHECK(vireo_protocol_header_encode(&header, wire, sizeof wire) == VIREO_OK);
    CHECK(vireo_protocol_frame_crc32c_calculate(wire, sizeof wire, NULL, 0, &header.crc32c) ==
          VIREO_OK);
    CHECK(vireo_protocol_header_encode(&header, wire, sizeof wire) == VIREO_OK);
    CHECK(send(f->peers[0], wire, sizeof wire, MSG_NOSIGNAL) == (ssize_t)sizeof wire);
    return true;
}

static bool basic_nulls(fixture_t *f) {
    for (size_t i = 0; i < 8; ++i) {
        call_io_t io = io_new(), old = io;
        errno = EDOM;
        CHECK(vireo_client_deadline_serve_once(
                  i == 0 ? NULL : f->server, i == 1 ? NULL : f->wheel, i == 2 ? NULL : &io.options,
                  (vireo_timer_wheel_advance_budget_t){1, 1}, i == 3 ? NULL : io.workspace,
                  sizeof io.workspace, i == 4 ? NULL : handler, f, i == 5 ? NULL : io.turns, 2,
                  i == 6 ? NULL : io.clients, 2,
                  i == 7 ? NULL : &io.report) == VIREO_RESULT_INVALID_ARGUMENT);
        CHECK(errno == EDOM && memcmp(io.workspace, old.workspace, sizeof io.workspace) == 0);
        CHECK(memcmp(io.turns, old.turns, sizeof io.turns) == 0 &&
              memcmp(io.clients, old.clients, sizeof io.clients) == 0);
        if (i == 7)
            CHECK(memcmp(&io.report, &old.report, sizeof io.report) == 0);
        else
            CHECK(io.report.stage == VIREO_CLIENT_DEADLINE_SERVE_NONE && !io.report.serve_called &&
                  !io.report.serve_completed);
    }
    return true;
}

static bool basic_budgets(fixture_t *f) {
    for (size_t i = 0; i < 5; ++i) {
        call_io_t io = io_new();
        clock_probe_t clock = {.times = {f->origin, f->origin}};
        vireo_timer_wheel_advance_budget_t budget = {1, 1};
        if (i == 0)
            io.options.timeout_ms = -1;
        if (i == 1)
            budget.max_ticks = 0;
        if (i == 2)
            budget.max_nodes = 0;
        if (i == 3)
            budget.max_ticks = VIREO_TIMER_WHEEL_ADVANCE_MAX_BUDGET + 1;
        if (i == 4)
            budget.max_nodes = VIREO_TIMER_WHEEL_ADVANCE_MAX_BUDGET + 1;
        CHECK(call(f, &io, budget, &clock) ==
              (i < 3 ? VIREO_RESULT_INVALID_ARGUMENT : VIREO_RESULT_RANGE));
        CHECK(errno == EDOM && clock.calls == 0 && !io.report.serve_called &&
              io.report.stage == VIREO_CLIENT_DEADLINE_SERVE_NONE);
    }
    return true;
}

static bool unprepared(fixture_t *f) {
    CHECK(wheel_replace(f, f->origin, UINT64_C(10000000), false));
    call_io_t io = io_new();
    clock_probe_t clock = {0};
    CHECK(call(f, &io, (vireo_timer_wheel_advance_budget_t){1, 1}, &clock) ==
          VIREO_RESULT_NOT_FOUND);
    CHECK(errno == EDOM && clock.calls == 0 && !io.report.serve_called &&
          io.report.stage == VIREO_CLIENT_DEADLINE_SERVE_CHECK_WHEEL);
    return true;
}

static bool stopped_wheel(fixture_t *f) {
    CHECK(vireo_timer_wheel_shutdown_begin(f->wheel) == VIREO_OK);
    call_io_t io = io_new();
    clock_probe_t clock = {.results = {VIREO_RESULT_IO, VIREO_RESULT_IO}};
    CHECK(call(f, &io, (vireo_timer_wheel_advance_budget_t){1, 1}, &clock) ==
          VIREO_RESULT_CANCELLED);
    CHECK(errno == EDOM && clock.calls == 0 &&
          io.report.stage == VIREO_CLIENT_DEADLINE_SERVE_CHECK_WHEEL);
    io.options.timeout_ms = -1;
    CHECK(call(f, &io, (vireo_timer_wheel_advance_budget_t){0, 1}, &clock) ==
          VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(io.report.stage == VIREO_CLIENT_DEADLINE_SERVE_NONE && clock.calls == 0);
    return true;
}

static bool before_clock_failure(fixture_t *f) {
    CHECK(peer_open(f, 0));
    call_io_t io = io_new(), old = io;
    clock_probe_t clock = {.results = {VIREO_RESULT_IO, VIREO_OK}, .errors = {EACCES, 0}};
    CHECK(call(f, &io, (vireo_timer_wheel_advance_budget_t){1, 1}, &clock) == VIREO_RESULT_IO);
    CHECK(errno == EDOM && clock.calls == 1 &&
          io.report.stage == VIREO_CLIENT_DEADLINE_SERVE_CLOCK_BEFORE);
    CHECK(!io.report.serve_called && io.report.clock_error.stage == VIREO_CLOCK_STAGE_READ &&
          io.report.clock_error.system_errno == EACCES && io.report.before_now_ns == 0);
    CHECK(memcmp(io.workspace, old.workspace, sizeof io.workspace) == 0 &&
          memcmp(io.clients, old.clients, sizeof io.clients) == 0);
    vireo_tcp_server_info_t server;
    CHECK(vireo_tcp_server_inspect(f->server, &server) == VIREO_OK && server.connection_count == 0);
    return true;
}

static bool plan_time_range(fixture_t *f) {
    CHECK(wheel_replace(f, 100, 10, true));
    for (size_t i = 0; i < 2; ++i) {
        if (i == 1) {
            vireo_timer_wheel_advance_report_t report;
            CHECK(vireo_timer_wheel_advance(f->wheel, 110,
                                            (vireo_timer_wheel_advance_budget_t){1, 1},
                                            &report) == VIREO_OK);
        }
        call_io_t io = io_new();
        clock_probe_t clock = {.times = {i == 0 ? 99 : 109, 110}};
        CHECK(call(f, &io, (vireo_timer_wheel_advance_budget_t){1, 1}, &clock) ==
              VIREO_RESULT_RANGE);
        CHECK(errno == EDOM && clock.calls == 1 && !io.report.serve_called &&
              io.report.stage == VIREO_CLIENT_DEADLINE_SERVE_PLAN_WAIT);
    }
    return true;
}

static bool service_validation(fixture_t *f) {
    for (size_t i = 0; i < 4; ++i) {
        call_io_t io = io_new(), old = io;
        clock_probe_t clock = {.times = {f->origin, f->origin}};
        if (i == 0)
            io.options.process.max_request_frame_bytes = 0;
        if (i == 1)
            io.options.round.max_clients = 0;
        if (i == 2)
            io.options.admit.max_accepts = 0;
        if (i == 3)
            io.clients[0].pool_id = 1;
        old = io;
        vireo_result_t const result =
            call(f, &io, (vireo_timer_wheel_advance_budget_t){1, 1}, &clock);
        CHECK(result == VIREO_RESULT_INVALID_ARGUMENT || result == VIREO_RESULT_RANGE);
        CHECK(errno == EDOM && clock.calls == 1 && io.report.serve_called &&
              !io.report.serve_completed && io.report.stage == VIREO_CLIENT_DEADLINE_SERVE_SERVICE);
        CHECK(io.report.serve_info.round.turn_count == 0 &&
              memcmp(io.clients, old.clients, sizeof io.clients) == 0 &&
              memcmp(io.turns, old.turns, sizeof io.turns) == 0 &&
              memcmp(io.workspace, old.workspace, sizeof io.workspace) == 0);
    }
    return true;
}

static bool empty_caps_and_extremes(fixture_t *f) {
    CHECK(vireo_tcp_server_request_stop(f->server, NULL) == VIREO_OK);
    uint64_t const times[] = {0, UINT64_MAX};
    for (size_t i = 0; i < 2; ++i) {
        CHECK(wheel_replace(f, times[i], 1, true));
        call_io_t io = io_new();
        io.options.timeout_ms = INT_MAX;
        clock_probe_t clock = {.times = {times[i], times[i]}};
        CHECK(call(f, &io, (vireo_timer_wheel_advance_budget_t){65536, 65536}, &clock) == VIREO_OK);
        CHECK(errno == EDOM && clock.calls == 2 &&
              io.report.stage == VIREO_CLIENT_DEADLINE_SERVE_NONE &&
              io.report.before_now_ns == times[i] && io.report.after_now_ns == times[i]);
        CHECK(io.report.wait_plan.timeout_ms == INT_MAX && !io.report.wait_plan.has_tick_deadline &&
              !io.report.wait_plan.timer_work_pending && io.report.serve_completed &&
              io.report.serve_info.round.turn_count == 0 && io.report.advance.progress.caught_up);
    }
    return true;
}

static bool active_ceil_caps(fixture_t *f) {
    CHECK(vireo_tcp_server_request_stop(f->server, NULL) == VIREO_OK);
    vireo_timer_handle_t timer = {0};
    CHECK(vireo_timer_wheel_register(f->wheel, f->origin, f->origin + UINT64_C(1000000000),
                                     &timer) == VIREO_OK);
    int const caps[] = {0, 5, INT_MAX};
    for (size_t i = 0; i < 3; ++i) {
        call_io_t io = io_new();
        io.options.timeout_ms = caps[i];
        clock_probe_t clock = {.times = {f->origin + 1, f->origin + 1}};
        CHECK(call(f, &io, (vireo_timer_wheel_advance_budget_t){1, 1}, &clock) == VIREO_OK);
        CHECK(errno == EDOM && io.options.timeout_ms == caps[i] &&
              io.report.wait_plan.has_tick_deadline && !io.report.wait_plan.timer_work_pending &&
              io.report.wait_plan.timeout_ms == (caps[i] < 10 ? caps[i] : 10));
        CHECK(io.report.wait_plan.tick_deadline_ns == f->origin + UINT64_C(10000000));
    }
    return true;
}

static bool bounded_nodes(fixture_t *f) {
    for (size_t i = 0; i < 3; ++i) {
        vireo_timer_handle_t timer = {0};
        CHECK(vireo_timer_wheel_register(f->wheel, f->origin, f->origin + 1, &timer) == VIREO_OK);
    }
    for (size_t i = 0; i < 2; ++i) {
        call_io_t io = io_new();
        io.options.timeout_ms = 20;
        clock_probe_t clock = {
            .times = {f->origin + UINT64_C(10000000), f->origin + UINT64_C(10000000)}};
        CHECK(call(f, &io, (vireo_timer_wheel_advance_budget_t){1, 1}, &clock) == VIREO_OK);
        CHECK(errno == EDOM && io.report.wait_plan.timeout_ms == 0 &&
              io.report.wait_plan.timer_work_pending && io.report.advance.nodes_examined == 1 &&
              io.report.advance.progress.ready_count == i + 1 &&
              !io.report.advance.progress.caught_up);
        CHECK(io.report.advance.ticks_started == (i == 0 ? 1 : 0));
        vireo_timer_wheel_registry_info_t registry;
        CHECK(vireo_timer_wheel_registry_inspect(f->wheel, &registry) == VIREO_OK &&
              registry.active_count == 3);
    }
    return true;
}

static bool bounded_ticks(fixture_t *f) {
    call_io_t io = io_new();
    io.options.timeout_ms = 20;
    clock_probe_t clock = {
        .times = {f->origin + UINT64_C(100000000), f->origin + UINT64_C(100000000)}};
    CHECK(call(f, &io, (vireo_timer_wheel_advance_budget_t){1, 1}, &clock) == VIREO_OK);
    CHECK(errno == EDOM && io.report.wait_plan.timer_work_pending &&
          io.report.wait_plan.timeout_ms == 0 && io.report.advance.ticks_started == 1 &&
          !io.report.advance.progress.caught_up && io.report.serve_completed);
    return true;
}

static bool late_clock_keeps_clients(fixture_t *f) {
    CHECK(peer_open(f, 0) && peer_open(f, 1));
    call_io_t io = io_new();
    io.options.timeout_ms = 20;
    clock_probe_t clock = {
        .times = {f->origin, 0}, .results = {VIREO_OK, VIREO_RESULT_IO}, .errors = {0, EACCES}};
    vireo_timer_wheel_progress_t before, after;
    CHECK(vireo_timer_wheel_progress_inspect(f->wheel, &before) == VIREO_OK);
    CHECK(call(f, &io, (vireo_timer_wheel_advance_budget_t){1, 1}, &clock) == VIREO_RESULT_IO);
    CHECK(errno == EDOM && clock.calls == 2 &&
          io.report.stage == VIREO_CLIENT_DEADLINE_SERVE_CLOCK_AFTER && io.report.serve_called &&
          io.report.serve_completed && io.report.serve_info.admission.admitted_count == 2 &&
          io.report.serve_info.initialized_count == 2 &&
          io.report.clock_error.system_errno == EACCES);
    for (size_t i = 0; i < 2; ++i) {
        vireo_tcp_server_client_info_t client;
        CHECK(vireo_tcp_server_client_inspect(f->server, io.clients[i], &client) == VIREO_OK);
    }
    vireo_tcp_server_info_t server;
    CHECK(vireo_tcp_server_inspect(f->server, &server) == VIREO_OK && server.connection_count == 2);
    CHECK(vireo_timer_wheel_progress_inspect(f->wheel, &after) == VIREO_OK &&
          after.latest_now_ns == before.latest_now_ns &&
          after.completed_tick == before.completed_tick && io.report.after_now_ns == 0 &&
          io.report.advance.ticks_started == 0);
    return true;
}

static bool late_advance_range(fixture_t *f) {
    CHECK(peer_open(f, 0));
    call_io_t io = io_new();
    io.options.timeout_ms = 20;
    clock_probe_t clock = {.times = {f->origin, f->origin - 1}};
    CHECK(call(f, &io, (vireo_timer_wheel_advance_budget_t){1, 1}, &clock) == VIREO_RESULT_RANGE);
    CHECK(errno == EDOM && clock.calls == 2 &&
          io.report.stage == VIREO_CLIENT_DEADLINE_SERVE_ADVANCE && io.report.serve_completed &&
          io.report.serve_info.admission.admitted_count == 1 &&
          io.report.after_now_ns == f->origin - 1 && io.report.advance.ticks_started == 0);
    vireo_tcp_server_client_info_t client;
    CHECK(vireo_tcp_server_client_inspect(f->server, io.clients[0], &client) == VIREO_OK);
    vireo_timer_wheel_progress_t progress;
    CHECK(vireo_timer_wheel_progress_inspect(f->wheel, &progress) == VIREO_OK &&
          progress.latest_now_ns == f->origin);
    return true;
}

static bool real_native_round(fixture_t *f) {
    CHECK(admit_client(f));
    uint64_t now;
    CHECK(vireo_clock_monotonic_now(&now, NULL) == VIREO_OK);
    vireo_timer_handle_t timer = {0};
    CHECK(vireo_timer_wheel_register(f->wheel, now, now + UINT64_C(1000000), &timer) == VIREO_OK);
    for (size_t i = 0; i < 256; ++i) {
        call_io_t io = io_new();
        io.options.timeout_ms = 20;
        CHECK(call(f, &io, (vireo_timer_wheel_advance_budget_t){16, 16}, NULL) == VIREO_OK);
        CHECK(errno == EDOM && io.report.before_now_ns >= now &&
              io.report.after_now_ns >= io.report.before_now_ns &&
              io.report.stage == VIREO_CLIENT_DEADLINE_SERVE_NONE && io.report.serve_completed);
        if (io.report.advance.progress.ready_count != 0) {
            vireo_timer_wheel_timer_info_t info;
            CHECK(vireo_timer_wheel_get(f->wheel, timer, &info) == VIREO_OK); /* 未自动领取。 */
            vireo_timer_wheel_expired_t expired;
            CHECK(vireo_timer_wheel_take_expired(f->wheel, &expired) == VIREO_OK &&
                  expired.handle.owner_id == timer.owner_id);
            CHECK(vireo_timer_wheel_get(f->wheel, timer, &info) == VIREO_RESULT_NOT_FOUND);
            return true;
        }
    }
    CHECK(false);
    return false;
}

static bool handler_failure(fixture_t *f) {
    CHECK(admit_client(f) && request_send(f));
    f->handler_result = VIREO_RESULT_PROTOCOL;
    clock_probe_t clock = {
        .times = {f->origin + UINT64_C(1000000000), f->origin + UINT64_C(1000000000)}};
    call_io_t io = io_new();
    CHECK(call(f, &io, (vireo_timer_wheel_advance_budget_t){1, 1}, &clock) ==
          VIREO_RESULT_PROTOCOL);
    CHECK(errno == EDOM && clock.calls == 1 && f->handler_calls == 1 && io.report.serve_called &&
          !io.report.serve_completed && io.report.stage == VIREO_CLIENT_DEADLINE_SERVE_SERVICE);
    CHECK(io.report.serve_error.stage == VIREO_TCP_SERVER_SERVE_ROUND &&
          io.report.serve_info.round.turn_count == 1 &&
          io.report.serve_info.round.failed_count == 1);
    vireo_tcp_server_client_info_t client;
    CHECK(vireo_tcp_server_client_inspect(f->server, f->client, &client) == VIREO_OK &&
          client.connection_info.read_buffer.readable_size == 32 &&
          client.connection_info.close_state == VIREO_CONNECTION_CLOSE_OPEN);
    CHECK(io.report.after_now_ns == 0 && io.report.advance.ticks_started == 0);
    return true;
}

static bool handler_stops_wheel(fixture_t *f) {
    CHECK(admit_client(f) && request_send(f));
    f->stop_wheel = true;
    call_io_t io = io_new();
    io.options.timeout_ms = 20;
    CHECK(call(f, &io, (vireo_timer_wheel_advance_budget_t){1, 1}, NULL) == VIREO_RESULT_CANCELLED);
    CHECK(errno == EDOM && f->handler_calls == 1 && io.report.serve_completed &&
          io.report.stage == VIREO_CLIENT_DEADLINE_SERVE_ADVANCE &&
          io.report.serve_info.round.turn_count == 1);
    vireo_timer_wheel_shutdown_info_t stopped;
    CHECK(vireo_timer_wheel_shutdown_inspect(f->wheel, &stopped) == VIREO_OK && stopped.stopping);
    return true;
}

static bool stopped_server_advances(fixture_t *f) {
    CHECK(admit_client(f));
    CHECK(vireo_tcp_server_request_stop(f->server, NULL) == VIREO_OK);
    call_io_t io = io_new(), old = io;
    clock_probe_t clock = {
        .times = {f->origin + UINT64_C(1000000000), f->origin + UINT64_C(1000000000)}};
    CHECK(call(f, &io, (vireo_timer_wheel_advance_budget_t){1, 1}, &clock) == VIREO_OK);
    CHECK(errno == EDOM && clock.calls == 2 && io.report.serve_completed &&
          io.report.serve_info.round.turn_count == 0 && io.report.advance.ticks_started == 1 &&
          io.report.advance.progress.latest_now_ns == clock.times[1]);
    CHECK(memcmp(io.workspace, old.workspace, sizeof io.workspace) == 0 &&
          memcmp(io.turns, old.turns, sizeof io.turns) == 0);
    vireo_tcp_server_info_t server;
    CHECK(vireo_tcp_server_inspect(f->server, &server) == VIREO_OK && server.connection_count == 1);
    return true;
}

static bool auto_modes_retained(fixture_t *f) {
    CHECK(admit_client(f));
    CHECK(vireo_tcp_server_set_auto_release_ready(f->server, true, NULL) == VIREO_OK);
    CHECK(vireo_tcp_server_set_auto_close_policy(f->server, true, NULL) == VIREO_OK);
    CHECK(vireo_tcp_server_client_request_close(
              f->server, f->client, VIREO_CONNECTION_CLOSE_MODE_IMMEDIATE,
              VIREO_CONNECTION_CLOSE_REASON_APPLICATION, NULL) == VIREO_OK);
    CHECK(vireo_tcp_server_schedule_client(f->server, f->client, NULL) == VIREO_OK);
    call_io_t io = io_new();
    CHECK(call(f, &io, (vireo_timer_wheel_advance_budget_t){1, 1}, NULL) == VIREO_OK);
    CHECK(errno == EDOM && io.report.serve_completed &&
          io.report.serve_info.round.turn_count == 1 && io.turns[0].released &&
          io.turns[0].release_attempted);
    vireo_tcp_server_info_t server;
    CHECK(vireo_tcp_server_inspect(f->server, &server) == VIREO_OK &&
          server.connection_count == 0 && server.auto_release_ready && server.auto_close_policy);
    return true;
}

/** 场景入口表，不属于产品数据模型。 */
typedef struct test_case {
    char const *name;         /**< 静态标签，仅用于报告。 */
    bool (*run)(fixture_t *); /**< 同步场景入口，不保存 fixture。 */
} test_case_t;

int main(void) {
    test_case_t const cases[] = {
        {"required NULL inputs and array preservation", basic_nulls},
        {"finite cap and explicit budget rejection", basic_budgets},
        {"unprepared wheel rejects before sampling", unprepared},
        {"stopped wheel priority and no sampling", stopped_wheel},
        {"simulated first clock failure has no admission", before_clock_failure},
        {"planner rejects before origin and prior advance", plan_time_range},
        {"delegated server validation follows first sample", service_validation},
        {"zero and MAX finite times with INT_MAX empty cap", empty_caps_and_extremes},
        {"active boundary ceiling and cap retain options", active_ceil_caps},
        {"node budget leaves ready identities unconsumed", bounded_nodes},
        {"tick debt gets one finite service opportunity", bounded_ticks},
        {"late simulated clock failure retains two owned clients", late_clock_keeps_clients},
        {"late synthetic time range keeps admitted client", late_advance_range},
        {"real CLOCK_MONOTONIC and TCP deadline discovery", real_native_round},
        {"real handler failure publishes service prefix", handler_failure},
        {"handler stops wheel and late advance reports cancellation", handler_stops_wheel},
        {"stopped server still advances independent wheel", stopped_server_advances},
        {"original explicit automatic modes stay effective", auto_modes_retained}};
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
    printf("18 groups, %zu failed\n", failed);
    return failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
