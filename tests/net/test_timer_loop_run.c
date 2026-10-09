/*
 * PROJECT : VIREO
 * FILE    : test_timer_loop_run.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-09
 * BRIEF   : 此模块负责：
 * -- 本层可控依赖验证调用顺序、预算和晚失败
 * -- 真实公开 clock/loop/wheel 及非阻塞 socketpair 组合验证
 */
#include "net/timer_loop_internal.h"
#include <vireo/timer/wheel_shutdown.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #condition); \
        return 1; \
    } \
} while (0)
#define EXPECT(expression, expected) do { \
    errno = EDOM; \
    CHECK((expression) == (expected)); \
    CHECK(errno == EDOM); \
} while (0)

/** 测试拥有两个独立对象，所有公开资源必须在测试结束后成对销毁。 */
typedef struct fixture {
    vireo_event_loop_t *loop; /**< 测试唯一拥有，适配层只短借。 */
    vireo_timer_wheel_t *wheel; /**< 测试唯一拥有，固定两个登记槽。 */
} fixture_t;

/** 只在模拟 loop 成功路径执行的公开轮动作，不伪装真实网络回调。 */
typedef enum late_action {
    ACTION_NONE = 0,
    ACTION_STOP_WHEEL,
    ACTION_ADVANCE_FUTURE
} late_action_t;

/** 本层依赖注入栈状态；两采样固定期望与 CLC 调用轨迹独立于实现。 */
typedef struct fake_state {
    vireo_monotonic_ns_t now[2]; /**< 两次成功采样的显式测试值，非真实运行证据。 */
    vireo_result_t clock_result[2]; /**< 每次采样的结果，由场景设置。 */
    vireo_clock_error_t clock_error[2]; /**< 每次采样完整原诊断。 */
    vireo_result_t loop_result; /**< 一次模拟网络入口结果。 */
    vireo_event_loop_error_t loop_error; /**< 模拟网络入口的完整原诊断。 */
    size_t clock_calls; /**< 实际采样调用计数，超过两次即异常。 */
    size_t loop_calls; /**< 模拟或真实桥接的 loop 调用计数。 */
    int timeout_seen; /**< 实际收到的毫秒等待，不是预期值。 */
    char trace[4]; /**< C、L、C 及结尾零，不存内部指针。 */
    size_t trace_count; /**< 已记录调用数，最多三。 */
    vireo_timer_wheel_t *wheel; /**< 模拟成功动作使用的短借轮，fixture 拥有。 */
    late_action_t action; /**< 模拟网络成功之后的公开轮动作。 */
    vireo_result_t action_result; /**< 该公开动作实际结果。 */
} fake_state_t;

/** 真实网络回调的栈上下文，不是产品业务 payload。 */
typedef struct network_probe {
    size_t calls; /**< 实际读取一个字节的回调次数。 */
    bool failed; /**< 回调读取/事件形态检查是否失败。 */
    bool stop_wheel; /**< 当前场景是否在真实回调中停止轮。 */
    vireo_timer_wheel_t *wheel; /**< fixture 拥有，注册期间短借，不销毁。 */
    vireo_result_t stop_result; /**< 真实 shutdown_begin 的结果。 */
} network_probe_t;

static vireo_timer_loop_run_options_t options(void)
{
    return (vireo_timer_loop_run_options_t){
        .max_wait_ms = 9, .advance_budget = { .max_ticks = 1, .max_nodes = 1 }
    };
}

static int setup(fixture_t *f, vireo_monotonic_ns_t origin,
                 vireo_duration_ns_t tick, bool prepare)
{
    vireo_event_loop_options_t loop_options = {
        .event_capacity = 4, .max_memory_bytes = VIREO_EVENT_LOOP_MAX_MEMORY,
        .registration_capacity = 2
    };
    vireo_timer_wheel_options_t wheel_options = {
        .geometry = { .origin_ns = origin, .tick_ns = tick, .bucket_count = 4 },
        .max_memory_bytes = VIREO_TIMER_WHEEL_MAX_MEMORY
    };
    vireo_timer_wheel_registry_options_t registry = {
        .capacity = 2, .max_memory_bytes = VIREO_TIMER_WHEEL_REGISTRY_MAX_MEMORY
    };
    EXPECT(vireo_event_loop_create(&loop_options, &f->loop, NULL), VIREO_OK);
    EXPECT(vireo_timer_wheel_create(&wheel_options, &f->wheel), VIREO_OK);
    if (prepare) {
        EXPECT(vireo_timer_wheel_prepare(f->wheel, &registry), VIREO_OK);
    }
    return 0;
}

static int cleanup(fixture_t *f, bool prepared)
{
    if (prepared) {
        EXPECT(vireo_timer_wheel_shutdown_begin(f->wheel), VIREO_OK);
        vireo_timer_wheel_shutdown_report_t report;
        for (size_t step = 0; step < 3; ++step) {
            EXPECT(vireo_timer_wheel_shutdown_step(f->wheel, 2, &report), VIREO_OK);
            if (report.finished) {
                break;
            }
        }
        CHECK(report.finished);
    }
    EXPECT(vireo_timer_wheel_destroy(&f->wheel), VIREO_OK);
    EXPECT(vireo_event_loop_destroy(&f->loop, NULL), VIREO_OK);
    return 0;
}

static fake_state_t state_for(fixture_t const *f)
{
    fake_state_t state = {0};
    state.now[0] = 101;
    state.now[1] = 135;
    state.timeout_seen = -2;
    state.wheel = f->wheel;
    return state;
}

static void trace(fake_state_t *s, char value)
{
    if (s->trace_count < sizeof(s->trace) - 1) {
        s->trace[s->trace_count++] = value;
    }
}

static vireo_result_t fake_now(vireo_monotonic_ns_t *out_now,
                               vireo_clock_error_t *out_error, void *context)
{
    fake_state_t *s = context;
    size_t const call = s->clock_calls++;
    trace(s, 'C');
    errno = EILSEQ;
    if (call >= 2) {
        *out_error = (vireo_clock_error_t){VIREO_CLOCK_STAGE_READ, 0};
        return VIREO_RESULT_INTERNAL;
    }
    *out_error = s->clock_error[call];
    if (s->clock_result[call] == VIREO_OK) {
        *out_now = s->now[call];
    }
    return s->clock_result[call];
}

static vireo_result_t fake_loop(vireo_event_loop_t *loop, int timeout_ms,
                                vireo_event_loop_run_info_t *out_info,
                                vireo_event_loop_error_t *out_error, void *context)
{
    (void)loop;
    fake_state_t *s = context;
    s->loop_calls++;
    s->timeout_seen = timeout_ms;
    trace(s, 'L');
    *out_error = s->loop_error;
    if (s->loop_result == VIREO_OK) {
        *out_info = (vireo_event_loop_run_info_t){3, 1, 1, 1};
        if (s->action == ACTION_STOP_WHEEL) {
            s->action_result = vireo_timer_wheel_shutdown_begin(s->wheel);
        } else if (s->action == ACTION_ADVANCE_FUTURE) {
            vireo_timer_wheel_advance_report_t report;
            s->action_result = vireo_timer_wheel_advance(s->wheel, 140,
                (vireo_timer_wheel_advance_budget_t){1, 1}, &report);
        }
    }
    errno = EILSEQ;
    return s->loop_result;
}

static vireo_result_t real_loop_bridge(vireo_event_loop_t *loop, int timeout_ms,
                                       vireo_event_loop_run_info_t *out_info,
                                       vireo_event_loop_error_t *out_error, void *context)
{
    fake_state_t *s = context;
    s->loop_calls++;
    s->timeout_seen = timeout_ms;
    trace(s, 'L');
    return vireo_event_loop_run_once(loop, timeout_ms, out_info, out_error);
}

static vireo_timer_loop_runtime_t runtime_for(fake_state_t *state)
{
    return (vireo_timer_loop_runtime_t){fake_now, fake_loop, state};
}

static bool no_errors(vireo_timer_loop_diagnostic_t const *d)
{
    return d->clock_error.stage == VIREO_CLOCK_STAGE_NONE && d->clock_error.system_errno == 0 &&
           d->loop_error.stage == VIREO_EVENT_LOOP_STAGE_NONE &&
           d->loop_error.epoll_error.stage == VIREO_EPOLL_STAGE_NONE &&
           d->loop_error.epoll_error.system_errno == 0 && d->loop_error.system_errno == 0;
}

static int failure(fixture_t *f, vireo_timer_loop_run_options_t const *o,
                    vireo_timer_loop_runtime_t const *runtime, vireo_result_t expected,
                    vireo_timer_loop_stage_t stage, bool completed,
                    vireo_timer_loop_diagnostic_t *out_diagnostic)
{
    vireo_timer_loop_run_report_t report;
    unsigned char before[sizeof(report)];
    memset(&report, 0xa5, sizeof(report));
    memcpy(before, &report, sizeof(report));
    memset(out_diagnostic, 0xa5, sizeof(*out_diagnostic));
    EXPECT(vireo_timer_loop_run_once_runtime(f->loop, f->wheel, o, &report,
           out_diagnostic, runtime), expected);
    CHECK(memcmp(before, &report, sizeof(report)) == 0);
    CHECK(out_diagnostic->stage == stage && out_diagnostic->loop_completed == completed);
    return 0;
}

static int test_arguments(void)
{
    fixture_t f = {0};
    CHECK(setup(&f, 100, 10, true) == 0);
    fake_state_t s = state_for(&f);
    vireo_timer_loop_runtime_t runtime = runtime_for(&s);
    vireo_timer_loop_run_options_t o = options();
    vireo_timer_loop_diagnostic_t d;
    vireo_timer_loop_run_report_t report;
    EXPECT(vireo_timer_loop_run_once_runtime(NULL, f.wheel, &o, &report, &d, &runtime),
           VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_timer_loop_run_once_runtime(f.loop, NULL, &o, &report, &d, &runtime),
           VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_timer_loop_run_once_runtime(f.loop, f.wheel, NULL, &report, &d, &runtime),
           VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_timer_loop_run_once_runtime(f.loop, f.wheel, &o, NULL, &d, &runtime),
           VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(d.stage == VIREO_TIMER_LOOP_STAGE_NONE && !d.loop_completed && no_errors(&d));
    CHECK(failure(&f, &o, NULL, VIREO_RESULT_INVALID_ARGUMENT,
                  VIREO_TIMER_LOOP_STAGE_NONE, false, &d) == 0);
    runtime.monotonic_now = NULL;
    CHECK(failure(&f, &o, &runtime, VIREO_RESULT_INVALID_ARGUMENT,
                  VIREO_TIMER_LOOP_STAGE_NONE, false, &d) == 0);
    runtime = runtime_for(&s);
    runtime.run_loop = NULL;
    CHECK(failure(&f, &o, &runtime, VIREO_RESULT_INVALID_ARGUMENT,
                  VIREO_TIMER_LOOP_STAGE_NONE, false, &d) == 0);
    CHECK(s.clock_calls == 0 && s.loop_calls == 0);
    EXPECT(vireo_timer_loop_run_once(NULL, f.wheel, &o, &report, NULL),
           VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(cleanup(&f, true) == 0);
    return 0;
}

static int test_budgets(void)
{
    fixture_t f = {0};
    CHECK(setup(&f, 100, 10, true) == 0);
    fake_state_t s = state_for(&f);
    vireo_timer_loop_runtime_t runtime = runtime_for(&s);
    vireo_timer_loop_run_options_t o = options();
    vireo_timer_loop_diagnostic_t d;
    o.max_wait_ms = -1;
    CHECK(failure(&f, &o, &runtime, VIREO_RESULT_INVALID_ARGUMENT,
                  VIREO_TIMER_LOOP_STAGE_NONE, false, &d) == 0);
    o = options(); o.advance_budget.max_ticks = 0;
    CHECK(failure(&f, &o, &runtime, VIREO_RESULT_INVALID_ARGUMENT,
                  VIREO_TIMER_LOOP_STAGE_NONE, false, &d) == 0);
    o = options(); o.advance_budget.max_nodes = 0;
    CHECK(failure(&f, &o, &runtime, VIREO_RESULT_INVALID_ARGUMENT,
                  VIREO_TIMER_LOOP_STAGE_NONE, false, &d) == 0);
    o = options(); o.advance_budget.max_ticks = 65537;
    CHECK(failure(&f, &o, &runtime, VIREO_RESULT_RANGE,
                  VIREO_TIMER_LOOP_STAGE_NONE, false, &d) == 0);
    o = options(); o.advance_budget.max_nodes = SIZE_MAX;
    CHECK(failure(&f, &o, &runtime, VIREO_RESULT_RANGE,
                  VIREO_TIMER_LOOP_STAGE_NONE, false, &d) == 0);
    CHECK(no_errors(&d) && s.clock_calls == 0 && s.loop_calls == 0);
    CHECK(cleanup(&f, true) == 0);
    return 0;
}

static int test_preflight(void)
{
    fixture_t f = {0};
    CHECK(setup(&f, 100, 10, false) == 0);
    fake_state_t s = state_for(&f);
    vireo_timer_loop_runtime_t runtime = runtime_for(&s);
    vireo_timer_loop_run_options_t o = options();
    vireo_timer_loop_diagnostic_t d;
    CHECK(failure(&f, &o, &runtime, VIREO_RESULT_NOT_FOUND,
                  VIREO_TIMER_LOOP_STAGE_CHECK_WHEEL, false, &d) == 0);
    CHECK(no_errors(&d) && s.clock_calls == 0 && s.loop_calls == 0);
    CHECK(cleanup(&f, false) == 0);
    f = (fixture_t){0};
    CHECK(setup(&f, 100, 10, true) == 0);
    s = state_for(&f); runtime = runtime_for(&s);
    EXPECT(vireo_timer_wheel_shutdown_begin(f.wheel), VIREO_OK);
    CHECK(failure(&f, &o, &runtime, VIREO_RESULT_CANCELLED,
                  VIREO_TIMER_LOOP_STAGE_CHECK_WHEEL, false, &d) == 0);
    o.advance_budget.max_nodes = 0;
    CHECK(failure(&f, &o, &runtime, VIREO_RESULT_INVALID_ARGUMENT,
                  VIREO_TIMER_LOOP_STAGE_NONE, false, &d) == 0);
    CHECK(no_errors(&d) && s.clock_calls == 0 && s.loop_calls == 0);
    CHECK(cleanup(&f, true) == 0);
    return 0;
}

static int test_clock_before(void)
{
    vireo_result_t const results[] = {VIREO_RESULT_IO, VIREO_RESULT_OVERFLOW, VIREO_RESULT_INTERNAL};
    for (size_t i = 0; i < 3; ++i) {
        fixture_t f = {0};
        CHECK(setup(&f, 100, 10, true) == 0);
        fake_state_t s = state_for(&f);
        s.clock_result[0] = results[i];
        s.clock_error[0] = (vireo_clock_error_t){
            i == 0 ? VIREO_CLOCK_STAGE_READ : VIREO_CLOCK_STAGE_CONVERT,
            i == 0 ? EACCES : 0
        };
        vireo_timer_loop_runtime_t runtime = runtime_for(&s);
        vireo_timer_loop_run_options_t o = options();
        vireo_timer_loop_diagnostic_t d;
        CHECK(failure(&f, &o, &runtime, results[i],
                      VIREO_TIMER_LOOP_STAGE_CLOCK_BEFORE, false, &d) == 0);
        CHECK(d.clock_error.stage == s.clock_error[0].stage &&
              d.clock_error.system_errno == s.clock_error[0].system_errno);
        CHECK(s.clock_calls == 1 && s.loop_calls == 0 && strcmp(s.trace, "C") == 0);
        CHECK(cleanup(&f, true) == 0);
    }
    return 0;
}

static int test_plan_failure(void)
{
    fixture_t f = {0};
    CHECK(setup(&f, 100, 10, true) == 0);
    fake_state_t s = state_for(&f); s.now[0] = 99;
    vireo_timer_loop_runtime_t runtime = runtime_for(&s);
    vireo_timer_loop_run_options_t o = options();
    vireo_timer_loop_diagnostic_t d;
    CHECK(failure(&f, &o, &runtime, VIREO_RESULT_RANGE,
                  VIREO_TIMER_LOOP_STAGE_PLAN_WAIT, false, &d) == 0);
    CHECK(no_errors(&d) && s.clock_calls == 1 && s.loop_calls == 0);
    CHECK(cleanup(&f, true) == 0);
    return 0;
}

static int test_loop_failures(void)
{
    vireo_result_t const results[] = {VIREO_RESULT_BUSY, VIREO_RESULT_IO, VIREO_RESULT_INTERNAL};
    for (size_t i = 0; i < 3; ++i) {
        fixture_t f = {0};
        CHECK(setup(&f, 100, 10, true) == 0);
        fake_state_t s = state_for(&f); s.loop_result = results[i];
        if (i == 1) {
            s.loop_error.stage = VIREO_EVENT_LOOP_STAGE_WAIT;
            s.loop_error.epoll_error = (vireo_epoll_error_t){VIREO_EPOLL_STAGE_WAIT, EINTR};
        } else if (i == 2) {
            s.loop_error.stage = VIREO_EVENT_LOOP_STAGE_WAKE_READ;
            s.loop_error.system_errno = 0;
        }
        vireo_timer_loop_runtime_t runtime = runtime_for(&s);
        vireo_timer_loop_run_options_t o = options();
        vireo_timer_loop_diagnostic_t d;
        CHECK(failure(&f, &o, &runtime, results[i],
                      VIREO_TIMER_LOOP_STAGE_RUN_LOOP, false, &d) == 0);
        CHECK(d.loop_error.stage == s.loop_error.stage &&
              d.loop_error.epoll_error.stage == s.loop_error.epoll_error.stage &&
              d.loop_error.epoll_error.system_errno == s.loop_error.epoll_error.system_errno &&
              d.loop_error.system_errno == s.loop_error.system_errno);
        CHECK(s.clock_calls == 1 && s.loop_calls == 1 && strcmp(s.trace, "CL") == 0);
        vireo_timer_wheel_progress_t progress;
        EXPECT(vireo_timer_wheel_progress_inspect(f.wheel, &progress), VIREO_OK);
        CHECK(progress.latest_now_ns == 100 && progress.completed_tick == 0);
        CHECK(cleanup(&f, true) == 0);
    }
    return 0;
}

static int test_clock_after(void)
{
    fixture_t f = {0};
    CHECK(setup(&f, 100, 10, true) == 0);
    fake_state_t s = state_for(&f);
    s.clock_result[1] = VIREO_RESULT_IO;
    s.clock_error[1] = (vireo_clock_error_t){VIREO_CLOCK_STAGE_READ, EIO};
    vireo_timer_loop_runtime_t runtime = runtime_for(&s);
    vireo_timer_loop_run_options_t o = options();
    vireo_timer_loop_diagnostic_t d;
    CHECK(failure(&f, &o, &runtime, VIREO_RESULT_IO,
                  VIREO_TIMER_LOOP_STAGE_CLOCK_AFTER, true, &d) == 0);
    CHECK(d.clock_error.stage == VIREO_CLOCK_STAGE_READ && d.clock_error.system_errno == EIO);
    CHECK(s.clock_calls == 2 && s.loop_calls == 1 && strcmp(s.trace, "CLC") == 0);
    vireo_timer_wheel_progress_t progress;
    EXPECT(vireo_timer_wheel_progress_inspect(f.wheel, &progress), VIREO_OK);
    CHECK(progress.latest_now_ns == 100 && progress.completed_tick == 0);
    /* 可空诊断不改变晚失败处理，也不能发布半份主报告。 */
    s = state_for(&f);
    s.clock_result[1] = VIREO_RESULT_IO;
    s.clock_error[1] = (vireo_clock_error_t){VIREO_CLOCK_STAGE_READ, EIO};
    runtime = runtime_for(&s);
    vireo_timer_loop_run_report_t report;
    unsigned char before[sizeof(report)];
    memset(&report, 0xa5, sizeof(report)); memcpy(before, &report, sizeof(report));
    EXPECT(vireo_timer_loop_run_once_runtime(f.loop, f.wheel, &o, &report, NULL, &runtime),
           VIREO_RESULT_IO);
    CHECK(memcmp(before, &report, sizeof(report)) == 0 && s.clock_calls == 2 && s.loop_calls == 1);
    CHECK(cleanup(&f, true) == 0);
    return 0;
}

static int test_advance_failures(void)
{
    late_action_t const actions[] = {ACTION_STOP_WHEEL, ACTION_ADVANCE_FUTURE};
    for (size_t i = 0; i < 2; ++i) {
        fixture_t f = {0};
        CHECK(setup(&f, 100, 10, true) == 0);
        fake_state_t s = state_for(&f); s.action = actions[i];
        vireo_timer_loop_runtime_t runtime = runtime_for(&s);
        vireo_timer_loop_run_options_t o = options();
        vireo_timer_loop_diagnostic_t d;
        CHECK(failure(&f, &o, &runtime, i == 0 ? VIREO_RESULT_CANCELLED : VIREO_RESULT_RANGE,
                      VIREO_TIMER_LOOP_STAGE_ADVANCE, true, &d) == 0);
        CHECK(no_errors(&d) && s.action_result == VIREO_OK);
        CHECK(s.clock_calls == 2 && s.loop_calls == 1 && strcmp(s.trace, "CLC") == 0);
        vireo_timer_wheel_progress_t progress;
        EXPECT(vireo_timer_wheel_progress_inspect(f.wheel, &progress), VIREO_OK);
        CHECK(progress.latest_now_ns == (i == 0 ? 100 : 140));
        CHECK(cleanup(&f, true) == 0);
    }
    return 0;
}

static int test_order_and_budget(void)
{
    fixture_t f = {0};
    CHECK(setup(&f, 100, 10, true) == 0);
    vireo_timer_handle_t handle = {0};
    EXPECT(vireo_timer_wheel_register(f.wheel, 100, 200, &handle), VIREO_OK);
    fake_state_t s = state_for(&f);
    vireo_timer_loop_runtime_t runtime = runtime_for(&s);
    vireo_timer_loop_run_options_t o = options();
    vireo_timer_loop_diagnostic_t d;
    vireo_timer_loop_run_report_t report;
    memset(&d, 0xa5, sizeof(d));
    EXPECT(vireo_timer_loop_run_once_runtime(f.loop, f.wheel, &o, &report, &d, &runtime), VIREO_OK);
    CHECK(d.stage == VIREO_TIMER_LOOP_STAGE_NONE && d.loop_completed && no_errors(&d));
    CHECK(s.clock_calls == 2 && s.loop_calls == 1 && strcmp(s.trace, "CLC") == 0);
    CHECK(s.timeout_seen == 1 && report.wait_plan.timeout_ms == 1 &&
          report.wait_plan.has_tick_deadline && !report.wait_plan.timer_work_pending &&
          report.wait_plan.tick_deadline_ns == 110);
    CHECK(report.before_now_ns == 101 && report.after_now_ns == 135);
    CHECK(report.loop.ready_count == 3 && report.loop.dispatched_count == 1 &&
          report.loop.stale_count == 1 && report.loop.filtered_count == 1);
    CHECK(report.advance.ticks_started == 1 && report.advance.nodes_examined == 0 &&
          report.advance.progress.latest_now_ns == 135 && report.advance.progress.target_tick == 3 &&
          report.advance.progress.completed_tick == 1 && !report.advance.progress.caught_up);
    s = state_for(&f); s.now[0] = 135; runtime = runtime_for(&s);
    EXPECT(vireo_timer_loop_run_once_runtime(f.loop, f.wheel, &o, &report, NULL, &runtime), VIREO_OK);
    CHECK(s.timeout_seen == 0 && report.wait_plan.timer_work_pending &&
          report.advance.progress.completed_tick == 2);
    s = state_for(&f); s.now[0] = 135; runtime = runtime_for(&s);
    EXPECT(vireo_timer_loop_run_once_runtime(f.loop, f.wheel, &o, &report, NULL, &runtime), VIREO_OK);
    CHECK(s.timeout_seen == 0 && report.advance.progress.completed_tick == 3 &&
          report.advance.progress.caught_up);
    CHECK(cleanup(&f, true) == 0);
    return 0;
}

static int test_discovery_not_consumption(void)
{
    fixture_t f = {0};
    CHECK(setup(&f, 100, 10, true) == 0);
    vireo_timer_handle_t handle = {0}, second = {0};
    EXPECT(vireo_timer_wheel_register(f.wheel, 100, 110, &handle), VIREO_OK);
    EXPECT(vireo_timer_wheel_register(f.wheel, 100, 110, &second), VIREO_OK);
    fake_state_t s = state_for(&f);
    vireo_timer_loop_runtime_t runtime = runtime_for(&s);
    vireo_timer_loop_run_options_t o = options();
    vireo_timer_loop_run_report_t report;
    EXPECT(vireo_timer_loop_run_once_runtime(f.loop, f.wheel, &o, &report, NULL, &runtime), VIREO_OK);
    CHECK(report.advance.progress.ready_count == 1 && report.advance.nodes_examined == 1 &&
          report.advance.progress.processing && report.advance.progress.completed_tick == 0);
    vireo_timer_wheel_timer_info_t timer;
    EXPECT(vireo_timer_wheel_get(f.wheel, handle, &timer), VIREO_OK);
    CHECK(timer.deadline_ns == 110);
    s = state_for(&f); s.now[0] = 135; runtime = runtime_for(&s);
    EXPECT(vireo_timer_loop_run_once_runtime(f.loop, f.wheel, &o, &report, NULL, &runtime), VIREO_OK);
    CHECK(s.timeout_seen == 0 && report.advance.progress.ready_count == 2 &&
          report.advance.nodes_examined == 1);
    vireo_timer_wheel_expired_t expired;
    EXPECT(vireo_timer_wheel_take_expired(f.wheel, &expired), VIREO_OK);
    bool const is_first = expired.handle.owner_id == handle.owner_id &&
        expired.handle.slot_index == handle.slot_index && expired.handle.generation == handle.generation;
    bool const is_second = expired.handle.owner_id == second.owner_id &&
        expired.handle.slot_index == second.slot_index && expired.handle.generation == second.generation;
    CHECK(is_first || is_second);
    vireo_timer_wheel_progress_t progress;
    EXPECT(vireo_timer_wheel_progress_inspect(f.wheel, &progress), VIREO_OK);
    CHECK(progress.ready_count == 1);
    CHECK(cleanup(&f, true) == 0);
    return 0;
}

static int test_numeric_caps(void)
{
    fixture_t f = {0};
    CHECK(setup(&f, 0, UINT64_MAX, true) == 0);
    vireo_timer_handle_t handle = {0};
    EXPECT(vireo_timer_wheel_register(f.wheel, 0, UINT64_MAX, &handle), VIREO_OK);
    vireo_timer_loop_run_options_t o = options();
    o.max_wait_ms = INT_MAX;
    fake_state_t s = state_for(&f); s.now[0] = 0; s.now[1] = 0;
    vireo_timer_loop_runtime_t runtime = runtime_for(&s);
    vireo_timer_loop_run_report_t report;
    EXPECT(vireo_timer_loop_run_once_runtime(f.loop, f.wheel, &o, &report, NULL, &runtime), VIREO_OK);
    CHECK(s.timeout_seen == INT_MAX && report.wait_plan.tick_deadline_ns == UINT64_MAX);
    s = state_for(&f); s.now[0] = 0; s.now[1] = 0; runtime = runtime_for(&s);
    o.max_wait_ms = 0; o.advance_budget.max_ticks = 65536; o.advance_budget.max_nodes = 65536;
    EXPECT(vireo_timer_loop_run_once_runtime(f.loop, f.wheel, &o, &report, NULL, &runtime), VIREO_OK);
    CHECK(s.timeout_seen == 0 && !report.wait_plan.timer_work_pending &&
          report.wait_plan.has_tick_deadline && report.advance.ticks_started == 0);
    CHECK(cleanup(&f, true) == 0);
    return 0;
}

static void read_one(vireo_event_loop_t *loop, vireo_event_loop_handle_t handle,
                      int fd, uint32_t events, void *context)
{
    (void)loop; (void)handle;
    network_probe_t *probe = context;
    unsigned char byte = 0;
    ssize_t const count = recv(fd, &byte, 1, MSG_DONTWAIT);
    if (count != 1 || byte != 'x' || (events & VIREO_EPOLL_EVENT_READ) == 0) {
        probe->failed = true;
    } else {
        probe->calls++;
    }
    if (probe->stop_wheel) {
        probe->stop_result = vireo_timer_wheel_shutdown_begin(probe->wheel);
    }
    errno = EILSEQ;
}

static int add_socket(fixture_t *f, network_probe_t *probe, int sockets[2],
                      vireo_event_loop_handle_t *out_handle)
{
    CHECK(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, sockets) == 0);
    vireo_event_loop_registration_t registration = {
        .fd = sockets[0], .interests = VIREO_EPOLL_INTEREST_READ,
        .callback = read_one, .context = probe
    };
    EXPECT(vireo_event_loop_add(f->loop, &registration, out_handle, NULL), VIREO_OK);
    CHECK(send(sockets[1], "x", 1, MSG_NOSIGNAL) == 1);
    return 0;
}

static int remove_socket(fixture_t *f, int sockets[2], vireo_event_loop_handle_t *handle)
{
    EXPECT(vireo_event_loop_del(f->loop, handle, NULL), VIREO_OK);
    CHECK(close(sockets[0]) == 0 && close(sockets[1]) == 0);
    return 0;
}

static int test_real_native(void)
{
    fixture_t f = {0};
    CHECK(setup(&f, 0, UINT64_MAX, true) == 0);
    vireo_timer_handle_t handle = {0};
    vireo_monotonic_ns_t seed;
    EXPECT(vireo_clock_monotonic_now(&seed, NULL), VIREO_OK);
    CHECK(seed < UINT64_MAX);
    EXPECT(vireo_timer_wheel_register(f.wheel, seed, UINT64_MAX, &handle), VIREO_OK);
    network_probe_t probe = { .wheel = f.wheel };
    int sockets[2];
    vireo_event_loop_handle_t registration = {0};
    CHECK(add_socket(&f, &probe, sockets, &registration) == 0);
    vireo_timer_loop_run_options_t o = options(); o.max_wait_ms = 0;
    vireo_timer_loop_run_report_t report;
    vireo_timer_loop_diagnostic_t d;
    EXPECT(vireo_timer_loop_run_once(f.loop, f.wheel, &o, &report, &d), VIREO_OK);
    CHECK(!probe.failed && probe.calls == 1 && report.loop.ready_count == 1 &&
          report.loop.dispatched_count == 1 && report.loop.stale_count == 0 &&
          report.loop.filtered_count == 0);
    CHECK(report.before_now_ns >= seed && report.after_now_ns >= report.before_now_ns &&
          report.advance.progress.latest_now_ns == report.after_now_ns &&
          report.advance.progress.completed_tick == 0 && report.advance.progress.caught_up);
    CHECK(report.wait_plan.timeout_ms == 0 && !report.wait_plan.timer_work_pending &&
          report.wait_plan.has_tick_deadline && report.wait_plan.tick_deadline_ns == UINT64_MAX);
    CHECK(d.stage == VIREO_TIMER_LOOP_STAGE_NONE && d.loop_completed && no_errors(&d));
    CHECK(remove_socket(&f, sockets, &registration) == 0);
    CHECK(cleanup(&f, true) == 0);
    return 0;
}

static int test_real_late_clock_failure(void)
{
    fixture_t f = {0};
    CHECK(setup(&f, 100, 10, true) == 0);
    network_probe_t probe = { .wheel = f.wheel };
    int sockets[2];
    vireo_event_loop_handle_t registration = {0};
    CHECK(add_socket(&f, &probe, sockets, &registration) == 0);
    fake_state_t s = state_for(&f);
    s.clock_result[1] = VIREO_RESULT_IO;
    s.clock_error[1] = (vireo_clock_error_t){VIREO_CLOCK_STAGE_READ, EIO};
    vireo_timer_loop_runtime_t runtime = runtime_for(&s); runtime.run_loop = real_loop_bridge;
    vireo_timer_loop_run_options_t o = options(); o.max_wait_ms = 0;
    vireo_timer_loop_diagnostic_t d;
    CHECK(failure(&f, &o, &runtime, VIREO_RESULT_IO,
                  VIREO_TIMER_LOOP_STAGE_CLOCK_AFTER, true, &d) == 0);
    CHECK(!probe.failed && probe.calls == 1 && s.loop_calls == 1 && s.clock_calls == 2);
    CHECK(d.clock_error.stage == VIREO_CLOCK_STAGE_READ && d.clock_error.system_errno == EIO);
    unsigned char byte;
    CHECK(recv(sockets[0], &byte, 1, MSG_DONTWAIT) == -1 &&
          (errno == EAGAIN || errno == EWOULDBLOCK));
    CHECK(remove_socket(&f, sockets, &registration) == 0);
    CHECK(cleanup(&f, true) == 0);
    return 0;
}

static int test_real_callback_stop(void)
{
    fixture_t f = {0};
    CHECK(setup(&f, 0, UINT64_MAX, true) == 0);
    network_probe_t probe = { .stop_wheel = true, .wheel = f.wheel };
    int sockets[2];
    vireo_event_loop_handle_t registration = {0};
    CHECK(add_socket(&f, &probe, sockets, &registration) == 0);
    vireo_timer_loop_run_options_t o = options(); o.max_wait_ms = 0;
    vireo_timer_loop_run_report_t report;
    unsigned char before[sizeof(report)];
    memset(&report, 0xa5, sizeof(report)); memcpy(before, &report, sizeof(report));
    vireo_timer_loop_diagnostic_t d;
    EXPECT(vireo_timer_loop_run_once(f.loop, f.wheel, &o, &report, &d), VIREO_RESULT_CANCELLED);
    CHECK(memcmp(before, &report, sizeof(report)) == 0 && !probe.failed && probe.calls == 1 &&
          probe.stop_result == VIREO_OK && d.stage == VIREO_TIMER_LOOP_STAGE_ADVANCE &&
          d.loop_completed && no_errors(&d));
    vireo_timer_wheel_shutdown_info_t stopped;
    EXPECT(vireo_timer_wheel_shutdown_inspect(f.wheel, &stopped), VIREO_OK);
    CHECK(stopped.stopping);
    CHECK(remove_socket(&f, sockets, &registration) == 0);
    CHECK(cleanup(&f, true) == 0);
    return 0;
}

static int test_stopped_loop_independent(void)
{
    fixture_t f = {0};
    CHECK(setup(&f, 0, UINT64_MAX, true) == 0);
    EXPECT(vireo_event_loop_request_stop(f.loop, NULL), VIREO_OK);
    vireo_timer_loop_run_options_t o = options(); o.max_wait_ms = INT_MAX;
    vireo_timer_loop_run_report_t report;
    vireo_timer_loop_diagnostic_t d;
    EXPECT(vireo_timer_loop_run_once(f.loop, f.wheel, &o, &report, &d), VIREO_OK);
    CHECK(report.loop.ready_count == 0 && report.loop.dispatched_count == 0 &&
          report.loop.stale_count == 0 && report.loop.filtered_count == 0);
    CHECK(report.wait_plan.timeout_ms == INT_MAX && report.after_now_ns >= report.before_now_ns &&
          report.advance.progress.latest_now_ns == report.after_now_ns && d.loop_completed);
    vireo_timer_wheel_shutdown_info_t info;
    EXPECT(vireo_timer_wheel_shutdown_inspect(f.wheel, &info), VIREO_OK);
    CHECK(!info.stopping && no_errors(&d));
    CHECK(cleanup(&f, true) == 0);
    return 0;
}

static int test_real_discovery_budget(void)
{
    fixture_t f = {0};
    vireo_monotonic_ns_t seed;
    EXPECT(vireo_clock_monotonic_now(&seed, NULL), VIREO_OK);
    CHECK(seed < UINT64_MAX);
    CHECK(setup(&f, seed, 1, true) == 0);
    vireo_timer_handle_t handle = {0};
    EXPECT(vireo_timer_wheel_register(f.wheel, seed, seed + 1, &handle), VIREO_OK);
    vireo_timer_loop_run_options_t o = options(); o.max_wait_ms = 0;
    vireo_timer_loop_run_report_t report;
    EXPECT(vireo_timer_loop_run_once(f.loop, f.wheel, &o, &report, NULL), VIREO_OK);
    /* 原时钟允许相邻采样相等；不以 sleep 或最低已逝时间制造确定性。 */
    bool const elapsed = report.after_now_ns > seed;
    CHECK(report.advance.ticks_started == (elapsed ? 1u : 0u) &&
          report.advance.nodes_examined == (elapsed ? 1u : 0u) &&
          report.advance.progress.completed_tick == (elapsed ? 1u : 0u) &&
          report.advance.progress.ready_count == (elapsed ? 1u : 0u));
    vireo_timer_wheel_timer_info_t timer;
    EXPECT(vireo_timer_wheel_get(f.wheel, handle, &timer), VIREO_OK);
    CHECK(timer.deadline_ns == seed + 1);
    printf("real clock discovery: elapsed=%d ticks=%zu nodes=%zu ready=%zu\n",
           elapsed ? 1 : 0, report.advance.ticks_started, report.advance.nodes_examined,
           report.advance.progress.ready_count);
    CHECK(cleanup(&f, true) == 0);
    return 0;
}

int main(void)
{
    int failures = 0;
    failures += test_arguments();
    failures += test_budgets();
    failures += test_preflight();
    failures += test_clock_before();
    failures += test_plan_failure();
    failures += test_loop_failures();
    failures += test_clock_after();
    failures += test_advance_failures();
    failures += test_order_and_budget();
    failures += test_discovery_not_consumption();
    failures += test_numeric_caps();
    failures += test_real_native();
    failures += test_real_late_clock_failure();
    failures += test_real_callback_stop();
    failures += test_stopped_loop_independent();
    failures += test_real_discovery_budget();
    printf("timer loop run: 16 groups, %d failures; unit seams and real public integrations distinguished\n", failures);
    return failures == 0 ? 0 : 1;
}
