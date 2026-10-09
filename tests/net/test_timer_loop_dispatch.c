/*
 * PROJECT : VIREO
 * FILE    : test_timer_loop_dispatch.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-09
 * BRIEF   : 此模块负责：
 * -- 验证预算、身份失效、回调修改与部分失败报告
 * -- 区分本层依赖故障注入和真实网络/轮/交付组合
 */
#include "net/timer_loop_dispatch_internal.h"
#include <vireo/net/timer_loop_run.h>
#include <vireo/timer/wheel_shutdown.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
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

/** 唯一拥有轮；回调只借用，不替测试释放。 */
typedef struct fixture {
    vireo_timer_wheel_t *wheel; /**< setup 创建、cleanup 最终销毁。 */
} fixture_t;

/** 回调只执行有限公开单项动作，不递归消费者。 */
typedef enum action {
    ACTION_NONE = 0, ACTION_CANCEL_OTHER, ACTION_REARM_OTHER,
    ACTION_REPLACE_READY, ACTION_STOP
} action_t;

/** 单次测试同步回调上下文，值记录不保存栈事件地址。 */
typedef struct delivery_probe {
    vireo_timer_wheel_t *wheel; /**< fixture 持有，整个消费短借。 */
    size_t calls; /**< 实际回调次数，无时间单位。 */
    size_t fail_at; /**< 指定此次回调失败；0 表示不失败。 */
    vireo_result_t failure; /**< 指定的回调错误，不是内核故障。 */
    vireo_timer_wheel_expired_t events[4]; /**< 只复制前四个历史值，非地址。 */
    bool invalid; /**< 历史身份或公开动作偏离测试合同。 */
    action_t action; /**< 单项修改策略；补充 ready 每次执行，其余只第一次。 */
    vireo_timer_handle_t other; /**< 待取消或重排的另一个活跃身份。 */
    vireo_timer_handle_t replacement; /**< 最后新登记身份，可能留给 cleanup。 */
    bool reused; /**< 同槽新代次确实与旧身份不同。 */
} delivery_probe_t;

/** own seam 只注入当前依赖失败，不伪造已经注销事件。 */
typedef struct fault_state {
    size_t inspect_calls; /**< 实际进度依赖调用次数。 */
    size_t take_calls; /**< 实际领取依赖调用次数。 */
    size_t fail_inspect_at; /**< 在哪一次观测失败，0 禁用。 */
    size_t fail_take_at; /**< 在哪一次领取失败，0 禁用。 */
    vireo_result_t failure; /**< 受控原错误码，失败不触碰轮或输出。 */
} fault_state_t;

/** 真实 socketpair 回调只非阻塞读取一个字节。 */
typedef struct network_probe {
    size_t calls; /**< 实际网络回调次数。 */
    bool invalid; /**< 事件或读到字节偏离预期。 */
} network_probe_t;

static bool same_handle(vireo_timer_handle_t a, vireo_timer_handle_t b)
{
    return a.owner_id == b.owner_id && a.slot_index == b.slot_index &&
           a.generation == b.generation;
}

/**
 * @brief 创建测试独占的固定四桶轮
 *
 * @param[in,out] f
 *     非空测试拥有者，入口 wheel 为 NULL。
 * @param[in] capacity
 *     正登记容量，测试取 1 至 65536。
 * @param[in] prepared
 *     是否立即 prepare。
 * @param[in] origin
 *     显式同域纳秒起点。
 *
 * @retval 0
 *     创建及所选准备成功，资源交给 fixture。
 * @retval 1
 *     公开合同断言失败，终止本场景。
 *
 * @note
 *     不保存 options 地址，不使用其他模块 private。
 */
static int setup(fixture_t *f, size_t capacity, bool prepared,
                 vireo_monotonic_ns_t origin)
{
    vireo_timer_wheel_options_t options = {
        .geometry = { .origin_ns = origin, .tick_ns = 1, .bucket_count = 4 },
        .max_memory_bytes = VIREO_TIMER_WHEEL_MAX_MEMORY
    };
    vireo_timer_wheel_registry_options_t registry = {
        .capacity = capacity, .max_memory_bytes = VIREO_TIMER_WHEEL_REGISTRY_MAX_MEMORY
    };
    EXPECT(vireo_timer_wheel_create(&options, &f->wheel), VIREO_OK);
    if (prepared) {
        EXPECT(vireo_timer_wheel_prepare(f->wheel, &registry), VIREO_OK);
    }
    return 0;
}

/**
 * @brief 显式停止、逐项注销并释放测试拥有的轮
 *
 * @param[in,out] f
 *     测试唯一拥有者，成功后 wheel 清空。
 * @param[in] prepared
 *     与实际 setup 准备状态一致。
 *
 * @retval 0
 *     全部资源成对释放。
 * @retval 1
 *     清理合同断言失败。
 *
 * @note
 *     无业务资源；step 全槽预算每次仍至多注销一项。
 */
static int cleanup(fixture_t *f, bool prepared)
{
    if (prepared) {
        EXPECT(vireo_timer_wheel_shutdown_begin(f->wheel), VIREO_OK);
        vireo_timer_wheel_shutdown_report_t report;
        do {
            EXPECT(vireo_timer_wheel_shutdown_step(f->wheel,
                    VIREO_TIMER_WHEEL_SHUTDOWN_MAX_SLOTS, &report), VIREO_OK);
        } while (!report.finished);
    }
    EXPECT(vireo_timer_wheel_destroy(&f->wheel), VIREO_OK);
    CHECK(f->wheel == NULL);
    return 0;
}

/**
 * @brief 构造相同到期刻度的测试登记并公开发现
 *
 * @param[in,out] f
 *     已 prepare 的测试轮，至少有 count 个空槽。
 * @param[in,out] handles
 *     count 个全零、独立可写身份，caller 保存这些数值。
 * @param[in] count
 *     测试取 1 至 65536。
 * @param[in] origin
 *     匹配轮起点且小于 UINT64_MAX，故 origin+1 可表示。
 *
 * @retval 0
 *     所有登记均被发现但尚未注销。
 * @retval 1
 *     公开合同断言失败。
 *
 * @note
 *     两预算明确传入；不依赖桶中顺序。
 */
static int ready_items(fixture_t *f, vireo_timer_handle_t *handles, size_t count,
                       vireo_monotonic_ns_t origin)
{
    for (size_t i = 0; i < count; ++i) {
        EXPECT(vireo_timer_wheel_register(f->wheel, origin, origin + 1, &handles[i]),
                VIREO_OK);
    }
    vireo_timer_wheel_advance_budget_t budget = { .max_ticks = 1, .max_nodes = count };
    vireo_timer_wheel_advance_report_t report;
    EXPECT(vireo_timer_wheel_advance(f->wheel, origin + 1, budget, &report), VIREO_OK);
    CHECK(report.progress.ready_count == count && report.progress.caught_up);
    return 0;
}

/**
 * @brief 断言无失败事件时全部嵌套逻辑值为零
 *
 * @param[in] report
 *     非空、已发布的短借报告。
 *
 * @retval 0
 *     七个无事件逻辑值符合合同。
 * @retval 1
 *     有效性或某字段错误。
 *
 * @note
 *     不读取 padding，不保存地址。
 */
static int no_failed_value(vireo_timer_loop_dispatch_report_t const *report)
{
    CHECK(!report->has_failed_delivery);
    CHECK(report->failed_delivery.handle.owner_id == 0);
    CHECK(report->failed_delivery.handle.slot_index == 0);
    CHECK(report->failed_delivery.handle.generation == 0);
    CHECK(report->failed_delivery.timer.deadline_ns == 0);
    CHECK(report->failed_delivery.timer.due_tick == 0);
    CHECK(report->failed_delivery.timer.bucket_index == 0);
    return 0;
}

/**
 * @brief 检查注销身份并执行选定的有限公开动作
 *
 * @param[in] expired
 *     非空历史值，只借到返回，至多复制前四个值。
 * @param[in,out] context
 *     可空；非空为本场景存活 probe，不保存事件地址。
 *
 * @retval VIREO_OK
 *     身份及动作检查成功且本次没有选定失败。
 * @retval VIREO_RESULT_INTERNAL
 *     身份/动作不符合测试预期。
 * @retval 其他非OK结果
 *     场景指定的失败码，可能已有其他登记修改。
 *
 * @note
 *     每次至多两次 get 检查及一次单项写，不递归消费/推进；刻意改 errno 验证外层恢复。
 */
static vireo_result_t deliver(vireo_timer_wheel_expired_t const *expired, void *context)
{
    errno = EILSEQ;
    if (context == NULL) {
        return VIREO_OK;
    }
    delivery_probe_t *p = context;
    if (p->calls < 4) {
        p->events[p->calls] = *expired;
    }
    ++p->calls;
    vireo_timer_wheel_timer_info_t info;
    if (vireo_timer_wheel_get(p->wheel, expired->handle, &info) != VIREO_RESULT_NOT_FOUND) {
        p->invalid = true;
    }
    vireo_result_t result = VIREO_OK;
    if (p->action == ACTION_REPLACE_READY) {
        p->replacement = (vireo_timer_handle_t){0};
        result = vireo_timer_wheel_register(p->wheel, 0, 1, &p->replacement);
        if (result == VIREO_OK) {
            p->reused = p->replacement.slot_index == expired->handle.slot_index &&
                        p->replacement.owner_id == expired->handle.owner_id &&
                        p->replacement.generation != expired->handle.generation;
            if (!p->reused || vireo_timer_wheel_get(p->wheel, expired->handle, &info) !=
                              VIREO_RESULT_NOT_FOUND) {
                p->invalid = true;
            }
        }
    } else if (p->calls == 1) {
        if ((p->action == ACTION_CANCEL_OTHER || p->action == ACTION_REARM_OTHER) &&
            same_handle(p->other, expired->handle)) {
            p->other = p->replacement;
        }
        if (p->action == ACTION_CANCEL_OTHER) {
            result = vireo_timer_wheel_cancel(p->wheel, &p->other);
        } else if (p->action == ACTION_REARM_OTHER) {
            result = vireo_timer_wheel_rearm(p->wheel, p->other, 1, 2);
        } else if (p->action == ACTION_STOP) {
            result = vireo_timer_wheel_shutdown_begin(p->wheel);
        }
    }
    if (result != VIREO_OK) {
        p->invalid = true;
    }
    if (p->invalid) {
        return VIREO_RESULT_INTERNAL;
    }
    return p->calls == p->fail_at ? p->failure : VIREO_OK;
}

/**
 * @brief 在选定次数注入观测错误，其余调用真实公开入口
 *
 * @param[in] wheel
 *     存活短借轮。
 * @param[out] out
 *     独立栈进度，注入失败不写。
 * @param[in,out] context
 *     非空 fault_state，记录调用次数。
 *
 * @return
 *     指定错误或真实公开观测结果。
 *
 * @note
 *     注入失败不改变轮，修改 errno 用于恢复断言。
 */
static vireo_result_t inspect_fault(vireo_timer_wheel_t const *wheel,
                                    vireo_timer_wheel_progress_t *out, void *context)
{
    fault_state_t *p = context;
    ++p->inspect_calls;
    errno = ERANGE;
    if (p->inspect_calls == p->fail_inspect_at) {
        return p->failure;
    }
    return vireo_timer_wheel_progress_inspect(wheel, out);
}

/**
 * @brief 在选定次数注入领取错误，其余真实领取
 *
 * @param[in,out] wheel
 *     存活短借轮，注入失败不摘链或归还。
 * @param[out] out
 *     独立栈事件，注入失败不写。
 * @param[in,out] context
 *     非空 fault_state，记录调用次数。
 *
 * @return
 *     指定错误或公开领取结果。
 *
 * @note
 *     不伪造已注销事件，修改 errno 验证外层恢复。
 */
static vireo_result_t take_fault(vireo_timer_wheel_t *wheel,
                                 vireo_timer_wheel_expired_t *out, void *context)
{
    fault_state_t *p = context;
    ++p->take_calls;
    errno = ERANGE;
    if (p->take_calls == p->fail_take_at) {
        return p->failure;
    }
    return vireo_timer_wheel_take_expired(wheel, out);
}

static vireo_timer_loop_dispatch_runtime_t runtime(fault_state_t *state)
{
    return (vireo_timer_loop_dispatch_runtime_t){
        .inspect = inspect_fault, .take = take_fault, .context = state
    };
}

static int test_basic_arguments(void)
{
    fixture_t f = {0}; CHECK(setup(&f, 1, true, 0) == 0);
    vireo_timer_handle_t h = {0}; CHECK(ready_items(&f, &h, 1, 0) == 0);
    delivery_probe_t p = { .wheel = f.wheel };
    vireo_timer_loop_dispatch_report_t report;
    memset(&report, 0xa5, sizeof(report)); unsigned char old[sizeof(report)];
    memcpy(old, &report, sizeof(old));
    EXPECT(vireo_timer_loop_dispatch(NULL, 1, deliver, &p, &report), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(memcmp(old, &report, sizeof(old)) == 0);
    EXPECT(vireo_timer_loop_dispatch(f.wheel, 0, deliver, &p, &report), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(memcmp(old, &report, sizeof(old)) == 0);
    EXPECT(vireo_timer_loop_dispatch(f.wheel, SIZE_MAX, NULL, &p, &report), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(memcmp(old, &report, sizeof(old)) == 0);
    EXPECT(vireo_timer_loop_dispatch(f.wheel, 1, deliver, &p, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(p.calls == 0);
    vireo_timer_wheel_timer_info_t info;
    EXPECT(vireo_timer_wheel_get(f.wheel, h, &info), VIREO_OK);
    return cleanup(&f, true);
}

static int test_budget_and_runtime_arguments(void)
{
    fixture_t f = {0}; CHECK(setup(&f, 1, false, 0) == 0);
    fault_state_t fault = {0}; vireo_timer_loop_dispatch_runtime_t ops = runtime(&fault);
    vireo_timer_loop_dispatch_report_t report;
    memset(&report, 0xa5, sizeof(report)); unsigned char old[sizeof(report)];
    memcpy(old, &report, sizeof(old));
    size_t const budgets[] = { VIREO_TIMER_LOOP_DISPATCH_MAX_EVENTS + 1, SIZE_MAX };
    for (size_t i = 0; i < sizeof(budgets) / sizeof(budgets[0]); ++i) {
        EXPECT(vireo_timer_loop_dispatch_runtime(f.wheel, budgets[i], deliver, NULL, &report, &ops), VIREO_RESULT_RANGE);
        CHECK(memcmp(old, &report, sizeof(old)) == 0);
    }
    EXPECT(vireo_timer_loop_dispatch_runtime(f.wheel, 1, deliver, NULL, &report, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(memcmp(old, &report, sizeof(old)) == 0);
    ops.inspect = NULL;
    EXPECT(vireo_timer_loop_dispatch_runtime(f.wheel, 1, deliver, NULL, &report, &ops), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(memcmp(old, &report, sizeof(old)) == 0);
    ops = runtime(&fault); ops.take = NULL;
    EXPECT(vireo_timer_loop_dispatch_runtime(f.wheel, 1, deliver, NULL, &report, &ops), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(memcmp(old, &report, sizeof(old)) == 0);
    CHECK(fault.inspect_calls == 0 && fault.take_calls == 0);
    return cleanup(&f, false);
}

static int test_unprepared_report(void)
{
    fixture_t f = {0}; CHECK(setup(&f, 1, false, 0) == 0);
    vireo_timer_loop_dispatch_report_t report; memset(&report, 0xa5, sizeof(report));
    EXPECT(vireo_timer_loop_dispatch(f.wheel, 1, deliver, NULL, &report), VIREO_RESULT_NOT_FOUND);
    CHECK(report.stage == VIREO_TIMER_LOOP_DISPATCH_STAGE_OBSERVE);
    CHECK(report.consumed_count == 0 && report.delivered_count == 0);
    CHECK(no_failed_value(&report) == 0);
    return cleanup(&f, false);
}

static int test_empty_and_null_context(void)
{
    fixture_t f = {0}; CHECK(setup(&f, 1, true, 0) == 0);
    vireo_timer_loop_dispatch_report_t report;
    EXPECT(vireo_timer_loop_dispatch(f.wheel, 1, deliver, NULL, &report), VIREO_OK);
    CHECK(report.stage == VIREO_TIMER_LOOP_DISPATCH_STAGE_NONE && report.consumed_count == 0);
    CHECK(report.delivered_count == 0 && no_failed_value(&report) == 0);
    vireo_timer_handle_t h = {0}; CHECK(ready_items(&f, &h, 1, 0) == 0);
    EXPECT(vireo_timer_loop_dispatch(f.wheel, 1, deliver, NULL, &report), VIREO_OK);
    CHECK(report.consumed_count == 1 && report.delivered_count == 1);
    return cleanup(&f, true);
}

static int test_max_finite_event(void)
{
    fixture_t f = {0}; CHECK(setup(&f, 1, true, UINT64_MAX - 1) == 0);
    vireo_timer_handle_t h = {0}; CHECK(ready_items(&f, &h, 1, UINT64_MAX - 1) == 0);
    delivery_probe_t p = { .wheel = f.wheel }; vireo_timer_loop_dispatch_report_t report;
    EXPECT(vireo_timer_loop_dispatch(f.wheel, 1, deliver, &p, &report), VIREO_OK);
    CHECK(p.calls == 1 && !p.invalid && same_handle(p.events[0].handle, h));
    CHECK(p.events[0].timer.deadline_ns == UINT64_MAX && p.events[0].timer.due_tick == 1);
    CHECK(p.events[0].timer.bucket_index == 1 && no_failed_value(&report) == 0);
    return cleanup(&f, true);
}

static int test_multiple_and_budget(void)
{
    fixture_t f = {0}; CHECK(setup(&f, 3, true, 0) == 0);
    vireo_timer_handle_t h[3] = {0}; CHECK(ready_items(&f, h, 3, 0) == 0);
    delivery_probe_t p = { .wheel = f.wheel }; vireo_timer_loop_dispatch_report_t report;
    EXPECT(vireo_timer_loop_dispatch(f.wheel, 1, deliver, &p, &report), VIREO_OK);
    CHECK(report.consumed_count == 1 && report.delivered_count == 1 && p.calls == 1);
    vireo_timer_loop_wait_plan_t plan;
    EXPECT(vireo_timer_loop_plan_wait(f.wheel, 1, 9, &plan), VIREO_OK);
    CHECK(plan.timer_work_pending && plan.timeout_ms == 0);
    EXPECT(vireo_timer_loop_dispatch(f.wheel, 3, deliver, &p, &report), VIREO_OK);
    CHECK(report.consumed_count == 2 && report.delivered_count == 2 && p.calls == 3 && !p.invalid);
    for (size_t i = 0; i < 3; ++i) {
        size_t matches = 0;
        for (size_t j = 0; j < 3; ++j) { if (same_handle(h[i], p.events[j].handle)) { ++matches; } }
        CHECK(matches == 1);
    }
    CHECK(no_failed_value(&report) == 0);
    EXPECT(vireo_timer_loop_plan_wait(f.wheel, 1, 9, &plan), VIREO_OK);
    CHECK(!plan.timer_work_pending && plan.timeout_ms == 9);
    return cleanup(&f, true);
}

static int test_callback_errors(void)
{
    vireo_result_t const errors[] = { VIREO_RESULT_NOT_FOUND, VIREO_RESULT_IO,
        VIREO_RESULT_CANCELLED, VIREO_RESULT_TIMEOUT, VIREO_RESULT_INVALID_ARGUMENT,
        VIREO_RESULT_RANGE, VIREO_RESULT_BUSY, VIREO_RESULT_OVERFLOW,
        VIREO_RESULT_NO_MEMORY, VIREO_RESULT_INTERNAL, VIREO_RESULT_PROTOCOL,
        VIREO_RESULT_DATABASE };
    for (size_t i = 0; i < sizeof(errors) / sizeof(errors[0]); ++i) {
        fixture_t f = {0}; CHECK(setup(&f, 1, true, 0) == 0);
        vireo_timer_handle_t h = {0}; CHECK(ready_items(&f, &h, 1, 0) == 0);
        delivery_probe_t p = { .wheel = f.wheel, .fail_at = 1, .failure = errors[i] };
        vireo_timer_loop_dispatch_report_t report;
        EXPECT(vireo_timer_loop_dispatch(f.wheel, 4, deliver, &p, &report), errors[i]);
        CHECK(report.stage == VIREO_TIMER_LOOP_DISPATCH_STAGE_DELIVER);
        CHECK(report.consumed_count == 1 && report.delivered_count == 0 && p.calls == 1);
        CHECK(report.has_failed_delivery && same_handle(report.failed_delivery.handle, h));
        CHECK(report.failed_delivery.timer.deadline_ns == 1 && report.failed_delivery.timer.due_tick == 1);
        CHECK(report.failed_delivery.timer.bucket_index == 1 && !p.invalid);
        EXPECT(vireo_timer_loop_dispatch(f.wheel, 4, deliver, &p, &report), VIREO_OK);
        CHECK(report.consumed_count == 0 && p.calls == 1 && no_failed_value(&report) == 0);
        CHECK(cleanup(&f, true) == 0);
    }
    return 0;
}

static int test_late_delivery_failure(void)
{
    fixture_t f = {0}; CHECK(setup(&f, 3, true, 0) == 0);
    vireo_timer_handle_t h[3] = {0}; CHECK(ready_items(&f, h, 3, 0) == 0);
    delivery_probe_t p = { .wheel = f.wheel, .fail_at = 2, .failure = VIREO_RESULT_IO };
    vireo_timer_loop_dispatch_report_t report;
    EXPECT(vireo_timer_loop_dispatch(f.wheel, 3, deliver, &p, &report), VIREO_RESULT_IO);
    CHECK(report.stage == VIREO_TIMER_LOOP_DISPATCH_STAGE_DELIVER && p.calls == 2 && !p.invalid);
    CHECK(report.consumed_count == 2 && report.delivered_count == 1 && report.has_failed_delivery);
    vireo_timer_wheel_expired_t saved = report.failed_delivery;
    CHECK(same_handle(saved.handle, p.events[1].handle));
    vireo_timer_wheel_progress_t progress;
    EXPECT(vireo_timer_wheel_progress_inspect(f.wheel, &progress), VIREO_OK);
    CHECK(progress.ready_count == 1);
    EXPECT(vireo_timer_loop_dispatch(f.wheel, 3, deliver, &p, &report), VIREO_OK);
    CHECK(report.consumed_count == 1 && report.delivered_count == 1 && p.calls == 3);
    CHECK(!same_handle(saved.handle, p.events[2].handle) && no_failed_value(&report) == 0);
    return cleanup(&f, true);
}

/* 回调根据事件身份选择另一个登记，不假设任何领取顺序。 */
static int callback_mutation(action_t action, bool fail)
{
    fixture_t f = {0}; CHECK(setup(&f, 2, true, 0) == 0);
    vireo_timer_handle_t h[2] = {0}; CHECK(ready_items(&f, h, 2, 0) == 0);
    delivery_probe_t p = { .wheel = f.wheel, .action = action,
        .fail_at = fail ? 1 : 0, .failure = VIREO_RESULT_IO,
        .other = h[0], .replacement = h[1] };
    vireo_timer_loop_dispatch_report_t report;
    EXPECT(vireo_timer_loop_dispatch(f.wheel, 3, deliver, &p, &report),
            fail ? VIREO_RESULT_IO : VIREO_OK);
    CHECK(!p.invalid && p.calls == 1 && report.consumed_count == 1);
    CHECK(report.delivered_count == (fail ? 0 : 1));
    vireo_timer_wheel_progress_t progress;
    EXPECT(vireo_timer_wheel_progress_inspect(f.wheel, &progress), VIREO_OK);
    CHECK(progress.ready_count == 0);
    vireo_timer_handle_t remaining = same_handle(h[0], p.events[0].handle) ? h[1] : h[0];
    vireo_timer_wheel_timer_info_t timer;
    EXPECT(vireo_timer_wheel_get(f.wheel, remaining, &timer),
            action == ACTION_CANCEL_OTHER ? VIREO_RESULT_NOT_FOUND : VIREO_OK);
    if (action == ACTION_REARM_OTHER) {
        CHECK(timer.deadline_ns == 2 && timer.due_tick == 2);
        CHECK(no_failed_value(&report) == 0);
    } else {
        CHECK(report.has_failed_delivery &&
              same_handle(report.failed_delivery.handle, p.events[0].handle));
    }
    return cleanup(&f, true);
}

static int test_cancel_other(void) { return callback_mutation(ACTION_CANCEL_OTHER, true); }
static int test_rearm_other(void) { return callback_mutation(ACTION_REARM_OTHER, false); }

static int test_replenishment_hard_budget(void)
{
    /* 先登记全部未来期限，再推进发现；此时间顺序不使用历史 now 补充。 */
    fixture_t full = {0};
    size_t const maximum = VIREO_TIMER_LOOP_DISPATCH_MAX_EVENTS;
    CHECK(setup(&full, maximum, true, 0) == 0);
    vireo_timer_handle_t *all = calloc(maximum, sizeof(*all));
    CHECK(all != NULL);
    CHECK(ready_items(&full, all, maximum, 0) == 0);
    delivery_probe_t full_probe = { .wheel = full.wheel };
    vireo_timer_loop_dispatch_report_t full_report;
    EXPECT(vireo_timer_loop_dispatch(full.wheel, maximum, deliver, &full_probe,
                                     &full_report), VIREO_OK);
    CHECK(full_probe.calls == maximum && !full_probe.invalid);
    CHECK(full_report.consumed_count == maximum && full_report.delivered_count == maximum);
    CHECK(no_failed_value(&full_report) == 0);
    vireo_timer_wheel_progress_t full_progress;
    EXPECT(vireo_timer_wheel_progress_inspect(full.wheel, &full_progress), VIREO_OK);
    CHECK(full_progress.ready_count == 0);
    free(all);
    CHECK(cleanup(&full, true) == 0);

    /* 已公开 register 不检查跨调用 now 单调；历史 now 数值模型不冒真实 clock 新鲜度。 */
    size_t const budgets[] = { 1, VIREO_TIMER_LOOP_DISPATCH_MAX_EVENTS };
    for (size_t i = 0; i < 2; ++i) {
        fixture_t f = {0}; CHECK(setup(&f, 1, true, 0) == 0);
        vireo_timer_handle_t h = {0}; CHECK(ready_items(&f, &h, 1, 0) == 0);
        delivery_probe_t p = { .wheel = f.wheel, .action = ACTION_REPLACE_READY };
        vireo_timer_loop_dispatch_report_t report;
        EXPECT(vireo_timer_loop_dispatch(f.wheel, budgets[i], deliver, &p, &report), VIREO_OK);
        CHECK(p.calls == budgets[i] && !p.invalid && p.reused);
        CHECK(report.consumed_count == budgets[i] && report.delivered_count == budgets[i]);
        vireo_timer_wheel_progress_t progress;
        EXPECT(vireo_timer_wheel_progress_inspect(f.wheel, &progress), VIREO_OK);
        CHECK(progress.ready_count == 1 && no_failed_value(&report) == 0);
        CHECK(cleanup(&f, true) == 0);
    }
    return 0;
}

static int test_stop_and_stopped_drain(void)
{
    for (size_t initially_stopped = 0; initially_stopped < 2; ++initially_stopped) {
        fixture_t f = {0}; CHECK(setup(&f, 3, true, 0) == 0);
        vireo_timer_handle_t h[2] = {0}; CHECK(ready_items(&f, h, 2, 0) == 0);
        vireo_timer_handle_t future = {0};
        EXPECT(vireo_timer_wheel_register(f.wheel, 1, 2, &future), VIREO_OK);
        if (initially_stopped != 0) { EXPECT(vireo_timer_wheel_shutdown_begin(f.wheel), VIREO_OK); }
        delivery_probe_t p = { .wheel = f.wheel, .action = ACTION_STOP };
        vireo_timer_loop_dispatch_report_t report;
        EXPECT(vireo_timer_loop_dispatch(f.wheel, 3, deliver, &p, &report), VIREO_OK);
        CHECK(report.consumed_count == 2 && p.calls == 2 && !p.invalid);
        vireo_timer_wheel_shutdown_info_t info;
        EXPECT(vireo_timer_wheel_shutdown_inspect(f.wheel, &info), VIREO_OK);
        CHECK(info.stopping && !info.finished && info.active_count == 1);
        vireo_timer_wheel_timer_info_t timer;
        EXPECT(vireo_timer_wheel_get(f.wheel, future, &timer), VIREO_OK);
        CHECK(timer.deadline_ns == 2);
        EXPECT(vireo_timer_loop_dispatch(f.wheel, 3, deliver, &p, &report), VIREO_OK);
        CHECK(report.consumed_count == 0 && p.calls == 2);
        CHECK(cleanup(&f, true) == 0);
    }
    return 0;
}

static int dependency_failures(bool inspect)
{
    vireo_result_t const failures[] = { VIREO_RESULT_NOT_FOUND, VIREO_RESULT_RANGE,
        VIREO_RESULT_INVALID_ARGUMENT, VIREO_RESULT_IO };
    for (size_t error = 0; error < 4; ++error) {
        for (size_t at = 1; at <= 2; ++at) {
            fixture_t f = {0}; CHECK(setup(&f, 2, true, 0) == 0);
            vireo_timer_handle_t h[2] = {0}; CHECK(ready_items(&f, h, 2, 0) == 0);
            fault_state_t fault = { .fail_inspect_at = inspect ? at : 0,
                .fail_take_at = inspect ? 0 : at, .failure = failures[error] };
            vireo_timer_loop_dispatch_runtime_t ops = runtime(&fault);
            delivery_probe_t p = { .wheel = f.wheel };
            vireo_timer_loop_dispatch_report_t report;
            EXPECT(vireo_timer_loop_dispatch_runtime(f.wheel, 2, deliver, &p, &report, &ops), failures[error]);
            CHECK(report.stage == (inspect ? VIREO_TIMER_LOOP_DISPATCH_STAGE_OBSERVE : VIREO_TIMER_LOOP_DISPATCH_STAGE_TAKE));
            CHECK(report.consumed_count == at - 1 && report.delivered_count == at - 1);
            CHECK(p.calls == at - 1 && !p.invalid && no_failed_value(&report) == 0);
            CHECK(fault.inspect_calls == at && fault.take_calls == (inspect ? at - 1 : at));
            vireo_timer_wheel_progress_t progress;
            EXPECT(vireo_timer_wheel_progress_inspect(f.wheel, &progress), VIREO_OK);
            CHECK(progress.ready_count == 3 - at);
            size_t active = 0; vireo_timer_wheel_timer_info_t timer;
            for (size_t i = 0; i < 2; ++i) {
                vireo_result_t result = vireo_timer_wheel_get(f.wheel, h[i], &timer);
                CHECK(result == VIREO_OK || result == VIREO_RESULT_NOT_FOUND);
                if (result == VIREO_OK) { ++active; }
            }
            CHECK(active == 3 - at);
            EXPECT(vireo_timer_loop_dispatch(f.wheel, 2, deliver, &p, &report), VIREO_OK);
            CHECK(report.consumed_count == 3 - at && p.calls == 2);
            CHECK(cleanup(&f, true) == 0);
        }
    }
    return 0;
}

static int test_observation_failures(void) { return dependency_failures(true); }
static int test_take_failures(void) { return dependency_failures(false); }

static int test_no_observation_after_budget(void)
{
    fixture_t f = {0}; CHECK(setup(&f, 2, true, 0) == 0);
    vireo_timer_handle_t h[2] = {0}; CHECK(ready_items(&f, h, 2, 0) == 0);
    fault_state_t fault = { .fail_inspect_at = 2, .failure = VIREO_RESULT_IO };
    vireo_timer_loop_dispatch_runtime_t ops = runtime(&fault);
    delivery_probe_t p = { .wheel = f.wheel }; vireo_timer_loop_dispatch_report_t report;
    EXPECT(vireo_timer_loop_dispatch_runtime(f.wheel, 1, deliver, &p, &report, &ops), VIREO_OK);
    CHECK(report.stage == VIREO_TIMER_LOOP_DISPATCH_STAGE_NONE && report.consumed_count == 1);
    CHECK(fault.inspect_calls == 1 && fault.take_calls == 1 && p.calls == 1);
    vireo_timer_wheel_progress_t progress;
    EXPECT(vireo_timer_wheel_progress_inspect(f.wheel, &progress), VIREO_OK);
    CHECK(progress.ready_count == 1);
    return cleanup(&f, true);
}

/**
 * @brief 从真实非阻塞 socketpair 读取一个预期字节
 *
 * @param[in] loop
 *     注册所属 loop，短借，回调不修改。
 * @param[in] handle
 *     注册身份副本，未用于释放。
 * @param[in] fd
 *     测试拥有的非阻塞客户端 fd，不在回调关闭。
 * @param[in] events
 *     公开 epoll 就绪位，预期 READ。
 * @param[in,out] context
 *     非空存活 network_probe，只记录次数及错误。
 *
 * @note
 *     严格一次 recv，无等待/DB/文件/GC；由测试返回后 DEL、close。
 */
static void network_read(vireo_event_loop_t *loop, vireo_event_loop_handle_t handle,
                          int fd, uint32_t events, void *context)
{
    (void)loop; (void)handle; network_probe_t *p = context; ++p->calls;
    char value = 0;
    if ((events & VIREO_EPOLL_EVENT_READ) == 0 || recv(fd, &value, 1, 0) != 1 || value != 'x') {
        p->invalid = true;
    }
}

static int test_native_round_and_dispatch(void)
{
    vireo_monotonic_ns_t sample;
    EXPECT(vireo_clock_monotonic_now(&sample, NULL), VIREO_OK);
    CHECK(sample > 0);
    fixture_t f = {0}; CHECK(setup(&f, 1, true, sample - 1) == 0);
    vireo_timer_handle_t h = {0};
    EXPECT(vireo_timer_wheel_register(f.wheel, sample - 1, sample, &h), VIREO_OK);
    vireo_event_loop_options_t options = {
        .event_capacity = 4, .max_memory_bytes = VIREO_EVENT_LOOP_MAX_MEMORY,
        .registration_capacity = 2
    };
    vireo_event_loop_t *loop = NULL;
    EXPECT(vireo_event_loop_create(&options, &loop, NULL), VIREO_OK);
    int sockets[2]; CHECK(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, sockets) == 0);
    network_probe_t net = {0};
    vireo_event_loop_registration_t registration = {
        .fd = sockets[0], .interests = VIREO_EPOLL_EVENT_READ,
        .callback = network_read, .context = &net
    };
    vireo_event_loop_handle_t network_handle = {0};
    EXPECT(vireo_event_loop_add(loop, &registration, &network_handle, NULL), VIREO_OK);
    CHECK(send(sockets[1], "x", 1, 0) == 1);
    vireo_timer_loop_run_options_t run = { .max_wait_ms = 0,
        .advance_budget = { .max_ticks = 1, .max_nodes = 1 } };
    vireo_timer_loop_run_report_t round; vireo_timer_loop_diagnostic_t diagnostic;
    EXPECT(vireo_timer_loop_run_once(loop, f.wheel, &run, &round, &diagnostic), VIREO_OK);
    CHECK(net.calls == 1 && !net.invalid && round.advance.progress.ready_count == 1);
    delivery_probe_t p = { .wheel = f.wheel }; vireo_timer_loop_dispatch_report_t report;
    EXPECT(vireo_timer_loop_dispatch(f.wheel, 1, deliver, &p, &report), VIREO_OK);
    CHECK(p.calls == 1 && !p.invalid && same_handle(p.events[0].handle, h));
    CHECK(p.events[0].timer.deadline_ns == sample && report.delivered_count == 1);
    EXPECT(vireo_event_loop_del(loop, &network_handle, NULL), VIREO_OK);
    CHECK(close(sockets[0]) == 0 && close(sockets[1]) == 0);
    EXPECT(vireo_event_loop_destroy(&loop, NULL), VIREO_OK);
    return cleanup(&f, true);
}

int main(void)
{
    int failures = 0;
    failures += test_basic_arguments();
    failures += test_budget_and_runtime_arguments();
    failures += test_unprepared_report();
    failures += test_empty_and_null_context();
    failures += test_max_finite_event();
    failures += test_multiple_and_budget();
    failures += test_callback_errors();
    failures += test_late_delivery_failure();
    failures += test_cancel_other();
    failures += test_rearm_other();
    failures += test_replenishment_hard_budget();
    failures += test_stop_and_stopped_drain();
    failures += test_observation_failures();
    failures += test_take_failures();
    failures += test_no_observation_after_budget();
    failures += test_native_round_and_dispatch();
    printf("timer loop dispatch: 16 groups, %d failures; 65536 full-capacity deliveries, numeric replenishment, native round\n", failures);
    return failures == 0 ? 0 : 1;
}
