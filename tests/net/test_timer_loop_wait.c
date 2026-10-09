/*
 * PROJECT : VIREO
 * FILE    : test_timer_loop_wait.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-09
 * BRIEF   : 此模块负责：
 * -- 以公开轮状态验证等待规划、失败保持及不消费工作
 */
#include <vireo/net/timer_loop.h>
#include <vireo/timer/wheel_advance.h>
#include <vireo/timer/wheel_shutdown.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

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

/** 测试栈值：通过四种公开观测证明规划没有改变可观察状态，不比较 padding。 */
typedef struct wheel_snapshot {
    vireo_timer_wheel_info_t base; /**< 几何及基础申请量快照。 */
    vireo_timer_wheel_registry_info_t registry; /**< 准备、容量及活跃登记计数快照。 */
    vireo_timer_wheel_progress_t progress; /**< 时间前沿、在途桶与 ready 计数快照。 */
    vireo_timer_wheel_shutdown_info_t shutdown; /**< 永久停止和身份收尾状态快照。 */
} wheel_snapshot_t;

static int snapshot(vireo_timer_wheel_t const *wheel, wheel_snapshot_t *out)
{
    EXPECT(vireo_timer_wheel_inspect(wheel, &out->base), VIREO_OK);
    EXPECT(vireo_timer_wheel_registry_inspect(wheel, &out->registry), VIREO_OK);
    EXPECT(vireo_timer_wheel_progress_inspect(wheel, &out->progress), VIREO_OK);
    EXPECT(vireo_timer_wheel_shutdown_inspect(wheel, &out->shutdown), VIREO_OK);
    return 0;
}

static bool same_snapshot(wheel_snapshot_t const *a, wheel_snapshot_t const *b)
{
    return a->base.geometry.origin_ns == b->base.geometry.origin_ns &&
           a->base.geometry.tick_ns == b->base.geometry.tick_ns &&
           a->base.geometry.bucket_count == b->base.geometry.bucket_count &&
           a->base.allocation_bytes == b->base.allocation_bytes &&
           a->base.max_memory_bytes == b->base.max_memory_bytes &&
           a->registry.prepared == b->registry.prepared &&
           a->registry.capacity == b->registry.capacity &&
           a->registry.active_count == b->registry.active_count &&
           a->registry.available_count == b->registry.available_count &&
           a->registry.allocation_bytes == b->registry.allocation_bytes &&
           a->registry.max_memory_bytes == b->registry.max_memory_bytes &&
           a->progress.latest_now_ns == b->progress.latest_now_ns &&
           a->progress.target_tick == b->progress.target_tick &&
           a->progress.completed_tick == b->progress.completed_tick &&
           a->progress.processing == b->progress.processing &&
           a->progress.ready_count == b->progress.ready_count &&
           a->progress.caught_up == b->progress.caught_up &&
           a->shutdown.stopping == b->shutdown.stopping &&
           a->shutdown.active_count == b->shutdown.active_count &&
           a->shutdown.finished == b->shutdown.finished;
}

static int make_wheel(vireo_monotonic_ns_t origin, vireo_duration_ns_t tick,
                      size_t capacity, vireo_timer_wheel_t **out)
{
    vireo_timer_wheel_options_t options = {
        .geometry = { .origin_ns = origin, .tick_ns = tick, .bucket_count = 4 },
        .max_memory_bytes = VIREO_TIMER_WHEEL_MAX_MEMORY
    };
    vireo_timer_wheel_registry_options_t registry = {
        .capacity = capacity, .max_memory_bytes = VIREO_TIMER_WHEEL_REGISTRY_MAX_MEMORY
    };
    EXPECT(vireo_timer_wheel_create(&options, out), VIREO_OK);
    EXPECT(vireo_timer_wheel_prepare(*out, &registry), VIREO_OK);
    return 0;
}

static int expect_plan(vireo_timer_wheel_t const *wheel, vireo_monotonic_ns_t now,
                       int cap, int timeout, bool pending, bool has_deadline,
                       vireo_monotonic_ns_t deadline)
{
    wheel_snapshot_t before, after;
    CHECK(snapshot(wheel, &before) == 0);
    vireo_timer_loop_wait_plan_t plan;
    memset(&plan, 0xa5, sizeof(plan));
    EXPECT(vireo_timer_loop_plan_wait(wheel, now, cap, &plan), VIREO_OK);
    CHECK(plan.timeout_ms == timeout && plan.timer_work_pending == pending &&
          plan.has_tick_deadline == has_deadline && plan.tick_deadline_ns == deadline);
    CHECK(plan.timeout_ms >= 0 && plan.timeout_ms <= cap);
    CHECK(snapshot(wheel, &after) == 0 && same_snapshot(&before, &after));
    return 0;
}

static int expect_error(vireo_timer_wheel_t const *wheel, vireo_monotonic_ns_t now,
                        int cap, vireo_result_t expected)
{
    vireo_timer_loop_wait_plan_t plan;
    unsigned char before[sizeof(plan)];
    memset(&plan, 0xa5, sizeof(plan));
    memcpy(before, &plan, sizeof(plan));
    EXPECT(vireo_timer_loop_plan_wait(wheel, now, cap, &plan), expected);
    CHECK(memcmp(before, &plan, sizeof(plan)) == 0);
    return 0;
}

static int test_arguments(void)
{
    vireo_timer_wheel_t *wheel = NULL;
    CHECK(make_wheel(100, 10, 1, &wheel) == 0);
    CHECK(expect_error(NULL, 100, 1, VIREO_RESULT_INVALID_ARGUMENT) == 0);
    CHECK(expect_error(wheel, 100, -1, VIREO_RESULT_INVALID_ARGUMENT) == 0);
    CHECK(expect_error(wheel, 100, INT_MIN, VIREO_RESULT_INVALID_ARGUMENT) == 0);
    EXPECT(vireo_timer_loop_plan_wait(wheel, 100, 1, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_timer_wheel_destroy(&wheel), VIREO_OK);
    return 0;
}

static int test_prepare(void)
{
    vireo_timer_wheel_t *wheel = NULL;
    vireo_timer_wheel_options_t options = {
        .geometry = { .origin_ns = 100, .tick_ns = 10, .bucket_count = 4 },
        .max_memory_bytes = VIREO_TIMER_WHEEL_MAX_MEMORY
    };
    vireo_timer_wheel_registry_options_t registry = { 1, VIREO_TIMER_WHEEL_REGISTRY_MAX_MEMORY };
    EXPECT(vireo_timer_wheel_create(&options, &wheel), VIREO_OK);
    CHECK(expect_error(wheel, 0, 1, VIREO_RESULT_NOT_FOUND) == 0);
    CHECK(expect_error(wheel, 0, -1, VIREO_RESULT_INVALID_ARGUMENT) == 0);
    EXPECT(vireo_timer_wheel_prepare(wheel, &registry), VIREO_OK);
    CHECK(expect_plan(wheel, 100, 7, 7, false, false, 0) == 0);
    EXPECT(vireo_timer_wheel_destroy(&wheel), VIREO_OK);
    return 0;
}

static int test_time_regression(void)
{
    vireo_timer_wheel_t *wheel = NULL;
    CHECK(make_wheel(100, 10, 1, &wheel) == 0);
    CHECK(expect_error(wheel, 99, 7, VIREO_RESULT_RANGE) == 0);
    vireo_timer_wheel_advance_report_t report;
    EXPECT(vireo_timer_wheel_advance(wheel, 101,
           (vireo_timer_wheel_advance_budget_t){1, 1}, &report), VIREO_OK);
    wheel_snapshot_t before, after;
    CHECK(snapshot(wheel, &before) == 0);
    CHECK(expect_error(wheel, 100, 7, VIREO_RESULT_RANGE) == 0);
    CHECK(snapshot(wheel, &after) == 0 && same_snapshot(&before, &after));
    CHECK(expect_plan(wheel, 101, 7, 7, false, false, 0) == 0);
    EXPECT(vireo_timer_wheel_destroy(&wheel), VIREO_OK);
    return 0;
}

static int test_empty_caps(void)
{
    vireo_timer_wheel_t *wheel = NULL;
    CHECK(make_wheel(UINT64_MAX, UINT64_MAX, 1, &wheel) == 0);
    CHECK(expect_plan(wheel, UINT64_MAX, INT_MAX, INT_MAX, false, false, 0) == 0);
    CHECK(expect_plan(wheel, UINT64_MAX, 0, 0, false, false, 0) == 0);
    CHECK(expect_plan(wheel, UINT64_MAX, 23, 23, false, false, 0) == 0);
    EXPECT(vireo_timer_wheel_destroy(&wheel), VIREO_OK);
    return 0;
}

static int test_rounding_caps(void)
{
    vireo_timer_wheel_t *wheel = NULL;
    vireo_timer_handle_t handle = {0};
    CHECK(make_wheel(100, 1500001, 1, &wheel) == 0);
    EXPECT(vireo_timer_wheel_register(wheel, 100, 1000100, &handle), VIREO_OK);
    CHECK(expect_plan(wheel, 100, INT_MAX, 2, false, true, 1500101) == 0);
    CHECK(expect_plan(wheel, 100, 1, 1, false, true, 1500101) == 0);
    CHECK(expect_plan(wheel, 100, 0, 0, false, true, 1500101) == 0);
    CHECK(expect_plan(wheel, 500101, 9, 1, false, true, 1500101) == 0);
    CHECK(expect_plan(wheel, 1500100, 9, 1, false, true, 1500101) == 0);
    /* 原 deadline 已过而刻度边界未到，仍只等量化边界，不执行原期限动作。 */
    CHECK(expect_plan(wheel, 1000100, 9, 1, false, true, 1500101) == 0);
    EXPECT(vireo_timer_wheel_cancel(wheel, &handle), VIREO_OK);
    EXPECT(vireo_timer_wheel_destroy(&wheel), VIREO_OK);
    return 0;
}

static int test_fresh_now(void)
{
    vireo_timer_wheel_t *wheel = NULL;
    vireo_timer_handle_t handle = {0};
    CHECK(make_wheel(0, 10, 1, &wheel) == 0);
    EXPECT(vireo_timer_wheel_register(wheel, 0, 100, &handle), VIREO_OK);
    /* 旧快照 caught_up=true，但新 now 的 floor=1，不能继续睡眠。 */
    CHECK(expect_plan(wheel, 10, 100, 0, true, false, 0) == 0);
    vireo_timer_wheel_advance_report_t report;
    EXPECT(vireo_timer_wheel_advance(wheel, 10,
           (vireo_timer_wheel_advance_budget_t){1, 1}, &report), VIREO_OK);
    CHECK(expect_plan(wheel, 10, 100, 1, false, true, 20) == 0);
    EXPECT(vireo_timer_wheel_cancel(wheel, &handle), VIREO_OK);
    EXPECT(vireo_timer_wheel_destroy(&wheel), VIREO_OK);
    return 0;
}

static int test_empty_debt(void)
{
    vireo_timer_wheel_t *wheel = NULL;
    CHECK(make_wheel(0, 10, 1, &wheel) == 0);
    CHECK(expect_plan(wheel, 30, 99, 0, true, false, 0) == 0);
    vireo_timer_wheel_advance_report_t report;
    EXPECT(vireo_timer_wheel_advance(wheel, 30,
           (vireo_timer_wheel_advance_budget_t){1, 1}, &report), VIREO_OK);
    CHECK(!report.progress.caught_up && report.progress.completed_tick == 1);
    CHECK(expect_plan(wheel, 30, 99, 0, true, false, 0) == 0);
    EXPECT(vireo_timer_wheel_advance(wheel, 30,
           (vireo_timer_wheel_advance_budget_t){2, 1}, &report), VIREO_OK);
    CHECK(expect_plan(wheel, 30, 99, 99, false, false, 0) == 0);
    EXPECT(vireo_timer_wheel_destroy(&wheel), VIREO_OK);
    return 0;
}

static int test_processing_empty_pending(void)
{
    vireo_timer_wheel_t *wheel = NULL;
    vireo_timer_handle_t first = {0}, second = {0};
    CHECK(make_wheel(0, 10, 2, &wheel) == 0);
    EXPECT(vireo_timer_wheel_register(wheel, 0, 50, &first), VIREO_OK);
    EXPECT(vireo_timer_wheel_register(wheel, 0, 90, &second), VIREO_OK);
    vireo_timer_wheel_advance_report_t report;
    EXPECT(vireo_timer_wheel_advance(wheel, 10,
           (vireo_timer_wheel_advance_budget_t){1, 1}, &report), VIREO_OK);
    CHECK(report.progress.processing && report.progress.ready_count == 0);
    CHECK(expect_plan(wheel, 10, 99, 0, true, false, 0) == 0);
    EXPECT(vireo_timer_wheel_cancel(wheel, &first), VIREO_OK);
    EXPECT(vireo_timer_wheel_cancel(wheel, &second), VIREO_OK);
    /* 全部项取消后 pending 环为空，processing 仍需原 advance 完成。 */
    CHECK(expect_plan(wheel, 10, 99, 0, true, false, 0) == 0);
    EXPECT(vireo_timer_wheel_advance(wheel, 10,
           (vireo_timer_wheel_advance_budget_t){1, 1}, &report), VIREO_OK);
    CHECK(expect_plan(wheel, 10, 99, 99, false, false, 0) == 0);
    EXPECT(vireo_timer_wheel_destroy(&wheel), VIREO_OK);
    return 0;
}

static int test_ready_not_consumed(void)
{
    vireo_timer_wheel_t *wheel = NULL;
    vireo_timer_handle_t handle = {0}, other = {0};
    CHECK(make_wheel(0, 10, 1, &wheel) == 0);
    EXPECT(vireo_timer_wheel_register(wheel, 0, 10, &handle), VIREO_OK);
    vireo_timer_wheel_advance_report_t report;
    EXPECT(vireo_timer_wheel_advance(wheel, 10,
           (vireo_timer_wheel_advance_budget_t){1, 1}, &report), VIREO_OK);
    CHECK(report.progress.caught_up && report.progress.ready_count == 1);
    CHECK(expect_plan(wheel, 10, INT_MAX, 0, true, false, 0) == 0);
    vireo_timer_wheel_timer_info_t timer;
    EXPECT(vireo_timer_wheel_get(wheel, handle, &timer), VIREO_OK);
    CHECK(timer.deadline_ns == 10);
    EXPECT(vireo_timer_wheel_register(wheel, 10, 20, &other), VIREO_RESULT_BUSY);
    vireo_timer_wheel_expired_t expired;
    EXPECT(vireo_timer_wheel_take_expired(wheel, &expired), VIREO_OK);
    CHECK(expired.handle.owner_id == handle.owner_id &&
          expired.handle.slot_index == handle.slot_index &&
          expired.handle.generation == handle.generation);
    EXPECT(vireo_timer_wheel_get(wheel, handle, &timer), VIREO_RESULT_NOT_FOUND);
    CHECK(expect_plan(wheel, 10, 7, 7, false, false, 0) == 0);
    EXPECT(vireo_timer_wheel_destroy(&wheel), VIREO_OK);
    return 0;
}

static int test_rearm_ready(void)
{
    vireo_timer_wheel_t *wheel = NULL;
    vireo_timer_handle_t handle = {0};
    CHECK(make_wheel(0, 10, 1, &wheel) == 0);
    vireo_timer_wheel_advance_report_t report;
    EXPECT(vireo_timer_wheel_advance(wheel, 20,
           (vireo_timer_wheel_advance_budget_t){2, 1}, &report), VIREO_OK);
    /* 合法晚登记直接成为 ready；规划既不领取也不自动重排。 */
    EXPECT(vireo_timer_wheel_register(wheel, 0, 10, &handle), VIREO_OK);
    CHECK(expect_plan(wheel, 20, 7, 0, true, false, 0) == 0);
    EXPECT(vireo_timer_wheel_rearm(wheel, handle, 20, 50), VIREO_OK);
    CHECK(expect_plan(wheel, 20, 7, 1, false, true, 30) == 0);
    EXPECT(vireo_timer_wheel_cancel(wheel, &handle), VIREO_OK);
    EXPECT(vireo_timer_wheel_destroy(&wheel), VIREO_OK);
    return 0;
}

static int test_stopping_priority(void)
{
    vireo_timer_wheel_t *wheel = NULL;
    vireo_timer_handle_t handle = {0};
    CHECK(make_wheel(100, 10, 1, &wheel) == 0);
    EXPECT(vireo_timer_wheel_register(wheel, 100, 200, &handle), VIREO_OK);
    EXPECT(vireo_timer_wheel_shutdown_begin(wheel), VIREO_OK);
    wheel_snapshot_t before, after;
    CHECK(snapshot(wheel, &before) == 0);
    CHECK(expect_error(wheel, 0, 9, VIREO_RESULT_CANCELLED) == 0);
    CHECK(expect_error(wheel, UINT64_MAX, 9, VIREO_RESULT_CANCELLED) == 0);
    CHECK(expect_error(wheel, 0, -1, VIREO_RESULT_INVALID_ARGUMENT) == 0);
    EXPECT(vireo_timer_loop_plan_wait(wheel, 0, 1, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(snapshot(wheel, &after) == 0 && same_snapshot(&before, &after));
    EXPECT(vireo_timer_wheel_cancel(wheel, &handle), VIREO_OK);
    CHECK(expect_error(wheel, 100, 9, VIREO_RESULT_CANCELLED) == 0);
    EXPECT(vireo_timer_wheel_destroy(&wheel), VIREO_OK);
    return 0;
}

static int test_full_range(void)
{
    vireo_timer_wheel_t *wheel = NULL;
    vireo_timer_handle_t handle = {0};
    CHECK(make_wheel(0, UINT64_MAX, 1, &wheel) == 0);
    EXPECT(vireo_timer_wheel_register(wheel, 0, UINT64_MAX, &handle), VIREO_OK);
    for (size_t repeat = 0; repeat < 32; ++repeat) {
        CHECK(expect_plan(wheel, 0, INT_MAX, INT_MAX, false, true, UINT64_MAX) == 0);
        CHECK(expect_plan(wheel, 0, 0, 0, false, true, UINT64_MAX) == 0);
    }
    CHECK(expect_plan(wheel, UINT64_MAX - 1, INT_MAX, 1, false, true, UINT64_MAX) == 0);
    CHECK(expect_plan(wheel, UINT64_MAX, INT_MAX, 0, true, false, 0) == 0);
    vireo_timer_wheel_advance_report_t report;
    EXPECT(vireo_timer_wheel_advance(wheel, UINT64_MAX,
           (vireo_timer_wheel_advance_budget_t){1, 1}, &report), VIREO_OK);
    CHECK(expect_plan(wheel, UINT64_MAX, INT_MAX, 0, true, false, 0) == 0);
    vireo_timer_wheel_expired_t expired;
    EXPECT(vireo_timer_wheel_take_expired(wheel, &expired), VIREO_OK);
    CHECK(expect_plan(wheel, UINT64_MAX, INT_MAX, INT_MAX, false, false, 0) == 0);
    EXPECT(vireo_timer_wheel_destroy(&wheel), VIREO_OK);
    return 0;
}

int main(void)
{
    int failures = 0;
    failures += test_arguments();
    failures += test_prepare();
    failures += test_time_regression();
    failures += test_empty_caps();
    failures += test_rounding_caps();
    failures += test_fresh_now();
    failures += test_empty_debt();
    failures += test_processing_empty_pending();
    failures += test_ready_not_consumed();
    failures += test_rearm_ready();
    failures += test_stopping_priority();
    failures += test_full_range();
    printf("timer loop wait: 12 groups, %d failures; public wheel interfaces only\n", failures);
    return failures == 0 ? 0 : 1;
}
