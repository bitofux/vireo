/*
 * PROJECT : VIREO
 * FILE    : test_wheel_integration.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-09
 * BRIEF   : 此模块负责：
 * -- 仅用公开接口核验时间、身份、推进与收尾的组合
 * -- 区分原期限、量化边界、到期交付与停机取消
 */
#include <vireo/timer/wheel_advance.h>
#include <vireo/timer/wheel_shutdown.h>

#include <errno.h>
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

/** 仅测试应用侧记录，不是轮的 callback 或业务资源。 */
typedef enum observed_reason {
    OBSERVED_PENDING = 0, /**< 外部记录尚未收到注销通知。 */
    OBSERVED_EXPIRED, /**< 通过 take_expired 收到到期历史值。 */
    OBSERVED_CANCELLED, /**< 通过 shutdown_step 收到停机取消历史值。 */
} observed_reason_t;

/** 公开返回值的外部期待，不预测槽选择或内部链位。 */
typedef struct application_record {
    vireo_timer_handle_t handle; /**< 原公开身份值，收到事件后仅用于关联历史。 */
    vireo_monotonic_ns_t deadline; /**< 独立期待的原纳秒期限，不是量化边界。 */
    observed_reason_t reason; /**< 测试消费者写一次的注销原因，不表示资源清理完成。 */
} application_record_t;

static bool same_handle(vireo_timer_handle_t a, vireo_timer_handle_t b) {
    return a.owner_id == b.owner_id && a.slot_index == b.slot_index && a.generation == b.generation;
}

/**
 * @brief 测试构造显式几何和固定登记资源，正常结束由各场景销毁
 *
 * @param[in] geometry
 *     合法公开几何值，无默认参数。
 * @param[in] capacity
 *     正登记容量，不是桶数。
 * @param[out] out
 *     入口 NULL 的轮拥有者地址，成功后测试负责销毁。
 *
 * @retval 0
 *     create 与 prepare 均符合公开成功合同。
 * @retval 1
 *     场景失败，立即令测试退出；失败诊断归测试宏处理。
 */
static int make_wheel(vireo_timer_wheel_geometry_t geometry, size_t capacity,
                      vireo_timer_wheel_t **out) {
    vireo_timer_wheel_options_t const options = {geometry, VIREO_TIMER_WHEEL_MAX_MEMORY};
    vireo_timer_wheel_registry_options_t const registry = {capacity, VIREO_TIMER_WHEEL_REGISTRY_MAX_MEMORY};
    EXPECT(vireo_timer_wheel_create(&options, out), VIREO_OK);
    EXPECT(vireo_timer_wheel_prepare(*out, &registry), VIREO_OK);
    return 0;
}

/**
 * @brief 测试重复同一 now 续接预算，只消费公开进度并限制夹具调用总数
 *
 * @param[in,out] wheel
 *     存活、已准备且尚未停止的轮，当前测试独占。
 * @param[in] now
 *     不小于前次成功推进的同域时间点。
 * @param[in] budget
 *     两项正预算，场景自选，无无限推进。
 *
 * @retval 0
 *     4096 次以内追上，且每次实际工作量不超过显式预算。
 * @retval 1
 *     返回、预算或夹具终止条件错误。
 *
 * @note
 *     不读取 private cursor 或链布局，不执行业务动作，不预测通知顺序。
 */
static int advance_to(vireo_timer_wheel_t *wheel, vireo_monotonic_ns_t now,
                      vireo_timer_wheel_advance_budget_t budget) {
    for (size_t calls = 0; calls < 4096; calls++) {
        vireo_timer_wheel_advance_report_t report;
        EXPECT(vireo_timer_wheel_advance(wheel, now, budget, &report), VIREO_OK);
        CHECK(report.ticks_started <= budget.max_ticks && report.nodes_examined <= budget.max_nodes);
        CHECK(report.progress.latest_now_ns == now);
        if (report.progress.caught_up) {
            return 0;
        }
    }
    CHECK(false);
    return 1;
}

static int explicit_100ms_512_buckets(void) {
    vireo_duration_ns_t tick;
    EXPECT(vireo_clock_duration_from_ms(100, &tick), VIREO_OK);
    CHECK(tick == UINT64_C(100000000));
    vireo_timer_wheel_geometry_t geometry;
    EXPECT(vireo_timer_wheel_geometry_make(1000, tick, 512, &geometry), VIREO_OK);
    vireo_timer_wheel_t *wheel = NULL;
    CHECK(make_wheel(geometry, 3, &wheel) == 0);
    uint64_t const delays[3] = {UINT64_C(100000000), UINT64_C(51300000000), UINT64_C(102500000000)};
    uint64_t const ticks[3] = {1, 513, 1025};
    vireo_timer_handle_t h[3] = {{0}};
    vireo_monotonic_ns_t deadlines[3];
    for (size_t i = 0; i < 3; i++) {
        EXPECT(vireo_clock_deadline_after(1000, delays[i], &deadlines[i]), VIREO_OK);
        EXPECT(vireo_timer_wheel_register(wheel, 1000, deadlines[i], &h[i]), VIREO_OK);
        vireo_timer_wheel_timer_info_t info;
        EXPECT(vireo_timer_wheel_get(wheel, h[i], &info), VIREO_OK);
        CHECK(info.deadline_ns == deadlines[i] && info.due_tick == ticks[i] && info.bucket_index == 1);
    }
    CHECK(advance_to(wheel, deadlines[0] - 1, (vireo_timer_wheel_advance_budget_t){17, 1}) == 0);
    vireo_timer_wheel_expired_t event;
    EXPECT(vireo_timer_wheel_take_expired(wheel, &event), VIREO_RESULT_NOT_FOUND);
    CHECK(advance_to(wheel, deadlines[0], (vireo_timer_wheel_advance_budget_t){1, 1}) == 0);
    EXPECT(vireo_timer_wheel_take_expired(wheel, &event), VIREO_OK);
    CHECK(same_handle(event.handle, h[0]) && event.timer.deadline_ns == deadlines[0]);
    EXPECT(vireo_timer_wheel_take_expired(wheel, &event), VIREO_RESULT_NOT_FOUND);
    /* 将第二圈原期限只延长 1ns，向上量化至514，不改变身份或第三圈期限。 */
    EXPECT(vireo_timer_wheel_rearm(wheel, h[1], deadlines[0], deadlines[1] + 1), VIREO_OK);
    vireo_timer_wheel_timer_info_t info;
    EXPECT(vireo_timer_wheel_get(wheel, h[1], &info), VIREO_OK);
    CHECK(info.due_tick == 514 && info.bucket_index == 2 && info.deadline_ns == deadlines[1] + 1);
    CHECK(advance_to(wheel, deadlines[1], (vireo_timer_wheel_advance_budget_t){17, 1}) == 0);
    EXPECT(vireo_timer_wheel_take_expired(wheel, &event), VIREO_RESULT_NOT_FOUND);
    CHECK(advance_to(wheel, UINT64_C(51400001000), (vireo_timer_wheel_advance_budget_t){1, 1}) == 0);
    EXPECT(vireo_timer_wheel_take_expired(wheel, &event), VIREO_OK);
    CHECK(same_handle(event.handle, h[1]) && event.timer.deadline_ns == deadlines[1] + 1);
    CHECK(advance_to(wheel, UINT64_C(102400001000), (vireo_timer_wheel_advance_budget_t){17, 1}) == 0);
    EXPECT(vireo_timer_wheel_take_expired(wheel, &event), VIREO_RESULT_NOT_FOUND);
    CHECK(advance_to(wheel, deadlines[2], (vireo_timer_wheel_advance_budget_t){1, 1}) == 0);
    EXPECT(vireo_timer_wheel_take_expired(wheel, &event), VIREO_OK);
    CHECK(same_handle(event.handle, h[2]) && event.timer.deadline_ns == deadlines[2] && event.timer.due_tick == 1025);
    for (size_t i = 0; i < 3; i++) {
        EXPECT(vireo_timer_wheel_get(wheel, h[i], &info), VIREO_RESULT_NOT_FOUND);
    }
    EXPECT(vireo_timer_wheel_destroy(&wheel), VIREO_OK);
    return 0;
}

static int nanoseconds_wait_and_quantization(void) {
    vireo_timer_wheel_geometry_t const geometry = {10, UINT64_C(1500001), 3};
    vireo_timer_wheel_t *wheel = NULL;
    CHECK(make_wheel(geometry, 1, &wheel) == 0);
    vireo_duration_ns_t duration;
    vireo_monotonic_ns_t deadline;
    EXPECT(vireo_clock_duration_from_ms(1, &duration), VIREO_OK);
    EXPECT(vireo_clock_deadline_after(10, duration, &deadline), VIREO_OK);
    CHECK(deadline == UINT64_C(1000010));
    vireo_timer_handle_t h = {0};
    EXPECT(vireo_timer_wheel_register(wheel, 10, deadline, &h), VIREO_OK);
    vireo_timer_wheel_timer_info_t info;
    EXPECT(vireo_timer_wheel_get(wheel, h, &info), VIREO_OK);
    CHECK(info.due_tick == 1 && info.bucket_index == 1);
    vireo_monotonic_ns_t boundary;
    EXPECT(vireo_timer_wheel_tick_time(geometry, info.due_tick, &boundary), VIREO_OK);
    CHECK(boundary == UINT64_C(1500011));
    int wait;
    EXPECT(vireo_clock_deadline_wait_ms(deadline - 1, deadline, 10, &wait), VIREO_OK);
    CHECK(wait == 1);
    EXPECT(vireo_clock_deadline_wait_ms(10, deadline, 0, &wait), VIREO_OK);
    CHECK(wait == 0);
    bool expired;
    EXPECT(vireo_clock_deadline_expired(10, deadline, &expired), VIREO_OK);
    CHECK(!expired); /* cap0 不是到期。 */
    EXPECT(vireo_clock_deadline_expired(deadline, deadline, &expired), VIREO_OK);
    CHECK(expired);
    CHECK(advance_to(wheel, deadline, (vireo_timer_wheel_advance_budget_t){1, 1}) == 0);
    vireo_timer_wheel_expired_t event;
    EXPECT(vireo_timer_wheel_take_expired(wheel, &event), VIREO_RESULT_NOT_FOUND);
    CHECK(advance_to(wheel, boundary - 1, (vireo_timer_wheel_advance_budget_t){1, 1}) == 0);
    EXPECT(vireo_timer_wheel_take_expired(wheel, &event), VIREO_RESULT_NOT_FOUND);
    CHECK(advance_to(wheel, boundary, (vireo_timer_wheel_advance_budget_t){1, 1}) == 0);
    EXPECT(vireo_timer_wheel_take_expired(wheel, &event), VIREO_OK);
    CHECK(event.timer.deadline_ns == deadline && event.timer.due_tick == 1 && same_handle(event.handle, h));
    EXPECT(vireo_timer_wheel_destroy(&wheel), VIREO_OK);
    return 0;
}

static int delivered_identity_and_other_wheel(void) {
    vireo_timer_wheel_geometry_t const geometry = {0, 1, 1};
    vireo_timer_wheel_t *first = NULL, *second = NULL;
    CHECK(make_wheel(geometry, 1, &first) == 0 && make_wheel(geometry, 1, &second) == 0);
    vireo_timer_handle_t old = {0}, current = {0}, other = {0};
    EXPECT(vireo_timer_wheel_register(first, 0, 1, &old), VIREO_OK);
    CHECK(advance_to(first, 1, (vireo_timer_wheel_advance_budget_t){1, 1}) == 0);
    vireo_timer_handle_t full = {0};
    EXPECT(vireo_timer_wheel_register(first, 1, 2, &full), VIREO_RESULT_BUSY);
    CHECK(same_handle(full, (vireo_timer_handle_t){0}));
    vireo_timer_wheel_expired_t event;
    EXPECT(vireo_timer_wheel_take_expired(first, &event), VIREO_OK);
    CHECK(same_handle(event.handle, old));
    EXPECT(vireo_timer_wheel_register(first, 1, 2, &current), VIREO_OK);
    CHECK(current.slot_index == old.slot_index && current.generation != old.generation && current.owner_id == old.owner_id);
    EXPECT(vireo_timer_wheel_register(second, 0, 2, &other), VIREO_OK);
    CHECK(other.owner_id != current.owner_id);
    vireo_timer_wheel_timer_info_t info;
    EXPECT(vireo_timer_wheel_get(first, old, &info), VIREO_RESULT_NOT_FOUND);
    EXPECT(vireo_timer_wheel_cancel(first, &old), VIREO_RESULT_NOT_FOUND);
    CHECK(same_handle(old, event.handle));
    EXPECT(vireo_timer_wheel_get(first, other, &info), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_timer_wheel_get(second, current, &info), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_timer_wheel_get(first, current, &info), VIREO_OK);
    EXPECT(vireo_timer_wheel_cancel(first, &current), VIREO_OK);
    CHECK(same_handle(current, (vireo_timer_handle_t){0}));
    EXPECT(vireo_timer_wheel_cancel(second, &other), VIREO_OK);
    EXPECT(vireo_timer_wheel_destroy(&first), VIREO_OK);
    EXPECT(vireo_timer_wheel_destroy(&second), VIREO_OK);
    return 0;
}

static int overflow_then_permanent_stop(void) {
    vireo_timer_wheel_geometry_t const geometry = {UINT64_MAX - 5, 4, 2};
    vireo_timer_wheel_t *wheel = NULL;
    CHECK(make_wheel(geometry, 1, &wheel) == 0);
    vireo_timer_handle_t h = {0}, output = {0};
    EXPECT(vireo_timer_wheel_register(wheel, geometry.origin_ns, UINT64_MAX - 4, &h), VIREO_OK);
    EXPECT(vireo_timer_wheel_rearm(wheel, h, geometry.origin_ns, UINT64_MAX), VIREO_RESULT_OVERFLOW);
    EXPECT(vireo_timer_wheel_register(wheel, geometry.origin_ns, UINT64_MAX, &output), VIREO_RESULT_OVERFLOW);
    CHECK(same_handle(output, (vireo_timer_handle_t){0}));
    vireo_timer_wheel_timer_info_t info;
    EXPECT(vireo_timer_wheel_get(wheel, h, &info), VIREO_OK);
    CHECK(info.deadline_ns == UINT64_MAX - 4 && info.due_tick == 1 && info.bucket_index == 1);
    uint64_t sentinel = 77;
    EXPECT(vireo_clock_deadline_after(UINT64_MAX, 1, &sentinel), VIREO_RESULT_OVERFLOW);
    CHECK(sentinel == 77);
    EXPECT(vireo_timer_wheel_deadline_tick(geometry, UINT64_MAX, &sentinel), VIREO_RESULT_OVERFLOW);
    CHECK(sentinel == 77);
    vireo_timer_wheel_advance_report_t report;
    memset(&report, 0xa5, sizeof(report));
    unsigned char saved[sizeof(report)]; memcpy(saved, &report, sizeof(report));
    EXPECT(vireo_timer_wheel_advance(wheel, geometry.origin_ns - 1,
           (vireo_timer_wheel_advance_budget_t){1, 1}, &report), VIREO_RESULT_RANGE);
    CHECK(memcmp(saved, &report, sizeof(report)) == 0);
    EXPECT(vireo_timer_wheel_shutdown_begin(wheel), VIREO_OK);
    EXPECT(vireo_timer_wheel_register(wheel, geometry.origin_ns - 1, UINT64_MAX, &output), VIREO_RESULT_CANCELLED);
    EXPECT(vireo_timer_wheel_rearm(wheel, h, geometry.origin_ns - 1, UINT64_MAX), VIREO_RESULT_CANCELLED);
    EXPECT(vireo_timer_wheel_advance(wheel, geometry.origin_ns - 1,
           (vireo_timer_wheel_advance_budget_t){1, 1}, &report), VIREO_RESULT_CANCELLED);
    CHECK(memcmp(saved, &report, sizeof(report)) == 0 && same_handle(output, (vireo_timer_handle_t){0}));
    vireo_timer_handle_t malformed = h; malformed.generation = 0;
    EXPECT(vireo_timer_wheel_rearm(wheel, malformed, 0, 0), VIREO_RESULT_INVALID_ARGUMENT);
    vireo_timer_wheel_shutdown_report_t shutdown;
    EXPECT(vireo_timer_wheel_shutdown_step(wheel, 1, &shutdown), VIREO_OK);
    CHECK(shutdown.has_cancelled && shutdown.finished && shutdown.remaining_count == 0);
    CHECK(same_handle(shutdown.cancelled.handle, h) && shutdown.cancelled.timer.deadline_ns == UINT64_MAX - 4);
    EXPECT(vireo_timer_wheel_get(wheel, h, &info), VIREO_RESULT_NOT_FOUND);
    EXPECT(vireo_timer_wheel_shutdown_step(wheel, 1, &shutdown), VIREO_OK);
    CHECK(!shutdown.has_cancelled && shutdown.scanned_slots == 0 && shutdown.finished);
    EXPECT(vireo_timer_wheel_destroy(&wheel), VIREO_OK);
    return 0;
}

/**
 * @brief 测试消费者按原身份只记录一次原因，不执行 callback 或持有资源
 *
 * @param[in,out] records
 *     当前测试独占的三个外部登记值。
 * @param[in] handle
 *     已注销的历史身份，用于匹配原记录，不再授权轮操作。
 * @param[in] deadline
 *     事件原 ns 期限，须与独立期待一致。
 * @param[in] reason
 *     此消费入口指定的 EXPIRED 或 CANCELLED。
 *
 * @retval 0
 *     恰有一项未消费记录匹配，更新测试原因。
 * @retval 1
 *     未匹配、重复或原期限错误。
 */
static int observe_event(application_record_t records[3], vireo_timer_handle_t handle,
                         vireo_monotonic_ns_t deadline, observed_reason_t reason) {
    for (size_t i = 0; i < 3; i++) {
        if (same_handle(records[i].handle, handle)) {
            CHECK(records[i].reason == OBSERVED_PENDING && records[i].deadline == deadline);
            records[i].reason = reason;
            return 0;
        }
    }
    CHECK(false);
    return 1;
}

static int bounded_external_value_consumer(void) {
    vireo_timer_wheel_t *wheel = NULL;
    CHECK(make_wheel((vireo_timer_wheel_geometry_t){0, 1, 2}, 3, &wheel) == 0);
    application_record_t records[3] = {
        {.handle = {0}, .deadline = 0, .reason = OBSERVED_PENDING},
    };
    for (size_t i = 0; i < 3; i++) {
        records[i].deadline = i == 2 ? 10u : 1u;
        EXPECT(vireo_timer_wheel_register(wheel, 0, records[i].deadline, &records[i].handle), VIREO_OK);
    }
    CHECK(advance_to(wheel, 1, (vireo_timer_wheel_advance_budget_t){1, 1}) == 0);
    /* 本轮调用者显式只领取一次，保留另一 ready；不执行“领取到空”的无预算循环。 */
    vireo_timer_wheel_expired_t event;
    EXPECT(vireo_timer_wheel_take_expired(wheel, &event), VIREO_OK);
    CHECK(observe_event(records, event.handle, event.timer.deadline_ns, OBSERVED_EXPIRED) == 0);
    vireo_timer_wheel_progress_t progress;
    vireo_timer_wheel_registry_info_t registry;
    EXPECT(vireo_timer_wheel_progress_inspect(wheel, &progress), VIREO_OK);
    EXPECT(vireo_timer_wheel_registry_inspect(wheel, &registry), VIREO_OK);
    CHECK(progress.caught_up && progress.ready_count == 1 && registry.active_count == 2);
    EXPECT(vireo_timer_wheel_shutdown_begin(wheel), VIREO_OK);
    EXPECT(vireo_timer_wheel_take_expired(wheel, &event), VIREO_OK);
    CHECK(observe_event(records, event.handle, event.timer.deadline_ns, OBSERVED_EXPIRED) == 0);
    vireo_timer_wheel_shutdown_report_t report;
    EXPECT(vireo_timer_wheel_shutdown_step(wheel, 3, &report), VIREO_OK);
    CHECK(report.has_cancelled && report.finished && report.cancelled.timer.deadline_ns == 10);
    CHECK(observe_event(records, report.cancelled.handle, report.cancelled.timer.deadline_ns, OBSERVED_CANCELLED) == 0);
    CHECK(records[0].reason == OBSERVED_EXPIRED && records[1].reason == OBSERVED_EXPIRED);
    CHECK(records[2].reason == OBSERVED_CANCELLED);
    EXPECT(vireo_timer_wheel_destroy(&wheel), VIREO_OK);
    CHECK(wheel == NULL);
    return 0;
}

int main(void) {
    int (*const tests[])(void) = {explicit_100ms_512_buckets, nanoseconds_wait_and_quantization,
        delivered_identity_and_other_wheel, overflow_then_permanent_stop, bounded_external_value_consumer};
    for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        if (tests[i]() != 0) {
            return 1;
        }
    }
    printf("wheel integration: 5 groups, 0 failures; public interfaces only; explicit 100ms/512 buckets\n");
    return 0;
}
