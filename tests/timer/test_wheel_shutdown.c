/*
 * PROJECT : VIREO
 * FILE    : test_wheel_shutdown.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-09
 * BRIEF   : 此模块负责：
 * -- 核验停止阶段、槽预算和三环收尾
 * -- 核验归还失败的链位、游标和完整输出保持
 * -- 用外部身份集合验证交替取消/领取和最终释放
 */
#include <vireo/timer/wheel_shutdown.h>
#include <vireo/timer/wheel_advance.h>
#include "timer/wheel_internal.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
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

/** 小轮失败快照；仅桶和容量均不超过四的夹具。 */
typedef struct state_snapshot {
    unsigned char control[sizeof(vireo_timer_wheel_t)]; /**< 包含停止标志/游标及两内嵌头的全部字节。 */
    unsigned char buckets[4 * sizeof(vireo_timer_wheel_link_t)]; /**< 实际桶环的原字节。 */
    unsigned char nodes[4 * sizeof(vireo_timer_wheel_node_t)]; /**< 实际节点表的原字节。 */
    vireo_timer_handle_owner_info_t owner; /**< public owner 逻辑值，不访问其私有表。 */
} state_snapshot_t;

/** 当前调用归还失败探针；不改变 owner、handle 或任何轮链接。 */
typedef struct release_probe {
    vireo_timer_wheel_link_t const *link; /**< 当前候选节点的短借链接。 */
    size_t calls; /**< 隔离 release 调用次数。 */
    bool detached; /**< 是否观察到先摘链为自环。 */
} release_probe_t;

/** 失败收尾输出及两侧邻位。 */
typedef struct report_guard {
    uint64_t before; /**< 前邻固定校验字节。 */
    vireo_timer_wheel_shutdown_report_t value; /**< step 输出目标。 */
    uint64_t after; /**< 后邻固定校验字节。 */
} report_guard_t;

/** 失败观测输出及两侧邻位。 */
typedef struct info_guard {
    uint64_t before; /**< 前邻固定校验字节。 */
    vireo_timer_wheel_shutdown_info_t value; /**< inspect 输出目标。 */
    uint64_t after; /**< 后邻固定校验字节。 */
} info_guard_t;

/** 独立模型保存外部登记，不模仿桶或停机游标。 */
typedef struct model_timer {
    bool active; /**< 模型是否尚持有有效登记。 */
    vireo_timer_handle_t handle; /**< public 返回身份，不预测槽选择。 */
    uint64_t deadline; /**< 独立期待的原 ns 期限。 */
} model_timer_t;

static bool same_handle(vireo_timer_handle_t a, vireo_timer_handle_t b) {
    return a.owner_id == b.owner_id && a.slot_index == b.slot_index && a.generation == b.generation;
}

static bool empty_cancelled(vireo_timer_wheel_shutdown_cancelled_t value) {
    return same_handle(value.handle, (vireo_timer_handle_t){0}) && value.timer.deadline_ns == 0 &&
           value.timer.due_tick == 0 && value.timer.bucket_index == 0;
}

static int make_wheel(size_t capacity, vireo_timer_wheel_t **out) {
    vireo_timer_wheel_options_t const options = {{0, 1, 1}, VIREO_TIMER_WHEEL_MAX_MEMORY};
    EXPECT(vireo_timer_wheel_create(&options, out), VIREO_OK);
    vireo_timer_wheel_registry_options_t const registry = {capacity, VIREO_TIMER_WHEEL_REGISTRY_MAX_MEMORY};
    EXPECT(vireo_timer_wheel_prepare(*out, &registry), VIREO_OK);
    return 0;
}

/** @brief 注册满表并按实际 public 槽号保存值，golden 仅针对明示物理槽扫描预算。 */
static int fill_by_slot(vireo_timer_wheel_t *wheel, size_t capacity, vireo_timer_handle_t *handles) {
    for (size_t i = 0; i < capacity; i++) {
        vireo_timer_handle_t h = {0};
        EXPECT(vireo_timer_wheel_register(wheel, 0, 10, &h), VIREO_OK);
        CHECK(h.slot_index < capacity && handles[h.slot_index].owner_id == 0);
        handles[h.slot_index] = h;
    }
    return 0;
}

static int save_state(vireo_timer_wheel_t const *wheel, state_snapshot_t *snapshot) {
    CHECK(wheel->bucket_count <= 4 && wheel->timer_capacity <= 4);
    memcpy(snapshot->control, wheel, sizeof(*wheel));
    memcpy(snapshot->buckets, wheel->buckets, wheel->bucket_count * sizeof(*wheel->buckets));
    if (wheel->owner != NULL) {
        memcpy(snapshot->nodes, wheel->nodes, wheel->node_bytes);
        EXPECT(vireo_timer_handle_owner_inspect(wheel->owner, &snapshot->owner), VIREO_OK);
    }
    return 0;
}

static int unchanged(vireo_timer_wheel_t const *wheel, state_snapshot_t const *snapshot) {
    CHECK(memcmp(snapshot->control, wheel, sizeof(*wheel)) == 0);
    CHECK(memcmp(snapshot->buckets, wheel->buckets, wheel->bucket_count * sizeof(*wheel->buckets)) == 0);
    if (wheel->owner != NULL) {
        CHECK(memcmp(snapshot->nodes, wheel->nodes, wheel->node_bytes) == 0);
        vireo_timer_handle_owner_info_t info;
        EXPECT(vireo_timer_handle_owner_inspect(wheel->owner, &info), VIREO_OK);
        CHECK(info.owner_id == snapshot->owner.owner_id && info.last_generation == snapshot->owner.last_generation);
        CHECK(info.capacity == snapshot->owner.capacity && info.active_count == snapshot->owner.active_count);
        CHECK(info.available_count == snapshot->owner.available_count && info.allocation_bytes == snapshot->owner.allocation_bytes);
        CHECK(info.max_memory_bytes == snapshot->owner.max_memory_bytes);
    }
    return 0;
}

static vireo_result_t release_failure(vireo_timer_handle_owner_t *owner,
                                       vireo_timer_handle_t *handle, void *context) {
    (void)owner;
    (void)handle;
    release_probe_t *probe = context;
    probe->calls++;
    probe->detached = probe->link->prev == probe->link && probe->link->next == probe->link;
    errno = EIO;
    return VIREO_RESULT_RANGE;
}

static int parameters_and_unprepared(void) {
    vireo_timer_wheel_t *wheel = NULL;
    vireo_timer_wheel_options_t const options = {{0, 1, 1}, 4096};
    EXPECT(vireo_timer_wheel_create(&options, &wheel), VIREO_OK);
    state_snapshot_t state; CHECK(save_state(wheel, &state) == 0);
    report_guard_t report, original;
    info_guard_t info, original_info;
    memset(&report, 0xa5, sizeof(report)); memcpy(&original, &report, sizeof(report));
    memset(&info, 0xb5, sizeof(info)); memcpy(&original_info, &info, sizeof(info));
    EXPECT(vireo_timer_wheel_shutdown_begin(NULL), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_timer_wheel_shutdown_begin(wheel), VIREO_RESULT_NOT_FOUND);
    EXPECT(vireo_timer_wheel_shutdown_inspect(NULL, &info.value), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_timer_wheel_shutdown_inspect(wheel, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_timer_wheel_shutdown_inspect(wheel, &info.value), VIREO_RESULT_NOT_FOUND);
    EXPECT(vireo_timer_wheel_shutdown_step(NULL, 1, &report.value), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_timer_wheel_shutdown_step(wheel, 1, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_timer_wheel_shutdown_step(wheel, 0, &report.value), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_timer_wheel_shutdown_step(wheel, 65537, &report.value), VIREO_RESULT_RANGE);
    EXPECT(vireo_timer_wheel_shutdown_step(wheel, 1, &report.value), VIREO_RESULT_NOT_FOUND);
    EXPECT(vireo_timer_wheel_shutdown_step_runtime(wheel, 1, &report.value, NULL, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(memcmp(&report, &original, sizeof(report)) == 0);
    CHECK(memcmp(&info, &original_info, sizeof(info)) == 0 && unchanged(wheel, &state) == 0);
    EXPECT(vireo_timer_wheel_destroy(&wheel), VIREO_OK);
    return 0;
}

static int begin_idempotence_and_freeze(void) {
    vireo_timer_wheel_t *wheel = NULL;
    CHECK(make_wheel(2, &wheel) == 0);
    vireo_timer_handle_t handles[2] = {{0}};
    CHECK(fill_by_slot(wheel, 2, handles) == 0);
    vireo_timer_wheel_advance_report_t advance;
    EXPECT(vireo_timer_wheel_advance(wheel, 10, (vireo_timer_wheel_advance_budget_t){1, 1}, &advance), VIREO_OK);
    /* 修改原字节副本的唯一标志，核 begin 不改变时间/头/资源/游标/其他字段。 */
    vireo_timer_wheel_t expected;
    memcpy(&expected, wheel, sizeof(expected)); expected.stopping = true;
    EXPECT(vireo_timer_wheel_shutdown_begin(wheel), VIREO_OK);
    CHECK(memcmp(&expected, wheel, sizeof(expected)) == 0);
    state_snapshot_t state; CHECK(save_state(wheel, &state) == 0);
    EXPECT(vireo_timer_wheel_shutdown_begin(wheel), VIREO_OK);
    CHECK(unchanged(wheel, &state) == 0);
    vireo_timer_wheel_shutdown_info_t info;
    EXPECT(vireo_timer_wheel_shutdown_inspect(wheel, &info), VIREO_OK);
    CHECK(info.stopping && info.active_count == 2 && !info.finished);
    EXPECT(vireo_timer_wheel_destroy(&wheel), VIREO_RESULT_BUSY);
    CHECK(unchanged(wheel, &state) == 0);
    for (size_t i = 0; i < 2; i++) {
        EXPECT(vireo_timer_wheel_cancel(wheel, &handles[i]), VIREO_OK);
    }
    EXPECT(vireo_timer_wheel_destroy(&wheel), VIREO_OK);
    return 0;
}

static int stopped_admission_and_error_priority(void) {
    vireo_timer_wheel_t *wheel = NULL;
    CHECK(make_wheel(2, &wheel) == 0);
    vireo_timer_handle_t h = {0};
    EXPECT(vireo_timer_wheel_register(wheel, 0, 1, &h), VIREO_OK);
    EXPECT(vireo_timer_wheel_shutdown_begin(wheel), VIREO_OK);
    state_snapshot_t state; CHECK(save_state(wheel, &state) == 0);
    vireo_timer_handle_t output = {0};
    EXPECT(vireo_timer_wheel_register(wheel, 0, 0, &output), VIREO_RESULT_CANCELLED);
    EXPECT(vireo_timer_wheel_register(wheel, 0, 2, &output), VIREO_RESULT_CANCELLED);
    CHECK(same_handle(output, (vireo_timer_handle_t){0}));
    EXPECT(vireo_timer_wheel_register(wheel, 0, 2, &h), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_timer_wheel_rearm(wheel, h, 0, 0), VIREO_RESULT_CANCELLED);
    EXPECT(vireo_timer_wheel_rearm(wheel, h, 0, 2), VIREO_RESULT_CANCELLED);
    EXPECT(vireo_timer_wheel_rearm(wheel, (vireo_timer_handle_t){0}, 0, 2), VIREO_RESULT_NOT_FOUND);
    vireo_timer_handle_t invalid = h; invalid.generation = 0;
    EXPECT(vireo_timer_wheel_rearm(wheel, invalid, 0, 2), VIREO_RESULT_INVALID_ARGUMENT);
    invalid = h; invalid.generation++;
    EXPECT(vireo_timer_wheel_rearm(wheel, invalid, 0, 2), VIREO_RESULT_NOT_FOUND);
    vireo_timer_wheel_advance_report_t report;
    memset(&report, 0xc4, sizeof(report));
    unsigned char original[sizeof(report)]; memcpy(original, &report, sizeof(report));
    EXPECT(vireo_timer_wheel_advance(wheel, 10, (vireo_timer_wheel_advance_budget_t){1, 1}, &report), VIREO_RESULT_CANCELLED);
    EXPECT(vireo_timer_wheel_advance(wheel, 10, (vireo_timer_wheel_advance_budget_t){0, 1}, &report), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_timer_wheel_advance(wheel, 10, (vireo_timer_wheel_advance_budget_t){65537, 1}, &report), VIREO_RESULT_RANGE);
    CHECK(memcmp(original, &report, sizeof(report)) == 0);
    vireo_timer_wheel_registry_options_t const registry = {2, 4096};
    EXPECT(vireo_timer_wheel_prepare(wheel, &registry), VIREO_RESULT_BUSY);
    CHECK(unchanged(wheel, &state) == 0);
    EXPECT(vireo_timer_wheel_cancel(wheel, &h), VIREO_OK);
    EXPECT(vireo_timer_wheel_destroy(&wheel), VIREO_OK);
    return 0;
}

static int sparse_budget_and_single_record(void) {
    vireo_timer_wheel_t *wheel = NULL;
    CHECK(make_wheel(4, &wheel) == 0);
    vireo_timer_handle_t h[4] = {{0}}; CHECK(fill_by_slot(wheel, 4, h) == 0);
    for (size_t i = 0; i < 3; i++) {
        EXPECT(vireo_timer_wheel_cancel(wheel, &h[i]), VIREO_OK);
    }
    EXPECT(vireo_timer_wheel_shutdown_begin(wheel), VIREO_OK);
    vireo_timer_wheel_shutdown_report_t report;
    for (size_t i = 0; i < 3; i++) {
        EXPECT(vireo_timer_wheel_shutdown_step(wheel, 1, &report), VIREO_OK);
        CHECK(report.scanned_slots == 1 && !report.has_cancelled && empty_cancelled(report.cancelled));
        CHECK(report.remaining_count == 1 && !report.finished && wheel->shutdown_cursor == i + 1);
        state_snapshot_t state; CHECK(save_state(wheel, &state) == 0);
        EXPECT(vireo_timer_wheel_shutdown_begin(wheel), VIREO_OK);
        CHECK(unchanged(wheel, &state) == 0);
    }
    EXPECT(vireo_timer_wheel_shutdown_step(wheel, 1, &report), VIREO_OK);
    CHECK(report.scanned_slots == 1 && report.has_cancelled && same_handle(report.cancelled.handle, h[3]));
    CHECK(report.cancelled.timer.deadline_ns == 10 && report.remaining_count == 0 && report.finished);
    EXPECT(vireo_timer_wheel_cancel(wheel, &h[3]), VIREO_RESULT_NOT_FOUND);
    EXPECT(vireo_timer_wheel_destroy(&wheel), VIREO_OK);
    return 0;
}

static int mixed_three_ring_cleanup(void) {
    vireo_timer_wheel_t *wheel = NULL;
    CHECK(make_wheel(4, &wheel) == 0);
    vireo_timer_handle_t h[4] = {{0}}; CHECK(fill_by_slot(wheel, 4, h) == 0);
    vireo_timer_wheel_advance_report_t advance;
    EXPECT(vireo_timer_wheel_advance(wheel, 1, (vireo_timer_wheel_advance_budget_t){1, 1}, &advance), VIREO_OK);
    /* future首项回普通桶，其余pending；晚重排一个变ready，另一个留普通桶。 */
    EXPECT(vireo_timer_wheel_rearm(wheel, h[0], 0, 1), VIREO_OK);
    EXPECT(vireo_timer_wheel_rearm(wheel, h[3], 1, 50), VIREO_OK);
    CHECK(wheel->pending.next != &wheel->pending && wheel->ready_count == 1);
    CHECK(wheel->buckets[0].next != &wheel->buckets[0] && wheel->processing);
    EXPECT(vireo_timer_wheel_shutdown_begin(wheel), VIREO_OK);
    bool seen[4] = {false};
    for (size_t i = 0; i < 4; i++) {
        vireo_timer_wheel_shutdown_report_t report;
        EXPECT(vireo_timer_wheel_shutdown_step(wheel, 4, &report), VIREO_OK);
        CHECK(report.has_cancelled && report.scanned_slots <= 4);
        size_t const slot = report.cancelled.handle.slot_index;
        CHECK(slot < 4 && !seen[slot] && same_handle(report.cancelled.handle, h[slot]));
        seen[slot] = true;
        CHECK(report.cancelled.timer.deadline_ns == (slot == 0 ? 1u : slot == 3 ? 50u : 10u));
        CHECK(report.remaining_count == 3 - i && report.finished == (i == 3));
        EXPECT(vireo_timer_wheel_get(wheel, h[slot], &report.cancelled.timer), VIREO_RESULT_NOT_FOUND);
    }
    CHECK(wheel->pending.next == &wheel->pending && wheel->ready.next == &wheel->ready);
    CHECK(wheel->buckets[0].next == &wheel->buckets[0] && wheel->ready_count == 0);
    CHECK(wheel->latest_now_ns == 1 && wheel->completed_tick == 0 && wheel->processing);
    EXPECT(vireo_timer_wheel_destroy(&wheel), VIREO_OK);
    return 0;
}

static int queries_cancel_and_expired_remain_usable(void) {
    vireo_timer_wheel_t *wheel = NULL;
    CHECK(make_wheel(3, &wheel) == 0);
    vireo_timer_handle_t h[3] = {{0}}; CHECK(fill_by_slot(wheel, 3, h) == 0);
    vireo_timer_wheel_advance_report_t advance;
    EXPECT(vireo_timer_wheel_advance(wheel, 10, (vireo_timer_wheel_advance_budget_t){1, 1}, &advance), VIREO_OK);
    /* 首次只访问tick1，需继续到tick10才发现；不提前将target当访问刻度。 */
    EXPECT(vireo_timer_wheel_advance(wheel, 10, (vireo_timer_wheel_advance_budget_t){10, 30}, &advance), VIREO_OK);
    CHECK(wheel->ready_count == 3);
    EXPECT(vireo_timer_wheel_shutdown_begin(wheel), VIREO_OK);
    vireo_timer_wheel_info_t base;
    vireo_timer_wheel_registry_info_t registry;
    vireo_timer_wheel_progress_t progress;
    EXPECT(vireo_timer_wheel_inspect(wheel, &base), VIREO_OK);
    EXPECT(vireo_timer_wheel_registry_inspect(wheel, &registry), VIREO_OK);
    EXPECT(vireo_timer_wheel_progress_inspect(wheel, &progress), VIREO_OK);
    CHECK(registry.active_count == 3 && progress.caught_up && progress.ready_count == 3);
    EXPECT(vireo_timer_wheel_cancel(wheel, &h[1]), VIREO_OK);
    vireo_timer_wheel_expired_t expired;
    EXPECT(vireo_timer_wheel_take_expired(wheel, &expired), VIREO_OK);
    CHECK(expired.timer.deadline_ns == 10 && wheel->ready_count == 1);
    vireo_timer_wheel_shutdown_report_t report;
    EXPECT(vireo_timer_wheel_shutdown_step(wheel, 3, &report), VIREO_OK);
    CHECK(report.has_cancelled && report.finished && report.cancelled.timer.deadline_ns == 10);
    vireo_timer_wheel_shutdown_info_t info;
    EXPECT(vireo_timer_wheel_shutdown_inspect(wheel, &info), VIREO_OK);
    CHECK(info.stopping && info.active_count == 0 && info.finished);
    EXPECT(vireo_timer_wheel_destroy(&wheel), VIREO_OK);
    return 0;
}

static int ready_failure_four_positions(void) {
    for (size_t position = 0; position < 4; position++) {
        vireo_timer_wheel_t *wheel = NULL;
        CHECK(make_wheel(4, &wheel) == 0);
        vireo_timer_handle_t h[4] = {{0}}; CHECK(fill_by_slot(wheel, 4, h) == 0);
        vireo_timer_wheel_advance_report_t advance;
        EXPECT(vireo_timer_wheel_advance(wheel, 10, (vireo_timer_wheel_advance_budget_t){10, 40}, &advance), VIREO_OK);
        CHECK(wheel->ready_count == 4);
        if (position == 1 || position == 2) {
            EXPECT(vireo_timer_wheel_rearm(wheel, h[0], 0, 10), VIREO_OK);
        }
        if (position == 1) {
            EXPECT(vireo_timer_wheel_rearm(wheel, h[3], 0, 10), VIREO_OK);
        }
        if (position == 3) {
            for (size_t i = 1; i < 4; i++) {
                EXPECT(vireo_timer_wheel_cancel(wheel, &h[i]), VIREO_OK);
            }
        }
        vireo_timer_wheel_link_t const *link = &wheel->nodes[h[0].slot_index].link;
        CHECK((link->prev == &wheel->ready) == (position == 0 || position == 3));
        CHECK((link->next == &wheel->ready) == (position == 2 || position == 3));
        EXPECT(vireo_timer_wheel_shutdown_begin(wheel), VIREO_OK);
        state_snapshot_t state; CHECK(save_state(wheel, &state) == 0);
        report_guard_t report, original;
        memset(&report, 0xc5, sizeof(report)); memcpy(&original, &report, sizeof(report));
        release_probe_t probe = {&wheel->nodes[h[0].slot_index].link, 0, false};
        EXPECT(vireo_timer_wheel_shutdown_step_runtime(wheel, 4, &report.value, release_failure, &probe), VIREO_RESULT_RANGE);
        CHECK(probe.calls == 1 && probe.detached && memcmp(&report, &original, sizeof(report)) == 0);
        CHECK(unchanged(wheel, &state) == 0);
        do {
            EXPECT(vireo_timer_wheel_shutdown_step(wheel, 4, &report.value), VIREO_OK);
        } while (!report.value.finished);
        EXPECT(vireo_timer_wheel_destroy(&wheel), VIREO_OK);
    }
    return 0;
}

static int pending_and_bucket_failure_hold(void) {
    for (size_t pending = 0; pending < 2; pending++) {
        vireo_timer_wheel_t *wheel = NULL;
        CHECK(make_wheel(2, &wheel) == 0);
        vireo_timer_handle_t h[2] = {{0}}; CHECK(fill_by_slot(wheel, 2, h) == 0);
        if (pending != 0) {
            EXPECT(vireo_timer_wheel_rearm(wheel, h[0], 0, 10), VIREO_OK);
        }
        vireo_timer_wheel_advance_report_t advance;
        EXPECT(vireo_timer_wheel_advance(wheel, 1, (vireo_timer_wheel_advance_budget_t){1, 1}, &advance), VIREO_OK);
        CHECK((wheel->pending.next == &wheel->nodes[h[0].slot_index].link) == (pending != 0));
        EXPECT(vireo_timer_wheel_shutdown_begin(wheel), VIREO_OK);
        state_snapshot_t state; CHECK(save_state(wheel, &state) == 0);
        report_guard_t report, original;
        memset(&report, 0xc6, sizeof(report)); memcpy(&original, &report, sizeof(report));
        release_probe_t probe = {&wheel->nodes[h[0].slot_index].link, 0, false};
        EXPECT(vireo_timer_wheel_shutdown_step_runtime(wheel, 2, &report.value, release_failure, &probe), VIREO_RESULT_RANGE);
        CHECK(probe.calls == 1 && probe.detached && unchanged(wheel, &state) == 0);
        CHECK(memcmp(&report, &original, sizeof(report)) == 0);
        EXPECT(vireo_timer_wheel_cancel(wheel, &h[0]), VIREO_OK);
        EXPECT(vireo_timer_wheel_cancel(wheel, &h[1]), VIREO_OK);
        EXPECT(vireo_timer_wheel_destroy(&wheel), VIREO_OK);
    }
    return 0;
}

static int skipped_slot_failure_does_not_publish_cursor(void) {
    vireo_timer_wheel_t *wheel = NULL;
    CHECK(make_wheel(3, &wheel) == 0);
    vireo_timer_handle_t h[3] = {{0}}; CHECK(fill_by_slot(wheel, 3, h) == 0);
    EXPECT(vireo_timer_wheel_cancel(wheel, &h[0]), VIREO_OK);
    EXPECT(vireo_timer_wheel_shutdown_begin(wheel), VIREO_OK);
    state_snapshot_t state; CHECK(save_state(wheel, &state) == 0);
    report_guard_t report, original;
    memset(&report, 0xc7, sizeof(report)); memcpy(&original, &report, sizeof(report));
    release_probe_t probe = {&wheel->nodes[h[1].slot_index].link, 0, false};
    EXPECT(vireo_timer_wheel_shutdown_step_runtime(wheel, 3, &report.value, release_failure, &probe), VIREO_RESULT_RANGE);
    CHECK(probe.calls == 1 && probe.detached && wheel->shutdown_cursor == 0);
    CHECK(unchanged(wheel, &state) == 0 && memcmp(&report, &original, sizeof(report)) == 0);
    EXPECT(vireo_timer_wheel_shutdown_step(wheel, 3, &report.value), VIREO_OK);
    CHECK(report.value.scanned_slots == 2 && report.value.has_cancelled && report.value.remaining_count == 1);
    EXPECT(vireo_timer_wheel_cancel(wheel, &h[2]), VIREO_OK);
    EXPECT(vireo_timer_wheel_destroy(&wheel), VIREO_OK);
    return 0;
}

static int empty_and_repeated_finished(void) {
    vireo_timer_wheel_t *wheel = NULL;
    CHECK(make_wheel(4, &wheel) == 0);
    vireo_timer_wheel_shutdown_info_t info;
    EXPECT(vireo_timer_wheel_shutdown_inspect(wheel, &info), VIREO_OK);
    CHECK(!info.stopping && info.active_count == 0 && !info.finished);
    report_guard_t report, original;
    memset(&report, 0xc8, sizeof(report)); memcpy(&original, &report, sizeof(report));
    state_snapshot_t state; CHECK(save_state(wheel, &state) == 0);
    EXPECT(vireo_timer_wheel_shutdown_step(wheel, 4, &report.value), VIREO_RESULT_BUSY);
    CHECK(unchanged(wheel, &state) == 0 && memcmp(&report, &original, sizeof(report)) == 0);
    EXPECT(vireo_timer_wheel_shutdown_begin(wheel), VIREO_OK);
    EXPECT(vireo_timer_wheel_shutdown_inspect(wheel, &info), VIREO_OK);
    CHECK(info.finished && info.active_count == 0);
    EXPECT(vireo_timer_wheel_shutdown_step(wheel, 65536, &report.value), VIREO_OK);
    CHECK(report.value.scanned_slots == 0 && !report.value.has_cancelled && empty_cancelled(report.value.cancelled));
    CHECK(report.value.finished && report.value.remaining_count == 0 && wheel->shutdown_cursor == 4);
    CHECK(save_state(wheel, &state) == 0);
    EXPECT(vireo_timer_wheel_shutdown_begin(wheel), VIREO_OK);
    EXPECT(vireo_timer_wheel_shutdown_step(wheel, 1, &report.value), VIREO_OK);
    CHECK(report.value.scanned_slots == 0 && unchanged(wheel, &state) == 0);
    EXPECT(vireo_timer_wheel_destroy(&wheel), VIREO_OK);
    CHECK(wheel == NULL);
    return 0;
}

static int maximum_capacity_sparse_scan(void) {
    size_t const capacity = VIREO_TIMER_WHEEL_REGISTRY_MAX_CAPACITY;
    vireo_timer_wheel_t *wheel = NULL;
    CHECK(make_wheel(capacity, &wheel) == 0);
    vireo_timer_handle_t *h = calloc(capacity, sizeof(*h)); CHECK(h != NULL);
    CHECK(fill_by_slot(wheel, capacity, h) == 0);
    for (size_t i = 0; i + 1 < capacity; i++) {
        EXPECT(vireo_timer_wheel_cancel(wheel, &h[i]), VIREO_OK);
    }
    vireo_timer_handle_t const last = h[capacity - 1];
    free(h);
    EXPECT(vireo_timer_wheel_shutdown_begin(wheel), VIREO_OK);
    vireo_timer_wheel_shutdown_report_t report;
    EXPECT(vireo_timer_wheel_shutdown_step(wheel, 65536, &report), VIREO_OK);
    CHECK(report.scanned_slots == 65536 && report.has_cancelled && same_handle(report.cancelled.handle, last));
    CHECK(report.remaining_count == 0 && report.finished);
    EXPECT(vireo_timer_wheel_destroy(&wheel), VIREO_OK);
    return 0;
}

/** @brief 独立外部身份集合，不读取真实cursor/链布局作为期望。 */
static int model_check(vireo_timer_wheel_t *wheel, model_timer_t model[4]) {
    size_t active = 0;
    for (size_t i = 0; i < 4; i++) {
        if (model[i].active) {
            active++;
            vireo_timer_wheel_timer_info_t info;
            EXPECT(vireo_timer_wheel_get(wheel, model[i].handle, &info), VIREO_OK);
            CHECK(info.deadline_ns == model[i].deadline);
        }
    }
    vireo_timer_wheel_shutdown_info_t info;
    EXPECT(vireo_timer_wheel_shutdown_inspect(wheel, &info), VIREO_OK);
    CHECK(info.stopping && info.active_count == active && info.finished == (active == 0));
    vireo_timer_wheel_registry_info_t registry;
    EXPECT(vireo_timer_wheel_registry_inspect(wheel, &registry), VIREO_OK);
    CHECK(registry.active_count == active && registry.available_count == 4 - active);
    return 0;
}

static int independent_shutdown_model(void) {
    for (size_t scenario = 0; scenario < 64; scenario++) {
        vireo_timer_wheel_t *wheel = NULL;
        CHECK(make_wheel(4, &wheel) == 0);
        model_timer_t model[4] = {{0}};
        for (size_t i = 0; i < 4; i++) {
            model[i].deadline = (uint64_t)(i + 1);
            EXPECT(vireo_timer_wheel_register(wheel, 0, model[i].deadline, &model[i].handle), VIREO_OK);
            model[i].active = true;
            if ((scenario & ((size_t)1 << i)) != 0) {
                EXPECT(vireo_timer_wheel_cancel(wheel, &model[i].handle), VIREO_OK);
                model[i].active = false;
            }
        }
        vireo_timer_wheel_advance_report_t advance;
        EXPECT(vireo_timer_wheel_advance(wheel, 5, (vireo_timer_wheel_advance_budget_t){1, 1}, &advance), VIREO_OK);
        if (model[3].active && (scenario & 16u) != 0) {
            EXPECT(vireo_timer_wheel_rearm(wheel, model[3].handle, 5, 50), VIREO_OK);
            model[3].deadline = 50;
        }
        EXPECT(vireo_timer_wheel_shutdown_begin(wheel), VIREO_OK);
        CHECK(model_check(wheel, model) == 0);
        size_t calls = 0;
        vireo_timer_wheel_shutdown_report_t report;
        do {
            if ((scenario & 32u) != 0 && calls == 0 && model[2].active) {
                EXPECT(vireo_timer_wheel_cancel(wheel, &model[2].handle), VIREO_OK);
                model[2].active = false;
            }
            if ((scenario & 16u) != 0 && wheel->ready_count != 0) {
                vireo_timer_wheel_expired_t expired;
                EXPECT(vireo_timer_wheel_take_expired(wheel, &expired), VIREO_OK);
                size_t j = 0;
                while (j < 4 && (!model[j].active || !same_handle(model[j].handle, expired.handle))) {
                    j++;
                }
                CHECK(j < 4 && expired.timer.deadline_ns == model[j].deadline);
                model[j].active = false;
            }
            size_t const budget = (scenario + calls) % 4 + 1;
            EXPECT(vireo_timer_wheel_shutdown_step(wheel, budget, &report), VIREO_OK);
            CHECK(++calls <= 5 && report.scanned_slots <= budget);
            if (report.has_cancelled) {
                size_t j = 0;
                while (j < 4 && (!model[j].active || !same_handle(model[j].handle, report.cancelled.handle))) {
                    j++;
                }
                CHECK(j < 4 && report.cancelled.timer.deadline_ns == model[j].deadline);
                model[j].active = false;
                EXPECT(vireo_timer_wheel_get(wheel, report.cancelled.handle, &report.cancelled.timer), VIREO_RESULT_NOT_FOUND);
            } else {
                CHECK(empty_cancelled(report.cancelled));
            }
            CHECK(model_check(wheel, model) == 0);
            vireo_timer_wheel_shutdown_info_t info;
            EXPECT(vireo_timer_wheel_shutdown_inspect(wheel, &info), VIREO_OK);
            CHECK(report.remaining_count == info.active_count && report.finished == info.finished);
            if (!report.finished) {
                EXPECT(vireo_timer_wheel_destroy(&wheel), VIREO_RESULT_BUSY);
            }
        } while (!report.finished);
        EXPECT(vireo_timer_wheel_destroy(&wheel), VIREO_OK);
    }
    return 0;
}

int main(void) {
    int (*const tests[])(void) = {
        parameters_and_unprepared, begin_idempotence_and_freeze, stopped_admission_and_error_priority,
        sparse_budget_and_single_record, mixed_three_ring_cleanup, queries_cancel_and_expired_remain_usable,
        ready_failure_four_positions, pending_and_bucket_failure_hold, skipped_slot_failure_does_not_publish_cursor,
        empty_and_repeated_finished, maximum_capacity_sparse_scan, independent_shutdown_model,
    };
    int failures = 0;
    for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        failures += tests[i]();
    }
    printf("wheel shutdown: 12 groups, %d failures; independent 64 scenarios; maximum 65536-slot scan; node=%zu control=%zu\n",
           failures, sizeof(vireo_timer_wheel_node_t), sizeof(vireo_timer_wheel_t));
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
