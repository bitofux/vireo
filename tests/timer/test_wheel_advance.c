/*
 * PROJECT : VIREO
 * FILE    : test_wheel_advance.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-09
 * BRIEF   : 此模块负责：
 * -- 核验预算、跨圈、量化边界和可续推进
 * -- 核验 ready 身份生命周期及失败精确回滚
 * -- 用独立有限模型检查到期通知与登记状态
 */
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

/** 小轮失败状态副本；桶/节点均不超过四，owner 只经公开快照读取。 */
typedef struct state_snapshot {
    unsigned char control[sizeof(vireo_timer_wheel_t)]; /**< 含两个内嵌头和所有推进字段的原字节。 */
    unsigned char buckets[4 * sizeof(vireo_timer_wheel_link_t)]; /**< 实际普通桶字节。 */
    unsigned char nodes[4 * sizeof(vireo_timer_wheel_node_t)]; /**< 实际固定节点字节。 */
    vireo_timer_handle_owner_info_t owner; /**< 身份 owner 的公开逻辑值，忽略 padding。 */
} state_snapshot_t;

/** 单次归还失败探针；不得改变身份或轮资源。 */
typedef struct release_probe {
    vireo_timer_wheel_link_t const *link; /**< 被摘下节点的短借链接。 */
    size_t calls; /**< 隔离 release 调用数。 */
    bool detached; /**< 是否观察到自环后才调用 release。 */
} release_probe_t;

/** 失败输出及两侧邻位。 */
typedef struct report_guard {
    uint64_t before; /**< 前邻校验值。 */
    vireo_timer_wheel_advance_report_t value; /**< advance 输出目标。 */
    uint64_t after; /**< 后邻校验值。 */
} report_guard_t;

/** 失败通知及两侧邻位。 */
typedef struct event_guard {
    uint64_t before; /**< 前邻校验值。 */
    vireo_timer_wheel_expired_t value; /**< take 输出目标。 */
    uint64_t after; /**< 后邻校验值。 */
} event_guard_t;

/** 失败进度及两侧邻位。 */
typedef struct progress_guard {
    uint64_t before; /**< 前邻校验值。 */
    vireo_timer_wheel_progress_t value; /**< inspect 输出目标。 */
    uint64_t after; /**< 后邻校验值。 */
} progress_guard_t;

/** 模型只记录外部登记，不模仿桶/槽/推进算法。 */
typedef struct model_timer {
    bool active; /**< 是否仍有有效登记。 */
    vireo_timer_handle_t handle; /**< 实际 public 返回值，不猜槽选择。 */
    uint64_t deadline; /**< 独立期待的原 ns 期限。 */
} model_timer_t;

static bool same_handle(vireo_timer_handle_t a, vireo_timer_handle_t b) {
    return a.owner_id == b.owner_id && a.slot_index == b.slot_index && a.generation == b.generation;
}

static int make_wheel(uint64_t origin, uint64_t tick, uint64_t buckets, size_t capacity,
                       vireo_timer_wheel_t **out) {
    vireo_timer_wheel_options_t const options = {{origin, tick, buckets}, VIREO_TIMER_WHEEL_MAX_MEMORY};
    EXPECT(vireo_timer_wheel_create(&options, out), VIREO_OK);
    vireo_timer_wheel_registry_options_t const registry = {capacity, VIREO_TIMER_WHEEL_REGISTRY_MAX_MEMORY};
    EXPECT(vireo_timer_wheel_prepare(*out, &registry), VIREO_OK);
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

/** @brief 独立枚举所有成员环，核对唯一归属/双向邻位和 public 活跃身份。 */
static int integrity(vireo_timer_wheel_t const *wheel) {
    bool seen[4] = {false};
    CHECK(wheel->timer_capacity <= 4 && wheel->bucket_count <= 4);
    size_t active = 0;
    size_t ready = 0;
    for (size_t ring = 0; ring < wheel->bucket_count + 2; ring++) {
        vireo_timer_wheel_link_t const *head = ring < wheel->bucket_count ? &wheel->buckets[ring] :
            ring == wheel->bucket_count ? &wheel->pending : &wheel->ready;
        CHECK(head->next->prev == head && head->prev->next == head);
        size_t count = 0;
        for (vireo_timer_wheel_link_t const *link = head->next; link != head; link = link->next) {
            CHECK(++count <= wheel->timer_capacity);
            size_t i = 0;
            while (i < wheel->timer_capacity && link != &wheel->nodes[i].link) {
                i++;
            }
            CHECK(i < wheel->timer_capacity && !seen[i]);
            seen[i] = true;
            CHECK(link->prev->next == link && link->next->prev == link);
            CHECK(wheel->nodes[i].ready == (ring == wheel->bucket_count + 1));
            if (ring < wheel->bucket_count) {
                CHECK(wheel->nodes[i].bucket_index == ring);
            }
            EXPECT(vireo_timer_handle_owner_validate(wheel->owner, wheel->nodes[i].handle), VIREO_OK);
            active++;
            ready += wheel->nodes[i].ready ? 1u : 0u;
        }
    }
    for (size_t i = 0; i < wheel->timer_capacity; i++) {
        if (!seen[i]) {
            CHECK(same_handle(wheel->nodes[i].handle, (vireo_timer_handle_t){0}));
            CHECK(!wheel->nodes[i].ready && wheel->nodes[i].link.next == &wheel->nodes[i].link);
            CHECK(wheel->nodes[i].link.prev == &wheel->nodes[i].link);
        }
    }
    vireo_timer_wheel_registry_info_t info;
    EXPECT(vireo_timer_wheel_registry_inspect(wheel, &info), VIREO_OK);
    CHECK(active == info.active_count && ready == wheel->ready_count);
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
    vireo_timer_wheel_options_t const options = {{100, 7, 4}, 4096};
    EXPECT(vireo_timer_wheel_create(&options, &wheel), VIREO_OK);
    state_snapshot_t state;
    CHECK(save_state(wheel, &state) == 0);
    report_guard_t report, original_report;
    event_guard_t event, original_event;
    progress_guard_t progress, original_progress;
    memset(&report, 0xa5, sizeof(report)); memcpy(&original_report, &report, sizeof(report));
    memset(&event, 0xa6, sizeof(event)); memcpy(&original_event, &event, sizeof(event));
    memset(&progress, 0xa7, sizeof(progress)); memcpy(&original_progress, &progress, sizeof(progress));
    vireo_timer_wheel_advance_budget_t const budget = {1, 1};
    EXPECT(vireo_timer_wheel_advance(NULL, 100, budget, &report.value), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_timer_wheel_advance(wheel, 100, budget, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_timer_wheel_advance(wheel, 100, (vireo_timer_wheel_advance_budget_t){0, 1}, &report.value), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_timer_wheel_advance(wheel, 100, (vireo_timer_wheel_advance_budget_t){1, 0}, &report.value), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_timer_wheel_advance(wheel, 100, (vireo_timer_wheel_advance_budget_t){65537, 1}, &report.value), VIREO_RESULT_RANGE);
    EXPECT(vireo_timer_wheel_advance(wheel, 100, (vireo_timer_wheel_advance_budget_t){1, 65537}, &report.value), VIREO_RESULT_RANGE);
    EXPECT(vireo_timer_wheel_advance(wheel, 100, budget, &report.value), VIREO_RESULT_NOT_FOUND);
    EXPECT(vireo_timer_wheel_progress_inspect(NULL, &progress.value), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_timer_wheel_progress_inspect(wheel, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_timer_wheel_progress_inspect(wheel, &progress.value), VIREO_RESULT_NOT_FOUND);
    EXPECT(vireo_timer_wheel_take_expired(NULL, &event.value), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_timer_wheel_take_expired(wheel, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_timer_wheel_take_expired(wheel, &event.value), VIREO_RESULT_NOT_FOUND);
    CHECK(memcmp(&report, &original_report, sizeof(report)) == 0);
    CHECK(memcmp(&event, &original_event, sizeof(event)) == 0);
    CHECK(memcmp(&progress, &original_progress, sizeof(progress)) == 0);
    CHECK(unchanged(wheel, &state) == 0);
    EXPECT(vireo_timer_wheel_destroy(&wheel), VIREO_OK);
    return 0;
}

static int time_and_failure_hold(void) {
    vireo_timer_wheel_t *wheel = NULL;
    CHECK(make_wheel(100, 7, 4, 2, &wheel) == 0);
    vireo_timer_wheel_progress_t progress;
    EXPECT(vireo_timer_wheel_progress_inspect(wheel, &progress), VIREO_OK);
    CHECK(progress.latest_now_ns == 100 && progress.completed_tick == 0 && progress.target_tick == 0);
    CHECK(progress.caught_up && !progress.processing && progress.ready_count == 0);
    vireo_timer_wheel_advance_report_t report;
    EXPECT(vireo_timer_wheel_advance(wheel, 106, (vireo_timer_wheel_advance_budget_t){1, 1}, &report), VIREO_OK);
    CHECK(report.ticks_started == 0 && report.nodes_examined == 0 && report.progress.caught_up);
    state_snapshot_t state; CHECK(save_state(wheel, &state) == 0);
    unsigned char previous[sizeof(report)]; memcpy(previous, &report, sizeof(report));
    EXPECT(vireo_timer_wheel_advance(wheel, 99, (vireo_timer_wheel_advance_budget_t){1, 1}, &report), VIREO_RESULT_RANGE);
    EXPECT(vireo_timer_wheel_advance(wheel, 105, (vireo_timer_wheel_advance_budget_t){1, 1}, &report), VIREO_RESULT_RANGE);
    CHECK(memcmp(previous, &report, sizeof(report)) == 0 && unchanged(wheel, &state) == 0);
    EXPECT(vireo_timer_wheel_advance(wheel, 106, (vireo_timer_wheel_advance_budget_t){1, 1}, &report), VIREO_OK);
    CHECK(report.ticks_started == 0);
    EXPECT(vireo_timer_wheel_destroy(&wheel), VIREO_OK);
    return 0;
}

static int multi_circle_and_resume(void) {
    vireo_timer_wheel_t *wheel = NULL;
    CHECK(make_wheel(1000, 100, 4, 3, &wheel) == 0);
    vireo_timer_handle_t handles[3] = {{0}};
    EXPECT(vireo_timer_wheel_register(wheel, 1000, 1250, &handles[0]), VIREO_OK);
    EXPECT(vireo_timer_wheel_register(wheel, 1000, 1700, &handles[1]), VIREO_OK);
    EXPECT(vireo_timer_wheel_register(wheel, 1000, 1251, &handles[2]), VIREO_OK);
    vireo_timer_wheel_advance_report_t report;
    EXPECT(vireo_timer_wheel_advance(wheel, 1700, (vireo_timer_wheel_advance_budget_t){3, 1}, &report), VIREO_OK);
    CHECK(report.ticks_started == 3 && report.nodes_examined == 1 && report.progress.completed_tick == 2);
    CHECK(report.progress.processing && report.progress.ready_count == 1 && !report.progress.caught_up);
    EXPECT(vireo_timer_wheel_advance(wheel, 1900, (vireo_timer_wheel_advance_budget_t){1, 1}, &report), VIREO_OK);
    CHECK(report.ticks_started == 0 && report.nodes_examined == 1 && report.progress.ready_count == 1);
    CHECK(report.progress.target_tick == 9 && report.progress.completed_tick == 2);
    CHECK(!wheel->nodes[handles[1].slot_index].ready && integrity(wheel) == 0);
    EXPECT(vireo_timer_wheel_advance(wheel, 1900, (vireo_timer_wheel_advance_budget_t){1, 1}, &report), VIREO_OK);
    CHECK(report.ticks_started == 1 && report.nodes_examined == 1 && report.progress.completed_tick == 4);
    CHECK(report.progress.ready_count == 2 && !wheel->nodes[handles[1].slot_index].ready);
    EXPECT(vireo_timer_wheel_advance(wheel, 1900, (vireo_timer_wheel_advance_budget_t){2, 1}, &report), VIREO_OK);
    CHECK(report.progress.completed_tick == 6 && report.nodes_examined == 0);
    EXPECT(vireo_timer_wheel_advance(wheel, 1900, (vireo_timer_wheel_advance_budget_t){1, 1}, &report), VIREO_OK);
    CHECK(report.progress.completed_tick == 7 && report.progress.ready_count == 3);
    CHECK(integrity(wheel) == 0);
    for (size_t i = 0; i < 3; i++) {
        EXPECT(vireo_timer_wheel_cancel(wheel, &handles[i]), VIREO_OK);
    }
    EXPECT(vireo_timer_wheel_destroy(&wheel), VIREO_OK);
    return 0;
}

static int quantization_no_early(void) {
    vireo_timer_wheel_t *wheel = NULL;
    CHECK(make_wheel(1000, 100, 4, 1, &wheel) == 0);
    vireo_timer_handle_t handle = {0};
    EXPECT(vireo_timer_wheel_register(wheel, 1000, 1250, &handle), VIREO_OK);
    vireo_timer_wheel_advance_report_t report;
    EXPECT(vireo_timer_wheel_advance(wheel, 1299, (vireo_timer_wheel_advance_budget_t){4, 4}, &report), VIREO_OK);
    CHECK(report.progress.completed_tick == 2 && report.progress.ready_count == 0);
    vireo_timer_wheel_expired_t event;
    EXPECT(vireo_timer_wheel_take_expired(wheel, &event), VIREO_RESULT_NOT_FOUND);
    EXPECT(vireo_timer_wheel_advance(wheel, 1300, (vireo_timer_wheel_advance_budget_t){4, 4}, &report), VIREO_OK);
    CHECK(report.progress.ready_count == 1 && report.progress.caught_up);
    EXPECT(vireo_timer_wheel_take_expired(wheel, &event), VIREO_OK);
    CHECK(event.timer.deadline_ns == 1250 && event.timer.due_tick == 3 && event.timer.bucket_index == 3);
    CHECK(same_handle(event.handle, handle));
    EXPECT(vireo_timer_wheel_get(wheel, handle, &event.timer), VIREO_RESULT_NOT_FOUND);
    EXPECT(vireo_timer_wheel_destroy(&wheel), VIREO_OK);
    return 0;
}

static int ready_identity_capacity_and_reuse(void) {
    vireo_timer_wheel_t *wheel = NULL;
    CHECK(make_wheel(0, 1, 1, 1, &wheel) == 0);
    vireo_timer_handle_t handle = {0};
    EXPECT(vireo_timer_wheel_register(wheel, 0, 1, &handle), VIREO_OK);
    vireo_timer_wheel_advance_report_t report;
    EXPECT(vireo_timer_wheel_advance(wheel, 1, (vireo_timer_wheel_advance_budget_t){1, 1}, &report), VIREO_OK);
    vireo_timer_wheel_timer_info_t info;
    EXPECT(vireo_timer_wheel_get(wheel, handle, &info), VIREO_OK);
    vireo_timer_handle_t fresh = {0};
    EXPECT(vireo_timer_wheel_register(wheel, 1, 2, &fresh), VIREO_RESULT_BUSY);
    EXPECT(vireo_timer_wheel_destroy(&wheel), VIREO_RESULT_BUSY);
    vireo_timer_wheel_expired_t event;
    EXPECT(vireo_timer_wheel_take_expired(wheel, &event), VIREO_OK);
    CHECK(same_handle(event.handle, handle) && !same_handle(handle, (vireo_timer_handle_t){0}));
    EXPECT(vireo_timer_wheel_cancel(wheel, &handle), VIREO_RESULT_NOT_FOUND);
    EXPECT(vireo_timer_wheel_rearm(wheel, event.handle, 1, 2), VIREO_RESULT_NOT_FOUND);
    EXPECT(vireo_timer_wheel_register(wheel, 1, 2, &fresh), VIREO_OK);
    CHECK(fresh.slot_index == event.handle.slot_index && fresh.generation != event.handle.generation);
    EXPECT(vireo_timer_wheel_get(wheel, event.handle, &info), VIREO_RESULT_NOT_FOUND);
    EXPECT(vireo_timer_wheel_cancel(wheel, &fresh), VIREO_OK);
    EXPECT(vireo_timer_wheel_destroy(&wheel), VIREO_OK);
    return 0;
}

static int late_register_and_ready_rearm(void) {
    vireo_timer_wheel_t *wheel = NULL;
    CHECK(make_wheel(100, 10, 4, 2, &wheel) == 0);
    vireo_timer_wheel_advance_report_t report;
    EXPECT(vireo_timer_wheel_advance(wheel, 150, (vireo_timer_wheel_advance_budget_t){5, 1}, &report), VIREO_OK);
    vireo_timer_handle_t handle = {0};
    /* 保持019-03调用时间规则：不额外拒绝小于latest_now的显式now。 */
    EXPECT(vireo_timer_wheel_register(wheel, 100, 130, &handle), VIREO_OK);
    CHECK(wheel->ready_count == 1 && integrity(wheel) == 0);
    EXPECT(vireo_timer_wheel_rearm(wheel, handle, 150, 190), VIREO_OK);
    CHECK(wheel->ready_count == 0 && !wheel->nodes[handle.slot_index].ready);
    vireo_timer_wheel_expired_t event;
    EXPECT(vireo_timer_wheel_take_expired(wheel, &event), VIREO_RESULT_NOT_FOUND);
    EXPECT(vireo_timer_wheel_rearm(wheel, handle, 100, 140), VIREO_OK);
    CHECK(wheel->ready_count == 1 && integrity(wheel) == 0);
    state_snapshot_t state; CHECK(save_state(wheel, &state) == 0);
    EXPECT(vireo_timer_wheel_rearm(wheel, handle, 150, 150), VIREO_RESULT_TIMEOUT);
    CHECK(unchanged(wheel, &state) == 0);
    EXPECT(vireo_timer_wheel_take_expired(wheel, &event), VIREO_OK);
    CHECK(event.timer.deadline_ns == 140 && same_handle(event.handle, handle));
    EXPECT(vireo_timer_wheel_destroy(&wheel), VIREO_OK);
    return 0;
}

static int pending_mutations_and_late_insert(void) {
    vireo_timer_wheel_t *wheel = NULL;
    CHECK(make_wheel(0, 10, 1, 4, &wheel) == 0);
    vireo_timer_handle_t h[4] = {{0}};
    EXPECT(vireo_timer_wheel_register(wheel, 0, 10, &h[0]), VIREO_OK);
    EXPECT(vireo_timer_wheel_register(wheel, 0, 10, &h[1]), VIREO_OK);
    EXPECT(vireo_timer_wheel_register(wheel, 0, 20, &h[2]), VIREO_OK);
    vireo_timer_wheel_advance_report_t report;
    EXPECT(vireo_timer_wheel_advance(wheel, 30, (vireo_timer_wheel_advance_budget_t){1, 1}, &report), VIREO_OK);
    CHECK(report.progress.processing && wheel->ready_count == 1);
    EXPECT(vireo_timer_wheel_register(wheel, 0, 10, &h[3]), VIREO_OK);
    CHECK(wheel->ready_count == 2); /* due不晚于在访问刻度，直接ready。 */
    EXPECT(vireo_timer_wheel_rearm(wheel, h[1], 30, 50), VIREO_OK); /* 摘pending插普通桶。 */
    EXPECT(vireo_timer_wheel_cancel(wheel, &h[2]), VIREO_OK);
    CHECK(wheel->pending.next == &wheel->pending && integrity(wheel) == 0);
    EXPECT(vireo_timer_wheel_advance(wheel, 30, (vireo_timer_wheel_advance_budget_t){1, 1}, &report), VIREO_OK);
    CHECK(report.progress.completed_tick == 2 && report.nodes_examined == 1 && wheel->ready_count == 2);
    for (size_t i = 0; i < 4; i++) {
        if (!same_handle(h[i], (vireo_timer_handle_t){0})) {
            EXPECT(vireo_timer_wheel_cancel(wheel, &h[i]), VIREO_OK);
        }
    }
    EXPECT(vireo_timer_wheel_destroy(&wheel), VIREO_OK);
    return 0;
}

static int empty_pending_destroy(void) {
    vireo_timer_wheel_t *wheel = NULL;
    CHECK(make_wheel(0, 1, 1, 2, &wheel) == 0);
    vireo_timer_handle_t h[2] = {{0}};
    for (size_t i = 0; i < 2; i++) {
        EXPECT(vireo_timer_wheel_register(wheel, 0, 1, &h[i]), VIREO_OK);
    }
    vireo_timer_wheel_advance_report_t report;
    EXPECT(vireo_timer_wheel_advance(wheel, 1, (vireo_timer_wheel_advance_budget_t){1, 1}, &report), VIREO_OK);
    CHECK(wheel->processing && wheel->pending.next != &wheel->pending);
    EXPECT(vireo_timer_wheel_destroy(&wheel), VIREO_RESULT_BUSY);
    for (size_t i = 0; i < 2; i++) {
        EXPECT(vireo_timer_wheel_cancel(wheel, &h[i]), VIREO_OK);
    }
    CHECK(wheel->processing && wheel->pending.next == &wheel->pending && integrity(wheel) == 0);
    EXPECT(vireo_timer_wheel_destroy(&wheel), VIREO_OK);
    CHECK(wheel == NULL);
    return 0;
}

static int ready_release_exact_rollback(void) {
    vireo_timer_wheel_t *wheel = NULL;
    CHECK(make_wheel(0, 1, 1, 4, &wheel) == 0);
    vireo_timer_handle_t h[4] = {{0}};
    for (size_t i = 0; i < 4; i++) {
        EXPECT(vireo_timer_wheel_register(wheel, 0, 1, &h[i]), VIREO_OK);
    }
    vireo_timer_wheel_advance_report_t report;
    EXPECT(vireo_timer_wheel_advance(wheel, 1, (vireo_timer_wheel_advance_budget_t){1, 4}, &report), VIREO_OK);
    state_snapshot_t state; CHECK(save_state(wheel, &state) == 0);
    event_guard_t event, original;
    memset(&event, 0xc5, sizeof(event)); memcpy(&original, &event, sizeof(event));
    release_probe_t probe = {wheel->ready.next, 0, false};
    EXPECT(vireo_timer_wheel_take_expired_runtime(wheel, &event.value, release_failure, &probe), VIREO_RESULT_RANGE);
    CHECK(probe.calls == 1 && probe.detached && memcmp(&event, &original, sizeof(event)) == 0);
    CHECK(unchanged(wheel, &state) == 0 && integrity(wheel) == 0);
    /* first/middle/last/only 的失败保持；成功取消后重新快照下一场景。 */
    size_t const order[4] = {1, 0, 3, 2};
    for (size_t i = 0; i < 4; i++) {
        size_t const j = order[i];
        CHECK(save_state(wheel, &state) == 0);
        vireo_timer_handle_t const old = h[j];
        probe = (release_probe_t){&wheel->nodes[h[j].slot_index].link, 0, false};
        EXPECT(vireo_timer_wheel_cancel_runtime(wheel, &h[j], release_failure, &probe), VIREO_RESULT_RANGE);
        CHECK(probe.calls == 1 && probe.detached && same_handle(h[j], old));
        CHECK(unchanged(wheel, &state) == 0 && integrity(wheel) == 0);
        EXPECT(vireo_timer_wheel_cancel(wheel, &h[j]), VIREO_OK);
    }
    CHECK(save_state(wheel, &state) == 0);
    EXPECT(vireo_timer_wheel_take_expired(wheel, &event.value), VIREO_RESULT_NOT_FOUND);
    CHECK(memcmp(&event, &original, sizeof(event)) == 0 && unchanged(wheel, &state) == 0);
    EXPECT(vireo_timer_wheel_destroy(&wheel), VIREO_OK);
    return 0;
}

static int empty_large_span_and_hard_budget(void) {
    vireo_timer_wheel_t *wheel = NULL;
    CHECK(make_wheel(0, 1, 1, 1, &wheel) == 0);
    vireo_timer_wheel_advance_report_t report;
    EXPECT(vireo_timer_wheel_advance(wheel, UINT64_MAX, (vireo_timer_wheel_advance_budget_t){65536, 65536}, &report), VIREO_OK);
    CHECK(report.ticks_started == 65536 && report.nodes_examined == 0);
    CHECK(report.progress.completed_tick == 65536 && !report.progress.caught_up);
    EXPECT(vireo_timer_wheel_advance(wheel, UINT64_MAX, (vireo_timer_wheel_advance_budget_t){1, 1}, &report), VIREO_OK);
    CHECK(report.progress.completed_tick == 65537 && report.ticks_started == 1);
    EXPECT(vireo_timer_wheel_destroy(&wheel), VIREO_OK);
    return 0;
}

static int maximum_finite_tick(void) {
    vireo_timer_wheel_t *wheel = NULL;
    CHECK(make_wheel(0, 1, 1, 1, &wheel) == 0);
    /* own 合法边界状态夹具，替代不可运行的MAX次数，不冒真实长期推进。 */
    wheel->completed_tick = UINT64_MAX - 1;
    wheel->latest_now_ns = UINT64_MAX - 1;
    vireo_timer_handle_t h = {0};
    EXPECT(vireo_timer_wheel_register(wheel, UINT64_MAX - 1, UINT64_MAX, &h), VIREO_OK);
    vireo_timer_wheel_advance_report_t report;
    EXPECT(vireo_timer_wheel_advance(wheel, UINT64_MAX, (vireo_timer_wheel_advance_budget_t){1, 1}, &report), VIREO_OK);
    CHECK(report.progress.completed_tick == UINT64_MAX && report.progress.caught_up);
    CHECK(report.progress.ready_count == 1 && integrity(wheel) == 0);
    EXPECT(vireo_timer_wheel_advance(wheel, UINT64_MAX, (vireo_timer_wheel_advance_budget_t){1, 1}, &report), VIREO_OK);
    CHECK(report.ticks_started == 0 && report.nodes_examined == 0);
    vireo_timer_wheel_expired_t event;
    EXPECT(vireo_timer_wheel_take_expired(wheel, &event), VIREO_OK);
    CHECK(event.timer.due_tick == UINT64_MAX && event.timer.deadline_ns == UINT64_MAX);
    EXPECT(vireo_timer_wheel_destroy(&wheel), VIREO_OK);
    CHECK(make_wheel(UINT64_MAX, 1, 1, 1, &wheel) == 0);
    EXPECT(vireo_timer_wheel_advance(wheel, UINT64_MAX, (vireo_timer_wheel_advance_budget_t){1, 1}, &report), VIREO_OK);
    CHECK(report.progress.target_tick == 0 && report.progress.completed_tick == 0 && report.progress.caught_up);
    EXPECT(vireo_timer_wheel_destroy(&wheel), VIREO_OK);
    return 0;
}

/** @brief 小范围独立逐边界枚举，不调用生产量化或桶函数。 */
static uint64_t model_boundary(uint64_t deadline) {
    uint64_t boundary = 100;
    while (boundary < deadline) {
        boundary += 7;
    }
    return boundary;
}

static int model_check(vireo_timer_wheel_t *wheel, model_timer_t model[4], uint64_t now,
                        bool caught_up) {
    size_t active = 0;
    size_t due = 0;
    for (size_t i = 0; i < 4; i++) {
        if (model[i].active) {
            active++;
            due += model_boundary(model[i].deadline) <= now ? 1u : 0u;
            vireo_timer_wheel_timer_info_t info;
            EXPECT(vireo_timer_wheel_get(wheel, model[i].handle, &info), VIREO_OK);
            CHECK(info.deadline_ns == model[i].deadline);
        }
    }
    vireo_timer_wheel_registry_info_t info;
    EXPECT(vireo_timer_wheel_registry_inspect(wheel, &info), VIREO_OK);
    CHECK(info.active_count == active && info.available_count == 4 - active);
    if (caught_up) {
        CHECK(wheel->ready_count == due);
    }
    CHECK(integrity(wheel) == 0);
    return 0;
}

static int independent_state_model(void) {
    vireo_timer_wheel_t *wheel = NULL;
    CHECK(make_wheel(100, 7, 4, 4, &wheel) == 0);
    model_timer_t model[4] = {{0}};
    uint64_t now = 100;
    for (size_t step = 0; step < 600; step++) {
        size_t const i = (step * 3 + step / 7) % 4;
        if (step % 5 == 0 && model[i].active) {
            EXPECT(vireo_timer_wheel_cancel(wheel, &model[i].handle), VIREO_OK);
            model[i].active = false;
        } else if (step % 3 == 0 && model[i].active) {
            uint64_t const deadline = now + (uint64_t)(step % 23) + 1;
            EXPECT(vireo_timer_wheel_rearm(wheel, model[i].handle, now, deadline), VIREO_OK);
            model[i].deadline = deadline;
        } else if (!model[i].active) {
            model[i].deadline = now + (uint64_t)(step % 37) + 1;
            EXPECT(vireo_timer_wheel_register(wheel, now, model[i].deadline, &model[i].handle), VIREO_OK);
            model[i].active = true;
        }
        now += (uint64_t)(step % 4);
        vireo_timer_wheel_advance_budget_t const budget = {step % 3 + 1, step % 2 + 1};
        vireo_timer_wheel_advance_report_t report;
        EXPECT(vireo_timer_wheel_advance(wheel, now, budget, &report), VIREO_OK);
        CHECK(report.ticks_started <= budget.max_ticks && report.nodes_examined <= budget.max_nodes);
        CHECK(model_check(wheel, model, now, report.progress.caught_up) == 0);
        vireo_timer_wheel_expired_t event;
        while (wheel->ready_count != 0) {
            EXPECT(vireo_timer_wheel_take_expired(wheel, &event), VIREO_OK);
            CHECK(model_boundary(event.timer.deadline_ns) <= now);
            size_t j = 0;
            while (j < 4 && (!model[j].active || !same_handle(model[j].handle, event.handle))) {
                j++;
            }
            CHECK(j < 4 && event.timer.deadline_ns == model[j].deadline);
            model[j].active = false;
            model[j].handle = (vireo_timer_handle_t){0};
            EXPECT(vireo_timer_wheel_get(wheel, event.handle, &event.timer), VIREO_RESULT_NOT_FOUND);
        }
        CHECK(model_check(wheel, model, now, report.progress.caught_up) == 0);
    }
    now += 100;
    vireo_timer_wheel_advance_report_t report;
    size_t calls = 0;
    do {
        EXPECT(vireo_timer_wheel_advance(wheel, now, (vireo_timer_wheel_advance_budget_t){1, 1}, &report), VIREO_OK);
        CHECK(++calls <= 100);
    } while (!report.progress.caught_up);
    CHECK(model_check(wheel, model, now, true) == 0);
    vireo_timer_wheel_expired_t event;
    while (wheel->ready_count != 0) {
        EXPECT(vireo_timer_wheel_take_expired(wheel, &event), VIREO_OK);
        size_t j = 0;
        while (j < 4 && (!model[j].active || !same_handle(model[j].handle, event.handle))) {
            j++;
        }
        CHECK(j < 4 && model_boundary(model[j].deadline) <= now);
        model[j].active = false;
    }
    CHECK(model_check(wheel, model, now, true) == 0);
    EXPECT(vireo_timer_wheel_destroy(&wheel), VIREO_OK);
    return 0;
}

int main(void) {
    int (*const tests[])(void) = {
        parameters_and_unprepared, time_and_failure_hold, multi_circle_and_resume,
        quantization_no_early, ready_identity_capacity_and_reuse, late_register_and_ready_rearm,
        pending_mutations_and_late_insert, empty_pending_destroy, ready_release_exact_rollback,
        empty_large_span_and_hard_budget, maximum_finite_tick, independent_state_model,
    };
    int failures = 0;
    for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        failures += tests[i]();
    }
    printf("wheel advance: 12 groups, %d failures; independent 600 transitions; node=%zu control=%zu\n",
           failures, sizeof(vireo_timer_wheel_node_t), sizeof(vireo_timer_wheel_t));
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
