/*
 * PROJECT : VIREO
 * FILE    : test_wheel_registry.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-09
 * BRIEF   : 此模块负责：
 * -- 核验真实身份登记、跨圈桶、取消和保留身份的重排
 * -- 验证预算、失败保持、依赖错误传播和精确链位回滚
 * -- 用独立有限状态模型核对公开快照与环完整性
 */
#include <vireo/timer/wheel_registry.h>
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

/** 仅记录本轮 allocator 的申请；public owner 的内存由其公开生命周期管理。 */
typedef struct allocation_probe {
    size_t calls; /**< 累计申请尝试，含失败。 */
    size_t fail_at; /**< 指定失败序号，0 关闭。 */
    size_t live; /**< 当前存活申请数。 */
    size_t frees; /**< 累计释放次数。 */
    void *pointers[8]; /**< 各尝试取得的存活地址，释放后 NULL。 */
    size_t bytes[8]; /**< 对应请求量，单位字节。 */
    bool reverse_order; /**< 释放是否始终针对最后存活申请。 */
} allocation_probe_t;

/** 只在本次隔离调用中借用；不冒充物理耗尽或原生 owner 缺陷。 */
typedef struct dependency_probe {
    size_t calls; /**< factory/acquire/release 被调用次数。 */
    vireo_result_t result; /**< 明确注入的失败结果，不注入成功。 */
    vireo_timer_wheel_link_t const *link; /**< release 时短借被摘下节点，其他路径 NULL。 */
    bool detached; /**< release 是否观察到节点已自环。 */
} dependency_probe_t;

/** 输出前后邻位，逐字节核验失败保持。 */
typedef struct timer_guard {
    uint64_t before; /**< 邻位 11。 */
    vireo_timer_wheel_timer_info_t value; /**< get 的真实输出。 */
    uint64_t after; /**< 邻位 19。 */
} timer_guard_t;

/** 小轮失败快照；只用于桶和容量均不超过四的夹具。 */
typedef struct state_snapshot {
    unsigned char control[sizeof(vireo_timer_wheel_t)]; /**< 控制块原始字节。 */
    unsigned char buckets[4 * sizeof(vireo_timer_wheel_link_t)]; /**< 实际桶表字节。 */
    unsigned char nodes[4 * sizeof(vireo_timer_wheel_node_t)]; /**< 已准备节点表字节。 */
    vireo_timer_handle_owner_info_t owner; /**< public 数值快照，比较逻辑字段而非 padding。 */
} state_snapshot_t;

/** 独立模型只记录业务可见状态，不复制真实槽选择或链布局算法。 */
typedef struct model_timer {
    bool active; /**< 此模型记录是否持有未取消的登记。 */
    vireo_timer_handle_t handle; /**< public 返回身份；不预测空闲槽选择。 */
    uint64_t deadline; /**< 期望原始 ns 期限。 */
} model_timer_t;

static bool same_handle(vireo_timer_handle_t a, vireo_timer_handle_t b) {
    return a.owner_id == b.owner_id && a.slot_index == b.slot_index && a.generation == b.generation;
}

static bool empty_handle(vireo_timer_handle_t a) {
    return same_handle(a, (vireo_timer_handle_t){0});
}

static void *probe_allocate(size_t bytes, void *context) {
    allocation_probe_t *p = context;
    size_t const index = p->calls++;
    errno = ENOMEM;
    if (index >= 8 || p->calls == p->fail_at) {
        return NULL;
    }
    void *memory = malloc(bytes);
    p->pointers[index] = memory;
    p->bytes[index] = bytes;
    if (memory != NULL) {
        memset(memory, 0xA5, bytes);
        p->live++;
    }
    return memory;
}

static void probe_deallocate(void *memory, void *context) {
    allocation_probe_t *p = context;
    size_t found = SIZE_MAX;
    size_t last = SIZE_MAX;
    for (size_t i = 0; i < 8; i++) {
        if (p->pointers[i] != NULL) {
            last = i;
            if (p->pointers[i] == memory) {
                found = i;
            }
        }
    }
    if (found == SIZE_MAX || found != last) {
        p->reverse_order = false;
    }
    if (found != SIZE_MAX) {
        p->pointers[found] = NULL;
        p->live--;
    }
    p->frees++;
    free(memory);
    errno = EIO;
}

static vireo_result_t factory_failure(vireo_timer_handle_owner_options_t const *options,
                                     vireo_timer_handle_owner_t **out, void *context) {
    (void)options;
    (void)out;
    dependency_probe_t *p = context;
    p->calls++;
    errno = EIO;
    return p->result;
}

static vireo_result_t acquire_failure(vireo_timer_handle_owner_t *owner,
                                     vireo_timer_handle_t *out, void *context) {
    (void)owner;
    (void)out;
    dependency_probe_t *p = context;
    p->calls++;
    errno = EIO;
    return p->result;
}

static vireo_result_t release_failure(vireo_timer_handle_owner_t *owner,
                                     vireo_timer_handle_t *handle, void *context) {
    (void)owner;
    (void)handle;
    dependency_probe_t *p = context;
    p->calls++;
    p->detached = p->link->prev == p->link && p->link->next == p->link;
    errno = EIO;
    return p->result;
}

static int create_wheel(vireo_timer_wheel_t **out, uint64_t origin, uint64_t tick,
                        uint64_t buckets, allocation_probe_t *probe) {
    vireo_timer_wheel_options_t const options = {{origin, tick, buckets}, VIREO_TIMER_WHEEL_MAX_MEMORY};
    if (probe == NULL) {
        EXPECT(vireo_timer_wheel_create(&options, out), VIREO_OK);
    } else {
        vireo_timer_wheel_allocator_t const allocator = {probe_allocate, probe_deallocate, probe};
        EXPECT(vireo_timer_wheel_create_runtime(&options, out, &allocator), VIREO_OK);
    }
    return 0;
}

static int prepare(vireo_timer_wheel_t *wheel, size_t capacity) {
    vireo_timer_wheel_registry_options_t const options = {capacity, VIREO_TIMER_WHEEL_REGISTRY_MAX_MEMORY};
    EXPECT(vireo_timer_wheel_prepare(wheel, &options), VIREO_OK);
    return 0;
}

static int capture(vireo_timer_wheel_t const *wheel, state_snapshot_t *out) {
    CHECK(wheel->bucket_count <= 4 && wheel->timer_capacity <= 4);
    memset(out, 0, sizeof(*out));
    memcpy(out->control, wheel, sizeof(*wheel));
    memcpy(out->buckets, wheel->buckets, wheel->bucket_count * sizeof(*wheel->buckets));
    if (wheel->owner != NULL) {
        memcpy(out->nodes, wheel->nodes, wheel->node_bytes);
        EXPECT(vireo_timer_handle_owner_inspect(wheel->owner, &out->owner), VIREO_OK);
    }
    return 0;
}

static int unchanged(vireo_timer_wheel_t const *wheel, state_snapshot_t const *old) {
    CHECK(memcmp(old->control, wheel, sizeof(*wheel)) == 0);
    CHECK(memcmp(old->buckets, wheel->buckets, wheel->bucket_count * sizeof(*wheel->buckets)) == 0);
    if (wheel->owner != NULL) {
        CHECK(memcmp(old->nodes, wheel->nodes, wheel->node_bytes) == 0);
        vireo_timer_handle_owner_info_t now;
        EXPECT(vireo_timer_handle_owner_inspect(wheel->owner, &now), VIREO_OK);
        CHECK(now.owner_id == old->owner.owner_id && now.last_generation == old->owner.last_generation);
        CHECK(now.capacity == old->owner.capacity && now.active_count == old->owner.active_count);
        CHECK(now.available_count == old->owner.available_count);
        CHECK(now.allocation_bytes == old->owner.allocation_bytes && now.max_memory_bytes == old->owner.max_memory_bytes);
    }
    return 0;
}

/** 有界遍历真实环，并核对每个活跃节点恰一次、空闲节点自环。 */
static int ring_integrity(vireo_timer_wheel_t const *wheel, size_t expected_active) {
    size_t total = 0;
    for (size_t b = 0; b < wheel->bucket_count; b++) {
        vireo_timer_wheel_link_t const *head = &wheel->buckets[b];
        CHECK(head->next->prev == head && head->prev->next == head);
        size_t count = 0;
        for (vireo_timer_wheel_link_t const *link = head->next; link != head; link = link->next) {
            CHECK(++count <= wheel->timer_capacity);
            CHECK(link->next->prev == link && link->prev->next == link);
            size_t found = 0;
            for (size_t i = 0; i < wheel->timer_capacity; i++) {
                if (link == &wheel->nodes[i].link) {
                    CHECK(!empty_handle(wheel->nodes[i].handle) && wheel->nodes[i].bucket_index == b);
                    found++;
                }
            }
            CHECK(found == 1);
        }
        total += count;
    }
    CHECK(total == expected_active);
    size_t active = 0;
    for (size_t i = 0; i < wheel->timer_capacity; i++) {
        vireo_timer_wheel_node_t const *n = &wheel->nodes[i];
        if (empty_handle(n->handle)) {
            CHECK(n->link.prev == &n->link && n->link.next == &n->link);
        } else {
            active++;
            size_t occurrences = 0;
            vireo_timer_wheel_link_t const *head = &wheel->buckets[n->bucket_index];
            size_t visited = 0;
            for (vireo_timer_wheel_link_t const *link = head->next; link != head; link = link->next) {
                CHECK(++visited <= wheel->timer_capacity);
                if (link == &n->link) {
                    occurrences++;
                }
            }
            CHECK(occurrences == 1);
        }
    }
    CHECK(active == expected_active);
    return 0;
}

static int parameters_and_unprepared(void) {
    vireo_timer_wheel_t *wheel = NULL;
    CHECK(create_wheel(&wheel, 1000, 100, 4, NULL) == 0);
    vireo_timer_wheel_registry_options_t options = {2, VIREO_TIMER_WHEEL_REGISTRY_MAX_MEMORY};
    vireo_timer_handle_t h = {0};
    timer_guard_t guard;
    memset(&guard, 0x7C, sizeof(guard));
    unsigned char saved[sizeof(guard)];
    memcpy(saved, &guard, sizeof(guard));
    EXPECT(vireo_timer_wheel_prepare(NULL, &options), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_timer_wheel_prepare(wheel, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_timer_wheel_registry_inspect(wheel, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    vireo_timer_wheel_registry_info_t info;
    memset(&info, 0x7C, sizeof(info));
    unsigned char info_saved[sizeof(info)];
    memcpy(info_saved, &info, sizeof(info));
    EXPECT(vireo_timer_wheel_registry_inspect(NULL, &info), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(memcmp(info_saved, &info, sizeof(info)) == 0);
    EXPECT(vireo_timer_wheel_registry_inspect(wheel, &info), VIREO_OK);
    CHECK(!info.prepared && info.capacity == 0 && info.active_count == 0 && info.available_count == 0);
    CHECK(info.allocation_bytes == 0 && info.max_memory_bytes == 0);
    EXPECT(vireo_timer_wheel_register(NULL, 1000, 1100, &h), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_timer_wheel_register(wheel, 1000, 1100, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_timer_wheel_register(wheel, 1000, 1100, &h), VIREO_RESULT_NOT_FOUND);
    CHECK(empty_handle(h));
    EXPECT(vireo_timer_wheel_get(wheel, h, &guard.value), VIREO_RESULT_NOT_FOUND);
    EXPECT(vireo_timer_wheel_get(NULL, h, &guard.value), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_timer_wheel_get(wheel, h, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_timer_wheel_cancel(wheel, &h), VIREO_RESULT_NOT_FOUND);
    EXPECT(vireo_timer_wheel_cancel(wheel, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_timer_wheel_cancel(NULL, &h), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_timer_wheel_rearm(wheel, h, 1000, 1100), VIREO_RESULT_NOT_FOUND);
    EXPECT(vireo_timer_wheel_rearm(NULL, h, 1000, 1100), VIREO_RESULT_INVALID_ARGUMENT);
    h = (vireo_timer_handle_t){0, 1, 1};
    EXPECT(vireo_timer_wheel_register(wheel, 1000, 1100, &h), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_timer_wheel_get(wheel, h, &guard.value), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_timer_wheel_cancel(wheel, &h), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_timer_wheel_rearm(wheel, h, 1000, 1100), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(memcmp(saved, &guard, sizeof(guard)) == 0);
    EXPECT(vireo_timer_wheel_prepare_runtime(wheel, &options, NULL, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    h = (vireo_timer_handle_t){0};
    EXPECT(vireo_timer_wheel_register_runtime(wheel, 1000, 1100, &h, NULL, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_timer_wheel_cancel_runtime(wheel, &h, NULL, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_timer_wheel_destroy(&wheel), VIREO_OK);
    return 0;
}

static int prepare_limits(void) {
    vireo_timer_wheel_t *wheel = NULL;
    CHECK(create_wheel(&wheel, 1000, 100, 4, NULL) == 0);
    state_snapshot_t saved;
    CHECK(capture(wheel, &saved) == 0);
    vireo_timer_wheel_registry_options_t options = {0, 1};
    EXPECT(vireo_timer_wheel_prepare(wheel, &options), VIREO_RESULT_INVALID_ARGUMENT);
    options = (vireo_timer_wheel_registry_options_t){1, 0};
    EXPECT(vireo_timer_wheel_prepare(wheel, &options), VIREO_RESULT_INVALID_ARGUMENT);
    options = (vireo_timer_wheel_registry_options_t){SIZE_MAX, VIREO_TIMER_WHEEL_REGISTRY_MAX_MEMORY};
    EXPECT(vireo_timer_wheel_prepare(wheel, &options), VIREO_RESULT_OVERFLOW);
    options.capacity = VIREO_TIMER_WHEEL_REGISTRY_MAX_CAPACITY + 1;
    EXPECT(vireo_timer_wheel_prepare(wheel, &options), VIREO_RESULT_RANGE);
    options = (vireo_timer_wheel_registry_options_t){1, VIREO_TIMER_WHEEL_REGISTRY_MAX_MEMORY + 1};
    EXPECT(vireo_timer_wheel_prepare(wheel, &options), VIREO_RESULT_RANGE);
    options = (vireo_timer_wheel_registry_options_t){1, sizeof(vireo_timer_wheel_node_t)};
    EXPECT(vireo_timer_wheel_prepare(wheel, &options), VIREO_RESULT_RANGE);
    options.max_memory_bytes--;
    EXPECT(vireo_timer_wheel_prepare(wheel, &options), VIREO_RESULT_RANGE);
    CHECK(unchanged(wheel, &saved) == 0);
    CHECK(prepare(wheel, 2) == 0);
    CHECK(capture(wheel, &saved) == 0);
    options = (vireo_timer_wheel_registry_options_t){2, VIREO_TIMER_WHEEL_REGISTRY_MAX_MEMORY};
    EXPECT(vireo_timer_wheel_prepare(wheel, &options), VIREO_RESULT_BUSY);
    options.capacity = 0;
    EXPECT(vireo_timer_wheel_prepare(wheel, &options), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(unchanged(wheel, &saved) == 0);
    EXPECT(vireo_timer_wheel_destroy(&wheel), VIREO_OK);
    return 0;
}

static int budget_and_snapshot(void) {
    /* 实际 public owner 请求量只能观测，不引用其 private sizeof。 */
    vireo_timer_handle_owner_options_t const owner_options = {3, VIREO_TIMER_HANDLE_OWNER_MAX_MEMORY};
    vireo_timer_handle_owner_t *owner = NULL;
    EXPECT(vireo_timer_handle_owner_create(&owner_options, &owner), VIREO_OK);
    vireo_timer_handle_owner_info_t owner_info;
    EXPECT(vireo_timer_handle_owner_inspect(owner, &owner_info), VIREO_OK);
    size_t const needed = 3 * sizeof(vireo_timer_wheel_node_t) + owner_info.allocation_bytes;
    EXPECT(vireo_timer_handle_owner_destroy(&owner), VIREO_OK);
    allocation_probe_t probe = {.reverse_order = true};
    vireo_timer_wheel_t *wheel = NULL;
    CHECK(create_wheel(&wheel, 1000, 100, 4, &probe) == 0);
    state_snapshot_t saved;
    CHECK(capture(wheel, &saved) == 0);
    vireo_timer_wheel_registry_options_t options = {3, needed - 1};
    EXPECT(vireo_timer_wheel_prepare(wheel, &options), VIREO_RESULT_RANGE);
    CHECK(unchanged(wheel, &saved) == 0 && probe.live == 2 && probe.frees == 1);
    options.max_memory_bytes = needed;
    EXPECT(vireo_timer_wheel_prepare(wheel, &options), VIREO_OK);
    options.capacity = 0;
    options.max_memory_bytes = 1;
    vireo_timer_wheel_registry_info_t info;
    EXPECT(vireo_timer_wheel_registry_inspect(wheel, &info), VIREO_OK);
    CHECK(info.prepared && info.capacity == 3 && info.active_count == 0 && info.available_count == 3);
    CHECK(info.allocation_bytes == needed && info.max_memory_bytes == needed);
    vireo_timer_wheel_info_t base;
    EXPECT(vireo_timer_wheel_inspect(wheel, &base), VIREO_OK);
    CHECK(base.allocation_bytes == sizeof(*wheel) + 4 * sizeof(vireo_timer_wheel_link_t));
    CHECK(base.max_memory_bytes == VIREO_TIMER_WHEEL_MAX_MEMORY);
    info.capacity = 0;
    EXPECT(vireo_timer_wheel_registry_inspect(wheel, &info), VIREO_OK);
    CHECK(info.capacity == 3 && ring_integrity(wheel, 0) == 0);
    EXPECT(vireo_timer_wheel_destroy(&wheel), VIREO_OK);
    CHECK(wheel == NULL && probe.live == 0 && probe.frees == 4 && probe.reverse_order);
    /* 数值快照不借用轮资源。 */
    CHECK(info.allocation_bytes == needed && base.geometry.origin_ns == 1000);
    return 0;
}

static int node_allocation_failure(void) {
    allocation_probe_t probe = {.fail_at = 3, .reverse_order = true};
    vireo_timer_wheel_t *wheel = NULL;
    CHECK(create_wheel(&wheel, 1000, 100, 4, &probe) == 0);
    state_snapshot_t saved;
    CHECK(capture(wheel, &saved) == 0);
    vireo_timer_wheel_registry_options_t const options = {2, VIREO_TIMER_WHEEL_REGISTRY_MAX_MEMORY};
    EXPECT(vireo_timer_wheel_prepare(wheel, &options), VIREO_RESULT_NO_MEMORY);
    CHECK(unchanged(wheel, &saved) == 0 && probe.calls == 3 && probe.live == 2 && probe.frees == 0);
    probe.fail_at = 0;
    EXPECT(vireo_timer_wheel_prepare(wheel, &options), VIREO_OK);
    CHECK(probe.calls == 4 && probe.live == 3);
    EXPECT(vireo_timer_wheel_destroy(&wheel), VIREO_OK);
    CHECK(probe.live == 0 && probe.frees == 3 && probe.reverse_order);
    return 0;
}

static int owner_creation_failure(void) {
    allocation_probe_t probe = {.reverse_order = true};
    vireo_timer_wheel_t *wheel = NULL;
    CHECK(create_wheel(&wheel, 1000, 100, 4, &probe) == 0);
    state_snapshot_t saved;
    CHECK(capture(wheel, &saved) == 0);
    vireo_timer_wheel_registry_options_t const options = {2, VIREO_TIMER_WHEEL_REGISTRY_MAX_MEMORY};
    dependency_probe_t dependency = {.result = VIREO_RESULT_NO_MEMORY};
    EXPECT(vireo_timer_wheel_prepare_runtime(wheel, &options, factory_failure, &dependency), VIREO_RESULT_NO_MEMORY);
    CHECK(unchanged(wheel, &saved) == 0 && probe.live == 2 && probe.frees == 1);
    dependency.result = VIREO_RESULT_OVERFLOW;
    EXPECT(vireo_timer_wheel_prepare_runtime(wheel, &options, factory_failure, &dependency), VIREO_RESULT_OVERFLOW);
    CHECK(unchanged(wheel, &saved) == 0 && probe.live == 2 && probe.frees == 2 && dependency.calls == 2);
    EXPECT(vireo_timer_wheel_prepare(wheel, &options), VIREO_OK);
    EXPECT(vireo_timer_wheel_destroy(&wheel), VIREO_OK);
    CHECK(probe.live == 0 && probe.frees == 5 && probe.reverse_order);
    return 0;
}

static int golden_buckets(void) {
    vireo_timer_wheel_t *wheel = NULL;
    CHECK(create_wheel(&wheel, 1000, 100, 4, NULL) == 0 && prepare(wheel, 3) == 0);
    uint64_t const deadlines[3] = {1250, 1450, 1650};
    uint64_t const ticks[3] = {3, 5, 7};
    uint64_t const buckets[3] = {3, 1, 3};
    vireo_timer_handle_t handles[3] = {{0}};
    for (size_t i = 0; i < 3; i++) {
        EXPECT(vireo_timer_wheel_register(wheel, 1000, deadlines[i], &handles[i]), VIREO_OK);
        timer_guard_t out = {.before = 11, .after = 19};
        EXPECT(vireo_timer_wheel_get(wheel, handles[i], &out.value), VIREO_OK);
        CHECK(out.value.deadline_ns == deadlines[i] && out.value.due_tick == ticks[i]);
        CHECK(out.value.bucket_index == buckets[i] && out.before == 11 && out.after == 19);
        CHECK(handles[i].generation == (uint64_t)i + 1);
        CHECK(ring_integrity(wheel, i + 1) == 0);
    }
    /* 查询不读现在的时钟、不移除过期登记；两个不同圈期限可位于同一桶。 */
    vireo_timer_wheel_timer_info_t info;
    EXPECT(vireo_timer_wheel_get(wheel, handles[0], &info), VIREO_OK);
    CHECK(info.deadline_ns == 1250);
    for (size_t i = 0; i < 3; i++) {
        EXPECT(vireo_timer_wheel_cancel(wheel, &handles[i]), VIREO_OK);
    }
    CHECK(ring_integrity(wheel, 0) == 0);
    EXPECT(vireo_timer_wheel_destroy(&wheel), VIREO_OK);
    return 0;
}

static int time_boundaries(void) {
    vireo_timer_wheel_t *wheel = NULL;
    CHECK(create_wheel(&wheel, 0, 1, 4, NULL) == 0 && prepare(wheel, 1) == 0);
    vireo_timer_handle_t h = {0};
    EXPECT(vireo_timer_wheel_register(wheel, UINT64_MAX - 1, UINT64_MAX, &h), VIREO_OK);
    vireo_timer_wheel_timer_info_t info;
    EXPECT(vireo_timer_wheel_get(wheel, h, &info), VIREO_OK);
    CHECK(info.deadline_ns == UINT64_MAX && info.due_tick == UINT64_MAX && info.bucket_index == 3);
    EXPECT(vireo_timer_wheel_rearm(wheel, h, 0, 1), VIREO_OK);
    EXPECT(vireo_timer_wheel_get(wheel, h, &info), VIREO_OK);
    CHECK(info.deadline_ns == 1 && info.due_tick == 1 && info.bucket_index == 1);
    EXPECT(vireo_timer_wheel_cancel(wheel, &h), VIREO_OK);
    EXPECT(vireo_timer_wheel_register(wheel, 0, 0, &h), VIREO_RESULT_TIMEOUT);
    EXPECT(vireo_timer_wheel_destroy(&wheel), VIREO_OK);
    CHECK(create_wheel(&wheel, 0, 2, 4, NULL) == 0 && prepare(wheel, 1) == 0);
    state_snapshot_t saved;
    CHECK(capture(wheel, &saved) == 0);
    EXPECT(vireo_timer_wheel_register(wheel, UINT64_MAX - 1, UINT64_MAX, &h), VIREO_RESULT_OVERFLOW);
    CHECK(empty_handle(h) && unchanged(wheel, &saved) == 0);
    EXPECT(vireo_timer_wheel_destroy(&wheel), VIREO_OK);
    CHECK(create_wheel(&wheel, UINT64_MAX, 1, 4, NULL) == 0 && prepare(wheel, 1) == 0);
    EXPECT(vireo_timer_wheel_register(wheel, UINT64_MAX - 1, UINT64_MAX, &h), VIREO_RESULT_RANGE);
    EXPECT(vireo_timer_wheel_register(wheel, UINT64_MAX, UINT64_MAX, &h), VIREO_RESULT_TIMEOUT);
    EXPECT(vireo_timer_wheel_destroy(&wheel), VIREO_OK);
    return 0;
}

static int identity_and_reuse(void) {
    vireo_timer_wheel_t *a = NULL;
    vireo_timer_wheel_t *b = NULL;
    CHECK(create_wheel(&a, 1000, 100, 4, NULL) == 0 && prepare(a, 1) == 0);
    CHECK(create_wheel(&b, 1000, 100, 4, NULL) == 0 && prepare(b, 1) == 0);
    vireo_timer_handle_t h = {0};
    EXPECT(vireo_timer_wheel_register(a, 1000, 1100, &h), VIREO_OK);
    vireo_timer_handle_t const old = h;
    vireo_timer_wheel_timer_info_t info;
    memset(&info, 0x7C, sizeof(info));
    unsigned char saved[sizeof(info)];
    memcpy(saved, &info, sizeof(info));
    EXPECT(vireo_timer_wheel_get(b, h, &info), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_timer_wheel_cancel(b, &h), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_timer_wheel_rearm(b, h, 0, 0), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(same_handle(h, old) && memcmp(saved, &info, sizeof(info)) == 0);
    vireo_timer_handle_t bad = h;
    bad.slot_index = 1;
    EXPECT(vireo_timer_wheel_get(a, bad, &info), VIREO_RESULT_RANGE);
    EXPECT(vireo_timer_wheel_cancel(a, &bad), VIREO_RESULT_RANGE);
    EXPECT(vireo_timer_wheel_rearm(a, bad, 0, 0), VIREO_RESULT_RANGE);
    bad.owner_id = 0;
    EXPECT(vireo_timer_wheel_get(a, bad, &info), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_timer_wheel_cancel(a, &h), VIREO_OK);
    CHECK(empty_handle(h));
    EXPECT(vireo_timer_wheel_cancel(a, &h), VIREO_RESULT_NOT_FOUND);
    EXPECT(vireo_timer_wheel_get(a, old, &info), VIREO_RESULT_NOT_FOUND);
    EXPECT(vireo_timer_wheel_register(a, 1000, 1200, &h), VIREO_OK);
    CHECK(h.slot_index == old.slot_index && h.owner_id == old.owner_id && h.generation > old.generation);
    bad = old;
    unsigned char old_bytes[sizeof(bad)];
    memcpy(old_bytes, &bad, sizeof(bad));
    EXPECT(vireo_timer_wheel_cancel(a, &bad), VIREO_RESULT_NOT_FOUND);
    CHECK(memcmp(old_bytes, &bad, sizeof(bad)) == 0);
    EXPECT(vireo_timer_wheel_rearm(a, old, 1000, 1400), VIREO_RESULT_NOT_FOUND);
    CHECK(memcmp(saved, &info, sizeof(info)) == 0);
    EXPECT(vireo_timer_wheel_cancel(a, &h), VIREO_OK);
    EXPECT(vireo_timer_wheel_destroy(&a), VIREO_OK);
    EXPECT(vireo_timer_wheel_destroy(&b), VIREO_OK);
    return 0;
}

static int full_and_dependency_error(void) {
    vireo_timer_wheel_t *wheel = NULL;
    CHECK(create_wheel(&wheel, 1000, 100, 4, NULL) == 0 && prepare(wheel, 1) == 0);
    vireo_timer_handle_t h = {0};
    EXPECT(vireo_timer_wheel_register(wheel, 1000, 1100, &h), VIREO_OK);
    state_snapshot_t saved;
    CHECK(capture(wheel, &saved) == 0);
    unsigned char handle_bytes[sizeof(h)];
    memcpy(handle_bytes, &h, sizeof(h));
    EXPECT(vireo_timer_wheel_register(wheel, 1000, 1200, &h), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(memcmp(handle_bytes, &h, sizeof(h)) == 0);
    vireo_timer_handle_t out = {0};
    unsigned char out_bytes[sizeof(out)];
    memcpy(out_bytes, &out, sizeof(out));
    EXPECT(vireo_timer_wheel_register(wheel, 1000, 1200, &out), VIREO_RESULT_BUSY);
    EXPECT(vireo_timer_wheel_register(wheel, 999, 1200, &out), VIREO_RESULT_RANGE);
    EXPECT(vireo_timer_wheel_register(wheel, 1100, 1100, &out), VIREO_RESULT_TIMEOUT);
    EXPECT(vireo_timer_wheel_register(wheel, 1200, 1100, &out), VIREO_RESULT_TIMEOUT);
    dependency_probe_t dependency = {.result = VIREO_RESULT_OVERFLOW};
    EXPECT(vireo_timer_wheel_register_runtime(wheel, 1000, 1200, &out, acquire_failure, &dependency), VIREO_RESULT_OVERFLOW);
    CHECK(dependency.calls == 1 && memcmp(out_bytes, &out, sizeof(out)) == 0);
    CHECK(unchanged(wheel, &saved) == 0);
    EXPECT(vireo_timer_wheel_cancel(wheel, &h), VIREO_OK);
    CHECK(capture(wheel, &saved) == 0);
    EXPECT(vireo_timer_wheel_register_runtime(wheel, 1000, 1200, &out, acquire_failure, &dependency), VIREO_RESULT_OVERFLOW);
    CHECK(unchanged(wheel, &saved) == 0 && dependency.calls == 2);
    EXPECT(vireo_timer_wheel_register(wheel, 1000, 1200, &out), VIREO_OK);
    EXPECT(vireo_timer_wheel_cancel(wheel, &out), VIREO_OK);
    EXPECT(vireo_timer_wheel_destroy(&wheel), VIREO_OK);
    return 0;
}

static int real_unlink_positions(void) {
    size_t const order[4] = {1, 0, 3, 2}; /* 中间、首、尾、唯一节点。 */
    vireo_timer_wheel_t *wheel = NULL;
    CHECK(create_wheel(&wheel, 1000, 100, 4, NULL) == 0 && prepare(wheel, 4) == 0);
    vireo_timer_handle_t h[4] = {{0}};
    for (size_t i = 0; i < 4; i++) {
        EXPECT(vireo_timer_wheel_register(wheel, 1000, 1100 + (uint64_t)i * 400, &h[i]), VIREO_OK);
    }
    CHECK(ring_integrity(wheel, 4) == 0);
    for (size_t i = 0; i < 4; i++) {
        vireo_timer_handle_t const stale = h[order[i]];
        EXPECT(vireo_timer_wheel_cancel(wheel, &h[order[i]]), VIREO_OK);
        CHECK(empty_handle(h[order[i]]) && ring_integrity(wheel, 3 - i) == 0);
        vireo_timer_wheel_timer_info_t info;
        EXPECT(vireo_timer_wheel_get(wheel, stale, &info), VIREO_RESULT_NOT_FOUND);
    }
    EXPECT(vireo_timer_wheel_destroy(&wheel), VIREO_OK);
    return 0;
}

static int rearm_atomicity(void) {
    vireo_timer_wheel_t *wheel = NULL;
    CHECK(create_wheel(&wheel, 1000, 100, 4, NULL) == 0 && prepare(wheel, 2) == 0);
    vireo_timer_handle_t h = {0};
    vireo_timer_handle_t other = {0};
    EXPECT(vireo_timer_wheel_register(wheel, 1000, 1100, &h), VIREO_OK);
    EXPECT(vireo_timer_wheel_register(wheel, 1000, 1500, &other), VIREO_OK);
    vireo_timer_handle_t const original = h;
    state_snapshot_t saved;
    CHECK(capture(wheel, &saved) == 0);
    EXPECT(vireo_timer_wheel_rearm(wheel, h, 999, 1600), VIREO_RESULT_RANGE);
    EXPECT(vireo_timer_wheel_rearm(wheel, h, 1600, 1600), VIREO_RESULT_TIMEOUT);
    EXPECT(vireo_timer_wheel_rearm(wheel, h, 1000, UINT64_MAX), VIREO_RESULT_OVERFLOW);
    CHECK(unchanged(wheel, &saved) == 0);
    uint64_t const deadlines[4] = {1900, 1200, 1101, 1100};
    uint64_t const ticks[4] = {9, 2, 2, 1};
    uint64_t const buckets[4] = {1, 2, 2, 1};
    for (size_t i = 0; i < 4; i++) {
        EXPECT(vireo_timer_wheel_rearm(wheel, h, 1000, deadlines[i]), VIREO_OK);
        vireo_timer_wheel_timer_info_t info;
        EXPECT(vireo_timer_wheel_get(wheel, h, &info), VIREO_OK);
        CHECK(info.deadline_ns == deadlines[i] && info.due_tick == ticks[i] && info.bucket_index == buckets[i]);
        CHECK(same_handle(h, original) && ring_integrity(wheel, 2) == 0);
        vireo_timer_handle_owner_info_t owner;
        EXPECT(vireo_timer_handle_owner_inspect(wheel->owner, &owner), VIREO_OK);
        CHECK(owner.last_generation == saved.owner.last_generation && owner.active_count == 2);
    }
    /* 旧期限已过仍可显式重排；延长策略由业务决定，此处不自动刷新。 */
    EXPECT(vireo_timer_wheel_rearm(wheel, h, 2000, 2100), VIREO_OK);
    EXPECT(vireo_timer_wheel_cancel(wheel, &h), VIREO_OK);
    EXPECT(vireo_timer_wheel_cancel(wheel, &other), VIREO_OK);
    EXPECT(vireo_timer_wheel_destroy(&wheel), VIREO_OK);
    return 0;
}

static int cancel_exact_rollback(void) {
    for (size_t target = 0; target < 4; target++) {
        vireo_timer_wheel_t *wheel = NULL;
        size_t const count = target == 3 ? 1 : 3;
        CHECK(create_wheel(&wheel, 1000, 100, 4, NULL) == 0 && prepare(wheel, count) == 0);
        vireo_timer_handle_t h[3] = {{0}};
        for (size_t i = 0; i < count; i++) {
            EXPECT(vireo_timer_wheel_register(wheel, 1000, 1100, &h[i]), VIREO_OK);
        }
        size_t const index = target == 3 ? 0 : target;
        state_snapshot_t saved;
        CHECK(capture(wheel, &saved) == 0);
        unsigned char handle_bytes[sizeof(h[index])];
        memcpy(handle_bytes, &h[index], sizeof(h[index]));
        dependency_probe_t p = {
            .result = VIREO_RESULT_NOT_FOUND, .link = &wheel->nodes[h[index].slot_index].link,
        };
        EXPECT(vireo_timer_wheel_cancel_runtime(wheel, &h[index], release_failure, &p), VIREO_RESULT_NOT_FOUND);
        CHECK(p.calls == 1 && p.detached && memcmp(handle_bytes, &h[index], sizeof(h[index])) == 0);
        CHECK(unchanged(wheel, &saved) == 0 && ring_integrity(wheel, count) == 0);
        for (size_t i = 0; i < count; i++) {
            EXPECT(vireo_timer_wheel_cancel(wheel, &h[i]), VIREO_OK);
        }
        EXPECT(vireo_timer_wheel_destroy(&wheel), VIREO_OK);
    }
    return 0;
}

static int destroy_resource_ownership(void) {
    allocation_probe_t probe = {.reverse_order = true};
    vireo_timer_wheel_t *wheel = NULL;
    CHECK(create_wheel(&wheel, 1000, 100, 4, &probe) == 0 && prepare(wheel, 2) == 0);
    vireo_timer_handle_t h = {0};
    EXPECT(vireo_timer_wheel_register(wheel, 1000, 1200, &h), VIREO_OK);
    state_snapshot_t saved;
    CHECK(capture(wheel, &saved) == 0);
    vireo_timer_wheel_t *const address = wheel;
    unsigned char probe_saved[sizeof(probe)];
    memcpy(probe_saved, &probe, sizeof(probe));
    EXPECT(vireo_timer_wheel_destroy(&wheel), VIREO_RESULT_BUSY);
    CHECK(wheel == address && unchanged(wheel, &saved) == 0);
    CHECK(memcmp(probe_saved, &probe, sizeof(probe)) == 0);
    EXPECT(vireo_timer_wheel_cancel(wheel, &h), VIREO_OK);
    EXPECT(vireo_timer_wheel_destroy(&wheel), VIREO_OK);
    CHECK(wheel == NULL && probe.live == 0 && probe.frees == 3 && probe.reverse_order);
    EXPECT(vireo_timer_wheel_destroy(&wheel), VIREO_OK);
    return 0;
}

static int maximum_capacity(void) {
    vireo_timer_wheel_t *wheel = NULL;
    CHECK(create_wheel(&wheel, 17, 5, 3, NULL) == 0);
    CHECK(prepare(wheel, VIREO_TIMER_WHEEL_REGISTRY_MAX_CAPACITY) == 0);
    vireo_timer_wheel_registry_info_t info;
    EXPECT(vireo_timer_wheel_registry_inspect(wheel, &info), VIREO_OK);
    CHECK(info.capacity == 65536 && info.active_count == 0 && info.available_count == 65536);
    CHECK(info.allocation_bytes <= info.max_memory_bytes);
    for (size_t i = 0; i < info.capacity; i++) {
        CHECK(empty_handle(wheel->nodes[i].handle));
        CHECK(wheel->nodes[i].link.prev == &wheel->nodes[i].link && wheel->nodes[i].link.next == &wheel->nodes[i].link);
    }
    EXPECT(vireo_timer_wheel_destroy(&wheel), VIREO_OK);
    return 0;
}

/** 逐个时间边界/桶递增生成期望，未调用生产映射或复制其除余表达式。 */
static int model_check(vireo_timer_wheel_t const *wheel, model_timer_t const model[3]) {
    size_t active = 0;
    for (size_t i = 0; i < 3; i++) {
        if (!model[i].active) {
            continue;
        }
        active++;
        uint64_t boundary = 17;
        uint64_t tick = 0;
        uint64_t bucket = 0;
        while (boundary < model[i].deadline) {
            boundary += 5;
            tick++;
            bucket++;
            if (bucket == 3) {
                bucket = 0;
            }
        }
        vireo_timer_wheel_timer_info_t info;
        EXPECT(vireo_timer_wheel_get(wheel, model[i].handle, &info), VIREO_OK);
        CHECK(info.deadline_ns == model[i].deadline && info.due_tick == tick && info.bucket_index == bucket);
    }
    vireo_timer_wheel_registry_info_t info;
    EXPECT(vireo_timer_wheel_registry_inspect(wheel, &info), VIREO_OK);
    CHECK(info.prepared && info.capacity == 3 && info.active_count == active && info.available_count == 3 - active);
    CHECK(ring_integrity(wheel, active) == 0);
    return 0;
}

static int independent_state_model(void) {
    vireo_timer_wheel_t *wheel = NULL;
    CHECK(create_wheel(&wheel, 17, 5, 3, NULL) == 0 && prepare(wheel, 3) == 0);
    model_timer_t model[3] = {{0}};
    for (size_t step = 0; step < 400; step++) {
        size_t const index = step % 3;
        uint64_t const deadline = 18 + (uint64_t)((step * 13) % 91);
        if (!model[index].active) {
            model[index].handle = (vireo_timer_handle_t){0};
            EXPECT(vireo_timer_wheel_register(wheel, 17, deadline, &model[index].handle), VIREO_OK);
            model[index].active = true;
            model[index].deadline = deadline;
        } else if (step % 4 == 0) {
            vireo_timer_handle_t const stale = model[index].handle;
            EXPECT(vireo_timer_wheel_cancel(wheel, &model[index].handle), VIREO_OK);
            model[index].active = false;
            vireo_timer_wheel_timer_info_t info;
            EXPECT(vireo_timer_wheel_get(wheel, stale, &info), VIREO_RESULT_NOT_FOUND);
        } else if (step % 4 == 1) {
            state_snapshot_t saved;
            CHECK(capture(wheel, &saved) == 0);
            EXPECT(vireo_timer_wheel_rearm(wheel, model[index].handle, deadline, deadline), VIREO_RESULT_TIMEOUT);
            CHECK(unchanged(wheel, &saved) == 0);
        } else {
            vireo_timer_handle_t const identity = model[index].handle;
            EXPECT(vireo_timer_wheel_rearm(wheel, identity, 17, deadline), VIREO_OK);
            CHECK(same_handle(identity, model[index].handle));
            model[index].deadline = deadline;
        }
        CHECK(model_check(wheel, model) == 0);
        if (model[0].active && model[1].active && model[2].active) {
            vireo_timer_handle_t out = {0};
            EXPECT(vireo_timer_wheel_register(wheel, 17, 200, &out), VIREO_RESULT_BUSY);
            CHECK(empty_handle(out) && model_check(wheel, model) == 0);
        }
    }
    for (size_t i = 0; i < 3; i++) {
        if (model[i].active) {
            EXPECT(vireo_timer_wheel_cancel(wheel, &model[i].handle), VIREO_OK);
            model[i].active = false;
        }
    }
    CHECK(model_check(wheel, model) == 0);
    EXPECT(vireo_timer_wheel_destroy(&wheel), VIREO_OK);
    return 0;
}

int main(void) {
    int (*const tests[])(void) = {
        parameters_and_unprepared, prepare_limits, budget_and_snapshot,
        node_allocation_failure, owner_creation_failure, golden_buckets,
        time_boundaries, identity_and_reuse, full_and_dependency_error,
        real_unlink_positions, rearm_atomicity, cancel_exact_rollback,
        destroy_resource_ownership, maximum_capacity, independent_state_model,
    };
    int failures = 0;
    for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        failures += tests[i]();
    }
    printf("wheel registry: 15 groups, %d failures; independent 400 transitions; node=%zu control=%zu\n",
           failures, sizeof(vireo_timer_wheel_node_t), sizeof(vireo_timer_wheel_t));
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
