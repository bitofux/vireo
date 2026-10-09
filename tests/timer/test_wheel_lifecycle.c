/*
 * PROJECT : VIREO
 * FILE    : test_wheel_lifecycle.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-09
 * BRIEF   : 此模块负责：
 * -- 验证真实固定 dummy 空桶与唯一资源生命周期
 * -- 受检预算边界、申请回滚、输出和 errno 保持
 * -- 用本层合法链接夹具验证 BUSY 与恢复，不登记 timer
 */
#include <vireo/timer/wheel.h>
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

/** 本层两处申请探针，指针仅在存活期间保存。 */
typedef struct allocation_probe {
    size_t calls; /**< 申请尝试数，最多两次。 */
    size_t fail_at; /**< 注入失败的申请序号，0 不注入。 */
    size_t live; /**< 当前尚未释放的申请数。 */
    size_t frees; /**< 释放次数。 */
    void *pointers[2]; /**< 两次成功申请的存活地址，释放前清 NULL。 */
    size_t bytes[2]; /**< 对应请求字节数。 */
    bool reverse_order; /**< 所有释放是否先最后存活申请。 */
} allocation_probe_t;

/** 观测输出与邻位，失败逐字节核对而不冻结 padding。 */
typedef struct info_guard {
    uint64_t before; /**< 固定 11。 */
    vireo_timer_wheel_info_t value; /**< 实际数值快照输出。 */
    uint64_t after; /**< 固定 19。 */
} info_guard_t;

/** 唯一拥有者输出邻位。 */
typedef struct wheel_guard {
    uint64_t before; /**< 固定 11。 */
    vireo_timer_wheel_t *value; /**< create/destroy 输出，入口 NULL 或存活轮。 */
    uint64_t after; /**< 固定 19。 */
} wheel_guard_t;

static void *probe_allocate(size_t bytes, void *context) {
    allocation_probe_t *probe = context;
    size_t const index = probe->calls++;
    errno = ENOMEM;
    if (index >= 2 || probe->calls == probe->fail_at) {
        return NULL;
    }
    void *memory = malloc(bytes);
    probe->pointers[index] = memory;
    probe->bytes[index] = bytes;
    if (memory != NULL) {
        memset(memory, 0xA5, bytes);
        probe->live++;
    }
    return memory;
}

static void probe_deallocate(void *memory, void *context) {
    allocation_probe_t *probe = context;
    size_t found = SIZE_MAX;
    size_t last = SIZE_MAX;
    for (size_t i = 0; i < 2; i++) {
        if (probe->pointers[i] != NULL) {
            last = i;
            if (probe->pointers[i] == memory) {
                found = i;
            }
        }
    }
    if (found == SIZE_MAX || found != last) {
        probe->reverse_order = false;
    }
    if (found != SIZE_MAX) {
        probe->pointers[found] = NULL;
        probe->live--;
    }
    probe->frees++;
    free(memory);
    errno = EIO;
}

static vireo_timer_wheel_allocator_t strategy(allocation_probe_t *probe) {
    return (vireo_timer_wheel_allocator_t){probe_allocate, probe_deallocate, probe};
}

static vireo_timer_wheel_options_t options_for(uint64_t count) {
    return (vireo_timer_wheel_options_t){{1000, 100, count}, VIREO_TIMER_WHEEL_MAX_MEMORY};
}

static int public_parameters(void) {
    wheel_guard_t out = {11, NULL, 19};
    unsigned char snapshot[sizeof(out)];
    memcpy(snapshot, &out, sizeof(out));
    vireo_timer_wheel_options_t options = options_for(2);
    info_guard_t info;
    memset(&info, 0x7C, sizeof(info));
    unsigned char info_snapshot[sizeof(info)];
    memcpy(info_snapshot, &info, sizeof(info));
    errno = EDOM;
    CHECK(vireo_timer_wheel_create(NULL, &out.value) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_timer_wheel_create(&options, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(memcmp(snapshot, &out, sizeof(out)) == 0);
    CHECK(vireo_timer_wheel_inspect(NULL, &info.value) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(memcmp(info_snapshot, &info, sizeof(info)) == 0);
    CHECK(vireo_timer_wheel_destroy(NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_timer_wheel_destroy(&out.value) == VIREO_OK);
    CHECK(memcmp(snapshot, &out, sizeof(out)) == 0 && errno == EDOM);
    CHECK(vireo_timer_wheel_create(&options, &out.value) == VIREO_OK);
    memcpy(snapshot, &out, sizeof(out));
    CHECK(vireo_timer_wheel_create(&options, &out.value) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(memcmp(snapshot, &out, sizeof(out)) == 0);
    CHECK(vireo_timer_wheel_inspect(out.value, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(errno == EDOM);
    CHECK(vireo_timer_wheel_destroy(&out.value) == VIREO_OK);
    CHECK(out.value == NULL && out.before == 11 && out.after == 19 && errno == EDOM);
    CHECK(vireo_timer_wheel_destroy(&out.value) == VIREO_OK);
    CHECK(out.value == NULL && errno == EDOM);
    return 0;
}

static int snapshot_copy(void) {
    vireo_timer_wheel_options_t options = options_for(3);
    vireo_timer_wheel_t *wheel = NULL;
    info_guard_t info = {.before = 11, .after = 19};
    errno = ERANGE;
    CHECK(vireo_timer_wheel_create(&options, &wheel) == VIREO_OK);
    options.geometry = (vireo_timer_wheel_geometry_t){9, 8, 7};
    options.max_memory_bytes = 1;
    CHECK(vireo_timer_wheel_inspect(wheel, &info.value) == VIREO_OK);
    CHECK(info.before == 11 && info.after == 19);
    CHECK(info.value.geometry.origin_ns == 1000 && info.value.geometry.tick_ns == 100);
    CHECK(info.value.geometry.bucket_count == 3);
    CHECK(info.value.max_memory_bytes == VIREO_TIMER_WHEEL_MAX_MEMORY);
    CHECK(info.value.allocation_bytes == sizeof(*wheel) + 3 * sizeof(vireo_timer_wheel_link_t));
    info.value.geometry.tick_ns = 1;
    info.value.allocation_bytes = 0;
    CHECK(vireo_timer_wheel_inspect(wheel, &info.value) == VIREO_OK);
    CHECK(info.value.geometry.tick_ns == 100 && info.value.allocation_bytes > 0);
    CHECK(vireo_timer_wheel_destroy(&wheel) == VIREO_OK && wheel == NULL && errno == ERANGE);
    /* 快照按值独立，轮释放后仍可读取；不使用任何旧轮裸别名。 */
    CHECK(info.value.geometry.bucket_count == 3 && info.value.geometry.origin_ns == 1000);
    return 0;
}

static int dummy_tables(void) {
    uint64_t const counts[] = {1, 2, 3, 512};
    for (size_t c = 0; c < sizeof(counts) / sizeof(counts[0]); c++) {
        allocation_probe_t probe = {.reverse_order = true};
        vireo_timer_wheel_allocator_t allocator = strategy(&probe);
        vireo_timer_wheel_options_t options = options_for(counts[c]);
        vireo_timer_wheel_t *wheel = NULL;
        errno = EDOM;
        CHECK(vireo_timer_wheel_create_runtime(&options, &wheel, &allocator) == VIREO_OK);
        CHECK(probe.calls == 2 && probe.live == 2 && probe.frees == 0);
        CHECK(probe.bytes[0] == sizeof(*wheel));
        CHECK(probe.bytes[1] == wheel->bucket_count * sizeof(vireo_timer_wheel_link_t));
        CHECK(wheel->bucket_count == counts[c] && errno == EDOM);
        for (size_t i = 0; i < wheel->bucket_count; i++) {
            CHECK(wheel->buckets[i].prev == &wheel->buckets[i]);
            CHECK(wheel->buckets[i].next == &wheel->buckets[i]);
            if (i > 0) {
                CHECK(&wheel->buckets[i] != &wheel->buckets[i - 1]);
            }
        }
        CHECK(wheel->allocation_bytes == probe.bytes[0] + probe.bytes[1]);
        CHECK(vireo_timer_wheel_destroy(&wheel) == VIREO_OK && wheel == NULL);
        CHECK(probe.live == 0 && probe.frees == 2 && probe.reverse_order && errno == EDOM);
    }
    return 0;
}

static int budget_boundary(void) {
    size_t const exact = sizeof(vireo_timer_wheel_t) + 3 * sizeof(vireo_timer_wheel_link_t);
    vireo_timer_wheel_options_t options = options_for(3);
    allocation_probe_t probe = {.reverse_order = true};
    vireo_timer_wheel_allocator_t allocator = strategy(&probe);
    wheel_guard_t out = {11, NULL, 19};
    unsigned char snapshot[sizeof(out)];
    memcpy(snapshot, &out, sizeof(out));
    errno = EDOM;
    options.max_memory_bytes = exact - 1;
    CHECK(vireo_timer_wheel_create_runtime(&options, &out.value, &allocator) == VIREO_RESULT_RANGE);
    CHECK(probe.calls == 0 && memcmp(snapshot, &out, sizeof(out)) == 0 && errno == EDOM);
    options.max_memory_bytes = exact;
    CHECK(vireo_timer_wheel_create_runtime(&options, &out.value, &allocator) == VIREO_OK);
    vireo_timer_wheel_info_t info;
    CHECK(vireo_timer_wheel_inspect(out.value, &info) == VIREO_OK);
    CHECK(info.allocation_bytes == exact && info.max_memory_bytes == exact);
    CHECK(vireo_timer_wheel_destroy(&out.value) == VIREO_OK);
    CHECK(out.value == NULL && out.before == 11 && out.after == 19);
    CHECK(probe.frees == 2 && probe.live == 0 && probe.reverse_order && errno == EDOM);
    return 0;
}

static int resource_limits(void) {
    vireo_timer_wheel_options_t options[] = {
        {{0, 0, 1}, VIREO_TIMER_WHEEL_MAX_MEMORY},
        {{0, 1, 0}, VIREO_TIMER_WHEEL_MAX_MEMORY},
        {{0, 1, 1}, 0},
        {{0, 1, VIREO_TIMER_WHEEL_MAX_BUCKETS + 1}, VIREO_TIMER_WHEEL_MAX_MEMORY},
        {{0, 1, 1}, VIREO_TIMER_WHEEL_MAX_MEMORY + 1},
        {{0, 1, 1}, 1},
    };
    for (size_t i = 0; i < sizeof(options) / sizeof(options[0]); i++) {
        allocation_probe_t probe = {.reverse_order = true};
        vireo_timer_wheel_allocator_t allocator = strategy(&probe);
        wheel_guard_t out = {11, NULL, 19};
        unsigned char snapshot[sizeof(out)];
        memcpy(snapshot, &out, sizeof(out));
        errno = EDOM;
        vireo_result_t const expected = i < 3 ? VIREO_RESULT_INVALID_ARGUMENT : VIREO_RESULT_RANGE;
        CHECK(vireo_timer_wheel_create_runtime(&options[i], &out.value, &allocator) == expected);
        CHECK(probe.calls == 0 && probe.frees == 0 && probe.live == 0);
        CHECK(memcmp(snapshot, &out, sizeof(out)) == 0 && errno == EDOM);
    }
    return 0;
}

static int arithmetic_priority(void) {
    allocation_probe_t probe = {.reverse_order = true};
    vireo_timer_wheel_allocator_t allocator = strategy(&probe);
    vireo_timer_wheel_options_t options = options_for(UINT64_MAX);
    wheel_guard_t out = {11, NULL, 19};
    unsigned char snapshot[sizeof(out)];
    memcpy(snapshot, &out, sizeof(out));
    errno = EDOM;
#if SIZE_MAX < UINT64_MAX
    CHECK(vireo_timer_wheel_create_runtime(&options, &out.value, &allocator) == VIREO_RESULT_RANGE);
#else
    CHECK(vireo_timer_wheel_create_runtime(&options, &out.value, &allocator) == VIREO_RESULT_OVERFLOW);
#endif
    options.geometry.bucket_count = (uint64_t)(SIZE_MAX / sizeof(vireo_timer_wheel_link_t)) + 1;
    CHECK(vireo_timer_wheel_create_runtime(&options, &out.value, &allocator) == VIREO_RESULT_OVERFLOW);
    options.geometry.bucket_count = (uint64_t)(SIZE_MAX / sizeof(vireo_timer_wheel_link_t));
    CHECK(sizeof(vireo_timer_wheel_t) > SIZE_MAX % sizeof(vireo_timer_wheel_link_t));
    CHECK(vireo_timer_wheel_create_runtime(&options, &out.value, &allocator) == VIREO_RESULT_OVERFLOW);
    options.geometry.tick_ns = 0;
    CHECK(vireo_timer_wheel_create_runtime(&options, &out.value, &allocator) == VIREO_RESULT_INVALID_ARGUMENT);
    options.geometry.tick_ns = 1;
    options.max_memory_bytes = 0;
    CHECK(vireo_timer_wheel_create_runtime(&options, &out.value, &allocator) == VIREO_RESULT_INVALID_ARGUMENT);
    options.max_memory_bytes = VIREO_TIMER_WHEEL_MAX_MEMORY;
    CHECK(vireo_timer_wheel_create_runtime(&options, NULL, &allocator) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(probe.calls == 0 && probe.frees == 0 && probe.live == 0);
    CHECK(memcmp(snapshot, &out, sizeof(out)) == 0 && errno == EDOM);
    return 0;
}

static int private_allocator_guards(void) {
    allocation_probe_t probe = {.reverse_order = true};
    vireo_timer_wheel_allocator_t allocator = strategy(&probe);
    vireo_timer_wheel_options_t options = options_for(1);
    vireo_timer_wheel_t *wheel = NULL;
    errno = EDOM;
    CHECK(vireo_timer_wheel_create_runtime(&options, &wheel, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    allocator.allocate = NULL;
    CHECK(vireo_timer_wheel_create_runtime(&options, &wheel, &allocator) == VIREO_RESULT_INVALID_ARGUMENT);
    allocator = strategy(&probe);
    allocator.deallocate = NULL;
    CHECK(vireo_timer_wheel_create_runtime(&options, &wheel, &allocator) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(wheel == NULL && probe.calls == 0 && probe.frees == 0 && errno == EDOM);
    return 0;
}

static int allocation_failure(void) {
    for (size_t fail = 1; fail <= 2; fail++) {
        allocation_probe_t probe = {.fail_at = fail, .reverse_order = true};
        vireo_timer_wheel_allocator_t allocator = strategy(&probe);
        vireo_timer_wheel_options_t options = options_for(3);
        wheel_guard_t out = {11, NULL, 19};
        unsigned char snapshot[sizeof(out)];
        memcpy(snapshot, &out, sizeof(out));
        errno = ERANGE;
        CHECK(vireo_timer_wheel_create_runtime(&options, &out.value, &allocator) == VIREO_RESULT_NO_MEMORY);
        CHECK(probe.calls == fail && probe.frees == fail - 1 && probe.live == 0);
        CHECK(probe.reverse_order && memcmp(snapshot, &out, sizeof(out)) == 0 && errno == ERANGE);
        /* 同一输出正常恢复；探针是独立新夹具，不重置生产轮。 */
        probe = (allocation_probe_t){.reverse_order = true};
        CHECK(vireo_timer_wheel_create_runtime(&options, &out.value, &allocator) == VIREO_OK);
        CHECK(vireo_timer_wheel_destroy(&out.value) == VIREO_OK && out.value == NULL);
        CHECK(probe.calls == 2 && probe.frees == 2 && probe.live == 0 && probe.reverse_order);
        CHECK(errno == ERANGE);
    }
    return 0;
}

static int allocator_copy_lifetime(void) {
    allocation_probe_t probe = {.reverse_order = true};
    vireo_timer_wheel_allocator_t allocator = strategy(&probe);
    vireo_timer_wheel_options_t options = options_for(2);
    vireo_timer_wheel_t *wheel = NULL;
    errno = EDOM;
    CHECK(vireo_timer_wheel_create_runtime(&options, &wheel, &allocator) == VIREO_OK);
    allocator = (vireo_timer_wheel_allocator_t){0};
    CHECK(vireo_timer_wheel_destroy(&wheel) == VIREO_OK && wheel == NULL);
    CHECK(probe.frees == 2 && probe.live == 0 && probe.reverse_order && errno == EDOM);
    return 0;
}

static int nonempty_destroy(void) {
    allocation_probe_t probe = {.reverse_order = true};
    vireo_timer_wheel_allocator_t allocator = strategy(&probe);
    vireo_timer_wheel_options_t options = options_for(3);
    wheel_guard_t out = {11, NULL, 19};
    errno = EDOM;
    CHECK(vireo_timer_wheel_create_runtime(&options, &out.value, &allocator) == VIREO_OK);
    size_t const positions[] = {0, 1, 2};
    for (size_t c = 0; c < sizeof(positions) / sizeof(positions[0]); c++) {
        vireo_timer_wheel_link_t *head = &out.value->buckets[positions[c]];
        /* 合法单节点双向环，仅测试本层链接状态；没有 timer 身份或登记入口。 */
        vireo_timer_wheel_link_t node = {head, head};
        head->prev = &node;
        head->next = &node;
        unsigned char out_snapshot[sizeof(out)];
        unsigned char control_snapshot[sizeof(vireo_timer_wheel_t)];
        unsigned char bucket_snapshot[3 * sizeof(vireo_timer_wheel_link_t)];
        unsigned char probe_snapshot[sizeof(probe)];
        memcpy(out_snapshot, &out, sizeof(out));
        memcpy(control_snapshot, out.value, sizeof(control_snapshot));
        memcpy(bucket_snapshot, out.value->buckets, sizeof(bucket_snapshot));
        memcpy(probe_snapshot, &probe, sizeof(probe));
        CHECK(vireo_timer_wheel_destroy(&out.value) == VIREO_RESULT_BUSY);
        CHECK(memcmp(out_snapshot, &out, sizeof(out)) == 0);
        CHECK(memcmp(control_snapshot, out.value, sizeof(control_snapshot)) == 0);
        CHECK(memcmp(bucket_snapshot, out.value->buckets, sizeof(bucket_snapshot)) == 0);
        CHECK(memcmp(probe_snapshot, &probe, sizeof(probe)) == 0);
        CHECK(node.prev == head && node.next == head && errno == EDOM);
        vireo_timer_wheel_info_t info;
        CHECK(vireo_timer_wheel_inspect(out.value, &info) == VIREO_OK);
        CHECK(info.geometry.bucket_count == 3 && probe.frees == 0);
        /* 夹具退场，栈 node 返回前确保没有链接留在轮中。 */
        head->prev = head;
        head->next = head;
    }
    CHECK(vireo_timer_wheel_destroy(&out.value) == VIREO_OK && out.value == NULL);
    CHECK(probe.frees == 2 && probe.live == 0 && probe.reverse_order && errno == EDOM);
    return 0;
}

static int maximum_table(void) {
    vireo_timer_wheel_options_t options = options_for(VIREO_TIMER_WHEEL_MAX_BUCKETS);
    options.geometry.origin_ns = UINT64_MAX;
    options.geometry.tick_ns = UINT64_MAX;
    vireo_timer_wheel_t *wheel = NULL;
    errno = EDOM;
    CHECK(vireo_timer_wheel_create(&options, &wheel) == VIREO_OK);
    CHECK(wheel->bucket_count == 65536);
    for (size_t i = 0; i < wheel->bucket_count; i++) {
        CHECK(wheel->buckets[i].prev == &wheel->buckets[i] && wheel->buckets[i].next == &wheel->buckets[i]);
    }
    vireo_timer_wheel_info_t info;
    CHECK(vireo_timer_wheel_inspect(wheel, &info) == VIREO_OK);
    CHECK(info.geometry.origin_ns == UINT64_MAX && info.geometry.tick_ns == UINT64_MAX);
    CHECK(info.geometry.bucket_count == VIREO_TIMER_WHEEL_MAX_BUCKETS);
    CHECK(info.allocation_bytes <= info.max_memory_bytes && errno == EDOM);
    CHECK(vireo_timer_wheel_destroy(&wheel) == VIREO_OK && wheel == NULL && errno == EDOM);
    return 0;
}

static int independent_wheels(void) {
    vireo_timer_wheel_options_t first_options = options_for(1);
    vireo_timer_wheel_options_t second_options = {{0, 1, 7}, VIREO_TIMER_WHEEL_MAX_MEMORY};
    vireo_timer_wheel_t *first = NULL;
    vireo_timer_wheel_t *second = NULL;
    errno = EDOM;
    CHECK(vireo_timer_wheel_create(&first_options, &first) == VIREO_OK);
    CHECK(vireo_timer_wheel_create(&second_options, &second) == VIREO_OK);
    CHECK(first != second && first->buckets != second->buckets);
    CHECK(vireo_timer_wheel_destroy(&first) == VIREO_OK && first == NULL);
    vireo_timer_wheel_info_t info;
    CHECK(vireo_timer_wheel_inspect(second, &info) == VIREO_OK);
    CHECK(info.geometry.origin_ns == 0 && info.geometry.tick_ns == 1 && info.geometry.bucket_count == 7);
    for (size_t i = 0; i < second->bucket_count; i++) {
        CHECK(second->buckets[i].prev == &second->buckets[i] && second->buckets[i].next == &second->buckets[i]);
    }
    CHECK(vireo_timer_wheel_destroy(&second) == VIREO_OK && second == NULL && errno == EDOM);
    return 0;
}

int main(void) {
    int failures = 0;
    failures += public_parameters();
    failures += snapshot_copy();
    failures += dummy_tables();
    failures += budget_boundary();
    failures += resource_limits();
    failures += arithmetic_priority();
    failures += private_allocator_guards();
    failures += allocation_failure();
    failures += allocator_copy_lifetime();
    failures += nonempty_destroy();
    failures += maximum_table();
    failures += independent_wheels();
    printf("wheel lifecycle: 12 groups, %d failures; dummy=%zu bytes, control=%zu bytes; no timer registration or advance\n",
           failures, sizeof(vireo_timer_wheel_link_t), sizeof(vireo_timer_wheel_t));
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
