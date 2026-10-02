/*
 * PROJECT : VIREO
 * FILE    : test_pool_lifecycle.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-02
 * BRIEF   : 此模块负责：
 * -- 验证总预算、实际对齐、候选发布与唯一生命周期
 * -- 在真实三点分配路径检查失败回滚、配对释放和 errno 保持
 */
#include <vireo/base/pool.h>
#include "base/pool_internal.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #condition); \
        return 1; \
    } \
} while (0)

typedef struct allocation_record {
    void *memory;
    size_t size;
} allocation_record_t;

typedef struct fixture {
    allocation_record_t records[3];
    size_t calls;
    size_t fail_at;
    size_t live_bytes;
    size_t peak_bytes;
    size_t releases;
    size_t release_order[3];
    vireo_pool_t **observer;
    int error;
} fixture_t;

/* 测试分配器实际 malloc；仅指定点返回 NULL，入口/回滚故意改变 errno。 */
static void *allocate_recorded(void *context, size_t size) {
    fixture_t *fixture = context;
    errno = ENOMEM;
    if (fixture->calls >= 3 || size == 0 || size > VIREO_POOL_MAX_MEMORY ||
        (fixture->observer != NULL && *fixture->observer != NULL)) {
        fixture->error = 1;
        return NULL;
    }
    size_t index = fixture->calls++;
    fixture->records[index].size = size;
    if (fixture->calls == fixture->fail_at) {
        return NULL;
    }
    void *memory = malloc(size);
    fixture->records[index].memory = memory;
    if (memory != NULL) {
        fixture->live_bytes += size;
        if (fixture->live_bytes > fixture->peak_bytes) {
            fixture->peak_bytes = fixture->live_bytes;
        }
    }
    return memory;
}

static void deallocate_recorded(void *context, void *memory) {
    fixture_t *fixture = context;
    errno = EIO;
    for (size_t i = 0; i < 3; ++i) {
        if (memory != NULL && fixture->records[i].memory == memory) {
            if (fixture->releases >= 3) {
                fixture->error = 1;
                return;
            }
            fixture->release_order[fixture->releases++] = i;
            fixture->live_bytes -= fixture->records[i].size;
            /* 清空已释放地址，只保存数值事件，不在之后读取悬空指针值。 */
            fixture->records[i].memory = NULL;
            free(memory);
            return;
        }
    }
    fixture->error = 1;
}

static vireo_pool_allocator_t allocator_for(fixture_t *fixture) {
    return (vireo_pool_allocator_t){.context = fixture,
        .allocate = allocate_recorded, .deallocate = deallocate_recorded};
}

static vireo_pool_options_t normal_options(void) {
    return (vireo_pool_options_t){.element_size = 13, .element_alignment = 8,
        .capacity = 3, .max_memory_bytes = VIREO_POOL_MAX_MEMORY};
}

static int inspect_checked(vireo_pool_t *pool, vireo_pool_info_t *out) {
    errno = EACCES;
    CHECK(vireo_pool_inspect(pool, out) == VIREO_OK);
    CHECK(errno == EACCES);
    return 0;
}

static int destroy_checked(vireo_pool_t **pool) {
    errno = ERANGE;
    CHECK(vireo_pool_destroy(pool) == VIREO_OK);
    CHECK(errno == ERANGE);
    CHECK(*pool == NULL);
    return 0;
}

static int expect_rejection(vireo_pool_options_t options, vireo_result_t expected) {
    vireo_pool_t *pool = NULL;
    fixture_t fixture = {.observer = &pool};
    vireo_pool_allocator_t allocator = allocator_for(&fixture);
    unsigned char before[sizeof(options)];
    memcpy(before, &options, sizeof(options));
    errno = EACCES;
    CHECK(vireo_pool_create_with_allocator(&options, &allocator, &pool) == expected);
    CHECK(pool == NULL && errno == EACCES);
    CHECK(memcmp(before, &options, sizeof(options)) == 0);
    CHECK(fixture.calls == 0 && fixture.releases == 0 && fixture.live_bytes == 0);
    CHECK(fixture.error == 0);
    /* 公共入口同样在分配前拒绝，避免只验证测试 seam。 */
    CHECK(vireo_pool_create(&options, &pool) == expected);
    CHECK(pool == NULL && errno == EACCES);
    return 0;
}

static int public_lifecycle(void) {
    vireo_pool_t *pool = NULL;
    vireo_pool_options_t options = normal_options();
    errno = EACCES;
    CHECK(vireo_pool_create(&options, &pool) == VIREO_OK);
    CHECK(pool != NULL && errno == EACCES);
    /* 选项只在创建期间借用，创建后改变它不改变池。 */
    options = (vireo_pool_options_t){0};
    vireo_pool_info_t info;
    CHECK(inspect_checked(pool, &info) == 0);
    CHECK(info.layout.element_size == 13 && info.layout.element_alignment == 8);
    CHECK(info.layout.capacity == 3 && info.layout.slot_stride == 16);
    CHECK(info.layout.storage_bytes == 48 && info.allocation_bytes > 48);
    CHECK(info.allocation_bytes <= info.max_memory_bytes);
    CHECK(info.max_memory_bytes == VIREO_POOL_MAX_MEMORY);
    CHECK(info.metadata_bytes > 0 && info.pool_id != 0 && info.last_generation == 0);
    CHECK(info.in_use_count == 0 && info.available_count == 3);
    CHECK(destroy_checked(&pool) == 0);
    CHECK(destroy_checked(&pool) == 0);
    CHECK(info.layout.storage_bytes == 48); /* 数值副本在销毁后有效。 */
    return 0;
}

static int actual_alignment_and_accounting(void) {
    for (size_t alignment = 1; alignment <= _Alignof(max_align_t); alignment *= 2) {
        vireo_pool_t *pool = NULL;
        fixture_t fixture = {.observer = &pool};
        vireo_pool_allocator_t allocator = allocator_for(&fixture);
        vireo_pool_options_t options = normal_options();
        options.element_alignment = alignment;
        errno = EACCES;
        CHECK(vireo_pool_create_with_allocator(&options, &allocator, &pool) == VIREO_OK);
        CHECK(errno == EACCES && fixture.error == 0 && fixture.calls == 3);
        vireo_pool_info_t info;
        CHECK(inspect_checked(pool, &info) == 0);
        /* 小输入逐字节找最小步长，不用生产 checked 公式。 */
        size_t stride = 13;
        while (stride % alignment != 0) {
            ++stride;
        }
        CHECK(info.layout.slot_stride == stride && info.layout.storage_bytes == stride * 3);
        CHECK(fixture.records[1].size == info.layout.storage_bytes);
        CHECK(fixture.records[2].size == info.metadata_bytes);
        CHECK(info.allocation_bytes == fixture.records[0].size + fixture.records[1].size + fixture.records[2].size);
        CHECK(info.allocation_bytes == fixture.live_bytes && info.allocation_bytes == fixture.peak_bytes);
        CHECK((uintptr_t)fixture.records[0].memory % _Alignof(max_align_t) == 0);
        for (size_t i = 0; i < 3; ++i) {
            unsigned char *slot = (unsigned char *)fixture.records[1].memory + i * stride;
            CHECK((uintptr_t)slot % alignment == 0);
        }
        CHECK(destroy_checked(&pool) == 0);
        CHECK(fixture.releases == 3 && fixture.live_bytes == 0 && fixture.error == 0);
        CHECK(fixture.release_order[0] == 2 && fixture.release_order[1] == 1 && fixture.release_order[2] == 0);
    }
    return 0;
}

static int actual_c_type(void) {
    struct sample { max_align_t value; unsigned char marker; };
    vireo_pool_options_t options = {.element_size = sizeof(struct sample),
        .element_alignment = _Alignof(struct sample), .capacity = 2,
        .max_memory_bytes = VIREO_POOL_MAX_MEMORY};
    vireo_pool_t *pool = NULL;
    CHECK(vireo_pool_create(&options, &pool) == VIREO_OK);
    vireo_pool_info_t info;
    CHECK(inspect_checked(pool, &info) == 0);
    CHECK(info.layout.element_size == sizeof(struct sample));
    CHECK(info.layout.element_alignment == _Alignof(struct sample));
    CHECK(info.layout.slot_stride == sizeof(struct sample));
    CHECK(info.layout.storage_bytes == 2 * sizeof(struct sample));
    CHECK(destroy_checked(&pool) == 0);
    return 0;
}

static int exact_total_budget(void) {
    vireo_pool_t *pool = NULL;
    fixture_t fixture = {.observer = &pool};
    vireo_pool_allocator_t allocator = allocator_for(&fixture);
    vireo_pool_options_t options = normal_options();
    CHECK(vireo_pool_create_with_allocator(&options, &allocator, &pool) == VIREO_OK);
    size_t control_bytes = fixture.records[0].size;
    size_t metadata_unit = fixture.records[2].size / options.capacity;
    size_t required = control_bytes + 48 + fixture.records[2].size;
    CHECK(destroy_checked(&pool) == 0);
    options.max_memory_bytes = required - 1;
    CHECK(expect_rejection(options, VIREO_RESULT_RANGE) == 0);
    options.max_memory_bytes = 48; /* 旧 slot-only 预算不能作为总预算。 */
    CHECK(expect_rejection(options, VIREO_RESULT_RANGE) == 0);
    options.max_memory_bytes = required;
    CHECK(vireo_pool_create(&options, &pool) == VIREO_OK);
    vireo_pool_info_t info;
    CHECK(inspect_checked(pool, &info) == 0);
    CHECK(info.allocation_bytes == required && info.max_memory_bytes == required);
    CHECK(destroy_checked(&pool) == 0);
    options = (vireo_pool_options_t){.element_size = 1, .element_alignment = 1,
        .capacity = 1, .max_memory_bytes = control_bytes + 1 + metadata_unit};
    CHECK(vireo_pool_create(&options, &pool) == VIREO_OK);
    CHECK(inspect_checked(pool, &info) == 0);
    CHECK(info.layout.storage_bytes == 1 && info.allocation_bytes == control_bytes + 1 + metadata_unit);
    CHECK(destroy_checked(&pool) == 0);
    return 0;
}

static int hard_memory_limit(void) {
    vireo_pool_t *pool = NULL;
    fixture_t fixture = {.observer = &pool};
    vireo_pool_allocator_t allocator = allocator_for(&fixture);
    vireo_pool_options_t options = normal_options();
    CHECK(vireo_pool_create_with_allocator(&options, &allocator, &pool) == VIREO_OK);
    size_t control_bytes = fixture.records[0].size;
    size_t metadata_unit = fixture.records[2].size / options.capacity;
    CHECK(destroy_checked(&pool) == 0);
    options = (vireo_pool_options_t){.element_size = VIREO_POOL_MAX_MEMORY - control_bytes - metadata_unit, .element_alignment = 1,
        .capacity = 1,
        .max_memory_bytes = VIREO_POOL_MAX_MEMORY};
    /* 真实生产 malloc 的请求总量恰等硬限；不触碰未初始化槽位。 */
    errno = EACCES;
    CHECK(vireo_pool_create(&options, &pool) == VIREO_OK && errno == EACCES);
    vireo_pool_info_t info;
    CHECK(inspect_checked(pool, &info) == 0);
    CHECK(info.allocation_bytes == VIREO_POOL_MAX_MEMORY);
    CHECK(destroy_checked(&pool) == 0);
    ++options.element_size;
    CHECK(expect_rejection(options, VIREO_RESULT_RANGE) == 0);
    options = normal_options();
    options.max_memory_bytes = VIREO_POOL_MAX_MEMORY + 1;
    CHECK(expect_rejection(options, VIREO_RESULT_RANGE) == 0);
    return 0;
}

static int zero_and_non_power_inputs(void) {
    for (size_t field = 0; field < 4; ++field) {
        vireo_pool_options_t options = normal_options();
        switch (field) {
            case 0: options.element_size = 0; break;
            case 1: options.element_alignment = 0; break;
            case 2: options.capacity = 0; break;
            default: options.max_memory_bytes = 0; break;
        }
        CHECK(expect_rejection(options, VIREO_RESULT_INVALID_ARGUMENT) == 0);
    }
    vireo_pool_options_t options = normal_options();
    options.element_alignment = 3;
    CHECK(expect_rejection(options, VIREO_RESULT_INVALID_ARGUMENT) == 0);
    options.element_alignment = SIZE_MAX;
    CHECK(expect_rejection(options, VIREO_RESULT_INVALID_ARGUMENT) == 0);
    return 0;
}

static int unsupported_alignment(void) {
    CHECK(_Alignof(max_align_t) <= SIZE_MAX / 2);
    vireo_pool_options_t options = normal_options();
    options.element_alignment = 2 * _Alignof(max_align_t);
    CHECK(expect_rejection(options, VIREO_RESULT_RANGE) == 0);
    /* M1仍接受数值扩展对齐，M2的资源策略没有收紧其合同。 */
    vireo_pool_layout_t layout;
    CHECK(vireo_pool_layout_compute(13, options.element_alignment, 3,
        SIZE_MAX, &layout) == VIREO_OK);
    return 0;
}

static int arithmetic_and_priority(void) {
    vireo_pool_options_t options = {.element_size = SIZE_MAX, .element_alignment = 2,
        .capacity = 1, .max_memory_bytes = 1};
    CHECK(expect_rejection(options, VIREO_RESULT_OVERFLOW) == 0);
    options.element_alignment = 1;
    options.element_size = SIZE_MAX / 2 + 1;
    options.capacity = 2;
    CHECK(expect_rejection(options, VIREO_RESULT_OVERFLOW) == 0);
    options.element_size = SIZE_MAX;
    options.capacity = 1; /* storage可表示，加入控制块才溢出。 */
    CHECK(expect_rejection(options, VIREO_RESULT_OVERFLOW) == 0);
    options.max_memory_bytes = VIREO_POOL_MAX_MEMORY + 1;
    CHECK(expect_rejection(options, VIREO_RESULT_OVERFLOW) == 0);
    options.element_alignment = 2 * _Alignof(max_align_t);
    CHECK(expect_rejection(options, VIREO_RESULT_OVERFLOW) == 0);
    options.max_memory_bytes = 0;
    CHECK(expect_rejection(options, VIREO_RESULT_INVALID_ARGUMENT) == 0);
    return 0;
}

static int null_create_inputs(void) {
    vireo_pool_t *pool = NULL;
    vireo_pool_options_t options = normal_options();
    errno = EACCES;
    CHECK(vireo_pool_create(NULL, &pool) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(pool == NULL && errno == EACCES);
    CHECK(vireo_pool_create(&options, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(errno == EACCES);
    return 0;
}

static int nonempty_owner_preserved(void) {
    vireo_pool_t *pool = NULL;
    vireo_pool_options_t options = normal_options();
    CHECK(vireo_pool_create(&options, &pool) == VIREO_OK);
    vireo_pool_t *identity = pool; /* 仅作存活期间比较，不能独立销毁。 */
    fixture_t fixture = {0};
    vireo_pool_allocator_t allocator = allocator_for(&fixture);
    errno = EACCES;
    CHECK(vireo_pool_create_with_allocator(&options, &allocator, &pool) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(pool == identity && errno == EACCES && fixture.calls == 0);
    CHECK(vireo_pool_create(&options, &pool) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(pool == identity && errno == EACCES);
    vireo_pool_info_t info;
    CHECK(inspect_checked(pool, &info) == 0 && info.layout.storage_bytes == 48);
    CHECK(destroy_checked(&pool) == 0);
    return 0;
}

static int invalid_allocator(void) {
    vireo_pool_t *pool = NULL;
    vireo_pool_options_t options = normal_options();
    fixture_t fixture = {.observer = &pool};
    vireo_pool_allocator_t allocator = allocator_for(&fixture);
    errno = EACCES;
    CHECK(vireo_pool_create_with_allocator(&options, NULL, &pool) == VIREO_RESULT_INVALID_ARGUMENT);
    allocator.allocate = NULL;
    CHECK(vireo_pool_create_with_allocator(&options, &allocator, &pool) == VIREO_RESULT_INVALID_ARGUMENT);
    allocator = allocator_for(&fixture);
    allocator.deallocate = NULL;
    CHECK(vireo_pool_create_with_allocator(&options, &allocator, &pool) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(pool == NULL && errno == EACCES && fixture.calls == 0 && fixture.error == 0);
    return 0;
}

static int allocation_failures_and_retry(void) {
    for (size_t failure = 1; failure <= 3; ++failure) {
        vireo_pool_t *pool = NULL;
        fixture_t fixture = {.fail_at = failure, .observer = &pool};
        vireo_pool_allocator_t allocator = allocator_for(&fixture);
        vireo_pool_options_t options = normal_options();
        errno = EACCES;
        CHECK(vireo_pool_create_with_allocator(&options, &allocator, &pool) == VIREO_RESULT_NO_MEMORY);
        CHECK(pool == NULL && errno == EACCES && fixture.error == 0);
        CHECK(fixture.calls == failure && fixture.releases == failure - 1 && fixture.live_bytes == 0);
        for (size_t i = 0; i < failure - 1; ++i) {
            CHECK(fixture.release_order[i] == failure - 2 - i);
        }
        CHECK(destroy_checked(&pool) == 0 && fixture.releases == failure - 1);
        fixture = (fixture_t){.observer = &pool};
        CHECK(vireo_pool_create_with_allocator(&options, &allocator, &pool) == VIREO_OK);
        CHECK(destroy_checked(&pool) == 0 && fixture.live_bytes == 0 && fixture.releases == 3);
        CHECK(fixture.error == 0);
    }
    return 0;
}

static int copied_allocator_and_repeated_observation(void) {
    vireo_pool_t *pool = NULL;
    fixture_t fixture = {.observer = &pool};
    vireo_pool_allocator_t allocator = allocator_for(&fixture);
    vireo_pool_options_t options = normal_options();
    CHECK(vireo_pool_create_with_allocator(&options, &allocator, &pool) == VIREO_OK);
    allocator = (vireo_pool_allocator_t){0}; /* 配对表应已复制，不借用外部表。 */
    for (size_t i = 0; i < 5; ++i) {
        vireo_pool_info_t info;
        CHECK(inspect_checked(pool, &info) == 0);
        CHECK(info.allocation_bytes == fixture.live_bytes && info.layout.storage_bytes == 48);
        CHECK(fixture.calls == 3 && fixture.releases == 0 && fixture.error == 0);
    }
    CHECK(destroy_checked(&pool) == 0);
    CHECK(fixture.live_bytes == 0 && fixture.releases == 3 && fixture.error == 0);
    CHECK(fixture.release_order[0] == 2 && fixture.release_order[1] == 1 && fixture.release_order[2] == 0);
    return 0;
}

static int inspect_failures_preserve_output(void) {
    vireo_pool_info_t info;
    memset(&info, 0xA5, sizeof(info));
    unsigned char before[sizeof(info)];
    memcpy(before, &info, sizeof(info));
    errno = EACCES;
    CHECK(vireo_pool_inspect(NULL, &info) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(errno == EACCES && memcmp(before, &info, sizeof(info)) == 0);
    CHECK(vireo_pool_inspect(NULL, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(errno == EACCES);
    vireo_pool_t *pool = NULL;
    vireo_pool_options_t options = normal_options();
    CHECK(vireo_pool_create(&options, &pool) == VIREO_OK);
    CHECK(vireo_pool_inspect(pool, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(errno == EACCES);
    CHECK(inspect_checked(pool, &info) == 0 && info.layout.storage_bytes == 48);
    CHECK(destroy_checked(&pool) == 0);
    return 0;
}

static int destroy_null_and_empty(void) {
    errno = EACCES;
    CHECK(vireo_pool_destroy(NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(errno == EACCES);
    vireo_pool_t *pool = NULL;
    CHECK(destroy_checked(&pool) == 0);
    CHECK(destroy_checked(&pool) == 0);
    return 0;
}

static int independent_pools_and_repeated_cycles(void) {
    for (size_t cycle = 0; cycle < 128; ++cycle) {
        vireo_pool_t *first = NULL;
        vireo_pool_t *second = NULL;
        fixture_t fixture = {.observer = &first};
        vireo_pool_allocator_t allocator = allocator_for(&fixture);
        vireo_pool_options_t options = normal_options();
        CHECK(vireo_pool_create_with_allocator(&options, &allocator, &first) == VIREO_OK);
        options.capacity = 1;
        CHECK(vireo_pool_create(&options, &second) == VIREO_OK);
        CHECK(first != second);
        CHECK(destroy_checked(&first) == 0 && fixture.live_bytes == 0 && fixture.error == 0);
        vireo_pool_info_t info;
        CHECK(inspect_checked(second, &info) == 0);
        CHECK(info.layout.capacity == 1 && info.layout.storage_bytes == 16);
        CHECK(destroy_checked(&second) == 0);
        CHECK(fixture.releases == 3 && fixture.release_order[0] == 2 && fixture.release_order[1] == 1 && fixture.release_order[2] == 0);
    }
    return 0;
}

int main(void) {
    struct { char const *name; int (*run)(void); } const groups[] = {
        {"public_lifecycle", public_lifecycle},
        {"actual_alignment_and_accounting", actual_alignment_and_accounting},
        {"actual_c_type", actual_c_type},
        {"exact_total_budget", exact_total_budget},
        {"hard_memory_limit", hard_memory_limit},
        {"zero_and_non_power_inputs", zero_and_non_power_inputs},
        {"unsupported_alignment", unsupported_alignment},
        {"arithmetic_and_priority", arithmetic_and_priority},
        {"null_create_inputs", null_create_inputs},
        {"nonempty_owner_preserved", nonempty_owner_preserved},
        {"invalid_allocator", invalid_allocator},
        {"allocation_failures_and_retry", allocation_failures_and_retry},
        {"copied_allocator_and_repeated_observation", copied_allocator_and_repeated_observation},
        {"inspect_failures_preserve_output", inspect_failures_preserve_output},
        {"destroy_null_and_empty", destroy_null_and_empty},
        {"independent_pools_and_repeated_cycles", independent_pools_and_repeated_cycles},
    };
    for (size_t i = 0; i < sizeof(groups) / sizeof(groups[0]); ++i) {
        if (groups[i].run() != 0) {
            fprintf(stderr, "FAIL pool lifecycle: %s\n", groups[i].name);
            return EXIT_FAILURE;
        }
        printf("PASS pool lifecycle: %s\n", groups[i].name);
    }
    printf("pool lifecycle: %zu groups passed; 128 paired lifecycle cycles\n",
        sizeof(groups) / sizeof(groups[0]));
    return EXIT_SUCCESS;
}
