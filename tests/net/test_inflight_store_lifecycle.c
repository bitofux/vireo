/*
 * PROJECT : VIREO
 * FILE    : test_inflight_store_lifecycle.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-13
 * BRIEF   : 空表资源、受检边界、失败保持和配对分配核验
 */
#include "net/inflight_store_internal.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "line %d: %s\n", __LINE__, #condition); \
        return 1; \
    } \
} while (0)

#define EXPECT(expression, expected) do { \
    errno = E2BIG; \
    vireo_result_t const observed = (expression); \
    CHECK(observed == (expected)); \
    CHECK(errno == E2BIG); \
} while (0)

/** 实际 malloc/free 账本，寿命覆盖相关表；不是业务数据。 */
typedef struct allocation_trace {
    size_t allocate_calls; /**< 真实申请入口次数。 */
    size_t free_calls; /**< 真实配对释放次数。 */
    size_t last_bytes; /**< 最近申请量，与公开快照对照。 */
    void *live; /**< 尚未释放的实际原块，不产生第二所有权。 */
    bool fail; /**< 申请返回 NULL 的受控开关。 */
    bool bad_free; /**< 不匹配释放的粘性失败标记。 */
} allocation_trace_t;

/**
 * @brief
 *     真实申请并填充脏底色，或受控返回 NULL；主动改变 errno。
 *
 * @param[in,out] context
 *     存活单线程账本，覆盖相关表的寿命。
 * @param[in] bytes
 *     已受检正申请量。
 *
 * @return
 *     正确对齐独占块或 NULL。
 */
static void *trace_allocate(void *context, size_t bytes) {
    allocation_trace_t *trace = context;
    ++trace->allocate_calls;
    trace->last_bytes = bytes;
    errno = ENOMEM;
    if (trace->fail) {
        return NULL;
    }
    trace->live = malloc(bytes);
    if (trace->live != NULL) {
        memset(trace->live, 0xa5, bytes);
    }
    return trace->live;
}

/**
 * @brief
 *     记录配对原块释放，并主动改变 errno。
 *
 * @param[in,out] context
 *     存活单线程账本。
 * @param[in] allocation
 *     本账本的实际原块。
 *
 * @note
 *     不匹配时记录失败，不盲目释放陌生地址。
 */
static void trace_deallocate(void *context, void *allocation) {
    allocation_trace_t *trace = context;
    ++trace->free_calls;
    if (allocation != trace->live || allocation == NULL) {
        trace->bad_free = true;
    } else {
        free(allocation);
        trace->live = NULL;
    }
    errno = EBADF;
}

/** 创建小容量独立表，资源全部配对释放。 */
static int lifecycle(void) {
    size_t const capacities[] = {1, 3, VIREO_INFLIGHT_STORE_MAX_CAPACITY};
    for (size_t i = 0; i < sizeof(capacities) / sizeof(capacities[0]); ++i) {
        vireo_inflight_store_options_t options = {
            capacities[i], VIREO_INFLIGHT_STORE_MAX_ALLOCATION_BYTES
        };
        vireo_inflight_store_t *store = NULL;
        EXPECT(vireo_inflight_store_create(&options, &store), VIREO_OK);
        CHECK(store != NULL);
        vireo_inflight_store_info_t info = {0};
        EXPECT(vireo_inflight_store_inspect(store, &info), VIREO_OK);
        CHECK(info.capacity == capacities[i] && info.count == 0);
        CHECK(info.allocated_bytes > 0 && info.allocated_bytes <= options.max_memory_bytes);
        CHECK(info.max_memory_bytes == options.max_memory_bytes);
        EXPECT(vireo_inflight_store_destroy(&store), VIREO_OK);
        CHECK(store == NULL);
        EXPECT(vireo_inflight_store_destroy(&store), VIREO_OK);
    }
    return 0;
}

/** 基础地址/零值优先拒绝，不产生申请。 */
static int basic_errors(void) {
    allocation_trace_t trace = {0};
    vireo_inflight_store_allocator_t const ops = {&trace, trace_allocate, trace_deallocate};
    vireo_inflight_store_options_t options = {3, 4096};
    vireo_inflight_store_t *store = NULL;
    EXPECT(vireo_inflight_store_create(NULL, &store), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_inflight_store_create(&options, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    options.capacity = 0;
    EXPECT(vireo_inflight_store_create_with_allocator(&options, &ops, &store),
        VIREO_RESULT_INVALID_ARGUMENT);
    options.capacity = SIZE_MAX;
    options.max_memory_bytes = 0;
    EXPECT(vireo_inflight_store_create_with_allocator(&options, &ops, &store),
        VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(store == NULL && trace.allocate_calls == 0 && trace.free_calls == 0);
    EXPECT(vireo_inflight_store_destroy(NULL), VIREO_RESULT_INVALID_ARGUMENT);
    return 0;
}

/** 非空创建目标保持原表及完整公开快照。 */
static int nonempty_output(void) {
    vireo_inflight_store_options_t const options = {3, 4096};
    vireo_inflight_store_t *store = NULL;
    EXPECT(vireo_inflight_store_create(&options, &store), VIREO_OK);
    vireo_inflight_store_t *const original = store;
    vireo_inflight_store_info_t before = {0};
    EXPECT(vireo_inflight_store_inspect(store, &before), VIREO_OK);
    EXPECT(vireo_inflight_store_create(&options, &store), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_inflight_store_create(NULL, &store), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(store == original);
    vireo_inflight_store_info_t after = {0};
    EXPECT(vireo_inflight_store_inspect(store, &after), VIREO_OK);
    CHECK(after.capacity == before.capacity && after.count == before.count);
    CHECK(after.allocated_bytes == before.allocated_bytes);
    CHECK(after.max_memory_bytes == before.max_memory_bytes);
    EXPECT(vireo_inflight_store_destroy(&store), VIREO_OK);
    return 0;
}

/** 观测失败保持输出所有字节，NULL 地址不读取无效资源。 */
static int inspect_errors(void) {
    vireo_inflight_store_info_t info;
    memset(&info, 0xa5, sizeof(info));
    unsigned char original[sizeof(info)];
    memcpy(original, &info, sizeof(info));
    EXPECT(vireo_inflight_store_inspect(NULL, &info), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(memcmp(original, &info, sizeof(info)) == 0);
    EXPECT(vireo_inflight_store_inspect(NULL, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    vireo_inflight_store_options_t const options = {1, 4096};
    vireo_inflight_store_t *store = NULL;
    EXPECT(vireo_inflight_store_create(&options, &store), VIREO_OK);
    EXPECT(vireo_inflight_store_inspect(store, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_inflight_store_destroy(&store), VIREO_OK);
    return 0;
}

/** 精确公开预算可创建，差一字节拒绝；快照超过表寿命仍只是值。 */
static int exact_budget(void) {
    vireo_inflight_store_options_t options = {3, 4096};
    vireo_inflight_store_t *store = NULL;
    EXPECT(vireo_inflight_store_create(&options, &store), VIREO_OK);
    vireo_inflight_store_info_t info = {0};
    EXPECT(vireo_inflight_store_inspect(store, &info), VIREO_OK);
    EXPECT(vireo_inflight_store_destroy(&store), VIREO_OK);
    CHECK(info.capacity == 3 && info.count == 0 && info.allocated_bytes > 1);
    options.max_memory_bytes = info.allocated_bytes - 1;
    allocation_trace_t trace = {0};
    vireo_inflight_store_allocator_t const ops = {&trace, trace_allocate, trace_deallocate};
    EXPECT(vireo_inflight_store_create_with_allocator(&options, &ops, &store), VIREO_RESULT_RANGE);
    CHECK(store == NULL && trace.allocate_calls == 0);
    options.max_memory_bytes = info.allocated_bytes;
    EXPECT(vireo_inflight_store_create_with_allocator(&options, &ops, &store), VIREO_OK);
    CHECK(trace.last_bytes == info.allocated_bytes);
    EXPECT(vireo_inflight_store_inspect(store, &info), VIREO_OK);
    CHECK(info.allocated_bytes == info.max_memory_bytes);
    EXPECT(vireo_inflight_store_destroy(&store), VIREO_OK);
    CHECK(trace.free_calls == 1 && trace.live == NULL && !trace.bad_free);
    return 0;
}

/** 数值可表示但超硬限时不进入申请，owner 保持空。 */
static int limits(void) {
    allocation_trace_t trace = {0};
    vireo_inflight_store_allocator_t const ops = {&trace, trace_allocate, trace_deallocate};
    vireo_inflight_store_t *store = NULL;
    vireo_inflight_store_options_t options = {
        VIREO_INFLIGHT_STORE_MAX_CAPACITY + 1, VIREO_INFLIGHT_STORE_MAX_ALLOCATION_BYTES
    };
    EXPECT(vireo_inflight_store_create_with_allocator(&options, &ops, &store), VIREO_RESULT_RANGE);
    options.capacity = 1;
    options.max_memory_bytes = VIREO_INFLIGHT_STORE_MAX_ALLOCATION_BYTES + 1;
    EXPECT(vireo_inflight_store_create_with_allocator(&options, &ops, &store), VIREO_RESULT_RANGE);
    options.max_memory_bytes = 1;
    EXPECT(vireo_inflight_store_create_with_allocator(&options, &ops, &store), VIREO_RESULT_RANGE);
    CHECK(store == NULL && trace.allocate_calls == 0 && trace.free_calls == 0);
    return 0;
}

/** 乘法不可表示优先于限额；最后可表示乘积按实际布局检验加法边界。 */
static int arithmetic(void) {
    allocation_trace_t trace = {0};
    vireo_inflight_store_allocator_t const ops = {&trace, trace_allocate, trace_deallocate};
    vireo_inflight_store_t *store = NULL;
    vireo_inflight_store_options_t options = {SIZE_MAX, SIZE_MAX};
    EXPECT(vireo_inflight_store_create_with_allocator(&options, &ops, &store), VIREO_RESULT_OVERFLOW);
    size_t const width = sizeof(vireo_inflight_store_slot_t);
    options.capacity = SIZE_MAX / width;
    size_t const bytes = options.capacity * width; /* 由商的边界保证可表示。 */
    vireo_result_t const expected = sizeof(vireo_inflight_store_t) > SIZE_MAX - bytes
        ? VIREO_RESULT_OVERFLOW : VIREO_RESULT_RANGE;
    EXPECT(vireo_inflight_store_create_with_allocator(&options, &ops, &store), expected);
    CHECK(store == NULL && trace.allocate_calls == 0 && trace.free_calls == 0);
    printf("last_product_boundary: control=%zu slot=%zu result=%s\n",
        sizeof(vireo_inflight_store_t), width, vireo_result_name(expected));
    return 0;
}

/** 非完整 seam 表为基本错误，申请和输出保持。 */
static int allocator_errors(void) {
    allocation_trace_t trace = {0};
    vireo_inflight_store_allocator_t ops = {&trace, trace_allocate, trace_deallocate};
    vireo_inflight_store_options_t const options = {3, 4096};
    vireo_inflight_store_t *store = NULL;
    EXPECT(vireo_inflight_store_create_with_allocator(&options, NULL, &store),
        VIREO_RESULT_INVALID_ARGUMENT);
    ops.allocate = NULL;
    EXPECT(vireo_inflight_store_create_with_allocator(&options, &ops, &store),
        VIREO_RESULT_INVALID_ARGUMENT);
    ops.allocate = trace_allocate;
    ops.deallocate = NULL;
    EXPECT(vireo_inflight_store_create_with_allocator(&options, &ops, &store),
        VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(store == NULL && trace.allocate_calls == 0 && trace.free_calls == 0);
    return 0;
}

/** 真实申请入口 NULL 后无残留，可由 caller 明确再发起创建。 */
static int allocation_failure(void) {
    allocation_trace_t trace = {0};
    trace.fail = true;
    vireo_inflight_store_allocator_t const ops = {&trace, trace_allocate, trace_deallocate};
    vireo_inflight_store_options_t const options = {3, 4096};
    vireo_inflight_store_t *store = NULL;
    EXPECT(vireo_inflight_store_create_with_allocator(&options, &ops, &store), VIREO_RESULT_NO_MEMORY);
    CHECK(store == NULL && trace.allocate_calls == 1 && trace.free_calls == 0 && trace.live == NULL);
    trace.fail = false;
    EXPECT(vireo_inflight_store_create_with_allocator(&options, &ops, &store), VIREO_OK);
    CHECK(store != NULL && trace.allocate_calls == 2);
    EXPECT(vireo_inflight_store_destroy(&store), VIREO_OK);
    EXPECT(vireo_inflight_store_destroy(&store), VIREO_OK);
    CHECK(trace.free_calls == 1 && trace.live == NULL && !trace.bad_free);
    return 0;
}

/** 脏内存逐槽逻辑初始化，allocator 表副本与原块配对保持。 */
static int initialization_and_pairing(void) {
    allocation_trace_t trace = {0};
    vireo_inflight_store_allocator_t ops = {&trace, trace_allocate, trace_deallocate};
    vireo_inflight_store_options_t options = {3, 4096};
    vireo_inflight_store_t *store = NULL;
    EXPECT(vireo_inflight_store_create_with_allocator(&options, &ops, &store), VIREO_OK);
    CHECK(trace.allocate_calls == 1 && trace.live == store);
    CHECK(trace.last_bytes == store->allocated_bytes && store->count == 0);
    for (size_t i = 0; i < options.capacity; ++i) {
        vireo_task_metadata_t const metadata = store->slots[i].metadata;
        CHECK(!store->slots[i].occupied);
        CHECK(metadata.route.client_owner_id == 0 && metadata.route.client_slot_index == 0);
        CHECK(metadata.route.client_generation == 0 && metadata.route.request_sequence == 0);
        CHECK(metadata.request_instance_id == 0 && metadata.operation == 0 && metadata.deadline_ns == 0);
    }
    options.capacity = 0;
    options.max_memory_bytes = 0;
    ops.context = NULL;
    ops.allocate = NULL;
    ops.deallocate = NULL; /* 改 caller 原表不改变容器保存的配对表副本。 */
    vireo_inflight_store_info_t info = {0};
    EXPECT(vireo_inflight_store_inspect(store, &info), VIREO_OK);
    CHECK(info.capacity == 3 && info.max_memory_bytes == 4096);
    EXPECT(vireo_inflight_store_destroy(&store), VIREO_OK);
    CHECK(store == NULL && trace.free_calls == 1 && trace.live == NULL && !trace.bad_free);
    return 0;
}

/** 固定测试清单，不持有资源。 */
typedef struct test_case {
    char const *name; /**< 静态组名，借至进程结束。 */
    int (*run)(void); /**< 同步测试入口，0 为通过，非 0 为失败。 */
} test_case_t;

int main(void) {
    test_case_t const cases[] = {
        {"lifecycle", lifecycle}, {"basic_errors", basic_errors},
        {"nonempty_output", nonempty_output}, {"inspect_errors", inspect_errors},
        {"exact_budget", exact_budget}, {"limits", limits}, {"arithmetic", arithmetic},
        {"allocator_errors", allocator_errors}, {"allocation_failure", allocation_failure},
        {"initialization_and_pairing", initialization_and_pairing}
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        if (cases[i].run() != 0) {
            fprintf(stderr, "FAILED: %s\n", cases[i].name);
            return 1;
        }
        printf("PASS: %s\n", cases[i].name);
    }
    printf("inflight store lifecycle: %zu groups passed\n", sizeof(cases) / sizeof(cases[0]));
    return 0;
}
