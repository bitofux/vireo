/*
 * PROJECT : VIREO
 * FILE    : test_completion_queue_lifecycle.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-12
 * BRIEF   : 固定空容器、受检边界、独立快照与实际分配失败核验
 */

#include "thread/completion_queue_internal.h"

#include <errno.h>
#include <stdbool.h>
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
    vireo_result_t const observed_result = (expression); \
    CHECK(observed_result == (expected)); \
    CHECK(errno == E2BIG); \
} while (0)

/** 本核心实际分配/释放账本，寿命覆盖相关队列，不替代真实 malloc/free。 */
typedef struct allocation_trace {
    size_t allocate_calls; /**< 实际进入申请 callback 的次数。 */
    size_t free_calls; /**< 实际进入释放 callback 的次数。 */
    size_t last_bytes; /**< 最近申请字节数，用于与公开申请快照比对。 */
    void *live; /**< 账本追踪的未释放原块，只由对应 callback 更新。 */
    bool fail; /**< 本次申请直接返回 NULL，不产生块。 */
    bool bad_free; /**< 曾收到不匹配原块的粘性错误标志。 */
} allocation_trace_t;

/**
 * @brief
 *     真实申请或返回 NULL，并主动扰动 errno 以验证外层保持。
 *
 * @param[in,out] context
 *     必需账本地址，单线程使用且存活到全部相关队列销毁。
 * @param[in] bytes
 *     已受检正申请量。
 *
 * @return
 *     全新正确对齐块或 NULL，账本记录真实申请，不伪造指针。
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
        memset(trace->live, 0xa5, bytes); /* 未初始化槽的脏底色，必须由构造逐槽赋 NULL。 */
    }
    return trace->live;
}

/**
 * @brief
 *     实际配对释放原块，同时记录错误配对并扰动 errno。
 *
 * @param[in,out] context
 *     存活账本，原块及其队列全部访问已经结束。
 * @param[in] allocation
 *     构造 callback 返回的唯一原块。
 *
 * @note
 *     无失败返回；非原块只记录错误，不执行非法 free。
 */
static void trace_deallocate(void *context, void *allocation) {
    allocation_trace_t *trace = context;
    ++trace->free_calls;
    if (allocation != trace->live) {
        trace->bad_free = true;
    } else {
        free(allocation);
        trace->live = NULL;
    }
    errno = EIO;
}

/* 最小、非 2 幂及最大容量均为空，正常 owner 清零且可重复销毁。 */
static int capacities(void) {
    size_t const capacities_to_test[] = {1, 3, VIREO_COMPLETION_QUEUE_MAX_CAPACITY};
    for (size_t i = 0; i < sizeof(capacities_to_test) / sizeof(capacities_to_test[0]); ++i) {
        vireo_completion_queue_options_t const options = {capacities_to_test[i],
            VIREO_COMPLETION_QUEUE_MAX_ALLOCATION_BYTES};
        vireo_completion_queue_t *queue = NULL;
        EXPECT(vireo_completion_queue_create(&options, &queue), VIREO_OK);
        CHECK(queue != NULL);
        vireo_completion_queue_info_t info = {0};
        EXPECT(vireo_completion_queue_inspect(queue, &info), VIREO_OK);
        CHECK(info.capacity == capacities_to_test[i] && info.count == 0);
        CHECK(info.allocated_bytes > 0 && info.allocated_bytes <= info.max_memory_bytes);
        CHECK(info.max_memory_bytes == options.max_memory_bytes);
        for (size_t slot = 0; slot < info.capacity; ++slot) {
            CHECK(queue->slots[slot] == NULL); /* 仅本核心私有核验空槽不变量。 */
        }
        EXPECT(vireo_completion_queue_destroy(&queue), VIREO_OK);
        CHECK(queue == NULL);
        EXPECT(vireo_completion_queue_destroy(&queue), VIREO_OK);
    }
    return 0;
}

/* 选项不被长期借用，快照可修改且可超过容器寿命。 */
static int independent_values(void) {
    vireo_completion_queue_options_t options = {3, 4096};
    unsigned char original[sizeof(options)];
    memcpy(original, &options, sizeof(options));
    vireo_completion_queue_t *queue = NULL;
    EXPECT(vireo_completion_queue_create(&options, &queue), VIREO_OK);
    CHECK(memcmp(&options, original, sizeof(options)) == 0);
    options = (vireo_completion_queue_options_t){1, 1};
    vireo_completion_queue_info_t info = {0};
    EXPECT(vireo_completion_queue_inspect(queue, &info), VIREO_OK);
    CHECK(info.capacity == 3 && info.count == 0 && info.max_memory_bytes == 4096);
    size_t const bytes = info.allocated_bytes;
    info = (vireo_completion_queue_info_t){99, 98, 97, 96, true, true};
    EXPECT(vireo_completion_queue_inspect(queue, &info), VIREO_OK);
    CHECK(info.capacity == 3 && info.count == 0 && info.allocated_bytes == bytes && !info.closed && !info.wait_prepared);
    EXPECT(vireo_completion_queue_destroy(&queue), VIREO_OK);
    CHECK(queue == NULL && info.capacity == 3 && info.max_memory_bytes == 4096);
    CHECK(info.allocated_bytes == bytes && info.count == 0);
    return 0;
}

static int invalid_creation(void) {
    vireo_completion_queue_options_t options = {1, 4096};
    vireo_completion_queue_t *queue = NULL;
    EXPECT(vireo_completion_queue_create(NULL, &queue), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_completion_queue_create(&options, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_completion_queue_create(NULL, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    options.capacity = 0;
    EXPECT(vireo_completion_queue_create(&options, &queue), VIREO_RESULT_INVALID_ARGUMENT);
    options.capacity = SIZE_MAX;
    options.max_memory_bytes = 0;
    EXPECT(vireo_completion_queue_create(&options, &queue), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(queue == NULL);
    options = (vireo_completion_queue_options_t){1, 4096};
    EXPECT(vireo_completion_queue_create(&options, &queue), VIREO_OK);
    vireo_completion_queue_t *const original = queue;
    EXPECT(vireo_completion_queue_create(&options, &queue), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(queue == original);
    vireo_completion_queue_info_t info = {0};
    EXPECT(vireo_completion_queue_inspect(queue, &info), VIREO_OK);
    CHECK(info.capacity == 1 && info.count == 0 && info.max_memory_bytes == 4096);
    EXPECT(vireo_completion_queue_destroy(&queue), VIREO_OK);
    return 0;
}

/* 非 OK 查询完整保留输出字节，NULL owner 地址与空 owner 值有不同合同。 */
static int invalid_observation_and_destroy(void) {
    vireo_completion_queue_info_t info;
    memset(&info, 0x5a, sizeof(info));
    unsigned char before[sizeof(info)];
    memcpy(before, &info, sizeof(info));
    EXPECT(vireo_completion_queue_inspect(NULL, &info), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(memcmp(before, &info, sizeof(info)) == 0);
    EXPECT(vireo_completion_queue_inspect(NULL, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_completion_queue_destroy(NULL), VIREO_RESULT_INVALID_ARGUMENT);
    vireo_completion_queue_t *queue = NULL;
    EXPECT(vireo_completion_queue_destroy(&queue), VIREO_OK);
    vireo_completion_queue_options_t const options = {3, 4096};
    EXPECT(vireo_completion_queue_create(&options, &queue), VIREO_OK);
    EXPECT(vireo_completion_queue_inspect(queue, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_completion_queue_inspect(queue, &info), VIREO_OK);
    CHECK(info.capacity == 3 && info.count == 0);
    EXPECT(vireo_completion_queue_destroy(&queue), VIREO_OK);
    return 0;
}

/* 限额拒绝在实际申请之前，预算非零不代表足够。 */
static int hard_limits(void) {
    allocation_trace_t trace = {0};
    vireo_completion_queue_allocator_t const allocator = {&trace, trace_allocate, trace_deallocate};
    vireo_completion_queue_t *queue = NULL;
    vireo_completion_queue_options_t options = {VIREO_COMPLETION_QUEUE_MAX_CAPACITY + 1,
        VIREO_COMPLETION_QUEUE_MAX_ALLOCATION_BYTES};
    EXPECT(vireo_completion_queue_create_with_allocator(&options, &allocator, &queue),
        VIREO_RESULT_RANGE);
    options = (vireo_completion_queue_options_t){1,
        VIREO_COMPLETION_QUEUE_MAX_ALLOCATION_BYTES + 1};
    EXPECT(vireo_completion_queue_create_with_allocator(&options, &allocator, &queue),
        VIREO_RESULT_RANGE);
    options.max_memory_bytes = 1;
    EXPECT(vireo_completion_queue_create_with_allocator(&options, &allocator, &queue),
        VIREO_RESULT_RANGE);
    CHECK(queue == NULL && trace.allocate_calls == 0 && trace.live == NULL);
    return 0;
}

/* 从公开快照取得申请量，精确预算成功，少 1 字节失败；不固定公共 sizeof。 */
static int exact_budget(void) {
    vireo_completion_queue_options_t options = {3, 4096};
    vireo_completion_queue_t *queue = NULL;
    EXPECT(vireo_completion_queue_create(&options, &queue), VIREO_OK);
    vireo_completion_queue_info_t info = {0};
    EXPECT(vireo_completion_queue_inspect(queue, &info), VIREO_OK);
    size_t const bytes = info.allocated_bytes;
    CHECK(bytes > 1);
    EXPECT(vireo_completion_queue_destroy(&queue), VIREO_OK);
    options.max_memory_bytes = bytes;
    EXPECT(vireo_completion_queue_create(&options, &queue), VIREO_OK);
    EXPECT(vireo_completion_queue_inspect(queue, &info), VIREO_OK);
    CHECK(info.allocated_bytes == bytes && info.max_memory_bytes == bytes && info.count == 0);
    EXPECT(vireo_completion_queue_destroy(&queue), VIREO_OK);
    options.max_memory_bytes = bytes - 1;
    EXPECT(vireo_completion_queue_create(&options, &queue), VIREO_RESULT_RANGE);
    CHECK(queue == NULL);
    return 0;
}

/* 分别命中乘法、加法不可表示；即使容量已超硬限仍必须先返回 OVERFLOW。 */
static int checked_arithmetic(void) {
    allocation_trace_t trace = {0};
    vireo_completion_queue_allocator_t const allocator = {&trace, trace_allocate, trace_deallocate};
    vireo_completion_queue_t *queue = NULL;
    size_t const pointer_bytes = sizeof(vireo_completion_t *);
    vireo_completion_queue_options_t options = {SIZE_MAX,
        VIREO_COMPLETION_QUEUE_MAX_ALLOCATION_BYTES};
    EXPECT(vireo_completion_queue_create_with_allocator(&options, &allocator, &queue),
        VIREO_RESULT_OVERFLOW);
    options.capacity = SIZE_MAX / pointer_bytes;
    CHECK(sizeof(vireo_completion_queue_t) > SIZE_MAX % pointer_bytes);
    EXPECT(vireo_completion_queue_create_with_allocator(&options, &allocator, &queue),
        VIREO_RESULT_OVERFLOW);
    options.max_memory_bytes = VIREO_COMPLETION_QUEUE_MAX_ALLOCATION_BYTES + 1;
    EXPECT(vireo_completion_queue_create_with_allocator(&options, &allocator, &queue),
        VIREO_RESULT_OVERFLOW);
    options.max_memory_bytes = 0;
    EXPECT(vireo_completion_queue_create_with_allocator(&options, &allocator, &queue),
        VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(queue == NULL && trace.allocate_calls == 0 && trace.free_calls == 0);
    return 0;
}

/* 真实 NULL 分配没有半发布，之后成功申请可正常配对释放；不是实际系统 OOM。 */
static int allocation_failure(void) {
    allocation_trace_t trace = {0};
    trace.fail = true;
    vireo_completion_queue_allocator_t const allocator = {&trace, trace_allocate, trace_deallocate};
    vireo_completion_queue_options_t const options = {3, 4096};
    vireo_completion_queue_t *queue = NULL;
    EXPECT(vireo_completion_queue_create_with_allocator(&options, &allocator, &queue),
        VIREO_RESULT_NO_MEMORY);
    CHECK(queue == NULL && trace.allocate_calls == 1 && trace.free_calls == 0 && trace.live == NULL);
    EXPECT(vireo_completion_queue_destroy(&queue), VIREO_OK);
    CHECK(trace.free_calls == 0);
    trace.fail = false;
    EXPECT(vireo_completion_queue_create_with_allocator(&options, &allocator, &queue), VIREO_OK);
    vireo_completion_queue_info_t info = {0};
    EXPECT(vireo_completion_queue_inspect(queue, &info), VIREO_OK);
    CHECK(info.allocated_bytes == trace.last_bytes && trace.allocate_calls == 2);
    for (size_t i = 0; i < info.capacity; ++i) {
        CHECK(queue->slots[i] == NULL);
    }
    EXPECT(vireo_completion_queue_destroy(&queue), VIREO_OK);
    CHECK(queue == NULL && trace.free_calls == 1 && trace.live == NULL && !trace.bad_free);
    return 0;
}

/* 只 own seam 的非法表及按值保存验证：不能借已返回的操作表地址。 */
static int paired_allocator(void) {
    allocation_trace_t trace = {0};
    vireo_completion_queue_allocator_t allocator = {&trace, trace_allocate, trace_deallocate};
    vireo_completion_queue_options_t const options = {3, 4096};
    vireo_completion_queue_t *queue = NULL;
    EXPECT(vireo_completion_queue_create_with_allocator(&options, NULL, &queue),
        VIREO_RESULT_INVALID_ARGUMENT);
    allocator.allocate = NULL;
    EXPECT(vireo_completion_queue_create_with_allocator(&options, &allocator, &queue),
        VIREO_RESULT_INVALID_ARGUMENT);
    allocator.allocate = trace_allocate;
    allocator.deallocate = NULL;
    EXPECT(vireo_completion_queue_create_with_allocator(&options, &allocator, &queue),
        VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(queue == NULL && trace.allocate_calls == 0);
    allocator.deallocate = trace_deallocate;
    EXPECT(vireo_completion_queue_create_with_allocator(&options, &allocator, &queue), VIREO_OK);
    vireo_completion_queue_t *const original = queue;
    EXPECT(vireo_completion_queue_create_with_allocator(&options, &allocator, &queue),
        VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(queue == original && trace.allocate_calls == 1 && trace.free_calls == 0);
    allocator = (vireo_completion_queue_allocator_t){0};
    EXPECT(vireo_completion_queue_destroy(&queue), VIREO_OK);
    EXPECT(vireo_completion_queue_destroy(&queue), VIREO_OK);
    CHECK(queue == NULL && trace.live == NULL && trace.free_calls == 1 && !trace.bad_free);
    return 0;
}

/** 固定场景清单，名称与函数只在 main 的顺序执行期使用。 */
typedef struct test_case {
    char const *name; /**< 静态场景名，不分配或释放。 */
    int (*run)(void); /**< 无参测试函数，0 表示该组通过。 */
} test_case_t;

int main(void) {
    test_case_t const cases[] = {
        {"capacities", capacities},
        {"independent_values", independent_values},
        {"invalid_creation", invalid_creation},
        {"invalid_observation_and_destroy", invalid_observation_and_destroy},
        {"hard_limits", hard_limits},
        {"exact_budget", exact_budget},
        {"checked_arithmetic", checked_arithmetic},
        {"allocation_failure", allocation_failure},
        {"paired_allocator", paired_allocator}
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        if (cases[i].run() != 0) {
            fprintf(stderr, "FAIL %s\n", cases[i].name);
            return EXIT_FAILURE;
        }
        printf("PASS %s\n", cases[i].name);
    }
    puts("completion queue lifecycle: 9 groups passed");
    return EXIT_SUCCESS;
}
