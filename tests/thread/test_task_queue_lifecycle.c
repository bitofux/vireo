/*
 * PROJECT : VIREO
 * FILE    : test_task_queue_lifecycle.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-11
 * BRIEF   : 空资源、预算、输出保持及真实申请失败
 */

#include "thread/task_queue_internal.h"

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

/**
 * @brief
 *     测试自持的单块资源观测；真实malloc/free，无全局可变fault。
 */
typedef struct allocation_trace {
    size_t attempts; /**< 包括失败的申请次数。 */
    size_t releases; /**< 配对释放次数。 */
    size_t requested_bytes; /**< 最近一次实际申请字节数。 */
    void *live; /**< 当前真实块的观测别名，不增加owner。 */
    bool fail; /**< 是否让本上下文的申请返回NULL。 */
    bool mismatch; /**< 是否观测重复申请或错误配对释放。 */
} allocation_trace_t;

/**
 * @brief
 *     记录请求并真实申请或注入NULL；成功块填非零以检验构造初始化。
 *
 * @param[in,out] context
 *     存活独占trace，持续到配对释放结束。
 * @param[in] bytes
 *     正请求字节数。
 *
 * @return
 *     新足量正确对齐块或NULL，故意扰动errno以验证恢复。
 */
static void *trace_allocate(void *context, size_t bytes) {
    allocation_trace_t *trace = context;
    ++trace->attempts;
    trace->requested_bytes = bytes;
    if (trace->live != NULL) { trace->mismatch = true; }
    trace->live = trace->fail ? NULL : malloc(bytes);
    if (trace->live != NULL) { memset(trace->live, 0xa5, bytes); }
    errno = ENOMEM;
    return trace->live;
}

/**
 * @brief
 *     观测精确配对释放并扰动errno，不释放借用context。
 *
 * @param[in,out] context
 *     对应活跃块的存活独占trace。
 * @param[in] allocation
 *     配对分配返回的完整原块，无在途访问。
 *
 * @note
 *     无失败返回；错误配对用mismatch留给测试断言。
 */
static void trace_deallocate(void *context, void *allocation) {
    allocation_trace_t *trace = context;
    ++trace->releases;
    if (allocation == NULL || allocation != trace->live) { trace->mismatch = true; }
    free(allocation);
    trace->live = NULL;
    errno = EILSEQ;
}

static int public_resources_and_snapshots(void) {
    size_t const capacities[] = {1, 3, VIREO_TASK_QUEUE_MAX_CAPACITY};
    for (size_t i = 0; i < sizeof(capacities) / sizeof(capacities[0]); ++i) {
        vireo_task_queue_options_t options = {capacities[i], VIREO_TASK_QUEUE_MAX_ALLOCATION_BYTES};
        vireo_task_queue_t *queue = NULL;
        errno = EDOM;
        CHECK(vireo_task_queue_create(&options, &queue) == VIREO_OK && queue != NULL && errno == EDOM);
        options.capacity = 0;
        options.max_memory_bytes = 0;
        vireo_task_queue_info_t info;
        CHECK(vireo_task_queue_inspect(queue, &info) == VIREO_OK && errno == EDOM);
        CHECK(info.capacity == capacities[i] && info.count == 0);
        CHECK(info.allocated_bytes == sizeof(vireo_task_queue_t) + capacities[i] * sizeof(vireo_task_t *));
        CHECK(info.max_memory_bytes == VIREO_TASK_QUEUE_MAX_ALLOCATION_BYTES);
        for (size_t slot = 0; slot < capacities[i]; ++slot) { CHECK(queue->slots[slot] == NULL); }
        CHECK(vireo_task_queue_destroy(&queue) == VIREO_OK && queue == NULL && errno == EDOM);
        CHECK(info.capacity == capacities[i] && info.count == 0);
    }
    return 0;
}

static int basic_guards(void) {
    vireo_task_queue_options_t options = {3, VIREO_TASK_QUEUE_MAX_ALLOCATION_BYTES};
    vireo_task_queue_t *queue = NULL;
    errno = ENOTTY;
    CHECK(vireo_task_queue_create(NULL, &queue) == VIREO_RESULT_INVALID_ARGUMENT && queue == NULL);
    CHECK(vireo_task_queue_create(&options, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_task_queue_create(NULL, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    options.capacity = 0;
    CHECK(vireo_task_queue_create(&options, &queue) == VIREO_RESULT_INVALID_ARGUMENT);
    options.capacity = 3;
    options.max_memory_bytes = 0;
    CHECK(vireo_task_queue_create(&options, &queue) == VIREO_RESULT_INVALID_ARGUMENT && queue == NULL);
    options.max_memory_bytes = VIREO_TASK_QUEUE_MAX_ALLOCATION_BYTES;
    CHECK(vireo_task_queue_create(&options, &queue) == VIREO_OK);
    vireo_task_queue_t *const original = queue;
    CHECK(vireo_task_queue_create(&options, &queue) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_task_queue_create(NULL, &queue) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(queue == original && errno == ENOTTY);
    CHECK(vireo_task_queue_destroy(&queue) == VIREO_OK && queue == NULL && errno == ENOTTY);
    return 0;
}

static int budget_boundaries(void) {
    allocation_trace_t trace = {0};
    vireo_task_queue_allocator_t const allocator = {&trace, trace_allocate, trace_deallocate};
    size_t const exact = sizeof(vireo_task_queue_t) + 3 * sizeof(vireo_task_t *);
    size_t const budgets[] = {0, 1, exact - 1, VIREO_TASK_QUEUE_MAX_ALLOCATION_BYTES + 1};
    for (size_t i = 0; i < sizeof(budgets) / sizeof(budgets[0]); ++i) {
        vireo_task_queue_options_t const options = {3, budgets[i]};
        vireo_task_queue_t *queue = NULL;
        errno = EAGAIN;
        vireo_result_t const expected = i == 0 ? VIREO_RESULT_INVALID_ARGUMENT : VIREO_RESULT_RANGE;
        CHECK(vireo_task_queue_create_with_allocator(&options, &allocator, &queue) == expected);
        CHECK(queue == NULL && trace.attempts == 0 && trace.releases == 0 && errno == EAGAIN);
    }
    vireo_task_queue_options_t const options = {3, exact};
    vireo_task_queue_t *queue = NULL;
    errno = EBUSY;
    CHECK(vireo_task_queue_create_with_allocator(&options, &allocator, &queue) == VIREO_OK);
    CHECK(trace.requested_bytes == exact && trace.attempts == 1 && errno == EBUSY);
    vireo_task_queue_info_t info;
    CHECK(vireo_task_queue_inspect(queue, &info) == VIREO_OK);
    CHECK(info.allocated_bytes == exact && info.max_memory_bytes == exact);
    CHECK(vireo_task_queue_destroy(&queue) == VIREO_OK && queue == NULL && errno == EBUSY);
    CHECK(trace.releases == 1 && trace.live == NULL && !trace.mismatch);
    return 0;
}

static int arithmetic_before_limits(void) {
    allocation_trace_t trace = {0};
    vireo_task_queue_allocator_t const allocator = {&trace, trace_allocate, trace_deallocate};
    vireo_task_queue_options_t options = {SIZE_MAX, VIREO_TASK_QUEUE_MAX_ALLOCATION_BYTES + 1};
    vireo_task_queue_t *queue = NULL;
    errno = ERANGE;
    CHECK(vireo_task_queue_create_with_allocator(&options, &allocator, &queue) == VIREO_RESULT_OVERFLOW);
    /* 此次乘法可表示，加入控制块才溢出，不能被限额RANGE掩盖。 */
    options.capacity = SIZE_MAX / sizeof(vireo_task_t *);
    CHECK(vireo_task_queue_create_with_allocator(&options, &allocator, &queue) == VIREO_RESULT_OVERFLOW);
    options.capacity = VIREO_TASK_QUEUE_MAX_CAPACITY + 1;
    options.max_memory_bytes = VIREO_TASK_QUEUE_MAX_ALLOCATION_BYTES;
    CHECK(vireo_task_queue_create_with_allocator(&options, &allocator, &queue) == VIREO_RESULT_RANGE);
    options.capacity = SIZE_MAX;
    options.max_memory_bytes = 0;
    CHECK(vireo_task_queue_create_with_allocator(&options, &allocator, &queue) == VIREO_RESULT_INVALID_ARGUMENT);
    options.capacity = 0;
    options.max_memory_bytes = VIREO_TASK_QUEUE_MAX_ALLOCATION_BYTES + 1;
    CHECK(vireo_task_queue_create_with_allocator(&options, &allocator, &queue) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(queue == NULL && trace.attempts == 0 && trace.releases == 0 && errno == ERANGE);
    return 0;
}

static int allocation_failure_and_recovery(void) {
    allocation_trace_t trace = {.fail = true};
    vireo_task_queue_allocator_t const allocator = {&trace, trace_allocate, trace_deallocate};
    vireo_task_queue_options_t const options = {3, VIREO_TASK_QUEUE_MAX_ALLOCATION_BYTES};
    vireo_task_queue_t *queue = NULL;
    errno = EDOM;
    CHECK(vireo_task_queue_create_with_allocator(&options, &allocator, &queue) == VIREO_RESULT_NO_MEMORY);
    CHECK(queue == NULL && trace.attempts == 1 && trace.releases == 0 && trace.live == NULL);
    CHECK(errno == EDOM && !trace.mismatch);
    trace.fail = false;
    CHECK(vireo_task_queue_create_with_allocator(&options, &allocator, &queue) == VIREO_OK);
    CHECK(queue != NULL && trace.attempts == 2 && errno == EDOM);
    CHECK(queue->count == 0 && queue->slots[0] == NULL && queue->slots[1] == NULL && queue->slots[2] == NULL);
    CHECK(vireo_task_queue_destroy(&queue) == VIREO_OK && queue == NULL && errno == EDOM);
    CHECK(trace.releases == 1 && trace.live == NULL && !trace.mismatch);
    return 0;
}

static int allocator_copy_and_private_guards(void) {
    allocation_trace_t trace = {0};
    vireo_task_queue_allocator_t allocator = {&trace, trace_allocate, trace_deallocate};
    vireo_task_queue_options_t const options = {1, VIREO_TASK_QUEUE_MAX_ALLOCATION_BYTES};
    vireo_task_queue_t *queue = NULL;
    errno = EINVAL;
    CHECK(vireo_task_queue_create_with_allocator(&options, NULL, &queue) == VIREO_RESULT_INVALID_ARGUMENT);
    allocator.allocate = NULL;
    CHECK(vireo_task_queue_create_with_allocator(&options, &allocator, &queue) == VIREO_RESULT_INVALID_ARGUMENT);
    allocator.allocate = trace_allocate;
    allocator.deallocate = NULL;
    CHECK(vireo_task_queue_create_with_allocator(&options, &allocator, &queue) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(queue == NULL && trace.attempts == 0 && errno == EINVAL);
    allocator.deallocate = trace_deallocate;
    CHECK(vireo_task_queue_create_with_allocator(&options, &allocator, &queue) == VIREO_OK);
    allocator.context = NULL;
    allocator.allocate = NULL;
    allocator.deallocate = NULL;
    CHECK(vireo_task_queue_destroy(&queue) == VIREO_OK && queue == NULL && errno == EINVAL);
    CHECK(trace.attempts == 1 && trace.releases == 1 && trace.live == NULL && !trace.mismatch);
    return 0;
}

static int query_failure_preserves(void) {
    vireo_task_queue_info_t info;
    unsigned char before[sizeof(info)];
    memset(&info, 0xa7, sizeof(info));
    memcpy(before, &info, sizeof(info));
    errno = EPIPE;
    CHECK(vireo_task_queue_inspect(NULL, &info) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(memcmp(before, &info, sizeof(info)) == 0 && errno == EPIPE);
    CHECK(vireo_task_queue_inspect(NULL, NULL) == VIREO_RESULT_INVALID_ARGUMENT && errno == EPIPE);
    vireo_task_queue_options_t const options = {3, VIREO_TASK_QUEUE_MAX_ALLOCATION_BYTES};
    vireo_task_queue_t *queue = NULL;
    CHECK(vireo_task_queue_create(&options, &queue) == VIREO_OK);
    CHECK(vireo_task_queue_inspect(queue, NULL) == VIREO_RESULT_INVALID_ARGUMENT && errno == EPIPE);
    CHECK(queue->capacity == 3 && queue->count == 0);
    CHECK(vireo_task_queue_inspect(queue, &info) == VIREO_OK && info.capacity == 3 && info.count == 0);
    CHECK(vireo_task_queue_destroy(&queue) == VIREO_OK && queue == NULL && errno == EPIPE);
    return 0;
}

static int destroy_idempotent(void) {
    vireo_task_queue_t *queue = NULL;
    errno = E2BIG;
    CHECK(vireo_task_queue_destroy(NULL) == VIREO_RESULT_INVALID_ARGUMENT && errno == E2BIG);
    CHECK(vireo_task_queue_destroy(&queue) == VIREO_OK && queue == NULL && errno == E2BIG);
    allocation_trace_t trace = {0};
    vireo_task_queue_allocator_t const allocator = {&trace, trace_allocate, trace_deallocate};
    vireo_task_queue_options_t const options = {1, VIREO_TASK_QUEUE_MAX_ALLOCATION_BYTES};
    CHECK(vireo_task_queue_create_with_allocator(&options, &allocator, &queue) == VIREO_OK);
    CHECK(vireo_task_queue_destroy(&queue) == VIREO_OK && queue == NULL && errno == E2BIG);
    CHECK(vireo_task_queue_destroy(&queue) == VIREO_OK && queue == NULL && errno == E2BIG);
    CHECK(trace.attempts == 1 && trace.releases == 1 && trace.live == NULL && !trace.mismatch);
    return 0;
}

static int independent_resources(void) {
    allocation_trace_t left_trace = {0};
    allocation_trace_t right_trace = {0};
    vireo_task_queue_allocator_t const left_allocator = {&left_trace, trace_allocate, trace_deallocate};
    vireo_task_queue_allocator_t const right_allocator = {&right_trace, trace_allocate, trace_deallocate};
    vireo_task_queue_options_t const left_options = {1, VIREO_TASK_QUEUE_MAX_ALLOCATION_BYTES};
    vireo_task_queue_options_t const right_options = {3, VIREO_TASK_QUEUE_MAX_ALLOCATION_BYTES};
    vireo_task_queue_t *left = NULL;
    vireo_task_queue_t *right = NULL;
    errno = ENOSPC;
    CHECK(vireo_task_queue_create_with_allocator(&left_options, &left_allocator, &left) == VIREO_OK);
    CHECK(vireo_task_queue_create_with_allocator(&right_options, &right_allocator, &right) == VIREO_OK);
    CHECK(left != right && left_trace.live != right_trace.live && errno == ENOSPC);
    CHECK(vireo_task_queue_destroy(&left) == VIREO_OK && left == NULL);
    CHECK(left_trace.releases == 1 && right_trace.releases == 0 && right_trace.live == right);
    vireo_task_queue_info_t info;
    CHECK(vireo_task_queue_inspect(right, &info) == VIREO_OK && info.capacity == 3 && info.count == 0);
    CHECK(vireo_task_queue_destroy(&right) == VIREO_OK && right == NULL && errno == ENOSPC);
    CHECK(right_trace.releases == 1 && !left_trace.mismatch && !right_trace.mismatch);
    return 0;
}

#define RUN(group) do { \
    if (group() != 0) { return 1; } \
    printf("PASS %s\n", #group); \
} while (0)

int main(void) {
    RUN(public_resources_and_snapshots);
    RUN(basic_guards);
    RUN(budget_boundaries);
    RUN(arithmetic_before_limits);
    RUN(allocation_failure_and_recovery);
    RUN(allocator_copy_and_private_guards);
    RUN(query_failure_preserves);
    RUN(destroy_idempotent);
    RUN(independent_resources);
    puts("test_task_queue_lifecycle: 9 groups passed");
    return 0;
}
