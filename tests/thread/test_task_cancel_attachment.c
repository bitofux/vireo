/*
 * PROJECT : VIREO
 * FILE    : test_task_cancel_attachment.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-11
 * BRIEF   : task取消关联、引用回滚与真实线程交接验证
 */

#include "thread/task_internal.h"
#include "thread/task_cancel_internal.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #condition); \
        return 1; \
    } \
} while (0)

/** @brief 本核心独占 seam；线程场景只在创建前或 join 后读写观测数据。 */
typedef struct allocation_trace {
    size_t attempts; /**< 包含失败的申请次数。 */
    size_t releases; /**< 原块配对释放次数。 */
    size_t bytes; /**< 最近申请量，字节。 */
    void *live; /**< 活跃块观测别名，不额外拥有。 */
    bool fail; /**< 本次上下文让申请返回 NULL。 */
    bool mismatch; /**< 重复申请或不配对释放标志。 */
    vireo_task_cancel_t *observe_cancel; /**< 仅独占构造时短借的状态，不新增引用。 */
    uint64_t references_at_allocate; /**< 申请调用时观测计数，证明 retain 先于申请。 */
} allocation_trace_t;

static void *trace_allocate(void *context, size_t bytes) {
    allocation_trace_t *trace = context;
    trace->attempts++;
    trace->bytes = bytes;
    if (trace->live != NULL) {
        trace->mismatch = true;
    }
    if (trace->observe_cancel != NULL) {
        trace->references_at_allocate = atomic_load(&trace->observe_cancel->references);
    }
    trace->live = trace->fail ? NULL : malloc(bytes);
    errno = ENOMEM;
    return trace->live;
}

static void trace_deallocate(void *context, void *allocation) {
    allocation_trace_t *trace = context;
    trace->releases++;
    if (allocation == NULL || allocation != trace->live) {
        trace->mismatch = true;
    }
    free(allocation);
    trace->live = NULL;
    errno = EILSEQ;
}

static vireo_task_metadata_t metadata(void) {
    vireo_task_metadata_t const value = {{7, 0, 3, 11}, 42, 1, 100};
    return value;
}

static uint64_t references(vireo_task_cancel_t *cancel) {
    /* 只用于无并发的本核心受控对象，不是公共观测入口。 */
    return atomic_load(&cancel->references);
}

static int legacy_without_cancel(void) {
    vireo_task_t *task = NULL;
    vireo_task_cancel_t *extra = NULL;
    errno = EDOM;
    CHECK(vireo_task_create_copy(metadata(), NULL, 0, 1024, &task) == VIREO_OK);
    bool requested = true;
    CHECK(vireo_task_is_cancel_requested(task, &requested) == VIREO_OK && !requested);
    CHECK(vireo_task_retain_cancel(task, &extra) == VIREO_RESULT_NOT_FOUND && extra == NULL);
    CHECK(vireo_task_destroy(&task) == VIREO_OK && task == NULL && errno == EDOM);
    return 0;
}

static int copy_and_source_lifetime(void) {
    allocation_trace_t trace = {0};
    vireo_task_cancel_allocator_t const allocator = {&trace, trace_allocate, trace_deallocate};
    vireo_task_cancel_t *source = NULL;
    vireo_task_t *task = NULL;
    unsigned char input[] = {0, 255, 17, 0};
    unsigned char const expected[] = {0, 255, 17, 0};
    errno = EDOM;
    CHECK(vireo_task_cancel_create_with_allocator(1024, &allocator, &source) == VIREO_OK);
    CHECK(vireo_task_create_copy_with_cancel(metadata(), input, sizeof(input), 1024,
                                             source, &task) == VIREO_OK);
    CHECK(references(source) == 2);
    memset(input, 5, sizeof(input));
    vireo_task_info_t info;
    CHECK(vireo_task_inspect(task, &info) == VIREO_OK);
    CHECK(info.metadata.route.client_owner_id == 7 && info.metadata.route.client_slot_index == 0);
    CHECK(info.metadata.route.client_generation == 3 && info.metadata.route.request_sequence == 11);
    CHECK(info.metadata.request_instance_id == 42 && info.metadata.operation == 1);
    CHECK(info.metadata.deadline_ns == 100 && info.payload_size == sizeof(input));
    CHECK(info.allocated_bytes == sizeof(vireo_task_t) + sizeof(input));
    {
        vireo_task_payload_view_t view;
        CHECK(vireo_task_borrow_payload(task, &view) == VIREO_OK);
        CHECK(view.data != input && view.size == sizeof(expected));
        CHECK(memcmp(view.data, expected, sizeof(expected)) == 0);
    }
    bool requested = true;
    CHECK(vireo_task_is_cancel_requested(task, &requested) == VIREO_OK && !requested);
    CHECK(vireo_task_cancel_request(source) == VIREO_OK);
    CHECK(vireo_task_cancel_destroy(&source) == VIREO_OK && source == NULL && trace.releases == 0);
    CHECK(vireo_task_is_cancel_requested(task, &requested) == VIREO_OK && requested);
    CHECK(vireo_task_destroy(&task) == VIREO_OK && task == NULL && errno == EDOM);
    CHECK(trace.attempts == 1 && trace.releases == 1 && trace.live == NULL && !trace.mismatch);
    return 0;
}

static int already_requested_and_finite_deadlines(void) {
    uint64_t const deadlines[] = {0, UINT64_MAX};
    vireo_task_cancel_t *source = NULL;
    errno = ERANGE;
    CHECK(vireo_task_cancel_create(1024, &source) == VIREO_OK);
    CHECK(vireo_task_cancel_request(source) == VIREO_OK);
    for (size_t i = 0; i < 2; i++) {
        vireo_task_metadata_t value = metadata();
        value.deadline_ns = deadlines[i];
        vireo_task_t *task = NULL;
        CHECK(vireo_task_create_copy_with_cancel(value, NULL, 0, sizeof(vireo_task_t),
                                                 source, &task) == VIREO_OK);
        bool requested = false;
        CHECK(vireo_task_is_cancel_requested(task, &requested) == VIREO_OK && requested);
        vireo_task_info_t info;
        CHECK(vireo_task_inspect(task, &info) == VIREO_OK && info.metadata.deadline_ns == deadlines[i]);
        vireo_task_payload_view_t view;
        CHECK(vireo_task_borrow_payload(task, &view) == VIREO_OK && view.data == NULL && view.size == 0);
        CHECK(vireo_task_destroy(&task) == VIREO_OK && references(source) == 1);
    }
    CHECK(vireo_task_cancel_destroy(&source) == VIREO_OK && errno == ERANGE);
    return 0;
}

static int extracted_reference_outlives_task(void) {
    allocation_trace_t trace = {0};
    vireo_task_cancel_allocator_t const allocator = {&trace, trace_allocate, trace_deallocate};
    vireo_task_cancel_t *source = NULL;
    vireo_task_cancel_t *extra = NULL;
    vireo_task_t *task = NULL;
    errno = EDOM;
    CHECK(vireo_task_cancel_create_with_allocator(1024, &allocator, &source) == VIREO_OK);
    CHECK(vireo_task_create_copy_with_cancel(metadata(), NULL, 0, 1024, source, &task) == VIREO_OK);
    CHECK(vireo_task_retain_cancel(task, &extra) == VIREO_OK && extra == source && references(extra) == 3);
    CHECK(vireo_task_cancel_destroy(&source) == VIREO_OK);
    CHECK(vireo_task_destroy(&task) == VIREO_OK && trace.releases == 0 && references(extra) == 1);
    bool requested = true;
    CHECK(vireo_task_cancel_is_requested(extra, &requested) == VIREO_OK && !requested);
    CHECK(vireo_task_cancel_request(extra) == VIREO_OK);
    CHECK(vireo_task_cancel_is_requested(extra, &requested) == VIREO_OK && requested);
    CHECK(vireo_task_cancel_destroy(&extra) == VIREO_OK && trace.releases == 1 && errno == EDOM);
    CHECK(trace.live == NULL && !trace.mismatch);
    return 0;
}

static int basic_creation_guards(void) {
    vireo_task_cancel_t *source = NULL;
    vireo_task_t *task = NULL;
    vireo_task_t *occupied = NULL;
    unsigned char const byte = 1;
    errno = EDOM;
    CHECK(vireo_task_cancel_create(1024, &source) == VIREO_OK);
    CHECK(vireo_task_create_copy(metadata(), NULL, 0, 1024, &occupied) == VIREO_OK);
    vireo_task_t *const original = occupied;
    CHECK(vireo_task_create_copy_with_cancel(metadata(), NULL, 0, 1024, source, NULL) ==
          VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_task_create_copy_with_cancel(metadata(), NULL, 0, 1024, NULL, &task) ==
          VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_task_create_copy_with_cancel(metadata(), NULL, 0, 0, source, &task) ==
          VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_task_create_copy_with_cancel(metadata(), NULL, 1, 1024, source, &task) ==
          VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_task_create_copy_with_cancel(metadata(), &byte, 1, 1024, source, &occupied) ==
          VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(task == NULL && occupied == original && references(source) == 1 && errno == EDOM);
    CHECK(vireo_task_destroy(&occupied) == VIREO_OK);
    CHECK(vireo_task_cancel_destroy(&source) == VIREO_OK);
    return 0;
}

static int invalid_metadata_preserves(void) {
    vireo_task_cancel_t *source = NULL;
    vireo_task_t *task = NULL;
    allocation_trace_t trace = {0};
    vireo_task_allocator_t const allocator = {&trace, trace_allocate, trace_deallocate};
    vireo_task_metadata_t values[5];
    for (size_t i = 0; i < 5; i++) {
        values[i] = metadata();
    }
    values[0].route.client_owner_id = 0;
    values[1].route.client_generation = 0;
    values[2].route.request_sequence = 0;
    values[3].request_instance_id = 0;
    values[4].operation = 0;
    errno = EDOM;
    CHECK(vireo_task_cancel_create(1024, &source) == VIREO_OK);
    for (size_t i = 0; i < 5; i++) {
        CHECK(vireo_task_create_copy_with_cancel_and_allocator(values[i], NULL, 0, 1024,
              source, &allocator, &task) == VIREO_RESULT_INVALID_ARGUMENT);
    }
    CHECK(task == NULL && trace.attempts == 0 && references(source) == 1 && errno == EDOM);
    CHECK(vireo_task_cancel_destroy(&source) == VIREO_OK);
    return 0;
}

static int private_allocator_guards(void) {
    vireo_task_cancel_t *source = NULL;
    vireo_task_t *task = NULL;
    vireo_task_allocator_t const no_allocate = {NULL, NULL, trace_deallocate};
    vireo_task_allocator_t const no_deallocate = {NULL, trace_allocate, NULL};
    errno = EDOM;
    CHECK(vireo_task_cancel_create(1024, &source) == VIREO_OK);
    CHECK(vireo_task_create_copy_with_cancel_and_allocator(metadata(), NULL, 0, 1024,
          source, NULL, &task) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_task_create_copy_with_cancel_and_allocator(metadata(), NULL, 0, 1024,
          source, &no_allocate, &task) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_task_create_copy_with_cancel_and_allocator(metadata(), NULL, 0, 1024,
          source, &no_deallocate, &task) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_task_create_copy_with_cancel_and_allocator(metadata(), NULL, 0, 1024,
          NULL, &no_allocate, &task) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(task == NULL && references(source) == 1 && errno == EDOM);
    CHECK(vireo_task_cancel_destroy(&source) == VIREO_OK);
    return 0;
}

static int checked_size_and_budget_precede_retain(void) {
    vireo_task_cancel_t *source = NULL;
    vireo_task_t *task = NULL;
    allocation_trace_t trace = {0};
    vireo_task_allocator_t const allocator = {&trace, trace_allocate, trace_deallocate};
    unsigned char const byte = 0;
    errno = EDOM;
    CHECK(vireo_task_cancel_create(1024, &source) == VIREO_OK);
    CHECK(vireo_task_create_copy_with_cancel_and_allocator(metadata(), &byte, SIZE_MAX,
          VIREO_TASK_MAX_ALLOCATION_BYTES + 1, source, &allocator, &task) == VIREO_RESULT_OVERFLOW);
    CHECK(task == NULL && trace.attempts == 0 && references(source) == 1);
    atomic_store(&source->references, UINT64_MAX);
    CHECK(vireo_task_create_copy_with_cancel_and_allocator(metadata(), &byte, SIZE_MAX,
          1, source, &allocator, &task) == VIREO_RESULT_OVERFLOW);
    CHECK(vireo_task_create_copy_with_cancel_and_allocator(metadata(), NULL, 0,
          sizeof(vireo_task_t) - 1, source, &allocator, &task) == VIREO_RESULT_RANGE);
    CHECK(vireo_task_create_copy_with_cancel_and_allocator(metadata(), NULL, 0,
          VIREO_TASK_MAX_ALLOCATION_BYTES + 1, source, &allocator, &task) == VIREO_RESULT_RANGE);
    CHECK(task == NULL && trace.attempts == 0 && references(source) == UINT64_MAX && errno == EDOM);
    atomic_store(&source->references, UINT64_C(1));
    CHECK(vireo_task_cancel_destroy(&source) == VIREO_OK);
    return 0;
}

static int retain_exhausted_before_allocate(void) {
    vireo_task_cancel_t *source = NULL;
    vireo_task_t *task = NULL;
    allocation_trace_t trace = {0};
    trace.fail = true;
    vireo_task_allocator_t const allocator = {&trace, trace_allocate, trace_deallocate};
    errno = EDOM;
    CHECK(vireo_task_cancel_create(1024, &source) == VIREO_OK);
    atomic_store(&source->references, UINT64_MAX);
    CHECK(vireo_task_create_copy_with_cancel_and_allocator(metadata(), NULL, 0, 1024,
          source, &allocator, &task) == VIREO_RESULT_OVERFLOW);
    CHECK(task == NULL && trace.attempts == 0 && references(source) == UINT64_MAX && errno == EDOM);
    atomic_store(&source->references, UINT64_C(1));
    CHECK(vireo_task_cancel_destroy(&source) == VIREO_OK);
    return 0;
}

static int allocation_failure_rolls_back_reference(void) {
    allocation_trace_t cancel_trace = {0};
    vireo_task_cancel_allocator_t const cancel_allocator = {
        &cancel_trace, trace_allocate, trace_deallocate
    };
    vireo_task_cancel_t *source = NULL;
    vireo_task_t *task = NULL;
    errno = EDOM;
    CHECK(vireo_task_cancel_create_with_allocator(1024, &cancel_allocator, &source) == VIREO_OK);
    allocation_trace_t task_trace = {0};
    task_trace.fail = true;
    task_trace.observe_cancel = source;
    vireo_task_allocator_t const task_allocator = {&task_trace, trace_allocate, trace_deallocate};
    CHECK(vireo_task_create_copy_with_cancel_and_allocator(metadata(), NULL, 0, 1024,
          source, &task_allocator, &task) == VIREO_RESULT_NO_MEMORY);
    CHECK(task == NULL && task_trace.attempts == 1 && task_trace.references_at_allocate == 2);
    CHECK(task_trace.releases == 0 && task_trace.live == NULL && !task_trace.mismatch);
    CHECK(references(source) == 1 && cancel_trace.releases == 0 && errno == EDOM);
    /* 原引用仍可操作，失败后没有永久泄漏引用，也没有错误触发取消。 */
    bool requested = true;
    CHECK(vireo_task_cancel_is_requested(source, &requested) == VIREO_OK && !requested);
    CHECK(vireo_task_cancel_request(source) == VIREO_OK);
    CHECK(vireo_task_cancel_destroy(&source) == VIREO_OK && cancel_trace.releases == 1);
    CHECK(cancel_trace.live == NULL && !cancel_trace.mismatch && errno == EDOM);
    return 0;
}

static int exact_task_budget_and_allocator_copy(void) {
    allocation_trace_t trace = {0};
    vireo_task_allocator_t allocator = {&trace, trace_allocate, trace_deallocate};
    vireo_task_cancel_t *source = NULL;
    vireo_task_t *task = NULL;
    unsigned char const data[] = {0, 1, 255};
    size_t const bytes = sizeof(vireo_task_t) + sizeof(data);
    errno = EDOM;
    CHECK(vireo_task_cancel_create(1024, &source) == VIREO_OK);
    trace.observe_cancel = source;
    CHECK(vireo_task_create_copy_with_cancel_and_allocator(metadata(), data, sizeof(data),
          bytes - 1, source, &allocator, &task) == VIREO_RESULT_RANGE);
    CHECK(trace.attempts == 0 && references(source) == 1);
    CHECK(vireo_task_create_copy_with_cancel_and_allocator(metadata(), data, sizeof(data),
          bytes, source, &allocator, &task) == VIREO_OK);
    CHECK(trace.attempts == 1 && trace.bytes == bytes && trace.references_at_allocate == 2);
    vireo_task_info_t info;
    CHECK(vireo_task_inspect(task, &info) == VIREO_OK && info.allocated_bytes == bytes);
    allocator.context = NULL;
    allocator.allocate = NULL;
    allocator.deallocate = NULL;
    CHECK(vireo_task_destroy(&task) == VIREO_OK && trace.releases == 1 && references(source) == 1);
    CHECK(trace.live == NULL && !trace.mismatch && errno == EDOM);
    CHECK(vireo_task_cancel_destroy(&source) == VIREO_OK);
    return 0;
}

static int query_and_extract_guards(void) {
    vireo_task_cancel_t *source = NULL;
    vireo_task_t *task = NULL;
    vireo_task_t *legacy = NULL;
    errno = EDOM;
    CHECK(vireo_task_cancel_create(1024, &source) == VIREO_OK);
    CHECK(vireo_task_create_copy_with_cancel(metadata(), NULL, 0, 1024, source, &task) == VIREO_OK);
    CHECK(vireo_task_create_copy(metadata(), NULL, 0, 1024, &legacy) == VIREO_OK);
    bool requested = true;
    CHECK(vireo_task_is_cancel_requested(NULL, &requested) == VIREO_RESULT_INVALID_ARGUMENT && requested);
    CHECK(vireo_task_is_cancel_requested(task, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_task_is_cancel_requested(legacy, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    vireo_task_cancel_t *extra = NULL;
    CHECK(vireo_task_retain_cancel(NULL, &extra) == VIREO_RESULT_INVALID_ARGUMENT && extra == NULL);
    CHECK(vireo_task_retain_cancel(task, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_task_retain_cancel(legacy, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    vireo_task_cancel_t *const original = source;
    CHECK(vireo_task_retain_cancel(task, &source) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_task_retain_cancel(legacy, &source) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(source == original && references(source) == 2 && errno == EDOM);
    CHECK(vireo_task_destroy(&legacy) == VIREO_OK);
    CHECK(vireo_task_destroy(&task) == VIREO_OK);
    CHECK(vireo_task_cancel_destroy(&source) == VIREO_OK);
    return 0;
}

static int extract_reference_exhaustion(void) {
    vireo_task_cancel_t *source = NULL;
    vireo_task_cancel_t *extra = NULL;
    vireo_task_t *task = NULL;
    errno = EDOM;
    CHECK(vireo_task_cancel_create(1024, &source) == VIREO_OK);
    CHECK(vireo_task_create_copy_with_cancel(metadata(), NULL, 0, 1024, source, &task) == VIREO_OK);
    atomic_store(&source->references, UINT64_MAX);
    CHECK(vireo_task_retain_cancel(task, &extra) == VIREO_RESULT_OVERFLOW && extra == NULL);
    CHECK(references(source) == UINT64_MAX && errno == EDOM);
    atomic_store(&source->references, UINT64_C(2));
    CHECK(vireo_task_destroy(&task) == VIREO_OK && references(source) == 1);
    CHECK(vireo_task_cancel_destroy(&source) == VIREO_OK);
    return 0;
}

static int move_preserves_reference_obligation(void) {
    vireo_task_cancel_t *source = NULL;
    vireo_task_t *task = NULL;
    vireo_task_t *destination = NULL;
    errno = EDOM;
    CHECK(vireo_task_cancel_create(1024, &source) == VIREO_OK);
    CHECK(vireo_task_create_copy_with_cancel(metadata(), NULL, 0, 1024, source, &task) == VIREO_OK);
    vireo_task_t *const original = task;
    CHECK(vireo_task_move(&task, &task) == VIREO_RESULT_INVALID_ARGUMENT && task == original);
    CHECK(references(source) == 2);
    CHECK(vireo_task_move(&task, &destination) == VIREO_OK && task == NULL && destination == original);
    CHECK(references(source) == 2);
    CHECK(vireo_task_destroy(&task) == VIREO_OK && references(source) == 2);
    CHECK(vireo_task_cancel_request(source) == VIREO_OK);
    bool requested = false;
    CHECK(vireo_task_is_cancel_requested(destination, &requested) == VIREO_OK && requested);
    CHECK(vireo_task_destroy(&destination) == VIREO_OK && references(source) == 1);
    CHECK(vireo_task_destroy(&destination) == VIREO_OK && references(source) == 1 && errno == EDOM);
    CHECK(vireo_task_cancel_destroy(&source) == VIREO_OK);
    return 0;
}

static int two_tasks_release_does_not_request(void) {
    vireo_task_cancel_t *source = NULL;
    vireo_task_t *a = NULL;
    vireo_task_t *b = NULL;
    errno = EDOM;
    CHECK(vireo_task_cancel_create(1024, &source) == VIREO_OK);
    CHECK(vireo_task_create_copy_with_cancel(metadata(), NULL, 0, 1024, source, &a) == VIREO_OK);
    CHECK(vireo_task_create_copy_with_cancel(metadata(), NULL, 0, 1024, source, &b) == VIREO_OK);
    CHECK(references(source) == 3);
    CHECK(vireo_task_destroy(&a) == VIREO_OK && references(source) == 2);
    bool requested = true;
    CHECK(vireo_task_is_cancel_requested(b, &requested) == VIREO_OK && !requested);
    CHECK(vireo_task_destroy(&b) == VIREO_OK && references(source) == 1);
    CHECK(vireo_task_cancel_is_requested(source, &requested) == VIREO_OK && !requested);
    CHECK(vireo_task_cancel_destroy(&source) == VIREO_OK && errno == EDOM);
    return 0;
}

/** @brief 单个测试 worker；create 发布输入，mutex/cond 协调，join 发布结果。 */
typedef struct worker_context {
    vireo_task_t *task; /**< 创建线程前转入的唯一 owner，仅 worker 使用并销毁。 */
    pthread_mutex_t mutex; /**< 保护 ready/go 握手，存活到 join 后销毁。 */
    pthread_cond_t condition; /**< 等待握手，无 sleep 或无限原子自旋。 */
    bool ready; /**< worker 已做初始 false 查询，mutex 保护。 */
    bool go; /**< 主线程已请求且释放来源，mutex 保护。 */
    bool passed; /**< worker 结果，仅 join 后由主线程读取。 */
} worker_context_t;

static void check_thread(int result) {
    if (result != 0) {
        fprintf(stderr, "pthread operation failed: %d\n", result);
        /* 无法建立安全寿命/唤醒时中止失败测试，不能返回并留线程访问栈。 */
        abort();
    }
}

static void *worker(void *argument) {
    worker_context_t *context = argument;
    errno = EDOM;
    bool requested = true;
    bool passed = vireo_task_is_cancel_requested(context->task, &requested) == VIREO_OK &&
        !requested && errno == EDOM;
    check_thread(pthread_mutex_lock(&context->mutex));
    context->ready = true;
    check_thread(pthread_cond_signal(&context->condition));
    while (!context->go) {
        check_thread(pthread_cond_wait(&context->condition, &context->mutex));
    }
    check_thread(pthread_mutex_unlock(&context->mutex));
    passed = (vireo_task_is_cancel_requested(context->task, &requested) == VIREO_OK &&
              requested && errno == EDOM) && passed;
    vireo_task_cancel_t *extra = NULL;
    passed = (vireo_task_retain_cancel(context->task, &extra) == VIREO_OK && errno == EDOM) && passed;
    passed = (vireo_task_destroy(&context->task) == VIREO_OK && context->task == NULL &&
              errno == EDOM) && passed;
    passed = (vireo_task_cancel_is_requested(extra, &requested) == VIREO_OK && requested &&
              errno == EDOM) && passed;
    passed = (vireo_task_cancel_destroy(&extra) == VIREO_OK && extra == NULL && errno == EDOM) && passed;
    context->passed = passed;
    return NULL;
}

static int thread_handoff_and_last_release(void) {
    worker_context_t context = {0};
    check_thread(pthread_mutex_init(&context.mutex, NULL));
    check_thread(pthread_cond_init(&context.condition, NULL));
    allocation_trace_t trace = {0};
    vireo_task_cancel_allocator_t const allocator = {&trace, trace_allocate, trace_deallocate};
    vireo_task_cancel_t *source = NULL;
    vireo_task_t *task = NULL;
    errno = EDOM;
    CHECK(vireo_task_cancel_create_with_allocator(1024, &allocator, &source) == VIREO_OK);
    CHECK(vireo_task_create_copy_with_cancel(metadata(), NULL, 0, 1024, source, &task) == VIREO_OK);
    CHECK(vireo_task_move(&task, &context.task) == VIREO_OK && task == NULL);
    pthread_t thread;
    int const created = pthread_create(&thread, NULL, worker, &context);
    if (created != 0) {
        CHECK(vireo_task_destroy(&context.task) == VIREO_OK);
        CHECK(vireo_task_cancel_destroy(&source) == VIREO_OK);
        check_thread(pthread_cond_destroy(&context.condition));
        check_thread(pthread_mutex_destroy(&context.mutex));
        CHECK(created == 0);
    }
    check_thread(pthread_mutex_lock(&context.mutex));
    while (!context.ready) {
        check_thread(pthread_cond_wait(&context.condition, &context.mutex));
    }
    /* worker 在 go 前不会销毁 task；确保最后释放必在 worker，非调度偶然。 */
    if (vireo_task_cancel_request(source) != VIREO_OK ||
        vireo_task_cancel_destroy(&source) != VIREO_OK || source != NULL || errno != EDOM ||
        trace.releases != 0) {
        abort();
    }
    context.go = true;
    check_thread(pthread_cond_signal(&context.condition));
    check_thread(pthread_mutex_unlock(&context.mutex));
    check_thread(pthread_join(thread, NULL));
    check_thread(pthread_cond_destroy(&context.condition));
    check_thread(pthread_mutex_destroy(&context.mutex));
    CHECK(context.passed && context.task == NULL);
    CHECK(trace.attempts == 1 && trace.releases == 1 && trace.live == NULL && !trace.mismatch);
    CHECK(errno == EDOM);
    return 0;
}

int main(void) {
    int (*const groups[])(void) = {
        legacy_without_cancel, copy_and_source_lifetime, already_requested_and_finite_deadlines,
        extracted_reference_outlives_task, basic_creation_guards, invalid_metadata_preserves,
        private_allocator_guards, checked_size_and_budget_precede_retain, retain_exhausted_before_allocate,
        allocation_failure_rolls_back_reference, exact_task_budget_and_allocator_copy,
        query_and_extract_guards, extract_reference_exhaustion, move_preserves_reference_obligation,
        two_tasks_release_does_not_request, thread_handoff_and_last_release
    };
    for (size_t i = 0; i < sizeof(groups) / sizeof(groups[0]); i++) {
        if (groups[i]() != 0) {
            return 1;
        }
    }
    printf("task cancel attachment: %zu groups passed\n", sizeof(groups) / sizeof(groups[0]));
    return 0;
}
