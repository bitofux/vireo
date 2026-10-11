/*
 * PROJECT : VIREO
 * FILE    : test_task_cancel.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-11
 * BRIEF   : 共享永久取消、引用寿命、失败与真实线程协作验证
 */

#include "thread/task_cancel_internal.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #condition); \
        return 1; \
    } \
} while (0)

/** @brief 单块真实申请观测；只在创建前或全部 join 后由主线程检查。 */
typedef struct allocation_trace {
    size_t attempts; /**< 包含失败的申请次数。 */
    size_t releases; /**< 最后引用的配对释放次数。 */
    size_t bytes; /**< 实际请求字节数。 */
    void *live; /**< 活跃块观测别名，不额外拥有，不解引用。 */
    bool fail; /**< 局部申请失败开关，创建前设置。 */
    bool mismatch; /**< 重复申请或错误配对释放标志。 */
} allocation_trace_t;

static void *trace_allocate(void *context, size_t bytes) {
    allocation_trace_t *trace = context;
    trace->attempts++;
    trace->bytes = bytes;
    if (trace->live != NULL) {
        trace->mismatch = true;
    }
    trace->live = trace->fail ? NULL : malloc(bytes);
    errno = ENOMEM;
    return trace->live;
}

static void trace_deallocate(void *context, void *allocation) {
    allocation_trace_t *trace = context;
    trace->releases++;
    if (allocation != trace->live || allocation == NULL) {
        trace->mismatch = true;
    }
    free(allocation);
    trace->live = NULL;
    errno = EILSEQ;
}

static int initial_and_permanent(void) {
    vireo_task_cancel_t *owner = NULL;
    errno = EDOM;
    CHECK(vireo_task_cancel_create(VIREO_TASK_CANCEL_MAX_ALLOCATION_BYTES, &owner) == VIREO_OK);
    bool requested = true;
    CHECK(vireo_task_cancel_is_requested(owner, &requested) == VIREO_OK && !requested);
    CHECK(vireo_task_cancel_request(owner) == VIREO_OK);
    CHECK(vireo_task_cancel_request(owner) == VIREO_OK);
    CHECK(vireo_task_cancel_is_requested(owner, &requested) == VIREO_OK && requested);
    CHECK(errno == EDOM);
    CHECK(vireo_task_cancel_destroy(&owner) == VIREO_OK && owner == NULL && errno == EDOM);
    return 0;
}

static int shared_lifetime(void) {
    allocation_trace_t trace = {0};
    vireo_task_cancel_allocator_t const allocator = {&trace, trace_allocate, trace_deallocate};
    vireo_task_cancel_t *a = NULL;
    vireo_task_cancel_t *b = NULL;
    vireo_task_cancel_t *c = NULL;
    errno = EDOM;
    CHECK(vireo_task_cancel_create_with_allocator(1024, &allocator, &a) == VIREO_OK);
    CHECK(vireo_task_cancel_retain(a, &b) == VIREO_OK && a == b);
    CHECK(vireo_task_cancel_request(a) == VIREO_OK);
    CHECK(vireo_task_cancel_destroy(&a) == VIREO_OK && a == NULL && trace.releases == 0);
    bool requested = false;
    CHECK(vireo_task_cancel_is_requested(b, &requested) == VIREO_OK && requested);
    CHECK(vireo_task_cancel_retain(b, &c) == VIREO_OK);
    CHECK(vireo_task_cancel_destroy(&b) == VIREO_OK && b == NULL && trace.releases == 0);
    CHECK(vireo_task_cancel_is_requested(c, &requested) == VIREO_OK && requested);
    CHECK(vireo_task_cancel_destroy(&c) == VIREO_OK && c == NULL);
    CHECK(trace.attempts == 1 && trace.releases == 1 && trace.live == NULL && !trace.mismatch);
    CHECK(errno == EDOM);
    return 0;
}

static int releasing_does_not_cancel(void) {
    vireo_task_cancel_t *a = NULL;
    vireo_task_cancel_t *b = NULL;
    errno = ERANGE;
    CHECK(vireo_task_cancel_create(1024, &a) == VIREO_OK);
    CHECK(vireo_task_cancel_retain(a, &b) == VIREO_OK);
    CHECK(vireo_task_cancel_destroy(&a) == VIREO_OK);
    bool requested = true;
    CHECK(vireo_task_cancel_is_requested(b, &requested) == VIREO_OK && !requested);
    CHECK(vireo_task_cancel_destroy(&b) == VIREO_OK && errno == ERANGE);
    return 0;
}

static int independent_states(void) {
    vireo_task_cancel_t *a = NULL;
    vireo_task_cancel_t *b = NULL;
    CHECK(vireo_task_cancel_create(1024, &a) == VIREO_OK);
    CHECK(vireo_task_cancel_create(1024, &b) == VIREO_OK && a != b);
    CHECK(vireo_task_cancel_request(a) == VIREO_OK);
    bool requested = true;
    CHECK(vireo_task_cancel_is_requested(b, &requested) == VIREO_OK && !requested);
    CHECK(vireo_task_cancel_destroy(&a) == VIREO_OK);
    CHECK(vireo_task_cancel_destroy(&b) == VIREO_OK);
    return 0;
}

static int invalid_arguments(void) {
    vireo_task_cancel_t *owner = NULL;
    bool requested = true;
    errno = EDOM;
    CHECK(vireo_task_cancel_create(0, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_task_cancel_create(0, &owner) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_task_cancel_retain(NULL, &owner) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_task_cancel_request(NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_task_cancel_is_requested(NULL, &requested) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(requested && owner == NULL && errno == EDOM);
    CHECK(vireo_task_cancel_create(1024, &owner) == VIREO_OK);
    vireo_task_cancel_t *const original = owner;
    CHECK(vireo_task_cancel_create(1024, &owner) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_task_cancel_retain(owner, &owner) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_task_cancel_retain(owner, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_task_cancel_is_requested(owner, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(owner == original && atomic_load(&owner->references) == 1 && errno == EDOM);
    CHECK(vireo_task_cancel_destroy(&owner) == VIREO_OK);
    return 0;
}

static int query_failure_preserves(void) {
    for (unsigned int i = 0; i < 2; i++) {
        bool values[] = {true, i != 0, false};
        errno = EDOM;
        CHECK(vireo_task_cancel_is_requested(NULL, &values[1]) == VIREO_RESULT_INVALID_ARGUMENT);
        CHECK(values[0] && values[1] == (i != 0) && !values[2] && errno == EDOM);
    }
    return 0;
}

static int budget_and_private_guards(void) {
    allocation_trace_t trace = {0};
    vireo_task_cancel_allocator_t allocator = {&trace, trace_allocate, trace_deallocate};
    vireo_task_cancel_t *owner = NULL;
    errno = EDOM;
    CHECK(vireo_task_cancel_create_with_allocator(0, &allocator, &owner) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_task_cancel_create_with_allocator(1024, NULL, &owner) == VIREO_RESULT_INVALID_ARGUMENT);
    allocator.allocate = NULL;
    CHECK(vireo_task_cancel_create_with_allocator(1024, &allocator, &owner) == VIREO_RESULT_INVALID_ARGUMENT);
    allocator.allocate = trace_allocate;
    allocator.deallocate = NULL;
    CHECK(vireo_task_cancel_create_with_allocator(1024, &allocator, &owner) == VIREO_RESULT_INVALID_ARGUMENT);
    allocator.deallocate = trace_deallocate;
    CHECK(vireo_task_cancel_create_with_allocator(sizeof(vireo_task_cancel_t) - 1,
          &allocator, &owner) == VIREO_RESULT_RANGE);
    CHECK(vireo_task_cancel_create_with_allocator(VIREO_TASK_CANCEL_MAX_ALLOCATION_BYTES + 1,
          &allocator, &owner) == VIREO_RESULT_RANGE);
    CHECK(owner == NULL && trace.attempts == 0 && trace.releases == 0 && errno == EDOM);
    CHECK(vireo_task_cancel_create_with_allocator(sizeof(vireo_task_cancel_t),
          &allocator, &owner) == VIREO_OK && errno == EDOM);
    CHECK(trace.bytes == sizeof(vireo_task_cancel_t) && trace.attempts == 1);
    CHECK(vireo_task_cancel_destroy(&owner) == VIREO_OK && errno == EDOM);
    CHECK(trace.releases == 1 && !trace.mismatch);
    return 0;
}

static int allocation_failure_and_table_copy(void) {
    allocation_trace_t trace = {0};
    trace.fail = true;
    vireo_task_cancel_allocator_t allocator = {&trace, trace_allocate, trace_deallocate};
    vireo_task_cancel_t *owner = NULL;
    errno = ERANGE;
    CHECK(vireo_task_cancel_create_with_allocator(1024, &allocator, &owner) == VIREO_RESULT_NO_MEMORY);
    CHECK(owner == NULL && trace.attempts == 1 && trace.releases == 0 && errno == ERANGE);
    trace.fail = false;
    CHECK(vireo_task_cancel_create_with_allocator(1024, &allocator, &owner) == VIREO_OK);
    allocator = (vireo_task_cancel_allocator_t){0};
    CHECK(vireo_task_cancel_destroy(&owner) == VIREO_OK && errno == ERANGE);
    CHECK(trace.attempts == 2 && trace.releases == 1 && trace.live == NULL && !trace.mismatch);
    return 0;
}

static int count_boundary(void) {
    vireo_task_cancel_t *owner = NULL;
    vireo_task_cancel_t *extra = NULL;
    CHECK(vireo_task_cancel_create(1024, &owner) == VIREO_OK);
    /* 仅独占测试对象；不会制造MAX份真实引用或在并发状态上注入计数。 */
    atomic_store(&owner->references, UINT64_MAX - 1);
    errno = EDOM;
    CHECK(vireo_task_cancel_retain(owner, &extra) == VIREO_OK);
    CHECK(atomic_load(&owner->references) == UINT64_MAX && extra == owner);
    vireo_task_cancel_t *rejected = NULL;
    CHECK(vireo_task_cancel_retain(owner, &rejected) == VIREO_RESULT_OVERFLOW);
    CHECK(rejected == NULL && atomic_load(&owner->references) == UINT64_MAX && errno == EDOM);
    CHECK(vireo_task_cancel_request(owner) == VIREO_OK);
    bool requested = false;
    CHECK(vireo_task_cancel_is_requested(extra, &requested) == VIREO_OK && requested);
    /* 恢复实际两份引用后，按真实公开生命周期分别释放。 */
    atomic_store(&owner->references, UINT64_C(2));
    CHECK(vireo_task_cancel_destroy(&extra) == VIREO_OK);
    CHECK(vireo_task_cancel_destroy(&owner) == VIREO_OK && errno == EDOM);
    return 0;
}

static int move_success(void) {
    vireo_task_cancel_t *source = NULL;
    vireo_task_cancel_t *destination = NULL;
    vireo_task_cancel_t *other = NULL;
    CHECK(vireo_task_cancel_create(1024, &source) == VIREO_OK);
    CHECK(vireo_task_cancel_retain(source, &other) == VIREO_OK);
    errno = EDOM;
    CHECK(vireo_task_cancel_move(&source, &destination) == VIREO_OK && source == NULL);
    CHECK(destination == other && atomic_load(&destination->references) == 2);
    CHECK(vireo_task_cancel_request(other) == VIREO_OK);
    bool requested = false;
    CHECK(vireo_task_cancel_is_requested(destination, &requested) == VIREO_OK && requested);
    CHECK(vireo_task_cancel_destroy(&source) == VIREO_OK);
    CHECK(vireo_task_cancel_destroy(&destination) == VIREO_OK);
    CHECK(vireo_task_cancel_destroy(&other) == VIREO_OK && errno == EDOM);
    return 0;
}

static int move_failure_and_empty(void) {
    vireo_task_cancel_t *a = NULL;
    vireo_task_cancel_t *b = NULL;
    vireo_task_cancel_t *empty = NULL;
    vireo_task_cancel_t *empty2 = NULL;
    CHECK(vireo_task_cancel_create(1024, &a) == VIREO_OK);
    CHECK(vireo_task_cancel_create(1024, &b) == VIREO_OK);
    vireo_task_cancel_t *const a_before = a;
    vireo_task_cancel_t *const b_before = b;
    errno = EDOM;
    CHECK(vireo_task_cancel_move(NULL, &empty) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_task_cancel_move(&a, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_task_cancel_move(&a, &a) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_task_cancel_move(&a, &b) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_task_cancel_move(&empty, &b) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_task_cancel_move(&empty, &empty2) == VIREO_RESULT_NOT_FOUND);
    CHECK(a == a_before && b == b_before && empty == NULL && empty2 == NULL && errno == EDOM);
    CHECK(vireo_task_cancel_destroy(&a) == VIREO_OK);
    CHECK(vireo_task_cancel_destroy(&b) == VIREO_OK);
    return 0;
}

static int destroy_idempotent(void) {
    vireo_task_cancel_t *owner = NULL;
    errno = EDOM;
    CHECK(vireo_task_cancel_destroy(NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_task_cancel_destroy(&owner) == VIREO_OK);
    CHECK(vireo_task_cancel_create(1024, &owner) == VIREO_OK);
    CHECK(vireo_task_cancel_destroy(&owner) == VIREO_OK && owner == NULL);
    CHECK(vireo_task_cancel_destroy(&owner) == VIREO_OK && errno == EDOM);
    return 0;
}

/** @brief pthread_create发布，子线程独占字段，join后主线程读取结果。 */
typedef struct worker_context {
    vireo_task_cancel_t *owner; /**< 转交给本线程的一份强引用，结束时清空。 */
    pthread_mutex_t *start_gate; /**< 可空启动门，借到join；主引用释放后才开门。 */
    size_t iterations; /**< 显式有限循环次数。 */
    bool request_here; /**< 是否在本线程中请求取消。 */
    bool saw_requested; /**< 本线程是否曾观测true，用于核验单调性。 */
    bool failed; /**< 公共结果或errno不符的线程局部记录。 */
    size_t completed; /**< 实际完成的循环次数，join后核对。 */
} worker_context_t;

static void *exercise_reference(void *argument) {
    worker_context_t *context = argument;
    if (context->start_gate != NULL) {
        if (pthread_mutex_lock(context->start_gate) != 0) {
            context->failed = true;
            (void)vireo_task_cancel_destroy(&context->owner);
            return NULL;
        }
        if (pthread_mutex_unlock(context->start_gate) != 0) {
            /* 门仍可能被占用，不能正常返回让其他线程无限等待。 */
            abort();
        }
    }
    errno = EDOM;
    for (size_t i = 0; i < context->iterations; i++) {
        vireo_task_cancel_t *extra = NULL;
        if (vireo_task_cancel_retain(context->owner, &extra) != VIREO_OK || errno != EDOM) {
            context->failed = true;
            /* 如结果成功但errno不符，仍归还已获得的引用。 */
            (void)vireo_task_cancel_destroy(&extra);
            break;
        }
        if (context->request_here && vireo_task_cancel_request(extra) != VIREO_OK) {
            context->failed = true;
        }
        bool requested = false;
        if (vireo_task_cancel_is_requested(extra, &requested) != VIREO_OK ||
            (context->saw_requested && !requested)) {
            context->failed = true;
        }
        context->saw_requested = context->saw_requested || requested;
        if (vireo_task_cancel_destroy(&extra) != VIREO_OK || extra != NULL || errno != EDOM) {
            context->failed = true;
        }
        context->completed++;
        if (context->failed) {
            break;
        }
    }
    if (vireo_task_cancel_destroy(&context->owner) != VIREO_OK ||
        context->owner != NULL || errno != EDOM) {
        context->failed = true;
    }
    return NULL;
}

static int concurrent_case(bool release_anchor, bool cancel_before_start) {
    enum { WORKERS = 6 };
    allocation_trace_t trace = {0};
    vireo_task_cancel_allocator_t const allocator = {&trace, trace_allocate, trace_deallocate};
    vireo_task_cancel_t *anchor = NULL;
    worker_context_t contexts[WORKERS] = {0};
    pthread_t threads[WORKERS];
    CHECK(vireo_task_cancel_create_with_allocator(1024, &allocator, &anchor) == VIREO_OK);
    if (cancel_before_start) {
        CHECK(vireo_task_cancel_request(anchor) == VIREO_OK);
    }
    pthread_mutex_t gate;
    if (pthread_mutex_init(&gate, NULL) != 0) {
        (void)vireo_task_cancel_destroy(&anchor);
        return 1;
    }
    if (pthread_mutex_lock(&gate) != 0) {
        (void)pthread_mutex_destroy(&gate);
        (void)vireo_task_cancel_destroy(&anchor);
        return 1;
    }
    size_t started = 0;
    bool setup_failed = false;
    for (size_t i = 0; i < WORKERS; i++) {
        contexts[i].iterations = 1000;
        contexts[i].request_here = i % 2 == 0;
        contexts[i].start_gate = release_anchor ? &gate : NULL;
        if (vireo_task_cancel_retain(anchor, &contexts[i].owner) != VIREO_OK) {
            setup_failed = true;
            break;
        }
        if (pthread_create(&threads[i], NULL, exercise_reference, &contexts[i]) != 0) {
            (void)vireo_task_cancel_destroy(&contexts[i].owner);
            setup_failed = true;
            break;
        }
        started++;
    }
    if (release_anchor) {
        (void)vireo_task_cancel_destroy(&anchor);
    }
    /* 需线程最终释放的两组：门尚未打开，主引用消耗后仍有线程引用保活。 */
    bool const release_deferred = !release_anchor || started == 0 || trace.releases == 0;
    if (pthread_mutex_unlock(&gate) != 0) {
        abort();
    }
    for (size_t i = 0; i < started; i++) {
        /* join失败不能安全返回仍被线程借用的栈；结束失败测试进程。 */
        if (pthread_join(threads[i], NULL) != 0) {
            fprintf(stderr, "task cancel: cannot join started worker\n");
            abort();
        }
    }
    bool observations_ok = true;
    for (size_t i = 0; i < started; i++) {
        if (contexts[i].failed || contexts[i].owner != NULL || contexts[i].completed != 1000 ||
            (cancel_before_start && !contexts[i].saw_requested)) {
            observations_ok = false;
        }
    }
    bool requested = false;
    if (anchor != NULL) {
        if (vireo_task_cancel_is_requested(anchor, &requested) != VIREO_OK || !requested) {
            observations_ok = false;
        }
    }
    (void)vireo_task_cancel_destroy(&anchor);
    int const gate_destroy_result = pthread_mutex_destroy(&gate);
    CHECK(!setup_failed && started == WORKERS && observations_ok && release_deferred);
    CHECK(gate_destroy_result == 0);
    CHECK(trace.attempts == 1 && trace.releases == 1 && trace.live == NULL && !trace.mismatch);
    return 0;
}

static int concurrent_retain_request(void) { return concurrent_case(false, false); }
static int concurrent_last_release(void) { return concurrent_case(true, false); }
static int cancelled_reference_publication(void) { return concurrent_case(true, true); }

int main(void) {
    int (*const groups[])(void) = {
        initial_and_permanent, shared_lifetime, releasing_does_not_cancel, independent_states,
        invalid_arguments, query_failure_preserves, budget_and_private_guards,
        allocation_failure_and_table_copy, count_boundary, move_success, move_failure_and_empty,
        destroy_idempotent, concurrent_retain_request, concurrent_last_release,
        cancelled_reference_publication
    };
    for (size_t i = 0; i < sizeof(groups) / sizeof(groups[0]); i++) {
        if (groups[i]() != 0) {
            return 1;
        }
    }
    printf("task cancel: %zu groups passed (3 real pthread groups)\n",
           sizeof(groups) / sizeof(groups[0]));
    return 0;
}
