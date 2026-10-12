/*
 * PROJECT : VIREO
 * FILE    : test_completion_queue_transfer.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-12
 * BRIEF   : FIFO/循环复用、同步失败真实进度与三 producer 单 consumer 交接
 */

#include "thread/completion_queue_internal.h"

#include <errno.h>
#include <sched.h>
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
#define PRODUCERS 3
#define ITEMS_PER_PRODUCER 64
#define RETRY_LIMIT 1000000

/** 单线程同步故障账本；错误注入只影响本队列，非全局开关。 */
typedef struct sync_trace {
    int init_error; /**< 非零时不初始化而报告此码。 */
    int lock_error; /**< 非零时不取得锁而报告此码。 */
    int unlock_error; /**< 真实成功解锁后报告此码。 */
    int destroy_error; /**< 非零时保留 mutex 而报告此码。 */
    size_t init_calls; /**< 初始化 callback 次数。 */
    size_t lock_calls; /**< 一次 try callback 次数。 */
    size_t unlock_calls; /**< 解锁 callback 次数。 */
    size_t destroy_calls; /**< 同步销毁 callback 次数。 */
} sync_trace_t;

/** 本核心分配账本，实际 malloc/free；上下文存活至队列销毁。 */
typedef struct allocation_trace {
    size_t allocations; /**< 申请 callback 次数。 */
    size_t frees; /**< 实际配对释放次数。 */
    bool fail; /**< 返回 NULL，不产生块。 */
} allocation_trace_t;

/**
 * @brief
 *     实际初始化或以无初始化状态返回故障。
 *
 * @param[in,out] context
 *     单线程存活同步账本。
 * @param[in,out] mutex
 *     待初始化存储。
 *
 * @return
 *     注入码或原 pthread 返回，主动扰动 errno。
 */
static int trace_init(void *context, pthread_mutex_t *mutex) {
    sync_trace_t *trace = context;
    ++trace->init_calls;
    errno = EDOM;
    return trace->init_error != 0 ? trace->init_error : pthread_mutex_init(mutex, NULL);
}

/**
 * @brief
 *     一次真实 try 或不持锁的故障返回。
 *
 * @param[in,out] context
 *     单线程存活同步账本。
 * @param[in,out] mutex
 *     已初始化 mutex。
 *
 * @return
 *     注入码或原 pthread 返回，不在 seam 内重试。
 */
static int trace_lock(void *context, pthread_mutex_t *mutex) {
    sync_trace_t *trace = context;
    ++trace->lock_calls;
    errno = EDOM;
    return trace->lock_error != 0 ? trace->lock_error : pthread_mutex_trylock(mutex);
}

/**
 * @brief
 *     真实释放锁后可报告错误，验证已提交交接不回滚。
 *
 * @param[in,out] context
 *     单线程存活同步账本。
 * @param[in,out] mutex
 *     本线程已取得的 mutex。
 *
 * @return
 *     真实解锁异常优先；否则返回注入码，不声称修复损坏的同步资源。
 */
static int trace_unlock(void *context, pthread_mutex_t *mutex) {
    sync_trace_t *trace = context;
    ++trace->unlock_calls;
    errno = EDOM;
    int const code = pthread_mutex_unlock(mutex);
    return code != 0 ? code : trace->unlock_error;
}

/**
 * @brief
 *     保留资源的失败或实际同步销毁。
 *
 * @param[in,out] context
 *     单线程存活同步账本。
 * @param[in,out] mutex
 *     空队列且全部访问结束的 mutex。
 *
 * @return
 *     注入码或原 pthread 销毁码。
 */
static int trace_destroy(void *context, pthread_mutex_t *mutex) {
    sync_trace_t *trace = context;
    ++trace->destroy_calls;
    errno = EDOM;
    return trace->destroy_error != 0 ? trace->destroy_error : pthread_mutex_destroy(mutex);
}

/**
 * @brief
 *     实际申请或不产生块的失败，记录并扰动 errno。
 *
 * @param[in,out] context
 *     单线程分配账本。
 * @param[in] bytes
 *     已受检正申请量。
 *
 * @return
 *     独占正确对齐块或 NULL。
 */
static void *trace_allocate(void *context, size_t bytes) {
    allocation_trace_t *trace = context;
    ++trace->allocations;
    errno = ENOMEM;
    return trace->fail ? NULL : malloc(bytes);
}

/**
 * @brief
 *     实际配对释放队列原块。
 *
 * @param[in,out] context
 *     存活分配账本。
 * @param[in] allocation
 *     本配对器的独占原块，全部访问结束。
 *
 * @note
 *     无失败返回，主动扰动 errno。
 */
static void trace_deallocate(void *context, void *allocation) {
    allocation_trace_t *trace = context;
    ++trace->frees;
    free(allocation);
    errno = EIO;
}

/** 按编号生成公开有效元数据及字节副本；局部输入立即改写以核验独立性。 */
static int make_completion(uint64_t id, vireo_completion_t **owner) {
    vireo_completion_metadata_t const metadata = {
        .request = {{7, 0, 3, 11}, id, 2, 100},
        .result = VIREO_RESULT_DATABASE,
        .suggested_status = VIREO_STATUS_DB_ERROR
    };
    uint64_t bytes[2] = {id, id ^ UINT64_C(0xdeadbeef12345678)};
    EXPECT(vireo_completion_create_copy(metadata, bytes, sizeof(bytes), 1024, owner), VIREO_OK);
    memset(bytes, 0, sizeof(bytes));
    return 0;
}

/** 对唯一领取结果只作公开快照/短借，借用在返回前结束，不保存 data 地址。 */
static int verify_completion(vireo_completion_t *owner, uint64_t id) {
    vireo_completion_info_t info;
    EXPECT(vireo_completion_inspect(owner, &info), VIREO_OK);
    CHECK(info.metadata.request.request_instance_id == id);
    CHECK(info.metadata.result == VIREO_RESULT_DATABASE);
    CHECK(info.metadata.suggested_status == VIREO_STATUS_DB_ERROR);
    vireo_completion_payload_view_t view;
    EXPECT(vireo_completion_borrow_payload(owner, &view), VIREO_OK);
    CHECK(view.size == 2 * sizeof(uint64_t));
    uint64_t bytes[2];
    memcpy(bytes, view.data, sizeof(bytes));
    CHECK(bytes[0] == id && bytes[1] == (id ^ UINT64_C(0xdeadbeef12345678)));
    return 0;
}

/** 报告按逻辑字段比较，不依赖 padding；完成后的报告只是历史值。 */
static bool report_is(vireo_completion_queue_transfer_report_t report,
    vireo_completion_queue_transfer_stage_t stage, bool transferred, int code) {
    return report.stage == stage && report.transferred == transferred && report.pthread_error == code;
}

/** 只用于本核心单线程故障测试，以完整本地操作表构造真实队列。 */
static int make_traced(sync_trace_t *sync, allocation_trace_t *allocation,
    vireo_completion_queue_t **queue) {
    vireo_completion_queue_options_t const options = {1, 4096};
    vireo_completion_queue_allocator_t const allocator = {
        allocation, trace_allocate, trace_deallocate
    };
    vireo_completion_queue_sync_t const operations = {
        sync, trace_init, trace_lock, trace_unlock, trace_destroy
    };
    EXPECT(vireo_completion_queue_create_with_ops(&options, &allocator, &operations, queue), VIREO_OK);
    return 0;
}

static int fifo_and_wrap(void) {
    size_t const capacities[] = {1, 3, 17};
    for (size_t c = 0; c < sizeof(capacities) / sizeof(capacities[0]); ++c) {
        vireo_completion_queue_t *queue = NULL;
        vireo_completion_queue_options_t const options = {capacities[c], 4096};
        EXPECT(vireo_completion_queue_create(&options, &queue), VIREO_OK);
        vireo_completion_t *expected[17] = {NULL};
        vireo_completion_queue_transfer_report_t report;
        /* 每轮先填满再逐项领取，交替少量操作令非 2 幂索引反复跨界。 */
        for (size_t round = 0; round < 5; ++round) {
            for (size_t i = 0; i < options.capacity; ++i) {
                vireo_completion_t *owner = NULL;
                CHECK(make_completion((uint64_t)(round * options.capacity + i + 1), &owner) == 0);
                expected[i] = owner;
                EXPECT(vireo_completion_queue_try_push(queue, &owner, &report), VIREO_OK);
                CHECK(owner == NULL && report_is(report, VIREO_COMPLETION_QUEUE_TRANSFER_NONE, true, 0));
            }
            vireo_completion_queue_info_t info;
            EXPECT(vireo_completion_queue_inspect(queue, &info), VIREO_OK);
            CHECK(info.count == options.capacity);
            for (size_t i = 0; i < options.capacity; ++i) {
                vireo_completion_t *owner = NULL;
                EXPECT(vireo_completion_queue_try_pop(queue, &owner, &report), VIREO_OK);
                CHECK(owner == expected[i]);
                CHECK(report_is(report, VIREO_COMPLETION_QUEUE_TRANSFER_NONE, true, 0));
                CHECK(verify_completion(owner, (uint64_t)(round * options.capacity + i + 1)) == 0);
                EXPECT(vireo_completion_destroy(&owner), VIREO_OK);
            }
            /* 额外一项令下一轮填满从不同槽开始。 */
            vireo_completion_t *owner = NULL;
            CHECK(make_completion(999, &owner) == 0);
            EXPECT(vireo_completion_queue_try_push(queue, &owner, &report), VIREO_OK);
            EXPECT(vireo_completion_queue_try_pop(queue, &owner, &report), VIREO_OK);
            EXPECT(vireo_completion_destroy(&owner), VIREO_OK);
        }
        vireo_completion_queue_info_t info;
        EXPECT(vireo_completion_queue_inspect(queue, &info), VIREO_OK);
        CHECK(info.count == 0);
        EXPECT(vireo_completion_queue_destroy(&queue), VIREO_OK);
    }
    return 0;
}

static int full_empty_and_destroy(void) {
    vireo_completion_queue_t *queue = NULL;
    vireo_completion_queue_options_t const options = {1, 4096};
    EXPECT(vireo_completion_queue_create(&options, &queue), VIREO_OK);
    vireo_completion_t *one = NULL, *two = NULL;
    vireo_completion_queue_transfer_report_t report;
    EXPECT(vireo_completion_queue_try_pop(queue, &one, &report), VIREO_RESULT_NOT_FOUND);
    CHECK(one == NULL && report_is(report, VIREO_COMPLETION_QUEUE_TRANSFER_NONE, false, 0));
    CHECK(make_completion(1, &one) == 0 && make_completion(2, &two) == 0);
    vireo_completion_t *saved_two = two;
    EXPECT(vireo_completion_queue_try_push(queue, &one, &report), VIREO_OK);
    EXPECT(vireo_completion_queue_try_push(queue, &two, &report), VIREO_RESULT_BUSY);
    CHECK(two == saved_two && report_is(report, VIREO_COMPLETION_QUEUE_TRANSFER_NONE, false, 0));
    vireo_completion_queue_t *saved_queue = queue;
    EXPECT(vireo_completion_queue_destroy(&queue), VIREO_RESULT_BUSY);
    CHECK(queue == saved_queue);
    EXPECT(vireo_completion_queue_try_pop(queue, &one, &report), VIREO_OK);
    CHECK(verify_completion(one, 1) == 0 && verify_completion(two, 2) == 0);
    EXPECT(vireo_completion_destroy(&one), VIREO_OK);
    EXPECT(vireo_completion_destroy(&two), VIREO_OK);
    EXPECT(vireo_completion_queue_destroy(&queue), VIREO_OK);
    return 0;
}

static int invalid_and_precedence(void) {
    sync_trace_t sync = {0};
    allocation_trace_t allocation = {0};
    vireo_completion_queue_t *queue = NULL;
    CHECK(make_traced(&sync, &allocation, &queue) == 0);
    vireo_completion_t *owner = NULL;
    vireo_completion_queue_transfer_report_t report = {VIREO_COMPLETION_QUEUE_TRANSFER_UNLOCK, true, EIO};
    sync.lock_error = EIO;
    EXPECT(vireo_completion_queue_try_push(queue, &owner, &report), VIREO_RESULT_NOT_FOUND);
    CHECK(sync.lock_calls == 0 && report_is(report, VIREO_COMPLETION_QUEUE_TRANSFER_NONE, false, 0));
    EXPECT(vireo_completion_queue_try_push(NULL, &owner, &report), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_completion_queue_try_pop(queue, NULL, &report), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(report_is(report, VIREO_COMPLETION_QUEUE_TRANSFER_NONE, false, 0));
    CHECK(make_completion(1, &owner) == 0);
    vireo_completion_t *saved = owner;
    EXPECT(vireo_completion_queue_try_pop(queue, &owner, &report), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_completion_queue_try_push(queue, &owner, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_completion_queue_try_pop(queue, &owner, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_completion_queue_try_push(queue, NULL, &report), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(owner == saved && sync.lock_calls == 0);
    sync.lock_error = 0;
    EXPECT(vireo_completion_destroy(&owner), VIREO_OK);
    EXPECT(vireo_completion_queue_destroy(&queue), VIREO_OK);
    CHECK(allocation.allocations == 1 && allocation.frees == 1);
    return 0;
}

static int actual_contention(void) {
    vireo_completion_queue_t *queue = NULL;
    vireo_completion_queue_options_t const options = {3, 4096};
    EXPECT(vireo_completion_queue_create(&options, &queue), VIREO_OK);
    vireo_completion_t *owner = NULL, *output = NULL;
    CHECK(make_completion(1, &owner) == 0);
    vireo_completion_t *saved = owner;
    vireo_completion_queue_transfer_report_t report;
    CHECK(pthread_mutex_lock(&queue->mutex) == 0);
    EXPECT(vireo_completion_queue_try_push(queue, &owner, &report), VIREO_RESULT_BUSY);
    CHECK(owner == saved && report_is(report, VIREO_COMPLETION_QUEUE_TRANSFER_LOCK, false, EBUSY));
    EXPECT(vireo_completion_queue_try_pop(queue, &output, &report), VIREO_RESULT_BUSY);
    CHECK(output == NULL && report_is(report, VIREO_COMPLETION_QUEUE_TRANSFER_LOCK, false, EBUSY));
    vireo_completion_queue_info_t info;
    memset(&info, 0xa5, sizeof(info));
    unsigned char before[sizeof(info)];
    memcpy(before, &info, sizeof(info));
    EXPECT(vireo_completion_queue_inspect(queue, &info), VIREO_RESULT_BUSY);
    CHECK(memcmp(before, &info, sizeof(info)) == 0);
    CHECK(pthread_mutex_unlock(&queue->mutex) == 0);
    EXPECT(vireo_completion_queue_try_push(queue, &owner, &report), VIREO_OK);
    EXPECT(vireo_completion_queue_try_pop(queue, &output, &report), VIREO_OK);
    EXPECT(vireo_completion_destroy(&output), VIREO_OK);
    EXPECT(vireo_completion_queue_destroy(&queue), VIREO_OK);
    return 0;
}

static int init_failure_and_copy(void) {
    int const failures[] = {ENOMEM, EINVAL};
    vireo_completion_queue_options_t const options = {1, 4096};
    for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); ++i) {
        sync_trace_t sync = {0};
        allocation_trace_t allocation = {0};
        sync.init_error = failures[i];
        vireo_completion_queue_t *queue = NULL;
        vireo_completion_queue_allocator_t allocator = {&allocation, trace_allocate, trace_deallocate};
        vireo_completion_queue_sync_t operations = {&sync, trace_init, trace_lock, trace_unlock, trace_destroy};
        EXPECT(vireo_completion_queue_create_with_ops(&options, &allocator, &operations, &queue),
            failures[i] == ENOMEM ? VIREO_RESULT_NO_MEMORY : VIREO_RESULT_INTERNAL);
        CHECK(queue == NULL && allocation.allocations == 1 && allocation.frees == 1);
        CHECK(sync.init_calls == 1 && sync.destroy_calls == 0);
        allocation.fail = true;
        EXPECT(vireo_completion_queue_create_with_ops(&options, &allocator, &operations, &queue),
            VIREO_RESULT_NO_MEMORY);
        CHECK(sync.init_calls == 1 && allocation.frees == 1);
        allocation.fail = false;
        sync.init_error = 0;
        EXPECT(vireo_completion_queue_create_with_ops(&options, &allocator, &operations, &queue), VIREO_OK);
        memset(&operations, 0, sizeof(operations));
        memset(&allocator, 0, sizeof(allocator));
        vireo_completion_queue_info_t info;
        EXPECT(vireo_completion_queue_inspect(queue, &info), VIREO_OK);
        EXPECT(vireo_completion_queue_destroy(&queue), VIREO_OK);
        CHECK(sync.lock_calls == 1 && sync.unlock_calls == 1 && sync.destroy_calls == 1);
        CHECK(allocation.frees == 2);
        EXPECT(vireo_completion_queue_create_with_ops(&options, &allocator, &operations, &queue),
            VIREO_RESULT_INVALID_ARGUMENT);
    }
    return 0;
}

static int lock_failure_and_inspect(void) {
    sync_trace_t sync = {0};
    allocation_trace_t allocation = {0};
    vireo_completion_queue_t *queue = NULL;
    CHECK(make_traced(&sync, &allocation, &queue) == 0);
    vireo_completion_t *owner = NULL, *output = NULL;
    CHECK(make_completion(1, &owner) == 0);
    vireo_completion_t *saved = owner;
    vireo_completion_queue_transfer_report_t report;
    int const failures[] = {EBUSY, EINVAL};
    for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); ++i) {
        sync.lock_error = failures[i];
        vireo_result_t const result = failures[i] == EBUSY ? VIREO_RESULT_BUSY : VIREO_RESULT_INTERNAL;
        EXPECT(vireo_completion_queue_try_push(queue, &owner, &report), result);
        CHECK(owner == saved && report_is(report, VIREO_COMPLETION_QUEUE_TRANSFER_LOCK, false, failures[i]));
        EXPECT(vireo_completion_queue_try_pop(queue, &output, &report), result);
        CHECK(output == NULL && report_is(report, VIREO_COMPLETION_QUEUE_TRANSFER_LOCK, false, failures[i]));
        vireo_completion_queue_info_t info;
        memset(&info, 0xa5, sizeof(info));
        unsigned char before[sizeof(info)];
        memcpy(before, &info, sizeof(info));
        EXPECT(vireo_completion_queue_inspect(queue, &info), result);
        CHECK(memcmp(before, &info, sizeof(info)) == 0);
    }
    CHECK(sync.lock_calls == 6 && sync.unlock_calls == 0);
    sync.lock_error = 0;
    EXPECT(vireo_completion_destroy(&owner), VIREO_OK);
    EXPECT(vireo_completion_queue_destroy(&queue), VIREO_OK);
    return 0;
}

static int unlock_real_progress(void) {
    sync_trace_t sync = {0};
    allocation_trace_t allocation = {0};
    vireo_completion_queue_t *queue = NULL;
    CHECK(make_traced(&sync, &allocation, &queue) == 0);
    vireo_completion_t *owner = NULL, *second = NULL;
    CHECK(make_completion(1, &owner) == 0 && make_completion(2, &second) == 0);
    vireo_completion_t *original = owner, *saved_second = second;
    vireo_completion_queue_transfer_report_t report;
    sync.unlock_error = EIO;
    EXPECT(vireo_completion_queue_try_push(queue, &owner, &report), VIREO_RESULT_INTERNAL);
    CHECK(owner == NULL && report_is(report, VIREO_COMPLETION_QUEUE_TRANSFER_UNLOCK, true, EIO));
    EXPECT(vireo_completion_queue_try_push(queue, &second, &report), VIREO_RESULT_INTERNAL);
    CHECK(second == saved_second && report_is(report, VIREO_COMPLETION_QUEUE_TRANSFER_UNLOCK, false, EIO));
    EXPECT(vireo_completion_queue_try_pop(queue, &owner, &report), VIREO_RESULT_INTERNAL);
    CHECK(owner == original && report_is(report, VIREO_COMPLETION_QUEUE_TRANSFER_UNLOCK, true, EIO));
    CHECK(verify_completion(owner, 1) == 0);
    EXPECT(vireo_completion_destroy(&owner), VIREO_OK);
    EXPECT(vireo_completion_queue_try_pop(queue, &owner, &report), VIREO_RESULT_INTERNAL);
    CHECK(owner == NULL && report_is(report, VIREO_COMPLETION_QUEUE_TRANSFER_UNLOCK, false, EIO));
    vireo_completion_queue_info_t info;
    memset(&info, 0xa5, sizeof(info));
    unsigned char before[sizeof(info)];
    memcpy(before, &info, sizeof(info));
    EXPECT(vireo_completion_queue_inspect(queue, &info), VIREO_RESULT_INTERNAL);
    CHECK(memcmp(before, &info, sizeof(info)) == 0);
    sync.unlock_error = 0;
    EXPECT(vireo_completion_queue_inspect(queue, &info), VIREO_OK);
    CHECK(info.count == 0);
    EXPECT(vireo_completion_destroy(&second), VIREO_OK);
    EXPECT(vireo_completion_queue_destroy(&queue), VIREO_OK);
    return 0;
}

static int destroy_failure(void) {
    sync_trace_t sync = {0};
    allocation_trace_t allocation = {0};
    vireo_completion_queue_t *queue = NULL;
    CHECK(make_traced(&sync, &allocation, &queue) == 0);
    vireo_completion_queue_t *saved = queue;
    vireo_completion_t *owner = NULL;
    CHECK(make_completion(1, &owner) == 0);
    vireo_completion_queue_transfer_report_t report;
    EXPECT(vireo_completion_queue_try_push(queue, &owner, &report), VIREO_OK);
    EXPECT(vireo_completion_queue_destroy(&queue), VIREO_RESULT_BUSY);
    CHECK(queue == saved && sync.destroy_calls == 0 && allocation.frees == 0);
    EXPECT(vireo_completion_queue_try_pop(queue, &owner, &report), VIREO_OK);
    EXPECT(vireo_completion_destroy(&owner), VIREO_OK);
    sync.destroy_error = EBUSY;
    EXPECT(vireo_completion_queue_destroy(&queue), VIREO_RESULT_BUSY);
    CHECK(queue == saved && allocation.frees == 0);
    sync.destroy_error = EINVAL;
    EXPECT(vireo_completion_queue_destroy(&queue), VIREO_RESULT_INTERNAL);
    CHECK(queue == saved && allocation.frees == 0);
    vireo_completion_queue_info_t info;
    EXPECT(vireo_completion_queue_inspect(queue, &info), VIREO_OK);
    sync.destroy_error = 0;
    EXPECT(vireo_completion_queue_destroy(&queue), VIREO_OK);
    CHECK(queue == NULL && allocation.frees == 1 && sync.destroy_calls == 3);
    return 0;
}

/** 每个 producer 的独立上下文；输入在 create 前发布，result 仅在 join 后读取。 */
typedef struct producer_context {
    vireo_completion_queue_t *queue; /**< 借用共同队列，寿命跨全部 join。 */
    size_t index; /**< 0..2，决定不重复测试编号，不是队列顺序。 */
    int result; /**< 本线程测试结果，主线程只在成功 join 后读取。 */
} producer_context_t;

/**
 * @brief
 *     真实 producer 构造并交接；有界重试只属测试 harness，库入口不重试。
 *
 * @param[in,out] argument
 *     本线程独立上下文，主线程在 join 前不访问 result。
 *
 * @return
 *     NULL；错误保存于 result，未交接 owner 由本线程清理。
 */
static void *producer(void *argument) {
    producer_context_t *context = argument;
    context->result = 1;
    for (size_t i = 0; i < ITEMS_PER_PRODUCER; ++i) {
        vireo_completion_t *owner = NULL;
        uint64_t const id = (uint64_t)(context->index * ITEMS_PER_PRODUCER + i + 1);
        if (make_completion(id, &owner) != 0) {
            (void)vireo_completion_destroy(&owner);
            return NULL;
        }
        bool sent = false;
        for (size_t attempt = 0; attempt < RETRY_LIMIT; ++attempt) {
            vireo_completion_queue_transfer_report_t report;
            errno = E2BIG;
            vireo_result_t const result = vireo_completion_queue_try_push(context->queue, &owner, &report);
            if (errno != E2BIG) {
                break;
            }
            if (result == VIREO_OK && owner == NULL &&
                report_is(report, VIREO_COMPLETION_QUEUE_TRANSFER_NONE, true, 0)) {
                sent = true;
                break;
            }
            if (result != VIREO_RESULT_BUSY || report.transferred || owner == NULL) {
                break;
            }
            (void)sched_yield();
        }
        if (!sent) {
            (void)vireo_completion_destroy(&owner);
            return NULL;
        }
    }
    context->result = 0;
    return NULL;
}

static int actual_mpsc(void) {
    vireo_completion_queue_t *queue = NULL;
    vireo_completion_queue_options_t const options = {7, 4096};
    EXPECT(vireo_completion_queue_create(&options, &queue), VIREO_OK);
    pthread_t threads[PRODUCERS];
    producer_context_t contexts[PRODUCERS];
    size_t created = 0;
    bool failed = false;
    for (size_t i = 0; i < PRODUCERS; ++i) {
        contexts[i] = (producer_context_t){queue, i, -1};
        if (pthread_create(&threads[i], NULL, producer, &contexts[i]) != 0) {
            failed = true;
            break;
        }
        ++created;
    }
    bool seen[PRODUCERS * ITEMS_PER_PRODUCER] = {false};
    size_t next[PRODUCERS] = {0};
    size_t received = 0;
    for (size_t attempt = 0; attempt < RETRY_LIMIT && received < created * ITEMS_PER_PRODUCER; ++attempt) {
        vireo_completion_t *owner = NULL;
        vireo_completion_queue_transfer_report_t report;
        errno = E2BIG;
        vireo_result_t const result = vireo_completion_queue_try_pop(queue, &owner, &report);
        if (errno != E2BIG) {
            failed = true;
        }
        if (result == VIREO_OK && owner != NULL && report.transferred) {
            vireo_completion_info_t info;
            if (vireo_completion_inspect(owner, &info) != VIREO_OK) {
                failed = true;
            } else {
                uint64_t const id = info.metadata.request.request_instance_id;
                if (id == 0 || id > created * ITEMS_PER_PRODUCER) {
                    failed = true;
                } else {
                    size_t const zero_id = (size_t)(id - 1);
                    size_t const p = zero_id / ITEMS_PER_PRODUCER;
                    size_t const sequence = zero_id % ITEMS_PER_PRODUCER;
                    if (seen[zero_id] || sequence != next[p] || verify_completion(owner, id) != 0) {
                        failed = true;
                    }
                    seen[zero_id] = true;
                    ++next[p];
                }
            }
            if (vireo_completion_destroy(&owner) != VIREO_OK) {
                failed = true;
            }
            ++received;
        } else if ((result == VIREO_RESULT_BUSY || result == VIREO_RESULT_NOT_FOUND) &&
            owner == NULL && !report.transferred) {
            (void)sched_yield();
        } else {
            failed = true;
            (void)vireo_completion_destroy(&owner);
            break;
        }
    }
    for (size_t i = 0; i < created; ++i) {
        CHECK(pthread_join(threads[i], NULL) == 0);
        if (contexts[i].result != 0 || next[i] != ITEMS_PER_PRODUCER) {
            failed = true;
        }
    }
    /* 测试失败也在 join 后领取残留，避免用自动 destroy 掩盖唯一所有权义务。 */
    for (;;) {
        vireo_completion_t *owner = NULL;
        vireo_completion_queue_transfer_report_t report;
        vireo_result_t const result = vireo_completion_queue_try_pop(queue, &owner, &report);
        if (result == VIREO_RESULT_NOT_FOUND) {
            break;
        }
        CHECK(result == VIREO_OK);
        failed = true;
        EXPECT(vireo_completion_destroy(&owner), VIREO_OK);
    }
    vireo_completion_queue_info_t info;
    EXPECT(vireo_completion_queue_inspect(queue, &info), VIREO_OK);
    CHECK(info.count == 0);
    EXPECT(vireo_completion_queue_destroy(&queue), VIREO_OK);
    CHECK(!failed && created == PRODUCERS && received == PRODUCERS * ITEMS_PER_PRODUCER);
    for (size_t i = 0; i < sizeof(seen) / sizeof(seen[0]); ++i) {
        CHECK(seen[i]);
    }
    return 0;
}

/** 测试组目录，只保存静态名称及对应单组函数，不保存运行资源。 */
typedef struct test_case {
    char const *name; /**< 日志中的测试组名称，静态只读。 */
    int (*run)(void); /**< 单组入口，0 成功，非零失败。 */
} test_case_t;

int main(void) {
    test_case_t const cases[] = {
        {"fifo_and_wrap", fifo_and_wrap},
        {"full_empty_and_destroy", full_empty_and_destroy},
        {"invalid_and_precedence", invalid_and_precedence},
        {"actual_contention", actual_contention},
        {"init_failure_and_copy", init_failure_and_copy},
        {"lock_failure_and_inspect", lock_failure_and_inspect},
        {"unlock_real_progress", unlock_real_progress},
        {"destroy_failure", destroy_failure},
        {"actual_mpsc", actual_mpsc}
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        if (cases[i].run() != 0) {
            fprintf(stderr, "FAIL %s\n", cases[i].name);
            return EXIT_FAILURE;
        }
        printf("PASS %s\n", cases[i].name);
    }
    return EXIT_SUCCESS;
}
