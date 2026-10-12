/*
 * PROJECT : VIREO
 * FILE    : test_completion_queue_close.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-12
 * BRIEF   : 永久关闭、保留FIFO排空、真实关闭进度及多producer关闭竞争
 */

#include "thread/completion_queue_internal.h"

#include <errno.h>
#include <sched.h>
#include <stdatomic.h>
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
#define ITEMS_PER_PRODUCER 32
#define RETRY_LIMIT 1000000

/** 单线程本核心故障账本，不在真实并发组修改操作表或故障字段。 */
typedef struct fault_trace {
    int lock_error; /**< 非零时不取得锁而报告此码。 */
    int unlock_error; /**< 实际成功解锁后报告注入码。 */
    size_t try_calls; /**< 每次 try callback 进入次数。 */
    size_t unlock_calls; /**< 实际解锁 callback 次数。 */
    size_t allocations; /**< 真实申请 callback 次数。 */
    size_t frees; /**< 配对释放 callback 次数。 */
} fault_trace_t;

/**
 * @brief
 *     同步测试使用标准初始化，无新增初始化故障协议。
 *
 * @param[in] context
 *     借用上下文，本适配不使用。
 * @param[in,out] mutex
 *     未初始化同步存储。
 *
 * @return
 *     原 pthread 返回码。
 */
static int trace_init(void *context, pthread_mutex_t *mutex) {
    (void)context;
    return pthread_mutex_init(mutex, NULL);
}

/**
 * @brief
 *     实际一次 try 或无持锁的故障，扰动 errno。
 *
 * @param[in,out] context
 *     单线程存活故障账本。
 * @param[in,out] mutex
 *     已初始化 mutex。
 *
 * @return
 *     注入码或原 pthread 直接返回码。
 */
static int trace_try(void *context, pthread_mutex_t *mutex) {
    fault_trace_t *trace = context;
    ++trace->try_calls;
    errno = EDOM;
    return trace->lock_error != 0 ? trace->lock_error : pthread_mutex_trylock(mutex);
}

/**
 * @brief
 *     实际释放后报告错误，核验关闭提交不回滚。
 *
 * @param[in,out] context
 *     单线程存活故障账本。
 * @param[in,out] mutex
 *     本线程实际取得的锁。
 *
 * @return
 *     真实异常优先，否则注入码；不模拟损坏同步恢复。
 */
static int trace_unlock(void *context, pthread_mutex_t *mutex) {
    fault_trace_t *trace = context;
    ++trace->unlock_calls;
    errno = EDOM;
    int const code = pthread_mutex_unlock(mutex);
    return code != 0 ? code : trace->unlock_error;
}

/**
 * @brief
 *     全部访问结束后的标准同步销毁。
 *
 * @param[in] context
 *     借用上下文，本适配不使用。
 * @param[in,out] mutex
 *     空队列的无访问 mutex。
 *
 * @return
 *     原 pthread 销毁返回码。
 */
static int trace_destroy(void *context, pthread_mutex_t *mutex) {
    (void)context;
    return pthread_mutex_destroy(mutex);
}

/**
 * @brief
 *     实际申请队列原块，记录以核验关闭无申请。
 *
 * @param[in,out] context
 *     单线程故障账本，覆盖队列寿命。
 * @param[in] bytes
 *     已受检正申请量。
 *
 * @return
 *     独占正确对齐块或 NULL。
 */
static void *trace_allocate(void *context, size_t bytes) {
    fault_trace_t *trace = context;
    ++trace->allocations;
    errno = ENOMEM;
    return malloc(bytes);
}

/**
 * @brief
 *     实际配对释放队列原块，关闭本身不得调用。
 *
 * @param[in,out] context
 *     单线程存活账本。
 * @param[in] allocation
 *     自有原块，全部访问结束。
 *
 * @note
 *     无失败返回，扰动 errno。
 */
static void trace_deallocate(void *context, void *allocation) {
    fault_trace_t *trace = context;
    ++trace->frees;
    free(allocation);
    errno = EIO;
}

/** 独立有效结果；局部输入改写，只有公开复制的响应字节随 owner 交接。 */
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

/** 只读快照及短借核验，不持有 view 超过返回，也不包含 completion 私有头。 */
static int verify_completion(vireo_completion_t *owner, uint64_t id) {
    vireo_completion_info_t info;
    EXPECT(vireo_completion_inspect(owner, &info), VIREO_OK);
    CHECK(info.metadata.request.request_instance_id == id);
    CHECK(info.metadata.result == VIREO_RESULT_DATABASE);
    vireo_completion_payload_view_t view;
    EXPECT(vireo_completion_borrow_payload(owner, &view), VIREO_OK);
    CHECK(view.size == 2 * sizeof(uint64_t));
    uint64_t bytes[2];
    memcpy(bytes, view.data, sizeof(bytes));
    CHECK(bytes[0] == id && bytes[1] == (id ^ UINT64_C(0xdeadbeef12345678)));
    return 0;
}

/** 关闭报告只按三个逻辑字段比较，changed 不等价于当前 closed。 */
static bool close_report_is(vireo_completion_queue_close_report_t report,
    vireo_completion_queue_close_stage_t stage, bool changed, int code) {
    return report.stage == stage && report.changed == changed && report.pthread_error == code;
}

/** 本核心单线程同步 seam 构造，操作表按值复制，trace 仍借至销毁。 */
static int make_traced(fault_trace_t *trace, vireo_completion_queue_t **queue) {
    vireo_completion_queue_options_t const options = {1, 4096};
    vireo_completion_queue_allocator_t const allocator = {trace, trace_allocate, trace_deallocate};
    vireo_completion_queue_sync_t const sync = {
        trace, trace_init, trace_try, trace_unlock, trace_destroy
    };
    EXPECT(vireo_completion_queue_create_with_ops(&options, &allocator, &sync, queue), VIREO_OK);
    return 0;
}

static int empty_and_repeat(void) {
    vireo_completion_queue_t *queue = NULL;
    vireo_completion_queue_options_t const options = {1, 4096};
    EXPECT(vireo_completion_queue_create(&options, &queue), VIREO_OK);
    vireo_completion_queue_info_t before;
    EXPECT(vireo_completion_queue_inspect(queue, &before), VIREO_OK);
    CHECK(!before.closed && before.count == 0);
    vireo_completion_t *owner = NULL;
    vireo_completion_queue_transfer_report_t transfer;
    EXPECT(vireo_completion_queue_try_pop(queue, &owner, &transfer), VIREO_RESULT_NOT_FOUND);
    vireo_completion_queue_close_report_t report;
    EXPECT(vireo_completion_queue_close(queue, &report), VIREO_OK);
    CHECK(close_report_is(report, VIREO_COMPLETION_QUEUE_CLOSE_NONE, true, 0));
    EXPECT(vireo_completion_queue_close(queue, &report), VIREO_OK);
    CHECK(close_report_is(report, VIREO_COMPLETION_QUEUE_CLOSE_NONE, false, 0));
    vireo_completion_queue_info_t after;
    EXPECT(vireo_completion_queue_inspect(queue, &after), VIREO_OK);
    CHECK(after.closed && after.count == 0 && !before.closed);
    CHECK(after.capacity == before.capacity && after.allocated_bytes == before.allocated_bytes &&
        after.max_memory_bytes == before.max_memory_bytes);
    for (size_t i = 0; i < 2; ++i) {
        EXPECT(vireo_completion_queue_try_pop(queue, &owner, &transfer), VIREO_RESULT_CANCELLED);
        CHECK(owner == NULL && !transfer.transferred && transfer.pthread_error == 0 &&
            transfer.stage == VIREO_COMPLETION_QUEUE_TRANSFER_NONE);
    }
    EXPECT(vireo_completion_queue_destroy(&queue), VIREO_OK);
    EXPECT(vireo_completion_queue_destroy(&queue), VIREO_OK);
    CHECK(queue == NULL && after.closed); /* 快照不保活，但其数值可独立继续读。 */
    return 0;
}

static int full_fifo_and_reject(void) {
    vireo_completion_queue_t *queue = NULL;
    vireo_completion_queue_options_t const options = {3, 4096};
    EXPECT(vireo_completion_queue_create(&options, &queue), VIREO_OK);
    vireo_completion_queue_transfer_report_t transfer;
    vireo_completion_t *saved[3];
    for (size_t i = 0; i < 3; ++i) {
        vireo_completion_t *owner = NULL;
        CHECK(make_completion((uint64_t)(i + 1), &owner) == 0);
        saved[i] = owner;
        EXPECT(vireo_completion_queue_try_push(queue, &owner, &transfer), VIREO_OK);
    }
    vireo_completion_queue_info_t before;
    EXPECT(vireo_completion_queue_inspect(queue, &before), VIREO_OK);
    CHECK(before.count == 3 && !before.closed);
    vireo_completion_queue_close_report_t report;
    EXPECT(vireo_completion_queue_close(queue, &report), VIREO_OK);
    CHECK(report.changed);
    EXPECT(vireo_completion_queue_close(queue, &report), VIREO_OK);
    CHECK(!report.changed);
    vireo_completion_queue_info_t after;
    EXPECT(vireo_completion_queue_inspect(queue, &after), VIREO_OK);
    CHECK(after.count == before.count && after.closed && !before.closed);
    vireo_completion_queue_t *original = queue;
    EXPECT(vireo_completion_queue_destroy(&queue), VIREO_RESULT_BUSY);
    CHECK(queue == original);
    vireo_completion_t *rejected = NULL;
    CHECK(make_completion(4, &rejected) == 0);
    vireo_completion_t *original_rejected = rejected;
    EXPECT(vireo_completion_queue_try_push(queue, &rejected, &transfer), VIREO_RESULT_CANCELLED);
    CHECK(rejected == original_rejected && !transfer.transferred && transfer.pthread_error == 0 &&
        transfer.stage == VIREO_COMPLETION_QUEUE_TRANSFER_NONE);
    CHECK(verify_completion(rejected, 4) == 0);
    EXPECT(vireo_completion_destroy(&rejected), VIREO_OK);
    for (size_t i = 0; i < 3; ++i) {
        vireo_completion_t *owner = NULL;
        EXPECT(vireo_completion_queue_try_pop(queue, &owner, &transfer), VIREO_OK);
        CHECK(owner == saved[i] && transfer.transferred);
        CHECK(verify_completion(owner, (uint64_t)(i + 1)) == 0);
        EXPECT(vireo_completion_destroy(&owner), VIREO_OK);
        EXPECT(vireo_completion_queue_inspect(queue, &after), VIREO_OK);
        CHECK(after.closed && after.count == 2 - i);
    }
    vireo_completion_t *owner = NULL;
    EXPECT(vireo_completion_queue_try_pop(queue, &owner, &transfer), VIREO_RESULT_CANCELLED);
    EXPECT(vireo_completion_queue_destroy(&queue), VIREO_OK);
    return 0;
}

static int wrapped_fifo(void) {
    vireo_completion_queue_t *queue = NULL;
    vireo_completion_queue_options_t const options = {3, 4096};
    EXPECT(vireo_completion_queue_create(&options, &queue), VIREO_OK);
    vireo_completion_queue_transfer_report_t transfer;
    for (size_t i = 1; i <= 5; ++i) {
        vireo_completion_t *owner = NULL;
        CHECK(make_completion((uint64_t)i, &owner) == 0);
        EXPECT(vireo_completion_queue_try_push(queue, &owner, &transfer), VIREO_OK);
        if (i <= 2) {
            EXPECT(vireo_completion_queue_try_pop(queue, &owner, &transfer), VIREO_OK);
            CHECK(verify_completion(owner, (uint64_t)i) == 0);
            EXPECT(vireo_completion_destroy(&owner), VIREO_OK);
        }
    }
    vireo_completion_queue_close_report_t report;
    EXPECT(vireo_completion_queue_close(queue, &report), VIREO_OK);
    for (uint64_t id = 3; id <= 5; ++id) {
        vireo_completion_t *owner = NULL;
        EXPECT(vireo_completion_queue_try_pop(queue, &owner, &transfer), VIREO_OK);
        CHECK(verify_completion(owner, id) == 0);
        EXPECT(vireo_completion_destroy(&owner), VIREO_OK);
    }
    EXPECT(vireo_completion_queue_destroy(&queue), VIREO_OK);
    return 0;
}

static int invalid_and_precedence(void) {
    fault_trace_t trace = {0};
    vireo_completion_queue_t *queue = NULL;
    CHECK(make_traced(&trace, &queue) == 0);
    vireo_completion_queue_close_report_t report = {VIREO_COMPLETION_QUEUE_CLOSE_UNLOCK, true, EIO};
    trace.lock_error = EINVAL;
    EXPECT(vireo_completion_queue_close(NULL, &report), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(close_report_is(report, VIREO_COMPLETION_QUEUE_CLOSE_NONE, false, 0));
    EXPECT(vireo_completion_queue_close(queue, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_completion_queue_close(NULL, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(trace.try_calls == 0);
    trace.lock_error = 0;
    EXPECT(vireo_completion_queue_close(queue, &report), VIREO_OK);
    size_t const calls = trace.try_calls;
    trace.lock_error = EINVAL;
    vireo_completion_t *owner = NULL;
    vireo_completion_queue_transfer_report_t transfer;
    EXPECT(vireo_completion_queue_try_push(queue, &owner, &transfer), VIREO_RESULT_NOT_FOUND);
    EXPECT(vireo_completion_queue_try_push(NULL, &owner, &transfer), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(make_completion(1, &owner) == 0);
    vireo_completion_t *original = owner;
    EXPECT(vireo_completion_queue_try_pop(queue, &owner, &transfer), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(trace.try_calls == calls && owner == original);
    EXPECT(vireo_completion_destroy(&owner), VIREO_OK);
    trace.lock_error = 0;
    EXPECT(vireo_completion_queue_destroy(&queue), VIREO_OK);
    CHECK(trace.allocations == 1 && trace.frees == 1);
    return 0;
}

static int actual_contention(void) {
    vireo_completion_queue_t *queue = NULL;
    vireo_completion_queue_options_t const options = {1, 4096};
    EXPECT(vireo_completion_queue_create(&options, &queue), VIREO_OK);
    CHECK(pthread_mutex_lock(&queue->mutex) == 0);
    vireo_completion_queue_close_report_t report;
    EXPECT(vireo_completion_queue_close(queue, &report), VIREO_RESULT_BUSY);
    CHECK(close_report_is(report, VIREO_COMPLETION_QUEUE_CLOSE_LOCK, false, EBUSY));
    CHECK(pthread_mutex_unlock(&queue->mutex) == 0);
    vireo_completion_queue_info_t info;
    EXPECT(vireo_completion_queue_inspect(queue, &info), VIREO_OK);
    CHECK(!info.closed);
    EXPECT(vireo_completion_queue_close(queue, &report), VIREO_OK);
    EXPECT(vireo_completion_queue_destroy(&queue), VIREO_OK);
    return 0;
}

static int lock_failures(void) {
    fault_trace_t trace = {0};
    vireo_completion_queue_t *queue = NULL;
    CHECK(make_traced(&trace, &queue) == 0);
    int const errors[] = {EBUSY, EINVAL};
    for (size_t i = 0; i < sizeof(errors) / sizeof(errors[0]); ++i) {
        trace.lock_error = errors[i];
        size_t const before = trace.try_calls;
        vireo_completion_queue_close_report_t report;
        EXPECT(vireo_completion_queue_close(queue, &report),
            errors[i] == EBUSY ? VIREO_RESULT_BUSY : VIREO_RESULT_INTERNAL);
        CHECK(close_report_is(report, VIREO_COMPLETION_QUEUE_CLOSE_LOCK, false, errors[i]));
        CHECK(trace.try_calls == before + 1 && trace.unlock_calls == 0);
    }
    trace.lock_error = 0;
    vireo_completion_queue_info_t info;
    EXPECT(vireo_completion_queue_inspect(queue, &info), VIREO_OK);
    CHECK(!info.closed && info.count == 0);
    vireo_completion_queue_close_report_t report;
    EXPECT(vireo_completion_queue_close(queue, &report), VIREO_OK);
    CHECK(report.changed && trace.allocations == 1 && trace.frees == 0);
    EXPECT(vireo_completion_queue_destroy(&queue), VIREO_OK);
    return 0;
}

static int unlock_progress(void) {
    fault_trace_t trace = {0};
    vireo_completion_queue_t *queue = NULL;
    CHECK(make_traced(&trace, &queue) == 0);
    vireo_completion_t *owner = NULL;
    CHECK(make_completion(1, &owner) == 0);
    vireo_completion_queue_transfer_report_t transfer;
    EXPECT(vireo_completion_queue_try_push(queue, &owner, &transfer), VIREO_OK);
    trace.unlock_error = EIO;
    vireo_completion_queue_close_report_t report;
    EXPECT(vireo_completion_queue_close(queue, &report), VIREO_RESULT_INTERNAL);
    CHECK(close_report_is(report, VIREO_COMPLETION_QUEUE_CLOSE_UNLOCK, true, EIO));
    EXPECT(vireo_completion_queue_close(queue, &report), VIREO_RESULT_INTERNAL);
    CHECK(close_report_is(report, VIREO_COMPLETION_QUEUE_CLOSE_UNLOCK, false, EIO));
    CHECK(make_completion(2, &owner) == 0);
    vireo_completion_t *original = owner;
    EXPECT(vireo_completion_queue_try_push(queue, &owner, &transfer), VIREO_RESULT_INTERNAL);
    CHECK(owner == original && !transfer.transferred && transfer.pthread_error == EIO &&
        transfer.stage == VIREO_COMPLETION_QUEUE_TRANSFER_UNLOCK);
    EXPECT(vireo_completion_destroy(&owner), VIREO_OK);
    EXPECT(vireo_completion_queue_try_pop(queue, &owner, &transfer), VIREO_RESULT_INTERNAL);
    CHECK(owner != NULL && transfer.transferred && transfer.pthread_error == EIO);
    CHECK(verify_completion(owner, 1) == 0);
    EXPECT(vireo_completion_destroy(&owner), VIREO_OK);
    EXPECT(vireo_completion_queue_try_pop(queue, &owner, &transfer), VIREO_RESULT_INTERNAL);
    CHECK(owner == NULL && !transfer.transferred && transfer.pthread_error == EIO);
    vireo_completion_queue_info_t info;
    memset(&info, 0xa5, sizeof(info));
    unsigned char before[sizeof(info)];
    memcpy(before, &info, sizeof(info));
    EXPECT(vireo_completion_queue_inspect(queue, &info), VIREO_RESULT_INTERNAL);
    CHECK(memcmp(before, &info, sizeof(info)) == 0);
    trace.unlock_error = 0;
    EXPECT(vireo_completion_queue_inspect(queue, &info), VIREO_OK);
    CHECK(info.closed && info.count == 0 && trace.allocations == 1 && trace.frees == 0);
    EXPECT(vireo_completion_queue_close(queue, &report), VIREO_OK);
    CHECK(!report.changed);
    EXPECT(vireo_completion_queue_destroy(&queue), VIREO_OK);
    CHECK(trace.frees == 1);
    return 0;
}

/** 测试阶段同步，原子字段无非原子并发访问；不是队列实现的一部分。 */
typedef struct race_gate {
    atomic_size_t arrived; /**< 完成第一项提交尝试的producer数，最多3。 */
    atomic_bool released; /**< main放行后续提交与close竞争，初始false。 */
} race_gate_t;

/** 每producer独立输入/结果，结果仅在对应pthread_join成功后读取。 */
typedef struct producer_context {
    vireo_completion_queue_t *queue; /**< 借用共同queue，活到全部join及排空结束。 */
    race_gate_t *gate; /**< 借用原子阶段门，寿命跨全部join。 */
    size_t index; /**< 0..2，选择不同测试编号区间，不表示提交顺序。 */
    size_t accepted; /**< 本线程真实转移项数，仅本线程写、join后main读。 */
    size_t rejected; /**< 本线程closed拒绝且自行清理项数。 */
    int result; /**< 本线程测试0成功/1失败，join前main不读取。 */
} producer_context_t;

/**
 * @brief
 *     第一项实际填槽，后续提交与关闭竞争，拒绝对象由本线程显式清理。
 *
 * @param[in,out] argument
 *     独立存活producer上下文；共享阶段字段仅原子访问。
 *
 * @return
 *     NULL；真实交接与清理结果留context，测试harness有界重试不属于库重试。
 */
static void *producer(void *argument) {
    producer_context_t *context = argument;
    context->result = 1;
    for (size_t i = 0; i < ITEMS_PER_PRODUCER; ++i) {
        if (i == 1) {
            bool released = false;
            for (size_t attempt = 0; attempt < RETRY_LIMIT; ++attempt) {
                if (atomic_load_explicit(&context->gate->released, memory_order_acquire)) {
                    released = true;
                    break;
                }
                (void)sched_yield();
            }
            if (!released) {
                return NULL;
            }
        }
        vireo_completion_t *owner = NULL;
        uint64_t const id = (uint64_t)(context->index * ITEMS_PER_PRODUCER + i + 2);
        bool handled = false;
        if (make_completion(id, &owner) == 0) {
            for (size_t attempt = 0; attempt < RETRY_LIMIT; ++attempt) {
                vireo_completion_queue_transfer_report_t report;
                errno = E2BIG;
                vireo_result_t const result = vireo_completion_queue_try_push(context->queue, &owner, &report);
                if (errno != E2BIG) {
                    break;
                }
                if (result == VIREO_OK && owner == NULL && report.transferred &&
                    report.stage == VIREO_COMPLETION_QUEUE_TRANSFER_NONE && report.pthread_error == 0) {
                    ++context->accepted;
                    handled = true;
                    break;
                }
                if (result == VIREO_RESULT_CANCELLED && owner != NULL && !report.transferred &&
                    report.stage == VIREO_COMPLETION_QUEUE_TRANSFER_NONE && report.pthread_error == 0) {
                    if (verify_completion(owner, id) == 0 && vireo_completion_destroy(&owner) == VIREO_OK) {
                        ++context->rejected;
                        handled = true;
                    }
                    break;
                }
                if (result != VIREO_RESULT_BUSY || owner == NULL || report.transferred) {
                    break;
                }
                (void)sched_yield();
            }
        }
        if (i == 0) {
            (void)atomic_fetch_add_explicit(&context->gate->arrived, 1, memory_order_release);
        }
        if (!handled) {
            (void)vireo_completion_destroy(&owner);
            return NULL;
        }
    }
    context->result = 0;
    return NULL;
}

static int actual_close_race(void) {
    vireo_completion_queue_t *queue = NULL;
    vireo_completion_queue_options_t const options = {4, 4096};
    EXPECT(vireo_completion_queue_create(&options, &queue), VIREO_OK);
    vireo_completion_t *seed = NULL;
    CHECK(make_completion(1, &seed) == 0);
    vireo_completion_queue_transfer_report_t transfer;
    EXPECT(vireo_completion_queue_try_push(queue, &seed, &transfer), VIREO_OK);
    race_gate_t gate;
    atomic_init(&gate.arrived, 0);
    atomic_init(&gate.released, false);
    pthread_t threads[PRODUCERS];
    producer_context_t contexts[PRODUCERS];
    size_t created = 0;
    bool failed = false;
    for (size_t i = 0; i < PRODUCERS; ++i) {
        contexts[i] = (producer_context_t){queue, &gate, i, 0, 0, -1};
        if (pthread_create(&threads[i], NULL, producer, &contexts[i]) != 0) {
            failed = true;
            break;
        }
        ++created;
    }
    bool arrived = false;
    for (size_t attempt = 0; attempt < RETRY_LIMIT; ++attempt) {
        if (atomic_load_explicit(&gate.arrived, memory_order_acquire) == created) {
            arrived = true;
            break;
        }
        (void)sched_yield();
    }
    if (!arrived) {
        failed = true;
    }
    /* 不消费，保证正常路径seed+三个首项填满；后续push与close都使用真实mutex。 */
    atomic_store_explicit(&gate.released, true, memory_order_release);
    bool closed = false;
    for (size_t attempt = 0; attempt < RETRY_LIMIT; ++attempt) {
        vireo_completion_queue_close_report_t report;
        errno = E2BIG;
        vireo_result_t const result = vireo_completion_queue_close(queue, &report);
        if (errno != E2BIG) {
            failed = true;
        }
        if (result == VIREO_OK && close_report_is(report, VIREO_COMPLETION_QUEUE_CLOSE_NONE, true, 0)) {
            closed = true;
            break;
        }
        if (result != VIREO_RESULT_BUSY || report.changed) {
            failed = true;
            break;
        }
        (void)sched_yield();
    }
    /* close确认后无新提交；main是唯一consumer，领取至closed空终止。 */
    bool seen[PRODUCERS * ITEMS_PER_PRODUCER + 1] = {false};
    size_t received = 0;
    bool terminal = false;
    for (size_t attempt = 0; attempt < RETRY_LIMIT; ++attempt) {
        vireo_completion_t *owner = NULL;
        errno = E2BIG;
        vireo_result_t const result = vireo_completion_queue_try_pop(queue, &owner, &transfer);
        if (errno != E2BIG) {
            failed = true;
        }
        if (result == VIREO_OK && owner != NULL && transfer.transferred) {
            vireo_completion_info_t info;
            if (vireo_completion_inspect(owner, &info) != VIREO_OK) {
                failed = true;
            } else {
                uint64_t const id = info.metadata.request.request_instance_id;
                if (id == 0 || id > PRODUCERS * ITEMS_PER_PRODUCER + 1) {
                    failed = true;
                } else {
                    size_t const index = (size_t)(id - 1);
                    if (seen[index] || verify_completion(owner, id) != 0) {
                        failed = true;
                    }
                    seen[index] = true;
                }
            }
            if (vireo_completion_destroy(&owner) != VIREO_OK) {
                failed = true;
            }
            ++received;
        } else if (result == VIREO_RESULT_CANCELLED && owner == NULL && !transfer.transferred) {
            terminal = true;
            break;
        } else if (result == VIREO_RESULT_BUSY && owner == NULL && !transfer.transferred) {
            (void)sched_yield();
        } else {
            failed = true;
            (void)vireo_completion_destroy(&owner);
            break;
        }
    }
    for (size_t i = 0; i < created; ++i) {
        CHECK(pthread_join(threads[i], NULL) == 0);
        if (contexts[i].result != 0 || contexts[i].accepted != 1 ||
            contexts[i].rejected != ITEMS_PER_PRODUCER - 1) {
            failed = true;
        }
    }
    /* 负路径也join后清残留，不靠destroy自动清理。 */
    for (;;) {
        vireo_completion_t *owner = NULL;
        vireo_result_t const result = vireo_completion_queue_try_pop(queue, &owner, &transfer);
        if (result == VIREO_RESULT_CANCELLED || result == VIREO_RESULT_NOT_FOUND) {
            break;
        }
        CHECK(result == VIREO_OK);
        failed = true;
        EXPECT(vireo_completion_destroy(&owner), VIREO_OK);
    }
    vireo_completion_queue_info_t info;
    EXPECT(vireo_completion_queue_inspect(queue, &info), VIREO_OK);
    CHECK(info.closed && info.count == 0);
    EXPECT(vireo_completion_queue_destroy(&queue), VIREO_OK);
    CHECK(!failed && closed && terminal && created == PRODUCERS && received == PRODUCERS + 1);
    CHECK(seen[0]);
    for (size_t i = 1; i < sizeof(seen) / sizeof(seen[0]); ++i) {
        CHECK(seen[i] == ((i - 1) % ITEMS_PER_PRODUCER == 0));
    }
    return 0;
}

/** 静态测试目录，名称与组函数不拥有运行资源。 */
typedef struct test_case {
    char const *name; /**< 静态只读组名，用于日志定位。 */
    int (*run)(void); /**< 单组入口，0成功/非零失败。 */
} test_case_t;

int main(void) {
    test_case_t const cases[] = {
        {"empty_and_repeat", empty_and_repeat},
        {"full_fifo_and_reject", full_fifo_and_reject},
        {"wrapped_fifo", wrapped_fifo},
        {"invalid_and_precedence", invalid_and_precedence},
        {"actual_contention", actual_contention},
        {"lock_failures", lock_failures},
        {"unlock_progress", unlock_progress},
        {"actual_close_race", actual_close_race}
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
