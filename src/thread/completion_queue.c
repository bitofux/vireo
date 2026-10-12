/*
 * PROJECT : VIREO
 * FILE    : completion_queue.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-12
 * BRIEF   : 完成队列的受检申请、MPSC 交接、生产等待与配对释放
 * IMPLEMENTATION : 同块 flexible 数组；mutex 保护 head/tail/count/closed 和槽所有权，条件回绕兼容非 2 幂。
 * -- cond 仅提示空间/关闭变化，等待循环重检谓词；prepare/destroy 排除全部访问。
 */

#include "completion_queue_internal.h"

#include <vireo/base/checked.h>

#include <errno.h>
#include <stdlib.h>

/**
 * @brief
 *     标准申请适配，外层负责 errno 保持。
 *
 * @param[in] context
 *     不使用，允许 NULL。
 * @param[in] bytes
 *     已受检并符合预算的正字节数。
 *
 * @return
 *     新独占对齐块，失败 NULL。
 */
static void *standard_allocate(void *context, size_t bytes) {
    (void)context;
    return malloc(bytes);
}

/**
 * @brief
 *     配对释放标准申请原块，外层负责 errno 保持。
 *
 * @param[in] context
 *     不使用，允许 NULL。
 * @param[in] allocation
 *     唯一拥有且全部访问结束的原块。
 *
 * @note
 *     无失败返回，不释放 caller 输入或借用上下文。
 */
static void standard_deallocate(void *context, void *allocation) {
    (void)context;
    free(allocation);
}

/**
 * @brief
 *     初始化默认非 robust mutex，外层保持 errno。
 *
 * @param[in] context
 *     不使用，允许 NULL。
 * @param[in,out] mutex
 *     存活同步存储，状态符合对应 pthread 操作的前提。
 *
 * @return
 *     原 pthread 返回码，不在这里映射或重试。
 */
static int standard_init(void *context, pthread_mutex_t *mutex) {
    (void)context;
    return pthread_mutex_init(mutex, NULL);
}

/**
 * @brief
 *     只尝试一次取得 mutex，外层保持 errno。
 *
 * @param[in] context
 *     不使用，允许 NULL。
 * @param[in,out] mutex
 *     存活同步存储，状态符合对应 pthread 操作的前提。
 *
 * @return
 *     原 pthread 返回码，不在这里映射或重试。
 */
static int standard_try_lock(void *context, pthread_mutex_t *mutex) {
    (void)context;
    return pthread_mutex_trylock(mutex);
}

/**
 * @brief
 *     释放已取得的 mutex，外层保持 errno。
 *
 * @param[in] context
 *     不使用，允许 NULL。
 * @param[in,out] mutex
 *     存活同步存储，状态符合对应 pthread 操作的前提。
 *
 * @return
 *     原 pthread 返回码，不在这里映射或重试。
 */
static int standard_unlock(void *context, pthread_mutex_t *mutex) {
    (void)context;
    return pthread_mutex_unlock(mutex);
}

/**
 * @brief
 *     全部访问结束后销毁 mutex，外层保持 errno。
 *
 * @param[in] context
 *     不使用，允许 NULL。
 * @param[in,out] mutex
 *     存活同步存储，状态符合对应 pthread 操作的前提。
 *
 * @return
 *     原 pthread 返回码，不在这里映射或重试。
 */
static int standard_destroy(void *context, pthread_mutex_t *mutex) {
    (void)context;
    return pthread_mutex_destroy(mutex);
}

static vireo_completion_queue_sync_t const standard_sync = {
    NULL, standard_init, standard_try_lock, standard_unlock, standard_destroy
};

vireo_result_t vireo_completion_queue_create_with_ops(
    vireo_completion_queue_options_t const *options,
    vireo_completion_queue_allocator_t const *allocator,
    vireo_completion_queue_sync_t const *sync, vireo_completion_queue_t **out_queue) {
    if (out_queue == NULL || *out_queue != NULL || options == NULL ||
        options->capacity == 0 || options->max_memory_bytes == 0 || allocator == NULL ||
        allocator->allocate == NULL || allocator->deallocate == NULL || sync == NULL ||
        sync->init == NULL || sync->try_lock == NULL || sync->unlock == NULL ||
        sync->destroy == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    size_t const capacity = options->capacity;
    size_t const budget = options->max_memory_bytes;
    size_t slot_bytes = 0;
    vireo_result_t result = vireo_checked_size_mul(capacity, sizeof(vireo_completion_t *),
        &slot_bytes);
    if (result != VIREO_OK) {
        return result;
    }
    size_t allocated_bytes = 0;
    result = vireo_checked_size_add(sizeof(vireo_completion_queue_t), slot_bytes,
        &allocated_bytes);
    if (result != VIREO_OK) {
        return result;
    }
    if (capacity > VIREO_COMPLETION_QUEUE_MAX_CAPACITY ||
        budget > VIREO_COMPLETION_QUEUE_MAX_ALLOCATION_BYTES || allocated_bytes > budget) {
        return VIREO_RESULT_RANGE;
    }
    int const saved_errno = errno;
    vireo_completion_queue_allocator_t const allocation_ops = *allocator;
    vireo_completion_queue_sync_t const sync_ops = *sync;
    vireo_completion_queue_t *queue = allocation_ops.allocate(allocation_ops.context,
        allocated_bytes);
    if (queue == NULL) {
        errno = saved_errno;
        return VIREO_RESULT_NO_MEMORY;
    }
    queue->capacity = capacity;
    queue->allocated_bytes = allocated_bytes;
    queue->max_memory_bytes = budget;
    queue->allocator = allocation_ops;
    queue->sync = sync_ops;
    queue->head = 0;
    queue->tail = 0;
    queue->count = 0;
    queue->high_watermark = 0;
    queue->full_rejections = 0;
    queue->closed_rejections = 0;
    queue->rejection_count_saturated = false;
    queue->closed = false;
    queue->wait_prepared = false;
    queue->retiring = false;
    for (size_t i = 0; i < capacity; ++i) {
        queue->slots[i] = NULL;
    }
    int const code = sync_ops.init(sync_ops.context, &queue->mutex);
    if (code != 0) {
        allocation_ops.deallocate(allocation_ops.context, queue);
        errno = saved_errno;
        return code == ENOMEM ? VIREO_RESULT_NO_MEMORY : VIREO_RESULT_INTERNAL;
    }
    *out_queue = queue;
    errno = saved_errno;
    return VIREO_OK;
}

vireo_result_t vireo_completion_queue_create_with_allocator(
    vireo_completion_queue_options_t const *options,
    vireo_completion_queue_allocator_t const *allocator, vireo_completion_queue_t **out_queue) {
    return vireo_completion_queue_create_with_ops(options, allocator, &standard_sync, out_queue);
}

vireo_result_t vireo_completion_queue_create(vireo_completion_queue_options_t const *options,
    vireo_completion_queue_t **out_queue) {
    vireo_completion_queue_allocator_t const allocator = {NULL, standard_allocate,
        standard_deallocate};
    return vireo_completion_queue_create_with_allocator(options, &allocator, out_queue);
}

vireo_result_t vireo_completion_queue_inspect(vireo_completion_queue_t const *queue,
    vireo_completion_queue_info_t *out_info) {
    if (queue == NULL || out_info == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    if (queue->retiring) {
        return VIREO_RESULT_CANCELLED;
    }
    int const saved_errno = errno;
    /* 逻辑只读观测；实际对象由非 const 申请块创建，锁自身必须可变。 */
    pthread_mutex_t *mutex = &((vireo_completion_queue_t *)queue)->mutex;
    int code = queue->sync.try_lock(queue->sync.context, mutex);
    if (code != 0) {
        errno = saved_errno;
        return code == EBUSY ? VIREO_RESULT_BUSY : VIREO_RESULT_INTERNAL;
    }
    vireo_completion_queue_info_t const info = {queue->capacity, queue->count,
        queue->allocated_bytes, queue->max_memory_bytes, queue->closed, queue->wait_prepared};
    code = queue->sync.unlock(queue->sync.context, mutex);
    if (code == 0) {
        *out_info = info;
    }
    errno = saved_errno;
    return code == 0 ? VIREO_OK : VIREO_RESULT_INTERNAL;
}

vireo_result_t vireo_completion_queue_inspect_metrics(vireo_completion_queue_t const *queue,
    vireo_completion_queue_metrics_t *out_metrics) {
    if (queue == NULL || out_metrics == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    if (queue->retiring) {
        return VIREO_RESULT_CANCELLED;
    }
    int const saved_errno = errno;
    pthread_mutex_t *mutex = &((vireo_completion_queue_t *)queue)->mutex;
    int code = queue->sync.try_lock(queue->sync.context, mutex);
    if (code != 0) {
        errno = saved_errno;
        return code == EBUSY ? VIREO_RESULT_BUSY : VIREO_RESULT_INTERNAL;
    }
    vireo_completion_queue_metrics_t const metrics = {queue->count, queue->high_watermark,
        queue->full_rejections, queue->closed_rejections, queue->rejection_count_saturated};
    code = queue->sync.unlock(queue->sync.context, mutex);
    if (code == 0) {
        *out_metrics = metrics;
    }
    errno = saved_errno;
    return code == 0 ? VIREO_OK : VIREO_RESULT_INTERNAL;
}

/**
 * @brief
 *     锁内记录一次真实拒绝，计数耗尽不影响工作返回码或 owner。
 *
 * @param[in,out] count
 *     必需累计地址，已持有所属 queue 的 mutex。
 * @param[in,out] saturated
 *     同 queue 的粘性标志，已持同一 mutex，入口可为 true。
 *
 * @note
 *     恰达 MAX 仍精确，再计才置标志；不回绕或清除已有标志。
 */
static void record_rejection(uint64_t *count, bool *saturated) {
    if (*count == UINT64_MAX) {
        *saturated = true;
    } else {
        ++*count;
    }
}

/**
 * @brief
 *     两种提交共用的锁内占用峰值更新。
 *
 * @param[in,out] queue
 *     已持 mutex、已经增加 count 的存活容器；count 不超过 capacity。
 *
 * @note
 *     不改变深度/owner；没有提交则不调用，不随领取下降。
 */
static void record_high_watermark(vireo_completion_queue_t *queue) {
    if (queue->count > queue->high_watermark) {
        queue->high_watermark = queue->count;
    }
}

/**
 * @brief
 *     一次 try 临界区内提交 owner 交接，统一发布同步诊断及真实进度。
 *
 * @param[in,out] queue
 *     存活队列，寿命由外层 caller 保证。
 * @param[in,out] owner
 *     push 的独占非空源或 pop 的独占空输出。
 * @param[in] pushing
 *     true 为提交，false 为领取；只选择本次方向，不保存。
 * @param[out] out_report
 *     独立必需报告，可写时每路径覆盖，不能与资源/owner/errno 重叠。
 *
 * @return
 *     沿公开交接合同；解锁错误覆盖普通结果，不撤销已经发生的转移。
 *
 * @note
 *     锁内只更新指针及有界索引/计数，不调用对象业务函数或申请。
 *     任意容量用边界条件回绕，避免无限累计序号溢出，全部路径保持 errno。
 */
static vireo_result_t transfer(vireo_completion_queue_t *queue, vireo_completion_t **owner,
    bool pushing, vireo_completion_queue_transfer_report_t *out_report) {
    int const saved_errno = errno;
    vireo_completion_queue_transfer_report_t report = {
        VIREO_COMPLETION_QUEUE_TRANSFER_NONE, false, 0
    };
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    if (queue == NULL || owner == NULL || out_report == NULL || (!pushing && *owner != NULL)) {
        goto done;
    }
    if (pushing && *owner == NULL) {
        result = VIREO_RESULT_NOT_FOUND;
        goto done;
    }
    if (queue->retiring) {
        result = VIREO_RESULT_CANCELLED;
        goto done;
    }
    int code = queue->sync.try_lock(queue->sync.context, &queue->mutex);
    if (code != 0) {
        report.stage = VIREO_COMPLETION_QUEUE_TRANSFER_LOCK;
        report.pthread_error = code;
        result = code == EBUSY ? VIREO_RESULT_BUSY : VIREO_RESULT_INTERNAL;
        goto done;
    }
    if (pushing) {
        result = queue->closed ? VIREO_RESULT_CANCELLED : VIREO_RESULT_BUSY;
        if (queue->closed) {
            record_rejection(&queue->closed_rejections, &queue->rejection_count_saturated);
        } else if (queue->count == queue->capacity) {
            record_rejection(&queue->full_rejections, &queue->rejection_count_saturated);
        }
        if (!queue->closed && queue->count < queue->capacity) {
            queue->slots[queue->tail] = *owner;
            *owner = NULL;
            queue->tail = queue->tail == queue->capacity - 1 ? 0 : queue->tail + 1;
            ++queue->count;
            record_high_watermark(queue);
            report.transferred = true;
            result = VIREO_OK;
        }
    } else {
        result = queue->closed ? VIREO_RESULT_CANCELLED : VIREO_RESULT_NOT_FOUND;
        if (queue->count != 0) {
            *owner = queue->slots[queue->head];
            queue->slots[queue->head] = NULL;
            queue->head = queue->head == queue->capacity - 1 ? 0 : queue->head + 1;
            --queue->count;
            report.transferred = true;
            result = VIREO_OK;
            if (queue->wait_prepared) {
                code = queue->wait_ops.signal(queue->wait_ops.context, &queue->cond);
                if (code != 0) {
                    report.stage = VIREO_COMPLETION_QUEUE_TRANSFER_WAKE;
                    report.pthread_error = code;
                    result = VIREO_RESULT_INTERNAL;
                }
            }
        }
    }
    code = queue->sync.unlock(queue->sync.context, &queue->mutex);
    if (code != 0) {
        report.stage = VIREO_COMPLETION_QUEUE_TRANSFER_UNLOCK;
        report.pthread_error = code;
        result = VIREO_RESULT_INTERNAL;
    }
done:
    if (out_report != NULL) {
        *out_report = report;
    }
    errno = saved_errno;
    return result;
}

vireo_result_t vireo_completion_queue_try_push(vireo_completion_queue_t *queue,
    vireo_completion_t **owner, vireo_completion_queue_transfer_report_t *out_report) {
    return transfer(queue, owner, true, out_report);
}

vireo_result_t vireo_completion_queue_try_pop(vireo_completion_queue_t *queue,
    vireo_completion_t **out_completion, vireo_completion_queue_transfer_report_t *out_report) {
    return transfer(queue, out_completion, false, out_report);
}

vireo_result_t vireo_completion_queue_destroy(vireo_completion_queue_t **owner) {
    if (owner == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    if (*owner == NULL) {
        return VIREO_OK;
    }
    vireo_completion_queue_t *queue = *owner;
    if (queue->count != 0) {
        return VIREO_RESULT_BUSY;
    }
    int const saved_errno = errno;
    if (queue->wait_prepared) {
        int const cond_code = queue->wait_ops.destroy(queue->wait_ops.context, &queue->cond);
        if (cond_code != 0) {
            errno = saved_errno;
            return cond_code == EBUSY ? VIREO_RESULT_BUSY : VIREO_RESULT_INTERNAL;
        }
        /* 已释放的 cond 不得重建或再次销毁；保留后续失败时的剩余资源。 */
        queue->wait_prepared = false;
        queue->retiring = true;
    }
    int const code = queue->sync.destroy(queue->sync.context, &queue->mutex);
    if (code != 0) {
        errno = saved_errno;
        return code == EBUSY ? VIREO_RESULT_BUSY : VIREO_RESULT_INTERNAL;
    }
    vireo_completion_queue_allocator_t const operations = queue->allocator;
    operations.deallocate(operations.context, queue);
    *owner = NULL;
    errno = saved_errno;
    return VIREO_OK;
}

vireo_result_t vireo_completion_queue_close(vireo_completion_queue_t *queue,
    vireo_completion_queue_close_report_t *out_report) {
    int const saved_errno = errno;
    vireo_completion_queue_close_report_t report = {VIREO_COMPLETION_QUEUE_CLOSE_NONE, false, 0};
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    if (queue == NULL || out_report == NULL) {
        goto done;
    }
    if (queue->retiring) {
        result = VIREO_RESULT_CANCELLED;
        goto done;
    }
    int code = queue->sync.try_lock(queue->sync.context, &queue->mutex);
    if (code != 0) {
        report.stage = VIREO_COMPLETION_QUEUE_CLOSE_LOCK;
        report.pthread_error = code;
        result = code == EBUSY ? VIREO_RESULT_BUSY : VIREO_RESULT_INTERNAL;
        goto done;
    }
    if (!queue->closed) {
        queue->closed = true;
        report.changed = true;
    }
    result = VIREO_OK;
    if (queue->wait_prepared) {
        code = queue->wait_ops.broadcast(queue->wait_ops.context, &queue->cond);
        if (code != 0) {
            report.stage = VIREO_COMPLETION_QUEUE_CLOSE_WAKE;
            report.pthread_error = code;
            result = VIREO_RESULT_INTERNAL;
        }
    }
    code = queue->sync.unlock(queue->sync.context, &queue->mutex);
    if (code != 0) {
        report.stage = VIREO_COMPLETION_QUEUE_CLOSE_UNLOCK;
        report.pthread_error = code;
        result = VIREO_RESULT_INTERNAL;
    }
done:
    if (out_report != NULL) {
        *out_report = report;
    }
    errno = saved_errno;
    return result;
}

/**
 * @brief
 *     初始化未使用的条件变量，外层保持 errno。
 *
 * @param[in] context
 *     不使用，可 NULL。
 * @param[in,out] cond
 *     存活同步存储，符合该 pthread 操作的状态和寿命前置。
 *
 * @return
 *     pthread 直接返回码，不读取 errno 或在适配内重试。
 */
static int standard_cond_init(void *context, pthread_cond_t *cond) {
    (void)context;
    return pthread_cond_init(cond, NULL);
}

/**
 * @brief
 *     允许等待取得原 mutex，外层保持 errno。
 *
 * @param[in] context
 *     不使用，可 NULL。
 * @param[in,out] mutex
 *     存活同步存储，符合该 pthread 操作的状态和寿命前置。
 *
 * @return
 *     pthread 直接返回码，不读取 errno 或在适配内重试。
 */
static int standard_blocking_lock(void *context, pthread_mutex_t *mutex) {
    (void)context;
    return pthread_mutex_lock(mutex);
}

/**
 * @brief
 *     释放原 mutex 等待，返回后重新持锁，外层保持 errno。
 *
 * @param[in] context
 *     不使用，可 NULL。
 * @param[in,out] cond
 *     存活同步存储，符合该 pthread 操作的状态和寿命前置。
 * @param[in,out] mutex
 *     本线程持有的同一非 robust mutex，返回仍持锁。
 *
 * @return
 *     pthread 直接返回码，不读取 errno 或在适配内重试。
 */
static int standard_cond_wait(void *context, pthread_cond_t *cond, pthread_mutex_t *mutex) {
    (void)context;
    return pthread_cond_wait(cond, mutex);
}

/**
 * @brief
 *     领取提交后通知一个空间等待者，外层保持 errno。
 *
 * @param[in] context
 *     不使用，可 NULL。
 * @param[in,out] cond
 *     存活同步存储，符合该 pthread 操作的状态和寿命前置。
 *
 * @return
 *     pthread 直接返回码，不读取 errno 或在适配内重试。
 */
static int standard_cond_signal(void *context, pthread_cond_t *cond) {
    (void)context;
    return pthread_cond_signal(cond);
}

/**
 * @brief
 *     关闭提交后广播所有等待者，外层保持 errno。
 *
 * @param[in] context
 *     不使用，可 NULL。
 * @param[in,out] cond
 *     存活同步存储，符合该 pthread 操作的状态和寿命前置。
 *
 * @return
 *     pthread 直接返回码，不读取 errno 或在适配内重试。
 */
static int standard_cond_broadcast(void *context, pthread_cond_t *cond) {
    (void)context;
    return pthread_cond_broadcast(cond);
}

/**
 * @brief
 *     全部访问结束后销毁条件变量，外层保持 errno。
 *
 * @param[in] context
 *     不使用，可 NULL。
 * @param[in,out] cond
 *     存活同步存储，符合该 pthread 操作的状态和寿命前置。
 *
 * @return
 *     pthread 直接返回码，不读取 errno 或在适配内重试。
 */
static int standard_cond_destroy(void *context, pthread_cond_t *cond) {
    (void)context;
    return pthread_cond_destroy(cond);
}

static vireo_completion_queue_wait_ops_t const standard_wait = {
    NULL, standard_cond_init, standard_blocking_lock, standard_cond_wait,
    standard_cond_signal, standard_cond_broadcast, standard_cond_destroy
};

vireo_result_t vireo_completion_queue_prepare_wait_with_ops(vireo_completion_queue_t *queue,
    vireo_completion_queue_wait_ops_t const *ops) {
    int const saved_errno = errno;
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    if (queue == NULL || ops == NULL || ops->init == NULL || ops->lock == NULL ||
        ops->wait == NULL || ops->signal == NULL || ops->broadcast == NULL ||
        ops->destroy == NULL) {
        goto done;
    }
    if (queue->retiring) {
        result = VIREO_RESULT_CANCELLED;
        goto done;
    }
    if (queue->count != 0 || queue->closed) {
        result = VIREO_RESULT_BUSY;
        goto done;
    }
    if (queue->wait_prepared) {
        result = VIREO_OK;
        goto done;
    }
    int const code = ops->init(ops->context, &queue->cond);
    if (code != 0) {
        result = code == ENOMEM ? VIREO_RESULT_NO_MEMORY : VIREO_RESULT_INTERNAL;
        goto done;
    }
    queue->wait_ops = *ops;
    queue->wait_prepared = true;
    result = VIREO_OK;
done:
    errno = saved_errno;
    return result;
}

vireo_result_t vireo_completion_queue_prepare_wait(vireo_completion_queue_t *queue) {
    return vireo_completion_queue_prepare_wait_with_ops(queue, &standard_wait);
}

vireo_result_t vireo_completion_queue_wait_push(vireo_completion_queue_t *queue,
    vireo_completion_t **owner, vireo_completion_queue_transfer_report_t *out_report) {
    int const saved_errno = errno;
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    vireo_completion_queue_transfer_report_t report = {
        VIREO_COMPLETION_QUEUE_TRANSFER_NONE, false, 0
    };
    if (queue == NULL || owner == NULL || out_report == NULL) {
        goto done;
    }
    if (*owner == NULL) {
        result = VIREO_RESULT_NOT_FOUND;
        goto done;
    }
    if (queue->retiring) {
        result = VIREO_RESULT_CANCELLED;
        goto done;
    }
    if (!queue->wait_prepared) {
        result = VIREO_RESULT_NOT_FOUND;
        goto done;
    }
    int code = queue->wait_ops.lock(queue->wait_ops.context, &queue->mutex);
    if (code != 0) {
        report.stage = VIREO_COMPLETION_QUEUE_TRANSFER_LOCK;
        report.pthread_error = code;
        result = VIREO_RESULT_INTERNAL;
        goto done;
    }
    while (queue->count == queue->capacity && !queue->closed) {
        code = queue->wait_ops.wait(queue->wait_ops.context, &queue->cond, &queue->mutex);
        if (code != 0) {
            report.stage = VIREO_COMPLETION_QUEUE_TRANSFER_WAIT;
            report.pthread_error = code;
            result = VIREO_RESULT_INTERNAL;
            goto unlock;
        }
    }
    if (queue->closed) {
        result = VIREO_RESULT_CANCELLED;
        record_rejection(&queue->closed_rejections, &queue->rejection_count_saturated);
    } else {
        queue->slots[queue->tail] = *owner;
        *owner = NULL;
        queue->tail = queue->tail == queue->capacity - 1 ? 0 : queue->tail + 1;
        ++queue->count;
        record_high_watermark(queue);
        report.transferred = true;
        result = VIREO_OK;
    }
unlock:
    code = queue->sync.unlock(queue->sync.context, &queue->mutex);
    if (code != 0) {
        report.stage = VIREO_COMPLETION_QUEUE_TRANSFER_UNLOCK;
        report.pthread_error = code;
        result = VIREO_RESULT_INTERNAL;
    }
done:
    if (out_report != NULL) {
        *out_report = report;
    }
    errno = saved_errno;
    return result;
}
