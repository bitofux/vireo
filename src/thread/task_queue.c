/*
 * PROJECT : VIREO
 * FILE    : task_queue.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-11
 * BRIEF   : 受检固定容器与mutex内唯一task交接
 */

#include "task_queue_internal.h"

#include <vireo/base/checked.h>

#include <errno.h>
#include <stdlib.h>

/**
 * @brief
 *     标准申请适配，返回独占容器原块。
 *
 * @param[in] context
 *     本适配不使用，允许NULL。
 * @param[in] bytes
 *     已受检且符合预算的正申请字节。
 *
 * @return
 *     新足量正确对齐的原块或NULL；errno由外层恢复。
 */
static void *standard_allocate(void *context, size_t bytes) {
    (void)context;
    return malloc(bytes);
}

/**
 * @brief
 *     配对释放无在途访问的标准原块。
 *
 * @param[in] context
 *     本适配不使用，允许NULL。
 * @param[in] allocation
 *     标准分配返回的原块，caller已结束全部对象访问。
 *
 * @note
 *     无失败返回，不清理task或context，errno由外层恢复。
 */
static void standard_deallocate(void *context, void *allocation) {
    (void)context;
    free(allocation);
}

/**
 * @brief
 *     初始化尚未发布的mutex，不使用自定义属性。
 *
 * @param[in] context
 *     标准适配不使用，允许NULL。
 * @param[out] mutex
 *     必需尚未初始化的队列内存，借至返回。
 *
 * @return
 *     pthread直接错误；成功后须在无访问时配对销毁。
 */
static int standard_mutex_init(void *context, pthread_mutex_t *mutex) {
    (void)context;
    return pthread_mutex_init(mutex, NULL);
}

/**
 * @brief
 *     一次尝试取得存活mutex，不内部循环重试。
 *
 * @param[in] context
 *     标准适配不使用，允许NULL。
 * @param[in,out] mutex
 *     必需已初始化对象，借至返回，成功后当前线程须解锁。
 *
 * @return
 *     pthread直接错误；0取得锁，EBUSY未取得锁。
 */
static int standard_mutex_try_lock(void *context, pthread_mutex_t *mutex) {
    (void)context;
    return pthread_mutex_trylock(mutex);
}

/**
 * @brief
 *     释放当前线程取得的mutex，配对try或阻塞加锁。
 *
 * @param[in] context
 *     标准适配不使用，允许NULL。
 * @param[in,out] mutex
 *     必需由当前线程持有，借至返回。
 *
 * @return
 *     pthread直接错误；不撤销临界区内已提交的状态。
 */
static int standard_mutex_unlock(void *context, pthread_mutex_t *mutex) {
    (void)context;
    return pthread_mutex_unlock(mutex);
}

/**
 * @brief
 *     外部排除全部访问后销毁空队列的mutex。
 *
 * @param[in] context
 *     标准适配不使用，允许NULL。
 * @param[in,out] mutex
 *     必需已初始化且无任何在途访问或持有者，借至返回。
 *
 * @return
 *     pthread直接错误；非0不得释放队列原块。
 */
static int standard_mutex_destroy(void *context, pthread_mutex_t *mutex) {
    (void)context;
    return pthread_mutex_destroy(mutex);
}

static vireo_task_queue_sync_ops_t const standard_sync = {
    NULL, standard_mutex_init, standard_mutex_try_lock, standard_mutex_unlock,
    standard_mutex_destroy
};

vireo_result_t vireo_task_queue_create_with_ops(vireo_task_queue_options_t const *options,
    vireo_task_queue_allocator_t const *allocator, vireo_task_queue_sync_ops_t const *sync,
    vireo_task_queue_t **out_queue) {
    int const saved_errno = errno;
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    if (out_queue == NULL || *out_queue != NULL || options == NULL ||
        options->capacity == 0 || options->max_memory_bytes == 0 || allocator == NULL ||
        allocator->allocate == NULL || allocator->deallocate == NULL || sync == NULL ||
        sync->init == NULL || sync->try_lock == NULL || sync->unlock == NULL ||
        sync->destroy == NULL) {
        goto done;
    }
    vireo_task_queue_options_t const snapshot = *options;
    size_t slots_bytes = 0;
    result = vireo_checked_size_mul(snapshot.capacity, sizeof(vireo_task_t *), &slots_bytes);
    if (result != VIREO_OK) {
        goto done;
    }
    size_t bytes = 0;
    result = vireo_checked_size_add(sizeof(vireo_task_queue_t), slots_bytes, &bytes);
    if (result != VIREO_OK) {
        goto done;
    }
    if (snapshot.capacity > VIREO_TASK_QUEUE_MAX_CAPACITY ||
        snapshot.max_memory_bytes > VIREO_TASK_QUEUE_MAX_ALLOCATION_BYTES ||
        bytes > snapshot.max_memory_bytes) {
        result = VIREO_RESULT_RANGE;
        goto done;
    }
    vireo_task_queue_t *queue = allocator->allocate(allocator->context, bytes);
    if (queue == NULL) {
        result = VIREO_RESULT_NO_MEMORY;
        goto done;
    }
    queue->capacity = snapshot.capacity;
    queue->count = 0;
    queue->high_watermark = 0;
    queue->full_rejections = 0;
    queue->closed_rejections = 0;
    queue->rejection_count_saturated = false;
    queue->allocated_bytes = bytes;
    queue->max_memory_bytes = snapshot.max_memory_bytes;
    queue->allocator = *allocator;
    queue->sync = *sync;
    queue->head = 0;
    queue->tail = 0;
    queue->state = VIREO_TASK_QUEUE_OPEN;
    queue->wait_prepared = false;
    queue->retiring = false;
    /* 逐项赋NULL，不假定全比特零就是本平台/未来平台的空指针表示。 */
    for (size_t i = 0; i < snapshot.capacity; ++i) {
        queue->slots[i] = NULL;
    }
    int const code = queue->sync.init(queue->sync.context, &queue->mutex);
    if (code != 0) {
        queue->allocator.deallocate(queue->allocator.context, queue);
        result = code == ENOMEM ? VIREO_RESULT_NO_MEMORY : VIREO_RESULT_INTERNAL;
        goto done;
    }
    *out_queue = queue;
    result = VIREO_OK;
done:
    errno = saved_errno;
    return result;
}

vireo_result_t vireo_task_queue_create_with_allocator(vireo_task_queue_options_t const *options,
    vireo_task_queue_allocator_t const *allocator, vireo_task_queue_t **out_queue) {
    return vireo_task_queue_create_with_ops(options, allocator, &standard_sync, out_queue);
}

vireo_result_t vireo_task_queue_create(vireo_task_queue_options_t const *options,
                                       vireo_task_queue_t **out_queue) {
    vireo_task_queue_allocator_t const allocator = {NULL, standard_allocate, standard_deallocate};
    return vireo_task_queue_create_with_allocator(options, &allocator, out_queue);
}

vireo_result_t vireo_task_queue_inspect(vireo_task_queue_t const *queue,
                                        vireo_task_queue_info_t *out_info) {
    int const saved_errno = errno;
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    if (queue == NULL || out_info == NULL) {
        goto done;
    }
    if (queue->retiring) {
        result = VIREO_RESULT_CANCELLED;
        goto done;
    }
    /* 公开const表示逻辑只读；create产生可变原块，内部同步状态仍需更新。 */
    vireo_task_queue_t *mutable_queue = (vireo_task_queue_t *)queue;
    int code = queue->sync.try_lock(queue->sync.context, &mutable_queue->mutex);
    if (code != 0) {
        result = code == EBUSY ? VIREO_RESULT_BUSY : VIREO_RESULT_INTERNAL;
        goto done;
    }
    vireo_task_queue_info_t const value = {
        queue->capacity, queue->count, queue->allocated_bytes, queue->max_memory_bytes,
        queue->state, queue->wait_prepared
    };
    code = queue->sync.unlock(queue->sync.context, &mutable_queue->mutex);
    if (code != 0) {
        result = VIREO_RESULT_INTERNAL;
        goto done;
    }
    *out_info = value;
    result = VIREO_OK;
done:
    errno = saved_errno;
    return result;
}

vireo_result_t vireo_task_queue_inspect_metrics(vireo_task_queue_t const *queue,
    vireo_task_queue_metrics_t *out_metrics) {
    int const saved_errno = errno;
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    if (queue == NULL || out_metrics == NULL) {
        goto done;
    }
    if (queue->retiring) {
        result = VIREO_RESULT_CANCELLED;
        goto done;
    }
    /* 原块可变，const仅表示逻辑观测；与交接共用mutex形成同一时点快照。 */
    vireo_task_queue_t *mutable_queue = (vireo_task_queue_t *)queue;
    int code = queue->sync.try_lock(queue->sync.context, &mutable_queue->mutex);
    if (code != 0) {
        result = code == EBUSY ? VIREO_RESULT_BUSY : VIREO_RESULT_INTERNAL;
        goto done;
    }
    vireo_task_queue_metrics_t const value = {
        queue->count, queue->high_watermark, queue->full_rejections,
        queue->closed_rejections, queue->rejection_count_saturated
    };
    code = queue->sync.unlock(queue->sync.context, &mutable_queue->mutex);
    if (code != 0) {
        result = VIREO_RESULT_INTERNAL;
        goto done;
    }
    *out_metrics = value;
    result = VIREO_OK;
done:
    errno = saved_errno;
    return result;
}

vireo_result_t vireo_task_queue_destroy(vireo_task_queue_t **owner) {
    int const saved_errno = errno;
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    if (owner == NULL) {
        goto done;
    }
    if (*owner != NULL) {
        /* 此读依赖caller已结束全部访问；并非“拿锁就可以并发销毁”。 */
        if ((*owner)->count != 0) {
            result = VIREO_RESULT_BUSY;
            goto done;
        }
        if ((*owner)->wait_prepared) {
            int const cond_code = (*owner)->wait_ops.destroy((*owner)->wait_ops.context,
                &(*owner)->cond);
            if (cond_code != 0) {
                result = cond_code == EBUSY ? VIREO_RESULT_BUSY : VIREO_RESULT_INTERNAL;
                goto done;
            }
            (*owner)->wait_prepared = false;
            (*owner)->retiring = true;
        }
        int const code = (*owner)->sync.destroy((*owner)->sync.context, &(*owner)->mutex);
        if (code != 0) {
            result = code == EBUSY ? VIREO_RESULT_BUSY : VIREO_RESULT_INTERNAL;
            goto done;
        }
        vireo_task_queue_allocator_t const allocator = (*owner)->allocator;
        allocator.deallocate(allocator.context, *owner);
    }
    *owner = NULL;
    result = VIREO_OK;
done:
    errno = saved_errno;
    return result;
}

/**
 * @brief
 *     私有交接角色，区分普通领取与关闭后交还，不对下游暴露。
 */
typedef enum transfer_kind {
    TRANSFER_PUSH, /**< 只在OPEN提交。 */
    TRANSFER_POP, /**< OPEN或非空DRAIN普通领取。 */
    TRANSFER_TAKE_CANCELLED /**< 只在CANCEL_PENDING交还。 */
} transfer_kind_t;

/**
 * @brief
 *     受检累计一次业务拒绝，保持饱和下界，不影响交接返回。
 *
 * @param[in,out] counter
 *     必需队列内对应累计地址，caller持有同一queue的mutex。
 * @param[in,out] saturated
 *     必需同队列受保护的粘性标志地址，只允许false变true。
 *
 * @note
 *     小于MAX才加一，故不会回绕；达到MAX仍精确，下次才标记失去精确性。
 *     私有有效地址不重叠，无失败或资源操作，不读取/修改errno。
 */
static void count_rejection(uint64_t *counter, bool *saturated) {
    if (*counter < UINT64_MAX) {
        ++*counter;
    } else {
        *saturated = true;
    }
}

/**
 * @brief
 *     在同一mutex内完成提交或领取，按真实commit发布进度。
 *
 * @param[in,out] queue
 *     存活对象短借，内部同步，禁止并发销毁。
 * @param[in,out] owner
 *     合法独占task owner；push非空，pop为空，不与资源/report/errno重叠。
 * @param[in] kind
 *     有效私有角色；按状态决定提交/普通领取/交还，不执行task或payload操作。
 * @param[out] report
 *     独立合法必需报告地址，只借返回；可写时每路径覆盖。
 *
 * @return
 *     公开try分类；解锁异常优先报告INTERNAL，保留已完成的交接。
 *
 * @note
 *     索引仅在0..capacity-1移动，count在限额内更新，不累计可溢出序号。
 *     不内部等待或重试，无申请；全部路径保持errno。
 */
static vireo_result_t transfer(vireo_task_queue_t *queue, vireo_task_t **owner, transfer_kind_t kind,
    vireo_task_queue_transfer_report_t *report) {
    int const saved_errno = errno;
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    vireo_task_queue_transfer_report_t value = {VIREO_TASK_QUEUE_STAGE_NONE, false, 0};
    if (report == NULL || queue == NULL || owner == NULL ||
        (kind != TRANSFER_PUSH && *owner != NULL)) {
        goto done;
    }
    if (kind == TRANSFER_PUSH && *owner == NULL) {
        result = VIREO_RESULT_NOT_FOUND;
        goto done;
    }
    if (queue->retiring) {
        result = VIREO_RESULT_CANCELLED;
        goto done;
    }
    int code = queue->sync.try_lock(queue->sync.context, &queue->mutex);
    if (code != 0) {
        value.stage = VIREO_TASK_QUEUE_STAGE_LOCK;
        value.pthread_error = code;
        result = code == EBUSY ? VIREO_RESULT_BUSY : VIREO_RESULT_INTERNAL;
        goto done;
    }
    if (kind == TRANSFER_PUSH) {
        if (queue->state != VIREO_TASK_QUEUE_OPEN) {
            count_rejection(&queue->closed_rejections, &queue->rejection_count_saturated);
            result = VIREO_RESULT_CANCELLED;
        } else if (queue->count == queue->capacity) {
            count_rejection(&queue->full_rejections, &queue->rejection_count_saturated);
            result = VIREO_RESULT_BUSY;
        } else {
            queue->slots[queue->tail] = *owner;
            *owner = NULL;
            queue->tail = queue->tail == queue->capacity - 1 ? 0 : queue->tail + 1;
            ++queue->count;
            if (queue->count > queue->high_watermark) {
                queue->high_watermark = queue->count;
            }
            value.transferred = true;
            result = VIREO_OK;
        }
    } else if (kind == TRANSFER_TAKE_CANCELLED &&
               queue->state != VIREO_TASK_QUEUE_CANCEL_PENDING) {
        result = VIREO_RESULT_BUSY;
    } else if (kind == TRANSFER_POP && queue->state == VIREO_TASK_QUEUE_CANCEL_PENDING) {
        result = VIREO_RESULT_CANCELLED;
    } else if (queue->count == 0) {
        result = kind == TRANSFER_POP && queue->state == VIREO_TASK_QUEUE_DRAIN ?
            VIREO_RESULT_CANCELLED : VIREO_RESULT_NOT_FOUND;
    } else {
        *owner = queue->slots[queue->head];
        queue->slots[queue->head] = NULL;
        queue->head = queue->head == queue->capacity - 1 ? 0 : queue->head + 1;
        --queue->count;
        value.transferred = true;
        result = VIREO_OK;
    }
    if (kind == TRANSFER_PUSH && value.transferred && queue->wait_prepared) {
        code = queue->wait_ops.signal(queue->wait_ops.context, &queue->cond);
        if (code != 0) {
            value.stage = VIREO_TASK_QUEUE_STAGE_WAKE;
            value.pthread_error = code;
            result = VIREO_RESULT_INTERNAL;
        }
    }
    code = queue->sync.unlock(queue->sync.context, &queue->mutex);
    if (code != 0) {
        value.stage = VIREO_TASK_QUEUE_STAGE_UNLOCK;
        value.pthread_error = code;
        result = VIREO_RESULT_INTERNAL;
    }
done:
    if (report != NULL) {
        *report = value;
    }
    errno = saved_errno;
    return result;
}

vireo_result_t vireo_task_queue_try_push(vireo_task_queue_t *queue, vireo_task_t **inout_task,
    vireo_task_queue_transfer_report_t *report) {
    return transfer(queue, inout_task, TRANSFER_PUSH, report);
}

vireo_result_t vireo_task_queue_try_pop(vireo_task_queue_t *queue, vireo_task_t **out_task,
    vireo_task_queue_transfer_report_t *report) {
    return transfer(queue, out_task, TRANSFER_POP, report);
}

vireo_result_t vireo_task_queue_try_take_cancelled(vireo_task_queue_t *queue,
    vireo_task_t **out_task, vireo_task_queue_transfer_report_t *report) {
    return transfer(queue, out_task, TRANSFER_TAKE_CANCELLED, report);
}

vireo_result_t vireo_task_queue_close(vireo_task_queue_t *queue, vireo_task_queue_state_t mode,
    vireo_task_queue_close_report_t *report) {
    int const saved_errno = errno;
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    vireo_task_queue_close_report_t value = {VIREO_TASK_QUEUE_STAGE_NONE, false, 0};
    if (report == NULL || queue == NULL ||
        (mode != VIREO_TASK_QUEUE_DRAIN && mode != VIREO_TASK_QUEUE_CANCEL_PENDING)) {
        goto done;
    }
    if (queue->retiring) {
        result = VIREO_RESULT_CANCELLED;
        goto done;
    }
    int code = queue->sync.try_lock(queue->sync.context, &queue->mutex);
    if (code != 0) {
        value.stage = VIREO_TASK_QUEUE_STAGE_LOCK;
        value.pthread_error = code;
        result = code == EBUSY ? VIREO_RESULT_BUSY : VIREO_RESULT_INTERNAL;
        goto done;
    }
    if (queue->state == VIREO_TASK_QUEUE_OPEN) {
        queue->state = mode;
        value.changed = true;
        result = VIREO_OK;
    } else {
        result = queue->state == mode ? VIREO_OK : VIREO_RESULT_BUSY;
    }
    if (result == VIREO_OK && queue->wait_prepared) {
        code = queue->wait_ops.broadcast(queue->wait_ops.context, &queue->cond);
        if (code != 0) {
            value.stage = VIREO_TASK_QUEUE_STAGE_WAKE;
            value.pthread_error = code;
            result = VIREO_RESULT_INTERNAL;
        }
    }
    code = queue->sync.unlock(queue->sync.context, &queue->mutex);
    if (code != 0) {
        value.stage = VIREO_TASK_QUEUE_STAGE_UNLOCK;
        value.pthread_error = code;
        result = VIREO_RESULT_INTERNAL;
    }
done:
    if (report != NULL) {
        *report = value;
    }
    errno = saved_errno;
    return result;
}

/**
 * @brief
 *     初始化嵌入cond；默认属性，不需要时钟选择。
 *
 * @param[in] context
 *     未使用，可NULL。
 * @param[out] cond
 *     必需未初始化资源，短借至返回。
 *
 * @return
 *     pthread直接错误，非0不发布资源。
 */
static int standard_cond_init(void *context, pthread_cond_t *cond) {
    (void)context;
    return pthread_cond_init(cond, NULL);
}

/**
 * @brief
 *     worker阻塞取得原非robust mutex。
 *
 * @param[in] context
 *     未使用，可NULL。
 * @param[in,out] mutex
 *     必需存活原mutex，成功由本线程持有。
 *
 * @return
 *     pthread直接错误，失败不取得锁。
 */
static int standard_mutex_lock(void *context, pthread_mutex_t *mutex) {
    (void)context;
    return pthread_mutex_lock(mutex);
}

/**
 * @brief
 *     原子释放mutex等待cond，返回前重获同一mutex。
 *
 * @param[in] context
 *     未使用，可NULL。
 * @param[in,out] cond
 *     存活cond，须与原mutex配对。
 * @param[in,out] mutex
 *     本线程持有原mutex，返回仍持有。
 *
 * @return
 *     pthread直接错误；caller循环检查谓词且保证POSIX取消禁用。
 */
static int standard_cond_wait(void *context, pthread_cond_t *cond, pthread_mutex_t *mutex) {
    (void)context;
    return pthread_cond_wait(cond, mutex);
}

/**
 * @brief
 *     提交后通知当前等待者，不保存通知额度。
 *
 * @param[in] context
 *     未使用，可NULL。
 * @param[in,out] cond
 *     必需存活cond，调用方持原mutex。
 *
 * @return
 *     pthread直接错误；失败不撤销提交。
 */
static int standard_cond_signal(void *context, pthread_cond_t *cond) {
    (void)context;
    return pthread_cond_signal(cond);
}

/**
 * @brief
 *     关闭后广播当前等待者，各自重检状态。
 *
 * @param[in] context
 *     未使用，可NULL。
 * @param[in,out] cond
 *     必需存活cond，调用方持原mutex。
 *
 * @return
 *     pthread直接错误；失败不撤销关闭。
 */
static int standard_cond_broadcast(void *context, pthread_cond_t *cond) {
    (void)context;
    return pthread_cond_broadcast(cond);
}

/**
 * @brief
 *     全部访问结束后销毁cond，不重建。
 *
 * @param[in] context
 *     未使用，可NULL。
 * @param[in,out] cond
 *     无等待者或在途访问的存活cond。
 *
 * @return
 *     pthread直接错误；成功后禁止再次访问该cond。
 */
static int standard_cond_destroy(void *context, pthread_cond_t *cond) {
    (void)context;
    return pthread_cond_destroy(cond);
}

static vireo_task_queue_wait_ops_t const standard_wait = {
    NULL, standard_cond_init, standard_mutex_lock, standard_cond_wait,
    standard_cond_signal, standard_cond_broadcast, standard_cond_destroy
};

vireo_result_t vireo_task_queue_prepare_wait_with_ops(vireo_task_queue_t *queue,
    vireo_task_queue_wait_ops_t const *ops) {
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
    if (queue->count != 0 || queue->state != VIREO_TASK_QUEUE_OPEN) {
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

vireo_result_t vireo_task_queue_prepare_wait(vireo_task_queue_t *queue) {
    return vireo_task_queue_prepare_wait_with_ops(queue, &standard_wait);
}

vireo_result_t vireo_task_queue_wait_pop(vireo_task_queue_t *queue, vireo_task_t **out_task,
    vireo_task_queue_transfer_report_t *report) {
    int const saved_errno = errno;
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    vireo_task_queue_transfer_report_t value = {VIREO_TASK_QUEUE_STAGE_NONE, false, 0};
    if (queue == NULL || out_task == NULL || report == NULL || *out_task != NULL) {
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
        value.stage = VIREO_TASK_QUEUE_STAGE_LOCK;
        value.pthread_error = code;
        result = VIREO_RESULT_INTERNAL;
        goto done;
    }
    while (queue->count == 0 && queue->state == VIREO_TASK_QUEUE_OPEN) {
        code = queue->wait_ops.wait(queue->wait_ops.context, &queue->cond, &queue->mutex);
        if (code != 0) {
            value.stage = VIREO_TASK_QUEUE_STAGE_WAIT;
            value.pthread_error = code;
            result = VIREO_RESULT_INTERNAL;
            goto unlock;
        }
    }
    if (queue->state == VIREO_TASK_QUEUE_CANCEL_PENDING || queue->count == 0) {
        result = VIREO_RESULT_CANCELLED;
    } else {
        *out_task = queue->slots[queue->head];
        queue->slots[queue->head] = NULL;
        queue->head = queue->head == queue->capacity - 1 ? 0 : queue->head + 1;
        --queue->count;
        value.transferred = true;
        result = VIREO_OK;
    }
unlock:
    code = queue->sync.unlock(queue->sync.context, &queue->mutex);
    if (code != 0) {
        value.stage = VIREO_TASK_QUEUE_STAGE_UNLOCK;
        value.pthread_error = code;
        result = VIREO_RESULT_INTERNAL;
    }
done:
    if (report != NULL) {
        *report = value;
    }
    errno = saved_errno;
    return result;
}
