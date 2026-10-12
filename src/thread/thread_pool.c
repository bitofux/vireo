/*
 * PROJECT : VIREO
 * FILE    : thread_pool.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-12
 * BRIEF   : 受检固定槽资源、显式任务执行与真实部分失败
 */

#include "thread_pool_internal.h"

#include <vireo/base/checked.h>

#include <errno.h>
#include <stdlib.h>

/**
 * @brief
 *     申请新独占块，errno 由外层恢复。
 *
 * @param[in] context
 *     标准适配未使用，允许 NULL。
 * @param[in] bytes
 *     已受检的正容器申请字节数。
 *
 * @return
 *     足量正确对齐的块或 NULL。
 */
static void *standard_allocate(void *context, size_t bytes) {
    (void)context;
    return malloc(bytes);
}

/**
 * @brief
 *     配对释放整个原块，不消费其他资源。
 *
 * @param[in] context
 *     标准适配未使用，允许 NULL。
 * @param[in] allocation
 *     标准适配返回的原块，全部访问已结束。
 *
 * @note
 *     free 无失败返回；errno 由外层恢复。
 */
static void standard_deallocate(void *context, void *allocation) {
    (void)context;
    free(allocation);
}

vireo_result_t vireo_thread_pool_create_with_allocator(
    vireo_thread_pool_options_t const *options,
    vireo_thread_pool_allocator_t const *allocator, vireo_thread_pool_t **out_pool) {
    int const saved_errno = errno;
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    if (options == NULL || out_pool == NULL || *out_pool != NULL ||
        options->worker_count == 0 || options->max_memory_bytes == 0 ||
        allocator == NULL || allocator->allocate == NULL || allocator->deallocate == NULL) {
        goto done;
    }
    size_t slot_bytes = 0;
    size_t total_bytes = 0;
    result = vireo_checked_size_mul(options->worker_count,
                                    sizeof(vireo_thread_pool_worker_slot_t), &slot_bytes);
    if (result != VIREO_OK) {
        goto done;
    }
    result = vireo_checked_size_add(sizeof(vireo_thread_pool_t), slot_bytes, &total_bytes);
    if (result != VIREO_OK) {
        goto done;
    }
    if (options->worker_count > VIREO_THREAD_POOL_MAX_WORKERS ||
        options->max_memory_bytes > VIREO_THREAD_POOL_MAX_ALLOCATION_BYTES ||
        total_bytes > options->max_memory_bytes) {
        result = VIREO_RESULT_RANGE;
        goto done;
    }
    vireo_thread_pool_t *pool = allocator->allocate(allocator->context, total_bytes);
    if (pool == NULL) {
        result = VIREO_RESULT_NO_MEMORY;
        goto done;
    }
    pool->worker_count = options->worker_count;
    pool->allocated_bytes = total_bytes;
    pool->max_memory_bytes = options->max_memory_bytes;
    pool->allocator = *allocator;
    pool->configuration = (vireo_thread_pool_configuration_t){NULL, NULL, NULL};
    pool->configured = false;
    pool->runtime = *vireo_thread_pool_standard_runtime();
    pool->mutex_initialized = false;
    pool->condition_initialized = false;
    pool->retiring = false;
    pool->start_attempted = false;
    pool->stop_requested = false;
    pool->execution_enabled = false;
    pool->created_count = 0;
    pool->joined_count = 0;
    for (size_t i = 0; i < pool->worker_count; ++i) {
        pool->workers[i].thread_created = false;
        pool->workers[i].thread_joined = false;
        pool->workers[i].pool = pool;
        pool->workers[i].worker_stage = VIREO_THREAD_POOL_STAGE_NONE;
        pool->workers[i].worker_pthread_error = 0;
        pool->workers[i].worker_result = VIREO_OK;
        pool->workers[i].worker_queue_report = (vireo_task_queue_transfer_report_t){0};
    }
    /* 未创建 pthread，thread 无有效值；只初始化可以合法观察的未创建标记。 */
    *out_pool = pool;
    result = VIREO_OK;
done:
    errno = saved_errno;
    return result;
}

vireo_result_t vireo_thread_pool_create(vireo_thread_pool_options_t const *options,
                                        vireo_thread_pool_t **out_pool) {
    vireo_thread_pool_allocator_t const allocator = {
        NULL, standard_allocate, standard_deallocate
    };
    return vireo_thread_pool_create_with_allocator(options, &allocator, out_pool);
}

/**
 * @brief
 *     只调用依赖的公开 inspect，不取得或修改 queue 拥有权。
 *
 * @param[in] context
 *     标准适配忽略，允许 NULL。
 * @param[in] queue
 *     存活队列，caller 排除其他访问，只借至返回。
 * @param[out] out_info
 *     必需独立输出，成功为公开六字段快照。
 *
 * @return
 *     公开 queue_inspect 原结果，失败保持输出。
 */
static vireo_result_t standard_queue_inspect(void *context, vireo_task_queue_t const *queue,
                                            vireo_task_queue_info_t *out_info) {
    (void)context;
    return vireo_task_queue_inspect(queue, out_info);
}

vireo_result_t vireo_thread_pool_configure_with_inspector(vireo_thread_pool_t *pool,
    vireo_thread_pool_configuration_t const *configuration,
    vireo_thread_pool_queue_inspector_t const *inspector,
    vireo_thread_pool_configure_stage_t *stage) {
    int const saved_errno = errno;
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    if (stage != NULL) {
        *stage = VIREO_THREAD_POOL_CONFIGURE_STAGE_NONE;
    }
    if (pool == NULL || configuration == NULL || configuration->queue == NULL ||
        configuration->execute == NULL || inspector == NULL || inspector->inspect == NULL) {
        goto done;
    }
    if (pool->retiring) {
        result = VIREO_RESULT_CANCELLED;
        goto done;
    }
    if (pool->configured) {
        result = VIREO_RESULT_BUSY;
        goto done;
    }
    if (stage != NULL) {
        *stage = VIREO_THREAD_POOL_CONFIGURE_STAGE_CHECK_QUEUE;
    }
    vireo_task_queue_info_t info;
    result = inspector->inspect(inspector->context, configuration->queue, &info);
    if (result != VIREO_OK) {
        goto done;
    }
    if (info.state != VIREO_TASK_QUEUE_OPEN) {
        result = VIREO_RESULT_CANCELLED;
        goto done;
    }
    if (!info.wait_prepared) {
        result = VIREO_RESULT_NOT_FOUND;
        goto done;
    }
    if (info.count != 0) {
        result = VIREO_RESULT_BUSY;
        goto done;
    }
    /* 外部排除访问；全部可失败检查结束后发布关联，没有跨线程原子提交承诺。 */
    pool->configuration = *configuration;
    pool->configured = true;
    if (stage != NULL) {
        *stage = VIREO_THREAD_POOL_CONFIGURE_STAGE_NONE;
    }
done:
    errno = saved_errno;
    return result;
}

vireo_result_t vireo_thread_pool_configure(vireo_thread_pool_t *pool,
    vireo_thread_pool_configuration_t const *configuration,
    vireo_thread_pool_configure_stage_t *stage) {
    vireo_thread_pool_queue_inspector_t const inspector = {NULL, standard_queue_inspect};
    return vireo_thread_pool_configure_with_inspector(pool, configuration, &inspector, stage);
}

vireo_result_t vireo_thread_pool_inspect(vireo_thread_pool_t const *pool,
                                         vireo_thread_pool_info_t *out_info) {
    int const saved_errno = errno;
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    if (pool != NULL && out_info != NULL) {
        if (pool->retiring) {
            result = VIREO_RESULT_CANCELLED;
        } else {
            vireo_thread_pool_info_t const value = {
                pool->worker_count, pool->allocated_bytes, pool->max_memory_bytes,
                pool->configured, pool->start_attempted, pool->stop_requested,
                pool->created_count, pool->joined_count, pool->execution_enabled
            };
            *out_info = value;
            result = VIREO_OK;
        }
    }
    errno = saved_errno;
    return result;
}

vireo_result_t vireo_thread_pool_destroy(vireo_thread_pool_t **owner) {
    int const saved_errno = errno;
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    if (owner == NULL) {
        goto done;
    }
    if (*owner == NULL) {
        result = VIREO_OK;
        goto done;
    }
    vireo_thread_pool_t *pool = *owner;
    if (pool->joined_count != pool->created_count) {
        result = VIREO_RESULT_BUSY;
        goto done;
    }
    if (pool->condition_initialized) {
        int const error = pool->runtime.condition_destroy(pool->runtime.context, &pool->condition);
        if (error != 0) {
            result = error == EBUSY ? VIREO_RESULT_BUSY : VIREO_RESULT_INTERNAL;
            goto done;
        }
        pool->condition_initialized = false;
        pool->retiring = true;
    }
    if (pool->mutex_initialized) {
        int const error = pool->runtime.mutex_destroy(pool->runtime.context, &pool->mutex);
        if (error != 0) {
            result = error == EBUSY ? VIREO_RESULT_BUSY : VIREO_RESULT_INTERNAL;
            goto done;
        }
        pool->mutex_initialized = false;
    }
    vireo_thread_pool_allocator_t const allocator = pool->allocator;
    allocator.deallocate(allocator.context, pool);
    *owner = NULL;
    result = VIREO_OK;
done:
    errno = saved_errno;
    return result;
}

/**
 * @brief
 *     初始化默认非 robust mutex，不保存地址。
 *
 * @param[in] context
 *     标准适配忽略，允许 NULL。
 * @param[in,out] mutex
 *     必需独立存活的同步存储，满足对应 POSIX 生命周期前置。
 *
 * @return
 *     0 或 pthread 直接错误数，外层恢复 errno。
 */
static int standard_mutex_init(void *context, pthread_mutex_t *mutex) {
    (void)context;
    return pthread_mutex_init(mutex, NULL);
}

/**
 * @brief
 *     销毁已无人使用的 mutex，不保存地址。
 *
 * @param[in] context
 *     标准适配忽略，允许 NULL。
 * @param[in,out] mutex
 *     必需独立存活的同步存储，满足对应 POSIX 生命周期前置。
 *
 * @return
 *     0 或 pthread 直接错误数，外层恢复 errno。
 */
static int standard_mutex_destroy(void *context, pthread_mutex_t *mutex) {
    (void)context;
    return pthread_mutex_destroy(mutex);
}

/**
 * @brief
 *     取得 worker 停止谓词的互斥锁，不保存地址。
 *
 * @param[in] context
 *     标准适配忽略，允许 NULL。
 * @param[in,out] mutex
 *     必需独立存活的同步存储，满足对应 POSIX 生命周期前置。
 *
 * @return
 *     0 或 pthread 直接错误数，外层恢复 errno。
 */
static int standard_mutex_lock(void *context, pthread_mutex_t *mutex) {
    (void)context;
    return pthread_mutex_lock(mutex);
}

/**
 * @brief
 *     释放当前线程持有的互斥锁，不保存地址。
 *
 * @param[in] context
 *     标准适配忽略，允许 NULL。
 * @param[in,out] mutex
 *     必需独立存活的同步存储，满足对应 POSIX 生命周期前置。
 *
 * @return
 *     0 或 pthread 直接错误数，外层恢复 errno。
 */
static int standard_mutex_unlock(void *context, pthread_mutex_t *mutex) {
    (void)context;
    return pthread_mutex_unlock(mutex);
}

/**
 * @brief
 *     初始化默认条件变量，不保存地址。
 *
 * @param[in] context
 *     标准适配忽略，允许 NULL。
 * @param[in,out] condition
 *     必需独立存活的同步存储，满足对应 POSIX 生命周期前置。
 *
 * @return
 *     0 或 pthread 直接错误数，外层恢复 errno。
 */
static int standard_condition_init(void *context, pthread_cond_t *condition) {
    (void)context;
    return pthread_cond_init(condition, NULL);
}

/**
 * @brief
 *     销毁无人等待的条件变量，不保存地址。
 *
 * @param[in] context
 *     标准适配忽略，允许 NULL。
 * @param[in,out] condition
 *     必需独立存活的同步存储，满足对应 POSIX 生命周期前置。
 *
 * @return
 *     0 或 pthread 直接错误数，外层恢复 errno。
 */
static int standard_condition_destroy(void *context, pthread_cond_t *condition) {
    (void)context;
    return pthread_cond_destroy(condition);
}

/**
 * @brief
 *     广播停止谓词可能已经改变，不保存地址。
 *
 * @param[in] context
 *     标准适配忽略，允许 NULL。
 * @param[in,out] condition
 *     必需独立存活的同步存储，满足对应 POSIX 生命周期前置。
 *
 * @return
 *     0 或 pthread 直接错误数，外层恢复 errno。
 */
static int standard_condition_broadcast(void *context, pthread_cond_t *condition) {
    (void)context;
    return pthread_cond_broadcast(condition);
}

/**
 * @brief
 *     原子释放锁并停驻，返回后以同一 mutex 重检谓词。
 *
 * @param[in] context
 *     标准适配忽略，允许 NULL。
 * @param[in,out] condition
 *     必需已初始化条件变量。
 * @param[in,out] mutex
 *     当前线程持有的非 robust mutex，返回时重新持有。
 *
 * @return
 *     0 或 pthread 直接错误，不能用通知次数替代谓词。
 */
static int standard_condition_wait(void *context, pthread_cond_t *condition,
                                   pthread_mutex_t *mutex) {
    (void)context;
    return pthread_cond_wait(condition, mutex);
}

/**
 * @brief
 *     按默认 joinable 属性创建真实线程，不 detach。
 *
 * @param[in] context
 *     标准适配忽略，允许 NULL。
 * @param[out] thread
 *     必需独立句柄存储，只在返回 0 时有效。
 * @param[in] entry
 *     必需入口函数，创建成功可立即执行。
 * @param[in] argument
 *     传给入口的存活槽，只借至线程结束。
 *
 * @return
 *     0 或 pthread 直接错误，失败 thread 值不读取。
 */
static int standard_thread_create(void *context, pthread_t *thread,
                                  void *(*entry)(void *), void *argument) {
    (void)context;
    return pthread_create(thread, NULL, entry, argument);
}

/**
 * @brief
 *     等待并回收一个有效、尚未 join 的线程。
 *
 * @param[in] context
 *     标准适配忽略，允许 NULL。
 * @param[in] thread
 *     成功创建且未消费的 joinable 句柄，不能是当前管理线程。
 *
 * @return
 *     0 或 pthread 直接错误，成功后不再使用句柄。
 */
static int standard_thread_join(void *context, pthread_t thread) {
    (void)context;
    return pthread_join(thread, NULL);
}

/**
 * @brief
 *     worker 入口先禁用 POSIX 取消，再进入锁/条件变量等待。
 *
 * @param[in] context
 *     标准适配忽略，允许 NULL。
 *
 * @return
 *     0 或 pthread 直接错误；线程结束前不恢复取消能力。
 */
static int standard_disable_cancel(void *context) {
    (void)context;
    int previous_state = 0;
    return pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previous_state);
}

/**
 * @brief
 *     worker 锁外使用依赖公开阻塞领取，保留真实转移输出与直接诊断。
 *
 * @param[in] context
 *     标准适配忽略，允许 NULL。
 * @param[in,out] queue
 *     存活、已 prepare 队列，借用由所属 pool 保证。
 * @param[out] task
 *     独立入口 NULL 的 worker 唯一 owner。
 * @param[out] report
 *     独立公开领取诊断，任何返回均由依赖发布。
 *
 * @return
 *     公开 wait_pop 原结果，不自行重试；本线程已禁用 POSIX 取消。
 */
static vireo_result_t standard_wait_pop(void *context, vireo_task_queue_t *queue,
    vireo_task_t **task, vireo_task_queue_transfer_report_t *report) {
    (void)context;
    return vireo_task_queue_wait_pop(queue, task, report);
}

vireo_thread_pool_runtime_t const *vireo_thread_pool_standard_runtime(void) {
    static vireo_thread_pool_runtime_t const runtime = {
        NULL, standard_queue_inspect, standard_mutex_init, standard_mutex_destroy,
        standard_mutex_lock, standard_mutex_unlock, standard_condition_init,
        standard_condition_destroy, standard_condition_wait, standard_condition_broadcast,
        standard_thread_create, standard_thread_join, standard_disable_cancel, standard_wait_pop
    };
    return &runtime;
}

/**
 * @brief
 *     检查局部操作表完整性，不访问其 context 或同步资源。
 *
 * @param[in] runtime
 *     可空短借操作表，非空须为有效可读地址。
 *
 * @return
 *     全部必需操作存在才 true，context 允许 NULL。
 */
static bool runtime_valid(vireo_thread_pool_runtime_t const *runtime) {
    return runtime != NULL && runtime->inspect_queue != NULL &&
        runtime->mutex_init != NULL && runtime->mutex_destroy != NULL &&
        runtime->mutex_lock != NULL && runtime->mutex_unlock != NULL &&
        runtime->condition_init != NULL && runtime->condition_destroy != NULL &&
        runtime->condition_wait != NULL && runtime->condition_broadcast != NULL &&
        runtime->thread_create != NULL && runtime->thread_join != NULL &&
        runtime->disable_cancel != NULL && runtime->wait_pop != NULL;
}

/**
 * @brief
 *     仅 worker 写自身首错；管理端成功 join 后才读取。
 *
 * @param[in,out] slot
 *     当前线程唯一错误写入槽，所属 pool 保活到 join。
 * @param[in] stage
 *     当前直接错误阶段。
 * @param[in] error
 *     非零 pthread 直接错误数。
 *
 * @note
 *     不覆盖更早首错，不发布任意业务数据，不由管理端并发调用。
 */
static void record_worker_error(vireo_thread_pool_worker_slot_t *slot,
                                 vireo_thread_pool_stage_t stage, int error) {
    if (slot->worker_result == VIREO_OK) {
        slot->worker_result = VIREO_RESULT_INTERNAL;
        slot->worker_stage = stage;
        slot->worker_pthread_error = error;
    }
}

/**
 * @brief
 *     放行后领取独占 task，回调返回后结束借用并释放，再处理下一项。
 *
 * @param[in,out] slot
 *     当前 worker 的独占错误写入槽；配置借用在全部 join 前有效。
 *
 * @note
 *     不持 pool 锁调用依赖或回调；领取异常也先清理真实已交出的 owner。
 *     合法唯一 owner 地址满足公开 task_destroy 的成功合同，无私有释放/失败假设。
 *     执行首错不阻止后续任务；领取异常退出，不重试可能损坏的同步。
 */
static void execute_tasks(vireo_thread_pool_worker_slot_t *slot) {
    vireo_thread_pool_t *pool = slot->pool;
    for (;;) {
        vireo_task_t *task = NULL;
        vireo_task_queue_transfer_report_t transfer = {0};
        vireo_result_t result = pool->runtime.wait_pop(pool->runtime.context,
            pool->configuration.queue, &task, &transfer);
        if (result == VIREO_RESULT_CANCELLED && task == NULL) {
            return;
        }
        if (result != VIREO_OK) {
            if (slot->worker_result == VIREO_OK) {
                slot->worker_result = result;
                slot->worker_stage = VIREO_THREAD_POOL_STAGE_TAKE_TASK;
                slot->worker_pthread_error = transfer.pthread_error;
                slot->worker_queue_report = transfer;
            }
            /* 返回码不撤回 owner；真实领取异常后也承担释放责任，不执行该项。 */
            (void)vireo_task_destroy(&task);
            return;
        }
        result = pool->configuration.execute(pool->configuration.context, task);
        if (result != VIREO_OK && slot->worker_result == VIREO_OK) {
            slot->worker_result = result;
            slot->worker_stage = VIREO_THREAD_POOL_STAGE_EXECUTE_TASK;
        }
        /* callback 必须正常返回且结束借用；有效 owner 的公开销毁保证成功。 */
        (void)vireo_task_destroy(&task);
    }
}

/**
 * @brief
 *     真实 worker 先停驻，锁内观测放行后才锁外领取/执行；停止不撤回放行。
 *
 * @param[in,out] argument
 *     必需稳定槽地址，创建前初始化；所属 pool 在对应 join 前存活。
 *
 * @return
 *     NULL；首错存于本槽，管理端成功 join 后观测。
 *
 * @note
 *     入场禁用取消；wait 循环重检谓词，返回时持锁，错误也经过一次解锁。
 *     不读取 thread/thread_created/joined 管理字段，避免创建返回前读取无效句柄。
 */
static void *parked_worker(void *argument) {
    int const saved_errno = errno;
    vireo_thread_pool_worker_slot_t *slot = argument;
    vireo_thread_pool_t *pool = slot->pool;
    vireo_thread_pool_runtime_t const *runtime = &pool->runtime;
    int error = runtime->disable_cancel(runtime->context);
    if (error != 0) {
        record_worker_error(slot, VIREO_THREAD_POOL_STAGE_SET_CANCEL_STATE, error);
        goto done;
    }
    error = runtime->mutex_lock(runtime->context, &pool->mutex);
    if (error != 0) {
        record_worker_error(slot, VIREO_THREAD_POOL_STAGE_LOCK, error);
        goto done;
    }
    while (!pool->stop_requested && !pool->execution_enabled) {
        error = runtime->condition_wait(runtime->context, &pool->condition, &pool->mutex);
        if (error != 0) {
            record_worker_error(slot, VIREO_THREAD_POOL_STAGE_WAIT, error);
            break;
        }
    }
    bool const execute = pool->execution_enabled && slot->worker_result == VIREO_OK;
    error = runtime->mutex_unlock(runtime->context, &pool->mutex);
    if (error != 0) {
        record_worker_error(slot, VIREO_THREAD_POOL_STAGE_UNLOCK, error);
    } else if (execute) {
        execute_tasks(slot);
    }
done:
    errno = saved_errno;
    return NULL;
}

/**
 * @brief
 *     锁内提交停止并广播；只有广播及解锁成功才进行锁外 join。
 *
 * @param[in,out] pool
 *     已尝试启动的存活池，管理端串行；只处理尚未 join 项。
 * @param[out] stage
 *     必需独立阶段，正常 NONE，失败为本次首错。
 * @param[out] pthread_error
 *     必需直接首错，正常 0。
 * @param[out] queue_report
 *     必需独立领取首错报告，其他首错为逻辑零。
 *
 * @return
 *     OK 或本次原首错；每个未回收项最多尝试一次，保留所有成功进度。
 *
 * @note
 *     每个成功 join 后才读取对应 worker 错误；一项失败仍尝试其他项。
 *     不保证损坏同步健康，不自动重试，不消费 queue 或释放 pool。
 */
static vireo_result_t stop_and_join_workers(vireo_thread_pool_t *pool,
    vireo_thread_pool_stage_t *stage, int *pthread_error,
    vireo_task_queue_transfer_report_t *queue_report) {
    *stage = VIREO_THREAD_POOL_STAGE_NONE;
    *pthread_error = 0;
    *queue_report = (vireo_task_queue_transfer_report_t){0};
    if (pool->created_count == pool->joined_count) {
        return VIREO_OK;
    }
    vireo_thread_pool_runtime_t const *runtime = &pool->runtime;
    int error = runtime->mutex_lock(runtime->context, &pool->mutex);
    if (error != 0) {
        *stage = VIREO_THREAD_POOL_STAGE_LOCK;
        *pthread_error = error;
        return VIREO_RESULT_INTERNAL;
    }
    pool->stop_requested = true;
    error = runtime->condition_broadcast(runtime->context, &pool->condition);
    if (error != 0) {
        *stage = VIREO_THREAD_POOL_STAGE_WAKE;
        *pthread_error = error;
    }
    error = runtime->mutex_unlock(runtime->context, &pool->mutex);
    if (error != 0 && *pthread_error == 0) {
        *stage = VIREO_THREAD_POOL_STAGE_UNLOCK;
        *pthread_error = error;
    }
    if (*pthread_error != 0) {
        return VIREO_RESULT_INTERNAL;
    }
    vireo_result_t result = VIREO_OK;
    for (size_t i = 0; i < pool->worker_count; ++i) {
        vireo_thread_pool_worker_slot_t *slot = &pool->workers[i];
        if (!slot->thread_created || slot->thread_joined) {
            continue;
        }
        error = runtime->thread_join(runtime->context, slot->thread);
        if (error != 0) {
            if (result == VIREO_OK) {
                result = VIREO_RESULT_INTERNAL;
                *stage = VIREO_THREAD_POOL_STAGE_JOIN_WORKER;
                *pthread_error = error;
            }
            continue;
        }
        slot->thread_joined = true;
        ++pool->joined_count;
        if (slot->worker_result != VIREO_OK && result == VIREO_OK) {
            result = slot->worker_result;
            *stage = slot->worker_stage;
            *pthread_error = slot->worker_pthread_error;
            *queue_report = slot->worker_queue_report;
        }
    }
    return result;
}

/**
 * @brief
 *     管理端串行条件下，将累计资源进度补入本次局部报告。
 *
 * @param[in] pool
 *     可空短借池，不读 worker 错误或同步存储。
 * @param[in,out] report
 *     必需已初始化局部报告，保留本次两个错误域。
 *
 * @note
 *     NULL pool 保持进度逻辑零；报告只含数值，不返内部地址。
 */
static void report_progress(vireo_thread_pool_t const *pool, vireo_thread_pool_report_t *report) {
    if (pool != NULL) {
        report->start_attempted = pool->start_attempted;
        report->stop_requested = pool->stop_requested;
        report->created_count = pool->created_count;
        report->joined_count = pool->joined_count;
        report->execution_enabled = pool->execution_enabled;
    }
}

vireo_result_t vireo_thread_pool_start_with_runtime(vireo_thread_pool_t *pool,
    vireo_thread_pool_runtime_t const *runtime, vireo_thread_pool_report_t *report) {
    int const saved_errno = errno;
    vireo_thread_pool_report_t value = {0};
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    if (pool == NULL || report == NULL || !runtime_valid(runtime)) {
        goto done;
    }
    if (pool->retiring) {
        result = VIREO_RESULT_CANCELLED;
        goto done;
    }
    if (!pool->configured) {
        result = VIREO_RESULT_NOT_FOUND;
        goto done;
    }
    if (pool->start_attempted) {
        result = VIREO_RESULT_BUSY;
        goto done;
    }
    vireo_task_queue_info_t info;
    value.stage = VIREO_THREAD_POOL_STAGE_CHECK_QUEUE;
    result = runtime->inspect_queue(runtime->context, pool->configuration.queue, &info);
    if (result != VIREO_OK) {
        goto done;
    }
    if (info.state != VIREO_TASK_QUEUE_OPEN) {
        result = VIREO_RESULT_CANCELLED;
        goto done;
    }
    if (!info.wait_prepared) {
        result = VIREO_RESULT_NOT_FOUND;
        goto done;
    }
    pool->runtime = *runtime;
    pool->start_attempted = true;
    value.stage = VIREO_THREAD_POOL_STAGE_INIT_MUTEX;
    value.pthread_error = runtime->mutex_init(runtime->context, &pool->mutex);
    if (value.pthread_error != 0) {
        result = value.pthread_error == ENOMEM ? VIREO_RESULT_NO_MEMORY : VIREO_RESULT_INTERNAL;
        goto done;
    }
    pool->mutex_initialized = true;
    value.stage = VIREO_THREAD_POOL_STAGE_INIT_CONDITION;
    value.pthread_error = runtime->condition_init(runtime->context, &pool->condition);
    if (value.pthread_error != 0) {
        result = value.pthread_error == ENOMEM ? VIREO_RESULT_NO_MEMORY : VIREO_RESULT_INTERNAL;
        goto done;
    }
    pool->condition_initialized = true;
    for (size_t i = 0; i < pool->worker_count; ++i) {
        vireo_thread_pool_worker_slot_t *slot = &pool->workers[i];
        value.stage = VIREO_THREAD_POOL_STAGE_CREATE_WORKER;
        value.pthread_error = runtime->thread_create(runtime->context, &slot->thread,
                                                     parked_worker, slot);
        if (value.pthread_error != 0) {
            result = value.pthread_error == EAGAIN ? VIREO_RESULT_NO_MEMORY : VIREO_RESULT_INTERNAL;
            value.cleanup_result = stop_and_join_workers(pool, &value.cleanup_stage,
                                                          &value.cleanup_pthread_error,
                                                          &value.queue_report);
            goto done;
        }
        slot->thread_created = true;
        ++pool->created_count;
    }
    value.stage = VIREO_THREAD_POOL_STAGE_NONE;
    result = VIREO_OK;
done:
    if (report != NULL) {
        report_progress(pool, &value);
        *report = value;
    }
    errno = saved_errno;
    return result;
}

vireo_result_t vireo_thread_pool_start(vireo_thread_pool_t *pool,
                                       vireo_thread_pool_report_t *report) {
    return vireo_thread_pool_start_with_runtime(pool, vireo_thread_pool_standard_runtime(), report);
}

vireo_result_t vireo_thread_pool_stop_and_join(vireo_thread_pool_t *pool,
                                               vireo_thread_pool_report_t *report) {
    int const saved_errno = errno;
    vireo_thread_pool_report_t value = {0};
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    if (pool == NULL || report == NULL) {
        goto done;
    }
    if (pool->retiring) {
        result = VIREO_RESULT_CANCELLED;
        goto done;
    }
    if (!pool->start_attempted) {
        result = VIREO_RESULT_NOT_FOUND;
        goto done;
    }
    if (pool->execution_enabled && pool->created_count != pool->joined_count) {
        vireo_task_queue_info_t info;
        value.stage = VIREO_THREAD_POOL_STAGE_CHECK_QUEUE;
        result = pool->runtime.inspect_queue(pool->runtime.context, pool->configuration.queue, &info);
        if (result != VIREO_OK) { goto done; }
        if (info.state == VIREO_TASK_QUEUE_OPEN) { result = VIREO_RESULT_BUSY; goto done; }
    }
    result = stop_and_join_workers(pool, &value.stage, &value.pthread_error, &value.queue_report);
done:
    if (report != NULL) {
        report_progress(pool, &value);
        *report = value;
    }
    errno = saved_errno;
    return result;
}


vireo_result_t vireo_thread_pool_enable_execution(vireo_thread_pool_t *pool,
    vireo_thread_pool_report_t *report) {
    int const saved_errno = errno;
    vireo_thread_pool_report_t value = {0};
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    if (pool == NULL || report == NULL) { goto done; }
    if (pool->retiring) { result = VIREO_RESULT_CANCELLED; goto done; }
    if (!pool->start_attempted) { result = VIREO_RESULT_NOT_FOUND; goto done; }
    if (pool->stop_requested) { result = VIREO_RESULT_CANCELLED; goto done; }
    if (pool->execution_enabled || pool->created_count != pool->worker_count ||
        pool->joined_count != 0) { result = VIREO_RESULT_BUSY; goto done; }
    vireo_task_queue_info_t info;
    value.stage = VIREO_THREAD_POOL_STAGE_CHECK_QUEUE;
    result = pool->runtime.inspect_queue(pool->runtime.context, pool->configuration.queue, &info);
    if (result != VIREO_OK) { goto done; }
    if (info.state != VIREO_TASK_QUEUE_OPEN) { result = VIREO_RESULT_CANCELLED; goto done; }
    if (!info.wait_prepared) { result = VIREO_RESULT_NOT_FOUND; goto done; }
    value.stage = VIREO_THREAD_POOL_STAGE_LOCK;
    value.pthread_error = pool->runtime.mutex_lock(pool->runtime.context, &pool->mutex);
    if (value.pthread_error != 0) { result = VIREO_RESULT_INTERNAL; goto done; }
    pool->execution_enabled = true;
    value.stage = VIREO_THREAD_POOL_STAGE_NONE;
    value.pthread_error = pool->runtime.condition_broadcast(pool->runtime.context, &pool->condition);
    if (value.pthread_error != 0) { value.stage = VIREO_THREAD_POOL_STAGE_WAKE; }
    int const unlock_error = pool->runtime.mutex_unlock(pool->runtime.context, &pool->mutex);
    if (unlock_error != 0 && value.pthread_error == 0) {
        value.stage = VIREO_THREAD_POOL_STAGE_UNLOCK;
        value.pthread_error = unlock_error;
    }
    result = value.pthread_error == 0 ? VIREO_OK : VIREO_RESULT_INTERNAL;
done:
    if (report != NULL) { report_progress(pool, &value); *report = value; }
    errno = saved_errno;
    return result;
}

vireo_result_t vireo_thread_pool_inspect_worker_result(vireo_thread_pool_t const *pool,
    size_t worker_index, vireo_thread_pool_worker_result_t *out_result) {
    int const saved_errno = errno;
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    if (pool == NULL || out_result == NULL) { goto done; }
    if (pool->retiring) { result = VIREO_RESULT_CANCELLED; goto done; }
    if (worker_index >= pool->worker_count) { result = VIREO_RESULT_RANGE; goto done; }
    vireo_thread_pool_worker_slot_t const *slot = &pool->workers[worker_index];
    if (!slot->thread_created) { result = VIREO_RESULT_NOT_FOUND; goto done; }
    if (!slot->thread_joined) { result = VIREO_RESULT_BUSY; goto done; }
    vireo_thread_pool_worker_result_t const value = {slot->worker_result, slot->worker_stage,
        slot->worker_pthread_error, slot->worker_queue_report};
    *out_result = value;
    result = VIREO_OK;
done:
    errno = saved_errno;
    return result;
}

/**
 * @brief
 *     一次调用依赖公开 try_push，不另观测或取得 pool 锁。
 *
 * @param[in] context
 *     标准适配忽略，允许 NULL。
 * @param[in,out] queue
 *     已配置的长期借用队列，本次短借，不访问私有布局。
 * @param[in,out] task_owner
 *     caller 独占非空 owner，成功或已转移异常均按公开规则清源。
 * @param[out] report
 *     必需独立原转移报告，由依赖每路径发布。
 *
 * @return
 *     原公开 result，errno 由外层保持，不隐式重试或清理。
 */
static vireo_result_t standard_queue_submit(void *context, vireo_task_queue_t *queue,
    vireo_task_t **task_owner, vireo_task_queue_transfer_report_t *report) {
    (void)context;
    return vireo_task_queue_try_push(queue, task_owner, report);
}

/* 串行管理使这些资格字段在本次调用中稳定；队列自身决定提交时的关闭/满状态。 */
vireo_result_t vireo_thread_pool_try_submit_with_submitter(vireo_thread_pool_t *pool,
    vireo_task_t **task_owner, vireo_thread_pool_queue_submitter_t const *submitter,
    vireo_thread_pool_submit_report_t *report) {
    int const saved_errno = errno;
    vireo_thread_pool_submit_report_t value = {0};
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    if (pool == NULL || task_owner == NULL || report == NULL ||
        submitter == NULL || submitter->try_push == NULL) { goto done; }
    if (*task_owner == NULL) { result = VIREO_RESULT_NOT_FOUND; goto done; }
    value.stage = VIREO_THREAD_POOL_SUBMIT_STAGE_CHECK_POOL;
    if (pool->retiring || pool->stop_requested) { result = VIREO_RESULT_CANCELLED; goto done; }
    if (!pool->configured || !pool->start_attempted) { result = VIREO_RESULT_NOT_FOUND; goto done; }
    if (pool->created_count != pool->worker_count || !pool->execution_enabled ||
        pool->joined_count != 0) { result = VIREO_RESULT_BUSY; goto done; }
    value.queue_called = true;
    value.stage = VIREO_THREAD_POOL_SUBMIT_STAGE_SUBMIT_QUEUE;
    result = submitter->try_push(submitter->context, pool->configuration.queue,
                                task_owner, &value.queue_report);
    if (result == VIREO_OK) { value.stage = VIREO_THREAD_POOL_SUBMIT_STAGE_NONE; }
done:
    if (report != NULL) { *report = value; }
    errno = saved_errno;
    return result;
}

vireo_result_t vireo_thread_pool_try_submit(vireo_thread_pool_t *pool,
    vireo_task_t **task_owner, vireo_thread_pool_submit_report_t *report) {
    vireo_thread_pool_queue_submitter_t const submitter = {NULL, standard_queue_submit};
    return vireo_thread_pool_try_submit_with_submitter(pool, task_owner, &submitter, report);
}

/**
 * @brief
 *     一次公开关闭，原报告与永久模式由依赖负责。
 *
 * @param[in] context
 *     标准适配忽略，允许 NULL。
 * @param[in,out] queue
 *     配置中的存活专用队列，只借至返回，不访问其私有状态。
 * @param[in] mode
 *     已验证的公开 DRAIN 或 CANCEL_PENDING。
 * @param[out] report
 *     必需独立原关闭报告，依赖每路径发布。
 *
 * @return
 *     原公开 result，不重试；errno 由外层保持。
 */
static vireo_result_t standard_queue_close(void *context, vireo_task_queue_t *queue,
    vireo_task_queue_state_t mode, vireo_task_queue_close_report_t *report) {
    (void)context;
    return vireo_task_queue_close(queue, mode, report);
}

/* 只有确认关闭/唤醒成功才进入原回收；changed 不能替代依赖的成功结果。 */
vireo_result_t vireo_thread_pool_shutdown_and_join_with_closer(vireo_thread_pool_t *pool,
    vireo_task_queue_state_t mode, vireo_thread_pool_queue_closer_t const *closer,
    vireo_thread_pool_shutdown_report_t *report) {
    int const saved_errno = errno;
    vireo_thread_pool_shutdown_report_t value = {0};
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    if (pool == NULL || report == NULL || closer == NULL || closer->close == NULL ||
        (mode != VIREO_TASK_QUEUE_DRAIN && mode != VIREO_TASK_QUEUE_CANCEL_PENDING)) {
        goto done;
    }
    value.stage = VIREO_THREAD_POOL_SHUTDOWN_STAGE_CHECK_POOL;
    if (pool->retiring) { result = VIREO_RESULT_CANCELLED; goto done; }
    if (!pool->configured || !pool->start_attempted) { result = VIREO_RESULT_NOT_FOUND; goto done; }
    if (pool->created_count != pool->worker_count || !pool->execution_enabled) {
        result = VIREO_RESULT_BUSY;
        goto done;
    }
    value.close_called = true;
    value.stage = VIREO_THREAD_POOL_SHUTDOWN_STAGE_CLOSE_QUEUE;
    result = closer->close(closer->context, pool->configuration.queue, mode, &value.close_report);
    if (result != VIREO_OK) { goto done; }
    value.join_called = true;
    value.stage = VIREO_THREAD_POOL_SHUTDOWN_STAGE_JOIN_WORKERS;
    result = vireo_thread_pool_stop_and_join(pool, &value.pool_report);
    if (result == VIREO_OK) { value.stage = VIREO_THREAD_POOL_SHUTDOWN_STAGE_NONE; }
done:
    if (report != NULL) { *report = value; }
    errno = saved_errno;
    return result;
}

vireo_result_t vireo_thread_pool_shutdown_and_join(vireo_thread_pool_t *pool,
    vireo_task_queue_state_t mode, vireo_thread_pool_shutdown_report_t *report) {
    vireo_thread_pool_queue_closer_t const closer = {NULL, standard_queue_close};
    return vireo_thread_pool_shutdown_and_join_with_closer(pool, mode, &closer, report);
}
