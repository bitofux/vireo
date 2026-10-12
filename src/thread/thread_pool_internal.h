/*
 * PROJECT : VIREO
 * FILE    : thread_pool_internal.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-12
 * BRIEF   : 仅本核心使用的线程槽、同步存储与局部资源 seam
 */

#ifndef VIREO_THREAD_THREAD_POOL_INTERNAL_H
#define VIREO_THREAD_THREAD_POOL_INTERNAL_H

#include <vireo/thread/thread_pool.h>

#include <pthread.h>
#include <stdbool.h>

/**
 * @brief
 *     本核心局部分配操作副本，context 短借至配对释放结束。
 *
 * @note
 *     allocate 返回新独占、足量、正确对齐的块或 NULL；deallocate 无失败返回。
 *     不得破坏输入、输出或重入；不向下游暴露布局或可替换分配器。
 */
typedef struct vireo_thread_pool_allocator {
    void *context; /**< 借用上下文，可 NULL，caller 保证寿命和同步。 */
    void *(*allocate)(void *context, size_t bytes); /**< 正字节请求，失败 NULL，可扰 errno。 */
    void (*deallocate)(void *context, void *allocation); /**< 配对释放整个原块，不释放 context。 */
} vireo_thread_pool_allocator_t;

/**
 * @brief
 *     本核心的 POSIX 操作副本；只用于本核心确定失败，禁止 foreign private。
 *
 * @note
 *     start 保存副本，context 借至 pool 销毁；所有回调必需，不重入 pool。
 *     创建/join 成功必须执行真实操作，失败创建不得留下线程，失败 join 不消费句柄。
 *     wait 返回时仍持非 robust mutex；测试 unlock 可真实释放后再报告失败，
 *     不得将此注入模型外推为损坏的 POSIX 同步可恢复。共享 context 须同步。
 */
typedef struct vireo_thread_pool_runtime {
    void *context; /**< 可空长期借用 context，不由 pool 释放。 */
    vireo_result_t (*inspect_queue)(void *, vireo_task_queue_t const *,
                                   vireo_task_queue_info_t *); /**< 只公开观测，OK 才产合法快照。 */
    int (*mutex_init)(void *, pthread_mutex_t *); /**< 初始化默认非 robust mutex。 */
    int (*mutex_destroy)(void *, pthread_mutex_t *); /**< 成功才消费该 mutex。 */
    int (*mutex_lock)(void *, pthread_mutex_t *); /**< 成功才取得锁。 */
    int (*mutex_unlock)(void *, pthread_mutex_t *); /**< 释放锁，返回直接错误。 */
    int (*condition_init)(void *, pthread_cond_t *); /**< 初始化默认条件变量。 */
    int (*condition_destroy)(void *, pthread_cond_t *); /**< 成功才消费条件变量。 */
    int (*condition_wait)(void *, pthread_cond_t *, pthread_mutex_t *); /**< 返回时持锁，允许虚假唤醒。 */
    int (*condition_broadcast)(void *, pthread_cond_t *); /**< 通知全部等待者，不替代停止谓词。 */
    int (*thread_create)(void *, pthread_t *, void *(*)(void *), void *); /**< 默认 joinable 创建，失败句柄无效。 */
    int (*thread_join)(void *, pthread_t); /**< 成功才回收，不允许并发 join 同一线程。 */
    int (*disable_cancel)(void *); /**< 当前 worker 入口禁用 POSIX 取消，直接返回错误。 */
    vireo_result_t (*wait_pop)(void *, vireo_task_queue_t *, vireo_task_t **,
        vireo_task_queue_transfer_report_t *); /**< 仅公开领取，成功使用真实交接，异常保真实 owner/report。 */
} vireo_thread_pool_runtime_t;

/**
 * @brief
 *     固定 worker 管理记录，创建与成功 join 之间句柄才可使用。
 *
 * @note
 *     未创建 thread 不初始化/读取；已 join 后也不再次用于 pthread API。
 *     worker 只写自身错误；管理端对应 join 成功后才读取错误，不并发观测。
 */
typedef struct vireo_thread_pool_worker_slot {
    pthread_t thread; /**< 成功创建产生的句柄，未创建或已 join 时不得使用。 */
    bool thread_created; /**< 初始 false，成功创建后永久 true，非活跃标志。 */
    bool thread_joined; /**< 初始 false，成功 join 后 true，不再回收该句柄。 */
    vireo_thread_pool_t *pool; /**< 借用所属 pool 至 worker 退出，全部 join 前不能释放。 */
    vireo_thread_pool_stage_t worker_stage; /**< worker 写首错，管理端成功 join 后读。 */
    int worker_pthread_error; /**< worker 首错的直接错误，初始 0，不通过 errno 上报。 */
    vireo_result_t worker_result; /**< worker 原始首错，初始 OK；执行失败也可无 pthread 错误。 */
    vireo_task_queue_transfer_report_t worker_queue_report; /**< TAKE_TASK 原报告，其他首错为逻辑零。 */
} vireo_thread_pool_worker_slot_t;

/**
 * @brief
 *     单次申请的控制块与固定槽 FAM，sizeof 不是公共合同。
 */
struct vireo_thread_pool {
    size_t worker_count; /**< 固定正配置槽数，不超公共硬限。 */
    size_t allocated_bytes; /**< sizeof 控制块加槽表的受检实际申请量。 */
    size_t max_memory_bytes; /**< 正创建预算，实际申请量不超过它。 */
    vireo_thread_pool_allocator_t allocator; /**< 操作表自有副本，context 借至销毁。 */
    vireo_thread_pool_configuration_t configuration; /**< 自有字段副本，queue/context 仅借用。 */
    bool configured; /**< 构造 false，完整装配后 true，没有运行期并发写保证。 */
    vireo_thread_pool_runtime_t runtime; /**< 自有操作表副本，context 借至最终销毁。 */
    pthread_mutex_t mutex; /**< start 初始化后有效，保护 worker 停止/放行谓词。 */
    pthread_cond_t condition; /**< start 初始化后有效，worker 同 mutex 循环等待。 */
    bool mutex_initialized; /**< 成功初始化 true，成功销毁 false，不读取无效存储。 */
    bool condition_initialized; /**< 成功初始化 true，成功销毁 false。 */
    bool retiring; /**< cond 已消费而 mutex 待销毁，仅允许 destroy。 */
    bool start_attempted; /**< 管理端提交单次实际启动尝试，永久不重置。 */
    bool stop_requested; /**< 管理端在锁内永久置 true，worker 同锁读取。 */
    bool execution_enabled; /**< 管理端锁内永久放行，worker 同锁读取；停止不撤回已放行。 */
    size_t created_count; /**< 管理端累计成功创建数，不超配置数。 */
    size_t joined_count; /**< 管理端累计成功 join 数，不超创建数。 */
    vireo_thread_pool_worker_slot_t workers[]; /**< worker_count 个槽，与控制块同申请同释放。 */
};

/**
 * @brief
 *     返回本核心默认只读 POSIX 适配表，静态生命周期，不允许修改或释放。
 *
 * @return
 *     非空借用操作表，context NULL，所有操作均走真实公开 API。
 */
vireo_thread_pool_runtime_t const *vireo_thread_pool_standard_runtime(void);

/**
 * @brief
 *     本核心局部启动 seam；成功尝试复制完整操作表，其他合同同公开 start。
 *
 * @param[in,out] pool
 *     必需存活池，管理端外部串行同步。
 * @param[in] runtime
 *     必需完整表，地址借至返回，context 存活且同步至 pool 销毁。
 * @param[out] report
 *     必需独立十一字段报告，每可写路径发布。
 *
 * @return
 *     公开 start 分类，无效操作表 INVALID_ARGUMENT；全部路径保持 errno。
 *
 * @note
 *     不供其他核心包含或调用，不使用全局可变故障，不包含依赖私有头。
 */
vireo_result_t vireo_thread_pool_start_with_runtime(vireo_thread_pool_t *pool,
    vireo_thread_pool_runtime_t const *runtime, vireo_thread_pool_report_t *report);

/**
 * @brief
 *     仅本核心的局部公开观测适配，测试注入不修改依赖私有状态。
 */
typedef struct vireo_thread_pool_queue_inspector {
    void *context; /**< 可空短借上下文，不保存到 pool。 */
    vireo_result_t (*inspect)(void *context, vireo_task_queue_t const *queue,
                             vireo_task_queue_info_t *out_info); /**< 必需，只读观测；仅 OK 才产出合法快照。 */
} vireo_thread_pool_queue_inspector_t;

/**
 * @brief
 *     仅本核心短借的公开提交 seam，不保存操作表或增加池持久字段。
 *
 * @note
 *     成功必须真实交接；未转移错误保持 owner，已转移错误保原清源事实及报告。
 *     不包含依赖私有头，不重入池；测试有限错误模型不代表损坏同步可恢复。
 */
typedef struct vireo_thread_pool_queue_submitter {
    void *context; /**< 可空上下文，仅本次借用，不由 pool 释放或保存。 */
    vireo_result_t (*try_push)(void *, vireo_task_queue_t *, vireo_task_t **,
        vireo_task_queue_transfer_report_t *); /**< 必需一次公开提交适配，真实 owner/report 责任沿公开队列。 */
} vireo_thread_pool_queue_submitter_t;

/**
 * @brief
 *     本核心短借的公开关闭适配，只验证两段编排的失败边界。
 *
 * @note
 *     成功必须真实公开关闭；失败保留实际关闭及原报告，不重入池。
 *     不保存表或 context，不含依赖私有头；有限模型不证明损坏同步可靠恢复。
 */
typedef struct vireo_thread_pool_queue_closer {
    void *context; /**< 可空上下文，只借至本次返回，不保存或释放。 */
    vireo_result_t (*close)(void *, vireo_task_queue_t *, vireo_task_queue_state_t,
        vireo_task_queue_close_report_t *); /**< 必需一次公开关闭适配，遵循原模式/实际进度。 */
} vireo_thread_pool_queue_closer_t;

/**
 * @brief
 *     本核心局部关闭编排入口，除必需适配校验外沿公开合同。
 *
 * @param[in,out] pool
 *     必需存活池，管理端串行同步，全调用禁用 POSIX 取消。
 * @param[in] mode
 *     只接受公开 DRAIN 或 CANCEL_PENDING。
 * @param[in] closer
 *     必需完整表，表与 context 只借至本次返回，不保存。
 * @param[out] report
 *     必需独立五字段报告，每可写路径发布。
 *
 * @return
 *     原公开结果；表 NULL 或回调缺失为 INVALID_ARGUMENT，优先资格检查。
 *
 * @note
 *     全路径保持 errno；只供本核心，不使用全局故障或 foreign private。
 */
vireo_result_t vireo_thread_pool_shutdown_and_join_with_closer(vireo_thread_pool_t *pool,
    vireo_task_queue_state_t mode, vireo_thread_pool_queue_closer_t const *closer,
    vireo_thread_pool_shutdown_report_t *report);

/**
 * @brief
 *     本核心局部提交入口，除必需操作表校验外沿公开 try_submit 合同。
 *
 * @param[in,out] pool
 *     必需存活池，管理与提交串行同步。
 * @param[in,out] task_owner
 *     必需独占 owner 地址，短借至返回，成功真实交接后清空。
 * @param[in] submitter
 *     必需完整操作表，表和 context 只借至本次返回，不保存或申请。
 * @param[out] report
 *     必需独立三字段报告，每可写路径覆盖。
 *
 * @return
 *     公开结果；操作表 NULL/缺回调为 INVALID_ARGUMENT，优先空源与资格。
 *
 * @note
 *     全部路径保持 errno；无全局 fault，不供其他核心包含或调用。
 */
vireo_result_t vireo_thread_pool_try_submit_with_submitter(vireo_thread_pool_t *pool,
    vireo_task_t **task_owner, vireo_thread_pool_queue_submitter_t const *submitter,
    vireo_thread_pool_submit_report_t *report);

/**
 * @brief
 *     本核心测试错误透传的局部 seam，其他合同与公开 configure 相同。
 *
 * @param[in,out] pool
 *     必需未装配存活 pool，caller 同步访问。
 * @param[in] configuration
 *     必需稳定配置，与公开入口相同借用边界。
 * @param[in] inspector
 *     必需局部操作表及观测函数，只借至返回，不保存；不得修改 queue 或重入。
 * @param[out] stage
 *     可空独立诊断，每可写路径覆盖。
 *
 * @return
 *     公开 configure 分类及观测返回原值；非法操作表为 INVALID_ARGUMENT。
 *
 * @note
 *     所有路径 errno 保持，无全局 fault，不包含或开放其他核心 private。
 */
vireo_result_t vireo_thread_pool_configure_with_inspector(vireo_thread_pool_t *pool,
    vireo_thread_pool_configuration_t const *configuration,
    vireo_thread_pool_queue_inspector_t const *inspector,
    vireo_thread_pool_configure_stage_t *stage);

/**
 * @brief
 *     仅本核心测试使用的配对分配入口，其他合同与公开 create 相同。
 *
 * @param[in] options
 *     必需稳定可读固定选项，仅借至返回。
 * @param[in] allocator
 *     必需有效操作表，地址仅借至返回；复制表，context 须存活至销毁。
 * @param[out] out_pool
 *     必需独占 owner 地址，入口 NULL，失败保持。
 *
 * @return
 *     公开 create 的分类；操作表 NULL 或回调缺失为 INVALID_ARGUMENT。
 *
 * @note
 *     无全局可变 fault，不供其他核心包含或调用，所有路径 errno 保持。
 */
vireo_result_t vireo_thread_pool_create_with_allocator(
    vireo_thread_pool_options_t const *options,
    vireo_thread_pool_allocator_t const *allocator, vireo_thread_pool_t **out_pool);

#endif
