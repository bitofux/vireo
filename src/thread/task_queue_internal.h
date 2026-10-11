/*
 * PROJECT : VIREO
 * FILE    : task_queue_internal.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-11
 * BRIEF   : 仅本核心使用的互斥循环数组与局部资源操作 seam
 */

#ifndef VIREO_THREAD_TASK_QUEUE_INTERNAL_H
#define VIREO_THREAD_TASK_QUEUE_INTERNAL_H

#include <vireo/thread/task_queue.h>

#include <pthread.h>

/**
 * @brief
 *     本核心局部配对分配表；按值保存操作，借用 context。
 *
 * @note
 *     allocate 返回新独占、足量、正确对齐的块或 NULL；deallocate 配对释放原块。
 *     context 须存活且适当同步到销毁，callback 不得破坏输入/输出或递归操作对象。
 *     不是公开可替换分配器，不供下游依赖。
 */
typedef struct vireo_task_queue_allocator {
    void *context; /**< 借用上下文，可NULL，不由queue释放。 */
    void *(*allocate)(void *context, size_t bytes); /**< 正字节申请，可扰动errno，失败NULL。 */
    void (*deallocate)(void *context, void *allocation); /**< 配对释放整个原块，无失败返回。 */
} vireo_task_queue_allocator_t;

/**
 * @brief
 *     本核心同步操作副本；直接返回pthread错误，不向下游公开。
 *
 * @note
 *     context借至销毁，操作表只借至创建返回；不允许递归操作或破坏资源。
 *     init失败不得留下已初始化mutex；try_lock失败不得获得锁。
 *     unlock遵循pthread释放语义；测试可在真实释放后注入报告错误。
 *     destroy失败不销毁mutex，成功完成真实销毁；不释放context。
 */
typedef struct vireo_task_queue_sync_ops {
    void *context; /**< 借用上下文，可NULL，caller保证寿命和同步。 */
    int (*init)(void *context, pthread_mutex_t *mutex); /**< 初始化默认非robust mutex。 */
    int (*try_lock)(void *context, pthread_mutex_t *mutex); /**< 一次尝试，直接返回错误码。 */
    int (*unlock)(void *context, pthread_mutex_t *mutex); /**< 释放本线程持有的mutex。 */
    int (*destroy)(void *context, pthread_mutex_t *mutex); /**< 无在途访问时销毁空资源mutex。 */
} vireo_task_queue_sync_ops_t;

/**
 * @brief
 *     仅本核心等待操作副本，复用同一mutex，不作为公共扩展点。
 *
 * @note
 *     context借至销毁；init失败不得初始化cond，lock失败不得持锁。
 *     wait返回时须仍持mutex；destroy失败保留cond，成功真实销毁。
 *     不递归、不破坏资源；测试可在真实唤醒后报告错误。
 */
typedef struct vireo_task_queue_wait_ops {
    void *context; /**< 借用上下文，须存活并同步到销毁。 */
    int (*init)(void *context, pthread_cond_t *cond); /**< 初始化未发布cond，失败保持。 */
    int (*lock)(void *context, pthread_mutex_t *mutex); /**< 阻塞取得原mutex，直接错误码。 */
    int (*wait)(void *context, pthread_cond_t *cond, pthread_mutex_t *mutex); /**< 原子释放并重获mutex。 */
    int (*signal)(void *context, pthread_cond_t *cond); /**< 通知至少一个当前等待者。 */
    int (*broadcast)(void *context, pthread_cond_t *cond); /**< 通知全部当前等待者。 */
    int (*destroy)(void *context, pthread_cond_t *cond); /**< 无访问时销毁cond，失败保持。 */
} vireo_task_queue_wait_ops_t;

/**
 * @brief
 *     同一次申请内的固定循环容器；布局和sizeof不是公共合同。
 */
struct vireo_task_queue {
    size_t capacity; /**< 固定槽位条数，正值且不超hard limit。 */
    size_t count; /**< mutex保护的占用条数，0..capacity，区分同索引满空。 */
    size_t high_watermark; /**< mutex保护的已提交最大count，初始0，只增不减。 */
    uint64_t full_rejections; /**< mutex保护的有效满拒绝累计，饱和到UINT64_MAX。 */
    uint64_t closed_rejections; /**< mutex保护的有效关闭拒绝累计，关闭优先满。 */
    bool rejection_count_saturated; /**< mutex保护的粘性标志，再计MAX时置true。 */
    size_t allocated_bytes; /**< sizeof控制块加固定槽数组的受检实际申请量。 */
    size_t max_memory_bytes; /**< 原显式容器字节预算，不计task自有申请。 */
    vireo_task_queue_allocator_t allocator; /**< 配对操作表自有副本，context借到销毁。 */
    vireo_task_queue_sync_ops_t sync; /**< 同步操作自有副本，context借到销毁。 */
    pthread_mutex_t mutex; /**< 发布后不拷贝/移动，保护索引、count、槽、state和指标。 */
    size_t head; /**< mutex保护的下一领取槽索引，始终小于capacity。 */
    size_t tail; /**< mutex保护的下一提交槽索引，始终小于capacity。 */
    vireo_task_queue_state_t state; /**< mutex保护；初始OPEN，首次关闭永久选定模式。 */
    vireo_task_queue_wait_ops_t wait_ops; /**< 成功prepare时复制，context借到销毁。 */
    pthread_cond_t cond; /**< prepare初始化后不移动，等待原mutex保护的谓词。 */
    bool wait_prepared; /**< cond存活标志，prepare/destroy外部排除全部访问。 */
    bool retiring; /**< cond已消耗但mutex尚待销毁；只能重试destroy。 */
    vireo_task_t *slots[]; /**< capacity个槽，非空元素唯一拥有task，空元素为NULL。 */
};

/**
 * @brief
 *     仅本核心实现和测试使用的分配失败入口，其他语义同公开create。
 *
 * @param[in] options
 *     公开有效选项，借到返回，不保存地址。
 * @param[in] allocator
 *     必需有效配对表，两callback非NULL；表借至返回，context借到销毁。
 * @param[out] out_queue
 *     必需合法空owner地址，不重叠输入、资源或errno。
 *
 * @return
 *     公开create分类；额外无效表为INVALID_ARGUMENT，失败保持输出及资源。
 *
 * @note
 *     全部路径保持errno，无全局可变fault，不向下游公开布局或setter。
 */
vireo_result_t vireo_task_queue_create_with_allocator(vireo_task_queue_options_t const *options,
    vireo_task_queue_allocator_t const *allocator, vireo_task_queue_t **out_queue);

/**
 * @brief
 *     本核心独占测试可注入配对分配及同步失败，公共语义不变。
 *
 * @param[in] options
 *     公开有效选项，短借至返回。
 * @param[in] allocator
 *     必需有效配对表，表短借，context借至销毁。
 * @param[in] sync
 *     必需有效同步表，四操作非NULL，表短借，context借至销毁。
 * @param[out] out_queue
 *     必需独立合法空owner，不重叠输入、资源或errno。
 *
 * @return
 *     公开create分类，无效操作表INVALID_ARGUMENT；失败不发布。
 *
 * @note
 *     所有路径保持errno，无全局可变fault；不供其他核心包含或使用。
 */
vireo_result_t vireo_task_queue_create_with_ops(vireo_task_queue_options_t const *options,
    vireo_task_queue_allocator_t const *allocator, vireo_task_queue_sync_ops_t const *sync,
    vireo_task_queue_t **out_queue);

/**
 * @brief
 *     本核心测试局部等待失败seam，其他语义同公开prepare_wait。
 *
 * @param[in,out] queue
 *     必需空OPEN对象，全部访问已结束。
 * @param[in] ops
 *     必需六个非NULL操作，表短借，context借至销毁。
 *
 * @return
 *     公开prepare分类，无效表INVALID_ARGUMENT，全部路径保持errno。
 */
vireo_result_t vireo_task_queue_prepare_wait_with_ops(vireo_task_queue_t *queue,
    vireo_task_queue_wait_ops_t const *ops);

#endif /* VIREO_THREAD_TASK_QUEUE_INTERNAL_H */
