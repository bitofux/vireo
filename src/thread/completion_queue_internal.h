/*
 * PROJECT : VIREO
 * FILE    : completion_queue_internal.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-12
 * BRIEF   : 仅本核心使用的配对分配/同步 seam 与受锁保护的循环槽布局
 */

#ifndef VIREO_THREAD_COMPLETION_QUEUE_INTERNAL_H
#define VIREO_THREAD_COMPLETION_QUEUE_INTERNAL_H

#include <vireo/thread/completion_queue.h>

#include <pthread.h>

/**
 * @brief
 *     本核心私有配对操作表，按值保存，不是公共可替换分配器。
 *
 * @note
 *     allocate 返回全新、足量、正确对齐的独占块或 NULL。
 *     deallocate 配对释放原块，无失败返回；callback 可改变 errno。
 *     context 借至全部相关容器销毁，callback 不重入或破坏输入、输出和资源。
 */
typedef struct vireo_completion_queue_allocator {
    void *context; /**< 借用上下文，可 NULL，不由队列释放。 */
    void *(*allocate)(void *context, size_t bytes); /**< 按正字节数申请，失败返回 NULL。 */
    void (*deallocate)(void *context, void *allocation); /**< 配对释放完整原块。 */
} vireo_completion_queue_allocator_t;

/**
 * @brief
 *     本核心私有同步表，按值保存，context 借至队列销毁。
 *
 * @note
 *     init 非零不得留下已初始化 mutex；try_lock 非零不得取得锁。
 *     unlock 为 0 表示已释放锁；非零不保证损坏同步的恢复。
 *     destroy 非零保留 mutex，0 表示已销毁。测试可真实解锁后报告注入错误。
 *     callback 可改变 errno，不重入；不是公共同步扩展点。
 */
typedef struct vireo_completion_queue_sync {
    void *context; /**< 借用上下文，可 NULL。 */
    int (*init)(void *context, pthread_mutex_t *mutex); /**< 默认非 robust mutex 初始化。 */
    int (*try_lock)(void *context, pthread_mutex_t *mutex); /**< 一次尝试，非零不持锁。 */
    int (*unlock)(void *context, pthread_mutex_t *mutex); /**< 释放已经取得的锁。 */
    int (*destroy)(void *context, pthread_mutex_t *mutex); /**< 无访问且空队列的同步收尾。 */
} vireo_completion_queue_sync_t;

/**
 * @brief
 *     本核心等待操作表，按值保存；不是公共扩展点。
 *
 * @note
 *     context 借至队列销毁，callback 不重入，可改变 errno。
 *     init 非零不留下已初始化 cond；lock 非零不得持锁。
 *     wait 入口持有原 mutex，返回仍持有它；0 仅提示重检谓词。
 *     signal/broadcast 的错误不撤销已提交状态；destroy 非零保留 cond。
 */
typedef struct vireo_completion_queue_wait_ops {
    void *context; /**< 借用上下文，可 NULL。 */
    int (*init)(void *context, pthread_cond_t *cond); /**< 初始化未使用的条件变量存储。 */
    int (*lock)(void *context, pthread_mutex_t *mutex); /**< 允许阻塞取得原 mutex。 */
    int (*wait)(void *context, pthread_cond_t *cond, pthread_mutex_t *mutex); /**< 原子释放并等待后重新持锁。 */
    int (*signal)(void *context, pthread_cond_t *cond); /**< 每次领取后提示一个等待者有空槽。 */
    int (*broadcast)(void *context, pthread_cond_t *cond); /**< 首次及重复关闭提示所有等待者。 */
    int (*destroy)(void *context, pthread_cond_t *cond); /**< 全部访问结束后销毁条件变量。 */
} vireo_completion_queue_wait_ops_t;

/** 固定同块槽数组；运行谓词和槽中 owner 全部由 mutex 保护。 */
struct vireo_completion_queue {
    size_t capacity; /**< 固定正槽数。 */
    size_t allocated_bytes; /**< 控制块加槽数组的受检申请字节数。 */
    size_t max_memory_bytes; /**< caller 显式容器预算。 */
    vireo_completion_queue_allocator_t allocator; /**< 自有操作表副本，context 借用。 */
    vireo_completion_queue_sync_t sync; /**< 自有同步表副本，context 借用。 */
    pthread_mutex_t mutex; /**< 发布/领取/观测的互斥及内存可见性。 */
    size_t head; /**< 下一领取槽，下标小于 capacity。 */
    size_t tail; /**< 下一提交槽，下标小于 capacity。 */
    size_t count; /**< 队列拥有的项数，0..capacity，区别空与满。 */
    size_t high_watermark; /**< 同 mutex 保护的历史提交占用峰值，初始 0，不下降。 */
    uint64_t full_rejections; /**< 同 mutex 保护的 try 满拒绝累计，初始 0，受检饱和。 */
    uint64_t closed_rejections; /**< 同 mutex 保护的 try/wait 关闭拒绝累计，初始 0。 */
    bool rejection_count_saturated; /**< 任一累计在 MAX 后再计时永久置 true，初始 false。 */
    bool closed; /**< 同 mutex 保护的永久提交终止谓词，默认 false，仅 close 置 true。 */
    vireo_completion_queue_wait_ops_t wait_ops; /**< prepare 成功后自有表副本，context 长借。 */
    pthread_cond_t cond; /**< 容量和关闭变化的提示，仅 prepare 成功后可用。 */
    bool wait_prepared; /**< 是否拥有已初始化 cond，仅在无并发的准备/销毁时修改。 */
    bool retiring; /**< cond 已消耗后进入仅重试 destroy 的终态，默认 false。 */
    vireo_completion_t *slots[]; /**< count 个非空独占 owner，其余槽 NULL。 */
};

/**
 * @brief
 *     本核心用于实际申请失败核验的窄构造入口，其余合同沿公开 create。
 *
 * @param[in] options
 *     必需稳定选项，仅借至返回。
 * @param[in] allocator
 *     必需有效配对表，两 callback 非 NULL，表借至返回，context 借至销毁。
 * @param[out] out_queue
 *     必需独占空 owner 地址，不与输入、资源或 errno 重叠。
 *
 * @return
 *     公开创建结果；额外非法配对表为 INVALID_ARGUMENT，失败主输出保持。
 *
 * @note
 *     所有路径保持 errno，没有全局可变故障开关，不供其他核心依赖。
 */
vireo_result_t vireo_completion_queue_create_with_allocator(
    vireo_completion_queue_options_t const *options,
    vireo_completion_queue_allocator_t const *allocator, vireo_completion_queue_t **out_queue);

/**
 * @brief
 *     配对分配与同步失败核验入口，只有本核心测试可使用。
 *
 * @param[in] options
 *     稳定选项，合同沿公开 create。
 * @param[in] allocator
 *     必需完整配对表，按值保存，context 借至销毁。
 * @param[in] sync
 *     必需完整同步表，按值保存，context 借至销毁。
 * @param[out] out_queue
 *     独占空 owner，不与输入、资源或 errno 重叠。
 *
 * @return
 *     沿公开 create；无效操作表 INVALID_ARGUMENT，失败输出保持。
 *
 * @note
 *     全部路径保持 errno，没有全局故障开关，不供其他核心依赖。
 */
vireo_result_t vireo_completion_queue_create_with_ops(
    vireo_completion_queue_options_t const *options,
    vireo_completion_queue_allocator_t const *allocator,
    vireo_completion_queue_sync_t const *sync, vireo_completion_queue_t **out_queue);

/**
 * @brief
 *     本核心用于等待故障核验的显式准备入口。
 *
 * @param[in,out] queue
 *     存活队列，caller 排除全部访问，其他前提沿公开 prepare_wait。
 * @param[in] ops
 *     必需完整表，仅借至返回，成功后按值保存；context 借至销毁。
 *
 * @return
 *     沿公开 prepare_wait；非法表为 INVALID_ARGUMENT，失败保持资源。
 *
 * @note
 *     errno 保持，没有全局故障开关，不供其他核心依赖。
 */
vireo_result_t vireo_completion_queue_prepare_wait_with_ops(vireo_completion_queue_t *queue,
    vireo_completion_queue_wait_ops_t const *ops);

#endif /* VIREO_THREAD_COMPLETION_QUEUE_INTERNAL_H */
