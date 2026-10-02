/*
 * PROJECT : VIREO
 * FILE    : pool_internal.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-02
 * BRIEF   : 此模块负责：
 * -- 提供池生命周期真实分配点的私有故障注入，不是下游合同
 */
#ifndef VIREO_BASE_POOL_INTERNAL_H
#define VIREO_BASE_POOL_INTERNAL_H

#include <vireo/base/pool.h>
#include <stdatomic.h>

/** 配对操作表按值保存，无全局可变 hook，不冻结运行时池布局。 */
typedef struct vireo_pool_allocator {
    void *context; /**< 借用至失败清理结束或成功池销毁，生产为 NULL。 */
    void *(*allocate)(void *context, size_t size); /**< 正 size；独立、max_align_t 对齐或 NULL。 */
    void (*deallocate)(void *context, void *memory); /**< 配对释放，不失败、不重入池。 */
} vireo_pool_allocator_t;

/**
 * @brief 用按值复制的分配器运行与公共 create 相同的完整创建路径
 * @param[in] options 公共 create 的有效选项，仅借用到返回。
 * @param[in] allocator 非 NULL，两个 callback 均必需；表借用到返回，context
 *     有效至回滚/销毁。callback 不修改输入、输出或已发布池，不重入池操作。
 * @param[in,out] out_pool 公共 create 的空拥有者地址，存储独立且调用期间独占。
 * @retval VIREO_OK 完整交付唯一池，按值保存配对操作。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 操作表/callback或公共参数非法。
 * @retval VIREO_RESULT_OVERFLOW 布局或总需求不可表示。
 * @retval VIREO_RESULT_RANGE 实际对齐或总预算不在公共合同范围。
 * @retval VIREO_RESULT_NO_MEMORY 任一分配失败，逆序清理已获资源。
 * @note options/allocator/out_pool互不重叠且不在候选资源内；外部同步，保持 errno。
 * @note 仅本模块实现与测试包含此头，不增加公共 include 根，不支持下游自定义分配器。
 */
vireo_result_t vireo_pool_create_with_allocator(vireo_pool_options_t const *options,
    vireo_pool_allocator_t const *allocator, vireo_pool_t **out_pool);

/**
 * @brief 使用独立原子身份源和初始发放序号运行同一创建核心，仅用于耗尽实验
 * @param[in,out] identity_source 非 NULL、已 atomic_init 的独立原子源，仅调用中借用；
 *     最大值拒绝，成功保留递增，失败分配也不回退，不重置生产全局计数器。
 * @param[in] initial_generation 创建时设置的已发放序号；槽位均初始化空闲，
 *     仅用于构造可到达的耗尽状态，不伪造在用位或修改已发布池。
 * @param[in] options 公共选项；allocator 为有效配对表；其context生命周期同上。
 * @param[in,out] out_pool 公共空拥有者地址，各输入输出与候选资源互不重叠。
 * @retval VIREO_OK 发布空池；其他结果与公共create相同，NULL身份源INVALID_ARGUMENT。
 * @note 外部同步，保持errno；数值源不存入池，只在创建核心使用。
 *     非公共接口，不能用于下游构造身份或作为实际布局合同。
 */
vireo_result_t vireo_pool_create_with_counters(vireo_pool_options_t const *options,
    vireo_pool_allocator_t const *allocator, _Atomic uint64_t *identity_source,
    uint64_t initial_generation, vireo_pool_t **out_pool);

#endif /* VIREO_BASE_POOL_INTERNAL_H */
