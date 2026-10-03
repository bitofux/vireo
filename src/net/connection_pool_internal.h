/*
- PROJECT : VIREO
- FILE    : connection_pool_internal.h
- AUTHOR  : bitofux
- DATE    : 2026-10-04
- BRIEF   : 此模块负责：
- -- 仅本模块测试的逐对象资源与公共依赖故障注入
 */
#ifndef VIREO_NET_CONNECTION_POOL_INTERNAL_H
#define VIREO_NET_CONNECTION_POOL_INTERNAL_H

#include <vireo/base/pool.h>
#include <vireo/net/connection_pool.h>

/**
 * 完整表按值复制；context 借用至 destroy 返回。无全局可变 hooks，不属于公共 API。
 * allocate/deallocate 遵守 malloc/free 配对；基础池 hooks 仅调用公共接口并遵守其 owner 合同。
 * 成功 create_storage 必须取得完整空基础池；构造回滚中其 destroy 必须成功。
 * 故障测试可拒绝调用或污染数值快照，不得偷偷取得租约、泄漏资源或消费失败 owner。
 * 不导入基础池/连接私有头、布局或 allocator seam；不保证修复违约 hooks/损坏对象。
 */
typedef struct vireo_connection_pool_ops {
    void *context;
    void *(*allocate)(void *context, size_t bytes);
    void (*deallocate)(void *context, void *memory);
    vireo_result_t (*create_storage)(void *context, vireo_pool_options_t const *options,
                                     vireo_pool_t **out_pool);
    vireo_result_t (*inspect_storage)(void *context, vireo_pool_t const *pool,
                                      vireo_pool_info_t *out_info);
    vireo_result_t (*destroy_storage)(void *context, vireo_pool_t **pool);
} vireo_connection_pool_ops_t;

/**
 * @brief 使用完整逐对象依赖表构造，仅本模块测试使用
 *
 * @param[in] options
 *     公共正容量与总预算选项。
 * @param[in] ops
 *     非空完整表，仅借用至按值复制；context 需覆盖对象生命期。
 * @param[in,out] out_pool
 *     公共唯一 owner 合同。
 * @param[out] error
 *     可空公共阶段诊断。
 *
 * @return 公共构造结果；表缺失或不完整为 INVALID_ARGUMENT。
 *
 * @note errno、失败保持与预算沿公共合同，不向下游开放。
 */
vireo_result_t vireo_connection_pool_create_with_ops(
    vireo_connection_pool_options_t const *options, vireo_connection_pool_ops_t const *ops,
    vireo_connection_pool_t **out_pool, vireo_connection_pool_error_t *error);

/**
 * 仅本模块操作测试，按值复制；context 借用至空容器 destroy 返回。
 * 只包装 public connection 接口，不调用其私有 close hook 或布局。
 * inspect 只提交数值；destroy 的 OK/IO 必须真实消费 owner，BUSY 必须保持所有资源。
 * 不允许回调重入本池或返回违反上述消费合同的故障，不保证修复损坏依赖。
 */
typedef struct vireo_connection_pool_connection_ops {
    void *context;
    vireo_result_t (*inspect)(void *context, vireo_connection_t const *connection,
                              vireo_connection_info_t *out_info);
    vireo_result_t (*destroy)(void *context, vireo_connection_t **owner,
                              vireo_connection_error_t *error);
} vireo_connection_pool_connection_ops_t;

/**
 * @brief 使用独立连接依赖表创建，资源申请仍使用默认公开实现
 *
 * @param[in] options
 *     公共三项显式选项，调用期间借用。
 * @param[in] connection_ops
 *     非空完整表，context 生命周期覆盖容器。
 * @param[in,out] out_pool
 *     独立空 owner，沿公共构造合同。
 * @param[out] error
 *     可空资源诊断。
 *
 * @retval VIREO_OK
 *     完整空容器取得资源并复制表。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     表缺失或不完整；其余结果沿公共构造合同。
 *
 * @note 只用于本模块测试，保持入口 errno。
 */
vireo_result_t vireo_connection_pool_create_with_connection_ops(
    vireo_connection_pool_options_t const *options,
    vireo_connection_pool_connection_ops_t const *connection_ops,
    vireo_connection_pool_t **out_pool, vireo_connection_pool_error_t *error);

#endif /* VIREO_NET_CONNECTION_POOL_INTERNAL_H */
