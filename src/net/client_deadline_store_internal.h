/*
 * PROJECT : VIREO
 * FILE    : client_deadline_store_internal.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-10
 * BRIEF   : 此模块负责：
 * -- 限定本层的固定容量数值记录保存、按完整身份查询及显式转出私有布局或测试依赖
 * -- 仅本模块实现及测试使用，不供下游依赖布局
 */
#ifndef VIREO_NET_CLIENT_DEADLINE_STORE_INTERNAL_H
#define VIREO_NET_CLIENT_DEADLINE_STORE_INTERNAL_H

#include <vireo/net/client_deadline_store.h>

/** 一次申请拥有控制块与柔性记录数组，无任何外部资源借用。 */
struct vireo_client_deadline_store {
    size_t capacity;         /**< 创建后稳定的数组槽数，正且不超过公共硬限。 */
    size_t count;            /**< 完整非空记录数；成功保存加一、转出减一。 */
    size_t allocation_bytes; /**< sizeof 控制块加完整数组请求字节，受检后稳定。 */
    size_t max_memory_bytes; /**< 创建时正预算，不计外部资源或 allocator 开销。 */
    vireo_client_deadline_binding_t
        records[]; /**< 拥有的固定数组，全零空槽；索引与 timer 槽独立。 */
};

/**
 * @brief 本层测试用同一构造路径的单点申请注入，不是业务回调
 *
 * @param[in] options
 *     沿公共 create 合同。
 * @param[in,out] out_store
 *     沿公共 create 的空拥有者合同。
 * @param[in] allocate
 *     必需函数，只调用一次；成功返回至少 bytes 字节的 malloc 兼容正确对齐独占内存。
 *     返回 NULL 为申请失败，不能改写借用参数或重入；成功内存最终由标准 free 消费。
 * @param[in,out] context
 *     可空，只借至构造返回，不保存，不处于新申请内。
 *
 * @note
 *     失败、错误顺序、errno 沿 public create，额外空函数为 INVALID_ARGUMENT。
 *     只模拟本层申请失败，不证明内核 OOM；生产使用标准 malloc。
 */
vireo_result_t vireo_client_deadline_store_create_runtime(
    vireo_client_deadline_store_options_t const *options, vireo_client_deadline_store_t **out_store,
    void *(*allocate)(size_t bytes, void *context), void *context);

#endif /* VIREO_NET_CLIENT_DEADLINE_STORE_INTERNAL_H */
