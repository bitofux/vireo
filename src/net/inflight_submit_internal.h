/*
 * PROJECT : VIREO
 * FILE    : inflight_submit_internal.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-13
 * BRIEF   : 仅本核心的公开依赖故障入口
 */
#ifndef VIREO_NET_INFLIGHT_SUBMIT_INTERNAL_H
#define VIREO_NET_INFLIGHT_SUBMIT_INTERNAL_H

#include <vireo/net/inflight_submit.h>

/** 短借操作表；操作须保持对应公开依赖的所有权/报告/失败保持合同。 */
typedef struct vireo_inflight_submit_operations {
    void *context; /**< 可空脚本上下文，短借至本次调用结束，不保存。 */
    vireo_result_t (*submit)(void *context, vireo_thread_pool_t *pool,
        vireo_task_t **task_owner, vireo_thread_pool_submit_report_t *report); /**< 必需，一次真实提交模型。 */
    vireo_result_t (*take)(void *context, vireo_inflight_store_t *store,
        vireo_task_metadata_t key, vireo_task_metadata_t *out,
        vireo_inflight_stage_t *stage); /**< 必需，成功真实移除，失败保持表。 */
} vireo_inflight_submit_operations_t;

/**
 * @brief
 *     沿公共合同执行，用本核心操作表核验已转移异常与撤销失败。
 *
 * @param[in,out] store
 *     与公共入口相同的 Reactor 表。
 * @param[in] server
 *     与公共入口相同的资源根。
 * @param[in,out] pool
 *     与公共入口相同的串行管理池。
 * @param[in] max_client_requests
 *     与公共入口相同的显式限额。
 * @param[in,out] task_owner
 *     与公共入口相同的唯一 owner。
 * @param[in] operations
 *     必需稳定操作表，两操作非空；不得重入或访问外部模块私有布局。
 * @param[out] report
 *     必需独立报告，每可写路径覆盖。
 *
 * @return
 *     公共原结果；额外非法操作表 INVALID_ARGUMENT/NONE，全部 errno 保持。
 */
vireo_result_t vireo_inflight_store_try_submit_with_operations(vireo_inflight_store_t *store,
    vireo_tcp_server_t const *server, vireo_thread_pool_t *pool,
    size_t max_client_requests, vireo_task_t **task_owner,
    vireo_inflight_submit_operations_t const *operations,
    vireo_inflight_submit_report_t *report);

#endif
