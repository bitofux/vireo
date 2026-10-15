/*
 * PROJECT : VIREO
 * FILE    : inflight_cancel_internal.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-13
 * BRIEF   : 仅本核心的引用耗尽依赖模型
 */
#ifndef VIREO_NET_INFLIGHT_CANCEL_INTERNAL_H
#define VIREO_NET_INFLIGHT_CANCEL_INTERNAL_H

#include <vireo/net/inflight_store.h>

/** 操作表短借；不得重入，成功真实取得引用，失败保持输出/引用义务。 */
typedef struct vireo_inflight_cancel_operations {
    void *context; /**< 可空局部上下文，不保存进表或交给 worker。 */
    vireo_result_t (*retain_task)(void *context, vireo_task_t const *task,
        vireo_task_cancel_t **out); /**< 必需；无关联 NOT_FOUND，耗尽 OVERFLOW。 */
    vireo_result_t (*retain_cancel)(void *context, vireo_task_cancel_t *cancel,
        vireo_task_cancel_t **out); /**< 必需；成功新引用，失败保源与输出。 */
} vireo_inflight_cancel_operations_t;

/**
 * @brief
 *     本核心仅引用取得适配，其余合同沿公共任务登记。
 *
 * @param[in,out] store
 *     必需 Reactor 独占表。
 * @param[in] server
 *     必需公开客户资源根。
 * @param[in] task
 *     必需存活只借 task，不移动/销毁。
 * @param[in] max_client_requests
 *     显式正限额。
 * @param[in] operations
 *     必需完整稳定操作表，短借至返回。
 * @param[out] stage
 *     可空独立诊断，每路径覆盖。
 *
 * @return
 *     公共原结果；非法操作表 INVALID_ARGUMENT/NONE，errno 保持。
 */
vireo_result_t vireo_inflight_store_register_task_limited_with_operations(
    vireo_inflight_store_t *store, vireo_tcp_server_t const *server,
    vireo_task_t const *task, size_t max_client_requests,
    vireo_inflight_cancel_operations_t const *operations, vireo_inflight_stage_t *stage);

/**
 * @brief
 *     本核心引用耗尽适配，其余合同沿公共引用查询。
 *
 * @param[in] store
 *     必需 Reactor 独占表，只借至返回。
 * @param[in] key
 *     完整有效请求身份。
 * @param[out] out_cancel
 *     必需入口空引用 owner，成功由 caller 释放。
 * @param[in] operations
 *     必需完整稳定操作表，短借至返回。
 * @param[out] stage
 *     可空独立诊断，每路径覆盖。
 *
 * @return
 *     公共原结果；非法操作表 INVALID_ARGUMENT/NONE，errno 保持。
 */
vireo_result_t vireo_inflight_store_retain_cancel_with_operations(
    vireo_inflight_store_t const *store, vireo_task_metadata_t key,
    vireo_task_cancel_t **out_cancel, vireo_inflight_cancel_operations_t const *operations,
    vireo_inflight_stage_t *stage);

#endif
