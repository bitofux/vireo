/* PROJECT : VIREO
 * FILE : auth_worker_runtime_internal.h
 * AUTHOR : bitofux
 * DATE : 2026-10-20
 * BRIEF : 应用本模块公开依赖的局部注入边界；不读取其他模块私有状态。 */
#ifndef VIREO_APP_AUTH_WORKER_RUNTIME_INTERNAL_H
#define VIREO_APP_AUTH_WORKER_RUNTIME_INTERNAL_H
#include "auth_worker_runtime.h"
/** 独立单调用的借用操作表；不保存到共享runtime，测试可为每worker提供独立context。 */
typedef struct vireo_auth_worker_runtime_ops {
    void *context; /**< 仅本次execute_with短借，不随task或runtime保存。 */
    vireo_result_t (*create)(void *,vireo_auth_worker_resources_t const *,
        vireo_auth_worker_options_t const *,vireo_auth_worker_t **); /**< 同18原所有权合同。 */
    vireo_result_t (*run)(void *,vireo_auth_worker_t *,vireo_task_t const *,
        vireo_auth_worker_report_t *); /**< 同18一次执行和去敏报告合同。 */
    vireo_result_t (*destroy)(void *,vireo_auth_worker_t **,
        vireo_auth_worker_cleanup_report_t *); /**< 同18原线程清理、非OK也可能清源。 */
} vireo_auth_worker_runtime_ops_t;
/**
 * @brief 本模块操作表驱动的同一次callback，不改变公开依赖或终止政策
 * @param[in,out] runtime 必需已初始化存活context，线程及借用同普通execute。
 * @param[in] task 必需该次pool短借task，不保存/销毁。
 * @param[in] ops 必需完整函数表，借至返回，各依赖严格遵守18原owner合同。
 * @return 同execute；操作表缺项返回INVALID_ARGUMENT且无依赖调用，不发布健康结论。
 * @note 正常返回保持errno；残留仍真实_Exit，不提供可返回fatal钩子。
 */
vireo_result_t vireo_auth_worker_runtime_execute_with(vireo_auth_worker_runtime_t *runtime,
    vireo_task_t const *task,vireo_auth_worker_runtime_ops_t const *ops);
#endif
