/* PROJECT: VIREO; FILE: directory_stat_worker_runtime_internal.h;
 * AUTHOR: bitofux; DATE: 2026-10-22; BRIEF: 本层公开依赖单次注入，不读其他层私有布局。 */
#ifndef VIREO_APP_DIRECTORY_STAT_WORKER_RUNTIME_INTERNAL_H
#define VIREO_APP_DIRECTORY_STAT_WORKER_RUNTIME_INTERNAL_H
#include "directory_stat_worker_runtime.h"
/** 单次借用操作表；各入口遵守对应公开owner/线程/报告合同，不保存或返回fatal。 */
typedef struct vireo_directory_stat_worker_runtime_ops {
    void *context; /**< 当前调用短借，可NULL。 */
    vireo_result_t (*create)(void *,vireo_directory_stat_worker_resources_t const *,
        vireo_directory_stat_worker_options_t const *,vireo_directory_stat_worker_t **); /**< 仅STAT create。 */
    vireo_result_t (*run)(void *,vireo_directory_stat_worker_t *,vireo_task_t const *,
        vireo_directory_stat_worker_report_t *); /**< 仅STAT run一次。 */
    vireo_result_t (*destroy)(void *,vireo_directory_stat_worker_t **,
        vireo_directory_stat_worker_cleanup_report_t *); /**< 原OS线程销毁。 */
    vireo_result_t (*auth_execute)(void *,vireo_auth_worker_runtime_t *,vireo_task_t const *); /**< 原auth callback。 */
} vireo_directory_stat_worker_runtime_ops_t;
/**
 * @brief 在同一callback内短借本层操作表，残留仍真实终止进程
 * @param[in,out] runtime 必需存活、已发布context，合同同普通execute。
 * @param[in] task 必需pool短借task，不保存/销毁。
 * @param[in] ops 必需完整操作表，借至返回，各入口正常返回且遵守公开合同。
 * @return 同普通execute；缺项INVALID_ARGUMENT，无业务调用。
 * @note 禁POSIX取消，保持正常返回errno；无fatal hook，不扩大依赖或资源寿命。
 */
vireo_result_t vireo_directory_stat_worker_runtime_execute_with(vireo_directory_stat_worker_runtime_t *runtime,
    vireo_task_t const *task,vireo_directory_stat_worker_runtime_ops_t const *ops);
#endif
