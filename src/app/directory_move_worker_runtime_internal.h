/* PROJECT : VIREO; FILE : directory_move_worker_runtime_internal.h;
 * AUTHOR : bitofux; DATE : 2026-10-25; BRIEF : 同app层单次依赖注入，不改变fatal策略。 */
#ifndef VIREO_APP_DIRECTORY_MOVE_WORKER_RUNTIME_INTERNAL_H
#define VIREO_APP_DIRECTORY_MOVE_WORKER_RUNTIME_INTERNAL_H
#include "directory_move_worker_runtime.h"
/** @brief 调用期短借表；只调用04公开owner/线程/报告合同，不读service私有布局。 */
typedef struct vireo_directory_move_worker_runtime_ops {
    void *context; /**< 可NULL，借至execute_with返回。 */
    vireo_result_t (*create)(void *, const vireo_directory_move_worker_resources_t *,
        const vireo_directory_move_worker_options_t *, vireo_directory_move_worker_t **); /**< 创建一次。 */
    vireo_result_t (*run)(void *, vireo_directory_move_worker_t *, const vireo_task_t *,
        vireo_directory_move_worker_report_t *); /**< 原线程至多一次run。 */
    vireo_result_t (*destroy)(void *, vireo_directory_move_worker_t **,
        vireo_directory_move_worker_cleanup_report_t *); /**< 原线程单次清理。 */
    vireo_result_t (*previous_execute)(void *, vireo_directory_mkdir_worker_runtime_t *,
        const vireo_task_t *); /**< 仅已注册前八标签委托。 */
} vireo_directory_move_worker_runtime_ops_t;
/**
 * @brief 同callback短借本层操作表，残留仍真实终止进程
 * @param[in,out] runtime
 *     必需存活已发布context，合同同execute。
 * @param[in] task
 *     必需pool短借task，不保存/销毁。
 * @param[in] ops
 *     必需完整表，借至返回，各入口遵守对应公开合同。
 * @return 同execute；缺项INVALID_ARGUMENT，无业务调用。
 * @note 禁POSIX取消，正常返回保持errno；无fatal hook，不扩大借用寿命。
 */
vireo_result_t vireo_directory_move_worker_runtime_execute_with(
    vireo_directory_move_worker_runtime_t *runtime, const vireo_task_t *task,
    const vireo_directory_move_worker_runtime_ops_t *ops);
#endif
