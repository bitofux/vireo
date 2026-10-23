/* PROJECT : VIREO; FILE : directory_list_completion_internal.h; AUTHOR : bitofux;
 * DATE : 2026-10-23; BRIEF : LIST发布的调用期分配/交接接点。 */
#ifndef VIREO_SERVICE_DIRECTORY_LIST_COMPLETION_INTERNAL_H
#define VIREO_SERVICE_DIRECTORY_LIST_COMPLETION_INTERNAL_H
#include <vireo/service/directory_list_completion.h>
typedef struct vireo_directory_list_completion_ops {
    void *context;                     /**< 短借至publish返回。 */
    void *(*allocate)(void *, size_t); /**< 返回独占工作区或NULL。 */
    void (*release)(void *, void *);   /**< 只消费本表分配且已擦除的区。 */
    vireo_result_t (*publish)(void *, const vireo_task_t *, vireo_result_t, vireo_status_t,
                              const void *, size_t, size_t, vireo_completion_queue_t *,
                              vireo_notifier_t *, vireo_completion_t **,
                              vireo_completion_publish_report_t *); /**< 原公开发布合同。 */
} vireo_directory_list_completion_ops_t;
vireo_result_t vireo_directory_list_completion_publish_with(
    const vireo_task_t *, uint32_t, const vireo_directory_list_task_result_t *, size_t,
    vireo_completion_queue_t *, vireo_notifier_t *, vireo_completion_t **,
    vireo_directory_list_completion_publish_report_t *,
    const vireo_directory_list_completion_ops_t *);
#endif
