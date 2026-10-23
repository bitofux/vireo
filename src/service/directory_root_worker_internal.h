/*
 * PROJECT : VIREO
 * FILE    : directory_root_worker_internal.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-22
 * BRIEF   : 根查询内部桥接与原线程所有权。
 */
#ifndef VIREO_SERVICE_DIRECTORY_ROOT_WORKER_INTERNAL_H
#define VIREO_SERVICE_DIRECTORY_ROOT_WORKER_INTERNAL_H
#include <vireo/service/directory_root_worker.h>
/** 表按值复制，context长期借至destroy；不使用其他组件私有布局。 */
typedef struct vireo_directory_root_worker_ops {
    void *context;                     /**< 调用者保活到worker销毁的故障上下文。 */
    void *(*allocate)(void *, size_t); /**< 控制块分配，失败返回NULL，不发布owner。 */
    void (*release)(void *, void *);   /**< 消费控制块，只在全部子owner空后调用。 */
    vireo_result_t (*attach)(
        void *, vireo_mysql_runtime_t *, vireo_mysql_thread_t **,
        vireo_mysql_error_t *); /**< 沿公开attach创建原线程guard，可保留失败诊断。 */
    vireo_result_t (*repository_create)(
        void *, vireo_mysql_thread_t *, vireo_mysql_pool_t *, vireo_mysql_node_repository_t **,
        vireo_mysql_node_error_t *); /**< 借guard/pool创建同线程repo，不接管外部资源。 */
    vireo_result_t (*clock)(void *, uint64_t *,
                            vireo_clock_error_t *); /**< 采一次同域MONOTONIC，不申请期限延长。 */
    vireo_result_t (*execute)(
        void *, const vireo_task_t *, const vireo_directory_root_task_options_t *,
        vireo_mysql_node_repository_t *, uint64_t,
        vireo_directory_root_task_result_t *); /**< 同步执行一次任务，原结果与返回码一致。 */
    vireo_result_t (*repository_destroy)(
        void *, vireo_mysql_node_repository_t **,
        vireo_mysql_node_error_t *); /**< 一次尝试清repo，失败仍按实际owner判断。 */
    vireo_result_t (*detach)(void *,
                             vireo_mysql_thread_t **); /**< repo空后清guard，返回码不证明消费。 */
    vireo_result_t (*publish)(void *, const vireo_task_t *, uint32_t,
                              const vireo_directory_root_task_result_t *, size_t,
                              vireo_completion_queue_t *, vireo_notifier_t *, vireo_completion_t **,
                              vireo_directory_root_completion_publish_report_t
                                  *); /**< 真实队列交接一次，未交接owner写回worker。 */
    vireo_result_t (*completion_destroy)(
        void *, vireo_completion_t **); /**< 仅消费未交接completion，失败按实际owner判断。 */
} vireo_directory_root_worker_ops_t;
/** 同公开create，额外完整同步操作表；所有权/线程/errno规则相同。 */
vireo_result_t vireo_directory_root_worker_create_with(
    const vireo_directory_root_worker_resources_t *, const vireo_directory_root_worker_options_t *,
    vireo_directory_root_worker_t **, const vireo_directory_root_worker_ops_t *);
#endif
