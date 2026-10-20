/* PROJECT : VIREO; FILE : auth_worker_internal.h; AUTHOR : bitofux; DATE : 2026-10-20.
 * 仅本模块测试的公开依赖替身；不接触依赖私有布局。 */
#ifndef VIREO_SERVICE_AUTH_WORKER_INTERNAL_H
#define VIREO_SERVICE_AUTH_WORKER_INTERNAL_H
#include <vireo/service/auth_worker.h>

/** 操作表复制，context借至destroy；失败/交接必须遵守各公开依赖owner合同。 */
typedef struct vireo_auth_worker_ops {
    void *context;
    void *(*allocate)(void *, size_t);
    void (*release)(void *, void *);
    vireo_result_t (*attach)(void *, vireo_mysql_runtime_t *, vireo_mysql_thread_t **, vireo_mysql_error_t *);
    vireo_result_t (*repository_create)(void *, vireo_mysql_thread_t *, vireo_mysql_pool_t *,
        vireo_password_policy_t const *, vireo_mysql_user_repository_t **, vireo_mysql_user_repository_error_t *);
    vireo_result_t (*capture)(void *, vireo_task_t const *, uint64_t, uint64_t, vireo_auth_task_options_t const *,
        vireo_auth_task_context_t *, vireo_auth_context_error_t *);
    vireo_result_t (*execute)(void *, vireo_task_t const *, vireo_auth_task_context_t const *,
        vireo_auth_task_options_t const *, vireo_mysql_user_repository_t *, vireo_auth_password_gate_t *,
        vireo_auth_login_verifier_t const *, vireo_auth_task_result_t *);
    vireo_result_t (*repository_destroy)(void *, vireo_mysql_user_repository_t **, vireo_mysql_user_repository_error_t *);
    vireo_result_t (*detach)(void *, vireo_mysql_thread_t **);
    vireo_result_t (*publish)(void *, vireo_task_t const *, vireo_auth_task_result_t const *, size_t,
        vireo_completion_queue_t *, vireo_notifier_t *, vireo_completion_t **,
        vireo_auth_completion_publish_report_t *);
    vireo_result_t (*completion_destroy)(void *, vireo_completion_t **);
} vireo_auth_worker_ops_t;

/** 本层局部注入，完整ops必需；其余合同同公开create。 */
vireo_result_t vireo_auth_worker_create_with(vireo_auth_worker_resources_t const *resources,
    vireo_auth_worker_options_t const *options, vireo_auth_worker_t **owner,
    vireo_auth_worker_ops_t const *ops);
#endif
