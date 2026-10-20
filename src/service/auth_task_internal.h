/* PROJECT : VIREO
 * FILE : auth_task_internal.h
 * AUTHOR : bitofux
 * DATE : 2026-10-20
 * BRIEF : 仅本模块测试使用的service边界注入，不替代生产默认调用。
 */
#ifndef VIREO_SERVICE_AUTH_TASK_INTERNAL_H
#define VIREO_SERVICE_AUTH_TASK_INTERNAL_H
#include <vireo/service/auth_task.h>

/** 四个同步借用调用；不得保留request、改写task或泄漏秘密。 */
typedef struct vireo_auth_task_ops {
    vireo_result_t (*registration)(vireo_mysql_user_repository_t *, vireo_auth_password_gate_t *,
        vireo_auth_registration_request_t const *, uint32_t,
        vireo_mysql_registration_report_t *, vireo_mysql_user_repository_error_t *);
    vireo_result_t (*login)(vireo_mysql_user_repository_t *, vireo_auth_password_gate_t *,
        vireo_auth_login_verifier_t const *, vireo_auth_login_request_t const *, uint32_t,
        vireo_auth_login_result_t *, vireo_mysql_user_repository_error_t *);
    vireo_result_t (*resume)(vireo_mysql_user_repository_t *,vireo_session_token_t const *,uint64_t,uint32_t,
        vireo_mysql_session_identity_t *,vireo_mysql_session_report_t *,vireo_mysql_user_repository_error_t *);
    vireo_result_t (*logout)(vireo_mysql_user_repository_t *,vireo_mysql_logout_input_t const *,uint32_t,
        vireo_mysql_logout_report_t *,vireo_mysql_user_repository_error_t *);
} vireo_auth_task_ops_t;

/** 私有注入入口，其余合同同公共execute；NULL ops/函数按必需地址错误保持out。 */
vireo_result_t vireo_auth_task_execute_with(vireo_task_t const *task,
    vireo_auth_task_context_t const *context, vireo_auth_task_options_t const *options,
    vireo_mysql_user_repository_t *repository, vireo_auth_password_gate_t *gate,
    vireo_auth_login_verifier_t const *verifier, vireo_auth_task_result_t *out,
    vireo_auth_task_ops_t const *ops);
#endif
