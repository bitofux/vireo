/* PROJECT : VIREO
 * FILE : auth_service_internal.h
 * AUTHOR : bitofux
 * DATE : 2026-10-19
 * BRIEF : 本组件单次工作区及显式测试依赖，不属于公共API。
 */
#ifndef VIREO_SERVICE_AUTH_SERVICE_INTERNAL_H
#define VIREO_SERVICE_AUTH_SERVICE_INTERNAL_H
#include <vireo/service/auth_service.h>
#include <vireo/service/auth_username.h>

/** @brief 本次调用独占的秘密工作区；统一出口擦全部字节，不保存任何长期owner。 */
typedef struct vireo_auth_service_workspace {
    vireo_auth_username_t username; /**< 规范化身份拥有值，只在本次调用存活。 */
    char phc[VIREO_PASSWORD_ENCODED_CAPACITY]; /**< 注册PHC；下层消费后擦除。 */
    size_t phc_length; /**< 注册PHC有效长度，不含NUL。 */
    vireo_mysql_user_credentials_t credentials; /**< 查询发布的独立秘密快照。 */
    vireo_mysql_registration_input_t registration; /**< 只短借本工作区的用户名/PHC。 */
    vireo_mysql_login_input_t login; /**< 含摘要副本，PHC短借credentials。 */
    vireo_session_token_t token; /**< 成功提交前禁止发布的本地bearer。 */
    vireo_session_token_digest_t digest; /**< 原始摘要，另有login内嵌副本。 */
    bool authenticated; /**< 仅当前验密快照结果，不表示事务成功。 */
} vireo_auth_service_workspace_t;

/** @brief 短借至单次调用返回的本组件依赖；回调不得跳出/保存借用指针。 */
typedef struct vireo_auth_service_runtime {
    void *context; /**< 测试拥有的同步上下文；native为NULL。 */
    vireo_result_t (*hash)(void *, vireo_auth_password_gate_t *, const void *, size_t,
        char *, size_t, size_t *); /**< 同公开hash_create，失败可能写临时区。 */
    vireo_result_t (*registration)(void *, vireo_mysql_user_repository_t *,
        const vireo_mysql_registration_input_t *, uint32_t, vireo_mysql_registration_report_t *,
        vireo_mysql_user_repository_error_t *); /**< 同repository_register。 */
    vireo_result_t (*lookup)(void *, vireo_mysql_user_repository_t *, const void *, size_t,
        uint32_t, vireo_mysql_user_credentials_t *, vireo_mysql_credentials_report_t *,
        vireo_mysql_user_repository_error_t *); /**< 同find_credentials。 */
    vireo_result_t (*verify)(void *, const vireo_auth_login_verifier_t *,
        vireo_auth_password_gate_t *, const vireo_mysql_user_credentials_t *, const void *,
        size_t, bool *); /**< 同verifier_verify，合法缺失才允许NULL凭据。 */
    vireo_result_t (*token)(void *, vireo_session_token_t *, vireo_session_token_digest_t *);
        /**< 同token_generate，无弱随机/内部重试。 */
    vireo_result_t (*login)(void *, vireo_mysql_user_repository_t *, const vireo_mysql_login_input_t *,
        uint32_t, vireo_mysql_login_report_t *, vireo_mysql_user_repository_error_t *);
        /**< 同repository_login，提交事实与返回码独立。 */
    void (*cleared)(void *, const vireo_auth_service_workspace_t *);
        /**< 可NULL；只观察已擦除且仍live的栈区，不得保存地址。 */
} vireo_auth_service_runtime_t;

/**
 * @brief 单次注册的显式私有依赖接点。
 * @param[in,out] repository 同公开register。
 * @param[in,out] gate 同公开register。
 * @param[in] request 同公开register。
 * @param[in] timeout_ms 同公开register。
 * @param[out] report 同公开register。
 * @param[out] error 同公开register。
 * @param[in] runtime 必需完整依赖，短借至返回；不替换全局状态。
 * @return 同公开register；runtime缺回调为INVALID_ARGUMENT且保持输出。
 * @note errno/线程/所有权同公开入口；cleared仅在runtime完整时于擦除后调用。
 */
vireo_result_t vireo_auth_service_register_with_runtime(vireo_mysql_user_repository_t *repository,
    vireo_auth_password_gate_t *gate, const vireo_auth_registration_request_t *request,
    uint32_t timeout_ms, vireo_mysql_registration_report_t *report,
    vireo_mysql_user_repository_error_t *error, const vireo_auth_service_runtime_t *runtime);

/**
 * @brief 单次登录的显式私有依赖接点。
 * @param[in,out] repository 同公开login。
 * @param[in,out] gate 同公开login。
 * @param[in] verifier 同公开login。
 * @param[in] request 同公开login。
 * @param[in] timeout_ms 同公开login。
 * @param[in,out] result 同公开login。
 * @param[out] error 同公开login。
 * @param[in] runtime 必需完整依赖，短借至返回；回调遵守所替代公开合同。
 * @return 同公开login；runtime缺回调为INVALID_ARGUMENT且保持输出。
 * @note errno/线程/所有权同公开入口，不能借测试接点访问其他模块私有布局。
 */
vireo_result_t vireo_auth_service_login_with_runtime(vireo_mysql_user_repository_t *repository,
    vireo_auth_password_gate_t *gate, const vireo_auth_login_verifier_t *verifier,
    const vireo_auth_login_request_t *request, uint32_t timeout_ms,
    vireo_auth_login_result_t *result, vireo_mysql_user_repository_error_t *error,
    const vireo_auth_service_runtime_t *runtime);
#endif
