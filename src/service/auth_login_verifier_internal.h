/*
 * PROJECT : VIREO
 * FILE    : auth_login_verifier_internal.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-19
 * BRIEF   : 本service的不可变状态与显式测试依赖边界。
 */
#ifndef VIREO_SERVICE_AUTH_LOGIN_VERIFIER_INTERNAL_H
#define VIREO_SERVICE_AUTH_LOGIN_VERIFIER_INTERNAL_H

#include <vireo/service/auth_login_verifier.h>

/** @brief 构造时复制的本组件依赖；context借到destroy，回调正常返回且支持所需并发。 */
typedef struct vireo_auth_login_verifier_runtime {
    void *context; /**< 测试拥有的上下文；native为NULL，不转移所有权。 */
    void *(*allocate)(void *context, size_t bytes); /**< 分配对齐的独占对象，失败NULL。 */
    void (*deallocate)(void *context, void *memory); /**< 配对释放已显式清零对象，不抛出控制流。 */
    vireo_result_t (*random)(void *context, unsigned char bytes[32]); /**< 生成32安全随机字节；失败可能部分写入。 */
    vireo_result_t (*create)(void *context, vireo_auth_password_gate_t *gate,
        void const *password, size_t length, char *encoded, size_t capacity,
        size_t *written); /**< 同041-02create；正常返回前完成KDF与额度归还。 */
    vireo_result_t (*verify)(void *context, vireo_auth_password_gate_t *gate,
        void const *password, size_t length, char const *encoded, size_t encoded_length,
        bool *matches); /**< 同041-02verify；不保留指针，可并发调用。 */
} vireo_auth_login_verifier_runtime_t;

/** @brief 成功发布后无可变字段、锁、明文密码或外部资源owner。 */
struct vireo_auth_login_verifier {
    char dummy_hash[VIREO_PASSWORD_ENCODED_CAPACITY]; /**< 内嵌替代PHC，带NUL，销毁时擦除。 */
    size_t dummy_hash_length; /**< 有效前缀长度1..127，不含NUL。 */
    vireo_auth_login_verifier_runtime_t runtime; /**< 按值复制的依赖，context只借用。 */
};

/**
 * @brief 仅本组件own测试使用的构造接点，不替换任何全局表。
 * @param[in,out] gate 同公开create，短借至返回。
 * @param[in,out] out 同公开create，独占空owner。
 * @param[in] runtime 必需完整依赖表，按值复制，context须存活至destroy完成。
 * @retval VIREO_OK 成功发布对象。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 地址/空owner/依赖函数不满足合同。
 * @retval VIREO_RESULT_NO_MEMORY 分配或KDF失败。
 * @retval VIREO_RESULT_IO 安全随机源失败。
 * @retval VIREO_RESULT_BUSY 共享gate无额度。
 * @retval VIREO_RESULT_CANCELLED 共享gate已关闭。
 * @retval VIREO_RESULT_INTERNAL 生成依赖错误或生成结果不满足固定不变量。
 * @note 输出保持/清理/errno/并发前提同公开create；仅包含本层私有头。
 */
vireo_result_t vireo_auth_login_verifier_create_with_runtime(vireo_auth_password_gate_t *gate,
    vireo_auth_login_verifier_t **out, vireo_auth_login_verifier_runtime_t const *runtime);

#endif
