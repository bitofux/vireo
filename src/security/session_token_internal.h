#ifndef VIREO_SECURITY_SESSION_TOKEN_INTERNAL_H
#define VIREO_SECURITY_SESSION_TOKEN_INTERNAL_H

#include <vireo/security/session_token.h>
#include <openssl/evp.h>
#include <stddef.h>

/* 本组件显式借用的运行边界；无可变全局表，不替换第三方函数。
 * 测试可以围绕真实EVP上下文注入故障；不属于公共ABI。 */
typedef struct vireo_session_token_runtime {
    void *context; /**< 每次调用借用的运行/测试上下文。 */
    int (*random_bytes)(void *context, unsigned char *out, int length);
    EVP_MD_CTX *(*digest_new)(void *context);
    void (*digest_free)(void *context, EVP_MD_CTX *digest);
    int (*digest_init)(void *context, EVP_MD_CTX *digest);
    int (*digest_update)(void *context, EVP_MD_CTX *digest, void const *data, size_t length);
    int (*digest_final)(void *context, EVP_MD_CTX *digest, unsigned char *out, unsigned int *length);
} vireo_session_token_runtime_t;

vireo_result_t vireo_session_token_generate_with_runtime(vireo_session_token_t *token,
    vireo_session_token_digest_t *digest, vireo_session_token_runtime_t const *runtime);
vireo_result_t vireo_session_token_digest_with_runtime(vireo_session_token_t const *token,
    vireo_session_token_digest_t *digest, vireo_session_token_runtime_t const *runtime);

#endif
