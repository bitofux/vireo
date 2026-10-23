/* PROJECT : VIREO; AUTHOR : bitofux; DATE : 2026-10-22;
 * BRIEF : 实例独占的OpenSSL依赖接点，无可变全局替换。 */
#ifndef VIREO_SECURITY_PAGE_TOKEN_INTERNAL_H
#define VIREO_SECURITY_PAGE_TOKEN_INTERNAL_H
#include <openssl/evp.h>
#include <stddef.h>
#include <vireo/security/page_token.h>

/** @brief key复制回调表；context由测试/caller保活到key销毁，ctx每调用独占。 */
typedef struct vireo_page_token_runtime {
    void *context;
    void *(*allocate)(void *, size_t);
    void (*free_memory)(void *, void *);
    EVP_MAC *(*fetch)(void *);
    void (*free_mac)(void *, EVP_MAC *);
    int (*random_bytes)(void *, unsigned char *, int);
    EVP_MAC_CTX *(*new_context)(void *, EVP_MAC *);
    void (*free_context)(void *, EVP_MAC_CTX *);
    int (*init)(void *, EVP_MAC_CTX *, const unsigned char *, size_t);
    int (*update)(void *, EVP_MAC_CTX *, const unsigned char *, size_t);
    int (*final)(void *, EVP_MAC_CTX *, unsigned char *, size_t *, size_t);
} vireo_page_token_runtime_t;

/** @brief 私有布局仅供实现/资源故障检查；所有字段创建后不变。 */
struct vireo_page_token_key {
    unsigned char secret[32];
    uint32_t id;
    EVP_MAC *algorithm;
    vireo_page_token_runtime_t runtime;
};

/** @brief 私有依赖创建；输出/errno同公开create，完整runtime及context借至destroy。 */
vireo_result_t vireo_page_token_key_create_with_runtime(vireo_page_token_key_t **out,
                                                        const vireo_page_token_runtime_t *runtime);
#endif
