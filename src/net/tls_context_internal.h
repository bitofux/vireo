/* 034-01 own 实现/测试资源缝；不作为下游合同，不安装或暴露 OpenSSL 布局。 */
#ifndef VIREO_NET_TLS_CONTEXT_INTERNAL_H
#define VIREO_NET_TLS_CONTEXT_INTERNAL_H

#include <openssl/ssl.h>
#include <vireo/net/tls_context.h>

/** 完整表短借到创建返回，按值保存；代码/context 活到回滚或销毁。
 *  回调不重入、不改输入/owner，资源回调返回真实资源或 NULL；库错误入当前线程队列。
 */
typedef struct vireo_tls_context_ops {
    void *context; /**< caller 借用的故障夹具，生产 NULL。 */
    void *(*allocate)(void *context, size_t size); /**< 正字节、基本对齐或 NULL。 */
    void (*deallocate)(void *context, void *pointer); /**< 配对释放，不失败。 */
    SSL_CTX *(*create_native)(void *context); /**< TLS_server_method context 或 NULL。 */
    BIO *(*create_bio)(void *context, void const *data, int size); /**< 只读内存 BIO 或 NULL。 */
} vireo_tls_context_ops_t;

struct vireo_tls_context {
    SSL_CTX *native; /**< 唯一配对 SSL_CTX_free；不转移给下游。 */
    size_t certificate_count; /**< 完整成功加载证书数，发布后固定。 */
    size_t max_wrapper_bytes; /**< 原包装预算，非第三方预算。 */
    vireo_tls_context_ops_t ops; /**< 值复制，保配对 allocator 及借用 context。 */
};

/**
 * @brief 用完整 own 操作表执行同一创建核心，供本层失败验证
 *
 * @param[in] options
 *     沿公共稳定材料/预算合同。
 * @param[in,out] out_context
 *     公共独立空 owner。
 * @param[out] error
 *     公共可空独立诊断。
 * @param[in] ops
 *     完整表；无效表 INVALID_ARGUMENT，其余同公共创建。
 *
 * @note 不作为公共 backend，不包含其他核心 private 头。
 */
vireo_result_t vireo_tls_context_create_with_ops(vireo_tls_context_options_t const *options,
    vireo_tls_context_t **out_context, vireo_tls_context_error_t *error,
    vireo_tls_context_ops_t const *ops);

#endif
