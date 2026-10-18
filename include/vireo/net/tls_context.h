/*
- PROJECT : VIREO
- FILE    : tls_context.h
- BRIEF   : 服务器 TLS 1.3 配置资源根；不提供连接、fd 或网络收发。
 */
#ifndef VIREO_NET_TLS_CONTEXT_H
#define VIREO_NET_TLS_CONTEXT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <vireo/base/result.h>

#define VIREO_TLS_CONTEXT_MAX_CERTIFICATE_BYTES ((size_t)1048576)
#define VIREO_TLS_CONTEXT_MAX_PRIVATE_KEY_BYTES ((size_t)65536)
#define VIREO_TLS_CONTEXT_MAX_WRAPPER_BYTES ((size_t)67108864)
#define VIREO_TLS_CONTEXT_PROTOCOL_1_3 UINT16_C(0x0304)

/** 唯一 owner；无公开布局、native 指针或共享所有权。 */
typedef struct vireo_tls_context vireo_tls_context_t;

/** 全部显式提供；PEM 只借到 create 返回，不保存源地址或原文副本。 */
typedef struct vireo_tls_context_options {
    unsigned char const *certificate_chain; /**< 叶子在前的 CERTIFICATE PEM 链。 */
    size_t certificate_chain_size;          /**< 正字节数，至多 1 MiB。 */
    unsigned char const *private_key;       /**< 单个未加密 PEM 私钥。 */
    size_t private_key_size;                /**< 正字节数，至多 64 KiB。 */
    size_t max_wrapper_bytes;               /**< 正包装预算，至多 64 MiB。 */
} vireo_tls_context_options_t;

/** 独立逻辑快照，不保活；版本数值不是本项目 wire 字段。 */
typedef struct vireo_tls_context_info {
    uint16_t minimum_protocol_version; /**< 固定 TLS 1.3。 */
    uint16_t maximum_protocol_version; /**< 固定 TLS 1.3。 */
    bool early_data_enabled;          /**< 固定 false。 */
    bool session_cache_enabled;       /**< 固定 false。 */
    bool session_tickets_enabled;     /**< 固定 false。 */
    bool client_certificate_required; /**< 固定 false，用户认证另层负责。 */
    size_t certificate_count;         /**< 已加载的叶子与中间证书数量。 */
    size_t wrapper_bytes;             /**< 本层控制块的实际请求字节。 */
    size_t max_wrapper_bytes;         /**< 原显式包装预算。 */
} vireo_tls_context_info_t;

typedef enum vireo_tls_context_stage {
    VIREO_TLS_CONTEXT_STAGE_NONE = 0,
    VIREO_TLS_CONTEXT_STAGE_ALLOCATE_WRAPPER = 1,
    VIREO_TLS_CONTEXT_STAGE_CREATE_NATIVE = 2,
    VIREO_TLS_CONTEXT_STAGE_CONFIGURE = 3,
    VIREO_TLS_CONTEXT_STAGE_CERTIFICATE = 4,
    VIREO_TLS_CONTEXT_STAGE_PRIVATE_KEY = 5,
    VIREO_TLS_CONTEXT_STAGE_MATCH_KEY = 6,
    VIREO_TLS_CONTEXT_STAGE_INSPECT = 7
} vireo_tls_context_stage_t;

/** 每可写路径覆盖逻辑字段；数值原因不含私钥/证书文本或错误字符串借用。 */
typedef struct vireo_tls_context_error {
    vireo_tls_context_stage_t stage; /**< 失败步骤；成功/基本拒绝为 NONE。 */
    uint64_t openssl_error_code;     /**< 本次首个 OpenSSL 原因码，没有则 0。 */
    bool has_more_errors;            /**< 本次还消费了其他原因码。 */
} vireo_tls_context_error_t;

/**
 * @brief 从稳定 PEM 字节构造唯一服务器 context，最后一次性发布 owner
 *
 * @param[in] options
 *     非空稳定选项；链叶子在前，各块之间/末尾仅允许 ASCII 空白。
 *     私钥接受 PRIVATE KEY、RSA PRIVATE KEY、EC PRIVATE KEY 或 DSA PRIVATE KEY；
 *     加密材料拒绝，不提示密码。源字节须真实可读，源的管理/擦除仍归 caller。
 * @param[in,out] out_context
 *     独立空 owner 地址，入口 *out_context 必须为 NULL；成功后最终 destroy。
 * @param[out] error
 *     可空独立诊断；NULL 不改变操作或清理。
 *
 * @retval VIREO_OK
 *     完整加载材料、匹配私钥并发布固定配置的 context。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址为空、owner 非空、长度/预算为零，或 PEM/密钥匹配不合规。
 * @retval VIREO_RESULT_OVERFLOW
 *     非零输入长度不能表示为 OpenSSL 所需 int；先于材料硬限。
 * @retval VIREO_RESULT_RANGE
 *     可表示长度超过硬限，或包装预算超限/不足。
 * @retval VIREO_RESULT_NO_MEMORY
 *     本层申请失败，或捕获到 OpenSSL 明确的 malloc failure。
 * @retval VIREO_RESULT_INTERNAL
 *     不能可靠细分的库资源/配置异常。
 *
 * @note 固定 min=max TLS1.3，禁 early data、session cache、ticket 发放；
 *     服务端不要求用户客户端证书，不证明对端信任、证书有效期或握手成功。
 * @note 失败保持主 owner 全部字节，按实际资源逆序清理；不部分发布或自动重试。
 * @note 预算仅本层控制块，不含 SSL_CTX/X509/EVP/BIO/provider、allocator/RSS、
 *     PEM 源或全局申请；不提供 TLS 总内存/硬实时保证。
 * @note 所有入口保持 errno。基本参数拒绝不触碰 OpenSSL 错误队列；真正操作
 *     库前清当前线程旧队列，失败立即复制首码及多码事实，清理后队列为空。
 *     caller 须预先保存自己的 OpenSSL 错误；不伪造 system_errno 或打印诊断。
 * @note 所有地址存活、对齐、按声明可读写、独立不重叠且不在对象自有资源内；
 *     不指 errno 存储，NULL 检查不验证野地址。只借输入到返回，不冻结 padding/ABI。
 * @note 同对象访问由 caller 串行；启动装配后可明确移交 Reactor，不在业务回调创建。
 *     无 fd/时间/网络动作，不用于 signal handler、强制取消或 fork 后未 exec 场景。
 *     不修改全局 allocator/provider/证书配置，不调用 OpenSSL 全局 cleanup。
 */
vireo_result_t vireo_tls_context_create_server(vireo_tls_context_options_t const *options,
    vireo_tls_context_t **out_context, vireo_tls_context_error_t *error);

/**
 * @brief 观测真实 native 配置并成功才发布独立快照
 *
 * @param[in] context
 *     非空存活对象，短借到返回，caller 串行访问。
 * @param[out] out_info
 *     独立必需可写输出，失败保持全部字节，不授予 native 借用或延长寿命。
 * @param[out] error
 *     可空独立诊断，每次覆盖逻辑字段。
 *
 * @retval VIREO_OK
 *     真实配置满足本合同，完整发布快照。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址为 NULL，不触碰库队列。
 * @retval VIREO_RESULT_INTERNAL
 *     实际配置/本层不变量异常，诊断为 INSPECT。
 *
 * @note 保持 errno；合法操作按 create 的合同清当前线程 OpenSSL 队列。
 *     不分配本层资源；地址/线程/ABI 要求沿 create，不检查证书信任或身份。
 */
vireo_result_t vireo_tls_context_inspect(vireo_tls_context_t const *context,
    vireo_tls_context_info_t *out_info, vireo_tls_context_error_t *error);

/**
 * @brief 结束全部访问/借用后配对释放并清空唯一 owner
 *
 * @param[in,out] context
 *     独立 owner 地址；*context 可为 NULL，非空须为未消费的唯一对象。
 * @param[out] error
 *     可空独立诊断，成功/地址拒绝均 NONE/0/false。
 *
 * @retval VIREO_OK
 *     已释放并置 NULL，或空 owner 的重复成功。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     owner 地址为 NULL。
 *
 * @note caller 先结束全部使用和借用；旧别名失效，没有自动并发寿命检测。
 *     不操作 fd，无网络 close/flush 或消费型 IO 错误；库释放无失败返回。
 *     非空销毁清线程 OpenSSL 队列，空操作不触碰队列；全部路径保持 errno。
 */
vireo_result_t vireo_tls_context_destroy(vireo_tls_context_t **context,
    vireo_tls_context_error_t *error);

#endif
