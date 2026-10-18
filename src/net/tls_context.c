/* 服务器 TLS1.3 资源根；外部材料只借用，native 资源完整成功才发布。 */
#include "tls_context_internal.h"

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/pem.h>

_Static_assert(sizeof(unsigned long) <= sizeof(uint64_t), "OpenSSL error code must fit uint64_t");

/** 本层标准 allocator；errno 由公共外层恢复，返回唯一区域或 NULL。 */
static void *system_allocate(void *context, size_t size)
{
    (void)context;
    return malloc(size);
}

/** 只释放本层配对区域，无错误返回；不访问释放后的对象。 */
static void system_deallocate(void *context, void *pointer)
{
    (void)context;
    free(pointer);
}

/** 新建真实服务器 native context；不修改全局库配置或取得 fd。 */
static SSL_CTX *system_create_native(void *context)
{
    (void)context;
    return SSL_CTX_new(TLS_server_method());
}

/** BIO 只借源字节，size 已证明正且可表示；BIO_free 不释放源。 */
static BIO *system_create_bio(void *context, void const *data, int size)
{
    (void)context;
    return BIO_new_mem_buf(data, size);
}

static vireo_tls_context_ops_t const system_ops = {
    NULL, system_allocate, system_deallocate, system_create_native, system_create_bio
};

/** 拒绝任何交互式私钥密码请求；输出缓冲完全不写。 */
static int reject_password(char *buffer, int size, int writing, void *context)
{
    (void)buffer;
    (void)size;
    (void)writing;
    (void)context;
    return 0;
}

/** 显式 ASCII 空白，避免 locale 或负 char 传给 ctype。 */
static bool ascii_space(unsigned char byte)
{
    return byte == ' ' || byte == '\t' || byte == '\r' || byte == '\n' ||
        byte == '\v' || byte == '\f';
}

/** 在本次受界 span 中跳过空白，不读取末端之外，不回绕。 */
static size_t skip_space(unsigned char const *data, size_t size, size_t position)
{
    while (position < size && ascii_space(data[position])) {
        ++position;
    }
    return position;
}

/**
 * @brief 识别一个严格 PEM 外壳，成功才提交块结束位置
 *
 * @param[in] data
 *     原稳定字节 span，position < size；不读取边界之外。
 * @param[in] begin/end
 *     固定标签文本，不含行结束；END 后只能是空白或 span 结束。
 * @param[out] out_end
 *     非空独立局部输出，失败保持；校验正文字符，解码/ASN.1 另验。
 *
 * @note 每次只向前扫描，固定标签比较；内容解码交真实 OpenSSL。
 */
static bool pem_block(unsigned char const *data, size_t size, size_t position,
    char const *begin, char const *end, size_t *out_end)
{
    size_t begin_size = strlen(begin);
    size_t end_size = strlen(end);
    if (begin_size >= size - position || memcmp(data + position, begin, begin_size) != 0) {
        return false;
    }
    size_t body = position + begin_size;
    if (data[body] != '\r' && data[body] != '\n') {
        return false;
    }
    for (size_t at = body; at < size; ++at) {
        if ((data[at - 1] == '\n' || data[at - 1] == '\r') &&
            end_size <= size - at && memcmp(data + at, end, end_size) == 0) {
            size_t after = at + end_size;
            if (after != size && !ascii_space(data[after])) {
                return false;
            }
            *out_end = after;
            return true;
        }
        unsigned char byte = data[at];
        if (!ascii_space(byte) && !(byte >= 'A' && byte <= 'Z') &&
            !(byte >= 'a' && byte <= 'z') && !(byte >= '0' && byte <= '9') &&
            byte != '+' && byte != '/' && byte != '=') {
            return false;
        }
    }
    return false;
}

/** 保存独立诊断并恢复入口 errno；不操作 OpenSSL 队列。 */
static vireo_result_t finish(vireo_tls_context_error_t *error,
    vireo_tls_context_error_t diagnostic, vireo_result_t result, int saved_errno)
{
    if (error != NULL) {
        *error = diagnostic;
    }
    errno = saved_errno;
    return result;
}

/**
 * @brief 立即取本次库原因，确定的 OOM 优先于保守分类
 *
 * @param[in,out] diagnostic
 *     非空局部诊断，stage 已由调用者设置。
 * @param[in] fallback
 *     无明确 OOM 时的当前失败分类。
 *
 * @note 消费本线程队列，不保存错误字符串；首码与后续存在事实分别保存。
 */
static vireo_result_t capture(vireo_tls_context_error_t *diagnostic, vireo_result_t fallback)
{
    unsigned long code;
    bool no_memory = false;
    while ((code = ERR_get_error()) != 0) {
        if (diagnostic->openssl_error_code == 0) {
            diagnostic->openssl_error_code = (uint64_t)code;
        } else {
            diagnostic->has_more_errors = true;
        }
        if (ERR_GET_REASON(code) == ERR_R_MALLOC_FAILURE) {
            no_memory = true;
        }
    }
    return no_memory ? VIREO_RESULT_NO_MEMORY : fallback;
}

/**
 * @brief 要求 PEM 解码结果恰好是一个有限长 DER SEQUENCE，不忽略内部尾随字节
 *
 * @param[in,out] bio
 *     本层拥有的只读内存 BIO；成功后 reset，仍由调用者释放。
 * @param[in,out] diagnostic
 *     当前阶段诊断；任何库失败均先捕获再释放临时库资源。
 *
 * @note 具体 X509/私钥语义仍交高层解码；临时解码缓冲由 OpenSSL 申请，
 *     配对 clear_free，既不留存材料，也不计入包装预算。
 */
static vireo_result_t validate_der_envelope(BIO *bio, vireo_tls_context_error_t *diagnostic)
{
    char *name = NULL;
    char *header = NULL;
    unsigned char *decoded = NULL;
    long length = 0;
    vireo_result_t result = VIREO_OK;
    if (PEM_read_bio_ex(bio, &name, &header, &decoded, &length, PEM_FLAG_ONLY_B64) != 1) {
        result = capture(diagnostic, VIREO_RESULT_INVALID_ARGUMENT);
    } else if (length <= 0) {
        result = VIREO_RESULT_INVALID_ARGUMENT;
    } else {
        unsigned char const *content = decoded;
        long content_length = 0;
        int tag = 0;
        int tag_class = 0;
        int flags = ASN1_get_object(&content, &content_length, &tag, &tag_class, length);
        if ((flags & 0x81) != 0 || (flags & V_ASN1_CONSTRUCTED) == 0 ||
            tag != V_ASN1_SEQUENCE || tag_class != V_ASN1_UNIVERSAL ||
            content_length != length - (long)(content - decoded) || header[0] != '\0') {
            result = capture(diagnostic, VIREO_RESULT_INVALID_ARGUMENT);
        }
    }
    OPENSSL_clear_free(decoded, length > 0 ? (size_t)length : 0);
    OPENSSL_free(header);
    OPENSSL_free(name);
    if (result == VIREO_OK) {
        ERR_clear_error();
        if (BIO_reset(bio) != 1) {
            result = capture(diagnostic, VIREO_RESULT_INTERNAL);
        }
    }
    return result;
}

/** 创建未发布资源的配对清理；先复制 allocator，释放后不再读对象。 */
static void release_context(vireo_tls_context_t *context)
{
    vireo_tls_context_ops_t ops = context->ops;
    SSL_CTX_free(context->native);
    ops.deallocate(ops.context, context);
}

/**
 * @brief 逐块加载叶子及链证书，库失败在局部释放前捕获原因
 *
 * @note 每个 BIO/X509 局部取得后均配对释放；add1 明确增加 native 所持引用。
 *     只接受 CERTIFICATE 外壳，所有源字节必须被材料或空白覆盖。
 */
static vireo_result_t load_certificates(vireo_tls_context_t *context,
    unsigned char const *data, size_t size, vireo_tls_context_error_t *diagnostic)
{
    size_t position = skip_space(data, size, 0);
    while (position < size) {
        ERR_clear_error();
        size_t end = 0;
        if (!pem_block(data, size, position, "-----BEGIN CERTIFICATE-----",
                "-----END CERTIFICATE-----", &end)) {
            return VIREO_RESULT_INVALID_ARGUMENT;
        }
        BIO *bio = context->ops.create_bio(context->ops.context, data + position,
            (int)(end - position));
        if (bio == NULL) {
            return capture(diagnostic, VIREO_RESULT_INTERNAL);
        }
        vireo_result_t envelope = validate_der_envelope(bio, diagnostic);
        if (envelope != VIREO_OK) {
            BIO_free(bio);
            return envelope;
        }
        X509 *certificate = PEM_read_bio_X509(bio, NULL, reject_password, NULL);
        if (certificate == NULL) {
            vireo_result_t result = capture(diagnostic, VIREO_RESULT_INVALID_ARGUMENT);
            BIO_free(bio);
            return result;
        }
        BIO_free(bio);
        ERR_clear_error();
        long installed = context->certificate_count == 0 ?
            SSL_CTX_use_certificate(context->native, certificate) :
            SSL_CTX_add1_chain_cert(context->native, certificate);
        if (installed != 1) {
            vireo_result_t result = capture(diagnostic, VIREO_RESULT_INVALID_ARGUMENT);
            X509_free(certificate);
            return result;
        }
        X509_free(certificate);
        ++context->certificate_count;
        position = skip_space(data, size, end);
    }
    return context->certificate_count == 0 ? VIREO_RESULT_INVALID_ARGUMENT : VIREO_OK;
}

/** 单私钥外壳识别；固定标签不拥有资源，不接受 ENCRYPTED PRIVATE KEY。 */
static bool private_key_block(unsigned char const *data, size_t size, size_t position,
    size_t *out_end)
{
    return pem_block(data, size, position, "-----BEGIN PRIVATE KEY-----",
            "-----END PRIVATE KEY-----", out_end) ||
        pem_block(data, size, position, "-----BEGIN RSA PRIVATE KEY-----",
            "-----END RSA PRIVATE KEY-----", out_end) ||
        pem_block(data, size, position, "-----BEGIN EC PRIVATE KEY-----",
            "-----END EC PRIVATE KEY-----", out_end) ||
        pem_block(data, size, position, "-----BEGIN DSA PRIVATE KEY-----",
            "-----END DSA PRIVATE KEY-----", out_end);
}

/** 真实解析单私钥并安装；局部 EVP/BIO 配对清理，不保存密码或输入字节。 */
static vireo_result_t load_private_key(vireo_tls_context_t *context,
    unsigned char const *data, size_t size, vireo_tls_context_error_t *diagnostic)
{
    ERR_clear_error();
    size_t position = skip_space(data, size, 0);
    size_t end = 0;
    if (position == size || !private_key_block(data, size, position, &end) ||
        skip_space(data, size, end) != size) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    BIO *bio = context->ops.create_bio(context->ops.context, data + position,
        (int)(end - position));
    if (bio == NULL) {
        return capture(diagnostic, VIREO_RESULT_INTERNAL);
    }
    vireo_result_t envelope = validate_der_envelope(bio, diagnostic);
    if (envelope != VIREO_OK) {
        BIO_free(bio);
        return envelope;
    }
    EVP_PKEY *key = PEM_read_bio_PrivateKey(bio, NULL, reject_password, NULL);
    if (key == NULL) {
        vireo_result_t result = capture(diagnostic, VIREO_RESULT_INVALID_ARGUMENT);
        BIO_free(bio);
        return result;
    }
    BIO_free(bio);
    ERR_clear_error();
    int installed = SSL_CTX_use_PrivateKey(context->native, key);
    vireo_result_t result = installed == 1 ? VIREO_OK :
        capture(diagnostic, VIREO_RESULT_INVALID_ARGUMENT);
    EVP_PKEY_free(key);
    return result;
}

/** 固定 native 配置和材料的因果顺序；每次库失败在任何释放前复制原诊断。 */
static vireo_result_t initialize_native(vireo_tls_context_t *candidate,
    vireo_tls_context_options_t const *options, vireo_tls_context_error_t *diagnostic)
{
    diagnostic->stage = VIREO_TLS_CONTEXT_STAGE_CREATE_NATIVE;
    candidate->native = candidate->ops.create_native(candidate->ops.context);
    if (candidate->native == NULL) {
        return capture(diagnostic, VIREO_RESULT_INTERNAL);
    }
    diagnostic->stage = VIREO_TLS_CONTEXT_STAGE_CONFIGURE;
    ERR_clear_error();
    if (SSL_CTX_set_min_proto_version(candidate->native, TLS1_3_VERSION) != 1 ||
        SSL_CTX_set_max_proto_version(candidate->native, TLS1_3_VERSION) != 1 ||
        SSL_CTX_set_max_early_data(candidate->native, 0) != 1 ||
        SSL_CTX_set_num_tickets(candidate->native, 0) != 1) {
        return capture(diagnostic, VIREO_RESULT_INTERNAL);
    }
    (void)SSL_CTX_set_session_cache_mode(candidate->native, SSL_SESS_CACHE_OFF);
    (void)SSL_CTX_set_options(candidate->native, SSL_OP_NO_TICKET);
    SSL_CTX_set_verify(candidate->native, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_default_passwd_cb(candidate->native, reject_password);
    diagnostic->stage = VIREO_TLS_CONTEXT_STAGE_CERTIFICATE;
    vireo_result_t result = load_certificates(candidate, options->certificate_chain,
        options->certificate_chain_size, diagnostic);
    if (result != VIREO_OK) {
        return result;
    }
    diagnostic->stage = VIREO_TLS_CONTEXT_STAGE_PRIVATE_KEY;
    result = load_private_key(candidate, options->private_key, options->private_key_size, diagnostic);
    if (result != VIREO_OK) {
        return result;
    }
    diagnostic->stage = VIREO_TLS_CONTEXT_STAGE_MATCH_KEY;
    ERR_clear_error();
    return SSL_CTX_check_private_key(candidate->native) == 1 ? VIREO_OK :
        capture(diagnostic, VIREO_RESULT_INVALID_ARGUMENT);
}

vireo_result_t vireo_tls_context_create_with_ops(vireo_tls_context_options_t const *options,
    vireo_tls_context_t **out_context, vireo_tls_context_error_t *error,
    vireo_tls_context_ops_t const *ops)
{
    int saved_errno = errno;
    vireo_tls_context_error_t diagnostic = {VIREO_TLS_CONTEXT_STAGE_NONE, 0, false};
    if (options == NULL || out_context == NULL || *out_context != NULL ||
        options->certificate_chain == NULL || options->private_key == NULL ||
        options->certificate_chain_size == 0 || options->private_key_size == 0 ||
        options->max_wrapper_bytes == 0 || ops == NULL || ops->allocate == NULL ||
        ops->deallocate == NULL || ops->create_native == NULL || ops->create_bio == NULL) {
        return finish(error, diagnostic, VIREO_RESULT_INVALID_ARGUMENT, saved_errno);
    }
    if (options->certificate_chain_size > (size_t)INT_MAX ||
        options->private_key_size > (size_t)INT_MAX) {
        return finish(error, diagnostic, VIREO_RESULT_OVERFLOW, saved_errno);
    }
    if (options->certificate_chain_size > VIREO_TLS_CONTEXT_MAX_CERTIFICATE_BYTES ||
        options->private_key_size > VIREO_TLS_CONTEXT_MAX_PRIVATE_KEY_BYTES ||
        options->max_wrapper_bytes > VIREO_TLS_CONTEXT_MAX_WRAPPER_BYTES ||
        options->max_wrapper_bytes < sizeof(vireo_tls_context_t)) {
        return finish(error, diagnostic, VIREO_RESULT_RANGE, saved_errno);
    }
    ERR_clear_error();
    vireo_tls_context_t *candidate = ops->allocate(ops->context, sizeof(*candidate));
    if (candidate == NULL) {
        diagnostic.stage = VIREO_TLS_CONTEXT_STAGE_ALLOCATE_WRAPPER;
        ERR_clear_error();
        return finish(error, diagnostic, VIREO_RESULT_NO_MEMORY, saved_errno);
    }
    *candidate = (vireo_tls_context_t){NULL, 0, options->max_wrapper_bytes, *ops};
    vireo_result_t result = initialize_native(candidate, options, &diagnostic);
    if (result != VIREO_OK) {
        release_context(candidate);
        ERR_clear_error();
        return finish(error, diagnostic, result, saved_errno);
    }
    ERR_clear_error();
    *out_context = candidate;
    diagnostic = (vireo_tls_context_error_t){VIREO_TLS_CONTEXT_STAGE_NONE, 0, false};
    return finish(error, diagnostic, VIREO_OK, saved_errno);
}

vireo_result_t vireo_tls_context_create_server(vireo_tls_context_options_t const *options,
    vireo_tls_context_t **out_context, vireo_tls_context_error_t *error)
{
    return vireo_tls_context_create_with_ops(options, out_context, error, &system_ops);
}

vireo_result_t vireo_tls_context_inspect(vireo_tls_context_t const *context,
    vireo_tls_context_info_t *out_info, vireo_tls_context_error_t *error)
{
    int saved_errno = errno;
    vireo_tls_context_error_t diagnostic = {VIREO_TLS_CONTEXT_STAGE_NONE, 0, false};
    if (context == NULL || out_info == NULL) {
        return finish(error, diagnostic, VIREO_RESULT_INVALID_ARGUMENT, saved_errno);
    }
    ERR_clear_error();
    if (context->native == NULL || context->certificate_count == 0 ||
        context->max_wrapper_bytes < sizeof(*context) ||
        context->max_wrapper_bytes > VIREO_TLS_CONTEXT_MAX_WRAPPER_BYTES ||
        SSL_CTX_get_min_proto_version(context->native) != TLS1_3_VERSION ||
        SSL_CTX_get_max_proto_version(context->native) != TLS1_3_VERSION ||
        SSL_CTX_get_max_early_data(context->native) != 0 ||
        SSL_CTX_get_session_cache_mode(context->native) != SSL_SESS_CACHE_OFF ||
        SSL_CTX_get_num_tickets(context->native) != 0 ||
        (SSL_CTX_get_options(context->native) & SSL_OP_NO_TICKET) == 0 ||
        SSL_CTX_get_verify_mode(context->native) != SSL_VERIFY_NONE) {
        diagnostic.stage = VIREO_TLS_CONTEXT_STAGE_INSPECT;
        vireo_result_t result = capture(&diagnostic, VIREO_RESULT_INTERNAL);
        ERR_clear_error();
        return finish(error, diagnostic, result, saved_errno);
    }
    vireo_tls_context_info_t info = {VIREO_TLS_CONTEXT_PROTOCOL_1_3,
        VIREO_TLS_CONTEXT_PROTOCOL_1_3, false, false, false, false,
        context->certificate_count, sizeof(*context), context->max_wrapper_bytes};
    ERR_clear_error();
    *out_info = info;
    return finish(error, diagnostic, VIREO_OK, saved_errno);
}

vireo_result_t vireo_tls_context_destroy(vireo_tls_context_t **context,
    vireo_tls_context_error_t *error)
{
    int saved_errno = errno;
    vireo_tls_context_error_t diagnostic = {VIREO_TLS_CONTEXT_STAGE_NONE, 0, false};
    if (context == NULL) {
        return finish(error, diagnostic, VIREO_RESULT_INVALID_ARGUMENT, saved_errno);
    }
    if (*context != NULL) {
        ERR_clear_error();
        release_context(*context);
        *context = NULL;
        ERR_clear_error();
    }
    return finish(error, diagnostic, VIREO_OK, saved_errno);
}
