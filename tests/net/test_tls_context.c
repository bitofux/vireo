/* 034-01：真实 OpenSSL 配置/材料与 own 资源故障分别验证；无网络握手。 */
#include "tls_context_internal.h"
#include "tls_context_fixtures.h"

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#define CHECK(condition) do { if (!(condition)) { \
    (void)fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition); abort(); \
} } while (0)
#define EXPECT(expression, expected) do { errno = ECHILD; \
    vireo_result_t actual_result = (expression); \
    CHECK(actual_result == (expected)); CHECK(errno == ECHILD); \
} while (0)

/** 每次创建独立选项；fixture 为公开测试字节，不含部署凭据。 */
static vireo_tls_context_options_t options(void)
{
    vireo_tls_context_options_t value = {fixture_leaf, sizeof(fixture_leaf) - 1,
        fixture_key, sizeof(fixture_key) - 1, 4096};
    return value;
}

/** 本层故障夹具：每次生命周期串行使用，计数无跨线程共享。 */
typedef struct fault_state {
    size_t allocations; /**< allocator 真实调用数。 */
    size_t deallocations; /**< 配对释放数，不含 OpenSSL 内部对象。 */
    size_t native_calls; /**< native 构造尝试数。 */
    size_t bio_calls; /**< 内存 BIO 构造尝试数。 */
    bool fail_allocate; /**< allocator 返回 NULL。 */
    bool fail_native; /**< native 构造返回 NULL。 */
    size_t fail_bio_at; /**< 非零时在该次 BIO 申请失败。 */
    unsigned int error_mode; /**< 0无原因，1明确OOM，2首普通错后OOM。 */
    bool cleanup_error; /**< free 前注入次错，核主诊断不被覆盖。 */
} fault_state_t;

/** 模拟当前线程的明确库错误，不冒称真实系统 OOM。 */
static void raise_fault(fault_state_t const *state)
{
    if (state->error_mode == 2) {
        ERR_raise(ERR_LIB_USER, 100);
    }
    if (state->error_mode != 0) {
        ERR_raise(ERR_LIB_SSL, ERR_R_MALLOC_FAILURE);
    }
}

/** 真实 allocator 计调用；失败时不取得资源，故意改变 errno。 */
static void *fault_allocate(void *context, size_t size)
{
    fault_state_t *state = context;
    ++state->allocations;
    errno = ENOMEM;
    return state->fail_allocate ? NULL : malloc(size);
}

/** 释放唯一包装块，可另注入清理次错，故意改变 errno。 */
static void fault_deallocate(void *context, void *pointer)
{
    fault_state_t *state = context;
    ++state->deallocations;
    if (state->cleanup_error) {
        ERR_raise(ERR_LIB_USER, 777);
    }
    free(pointer);
    errno = EIO;
}

/** 返回真实 TLS server context 或可控 NULL，供本层创建回滚验证。 */
static SSL_CTX *fault_native(void *context)
{
    fault_state_t *state = context;
    ++state->native_calls;
    if (state->fail_native) {
        raise_fault(state);
        return NULL;
    }
    return SSL_CTX_new(TLS_server_method());
}

/** 指定第几次 BIO 失败，其他时刻真实借用材料。 */
static BIO *fault_bio(void *context, void const *data, int size)
{
    fault_state_t *state = context;
    ++state->bio_calls;
    if (state->bio_calls == state->fail_bio_at) {
        raise_fault(state);
        return NULL;
    }
    return BIO_new_mem_buf(data, size);
}

/** 按值操作表只活于本测试；配对 context 活到对象销毁。 */
static vireo_tls_context_ops_t fault_ops(fault_state_t *state)
{
    vireo_tls_context_ops_t ops = {state, fault_allocate, fault_deallocate, fault_native, fault_bio};
    return ops;
}

/** 读取本进程 fd 数；同一目录枚举自身占用对两次统计相同。 */
static size_t fd_count(void)
{
    DIR *directory = opendir("/proc/self/fd");
    CHECK(directory != NULL);
    size_t count = 0;
    struct dirent *entry;
    while ((entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
            ++count;
        }
    }
    CHECK(closedir(directory) == 0);
    return count;
}

/** 验真实 native getters，不能仅凭保存的 options 宣称配置已生效。 */
static void lifecycle_and_configuration(void)
{
    vireo_tls_context_options_t value = options();
    vireo_tls_context_t *owner = NULL;
    vireo_tls_context_error_t error;
    EXPECT(vireo_tls_context_create_server(&value, &owner, &error), VIREO_OK);
    CHECK(owner != NULL && error.stage == VIREO_TLS_CONTEXT_STAGE_NONE);
    CHECK(error.openssl_error_code == 0 && !error.has_more_errors);
    CHECK(SSL_CTX_get_min_proto_version(owner->native) == TLS1_3_VERSION);
    CHECK(SSL_CTX_get_max_proto_version(owner->native) == TLS1_3_VERSION);
    CHECK(SSL_CTX_get_max_early_data(owner->native) == 0);
    CHECK(SSL_CTX_get_num_tickets(owner->native) == 0);
    CHECK(SSL_CTX_get_session_cache_mode(owner->native) == SSL_SESS_CACHE_OFF);
    CHECK((SSL_CTX_get_options(owner->native) & SSL_OP_NO_TICKET) != 0);
    CHECK(SSL_CTX_get_verify_mode(owner->native) == SSL_VERIFY_NONE);
    CHECK(SSL_CTX_get0_certificate(owner->native) != NULL);
    CHECK(SSL_CTX_get0_privatekey(owner->native) != NULL);
    vireo_tls_context_info_t info;
    EXPECT(vireo_tls_context_inspect(owner, &info, &error), VIREO_OK);
    CHECK(info.minimum_protocol_version == VIREO_TLS_CONTEXT_PROTOCOL_1_3);
    CHECK(info.maximum_protocol_version == VIREO_TLS_CONTEXT_PROTOCOL_1_3);
    CHECK(!info.early_data_enabled && !info.session_cache_enabled);
    CHECK(!info.session_tickets_enabled && !info.client_certificate_required);
    CHECK(info.certificate_count == 1 && info.wrapper_bytes == sizeof(*owner));
    CHECK(info.max_wrapper_bytes == value.max_wrapper_bytes);
    vireo_tls_context_t *original = owner;
    EXPECT(vireo_tls_context_create_server(&value, &owner, &error), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(owner == original);
    EXPECT(vireo_tls_context_destroy(&owner, &error), VIREO_OK);
    CHECK(owner == NULL && error.stage == VIREO_TLS_CONTEXT_STAGE_NONE);
    EXPECT(vireo_tls_context_destroy(&owner, NULL), VIREO_OK);
}

/** 参数拒绝保持所有主要输出；地址拒绝先于库队列触碰。 */
static void invalid_arguments(void)
{
    vireo_tls_context_options_t value = options();
    vireo_tls_context_t *owner = NULL;
    vireo_tls_context_error_t error = {VIREO_TLS_CONTEXT_STAGE_CERTIFICATE, 123, true};
    EXPECT(vireo_tls_context_create_server(NULL, &owner, &error), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(owner == NULL && error.stage == VIREO_TLS_CONTEXT_STAGE_NONE);
    CHECK(error.openssl_error_code == 0 && !error.has_more_errors);
    EXPECT(vireo_tls_context_create_server(&value, NULL, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_tls_context_destroy(NULL, &error), VIREO_RESULT_INVALID_ARGUMENT);
    vireo_tls_context_info_t info;
    memset(&info, 0xA5, sizeof(info));
    unsigned char original[sizeof(info)];
    memcpy(original, &info, sizeof(info));
    EXPECT(vireo_tls_context_inspect(NULL, &info, &error), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(memcmp(original, &info, sizeof(info)) == 0);
    for (unsigned int index = 0; index < 5; ++index) {
        value = options();
        if (index == 0) { value.certificate_chain = NULL; }
        if (index == 1) { value.private_key = NULL; }
        if (index == 2) { value.certificate_chain_size = 0; }
        if (index == 3) { value.private_key_size = 0; }
        if (index == 4) { value.max_wrapper_bytes = 0; }
        EXPECT(vireo_tls_context_create_server(&value, &owner, NULL), VIREO_RESULT_INVALID_ARGUMENT);
        CHECK(owner == NULL);
    }
}

/** 先验拒绝不读取伪大 span；预算恰等控制块能成功。 */
static void numeric_boundaries(void)
{
    vireo_tls_context_t *owner = NULL;
    vireo_tls_context_options_t value = options();
    value.certificate_chain_size = (size_t)INT_MAX + 1;
    EXPECT(vireo_tls_context_create_server(&value, &owner, NULL), VIREO_RESULT_OVERFLOW);
    value = options(); value.private_key_size = (size_t)INT_MAX + 1;
    EXPECT(vireo_tls_context_create_server(&value, &owner, NULL), VIREO_RESULT_OVERFLOW);
    value = options(); value.certificate_chain_size = VIREO_TLS_CONTEXT_MAX_CERTIFICATE_BYTES + 1;
    EXPECT(vireo_tls_context_create_server(&value, &owner, NULL), VIREO_RESULT_RANGE);
    value = options(); value.private_key_size = VIREO_TLS_CONTEXT_MAX_PRIVATE_KEY_BYTES + 1;
    EXPECT(vireo_tls_context_create_server(&value, &owner, NULL), VIREO_RESULT_RANGE);
    value = options(); value.max_wrapper_bytes = VIREO_TLS_CONTEXT_MAX_WRAPPER_BYTES + 1;
    EXPECT(vireo_tls_context_create_server(&value, &owner, NULL), VIREO_RESULT_RANGE);
    value = options(); value.max_wrapper_bytes = sizeof(*owner) - 1;
    EXPECT(vireo_tls_context_create_server(&value, &owner, NULL), VIREO_RESULT_RANGE);
    CHECK(owner == NULL);
    value.max_wrapper_bytes = sizeof(*owner);
    EXPECT(vireo_tls_context_create_server(&value, &owner, NULL), VIREO_OK);
    EXPECT(vireo_tls_context_inspect(owner, NULL, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_tls_context_destroy(&owner, NULL), VIREO_OK);
    value.max_wrapper_bytes = VIREO_TLS_CONTEXT_MAX_WRAPPER_BYTES;
    EXPECT(vireo_tls_context_create_server(&value, &owner, NULL), VIREO_OK);
    EXPECT(vireo_tls_context_destroy(&owner, NULL), VIREO_OK);
}

/** 拼接固定材料与尾部空白；返回 caller owner，调用结束显式 free。 */
static unsigned char *concatenate(unsigned char const *first, size_t first_size,
    unsigned char const *second, size_t second_size, size_t extra_spaces)
{
    size_t total = first_size + second_size + extra_spaces;
    unsigned char *bytes = malloc(total);
    CHECK(bytes != NULL);
    memcpy(bytes, first, first_size);
    if (second_size != 0) { memcpy(bytes + first_size, second, second_size); }
    memset(bytes + first_size + second_size, ' ', extra_spaces);
    return bytes;
}

/** 将公开夹具改为 CRLF，前后加合法空白，验证常见 PEM 换行与包围空白。 */
static unsigned char *crlf_material(unsigned char const *source, size_t size, size_t *out_size)
{
    unsigned char *bytes = malloc(size * 2 + 4);
    CHECK(bytes != NULL);
    size_t used = 0;
    bytes[used++] = ' '; bytes[used++] = '\t';
    for (size_t at = 0; at < size; ++at) {
        if (source[at] == '\n') { bytes[used++] = '\r'; }
        bytes[used++] = source[at];
    }
    bytes[used++] = '\v'; bytes[used++] = '\f';
    *out_size = used;
    return bytes;
}

/** 真实签名叶子+根链；native 链顺序/内容核验，释放 caller 源后仍可观察。 */
static void chain_and_source_lifetime(void)
{
    vireo_tls_context_options_t value = options();
    size_t size = sizeof(fixture_leaf) + sizeof(fixture_root) - 2;
    unsigned char *chain = concatenate(fixture_leaf, sizeof(fixture_leaf) - 1,
        fixture_root, sizeof(fixture_root) - 1, 6);
    unsigned char *key = concatenate(fixture_key, sizeof(fixture_key) - 1, NULL, 0, 3);
    value.certificate_chain = chain; value.certificate_chain_size = size + 6;
    value.private_key = key; value.private_key_size = sizeof(fixture_key) - 1 + 3;
    vireo_tls_context_t *owner = NULL;
    EXPECT(vireo_tls_context_create_server(&value, &owner, NULL), VIREO_OK);
    memset(chain, 0, size + 6); memset(key, 0, value.private_key_size);
    free(chain); free(key);
    vireo_tls_context_info_t info;
    EXPECT(vireo_tls_context_inspect(owner, &info, NULL), VIREO_OK);
    CHECK(info.certificate_count == 2);
    STACK_OF(X509) *native_chain = NULL;
    CHECK(SSL_CTX_get0_chain_certs(owner->native, &native_chain) == 1);
    CHECK(native_chain != NULL && sk_X509_num(native_chain) == 1);
    CHECK(X509_check_issued(sk_X509_value(native_chain, 0),
        SSL_CTX_get0_certificate(owner->native)) == X509_V_OK);
    EXPECT(vireo_tls_context_destroy(&owner, NULL), VIREO_OK);
    value = options();
    chain = crlf_material(fixture_leaf, sizeof(fixture_leaf) - 1, &value.certificate_chain_size);
    key = crlf_material(fixture_key, sizeof(fixture_key) - 1, &value.private_key_size);
    value.certificate_chain = chain; value.private_key = key;
    EXPECT(vireo_tls_context_create_server(&value, &owner, NULL), VIREO_OK);
    EXPECT(vireo_tls_context_destroy(&owner, NULL), VIREO_OK);
    free(key); free(chain);
    BIO *input = BIO_new_mem_buf(fixture_key, (int)(sizeof(fixture_key) - 1));
    BIO *traditional = BIO_new(BIO_s_mem());
    CHECK(input != NULL && traditional != NULL);
    EVP_PKEY *native_key = PEM_read_bio_PrivateKey(input, NULL, NULL, NULL);
    CHECK(native_key != NULL);
    CHECK(PEM_write_bio_PrivateKey_traditional(traditional, native_key, NULL, NULL, 0,
        NULL, NULL) == 1);
    char *traditional_bytes = NULL;
    long traditional_size = BIO_get_mem_data(traditional, &traditional_bytes);
    CHECK(traditional_size > 0);
    value = options(); value.private_key = (unsigned char const *)traditional_bytes;
    value.private_key_size = (size_t)traditional_size;
    EXPECT(vireo_tls_context_create_server(&value, &owner, NULL), VIREO_OK);
    EXPECT(vireo_tls_context_destroy(&owner, NULL), VIREO_OK);
    EVP_PKEY_free(native_key); BIO_free(traditional); BIO_free(input);
}

/** 实际硬上限的合法材料加空白，不将上限+1先验拒绝冒上限成功。 */
static void maximum_material_lengths(void)
{
    vireo_tls_context_options_t value = options();
    unsigned char *cert = concatenate(fixture_leaf, sizeof(fixture_leaf) - 1, NULL, 0,
        VIREO_TLS_CONTEXT_MAX_CERTIFICATE_BYTES - (sizeof(fixture_leaf) - 1));
    unsigned char *key = concatenate(fixture_key, sizeof(fixture_key) - 1, NULL, 0,
        VIREO_TLS_CONTEXT_MAX_PRIVATE_KEY_BYTES - (sizeof(fixture_key) - 1));
    value.certificate_chain = cert; value.certificate_chain_size = VIREO_TLS_CONTEXT_MAX_CERTIFICATE_BYTES;
    value.private_key = key; value.private_key_size = VIREO_TLS_CONTEXT_MAX_PRIVATE_KEY_BYTES;
    vireo_tls_context_t *owner = NULL;
    EXPECT(vireo_tls_context_create_server(&value, &owner, NULL), VIREO_OK);
    EXPECT(vireo_tls_context_destroy(&owner, NULL), VIREO_OK);
    free(key); free(cert);
}

/** 对真实解析拒绝核 owner/errno/阶段及队列清空，不推断系统错误。 */
static void expect_material_rejection(unsigned char const *data, size_t size, bool is_key)
{
    vireo_tls_context_options_t value = options();
    if (is_key) { value.private_key = data; value.private_key_size = size; }
    else { value.certificate_chain = data; value.certificate_chain_size = size; }
    vireo_tls_context_t *owner = NULL;
    vireo_tls_context_error_t error;
    EXPECT(vireo_tls_context_create_server(&value, &owner, &error), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(owner == NULL);
    CHECK(error.stage == (is_key ? VIREO_TLS_CONTEXT_STAGE_PRIVATE_KEY :
        VIREO_TLS_CONTEXT_STAGE_CERTIFICATE));
    CHECK(ERR_peek_error() == 0);
}

/** 保留合法 PEM 外壳和完整对象，在解码后的 DER 尾部加入非材料字节。 */
static void reject_der_suffix(unsigned char const *source, size_t size, bool is_key)
{
    BIO *input = BIO_new_mem_buf(source, (int)size);
    BIO *output = BIO_new(BIO_s_mem());
    CHECK(input != NULL && output != NULL);
    char *name = NULL;
    char *header = NULL;
    unsigned char *decoded = NULL;
    long length = 0;
    CHECK(PEM_read_bio(input, &name, &header, &decoded, &length) == 1);
    CHECK(length > 0 && length < INT_MAX);
    unsigned char *extra = OPENSSL_malloc((size_t)length + 1);
    CHECK(extra != NULL);
    memcpy(extra, decoded, (size_t)length);
    extra[length] = 0;
    CHECK(PEM_write_bio(output, name, header, extra, length + 1) > 0);
    char *bytes = NULL;
    long output_size = BIO_get_mem_data(output, &bytes);
    CHECK(output_size > 0);
    expect_material_rejection((unsigned char const *)bytes, (size_t)output_size, is_key);
    OPENSSL_clear_free(extra, (size_t)length + 1);
    OPENSSL_clear_free(decoded, (size_t)length);
    OPENSSL_free(header); OPENSSL_free(name);
    BIO_free(output); BIO_free(input);
}

/** 畸形/截断/额外数据不被 PEM 的宽松扫描静默跳过；包括嵌入 NUL。 */
static void malformed_materials(void)
{
    unsigned char const garbage[] = "not a pem";
    unsigned char const bad_cert[] = "-----BEGIN CERTIFICATE-----\n!bad!\n-----END CERTIFICATE-----\n";
    unsigned char const bad_key[] = "-----BEGIN PRIVATE KEY-----\n!bad!\n-----END PRIVATE KEY-----\n";
    expect_material_rejection(garbage, sizeof(garbage) - 1, false);
    expect_material_rejection(garbage, sizeof(garbage) - 1, true);
    expect_material_rejection(bad_cert, sizeof(bad_cert) - 1, false);
    expect_material_rejection(bad_key, sizeof(bad_key) - 1, true);
    expect_material_rejection(fixture_leaf, sizeof(fixture_leaf) - 20, false);
    expect_material_rejection(fixture_key, sizeof(fixture_key) - 20, true);
    reject_der_suffix(fixture_leaf, sizeof(fixture_leaf) - 1, false);
    reject_der_suffix(fixture_key, sizeof(fixture_key) - 1, true);
    for (unsigned int index = 0; index < 2; ++index) {
        bool is_key = index != 0;
        unsigned char const *source = is_key ? fixture_key : fixture_leaf;
        size_t size = is_key ? sizeof(fixture_key) - 1 : sizeof(fixture_leaf) - 1;
        unsigned char *copy = concatenate(source, size, garbage, sizeof(garbage), 0);
        expect_material_rejection(copy, size + sizeof(garbage), is_key);
        copy[size] = 0;
        expect_material_rejection(copy, size + 1, is_key);
        free(copy);
        copy = concatenate(source, size, NULL, 0, 0);
        unsigned char *line = (unsigned char *)strchr((char const *)source, '\n');
        CHECK(line != NULL);
        size_t body = (size_t)(line - source) + 1;
        copy[body] = '!';
        expect_material_rejection(copy, size, is_key);
        copy[body] = 0;
        expect_material_rejection(copy, size, is_key);
        free(copy);
        copy = concatenate(garbage, sizeof(garbage) - 1, source, size, 0);
        expect_material_rejection(copy, size + sizeof(garbage) - 1, is_key);
        free(copy);
    }
    unsigned char *duplicate = concatenate(fixture_key, sizeof(fixture_key) - 1,
        fixture_key, sizeof(fixture_key) - 1, 0);
    expect_material_rejection(duplicate, 2 * (sizeof(fixture_key) - 1), true);
    free(duplicate);
}

/** PKCS8 和传统 PEM 加密均直接拒绝，不进入终端密码交互。 */
static void encrypted_materials(void)
{
    expect_material_rejection(fixture_encrypted_key, sizeof(fixture_encrypted_key) - 1, true);
    expect_material_rejection(fixture_traditional_encrypted_key,
        sizeof(fixture_traditional_encrypted_key) - 1, true);
}

/** 真正错配的合法私钥，不能只测坏格式。 */
static void mismatched_key(void)
{
    vireo_tls_context_options_t value = options();
    value.private_key = fixture_other_key; value.private_key_size = sizeof(fixture_other_key) - 1;
    vireo_tls_context_t *owner = NULL;
    vireo_tls_context_error_t error;
    EXPECT(vireo_tls_context_create_server(&value, &owner, &error), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(owner == NULL && error.openssl_error_code != 0);
    CHECK(error.stage == VIREO_TLS_CONTEXT_STAGE_PRIVATE_KEY ||
        error.stage == VIREO_TLS_CONTEXT_STAGE_MATCH_KEY);
    CHECK(ERR_peek_error() == 0);
}

/** 参数拒绝保旧队列，真正库操作清旧队列；诊断副本与库队列寿命独立。 */
static void error_queue_contract(void)
{
    ERR_clear_error(); ERR_raise(ERR_LIB_USER, 123);
    unsigned long original = ERR_peek_error();
    vireo_tls_context_t *owner = NULL;
    EXPECT(vireo_tls_context_create_server(NULL, &owner, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(ERR_peek_error() == original);
    EXPECT(vireo_tls_context_destroy(&owner, NULL), VIREO_OK);
    CHECK(ERR_peek_error() == original);
    vireo_tls_context_options_t value = options();
    EXPECT(vireo_tls_context_create_server(&value, &owner, NULL), VIREO_OK);
    CHECK(ERR_peek_error() == 0);
    ERR_raise(ERR_LIB_USER, 124);
    vireo_tls_context_info_t info;
    EXPECT(vireo_tls_context_inspect(owner, &info, NULL), VIREO_OK);
    CHECK(ERR_peek_error() == 0);
    ERR_raise(ERR_LIB_USER, 125);
    EXPECT(vireo_tls_context_destroy(&owner, NULL), VIREO_OK);
    CHECK(ERR_peek_error() == 0);
    unsigned char const bad[] = "-----BEGIN CERTIFICATE-----\nMAA=\n-----END CERTIFICATE-----";
    value.certificate_chain = bad; value.certificate_chain_size = sizeof(bad) - 1;
    vireo_tls_context_error_t error;
    ERR_raise(ERR_LIB_USER, 126);
    EXPECT(vireo_tls_context_create_server(&value, &owner, &error), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(error.openssl_error_code != 0 && ERR_peek_error() == 0);
    uint64_t saved = error.openssl_error_code;
    ERR_raise(ERR_LIB_USER, 127); ERR_clear_error();
    CHECK(error.openssl_error_code == saved);
}

/** 申请/库构造失败、无原因分类、多码与清理次错，实际资源由 LSan 核配对。 */
static void allocation_and_library_failures(void)
{
    for (unsigned int mode = 0; mode < 5; ++mode) {
        fault_state_t state = {0};
        state.fail_allocate = mode == 0;
        state.fail_native = mode == 1 || mode == 2;
        state.fail_bio_at = mode == 3 ? 1 : (mode == 4 ? 2 : 0);
        state.error_mode = mode == 1 ? 0 : 2;
        state.cleanup_error = true;
        vireo_tls_context_ops_t ops = fault_ops(&state);
        vireo_tls_context_options_t value = options();
        vireo_tls_context_t *owner = NULL;
        vireo_tls_context_error_t error;
        EXPECT(vireo_tls_context_create_with_ops(&value, &owner, &error, &ops),
            mode == 1 ? VIREO_RESULT_INTERNAL : VIREO_RESULT_NO_MEMORY);
        CHECK(owner == NULL && state.allocations == 1);
        CHECK(state.deallocations == (mode == 0 ? 0U : 1U));
        CHECK(state.native_calls == (mode == 0 ? 0U : 1U));
        CHECK(ERR_peek_error() == 0);
        if (mode < 2) {
            CHECK(error.openssl_error_code == 0 && !error.has_more_errors);
        } else {
            CHECK(ERR_GET_LIB((unsigned long)error.openssl_error_code) == ERR_LIB_USER);
            CHECK(ERR_GET_REASON((unsigned long)error.openssl_error_code) == 100);
            CHECK(error.has_more_errors);
        }
        CHECK(error.stage == (mode == 0 ? VIREO_TLS_CONTEXT_STAGE_ALLOCATE_WRAPPER :
            (mode < 3 ? VIREO_TLS_CONTEXT_STAGE_CREATE_NATIVE :
                (mode == 3 ? VIREO_TLS_CONTEXT_STAGE_CERTIFICATE : VIREO_TLS_CONTEXT_STAGE_PRIVATE_KEY))));
    }
    fault_state_t state = {0};
    vireo_tls_context_ops_t ops = fault_ops(&state);
    vireo_tls_context_options_t value = options();
    vireo_tls_context_t *owner = NULL;
    EXPECT(vireo_tls_context_create_with_ops(&value, &owner, NULL, &ops), VIREO_OK);
    CHECK(state.allocations == 1 && state.deallocations == 0 && state.bio_calls == 2);
    EXPECT(vireo_tls_context_destroy(&owner, NULL), VIREO_OK);
    CHECK(state.deallocations == 1);
}

/** 无效 own 表在任何资源回调前拒绝；不提供下游可插拔 backend。 */
static void invalid_resource_table(void)
{
    fault_state_t state = {0};
    vireo_tls_context_options_t value = options();
    vireo_tls_context_t *owner = NULL;
    EXPECT(vireo_tls_context_create_with_ops(&value, &owner, NULL, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    for (unsigned int index = 0; index < 4; ++index) {
        vireo_tls_context_ops_t ops = fault_ops(&state);
        if (index == 0) { ops.allocate = NULL; }
        if (index == 1) { ops.deallocate = NULL; }
        if (index == 2) { ops.create_native = NULL; }
        if (index == 3) { ops.create_bio = NULL; }
        EXPECT(vireo_tls_context_create_with_ops(&value, &owner, NULL, &ops), VIREO_RESULT_INVALID_ARGUMENT);
    }
    CHECK(state.allocations == 0 && state.native_calls == 0);
}

/** own white-box 配置破坏只验证防御性观测；不冒真实库自行变异。 */
static void inspect_preserves_output(void)
{
    vireo_tls_context_options_t value = options();
    vireo_tls_context_t *owner = NULL;
    EXPECT(vireo_tls_context_create_server(&value, &owner, NULL), VIREO_OK);
    vireo_tls_context_info_t info;
    memset(&info, 0xA7, sizeof(info));
    unsigned char original[sizeof(info)]; memcpy(original, &info, sizeof(info));
    CHECK(SSL_CTX_set_max_early_data(owner->native, 1) == 1);
    vireo_tls_context_error_t error;
    EXPECT(vireo_tls_context_inspect(owner, &info, &error), VIREO_RESULT_INTERNAL);
    CHECK(error.stage == VIREO_TLS_CONTEXT_STAGE_INSPECT);
    CHECK(memcmp(original, &info, sizeof(info)) == 0);
    CHECK(SSL_CTX_set_max_early_data(owner->native, 0) == 1);
    EXPECT(vireo_tls_context_inspect(owner, &info, NULL), VIREO_OK);
    EXPECT(vireo_tls_context_destroy(&owner, NULL), VIREO_OK);
}

/** 驱动每组后打印实际 PASS；测试上下 fd 一致，不称全部库路径无泄漏。 */
int main(void)
{
    size_t before = fd_count();
#define RUN(function) do { function(); (void)puts("[PASS] " #function); } while (0)
    RUN(lifecycle_and_configuration);
    RUN(invalid_arguments);
    RUN(numeric_boundaries);
    RUN(chain_and_source_lifetime);
    RUN(maximum_material_lengths);
    RUN(malformed_materials);
    RUN(encrypted_materials);
    RUN(mismatched_key);
    RUN(error_queue_contract);
    RUN(allocation_and_library_failures);
    RUN(invalid_resource_table);
    RUN(inspect_preserves_output);
#undef RUN
    size_t after = fd_count();
    CHECK(before == after);
    (void)printf("12 groups passed; fd %zu -> %zu\n", before, after);
    return 0;
}
