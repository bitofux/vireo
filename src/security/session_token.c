#include "session_token_internal.h"
#include <errno.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <string.h>

/* sizeof包含且只包含字符串自带的一个NUL；此字节串是持久摘要v1合同。 */
static unsigned char const domain[] = "vireo/session-token/v1";
_Static_assert(sizeof(domain) == 23, "session digest v1 domain length");
_Static_assert(EVP_MAX_MD_SIZE >= VIREO_SESSION_TOKEN_DIGEST_BYTES, "digest workspace");

static int native_random(void *context, unsigned char *out, int length) {
    (void)context;
    return RAND_priv_bytes(out, length);
}

static EVP_MD_CTX *native_new(void *context) {
    (void)context;
    return EVP_MD_CTX_new();
}

static void native_free(void *context, EVP_MD_CTX *digest) {
    (void)context;
    EVP_MD_CTX_free(digest);
}

static int native_init(void *context, EVP_MD_CTX *digest) {
    (void)context;
    return EVP_DigestInit_ex(digest, EVP_sha256(), NULL);
}

static int native_update(void *context, EVP_MD_CTX *digest, void const *data, size_t length) {
    (void)context;
    return EVP_DigestUpdate(digest, data, length);
}

static int native_final(void *context, EVP_MD_CTX *digest, unsigned char *out, unsigned int *length) {
    (void)context;
    return EVP_DigestFinal_ex(digest, out, length);
}

static vireo_session_token_runtime_t const native_runtime = {
    NULL, native_random, native_new, native_free, native_init, native_update, native_final
};

static bool digest_runtime_valid(vireo_session_token_runtime_t const *runtime) {
    return runtime != NULL && runtime->digest_new != NULL && runtime->digest_free != NULL &&
        runtime->digest_init != NULL && runtime->digest_update != NULL && runtime->digest_final != NULL;
}

/* caller已验证地址；局部EVP最大输出区避免把native接口的容量假设传给caller。 */
static vireo_result_t calculate(vireo_session_token_t const *token,
    vireo_session_token_digest_t *digest, vireo_session_token_runtime_t const *runtime) {
    unsigned char temporary[EVP_MAX_MD_SIZE] = {0};
    unsigned int length = 0;
    vireo_result_t result = VIREO_RESULT_NO_MEMORY;
    EVP_MD_CTX *context = runtime->digest_new(runtime->context);
    if (context == NULL) { goto done; }
    result = VIREO_RESULT_INTERNAL;
    if (runtime->digest_init(runtime->context, context) != 1) { goto done; }
    if (runtime->digest_update(runtime->context, context, domain, sizeof(domain)) != 1) { goto done; }
    if (runtime->digest_update(runtime->context, context, token->bytes, sizeof(token->bytes)) != 1) {
        goto done;
    }
    if (runtime->digest_final(runtime->context, context, temporary, &length) != 1 ||
        length != VIREO_SESSION_TOKEN_DIGEST_BYTES) { goto done; }
    memcpy(digest->bytes, temporary, sizeof(digest->bytes));
    result = VIREO_OK;
done:
    if (context != NULL) { runtime->digest_free(runtime->context, context); }
    OPENSSL_cleanse(temporary, sizeof(temporary));
    return result;
}

vireo_result_t vireo_session_token_generate_with_runtime(vireo_session_token_t *token,
    vireo_session_token_digest_t *digest, vireo_session_token_runtime_t const *runtime) {
    int const saved_errno = errno;
    vireo_session_token_t temporary_token = {{0}};
    vireo_session_token_digest_t temporary_digest = {{0}};
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    if (token == NULL || digest == NULL || !digest_runtime_valid(runtime) ||
        runtime->random_bytes == NULL) { goto done; }
    if (runtime->random_bytes(runtime->context, temporary_token.bytes,
            VIREO_SESSION_TOKEN_BYTES) != 1) {
        result = VIREO_RESULT_IO;
        goto done;
    }
    result = calculate(&temporary_token, &temporary_digest, runtime);
    if (result == VIREO_OK) {
        *token = temporary_token;
        *digest = temporary_digest;
    }
done:
    OPENSSL_cleanse(&temporary_token, sizeof(temporary_token));
    OPENSSL_cleanse(&temporary_digest, sizeof(temporary_digest));
    errno = saved_errno;
    return result;
}

vireo_result_t vireo_session_token_digest_with_runtime(vireo_session_token_t const *token,
    vireo_session_token_digest_t *digest, vireo_session_token_runtime_t const *runtime) {
    int const saved_errno = errno;
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    if (token != NULL && digest != NULL && digest_runtime_valid(runtime)) {
        result = calculate(token, digest, runtime);
    }
    errno = saved_errno;
    return result;
}

vireo_result_t vireo_session_token_generate(
    vireo_session_token_t *token, vireo_session_token_digest_t *digest) {
    return vireo_session_token_generate_with_runtime(token, digest, &native_runtime);
}

vireo_result_t vireo_session_token_digest(
    vireo_session_token_t const *token, vireo_session_token_digest_t *digest) {
    return vireo_session_token_digest_with_runtime(token, digest, &native_runtime);
}

vireo_result_t vireo_session_token_digest_equal(vireo_session_token_digest_t const *left,
    vireo_session_token_digest_t const *right, bool *matches) {
    int const saved_errno = errno;
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    if (left != NULL && right != NULL && matches != NULL) {
        *matches = CRYPTO_memcmp(left->bytes, right->bytes, sizeof(left->bytes)) == 0;
        result = VIREO_OK;
    }
    errno = saved_errno;
    return result;
}

vireo_result_t vireo_session_token_clear(vireo_session_token_t *token) {
    int const saved_errno = errno;
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    if (token != NULL) {
        OPENSSL_cleanse(token->bytes, sizeof(token->bytes));
        result = VIREO_OK;
    }
    errno = saved_errno;
    return result;
}
