/* 同步密码设施：先检查成本，临时结果完整后才提交caller输出。 */
#include "password_internal.h"
#include <argon2.h>
#include <errno.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>

static int native_allocate(uint8_t **out, size_t bytes) {
    *out = malloc(bytes);
    return *out == NULL ? -1 : 0;
}

static void native_free(uint8_t *memory, size_t bytes) {
    /* 本组件持有的矩阵释放边界显式清理，不修改第三方全局清理开关。 */
    if (memory != NULL) { OPENSSL_cleanse(memory, bytes); }
    free(memory);
}

static int random_bytes(void *context, unsigned char *out, int length) {
    (void)context;
    return RAND_bytes(out, length);
}

static vireo_result_t derive(void *context, void const *password, size_t length,
    unsigned char const salt[VIREO_PASSWORD_SALT_BYTES], uint32_t memory_kib,
    uint32_t iterations, unsigned char tag[VIREO_PASSWORD_TAG_BYTES]) {
    (void)context;
    unsigned char password_copy[VIREO_PASSWORD_MAX_BYTES] = {0};
    unsigned char salt_copy[VIREO_PASSWORD_SALT_BYTES];
    memcpy(password_copy, password, length);
    memcpy(salt_copy, salt, sizeof(salt_copy));
    argon2_context native = {
        .out = tag, .outlen = VIREO_PASSWORD_TAG_BYTES,
        .pwd = password_copy, .pwdlen = (uint32_t)length,
        .salt = salt_copy, .saltlen = VIREO_PASSWORD_SALT_BYTES,
        .secret = NULL, .secretlen = 0, .ad = NULL, .adlen = 0,
        .t_cost = iterations, .m_cost = memory_kib, .lanes = 1, .threads = 1,
        .version = ARGON2_VERSION_13, .allocate_cbk = native_allocate, .free_cbk = native_free,
        .flags = ARGON2_FLAG_CLEAR_PASSWORD
    };
    int const result = argon2id_ctx(&native);
    OPENSSL_cleanse(password_copy, sizeof(password_copy));
    OPENSSL_cleanse(salt_copy, sizeof(salt_copy));
    OPENSSL_cleanse(&native, sizeof(native));
    if (result == ARGON2_OK) { return VIREO_OK; }
    return result == ARGON2_MEMORY_ALLOCATION_ERROR ? VIREO_RESULT_NO_MEMORY : VIREO_RESULT_INTERNAL;
}

static vireo_password_runtime_t const native_runtime = {NULL, random_bytes, derive};

vireo_result_t vireo_password_create_with_runtime(vireo_password_policy_t const *policy,
    void const *password, size_t length, char *encoded, size_t capacity,
    size_t *encoded_length, vireo_password_runtime_t const *runtime) {
    int const saved_errno = errno;
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    unsigned char salt[VIREO_PASSWORD_SALT_BYTES] = {0};
    unsigned char tag[VIREO_PASSWORD_TAG_BYTES] = {0};
    char temporary[VIREO_PASSWORD_ENCODED_CAPACITY] = {0};
    size_t written = 0;
    if (!vireo_password_policy_valid(policy) || password == NULL || encoded == NULL ||
        encoded_length == NULL || runtime == NULL || runtime->random_bytes == NULL ||
        runtime->derive == NULL) { goto done; }
    if (length == 0 || length > policy->max_password_bytes ||
        capacity < VIREO_PASSWORD_ENCODED_CAPACITY) {
        result = VIREO_RESULT_RANGE;
        goto done;
    }
    if (runtime->random_bytes(runtime->context, salt, VIREO_PASSWORD_SALT_BYTES) != 1) {
        result = VIREO_RESULT_IO;
        goto done;
    }
    result = runtime->derive(runtime->context, password, length, salt,
        policy->create_memory_kib, policy->create_iterations, tag);
    if (result != VIREO_OK) { goto done; }
    result = vireo_password_encode(policy->create_memory_kib, policy->create_iterations,
        salt, tag, temporary, &written);
    if (result == VIREO_OK) {
        memcpy(encoded, temporary, written + 1);
        *encoded_length = written;
    }
done:
    OPENSSL_cleanse(salt, sizeof(salt));
    OPENSSL_cleanse(tag, sizeof(tag));
    OPENSSL_cleanse(temporary, sizeof(temporary));
    errno = saved_errno;
    return result;
}

vireo_result_t vireo_password_hash_create(vireo_password_policy_t const *policy,
    void const *password, size_t length, char *encoded, size_t capacity, size_t *encoded_length) {
    return vireo_password_create_with_runtime(policy, password, length, encoded, capacity,
        encoded_length, &native_runtime);
}

vireo_result_t vireo_password_hash_inspect(vireo_password_policy_t const *policy,
    char const *encoded, size_t length, vireo_password_info_t *info) {
    int const saved_errno = errno;
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    vireo_password_record_t record = {0};
    if (!vireo_password_policy_valid(policy) || encoded == NULL || info == NULL) { goto done; }
    if (length == 0 || length >= VIREO_PASSWORD_ENCODED_CAPACITY) {
        result = VIREO_RESULT_RANGE;
        goto done;
    }
    result = vireo_password_parse(policy, encoded, length, &record);
    if (result == VIREO_OK) { *info = record.info; }
done:
    OPENSSL_cleanse(&record, sizeof(record));
    errno = saved_errno;
    return result;
}

vireo_result_t vireo_password_verify_with_runtime(vireo_password_policy_t const *policy,
    void const *password, size_t length, char const *encoded, size_t encoded_length,
    bool *matches, vireo_password_runtime_t const *runtime) {
    int const saved_errno = errno;
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    vireo_password_record_t record = {0};
    unsigned char tag[VIREO_PASSWORD_TAG_BYTES] = {0};
    if (!vireo_password_policy_valid(policy) || password == NULL || encoded == NULL ||
        matches == NULL || runtime == NULL || runtime->derive == NULL) { goto done; }
    if (length == 0 || length > policy->max_password_bytes || encoded_length == 0 ||
        encoded_length >= VIREO_PASSWORD_ENCODED_CAPACITY) {
        result = VIREO_RESULT_RANGE;
        goto done;
    }
    result = vireo_password_parse(policy, encoded, encoded_length, &record);
    if (result != VIREO_OK) { goto done; }
    result = runtime->derive(runtime->context, password, length, record.salt,
        record.info.memory_kib, record.info.iterations, tag);
    if (result == VIREO_OK) { *matches = CRYPTO_memcmp(tag, record.tag, sizeof(tag)) == 0; }
done:
    OPENSSL_cleanse(tag, sizeof(tag));
    OPENSSL_cleanse(&record, sizeof(record));
    errno = saved_errno;
    return result;
}

vireo_result_t vireo_password_hash_verify(vireo_password_policy_t const *policy,
    void const *password, size_t length, char const *encoded, size_t encoded_length, bool *matches) {
    return vireo_password_verify_with_runtime(policy, password, length, encoded, encoded_length,
        matches, &native_runtime);
}
