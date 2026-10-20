/*
 * PROJECT : VIREO
 * FILE    : auth_login_verifier.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-19
 * BRIEF   : 一次构造替代PHC，按可信账户快照统一验密与拒绝。
 * IMPLEMENTATION : 不保存外部gate或数据库owner，只有active真实匹配可发布true。
 */
#include "auth_login_verifier_internal.h"
#include <errno.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>

static void *native_allocate(void *context, size_t bytes)
{
    (void)context;
    return malloc(bytes);
}

static void native_deallocate(void *context, void *memory)
{
    (void)context;
    free(memory);
}

static vireo_result_t native_random(void *context, unsigned char bytes[32])
{
    (void)context;
    return RAND_priv_bytes(bytes, 32) == 1 ? VIREO_OK : VIREO_RESULT_IO;
}

static vireo_result_t native_create(void *context, vireo_auth_password_gate_t *gate,
    void const *password, size_t length, char *encoded, size_t capacity, size_t *written)
{
    (void)context;
    return vireo_auth_password_hash_create(gate, password, length, encoded, capacity, written);
}

static vireo_result_t native_verify(void *context, vireo_auth_password_gate_t *gate,
    void const *password, size_t length, char const *encoded, size_t encoded_length, bool *matches)
{
    (void)context;
    return vireo_auth_password_hash_verify(gate, password, length, encoded, encoded_length, matches);
}

static vireo_auth_login_verifier_runtime_t const native_runtime = {
    NULL, native_allocate, native_deallocate, native_random, native_create, native_verify
};

/**
 * @brief 先复制释放依赖，再擦除整个对象，避免从已清零字段读取函数指针。
 * @param[in,out] value 独占且存活对象，无任何并发借用；runtime已完整初始化。
 * @note 同时用于构造失败和排他销毁；不返回资源，不修改caller的owner。
 */
static void discard(vireo_auth_login_verifier_t *value)
{
    vireo_auth_login_verifier_runtime_t const runtime = value->runtime;
    OPENSSL_cleanse(value, sizeof(*value));
    runtime.deallocate(runtime.context, value);
}

vireo_result_t vireo_auth_login_verifier_create_with_runtime(vireo_auth_password_gate_t *gate,
    vireo_auth_login_verifier_t **out, vireo_auth_login_verifier_runtime_t const *runtime)
{
    int const saved = errno;
    unsigned char random[32] = {0};
    char password[64] = {0};
    vireo_password_info_t info = {0};
    vireo_password_policy_t const policy = VIREO_PASSWORD_POLICY_DEFAULT;
    vireo_auth_login_verifier_t *value = NULL;
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    if (gate == NULL || out == NULL || *out != NULL || runtime == NULL ||
        runtime->allocate == NULL || runtime->deallocate == NULL || runtime->random == NULL ||
        runtime->create == NULL || runtime->verify == NULL) { goto done; }
    value = runtime->allocate(runtime->context, sizeof(*value));
    if (value == NULL) { result = VIREO_RESULT_NO_MEMORY; goto done; }
    memset(value, 0, sizeof(*value));
    value->runtime = *runtime;
    result = runtime->random(runtime->context, random);
    if (result != VIREO_OK) { goto done; }
    static char const hex[] = "0123456789abcdef";
    for (size_t i = 0; i < sizeof(random); ++i) {
        password[2 * i] = hex[random[i] >> 4];
        password[2 * i + 1] = hex[random[i] & 15];
    }
    result = runtime->create(runtime->context, gate, password, sizeof(password),
        value->dummy_hash, sizeof(value->dummy_hash), &value->dummy_hash_length);
    if (result != VIREO_OK) { goto done; }
    /* 检查长度后才下标访问；测试依赖也不能发布不符合本层固定生成合同的对象。 */
    if (value->dummy_hash_length == 0 || value->dummy_hash_length >= sizeof(value->dummy_hash) ||
        value->dummy_hash[value->dummy_hash_length] != '\0' ||
        vireo_password_hash_inspect(&policy, value->dummy_hash, value->dummy_hash_length, &info) != VIREO_OK ||
        info.memory_kib != 65536 || info.iterations != 3) {
        result = VIREO_RESULT_INTERNAL;
        goto done;
    }
    *out = value;
    value = NULL;
done:
    if (value != NULL) { discard(value); }
    OPENSSL_cleanse(random, sizeof(random));
    OPENSSL_cleanse(password, sizeof(password));
    OPENSSL_cleanse(&info, sizeof(info));
    errno = saved;
    return result;
}

vireo_result_t vireo_auth_login_verifier_create(
    vireo_auth_password_gate_t *gate, vireo_auth_login_verifier_t **out)
{
    return vireo_auth_login_verifier_create_with_runtime(gate, out, &native_runtime);
}

vireo_result_t vireo_auth_login_verifier_verify(vireo_auth_login_verifier_t const *verifier,
    vireo_auth_password_gate_t *gate, vireo_mysql_user_credentials_t const *credentials,
    void const *password, size_t length, bool *authenticated)
{
    int const saved = errno;
    bool matches = false;
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    if (verifier == NULL || gate == NULL || password == NULL || authenticated == NULL) { goto done; }
    result = vireo_auth_password_validate(password, length);
    if (result != VIREO_OK) { goto done; }
    if (credentials != NULL) {
        if (credentials->user_id == 0 || (credentials->status != VIREO_MYSQL_USER_STATUS_ACTIVE &&
            credentials->status != VIREO_MYSQL_USER_STATUS_DISABLED)) {
            result = VIREO_RESULT_INVALID_ARGUMENT;
            goto done;
        }
        if (credentials->password_hash_length == 0 ||
            credentials->password_hash_length >= VIREO_PASSWORD_ENCODED_CAPACITY) {
            result = VIREO_RESULT_RANGE;
            goto done;
        }
    }
    char const *encoded = credentials != NULL ? credentials->password_hash : verifier->dummy_hash;
    size_t const encoded_length = credentials != NULL ? credentials->password_hash_length : verifier->dummy_hash_length;
    result = verifier->runtime.verify(verifier->runtime.context, gate, password, length,
        encoded, encoded_length, &matches);
    if (result == VIREO_OK) {
        *authenticated = credentials != NULL && credentials->status == VIREO_MYSQL_USER_STATUS_ACTIVE && matches;
    }
done:
    OPENSSL_cleanse(&matches, sizeof(matches));
    errno = saved;
    return result;
}

vireo_result_t vireo_auth_login_verifier_destroy(vireo_auth_login_verifier_t **owner)
{
    int const saved = errno;
    if (owner == NULL) { return VIREO_RESULT_INVALID_ARGUMENT; }
    if (*owner != NULL) {
        discard(*owner);
        *owner = NULL;
    }
    errno = saved;
    return VIREO_OK;
}
