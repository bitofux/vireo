/*
 * PROJECT : VIREO
 * FILE    : auth_password.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-19
 * BRIEF   : 统一密码格式、原子双额度及低层计算的成对收尾。
 * IMPLEMENTATION : 同一原子值提交count和KiB；计算结束才归还，不在close时清账。
 */
#include "auth_password_internal.h"
#include <errno.h>
#include <limits.h>
#include <openssl/crypto.h>
#include <stdlib.h>
#include <string.h>

_Static_assert(CHAR_BIT == 8, "auth passwords require 8-bit bytes");

#define COUNT_MASK UINT64_C(511)
#define MEMORY_MASK UINT64_C(2097151)
#define CLOSED_BIT (UINT64_C(1) << 30)

static vireo_password_policy_t const policy = {65536, 3, 262144, 10, 64};

/* native适配只桥接公开合同；不引入跨层私有状态。 */
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

static vireo_result_t native_create(void *context, vireo_password_policy_t const *p,
    void const *password, size_t length, char *encoded, size_t capacity, size_t *written)
{
    (void)context;
    return vireo_password_hash_create(p, password, length, encoded, capacity, written);
}

static vireo_result_t native_inspect(void *context, vireo_password_policy_t const *p,
    char const *encoded, size_t length, vireo_password_info_t *info)
{
    (void)context;
    return vireo_password_hash_inspect(p, encoded, length, info);
}

static vireo_result_t native_verify(void *context, vireo_password_policy_t const *p,
    void const *password, size_t length, char const *encoded, size_t encoded_length, bool *matches)
{
    (void)context;
    return vireo_password_hash_verify(p, password, length, encoded, encoded_length, matches);
}

/**
 * @brief native依赖的seq_cst弱CAS适配，失败按C11更新expected。
 * @param[in] context native固定NULL，不访问。
 * @param[in,out] state 存活的共享原子值。
 * @param[in,out] expected caller独占的本次比较值，失败更新为观察值。
 * @param[in] desired 通过两额度检查后的完整新状态。
 * @retval true 完整提交，原子序列中的成功预留点。
 * @retval false 未提交，可能是竞争或弱CAS伪失败。
 * @note 不等待容量，不保证平台lock-free；只供reserve调用。
 */
static bool native_compare_exchange(void *context, atomic_uint_least64_t *state,
    uint_least64_t *expected, uint_least64_t desired)
{
    (void)context;
    return atomic_compare_exchange_weak(state, expected, desired);
}

static vireo_auth_password_runtime_t const native_runtime = {
    NULL, native_allocate, native_deallocate, native_create, native_inspect, native_verify,
    native_compare_exchange
};

vireo_result_t vireo_auth_password_validate(void const *password, size_t length)
{
    if (password == NULL) { return VIREO_RESULT_INVALID_ARGUMENT; }
    if (length < VIREO_AUTH_PASSWORD_MIN_BYTES || length > VIREO_AUTH_PASSWORD_MAX_BYTES) {
        return VIREO_RESULT_RANGE;
    }
    unsigned char const *bytes = password;
    for (size_t i = 0; i < length; ++i) {
        if (bytes[i] < 0x21 || bytes[i] > 0x7e) { return VIREO_RESULT_PROTOCOL; }
    }
    return VIREO_OK;
}

vireo_result_t vireo_auth_password_gate_create_with_runtime(
    vireo_auth_password_gate_options_t const *options, vireo_auth_password_gate_t **out,
    vireo_auth_password_runtime_t const *runtime)
{
    int const saved = errno;
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    if (options == NULL || out == NULL || *out != NULL || runtime == NULL ||
        runtime->allocate == NULL || runtime->deallocate == NULL || runtime->create == NULL ||
        runtime->inspect == NULL || runtime->verify == NULL || runtime->compare_exchange == NULL) {
        goto done;
    }
    if (options->max_parallel < 1 || options->max_parallel > VIREO_AUTH_PASSWORD_MAX_PARALLEL ||
        options->memory_budget_kib < VIREO_AUTH_PASSWORD_MIN_BUDGET_KIB ||
        options->memory_budget_kib > VIREO_AUTH_PASSWORD_MAX_BUDGET_KIB) {
        result = VIREO_RESULT_RANGE;
        goto done;
    }
    vireo_auth_password_gate_t *gate = runtime->allocate(runtime->context, sizeof(*gate));
    if (gate == NULL) { result = VIREO_RESULT_NO_MEMORY; goto done; }
    gate->max_parallel = options->max_parallel;
    gate->memory_budget_kib = options->memory_budget_kib;
    gate->runtime = *runtime;
    atomic_init(&gate->state, 0);
    *out = gate;
    result = VIREO_OK;
done:
    errno = saved;
    return result;
}

vireo_result_t vireo_auth_password_gate_create(
    vireo_auth_password_gate_options_t const *options, vireo_auth_password_gate_t **out)
{
    return vireo_auth_password_gate_create_with_runtime(options, out, &native_runtime);
}

vireo_result_t vireo_auth_password_gate_close(vireo_auth_password_gate_t *gate)
{
    int const saved = errno;
    if (gate == NULL) { return VIREO_RESULT_INVALID_ARGUMENT; }
    (void)atomic_fetch_or(&gate->state, CLOSED_BIT);
    errno = saved;
    return VIREO_OK;
}

vireo_result_t vireo_auth_password_gate_destroy(vireo_auth_password_gate_t **owner)
{
    int const saved = errno;
    if (owner == NULL) { return VIREO_RESULT_INVALID_ARGUMENT; }
    if (*owner == NULL) { return VIREO_OK; }
    uint_least64_t const state = atomic_load(&(*owner)->state);
    if (state != CLOSED_BIT) { errno = saved; return VIREO_RESULT_BUSY; }
    (*owner)->runtime.deallocate((*owner)->runtime.context, *owner);
    *owner = NULL;
    errno = saved;
    return VIREO_OK;
}

/**
 * @brief 用至多32次弱CAS一起预留双额度；没有等待者或半收费。
 * @param[in,out] gate 存活共享对象；不与destroy并发。
 * @param[in] memory_kib 已由固定生成参数或035inspect获准的完整m。
 * @retval VIREO_OK 已计费一槽及memory_kib，caller必须在低层返回后恰好归还。
 * @retval VIREO_RESULT_CANCELLED 观察到永久关闭。
 * @retval VIREO_RESULT_BUSY 任一额度不足或竞争尝试耗尽。
 * @note private runtime须正常返回；不支持取消跳栈，不发布业务结果。
 */
static vireo_result_t reserve(vireo_auth_password_gate_t *gate, uint32_t memory_kib)
{
    uint_least64_t state = atomic_load(&gate->state);
    uint_least64_t const amount = ((uint_least64_t)memory_kib << 9) + 1;
    for (unsigned int attempt = 0; attempt < 32; ++attempt) {
        if ((state & CLOSED_BIT) != 0) { return VIREO_RESULT_CANCELLED; }
        uint_least64_t const count = state & COUNT_MASK;
        uint_least64_t const used = (state >> 9) & MEMORY_MASK;
        if (count >= gate->max_parallel || memory_kib > gate->memory_budget_kib - used) {
            return VIREO_RESULT_BUSY;
        }
        if (gate->runtime.compare_exchange(gate->runtime.context, &gate->state, &state,
                                          state + amount)) { return VIREO_OK; }
    }
    return VIREO_RESULT_BUSY;
}

/**
 * @brief 只有成功reserve的栈在低层返回后用同一m归还，两个分量足够、不跨字段借位。
 * @param[in,out] gate 仍存活的共享对象，不与destroy并发。
 * @param[in] memory_kib 本栈已预留且尚未归还的完整m参数。
 * @note 一次seq_cst原子减法，不根据closed跳过归还；不支持重复或无预留调用。
 */
static void release(vireo_auth_password_gate_t *gate, uint32_t memory_kib)
{
    (void)atomic_fetch_sub(&gate->state, ((uint_least64_t)memory_kib << 9) + 1);
}

vireo_result_t vireo_auth_password_hash_create(vireo_auth_password_gate_t *gate,
    void const *password, size_t length, char *encoded, size_t capacity, size_t *encoded_length)
{
    int const saved = errno;
    char temporary[VIREO_PASSWORD_ENCODED_CAPACITY] = {0};
    size_t written = 0;
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    if (gate == NULL || password == NULL || encoded == NULL || encoded_length == NULL) { goto done; }
    if (capacity < VIREO_PASSWORD_ENCODED_CAPACITY || length < VIREO_AUTH_PASSWORD_MIN_BYTES ||
        length > VIREO_AUTH_PASSWORD_MAX_BYTES) { result = VIREO_RESULT_RANGE; goto done; }
    result = vireo_auth_password_validate(password, length);
    if (result != VIREO_OK) { goto done; }
    result = reserve(gate, policy.create_memory_kib);
    if (result != VIREO_OK) { goto done; }
    result = gate->runtime.create(gate->runtime.context, &policy, password, length,
                                  temporary, sizeof(temporary), &written);
    release(gate, policy.create_memory_kib);
    if (result == VIREO_OK) {
        if (written == 0 || written >= sizeof(temporary) || temporary[written] != '\0') {
            result = VIREO_RESULT_INTERNAL;
        } else {
            memcpy(encoded, temporary, written + 1);
            *encoded_length = written;
        }
    }
done:
    OPENSSL_cleanse(temporary, sizeof(temporary));
    errno = saved;
    return result;
}

vireo_result_t vireo_auth_password_hash_verify(vireo_auth_password_gate_t *gate,
    void const *password, size_t length, char const *encoded, size_t encoded_length, bool *matches)
{
    int const saved = errno;
    vireo_password_info_t info = {0};
    bool temporary = false;
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    if (gate == NULL || password == NULL || encoded == NULL || matches == NULL) { goto done; }
    if (length < VIREO_AUTH_PASSWORD_MIN_BYTES || length > VIREO_AUTH_PASSWORD_MAX_BYTES ||
        encoded_length == 0 || encoded_length >= VIREO_PASSWORD_ENCODED_CAPACITY) {
        result = VIREO_RESULT_RANGE;
        goto done;
    }
    result = vireo_auth_password_validate(password, length);
    if (result != VIREO_OK) { goto done; }
    result = gate->runtime.inspect(gate->runtime.context, &policy, encoded, encoded_length, &info);
    if (result != VIREO_OK) { goto done; }
    result = reserve(gate, info.memory_kib);
    if (result != VIREO_OK) { goto done; }
    result = gate->runtime.verify(gate->runtime.context, &policy, password, length,
                                  encoded, encoded_length, &temporary);
    release(gate, info.memory_kib);
    if (result == VIREO_OK) { *matches = temporary; }
done:
    OPENSSL_cleanse(&info, sizeof(info));
    OPENSSL_cleanse(&temporary, sizeof(temporary));
    errno = saved;
    return result;
}
