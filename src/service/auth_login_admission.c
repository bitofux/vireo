/* PROJECT : VIREO
 * FILE : auth_login_admission.c
 * DATE : 2026-10-19
 * BRIEF : 无IO/采时/锁的三身份构键及一次037完整扣费。
 */
#include "auth_login_admission_internal.h"
#include <vireo/service/auth_username.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

static void *native_allocate(void *context, size_t bytes)
{
    (void)context;
    return malloc(bytes);
}

static void native_release(void *context, void *memory)
{
    (void)context;
    free(memory);
}

static vireo_result_t native_create_limiter(void *context,
    vireo_rate_limiter_options_t const *options, vireo_rate_limit_policy_t const *policies,
    size_t count, vireo_monotonic_ns_t now, vireo_rate_limiter_t **out)
{
    (void)context;
    return vireo_rate_limiter_create(options, policies, count, now, out);
}

static vireo_auth_login_admission_runtime_t const native_runtime = {
    NULL, native_allocate, native_release, native_create_limiter
};

vireo_result_t vireo_auth_login_admission_create_with_runtime(
    vireo_auth_login_admission_options_t const *options, vireo_monotonic_ns_t now,
    vireo_auth_login_admission_t **out, vireo_auth_login_admission_runtime_t const *runtime)
{
    int const saved = errno;
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    if (options == NULL || out == NULL || *out != NULL || runtime == NULL ||
        runtime->allocate == NULL || runtime->release == NULL || runtime->create_limiter == NULL) {
        goto done;
    }
    vireo_rate_limiter_options_t const storage = {options->max_keys, options->max_memory_bytes};
    vireo_rate_limit_policy_t const policies[] = {
        {1, options->peer.burst_tokens, options->peer.refill_interval_ns},
        {2, options->account.burst_tokens, options->account.refill_interval_ns},
        {3, options->device.burst_tokens, options->device.refill_interval_ns}
    };
    /* 先由037验证资源数学/政策并取得子owner；wrapper失败时完整回滚。
     * 不复制037私有sizeof或预算算法，也不为了验证配置做重复试分配。 */
    vireo_rate_limiter_t *limiter = NULL;
    result = runtime->create_limiter(runtime->context, &storage, policies, 3, now, &limiter);
    if (result != VIREO_OK) { goto done; }
    vireo_auth_login_admission_t *admission = runtime->allocate(runtime->context, sizeof(*admission));
    if (admission == NULL) {
        (void)vireo_rate_limiter_destroy(&limiter);
        result = VIREO_RESULT_NO_MEMORY;
        goto done;
    }
    admission->limiter = limiter;
    admission->runtime = *runtime;
    *out = admission;
    result = VIREO_OK;
done:
    errno = saved;
    return result;
}

vireo_result_t vireo_auth_login_admission_create(
    vireo_auth_login_admission_options_t const *options, vireo_monotonic_ns_t now,
    vireo_auth_login_admission_t **out)
{
    return vireo_auth_login_admission_create_with_runtime(options, now, out, &native_runtime);
}

vireo_result_t vireo_auth_login_admission_check(vireo_auth_login_admission_t *admission,
    vireo_monotonic_ns_t now, vireo_auth_login_peer_t const *peer,
    char const *username, size_t username_length,
    unsigned char const device[VIREO_AUTH_LOGIN_DEVICE_BYTES], vireo_rate_limit_decision_t *decision)
{
    int const saved = errno;
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    if (admission == NULL || peer == NULL || username == NULL || device == NULL || decision == NULL) {
        goto done;
    }
    if (username_length < VIREO_AUTH_USERNAME_MIN_LENGTH ||
        username_length > VIREO_AUTH_USERNAME_MAX_LENGTH) { result = VIREO_RESULT_RANGE; goto done; }
    if (peer->family != VIREO_AUTH_LOGIN_PEER_IPV4 && peer->family != VIREO_AUTH_LOGIN_PEER_IPV6) {
        goto done;
    }
    if (peer->family == VIREO_AUTH_LOGIN_PEER_IPV4) {
        for (size_t i = 4; i < sizeof(peer->address); ++i) {
            if (peer->address[i] != 0) { goto done; }
        }
    }
    vireo_auth_username_t account;
    result = vireo_auth_username_prepare(username, username_length, &account);
    if (result != VIREO_OK) { goto done; }
    vireo_rate_limit_request_t requests[3] = {{.policy_id = 1, .cost = 1},
        {.policy_id = 2, .cost = 1}, {.policy_id = 3, .cost = 1}};
    /* 不按原生结构内存编码；mapped IPv6显式取最后4字节，与IPv4共桶。 */
    static unsigned char const mapped_prefix[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
    if (peer->family == VIREO_AUTH_LOGIN_PEER_IPV6 &&
        memcmp(peer->address, mapped_prefix, sizeof(mapped_prefix)) == 0) {
        requests[0].key[0] = VIREO_AUTH_LOGIN_PEER_IPV4;
        memcpy(requests[0].key + 1, peer->address + 12, 4);
    } else {
        requests[0].key[0] = peer->family;
        memcpy(requests[0].key + 1, peer->address,
            peer->family == VIREO_AUTH_LOGIN_PEER_IPV4 ? 4 : 16);
    }
    memcpy(requests[1].key, account.key, sizeof(account.key));
    memcpy(requests[2].key, device, VIREO_AUTH_LOGIN_DEVICE_BYTES);
    result = vireo_rate_limiter_check(admission->limiter, now, requests, 3, decision);
done:
    errno = saved;
    return result;
}

vireo_result_t vireo_auth_login_admission_destroy(vireo_auth_login_admission_t **owner)
{
    int const saved = errno;
    if (owner == NULL) { return VIREO_RESULT_INVALID_ARGUMENT; }
    if (*owner != NULL) {
        vireo_auth_login_admission_runtime_t const runtime = (*owner)->runtime;
        (void)vireo_rate_limiter_destroy(&(*owner)->limiter);
        runtime.release(runtime.context, *owner);
        *owner = NULL;
    }
    errno = saved;
    return VIREO_OK;
}
