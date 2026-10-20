/* PROJECT : VIREO
 * FILE : auth_task_context.c
 * AUTHOR : bitofux
 * DATE : 2026-10-20
 * BRIEF : 不重试的随机/UTC/单调采样及受检时间装配。
 */
#define _POSIX_C_SOURCE 200809L
#include "auth_task_context_internal.h"
#include <vireo/base/checked.h>
#include <vireo/base/secure_clear.h>
#include <errno.h>
#include <openssl/rand.h>

/* 原生桥接只让外层解释其返回约定和独立诊断，不输出OpenSSL文本。 */
static int random_native(void *context, unsigned char out[16])
{ (void)context; return RAND_priv_bytes(out, 16); }
static int utc_native(void *context, struct timespec *out)
{ (void)context; return clock_gettime(CLOCK_REALTIME, out); }
static vireo_result_t monotonic_native(void *context, vireo_monotonic_ns_t *out,
    vireo_clock_error_t *error)
{ (void)context; return vireo_clock_monotonic_now(out, error); }
static vireo_auth_context_ops_t const native_ops = {random_native, utc_native, monotonic_native, NULL};

vireo_result_t vireo_auth_task_context_with(vireo_task_t const *task,
    vireo_monotonic_ns_t received_at_ns, uint64_t session_lifetime_ms,
    vireo_auth_task_options_t const *options,
    vireo_auth_task_context_t *out, vireo_auth_context_error_t *error,
    vireo_auth_context_ops_t const *ops)
{
    int const saved_errno = errno;
    vireo_auth_context_error_t diagnostic = {0};
    vireo_auth_task_context_t value = {0};
    vireo_result_t rc = VIREO_RESULT_INVALID_ARGUMENT;
    if (task == NULL || options == NULL || out == NULL || ops == NULL || ops->random == NULL ||
        ops->utc == NULL || ops->monotonic == NULL) goto done;
    diagnostic.stage = VIREO_AUTH_CONTEXT_TASK;
    vireo_task_info_t info;
    rc = vireo_task_inspect(task, &info);
    if (rc != VIREO_OK) goto done;
    value.metadata = info.metadata;
    vireo_task_payload_view_t payload;
    rc = vireo_task_borrow_payload(task, &payload);
    if (rc != VIREO_OK) goto done;
    diagnostic.stage = VIREO_AUTH_CONTEXT_DECODE;
    if (payload.size == 0) {
        diagnostic.request_issue = VIREO_AUTH_REQUEST_ISSUE_HEADER;
        rc = VIREO_RESULT_PROTOCOL; goto done;
    }
    vireo_auth_request_view_t view;
    vireo_auth_logout_identity_t identity;
    vireo_command_t const command = vireo_auth_task_command(options, info.metadata.operation);
    if (!command) { rc=VIREO_RESULT_INVALID_ARGUMENT; goto done; }
    rc = vireo_auth_task_borrow_request(task, command, &view, &identity, &diagnostic.request_issue);
    if (rc != VIREO_OK) goto done;
    bool const login = view.command == VIREO_COMMAND_LOGIN;
    if (login && session_lifetime_ms == 0) {
        diagnostic.stage = VIREO_AUTH_CONTEXT_NONE;
        rc = VIREO_RESULT_RANGE; goto done;
    }
    diagnostic.stage = VIREO_AUTH_CONTEXT_RANDOM;
    rc = VIREO_RESULT_IO;
    if (ops->random(ops->context, value.request_id) != 1) goto done;
    unsigned char bits = 0;
    for (size_t i = 0; i < sizeof(value.request_id); ++i) bits |= value.request_id[i];
    if (bits == 0) goto done;
    diagnostic.stage = VIREO_AUTH_CONTEXT_UTC;
    struct timespec utc = {0};
    int const sampled = ops->utc(ops->context, &utc);
    if (sampled == -1) { diagnostic.system_errno = errno; goto done; }
    rc = VIREO_RESULT_INTERNAL;
    if (sampled != 0 || utc.tv_sec < 0 || utc.tv_nsec < 0 || utc.tv_nsec >= 1000000000L) goto done;
    rc = VIREO_RESULT_OVERFLOW;
    if ((uintmax_t)utc.tv_sec > UINT64_MAX) goto done;
    uint64_t seconds_ms = 0;
    rc = vireo_checked_u64_mul((uint64_t)utc.tv_sec, UINT64_C(1000), &seconds_ms);
    if (rc != VIREO_OK) goto done;
    rc = vireo_checked_u64_add(seconds_ms, (uint64_t)utc.tv_nsec / UINT64_C(1000000), &value.occurred_at_ms);
    if (rc != VIREO_OK) goto done;
    if (login) {
        diagnostic.stage = VIREO_AUTH_CONTEXT_EXPIRY;
        rc = vireo_checked_u64_add(value.occurred_at_ms, session_lifetime_ms, &value.expires_at_ms);
        if (rc != VIREO_OK) goto done;
    }
    diagnostic.stage = VIREO_AUTH_CONTEXT_MONOTONIC;
    rc = ops->monotonic(ops->context, &value.now_ns, &diagnostic.monotonic_error);
    if (rc != VIREO_OK) goto done;
    diagnostic.stage = VIREO_AUTH_CONTEXT_LATENCY;
    if (value.now_ns < received_at_ns) { rc = VIREO_RESULT_RANGE; goto done; }
    value.latency_us = (value.now_ns - received_at_ns) / UINT64_C(1000);
    *out = value;
    diagnostic.stage = VIREO_AUTH_CONTEXT_NONE;
done:
    if (error != NULL) *error = diagnostic;
    (void)vireo_secure_clear(&value, sizeof(value));
    errno = saved_errno;
    return rc;
}

vireo_result_t vireo_auth_task_context_capture(vireo_task_t const *task,
    vireo_monotonic_ns_t received_at_ns, uint64_t session_lifetime_ms,
    vireo_auth_task_options_t const *options,
    vireo_auth_task_context_t *out, vireo_auth_context_error_t *error)
{
    return vireo_auth_task_context_with(task, received_at_ns, session_lifetime_ms, options, out, error, &native_ops);
}
