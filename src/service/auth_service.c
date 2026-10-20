/* PROJECT : VIREO
 * FILE : auth_service.c
 * AUTHOR : bitofux
 * DATE : 2026-10-19
 * BRIEF : 复用worker资源完成注册/登录，按提交事实交付并统一擦除局部秘密。
 * IMPLEMENTATION : 无长期状态或分配；即使caller不取诊断也检查清理错误。
 */
#include "auth_service_internal.h"
#include <vireo/base/secure_clear.h>
#include <errno.h>
#include <string.h>

static vireo_result_t native_hash(void *c, vireo_auth_password_gate_t *g, const void *p,
    size_t n, char *h, size_t cap, size_t *len)
{ (void)c; return vireo_auth_password_hash_create(g, p, n, h, cap, len); }
static vireo_result_t native_registration(void *c, vireo_mysql_user_repository_t *r,
    const vireo_mysql_registration_input_t *in, uint32_t ms, vireo_mysql_registration_report_t *out,
    vireo_mysql_user_repository_error_t *e)
{ (void)c; return vireo_mysql_user_repository_register(r, in, ms, out, e); }
static vireo_result_t native_lookup(void *c, vireo_mysql_user_repository_t *r, const void *key,
    size_t len, uint32_t ms, vireo_mysql_user_credentials_t *out, vireo_mysql_credentials_report_t *report,
    vireo_mysql_user_repository_error_t *e)
{ (void)c; return vireo_mysql_user_repository_find_credentials(r, key, len, ms, out, report, e); }
static vireo_result_t native_verify(void *c, const vireo_auth_login_verifier_t *v,
    vireo_auth_password_gate_t *g, const vireo_mysql_user_credentials_t *in, const void *p,
    size_t n, bool *out)
{ (void)c; return vireo_auth_login_verifier_verify(v, g, in, p, n, out); }
static vireo_result_t native_token(void *c, vireo_session_token_t *t, vireo_session_token_digest_t *d)
{ (void)c; return vireo_session_token_generate(t, d); }
static vireo_result_t native_login(void *c, vireo_mysql_user_repository_t *r,
    const vireo_mysql_login_input_t *in, uint32_t ms, vireo_mysql_login_report_t *out,
    vireo_mysql_user_repository_error_t *e)
{ (void)c; return vireo_mysql_user_repository_login(r, in, ms, out, e); }
static const vireo_auth_service_runtime_t native_runtime = {
    NULL, native_hash, native_registration, native_lookup, native_verify, native_token, native_login, NULL
};

static bool complete(const vireo_auth_service_runtime_t *r)
{
    return r != NULL && r->hash != NULL && r->registration != NULL && r->lookup != NULL &&
        r->verify != NULL && r->token != NULL && r->login != NULL;
}

/* 固定16字节事件ID检查不把它解释为C字符串或幂等回执。 */
static bool event_nonzero(const unsigned char id[16])
{
    unsigned char bits = 0;
    for (size_t i = 0; i < 16; ++i) { bits |= id[i]; }
    return bits != 0;
}

/**
 * @brief 先擦完整仍live工作区，再允许本组件测试观察；最后恢复caller errno。
 * @param[in,out] w 本次独占完整栈值，不与runtime/errno重叠。
 * @param[in] runtime 可NULL/不完整，仅完整依赖才调用可选观察者。
 * @param[in] saved 入口errno。
 * @param[in] result 原返回结果，擦除不改变持久事实。
 * @return 原result。
 * @note 观察者必须正常返回且不保留w；无free后/返回后读取。
 */
static vireo_result_t finish(vireo_auth_service_workspace_t *w,
    const vireo_auth_service_runtime_t *runtime, int saved, vireo_result_t result)
{
    (void)vireo_secure_clear(w, sizeof(*w));
    if (complete(runtime) && runtime->cleared != NULL) { runtime->cleared(runtime->context, w); }
    errno = saved;
    return result;
}

vireo_result_t vireo_auth_service_register_with_runtime(vireo_mysql_user_repository_t *repository,
    vireo_auth_password_gate_t *gate, const vireo_auth_registration_request_t *request,
    uint32_t timeout_ms, vireo_mysql_registration_report_t *report,
    vireo_mysql_user_repository_error_t *error, const vireo_auth_service_runtime_t *runtime)
{
    int const saved = errno;
    vireo_auth_service_workspace_t w = {0};
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    if (repository == NULL || gate == NULL || request == NULL || report == NULL ||
        request->username == NULL || request->password == NULL || !complete(runtime)) { goto done; }
    memset(report, 0, sizeof(*report));
    if (error != NULL) { memset(error, 0, sizeof(*error)); }
    if (timeout_ms > VIREO_MYSQL_POOL_WAIT_MS_MAX) { result = VIREO_RESULT_RANGE; goto done; }
    if (!event_nonzero(request->request_id)) { goto done; }
    result = vireo_auth_username_prepare(request->username, request->username_length, &w.username);
    if (result != VIREO_OK) { goto done; }
    result = vireo_auth_password_validate(request->password, request->password_length);
    if (result != VIREO_OK) { goto done; }
    result = runtime->hash(runtime->context, gate, request->password, request->password_length,
        w.phc, sizeof(w.phc), &w.phc_length);
    if (result != VIREO_OK) { goto done; }
    w.registration.username = w.username.username;
    w.registration.username_length = w.username.length;
    w.registration.username_key = w.username.key;
    w.registration.username_key_length = w.username.length;
    w.registration.password_hash = w.phc;
    w.registration.password_hash_length = w.phc_length;
    memcpy(w.registration.request_id, request->request_id, sizeof(w.registration.request_id));
    w.registration.occurred_at_ms = request->occurred_at_ms;
    w.registration.latency_us = request->latency_us;
    result = runtime->registration(runtime->context, repository, &w.registration, timeout_ms, report, error);
done:
    return finish(&w, runtime, saved, result);
}

vireo_result_t vireo_auth_service_register(vireo_mysql_user_repository_t *repository,
    vireo_auth_password_gate_t *gate, const vireo_auth_registration_request_t *request,
    uint32_t timeout_ms, vireo_mysql_registration_report_t *report,
    vireo_mysql_user_repository_error_t *error)
{ return vireo_auth_service_register_with_runtime(repository, gate, request, timeout_ms, report, error, &native_runtime); }

vireo_result_t vireo_auth_service_login_with_runtime(vireo_mysql_user_repository_t *repository,
    vireo_auth_password_gate_t *gate, const vireo_auth_login_verifier_t *verifier,
    const vireo_auth_login_request_t *request, uint32_t timeout_ms, vireo_auth_login_result_t *out,
    vireo_mysql_user_repository_error_t *error, const vireo_auth_service_runtime_t *runtime)
{
    int const saved = errno;
    vireo_auth_service_workspace_t w = {0};
    vireo_mysql_user_repository_error_t local = {0};
    vireo_mysql_user_repository_error_t *e = error != NULL ? error : &local;
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    if (repository == NULL || gate == NULL || verifier == NULL || request == NULL || out == NULL ||
        request->username == NULL || request->password == NULL || !complete(runtime)) { goto done; }
    (void)vireo_secure_clear(out, sizeof(*out));
    memset(e, 0, sizeof(*e));
    if (timeout_ms > VIREO_MYSQL_POOL_WAIT_MS_MAX || request->expires_at_ms <= request->issued_at_ms) {
        result = VIREO_RESULT_RANGE; goto done;
    }
    if (!event_nonzero(request->request_id)) { goto done; }
    result = vireo_auth_username_prepare(request->username, request->username_length, &w.username);
    if (result != VIREO_OK) { goto done; }
    result = vireo_auth_password_validate(request->password, request->password_length);
    if (result != VIREO_OK) { goto done; }
    result = runtime->lookup(runtime->context, repository, w.username.key, w.username.length,
        timeout_ms, &w.credentials, &out->lookup, e);
    /* repository可保留NOT_FOUND主因并另记清理错误；不让此类故障进入dummy分支。 */
    if (result == VIREO_RESULT_NOT_FOUND && e->cleanup_result != VIREO_OK) {
        result = e->cleanup_result; goto done;
    }
    if (result != VIREO_OK && result != VIREO_RESULT_NOT_FOUND) { goto done; }
    if (out->lookup.cleanup_pending || out->lookup.found != (result == VIREO_OK)) {
        result = VIREO_RESULT_INTERNAL; goto done;
    }
    result = runtime->verify(runtime->context, verifier, gate,
        out->lookup.found ? &w.credentials : NULL, request->password, request->password_length,
        &w.authenticated);
    if (result != VIREO_OK) { goto done; }
    if (!w.authenticated) { result = VIREO_RESULT_NOT_FOUND; goto done; }
    if (!out->lookup.found || w.credentials.user_id == 0 ||
        w.credentials.status != VIREO_MYSQL_USER_STATUS_ACTIVE) { result = VIREO_RESULT_INTERNAL; goto done; }
    result = runtime->token(runtime->context, &w.token, &w.digest);
    if (result != VIREO_OK) { goto done; }
    w.login.user_id = w.credentials.user_id;
    w.login.verified_password_hash = w.credentials.password_hash;
    w.login.verified_password_hash_length = w.credentials.password_hash_length;
    w.login.token_digest = w.digest;
    w.login.issued_at_ms = request->issued_at_ms;
    w.login.expires_at_ms = request->expires_at_ms;
    memcpy(w.login.request_id, request->request_id, sizeof(w.login.request_id));
    w.login.latency_us = request->latency_us;
    result = runtime->login(runtime->context, repository, &w.login, timeout_ms, &out->transaction, e);
    if (out->transaction.commit == VIREO_MYSQL_LOGIN_COMMITTED) {
        out->user_id = w.credentials.user_id;
        out->issued_at_ms = request->issued_at_ms;
        out->expires_at_ms = request->expires_at_ms;
        out->token = w.token;
    }
    if (result == VIREO_RESULT_NOT_FOUND && e->cleanup_result != VIREO_OK) { result = e->cleanup_result; }
done:
    return finish(&w, runtime, saved, result);
}

vireo_result_t vireo_auth_service_login(vireo_mysql_user_repository_t *repository,
    vireo_auth_password_gate_t *gate, const vireo_auth_login_verifier_t *verifier,
    const vireo_auth_login_request_t *request, uint32_t timeout_ms, vireo_auth_login_result_t *result,
    vireo_mysql_user_repository_error_t *error)
{ return vireo_auth_service_login_with_runtime(repository, gate, verifier, request, timeout_ms, result, error, &native_runtime); }

vireo_result_t vireo_auth_login_result_clear(vireo_auth_login_result_t *result)
{ return result == NULL ? VIREO_RESULT_INVALID_ARGUMENT : vireo_secure_clear(result, sizeof(*result)); }


vireo_result_t vireo_auth_service_resume(vireo_mysql_user_repository_t *repository,
    vireo_session_token_t const *token, uint64_t now, uint32_t timeout,
    vireo_mysql_session_identity_t *identity, vireo_mysql_session_report_t *report,
    vireo_mysql_user_repository_error_t *error)
{
    int const saved=errno;
    if (!repository || !token || !identity || !report) return VIREO_RESULT_INVALID_ARGUMENT;
    *identity=(vireo_mysql_session_identity_t){0}; *report=(vireo_mysql_session_report_t){0};
    if (error) *error=(vireo_mysql_user_repository_error_t){0};
    vireo_session_token_digest_t digest={0};
    vireo_result_t rc=timeout>60000?VIREO_RESULT_RANGE:vireo_session_token_digest(token,&digest);
    if (rc==VIREO_OK) rc=vireo_mysql_user_repository_find_session(repository,&digest,now,timeout,identity,report,error);
    (void)vireo_secure_clear(&digest,sizeof(digest)); errno=saved; return rc;
}
vireo_result_t vireo_auth_service_logout(vireo_mysql_user_repository_t *repository,
    vireo_mysql_logout_input_t const *input, uint32_t timeout,
    vireo_mysql_logout_report_t *report, vireo_mysql_user_repository_error_t *error)
{ return vireo_mysql_user_repository_logout(repository,input,timeout,report,error); }
