/*
 * PROJECT : VIREO
 * FILE    : notifier_server.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-14
 * BRIEF   : 一次公开inspect及server登记/注销；不保存外部对象或私有loop
 */
#include "notifier_server_internal.h"
#include <errno.h>

static vireo_result_t inspect_public(void *ctx, vireo_notifier_t const *n, vireo_notifier_info_t *i)
{
    (void)ctx; return vireo_notifier_inspect(n, i);
}
static vireo_result_t bind_public(void *ctx, vireo_tcp_server_t *s, int fd,
    vireo_event_loop_handle_t *h, vireo_tcp_server_auxiliary_error_t *e)
{
    (void)ctx; return vireo_tcp_server_auxiliary_read_register(s, fd, h, e);
}
static vireo_result_t unbind_public(void *ctx, vireo_tcp_server_t *s,
    vireo_event_loop_handle_t *h, vireo_tcp_server_auxiliary_error_t *e)
{
    (void)ctx; return vireo_tcp_server_auxiliary_read_unregister(s, h, e);
}
static vireo_notifier_server_ops_t const system_ops = {inspect_public, bind_public, unbind_public};

/** 独立阶段/原原因每路径覆盖，恢复errno；不拥有资源或重试。 */
static vireo_result_t finish(vireo_result_t result, vireo_notifier_server_stage_t stage,
    vireo_tcp_server_auxiliary_error_t value, vireo_notifier_server_error_t *error, int saved)
{
    if (error != NULL) *error = (vireo_notifier_server_error_t){
        result == VIREO_OK ? VIREO_NOTIFIER_SERVER_NONE : stage, value};
    errno = saved; return result;
}
static bool valid_ops(vireo_notifier_server_ops_t const *ops)
{
    return ops != NULL && ops->inspect != NULL && ops->bind != NULL && ops->unbind != NULL;
}

vireo_result_t vireo_notifier_server_register_with_ops(vireo_tcp_server_t *s,
    vireo_notifier_t const *n, vireo_event_loop_handle_t *h, vireo_notifier_server_error_t *e,
    vireo_notifier_server_ops_t const *ops, void *ctx)
{
    int const saved = errno;
    vireo_tcp_server_auxiliary_error_t value = {0};
    if (s == NULL || n == NULL || h == NULL || !valid_ops(ops) || h->loop_id != 0 || h->token != 0)
        return finish(VIREO_RESULT_INVALID_ARGUMENT, VIREO_NOTIFIER_SERVER_NONE, value, e, saved);
    vireo_notifier_info_t info = {0};
    vireo_result_t result = ops->inspect(ctx, n, &info);
    if (result != VIREO_OK)
        return finish(result, VIREO_NOTIFIER_SERVER_INSPECT_NOTIFIER, value, e, saved);
    result = ops->bind(ctx, s, info.fd, h, &value);
    return finish(result, VIREO_NOTIFIER_SERVER_REGISTER, value, e, saved);
}

vireo_result_t vireo_notifier_server_unregister_with_ops(vireo_tcp_server_t *s,
    vireo_event_loop_handle_t *h, vireo_notifier_server_error_t *e,
    vireo_notifier_server_ops_t const *ops, void *ctx)
{
    int const saved = errno;
    vireo_tcp_server_auxiliary_error_t value = {0};
    if (s == NULL || h == NULL || !valid_ops(ops))
        return finish(VIREO_RESULT_INVALID_ARGUMENT, VIREO_NOTIFIER_SERVER_NONE, value, e, saved);
    vireo_result_t const result = ops->unbind(ctx, s, h, &value);
    return finish(result, VIREO_NOTIFIER_SERVER_UNREGISTER, value, e, saved);
}

vireo_result_t vireo_notifier_server_register(vireo_tcp_server_t *s, vireo_notifier_t const *n,
    vireo_event_loop_handle_t *h, vireo_notifier_server_error_t *e)
{
    return vireo_notifier_server_register_with_ops(s, n, h, e, &system_ops, NULL);
}
vireo_result_t vireo_notifier_server_unregister(vireo_tcp_server_t *s,
    vireo_event_loop_handle_t *h, vireo_notifier_server_error_t *e)
{
    return vireo_notifier_server_unregister_with_ops(s, h, e, &system_ops, NULL);
}
