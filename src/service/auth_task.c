/* PROJECT : VIREO
 * FILE : auth_task.c
 * AUTHOR : bitofux
 * DATE : 2026-10-20
 * BRIEF : 从独立task短借密码；在唯一service调用后不覆盖提交事实。
 */
#include "auth_task_internal.h"
#include <vireo/base/secure_clear.h>
#include <errno.h>
#include <string.h>

/* VAL1只来自可信Reactor构造；magic只是形态，operation决定解析模式。 */
static void put64(unsigned char *p,uint64_t v)
{ for(size_t i=0;i<8;++i) p[i]=(unsigned char)(v>>((7-i)*8)); }
static uint64_t get64(unsigned char const *p)
{ uint64_t v=0; for(size_t i=0;i<8;++i) v=(v<<8)|p[i]; return v; }

vireo_command_t vireo_auth_task_command(vireo_auth_task_options_t const *o,uint32_t operation)
{
    if(!o) return 0;
    uint32_t const ids[4]={o->register_operation,o->login_operation,o->logout_operation,o->resume_operation};
    vireo_command_t const commands[4]={VIREO_COMMAND_REGISTER,VIREO_COMMAND_LOGIN,VIREO_COMMAND_LOGOUT,VIREO_COMMAND_SESSION_RESUME};
    for(size_t i=0;i<4;++i) {
        if(!ids[i]) return 0;
        for(size_t j=0;j<i;++j) if(ids[i]==ids[j]) return 0;
    }
    for(size_t i=0;i<4;++i) if(ids[i]==operation) return commands[i];
    return 0;
}
vireo_result_t vireo_auth_task_create_logout(vireo_task_metadata_t metadata,
    uint32_t operation,uint8_t const *wire,size_t size,vireo_auth_logout_identity_t const *identity,
    size_t budget,vireo_task_cancel_t *cancel,vireo_task_t **out)
{
    int const saved=errno; unsigned char local[56]={0};
    vireo_result_t rc=VIREO_RESULT_INVALID_ARGUMENT;
    if(!wire || !identity || !out || *out || !operation || operation!=metadata.operation ||
       !identity->user_id || !identity->session_id || !budget) goto done;
    vireo_auth_request_view_t view; vireo_auth_request_issue_t issue;
    rc=vireo_auth_request_decode(wire,size,&view,&issue); if(rc!=VIREO_OK) goto done;
    rc=VIREO_RESULT_PROTOCOL;
    if(size!=32 || view.command!=VIREO_COMMAND_LOGOUT || view.sequence!=metadata.route.request_sequence) goto done;
    memcpy(local,"VAL1",4); put64(local+8,identity->user_id); put64(local+16,identity->session_id);
    memcpy(local+24,wire,32);
    rc=cancel?vireo_task_create_copy_with_cancel(metadata,local,sizeof(local),budget,cancel,out):
        vireo_task_create_copy(metadata,local,sizeof(local),budget,out);
done:
    (void)vireo_secure_clear(local,sizeof(local)); errno=saved; return rc;
}
vireo_result_t vireo_auth_task_borrow_request(vireo_task_t const *task,vireo_command_t expected,
    vireo_auth_request_view_t *view,vireo_auth_logout_identity_t *identity,vireo_auth_request_issue_t *issue)
{
    int const saved=errno; vireo_result_t rc=VIREO_RESULT_INVALID_ARGUMENT;
    if(issue) *issue=VIREO_AUTH_REQUEST_ISSUE_NONE;
    if(!task || !view || !identity || !issue || (expected!=VIREO_COMMAND_REGISTER && expected!=VIREO_COMMAND_LOGIN &&
       expected!=VIREO_COMMAND_LOGOUT && expected!=VIREO_COMMAND_SESSION_RESUME)) goto done;
    vireo_task_info_t info; vireo_task_payload_view_t bytes;
    rc=vireo_task_inspect(task,&info); if(rc!=VIREO_OK) goto done;
    rc=vireo_task_borrow_payload(task,&bytes); if(rc!=VIREO_OK) goto done;
    size_t const offset=expected==VIREO_COMMAND_LOGOUT?24:0;
    vireo_auth_logout_identity_t target={0};
    rc=VIREO_RESULT_PROTOCOL;
    if(bytes.size<32+offset) { *issue=VIREO_AUTH_REQUEST_ISSUE_HEADER; goto done; }
    if(offset) {
        if(bytes.size!=56 || memcmp(bytes.data,"VAL1",4) || bytes.data[4] || bytes.data[5] || bytes.data[6] || bytes.data[7])
            { *issue=VIREO_AUTH_REQUEST_ISSUE_ENVELOPE; goto done; }
        target=(vireo_auth_logout_identity_t){get64(bytes.data+8),get64(bytes.data+16)};
        if(!target.user_id || !target.session_id) { *issue=VIREO_AUTH_REQUEST_ISSUE_ENVELOPE; goto done; }
    }
    vireo_auth_request_view_t next;
    rc=vireo_auth_request_decode(bytes.data+offset,bytes.size-offset,&next,issue); if(rc!=VIREO_OK) goto done;
    if(next.command!=expected || next.sequence!=info.metadata.route.request_sequence) {
        rc=VIREO_RESULT_PROTOCOL; *issue=VIREO_AUTH_REQUEST_ISSUE_ENVELOPE; goto done;
    }
    *view=next; *identity=target;
done: errno=saved; return rc;
}

static vireo_auth_task_ops_t const public_ops = {
    vireo_auth_service_register, vireo_auth_service_login,
    vireo_auth_service_resume, vireo_auth_service_logout
};

vireo_result_t vireo_auth_task_execute_with(vireo_task_t const *task,
    vireo_auth_task_context_t const *context, vireo_auth_task_options_t const *options,
    vireo_mysql_user_repository_t *repository, vireo_auth_password_gate_t *gate,
    vireo_auth_login_verifier_t const *verifier, vireo_auth_task_result_t *out,
    vireo_auth_task_ops_t const *ops)
{
    int const saved_errno = errno;
    if (task == NULL || context == NULL || options == NULL || repository == NULL ||
        gate == NULL || verifier == NULL || out == NULL || ops == NULL ||
        ops->registration == NULL || ops->login == NULL || ops->resume == NULL || ops->logout == NULL)
        return VIREO_RESULT_INVALID_ARGUMENT;
    (void)vireo_auth_task_result_clear(out);
    out->stage = VIREO_AUTH_TASK_CONTEXT;
    vireo_result_t rc = VIREO_RESULT_INVALID_ARGUMENT;
    if (!vireo_auth_task_command(options, options->register_operation))
        goto done;
    if (options->pool_timeout_ms > UINT32_C(60000)) {
        rc = VIREO_RESULT_RANGE;
        goto done;
    }
    unsigned char id_bits = 0;
    for (size_t i = 0; i < sizeof(context->request_id); ++i)
        id_bits |= context->request_id[i];
    if (id_bits == 0) goto done;
    vireo_task_info_t info;
    rc = vireo_task_inspect(task, &info);
    if (rc != VIREO_OK) goto done;
    out->metadata = info.metadata;
    bool same = false;
    rc = vireo_task_metadata_same_request(info.metadata, context->metadata, &same);
    if (rc != VIREO_OK) goto done;
    if (!same || info.metadata.operation != context->metadata.operation ||
        info.metadata.deadline_ns != context->metadata.deadline_ns) {
        rc = VIREO_RESULT_INVALID_ARGUMENT;
        goto done;
    }
    out->stage = VIREO_AUTH_TASK_DECODE;
    vireo_task_payload_view_t payload;
    rc = vireo_task_borrow_payload(task, &payload);
    if (rc != VIREO_OK) goto done;
    /* 空task没有完整frame；不用NULL触发decode的参数错误。 */
    if (payload.size == 0) {
        out->request_issue = VIREO_AUTH_REQUEST_ISSUE_HEADER;
        rc = VIREO_RESULT_PROTOCOL;
        goto done;
    }
    vireo_auth_request_view_t view;
    vireo_command_t const expected=vireo_auth_task_command(options,info.metadata.operation);
    if(!expected) { rc=VIREO_RESULT_PROTOCOL; goto done; }
    rc = vireo_auth_task_borrow_request(task, expected, &view, &out->logout_target, &out->request_issue);
    if (rc != VIREO_OK) {
        if(out->request_issue==VIREO_AUTH_REQUEST_ISSUE_ENVELOPE) out->stage=VIREO_AUTH_TASK_MATCH;
        goto done;
    }
    out->command = view.command;
    out->stage = VIREO_AUTH_TASK_MATCH;
    bool const login = view.command == VIREO_COMMAND_LOGIN;
    if (login && context->expires_at_ms <= context->occurred_at_ms) {
        rc = VIREO_RESULT_RANGE;
        goto done;
    }
    out->stage = VIREO_AUTH_TASK_CANCEL;
    bool requested = false;
    rc = vireo_task_is_cancel_requested(task, &requested);
    if (rc != VIREO_OK) goto done;
    if (requested) {
        rc = VIREO_RESULT_CANCELLED;
        goto done;
    }
    out->stage = VIREO_AUTH_TASK_DEADLINE;
    if (context->now_ns >= info.metadata.deadline_ns) {
        rc = VIREO_RESULT_TIMEOUT;
        goto done;
    }
    out->stage = VIREO_AUTH_TASK_SERVICE;
    if (view.command == VIREO_COMMAND_SESSION_RESUME) {
        vireo_session_token_t token;
        memcpy(token.bytes,view.token,sizeof(token.bytes));
        rc=ops->resume(repository,&token,context->occurred_at_ms,options->pool_timeout_ms,
            &out->resume_identity,&out->resume_report,&out->error);
        (void)vireo_session_token_clear(&token);
    } else if (view.command == VIREO_COMMAND_LOGOUT) {
        vireo_mysql_logout_input_t request={.user_id=out->logout_target.user_id,.session_id=out->logout_target.session_id,
            .occurred_at_ms=context->occurred_at_ms,.latency_us=context->latency_us};
        memcpy(request.request_id,context->request_id,16);
        rc=ops->logout(repository,&request,options->pool_timeout_ms,&out->logout_report,&out->error);
        (void)vireo_secure_clear(&request,sizeof(request));
    } else if (login) {
        vireo_auth_login_request_t request = {
            .username = (char const *)view.username, .username_length = view.username_size,
            .password = view.password, .password_length = view.password_size,
            .issued_at_ms = context->occurred_at_ms, .expires_at_ms = context->expires_at_ms,
            .latency_us = context->latency_us
        };
        memcpy(request.request_id, context->request_id, sizeof(request.request_id));
        rc = ops->login(repository, gate, verifier, &request, options->pool_timeout_ms,
            &out->login, &out->error);
        (void)vireo_secure_clear(&request, sizeof(request));
    } else {
        vireo_auth_registration_request_t request = {
            .username = (char const *)view.username, .username_length = view.username_size,
            .password = view.password, .password_length = view.password_size,
            .occurred_at_ms = context->occurred_at_ms, .latency_us = context->latency_us
        };
        memcpy(request.request_id, context->request_id, sizeof(request.request_id));
        rc = ops->registration(repository, gate, &request, options->pool_timeout_ms,
            &out->registration, &out->error);
        (void)vireo_secure_clear(&request, sizeof(request));
    }
done:
    out->result = rc;
    errno = saved_errno;
    return rc;
}

vireo_result_t vireo_auth_task_execute(vireo_task_t const *task,
    vireo_auth_task_context_t const *context, vireo_auth_task_options_t const *options,
    vireo_mysql_user_repository_t *repository, vireo_auth_password_gate_t *gate,
    vireo_auth_login_verifier_t const *verifier, vireo_auth_task_result_t *out)
{
    return vireo_auth_task_execute_with(task, context, options, repository, gate, verifier, out, &public_ops);
}

vireo_result_t vireo_auth_task_result_clear(vireo_auth_task_result_t *result)
{
    if (result == NULL) return VIREO_RESULT_INVALID_ARGUMENT;
    return vireo_secure_clear(result, sizeof(*result));
}
