/* PROJECT : VIREO
 * FILE : auth_completion.c
 * AUTHOR : bitofux
 * DATE : 2026-10-20
 * BRIEF : 固定内部VAC1/VAC2投影，不复制结构padding、repo诊断或网络状态。
 */
#include "auth_completion_internal.h"
#include <vireo/base/secure_clear.h>
#include <errno.h>
#include <string.h>

/* 只操作本文件已经验证边界的固定88/120字节局部区，无移位到类型宽度的情况。 */
static void put64(unsigned char *p, uint64_t value)
{ for (size_t i = 0; i < 8; ++i) p[i] = (unsigned char)(value >> ((7 - i) * 8)); }
static uint64_t get64(unsigned char const *p)
{ uint64_t value = 0; for (size_t i = 0; i < 8; ++i) value = (value << 8) | p[i]; return value; }

/* token全零是合法已提交凭据，只有非提交/REGISTER时才检查字段必须零。 */
static bool token_zero(vireo_session_token_t const *token)
{ unsigned char bits = 0; for (size_t i = 0; i < sizeof(token->bytes); ++i) bits |= token->bytes[i]; return bits == 0; }

/**
 * @brief 核专用投影的命令、三态与身份/时间/状态配对
 * @param[in] o 必需存活局部值，只读短借。
 * @return true表示逻辑形态成立，不证明来源/授权/客户当前性。
 * @note 无资源/errno/同步副作用，调用者已验证metadata基本形态。
 */
static bool shape(vireo_auth_completion_outcome_t const *o)
{
    bool const resume=o->command==VIREO_COMMAND_SESSION_RESUME, logout=o->command==VIREO_COMMAND_LOGOUT;
    if (o->command != VIREO_COMMAND_REGISTER && o->command != VIREO_COMMAND_LOGIN && !resume && !logout) return false;
    if (o->commit != VIREO_AUTH_NOT_COMMITTED && o->commit != VIREO_AUTH_COMMITTED &&
        o->commit != VIREO_AUTH_COMMIT_UNKNOWN) return false;
    if(resume || logout) {
        if(o->root_node_id || !token_zero(&o->token)) return false;
        if(resume) {
            if(o->commit!=VIREO_AUTH_NOT_COMMITTED || o->audit_id || o->logout_target.user_id ||
               o->logout_target.session_id || o->revoked_at_ms || o->already_revoked) return false;
            if(o->resume_validated) return o->metadata.result==VIREO_OK && o->metadata.suggested_status==VIREO_STATUS_OK &&
                o->user_id && o->session_id && o->expires_at_ms>o->issued_at_ms;
            return o->metadata.result!=VIREO_OK && o->metadata.suggested_status!=VIREO_STATUS_OK &&
                !o->user_id && !o->session_id && !o->issued_at_ms && !o->expires_at_ms;
        }
        if(o->resume_validated || o->user_id || o->session_id || o->issued_at_ms || o->expires_at_ms ||
           !o->logout_target.user_id || !o->logout_target.session_id) return false;
        if(o->commit==VIREO_AUTH_COMMITTED) return o->metadata.suggested_status==VIREO_STATUS_OK &&
            (o->already_revoked ? o->audit_id==0 : o->audit_id!=0);
        return o->metadata.result!=VIREO_OK && o->metadata.suggested_status!=VIREO_STATUS_OK &&
            !o->audit_id && !o->revoked_at_ms && !o->already_revoked &&
            (o->commit!=VIREO_AUTH_COMMIT_UNKNOWN || o->metadata.suggested_status==VIREO_STATUS_INTERNAL_ERROR);
    }
    if(o->resume_validated || o->logout_target.user_id || o->logout_target.session_id || o->revoked_at_ms || o->already_revoked) return false;
    if (o->commit == VIREO_AUTH_COMMITTED) {
        if (o->metadata.suggested_status != VIREO_STATUS_OK || o->user_id == 0 || o->audit_id == 0) return false;
        if (o->command == VIREO_COMMAND_REGISTER)
            return o->root_node_id != 0 && o->session_id == 0 && o->issued_at_ms == 0 && o->expires_at_ms == 0 && token_zero(&o->token);
        return o->root_node_id == 0 && o->session_id != 0 && o->expires_at_ms > o->issued_at_ms;
    }
    if (o->metadata.result == VIREO_OK || o->metadata.suggested_status == VIREO_STATUS_OK ||
        o->user_id != 0 || o->root_node_id != 0 || o->session_id != 0 || o->audit_id != 0 ||
        o->issued_at_ms != 0 || o->expires_at_ms != 0 || !token_zero(&o->token)) return false;
    return o->commit != VIREO_AUTH_COMMIT_UNKNOWN || o->metadata.suggested_status == VIREO_STATUS_INTERNAL_ERROR;
}

/**
 * @brief 将原执行事实投影成必要业务值，保留原工作rc
 * @param[in] r 必需原结果，短借不改；caller保证未篡改service事实。
 * @param[out] o 必需独立已清零局部值，失败可改变。
 * @return INVALID_ARGUMENT表示源事实畸形，否则OK。
 * @note 不保存指针/资源，不管理repo；调用者统一擦局部o。
 */
static vireo_result_t project(vireo_auth_task_result_t const *r, vireo_auth_completion_outcome_t *o)
{
    if (r->stage < VIREO_AUTH_TASK_CONTEXT || r->stage > VIREO_AUTH_TASK_SERVICE) return VIREO_RESULT_INVALID_ARGUMENT;
    o->command = r->command;
    bool const login = r->command == VIREO_COMMAND_LOGIN;
    bool const resume=r->command==VIREO_COMMAND_SESSION_RESUME, logout=r->command==VIREO_COMMAND_LOGOUT;
    if (r->command != VIREO_COMMAND_REGISTER && !login && !resume && !logout) return VIREO_RESULT_INVALID_ARGUMENT;
    bool committed = false, unknown = false;
    if (login) {
        if (r->login.transaction.commit == VIREO_MYSQL_LOGIN_COMMITTED) committed = true;
        else if (r->login.transaction.commit == VIREO_MYSQL_LOGIN_UNKNOWN) unknown = true;
        else if (r->login.transaction.commit != VIREO_MYSQL_LOGIN_NOT_COMMITTED) return VIREO_RESULT_INVALID_ARGUMENT;
        o->user_id = r->login.user_id; o->session_id = r->login.transaction.session_id;
        o->audit_id = r->login.transaction.audit_id; o->issued_at_ms = r->login.issued_at_ms;
        o->expires_at_ms = r->login.expires_at_ms; o->token = r->login.token;
    } else if(resume) {
        o->resume_validated=r->resume_report.valid;
        o->user_id=r->resume_identity.user_id; o->session_id=r->resume_identity.session_id;
        o->issued_at_ms=r->resume_identity.issued_at_ms; o->expires_at_ms=r->resume_identity.expires_at_ms;
        if(o->resume_validated && (r->stage!=VIREO_AUTH_TASK_SERVICE || r->resume_report.cleanup_pending)) return VIREO_RESULT_INVALID_ARGUMENT;
    } else if(logout) {
        o->logout_target=r->logout_target;
        if(r->logout_report.commit==VIREO_MYSQL_LOGOUT_COMMITTED) committed=true;
        else if(r->logout_report.commit==VIREO_MYSQL_LOGOUT_UNKNOWN) unknown=true;
        else if(r->logout_report.commit!=VIREO_MYSQL_LOGOUT_NOT_COMMITTED) return VIREO_RESULT_INVALID_ARGUMENT;
        if(committed && r->logout_report.session_id!=o->logout_target.session_id) return VIREO_RESULT_INVALID_ARGUMENT;
        if(!committed && r->logout_report.session_id) return VIREO_RESULT_INVALID_ARGUMENT;
        o->audit_id=r->logout_report.audit_id; o->revoked_at_ms=r->logout_report.revoked_at_ms;
        o->already_revoked=r->logout_report.already_revoked;
    } else {
        if (r->registration.commit == VIREO_MYSQL_REGISTRATION_COMMITTED) committed = true;
        else if (r->registration.commit == VIREO_MYSQL_REGISTRATION_UNKNOWN) unknown = true;
        else if (r->registration.commit != VIREO_MYSQL_REGISTRATION_NOT_COMMITTED) return VIREO_RESULT_INVALID_ARGUMENT;
        o->user_id = r->registration.user_id; o->root_node_id = r->registration.root_node_id;
        o->audit_id = r->registration.audit_id;
    }
    if (r->stage != VIREO_AUTH_TASK_SERVICE && (committed || unknown)) return VIREO_RESULT_INVALID_ARGUMENT;
    o->commit = committed ? VIREO_AUTH_COMMITTED : unknown ? VIREO_AUTH_COMMIT_UNKNOWN : VIREO_AUTH_NOT_COMMITTED;
    vireo_status_t status = VIREO_STATUS_INTERNAL_ERROR;
    if (committed || o->resume_validated) status = VIREO_STATUS_OK;
    else if (!unknown) {
        if (r->stage == VIREO_AUTH_TASK_SERVICE && (login || resume || logout) && r->result == VIREO_RESULT_NOT_FOUND)
            status = VIREO_STATUS_AUTHENTICATION_FAILED;
        else if (r->stage == VIREO_AUTH_TASK_SERVICE && r->command==VIREO_COMMAND_REGISTER && r->registration.conflict == VIREO_MYSQL_REGISTRATION_USERNAME_CONFLICT)
            status = VIREO_STATUS_USER_EXISTS;
        else if (r->stage == VIREO_AUTH_TASK_DECODE && r->result == VIREO_RESULT_PROTOCOL) status = VIREO_STATUS_BAD_REQUEST;
        else if (r->result == VIREO_RESULT_TIMEOUT) status = VIREO_STATUS_TIMEOUT;
        else if (r->result == VIREO_RESULT_BUSY) status = VIREO_STATUS_BUSY;
        else if (r->result == VIREO_RESULT_CANCELLED) status = VIREO_STATUS_UNAVAILABLE;
    }
    vireo_result_t rc = vireo_completion_metadata_make(r->metadata, r->result, status, &o->metadata);
    if (rc != VIREO_OK || !shape(o)) return VIREO_RESULT_INVALID_ARGUMENT;
    return VIREO_OK;
}

vireo_result_t vireo_auth_completion_publish_with(vireo_task_t const *task,
    vireo_auth_task_result_t const *result, size_t allocation_budget,
    vireo_completion_queue_t *queue, vireo_notifier_t *notifier,
    vireo_completion_t **remaining, vireo_auth_completion_publish_report_t *report,
    vireo_auth_publish_fn publish)
{
    int const saved_errno = errno;
    vireo_auth_completion_publish_report_t progress = {0};
    vireo_auth_completion_outcome_t outcome = {0};
    unsigned char bytes[VIREO_AUTH_COMPLETION_SESSION_BYTES] = {0};
    vireo_result_t rc = VIREO_RESULT_INVALID_ARGUMENT;
    if (task == NULL || result == NULL || queue == NULL || notifier == NULL || remaining == NULL ||
        report == NULL || publish == NULL || allocation_budget == 0 || *remaining != NULL) goto done;
    rc = project(result, &outcome);
    if (rc != VIREO_OK) goto done;
    progress.result_validated = true;
    vireo_task_info_t info;
    rc = vireo_task_inspect(task, &info);
    if (rc != VIREO_OK) goto done;
    bool same = false;
    rc = vireo_task_metadata_same_request(info.metadata, result->metadata, &same);
    if (rc != VIREO_OK) goto done;
    if (!same || info.metadata.operation != result->metadata.operation || info.metadata.deadline_ns != result->metadata.deadline_ns) {
        rc = VIREO_RESULT_INVALID_ARGUMENT; goto done;
    }
    vireo_auth_request_view_t view; vireo_auth_request_issue_t issue;
    vireo_auth_logout_identity_t target;
    rc=vireo_auth_task_borrow_request(task,result->command,&view,&target,&issue);
    if(rc!=VIREO_OK) goto done;
    if(target.user_id!=outcome.logout_target.user_id || target.session_id!=outcome.logout_target.session_id) {
        rc=VIREO_RESULT_INVALID_ARGUMENT; goto done;
    }
    progress.task_matched = true;
    bool const session=result->command==VIREO_COMMAND_SESSION_RESUME || result->command==VIREO_COMMAND_LOGOUT;
    size_t const payload_size=session?VIREO_AUTH_COMPLETION_SESSION_BYTES:VIREO_AUTH_COMPLETION_PAYLOAD_BYTES;
    memcpy(bytes, session?"VAC2":"VAC1", 4);
    bytes[6]=(unsigned char)outcome.resume_validated;
    bytes[4] = (unsigned char)(outcome.command >> 8); bytes[5] = (unsigned char)outcome.command;
    bytes[7] = (unsigned char)outcome.commit;
    put64(bytes + 8, outcome.user_id); put64(bytes + 16, outcome.root_node_id);
    put64(bytes + 24, outcome.session_id); put64(bytes + 32, outcome.audit_id);
    put64(bytes + 40, outcome.issued_at_ms); put64(bytes + 48, outcome.expires_at_ms);
    memcpy(bytes + 56, outcome.token.bytes, sizeof(outcome.token.bytes));
    if(session) { put64(bytes+88,outcome.logout_target.user_id); put64(bytes+96,outcome.logout_target.session_id);
        put64(bytes+104,outcome.revoked_at_ms); bytes[112]=(unsigned char)outcome.already_revoked; }
    progress.publish_called = true;
    rc = publish(task, result->result, outcome.metadata.suggested_status, bytes, payload_size,
        allocation_budget, queue, notifier, remaining, &progress.publication);
done:
    (void)vireo_secure_clear(bytes, sizeof(bytes));
    (void)vireo_auth_completion_outcome_clear(&outcome);
    if (report != NULL) *report = progress;
    errno = saved_errno;
    return rc;
}

vireo_result_t vireo_auth_completion_publish(vireo_task_t const *task,
    vireo_auth_task_result_t const *result, size_t allocation_budget,
    vireo_completion_queue_t *queue, vireo_notifier_t *notifier,
    vireo_completion_t **remaining, vireo_auth_completion_publish_report_t *report)
{
    return vireo_auth_completion_publish_with(task, result, allocation_budget, queue, notifier,
        remaining, report, vireo_completion_copy_wait_publish);
}

vireo_result_t vireo_auth_completion_decode(vireo_completion_t const *completion,
    vireo_auth_completion_outcome_t *out)
{
    int const saved_errno = errno;
    vireo_auth_completion_outcome_t value = {0};
    vireo_result_t rc = VIREO_RESULT_INVALID_ARGUMENT;
    if (completion == NULL || out == NULL) goto done;
    vireo_completion_info_t info;
    rc = vireo_completion_inspect(completion, &info);
    if (rc != VIREO_OK) goto done;
    rc = vireo_completion_metadata_make(info.metadata.request, info.metadata.result,
        info.metadata.suggested_status, &value.metadata);
    if (rc != VIREO_OK) { rc = VIREO_RESULT_PROTOCOL; goto done; }
    vireo_completion_payload_view_t payload;
    rc = vireo_completion_borrow_payload(completion, &payload);
    if (rc != VIREO_OK) goto done;
    rc = VIREO_RESULT_PROTOCOL;
    bool const v2=payload.size==VIREO_AUTH_COMPLETION_SESSION_BYTES;
    if((!v2 && payload.size!=VIREO_AUTH_COMPLETION_PAYLOAD_BYTES) ||
       memcmp(payload.data,v2?"VAC2":"VAC1",4) || payload.data[7]>2 || payload.data[6]>(v2?1:0)) goto done;
    unsigned char const *p=payload.data;
    value.command=(uint16_t)((uint16_t)p[4]<<8|p[5]);
    if(v2 != (value.command==VIREO_COMMAND_SESSION_RESUME || value.command==VIREO_COMMAND_LOGOUT)) goto done;
    value.resume_validated=p[6]!=0;
    if(v2) {
        if(p[112]>1) goto done;
        for(size_t i=113;i<120;++i) if(p[i]) goto done;
        value.logout_target=(vireo_auth_logout_identity_t){get64(p+88),get64(p+96)};
        value.revoked_at_ms=get64(p+104); value.already_revoked=p[112]!=0;
    }
    value.commit = p[7] == 0 ? VIREO_AUTH_NOT_COMMITTED : p[7] == 1 ? VIREO_AUTH_COMMITTED : VIREO_AUTH_COMMIT_UNKNOWN;
    value.user_id = get64(p + 8); value.root_node_id = get64(p + 16);
    value.session_id = get64(p + 24); value.audit_id = get64(p + 32);
    value.issued_at_ms = get64(p + 40); value.expires_at_ms = get64(p + 48);
    memcpy(value.token.bytes, p + 56, sizeof(value.token.bytes));
    if (!shape(&value)) goto done;
    *out = value;
    rc = VIREO_OK;
done:
    (void)vireo_auth_completion_outcome_clear(&value);
    errno = saved_errno;
    return rc;
}

vireo_result_t vireo_auth_completion_outcome_clear(vireo_auth_completion_outcome_t *outcome)
{
    if (outcome == NULL) return VIREO_RESULT_INVALID_ARGUMENT;
    return vireo_secure_clear(outcome, sizeof(*outcome));
}


vireo_result_t vireo_auth_failure_event_from_task(vireo_auth_task_result_t const *r,
    vireo_auth_task_context_t const *context, vireo_auth_failure_event_t *event)
{
    int const saved=errno;
    vireo_result_t rc=VIREO_RESULT_INVALID_ARGUMENT;
    vireo_auth_completion_outcome_t o={0};
    if(!r || !context || !event) goto done;
    bool same=false; unsigned bits=0;
    for(size_t i=0;i<16;++i) bits|=context->request_id[i];
    if(!bits || vireo_task_metadata_same_request(r->metadata,context->metadata,&same)!=VIREO_OK || !same ||
       r->metadata.operation!=context->metadata.operation || r->metadata.deadline_ns!=context->metadata.deadline_ns) goto done;
    rc=project(r,&o); if(rc!=VIREO_OK) goto done;
    rc=VIREO_RESULT_NOT_FOUND;
    if(o.commit!=VIREO_AUTH_NOT_COMMITTED || o.resume_validated || o.metadata.suggested_status==VIREO_STATUS_OK) goto done;
    vireo_auth_failure_event_t next={.occurred_at_ms=context->occurred_at_ms,.latency_us=context->latency_us,
        .status=o.metadata.suggested_status,.origin=VIREO_AUTH_FAILURE_WORKER};
    next.action=o.command==VIREO_COMMAND_REGISTER?1:o.command==VIREO_COMMAND_LOGIN?2:o.command==VIREO_COMMAND_LOGOUT?3:4;
    memcpy(next.request_id,context->request_id,16); *event=next; rc=VIREO_OK;
done:
    (void)vireo_secure_clear(&o,sizeof(o)); errno=saved; return rc;
}
