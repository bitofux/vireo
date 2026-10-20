/* PROJECT : VIREO
 * FILE : test_auth_task.c
 * AUTHOR : bitofux
 * DATE : 2026-10-20
 * BRIEF : service前置隔离、输入短借、原始提交/清理事实与敏感结果清理。
 */
#include "auth_task_internal.h"
#include "auth_task_test_support.h"

static max_align_t tags[3];
static vireo_mysql_user_repository_t *const repo = (void *)&tags[0];
static vireo_auth_password_gate_t *const gate = (void *)&tags[1];
static vireo_auth_login_verifier_t const *const verifier = (void *)&tags[2];
static vireo_auth_task_options_t const options = {100, 101, 5000,102,103};
static unsigned calls;
static vireo_result_t service_rc;
static vireo_auth_login_result_t login_fact;
static vireo_mysql_registration_report_t register_fact;
static unsigned char const *owned_begin;
static unsigned char const *owned_end;

/** 只接受task自有密码和可信context数值；返回后不能保存request借用。 */
static void check_request(char const *u, size_t un, void const *p, size_t pn,
    unsigned char const id[16], uint64_t at, uint64_t latency, uint32_t ms)
{
    assert(un == 7 && !memcmp(u, "Alice_7", un) && pn == 9 && !memcmp(p, "Correct!7", pn));
    assert((unsigned char const *)p >= owned_begin && (unsigned char const *)p + pn <= owned_end);
    assert(id[0] == 1 && id[15] == 9 && (at == 0 || at == 2000 || at == 1000));
    assert(latency == 13 && ms == 5000);
    ++calls;
}
static vireo_result_t reg(vireo_mysql_user_repository_t *r, vireo_auth_password_gate_t *g,
    vireo_auth_registration_request_t const *q, uint32_t ms,
    vireo_mysql_registration_report_t *out, vireo_mysql_user_repository_error_t *e)
{
    assert(r == repo && g == gate);
    check_request(q->username, q->username_length, q->password, q->password_length,
        q->request_id, q->occurred_at_ms, q->latency_us, ms);
    *out = register_fact; e->cleanup_result = VIREO_RESULT_DATABASE; errno = ERANGE; return service_rc;
}
static vireo_result_t login(vireo_mysql_user_repository_t *r, vireo_auth_password_gate_t *g,
    vireo_auth_login_verifier_t const *v, vireo_auth_login_request_t const *q, uint32_t ms,
    vireo_auth_login_result_t *out, vireo_mysql_user_repository_error_t *e)
{
    assert(r == repo && g == gate && v == verifier && q->expires_at_ms == 5000);
    check_request(q->username, q->username_length, q->password, q->password_length,
        q->request_id, q->issued_at_ms, q->latency_us, ms);
    *out = login_fact; e->cleanup_result = VIREO_RESULT_DATABASE; errno = ERANGE; return service_rc;
}
static vireo_auth_task_ops_t const ops = {reg, login, vireo_auth_service_resume, vireo_auth_service_logout};

/** 独立frame复制后立即破坏原始缓冲，证明service只短借task自有副本。 */
static vireo_task_t *make_task(bool is_login, uint32_t sequence, uint32_t operation,
    bool corrupt, bool empty, vireo_task_cancel_t *cancel)
{
    unsigned char wire[156]; size_t n = frame(wire, is_login, sequence, false);
    if (corrupt) wire[n - 1] ^= 1;
    vireo_auth_task_context_t c = task_context(7, 9, is_login); c.metadata.operation = operation;
    vireo_task_t *task = NULL;
    if (cancel != NULL) CHECK(vireo_task_create_copy_with_cancel(c.metadata, wire, empty ? 0 : n, 4096, cancel, &task), VIREO_OK);
    else CHECK(vireo_task_create_copy(c.metadata, wire, empty ? 0 : n, 4096, &task), VIREO_OK);
    CHECK(vireo_secure_clear(wire, sizeof(wire)), VIREO_OK);
    vireo_task_payload_view_t view;
    CHECK(vireo_task_borrow_payload(task, &view), VIREO_OK);
    owned_begin = view.data; owned_end = view.size == 0 ? view.data : view.data + view.size;
    return task;
}
static void rejected(vireo_task_t *task, vireo_auth_task_context_t const *c,
    vireo_auth_task_options_t const *o, vireo_result_t rc, vireo_auth_task_stage_t stage)
{
    vireo_auth_task_result_t out; memset(&out, 0xa5, sizeof(out)); unsigned const before = calls;
    CHECK(vireo_auth_task_execute_with(task, c, o, repo, gate, verifier, &out, &ops), rc);
    assert(calls == before && out.result == rc && out.stage == stage);
    assert(out.registration.commit == VIREO_MYSQL_REGISTRATION_NOT_COMMITTED && out.login.user_id == 0);
    for (size_t i = 0; i < sizeof(out.login.token.bytes); ++i) assert(out.login.token.bytes[i] == 0);
    CHECK(vireo_auth_task_result_clear(&out), VIREO_OK);
}
static vireo_result_t resume_test(vireo_mysql_user_repository_t *r,vireo_session_token_t const *token,
    uint64_t now,uint32_t timeout,vireo_mysql_session_identity_t *identity,
    vireo_mysql_session_report_t *report,vireo_mysql_user_repository_error_t *error)
{
    assert(r==repo && now==2000 && timeout==5000 && token->bytes[0]==0xa5 && token->bytes[31]==0xa5);
    ++calls; *identity=(vireo_mysql_session_identity_t){.user_id=7,.session_id=8,.issued_at_ms=100,.expires_at_ms=5000};
    *report=(vireo_mysql_session_report_t){.valid=true}; (void)error; return VIREO_OK;
}
static vireo_result_t logout_test(vireo_mysql_user_repository_t *r,vireo_mysql_logout_input_t const *input,
    uint32_t timeout,vireo_mysql_logout_report_t *report,vireo_mysql_user_repository_error_t *error)
{
    assert(r==repo && timeout==5000 && input->user_id==7 && input->session_id==8 && input->occurred_at_ms==2000 && input->request_id[0]==1);
    ++calls; *report=(vireo_mysql_logout_report_t){.commit=VIREO_MYSQL_LOGOUT_COMMITTED,.session_id=8,.audit_id=9,.revoked_at_ms=2000};
    (void)error; return VIREO_OK;
}
static void session_tasks(void)
{
    vireo_auth_task_ops_t const injected={reg,login,resume_test,logout_test};
    vireo_auth_task_context_t c=task_context(7,9,true); c.metadata.operation=102;
    unsigned char wire[68]={0};
    vireo_protocol_header_t h={.command=VIREO_COMMAND_LOGOUT,.sequence=7,.session_handle=1};
    CHECK(vireo_protocol_header_encode(&h,wire,32),VIREO_OK);
    CHECK(vireo_protocol_frame_crc32c_calculate(wire,32,NULL,0,&h.crc32c),VIREO_OK);
    CHECK(vireo_protocol_header_encode(&h,wire,32),VIREO_OK);
    vireo_auth_logout_identity_t const target={7,8}; vireo_task_t *task=NULL;
    CHECK(vireo_auth_task_create_logout(c.metadata,102,wire,32,&target,4096,NULL,&task),VIREO_OK);
    vireo_auth_task_result_t result;
    unsigned n=calls;
    CHECK(vireo_auth_task_execute_with(task,&c,&options,repo,gate,verifier,&result,&injected),VIREO_OK);
    assert(calls==n+1 && result.logout_target.user_id==7 && result.logout_report.session_id==8 && !result.resume_report.valid);
    vireo_task_payload_view_t payload; CHECK(vireo_task_borrow_payload(task,&payload),VIREO_OK);
    assert(payload.size==56 && !memcmp(payload.data,"VAL1",4));
    unsigned char trusted[56]; memcpy(trusted,payload.data,56);
    CHECK(vireo_task_destroy(&task),VIREO_OK);
    /* 原wire、畸形可信封装、reserved/零身份/错误operation均不得执行SQL。 */
    for(unsigned mode=0;mode<6;++mode) {
        unsigned char bad[56]; memcpy(bad,trusted,56);
        if(mode==1) bad[0]^=1;
        if(mode==2) bad[4]=1;
        if(mode==3) memset(bad+8,0,8);
        if(mode==4) memset(bad+16,0,8);
        if(mode==5) c.metadata.operation=103;
        CHECK(vireo_task_create_copy(c.metadata,mode==0?wire:bad,mode==0?32:56,4096,&task),VIREO_OK);
        n=calls;
        CHECK(vireo_auth_task_execute_with(task,&c,&options,repo,gate,verifier,&result,&injected),VIREO_RESULT_PROTOCOL);
        assert(calls==n); CHECK(vireo_task_destroy(&task),VIREO_OK);
    }
    c.metadata.operation=103;
    h=(vireo_protocol_header_t){.command=VIREO_COMMAND_SESSION_RESUME,.sequence=7,.body_len=36};
    wire[33]=4; wire[35]=32; memset(wire+36,0xa5,32);
    CHECK(vireo_protocol_header_encode(&h,wire,32),VIREO_OK);
    CHECK(vireo_protocol_frame_crc32c_calculate(wire,32,wire+32,36,&h.crc32c),VIREO_OK);
    CHECK(vireo_protocol_header_encode(&h,wire,32),VIREO_OK);
    CHECK(vireo_task_create_copy(c.metadata,wire,68,4096,&task),VIREO_OK); n=calls;
    CHECK(vireo_auth_task_execute_with(task,&c,&options,repo,gate,verifier,&result,&injected),VIREO_OK);
    assert(calls==n+1 && result.resume_report.valid && result.resume_identity.session_id==8 && !result.login.user_id);
    CHECK(vireo_task_destroy(&task),VIREO_OK); CHECK(vireo_auth_task_result_clear(&result),VIREO_OK);
    CHECK(vireo_secure_clear(wire,sizeof wire),VIREO_OK); CHECK(vireo_secure_clear(trusted,sizeof trusted),VIREO_OK);
}

int main(void)
{
    session_tasks();
    calls=0;
    vireo_auth_task_context_t c = task_context(7, 9, true);
    vireo_task_t *task = make_task(true, 7, 101, false, false, NULL);
    vireo_auth_task_result_t out; memset(&out, 0xa5, sizeof(out));
    unsigned char before[sizeof(out)]; memcpy(before, &out, sizeof(out));
    /* NULL边界不能擦除尚未交付的旧输出，逐个必需地址验证。 */
    CHECK(vireo_auth_task_execute(NULL, &c, &options, repo, gate, verifier, &out), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_auth_task_execute(task, NULL, &options, repo, gate, verifier, &out), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_auth_task_execute(task, &c, NULL, repo, gate, verifier, &out), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_auth_task_execute(task, &c, &options, NULL, gate, verifier, &out), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_auth_task_execute(task, &c, &options, repo, NULL, verifier, &out), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_auth_task_execute(task, &c, &options, repo, gate, NULL, &out), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_auth_task_execute(task, &c, &options, repo, gate, verifier, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    assert(!memcmp(before, &out, sizeof(out)) && calls == 0);
    CHECK(vireo_auth_task_result_clear(NULL), VIREO_RESULT_INVALID_ARGUMENT);
    for (unsigned i = 0; i < 9; ++i) {
        vireo_auth_task_context_t bad = c;
        switch (i) {
        case 0: bad.metadata.route.client_owner_id = 2; break;
        case 1: bad.metadata.route.client_slot_index = 1; break;
        case 2: bad.metadata.route.client_generation = 2; break;
        case 3: bad.metadata.route.request_sequence = 8; break;
        case 4: ++bad.metadata.request_instance_id; break;
        case 5: ++bad.metadata.operation; break;
        case 6: ++bad.metadata.deadline_ns; break;
        case 7: memset(bad.request_id, 0, 16); break;
        default: bad.metadata.operation = 0; break;
        }
        rejected(task, &bad, &options, VIREO_RESULT_INVALID_ARGUMENT, VIREO_AUTH_TASK_CONTEXT);
    }
    vireo_auth_task_options_t bad_options = options; bad_options.login_operation = 100;
    rejected(task, &c, &bad_options, VIREO_RESULT_INVALID_ARGUMENT, VIREO_AUTH_TASK_CONTEXT);
    bad_options = options; bad_options.register_operation = 0;
    rejected(task, &c, &bad_options, VIREO_RESULT_INVALID_ARGUMENT, VIREO_AUTH_TASK_CONTEXT);
    bad_options = options; bad_options.pool_timeout_ms = 60001;
    rejected(task, &c, &bad_options, VIREO_RESULT_RANGE, VIREO_AUTH_TASK_CONTEXT);
    for (unsigned i = 0; i < 2; ++i) {
        vireo_auth_task_context_t bad = c; bad.expires_at_ms = i == 0 ? 2000 : 1999;
        rejected(task, &bad, &options, VIREO_RESULT_RANGE, VIREO_AUTH_TASK_MATCH);
    }
    c.now_ns = 100;
    rejected(task, &c, &options, VIREO_RESULT_TIMEOUT, VIREO_AUTH_TASK_DEADLINE);
    c.now_ns = UINT64_MAX;
    rejected(task, &c, &options, VIREO_RESULT_TIMEOUT, VIREO_AUTH_TASK_DEADLINE);
    c.now_ns = 99;
    /* 跨所有内部返回码保留service原始事实；绝不第二次调用或重写commit。 */
    for (int code = 0; code <= (int)VIREO_RESULT_INTERNAL; ++code) {
        memset(&login_fact, 0, sizeof(login_fact)); service_rc = (vireo_result_t)code;
        login_fact.transaction.commit = VIREO_MYSQL_LOGIN_COMMITTED;
        login_fact.transaction.session_id = 71; login_fact.transaction.audit_id = 72;
        login_fact.lookup.cleanup_pending = code % 2 == 0;
        login_fact.transaction.cleanup_pending = code % 2 != 0;
        login_fact.user_id = 73; login_fact.issued_at_ms = 2000; login_fact.expires_at_ms = 5000;
        memset(login_fact.token.bytes, 0x5a, 32); unsigned const called = calls;
        CHECK(vireo_auth_task_execute_with(task, &c, &options, repo, gate, verifier, &out, &ops), service_rc);
        assert(calls == called + 1 && out.stage == VIREO_AUTH_TASK_SERVICE && out.result == service_rc);
        assert(!memcmp(&out.login, &login_fact, sizeof(login_fact)) && out.error.cleanup_result == VIREO_RESULT_DATABASE);
        CHECK(vireo_auth_task_result_clear(&out), VIREO_OK);
        CHECK(vireo_auth_task_result_clear(&out), VIREO_OK);
        unsigned char const *bytes = (void *)&out;
        for (size_t i = 0; i < sizeof(out); ++i) assert(bytes[i] == 0);
    }
    for (unsigned i = 0; i < 2; ++i) {
        memset(&login_fact, 0, sizeof(login_fact)); login_fact.transaction.commit = i ? VIREO_MYSQL_LOGIN_UNKNOWN : VIREO_MYSQL_LOGIN_NOT_COMMITTED;
        login_fact.transaction.cleanup_pending = true; service_rc = VIREO_RESULT_DATABASE;
        CHECK(vireo_auth_task_execute_with(task, &c, &options, repo, gate, verifier, &out, &ops), service_rc);
        assert(!memcmp(&out.login, &login_fact, sizeof(login_fact)));
        CHECK(vireo_auth_task_result_clear(&out), VIREO_OK);
    }
    CHECK(vireo_task_destroy(&task), VIREO_OK);
    for (unsigned i = 0; i < 4; ++i) {
        task = make_task(true, i == 0 ? 8 : 7, i == 1 ? 100 : 101, i == 2, i == 3, NULL);
        c = task_context(7, 9, true); if (i == 1) c.metadata.operation = 100;
        rejected(task, &c, &options, VIREO_RESULT_PROTOCOL, i < 2 ? VIREO_AUTH_TASK_MATCH : VIREO_AUTH_TASK_DECODE);
        CHECK(vireo_task_destroy(&task), VIREO_OK);
    }
    vireo_task_cancel_t *cancel = NULL; CHECK(vireo_task_cancel_create(4096, &cancel), VIREO_OK);
    task = make_task(true, 7, 101, false, false, cancel);
    CHECK(vireo_task_cancel_request(cancel), VIREO_OK);
    c = task_context(7, 9, true); c.now_ns = 100;
    rejected(task, &c, &options, VIREO_RESULT_CANCELLED, VIREO_AUTH_TASK_CANCEL);
    CHECK(vireo_task_destroy(&task), VIREO_OK); CHECK(vireo_task_cancel_destroy(&cancel), VIREO_OK);
    task = make_task(false, 7, 100, false, false, NULL); c = task_context(7, 9, false);
    c.occurred_at_ms = 0; c.expires_at_ms = UINT64_MAX;
    for (unsigned i = 0; i < 3; ++i) {
        register_fact = (vireo_mysql_registration_report_t){.commit = i == 0 ? VIREO_MYSQL_REGISTRATION_COMMITTED :
            i == 1 ? VIREO_MYSQL_REGISTRATION_UNKNOWN : VIREO_MYSQL_REGISTRATION_NOT_COMMITTED, .cleanup_pending = true};
        if (i == 0) { register_fact.user_id = 1; register_fact.root_node_id = 2; register_fact.audit_id = 3; }
        CHECK(vireo_auth_task_execute_with(task, &c, &options, repo, gate, verifier, &out, &ops), service_rc);
        assert(out.command == VIREO_COMMAND_REGISTER && !memcmp(&out.registration, &register_fact, sizeof(register_fact)));
        CHECK(vireo_auth_task_result_clear(&out), VIREO_OK);
    }
    CHECK(vireo_task_destroy(&task), VIREO_OK);
    printf("PASS auth_task: 6 groups, complete association, pre-service isolation, %u single service calls, commit/cleanup preservation, secure clear\n", calls);
    return 0;
}
