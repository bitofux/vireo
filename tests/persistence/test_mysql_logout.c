#define _POSIX_C_SOURCE 200809L
#include "mysql_user_repository_internal.h"
#include "mysql_pool_internal.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(call,want) do { errno=EDOM; vireo_result_t got_=(call); if(got_!=(want)) { fprintf(stderr,"line %d got %d want %d\n",__LINE__,(int)got_,(int)(want)); abort(); } assert(errno==EDOM); } while(0)
enum operation { NONE, BEGIN, ACCOUNT, SESSION, UPDATE, AUDIT, COMMIT, ROLLBACK, OP_COUNT };
struct model_statement { enum operation op; };
static struct {
    size_t blocks, statements, acquired, released, prepared[OP_COUNT], executed[OP_COUNT];
    enum operation prepare_fail, execute_fail, close_fail, bad_shape;
    bool allocation_fail, not_started, keep_statement, acquire_partial, release_keep, release_consumed;
    bool borrow_fail, acquire_empty;
    unsigned int mysql_code;
    unsigned int shape;
    unsigned int fetches; enum operation read_fault; bool extra, fetch_fail, column_fail, second_fetch_fail;
    bool absent_user, absent_session, user_null; char user_bad[32], cells[6][32]; bool nulls[6];
    uint64_t changed_rows;
    vireo_mysql_pool_disposition_t disposition;
} m;
static const char phc[]="$argon2id$v=19$m=65536,t=3,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
static vireo_password_policy_t policy=VIREO_PASSWORD_POLICY_DEFAULT;
static vireo_mysql_thread_t *thread;
static vireo_mysql_pool_t pool;
static vireo_mysql_connection_t connection;
static vireo_mysql_user_repository_t *repo;
static vireo_mysql_logout_input_t input;
static vireo_mysql_logout_report_t report;
static vireo_mysql_user_repository_error_t error;
static size_t scenarios;
static void *allocate(size_t n)
{ if(m.allocation_fail) { return NULL; } void *p=malloc(n); assert(p); ++m.blocks; return p; }
static void release_memory(void *p)
{ assert(p && m.blocks==1); --m.blocks; free(p); }
static vireo_result_t acquire(vireo_mysql_thread_t *t,vireo_mysql_pool_t *p,uint32_t wait,
    vireo_mysql_lease_t *l,vireo_mysql_pool_acquisition_t *a,vireo_mysql_pool_error_t *e)
{
    assert(t==thread && p==&pool && wait<=60000 && !l->owner); ++m.acquired;
    *a=(vireo_mysql_pool_acquisition_t){0}; *e=(vireo_mysql_pool_error_t){0};
    if(m.acquire_empty) { return VIREO_RESULT_BUSY; }
    *l=(vireo_mysql_lease_t){p,0,1}; a->acquired=true;
    if(m.acquire_partial) { e->stage=VIREO_MYSQL_POOL_STAGE_UNLOCK; e->pthread_code=EINVAL; return VIREO_RESULT_INTERNAL; }
    return VIREO_OK;
}
static vireo_result_t borrow(vireo_mysql_thread_t *t,vireo_mysql_pool_t *p,
    const vireo_mysql_lease_t *l,vireo_mysql_connection_t **out)
{
    assert(t==thread && p==&pool && l->owner==p);
    if(m.borrow_fail) { return VIREO_RESULT_INTERNAL; }
    *out=&connection; return VIREO_OK;
}
static vireo_result_t release(vireo_mysql_thread_t *t,vireo_mysql_pool_t *p,
    vireo_mysql_lease_t *l,vireo_mysql_pool_disposition_t d,
    vireo_mysql_pool_release_t *out,vireo_mysql_pool_error_t *e)
{
    assert(t==thread && p==&pool && l->owner==p && m.statements==0); ++m.released; m.disposition=d;
    *out=(vireo_mysql_pool_release_t){0}; *e=(vireo_mysql_pool_error_t){0};
    if(m.release_keep) { e->stage=VIREO_MYSQL_POOL_STAGE_LOCK; e->pthread_code=EINVAL; return VIREO_RESULT_INTERNAL; }
    *l=(vireo_mysql_lease_t){0}; out->released=true; out->reusable=d==VIREO_MYSQL_POOL_RECYCLE;
    if(m.release_consumed) { e->stage=VIREO_MYSQL_POOL_STAGE_RESET; e->database.mysql_code=2013; return VIREO_RESULT_DATABASE; }
    return VIREO_OK;
}
static enum operation identify(const char *sql,size_t n)
{
    assert(strlen(sql)==n);
    if(!strcmp(sql,"SET autocommit=0")) { return BEGIN; }
    if(!strcmp(sql,"SELECT id FROM users WHERE id=? FOR UPDATE")) { return ACCOUNT; }
    if(!strcmp(sql,"SELECT user_id,status,issued_at_ms,expires_at_ms,revoked_at_ms,last_seen_at_ms FROM sessions WHERE id=? FOR UPDATE")) { return SESSION; }
    if(!strcmp(sql,"UPDATE sessions SET status=2,revoked_at_ms=? WHERE id=? AND user_id=? AND status=1")) { return UPDATE; }
    if(!strcmp(sql,"INSERT INTO operation_audits(request_id,user_id,session_id,action,target_type,target_id,target_hash,status,latency_us,detail,occurred_at_ms) VALUES(?,?,?,3,2,?,NULL,0,?,'',?)")) { return AUDIT; }
    if(!strcmp(sql,"COMMIT")) { return COMMIT; }
    assert(!strcmp(sql,"ROLLBACK"));return ROLLBACK;
}
static vireo_result_t prepare(vireo_mysql_thread_t *t,vireo_mysql_connection_t *c,
    const char *sql,size_t n,const vireo_mysql_statement_limits_t *limits,vireo_mysql_statement_t **out,vireo_mysql_error_t *e)
{
    assert(t==thread && c==&connection && !*out && !m.statements);
    enum operation op=identify(sql,n);++m.prepared[op];*e=(vireo_mysql_error_t){0};
    if(op==ACCOUNT || op==SESSION) { assert(limits->max_parameters==1 && limits->max_columns==(op==ACCOUNT ? 1U : 6U) && !limits->max_parameter_bytes && limits->max_cell_bytes==20); }
    else { assert(limits->max_parameters==6 && !limits->max_columns && limits->max_parameter_bytes==655 && limits->max_cell_bytes==1); }
    assert(limits->max_memory_bytes==32768);
    if(op==m.prepare_fail) { e->stage=VIREO_MYSQL_STAGE_STATEMENT_PREPARE;e->mysql_code=m.mysql_code;return VIREO_RESULT_DATABASE; }
    struct model_statement *s=malloc(sizeof(*s));assert(s);s->op=op;*out=(vireo_mysql_statement_t *)s;++m.statements;m.fetches=0;return VIREO_OK;
}
static void span(const vireo_mysql_parameter_t *p,const void *data,size_t n)
{ assert(p->kind==VIREO_MYSQL_PARAMETER_BYTES && p->value.span.length==n && !memcmp(p->value.span.data,data,n)); }
static void number(const vireo_mysql_parameter_t *p,uint64_t n)
{ assert(p->kind==VIREO_MYSQL_PARAMETER_U64 && p->value.u64==n); }
static vireo_result_t execute(vireo_mysql_thread_t *t,vireo_mysql_statement_t *s,
    const vireo_mysql_parameter_t *p,size_t n,vireo_mysql_execution_t *out,vireo_mysql_error_t *e)
{
    assert(t==thread && s && m.statements==1);enum operation op=((struct model_statement *)s)->op;
    ++m.executed[op];*e=(vireo_mysql_error_t){0};*out=(vireo_mysql_execution_t){.execution_started=true};
    if(op==ACCOUNT) { assert(n==1 && m.executed[BEGIN]);number(p,input.user_id); }
    else if(op==SESSION) { assert(n==1 && m.executed[ACCOUNT]);number(p,input.session_id); }
    else if(op==UPDATE) { assert(n==3 && m.executed[SESSION]);number(p,input.occurred_at_ms);number(p+1,input.session_id);number(p+2,input.user_id); }
    else if(op==AUDIT) { assert(n==6 && m.executed[UPDATE]);span(p,input.request_id,16);number(p+1,input.user_id);number(p+2,input.session_id);number(p+3,input.session_id);number(p+4,input.latency_us);number(p+5,input.occurred_at_ms); }
    else { assert(n==0 && !p); }
    if(op==m.execute_fail) { out->execution_started=!m.not_started;e->stage=VIREO_MYSQL_STAGE_STATEMENT_EXECUTE;e->mysql_code=m.mysql_code;return VIREO_RESULT_DATABASE; }
    if(op==AUDIT) { out->affected_rows=1;out->insert_id=33; }
    if(op==ACCOUNT || op==SESSION) { out->has_result=true; }
    if(op==UPDATE) { out->affected_rows=m.changed_rows; }
    if(op==m.bad_shape) {
        if(m.shape==0) { out->has_result=op!=ACCOUNT && op!=SESSION; }
        else if(m.shape==1) { out->affected_rows=0; }
        else { out->insert_id=0; }
    }return VIREO_OK;
}
static vireo_result_t close_statement(vireo_mysql_thread_t *t,vireo_mysql_statement_t **s,vireo_mysql_error_t *e)
{
    assert(t==thread && *s && m.statements==1);enum operation op=((struct model_statement *)*s)->op;*e=(vireo_mysql_error_t){0};
    if(op!=m.close_fail || !m.keep_statement) { free(*s);*s=NULL;--m.statements; }
    if(op==m.close_fail) { e->stage=VIREO_MYSQL_STAGE_STATEMENT_CLOSE;e->mysql_code=2013;return m.keep_statement ? VIREO_RESULT_BUSY : VIREO_RESULT_DATABASE; }return VIREO_OK;
}
static vireo_result_t fetch(vireo_mysql_thread_t *t,vireo_mysql_statement_t *s,vireo_mysql_fetch_outcome_t *out,vireo_mysql_error_t *e)
{
    enum operation op=((struct model_statement *)s)->op;assert(t==thread && (op==ACCOUNT || op==SESSION));++m.fetches;*e=(vireo_mysql_error_t){0};
    if(op==m.read_fault && (m.fetch_fail || (m.second_fetch_fail && m.fetches==2))) { e->stage=VIREO_MYSQL_STAGE_STATEMENT_FETCH;return VIREO_RESULT_DATABASE; }
    bool absent=op==ACCOUNT ? m.absent_user : m.absent_session;
    *out=absent || (m.fetches>1 && !(m.extra && op==m.read_fault)) ? VIREO_MYSQL_FETCH_DONE : VIREO_MYSQL_FETCH_ROW;
    if(op==SESSION && m.fetches>1) { memset(m.cells,'x',sizeof(m.cells)); }return VIREO_OK;
}
static vireo_result_t column(vireo_mysql_thread_t *t,const vireo_mysql_statement_t *s,size_t i,vireo_mysql_cell_view_t *out)
{
    enum operation op=((const struct model_statement *)s)->op;assert(t==thread && (op==ACCOUNT || op==SESSION));
    if(m.column_fail && op==m.read_fault) { return VIREO_RESULT_DATABASE; }
    static char id[32];(void)snprintf(id,sizeof(id),"%llu",(unsigned long long)input.user_id);
    const char *data;bool null;
    if(op==ACCOUNT) { assert(i==0);data=m.user_bad[0] ? m.user_bad : id;null=m.user_null; }
    else { assert(i<6);data=m.cells[i];null=m.nulls[i]; }
    *out=(vireo_mysql_cell_view_t){.data=(const unsigned char *)data,.length=strlen(data),.is_null=null};return VIREO_OK;
}
static const vireo_mysql_user_repository_ops_t ops={allocate,release_memory,acquire,borrow,release,prepare,execute,close_statement,fetch,column};
static void cell(size_t i,const char *s) { assert(i<6 && strlen(s)<sizeof(m.cells[i]));memset(m.cells[i],0,sizeof(m.cells[i]));memcpy(m.cells[i],s,strlen(s)); }
static void start(void)
{
    assert(!repo && !m.blocks && !m.statements);memset(&m,0,sizeof(m));m.mysql_code=1062;m.changed_rows=1;
    input=(vireo_mysql_logout_input_t){.user_id=11,.session_id=22,.request_id={1},.occurred_at_ms=1234,.latency_us=97};
    const char *values[]={"11","1","1000","9999","0","1000"};for(size_t i=0;i<6;++i) { cell(i,values[i]); }m.nulls[4]=true;
    CHECK(vireo_mysql_user_repository_create_with_ops(thread,&pool,&policy,&repo,&error,&ops),VIREO_OK);++scenarios;
}
static void stop(void)
{
    m.close_fail=NONE;m.release_keep=false;m.release_consumed=false;
    CHECK(vireo_mysql_user_repository_destroy(&repo,NULL),VIREO_OK);assert(!repo && !m.blocks && !m.statements);
}
static void run(vireo_result_t want)
{ memset(&report,0xa5,sizeof(report));memset(&error,0xa5,sizeof(error));CHECK(vireo_mysql_user_repository_logout(repo,&input,0,&report,&error),want); }
static void no_ids(void) { assert(!report.session_id && !report.audit_id && !report.revoked_at_ms && !report.already_revoked); }
static void committed(void)
{ assert(report.commit==VIREO_MYSQL_LOGOUT_COMMITTED && report.session_id==input.session_id && report.audit_id==33 && report.revoked_at_ms==input.occurred_at_ms && !report.already_revoked && !report.rollback_confirmed); }
static void busy_all(void)
{
    size_t n=m.acquired;run(VIREO_RESULT_BUSY);assert(report.cleanup_pending);
    vireo_mysql_registration_report_t a;vireo_mysql_login_report_t b;vireo_mysql_user_credentials_t c;vireo_mysql_credentials_report_t d;
    vireo_mysql_session_identity_t identity;vireo_mysql_session_report_t session;
    CHECK(vireo_mysql_user_repository_register(repo,NULL,0,&a,NULL),VIREO_RESULT_BUSY);
    CHECK(vireo_mysql_user_repository_login(repo,NULL,0,&b,NULL),VIREO_RESULT_BUSY);
    CHECK(vireo_mysql_user_repository_find_credentials(repo,NULL,0,0,&c,&d,NULL),VIREO_RESULT_BUSY);
    CHECK(vireo_mysql_user_repository_find_session(repo,NULL,0,0,&identity,&session,NULL),VIREO_RESULT_BUSY);
    assert(a.cleanup_pending && b.cleanup_pending && d.cleanup_pending && session.cleanup_pending && n==m.acquired);
}
static void *wrong_thread(void *unused)
{ (void)unused;vireo_mysql_logout_report_t out;CHECK(vireo_mysql_user_repository_logout(repo,&input,0,&out,NULL),VIREO_RESULT_INVALID_ARGUMENT);assert(!out.session_id && !out.audit_id);return NULL; }
int main(void)
{
    struct sigaction sa={0};sa.sa_handler=SIG_IGN;assert(!sigemptyset(&sa.sa_mask) && !sigaction(SIGPIPE,&sa,NULL));
    vireo_mysql_runtime_t *runtime=NULL;CHECK(vireo_mysql_runtime_create(&runtime,NULL),VIREO_OK);CHECK(vireo_mysql_thread_attach(runtime,&thread,NULL),VIREO_OK);pool.runtime=runtime;
    start();run(VIREO_OK);committed();assert(m.disposition==VIREO_MYSQL_POOL_RECYCLE && !error.stage);
    pthread_t other;assert(!pthread_create(&other,NULL,wrong_thread,NULL) && !pthread_join(other,NULL));stop();
    for(unsigned int i=0;i<3;++i) { start();if(i==0) { input.user_id=0; }else if(i==1) { input.session_id=0; }else { memset(input.request_id,0,16); }run(VIREO_RESULT_INVALID_ARGUMENT);assert(!m.acquired);no_ids();stop(); }
    start();CHECK(vireo_mysql_user_repository_logout(repo,&input,60001,&report,NULL),VIREO_RESULT_RANGE);CHECK(vireo_mysql_user_repository_logout(repo,NULL,0,&report,NULL),VIREO_RESULT_INVALID_ARGUMENT);CHECK(vireo_mysql_user_repository_logout(repo,&input,0,NULL,NULL),VIREO_RESULT_INVALID_ARGUMENT);assert(!m.acquired);stop();
    start();cell(1,"2");m.nulls[4]=false;cell(4,"1200");run(VIREO_OK);assert(report.commit==VIREO_MYSQL_LOGOUT_COMMITTED && report.already_revoked && report.revoked_at_ms==1200 && report.session_id==22 && !report.audit_id && !m.executed[UPDATE] && !m.executed[AUDIT]);stop();
    start();input.user_id=UINT64_MAX;input.session_id=UINT64_MAX;input.occurred_at_ms=UINT64_MAX;input.latency_us=UINT64_MAX;cell(0,"18446744073709551615");run(VIREO_OK);committed();stop();
    start();cell(2,"0");cell(5,"0");input.occurred_at_ms=0;run(VIREO_OK);committed();stop();
    for(unsigned int i=0;i<4;++i) {
        start();if(i==0) { m.absent_user=true; }else if(i==1) { m.absent_session=true; }else if(i==2) { cell(0,"12"); }else { input.occurred_at_ms=999; }
        run(i==3 ? VIREO_RESULT_RANGE : VIREO_RESULT_NOT_FOUND);assert(report.issue==(vireo_mysql_logout_issue_t)(i+1) && report.rollback_confirmed && !m.executed[UPDATE]);no_ids();stop();
    }
    for(unsigned int i=0;i<3;++i) { start();if(i==0) { m.user_null=true; }else { strcpy(m.user_bad,i==1 ? "0" : "12"); }run(VIREO_RESULT_DATABASE);assert(report.issue==VIREO_MYSQL_LOGOUT_UNEXPECTED_RESULT && report.rollback_confirmed);no_ids();stop(); }
    for(size_t i=0;i<6;++i) { if(i==4) { continue; }start();m.nulls[i]=true;run(VIREO_RESULT_DATABASE);assert(report.issue==VIREO_MYSQL_LOGOUT_UNEXPECTED_RESULT);stop(); }
    for(unsigned int i=0;i<13;++i) {
        start();switch(i) {
        case 0:cell(0,"0");break;case 1:cell(1,"3");break;case 2:cell(2,"18446744073709551616");break;
        case 3:cell(3,"1000");break;case 4:cell(3,"999");break;case 5:cell(5,"999");break;case 6:cell(5,"10000");break;
        case 7:m.nulls[4]=false;break;case 8:cell(1,"2");break;case 9:cell(1,"2");m.nulls[4]=false;cell(4,"999");break;
        case 10:cell(2,"-1");break;case 11:cell(3,"");break;default:cell(5,"1x");break;
        }run(VIREO_RESULT_DATABASE);assert(report.issue==VIREO_MYSQL_LOGOUT_UNEXPECTED_RESULT && report.rollback_confirmed && !m.executed[UPDATE]);no_ids();stop();
    }
    for(enum operation op=ACCOUNT;op<=SESSION;op=(enum operation)(op+1)) {
        for(unsigned int i=0;i<4;++i) { start();m.read_fault=op;if(i==0) { m.fetch_fail=true; }else if(i==1) { m.second_fetch_fail=true; }else if(i==2) { m.column_fail=true; }else { m.extra=true; }run(VIREO_RESULT_DATABASE);assert(report.rollback_confirmed && !m.executed[UPDATE]);no_ids();stop(); }
    }
    for(enum operation op=BEGIN;op<=COMMIT;op=(enum operation)(op+1)) {
        for(unsigned int kind=0;kind<3;++kind) {
            start();if(kind==0) { m.prepare_fail=op; }else if(kind==1) { m.execute_fail=op; }else { m.close_fail=op; }
            run(VIREO_RESULT_DATABASE);
            if(op==COMMIT && kind==2) { committed(); }
            else if(op==COMMIT && kind==1) { assert(report.commit==VIREO_MYSQL_LOGOUT_UNKNOWN && !report.rollback_confirmed && !m.executed[ROLLBACK] && m.disposition==VIREO_MYSQL_POOL_DISCARD);no_ids(); }
            else { assert(report.commit==VIREO_MYSQL_LOGOUT_NOT_COMMITTED && report.rollback_confirmed==(op!=BEGIN || kind!=0));no_ids(); }
            if(op==AUDIT && kind==1) { assert(report.issue==VIREO_MYSQL_LOGOUT_REQUEST_CONFLICT); }stop();
        }
    }
    for(enum operation op=BEGIN;op<=COMMIT;op=(enum operation)(op+1)) {
        start();m.bad_shape=op;run(VIREO_RESULT_DATABASE);assert(report.issue==VIREO_MYSQL_LOGOUT_UNEXPECTED_RESULT);
        assert(report.commit==(op==COMMIT ? VIREO_MYSQL_LOGOUT_UNKNOWN : VIREO_MYSQL_LOGOUT_NOT_COMMITTED));no_ids();stop();
    }
    start();m.changed_rows=0;run(VIREO_RESULT_DATABASE);assert(report.rollback_confirmed && !m.executed[AUDIT]);stop();
    start();m.changed_rows=2;run(VIREO_RESULT_DATABASE);assert(report.rollback_confirmed && !m.executed[AUDIT]);stop();
    for(unsigned int i=1;i<=2;++i) { start();m.bad_shape=AUDIT;m.shape=i;run(VIREO_RESULT_DATABASE);assert(report.issue==VIREO_MYSQL_LOGOUT_UNEXPECTED_RESULT && report.rollback_confirmed);no_ids();stop(); }
    start();m.execute_fail=COMMIT;m.not_started=true;run(VIREO_RESULT_DATABASE);assert(report.commit==VIREO_MYSQL_LOGOUT_NOT_COMMITTED && report.rollback_confirmed);no_ids();stop();
    start();m.execute_fail=BEGIN;m.not_started=true;run(VIREO_RESULT_DATABASE);assert(!m.executed[ROLLBACK]);no_ids();stop();
    start();m.execute_fail=AUDIT;m.mysql_code=1213;run(VIREO_RESULT_DATABASE);assert(report.issue==VIREO_MYSQL_LOGOUT_ISSUE_NONE && report.rollback_confirmed);stop();
    for(enum operation op=BEGIN;op<=COMMIT;op=(enum operation)(op+1)) {
        start();m.close_fail=op;m.keep_statement=true;run(VIREO_RESULT_BUSY);assert(report.cleanup_pending && !m.released && !m.executed[ROLLBACK]);
        if(op==COMMIT) { committed(); }else { no_ids(); }busy_all();stop();
    }
    start();m.release_keep=true;run(VIREO_RESULT_INTERNAL);committed();busy_all();CHECK(vireo_mysql_user_repository_destroy(&repo,NULL),VIREO_RESULT_INTERNAL);assert(repo);stop();
    start();m.release_consumed=true;run(VIREO_RESULT_DATABASE);committed();assert(!report.cleanup_pending);stop();
    start();m.absent_session=true;m.execute_fail=ROLLBACK;run(VIREO_RESULT_NOT_FOUND);assert(!report.rollback_confirmed && error.stage==VIREO_MYSQL_USER_REPOSITORY_STAGE_LOGOUT_SESSION && error.cleanup_stage==VIREO_MYSQL_USER_REPOSITORY_STAGE_ROLLBACK && m.disposition==VIREO_MYSQL_POOL_DISCARD);no_ids();stop();
    start();m.absent_session=true;m.close_fail=ROLLBACK;run(VIREO_RESULT_NOT_FOUND);assert(report.rollback_confirmed && error.cleanup_stage==VIREO_MYSQL_USER_REPOSITORY_STAGE_STATEMENT_CLOSE);stop();
    start();m.absent_session=true;m.close_fail=SESSION;m.keep_statement=true;run(VIREO_RESULT_NOT_FOUND);assert(report.cleanup_pending && !m.executed[ROLLBACK]);busy_all();stop();
    start();m.acquire_partial=true;m.release_keep=true;run(VIREO_RESULT_INTERNAL);assert(!m.executed[BEGIN]);busy_all();stop();
    start();m.acquire_empty=true;run(VIREO_RESULT_BUSY);assert(!m.released);stop();
    start();m.borrow_fail=true;run(VIREO_RESULT_INTERNAL);assert(!m.executed[BEGIN] && m.disposition==VIREO_MYSQL_POOL_DISCARD);stop();
    /* 旧四方法的partial lease残留也挡新logout，无第二次acquire。 */
    for(unsigned int i=0;i<4;++i) {
        start();m.acquire_partial=true;m.release_keep=true;
        if(i==0) { vireo_mysql_registration_input_t in={.username="a",.username_length=1,.username_key="a",.username_key_length=1,.password_hash=phc,.password_hash_length=sizeof(phc)-1,.request_id={1}};vireo_mysql_registration_report_t out;CHECK(vireo_mysql_user_repository_register(repo,&in,0,&out,NULL),VIREO_RESULT_INTERNAL); }
        else if(i==1) { vireo_mysql_login_input_t in={.user_id=11,.verified_password_hash=phc,.verified_password_hash_length=sizeof(phc)-1,.issued_at_ms=1,.expires_at_ms=2,.request_id={1}};vireo_mysql_login_report_t out;CHECK(vireo_mysql_user_repository_login(repo,&in,0,&out,NULL),VIREO_RESULT_INTERNAL); }
        else if(i==2) { vireo_mysql_user_credentials_t out;vireo_mysql_credentials_report_t state;CHECK(vireo_mysql_user_repository_find_credentials(repo,"a",1,0,&out,&state,NULL),VIREO_RESULT_INTERNAL); }
        else { vireo_session_token_digest_t digest={{0}};vireo_mysql_session_identity_t out;vireo_mysql_session_report_t state;CHECK(vireo_mysql_user_repository_find_session(repo,&digest,0,0,&out,&state,NULL),VIREO_RESULT_INTERNAL); }
        busy_all();stop();
    }
    CHECK(vireo_mysql_thread_detach(&thread),VIREO_OK);CHECK(vireo_mysql_runtime_destroy(&runtime),VIREO_OK);
    printf("PASS %zu logout resource-boundary scenarios: user/session lock order, exact audit/update, repeated effect, shapes/time/u64, three commit facts, rollback/cleanup, five-method ownership, errno/thread\n",scenarios);return 0;
}
