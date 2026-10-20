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
    unsigned int fetches, row_shape; bool absent, disabled, changed, future, extra, fetch_fail, column_fail;
    bool second_fetch_fail; uint64_t changed_rows;
    vireo_mysql_pool_disposition_t disposition;
} m;
static const char phc[]="$argon2id$v=19$m=65536,t=3,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
static vireo_password_policy_t policy=VIREO_PASSWORD_POLICY_DEFAULT;
static vireo_mysql_thread_t *thread;
static vireo_mysql_pool_t pool;
static vireo_mysql_connection_t connection;
static vireo_mysql_user_repository_t *repo;
static vireo_mysql_login_input_t input;
static vireo_mysql_login_report_t report;
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
    if(!strncmp(sql,"SELECT password_hash,",21)) { assert(!strcmp(sql,"SELECT password_hash,status,created_at_ms FROM users WHERE id=? FOR UPDATE")); return ACCOUNT; }
    if(!strncmp(sql,"INSERT INTO sessions(",21)) { return SESSION; }
    if(!strncmp(sql,"UPDATE users SET",16)) { return UPDATE; }
    if(!strncmp(sql,"INSERT INTO operation_audits(",29)) { return AUDIT; }
    if(!strcmp(sql,"COMMIT")) { return COMMIT; }
    assert(!strcmp(sql,"ROLLBACK")); return ROLLBACK;
}
static vireo_result_t prepare(vireo_mysql_thread_t *t,vireo_mysql_connection_t *c,
    const char *sql,size_t n,const vireo_mysql_statement_limits_t *limits,
    vireo_mysql_statement_t **out,vireo_mysql_error_t *e)
{
    assert(t==thread && c==&connection && !*out && m.statements==0);
    assert((limits->max_parameters==6 && limits->max_columns==0 && limits->max_parameter_bytes>=639) || (limits->max_parameters==1 && limits->max_columns==3 && limits->max_cell_bytes==127));
    enum operation op=identify(sql,n); ++m.prepared[op]; *e=(vireo_mysql_error_t){0};
    if(op==m.prepare_fail) { e->stage=VIREO_MYSQL_STAGE_STATEMENT_PREPARE; e->mysql_code=m.mysql_code; return VIREO_RESULT_DATABASE; }
    struct model_statement *s=malloc(sizeof(*s)); assert(s); s->op=op;
    *out=(vireo_mysql_statement_t *)s; ++m.statements; return VIREO_OK;
}
static void span(const vireo_mysql_parameter_t *p,vireo_mysql_parameter_kind_t kind,const void *data,size_t n)
{ assert(p->kind==kind && p->value.span.length==n && !memcmp(p->value.span.data,data,n)); }
static void number(const vireo_mysql_parameter_t *p,uint64_t n)
{ assert(p->kind==VIREO_MYSQL_PARAMETER_U64 && p->value.u64==n); }
static vireo_result_t execute(vireo_mysql_thread_t *t,vireo_mysql_statement_t *s,
    const vireo_mysql_parameter_t *p,size_t n,vireo_mysql_execution_t *out,vireo_mysql_error_t *e)
{
    assert(t==thread && s && m.statements==1); enum operation op=((struct model_statement *)s)->op;
    ++m.executed[op]; *e=(vireo_mysql_error_t){0}; *out=(vireo_mysql_execution_t){.execution_started=true};
    if(op==ACCOUNT) { assert(n==1); number(p,input.user_id); }
    else if(op==SESSION) {
        assert(n==5); number(p,input.user_id); span(p+1,VIREO_MYSQL_PARAMETER_BYTES,input.token_digest.bytes,32);
        number(p+2,input.issued_at_ms); number(p+3,input.expires_at_ms); number(p+4,input.issued_at_ms);
    } else if(op==UPDATE) { assert(n==3); number(p,input.issued_at_ms); number(p+1,input.issued_at_ms); number(p+2,input.user_id); }
    else if(op==AUDIT) { assert(n==6); span(p,VIREO_MYSQL_PARAMETER_BYTES,input.request_id,16); number(p+1,input.user_id); number(p+2,22); number(p+3,22); number(p+4,input.latency_us); number(p+5,input.issued_at_ms); }
    else { assert(n==0 && !p); }
    if(op==m.execute_fail) {
        out->execution_started=!m.not_started; e->stage=VIREO_MYSQL_STAGE_STATEMENT_EXECUTE;
        e->mysql_code=m.mysql_code; memcpy(e->sqlstate,"HY000",6); return VIREO_RESULT_DATABASE;
    }
    if(op==SESSION || op==AUDIT) { out->affected_rows=1; out->insert_id=op==SESSION ? 22 : 33; }
    if(op==ACCOUNT) { out->has_result=true; }
    if(op==UPDATE) { out->affected_rows=m.changed_rows; }
    if(op==m.bad_shape) {
        if(m.shape==0) { out->has_result=op!=ACCOUNT; }
        else if(m.shape==1) { out->affected_rows=0; }
        else { out->insert_id=0; }
    }
    return VIREO_OK;
}
static vireo_result_t close_statement(vireo_mysql_thread_t *t,vireo_mysql_statement_t **s,vireo_mysql_error_t *e)
{
    assert(t==thread && *s && m.statements==1); enum operation op=((struct model_statement *)*s)->op;
    *e=(vireo_mysql_error_t){0};
    if(op!=m.close_fail || !m.keep_statement) { free(*s); *s=NULL; --m.statements; }
    if(op==m.close_fail) { e->stage=VIREO_MYSQL_STAGE_STATEMENT_CLOSE; e->mysql_code=2013; return m.keep_statement ? VIREO_RESULT_BUSY : VIREO_RESULT_DATABASE; }
    return VIREO_OK;
}
static vireo_result_t fetch(vireo_mysql_thread_t *t,vireo_mysql_statement_t *s,
    vireo_mysql_fetch_outcome_t *out,vireo_mysql_error_t *e)
{
    assert(t==thread && ((struct model_statement *)s)->op==ACCOUNT); ++m.fetches;
    *e=(vireo_mysql_error_t){0};
    if(m.fetch_fail || (m.second_fetch_fail && m.fetches==2)) { e->stage=VIREO_MYSQL_STAGE_STATEMENT_FETCH; return VIREO_RESULT_DATABASE; }
    *out=m.absent || (m.fetches>1 && !m.extra) ? VIREO_MYSQL_FETCH_DONE : VIREO_MYSQL_FETCH_ROW; return VIREO_OK;
}
static vireo_result_t column(vireo_mysql_thread_t *t,const vireo_mysql_statement_t *s,
    size_t i,vireo_mysql_cell_view_t *out)
{
    assert(t==thread && ((const struct model_statement *)s)->op==ACCOUNT && i<3);
    if(m.column_fail) { return VIREO_RESULT_DATABASE; }
    const char *data=i==0 ? (m.changed ? "different" : input.verified_password_hash) :
        (i==1 ? (m.disabled ? "2" : "1") : (m.future ? "2000" : "1000"));
    size_t n=i==0 && !m.changed ? input.verified_password_hash_length : strlen(data);
    if(i==1 && m.row_shape==1) { data="3"; n=1; }
    if(i==2) {
        if(m.row_shape==2) { data="18446744073709551616"; n=20; }
        if(m.row_shape==3) { data="-1"; n=2; }
        if(m.row_shape==4) { n=0; }
        if(m.row_shape==5) { data="1a"; n=2; }
        if(m.row_shape==6) { data="18446744073709551615"; n=20; }
    }
    *out=(vireo_mysql_cell_view_t){.data=(const unsigned char *)data,.length=n,.is_null=i==0 && m.row_shape==7};
    return VIREO_OK;
}
static const vireo_mysql_user_repository_ops_t ops={allocate,release_memory,acquire,borrow,release,prepare,execute,close_statement,fetch,column};
static void start(void)
{
    assert(!repo && !m.blocks && !m.statements); memset(&m,0,sizeof(m)); m.mysql_code=1062; m.changed_rows=1;
    input=(vireo_mysql_login_input_t){.user_id=11,.verified_password_hash=phc,.verified_password_hash_length=sizeof(phc)-1,
        .request_id={1},.issued_at_ms=1234,.expires_at_ms=9999,.latency_us=97};
    CHECK(vireo_mysql_user_repository_create_with_ops(thread,&pool,&policy,&repo,&error,&ops),VIREO_OK);
    ++scenarios;
}
static void stop(void)
{
    m.close_fail=NONE; m.release_keep=false; m.release_consumed=false;
    CHECK(vireo_mysql_user_repository_destroy(&repo,&error),VIREO_OK);
    assert(!repo && !m.blocks && !m.statements);
}
static void run(vireo_result_t result)
{ memset(&report,0xa5,sizeof(report)); memset(&error,0xa5,sizeof(error)); CHECK(vireo_mysql_user_repository_login(repo,&input,0,&report,&error),result); }
static void no_ids(void) { assert(!report.session_id && !report.audit_id); }
static void committed(void)
{ assert(report.commit==VIREO_MYSQL_LOGIN_COMMITTED && report.session_id==22 && report.audit_id==33 && !report.rollback_confirmed); }
static void busy_both(void)
{
    size_t calls=m.acquired;run(VIREO_RESULT_BUSY);assert(report.cleanup_pending && calls==m.acquired);
    vireo_mysql_registration_report_t out;
    CHECK(vireo_mysql_user_repository_register(repo,NULL,0,&out,NULL),VIREO_RESULT_BUSY);
    assert(out.cleanup_pending && calls==m.acquired);
}
static void *wrong_thread(void *unused)
{
    (void)unused;vireo_mysql_login_report_t out;
    CHECK(vireo_mysql_user_repository_login(repo,&input,0,&out,NULL),VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_mysql_user_repository_destroy(&repo,NULL),VIREO_RESULT_INVALID_ARGUMENT);return NULL;
}
int main(void)
{
    struct sigaction sa={0};sa.sa_handler=SIG_IGN;assert(!sigemptyset(&sa.sa_mask) && !sigaction(SIGPIPE,&sa,NULL));
    vireo_mysql_runtime_t *runtime=NULL;CHECK(vireo_mysql_runtime_create(&runtime,NULL),VIREO_OK);
    CHECK(vireo_mysql_thread_attach(runtime,&thread,NULL),VIREO_OK);pool.runtime=runtime;
    start();run(VIREO_OK);committed();assert(m.disposition==VIREO_MYSQL_POOL_RECYCLE && error.stage==0);
    pthread_t other;assert(!pthread_create(&other,NULL,wrong_thread,NULL) && !pthread_join(other,NULL));stop();
    for(unsigned int i=0;i<10;++i) {
        start();vireo_result_t want=VIREO_RESULT_RANGE;
        switch(i) {
        case 0:input.user_id=0;want=VIREO_RESULT_INVALID_ARGUMENT;break;
        case 1:input.verified_password_hash=NULL;want=VIREO_RESULT_INVALID_ARGUMENT;break;
        case 2:input.verified_password_hash_length=0;break;
        case 3:input.verified_password_hash_length=128;break;
        case 4:memset(input.request_id,0,16);want=VIREO_RESULT_INVALID_ARGUMENT;break;
        case 5:input.verified_password_hash="bad";input.verified_password_hash_length=3;want=VIREO_RESULT_PROTOCOL;break;
        case 6:input.expires_at_ms=input.issued_at_ms;break;
        case 7:input.expires_at_ms=0;break;
        case 8:input.issued_at_ms=UINT64_MAX;input.expires_at_ms=UINT64_MAX;break;
        default:input.verified_password_hash="$argon2id$v=19$m=262145,t=3,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";input.verified_password_hash_length=strlen(input.verified_password_hash);break;
        }
        run(want);assert(!m.acquired && error.stage==VIREO_MYSQL_USER_REPOSITORY_STAGE_VALIDATE);no_ids();stop();
    }
    start();CHECK(vireo_mysql_user_repository_login(repo,&input,60001,&report,NULL),VIREO_RESULT_RANGE);
    CHECK(vireo_mysql_user_repository_login(repo,NULL,0,&report,NULL),VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_mysql_user_repository_login(repo,&input,0,NULL,NULL),VIREO_RESULT_INVALID_ARGUMENT);assert(!m.acquired);stop();
    start();input.verified_password_hash="$argon2id$v=19$m=8,t=1,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    input.verified_password_hash_length=strlen(input.verified_password_hash);run(VIREO_OK);committed();stop();
    start();m.changed_rows=0;run(VIREO_OK);committed();stop();
    start();m.row_shape=6;input.issued_at_ms=UINT64_MAX-1;input.expires_at_ms=UINT64_MAX;
    run(VIREO_RESULT_RANGE);assert(report.issue==VIREO_MYSQL_LOGIN_TIME_BEFORE_USER);stop();
    start();input.issued_at_ms=UINT64_MAX-1;input.expires_at_ms=UINT64_MAX;run(VIREO_OK);committed();stop();
    for(unsigned int i=0;i<4;++i) {
        start();if(i==0) { m.absent=true; }else if(i==1) { m.disabled=true; }else if(i==2) { m.changed=true; }else { m.future=true; }
        run(i==3 ? VIREO_RESULT_RANGE : VIREO_RESULT_NOT_FOUND);
        assert(report.issue==(vireo_mysql_login_issue_t)(i+1) && report.rollback_confirmed && !m.executed[SESSION]);no_ids();stop();
    }
    for(unsigned int i=1;i<=7;++i) {
        if(i==6) { continue; }start();m.row_shape=i;run(VIREO_RESULT_DATABASE);
        assert(report.issue==VIREO_MYSQL_LOGIN_UNEXPECTED_RESULT && report.rollback_confirmed && !m.executed[SESSION]);no_ids();stop();
    }
    for(unsigned int i=0;i<4;++i) {
        start();if(i==0) { m.fetch_fail=true; }else if(i==1) { m.second_fetch_fail=true; }else if(i==2) { m.column_fail=true; }else { m.extra=true; }
        run(VIREO_RESULT_DATABASE);assert(report.rollback_confirmed && error.stage==VIREO_MYSQL_USER_REPOSITORY_STAGE_ACCOUNT && !m.executed[SESSION]);no_ids();stop();
    }
    for(enum operation op=BEGIN;op<=COMMIT;op=(enum operation)(op+1)) {
        start();m.prepare_fail=op;run(VIREO_RESULT_DATABASE);no_ids();assert(report.commit==0 && report.rollback_confirmed==(op!=BEGIN) && !m.executed[COMMIT]);stop();
        start();m.execute_fail=op;run(VIREO_RESULT_DATABASE);no_ids();
        if(op==COMMIT) { assert(report.commit==VIREO_MYSQL_LOGIN_UNKNOWN && !m.executed[ROLLBACK] && m.disposition==VIREO_MYSQL_POOL_DISCARD); }
        else { assert(report.commit==0 && report.rollback_confirmed); }
        if(op==SESSION) { assert(report.issue==VIREO_MYSQL_LOGIN_DIGEST_CONFLICT); }
        if(op==AUDIT) { assert(report.issue==VIREO_MYSQL_LOGIN_REQUEST_CONFLICT); }stop();
        start();m.close_fail=op;run(VIREO_RESULT_DATABASE);assert(error.cleanup_result==VIREO_RESULT_DATABASE && !report.cleanup_pending);
        if(op==COMMIT) { committed(); }else { no_ids();assert(report.rollback_confirmed); }stop();
        start();m.close_fail=op;m.keep_statement=true;run(VIREO_RESULT_BUSY);assert(report.cleanup_pending && !m.released);
        if(op==COMMIT) { committed(); }else { no_ids(); }busy_both();stop();
    }
    start();m.execute_fail=BEGIN;m.not_started=true;run(VIREO_RESULT_DATABASE);assert(report.commit==0 && !report.rollback_confirmed && !m.executed[ROLLBACK] && m.disposition==VIREO_MYSQL_POOL_DISCARD);stop();
    start();m.execute_fail=COMMIT;m.not_started=true;run(VIREO_RESULT_DATABASE);assert(report.commit==0 && report.rollback_confirmed);no_ids();stop();
    for(enum operation op=SESSION;op<=AUDIT;op=(enum operation)(op+1)) {
        if(op==UPDATE) { continue; }
        for(unsigned int i=0;i<3;++i) { start();m.bad_shape=op;m.shape=i;run(VIREO_RESULT_DATABASE);no_ids();assert(report.rollback_confirmed && !m.executed[COMMIT]);stop(); }
    }
    start();m.changed_rows=2;run(VIREO_RESULT_DATABASE);assert(report.issue==VIREO_MYSQL_LOGIN_UNEXPECTED_RESULT && report.rollback_confirmed);stop();
    start();m.bad_shape=ACCOUNT;run(VIREO_RESULT_DATABASE);assert(report.issue==VIREO_MYSQL_LOGIN_UNEXPECTED_RESULT && report.rollback_confirmed);stop();
    start();m.bad_shape=COMMIT;run(VIREO_RESULT_DATABASE);assert(report.commit==VIREO_MYSQL_LOGIN_UNKNOWN && !m.executed[ROLLBACK]);no_ids();stop();
    start();m.absent=true;m.close_fail=ACCOUNT;run(VIREO_RESULT_NOT_FOUND);assert(error.stage==VIREO_MYSQL_USER_REPOSITORY_STAGE_ACCOUNT && error.cleanup_stage==VIREO_MYSQL_USER_REPOSITORY_STAGE_STATEMENT_CLOSE);stop();
    start();m.prepare_fail=SESSION;m.execute_fail=ROLLBACK;m.close_fail=ROLLBACK;m.release_keep=true;run(VIREO_RESULT_DATABASE);
    assert(error.stage==VIREO_MYSQL_USER_REPOSITORY_STAGE_SESSION && error.cleanup_stage==VIREO_MYSQL_USER_REPOSITORY_STAGE_ROLLBACK && report.cleanup_pending && !report.rollback_confirmed);busy_both();stop();
    start();m.acquire_partial=true;m.release_keep=true;run(VIREO_RESULT_INTERNAL);assert(report.cleanup_pending);busy_both();stop();
    start();m.acquire_partial=true;run(VIREO_RESULT_INTERNAL);assert(!report.cleanup_pending && m.released==1 && !m.prepared[BEGIN]);stop();
    start();m.acquire_empty=true;run(VIREO_RESULT_BUSY);assert(!m.released);stop();
    start();m.borrow_fail=true;run(VIREO_RESULT_INTERNAL);assert(m.disposition==VIREO_MYSQL_POOL_DISCARD && !m.prepared[BEGIN]);stop();
    start();m.release_keep=true;run(VIREO_RESULT_INTERNAL);committed();busy_both();stop();
    start();m.release_consumed=true;run(VIREO_RESULT_DATABASE);committed();assert(!report.cleanup_pending);stop();
    CHECK(vireo_mysql_thread_detach(&thread),VIREO_OK);CHECK(vireo_mysql_runtime_destroy(&runtime),VIREO_OK);
    printf("PASS %zu login resource-boundary scenarios: locked snapshot, historical PHC, monotonic times, exact parameters, faults, three commit facts, cross-method ownership, errno/thread\n",scenarios);return 0;
}
