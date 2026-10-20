#define _POSIX_C_SOURCE 200809L
#include "mysql_user_repository_internal.h"
#include "mysql_pool_internal.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(call,want) do { errno=EDOM; vireo_result_t got_=(call); if(got_!=(want)) { fprintf(stderr,"line %d got %d want %d\n",__LINE__,(int)got_,(int)(want)); abort(); } assert(errno==EDOM); } while(0)
enum operation { NONE, BEGIN, AUDIT, COMMIT, ROLLBACK, OP_COUNT };
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
static vireo_password_policy_t policy=VIREO_PASSWORD_POLICY_DEFAULT;
static vireo_mysql_thread_t *thread;
static vireo_mysql_pool_t pool;
static vireo_mysql_connection_t connection;
static vireo_mysql_user_repository_t *repo;
static vireo_mysql_auth_failure_input_t input;
static vireo_mysql_auth_failure_report_t report;
static vireo_mysql_user_repository_error_t error;
static size_t scenarios;
static void *allocate(size_t n)
{ if(m.allocation_fail) { return NULL; } void *p=malloc(n); assert(p); ++m.blocks; return p; }
static void release_memory(void *p)
{ assert(p && m.blocks==1); --m.blocks; free(p); }
static vireo_result_t acquire(vireo_mysql_thread_t *t,vireo_mysql_pool_t *p,uint32_t wait,
    vireo_mysql_lease_t *l,vireo_mysql_pool_acquisition_t *a,vireo_mysql_pool_error_t *e)
{
    assert(t==thread && p==&pool && wait==0 && !l->owner); ++m.acquired;
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
    if(!strcmp(sql,"INSERT INTO operation_audits(request_id,user_id,session_id,action,target_type,target_id,target_hash,status,latency_us,detail,occurred_at_ms) VALUES(?,NULL,NULL,?,0,NULL,NULL,?,?,?,?)")) { return AUDIT; }
    if(!strcmp(sql,"COMMIT")) { return COMMIT; }
    assert(!strcmp(sql,"ROLLBACK"));return ROLLBACK;
}
static vireo_result_t prepare(vireo_mysql_thread_t *t,vireo_mysql_connection_t *c,
    const char *sql,size_t n,const vireo_mysql_statement_limits_t *limits,vireo_mysql_statement_t **out,vireo_mysql_error_t *e)
{
    assert(t==thread && c==&connection && !*out && !m.statements);
    enum operation op=identify(sql,n);++m.prepared[op];*e=(vireo_mysql_error_t){0};
    assert(limits->max_parameters==6 && !limits->max_columns && limits->max_parameter_bytes==655 && limits->max_cell_bytes==1);
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
    if(op==AUDIT) { assert(n==6 && m.executed[BEGIN]); span(p,input.request_id,16);number(p+1,input.action);number(p+2,input.status);number(p+3,input.latency_us);
        const char *detail=input.origin==1?"source=reactor":"source=worker";
        span(p+4,detail,strlen(detail));number(p+5,input.occurred_at_ms); }
    else { assert(n==0 && !p); }
    if(op==m.execute_fail) { out->execution_started=!m.not_started;e->stage=VIREO_MYSQL_STAGE_STATEMENT_EXECUTE;e->mysql_code=m.mysql_code;return VIREO_RESULT_DATABASE; }
    if(op==AUDIT) { out->affected_rows=1;out->insert_id=33; }
    if(op==m.bad_shape) {
        if(m.shape==0) { out->has_result=true; }
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
    (void)t;(void)s;(void)out;(void)e;assert(0);return VIREO_RESULT_INTERNAL;
}
static vireo_result_t column(vireo_mysql_thread_t *t,const vireo_mysql_statement_t *s,size_t i,vireo_mysql_cell_view_t *out)
{ (void)t;(void)s;(void)i;(void)out;assert(0);return VIREO_RESULT_INTERNAL; }
static const vireo_mysql_user_repository_ops_t ops={allocate,release_memory,acquire,borrow,release,prepare,execute,close_statement,fetch,column};
static void start(void)
{
    assert(!repo && !m.blocks && !m.statements);memset(&m,0,sizeof m);m.mysql_code=1062;
    input=(vireo_mysql_auth_failure_input_t){.request_id={1},.occurred_at_ms=1234,.latency_us=97,.action=2,.status=1104,.origin=2};
    CHECK(vireo_mysql_user_repository_create_with_ops(thread,&pool,&policy,&repo,&error,&ops),VIREO_OK);++scenarios;
}
static void stop(void)
{
    m.close_fail=NONE;m.release_keep=false;m.release_consumed=false;
    CHECK(vireo_mysql_user_repository_destroy(&repo,NULL),VIREO_OK);assert(!repo && !m.blocks && !m.statements);
}
static void run(vireo_result_t want)
{ CHECK(vireo_mysql_user_repository_append_auth_failure(repo,&input,&report,&error),want); }
int main(void)
{
    struct sigaction sa={0};sa.sa_handler=SIG_IGN;assert(!sigemptyset(&sa.sa_mask) && !sigaction(SIGPIPE,&sa,NULL));
    vireo_mysql_runtime_t *runtime=NULL;CHECK(vireo_mysql_runtime_create(&runtime,NULL),VIREO_OK);CHECK(vireo_mysql_thread_attach(runtime,&thread,NULL),VIREO_OK);pool.runtime=runtime;
    for(unsigned action=1;action<=4;++action) for(unsigned origin=1;origin<=2;++origin) {
        start();input.action=(uint16_t)action;input.origin=(uint8_t)origin;input.occurred_at_ms=UINT64_MAX;input.latency_us=UINT64_MAX;
        run(VIREO_OK);assert(report.commit==VIREO_MYSQL_AUTH_FAILURE_COMMITTED && report.audit_id==33 && m.disposition==VIREO_MYSQL_POOL_RECYCLE && !report.cleanup_pending);stop();
    }
    for(unsigned i=0;i<5;++i) {
        start();if(i==0) memset(input.request_id,0,16);else if(i==1) input.action=0;else if(i==2) input.status=0;else if(i==3) input.origin=3;else input.action=5;
        run(VIREO_RESULT_INVALID_ARGUMENT);assert(!m.acquired);stop();
    }
    for(enum operation op=BEGIN;op<=COMMIT;op=(enum operation)(op+1)) for(unsigned kind=0;kind<3;++kind) {
        start();if(kind==0) m.prepare_fail=op;else if(kind==1) m.execute_fail=op;else m.close_fail=op;
        run(VIREO_RESULT_DATABASE);
        if(op==COMMIT && kind==2) assert(report.commit==VIREO_MYSQL_AUTH_FAILURE_COMMITTED && report.audit_id==33);
        else if(op==COMMIT && kind==1) assert(report.commit==VIREO_MYSQL_AUTH_FAILURE_UNKNOWN && !m.executed[ROLLBACK] && m.disposition==VIREO_MYSQL_POOL_DISCARD);
        else assert(report.commit==VIREO_MYSQL_AUTH_FAILURE_NOT_COMMITTED && !report.audit_id);
        stop();
    }
    for(enum operation op=BEGIN;op<=COMMIT;op=(enum operation)(op+1)) {
        start();m.close_fail=op;m.keep_statement=true;run(VIREO_RESULT_BUSY);assert(report.cleanup_pending && !m.released);
        size_t acquired=m.acquired;run(VIREO_RESULT_BUSY);assert(m.acquired==acquired);stop();
    }
    start();m.execute_fail=COMMIT;m.not_started=true;run(VIREO_RESULT_DATABASE);assert(report.commit==VIREO_MYSQL_AUTH_FAILURE_NOT_COMMITTED && m.executed[ROLLBACK]);stop();
    start();m.release_keep=true;run(VIREO_RESULT_INTERNAL);assert(report.commit==VIREO_MYSQL_AUTH_FAILURE_COMMITTED && report.cleanup_pending);stop();
    start();m.release_consumed=true;run(VIREO_RESULT_DATABASE);assert(report.commit==VIREO_MYSQL_AUTH_FAILURE_COMMITTED && !report.cleanup_pending);stop();
    start();m.acquire_partial=true;m.release_keep=true;run(VIREO_RESULT_INTERNAL);assert(report.cleanup_pending && !m.executed[BEGIN]);stop();
    start();m.acquire_empty=true;run(VIREO_RESULT_BUSY);assert(!m.executed[BEGIN] && !m.released);stop();
    start();m.borrow_fail=true;run(VIREO_RESULT_INTERNAL);assert(!m.executed[BEGIN] && m.disposition==VIREO_MYSQL_POOL_DISCARD);stop();
    for(unsigned shape=0;shape<3;++shape) { start();m.bad_shape=AUDIT;m.shape=shape;run(VIREO_RESULT_DATABASE);assert(report.commit==VIREO_MYSQL_AUTH_FAILURE_NOT_COMMITTED && m.executed[ROLLBACK]);stop(); }
    CHECK(vireo_mysql_thread_detach(&thread),VIREO_OK);CHECK(vireo_mysql_runtime_destroy(&runtime),VIREO_OK);
    printf("PASS %zu failure-audit transaction scenarios\n",scenarios);return 0;
}
