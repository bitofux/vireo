#define _POSIX_C_SOURCE 200809L
#include "mysql_user_repository_internal.h"
#include "mysql_pool_internal.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(call,want) do { errno=EDOM; vireo_result_t got_=(call); if(got_!=(want)) { fprintf(stderr,"line %d got %d want %d\n",__LINE__,(int)got_,(int)(want)); abort(); } assert(errno==EDOM); } while(0)
enum operation { NONE, BEGIN, USER, ROOT, AUDIT, COMMIT, ROLLBACK, OP_COUNT };
struct model_statement { enum operation op; };
static struct {
    size_t blocks, statements, acquired, released, prepared[OP_COUNT], executed[OP_COUNT];
    enum operation prepare_fail, execute_fail, close_fail, bad_shape;
    bool allocation_fail, not_started, keep_statement, acquire_partial, release_keep, release_consumed;
    bool borrow_fail, acquire_empty;
    unsigned int mysql_code;
    unsigned int shape;
    vireo_mysql_pool_disposition_t disposition;
} m;
static const char phc[]="$argon2id$v=19$m=65536,t=3,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
static vireo_password_policy_t policy=VIREO_PASSWORD_POLICY_DEFAULT;
static vireo_mysql_thread_t *thread;
static vireo_mysql_pool_t pool;
static vireo_mysql_connection_t connection;
static vireo_mysql_user_repository_t *repo;
static vireo_mysql_registration_input_t input;
static vireo_mysql_registration_report_t report;
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
    if(!strncmp(sql,"INSERT INTO users(",18)) { return USER; }
    if(!strncmp(sql,"INSERT INTO file_nodes(",23)) { return ROOT; }
    if(!strncmp(sql,"INSERT INTO operation_audits(",29)) { return AUDIT; }
    if(!strcmp(sql,"COMMIT")) { return COMMIT; }
    assert(!strcmp(sql,"ROLLBACK")); return ROLLBACK;
}
static vireo_result_t prepare(vireo_mysql_thread_t *t,vireo_mysql_connection_t *c,
    const char *sql,size_t n,const vireo_mysql_statement_limits_t *limits,
    vireo_mysql_statement_t **out,vireo_mysql_error_t *e)
{
    assert(t==thread && c==&connection && !*out && m.statements==0);
    assert(limits->max_parameters==6 && limits->max_columns==0 && limits->max_parameter_bytes>=639);
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
    if(op==USER) {
        assert(n==5); span(p,VIREO_MYSQL_PARAMETER_TEXT,input.username,input.username_length);
        span(p+1,VIREO_MYSQL_PARAMETER_BYTES,input.username_key,input.username_key_length);
        span(p+2,VIREO_MYSQL_PARAMETER_BYTES,input.password_hash,input.password_hash_length);
        number(p+3,input.occurred_at_ms); number(p+4,input.occurred_at_ms);
    } else if(op==ROOT) { assert(n==3); number(p,11); number(p+1,input.occurred_at_ms); number(p+2,input.occurred_at_ms); }
    else if(op==AUDIT) { assert(n==5); span(p,VIREO_MYSQL_PARAMETER_BYTES,input.request_id,16); number(p+1,11); number(p+2,11); number(p+3,input.latency_us); number(p+4,input.occurred_at_ms); }
    else { assert(n==0 && !p); }
    if(op==m.execute_fail) {
        out->execution_started=!m.not_started; e->stage=VIREO_MYSQL_STAGE_STATEMENT_EXECUTE;
        e->mysql_code=m.mysql_code; memcpy(e->sqlstate,"HY000",6); return VIREO_RESULT_DATABASE;
    }
    if(op==USER || op==ROOT || op==AUDIT) {
        out->affected_rows=1; out->insert_id=op==USER ? 11 : (op==ROOT ? 22 : 33);
    }
    if(op==m.bad_shape) {
        if(m.shape==0) { out->has_result=true; }
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
static const vireo_mysql_user_repository_ops_t ops={allocate,release_memory,acquire,borrow,release,prepare,execute,close_statement,vireo_mysql_statement_fetch,vireo_mysql_statement_column};
static void start(void)
{
    assert(!repo && !m.blocks && !m.statements); memset(&m,0,sizeof(m)); m.mysql_code=1062;
    input=(vireo_mysql_registration_input_t){.username="alice",.username_length=5,
        .username_key="alice",.username_key_length=5,.password_hash=phc,.password_hash_length=sizeof(phc)-1,
        .request_id={1},.occurred_at_ms=1234,.latency_us=97};
    CHECK(vireo_mysql_user_repository_create_with_ops(thread,&pool,&policy,&repo,&error,&ops),VIREO_OK);
    assert(repo && m.blocks==1 && !m.acquired); ++scenarios;
}
static void stop(void)
{
    m.close_fail=NONE; m.release_keep=false; m.release_consumed=false;
    CHECK(vireo_mysql_user_repository_destroy(&repo,&error),VIREO_OK);
    assert(!repo && !m.blocks && !m.statements);
}
static void run(vireo_result_t result)
{ memset(&report,0xa5,sizeof(report)); memset(&error,0xa5,sizeof(error)); CHECK(vireo_mysql_user_repository_register(repo,&input,0,&report,&error),result); }
static void no_ids(void)
{ assert(!report.user_id && !report.root_node_id && !report.audit_id); }
static void committed(void)
{ assert(report.commit==VIREO_MYSQL_REGISTRATION_COMMITTED && report.user_id==11 && report.root_node_id==22 && report.audit_id==33 && !report.rollback_confirmed); }
static void *wrong_thread(void *unused)
{
    (void)unused; vireo_mysql_registration_report_t out;
    CHECK(vireo_mysql_user_repository_register(repo,&input,0,&out,NULL),VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_mysql_user_repository_destroy(&repo,NULL),VIREO_RESULT_INVALID_ARGUMENT); assert(repo); return NULL;
}
int main(void)
{
    struct sigaction sa={0}; sa.sa_handler=SIG_IGN; assert(!sigemptyset(&sa.sa_mask) && !sigaction(SIGPIPE,&sa,NULL));
    vireo_mysql_runtime_t *runtime=NULL; CHECK(vireo_mysql_runtime_create(&runtime,NULL),VIREO_OK);
    CHECK(vireo_mysql_thread_attach(runtime,&thread,NULL),VIREO_OK); pool.runtime=runtime;
    start(); run(VIREO_OK); committed(); assert(m.released==1 && m.disposition==VIREO_MYSQL_POOL_RECYCLE && error.stage==0);
    pthread_t other; assert(!pthread_create(&other,NULL,wrong_thread,NULL) && !pthread_join(other,NULL)); stop();
    /* 边界拒绝必须在acquire之前发生；指针/长度不是C字符串。 */
    for(unsigned int i=0;i<12;++i) {
        start(); vireo_result_t want=VIREO_RESULT_RANGE;
        switch(i) {
        case 0:input.username=NULL;want=VIREO_RESULT_INVALID_ARGUMENT;break;
        case 1:input.username_length=0;break;
        case 2:input.username_length=257;break;
        case 3:input.username_key_length=0;break;
        case 4:input.username_key_length=257;break;
        case 5:input.password_hash_length=0;break;
        case 6:input.password_hash_length=128;break;
        case 7:memset(input.request_id,0,16);want=VIREO_RESULT_INVALID_ARGUMENT;break;
        case 8:input.password_hash="bad";input.password_hash_length=3;want=VIREO_RESULT_PROTOCOL;break;
        case 9:input.username_key=NULL;want=VIREO_RESULT_INVALID_ARGUMENT;break;
        case 10:input.password_hash=NULL;want=VIREO_RESULT_INVALID_ARGUMENT;break;
        default:input.password_hash="$argon2id$v=19$m=8,t=1,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";input.password_hash_length=strlen(input.password_hash);break;
        }
        run(want); assert(m.acquired==0 && report.commit==0 && error.stage==VIREO_MYSQL_USER_REPOSITORY_STAGE_VALIDATE); no_ids(); stop();
    }
    start(); CHECK(vireo_mysql_user_repository_register(repo,&input,60001,&report,NULL),VIREO_RESULT_RANGE); assert(!m.acquired); stop();
    start(); char name[256],key[256]; memset(name,'a',sizeof(name)); memset(key,0,sizeof(key));
    input.username=name;input.username_length=256;input.username_key=key;input.username_key_length=256;input.request_id[0]=0;input.request_id[15]=1;
    CHECK(vireo_mysql_user_repository_register(repo,&input,60000,&report,NULL),VIREO_OK); committed(); stop();
    for(enum operation op=BEGIN;op<=COMMIT;op=(enum operation)(op+1)) {
        start(); m.prepare_fail=op; run(VIREO_RESULT_DATABASE); no_ids();
        assert(report.commit==0 && !report.cleanup_pending && !m.executed[COMMIT]);
        assert(report.rollback_confirmed==(op!=BEGIN) && !report.conflict); stop();
        start(); m.execute_fail=op; run(VIREO_RESULT_DATABASE); no_ids();
        if(op==COMMIT) { assert(report.commit==VIREO_MYSQL_REGISTRATION_UNKNOWN && !m.executed[ROLLBACK] && m.disposition==VIREO_MYSQL_POOL_DISCARD); }
        else { assert(report.commit==0 && report.rollback_confirmed && !m.executed[COMMIT]); }
        if(op==USER) { assert(report.conflict==VIREO_MYSQL_REGISTRATION_USERNAME_CONFLICT); }
        if(op==AUDIT) { assert(report.conflict==VIREO_MYSQL_REGISTRATION_REQUEST_CONFLICT); }
        stop();
        start(); m.close_fail=op; run(VIREO_RESULT_DATABASE);
        assert(error.cleanup_result==VIREO_RESULT_DATABASE && !report.cleanup_pending);
        if(op==COMMIT) { committed(); } else { no_ids(); assert(report.rollback_confirmed); }
        stop();
        start(); m.close_fail=op; m.keep_statement=true; run(VIREO_RESULT_BUSY);
        assert(report.cleanup_pending && !m.released); if(op==COMMIT) { committed(); } else { no_ids(); }
        size_t calls=m.acquired; run(VIREO_RESULT_BUSY); assert(report.cleanup_pending && calls==m.acquired);
        vireo_mysql_login_report_t login;
        CHECK(vireo_mysql_user_repository_login(repo,NULL,0,&login,NULL),VIREO_RESULT_BUSY);
        assert(login.cleanup_pending && calls==m.acquired); stop();
    }
    start(); m.execute_fail=COMMIT;m.not_started=true;run(VIREO_RESULT_DATABASE);
    assert(report.commit==0 && report.rollback_confirmed); no_ids(); stop();
    for(enum operation op=USER;op<=AUDIT;op=(enum operation)(op+1)) {
        for(unsigned int shape=0;shape<3;++shape) {
            start();m.bad_shape=op;m.shape=shape;run(VIREO_RESULT_DATABASE);no_ids();assert(report.rollback_confirmed && !report.conflict && !m.executed[COMMIT]);stop();
        }
    }
    start();m.bad_shape=COMMIT;run(VIREO_RESULT_DATABASE);assert(report.commit==VIREO_MYSQL_REGISTRATION_UNKNOWN && !m.executed[ROLLBACK]);no_ids();stop();
    start();m.bad_shape=BEGIN;run(VIREO_RESULT_DATABASE);assert(report.rollback_confirmed && !m.executed[USER]);no_ids();stop();
    start();m.prepare_fail=ROOT;m.close_fail=ROLLBACK;run(VIREO_RESULT_DATABASE);
    assert(report.rollback_confirmed && error.stage==VIREO_MYSQL_USER_REPOSITORY_STAGE_ROOT && error.cleanup_stage==VIREO_MYSQL_USER_REPOSITORY_STAGE_STATEMENT_CLOSE);stop();
    start();m.prepare_fail=ROOT;m.execute_fail=ROLLBACK;m.close_fail=ROLLBACK;m.release_keep=true;run(VIREO_RESULT_DATABASE);
    assert(error.stage==VIREO_MYSQL_USER_REPOSITORY_STAGE_ROOT && error.cleanup_stage==VIREO_MYSQL_USER_REPOSITORY_STAGE_ROLLBACK && report.cleanup_pending && !report.rollback_confirmed);no_ids();stop();
    start();m.acquire_partial=true;m.release_keep=true;run(VIREO_RESULT_INTERNAL);assert(report.cleanup_pending && m.released==1 && error.stage==VIREO_MYSQL_USER_REPOSITORY_STAGE_ACQUIRE);stop();
    start();m.acquire_partial=true;run(VIREO_RESULT_INTERNAL);assert(!report.cleanup_pending && m.released==1 && !m.prepared[BEGIN]);stop();
    start();m.acquire_empty=true;run(VIREO_RESULT_BUSY);assert(!m.released && !m.statements);stop();
    start();m.borrow_fail=true;run(VIREO_RESULT_INTERNAL);assert(m.released==1 && m.disposition==VIREO_MYSQL_POOL_DISCARD && !m.prepared[BEGIN]);stop();
    start();m.release_keep=true;run(VIREO_RESULT_INTERNAL);committed();assert(report.cleanup_pending);
    CHECK(vireo_mysql_user_repository_destroy(&repo,&error),VIREO_RESULT_INTERNAL);assert(repo);stop();
    start();m.release_consumed=true;run(VIREO_RESULT_DATABASE);committed();assert(!report.cleanup_pending);stop();
    start();policy.create_iterations=4;run(VIREO_OK);committed();policy.create_iterations=3;
    CHECK(vireo_mysql_user_repository_create(thread,&pool,&policy,&repo,&error),VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_mysql_user_repository_register(repo,NULL,0,&report,&error),VIREO_RESULT_INVALID_ARGUMENT);
    size_t prior_calls=m.acquired;
    CHECK(vireo_mysql_user_repository_register(repo,&input,0,NULL,&error),VIREO_RESULT_INVALID_ARGUMENT);assert(prior_calls==m.acquired);stop();
    start();m.close_fail=ROOT;m.keep_statement=true;run(VIREO_RESULT_BUSY);m.keep_statement=false;
    CHECK(vireo_mysql_user_repository_destroy(&repo,&error),VIREO_RESULT_DATABASE);assert(!repo && !m.blocks && !m.statements && !m.executed[COMMIT]);
    m.allocation_fail=true; CHECK(vireo_mysql_user_repository_create_with_ops(thread,&pool,&policy,&repo,&error,&ops),VIREO_RESULT_NO_MEMORY);assert(!repo);m.allocation_fail=false;
    vireo_password_policy_t bad=policy;bad.max_password_bytes=0;
    CHECK(vireo_mysql_user_repository_create(thread,&pool,&bad,&repo,&error),VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_mysql_user_repository_create(NULL,&pool,&policy,&repo,&error),VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_mysql_user_repository_create(thread,NULL,&policy,&repo,&error),VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_mysql_user_repository_destroy(NULL,NULL),VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_mysql_user_repository_destroy(&repo,NULL),VIREO_OK);
    CHECK(vireo_mysql_thread_detach(&thread),VIREO_OK);CHECK(vireo_mysql_runtime_destroy(&runtime),VIREO_OK);
    printf("PASS %zu repository resource-boundary scenarios: transaction facts, input, exact parameters, conflict, cleanup ownership, no replay, errno/thread\n",scenarios);
    return 0;
}
