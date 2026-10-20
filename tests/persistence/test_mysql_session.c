#define _POSIX_C_SOURCE 200809L
#include "mysql_user_repository_internal.h"
#include "mysql_pool_internal.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(call,want) do { errno=EDOM;vireo_result_t got_=(call);if(got_!=(want)) { fprintf(stderr,"line %d got %d want %d\n",__LINE__,(int)got_,(int)(want));abort(); }assert(errno==EDOM); } while(0)
static struct {
    bool acquire_empty,acquire_partial,borrow_fail,prepare_fail,execute_fail,fetch_fail,second_fetch_fail;
    bool column_fail,close_fail,close_keep,release_keep,release_consumed,absent,extra,no_result;
    bool nulls[8];char cells[8][32];unsigned int fetches;
    size_t blocks,statements,acquires,releases,executes;
    vireo_mysql_pool_disposition_t disposition;
} m;
static vireo_mysql_thread_t *thread;
static vireo_mysql_pool_t pool;
static vireo_mysql_connection_t connection;
static vireo_mysql_user_repository_t *repo;
static vireo_password_policy_t policy=VIREO_PASSWORD_POLICY_DEFAULT;
static vireo_session_token_digest_t digest;
static uint64_t now;
static size_t scenarios;
static vireo_mysql_session_identity_t identity;
static vireo_mysql_session_report_t report;
static vireo_mysql_user_repository_error_t error;
static void *allocate(size_t n) { void *p=malloc(n);assert(p);++m.blocks;return p; }
static void release_memory(void *p) { assert(p && m.blocks==1);--m.blocks;free(p); }
static vireo_result_t acquire(vireo_mysql_thread_t *t,vireo_mysql_pool_t *p,uint32_t wait,
    vireo_mysql_lease_t *l,vireo_mysql_pool_acquisition_t *out,vireo_mysql_pool_error_t *e)
{
    assert(t==thread && p==&pool && wait<=60000 && !l->owner);++m.acquires;
    *out=(vireo_mysql_pool_acquisition_t){0};*e=(vireo_mysql_pool_error_t){0};
    if(m.acquire_empty) { return VIREO_RESULT_BUSY; }
    *l=(vireo_mysql_lease_t){p,0,1};out->acquired=true;
    if(m.acquire_partial) { e->stage=VIREO_MYSQL_POOL_STAGE_UNLOCK;return VIREO_RESULT_INTERNAL; }return VIREO_OK;
}
static vireo_result_t borrow(vireo_mysql_thread_t *t,vireo_mysql_pool_t *p,const vireo_mysql_lease_t *l,vireo_mysql_connection_t **out)
{ assert(t==thread && p==&pool && l->owner==p);if(m.borrow_fail) { return VIREO_RESULT_INTERNAL; }*out=&connection;return VIREO_OK; }
static vireo_result_t release(vireo_mysql_thread_t *t,vireo_mysql_pool_t *p,vireo_mysql_lease_t *l,
    vireo_mysql_pool_disposition_t d,vireo_mysql_pool_release_t *out,vireo_mysql_pool_error_t *e)
{
    assert(t==thread && p==&pool && l->owner==p && !m.statements);++m.releases;m.disposition=d;
    *out=(vireo_mysql_pool_release_t){0};*e=(vireo_mysql_pool_error_t){0};
    if(m.release_keep) { e->stage=VIREO_MYSQL_POOL_STAGE_LOCK;return VIREO_RESULT_INTERNAL; }
    *l=(vireo_mysql_lease_t){0};out->released=true;
    if(m.release_consumed) { e->stage=VIREO_MYSQL_POOL_STAGE_RESET;return VIREO_RESULT_DATABASE; }return VIREO_OK;
}
static vireo_result_t prepare(vireo_mysql_thread_t *t,vireo_mysql_connection_t *c,const char *sql,size_t n,
    const vireo_mysql_statement_limits_t *limits,vireo_mysql_statement_t **out,vireo_mysql_error_t *e)
{
    assert(t==thread && c==&connection && !*out && !m.statements);
    assert(strlen(sql)==n && !strcmp(sql,"SELECT s.id,s.user_id,s.status,s.issued_at_ms,s.expires_at_ms,s.revoked_at_ms,s.last_seen_at_ms,u.status FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_digest=?"));
    assert(limits->max_parameters==1 && limits->max_columns==8 && limits->max_parameter_bytes==32 && limits->max_cell_bytes==20 && limits->max_memory_bytes==32768);
    *e=(vireo_mysql_error_t){0};if(m.prepare_fail) { e->stage=VIREO_MYSQL_STAGE_STATEMENT_PREPARE;return VIREO_RESULT_DATABASE; }
    *out=malloc(1);assert(*out);++m.statements;m.fetches=0;return VIREO_OK;
}
static vireo_result_t execute(vireo_mysql_thread_t *t,vireo_mysql_statement_t *s,const vireo_mysql_parameter_t *p,
    size_t n,vireo_mysql_execution_t *out,vireo_mysql_error_t *e)
{
    assert(t==thread && s && n==1 && p->kind==VIREO_MYSQL_PARAMETER_BYTES);
    assert(p->value.span.length==32 && !memcmp(p->value.span.data,digest.bytes,32));++m.executes;
    *e=(vireo_mysql_error_t){0};*out=(vireo_mysql_execution_t){.execution_started=true,.has_result=!m.no_result};
    if(m.execute_fail) { e->stage=VIREO_MYSQL_STAGE_STATEMENT_EXECUTE;e->mysql_code=2013;return VIREO_RESULT_DATABASE; }return VIREO_OK;
}
static vireo_result_t fetch(vireo_mysql_thread_t *t,vireo_mysql_statement_t *s,vireo_mysql_fetch_outcome_t *out,vireo_mysql_error_t *e)
{
    assert(t==thread && s);++m.fetches;*e=(vireo_mysql_error_t){0};
    if(m.fetch_fail || (m.second_fetch_fail && m.fetches==2)) { e->stage=VIREO_MYSQL_STAGE_STATEMENT_FETCH;return VIREO_RESULT_DATABASE; }
    *out=m.absent || (m.fetches>1 && !m.extra) ? VIREO_MYSQL_FETCH_DONE : VIREO_MYSQL_FETCH_ROW;
    if(m.fetches>1) { memset(m.cells,'x',sizeof(m.cells)); }return VIREO_OK;
}
static vireo_result_t column(vireo_mysql_thread_t *t,const vireo_mysql_statement_t *s,size_t i,vireo_mysql_cell_view_t *out)
{
    assert(t==thread && s && i<8);if(m.column_fail) { return VIREO_RESULT_DATABASE; }
    *out=(vireo_mysql_cell_view_t){.data=(const unsigned char *)m.cells[i],.length=strlen(m.cells[i]),.is_null=m.nulls[i]};return VIREO_OK;
}
static vireo_result_t close_statement(vireo_mysql_thread_t *t,vireo_mysql_statement_t **s,vireo_mysql_error_t *e)
{
    assert(t==thread && *s && m.statements==1);*e=(vireo_mysql_error_t){0};
    if(!m.close_keep) { free(*s);*s=NULL;--m.statements; }
    if(m.close_fail || m.close_keep) { e->stage=VIREO_MYSQL_STAGE_STATEMENT_CLOSE;return m.close_keep ? VIREO_RESULT_BUSY : VIREO_RESULT_DATABASE; }return VIREO_OK;
}
static const vireo_mysql_user_repository_ops_t ops={allocate,release_memory,acquire,borrow,release,prepare,execute,close_statement,fetch,column};
static void zero(const void *p,size_t n) { const unsigned char *bytes=p;for(size_t i=0;i<n;++i) { assert(bytes[i]==0); } }
static void cell(size_t i,const char *s) { assert(i<8 && strlen(s)<sizeof(m.cells[i]));memset(m.cells[i],0,sizeof(m.cells[i]));memcpy(m.cells[i],s,strlen(s)); }
static void start(void)
{
    assert(!repo && !m.blocks && !m.statements);memset(&m,0,sizeof(m));memset(&digest,0,sizeof(digest));now=150;
    const char *values[]={"7","42","1","100","200","0","100","1"};
    for(size_t i=0;i<8;++i) { cell(i,values[i]); }m.nulls[5]=true;
    CHECK(vireo_mysql_user_repository_create_with_ops(thread,&pool,&policy,&repo,NULL,&ops),VIREO_OK);++scenarios;
}
static void stop(void)
{
    m.close_fail=false;m.close_keep=false;m.release_keep=false;m.release_consumed=false;
    CHECK(vireo_mysql_user_repository_destroy(&repo,NULL),VIREO_OK);assert(!repo && !m.blocks && !m.statements);
}
static void run(vireo_result_t want,vireo_mysql_session_issue_t issue)
{
    memset(&identity,0xa5,sizeof(identity));memset(&report,0xa5,sizeof(report));memset(&error,0xa5,sizeof(error));
    CHECK(vireo_mysql_user_repository_find_session(repo,&digest,now,0,&identity,&report,&error),want);
    assert(report.valid==(want==VIREO_OK) && report.issue==issue);
    if(want!=VIREO_OK) { zero(&identity,sizeof(identity)); }
}
static void busy_all(void)
{
    size_t count=m.acquires;run(VIREO_RESULT_BUSY,VIREO_MYSQL_SESSION_ISSUE_NONE);assert(report.cleanup_pending);
    vireo_mysql_registration_report_t registration;vireo_mysql_login_report_t login;
    vireo_mysql_user_credentials_t credentials;vireo_mysql_credentials_report_t found;
    CHECK(vireo_mysql_user_repository_register(repo,NULL,0,&registration,NULL),VIREO_RESULT_BUSY);
    CHECK(vireo_mysql_user_repository_login(repo,NULL,0,&login,NULL),VIREO_RESULT_BUSY);
    CHECK(vireo_mysql_user_repository_find_credentials(repo,NULL,0,0,&credentials,&found,NULL),VIREO_RESULT_BUSY);
    assert(registration.cleanup_pending && login.cleanup_pending && found.cleanup_pending && count==m.acquires);zero(&credentials,sizeof(credentials));
}
static void *wrong_thread(void *unused)
{
    (void)unused;vireo_mysql_session_identity_t out;vireo_mysql_session_report_t state;
    CHECK(vireo_mysql_user_repository_find_session(repo,&digest,now,0,&out,&state,NULL),VIREO_RESULT_INVALID_ARGUMENT);zero(&out,sizeof(out));return NULL;
}
int main(void)
{
    struct sigaction sa={0};sa.sa_handler=SIG_IGN;assert(!sigemptyset(&sa.sa_mask) && !sigaction(SIGPIPE,&sa,NULL));
    vireo_mysql_runtime_t *runtime=NULL;CHECK(vireo_mysql_runtime_create(&runtime,NULL),VIREO_OK);
    CHECK(vireo_mysql_thread_attach(runtime,&thread,NULL),VIREO_OK);pool.runtime=runtime;
    start();run(VIREO_OK,VIREO_MYSQL_SESSION_ISSUE_NONE);assert(identity.session_id==7 && identity.user_id==42 && identity.issued_at_ms==100 && identity.expires_at_ms==200 && !report.cleanup_pending && m.disposition==VIREO_MYSQL_POOL_RECYCLE);
    pthread_t other;assert(!pthread_create(&other,NULL,wrong_thread,NULL) && !pthread_join(other,NULL));stop();
    start();digest.bytes[0]=1;digest.bytes[31]=255;run(VIREO_OK,VIREO_MYSQL_SESSION_ISSUE_NONE);stop();
    start();CHECK(vireo_mysql_user_repository_find_session(repo,NULL,now,0,&identity,&report,NULL),VIREO_RESULT_INVALID_ARGUMENT);zero(&identity,sizeof(identity));
    CHECK(vireo_mysql_user_repository_find_session(repo,&digest,now,60001,&identity,&report,NULL),VIREO_RESULT_RANGE);
    CHECK(vireo_mysql_user_repository_find_session(repo,&digest,now,0,NULL,&report,NULL),VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_mysql_user_repository_find_session(repo,&digest,now,0,&identity,NULL,NULL),VIREO_RESULT_INVALID_ARGUMENT);assert(!m.acquires);stop();
    for(unsigned int i=0;i<4;++i) {
        start();now=i==0 ? 99 : (i==1 ? 100 : (i==2 ? 199 : 200));
        run(i==0 || i==3 ? VIREO_RESULT_NOT_FOUND : VIREO_OK,i==0 ? VIREO_MYSQL_SESSION_NOT_YET_VALID : (i==3 ? VIREO_MYSQL_SESSION_EXPIRED : VIREO_MYSQL_SESSION_ISSUE_NONE));stop();
    }
    start();cell(0,"18446744073709551615");cell(1,"18446744073709551615");cell(4,"18446744073709551615");now=UINT64_MAX-1;
    run(VIREO_OK,VIREO_MYSQL_SESSION_ISSUE_NONE);assert(identity.session_id==UINT64_MAX && identity.user_id==UINT64_MAX && identity.expires_at_ms==UINT64_MAX);stop();
    start();cell(3,"0");cell(6,"0");now=0;run(VIREO_OK,VIREO_MYSQL_SESSION_ISSUE_NONE);stop();
    start();now=UINT64_MAX;run(VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_SESSION_EXPIRED);stop();
    start();m.absent=true;run(VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_SESSION_NOT_FOUND);stop();
    start();cell(2,"2");m.nulls[5]=false;cell(5,"100");now=UINT64_MAX;cell(7,"2");run(VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_SESSION_REVOKED);stop();
    start();cell(7,"2");now=0;run(VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_SESSION_USER_DISABLED);stop();
    for(size_t i=0;i<8;++i) {
        if(i==5) { continue; }start();m.nulls[i]=true;run(VIREO_RESULT_DATABASE,VIREO_MYSQL_SESSION_ISSUE_NONE);stop();
    }
    for(unsigned int i=0;i<17;++i) {
        start();switch(i) {
        case 0:cell(0,"0");break;case 1:cell(1,"0");break;case 2:cell(0,"18446744073709551616");break;
        case 3:cell(1,"-1");break;case 4:cell(2,"3");break;case 5:cell(7,"0");break;case 6:cell(3,"");break;
        case 7:cell(4,"100");break;case 8:cell(4,"99");break;case 9:cell(6,"99");break;case 10:cell(6,"201");break;
        case 11:m.nulls[5]=false;break;case 12:cell(2,"2");break;
        case 13:cell(2,"2");m.nulls[5]=false;cell(5,"99");break;
        case 14:cell(4,"2x");break;case 15:cell(3,"+1");break;default:cell(2,"2");m.nulls[5]=false;cell(5,"");break;
        }run(VIREO_RESULT_DATABASE,VIREO_MYSQL_SESSION_ISSUE_NONE);assert(m.disposition==VIREO_MYSQL_POOL_DISCARD);stop();
    }
    for(unsigned int i=0;i<7;++i) {
        start();switch(i) { case 0:m.prepare_fail=true;break;case 1:m.execute_fail=true;break;case 2:m.fetch_fail=true;break;
        case 3:m.second_fetch_fail=true;break;case 4:m.column_fail=true;break;case 5:m.extra=true;break;default:m.no_result=true;break; }
        run(VIREO_RESULT_DATABASE,VIREO_MYSQL_SESSION_ISSUE_NONE);assert(error.stage==VIREO_MYSQL_USER_REPOSITORY_STAGE_SESSION_LOOKUP);stop();
    }
    start();m.close_fail=true;run(VIREO_RESULT_DATABASE,VIREO_MYSQL_SESSION_ISSUE_NONE);assert(!report.cleanup_pending && error.cleanup_stage==VIREO_MYSQL_USER_REPOSITORY_STAGE_STATEMENT_CLOSE);stop();
    start();m.close_keep=true;run(VIREO_RESULT_BUSY,VIREO_MYSQL_SESSION_ISSUE_NONE);assert(!m.releases);busy_all();stop();
    start();m.release_keep=true;run(VIREO_RESULT_INTERNAL,VIREO_MYSQL_SESSION_ISSUE_NONE);busy_all();CHECK(vireo_mysql_user_repository_destroy(&repo,NULL),VIREO_RESULT_INTERNAL);assert(repo);stop();
    start();m.release_consumed=true;run(VIREO_RESULT_DATABASE,VIREO_MYSQL_SESSION_ISSUE_NONE);assert(!report.cleanup_pending);stop();
    start();m.absent=true;m.close_fail=true;run(VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_SESSION_NOT_FOUND);assert(error.cleanup_result==VIREO_RESULT_DATABASE && m.disposition==VIREO_MYSQL_POOL_DISCARD);stop();
    start();m.fetch_fail=true;m.close_fail=true;m.release_keep=true;run(VIREO_RESULT_DATABASE,VIREO_MYSQL_SESSION_ISSUE_NONE);
    assert(error.stage==VIREO_MYSQL_USER_REPOSITORY_STAGE_SESSION_LOOKUP && error.cleanup_stage==VIREO_MYSQL_USER_REPOSITORY_STAGE_STATEMENT_CLOSE);busy_all();stop();
    start();m.acquire_partial=true;m.release_keep=true;run(VIREO_RESULT_INTERNAL,VIREO_MYSQL_SESSION_ISSUE_NONE);assert(!m.executes);busy_all();stop();
    start();m.acquire_empty=true;run(VIREO_RESULT_BUSY,VIREO_MYSQL_SESSION_ISSUE_NONE);assert(!m.releases && !m.executes);stop();
    start();m.borrow_fail=true;run(VIREO_RESULT_INTERNAL,VIREO_MYSQL_SESSION_ISSUE_NONE);assert(m.disposition==VIREO_MYSQL_POOL_DISCARD && !m.executes);stop();
    /* 旧方法留下同一lease后，新查询同样先被门禁挡住，尚未进入SQL。 */
    for(unsigned int i=0;i<3;++i) {
        start();m.acquire_partial=true;m.release_keep=true;
        if(i==0) {
            static const char hash[]="$argon2id$v=19$m=65536,t=3,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
            vireo_mysql_registration_input_t in={.username="a",.username_length=1,.username_key="a",.username_key_length=1,.password_hash=hash,.password_hash_length=sizeof(hash)-1};in.request_id[0]=1;
            vireo_mysql_registration_report_t state;CHECK(vireo_mysql_user_repository_register(repo,&in,0,&state,NULL),VIREO_RESULT_INTERNAL);
        } else if(i==1) {
            static const char hash[]="$argon2id$v=19$m=65536,t=3,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
            vireo_mysql_login_input_t in={.user_id=42,.verified_password_hash=hash,.verified_password_hash_length=sizeof(hash)-1,.issued_at_ms=1,.expires_at_ms=2};in.request_id[0]=1;
            vireo_mysql_login_report_t state;CHECK(vireo_mysql_user_repository_login(repo,&in,0,&state,NULL),VIREO_RESULT_INTERNAL);
        } else {
            vireo_mysql_user_credentials_t out;vireo_mysql_credentials_report_t state;
            CHECK(vireo_mysql_user_repository_find_credentials(repo,"a",1,0,&out,&state,NULL),VIREO_RESULT_INTERNAL);
        }assert(!m.executes);busy_all();stop();
    }
    CHECK(vireo_mysql_thread_detach(&thread),VIREO_OK);CHECK(vireo_mysql_runtime_destroy(&runtime),VIREO_OK);
    printf("PASS %zu session resource-boundary scenarios: digest binding, expiry/issued/u64, invalid rows, EOF lifetime, four-method ownership, zero failure identity, errno/thread\n",scenarios);return 0;
}
