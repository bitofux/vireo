#define _POSIX_C_SOURCE 200809L
#include "mysql_user_repository_internal.h"
#include "mysql_pool_internal.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(call,want) do { errno=EDOM;vireo_result_t got_=(call);if(got_!=(want)) { fprintf(stderr,"line %d got %d want %d\n",__LINE__,(int)got_,(int)(want));abort(); }assert(errno==EDOM); } while(0)
static const char phc[]="$argon2id$v=19$m=65536,t=3,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
static const char historical[]="$argon2id$v=19$m=8,t=1,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
static const char costly[]="$argon2id$v=19$m=262145,t=3,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
static struct {
    bool acquire_empty, acquire_partial, borrow_fail, prepare_fail, execute_fail;
    bool fetch_fail, second_fetch_fail, column_fail, close_fail, close_keep, release_keep, release_consumed;
    bool absent, extra, no_result, disabled, old_phc, high_cost;
    unsigned int shape, fetches;
    size_t blocks, statements, acquires, releases, executes;
    char row_hash[128];
    vireo_mysql_pool_disposition_t disposition;
} m;
static vireo_mysql_thread_t *thread;
static vireo_mysql_pool_t pool;
static vireo_mysql_connection_t connection;
static vireo_mysql_user_repository_t *repo;
static vireo_password_policy_t policy=VIREO_PASSWORD_POLICY_DEFAULT;
static const void *key;
static size_t key_length,scenarios;
static vireo_mysql_user_credentials_t credentials;
static vireo_mysql_credentials_report_t report;
static vireo_mysql_user_repository_error_t error;
static void *allocate(size_t bytes) { void *p=malloc(bytes);assert(p);++m.blocks;return p; }
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
    assert(strlen(sql)==n && !strcmp(sql,"SELECT id,status,password_hash FROM users WHERE username_key=?"));
    assert(limits->max_parameters==1 && limits->max_columns==3 && limits->max_parameter_bytes==256 && limits->max_cell_bytes==127 && limits->max_memory_bytes==32768);
    *e=(vireo_mysql_error_t){0};if(m.prepare_fail) { e->stage=VIREO_MYSQL_STAGE_STATEMENT_PREPARE;return VIREO_RESULT_DATABASE; }
    *out=malloc(1);assert(*out);++m.statements;m.fetches=0;return VIREO_OK;
}
static vireo_result_t execute(vireo_mysql_thread_t *t,vireo_mysql_statement_t *s,
    const vireo_mysql_parameter_t *p,size_t n,vireo_mysql_execution_t *out,vireo_mysql_error_t *e)
{
    assert(t==thread && s && m.statements==1 && n==1 && p->kind==VIREO_MYSQL_PARAMETER_BYTES);
    assert(p->value.span.length==key_length && !memcmp(p->value.span.data,key,key_length));++m.executes;
    *e=(vireo_mysql_error_t){0};*out=(vireo_mysql_execution_t){.execution_started=true,.has_result=!m.no_result};
    if(m.execute_fail) { e->stage=VIREO_MYSQL_STAGE_STATEMENT_EXECUTE;e->mysql_code=2013;return VIREO_RESULT_DATABASE; }
    const char *hash=m.old_phc ? historical : (m.high_cost ? costly : phc);
    memset(m.row_hash,0,sizeof(m.row_hash));memcpy(m.row_hash,hash,strlen(hash));return VIREO_OK;
}
static vireo_result_t fetch(vireo_mysql_thread_t *t,vireo_mysql_statement_t *s,vireo_mysql_fetch_outcome_t *out,vireo_mysql_error_t *e)
{
    assert(t==thread && s);++m.fetches;*e=(vireo_mysql_error_t){0};
    if(m.fetch_fail || (m.second_fetch_fail && m.fetches==2)) { e->stage=VIREO_MYSQL_STAGE_STATEMENT_FETCH;return VIREO_RESULT_DATABASE; }
    *out=m.absent || (m.fetches>1 && !m.extra) ? VIREO_MYSQL_FETCH_DONE : VIREO_MYSQL_FETCH_ROW;
    /* 模拟下一fetch导致旧行视图失效，凭据必须此前已复制。 */
    if(m.fetches>1) { memset(m.row_hash,'x',sizeof(m.row_hash)); }return VIREO_OK;
}
static vireo_result_t column(vireo_mysql_thread_t *t,const vireo_mysql_statement_t *s,size_t i,vireo_mysql_cell_view_t *out)
{
    assert(t==thread && s && i<3);if(m.column_fail) { return VIREO_RESULT_DATABASE; }
    const char *data=i==0 ? "42" : (i==1 ? (m.disabled ? "2" : "1") : m.row_hash);size_t n=strlen(data);
    if(i==0) {
        switch(m.shape) {
        case 1:data="0";n=1;break;
        case 2:data="18446744073709551615";n=20;break;
        case 3:data="18446744073709551616";n=20;break;
        case 4:data="-1";n=2;break;
        case 5:data="1x";n=2;break;
        case 6:n=0;break;
        default:break;
        }
    }
    if(i==1 && m.shape==7) { data="3";n=1; }
    if(i==2 && m.shape==8) { data="bad";n=3; }
    if(i==2 && m.shape==9) { n=128; }
    if(i==2 && m.shape==10) { n=0; }
    *out=(vireo_mysql_cell_view_t){.data=(const unsigned char *)data,.length=n,.is_null=i==2 && m.shape==11};return VIREO_OK;
}
static vireo_result_t close_statement(vireo_mysql_thread_t *t,vireo_mysql_statement_t **s,vireo_mysql_error_t *e)
{
    assert(t==thread && *s && m.statements==1);*e=(vireo_mysql_error_t){0};
    if(!m.close_keep) { free(*s);*s=NULL;--m.statements; }
    if(m.close_fail || m.close_keep) { e->stage=VIREO_MYSQL_STAGE_STATEMENT_CLOSE;return m.close_keep ? VIREO_RESULT_BUSY : VIREO_RESULT_DATABASE; }return VIREO_OK;
}
static const vireo_mysql_user_repository_ops_t ops={allocate,release_memory,acquire,borrow,release,prepare,execute,close_statement,fetch,column};
static void zero(const void *p,size_t n) { const unsigned char *bytes=p;for(size_t i=0;i<n;++i) { assert(bytes[i]==0); } }
static void start(void)
{
    assert(!repo && !m.blocks && !m.statements);memset(&m,0,sizeof(m));key="alice";key_length=5;
    CHECK(vireo_mysql_user_repository_create_with_ops(thread,&pool,&policy,&repo,&error,&ops),VIREO_OK);++scenarios;
}
static void stop(void)
{
    m.close_fail=false;m.close_keep=false;m.release_keep=false;m.release_consumed=false;
    CHECK(vireo_mysql_user_repository_destroy(&repo,NULL),VIREO_OK);assert(!repo && !m.blocks && !m.statements);
    CHECK(vireo_mysql_user_credentials_clear(&credentials),VIREO_OK);zero(&credentials,sizeof(credentials));
}
static void run(vireo_result_t want)
{
    memset(&credentials,0xa5,sizeof(credentials));memset(&report,0xa5,sizeof(report));memset(&error,0xa5,sizeof(error));
    CHECK(vireo_mysql_user_repository_find_credentials(repo,key,key_length,0,&credentials,&report,&error),want);
    assert(report.found==(want==VIREO_OK));
    if(want!=VIREO_OK) { zero(&credentials,sizeof(credentials)); }
}
static void found(const char *hash)
{
    assert(credentials.user_id==(m.shape==2 ? UINT64_MAX : 42) && credentials.status==(m.disabled ? VIREO_MYSQL_USER_STATUS_DISABLED : VIREO_MYSQL_USER_STATUS_ACTIVE));
    assert(credentials.password_hash_length==strlen(hash) && !memcmp(credentials.password_hash,hash,strlen(hash)));
    zero(credentials.password_hash+strlen(hash),sizeof(credentials.password_hash)-strlen(hash));assert(!report.cleanup_pending);
}
static void busy_all(void)
{
    size_t prior=m.acquires;run(VIREO_RESULT_BUSY);assert(report.cleanup_pending && prior==m.acquires);
    vireo_mysql_registration_report_t registration;vireo_mysql_login_report_t login;
    CHECK(vireo_mysql_user_repository_register(repo,NULL,0,&registration,NULL),VIREO_RESULT_BUSY);
    CHECK(vireo_mysql_user_repository_login(repo,NULL,0,&login,NULL),VIREO_RESULT_BUSY);
    assert(registration.cleanup_pending && login.cleanup_pending && prior==m.acquires);
}
static void *wrong_thread(void *unused)
{
    (void)unused;vireo_mysql_user_credentials_t out;vireo_mysql_credentials_report_t state;
    CHECK(vireo_mysql_user_repository_find_credentials(repo,key,key_length,0,&out,&state,NULL),VIREO_RESULT_INVALID_ARGUMENT);zero(&out,sizeof(out));return NULL;
}
int main(void)
{
    struct sigaction sa={0};sa.sa_handler=SIG_IGN;assert(!sigemptyset(&sa.sa_mask) && !sigaction(SIGPIPE,&sa,NULL));
    vireo_mysql_runtime_t *runtime=NULL;CHECK(vireo_mysql_runtime_create(&runtime,NULL),VIREO_OK);
    CHECK(vireo_mysql_thread_attach(runtime,&thread,NULL),VIREO_OK);pool.runtime=runtime;
    start();run(VIREO_OK);found(phc);assert(m.disposition==VIREO_MYSQL_POOL_RECYCLE);
    pthread_t other;assert(!pthread_create(&other,NULL,wrong_thread,NULL) && !pthread_join(other,NULL));
    vireo_mysql_user_credentials_t copy=credentials;CHECK(vireo_mysql_user_credentials_clear(&credentials),VIREO_OK);zero(&credentials,sizeof(credentials));assert(copy.user_id==42);
    CHECK(vireo_mysql_user_credentials_clear(&copy),VIREO_OK);CHECK(vireo_mysql_user_credentials_clear(NULL),VIREO_RESULT_INVALID_ARGUMENT);stop();
    for(unsigned int i=0;i<3;++i) {
        start();if(i==0) { key=NULL; }else { key_length=i==1 ? 0 : 257; }
        run(i==0 ? VIREO_RESULT_INVALID_ARGUMENT : VIREO_RESULT_RANGE);assert(!m.acquires);stop();
    }
    start();CHECK(vireo_mysql_user_repository_find_credentials(repo,key,key_length,60001,&credentials,&report,NULL),VIREO_RESULT_RANGE);
    CHECK(vireo_mysql_user_repository_find_credentials(repo,key,key_length,0,NULL,&report,NULL),VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_mysql_user_repository_find_credentials(repo,key,key_length,0,&credentials,NULL,NULL),VIREO_RESULT_INVALID_ARGUMENT);assert(!m.acquires);stop();
    start();unsigned char binary[256]={0};binary[255]=1;key=binary;key_length=sizeof(binary);run(VIREO_OK);found(phc);stop();
    start();m.disabled=true;run(VIREO_OK);found(phc);stop();
    start();m.old_phc=true;run(VIREO_OK);found(historical);stop();
    start();m.high_cost=true;run(VIREO_RESULT_RANGE);assert(m.disposition==VIREO_MYSQL_POOL_DISCARD);stop();
    start();m.absent=true;run(VIREO_RESULT_NOT_FOUND);assert(m.disposition==VIREO_MYSQL_POOL_RECYCLE && !report.cleanup_pending);stop();
    for(unsigned int i=1;i<=11;++i) {
        start();m.shape=i;run(i==2 ? VIREO_OK : (i==8 ? VIREO_RESULT_PROTOCOL : VIREO_RESULT_DATABASE));
        if(i==2) { found(phc); }else { assert(m.disposition==VIREO_MYSQL_POOL_DISCARD && error.stage==VIREO_MYSQL_USER_REPOSITORY_STAGE_CREDENTIALS); }stop();
    }
    for(unsigned int i=0;i<7;++i) {
        start();switch(i) {
        case 0:m.prepare_fail=true;break;case 1:m.execute_fail=true;break;case 2:m.fetch_fail=true;break;
        case 3:m.second_fetch_fail=true;break;case 4:m.column_fail=true;break;case 5:m.extra=true;break;default:m.no_result=true;break;
        }
        run(VIREO_RESULT_DATABASE);assert(error.stage==VIREO_MYSQL_USER_REPOSITORY_STAGE_CREDENTIALS && !report.cleanup_pending);stop();
    }
    start();m.close_fail=true;run(VIREO_RESULT_DATABASE);assert(error.cleanup_stage==VIREO_MYSQL_USER_REPOSITORY_STAGE_STATEMENT_CLOSE && !report.cleanup_pending);stop();
    start();m.close_keep=true;run(VIREO_RESULT_BUSY);assert(report.cleanup_pending && !m.releases);busy_all();stop();
    start();m.release_keep=true;run(VIREO_RESULT_INTERNAL);assert(report.cleanup_pending && error.stage==VIREO_MYSQL_USER_REPOSITORY_STAGE_RELEASE);busy_all();
    CHECK(vireo_mysql_user_repository_destroy(&repo,NULL),VIREO_RESULT_INTERNAL);assert(repo);stop();
    start();m.release_consumed=true;run(VIREO_RESULT_DATABASE);assert(!report.cleanup_pending);stop();
    start();m.fetch_fail=true;m.close_fail=true;m.release_keep=true;run(VIREO_RESULT_DATABASE);
    assert(report.cleanup_pending && error.stage==VIREO_MYSQL_USER_REPOSITORY_STAGE_CREDENTIALS && error.cleanup_stage==VIREO_MYSQL_USER_REPOSITORY_STAGE_STATEMENT_CLOSE);busy_all();stop();
    start();m.absent=true;m.close_fail=true;run(VIREO_RESULT_NOT_FOUND);assert(error.stage==VIREO_MYSQL_USER_REPOSITORY_STAGE_CREDENTIALS && error.cleanup_result==VIREO_RESULT_DATABASE && m.disposition==VIREO_MYSQL_POOL_DISCARD);stop();
    start();m.acquire_partial=true;m.release_keep=true;run(VIREO_RESULT_INTERNAL);assert(report.cleanup_pending && !m.executes);busy_all();stop();
    start();m.acquire_empty=true;run(VIREO_RESULT_BUSY);assert(!m.releases && !m.executes);stop();
    start();m.borrow_fail=true;run(VIREO_RESULT_INTERNAL);assert(m.disposition==VIREO_MYSQL_POOL_DISCARD && !m.executes);stop();
    CHECK(vireo_mysql_thread_detach(&thread),VIREO_OK);CHECK(vireo_mysql_runtime_destroy(&runtime),VIREO_OK);
    printf("PASS %zu credential resource-boundary scenarios: owned snapshot, EOF view invalidation, binary input, PHC policy, zero on every failure, cleanup ownership, three-method BUSY, errno/thread\n",scenarios);return 0;
}
