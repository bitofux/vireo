#define _POSIX_C_SOURCE 200809L
#include "mysql_user_repository_internal.h"
#include <vireo/persistence/mysql_schema.h>
#include <assert.h>
#include <argon2.h>
#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(call,want) do { errno=EDOM; vireo_result_t got_=(call); if(got_!=(want)) { fprintf(stderr,"line %d result %d wanted %d\n",__LINE__,(int)got_,(int)(want)); abort(); } assert(errno==EDOM); } while(0)
static vireo_mysql_runtime_t *runtime;
static vireo_mysql_thread_t *thread;
static vireo_mysql_pool_t *pool;
static vireo_mysql_connection_t *observer;
static vireo_mysql_user_repository_t *repo;
static vireo_password_policy_t policy=VIREO_PASSWORD_POLICY_DEFAULT;
static char phc[VIREO_PASSWORD_ENCODED_CAPACITY];
static size_t phc_length, cases;
static unsigned char serial;
static const vireo_mysql_statement_limits_t query_limits={0,3,0,512,32768};
static vireo_mysql_statement_t *query(const char *sql)
{
    vireo_mysql_statement_t *s=NULL;vireo_mysql_execution_t ex;vireo_mysql_error_t error;
    CHECK(vireo_mysql_statement_prepare(thread,observer,sql,strlen(sql),&query_limits,&s,&error),VIREO_OK);
    CHECK(vireo_mysql_statement_execute(thread,s,NULL,0,&ex,&error),VIREO_OK);assert(ex.has_result);return s;
}
static void row(vireo_mysql_statement_t *s)
{ vireo_mysql_fetch_outcome_t out;CHECK(vireo_mysql_statement_fetch(thread,s,&out,NULL),VIREO_OK);assert(out==VIREO_MYSQL_FETCH_ROW); }
static void cell(vireo_mysql_statement_t *s,size_t col,const void *expected,size_t n)
{
    vireo_mysql_cell_view_t c;CHECK(vireo_mysql_statement_column(thread,s,col,&c),VIREO_OK);
    assert(!c.is_null && c.length==n && !memcmp(c.data,expected,n));
}
static void end(vireo_mysql_statement_t **s)
{
    vireo_mysql_fetch_outcome_t out;CHECK(vireo_mysql_statement_fetch(thread,*s,&out,NULL),VIREO_OK);
    assert(out==VIREO_MYSQL_FETCH_DONE);CHECK(vireo_mysql_statement_destroy(thread,s,NULL),VIREO_OK);assert(!*s);
}
static void scalar(const char *sql,const char *expected)
{ vireo_mysql_statement_t *s=query(sql);row(s);cell(s,0,expected,strlen(expected));end(&s); }
static void mutate(const char *sql)
{
    vireo_mysql_statement_t *s=NULL;vireo_mysql_execution_t ex;
    CHECK(vireo_mysql_statement_prepare(thread,observer,sql,strlen(sql),&query_limits,&s,NULL),VIREO_OK);
    CHECK(vireo_mysql_statement_execute(thread,s,NULL,0,&ex,NULL),VIREO_OK);assert(!ex.has_result);
    CHECK(vireo_mysql_statement_destroy(thread,&s,NULL),VIREO_OK);
}
static void snapshot(char out[256])
{
    vireo_mysql_statement_t *s=query("SELECT CONCAT_WS('|',"
        "(SELECT COUNT(*) FROM sessions),(SELECT COUNT(*) FROM operation_audits),"
        "(SELECT COALESCE(SUM(CRC32(CONCAT_WS(':',id,HEX(password_hash),status,updated_at_ms,COALESCE(last_login_at_ms,'N')))),0) FROM users),"
        "(SELECT COALESCE(SUM(CRC32(CONCAT_WS(':',id,user_id,HEX(token_digest),status,issued_at_ms,expires_at_ms,COALESCE(revoked_at_ms,'N'),last_seen_at_ms))),0) FROM sessions),"
        "(SELECT COALESCE(SUM(CRC32(CONCAT_WS(':',id,HEX(request_id),user_id,COALESCE(session_id,'N'),action,target_type,target_id,status,latency_us,occurred_at_ms))),0) FROM operation_audits))");
    row(s);vireo_mysql_cell_view_t c;CHECK(vireo_mysql_statement_column(thread,s,0,&c),VIREO_OK);
    assert(!c.is_null && c.length<256);memcpy(out,c.data,c.length);out[c.length]=0;end(&s);
}
static uint64_t register_user(const char *name,uint64_t created)
{
    vireo_mysql_registration_input_t in={.username=name,.username_length=strlen(name),.username_key=name,
        .username_key_length=strlen(name),.password_hash=phc,.password_hash_length=phc_length,
        .request_id={1},.occurred_at_ms=created};
    assert(serial<250);in.request_id[15]=++serial;vireo_mysql_registration_report_t out;
    CHECK(vireo_mysql_user_repository_register(repo,&in,0,&out,NULL),VIREO_OK);assert(out.commit==VIREO_MYSQL_REGISTRATION_COMMITTED);
    return out.user_id;
}
static vireo_mysql_login_input_t make_input(uint64_t user,uint64_t issued)
{
    vireo_mysql_login_input_t in={.user_id=user,.verified_password_hash=phc,.verified_password_hash_length=phc_length,
        .issued_at_ms=issued,.expires_at_ms=issued+1,.latency_us=678};
    assert(serial<250);in.request_id[15]=++serial;
    vireo_session_token_t token;CHECK(vireo_session_token_generate(&token,&in.token_digest),VIREO_OK);
    vireo_session_token_digest_t computed;bool matches=false;
    CHECK(vireo_session_token_digest(&token,&computed),VIREO_OK);
    CHECK(vireo_session_token_digest_equal(&computed,&in.token_digest,&matches),VIREO_OK);assert(matches);
    CHECK(vireo_session_token_clear(&token),VIREO_OK);return in;
}
static void times(uint64_t user,uint64_t time)
{
    char sql[256],expected[128];
    (void)snprintf(sql,sizeof(sql),"SELECT CONCAT_WS('|',last_login_at_ms,updated_at_ms) FROM users WHERE id=%llu",(unsigned long long)user);
    (void)snprintf(expected,sizeof(expected),"%llu|%llu",(unsigned long long)time,(unsigned long long)time);scalar(sql,expected);
}
static void verify(const vireo_mysql_login_input_t *in,const vireo_mysql_login_report_t *out)
{
    assert(out->commit==VIREO_MYSQL_LOGIN_COMMITTED && out->session_id && out->audit_id);
    char sql[1024],expected[512];
    (void)snprintf(sql,sizeof(sql),"SELECT token_digest FROM sessions WHERE id=%llu",(unsigned long long)out->session_id);
    vireo_mysql_statement_t *s=query(sql);row(s);cell(s,0,in->token_digest.bytes,32);end(&s);
    (void)snprintf(sql,sizeof(sql),"SELECT CONCAT_WS('|',user_id,status,issued_at_ms,expires_at_ms,revoked_at_ms IS NULL,last_seen_at_ms) FROM sessions WHERE id=%llu",(unsigned long long)out->session_id);
    (void)snprintf(expected,sizeof(expected),"%llu|1|%llu|%llu|1|%llu",(unsigned long long)in->user_id,(unsigned long long)in->issued_at_ms,(unsigned long long)in->expires_at_ms,(unsigned long long)in->issued_at_ms);scalar(sql,expected);
    (void)snprintf(sql,sizeof(sql),"SELECT CONCAT_WS('|',user_id,session_id,action,target_type,target_id,target_hash IS NULL,status,latency_us,OCTET_LENGTH(detail),occurred_at_ms) FROM operation_audits WHERE id=%llu",(unsigned long long)out->audit_id);
    (void)snprintf(expected,sizeof(expected),"%llu|%llu|2|2|%llu|1|0|%llu|0|%llu",(unsigned long long)in->user_id,(unsigned long long)out->session_id,(unsigned long long)out->session_id,(unsigned long long)in->latency_us,(unsigned long long)in->issued_at_ms);scalar(sql,expected);
    (void)snprintf(sql,sizeof(sql),"SELECT request_id FROM operation_audits WHERE id=%llu",(unsigned long long)out->audit_id);
    s=query(sql);row(s);cell(s,0,in->request_id,16);end(&s);++cases;
}
static void unchanged(const vireo_mysql_login_input_t *in,vireo_result_t want,vireo_mysql_login_issue_t issue)
{
    char before[256],after[256];snapshot(before);vireo_mysql_login_report_t out;vireo_mysql_user_repository_error_t error;
    CHECK(vireo_mysql_user_repository_login(repo,in,0,&out,&error),want);
    assert(out.commit==VIREO_MYSQL_LOGIN_NOT_COMMITTED && !out.session_id && !out.audit_id && !out.cleanup_pending && out.issue==issue);
    if(issue==VIREO_MYSQL_LOGIN_DIGEST_CONFLICT || issue==VIREO_MYSQL_LOGIN_REQUEST_CONFLICT) { assert(error.database.mysql_code==1062 && out.rollback_confirmed); }
    snapshot(after);assert(!strcmp(before,after));++cases;
}
enum fault_mode { HEALTHY, UPDATE_FAILURE, UNKNOWN_ROLLED_BACK, UNKNOWN_COMMITTED, COMMIT_CLOSE, RELEASE_PENDING, RELEASE_CONSUMED };
static enum fault_mode fault;
static bool current_update,current_commit;
static vireo_result_t fault_prepare(vireo_mysql_thread_t *t,vireo_mysql_connection_t *c,
    const char *sql,size_t n,const vireo_mysql_statement_limits_t *l,vireo_mysql_statement_t **s,vireo_mysql_error_t *e)
{
    current_update=strncmp(sql,"UPDATE users SET",16)==0;current_commit=strcmp(sql,"COMMIT")==0;
    return vireo_mysql_statement_prepare(t,c,sql,n,l,s,e);
}
static vireo_result_t fault_execute(vireo_mysql_thread_t *t,vireo_mysql_statement_t *s,
    const vireo_mysql_parameter_t *p,size_t n,vireo_mysql_execution_t *out,vireo_mysql_error_t *e)
{
    if((fault==UPDATE_FAILURE && current_update) || (fault==UNKNOWN_ROLLED_BACK && current_commit)) {
        *out=(vireo_mysql_execution_t){.execution_started=true};
        *e=(vireo_mysql_error_t){.stage=VIREO_MYSQL_STAGE_STATEMENT_EXECUTE,.mysql_code=2013};
        memcpy(e->sqlstate,"HY000",6);return VIREO_RESULT_DATABASE;
    }
    vireo_result_t result=vireo_mysql_statement_execute(t,s,p,n,out,e);
    if(result==VIREO_OK && fault==UNKNOWN_COMMITTED && current_commit) {
        *e=(vireo_mysql_error_t){.stage=VIREO_MYSQL_STAGE_STATEMENT_EXECUTE,.mysql_code=2013};
        memcpy(e->sqlstate,"HY000",6);return VIREO_RESULT_DATABASE;
    }
    return result;
}
static vireo_result_t fault_close(vireo_mysql_thread_t *t,vireo_mysql_statement_t **s,vireo_mysql_error_t *e)
{
    vireo_result_t result=vireo_mysql_statement_destroy(t,s,e);
    if(result==VIREO_OK && fault==COMMIT_CLOSE && current_commit) {
        *e=(vireo_mysql_error_t){.stage=VIREO_MYSQL_STAGE_STATEMENT_CLOSE,.mysql_code=2013};return VIREO_RESULT_DATABASE;
    }
    return result;
}
static vireo_result_t fault_release(vireo_mysql_thread_t *t,vireo_mysql_pool_t *p,
    vireo_mysql_lease_t *l,vireo_mysql_pool_disposition_t d,vireo_mysql_pool_release_t *out,vireo_mysql_pool_error_t *e)
{
    if(fault==RELEASE_PENDING) {
        *out=(vireo_mysql_pool_release_t){0};*e=(vireo_mysql_pool_error_t){.stage=VIREO_MYSQL_POOL_STAGE_LOCK,.pthread_code=EINVAL};return VIREO_RESULT_INTERNAL;
    }
    vireo_result_t result=vireo_mysql_pool_release(t,p,l,d,out,e);
    if(result==VIREO_OK && fault==RELEASE_CONSUMED) {
        *e=(vireo_mysql_pool_error_t){.stage=VIREO_MYSQL_POOL_STAGE_SIGNAL,.pthread_code=EINVAL};return VIREO_RESULT_INTERNAL;
    }
    return result;
}
static void refill(void)
{
    vireo_mysql_pool_info_t info;CHECK(vireo_mysql_pool_inspect(pool,&info),VIREO_OK);
    while(info.vacant) {
        vireo_mysql_pool_refill_t restored;CHECK(vireo_mysql_pool_refill(thread,pool,&restored,NULL),VIREO_OK);assert(restored.restored);
        CHECK(vireo_mysql_pool_inspect(pool,&info),VIREO_OK);
    }
}
static void failures(uint64_t user)
{
    CHECK(vireo_mysql_user_repository_destroy(&repo,NULL),VIREO_OK);
    vireo_mysql_user_repository_ops_t ops=vireo_mysql_user_repository_native_ops;
    ops.prepare=fault_prepare;ops.execute=fault_execute;ops.close=fault_close;ops.release=fault_release;
    CHECK(vireo_mysql_user_repository_create_with_ops(thread,pool,&policy,&repo,NULL,&ops),VIREO_OK);
    fault=UPDATE_FAILURE;vireo_mysql_login_input_t in=make_input(user,9000);unchanged(&in,VIREO_RESULT_DATABASE,0);
    fault=UNKNOWN_ROLLED_BACK;in=make_input(user,9001);
    char before[256],after[256];snapshot(before);vireo_mysql_login_report_t out;vireo_mysql_user_repository_error_t error;
    CHECK(vireo_mysql_user_repository_login(repo,&in,0,&out,&error),VIREO_RESULT_DATABASE);
    assert(out.commit==VIREO_MYSQL_LOGIN_UNKNOWN && !out.rollback_confirmed && !out.session_id && !out.cleanup_pending);
    snapshot(after);assert(!strcmp(before,after));++cases;
    fault=UNKNOWN_COMMITTED;in=make_input(user,9002);
    CHECK(vireo_mysql_user_repository_login(repo,&in,0,&out,&error),VIREO_RESULT_DATABASE);
    assert(out.commit==VIREO_MYSQL_LOGIN_UNKNOWN && !out.rollback_confirmed && !out.session_id && !out.audit_id && !out.cleanup_pending);
    char sql[512];(void)snprintf(sql,sizeof(sql),"SELECT COUNT(*) FROM sessions s JOIN operation_audits a ON a.session_id=s.id AND a.target_id=s.id WHERE s.user_id=%llu AND s.issued_at_ms=9002 AND a.action=2",(unsigned long long)user);
    scalar(sql,"1");times(user,9002);++cases;
    for(enum fault_mode mode=COMMIT_CLOSE;mode<=RELEASE_CONSUMED;mode=(enum fault_mode)(mode+1)) {
        fault=mode;in=make_input(user,9100+(uint64_t)mode);
        CHECK(vireo_mysql_user_repository_login(repo,&in,0,&out,&error),mode==COMMIT_CLOSE ? VIREO_RESULT_DATABASE : VIREO_RESULT_INTERNAL);
        verify(&in,&out);times(user,in.issued_at_ms);assert(out.cleanup_pending==(mode==RELEASE_PENDING));
        if(mode==RELEASE_PENDING) {
            CHECK(vireo_mysql_user_repository_login(repo,&in,0,&out,NULL),VIREO_RESULT_BUSY);assert(out.cleanup_pending);
            vireo_mysql_registration_report_t registration;
            CHECK(vireo_mysql_user_repository_register(repo,NULL,0,&registration,NULL),VIREO_RESULT_BUSY);assert(registration.cleanup_pending);
            CHECK(vireo_mysql_user_repository_destroy(&repo,NULL),VIREO_RESULT_INTERNAL);assert(repo);
            fault=HEALTHY;CHECK(vireo_mysql_user_repository_destroy(&repo,NULL),VIREO_OK);assert(!repo);
            CHECK(vireo_mysql_user_repository_create_with_ops(thread,pool,&policy,&repo,NULL,&ops),VIREO_OK);
        }
    }
    fault=HEALTHY;CHECK(vireo_mysql_user_repository_destroy(&repo,NULL),VIREO_OK);
    CHECK(vireo_mysql_user_repository_create(thread,pool,&policy,&repo,NULL),VIREO_OK);refill();
    puts("PASS real DB with boundary injection: session/update rollback, identical UNKNOWN with actual rollback/commit, committed IDs survive cleanup, residual lease blocks both methods; no wire failure claimed");
}
struct racer { pthread_barrier_t *barrier;vireo_mysql_login_input_t input;vireo_mysql_login_report_t out;vireo_result_t result; };
static void *race(void *arg)
{
    struct racer *r=arg;vireo_mysql_thread_t *t=NULL;vireo_mysql_user_repository_t *repository=NULL;
    CHECK(vireo_mysql_thread_attach(runtime,&t,NULL),VIREO_OK);
    CHECK(vireo_mysql_user_repository_create(t,pool,&policy,&repository,NULL),VIREO_OK);
    int code=pthread_barrier_wait(r->barrier);assert(code==0 || code==PTHREAD_BARRIER_SERIAL_THREAD);
    errno=EDOM;r->result=vireo_mysql_user_repository_login(repository,&r->input,1000,&r->out,NULL);assert(errno==EDOM);
    CHECK(vireo_mysql_user_repository_destroy(&repository,NULL),VIREO_OK);CHECK(vireo_mysql_thread_detach(&t),VIREO_OK);return NULL;
}
static void concurrency(uint64_t user,bool same_digest)
{
    pthread_barrier_t barrier;assert(!pthread_barrier_init(&barrier,NULL,2));
    struct racer r[2]={{.barrier=&barrier,.input=make_input(user,10001)},{.barrier=&barrier,.input=make_input(user,10002)}};
    if(same_digest) { r[1].input.token_digest=r[0].input.token_digest; }
    pthread_t threads[2];for(size_t i=0;i<2;++i) { assert(!pthread_create(threads+i,NULL,race,r+i)); }
    for(size_t i=0;i<2;++i) { assert(!pthread_join(threads[i],NULL)); }assert(!pthread_barrier_destroy(&barrier));
    size_t won=0;uint64_t latest=0;
    for(size_t i=0;i<2;++i) {
        if(r[i].result==VIREO_OK) { ++won;verify(&r[i].input,&r[i].out);if(r[i].input.issued_at_ms>latest) { latest=r[i].input.issued_at_ms; } }
        else { assert(r[i].result==VIREO_RESULT_DATABASE && r[i].out.issue==VIREO_MYSQL_LOGIN_DIGEST_CONFLICT && r[i].out.rollback_confirmed && !r[i].out.cleanup_pending && !r[i].out.session_id); }
    }
    assert(won==(same_digest ? 1u : 2u));times(user,latest);
    printf("PASS two OS workers, same locked user, %s: %zu commits, monotonic times\n",same_digest ? "same digest" : "distinct digests",won);
}
static size_t fd_count(void)
{ DIR *d=opendir("/proc/self/fd");assert(d);size_t n=0;while(readdir(d)) { ++n; }assert(!closedir(d));return n; }
int main(int argc,char **argv)
{
    assert(argc==5 && !setvbuf(stdout,NULL,_IONBF,0));
    char password[1026];FILE *f=fopen(argv[3],"r");assert(f && fgets(password,(int)sizeof(password),f) && !fclose(f));password[strcspn(password,"\n")]=0;
    struct sigaction sa={0};sa.sa_handler=SIG_IGN;assert(!sigemptyset(&sa.sa_mask) && !sigaction(SIGPIPE,&sa,NULL));
    CHECK(vireo_mysql_runtime_create(&runtime,NULL),VIREO_OK);CHECK(vireo_mysql_thread_attach(runtime,&thread,NULL),VIREO_OK);size_t fd=fd_count();
    vireo_mysql_connection_options_t options={argv[1],argv[2],password,argv[4],3,3,3};
    const vireo_mysql_migration_t *catalog=NULL;size_t count=0;CHECK(vireo_mysql_schema_catalog(&catalog,&count),VIREO_OK);
    vireo_mysql_migration_report_t migration;CHECK(vireo_mysql_migration_apply(thread,&options,catalog,count,&migration,NULL),VIREO_OK);assert(migration.ready && migration.steps_completed==14);
    CHECK(vireo_mysql_connection_open(thread,&options,&observer,NULL),VIREO_OK);
    vireo_mysql_pool_options_t config={options,4,4,VIREO_MYSQL_POOL_MEMORY_MAX};CHECK(vireo_mysql_pool_create(thread,&config,&pool,NULL),VIREO_OK);
    CHECK(vireo_mysql_user_repository_create(thread,pool,&policy,&repo,NULL),VIREO_OK);
    static const unsigned char raw_password[]={'s','e','c',0,'r','e','t'};
    CHECK(vireo_password_hash_create(&policy,raw_password,sizeof(raw_password),phc,sizeof(phc),&phc_length),VIREO_OK);
    bool verification=false;
    CHECK(vireo_password_hash_verify(&policy,raw_password,sizeof(raw_password),phc,phc_length,&verification),VIREO_OK);assert(verification);
    uint64_t user=register_user("alice",1000);vireo_mysql_login_input_t in=make_input(user,2000);vireo_mysql_login_report_t out;
    /* 同request不同action合法：注册事件的ID可用于一次LOGIN事件。 */
    in.request_id[0]=1;in.request_id[15]=1;
    CHECK(vireo_mysql_user_repository_login(repo,&in,0,&out,NULL),VIREO_OK);verify(&in,&out);times(user,2000);
    vireo_mysql_login_input_t first=in;
    in=make_input(user,2000);CHECK(vireo_mysql_user_repository_login(repo,&in,0,&out,NULL),VIREO_OK);verify(&in,&out);times(user,2000);
    in=make_input(user,1500);CHECK(vireo_mysql_user_repository_login(repo,&in,0,&out,NULL),VIREO_OK);verify(&in,&out);times(user,2000);
    in=make_input(user,3000);in.token_digest=first.token_digest;unchanged(&in,VIREO_RESULT_DATABASE,VIREO_MYSQL_LOGIN_DIGEST_CONFLICT);
    uint64_t other=register_user("other",1000);in=make_input(other,3000);in.token_digest=first.token_digest;unchanged(&in,VIREO_RESULT_DATABASE,VIREO_MYSQL_LOGIN_DIGEST_CONFLICT);
    in=make_input(user,4000);memcpy(in.request_id,first.request_id,16);unchanged(&in,VIREO_RESULT_DATABASE,VIREO_MYSQL_LOGIN_REQUEST_CONFLICT);times(user,2000);
    in=make_input(UINT64_MAX,3000);unchanged(&in,VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_LOGIN_USER_NOT_FOUND);
    in=make_input(user,999);unchanged(&in,VIREO_RESULT_RANGE,VIREO_MYSQL_LOGIN_TIME_BEFORE_USER);
    mutate("UPDATE users SET status=2 WHERE username_key='alice'");in=make_input(user,3000);unchanged(&in,VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_LOGIN_USER_DISABLED);
    mutate("UPDATE users SET status=1 WHERE username_key='alice'");
    char old_phc[VIREO_PASSWORD_ENCODED_CAPACITY];size_t old_length=phc_length;memcpy(old_phc,phc,phc_length);
    CHECK(vireo_password_hash_create(&policy,raw_password,sizeof(raw_password),phc,sizeof(phc),&phc_length),VIREO_OK);
    in=make_input(user,3000);unchanged(&in,VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_LOGIN_PASSWORD_CHANGED);
    memcpy(phc,old_phc,old_length);phc_length=old_length;
    /* 保存真实低成本历史PHC，默认create策略不变；先实际验密，再允许登录。 */
    static const unsigned char salt[16]={1};
    assert(argon2id_hash_encoded(1,8,1,raw_password,sizeof(raw_password),salt,sizeof(salt),32,old_phc,sizeof(old_phc))==ARGON2_OK);
    old_length=strlen(old_phc);
    char sql[512];(void)snprintf(sql,sizeof(sql),"UPDATE users SET password_hash='%.*s' WHERE username_key='other'",(int)old_length,old_phc);mutate(sql);
    CHECK(vireo_password_hash_verify(&policy,raw_password,sizeof(raw_password),old_phc,old_length,&verification),VIREO_OK);assert(verification);
    in=make_input(other,3000);in.verified_password_hash=old_phc;in.verified_password_hash_length=old_length;
    memset(&in.token_digest,0,sizeof(in.token_digest));CHECK(vireo_mysql_user_repository_login(repo,&in,0,&out,NULL),VIREO_OK);verify(&in,&out);times(other,3000);
    uint64_t maxuser=register_user("maximum",UINT64_MAX-1);in=make_input(maxuser,UINT64_MAX-1);in.latency_us=UINT64_MAX;
    CHECK(vireo_mysql_user_repository_login(repo,&in,0,&out,NULL),VIREO_OK);verify(&in,&out);times(maxuser,UINT64_MAX-1);
    failures(user);concurrency(register_user("race-distinct",1000),false);concurrency(register_user("race-digest",1000),true);
    vireo_mysql_lease_t leases[4]={{0}};vireo_mysql_pool_acquisition_t a;
    for(size_t i=0;i<4;++i) { CHECK(vireo_mysql_pool_acquire(thread,pool,0,leases+i,&a,NULL),VIREO_OK); }
    in=make_input(user,11000);unchanged(&in,VIREO_RESULT_BUSY,0);
    for(size_t i=0;i<4;++i) { vireo_mysql_pool_release_t released;CHECK(vireo_mysql_pool_release(thread,pool,leases+i,VIREO_MYSQL_POOL_RECYCLE,&released,NULL),VIREO_OK); }
    bool closed;CHECK(vireo_mysql_pool_close(pool,&closed,NULL),VIREO_OK);assert(closed);unchanged(&in,VIREO_RESULT_CANCELLED,0);
    CHECK(vireo_mysql_user_repository_destroy(&repo,NULL),VIREO_OK);CHECK(vireo_mysql_pool_destroy(thread,&pool,NULL),VIREO_OK);
    CHECK(vireo_mysql_connection_destroy(thread,&observer),VIREO_OK);CHECK(vireo_mysql_thread_detach(&thread),VIREO_OK);CHECK(vireo_mysql_runtime_destroy(&runtime),VIREO_OK);
    assert(fd_count()==fd);memset(password,0,sizeof(password));memset(phc,0,sizeof(phc));
    printf("PASS %zu real login observations, exact session/audit fields, monotonic times, whole rollback, actual password verification and digest-only storage; FD %zu -> %zu\n",cases,fd,fd_count());return 0;
}
