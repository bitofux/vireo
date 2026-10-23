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
static const unsigned char raw_password[]={'s','e','s',0,'s','i','o','n'};
static void zero(const void *p,size_t n) { const unsigned char *bytes=p;for(size_t i=0;i<n;++i) { assert(bytes[i]==0); } }
static void snapshot(char out[256])
{
    vireo_mysql_statement_t *s=query("SELECT CONCAT_WS('|',(SELECT COUNT(*) FROM users),(SELECT COUNT(*) FROM sessions),"
        "(SELECT COUNT(*) FROM operation_audits),(SELECT COALESCE(SUM(CRC32(CONCAT_WS(':',id,status,created_at_ms,updated_at_ms,COALESCE(last_login_at_ms,'N')))),0) FROM users),"
        "(SELECT COALESCE(SUM(CRC32(CONCAT_WS(':',id,user_id,HEX(token_digest),status,issued_at_ms,expires_at_ms,COALESCE(revoked_at_ms,'N'),last_seen_at_ms))),0) FROM sessions))");
    row(s);vireo_mysql_cell_view_t c;CHECK(vireo_mysql_statement_column(thread,s,0,&c),VIREO_OK);assert(!c.is_null && c.length<256);
    memcpy(out,c.data,c.length);out[c.length]=0;end(&s);
}
static uint64_t register_user(const char *key)
{
    vireo_mysql_registration_input_t in={.username=key,.username_length=strlen(key),.username_key=key,
        .username_key_length=strlen(key),.password_hash=phc,.password_hash_length=phc_length,.occurred_at_ms=1000};
    in.request_id[15]=++serial;vireo_mysql_registration_report_t out;
    CHECK(vireo_mysql_user_repository_register(repo,&in,0,&out,NULL),VIREO_OK);assert(out.commit==VIREO_MYSQL_REGISTRATION_COMMITTED);return out.user_id;
}
static uint64_t login(uint64_t user,const vireo_session_token_digest_t *digest)
{
    vireo_mysql_login_input_t in={.user_id=user,.verified_password_hash=phc,.verified_password_hash_length=phc_length,
        .token_digest=*digest,.issued_at_ms=2000,.expires_at_ms=9000};
    in.request_id[15]=++serial;vireo_mysql_login_report_t out;
    CHECK(vireo_mysql_user_repository_login(repo,&in,0,&out,NULL),VIREO_OK);assert(out.commit==VIREO_MYSQL_LOGIN_COMMITTED && out.session_id);return out.session_id;
}
static void refill(void)
{
    vireo_mysql_pool_info_t info;CHECK(vireo_mysql_pool_inspect(pool,&info),VIREO_OK);
    while(info.vacant) { vireo_mysql_pool_refill_t out;CHECK(vireo_mysql_pool_refill(thread,pool,&out,NULL),VIREO_OK);assert(out.restored);CHECK(vireo_mysql_pool_inspect(pool,&info),VIREO_OK); }
}
static vireo_mysql_session_identity_t check(const vireo_session_token_digest_t *digest,uint64_t now,
    vireo_result_t want,vireo_mysql_session_issue_t issue,const vireo_mysql_session_identity_t *expected)
{
    char before[256],after[256];snapshot(before);vireo_mysql_session_identity_t out;memset(&out,0xa5,sizeof(out));vireo_mysql_session_report_t report;
    CHECK(vireo_mysql_user_repository_find_session(repo,digest,now,0,&out,&report,NULL),want);
    assert(report.valid==(want==VIREO_OK) && report.issue==issue && !report.cleanup_pending);
    if(want==VIREO_OK) { assert(expected && out.session_id==expected->session_id && out.user_id==expected->user_id && out.issued_at_ms==expected->issued_at_ms && out.expires_at_ms==expected->expires_at_ms); }
    else { zero(&out,sizeof(out)); }
    snapshot(after);assert(!strcmp(before,after));++cases;return out;
}
enum fault_mode { HEALTHY, FETCH_FAILURE, CLOSE_CONSUMED, CLOSE_PENDING, RELEASE_PENDING, RELEASE_CONSUMED };
static enum fault_mode fault;
static vireo_result_t fault_fetch(vireo_mysql_thread_t *t,vireo_mysql_statement_t *s,vireo_mysql_fetch_outcome_t *out,vireo_mysql_error_t *e)
{
    if(fault==FETCH_FAILURE) { *e=(vireo_mysql_error_t){.stage=VIREO_MYSQL_STAGE_STATEMENT_FETCH,.mysql_code=2013};return VIREO_RESULT_DATABASE; }
    return vireo_mysql_statement_fetch(t,s,out,e);
}
static vireo_result_t fault_close(vireo_mysql_thread_t *t,vireo_mysql_statement_t **s,vireo_mysql_error_t *e)
{
    if(fault==CLOSE_PENDING) { *e=(vireo_mysql_error_t){.stage=VIREO_MYSQL_STAGE_STATEMENT_CLOSE};return VIREO_RESULT_BUSY; }
    vireo_result_t result=vireo_mysql_statement_destroy(t,s,e);
    if(result==VIREO_OK && fault==CLOSE_CONSUMED) { *e=(vireo_mysql_error_t){.stage=VIREO_MYSQL_STAGE_STATEMENT_CLOSE,.mysql_code=2013};return VIREO_RESULT_DATABASE; }return result;
}
static vireo_result_t fault_release(vireo_mysql_thread_t *t,vireo_mysql_pool_t *p,vireo_mysql_lease_t *l,
    vireo_mysql_pool_disposition_t d,vireo_mysql_pool_release_t *out,vireo_mysql_pool_error_t *e)
{
    if(fault==RELEASE_PENDING) { *out=(vireo_mysql_pool_release_t){0};*e=(vireo_mysql_pool_error_t){.stage=VIREO_MYSQL_POOL_STAGE_LOCK};return VIREO_RESULT_INTERNAL; }
    vireo_result_t result=vireo_mysql_pool_release(t,p,l,d,out,e);
    if(result==VIREO_OK && fault==RELEASE_CONSUMED) { *e=(vireo_mysql_pool_error_t){.stage=VIREO_MYSQL_POOL_STAGE_RESET};return VIREO_RESULT_DATABASE; }return result;
}
static void failures(const vireo_session_token_digest_t *digest)
{
    CHECK(vireo_mysql_user_repository_destroy(&repo,NULL),VIREO_OK);vireo_mysql_user_repository_ops_t ops=vireo_mysql_user_repository_native_ops;
    ops.fetch=fault_fetch;ops.close=fault_close;ops.release=fault_release;
    for(enum fault_mode mode=FETCH_FAILURE;mode<=RELEASE_CONSUMED;mode=(enum fault_mode)(mode+1)) {
        fault=HEALTHY;CHECK(vireo_mysql_user_repository_create_with_ops(thread,pool,&policy,&repo,NULL,&ops),VIREO_OK);fault=mode;
        char before[256],after[256];snapshot(before);vireo_mysql_session_identity_t out;vireo_mysql_session_report_t report;
        vireo_result_t want=mode==CLOSE_PENDING ? VIREO_RESULT_BUSY : (mode==RELEASE_PENDING ? VIREO_RESULT_INTERNAL : VIREO_RESULT_DATABASE);
        CHECK(vireo_mysql_user_repository_find_session(repo,digest,2000,0,&out,&report,NULL),want);zero(&out,sizeof(out));assert(!report.valid && report.issue==VIREO_MYSQL_SESSION_ISSUE_NONE);
        bool pending=mode==CLOSE_PENDING || mode==RELEASE_PENDING;assert(report.cleanup_pending==pending);
        if(pending) {
            vireo_mysql_registration_report_t registration;vireo_mysql_login_report_t login_report;
            vireo_mysql_user_credentials_t credentials;vireo_mysql_credentials_report_t found;
            CHECK(vireo_mysql_user_repository_register(repo,NULL,0,&registration,NULL),VIREO_RESULT_BUSY);
            CHECK(vireo_mysql_user_repository_login(repo,NULL,0,&login_report,NULL),VIREO_RESULT_BUSY);
            CHECK(vireo_mysql_user_repository_find_credentials(repo,NULL,0,0,&credentials,&found,NULL),VIREO_RESULT_BUSY);
            CHECK(vireo_mysql_user_repository_find_session(repo,digest,2000,0,&out,&report,NULL),VIREO_RESULT_BUSY);
            assert(registration.cleanup_pending && login_report.cleanup_pending && found.cleanup_pending && report.cleanup_pending);zero(&credentials,sizeof(credentials));zero(&out,sizeof(out));
            CHECK(vireo_mysql_user_repository_destroy(&repo,NULL),mode==CLOSE_PENDING ? VIREO_RESULT_BUSY : VIREO_RESULT_INTERNAL);assert(repo);
        }
        fault=HEALTHY;CHECK(vireo_mysql_user_repository_destroy(&repo,NULL),VIREO_OK);refill();snapshot(after);assert(!strcmp(before,after));++cases;
    }
    CHECK(vireo_mysql_user_repository_create(thread,pool,&policy,&repo,NULL),VIREO_OK);
    puts("PASS real DB with boundary injections: fetch/close/release failures publish no identity; pending ownership gates four methods; no wire fault claimed");
}
struct reader { vireo_session_token_digest_t digest;vireo_mysql_session_identity_t expected,out; };
static void *read_worker(void *arg)
{
    struct reader *reader=arg;vireo_mysql_thread_t *t=NULL;vireo_mysql_user_repository_t *repository=NULL;
    CHECK(vireo_mysql_thread_attach(runtime,&t,NULL),VIREO_OK);CHECK(vireo_mysql_user_repository_create(t,pool,&policy,&repository,NULL),VIREO_OK);
    vireo_mysql_session_report_t report;CHECK(vireo_mysql_user_repository_find_session(repository,&reader->digest,2000,1000,&reader->out,&report,NULL),VIREO_OK);
    assert(report.valid && !report.cleanup_pending && reader->out.session_id==reader->expected.session_id && reader->out.user_id==reader->expected.user_id);
    CHECK(vireo_mysql_user_repository_destroy(&repository,NULL),VIREO_OK);CHECK(vireo_mysql_thread_detach(&t),VIREO_OK);return NULL;
}
static void workers(const vireo_session_token_digest_t *digest,const vireo_mysql_session_identity_t *expected)
{
    struct reader readers[2]={{.digest=*digest,.expected=*expected},{.digest=*digest,.expected=*expected}};pthread_t threads[2];
    for(size_t i=0;i<2;++i) { assert(!pthread_create(threads+i,NULL,read_worker,readers+i)); }
    for(size_t i=0;i<2;++i) { assert(!pthread_join(threads[i],NULL));assert(readers[i].out.expires_at_ms==9000); }
    memset(&readers[0].out,0,sizeof(readers[0].out));assert(readers[1].out.user_id==expected->user_id);++cases;
    puts("PASS two OS workers, own guards/repositories, shared pool, independent identity values survive detach; no strict query overlap claimed");
}
static size_t fd_count(void)
{ DIR *d=opendir("/proc/self/fd");assert(d);size_t n=0;while(readdir(d)) { ++n; }assert(!closedir(d));return n; }
int main(int argc,char **argv)
{
    assert(argc==5 && !setvbuf(stdout,NULL,_IONBF,0));char password[1026];FILE *f=fopen(argv[3],"r");
    assert(f && fgets(password,(int)sizeof(password),f) && !fclose(f));password[strcspn(password,"\n")]=0;
    struct sigaction sa={0};sa.sa_handler=SIG_IGN;assert(!sigemptyset(&sa.sa_mask) && !sigaction(SIGPIPE,&sa,NULL));
    CHECK(vireo_mysql_runtime_create(&runtime,NULL),VIREO_OK);CHECK(vireo_mysql_thread_attach(runtime,&thread,NULL),VIREO_OK);size_t fd=fd_count();
    vireo_mysql_connection_options_t options={argv[1],argv[2],password,argv[4],3,3,3};const vireo_mysql_migration_t *catalog=NULL;size_t count=0;
    CHECK(vireo_mysql_schema_catalog(&catalog,&count),VIREO_OK);vireo_mysql_migration_report_t migration;
    CHECK(vireo_mysql_migration_apply(thread,&options,catalog,count,&migration,NULL),VIREO_OK);assert(migration.ready && migration.steps_completed==15);
    CHECK(vireo_mysql_connection_open(thread,&options,&observer,NULL),VIREO_OK);
    vireo_mysql_pool_options_t config={options,4,4,VIREO_MYSQL_POOL_MEMORY_MAX};CHECK(vireo_mysql_pool_create(thread,&config,&pool,NULL),VIREO_OK);
    CHECK(vireo_mysql_user_repository_create(thread,pool,&policy,&repo,NULL),VIREO_OK);
    CHECK(vireo_password_hash_create(&policy,raw_password,sizeof(raw_password),phc,sizeof(phc),&phc_length),VIREO_OK);
    uint64_t user=register_user("alice");vireo_mysql_user_credentials_t credentials;vireo_mysql_credentials_report_t found;
    CHECK(vireo_mysql_user_repository_find_credentials(repo,"alice",5,0,&credentials,&found,NULL),VIREO_OK);assert(found.found && credentials.user_id==user);
    bool matches=false;CHECK(vireo_password_hash_verify(&policy,raw_password,sizeof(raw_password),credentials.password_hash,credentials.password_hash_length,&matches),VIREO_OK);assert(matches);
    vireo_session_token_t token;vireo_session_token_digest_t generated,digest;
    CHECK(vireo_session_token_generate(&token,&generated),VIREO_OK);uint64_t session=login(user,&generated);
    CHECK(vireo_session_token_digest(&token,&digest),VIREO_OK);assert(!memcmp(&generated,&digest,sizeof(digest)));
    CHECK(vireo_mysql_user_credentials_clear(&credentials),VIREO_OK);CHECK(vireo_session_token_clear(&token),VIREO_OK);
    vireo_mysql_session_identity_t expected={session,user,2000,9000};
    vireo_mysql_session_identity_t out=check(&digest,2000,VIREO_OK,VIREO_MYSQL_SESSION_ISSUE_NONE,&expected);
    CHECK(vireo_mysql_user_repository_destroy(&repo,NULL),VIREO_OK);assert(out.session_id==session && out.user_id==user);
    CHECK(vireo_mysql_user_repository_create(thread,pool,&policy,&repo,NULL),VIREO_OK);
    (void)check(&digest,1999,VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_SESSION_NOT_YET_VALID,NULL);
    (void)check(&digest,8999,VIREO_OK,VIREO_MYSQL_SESSION_ISSUE_NONE,&expected);
    (void)check(&digest,9000,VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_SESSION_EXPIRED,NULL);
    (void)check(&digest,UINT64_MAX,VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_SESSION_EXPIRED,NULL);
    vireo_session_token_digest_t wrong=digest;wrong.bytes[0]^=1;(void)check(&wrong,2000,VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_SESSION_NOT_FOUND,NULL);
    char sql[512];(void)snprintf(sql,sizeof(sql),"UPDATE sessions SET last_seen_at_ms=3000 WHERE id=%llu",(unsigned long long)session);mutate(sql);
    (void)check(&digest,2000,VIREO_OK,VIREO_MYSQL_SESSION_ISSUE_NONE,&expected);
    scalar("SELECT COUNT(*) FROM sessions WHERE last_seen_at_ms=3000 AND status=1","1");
    mutate("UPDATE users SET status=2 WHERE username_key='alice'");(void)check(&digest,2000,VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_SESSION_USER_DISABLED,NULL);
    mutate("UPDATE users SET status=1 WHERE username_key='alice'");
    (void)snprintf(sql,sizeof(sql),"UPDATE sessions SET status=2,revoked_at_ms=2500 WHERE id=%llu",(unsigned long long)session);mutate(sql);
    (void)check(&digest,2000,VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_SESSION_REVOKED,NULL);
    /* 同用户另一Session保持有效，撤销一个不影响另一个。 */
    CHECK(vireo_session_token_generate(&token,&generated),VIREO_OK);uint64_t second=login(user,&generated);CHECK(vireo_session_token_clear(&token),VIREO_OK);
    vireo_mysql_session_identity_t another={second,user,2000,9000};(void)check(&generated,2000,VIREO_OK,VIREO_MYSQL_SESSION_ISSUE_NONE,&another);
    (void)check(&digest,UINT64_MAX,VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_SESSION_REVOKED,NULL);
    /* 全零是合法数据库摘要值，不表示它是全零token的摘要。 */
    vireo_session_token_digest_t all_zero={{0}};uint64_t zero_session=login(user,&all_zero);
    vireo_mysql_session_identity_t zero_expected={zero_session,user,2000,9000};(void)check(&all_zero,2000,VIREO_OK,VIREO_MYSQL_SESSION_ISSUE_NONE,&zero_expected);
    uint64_t bob=register_user("bob");CHECK(vireo_session_token_generate(&token,&wrong),VIREO_OK);uint64_t bob_session=login(bob,&wrong);CHECK(vireo_session_token_clear(&token),VIREO_OK);
    vireo_mysql_session_identity_t bob_expected={bob_session,bob,2000,9000};(void)check(&wrong,2000,VIREO_OK,VIREO_MYSQL_SESSION_ISSUE_NONE,&bob_expected);
    workers(&generated,&another);failures(&generated);
    /* 最大ID/时间由schema允许；放在所有自增插入之后。 */
    mutate("INSERT INTO users(id,username,username_key,password_hash,status,created_at_ms,updated_at_ms) SELECT 18446744073709551615,'maximum','maximum',password_hash,1,0,0 FROM users WHERE username_key='alice'");
    mutate("INSERT INTO sessions(id,user_id,token_digest,status,issued_at_ms,expires_at_ms,revoked_at_ms,last_seen_at_ms) VALUES(18446744073709551615,18446744073709551615,UNHEX(REPEAT('5A',32)),1,0,18446744073709551615,NULL,0)");
    vireo_session_token_digest_t maximum;memset(&maximum,0x5a,sizeof(maximum));vireo_mysql_session_identity_t max_expected={UINT64_MAX,UINT64_MAX,0,UINT64_MAX};
    (void)check(&maximum,0,VIREO_OK,VIREO_MYSQL_SESSION_ISSUE_NONE,&max_expected);
    (void)check(&maximum,UINT64_MAX-1,VIREO_OK,VIREO_MYSQL_SESSION_ISSUE_NONE,&max_expected);
    (void)check(&maximum,UINT64_MAX,VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_SESSION_EXPIRED,NULL);
    vireo_mysql_lease_t leases[4]={{0}};vireo_mysql_pool_acquisition_t acquired;
    for(size_t i=0;i<4;++i) { CHECK(vireo_mysql_pool_acquire(thread,pool,0,leases+i,&acquired,NULL),VIREO_OK); }
    (void)check(&generated,2000,VIREO_RESULT_BUSY,VIREO_MYSQL_SESSION_ISSUE_NONE,NULL);
    for(size_t i=0;i<4;++i) { vireo_mysql_pool_release_t released;CHECK(vireo_mysql_pool_release(thread,pool,leases+i,VIREO_MYSQL_POOL_RECYCLE,&released,NULL),VIREO_OK); }
    bool closed;CHECK(vireo_mysql_pool_close(pool,&closed,NULL),VIREO_OK);assert(closed);
    (void)check(&generated,2000,VIREO_RESULT_CANCELLED,VIREO_MYSQL_SESSION_ISSUE_NONE,NULL);
    CHECK(vireo_mysql_user_repository_destroy(&repo,NULL),VIREO_OK);CHECK(vireo_mysql_pool_destroy(thread,&pool,NULL),VIREO_OK);
    CHECK(vireo_mysql_connection_destroy(thread,&observer),VIREO_OK);CHECK(vireo_mysql_thread_detach(&thread),VIREO_OK);CHECK(vireo_mysql_runtime_destroy(&runtime),VIREO_OK);
    assert(fd_count()==fd);memset(password,0,sizeof(password));
    printf("PASS %zu real session observations: registration/credential/verify/login/token-digest chain, exact validity interval, revocation/account state, read-only identity, two workers, failure cleanup, FD %zu -> %zu\n",cases,fd,fd_count());return 0;
}
