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
static const unsigned char raw_password[]={'s','e','c',0,'r','e','t'};
static void snapshot(char out[256])
{
    vireo_mysql_statement_t *s=query("SELECT CONCAT_WS('|',(SELECT COUNT(*) FROM users),"
        "(SELECT COUNT(*) FROM sessions),(SELECT COUNT(*) FROM operation_audits),"
        "(SELECT COALESCE(SUM(CRC32(CONCAT_WS(':',id,HEX(username_key),HEX(password_hash),status,created_at_ms,updated_at_ms,COALESCE(last_login_at_ms,'N')))),0) FROM users))");
    row(s);vireo_mysql_cell_view_t c;CHECK(vireo_mysql_statement_column(thread,s,0,&c),VIREO_OK);assert(!c.is_null && c.length<256);
    memcpy(out,c.data,c.length);out[c.length]=0;end(&s);
}
static uint64_t register_user(const void *key,size_t length)
{
    vireo_mysql_registration_input_t in={.username="display-name",.username_length=12,.username_key=key,
        .username_key_length=length,.password_hash=phc,.password_hash_length=phc_length,.occurred_at_ms=1000};
    assert(serial<250);in.request_id[15]=++serial;vireo_mysql_registration_report_t out;
    CHECK(vireo_mysql_user_repository_register(repo,&in,0,&out,NULL),VIREO_OK);assert(out.commit==VIREO_MYSQL_REGISTRATION_COMMITTED);return out.user_id;
}
static void refill(void)
{
    vireo_mysql_pool_info_t info;CHECK(vireo_mysql_pool_inspect(pool,&info),VIREO_OK);
    while(info.vacant) { vireo_mysql_pool_refill_t out;CHECK(vireo_mysql_pool_refill(thread,pool,&out,NULL),VIREO_OK);assert(out.restored);CHECK(vireo_mysql_pool_inspect(pool,&info),VIREO_OK); }
}
static void zero(const void *p,size_t n) { const unsigned char *bytes=p;for(size_t i=0;i<n;++i) { assert(bytes[i]==0); } }
static vireo_mysql_user_credentials_t lookup(const void *key,size_t length,uint64_t id,vireo_mysql_user_status_t status)
{
    char before[256],after[256];snapshot(before);vireo_mysql_user_credentials_t out;vireo_mysql_credentials_report_t report;
    CHECK(vireo_mysql_user_repository_find_credentials(repo,key,length,0,&out,&report,NULL),VIREO_OK);
    assert(report.found && !report.cleanup_pending && out.user_id==id && out.status==status);
    assert(out.password_hash_length==phc_length && !memcmp(out.password_hash,phc,phc_length));
    zero(out.password_hash+phc_length,sizeof(out.password_hash)-phc_length);
    vireo_mysql_pool_info_t info;CHECK(vireo_mysql_pool_inspect(pool,&info),VIREO_OK);assert(!info.leased);
    snapshot(after);assert(!strcmp(before,after));++cases;return out;
}
static void rejected(const void *key,size_t length,vireo_result_t want)
{
    char before[256],after[256];snapshot(before);vireo_mysql_user_credentials_t out;memset(&out,0xa5,sizeof(out));vireo_mysql_credentials_report_t report;
    CHECK(vireo_mysql_user_repository_find_credentials(repo,key,length,0,&out,&report,NULL),want);
    zero(&out,sizeof(out));assert(!report.found && !report.cleanup_pending);snapshot(after);assert(!strcmp(before,after));++cases;refill();
}
static void login_with(const vireo_mysql_user_credentials_t *credentials,vireo_result_t want,vireo_mysql_login_issue_t issue)
{
    vireo_mysql_login_input_t in={.user_id=credentials->user_id,.verified_password_hash=credentials->password_hash,
        .verified_password_hash_length=credentials->password_hash_length,.issued_at_ms=2000,.expires_at_ms=9000};
    assert(serial<250);in.request_id[15]=++serial;vireo_session_token_t token;
    CHECK(vireo_session_token_generate(&token,&in.token_digest),VIREO_OK);vireo_mysql_login_report_t out;
    CHECK(vireo_mysql_user_repository_login(repo,&in,0,&out,NULL),want);
    if(want==VIREO_OK) {
        assert(out.commit==VIREO_MYSQL_LOGIN_COMMITTED && out.session_id && out.audit_id);
        char sql[512];(void)snprintf(sql,sizeof(sql),"SELECT token_digest FROM sessions WHERE id=%llu",(unsigned long long)out.session_id);
        vireo_mysql_statement_t *s=query(sql);row(s);cell(s,0,in.token_digest.bytes,32);end(&s);
        (void)snprintf(sql,sizeof(sql),"SELECT COUNT(*) FROM users u JOIN sessions s ON s.user_id=u.id JOIN operation_audits a ON a.session_id=s.id AND a.target_id=s.id WHERE s.id=%llu AND a.id=%llu AND u.last_login_at_ms=2000 AND u.updated_at_ms=2000 AND a.action=2 AND a.target_type=2 AND a.status=0",(unsigned long long)out.session_id,(unsigned long long)out.audit_id);scalar(sql,"1");
    } else { assert(out.issue==issue && out.commit==VIREO_MYSQL_LOGIN_NOT_COMMITTED && out.rollback_confirmed && !out.session_id); }
    CHECK(vireo_session_token_clear(&token),VIREO_OK);++cases;
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
static void failures(void)
{
    CHECK(vireo_mysql_user_repository_destroy(&repo,NULL),VIREO_OK);vireo_mysql_user_repository_ops_t ops=vireo_mysql_user_repository_native_ops;
    ops.fetch=fault_fetch;ops.close=fault_close;ops.release=fault_release;
    for(enum fault_mode mode=FETCH_FAILURE;mode<=RELEASE_CONSUMED;mode=(enum fault_mode)(mode+1)) {
        fault=HEALTHY;CHECK(vireo_mysql_user_repository_create_with_ops(thread,pool,&policy,&repo,NULL,&ops),VIREO_OK);fault=mode;
        char before[256],after[256];snapshot(before);vireo_mysql_user_credentials_t out;vireo_mysql_credentials_report_t report;
        vireo_result_t want=mode==CLOSE_PENDING ? VIREO_RESULT_BUSY : (mode==RELEASE_PENDING ? VIREO_RESULT_INTERNAL : VIREO_RESULT_DATABASE);
        CHECK(vireo_mysql_user_repository_find_credentials(repo,"alice",5,0,&out,&report,NULL),want);zero(&out,sizeof(out));assert(!report.found);
        bool pending=mode==CLOSE_PENDING || mode==RELEASE_PENDING;assert(report.cleanup_pending==pending);
        if(pending) {
            vireo_mysql_registration_report_t registration;vireo_mysql_login_report_t login;
            CHECK(vireo_mysql_user_repository_register(repo,NULL,0,&registration,NULL),VIREO_RESULT_BUSY);
            CHECK(vireo_mysql_user_repository_login(repo,NULL,0,&login,NULL),VIREO_RESULT_BUSY);
            CHECK(vireo_mysql_user_repository_find_credentials(repo,"alice",5,0,&out,&report,NULL),VIREO_RESULT_BUSY);
            assert(registration.cleanup_pending && login.cleanup_pending && report.cleanup_pending);zero(&out,sizeof(out));
            CHECK(vireo_mysql_user_repository_destroy(&repo,NULL),mode==CLOSE_PENDING ? VIREO_RESULT_BUSY : VIREO_RESULT_INTERNAL);assert(repo);
        }
        fault=HEALTHY;CHECK(vireo_mysql_user_repository_destroy(&repo,NULL),VIREO_OK);refill();snapshot(after);assert(!strcmp(before,after));++cases;
    }
    CHECK(vireo_mysql_user_repository_create(thread,pool,&policy,&repo,NULL),VIREO_OK);
    puts("PASS real DB with boundary injections: fetch/close/release failures publish no credentials; residual statement/lease block three methods until destroy; no wire fault claimed");
}
struct reader { uint64_t user;vireo_mysql_user_credentials_t out; };
static void *read_worker(void *arg)
{
    struct reader *reader=arg;vireo_mysql_thread_t *t=NULL;vireo_mysql_user_repository_t *repository=NULL;
    CHECK(vireo_mysql_thread_attach(runtime,&t,NULL),VIREO_OK);CHECK(vireo_mysql_user_repository_create(t,pool,&policy,&repository,NULL),VIREO_OK);
    vireo_mysql_credentials_report_t report;CHECK(vireo_mysql_user_repository_find_credentials(repository,"alice",5,1000,&reader->out,&report,NULL),VIREO_OK);
    assert(report.found && !report.cleanup_pending && reader->out.user_id==reader->user);
    CHECK(vireo_mysql_user_repository_destroy(&repository,NULL),VIREO_OK);CHECK(vireo_mysql_thread_detach(&t),VIREO_OK);return NULL;
}
static void workers(uint64_t user)
{
    struct reader readers[2]={{.user=user},{.user=user}};pthread_t threads[2];
    for(size_t i=0;i<2;++i) { assert(!pthread_create(threads+i,NULL,read_worker,readers+i)); }
    for(size_t i=0;i<2;++i) { assert(!pthread_join(threads[i],NULL));assert(readers[i].out.password_hash_length==phc_length && !memcmp(readers[i].out.password_hash,phc,phc_length)); }
    CHECK(vireo_mysql_user_credentials_clear(&readers[0].out),VIREO_OK);zero(&readers[0].out,sizeof(readers[0].out));assert(readers[1].out.user_id==user);
    CHECK(vireo_mysql_user_credentials_clear(&readers[1].out),VIREO_OK);++cases;
    puts("PASS two OS workers with own guards/repositories, shared pool, independent credential values surviving worker detach");
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
    CHECK(vireo_mysql_migration_apply(thread,&options,catalog,count,&migration,NULL),VIREO_OK);assert(migration.ready && migration.steps_completed==16);
    CHECK(vireo_mysql_connection_open(thread,&options,&observer,NULL),VIREO_OK);
    vireo_mysql_pool_options_t config={options,4,4,VIREO_MYSQL_POOL_MEMORY_MAX};CHECK(vireo_mysql_pool_create(thread,&config,&pool,NULL),VIREO_OK);
    CHECK(vireo_mysql_user_repository_create(thread,pool,&policy,&repo,NULL),VIREO_OK);
    CHECK(vireo_password_hash_create(&policy,raw_password,sizeof(raw_password),phc,sizeof(phc),&phc_length),VIREO_OK);
    uint64_t user=register_user("alice",5);vireo_mysql_user_credentials_t credentials=lookup("alice",5,user,VIREO_MYSQL_USER_STATUS_ACTIVE);
    /* 归还连接甚至destroy R后，拥有值仍可用；昂贵验密不占池租约。 */
    CHECK(vireo_mysql_user_repository_destroy(&repo,NULL),VIREO_OK);bool matches=false;
    CHECK(vireo_password_hash_verify(&policy,raw_password,sizeof(raw_password),credentials.password_hash,credentials.password_hash_length,&matches),VIREO_OK);assert(matches);
    CHECK(vireo_mysql_user_repository_create(thread,pool,&policy,&repo,NULL),VIREO_OK);login_with(&credentials,VIREO_OK,0);
    CHECK(vireo_password_hash_verify(&policy,"wrong",5,credentials.password_hash,credentials.password_hash_length,&matches),VIREO_OK);assert(!matches);
    /* 查询时active，之后禁用或改PHC：旧验密快照不能创建Session。 */
    mutate("UPDATE users SET status=2 WHERE username_key='alice'");vireo_mysql_user_credentials_t disabled=lookup("alice",5,user,VIREO_MYSQL_USER_STATUS_DISABLED);
    login_with(&credentials,VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_LOGIN_USER_DISABLED);CHECK(vireo_mysql_user_credentials_clear(&disabled),VIREO_OK);
    mutate("UPDATE users SET status=1,password_hash=REPLACE(password_hash,'t=3','t=4') WHERE username_key='alice'");
    login_with(&credentials,VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_LOGIN_PASSWORD_CHANGED);
    char sql[512];(void)snprintf(sql,sizeof(sql),"UPDATE users SET password_hash='%.*s' WHERE username_key='alice'",(int)phc_length,phc);mutate(sql);
    CHECK(vireo_mysql_user_credentials_clear(&credentials),VIREO_OK);zero(&credentials,sizeof(credentials));
    rejected("ALICE",5,VIREO_RESULT_NOT_FOUND);rejected("alice ",6,VIREO_RESULT_NOT_FOUND);rejected("' OR 1=1 --",11,VIREO_RESULT_NOT_FOUND);
    const unsigned char binary[4]={'a',0,'b',' '};uint64_t id=register_user(binary,sizeof(binary));credentials=lookup(binary,sizeof(binary),id,VIREO_MYSQL_USER_STATUS_ACTIVE);
    CHECK(vireo_mysql_user_credentials_clear(&credentials),VIREO_OK);rejected(binary,sizeof(binary)-1,VIREO_RESULT_NOT_FOUND);
    unsigned char maximum[256]={0};maximum[255]=1;id=register_user(maximum,sizeof(maximum));credentials=lookup(maximum,sizeof(maximum),id,VIREO_MYSQL_USER_STATUS_ACTIVE);CHECK(vireo_mysql_user_credentials_clear(&credentials),VIREO_OK);
    const unsigned char minimum[1]={0};id=register_user(minimum,sizeof(minimum));credentials=lookup(minimum,sizeof(minimum),id,VIREO_MYSQL_USER_STATUS_ACTIVE);CHECK(vireo_mysql_user_credentials_clear(&credentials),VIREO_OK);
    mutate("UPDATE users SET password_hash='bad' WHERE username_key='alice'");rejected("alice",5,VIREO_RESULT_PROTOCOL);
    mutate("UPDATE users SET password_hash='$argon2id$v=19$m=262145,t=3,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' WHERE username_key='alice'");rejected("alice",5,VIREO_RESULT_RANGE);
    (void)snprintf(sql,sizeof(sql),"UPDATE users SET password_hash='%.*s' WHERE username_key='alice'",(int)phc_length,phc);mutate(sql);
    char previous[128];size_t previous_length=phc_length;memcpy(previous,phc,phc_length);static const unsigned char salt[16]={1};
    assert(argon2id_hash_encoded(1,8,1,raw_password,sizeof(raw_password),salt,sizeof(salt),32,phc,sizeof(phc))==ARGON2_OK);phc_length=strlen(phc);
    (void)snprintf(sql,sizeof(sql),"UPDATE users SET password_hash='%.*s' WHERE username_key='alice'",(int)phc_length,phc);mutate(sql);
    credentials=lookup("alice",5,user,VIREO_MYSQL_USER_STATUS_ACTIVE);
    CHECK(vireo_password_hash_verify(&policy,raw_password,sizeof(raw_password),credentials.password_hash,credentials.password_hash_length,&matches),VIREO_OK);assert(matches);login_with(&credentials,VIREO_OK,0);CHECK(vireo_mysql_user_credentials_clear(&credentials),VIREO_OK);
    memcpy(phc,previous,previous_length);phc_length=previous_length;
    (void)snprintf(sql,sizeof(sql),"UPDATE users SET password_hash='%.*s' WHERE username_key='alice'",(int)phc_length,phc);mutate(sql);
    workers(user);failures();
    /* 最大持久ID可读；显式插入放最后，避免耗尽自增后再注册。 */
    (void)snprintf(sql,sizeof(sql),"INSERT INTO users(id,username,username_key,password_hash,status,created_at_ms,updated_at_ms) VALUES(18446744073709551615,'maximum','maximum','%.*s',1,1,1)",(int)phc_length,phc);mutate(sql);
    credentials=lookup("maximum",7,UINT64_MAX,VIREO_MYSQL_USER_STATUS_ACTIVE);CHECK(vireo_mysql_user_credentials_clear(&credentials),VIREO_OK);
    vireo_mysql_lease_t leases[4]={{0}};vireo_mysql_pool_acquisition_t acquired;
    for(size_t i=0;i<4;++i) { CHECK(vireo_mysql_pool_acquire(thread,pool,0,leases+i,&acquired,NULL),VIREO_OK); }
    rejected("alice",5,VIREO_RESULT_BUSY);
    for(size_t i=0;i<4;++i) { vireo_mysql_pool_release_t released;CHECK(vireo_mysql_pool_release(thread,pool,leases+i,VIREO_MYSQL_POOL_RECYCLE,&released,NULL),VIREO_OK); }
    bool closed;CHECK(vireo_mysql_pool_close(pool,&closed,NULL),VIREO_OK);assert(closed);
    /* 关闭后不能refill，单独检查失败输出。 */
    vireo_mysql_credentials_report_t report;memset(&credentials,0xa5,sizeof(credentials));
    CHECK(vireo_mysql_user_repository_find_credentials(repo,"alice",5,0,&credentials,&report,NULL),VIREO_RESULT_CANCELLED);assert(!report.found && !report.cleanup_pending);zero(&credentials,sizeof(credentials));++cases;
    CHECK(vireo_mysql_user_repository_destroy(&repo,NULL),VIREO_OK);CHECK(vireo_mysql_pool_destroy(thread,&pool,NULL),VIREO_OK);
    CHECK(vireo_mysql_connection_destroy(thread,&observer),VIREO_OK);CHECK(vireo_mysql_thread_detach(&thread),VIREO_OK);CHECK(vireo_mysql_runtime_destroy(&runtime),VIREO_OK);
    assert(fd_count()==fd);memset(password,0,sizeof(password));CHECK(vireo_mysql_user_credentials_clear(&credentials),VIREO_OK);
    printf("PASS %zu real credential observations: binary keys, read-only snapshots, independent lifetime, password verification and login chain, stale snapshot rejection, historical PHC, zero failure output, FD %zu -> %zu\n",cases,fd,fd_count());return 0;
}
