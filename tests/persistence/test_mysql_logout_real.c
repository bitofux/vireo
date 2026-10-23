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
static vireo_mysql_logout_report_t logout(uint64_t user,uint64_t session,unsigned char event,uint64_t when,vireo_result_t want)
{
    vireo_mysql_logout_input_t in={.user_id=user,.session_id=session,.request_id={0},.occurred_at_ms=when,.latency_us=97};in.request_id[15]=event;
    vireo_mysql_logout_report_t out;CHECK(vireo_mysql_user_repository_logout(repo,&in,0,&out,NULL),want);++cases;return out;
}
static void revoked(uint64_t session,uint64_t when)
{
    char sql[512],time[32];(void)snprintf(sql,sizeof(sql),"SELECT status,revoked_at_ms,last_seen_at_ms FROM sessions WHERE id=%llu",(unsigned long long)session);
    (void)snprintf(time,sizeof(time),"%llu",(unsigned long long)when);vireo_mysql_statement_t *s=query(sql);row(s);cell(s,0,"2",1);cell(s,1,time,strlen(time));cell(s,2,"2000",4);end(&s);
}
static void audit(const vireo_mysql_logout_report_t *out,uint64_t user,unsigned char event,uint64_t when)
{
    assert(out->commit==VIREO_MYSQL_LOGOUT_COMMITTED && !out->already_revoked && out->audit_id && out->session_id && out->revoked_at_ms==when);
    char sql[768];(void)snprintf(sql,sizeof(sql),"SELECT COUNT(*) FROM operation_audits WHERE id=%llu AND user_id=%llu AND session_id=%llu AND action=3 AND target_type=2 AND target_id=%llu AND target_hash IS NULL AND status=0 AND latency_us=97 AND OCTET_LENGTH(detail)=0 AND occurred_at_ms=%llu",(unsigned long long)out->audit_id,(unsigned long long)user,(unsigned long long)out->session_id,(unsigned long long)out->session_id,(unsigned long long)when);scalar(sql,"1");
    (void)snprintf(sql,sizeof(sql),"SELECT request_id FROM operation_audits WHERE id=%llu",(unsigned long long)out->audit_id);unsigned char request[16]={0};request[15]=event;vireo_mysql_statement_t *s=query(sql);row(s);cell(s,0,request,16);end(&s);
}
static void rejected(uint64_t user,uint64_t session,unsigned char event,uint64_t when,vireo_result_t want,vireo_mysql_logout_issue_t issue)
{
    char before[256],after[256];snapshot(before);vireo_mysql_logout_report_t out=logout(user,session,event,when,want);
    assert(out.issue==issue && out.commit==VIREO_MYSQL_LOGOUT_NOT_COMMITTED && out.rollback_confirmed && !out.cleanup_pending && !out.session_id && !out.audit_id && !out.revoked_at_ms && !out.already_revoked);
    snapshot(after);assert(!strcmp(before,after));
}
static uint64_t new_session(uint64_t user,vireo_session_token_digest_t *digest)
{ vireo_session_token_t token;CHECK(vireo_session_token_generate(&token,digest),VIREO_OK);uint64_t id=login(user,digest);CHECK(vireo_session_token_clear(&token),VIREO_OK);return id; }
enum fault_mode { HEALTHY, COMMIT_BEFORE, COMMIT_AFTER, COMMIT_CLOSE_CONSUMED, COMMIT_CLOSE_PENDING, RELEASE_PENDING, RELEASE_CONSUMED, UPDATE_CLOSE_PENDING, AUDIT_FAILURE };
static enum fault_mode fault;
static enum { OTHER, COMMIT_OP, UPDATE_OP, AUDIT_OP } current;
static vireo_result_t fault_prepare(vireo_mysql_thread_t *t,vireo_mysql_connection_t *c,const char *sql,size_t n,const vireo_mysql_statement_limits_t *limits,vireo_mysql_statement_t **s,vireo_mysql_error_t *e)
{
    current=!strcmp(sql,"COMMIT") ? COMMIT_OP : (!strncmp(sql,"UPDATE sessions SET",19) ? UPDATE_OP : (!strncmp(sql,"INSERT INTO operation_audits",27) ? AUDIT_OP : OTHER));
    return vireo_mysql_statement_prepare(t,c,sql,n,limits,s,e);
}
static vireo_result_t fault_execute(vireo_mysql_thread_t *t,vireo_mysql_statement_t *s,const vireo_mysql_parameter_t *p,size_t n,vireo_mysql_execution_t *out,vireo_mysql_error_t *e)
{
    if((current==COMMIT_OP && fault==COMMIT_BEFORE) || (current==AUDIT_OP && fault==AUDIT_FAILURE)) {
        *out=(vireo_mysql_execution_t){.execution_started=true};*e=(vireo_mysql_error_t){.stage=VIREO_MYSQL_STAGE_STATEMENT_EXECUTE,.mysql_code=2013};return VIREO_RESULT_DATABASE;
    }
    vireo_result_t result=vireo_mysql_statement_execute(t,s,p,n,out,e);
    if(result==VIREO_OK && current==COMMIT_OP && fault==COMMIT_AFTER) { *e=(vireo_mysql_error_t){.stage=VIREO_MYSQL_STAGE_STATEMENT_EXECUTE,.mysql_code=2013};return VIREO_RESULT_DATABASE; }return result;
}
static vireo_result_t fault_close(vireo_mysql_thread_t *t,vireo_mysql_statement_t **s,vireo_mysql_error_t *e)
{
    if((current==COMMIT_OP && fault==COMMIT_CLOSE_PENDING) || (current==UPDATE_OP && fault==UPDATE_CLOSE_PENDING)) { *e=(vireo_mysql_error_t){.stage=VIREO_MYSQL_STAGE_STATEMENT_CLOSE};return VIREO_RESULT_BUSY; }
    vireo_result_t result=vireo_mysql_statement_destroy(t,s,e);
    if(result==VIREO_OK && current==COMMIT_OP && fault==COMMIT_CLOSE_CONSUMED) { *e=(vireo_mysql_error_t){.stage=VIREO_MYSQL_STAGE_STATEMENT_CLOSE,.mysql_code=2013};return VIREO_RESULT_DATABASE; }return result;
}
static vireo_result_t fault_release(vireo_mysql_thread_t *t,vireo_mysql_pool_t *p,vireo_mysql_lease_t *l,vireo_mysql_pool_disposition_t d,vireo_mysql_pool_release_t *out,vireo_mysql_pool_error_t *e)
{
    if(fault==RELEASE_PENDING) { *out=(vireo_mysql_pool_release_t){0};*e=(vireo_mysql_pool_error_t){.stage=VIREO_MYSQL_POOL_STAGE_LOCK};return VIREO_RESULT_INTERNAL; }
    vireo_result_t result=vireo_mysql_pool_release(t,p,l,d,out,e);
    if(result==VIREO_OK && fault==RELEASE_CONSUMED) { *e=(vireo_mysql_pool_error_t){.stage=VIREO_MYSQL_POOL_STAGE_RESET};return VIREO_RESULT_DATABASE; }return result;
}
static void failures(uint64_t user)
{
    vireo_mysql_user_repository_ops_t ops=vireo_mysql_user_repository_native_ops;ops.prepare=fault_prepare;ops.execute=fault_execute;ops.close=fault_close;ops.release=fault_release;
    for(enum fault_mode mode=COMMIT_BEFORE;mode<=AUDIT_FAILURE;mode=(enum fault_mode)(mode+1)) {
        vireo_session_token_digest_t digest;uint64_t session=new_session(user,&digest);CHECK(vireo_mysql_user_repository_destroy(&repo,NULL),VIREO_OK);
        CHECK(vireo_mysql_user_repository_create_with_ops(thread,pool,&policy,&repo,NULL,&ops),VIREO_OK);fault=mode;
        bool pending=mode==COMMIT_CLOSE_PENDING || mode==RELEASE_PENDING || mode==UPDATE_CLOSE_PENDING;
        vireo_result_t want=mode==RELEASE_PENDING ? VIREO_RESULT_INTERNAL : (pending ? VIREO_RESULT_BUSY : VIREO_RESULT_DATABASE);
        vireo_mysql_logout_report_t out=logout(user,session,(unsigned char)(100+(unsigned int)mode),3000,want);
        bool committed=mode>=COMMIT_CLOSE_CONSUMED && mode<=RELEASE_CONSUMED;
        bool unknown=mode==COMMIT_BEFORE || mode==COMMIT_AFTER;
        assert(out.commit==(committed ? VIREO_MYSQL_LOGOUT_COMMITTED : (unknown ? VIREO_MYSQL_LOGOUT_UNKNOWN : VIREO_MYSQL_LOGOUT_NOT_COMMITTED)));
        assert(out.cleanup_pending==pending && !out.already_revoked && out.rollback_confirmed==(mode==AUDIT_FAILURE));
        if(committed) { assert(out.session_id==session && out.audit_id && out.revoked_at_ms==3000); }
        else { assert(!out.session_id && !out.audit_id && !out.revoked_at_ms); }
        if(pending) {
            vireo_mysql_registration_report_t a;vireo_mysql_login_report_t b;vireo_mysql_user_credentials_t c;vireo_mysql_credentials_report_t d;
            vireo_mysql_session_identity_t identity;vireo_mysql_session_report_t state;vireo_mysql_logout_report_t other;
            CHECK(vireo_mysql_user_repository_register(repo,NULL,0,&a,NULL),VIREO_RESULT_BUSY);
            CHECK(vireo_mysql_user_repository_login(repo,NULL,0,&b,NULL),VIREO_RESULT_BUSY);
            CHECK(vireo_mysql_user_repository_find_credentials(repo,NULL,0,0,&c,&d,NULL),VIREO_RESULT_BUSY);
            CHECK(vireo_mysql_user_repository_find_session(repo,NULL,0,0,&identity,&state,NULL),VIREO_RESULT_BUSY);
            CHECK(vireo_mysql_user_repository_logout(repo,NULL,0,&other,NULL),VIREO_RESULT_BUSY);
            assert(a.cleanup_pending && b.cleanup_pending && d.cleanup_pending && state.cleanup_pending && other.cleanup_pending);
            CHECK(vireo_mysql_user_repository_destroy(&repo,NULL),mode==RELEASE_PENDING ? VIREO_RESULT_INTERNAL : VIREO_RESULT_BUSY);assert(repo);
        }
        fault=HEALTHY;CHECK(vireo_mysql_user_repository_destroy(&repo,NULL),VIREO_OK);refill();
        CHECK(vireo_mysql_user_repository_create(thread,pool,&policy,&repo,NULL),VIREO_OK);
        bool persisted=committed || mode==COMMIT_AFTER;
        char sql[256];(void)snprintf(sql,sizeof(sql),"SELECT status FROM sessions WHERE id=%llu",(unsigned long long)session);scalar(sql,persisted ? "2" : "1");
        (void)snprintf(sql,sizeof(sql),"SELECT COUNT(*) FROM operation_audits WHERE action=3 AND session_id=%llu",(unsigned long long)session);scalar(sql,persisted ? "1" : "0");
        if(persisted) { revoked(session,3000);(void)check(&digest,3000,VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_SESSION_REVOKED,NULL); }
        else { vireo_mysql_session_identity_t expected={session,user,2000,9000};(void)check(&digest,3000,VIREO_OK,VIREO_MYSQL_SESSION_ISSUE_NONE,&expected); }
    }
    puts("PASS real DB boundary injections: unknown COMMIT before/after with different durable outcomes; committed cleanup errors preserve receipt; pending rollback ownership; no real wire fault claimed");
}
static pthread_barrier_t barrier;
struct worker { vireo_mysql_logout_input_t input;vireo_mysql_logout_report_t out; };
static void *logout_worker(void *arg)
{
    struct worker *w=arg;vireo_mysql_thread_t *t=NULL;vireo_mysql_user_repository_t *repository=NULL;
    CHECK(vireo_mysql_thread_attach(runtime,&t,NULL),VIREO_OK);CHECK(vireo_mysql_user_repository_create(t,pool,&policy,&repository,NULL),VIREO_OK);
    int ready=pthread_barrier_wait(&barrier);assert(ready==0 || ready==PTHREAD_BARRIER_SERIAL_THREAD);
    CHECK(vireo_mysql_user_repository_logout(repository,&w->input,1000,&w->out,NULL),VIREO_OK);
    CHECK(vireo_mysql_user_repository_destroy(&repository,NULL),VIREO_OK);CHECK(vireo_mysql_thread_detach(&t),VIREO_OK);return NULL;
}
static void workers(uint64_t user,uint64_t session)
{
    struct worker w[2]={{.input={.user_id=user,.session_id=session,.request_id={0},.occurred_at_ms=3000,.latency_us=97}},
        {.input={.user_id=user,.session_id=session,.request_id={0},.occurred_at_ms=4000,.latency_us=97}}};w[0].input.request_id[15]=90;w[1].input.request_id[15]=91;
    assert(!pthread_barrier_init(&barrier,NULL,2));pthread_t threads[2];
    for(size_t i=0;i<2;++i) { assert(!pthread_create(threads+i,NULL,logout_worker,w+i)); }
    for(size_t i=0;i<2;++i) { assert(!pthread_join(threads[i],NULL));assert(w[i].out.commit==VIREO_MYSQL_LOGOUT_COMMITTED && w[i].out.session_id==session); }
    assert(!pthread_barrier_destroy(&barrier));size_t first=w[0].out.already_revoked ? 1U : 0U;
    assert(!w[first].out.already_revoked && w[1-first].out.already_revoked && !w[1-first].out.audit_id && w[0].out.revoked_at_ms==w[1].out.revoked_at_ms);
    audit(&w[first].out,user,w[first].input.request_id[15],w[first].input.occurred_at_ms);revoked(session,w[first].input.occurred_at_ms);
    char sql[256];(void)snprintf(sql,sizeof(sql),"SELECT COUNT(*) FROM operation_audits WHERE action=3 AND session_id=%llu",(unsigned long long)session);scalar(sql,"1");++cases;
    puts("PASS two OS workers competing to logout one session: one transition/audit, one already-revoked receipt, original timestamp preserved");
}
static size_t fd_count(void)
{ DIR *d=opendir("/proc/self/fd");assert(d);size_t n=0;while(readdir(d)) { ++n; }assert(!closedir(d));return n; }
int main(int argc,char **argv)
{
    assert(argc==5 && !setvbuf(stdout,NULL,_IONBF,0));char password[1026];FILE *f=fopen(argv[3],"r");assert(f && fgets(password,(int)sizeof(password),f) && !fclose(f));password[strcspn(password,"\n")]=0;
    struct sigaction sa={0};sa.sa_handler=SIG_IGN;assert(!sigemptyset(&sa.sa_mask) && !sigaction(SIGPIPE,&sa,NULL));
    CHECK(vireo_mysql_runtime_create(&runtime,NULL),VIREO_OK);CHECK(vireo_mysql_thread_attach(runtime,&thread,NULL),VIREO_OK);size_t fd=fd_count();
    vireo_mysql_connection_options_t options={argv[1],argv[2],password,argv[4],3,3,3};const vireo_mysql_migration_t *catalog=NULL;size_t count=0;
    CHECK(vireo_mysql_schema_catalog(&catalog,&count),VIREO_OK);vireo_mysql_migration_report_t migration;CHECK(vireo_mysql_migration_apply(thread,&options,catalog,count,&migration,NULL),VIREO_OK);assert(migration.ready && migration.steps_completed==15);
    CHECK(vireo_mysql_connection_open(thread,&options,&observer,NULL),VIREO_OK);vireo_mysql_pool_options_t config={options,4,4,VIREO_MYSQL_POOL_MEMORY_MAX};CHECK(vireo_mysql_pool_create(thread,&config,&pool,NULL),VIREO_OK);CHECK(vireo_mysql_user_repository_create(thread,pool,&policy,&repo,NULL),VIREO_OK);
    CHECK(vireo_password_hash_create(&policy,raw_password,sizeof(raw_password),phc,sizeof(phc),&phc_length),VIREO_OK);
    uint64_t user=register_user("alice"),bob=register_user("bob");vireo_mysql_user_credentials_t credentials;vireo_mysql_credentials_report_t found;
    CHECK(vireo_mysql_user_repository_find_credentials(repo,"alice",5,0,&credentials,&found,NULL),VIREO_OK);bool matches=false;
    CHECK(vireo_password_hash_verify(&policy,raw_password,sizeof(raw_password),credentials.password_hash,credentials.password_hash_length,&matches),VIREO_OK);assert(found.found && matches && credentials.user_id==user);
    CHECK(vireo_mysql_user_credentials_clear(&credentials),VIREO_OK);vireo_session_token_t token;vireo_session_token_digest_t digest,derived,other;
    CHECK(vireo_session_token_generate(&token,&digest),VIREO_OK);uint64_t session=login(user,&digest);CHECK(vireo_session_token_digest(&token,&derived),VIREO_OK);assert(!memcmp(&derived,&digest,sizeof(digest)));CHECK(vireo_session_token_clear(&token),VIREO_OK);
    uint64_t second=new_session(user,&other);vireo_mysql_session_identity_t expected={session,user,2000,9000};(void)check(&digest,2000,VIREO_OK,VIREO_MYSQL_SESSION_ISSUE_NONE,&expected);
    vireo_mysql_logout_report_t out=logout(user,session,77,3000,VIREO_OK);audit(&out,user,77,3000);revoked(session,3000);
    (void)check(&derived,3000,VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_SESSION_REVOKED,NULL);
    vireo_mysql_session_identity_t expected_other={second,user,2000,9000};(void)check(&other,3000,VIREO_OK,VIREO_MYSQL_SESSION_ISSUE_NONE,&expected_other);
    scalar("SELECT COUNT(*) FROM users WHERE username_key='alice' AND last_login_at_ms=2000 AND updated_at_ms=2000","1");
    char before[256],after[256];snapshot(before);out=logout(user,session,78,2500,VIREO_OK);assert(out.already_revoked && out.revoked_at_ms==3000 && !out.audit_id && out.session_id==session);snapshot(after);assert(!strcmp(before,after));
    rejected(999999,second,80,3000,VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_LOGOUT_USER_NOT_FOUND);
    rejected(user,999999,80,3000,VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_LOGOUT_SESSION_NOT_FOUND);
    rejected(bob,second,80,3000,VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_LOGOUT_OWNER_MISMATCH);
    rejected(user,second,80,1999,VIREO_RESULT_RANGE,VIREO_MYSQL_LOGOUT_TIME_BEFORE_ISSUED);
    rejected(user,second,77,3000,VIREO_RESULT_DATABASE,VIREO_MYSQL_LOGOUT_REQUEST_CONFLICT);
    (void)check(&other,3000,VIREO_OK,VIREO_MYSQL_SESSION_ISSUE_NONE,&expected_other);
    out=logout(user,second,79,10000,VIREO_OK);audit(&out,user,79,10000);revoked(second,10000);(void)check(&other,10000,VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_SESSION_REVOKED,NULL);
    uint64_t disabled=new_session(user,&other);mutate("UPDATE users SET status=2 WHERE username_key='alice'");out=logout(user,disabled,81,3000,VIREO_OK);audit(&out,user,81,3000);mutate("UPDATE users SET status=1 WHERE username_key='alice'");
    vireo_session_token_digest_t zero_digest={{0}};uint64_t zero_session=login(user,&zero_digest);out=logout(user,zero_session,82,3000,VIREO_OK);audit(&out,user,82,3000);(void)check(&zero_digest,3000,VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_SESSION_REVOKED,NULL);
    uint64_t concurrent=new_session(user,&other);workers(user,concurrent);failures(user);
    /* 最大ID/时间放最后，避免后续自增耗尽；撤销时间不受expires上界限制。 */
    mutate("INSERT INTO users(id,username,username_key,password_hash,status,created_at_ms,updated_at_ms) SELECT 18446744073709551615,'maximum','maximum',password_hash,1,0,0 FROM users WHERE username_key='alice'");
    mutate("INSERT INTO sessions(id,user_id,token_digest,status,issued_at_ms,expires_at_ms,revoked_at_ms,last_seen_at_ms) VALUES(18446744073709551615,18446744073709551615,UNHEX(REPEAT('5A',32)),1,0,18446744073709551615,NULL,0)");
    out=logout(UINT64_MAX,UINT64_MAX,120,UINT64_MAX,VIREO_OK);audit(&out,UINT64_MAX,120,UINT64_MAX);
    assert(out.session_id==UINT64_MAX && out.revoked_at_ms==UINT64_MAX);snapshot(before);out=logout(UINT64_MAX,UINT64_MAX,121,0,VIREO_OK);assert(out.already_revoked && out.revoked_at_ms==UINT64_MAX && !out.audit_id);snapshot(after);assert(!strcmp(before,after));
    vireo_mysql_lease_t leases[4]={{0}};vireo_mysql_pool_acquisition_t acquired;for(size_t i=0;i<4;++i) { CHECK(vireo_mysql_pool_acquire(thread,pool,0,leases+i,&acquired,NULL),VIREO_OK); }
    snapshot(before);out=logout(user,session,122,3000,VIREO_RESULT_BUSY);assert(!out.cleanup_pending && !out.session_id);snapshot(after);assert(!strcmp(before,after));
    for(size_t i=0;i<4;++i) { vireo_mysql_pool_release_t release;CHECK(vireo_mysql_pool_release(thread,pool,leases+i,VIREO_MYSQL_POOL_RECYCLE,&release,NULL),VIREO_OK); }
    bool closed;CHECK(vireo_mysql_pool_close(pool,&closed,NULL),VIREO_OK);assert(closed);snapshot(before);out=logout(user,session,122,3000,VIREO_RESULT_CANCELLED);assert(!out.cleanup_pending && !out.session_id);snapshot(after);assert(!strcmp(before,after));
    CHECK(vireo_mysql_user_repository_destroy(&repo,NULL),VIREO_OK);CHECK(vireo_mysql_pool_destroy(thread,&pool,NULL),VIREO_OK);CHECK(vireo_mysql_connection_destroy(thread,&observer),VIREO_OK);CHECK(vireo_mysql_thread_detach(&thread),VIREO_OK);CHECK(vireo_mysql_runtime_destroy(&runtime),VIREO_OK);
    assert(fd_count()==fd);memset(password,0,sizeof(password));printf("PASS %zu real logout observations: login/digest/lookup/logout/rejection, repeat/expiry/disabled/u64, audit rollback, two workers, unknown commit and cleanup facts, FD %zu -> %zu\n",cases,fd,fd_count());return 0;
}
