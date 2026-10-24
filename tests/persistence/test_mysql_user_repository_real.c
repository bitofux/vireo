#define _POSIX_C_SOURCE 200809L
#include "mysql_user_repository_internal.h"
#include <vireo/persistence/mysql_schema.h>
#include <assert.h>
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
static void snapshot(char out[256])
{
    vireo_mysql_statement_t *s=query("SELECT CONCAT_WS('|',"
        "(SELECT COUNT(*) FROM users),(SELECT COUNT(*) FROM file_nodes),(SELECT COUNT(*) FROM operation_audits),"
        "(SELECT COALESCE(SUM(CRC32(CONCAT_WS(':',id,HEX(username),HEX(username_key),HEX(password_hash),status,created_at_ms,updated_at_ms,COALESCE(last_login_at_ms,'N')))),0) FROM users),"
        "(SELECT COALESCE(SUM(CRC32(CONCAT_WS(':',id,owner_id,COALESCE(parent_id,'N'),HEX(name),node_type,state,COALESCE(HEX(object_hash),'N'),size,created_at_ms,updated_at_ms,COALESCE(deleted_at_ms,'N')))),0) FROM file_nodes),"
        "(SELECT COALESCE(SUM(CRC32(CONCAT_WS(':',id,HEX(request_id),COALESCE(user_id,'N'),COALESCE(session_id,'N'),action,target_type,COALESCE(target_id,'N'),COALESCE(HEX(target_hash),'N'),status,latency_us,HEX(detail),occurred_at_ms))),0) FROM operation_audits))");
    row(s);vireo_mysql_cell_view_t c;CHECK(vireo_mysql_statement_column(thread,s,0,&c),VIREO_OK);
    assert(!c.is_null && c.length<256);memcpy(out,c.data,c.length);out[c.length]=0;end(&s);
}
static vireo_mysql_registration_input_t make_input(const char *key)
{
    vireo_mysql_registration_input_t in={.username=key,.username_length=strlen(key),.username_key=key,
        .username_key_length=strlen(key),.password_hash=phc,.password_hash_length=phc_length,
        .occurred_at_ms=12345,.latency_us=678};
    assert(serial<250);in.request_id[15]=++serial;return in;
}
static void verify(const vireo_mysql_registration_input_t *in,const vireo_mysql_registration_report_t *out)
{
    assert(out->commit==VIREO_MYSQL_REGISTRATION_COMMITTED && out->user_id && out->root_node_id && out->audit_id);
    char sql[2048],expected[256];
    (void)snprintf(sql,sizeof(sql),"SELECT username,username_key,password_hash FROM users WHERE id=%llu",(unsigned long long)out->user_id);
    vireo_mysql_statement_t *s=query(sql);row(s);cell(s,0,in->username,in->username_length);
    cell(s,1,in->username_key,in->username_key_length);cell(s,2,in->password_hash,in->password_hash_length);end(&s);
    (void)snprintf(sql,sizeof(sql),"SELECT CONCAT_WS('|',status,created_at_ms,updated_at_ms,last_login_at_ms IS NULL) FROM users WHERE id=%llu",(unsigned long long)out->user_id);
    (void)snprintf(expected,sizeof(expected),"1|%llu|%llu|1",(unsigned long long)in->occurred_at_ms,(unsigned long long)in->occurred_at_ms);scalar(sql,expected);
    (void)snprintf(sql,sizeof(sql),"SELECT CONCAT_WS('|',owner_id,parent_id IS NULL,OCTET_LENGTH(name),node_type,state,object_hash IS NULL,size,created_at_ms,updated_at_ms,deleted_at_ms IS NULL,active_root_owner=owner_id) FROM file_nodes WHERE id=%llu",(unsigned long long)out->root_node_id);
    (void)snprintf(expected,sizeof(expected),"%llu|1|0|1|2|1|0|%llu|%llu|1|1",(unsigned long long)out->user_id,(unsigned long long)in->occurred_at_ms,(unsigned long long)in->occurred_at_ms);scalar(sql,expected);
    (void)snprintf(sql,sizeof(sql),"SELECT CONCAT_WS('|',user_id,session_id IS NULL,action,target_type,target_id,target_hash IS NULL,status,latency_us,OCTET_LENGTH(detail),occurred_at_ms) FROM operation_audits WHERE id=%llu",(unsigned long long)out->audit_id);
    (void)snprintf(expected,sizeof(expected),"%llu|1|1|1|%llu|1|0|%llu|0|%llu",(unsigned long long)out->user_id,(unsigned long long)out->user_id,(unsigned long long)in->latency_us,(unsigned long long)in->occurred_at_ms);scalar(sql,expected);
    (void)snprintf(sql,sizeof(sql),"SELECT request_id FROM operation_audits WHERE id=%llu",(unsigned long long)out->audit_id);
    s=query(sql);row(s);cell(s,0,in->request_id,16);end(&s);++cases;
}
static void unchanged(const vireo_mysql_registration_input_t *in,vireo_result_t want,
    vireo_mysql_registration_conflict_t conflict)
{
    char before[256],after[256];snapshot(before);vireo_mysql_registration_report_t out;vireo_mysql_user_repository_error_t error;
    CHECK(vireo_mysql_user_repository_register(repo,in,0,&out,&error),want);
    assert(out.commit==VIREO_MYSQL_REGISTRATION_NOT_COMMITTED && !out.user_id && !out.root_node_id && !out.audit_id && !out.cleanup_pending && out.conflict==conflict);
    if(conflict) { assert(error.database.mysql_code==1062 && out.rollback_confirmed); }
    snapshot(after);assert(!strcmp(before,after));++cases;
}
enum fault_mode { HEALTHY, ROOT_FAILURE, UNKNOWN_ROLLED_BACK, UNKNOWN_COMMITTED, COMMIT_CLOSE, RELEASE_PENDING, RELEASE_CONSUMED };
static enum fault_mode fault;
static bool current_root,current_commit;
static vireo_result_t fault_prepare(vireo_mysql_thread_t *t,vireo_mysql_connection_t *c,
    const char *sql,size_t n,const vireo_mysql_statement_limits_t *l,vireo_mysql_statement_t **s,vireo_mysql_error_t *e)
{
    current_root=strncmp(sql,"INSERT INTO file_nodes(",23)==0;current_commit=strcmp(sql,"COMMIT")==0;
    return vireo_mysql_statement_prepare(t,c,sql,n,l,s,e);
}
static vireo_result_t fault_execute(vireo_mysql_thread_t *t,vireo_mysql_statement_t *s,
    const vireo_mysql_parameter_t *p,size_t n,vireo_mysql_execution_t *out,vireo_mysql_error_t *e)
{
    if((fault==ROOT_FAILURE && current_root) || (fault==UNKNOWN_ROLLED_BACK && current_commit)) {
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
static void failures(void)
{
    CHECK(vireo_mysql_user_repository_destroy(&repo,NULL),VIREO_OK);
    vireo_mysql_user_repository_ops_t ops=vireo_mysql_user_repository_native_ops;
    ops.prepare=fault_prepare;ops.execute=fault_execute;ops.close=fault_close;ops.release=fault_release;
    CHECK(vireo_mysql_user_repository_create_with_ops(thread,pool,&policy,&repo,NULL,&ops),VIREO_OK);
    fault=ROOT_FAILURE;vireo_mysql_registration_input_t in=make_input("root-failure");unchanged(&in,VIREO_RESULT_DATABASE,0);
    fault=UNKNOWN_ROLLED_BACK;in=make_input("unknown-rollback");
    char before[256],after[256];snapshot(before);vireo_mysql_registration_report_t out;vireo_mysql_user_repository_error_t error;
    CHECK(vireo_mysql_user_repository_register(repo,&in,0,&out,&error),VIREO_RESULT_DATABASE);
    assert(out.commit==VIREO_MYSQL_REGISTRATION_UNKNOWN && !out.rollback_confirmed && !out.user_id && !out.cleanup_pending);
    snapshot(after);assert(!strcmp(before,after));++cases;
    fault=UNKNOWN_COMMITTED;in=make_input("unknown-commit");
    CHECK(vireo_mysql_user_repository_register(repo,&in,0,&out,&error),VIREO_RESULT_DATABASE);
    assert(out.commit==VIREO_MYSQL_REGISTRATION_UNKNOWN && !out.rollback_confirmed && !out.user_id && !out.cleanup_pending);
    scalar("SELECT COUNT(*) FROM users u JOIN file_nodes n ON n.owner_id=u.id JOIN operation_audits a ON a.user_id=u.id AND a.target_id=u.id WHERE u.username_key='unknown-commit' AND n.parent_id IS NULL AND a.action=1","1");++cases;
    for(enum fault_mode mode=COMMIT_CLOSE;mode<=RELEASE_CONSUMED;mode=(enum fault_mode)(mode+1)) {
        fault=mode;char key[32];(void)snprintf(key,sizeof(key),"post-commit-%d",(int)mode);in=make_input(key);
        CHECK(vireo_mysql_user_repository_register(repo,&in,0,&out,&error),mode==COMMIT_CLOSE ? VIREO_RESULT_DATABASE : VIREO_RESULT_INTERNAL);
        verify(&in,&out);assert(out.cleanup_pending==(mode==RELEASE_PENDING));
        if(mode==RELEASE_PENDING) {
            vireo_mysql_pool_info_t info;CHECK(vireo_mysql_pool_inspect(pool,&info),VIREO_OK);assert(info.leased==1);
            CHECK(vireo_mysql_user_repository_register(repo,&in,0,&out,NULL),VIREO_RESULT_BUSY);assert(out.cleanup_pending);
            CHECK(vireo_mysql_user_repository_destroy(&repo,NULL),VIREO_RESULT_INTERNAL);assert(repo);
            fault=HEALTHY;CHECK(vireo_mysql_user_repository_destroy(&repo,NULL),VIREO_OK);assert(!repo);
            CHECK(vireo_mysql_user_repository_create_with_ops(thread,pool,&policy,&repo,NULL,&ops),VIREO_OK);
        }
    }
    fault=HEALTHY;CHECK(vireo_mysql_user_repository_destroy(&repo,NULL),VIREO_OK);
    CHECK(vireo_mysql_user_repository_create(thread,pool,&policy,&repo,NULL),VIREO_OK);
    puts("PASS real DB plus repository-boundary faults: root rollback, identical UNKNOWN with actual rollback/commit, committed IDs survive close/release errors, residual lease retained until destroy; no real wire fault claimed");
}
struct racer { pthread_barrier_t *barrier;vireo_mysql_registration_input_t input;vireo_mysql_registration_report_t out;vireo_result_t result; };
static void *race(void *arg)
{
    struct racer *r=arg;vireo_mysql_thread_t *t=NULL;vireo_mysql_user_repository_t *repository=NULL;
    CHECK(vireo_mysql_thread_attach(runtime,&t,NULL),VIREO_OK);
    CHECK(vireo_mysql_user_repository_create(t,pool,&policy,&repository,NULL),VIREO_OK);
    int code=pthread_barrier_wait(r->barrier);assert(code==0 || code==PTHREAD_BARRIER_SERIAL_THREAD);
    errno=EDOM;r->result=vireo_mysql_user_repository_register(repository,&r->input,1000,&r->out,NULL);assert(errno==EDOM);
    CHECK(vireo_mysql_user_repository_destroy(&repository,NULL),VIREO_OK);CHECK(vireo_mysql_thread_detach(&t),VIREO_OK);return NULL;
}
static void concurrency(void)
{
    pthread_barrier_t barrier;assert(!pthread_barrier_init(&barrier,NULL,2));
    struct racer r[2]={{.barrier=&barrier,.input=make_input("race")},{.barrier=&barrier,.input=make_input("race")}};
    pthread_t threads[2];for(size_t i=0;i<2;++i) { assert(!pthread_create(threads+i,NULL,race,r+i)); }
    for(size_t i=0;i<2;++i) { assert(!pthread_join(threads[i],NULL)); }assert(!pthread_barrier_destroy(&barrier));
    size_t won=0;
    for(size_t i=0;i<2;++i) {
        if(r[i].result==VIREO_OK) { ++won;verify(&r[i].input,&r[i].out); }
        else { assert(r[i].result==VIREO_RESULT_DATABASE && r[i].out.conflict==VIREO_MYSQL_REGISTRATION_USERNAME_CONFLICT && r[i].out.rollback_confirmed && !r[i].out.cleanup_pending && !r[i].out.user_id); }
    }
    assert(won==1);scalar("SELECT COUNT(*) FROM users WHERE username_key='race'","1");
    scalar("SELECT COUNT(*) FROM file_nodes n LEFT JOIN users u ON u.id=n.owner_id WHERE u.id IS NULL","0");
    puts("PASS two OS workers, two guards/repositories, shared pool and same key: exactly one whole registration, one rolled-back conflict");
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
    const vireo_mysql_migration_t *catalog=NULL;size_t count=0;CHECK(vireo_mysql_schema_catalog(&catalog,&count),VIREO_OK);assert(count==10);
    vireo_mysql_migration_report_t migration;CHECK(vireo_mysql_migration_apply(thread,&options,catalog,count,&migration,NULL),VIREO_OK);assert(migration.ready && migration.steps_completed==16);
    CHECK(vireo_mysql_connection_open(thread,&options,&observer,NULL),VIREO_OK);
    vireo_mysql_pool_options_t config={options,4,4,VIREO_MYSQL_POOL_MEMORY_MAX};CHECK(vireo_mysql_pool_create(thread,&config,&pool,NULL),VIREO_OK);
    CHECK(vireo_mysql_user_repository_create(thread,pool,&policy,&repo,NULL),VIREO_OK);
    static const unsigned char raw_password[]={'s','e','c',0,'r','e','t'};
    CHECK(vireo_password_hash_create(&policy,raw_password,sizeof(raw_password),phc,sizeof(phc),&phc_length),VIREO_OK);
    vireo_mysql_registration_input_t in=make_input("alice");vireo_mysql_registration_report_t out;
    CHECK(vireo_mysql_user_repository_register(repo,&in,0,&out,NULL),VIREO_OK);verify(&in,&out);
    unsigned char original_id[16];memcpy(original_id,in.request_id,16);
    in=make_input("alice");unchanged(&in,VIREO_RESULT_DATABASE,VIREO_MYSQL_REGISTRATION_USERNAME_CONFLICT);
    in=make_input("audit-conflict");memcpy(in.request_id,original_id,16);unchanged(&in,VIREO_RESULT_DATABASE,VIREO_MYSQL_REGISTRATION_REQUEST_CONFLICT);
    scalar("SELECT COUNT(*) FROM users WHERE username_key='audit-conflict'","0");
    char name[260];for(size_t i=0;i<65;++i) { memcpy(name+i*4,"\xF0\x9F\x8C\xB1",4); }
    in=make_input("unicode64");in.username=name;in.username_length=256;in.occurred_at_ms=UINT64_MAX;in.latency_us=UINT64_MAX;
    CHECK(vireo_mysql_user_repository_register(repo,&in,0,&out,NULL),VIREO_OK);verify(&in,&out);
    in=make_input("unicode65");memset(name,'a',65);in.username=name;in.username_length=65;unchanged(&in,VIREO_RESULT_DATABASE,0);
    in=make_input("invalid-utf8");in.username="\xC0\xAF";in.username_length=2;unchanged(&in,VIREO_RESULT_DATABASE,0);
    const char binary_key[4]={'k',0,'e','y'};in=make_input("binary-key");in.username_key=binary_key;in.username_key_length=4;
    CHECK(vireo_mysql_user_repository_register(repo,&in,0,&out,NULL),VIREO_OK);verify(&in,&out);
    unsigned char max_key[256]={0};max_key[255]=1;in=make_input("max-key");in.username_key=max_key;in.username_key_length=sizeof(max_key);
    CHECK(vireo_mysql_user_repository_register(repo,&in,0,&out,NULL),VIREO_OK);verify(&in,&out);
    failures();
    /* 未知结果/残留清理使用DISCARD；管理方显式补槽，产品入口不自动重连。 */
    vireo_mysql_pool_info_t info;CHECK(vireo_mysql_pool_inspect(pool,&info),VIREO_OK);
    while(info.vacant) {
        vireo_mysql_pool_refill_t restored;CHECK(vireo_mysql_pool_refill(thread,pool,&restored,NULL),VIREO_OK);assert(restored.restored);
        CHECK(vireo_mysql_pool_inspect(pool,&info),VIREO_OK);
    }
    concurrency();
    /* 真实容量门禁：全部租出后register不得执行写；归还恢复基线。 */
    vireo_mysql_lease_t leases[4]={{0}};vireo_mysql_pool_acquisition_t a;
    for(size_t i=0;i<4;++i) { CHECK(vireo_mysql_pool_acquire(thread,pool,0,leases+i,&a,NULL),VIREO_OK);assert(a.acquired); }
    in=make_input("no-capacity");unchanged(&in,VIREO_RESULT_BUSY,0);
    for(size_t i=0;i<4;++i) { vireo_mysql_pool_release_t released;CHECK(vireo_mysql_pool_release(thread,pool,leases+i,VIREO_MYSQL_POOL_RECYCLE,&released,NULL),VIREO_OK);assert(released.released); }
    bool closed;CHECK(vireo_mysql_pool_close(pool,&closed,NULL),VIREO_OK);assert(closed);
    unchanged(&in,VIREO_RESULT_CANCELLED,0);
    CHECK(vireo_mysql_user_repository_destroy(&repo,NULL),VIREO_OK);CHECK(vireo_mysql_pool_destroy(thread,&pool,NULL),VIREO_OK);
    CHECK(vireo_mysql_connection_destroy(thread,&observer),VIREO_OK);CHECK(vireo_mysql_thread_detach(&thread),VIREO_OK);CHECK(vireo_mysql_runtime_destroy(&runtime),VIREO_OK);
    assert(fd_count()==fd);memset(password,0,sizeof(password));memset(phc,0,sizeof(phc));
    printf("PASS %zu real registration observations, exact user/root/audit fields, whole rollback and original rows preserved; FD %zu -> %zu\n",cases,fd,fd_count());return 0;
}
