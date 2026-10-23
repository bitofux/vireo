/* PROJECT : VIREO; FILE : test_mysql_node_mkdir_real.c; AUTHOR : bitofux;
 * DATE : 2026-10-21; BRIEF : 真实目录/审计原子事务、三态提交和受控双worker。 */
#define _POSIX_C_SOURCE 200809L
#include "mysql_node_repository_internal.h"
#include <vireo/persistence/mysql_schema.h>
#include <vireo/persistence/mysql_user_repository.h>
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(call,want) do { errno=EDOM; vireo_result_t got_=(call); if(got_!=(want)) { fprintf(stderr,"line %d result %d want %d\n",__LINE__,(int)got_,(int)(want)); abort(); } assert(errno==EDOM); } while(0)
static vireo_mysql_runtime_t *runtime;
static vireo_mysql_thread_t *thread;
static vireo_mysql_pool_t *pool;
static vireo_mysql_connection_t *observer;
static vireo_mysql_user_repository_t *users;
static vireo_mysql_node_repository_t *nodes;
static vireo_password_policy_t policy=VIREO_PASSWORD_POLICY_DEFAULT;
static char phc[VIREO_PASSWORD_ENCODED_CAPACITY];
static size_t phc_length,cases;
static unsigned char serial;
static _Thread_local uint64_t sample_ms=2000;
static _Thread_local size_t utc_calls;
static vireo_mysql_node_actor_t alice,bob;
static uint64_t alice_root,bob_root;
static const vireo_mysql_statement_limits_t limits={0,3,0,1024,32768};
static pthread_mutex_t mutex=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t condition;
static unsigned phase;
static bool release_first,second_started,second_done;
static struct timespec deadline(void)
{ struct timespec t;assert(!clock_gettime(CLOCK_MONOTONIC,&t));t.tv_sec+=10;return t; }
static void wait_flag(const bool *flag)
{ struct timespec t=deadline();while(!*flag) { assert(!pthread_cond_timedwait(&condition,&mutex,&t)); } }
static int fixed_utc(struct timespec *out)
{ ++utc_calls;*out=(struct timespec){.tv_sec=(time_t)(sample_ms/1000),.tv_nsec=(long)(sample_ms%1000)*1000000L};return 0; }
static int paused_utc(struct timespec *out)
{
    if(utc_calls==0) {
        assert(!pthread_mutex_lock(&mutex));phase=1;assert(!pthread_cond_broadcast(&condition));wait_flag(&release_first);
        assert(!second_done);assert(!pthread_mutex_unlock(&mutex));
    }
    return fixed_utc(out);
}
static vireo_mysql_statement_t *execute_sql(const char *sql,bool rows)
{
    vireo_mysql_statement_t *s=NULL;vireo_mysql_execution_t ex;
    CHECK(vireo_mysql_statement_prepare(thread,observer,sql,strlen(sql),&limits,&s,NULL),VIREO_OK);
    CHECK(vireo_mysql_statement_execute(thread,s,NULL,0,&ex,NULL),VIREO_OK);assert(ex.has_result==rows);return s;
}
static void mutate(const char *sql)
{ vireo_mysql_statement_t *s=execute_sql(sql,false);CHECK(vireo_mysql_statement_destroy(thread,&s,NULL),VIREO_OK); }
static uint64_t scalar(const char *sql)
{
    vireo_mysql_statement_t *s=execute_sql(sql,true);vireo_mysql_fetch_outcome_t fetched;vireo_mysql_cell_view_t c;
    CHECK(vireo_mysql_statement_fetch(thread,s,&fetched,NULL),VIREO_OK);assert(fetched==VIREO_MYSQL_FETCH_ROW);
    CHECK(vireo_mysql_statement_column(thread,s,0,&c),VIREO_OK);assert(!c.is_null && c.length<32);
    char b[32]={0};memcpy(b,c.data,c.length);char *end;errno=0;unsigned long long n=strtoull(b,&end,10);assert(!errno && !*end);
    CHECK(vireo_mysql_statement_fetch(thread,s,&fetched,NULL),VIREO_OK);assert(fetched==VIREO_MYSQL_FETCH_DONE);
    CHECK(vireo_mysql_statement_destroy(thread,&s,NULL),VIREO_OK);return (uint64_t)n;
}
static vireo_mysql_node_actor_t account(const char *name,uint64_t *root)
{
    vireo_mysql_registration_input_t in={.username=name,.username_length=strlen(name),.username_key=name,
        .username_key_length=strlen(name),.password_hash=phc,.password_hash_length=phc_length,.occurred_at_ms=1000};
    in.request_id[15]=++serial;vireo_mysql_registration_report_t reg;
    CHECK(vireo_mysql_user_repository_register(users,&in,0,&reg,NULL),VIREO_OK);assert(reg.commit==VIREO_MYSQL_REGISTRATION_COMMITTED);*root=reg.root_node_id;
    vireo_mysql_login_input_t login={.user_id=reg.user_id,.verified_password_hash=phc,.verified_password_hash_length=phc_length,.issued_at_ms=1000,.expires_at_ms=3000};
    login.token_digest.bytes[0]=serial;login.request_id[15]=++serial;vireo_mysql_login_report_t logged;
    CHECK(vireo_mysql_user_repository_login(users,&login,0,&logged,NULL),VIREO_OK);assert(logged.commit==VIREO_MYSQL_LOGIN_COMMITTED);
    return (vireo_mysql_node_actor_t){reg.user_id,logged.session_id};
}
static void zeroed(const void *p,size_t n)
{ const unsigned char *s=p;for(size_t i=0;i<n;++i) { assert(!s[i]); } }
static vireo_mysql_node_mkdir_input_t make_input(uint64_t parent,const void *name,size_t n)
{
    vireo_mysql_node_mkdir_input_t in={.parent_id=parent,.name=name,.name_length=n,.request_id={0x11}};
    assert(serial<250);in.request_id[15]=++serial;return in;
}
/* DISCARD不自动补槽；测试管理方在各故障场景结束后显式恢复容量。 */
static void refill_pool(void)
{
    vireo_mysql_pool_info_t info;CHECK(vireo_mysql_pool_inspect(pool,&info),VIREO_OK);
    size_t vacant=info.vacant;
    for(size_t i=0;i<vacant;++i) {
        vireo_mysql_pool_refill_t out;CHECK(vireo_mysql_pool_refill(thread,pool,&out,NULL),VIREO_OK);assert(out.restored);
    }
}
static vireo_mysql_node_mkdir_report_t create_dir(vireo_mysql_node_actor_t who,
    const vireo_mysql_node_mkdir_input_t *in,vireo_result_t want,vireo_mysql_node_issue_t issue)
{
    uint64_t before_nodes=scalar("SELECT COUNT(*) FROM file_nodes"),before_audits=scalar("SELECT COUNT(*) FROM operation_audits");
    vireo_mysql_node_mkdir_report_t out;memset(&out,0xa5,sizeof(out));vireo_mysql_node_error_t e;
    CHECK(vireo_mysql_node_repository_mkdir(nodes,&who,in,0,&out,&e),want);
    assert(out.issue==issue && !out.cleanup_pending);
    if(want==VIREO_OK) {
        assert(out.commit==VIREO_MYSQL_NODE_MKDIR_COMMITTED && out.node.id && out.audit_id && !out.rollback_confirmed);
        assert(out.node.owner_id==who.user_id && out.node.has_parent && out.node.parent_id==in->parent_id);
        assert(out.node.name_length==in->name_length && !memcmp(out.node.name,in->name,in->name_length));
        assert(out.node.kind==VIREO_MYSQL_NODE_DIRECTORY && !out.node.has_object_hash && !out.node.size);
        assert(out.node.created_at_ms==sample_ms && out.node.updated_at_ms==sample_ms);
        char sql[2048];int n=snprintf(sql,sizeof(sql),"SELECT COUNT(*) FROM operation_audits WHERE id=%llu AND user_id=%llu AND session_id=%llu AND action=5 AND target_type=3 AND target_id=%llu AND target_hash IS NULL AND status=0 AND latency_us=0 AND OCTET_LENGTH(detail)=0 AND occurred_at_ms=%llu",(unsigned long long)out.audit_id,(unsigned long long)who.user_id,(unsigned long long)who.session_id,(unsigned long long)out.node.id,(unsigned long long)sample_ms);
        assert(n>0 && (size_t)n<sizeof(sql) && scalar(sql)==1);
        vireo_mysql_node_value_t value;vireo_mysql_node_report_t r;
        CHECK(vireo_mysql_node_repository_stat(nodes,&who,out.node.id,0,&value,&r,NULL),VIREO_OK);
        assert(value.id==out.node.id && value.parent_id==in->parent_id && value.name_length==in->name_length && !memcmp(value.name,in->name,in->name_length));
    } else { assert(out.commit==VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED && !out.audit_id);zeroed(&out.node,sizeof(out.node)); }
    assert(scalar("SELECT COUNT(*) FROM file_nodes")==before_nodes+(want==VIREO_OK ? 1u : 0u));
    assert(scalar("SELECT COUNT(*) FROM operation_audits")==before_audits+(want==VIREO_OK ? 1u : 0u));++cases;refill_pool();return out;
}
enum fault { NONE, EXPIRE_AUDIT, LOST_COMMIT_REPLY, NO_NATIVE_COMMIT, COMMIT_CLOSE, RELEASE_PENDING, FAIL_UTC2 };
static enum fault fault;
static vireo_mysql_statement_t *commit_statement,*audit_statement;
static vireo_result_t fault_prepare(vireo_mysql_thread_t *t,vireo_mysql_connection_t *c,
    const char *sql,size_t n,const vireo_mysql_statement_limits_t *l,vireo_mysql_statement_t **out,vireo_mysql_error_t *e)
{
    vireo_result_t rc=vireo_mysql_statement_prepare(t,c,sql,n,l,out,e);
    if(rc==VIREO_OK) { if(!strcmp(sql,"COMMIT")) { commit_statement=*out; }if(strstr(sql,"INSERT INTO operation_audits")) { audit_statement=*out; } }
    return rc;
}
static vireo_result_t fault_execute(vireo_mysql_thread_t *t,vireo_mysql_statement_t *s,
    const vireo_mysql_parameter_t *p,size_t n,vireo_mysql_execution_t *out,vireo_mysql_error_t *e)
{
    if(s==commit_statement && fault==NO_NATIVE_COMMIT) {
        *out=(vireo_mysql_execution_t){0};*e=(vireo_mysql_error_t){.mysql_code=2013};return VIREO_RESULT_DATABASE;
    }
    vireo_result_t rc=vireo_mysql_statement_execute(t,s,p,n,out,e);
    if(rc==VIREO_OK && s==audit_statement && fault==EXPIRE_AUDIT) { sample_ms=3000; }
    if(rc==VIREO_OK && s==commit_statement && fault==LOST_COMMIT_REPLY) { e->mysql_code=2013;return VIREO_RESULT_DATABASE; }
    return rc;
}
static vireo_result_t fault_close(vireo_mysql_thread_t *t,vireo_mysql_statement_t **s,vireo_mysql_error_t *e)
{
    bool commit=*s==commit_statement;bool audit=*s==audit_statement;
    vireo_result_t rc=vireo_mysql_statement_destroy(t,s,e);
    if(*s==NULL) { if(commit) { commit_statement=NULL; }if(audit) { audit_statement=NULL; } }
    return rc==VIREO_OK && commit && fault==COMMIT_CLOSE ? VIREO_RESULT_DATABASE : rc;
}
static vireo_result_t fault_release(vireo_mysql_thread_t *t,vireo_mysql_pool_t *p,vireo_mysql_lease_t *lease,
    vireo_mysql_pool_disposition_t d,vireo_mysql_pool_release_t *out,vireo_mysql_pool_error_t *e)
{
    if(fault==RELEASE_PENDING) { *out=(vireo_mysql_pool_release_t){0};*e=(vireo_mysql_pool_error_t){0};return VIREO_RESULT_INTERNAL; }
    return vireo_mysql_pool_release(t,p,lease,d,out,e);
}
static int fault_utc(struct timespec *out)
{ if(fault==FAIL_UTC2 && utc_calls==1) { ++utc_calls;errno=EIO;return -1; }return fixed_utc(out); }
static void recreate(bool faults)
{
    CHECK(vireo_mysql_node_repository_destroy(&nodes,NULL),VIREO_OK);vireo_mysql_node_ops_t ops=vireo_mysql_node_native_ops;
    ops.utc=faults ? fault_utc : fixed_utc;
    if(faults) { ops.prepare=fault_prepare;ops.execute=fault_execute;ops.close=fault_close;ops.release=fault_release; }
    CHECK(vireo_mysql_node_repository_create_with_ops(thread,pool,&nodes,NULL,&ops),VIREO_OK);
}
static void fault_cases(void)
{
    recreate(true);
    for(enum fault which=EXPIRE_AUDIT;which<=FAIL_UTC2;which=(enum fault)(which+1)) {
        fault=which;sample_ms=2000;utc_calls=0;commit_statement=NULL;audit_statement=NULL;
        char name[32];int n=snprintf(name,sizeof(name),"fault-%u",(unsigned)which);assert(n>0 && (size_t)n<sizeof(name));
        vireo_mysql_node_mkdir_input_t in=make_input(alice_root,name,(size_t)n);
        uint64_t before_nodes=scalar("SELECT COUNT(*) FROM file_nodes"),before_audits=scalar("SELECT COUNT(*) FROM operation_audits");
        vireo_mysql_node_mkdir_report_t r;vireo_mysql_node_error_t e;
        vireo_result_t expected=which==EXPIRE_AUDIT ? VIREO_RESULT_NOT_FOUND : which==RELEASE_PENDING ? VIREO_RESULT_INTERNAL : which==FAIL_UTC2 ? VIREO_RESULT_IO : VIREO_RESULT_DATABASE;
        CHECK(vireo_mysql_node_repository_mkdir(nodes,&alice,&in,0,&r,&e),expected);
        bool durable=which==LOST_COMMIT_REPLY || which==COMMIT_CLOSE || which==RELEASE_PENDING;
        assert(scalar("SELECT COUNT(*) FROM file_nodes")==before_nodes+(durable ? 1u : 0u));
        assert(scalar("SELECT COUNT(*) FROM operation_audits")==before_audits+(durable ? 1u : 0u));
        if(which==LOST_COMMIT_REPLY) { assert(r.commit==VIREO_MYSQL_NODE_MKDIR_UNKNOWN && !r.rollback_confirmed && !r.audit_id);zeroed(&r.node,sizeof(r.node)); }
        else if(which==COMMIT_CLOSE || which==RELEASE_PENDING) { assert(r.commit==VIREO_MYSQL_NODE_MKDIR_COMMITTED && r.node.id && r.audit_id && !r.rollback_confirmed); }
        else { assert(r.commit==VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED && r.rollback_confirmed && !r.audit_id);zeroed(&r.node,sizeof(r.node)); }
        if(which==EXPIRE_AUDIT) { assert(r.issue==VIREO_MYSQL_NODE_AUTH_REJECTED && utc_calls==2); }
        if(which==RELEASE_PENDING) {
            assert(r.cleanup_pending);vireo_mysql_node_mkdir_report_t again;
            CHECK(vireo_mysql_node_repository_mkdir(nodes,&alice,&in,0,&again,NULL),VIREO_RESULT_BUSY);assert(again.cleanup_pending);
            fault=NONE;recreate(true);
        } else { assert(!r.cleanup_pending); }
        ++cases;refill_pool();
    }
    fault=NONE;sample_ms=2000;recreate(false);
    puts("PASS real DML/audit rollback after expiry/UTC failure; real COMMIT with hidden reply; confirmed commit survives close/release faults (injected seams)");
}
struct worker { bool first,logout;const char *name;unsigned char event;vireo_result_t result;vireo_mysql_node_mkdir_report_t report; };
static vireo_result_t second_execute(vireo_mysql_thread_t *t,vireo_mysql_statement_t *s,
    const vireo_mysql_parameter_t *p,size_t n,vireo_mysql_execution_t *out,vireo_mysql_error_t *e)
{
    if(n==2) {
        assert(!pthread_mutex_lock(&mutex));second_started=true;assert(!pthread_cond_broadcast(&condition));assert(!pthread_mutex_unlock(&mutex));
    }
    return vireo_mysql_statement_execute(t,s,p,n,out,e);
}
static void *work(void *arg)
{
    struct worker *w=arg;vireo_mysql_thread_t *t=NULL;CHECK(vireo_mysql_thread_attach(runtime,&t,NULL),VIREO_OK);utc_calls=0;sample_ms=2000;
    if(w->logout) {
        vireo_mysql_user_repository_t *r=NULL;CHECK(vireo_mysql_user_repository_create(t,pool,&policy,&r,NULL),VIREO_OK);
        assert(!pthread_mutex_lock(&mutex));second_started=true;assert(!pthread_cond_broadcast(&condition));assert(!pthread_mutex_unlock(&mutex));
        vireo_mysql_logout_input_t in={.user_id=alice.user_id,.session_id=alice.session_id,.request_id={0x7f},.occurred_at_ms=2000};vireo_mysql_logout_report_t out;
        CHECK(vireo_mysql_user_repository_logout(r,&in,0,&out,NULL),VIREO_OK);assert(out.commit==VIREO_MYSQL_LOGOUT_COMMITTED);
        CHECK(vireo_mysql_user_repository_destroy(&r,NULL),VIREO_OK);
    } else {
        vireo_mysql_node_ops_t ops=vireo_mysql_node_native_ops;ops.utc=w->first ? paused_utc : fixed_utc;
        if(!w->first) { ops.execute=second_execute; }
        vireo_mysql_node_repository_t *r=NULL;CHECK(vireo_mysql_node_repository_create_with_ops(t,pool,&r,NULL,&ops),VIREO_OK);
        vireo_mysql_node_mkdir_input_t in={.parent_id=alice_root,.name=(const unsigned char *)w->name,.name_length=strlen(w->name),.request_id={0x70}};in.request_id[15]=w->event;
        errno=EDOM;w->result=vireo_mysql_node_repository_mkdir(r,&alice,&in,0,&w->report,NULL);assert(errno==EDOM);
        CHECK(vireo_mysql_node_repository_destroy(&r,NULL),VIREO_OK);
    }
    if(!w->first) { assert(!pthread_mutex_lock(&mutex));second_done=true;assert(!pthread_cond_broadcast(&condition));assert(!pthread_mutex_unlock(&mutex)); }
    CHECK(vireo_mysql_thread_detach(&t),VIREO_OK);return NULL;
}
static void concurrent(unsigned scenario)
{
    phase=0;release_first=false;second_started=false;second_done=false;
    struct worker a={.first=true,.name=scenario==0 ? "race-same" : scenario==1 ? "race-a" : "before-logout",.event=(unsigned char)(scenario*2+1)};
    struct worker b={.logout=scenario==2,.name=scenario==0 ? "race-same" : "race-b",.event=(unsigned char)(scenario*2+2)};
    uint64_t before_nodes=scalar("SELECT COUNT(*) FROM file_nodes"),before_audits=scalar("SELECT COUNT(*) FROM operation_audits");
    pthread_t t1,t2;assert(!pthread_create(&t1,NULL,work,&a));assert(!pthread_mutex_lock(&mutex));
    struct timespec due=deadline();while(phase!=1) { assert(!pthread_cond_timedwait(&condition,&mutex,&due)); }assert(!pthread_mutex_unlock(&mutex));
    assert(!pthread_create(&t2,NULL,work,&b));assert(!pthread_mutex_lock(&mutex));wait_flag(&second_started);
    assert(!second_done);release_first=true;assert(!pthread_cond_broadcast(&condition));assert(!pthread_mutex_unlock(&mutex));
    assert(!pthread_join(t1,NULL) && !pthread_join(t2,NULL));assert(a.result==VIREO_OK && a.report.commit==VIREO_MYSQL_NODE_MKDIR_COMMITTED && second_done);
    if(scenario==0) { assert(b.result==VIREO_RESULT_DATABASE && b.report.issue==VIREO_MYSQL_NODE_NAME_CONFLICT && b.report.rollback_confirmed); }
    if(scenario==1) { assert(b.result==VIREO_OK && b.report.commit==VIREO_MYSQL_NODE_MKDIR_COMMITTED); }
    assert(scalar("SELECT COUNT(*) FROM file_nodes")==before_nodes+(scenario==1 ? 2u : 1u));
    assert(scalar("SELECT COUNT(*) FROM operation_audits")==before_audits+(scenario==0 ? 1u : 2u));++cases;
    if(scenario==2) {
        vireo_mysql_node_mkdir_input_t in=make_input(alice_root,"after-logout",12);
        (void)create_dir(alice,&in,VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_NODE_AUTH_REJECTED);
        struct worker later={.name="later-worker",.event=99};assert(!pthread_create(&t2,NULL,work,&later) && !pthread_join(t2,NULL));
        assert(later.result==VIREO_RESULT_NOT_FOUND && later.report.issue==VIREO_MYSQL_NODE_AUTH_REJECTED);++cases;
    }
}
static size_t fd_count(void)
{ DIR *d=opendir("/proc/self/fd");assert(d);size_t n=0;while(readdir(d)) { ++n; }assert(!closedir(d));return n; }
int main(int argc,char **argv)
{
    assert(argc==5 && !setvbuf(stdout,NULL,_IONBF,0));char password[1026];FILE *f=fopen(argv[3],"r");
    assert(f && fgets(password,(int)sizeof(password),f) && !fclose(f));password[strcspn(password,"\n")]=0;
    struct sigaction sa={0};sa.sa_handler=SIG_IGN;assert(!sigemptyset(&sa.sa_mask) && !sigaction(SIGPIPE,&sa,NULL));
    pthread_condattr_t attr;assert(!pthread_condattr_init(&attr) && !pthread_condattr_setclock(&attr,CLOCK_MONOTONIC));
    assert(!pthread_cond_init(&condition,&attr) && !pthread_condattr_destroy(&attr));size_t fd=fd_count();
    CHECK(vireo_mysql_runtime_create(&runtime,NULL),VIREO_OK);CHECK(vireo_mysql_thread_attach(runtime,&thread,NULL),VIREO_OK);
    vireo_mysql_connection_options_t options={argv[1],argv[2],password,argv[4],3,3,3};
    const vireo_mysql_migration_t *catalog;size_t count;CHECK(vireo_mysql_schema_catalog(&catalog,&count),VIREO_OK);vireo_mysql_migration_report_t migration;
    CHECK(vireo_mysql_migration_apply(thread,&options,catalog,count,&migration,NULL),VIREO_OK);assert(migration.ready && migration.steps_completed==15);
    CHECK(vireo_mysql_connection_open(thread,&options,&observer,NULL),VIREO_OK);
    vireo_mysql_pool_options_t config={options,4,4,VIREO_MYSQL_POOL_MEMORY_MAX};CHECK(vireo_mysql_pool_create(thread,&config,&pool,NULL),VIREO_OK);
    CHECK(vireo_mysql_user_repository_create(thread,pool,&policy,&users,NULL),VIREO_OK);
    const char pass[]="real-password";CHECK(vireo_password_hash_create(&policy,pass,sizeof(pass)-1,phc,sizeof(phc),&phc_length),VIREO_OK);
    alice=account("alice",&alice_root);bob=account("bob",&bob_root);recreate(false);
    vireo_mysql_node_mkdir_input_t first=make_input(alice_root,"资料",sizeof("资料")-1);
    vireo_mysql_node_mkdir_report_t made=create_dir(alice,&first,VIREO_OK,VIREO_MYSQL_NODE_ISSUE_NONE);
    assert(first.parent_id==alice_root && made.node.id!=alice_root);
    (void)create_dir(alice,&first,VIREO_RESULT_DATABASE,VIREO_MYSQL_NODE_NAME_CONFLICT);
    vireo_mysql_node_mkdir_input_t reused=first;reused.name=(const unsigned char *)"another-name";reused.name_length=12;
    (void)create_dir(alice,&reused,VIREO_RESULT_DATABASE,VIREO_MYSQL_NODE_ISSUE_NONE);
    vireo_mysql_node_mkdir_input_t in=make_input(made.node.id,"nested",6);(void)create_dir(alice,&in,VIREO_OK,VIREO_MYSQL_NODE_ISSUE_NONE);
    in=make_input(bob_root,"same-under-bob",14);(void)create_dir(alice,&in,VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_NODE_NOT_FOUND);
    in=make_input(alice_root,"same-under-alice",16);(void)create_dir(bob,&in,VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_NODE_NOT_FOUND);
    in=make_input(UINT64_MAX,"missing",7);(void)create_dir(alice,&in,VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_NODE_NOT_FOUND);
    char sql[2048];int n=snprintf(sql,sizeof(sql),"INSERT INTO file_nodes(owner_id,parent_id,name,node_type,state,object_hash,size,created_at_ms,updated_at_ms,deleted_at_ms) VALUES(%llu,%llu,'uploading',2,1,NULL,0,1000,1000,NULL),(%llu,%llu,'deleted',1,3,NULL,0,1000,1000,1000)",(unsigned long long)alice.user_id,(unsigned long long)alice_root,(unsigned long long)alice.user_id,(unsigned long long)alice_root);
    assert(n>0 && (size_t)n<sizeof(sql));mutate(sql);uint64_t deleted=scalar("SELECT MAX(id) FROM file_nodes"),uploading=deleted-1;
    in=make_input(alice_root,"uploading",9);(void)create_dir(alice,&in,VIREO_RESULT_DATABASE,VIREO_MYSQL_NODE_NAME_CONFLICT);
    in=make_input(uploading,"under-file",10);(void)create_dir(alice,&in,VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_NODE_NOT_FOUND);
    in=make_input(deleted,"under-deleted",13);(void)create_dir(alice,&in,VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_NODE_NOT_FOUND);
    in=make_input(alice_root,"deleted",7);vireo_mysql_node_mkdir_report_t replacement=create_dir(alice,&in,VIREO_OK,VIREO_MYSQL_NODE_ISSUE_NONE);assert(replacement.node.id!=deleted);
    mutate("INSERT INTO objects(object_hash,size,state,ref_count,storage_class,created_at_ms,updated_at_ms,verified_at_ms) VALUES(UNHEX(REPEAT('00',32)),0,2,1,1,1000,1000,1000)");
    (void)snprintf(sql,sizeof(sql),"UPDATE file_nodes SET state=2,object_hash=UNHEX(REPEAT('00',32)) WHERE id=%llu",(unsigned long long)uploading);mutate(sql);
    in=make_input(uploading,"under-active-file",17);(void)create_dir(alice,&in,VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_NODE_NOT_FOUND);
    in=make_input(alice_root,"uploading",9);(void)create_dir(alice,&in,VIREO_RESULT_DATABASE,VIREO_MYSQL_NODE_NAME_CONFLICT);
    unsigned char maximum[256];memset(maximum,'x',sizeof(maximum));
    in=make_input(alice_root,maximum,255);(void)create_dir(alice,&in,VIREO_OK,VIREO_MYSQL_NODE_ISSUE_NONE);
    in=make_input(alice_root,maximum,256);(void)create_dir(alice,&in,VIREO_RESULT_RANGE,VIREO_MYSQL_NODE_ISSUE_NONE);
    const unsigned char *names[]={(const unsigned char *)"A",(const unsigned char *)"a",(const unsigned char *)" a",(const unsigned char *)"a ",(const unsigned char *)"\xff",(const unsigned char *)"\x01"};
    const size_t lengths[]={1,1,2,2,1,1};
    for(size_t i=0;i<6;++i) { in=make_input(alice_root,names[i],lengths[i]);(void)create_dir(alice,&in,VIREO_OK,VIREO_MYSQL_NODE_ISSUE_NONE); }
    const unsigned char *bad[]={(const unsigned char *)"",(const unsigned char *)".",(const unsigned char *)"..",(const unsigned char *)"a/b",(const unsigned char *)"a\0b"};
    const size_t bad_lengths[]={0,1,2,3,3};
    for(size_t i=0;i<5;++i) { in=make_input(alice_root,bad[i],bad_lengths[i]);(void)create_dir(alice,&in,i==0 ? VIREO_RESULT_RANGE : VIREO_RESULT_PROTOCOL,VIREO_MYSQL_NODE_ISSUE_NONE); }
    (void)snprintf(sql,sizeof(sql),"SELECT updated_at_ms FROM file_nodes WHERE id=%llu",(unsigned long long)alice_root);assert(scalar(sql)==1000);
    (void)snprintf(sql,sizeof(sql),"SELECT last_seen_at_ms FROM sessions WHERE id=%llu",(unsigned long long)alice.session_id);assert(scalar(sql)==1000);
    vireo_mysql_node_list_query_t q={alice_root,0,64};vireo_mysql_node_page_t page;vireo_mysql_node_report_t rr;
    CHECK(vireo_mysql_node_repository_list_children(nodes,&alice,&q,0,&page,&rr,NULL),VIREO_OK);bool found=false;
    for(size_t i=0;i<page.count;++i) { if(page.nodes[i].id==made.node.id) { found=true; } }assert(found && !page.has_more);++cases;
    const uint64_t times[]={999,1000,2999,3000};
    for(size_t i=0;i<4;++i) {
        sample_ms=times[i];char b[32];n=snprintf(b,sizeof(b),"time-%zu",i);assert(n>0 && (size_t)n<sizeof(b));in=make_input(alice_root,b,(size_t)n);
        bool valid=sample_ms>=1000 && sample_ms<3000;(void)create_dir(alice,&in,valid ? VIREO_OK : VIREO_RESULT_NOT_FOUND,valid ? VIREO_MYSQL_NODE_ISSUE_NONE : VIREO_MYSQL_NODE_AUTH_REJECTED);
    }
    in=make_input(UINT64_MAX,"missing-expired",15);(void)create_dir(alice,&in,VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_NODE_AUTH_REJECTED);sample_ms=2000;
    vireo_mysql_node_actor_t forged={bob.user_id,alice.session_id};in=make_input(bob_root,"forged",6);(void)create_dir(forged,&in,VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_NODE_AUTH_REJECTED);
    mutate("UPDATE users SET status=2 WHERE username_key='alice'");in=make_input(alice_root,"disabled",8);(void)create_dir(alice,&in,VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_NODE_AUTH_REJECTED);mutate("UPDATE users SET status=1 WHERE username_key='alice'");
    fault_cases();concurrent(0);concurrent(1);concurrent(2);
    (void)snprintf(sql,sizeof(sql),"UPDATE sessions SET expires_at_ms=18446744073709551615 WHERE id=%llu",(unsigned long long)bob.session_id);mutate(sql);
    CHECK(vireo_mysql_node_repository_destroy(&nodes,NULL),VIREO_OK);CHECK(vireo_mysql_node_repository_create(thread,pool,&nodes,NULL),VIREO_OK);
    in=make_input(bob_root,"native-time",11);vireo_mysql_node_mkdir_report_t native;
    CHECK(vireo_mysql_node_repository_mkdir(nodes,&bob,&in,0,&native,NULL),VIREO_OK);assert(native.commit==VIREO_MYSQL_NODE_MKDIR_COMMITTED && native.node.created_at_ms>3000 && native.audit_id);++cases;
    CHECK(vireo_mysql_node_repository_destroy(&nodes,NULL),VIREO_OK);assert(made.node.name_length==sizeof("资料")-1 && !memcmp(made.node.name,"资料",sizeof("资料")-1));
    CHECK(vireo_mysql_user_repository_destroy(&users,NULL),VIREO_OK);bool closed=false;CHECK(vireo_mysql_pool_close(pool,&closed,NULL),VIREO_OK);assert(closed);
    CHECK(vireo_mysql_pool_destroy(thread,&pool,NULL),VIREO_OK);CHECK(vireo_mysql_connection_destroy(thread,&observer),VIREO_OK);
    CHECK(vireo_mysql_thread_detach(&thread),VIREO_OK);CHECK(vireo_mysql_runtime_destroy(&runtime),VIREO_OK);
    assert(!pthread_cond_destroy(&condition) && !pthread_mutex_destroy(&mutex));memset(password,0,sizeof(password));assert(fd_count()==fd);
    printf("PASS %zu real mkdir observations: atomic directory/audit, owner/names/expiry, two workers same/different name and logout, native UTC; FD %zu -> %zu\n",cases,fd,fd_count());return 0;
}
