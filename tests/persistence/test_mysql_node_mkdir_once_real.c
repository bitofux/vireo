/* PROJECT : VIREO; FILE : test_mysql_node_mkdir_once_real.c; AUTHOR : bitofux;
 * DATE : 2026-10-21; BRIEF : 真实目录/审计原子事务、三态提交和受控双worker。 */
#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#include "mysql_node_repository_internal.h"
#include <vireo/persistence/mysql_node_mkdir_receipt.h>
#include <spawn.h>
#include <sys/wait.h>
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
static bool release_first,second_started,second_done,allow_retry;
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
static vireo_mysql_node_mkdir_once_input_t make_input(uint64_t parent,const void *name,size_t n)
{
    vireo_mysql_node_mkdir_once_input_t in={.parent_id=parent,.name=name,.name_length=n,.idempotency_key={0x22},.request_id={0x11}};
    assert(serial<250);in.request_id[15]=++serial;in.idempotency_key[15]=serial;return in;
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
static vireo_mysql_node_mkdir_once_report_t create_dir(vireo_mysql_node_actor_t who,
    const vireo_mysql_node_mkdir_once_input_t *in,vireo_result_t want,vireo_mysql_node_issue_t issue,
    vireo_mysql_node_mkdir_effect_t effect)
{
    uint64_t before_nodes=scalar("SELECT COUNT(*) FROM file_nodes"),before_audits=scalar("SELECT COUNT(*) FROM operation_audits"),before_receipts=scalar("SELECT COUNT(*) FROM directory_write_receipts");
    vireo_mysql_node_mkdir_once_report_t out;memset(&out,0xa5,sizeof(out));vireo_mysql_node_error_t e;
    errno=EDOM;vireo_result_t rc=vireo_mysql_node_repository_mkdir_once(nodes,&who,in,0,&out,&e);assert(errno==EDOM);
    if(rc!=want) { fprintf(stderr,"case %zu result %d want %d stage %d mysql %u issue %d effect %d cleanup %d\n",cases,(int)rc,(int)want,(int)e.stage,e.database.mysql_code,(int)out.issue,(int)out.effect,(int)e.cleanup_result);abort(); }
    assert(out.issue==issue && !out.cleanup_pending && out.effect==effect);
    bool created=effect==VIREO_MYSQL_NODE_MKDIR_EFFECT_CREATED;
    if(effect!=VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE) {
        assert(out.node_id && out.audit_id && !memcmp(out.idempotency_key,in->idempotency_key,16));
        assert(out.commit==(created ? VIREO_MYSQL_NODE_MKDIR_COMMITTED : VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED));
        assert(out.rollback_confirmed==!created);
        char sql[2048];int n=snprintf(sql,sizeof(sql),"SELECT COUNT(*) FROM directory_write_receipts WHERE user_id=%llu AND result_node_id=%llu AND audit_id=%llu",(unsigned long long)who.user_id,(unsigned long long)out.node_id,(unsigned long long)out.audit_id);
        assert(n>0 && (size_t)n<sizeof(sql) && scalar(sql)==1);
        if(created) {
            n=snprintf(sql,sizeof(sql),"SELECT COUNT(*) FROM operation_audits WHERE id=%llu AND user_id=%llu AND session_id=%llu AND action=5 AND target_type=3 AND target_id=%llu AND status=0 AND occurred_at_ms=%llu",(unsigned long long)out.audit_id,(unsigned long long)who.user_id,(unsigned long long)who.session_id,(unsigned long long)out.node_id,(unsigned long long)sample_ms);
            assert(n>0 && (size_t)n<sizeof(sql) && scalar(sql)==1);
        }
    } else { assert(!out.node_id && !out.audit_id && out.commit==VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED);zeroed(out.idempotency_key,16); }
    assert(scalar("SELECT COUNT(*) FROM file_nodes")==before_nodes+(created ? 1u : 0u));
    assert(scalar("SELECT COUNT(*) FROM operation_audits")==before_audits+(created ? 1u : 0u));
    assert(scalar("SELECT COUNT(*) FROM directory_write_receipts")==before_receipts+(created ? 1u : 0u));++cases;refill_pool();return out;
}
enum fault { NONE, EXPIRE_AUDIT, LOST_COMMIT_REPLY, NO_NATIVE_COMMIT, COMMIT_CLOSE, RELEASE_PENDING, FAIL_UTC2, FAIL_NODE, FAIL_AUDIT, FAIL_RECEIPT, RECOVERY_ROLLBACK, RECOVERY_CLOSE, RECOVERY_RELEASE };
static enum fault fault;
static vireo_mysql_statement_t *commit_statement,*audit_statement,*node_statement,*receipt_statement,*rollback_statement;
static vireo_result_t fault_prepare(vireo_mysql_thread_t *t,vireo_mysql_connection_t *c,
    const char *sql,size_t n,const vireo_mysql_statement_limits_t *l,vireo_mysql_statement_t **out,vireo_mysql_error_t *e)
{
    vireo_result_t rc=vireo_mysql_statement_prepare(t,c,sql,n,l,out,e);
    if(rc==VIREO_OK) { if(!strcmp(sql,"COMMIT")) { commit_statement=*out; }if(strstr(sql,"INSERT INTO operation_audits")) { audit_statement=*out; }if(strstr(sql,"INSERT INTO file_nodes")) { node_statement=*out; }if(strstr(sql,"INSERT INTO directory_write_receipts")) { receipt_statement=*out; }if(!strcmp(sql,"ROLLBACK")) { rollback_statement=*out; } }
    return rc;
}
static vireo_result_t fault_execute(vireo_mysql_thread_t *t,vireo_mysql_statement_t *s,
    const vireo_mysql_parameter_t *p,size_t n,vireo_mysql_execution_t *out,vireo_mysql_error_t *e)
{
    if(s==commit_statement && fault==NO_NATIVE_COMMIT) {
        *out=(vireo_mysql_execution_t){0};*e=(vireo_mysql_error_t){.mysql_code=2013};return VIREO_RESULT_DATABASE;
    }
    if((s==node_statement && fault==FAIL_NODE) || (s==audit_statement && fault==FAIL_AUDIT) ||
        (s==receipt_statement && fault==FAIL_RECEIPT)) {
        /* Execute actual invalid SQL values through the native driver. All earlier
         * writes are real; CHECK rejection must roll back the complete transaction. */
        vireo_mysql_parameter_t invalid[7];assert(n<=7);memcpy(invalid,p,n*sizeof(*p));
        static const unsigned char zero[16]={0},slash[]="/";
        if(fault==FAIL_NODE) { invalid[2]=(vireo_mysql_parameter_t){.kind=VIREO_MYSQL_PARAMETER_BYTES,.value.span={slash,1}}; }
        if(fault==FAIL_AUDIT) { invalid[0]=(vireo_mysql_parameter_t){.kind=VIREO_MYSQL_PARAMETER_BYTES,.value.span={zero,16}}; }
        if(fault==FAIL_RECEIPT) { invalid[2]=(vireo_mysql_parameter_t){.kind=VIREO_MYSQL_PARAMETER_U64,.value.u64=0}; }
        vireo_result_t rejected=vireo_mysql_statement_execute(t,s,invalid,n,out,e);
        assert(rejected==VIREO_RESULT_DATABASE && e->mysql_code==3819);return rejected;
    }
    if(s==rollback_statement && fault==RECOVERY_ROLLBACK) {
        *out=(vireo_mysql_execution_t){0};*e=(vireo_mysql_error_t){.mysql_code=1205};return VIREO_RESULT_DATABASE;
    }
    vireo_result_t rc=vireo_mysql_statement_execute(t,s,p,n,out,e);
    if(rc==VIREO_OK && s==audit_statement && fault==EXPIRE_AUDIT) { sample_ms=3000; }
    if(rc==VIREO_OK && s==commit_statement && fault==LOST_COMMIT_REPLY) { e->mysql_code=2013;return VIREO_RESULT_DATABASE; }
    return rc;
}
static vireo_result_t fault_close(vireo_mysql_thread_t *t,vireo_mysql_statement_t **s,vireo_mysql_error_t *e)
{
    bool commit=*s==commit_statement;bool audit=*s==audit_statement;bool node=*s==node_statement;bool receipt=*s==receipt_statement;bool rollback=*s==rollback_statement;
    vireo_result_t rc=vireo_mysql_statement_destroy(t,s,e);
    if(*s==NULL) { if(commit) { commit_statement=NULL; }if(audit) { audit_statement=NULL; }if(node) { node_statement=NULL; }if(receipt) { receipt_statement=NULL; }if(rollback) { rollback_statement=NULL; } }
    return rc==VIREO_OK && ((commit && fault==COMMIT_CLOSE) || (rollback && fault==RECOVERY_CLOSE)) ? VIREO_RESULT_DATABASE : rc;
}
static vireo_result_t fault_release(vireo_mysql_thread_t *t,vireo_mysql_pool_t *p,vireo_mysql_lease_t *lease,
    vireo_mysql_pool_disposition_t d,vireo_mysql_pool_release_t *out,vireo_mysql_pool_error_t *e)
{
    if(fault==RELEASE_PENDING || fault==RECOVERY_RELEASE) { *out=(vireo_mysql_pool_release_t){0};*e=(vireo_mysql_pool_error_t){0};return VIREO_RESULT_INTERNAL; }
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
    for(enum fault which=EXPIRE_AUDIT;which<=FAIL_RECEIPT;which=(enum fault)(which+1)) {
        fault=which;sample_ms=2000;utc_calls=0;
        char name[32];int n=snprintf(name,sizeof(name),"fault-%u",(unsigned)which);assert(n>0 && (size_t)n<sizeof(name));
        vireo_mysql_node_mkdir_once_input_t in=make_input(alice_root,name,(size_t)n);
        uint64_t before_nodes=scalar("SELECT COUNT(*) FROM file_nodes"),before_audits=scalar("SELECT COUNT(*) FROM operation_audits"),before_receipts=scalar("SELECT COUNT(*) FROM directory_write_receipts");
        vireo_mysql_node_mkdir_once_report_t r;vireo_mysql_node_error_t e;
        vireo_result_t expected=which==EXPIRE_AUDIT ? VIREO_RESULT_NOT_FOUND : which==RELEASE_PENDING ? VIREO_RESULT_INTERNAL : which==FAIL_UTC2 ? VIREO_RESULT_IO : VIREO_RESULT_DATABASE;
        CHECK(vireo_mysql_node_repository_mkdir_once(nodes,&alice,&in,0,&r,&e),expected);
        if(which>=FAIL_NODE && which<=FAIL_RECEIPT) { assert(e.database.mysql_code==3819 && r.rollback_confirmed); }
        bool durable=which==LOST_COMMIT_REPLY || which==COMMIT_CLOSE || which==RELEASE_PENDING;
        assert(scalar("SELECT COUNT(*) FROM file_nodes")==before_nodes+(durable ? 1u : 0u));
        assert(scalar("SELECT COUNT(*) FROM operation_audits")==before_audits+(durable ? 1u : 0u));
        assert(scalar("SELECT COUNT(*) FROM directory_write_receipts")==before_receipts+(durable ? 1u : 0u));
        if(which==LOST_COMMIT_REPLY) { assert(r.commit==VIREO_MYSQL_NODE_MKDIR_UNKNOWN && r.effect==VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE && !r.rollback_confirmed && !r.node_id && !r.audit_id);zeroed(r.idempotency_key,16); }
        else if(durable) { assert(r.commit==VIREO_MYSQL_NODE_MKDIR_COMMITTED && r.effect==VIREO_MYSQL_NODE_MKDIR_EFFECT_CREATED && r.node_id && r.audit_id); }
        else { assert(r.commit==VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED && r.rollback_confirmed && !r.node_id && !r.audit_id); }
        if(which==RELEASE_PENDING) {
            assert(r.cleanup_pending);vireo_mysql_node_mkdir_once_report_t again;
            CHECK(vireo_mysql_node_repository_mkdir_once(nodes,&alice,&in,0,&again,NULL),VIREO_RESULT_BUSY);assert(again.cleanup_pending);
        } else { assert(!r.cleanup_pending); }
        fault=NONE;sample_ms=2000;recreate(true);refill_pool();
        vireo_mysql_node_mkdir_once_report_t retry=create_dir(alice,&in,VIREO_OK,VIREO_MYSQL_NODE_ISSUE_NONE,durable ? VIREO_MYSQL_NODE_MKDIR_EFFECT_RECOVERED : VIREO_MYSQL_NODE_MKDIR_EFFECT_CREATED);
        for(enum fault recovery=RECOVERY_ROLLBACK;recovery<=RECOVERY_RELEASE;recovery=(enum fault)(recovery+1)) {
            fault=recovery;
            CHECK(vireo_mysql_node_repository_mkdir_once(nodes,&alice,&in,0,&r,&e),recovery==RECOVERY_RELEASE ? VIREO_RESULT_INTERNAL : VIREO_RESULT_DATABASE);
            assert(r.effect==VIREO_MYSQL_NODE_MKDIR_EFFECT_RECOVERED && r.commit==VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED && r.node_id==retry.node_id && r.audit_id==retry.audit_id);
            fault=NONE;recreate(true);refill_pool();++cases;
        }
        ++cases;
    }
    fault=NONE;sample_ms=2000;recreate(false);
    puts("PASS three-write rollback and retry; real COMMIT then simulated reply failure recovers; created/recovered facts survive cleanup errors");
}
/* First worker holds user X. The second native execution must actually return
 * lock-wait timeout 1205 before A is released; then a fresh public call retries.
 * This handshake proves database overlap without scheduler sleeps or P_S grants. */
struct worker {
    bool first;unsigned scenario;vireo_result_t result;
    vireo_mysql_node_mkdir_once_report_t report;
};
static vireo_result_t wait_prepare(vireo_mysql_thread_t *t,vireo_mysql_connection_t *c,
    const char *sql,size_t n,const vireo_mysql_statement_limits_t *l,vireo_mysql_statement_t **out,vireo_mysql_error_t *e)
{
    if(strstr(sql,"FROM users")) {
        static const char timeout[]="SET SESSION innodb_lock_wait_timeout=1";
        vireo_mysql_statement_t *s=NULL;vireo_mysql_execution_t ex;
        CHECK(vireo_mysql_statement_prepare(t,c,timeout,sizeof(timeout)-1,l,&s,NULL),VIREO_OK);
        CHECK(vireo_mysql_statement_execute(t,s,NULL,0,&ex,NULL),VIREO_OK);
        CHECK(vireo_mysql_statement_destroy(t,&s,NULL),VIREO_OK);
    }
    return vireo_mysql_statement_prepare(t,c,sql,n,l,out,e);
}
static void *work(void *arg)
{
    struct worker *w=arg;vireo_mysql_thread_t *t=NULL;CHECK(vireo_mysql_thread_attach(runtime,&t,NULL),VIREO_OK);utc_calls=0;sample_ms=2000;
    vireo_mysql_node_ops_t ops=vireo_mysql_node_native_ops;ops.utc=w->first ? paused_utc : fixed_utc;if(!w->first) { ops.prepare=wait_prepare; }
    vireo_mysql_node_repository_t *r=NULL;CHECK(vireo_mysql_node_repository_create_with_ops(t,pool,&r,NULL,&ops),VIREO_OK);
    const char *name=w->scenario==0 ? "race-same" : w->scenario==1 ? (w->first ? "race-one" : "race-two") : "race-name";
    vireo_mysql_node_mkdir_once_input_t in={.parent_id=alice_root,.name=(const unsigned char *)name,.name_length=strlen(name),.idempotency_key={0x71},.request_id={0x70}};
    in.idempotency_key[15]=(unsigned char)(w->scenario*2+1+(w->scenario==2 && !w->first ? 1 : 0));in.request_id[15]=(unsigned char)(w->scenario*2+1+(w->first ? 0 : 1));
    vireo_mysql_node_error_t e;
    if(!w->first) {
        CHECK(vireo_mysql_node_repository_mkdir_once(r,&alice,&in,0,&w->report,&e),VIREO_RESULT_DATABASE);
        assert(e.database.mysql_code==1205 && w->report.issue==VIREO_MYSQL_NODE_ISSUE_NONE && w->report.effect==VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE);
        assert(!pthread_mutex_lock(&mutex));second_started=true;assert(!pthread_cond_broadcast(&condition));wait_flag(&allow_retry);assert(!pthread_mutex_unlock(&mutex));
    }
    errno=EDOM;w->result=vireo_mysql_node_repository_mkdir_once(r,&alice,&in,0,&w->report,&e);assert(errno==EDOM);
    CHECK(vireo_mysql_node_repository_destroy(&r,NULL),VIREO_OK);
    if(!w->first) { assert(!pthread_mutex_lock(&mutex));second_done=true;assert(!pthread_cond_broadcast(&condition));assert(!pthread_mutex_unlock(&mutex)); }
    CHECK(vireo_mysql_thread_detach(&t),VIREO_OK);return NULL;
}
static void concurrent(unsigned scenario)
{
    phase=0;release_first=false;second_started=false;second_done=false;allow_retry=false;
    struct worker a={.first=true,.scenario=scenario},b={.scenario=scenario};
    uint64_t before_nodes=scalar("SELECT COUNT(*) FROM file_nodes"),before_audits=scalar("SELECT COUNT(*) FROM operation_audits"),before_receipts=scalar("SELECT COUNT(*) FROM directory_write_receipts");
    pthread_t t1,t2;assert(!pthread_create(&t1,NULL,work,&a));assert(!pthread_mutex_lock(&mutex));
    struct timespec due=deadline();while(phase!=1) { assert(!pthread_cond_timedwait(&condition,&mutex,&due)); }assert(!pthread_mutex_unlock(&mutex));
    assert(!pthread_create(&t2,NULL,work,&b));assert(!pthread_mutex_lock(&mutex));wait_flag(&second_started);
    assert(!second_done);release_first=true;assert(!pthread_cond_broadcast(&condition));assert(!pthread_mutex_unlock(&mutex));
    assert(!pthread_join(t1,NULL));assert(a.result==VIREO_OK && a.report.effect==VIREO_MYSQL_NODE_MKDIR_EFFECT_CREATED);
    assert(!pthread_mutex_lock(&mutex));allow_retry=true;assert(!pthread_cond_broadcast(&condition));assert(!pthread_mutex_unlock(&mutex));assert(!pthread_join(t2,NULL) && second_done);
    if(scenario==0) { assert(b.result==VIREO_OK && b.report.effect==VIREO_MYSQL_NODE_MKDIR_EFFECT_RECOVERED && b.report.node_id==a.report.node_id && b.report.audit_id==a.report.audit_id); }
    else { assert(b.result==VIREO_RESULT_DATABASE && b.report.issue==(scenario==1 ? VIREO_MYSQL_NODE_IDEMPOTENCY_CONFLICT : VIREO_MYSQL_NODE_NAME_CONFLICT) && b.report.rollback_confirmed); }
    assert(scalar("SELECT COUNT(*) FROM file_nodes")==before_nodes+1);
    assert(scalar("SELECT COUNT(*) FROM operation_audits")==before_audits+1);
    assert(scalar("SELECT COUNT(*) FROM directory_write_receipts")==before_receipts+1);++cases;refill_pool();
}
static size_t fd_count(void)
{ DIR *d=opendir("/proc/self/fd");assert(d);size_t n=0;while(readdir(d)) { ++n; }assert(!closedir(d));return n; }
extern char **environ;
static void exec_recover(char **argv,vireo_mysql_node_mkdir_once_input_t *in,vireo_mysql_node_mkdir_once_report_t r)
{
    char values[6][32];uint64_t ids[]={alice.user_id,alice.session_id,in->parent_id,r.node_id,r.audit_id,in->idempotency_key[15]};
    for(size_t i=0;i<6;++i) { int n=snprintf(values[i],sizeof(values[i]),"%llu",(unsigned long long)ids[i]);assert(n>0 && (size_t)n<sizeof(values[i])); }
    char *args[]={argv[0],argv[1],argv[2],argv[3],argv[4],"recover",values[0],values[1],values[2],values[3],values[4],values[5],NULL};
    posix_spawn_file_actions_t actions;assert(!posix_spawn_file_actions_init(&actions));assert(!posix_spawn_file_actions_addclosefrom_np(&actions,3));
    pid_t pid;assert(!posix_spawn(&pid,argv[0],&actions,NULL,args,environ));assert(!posix_spawn_file_actions_destroy(&actions));
    int status;assert(waitpid(pid,&status,0)==pid && WIFEXITED(status) && WEXITSTATUS(status)==0);++cases;
}
static uint64_t parse_id(const char *s)
{ errno=0;char *end;unsigned long long n=strtoull(s,&end,10);assert(!errno && !*end && n>0);return (uint64_t)n; }
static void business_cases(char **argv)
{
    vireo_mysql_node_mkdir_once_input_t in=make_input(alice_root,"original",8);
    vireo_mysql_node_mkdir_once_report_t first=create_dir(alice,&in,VIREO_OK,VIREO_MYSQL_NODE_ISSUE_NONE,VIREO_MYSQL_NODE_MKDIR_EFFECT_CREATED);
    vireo_mysql_node_mkdir_once_report_t recovered=create_dir(alice,&in,VIREO_OK,VIREO_MYSQL_NODE_ISSUE_NONE,VIREO_MYSQL_NODE_MKDIR_EFFECT_RECOVERED);assert(first.node_id==recovered.node_id && first.audit_id==recovered.audit_id);
    vireo_mysql_node_mkdir_once_input_t changed=in;changed.parent_id=UINT64_MAX;(void)create_dir(alice,&changed,VIREO_RESULT_DATABASE,VIREO_MYSQL_NODE_IDEMPOTENCY_CONFLICT,VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE);
    changed=in;changed.name=(const unsigned char *)"originam";(void)create_dir(alice,&changed,VIREO_RESULT_DATABASE,VIREO_MYSQL_NODE_IDEMPOTENCY_CONFLICT,VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE);
    changed.name_length=7;(void)create_dir(alice,&changed,VIREO_RESULT_DATABASE,VIREO_MYSQL_NODE_IDEMPOTENCY_CONFLICT,VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE);
    changed=in;changed.parent_id=bob_root;changed.request_id[14]=0x40;(void)create_dir(bob,&changed,VIREO_OK,VIREO_MYSQL_NODE_ISSUE_NONE,VIREO_MYSQL_NODE_MKDIR_EFFECT_CREATED);
    vireo_mysql_node_mkdir_once_input_t destination_in=make_input(alice_root,"destination",11);
    vireo_mysql_node_mkdir_once_report_t destination=create_dir(alice,&destination_in,VIREO_OK,VIREO_MYSQL_NODE_ISSUE_NONE,VIREO_MYSQL_NODE_MKDIR_EFFECT_CREATED);
    char sql[2048];(void)snprintf(sql,sizeof(sql),"UPDATE file_nodes SET name='moved',parent_id=%llu WHERE id=%llu",(unsigned long long)destination.node_id,(unsigned long long)first.node_id);mutate(sql);
    (void)create_dir(alice,&in,VIREO_OK,VIREO_MYSQL_NODE_ISSUE_NONE,VIREO_MYSQL_NODE_MKDIR_EFFECT_RECOVERED);
    (void)snprintf(sql,sizeof(sql),"UPDATE file_nodes SET state=3,deleted_at_ms=2000,updated_at_ms=2000 WHERE id=%llu",(unsigned long long)first.node_id);mutate(sql);
    (void)create_dir(alice,&in,VIREO_OK,VIREO_MYSQL_NODE_ISSUE_NONE,VIREO_MYSQL_NODE_MKDIR_EFFECT_RECOVERED);
    /* A new Session can recover an old user's receipt; the old Session is revoked. */
    vireo_mysql_login_input_t login={.user_id=alice.user_id,.verified_password_hash=phc,.verified_password_hash_length=phc_length,.issued_at_ms=1000,.expires_at_ms=3000,.request_id={0x30}};
    login.token_digest.bytes[0]=0x30;vireo_mysql_login_report_t logged;CHECK(vireo_mysql_user_repository_login(users,&login,0,&logged,NULL),VIREO_OK);
    vireo_mysql_node_actor_t previous=alice;alice.session_id=logged.session_id;
    (void)create_dir(alice,&in,VIREO_OK,VIREO_MYSQL_NODE_ISSUE_NONE,VIREO_MYSQL_NODE_MKDIR_EFFECT_RECOVERED);
    (void)snprintf(sql,sizeof(sql),"UPDATE sessions SET status=2,revoked_at_ms=2000 WHERE id=%llu",(unsigned long long)previous.session_id);mutate(sql);
    (void)create_dir(previous,&in,VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_NODE_AUTH_REJECTED,VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE);
    mutate("UPDATE users SET status=2 WHERE username_key='alice'");(void)create_dir(alice,&in,VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_NODE_AUTH_REJECTED,VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE);mutate("UPDATE users SET status=1 WHERE username_key='alice'");
    sample_ms=3000;(void)create_dir(alice,&changed,VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_NODE_AUTH_REJECTED,VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE);sample_ms=2000;
    changed=make_input(alice_root,"original",8);(void)create_dir(alice,&changed,VIREO_OK,VIREO_MYSQL_NODE_ISSUE_NONE,VIREO_MYSQL_NODE_MKDIR_EFFECT_CREATED);
    /* Duplicate trusted audit event fails after node insert; no receipt is cached. */
    vireo_mysql_node_mkdir_once_input_t duplicate=make_input(alice_root,"audit-duplicate",15);memcpy(duplicate.request_id,changed.request_id,16);
    (void)create_dir(alice,&duplicate,VIREO_RESULT_DATABASE,VIREO_MYSQL_NODE_ISSUE_NONE,VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE);duplicate.request_id[14]=1;
    (void)create_dir(alice,&duplicate,VIREO_OK,VIREO_MYSQL_NODE_ISSUE_NONE,VIREO_MYSQL_NODE_MKDIR_EFFECT_CREATED);
    vireo_mysql_node_mkdir_once_input_t parent_in=make_input(alice_root,"temporary-parent",16);vireo_mysql_node_mkdir_once_report_t parent=create_dir(alice,&parent_in,VIREO_OK,VIREO_MYSQL_NODE_ISSUE_NONE,VIREO_MYSQL_NODE_MKDIR_EFFECT_CREATED);
    vireo_mysql_node_mkdir_once_input_t child=make_input(parent.node_id,"child",5);(void)create_dir(alice,&child,VIREO_OK,VIREO_MYSQL_NODE_ISSUE_NONE,VIREO_MYSQL_NODE_MKDIR_EFFECT_CREATED);
    (void)snprintf(sql,sizeof(sql),"UPDATE file_nodes SET state=3,deleted_at_ms=2000,updated_at_ms=2000 WHERE id=%llu",(unsigned long long)parent.node_id);mutate(sql);
    (void)create_dir(alice,&child,VIREO_OK,VIREO_MYSQL_NODE_ISSUE_NONE,VIREO_MYSQL_NODE_MKDIR_EFFECT_RECOVERED);
    vireo_mysql_node_mkdir_once_input_t failed=make_input(parent.node_id,"repair",6);(void)create_dir(alice,&failed,VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_NODE_NOT_FOUND,VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE);
    (void)snprintf(sql,sizeof(sql),"UPDATE file_nodes SET state=2,deleted_at_ms=NULL WHERE id=%llu",(unsigned long long)parent.node_id);mutate(sql);
    (void)create_dir(alice,&failed,VIREO_OK,VIREO_MYSQL_NODE_ISSUE_NONE,VIREO_MYSQL_NODE_MKDIR_EFFECT_CREATED);
    unsigned char maximum[255];memset(maximum,0xff,sizeof(maximum));in=make_input(alice_root,maximum,255);(void)create_dir(alice,&in,VIREO_OK,VIREO_MYSQL_NODE_ISSUE_NONE,VIREO_MYSQL_NODE_MKDIR_EFFECT_CREATED);(void)create_dir(alice,&in,VIREO_OK,VIREO_MYSQL_NODE_ISSUE_NONE,VIREO_MYSQL_NODE_MKDIR_EFFECT_RECOVERED);
    in=make_input(alice_root,"exec-history",12);first=create_dir(alice,&in,VIREO_OK,VIREO_MYSQL_NODE_ISSUE_NONE,VIREO_MYSQL_NODE_MKDIR_EFFECT_CREATED);exec_recover(argv,&in,first);
    (void)snprintf(sql,sizeof(sql),"SELECT last_seen_at_ms FROM sessions WHERE id=%llu",(unsigned long long)alice.session_id);assert(scalar(sql)==1000);
    (void)snprintf(sql,sizeof(sql),"SELECT updated_at_ms FROM file_nodes WHERE id=%llu",(unsigned long long)alice_root);assert(scalar(sql)==1000);
}
int main(int argc,char **argv)
{
    assert((argc==5 || argc==12) && !setvbuf(stdout,NULL,_IONBF,0));char password[1026];FILE *f=fopen(argv[3],"r");
    assert(f && fgets(password,(int)sizeof(password),f) && !fclose(f));password[strcspn(password,"\n")]=0;
    struct sigaction sa={0};sa.sa_handler=SIG_IGN;assert(!sigemptyset(&sa.sa_mask) && !sigaction(SIGPIPE,&sa,NULL));
    pthread_condattr_t attr;assert(!pthread_condattr_init(&attr) && !pthread_condattr_setclock(&attr,CLOCK_MONOTONIC));
    assert(!pthread_cond_init(&condition,&attr) && !pthread_condattr_destroy(&attr));size_t fd=fd_count();
    CHECK(vireo_mysql_runtime_create(&runtime,NULL),VIREO_OK);CHECK(vireo_mysql_thread_attach(runtime,&thread,NULL),VIREO_OK);
    vireo_mysql_connection_options_t options={argv[1],argv[2],password,argv[4],3,3,3};
    if(argc==5) {
        const vireo_mysql_migration_t *catalog;size_t count;CHECK(vireo_mysql_schema_catalog(&catalog,&count),VIREO_OK);vireo_mysql_migration_report_t migration;
        CHECK(vireo_mysql_migration_apply(thread,&options,catalog,count,&migration,NULL),VIREO_OK);assert(migration.ready && migration.steps_completed==15 && migration.applied_after==9);
    }
    CHECK(vireo_mysql_connection_open(thread,&options,&observer,NULL),VIREO_OK);
    vireo_mysql_pool_options_t config={options,4,4,VIREO_MYSQL_POOL_MEMORY_MAX};CHECK(vireo_mysql_pool_create(thread,&config,&pool,NULL),VIREO_OK);recreate(false);
    if(argc==12) {
        assert(!strcmp(argv[5],"recover"));alice=(vireo_mysql_node_actor_t){parse_id(argv[6]),parse_id(argv[7])};
        vireo_mysql_node_mkdir_once_input_t in={.parent_id=parse_id(argv[8]),.name=(const unsigned char *)"exec-history",.name_length=12,.idempotency_key={0x22},.request_id={0xee}};
        uint64_t key=parse_id(argv[11]);assert(key<=255);in.idempotency_key[15]=(unsigned char)key;
        vireo_mysql_node_mkdir_once_report_t recovered=create_dir(alice,&in,VIREO_OK,VIREO_MYSQL_NODE_ISSUE_NONE,VIREO_MYSQL_NODE_MKDIR_EFFECT_RECOVERED);
        assert(recovered.node_id==parse_id(argv[9]) && recovered.audit_id==parse_id(argv[10]));
        puts("PASS fresh exec process/guard/pool/repo recovered original node/audit from same live mysqld; inherited descriptors closed");
    } else {
        CHECK(vireo_mysql_user_repository_create(thread,pool,&policy,&users,NULL),VIREO_OK);
        const char pass[]="real-password";CHECK(vireo_password_hash_create(&policy,pass,sizeof(pass)-1,phc,sizeof(phc),&phc_length),VIREO_OK);
        alice=account("alice",&alice_root);bob=account("bob",&bob_root);business_cases(argv);fault_cases();concurrent(0);concurrent(1);concurrent(2);
        CHECK(vireo_mysql_user_repository_destroy(&users,NULL),VIREO_OK);
    }
    CHECK(vireo_mysql_node_repository_destroy(&nodes,NULL),VIREO_OK);bool closed=false;CHECK(vireo_mysql_pool_close(pool,&closed,NULL),VIREO_OK);assert(closed);
    CHECK(vireo_mysql_pool_destroy(thread,&pool,NULL),VIREO_OK);CHECK(vireo_mysql_connection_destroy(thread,&observer),VIREO_OK);
    CHECK(vireo_mysql_thread_detach(&thread),VIREO_OK);CHECK(vireo_mysql_runtime_destroy(&runtime),VIREO_OK);
    assert(!pthread_cond_destroy(&condition) && !pthread_mutex_destroy(&mutex));memset(password,0,sizeof(password));assert(fd_count()==fd);
    printf("PASS %zu real mkdir_once observations; atomic three writes/history/auth/retry/cleanup/exec; three dual-worker races with observed native1205 handshake; FD %zu -> %zu\n",cases,fd,fd_count());return 0;
}
