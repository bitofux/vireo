/* PROJECT : VIREO; FILE : test_mysql_node_move_real.c; AUTHOR : bitofux;
 * DATE : 2026-10-21; BRIEF : 真实移动/审计、祖先检查、三态提交与实际行锁等待。 */
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
static bool release_first,second_started,second_done,independent_user;
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
        assert(!second_done || independent_user);assert(!pthread_mutex_unlock(&mutex));
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
static uint64_t mkdir_at(vireo_mysql_node_actor_t who,uint64_t parent,const char *name)
{ vireo_mysql_node_mkdir_input_t in=make_input(parent,name,strlen(name));return create_dir(who,&in,VIREO_OK,VIREO_MYSQL_NODE_ISSUE_NONE).node.id; }
static vireo_mysql_node_move_input_t move_input(uint64_t id,uint64_t parent,const void *name,size_t n)
{
    assert(serial<250);vireo_mysql_node_move_input_t in={.node_id=id,.new_parent_id=parent,.name=name,.name_length=n,.request_id={0x44}};in.request_id[15]=++serial;return in;
}
static vireo_mysql_node_value_t stat_node(vireo_mysql_node_actor_t who,uint64_t id)
{
    vireo_mysql_node_value_t v;vireo_mysql_node_report_t report;
    CHECK(vireo_mysql_node_repository_stat(nodes,&who,id,0,&v,&report,NULL),VIREO_OK);return v;
}
static uint64_t field(uint64_t id,const char *column)
{
    char sql[256];int n=snprintf(sql,sizeof(sql),"SELECT %s FROM file_nodes WHERE id=%llu",column,(unsigned long long)id);assert(n>0 && (size_t)n<sizeof(sql));return scalar(sql);
}
static void set_parent(uint64_t id,uint64_t parent)
{
    char sql[256];int n=snprintf(sql,sizeof(sql),"UPDATE file_nodes SET parent_id=%llu WHERE id=%llu",(unsigned long long)parent,(unsigned long long)id);assert(n>0 && (size_t)n<sizeof(sql));mutate(sql);
}
static vireo_mysql_node_move_report_t move_node(vireo_mysql_node_actor_t who,
    const vireo_mysql_node_move_input_t *in,vireo_result_t want,vireo_mysql_node_issue_t issue)
{
    uint64_t before_nodes=scalar("SELECT COUNT(*) FROM file_nodes"),before_audits=scalar("SELECT COUNT(*) FROM operation_audits");
    uint64_t before_parent=field(in->node_id,"COALESCE(parent_id,0)"),before_time=field(in->node_id,"updated_at_ms");
    vireo_mysql_node_move_report_t out;vireo_mysql_node_error_t e;
    CHECK(vireo_mysql_node_repository_move(nodes,&who,in,0,&out,&e),want);assert(out.issue==issue && !out.cleanup_pending);
    if(want==VIREO_OK) {
        assert(out.commit==VIREO_MYSQL_NODE_MOVE_COMMITTED && out.node.id==in->node_id && out.audit_id && !out.rollback_confirmed);
        assert(out.node.owner_id==who.user_id && out.node.has_parent && out.node.parent_id==in->new_parent_id);
        assert(out.node.name_length==in->name_length && !memcmp(out.node.name,in->name,in->name_length));
        assert(out.node.updated_at_ms==(out.changed && sample_ms>before_time ? sample_ms : before_time));
        char sql[2048];int n=snprintf(sql,sizeof(sql),"SELECT COUNT(*) FROM operation_audits WHERE id=%llu AND user_id=%llu AND session_id=%llu AND action=6 AND target_type=3 AND target_id=%llu AND target_hash IS NULL AND status=0 AND latency_us=0 AND OCTET_LENGTH(detail)=0 AND occurred_at_ms=%llu",(unsigned long long)out.audit_id,(unsigned long long)who.user_id,(unsigned long long)who.session_id,(unsigned long long)out.node.id,(unsigned long long)sample_ms);
        assert(n>0 && (size_t)n<sizeof(sql) && scalar(sql)==1);
        vireo_mysql_node_value_t got=stat_node(who,in->node_id);assert(got.id==out.node.id && got.parent_id==out.node.parent_id && got.updated_at_ms==out.node.updated_at_ms && got.name_length==in->name_length && !memcmp(got.name,in->name,in->name_length));
    } else {
        assert(out.commit==VIREO_MYSQL_NODE_MOVE_NOT_COMMITTED && !out.audit_id && !out.changed);zeroed(&out.node,sizeof(out.node));
        assert(field(in->node_id,"COALESCE(parent_id,0)")==before_parent && field(in->node_id,"updated_at_ms")==before_time);
    }
    assert(scalar("SELECT COUNT(*) FROM file_nodes")==before_nodes);
    assert(scalar("SELECT COUNT(*) FROM operation_audits")==before_audits+(want==VIREO_OK ? 1u : 0u));++cases;refill_pool();return out;
}
static void fault_cases(uint64_t id,uint64_t parent)
{
    recreate(true);
    for(enum fault which=EXPIRE_AUDIT;which<=FAIL_UTC2;which=(enum fault)(which+1)) {
        fault=which;sample_ms=2000;utc_calls=0;commit_statement=NULL;audit_statement=NULL;
        char name[32];int n=snprintf(name,sizeof(name),"fault-%u",(unsigned)which);assert(n>0 && (size_t)n<sizeof(name));
        vireo_mysql_node_move_input_t in=move_input(id,parent,name,(size_t)n);
        uint64_t before_audits=scalar("SELECT COUNT(*) FROM operation_audits"),before_name=field(id,"CRC32(name)");
        vireo_mysql_node_move_report_t out;vireo_mysql_node_error_t e;
        vireo_result_t expected=which==EXPIRE_AUDIT ? VIREO_RESULT_NOT_FOUND : which==RELEASE_PENDING ? VIREO_RESULT_INTERNAL : which==FAIL_UTC2 ? VIREO_RESULT_IO : VIREO_RESULT_DATABASE;
        CHECK(vireo_mysql_node_repository_move(nodes,&alice,&in,0,&out,&e),expected);
        bool durable=which==LOST_COMMIT_REPLY || which==COMMIT_CLOSE || which==RELEASE_PENDING;
        assert(scalar("SELECT COUNT(*) FROM operation_audits")==before_audits+(durable ? 1u : 0u));
        if(durable) { char sql[256];n=snprintf(sql,sizeof(sql),"SELECT COUNT(*) FROM file_nodes WHERE id=%llu AND name='%s'",(unsigned long long)id,name);assert(n>0 && (size_t)n<sizeof(sql) && scalar(sql)==1); }
        else { assert(field(id,"CRC32(name)")==before_name); }
        if(which==LOST_COMMIT_REPLY) { assert(out.commit==VIREO_MYSQL_NODE_MOVE_UNKNOWN && !out.rollback_confirmed && !out.audit_id && !out.changed);zeroed(&out.node,sizeof(out.node)); }
        else if(which==COMMIT_CLOSE || which==RELEASE_PENDING) { assert(out.commit==VIREO_MYSQL_NODE_MOVE_COMMITTED && out.node.id==id && out.audit_id && out.changed && !out.rollback_confirmed); }
        else { assert(out.commit==VIREO_MYSQL_NODE_MOVE_NOT_COMMITTED && out.rollback_confirmed && !out.audit_id && !out.changed);zeroed(&out.node,sizeof(out.node)); }
        if(which==EXPIRE_AUDIT) { assert(out.issue==VIREO_MYSQL_NODE_AUTH_REJECTED && utc_calls==2); }
        if(which==RELEASE_PENDING) {
            assert(out.cleanup_pending);vireo_mysql_node_move_report_t again;
            CHECK(vireo_mysql_node_repository_move(nodes,&alice,&in,0,&again,NULL),VIREO_RESULT_BUSY);assert(again.cleanup_pending);
            fault=NONE;recreate(true);
        } else { assert(!out.cleanup_pending); }
        ++cases;refill_pool();
    }
    fault=NONE;sample_ms=2000;recreate(false);
    puts("PASS real UPDATE/audit rollback after expiry/UTC failure; real COMMIT hidden reply and confirmed commit survives cleanup faults (injected seams)");
}
struct worker { bool first,logout,mkdir,bob;uint64_t id,parent;const char *name;unsigned char event;vireo_result_t result;vireo_mysql_node_move_report_t report; };
static vireo_result_t second_execute(vireo_mysql_thread_t *t,vireo_mysql_statement_t *s,
    const vireo_mysql_parameter_t *p,size_t n,vireo_mysql_execution_t *out,vireo_mysql_error_t *e)
{
    if(n==1) { assert(!pthread_mutex_lock(&mutex));second_started=true;assert(!pthread_cond_broadcast(&condition));assert(!pthread_mutex_unlock(&mutex)); }
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
        vireo_mysql_node_ops_t ops=vireo_mysql_node_native_ops;ops.utc=w->first ? paused_utc : fixed_utc;if(!w->first) { ops.execute=second_execute; }
        vireo_mysql_node_repository_t *r=NULL;CHECK(vireo_mysql_node_repository_create_with_ops(t,pool,&r,NULL,&ops),VIREO_OK);
        if(w->mkdir) {
            vireo_mysql_node_mkdir_input_t in={.parent_id=w->parent,.name=(const unsigned char *)w->name,.name_length=strlen(w->name),.request_id={0x71}};in.request_id[15]=w->event;
            vireo_mysql_node_mkdir_report_t out;CHECK(vireo_mysql_node_repository_mkdir(r,&alice,&in,0,&out,NULL),VIREO_OK);assert(out.commit==VIREO_MYSQL_NODE_MKDIR_COMMITTED);w->result=VIREO_OK;
        } else {
            vireo_mysql_node_move_input_t in={.node_id=w->id,.new_parent_id=w->parent,.name=(const unsigned char *)w->name,.name_length=strlen(w->name),.request_id={0x70}};in.request_id[15]=w->event;
            errno=EDOM;w->result=vireo_mysql_node_repository_move(r,w->bob ? &bob : &alice,&in,0,&w->report,NULL);assert(errno==EDOM);
        }
        CHECK(vireo_mysql_node_repository_destroy(&r,NULL),VIREO_OK);
    }
    if(!w->first) { assert(!pthread_mutex_lock(&mutex));second_done=true;assert(!pthread_cond_broadcast(&condition));assert(!pthread_mutex_unlock(&mutex)); }
    CHECK(vireo_mysql_thread_detach(&t),VIREO_OK);return NULL;
}
/* SHOW GLOBAL STATUS is available to the fixture user and does not require performance_schema/PROCESS. */
static uint64_t lock_waits(void)
{
    vireo_mysql_statement_t *s=execute_sql("SHOW GLOBAL STATUS LIKE 'Innodb_row_lock_current_waits'",true);
    vireo_mysql_fetch_outcome_t f;vireo_mysql_cell_view_t c;
    CHECK(vireo_mysql_statement_fetch(thread,s,&f,NULL),VIREO_OK);assert(f==VIREO_MYSQL_FETCH_ROW);
    CHECK(vireo_mysql_statement_column(thread,s,1,&c),VIREO_OK);assert(!c.is_null && c.length<32);char text[32]={0};memcpy(text,c.data,c.length);
    char *end;errno=0;unsigned long long n=strtoull(text,&end,10);assert(!errno && !*end);
    CHECK(vireo_mysql_statement_fetch(thread,s,&f,NULL),VIREO_OK);assert(f==VIREO_MYSQL_FETCH_DONE);
    CHECK(vireo_mysql_statement_destroy(thread,&s,NULL),VIREO_OK);return (uint64_t)n;
}
static void concurrent(unsigned scenario)
{
    char a_name[32],b_name[32];int na=snprintf(a_name,sizeof(a_name),"race-a-%u",scenario),nb=snprintf(b_name,sizeof(b_name),"race-b-%u",scenario);assert(na>0 && nb>0);
    uint64_t a=mkdir_at(alice,alice_root,a_name),a_child=mkdir_at(alice,a,"a-child");
    uint64_t b=mkdir_at(alice,alice_root,b_name),b_child=mkdir_at(alice,b,"b-child");
    uint64_t bob_node=0;if(scenario==3) { bob_node=mkdir_at(bob,bob_root,"bob-race"); }
    phase=0;release_first=false;second_started=false;second_done=false;independent_user=scenario==3;assert(lock_waits()==0);
    struct worker first={.first=true,.id=a,.parent=b_child,.name="moved-a",.event=(unsigned char)(scenario*2+1)};
    struct worker second={.logout=scenario==2,.mkdir=scenario==1,.bob=scenario==3,.id=scenario==3 ? bob_node : b,.parent=scenario==3 ? bob_root : a_child,.name="second",.event=(unsigned char)(scenario*2+2)};
    uint64_t audits=scalar("SELECT COUNT(*) FROM operation_audits");
    pthread_t t1,t2;assert(!pthread_create(&t1,NULL,work,&first));assert(!pthread_mutex_lock(&mutex));
    struct timespec due=deadline();while(phase!=1) { assert(!pthread_cond_timedwait(&condition,&mutex,&due)); }assert(!pthread_mutex_unlock(&mutex));
    assert(!pthread_create(&t2,NULL,work,&second));assert(!pthread_mutex_lock(&mutex));wait_flag(&second_started);assert(!pthread_mutex_unlock(&mutex));
    if(scenario<3) {
        bool observed=false;due=deadline();
        do { if(lock_waits()>0) { observed=true;break; }struct timespec now;assert(!clock_gettime(CLOCK_MONOTONIC,&now));if(now.tv_sec>=due.tv_sec) { break; }struct timespec pause={0,1000000};assert(!nanosleep(&pause,NULL)); }while(!observed);
        assert(observed);printf("PASS observed InnoDB row-lock wait with first move paused holding user X, scenario %u\n",scenario);
    } else { assert(!pthread_mutex_lock(&mutex));wait_flag(&second_done);assert(!pthread_mutex_unlock(&mutex));assert(lock_waits()==0); }
    assert(!pthread_mutex_lock(&mutex));if(scenario<3) { assert(!second_done); }release_first=true;assert(!pthread_cond_broadcast(&condition));assert(!pthread_mutex_unlock(&mutex));
    assert(!pthread_join(t1,NULL) && !pthread_join(t2,NULL));assert(first.result==VIREO_OK && first.report.commit==VIREO_MYSQL_NODE_MOVE_COMMITTED && second_done);
    if(scenario==0) { assert(second.result==VIREO_RESULT_DATABASE && second.report.issue==VIREO_MYSQL_NODE_MOVE_CYCLE && second.report.rollback_confirmed);assert(field(a,"parent_id")==b_child && field(b,"parent_id")==alice_root); }
    if(scenario==1 || scenario==3) { assert(second.result==VIREO_OK); }
    assert(scalar("SELECT COUNT(*) FROM operation_audits")==audits+(scenario==0 ? 1u : 2u));++cases;refill_pool();
    if(scenario==2) {
        vireo_mysql_node_move_input_t in=move_input(a,alice_root,"after-logout",12);
        (void)move_node(alice,&in,VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_NODE_AUTH_REJECTED);
        struct worker later={.id=a,.parent=alice_root,.name="later",.event=99};assert(!pthread_create(&t2,NULL,work,&later) && !pthread_join(t2,NULL));assert(later.result==VIREO_RESULT_NOT_FOUND && later.report.issue==VIREO_MYSQL_NODE_AUTH_REJECTED);++cases;
    }
}
static size_t fd_count(void)
{ DIR *d=opendir("/proc/self/fd");assert(d);size_t n=0;while(readdir(d)) { ++n; }assert(!closedir(d));return n; }
static uint64_t insert_dir(uint64_t parent,const char *name)
{
    char sql[512];int n=snprintf(sql,sizeof(sql),"INSERT INTO file_nodes(owner_id,parent_id,name,node_type,state,object_hash,size,created_at_ms,updated_at_ms,deleted_at_ms) VALUES(%llu,%llu,'%s',1,2,NULL,0,1000,1000,NULL)",(unsigned long long)alice.user_id,(unsigned long long)parent,name);assert(n>0 && (size_t)n<sizeof(sql));mutate(sql);return scalar("SELECT LAST_INSERT_ID()");
}
static void boundary_cases(uint64_t id)
{
    uint64_t end=alice_root;
    for(size_t depth=2;depth<=257;++depth) {
        end=insert_dir(end,"deep");
        if(depth==255 || depth==256 || depth==257) {
            vireo_mysql_node_move_input_t in=move_input(id,end,"deep-source",11);
            (void)move_node(alice,&in,depth<=256 ? VIREO_OK : VIREO_RESULT_RANGE,depth<=256 ? VIREO_MYSQL_NODE_ISSUE_NONE : VIREO_MYSQL_NODE_ANCESTRY_LIMIT);
            set_parent(id,alice_root);
            /* Check the independent old-parent chain budget too. */
            set_parent(id,end);in=move_input(id,alice_root,"from-deep",9);
            (void)move_node(alice,&in,depth<=256 ? VIREO_OK : VIREO_RESULT_RANGE,depth<=256 ? VIREO_MYSQL_NODE_ISSUE_NONE : VIREO_MYSQL_NODE_ANCESTRY_LIMIT);set_parent(id,alice_root);
        }
    }
}
int main(int argc,char **argv)
{
    assert(argc==5 && !setvbuf(stdout,NULL,_IONBF,0));char password[1026];FILE *f=fopen(argv[3],"r");
    assert(f && fgets(password,(int)sizeof(password),f) && !fclose(f));password[strcspn(password,"\n")]=0;
    struct sigaction sa={0};sa.sa_handler=SIG_IGN;assert(!sigemptyset(&sa.sa_mask) && !sigaction(SIGPIPE,&sa,NULL));
    pthread_condattr_t attr;assert(!pthread_condattr_init(&attr) && !pthread_condattr_setclock(&attr,CLOCK_MONOTONIC));assert(!pthread_cond_init(&condition,&attr) && !pthread_condattr_destroy(&attr));size_t fd=fd_count();
    CHECK(vireo_mysql_runtime_create(&runtime,NULL),VIREO_OK);CHECK(vireo_mysql_thread_attach(runtime,&thread,NULL),VIREO_OK);
    vireo_mysql_connection_options_t options={argv[1],argv[2],password,argv[4],3,3,3};
    const vireo_mysql_migration_t *catalog;size_t count;CHECK(vireo_mysql_schema_catalog(&catalog,&count),VIREO_OK);vireo_mysql_migration_report_t migration;
    CHECK(vireo_mysql_migration_apply(thread,&options,catalog,count,&migration,NULL),VIREO_OK);assert(migration.ready && migration.steps_completed==17);
    CHECK(vireo_mysql_connection_open(thread,&options,&observer,NULL),VIREO_OK);
    vireo_mysql_pool_options_t config={options,4,4,VIREO_MYSQL_POOL_MEMORY_MAX};CHECK(vireo_mysql_pool_create(thread,&config,&pool,NULL),VIREO_OK);
    CHECK(vireo_mysql_user_repository_create(thread,pool,&policy,&users,NULL),VIREO_OK);
    const char pass[]="real-password";CHECK(vireo_password_hash_create(&policy,pass,sizeof(pass)-1,phc,sizeof(phc),&phc_length),VIREO_OK);
    alice=account("alice",&alice_root);bob=account("bob",&bob_root);recreate(false);
    uint64_t source=mkdir_at(alice,alice_root,"资料"),child=mkdir_at(alice,source,"child"),target=mkdir_at(alice,alice_root,"归档");
    vireo_mysql_node_move_input_t in=move_input(source,target,"旧资料",sizeof("旧资料")-1);
    vireo_mysql_node_move_report_t moved=move_node(alice,&in,VIREO_OK,VIREO_MYSQL_NODE_ISSUE_NONE);assert(moved.changed && field(child,"parent_id")==source && moved.node.created_at_ms==2000);
    uint64_t before_time=field(source,"updated_at_ms");sample_ms=2500;in=move_input(source,target,"旧资料",sizeof("旧资料")-1);
    vireo_mysql_node_move_report_t noop=move_node(alice,&in,VIREO_OK,VIREO_MYSQL_NODE_ISSUE_NONE);assert(!noop.changed && noop.node.updated_at_ms==before_time);
    vireo_mysql_node_move_input_t duplicate=in;duplicate.name=(const unsigned char *)"rollback-name";duplicate.name_length=13;
    (void)move_node(alice,&duplicate,VIREO_RESULT_DATABASE,VIREO_MYSQL_NODE_ISSUE_NONE);assert(field(source,"updated_at_ms")==before_time);
    sample_ms=1800;in=move_input(source,target,"backward",8);moved=move_node(alice,&in,VIREO_OK,VIREO_MYSQL_NODE_ISSUE_NONE);assert(moved.node.updated_at_ms==2000);sample_ms=2000;
    in=move_input(source,child,"cycle",5);(void)move_node(alice,&in,VIREO_RESULT_DATABASE,VIREO_MYSQL_NODE_MOVE_CYCLE);
    in=move_input(source,source,"self",4);(void)move_node(alice,&in,VIREO_RESULT_DATABASE,VIREO_MYSQL_NODE_MOVE_CYCLE);
    in=move_input(alice_root,target,"root",4);(void)move_node(alice,&in,VIREO_RESULT_DATABASE,VIREO_MYSQL_NODE_ROOT_IMMOVABLE);
    in=move_input(bob_root,target,"foreign",7);(void)move_node(alice,&in,VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_NODE_NOT_FOUND);
    in=move_input(source,bob_root,"foreign",7);(void)move_node(alice,&in,VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_NODE_NOT_FOUND);
    char sql[2048];int n=snprintf(sql,sizeof(sql),"INSERT INTO file_nodes(owner_id,parent_id,name,node_type,state,object_hash,size,created_at_ms,updated_at_ms,deleted_at_ms) VALUES(%llu,%llu,'uploading',2,1,NULL,0,1000,1000,NULL),(%llu,%llu,'deleted',1,3,NULL,0,1000,1000,1000)",(unsigned long long)alice.user_id,(unsigned long long)target,(unsigned long long)alice.user_id,(unsigned long long)target);assert(n>0 && (size_t)n<sizeof(sql));mutate(sql);
    uint64_t uploading=scalar("SELECT MAX(id)-1 FROM file_nodes"),deleted=uploading+1;
    in=move_input(source,target,"uploading",9);(void)move_node(alice,&in,VIREO_RESULT_DATABASE,VIREO_MYSQL_NODE_NAME_CONFLICT);
    for(unsigned which=0;which<2;++which) { in=move_input(which ? deleted : uploading,target,"inactive",8);(void)move_node(alice,&in,VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_NODE_NOT_FOUND); }
    in=move_input(source,target,"deleted",7);(void)move_node(alice,&in,VIREO_OK,VIREO_MYSQL_NODE_ISSUE_NONE);
    mutate("INSERT INTO objects(object_hash,size,state,ref_count,storage_class,created_at_ms,updated_at_ms,verified_at_ms) VALUES(UNHEX(REPEAT('a9',32)),91,2,1,1,1000,1000,1000)");
    (void)snprintf(sql,sizeof(sql),"UPDATE file_nodes SET state=2,size=91,object_hash=UNHEX(REPEAT('a9',32)) WHERE id=%llu",(unsigned long long)uploading);mutate(sql);
    in=move_input(source,uploading,"file-parent",11);(void)move_node(alice,&in,VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_NODE_NOT_FOUND);
    in=move_input(source,target,"uploading",9);(void)move_node(alice,&in,VIREO_RESULT_DATABASE,VIREO_MYSQL_NODE_NAME_CONFLICT);
    in=move_input(uploading,alice_root,"active-file",11);moved=move_node(alice,&in,VIREO_OK,VIREO_MYSQL_NODE_ISSUE_NONE);assert(moved.node.kind==VIREO_MYSQL_NODE_FILE && moved.node.has_object_hash && moved.node.size==91 && moved.node.created_at_ms==1000);for(size_t i=0;i<32;++i) { assert(moved.node.object_hash[i]==0xa9); }
    uint64_t bad=mkdir_at(alice,alice_root,"bad-parent");set_parent(source,bad);set_parent(bad,bad);
    in=move_input(source,alice_root,"invalid-old-chain",17);(void)move_node(alice,&in,VIREO_RESULT_DATABASE,VIREO_MYSQL_NODE_TREE_INVALID);set_parent(bad,alice_root);set_parent(source,target);
    set_parent(bad,bad);in=move_input(source,bad,"invalid-new-chain",17);(void)move_node(alice,&in,VIREO_RESULT_DATABASE,VIREO_MYSQL_NODE_TREE_INVALID);set_parent(bad,alice_root);
    set_parent(source,deleted);in=move_input(source,alice_root,"inactive-ancestor",17);(void)move_node(alice,&in,VIREO_RESULT_DATABASE,VIREO_MYSQL_NODE_TREE_INVALID);set_parent(source,target);
    set_parent(source,uploading);in=move_input(source,alice_root,"file-ancestor",13);(void)move_node(alice,&in,VIREO_RESULT_DATABASE,VIREO_MYSQL_NODE_TREE_INVALID);set_parent(source,target);
    boundary_cases(source);
    unsigned char maximum[255];memset(maximum,0xff,sizeof(maximum));in=move_input(source,target,maximum,255);(void)move_node(alice,&in,VIREO_OK,VIREO_MYSQL_NODE_ISSUE_NONE);
    const unsigned char *names[]={(const unsigned char *)"A",(const unsigned char *)"a",(const unsigned char *)" a",(const unsigned char *)"a ",(const unsigned char *)"\xff",(const unsigned char *)"\x01"};const size_t lengths[]={1,1,2,2,1,1};
    for(size_t i=0;i<6;++i) { in=move_input(source,target,names[i],lengths[i]);(void)move_node(alice,&in,VIREO_OK,VIREO_MYSQL_NODE_ISSUE_NONE); }
    vireo_mysql_node_list_query_t query={target,0,64};vireo_mysql_node_page_t page;vireo_mysql_node_report_t rr;CHECK(vireo_mysql_node_repository_list_children(nodes,&alice,&query,0,&page,&rr,NULL),VIREO_OK);bool found=false;for(size_t i=0;i<page.count;++i) { if(page.nodes[i].id==source) { found=true;assert(page.nodes[i].name_length==1 && page.nodes[i].name[0]==1); } }assert(found);++cases;
    assert(field(alice_root,"updated_at_ms")==1000);(void)snprintf(sql,sizeof(sql),"SELECT last_seen_at_ms FROM sessions WHERE id=%llu",(unsigned long long)alice.session_id);assert(scalar(sql)==1000);
    vireo_mysql_node_actor_t forged={bob.user_id,alice.session_id};in=move_input(source,target,"forged",6);(void)move_node(forged,&in,VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_NODE_AUTH_REJECTED);
    mutate("UPDATE users SET status=2 WHERE username_key='alice'");(void)move_node(alice,&in,VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_NODE_AUTH_REJECTED);mutate("UPDATE users SET status=1 WHERE username_key='alice'");
    const uint64_t times[]={999,1000,2999,3000};for(size_t i=0;i<4;++i) {
        sample_ms=times[i];in=move_input(source,target,"time",4);bool ok=sample_ms>=1000 && sample_ms<3000;(void)move_node(alice,&in,ok ? VIREO_OK : VIREO_RESULT_NOT_FOUND,ok ? VIREO_MYSQL_NODE_ISSUE_NONE : VIREO_MYSQL_NODE_AUTH_REJECTED);
    }
    in=move_input(alice_root,target,"expired-root",12);(void)move_node(alice,&in,VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_NODE_AUTH_REJECTED);sample_ms=2000;
    fault_cases(source,target);concurrent(0);concurrent(1);concurrent(3);concurrent(2);
    (void)snprintf(sql,sizeof(sql),"UPDATE sessions SET expires_at_ms=18446744073709551615 WHERE id=%llu",(unsigned long long)bob.session_id);mutate(sql);
    uint64_t native_source=mkdir_at(bob,bob_root,"native-source");CHECK(vireo_mysql_node_repository_destroy(&nodes,NULL),VIREO_OK);CHECK(vireo_mysql_node_repository_create(thread,pool,&nodes,NULL),VIREO_OK);
    in=move_input(native_source,bob_root,"native-time",11);vireo_mysql_node_move_report_t native;CHECK(vireo_mysql_node_repository_move(nodes,&bob,&in,0,&native,NULL),VIREO_OK);assert(native.commit==VIREO_MYSQL_NODE_MOVE_COMMITTED && native.node.updated_at_ms>3000 && native.changed && native.audit_id);++cases;
    CHECK(vireo_mysql_node_repository_destroy(&nodes,NULL),VIREO_OK);assert(noop.node.name_length==sizeof("旧资料")-1 && !memcmp(noop.node.name,"旧资料",sizeof("旧资料")-1));
    CHECK(vireo_mysql_user_repository_destroy(&users,NULL),VIREO_OK);bool closed=false;CHECK(vireo_mysql_pool_close(pool,&closed,NULL),VIREO_OK);assert(closed);
    CHECK(vireo_mysql_pool_destroy(thread,&pool,NULL),VIREO_OK);CHECK(vireo_mysql_connection_destroy(thread,&observer),VIREO_OK);
    CHECK(vireo_mysql_thread_detach(&thread),VIREO_OK);CHECK(vireo_mysql_runtime_destroy(&runtime),VIREO_OK);
    assert(!pthread_cond_destroy(&condition) && !pthread_mutex_destroy(&mutex));memset(password,0,sizeof(password));assert(fd_count()==fd);
    printf("PASS %zu real move observations: update/audit atomicity, unchanged, tree256/257, hidden commit response, native UTC; three actual row-lock waits / reciprocal four-row branches / mkdir / logout / other user; FD %zu -> %zu\n",cases,fd,fd_count());return 0;
}
