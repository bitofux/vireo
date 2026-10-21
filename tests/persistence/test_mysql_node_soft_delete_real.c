/* PROJECT : VIREO; FILE : test_mysql_node_soft_delete_real.c; AUTHOR : bitofux;
 * DATE : 2026-10-21; BRIEF : 真实软删除、对象引用/审计原子性与锁等待。 */
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
enum fault { NONE, EXPIRE_AUDIT, LOST_COMMIT_REPLY, NO_NATIVE_COMMIT, COMMIT_CLOSE, RELEASE_PENDING, FAIL_UTC2, FAIL_OBJECT_UPDATE };
static enum fault fault;
static vireo_mysql_statement_t *commit_statement,*audit_statement,*object_update_statement;
static vireo_result_t fault_prepare(vireo_mysql_thread_t *t,vireo_mysql_connection_t *c,
    const char *sql,size_t n,const vireo_mysql_statement_limits_t *l,vireo_mysql_statement_t **out,vireo_mysql_error_t *e)
{
    vireo_result_t rc=vireo_mysql_statement_prepare(t,c,sql,n,l,out,e);
    if(rc==VIREO_OK) { if(!strcmp(sql,"COMMIT")) { commit_statement=*out; }if(strstr(sql,"INSERT INTO operation_audits")) { audit_statement=*out; }if(strstr(sql,"UPDATE objects SET")) { object_update_statement=*out; } }
    return rc;
}
static vireo_result_t fault_execute(vireo_mysql_thread_t *t,vireo_mysql_statement_t *s,
    const vireo_mysql_parameter_t *p,size_t n,vireo_mysql_execution_t *out,vireo_mysql_error_t *e)
{
    if(s==commit_statement && fault==NO_NATIVE_COMMIT) {
        *out=(vireo_mysql_execution_t){0};*e=(vireo_mysql_error_t){.mysql_code=2013};return VIREO_RESULT_DATABASE;
    }
    if(s==object_update_statement && fault==FAIL_OBJECT_UPDATE) { *out=(vireo_mysql_execution_t){0};*e=(vireo_mysql_error_t){.mysql_code=2013};return VIREO_RESULT_DATABASE; }
    vireo_result_t rc=vireo_mysql_statement_execute(t,s,p,n,out,e);
    if(rc==VIREO_OK && s==audit_statement && fault==EXPIRE_AUDIT) { sample_ms=3000; }
    if(rc==VIREO_OK && s==commit_statement && fault==LOST_COMMIT_REPLY) { e->mysql_code=2013;return VIREO_RESULT_DATABASE; }
    return rc;
}
static vireo_result_t fault_close(vireo_mysql_thread_t *t,vireo_mysql_statement_t **s,vireo_mysql_error_t *e)
{
    bool commit=*s==commit_statement;bool audit=*s==audit_statement;bool object_update=*s==object_update_statement;
    vireo_result_t rc=vireo_mysql_statement_destroy(t,s,e);
    if(*s==NULL) { if(commit) { commit_statement=NULL; }if(audit) { audit_statement=NULL; }if(object_update) { object_update_statement=NULL; } }
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
static vireo_mysql_node_soft_delete_input_t delete_input(uint64_t id)
{ assert(serial<250);vireo_mysql_node_soft_delete_input_t in={.node_id=id,.request_id={0x55}};in.request_id[15]=++serial;return in; }
static uint64_t field(uint64_t id,const char *column)
{ char sql[256];int n=snprintf(sql,sizeof(sql),"SELECT %s FROM file_nodes WHERE id=%llu",column,(unsigned long long)id);assert(n>0 && (size_t)n<sizeof(sql));return scalar(sql); }
static void set_parent(uint64_t id,uint64_t parent)
{ char sql[256];int n=snprintf(sql,sizeof(sql),"UPDATE file_nodes SET parent_id=%llu WHERE id=%llu",(unsigned long long)parent,(unsigned long long)id);assert(n>0 && (size_t)n<sizeof(sql));mutate(sql); }
/* Controlled SQL fixtures prepare active/uploading files; upload/CAS service is not implemented here. */
static void object_fixture(unsigned hash,unsigned state,uint64_t refs)
{
    char sql[640];int n=snprintf(sql,sizeof(sql),"INSERT INTO objects(object_hash,size,state,ref_count,storage_class,created_at_ms,updated_at_ms,verified_at_ms) VALUES(UNHEX(REPEAT('%02x',32)),91,%u,%llu,1,1000,1500,%s)",hash,state,(unsigned long long)refs,state==2 ? "1000" : "NULL");assert(n>0 && (size_t)n<sizeof(sql));mutate(sql);
}
static uint64_t file_fixture(vireo_mysql_node_actor_t who,uint64_t parent,const char *name,unsigned hash,unsigned state)
{
    char sql[640],payload[64];int k=snprintf(payload,sizeof(payload),"UNHEX(REPEAT('%02x',32))",hash);assert(k>0 && (size_t)k<sizeof(payload));
    int n=snprintf(sql,sizeof(sql),"INSERT INTO file_nodes(owner_id,parent_id,name,node_type,state,object_hash,size,created_at_ms,updated_at_ms,deleted_at_ms) VALUES(%llu,%llu,'%s',2,%u,%s,91,1000,1500,%s)",(unsigned long long)who.user_id,(unsigned long long)parent,name,state,state==1 ? "NULL" : payload,state==3 ? "1500" : "NULL");assert(n>0 && (size_t)n<sizeof(sql));mutate(sql);return scalar("SELECT LAST_INSERT_ID()");
}
static uint64_t refs(unsigned hash)
{ char sql[192];int n=snprintf(sql,sizeof(sql),"SELECT ref_count FROM objects WHERE object_hash=UNHEX(REPEAT('%02x',32))",hash);assert(n>0 && (size_t)n<sizeof(sql));return scalar(sql); }
static uint64_t node_signature(uint64_t id)
{
    char sql[640];int n=snprintf(sql,sizeof(sql),"SELECT COALESCE(MAX(CRC32(CONCAT_WS(':',id,owner_id,COALESCE(parent_id,0),HEX(name),node_type,state,COALESCE(HEX(object_hash),''),size,created_at_ms,updated_at_ms,COALESCE(deleted_at_ms,0)))),0) FROM file_nodes WHERE id=%llu",(unsigned long long)id);assert(n>0 && (size_t)n<sizeof(sql));return scalar(sql);
}
static void absent(vireo_mysql_node_actor_t who,uint64_t id)
{
    vireo_mysql_node_value_t value;memset(&value,0xa5,sizeof(value));vireo_mysql_node_report_t report;
    CHECK(vireo_mysql_node_repository_stat(nodes,&who,id,0,&value,&report,NULL),VIREO_RESULT_NOT_FOUND);
    assert(report.issue==VIREO_MYSQL_NODE_NOT_FOUND);zeroed(&value,sizeof(value));
}
static vireo_mysql_node_soft_delete_report_t delete_node(vireo_mysql_node_actor_t who,
    const vireo_mysql_node_soft_delete_input_t *in,vireo_result_t want,vireo_mysql_node_issue_t issue)
{
    uint64_t before_nodes=scalar("SELECT COUNT(*) FROM file_nodes"),before_audits=scalar("SELECT COUNT(*) FROM operation_audits"),signature=node_signature(in->node_id);
    uint64_t before_refs=scalar("SELECT COALESCE(SUM(ref_count),0) FROM objects"),old_updated=0,kind=0;
    if(want==VIREO_OK) { old_updated=field(in->node_id,"updated_at_ms");kind=field(in->node_id,"node_type"); }
    vireo_mysql_node_soft_delete_report_t out;vireo_mysql_node_error_t e;
    CHECK(vireo_mysql_node_repository_soft_delete(nodes,&who,in,0,&out,&e),want);assert(out.issue==issue && !out.cleanup_pending);
    if(want==VIREO_OK) {
        assert(out.commit==VIREO_MYSQL_NODE_SOFT_DELETE_COMMITTED && out.node_id==in->node_id && out.audit_id && !out.rollback_confirmed);
        assert(field(in->node_id,"state")==3 && field(in->node_id,"deleted_at_ms")==out.deleted_at_ms && field(in->node_id,"updated_at_ms")==out.deleted_at_ms);
        assert(out.deleted_at_ms==(sample_ms>old_updated ? sample_ms : old_updated));
        assert(scalar("SELECT COALESCE(SUM(ref_count),0) FROM objects")==before_refs-(kind==2 ? 1u : 0u));
        char sql[1024];int n=snprintf(sql,sizeof(sql),"SELECT COUNT(*) FROM operation_audits WHERE id=%llu AND user_id=%llu AND session_id=%llu AND action=7 AND target_type=3 AND target_id=%llu AND target_hash IS NULL AND status=0 AND latency_us=0 AND OCTET_LENGTH(detail)=0 AND occurred_at_ms=%llu",(unsigned long long)out.audit_id,(unsigned long long)who.user_id,(unsigned long long)who.session_id,(unsigned long long)out.node_id,(unsigned long long)sample_ms);assert(n>0 && (size_t)n<sizeof(sql) && scalar(sql)==1);
        absent(who,in->node_id);
    } else {
        assert(out.commit==VIREO_MYSQL_NODE_SOFT_DELETE_NOT_COMMITTED && !out.node_id && !out.audit_id && !out.deleted_at_ms && out.rollback_confirmed);
        assert(node_signature(in->node_id)==signature && scalar("SELECT COALESCE(SUM(ref_count),0) FROM objects")==before_refs);
    }
    assert(scalar("SELECT COUNT(*) FROM file_nodes")==before_nodes);
    assert(scalar("SELECT COUNT(*) FROM operation_audits")==before_audits+(want==VIREO_OK ? 1u : 0u));++cases;refill_pool();return out;
}
static void fault_cases(void)
{
    for(enum fault which=EXPIRE_AUDIT;which<=FAIL_OBJECT_UPDATE;which=(enum fault)(which+1)) {
        unsigned hash=0x80u+(unsigned)which;object_fixture(hash,2,1);char name[32];int n=snprintf(name,sizeof(name),"fault-%u",(unsigned)which);assert(n>0 && (size_t)n<sizeof(name));
        uint64_t id=file_fixture(alice,alice_root,name,hash,2);vireo_mysql_node_soft_delete_input_t in=delete_input(id);
        recreate(true);fault=which;sample_ms=2000;utc_calls=0;commit_statement=NULL;audit_statement=NULL;object_update_statement=NULL;
        uint64_t before_audits=scalar("SELECT COUNT(*) FROM operation_audits"),signature=node_signature(id);
        vireo_mysql_node_soft_delete_report_t out;vireo_mysql_node_error_t e;
        vireo_result_t want=which==EXPIRE_AUDIT ? VIREO_RESULT_NOT_FOUND : which==RELEASE_PENDING ? VIREO_RESULT_INTERNAL : which==FAIL_UTC2 ? VIREO_RESULT_IO : VIREO_RESULT_DATABASE;
        CHECK(vireo_mysql_node_repository_soft_delete(nodes,&alice,&in,0,&out,&e),want);
        bool durable=which==LOST_COMMIT_REPLY || which==COMMIT_CLOSE || which==RELEASE_PENDING;
        assert(scalar("SELECT COUNT(*) FROM operation_audits")==before_audits+(durable ? 1u : 0u) && refs(hash)==(durable ? 0u : 1u));
        if(durable) { assert(field(id,"state")==3); }else { assert(node_signature(id)==signature); }
        if(which==LOST_COMMIT_REPLY) { assert(out.commit==VIREO_MYSQL_NODE_SOFT_DELETE_UNKNOWN && !out.rollback_confirmed && !out.node_id && !out.audit_id && !out.deleted_at_ms); }
        else if(which==COMMIT_CLOSE || which==RELEASE_PENDING) { assert(out.commit==VIREO_MYSQL_NODE_SOFT_DELETE_COMMITTED && out.node_id==id && out.audit_id && out.deleted_at_ms==2000 && !out.rollback_confirmed); }
        else { assert(out.commit==VIREO_MYSQL_NODE_SOFT_DELETE_NOT_COMMITTED && out.rollback_confirmed && !out.node_id && !out.audit_id && !out.deleted_at_ms); }
        if(which==EXPIRE_AUDIT) { assert(out.issue==VIREO_MYSQL_NODE_AUTH_REJECTED && utc_calls==2); }
        if(which==RELEASE_PENDING) {
            assert(out.cleanup_pending);vireo_mysql_node_soft_delete_report_t again;
            CHECK(vireo_mysql_node_repository_soft_delete(nodes,&alice,&in,0,&again,NULL),VIREO_RESULT_BUSY);assert(again.cleanup_pending);
        } else { assert(!out.cleanup_pending); }
        fault=NONE;sample_ms=2000;recreate(false);refill_pool();++cases;
    }
    puts("PASS actual SQL node/object/audit rollback at object failure, audit/UTC expiry, and commit/cleanup seams; seams are not native network failures");
}
struct worker { bool first,mkdir,move,logout,bob;uint64_t id,parent;const char *name;unsigned char event;vireo_result_t result;vireo_mysql_node_soft_delete_report_t report;vireo_mysql_node_issue_t issue; };
static vireo_result_t second_execute(vireo_mysql_thread_t *t,vireo_mysql_statement_t *s,
    const vireo_mysql_parameter_t *p,size_t n,vireo_mysql_execution_t *out,vireo_mysql_error_t *e)
{
    if(n==1) { assert(!pthread_mutex_lock(&mutex));second_started=true;assert(!pthread_cond_broadcast(&condition));assert(!pthread_mutex_unlock(&mutex)); }
    return vireo_mysql_statement_execute(t,s,p,n,out,e);
}
static void *work(void *arg)
{
    struct worker *w=arg;vireo_mysql_thread_t *t=NULL;CHECK(vireo_mysql_thread_attach(runtime,&t,NULL),VIREO_OK);utc_calls=0;sample_ms=2000;
    const vireo_mysql_node_actor_t *who=w->bob ? &bob : &alice;
    if(w->logout) {
        vireo_mysql_user_repository_t *r=NULL;CHECK(vireo_mysql_user_repository_create(t,pool,&policy,&r,NULL),VIREO_OK);
        assert(!pthread_mutex_lock(&mutex));second_started=true;assert(!pthread_cond_broadcast(&condition));assert(!pthread_mutex_unlock(&mutex));
        vireo_mysql_logout_input_t in={.user_id=who->user_id,.session_id=who->session_id,.request_id={0x7f},.occurred_at_ms=2000};vireo_mysql_logout_report_t out;
        CHECK(vireo_mysql_user_repository_logout(r,&in,0,&out,NULL),VIREO_OK);assert(out.commit==VIREO_MYSQL_LOGOUT_COMMITTED);w->result=VIREO_OK;
        CHECK(vireo_mysql_user_repository_destroy(&r,NULL),VIREO_OK);
    } else {
        vireo_mysql_node_ops_t ops=vireo_mysql_node_native_ops;ops.utc=w->first ? paused_utc : fixed_utc;if(!w->first) { ops.execute=second_execute; }
        vireo_mysql_node_repository_t *r=NULL;CHECK(vireo_mysql_node_repository_create_with_ops(t,pool,&r,NULL,&ops),VIREO_OK);
        if(w->mkdir) {
            vireo_mysql_node_mkdir_input_t in={.parent_id=w->parent,.name=(const unsigned char *)w->name,.name_length=strlen(w->name),.request_id={0x71}};in.request_id[15]=w->event;
            vireo_mysql_node_mkdir_report_t out;errno=EDOM;w->result=vireo_mysql_node_repository_mkdir(r,who,&in,0,&out,NULL);assert(errno==EDOM);w->issue=out.issue;
        } else if(w->move) {
            vireo_mysql_node_move_input_t in={.node_id=w->id,.new_parent_id=w->parent,.name=(const unsigned char *)w->name,.name_length=strlen(w->name),.request_id={0x72}};in.request_id[15]=w->event;
            vireo_mysql_node_move_report_t out;errno=EDOM;w->result=vireo_mysql_node_repository_move(r,who,&in,0,&out,NULL);assert(errno==EDOM);w->issue=out.issue;
        } else {
            vireo_mysql_node_soft_delete_input_t in={.node_id=w->id,.request_id={0x70}};in.request_id[15]=w->event;
            errno=EDOM;w->result=vireo_mysql_node_repository_soft_delete(r,who,&in,0,&w->report,NULL);assert(errno==EDOM);w->issue=w->report.issue;
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
    char name[40];int n=snprintf(name,sizeof(name),"race-%u",scenario);assert(n>0 && (size_t)n<sizeof(name));
    uint64_t parent=mkdir_at(alice,alice_root,name),other=mkdir_at(alice,alice_root,"race-other");
    struct worker first={.first=true,.id=parent,.parent=parent,.name="first-child",.event=(unsigned char)(scenario*2+1)};
    struct worker second={.id=parent,.parent=parent,.name="second-child",.event=(unsigned char)(scenario*2+2)};
    if(scenario==0) { second.mkdir=true; }
    if(scenario==1) { first.mkdir=true; }
    if(scenario==2) { second.move=true;second.id=other; }
    if(scenario==3) { first.move=true;first.id=other; }
    if(scenario==4) { object_fixture(0xe1,2,2);first.id=file_fixture(alice,parent,"shared-a",0xe1,2);second.id=file_fixture(bob,bob_root,"shared-b",0xe1,2);second.bob=true; }
    if(scenario==5) { second.logout=true; }
    phase=0;release_first=false;second_started=false;second_done=false;independent_user=false;assert(lock_waits()==0);
    uint64_t audits=scalar("SELECT COUNT(*) FROM operation_audits");
    pthread_t t1,t2;assert(!pthread_create(&t1,NULL,work,&first));assert(!pthread_mutex_lock(&mutex));
    struct timespec due=deadline();while(phase!=1) { assert(!pthread_cond_timedwait(&condition,&mutex,&due)); }assert(!pthread_mutex_unlock(&mutex));
    assert(!pthread_create(&t2,NULL,work,&second));assert(!pthread_mutex_lock(&mutex));wait_flag(&second_started);assert(!pthread_mutex_unlock(&mutex));
    bool observed=false;due=deadline();
    do { if(lock_waits()>0) { observed=true;break; }struct timespec now;assert(!clock_gettime(CLOCK_MONOTONIC,&now));if(now.tv_sec>=due.tv_sec) { break; }struct timespec pause={0,1000000};assert(!nanosleep(&pause,NULL)); }while(!observed);
    assert(observed);printf("PASS actual InnoDB row-lock wait: soft-delete race %u (%s)\n",scenario,scenario==4 ? "different users, shared object X" : "same user coordination");
    assert(!pthread_mutex_lock(&mutex));assert(!second_done);release_first=true;assert(!pthread_cond_broadcast(&condition));assert(!pthread_mutex_unlock(&mutex));
    assert(!pthread_join(t1,NULL) && !pthread_join(t2,NULL));assert(first.result==VIREO_OK && second_done);
    if(scenario==0 || scenario==2) { assert(second.result==VIREO_RESULT_NOT_FOUND && second.issue==VIREO_MYSQL_NODE_NOT_FOUND && field(parent,"state")==3); }
    if(scenario==1 || scenario==3) { assert(second.result==VIREO_RESULT_DATABASE && second.issue==VIREO_MYSQL_NODE_DIRECTORY_NOT_EMPTY && field(parent,"state")==2); }
    if(scenario==4) { assert(second.result==VIREO_OK && first.report.commit==VIREO_MYSQL_NODE_SOFT_DELETE_COMMITTED && second.report.commit==VIREO_MYSQL_NODE_SOFT_DELETE_COMMITTED && refs(0xe1)==0); }
    if(scenario==5) { assert(second.result==VIREO_OK && field(parent,"state")==3); }
    assert(scalar("SELECT COUNT(*) FROM operation_audits")==audits+(scenario>=4 ? 2u : 1u));
    char sql[640];n=snprintf(sql,sizeof(sql),"SELECT COUNT(*) FROM file_nodes c JOIN file_nodes p ON c.owner_id=p.owner_id AND c.parent_id=p.id WHERE p.id=%llu AND p.state=3 AND c.state IN (1,2)",(unsigned long long)parent);assert(n>0 && (size_t)n<sizeof(sql) && scalar(sql)==0);++cases;refill_pool();
    /* Reuse the same directory name only after this scenario completes. */
    n=snprintf(sql,sizeof(sql),"UPDATE file_nodes SET name=CONCAT('retained-',id) WHERE id=%llu",(unsigned long long)other);assert(n>0 && (size_t)n<sizeof(sql));mutate(sql);
    if(scenario==5) { vireo_mysql_node_soft_delete_input_t in=delete_input(other);(void)delete_node(alice,&in,VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_NODE_AUTH_REJECTED); }
}
static size_t fd_count(void)
{ DIR *d=opendir("/proc/self/fd");assert(d);size_t n=0;while(readdir(d)) { ++n; }assert(!closedir(d));return n; }
static uint64_t insert_dir(uint64_t parent,const char *name)
{
    char sql[512];int n=snprintf(sql,sizeof(sql),"INSERT INTO file_nodes(owner_id,parent_id,name,node_type,state,object_hash,size,created_at_ms,updated_at_ms,deleted_at_ms) VALUES(%llu,%llu,'%s',1,2,NULL,0,1000,1000,NULL)",(unsigned long long)alice.user_id,(unsigned long long)parent,name);assert(n>0 && (size_t)n<sizeof(sql));mutate(sql);return scalar("SELECT LAST_INSERT_ID()");
}
static void boundary_cases(void)
{
    uint64_t end=alice_root;
    for(size_t depth=2;depth<=257;++depth) {
        end=insert_dir(end,"deep");
        if(depth==255 || depth==256 || depth==257) {
            uint64_t id=insert_dir(end,"candidate");vireo_mysql_node_soft_delete_input_t in=delete_input(id);
            (void)delete_node(alice,&in,depth<=256 ? VIREO_OK : VIREO_RESULT_RANGE,depth<=256 ? VIREO_MYSQL_NODE_ISSUE_NONE : VIREO_MYSQL_NODE_ANCESTRY_LIMIT);
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
    CHECK(vireo_mysql_migration_apply(thread,&options,catalog,count,&migration,NULL),VIREO_OK);assert(migration.ready && migration.steps_completed==14);
    CHECK(vireo_mysql_connection_open(thread,&options,&observer,NULL),VIREO_OK);
    vireo_mysql_pool_options_t config={options,4,4,VIREO_MYSQL_POOL_MEMORY_MAX};CHECK(vireo_mysql_pool_create(thread,&config,&pool,NULL),VIREO_OK);
    CHECK(vireo_mysql_user_repository_create(thread,pool,&policy,&users,NULL),VIREO_OK);
    const char pass[]="real-password";CHECK(vireo_password_hash_create(&policy,pass,sizeof(pass)-1,phc,sizeof(phc),&phc_length),VIREO_OK);
    alice=account("alice",&alice_root);bob=account("bob",&bob_root);recreate(false);
    uint64_t dir=mkdir_at(alice,alice_root,"资料");vireo_mysql_node_soft_delete_input_t in=delete_input(dir);
    vireo_mysql_node_soft_delete_input_t first_event=in;vireo_mysql_node_soft_delete_report_t saved=delete_node(alice,&in,VIREO_OK,VIREO_MYSQL_NODE_ISSUE_NONE);
    (void)delete_node(alice,&in,VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_NODE_NOT_FOUND);
    uint64_t replacement=mkdir_at(alice,alice_root,"资料");assert(replacement!=dir);
    in=delete_input(alice_root);(void)delete_node(alice,&in,VIREO_RESULT_DATABASE,VIREO_MYSQL_NODE_ROOT_UNDELETABLE);
    in=delete_input(bob_root);(void)delete_node(alice,&in,VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_NODE_NOT_FOUND);
    in=delete_input(UINT64_MAX);(void)delete_node(alice,&in,VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_NODE_NOT_FOUND);
    uint64_t child=mkdir_at(alice,replacement,"child");in=delete_input(replacement);(void)delete_node(alice,&in,VIREO_RESULT_DATABASE,VIREO_MYSQL_NODE_DIRECTORY_NOT_EMPTY);
    in=delete_input(child);(void)delete_node(alice,&in,VIREO_OK,VIREO_MYSQL_NODE_ISSUE_NONE);
    uint64_t uploading=file_fixture(alice,replacement,"upload",0,1);in=delete_input(replacement);(void)delete_node(alice,&in,VIREO_RESULT_DATABASE,VIREO_MYSQL_NODE_DIRECTORY_NOT_EMPTY);
    in=delete_input(uploading);(void)delete_node(alice,&in,VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_NODE_NOT_FOUND);
    char sql[1024];int n=snprintf(sql,sizeof(sql),"UPDATE file_nodes SET state=3,deleted_at_ms=1500 WHERE id=%llu",(unsigned long long)uploading);assert(n>0 && (size_t)n<sizeof(sql));mutate(sql);
    in=delete_input(replacement);(void)delete_node(alice,&in,VIREO_OK,VIREO_MYSQL_NODE_ISSUE_NONE);assert(field(child,"parent_id")==replacement);
    object_fixture(0xa9,2,2);uint64_t a=file_fixture(alice,alice_root,"a",0xa9,2),b=file_fixture(bob,bob_root,"b",0xa9,2);
    uint64_t original_parent=field(a,"parent_id"),original_name=field(a,"CRC32(name)");
    in=delete_input(a);(void)delete_node(alice,&in,VIREO_OK,VIREO_MYSQL_NODE_ISSUE_NONE);assert(refs(0xa9)==1);
    vireo_mysql_node_value_t value;vireo_mysql_node_report_t r;CHECK(vireo_mysql_node_repository_stat(nodes,&bob,b,0,&value,&r,NULL),VIREO_OK);assert(value.has_object_hash && value.size==91);
    assert(field(a,"parent_id")==original_parent && field(a,"CRC32(name)")==original_name && field(a,"size")==91 && field(a,"OCTET_LENGTH(object_hash)")==32 && field(a,"created_at_ms")==1000);
    in=delete_input(a);(void)delete_node(alice,&in,VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_NODE_NOT_FOUND);assert(refs(0xa9)==1);
    in=delete_input(b);(void)delete_node(bob,&in,VIREO_OK,VIREO_MYSQL_NODE_ISSUE_NONE);assert(refs(0xa9)==0 && scalar("SELECT COUNT(*) FROM objects")==1 && scalar("SELECT COUNT(*) FROM gc_jobs")==0);
    vireo_mysql_node_list_query_t visible_query={alice_root,0,64};vireo_mysql_node_page_t visible_page;
    CHECK(vireo_mysql_node_repository_list_children(nodes,&alice,&visible_query,0,&visible_page,&r,NULL),VIREO_OK);
    for(size_t i=0;i<visible_page.count;++i) { assert(visible_page.nodes[i].id!=dir && visible_page.nodes[i].id!=replacement && visible_page.nodes[i].id!=a); }++cases;
    for(unsigned state=1;state<=4;++state) {
        object_fixture(0xb0u+state,state,state==3 ? 0u : 1u);char name[32];n=snprintf(name,sizeof(name),"state-%u",state);assert(n>0 && (size_t)n<sizeof(name));uint64_t id=file_fixture(alice,alice_root,name,0xb0u+state,2);in=delete_input(id);
        (void)delete_node(alice,&in,state==3 ? VIREO_RESULT_DATABASE : VIREO_OK,state==3 ? VIREO_MYSQL_NODE_OBJECT_REFERENCE_INVALID : VIREO_MYSQL_NODE_ISSUE_NONE);
    }
    object_fixture(0xc1,2,0);a=file_fixture(alice,alice_root,"zero-ref",0xc1,2);in=delete_input(a);(void)delete_node(alice,&in,VIREO_RESULT_DATABASE,VIREO_MYSQL_NODE_OBJECT_REFERENCE_INVALID);
    object_fixture(0xc2,2,1);a=file_fixture(alice,alice_root,"bad-size",0xc2,2);n=snprintf(sql,sizeof(sql),"UPDATE file_nodes SET size=92 WHERE id=%llu",(unsigned long long)a);assert(n>0 && (size_t)n<sizeof(sql));mutate(sql);in=delete_input(a);(void)delete_node(alice,&in,VIREO_RESULT_DATABASE,VIREO_MYSQL_NODE_OBJECT_REFERENCE_INVALID);
    /* Reusing an earlier successful execution event must roll back the new file AND its decrement. */
    object_fixture(0xc3,2,1);a=file_fixture(alice,alice_root,"duplicate-audit",0xc3,2);in=delete_input(a);uint64_t before_audits=scalar("SELECT COUNT(*) FROM operation_audits");
    memcpy(in.request_id,first_event.request_id,16);
    uint64_t signature=node_signature(a);vireo_mysql_node_soft_delete_report_t duplicate;vireo_mysql_node_error_t e;
    CHECK(vireo_mysql_node_repository_soft_delete(nodes,&alice,&in,0,&duplicate,&e),VIREO_RESULT_DATABASE);assert(e.database.mysql_code==1062 && duplicate.rollback_confirmed && refs(0xc3)==1 && node_signature(a)==signature && scalar("SELECT COUNT(*) FROM operation_audits")==before_audits);refill_pool();++cases;
    uint64_t bad=mkdir_at(alice,alice_root,"bad-parent"),candidate=mkdir_at(alice,bad,"candidate");set_parent(bad,bad);in=delete_input(candidate);(void)delete_node(alice,&in,VIREO_RESULT_DATABASE,VIREO_MYSQL_NODE_TREE_INVALID);set_parent(bad,alice_root);
    n=snprintf(sql,sizeof(sql),"UPDATE file_nodes SET state=3,deleted_at_ms=updated_at_ms WHERE id=%llu",(unsigned long long)bad);assert(n>0 && (size_t)n<sizeof(sql));mutate(sql);in=delete_input(candidate);(void)delete_node(alice,&in,VIREO_RESULT_DATABASE,VIREO_MYSQL_NODE_TREE_INVALID);
    boundary_cases();
    for(unsigned i=0;i<4;++i) {
        char name[24];n=snprintf(name,sizeof(name),"clock-%u",i);assert(n>0 && (size_t)n<sizeof(name));sample_ms=2000;uint64_t id=mkdir_at(alice,alice_root,name);const uint64_t times[]={999,1000,2999,3000};sample_ms=times[i];in=delete_input(id);bool valid=sample_ms>=1000 && sample_ms<3000;(void)delete_node(alice,&in,valid ? VIREO_OK : VIREO_RESULT_NOT_FOUND,valid ? VIREO_MYSQL_NODE_ISSUE_NONE : VIREO_MYSQL_NODE_AUTH_REJECTED);
    }
    in=delete_input(alice_root);(void)delete_node(alice,&in,VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_NODE_AUTH_REJECTED);sample_ms=2000;
    object_fixture(0xc4,2,1);a=file_fixture(alice,alice_root,"rollback-clock",0xc4,2);n=snprintf(sql,sizeof(sql),"UPDATE file_nodes SET updated_at_ms=2500 WHERE id=%llu",(unsigned long long)a);assert(n>0 && (size_t)n<sizeof(sql));mutate(sql);mutate("UPDATE objects SET updated_at_ms=2600 WHERE object_hash=UNHEX(REPEAT('c4',32))");in=delete_input(a);(void)delete_node(alice,&in,VIREO_OK,VIREO_MYSQL_NODE_ISSUE_NONE);assert(field(a,"deleted_at_ms")==2500 && scalar("SELECT updated_at_ms FROM objects WHERE object_hash=UNHEX(REPEAT('c4',32))")==2600);
    vireo_mysql_node_actor_t forged={bob.user_id,alice.session_id};in=delete_input(candidate);(void)delete_node(forged,&in,VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_NODE_AUTH_REJECTED);
    fault_cases();for(unsigned i=0;i<6;++i) { concurrent(i); }
    vireo_mysql_node_list_query_t query={alice_root,0,64};vireo_mysql_node_page_t page;CHECK(vireo_mysql_node_repository_list_children(nodes,&bob,&query,0,&page,&r,NULL),VIREO_RESULT_NOT_FOUND);
    n=snprintf(sql,sizeof(sql),"UPDATE sessions SET expires_at_ms=18446744073709551615 WHERE id=%llu",(unsigned long long)bob.session_id);assert(n>0 && (size_t)n<sizeof(sql));mutate(sql);
    uint64_t native_id=mkdir_at(bob,bob_root,"native");CHECK(vireo_mysql_node_repository_destroy(&nodes,NULL),VIREO_OK);CHECK(vireo_mysql_node_repository_create(thread,pool,&nodes,NULL),VIREO_OK);
    in=delete_input(native_id);vireo_mysql_node_soft_delete_report_t native;CHECK(vireo_mysql_node_repository_soft_delete(nodes,&bob,&in,0,&native,NULL),VIREO_OK);assert(native.commit==VIREO_MYSQL_NODE_SOFT_DELETE_COMMITTED && native.deleted_at_ms>3000);++cases;
    CHECK(vireo_mysql_node_repository_destroy(&nodes,NULL),VIREO_OK);assert(saved.node_id==dir && saved.audit_id && saved.deleted_at_ms==2000);
    CHECK(vireo_mysql_user_repository_destroy(&users,NULL),VIREO_OK);bool closed=false;CHECK(vireo_mysql_pool_close(pool,&closed,NULL),VIREO_OK);assert(closed);
    CHECK(vireo_mysql_pool_destroy(thread,&pool,NULL),VIREO_OK);CHECK(vireo_mysql_connection_destroy(thread,&observer),VIREO_OK);
    CHECK(vireo_mysql_thread_detach(&thread),VIREO_OK);CHECK(vireo_mysql_runtime_destroy(&runtime),VIREO_OK);
    assert(!pthread_cond_destroy(&condition) && !pthread_mutex_destroy(&mutex));memset(password,0,sizeof(password));assert(fd_count()==fd);
    printf("PASS %zu real soft-delete observations: node/object/audit atomicity, shared references 2-1-0, empty/uploading/deleted children, tree256/257, commit seams, native UTC, six actual InnoDB waits, FD %zu -> %zu\n",cases,fd,fd_count());return 0;
}
