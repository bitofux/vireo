/* PROJECT : VIREO; FILE : test_mysql_node_mkdir_once.c; AUTHOR : bitofux;
 * DATE : 2026-10-21; BRIEF : 目录事务、提交/清理独立事实与逐资源失败。 */
#define _POSIX_C_SOURCE 200809L
#include "mysql_node_repository_internal.h"
#include <vireo/persistence/mysql_node_mkdir_receipt.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(call,want) do { errno=EDOM; vireo_result_t got_=(call); if(got_!=(want)) { fprintf(stderr,"line %d got %d want %d\n",__LINE__,(int)got_,(int)(want)); abort(); } assert(errno==EDOM); } while(0)
enum op { BEGIN, USER, SESSION, PARENT, NAME, INSERT, AUDIT, COMMIT, ROLLBACK, RECEIPT, RECEIPT_INSERT, OPS };
struct statement { enum op op; size_t fetched; };
static struct {
    size_t calls,fail_at,allocations,statements,leases,prepared[OPS],utc_calls;
    size_t pending_nodes,pending_audits,pending_receipts,nodes,audits,receipts;
    uint64_t first_ms,second_ms;
    unsigned occupied,shape,utc_mode;
    int bad_result,duplicate,execute_error,close_error,keep_close;
    bool receipt; unsigned receipt_shape; bool missing_user,disabled,missing_session,revoked,wrong_session,no_parent,file_parent;
    bool before_native,apply_failed_commit,keep_release,consume_release_error,partial_acquire;
    vireo_mysql_pool_disposition_t disposition;
} m;
static _Alignas(max_align_t) unsigned char thread_storage,pool_storage,connection_storage;
static vireo_mysql_thread_t *thread;
static vireo_mysql_pool_t *pool;
static vireo_mysql_node_repository_t *repo;
static const vireo_mysql_node_actor_t actor={7,51};
static const unsigned char name[]="abc";
static vireo_mysql_node_mkdir_once_input_t input;
static vireo_mysql_node_mkdir_once_report_t report;
static vireo_mysql_node_error_t error;
static size_t scenarios;
static bool fail(void) { return ++m.calls==m.fail_at; }
static void zeroed(const void *p,size_t n)
{ const unsigned char *b=p;for(size_t i=0;i<n;++i) { assert(b[i]==0); } }
static void *allocate(size_t n)
{ if(fail()) { return NULL; }void *p=malloc(n);assert(p);++m.allocations;return p; }
static void free_memory(void *p) { assert(m.allocations);--m.allocations;free(p); }
static vireo_result_t acquire(vireo_mysql_thread_t *t,vireo_mysql_pool_t *p,uint32_t wait,
    vireo_mysql_lease_t *lease,vireo_mysql_pool_acquisition_t *out,vireo_mysql_pool_error_t *e)
{
    assert(t==thread && p==pool && wait<=60000 && !lease->owner);*out=(vireo_mysql_pool_acquisition_t){0};*e=(vireo_mysql_pool_error_t){0};
    bool failed=fail();if(failed && !m.partial_acquire) { return VIREO_RESULT_BUSY; }
    *lease=(vireo_mysql_lease_t){.owner=pool,.generation=1};out->acquired=true;++m.leases;
    return failed ? VIREO_RESULT_INTERNAL : VIREO_OK;
}
static vireo_result_t borrow(vireo_mysql_thread_t *t,vireo_mysql_pool_t *p,const vireo_mysql_lease_t *lease,vireo_mysql_connection_t **out)
{
    assert(t==thread && p==pool && lease->owner==pool);if(fail()) { return VIREO_RESULT_INTERNAL; }
    *out=(void *)&connection_storage;return VIREO_OK;
}
static vireo_result_t release(vireo_mysql_thread_t *t,vireo_mysql_pool_t *p,vireo_mysql_lease_t *lease,
    vireo_mysql_pool_disposition_t disposition,vireo_mysql_pool_release_t *out,vireo_mysql_pool_error_t *e)
{
    assert(t==thread && p==pool && lease->owner==pool && !m.statements && m.leases==1);
    *out=(vireo_mysql_pool_release_t){0};*e=(vireo_mysql_pool_error_t){0};m.disposition=disposition;
    if(fail() || m.keep_release) { return VIREO_RESULT_INTERNAL; }
    if(disposition==VIREO_MYSQL_POOL_DISCARD) { m.pending_nodes=0;m.pending_audits=0;m.pending_receipts=0; }
    *lease=(vireo_mysql_lease_t){0};out->released=true;--m.leases;
    return m.consume_release_error ? VIREO_RESULT_DATABASE : VIREO_OK;
}
static enum op identify(const char *sql)
{
    if(!strcmp(sql,"SET autocommit=0")) { return BEGIN; }
    if(!strcmp(sql,"COMMIT")) { assert(m.utc_calls==2 && m.prepared[AUDIT]==1 && m.prepared[RECEIPT_INSERT]==1);return COMMIT; }
    if(!strcmp(sql,"ROLLBACK")) { return ROLLBACK; }
    if(strstr(sql,"FROM directory_write_receipts")) { assert(strstr(sql,"user_id=? AND command=1027 AND idempotency_key=? FOR UPDATE") && m.prepared[SESSION] && !m.prepared[PARENT]);return RECEIPT; }
    if(strstr(sql,"INSERT INTO directory_write_receipts")) { assert(m.prepared[AUDIT] && strstr(sql,"VALUES(?,1027,?,1,?,?,?,?,?)"));return RECEIPT_INSERT; }
    if(strstr(sql,"FROM users")) { assert(strstr(sql,"FOR UPDATE") && !m.prepared[SESSION]);return USER; }
    if(strstr(sql,"FROM sessions")) { assert(strstr(sql,"FOR SHARE") && m.prepared[USER] && !m.prepared[PARENT]);return SESSION; }
    if(strstr(sql,"SELECT id,owner_id,parent_id,name,state")) {
        assert(strstr(sql,"live_name=? FOR UPDATE") && strstr(sql,"owner_id=? AND parent_id=?") && m.prepared[PARENT]);return NAME;
    }
    if(strstr(sql,"SELECT id,owner_id,parent_id,name,node_type")) {
        assert(strstr(sql,"owner_id=? AND id=? AND state=2 FOR UPDATE") && m.prepared[SESSION]);return PARENT;
    }
    if(strstr(sql,"INSERT INTO file_nodes")) {
        assert(strstr(sql,"VALUES(?,?,?,1,2,NULL,0,?,?,NULL)") && m.utc_calls==1 && m.prepared[NAME]);return INSERT;
    }
    assert(strstr(sql,"INSERT INTO operation_audits") && strstr(sql,"VALUES(?,?,?,5,3,?,NULL,0,0,'',?)") && m.prepared[INSERT]);return AUDIT;
}
static vireo_result_t prepare(vireo_mysql_thread_t *t,vireo_mysql_connection_t *c,const char *sql,size_t n,
    const vireo_mysql_statement_limits_t *limits,vireo_mysql_statement_t **out,vireo_mysql_error_t *e)
{
    assert(t==thread && c==(void *)&connection_storage && strlen(sql)==n && !*out && !m.statements);
    enum op op=identify(sql);++m.prepared[op];bool read=op==SESSION;bool receipt=op==RECEIPT || op==RECEIPT_INSERT;
    assert(limits->max_parameters==(receipt ? 7u : read ? 4u : 5u) && limits->max_parameter_bytes==(receipt ? 271u : read ? 0u : 255u) && limits->max_columns==11 && limits->max_cell_bytes==255 && limits->max_memory_bytes==32768);
    *e=(vireo_mysql_error_t){0};if(fail()) { e->mysql_code=2013;return VIREO_RESULT_DATABASE; }
    struct statement *s=calloc(1,sizeof(*s));assert(s);s->op=op;*out=(void *)s;++m.statements;return VIREO_OK;
}
static void u64(const vireo_mysql_parameter_t *p,uint64_t expected)
{ assert(p->kind==VIREO_MYSQL_PARAMETER_U64 && p->value.u64==expected); }
static void span(const vireo_mysql_parameter_t *p,const void *bytes,size_t n)
{ assert(p->kind==VIREO_MYSQL_PARAMETER_BYTES && p->value.span.length==n && !memcmp(p->value.span.data,bytes,n)); }
static void apply_commit(void)
{ assert(m.pending_nodes==1 && m.pending_audits==1 && m.pending_receipts==1);m.nodes+=m.pending_nodes;m.audits+=m.pending_audits;m.receipts+=m.pending_receipts;m.pending_nodes=0;m.pending_audits=0;m.pending_receipts=0; }
static vireo_result_t execute(vireo_mysql_thread_t *t,vireo_mysql_statement_t *statement,
    const vireo_mysql_parameter_t *p,size_t n,vireo_mysql_execution_t *out,vireo_mysql_error_t *e)
{
    struct statement *s=(void *)statement;assert(t==thread);*e=(vireo_mysql_error_t){0};*out=(vireo_mysql_execution_t){0};
    if(s->op==BEGIN || s->op==COMMIT || s->op==ROLLBACK) { assert(!p && !n); }
    else if(s->op==USER || s->op==SESSION) { assert(n==1);u64(p,s->op==USER ? 7u : 51u); }
    else if(s->op==RECEIPT) { assert(n==2);u64(p,7);span(p+1,input.idempotency_key,16); }
    else if(s->op==RECEIPT_INSERT) { assert(n==7);u64(p,7);span(p+1,input.idempotency_key,16);u64(p+2,22);span(p+3,input.name,input.name_length);u64(p+4,31);u64(p+5,501);u64(p+6,m.first_ms); }
    else if(s->op==PARENT) { assert(n==2);u64(p,7);u64(p+1,22); }
    else if(s->op==NAME) { assert(n==3);u64(p,7);u64(p+1,22);span(p+2,input.name,input.name_length); }
    else if(s->op==INSERT) { assert(n==5);u64(p,7);u64(p+1,22);span(p+2,input.name,input.name_length);u64(p+3,m.first_ms);u64(p+4,m.first_ms); }
    else { assert(n==5);span(p,input.request_id,16);u64(p+1,7);u64(p+2,51);u64(p+3,31);u64(p+4,m.first_ms); }
    bool failed=fail() || m.execute_error==(int)s->op;
    out->execution_started=!(failed && m.before_native);
    if(failed) {
        if(s->op==COMMIT && m.apply_failed_commit) { apply_commit(); }
        e->mysql_code=(m.execute_error==(int)s->op && (s->op==INSERT || s->op==AUDIT || s->op==RECEIPT_INSERT)) ? 1062u : 2013u;return VIREO_RESULT_DATABASE;
    }
    out->has_result=s->op==USER || s->op==SESSION || s->op==PARENT || s->op==NAME || s->op==RECEIPT;
    if(s->op==INSERT || s->op==AUDIT || s->op==RECEIPT_INSERT) {
        out->affected_rows=1;out->insert_id=s->op==INSERT ? 31u : 501u;
        if(s->op==INSERT) { ++m.pending_nodes; }else if(s->op==AUDIT) { ++m.pending_audits; }else { ++m.pending_receipts;out->insert_id=0; if(m.shape==40) { out->affected_rows=0; }if(m.shape==41) { out->affected_rows=2; }if(m.shape==42) { out->insert_id=UINT64_MAX; } }
        unsigned shape=m.shape;
        if(s->op==AUDIT && shape>=30 && shape<=32) { shape-=10; }
        if((s->op==INSERT && m.shape>=20 && m.shape<=22) || (s->op==AUDIT && m.shape>=30 && m.shape<=32)) {
            if(shape==20) { out->affected_rows=0; }if(shape==21) { out->affected_rows=2; }if(shape==22) { out->insert_id=0; }
        }
    }
    if(s->op==COMMIT) { apply_commit(); }
    if(s->op==ROLLBACK) { m.pending_nodes=0;m.pending_audits=0;m.pending_receipts=0; }
    if(m.bad_result==(int)s->op) { out->has_result=!out->has_result; }
    return VIREO_OK;
}
static vireo_result_t fetch(vireo_mysql_thread_t *t,vireo_mysql_statement_t *statement,vireo_mysql_fetch_outcome_t *out,vireo_mysql_error_t *e)
{
    struct statement *s=(void *)statement;assert(t==thread);*e=(vireo_mysql_error_t){0};if(fail()) { e->mysql_code=2013;return VIREO_RESULT_DATABASE; }
    bool missing=(s->op==RECEIPT && !m.receipt)||(s->op==USER && m.missing_user)||(s->op==SESSION && m.missing_session)||(s->op==PARENT && m.no_parent)||(s->op==NAME && !m.occupied);
    size_t rows=missing ? 0 : (m.duplicate==(int)s->op ? 2u : 1u);
    *out=s->fetched++<rows ? VIREO_MYSQL_FETCH_ROW : VIREO_MYSQL_FETCH_DONE;return VIREO_OK;
}
static vireo_result_t column(vireo_mysql_thread_t *t,const vireo_mysql_statement_t *statement,size_t i,vireo_mysql_cell_view_t *out)
{
    const struct statement *s=(const void *)statement;assert(t==thread);if(fail()) { return VIREO_RESULT_DATABASE; }
    static const char *const user[]={"7","1"},*const session[]={"51","7","1","1000","3000",NULL,"1000"};
    static const char *const parent[]={"22","7",NULL,"","1","2",NULL,"0","1000","1000",NULL};
    static const char *const named[]={"91","7","22","abc","2"};
    const char *v=s->op==USER ? user[i] : s->op==SESSION ? session[i] : s->op==PARENT ? parent[i] : s->op==RECEIPT ? NULL : named[i];
    if(s->op==USER && i==1 && m.disabled) { v="2"; }
    if(s->op==SESSION) {
        if(i==1 && m.wrong_session) { v="8"; }if(i==2 && m.revoked) { v="2"; }if(i==5 && m.revoked) { v="1000"; }
    }
    if(s->op==PARENT && m.file_parent) {
        if(i==2) { v="1"; }if(i==3) { v="file"; }if(i==4) { v="2"; }if(i==6) { v=""; }
    }
    if(s->op==NAME) {
        if(i==4 && m.occupied==1) { v="1"; }
        if(i==0 && m.shape==1) { v="0"; }if(i==1 && m.shape==2) { v="8"; }if(i==2 && m.shape==3) { v="23"; }
        if(i==3 && m.shape==4) { v="abd"; }if(i==3 && m.shape==5) { v=NULL; }if(i==4 && m.shape==6) { v="3"; }
        if(i==0 && m.shape==7) { v="18446744073709551616"; }if(i==0 && m.shape==8) { v="-1"; }
        if(m.shape==9) { return VIREO_RESULT_RANGE; }
    }
    if(s->op==RECEIPT) {
        static const char *const receipt[]={"7","1027",NULL,"1","22","abc","31","501","0"};
        v=receipt[i];
        if(m.receipt_shape==i+1) { v="0"; }
        if(m.receipt_shape==10 && i==4) { v="23"; }
        if(m.receipt_shape==11 && i==5) { v="abd"; }
        if(m.receipt_shape==12 && i==5) { v=".."; }
        if(m.receipt_shape==13 && i==8) { v="18446744073709551616"; }
        if(m.receipt_shape==14 && i==8) { v=NULL; }
        if(m.receipt_shape==15 && i==8) { v="18446744073709551615"; }
        if(m.receipt_shape==16 && i==5) { v=NULL; }
        if(m.receipt_shape==17 && i==5) { v=""; }
        if(m.receipt_shape==18 && i==5) { v="a/b"; }
        if(m.receipt_shape==19 && i==1) { v="1028"; }
        if(m.receipt_shape==20 && i==6) { v="-1"; }
        if(m.receipt_shape==21 && i==6) { v="18446744073709551616"; }
        if(m.receipt_shape==22) { return VIREO_RESULT_RANGE; }
    }
    *out=(vireo_mysql_cell_view_t){.data=(const unsigned char *)v,.length=v ? strlen(v) : 0,.is_null=v==NULL};
    if(s->op==RECEIPT && i==2 && m.receipt_shape!=3) { out->data=input.idempotency_key;out->length=16;out->is_null=false; }
    if(s->op==PARENT && m.file_parent && i==6) { static const unsigned char hash[32]={0};out->data=hash;out->length=32; }
    if(s->op==NAME && i==3 && m.shape==10) { out->length=256; }
    return VIREO_OK;
}
static vireo_result_t close_statement(vireo_mysql_thread_t *t,vireo_mysql_statement_t **out,vireo_mysql_error_t *e)
{
    assert(t==thread && *out && m.statements==1);*e=(vireo_mysql_error_t){0};struct statement *s=(void *)*out;
    bool failed=fail() || m.close_error==(int)s->op;
    if(m.keep_close==(int)s->op) { return VIREO_RESULT_BUSY; }
    free(s);*out=NULL;--m.statements;return failed ? VIREO_RESULT_DATABASE : VIREO_OK;
}
static int utc(struct timespec *out)
{
    assert((m.prepared[PARENT] || m.receipt) && !m.statements);++m.utc_calls;
    if(fail() || m.utc_mode==m.utc_calls) { errno=EIO;return -1; }
    uint64_t ms=m.utc_calls==1 ? m.first_ms : m.second_ms;
    *out=(struct timespec){.tv_sec=(time_t)(ms/1000),.tv_nsec=(long)(ms%1000)*1000000L};
    if(m.utc_mode==3) { out->tv_nsec=1000000000L; }if(m.utc_mode==4) { out->tv_sec=-1; }
    if(m.utc_mode==5) { out->tv_sec=(time_t)INT64_MAX; }if(m.utc_mode==6) { return 7; }return 0;
}
static const vireo_mysql_node_ops_t ops={allocate,free_memory,acquire,borrow,release,prepare,execute,fetch,column,close_statement,utc};
static void start(void)
{
    assert(!repo && !m.allocations && !m.statements && !m.leases);memset(&m,0,sizeof(m));
    m.first_ms=2000;m.second_ms=2001;m.bad_result=-1;m.duplicate=-1;m.execute_error=-1;m.close_error=-1;m.keep_close=-1;
    input=(vireo_mysql_node_mkdir_once_input_t){.parent_id=22,.name=name,.name_length=3,.idempotency_key={2},.request_id={1}};
    CHECK(vireo_mysql_node_repository_create_with_ops(thread,pool,&repo,&error,&ops),VIREO_OK);m.calls=0;++scenarios;
}
static vireo_result_t run(void)
{
    memset(&report,0xa5,sizeof(report));errno=EDOM;
    vireo_result_t rc=vireo_mysql_node_repository_mkdir_once(repo,&actor,&input,0,&report,&error);assert(errno==EDOM);
    assert(report.cleanup_pending==(m.statements!=0 || m.leases!=0));
    if(report.effect==VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE) { assert(!report.node_id && !report.audit_id);zeroed(report.idempotency_key,16); }
    else {
        assert(report.node_id==31 && report.audit_id==501 && !memcmp(report.idempotency_key,input.idempotency_key,16));
        if(report.effect==VIREO_MYSQL_NODE_MKDIR_EFFECT_CREATED) { assert(report.commit==VIREO_MYSQL_NODE_MKDIR_COMMITTED && m.nodes==1 && m.audits==1 && m.receipts==1 && !report.rollback_confirmed); }
        else { assert(report.commit==VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED && !m.prepared[PARENT] && !m.prepared[INSERT] && !m.prepared[AUDIT] && !m.prepared[COMMIT]); }
    }
    if(rc==VIREO_OK) { assert(report.effect!=VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE && !report.cleanup_pending && !error.stage); }
    return rc;
}
static void stop(void)
{
    assert(m.allocations==1);m.fail_at=0;m.keep_release=false;m.consume_release_error=false;m.keep_close=-1;m.close_error=-1;m.execute_error=-1;
    CHECK(vireo_mysql_node_repository_destroy(&repo,NULL),VIREO_OK);assert(!repo && !m.allocations && !m.leases && !m.statements);
}
static void *wrong_thread(void *unused)
{
    (void)unused;vireo_mysql_node_mkdir_once_report_t out;CHECK(vireo_mysql_node_repository_mkdir_once(repo,&actor,&input,0,&out,NULL),VIREO_RESULT_INVALID_ARGUMENT);return NULL;
}
int main(void)
{
    thread=(void *)&thread_storage;pool=(void *)&pool_storage;
    start();m.receipt=true;assert(run()==VIREO_OK && report.effect==VIREO_MYSQL_NODE_MKDIR_EFFECT_RECOVERED && report.rollback_confirmed && m.utc_calls==1);size_t recovery_calls=m.calls;stop();
    for(size_t at=1;at<=recovery_calls;++at) { start();m.receipt=true;m.fail_at=at;assert(run()!=VIREO_OK);stop(); }
    for(unsigned shape=1;shape<=22;++shape) {
        start();m.receipt=true;m.receipt_shape=shape;
        vireo_result_t want=(shape==6 || shape==10 || shape==11) ? VIREO_RESULT_DATABASE : (shape==9 || shape==15) ? VIREO_OK : VIREO_RESULT_DATABASE;
        assert(run()==want);
        if(want!=VIREO_OK) { assert(report.issue==((shape==6 || shape==10 || shape==11) ? VIREO_MYSQL_NODE_IDEMPOTENCY_CONFLICT : VIREO_MYSQL_NODE_RECEIPT_INVALID)); }
        stop();
    }
    start();m.receipt=true;m.duplicate=RECEIPT;assert(run()==VIREO_RESULT_DATABASE && report.issue==VIREO_MYSQL_NODE_RECEIPT_INVALID);stop();
    for(unsigned which=0;which<6;++which) {
        start();m.receipt=true;
        if(which==0) { m.execute_error=ROLLBACK; }if(which==1) { m.close_error=ROLLBACK; }if(which==2) { m.keep_close=ROLLBACK; }
        if(which==3) { m.keep_release=true; }if(which==4) { m.consume_release_error=true; }if(which==5) { m.bad_result=ROLLBACK; }
        assert(run()!=VIREO_OK && report.effect==VIREO_MYSQL_NODE_MKDIR_EFFECT_RECOVERED);stop();
    }
    start();m.receipt=true;m.receipt_shape=11;m.first_ms=3000;assert(run()==VIREO_RESULT_NOT_FOUND && report.issue==VIREO_MYSQL_NODE_AUTH_REJECTED);stop();
    start();m.receipt=true;m.close_error=RECEIPT;assert(run()!=VIREO_OK && report.effect==VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE);stop();
    for(unsigned shape=40;shape<=42;++shape) { start();m.shape=shape;assert(run()==(shape==42 ? VIREO_OK : VIREO_RESULT_DATABASE));stop(); }
    start();m.execute_error=RECEIPT_INSERT;assert(run()==VIREO_RESULT_DATABASE && error.database.mysql_code==1062 && report.issue==VIREO_MYSQL_NODE_ISSUE_NONE && !m.nodes && !m.audits && !m.receipts);stop();
    start();memset(input.idempotency_key,0,16);assert(run()==VIREO_RESULT_INVALID_ARGUMENT && !m.calls);stop();
    start();assert(run()==VIREO_OK);size_t normal_calls=m.calls;assert(m.utc_calls==2 && m.disposition==VIREO_MYSQL_POOL_RECYCLE);stop();
    for(size_t at=1;at<=normal_calls;++at) { start();m.fail_at=at;assert(run()!=VIREO_OK);assert(error.stage!=VIREO_MYSQL_NODE_STAGE_NONE);stop(); }
    start();m.occupied=2;assert(run()==VIREO_RESULT_DATABASE);size_t conflict_calls=m.calls;stop();
    for(size_t at=1;at<=conflict_calls;++at) { start();m.occupied=2;m.fail_at=at;assert(run()!=VIREO_OK && m.calls>=at && report.commit==VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED);stop(); }
    for(unsigned state=1;state<=2;++state) { start();m.occupied=state;assert(run()==VIREO_RESULT_DATABASE && report.issue==VIREO_MYSQL_NODE_NAME_CONFLICT && report.rollback_confirmed && !m.prepared[INSERT] && !m.prepared[AUDIT]);stop(); }
    for(unsigned shape=1;shape<=10;++shape) { start();m.occupied=2;m.shape=shape;assert(run()==VIREO_RESULT_DATABASE && report.issue==VIREO_MYSQL_NODE_UNEXPECTED_RESULT && error.stage==VIREO_MYSQL_NODE_STAGE_NAME_CHECK);stop(); }
    for(int op=USER;op<=NAME;++op) { start();m.occupied=2;m.duplicate=op;assert(run()==VIREO_RESULT_DATABASE && report.issue==VIREO_MYSQL_NODE_UNEXPECTED_RESULT);stop(); }
    for(int op=BEGIN;op<=COMMIT;++op) { start();m.bad_result=op;assert(run()==VIREO_RESULT_DATABASE);if(op==COMMIT) { assert(report.commit==VIREO_MYSQL_NODE_MKDIR_UNKNOWN && !m.prepared[ROLLBACK] && m.disposition==VIREO_MYSQL_POOL_DISCARD); }stop(); }
    for(unsigned shape=20;shape<=22;++shape) { start();m.shape=shape;assert(run()==VIREO_RESULT_DATABASE && error.stage==VIREO_MYSQL_NODE_STAGE_INSERT && report.rollback_confirmed && !m.pending_nodes);stop(); }
    for(unsigned shape=30;shape<=32;++shape) { start();m.shape=shape;assert(run()==VIREO_RESULT_DATABASE && error.stage==VIREO_MYSQL_NODE_STAGE_AUDIT && report.rollback_confirmed && !m.pending_nodes && !m.pending_audits);stop(); }
    for(int op=INSERT;op<=AUDIT;++op) { start();m.execute_error=op;assert(run()==VIREO_RESULT_DATABASE && error.database.mysql_code==1062 && report.issue==VIREO_MYSQL_NODE_ISSUE_NONE && report.rollback_confirmed && !m.nodes && !m.audits);stop(); }
    for(unsigned before=0;before<=1;++before) { for(unsigned applied=0;applied<=1-before;++applied) { start();m.execute_error=COMMIT;m.before_native=before!=0;m.apply_failed_commit=applied!=0;assert(run()==VIREO_RESULT_DATABASE);assert(report.commit==(before ? VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED : VIREO_MYSQL_NODE_MKDIR_UNKNOWN));assert(m.prepared[ROLLBACK]==before);if(!before) { assert(m.disposition==VIREO_MYSQL_POOL_DISCARD); }stop(); } }
    for(int op=BEGIN;op<=COMMIT;++op) { start();m.close_error=op;assert(run()==VIREO_RESULT_DATABASE && error.cleanup_stage==VIREO_MYSQL_NODE_STAGE_STATEMENT_CLOSE);assert(report.commit==(op==COMMIT ? VIREO_MYSQL_NODE_MKDIR_COMMITTED : VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED));stop(); }
    for(int op=NAME;op<=COMMIT;++op) {
        start();m.keep_close=op;assert(run()==VIREO_RESULT_BUSY && report.cleanup_pending);size_t calls=m.calls;
        vireo_mysql_node_mkdir_once_report_t again;CHECK(vireo_mysql_node_repository_mkdir_once(repo,&actor,&input,0,&again,NULL),VIREO_RESULT_BUSY);assert(again.cleanup_pending && m.calls==calls);stop();
    }
    start();m.keep_release=true;assert(run()==VIREO_RESULT_INTERNAL && report.commit==VIREO_MYSQL_NODE_MKDIR_COMMITTED && report.cleanup_pending);stop();
    start();m.consume_release_error=true;assert(run()==VIREO_RESULT_DATABASE && report.commit==VIREO_MYSQL_NODE_MKDIR_COMMITTED && !report.cleanup_pending);stop();
    start();m.occupied=2;m.close_error=ROLLBACK;assert(run()==VIREO_RESULT_DATABASE && report.rollback_confirmed && error.stage==VIREO_MYSQL_NODE_STAGE_NAME_CHECK && error.cleanup_stage==VIREO_MYSQL_NODE_STAGE_STATEMENT_CLOSE);stop();
    start();m.occupied=2;m.execute_error=ROLLBACK;assert(run()==VIREO_RESULT_DATABASE && !report.rollback_confirmed && error.stage==VIREO_MYSQL_NODE_STAGE_NAME_CHECK && error.cleanup_stage==VIREO_MYSQL_NODE_STAGE_ROLLBACK && m.disposition==VIREO_MYSQL_POOL_DISCARD);stop();
    start();m.occupied=2;m.bad_result=ROLLBACK;assert(run()==VIREO_RESULT_DATABASE && !report.rollback_confirmed && error.stage==VIREO_MYSQL_NODE_STAGE_NAME_CHECK && error.cleanup_stage==VIREO_MYSQL_NODE_STAGE_ROLLBACK);stop();
    start();m.occupied=2;m.keep_close=ROLLBACK;assert(run()==VIREO_RESULT_DATABASE && report.rollback_confirmed && report.cleanup_pending);stop();
    start();m.execute_error=AUDIT;m.keep_release=true;assert(run()==VIREO_RESULT_DATABASE && error.stage==VIREO_MYSQL_NODE_STAGE_AUDIT && error.database.mysql_code==1062 && error.cleanup_stage==VIREO_MYSQL_NODE_STAGE_RELEASE && report.cleanup_pending);stop();
    start();m.partial_acquire=true;m.fail_at=1;assert(run()==VIREO_RESULT_INTERNAL && !report.cleanup_pending);stop();
    for(unsigned which=0;which<7;++which) {
        start();m.missing_user=which==0;m.disabled=which==1;m.missing_session=which==2;m.revoked=which==3;m.wrong_session=which==4;m.no_parent=which==5;m.file_parent=which==6;
        assert(run()==VIREO_RESULT_NOT_FOUND && report.issue==(which<5 ? VIREO_MYSQL_NODE_AUTH_REJECTED : VIREO_MYSQL_NODE_NOT_FOUND) && !m.prepared[INSERT]);stop();
    }
    const uint64_t times[]={999,1000,2999,3000,UINT64_MAX};
    for(size_t i=0;i<5;++i) { for(size_t j=0;j<5;++j) {
        start();m.first_ms=times[i];m.second_ms=times[j];bool ok=times[i]>=1000 && times[i]<3000 && times[j]>=1000 && times[j]<3000;
        assert(run()==(ok ? VIREO_OK : VIREO_RESULT_NOT_FOUND));if(!ok) { assert(report.issue==VIREO_MYSQL_NODE_AUTH_REJECTED && report.rollback_confirmed && !m.nodes && !m.audits); }stop();
    } }
    start();m.occupied=2;m.first_ms=3000;assert(run()==VIREO_RESULT_NOT_FOUND && report.issue==VIREO_MYSQL_NODE_AUTH_REJECTED);stop();
    start();m.no_parent=true;m.first_ms=3000;assert(run()==VIREO_RESULT_NOT_FOUND && report.issue==VIREO_MYSQL_NODE_AUTH_REJECTED && !m.prepared[NAME]);stop();
    for(unsigned mode=1;mode<=6;++mode) { start();m.utc_mode=mode;vireo_result_t expected=mode<=2 ? VIREO_RESULT_IO : mode==5 ? VIREO_RESULT_OVERFLOW : VIREO_RESULT_INTERNAL;assert(run()==expected && report.rollback_confirmed);if(mode==2) { assert(m.prepared[AUDIT] && !m.nodes); }stop(); }
    unsigned char long_name[256];memset(long_name,'x',sizeof(long_name));
    for(size_t n=1;n<=255;++n) { start();input.name=long_name;input.name_length=n;assert(run()==VIREO_OK);stop(); }
    const unsigned char *invalid[]={(const unsigned char *)".",(const unsigned char *)"..",(const unsigned char *)"a/b",(const unsigned char *)"a\0b"};
    const size_t invalid_size[]={1,2,3,3};
    for(size_t i=0;i<4;++i) { start();input.name=invalid[i];input.name_length=invalid_size[i];assert(run()==VIREO_RESULT_PROTOCOL && !m.calls);stop(); }
    start();input.name=(const unsigned char *)(uintptr_t)1;input.name_length=SIZE_MAX;assert(run()==VIREO_RESULT_RANGE && !m.calls);stop();
    start();memset(input.idempotency_key,0,16);input.idempotency_key[15]=0xff;assert(run()==VIREO_OK);stop();
    start();input.name=long_name;input.name_length=256;assert(run()==VIREO_RESULT_RANGE && !m.calls);stop();
    start();input.name_length=0;assert(run()==VIREO_RESULT_RANGE && !m.calls);stop();
    start();memset(input.request_id,0,16);assert(run()==VIREO_RESULT_INVALID_ARGUMENT && !m.calls);stop();
    start();input.parent_id=0;assert(run()==VIREO_RESULT_INVALID_ARGUMENT && !m.calls);stop();
    start();input.name=NULL;assert(run()==VIREO_RESULT_INVALID_ARGUMENT && !m.calls);stop();
    start();CHECK(vireo_mysql_node_repository_mkdir_once(repo,&actor,&input,60001,&report,&error),VIREO_RESULT_RANGE);assert(!m.calls);stop();
    start();CHECK(vireo_mysql_node_repository_mkdir_once(repo,NULL,&input,0,&report,NULL),VIREO_RESULT_INVALID_ARGUMENT);CHECK(vireo_mysql_node_repository_mkdir_once(repo,&actor,NULL,0,&report,NULL),VIREO_RESULT_INVALID_ARGUMENT);CHECK(vireo_mysql_node_repository_mkdir_once(repo,&actor,&input,0,NULL,NULL),VIREO_RESULT_INVALID_ARGUMENT);pthread_t other;assert(!pthread_create(&other,NULL,wrong_thread,NULL) && !pthread_join(other,NULL));assert(!m.calls);stop();
    start();vireo_mysql_node_actor_t empty={0,51};CHECK(vireo_mysql_node_repository_mkdir_once(repo,&empty,&input,0,&report,NULL),VIREO_RESULT_INVALID_ARGUMENT);empty=(vireo_mysql_node_actor_t){7,0};CHECK(vireo_mysql_node_repository_mkdir_once(repo,&empty,&input,0,&report,NULL),VIREO_RESULT_INVALID_ARGUMENT);CHECK(vireo_mysql_node_repository_mkdir_once(NULL,&actor,&input,0,&report,NULL),VIREO_RESULT_INVALID_ARGUMENT);assert(!m.calls);stop();
    start();CHECK(vireo_mysql_node_repository_mkdir_once(repo,&actor,&input,0,&report,NULL),VIREO_OK);assert(report.commit==VIREO_MYSQL_NODE_MKDIR_COMMITTED);stop();
    printf("PASS %zu mkdir scenarios; %zu individually failed resource calls; commit facts, atomic audit, two UTC, names, cleanup and errno\n",scenarios,normal_calls+conflict_calls);return 0;
}
