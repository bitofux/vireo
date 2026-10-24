/* PROJECT : VIREO; FILE : test_mysql_node_move_once.c; AUTHOR : bitofux;
 * DATE : 2026-10-21; BRIEF : 完整回执/树移动/历史恢复、逐资源失败与提交清理事实。 */
#define _POSIX_C_SOURCE 200809L
#include "mysql_node_repository_internal.h"
#include <vireo/persistence/mysql_node_move_receipt.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(call,want) do { errno=EDOM; vireo_result_t got_=(call); if(got_!=(want)) { fprintf(stderr,"line %d got %d want %d\n",__LINE__,(int)got_,(int)(want)); abort(); } assert(errno==EDOM); } while(0)
enum op { BEGIN, USER, SESSION, SOURCE, TARGET, ANCESTOR, NAME, UPDATE, AUDIT, COMMIT, ROLLBACK, RECEIPT, RECEIPT_INSERT, OPS };
struct node { uint64_t id,owner,parent,created,updated,size; unsigned kind,state; unsigned char name[255],hash[32];size_t length; };
struct statement { enum op op;size_t fetched;struct node *node;char numbers[11][32]; };
static struct {
    size_t calls,fail_at,allocations,statements,leases,prepared[OPS],utc_calls,count;
    size_t pending_nodes,pending_audits,pending_receipts,nodes,audits,receipts;
    uint64_t first_ms,second_ms;
    unsigned shape,utc_mode,receipt_shape;
    bool receipt;
    int bad_result,duplicate,execute_error,close_error,keep_close,shape_op;
    bool missing_user,disabled,missing_session,revoked,wrong_session;
    bool before_native,apply_failed_commit,keep_release,consume_release_error,partial_acquire,missing_name;
    vireo_mysql_pool_disposition_t disposition;
    struct node tree[600];
} m;
static _Alignas(max_align_t) unsigned char thread_storage,pool_storage,connection_storage;
static vireo_mysql_thread_t *thread;
static vireo_mysql_pool_t *pool;
static vireo_mysql_node_repository_t *repo;
static const vireo_mysql_node_actor_t actor={7,51};
static vireo_mysql_node_move_once_input_t input;
static vireo_mysql_node_move_once_report_t report;
static vireo_mysql_node_error_t error;
static size_t scenarios;
static bool fail(void) { return ++m.calls==m.fail_at; }
static void zeroed(const void *p,size_t n)
{ const unsigned char *b=p;for(size_t i=0;i<n;++i) { assert(b[i]==0); } }
static struct node *find(uint64_t id)
{ for(size_t i=0;i<m.count;++i) { if(m.tree[i].id==id) { return m.tree+i; } }return NULL; }
static struct node *add(uint64_t id,uint64_t parent,const char *name)
{
    assert(!find(id) && m.count<600);struct node *v=m.tree+m.count++;*v=(struct node){.id=id,.owner=7,.parent=parent,.kind=1,.state=2,.created=1000,.updated=1500,.length=strlen(name)};
    memcpy(v->name,name,v->length);return v;
}
static void file(struct node *v) { v->kind=2;v->size=91;memset(v->hash,0xa9,32); }
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
{ assert(t==thread && p==pool && lease->owner==pool);if(fail()) { return VIREO_RESULT_INTERNAL; }*out=(void *)&connection_storage;return VIREO_OK; }
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
    if(strstr(sql,"FROM directory_write_receipts")) { assert(strstr(sql,"request_parent_id,request_node_id,request_name,result_node_id,audit_id,created_at_ms") && strstr(sql,"user_id=? AND command=1029 AND idempotency_key=? FOR UPDATE") && m.prepared[SESSION] && !m.prepared[SOURCE]);return RECEIPT; }
    if(strstr(sql,"INSERT INTO directory_write_receipts")) { assert(strstr(sql,"VALUES(?,1029,?,1,?,?,?,?,?,?)") && m.prepared[AUDIT]);return RECEIPT_INSERT; }
    if(strstr(sql,"FROM users")) { assert(strstr(sql,"FOR UPDATE") && !m.prepared[SESSION]);return USER; }
    if(strstr(sql,"FROM sessions")) { assert(strstr(sql,"FOR SHARE") && m.prepared[USER] && !m.prepared[SOURCE]);return SESSION; }
    if(strstr(sql,"SELECT id,owner_id,parent_id,name,state")) {
        assert(strstr(sql,"live_name=? FOR UPDATE") && strstr(sql,"owner_id=? AND parent_id=?") && m.prepared[ANCESTOR]);return NAME;
    }
    if(strstr(sql,"SELECT id,owner_id,parent_id,name,node_type")) {
        assert(strstr(sql,"owner_id=? AND id=? AND state=2 FOR ") && m.prepared[SESSION]);
        if(strstr(sql,"FOR SHARE")) { assert(m.prepared[TARGET]);return ANCESTOR; }
        assert(strstr(sql,"FOR UPDATE"));return m.prepared[SOURCE] ? TARGET : SOURCE;
    }
    if(strstr(sql,"UPDATE file_nodes")) {
        assert(!strcmp(sql,"UPDATE file_nodes SET parent_id=?,name=?,updated_at_ms=? WHERE owner_id=? AND id=? AND state=2") && m.utc_calls==1 && m.prepared[NAME]);return UPDATE;
    }
    assert(strstr(sql,"INSERT INTO operation_audits") && strstr(sql,"VALUES(?,?,?,6,3,?,NULL,0,0,'',?)") && m.prepared[NAME]);return AUDIT;
}
static vireo_result_t prepare(vireo_mysql_thread_t *t,vireo_mysql_connection_t *c,const char *sql,size_t n,
    const vireo_mysql_statement_limits_t *limits,vireo_mysql_statement_t **out,vireo_mysql_error_t *e)
{
    assert(t==thread && c==(void *)&connection_storage && strlen(sql)==n && !*out && !m.statements);
    enum op op=identify(sql);++m.prepared[op];bool old_read=op==SESSION;bool receipt=op==RECEIPT || op==RECEIPT_INSERT;
    assert(limits->max_parameters==(receipt ? 8u : old_read ? 4u : 5u) && limits->max_parameter_bytes==(receipt ? 271u : old_read ? 0u : 255u) && limits->max_columns==(receipt ? 10u : 11u) && limits->max_cell_bytes==255 && limits->max_memory_bytes==32768);
    *e=(vireo_mysql_error_t){0};if(fail()) { e->mysql_code=2013;return VIREO_RESULT_DATABASE; }
    struct statement *s=calloc(1,sizeof(*s));assert(s);s->op=op;*out=(void *)s;++m.statements;return VIREO_OK;
}
static void u64(const vireo_mysql_parameter_t *p,uint64_t expected)
{ assert(p->kind==VIREO_MYSQL_PARAMETER_U64 && p->value.u64==expected); }
static void span(const vireo_mysql_parameter_t *p,const void *bytes,size_t n)
{ assert(p->kind==VIREO_MYSQL_PARAMETER_BYTES && p->value.span.length==n && !memcmp(p->value.span.data,bytes,n)); }
static void apply_commit(void)
{ assert(m.pending_nodes<=1 && m.pending_audits==1 && m.pending_receipts==1);m.nodes+=m.pending_nodes;m.audits+=m.pending_audits;m.receipts+=m.pending_receipts;m.pending_nodes=0;m.pending_audits=0;m.pending_receipts=0; }
static vireo_result_t execute(vireo_mysql_thread_t *t,vireo_mysql_statement_t *statement,
    const vireo_mysql_parameter_t *p,size_t n,vireo_mysql_execution_t *out,vireo_mysql_error_t *e)
{
    struct statement *s=(void *)statement;assert(t==thread);*e=(vireo_mysql_error_t){0};*out=(vireo_mysql_execution_t){0};
    if(s->op==BEGIN || s->op==COMMIT || s->op==ROLLBACK) { assert(!p && !n); }
    else if(s->op==USER || s->op==SESSION) { assert(n==1);u64(p,s->op==USER ? 7u : 51u); }
    else if(s->op==RECEIPT) { assert(n==2);u64(p,7);span(p+1,input.idempotency_key,16); }
    else if(s->op==RECEIPT_INSERT) { assert(n==8);u64(p,7);span(p+1,input.idempotency_key,16);u64(p+2,input.new_parent_id);u64(p+3,input.node_id);span(p+4,input.name,input.name_length);u64(p+5,input.node_id);u64(p+6,501);u64(p+7,m.first_ms); }
    else if(s->op==SOURCE || s->op==TARGET || s->op==ANCESTOR) {
        assert(n==2);u64(p,7);assert(p[1].kind==VIREO_MYSQL_PARAMETER_U64);
        uint64_t id=p[1].value.u64;if(s->op==SOURCE) { assert(id==input.node_id); }if(s->op==TARGET) { assert(id==input.new_parent_id); }
        s->node=find(id);if(s->node && (s->node->owner!=7 || s->node->state!=2)) { s->node=NULL; }
    } else if(s->op==NAME) {
        assert(n==3);u64(p,7);u64(p+1,input.new_parent_id);span(p+2,input.name,input.name_length);
        for(size_t i=0;i<m.count;++i) { struct node *v=m.tree+i;if(v->owner==7 && v->parent==input.new_parent_id && (v->state==1 || v->state==2) && v->length==input.name_length && !memcmp(v->name,input.name,v->length)) { assert(!s->node);s->node=v; } }
        if(m.missing_name) { s->node=NULL; }
    } else if(s->op==UPDATE) {
        struct node *source=find(input.node_id);assert(source);assert(n==5);u64(p,input.new_parent_id);span(p+1,input.name,input.name_length);
        u64(p+2,m.first_ms>source->updated ? m.first_ms : source->updated);u64(p+3,7);u64(p+4,input.node_id);
    } else { assert(n==5);span(p,input.request_id,16);u64(p+1,7);u64(p+2,51);u64(p+3,input.node_id);u64(p+4,m.first_ms); }
    bool failed=fail() || m.execute_error==(int)s->op;out->execution_started=!(failed && m.before_native);
    if(failed) {
        if(s->op==COMMIT && m.apply_failed_commit) { apply_commit(); }
        e->mysql_code=(m.execute_error==(int)s->op && (s->op==UPDATE || s->op==AUDIT || s->op==RECEIPT_INSERT)) ? 1062u : 2013u;return VIREO_RESULT_DATABASE;
    }
    out->has_result=(s->op>=USER && s->op<=NAME) || s->op==RECEIPT;
    if(s->op==UPDATE || s->op==AUDIT || s->op==RECEIPT_INSERT) {
        out->affected_rows=1;out->insert_id=s->op==UPDATE || s->op==RECEIPT_INSERT ? 0u : 501u;
        if(s->op==UPDATE) { ++m.pending_nodes; }else if(s->op==AUDIT) { ++m.pending_audits; }else { ++m.pending_receipts; }
        if(m.shape_op==(int)s->op) { if(m.shape==20) { out->affected_rows=0; }if(m.shape==21) { out->affected_rows=2; }if(m.shape==22) { out->insert_id=0; } }
    }
    if(s->op==COMMIT) { apply_commit(); }if(s->op==ROLLBACK) { m.pending_nodes=0;m.pending_audits=0;m.pending_receipts=0; }
    if(m.bad_result==(int)s->op) { out->has_result=!out->has_result; }return VIREO_OK;
}
static vireo_result_t fetch(vireo_mysql_thread_t *t,vireo_mysql_statement_t *statement,vireo_mysql_fetch_outcome_t *out,vireo_mysql_error_t *e)
{
    struct statement *s=(void *)statement;assert(t==thread);*e=(vireo_mysql_error_t){0};if(fail()) { e->mysql_code=2013;return VIREO_RESULT_DATABASE; }
    bool missing=(s->op==RECEIPT && !m.receipt)||(s->op==USER && m.missing_user)||(s->op==SESSION && m.missing_session)||(s->op>=SOURCE && s->op<=NAME && !s->node);
    size_t rows=missing ? 0 : (m.duplicate==(int)s->op ? 2u : 1u);
    *out=s->fetched++<rows ? VIREO_MYSQL_FETCH_ROW : VIREO_MYSQL_FETCH_DONE;return VIREO_OK;
}
static vireo_result_t column(vireo_mysql_thread_t *t,const vireo_mysql_statement_t *statement,size_t i,vireo_mysql_cell_view_t *out)
{
    struct statement *s=(void *)statement;assert(t==thread);if(fail()) { return VIREO_RESULT_DATABASE; }
    static const char *const user[]={"7","1"},*const session[]={"51","7","1","1000","3000",NULL,"1000"};
    const unsigned char *v=NULL;size_t length=0;bool num=false;uint64_t number=0;struct node *a=s->node;
    if(s->op==USER || s->op==SESSION) {
        const char *c=s->op==USER ? user[i] : session[i];
        if(s->op==USER && i==1 && m.disabled) { c="2"; }
        if(s->op==SESSION) { if(i==1 && m.wrong_session) { c="8"; }if(i==2 && m.revoked) { c="2"; }if(i==5 && m.revoked) { c="1000"; } }
        v=(const unsigned char *)c;length=c ? strlen(c) : 0;
    } else if(s->op==RECEIPT) {
        assert(i<10);static const char *const row[]={"7","1029",NULL,"1","44","31","xyz","31","501","0"};
        const char *c=row[i];unsigned sh=m.receipt_shape;
        if(sh==i+1) { c="0"; }
        if(sh==11 && i==4) { c="23"; }
        if(sh==12 && (i==5 || i==7)) { c="32"; }
        if(sh==13 && i==6) { c="xyy"; }if(sh==14 && i==6) { c="xy"; }
        if(sh==15 && i==6) { c=NULL; }if(sh==16 && i==6) { c=".."; }if(sh==17 && i==6) { c="a/b"; }
        if(sh==18 && i==6) { c="a\0b"; }if(sh==20 && i==9) { c="18446744073709551616"; }
        if(sh==21 && i==9) { c=NULL; }if(sh==22) { return VIREO_RESULT_RANGE; }
        v=(const unsigned char *)c;length=c ? strlen(c) : 0;
        if(i==2 && sh!=3) { v=input.idempotency_key;length=16;if(sh==23) { static const unsigned char wrong[16]={99};v=wrong; } }
        if(i==6 && sh==18) { length=3; }if(i==6 && sh==19) { length=256; }
        if(i==6 && sh==24) { static const unsigned char embedded[]={ 'x',0,'z' };v=embedded;length=3; }
    } else {
        assert(a);num=true;
        if(i==0) { number=a->id; }else if(i==1) { number=a->owner; }else if(i==2) { number=a->parent;if(!number) { num=false; } }
        else if(i==3) { num=false;v=a->name;length=a->length; }
        else if(s->op==NAME) { number=a->state; }
        else if(i==4) { number=a->kind; }else if(i==5) { number=a->state; }
        else if(i==6) { num=false;if(a->kind==2) { v=a->hash;length=32; } }
        else if(i==7) { number=a->size; }else if(i==8) { number=a->created; }else if(i==9) { number=a->updated; }else { num=false; }
        if(m.shape_op==(int)s->op) {
            if(m.shape==1 && i==0) { number=0; }
            if(m.shape==2 && i==1) { number=8; }
            if(m.shape==3 && i==2) { number=999; }
            if(m.shape==4 && i==3) { v=(const unsigned char *)"wrong";length=5; }
            if(m.shape==5 && i==3) { v=NULL;length=0; }
            if(m.shape==6 && i==(s->op==NAME ? 4u : 5u)) { number=3; }
            if(m.shape==7 && i==0) { num=false;v=(const unsigned char *)"18446744073709551616";length=20; }
            if(m.shape==8 && i==0) { num=false;v=(const unsigned char *)"-1";length=2; }
            if(m.shape==9) { return VIREO_RESULT_RANGE; }
            if(m.shape==10 && i==3) { length=256; }
        }
    }
    if(num) { int n=snprintf(s->numbers[i],32,"%llu",(unsigned long long)number);assert(n>0 && n<32);v=(const unsigned char *)s->numbers[i];length=(size_t)n; }
    *out=(vireo_mysql_cell_view_t){.data=v,.length=length,.is_null=v==NULL};return VIREO_OK;
}
static vireo_result_t close_statement(vireo_mysql_thread_t *t,vireo_mysql_statement_t **out,vireo_mysql_error_t *e)
{
    assert(t==thread && *out && m.statements==1);*e=(vireo_mysql_error_t){0};struct statement *s=(void *)*out;
    bool failed=fail() || m.close_error==(int)s->op;if(m.keep_close==(int)s->op) { return VIREO_RESULT_BUSY; }
    free(s);*out=NULL;--m.statements;return failed ? VIREO_RESULT_DATABASE : VIREO_OK;
}
static int utc(struct timespec *out)
{
    assert((m.prepared[SOURCE] || m.receipt) && !m.statements);++m.utc_calls;
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
    m.first_ms=2000;m.second_ms=2001;m.bad_result=-1;m.duplicate=-1;m.execute_error=-1;m.close_error=-1;m.keep_close=-1;m.shape_op=-1;
    (void)add(22,0,"");(void)add(31,22,"abc");(void)add(44,22,"target");
    input=(vireo_mysql_node_move_once_input_t){.node_id=31,.new_parent_id=44,.name=(const unsigned char *)"xyz",.name_length=3,.request_id={1},.idempotency_key={2}};
    CHECK(vireo_mysql_node_repository_create_with_ops(thread,pool,&repo,&error,&ops),VIREO_OK);m.calls=0;++scenarios;
}
static vireo_result_t run(void)
{
    memset(&report,0xa5,sizeof(report));errno=EDOM;
    vireo_result_t rc=vireo_mysql_node_repository_move_once(repo,&actor,&input,0,&report,&error);assert(errno==EDOM);
    assert(report.cleanup_pending==(m.statements!=0 || m.leases!=0));
    if(report.effect==VIREO_MYSQL_NODE_MOVE_EFFECT_NONE) { assert(!report.node_id && !report.audit_id);zeroed(report.idempotency_key,16); }
    else {
        assert(report.node_id==input.node_id && report.audit_id==501 && !memcmp(report.idempotency_key,input.idempotency_key,16));
        if(report.effect==VIREO_MYSQL_NODE_MOVE_EFFECT_APPLIED) { assert(report.commit==VIREO_MYSQL_NODE_MOVE_COMMITTED && m.audits==1 && m.receipts==1 && !report.rollback_confirmed); }
        else { assert(report.commit==VIREO_MYSQL_NODE_MOVE_NOT_COMMITTED && !m.prepared[SOURCE] && !m.prepared[TARGET] && !m.prepared[ANCESTOR] && !m.prepared[NAME] && !m.prepared[UPDATE] && !m.prepared[AUDIT] && !m.prepared[RECEIPT_INSERT] && !m.prepared[COMMIT]); }
    }
    if(rc==VIREO_OK) { assert(report.effect!=VIREO_MYSQL_NODE_MOVE_EFFECT_NONE && !report.cleanup_pending && !error.stage); }return rc;
}

static void stop(void)
{
    assert(m.allocations==1);m.fail_at=0;m.keep_release=false;m.consume_release_error=false;m.keep_close=-1;m.close_error=-1;m.execute_error=-1;
    CHECK(vireo_mysql_node_repository_destroy(&repo,NULL),VIREO_OK);assert(!repo && !m.allocations && !m.leases && !m.statements);
}
static void reject(vireo_result_t want,vireo_mysql_node_issue_t issue)
{ CHECK(run(),want);assert(report.issue==issue && report.rollback_confirmed && !m.nodes && !m.audits && !m.prepared[UPDATE] && !m.prepared[AUDIT]); }
static void *wrong_thread(void *unused)
{ (void)unused;vireo_mysql_node_move_once_report_t out;CHECK(vireo_mysql_node_repository_move_once(repo,&actor,&input,0,&out,NULL),VIREO_RESULT_INVALID_ARGUMENT);return NULL; }
static void chain(size_t count,bool source)
{
    assert(count>1 && count<=257);for(size_t i=1;i<count;++i) { (void)add(100+i,i==1 ? 22 : 99+i,"d"); }
    if(source) { find(31)->parent=100+count-1; }else { input.new_parent_id=100+count-1; }
}
int main(void)
{
    thread=(void *)&thread_storage;pool=(void *)&pool_storage;
    start();m.receipt=true;CHECK(run(),VIREO_OK);assert(report.effect==VIREO_MYSQL_NODE_MOVE_EFFECT_RECOVERED && report.rollback_confirmed && m.utc_calls==1);size_t recovery_calls=m.calls;stop();
    for(size_t at=1;at<=recovery_calls;++at) { start();m.receipt=true;m.fail_at=at;assert(run()!=VIREO_OK && error.stage);stop(); }
    for(unsigned shape=1;shape<=24;++shape) {
        start();m.receipt=true;m.receipt_shape=shape;CHECK(run(),shape==10 ? VIREO_OK : VIREO_RESULT_DATABASE);
        if(shape!=10) { assert(report.issue==(shape==7 || (shape>=11 && shape<=14) ? VIREO_MYSQL_NODE_IDEMPOTENCY_CONFLICT : VIREO_MYSQL_NODE_RECEIPT_INVALID)); }stop();
    }
    start();m.receipt=true;m.duplicate=RECEIPT;CHECK(run(),VIREO_RESULT_DATABASE);assert(report.issue==VIREO_MYSQL_NODE_RECEIPT_INVALID);stop();
    for(unsigned which=0;which<6;++which) {
        start();m.receipt=true;if(which==0) { m.execute_error=ROLLBACK; }if(which==1) { m.close_error=ROLLBACK; }if(which==2) { m.keep_close=ROLLBACK; }if(which==3) { m.keep_release=true; }if(which==4) { m.consume_release_error=true; }if(which==5) { m.bad_result=ROLLBACK; }
        assert(run()!=VIREO_OK && report.effect==VIREO_MYSQL_NODE_MOVE_EFFECT_RECOVERED);stop();
    }
    start();m.receipt=true;m.receipt_shape=13;m.first_ms=3000;reject(VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_NODE_AUTH_REJECTED);stop();
    start();m.receipt=true;m.close_error=RECEIPT;assert(run()!=VIREO_OK && report.effect==VIREO_MYSQL_NODE_MOVE_EFFECT_NONE);stop();
    for(int op=RECEIPT;op<=RECEIPT_INSERT;++op) {
        start();m.bad_result=op;CHECK(run(),VIREO_RESULT_DATABASE);stop();
        start();m.close_error=op;CHECK(run(),VIREO_RESULT_DATABASE);assert(report.effect==VIREO_MYSQL_NODE_MOVE_EFFECT_NONE);stop();
        start();m.keep_close=op;CHECK(run(),VIREO_RESULT_BUSY);assert(report.cleanup_pending);stop();
    }
    for(unsigned shape=20;shape<=22;++shape) { start();m.shape_op=RECEIPT_INSERT;m.shape=shape;CHECK(run(),shape==22 ? VIREO_OK : VIREO_RESULT_DATABASE);stop(); }
    start();m.execute_error=RECEIPT_INSERT;CHECK(run(),VIREO_RESULT_DATABASE);assert(error.database.mysql_code==1062 && report.issue==VIREO_MYSQL_NODE_ISSUE_NONE && !m.nodes && !m.audits && !m.receipts);stop();
    start();memset(input.idempotency_key,0,16);CHECK(run(),VIREO_RESULT_INVALID_ARGUMENT);assert(!m.calls);stop();
    start();memset(input.idempotency_key,0,16);input.idempotency_key[15]=255;CHECK(run(),VIREO_OK);stop();
    start();input.name=(const unsigned char *)(uintptr_t)1;input.name_length=SIZE_MAX;CHECK(run(),VIREO_RESULT_RANGE);assert(!m.calls);stop();
    start();CHECK(run(),VIREO_OK);size_t normal_calls=m.calls;assert(m.utc_calls==2 && m.disposition==VIREO_MYSQL_POOL_RECYCLE && m.prepared[ANCESTOR]==3);stop();
    for(size_t at=1;at<=normal_calls;++at) { start();m.fail_at=at;assert(run()!=VIREO_OK && error.stage);stop(); }
    start();input.new_parent_id=22;input.name=(const unsigned char *)"abc";CHECK(run(),VIREO_OK);assert(!m.nodes && !m.prepared[UPDATE] && m.receipts==1);size_t noop_calls=m.calls;stop();
    for(size_t at=1;at<=noop_calls;++at) { start();input.new_parent_id=22;input.name=(const unsigned char *)"abc";m.fail_at=at;assert(run()!=VIREO_OK);stop(); }
    for(unsigned state=1;state<=3;++state) {
        start();struct node *v=add(91,44,"xyz");v->state=state;if(state==3) { CHECK(run(),VIREO_OK); }else { reject(VIREO_RESULT_DATABASE,VIREO_MYSQL_NODE_NAME_CONFLICT); }stop();
    }
    start();(void)add(91,44,"xyz");reject(VIREO_RESULT_DATABASE,VIREO_MYSQL_NODE_NAME_CONFLICT);size_t conflict_calls=m.calls;stop();
    for(size_t at=1;at<=conflict_calls;++at) { start();(void)add(91,44,"xyz");m.fail_at=at;assert(run()!=VIREO_OK && m.calls>=at && report.commit==VIREO_MYSQL_NODE_MOVE_NOT_COMMITTED);stop(); }
    for(unsigned shape=1;shape<=10;++shape) { start();(void)add(91,44,"xyz");m.shape_op=NAME;m.shape=shape;CHECK(run(),VIREO_RESULT_DATABASE);assert(report.issue==VIREO_MYSQL_NODE_UNEXPECTED_RESULT && error.stage==VIREO_MYSQL_NODE_STAGE_NAME_CHECK);stop(); }
    for(int op=SOURCE;op<=ANCESTOR;++op) { for(unsigned shape=1;shape<=10;++shape) {
        if(shape==3 || shape==4) { continue; } /* Valid alternate values are checked by the tree/name policy, not row shape. */
        start();m.shape_op=op;m.shape=shape;CHECK(run(),VIREO_RESULT_DATABASE);assert(report.issue==VIREO_MYSQL_NODE_UNEXPECTED_RESULT);stop();
    } }
    for(int op=USER;op<=NAME;++op) { start();(void)add(91,44,"xyz");m.duplicate=op;CHECK(run(),VIREO_RESULT_DATABASE);assert(report.issue==VIREO_MYSQL_NODE_UNEXPECTED_RESULT);stop(); }
    for(int op=BEGIN;op<=COMMIT;++op) { start();m.bad_result=op;CHECK(run(),VIREO_RESULT_DATABASE);if(op==COMMIT) { assert(report.commit==VIREO_MYSQL_NODE_MOVE_UNKNOWN && !m.prepared[ROLLBACK] && m.disposition==VIREO_MYSQL_POOL_DISCARD); }stop(); }
    for(int op=UPDATE;op<=AUDIT;++op) { for(unsigned shape=20;shape<=22;++shape) { start();m.shape_op=op;m.shape=shape;CHECK(run(),op==UPDATE && shape==22 ? VIREO_OK : VIREO_RESULT_DATABASE);stop(); } }
    for(int op=UPDATE;op<=AUDIT;++op) { start();m.execute_error=op;CHECK(run(),VIREO_RESULT_DATABASE);assert(error.database.mysql_code==1062 && report.issue==VIREO_MYSQL_NODE_ISSUE_NONE && report.rollback_confirmed && !m.nodes && !m.audits);stop(); }
    for(unsigned before=0;before<=1;++before) { for(unsigned applied=0;applied<=1-before;++applied) { start();m.execute_error=COMMIT;m.before_native=before!=0;m.apply_failed_commit=applied!=0;CHECK(run(),VIREO_RESULT_DATABASE);assert(report.commit==(before ? VIREO_MYSQL_NODE_MOVE_NOT_COMMITTED : VIREO_MYSQL_NODE_MOVE_UNKNOWN));assert(m.prepared[ROLLBACK]==before);if(!before) { assert(m.disposition==VIREO_MYSQL_POOL_DISCARD); }stop(); } }
    for(int op=BEGIN;op<=COMMIT;++op) { start();m.close_error=op;CHECK(run(),VIREO_RESULT_DATABASE);assert(error.cleanup_stage==VIREO_MYSQL_NODE_STAGE_STATEMENT_CLOSE && report.commit==(op==COMMIT ? VIREO_MYSQL_NODE_MOVE_COMMITTED : VIREO_MYSQL_NODE_MOVE_NOT_COMMITTED));stop(); }
    for(int op=NAME;op<=COMMIT;++op) {
        start();m.keep_close=op;CHECK(run(),VIREO_RESULT_BUSY);assert(report.cleanup_pending);size_t calls=m.calls;
        vireo_mysql_node_move_once_report_t again;CHECK(vireo_mysql_node_repository_move_once(repo,&actor,&input,0,&again,NULL),VIREO_RESULT_BUSY);assert(again.cleanup_pending && m.calls==calls);stop();
    }
    start();m.keep_release=true;CHECK(run(),VIREO_RESULT_INTERNAL);assert(report.commit==VIREO_MYSQL_NODE_MOVE_COMMITTED && report.cleanup_pending);stop();
    start();m.consume_release_error=true;CHECK(run(),VIREO_RESULT_DATABASE);assert(report.commit==VIREO_MYSQL_NODE_MOVE_COMMITTED && !report.cleanup_pending);stop();
    for(int mode=0;mode<4;++mode) {
        start();(void)add(91,44,"xyz");if(mode==0) { m.close_error=ROLLBACK; }if(mode==1) { m.execute_error=ROLLBACK; }if(mode==2) { m.bad_result=ROLLBACK; }if(mode==3) { m.keep_close=ROLLBACK; }
        CHECK(run(),VIREO_RESULT_DATABASE);assert(report.issue==VIREO_MYSQL_NODE_NAME_CONFLICT && error.stage==VIREO_MYSQL_NODE_STAGE_NAME_CHECK && error.cleanup_result && report.rollback_confirmed==(mode==0 || mode==3));stop();
    }
    start();m.execute_error=AUDIT;m.keep_release=true;CHECK(run(),VIREO_RESULT_DATABASE);assert(error.stage==VIREO_MYSQL_NODE_STAGE_AUDIT && error.database.mysql_code==1062 && error.cleanup_stage==VIREO_MYSQL_NODE_STAGE_RELEASE && report.cleanup_pending);stop();
    start();m.partial_acquire=true;m.fail_at=1;CHECK(run(),VIREO_RESULT_INTERNAL);assert(!report.cleanup_pending);stop();
    for(unsigned which=0;which<5;++which) {
        start();m.missing_user=which==0;m.disabled=which==1;m.missing_session=which==2;m.revoked=which==3;m.wrong_session=which==4;
        reject(VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_NODE_AUTH_REJECTED);stop();
    }
    for(unsigned target=0;target<2;++target) { for(unsigned which=0;which<5;++which) {
        start();struct node *v=find(target ? 44 : 31);if(which==0) { v->id=99; }if(which==1) { v->owner=8; }if(which==2) { v->state=1; }if(which==3) { v->state=3; }if(which==4) { file(v); }
        if(!target && which==4) { CHECK(run(),VIREO_OK); }else { reject(VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_NODE_NOT_FOUND); }stop();
    } }
    start();input.node_id=22;reject(VIREO_RESULT_DATABASE,VIREO_MYSQL_NODE_ROOT_IMMOVABLE);stop();
    start();input.node_id=22;input.new_parent_id=99;reject(VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_NODE_NOT_FOUND);stop();
    start();input.new_parent_id=31;reject(VIREO_RESULT_DATABASE,VIREO_MYSQL_NODE_MOVE_CYCLE);stop();
    start();find(44)->parent=31;reject(VIREO_RESULT_DATABASE,VIREO_MYSQL_NODE_MOVE_CYCLE);stop();
    start();file(find(31));input.new_parent_id=31;reject(VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_NODE_NOT_FOUND);stop();
    for(unsigned target=0;target<2;++target) { for(unsigned which=0;which<5;++which) {
        start();struct node *v=add(55,22,"ancestor");if(target) { find(44)->parent=55; }else { find(31)->parent=55; }
        if(which==0) { v->id=99; }if(which==1) { v->state=3; }if(which==2) { file(v); }if(which==3) { v->parent=55; }if(which==4) { (void)add(56,55,"loop");v->parent=56; }
        reject(VIREO_RESULT_DATABASE,VIREO_MYSQL_NODE_TREE_INVALID);stop();
    } }
    for(unsigned source=0;source<2;++source) { for(size_t count=255;count<=257;++count) { start();chain(count,source!=0);if(count<=256) { CHECK(run(),VIREO_OK); }else { reject(VIREO_RESULT_RANGE,VIREO_MYSQL_NODE_ANCESTRY_LIMIT); }stop(); } }
    /* Source-chain corruption wins over target cycle/name; identity time wins over all domain failures. */
    for(unsigned domain=0;domain<6;++domain) {
        start();if(domain==0) { input.node_id=99; }if(domain==1) { input.node_id=22; }if(domain==2) { find(31)->parent=99;find(44)->parent=31; }if(domain==3) { input.new_parent_id=31; }if(domain==4) { (void)add(91,44,"xyz"); }if(domain==5) { chain(257,true); }
        m.first_ms=3000;reject(VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_NODE_AUTH_REJECTED);assert(m.utc_calls==1);stop();
    }
    start();find(31)->parent=99;find(44)->parent=31;reject(VIREO_RESULT_DATABASE,VIREO_MYSQL_NODE_TREE_INVALID);stop();
    start();input.new_parent_id=22;input.name=(const unsigned char *)"abc";m.missing_name=true;CHECK(run(),VIREO_RESULT_DATABASE);assert(report.issue==VIREO_MYSQL_NODE_UNEXPECTED_RESULT && !m.utc_calls);stop();
    start();input.new_parent_id=22;input.name=(const unsigned char *)"abc";m.execute_error=AUDIT;CHECK(run(),VIREO_RESULT_DATABASE);assert(report.rollback_confirmed && !m.nodes && !m.audits && !m.prepared[UPDATE]);stop();
    const uint64_t times[]={999,1000,2999,3000,UINT64_MAX};
    for(size_t i=0;i<5;++i) { for(size_t j=0;j<5;++j) {
        start();m.first_ms=times[i];m.second_ms=times[j];bool ok=times[i]>=1000 && times[i]<3000 && times[j]>=1000 && times[j]<3000;
        CHECK(run(),ok ? VIREO_OK : VIREO_RESULT_NOT_FOUND);if(!ok) { assert(report.issue==VIREO_MYSQL_NODE_AUTH_REJECTED && report.rollback_confirmed && !m.nodes && !m.audits); }stop();
    } }
    for(unsigned mode=1;mode<=6;++mode) { start();m.utc_mode=mode;CHECK(run(),mode<=2 ? VIREO_RESULT_IO : mode==5 ? VIREO_RESULT_OVERFLOW : VIREO_RESULT_INTERNAL);if(mode<=2) { assert(error.system_errno==EIO); }stop(); }
    start();find(31)->updated=2500;m.first_ms=2000;CHECK(run(),VIREO_OK);assert(m.prepared[UPDATE]==1);stop();
    unsigned char maximum[256];memset(maximum,0xff,sizeof(maximum));
    for(size_t n=1;n<=255;n+=254) { start();input.name=maximum;input.name_length=n;CHECK(run(),VIREO_OK);stop(); }
    const unsigned char *bad[]={(const unsigned char *)".",(const unsigned char *)"..",(const unsigned char *)"a/b",(const unsigned char *)"a\0b"};const size_t lengths[]={1,2,3,3};
    for(size_t i=0;i<4;++i) { start();input.name=bad[i];input.name_length=lengths[i];CHECK(run(),VIREO_RESULT_PROTOCOL);assert(!m.calls);stop(); }
    for(unsigned which=0;which<8;++which) {
        start();if(which==0) { input.node_id=0; }if(which==1) { input.new_parent_id=0; }if(which==2) { input.name=NULL; }if(which==3) { memset(input.request_id,0,16); }if(which==4) { input.name_length=0; }if(which==5) { input.name_length=256; }
        if(which<6) { CHECK(run(),which>=4 ? VIREO_RESULT_RANGE : VIREO_RESULT_INVALID_ARGUMENT); }else if(which==6) { CHECK(vireo_mysql_node_repository_move_once(repo,&actor,&input,60001,&report,&error),VIREO_RESULT_RANGE); }else { vireo_mysql_node_actor_t bad_actor={0,51};CHECK(vireo_mysql_node_repository_move_once(repo,&bad_actor,&input,0,&report,&error),VIREO_RESULT_INVALID_ARGUMENT); }assert(!m.calls);stop();
    }
    start();CHECK(vireo_mysql_node_repository_move_once(NULL,&actor,&input,0,&report,&error),VIREO_RESULT_INVALID_ARGUMENT);CHECK(vireo_mysql_node_repository_move_once(repo,NULL,&input,0,&report,&error),VIREO_RESULT_INVALID_ARGUMENT);CHECK(vireo_mysql_node_repository_move_once(repo,&actor,NULL,0,&report,&error),VIREO_RESULT_INVALID_ARGUMENT);CHECK(vireo_mysql_node_repository_move_once(repo,&actor,&input,0,NULL,&error),VIREO_RESULT_INVALID_ARGUMENT);
    pthread_t other;assert(!pthread_create(&other,NULL,wrong_thread,NULL) && !pthread_join(other,NULL));stop();
    printf("PASS %zu move_once scenarios; resource failure points %zu changed / %zu unchanged / %zu conflict; tree256/257, time, atomic update/audit/receipt, commit/cleanup facts\n",scenarios,normal_calls,noop_calls,conflict_calls);return 0;
}
