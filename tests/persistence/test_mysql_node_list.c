/* PROJECT : VIREO; FILE : test_mysql_node_list.c; AUTHOR : bitofux;
 * DATE : 2026-10-21; BRIEF : 页边界、lookahead完整校验与逐资源失败的独立模型。 */
#define _POSIX_C_SOURCE 200809L
#include "mysql_node_repository_internal.h"
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(call,want) do { errno=EDOM; vireo_result_t got_=(call); if(got_!=(want)) { fprintf(stderr,"line %d got %d want %d\n",__LINE__,(int)got_,(int)(want)); abort(); } assert(errno==EDOM); } while(0)
enum op { BEGIN, USER, SESSION, PARENT, CHILDREN, ROLLBACK };
struct statement { enum op op; size_t fetched; char text[11][32]; };
static struct {
    size_t calls,fail_at,allocations,statements,leases,prepared[6],total,selected_count,shape_row;
    uint64_t ids[70],selected[70],after,limit,now;
    bool no_parent,file_parent,missing_user,missing_session,disabled,revoked,wrong_session;
    bool keep_close,keep_release,consumed_release,partial_acquire,borrow_fail,over_limit,advance_time;
    unsigned shape,utc_mode;
    vireo_mysql_pool_disposition_t disposition;
} m;
static _Alignas(max_align_t) unsigned char thread_storage,pool_storage,connection_storage;
static vireo_mysql_thread_t *thread;
static vireo_mysql_pool_t *pool;
static vireo_mysql_node_repository_t *repo;
static const vireo_mysql_node_actor_t actor={7,51};
static vireo_mysql_node_page_t page;
static vireo_mysql_node_report_t report;
static vireo_mysql_node_error_t error;
static size_t scenarios;
static bool fail(void) { return ++m.calls==m.fail_at; }
static void *allocate(size_t n) { if(fail()) { return NULL; } void *p=malloc(n);assert(p);++m.allocations;return p; }
static void free_memory(void *p) { assert(m.allocations>0);--m.allocations;free(p); }
static void zeroed(const void *p,size_t n) { const unsigned char *s=p;for(size_t i=0;i<n;++i) { assert(!s[i]); } }
static vireo_result_t acquire(vireo_mysql_thread_t *t,vireo_mysql_pool_t *p,uint32_t wait,
    vireo_mysql_lease_t *lease,vireo_mysql_pool_acquisition_t *out,vireo_mysql_pool_error_t *e)
{
    assert(t==thread && p==pool && wait<=60000 && !lease->owner);*e=(vireo_mysql_pool_error_t){0};*out=(vireo_mysql_pool_acquisition_t){0};
    bool failed=fail();if(failed && !m.partial_acquire) { return VIREO_RESULT_BUSY; }
    *lease=(vireo_mysql_lease_t){.owner=pool,.generation=1};out->acquired=true;++m.leases;
    return failed ? VIREO_RESULT_INTERNAL : VIREO_OK;
}
static vireo_result_t borrow(vireo_mysql_thread_t *t,vireo_mysql_pool_t *p,const vireo_mysql_lease_t *lease,vireo_mysql_connection_t **out)
{
    assert(t==thread && p==pool && lease->owner==pool);if(fail() || m.borrow_fail) { return VIREO_RESULT_INTERNAL; }
    *out=(void *)&connection_storage;return VIREO_OK;
}
static vireo_result_t release(vireo_mysql_thread_t *t,vireo_mysql_pool_t *p,vireo_mysql_lease_t *lease,
    vireo_mysql_pool_disposition_t disposition,vireo_mysql_pool_release_t *out,vireo_mysql_pool_error_t *e)
{
    assert(t==thread && p==pool && lease->owner==pool && !m.statements && m.leases==1);
    *out=(vireo_mysql_pool_release_t){0};*e=(vireo_mysql_pool_error_t){0};m.disposition=disposition;
    if(fail() || m.keep_release) { return VIREO_RESULT_INTERNAL; }
    *lease=(vireo_mysql_lease_t){0};out->released=true;--m.leases;
    return m.consumed_release ? VIREO_RESULT_DATABASE : VIREO_OK;
}
static enum op identify(const char *sql)
{
    if(!strcmp(sql,"SET autocommit=0")) { return BEGIN; }
    if(!strcmp(sql,"ROLLBACK")) { return ROLLBACK; }
    assert(strstr(sql,"FOR SHARE"));
    if(strstr(sql,"FROM users")) { assert(!m.prepared[SESSION] && !m.prepared[PARENT]);return USER; }
    if(strstr(sql,"FROM sessions")) { assert(m.prepared[USER]==1 && !m.prepared[PARENT]);return SESSION; }
    assert(strstr(sql,"FROM file_nodes WHERE owner_id=? AND ") && strstr(sql,"state=2") && m.prepared[SESSION]==1);
    if(strstr(sql,"id>?")) {
        assert(m.prepared[PARENT]==1 && strstr(sql,"parent_id=?") && strstr(sql,"ORDER BY id ASC LIMIT ? FOR SHARE"));return CHILDREN;
    }
    assert(strstr(sql,"AND id=?") && !strstr(sql,"LIMIT"));return PARENT;
}
static vireo_result_t prepare(vireo_mysql_thread_t *t,vireo_mysql_connection_t *c,const char *sql,size_t n,
    const vireo_mysql_statement_limits_t *limits,vireo_mysql_statement_t **out,vireo_mysql_error_t *e)
{
    assert(t==thread && c==(void *)&connection_storage && strlen(sql)==n && !*out && !m.statements);
    assert(limits->max_parameters==4 && limits->max_columns==11 && limits->max_cell_bytes==255);
    *e=(vireo_mysql_error_t){0};enum op op=identify(sql);++m.prepared[op];
    if(fail()) { e->mysql_code=2013;return VIREO_RESULT_DATABASE; }
    struct statement *s=calloc(1,sizeof(*s));assert(s);s->op=op;*out=(void *)s;++m.statements;return VIREO_OK;
}
static vireo_result_t execute(vireo_mysql_thread_t *t,vireo_mysql_statement_t *statement,
    const vireo_mysql_parameter_t *p,size_t n,vireo_mysql_execution_t *out,vireo_mysql_error_t *e)
{
    struct statement *s=(void *)statement;assert(t==thread);*e=(vireo_mysql_error_t){0};*out=(vireo_mysql_execution_t){.execution_started=true};
    if(s->op==BEGIN || s->op==ROLLBACK) { assert(!p && !n); }
    else {
        size_t expected=s->op==CHILDREN ? 4u : (s->op==PARENT ? 2u : 1u);assert(n==expected);
        for(size_t i=0;i<n;++i) { assert(p[i].kind==VIREO_MYSQL_PARAMETER_U64); }
        assert(p[0].value.u64==(s->op==SESSION ? 51u : 7u));out->has_result=true;
        if(s->op==PARENT || s->op==CHILDREN) { assert(p[1].value.u64==22); }
        if(s->op==CHILDREN) {
            m.after=p[2].value.u64;m.limit=p[3].value.u64;assert(m.limit>=2 && m.limit<=65);m.selected_count=0;
            for(size_t i=0;i<m.total;++i) {
                if(m.ids[i]>m.after && (m.over_limit || m.selected_count<m.limit)) { m.selected[m.selected_count++]=m.ids[i]; }
            }
            if(m.advance_time) { m.now=3000; }
            if(m.shape==18) { out->has_result=false; }
        }
    }
    if(fail()) { e->mysql_code=2013;return VIREO_RESULT_DATABASE; }return VIREO_OK;
}
static vireo_result_t fetch(vireo_mysql_thread_t *t,vireo_mysql_statement_t *statement,vireo_mysql_fetch_outcome_t *out,vireo_mysql_error_t *e)
{
    struct statement *s=(void *)statement;assert(t==thread);*e=(vireo_mysql_error_t){0};
    if(fail()) { e->mysql_code=2013;return VIREO_RESULT_DATABASE; }
    bool missing=(s->op==USER && m.missing_user)||(s->op==SESSION && m.missing_session)||(s->op==PARENT && m.no_parent);
    size_t count=missing ? 0 : (s->op==CHILDREN ? m.selected_count : 1);
    *out=s->fetched++<count ? VIREO_MYSQL_FETCH_ROW : VIREO_MYSQL_FETCH_DONE;
    return VIREO_OK;
}
static vireo_result_t column(vireo_mysql_thread_t *t,const vireo_mysql_statement_t *statement,size_t i,vireo_mysql_cell_view_t *out)
{
    struct statement *s=(void *)statement;assert(t==thread);if(fail()) { return VIREO_RESULT_DATABASE; }
    static const char *const user[]={"7","1"},*const session[]={"51","7","1","1000","3000",NULL,"1000"};
    static const char *const parent[]={"22","7",NULL,"","1","2",NULL,"0","1000","1000",NULL};
    static const char *const child[]={NULL,"7","22",NULL,"1","2",NULL,"0","1000","1000",NULL};
    const char *v=s->op==USER ? user[i] : (s->op==SESSION ? session[i] : (s->op==PARENT ? parent[i] : child[i]));
    bool binary=false;static const unsigned char hash[32]={0};
    if(s->op==USER && i==1 && m.disabled) { v="2"; }
    if(s->op==SESSION) {
        if(m.wrong_session && i==1) { v="8"; }
        if(m.revoked && i==2) { v="2"; }if(m.revoked && i==5) { v="1000"; }
    }
    bool is_file=(s->op==PARENT && m.file_parent)||(s->op==CHILDREN && (s->fetched-1)%3==1);
    if(is_file) {
        if(i==2) { v=s->op==PARENT ? "1" : "22"; }if(i==3) { v="file"; }
        if(i==4) { v="2"; }if(i==6) { v="";binary=true; }if(i==7) { v="18446744073709551615"; }
    }
    if(s->op==CHILDREN) {
        size_t row=s->fetched-1;assert(row<m.selected_count);
        if(i==0) { (void)snprintf(s->text[i],sizeof(s->text[i]),"%llu",(unsigned long long)m.selected[row]);v=s->text[i]; }
        if(i==3) { (void)snprintf(s->text[i],sizeof(s->text[i]),"n%llu",(unsigned long long)m.selected[row]);v=s->text[i]; }
        if(row==m.shape_row) {
            if(m.shape==1 && i==1) { v="8"; }
            if(m.shape==2 && i==2) { v="23"; }
            if((m.shape==3 || m.shape==4) && i==0) { assert(row>0);(void)snprintf(s->text[i],sizeof(s->text[i]),"%llu",(unsigned long long)(m.selected[row-1]-(m.shape==4 ? 1u : 0u)));v=s->text[i]; }
            if(m.shape==5 && i==3) { v=NULL; }
            if(m.shape==7 && i==0) { v="18446744073709551616"; }
            if(m.shape==8 && i==5) { v="1"; }
            if(m.shape==9 && i==4) { v="1"; }if(m.shape==9 && i==6) { v="bad";binary=false; }
            if(m.shape==10 && i==4) { v="2"; }if(m.shape==10 && i==6) { v=NULL;binary=false; }
            if(m.shape==11 && i==9) { v="999"; }
            if(m.shape==13 && i==2) { v=NULL; }
            if(m.shape==14 && i==3) { v=".."; }
            if(m.shape==15 && i==0) { v="0"; }
            if(m.shape==17) { return VIREO_RESULT_RANGE; }
        }
    }
    *out=(vireo_mysql_cell_view_t){.data=(const unsigned char *)v,.length=v ? strlen(v) : 0,.is_null=v==NULL};
    if(binary) { out->data=hash;out->length=32; }
    if(s->op==CHILDREN && s->fetched-1==m.shape_row && i==3) {
        if(m.shape==6) { out->length=256; }
        if(m.shape==12) { static const unsigned char name[]={'a',0,'b'};out->data=name;out->length=3; }
    }
    return VIREO_OK;
}
static vireo_result_t close_statement(vireo_mysql_thread_t *t,vireo_mysql_statement_t **out,vireo_mysql_error_t *e)
{
    assert(t==thread && *out && m.statements==1);*e=(vireo_mysql_error_t){0};bool failed=fail();
    if(m.keep_close && ((struct statement *)(void *)*out)->op==CHILDREN) { return VIREO_RESULT_BUSY; }
    free(*out);*out=NULL;--m.statements;return failed ? VIREO_RESULT_DATABASE : VIREO_OK;
}
static int utc(struct timespec *out)
{
    assert(m.prepared[PARENT] && !m.statements);
    if(fail() || m.utc_mode==1) { errno=EIO;return -1; }
    *out=(struct timespec){.tv_sec=(time_t)(m.now/1000),.tv_nsec=(long)(m.now%1000)*1000000L};
    if(m.utc_mode==2) { out->tv_nsec=1000000000L; }if(m.utc_mode==3) { out->tv_sec=-1; }
    if(m.utc_mode==4) { out->tv_sec=(time_t)INT64_MAX; }if(m.utc_mode==5) { return 7; }return 0;
}
static const vireo_mysql_node_ops_t ops={allocate,free_memory,acquire,borrow,release,prepare,execute,fetch,column,close_statement,utc};
static void start(void)
{
    assert(!repo && !m.allocations && !m.statements && !m.leases);memset(&m,0,sizeof(m));m.now=2000;m.total=3;
    for(size_t i=0;i<70;++i) { m.ids[i]=100+(uint64_t)i; }
    CHECK(vireo_mysql_node_repository_create_with_ops(thread,pool,&repo,&error,&ops),VIREO_OK);m.calls=0;++scenarios;
}
static void stop(void)
{
    assert(m.allocations==1);m.keep_close=false;m.keep_release=false;m.consumed_release=false;m.fail_at=0;
    CHECK(vireo_mysql_node_repository_destroy(&repo,NULL),VIREO_OK);assert(!repo && !m.allocations && !m.statements && !m.leases);
}
static vireo_result_t run(uint64_t after,size_t size)
{
    vireo_mysql_node_list_query_t q={22,after,size};memset(&page,0xa5,sizeof(page));errno=EDOM;
    vireo_result_t rc=vireo_mysql_node_repository_list_children(repo,&actor,&q,0,&page,&report,&error);
    assert(errno==EDOM && report.found==(rc==VIREO_OK) && m.allocations==1);
    if(rc!=VIREO_OK) { zeroed(&page,sizeof(page)); }
    else {
        assert(page.count<=size && page.count<=64 && report.rollback_confirmed && !report.cleanup_pending);
        if(page.has_more) { assert(page.count>0 && page.next_after_id==page.nodes[page.count-1].id); }
        else { assert(!page.next_after_id); }
        zeroed(page.nodes+page.count,(64-page.count)*sizeof(page.nodes[0]));
    }
    return rc;
}
static void *wrong_thread(void *unused)
{
    (void)unused;vireo_mysql_node_list_query_t q={22,0,2};vireo_mysql_node_page_t out;vireo_mysql_node_report_t r;
    CHECK(vireo_mysql_node_repository_list_children(repo,&actor,&q,0,&out,&r,NULL),VIREO_RESULT_INVALID_ARGUMENT);zeroed(&out,sizeof(out));return NULL;
}
int main(void)
{
    thread=(void *)&thread_storage;pool=(void *)&pool_storage;
    start();assert(run(0,2)==VIREO_OK && page.count==2 && page.nodes[0].id==100 && page.next_after_id==101);
    assert(page.nodes[1].has_object_hash && page.nodes[1].size==UINT64_MAX);size_t normal_calls=m.calls;
    pthread_t other;assert(!pthread_create(&other,NULL,wrong_thread,NULL) && !pthread_join(other,NULL));stop();
    for(size_t i=1;i<=normal_calls;++i) { start();m.fail_at=i;assert(run(0,2)!=VIREO_OK);stop(); }
    const size_t totals[]={0,1,2,64,65,70};
    for(size_t size=1;size<=64;++size) {
        for(size_t j=0;j<sizeof(totals)/sizeof(totals[0]);++j) {
            start();m.total=totals[j];assert(run(0,size)==VIREO_OK);size_t expected=m.total<size ? m.total : size;
            assert(page.count==expected && page.has_more==(m.total>size));
            for(size_t k=0;k<expected;++k) { assert(page.nodes[k].id==100+(uint64_t)k && page.nodes[k].parent_id==22); }stop();
        }
    }
    for(unsigned shape=1;shape<=18;++shape) {
        if(shape==16) { continue; }
        start();m.shape=shape;m.shape_row=2;assert(run(0,2)==VIREO_RESULT_DATABASE);stop();
    }
    start();m.total=5;m.over_limit=true;assert(run(0,2)==VIREO_RESULT_DATABASE);stop();
    start();m.ids[0]=UINT64_MAX-1;m.ids[1]=UINT64_MAX;m.total=2;assert(run(0,1)==VIREO_OK && page.next_after_id==UINT64_MAX-1);stop();
    start();assert(run(UINT64_MAX,64)==VIREO_OK && page.count==0);stop();
    start();assert(run(100,2)==VIREO_OK && page.count==2 && page.nodes[0].id==101 && !page.has_more);stop();
    for(unsigned reason=0;reason<5;++reason) {
        start();m.missing_user=reason==0;m.missing_session=reason==1;m.disabled=reason==2;m.revoked=reason==3;m.wrong_session=reason==4;
        assert(run(0,2)==VIREO_RESULT_NOT_FOUND && report.issue==VIREO_MYSQL_NODE_AUTH_REJECTED && !m.prepared[PARENT]);stop();
    }
    for(unsigned kind=0;kind<2;++kind) {
        for(unsigned expired=0;expired<2;++expired) {
            start();m.no_parent=kind==0;m.file_parent=kind==1;m.now=expired ? 3000 : 2000;
            assert(run(0,2)==VIREO_RESULT_NOT_FOUND && !m.prepared[CHILDREN]);
            assert(report.issue==(expired ? VIREO_MYSQL_NODE_AUTH_REJECTED : VIREO_MYSQL_NODE_NOT_FOUND));stop();
        }
    }
    const uint64_t times[]={999,1000,2999,3000};
    for(size_t i=0;i<4;++i) { start();m.now=times[i];bool valid=m.now>=1000 && m.now<3000;assert(run(0,2)==(valid ? VIREO_OK : VIREO_RESULT_NOT_FOUND));stop(); }
    start();m.advance_time=true;assert(run(0,2)==VIREO_RESULT_NOT_FOUND && m.now==3000);stop();
    for(unsigned mode=1;mode<=5;++mode) { start();m.utc_mode=mode;assert(run(0,2)==(mode==1 ? VIREO_RESULT_IO : (mode==4 ? VIREO_RESULT_OVERFLOW : VIREO_RESULT_INTERNAL)));stop(); }
    start();m.keep_close=true;assert(run(0,2)==VIREO_RESULT_BUSY && report.cleanup_pending);size_t calls=m.calls;assert(run(0,2)==VIREO_RESULT_BUSY && m.calls==calls);stop();
    start();m.keep_release=true;assert(run(0,2)==VIREO_RESULT_INTERNAL && report.cleanup_pending && report.rollback_confirmed);stop();
    start();m.consumed_release=true;assert(run(0,2)==VIREO_RESULT_DATABASE && !report.cleanup_pending);stop();
    start();m.partial_acquire=true;m.fail_at=2;assert(run(0,2)==VIREO_RESULT_INTERNAL && !m.leases && m.disposition==VIREO_MYSQL_POOL_DISCARD);stop();
    start();m.borrow_fail=true;assert(run(0,2)==VIREO_RESULT_INTERNAL && !m.leases);stop();
    start();m.shape=2;m.shape_row=2;m.keep_release=true;assert(run(0,2)==VIREO_RESULT_DATABASE && error.stage==VIREO_MYSQL_NODE_STAGE_NODE && error.cleanup_result==VIREO_RESULT_INTERNAL);stop();
    start();assert(run(0,0)==VIREO_RESULT_RANGE && !m.calls);assert(run(0,65)==VIREO_RESULT_RANGE && !m.calls);
    vireo_mysql_node_list_query_t q={0,0,2};
    CHECK(vireo_mysql_node_repository_list_children(repo,&actor,&q,0,&page,&report,NULL),VIREO_RESULT_INVALID_ARGUMENT);q.directory_id=22;
    CHECK(vireo_mysql_node_repository_list_children(repo,&actor,&q,60001,&page,&report,NULL),VIREO_RESULT_RANGE);
    CHECK(vireo_mysql_node_repository_list_children(repo,&actor,NULL,0,&page,&report,NULL),VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_mysql_node_repository_list_children(repo,NULL,&q,0,&page,&report,NULL),VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_mysql_node_repository_list_children(repo,&actor,&q,0,NULL,&report,NULL),VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_mysql_node_repository_list_children(repo,&actor,&q,0,&page,NULL,NULL),VIREO_RESULT_INVALID_ARGUMENT);assert(!m.calls);stop();
    printf("PASS %zu list scenarios; %zu individually failed resource calls; all 64 page sizes, lookahead corruption, cleanup and UTC\n",scenarios,normal_calls);return 0;
}
