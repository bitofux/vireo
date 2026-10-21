/* PROJECT : VIREO; FILE : test_mysql_node_repository.c;
 * AUTHOR : bitofux; DATE : 2026-10-21; BRIEF : 锁序、行形状、UTC及逐资源故障闭环。 */
#define _POSIX_C_SOURCE 200809L
#include "mysql_node_repository_internal.h"
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(call,want) do { errno=EDOM; vireo_result_t got_=(call); if(got_!=(want)) { fprintf(stderr,"line %d got %d want %d\n",__LINE__,(int)got_,(int)(want)); abort(); } assert(errno==EDOM); } while(0)
enum op { BEGIN, USER, SESSION, NODE, ROLLBACK };
struct statement { enum op op; unsigned fetches; };
static struct {
    size_t calls, fail_at, allocations, statements, leases, utc_calls, prepared[5];
    bool alloc_fail, keep_close, keep_release, consumed_release, acquire_partial, borrow_fail;
    bool root, missing_node, missing_user, missing_session, disabled, revoked, wrong_owner, duplicate;
    unsigned shape, utc_mode;
    uint64_t now;
    enum op last;
    vireo_mysql_pool_disposition_t disposition;
} m;
static _Alignas(max_align_t) unsigned char thread_storage, pool_storage, connection_storage;
static vireo_mysql_thread_t *thread;
static vireo_mysql_pool_t *pool;
static vireo_mysql_node_repository_t *repo;
static vireo_mysql_node_actor_t actor={7,51};
static vireo_mysql_node_value_t value;
static vireo_mysql_node_report_t report;
static vireo_mysql_node_error_t error;
static size_t scenarios;
static bool fail(void) { return ++m.calls==m.fail_at; }
static void *allocate(size_t n) { if(m.alloc_fail) { return NULL; } void *p=malloc(n);assert(p);++m.allocations;return p; }
static void free_memory(void *p) { assert(m.allocations==1);--m.allocations;free(p); }
static vireo_result_t acquire(vireo_mysql_thread_t *t,vireo_mysql_pool_t *p,uint32_t wait,
    vireo_mysql_lease_t *lease,vireo_mysql_pool_acquisition_t *out,vireo_mysql_pool_error_t *e)
{
    assert(t==thread && p==pool && wait<=60000 && !lease->owner);*e=(vireo_mysql_pool_error_t){0};*out=(vireo_mysql_pool_acquisition_t){0};
    bool failed=fail();if(failed && !m.acquire_partial) { return VIREO_RESULT_BUSY; }
    *lease=(vireo_mysql_lease_t){.owner=pool,.generation=1};out->acquired=true;++m.leases;
    return failed ? VIREO_RESULT_INTERNAL : VIREO_OK;
}
static vireo_result_t borrow(vireo_mysql_thread_t *t,vireo_mysql_pool_t *p,const vireo_mysql_lease_t *lease,vireo_mysql_connection_t **out)
{
    assert(t==thread && p==pool && lease->owner==pool);if(fail() || m.borrow_fail) { return VIREO_RESULT_INTERNAL; }
    *out=(vireo_mysql_connection_t *)&connection_storage;return VIREO_OK;
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
    assert(strstr(sql,"FOR SHARE") && !strstr(sql,"LIMIT"));
    if(strstr(sql,"FROM users")) { assert(!m.prepared[SESSION] && !m.prepared[NODE]);return USER; }
    if(strstr(sql,"FROM sessions")) { assert(m.prepared[USER]==1 && !m.prepared[NODE]);return SESSION; }
    assert(strstr(sql,"FROM file_nodes WHERE owner_id=? AND ") && strstr(sql,"state=2"));
    assert(m.prepared[SESSION]==1);m.root=strstr(sql,"parent_id IS NULL")!=NULL;return NODE;
}
static vireo_result_t prepare(vireo_mysql_thread_t *t,vireo_mysql_connection_t *c,const char *sql,size_t n,
    const vireo_mysql_statement_limits_t *limits,vireo_mysql_statement_t **out,vireo_mysql_error_t *e)
{
    assert(t==thread && c==(void *)&connection_storage && strlen(sql)==n && !*out && !m.statements);
    assert(limits->max_parameters==4 && limits->max_columns==11 && limits->max_cell_bytes==255);
    *e=(vireo_mysql_error_t){0};enum op op=identify(sql);++m.prepared[op];m.last=op;
    if(fail()) { e->mysql_code=2013;return VIREO_RESULT_DATABASE; }
    struct statement *s=malloc(sizeof(*s));assert(s);*s=(struct statement){.op=op};*out=(void *)s;++m.statements;return VIREO_OK;
}
static vireo_result_t execute(vireo_mysql_thread_t *t,vireo_mysql_statement_t *statement,
    const vireo_mysql_parameter_t *p,size_t n,vireo_mysql_execution_t *out,vireo_mysql_error_t *e)
{
    struct statement *s=(void *)statement;assert(t==thread);*e=(vireo_mysql_error_t){0};
    *out=(vireo_mysql_execution_t){.execution_started=true};
    if(s->op==BEGIN || s->op==ROLLBACK) { assert(!p && !n); }
    else {
        assert(n==(s->op==NODE && !m.root ? 2u : 1u) && p[0].kind==VIREO_MYSQL_PARAMETER_U64);
        assert(p[0].value.u64==(s->op==SESSION ? 51u : 7u));
        if(n==2) { assert(p[1].kind==VIREO_MYSQL_PARAMETER_U64 && p[1].value.u64==22); }
        out->has_result=true;
    }
    if(fail()) { e->mysql_code=2013;return VIREO_RESULT_DATABASE; }
    if(m.shape==1 && s->op==NODE) { out->has_result=false; }
    return VIREO_OK;
}
static vireo_result_t fetch(vireo_mysql_thread_t *t,vireo_mysql_statement_t *statement,vireo_mysql_fetch_outcome_t *out,vireo_mysql_error_t *e)
{
    assert(t==thread);struct statement *s=(void *)statement;*e=(vireo_mysql_error_t){0};
    if(fail()) { e->mysql_code=2013;return VIREO_RESULT_DATABASE; }
    bool missing=(s->op==USER && m.missing_user)||(s->op==SESSION && m.missing_session)||(s->op==NODE && m.missing_node);
    *out=missing || s->fetches++>0 ? VIREO_MYSQL_FETCH_DONE : VIREO_MYSQL_FETCH_ROW;
    if(m.duplicate && s->op==NODE && s->fetches==2) { *out=VIREO_MYSQL_FETCH_ROW; }
    return VIREO_OK;
}
static vireo_result_t column(vireo_mysql_thread_t *t,const vireo_mysql_statement_t *statement,size_t i,vireo_mysql_cell_view_t *out)
{
    assert(t==thread);const struct statement *s=(const void *)statement;
    static const char *const user[]={"7","1"};
    static const char *const session[]={"51","7","1","1000","3000",NULL,"1000"};
    static const char *const node[]={"22","7",NULL,"","1","2",NULL,"0","1000","1000",NULL};
    if(fail()) { return VIREO_RESULT_DATABASE; }
    const char *v=s->op==USER ? user[i] : (s->op==SESSION ? session[i] : node[i]);
    if(s->op==USER && i==1 && m.disabled) { v="2"; }
    if(s->op==SESSION && m.revoked) { if(i==2) { v="2"; } if(i==5) { v="1000"; } }
    if(s->op==SESSION && i==1 && m.wrong_owner) { v="8"; }
    if(s->op==USER && m.shape==19 && i==1) { v="3"; }
    if(s->op==SESSION) {
        if(m.shape==20 && i==2) { v="3"; }
        if(m.shape==21 && i==4) { v="1000"; }
        if(m.shape==22 && i==6) { v="3001"; }
        if(m.shape==23) { if(i==2) { v="2"; } if(i==5) { v="999"; } }
        if(m.shape==24 && i==5) { v="1000"; }
    }
    if(s->op==NODE) {
        if(m.shape==2 && i==0) { v="18446744073709551616"; }
        if(m.shape==3 && i==1) { v="8"; }
        if(m.shape==4 && i==10) { v="1000"; }
        if(m.shape==5 && i==8) { v="2000"; }
        if(m.shape==6 && i==4) { v="2"; }
        if(m.shape==7 && i==5) { v="1"; }
        if(m.shape==8 && i==7) { v="-1"; }
        if(m.shape>=9) {
            if(i==2) { v="1"; } if(i==3) { v="ok"; }
            if(m.shape==9 && i==3) { v=".."; }
            if(m.shape==10 && i==3) { v="a/b"; }
            if(m.shape==11 && i==3) { v="."; }
            if(m.shape==12 && i==3) { v=""; }
        }
    }
    if(s->op==NODE) {
        if(m.shape==15 && i==2) { v=NULL; }
        if(m.shape==16 && i==6) { v="bad-hash"; }
        if(m.shape==25 && i==0) { v=NULL; }
    }
    *out=(vireo_mysql_cell_view_t){.data=(const unsigned char *)v,.length=v ? strlen(v) : 0,.is_null=v==NULL};
    if(s->op==NODE && i==3 && m.shape==14) { out->length=256; }
    if(s->op==NODE && i==3 && m.shape==18) {
        static const unsigned char bad_name[3]={'a',0,'b'};out->data=bad_name;out->length=3;
    }
    return VIREO_OK;
}
static vireo_result_t close_statement(vireo_mysql_thread_t *t,vireo_mysql_statement_t **out,vireo_mysql_error_t *e)
{
    assert(t==thread && *out && m.statements==1);*e=(vireo_mysql_error_t){0};
    bool failed=fail();if(m.keep_close) { return VIREO_RESULT_BUSY; }
    free(*out);*out=NULL;--m.statements;return failed ? VIREO_RESULT_DATABASE : VIREO_OK;
}
static int utc(struct timespec *out)
{
    assert(m.prepared[NODE] && !m.statements);++m.utc_calls;
    if(fail() || m.utc_mode==1) { errno=EIO;return -1; }
    *out=(struct timespec){.tv_sec=(time_t)(m.now/1000),.tv_nsec=(long)(m.now%1000)*1000000L};
    if(m.utc_mode==2) { out->tv_nsec=1000000000L; }
    if(m.utc_mode==3) { out->tv_sec=-1; }
    if(m.utc_mode==4) { out->tv_sec=(time_t)INT64_MAX; }
    if(m.utc_mode==5) { return 7; }return 0;
}
static const vireo_mysql_node_ops_t ops={allocate,free_memory,acquire,borrow,release,prepare,execute,fetch,column,close_statement,utc};
static void start(void)
{
    assert(!repo && !m.allocations && !m.statements && !m.leases);memset(&m,0,sizeof(m));m.now=2000;
    CHECK(vireo_mysql_node_repository_create_with_ops(thread,pool,&repo,&error,&ops),VIREO_OK);++scenarios;
}
static void stop(void)
{
    m.keep_close=false;m.keep_release=false;m.consumed_release=false;m.fail_at=0;
    CHECK(vireo_mysql_node_repository_destroy(&repo,NULL),VIREO_OK);assert(!repo && !m.allocations && !m.statements && !m.leases);
}
static vireo_result_t run(bool root)
{
    memset(&value,0xa5,sizeof(value));errno=EDOM;
    vireo_result_t rc=root ? vireo_mysql_node_repository_get_root(repo,&actor,0,&value,&report,&error) :
        vireo_mysql_node_repository_stat(repo,&actor,22,0,&value,&report,&error);
    assert(errno==EDOM && report.found==(rc==VIREO_OK));
    if(rc!=VIREO_OK) { const unsigned char *p=(const void *)&value;for(size_t i=0;i<sizeof(value);++i) { assert(p[i]==0); } }
    return rc;
}
static void *wrong_thread(void *unused)
{
    (void)unused;vireo_mysql_node_value_t out;vireo_mysql_node_report_t r;
    CHECK(vireo_mysql_node_repository_get_root(repo,&actor,0,&out,&r,NULL),VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_mysql_node_repository_destroy(&repo,NULL),VIREO_RESULT_INVALID_ARGUMENT);return NULL;
}
int main(void)
{
    thread=(void *)&thread_storage;pool=(void *)&pool_storage;
    start();assert(run(true)==VIREO_OK && value.id==22 && value.owner_id==7 && !value.has_parent);
    assert(report.rollback_confirmed && !report.cleanup_pending && m.utc_calls==1 && m.disposition==VIREO_MYSQL_POOL_RECYCLE);
    size_t normal_calls=m.calls;pthread_t other;assert(!pthread_create(&other,NULL,wrong_thread,NULL) && !pthread_join(other,NULL));stop();
    /* 每个底层调用各失败一次，检查不发布值且所有子owner最终可消费。 */
    for(size_t i=1;i<=normal_calls;++i) { start();m.fail_at=i;assert(run(false)!=VIREO_OK);stop(); }
    for(unsigned int shape=1;shape<=25;++shape) {
        if(shape==13 || shape==17) { continue; }
        start();m.shape=shape;assert(run(shape<9)==VIREO_RESULT_DATABASE);stop();
    }
    start();m.shape=13;assert(run(false)==VIREO_OK && value.has_parent && value.name_length==2);stop();
    start();m.missing_node=true;assert(run(false)==VIREO_RESULT_NOT_FOUND && report.issue==VIREO_MYSQL_NODE_NOT_FOUND);stop();
    start();m.missing_node=true;assert(run(true)==VIREO_RESULT_DATABASE && report.issue==VIREO_MYSQL_NODE_ROOT_INVARIANT);stop();
    for(unsigned int reason=0;reason<5;++reason) {
        start();m.missing_user=reason==0;m.missing_session=reason==1;m.disabled=reason==2;m.revoked=reason==3;m.wrong_owner=reason==4;
        assert(run(true)==VIREO_RESULT_NOT_FOUND && report.issue==VIREO_MYSQL_NODE_AUTH_REJECTED && !m.prepared[NODE]);stop();
    }
    for(uint64_t now=999;now<=3000;now+=1) {
        if(now!=999 && now!=1000 && now!=2999 && now!=3000) { continue; }
        start();m.now=now;m.missing_node=true;assert(run(false)==VIREO_RESULT_NOT_FOUND);
        assert(report.issue==(now<1000 || now>=3000 ? VIREO_MYSQL_NODE_AUTH_REJECTED : VIREO_MYSQL_NODE_NOT_FOUND));stop();
    }
    for(unsigned int mode=1;mode<=5;++mode) {
        start();m.utc_mode=mode;assert(run(true)==(mode==1 ? VIREO_RESULT_IO : (mode==4 ? VIREO_RESULT_OVERFLOW : VIREO_RESULT_INTERNAL)));stop();
    }
    start();m.duplicate=true;assert(run(true)==VIREO_RESULT_DATABASE);stop();
    start();m.keep_close=true;assert(run(true)==VIREO_RESULT_BUSY && report.cleanup_pending);
    size_t calls=m.calls;assert(run(true)==VIREO_RESULT_BUSY && m.calls==calls);stop();
    start();m.keep_release=true;assert(run(true)==VIREO_RESULT_INTERNAL && report.cleanup_pending && report.rollback_confirmed);
    assert(run(false)==VIREO_RESULT_BUSY);stop();
    start();m.consumed_release=true;assert(run(true)==VIREO_RESULT_DATABASE && !report.cleanup_pending);stop();
    start();m.acquire_partial=true;m.fail_at=1;assert(run(true)==VIREO_RESULT_INTERNAL && !m.leases && m.disposition==VIREO_MYSQL_POOL_DISCARD);stop();
    start();m.borrow_fail=true;assert(run(true)==VIREO_RESULT_INTERNAL && !m.leases);stop();
    start();m.fail_at=11;m.keep_release=true;assert(run(true)==VIREO_RESULT_DATABASE && error.stage==VIREO_MYSQL_NODE_STAGE_USER);
    assert(error.cleanup_result==VIREO_RESULT_INTERNAL && report.cleanup_pending);stop();
    start();vireo_mysql_node_repository_t *saved_repo=repo;
    CHECK(vireo_mysql_node_repository_create(thread,pool,&repo,NULL),VIREO_RESULT_INVALID_ARGUMENT);assert(repo==saved_repo);
    CHECK(vireo_mysql_node_repository_get_root(repo,&actor,0,NULL,&report,NULL),VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_mysql_node_repository_get_root(repo,&actor,0,&value,NULL,NULL),VIREO_RESULT_INVALID_ARGUMENT);
    vireo_mysql_node_actor_t bad={0};CHECK(vireo_mysql_node_repository_get_root(repo,&bad,0,&value,&report,NULL),VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_mysql_node_repository_stat(repo,&actor,0,0,&value,&report,NULL),VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_mysql_node_repository_get_root(repo,&actor,60001,&value,&report,NULL),VIREO_RESULT_RANGE);assert(!m.calls);stop();
    CHECK(vireo_mysql_node_repository_create_with_ops(NULL,pool,&repo,NULL,&ops),VIREO_RESULT_INVALID_ARGUMENT);
    vireo_mysql_node_ops_t bad_ops=ops;bad_ops.utc=NULL;
    CHECK(vireo_mysql_node_repository_create_with_ops(thread,pool,&repo,NULL,&bad_ops),VIREO_RESULT_INVALID_ARGUMENT);
    m.alloc_fail=true;CHECK(vireo_mysql_node_repository_create_with_ops(thread,pool,&repo,&error,&ops),VIREO_RESULT_NO_MEMORY);assert(!repo);
    CHECK(vireo_mysql_node_repository_destroy(&repo,NULL),VIREO_OK);
    printf("PASS %zu node repository scenarios; %zu resource-call fault points, lock-order/owner predicates, UTC, output clearing and residual ownership\n",scenarios,normal_calls);
    return 0;
}
