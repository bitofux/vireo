/* PROJECT : VIREO; FILE : test_auth_worker.c; AUTHOR : bitofux; DATE : 2026-10-20.
 * 当前模块边界注入：提交事实、残留owner、同线程恢复及严格防重。 */
#define _POSIX_C_SOURCE 200809L
#include "auth_task_test_support.h"
#include "auth_worker_internal.h"
#include <pthread.h>
#include <stddef.h>

typedef struct model {
    max_align_t guard, repo;
    unsigned attached, created, captured, executed, published, destroyed, detached, completion_destroyed, freed;
    unsigned fail_repository, fail_detach, fail_completion;
    bool consumed_repository, allocation_fail, notify_fail;
    vireo_result_t attach_rc, create_rc, capture_rc, work_rc;
    vireo_auth_commit_t commit;
    size_t allocation_size;
    vireo_auth_worker_resources_t resources;
    vireo_auth_worker_options_t options;
} model_t;
static void *allocate(void *p,size_t n)
{ model_t *m=p; m->allocation_size=n; return m->allocation_fail?NULL:malloc(n); }
static void release(void *p,void *allocation)
{
    model_t *m=p; unsigned char const *bytes=allocation;
    for(size_t i=0;i<m->allocation_size;++i) assert(bytes[i]==0);
    ++m->freed; free(allocation);
}
static vireo_result_t attach(void *p,vireo_mysql_runtime_t *r,vireo_mysql_thread_t **out,vireo_mysql_error_t *e)
{
    model_t *m=p; assert(r==m->resources.runtime && !*out); ++m->attached; (void)e;
    if(m->attach_rc==VIREO_OK) *out=(vireo_mysql_thread_t *)&m->guard;
    return m->attach_rc;
}
static vireo_result_t create(void *p,vireo_mysql_thread_t *t,vireo_mysql_pool_t *pool,
    vireo_password_policy_t const *policy,vireo_mysql_user_repository_t **out,vireo_mysql_user_repository_error_t *e)
{
    model_t *m=p; assert(t==(vireo_mysql_thread_t *)&m->guard && pool==m->resources.database && !*out);
    assert(policy->create_iterations==3); ++m->created; (void)e;
    if(m->create_rc==VIREO_OK) *out=(vireo_mysql_user_repository_t *)&m->repo;
    return m->create_rc;
}
static vireo_result_t capture(void *p,vireo_task_t const *task,uint64_t received,uint64_t lifetime,vireo_auth_task_options_t const *options,
    vireo_auth_task_context_t *out,vireo_auth_context_error_t *e)
{
    (void)options; model_t *m=p; ++m->captured; assert(received==90 && lifetime==60000); (void)e;
    if(m->capture_rc!=VIREO_OK) return m->capture_rc;
    vireo_task_info_t info; CHECK(vireo_task_inspect(task,&info),VIREO_OK);
    *out=task_context(7,1,info.metadata.operation==101); out->metadata=info.metadata;
    return VIREO_OK;
}
static vireo_result_t execute(void *p,vireo_task_t const *task,vireo_auth_task_context_t const *context,
    vireo_auth_task_options_t const *o,vireo_mysql_user_repository_t *r,vireo_auth_password_gate_t *g,
    vireo_auth_login_verifier_t const *v,vireo_auth_task_result_t *out)
{
    model_t *m=p; ++m->executed; assert(o->login_operation==101 && r==(vireo_mysql_user_repository_t *)&m->repo);
    assert(g==m->resources.gate && v==m->resources.verifier && task && context->request_id[0]);
    bool login=context->metadata.operation==101;
    *out=(vireo_auth_task_result_t){.stage=VIREO_AUTH_TASK_SERVICE,.result=m->work_rc,
        .metadata=context->metadata,.command=login?VIREO_COMMAND_LOGIN:VIREO_COMMAND_REGISTER};
    if(login) {
        out->login.transaction.commit=m->commit==VIREO_AUTH_COMMITTED?VIREO_MYSQL_LOGIN_COMMITTED:
            m->commit==VIREO_AUTH_COMMIT_UNKNOWN?VIREO_MYSQL_LOGIN_UNKNOWN:VIREO_MYSQL_LOGIN_NOT_COMMITTED;
        out->login.lookup.cleanup_pending=m->fail_repository!=0;
        if(m->commit==VIREO_AUTH_COMMITTED) {
            out->login.user_id=2; out->login.transaction.session_id=3; out->login.transaction.audit_id=4;
            out->login.issued_at_ms=5; out->login.expires_at_ms=60005; memset(out->login.token.bytes,0x91,32);
        }
    } else {
        out->registration.commit=m->commit==VIREO_AUTH_COMMITTED?VIREO_MYSQL_REGISTRATION_COMMITTED:
            m->commit==VIREO_AUTH_COMMIT_UNKNOWN?VIREO_MYSQL_REGISTRATION_UNKNOWN:VIREO_MYSQL_REGISTRATION_NOT_COMMITTED;
        out->registration.cleanup_pending=m->fail_repository!=0;
        if(m->commit==VIREO_AUTH_COMMITTED) {
            out->registration.user_id=2; out->registration.root_node_id=3; out->registration.audit_id=4;
        }
    }
    return m->work_rc;
}
static vireo_result_t destroy(void *p,vireo_mysql_user_repository_t **r,vireo_mysql_user_repository_error_t *e)
{
    model_t *m=p; ++m->destroyed; assert(*r==(vireo_mysql_user_repository_t *)&m->repo); (void)e;
    if(m->fail_repository) { --m->fail_repository; if(m->consumed_repository) *r=NULL; return VIREO_RESULT_DATABASE; }
    *r=NULL; return VIREO_OK;
}
static vireo_result_t detach(void *p,vireo_mysql_thread_t **t)
{
    model_t *m=p; ++m->detached; assert(*t==(vireo_mysql_thread_t *)&m->guard);
    if(m->fail_detach) { --m->fail_detach; return VIREO_RESULT_INTERNAL; }
    *t=NULL; return VIREO_OK;
}
static vireo_result_t publish(void *p,vireo_task_t const *t,vireo_auth_task_result_t const *result,size_t budget,
    vireo_completion_queue_t *q,vireo_notifier_t *n,vireo_completion_t **remaining,vireo_auth_completion_publish_report_t *out)
{
    model_t *m=p; ++m->published;
    vireo_result_t rc=vireo_auth_completion_publish(t,result,budget,q,n,remaining,out);
    if(m->notify_fail && out->publication.completion_transferred) {
        out->publication.notify_result=VIREO_RESULT_IO; out->publication.stage=VIREO_COMPLETION_PUBLISH_NOTIFY;
        return VIREO_RESULT_IO;
    }
    return rc;
}
static vireo_result_t completion_destroy(void *p,vireo_completion_t **owner)
{
    model_t *m=p; ++m->completion_destroyed;
    if(m->fail_completion) { --m->fail_completion; return VIREO_RESULT_INTERNAL; }
    return vireo_completion_destroy(owner);
}
static vireo_auth_worker_ops_t operations(model_t *m)
{ return (vireo_auth_worker_ops_t){m,allocate,release,attach,create,capture,execute,destroy,detach,publish,completion_destroy}; }
static void setup(model_t *m,bool prepared)
{
    *m=(model_t){.commit=VIREO_AUTH_COMMITTED};
    /* 只将不解引用的存活对齐地址当作本层借用依赖标记，queue/notifier使用真实公开对象。 */
    m->resources.runtime=(vireo_mysql_runtime_t *)&m->guard;
    m->resources.database=(vireo_mysql_pool_t *)&m->repo;
    m->resources.gate=(vireo_auth_password_gate_t *)&m->guard;
    m->resources.verifier=(vireo_auth_login_verifier_t *)&m->repo;
    vireo_completion_queue_options_t const qo={1,65536}; vireo_notifier_options_t const no={4096};
    CHECK(vireo_completion_queue_create(&qo,&m->resources.queue),VIREO_OK);
    if(prepared) CHECK(vireo_completion_queue_prepare_wait(m->resources.queue),VIREO_OK);
    CHECK(vireo_notifier_create(&no,&m->resources.notifier,NULL),VIREO_OK);
    uint64_t now=0;CHECK(vireo_clock_monotonic_now(&now,NULL),VIREO_OK);
    vireo_auth_failure_audit_options_t const ao={256,65536,8,UINT64_C(1000000000)};
    CHECK(vireo_auth_failure_audit_create(&ao,now,&m->resources.audit),VIREO_OK);
    m->options=(vireo_auth_worker_options_t){.execution={100,101,5000,102,103},.password=VIREO_PASSWORD_POLICY_DEFAULT,
        .request_timeout_ns=10,.session_lifetime_ms=60000,.completion_allocation_budget=4096,.max_memory_bytes=65536};
}
static vireo_auth_worker_t *worker(model_t *m)
{
    vireo_auth_worker_t *w=NULL; vireo_auth_worker_ops_t const ops=operations(m);
    CHECK(vireo_auth_worker_create_with(&m->resources,&m->options,&w,&ops),VIREO_OK); return w;
}
static vireo_task_t *task(bool login,unsigned mode)
{
    unsigned char bytes[156]; size_t n=frame(bytes,login,7,false);
    vireo_task_metadata_t metadata=task_context(7,1,login).metadata;
    if(mode==1) bytes[0]^=1;
    if(mode==2) metadata.operation=99;
    if(mode==3) ++metadata.route.request_sequence;
    if(mode==4) metadata.deadline_ns=9;
    vireo_task_t *t=NULL; CHECK(vireo_task_create_copy(metadata,mode==5?NULL:bytes,mode==5?0:n,4096,&t),VIREO_OK);
    CHECK(vireo_secure_clear(bytes,sizeof(bytes)),VIREO_OK); return t;
}
static void outcome(model_t *m,vireo_auth_commit_t commit,vireo_result_t result,vireo_status_t status)
{
    vireo_completion_t *c=NULL; vireo_completion_queue_transfer_report_t moved;
    CHECK(vireo_completion_queue_try_pop(m->resources.queue,&c,&moved),VIREO_OK); assert(c && moved.transferred);
    vireo_auth_completion_outcome_t out={0}; CHECK(vireo_auth_completion_decode(c,&out),VIREO_OK);
    assert(out.commit==commit && out.metadata.result==result && out.metadata.suggested_status==status);
    if(commit==VIREO_AUTH_COMMITTED && out.command==VIREO_COMMAND_LOGIN) assert(out.token.bytes[31]==0x91);
    CHECK(vireo_completion_destroy(&c),VIREO_OK); CHECK(vireo_auth_completion_outcome_clear(&out),VIREO_OK);
    CHECK(vireo_completion_queue_try_pop(m->resources.queue,&c,&moved),VIREO_RESULT_NOT_FOUND); assert(!c);
}
static void teardown(model_t *m)
{
    CHECK(vireo_completion_queue_destroy(&m->resources.queue),VIREO_OK);
    CHECK(vireo_notifier_destroy(&m->resources.notifier,NULL),VIREO_OK);
    CHECK(vireo_auth_failure_audit_close(m->resources.audit,VIREO_AUTH_FAILURE_STOP),VIREO_OK);
    CHECK(vireo_auth_failure_audit_destroy(&m->resources.audit),VIREO_OK);
}
static void invalid(void)
{
    model_t m; setup(&m,true); vireo_auth_worker_ops_t ops=operations(&m); vireo_auth_worker_t *w=NULL;
    CHECK(vireo_auth_worker_create(NULL,&m.options,&w),VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_auth_worker_create(&m.resources,NULL,&w),VIREO_RESULT_INVALID_ARGUMENT);
    for(unsigned i=0;i<10;++i) {
        vireo_auth_worker_options_t o=m.options;
        switch(i) {
        case 0:o.execution.login_operation=100;break;
        case 1:o.request_timeout_ns=0;break;
        case 2:o.session_lifetime_ms=0;break;
        case 3:o.completion_allocation_budget=0;break;
        case 4:o.max_memory_bytes=0;break;
        case 5:o.execution.pool_timeout_ms=60001;break;
        case 6:o.max_memory_bytes=1;break;
        case 7:o.max_memory_bytes=67108865;break;
        case 8:o.completion_allocation_budget=VIREO_COMPLETION_MAX_ALLOCATION_BYTES+1;break;
        default:o.execution.register_operation=0;break;
        }
        CHECK(vireo_auth_worker_create_with(&m.resources,&o,&w,&ops),i>=5 && i<=8?VIREO_RESULT_RANGE:VIREO_RESULT_INVALID_ARGUMENT);
        assert(!w);
    }
    m.allocation_fail=true;
    CHECK(vireo_auth_worker_create_with(&m.resources,&m.options,&w,&ops),VIREO_RESULT_NO_MEMORY); assert(!w);
    m.allocation_fail=false; w=worker(&m);
    CHECK(vireo_auth_worker_create_with(&m.resources,&m.options,&w,&ops),VIREO_RESULT_INVALID_ARGUMENT);
    vireo_auth_worker_report_t p; CHECK(vireo_auth_worker_run(w,NULL,&p),VIREO_RESULT_INVALID_ARGUMENT); assert(!p.attempted);
    vireo_auth_worker_cleanup_report_t cleanup;
    CHECK(vireo_auth_worker_destroy(&w,&cleanup),VIREO_OK); assert(!w && m.freed==1);
    CHECK(vireo_auth_worker_destroy(&w,&cleanup),VIREO_OK);
    CHECK(vireo_auth_worker_destroy(NULL,&cleanup),VIREO_RESULT_INVALID_ARGUMENT);
    teardown(&m);
}
static void boundaries(void)
{
    for(unsigned i=1;i<=5;++i) {
        model_t m; setup(&m,true); vireo_auth_worker_t *w=worker(&m); vireo_task_t *t=task(true,i);
        vireo_auth_worker_report_t p; vireo_result_t rc=i==1 || i==5?VIREO_RESULT_PROTOCOL:i==4?VIREO_RESULT_RANGE:VIREO_RESULT_INVALID_ARGUMENT;
        CHECK(vireo_auth_worker_run(w,t,&p),rc); assert(p.attempted && !p.task_validated && !m.attached && !m.executed && !m.published);
        CHECK(vireo_auth_worker_run(w,t,&p),VIREO_RESULT_BUSY); assert(!m.attached);
        CHECK(vireo_task_destroy(&t),VIREO_OK); vireo_auth_worker_cleanup_report_t c;
        CHECK(vireo_auth_worker_destroy(&w,&c),VIREO_OK); assert(!w); teardown(&m);
    }
}
static void failures(void)
{
    for(unsigned i=0;i<13;++i) {
        model_t m; setup(&m,i!=9); bool login=i!=12;
        vireo_result_t expected=VIREO_OK,work_rc=VIREO_OK;
        vireo_auth_commit_t commit=VIREO_AUTH_COMMITTED; vireo_status_t status=VIREO_STATUS_OK;
        switch(i) {
        case 0:m.attach_rc=VIREO_RESULT_NO_MEMORY;expected=work_rc=m.attach_rc;commit=VIREO_AUTH_NOT_COMMITTED;status=VIREO_STATUS_INTERNAL_ERROR;break;
        case 1:m.create_rc=VIREO_RESULT_NO_MEMORY;expected=work_rc=m.create_rc;commit=VIREO_AUTH_NOT_COMMITTED;status=VIREO_STATUS_INTERNAL_ERROR;break;
        case 2:m.capture_rc=VIREO_RESULT_IO;expected=work_rc=m.capture_rc;commit=VIREO_AUTH_NOT_COMMITTED;status=VIREO_STATUS_INTERNAL_ERROR;break;
        case 3:m.work_rc=VIREO_RESULT_NOT_FOUND;m.commit=VIREO_AUTH_NOT_COMMITTED;expected=work_rc=m.work_rc;commit=m.commit;status=VIREO_STATUS_AUTHENTICATION_FAILED;break;
        case 4:m.work_rc=VIREO_RESULT_DATABASE;m.commit=VIREO_AUTH_COMMIT_UNKNOWN;expected=work_rc=m.work_rc;commit=m.commit;status=VIREO_STATUS_INTERNAL_ERROR;break;
        case 5:m.work_rc=VIREO_RESULT_DATABASE;m.fail_repository=2;expected=work_rc=m.work_rc;break;
        case 6:m.fail_repository=1;m.consumed_repository=true;expected=VIREO_RESULT_DATABASE;break;
        case 7:m.fail_detach=2;expected=VIREO_RESULT_INTERNAL;break;
        case 8:m.notify_fail=true;expected=VIREO_RESULT_IO;break;
        case 9:expected=VIREO_RESULT_NOT_FOUND;m.fail_completion=1;break;
        case 10: { vireo_completion_queue_close_report_t c; CHECK(vireo_completion_queue_close(m.resources.queue,&c),VIREO_OK);expected=VIREO_RESULT_CANCELLED;break; }
        case 11:m.options.completion_allocation_budget=1;expected=VIREO_RESULT_RANGE;break;
        default:m.fail_repository=2;expected=VIREO_RESULT_DATABASE;break;
        }
        vireo_auth_worker_t *w=worker(&m); vireo_task_t *t=task(login,0); vireo_auth_worker_report_t p;
        CHECK(vireo_auth_worker_run(w,t,&p),expected);
        assert(p.task_validated && p.work_result==work_rc && p.publish_called && m.published==1);
        if(i>=9 && i<=11) assert(!p.publication.publication.completion_transferred);
        else {
            assert(p.publication.publication.completion_transferred);
            outcome(&m,commit,work_rc,status);
        }
        assert(m.executed==(i<=2?0u:1u));
        vireo_auth_failure_audit_info_t audit_info;
        CHECK(vireo_auth_failure_audit_inspect(m.resources.audit,&audit_info),VIREO_OK);
        assert(audit_info.queued==(i==3?1U:0U));
        unsigned destroyed=m.destroyed,detached=m.detached;
        CHECK(vireo_auth_worker_run(w,t,&p),VIREO_RESULT_BUSY);
        assert(m.destroyed==destroyed && m.detached==detached && m.published==1);
        CHECK(vireo_auth_failure_audit_inspect(m.resources.audit,&audit_info),VIREO_OK);
        assert(audit_info.queued==(i==3?1U:0U));
        CHECK(vireo_task_destroy(&t),VIREO_OK); /* 清理恢复不借旧task。 */
        if(i==5 || i==12) assert(p.cleanup.repository_pending && p.cleanup.thread_pending && !m.detached);
        if(i==6) assert(!p.cleanup.repository_pending && !p.cleanup.thread_pending && m.detached==1);
        vireo_auth_worker_cleanup_report_t c;
        vireo_result_t next=i==5 || i==12?VIREO_RESULT_DATABASE:i==7 || i==9?VIREO_RESULT_INTERNAL:VIREO_OK;
        CHECK(vireo_auth_worker_destroy(&w,&c),next);
        if(next!=VIREO_OK) {
            assert(w && !m.freed);
            if(i==5 || i==12) assert(c.repository_pending && c.thread_pending && !c.detach_called);
            CHECK(vireo_auth_worker_destroy(&w,&c),VIREO_OK);
        }
        assert(!w && m.freed==1 && m.published==1 && m.executed==(i<=2?0u:1u));
        if(i==9 || i==10) assert(m.completion_destroyed==(i==9?2u:1u));
        teardown(&m);
    }
}
typedef struct foreign {vireo_auth_worker_t *w;vireo_task_t *task;} foreign_t;
static void *foreign_call(void *p)
{
    foreign_t *f=p; vireo_auth_worker_report_t r;
    CHECK(vireo_auth_worker_run(f->w,f->task,&r),VIREO_RESULT_INVALID_ARGUMENT); assert(!r.attempted);
    vireo_auth_worker_t *copy=f->w; vireo_auth_worker_cleanup_report_t c;
    CHECK(vireo_auth_worker_destroy(&copy,&c),VIREO_RESULT_INVALID_ARGUMENT); assert(copy==f->w); return NULL;
}
static void affinity(void)
{
    model_t m; setup(&m,true); vireo_auth_worker_t *w=worker(&m); vireo_task_t *t=task(true,0);
    foreign_t f={w,t}; pthread_t thread; assert(pthread_create(&thread,NULL,foreign_call,&f)==0);
    assert(pthread_join(thread,NULL)==0); assert(!m.attached);
    vireo_auth_worker_report_t r; CHECK(vireo_auth_worker_run(w,t,&r),VIREO_OK);
    outcome(&m,VIREO_AUTH_COMMITTED,VIREO_OK,VIREO_STATUS_OK);
    CHECK(vireo_task_destroy(&t),VIREO_OK); vireo_auth_worker_cleanup_report_t c;
    CHECK(vireo_auth_worker_destroy(&w,&c),VIREO_OK); teardown(&m);
}
int main(void)
{
    invalid(); boundaries(); failures(); affinity();
    puts("PASS auth_worker: 13 failure/commit/transfer models, 5 invalid tasks, owner-affine cleanup after task death, no reexecute/republish, zeroed freed receipts");
    return 0;
}
