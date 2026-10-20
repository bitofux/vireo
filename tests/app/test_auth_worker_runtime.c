/* PROJECT : VIREO
 * FILE : test_auth_worker_runtime.c
 * AUTHOR : bitofux
 * DATE : 2026-10-20
 * BRIEF : 应用边界注入、同线程有限清理、故障并发OR及真实exec终止。
 */
#define _POSIX_C_SOURCE 200809L
#include "auth_worker_runtime_internal.h"
#include "auth_task_test_support.h"
#include <pthread.h>
#include <sys/wait.h>
#include <unistd.h>

typedef struct model {
    max_align_t marker;
    pthread_t thread;
    pthread_barrier_t *barrier;
    unsigned create_calls,run_calls,destroy_calls,clear_at;
    vireo_result_t create_rc,run_rc,destroy_rc;
    bool valid,transferred,publish_ok,run_cleanup_error;
    int trace;
} model_t;
static void trace(model_t *m,char byte)
{ if(m->trace>=0) assert(write(m->trace,&byte,1)==1); }
static vireo_result_t create(void *p,vireo_auth_worker_resources_t const *r,
    vireo_auth_worker_options_t const *o,vireo_auth_worker_t **owner)
{
    model_t *m=p; assert(r && o && !*owner); ++m->create_calls; m->thread=pthread_self(); trace(m,'C');
    if(m->barrier) { int rc=pthread_barrier_wait(m->barrier); assert(rc==0 || rc==PTHREAD_BARRIER_SERIAL_THREAD); }
    if(m->create_rc==VIREO_OK) *owner=(vireo_auth_worker_t *)&m->marker;
    return m->create_rc;
}
static vireo_result_t run(void *p,vireo_auth_worker_t *owner,vireo_task_t const *t,vireo_auth_worker_report_t *out)
{
    model_t *m=p; assert(owner==(vireo_auth_worker_t *)&m->marker && t && pthread_equal(m->thread,pthread_self()));
    assert(++m->run_calls==1); trace(m,'E');
    *out=(vireo_auth_worker_report_t){.attempted=true,.task_validated=m->valid,
        .work_result=m->run_rc,.publish_called=m->valid,.publish_result=m->publish_ok?VIREO_OK:VIREO_RESULT_IO};
    out->publication.publication.completion_transferred=m->transferred;
    out->cleanup.repository_called=m->run_cleanup_error;
    out->cleanup.repository_result=m->run_cleanup_error?VIREO_RESULT_DATABASE:VIREO_OK;
    return m->run_rc;
}
static vireo_result_t destroy(void *p,vireo_auth_worker_t **owner,vireo_auth_worker_cleanup_report_t *out)
{
    model_t *m=p; assert(*owner==(vireo_auth_worker_t *)&m->marker && pthread_equal(m->thread,pthread_self()));
    ++m->destroy_calls; trace(m,'D');
    bool const pending=m->destroy_calls<m->clear_at;
    if(!pending) *owner=NULL;
    *out=(vireo_auth_worker_cleanup_report_t){.thread_pending=pending,.detach_called=true,
        .detach_result=m->destroy_rc};
    return m->destroy_rc;
}
static vireo_auth_worker_runtime_ops_t operations(model_t *m)
{ return (vireo_auth_worker_runtime_ops_t){m,create,run,destroy}; }
static model_t model(void)
{ return (model_t){.clear_at=1,.valid=true,.transferred=true,.publish_ok=true,.trace=-1}; }
static void init(vireo_auth_worker_runtime_t *runtime,size_t attempts)
{
    /* 此单元fake操作不解引用关联；地址仅是当前测试存活对齐标记。 */
    static max_align_t marker;
    vireo_auth_worker_resources_t const r={(vireo_mysql_runtime_t *)&marker,(vireo_mysql_pool_t *)&marker,
        (vireo_auth_password_gate_t *)&marker,(vireo_auth_login_verifier_t *)&marker,
        (vireo_completion_queue_t *)&marker,(vireo_notifier_t *)&marker,NULL};
    vireo_auth_worker_options_t const o={.execution={100,101,5000,102,103},.password=VIREO_PASSWORD_POLICY_DEFAULT,
        .request_timeout_ns=10,.session_lifetime_ms=60000,.completion_allocation_budget=4096,.max_memory_bytes=65536};
    CHECK(vireo_auth_worker_runtime_init(runtime,&r,&o,attempts),VIREO_OK);
}
static vireo_task_t *task(void)
{
    unsigned char wire[156]; size_t n=frame(wire,true,7,false);
    vireo_task_metadata_t metadata=task_context(7,1,true).metadata;
    vireo_task_t *out=NULL; CHECK(vireo_task_create_copy(metadata,wire,n,4096,&out),VIREO_OK);
    CHECK(vireo_secure_clear(wire,sizeof wire),VIREO_OK); return out;
}
static unsigned faults(vireo_auth_worker_runtime_t const *r)
{ unsigned value=999; CHECK(vireo_auth_worker_runtime_inspect_faults(r,&value),VIREO_OK);return value; }
static void invalid(vireo_task_t const *t)
{
    vireo_auth_worker_runtime_t r; init(&r,3);
    unsigned out=99; CHECK(vireo_auth_worker_runtime_inspect_faults(NULL,&out),VIREO_RESULT_INVALID_ARGUMENT);assert(out==99);
    CHECK(vireo_auth_worker_runtime_inspect_faults(&r,NULL),VIREO_RESULT_INVALID_ARGUMENT);
    model_t m=model();vireo_auth_worker_runtime_ops_t ops=operations(&m);
    CHECK(vireo_auth_worker_runtime_execute(NULL,t),VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_auth_worker_runtime_execute(&r,NULL),VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_auth_worker_runtime_execute_with(&r,t,NULL),VIREO_RESULT_INVALID_ARGUMENT);
    ops.destroy=NULL;CHECK(vireo_auth_worker_runtime_execute_with(&r,t,&ops),VIREO_RESULT_INVALID_ARGUMENT);
    assert(!m.create_calls && !faults(&r));
    for(unsigned i=0;i<17;++i) {
        vireo_auth_worker_runtime_t target; unsigned char bytes[sizeof target];
        memset(&target,0x93,sizeof target);memcpy(bytes,&target,sizeof target);
        vireo_auth_worker_resources_t resources=r.resources;
        vireo_auth_worker_options_t o=r.options;size_t count=3;
        switch(i) {
        case 0:resources.runtime=NULL;break;case 1:resources.database=NULL;break;
        case 2:resources.gate=NULL;break;case 3:resources.verifier=NULL;break;
        case 4:resources.queue=NULL;break;case 5:resources.notifier=NULL;break;
        case 6:o.execution.register_operation=0;break;case 7:o.execution.login_operation=100;break;
        case 8:o.request_timeout_ns=0;break;case 9:o.session_lifetime_ms=0;break;
        case 10:o.completion_allocation_budget=0;break;case 11:o.max_memory_bytes=0;break;
        case 12:count=0;break;case 13:count=17;break;case 14:o.execution.pool_timeout_ms=60001;break;
        case 15:o.max_memory_bytes=67108865;break;
        default:o.completion_allocation_budget=VIREO_COMPLETION_MAX_ALLOCATION_BYTES+1;break;
        }
        CHECK(vireo_auth_worker_runtime_init(&target,&resources,&o,count),i>=13?VIREO_RESULT_RANGE:VIREO_RESULT_INVALID_ARGUMENT);
        assert(!memcmp(bytes,&target,sizeof target));
    }
    vireo_auth_worker_runtime_t unused;
    CHECK(vireo_auth_worker_runtime_init(NULL,&r.resources,&r.options,3),VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_auth_worker_runtime_init(&unused,NULL,&r.options,3),VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_auth_worker_runtime_init(&unused,&r.resources,NULL,3),VIREO_RESULT_INVALID_ARGUMENT);
}
static void cases(vireo_task_t const *t)
{
    for(unsigned i=0;i<10;++i) {
        vireo_auth_worker_runtime_t r;init(&r,3);model_t m=model();unsigned expected=0;
        switch(i) {
        case 0:break;
        case 1:m.run_rc=VIREO_RESULT_NOT_FOUND;break; /* 普通错密不能误报基础故障。 */
        case 2:m.run_rc=VIREO_RESULT_DATABASE;break; /* UNKNOWN/DB错误的正常交接同样不误升级。 */
        case 3:m.create_rc=VIREO_RESULT_NO_MEMORY;expected=1;break;
        case 4:m.valid=false;m.transferred=false;m.publish_ok=false;m.run_rc=VIREO_RESULT_PROTOCOL;expected=10;break;
        case 5:m.publish_ok=false;m.run_rc=VIREO_RESULT_IO;expected=8;break; /* 已转移而报错。 */
        case 6:m.publish_ok=false;m.transferred=false;m.run_rc=VIREO_RESULT_NO_MEMORY;expected=8;break;
        case 7:m.run_cleanup_error=true;m.run_rc=VIREO_RESULT_DATABASE;expected=4;break;
        case 8:m.destroy_rc=VIREO_RESULT_DATABASE;expected=4;break; /* 报错但owner已空。 */
        default:m.clear_at=3;m.destroy_rc=VIREO_RESULT_INTERNAL;expected=4;break;
        }
        vireo_auth_worker_runtime_ops_t const ops=operations(&m);
        vireo_result_t rc=m.create_rc!=VIREO_OK?m.create_rc:m.run_rc!=VIREO_OK?m.run_rc:m.destroy_rc;
        CHECK(vireo_auth_worker_runtime_execute_with(&r,t,&ops),rc);
        assert(faults(&r)==expected && m.create_calls==1 && m.run_calls==(i==3?0u:1u));
        assert(m.destroy_calls==(i==3?0u:m.clear_at));
        if(expected) { CHECK(vireo_auth_worker_runtime_execute_with(&r,t,&ops),VIREO_RESULT_CANCELLED);assert(m.create_calls==1); }
    }
    for(unsigned budget=1;budget<=16;++budget) {
        vireo_auth_worker_runtime_t r;init(&r,budget);model_t m=model();m.clear_at=budget;m.destroy_rc=budget>1?VIREO_RESULT_BUSY:VIREO_OK;
        vireo_auth_worker_runtime_ops_t const ops=operations(&m);
        CHECK(vireo_auth_worker_runtime_execute_with(&r,t,&ops),m.destroy_rc);
        assert(m.destroy_calls==budget && faults(&r)==(budget>1?4u:0u));
    }
}
typedef struct thread_input {
    vireo_auth_worker_runtime_t *runtime;
    vireo_task_t const *task;
    model_t model;
    vireo_result_t result;
} thread_input_t;
static void *parallel(void *p)
{
    thread_input_t *x=p;int old=0;assert(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,&old)==0);
    vireo_auth_worker_runtime_ops_t const ops=operations(&x->model);
    x->result=vireo_auth_worker_runtime_execute_with(x->runtime,x->task,&ops);
    assert(pthread_setcancelstate(old,NULL)==0);return NULL;
}
static void concurrent(vireo_task_t const *t)
{
    vireo_auth_worker_runtime_t r;init(&r,3);pthread_barrier_t barrier;
    assert(pthread_barrier_init(&barrier,NULL,4)==0);pthread_t threads[4];thread_input_t inputs[4];
    for(size_t i=0;i<4;++i) {
        inputs[i]=(thread_input_t){.runtime=&r,.task=t,.model=model()};inputs[i].model.barrier=&barrier;
        if(i==0)inputs[i].model.create_rc=VIREO_RESULT_NO_MEMORY;
        if(i==1)inputs[i].model.valid=false;
        if(i==2)inputs[i].model.run_cleanup_error=true;
        if(i==3)inputs[i].model.publish_ok=false;
        assert(pthread_create(&threads[i],NULL,parallel,&inputs[i])==0);
    }
    for(size_t i=0;i<4;++i)assert(pthread_join(threads[i],NULL)==0);
    assert(faults(&r)==15);assert(pthread_barrier_destroy(&barrier)==0);
}
static int exit_trace=-1;
static void at_exit(void) { if(exit_trace>=0) (void)write(exit_trace,"A",1); }
static void fatal_child(int fd,unsigned budget)
{
    exit_trace=fd;assert(atexit(at_exit)==0);
    vireo_auth_worker_runtime_t r;init(&r,budget);vireo_task_t *t=task();
    thread_input_t input={.runtime=&r,.task=t,.model=model()};
    input.model.trace=fd;input.model.clear_at=17;input.model.destroy_rc=VIREO_RESULT_DATABASE;
    pthread_t worker;assert(pthread_create(&worker,NULL,parallel,&input)==0);
    assert(pthread_join(worker,NULL)==0);(void)write(fd,"R",1);exit(99);
}
static void fatal_cases(void)
{
    unsigned const budgets[]={1,3,16};
    for(size_t i=0;i<3;++i) {
        int channel[2];assert(pipe(channel)==0);pid_t pid=fork();assert(pid>=0);
        if(!pid) {
            assert(close(channel[0])==0);char fd[32],budget[32];
            assert(snprintf(fd,sizeof fd,"%d",channel[1])>0);
            assert(snprintf(budget,sizeof budget,"%u",budgets[i])>0);
            execl("/proc/self/exe","runtime-test","--fatal",fd,budget,(char *)NULL);_Exit(98);
        }
        assert(close(channel[1])==0);char bytes[64];size_t n=0;
        for(;;) { ssize_t amount=read(channel[0],bytes+n,sizeof bytes-n);if(amount<0 && errno==EINTR)continue;assert(amount>=0);if(!amount)break;n+=(size_t)amount;assert(n<sizeof bytes); }
        assert(close(channel[0])==0);int status=0;assert(waitpid(pid,&status,0)==pid);
        assert(WIFEXITED(status) && WEXITSTATUS(status)==EXIT_FAILURE);
        assert(n==budgets[i]+2 && bytes[0]=='C' && bytes[1]=='E');
        for(size_t j=2;j<n;++j)assert(bytes[j]=='D');
    }
}
int main(int argc,char **argv)
{
    if(argc==4 && !strcmp(argv[1],"--fatal")) { fatal_child(atoi(argv[2]),(unsigned)atoi(argv[3]));return 99; }
    assert(argc==1);int old=0;assert(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,&old)==0);
    vireo_task_t *t=task();invalid(t);cases(t);concurrent(t);CHECK(vireo_task_destroy(&t),VIREO_OK);
    fatal_cases();assert(pthread_setcancelstate(old,NULL)==0);
    puts("PASS auth_worker_runtime: invalid/errno/output, ten fault/transfer/owner models, budgets1..16, four simultaneous workers OR all bits, exec worker _Exit budgets1/3/16 without callback return or atexit");return 0;
}
