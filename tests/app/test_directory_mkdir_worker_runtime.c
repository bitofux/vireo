/* PROJECT : VIREO
 * FILE : test_directory_mkdir_worker_runtime.c
 * AUTHOR : bitofux
 * DATE : 2026-10-20
 * BRIEF : 应用边界注入、同线程有限清理、故障并发OR及真实exec终止。
 */
#define _POSIX_C_SOURCE 200809L
#include "directory_mkdir_worker_runtime_internal.h"
#include "auth_process_internal.h"
#include "directory_mkdir_bridge_test_support.h"
#include <pthread.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sched.h>
#include <vireo/thread/thread_pool.h>

typedef struct model {
    max_align_t marker;
    pthread_t thread;
    pthread_barrier_t *barrier;
    unsigned create_calls,run_calls,destroy_calls,clear_at;
    vireo_result_t create_rc,run_rc,destroy_rc;
    bool valid,transferred,publish_ok,run_cleanup_error,inner_cleanup_error,inner_pending,blocked;
    unsigned auth_calls;
    vireo_mysql_node_mkdir_commit_t raw_commit;
    vireo_mysql_node_mkdir_effect_t raw_effect;
    int trace;
} model_t;
static void trace(model_t *m,char byte)
{ if(m->trace>=0) assert(write(m->trace,&byte,1)==1); }
static vireo_result_t create(void *p,vireo_directory_mkdir_worker_resources_t const *r,
    vireo_directory_mkdir_worker_options_t const *o,vireo_directory_mkdir_worker_t **owner)
{
    model_t *m=p; assert(r && o && !*owner); ++m->create_calls; m->thread=pthread_self(); trace(m,'C');
    if(m->barrier) { int rc=pthread_barrier_wait(m->barrier); assert(rc==0 || rc==PTHREAD_BARRIER_SERIAL_THREAD); }
    if(m->create_rc==VIREO_OK) *owner=(vireo_directory_mkdir_worker_t *)&m->marker;
    return m->create_rc;
}
static vireo_result_t run(void *p,vireo_directory_mkdir_worker_t *owner,vireo_task_t const *t,vireo_directory_mkdir_worker_report_t *out)
{
    model_t *m=p; assert(owner==(vireo_directory_mkdir_worker_t *)&m->marker && t && pthread_equal(m->thread,pthread_self()));
    assert(++m->run_calls==1); trace(m,'E');
    *out=(vireo_directory_mkdir_worker_report_t){.attempted=true,.task_validated=m->valid,
        .work_result=m->run_rc,.publish_called=m->valid,.publish_result=m->publish_ok?VIREO_OK:VIREO_RESULT_IO};
    out->publication.publication.completion_transferred=m->transferred;
    out->cleanup.repository_called=m->run_cleanup_error;
    out->cleanup.repository_result=m->run_cleanup_error?VIREO_RESULT_DATABASE:VIREO_OK;
    out->work_error.cleanup_result=m->inner_cleanup_error?VIREO_RESULT_DATABASE:VIREO_OK;
    out->service.repository.cleanup_pending=m->inner_pending;
    out->service.repository.commit=m->raw_commit;
    out->service.repository.effect=m->raw_effect;
    out->publication_blocked_by_cleanup=m->blocked;
    return m->run_rc;
}
static vireo_result_t destroy(void *p,vireo_directory_mkdir_worker_t **owner,vireo_directory_mkdir_worker_cleanup_report_t *out)
{
    model_t *m=p; assert(*owner==(vireo_directory_mkdir_worker_t *)&m->marker && pthread_equal(m->thread,pthread_self()));
    ++m->destroy_calls; trace(m,'D');
    bool const pending=m->destroy_calls<m->clear_at;
    if(!pending) *owner=NULL;
    *out=(vireo_directory_mkdir_worker_cleanup_report_t){.thread_pending=pending,.detach_called=true,
        .detach_result=m->destroy_rc};
    return m->destroy_rc;
}
static vireo_result_t previous_execute(void *p,vireo_directory_list_worker_runtime_t *r,vireo_task_t const *t)
{ model_t *m=p; assert(r && t); ++m->auth_calls; return VIREO_RESULT_NOT_FOUND; }
static vireo_directory_mkdir_worker_runtime_ops_t operations(model_t *m)
{ return (vireo_directory_mkdir_worker_runtime_ops_t){m,create,run,destroy,previous_execute}; }
static model_t model(void)
{ return (model_t){.clear_at=1,.valid=true,.transferred=true,.publish_ok=true,.trace=-1}; }
static void init(vireo_directory_mkdir_worker_runtime_t *runtime,size_t attempts)
{
    static max_align_t markers[6]; static vireo_auth_worker_runtime_t auth; static vireo_directory_stat_worker_runtime_t stat; static vireo_directory_root_worker_runtime_t previous;
    vireo_auth_worker_resources_t const ar={(vireo_mysql_runtime_t *)&markers[0],(vireo_mysql_pool_t *)&markers[0],
        (vireo_auth_password_gate_t *)&markers[0],(vireo_auth_login_verifier_t *)&markers[0],
        (vireo_completion_queue_t *)&markers[0],(vireo_notifier_t *)&markers[0],NULL};
    vireo_auth_worker_options_t const ao={.execution={100,101,5000,102,103},.password=VIREO_PASSWORD_POLICY_DEFAULT,
        .request_timeout_ns=10,.session_lifetime_ms=60000,.completion_allocation_budget=4096,.max_memory_bytes=65536};
    CHECK(vireo_auth_worker_runtime_init(&auth,&ar,&ao,3),VIREO_OK);
    vireo_directory_stat_worker_resources_t const sr={ar.runtime,ar.database,(vireo_completion_queue_t *)&markers[2],ar.notifier};
    vireo_directory_stat_worker_options_t const so={.execution={401,5000},.completion_allocation_budget=4096,.max_memory_bytes=65536};
    CHECK(vireo_directory_stat_worker_runtime_init(&stat,&auth,&sr,&so,3),VIREO_OK);
    vireo_directory_root_worker_resources_t const rr={ar.runtime,ar.database,(vireo_completion_queue_t *)&markers[3],ar.notifier};
    vireo_directory_root_worker_options_t const ro={.execution={402,5000},.completion_allocation_budget=4096,.max_memory_bytes=65536};
    CHECK(vireo_directory_root_worker_runtime_init(&previous,&stat,&rr,&ro,3),VIREO_OK);
    static vireo_directory_list_worker_runtime_t list;
    vireo_directory_list_worker_resources_t const lr={ar.runtime,(vireo_page_token_key_t *)&markers[4],ar.database,(vireo_completion_queue_t *)&markers[1],ar.notifier};
    vireo_directory_list_worker_options_t const lo={.execution={403,5000},.completion_allocation_budget=32768,.max_memory_bytes=65536};
    CHECK(vireo_directory_list_worker_runtime_init(&list,&previous,&lr,&lo,3),VIREO_OK);
    vireo_directory_mkdir_worker_resources_t const r={ar.runtime,ar.database,(vireo_completion_queue_t *)&markers[5],ar.notifier};
    vireo_directory_mkdir_worker_options_t const o={.execution={400,5000},.completion_allocation_budget=4096,.max_memory_bytes=65536};
    CHECK(vireo_directory_mkdir_worker_runtime_init(runtime,&list,&r,&o,attempts),VIREO_OK);
}
static vireo_task_t *task(void) { return make_task(42,NULL); }
static unsigned faults(vireo_directory_mkdir_worker_runtime_t const *r)
{ vireo_directory_mkdir_worker_faults_t value={99,99,99,99,99}; CHECK(vireo_directory_mkdir_worker_runtime_inspect_faults(r,&value),VIREO_OK);return value.mkdir; }
static void invalid(vireo_task_t const *t)
{
    vireo_directory_mkdir_worker_runtime_t r; init(&r,3);
    vireo_directory_mkdir_worker_faults_t out={99,99,99,99,99};
    CHECK(vireo_directory_mkdir_worker_runtime_inspect_faults(NULL,&out),VIREO_RESULT_INVALID_ARGUMENT); assert(out.auth==99 && out.stat==99 && out.root==99);
    CHECK(vireo_directory_mkdir_worker_runtime_execute(NULL,t),VIREO_RESULT_INVALID_ARGUMENT);
    for(unsigned i=0;i<19;++i) {
        vireo_directory_mkdir_worker_runtime_t target; unsigned char bytes[sizeof target];
        memset(&target,0x93,sizeof target);memcpy(bytes,&target,sizeof target);
        vireo_directory_mkdir_worker_resources_t resources=r.resources;
        vireo_directory_mkdir_worker_options_t o=r.options;size_t count=3;
        vireo_result_t want=VIREO_RESULT_INVALID_ARGUMENT;
        switch(i) {
        case 0:resources.runtime=NULL;break;case 1:resources.database=NULL;break;
        case 2:resources.queue=NULL;break;case 3:resources.notifier=NULL;break;
        case 4:resources.queue=r.previous->previous->previous->auth->resources.queue;break;
        case 5:o.execution.mkdir_operation=100;break;case 6:o.execution.mkdir_operation=0;break;
        case 7:o.completion_allocation_budget=0;break;case 8:o.max_memory_bytes=0;break;
        case 9:count=0;break;case 10:count=17;want=VIREO_RESULT_RANGE;break;
        case 11:o.execution.pool_timeout_ms=60001;want=VIREO_RESULT_RANGE;break;
        case 12:o.max_memory_bytes=67108865;want=VIREO_RESULT_RANGE;break;
        case 14:resources.queue=r.previous->resources.queue;break;
        case 15:o.execution.mkdir_operation=402;break;
        case 16:o.execution.mkdir_operation=403;break;
        case 17:resources.queue=r.previous->previous->resources.queue;break;
        case 18:o.execution.mkdir_operation=401;break;
        default:o.completion_allocation_budget=VIREO_COMPLETION_MAX_ALLOCATION_BYTES+1;want=VIREO_RESULT_RANGE;break;
        }
        CHECK(vireo_directory_mkdir_worker_runtime_init(&target,r.previous,&resources,&o,count),want);
        assert(!memcmp(bytes,&target,sizeof target));
    }
    for(uint32_t operation=100;operation<=107;++operation) {
        init(&r,3);vireo_task_metadata_t m=metadata();m.operation=operation==104?401:operation==105?402:operation==106?403:operation;
        vireo_task_t *routed=NULL;CHECK(vireo_task_create_copy(m,"x",1,4096,&routed),VIREO_OK);
        model_t model_value=model();vireo_directory_mkdir_worker_runtime_ops_t ops=operations(&model_value);
        CHECK(vireo_directory_mkdir_worker_runtime_execute_with(&r,routed,&ops),operation==107?VIREO_RESULT_PROTOCOL:VIREO_RESULT_NOT_FOUND);
        assert(model_value.auth_calls==(operation==107?0u:1u) && !model_value.create_calls);
        assert(faults(&r)==(operation==107?32u:0u)); CHECK(vireo_task_destroy(&routed),VIREO_OK);
    }
    for(unsigned domain=0;domain<5;++domain) {
        init(&r,3);
        atomic_uint *domains[]={&r.previous->previous->previous->auth->faults,&r.previous->previous->previous->faults,
            &r.previous->previous->faults,&r.previous->faults,&r.faults};
        atomic_store(domains[domain],4);
        model_t m=model();vireo_directory_mkdir_worker_runtime_ops_t ops=operations(&m);
        CHECK(vireo_directory_mkdir_worker_runtime_execute_with(&r,t,&ops),VIREO_RESULT_CANCELLED);assert(!m.create_calls);
        vireo_directory_mkdir_worker_faults_t observed={0};
        CHECK(vireo_directory_mkdir_worker_runtime_inspect_faults(&r,&observed),VIREO_OK);
        unsigned const values[]={observed.auth,observed.stat,observed.root,observed.list,observed.mkdir};
        for(unsigned i=0;i<5;++i)assert(values[i]==(i==domain?4u:0u));
        if(domain<4) {
            vireo_directory_mkdir_worker_runtime_t target;unsigned char saved[sizeof target];
            memset(&target,0xa7,sizeof target);memcpy(saved,&target,sizeof target);
            CHECK(vireo_directory_mkdir_worker_runtime_init(&target,r.previous,&r.resources,&r.options,3),VIREO_RESULT_BUSY);
            assert(!memcmp(saved,&target,sizeof target));
        }
    }
}
static void cases(vireo_task_t const *t)
{
    for(unsigned i=0;i<16;++i) {
        vireo_directory_mkdir_worker_runtime_t r;init(&r,3);model_t m=model();unsigned expected=0;
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
        case 10:m.inner_cleanup_error=true;expected=4;break;
        case 11:m.inner_pending=true;expected=4;break;
        case 12:m.blocked=true;m.publish_ok=false;m.transferred=false;expected=12;break;
        case 14:m.raw_commit=VIREO_MYSQL_NODE_MKDIR_COMMITTED;m.raw_effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_CREATED;m.inner_cleanup_error=true;expected=4;break;
        case 15:m.raw_effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_RECOVERED;m.inner_pending=true;expected=4;break;
        default:m.clear_at=3;m.destroy_rc=VIREO_RESULT_INTERNAL;expected=4;break;
        }
        vireo_directory_mkdir_worker_runtime_ops_t const ops=operations(&m);
        vireo_result_t rc=m.create_rc!=VIREO_OK?m.create_rc:m.run_rc!=VIREO_OK?m.run_rc:m.destroy_rc;
        CHECK(vireo_directory_mkdir_worker_runtime_execute_with(&r,t,&ops),rc);
        assert(faults(&r)==expected && m.create_calls==1 && m.run_calls==(i==3?0u:1u));
        assert(m.destroy_calls==(i==3?0u:m.clear_at));
        if(expected) { CHECK(vireo_directory_mkdir_worker_runtime_execute_with(&r,t,&ops),VIREO_RESULT_CANCELLED);assert(m.create_calls==1); }
    }
    for(unsigned budget=1;budget<=16;++budget) {
        vireo_directory_mkdir_worker_runtime_t r;init(&r,budget);model_t m=model();m.clear_at=budget;m.destroy_rc=budget>1?VIREO_RESULT_BUSY:VIREO_OK;
        vireo_directory_mkdir_worker_runtime_ops_t const ops=operations(&m);
        CHECK(vireo_directory_mkdir_worker_runtime_execute_with(&r,t,&ops),m.destroy_rc);
        assert(m.destroy_calls==budget && faults(&r)==(budget>1?4u:0u));
    }
}
typedef struct thread_input {
    vireo_directory_mkdir_worker_runtime_t *runtime;
    vireo_task_t const *task;
    model_t model;
    vireo_result_t result;
} thread_input_t;
static void *parallel(void *p)
{
    thread_input_t *x=p;int old=0;assert(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,&old)==0);
    vireo_directory_mkdir_worker_runtime_ops_t const ops=operations(&x->model);
    x->result=vireo_directory_mkdir_worker_runtime_execute_with(x->runtime,x->task,&ops);
    assert(pthread_setcancelstate(old,NULL)==0);return NULL;
}
static void concurrent(vireo_task_t const *t)
{
    vireo_directory_mkdir_worker_runtime_t r;init(&r,3);pthread_barrier_t barrier;
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
    vireo_directory_mkdir_worker_runtime_t r;init(&r,budget);vireo_task_t *t=task();
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
typedef struct close_fixture {
    vireo_completion_queue_t *queues[5];
    vireo_notifier_t *notifier;
    atomic_uint first,attempting,finished;
} close_fixture_t;
static vireo_result_t publish_twice(void *context,vireo_task_t const *t)
{
    close_fixture_t *f=context; vireo_task_info_t info; CHECK(vireo_task_inspect(t,&info),VIREO_OK);
    size_t const index=(size_t)(info.metadata.operation-400);
    for(unsigned i=0;i<3;++i) {
        if(i==1) atomic_fetch_add_explicit(&f->attempting,1,memory_order_release);
        vireo_completion_t *left=NULL; vireo_completion_publish_report_t p;
        vireo_result_t rc=vireo_completion_copy_wait_publish(t,VIREO_OK,VIREO_STATUS_OK,"x",1,4096,
            f->queues[index],f->notifier,&left,&p);
        if(i==0) { assert(rc==VIREO_OK && p.completion_transferred && !left); atomic_fetch_add_explicit(&f->first,1,memory_order_release); }
        else { assert(rc==VIREO_RESULT_CANCELLED && !p.completion_transferred && left); CHECK(vireo_completion_destroy(&left),VIREO_OK); }
    }
    atomic_fetch_add_explicit(&f->finished,1,memory_order_release); return VIREO_OK;
}
/** 五类真实producer均在满queue尚未返回；六close确认后join，无需先pop腾空间。 */
static void close_six_queues(void)
{
    close_fixture_t f={0};atomic_init(&f.first,0);atomic_init(&f.attempting,0);atomic_init(&f.finished,0);
    vireo_notifier_options_t no={4096};CHECK(vireo_notifier_create(&no,&f.notifier,NULL),VIREO_OK);
    for(size_t i=0;i<5;++i) {
        vireo_completion_queue_options_t co={1,65536};CHECK(vireo_completion_queue_create(&co,&f.queues[i]),VIREO_OK);
        CHECK(vireo_completion_queue_prepare_wait(f.queues[i]),VIREO_OK);
    }
    vireo_task_queue_t *tasks=NULL;vireo_task_queue_options_t qo={5,65536};CHECK(vireo_task_queue_create(&qo,&tasks),VIREO_OK);
    CHECK(vireo_task_queue_prepare_wait(tasks),VIREO_OK);vireo_thread_pool_t *workers=NULL;
    vireo_thread_pool_options_t po={5,65536};CHECK(vireo_thread_pool_create(&po,&workers),VIREO_OK);
    vireo_thread_pool_configuration_t config={tasks,publish_twice,&f};vireo_thread_pool_report_t report;
    CHECK(vireo_thread_pool_configure(workers,&config,NULL),VIREO_OK);CHECK(vireo_thread_pool_start(workers,&report),VIREO_OK);
    CHECK(vireo_thread_pool_enable_execution(workers,&report),VIREO_OK);
    for(uint32_t i=0;i<5;++i) {
        vireo_task_metadata_t meta=metadata();meta.operation=400+i;meta.route.request_sequence=i+1;meta.request_instance_id=i+1;
        vireo_task_t *t=NULL;CHECK(vireo_task_create_copy(meta,"x",1,4096,&t),VIREO_OK);
        /* Workers already consume the queue: its nonwaiting lock may return BUSY.
         * Retry only a queue-stage rejection that retained this exact task. */
        uint64_t submit_start=0,submit_now=0;CHECK(vireo_clock_monotonic_now(&submit_start,NULL),VIREO_OK);
        vireo_thread_pool_submit_report_t moved;vireo_result_t submitted=VIREO_RESULT_BUSY;
        for(size_t attempt=0;attempt<100000 && submitted==VIREO_RESULT_BUSY;++attempt) {
            errno=EDOM;submitted=vireo_thread_pool_try_submit(workers,&t,&moved);assert(errno==EDOM);
            if(submitted==VIREO_RESULT_BUSY) {
                assert(moved.stage==VIREO_THREAD_POOL_SUBMIT_STAGE_SUBMIT_QUEUE && moved.queue_called && !moved.queue_report.transferred && t);
                assert(sched_yield()==0);CHECK(vireo_clock_monotonic_now(&submit_now,NULL),VIREO_OK);
                assert(submit_now-submit_start<UINT64_C(10000000000));
            }
        }
        CHECK(submitted,VIREO_OK);assert(!t && moved.queue_report.transferred);
    }
    uint64_t start=0,now=0;CHECK(vireo_clock_monotonic_now(&start,NULL),VIREO_OK);
    while(atomic_load_explicit(&f.first,memory_order_acquire)<5 || atomic_load_explicit(&f.attempting,memory_order_acquire)<5) {
        assert(sched_yield()==0);CHECK(vireo_clock_monotonic_now(&now,NULL),VIREO_OK);assert(now-start<UINT64_C(10000000000));
    }
    assert(!atomic_load_explicit(&f.finished,memory_order_acquire));
    bool closed[6]={false,false,false,false,false,false};
    for(size_t attempt=0;attempt<100000 && (!closed[0] || !closed[1] || !closed[2] || !closed[3] || !closed[4] || !closed[5]);++attempt) {
        if(!closed[0]) { vireo_task_queue_close_report_t p;vireo_result_t rc=vireo_task_queue_close(tasks,VIREO_TASK_QUEUE_CANCEL_PENDING,&p);assert(rc==VIREO_OK || rc==VIREO_RESULT_BUSY);closed[0]=rc==VIREO_OK; }
        for(size_t i=0;i<5;++i) if(!closed[i+1]) { vireo_completion_queue_close_report_t p;vireo_result_t rc=vireo_completion_queue_close(f.queues[i],&p);assert(rc==VIREO_OK || rc==VIREO_RESULT_BUSY);closed[i+1]=rc==VIREO_OK; }
        assert(sched_yield()==0);
    }
    assert(closed[0] && closed[1] && closed[2] && closed[3] && closed[4] && closed[5]);vireo_result_t joined=VIREO_RESULT_BUSY;
    for(size_t i=0;i<100000 && joined==VIREO_RESULT_BUSY;++i) { joined=vireo_thread_pool_stop_and_join(workers,&report);if(joined==VIREO_RESULT_BUSY)assert(sched_yield()==0); }
    assert(joined==VIREO_OK && report.joined_count==5 && atomic_load_explicit(&f.finished,memory_order_acquire)==5);
    for(size_t i=0;i<5;++i) {
        vireo_completion_t *c=NULL;vireo_completion_queue_transfer_report_t p;
        CHECK(vireo_completion_queue_try_pop(f.queues[i],&c,&p),VIREO_OK);CHECK(vireo_completion_destroy(&c),VIREO_OK);
        CHECK(vireo_completion_queue_try_pop(f.queues[i],&c,&p),VIREO_RESULT_CANCELLED);
        CHECK(vireo_completion_queue_destroy(&f.queues[i]),VIREO_OK);
    }
    CHECK(vireo_thread_pool_destroy(&workers),VIREO_OK);CHECK(vireo_task_queue_destroy(&tasks),VIREO_OK);
    CHECK(vireo_notifier_destroy(&f.notifier,NULL),VIREO_OK);
}
static unsigned join_calls,join_busy_count;
static vireo_thread_pool_stage_t join_stage;
static vireo_result_t joining(vireo_thread_pool_t *pool,vireo_thread_pool_report_t *out)
{
    assert(pool); ++join_calls;
    *out=(vireo_thread_pool_report_t){.stage=join_calls<=join_busy_count?join_stage:VIREO_THREAD_POOL_STAGE_NONE};
    return join_calls<=join_busy_count?VIREO_RESULT_BUSY:VIREO_OK;
}
static void join_contention(void)
{
    max_align_t marker; vireo_thread_pool_t *pool=(vireo_thread_pool_t *)&marker;
    vireo_thread_pool_report_t report={0};
    join_stage=VIREO_THREAD_POOL_STAGE_CHECK_QUEUE; join_busy_count=2;join_calls=0;
    CHECK(vireo_auth_process_join_with(pool,3,joining,&report),VIREO_OK);assert(join_calls==3);
    join_busy_count=3;join_calls=0;
    CHECK(vireo_auth_process_join_with(pool,3,joining,&report),VIREO_RESULT_BUSY);assert(join_calls==3 && report.stage==join_stage);
    join_stage=VIREO_THREAD_POOL_STAGE_EXECUTE_TASK;join_calls=0;
    CHECK(vireo_auth_process_join_with(pool,3,joining,&report),VIREO_RESULT_BUSY);assert(join_calls==1);
    join_stage=VIREO_THREAD_POOL_STAGE_JOIN_WORKER;join_calls=0;
    CHECK(vireo_auth_process_join_with(pool,3,joining,&report),VIREO_RESULT_BUSY);assert(join_calls==1);
    CHECK(vireo_auth_process_join_with(pool,0,joining,&report),VIREO_RESULT_INVALID_ARGUMENT);assert(join_calls==1);
}
int main(int argc,char **argv)
{
    if(argc==4 && !strcmp(argv[1],"--fatal")) { fatal_child(atoi(argv[2]),(unsigned)atoi(argv[3]));return 99; }
    assert(argc==1);int old=0;assert(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,&old)==0);
    vireo_task_t *t=task();invalid(t);cases(t);concurrent(t);CHECK(vireo_task_destroy(&t),VIREO_OK);
    fatal_cases();close_six_queues();join_contention();assert(pthread_setcancelstate(old,NULL)==0);
    puts("PASS directory_mkdir_worker_runtime: op routing, sixteen fault/transfer/owner models including raw COMMITTED/RECOVERED cleanup history, budgets1..16, four simultaneous workers OR all bits, exec worker _Exit budgets1/3/16, five real producers full before six-close/join and final drains");return 0;
}
