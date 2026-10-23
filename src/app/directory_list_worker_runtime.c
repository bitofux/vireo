/* PROJECT: VIREO; FILE: directory_list_worker_runtime.c;
 * AUTHOR: bitofux; DATE: 2026-10-23; BRIEF: 混合标签分发、原线程有限清理和永久故障。 */
#include "directory_list_worker_runtime_internal.h"
#include <errno.h>
#include <stdlib.h>

vireo_result_t vireo_directory_list_worker_runtime_init(vireo_directory_list_worker_runtime_t *runtime,
    vireo_directory_root_worker_runtime_t *previous,vireo_directory_list_worker_resources_t const *r,
    vireo_directory_list_worker_options_t const *o,size_t attempts)
{
    int const saved=errno;
    vireo_result_t rc=VIREO_RESULT_INVALID_ARGUMENT;
    if(!runtime || !previous || !r || !o || !r->runtime || !r->key || !r->database || !r->queue || !r->notifier ||
       r->runtime!=previous->previous->auth->resources.runtime || r->database!=previous->previous->auth->resources.database ||
       r->notifier!=previous->previous->auth->resources.notifier || r->queue==previous->previous->auth->resources.queue || r->queue==previous->resources.queue || r->queue==previous->previous->resources.queue ||
       !o->execution.list_operation || !o->completion_allocation_budget || !o->max_memory_bytes || !attempts ||
       (vireo_auth_task_command(&previous->previous->auth->options.execution,o->execution.list_operation) || o->execution.list_operation==previous->previous->options.execution.stat_operation || o->execution.list_operation==previous->options.execution.root_operation)) goto done;
    rc=VIREO_RESULT_RANGE;
    if(attempts>16 || o->execution.pool_timeout_ms>60000 || o->max_memory_bytes>(size_t)67108864 ||
       o->completion_allocation_budget>VIREO_COMPLETION_MAX_ALLOCATION_BYTES) goto done;
    rc=VIREO_RESULT_BUSY;
    if(atomic_load_explicit(&previous->previous->auth->faults,memory_order_relaxed) || atomic_load_explicit(&previous->faults,memory_order_relaxed) || atomic_load_explicit(&previous->previous->faults,memory_order_relaxed)) goto done;
    atomic_uint probe; atomic_init(&probe,0);
    if(!atomic_is_lock_free(&probe)) { rc=VIREO_RESULT_INTERNAL; goto done; }
    runtime->previous=previous; runtime->resources=*r; runtime->options=*o; runtime->destroy_attempts=attempts;
    atomic_init(&runtime->faults,0); rc=VIREO_OK;
done:
    errno=saved; return rc;
}

vireo_result_t vireo_directory_list_worker_runtime_inspect_faults(
    vireo_directory_list_worker_runtime_t const *r,vireo_directory_list_worker_faults_t *out)
{
    int const saved=errno; vireo_result_t rc=VIREO_RESULT_INVALID_ARGUMENT;
    if(r && out) {
        vireo_directory_list_worker_faults_t p={0};
        vireo_directory_root_worker_faults_t before={0};
        rc=vireo_directory_root_worker_runtime_inspect_faults(r->previous,&before);
        if(rc==VIREO_OK) { p.auth=before.auth; p.stat=before.stat; p.root=before.root; p.list=atomic_load_explicit(&r->faults,memory_order_relaxed); *out=p; }
    }
    errno=saved; return rc;
}

/** 原子只表达位集合，无伴随payload发布；外层负责errno。 */
static void latch(vireo_directory_list_worker_runtime_t *r,unsigned bits)
{ (void)atomic_fetch_or_explicit(&r->faults,bits,memory_order_relaxed); }
/** 实际调用错误与实际残留独立判断，不从未调用零值推导清理成功。 */
static bool cleanup_failed(vireo_directory_list_worker_cleanup_report_t const *p)
{
    return (p->repository_called && p->repository_result!=VIREO_OK) ||
        (p->detach_called && p->detach_result!=VIREO_OK) ||
        (p->completion_called && p->completion_result!=VIREO_OK) ||
        p->repository_pending || p->thread_pending || p->completion_pending;
}

vireo_result_t vireo_directory_list_worker_runtime_execute_with(vireo_directory_list_worker_runtime_t *r,
    vireo_task_t const *task,vireo_directory_list_worker_runtime_ops_t const *ops)
{
    int const saved=errno; vireo_result_t rc=VIREO_RESULT_INVALID_ARGUMENT;
    if(!r || !task || !ops || !ops->create || !ops->run || !ops->destroy || !ops->previous_execute) goto done;
    vireo_directory_list_worker_faults_t faults;
    rc=vireo_directory_list_worker_runtime_inspect_faults(r,&faults);
    if(rc!=VIREO_OK) goto done;
    if(faults.auth || faults.stat || faults.root || faults.list) { rc=VIREO_RESULT_CANCELLED; goto done; }
    vireo_task_info_t info;
    rc=vireo_task_inspect(task,&info);
    if(rc!=VIREO_OK) { latch(r,VIREO_DIRECTORY_LIST_WORKER_FAULT_DISPATCH); goto done; }
    if((vireo_auth_task_command(&r->previous->previous->auth->options.execution,info.metadata.operation) || info.metadata.operation==r->previous->previous->options.execution.stat_operation || info.metadata.operation==r->previous->options.execution.root_operation)) {
        rc=ops->previous_execute(ops->context,r->previous,task); goto done;
    }
    if(info.metadata.operation!=r->options.execution.list_operation) {
        latch(r,VIREO_DIRECTORY_LIST_WORKER_FAULT_DISPATCH); rc=VIREO_RESULT_PROTOCOL; goto done;
    }
    vireo_directory_list_worker_t *owner=NULL;
    rc=ops->create(ops->context,&r->resources,&r->options,&owner);
    if(rc!=VIREO_OK) { latch(r,VIREO_DIRECTORY_LIST_WORKER_FAULT_CREATE); goto done; }
    vireo_directory_list_worker_report_t p={0};
    rc=ops->run(ops->context,owner,task,&p);
    unsigned bits=0;
    if(!p.task_validated) bits|=VIREO_DIRECTORY_LIST_WORKER_FAULT_TASK;
    if(p.publication_blocked_by_cleanup || cleanup_failed(&p.cleanup) ||
       p.work_error.repository.cleanup_result!=VIREO_OK || p.repository.cleanup_pending)
        bits|=VIREO_DIRECTORY_LIST_WORKER_FAULT_CLEANUP;
    if(!p.publish_called || p.publish_result!=VIREO_OK || !p.publication.publication.completion_transferred)
        bits|=VIREO_DIRECTORY_LIST_WORKER_FAULT_PUBLISH;
    latch(r,bits);
    for(size_t i=0;owner && i<r->destroy_attempts;++i) {
        vireo_directory_list_worker_cleanup_report_t cleanup={0};
        vireo_result_t const cleaned=ops->destroy(ops->context,&owner,&cleanup);
        if(cleaned!=VIREO_OK || owner || cleanup_failed(&cleanup)) latch(r,VIREO_DIRECTORY_LIST_WORKER_FAULT_CLEANUP);
        if(rc==VIREO_OK) rc=cleaned;
    }
    if(owner) { latch(r,VIREO_DIRECTORY_LIST_WORKER_FAULT_RESIDUAL); _Exit(EXIT_FAILURE); }
done:
    errno=saved; return rc;
}

static vireo_result_t create(void *c,vireo_directory_list_worker_resources_t const *r,
    vireo_directory_list_worker_options_t const *o,vireo_directory_list_worker_t **owner)
{ (void)c; return vireo_directory_list_worker_create(r,o,owner); }
static vireo_result_t run(void *c,vireo_directory_list_worker_t *w,vireo_task_t const *t,vireo_directory_list_worker_report_t *p)
{ (void)c; return vireo_directory_list_worker_run(w,t,p); }
static vireo_result_t destroy(void *c,vireo_directory_list_worker_t **w,vireo_directory_list_worker_cleanup_report_t *p)
{ (void)c; return vireo_directory_list_worker_destroy(w,p); }
static vireo_result_t previous_execute(void *c,vireo_directory_root_worker_runtime_t *r,vireo_task_t const *t)
{ (void)c; return vireo_directory_root_worker_runtime_execute(r,t); }

vireo_result_t vireo_directory_list_worker_runtime_execute(void *context,vireo_task_t const *task)
{
    vireo_directory_list_worker_runtime_ops_t const ops={NULL,create,run,destroy,previous_execute};
    return vireo_directory_list_worker_runtime_execute_with(context,task,&ops);
}
