#include "directory_remove_worker_runtime_internal.h"
#include <errno.h>
#include <stdlib.h>

static void latch(vireo_directory_remove_worker_runtime_t *r,unsigned bits)
{ (void)atomic_fetch_or_explicit(&r->faults,bits,memory_order_relaxed); }
static bool cleanup_failed(vireo_directory_remove_worker_cleanup_report_t const *p)
{ return (p->repository_called && p->repository_result!=VIREO_OK) ||
    (p->detach_called && p->detach_result!=VIREO_OK) ||
    (p->completion_called && p->completion_result!=VIREO_OK) ||
    p->repository_pending || p->thread_pending || p->completion_pending; }

vireo_result_t vireo_directory_remove_worker_runtime_init(
    vireo_directory_remove_worker_runtime_t *runtime,vireo_directory_move_worker_runtime_t *previous,
    vireo_directory_remove_worker_resources_t const *r,vireo_directory_remove_worker_options_t const *o,size_t attempts)
{
    int const saved=errno; vireo_result_t rc=VIREO_RESULT_INVALID_ARGUMENT;
    if(!runtime || !previous || !r || !o || !r->runtime || !r->database || !r->queue || !r->notifier ||
       !o->execution.remove_operation || !o->completion_allocation_budget || !o->max_memory_bytes || !attempts) goto done;
    vireo_directory_move_worker_faults_t before;
    rc=vireo_directory_move_worker_runtime_inspect_faults(previous,&before); if(rc!=VIREO_OK) goto done;
    rc=VIREO_RESULT_BUSY;
    if(before.auth || before.stat || before.root || before.list || before.mkdir || before.move) goto done;
    vireo_auth_worker_runtime_t const *auth=previous->previous->previous->previous->previous->auth;
    vireo_completion_queue_t *const queues[]={auth->resources.queue,previous->resources.queue,previous->previous->resources.queue,
        previous->previous->previous->resources.queue,previous->previous->previous->previous->resources.queue,
        previous->previous->previous->previous->previous->resources.queue};
    uint32_t const operations[]={auth->options.execution.register_operation,auth->options.execution.login_operation,
        auth->options.execution.logout_operation,auth->options.execution.resume_operation,
        previous->previous->previous->previous->previous->options.execution.stat_operation,
        previous->previous->previous->previous->options.execution.root_operation,
        previous->previous->previous->options.execution.list_operation,previous->previous->options.execution.mkdir_operation,
        previous->options.execution.move_operation};
    if(r->runtime!=auth->resources.runtime || r->database!=auth->resources.database || r->notifier!=auth->resources.notifier) goto done;
    for(size_t i=0;i<6;++i) if(r->queue==queues[i]) goto done;
    for(size_t i=0;i<9;++i) if(o->execution.remove_operation==operations[i]) goto done;
    rc=VIREO_RESULT_RANGE;
    if(attempts>16 || o->execution.pool_timeout_ms>60000 || o->max_memory_bytes>(size_t)67108864 ||
       o->completion_allocation_budget>VIREO_COMPLETION_MAX_ALLOCATION_BYTES) goto done;
    atomic_uint probe; atomic_init(&probe,0); if(!atomic_is_lock_free(&probe)) { rc=VIREO_RESULT_INTERNAL; goto done; }
    runtime->previous=previous; runtime->resources=*r; runtime->options=*o; runtime->destroy_attempts=attempts;
    atomic_init(&runtime->faults,0); rc=VIREO_OK;
done: errno=saved; return rc;
}

vireo_result_t vireo_directory_remove_worker_runtime_inspect_faults(
    vireo_directory_remove_worker_runtime_t const *r,vireo_directory_remove_worker_faults_t *out)
{
    int const saved=errno; vireo_result_t rc=VIREO_RESULT_INVALID_ARGUMENT;
    if(r && out) {
        vireo_directory_move_worker_faults_t p={0};
        rc=vireo_directory_move_worker_runtime_inspect_faults(r->previous,&p);
        if(rc==VIREO_OK) { out->auth=p.auth; out->stat=p.stat; out->root=p.root; out->list=p.list; out->mkdir=p.mkdir; out->move=p.move; out->remove=atomic_load_explicit(&r->faults,memory_order_relaxed); }
    }
    errno=saved; return rc;
}

vireo_result_t vireo_directory_remove_worker_runtime_execute_with(
    vireo_directory_remove_worker_runtime_t *r,const vireo_task_t *task,const vireo_directory_remove_worker_runtime_ops_t *ops)
{
    int const saved=errno; vireo_result_t rc=VIREO_RESULT_INVALID_ARGUMENT;
    if(!r || !task || !ops || !ops->create || !ops->run || !ops->destroy || !ops->previous_execute) goto done;
    vireo_directory_remove_worker_faults_t faults;
    rc=vireo_directory_remove_worker_runtime_inspect_faults(r,&faults); if(rc!=VIREO_OK) goto done;
    if(faults.auth||faults.stat||faults.root||faults.list||faults.mkdir||faults.move||faults.remove) { rc=VIREO_RESULT_CANCELLED; goto done; }
    vireo_task_info_t info; rc=vireo_task_inspect(task,&info);
    if(rc!=VIREO_OK) { latch(r,VIREO_DIRECTORY_REMOVE_WORKER_FAULT_DISPATCH); goto done; }
    vireo_directory_move_worker_runtime_t const *previous=r->previous;
    vireo_auth_worker_runtime_t const *auth=previous->previous->previous->previous->previous->auth;
    bool const previous_operation =
        vireo_auth_task_command(&auth->options.execution,info.metadata.operation) ||
        info.metadata.operation==previous->previous->previous->previous->previous->options.execution.stat_operation ||
        info.metadata.operation==previous->previous->previous->previous->options.execution.root_operation ||
        info.metadata.operation==previous->previous->previous->options.execution.list_operation ||
        info.metadata.operation==previous->previous->options.execution.mkdir_operation ||
        info.metadata.operation==r->previous->options.execution.move_operation;
    if(!previous_operation && info.metadata.operation!=r->options.execution.remove_operation) {
        /* The shared pool can contain a task for another configured process stage;
         * it is not a REMOVE runtime fault and must not poison the worker domain. */
        rc=VIREO_RESULT_NOT_FOUND; goto done;
    }
    if(info.metadata.operation!=r->options.execution.remove_operation) {
        rc=ops->previous_execute(ops->context,r->previous,task);
        goto done;
    }
    vireo_directory_remove_worker_t *owner=NULL;
    rc=ops->create(ops->context,&r->resources,&r->options,&owner);
    if(rc!=VIREO_OK) { latch(r,VIREO_DIRECTORY_REMOVE_WORKER_FAULT_CREATE); goto done; }
    vireo_directory_remove_worker_report_t p={0}; rc=ops->run(ops->context,owner,task,&p);
    unsigned bits=0;
    if(!p.task_validated) bits|=VIREO_DIRECTORY_REMOVE_WORKER_FAULT_TASK;
    if(p.publication_blocked_by_cleanup || cleanup_failed(&p.cleanup) || p.work_error.cleanup_result!=VIREO_OK || p.service.repository.cleanup_pending) bits|=VIREO_DIRECTORY_REMOVE_WORKER_FAULT_CLEANUP;
    if(!p.publish_called || p.publish_result!=VIREO_OK || !p.publication.publication.completion_transferred) bits|=VIREO_DIRECTORY_REMOVE_WORKER_FAULT_PUBLISH;
    latch(r,bits);
    for(size_t i=0;owner && i<r->destroy_attempts;++i) {
        vireo_directory_remove_worker_cleanup_report_t clean={0};
        vireo_result_t const cleaned=ops->destroy(ops->context,&owner,&clean);
        if(cleaned!=VIREO_OK || owner || cleanup_failed(&clean)) latch(r,VIREO_DIRECTORY_REMOVE_WORKER_FAULT_CLEANUP);
        if(rc==VIREO_OK) rc=cleaned;
    }
    if(owner) { latch(r,VIREO_DIRECTORY_REMOVE_WORKER_FAULT_RESIDUAL); _Exit(EXIT_FAILURE); }
done: errno=saved; return rc;
}
static vireo_result_t create(void *c,vireo_directory_remove_worker_resources_t const *r,vireo_directory_remove_worker_options_t const *o,vireo_directory_remove_worker_t **owner)
{ (void)c; return vireo_directory_remove_worker_create(r,o,owner); }
static vireo_result_t run(void *c,vireo_directory_remove_worker_t *w,const vireo_task_t *t,vireo_directory_remove_worker_report_t *p)
{ (void)c; return vireo_directory_remove_worker_run(w,t,p); }
static vireo_result_t destroy(void *c,vireo_directory_remove_worker_t **w,vireo_directory_remove_worker_cleanup_report_t *p)
{ (void)c; return vireo_directory_remove_worker_destroy(w,p); }
static vireo_result_t previous_execute(void *c,vireo_directory_move_worker_runtime_t *r,const vireo_task_t *t)
{ (void)c; return vireo_directory_move_worker_runtime_execute(r,t); }
vireo_result_t vireo_directory_remove_worker_runtime_execute(void *context,const vireo_task_t *task)
{ const vireo_directory_remove_worker_runtime_ops_t ops={NULL,create,run,destroy,previous_execute}; return vireo_directory_remove_worker_runtime_execute_with(context,task,&ops); }
