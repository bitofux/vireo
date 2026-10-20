/* PROJECT : VIREO
 * FILE : auth_worker_runtime.c
 * AUTHOR : bitofux
 * DATE : 2026-10-20
 * BRIEF : 原线程owner清空才返回；错误类别与业务/交接事实分离。
 */
#include "auth_worker_runtime_internal.h"
#include <errno.h>
#include <stdlib.h>

vireo_result_t vireo_auth_worker_runtime_init(vireo_auth_worker_runtime_t *runtime,
    vireo_auth_worker_resources_t const *r,vireo_auth_worker_options_t const *o,size_t attempts)
{
    int const saved=errno;
    vireo_result_t rc=VIREO_RESULT_INVALID_ARGUMENT;
    if(!runtime || !r || !o || !r->runtime || !r->database || !r->gate || !r->verifier || !r->queue || !r->notifier ||
       !o->execution.register_operation || !o->execution.login_operation ||
       !vireo_auth_task_command(&o->execution,o->execution.register_operation) || !o->request_timeout_ns ||
       !o->session_lifetime_ms || !o->completion_allocation_budget || !o->max_memory_bytes || !attempts) goto done;
    rc=VIREO_RESULT_RANGE;
    if(attempts>16 || o->execution.pool_timeout_ms>60000 || o->max_memory_bytes>(size_t)67108864 ||
       o->completion_allocation_budget>VIREO_COMPLETION_MAX_ALLOCATION_BYTES) goto done;
    atomic_uint probe;
    atomic_init(&probe,0);
    rc=VIREO_RESULT_INTERNAL;
    if(!atomic_is_lock_free(&probe)) goto done;
    /* 原子字段不通过结构赋值复制；失败之前完全不写caller存储。 */
    runtime->resources=*r; runtime->options=*o; runtime->destroy_attempts=attempts;
    atomic_init(&runtime->faults,0);
    rc=VIREO_OK;
done:
    errno=saved; return rc;
}

vireo_result_t vireo_auth_worker_runtime_inspect_faults(vireo_auth_worker_runtime_t const *runtime,
    unsigned *out_faults)
{
    int const saved=errno;
    vireo_result_t rc=VIREO_RESULT_INVALID_ARGUMENT;
    if(runtime && out_faults) { *out_faults=atomic_load_explicit(&runtime->faults,memory_order_relaxed); rc=VIREO_OK; }
    errno=saved; return rc;
}

/**
 * @brief 无伴随payload发布，多个worker补充同一永久位集合
 * @param[in,out] runtime 必需已发布context，只有faults并发原子写。
 * @param[in] bits 本次已判明的五位子集，0也合法。
 * @note 不等待或保存指针，原子只表达自身；外层保持errno。
 */
static void latch(vireo_auth_worker_runtime_t *runtime,unsigned bits)
{ (void)atomic_fetch_or_explicit(&runtime->faults,bits,memory_order_relaxed); }

/**
 * @brief 按实际调用及残留判清理故障，不把未调用零值当成功证据
 * @param[in] p 必需独立存活的本次去敏清理报告，只借至返回。
 * @retval true 实际调用非OK或任一子owner残留。
 * @retval false 本报告未发现清理故障，不证明其他阶段/worker健康。
 * @note 只读，无资源操作；外层保持errno。
 */
static bool cleanup_failed(vireo_auth_worker_cleanup_report_t const *p)
{
    return (p->repository_called && p->repository_result!=VIREO_OK) ||
        (p->detach_called && p->detach_result!=VIREO_OK) ||
        (p->completion_called && p->completion_result!=VIREO_OK) ||
        p->repository_pending || p->thread_pending || p->completion_pending;
}

vireo_result_t vireo_auth_worker_runtime_execute_with(vireo_auth_worker_runtime_t *runtime,
    vireo_task_t const *task,vireo_auth_worker_runtime_ops_t const *ops)
{
    int const saved=errno;
    vireo_result_t rc=VIREO_RESULT_INVALID_ARGUMENT;
    if(!runtime || !task || !ops || !ops->create || !ops->run || !ops->destroy) goto done;
    if(atomic_load_explicit(&runtime->faults,memory_order_relaxed)) { rc=VIREO_RESULT_CANCELLED; goto done; }
    vireo_auth_worker_t *owner=NULL;
    rc=ops->create(ops->context,&runtime->resources,&runtime->options,&owner);
    if(rc!=VIREO_OK) { latch(runtime,VIREO_AUTH_WORKER_FAULT_CREATE); goto done; }
    vireo_auth_worker_report_t report={0};
    rc=ops->run(ops->context,owner,task,&report);
    unsigned bits=0;
    if(!report.task_validated) bits|=VIREO_AUTH_WORKER_FAULT_TASK;
    if(cleanup_failed(&report.cleanup)) bits|=VIREO_AUTH_WORKER_FAULT_CLEANUP;
    if(!report.publish_called || report.publish_result!=VIREO_OK ||
       !report.publication.publication.completion_transferred) bits|=VIREO_AUTH_WORKER_FAULT_PUBLISH;
    if(bits) latch(runtime,bits);
    for(size_t i=0;owner && i<runtime->destroy_attempts;++i) {
        vireo_auth_worker_cleanup_report_t cleanup={0};
        vireo_result_t const cleaned=ops->destroy(ops->context,&owner,&cleanup);
        if(cleaned!=VIREO_OK || owner || cleanup_failed(&cleanup)) latch(runtime,VIREO_AUTH_WORKER_FAULT_CLEANUP);
        if(rc==VIREO_OK) rc=cleaned;
    }
    if(owner) {
        latch(runtime,VIREO_AUTH_WORKER_FAULT_RESIDUAL);
        /* 应用明确选择结束进程，不能带同OS线程DB owner返回通用池。 */
        _Exit(EXIT_FAILURE);
    }
done:
    errno=saved; return rc;
}

static vireo_result_t create(void *c,vireo_auth_worker_resources_t const *r,
    vireo_auth_worker_options_t const *o,vireo_auth_worker_t **owner)
{ (void)c; return vireo_auth_worker_create(r,o,owner); }
static vireo_result_t run(void *c,vireo_auth_worker_t *w,vireo_task_t const *task,vireo_auth_worker_report_t *p)
{ (void)c; return vireo_auth_worker_run(w,task,p); }
static vireo_result_t destroy(void *c,vireo_auth_worker_t **owner,vireo_auth_worker_cleanup_report_t *p)
{ (void)c; return vireo_auth_worker_destroy(owner,p); }

vireo_result_t vireo_auth_worker_runtime_execute(void *context,vireo_task_t const *task)
{
    vireo_auth_worker_runtime_ops_t const ops={NULL,create,run,destroy};
    return vireo_auth_worker_runtime_execute_with(context,task,&ops);
}
