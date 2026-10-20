/*
 * PROJECT : VIREO
 * FILE    : auth_worker.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-20
 * BRIEF   : 一次执行与只清理恢复分离；真实owner决定线程资源寿命。
 */
#include "auth_worker_internal.h"
#include <vireo/base/secure_clear.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>

struct vireo_auth_worker {
    pthread_t thread; /**< 创建OS线程，仅活线程内比较，不允许移交至另一线程。 */
    vireo_auth_worker_resources_t resources; /**< 配对依赖长期借用副本。 */
    vireo_auth_worker_options_t options; /**< 不变政策副本，无默认超时。 */
    vireo_auth_worker_ops_t ops; /**< 本模块公开依赖操作副本。 */
    vireo_mysql_thread_t *guard; /**< 本worker attach产生，repository未空前不可detach。 */
    vireo_mysql_user_repository_t *repository; /**< 失败仍保留的同线程DB owner。 */
    vireo_completion_t *completion; /**< 仅未交接的独立完成对象，不持task。 */
    vireo_auth_worker_report_t report; /**< 永久attempted与去敏执行事实，无token。 */
};

/* 标准操作只沿公开依赖调用，不读其他模块私有布局。 */
static void *allocate(void *c, size_t bytes) { (void)c; return calloc(1, bytes); }
static void release(void *c, void *p) { (void)c; free(p); }
static vireo_result_t attach(void *c, vireo_mysql_runtime_t *r, vireo_mysql_thread_t **t, vireo_mysql_error_t *e)
{ (void)c; return vireo_mysql_thread_attach(r,t,e); }
static vireo_result_t repository_create(void *c, vireo_mysql_thread_t *t, vireo_mysql_pool_t *p,
    vireo_password_policy_t const *policy, vireo_mysql_user_repository_t **r, vireo_mysql_user_repository_error_t *e)
{ (void)c; return vireo_mysql_user_repository_create(t,p,policy,r,e); }
static vireo_result_t capture(void *c, vireo_task_t const *t, uint64_t received, uint64_t lifetime, vireo_auth_task_options_t const *options,
    vireo_auth_task_context_t *out, vireo_auth_context_error_t *e)
{ (void)c; return vireo_auth_task_context_capture(t,received,lifetime,options,out,e); }
static vireo_result_t execute(void *c, vireo_task_t const *t, vireo_auth_task_context_t const *context,
    vireo_auth_task_options_t const *o, vireo_mysql_user_repository_t *r, vireo_auth_password_gate_t *g,
    vireo_auth_login_verifier_t const *v, vireo_auth_task_result_t *out)
{ (void)c; return vireo_auth_task_execute(t,context,o,r,g,v,out); }
static vireo_result_t repository_destroy(void *c, vireo_mysql_user_repository_t **r, vireo_mysql_user_repository_error_t *e)
{ (void)c; return vireo_mysql_user_repository_destroy(r,e); }
static vireo_result_t detach(void *c, vireo_mysql_thread_t **t)
{ (void)c; return vireo_mysql_thread_detach(t); }
static vireo_result_t publish(void *c, vireo_task_t const *t, vireo_auth_task_result_t const *result,
    size_t budget, vireo_completion_queue_t *q, vireo_notifier_t *n, vireo_completion_t **remaining,
    vireo_auth_completion_publish_report_t *report)
{ (void)c; return vireo_auth_completion_publish(t,result,budget,q,n,remaining,report); }
static vireo_result_t completion_destroy(void *c, vireo_completion_t **owner)
{ (void)c; return vireo_completion_destroy(owner); }

vireo_result_t vireo_auth_worker_create_with(vireo_auth_worker_resources_t const *r,
    vireo_auth_worker_options_t const *o, vireo_auth_worker_t **owner, vireo_auth_worker_ops_t const *ops)
{
    int const saved = errno;
    vireo_result_t rc = VIREO_RESULT_INVALID_ARGUMENT;
    if (!r || !o || !owner || *owner || !r->runtime || !r->database || !r->gate || !r->verifier ||
        !r->queue || !r->notifier || !o->execution.register_operation || !o->execution.login_operation ||
        !vireo_auth_task_command(&o->execution,o->execution.register_operation) || !o->request_timeout_ns ||
        !o->session_lifetime_ms || !o->completion_allocation_budget || !o->max_memory_bytes ||
        !ops || !ops->allocate || !ops->release || !ops->attach || !ops->repository_create ||
        !ops->capture || !ops->execute || !ops->repository_destroy || !ops->detach || !ops->publish ||
        !ops->completion_destroy) goto done;
    rc = VIREO_RESULT_RANGE;
    if (o->execution.pool_timeout_ms > 60000 || o->max_memory_bytes > (size_t)67108864 ||
        o->max_memory_bytes < sizeof(vireo_auth_worker_t) ||
        o->completion_allocation_budget > VIREO_COMPLETION_MAX_ALLOCATION_BYTES) goto done;
    vireo_auth_worker_t *w = ops->allocate(ops->context,sizeof(*w));
    rc = VIREO_RESULT_NO_MEMORY;
    if (!w) goto done;
    *w = (vireo_auth_worker_t){.thread=pthread_self(),.resources=*r,.options=*o,.ops=*ops};
    *owner = w;
    rc = VIREO_OK;
done:
    errno = saved;
    return rc;
}

vireo_result_t vireo_auth_worker_create(vireo_auth_worker_resources_t const *r,
    vireo_auth_worker_options_t const *o, vireo_auth_worker_t **owner)
{
    vireo_auth_worker_ops_t const ops = {NULL,allocate,release,attach,repository_create,capture,execute,
        repository_destroy,detach,publish,completion_destroy};
    return vireo_auth_worker_create_with(r,o,owner,&ops);
}

/**
 * @brief 各owner每次最多清一次，repo未消费时禁止结束其线程guard
 * @param[in,out] w 必需当前OS线程独占对象，依赖存活。
 * @param[out] p 必需独立输出，覆盖本次清理及剩余事实。
 * @return 首清理错误；没有错误不代表caller可以丢弃仍存活的依赖。
 * @note 不重做业务/发布；当前私有操作表保证原公开owner合同，外层保持errno。
 */
static vireo_result_t cleanup(vireo_auth_worker_t *w, vireo_auth_worker_cleanup_report_t *p)
{
    *p = (vireo_auth_worker_cleanup_report_t){0};
    vireo_result_t rc = VIREO_OK;
    if (w->repository) {
        p->repository_called = true;
        p->repository_result = w->ops.repository_destroy(w->ops.context,&w->repository,&p->repository_error);
        rc = p->repository_result;
    }
    if (!w->repository && w->guard) {
        p->detach_called = true;
        p->detach_result = w->ops.detach(w->ops.context,&w->guard);
        if (rc == VIREO_OK) rc = p->detach_result;
    }
    if (w->completion) {
        p->completion_called = true;
        p->completion_result = w->ops.completion_destroy(w->ops.context,&w->completion);
        if (rc == VIREO_OK) rc = p->completion_result;
    }
    p->repository_pending = w->repository != NULL;
    p->thread_pending = w->guard != NULL;
    p->completion_pending = w->completion != NULL;
    return rc;
}

/**
 * @brief 对原独立task核验命令和元数据，未通过前不获取DB资源
 * @param[in] w 必需当前线程存活owner，只读选项。
 * @param[in] task 必需当前调用短借，不能保存。
 * @param[out] r 必需已零局部执行结果，失败允许保inspect/decode前缀。
 * @return 原inspect/borrow/decode结果；关联错误INVALID_ARGUMENT；期限不足RANGE。
 * @note 不认证metadata来源，无分配；临时view只借task，调用结束不保留。
 */
static vireo_result_t validate(vireo_auth_worker_t *w, vireo_task_t const *task,
    vireo_auth_task_result_t *r)
{
    vireo_task_info_t info;
    vireo_result_t rc = vireo_task_inspect(task,&info);
    if (rc != VIREO_OK) return rc;
    r->metadata = info.metadata;
    vireo_auth_request_view_t view; vireo_auth_logout_identity_t target;
    vireo_command_t const command=vireo_auth_task_command(&w->options.execution,info.metadata.operation);
    if(!command) return VIREO_RESULT_INVALID_ARGUMENT;
    rc=vireo_auth_task_borrow_request(task,command,&view,&target,&r->request_issue);
    if(rc!=VIREO_OK) return r->request_issue==VIREO_AUTH_REQUEST_ISSUE_ENVELOPE?VIREO_RESULT_INVALID_ARGUMENT:rc;
    r->command=view.command; r->logout_target=target;
    if (info.metadata.deadline_ns < w->options.request_timeout_ns) return VIREO_RESULT_RANGE;
    return VIREO_OK;
}

vireo_result_t vireo_auth_worker_run(vireo_auth_worker_t *w, vireo_task_t const *task,
    vireo_auth_worker_report_t *report)
{
    int const saved = errno;
    vireo_result_t rc = VIREO_RESULT_INVALID_ARGUMENT;
    vireo_auth_task_result_t result = {.stage=VIREO_AUTH_TASK_CONTEXT};
    vireo_auth_task_context_t context = {0};
    if (report) *report = (vireo_auth_worker_report_t){0};
    if (!w || !task || !report || !pthread_equal(w->thread,pthread_self())) goto done;
    if (w->report.attempted) { *report = w->report; rc = VIREO_RESULT_BUSY; goto done; }
    w->report.attempted = true;
    rc = validate(w,task,&result);
    if (rc != VIREO_OK) goto completed;
    w->report.task_validated = true;
    w->report.attach_called = true;
    rc = w->ops.attach(w->ops.context,w->resources.runtime,&w->guard,&w->report.attach_error);
    if (rc != VIREO_OK) goto completed;
    w->report.repository_called = true;
    rc = w->ops.repository_create(w->ops.context,w->guard,w->resources.database,
        &w->options.password,&w->repository,&w->report.work_error);
    if (rc != VIREO_OK) goto completed;
    w->report.capture_called = true;
    rc = w->ops.capture(w->ops.context,task,result.metadata.deadline_ns-w->options.request_timeout_ns,
        w->options.session_lifetime_ms,&w->options.execution,&context,&w->report.context_error);
    if (rc != VIREO_OK) goto completed;
    w->report.execute_called = true;
    rc = w->ops.execute(w->ops.context,task,&context,&w->options.execution,w->repository,
        w->resources.gate,w->resources.verifier,&result);
    w->report.work_error = result.error;
completed:
    result.result = rc;
    w->report.metadata = result.metadata;
    w->report.command = result.command;
    w->report.request_issue = result.request_issue;
    w->report.work_result = rc;
    w->report.work_stage = result.stage;
    w->report.registration = result.registration;
    w->report.lookup = result.login.lookup;
    w->report.transaction = result.login.transaction;
    w->report.resume_identity=result.resume_identity; w->report.resume_report=result.resume_report;
    w->report.logout_target=result.logout_target; w->report.logout_report=result.logout_report;
    if (w->resources.audit && w->report.execute_called) {
        vireo_auth_failure_event_t event={0};
        if (vireo_auth_failure_event_from_task(&result,&context,&event)==VIREO_OK) {
            uint64_t now=0; vireo_auth_failure_disposition_t disposition;
            if (vireo_clock_monotonic_now(&now,NULL)==VIREO_OK)
                (void)vireo_auth_failure_audit_try_offer(w->resources.audit,&event,now,&disposition);
        }
        (void)vireo_secure_clear(&event,sizeof(event));
    }
    vireo_result_t const cleaned = cleanup(w,&w->report.cleanup);
    if (w->report.task_validated) {
        w->report.publish_called = true;
        w->report.publish_result = w->ops.publish(w->ops.context,task,&result,
            w->options.completion_allocation_budget,w->resources.queue,w->resources.notifier,
            &w->completion,&w->report.publication);
    }
    w->report.completion_pending = w->completion != NULL;
    if (rc == VIREO_OK) rc = cleaned;
    if (rc == VIREO_OK && w->report.publish_called) rc = w->report.publish_result;
    *report = w->report;
done:
    (void)vireo_auth_task_result_clear(&result);
    (void)vireo_secure_clear(&context,sizeof(context));
    errno = saved;
    return rc;
}

vireo_result_t vireo_auth_worker_destroy(vireo_auth_worker_t **owner,
    vireo_auth_worker_cleanup_report_t *report)
{
    int const saved = errno;
    vireo_result_t rc = VIREO_RESULT_INVALID_ARGUMENT;
    if (report) *report = (vireo_auth_worker_cleanup_report_t){0};
    if (!owner || !report) goto done;
    if (!*owner) { rc = VIREO_OK; goto done; }
    vireo_auth_worker_t *w = *owner;
    if (!pthread_equal(w->thread,pthread_self())) goto done;
    rc = cleanup(w,report);
    if (!w->repository && !w->guard && !w->completion) {
        vireo_auth_worker_ops_t const ops = w->ops;
        (void)vireo_secure_clear(w,sizeof(*w));
        ops.release(ops.context,w);
        *owner = NULL;
    }
done:
    errno = saved;
    return rc;
}
