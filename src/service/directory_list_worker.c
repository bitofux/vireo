/* PROJECT : VIREO; FILE : directory_list_worker.c; AUTHOR : bitofux;
 * DATE : 2026-10-23; BRIEF : LIST原线程单次执行、真实owner清理门禁与一次发布。 */
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <vireo/base/secure_clear.h>
#include "directory_list_worker_internal.h"

struct vireo_directory_list_worker {
    pthread_t thread; /**< 创建线程，所有owner操作必须同线程。 */
    vireo_directory_list_worker_resources_t resources; /**< 五项长期只读借用。 */
    vireo_directory_list_worker_options_t options;     /**< 不变值配置。 */
    vireo_directory_list_worker_ops_t ops;             /**< 本层独立操作表。 */
    vireo_mysql_thread_t *guard;                 /**< 原线程独占，repo空后才能detach。 */
    vireo_mysql_node_repository_t *repository;   /**< 原线程独占残留清理责任。 */
    vireo_completion_t *remaining;               /**< 仅未交接的独立完成对象。 */
    vireo_directory_list_worker_report_t report; /**< 去敏缓存，不存页或key。 */
    vireo_directory_list_task_result_t workspace; /**< 大结果计入本层heap预算，run出口擦除。 */
};
_Static_assert(sizeof(vireo_directory_list_task_result_t) <= 24576, "LIST task result budget");

static void *native_allocate(void *c, size_t n) {
    (void)c;
    return malloc(n);
}
static void native_release(void *c, void *p) {
    (void)c;
    free(p);
}
static vireo_result_t native_attach(void *c, vireo_mysql_runtime_t *r, vireo_mysql_thread_t **g,
                                    vireo_mysql_error_t *e) {
    (void)c;
    return vireo_mysql_thread_attach(r, g, e);
}
static vireo_result_t native_repository(void *c, vireo_mysql_thread_t *g, vireo_mysql_pool_t *p,
                                        vireo_mysql_node_repository_t **r,
                                        vireo_mysql_node_error_t *e) {
    (void)c;
    return vireo_mysql_node_repository_create(g, p, r, e);
}
static vireo_result_t native_clock(void *c, uint64_t *now, vireo_clock_error_t *e) {
    (void)c;
    return vireo_clock_monotonic_now(now, e);
}
static vireo_result_t native_execute(void *c, const vireo_task_t *t,
                                     const vireo_directory_list_task_options_t *o,
                                     vireo_mysql_node_repository_t *r,
                                     const vireo_page_token_key_t *k, uint64_t now,
                                     vireo_directory_list_task_result_t *v) {
    (void)c;
    return vireo_directory_list_task_execute(t, o, r, k, now, v);
}
static vireo_result_t native_destroy_repository(void *c, vireo_mysql_node_repository_t **r,
                                                vireo_mysql_node_error_t *e) {
    (void)c;
    return vireo_mysql_node_repository_destroy(r, e);
}
static vireo_result_t native_detach(void *c, vireo_mysql_thread_t **g) {
    (void)c;
    return vireo_mysql_thread_detach(g);
}
static vireo_result_t native_publish(void *c, const vireo_task_t *t, uint32_t op,
                                     const vireo_directory_list_task_result_t *v, size_t b,
                                     vireo_completion_queue_t *q, vireo_notifier_t *n,
                                     vireo_completion_t **o,
                                     vireo_directory_list_completion_publish_report_t *p) {
    (void)c;
    return vireo_directory_list_completion_publish(t, op, v, b, q, n, o, p);
}
static vireo_result_t native_destroy_completion(void *c, vireo_completion_t **o) {
    (void)c;
    return vireo_completion_destroy(o);
}
static const vireo_directory_list_worker_ops_t native_ops = {
    NULL,           native_allocate,           native_release,
    native_attach,  native_repository,         native_clock,
    native_execute, native_destroy_repository, native_detach,
    native_publish, native_destroy_completion};

vireo_result_t vireo_directory_list_worker_create_with(
    const vireo_directory_list_worker_resources_t *r,
    const vireo_directory_list_worker_options_t *o, vireo_directory_list_worker_t **owner,
    const vireo_directory_list_worker_ops_t *ops) {
    const int saved = errno;
    vireo_result_t rc = VIREO_RESULT_INVALID_ARGUMENT;
    if (!r || !o || !owner || *owner || !ops || !r->runtime || !r->key || !r->database ||
        !r->queue || !r->notifier || !o->execution.list_operation ||
        !o->completion_allocation_budget || !o->max_memory_bytes || !ops->allocate ||
        !ops->release || !ops->attach || !ops->repository_create || !ops->clock || !ops->execute ||
        !ops->repository_destroy || !ops->detach || !ops->publish || !ops->completion_destroy)
        goto done;
    if (o->execution.pool_timeout_ms > 60000 ||
        o->completion_allocation_budget > VIREO_COMPLETION_MAX_ALLOCATION_BYTES ||
        o->max_memory_bytes > (size_t)67108864 || o->max_memory_bytes < sizeof(**owner)) {
        rc = VIREO_RESULT_RANGE;
        goto done;
    }
    vireo_directory_list_worker_t *w = ops->allocate(ops->context, sizeof(*w));
    if (!w) {
        rc = VIREO_RESULT_NO_MEMORY;
        goto done;
    }
    memset(w, 0, sizeof(*w));
    w->thread = pthread_self();
    w->resources = *r;
    w->options = *o;
    w->ops = *ops;
    *owner = w;
    rc = VIREO_OK;
done:
    errno = saved;
    return rc;
}
vireo_result_t vireo_directory_list_worker_create(const vireo_directory_list_worker_resources_t *r,
                                                  const vireo_directory_list_worker_options_t *o,
                                                  vireo_directory_list_worker_t **owner) {
    return vireo_directory_list_worker_create_with(r, o, owner, &native_ops);
}

/**
 * @brief 原线程按repo→guard顺序清理，destroy时另外消费未交接completion。
 * @param[in,out] w 创建线程独占控制块；每个子owner本次至多尝试一次。
 * @param[in] completion 是否包含未交接结果的显式丢弃。
 * @param[out] p 本次清零报告，保存各原返回和实际残留。
 * @retval VIREO_OK 操作全成功且实际owner全部空。
 * @retval VIREO_RESULT_INTERNAL 依赖称OK但仍有owner，禁止发布。
 * @return 其余为首个真实清理失败；返回非OK也可能已消费。
 * @note repo残留不detach，无内部重试；仅调用对应操作表，不释放外部借用。
 */
static vireo_result_t cleanup(vireo_directory_list_worker_t *w, bool completion,
                              vireo_directory_list_worker_cleanup_report_t *p) {
    memset(p, 0, sizeof(*p));
    vireo_result_t first = VIREO_OK;
    if (w->repository) {
        p->repository_called = true;
        p->repository_result =
            w->ops.repository_destroy(w->ops.context, &w->repository, &p->repository_error);
        first = p->repository_result;
    }
    if (!w->repository && w->guard) {
        p->detach_called = true;
        p->detach_result = w->ops.detach(w->ops.context, &w->guard);
        if (first == VIREO_OK)
            first = p->detach_result;
    }
    if (completion && w->remaining) {
        p->completion_called = true;
        p->completion_result = w->ops.completion_destroy(w->ops.context, &w->remaining);
        if (first == VIREO_OK)
            first = p->completion_result;
    }
    p->repository_pending = w->repository != NULL;
    p->thread_pending = w->guard != NULL;
    p->completion_pending = w->remaining != NULL;
    if (first == VIREO_OK && (p->repository_pending || p->thread_pending || p->completion_pending))
        first = VIREO_RESULT_INTERNAL;
    return first;
}

vireo_result_t vireo_directory_list_worker_run(vireo_directory_list_worker_t *w,
                                               const vireo_task_t *task,
                                               vireo_directory_list_worker_report_t *report) {
    const int saved = errno;
    vireo_result_t rc = VIREO_RESULT_INVALID_ARGUMENT;
    if (report)
        memset(report, 0, sizeof(*report));
    if (!w || !task || !report || !pthread_equal(w->thread, pthread_self()))
        goto done;
    if (w->report.attempted) {
        *report = w->report;
        rc = VIREO_RESULT_BUSY;
        goto done;
    }
    vireo_directory_list_worker_report_t *p = &w->report;
    vireo_directory_list_task_result_t *v = &w->workspace;
    p->attempted = true;
    v->stage = VIREO_DIRECTORY_LIST_TASK_DECODE;
    rc = vireo_directory_list_task_read(task, w->options.execution.list_operation, &v->input,
                                        &v->request_issue);
    if (rc != VIREO_OK) {
        p->work_result = rc;
        p->work_stage = v->stage;
        p->request_issue = v->request_issue;
        goto finish;
    }
    p->task_validated = true;
    p->metadata = v->input.metadata;
    v->stage = VIREO_DIRECTORY_LIST_TASK_CONTEXT;
    p->attach_called = true;
    rc = w->ops.attach(w->ops.context, w->resources.runtime, &w->guard, &p->attach_error);
    if (rc == VIREO_OK && !w->guard)
        rc = VIREO_RESULT_INTERNAL;
    if (rc == VIREO_OK) {
        p->repository_called = true;
        rc = w->ops.repository_create(w->ops.context, w->guard, w->resources.database,
                                      &w->repository, &p->repository_create_error);
        if (rc == VIREO_OK && !w->repository)
            rc = VIREO_RESULT_INTERNAL;
    }
    uint64_t now = 0;
    if (rc == VIREO_OK) {
        p->clock_called = true;
        rc = w->ops.clock(w->ops.context, &now, &p->clock_error);
    }
    if (rc == VIREO_OK) {
        p->execute_called = true;
        rc = w->ops.execute(w->ops.context, task, &w->options.execution, w->repository,
                            w->resources.key, now, v);
    } else
        v->result = rc;
    p->work_result = rc;
    p->work_stage = v->stage;
    p->request_issue = v->request_issue;
    p->work_error = v->error;
    p->outcome = v->service.outcome;
    p->repository_operation = v->service.repository_operation;
    p->repository_result = v->service.repository_result;
    p->repository = v->service.repository;
    p->token_checked = v->service.token_checked;
    p->token_result = v->service.token_result;
    const vireo_result_t cleanup_rc = cleanup(w, false, &p->cleanup);
    p->publication_blocked_by_cleanup = cleanup_rc != VIREO_OK;
    if (cleanup_rc == VIREO_OK) {
        p->publish_called = true;
        p->publish_result =
            w->ops.publish(w->ops.context, task, w->options.execution.list_operation, v,
                           w->options.completion_allocation_budget, w->resources.queue,
                           w->resources.notifier, &w->remaining, &p->publication);
    }
    p->completion_pending = w->remaining != NULL;
    if (rc == VIREO_OK)
        rc = cleanup_rc;
    if (rc == VIREO_OK)
        rc = p->publish_result;
finish:
    (void)vireo_secure_clear(&w->workspace, sizeof(w->workspace));
    *report = *p;
done:
    errno = saved;
    return rc;
}

vireo_result_t vireo_directory_list_worker_destroy(
    vireo_directory_list_worker_t **owner, vireo_directory_list_worker_cleanup_report_t *report) {
    const int saved = errno;
    vireo_result_t rc = VIREO_RESULT_INVALID_ARGUMENT;
    if (report)
        memset(report, 0, sizeof(*report));
    if (!owner || !report)
        goto done;
    vireo_directory_list_worker_t *w = *owner;
    if (!w) {
        rc = VIREO_OK;
        goto done;
    }
    if (!pthread_equal(w->thread, pthread_self()))
        goto done;
    rc = cleanup(w, true, report);
    if (!w->guard && !w->repository && !w->remaining) {
        void (*release)(void *, void *) = w->ops.release;
        void *context = w->ops.context;
        (void)vireo_secure_clear(w, sizeof(*w));
        release(context, w);
        *owner = NULL;
    }
done:
    errno = saved;
    return rc;
}
