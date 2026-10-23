/*
 * PROJECT : VIREO
 * FILE    : directory_mkdir_worker.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-24
 * BRIEF   : 目录创建内部桥接与原线程所有权。
 */
#include <errno.h>
#include <openssl/rand.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <vireo/base/secure_clear.h>
#include "directory_mkdir_worker_internal.h"

struct vireo_directory_mkdir_worker {
    pthread_t thread;                                   /**< 创建线程，禁止移交。 */
    vireo_directory_mkdir_worker_resources_t resources; /**< 四个长期借用指针。 */
    vireo_directory_mkdir_worker_options_t options;     /**< 不变配置。 */
    vireo_directory_mkdir_worker_ops_t ops; /**< 本层公开依赖及借用context。 */
    vireo_mysql_thread_t *guard;            /**< 本层原线程owner，repo清空后才detach。 */
    vireo_mysql_node_repository_t *repository; /**< 同线程数据库owner，失败可残留。 */
    vireo_completion_t *completion; /**< 仅未交接对象，destroy时显式丢弃。 */
    vireo_directory_mkdir_worker_report_t report; /**< 永久attempted及受控原写事实，含原IDs/key。 */
};
/** @brief 申请本worker独占的清零控制块。
 * @param[in] c 未使用。
 * @param[in] n 已由create核定的sizeof控制块。
 * @return 新owner或NULL；由release配对释放。
 * @note calloc可能改errno；外层入口负责保持。
 */
static void *allocate(void *c, size_t n) {
    (void)c;
    return calloc(1, n);
}
/** @brief 释放已清空子owner且已擦除的控制块。
 * @param[in] c 未使用。
 * @param[in] p 本allocator返回的独占地址，消费后不可访问。
 * @note 原创建线程调用；外层入口保持errno。
 */
static void release(void *c, void *p) {
    (void)c;
    free(p);
}
/** @brief 私有注入接点同步转发MySQL线程attach。
 * @param[in] c 未使用；其余参数遵守所调用公开接口合同。
 * @param[in,out] t 借用独立地址，线程guard所有权/输出遵守公开合同。
 * @return 公开接口原rc，不重试、不重写诊断。
 * @note 原创建线程调用，依赖由caller保活；外层入口保持errno。
 */
static vireo_result_t attach(void *c, vireo_mysql_runtime_t *r, vireo_mysql_thread_t **t,
                             vireo_mysql_error_t *e) {
    (void)c;
    return vireo_mysql_thread_attach(r, t, e);
}
/** @brief 私有注入接点同步转发公开repo create。
 * @param[in] c 未使用；其余参数遵守所调用公开接口合同。
 * @param[in,out] r 借用独立地址，repo所有权/输出遵守公开合同。
 * @return 公开接口原rc，不重试、不重写诊断。
 * @note 原创建线程调用，依赖由caller保活；外层入口保持errno。
 */
static vireo_result_t create_repo(void *c, vireo_mysql_thread_t *t, vireo_mysql_pool_t *p,
                                  vireo_mysql_node_repository_t **r, vireo_mysql_node_error_t *e) {
    (void)c;
    return vireo_mysql_node_repository_create(t, p, r, e);
}
/** @brief 一次生成独立的私有随机执行事件。
 * @param[in] c 未使用。
 * @param[out] out 独占16字节；失败也可能部分写入。
 * @return RAND_priv_bytes原整数；外层另核非零并擦除失败字节。
 * @note 同步调用，无重试；外层入口保持errno。
 */
static int random_event(void *c, unsigned char out[16]) {
    (void)c;
    return RAND_priv_bytes(out, 16);
}
/** @brief 私有注入接点同步转发公开MONOTONIC采时。
 * @param[in] c 未使用；其余参数遵守所调用公开接口合同。
 * @param[in,out] now 借用独立地址，纳秒值所有权/输出遵守公开合同。
 * @return 公开接口原rc，不重试、不重写诊断。
 * @note 原创建线程调用，依赖由caller保活；外层入口保持errno。
 */
static vireo_result_t clock_now(void *c, uint64_t *now, vireo_clock_error_t *e) {
    (void)c;
    return vireo_clock_monotonic_now(now, e);
}
/** @brief 私有注入接点同步转发公开task execute。
 * @param[in] c 未使用；其余参数遵守所调用公开接口合同。
 * @param[in,out] out 借用独立地址，完整执行结果所有权/输出遵守公开合同。
 * @return 公开接口原rc，不重试、不重写诊断。
 * @note 原创建线程调用，依赖由caller保活；外层入口保持errno。
 */
static vireo_result_t execute(void *c, const vireo_task_t *t,
                              const vireo_directory_mkdir_task_options_t *o,
                              vireo_mysql_node_repository_t *r, const unsigned char event[16],
                              uint64_t now, vireo_directory_mkdir_task_result_t *out) {
    (void)c;
    return vireo_directory_mkdir_task_execute(t, o, r, event, now, out);
}
/** @brief 私有注入接点同步转发公开repo destroy。
 * @param[in] c 未使用；其余参数遵守所调用公开接口合同。
 * @param[in,out] r 借用独立地址，repo所有权/输出遵守公开合同。
 * @return 公开接口原rc，不重试、不重写诊断。
 * @note 原创建线程调用，依赖由caller保活；外层入口保持errno。
 */
static vireo_result_t destroy_repo(void *c, vireo_mysql_node_repository_t **r,
                                   vireo_mysql_node_error_t *e) {
    (void)c;
    return vireo_mysql_node_repository_destroy(r, e);
}
/** @brief 私有注入接点同步转发公开thread detach。
 * @param[in] c 未使用；其余参数遵守所调用公开接口合同。
 * @param[in,out] t 借用独立地址，线程guard所有权/输出遵守公开合同。
 * @return 公开接口原rc，不重试、不重写诊断。
 * @note 原创建线程调用，依赖由caller保活；外层入口保持errno。
 */
static vireo_result_t detach(void *c, vireo_mysql_thread_t **t) {
    (void)c;
    return vireo_mysql_thread_detach(t);
}
/** @brief 私有注入接点同步转发公开完成交接。
 * @param[in] c 未使用；其余参数遵守所调用公开接口合同。
 * @param[in,out] left 借用独立地址，未交接completion所有权/输出遵守公开合同。
 * @return 公开接口原rc，不重试、不重写诊断。
 * @note 原创建线程调用，依赖由caller保活；外层入口保持errno。
 */
static vireo_result_t publish(void *c, const vireo_task_t *t, uint32_t op,
                              const vireo_directory_mkdir_task_result_t *r, size_t budget,
                              vireo_completion_queue_t *q, vireo_notifier_t *n,
                              vireo_completion_t **left,
                              vireo_directory_mkdir_completion_publish_report_t *p) {
    (void)c;
    return vireo_directory_mkdir_completion_publish(t, op, r, budget, q, n, left, p);
}
/** @brief 私有注入接点同步转发公开completion destroy。
 * @param[in] c 未使用；其余参数遵守所调用公开接口合同。
 * @param[in,out] owner 借用独立地址，未交接completion所有权/输出遵守公开合同。
 * @return 公开接口原rc，不重试、不重写诊断。
 * @note 原创建线程调用，依赖由caller保活；外层入口保持errno。
 */
static vireo_result_t destroy_completion(void *c, vireo_completion_t **owner) {
    (void)c;
    return vireo_completion_destroy(owner);
}

vireo_result_t vireo_directory_mkdir_worker_create_with(
    const vireo_directory_mkdir_worker_resources_t *r,
    const vireo_directory_mkdir_worker_options_t *o, vireo_directory_mkdir_worker_t **owner,
    const vireo_directory_mkdir_worker_ops_t *ops) {
    const int saved = errno;
    vireo_result_t rc = VIREO_RESULT_INVALID_ARGUMENT;
    if (!r || !o || !owner || *owner || !r->runtime || !r->database || !r->queue || !r->notifier ||
        !o->execution.mkdir_operation || !o->completion_allocation_budget || !o->max_memory_bytes ||
        !ops || !ops->allocate || !ops->release || !ops->attach || !ops->repository_create ||
        !ops->random || !ops->clock || !ops->execute || !ops->repository_destroy || !ops->detach ||
        !ops->publish || !ops->completion_destroy)
        goto done;
    rc = VIREO_RESULT_RANGE;
    if (o->execution.pool_timeout_ms > 60000 || o->max_memory_bytes > (size_t)67108864 ||
        o->max_memory_bytes < sizeof(vireo_directory_mkdir_worker_t) ||
        o->completion_allocation_budget > VIREO_COMPLETION_MAX_ALLOCATION_BYTES)
        goto done;
    vireo_directory_mkdir_worker_t *w = ops->allocate(ops->context, sizeof(*w));
    rc = VIREO_RESULT_NO_MEMORY;
    if (!w)
        goto done;
    *w = (vireo_directory_mkdir_worker_t){
        .thread = pthread_self(), .resources = *r, .options = *o, .ops = *ops};
    *owner = w;
    rc = VIREO_OK;
done:
    errno = saved;
    return rc;
}
vireo_result_t vireo_directory_mkdir_worker_create(
    const vireo_directory_mkdir_worker_resources_t *r,
    const vireo_directory_mkdir_worker_options_t *o, vireo_directory_mkdir_worker_t **owner) {
    const vireo_directory_mkdir_worker_ops_t ops = {
        NULL,      allocate, release,      attach, create_repo, random_event,
        clock_now, execute,  destroy_repo, detach, publish,     destroy_completion};
    return vireo_directory_mkdir_worker_create_with(r, o, owner, &ops);
}
/* 每次每owner只试一次，真实owner残留即使rc为OK也不能解除门禁。 */
/** @brief 原线程每子owner至多清理一次，并记录真实残留。
 * @param[in,out] w 创建线程独占控制块，外部资源仍保活。
 * @param[out] p 独立报告，入口清零，保存各原rc与owner残留。
 * @return 首个清理错误；原rc全OK但owner残留时INTERNAL。
 * @note repo空后才detach；仅消费本层owner，不发布或重新执行SQL。
 *     外层保持errno；不释放w，只有destroy在全部子owner空时释放。
 */
static vireo_result_t cleanup(vireo_directory_mkdir_worker_t *w,
                              vireo_directory_mkdir_worker_cleanup_report_t *p) {
    memset(p, 0, sizeof(*p));
    vireo_result_t rc = VIREO_OK;
    if (w->repository) {
        p->repository_called = true;
        p->repository_result =
            w->ops.repository_destroy(w->ops.context, &w->repository, &p->repository_error);
        rc = p->repository_result;
    }
    if (!w->repository && w->guard) {
        p->detach_called = true;
        p->detach_result = w->ops.detach(w->ops.context, &w->guard);
        if (rc == VIREO_OK)
            rc = p->detach_result;
    }
    if (w->completion) {
        p->completion_called = true;
        p->completion_result = w->ops.completion_destroy(w->ops.context, &w->completion);
        if (rc == VIREO_OK)
            rc = p->completion_result;
    }
    p->repository_pending = w->repository != NULL;
    p->thread_pending = w->guard != NULL;
    p->completion_pending = w->completion != NULL;
    if (rc == VIREO_OK && (w->repository || w->guard || w->completion))
        rc = VIREO_RESULT_INTERNAL;
    return rc;
}
vireo_result_t vireo_directory_mkdir_worker_run(vireo_directory_mkdir_worker_t *w,
                                                const vireo_task_t *task,
                                                vireo_directory_mkdir_worker_report_t *report) {
    const int saved = errno;
    vireo_result_t rc = VIREO_RESULT_INVALID_ARGUMENT;
    unsigned char event[16] = {0};
    vireo_directory_mkdir_task_result_t result = {.stage = VIREO_DIRECTORY_MKDIR_TASK_CONTEXT};
    if (report)
        memset(report, 0, sizeof(*report));
    if (!w || !task || !report || !pthread_equal(w->thread, pthread_self()))
        goto done;
    if (w->report.attempted) {
        *report = w->report;
        rc = VIREO_RESULT_BUSY;
        goto done;
    }
    w->report.attempted = true;
    vireo_task_info_t info;
    rc = vireo_task_inspect(task, &info);
    if (rc != VIREO_OK)
        goto completed;
    w->report.metadata = info.metadata;
    result.stage = VIREO_DIRECTORY_MKDIR_TASK_DECODE;
    rc = vireo_directory_mkdir_task_read(task, w->options.execution.mkdir_operation, &result.input,
                                         &result.request_issue);
    if (rc != VIREO_OK) {
        if (result.request_issue == VIREO_NODE_MKDIR_ISSUE_ENVELOPE)
            result.stage = VIREO_DIRECTORY_MKDIR_TASK_MATCH;
        goto completed;
    }
    result.stage = VIREO_DIRECTORY_MKDIR_TASK_CONTEXT;
    w->report.task_validated = true;
    w->report.attach_called = true;
    rc = w->ops.attach(w->ops.context, w->resources.runtime, &w->guard, &w->report.attach_error);
    if (rc != VIREO_OK)
        goto completed;
    w->report.repository_called = true;
    rc = w->ops.repository_create(w->ops.context, w->guard, w->resources.database, &w->repository,
                                  &w->report.work_error);
    if (rc != VIREO_OK)
        goto completed;
    unsigned char event_nonzero = 0;
    w->report.random_called = true;
    const int generated = w->ops.random(w->ops.context, result.request_id);
    for (size_t i = 0; i < 16; ++i)
        event_nonzero |= result.request_id[i];
    w->report.random_result = generated == 1 && event_nonzero ? VIREO_OK : VIREO_RESULT_IO;
    rc = w->report.random_result;
    if (rc != VIREO_OK) {
        result.stage = VIREO_DIRECTORY_MKDIR_TASK_RANDOM;
        (void)vireo_secure_clear(result.request_id, 16);
        goto completed;
    }
    memcpy(event, result.request_id, 16);
    (void)vireo_secure_clear(result.request_id, 16);
    uint64_t now = 0;
    w->report.clock_called = true;
    rc = w->ops.clock(w->ops.context, &now, &w->report.clock_error);
    if (rc != VIREO_OK)
        goto completed;
    w->report.execute_called = true;
    rc = w->ops.execute(w->ops.context, task, &w->options.execution, w->repository, event, now,
                        &result);
    w->report.work_error = result.error;
completed:
    result.result = rc;
    w->report.work_result = rc;
    w->report.work_stage = result.stage;
    w->report.request_issue = result.request_issue;
    w->report.service = result.service;
    const vireo_result_t cleaned = cleanup(w, &w->report.cleanup);
    w->report.publication_blocked_by_cleanup = cleaned != VIREO_OK;
    if (w->report.task_validated && cleaned == VIREO_OK) {
        w->report.publish_called = true;
        w->report.publish_result =
            w->ops.publish(w->ops.context, task, w->options.execution.mkdir_operation, &result,
                           w->options.completion_allocation_budget, w->resources.queue,
                           w->resources.notifier, &w->completion, &w->report.publication);
    }
    w->report.completion_pending = w->completion != NULL;
    if (rc == VIREO_OK)
        rc = cleaned;
    if (rc == VIREO_OK && w->report.publish_called)
        rc = w->report.publish_result;
    *report = w->report;
done:
    (void)vireo_secure_clear(event, sizeof(event));
    (void)vireo_secure_clear(&result, sizeof(result));
    errno = saved;
    return rc;
}
vireo_result_t vireo_directory_mkdir_worker_destroy(
    vireo_directory_mkdir_worker_t **owner, vireo_directory_mkdir_worker_cleanup_report_t *report) {
    const int saved = errno;
    vireo_result_t rc = VIREO_RESULT_INVALID_ARGUMENT;
    if (report)
        memset(report, 0, sizeof(*report));
    if (!owner || !report)
        goto done;
    if (!*owner) {
        rc = VIREO_OK;
        goto done;
    }
    vireo_directory_mkdir_worker_t *w = *owner;
    if (!pthread_equal(w->thread, pthread_self()))
        goto done;
    rc = cleanup(w, report);
    if (!w->repository && !w->guard && !w->completion) {
        const vireo_directory_mkdir_worker_ops_t ops = w->ops;
        (void)vireo_secure_clear(w, sizeof(*w));
        ops.release(ops.context, w);
        *owner = NULL;
    }
done:
    errno = saved;
    return rc;
}
