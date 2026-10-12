/*
 * PROJECT : VIREO
 * FILE    : test_async_components_integration.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-13
 * BRIEF   : 六组件公开链路中的协作取消、期限、身份与唯一清理
 */
#define _POSIX_C_SOURCE 200809L
#include <vireo/thread/completion_queue.h>
#include <vireo/thread/notifier.h>
#include <vireo/thread/thread_pool.h>

#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #x); abort(); } } while (0)
#define EXPECT(x, wanted) do { errno = EDOM; vireo_result_t const got = (x); CHECK(got == (wanted) && errno == EDOM); } while (0)
#define RETRY_LIMIT 1000000U

/** 启动前固定的长借上下文；两个 barrier 只协调测试安全点。 */
typedef struct execution_context {
    vireo_completion_queue_t *outputs; /**< 借用至 pool 销毁，不拥有 queue。 */
    vireo_notifier_t *notifier; /**< 借用至所有 worker join，不直接使用其 fd。 */
    uint64_t now_ns; /**< 显式合成 MONOTONIC 域样本，仅测试执行函数的期限策略。 */
    pthread_barrier_t entered; /**< 请求1与 main 两参与者，确认该请求已领取。 */
    pthread_barrier_t release; /**< 请求1与 main 两参与者，允许安全点继续。 */
} execution_context_t;

/** main 独占 owner 存储；context 原位初始化，不复制同步对象。 */
typedef struct integration_fixture {
    vireo_task_queue_t *tasks; /**< 唯一拥有，成功配置后长期借给 pool。 */
    vireo_thread_pool_t *pool; /**< 唯一拥有，管理由 main 串行调用。 */
    vireo_completion_queue_t *outputs; /**< 唯一拥有，main 是唯一 consumer。 */
    vireo_notifier_t *notifier; /**< 唯一拥有，main 仅短借 fd 用于 poll。 */
    vireo_task_cancel_t *inflight_cancel; /**< main 持一份引用，task 可独立保留关联引用。 */
    vireo_task_cancel_t *pending_cancel; /**< 待执行项共享引用，CP 不自动请求它。 */
    execution_context_t context; /**< 长借到 pool 销毁，资源与时间发布前固定。 */
    size_t workers; /**< 正配置槽数，结束时核对实际 create/join 累计。 */
} integration_fixture_t;

/**
 * @brief
 *     等待测试门闩，接受普通参与者与唯一 serial 返回。
 */
static void meet(pthread_barrier_t *barrier) {
    int const result = pthread_barrier_wait(barrier);
    CHECK(result == 0 || result == PTHREAD_BARRIER_SERIAL_THREAD);
}

/**
 * @brief
 *     相同客户租约及 sequence，独立 instance 仍区分每个测试请求。
 */
static vireo_task_metadata_t request(uint64_t id, uint64_t deadline_ns) {
    vireo_task_route_t route;
    vireo_task_metadata_t metadata;
    EXPECT(vireo_task_route_make(73, 5, 11, 7, &route), VIREO_OK);
    EXPECT(vireo_task_metadata_make(route, id, 9, deadline_ns, &metadata), VIREO_OK);
    return metadata;
}

/**
 * @brief
 *     复制输入后改写原字节，worker 只能观察独立副本。
 */
static vireo_task_t *make_task(uint64_t id, uint64_t deadline_ns,
                              vireo_task_cancel_t *cancel) {
    unsigned char bytes[3] = {(unsigned char)id, 0xA5, 0};
    vireo_task_t *owner = NULL;
    vireo_task_metadata_t const metadata = request(id, deadline_ns);
    if (cancel == NULL) {
        EXPECT(vireo_task_create_copy(metadata, bytes, sizeof(bytes), 4096, &owner), VIREO_OK);
    } else {
        EXPECT(vireo_task_create_copy_with_cancel(metadata, bytes, sizeof(bytes), 4096,
                                                cancel, &owner), VIREO_OK);
    }
    bytes[0] = 255;
    vireo_task_payload_view_t view;
    EXPECT(vireo_task_borrow_payload(owner, &view), VIREO_OK);
    CHECK(view.size == sizeof(bytes) && view.data[0] == (unsigned char)id);
    return owner;
}

/**
 * @brief
 *     在明确安全点检查取消及期限，形成独立结果后交接并提示。
 *
 * @param[in,out] context
 *     启动前固定的长借上下文；只有请求1参与两道门闩。
 * @param[in] task
 *     只读借到返回，不保存或销毁，由 pool 返回后清理。
 *
 * @return
 *     已记录的工作分类或原提交错误，不以错误返回推断尚未交接。
 *
 * @note
 *     worker 已禁 POSIX 取消；允许 wait_push，不重入 pool 管理或操作客户 fd。
 *     取消优先期限是本测试执行函数的策略，不新增库默认行为。
 *     未交接响应仍由本函数清理，已交接后的通知失败不重投或销毁。
 */
static vireo_result_t execute(void *context, vireo_task_t const *task) {
    execution_context_t *c = context;
    vireo_task_info_t info;
    vireo_task_payload_view_t view;
    EXPECT(vireo_task_inspect(task, &info), VIREO_OK);
    EXPECT(vireo_task_borrow_payload(task, &view), VIREO_OK);
    uint64_t const id = info.metadata.request_instance_id;
    CHECK(id >= 1 && id <= 3 && view.size == 3);
    CHECK(view.data[0] == (unsigned char)id && view.data[1] == 0xA5 && view.data[2] == 0);
    if (id == 1) { meet(&c->entered); meet(&c->release); }
    bool cancelled = false;
    bool expired = false;
    EXPECT(vireo_task_is_cancel_requested(task, &cancelled), VIREO_OK);
    EXPECT(vireo_task_metadata_deadline_expired(info.metadata, c->now_ns, &expired), VIREO_OK);
    vireo_result_t const work = cancelled ? VIREO_RESULT_CANCELLED
        : expired ? VIREO_RESULT_TIMEOUT : VIREO_OK;
    vireo_status_t const status = cancelled ? VIREO_STATUS_TASK_CANCELLED
        : expired ? VIREO_STATUS_TIMEOUT : VIREO_STATUS_OK;
    vireo_completion_metadata_t metadata;
    EXPECT(vireo_completion_metadata_make(info.metadata, work, status, &metadata), VIREO_OK);
    unsigned char response[3] = {(unsigned char)id, view.data[1], (unsigned char)work};
    vireo_completion_t *owner = NULL;
    EXPECT(vireo_completion_create_copy(metadata, response, sizeof(response), 4096, &owner), VIREO_OK);
    response[0] = 255;
    vireo_completion_queue_transfer_report_t transfer;
    errno = EDOM;
    vireo_result_t const submitted = vireo_completion_queue_wait_push(c->outputs, &owner, &transfer);
    CHECK(errno == EDOM);
    if (!transfer.transferred) {
        CHECK(owner != NULL && submitted != VIREO_OK);
        EXPECT(vireo_completion_destroy(&owner), VIREO_OK);
        return submitted;
    }
    CHECK(owner == NULL);
    vireo_notifier_notify_outcome_t outcome;
    errno = EDOM;
    vireo_result_t const notified = vireo_notifier_notify(c->notifier, &outcome, NULL);
    CHECK(errno == EDOM);
    if (submitted != VIREO_OK) { return submitted; }
    if (notified != VIREO_OK) { return notified; }
    CHECK(outcome == VIREO_NOTIFIER_NOTIFY_INCREMENTED);
    return work;
}

/**
 * @brief
 *     显式固定容量和预算，完整装配后启动并放行真实 worker。
 */
static void prepare(integration_fixture_t *f, size_t workers, uint64_t now_ns) {
    *f = (integration_fixture_t){0};
    f->workers = workers;
    vireo_task_queue_options_t const tasks = {2, 65536};
    vireo_completion_queue_options_t const outputs = {1, 65536};
    vireo_thread_pool_options_t const pool = {workers, 65536};
    vireo_notifier_options_t const notifier = {4096};
    EXPECT(vireo_task_queue_create(&tasks, &f->tasks), VIREO_OK);
    EXPECT(vireo_task_queue_prepare_wait(f->tasks), VIREO_OK);
    EXPECT(vireo_completion_queue_create(&outputs, &f->outputs), VIREO_OK);
    EXPECT(vireo_completion_queue_prepare_wait(f->outputs), VIREO_OK);
    EXPECT(vireo_notifier_create(&notifier, &f->notifier, NULL), VIREO_OK);
    EXPECT(vireo_task_cancel_create(4096, &f->inflight_cancel), VIREO_OK);
    EXPECT(vireo_task_cancel_create(4096, &f->pending_cancel), VIREO_OK);
    f->context.outputs = f->outputs;
    f->context.notifier = f->notifier;
    f->context.now_ns = now_ns;
    CHECK(pthread_barrier_init(&f->context.entered, NULL, 2) == 0);
    CHECK(pthread_barrier_init(&f->context.release, NULL, 2) == 0);
    EXPECT(vireo_thread_pool_create(&pool, &f->pool), VIREO_OK);
    vireo_thread_pool_configuration_t const configuration = {f->tasks, execute, &f->context};
    EXPECT(vireo_thread_pool_configure(f->pool, &configuration, NULL), VIREO_OK);
    vireo_thread_pool_report_t report;
    EXPECT(vireo_thread_pool_start(f->pool, &report), VIREO_OK);
    CHECK(report.created_count == workers && report.joined_count == 0);
    EXPECT(vireo_thread_pool_enable_execution(f->pool, &report), VIREO_OK);
    CHECK(report.execution_enabled);
}

/**
 * @brief
 *     测试驱动仅对未交接的锁竞争有限重试，不改变生产 try 一次合同。
 */
static void submit(integration_fixture_t *f, uint64_t id, uint64_t deadline_ns,
                   vireo_task_cancel_t *cancel) {
    vireo_task_t *owner = make_task(id, deadline_ns, cancel);
    for (unsigned i = 0; i < RETRY_LIMIT; ++i) {
        vireo_thread_pool_submit_report_t report;
        errno = EDOM;
        vireo_result_t const result = vireo_thread_pool_try_submit(f->pool, &owner, &report);
        CHECK(errno == EDOM && report.queue_called);
        if (result == VIREO_OK) { CHECK(report.queue_report.transferred && owner == NULL); return; }
        CHECK(result == VIREO_RESULT_BUSY && !report.queue_report.transferred && owner != NULL);
        CHECK(report.queue_report.stage == VIREO_TASK_QUEUE_STAGE_LOCK);
        (void)sched_yield();
    }
    CHECK(false);
}

/**
 * @brief
 *     唯一 consumer 同时看提示和真实队列，有限 poll 只是测试保护。
 */
static vireo_completion_t *take(integration_fixture_t *f) {
    vireo_notifier_info_t info;
    EXPECT(vireo_notifier_inspect(f->notifier, &info), VIREO_OK);
    for (unsigned i = 0; i < 1000U; ++i) {
        uint64_t hints;
        EXPECT(vireo_notifier_consume(f->notifier, &hints, NULL), VIREO_OK);
        vireo_completion_t *owner = NULL;
        vireo_completion_queue_transfer_report_t report;
        errno = EDOM;
        vireo_result_t const result = vireo_completion_queue_try_pop(f->outputs, &owner, &report);
        CHECK(errno == EDOM);
        if (result == VIREO_OK) { CHECK(owner != NULL && report.transferred); return owner; }
        CHECK((result == VIREO_RESULT_BUSY || result == VIREO_RESULT_NOT_FOUND)
              && owner == NULL && !report.transferred);
        struct pollfd borrowed = {info.fd, POLLIN, 0};
        CHECK(poll(&borrowed, 1, 10) >= 0);
        CHECK((borrowed.revents & (POLLERR | POLLHUP | POLLNVAL)) == 0);
    }
    CHECK(false);
    return NULL;
}

/**
 * @brief
 *     核对完整请求和独立响应副本，不以 sequence 或提示计数关联。
 */
static void validate(vireo_completion_t const *owner, uint64_t id, uint64_t deadline_ns,
                     vireo_result_t work) {
    vireo_completion_info_t info;
    vireo_completion_payload_view_t view;
    EXPECT(vireo_completion_inspect(owner, &info), VIREO_OK);
    EXPECT(vireo_completion_borrow_payload(owner, &view), VIREO_OK);
    bool same = false;
    EXPECT(vireo_task_metadata_same_request(info.metadata.request, request(id, deadline_ns), &same), VIREO_OK);
    CHECK(same && info.metadata.request.operation == 9);
    CHECK(info.metadata.request.deadline_ns == deadline_ns && info.metadata.result == work);
    vireo_status_t const status = work == VIREO_RESULT_CANCELLED ? VIREO_STATUS_TASK_CANCELLED
        : work == VIREO_RESULT_TIMEOUT ? VIREO_STATUS_TIMEOUT : VIREO_STATUS_OK;
    CHECK(info.metadata.suggested_status == status && info.payload_size == 3 && view.size == 3);
    CHECK(view.data[0] == (unsigned char)id && view.data[1] == 0xA5
          && view.data[2] == (unsigned char)work);
}

/**
 * @brief
 *     提交首次永久关闭，只对尚未提交的锁竞争有限重试。
 */
static void close_tasks(integration_fixture_t *f, vireo_task_queue_state_t mode) {
    for (unsigned i = 0; i < RETRY_LIMIT; ++i) {
        vireo_task_queue_close_report_t report;
        errno = EDOM;
        vireo_result_t const result = vireo_task_queue_close(f->tasks, mode, &report);
        CHECK(errno == EDOM);
        if (result == VIREO_OK) { CHECK(report.changed); return; }
        CHECK(result == VIREO_RESULT_BUSY && !report.changed && report.stage == VIREO_TASK_QUEUE_STAGE_LOCK);
        (void)sched_yield();
    }
    CHECK(false);
}

/**
 * @brief
 *     所有预期结果已取回后 join，再无条件最后 drain 并配对销毁。
 */
static void finish(integration_fixture_t *f, vireo_result_t expected_error) {
    vireo_thread_pool_report_t report;
    vireo_result_t joined = VIREO_RESULT_BUSY;
    for (unsigned i = 0; i < RETRY_LIMIT; ++i) {
        errno = EDOM;
        joined = vireo_thread_pool_stop_and_join(f->pool, &report);
        CHECK(errno == EDOM);
        if (joined != VIREO_RESULT_BUSY) { break; }
        CHECK(report.stage == VIREO_THREAD_POOL_STAGE_CHECK_QUEUE && report.pthread_error == 0);
        (void)sched_yield();
    }
    CHECK(joined == expected_error);
    CHECK(report.created_count == f->workers && report.joined_count == f->workers);
    CHECK(report.stop_requested && report.cleanup_result == VIREO_OK);
    size_t errors = 0;
    for (size_t i = 0; i < f->workers; ++i) {
        vireo_thread_pool_worker_result_t result;
        EXPECT(vireo_thread_pool_inspect_worker_result(f->pool, i, &result), VIREO_OK);
        CHECK(result.pthread_error == 0);
        if (result.result != VIREO_OK) {
            CHECK(result.result == expected_error && result.stage == VIREO_THREAD_POOL_STAGE_EXECUTE_TASK);
            ++errors;
        }
    }
    CHECK(errors == 1);
    EXPECT(vireo_thread_pool_stop_and_join(f->pool, &report), VIREO_OK);
    vireo_completion_queue_close_report_t closed;
    EXPECT(vireo_completion_queue_close(f->outputs, &closed), VIREO_OK);
    CHECK(closed.changed);
    vireo_completion_t *remaining = NULL;
    vireo_completion_queue_transfer_report_t transfer;
    EXPECT(vireo_completion_queue_try_pop(f->outputs, &remaining, &transfer), VIREO_RESULT_CANCELLED);
    CHECK(remaining == NULL && !transfer.transferred);
    uint64_t hints;
    EXPECT(vireo_notifier_consume(f->notifier, &hints, NULL), VIREO_OK);
    EXPECT(vireo_notifier_consume(f->notifier, &hints, NULL), VIREO_OK);
    CHECK(hints == 0);
    vireo_completion_queue_metrics_t metrics;
    EXPECT(vireo_completion_queue_inspect_metrics(f->outputs, &metrics), VIREO_OK);
    CHECK(metrics.depth == 0 && metrics.high_watermark == 1);
    CHECK(metrics.full_rejections == 0 && metrics.closed_rejections == 0);
    EXPECT(vireo_thread_pool_destroy(&f->pool), VIREO_OK);
    EXPECT(vireo_task_queue_destroy(&f->tasks), VIREO_OK);
    EXPECT(vireo_completion_queue_destroy(&f->outputs), VIREO_OK);
    EXPECT(vireo_notifier_destroy(&f->notifier, NULL), VIREO_OK);
    EXPECT(vireo_task_cancel_destroy(&f->inflight_cancel), VIREO_OK);
    EXPECT(vireo_task_cancel_destroy(&f->pending_cancel), VIREO_OK);
    CHECK(pthread_barrier_destroy(&f->context.release) == 0);
    CHECK(pthread_barrier_destroy(&f->context.entered) == 0);
    CHECK(f->pool == NULL && f->tasks == NULL && f->outputs == NULL && f->notifier == NULL);
    CHECK(f->inflight_cancel == NULL && f->pending_cancel == NULL);
}

/**
 * @brief
 *     第一项已领取后才请求取消，后两项仍执行；满提交不转移源。
 */
static void cancelled_result_and_drain(void) {
    integration_fixture_t f;
    prepare(&f, 1, 99);
    submit(&f, 1, 100, f.inflight_cancel);
    meet(&f.context.entered);
    submit(&f, 2, 100, NULL);
    submit(&f, 3, 100, NULL);
    vireo_task_t *rejected = make_task(4, 100, NULL);
    vireo_thread_pool_submit_report_t report;
    EXPECT(vireo_thread_pool_try_submit(f.pool, &rejected, &report), VIREO_RESULT_BUSY);
    CHECK(rejected != NULL && report.queue_called && !report.queue_report.transferred);
    CHECK(report.queue_report.stage == VIREO_TASK_QUEUE_STAGE_NONE);
    EXPECT(vireo_task_destroy(&rejected), VIREO_OK);
    vireo_task_queue_metrics_t metrics;
    EXPECT(vireo_task_queue_inspect_metrics(f.tasks, &metrics), VIREO_OK);
    CHECK(metrics.depth == 2 && metrics.high_watermark == 2 && metrics.full_rejections == 1);
    EXPECT(vireo_task_cancel_request(f.inflight_cancel), VIREO_OK);
    close_tasks(&f, VIREO_TASK_QUEUE_DRAIN);
    meet(&f.context.release);
    for (uint64_t id = 1; id <= 3; ++id) {
        vireo_completion_t *owner = take(&f);
        validate(owner, id, 100, id == 1 ? VIREO_RESULT_CANCELLED : VIREO_OK);
        EXPECT(vireo_completion_destroy(&owner), VIREO_OK);
    }
    finish(&f, VIREO_RESULT_CANCELLED);
}

/**
 * @brief
 *     CP 不请求共享取消；caller 取回 pending，inflight 仍形成一个完成项。
 */
static void pending_and_inflight_are_distinct(void) {
    integration_fixture_t f;
    prepare(&f, 1, 99);
    submit(&f, 1, 100, f.inflight_cancel);
    meet(&f.context.entered);
    submit(&f, 2, 100, f.pending_cancel);
    submit(&f, 3, 100, f.pending_cancel);
    close_tasks(&f, VIREO_TASK_QUEUE_CANCEL_PENDING);
    for (uint64_t id = 2; id <= 3; ++id) {
        vireo_task_t *owner = NULL;
        vireo_task_queue_transfer_report_t report;
        EXPECT(vireo_task_queue_try_take_cancelled(f.tasks, &owner, &report), VIREO_OK);
        CHECK(report.transferred && owner != NULL);
        bool requested = true;
        EXPECT(vireo_task_is_cancel_requested(owner, &requested), VIREO_OK);
        CHECK(requested == (id == 3));
        vireo_task_info_t info;
        EXPECT(vireo_task_inspect(owner, &info), VIREO_OK);
        CHECK(info.metadata.request_instance_id == id);
        if (id == 2) { EXPECT(vireo_task_cancel_request(f.pending_cancel), VIREO_OK); }
        EXPECT(vireo_task_destroy(&owner), VIREO_OK);
    }
    EXPECT(vireo_task_cancel_request(f.inflight_cancel), VIREO_OK);
    meet(&f.context.release);
    vireo_completion_t *owner = take(&f);
    validate(owner, 1, 100, VIREO_RESULT_CANCELLED);
    EXPECT(vireo_completion_destroy(&owner), VIREO_OK);
    finish(&f, VIREO_RESULT_CANCELLED);
}

/**
 * @brief
 *     两 worker 逆序形成结果；pool/task 已销毁仍可读取独立响应。
 */
static void reordered_results_keep_identity(void) {
    integration_fixture_t f;
    prepare(&f, 2, 99);
    submit(&f, 1, 100, f.inflight_cancel);
    meet(&f.context.entered);
    submit(&f, 2, 100, NULL);
    vireo_completion_t *second = take(&f);
    validate(second, 2, 100, VIREO_OK);
    EXPECT(vireo_task_cancel_request(f.inflight_cancel), VIREO_OK);
    close_tasks(&f, VIREO_TASK_QUEUE_DRAIN);
    meet(&f.context.release);
    vireo_completion_t *first = take(&f);
    validate(first, 1, 100, VIREO_RESULT_CANCELLED);
    vireo_completion_info_t a;
    vireo_completion_info_t b;
    EXPECT(vireo_completion_inspect(first, &a), VIREO_OK);
    EXPECT(vireo_completion_inspect(second, &b), VIREO_OK);
    bool same = true;
    EXPECT(vireo_completion_metadata_same_request(a.metadata, b.metadata, &same), VIREO_OK);
    CHECK(!same && a.metadata.request.route.request_sequence == b.metadata.request.route.request_sequence);
    finish(&f, VIREO_RESULT_CANCELLED);
    validate(first, 1, 100, VIREO_RESULT_CANCELLED);
    validate(second, 2, 100, VIREO_OK);
    EXPECT(vireo_completion_destroy(&first), VIREO_OK);
    EXPECT(vireo_completion_destroy(&second), VIREO_OK);
}

/**
 * @brief
 *     到期由执行函数明确判断，0/MAX 仍有限；pool 不自动过滤 task。
 */
static void explicit_deadline_policy(void) {
    integration_fixture_t f;
    prepare(&f, 1, 100);
    submit(&f, 1, 100, NULL);
    meet(&f.context.entered);
    submit(&f, 2, UINT64_MAX, NULL);
    submit(&f, 3, 0, NULL);
    close_tasks(&f, VIREO_TASK_QUEUE_DRAIN);
    meet(&f.context.release);
    for (uint64_t id = 1; id <= 3; ++id) {
        vireo_completion_t *owner = take(&f);
        validate(owner, id, id == 2 ? UINT64_MAX : id == 1 ? 100 : 0,
                 id == 2 ? VIREO_OK : VIREO_RESULT_TIMEOUT);
        EXPECT(vireo_completion_destroy(&owner), VIREO_OK);
    }
    finish(&f, VIREO_RESULT_TIMEOUT);
}

int main(void) {
    int previous;
    CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previous) == 0);
    cancelled_result_and_drain();
    pending_and_inflight_are_distinct();
    reordered_results_keep_identity();
    explicit_deadline_policy();
    CHECK(pthread_setcancelstate(previous, NULL) == 0);
    puts("test_async_components_integration: 4 groups passed");
    return 0;
}
