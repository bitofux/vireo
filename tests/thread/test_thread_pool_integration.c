/*
 * PROJECT : VIREO
 * FILE    : test_thread_pool_integration.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-12
 * BRIEF   : 仅公开接口的完整任务移交、关闭和依赖收尾
 */
#define _POSIX_C_SOURCE 200809L
#include <vireo/thread/thread_pool.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); exit(1); } } while (0)
#define TASK_COUNT 127
#define RETRY_LIMIT 100000

/**
 * @brief
 *     稳定的执行策略、原子账本与真实在途会合，不保存 task 指针。
 *
 * @note
 *     策略在启动前写完；worker 仅更新原子账本，屏障不复制或移动。
 */
typedef struct integration_context {
    uint64_t owner_id; /**< 此场景数值客户域，启动前稳定，各场景不同。 */
    atomic_uint seen[TASK_COUNT + 1]; /**< 每个实例的回调次数，初始零。 */
    atomic_size_t calls; /**< 全部实际回调次数，不等提交次数。 */
    atomic_size_t body_calls; /**< 显式安全点后进入模拟工作段的次数。 */
    bool hold_first; /**< 实例1在两个屏障之间保留短借，启动前稳定。 */
    bool honor_cancel; /**< 本测试执行函数是否选择检查协作取消。 */
    bool error_at_two; /**< 实例2工作段后返回 DATABASE，其他实例继续。 */
    pthread_barrier_t entered; /**< 两方会合，证明实例1已被领取并进入回调。 */
    pthread_barrier_t release; /**< 两方会合，允许实例1结束借用并正常返回。 */
} integration_context_t;

/**
 * @brief
 *     调用者唯一拥有的资源与稳定长期借用上下文。
 */
typedef struct integration_fixture {
    vireo_thread_pool_t *pool; /**< 唯一 owner，同池管理由主线程串行调用。 */
    vireo_task_queue_t *queue; /**< 唯一专用队列，借至 pool 销毁。 */
    integration_context_t context; /**< 自有稳定存储，全部 worker join 后结束。 */
} integration_fixture_t;

/**
 * @brief
 *     真实双方屏障；不用睡眠推测任务已领取。
 *
 * @param[in,out] barrier
 *     已初始化且在两个参与者退出前保持地址稳定。
 */
static void meet(pthread_barrier_t *barrier) {
    int const error = pthread_barrier_wait(barrier);
    CHECK(error == 0 || error == PTHREAD_BARRIER_SERIAL_THREAD);
}

/**
 * @brief
 *     只公开读取独立身份及 payload；策略由此执行函数明确决定。
 *
 * @param[in,out] context
 *     长期借用上下文；共享计数为原子，策略只读。
 * @param[in] task
 *     只借到返回，不保存、移动或销毁。
 *
 * @return
 *     显式安全点的 CANCELLED、实例2的 DATABASE 或 OK。
 *
 * @note
 *     屏障用于测试控制在途区间，回调最终正常返回，借用随之结束。
 */
static vireo_result_t execute(void *context, vireo_task_t const *task) {
    integration_context_t *c = context;
    vireo_task_info_t info;
    vireo_task_payload_view_t view;
    CHECK(vireo_task_inspect(task, &info) == VIREO_OK);
    uint64_t const id = info.metadata.request_instance_id;
    CHECK(id > 0 && id <= TASK_COUNT);
    CHECK(info.metadata.route.client_owner_id == c->owner_id);
    CHECK(info.metadata.route.client_slot_index == 2);
    CHECK(info.metadata.route.client_generation == 9);
    CHECK(info.metadata.route.request_sequence == 7 && info.metadata.operation == 9);
    CHECK(vireo_task_borrow_payload(task, &view) == VIREO_OK);
    if (id % 4 == 0) {
        CHECK(info.payload_size == 0 && view.size == 0 && view.data == NULL);
    } else {
        CHECK(info.payload_size == 3 && view.size == 3);
        CHECK(view.data[0] == (unsigned char)id && view.data[1] == 0 && view.data[2] == 255);
    }
    bool expired = false;
    CHECK(vireo_task_metadata_deadline_expired(info.metadata, 0, &expired) == VIREO_OK);
    CHECK(expired == (id % 2 == 0));
    CHECK(atomic_fetch_add(&c->seen[(size_t)id], 1) == 0);
    (void)atomic_fetch_add(&c->calls, 1);
    if (c->hold_first && id == 1) {
        meet(&c->entered);
        meet(&c->release);
        CHECK(view.size == 3 && view.data[0] == 1);
    }
    bool requested = false;
    CHECK(vireo_task_is_cancel_requested(task, &requested) == VIREO_OK);
    if (c->honor_cancel && requested) {
        errno = EILSEQ;
        return VIREO_RESULT_CANCELLED;
    }
    (void)atomic_fetch_add(&c->body_calls, 1);
    errno = EILSEQ;
    return c->error_at_two && id == 2 ? VIREO_RESULT_DATABASE : VIREO_OK;
}

/**
 * @brief
 *     原位建立独占资源；所有策略和上下文在启动前初始化。
 *
 * @param[out] f
 *     未发布、地址稳定的 fixture，不按值复制同步对象。
 * @param[in] workers
 *     显式正固定 worker 数。
 * @param[in] capacity
 *     显式正队列槽数，包含非2幂容量。
 * @param[in] owner_id
 *     场景独立的非零数值身份。
 */
static void prepare(integration_fixture_t *f, size_t workers, size_t capacity, uint64_t owner_id) {
    memset(f, 0, sizeof(*f));
    f->context.owner_id = owner_id;
    for (size_t i = 0; i <= TASK_COUNT; ++i) { atomic_init(&f->context.seen[i], 0); }
    atomic_init(&f->context.calls, 0);
    atomic_init(&f->context.body_calls, 0);
    CHECK(pthread_barrier_init(&f->context.entered, NULL, 2) == 0);
    CHECK(pthread_barrier_init(&f->context.release, NULL, 2) == 0);
    vireo_task_queue_options_t const queue_options = {capacity, 65536};
    vireo_thread_pool_options_t const pool_options = {workers, 65536};
    CHECK(vireo_task_queue_create(&queue_options, &f->queue) == VIREO_OK);
    CHECK(vireo_task_queue_prepare_wait(f->queue) == VIREO_OK);
    CHECK(vireo_thread_pool_create(&pool_options, &f->pool) == VIREO_OK);
    vireo_thread_pool_configuration_t const configuration = {f->queue, execute, &f->context};
    CHECK(vireo_thread_pool_configure(f->pool, &configuration, NULL) == VIREO_OK);
}

/**
 * @brief
 *     开启真实固定 worker，再显式放行，不存在并发管理。
 *
 * @param[in,out] f
 *     装配成功，调用期间排除 queue 其他访问。
 */
static void start(integration_fixture_t *f) {
    vireo_thread_pool_report_t report;
    errno = EDOM;
    CHECK(vireo_thread_pool_start(f->pool, &report) == VIREO_OK && errno == EDOM);
    CHECK(report.start_attempted && report.created_count > 0 && report.joined_count == 0);
    CHECK(!report.execution_enabled && !report.stop_requested);
    CHECK(vireo_thread_pool_enable_execution(f->pool, &report) == VIREO_OK && errno == EDOM);
    CHECK(report.execution_enabled && !report.stop_requested);
}

/**
 * @brief
 *     通过公开构造复制独立输入；同 sequence 的请求用实例号区分。
 *
 * @param[in] f
 *     地址稳定的场景身份来源。
 * @param[in] id
 *     本场景不复用的正请求实例号。
 * @param[in] cancel
 *     可空存活共享取消来源，不消费 caller 强引用。
 *
 * @return
 *     caller 唯一拥有的 task，源字节随后被改写以检查独立复制。
 */
static vireo_task_t *make_task(integration_fixture_t const *f, uint64_t id, vireo_task_cancel_t *cancel) {
    vireo_task_route_t route;
    vireo_task_metadata_t metadata;
    CHECK(vireo_task_route_make(f->context.owner_id, 2, 9, 7, &route) == VIREO_OK);
    CHECK(vireo_task_metadata_make(route, id, 9, id % 2 == 0 ? 0 : UINT64_MAX, &metadata) == VIREO_OK);
    unsigned char bytes[3] = {(unsigned char)id, 0, 255};
    size_t const size = id % 4 == 0 ? 0 : sizeof(bytes);
    vireo_task_t *task = NULL;
    if (cancel == NULL) {
        CHECK(vireo_task_create_copy(metadata, bytes, size, 4096, &task) == VIREO_OK);
    } else {
        CHECK(vireo_task_create_copy_with_cancel(metadata, bytes, size, 4096, cancel, &task) == VIREO_OK);
    }
    memset(bytes, 17, sizeof(bytes));
    return task;
}

/**
 * @brief
 *     测试 caller 显式有限重试未转移的 BUSY，不改变产品单次尝试合同。
 *
 * @param[in,out] f
 *     已放行，只有此管理线程提交。
 * @param[in,out] owner
 *     非空唯一 task 源，成功清空；其他失败立即暴露。
 */
static void submit(integration_fixture_t *f, vireo_task_t **owner) {
    vireo_task_t *const before = *owner;
    for (size_t i = 0; i < RETRY_LIMIT; ++i) {
        vireo_thread_pool_submit_report_t report;
        errno = EDOM;
        vireo_result_t const result = vireo_thread_pool_try_submit(f->pool, owner, &report);
        CHECK(errno == EDOM && report.queue_called);
        if (result == VIREO_OK) {
            CHECK(*owner == NULL && report.queue_report.transferred);
            CHECK(report.stage == VIREO_THREAD_POOL_SUBMIT_STAGE_NONE);
            return;
        }
        CHECK(result == VIREO_RESULT_BUSY && *owner == before && !report.queue_report.transferred);
        CHECK(report.stage == VIREO_THREAD_POOL_SUBMIT_STAGE_SUBMIT_QUEUE);
        CHECK(report.queue_report.stage == VIREO_TASK_QUEUE_STAGE_NONE ||
            (report.queue_report.stage == VIREO_TASK_QUEUE_STAGE_LOCK && report.queue_report.pthread_error == EBUSY));
        (void)sched_yield();
    }
    CHECK(false);
}

/**
 * @brief
 *     测试 caller 仅重试明确的健康锁竞争；业务、模式和同步错误不重试。
 *
 * @param[in,out] f
 *     唯一串行管理的完整已放行池。
 * @param[in] mode
 *     此场景已选的永久关闭模式。
 * @param[out] report
 *     最后一次真实两段报告，包括原始 worker 错误与全 join 进度。
 *
 * @return
 *     首个非锁竞争的公开原结果。
 */
static vireo_result_t shutdown(integration_fixture_t *f, vireo_task_queue_state_t mode,
    vireo_thread_pool_shutdown_report_t *report) {
    for (size_t i = 0; i < RETRY_LIMIT; ++i) {
        errno = EDOM;
        vireo_result_t const result = vireo_thread_pool_shutdown_and_join(f->pool, mode, report);
        CHECK(errno == EDOM);
        bool const close_busy = report->stage == VIREO_THREAD_POOL_SHUTDOWN_STAGE_CLOSE_QUEUE &&
            report->close_report.stage == VIREO_TASK_QUEUE_STAGE_LOCK && report->close_report.pthread_error == EBUSY;
        bool const inspect_busy = report->stage == VIREO_THREAD_POOL_SHUTDOWN_STAGE_JOIN_WORKERS &&
            report->pool_report.stage == VIREO_THREAD_POOL_STAGE_CHECK_QUEUE;
        if (result != VIREO_RESULT_BUSY || (!close_busy && !inspect_busy)) { return result; }
        (void)sched_yield();
    }
    CHECK(false);
    return VIREO_RESULT_INTERNAL;
}

/**
 * @brief
 *     公开关闭操作；caller 可重试竞争，永久模式冲突直接暴露。
 *
 * @param[in,out] f
 *     存活专用队列，不并发管理 pool。
 * @param[in] mode
 *     本场景永久模式。
 */
static void close_queue(integration_fixture_t *f, vireo_task_queue_state_t mode) {
    for (size_t i = 0; i < RETRY_LIMIT; ++i) {
        vireo_task_queue_close_report_t report;
        vireo_result_t const result = vireo_task_queue_close(f->queue, mode, &report);
        if (result == VIREO_OK) { CHECK(report.changed); return; }
        CHECK(result == VIREO_RESULT_BUSY && report.stage == VIREO_TASK_QUEUE_STAGE_LOCK && report.pthread_error == EBUSY);
        (void)sched_yield();
    }
    CHECK(false);
}

/**
 * @brief
 *     全部 join 且 pending 已清空后结束长期借用并配对释放资源。
 *
 * @param[in,out] f
 *     main 独占，worker 已退出，所有 task 借用已结束。
 */
static void finish(integration_fixture_t *f) {
    CHECK(vireo_thread_pool_destroy(&f->pool) == VIREO_OK && f->pool == NULL);
    CHECK(vireo_thread_pool_destroy(&f->pool) == VIREO_OK);
    CHECK(vireo_task_queue_destroy(&f->queue) == VIREO_OK && f->queue == NULL);
    CHECK(vireo_task_queue_destroy(&f->queue) == VIREO_OK);
    CHECK(pthread_barrier_destroy(&f->context.entered) == 0);
    CHECK(pthread_barrier_destroy(&f->context.release) == 0);
}

static void test_public_pipeline(void) {
    size_t const workers[] = {1, 3, 7};
    size_t const capacities[] = {1, 3, 31};
    for (size_t scenario = 0; scenario < 3; ++scenario) {
        integration_fixture_t f;
        prepare(&f, workers[scenario], capacities[scenario], 100 + scenario);
        vireo_thread_pool_info_t before;
        CHECK(vireo_thread_pool_inspect(f.pool, &before) == VIREO_OK);
        CHECK(before.configured && !before.start_attempted && before.created_count == 0);
        start(&f);
        for (uint64_t id = 1; id <= TASK_COUNT; ++id) {
            vireo_task_t *task = make_task(&f, id, NULL);
            submit(&f, &task);
        }
        vireo_thread_pool_shutdown_report_t report;
        CHECK(shutdown(&f, VIREO_TASK_QUEUE_DRAIN, &report) == VIREO_OK);
        CHECK(report.close_called && report.join_called && report.pool_report.stop_requested);
        CHECK(report.pool_report.created_count == workers[scenario] && report.pool_report.joined_count == workers[scenario]);
        CHECK(atomic_load(&f.context.calls) == TASK_COUNT && atomic_load(&f.context.body_calls) == TASK_COUNT);
        for (size_t id = 1; id <= TASK_COUNT; ++id) { CHECK(atomic_load(&f.context.seen[id]) == 1); }
        for (size_t i = 0; i < workers[scenario]; ++i) {
            vireo_thread_pool_worker_result_t worker;
            CHECK(vireo_thread_pool_inspect_worker_result(f.pool, i, &worker) == VIREO_OK);
            CHECK(worker.result == VIREO_OK && worker.stage == VIREO_THREAD_POOL_STAGE_NONE);
        }
        vireo_task_queue_metrics_t metrics;
        CHECK(vireo_task_queue_inspect_metrics(f.queue, &metrics) == VIREO_OK);
        CHECK(metrics.depth == 0 && metrics.high_watermark > 0 && metrics.high_watermark <= capacities[scenario]);
        CHECK(shutdown(&f, VIREO_TASK_QUEUE_DRAIN, &report) == VIREO_OK && !report.close_report.changed);
        CHECK(shutdown(&f, VIREO_TASK_QUEUE_CANCEL_PENDING, &report) == VIREO_RESULT_BUSY && !report.join_called);
        finish(&f);
        CHECK(before.configured && !before.start_attempted && before.created_count == 0);
        CHECK(metrics.depth == 0 && metrics.high_watermark > 0);
    }
}

/**
 * @brief
 *     一项真实在途加三项排队，使容量拒绝与锁竞争可区分。
 *
 * @param[in,out] f
 *     新场景，初始化后设置测试策略再启动。
 * @param[in] owner_id
 *     独立数值客户身份。
 * @param[in] cancel
 *     第一项关联的存活取消来源，可 NULL。
 * @param[in] pending_cancel
 *     后三项关联的存活取消来源，可 NULL，不自动请求。
 * @param[in] honor_cancel
 *     执行函数是否显式检查取消安全点。
 * @param[in] error_at_two
 *     实例2是否产生业务原错。
 */
static void fill_held(integration_fixture_t *f, uint64_t owner_id, vireo_task_cancel_t *cancel,
    vireo_task_cancel_t *pending_cancel, bool honor_cancel, bool error_at_two) {
    prepare(f, 1, 3, owner_id);
    f->context.hold_first = true;
    f->context.honor_cancel = honor_cancel;
    f->context.error_at_two = error_at_two;
    start(f);
    vireo_task_t *task = make_task(f, 1, cancel);
    submit(f, &task);
    meet(&f->context.entered);
    for (uint64_t id = 2; id <= 4; ++id) { task = make_task(f, id, pending_cancel); submit(f, &task); }
    vireo_task_queue_info_t queue;
    CHECK(vireo_task_queue_inspect(f->queue, &queue) == VIREO_OK && queue.count == 3);
    CHECK(atomic_load(&f->context.calls) == 1);
    task = make_task(f, 5, NULL);
    vireo_task_t *const held = task;
    vireo_thread_pool_submit_report_t report;
    errno = EDOM;
    CHECK(vireo_thread_pool_try_submit(f->pool, &task, &report) == VIREO_RESULT_BUSY && errno == EDOM);
    CHECK(task == held && report.queue_called && !report.queue_report.transferred);
    CHECK(report.queue_report.stage == VIREO_TASK_QUEUE_STAGE_NONE && report.queue_report.pthread_error == 0);
    vireo_task_queue_metrics_t metrics;
    CHECK(vireo_task_queue_inspect_metrics(f->queue, &metrics) == VIREO_OK);
    CHECK(metrics.depth == 3 && metrics.high_watermark == 3 && metrics.full_rejections == 1 && metrics.closed_rejections == 0);
    CHECK(vireo_task_destroy(&task) == VIREO_OK && task == NULL);
}

static void test_explicit_cooperation(void) {
    for (size_t policy = 0; policy < 2; ++policy) {
        integration_fixture_t f;
        vireo_task_cancel_t *cancel = NULL;
        CHECK(vireo_task_cancel_create(4096, &cancel) == VIREO_OK);
        fill_held(&f, 200 + policy, cancel, NULL, policy == 1, policy == 1);
        CHECK(vireo_task_cancel_request(cancel) == VIREO_OK);
        close_queue(&f, VIREO_TASK_QUEUE_DRAIN);
        meet(&f.context.release);
        vireo_thread_pool_shutdown_report_t report;
        vireo_result_t const expected = policy == 1 ? VIREO_RESULT_CANCELLED : VIREO_OK;
        CHECK(shutdown(&f, VIREO_TASK_QUEUE_DRAIN, &report) == expected);
        CHECK(report.close_called && report.join_called && report.pool_report.joined_count == 1);
        CHECK(!report.close_report.changed);
        CHECK(atomic_load(&f.context.calls) == 4 && atomic_load(&f.context.body_calls) == (policy == 1 ? 3 : 4));
        for (size_t id = 1; id <= 4; ++id) { CHECK(atomic_load(&f.context.seen[id]) == 1); }
        vireo_thread_pool_worker_result_t worker;
        CHECK(vireo_thread_pool_inspect_worker_result(f.pool, 0, &worker) == VIREO_OK);
        CHECK(worker.result == expected);
        if (policy == 1) {
            CHECK(worker.stage == VIREO_THREAD_POOL_STAGE_EXECUTE_TASK && worker.pthread_error == 0);
            CHECK(report.stage == VIREO_THREAD_POOL_SHUTDOWN_STAGE_JOIN_WORKERS);
            CHECK(report.pool_report.stage == VIREO_THREAD_POOL_STAGE_EXECUTE_TASK);
        }
        CHECK(shutdown(&f, VIREO_TASK_QUEUE_DRAIN, &report) == VIREO_OK);
        CHECK(vireo_thread_pool_inspect_worker_result(f.pool, 0, &worker) == VIREO_OK && worker.result == expected);
        finish(&f);
        bool requested = false;
        CHECK(vireo_task_cancel_is_requested(cancel, &requested) == VIREO_OK && requested);
        CHECK(vireo_task_cancel_destroy(&cancel) == VIREO_OK && cancel == NULL);
        CHECK(worker.result == expected);
    }
}

static void test_cancel_pending_ownership(void) {
    integration_fixture_t f;
    vireo_task_cancel_t *cancel = NULL;
    CHECK(vireo_task_cancel_create(4096, &cancel) == VIREO_OK);
    fill_held(&f, 300, NULL, cancel, false, false);
    close_queue(&f, VIREO_TASK_QUEUE_CANCEL_PENDING);
    vireo_task_t *rejected = make_task(&f, 5, NULL);
    vireo_task_t *const before = rejected;
    vireo_thread_pool_submit_report_t submit_report;
    CHECK(vireo_thread_pool_try_submit(f.pool, &rejected, &submit_report) == VIREO_RESULT_CANCELLED);
    CHECK(rejected == before && submit_report.queue_called && !submit_report.queue_report.transferred);
    vireo_task_queue_metrics_t metrics;
    CHECK(vireo_task_queue_inspect_metrics(f.queue, &metrics) == VIREO_OK);
    CHECK(metrics.depth == 3 && metrics.full_rejections == 1 && metrics.closed_rejections == 1);
    meet(&f.context.release);
    vireo_thread_pool_shutdown_report_t report;
    CHECK(shutdown(&f, VIREO_TASK_QUEUE_CANCEL_PENDING, &report) == VIREO_OK);
    CHECK(report.pool_report.joined_count == 1 && atomic_load(&f.context.calls) == 1);
    CHECK(vireo_thread_pool_destroy(&f.pool) == VIREO_OK && f.pool == NULL);
    vireo_task_queue_t *const queue_before = f.queue;
    CHECK(vireo_task_queue_destroy(&f.queue) == VIREO_RESULT_BUSY && f.queue == queue_before);
    for (uint64_t id = 2; id <= 4; ++id) {
        vireo_task_t *task = NULL;
        vireo_task_queue_transfer_report_t transfer;
        CHECK(vireo_task_queue_try_take_cancelled(f.queue, &task, &transfer) == VIREO_OK && transfer.transferred);
        vireo_task_info_t info;
        CHECK(vireo_task_inspect(task, &info) == VIREO_OK && info.metadata.request_instance_id == id);
        vireo_task_payload_view_t view;
        CHECK(vireo_task_borrow_payload(task, &view) == VIREO_OK);
        if (id == 4) { CHECK(view.size == 0 && view.data == NULL); }
        else { CHECK(view.size == 3 && view.data[0] == (unsigned char)id && view.data[1] == 0 && view.data[2] == 255); }
        CHECK(atomic_load(&f.context.seen[(size_t)id]) == 0);
        bool requested = true;
        CHECK(vireo_task_is_cancel_requested(task, &requested) == VIREO_OK && requested == (id > 2));
        /* close/join 没有请求取消；caller 在首项取回后才明确请求。 */
        if (id == 2) { CHECK(vireo_task_cancel_request(cancel) == VIREO_OK); }
        /* 不再使用短借 view，随后由唯一 owner 配对销毁。 */
        CHECK(vireo_task_destroy(&task) == VIREO_OK && task == NULL);
    }
    vireo_task_t *task = NULL;
    vireo_task_queue_transfer_report_t transfer;
    CHECK(vireo_task_queue_try_take_cancelled(f.queue, &task, &transfer) == VIREO_RESULT_NOT_FOUND && task == NULL);
    CHECK(vireo_task_destroy(&rejected) == VIREO_OK && rejected == NULL);
    finish(&f);
    bool requested = false;
    CHECK(vireo_task_cancel_is_requested(cancel, &requested) == VIREO_OK && requested);
    CHECK(vireo_task_cancel_destroy(&cancel) == VIREO_OK && cancel == NULL);
    CHECK(metrics.depth == 3 && report.pool_report.joined_count == 1);
}

static void test_parked_cleanup(void) {
    integration_fixture_t f;
    prepare(&f, 3, 3, 400);
    for (uint64_t id = 1; id <= 2; ++id) {
        vireo_task_t *task = make_task(&f, id, NULL);
        vireo_task_queue_transfer_report_t transfer;
        CHECK(vireo_task_queue_try_push(f.queue, &task, &transfer) == VIREO_OK && task == NULL);
    }
    vireo_thread_pool_report_t management;
    CHECK(vireo_thread_pool_start(f.pool, &management) == VIREO_OK && !management.execution_enabled);
    vireo_thread_pool_worker_result_t output = {VIREO_RESULT_DATABASE, VIREO_THREAD_POOL_STAGE_EXECUTE_TASK, 0, {0}};
    unsigned char saved[sizeof(output)];
    memcpy(saved, &output, sizeof(output));
    CHECK(vireo_thread_pool_inspect_worker_result(f.pool, 0, &output) == VIREO_RESULT_BUSY);
    CHECK(memcmp(saved, &output, sizeof(output)) == 0);
    CHECK(vireo_thread_pool_stop_and_join(f.pool, &management) == VIREO_OK && management.joined_count == 3);
    CHECK(atomic_load(&f.context.calls) == 0);
    vireo_thread_pool_shutdown_report_t report;
    CHECK(vireo_thread_pool_shutdown_and_join(f.pool, VIREO_TASK_QUEUE_DRAIN, &report) == VIREO_RESULT_BUSY);
    CHECK(!report.close_called && !report.join_called);
    CHECK(vireo_thread_pool_destroy(&f.pool) == VIREO_OK && f.pool == NULL);
    vireo_task_queue_info_t info;
    CHECK(vireo_task_queue_inspect(f.queue, &info) == VIREO_OK && info.state == VIREO_TASK_QUEUE_OPEN && info.count == 2);
    for (uint64_t id = 1; id <= 2; ++id) {
        vireo_task_t *task = NULL;
        vireo_task_queue_transfer_report_t transfer;
        CHECK(vireo_task_queue_try_pop(f.queue, &task, &transfer) == VIREO_OK);
        vireo_task_info_t task_info;
        CHECK(vireo_task_inspect(task, &task_info) == VIREO_OK && task_info.metadata.request_instance_id == id);
        CHECK(vireo_task_destroy(&task) == VIREO_OK);
    }
    finish(&f);
    CHECK(info.state == VIREO_TASK_QUEUE_OPEN && info.count == 2);
}

int main(void) {
    int previous = 0;
    CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previous) == 0);
    test_public_pipeline();
    test_explicit_cooperation();
    test_cancel_pending_ownership();
    test_parked_cleanup();
    CHECK(pthread_setcancelstate(previous, NULL) == 0);
    puts("thread pool integration: 4 groups passed (7 real scenarios)");
    return 0;
}
