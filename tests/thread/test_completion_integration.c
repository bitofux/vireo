/*
 * PROJECT : VIREO
 * FILE    : test_completion_integration.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-12
 * BRIEF   : 仅公开合同的任务、独立结果、真实 worker 与显式取消清理集成
 */
#define _POSIX_C_SOURCE 200809L

#include <vireo/thread/completion.h>
#include <vireo/thread/thread_pool.h>

#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #condition); \
        exit(1); \
    } \
} while (0)

#define EXPECT(call, expected) do { \
    errno = EDOM; \
    CHECK((call) == (expected)); \
    CHECK(errno == EDOM); \
} while (0)

#define RESULT_SLOTS 5
#define RETRY_LIMIT 100000
#define COPY_OPERATION ((uint32_t)1)
#define FAIL_OPERATION ((uint32_t)2)

/**
 * @brief
 *     caller 自持的固定结果 owner 与单 worker 账本，不是 completion queue。
 *
 * @note
 *     策略在启动前写完；运行期间只有唯一 worker 写，main 成功 join 后才读取。
 *     context 存活至 pool 销毁，不保存 task 指针或 payload view，不复制同步对象。
 */
typedef struct completion_context {
    uint64_t owner_id; /**< 场景数值客户域，启动前固定，不认证当前客户。 */
    uint64_t now_ns; /**< 显式 MONOTONIC 纳秒样本，不采样或等待真实期限。 */
    uint64_t failing_budget_instance; /**< 此测试使用预算1的实例，0表示无注入，非产品策略。 */
    vireo_completion_t *outputs[RESULT_SLOTS]; /**< caller 唯一拥有的结果，初始 NULL。 */
    vireo_result_t work_results[RESULT_SLOTS]; /**< 本测试明确选择的工作分类，不是构造结果。 */
    vireo_result_t creation_results[RESULT_SLOTS]; /**< create_copy 的真实返回，失败不产生 owner。 */
    unsigned calls[RESULT_SLOTS]; /**< 每实例实际 callback 次数，初始零，只由单 worker 修改。 */
    size_t body_calls; /**< 通过显式安全点后进入模拟工作段的次数。 */
} completion_context_t;

/**
 * @brief
 *     main 唯一拥有的池、专用队列与地址稳定的执行上下文。
 */
typedef struct completion_fixture {
    vireo_thread_pool_t *pool; /**< 唯一 owner，main 串行管理，join 后才销毁。 */
    vireo_task_queue_t *queue; /**< 唯一 owner，借给 pool 至 pool 销毁，pending 由 caller 清理。 */
    completion_context_t context; /**< 自有存储，所有 worker join 后才读取结果/结束长期借用。 */
} completion_fixture_t;

/**
 * @brief
 *     本测试明确选择协议建议，不是库内映射或生产默认策略。
 *
 * @param[in] result
 *     本测试的四类工作结果。
 *
 * @return
 *     对应场景明确采用的已注册建议。
 */
static vireo_status_t suggested_status(vireo_result_t result) {
    switch (result) {
        case VIREO_OK: return VIREO_STATUS_OK;
        case VIREO_RESULT_DATABASE: return VIREO_STATUS_DB_ERROR;
        case VIREO_RESULT_CANCELLED: return VIREO_STATUS_TASK_CANCELLED;
        case VIREO_RESULT_TIMEOUT: return VIREO_STATUS_TIMEOUT;
        default: CHECK(false); return VIREO_STATUS_INTERNAL_ERROR;
    }
}

/**
 * @brief
 *     显式安全点、模拟工作与独立响应构造，task 只借到正常返回。
 *
 * @param[in,out] context
 *     稳定长期借用存储，唯一 worker 写，main 不在运行期间读取。
 * @param[in] task
 *     worker 唯一拥有对象的 const 短借，不保存、移动或销毁。
 *
 * @return
 *     构造失败原错，或已成功保存完成对象的工作结果。
 *
 * @note
 *     此测试选择先取消后期限的检查顺序，不冻结业务优先级。
 *     工作失败也可有独立结果；创建失败无结果，账本另记原错，pool 返回后清理 task。
 */
static vireo_result_t execute(void *context, vireo_task_t const *task) {
    completion_context_t *c = context;
    vireo_task_info_t info = {0};
    EXPECT(vireo_task_inspect(task, &info), VIREO_OK);
    uint64_t const instance = info.metadata.request_instance_id;
    CHECK(instance > 0 && instance <= RESULT_SLOTS);
    size_t const slot = (size_t)(instance - 1);
    CHECK(info.metadata.route.client_owner_id == c->owner_id && c->calls[slot] == 0);
    CHECK(c->outputs[slot] == NULL);
    c->calls[slot]++;
    bool requested = false, expired = false;
    EXPECT(vireo_task_is_cancel_requested(task, &requested), VIREO_OK);
    EXPECT(vireo_task_metadata_deadline_expired(info.metadata, c->now_ns, &expired), VIREO_OK);
    vireo_result_t work = VIREO_OK;
    unsigned char response[4] = {0};
    size_t response_size = 0;
    vireo_task_payload_view_t input = {0};
    if (requested) {
        work = VIREO_RESULT_CANCELLED;
    } else if (expired) {
        work = VIREO_RESULT_TIMEOUT;
    } else {
        c->body_calls++;
        CHECK(info.metadata.operation == COPY_OPERATION || info.metadata.operation == FAIL_OPERATION);
        work = info.metadata.operation == FAIL_OPERATION ? VIREO_RESULT_DATABASE : VIREO_OK;
        EXPECT(vireo_task_borrow_payload(task, &input), VIREO_OK);
        if (input.size != 0) {
            CHECK(input.size == 3 && input.data[0] == (unsigned char)instance &&
                input.data[1] == 0 && input.data[2] == 255);
            memcpy(response, input.data, input.size);
            response[3] = 0x5a;
            response_size = sizeof(response);
        } else {
            CHECK(input.data == NULL);
        }
    }
    c->work_results[slot] = work;
    vireo_completion_metadata_t metadata = {0};
    EXPECT(vireo_completion_metadata_make(info.metadata, work, suggested_status(work), &metadata), VIREO_OK);
    size_t const budget = instance == c->failing_budget_instance ? 1 : 4096;
    errno = EDOM;
    vireo_result_t const created = vireo_completion_create_copy(metadata, response,
        response_size, budget, &c->outputs[slot]);
    CHECK(errno == EDOM);
    c->creation_results[slot] = created;
    if (created != VIREO_OK) {
        CHECK(created == VIREO_RESULT_RANGE && instance == c->failing_budget_instance);
        CHECK(c->outputs[slot] == NULL);
        /* 构造失败不能消费仍被 task 拥有的输入。 */
        CHECK(input.size == 3 && input.data[0] == (unsigned char)instance && input.data[2] == 255);
    } else {
        CHECK(c->outputs[slot] != NULL);
    }
    input = (vireo_task_payload_view_t){0};
    memset(response, 0, sizeof(response)); /* 结果须已复制，不能借此 callback 的栈。 */
    errno = EILSEQ;
    return created == VIREO_OK ? work : created;
}

/**
 * @brief
 *     原位准备空专用队列与单 worker，未启动，尚无并发访问。
 *
 * @param[out] f
 *     未发布、地址稳定的存储，持有全部最终清理义务。
 * @param[in] owner_id
 *     此场景非零数值域。
 */
static void prepare(completion_fixture_t *f, uint64_t owner_id) {
    memset(f, 0, sizeof(*f));
    f->context.owner_id = owner_id;
    f->context.now_ns = 100;
    vireo_task_queue_options_t const queue_options = {RESULT_SLOTS, 65536};
    vireo_thread_pool_options_t const pool_options = {1, 65536};
    EXPECT(vireo_task_queue_create(&queue_options, &f->queue), VIREO_OK);
    EXPECT(vireo_task_queue_prepare_wait(f->queue), VIREO_OK);
    EXPECT(vireo_thread_pool_create(&pool_options, &f->pool), VIREO_OK);
    vireo_thread_pool_configuration_t const configuration = {f->queue, execute, &f->context};
    EXPECT(vireo_thread_pool_configure(f->pool, &configuration, NULL), VIREO_OK);
}

/**
 * @brief
 *     通过公开入口构造独立任务并交给尚无 worker 访问的队列。
 *
 * @param[in,out] f
 *     已配置、未启动的稳定 fixture，queue 有容量。
 * @param[in] instance
 *     1..5，不复用，同客户使用相同 sequence。
 * @param[in] operation
 *     本测试 COPY 或 FAIL 标签。
 * @param[in] deadline
 *     同域 MONOTONIC 纳秒的有限期限。
 * @param[in] cancel
 *     可空存活强引用来源，不消费来源。
 */
static void enqueue(completion_fixture_t *f, uint64_t instance, uint32_t operation,
    uint64_t deadline, vireo_task_cancel_t *cancel) {
    vireo_task_route_t route = {0};
    vireo_task_metadata_t metadata = {0};
    EXPECT(vireo_task_route_make(f->context.owner_id, 7, 9, 7, &route), VIREO_OK);
    EXPECT(vireo_task_metadata_make(route, instance, operation, deadline, &metadata), VIREO_OK);
    unsigned char input[] = {(unsigned char)instance, 0, 255};
    size_t const size = instance == RESULT_SLOTS ? 0 : sizeof(input);
    vireo_task_t *task = NULL;
    if (cancel == NULL) {
        EXPECT(vireo_task_create_copy(metadata, input, size, 4096, &task), VIREO_OK);
    } else {
        EXPECT(vireo_task_create_copy_with_cancel(metadata, input, size, 4096, cancel, &task), VIREO_OK);
    }
    memset(input, 17, sizeof(input));
    vireo_task_queue_transfer_report_t transfer = {0};
    EXPECT(vireo_task_queue_try_push(f->queue, &task, &transfer), VIREO_OK);
    CHECK(task == NULL && transfer.transferred && transfer.pthread_error == 0);
}

/**
 * @brief
 *     真实启动并放行一个 worker，队列资格观测期间无其他队列访问。
 *
 * @param[in,out] f
 *     已配置、已入队且仍 OPEN/prepared 的 fixture。
 */
static void start(completion_fixture_t *f) {
    vireo_thread_pool_report_t report = {0};
    EXPECT(vireo_thread_pool_start(f->pool, &report), VIREO_OK);
    CHECK(report.created_count == 1 && report.joined_count == 0 && !report.execution_enabled);
    EXPECT(vireo_thread_pool_enable_execution(f->pool, &report), VIREO_OK);
    CHECK(report.execution_enabled);
}

/**
 * @brief
 *     caller 有限重试健康锁竞争，实际 DRAIN 和全部 join 后才读 context。
 *
 * @param[in,out] f
 *     完整已放行池，main 唯一串行管理且 POSIX 取消已禁用。
 * @param[in] expected
 *     FIFO 单 worker 的首个 callback 错误，不是每请求结果。
 *
 * @note
 *     不重试业务、同步异常或未知 BUSY；pool 内没有新增重试策略。
 */
static void finish_workers(completion_fixture_t *f, vireo_result_t expected) {
    vireo_thread_pool_shutdown_report_t report = {0};
    bool done = false;
    for (size_t attempt = 0; attempt < RETRY_LIMIT; ++attempt) {
        errno = EDOM;
        vireo_result_t const result = vireo_thread_pool_shutdown_and_join(f->pool,
            VIREO_TASK_QUEUE_DRAIN, &report);
        CHECK(errno == EDOM);
        bool const close_busy = report.stage == VIREO_THREAD_POOL_SHUTDOWN_STAGE_CLOSE_QUEUE &&
            report.close_report.stage == VIREO_TASK_QUEUE_STAGE_LOCK && report.close_report.pthread_error == EBUSY;
        bool const inspect_busy = report.stage == VIREO_THREAD_POOL_SHUTDOWN_STAGE_JOIN_WORKERS &&
            report.pool_report.stage == VIREO_THREAD_POOL_STAGE_CHECK_QUEUE;
        if (result == VIREO_RESULT_BUSY && (close_busy || inspect_busy)) {
            (void)sched_yield();
            continue;
        }
        CHECK(result == expected && report.close_called && report.join_called);
        CHECK(report.pool_report.created_count == 1 && report.pool_report.joined_count == 1);
        done = true;
        break;
    }
    CHECK(done);
    vireo_thread_pool_worker_result_t worker = {0};
    EXPECT(vireo_thread_pool_inspect_worker_result(f->pool, 0, &worker), VIREO_OK);
    CHECK(worker.result == expected && worker.stage == VIREO_THREAD_POOL_STAGE_EXECUTE_TASK &&
        worker.pthread_error == 0);
    /* 首错持久保存；已回收后重复收尾不重复返回历史工作失败。 */
    EXPECT(vireo_thread_pool_stop_and_join(f->pool, &report.pool_report), VIREO_OK);
    vireo_task_queue_info_t queue_info = {0};
    EXPECT(vireo_task_queue_inspect(f->queue, &queue_info), VIREO_OK);
    CHECK(queue_info.count == 0 && queue_info.state == VIREO_TASK_QUEUE_DRAIN);
    EXPECT(vireo_thread_pool_destroy(&f->pool), VIREO_OK);
    EXPECT(vireo_task_queue_destroy(&f->queue), VIREO_OK);
    CHECK(f->pool == NULL && f->queue == NULL);
}

/**
 * @brief
 *     所有 task/pool/queue 已结束后读取独立结果，再移动到局部 owner 并释放。
 *
 * @param[in,out] c
 *     已由成功 join 同步的 caller context。
 * @param[in] instance
 *     1..5且成功构造的结果实例。
 * @param[in] expected
 *     独立手写工作分类期望。
 * @param[in] deadline
 *     创建 task 时的原纳秒期限。
 */
static void consume(completion_context_t *c, uint64_t instance, vireo_result_t expected, uint64_t deadline) {
    size_t const slot = (size_t)(instance - 1);
    CHECK(c->calls[slot] == 1 && c->work_results[slot] == expected && c->creation_results[slot] == VIREO_OK);
    vireo_completion_t *owner = NULL;
    EXPECT(vireo_completion_move(&c->outputs[slot], &owner), VIREO_OK);
    CHECK(c->outputs[slot] == NULL && owner != NULL);
    vireo_completion_info_t info = {0};
    EXPECT(vireo_completion_inspect(owner, &info), VIREO_OK);
    CHECK(info.metadata.request.route.client_owner_id == c->owner_id);
    CHECK(info.metadata.request.route.client_slot_index == 7 && info.metadata.request.route.client_generation == 9);
    CHECK(info.metadata.request.route.request_sequence == 7 && info.metadata.request.request_instance_id == instance);
    CHECK(info.metadata.request.operation == (expected == VIREO_RESULT_DATABASE ? FAIL_OPERATION : COPY_OPERATION));
    CHECK(info.metadata.request.deadline_ns == deadline && info.metadata.result == expected);
    CHECK(info.metadata.suggested_status == suggested_status(expected));
    vireo_completion_payload_view_t view = {0};
    EXPECT(vireo_completion_borrow_payload(owner, &view), VIREO_OK);
    if ((expected == VIREO_OK || expected == VIREO_RESULT_DATABASE) && instance != RESULT_SLOTS) {
        unsigned char const bytes[] = {(unsigned char)instance, 0, 255, 0x5a};
        CHECK(info.payload_size == sizeof(bytes) && view.size == sizeof(bytes));
        CHECK(memcmp(view.data, bytes, sizeof(bytes)) == 0);
    } else {
        CHECK(info.payload_size == 0 && view.size == 0 && view.data == NULL);
    }
    view = (vireo_completion_payload_view_t){0};
    EXPECT(vireo_completion_destroy(&owner), VIREO_OK);
    CHECK(owner == NULL);
    bool expired = false;
    EXPECT(vireo_completion_metadata_deadline_expired(info.metadata, 100, &expired), VIREO_OK);
    CHECK(expired == (deadline <= 100)); /* 无资源的独立快照仍可查询。 */
}

static void historical_identity_and_deadline(void) {
    vireo_completion_t *results[3] = {0};
    vireo_completion_info_t snapshots[3] = {0};
    uint64_t const instances[] = {88, 89, 88};
    uint64_t const generations[] = {5, 5, 6};
    uint64_t const deadlines[] = {100, UINT64_MAX, 0};
    vireo_result_t const work[] = {VIREO_OK, VIREO_RESULT_DATABASE, VIREO_RESULT_CANCELLED};
    for (size_t i = 0; i < 3; ++i) {
        vireo_task_route_t route = {0};
        vireo_task_metadata_t request = {0};
        EXPECT(vireo_task_route_make(7, 2, generations[i], 9, &route), VIREO_OK);
        EXPECT(vireo_task_metadata_make(route, instances[i], 3, deadlines[i], &request), VIREO_OK);
        unsigned char data[] = {0x31, 0, 0x32};
        vireo_task_t *task = NULL;
        EXPECT(vireo_task_create_copy(request, data, sizeof(data), 4096, &task), VIREO_OK);
        vireo_task_info_t task_info = {0};
        EXPECT(vireo_task_inspect(task, &task_info), VIREO_OK);
        vireo_completion_metadata_t metadata = {0};
        EXPECT(vireo_completion_metadata_make(task_info.metadata, work[i], suggested_status(work[i]), &metadata), VIREO_OK);
        EXPECT(vireo_completion_create_copy(metadata, data, sizeof(data), 4096, &results[i]), VIREO_OK);
        memset(data, 0xff, sizeof(data));
        EXPECT(vireo_task_destroy(&task), VIREO_OK);
        EXPECT(vireo_completion_inspect(results[i], &snapshots[i]), VIREO_OK);
        CHECK(snapshots[i].metadata.request.request_instance_id == instances[i]);
        CHECK(snapshots[i].metadata.request.route.client_generation == generations[i]);
        CHECK(snapshots[i].metadata.result == work[i]);
    }
    for (size_t i = 0; i < 3; ++i) {
        for (size_t j = 0; j < 3; ++j) {
            bool same = true;
            EXPECT(vireo_completion_metadata_same_request(snapshots[i].metadata, snapshots[j].metadata, &same), VIREO_OK);
            CHECK(same == (i == j));
        }
        bool expired = false;
        EXPECT(vireo_completion_metadata_deadline_expired(snapshots[i].metadata, 100, &expired), VIREO_OK);
        CHECK(expired == (i != 1));
        EXPECT(vireo_completion_destroy(&results[i]), VIREO_OK);
        CHECK(snapshots[i].metadata.result == work[i]);
    }
}

static void cancel_outlives_task(void) {
    vireo_task_cancel_t *source = NULL, *exported = NULL;
    EXPECT(vireo_task_cancel_create(4096, &source), VIREO_OK);
    vireo_task_metadata_t const request = {{19, 0, 2, 9}, 1, COPY_OPERATION, UINT64_MAX};
    vireo_task_t *task = NULL;
    EXPECT(vireo_task_create_copy_with_cancel(request, NULL, 0, 4096, source, &task), VIREO_OK);
    EXPECT(vireo_task_retain_cancel(task, &exported), VIREO_OK);
    EXPECT(vireo_task_cancel_destroy(&source), VIREO_OK);
    EXPECT(vireo_task_cancel_request(exported), VIREO_OK);
    bool requested = false;
    EXPECT(vireo_task_is_cancel_requested(task, &requested), VIREO_OK);
    CHECK(requested);
    vireo_task_info_t task_info = {0};
    EXPECT(vireo_task_inspect(task, &task_info), VIREO_OK);
    vireo_completion_metadata_t metadata = {0};
    EXPECT(vireo_completion_metadata_make(task_info.metadata, VIREO_RESULT_CANCELLED,
        VIREO_STATUS_TASK_CANCELLED, &metadata), VIREO_OK);
    vireo_completion_t *completion = NULL;
    EXPECT(vireo_completion_create_copy(metadata, NULL, 0, 4096, &completion), VIREO_OK);
    EXPECT(vireo_task_destroy(&task), VIREO_OK);
    EXPECT(vireo_task_cancel_is_requested(exported, &requested), VIREO_OK);
    CHECK(requested);
    EXPECT(vireo_task_cancel_destroy(&exported), VIREO_OK);
    CHECK(source == NULL && exported == NULL && task == NULL);
    vireo_completion_info_t info = {0};
    EXPECT(vireo_completion_inspect(completion, &info), VIREO_OK);
    CHECK(info.metadata.result == VIREO_RESULT_CANCELLED && info.metadata.request.request_instance_id == 1);
    EXPECT(vireo_completion_destroy(&completion), VIREO_OK);
}

static void worker_outcomes(void) {
    completion_fixture_t f;
    prepare(&f, 41);
    vireo_task_cancel_t *cancel = NULL;
    EXPECT(vireo_task_cancel_create(4096, &cancel), VIREO_OK);
    EXPECT(vireo_task_cancel_request(cancel), VIREO_OK);
    enqueue(&f, 1, COPY_OPERATION, UINT64_MAX, NULL);
    enqueue(&f, 2, FAIL_OPERATION, UINT64_MAX, NULL);
    enqueue(&f, 3, COPY_OPERATION, UINT64_MAX, cancel);
    enqueue(&f, 4, COPY_OPERATION, 100, NULL);
    enqueue(&f, 5, COPY_OPERATION, UINT64_MAX, NULL);
    EXPECT(vireo_task_cancel_destroy(&cancel), VIREO_OK);
    start(&f);
    finish_workers(&f, VIREO_RESULT_DATABASE);
    CHECK(f.context.body_calls == 3);
    vireo_result_t const expected[] = {VIREO_OK, VIREO_RESULT_DATABASE, VIREO_RESULT_CANCELLED,
        VIREO_RESULT_TIMEOUT, VIREO_OK};
    for (size_t i = 0; i < RESULT_SLOTS; ++i) {
        consume(&f.context, (uint64_t)i + 1, expected[i], i == 3 ? 100 : UINT64_MAX);
    }
}

static void creation_failure_and_continued_cleanup(void) {
    completion_fixture_t f;
    prepare(&f, 42);
    f.context.failing_budget_instance = 2;
    for (uint64_t instance = 1; instance <= 3; ++instance) {
        enqueue(&f, instance, COPY_OPERATION, UINT64_MAX, NULL);
    }
    start(&f);
    finish_workers(&f, VIREO_RESULT_RANGE);
    CHECK(f.context.body_calls == 3 && f.context.calls[1] == 1);
    CHECK(f.context.work_results[1] == VIREO_OK && f.context.creation_results[1] == VIREO_RESULT_RANGE);
    CHECK(f.context.outputs[1] == NULL);
    consume(&f.context, 1, VIREO_OK, UINT64_MAX);
    consume(&f.context, 3, VIREO_OK, UINT64_MAX);
}

static void cancel_pending_is_caller_owned(void) {
    vireo_task_queue_t *queue = NULL;
    vireo_task_queue_options_t const options = {2, 65536};
    EXPECT(vireo_task_queue_create(&options, &queue), VIREO_OK);
    vireo_task_cancel_t *cancels[2] = {0};
    for (size_t i = 0; i < 2; ++i) {
        EXPECT(vireo_task_cancel_create(4096, &cancels[i]), VIREO_OK);
        vireo_task_metadata_t const request = {{51, 0, 1, 7}, (uint64_t)i + 101, COPY_OPERATION, UINT64_MAX};
        vireo_task_t *task = NULL;
        EXPECT(vireo_task_create_copy_with_cancel(request, NULL, 0, 4096, cancels[i], &task), VIREO_OK);
        vireo_task_queue_transfer_report_t transfer = {0};
        EXPECT(vireo_task_queue_try_push(queue, &task, &transfer), VIREO_OK);
        CHECK(task == NULL && transfer.transferred);
    }
    vireo_task_queue_close_report_t closed = {0};
    EXPECT(vireo_task_queue_close(queue, VIREO_TASK_QUEUE_CANCEL_PENDING, &closed), VIREO_OK);
    CHECK(closed.changed);
    vireo_task_t *task = NULL;
    vireo_task_queue_transfer_report_t transfer = {0};
    EXPECT(vireo_task_queue_try_pop(queue, &task, &transfer), VIREO_RESULT_CANCELLED);
    CHECK(task == NULL && !transfer.transferred);
    EXPECT(vireo_task_queue_destroy(&queue), VIREO_RESULT_BUSY);
    for (size_t i = 0; i < 2; ++i) {
        EXPECT(vireo_task_queue_try_take_cancelled(queue, &task, &transfer), VIREO_OK);
        CHECK(task != NULL && transfer.transferred);
        bool requested = true;
        EXPECT(vireo_task_is_cancel_requested(task, &requested), VIREO_OK);
        CHECK(!requested); /* queue close 没有自动 request_cancel。 */
        EXPECT(vireo_task_cancel_request(cancels[i]), VIREO_OK);
        EXPECT(vireo_task_is_cancel_requested(task, &requested), VIREO_OK);
        CHECK(requested);
        vireo_task_info_t info = {0};
        EXPECT(vireo_task_inspect(task, &info), VIREO_OK);
        CHECK(info.metadata.request_instance_id == (uint64_t)i + 101);
        vireo_completion_metadata_t metadata = {0};
        EXPECT(vireo_completion_metadata_make(info.metadata, VIREO_RESULT_CANCELLED,
            VIREO_STATUS_TASK_CANCELLED, &metadata), VIREO_OK);
        vireo_completion_t *completion = NULL;
        EXPECT(vireo_completion_create_copy(metadata, NULL, 0, 4096, &completion), VIREO_OK);
        EXPECT(vireo_task_destroy(&task), VIREO_OK);
        EXPECT(vireo_task_cancel_destroy(&cancels[i]), VIREO_OK);
        vireo_completion_info_t result = {0};
        EXPECT(vireo_completion_inspect(completion, &result), VIREO_OK);
        CHECK(result.metadata.request.request_instance_id == (uint64_t)i + 101 &&
            result.metadata.result == VIREO_RESULT_CANCELLED);
        EXPECT(vireo_completion_destroy(&completion), VIREO_OK);
    }
    EXPECT(vireo_task_queue_try_take_cancelled(queue, &task, &transfer), VIREO_RESULT_NOT_FOUND);
    CHECK(task == NULL && !transfer.transferred);
    EXPECT(vireo_task_queue_destroy(&queue), VIREO_OK);
    CHECK(queue == NULL);
}

int main(void) {
    int previous_cancel_state = 0;
    CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previous_cancel_state) == 0);
    historical_identity_and_deadline();
    cancel_outlives_task();
    worker_outcomes();
    creation_failure_and_continued_cleanup();
    cancel_pending_is_caller_owned();
    CHECK(pthread_setcancelstate(previous_cancel_state, NULL) == 0);
    puts("completion integration: 5 groups passed");
    return 0;
}
