/*
 * PROJECT : VIREO
 * FILE    : test_completion_queue_integration.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-13
 * BRIEF   : 仅公开合同的多 worker 回投、实时消费、关闭和最后排空验证
 */
#include <vireo/thread/completion_queue.h>
#include <vireo/thread/thread_pool.h>

#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #x); abort(); } } while (0)
#define EXPECT(x, expected) do { errno = EDOM; vireo_result_t const got = (x); CHECK(got == (expected) && errno == EDOM); } while (0)
#define RETRY_LIMIT 4000000U
#define MAX_REQUESTS 96U
#define INPUT_SALT UINT64_C(0x1745abcd012389ef)
#define RESPONSE_SALT UINT64_C(0x129087ff0abc3345)

/**
 * @brief
 *     启动前固定策略、运行原子计数的执行上下文，不保存 task/响应借用地址。
 */
typedef struct delivery_context {
    vireo_completion_queue_t *outputs; /**< 借用结果队列，所有 worker join 前保活。 */
    atomic_bool release; /**< caller release 放行、worker acquire 读；仅测试门控，不是产品取消。 */
    uint64_t budget_failure_id; /**< 指定预算1的实例，0为无故障，启动前固定。 */
    uint64_t work_failure_id; /**< 明确选择 DATABASE 结果的实例，0为无故障，启动前固定。 */
    atomic_size_t started; /**< 已进入 callback 的条数，不表示等待或已完成。 */
    atomic_size_t submit_started; /**< 已准备调用 wait_push 的条数，不证明内部 cond_wait 位置。 */
    atomic_size_t submitted; /**< 报告已经转移给完成队列的条数。 */
    atomic_size_t rejected; /**< wait_push 实际返回 CANCELLED 的条数。 */
    atomic_size_t creation_failures; /**< 响应预算校验返回 RANGE、没有 owner 的条数。 */
    atomic_size_t cleaned; /**< 提交未转移后由 worker 配对销毁的响应条数。 */
} delivery_context_t;

/** fixture 地址保持稳定，pool 对 context 和任务队列的长借到 pool 销毁。 */
typedef struct delivery_fixture {
    vireo_thread_pool_t *pool; /**< caller 唯一 owner，管理交给 helper 时 main 不访问。 */
    vireo_task_queue_t *tasks; /**< caller 唯一 owner，专用 pool，pending 由 caller 处理。 */
    vireo_completion_queue_t *outputs; /**< caller 唯一 owner，main 为单 consumer。 */
    size_t workers; /**< 固定 worker 配置条数，不是正在运行的线程数。 */
    delivery_context_t context; /**< 自有稳定上下文，原子显式初始化，不复制此 fixture。 */
} delivery_fixture_t;

/** 仅一个 helper 管理 pool；结果经原子完成提示及 pthread_join 发布。 */
typedef struct join_context {
    vireo_thread_pool_t *pool; /**< 借至 helper join，main 保活且不同时管理。 */
    atomic_bool finished; /**< stop_and_join 返回后 release true，main acquire 读，非池生命周期所有者。 */
    vireo_result_t result; /**< helper 独占写，main pthread_join 后读原结果。 */
    vireo_thread_pool_report_t report; /**< helper 独占管理报告，main pthread_join 后读真实进度。 */
} join_context_t;

/**
 * @brief
 *     生成独立请求数值描述，偶数期限0仍是有效有限时间，不自动过滤。
 *
 * @param[in] id
 *     1..96实例标签；仅场景身份，不认证网络客户。
 *
 * @return
 *     完整独立元数据；CHECK 失败直接终止测试。
 */
static vireo_task_metadata_t request_metadata(uint64_t id) {
    CHECK(id > 0 && id <= MAX_REQUESTS);
    vireo_task_route_t route;
    EXPECT(vireo_task_route_make(103, (size_t)(id % 3), 17 + id % 2,
        (uint32_t)id, &route), VIREO_OK);
    vireo_task_metadata_t metadata;
    EXPECT(vireo_task_metadata_make(route, id, 7, id % 2 == 0 ? 0 : UINT64_MAX,
        &metadata), VIREO_OK);
    return metadata;
}

/**
 * @brief
 *     公开复制任务字节，随后改写原输入，返回唯一 owner。
 *
 * @param[in] id
 *     1..96非零标签。
 *
 * @return
 *     caller 自有 task，不保存输入数组地址。
 */
static vireo_task_t *make_task(uint64_t id) {
    uint64_t bytes[2] = {id, id ^ INPUT_SALT};
    vireo_task_t *task = NULL;
    EXPECT(vireo_task_create_copy(request_metadata(id), bytes, sizeof(bytes), 1024, &task), VIREO_OK);
    memset(bytes, 0, sizeof(bytes));
    return task;
}

/**
 * @brief
 *     pool 借 task 给本函数；独立响应交接或明确失败清理后正常返回。
 *
 * @param[in,out] context
 *     稳定长借存储，策略启动前固定，共享计数只原子访问。
 * @param[in] task
 *     短借 const task 到返回，不保存、移动或销毁；pool 负责后续清理。
 *
 * @return
 *     已交接的原提交结果、预算构造 RANGE 或关闭 CANCELLED，pool 可记录首错。
 *
 * @note
 *     worker 已由 pool 禁用 POSIX 取消，不改变它，不重入 pool 管理。
 *     只模拟明确的结果值，不执行 DB、网络或真实期限策略；允许阻塞 wait_push。
 *     失败源仍自有时配对销毁，已经交接时不销毁、不回滚。
 */
static vireo_result_t execute(void *context, vireo_task_t const *task) {
    delivery_context_t *c = context;
    vireo_task_info_t info;
    vireo_task_payload_view_t view;
    EXPECT(vireo_task_inspect(task, &info), VIREO_OK);
    EXPECT(vireo_task_borrow_payload(task, &view), VIREO_OK);
    uint64_t const id = info.metadata.request_instance_id;
    CHECK(id > 0 && id <= MAX_REQUESTS && view.size == 2 * sizeof(uint64_t));
    uint64_t input[2];
    memcpy(input, view.data, sizeof(input));
    CHECK(input[0] == id && input[1] == (id ^ INPUT_SALT));
    atomic_fetch_add_explicit(&c->started, 1, memory_order_release);
    while (!atomic_load_explicit(&c->release, memory_order_acquire)) { sched_yield(); }
    vireo_result_t const work = id == c->work_failure_id ? VIREO_RESULT_DATABASE : VIREO_OK;
    vireo_status_t const status = work == VIREO_OK ? VIREO_STATUS_OK : VIREO_STATUS_DB_ERROR;
    vireo_completion_metadata_t metadata;
    EXPECT(vireo_completion_metadata_make(info.metadata, work, status, &metadata), VIREO_OK);
    uint64_t response[3] = {id, input[1] ^ RESPONSE_SALT, info.metadata.route.client_generation};
    vireo_completion_t *owner = NULL;
    errno = EDOM;
    vireo_result_t result = vireo_completion_create_copy(metadata, response, sizeof(response),
        id == c->budget_failure_id ? 1 : 1024, &owner);
    CHECK(errno == EDOM);
    memset(response, 0, sizeof(response));
    if (result != VIREO_OK) {
        CHECK(id == c->budget_failure_id && result == VIREO_RESULT_RANGE && owner == NULL);
        atomic_fetch_add_explicit(&c->creation_failures, 1, memory_order_relaxed);
        return result;
    }
    atomic_fetch_add_explicit(&c->submit_started, 1, memory_order_release);
    vireo_completion_queue_transfer_report_t report;
    errno = EDOM;
    result = vireo_completion_queue_wait_push(c->outputs, &owner, &report);
    CHECK(errno == EDOM);
    if (report.transferred) {
        CHECK(owner == NULL);
        atomic_fetch_add_explicit(&c->submitted, 1, memory_order_release);
    } else {
        CHECK(owner != NULL && result == VIREO_RESULT_CANCELLED);
        atomic_fetch_add_explicit(&c->rejected, 1, memory_order_relaxed);
        EXPECT(vireo_completion_destroy(&owner), VIREO_OK);
        atomic_fetch_add_explicit(&c->cleaned, 1, memory_order_relaxed);
    }
    return result;
}

/**
 * @brief
 *     原子等待测试阶段，不读取活跃线程的普通报告或 owner。
 *
 * @param[in] counter
 *     存活原子计数，生产者 release 发布。
 * @param[in] minimum
 *     预期最低次数，不等于内部等待者数量。
 *
 * @note
 *     有限让步用于测试握手，不是生产等待时限或队列内部自旋。
 */
static void await_count(atomic_size_t const *counter, size_t minimum) {
    for (unsigned i = 0; i < RETRY_LIMIT; ++i) {
        if (atomic_load_explicit(counter, memory_order_acquire) >= minimum) { return; }
        sched_yield();
    }
    CHECK(false);
}

/**
 * @brief
 *     创建两个显式预算队列和固定 pool，真实线程先停驻不取任务。
 *
 * @param[in,out] f
 *     未使用的稳定 fixture 地址，不能随后复制或移动。
 * @param[in] workers
 *     正固定 worker 数。
 * @param[in] task_capacity
 *     正任务槽数，足以预放本组任务。
 * @param[in] output_capacity
 *     正响应槽数，允许小于任务数。
 * @param[in] held
 *     true 时 callback 到测试门暂停，caller 须明确放行。
 * @param[in] budget_failure_id
 *     预算1实例，0无故障。
 * @param[in] work_failure_id
 *     DATABASE结果实例，0无故障。
 */
static void init_fixture(delivery_fixture_t *f, size_t workers, size_t task_capacity,
    size_t output_capacity, bool held, uint64_t budget_failure_id, uint64_t work_failure_id) {
    f->pool = NULL; f->tasks = NULL; f->outputs = NULL; f->workers = workers;
    vireo_task_queue_options_t const task_options = {task_capacity, 8192};
    vireo_completion_queue_options_t const output_options = {output_capacity, 8192};
    EXPECT(vireo_task_queue_create(&task_options, &f->tasks), VIREO_OK);
    EXPECT(vireo_task_queue_prepare_wait(f->tasks), VIREO_OK);
    EXPECT(vireo_completion_queue_create(&output_options, &f->outputs), VIREO_OK);
    EXPECT(vireo_completion_queue_prepare_wait(f->outputs), VIREO_OK);
    f->context.outputs = f->outputs;
    f->context.budget_failure_id = budget_failure_id;
    f->context.work_failure_id = work_failure_id;
    atomic_init(&f->context.release, !held);
    atomic_init(&f->context.started, 0);
    atomic_init(&f->context.submit_started, 0);
    atomic_init(&f->context.submitted, 0);
    atomic_init(&f->context.rejected, 0);
    atomic_init(&f->context.creation_failures, 0);
    atomic_init(&f->context.cleaned, 0);
    vireo_thread_pool_options_t const options = {workers, 8192};
    EXPECT(vireo_thread_pool_create(&options, &f->pool), VIREO_OK);
    vireo_thread_pool_configuration_t const configuration = {f->tasks, execute, &f->context};
    EXPECT(vireo_thread_pool_configure(f->pool, &configuration, NULL), VIREO_OK);
    vireo_thread_pool_report_t report;
    EXPECT(vireo_thread_pool_start(f->pool, &report), VIREO_OK);
    CHECK(report.created_count == workers && report.joined_count == 0 && !report.execution_enabled);
}

/**
 * @brief
 *     线程仍停驻时预放完整任务，无与 worker 的任务队列访问竞争。
 *
 * @param[in,out] f
 *     已启动未放行 fixture。
 * @param[in] count
 *     1..96且不超过显式任务容量。
 */
static void seed_tasks(delivery_fixture_t *f, size_t count) {
    CHECK(count > 0 && count <= MAX_REQUESTS);
    vireo_task_queue_transfer_report_t report;
    for (size_t i = 1; i <= count; ++i) {
        vireo_task_t *task = make_task((uint64_t)i);
        EXPECT(vireo_task_queue_try_push(f->tasks, &task, &report), VIREO_OK);
        CHECK(task == NULL && report.transferred);
    }
    vireo_thread_pool_report_t pool_report;
    EXPECT(vireo_thread_pool_enable_execution(f->pool, &pool_report), VIREO_OK);
    CHECK(pool_report.execution_enabled);
}

/**
 * @brief
 *     公共 close 的真实锁竞争只在测试外层有限让步，模式永久保持。
 *
 * @param[in,out] tasks
 *     存活任务队列，可与 worker 领取并发。
 * @param[in] mode
 *     DRAIN 或 CANCEL_PENDING。
 */
static void close_tasks(vireo_task_queue_t *tasks, vireo_task_queue_state_t mode) {
    for (unsigned i = 0; i < RETRY_LIMIT; ++i) {
        vireo_task_queue_close_report_t report;
        errno = EDOM;
        vireo_result_t const result = vireo_task_queue_close(tasks, mode, &report);
        CHECK(errno == EDOM);
        if (result == VIREO_OK) { return; }
        CHECK(result == VIREO_RESULT_BUSY && !report.changed && report.pthread_error == EBUSY);
        sched_yield();
    }
    CHECK(false);
}

/**
 * @brief
 *     已成功关闭任务队列后回收 worker，只资格观测竞争可在外层重试。
 *
 * @param[in,out] pool
 *     同步交给此唯一管理调用者的存活池，全程禁POSIX取消。
 * @param[out] report
 *     此线程独占报告，记录最后一次实际调用及累计回收进度。
 *
 * @return
 *     原回收/worker首错；不把已有进度当成可盲目重试的 BUSY。
 */
static vireo_result_t finish_join(vireo_thread_pool_t *pool, vireo_thread_pool_report_t *report) {
    for (unsigned i = 0; i < RETRY_LIMIT; ++i) {
        errno = EDOM;
        vireo_result_t const result = vireo_thread_pool_stop_and_join(pool, report);
        CHECK(errno == EDOM);
        if (result != VIREO_RESULT_BUSY) { return result; }
        CHECK(report->stage == VIREO_THREAD_POOL_STAGE_CHECK_QUEUE && report->pthread_error == 0);
        sched_yield();
    }
    CHECK(false);
    return VIREO_RESULT_INTERNAL;
}

/**
 * @brief
 *     唯一管理线程 join，main 同时保持单消费者领取能力。
 *
 * @param[in,out] argument
 *     存活独占 join_context；完成标志原子，普通结果只 pthread_join 后读。
 *
 * @return
 *     NULL，无资源所有权返回。
 */
static void *join_workers(void *argument) {
    join_context_t *j = argument;
    CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL) == 0);
    j->result = finish_join(j->pool, &j->report);
    atomic_store_explicit(&j->finished, true, memory_order_release);
    return NULL;
}

/**
 * @brief
 *     核验完整请求描述、显式工作结果和独立响应字节，不认证当前网络客户。
 *
 * @param[in] completion
 *     consumer 唯一拥有对象，只在此函数内短借 payload。
 * @param[in] work_failure_id
 *     本组明确定义的 DATABASE 实例，0为无故障。
 *
 * @return
 *     非零实例标签，供caller精确去重。
 */
static uint64_t verify_completion(vireo_completion_t const *completion, uint64_t work_failure_id) {
    vireo_completion_info_t info;
    vireo_completion_payload_view_t view;
    EXPECT(vireo_completion_inspect(completion, &info), VIREO_OK);
    EXPECT(vireo_completion_borrow_payload(completion, &view), VIREO_OK);
    uint64_t const id = info.metadata.request.request_instance_id;
    CHECK(id > 0 && id <= MAX_REQUESTS);
    vireo_task_metadata_t const expected = request_metadata(id);
    bool same = false, expired = false;
    EXPECT(vireo_task_metadata_same_request(info.metadata.request, expected, &same), VIREO_OK);
    CHECK(same && info.metadata.request.operation == expected.operation);
    CHECK(info.metadata.request.deadline_ns == expected.deadline_ns);
    EXPECT(vireo_completion_metadata_deadline_expired(info.metadata, 1, &expired), VIREO_OK);
    CHECK(expired == (id % 2 == 0));
    vireo_result_t const work = id == work_failure_id ? VIREO_RESULT_DATABASE : VIREO_OK;
    CHECK(info.metadata.result == work);
    CHECK(info.metadata.suggested_status == (work == VIREO_OK ? VIREO_STATUS_OK : VIREO_STATUS_DB_ERROR));
    uint64_t data[3];
    CHECK(info.payload_size == sizeof(data) && view.size == sizeof(data));
    memcpy(data, view.data, sizeof(data));
    CHECK(data[0] == id && data[1] == (id ^ INPUT_SALT ^ RESPONSE_SALT));
    CHECK(data[2] == expected.route.client_generation);
    return id;
}

/**
 * @brief
 *     对一项真实转出响应核验、去重并配对销毁。
 *
 * @param[in,out] completion
 *     必需独占非空 owner 地址，函数成功后清空。
 * @param[in,out] seen
 *     main独占的97个bool，实例1..96用来去重，不跨线程共享。
 * @param[in,out] count
 *     main独占领取数量，单位条。
 * @param[in] work_failure_id
 *     本组工作错误标签。
 */
static void record_output(vireo_completion_t **completion, bool seen[MAX_REQUESTS + 1],
    size_t *count, uint64_t work_failure_id) {
    uint64_t const id = verify_completion(*completion, work_failure_id);
    CHECK(!seen[id]); seen[id] = true; ++*count;
    EXPECT(vireo_completion_destroy(completion), VIREO_OK);
}

/**
 * @brief
 *     helper join期间main持续领取，完成后先pthread_join helper再操作pool。
 *
 * @param[in,out] f
 *     存活fixture，main此函数内不管理pool，仅访问completion queue。
 * @param[in,out] j
 *     存活独占helper上下文，结果pthread_join后才读。
 * @param[in,out] seen
 *     main独占去重记录。
 * @param[in,out] count
 *     main独占已消费条数。
 *
 * @note
 *     atomic finished只是提示；实际线程句柄仍必须pthread_join消费。
 */
static void consume_during_join(delivery_fixture_t *f, join_context_t *j,
    bool seen[MAX_REQUESTS + 1], size_t *count) {
    j->pool = f->pool; j->result = VIREO_OK;
    atomic_init(&j->finished, false);
    pthread_t helper;
    CHECK(pthread_create(&helper, NULL, join_workers, j) == 0);
    unsigned attempts = 0;
    while (!atomic_load_explicit(&j->finished, memory_order_acquire)) {
        CHECK(attempts++ < RETRY_LIMIT);
        vireo_completion_t *completion = NULL;
        vireo_completion_queue_transfer_report_t report;
        errno = EDOM;
        vireo_result_t const result = vireo_completion_queue_try_pop(f->outputs, &completion, &report);
        CHECK(errno == EDOM);
        if (result == VIREO_OK) {
            CHECK(report.transferred && completion != NULL);
            record_output(&completion, seen, count, f->context.work_failure_id);
        } else {
            CHECK((result == VIREO_RESULT_BUSY || result == VIREO_RESULT_NOT_FOUND) &&
                !report.transferred && completion == NULL);
            sched_yield();
        }
    }
    CHECK(pthread_join(helper, NULL) == 0);
    CHECK(j->report.created_count == f->workers && j->report.joined_count == f->workers);
}

/**
 * @brief
 *     all worker join 后close结果队列，并真实调用最后drain到CANCELLED。
 *
 * @param[in,out] f
 *     所有producer已经成功join的存活fixture。
 * @param[in,out] seen
 *     main独占去重记录。
 * @param[in,out] count
 *     main独占总领取数。
 *
 * @return
 *     本次最后drain实际领取条数，可以为0。
 */
static size_t final_drain(delivery_fixture_t *f, bool seen[MAX_REQUESTS + 1], size_t *count) {
    vireo_completion_queue_close_report_t closed;
    EXPECT(vireo_completion_queue_close(f->outputs, &closed), VIREO_OK);
    size_t const before = *count;
    for (;;) {
        vireo_completion_t *completion = NULL;
        vireo_completion_queue_transfer_report_t report;
        errno = EDOM;
        vireo_result_t const result = vireo_completion_queue_try_pop(f->outputs, &completion, &report);
        CHECK(errno == EDOM);
        if (result == VIREO_RESULT_CANCELLED) {
            CHECK(completion == NULL && !report.transferred); break;
        }
        CHECK(result == VIREO_OK && report.transferred && completion != NULL);
        record_output(&completion, seen, count, f->context.work_failure_id);
    }
    return *count - before;
}

/**
 * @brief
 *     join后公开核验worker首错，允许没处理故障实例的worker保留OK。
 *
 * @param[in] f
 *     全部worker成功join且caller串行管理的fixture。
 * @param[in] error
 *     本场景唯一允许的非OK首错，OK场景不允许任何错误。
 *
 * @return
 *     有该非OK首错的worker条数；不代表失败任务条数。
 */
static size_t verify_workers(delivery_fixture_t const *f, vireo_result_t error) {
    vireo_thread_pool_info_t info;
    EXPECT(vireo_thread_pool_inspect(f->pool, &info), VIREO_OK);
    CHECK(info.created_count == f->workers && info.joined_count == f->workers);
    CHECK(info.stop_requested && info.execution_enabled);
    size_t errors = 0;
    for (size_t i = 0; i < f->workers; ++i) {
        vireo_thread_pool_worker_result_t result;
        EXPECT(vireo_thread_pool_inspect_worker_result(f->pool, i, &result), VIREO_OK);
        if (result.result != VIREO_OK) {
            CHECK(error != VIREO_OK && result.result == error);
            CHECK(result.stage == VIREO_THREAD_POOL_STAGE_EXECUTE_TASK && result.pthread_error == 0);
            ++errors;
        } else { CHECK(result.stage == VIREO_THREAD_POOL_STAGE_NONE); }
    }
    return errors;
}

/**
 * @brief
 *     停止所有访问并核验两个队列为空后销毁，pool先释放长期借用。
 *
 * @param[in,out] f
 *     全部worker/helper已join，pending和响应均已显式处理的fixture。
 * @param[in] rejected
 *     预期完成队列关闭拒绝累计。
 */
static void destroy_fixture(delivery_fixture_t *f, uint64_t rejected) {
    vireo_completion_queue_info_t info;
    vireo_completion_queue_metrics_t metrics;
    EXPECT(vireo_completion_queue_inspect(f->outputs, &info), VIREO_OK);
    EXPECT(vireo_completion_queue_inspect_metrics(f->outputs, &metrics), VIREO_OK);
    CHECK(info.count == 0 && info.closed && info.wait_prepared && info.max_memory_bytes == 8192);
    CHECK(info.allocated_bytes <= info.max_memory_bytes && metrics.depth == 0);
    CHECK(metrics.high_watermark <= info.capacity && metrics.full_rejections == 0);
    CHECK(metrics.closed_rejections == rejected && !metrics.rejection_count_saturated);
    vireo_task_queue_info_t task_info;
    EXPECT(vireo_task_queue_inspect(f->tasks, &task_info), VIREO_OK);
    CHECK(task_info.count == 0 && task_info.state != VIREO_TASK_QUEUE_OPEN);
    EXPECT(vireo_thread_pool_destroy(&f->pool), VIREO_OK);
    EXPECT(vireo_completion_queue_destroy(&f->outputs), VIREO_OK);
    EXPECT(vireo_task_queue_destroy(&f->tasks), VIREO_OK);
    CHECK(f->pool == NULL && f->outputs == NULL && f->tasks == NULL);
}

/**
 * @brief
 *     4worker/96任务/3结果槽，先观察满占用与提交入口边界，再持续消费配合join。
 *
 * @note
 *     submit_started不证明内部cond_wait已进入；具体等待位置由本核心旧wait测试验证。
 */
static void live_drain(void) {
    delivery_fixture_t f;
    init_fixture(&f, 4, 97, 3, false, 0, 0);
    seed_tasks(&f, 96);
    await_count(&f.context.submitted, 3);
    await_count(&f.context.submit_started, 4);
    vireo_completion_queue_metrics_t metrics;
    vireo_result_t observed = VIREO_RESULT_BUSY;
    for (unsigned i = 0; i < RETRY_LIMIT && observed == VIREO_RESULT_BUSY; ++i) {
        errno = EDOM;
        observed = vireo_completion_queue_inspect_metrics(f.outputs, &metrics);
        CHECK(errno == EDOM); sched_yield();
    }
    CHECK(observed == VIREO_OK && metrics.depth == 3 && metrics.high_watermark == 3);
    CHECK(metrics.full_rejections == 0 && atomic_load_explicit(&f.context.submitted, memory_order_acquire) == 3);
    close_tasks(f.tasks, VIREO_TASK_QUEUE_DRAIN);
    bool seen[MAX_REQUESTS + 1] = {false}; size_t count = 0;
    join_context_t join;
    consume_during_join(&f, &join, seen, &count);
    CHECK(join.result == VIREO_OK);
    (void)final_drain(&f, seen, &count);
    CHECK(count == 96 && atomic_load(&f.context.started) == 96 && atomic_load(&f.context.submitted) == 96);
    CHECK(atomic_load(&f.context.rejected) == 0 && atomic_load(&f.context.creation_failures) == 0);
    for (size_t i = 1; i <= 96; ++i) { CHECK(seen[i]); }
    CHECK(verify_workers(&f, VIREO_OK) == 0);
    destroy_fixture(&f, 0);
}

/**
 * @brief
 *     明确结果容量容纳全部五项，join后真实最后drain五项，不把空队列当join证明。
 */
static void buffered_last_drain(void) {
    delivery_fixture_t f;
    init_fixture(&f, 2, 11, 7, false, 0, 0);
    seed_tasks(&f, 5); close_tasks(f.tasks, VIREO_TASK_QUEUE_DRAIN);
    vireo_thread_pool_report_t report;
    CHECK(finish_join(f.pool, &report) == VIREO_OK && report.joined_count == 2);
    vireo_completion_queue_info_t info;
    EXPECT(vireo_completion_queue_inspect(f.outputs, &info), VIREO_OK);
    CHECK(info.count == 5 && !info.closed);
    bool seen[MAX_REQUESTS + 1] = {false}; size_t count = 0;
    CHECK(final_drain(&f, seen, &count) == 5 && count == 5);
    CHECK(verify_workers(&f, VIREO_OK) == 0);
    destroy_fixture(&f, 0);
}

/**
 * @brief
 *     CP收回七个pending，不抢占两个已领取callback，结果端继续消费直到join。
 */
static void cancel_pending(void) {
    delivery_fixture_t f;
    init_fixture(&f, 2, 11, 1, true, 0, 0);
    seed_tasks(&f, 9); await_count(&f.context.started, 2);
    close_tasks(f.tasks, VIREO_TASK_QUEUE_CANCEL_PENDING);
    bool cancelled[MAX_REQUESTS + 1] = {false}; size_t pending = 0;
    for (;;) {
        vireo_task_t *task = NULL;
        vireo_task_queue_transfer_report_t report;
        EXPECT(vireo_task_queue_try_take_cancelled(f.tasks, &task, &report),
            pending < 7 ? VIREO_OK : VIREO_RESULT_NOT_FOUND);
        if (task == NULL) { CHECK(pending == 7 && !report.transferred); break; }
        vireo_task_info_t info;
        EXPECT(vireo_task_inspect(task, &info), VIREO_OK);
        uint64_t const id = info.metadata.request_instance_id;
        CHECK(id >= 3 && id <= 9 && !cancelled[id] && report.transferred);
        cancelled[id] = true; ++pending;
        EXPECT(vireo_task_destroy(&task), VIREO_OK);
    }
    atomic_store_explicit(&f.context.release, true, memory_order_release);
    bool seen[MAX_REQUESTS + 1] = {false}; size_t count = 0;
    join_context_t join;
    consume_during_join(&f, &join, seen, &count);
    CHECK(join.result == VIREO_OK);
    (void)final_drain(&f, seen, &count);
    CHECK(count == 2 && seen[1] && seen[2] && atomic_load(&f.context.started) == 2);
    CHECK(atomic_load(&f.context.submitted) == 2 && atomic_load(&f.context.cleaned) == 0);
    for (size_t i = 3; i <= 9; ++i) { CHECK(cancelled[i] && !seen[i]); }
    CHECK(verify_workers(&f, VIREO_OK) == 0);
    destroy_fixture(&f, 0);
}

/**
 * @brief
 *     结果端预关闭，十二个真实callback提交被拒且仍唯一拥有，各自明确销毁。
 */
static void closed_outputs(void) {
    delivery_fixture_t f;
    init_fixture(&f, 3, 13, 1, false, 0, 0);
    vireo_completion_queue_close_report_t closed;
    EXPECT(vireo_completion_queue_close(f.outputs, &closed), VIREO_OK);
    CHECK(closed.changed);
    seed_tasks(&f, 12); close_tasks(f.tasks, VIREO_TASK_QUEUE_DRAIN);
    vireo_thread_pool_report_t report;
    CHECK(finish_join(f.pool, &report) == VIREO_RESULT_CANCELLED && report.joined_count == 3);
    CHECK(atomic_load(&f.context.started) == 12 && atomic_load(&f.context.submitted) == 0);
    CHECK(atomic_load(&f.context.rejected) == 12 && atomic_load(&f.context.cleaned) == 12);
    CHECK(atomic_load(&f.context.creation_failures) == 0);
    bool seen[MAX_REQUESTS + 1] = {false}; size_t count = 0;
    CHECK(final_drain(&f, seen, &count) == 0 && count == 0);
    CHECK(verify_workers(&f, VIREO_RESULT_CANCELLED) > 0);
    destroy_fixture(&f, 12);
}

/**
 * @brief
 *     一项工作错误仍产生独立响应，一项公开预算失败无半owner，其他任务继续。
 */
static void explicit_failures(void) {
    delivery_fixture_t f;
    init_fixture(&f, 2, 11, 7, false, 3, 2);
    seed_tasks(&f, 6); close_tasks(f.tasks, VIREO_TASK_QUEUE_DRAIN);
    vireo_thread_pool_report_t report;
    CHECK(finish_join(f.pool, &report) == VIREO_RESULT_RANGE && report.joined_count == 2);
    bool seen[MAX_REQUESTS + 1] = {false}; size_t count = 0;
    CHECK(final_drain(&f, seen, &count) == 5 && count == 5 && seen[2] && !seen[3]);
    CHECK(atomic_load(&f.context.started) == 6 && atomic_load(&f.context.submitted) == 5);
    CHECK(atomic_load(&f.context.creation_failures) == 1 && atomic_load(&f.context.cleaned) == 0);
    CHECK(verify_workers(&f, VIREO_RESULT_RANGE) == 1);
    destroy_fixture(&f, 0);
}

/**
 * @brief
 *     唯一worker提交顺序可核FIFO，移出结果不借task/pool/queue且旧快照独立。
 */
static void fifo_and_independent_lifetime(void) {
    delivery_fixture_t f;
    init_fixture(&f, 1, 11, 9, false, 0, 0);
    seed_tasks(&f, 7); close_tasks(f.tasks, VIREO_TASK_QUEUE_DRAIN);
    vireo_thread_pool_report_t pool_report;
    CHECK(finish_join(f.pool, &pool_report) == VIREO_OK && pool_report.joined_count == 1);
    vireo_completion_queue_close_report_t closed;
    EXPECT(vireo_completion_queue_close(f.outputs, &closed), VIREO_OK);
    vireo_completion_t *kept = NULL;
    vireo_completion_queue_info_t initial;
    EXPECT(vireo_completion_queue_inspect(f.outputs, &initial), VIREO_OK);
    CHECK(initial.count == 7);
    for (uint64_t id = 1; id <= 7; ++id) {
        vireo_completion_t *completion = NULL;
        vireo_completion_queue_transfer_report_t report;
        EXPECT(vireo_completion_queue_try_pop(f.outputs, &completion, &report), VIREO_OK);
        CHECK(report.transferred && verify_completion(completion, 0) == id);
        if (id == 1) {
            EXPECT(vireo_completion_move(&completion, &kept), VIREO_OK);
            CHECK(completion == NULL && kept != NULL);
        } else { EXPECT(vireo_completion_destroy(&completion), VIREO_OK); }
    }
    CHECK(initial.count == 7 && initial.closed);
    CHECK(verify_workers(&f, VIREO_OK) == 0);
    destroy_fixture(&f, 0);
    CHECK(verify_completion(kept, 0) == 1);
    EXPECT(vireo_completion_destroy(&kept), VIREO_OK);
    CHECK(kept == NULL);
}

/**
 * @brief
 *     全程禁POSIX取消，六组实际公开集成；CHECK失败终止以保护活线程输入寿命。
 *
 * @return
 *     成功0；失败abort，不留活线程访问已返回的fixture。
 */
int main(void) {
    int previous = 0;
    CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previous) == 0);
    live_drain(); buffered_last_drain(); cancel_pending(); closed_outputs();
    explicit_failures(); fifo_and_independent_lifetime();
    CHECK(pthread_setcancelstate(previous, NULL) == 0);
    puts("test_completion_queue_integration: 6 groups PASS");
    return 0;
}
