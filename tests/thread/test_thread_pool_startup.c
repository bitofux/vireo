/*
 * PROJECT : VIREO
 * FILE    : test_thread_pool_startup.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-12
 * BRIEF   : 真实停驻线程、部分启动失败、明确回收与局部故障
 */
#define _POSIX_C_SOURCE 200809L
#include "thread_pool_internal.h"
#include <errno.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(expression) do { if (!(expression)) { \
    fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #expression); exit(1); \
} } while (0)

/**
 * @brief
 *     同步故障分类，各失败最多消费一次；不同线程使用原子账本。
 */
typedef enum operation {
    OP_MUTEX_INIT, OP_MUTEX_DESTROY, OP_MANAGER_LOCK, OP_MANAGER_UNLOCK,
    OP_CONDITION_INIT, OP_CONDITION_DESTROY, OP_WAIT, OP_WAKE, OP_CREATE,
    OP_JOIN, OP_CANCEL, OP_WORKER_LOCK, OP_WORKER_UNLOCK, OP_COUNT
} operation_t;

/**
 * @brief
 *     局部运行适配的共享测试账本，存活至 pool 销毁之后。
 */
typedef struct runtime_trace {
    atomic_size_t calls[OP_COUNT]; /**< 每操作尝试次数，原子，含注入失败。 */
    atomic_int errors[OP_COUNT]; /**< 一次性直接错误，各操作 atomic_exchange 消费。 */
    size_t fail_create_at; /**< 第几次创建失败，启动前设置，0 为无故障。 */
    int create_error; /**< 创建定点直接错误，启动前稳定。 */
    pthread_t manager; /**< 存活管理线程身份，用于区分管理/worker 锁操作。 */
    vireo_result_t inspect_result; /**< 局部观测脚本返回值，不改真实 queue。 */
    bool scripted_inspect; /**< true 才用脚本快照，否则公开观测。 */
    vireo_task_queue_info_t scripted_info; /**< 脚本合法公开快照，只有 OK 才发布。 */
    atomic_bool gate_enabled; /**< 某 worker 错误路径的单次真实 barrier 入场。 */
    pthread_barrier_t gate; /**< 仅 gate_enabled 场景初始化，使用后显式销毁。 */
} runtime_trace_t;

/**
 * @brief
 *     两个唯一资源 owner 及长期借用目标，不产生额外 pool/queue 所有者。
 */
typedef struct startup_fixture {
    vireo_thread_pool_t *pool; /**< 独占 owner，全部 join 后先销毁。 */
    vireo_task_queue_t *queue; /**< 独占专用 queue，不归 pool 销毁。 */
    atomic_size_t executions; /**< 若产品误调用 execute 则增加，必须始终零。 */
    runtime_trace_t trace; /**< 自有共享操作账本，最后才结束寿命。 */
} startup_fixture_t;

/**
 * @brief
 *     增加尝试并取走一次直接故障；故意扰动当前线程 errno。
 *
 * @param[in,out] trace
 *     存活共享原子账本。
 * @param[in] operation
 *     有效局部操作索引。
 *
 * @return
 *     0 或指定的一次性直接错误，不执行真实操作。
 */
static int injected_error(runtime_trace_t *trace, operation_t operation) {
    (void)atomic_fetch_add(&trace->calls[operation], 1);
    errno = EIO;
    return atomic_exchange(&trace->errors[operation], 0);
}

/**
 * @brief
 *     只公开观测真实 queue 或发布局部合法脚本，不接触依赖私有状态。
 *
 * @param[in,out] context
 *     存活 trace。
 * @param[in] queue
 *     短借真实存活 queue。
 * @param[out] info
 *     仅 OK 发布公开快照。
 *
 * @return
 *     脚本或公开观测原值。
 */
static vireo_result_t inspect_queue(void *context, vireo_task_queue_t const *queue,
                                   vireo_task_queue_info_t *info) {
    runtime_trace_t *trace = context;
    errno = EIO;
    if (!trace->scripted_inspect) { return vireo_task_queue_inspect(queue, info); }
    if (trace->inspect_result == VIREO_OK) { *info = trace->scripted_info; }
    return trace->inspect_result;
}

/**
 * @brief
 *     mutex_init 定点故障；无故障调用真实 POSIX 操作。
 *
 * @param[in,out] context
 *     存活共享原子 trace。
 * @param[in,out] value
 *     必需符合 POSIX 生命周期前置的同步存储。
 *
 * @return
 *     注入或真实直接错误；失败注入不消费资源。
 */
static int traced_mutex_init(void *context, pthread_mutex_t *value) {
    int const error = injected_error(context, OP_MUTEX_INIT);
    return error != 0 ? error : pthread_mutex_init(value, NULL);
}

/**
 * @brief
 *     mutex_destroy 定点故障；无故障调用真实 POSIX 操作。
 *
 * @param[in,out] context
 *     存活共享原子 trace。
 * @param[in,out] value
 *     必需符合 POSIX 生命周期前置的同步存储。
 *
 * @return
 *     注入或真实直接错误；失败注入不消费资源。
 */
static int traced_mutex_destroy(void *context, pthread_mutex_t *value) {
    int const error = injected_error(context, OP_MUTEX_DESTROY);
    return error != 0 ? error : pthread_mutex_destroy(value);
}

/**
 * @brief
 *     condition_init 定点故障；无故障调用真实 POSIX 操作。
 *
 * @param[in,out] context
 *     存活共享原子 trace。
 * @param[in,out] value
 *     必需符合 POSIX 生命周期前置的同步存储。
 *
 * @return
 *     注入或真实直接错误；失败注入不消费资源。
 */
static int traced_condition_init(void *context, pthread_cond_t *value) {
    int const error = injected_error(context, OP_CONDITION_INIT);
    return error != 0 ? error : pthread_cond_init(value, NULL);
}

/**
 * @brief
 *     condition_destroy 定点故障；无故障调用真实 POSIX 操作。
 *
 * @param[in,out] context
 *     存活共享原子 trace。
 * @param[in,out] value
 *     必需符合 POSIX 生命周期前置的同步存储。
 *
 * @return
 *     注入或真实直接错误；失败注入不消费资源。
 */
static int traced_condition_destroy(void *context, pthread_cond_t *value) {
    int const error = injected_error(context, OP_CONDITION_DESTROY);
    return error != 0 ? error : pthread_cond_destroy(value);
}

/**
 * @brief
 *     condition_broadcast 定点故障；无故障调用真实 POSIX 操作。
 *
 * @param[in,out] context
 *     存活共享原子 trace。
 * @param[in,out] value
 *     必需符合 POSIX 生命周期前置的同步存储。
 *
 * @return
 *     注入或真实直接错误；失败注入不消费资源。
 */
static int traced_condition_broadcast(void *context, pthread_cond_t *value) {
    int const error = injected_error(context, OP_WAKE);
    return error != 0 ? error : pthread_cond_broadcast(value);
}

/**
 * @brief
 *     按存活 manager 身份分别注入，避免 worker 抢走管理端故障。
 *
 * @param[in,out] context
 *     存活共享 trace。
 * @param[in,out] mutex
 *     真实已初始化 mutex。
 *
 * @return
 *     注入或真实直接错误，失败不取得锁。
 */
static int traced_mutex_lock(void *context, pthread_mutex_t *mutex) {
    runtime_trace_t *trace = context;
    operation_t const op = pthread_equal(pthread_self(), trace->manager) != 0
        ? OP_MANAGER_LOCK : OP_WORKER_LOCK;
    int const error = injected_error(trace, op);
    return error != 0 ? error : pthread_mutex_lock(mutex);
}

/**
 * @brief
 *     解锁故障模型先真实释放，再报告异常，不损坏实际锁。
 *
 * @param[in,out] context
 *     存活共享 trace。
 * @param[in,out] mutex
 *     当前线程已取得的真实 mutex。
 *
 * @return
 *     真实解锁错误优先，否则返回一次注入；不是损坏同步恢复证明。
 */
static int traced_mutex_unlock(void *context, pthread_mutex_t *mutex) {
    runtime_trace_t *trace = context;
    operation_t const op = pthread_equal(pthread_self(), trace->manager) != 0
        ? OP_MANAGER_UNLOCK : OP_WORKER_UNLOCK;
    int const error = injected_error(trace, op);
    int const real_error = pthread_mutex_unlock(mutex);
    return real_error != 0 ? real_error : error;
}

/**
 * @brief
 *     错误 worker 可在真实 barrier 与管理端会合，确保目标分支实际执行。
 *
 * @param[in,out] trace
 *     存活原子账本，gate 启用时已初始化两人 barrier。
 *
 * @note
 *     只首个启用者会合，不用 sleep 或无界轮询预测调度。
 */
static void enter_gate(runtime_trace_t *trace) {
    if (atomic_exchange(&trace->gate_enabled, false)) {
        int const error = pthread_barrier_wait(&trace->gate);
        CHECK(error == 0 || error == PTHREAD_BARRIER_SERIAL_THREAD);
    }
}

/**
 * @brief
 *     真实 wait 或持锁返回的局部故障，符合 own seam 前置。
 *
 * @param[in,out] context
 *     存活共享 trace。
 * @param[in,out] condition
 *     真实已初始化 cond。
 * @param[in,out] mutex
 *     当前线程持有的非 robust mutex。
 *
 * @return
 *     直接错误，所有返回仍持 mutex。
 */
static int traced_condition_wait(void *context, pthread_cond_t *condition,
                                 pthread_mutex_t *mutex) {
    runtime_trace_t *trace = context;
    enter_gate(trace);
    int const error = injected_error(trace, OP_WAIT);
    return error != 0 ? error : pthread_cond_wait(condition, mutex);
}

/**
 * @brief
 *     指定第 k 次失败，其余创建真实默认 joinable 线程。
 *
 * @param[in,out] context
 *     存活共享 trace，创建脚本在启动前固定。
 * @param[out] thread
 *     必需句柄输出，成功才有效。
 * @param[in] entry
 *     产品真实 worker 入口。
 * @param[in] argument
 *     存活产品槽地址，借至线程结束。
 *
 * @return
 *     定点或真实直接错误，失败不创建线程。
 */
static int traced_thread_create(void *context, pthread_t *thread,
                                void *(*entry)(void *), void *argument) {
    runtime_trace_t *trace = context;
    size_t const attempt = atomic_fetch_add(&trace->calls[OP_CREATE], 1) + 1;
    errno = EIO;
    if (trace->fail_create_at == attempt) { return trace->create_error; }
    return pthread_create(thread, NULL, entry, argument);
}

/**
 * @brief
 *     失败不消费句柄；正常实际 join 使 worker 错误可观察。
 *
 * @param[in,out] context
 *     存活共享 trace。
 * @param[in] thread
 *     有效未消费句柄，只管理线程调用。
 *
 * @return
 *     注入或真实直接错误。
 */
static int traced_thread_join(void *context, pthread_t thread) {
    int const error = injected_error(context, OP_JOIN);
    return error != 0 ? error : pthread_join(thread, NULL);
}

/**
 * @brief
 *     单项入口错误先会合再退出；正常实际禁用取消后才进入等待。
 *
 * @param[in,out] context
 *     存活共享 trace。
 *
 * @return
 *     注入或真实直接错误，不恢复取消能力。
 */
static int traced_disable_cancel(void *context) {
    runtime_trace_t *trace = context;
    int const error = injected_error(trace, OP_CANCEL);
    if (error != 0) { enter_gate(trace); return error; }
    int previous = 0;
    return pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previous);
}

/**
 * @brief
 *     仅检测错误的任务执行，本项计数始终零。
 *
 * @param[in,out] context
 *     自有原子计数，借至 pool 销毁。
 * @param[in] task
 *     若调用须合法只读借用，本测试不消费。
 *
 * @return
 *     公开观察结果，不模拟 completion。
 */
static vireo_result_t unused_execute(void *context, vireo_task_t const *task) {
    (void)atomic_fetch_add((atomic_size_t *)context, 1);
    vireo_task_info_t info;
    return vireo_task_inspect(task, &info);
}

/**
 * @brief
 *     建立独占 pool/专用公开 prepared queue 和完全初始化原子账本。
 *
 * @param[out] fixture
 *     新存储，资源从 NULL 构造；不普通复制已初始化同步对象。
 * @param[in] workers
 *     正配置槽数，本组预算足够。
 * @param[in] configure
 *     是否公开装配，queue 始终 prepare。
 *
 * @note
 *     任一步失败测试立即退出，正常退出前所有资源显式配对清理。
 */
static void make_fixture(startup_fixture_t *fixture, size_t workers, bool configure) {
    fixture->pool = NULL;
    fixture->queue = NULL;
    atomic_init(&fixture->executions, 0);
    runtime_trace_t *trace = &fixture->trace;
    for (size_t i = 0; i < OP_COUNT; ++i) {
        atomic_init(&trace->calls[i], 0);
        atomic_init(&trace->errors[i], 0);
    }
    trace->fail_create_at = 0;
    trace->create_error = 0;
    trace->manager = pthread_self();
    trace->inspect_result = VIREO_OK;
    trace->scripted_inspect = false;
    trace->scripted_info = (vireo_task_queue_info_t){0};
    atomic_init(&trace->gate_enabled, false);
    vireo_thread_pool_options_t const options = {workers, 65536};
    vireo_task_queue_options_t const queue_options = {3, 4096};
    CHECK(vireo_thread_pool_create(&options, &fixture->pool) == VIREO_OK);
    CHECK(vireo_task_queue_create(&queue_options, &fixture->queue) == VIREO_OK);
    CHECK(vireo_task_queue_prepare_wait(fixture->queue) == VIREO_OK);
    if (configure) {
        vireo_thread_pool_configuration_t const config = {
            fixture->queue, unused_execute, &fixture->executions
        };
        CHECK(vireo_thread_pool_configure(fixture->pool, &config, NULL) == VIREO_OK);
    }
}

/**
 * @brief
 *     复制完整局部操作表，context 借用 fixture 内账本直到销毁。
 *
 * @param[in,out] fixture
 *     存活自有 fixture，不转移拥有权。
 *
 * @return
 *     表值副本，可在 start 返回后改变原表，不影响 pool。
 */
static vireo_thread_pool_runtime_t make_runtime(startup_fixture_t *fixture) {
    vireo_thread_pool_runtime_t const runtime = {
        &fixture->trace, inspect_queue, traced_mutex_init, traced_mutex_destroy,
        traced_mutex_lock, traced_mutex_unlock, traced_condition_init,
        traced_condition_destroy, traced_condition_wait, traced_condition_broadcast,
        traced_thread_create, traced_thread_join, traced_disable_cancel,
        vireo_thread_pool_standard_runtime()->wait_pop
    };
    return runtime;
}

/**
 * @brief
 *     结束 pool 借用再释放空 queue，核实本项没有调用 execute。
 *
 * @param[in,out] fixture
 *     已全部 join、没有残留故障的唯一 owner，queue 必须为空。
 */
static void destroy_fixture(startup_fixture_t *fixture) {
    CHECK(vireo_thread_pool_destroy(&fixture->pool) == VIREO_OK);
    CHECK(vireo_task_queue_destroy(&fixture->queue) == VIREO_OK);
    CHECK(atomic_load(&fixture->executions) == 0);
}

/**
 * @brief
 *     正常独立进度报告，不依成功结构的 padding 内容。
 *
 * @param[in] report
 *     必需已发布的独立报告。
 * @param[in] created
 *     预期累计创建条数。
 * @param[in] joined
 *     预期累计 join 条数。
 */
static void check_progress(vireo_thread_pool_report_t const *report,
                            size_t created, size_t joined) {
    CHECK(report->start_attempted);
    CHECK(report->created_count == created && report->joined_count == joined);
    CHECK(report->cleanup_result == VIREO_OK);
    CHECK(report->cleanup_stage == VIREO_THREAD_POOL_STAGE_NONE);
    CHECK(report->cleanup_pthread_error == 0);
}

/**
 * @brief
 *     必需地址、未配置/未尝试及九字段每路径发布，errno 保持。
 */
static void test_basic(void) {
    startup_fixture_t f; make_fixture(&f, 1, false);
    vireo_thread_pool_report_t report;
    memset(&report, 0xa5, sizeof(report));
    errno = EDOM;
    CHECK(vireo_thread_pool_start(NULL, &report) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(errno == EDOM && !report.start_attempted && report.created_count == 0);
    CHECK(report.stage == VIREO_THREAD_POOL_STAGE_NONE && report.pthread_error == 0);
    CHECK(report.cleanup_result == VIREO_OK && report.cleanup_pthread_error == 0);
    CHECK(!report.stop_requested && report.joined_count == 0);
    CHECK(vireo_thread_pool_start(f.pool, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_thread_pool_start(f.pool, &report) == VIREO_RESULT_NOT_FOUND);
    CHECK(vireo_thread_pool_stop_and_join(NULL, &report) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_thread_pool_stop_and_join(f.pool, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_thread_pool_stop_and_join(f.pool, &report) == VIREO_RESULT_NOT_FOUND);
    CHECK(errno == EDOM && !report.start_attempted);
    destroy_fixture(&f);
}

/**
 * @brief
 *     真实 1/3/7 线程创建与立即协作停止，join 后累计数与独立旧快照。
 */
static void test_real_workers(void) {
    size_t const counts[] = {1, 3, 7};
    for (size_t n = 0; n < sizeof(counts) / sizeof(counts[0]); ++n) {
        startup_fixture_t f; make_fixture(&f, counts[n], true);
        vireo_thread_pool_report_t report;
        vireo_thread_pool_info_t before;
        CHECK(vireo_thread_pool_inspect(f.pool, &before) == VIREO_OK);
        CHECK(!before.start_attempted && !before.stop_requested && before.created_count == 0);
        errno = ERANGE;
        CHECK(vireo_thread_pool_start(f.pool, &report) == VIREO_OK);
        CHECK(errno == ERANGE && report.stage == VIREO_THREAD_POOL_STAGE_NONE);
        check_progress(&report, counts[n], 0);
        CHECK(!report.stop_requested);
        CHECK(vireo_thread_pool_destroy(&f.pool) == VIREO_RESULT_BUSY && f.pool != NULL);
        CHECK(vireo_thread_pool_stop_and_join(f.pool, &report) == VIREO_OK);
        check_progress(&report, counts[n], counts[n]);
        CHECK(errno == ERANGE && report.stop_requested);
        vireo_thread_pool_info_t after;
        CHECK(vireo_thread_pool_inspect(f.pool, &after) == VIREO_OK);
        CHECK(after.worker_count == counts[n] && after.configured && after.start_attempted);
        CHECK(after.stop_requested && after.created_count == counts[n] && after.joined_count == counts[n]);
        CHECK(!before.start_attempted && before.created_count == 0);
        destroy_fixture(&f);
    }
}

/**
 * @brief
 *     已尝试重复 start 永久 BUSY，重复 join 不再次消费任何句柄。
 */
static void test_repeated(void) {
    startup_fixture_t f; make_fixture(&f, 3, true);
    vireo_thread_pool_runtime_t runtime = make_runtime(&f);
    vireo_thread_pool_report_t report;
    CHECK(vireo_thread_pool_start_with_runtime(f.pool, &runtime, &report) == VIREO_OK);
    CHECK(vireo_thread_pool_start(f.pool, &report) == VIREO_RESULT_BUSY);
    check_progress(&report, 3, 0);
    CHECK(vireo_thread_pool_stop_and_join(f.pool, &report) == VIREO_OK);
    size_t const joins = atomic_load(&f.trace.calls[OP_JOIN]);
    CHECK(joins == 3);
    CHECK(vireo_thread_pool_stop_and_join(f.pool, &report) == VIREO_OK);
    CHECK(atomic_load(&f.trace.calls[OP_JOIN]) == joins);
    CHECK(vireo_thread_pool_start(f.pool, &report) == VIREO_RESULT_BUSY);
    check_progress(&report, 3, 3);
    destroy_fixture(&f);
}

/**
 * @brief
 *     真实排队 task 不被停驻 worker 消费，pool 销毁后原 owner 正常领取清理。
 */
static void test_queued_task(void) {
    startup_fixture_t f; make_fixture(&f, 3, true);
    vireo_task_route_t route;
    vireo_task_metadata_t metadata;
    vireo_task_t *task = NULL;
    unsigned char const payload[] = {0, 0xfe, 0x12};
    CHECK(vireo_task_route_make(1, 2, 3, 4, &route) == VIREO_OK);
    CHECK(vireo_task_metadata_make(route, 5, 6, 100, &metadata) == VIREO_OK);
    CHECK(vireo_task_create_copy(metadata, payload, sizeof(payload), 4096, &task) == VIREO_OK);
    vireo_task_t const *identity = task;
    vireo_task_queue_transfer_report_t transfer;
    CHECK(vireo_task_queue_try_push(f.queue, &task, &transfer) == VIREO_OK);
    CHECK(task == NULL && transfer.transferred);
    vireo_thread_pool_report_t report;
    CHECK(vireo_thread_pool_start(f.pool, &report) == VIREO_OK);
    CHECK(vireo_thread_pool_stop_and_join(f.pool, &report) == VIREO_OK);
    CHECK(vireo_thread_pool_destroy(&f.pool) == VIREO_OK);
    vireo_task_queue_info_t info;
    CHECK(vireo_task_queue_inspect(f.queue, &info) == VIREO_OK);
    CHECK(info.count == 1 && info.state == VIREO_TASK_QUEUE_OPEN && info.wait_prepared);
    CHECK(vireo_task_queue_try_pop(f.queue, &task, &transfer) == VIREO_OK);
    CHECK(task == identity && transfer.transferred);
    vireo_task_payload_view_t view;
    CHECK(vireo_task_borrow_payload(task, &view) == VIREO_OK);
    CHECK(view.size == sizeof(payload) && memcmp(view.data, payload, sizeof(payload)) == 0);
    CHECK(vireo_task_destroy(&task) == VIREO_OK);
    destroy_fixture(&f);
}

/**
 * @brief
 *     装配后真实关闭队列不消耗启动尝试，两个永久模式均拒绝。
 */
static void test_closed_queue(void) {
    vireo_task_queue_state_t const modes[] = {VIREO_TASK_QUEUE_DRAIN, VIREO_TASK_QUEUE_CANCEL_PENDING};
    for (size_t i = 0; i < 2; ++i) {
        startup_fixture_t f; make_fixture(&f, 1, true);
        vireo_task_queue_close_report_t close_report;
        CHECK(vireo_task_queue_close(f.queue, modes[i], &close_report) == VIREO_OK);
        vireo_thread_pool_report_t report;
        CHECK(vireo_thread_pool_start(f.pool, &report) == VIREO_RESULT_CANCELLED);
        CHECK(report.stage == VIREO_THREAD_POOL_STAGE_CHECK_QUEUE && !report.start_attempted);
        CHECK(!f.pool->mutex_initialized && !f.pool->condition_initialized);
        destroy_fixture(&f);
    }
}

/**
 * @brief
 *     局部表非法/依赖失败保持全 pool 字节，资格拒绝可纠正后显式启动。
 */
static void test_preflight(void) {
    startup_fixture_t f; make_fixture(&f, 1, true);
    size_t const bytes = f.pool->allocated_bytes;
    unsigned char *before = malloc(bytes); CHECK(before != NULL);
    memcpy(before, f.pool, bytes);
    vireo_thread_pool_runtime_t runtime = make_runtime(&f);
    vireo_thread_pool_report_t report;
    CHECK(vireo_thread_pool_start_with_runtime(f.pool, NULL, &report) == VIREO_RESULT_INVALID_ARGUMENT);
    runtime.thread_create = NULL;
    CHECK(vireo_thread_pool_start_with_runtime(f.pool, &runtime, &report) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(memcmp(before, f.pool, bytes) == 0);
    runtime = make_runtime(&f);
    f.trace.scripted_inspect = true;
    vireo_result_t const errors[] = {VIREO_RESULT_BUSY, VIREO_RESULT_INTERNAL, VIREO_RESULT_IO};
    for (size_t i = 0; i < 3; ++i) {
        f.trace.inspect_result = errors[i]; errno = EDOM;
        CHECK(vireo_thread_pool_start_with_runtime(f.pool, &runtime, &report) == errors[i]);
        CHECK(errno == EDOM && report.stage == VIREO_THREAD_POOL_STAGE_CHECK_QUEUE);
        CHECK(report.pthread_error == 0 && !report.start_attempted);
        CHECK(memcmp(before, f.pool, bytes) == 0);
    }
    f.trace.inspect_result = VIREO_OK;
    f.trace.scripted_info.state = VIREO_TASK_QUEUE_OPEN;
    f.trace.scripted_info.wait_prepared = false;
    CHECK(vireo_thread_pool_start_with_runtime(f.pool, &runtime, &report) == VIREO_RESULT_NOT_FOUND);
    CHECK(memcmp(before, f.pool, bytes) == 0);
    f.trace.scripted_info.state = VIREO_TASK_QUEUE_DRAIN;
    CHECK(vireo_thread_pool_start_with_runtime(f.pool, &runtime, &report) == VIREO_RESULT_CANCELLED);
    CHECK(memcmp(before, f.pool, bytes) == 0);
    free(before);
    f.trace.scripted_inspect = false;
    CHECK(vireo_thread_pool_start_with_runtime(f.pool, &runtime, &report) == VIREO_OK);
    CHECK(vireo_thread_pool_stop_and_join(f.pool, &report) == VIREO_OK);
    destroy_fixture(&f);
}

/**
 * @brief
 *     init 首步失败保尝试状态，后续不读未初始化同步/线程句柄。
 */
static void test_mutex_init_failure(void) {
    int const errors[] = {ENOMEM, EINVAL};
    for (size_t i = 0; i < 2; ++i) {
        startup_fixture_t f; make_fixture(&f, 1, true);
        vireo_thread_pool_runtime_t runtime = make_runtime(&f);
        atomic_store(&f.trace.errors[OP_MUTEX_INIT], errors[i]);
        vireo_thread_pool_report_t report; errno = ERANGE;
        CHECK(vireo_thread_pool_start_with_runtime(f.pool, &runtime, &report) ==
              (i == 0 ? VIREO_RESULT_NO_MEMORY : VIREO_RESULT_INTERNAL));
        CHECK(errno == ERANGE && report.stage == VIREO_THREAD_POOL_STAGE_INIT_MUTEX);
        CHECK(report.pthread_error == errors[i]); check_progress(&report, 0, 0);
        CHECK(!f.pool->mutex_initialized && !f.pool->condition_initialized);
        CHECK(vireo_thread_pool_start(f.pool, &report) == VIREO_RESULT_BUSY);
        CHECK(vireo_thread_pool_stop_and_join(f.pool, &report) == VIREO_OK);
        destroy_fixture(&f);
        CHECK(atomic_load(&f.trace.calls[OP_MUTEX_DESTROY]) == 0);
        CHECK(atomic_load(&f.trace.calls[OP_CREATE]) == 0);
    }
}

/**
 * @brief
 *     cond 初始化失败只留下有效 mutex，显式销毁恰配对一次。
 */
static void test_condition_init_failure(void) {
    int const errors[] = {ENOMEM, EINVAL};
    for (size_t i = 0; i < 2; ++i) {
        startup_fixture_t f; make_fixture(&f, 1, true);
        vireo_thread_pool_runtime_t runtime = make_runtime(&f);
        atomic_store(&f.trace.errors[OP_CONDITION_INIT], errors[i]);
        vireo_thread_pool_report_t report;
        CHECK(vireo_thread_pool_start_with_runtime(f.pool, &runtime, &report) ==
              (i == 0 ? VIREO_RESULT_NO_MEMORY : VIREO_RESULT_INTERNAL));
        CHECK(report.stage == VIREO_THREAD_POOL_STAGE_INIT_CONDITION && report.pthread_error == errors[i]);
        CHECK(f.pool->mutex_initialized && !f.pool->condition_initialized);
        check_progress(&report, 0, 0);
        destroy_fixture(&f);
        CHECK(atomic_load(&f.trace.calls[OP_MUTEX_DESTROY]) == 1);
        CHECK(atomic_load(&f.trace.calls[OP_CONDITION_DESTROY]) == 0);
    }
}

/**
 * @brief
 *     第1/3次创建失败只回收已成功创建部分，保原首错和真实计数。
 */
static void test_create_failure(void) {
    for (size_t i = 0; i < 4; ++i) {
        startup_fixture_t f; make_fixture(&f, 3, true);
        vireo_thread_pool_runtime_t runtime = make_runtime(&f);
        f.trace.fail_create_at = i < 2 ? 1 : 3;
        f.trace.create_error = i % 2 == 0 ? EAGAIN : EPERM;
        size_t const created = f.trace.fail_create_at - 1;
        vireo_thread_pool_report_t report; errno = EDOM;
        CHECK(vireo_thread_pool_start_with_runtime(f.pool, &runtime, &report) ==
              (i % 2 == 0 ? VIREO_RESULT_NO_MEMORY : VIREO_RESULT_INTERNAL));
        CHECK(errno == EDOM && report.stage == VIREO_THREAD_POOL_STAGE_CREATE_WORKER);
        CHECK(report.pthread_error == f.trace.create_error);
        check_progress(&report, created, created);
        CHECK(atomic_load(&f.trace.calls[OP_JOIN]) == created);
        CHECK(vireo_thread_pool_start(f.pool, &report) == VIREO_RESULT_BUSY);
        destroy_fixture(&f);
    }
}

/**
 * @brief
 *     创建原错与回收 join 首错分别保留，继续处理其他项，重试只回收剩余项。
 */
static void test_rollback_join_failure(void) {
    startup_fixture_t f; make_fixture(&f, 3, true);
    vireo_thread_pool_runtime_t runtime = make_runtime(&f);
    f.trace.fail_create_at = 3; f.trace.create_error = EAGAIN;
    atomic_store(&f.trace.errors[OP_JOIN], EIO);
    vireo_thread_pool_report_t report;
    CHECK(vireo_thread_pool_start_with_runtime(f.pool, &runtime, &report) == VIREO_RESULT_NO_MEMORY);
    CHECK(report.stage == VIREO_THREAD_POOL_STAGE_CREATE_WORKER && report.pthread_error == EAGAIN);
    CHECK(report.cleanup_result == VIREO_RESULT_INTERNAL);
    CHECK(report.cleanup_stage == VIREO_THREAD_POOL_STAGE_JOIN_WORKER && report.cleanup_pthread_error == EIO);
    CHECK(report.created_count == 2 && report.joined_count == 1 && report.stop_requested);
    CHECK(atomic_load(&f.trace.calls[OP_JOIN]) == 2);
    CHECK(vireo_thread_pool_destroy(&f.pool) == VIREO_RESULT_BUSY);
    CHECK(vireo_thread_pool_stop_and_join(f.pool, &report) == VIREO_OK);
    CHECK(atomic_load(&f.trace.calls[OP_JOIN]) == 3);
    check_progress(&report, 2, 2);
    destroy_fixture(&f);
}

/**
 * @brief
 *     启动回收 wake/unlock 异常不盲目 join，保已提交停止供显式收尾。
 */
static void test_rollback_wake_failure(void) {
    operation_t const operations[] = {OP_WAKE, OP_MANAGER_UNLOCK};
    vireo_thread_pool_stage_t const stages[] = {VIREO_THREAD_POOL_STAGE_WAKE, VIREO_THREAD_POOL_STAGE_UNLOCK};
    for (size_t i = 0; i < 2; ++i) {
        startup_fixture_t f; make_fixture(&f, 3, true);
        vireo_thread_pool_runtime_t runtime = make_runtime(&f);
        f.trace.fail_create_at = 3; f.trace.create_error = EAGAIN;
        atomic_store(&f.trace.errors[operations[i]], EIO);
        vireo_thread_pool_report_t report;
        CHECK(vireo_thread_pool_start_with_runtime(f.pool, &runtime, &report) == VIREO_RESULT_NO_MEMORY);
        CHECK(report.cleanup_result == VIREO_RESULT_INTERNAL && report.cleanup_stage == stages[i]);
        CHECK(report.cleanup_pthread_error == EIO && report.stop_requested);
        CHECK(report.created_count == 2 && report.joined_count == 0);
        CHECK(atomic_load(&f.trace.calls[OP_JOIN]) == 0);
        CHECK(vireo_thread_pool_destroy(&f.pool) == VIREO_RESULT_BUSY);
        CHECK(vireo_thread_pool_stop_and_join(f.pool, &report) == VIREO_OK);
        check_progress(&report, 2, 2);
        destroy_fixture(&f);
    }
}

/**
 * @brief
 *     管理 lock/wake/unlock 单错的永久停止进度不同，均不得提前 join。
 */
static void test_stop_sync_failure(void) {
    operation_t const operations[] = {OP_MANAGER_LOCK, OP_WAKE, OP_MANAGER_UNLOCK};
    vireo_thread_pool_stage_t const stages[] = {
        VIREO_THREAD_POOL_STAGE_LOCK, VIREO_THREAD_POOL_STAGE_WAKE, VIREO_THREAD_POOL_STAGE_UNLOCK
    };
    for (size_t i = 0; i < 3; ++i) {
        startup_fixture_t f; make_fixture(&f, 3, true);
        vireo_thread_pool_runtime_t runtime = make_runtime(&f);
        vireo_thread_pool_report_t report;
        CHECK(vireo_thread_pool_start_with_runtime(f.pool, &runtime, &report) == VIREO_OK);
        atomic_store(&f.trace.errors[operations[i]], EIO); errno = ERANGE;
        CHECK(vireo_thread_pool_stop_and_join(f.pool, &report) == VIREO_RESULT_INTERNAL);
        CHECK(errno == ERANGE && report.stage == stages[i] && report.pthread_error == EIO);
        check_progress(&report, 3, 0);
        CHECK(report.stop_requested == (i != 0));
        CHECK(atomic_load(&f.trace.calls[OP_JOIN]) == 0);
        CHECK(vireo_thread_pool_stop_and_join(f.pool, &report) == VIREO_OK);
        check_progress(&report, 3, 3);
        destroy_fixture(&f);
    }
}

/**
 * @brief
 *     正常启动后单项 join 拒绝仍回收其余项，下次恰处理一个剩余句柄。
 */
static void test_stop_join_failure(void) {
    startup_fixture_t f; make_fixture(&f, 3, true);
    vireo_thread_pool_runtime_t runtime = make_runtime(&f);
    vireo_thread_pool_report_t report;
    CHECK(vireo_thread_pool_start_with_runtime(f.pool, &runtime, &report) == VIREO_OK);
    atomic_store(&f.trace.errors[OP_JOIN], EIO);
    CHECK(vireo_thread_pool_stop_and_join(f.pool, &report) == VIREO_RESULT_INTERNAL);
    CHECK(report.stage == VIREO_THREAD_POOL_STAGE_JOIN_WORKER && report.pthread_error == EIO);
    check_progress(&report, 3, 2);
    CHECK(atomic_load(&f.trace.calls[OP_JOIN]) == 3);
    CHECK(vireo_thread_pool_destroy(&f.pool) == VIREO_RESULT_BUSY);
    CHECK(vireo_thread_pool_stop_and_join(f.pool, &report) == VIREO_OK);
    CHECK(atomic_load(&f.trace.calls[OP_JOIN]) == 4);
    destroy_fixture(&f);
}

/**
 * @brief
 *     worker 入口取消状态错误在真实 barrier 后被 join 观测，不丢线程回收。
 */
static void test_worker_cancel_failure(void) {
    startup_fixture_t f; make_fixture(&f, 1, true);
    vireo_thread_pool_runtime_t runtime = make_runtime(&f);
    CHECK(pthread_barrier_init(&f.trace.gate, NULL, 2) == 0);
    atomic_store(&f.trace.gate_enabled, true);
    atomic_store(&f.trace.errors[OP_CANCEL], EINVAL);
    vireo_thread_pool_report_t report;
    CHECK(vireo_thread_pool_start_with_runtime(f.pool, &runtime, &report) == VIREO_OK);
    int const gate_error = pthread_barrier_wait(&f.trace.gate);
    CHECK(gate_error == 0 || gate_error == PTHREAD_BARRIER_SERIAL_THREAD);
    CHECK(vireo_thread_pool_stop_and_join(f.pool, &report) == VIREO_RESULT_INTERNAL);
    CHECK(report.stage == VIREO_THREAD_POOL_STAGE_SET_CANCEL_STATE && report.pthread_error == EINVAL);
    check_progress(&report, 1, 1);
    CHECK(pthread_barrier_destroy(&f.trace.gate) == 0);
    destroy_fixture(&f);
}

/**
 * @brief
 *     worker 自身 lock/unlock 错误与管理端故障分离，成功 join 后才读取。
 */
static void test_worker_lock_failure(void) {
    operation_t const operations[] = {OP_WORKER_LOCK, OP_WORKER_UNLOCK};
    vireo_thread_pool_stage_t const stages[] = {VIREO_THREAD_POOL_STAGE_LOCK, VIREO_THREAD_POOL_STAGE_UNLOCK};
    for (size_t i = 0; i < 2; ++i) {
        startup_fixture_t f; make_fixture(&f, 1, true);
        vireo_thread_pool_runtime_t runtime = make_runtime(&f);
        atomic_store(&f.trace.errors[operations[i]], EIO);
        vireo_thread_pool_report_t report;
        CHECK(vireo_thread_pool_start_with_runtime(f.pool, &runtime, &report) == VIREO_OK);
        CHECK(vireo_thread_pool_stop_and_join(f.pool, &report) == VIREO_RESULT_INTERNAL);
        CHECK(report.stage == stages[i] && report.pthread_error == EIO);
        check_progress(&report, 1, 1);
        destroy_fixture(&f);
    }
}

/**
 * @brief
 *     barrier 确保真实 worker 进入 wait 故障分支，持锁失败后正确解锁/回收。
 */
static void test_worker_wait_failure(void) {
    startup_fixture_t f; make_fixture(&f, 1, true);
    vireo_thread_pool_runtime_t runtime = make_runtime(&f);
    CHECK(pthread_barrier_init(&f.trace.gate, NULL, 2) == 0);
    atomic_store(&f.trace.gate_enabled, true);
    atomic_store(&f.trace.errors[OP_WAIT], EIO);
    vireo_thread_pool_report_t report;
    CHECK(vireo_thread_pool_start_with_runtime(f.pool, &runtime, &report) == VIREO_OK);
    int const gate_error = pthread_barrier_wait(&f.trace.gate);
    CHECK(gate_error == 0 || gate_error == PTHREAD_BARRIER_SERIAL_THREAD);
    CHECK(vireo_thread_pool_stop_and_join(f.pool, &report) == VIREO_RESULT_INTERNAL);
    CHECK(report.stage == VIREO_THREAD_POOL_STAGE_WAIT && report.pthread_error == EIO);
    check_progress(&report, 1, 1);
    CHECK(pthread_barrier_destroy(&f.trace.gate) == 0);
    destroy_fixture(&f);
}

/**
 * @brief
 *     cond 销毁失败没有消费，owner 和观测保持可用，下一次恰重试该资源。
 */
static void test_condition_destroy_failure(void) {
    int const errors[] = {EBUSY, EIO};
    for (size_t i = 0; i < 2; ++i) {
        startup_fixture_t f; make_fixture(&f, 1, true);
        vireo_thread_pool_runtime_t runtime = make_runtime(&f);
        vireo_thread_pool_report_t report;
        CHECK(vireo_thread_pool_start_with_runtime(f.pool, &runtime, &report) == VIREO_OK);
        CHECK(vireo_thread_pool_stop_and_join(f.pool, &report) == VIREO_OK);
        atomic_store(&f.trace.errors[OP_CONDITION_DESTROY], errors[i]); errno = EDOM;
        CHECK(vireo_thread_pool_destroy(&f.pool) == (i == 0 ? VIREO_RESULT_BUSY : VIREO_RESULT_INTERNAL));
        CHECK(errno == EDOM && f.pool != NULL && !f.pool->retiring);
        CHECK(f.pool->condition_initialized && f.pool->mutex_initialized);
        vireo_thread_pool_info_t info;
        CHECK(vireo_thread_pool_inspect(f.pool, &info) == VIREO_OK);
        CHECK(atomic_load(&f.trace.calls[OP_MUTEX_DESTROY]) == 0);
        destroy_fixture(&f);
        CHECK(atomic_load(&f.trace.calls[OP_CONDITION_DESTROY]) == 2);
        CHECK(atomic_load(&f.trace.calls[OP_MUTEX_DESTROY]) == 1);
    }
}

/**
 * @brief
 *     cond 已消费而 mutex 销毁失败，仅重试 destroy，不发布错误快照或重复销毁。
 */
static void test_retiring(void) {
    int const errors[] = {EBUSY, EIO};
    for (size_t i = 0; i < 2; ++i) {
        startup_fixture_t f; make_fixture(&f, 1, true);
        vireo_thread_pool_runtime_t runtime = make_runtime(&f);
        vireo_thread_pool_report_t report;
        CHECK(vireo_thread_pool_start_with_runtime(f.pool, &runtime, &report) == VIREO_OK);
        CHECK(vireo_thread_pool_stop_and_join(f.pool, &report) == VIREO_OK);
        atomic_store(&f.trace.errors[OP_MUTEX_DESTROY], errors[i]);
        CHECK(vireo_thread_pool_destroy(&f.pool) == (i == 0 ? VIREO_RESULT_BUSY : VIREO_RESULT_INTERNAL));
        CHECK(f.pool != NULL && f.pool->retiring && !f.pool->condition_initialized && f.pool->mutex_initialized);
        vireo_thread_pool_info_t info;
        unsigned char before[sizeof(info)]; memset(&info, 0xa5, sizeof(info)); memcpy(before, &info, sizeof(info));
        CHECK(vireo_thread_pool_inspect(f.pool, &info) == VIREO_RESULT_CANCELLED);
        CHECK(memcmp(before, &info, sizeof(info)) == 0);
        CHECK(vireo_thread_pool_start(f.pool, &report) == VIREO_RESULT_CANCELLED);
        CHECK(vireo_thread_pool_stop_and_join(f.pool, &report) == VIREO_RESULT_CANCELLED);
        check_progress(&report, 1, 1);
        CHECK(vireo_thread_pool_stop_and_join(f.pool, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
        vireo_thread_pool_configuration_t const config = {f.queue, unused_execute, &f.executions};
        vireo_thread_pool_configure_stage_t stage;
        CHECK(vireo_thread_pool_configure(f.pool, &config, &stage) == VIREO_RESULT_CANCELLED);
        CHECK(stage == VIREO_THREAD_POOL_CONFIGURE_STAGE_NONE);
        destroy_fixture(&f);
        CHECK(atomic_load(&f.trace.calls[OP_CONDITION_DESTROY]) == 1);
        CHECK(atomic_load(&f.trace.calls[OP_MUTEX_DESTROY]) == 2);
    }
}

/**
 * @brief
 *     原操作表地址短借，字段副本在真实 start 后不随原表改变。
 */
static void test_runtime_copy(void) {
    startup_fixture_t f; make_fixture(&f, 3, true);
    vireo_thread_pool_runtime_t runtime = make_runtime(&f);
    vireo_thread_pool_report_t report;
    CHECK(vireo_thread_pool_start_with_runtime(f.pool, &runtime, &report) == VIREO_OK);
    runtime = (vireo_thread_pool_runtime_t){0};
    CHECK(runtime.thread_join == NULL);
    CHECK(vireo_thread_pool_stop_and_join(f.pool, &report) == VIREO_OK);
    CHECK(atomic_load(&f.trace.calls[OP_JOIN]) == 3);
    destroy_fixture(&f);
}

int main(void) {
    int previous = 0;
    CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previous) == 0);
    test_basic(); test_real_workers(); test_repeated(); test_queued_task();
    test_closed_queue(); test_preflight(); test_mutex_init_failure();
    test_condition_init_failure(); test_create_failure(); test_rollback_join_failure();
    test_rollback_wake_failure(); test_stop_sync_failure(); test_stop_join_failure();
    test_worker_cancel_failure(); test_worker_lock_failure(); test_worker_wait_failure();
    test_condition_destroy_failure(); test_retiring(); test_runtime_copy();
    CHECK(pthread_setcancelstate(previous, NULL) == 0);
    puts("test_thread_pool_startup: 19 groups passed");
    return 0;
}
