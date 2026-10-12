/*
 * PROJECT : VIREO
 * FILE    : test_thread_pool_execution.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-12
 * BRIEF   : 显式放行、真实任务交接、关闭与唯一 owner 清理
 */
#define _POSIX_C_SOURCE 200809L
#include "thread_pool_internal.h"
#include <errno.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); exit(1); } } while (0)
#define TASK_LIMIT 128

/**
 * @brief
 *     独立资源 owner、实际回调账本及本核心局部注入上下文。
 *
 * @note
 *     manager 脚本在启线程前稳定；跨线程账本与一次故障用原子。
 *     两个 barrier 只在 hold_first 场景使用，不靠 sleep 决定 task 是否在途。
 */
typedef struct execution_fixture {
    vireo_thread_pool_t *pool; /**< 唯一 pool owner，全部 join 后先销毁。 */
    vireo_task_queue_t *queue; /**< 独立专用 queue owner，最后排空销毁。 */
    vireo_thread_pool_runtime_t runtime; /**< 操作表副本，context 借用本 fixture。 */
    atomic_uint seen[TASK_LIMIT]; /**< 各任务真实执行次数，按 sequence 索引。 */
    atomic_size_t calls; /**< 回调总数，不等队列深度。 */
    atomic_size_t cancelled_seen; /**< 回调实际读到共享 cancel=true 的次数。 */
    atomic_size_t wait_calls; /**< 公开领取适配尝试次数。 */
    atomic_int wait_fault; /**< 0 正常，1 未交接失败，2 真实交接后异常；只消费一次。 */
    atomic_int lock_fault; /**< 管理端下一次 lock 的一次直接错误。 */
    atomic_int wake_fault; /**< 管理端下一次广播的一次直接错误。 */
    atomic_int unlock_fault; /**< 管理端实际解锁后报告的一次直接错误。 */
    pthread_t manager; /**< 存活测试主线程身份，不与已 join 句柄比较。 */
    bool hold_first; /**< 启动前稳定，sequence=1 回调两次 barrier 会合。 */
    pthread_barrier_t entered; /**< 在途回调已进入的两方真实会合。 */
    pthread_barrier_t release; /**< 主线程确认关闭后允许回调正常返回。 */
    bool fail_execution; /**< 启动前稳定，任务1/2分别返回 IO/DATABASE。 */
    size_t create_calls; /**< 仅管理端访问的真实创建尝试数。 */
    size_t fail_create_at; /**< 启动前定点失败序号，0 无失败。 */
    vireo_result_t inspect_fault; /**< 仅管理端公开观测适配的局部原错；OK 走真实 inspect。 */
} execution_fixture_t;

/* barrier 的成功包含 SERIAL_THREAD，不以线程先后作为运行证明。 */
/**
 * @brief
 *     两方真实会合，不靠 sleep 推断在途位置。
 *
 * @param[in,out] barrier
 *     已初始化两方 barrier，全部参与者存活至返回。
 *
 * @note
 *     正常返回；任何非 POSIX 成功结果终止测试，避免继续使用不可靠同步。
 */
static void meet(pthread_barrier_t *barrier) {
    int const result = pthread_barrier_wait(barrier);
    CHECK(result == 0 || result == PTHREAD_BARRIER_SERIAL_THREAD);
}

/**
 * @brief
 *     检查只借输入身份和独立 payload，结束借用后正常返回。
 *
 * @param[in,out] context
 *     存活 fixture，其并发账本均为原子，策略在启动前稳定。
 * @param[in] task
 *     worker 唯一拥有的 const task，禁止保存地址、移动或销毁。
 *
 * @return
 *     通常 OK；指定的任务1/2产生两个不同业务错误，用来核首错及继续领取。
 */
static vireo_result_t execute(void *context, vireo_task_t const *task) {
    execution_fixture_t *f = context;
    vireo_task_info_t info;
    vireo_task_payload_view_t view;
    CHECK(vireo_task_inspect(task, &info) == VIREO_OK);
    size_t const seq = info.metadata.route.request_sequence;
    CHECK(seq > 0 && seq < TASK_LIMIT);
    CHECK(info.metadata.request_instance_id == (uint64_t)seq);
    CHECK(info.metadata.operation == 7 && info.metadata.deadline_ns == 0);
    CHECK(vireo_task_borrow_payload(task, &view) == VIREO_OK);
    CHECK(view.size == 3 && view.data[0] == (unsigned char)seq && view.data[1] == 0 && view.data[2] == 255);
    CHECK(atomic_fetch_add(&f->seen[seq], 1) == 0);
    (void)atomic_fetch_add(&f->calls, 1);
    bool requested = false;
    CHECK(vireo_task_is_cancel_requested(task, &requested) == VIREO_OK);
    if (requested) { (void)atomic_fetch_add(&f->cancelled_seen, 1); }
    if (f->hold_first && seq == 1) {
        meet(&f->entered);
        meet(&f->release);
        /* in-flight 期间输入依旧存活，借用不会因 queue 关闭而失效。 */
        CHECK(view.data[0] == 1 && view.data[2] == 255);
    }
    errno = EILSEQ;
    if (f->fail_execution && seq == 1) { return VIREO_RESULT_IO; }
    if (f->fail_execution && seq == 2) { return VIREO_RESULT_DATABASE; }
    return VIREO_OK;
}

/**
 * @brief
 *     own seam 只调用依赖公开领取；异常交接用真实 pop，再报告局部解锁模型错误。
 *
 * @param[in,out] context
 *     存活 fixture，一次故障由原子消费。
 * @param[in,out] queue
 *     存活 prepared 队列，不访问其私有布局。
 * @param[out] task
 *     worker 独占空 owner，异常后也保存真实公开交接所得 owner。
 * @param[out] report
 *     独立 transfer 输出，错误模型遵循公开 owner 保持/转移规则。
 *
 * @return
 *     公开结果或一次 INTERNAL；不模拟同步损坏可恢复，不调用 foreign private。
 */
static vireo_result_t take_task(void *context, vireo_task_queue_t *queue,
    vireo_task_t **task, vireo_task_queue_transfer_report_t *report) {
    execution_fixture_t *f = context;
    (void)atomic_fetch_add(&f->wait_calls, 1);
    int const fault = atomic_exchange(&f->wait_fault, 0);
    errno = ENOSPC;
    if (fault == 1) {
        *report = (vireo_task_queue_transfer_report_t){VIREO_TASK_QUEUE_STAGE_LOCK, false, EIO};
        return VIREO_RESULT_INTERNAL;
    }
    vireo_result_t const result = vireo_task_queue_wait_pop(queue, task, report);
    if (fault == 2 && result == VIREO_OK) {
        *report = (vireo_task_queue_transfer_report_t){VIREO_TASK_QUEUE_STAGE_UNLOCK, true, EIO};
        return VIREO_RESULT_INTERNAL;
    }
    return result;
}

/* 这些 manager-only 故障不会由 worker 抢走，成功路径均执行真实 POSIX 操作。 */
/**
 * @brief
 *     区分存活 manager，单次注入失败不获取实际锁。
 *
 * @param[in,out] context
 *     存活 fixture，管理故障用原子消费。
 * @param[in,out] mutex
 *     已初始化 pool mutex，仅成功返回才持有。
 *
 * @note
 *     0 或直接 pthread 错误；无故障使用真实 pthread_mutex_lock。
 */
static int lock_pool(void *context, pthread_mutex_t *mutex) {
    execution_fixture_t *f = context;
    if (pthread_equal(pthread_self(), f->manager) != 0) {
        int const error = atomic_exchange(&f->lock_fault, 0);
        if (error != 0) { return error; }
    }
    return pthread_mutex_lock(mutex);
}
/**
 * @brief
 *     一次广播故障或真实唤醒，不替代 pool 谓词。
 *
 * @param[in,out] context
 *     存活 fixture，一次故障原子消费。
 * @param[in,out] condition
 *     已初始化条件变量，只借至返回。
 *
 * @note
 *     0 或直接错误；失败不伪造真实唤醒成功。
 */
static int wake_pool(void *context, pthread_cond_t *condition) {
    execution_fixture_t *f = context;
    int const error = atomic_exchange(&f->wake_fault, 0);
    return error != 0 ? error : pthread_cond_broadcast(condition);
}
/**
 * @brief
 *     真实释放锁后再给 manager 报告局部直接错误。
 *
 * @param[in,out] context
 *     存活 fixture，worker 不消费 manager 故障。
 * @param[in,out] mutex
 *     调用线程已持有的实际 mutex。
 *
 * @note
 *     实际结果或注入错误；此有限模型不能证明真实损坏同步可恢复。
 */
static int unlock_pool(void *context, pthread_mutex_t *mutex) {
    execution_fixture_t *f = context;
    int const result = pthread_mutex_unlock(mutex);
    if (result == 0 && pthread_equal(pthread_self(), f->manager) != 0) {
        return atomic_exchange(&f->unlock_fault, 0);
    }
    return result;
}
/**
 * @brief
 *     第指定次创建拒绝，其余用真实默认 joinable 线程。
 *
 * @param[in,out] context
 *     manager 独占稳定创建脚本，不由 worker 修改。
 * @param[out] thread
 *     独立句柄存储，只有成功创建后有效。
 * @param[in] entry
 *     实际 worker 函数入口。
 * @param[in] argument
 *     创建前稳定槽，只借至线程结束。
 *
 * @note
 *     0 或 EAGAIN/真实直接错误；失败注入不留下线程。
 */
static int create_worker(void *context, pthread_t *thread, void *(*entry)(void *), void *argument) {
    execution_fixture_t *f = context;
    ++f->create_calls;
    if (f->create_calls == f->fail_create_at) { return EAGAIN; }
    return pthread_create(thread, NULL, entry, argument);
}
/**
 * @brief
 *     只公开观测或透传 manager 原错，不访问依赖私有状态。
 *
 * @param[in,out] context
 *     存活 fixture，观测脚本仅 manager 使用。
 * @param[in] queue
 *     有效存活 public queue。
 * @param[out] info
 *     只有 OK 才发布公开快照，失败保持。
 *
 * @note
 *     脚本或公开原 result；不会伪造同步错误是实际 OS 错误。
 */
static vireo_result_t inspect_queue(void *context, vireo_task_queue_t const *queue,
    vireo_task_queue_info_t *info) {
    execution_fixture_t *f = context;
    return f->inspect_fault == VIREO_OK ? vireo_task_queue_inspect(queue, info) : f->inspect_fault;
}

/**
 * @brief
 *     创建独立空 prepared queue 和未启动 pool，固定显式配置、配对 barrier。
 *
 * @param[out] f
 *     存活 fixture 存储，之后不得移动，借用直到 finish 返回。
 * @param[in] workers
 *     正配置数，测试仅使用1/3/7。
 */
static void prepare(execution_fixture_t *f, size_t workers) {
    f->pool = NULL; f->queue = NULL;
    for (size_t i = 0; i < TASK_LIMIT; ++i) { atomic_init(&f->seen[i], 0); }
    atomic_init(&f->calls, 0); atomic_init(&f->cancelled_seen, 0);
    atomic_init(&f->wait_calls, 0); atomic_init(&f->wait_fault, 0);
    atomic_init(&f->lock_fault, 0); atomic_init(&f->wake_fault, 0); atomic_init(&f->unlock_fault, 0);
    f->manager = pthread_self(); f->hold_first = false; f->fail_execution = false;
    f->create_calls = 0; f->fail_create_at = 0; f->inspect_fault = VIREO_OK;
    CHECK(pthread_barrier_init(&f->entered, NULL, 2) == 0);
    CHECK(pthread_barrier_init(&f->release, NULL, 2) == 0);
    vireo_task_queue_options_t const q = {127, 65536};
    vireo_thread_pool_options_t const p = {workers, 65536};
    CHECK(vireo_task_queue_create(&q, &f->queue) == VIREO_OK);
    CHECK(vireo_task_queue_prepare_wait(f->queue) == VIREO_OK);
    CHECK(vireo_thread_pool_create(&p, &f->pool) == VIREO_OK);
    vireo_thread_pool_configuration_t const config = {f->queue, execute, f};
    CHECK(vireo_thread_pool_configure(f->pool, &config, NULL) == VIREO_OK);
    f->runtime = *vireo_thread_pool_standard_runtime();
    f->runtime.context = f; f->runtime.wait_pop = take_task;
    f->runtime.mutex_lock = lock_pool; f->runtime.mutex_unlock = unlock_pool;
    f->runtime.condition_broadcast = wake_pool;
    f->runtime.thread_create = create_worker; f->runtime.inspect_queue = inspect_queue;
}

/* 测试 caller 允许显式处理一次 trylock 竞争；有固定10000次预算，无无限自旋或 sleep。 */
/**
 * @brief
 *     测试 caller 在固定尝试预算内完成一次公开关闭。
 *
 * @param[in,out] f
 *     存活 queue fixture，不移动 owner。
 * @param[in] mode
 *     DRAIN 或 CANCEL_PENDING，本测试不切换已经选定模式。
 *
 * @note
 *     正常返回表示 close OK；其他异常或预算耗尽终止测试，不盲目 join。
 */
static void close_queue(execution_fixture_t *f, vireo_task_queue_state_t mode) {
    vireo_task_queue_close_report_t report;
    for (size_t n = 0; n < 10000; ++n) {
        vireo_result_t const result = vireo_task_queue_close(f->queue, mode, &report);
        if (result == VIREO_OK) { return; }
        CHECK(result == VIREO_RESULT_BUSY && report.stage == VIREO_TASK_QUEUE_STAGE_LOCK);
        (void)sched_yield();
    }
    CHECK(false);
}
/**
 * @brief
 *     固定预算处理公开观测竞争，再保存真实 join 结果。
 *
 * @param[in,out] f
 *     queue 已成功 close，pool 存活且管理端串行。
 * @param[out] report
 *     独立管理输出，每次由 public stop_and_join 覆盖。
 *
 * @note
 *     原 stop/join result；只有限重试观测竞争，不自动重试损坏同步。
 */
static vireo_result_t join_pool(execution_fixture_t *f, vireo_thread_pool_report_t *report) {
    for (size_t n = 0; n < 10000; ++n) {
        vireo_result_t const result = vireo_thread_pool_stop_and_join(f->pool, report);
        if (result != VIREO_RESULT_BUSY) { return result; }
        CHECK(report->stage == VIREO_THREAD_POOL_STAGE_CHECK_QUEUE);
        (void)sched_yield();
    }
    CHECK(false);
    return VIREO_RESULT_INTERNAL;
}

/**
 * @brief
 *     构造并复制 task 到公开 queue，成功移交后只保留数值序号。
 *
 * @param[in,out] f
 *     存活 fixture，pool 只借 queue，task 使用独立局部 owner。
 * @param[in] seq
 *     1..127，完整请求身份和三字节内容使用它，互不复用。
 * @param[in] cancel
 *     可空有效强引用来源，create 只增加 task 本份而不消费来源。
 */
static void push_task(execution_fixture_t *f, uint32_t seq, vireo_task_cancel_t *cancel) {
    vireo_task_route_t route;
    vireo_task_metadata_t metadata;
    CHECK(vireo_task_route_make(1, 0, 1, seq, &route) == VIREO_OK);
    CHECK(vireo_task_metadata_make(route, seq, 7, 0, &metadata) == VIREO_OK);
    unsigned char bytes[] = {(unsigned char)seq, 0, 255};
    vireo_task_t *task = NULL;
    if (cancel == NULL) {
        CHECK(vireo_task_create_copy(metadata, bytes, sizeof(bytes), 4096, &task) == VIREO_OK);
    } else {
        CHECK(vireo_task_create_copy_with_cancel(metadata, bytes, sizeof(bytes), 4096, cancel, &task) == VIREO_OK);
    }
    bytes[0] = 0; /* 验证独立复制输入，无 callback 外借此栈数组。 */
    vireo_task_queue_transfer_report_t report;
    for (size_t n = 0; n < 10000; ++n) {
        vireo_result_t const result = vireo_task_queue_try_push(f->queue, &task, &report);
        if (result == VIREO_OK) { CHECK(task == NULL && report.transferred); return; }
        CHECK(result == VIREO_RESULT_BUSY && task != NULL && !report.transferred);
        (void)sched_yield();
    }
    CHECK(false);
}

/* 所有线程已 join，结束借用后释放自身资源；pending 清理由 caller 显式完成。 */
/**
 * @brief
 *     先结束 pool 长借用，再由 caller 逐项清理 pending 并释放 queue。
 *
 * @param[in,out] f
 *     全部 worker 已成功 join，回调与 barrier 访问已结束。
 *
 * @note
 *     正常返回表示 owner/同步已配对消费，不使用旧裸别名。
 */
static void finish(execution_fixture_t *f) {
    CHECK(vireo_thread_pool_destroy(&f->pool) == VIREO_OK && f->pool == NULL);
    vireo_task_queue_info_t info;
    CHECK(vireo_task_queue_inspect(f->queue, &info) == VIREO_OK);
    while (info.count != 0) {
        vireo_task_t *task = NULL;
        vireo_task_queue_transfer_report_t report;
        vireo_result_t const result = info.state == VIREO_TASK_QUEUE_CANCEL_PENDING
            ? vireo_task_queue_try_take_cancelled(f->queue, &task, &report)
            : vireo_task_queue_try_pop(f->queue, &task, &report);
        CHECK(result == VIREO_OK && report.transferred && task != NULL);
        CHECK(vireo_task_destroy(&task) == VIREO_OK && task == NULL);
        CHECK(vireo_task_queue_inspect(f->queue, &info) == VIREO_OK);
    }
    CHECK(vireo_task_queue_destroy(&f->queue) == VIREO_OK);
    CHECK(pthread_barrier_destroy(&f->entered) == 0);
    CHECK(pthread_barrier_destroy(&f->release) == 0);
}

static void test_basic_and_preservation(void) {
    execution_fixture_t f; prepare(&f, 1);
    vireo_thread_pool_report_t report;
    vireo_thread_pool_worker_result_t value;
    unsigned char before[sizeof(value)]; memset(&value, 0xa5, sizeof(value)); memcpy(before, &value, sizeof(value));
    errno = EDOM;
    CHECK(vireo_thread_pool_enable_execution(NULL, &report) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(!report.execution_enabled && report.created_count == 0 && report.queue_report.pthread_error == 0);
    CHECK(vireo_thread_pool_enable_execution(f.pool, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_thread_pool_enable_execution(f.pool, &report) == VIREO_RESULT_NOT_FOUND);
    CHECK(vireo_thread_pool_inspect_worker_result(NULL, 0, &value) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_thread_pool_inspect_worker_result(f.pool, 0, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_thread_pool_inspect_worker_result(f.pool, 1, &value) == VIREO_RESULT_RANGE);
    CHECK(vireo_thread_pool_inspect_worker_result(f.pool, 0, &value) == VIREO_RESULT_NOT_FOUND);
    CHECK(memcmp(before, &value, sizeof(value)) == 0 && errno == EDOM);
    CHECK(vireo_thread_pool_start_with_runtime(f.pool, &f.runtime, &report) == VIREO_OK);
    CHECK(vireo_thread_pool_inspect_worker_result(f.pool, 0, &value) == VIREO_RESULT_BUSY);
    CHECK(memcmp(before, &value, sizeof(value)) == 0);
    CHECK(vireo_thread_pool_stop_and_join(f.pool, &report) == VIREO_OK);
    CHECK(vireo_thread_pool_inspect_worker_result(f.pool, 0, &value) == VIREO_OK);
    CHECK(value.result == VIREO_OK && value.stage == VIREO_THREAD_POOL_STAGE_NONE && value.pthread_error == 0);
    CHECK(!report.execution_enabled && atomic_load(&f.wait_calls) == 0);
    CHECK(vireo_thread_pool_enable_execution(f.pool, &report) == VIREO_RESULT_CANCELLED);
    finish(&f);
    puts("PASS execution: basic and whole-output preservation");
}

static void test_drain_and_unique_execution(void) {
    size_t const counts[] = {1, 3, 7};
    for (size_t n = 0; n < 3; ++n) {
        execution_fixture_t f; prepare(&f, counts[n]);
        vireo_task_cancel_t *cancel = NULL;
        CHECK(vireo_task_cancel_create(4096, &cancel) == VIREO_OK);
        CHECK(vireo_task_cancel_request(cancel) == VIREO_OK);
        for (uint32_t seq = 1; seq <= 63; ++seq) { push_task(&f, seq, seq == 1 ? cancel : NULL); }
        vireo_thread_pool_report_t report;
        CHECK(vireo_thread_pool_start_with_runtime(f.pool, &f.runtime, &report) == VIREO_OK);
        CHECK(atomic_load(&f.calls) == 0 && atomic_load(&f.wait_calls) == 0);
        vireo_thread_pool_info_t before;
        CHECK(vireo_thread_pool_inspect(f.pool, &before) == VIREO_OK && !before.execution_enabled);
        errno = EDOM;
        CHECK(vireo_thread_pool_enable_execution(f.pool, &report) == VIREO_OK);
        CHECK(errno == EDOM && report.execution_enabled);
        CHECK(vireo_thread_pool_enable_execution(f.pool, &report) == VIREO_RESULT_BUSY);
        close_queue(&f, VIREO_TASK_QUEUE_DRAIN);
        CHECK(join_pool(&f, &report) == VIREO_OK);
        CHECK(report.created_count == counts[n] && report.joined_count == counts[n]);
        CHECK(atomic_load(&f.calls) == 63 && atomic_load(&f.cancelled_seen) == 1);
        for (size_t seq = 1; seq <= 63; ++seq) { CHECK(atomic_load(&f.seen[seq]) == 1); }
        for (size_t i = 0; i < counts[n]; ++i) {
            vireo_thread_pool_worker_result_t value;
            CHECK(vireo_thread_pool_inspect_worker_result(f.pool, i, &value) == VIREO_OK);
            CHECK(value.result == VIREO_OK && value.queue_report.pthread_error == 0);
        }
        CHECK(!before.execution_enabled && before.joined_count == 0);
        CHECK(vireo_task_cancel_destroy(&cancel) == VIREO_OK);
        finish(&f);
    }
    puts("PASS execution: 1/3/7 workers drain 189 unique tasks, cancelled and finite-zero deadline still handed to callback");
}

static void test_callback_first_error_and_continue(void) {
    execution_fixture_t f; prepare(&f, 1); f.fail_execution = true;
    for (uint32_t seq = 1; seq <= 7; ++seq) { push_task(&f, seq, NULL); }
    vireo_thread_pool_report_t report;
    CHECK(vireo_thread_pool_start_with_runtime(f.pool, &f.runtime, &report) == VIREO_OK);
    CHECK(vireo_thread_pool_enable_execution(f.pool, &report) == VIREO_OK);
    close_queue(&f, VIREO_TASK_QUEUE_DRAIN);
    errno = ERANGE;
    CHECK(join_pool(&f, &report) == VIREO_RESULT_IO);
    CHECK(errno == ERANGE && report.stage == VIREO_THREAD_POOL_STAGE_EXECUTE_TASK && report.pthread_error == 0);
    CHECK(report.joined_count == 1 && report.queue_report.stage == VIREO_TASK_QUEUE_STAGE_NONE);
    CHECK(atomic_load(&f.calls) == 7);
    CHECK(vireo_thread_pool_stop_and_join(f.pool, &report) == VIREO_OK);
    vireo_thread_pool_worker_result_t value;
    CHECK(vireo_thread_pool_inspect_worker_result(f.pool, 0, &value) == VIREO_OK);
    CHECK(value.result == VIREO_RESULT_IO && value.stage == VIREO_THREAD_POOL_STAGE_EXECUTE_TASK);
    finish(&f);
    puts("PASS execution: callback IO preserved, later DATABASE and remaining tasks do not overwrite first error");
}

static void test_cancel_pending_inflight(void) {
    execution_fixture_t f; prepare(&f, 1); f.hold_first = true;
    for (uint32_t seq = 1; seq <= 7; ++seq) { push_task(&f, seq, NULL); }
    vireo_thread_pool_report_t report;
    CHECK(vireo_thread_pool_start_with_runtime(f.pool, &f.runtime, &report) == VIREO_OK);
    CHECK(vireo_thread_pool_enable_execution(f.pool, &report) == VIREO_OK);
    meet(&f.entered);
    close_queue(&f, VIREO_TASK_QUEUE_CANCEL_PENDING);
    vireo_task_queue_info_t info;
    CHECK(vireo_task_queue_inspect(f.queue, &info) == VIREO_OK && info.count == 6);
    meet(&f.release);
    CHECK(join_pool(&f, &report) == VIREO_OK && report.joined_count == 1);
    CHECK(atomic_load(&f.calls) == 1 && atomic_load(&f.seen[1]) == 1);
    CHECK(vireo_task_queue_inspect(f.queue, &info) == VIREO_OK && info.count == 6);
    finish(&f);
    puts("PASS execution: CANCEL_PENDING preserves six caller-owned cleanup obligations; in-flight callback returns normally");
}

static void test_open_stop_rejected(void) {
    execution_fixture_t f; prepare(&f, 1);
    f.hold_first = true; push_task(&f, 1, NULL);
    vireo_thread_pool_report_t report;
    CHECK(vireo_thread_pool_start_with_runtime(f.pool, &f.runtime, &report) == VIREO_OK);
    CHECK(vireo_thread_pool_enable_execution(f.pool, &report) == VIREO_OK);
    meet(&f.entered);
    errno = ERANGE;
    CHECK(vireo_thread_pool_stop_and_join(f.pool, &report) == VIREO_RESULT_BUSY);
    CHECK(errno == ERANGE && !report.stop_requested && report.joined_count == 0);
    CHECK(report.stage == VIREO_THREAD_POOL_STAGE_CHECK_QUEUE);
    f.inspect_fault = VIREO_RESULT_IO;
    CHECK(vireo_thread_pool_stop_and_join(f.pool, &report) == VIREO_RESULT_IO);
    CHECK(!report.stop_requested && report.joined_count == 0);
    f.inspect_fault = VIREO_OK;
    close_queue(&f, VIREO_TASK_QUEUE_DRAIN); meet(&f.release);
    CHECK(join_pool(&f, &report) == VIREO_OK);
    finish(&f);
    puts("PASS execution: OPEN or failed public inspect rejects join without stopping or consuming handles");
}

static void test_queue_failure_owner_progress(void) {
    for (int mode = 1; mode <= 2; ++mode) {
        execution_fixture_t f; prepare(&f, 1); push_task(&f, 1, NULL);
        atomic_store(&f.wait_fault, mode);
        vireo_thread_pool_report_t report;
        CHECK(vireo_thread_pool_start_with_runtime(f.pool, &f.runtime, &report) == VIREO_OK);
        CHECK(vireo_thread_pool_enable_execution(f.pool, &report) == VIREO_OK);
        close_queue(&f, VIREO_TASK_QUEUE_DRAIN);
        CHECK(join_pool(&f, &report) == VIREO_RESULT_INTERNAL);
        CHECK(report.joined_count == 1 && report.stage == VIREO_THREAD_POOL_STAGE_TAKE_TASK);
        CHECK(report.pthread_error == EIO && report.queue_report.transferred == (mode == 2));
        CHECK(report.queue_report.stage == (mode == 1 ? VIREO_TASK_QUEUE_STAGE_LOCK : VIREO_TASK_QUEUE_STAGE_UNLOCK));
        CHECK(atomic_load(&f.calls) == 0 && atomic_load(&f.wait_calls) == 1);
        vireo_thread_pool_worker_result_t value;
        CHECK(vireo_thread_pool_inspect_worker_result(f.pool, 0, &value) == VIREO_OK);
        CHECK(value.result == VIREO_RESULT_INTERNAL && value.queue_report.transferred == (mode == 2));
        vireo_task_queue_info_t info;
        CHECK(vireo_task_queue_inspect(f.queue, &info) == VIREO_OK && info.count == (mode == 1 ? (size_t)1 : (size_t)0));
        finish(&f);
    }
    puts("PASS execution: queue errors before/after real ownership transfer clean only the actual owner, never execute or retry");
}

static void test_enable_sync_progress(void) {
    for (int mode = 0; mode < 3; ++mode) {
        execution_fixture_t f; prepare(&f, 1);
        vireo_thread_pool_report_t report;
        CHECK(vireo_thread_pool_start_with_runtime(f.pool, &f.runtime, &report) == VIREO_OK);
        if (mode == 0) { atomic_store(&f.lock_fault, EIO); }
        if (mode == 1) { atomic_store(&f.wake_fault, EIO); }
        if (mode == 2) { atomic_store(&f.unlock_fault, EIO); }
        errno = EDOM;
        CHECK(vireo_thread_pool_enable_execution(f.pool, &report) == VIREO_RESULT_INTERNAL);
        CHECK(errno == EDOM && report.execution_enabled == (mode != 0));
        CHECK(report.stage == (mode == 0 ? VIREO_THREAD_POOL_STAGE_LOCK :
            mode == 1 ? VIREO_THREAD_POOL_STAGE_WAKE : VIREO_THREAD_POOL_STAGE_UNLOCK));
        if (mode == 0) { CHECK(vireo_thread_pool_enable_execution(f.pool, &report) == VIREO_OK); }
        else { CHECK(vireo_thread_pool_enable_execution(f.pool, &report) == VIREO_RESULT_BUSY); }
        close_queue(&f, VIREO_TASK_QUEUE_DRAIN);
        CHECK(join_pool(&f, &report) == VIREO_OK);
        CHECK(report.execution_enabled && report.joined_count == 1);
        finish(&f);
    }
    puts("PASS execution: enable LOCK preserves flag; WAKE/UNLOCK failures preserve committed flag and explicit cleanup");
}

static void test_enable_preflight_and_partial_start(void) {
    execution_fixture_t f; prepare(&f, 3); f.fail_create_at = 2;
    push_task(&f, 1, NULL);
    vireo_thread_pool_report_t report;
    CHECK(vireo_thread_pool_start_with_runtime(f.pool, &f.runtime, &report) == VIREO_RESULT_NO_MEMORY);
    CHECK(report.created_count == 1 && report.joined_count == 1);
    CHECK(vireo_thread_pool_enable_execution(f.pool, &report) == VIREO_RESULT_CANCELLED);
    CHECK(!report.execution_enabled && atomic_load(&f.calls) == 0 && atomic_load(&f.wait_calls) == 0);
    finish(&f);
    for (int mode = 0; mode < 3; ++mode) {
        prepare(&f, 1);
        CHECK(vireo_thread_pool_start_with_runtime(f.pool, &f.runtime, &report) == VIREO_OK);
        if (mode == 0) { f.inspect_fault = VIREO_RESULT_IO; }
        else { close_queue(&f, mode == 1 ? VIREO_TASK_QUEUE_DRAIN : VIREO_TASK_QUEUE_CANCEL_PENDING); }
        CHECK(vireo_thread_pool_enable_execution(f.pool, &report) ==
            (mode == 0 ? VIREO_RESULT_IO : VIREO_RESULT_CANCELLED));
        CHECK(!report.execution_enabled && report.stage == VIREO_THREAD_POOL_STAGE_CHECK_QUEUE);
        f.inspect_fault = VIREO_OK;
        CHECK(vireo_thread_pool_stop_and_join(f.pool, &report) == VIREO_OK);
        finish(&f);
    }
    puts("PASS execution: partial startup never consumes queued task; failed or closed preflight never commits enable");
}

static void test_push_after_enable(void) {
    execution_fixture_t f; prepare(&f, 3);
    vireo_thread_pool_report_t report;
    CHECK(vireo_thread_pool_start_with_runtime(f.pool, &f.runtime, &report) == VIREO_OK);
    CHECK(vireo_thread_pool_enable_execution(f.pool, &report) == VIREO_OK);
    for (uint32_t seq = 1; seq <= 31; ++seq) { push_task(&f, seq, NULL); }
    close_queue(&f, VIREO_TASK_QUEUE_DRAIN);
    CHECK(join_pool(&f, &report) == VIREO_OK);
    CHECK(atomic_load(&f.calls) == 31);
    for (size_t seq = 1; seq <= 31; ++seq) { CHECK(atomic_load(&f.seen[seq]) == 1); }
    finish(&f);
    puts("PASS execution: concurrent public pushes after enable transfer and execute 31 tasks exactly once");
}

int main(void) {
    int previous = 0;
    CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previous) == 0);
    test_basic_and_preservation(); test_drain_and_unique_execution();
    test_callback_first_error_and_continue(); test_cancel_pending_inflight();
    test_open_stop_rejected(); test_queue_failure_owner_progress();
    test_enable_sync_progress(); test_enable_preflight_and_partial_start();
    test_push_after_enable();
    CHECK(pthread_setcancelstate(previous, NULL) == 0);
    puts("test_thread_pool_execution: 9 groups passed");
    return 0;
}
