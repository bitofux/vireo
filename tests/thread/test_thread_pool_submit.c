/*
 * PROJECT : VIREO
 * FILE    : test_thread_pool_submit.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-12
 * BRIEF   : 池准入、一次公开交接及真实执行/异常所有权
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
#define TASK_LIMIT 64

_Static_assert(VIREO_THREAD_POOL_SUBMIT_STAGE_NONE == 0, "submit none");
_Static_assert(VIREO_THREAD_POOL_SUBMIT_STAGE_CHECK_POOL == 1, "submit pool");
_Static_assert(VIREO_THREAD_POOL_SUBMIT_STAGE_SUBMIT_QUEUE == 2, "submit queue");
_Static_assert(VIREO_THREAD_POOL_STAGE_EXECUTE_TASK == 12, "old stages held");

/**
 * @brief
 *     实际资源、原子执行账本与两方屏障，存活到所有 worker join 后。
 *
 * @note
 *     启动脚本/回调策略在创建线程前稳定；销毁脚本仅 manager 使用。
 *     不复制已初始化同步对象，不读取依赖私有布局。
 */
typedef struct submit_fixture {
    vireo_thread_pool_t *pool; /**< 唯一 pool owner，全部 join 后先销毁。 */
    vireo_task_queue_t *queue; /**< 独立专用 queue owner，pool 结束借用后销毁。 */
    vireo_thread_pool_runtime_t runtime; /**< 本核心操作副本，context 长借此 fixture。 */
    atomic_uint seen[TASK_LIMIT]; /**< 每身份实际执行次数，初始零，worker 原子更新。 */
    atomic_size_t calls; /**< 实际回调次数，不代表排队或完成数。 */
    atomic_size_t cancelled_seen; /**< 回调实际观测到取消的次数，不代表已停止。 */
    bool hold_first; /**< 启线程前稳定，第一项回调等待实际两方屏障。 */
    vireo_result_t execution_error; /**< 启线程前稳定的回调结果，不改变提交结果。 */
    pthread_barrier_t entered; /**< 第一项已领取进入回调的两方会合。 */
    pthread_barrier_t release; /**< 管理端确定满/关闭后，允许第一项正常返回。 */
    int init_error; /**< manager 的 mutex 初始化局部直接错误，不留下实际锁。 */
    size_t create_calls; /**< manager 实际线程创建尝试次数，有限有界。 */
    size_t fail_create_at; /**< 第指定次拒绝创建，0 无故障，其余真实创建。 */
    int destroy_error; /**< manager 下一次 mutex destroy 拒绝，不消耗实际锁。 */
} submit_fixture_t;

/**
 * @brief
 *     manager 短借的一次提交模型，成功交接必须调用公开队列。
 */
typedef struct submit_trace {
    size_t calls; /**< 适配尝试次数，应精确为零或一次。 */
    int mode; /**< 0 公开提交，1 未交接拒绝，2/3 真实交接后 WAKE/UNLOCK 模型。 */
    vireo_result_t result; /**< mode1 原结果，不覆盖真实成功的 owner 事实。 */
    vireo_task_queue_stage_t stage; /**< mode1 原公开诊断阶段。 */
    int pthread_error; /**< mode1 直接诊断，不通过 errno 传递。 */
} submit_trace_t;

/**
 * @brief
 *     实际两方会合，成功包括 SERIAL_THREAD，不靠 sleep 推断在途。
 *
 * @param[in,out] barrier
 *     已初始化的两方同步对象，参与者保持存活。
 *
 * @note
 *     非成功同步结果终止测试，不继续操作不可靠对象。
 */
static void meet(pthread_barrier_t *barrier) {
    int const error = pthread_barrier_wait(barrier);
    CHECK(error == 0 || error == PTHREAD_BARRIER_SERIAL_THREAD);
}

/**
 * @brief
 *     只借真实独立输入，以原子账本证明至多执行一次；借用结束正常返回。
 *
 * @param[in,out] context
 *     存活 fixture，worker 共享写仅为原子，策略在启动前稳定。
 * @param[in] task
 *     有效只借 task，不保留、移动或销毁。
 *
 * @return
 *     已设定业务结果；不影响此前提交事实，不用该错误回滚业务。
 */
static vireo_result_t execute(void *context, vireo_task_t const *task) {
    submit_fixture_t *f = context;
    vireo_task_info_t info;
    vireo_task_payload_view_t view;
    CHECK(vireo_task_inspect(task, &info) == VIREO_OK);
    size_t const sequence = info.metadata.route.request_sequence;
    CHECK(sequence > 0 && sequence < TASK_LIMIT);
    CHECK(info.metadata.request_instance_id == (uint64_t)sequence);
    CHECK(info.metadata.operation == 9 && info.metadata.deadline_ns == 0);
    CHECK(vireo_task_borrow_payload(task, &view) == VIREO_OK);
    CHECK(view.size == 3 && view.data[0] == (unsigned char)sequence &&
          view.data[1] == 0 && view.data[2] == 255);
    CHECK(atomic_fetch_add(&f->seen[sequence], 1) == 0);
    (void)atomic_fetch_add(&f->calls, 1);
    bool requested = false;
    CHECK(vireo_task_is_cancel_requested(task, &requested) == VIREO_OK);
    if (requested) { (void)atomic_fetch_add(&f->cancelled_seen, 1); }
    if (f->hold_first && sequence == 1) {
        meet(&f->entered);
        meet(&f->release);
        CHECK(view.data[0] == 1 && view.data[2] == 255);
    }
    errno = EILSEQ;
    return f->execution_error;
}

/**
 * @brief
 *     初始化的有限失败不留下资源，成功路径真实 POSIX 初始化。
 *
 * @param[in,out] context
 *     仅 manager 读取稳定初始化脚本。
 * @param[out] mutex
 *     有效未初始化存储，只有零返回才可使用。
 *
 * @return
 *     直接 pthread 或局部错误，不冒真实系统耗尽。
 */
static int init_mutex(void *context, pthread_mutex_t *mutex) {
    submit_fixture_t *f = context;
    return f->init_error != 0 ? f->init_error : pthread_mutex_init(mutex, NULL);
}

/**
 * @brief
 *     指定创建拒绝不留下线程，其他项真实 joinable 创建。
 *
 * @param[in,out] context
 *     manager 独占脚本，worker 不访问。
 * @param[out] thread
 *     仅成功时有效的句柄存储。
 * @param[in] entry
 *     真实 worker 入口。
 * @param[in] argument
 *     已稳定的 worker 槽，借至线程结束。
 *
 * @return
 *     0、EAGAIN 或真实直接错误。
 */
static int create_worker(void *context, pthread_t *thread, void *(*entry)(void *), void *argument) {
    submit_fixture_t *f = context;
    ++f->create_calls;
    return f->create_calls == f->fail_create_at ? EAGAIN : pthread_create(thread, NULL, entry, argument);
}

/**
 * @brief
 *     一次销毁拒绝保留实际 mutex，移除脚本后可真实销毁。
 *
 * @param[in,out] context
 *     manager 独占的一次脚本。
 * @param[in,out] mutex
 *     有效且全部访问已结束的同步资源。
 *
 * @return
 *     0 或直接错误；该有限模型不保证真实损坏同步可恢复。
 */
static int destroy_mutex(void *context, pthread_mutex_t *mutex) {
    submit_fixture_t *f = context;
    int const error = f->destroy_error;
    f->destroy_error = 0;
    return error != 0 ? error : pthread_mutex_destroy(mutex);
}

/**
 * @brief
 *     保真实 owner 的公开提交适配，未交接/已交接异常分别可核对。
 *
 * @param[in,out] context
 *     本次 manager 短借脚本，不保存或与 worker 共享。
 * @param[in,out] queue
 *     有效公开队列，禁止访问私有状态。
 * @param[in,out] owner
 *     独占非空源，mode2/3 先真实公开交接，再报告模型错误。
 * @param[out] report
 *     必需原报告，未交接模型保持源并发布 false。
 *
 * @return
 *     原公开结果、mode1 原拒绝或已真实交接后的 INTERNAL。
 *
 * @note
 *     无隐式重试；model WAKE/UNLOCK 不破坏实际同步，不外推异常恢复能力。
 */
static vireo_result_t submit_task(void *context, vireo_task_queue_t *queue,
    vireo_task_t **owner, vireo_task_queue_transfer_report_t *report) {
    submit_trace_t *trace = context;
    ++trace->calls;
    errno = ENOSPC;
    if (trace->mode == 1) {
        *report = (vireo_task_queue_transfer_report_t){trace->stage, false, trace->pthread_error};
        return trace->result;
    }
    vireo_result_t const result = vireo_task_queue_try_push(queue, owner, report);
    if (result == VIREO_OK && (trace->mode == 2 || trace->mode == 3)) {
        *report = (vireo_task_queue_transfer_report_t){trace->mode == 2 ?
            VIREO_TASK_QUEUE_STAGE_WAKE : VIREO_TASK_QUEUE_STAGE_UNLOCK, true, EIO};
        return VIREO_RESULT_INTERNAL;
    }
    return result;
}

/**
 * @brief
 *     原地构造固定预算资源和 fixture，不移动同步对象。
 *
 * @param[out] f
 *     稳定可写地址，存活到 finish。
 * @param[in] workers
 *     本场景显式正 worker 数。
 * @param[in] capacity
 *     本场景显式正队列容量。
 *
 * @note
 *     创建/prepare/configure 无外部并发，不启动线程；初始化全部原子/屏障。
 */
static void prepare(submit_fixture_t *f, size_t workers, size_t capacity) {
    f->pool = NULL; f->queue = NULL;
    f->runtime = *vireo_thread_pool_standard_runtime(); f->runtime.context = f;
    f->runtime.mutex_init = init_mutex; f->runtime.thread_create = create_worker;
    f->runtime.mutex_destroy = destroy_mutex;
    for (size_t i = 0; i < TASK_LIMIT; ++i) { atomic_init(&f->seen[i], 0); }
    atomic_init(&f->calls, 0); atomic_init(&f->cancelled_seen, 0);
    f->hold_first = false; f->execution_error = VIREO_OK;
    f->init_error = 0; f->create_calls = 0; f->fail_create_at = 0; f->destroy_error = 0;
    CHECK(pthread_barrier_init(&f->entered, NULL, 2) == 0);
    CHECK(pthread_barrier_init(&f->release, NULL, 2) == 0);
    vireo_task_queue_options_t const q = {capacity, 65536};
    vireo_thread_pool_options_t const p = {workers, 65536};
    CHECK(vireo_task_queue_create(&q, &f->queue) == VIREO_OK);
    CHECK(vireo_task_queue_prepare_wait(f->queue) == VIREO_OK);
    CHECK(vireo_thread_pool_create(&p, &f->pool) == VIREO_OK);
    vireo_thread_pool_configuration_t const c = {f->queue, execute, f};
    CHECK(vireo_thread_pool_configure(f->pool, &c, NULL) == VIREO_OK);
}

/**
 * @brief
 *     在任何 worker 放行前真实完整启动并放行。
 *
 * @param[in,out] f
 *     已装配 fixture，策略和运行表稳定。
 *
 * @note
 *     调用者取消已禁用，无队列并发访问资格检查；不重试管理错误。
 */
static void start(submit_fixture_t *f) {
    vireo_thread_pool_report_t report;
    CHECK(vireo_thread_pool_start_with_runtime(f->pool, &f->runtime, &report) == VIREO_OK);
    CHECK(vireo_thread_pool_enable_execution(f->pool, &report) == VIREO_OK);
}

/**
 * @brief
 *     生成独立输入，复制后改变源字节，回调另核原 payload。
 *
 * @param[in] sequence
 *     1..63 的本场景身份标签/实例。
 * @param[in] cancel
 *     可空调用者强引用，只由公开构造 retain。
 *
 * @return
 *     独占 task owner，由 caller 提交或公开销毁。
 */
static vireo_task_t *make_task(uint32_t sequence, vireo_task_cancel_t *cancel) {
    vireo_task_route_t route;
    vireo_task_metadata_t metadata;
    vireo_task_t *task = NULL;
    unsigned char bytes[] = {(unsigned char)sequence, 0, 255};
    CHECK(vireo_task_route_make(1, 0, 1, sequence, &route) == VIREO_OK);
    CHECK(vireo_task_metadata_make(route, sequence, 9, 0, &metadata) == VIREO_OK);
    if (cancel == NULL) {
        CHECK(vireo_task_create_copy(metadata, bytes, sizeof bytes, 4096, &task) == VIREO_OK);
    } else {
        CHECK(vireo_task_create_copy_with_cancel(metadata, bytes, sizeof bytes, 4096, cancel, &task) == VIREO_OK);
    }
    memset(bytes, 17, sizeof bytes);
    return task;
}

/**
 * @brief
 *     caller 显式有界处理公开锁竞争，不把它藏成产品内部重试。
 *
 * @param[in,out] queue
 *     存活 queue，与 worker 同期关闭由公开同步处理。
 * @param[in] mode
 *     DRAIN 或 CANCEL_PENDING。
 *
 * @note
 *     仅 LOCK/EBUSY/未改变可重试；其他真实失败立即终止测试。
 */
static void close_queue(vireo_task_queue_t *queue, vireo_task_queue_state_t mode) {
    for (size_t i = 0; i < 10000; ++i) {
        vireo_task_queue_close_report_t report;
        vireo_result_t const result = vireo_task_queue_close(queue, mode, &report);
        if (result == VIREO_OK) { return; }
        CHECK(result == VIREO_RESULT_BUSY && report.stage == VIREO_TASK_QUEUE_STAGE_LOCK &&
              report.pthread_error == EBUSY && !report.changed);
        CHECK(sched_yield() == 0);
    }
    CHECK(false);
}

/**
 * @brief
 *     caller 显式有界处理 worker 短占队列锁，不掩盖满表或已转移异常。
 *
 * @param[in,out] f
 *     已完整启动/放行的存活 fixture，同池管理串行。
 * @param[in,out] task
 *     caller 独占源，每次未转移 LOCK/EBUSY 后才允许再尝试。
 * @param[out] report
 *     必需独立报告，成功保存最终该次实际转移。
 *
 * @note
 *     这是测试调用者策略，产品入口仍一次调用；只因 LOCK/EBUSY 重试，预算有界。
 */
static void submit_success(submit_fixture_t *f, vireo_task_t **task,
                           vireo_thread_pool_submit_report_t *report) {
    for (size_t i = 0; i < 10000; ++i) {
        errno = EDOM;
        vireo_result_t const result = vireo_thread_pool_try_submit(f->pool, task, report);
        CHECK(errno == EDOM && report->queue_called);
        if (result == VIREO_OK) {
            CHECK(*task == NULL && report->queue_report.transferred &&
                  report->stage == VIREO_THREAD_POOL_SUBMIT_STAGE_NONE);
            return;
        }
        CHECK(result == VIREO_RESULT_BUSY && *task != NULL && !report->queue_report.transferred &&
              report->queue_report.stage == VIREO_TASK_QUEUE_STAGE_LOCK &&
              report->queue_report.pthread_error == EBUSY);
        CHECK(sched_yield() == 0);
    }
    CHECK(false);
}

/**
 * @brief
 *     worker 可能短占 queue 锁时，调用者显式有界取得收尾资格。
 *
 * @param[in,out] f
 *     queue 已成功关闭且 callback 被允许正常返回的 fixture。
 * @param[in] expected
 *     本场景真实回调首错或 OK。
 *
 * @note
 *     只对 CHECK_QUEUE/BUSY 重试；全部线程成功 join 后才结束依赖寿命。
 */
static void join_workers(submit_fixture_t *f, vireo_result_t expected) {
    for (size_t i = 0; i < 10000; ++i) {
        vireo_thread_pool_report_t report;
        vireo_result_t const result = vireo_thread_pool_stop_and_join(f->pool, &report);
        if (result == VIREO_RESULT_BUSY && report.stage == VIREO_THREAD_POOL_STAGE_CHECK_QUEUE) {
            CHECK(sched_yield() == 0); continue;
        }
        CHECK(result == expected && report.joined_count == report.created_count);
        return;
    }
    CHECK(false);
}

/**
 * @brief
 *     全部线程回收后结束池借用，再销毁已空队列与本测试同步对象。
 *
 * @param[in,out] f
 *     无访问、pending 已由 caller 显式清理的 fixture。
 *
 * @note
 *     不自动隐藏 pending 清理，队列非空直接使测试失败。
 */
static void finish(submit_fixture_t *f) {
    CHECK(vireo_thread_pool_destroy(&f->pool) == VIREO_OK);
    CHECK(vireo_task_queue_destroy(&f->queue) == VIREO_OK);
    CHECK(pthread_barrier_destroy(&f->entered) == 0);
    CHECK(pthread_barrier_destroy(&f->release) == 0);
}

/* 测试只比较逻辑字段，不把成功 padding 当 ABI；失败 owner 精确保原指针。 */
static void no_queue(vireo_thread_pool_submit_report_t const *report,
                     vireo_thread_pool_submit_stage_t stage) {
    CHECK(report->stage == stage && !report->queue_called);
    CHECK(report->queue_report.stage == VIREO_TASK_QUEUE_STAGE_NONE &&
          !report->queue_report.transferred && report->queue_report.pthread_error == 0);
}

/* 基本错误优先资格；NULL report 没有可写输出，其他路径必须覆盖旧诊断。 */
static void test_basic(void) {
    submit_fixture_t f; prepare(&f, 1, 2);
    vireo_task_t *task = make_task(1, NULL); vireo_task_t *const saved = task;
    vireo_thread_pool_submit_report_t report;
    memset(&report, 0xa5, sizeof report); errno = EDOM;
    CHECK(vireo_thread_pool_try_submit(NULL, &task, &report) == VIREO_RESULT_INVALID_ARGUMENT);
    no_queue(&report, VIREO_THREAD_POOL_SUBMIT_STAGE_NONE); CHECK(task == saved && errno == EDOM);
    CHECK(vireo_thread_pool_try_submit(f.pool, NULL, &report) == VIREO_RESULT_INVALID_ARGUMENT);
    no_queue(&report, VIREO_THREAD_POOL_SUBMIT_STAGE_NONE);
    CHECK(vireo_thread_pool_try_submit(f.pool, &task, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(task == saved && errno == EDOM);
    CHECK(vireo_thread_pool_try_submit_with_submitter(f.pool, &task, NULL, &report) == VIREO_RESULT_INVALID_ARGUMENT);
    vireo_thread_pool_queue_submitter_t const invalid = {NULL, NULL};
    CHECK(vireo_thread_pool_try_submit_with_submitter(f.pool, &task, &invalid, &report) == VIREO_RESULT_INVALID_ARGUMENT);
    no_queue(&report, VIREO_THREAD_POOL_SUBMIT_STAGE_NONE); CHECK(task == saved && errno == EDOM);
    vireo_task_t *empty = NULL;
    CHECK(vireo_thread_pool_try_submit(f.pool, &empty, &report) == VIREO_RESULT_NOT_FOUND);
    no_queue(&report, VIREO_THREAD_POOL_SUBMIT_STAGE_NONE);
    CHECK(vireo_thread_pool_try_submit(f.pool, &task, &report) == VIREO_RESULT_NOT_FOUND);
    no_queue(&report, VIREO_THREAD_POOL_SUBMIT_STAGE_CHECK_POOL);
    CHECK(task == saved && errno == EDOM);
    CHECK(vireo_task_destroy(&task) == VIREO_OK); finish(&f);
}

/* 真实未配置、停驻、初始化失败、部分创建停止均不触 queue。 */
static void test_lifecycle(void) {
    vireo_thread_pool_options_t const options = {1, 4096};
    vireo_thread_pool_t *unconfigured = NULL;
    CHECK(vireo_thread_pool_create(&options, &unconfigured) == VIREO_OK);
    vireo_task_t *task = make_task(1, NULL); vireo_task_t *const saved = task;
    vireo_thread_pool_submit_report_t report; errno = EDOM;
    CHECK(vireo_thread_pool_try_submit(unconfigured, &task, &report) == VIREO_RESULT_NOT_FOUND);
    no_queue(&report, VIREO_THREAD_POOL_SUBMIT_STAGE_CHECK_POOL);
    CHECK(vireo_thread_pool_destroy(&unconfigured) == VIREO_OK);
    submit_fixture_t f; prepare(&f, 1, 2);
    vireo_thread_pool_report_t management;
    CHECK(vireo_thread_pool_start_with_runtime(f.pool, &f.runtime, &management) == VIREO_OK);
    CHECK(vireo_thread_pool_try_submit(f.pool, &task, &report) == VIREO_RESULT_BUSY);
    no_queue(&report, VIREO_THREAD_POOL_SUBMIT_STAGE_CHECK_POOL);
    join_workers(&f, VIREO_OK);
    CHECK(vireo_thread_pool_try_submit(f.pool, &task, &report) == VIREO_RESULT_CANCELLED);
    vireo_task_t *empty = NULL;
    CHECK(vireo_thread_pool_try_submit(f.pool, &empty, &report) == VIREO_RESULT_NOT_FOUND);
    no_queue(&report, VIREO_THREAD_POOL_SUBMIT_STAGE_NONE); finish(&f);
    prepare(&f, 1, 2); f.init_error = ENOMEM;
    CHECK(vireo_thread_pool_start_with_runtime(f.pool, &f.runtime, &management) == VIREO_RESULT_NO_MEMORY);
    CHECK(vireo_thread_pool_try_submit(f.pool, &task, &report) == VIREO_RESULT_BUSY);
    no_queue(&report, VIREO_THREAD_POOL_SUBMIT_STAGE_CHECK_POOL); finish(&f);
    prepare(&f, 3, 2); f.fail_create_at = 2;
    CHECK(vireo_thread_pool_start_with_runtime(f.pool, &f.runtime, &management) == VIREO_RESULT_NO_MEMORY);
    CHECK(management.created_count == 1 && management.joined_count == 1 && management.stop_requested);
    CHECK(vireo_thread_pool_try_submit(f.pool, &task, &report) == VIREO_RESULT_CANCELLED);
    no_queue(&report, VIREO_THREAD_POOL_SUBMIT_STAGE_CHECK_POOL);
    CHECK(task == saved && errno == EDOM && atomic_load(&f.calls) == 0);
    CHECK(vireo_task_destroy(&task) == VIREO_OK); finish(&f);
}

/* 单/多 worker 真领取；显式取消和有限 deadline0 不被 submit 自动过滤。 */
static void test_real_submit(void) {
    size_t const workers[] = {1, 3, 7};
    for (size_t w = 0; w < sizeof workers / sizeof workers[0]; ++w) {
        submit_fixture_t f; prepare(&f, workers[w], 63); start(&f);
        vireo_task_cancel_t *cancel = NULL;
        CHECK(vireo_task_cancel_create(4096, &cancel) == VIREO_OK);
        CHECK(vireo_task_cancel_request(cancel) == VIREO_OK);
        for (uint32_t s = 1; s <= 31; ++s) {
            vireo_task_t *task = make_task(s, s == 1 ? cancel : NULL);
            bool submitted = false;
            for (size_t i = 0; i < 10000; ++i) {
                vireo_thread_pool_submit_report_t report; errno = EDOM;
                vireo_result_t const result = vireo_thread_pool_try_submit(f.pool, &task, &report);
                CHECK(errno == EDOM && report.queue_called);
                if (result == VIREO_OK) {
                    CHECK(task == NULL && report.stage == VIREO_THREAD_POOL_SUBMIT_STAGE_NONE &&
                          report.queue_report.transferred && report.queue_report.pthread_error == 0);
                    submitted = true; break;
                }
                CHECK(result == VIREO_RESULT_BUSY && task != NULL && !report.queue_report.transferred &&
                      report.stage == VIREO_THREAD_POOL_SUBMIT_STAGE_SUBMIT_QUEUE &&
                      report.queue_report.stage == VIREO_TASK_QUEUE_STAGE_LOCK &&
                      report.queue_report.pthread_error == EBUSY);
                CHECK(sched_yield() == 0);
            }
            CHECK(submitted);
        }
        close_queue(f.queue, VIREO_TASK_QUEUE_DRAIN); join_workers(&f, VIREO_OK);
        CHECK(atomic_load(&f.calls) == 31 && atomic_load(&f.cancelled_seen) == 1);
        for (size_t s = 1; s <= 31; ++s) { CHECK(atomic_load(&f.seen[s]) == 1); }
        CHECK(vireo_task_cancel_destroy(&cancel) == VIREO_OK); finish(&f);
    }
}

/* barrier 固定一在途、一 pending、第三项被真实满表拒绝；指标只计依赖拒绝。 */
static void test_full(void) {
    submit_fixture_t f; prepare(&f, 1, 1); f.hold_first = true; start(&f);
    vireo_task_t *task = make_task(1, NULL);
    vireo_thread_pool_submit_report_t report;
    submit_success(&f, &task, &report);
    meet(&f.entered);
    task = make_task(2, NULL);
    submit_success(&f, &task, &report);
    task = make_task(3, NULL); vireo_task_t *const saved = task; errno = EDOM;
    CHECK(vireo_thread_pool_try_submit(f.pool, &task, &report) == VIREO_RESULT_BUSY);
    CHECK(task == saved && errno == EDOM && report.queue_called && !report.queue_report.transferred);
    CHECK(report.stage == VIREO_THREAD_POOL_SUBMIT_STAGE_SUBMIT_QUEUE &&
          report.queue_report.stage == VIREO_TASK_QUEUE_STAGE_NONE && report.queue_report.pthread_error == 0);
    vireo_task_queue_metrics_t metrics;
    CHECK(vireo_task_queue_inspect_metrics(f.queue, &metrics) == VIREO_OK);
    CHECK(metrics.depth == 1 && metrics.high_watermark == 1 && metrics.full_rejections == 1);
    close_queue(f.queue, VIREO_TASK_QUEUE_DRAIN);
    CHECK(vireo_thread_pool_try_submit(f.pool, &task, &report) == VIREO_RESULT_CANCELLED);
    CHECK(task == saved && report.queue_called && !report.queue_report.transferred);
    CHECK(vireo_task_queue_inspect_metrics(f.queue, &metrics) == VIREO_OK);
    CHECK(metrics.closed_rejections == 1 && metrics.full_rejections == 1);
    meet(&f.release); join_workers(&f, VIREO_OK);
    CHECK(atomic_load(&f.calls) == 2 && atomic_load(&f.seen[3]) == 0);
    CHECK(vireo_task_destroy(&task) == VIREO_OK); finish(&f);
}

/* 两种公开永久关闭都拒绝 pool 提交；CP pending 仍显式归 caller 清理。 */
static void test_closed(void) {
    vireo_task_queue_state_t const modes[] = {VIREO_TASK_QUEUE_DRAIN, VIREO_TASK_QUEUE_CANCEL_PENDING};
    for (size_t i = 0; i < sizeof modes / sizeof modes[0]; ++i) {
        submit_fixture_t f; prepare(&f, 1, 2); f.hold_first = true; start(&f);
        vireo_task_t *task = make_task(1, NULL);
        vireo_thread_pool_submit_report_t report;
        submit_success(&f, &task, &report); meet(&f.entered);
        task = make_task(2, NULL);
        submit_success(&f, &task, &report);
        close_queue(f.queue, modes[i]);
        task = make_task(3, NULL); vireo_task_t *const saved = task; errno = EDOM;
        CHECK(vireo_thread_pool_try_submit(f.pool, &task, &report) == VIREO_RESULT_CANCELLED);
        CHECK(report.stage == VIREO_THREAD_POOL_SUBMIT_STAGE_SUBMIT_QUEUE && report.queue_called &&
              !report.queue_report.transferred && task == saved && errno == EDOM);
        meet(&f.release); join_workers(&f, VIREO_OK);
        if (modes[i] == VIREO_TASK_QUEUE_CANCEL_PENDING) {
            vireo_task_t *pending = NULL; vireo_task_queue_transfer_report_t transfer;
            CHECK(vireo_task_queue_try_take_cancelled(f.queue, &pending, &transfer) == VIREO_OK);
            vireo_task_info_t info; CHECK(vireo_task_inspect(pending, &info) == VIREO_OK);
            CHECK(info.metadata.route.request_sequence == 2 && atomic_load(&f.seen[2]) == 0);
            CHECK(vireo_task_destroy(&pending) == VIREO_OK);
        }
        CHECK(atomic_load(&f.seen[1]) == 1 && atomic_load(&f.seen[3]) == 0);
        CHECK(vireo_task_destroy(&task) == VIREO_OK); finish(&f);
    }
}

/* seam 数零/一验证资格拒绝不触依赖、BUSY/原错没有隐藏重试和 owner 消耗。 */
static void test_dependency_errors(void) {
    submit_fixture_t f; prepare(&f, 1, 2);
    submit_trace_t trace = {0, 1, VIREO_RESULT_BUSY, VIREO_TASK_QUEUE_STAGE_LOCK, EBUSY};
    vireo_thread_pool_queue_submitter_t const seam = {&trace, submit_task};
    vireo_task_t *task = make_task(1, NULL); vireo_task_t *const saved = task;
    vireo_thread_pool_submit_report_t report;
    CHECK(vireo_thread_pool_try_submit_with_submitter(f.pool, &task, &seam, &report) == VIREO_RESULT_NOT_FOUND);
    CHECK(trace.calls == 0); start(&f);
    vireo_result_t const errors[] = {VIREO_RESULT_BUSY, VIREO_RESULT_INTERNAL, VIREO_RESULT_IO,
                                   VIREO_RESULT_OVERFLOW, VIREO_RESULT_NOT_FOUND};
    for (size_t i = 0; i < sizeof errors / sizeof errors[0]; ++i) {
        trace.result = errors[i]; trace.calls = 0;
        trace.pthread_error = i < 2 ? (i == 0 ? EBUSY : EIO) : 0;
        memset(&report, 0xa5, sizeof report); errno = EDOM;
        CHECK(vireo_thread_pool_try_submit_with_submitter(f.pool, &task, &seam, &report) == errors[i]);
        CHECK(trace.calls == 1 && task == saved && errno == EDOM && report.queue_called &&
              report.stage == VIREO_THREAD_POOL_SUBMIT_STAGE_SUBMIT_QUEUE &&
              report.queue_report.stage == trace.stage && !report.queue_report.transferred &&
              report.queue_report.pthread_error == trace.pthread_error);
    }
    close_queue(f.queue, VIREO_TASK_QUEUE_DRAIN); join_workers(&f, VIREO_OK);
    CHECK(atomic_load(&f.calls) == 0); CHECK(vireo_task_destroy(&task) == VIREO_OK); finish(&f);
}

/* 真实公开交接后才注入异常：callback 获得该项，caller 只保报告而没有第二 owner。 */
static void test_transferred_errors(void) {
    for (int mode = 2; mode <= 3; ++mode) {
        submit_fixture_t f; prepare(&f, 1, 2); f.hold_first = true; start(&f);
        submit_trace_t trace = {0, mode, VIREO_OK, VIREO_TASK_QUEUE_STAGE_NONE, 0};
        vireo_thread_pool_queue_submitter_t const seam = {&trace, submit_task};
        vireo_task_t *task = make_task(1, NULL);
        vireo_thread_pool_submit_report_t report;
        submit_success(&f, &task, &report);
        meet(&f.entered); /* worker 在 task1 回调屏障中，task2 的交接没有领取锁竞争。 */
        task = make_task(2, NULL); errno = EDOM;
        CHECK(vireo_thread_pool_try_submit_with_submitter(f.pool, &task, &seam, &report) == VIREO_RESULT_INTERNAL);
        CHECK(trace.calls == 1 && task == NULL && errno == EDOM && report.queue_called &&
              report.stage == VIREO_THREAD_POOL_SUBMIT_STAGE_SUBMIT_QUEUE &&
              report.queue_report.transferred && report.queue_report.pthread_error == EIO &&
              report.queue_report.stage == (mode == 2 ? VIREO_TASK_QUEUE_STAGE_WAKE : VIREO_TASK_QUEUE_STAGE_UNLOCK));
        vireo_thread_pool_submit_report_t const snapshot = report;
        close_queue(f.queue, VIREO_TASK_QUEUE_DRAIN); meet(&f.release);
        join_workers(&f, VIREO_OK);
        CHECK(atomic_load(&f.calls) == 2 && atomic_load(&f.seen[2]) == 1 && snapshot.queue_report.transferred);
        finish(&f); /* LSan 核实真实 worker 清理，无 caller 自动销毁已转移旧别名。 */
    }
}

/* task 接纳成功与回调原错不同；worker 仍清理，结果只能 join 后另读。 */
static void test_execution_error(void) {
    submit_fixture_t f; prepare(&f, 1, 2); f.execution_error = VIREO_RESULT_DATABASE; start(&f);
    vireo_task_t *task = make_task(1, NULL); vireo_thread_pool_submit_report_t report;
    submit_success(&f, &task, &report);
    CHECK(report.queue_report.transferred && report.stage == VIREO_THREAD_POOL_SUBMIT_STAGE_NONE);
    close_queue(f.queue, VIREO_TASK_QUEUE_DRAIN); join_workers(&f, VIREO_RESULT_DATABASE);
    vireo_thread_pool_worker_result_t result;
    CHECK(vireo_thread_pool_inspect_worker_result(f.pool, 0, &result) == VIREO_OK);
    CHECK(result.result == VIREO_RESULT_DATABASE && result.stage == VIREO_THREAD_POOL_STAGE_EXECUTE_TASK);
    finish(&f);
}

/* 实际 cond 已销毁而 mutex 拒绝销毁产生 retiring，源保持且空源优先。 */
static void test_retiring(void) {
    submit_fixture_t f; prepare(&f, 1, 2);
    vireo_thread_pool_report_t management;
    CHECK(vireo_thread_pool_start_with_runtime(f.pool, &f.runtime, &management) == VIREO_OK);
    join_workers(&f, VIREO_OK); f.destroy_error = EBUSY;
    CHECK(vireo_thread_pool_destroy(&f.pool) == VIREO_RESULT_BUSY && f.pool != NULL);
    vireo_task_t *task = make_task(1, NULL); vireo_task_t *const saved = task;
    vireo_thread_pool_submit_report_t report; errno = EDOM;
    CHECK(vireo_thread_pool_try_submit(f.pool, &task, &report) == VIREO_RESULT_CANCELLED);
    no_queue(&report, VIREO_THREAD_POOL_SUBMIT_STAGE_CHECK_POOL);
    CHECK(task == saved && errno == EDOM);
    vireo_task_t *empty = NULL;
    CHECK(vireo_thread_pool_try_submit(f.pool, &empty, &report) == VIREO_RESULT_NOT_FOUND);
    no_queue(&report, VIREO_THREAD_POOL_SUBMIT_STAGE_NONE);
    CHECK(vireo_task_destroy(&task) == VIREO_OK); finish(&f);
}

int main(void) {
    int previous;
    CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previous) == 0);
    test_basic(); test_lifecycle(); test_real_submit(); test_full(); test_closed();
    test_dependency_errors(); test_transferred_errors(); test_execution_error(); test_retiring();
    CHECK(pthread_setcancelstate(previous, NULL) == 0);
    puts("test_thread_pool_submit: 9 groups passed");
    return 0;
}
