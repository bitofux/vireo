/*
 * PROJECT : VIREO
 * FILE    : test_thread_pool_shutdown.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-12
 * BRIEF   : 关闭成功后回收、真实在途与两段部分进度
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
#define ATTEMPT_LIMIT 100000

_Static_assert(VIREO_THREAD_POOL_SHUTDOWN_STAGE_NONE == 0, "shutdown none");
_Static_assert(VIREO_THREAD_POOL_SHUTDOWN_STAGE_CHECK_POOL == 1, "shutdown check");
_Static_assert(VIREO_THREAD_POOL_SHUTDOWN_STAGE_CLOSE_QUEUE == 2, "shutdown close");
_Static_assert(VIREO_THREAD_POOL_SHUTDOWN_STAGE_JOIN_WORKERS == 3, "shutdown join");
_Static_assert(VIREO_THREAD_POOL_STAGE_EXECUTE_TASK == 12, "old management stages");
_Static_assert(VIREO_THREAD_POOL_SUBMIT_STAGE_SUBMIT_QUEUE == 2, "old submit stages");

/**
 * @brief
 *     独立资源、真实执行原子账本及管理端有限失败脚本。
 *
 * @note
 *     策略在启动前稳定，管理脚本由串行管理线程使用；不移动已初始化同步对象。
 *     没有 queue/task 私有状态，全部线程 join 后才能结束 fixture 寿命。
 */
typedef struct shutdown_fixture {
    vireo_thread_pool_t *pool; /**< 唯一池 owner，全部 join 后销毁。 */
    vireo_task_queue_t *queue; /**< 唯一专用队列 owner，借用结束且为空后销毁。 */
    vireo_thread_pool_runtime_t runtime; /**< 自有操作副本，context 长借此 fixture。 */
    atomic_uint seen[TASK_LIMIT]; /**< 各任务身份实际执行次数，初始零。 */
    atomic_size_t calls; /**< 实际回调总次数，worker 原子更新。 */
    atomic_size_t join_calls; /**< 实际回收适配尝试次数，包括未消耗句柄的拒绝。 */
    bool hold_first; /**< 启动前稳定，task1 回调通过两个屏障暂停。 */
    vireo_result_t execution_error; /**< 启动前稳定的业务原错，不等管理关闭失败。 */
    pthread_barrier_t entered; /**< 任务1 已进入回调的真实两方会合。 */
    pthread_barrier_t release; /**< 观察真实关闭后允许任务1 正常返回。 */
    int init_error; /**< 下一启动的直接初始化拒绝，不留下实际 mutex。 */
    size_t create_calls; /**< 管理端累计创建适配尝试数，worker 不访问。 */
    size_t fail_create_at; /**< 启动前稳定，第指定次拒绝创建，零表示不注入。 */
    size_t join_failures; /**< 管理端尚余拒绝次数，失败不消耗句柄。 */
    vireo_result_t inspect_error; /**< 管理端原公开观测错误，OK 时真实 inspect。 */
    int destroy_error; /**< 管理端下一 mutex 销毁拒绝，不消耗实际锁。 */
} shutdown_fixture_t;

/**
 * @brief
 *     本次短借关闭脚本，成功和已提交异常先真实公开关闭。
 */
typedef struct close_trace {
    size_t calls; /**< 本次尝试次数，资格拒绝零，通过后精确一次。 */
    int mode; /**< 0 真实公开，1 无关闭拒绝，2/3 真实关闭后 WAKE/UNLOCK 模型。 */
    vireo_result_t result; /**< 模式1 原结果，不改变队列或线程。 */
    vireo_task_queue_stage_t stage; /**< 模式1 原诊断阶段。 */
    int pthread_error; /**< 原直接诊断，非入口 errno。 */
} close_trace_t;

/**
 * @brief
 *     独占关闭管理调用的线程输入与结果，主线程 join 后才读报告。
 */
typedef struct shutdown_job {
    shutdown_fixture_t *fixture; /**< 长借至本管理线程 join，主线程不并发调用池管理。 */
    vireo_task_queue_state_t mode; /**< 创建线程前稳定的 DRAIN 或 CANCEL_PENDING。 */
    vireo_thread_pool_shutdown_report_t report; /**< 管理线程写，主线程成功 join 后读。 */
    vireo_result_t result; /**< 管理线程最终原结果。 */
    atomic_bool finished; /**< 完成调用后才置 true，供主线程独立观测。 */
    bool errno_held; /**< 管理线程检查入口 errno 是否保持，join 后读取。 */
} shutdown_job_t;

/**
 * @brief
 *     两方真实会合，不靠 sleep 推断 task 已被领取。
 *
 * @param[in,out] barrier
 *     已初始化、存活到两个参与者退出的同步对象。
 *
 * @note
 *     SERIAL_THREAD 也属于成功，其他错误立即终止测试。
 */
static void meet(pthread_barrier_t *barrier) {
    int const error = pthread_barrier_wait(barrier);
    CHECK(error == 0 || error == PTHREAD_BARRIER_SERIAL_THREAD);
}

/**
 * @brief
 *     核实独立 payload 与至多一次执行，回调不接管 task。
 *
 * @param[in,out] context
 *     存活 fixture，worker 共享可变账本为原子，策略在启动前稳定。
 * @param[in] task
 *     只借到本次返回，禁止保存、移动或销毁。
 *
 * @return
 *     指定的原业务结果；结束借用后正常返回。
 */
static vireo_result_t execute(void *context, vireo_task_t const *task) {
    shutdown_fixture_t *f = context;
    vireo_task_info_t info;
    vireo_task_payload_view_t view;
    CHECK(vireo_task_inspect(task, &info) == VIREO_OK);
    uint32_t const seq = info.metadata.route.request_sequence;
    CHECK(seq > 0 && seq < TASK_LIMIT && info.metadata.request_instance_id == seq);
    CHECK(info.metadata.operation == 8 && info.metadata.deadline_ns == 0);
    CHECK(vireo_task_borrow_payload(task, &view) == VIREO_OK);
    CHECK(view.size == 3 && view.data[0] == (unsigned char)seq && view.data[1] == 0 && view.data[2] == 255);
    CHECK(atomic_fetch_add(&f->seen[seq], 1) == 0);
    (void)atomic_fetch_add(&f->calls, 1);
    if (f->hold_first && seq == 1) {
        meet(&f->entered);
        meet(&f->release);
        CHECK(view.data[0] == 1 && view.data[2] == 255);
    }
    errno = EILSEQ;
    return f->execution_error;
}

/**
 * @brief
 *     初始化拒绝不获取资源，零脚本执行真实 POSIX 初始化。
 *
 * @param[in,out] context
 *     管理端独占脚本。
 * @param[out] mutex
 *     未初始化存储，仅零返回后有效。
 *
 * @return
 *     直接错误或实际初始化结果，不冒真实系统耗尽。
 */
static int init_mutex(void *context, pthread_mutex_t *mutex) {
    shutdown_fixture_t *f = context;
    return f->init_error != 0 ? f->init_error : pthread_mutex_init(mutex, NULL);
}

/**
 * @brief
 *     成功创建真实 joinable worker，指定拒绝不留下线程。
 *
 * @param[in,out] context
 *     管理脚本，不由 worker 访问。
 * @param[out] thread
 *     仅成功时为有效句柄。
 * @param[in] entry
 *     实际 worker 入口。
 * @param[in] argument
 *     稳定槽地址，借到线程结束。
 *
 * @return
 *     0、定点 EAGAIN 或真实直接错误。
 */
static int create_worker(void *context, pthread_t *thread, void *(*entry)(void *), void *argument) {
    shutdown_fixture_t *f = context;
    ++f->create_calls;
    return f->create_calls == f->fail_create_at ? EAGAIN : pthread_create(thread, NULL, entry, argument);
}

/**
 * @brief
 *     拒绝时保留有效未 join 句柄，成功实际回收，不重复消费。
 *
 * @param[in,out] context
 *     串行管理脚本；尝试账本原子供观察者读取。
 * @param[in] thread
 *     已创建、尚未成功 join 的真实句柄。
 *
 * @return
 *     局部 EBUSY 或真实 join 结果，不代表损坏同步恢复。
 */
static int join_worker(void *context, pthread_t thread) {
    shutdown_fixture_t *f = context;
    (void)atomic_fetch_add(&f->join_calls, 1);
    errno = ENOSPC;
    if (f->join_failures != 0) { --f->join_failures; return EBUSY; }
    return pthread_join(thread, NULL);
}

/**
 * @brief
 *     原观测错误不产出快照，正常只调用公开 inspect。
 *
 * @param[in,out] context
 *     管理线程独占脚本，不与池管理并发修改。
 * @param[in] queue
 *     存活公开队列，只借本次。
 * @param[out] info
 *     仅 OK 发布的原六字段输出。
 *
 * @return
 *     脚本原结果或公开结果，故意扰动 errno 验证外层保持。
 */
static vireo_result_t inspect_queue(void *context, vireo_task_queue_t const *queue,
    vireo_task_queue_info_t *info) {
    shutdown_fixture_t *f = context;
    errno = ENOSPC;
    return f->inspect_error != VIREO_OK ? f->inspect_error : vireo_task_queue_inspect(queue, info);
}

/**
 * @brief
 *     一次拒绝不消耗 mutex，移除脚本后真实销毁。
 *
 * @param[in,out] context
 *     全部 join 后管理端独占的一次脚本。
 * @param[in,out] mutex
 *     实际有效的同步对象，只有零返回才消费。
 *
 * @return
 *     指定直接错误或真实销毁结果。
 */
static int destroy_mutex(void *context, pthread_mutex_t *mutex) {
    shutdown_fixture_t *f = context;
    int const error = f->destroy_error;
    f->destroy_error = 0;
    return error != 0 ? error : pthread_mutex_destroy(mutex);
}

/**
 * @brief
 *     有限原错模型或一次真实公开关闭后报告异常，不改变依赖私有状态。
 *
 * @param[in,out] context
 *     本管理调用短借脚本。
 * @param[in,out] queue
 *     存活公开队列，真实操作只走其 public API。
 * @param[in] mode
 *     已核实的合法永久关闭策略。
 * @param[out] report
 *     原三字段关闭事实，提交后错误仍 changed=true。
 *
 * @return
 *     原结果或局部 INTERNAL；模型不损坏实际锁或唤醒。
 */
static vireo_result_t close_queue(void *context, vireo_task_queue_t *queue,
    vireo_task_queue_state_t mode, vireo_task_queue_close_report_t *report) {
    close_trace_t *trace = context;
    ++trace->calls;
    errno = ENOSPC;
    if (trace->mode == 1) {
        *report = (vireo_task_queue_close_report_t){trace->stage, false, trace->pthread_error};
        return trace->result;
    }
    vireo_result_t const result = vireo_task_queue_close(queue, mode, report);
    if (result == VIREO_OK && (trace->mode == 2 || trace->mode == 3)) {
        *report = (vireo_task_queue_close_report_t){trace->mode == 2 ?
            VIREO_TASK_QUEUE_STAGE_WAKE : VIREO_TASK_QUEUE_STAGE_UNLOCK, true, EIO};
        return VIREO_RESULT_INTERNAL;
    }
    return result;
}

/**
 * @brief
 *     在稳定地址构造独立资源、完整原子与两方屏障，不启动线程。
 *
 * @param[out] f
 *     存活到 finish 的 fixture，不允许按值移动。
 * @param[in] workers
 *     本场景显式正 worker 数。
 * @param[in] capacity
 *     本场景显式正队列容量。
 *
 * @note
 *     资源申请/prepare/configure 无并发访问，context 均只借用。
 */
static void prepare(shutdown_fixture_t *f, size_t workers, size_t capacity) {
    f->pool = NULL; f->queue = NULL;
    f->runtime = *vireo_thread_pool_standard_runtime(); f->runtime.context = f;
    f->runtime.mutex_init = init_mutex; f->runtime.thread_create = create_worker;
    f->runtime.thread_join = join_worker; f->runtime.inspect_queue = inspect_queue;
    f->runtime.mutex_destroy = destroy_mutex;
    for (size_t i = 0; i < TASK_LIMIT; ++i) { atomic_init(&f->seen[i], 0); }
    atomic_init(&f->calls, 0); atomic_init(&f->join_calls, 0);
    f->hold_first = false; f->execution_error = VIREO_OK; f->init_error = 0;
    f->create_calls = 0; f->fail_create_at = 0; f->join_failures = 0;
    f->inspect_error = VIREO_OK; f->destroy_error = 0;
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
 *     实际启动再放行，全部策略已稳定，不在资格检查期间访问队列。
 *
 * @param[in,out] f
 *     已配置的存活 fixture。
 *
 * @note
 *     管理调用线程已经禁用 POSIX 取消，不重试启动错误。
 */
static void start(shutdown_fixture_t *f) {
    vireo_thread_pool_report_t report;
    CHECK(vireo_thread_pool_start_with_runtime(f->pool, &f->runtime, &report) == VIREO_OK);
    CHECK(vireo_thread_pool_enable_execution(f->pool, &report) == VIREO_OK);
}

/**
 * @brief
 *     构造真实独立 payload，复制后破坏源验证不借 caller 字节。
 *
 * @param[in] sequence
 *     本场景 1..63 数值身份。
 * @param[in] cancel
 *     可空独立强引用，构造按公开合同 retain。
 *
 * @return
 *     caller 唯一 task owner，提交成功后不得访问旧别名。
 */
static vireo_task_t *make_task(uint32_t sequence, vireo_task_cancel_t *cancel) {
    vireo_task_route_t route;
    vireo_task_metadata_t metadata;
    vireo_task_t *task = NULL;
    unsigned char bytes[] = {(unsigned char)sequence, 0, 255};
    CHECK(vireo_task_route_make(1, 0, 1, sequence, &route) == VIREO_OK);
    CHECK(vireo_task_metadata_make(route, sequence, 8, 0, &metadata) == VIREO_OK);
    if (cancel == NULL) { CHECK(vireo_task_create_copy(metadata, bytes, sizeof bytes, 4096, &task) == VIREO_OK); }
    else { CHECK(vireo_task_create_copy_with_cancel(metadata, bytes, sizeof bytes, 4096, cancel, &task) == VIREO_OK); }
    memset(bytes, 17, sizeof bytes);
    return task;
}

/**
 * @brief
 *     caller 只显式有界处理锁竞争，不把重试藏进产品。
 *
 * @param[in,out] f
 *     已放行的存活池。
 * @param[in,out] owner
 *     caller 独占非空任务，成功清源。
 *
 * @note
 *     真满或关闭不重试，非 OK 已转移也不重试或重复清理。
 */
static void push_task(shutdown_fixture_t *f, vireo_task_t **owner) {
    for (size_t i = 0; i < ATTEMPT_LIMIT; ++i) {
        vireo_thread_pool_submit_report_t report;
        vireo_result_t const result = vireo_thread_pool_try_submit(f->pool, owner, &report);
        if (result == VIREO_RESULT_BUSY && report.queue_called &&
            report.queue_report.stage == VIREO_TASK_QUEUE_STAGE_LOCK &&
            report.queue_report.pthread_error == EBUSY && !report.queue_report.transferred) {
            CHECK(sched_yield() == 0); continue;
        }
        CHECK(result == VIREO_OK && *owner == NULL && report.queue_report.transferred);
        return;
    }
    CHECK(false);
}

/**
 * @brief
 *     caller 有界处理两段已知观测竞争，保留最后实际报告。
 *
 * @param[in,out] f
 *     管理线程独占池管理，worker 可并发领取。
 * @param[in] mode
 *     稳定的 DRAIN 或 CANCEL_PENDING。
 * @param[out] report
 *     独立本场景最后一次调用报告。
 *
 * @return
 *     第一次非竞争原结果，不重试模式冲突/同步损坏/业务或 join 原错。
 */
static vireo_result_t shutdown_uncontended(shutdown_fixture_t *f, vireo_task_queue_state_t mode,
    vireo_thread_pool_shutdown_report_t *report) {
    for (size_t i = 0; i < ATTEMPT_LIMIT; ++i) {
        vireo_result_t const result = vireo_thread_pool_shutdown_and_join(f->pool, mode, report);
        bool const close_busy = report->stage == VIREO_THREAD_POOL_SHUTDOWN_STAGE_CLOSE_QUEUE &&
            report->close_report.stage == VIREO_TASK_QUEUE_STAGE_LOCK && report->close_report.pthread_error == EBUSY;
        bool const inspect_busy = report->stage == VIREO_THREAD_POOL_SHUTDOWN_STAGE_JOIN_WORKERS &&
            report->pool_report.stage == VIREO_THREAD_POOL_STAGE_CHECK_QUEUE;
        if (result == VIREO_RESULT_BUSY && (close_busy || inspect_busy)) {
            CHECK(sched_yield() == 0); continue;
        }
        return result;
    }
    CHECK(false);
    return VIREO_RESULT_INTERNAL;
}

/**
 * @brief
 *     公开数值观察可短暂竞争，caller 有界显式重试。
 *
 * @param[in] queue
 *     存活队列，不与销毁并发。
 *
 * @return
 *     成功的独立六字段值，不返回依赖内部地址。
 */
static vireo_task_queue_info_t queue_info(vireo_task_queue_t const *queue) {
    for (size_t i = 0; i < ATTEMPT_LIMIT; ++i) {
        vireo_task_queue_info_t info;
        vireo_result_t const result = vireo_task_queue_inspect(queue, &info);
        if (result == VIREO_RESULT_BUSY) { CHECK(sched_yield() == 0); continue; }
        CHECK(result == VIREO_OK); return info;
    }
    CHECK(false);
    return (vireo_task_queue_info_t){0};
}

/**
 * @brief
 *     全部 worker/管理线程 join、pending 显式清理之后配对释放。
 *
 * @param[in,out] f
 *     无并发访问的 fixture，允许 pool 已提前销毁。
 *
 * @note
 *     queue 非空直接失败，不在 helper 内偷偷取回任务。
 */
static void finish(shutdown_fixture_t *f) {
    CHECK(vireo_thread_pool_destroy(&f->pool) == VIREO_OK);
    CHECK(vireo_task_queue_destroy(&f->queue) == VIREO_OK);
    CHECK(pthread_barrier_destroy(&f->entered) == 0);
    CHECK(pthread_barrier_destroy(&f->release) == 0);
}

/* 只比较逻辑字段，零报告不是 ABI/padding 承诺，也不当实际运行快照。 */
static void no_join(vireo_thread_pool_shutdown_report_t const *report) {
    vireo_thread_pool_report_t const *p = &report->pool_report;
    CHECK(!report->join_called && p->stage == VIREO_THREAD_POOL_STAGE_NONE && p->pthread_error == 0);
    CHECK(!p->start_attempted && !p->stop_requested && p->created_count == 0 && p->joined_count == 0);
    CHECK(p->cleanup_result == VIREO_OK && p->cleanup_stage == VIREO_THREAD_POOL_STAGE_NONE && p->cleanup_pthread_error == 0);
    CHECK(!p->execution_enabled && p->queue_report.stage == VIREO_TASK_QUEUE_STAGE_NONE &&
          !p->queue_report.transferred && p->queue_report.pthread_error == 0);
}
static void no_close(vireo_thread_pool_shutdown_report_t const *report,
    vireo_thread_pool_shutdown_stage_t stage) {
    CHECK(report->stage == stage && !report->close_called);
    CHECK(report->close_report.stage == VIREO_TASK_QUEUE_STAGE_NONE &&
          !report->close_report.changed && report->close_report.pthread_error == 0);
    no_join(report);
}

/* 必需输出/非法模式优先资格，毒值报告必须被全部逻辑字段覆盖。 */
static void test_basic(void) {
    shutdown_fixture_t f; prepare(&f, 1, 1);
    vireo_thread_pool_shutdown_report_t report;
    vireo_task_queue_state_t const modes[] = {VIREO_TASK_QUEUE_OPEN, (vireo_task_queue_state_t)-1, (vireo_task_queue_state_t)99};
    memset(&report, 0xa5, sizeof report); errno = EDOM;
    CHECK(vireo_thread_pool_shutdown_and_join(NULL, VIREO_TASK_QUEUE_DRAIN, &report) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(errno == EDOM); no_close(&report, VIREO_THREAD_POOL_SHUTDOWN_STAGE_NONE);
    CHECK(vireo_thread_pool_shutdown_and_join(f.pool, VIREO_TASK_QUEUE_DRAIN, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(errno == EDOM);
    for (size_t i = 0; i < sizeof modes / sizeof modes[0]; ++i) {
        memset(&report, 0xa5, sizeof report);
        CHECK(vireo_thread_pool_shutdown_and_join(f.pool, modes[i], &report) == VIREO_RESULT_INVALID_ARGUMENT);
        no_close(&report, VIREO_THREAD_POOL_SHUTDOWN_STAGE_NONE); CHECK(errno == EDOM);
    }
    vireo_thread_pool_queue_closer_t const missing = {NULL, NULL};
    CHECK(vireo_thread_pool_shutdown_and_join_with_closer(f.pool, VIREO_TASK_QUEUE_DRAIN, NULL, &report) == VIREO_RESULT_INVALID_ARGUMENT);
    no_close(&report, VIREO_THREAD_POOL_SHUTDOWN_STAGE_NONE);
    CHECK(vireo_thread_pool_shutdown_and_join_with_closer(f.pool, VIREO_TASK_QUEUE_DRAIN, &missing, &report) == VIREO_RESULT_INVALID_ARGUMENT);
    no_close(&report, VIREO_THREAD_POOL_SHUTDOWN_STAGE_NONE); CHECK(errno == EDOM);
    CHECK(queue_info(f.queue).state == VIREO_TASK_QUEUE_OPEN && atomic_load(&f.join_calls) == 0);
    finish(&f);
}

/* 只真实构造不同生命周期，不修改候选私有布局伪造资格。 */
static void test_admission(void) {
    vireo_thread_pool_t *unconfigured = NULL;
    vireo_thread_pool_options_t const options = {1, 4096};
    vireo_thread_pool_shutdown_report_t report;
    CHECK(vireo_thread_pool_create(&options, &unconfigured) == VIREO_OK);
    errno = EDOM;
    CHECK(vireo_thread_pool_shutdown_and_join(unconfigured, VIREO_TASK_QUEUE_DRAIN, &report) == VIREO_RESULT_NOT_FOUND);
    no_close(&report, VIREO_THREAD_POOL_SHUTDOWN_STAGE_CHECK_POOL); CHECK(errno == EDOM);
    CHECK(vireo_thread_pool_destroy(&unconfigured) == VIREO_OK);
    for (int scenario = 0; scenario < 4; ++scenario) {
        shutdown_fixture_t f; prepare(&f, scenario == 3 ? 3 : 1, 1);
        close_trace_t trace = {0, 0, VIREO_OK, VIREO_TASK_QUEUE_STAGE_NONE, 0};
        vireo_thread_pool_queue_closer_t const closer = {&trace, close_queue};
        vireo_thread_pool_report_t management;
        if (scenario == 1) { CHECK(vireo_thread_pool_start_with_runtime(f.pool, &f.runtime, &management) == VIREO_OK); }
        if (scenario == 2) { f.init_error = ENOMEM; CHECK(vireo_thread_pool_start_with_runtime(f.pool, &f.runtime, &management) == VIREO_RESULT_NO_MEMORY); }
        if (scenario == 3) {
            f.fail_create_at = 2;
            CHECK(vireo_thread_pool_start_with_runtime(f.pool, &f.runtime, &management) == VIREO_RESULT_NO_MEMORY);
            CHECK(management.created_count == 1 && management.joined_count == 1 && management.stop_requested);
        }
        errno = EDOM; memset(&report, 0xa5, sizeof report);
        CHECK(vireo_thread_pool_shutdown_and_join_with_closer(f.pool, VIREO_TASK_QUEUE_DRAIN, &closer, &report) ==
              (scenario == 0 ? VIREO_RESULT_NOT_FOUND : VIREO_RESULT_BUSY));
        no_close(&report, VIREO_THREAD_POOL_SHUTDOWN_STAGE_CHECK_POOL);
        CHECK(trace.calls == 0 && errno == EDOM && queue_info(f.queue).state == VIREO_TASK_QUEUE_OPEN);
        if (scenario != 0) { CHECK(vireo_thread_pool_stop_and_join(f.pool, &management) == VIREO_OK); }
        finish(&f);
    }
}

/* 真实1/3/7 worker 各31独立任务，无遗漏或重复；关闭/回收报告可独立保留。 */
static void test_drain(void) {
    size_t const workers[] = {1, 3, 7};
    for (size_t w = 0; w < sizeof workers / sizeof workers[0]; ++w) {
        shutdown_fixture_t f; prepare(&f, workers[w], 31); start(&f);
        for (uint32_t i = 1; i <= 31; ++i) { vireo_task_t *task = make_task(i, NULL); push_task(&f, &task); }
        vireo_thread_pool_shutdown_report_t report; errno = EDOM;
        CHECK(shutdown_uncontended(&f, VIREO_TASK_QUEUE_DRAIN, &report) == VIREO_OK);
        CHECK(errno == EDOM && report.stage == VIREO_THREAD_POOL_SHUTDOWN_STAGE_NONE && report.close_called && report.join_called);
        CHECK(report.pool_report.created_count == workers[w] && report.pool_report.joined_count == workers[w]);
        CHECK(report.pool_report.start_attempted && report.pool_report.stop_requested && report.pool_report.execution_enabled);
        CHECK(atomic_load(&f.join_calls) == workers[w] && atomic_load(&f.calls) == 31);
        for (size_t i = 1; i <= 31; ++i) { CHECK(atomic_load(&f.seen[i]) == 1); }
        CHECK(queue_info(f.queue).state == VIREO_TASK_QUEUE_DRAIN && queue_info(f.queue).count == 0);
        vireo_thread_pool_shutdown_report_t const saved = report;
        CHECK(vireo_thread_pool_shutdown_and_join(f.pool, VIREO_TASK_QUEUE_DRAIN, &report) == VIREO_OK);
        CHECK(!report.close_report.changed && report.join_called && report.pool_report.joined_count == workers[w]);
        CHECK(atomic_load(&f.join_calls) == workers[w]);
        CHECK(vireo_thread_pool_shutdown_and_join(f.pool, VIREO_TASK_QUEUE_CANCEL_PENDING, &report) == VIREO_RESULT_BUSY);
        CHECK(report.close_called && report.stage == VIREO_THREAD_POOL_SHUTDOWN_STAGE_CLOSE_QUEUE && !report.close_report.changed);
        no_join(&report);
        vireo_task_t *rejected = make_task(32, NULL); vireo_task_t *original = rejected;
        vireo_thread_pool_submit_report_t submit;
        CHECK(vireo_thread_pool_try_submit(f.pool, &rejected, &submit) == VIREO_RESULT_CANCELLED);
        CHECK(rejected == original && !submit.queue_called);
        CHECK(vireo_task_destroy(&rejected) == VIREO_OK);
        finish(&f);
        CHECK(saved.pool_report.joined_count == workers[w] && saved.close_called && saved.join_called);
    }
}

/**
 * @brief
 *     专用管理线程禁用 POSIX 取消，调用结束后发布完成事实。
 *
 * @param[in,out] argument
 *     稳定 job，主线程成功 join 后才读取非原子结果。
 *
 * @return
 *     NULL；不从此线程执行任务或并发调用其他池管理。
 */
static void *run_shutdown(void *argument) {
    shutdown_job_t *job = argument;
    int old_cancel = 0;
    CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &old_cancel) == 0);
    errno = EDOM;
    job->result = shutdown_uncontended(job->fixture, job->mode, &job->report);
    job->errno_held = errno == EDOM;
    atomic_store(&job->finished, true);
    CHECK(pthread_setcancelstate(old_cancel, NULL) == 0);
    return NULL;
}

/* 两种模式在同一真实在途点区别：CP保pending/cancel=false，DRAIN继续执行。 */
static void test_inflight_modes(void) {
    vireo_task_queue_state_t const modes[] = {VIREO_TASK_QUEUE_DRAIN, VIREO_TASK_QUEUE_CANCEL_PENDING};
    for (size_t m = 0; m < sizeof modes / sizeof modes[0]; ++m) {
        shutdown_fixture_t f; prepare(&f, 1, 2); f.hold_first = true; start(&f);
        vireo_task_t *task = make_task(1, NULL); push_task(&f, &task); meet(&f.entered);
        vireo_task_cancel_t *cancel = NULL;
        CHECK(vireo_task_cancel_create(4096, &cancel) == VIREO_OK);
        task = make_task(2, cancel); push_task(&f, &task);
        shutdown_job_t job;
        job.fixture = &f; job.mode = modes[m]; job.result = VIREO_RESULT_INTERNAL;
        job.report = (vireo_thread_pool_shutdown_report_t){0}; job.errno_held = false;
        atomic_init(&job.finished, false);
        pthread_t manager;
        CHECK(pthread_create(&manager, NULL, run_shutdown, &job) == 0);
        bool closed = false;
        for (size_t i = 0; i < ATTEMPT_LIMIT; ++i) {
            vireo_task_queue_info_t const info = queue_info(f.queue);
            if (info.state == modes[m]) { CHECK(info.count == 1); closed = true; break; }
            CHECK(sched_yield() == 0);
        }
        CHECK(closed && !atomic_load(&job.finished) && atomic_load(&f.calls) == 1);
        meet(&f.release);
        CHECK(pthread_join(manager, NULL) == 0);
        CHECK(job.result == VIREO_OK && job.errno_held && atomic_load(&job.finished));
        CHECK(job.report.close_called && job.report.join_called && job.report.pool_report.joined_count == 1);
        vireo_thread_pool_shutdown_report_t repeated;
        CHECK(vireo_thread_pool_shutdown_and_join(f.pool, modes[m], &repeated) == VIREO_OK);
        CHECK(!repeated.close_report.changed && repeated.join_called && repeated.pool_report.joined_count == 1);
        CHECK(atomic_load(&f.join_calls) == 1);
        CHECK(vireo_thread_pool_shutdown_and_join(f.pool, modes[m] == VIREO_TASK_QUEUE_DRAIN ?
            VIREO_TASK_QUEUE_CANCEL_PENDING : VIREO_TASK_QUEUE_DRAIN, &repeated) == VIREO_RESULT_BUSY);
        CHECK(repeated.close_called && repeated.stage == VIREO_THREAD_POOL_SHUTDOWN_STAGE_CLOSE_QUEUE);
        no_join(&repeated);
        CHECK(vireo_thread_pool_destroy(&f.pool) == VIREO_OK);
        if (modes[m] == VIREO_TASK_QUEUE_CANCEL_PENDING) {
            CHECK(atomic_load(&f.calls) == 1 && atomic_load(&f.seen[2]) == 0);
            CHECK(vireo_task_queue_destroy(&f.queue) == VIREO_RESULT_BUSY && f.queue != NULL);
            vireo_task_queue_transfer_report_t transfer;
            CHECK(vireo_task_queue_try_take_cancelled(f.queue, &task, &transfer) == VIREO_OK && transfer.transferred);
            vireo_task_payload_view_t view; bool requested = true;
            CHECK(vireo_task_borrow_payload(task, &view) == VIREO_OK && view.size == 3 && view.data[0] == 2);
            CHECK(vireo_task_is_cancel_requested(task, &requested) == VIREO_OK && !requested);
            CHECK(vireo_task_destroy(&task) == VIREO_OK);
            CHECK(vireo_task_queue_try_take_cancelled(f.queue, &task, &transfer) == VIREO_RESULT_NOT_FOUND && task == NULL);
        } else { CHECK(atomic_load(&f.calls) == 2 && atomic_load(&f.seen[2]) == 1); }
        bool requested = true;
        CHECK(vireo_task_cancel_is_requested(cancel, &requested) == VIREO_OK && !requested);
        CHECK(vireo_task_cancel_destroy(&cancel) == VIREO_OK);
        finish(&f);
    }
}

/* 未关闭脚本逐原错透传，一次适配、不join、不偷偷变模式。 */
static void test_close_errors(void) {
    shutdown_fixture_t f; prepare(&f, 1, 1); start(&f);
    vireo_result_t const errors[] = {VIREO_RESULT_BUSY, VIREO_RESULT_INTERNAL, VIREO_RESULT_IO,
        VIREO_RESULT_OVERFLOW, VIREO_RESULT_NOT_FOUND};
    for (size_t i = 0; i < sizeof errors / sizeof errors[0]; ++i) {
        close_trace_t trace = {0, 1, errors[i], VIREO_TASK_QUEUE_STAGE_LOCK, EIO};
        vireo_thread_pool_queue_closer_t const closer = {&trace, close_queue};
        vireo_thread_pool_shutdown_report_t report; memset(&report, 0xa5, sizeof report); errno = EDOM;
        CHECK(vireo_thread_pool_shutdown_and_join_with_closer(f.pool, VIREO_TASK_QUEUE_DRAIN, &closer, &report) == errors[i]);
        CHECK(errno == EDOM && trace.calls == 1 && report.close_called && report.stage == VIREO_THREAD_POOL_SHUTDOWN_STAGE_CLOSE_QUEUE);
        CHECK(report.close_report.stage == VIREO_TASK_QUEUE_STAGE_LOCK && report.close_report.pthread_error == EIO && !report.close_report.changed);
        no_join(&report); CHECK(atomic_load(&f.join_calls) == 0 && queue_info(f.queue).state == VIREO_TASK_QUEUE_OPEN);
    }
    vireo_thread_pool_shutdown_report_t report;
    CHECK(shutdown_uncontended(&f, VIREO_TASK_QUEUE_DRAIN, &report) == VIREO_OK);
    close_trace_t trace = {0, 0, VIREO_OK, VIREO_TASK_QUEUE_STAGE_NONE, 0};
    vireo_thread_pool_queue_closer_t const closer = {&trace, close_queue};
    CHECK(vireo_thread_pool_shutdown_and_join_with_closer(f.pool, VIREO_TASK_QUEUE_DRAIN, &closer, &report) == VIREO_OK);
    CHECK(trace.calls == 1 && report.close_called && !report.close_report.changed && report.join_called &&
          report.stage == VIREO_THREAD_POOL_SHUTDOWN_STAGE_NONE && report.pool_report.joined_count == 1);
    finish(&f);
}

/* 实际关闭已提交后报WAKE/UNLOCK模型，必须不触原stop/join，即使changed=true。 */
static void test_close_committed_error(void) {
    for (int mode = 2; mode <= 3; ++mode) {
        shutdown_fixture_t f; prepare(&f, 1, 2); f.hold_first = true; start(&f);
        vireo_task_t *task = make_task(1, NULL); push_task(&f, &task); meet(&f.entered);
        task = make_task(2, NULL); push_task(&f, &task);
        close_trace_t trace = {0, mode, VIREO_OK, VIREO_TASK_QUEUE_STAGE_NONE, 0};
        vireo_thread_pool_queue_closer_t const closer = {&trace, close_queue};
        vireo_thread_pool_shutdown_report_t report; memset(&report, 0xa5, sizeof report); errno = EDOM;
        CHECK(vireo_thread_pool_shutdown_and_join_with_closer(f.pool, VIREO_TASK_QUEUE_DRAIN, &closer, &report) == VIREO_RESULT_INTERNAL);
        CHECK(errno == EDOM && trace.calls == 1 && report.close_called && report.close_report.changed);
        CHECK(report.stage == VIREO_THREAD_POOL_SHUTDOWN_STAGE_CLOSE_QUEUE && report.close_report.pthread_error == EIO);
        CHECK(report.close_report.stage == (mode == 2 ? VIREO_TASK_QUEUE_STAGE_WAKE : VIREO_TASK_QUEUE_STAGE_UNLOCK));
        no_join(&report); CHECK(atomic_load(&f.join_calls) == 0);
        vireo_thread_pool_info_t info;
        CHECK(vireo_thread_pool_inspect(f.pool, &info) == VIREO_OK && !info.stop_requested && info.joined_count == 0);
        CHECK(queue_info(f.queue).state == VIREO_TASK_QUEUE_DRAIN && queue_info(f.queue).count == 1);
        vireo_thread_pool_shutdown_report_t const saved = report;
        meet(&f.release);
        CHECK(shutdown_uncontended(&f, VIREO_TASK_QUEUE_DRAIN, &report) == VIREO_OK);
        CHECK(!report.close_report.changed && report.pool_report.joined_count == 1 && atomic_load(&f.calls) == 2);
        finish(&f);
        CHECK(saved.close_report.changed && !saved.join_called && saved.close_report.pthread_error == EIO);
    }
}

/* 关闭成功但后段观测原错保两段事实，换模式仍BUSY，同模式显式再收尾。 */
static void test_join_dependency_error(void) {
    shutdown_fixture_t f; prepare(&f, 1, 1); start(&f); f.inspect_error = VIREO_RESULT_IO;
    vireo_thread_pool_shutdown_report_t report; errno = EDOM;
    CHECK(shutdown_uncontended(&f, VIREO_TASK_QUEUE_DRAIN, &report) == VIREO_RESULT_IO);
    CHECK(errno == EDOM && report.close_called && report.join_called && report.stage == VIREO_THREAD_POOL_SHUTDOWN_STAGE_JOIN_WORKERS);
    CHECK(report.close_report.stage == VIREO_TASK_QUEUE_STAGE_NONE && report.close_report.pthread_error == 0);
    CHECK(report.pool_report.stage == VIREO_THREAD_POOL_STAGE_CHECK_QUEUE && report.pool_report.start_attempted &&
          report.pool_report.execution_enabled && report.pool_report.created_count == 1 && report.pool_report.joined_count == 0 && !report.pool_report.stop_requested);
    CHECK(atomic_load(&f.join_calls) == 0 && queue_info(f.queue).state == VIREO_TASK_QUEUE_DRAIN);
    vireo_thread_pool_shutdown_report_t const saved = report;
    f.inspect_error = VIREO_OK;
    CHECK(shutdown_uncontended(&f, VIREO_TASK_QUEUE_CANCEL_PENDING, &report) == VIREO_RESULT_BUSY);
    CHECK(report.close_called && !report.close_report.changed && report.stage == VIREO_THREAD_POOL_SHUTDOWN_STAGE_CLOSE_QUEUE);
    no_join(&report);
    CHECK(shutdown_uncontended(&f, VIREO_TASK_QUEUE_DRAIN, &report) == VIREO_OK && !report.close_report.changed);
    finish(&f); CHECK(saved.pool_report.joined_count == 0 && saved.join_called);
}

/* 一句柄不消费的拒绝，其余真实join成功；后续仅再尝试剩余项。 */
static void test_partial_join(void) {
    shutdown_fixture_t f; prepare(&f, 3, 1); start(&f); f.join_failures = 1;
    vireo_thread_pool_shutdown_report_t report; errno = EDOM;
    CHECK(shutdown_uncontended(&f, VIREO_TASK_QUEUE_DRAIN, &report) == VIREO_RESULT_INTERNAL);
    CHECK(errno == EDOM && report.stage == VIREO_THREAD_POOL_SHUTDOWN_STAGE_JOIN_WORKERS && report.close_called && report.join_called);
    CHECK(report.pool_report.stage == VIREO_THREAD_POOL_STAGE_JOIN_WORKER && report.pool_report.pthread_error == EBUSY);
    CHECK(report.pool_report.stop_requested && report.pool_report.created_count == 3 && report.pool_report.joined_count == 2);
    CHECK(atomic_load(&f.join_calls) == 3);
    vireo_thread_pool_t *original = f.pool;
    CHECK(vireo_thread_pool_destroy(&f.pool) == VIREO_RESULT_BUSY && f.pool == original);
    vireo_thread_pool_shutdown_report_t const saved = report;
    CHECK(shutdown_uncontended(&f, VIREO_TASK_QUEUE_DRAIN, &report) == VIREO_OK);
    CHECK(!report.close_report.changed && report.pool_report.joined_count == 3 && atomic_load(&f.join_calls) == 4);
    CHECK(vireo_thread_pool_shutdown_and_join(f.pool, VIREO_TASK_QUEUE_DRAIN, &report) == VIREO_OK && atomic_load(&f.join_calls) == 4);
    finish(&f); CHECK(saved.pool_report.joined_count == 2 && saved.pool_report.pthread_error == EBUSY);
}

/* 原业务首错不回滚完整回收；重复收尾OK，join后历史首错仍可查询。 */
static void test_worker_error(void) {
    shutdown_fixture_t f; prepare(&f, 1, 2); f.execution_error = VIREO_RESULT_DATABASE; start(&f);
    for (uint32_t i = 1; i <= 2; ++i) { vireo_task_t *task = make_task(i, NULL); push_task(&f, &task); }
    vireo_thread_pool_shutdown_report_t report; errno = EDOM;
    CHECK(shutdown_uncontended(&f, VIREO_TASK_QUEUE_DRAIN, &report) == VIREO_RESULT_DATABASE);
    CHECK(errno == EDOM && report.join_called && report.close_called && report.stage == VIREO_THREAD_POOL_SHUTDOWN_STAGE_JOIN_WORKERS);
    CHECK(report.pool_report.stage == VIREO_THREAD_POOL_STAGE_EXECUTE_TASK && report.pool_report.pthread_error == 0 && report.pool_report.joined_count == 1);
    CHECK(atomic_load(&f.calls) == 2 && atomic_load(&f.seen[1]) == 1 && atomic_load(&f.seen[2]) == 1);
    vireo_thread_pool_worker_result_t worker;
    CHECK(vireo_thread_pool_inspect_worker_result(f.pool, 0, &worker) == VIREO_OK && worker.result == VIREO_RESULT_DATABASE);
    CHECK(vireo_thread_pool_shutdown_and_join(f.pool, VIREO_TASK_QUEUE_DRAIN, &report) == VIREO_OK && report.pool_report.joined_count == 1);
    CHECK(vireo_thread_pool_inspect_worker_result(f.pool, 0, &worker) == VIREO_OK && worker.result == VIREO_RESULT_DATABASE);
    finish(&f);
}

/* 真实cond已消费/mutex尚有效，retiring先于普通资格；只重试destroy，不触queue。 */
static void test_retiring(void) {
    shutdown_fixture_t f; prepare(&f, 1, 1); start(&f);
    vireo_thread_pool_shutdown_report_t report;
    CHECK(shutdown_uncontended(&f, VIREO_TASK_QUEUE_DRAIN, &report) == VIREO_OK);
    f.destroy_error = EBUSY;
    CHECK(vireo_thread_pool_destroy(&f.pool) == VIREO_RESULT_BUSY && f.pool != NULL);
    close_trace_t trace = {0, 0, VIREO_OK, VIREO_TASK_QUEUE_STAGE_NONE, 0};
    vireo_thread_pool_queue_closer_t const closer = {&trace, close_queue};
    memset(&report, 0xa5, sizeof report); errno = EDOM;
    CHECK(vireo_thread_pool_shutdown_and_join_with_closer(f.pool, VIREO_TASK_QUEUE_DRAIN, &closer, &report) == VIREO_RESULT_CANCELLED);
    CHECK(errno == EDOM && trace.calls == 0); no_close(&report, VIREO_THREAD_POOL_SHUTDOWN_STAGE_CHECK_POOL);
    CHECK(vireo_thread_pool_shutdown_and_join(f.pool, VIREO_TASK_QUEUE_OPEN, &report) == VIREO_RESULT_INVALID_ARGUMENT);
    no_close(&report, VIREO_THREAD_POOL_SHUTDOWN_STAGE_NONE);
    finish(&f);
}

int main(void) {
    int old_cancel = 0;
    CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &old_cancel) == 0);
    test_basic(); test_admission(); test_drain(); test_inflight_modes(); test_close_errors();
    test_close_committed_error(); test_join_dependency_error(); test_partial_join(); test_worker_error(); test_retiring();
    CHECK(pthread_setcancelstate(old_cancel, NULL) == 0);
    puts("test_thread_pool_shutdown: 10 groups passed");
    return 0;
}
