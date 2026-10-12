/*
 * PROJECT : VIREO
 * FILE    : test_notifier_queue_cooperation.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-13
 * BRIEF   : 公开结果交接后提示、失败归属与真实消费/join收尾
 */
#define _POSIX_C_SOURCE 200809L
#include "thread/notifier_internal.h"
#include <vireo/thread/completion_queue.h>
#include <vireo/thread/thread_pool.h>

#include <dirent.h>
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #x); abort(); } } while (0)
#define EXPECT(x, wanted) do { errno = EDOM; vireo_result_t const got = (x); CHECK(got == (wanted) && errno == EDOM); } while (0)
#define RETRY_LIMIT 1000000U
#define MAX_REQUESTS 32U
#define PAYLOAD_SALT UINT64_C(0x238fa57201bced49)

/** 本核心注入环境；错误策略发布前固定，跨 worker 调用数只原子访问。 */
typedef struct io_fault {
    int fd; /**< 创建时写，之后只读的测试 oracle 数值，不产生第二 owner。 */
    int read_error; /**< 0 原生读，非零一次 -1/该 errno；并发期间不改。 */
    int write_error; /**< 0 原生写，非零一次 -1/该 errno；并发期间不改。 */
    atomic_size_t reads; /**< 实际进入 read seam 的次数，不等于消费条数。 */
    atomic_size_t writes; /**< 实际进入 write seam 的次数，包含注入失败。 */
} io_fault_t;

/** 配置地址借到 pool 销毁，固定资源地址只读，共享进度只用原子。 */
typedef struct run_context {
    vireo_completion_queue_t *outputs; /**< 借用结果队列，全部 worker 结束前存活。 */
    vireo_notifier_t *notifier; /**< 借用提示资源，全部 notify/consume/poll 结束前存活。 */
    atomic_bool release; /**< 测试门控；不代表生产取消或完成状态。 */
    atomic_size_t started; /**< 已进入 callback 的次数，不证明 cond_wait 已进入。 */
    atomic_size_t submitted; /**< 报告真实转移到结果队列的次数。 */
    atomic_size_t rejected; /**< 未转移且关闭拒绝的次数。 */
    atomic_size_t cleaned; /**< worker 对未移交自有响应配对销毁的次数。 */
    atomic_size_t notified; /**< 真实增量通知成功次数，不等于 queue 当前深度。 */
    atomic_size_t notify_failed; /**< 已交接之后提示 IO 的次数，不是交接失败。 */
} run_context_t;

/** main 唯一管理资源，地址不能在发布后移动，普通指针副本不保活。 */
typedef struct run_fixture {
    vireo_task_queue_t *tasks; /**< main owner，专用 pool，pending 由 main 处理。 */
    vireo_completion_queue_t *outputs; /**< main owner，main 是唯一 consumer。 */
    vireo_thread_pool_t *pool; /**< 管理权借给 helper 时 main 不访问该池。 */
    vireo_notifier_t *notifier; /**< main owner，worker 只借用入口。 */
    io_fault_t fault; /**< 可选 notifier own seam；地址存活至 notifier 销毁。 */
    run_context_t context; /**< pool 长借的自有稳定执行上下文，不复制原子对象。 */
    size_t workers; /**< 配置槽数，另用实际 report 验证创建及 join。 */
} run_fixture_t;

/** 唯一 helper 串行管理 pool，普通报告只能在真实 pthread_join 后读取。 */
typedef struct join_context {
    vireo_thread_pool_t *pool; /**< 借至 helper join，不由 helper 销毁。 */
    atomic_bool finished; /**< release/acquire 返回提示，不代替 pthread_join。 */
    vireo_result_t result; /**< helper 独占写的原停止/首错结果。 */
    vireo_thread_pool_report_t report; /**< helper 独占写的实际累计回收报告。 */
} join_context_t;

/**
 * @brief
 *     仅 main 更新的真实线程创建计数，不是产品指标或并发共享状态。
 */
static size_t actual_workers;
static size_t actual_helpers;

/**
 * @brief
 *     配对资源操作只用于本核心 notifier seam，不读取外核私有布局。
 */
static void *io_allocate(void *context, size_t size) { (void)context; return malloc(size); }
static void io_deallocate(void *context, void *memory) { (void)context; free(memory); }
static int io_create(void *context, unsigned int initval, int flags) {
    io_fault_t *f = context;
    CHECK(initval == 0 && flags == (EFD_NONBLOCK | EFD_CLOEXEC));
    f->fd = eventfd(initval, flags);
    return f->fd;
}
static int io_close(void *context, int fd) {
    io_fault_t const *f = context;
    CHECK(fd == f->fd);
    return close(fd);
}
static ssize_t io_read(void *context, int fd, void *bytes, size_t size) {
    io_fault_t *f = context;
    CHECK(fd == f->fd && size == sizeof(uint64_t));
    atomic_fetch_add_explicit(&f->reads, 1, memory_order_relaxed);
    if (f->read_error != 0) { errno = f->read_error; return -1; }
    return read(fd, bytes, size);
}
static ssize_t io_write(void *context, int fd, void const *bytes, size_t size) {
    io_fault_t *f = context;
    CHECK(fd == f->fd && size == sizeof(uint64_t));
    uint64_t one;
    memcpy(&one, bytes, sizeof(one));
    CHECK(one == 1);
    atomic_fetch_add_explicit(&f->writes, 1, memory_order_relaxed);
    if (f->write_error != 0) { errno = f->write_error; return -1; }
    return write(fd, bytes, size);
}

/**
 * @brief
 *     显式创建真实 notifier，默认或本核心 I/O 注入均不改生产表。
 *
 * @param[in,out] fault
 *     可空；非空时策略先填好并保持到销毁，计数显式初始化。
 *
 * @return
 *     唯一 owned notifier；失败 CHECK 终止并保留实际失败证据。
 */
static vireo_notifier_t *make_notifier(io_fault_t *fault) {
    vireo_notifier_options_t const options = {4096};
    vireo_notifier_t *owner = NULL;
    if (fault == NULL) {
        EXPECT(vireo_notifier_create(&options, &owner, NULL), VIREO_OK);
    } else {
        atomic_init(&fault->reads, 0);
        atomic_init(&fault->writes, 0);
        vireo_notifier_ops_t const ops = {fault, io_allocate, io_deallocate, io_create,
            io_close, io_read, io_write};
        EXPECT(vireo_notifier_create_with_ops(&options, &ops, &owner, NULL), VIREO_OK);
    }
    return owner;
}

/**
 * @brief
 *     合成独立有效请求，不访问或认证真实 Reactor 客户。
 *
 * @param[in] id
 *     本组 1..32 不复用标签，普通 sequence 与实例身份分开。
 *
 * @return
 *     route/instance/operation/deadline 逻辑值；0/MAX 期限不自动过滤。
 */
static vireo_task_metadata_t request(uint64_t id) {
    CHECK(id > 0 && id <= MAX_REQUESTS);
    vireo_task_route_t route;
    EXPECT(vireo_task_route_make(107, (size_t)(id % 3), 19 + id % 2, (uint32_t)id,
        &route), VIREO_OK);
    vireo_task_metadata_t metadata;
    EXPECT(vireo_task_metadata_make(route, id, 11, id % 2 == 0 ? 0 : UINT64_MAX,
        &metadata), VIREO_OK);
    return metadata;
}

/**
 * @brief
 *     复制两段数值响应，输入改写后对象仍独立。
 *
 * @param[in] metadata
 *     有效完整请求值，所有字段由 caller 明确提供。
 *
 * @return
 *     caller 唯一 owned completion；不保留 task 或输入字节指针。
 */
static vireo_completion_t *make_completion(vireo_task_metadata_t metadata) {
    vireo_completion_metadata_t result;
    EXPECT(vireo_completion_metadata_make(metadata, VIREO_OK, VIREO_STATUS_OK, &result), VIREO_OK);
    uint64_t bytes[2] = {metadata.request_instance_id, metadata.request_instance_id ^ PAYLOAD_SALT};
    vireo_completion_t *owner = NULL;
    EXPECT(vireo_completion_create_copy(result, bytes, sizeof(bytes), 1024, &owner), VIREO_OK);
    memset(bytes, 0, sizeof(bytes));
    return owner;
}

/**
 * @brief
 *     核验真实移出对象的身份/响应字节并消费唯一 owner。
 *
 * @param[in,out] owner
 *     main 独占的非空 completion owner，短借结束后销毁。
 * @param[in,out] seen
 *     main 独占的 33 项去重表，不能跨线程共享。
 * @param[in,out] count
 *     main 独占消费条数，不按 notifier count 加值。
 */
static void record(vireo_completion_t **owner, bool seen[MAX_REQUESTS + 1], size_t *count) {
    vireo_completion_info_t info;
    vireo_completion_payload_view_t view;
    EXPECT(vireo_completion_inspect(*owner, &info), VIREO_OK);
    EXPECT(vireo_completion_borrow_payload(*owner, &view), VIREO_OK);
    uint64_t const id = info.metadata.request.request_instance_id;
    CHECK(id > 0 && id <= MAX_REQUESTS && !seen[id]);
    vireo_task_metadata_t const expected = request(id);
    bool same = false;
    EXPECT(vireo_task_metadata_same_request(info.metadata.request, expected, &same), VIREO_OK);
    CHECK(same && info.metadata.request.operation == expected.operation);
    CHECK(info.metadata.request.deadline_ns == expected.deadline_ns);
    CHECK(info.metadata.result == VIREO_OK && info.metadata.suggested_status == VIREO_STATUS_OK);
    uint64_t bytes[2];
    CHECK(view.size == sizeof(bytes) && info.payload_size == sizeof(bytes));
    memcpy(bytes, view.data, sizeof(bytes));
    CHECK(bytes[0] == id && bytes[1] == (id ^ PAYLOAD_SALT));
    seen[id] = true; ++*count;
    EXPECT(vireo_completion_destroy(owner), VIREO_OK);
    CHECK(*owner == NULL);
}

/**
 * @brief
 *     main 单消费者反复调用公开 try_pop，到当前暂空或 closed 空为止。
 *
 * @param[in,out] outputs
 *     存活队列；锁竞争仅测试 caller 外层有限让步，不修改库行为。
 * @param[in,out] seen
 *     main 去重表。
 * @param[in,out] count
 *     main 实际条数，成功移出才增加。
 *
 * @return
 *     当前结束的 NOT_FOUND 或 CANCELLED；不代表 worker 已结束。
 */
static vireo_result_t drain(vireo_completion_queue_t *outputs,
    bool seen[MAX_REQUESTS + 1], size_t *count) {
    for (unsigned i = 0; i < RETRY_LIMIT; ++i) {
        vireo_completion_t *owner = NULL;
        vireo_completion_queue_transfer_report_t report;
        errno = EDOM;
        vireo_result_t const result = vireo_completion_queue_try_pop(outputs, &owner, &report);
        CHECK(errno == EDOM);
        if (report.transferred) {
            CHECK(result == VIREO_OK && owner != NULL);
            record(&owner, seen, count);
        } else {
            CHECK(owner == NULL);
            if (result == VIREO_RESULT_NOT_FOUND || result == VIREO_RESULT_CANCELLED) { return result; }
            CHECK(result == VIREO_RESULT_BUSY && report.pthread_error == EBUSY);
            (void)sched_yield();
        }
    }
    CHECK(false);
    return VIREO_RESULT_INTERNAL;
}

/**
 * @brief
 *     单线程基础场景，prepare 的实际空间通知行为也参与此轮回归。
 */
static vireo_completion_queue_t *make_outputs(size_t capacity) {
    vireo_completion_queue_options_t const options = {capacity, 8192};
    vireo_completion_queue_t *owner = NULL;
    EXPECT(vireo_completion_queue_create(&options, &owner), VIREO_OK);
    EXPECT(vireo_completion_queue_prepare_wait(owner), VIREO_OK);
    return owner;
}
static void close_outputs(vireo_completion_queue_t *outputs) {
    vireo_completion_queue_close_report_t report;
    EXPECT(vireo_completion_queue_close(outputs, &report), VIREO_OK);
}

/**
 * @brief
 *     仅真实移交后通知一次；结果已经归队列时不收回或重新 push。
 *
 * @param[in,out] context
 *     pool 长借的稳定策略/原子进度。
 * @param[in] task
 *     const 短借到返回，pool 负责其销毁；不保存地址。
 *
 * @return
 *     原交接或通知结果，首错由 pool 公开观测；不回滚业务/队列动作。
 *
 * @note
 *     pool 禁用了 POSIX 取消；允许 worker wait_push，不改取消状态或重入 pool。
 *     仅测试 caller 协作，不是新增产品自动回投或生产恢复策略。
 */
static vireo_result_t execute(void *context, vireo_task_t const *task) {
    run_context_t *c = context;
    vireo_task_info_t info;
    EXPECT(vireo_task_inspect(task, &info), VIREO_OK);
    atomic_fetch_add_explicit(&c->started, 1, memory_order_release);
    while (!atomic_load_explicit(&c->release, memory_order_acquire)) { (void)sched_yield(); }
    vireo_completion_t *owner = make_completion(info.metadata);
    vireo_completion_queue_transfer_report_t report;
    errno = EDOM;
    vireo_result_t const pushed = vireo_completion_queue_wait_push(c->outputs, &owner, &report);
    CHECK(errno == EDOM);
    if (!report.transferred) {
        CHECK(pushed == VIREO_RESULT_CANCELLED && owner != NULL);
        atomic_fetch_add_explicit(&c->rejected, 1, memory_order_relaxed);
        EXPECT(vireo_completion_destroy(&owner), VIREO_OK);
        atomic_fetch_add_explicit(&c->cleaned, 1, memory_order_relaxed);
        return pushed;
    }
    CHECK(owner == NULL);
    atomic_fetch_add_explicit(&c->submitted, 1, memory_order_release);
    vireo_notifier_notify_outcome_t outcome = VIREO_NOTIFIER_NOTIFY_ALREADY_PENDING;
    vireo_notifier_error_t error;
    errno = EDOM;
    vireo_result_t const notified = vireo_notifier_notify(c->notifier, &outcome, &error);
    CHECK(errno == EDOM);
    if (notified == VIREO_OK) {
        CHECK(outcome == VIREO_NOTIFIER_NOTIFY_INCREMENTED && error.stage == VIREO_NOTIFIER_STAGE_NONE);
        atomic_fetch_add_explicit(&c->notified, 1, memory_order_release);
    } else {
        CHECK(notified == VIREO_RESULT_IO && error.stage == VIREO_NOTIFIER_STAGE_NOTIFY && error.system_errno == EINTR);
        CHECK(outcome == VIREO_NOTIFIER_NOTIFY_ALREADY_PENDING);
        atomic_fetch_add_explicit(&c->notify_failed, 1, memory_order_release);
    }
    return pushed != VIREO_OK ? pushed : notified;
}

/**
 * @brief
 *     配置固定预算和 worker，线程先停驻，context 地址稳定。
 *
 * @param[in,out] f
 *     尚未使用的 main fixture，随后不可复制。
 * @param[in] workers
 *     本组实际配置 worker 数。
 * @param[in] output_capacity
 *     显式结果容量；小容量场景必须保持 consumer 能力。
 * @param[in] held
 *     true 使已领取 callback 等待测试放行。
 * @param[in] fail_notify
 *     true 使用固定 EINTR seam；后续由测试 caller 主动扫描恢复。
 */
static void init_fixture(run_fixture_t *f, size_t workers, size_t output_capacity,
    bool held, bool fail_notify) {
    f->tasks = NULL; f->pool = NULL; f->workers = workers;
    vireo_task_queue_options_t const tasks = {MAX_REQUESTS, 8192};
    EXPECT(vireo_task_queue_create(&tasks, &f->tasks), VIREO_OK);
    EXPECT(vireo_task_queue_prepare_wait(f->tasks), VIREO_OK);
    f->outputs = make_outputs(output_capacity);
    f->fault.fd = -1; f->fault.read_error = 0; f->fault.write_error = fail_notify ? EINTR : 0;
    if (!fail_notify) { atomic_init(&f->fault.reads, 0); atomic_init(&f->fault.writes, 0); }
    f->notifier = make_notifier(fail_notify ? &f->fault : NULL);
    run_context_t *c = &f->context;
    c->outputs = f->outputs; c->notifier = f->notifier;
    atomic_init(&c->release, !held); atomic_init(&c->started, 0);
    atomic_init(&c->submitted, 0); atomic_init(&c->rejected, 0); atomic_init(&c->cleaned, 0);
    atomic_init(&c->notified, 0); atomic_init(&c->notify_failed, 0);
    vireo_thread_pool_options_t const options = {workers, 8192};
    EXPECT(vireo_thread_pool_create(&options, &f->pool), VIREO_OK);
    vireo_thread_pool_configuration_t const configuration = {f->tasks, execute, c};
    EXPECT(vireo_thread_pool_configure(f->pool, &configuration, NULL), VIREO_OK);
    vireo_thread_pool_report_t report;
    EXPECT(vireo_thread_pool_start(f->pool, &report), VIREO_OK);
    CHECK(report.created_count == workers && report.joined_count == 0 && !report.execution_enabled);
    actual_workers += report.created_count;
}

/**
 * @brief
 *     未放行时预放任务，输入为独立元数据，成功后 task 由队列/pool 管理。
 */
static void seed(run_fixture_t *f, size_t count) {
    CHECK(count > 0 && count <= MAX_REQUESTS);
    for (size_t i = 1; i <= count; ++i) {
        vireo_task_t *owner = NULL;
        EXPECT(vireo_task_create_copy(request((uint64_t)i), NULL, 0, 1024, &owner), VIREO_OK);
        vireo_task_queue_transfer_report_t report;
        EXPECT(vireo_task_queue_try_push(f->tasks, &owner, &report), VIREO_OK);
        CHECK(report.transferred && owner == NULL);
    }
    vireo_thread_pool_report_t report;
    EXPECT(vireo_thread_pool_enable_execution(f->pool, &report), VIREO_OK);
    CHECK(report.execution_enabled);
}

/**
 * @brief
 *     仅测试握手，入口 marker 不等于已经进入外核 cond_wait。
 */
static void await_count(atomic_size_t const *count, size_t wanted) {
    for (unsigned i = 0; i < RETRY_LIMIT; ++i) {
        if (atomic_load_explicit(count, memory_order_acquire) >= wanted) { return; }
        (void)sched_yield();
    }
    CHECK(false);
}
static void close_tasks(vireo_task_queue_t *tasks, vireo_task_queue_state_t mode) {
    for (unsigned i = 0; i < RETRY_LIMIT; ++i) {
        vireo_task_queue_close_report_t report;
        errno = EDOM;
        vireo_result_t const result = vireo_task_queue_close(tasks, mode, &report);
        CHECK(errno == EDOM);
        if (result == VIREO_OK) { return; }
        CHECK(result == VIREO_RESULT_BUSY && !report.changed && report.pthread_error == EBUSY);
        (void)sched_yield();
    }
    CHECK(false);
}

/**
 * @brief
 *     唯一管理者关闭后 join；只队列资格检查竞争允许测试外层重试。
 *
 * @param[in,out] pool
 *     全程禁 POSIX 取消的 caller 串行管理，consumer 可以同时消费结果。
 * @param[out] report
 *     独占管理报告，不把原首错和真实 join 进度合并成成功布尔。
 *
 * @return
 *     原停止及 worker 首错，包含已经完成的真实 join 进度。
 */
static vireo_result_t finish_join(vireo_thread_pool_t *pool, vireo_thread_pool_report_t *report) {
    for (unsigned i = 0; i < RETRY_LIMIT; ++i) {
        errno = EDOM;
        vireo_result_t const result = vireo_thread_pool_stop_and_join(pool, report);
        CHECK(errno == EDOM);
        if (result != VIREO_RESULT_BUSY) { return result; }
        CHECK(report->stage == VIREO_THREAD_POOL_STAGE_CHECK_QUEUE && report->pthread_error == 0);
        (void)sched_yield();
    }
    CHECK(false);
    return VIREO_RESULT_INTERNAL;
}
static void *join_workers(void *argument) {
    join_context_t *j = argument;
    CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL) == 0);
    j->result = finish_join(j->pool, &j->report);
    atomic_store_explicit(&j->finished, true, memory_order_release);
    return NULL;
}

/**
 * @brief
 *     poll 只借 notifier fd，真实可读时一次消费，然后查队列至暂空。
 *
 * @param[in,out] f
 *     main 为唯一结果/prompt consumer，全部资源存活。
 * @param[in,out] seen
 *     main 独占去重表。
 * @param[in,out] count
 *     真实条数。
 * @param[in] fallback
 *     true 时每轮主动扫描 queue，是测试 caller 故障恢复，不是产品策略。
 *
 * @note
 *     poll 的 10ms 只测试保护；没有新网络/生产超时合同或逐条计数驱动 pop。
 */
static void pump(run_fixture_t *f, bool seen[MAX_REQUESTS + 1], size_t *count, bool fallback) {
    vireo_notifier_info_t info;
    EXPECT(vireo_notifier_inspect(f->notifier, &info), VIREO_OK);
    struct pollfd p = {info.fd, POLLIN, 0};
    int const ready = poll(&p, 1, fallback ? 0 : 10);
    CHECK(ready >= 0 && (p.revents & (POLLERR | POLLHUP | POLLNVAL)) == 0);
    bool const readable = (p.revents & POLLIN) != 0;
    if (readable) {
        uint64_t hints = 0;
        EXPECT(vireo_notifier_consume(f->notifier, &hints, NULL), VIREO_OK);
        CHECK(hints > 0);
    }
    if (readable || fallback) { CHECK(drain(f->outputs, seen, count) == VIREO_RESULT_NOT_FOUND); }
    if (fallback && !readable) { (void)sched_yield(); }
}

/**
 * @brief
 *     helper 阻塞 join 时 main 保持单 consumer，报告必须真实 join helper 后读。
 *
 * @param[in,out] f
 *     tasks 已关闭，main 不同时管理 pool。
 * @param[in,out] seen
 *     main 独占记录。
 * @param[in,out] count
 *     实际已消费条数。
 * @param[in] fallback
 *     明确场景是否主动扫描恢复无提示的已提交结果。
 *
 * @return
 *     原 pool 首错；另核验全部 worker 实际 join，不因错误跳过回收。
 */
static vireo_result_t consume_and_join(run_fixture_t *f, bool seen[MAX_REQUESTS + 1],
    size_t *count, bool fallback) {
    join_context_t j;
    j.pool = f->pool; j.result = VIREO_OK; atomic_init(&j.finished, false);
    pthread_t helper;
    CHECK(pthread_create(&helper, NULL, join_workers, &j) == 0);
    ++actual_helpers;
    for (unsigned i = 0; !atomic_load_explicit(&j.finished, memory_order_acquire); ++i) {
        CHECK(i < RETRY_LIMIT);
        pump(f, seen, count, fallback);
    }
    CHECK(pthread_join(helper, NULL) == 0);
    CHECK(j.report.created_count == f->workers && j.report.joined_count == f->workers);
    return j.result;
}

/**
 * @brief
 *     全部 producer join 后无条件最后查队列，不以 hint0 代替 drain。
 *
 * @param[in,out] f
 *     所有 worker/helper 已成功 join，main 串行访问。
 * @param[in,out] seen
 *     main 去重表。
 * @param[in,out] count
 *     main 总条数。
 *
 * @return
 *     最后 drain 的真实领取条数，可为0。
 */
static size_t final_drain(run_fixture_t *f, bool seen[MAX_REQUESTS + 1], size_t *count) {
    close_outputs(f->outputs);
    size_t const before = *count;
    CHECK(drain(f->outputs, seen, count) == VIREO_RESULT_CANCELLED);
    uint64_t hints = UINT64_MAX;
    EXPECT(vireo_notifier_consume(f->notifier, &hints, NULL), VIREO_OK);
    EXPECT(vireo_notifier_consume(f->notifier, &hints, NULL), VIREO_OK);
    CHECK(hints == 0);
    return *count - before;
}

/**
 * @brief
 *     成功 join 后观测各 worker 首错；已提交响应不能因首错被销毁两次。
 */
static size_t worker_errors(run_fixture_t const *f, vireo_result_t allowed) {
    size_t errors = 0;
    for (size_t i = 0; i < f->workers; ++i) {
        vireo_thread_pool_worker_result_t result;
        EXPECT(vireo_thread_pool_inspect_worker_result(f->pool, i, &result), VIREO_OK);
        if (result.result != VIREO_OK) {
            CHECK(result.result == allowed && result.stage == VIREO_THREAD_POOL_STAGE_EXECUTE_TASK);
            CHECK(result.pthread_error == 0); ++errors;
        } else { CHECK(result.stage == VIREO_THREAD_POOL_STAGE_NONE); }
    }
    return errors;
}

/**
 * @brief
 *     先解除 pool 长借，再配对销毁空队列及结束全部借用的 notifier。
 *
 * @param[in,out] f
 *     全部线程已 join，pending/响应已处理；不得并发访问或保留 poll 注册。
 * @param[in] rejected
 *     本组预期的输出关闭拒绝次数，与真实清理次数核对。
 */
static void destroy_fixture(run_fixture_t *f, uint64_t rejected) {
    vireo_completion_queue_info_t info;
    vireo_completion_queue_metrics_t metrics;
    EXPECT(vireo_completion_queue_inspect(f->outputs, &info), VIREO_OK);
    EXPECT(vireo_completion_queue_inspect_metrics(f->outputs, &metrics), VIREO_OK);
    CHECK(info.closed && info.count == 0 && metrics.depth == 0 && info.wait_prepared);
    CHECK(metrics.high_watermark <= info.capacity && metrics.full_rejections == 0);
    CHECK(metrics.closed_rejections == rejected && !metrics.rejection_count_saturated);
    vireo_task_queue_info_t tasks;
    EXPECT(vireo_task_queue_inspect(f->tasks, &tasks), VIREO_OK);
    CHECK(tasks.count == 0 && tasks.state != VIREO_TASK_QUEUE_OPEN);
    EXPECT(vireo_thread_pool_destroy(&f->pool), VIREO_OK);
    EXPECT(vireo_task_queue_destroy(&f->tasks), VIREO_OK);
    EXPECT(vireo_completion_queue_destroy(&f->outputs), VIREO_OK);
    EXPECT(vireo_notifier_destroy(&f->notifier, NULL), VIREO_OK);
    CHECK(f->pool == NULL && f->tasks == NULL && f->outputs == NULL && f->notifier == NULL);
}

/**
 * @brief
 *     六项真实响应、八次合法提示；额外提示只构造测试反例，不是生产优化。
 */
static void merged_hint_queue_truth(void) {
    vireo_completion_queue_t *outputs = make_outputs(8);
    vireo_notifier_t *notifier = make_notifier(NULL);
    for (uint64_t id = 1; id <= 6; ++id) {
        vireo_completion_t *owner = make_completion(request(id));
        vireo_completion_queue_transfer_report_t report;
        EXPECT(vireo_completion_queue_try_push(outputs, &owner, &report), VIREO_OK);
        CHECK(report.transferred && owner == NULL);
        vireo_notifier_notify_outcome_t outcome;
        EXPECT(vireo_notifier_notify(notifier, &outcome, NULL), VIREO_OK);
        CHECK(outcome == VIREO_NOTIFIER_NOTIFY_INCREMENTED);
    }
    for (unsigned i = 0; i < 2; ++i) {
        vireo_notifier_notify_outcome_t outcome;
        EXPECT(vireo_notifier_notify(notifier, &outcome, NULL), VIREO_OK);
    }
    uint64_t hints = 0;
    EXPECT(vireo_notifier_consume(notifier, &hints, NULL), VIREO_OK);
    CHECK(hints == 8);
    bool seen[MAX_REQUESTS + 1] = {false}; size_t count = 0;
    CHECK(drain(outputs, seen, &count) == VIREO_RESULT_NOT_FOUND && count == 6);
    EXPECT(vireo_notifier_consume(notifier, &hints, NULL), VIREO_OK);
    CHECK(hints == 0);
    close_outputs(outputs);
    CHECK(drain(outputs, seen, &count) == VIREO_RESULT_CANCELLED);
    EXPECT(vireo_completion_queue_destroy(&outputs), VIREO_OK);
    EXPECT(vireo_notifier_destroy(&notifier, NULL), VIREO_OK);
}

/**
 * @brief
 *     结果先真实交接，再注入通知 EINTR；主输出保持不改变 queue 的唯一归属。
 */
static void publish_then_notify_error(void) {
    io_fault_t fault; fault.fd = -1; fault.read_error = 0; fault.write_error = EINTR;
    vireo_notifier_t *notifier = make_notifier(&fault);
    vireo_completion_queue_t *outputs = make_outputs(1);
    vireo_completion_t *owner = make_completion(request(1));
    vireo_completion_queue_transfer_report_t transfer;
    EXPECT(vireo_completion_queue_try_push(outputs, &owner, &transfer), VIREO_OK);
    CHECK(transfer.transferred && owner == NULL);
    vireo_notifier_notify_outcome_t outcome = VIREO_NOTIFIER_NOTIFY_ALREADY_PENDING;
    vireo_notifier_error_t error;
    EXPECT(vireo_notifier_notify(notifier, &outcome, &error), VIREO_RESULT_IO);
    CHECK(outcome == VIREO_NOTIFIER_NOTIFY_ALREADY_PENDING && error.system_errno == EINTR);
    CHECK(error.stage == VIREO_NOTIFIER_STAGE_NOTIFY && atomic_load(&fault.writes) == 1);
    uint64_t hints = UINT64_MAX;
    EXPECT(vireo_notifier_consume(notifier, &hints, NULL), VIREO_OK);
    CHECK(hints == 0);
    bool seen[MAX_REQUESTS + 1] = {false}; size_t count = 0;
    CHECK(drain(outputs, seen, &count) == VIREO_RESULT_NOT_FOUND && count == 1 && seen[1]);
    close_outputs(outputs);
    EXPECT(vireo_completion_queue_destroy(&outputs), VIREO_OK);
    EXPECT(vireo_notifier_destroy(&notifier, NULL), VIREO_OK);
}

/**
 * @brief
 *     consume 的 I/O 失败保持计数输出，caller 仍能公开取回真正队列内容。
 */
static void consume_error_keeps_queue(void) {
    io_fault_t fault; fault.fd = -1; fault.read_error = EINTR; fault.write_error = 0;
    vireo_notifier_t *notifier = make_notifier(&fault);
    vireo_completion_queue_t *outputs = make_outputs(1);
    vireo_completion_t *owner = make_completion(request(1));
    vireo_completion_queue_transfer_report_t transfer;
    EXPECT(vireo_completion_queue_try_push(outputs, &owner, &transfer), VIREO_OK);
    vireo_notifier_notify_outcome_t outcome;
    EXPECT(vireo_notifier_notify(notifier, &outcome, NULL), VIREO_OK);
    uint64_t hints = 91;
    vireo_notifier_error_t error;
    EXPECT(vireo_notifier_consume(notifier, &hints, &error), VIREO_RESULT_IO);
    CHECK(hints == 91 && error.stage == VIREO_NOTIFIER_STAGE_CONSUME && error.system_errno == EINTR);
    CHECK(atomic_load(&fault.reads) == 1 && transfer.transferred && owner == NULL);
    bool seen[MAX_REQUESTS + 1] = {false}; size_t count = 0;
    CHECK(drain(outputs, seen, &count) == VIREO_RESULT_NOT_FOUND && count == 1);
    fault.read_error = 0; /* 全部访问串行，明确 caller 再调用，不是内部重试。 */
    EXPECT(vireo_notifier_consume(notifier, &hints, NULL), VIREO_OK);
    CHECK(hints == 1 && atomic_load(&fault.reads) == 2);
    close_outputs(outputs);
    EXPECT(vireo_completion_queue_destroy(&outputs), VIREO_OK);
    EXPECT(vireo_notifier_destroy(&notifier, NULL), VIREO_OK);
}

/**
 * @brief
 *     满/关闭没有真实交接，不通知；未移交源仍由 caller 明确配对销毁。
 */
static void rejected_submission_no_notification(void) {
    io_fault_t fault; fault.fd = -1; fault.read_error = 0; fault.write_error = 0;
    vireo_notifier_t *notifier = make_notifier(&fault);
    vireo_completion_queue_t *outputs = make_outputs(1);
    vireo_completion_t *owner = make_completion(request(1));
    vireo_completion_queue_transfer_report_t report;
    EXPECT(vireo_completion_queue_try_push(outputs, &owner, &report), VIREO_OK);
    CHECK(report.transferred && owner == NULL);
    vireo_notifier_notify_outcome_t outcome;
    EXPECT(vireo_notifier_notify(notifier, &outcome, NULL), VIREO_OK);
    owner = make_completion(request(2));
    vireo_completion_t *const original = owner;
    EXPECT(vireo_completion_queue_try_push(outputs, &owner, &report), VIREO_RESULT_BUSY);
    CHECK(!report.transferred && owner == original && atomic_load(&fault.writes) == 1);
    EXPECT(vireo_completion_destroy(&owner), VIREO_OK);
    close_outputs(outputs);
    owner = make_completion(request(3));
    EXPECT(vireo_completion_queue_try_push(outputs, &owner, &report), VIREO_RESULT_CANCELLED);
    CHECK(!report.transferred && owner != NULL && atomic_load(&fault.writes) == 1);
    EXPECT(vireo_completion_destroy(&owner), VIREO_OK);
    uint64_t hints = 0;
    EXPECT(vireo_notifier_consume(notifier, &hints, NULL), VIREO_OK);
    CHECK(hints == 1);
    bool seen[MAX_REQUESTS + 1] = {false}; size_t count = 0;
    CHECK(drain(outputs, seen, &count) == VIREO_RESULT_CANCELLED && count == 1 && seen[1]);
    EXPECT(vireo_completion_queue_destroy(&outputs), VIREO_OK);
    EXPECT(vireo_notifier_destroy(&notifier, NULL), VIREO_OK);
}

/**
 * @brief
 *     4 worker/24项/1结果槽，只按真实提示消费，保持消费能力配合 helper join。
 */
static void live_drain_and_join(void) {
    run_fixture_t f; init_fixture(&f, 4, 1, false, false); seed(&f, 24);
    await_count(&f.context.submitted, 1);
    close_tasks(f.tasks, VIREO_TASK_QUEUE_DRAIN);
    bool seen[MAX_REQUESTS + 1] = {false}; size_t count = 0;
    CHECK(consume_and_join(&f, seen, &count, false) == VIREO_OK);
    (void)final_drain(&f, seen, &count);
    CHECK(count == 24 && atomic_load(&f.context.submitted) == 24 && atomic_load(&f.context.notified) == 24);
    CHECK(atomic_load(&f.context.cleaned) == 0 && worker_errors(&f, VIREO_OK) == 0);
    for (size_t i = 1; i <= 24; ++i) { CHECK(seen[i]); }
    destroy_fixture(&f, 0);
}

/**
 * @brief
 *     所有提示注入 EINTR，1槽仍靠明确 caller 扫描前进；不是产品恢复保证。
 */
static void notification_failure_fallback(void) {
    run_fixture_t f; init_fixture(&f, 3, 1, false, true); seed(&f, 15);
    await_count(&f.context.notify_failed, 1);
    uint64_t hints = UINT64_MAX;
    EXPECT(vireo_notifier_consume(f.notifier, &hints, NULL), VIREO_OK);
    CHECK(hints == 0);
    close_tasks(f.tasks, VIREO_TASK_QUEUE_DRAIN);
    bool seen[MAX_REQUESTS + 1] = {false}; size_t count = 0;
    CHECK(consume_and_join(&f, seen, &count, true) == VIREO_RESULT_IO);
    (void)final_drain(&f, seen, &count);
    CHECK(count == 15 && atomic_load(&f.context.submitted) == 15);
    CHECK(atomic_load(&f.context.notify_failed) == 15 && atomic_load(&f.context.notified) == 0);
    CHECK(atomic_load(&f.context.cleaned) == 0 && atomic_load(&f.fault.writes) == 15);
    CHECK(worker_errors(&f, VIREO_RESULT_IO) > 0);
    for (size_t i = 1; i <= 15; ++i) { CHECK(seen[i]); }
    destroy_fixture(&f, 0);
}

/**
 * @brief
 *     显式容量容纳全部剩余结果，join后先读提示而不pop，随后无条件最后排空。
 */
static void buffered_final_drain(void) {
    run_fixture_t f; init_fixture(&f, 2, 5, false, false); seed(&f, 5);
    close_tasks(f.tasks, VIREO_TASK_QUEUE_DRAIN);
    vireo_thread_pool_report_t report;
    CHECK(finish_join(f.pool, &report) == VIREO_OK && report.joined_count == 2);
    uint64_t hints = 0;
    EXPECT(vireo_notifier_consume(f.notifier, &hints, NULL), VIREO_OK);
    CHECK(hints == 5);
    EXPECT(vireo_notifier_consume(f.notifier, &hints, NULL), VIREO_OK);
    CHECK(hints == 0);
    bool seen[MAX_REQUESTS + 1] = {false}; size_t count = 0;
    CHECK(final_drain(&f, seen, &count) == 5 && count == 5);
    CHECK(worker_errors(&f, VIREO_OK) == 0);
    destroy_fixture(&f, 0);
}

/**
 * @brief
 *     七pending由caller收回，两个已领取callback放行后正常提交和提示。
 */
static void cancel_pending_keeps_inflight(void) {
    run_fixture_t f; init_fixture(&f, 2, 1, true, false); seed(&f, 9);
    await_count(&f.context.started, 2); close_tasks(f.tasks, VIREO_TASK_QUEUE_CANCEL_PENDING);
    for (size_t i = 3; i <= 9; ++i) {
        vireo_task_t *owner = NULL;
        vireo_task_queue_transfer_report_t report;
        EXPECT(vireo_task_queue_try_take_cancelled(f.tasks, &owner, &report), VIREO_OK);
        vireo_task_info_t info;
        EXPECT(vireo_task_inspect(owner, &info), VIREO_OK);
        CHECK(report.transferred && info.metadata.request_instance_id == i);
        EXPECT(vireo_task_destroy(&owner), VIREO_OK);
    }
    vireo_task_t *empty = NULL;
    vireo_task_queue_transfer_report_t report;
    EXPECT(vireo_task_queue_try_take_cancelled(f.tasks, &empty, &report), VIREO_RESULT_NOT_FOUND);
    CHECK(empty == NULL && !report.transferred);
    atomic_store_explicit(&f.context.release, true, memory_order_release);
    bool seen[MAX_REQUESTS + 1] = {false}; size_t count = 0;
    CHECK(consume_and_join(&f, seen, &count, false) == VIREO_OK);
    (void)final_drain(&f, seen, &count);
    CHECK(count == 2 && seen[1] && seen[2] && atomic_load(&f.context.started) == 2);
    CHECK(atomic_load(&f.context.submitted) == 2 && atomic_load(&f.context.notified) == 2);
    CHECK(worker_errors(&f, VIREO_OK) == 0); destroy_fixture(&f, 0);
}

/**
 * @brief
 *     结果端提前永久关闭是一种测试失败策略，源清理由worker完成且不notify。
 */
static void early_result_close(void) {
    run_fixture_t f; init_fixture(&f, 2, 1, true, false); seed(&f, 12);
    await_count(&f.context.started, 2); close_outputs(f.outputs);
    close_tasks(f.tasks, VIREO_TASK_QUEUE_DRAIN);
    atomic_store_explicit(&f.context.release, true, memory_order_release);
    vireo_thread_pool_report_t report;
    CHECK(finish_join(f.pool, &report) == VIREO_RESULT_CANCELLED && report.joined_count == 2);
    bool seen[MAX_REQUESTS + 1] = {false}; size_t count = 0;
    CHECK(final_drain(&f, seen, &count) == 0 && count == 0);
    CHECK(atomic_load(&f.context.rejected) == 12 && atomic_load(&f.context.cleaned) == 12);
    CHECK(atomic_load(&f.context.submitted) == 0 && atomic_load(&f.context.notified) == 0);
    CHECK(atomic_load(&f.context.notify_failed) == 0 && worker_errors(&f, VIREO_RESULT_CANCELLED) > 0);
    destroy_fixture(&f, 12);
}

/**
 * @brief
 *     /proc资源口径仅本进程前后匹配，包含本次目录句柄。
 */
static size_t fd_count(void) {
    DIR *directory = opendir("/proc/self/fd");
    CHECK(directory != NULL);
    size_t count = 0;
    errno = 0;
    struct dirent *entry;
    while ((entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) { ++count; }
    }
    int const cause = errno;
    CHECK(closedir(directory) == 0 && cause == 0);
    return count;
}

int main(void) {
    int previous_cancel_state;
    CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previous_cancel_state) == 0);
    size_t const before = fd_count();
    void (*const tests[])(void) = {merged_hint_queue_truth, publish_then_notify_error,
        consume_error_keeps_queue, rejected_submission_no_notification, live_drain_and_join,
        notification_failure_fallback, buffered_final_drain, cancel_pending_keeps_inflight,
        early_result_close};
    for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); ++i) { tests[i](); }
    CHECK(actual_workers == 13 && actual_helpers == 3 && fd_count() == before);
    CHECK(pthread_setcancelstate(previous_cancel_state, NULL) == 0);
    printf("notifier queue cooperation: 9 groups passed (%zu pool workers, %zu helpers created/joined)\n",
        actual_workers, actual_helpers);
    return 0;
}
