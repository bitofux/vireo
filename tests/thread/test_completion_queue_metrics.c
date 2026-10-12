/*
 * PROJECT : VIREO
 * FILE    : test_completion_queue_metrics.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-12
 * BRIEF   : 指标口径、真实等待/竞争、饱和及失败进度；只用本核心私有 seam
 */
#include "thread/completion_queue_internal.h"
#include <errno.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); abort(); } } while (0)
#define EXPECT(x, expected) do { errno = E2BIG; vireo_result_t const got = (x); CHECK(got == (expected) && errno == E2BIG); } while (0)
#define RETRY_LIMIT 2000000U

/** 无并发配置故障；等待谓词在原 mutex 内访问，握手用独立原子。 */
typedef struct metric_fault {
    int lock_error; /**< try/blocking lock 的注入错误，非零不持锁。 */
    int unlock_error; /**< 真正解锁之后报告的注入错误。 */
    int destroy_error; /**< mutex 尚未销毁时报告的错误。 */
    int wait_error; /**< 持原锁的等待错误，不提交 owner。 */
    size_t allocations; /**< 外部无访问时累计真实控制块申请次数。 */
    size_t frees; /**< 外部无访问时累计配对释放次数。 */
    unsigned spurious; /**< 原锁保护的有限虚假唤醒余额。 */
    unsigned waiting; /**< 原锁保护的当前真实 cond_wait 数。 */
    atomic_uint waits; /**< release 发布的等待入口次数，main acquire 握手。 */
} metric_fault_t;

/**
 * @brief
 *     配对分配适配，计数只在外部无访问阶段使用。
 *
 * @param[in,out] context
 *     存活 metric_fault。
 * @param[in] bytes
 *     正、受检的申请字节数。
 *
 * @return
 *     malloc 原块或 NULL。
 */
static void *allocate(void *context, size_t bytes) {
    metric_fault_t *f = context;
    ++f->allocations;
    return malloc(bytes);
}

/**
 * @brief
 *     配对释放原块并记录资源账。
 *
 * @param[in,out] context
 *     存活 metric_fault。
 * @param[in] allocation
 *     全部访问结束的独占原块。
 */
static void deallocate(void *context, void *allocation) {
    metric_fault_t *f = context;
    ++f->frees;
    free(allocation);
}

/**
 * @brief
 *     初始化默认非 robust mutex。
 *
 * @param[in] context
 *     未使用，可 NULL。
 * @param[in,out] mutex
 *     未初始化的有效同步存储。
 *
 * @return
 *     直接 pthread 码。
 */
static int init(void *context, pthread_mutex_t *mutex) {
    (void)context;
    return pthread_mutex_init(mutex, NULL);
}

/**
 * @brief
 *     一次 try；注入非零时不取锁。
 *
 * @param[in] context
 *     无并发写的故障配置。
 * @param[in,out] mutex
 *     存活 mutex。
 *
 * @return
 *     注入或直接 pthread 码；改变 errno 以验证外层保持。
 */
static int try_lock(void *context, pthread_mutex_t *mutex) {
    metric_fault_t const *f = context;
    errno = EIO;
    return f->lock_error != 0 ? f->lock_error : pthread_mutex_trylock(mutex);
}

/**
 * @brief
 *     实际释放原锁后注入错误，核验已发生进度。
 *
 * @param[in] context
 *     无并发写的故障配置。
 * @param[in,out] mutex
 *     当前调用者持有的 mutex。
 *
 * @return
 *     真实错误优先，否则注入码。
 */
static int unlock(void *context, pthread_mutex_t *mutex) {
    metric_fault_t const *f = context;
    int const code = pthread_mutex_unlock(mutex);
    errno = EIO;
    return code != 0 ? code : f->unlock_error;
}

/**
 * @brief
 *     无访问时销毁 mutex；注入失败保留资源。
 *
 * @param[in] context
 *     无并发写的故障配置。
 * @param[in,out] mutex
 *     无任何访问的存活 mutex。
 *
 * @return
 *     注入或直接 pthread 码。
 */
static int destroy_mutex(void *context, pthread_mutex_t *mutex) {
    metric_fault_t const *f = context;
    return f->destroy_error != 0 ? f->destroy_error : pthread_mutex_destroy(mutex);
}

/**
 * @brief
 *     初始化原块内的条件变量。
 *
 * @param[in] context
 *     未使用，可 NULL。
 * @param[in,out] cond
 *     未初始化的同步存储。
 *
 * @return
 *     直接 pthread 码。
 */
static int init_cond(void *context, pthread_cond_t *cond) {
    (void)context;
    return pthread_cond_init(cond, NULL);
}

/**
 * @brief
 *     允许阻塞的原 mutex 加锁适配。
 *
 * @param[in] context
 *     无并发写的故障配置。
 * @param[in,out] mutex
 *     存活同步资源。
 *
 * @return
 *     注入或直接 pthread 码，非零不持锁。
 */
static int lock(void *context, pthread_mutex_t *mutex) {
    metric_fault_t const *f = context;
    errno = EIO;
    return f->lock_error != 0 ? f->lock_error : pthread_mutex_lock(mutex);
}

/**
 * @brief
 *     在原 mutex 内模拟有限虚假唤醒，再真实等待空间或关闭。
 *
 * @param[in,out] context
 *     原 mutex 保护的计数及稳定故障配置。
 * @param[in,out] cond
 *     存活条件变量。
 * @param[in,out] mutex
 *     入口及返回均由调用者持有。
 *
 * @return
 *     注入或直接 pthread 码；0 仍须重检谓词。
 */
static int wait(void *context, pthread_cond_t *cond, pthread_mutex_t *mutex) {
    metric_fault_t *f = context;
    atomic_fetch_add_explicit(&f->waits, 1, memory_order_release);
    errno = EIO;
    if (f->wait_error != 0) { return f->wait_error; }
    if (f->spurious != 0) { --f->spurious; return 0; }
    ++f->waiting;
    int const code = pthread_cond_wait(cond, mutex);
    --f->waiting;
    return code;
}

/**
 * @brief
 *     领取之后提示一个真实等待者。
 *
 * @param[in] context
 *     未使用，可 NULL。
 * @param[in,out] cond
 *     存活条件变量。
 *
 * @return
 *     直接 pthread 码。
 */
static int signal(void *context, pthread_cond_t *cond) {
    (void)context;
    return pthread_cond_signal(cond);
}

/**
 * @brief
 *     关闭之后提示全部真实等待者。
 *
 * @param[in] context
 *     未使用，可 NULL。
 * @param[in,out] cond
 *     存活条件变量。
 *
 * @return
 *     直接 pthread 码。
 */
static int broadcast(void *context, pthread_cond_t *cond) {
    (void)context;
    return pthread_cond_broadcast(cond);
}

/**
 * @brief
 *     全部访问结束后实际销毁条件变量。
 *
 * @param[in] context
 *     未使用，可 NULL。
 * @param[in,out] cond
 *     无访问的存活条件变量。
 *
 * @return
 *     直接 pthread 码。
 */
static int destroy_cond(void *context, pthread_cond_t *cond) {
    (void)context;
    return pthread_cond_destroy(cond);
}

/**
 * @brief
 *     创建局部故障队列，保持 context 到销毁。
 *
 * @param[in] capacity
 *     正槽数。
 * @param[in,out] f
 *     外部无访问的零初始化故障记录。
 *
 * @return
 *     新唯一 queue owner。
 */
static vireo_completion_queue_t *make_queue(size_t capacity, metric_fault_t *f) {
    atomic_init(&f->waits, 0);
    vireo_completion_queue_options_t const options = {capacity, 4096};
    vireo_completion_queue_allocator_t const allocator = {f, allocate, deallocate};
    vireo_completion_queue_sync_t const sync = {f, init, try_lock, unlock, destroy_mutex};
    vireo_completion_queue_t *queue = NULL;
    EXPECT(vireo_completion_queue_create_with_ops(&options, &allocator, &sync, &queue), VIREO_OK);
    return queue;
}

/**
 * @brief
 *     仅用公开合同创建独立 completion，标签不认证真实网络请求。
 *
 * @param[in] id
 *     非零实例标签与 payload 值。
 *
 * @return
 *     caller 唯一 owner，字节已经复制。
 */
static vireo_completion_t *make_completion(uint64_t id) {
    vireo_completion_metadata_t const metadata = {
        .request = {{7, 0, 3, 11}, id, 2, UINT64_MAX},
        .result = VIREO_RESULT_DATABASE, .suggested_status = VIREO_STATUS_DB_ERROR
    };
    vireo_completion_t *completion = NULL;
    EXPECT(vireo_completion_create_copy(metadata, &id, sizeof(id), 1024, &completion), VIREO_OK);
    return completion;
}

/**
 * @brief
 *     准备局部等待操作表，context 长借至销毁。
 *
 * @param[in,out] queue
 *     无访问、空 OPEN 队列。
 * @param[in,out] f
 *     存活故障记录。
 */
static void prepare(vireo_completion_queue_t *queue, metric_fault_t *f) {
    vireo_completion_queue_wait_ops_t const ops = {
        f, init_cond, lock, wait, signal, broadcast, destroy_cond
    };
    EXPECT(vireo_completion_queue_prepare_wait_with_ops(queue, &ops), VIREO_OK);
}

/**
 * @brief
 *     查询并核验五逻辑字段，不比较成功输出 padding。
 *
 * @param[in] queue
 *     存活短借容器。
 * @param[in] depth
 *     预期条数。
 * @param[in] peak
 *     预期历史条数峰值。
 * @param[in] full
 *     预期满拒绝累计。
 * @param[in] closed
 *     预期关闭拒绝累计。
 * @param[in] saturated
 *     预期永久饱和标志。
 */
static void expect(vireo_completion_queue_t *queue, size_t depth, size_t peak,
    uint64_t full, uint64_t closed, bool saturated) {
    vireo_completion_queue_metrics_t m;
    EXPECT(vireo_completion_queue_inspect_metrics(queue, &m), VIREO_OK);
    CHECK(m.depth == depth && m.high_watermark == peak && m.full_rejections == full);
    CHECK(m.closed_rejections == closed && m.rejection_count_saturated == saturated);
}

/**
 * @brief
 *     mixed try/wait 提交和绕圈，领取后结果尚存活但不计深度；旧快照不跟随。
 */
static void flow(void) {
    metric_fault_t f = {0};
    vireo_completion_queue_t *q = make_queue(3, &f);
    prepare(q, &f);
    vireo_completion_queue_metrics_t initial;
    EXPECT(vireo_completion_queue_inspect_metrics(q, &initial), VIREO_OK);
    expect(q, 0, 0, 0, 0, false);
    vireo_completion_queue_transfer_report_t report;
    for (uint64_t round = 0; round < 3; ++round) {
        for (size_t i = 0; i < 3; ++i) {
            vireo_completion_t *c = make_completion(round * 3 + (uint64_t)i + 1);
            if (i == 1) { EXPECT(vireo_completion_queue_wait_push(q, &c, &report), VIREO_OK); }
            else { EXPECT(vireo_completion_queue_try_push(q, &c, &report), VIREO_OK); }
            CHECK(c == NULL && report.transferred);
            expect(q, i + 1, round == 0 ? i + 1 : 3, 0, 0, false);
        }
        for (size_t i = 0; i < 3; ++i) {
            vireo_completion_t *c = NULL;
            EXPECT(vireo_completion_queue_try_pop(q, &c, &report), VIREO_OK);
            vireo_completion_info_t info;
            EXPECT(vireo_completion_inspect(c, &info), VIREO_OK);
            CHECK(info.metadata.request.request_instance_id == round * 3 + (uint64_t)i + 1);
            expect(q, 2 - i, 3, 0, 0, false);
            EXPECT(vireo_completion_destroy(&c), VIREO_OK);
        }
    }
    CHECK(initial.depth == 0 && initial.high_watermark == 0 && initial.full_rejections == 0);
    vireo_completion_queue_info_t info;
    EXPECT(vireo_completion_queue_inspect(q, &info), VIREO_OK);
    CHECK(info.capacity == 3 && info.count == 0 && info.max_memory_bytes == 4096);
    CHECK(!info.closed && info.wait_prepared);
    CHECK(info.allocated_bytes == sizeof(*q) + 3 * sizeof(vireo_completion_t *));
    vireo_completion_queue_options_t const tight = {3, info.allocated_bytes - 1};
    vireo_completion_queue_t *other = NULL;
    EXPECT(vireo_completion_queue_create(&tight, &other), VIREO_RESULT_RANGE);
    CHECK(other == NULL && f.allocations == 1 && f.frees == 0);
    EXPECT(vireo_completion_queue_destroy(&q), VIREO_OK);
    CHECK(q == NULL && f.frees == 1);
}

/**
 * @brief
 *     基本、未准备、锁失败/等待异常均不计；快照错误整个字节保持。
 */
static void guards(void) {
    metric_fault_t f = {0};
    vireo_completion_queue_t *q = make_queue(1, &f);
    vireo_completion_t *c = make_completion(1), *empty = NULL;
    vireo_completion_queue_transfer_report_t report;
    EXPECT(vireo_completion_queue_try_push(q, &c, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_completion_queue_wait_push(q, &c, &report), VIREO_RESULT_NOT_FOUND);
    EXPECT(vireo_completion_queue_try_push(q, &empty, &report), VIREO_RESULT_NOT_FOUND);
    vireo_completion_queue_metrics_t out;
    unsigned char before[sizeof(out)];
    memset(&out, 0xa5, sizeof(out)); memcpy(before, &out, sizeof(out));
    EXPECT(vireo_completion_queue_inspect_metrics(NULL, &out), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_completion_queue_inspect_metrics(q, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(memcmp(before, &out, sizeof(out)) == 0);
    int const codes[] = {EBUSY, EINVAL};
    for (size_t i = 0; i < 2; ++i) {
        f.lock_error = codes[i];
        vireo_result_t const result = i == 0 ? VIREO_RESULT_BUSY : VIREO_RESULT_INTERNAL;
        EXPECT(vireo_completion_queue_inspect_metrics(q, &out), result);
        CHECK(memcmp(before, &out, sizeof(out)) == 0);
        EXPECT(vireo_completion_queue_try_push(q, &c, &report), result);
        CHECK(c != NULL && !report.transferred);
    }
    f.lock_error = 0; f.unlock_error = EINVAL;
    EXPECT(vireo_completion_queue_inspect_metrics(q, &out), VIREO_RESULT_INTERNAL);
    CHECK(memcmp(before, &out, sizeof(out)) == 0);
    f.unlock_error = 0; expect(q, 0, 0, 0, 0, false);
    prepare(q, &f);
    f.lock_error = EINVAL;
    EXPECT(vireo_completion_queue_wait_push(q, &c, &report), VIREO_RESULT_INTERNAL);
    f.lock_error = 0;
    vireo_completion_t *seed = make_completion(2);
    EXPECT(vireo_completion_queue_try_push(q, &seed, &report), VIREO_OK);
    f.wait_error = EINVAL;
    EXPECT(vireo_completion_queue_wait_push(q, &c, &report), VIREO_RESULT_INTERNAL);
    CHECK(c != NULL && !report.transferred && report.stage == VIREO_COMPLETION_QUEUE_TRANSFER_WAIT);
    expect(q, 1, 1, 0, 0, false);
    f.wait_error = 0;
    EXPECT(vireo_completion_queue_try_pop(q, &seed, &report), VIREO_OK);
    EXPECT(vireo_completion_destroy(&seed), VIREO_OK);
    EXPECT(vireo_completion_destroy(&c), VIREO_OK);
    EXPECT(vireo_completion_queue_destroy(&q), VIREO_OK);
}

/**
 * @brief
 *     真实提交/拒绝后 unlock 异常保留两种提交峰值和两类累计。
 */
static void progress(void) {
    metric_fault_t f = {0};
    vireo_completion_queue_t *q = make_queue(2, &f);
    prepare(q, &f);
    vireo_completion_t *a = make_completion(1), *b = make_completion(2), *extra = make_completion(3);
    vireo_completion_queue_transfer_report_t report;
    f.unlock_error = EPERM;
    EXPECT(vireo_completion_queue_try_push(q, &a, &report), VIREO_RESULT_INTERNAL);
    CHECK(a == NULL && report.transferred);
    EXPECT(vireo_completion_queue_wait_push(q, &b, &report), VIREO_RESULT_INTERNAL);
    CHECK(b == NULL && report.transferred);
    EXPECT(vireo_completion_queue_try_push(q, &extra, &report), VIREO_RESULT_INTERNAL);
    CHECK(extra != NULL && !report.transferred && report.stage == VIREO_COMPLETION_QUEUE_TRANSFER_UNLOCK);
    f.unlock_error = 0; expect(q, 2, 2, 1, 0, false);
    vireo_completion_queue_close_report_t closed;
    EXPECT(vireo_completion_queue_close(q, &closed), VIREO_OK);
    EXPECT(vireo_completion_queue_close(q, &closed), VIREO_OK);
    CHECK(!closed.changed);
    f.unlock_error = EPERM;
    EXPECT(vireo_completion_queue_try_push(q, &extra, &report), VIREO_RESULT_INTERNAL);
    EXPECT(vireo_completion_queue_wait_push(q, &extra, &report), VIREO_RESULT_INTERNAL);
    CHECK(extra != NULL && !report.transferred);
    f.unlock_error = 0; expect(q, 2, 2, 1, 2, false);
    EXPECT(vireo_completion_queue_try_pop(q, &a, &report), VIREO_OK);
    EXPECT(vireo_completion_queue_try_pop(q, &b, &report), VIREO_OK);
    expect(q, 0, 2, 1, 2, false);
    EXPECT(vireo_completion_destroy(&a), VIREO_OK);
    EXPECT(vireo_completion_destroy(&b), VIREO_OK);
    EXPECT(vireo_completion_destroy(&extra), VIREO_OK);
    EXPECT(vireo_completion_queue_destroy(&q), VIREO_OK);
}

/**
 * @brief
 *     外部无访问时仅本核心白盒设置 MAX 边界，不冒执行 MAX 次拒绝。
 */
static void saturation(void) {
    metric_fault_t f = {0};
    vireo_completion_queue_t *q = make_queue(1, &f);
    prepare(q, &f);
    vireo_completion_t *seed = make_completion(1), *extra = make_completion(2);
    vireo_completion_queue_transfer_report_t report;
    EXPECT(vireo_completion_queue_try_push(q, &seed, &report), VIREO_OK);
    q->full_rejections = UINT64_MAX - 1;
    EXPECT(vireo_completion_queue_try_push(q, &extra, &report), VIREO_RESULT_BUSY);
    expect(q, 1, 1, UINT64_MAX, 0, false);
    EXPECT(vireo_completion_queue_try_push(q, &extra, &report), VIREO_RESULT_BUSY);
    expect(q, 1, 1, UINT64_MAX, 0, true);
    vireo_completion_queue_close_report_t closed;
    EXPECT(vireo_completion_queue_close(q, &closed), VIREO_OK);
    EXPECT(vireo_completion_queue_wait_push(q, &extra, &report), VIREO_RESULT_CANCELLED);
    expect(q, 1, 1, UINT64_MAX, 1, true);
    EXPECT(vireo_completion_queue_try_pop(q, &seed, &report), VIREO_OK);
    EXPECT(vireo_completion_destroy(&seed), VIREO_OK);
    EXPECT(vireo_completion_destroy(&extra), VIREO_OK);
    EXPECT(vireo_completion_queue_destroy(&q), VIREO_OK);
    q = make_queue(1, &f); prepare(q, &f); extra = make_completion(3);
    EXPECT(vireo_completion_queue_close(q, &closed), VIREO_OK);
    q->closed_rejections = UINT64_MAX - 1;
    EXPECT(vireo_completion_queue_wait_push(q, &extra, &report), VIREO_RESULT_CANCELLED);
    expect(q, 0, 0, 0, UINT64_MAX, false);
    EXPECT(vireo_completion_queue_try_push(q, &extra, &report), VIREO_RESULT_CANCELLED);
    expect(q, 0, 0, 0, UINT64_MAX, true);
    EXPECT(vireo_completion_destroy(&extra), VIREO_OK);
    EXPECT(vireo_completion_queue_destroy(&q), VIREO_OK);
}

/**
 * @brief
 *     条件变量实际销毁而 mutex 失败后，观测保持输出/errno且不计拒绝。
 */
static void retiring(void) {
    metric_fault_t f = {0};
    vireo_completion_queue_t *q = make_queue(1, &f); prepare(q, &f);
    f.destroy_error = EINVAL;
    EXPECT(vireo_completion_queue_destroy(&q), VIREO_RESULT_INTERNAL);
    CHECK(q != NULL && q->retiring && !q->wait_prepared);
    vireo_completion_queue_metrics_t out;
    unsigned char before[sizeof(out)];
    memset(&out, 0xa5, sizeof(out)); memcpy(before, &out, sizeof(out));
    EXPECT(vireo_completion_queue_inspect_metrics(q, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_completion_queue_inspect_metrics(q, &out), VIREO_RESULT_CANCELLED);
    CHECK(memcmp(before, &out, sizeof(out)) == 0);
    vireo_completion_t *c = make_completion(1);
    vireo_completion_queue_transfer_report_t report;
    EXPECT(vireo_completion_queue_try_push(q, &c, &report), VIREO_RESULT_CANCELLED);
    EXPECT(vireo_completion_queue_wait_push(q, &c, &report), VIREO_RESULT_CANCELLED);
    CHECK(c != NULL && q->full_rejections == 0 && q->closed_rejections == 0);
    EXPECT(vireo_completion_destroy(&c), VIREO_OK);
    f.destroy_error = 0;
    EXPECT(vireo_completion_queue_destroy(&q), VIREO_OK);
}

/** 一次等待提交的线程上下文，由 join 发布最终结果给 main。 */
typedef struct sender {
    vireo_completion_queue_t *queue; /**< 借到该线程 join，main 保活。 */
    vireo_completion_t *owner; /**< worker 唯一源，join 后 main 才读或清理。 */
    vireo_result_t result; /**< 该次 wait_push 原结果，join 后可读。 */
    vireo_completion_queue_transfer_report_t report; /**< 独占报告，join 后可读。 */
} sender_t;

/**
 * @brief
 *     禁用 POSIX 取消后进行一次真实 wait_push。
 *
 * @param[in,out] argument
 *     存活独占 sender，main 到 join 后才访问可变字段。
 *
 * @return
 *     NULL，无其他 owner。
 */
static void *send_one(void *argument) {
    sender_t *s = argument;
    CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL) == 0);
    errno = E2BIG;
    s->result = vireo_completion_queue_wait_push(s->queue, &s->owner, &s->report);
    CHECK(errno == E2BIG);
    return NULL;
}

/**
 * @brief
 *     等到真实 cond_wait 已释放原锁，排除虚假唤醒计数歧义。
 *
 * @param[in,out] q
 *     存活队列，仅测试使用自己的原 mutex。
 * @param[in] f
 *     原子次数与原锁保护的 waiting 记录。
 */
static void await_wait(vireo_completion_queue_t *q, metric_fault_t const *f) {
    for (unsigned i = 0; i < RETRY_LIMIT; ++i) {
        if (atomic_load_explicit(&f->waits, memory_order_acquire) != 0) {
            CHECK(pthread_mutex_lock(&q->mutex) == 0);
            bool const waiting = f->waiting != 0;
            CHECK(pthread_mutex_unlock(&q->mutex) == 0);
            if (waiting) { return; }
        }
        sched_yield();
    }
    CHECK(false);
}

/**
 * @brief
 *     真正满等待/两次虚假醒来不计满拒绝，pop 后提交更新峰值。
 */
static void waiting_space(void) {
    metric_fault_t f = {0};
    vireo_completion_queue_t *q = make_queue(1, &f); prepare(q, &f);
    f.spurious = 2;
    vireo_completion_t *seed = make_completion(1);
    vireo_completion_queue_transfer_report_t report;
    EXPECT(vireo_completion_queue_try_push(q, &seed, &report), VIREO_OK);
    sender_t s = {q, make_completion(2), VIREO_OK, {0}};
    pthread_t thread;
    CHECK(pthread_create(&thread, NULL, send_one, &s) == 0);
    await_wait(q, &f);
    expect(q, 1, 1, 0, 0, false);
    EXPECT(vireo_completion_queue_try_pop(q, &seed, &report), VIREO_OK);
    CHECK(pthread_join(thread, NULL) == 0);
    CHECK(s.result == VIREO_OK && s.owner == NULL && s.report.transferred);
    expect(q, 1, 1, 0, 0, false);
    EXPECT(vireo_completion_destroy(&seed), VIREO_OK);
    EXPECT(vireo_completion_queue_try_pop(q, &seed, &report), VIREO_OK);
    EXPECT(vireo_completion_destroy(&seed), VIREO_OK);
    EXPECT(vireo_completion_queue_destroy(&q), VIREO_OK);
}

/**
 * @brief
 *     真正满等待被 close 广播唤醒，只计一次关闭拒绝，仍保源与 FIFO 原项。
 */
static void waiting_close(void) {
    metric_fault_t f = {0};
    vireo_completion_queue_t *q = make_queue(1, &f); prepare(q, &f);
    f.spurious = 2;
    vireo_completion_t *seed = make_completion(1);
    vireo_completion_queue_transfer_report_t report;
    EXPECT(vireo_completion_queue_try_push(q, &seed, &report), VIREO_OK);
    sender_t s = {q, make_completion(2), VIREO_OK, {0}};
    pthread_t thread;
    CHECK(pthread_create(&thread, NULL, send_one, &s) == 0);
    await_wait(q, &f); expect(q, 1, 1, 0, 0, false);
    vireo_completion_queue_close_report_t closed;
    EXPECT(vireo_completion_queue_close(q, &closed), VIREO_OK);
    CHECK(pthread_join(thread, NULL) == 0);
    CHECK(s.result == VIREO_RESULT_CANCELLED && s.owner != NULL && !s.report.transferred);
    expect(q, 1, 1, 0, 1, false);
    EXPECT(vireo_completion_queue_wait_push(q, &s.owner, &report), VIREO_RESULT_CANCELLED);
    expect(q, 1, 1, 0, 2, false);
    EXPECT(vireo_completion_destroy(&s.owner), VIREO_OK);
    EXPECT(vireo_completion_queue_try_pop(q, &seed, &report), VIREO_OK);
    EXPECT(vireo_completion_destroy(&seed), VIREO_OK);
    expect(q, 0, 1, 0, 2, false);
    EXPECT(vireo_completion_queue_destroy(&q), VIREO_OK);
}

/** 实际锁竞争线程的独占输入。 */
typedef struct contender {
    vireo_completion_queue_t *queue; /**< 借至 join，main 持原锁且保活。 */
    vireo_completion_t *owner; /**< worker 源未转移，join 后 main 配对销毁。 */
} contender_t;

/**
 * @brief
 *     主线程持锁至 join 时，真实竞争 BUSY 保持快照与 owner，不计拒绝。
 *
 * @param[in,out] argument
 *     存活独占 contender。
 *
 * @return
 *     NULL，无额外 owner。
 */
static void *contend(void *argument) {
    contender_t *c = argument;
    vireo_completion_queue_metrics_t out;
    unsigned char before[sizeof(out)];
    memset(&out, 0xa5, sizeof(out)); memcpy(before, &out, sizeof(out));
    EXPECT(vireo_completion_queue_inspect_metrics(c->queue, &out), VIREO_RESULT_BUSY);
    CHECK(memcmp(before, &out, sizeof(out)) == 0);
    vireo_completion_queue_transfer_report_t report;
    EXPECT(vireo_completion_queue_try_push(c->queue, &c->owner, &report), VIREO_RESULT_BUSY);
    CHECK(c->owner != NULL && !report.transferred && report.pthread_error == EBUSY);
    return NULL;
}

/** 固定满队列的多 producer oracle。 */
typedef struct producer {
    vireo_completion_queue_t *queue; /**< main 保活且保持满 OPEN，借至全部 join。 */
    atomic_bool *start; /**< main release 开门，worker acquire 读；不替代队列同步。 */
    uint64_t id; /**< 各 worker 独立完成对象标签。 */
} producer_t;

/**
 * @brief
 *     每线程只累积 500 次真正容量拒绝，锁竞争不计 oracle。
 *
 * @param[in] argument
 *     存活只读 producer 输入。
 *
 * @return
 *     NULL，该线程未提交的 owner 已自行销毁。
 */
static void *produce(void *argument) {
    producer_t const *p = argument;
    vireo_completion_t *c = make_completion(p->id);
    while (!atomic_load_explicit(p->start, memory_order_acquire)) { sched_yield(); }
    unsigned rejected = 0;
    for (unsigned attempt = 0; rejected < 500 && attempt < RETRY_LIMIT; ++attempt) {
        vireo_completion_queue_transfer_report_t report;
        EXPECT(vireo_completion_queue_try_push(p->queue, &c, &report), VIREO_RESULT_BUSY);
        CHECK(c != NULL && !report.transferred);
        if (report.stage == VIREO_COMPLETION_QUEUE_TRANSFER_NONE) {
            CHECK(report.pthread_error == 0); ++rejected;
        } else {
            CHECK(report.stage == VIREO_COMPLETION_QUEUE_TRANSFER_LOCK && report.pthread_error == EBUSY);
            sched_yield();
        }
        vireo_completion_queue_metrics_t m;
        errno = E2BIG;
        vireo_result_t const result = vireo_completion_queue_inspect_metrics(p->queue, &m);
        CHECK(errno == E2BIG && (result == VIREO_OK || result == VIREO_RESULT_BUSY));
        if (result == VIREO_OK) {
            CHECK(m.depth == 3 && m.high_watermark == 3 && m.full_rejections > 0);
            CHECK(m.full_rejections <= 1500 && m.closed_rejections == 0 && !m.rejection_count_saturated);
        }
    }
    CHECK(rejected == 500);
    EXPECT(vireo_completion_destroy(&c), VIREO_OK);
    return NULL;
}

/**
 * @brief
 *     真实锁竞争与三 producer 的 1500 次精确容量拒绝，无 sleep 或共享 owner。
 */
static void concurrency(void) {
    vireo_completion_queue_options_t const options = {3, 4096};
    vireo_completion_queue_t *q = NULL;
    EXPECT(vireo_completion_queue_create(&options, &q), VIREO_OK);
    contender_t c = {q, make_completion(9)};
    pthread_t thread;
    CHECK(pthread_mutex_lock(&q->mutex) == 0);
    CHECK(pthread_create(&thread, NULL, contend, &c) == 0);
    CHECK(pthread_join(thread, NULL) == 0);
    CHECK(pthread_mutex_unlock(&q->mutex) == 0);
    expect(q, 0, 0, 0, 0, false);
    EXPECT(vireo_completion_destroy(&c.owner), VIREO_OK);
    vireo_completion_queue_transfer_report_t report;
    for (uint64_t id = 1; id <= 3; ++id) {
        vireo_completion_t *seed = make_completion(id);
        EXPECT(vireo_completion_queue_try_push(q, &seed, &report), VIREO_OK);
    }
    atomic_bool start; atomic_init(&start, false);
    producer_t producers[3]; pthread_t threads[3];
    for (size_t i = 0; i < 3; ++i) {
        producers[i] = (producer_t){q, &start, (uint64_t)i + 10};
        CHECK(pthread_create(&threads[i], NULL, produce, &producers[i]) == 0);
    }
    atomic_store_explicit(&start, true, memory_order_release);
    for (size_t i = 0; i < 3; ++i) { CHECK(pthread_join(threads[i], NULL) == 0); }
    expect(q, 3, 3, 1500, 0, false);
    for (size_t i = 0; i < 3; ++i) {
        vireo_completion_t *seed = NULL;
        EXPECT(vireo_completion_queue_try_pop(q, &seed, &report), VIREO_OK);
        EXPECT(vireo_completion_destroy(&seed), VIREO_OK);
    }
    EXPECT(vireo_completion_queue_destroy(&q), VIREO_OK);
}

/**
 * @brief
 *     全调用禁用 POSIX 取消，依次执行八个有区分力的实际测试组。
 *
 * @return
 *     成功 0；CHECK 失败直接终止以保护仍存活线程的输入寿命。
 */
int main(void) {
    int previous = 0;
    CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previous) == 0);
    flow(); guards(); progress(); saturation(); retiring();
    waiting_space(); waiting_close(); concurrency();
    CHECK(pthread_setcancelstate(previous, NULL) == 0);
    puts("test_completion_queue_metrics: 8 groups PASS");
    return 0;
}
