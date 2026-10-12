/*
 * PROJECT : VIREO
 * FILE    : test_completion_queue_wait.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-12
 * BRIEF   : worker容量等待、pop空间提示、永久关闭广播与真实失败进度
 */
#include "thread/completion_queue_internal.h"

#include <errno.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 失败终止测试进程，不让仍存活线程访问已返回的栈上下文。 */
#define CHECK(c) do { if (!(c)) { \
    fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #c); abort(); \
} } while (0)

/**
 * @brief
 *     本测试局部同步故障与调用记录；并发时只修改atomic等待计数。
 */
typedef struct wait_trace {
    int init_error; /**< 初始化失败，不初始化真实cond。 */
    int lock_error; /**< 获取mutex前直接失败。 */
    int wait_error; /**< 持mutex返回错误，不释放锁。 */
    int signal_error; /**< 不执行通知，模拟通知失败。 */
    int broadcast_error; /**< 不执行广播，模拟广播失败。 */
    int cond_destroy_error; /**< 失败保留真实cond。 */
    int mutex_destroy_error; /**< 失败保留真实mutex。 */
    int unlock_error; /**< 真实解锁后返回注入错误。 */
    unsigned init_calls; /**< 外部无访问期间初始化调用次数。 */
    unsigned signal_calls; /**< 原mutex保护的signal调用次数。 */
    unsigned broadcast_calls; /**< 原mutex保护的broadcast调用次数。 */
    unsigned cond_destroy_calls; /**< 外部无访问期间cond销毁调用次数。 */
    unsigned mutex_destroy_calls; /**< 外部无访问期间mutex销毁调用次数。 */
    unsigned spurious; /**< 原mutex保护的有限虚假唤醒次数。 */
    unsigned waiting; /**< 原mutex保护的当前真实cond_wait调用数，排除虚假醒来累计计数歧义。 */
    size_t allocations; /**< 控制块真实申请次数，无并发时访问。 */
    size_t frees; /**< 配对释放次数，无并发时访问。 */
    atomic_uint waits; /**< 每次wait入口发布计数，main据此握手。 */
} wait_trace_t;

/**
 * @brief
 *     cond初始化故障适配，不留下半初始化资源。
 *
 * @param[in,out] ctx
 *     存活局部记录。
 * @param[out] cond
 *     未初始化资源。
 *
 * @return
 *     真实pthread或注入错误码。
 */
static int cond_init(void *ctx, pthread_cond_t *cond) {
    wait_trace_t *t = ctx;
    ++t->init_calls;
    errno = EIO;
    return t->init_error != 0 ? t->init_error : pthread_cond_init(cond, NULL);
}

/**
 * @brief
 *     阻塞加锁或在取得锁之前拒绝。
 *
 * @param[in] ctx
 *     不并发修改故障字段的存活记录。
 * @param[in,out] mutex
 *     原存活mutex。
 *
 * @return
 *     直接错误码，非0未取得锁。
 */
static int blocking_lock(void *ctx, pthread_mutex_t *mutex) {
    wait_trace_t *t = ctx;
    errno = EIO;
    return t->lock_error != 0 ? t->lock_error : pthread_mutex_lock(mutex);
}

/**
 * @brief
 *     记录真实等待入口；有限虚假醒来与失败均保持mutex持有。
 *
 * @param[in,out] ctx
 *     原mutex保护字段和atomic计数。
 * @param[in,out] cond
 *     真实存活cond。
 * @param[in,out] mutex
 *     本线程持有的原mutex。
 *
 * @return
 *     直接错误码或真实等待结果，返回仍持mutex。
 */
static int cond_wait(void *ctx, pthread_cond_t *cond, pthread_mutex_t *mutex) {
    wait_trace_t *t = ctx;
    atomic_fetch_add_explicit(&t->waits, 1, memory_order_release);
    errno = EIO;
    if (t->wait_error != 0) {
        return t->wait_error;
    }
    if (t->spurious != 0) {
        --t->spurious;
        return 0;
    }
    ++t->waiting;
    int const code = pthread_cond_wait(cond, mutex);
    --t->waiting;
    return code;
}

/**
 * @brief
 *     提交通知记录，失败不撤销已提交task。
 *
 * @param[in,out] ctx
 *     原mutex保护记录。
 * @param[in,out] cond
 *     存活cond。
 *
 * @return
 *     真实或注入直接错误码。
 */
static int cond_signal(void *ctx, pthread_cond_t *cond) {
    wait_trace_t *t = ctx;
    ++t->signal_calls;
    errno = EIO;
    return t->signal_error != 0 ? t->signal_error : pthread_cond_signal(cond);
}

/**
 * @brief
 *     关闭广播记录，失败保留关闭提交。
 *
 * @param[in,out] ctx
 *     原mutex保护记录。
 * @param[in,out] cond
 *     存活cond。
 *
 * @return
 *     真实或注入直接错误码。
 */
static int cond_broadcast(void *ctx, pthread_cond_t *cond) {
    wait_trace_t *t = ctx;
    ++t->broadcast_calls;
    errno = EIO;
    return t->broadcast_error != 0 ? t->broadcast_error : pthread_cond_broadcast(cond);
}

/**
 * @brief
 *     cond销毁故障，失败不执行真实销毁。
 *
 * @param[in,out] ctx
 *     外部已排除访问的记录。
 * @param[in,out] cond
 *     无访问的存活资源。
 *
 * @return
 *     真实或注入直接错误码。
 */
static int cond_destroy(void *ctx, pthread_cond_t *cond) {
    wait_trace_t *t = ctx;
    ++t->cond_destroy_calls;
    errno = EIO;
    return t->cond_destroy_error != 0 ? t->cond_destroy_error : pthread_cond_destroy(cond);
}

/**
 * @brief
 *     默认mutex初始化，与等待适配共享记录寿命。
 *
 * @param[in] ctx
 *     未使用，可NULL。
 * @param[out] mutex
 *     尚未初始化资源。
 *
 * @return
 *     pthread直接错误。
 */
static int mutex_init(void *ctx, pthread_mutex_t *mutex) {
    (void)ctx;
    return pthread_mutex_init(mutex, NULL);
}

/**
 * @brief
 *     原try接口仍只尝试一次，不等待。
 *
 * @param[in] ctx
 *     未使用，可NULL。
 * @param[in,out] mutex
 *     存活资源。
 *
 * @return
 *     pthread直接错误。
 */
static int try_lock(void *ctx, pthread_mutex_t *mutex) {
    (void)ctx;
    return pthread_mutex_trylock(mutex);
}

/**
 * @brief
 *     真实解锁后可注入错误，保留已发生进度。
 *
 * @param[in] ctx
 *     存活记录，故障值不在访问期间修改。
 * @param[in,out] mutex
 *     本线程持有资源。
 *
 * @return
 *     真实失败优先，或注入错误。
 */
static int unlock(void *ctx, pthread_mutex_t *mutex) {
    wait_trace_t *t = ctx;
    int const code = pthread_mutex_unlock(mutex);
    errno = EIO;
    return code != 0 ? code : t->unlock_error;
}

/**
 * @brief
 *     mutex销毁计数，失败保留资源供重试。
 *
 * @param[in,out] ctx
 *     无并发访问的存活记录。
 * @param[in,out] mutex
 *     无访问资源。
 *
 * @return
 *     真实或注入直接错误。
 */
static int mutex_destroy(void *ctx, pthread_mutex_t *mutex) {
    wait_trace_t *t = ctx;
    ++t->mutex_destroy_calls;
    errno = EIO;
    return t->mutex_destroy_error != 0 ? t->mutex_destroy_error : pthread_mutex_destroy(mutex);
}

/**
 * @brief
 *     本核心容器申请适配。
 *
 * @param[in] ctx
 *     存活局部申请计数，不在有访问时修改。
 * @param[in] bytes
 *     受检正申请量。
 *
 * @return
 *     新独占原块或NULL。
 */
static void *allocate(void *ctx, size_t bytes) {
    wait_trace_t *t = ctx;
    ++t->allocations;
    return malloc(bytes);
}

/**
 * @brief
 *     配对释放无访问原块。
 *
 * @param[in] ctx
 *     存活局部释放计数，全部访问已结束。
 * @param[in] ptr
 *     唯一原块。
 *
 * @note
 *     不释放completion或记录上下文。
 */
static void deallocate(void *ctx, void *ptr) {
    wait_trace_t *t = ctx;
    ++t->frees;
    free(ptr);
}

/**
 * @brief
 *     生成按值等待操作副本，context借至queue销毁。
 *
 * @param[in,out] t
 *     稳定局部记录。
 *
 * @return
 *     本核心有效操作表。
 */
static vireo_completion_queue_wait_ops_t wait_ops(wait_trace_t *t) {
    vireo_completion_queue_wait_ops_t const ops = {
        t, cond_init, blocking_lock, cond_wait, cond_signal, cond_broadcast, cond_destroy
    };
    return ops;
}

/**
 * @brief
 *     创建固定三槽queue，不prepare，测试负责销毁。
 *
 * @param[in,out] t
 *     已初始化且存活到销毁的记录。
 *
 * @return
 *     唯一queue owner，失败终止进程。
 */
static vireo_completion_queue_t *new_queue(wait_trace_t *t) {
    vireo_completion_queue_options_t const opts = {3, 4096};
    vireo_completion_queue_allocator_t const alloc = {t, allocate, deallocate};
    vireo_completion_queue_sync_t const sync = {t, mutex_init, try_lock, unlock, mutex_destroy};
    vireo_completion_queue_t *q = NULL;
    CHECK(vireo_completion_queue_create_with_ops(&opts, &alloc, &sync, &q) == VIREO_OK);
    return q;
}


/* 每次工程调用核验 errno；线程入口自身禁用取消，不将测试harness重试写成库行为。 */
#define EXPECT(expr, expected) do { \
    errno = E2BIG; \
    vireo_result_t const got = (expr); \
    CHECK(got == (expected) && errno == E2BIG); \
} while (0)
#define RETRY_LIMIT 2000000U

/**
 * @brief
 *     生成独立完成字节副本，返回唯一 owner。
 *
 * @param[in] id
 *     非零实例标签和 payload 校验值。
 *
 * @return
 *     caller 自有 completion，失败终止测试进程。
 */
static vireo_completion_t *new_completion(uint64_t id) {
    vireo_completion_metadata_t const metadata = {
        .request = {{7, 0, 3, 11}, id, 2, UINT64_MAX},
        .result = VIREO_RESULT_DATABASE,
        .suggested_status = VIREO_STATUS_DB_ERROR
    };
    uint64_t bytes[2] = {id, id ^ UINT64_C(0xdeadbeef12345678)};
    vireo_completion_t *owner = NULL;
    EXPECT(vireo_completion_create_copy(metadata, bytes, sizeof(bytes), 1024, &owner), VIREO_OK);
    memset(bytes, 0, sizeof(bytes));
    return owner;
}

/**
 * @brief
 *     只通过公开快照与短借核验返回结果，借用在返回前结束。
 *
 * @param[in] owner
 *     caller 唯一拥有的 completion，不在本函数销毁。
 *
 * @return
 *     经元数据和两校验字一致性核验的实例号。
 */
static uint64_t completion_id(vireo_completion_t *owner) {
    vireo_completion_info_t info;
    vireo_completion_payload_view_t view;
    EXPECT(vireo_completion_inspect(owner, &info), VIREO_OK);
    EXPECT(vireo_completion_borrow_payload(owner, &view), VIREO_OK);
    uint64_t bytes[2];
    CHECK(view.size == sizeof(bytes));
    memcpy(bytes, view.data, sizeof(bytes));
    CHECK(bytes[0] == info.metadata.request.request_instance_id);
    CHECK(bytes[1] == (bytes[0] ^ UINT64_C(0xdeadbeef12345678)));
    CHECK(info.metadata.result == VIREO_RESULT_DATABASE &&
        info.metadata.suggested_status == VIREO_STATUS_DB_ERROR);
    return bytes[0];
}

/**
 * @brief
 *     单消费者的有限 try 领取harness，仅临时空/竞争时yield。
 *
 * @param[in,out] q
 *     存活队列，主线程独占consumer角色。
 *
 * @return
 *     成功转出的唯一completion，caller负责处理销毁；超过预算终止进程。
 */
static vireo_completion_t *pop(vireo_completion_queue_t *q) {
    vireo_completion_t *out = NULL;
    for (unsigned i = 0; i < RETRY_LIMIT; ++i) {
        vireo_completion_queue_transfer_report_t report;
        errno = E2BIG;
        vireo_result_t const result = vireo_completion_queue_try_pop(q, &out, &report);
        CHECK(errno == E2BIG);
        if (result == VIREO_OK) {
            CHECK(report.transferred && out != NULL);
            return out;
        }
        CHECK((result == VIREO_RESULT_BUSY || result == VIREO_RESULT_NOT_FOUND) &&
            !report.transferred && out == NULL);
        sched_yield();
    }
    CHECK(false);
    return NULL;
}

/**
 * @brief
 *     仅测试调用者有限重试close，产品入口仍一次try。
 *
 * @param[in,out] q
 *     存活队列，无销毁并发。
 *
 * @note
 *     只接受真实锁竞争，其他失败终止进程。
 */
static void close_queue(vireo_completion_queue_t *q) {
    for (unsigned i = 0; i < RETRY_LIMIT; ++i) {
        vireo_completion_queue_close_report_t report;
        errno = E2BIG;
        vireo_result_t const result = vireo_completion_queue_close(q, &report);
        CHECK(errno == E2BIG);
        if (result == VIREO_OK) {
            return;
        }
        CHECK(result == VIREO_RESULT_BUSY && !report.changed);
        sched_yield();
    }
    CHECK(false);
}

/**
 * @brief
 *     atomic入口计数与原mutex握手证明真实等待，无sleep猜测。
 *
 * @param[in,out] q
 *     存活队列，测试为此核心可观察原mutex。
 * @param[in] t
 *     生存至全部join后的计数记录，仅atomic waits跨线程读。
 * @param[in] n
 *     预期至少进入wait的次数。
 * @param[in] min_waiting
 *     同原mutex内必须同时存在的真实等待者数量，不把虚假唤醒算成新线程。
 *
 * @note
 *     虚假唤醒耗尽后再握手；取得mutex说明最后进入者已释放原mutex。
 */
static void await_wait(vireo_completion_queue_t *q, wait_trace_t const *t, unsigned n,
    unsigned min_waiting) {
    for (unsigned i = 0; i < RETRY_LIMIT; ++i) {
        if (atomic_load_explicit(&t->waits, memory_order_acquire) >= n) {
            CHECK(pthread_mutex_lock(&q->mutex) == 0);
            bool const ready = t->waiting >= min_waiting;
            CHECK(pthread_mutex_unlock(&q->mutex) == 0);
            if (ready) {
                return;
            }
        }
        sched_yield();
    }
    CHECK(false);
}

/** 一次生产交接的独占记录，main只在对应join后读输出。 */
typedef struct sender {
    vireo_completion_queue_t *queue; /**< 借至线程返回，queue销毁在全部join后。 */
    vireo_completion_t *owner; /**< worker唯一源；失败由join后的main接回清理。 */
    vireo_result_t result; /**< wait_push实际返回值。 */
    vireo_completion_queue_transfer_report_t report; /**< 实际同步阶段和转移。 */
} sender_t;

/**
 * @brief
 *     worker禁用POSIX取消，执行一次生产等待。
 *
 * @param[in,out] arg
 *     caller已发布的独占sender，输出只在join后读。
 *
 * @return
 *     NULL，不销毁保留源，清理义务随join转交main。
 */
static void *send_one(void *arg) {
    sender_t *s = arg;
    int old = 0;
    CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &old) == 0);
    errno = EDOM;
    s->result = vireo_completion_queue_wait_push(s->queue, &s->owner, &s->report);
    CHECK(errno == EDOM);
    CHECK(pthread_setcancelstate(old, NULL) == 0);
    return NULL;
}

/**
 * @brief
 *     填满三槽，源均经公开wait入口转移，返回时无局部owner。
 *
 * @param[in,out] q
 *     已prepare空三槽队列，本函数期间无其他访问。
 *
 * @note
 *     固定三个独立结果，成功后queue唯一拥有，失败终止测试进程。
 */
static void fill(vireo_completion_queue_t *q) {
    for (uint64_t id = 1; id <= 3; ++id) {
        vireo_completion_t *owner = new_completion(id);
        vireo_completion_queue_transfer_report_t report;
        EXPECT(vireo_completion_queue_wait_push(q, &owner, &report), VIREO_OK);
        CHECK(owner == NULL && report.transferred);
    }
}

/** 空OPEN重复prepare、真实初始化失败保持、操作表副本和实际申请量。 */
static void preparation(void) {
    wait_trace_t t = {0};
    atomic_init(&t.waits, 0);
    vireo_completion_queue_t *q = new_queue(&t);
    vireo_completion_queue_info_t info;
    EXPECT(vireo_completion_queue_inspect(q, &info), VIREO_OK);
    CHECK(!info.wait_prepared && !info.closed && info.count == 0);
    vireo_completion_t *owner = new_completion(1);
    vireo_completion_queue_transfer_report_t report;
    EXPECT(vireo_completion_queue_wait_push(q, &owner, &report), VIREO_RESULT_NOT_FOUND);
    CHECK(owner != NULL && !report.transferred);
    EXPECT(vireo_completion_queue_prepare_wait(NULL), VIREO_RESULT_INVALID_ARGUMENT);
    vireo_completion_queue_wait_ops_t ops = wait_ops(&t);
    EXPECT(vireo_completion_queue_prepare_wait_with_ops(q, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    vireo_completion_queue_wait_ops_t bad = ops;
    bad.wait = NULL;
    EXPECT(vireo_completion_queue_prepare_wait_with_ops(q, &bad), VIREO_RESULT_INVALID_ARGUMENT);
    t.init_error = ENOMEM;
    EXPECT(vireo_completion_queue_prepare_wait_with_ops(q, &ops), VIREO_RESULT_NO_MEMORY);
    CHECK(!q->wait_prepared && !q->retiring && t.init_calls == 1);
    t.init_error = EAGAIN;
    EXPECT(vireo_completion_queue_prepare_wait_with_ops(q, &ops), VIREO_RESULT_INTERNAL);
    CHECK(!q->wait_prepared && t.init_calls == 2);
    t.init_error = 0;
    EXPECT(vireo_completion_queue_prepare_wait_with_ops(q, &ops), VIREO_OK);
    ops.context = NULL;
    ops.wait = NULL;
    EXPECT(vireo_completion_queue_prepare_wait(q), VIREO_OK);
    CHECK(t.init_calls == 3 && t.allocations == 1);
    EXPECT(vireo_completion_queue_inspect(q, &info), VIREO_OK);
    CHECK(info.wait_prepared && info.allocated_bytes == sizeof(*q) + 3 * sizeof(owner));
    EXPECT(vireo_completion_queue_wait_push(q, &owner, &report), VIREO_OK);
    EXPECT(vireo_completion_queue_prepare_wait(q), VIREO_RESULT_BUSY);
    EXPECT(vireo_completion_queue_destroy(&q), VIREO_RESULT_BUSY);
    CHECK(t.cond_destroy_calls == 0);
    owner = pop(q);
    CHECK(completion_id(owner) == 1);
    EXPECT(vireo_completion_destroy(&owner), VIREO_OK);
    close_queue(q);
    EXPECT(vireo_completion_queue_prepare_wait(q), VIREO_RESULT_BUSY);
    EXPECT(vireo_completion_queue_destroy(&q), VIREO_OK);
    CHECK(q == NULL && t.cond_destroy_calls == 1 && t.mutex_destroy_calls == 1 &&
        t.allocations == 1 && t.frees == 1);
    EXPECT(vireo_completion_queue_destroy(&q), VIREO_OK);
}

/** 必需地址优先、空源优先、关闭但未prepare仍NOT_FOUND，关闭优先空余容量。 */
static void invalid_and_precedence(void) {
    wait_trace_t t = {0};
    atomic_init(&t.waits, 0);
    vireo_completion_queue_t *q = new_queue(&t);
    vireo_completion_t *owner = NULL;
    vireo_completion_queue_transfer_report_t report;
    EXPECT(vireo_completion_queue_wait_push(NULL, &owner, &report), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(report.stage == VIREO_COMPLETION_QUEUE_TRANSFER_NONE && !report.transferred &&
        report.pthread_error == 0);
    EXPECT(vireo_completion_queue_wait_push(q, NULL, &report), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_completion_queue_wait_push(q, &owner, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_completion_queue_wait_push(q, &owner, &report), VIREO_RESULT_NOT_FOUND);
    close_queue(q);
    owner = new_completion(1);
    vireo_completion_t *saved = owner;
    EXPECT(vireo_completion_queue_wait_push(q, &owner, &report), VIREO_RESULT_NOT_FOUND);
    CHECK(owner == saved && !report.transferred);
    EXPECT(vireo_completion_queue_try_push(q, &owner, &report), VIREO_RESULT_CANCELLED);
    EXPECT(vireo_completion_destroy(&owner), VIREO_OK);
    EXPECT(vireo_completion_queue_destroy(&q), VIREO_OK);
    q = new_queue(&t);
    vireo_completion_queue_wait_ops_t const ops = wait_ops(&t);
    EXPECT(vireo_completion_queue_prepare_wait_with_ops(q, &ops), VIREO_OK);
    close_queue(q);
    owner = new_completion(2);
    saved = owner;
    EXPECT(vireo_completion_queue_wait_push(q, &owner, &report), VIREO_RESULT_CANCELLED);
    CHECK(owner == saved && !report.transferred && report.pthread_error == 0);
    EXPECT(vireo_completion_destroy(&owner), VIREO_OK);
    EXPECT(vireo_completion_queue_destroy(&q), VIREO_OK);
}

/** wait提交与try领取混用仍FIFO，任意容量3按条件回绕。 */
static void fifo_and_wrap(void) {
    vireo_completion_queue_options_t const opts = {3, 4096};
    vireo_completion_queue_t *q = NULL;
    EXPECT(vireo_completion_queue_create(&opts, &q), VIREO_OK);
    EXPECT(vireo_completion_queue_prepare_wait(q), VIREO_OK);
    fill(q);
    for (uint64_t id = 1; id <= 7; ++id) {
        vireo_completion_t *out = pop(q);
        CHECK(completion_id(out) == id);
        EXPECT(vireo_completion_destroy(&out), VIREO_OK);
        if (id <= 4) {
            out = new_completion(id + 3);
            vireo_completion_queue_transfer_report_t report;
            EXPECT(vireo_completion_queue_wait_push(q, &out, &report), VIREO_OK);
            CHECK(out == NULL && report.transferred && report.stage == VIREO_COMPLETION_QUEUE_TRANSFER_NONE);
        }
    }
    close_queue(q);
    vireo_completion_t *out = NULL;
    vireo_completion_queue_transfer_report_t report;
    EXPECT(vireo_completion_queue_try_pop(q, &out, &report), VIREO_RESULT_CANCELLED);
    EXPECT(vireo_completion_queue_destroy(&q), VIREO_OK);
}

/** 阻塞加锁/满表wait错误保持源，unlock错误覆盖WAIT诊断，不改变队列归属。 */
static void wait_failures(void) {
    wait_trace_t t = {0};
    atomic_init(&t.waits, 0);
    vireo_completion_queue_t *q = new_queue(&t);
    vireo_completion_queue_wait_ops_t const ops = wait_ops(&t);
    EXPECT(vireo_completion_queue_prepare_wait_with_ops(q, &ops), VIREO_OK);
    fill(q);
    vireo_completion_t *owner = new_completion(4);
    vireo_completion_t *saved = owner;
    vireo_completion_queue_transfer_report_t report;
    t.lock_error = EBUSY;
    EXPECT(vireo_completion_queue_wait_push(q, &owner, &report), VIREO_RESULT_INTERNAL);
    CHECK(report.stage == VIREO_COMPLETION_QUEUE_TRANSFER_LOCK && report.pthread_error == EBUSY &&
        !report.transferred && owner == saved);
    t.lock_error = EINVAL;
    EXPECT(vireo_completion_queue_wait_push(q, &owner, &report), VIREO_RESULT_INTERNAL);
    CHECK(report.pthread_error == EINVAL && atomic_load(&t.waits) == 0);
    t.lock_error = 0;
    t.wait_error = EIO;
    EXPECT(vireo_completion_queue_wait_push(q, &owner, &report), VIREO_RESULT_INTERNAL);
    CHECK(report.stage == VIREO_COMPLETION_QUEUE_TRANSFER_WAIT && report.pthread_error == EIO &&
        !report.transferred && owner == saved && q->count == 3);
    t.unlock_error = EFAULT;
    EXPECT(vireo_completion_queue_wait_push(q, &owner, &report), VIREO_RESULT_INTERNAL);
    CHECK(report.stage == VIREO_COMPLETION_QUEUE_TRANSFER_UNLOCK && report.pthread_error == EFAULT &&
        !report.transferred && owner == saved && q->count == 3);
    t.unlock_error = 0;
    t.wait_error = 0;
    CHECK(completion_id(owner) == 4);
    EXPECT(vireo_completion_destroy(&owner), VIREO_OK);
    for (uint64_t id = 1; id <= 3; ++id) {
        owner = pop(q);
        CHECK(completion_id(owner) == id);
        EXPECT(vireo_completion_destroy(&owner), VIREO_OK);
    }
    EXPECT(vireo_completion_queue_destroy(&q), VIREO_OK);
}

/** wait成功提交后的真实unlock失败仍清源；关闭拒绝后的unlock失败仍保源。 */
static void wait_unlock_progress(void) {
    wait_trace_t t = {0};
    atomic_init(&t.waits, 0);
    vireo_completion_queue_t *q = new_queue(&t);
    vireo_completion_queue_wait_ops_t const ops = wait_ops(&t);
    EXPECT(vireo_completion_queue_prepare_wait_with_ops(q, &ops), VIREO_OK);
    vireo_completion_t *owner = new_completion(1);
    vireo_completion_queue_transfer_report_t report;
    t.unlock_error = EIO;
    EXPECT(vireo_completion_queue_wait_push(q, &owner, &report), VIREO_RESULT_INTERNAL);
    CHECK(owner == NULL && report.transferred && report.stage == VIREO_COMPLETION_QUEUE_TRANSFER_UNLOCK &&
        report.pthread_error == EIO && q->count == 1);
    t.unlock_error = 0;
    owner = pop(q);
    CHECK(completion_id(owner) == 1);
    EXPECT(vireo_completion_destroy(&owner), VIREO_OK);
    close_queue(q);
    owner = new_completion(2);
    vireo_completion_t *saved = owner;
    t.unlock_error = EINVAL;
    EXPECT(vireo_completion_queue_wait_push(q, &owner, &report), VIREO_RESULT_INTERNAL);
    CHECK(owner == saved && !report.transferred && report.stage == VIREO_COMPLETION_QUEUE_TRANSFER_UNLOCK);
    t.unlock_error = 0;
    EXPECT(vireo_completion_destroy(&owner), VIREO_OK);
    EXPECT(vireo_completion_queue_destroy(&q), VIREO_OK);
}

/** pop信号/close广播失败保真实提交，unlock双错优先；重复close再广播。 */
static void notification_progress(void) {
    wait_trace_t t = {0};
    atomic_init(&t.waits, 0);
    vireo_completion_queue_t *q = new_queue(&t);
    vireo_completion_queue_wait_ops_t const ops = wait_ops(&t);
    EXPECT(vireo_completion_queue_prepare_wait_with_ops(q, &ops), VIREO_OK);
    fill(q);
    t.signal_error = EIO;
    vireo_completion_t *out = NULL;
    vireo_completion_queue_transfer_report_t report;
    EXPECT(vireo_completion_queue_try_pop(q, &out, &report), VIREO_RESULT_INTERNAL);
    CHECK(report.transferred && report.stage == VIREO_COMPLETION_QUEUE_TRANSFER_WAKE &&
        report.pthread_error == EIO && q->count == 2 && completion_id(out) == 1);
    EXPECT(vireo_completion_destroy(&out), VIREO_OK);
    t.unlock_error = EFAULT;
    EXPECT(vireo_completion_queue_try_pop(q, &out, &report), VIREO_RESULT_INTERNAL);
    CHECK(report.transferred && report.stage == VIREO_COMPLETION_QUEUE_TRANSFER_UNLOCK &&
        report.pthread_error == EFAULT && q->count == 1 && completion_id(out) == 2);
    EXPECT(vireo_completion_destroy(&out), VIREO_OK);
    t.unlock_error = 0;
    t.signal_error = 0;
    out = pop(q);
    CHECK(completion_id(out) == 3 && t.signal_calls == 3);
    EXPECT(vireo_completion_destroy(&out), VIREO_OK);
    t.broadcast_error = EIO;
    vireo_completion_queue_close_report_t cr;
    EXPECT(vireo_completion_queue_close(q, &cr), VIREO_RESULT_INTERNAL);
    CHECK(cr.changed && q->closed && cr.stage == VIREO_COMPLETION_QUEUE_CLOSE_WAKE && cr.pthread_error == EIO);
    EXPECT(vireo_completion_queue_close(q, &cr), VIREO_RESULT_INTERNAL);
    CHECK(!cr.changed && cr.stage == VIREO_COMPLETION_QUEUE_CLOSE_WAKE);
    t.unlock_error = EFAULT;
    EXPECT(vireo_completion_queue_close(q, &cr), VIREO_RESULT_INTERNAL);
    CHECK(!cr.changed && cr.stage == VIREO_COMPLETION_QUEUE_CLOSE_UNLOCK && cr.pthread_error == EFAULT);
    t.unlock_error = 0;
    t.broadcast_error = 0;
    EXPECT(vireo_completion_queue_close(q, &cr), VIREO_OK);
    CHECK(!cr.changed && cr.stage == VIREO_COMPLETION_QUEUE_CLOSE_NONE && t.broadcast_calls == 4);
    CHECK(t.allocations == 1 && t.frees == 0);
    EXPECT(vireo_completion_queue_destroy(&q), VIREO_OK);
}

/** cond失败保资源可再观察；后续成功先销毁cond，再销毁mutex。 */
static void condition_destroy_failure(void) {
    wait_trace_t t = {0};
    atomic_init(&t.waits, 0);
    vireo_completion_queue_t *q = new_queue(&t);
    vireo_completion_queue_t *saved = q;
    vireo_completion_queue_wait_ops_t const ops = wait_ops(&t);
    EXPECT(vireo_completion_queue_prepare_wait_with_ops(q, &ops), VIREO_OK);
    t.cond_destroy_error = EBUSY;
    EXPECT(vireo_completion_queue_destroy(&q), VIREO_RESULT_BUSY);
    CHECK(q == saved && q->wait_prepared && !q->retiring && t.mutex_destroy_calls == 0 && t.frees == 0);
    t.cond_destroy_error = EINVAL;
    EXPECT(vireo_completion_queue_destroy(&q), VIREO_RESULT_INTERNAL);
    vireo_completion_queue_info_t info;
    EXPECT(vireo_completion_queue_inspect(q, &info), VIREO_OK);
    CHECK(info.wait_prepared && !info.closed && info.count == 0);
    EXPECT(vireo_completion_queue_prepare_wait(q), VIREO_OK);
    CHECK(t.init_calls == 1);
    t.cond_destroy_error = 0;
    EXPECT(vireo_completion_queue_destroy(&q), VIREO_OK);
    CHECK(q == NULL && t.cond_destroy_calls == 3 && t.mutex_destroy_calls == 1 && t.frees == 1);
}

/** cond消耗后mutex失败只保剩余资源，所有运行入口拒绝且不重复销毁cond。 */
static void retired_destroy_retry(void) {
    wait_trace_t t = {0};
    atomic_init(&t.waits, 0);
    vireo_completion_queue_t *q = new_queue(&t);
    vireo_completion_queue_t *saved = q;
    vireo_completion_queue_wait_ops_t const ops = wait_ops(&t);
    EXPECT(vireo_completion_queue_prepare_wait_with_ops(q, &ops), VIREO_OK);
    t.mutex_destroy_error = EBUSY;
    EXPECT(vireo_completion_queue_destroy(&q), VIREO_RESULT_BUSY);
    CHECK(q == saved && q->retiring && !q->wait_prepared && t.cond_destroy_calls == 1 && t.frees == 0);
    vireo_completion_queue_info_t info;
    memset(&info, 0xa5, sizeof(info));
    unsigned char before[sizeof(info)];
    memcpy(before, &info, sizeof(info));
    EXPECT(vireo_completion_queue_inspect(q, &info), VIREO_RESULT_CANCELLED);
    CHECK(memcmp(before, &info, sizeof(info)) == 0);
    EXPECT(vireo_completion_queue_prepare_wait(q), VIREO_RESULT_CANCELLED);
    vireo_completion_t *owner = new_completion(1);
    vireo_completion_t *original = owner;
    vireo_completion_queue_transfer_report_t report;
    EXPECT(vireo_completion_queue_wait_push(q, &owner, &report), VIREO_RESULT_CANCELLED);
    EXPECT(vireo_completion_queue_try_push(q, &owner, &report), VIREO_RESULT_CANCELLED);
    CHECK(owner == original && !report.transferred);
    vireo_completion_queue_close_report_t cr;
    EXPECT(vireo_completion_queue_close(q, &cr), VIREO_RESULT_CANCELLED);
    CHECK(!cr.changed && cr.stage == VIREO_COMPLETION_QUEUE_CLOSE_NONE);
    vireo_completion_t *out = NULL;
    EXPECT(vireo_completion_queue_try_pop(q, &out, &report), VIREO_RESULT_CANCELLED);
    EXPECT(vireo_completion_queue_wait_push(q, &out, &report), VIREO_RESULT_NOT_FOUND);
    EXPECT(vireo_completion_queue_try_pop(q, &owner, &report), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_completion_queue_inspect(q, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_completion_destroy(&owner), VIREO_OK);
    t.mutex_destroy_error = EINVAL;
    EXPECT(vireo_completion_queue_destroy(&q), VIREO_RESULT_INTERNAL);
    CHECK(t.cond_destroy_calls == 1 && t.init_calls == 1 && t.mutex_destroy_calls == 2 && q == saved);
    t.mutex_destroy_error = 0;
    EXPECT(vireo_completion_queue_destroy(&q), VIREO_OK);
    CHECK(q == NULL && t.cond_destroy_calls == 1 && t.mutex_destroy_calls == 3 && t.frees == 1);
}

/** 未prepare的mutex销毁失败保原运行状态，不能误判cond已消耗。 */
static void unprepared_destroy_retry(void) {
    wait_trace_t t = {0};
    atomic_init(&t.waits, 0);
    vireo_completion_queue_t *q = new_queue(&t);
    t.mutex_destroy_error = EBUSY;
    EXPECT(vireo_completion_queue_destroy(&q), VIREO_RESULT_BUSY);
    CHECK(!q->retiring && !q->wait_prepared && t.cond_destroy_calls == 0);
    t.mutex_destroy_error = 0;
    EXPECT(vireo_completion_queue_destroy(&q), VIREO_OK);
    CHECK(t.frees == 1);
}

/** 真实满表等待，有限虚假醒来和无空间广播都必须重检；pop后才提交。 */
static void actual_space_wakeup(void) {
    wait_trace_t t = {0};
    atomic_init(&t.waits, 0);
    t.spurious = 2;
    vireo_completion_queue_t *q = new_queue(&t);
    vireo_completion_queue_wait_ops_t const ops = wait_ops(&t);
    EXPECT(vireo_completion_queue_prepare_wait_with_ops(q, &ops), VIREO_OK);
    fill(q);
    sender_t s = {.queue = q, .owner = new_completion(4)};
    pthread_t thread;
    CHECK(pthread_create(&thread, NULL, send_one, &s) == 0);
    await_wait(q, &t, 3, 1);
    CHECK(pthread_mutex_lock(&q->mutex) == 0);
    CHECK(q->count == 3 && pthread_cond_broadcast(&q->cond) == 0);
    CHECK(pthread_mutex_unlock(&q->mutex) == 0);
    await_wait(q, &t, 4, 1);
    vireo_completion_t *out = pop(q);
    CHECK(completion_id(out) == 1);
    EXPECT(vireo_completion_destroy(&out), VIREO_OK);
    CHECK(pthread_join(thread, NULL) == 0);
    CHECK(s.result == VIREO_OK && s.owner == NULL && s.report.transferred && t.spurious == 0);
    for (uint64_t id = 2; id <= 4; ++id) {
        out = pop(q);
        CHECK(completion_id(out) == id);
        EXPECT(vireo_completion_destroy(&out), VIREO_OK);
    }
    CHECK(t.signal_calls == 4 && atomic_load(&t.waits) >= 4);
    EXPECT(vireo_completion_queue_destroy(&q), VIREO_OK);
}

/** 三个已真实等待的producer被一次close广播唤醒，全部保源取消，原三项仍FIFO。 */
static void actual_close_broadcast(void) {
    wait_trace_t t = {0};
    atomic_init(&t.waits, 0);
    vireo_completion_queue_t *q = new_queue(&t);
    vireo_completion_queue_wait_ops_t const ops = wait_ops(&t);
    EXPECT(vireo_completion_queue_prepare_wait_with_ops(q, &ops), VIREO_OK);
    fill(q);
    sender_t senders[3];
    pthread_t threads[3];
    for (size_t i = 0; i < 3; ++i) {
        senders[i] = (sender_t){.queue = q, .owner = new_completion((uint64_t)i + 4)};
        CHECK(pthread_create(&threads[i], NULL, send_one, &senders[i]) == 0);
    }
    await_wait(q, &t, 3, 3);
    close_queue(q);
    for (size_t i = 0; i < 3; ++i) {
        CHECK(pthread_join(threads[i], NULL) == 0);
        CHECK(senders[i].result == VIREO_RESULT_CANCELLED && !senders[i].report.transferred &&
            senders[i].report.stage == VIREO_COMPLETION_QUEUE_TRANSFER_NONE);
        CHECK(completion_id(senders[i].owner) == (uint64_t)i + 4);
        EXPECT(vireo_completion_destroy(&senders[i].owner), VIREO_OK);
    }
    CHECK(t.broadcast_calls == 1);
    for (uint64_t id = 1; id <= 3; ++id) {
        vireo_completion_t *out = pop(q);
        CHECK(completion_id(out) == id);
        EXPECT(vireo_completion_destroy(&out), VIREO_OK);
    }
    vireo_completion_t *out = NULL;
    vireo_completion_queue_transfer_report_t report;
    EXPECT(vireo_completion_queue_try_pop(q, &out, &report), VIREO_RESULT_CANCELLED);
    EXPECT(vireo_completion_queue_destroy(&q), VIREO_OK);
}

/** 三个已等待producer随着单consumer持续腾槽全部成功，核验六项唯一归属。 */
static void actual_multiple_space(void) {
    wait_trace_t t = {0};
    atomic_init(&t.waits, 0);
    vireo_completion_queue_t *q = new_queue(&t);
    vireo_completion_queue_wait_ops_t const ops = wait_ops(&t);
    EXPECT(vireo_completion_queue_prepare_wait_with_ops(q, &ops), VIREO_OK);
    fill(q);
    sender_t senders[3];
    pthread_t threads[3];
    for (size_t i = 0; i < 3; ++i) {
        senders[i] = (sender_t){.queue = q, .owner = new_completion((uint64_t)i + 4)};
        CHECK(pthread_create(&threads[i], NULL, send_one, &senders[i]) == 0);
    }
    await_wait(q, &t, 3, 3);
    bool seen[7] = {false};
    for (size_t i = 0; i < 6; ++i) {
        vireo_completion_t *out = pop(q);
        uint64_t const id = completion_id(out);
        CHECK(id >= 1 && id <= 6 && !seen[id]);
        if (i < 3) {
            CHECK(id == (uint64_t)i + 1);
        }
        seen[id] = true;
        EXPECT(vireo_completion_destroy(&out), VIREO_OK);
    }
    for (size_t i = 0; i < 3; ++i) {
        CHECK(pthread_join(threads[i], NULL) == 0);
        CHECK(senders[i].result == VIREO_OK && senders[i].owner == NULL && senders[i].report.transferred);
    }
    CHECK(t.signal_calls == 6);
    close_queue(q);
    EXPECT(vireo_completion_queue_destroy(&q), VIREO_OK);
}

/** 标准公开等待入口的独占生产记录；结果只在join后读。 */
typedef struct stream_sender {
    vireo_completion_queue_t *queue; /**< 借至全部worker join之后。 */
    uint64_t first_id; /**< 本producer首项实例号，区间互不重叠。 */
    size_t count; /**< 要提交的固定项数。 */
} stream_sender_t;

/**
 * @brief
 *     标准wait适配实际多producer提交，结果只经queue发布给singleconsumer。
 *
 * @param[in] arg
 *     create前已发布且存活至join的不可变生产描述。
 *
 * @return
 *     NULL，每项成功后没有局部owner，不依赖其他模块私有头。
 */
static void *send_stream(void *arg) {
    stream_sender_t const *s = arg;
    CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL) == 0);
    for (size_t i = 0; i < s->count; ++i) {
        vireo_completion_t *owner = new_completion(s->first_id + (uint64_t)i);
        vireo_completion_queue_transfer_report_t report;
        EXPECT(vireo_completion_queue_wait_push(s->queue, &owner, &report), VIREO_OK);
        CHECK(owner == NULL && report.transferred);
    }
    return NULL;
}

/** 只用公开构造和默认等待适配，3producer各24项＋seed3项，共75项完整独立消费。 */
static void actual_standard_mpsc(void) {
    vireo_completion_queue_options_t const opts = {3, 4096};
    vireo_completion_queue_t *q = NULL;
    EXPECT(vireo_completion_queue_create(&opts, &q), VIREO_OK);
    EXPECT(vireo_completion_queue_prepare_wait(q), VIREO_OK);
    fill(q);
    stream_sender_t senders[3];
    pthread_t threads[3];
    for (size_t i = 0; i < 3; ++i) {
        senders[i] = (stream_sender_t){q, (uint64_t)i * 24 + 4, 24};
        CHECK(pthread_create(&threads[i], NULL, send_stream, &senders[i]) == 0);
    }
    bool seen[76] = {false};
    uint64_t last[3] = {3, 27, 51};
    for (size_t i = 0; i < 75; ++i) {
        vireo_completion_t *out = pop(q);
        uint64_t const id = completion_id(out);
        CHECK(id >= 1 && id <= 75 && !seen[id]);
        if (i < 3) {
            CHECK(id == (uint64_t)i + 1);
        } else {
            CHECK(id >= 4);
            size_t const producer = (size_t)((id - 4) / 24);
            CHECK(producer < 3 && id == last[producer] + 1);
            last[producer] = id;
        }
        seen[id] = true;
        EXPECT(vireo_completion_destroy(&out), VIREO_OK);
    }
    for (size_t i = 0; i < 3; ++i) {
        CHECK(pthread_join(threads[i], NULL) == 0);
    }
    CHECK(last[0] == 27 && last[1] == 51 && last[2] == 75);
    close_queue(q);
    vireo_completion_queue_info_t info;
    EXPECT(vireo_completion_queue_inspect(q, &info), VIREO_OK);
    CHECK(info.count == 0 && info.closed && info.wait_prepared);
    EXPECT(vireo_completion_queue_destroy(&q), VIREO_OK);
}

/** 测试目录不保存动态资源，main串行调用，失败直接结束进程。 */
typedef struct test_case {
    char const *name; /**< 稳定场景名，只借静态字符串。 */
    void (*run)(void); /**< 本组入口，不跨组保留资源。 */
} test_case_t;

int main(void) {
    CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL) == 0);
    test_case_t const cases[] = {
        {"preparation", preparation},
        {"invalid_and_precedence", invalid_and_precedence},
        {"fifo_and_wrap", fifo_and_wrap},
        {"wait_failures", wait_failures},
        {"wait_unlock_progress", wait_unlock_progress},
        {"notification_progress", notification_progress},
        {"condition_destroy_failure", condition_destroy_failure},
        {"retired_destroy_retry", retired_destroy_retry},
        {"unprepared_destroy_retry", unprepared_destroy_retry},
        {"actual_space_wakeup", actual_space_wakeup},
        {"actual_close_broadcast", actual_close_broadcast},
        {"actual_multiple_space", actual_multiple_space},
        {"actual_standard_mpsc", actual_standard_mpsc}
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        cases[i].run();
        printf("PASS %s\n", cases[i].name);
    }
    printf("completion_queue_wait: %zu groups PASS\n", sizeof(cases) / sizeof(cases[0]));
    return 0;
}
