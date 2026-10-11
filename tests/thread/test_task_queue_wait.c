/*
 * PROJECT : VIREO
 * FILE    : test_task_queue_wait.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-11
 * BRIEF   : worker谓词等待、关闭广播和分阶段同步故障
 */
#include "thread/task_queue_internal.h"

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
    return pthread_cond_wait(cond, mutex);
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
 *     未使用，可NULL。
 * @param[in] bytes
 *     受检正申请量。
 *
 * @return
 *     新独占原块或NULL。
 */
static void *allocate(void *ctx, size_t bytes) {
    (void)ctx;
    return malloc(bytes);
}

/**
 * @brief
 *     配对释放无访问原块。
 *
 * @param[in] ctx
 *     未使用，可NULL。
 * @param[in] ptr
 *     唯一原块。
 *
 * @note
 *     不释放task或记录上下文。
 */
static void deallocate(void *ctx, void *ptr) {
    (void)ctx;
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
static vireo_task_queue_wait_ops_t wait_ops(wait_trace_t *t) {
    vireo_task_queue_wait_ops_t const ops = {
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
static vireo_task_queue_t *new_queue(wait_trace_t *t) {
    vireo_task_queue_options_t const opts = {3, 4096};
    vireo_task_queue_allocator_t const alloc = {NULL, allocate, deallocate};
    vireo_task_queue_sync_ops_t const sync = {t, mutex_init, try_lock, unlock, mutex_destroy};
    vireo_task_queue_t *q = NULL;
    CHECK(vireo_task_queue_create_with_ops(&opts, &alloc, &sync, &q) == VIREO_OK);
    return q;
}

/**
 * @brief
 *     新task携带独立metadata与payload校验字，无其他核心私有头。
 *
 * @param[in] id
 *     非零请求实例标签。
 *
 * @return
 *     唯一task owner，来源复制后立即改写。
 */
static vireo_task_t *new_task(uint64_t id) {
    vireo_task_metadata_t const meta = {{1, 0, 1, 1}, id, 7, UINT64_MAX};
    uint64_t data = id;
    vireo_task_t *task = NULL;
    CHECK(vireo_task_create_copy(meta, &data, sizeof(data), 1024, &task) == VIREO_OK);
    data = 0;
    return task;
}

/**
 * @brief
 *     通过公开inspect及payload借用核对唯一task内容。
 *
 * @param[in] task
 *     caller当前唯一拥有的task，借至返回。
 *
 * @return
 *     非零实例标签，借用在返回前结束。
 */
static uint64_t task_id(vireo_task_t *task) {
    vireo_task_info_t info;
    vireo_task_payload_view_t view;
    CHECK(vireo_task_inspect(task, &info) == VIREO_OK);
    CHECK(vireo_task_borrow_payload(task, &view) == VIREO_OK);
    uint64_t id = 0;
    CHECK(view.size == sizeof(id));
    memcpy(&id, view.data, sizeof(id));
    CHECK(id == info.metadata.request_instance_id);
    return id;
}

/**
 * @brief
 *     caller有限重试try提交；产品入口本身不自旋或等待。
 *
 * @param[in,out] q
 *     存活queue。
 * @param[in,out] task
 *     独占task owner，成功清空。
 *
 * @note
 *     只把正常BUSY当压力，其他失败立即终止测试。
 */
static void push(vireo_task_queue_t *q, vireo_task_t **task) {
    for (unsigned i = 0; i < 2000000; ++i) {
        vireo_task_queue_transfer_report_t r;
        vireo_result_t const result = vireo_task_queue_try_push(q, task, &r);
        if (result == VIREO_OK) {
            CHECK(r.transferred && *task == NULL);
            return;
        }
        CHECK(result == VIREO_RESULT_BUSY && !r.transferred);
        sched_yield();
    }
    CHECK(false);
}

/**
 * @brief
 *     caller有限重试关闭，只接受正常竞争。
 *
 * @param[in,out] q
 *     存活queue。
 * @param[in] mode
 *     DRAIN或CANCEL_PENDING。
 *
 * @note
 *     不是产品内部循环，失败终止进程。
 */
static void close_queue(vireo_task_queue_t *q, vireo_task_queue_state_t mode) {
    for (unsigned i = 0; i < 2000000; ++i) {
        vireo_task_queue_close_report_t r;
        vireo_result_t const result = vireo_task_queue_close(q, mode, &r);
        if (result == VIREO_OK) {
            return;
        }
        CHECK(result == VIREO_RESULT_BUSY);
        sched_yield();
    }
    CHECK(false);
}

/**
 * @brief
 *     等待atomic入口计数，再取得原mutex证明worker已原子释放它。
 *
 * @param[in,out] q
 *     存活queue。
 * @param[in] t
 *     存活计数记录。
 * @param[in] n
 *     预期至少进入wait的次数。
 *
 * @note
 *     不用sleep假定时序；main取得锁后worker已进入真实wait。
 */
static void await_wait(vireo_task_queue_t *q, wait_trace_t const *t, unsigned n) {
    for (unsigned i = 0; i < 2000000; ++i) {
        if (atomic_load_explicit(&t->waits, memory_order_acquire) >= n) {
            CHECK(pthread_mutex_lock(&q->mutex) == 0);
            CHECK(pthread_mutex_unlock(&q->mutex) == 0);
            return;
        }
        sched_yield();
    }
    CHECK(false);
}

/**
 * @brief
 *     一次worker领取记录，join后main读取输出，不产生第二owner。
 */
typedef struct receiver {
    vireo_task_queue_t *queue; /**< 短借共享对象，到join后结束。 */
    vireo_task_t *task; /**< worker唯一接收输出，join后转交main清理。 */
    vireo_result_t result; /**< wait_pop原返回值。 */
    vireo_task_queue_transfer_report_t report; /**< 本次同步进度报告。 */
} receiver_t;

/**
 * @brief
 *     实际worker禁用POSIX取消，调用一次wait_pop后返回。
 *
 * @param[in,out] arg
 *     存活独占receiver，main仅在join后读输出。
 *
 * @return
 *     NULL，不销毁可能已收到的task。
 */
static void *receive(void *arg) {
    receiver_t *r = arg;
    int old = 0;
    CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &old) == 0);
    errno = EDOM;
    r->result = vireo_task_queue_wait_pop(r->queue, &r->task, &r->report);
    CHECK(errno == EDOM);
    CHECK(pthread_setcancelstate(old, NULL) == 0);
    return NULL;
}

/**
 * @brief
 *     初始化、重复准备、非空/关闭拒绝、主输出及errno保持。
 *
 * @note
 *     无worker；故障字段只在全部访问之外修改。
 */
static void preparation(void) {
    wait_trace_t t = {0};
    atomic_init(&t.waits, 0);
    vireo_task_queue_t *q = new_queue(&t);
    vireo_task_queue_wait_ops_t ops = wait_ops(&t);
    vireo_task_t *out = NULL;
    vireo_task_queue_transfer_report_t r;
    CHECK(vireo_task_queue_wait_pop(q, &out, &r) == VIREO_RESULT_NOT_FOUND);
    CHECK(!r.transferred && out == NULL);
    CHECK(vireo_task_queue_prepare_wait(NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    vireo_task_queue_wait_ops_t bad = ops;
    bad.wait = NULL;
    CHECK(vireo_task_queue_prepare_wait_with_ops(q, &bad) == VIREO_RESULT_INVALID_ARGUMENT);
    t.init_error = ENOMEM;
    errno = EDOM;
    CHECK(vireo_task_queue_prepare_wait_with_ops(q, &ops) == VIREO_RESULT_NO_MEMORY);
    CHECK(errno == EDOM && !q->wait_prepared);
    t.init_error = EAGAIN;
    CHECK(vireo_task_queue_prepare_wait_with_ops(q, &ops) == VIREO_RESULT_INTERNAL);
    CHECK(errno == EDOM && !q->wait_prepared);
    t.init_error = 0;
    CHECK(vireo_task_queue_prepare_wait_with_ops(q, &ops) == VIREO_OK);
    CHECK(vireo_task_queue_prepare_wait(q) == VIREO_OK && t.init_calls == 3);
    vireo_task_queue_info_t info;
    CHECK(vireo_task_queue_inspect(q, &info) == VIREO_OK);
    CHECK(info.wait_prepared && info.allocated_bytes == sizeof(*q) + 3 * sizeof(out));
    out = new_task(1);
    push(q, &out);
    CHECK(vireo_task_queue_prepare_wait(q) == VIREO_RESULT_BUSY);
    CHECK(vireo_task_queue_destroy(&q) == VIREO_RESULT_BUSY && t.cond_destroy_calls == 0);
    CHECK(vireo_task_queue_wait_pop(q, &out, &r) == VIREO_OK && task_id(out) == 1);
    CHECK(vireo_task_destroy(&out) == VIREO_OK);
    close_queue(q, VIREO_TASK_QUEUE_DRAIN);
    CHECK(vireo_task_queue_prepare_wait(q) == VIREO_RESULT_BUSY);
    CHECK(vireo_task_queue_destroy(&q) == VIREO_OK && q == NULL);
    CHECK(t.cond_destroy_calls == 1 && t.mutex_destroy_calls == 1);
}

/**
 * @brief
 *     基本参数优先、阻塞加锁错误、等待错误与unlock诊断优先。
 *
 * @note
 *     调用线程在main已禁用POSIX取消；注入wait失败始终仍持mutex。
 */
static void wait_failures(void) {
    wait_trace_t t = {0};
    atomic_init(&t.waits, 0);
    vireo_task_queue_t *q = new_queue(&t);
    vireo_task_queue_wait_ops_t const ops = wait_ops(&t);
    CHECK(vireo_task_queue_prepare_wait_with_ops(q, &ops) == VIREO_OK);
    vireo_task_t *task = new_task(1);
    vireo_task_queue_transfer_report_t r;
    t.lock_error = EBUSY;
    CHECK(vireo_task_queue_wait_pop(q, &task, &r) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(!r.transferred && r.stage == VIREO_TASK_QUEUE_STAGE_NONE);
    CHECK(vireo_task_destroy(&task) == VIREO_OK);
    CHECK(vireo_task_queue_wait_pop(NULL, &task, &r) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_task_queue_wait_pop(q, NULL, &r) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_task_queue_wait_pop(q, &task, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    errno = EDOM;
    CHECK(vireo_task_queue_wait_pop(q, &task, &r) == VIREO_RESULT_INTERNAL);
    CHECK(errno == EDOM && r.stage == VIREO_TASK_QUEUE_STAGE_LOCK && r.pthread_error == EBUSY);
    t.lock_error = EINVAL;
    CHECK(vireo_task_queue_wait_pop(q, &task, &r) == VIREO_RESULT_INTERNAL);
    CHECK(r.pthread_error == EINVAL && task == NULL);
    t.lock_error = 0;
    t.wait_error = EINVAL;
    CHECK(vireo_task_queue_wait_pop(q, &task, &r) == VIREO_RESULT_INTERNAL);
    CHECK(r.stage == VIREO_TASK_QUEUE_STAGE_WAIT && !r.transferred && errno == EDOM);
    t.unlock_error = EPERM;
    CHECK(vireo_task_queue_wait_pop(q, &task, &r) == VIREO_RESULT_INTERNAL);
    CHECK(r.stage == VIREO_TASK_QUEUE_STAGE_UNLOCK && r.pthread_error == EPERM);
    t.wait_error = 0;
    t.unlock_error = 0;
    task = new_task(2);
    push(q, &task);
    t.unlock_error = EIO;
    CHECK(vireo_task_queue_wait_pop(q, &task, &r) == VIREO_RESULT_INTERNAL);
    CHECK(r.transferred && task_id(task) == 2 && r.stage == VIREO_TASK_QUEUE_STAGE_UNLOCK);
    CHECK(vireo_task_destroy(&task) == VIREO_OK);
    t.unlock_error = 0;
    CHECK(vireo_task_queue_destroy(&q) == VIREO_OK);
}

/**
 * @brief
 *     通知失败保真实提交/关闭，重复同模式再广播，unlock优先。
 *
 * @note
 *     无等待者，不把故障清除后可继续的测试模型冒充真实损坏资源可恢复。
 */
static void wake_failures(void) {
    wait_trace_t t = {0};
    atomic_init(&t.waits, 0);
    vireo_task_queue_t *q = new_queue(&t);
    vireo_task_queue_wait_ops_t const ops = wait_ops(&t);
    CHECK(vireo_task_queue_prepare_wait_with_ops(q, &ops) == VIREO_OK);
    vireo_task_t *task = new_task(1);
    vireo_task_queue_transfer_report_t r;
    t.signal_error = EINVAL;
    errno = EDOM;
    CHECK(vireo_task_queue_try_push(q, &task, &r) == VIREO_RESULT_INTERNAL);
    CHECK(errno == EDOM && task == NULL && r.transferred);
    CHECK(r.stage == VIREO_TASK_QUEUE_STAGE_WAKE && r.pthread_error == EINVAL && q->count == 1);
    t.signal_error = 0;
    CHECK(vireo_task_queue_wait_pop(q, &task, &r) == VIREO_OK);
    CHECK(vireo_task_destroy(&task) == VIREO_OK);
    t.signal_error = EINVAL;
    t.unlock_error = EPERM;
    task = new_task(2);
    CHECK(vireo_task_queue_try_push(q, &task, &r) == VIREO_RESULT_INTERNAL);
    CHECK(r.stage == VIREO_TASK_QUEUE_STAGE_UNLOCK && r.pthread_error == EPERM && r.transferred);
    t.signal_error = 0;
    t.unlock_error = 0;
    CHECK(vireo_task_queue_try_pop(q, &task, &r) == VIREO_OK);
    CHECK(vireo_task_destroy(&task) == VIREO_OK);
    vireo_task_queue_close_report_t cr;
    t.broadcast_error = EINVAL;
    CHECK(vireo_task_queue_close(q, VIREO_TASK_QUEUE_DRAIN, &cr) == VIREO_RESULT_INTERNAL);
    CHECK(cr.changed && cr.stage == VIREO_TASK_QUEUE_STAGE_WAKE && q->state == VIREO_TASK_QUEUE_DRAIN);
    CHECK(vireo_task_queue_close(q, VIREO_TASK_QUEUE_DRAIN, &cr) == VIREO_RESULT_INTERNAL);
    CHECK(!cr.changed && t.broadcast_calls == 2);
    CHECK(vireo_task_queue_close(q, VIREO_TASK_QUEUE_CANCEL_PENDING, &cr) == VIREO_RESULT_BUSY);
    CHECK(t.broadcast_calls == 2);
    t.unlock_error = EPERM;
    CHECK(vireo_task_queue_close(q, VIREO_TASK_QUEUE_DRAIN, &cr) == VIREO_RESULT_INTERNAL);
    CHECK(!cr.changed && cr.stage == VIREO_TASK_QUEUE_STAGE_UNLOCK && cr.pthread_error == EPERM);
    t.broadcast_error = 0;
    t.unlock_error = 0;
    close_queue(q, VIREO_TASK_QUEUE_DRAIN);
    CHECK(t.broadcast_calls == 4);
    CHECK(vireo_task_queue_destroy(&q) == VIREO_OK);
}

/**
 * @brief
 *     cond失败整体保持；cond消耗而mutex失败时只可重试destroy。
 *
 * @note
 *     核对所有运行入口、基本错误优先、快照逐字节保持与不重复cond销毁。
 */
static void phased_destroy(void) {
    wait_trace_t t = {0};
    atomic_init(&t.waits, 0);
    vireo_task_queue_t *q = new_queue(&t);
    vireo_task_queue_wait_ops_t const ops = wait_ops(&t);
    CHECK(vireo_task_queue_prepare_wait_with_ops(q, &ops) == VIREO_OK);
    vireo_task_queue_t *const original = q;
    t.cond_destroy_error = EBUSY;
    CHECK(vireo_task_queue_destroy(&q) == VIREO_RESULT_BUSY);
    CHECK(q == original && q->wait_prepared && !q->retiring && t.mutex_destroy_calls == 0);
    t.cond_destroy_error = EINVAL;
    CHECK(vireo_task_queue_destroy(&q) == VIREO_RESULT_INTERNAL);
    CHECK(q == original && q->wait_prepared);
    t.cond_destroy_error = 0;
    t.mutex_destroy_error = EBUSY;
    CHECK(vireo_task_queue_destroy(&q) == VIREO_RESULT_BUSY);
    CHECK(q == original && !q->wait_prepared && q->retiring && t.cond_destroy_calls == 3);
    vireo_task_queue_info_t info;
    memset(&info, 0xa5, sizeof(info));
    unsigned char snapshot[sizeof(info)];
    memcpy(snapshot, &info, sizeof(info));
    errno = EDOM;
    CHECK(vireo_task_queue_inspect(q, &info) == VIREO_RESULT_CANCELLED);
    CHECK(memcmp(&info, snapshot, sizeof(info)) == 0 && errno == EDOM);
    CHECK(vireo_task_queue_prepare_wait(q) == VIREO_RESULT_CANCELLED);
    vireo_task_queue_transfer_report_t r;
    vireo_task_queue_close_report_t cr;
    vireo_task_t *task = new_task(1);
    CHECK(vireo_task_queue_wait_pop(q, &task, &r) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_task_queue_try_push(q, &task, &r) == VIREO_RESULT_CANCELLED && task != NULL);
    CHECK(vireo_task_destroy(&task) == VIREO_OK);
    CHECK(vireo_task_queue_try_push(q, &task, &r) == VIREO_RESULT_NOT_FOUND);
    CHECK(vireo_task_queue_try_pop(q, &task, &r) == VIREO_RESULT_CANCELLED);
    CHECK(vireo_task_queue_try_take_cancelled(q, &task, &r) == VIREO_RESULT_CANCELLED);
    CHECK(vireo_task_queue_wait_pop(q, &task, &r) == VIREO_RESULT_CANCELLED);
    CHECK(vireo_task_queue_close(q, VIREO_TASK_QUEUE_DRAIN, &cr) == VIREO_RESULT_CANCELLED);
    CHECK(vireo_task_queue_close(q, VIREO_TASK_QUEUE_OPEN, &cr) == VIREO_RESULT_INVALID_ARGUMENT);
    t.mutex_destroy_error = EINVAL;
    CHECK(vireo_task_queue_destroy(&q) == VIREO_RESULT_INTERNAL && t.cond_destroy_calls == 3);
    t.mutex_destroy_error = 0;
    CHECK(vireo_task_queue_destroy(&q) == VIREO_OK && q == NULL && t.cond_destroy_calls == 3);
    CHECK(vireo_task_queue_destroy(&q) == VIREO_OK && errno == EDOM);
}

/**
 * @brief
 *     真实signal与空谓词广播；worker醒来必须再次等待，不能空取。
 *
 * @note
 *     使用入口计数与mutex握手，避免sleep；另注入一次不释放锁的虚假醒来。
 */
static void signal_and_spurious(void) {
    wait_trace_t t = {0};
    atomic_init(&t.waits, 0);
    t.spurious = 1;
    vireo_task_queue_t *q = new_queue(&t);
    vireo_task_queue_wait_ops_t const ops = wait_ops(&t);
    CHECK(vireo_task_queue_prepare_wait_with_ops(q, &ops) == VIREO_OK);
    receiver_t r = {.queue = q};
    pthread_t worker;
    CHECK(pthread_create(&worker, NULL, receive, &r) == 0);
    await_wait(q, &t, 2);
    CHECK(pthread_mutex_lock(&q->mutex) == 0);
    CHECK(pthread_cond_broadcast(&q->cond) == 0);
    CHECK(pthread_mutex_unlock(&q->mutex) == 0);
    await_wait(q, &t, 3);
    vireo_task_t *task = new_task(17);
    push(q, &task);
    CHECK(pthread_join(worker, NULL) == 0);
    CHECK(r.result == VIREO_OK && r.report.transferred && task_id(r.task) == 17);
    CHECK(vireo_task_destroy(&r.task) == VIREO_OK);
    CHECK(vireo_task_queue_destroy(&q) == VIREO_OK);
}

/**
 * @brief
 *     两关闭模式都广播全部真实等待worker，无需逐worker提交唤醒task。
 *
 * @note
 *     四worker已等待后关闭，再逐个join，确保销毁前访问结束。
 */
static void broadcast_shutdown(void) {
    for (unsigned mode = 1; mode <= 2; ++mode) {
        wait_trace_t t = {0};
        atomic_init(&t.waits, 0);
        vireo_task_queue_t *q = new_queue(&t);
        vireo_task_queue_wait_ops_t const ops = wait_ops(&t);
        CHECK(vireo_task_queue_prepare_wait_with_ops(q, &ops) == VIREO_OK);
        receiver_t r[4] = {{.queue = q}, {.queue = q}, {.queue = q}, {.queue = q}};
        pthread_t workers[4];
        for (unsigned i = 0; i < 4; ++i) {
            CHECK(pthread_create(&workers[i], NULL, receive, &r[i]) == 0);
        }
        await_wait(q, &t, 4);
        close_queue(q, (vireo_task_queue_state_t)mode);
        for (unsigned i = 0; i < 4; ++i) {
            CHECK(pthread_join(workers[i], NULL) == 0);
            CHECK(r[i].result == VIREO_RESULT_CANCELLED && r[i].task == NULL && !r[i].report.transferred);
        }
        CHECK(t.broadcast_calls == 1);
        CHECK(vireo_task_queue_destroy(&q) == VIREO_OK);
    }
}

/**
 * @brief
 *     真实等待者遇到广播故障后，由caller显式同模式重复关闭再通知。
 *
 * @note
 *     故障清除仅是局部seam模型，不证明损坏的系统资源可恢复。
 */
static void repeat_close_wakes(void) {
    wait_trace_t t = {0};
    atomic_init(&t.waits, 0);
    t.broadcast_error = EINVAL;
    vireo_task_queue_t *q = new_queue(&t);
    vireo_task_queue_wait_ops_t const ops = wait_ops(&t);
    CHECK(vireo_task_queue_prepare_wait_with_ops(q, &ops) == VIREO_OK);
    receiver_t r = {.queue = q};
    pthread_t worker;
    CHECK(pthread_create(&worker, NULL, receive, &r) == 0);
    await_wait(q, &t, 1);
    vireo_task_queue_close_report_t cr;
    CHECK(vireo_task_queue_close(q, VIREO_TASK_QUEUE_DRAIN, &cr) == VIREO_RESULT_INTERNAL);
    CHECK(cr.changed && cr.stage == VIREO_TASK_QUEUE_STAGE_WAKE);
    /* 此字段仅main广播适配访问；不与worker等待计数/谓词混用。 */
    t.broadcast_error = 0;
    CHECK(vireo_task_queue_close(q, VIREO_TASK_QUEUE_DRAIN, &cr) == VIREO_OK);
    CHECK(!cr.changed && t.broadcast_calls == 2);
    CHECK(pthread_join(worker, NULL) == 0);
    CHECK(r.result == VIREO_RESULT_CANCELLED && r.task == NULL);
    CHECK(vireo_task_queue_destroy(&q) == VIREO_OK);
}

/**
 * @brief
 *     关闭前已有task的FIFO、绕圈、DRAIN排空及CANCEL_PENDING专用取回。
 *
 * @note
 *     同一线程明确禁用POSIX取消，未prepare旧入口仍可用。
 */
static void pending_and_fifo(void) {
    for (unsigned mode = 1; mode <= 2; ++mode) {
        wait_trace_t t = {0};
        atomic_init(&t.waits, 0);
        vireo_task_queue_t *q = new_queue(&t);
        CHECK(vireo_task_queue_prepare_wait(q) == VIREO_OK);
        vireo_task_t *task = new_task(1);
        vireo_task_queue_transfer_report_t r;
        push(q, &task);
        task = new_task(2);
        push(q, &task);
        CHECK(vireo_task_queue_wait_pop(q, &task, &r) == VIREO_OK && task_id(task) == 1);
        CHECK(vireo_task_destroy(&task) == VIREO_OK);
        task = new_task(3);
        push(q, &task);
        task = new_task(4);
        push(q, &task);
        close_queue(q, (vireo_task_queue_state_t)mode);
        CHECK(vireo_task_queue_destroy(&q) == VIREO_RESULT_BUSY);
        if (mode == 2) {
            CHECK(vireo_task_queue_wait_pop(q, &task, &r) == VIREO_RESULT_CANCELLED);
        }
        for (uint64_t id = 2; id <= 4; ++id) {
            vireo_result_t const result = mode == 1 ? vireo_task_queue_wait_pop(q, &task, &r) :
                vireo_task_queue_try_take_cancelled(q, &task, &r);
            CHECK(result == VIREO_OK && r.transferred && task_id(task) == id);
            CHECK(vireo_task_destroy(&task) == VIREO_OK);
        }
        CHECK(vireo_task_queue_wait_pop(q, &task, &r) == VIREO_RESULT_CANCELLED);
        CHECK(vireo_task_queue_destroy(&q) == VIREO_OK);
    }
}

#define TOTAL 120
/**
 * @brief
 *     混合try与wait消费者的独立核验记录，不依赖queue自报count作成功依据。
 */
typedef struct consumer {
    vireo_task_queue_t *queue; /**< 借至所有worker join。 */
    atomic_uint *seen; /**< TOTAL个共享atomic，逐id唯一领取计数。 */
    bool use_wait; /**< true阻塞领取，false caller有限try重试。 */
} consumer_t;

/**
 * @brief
 *     混合消费者读payload、核唯一性并清理task，直到DRAIN排空。
 *
 * @param[in] arg
 *     存活独立consumer记录，指向共享原子计数。
 *
 * @return
 *     NULL，全部已领取task在恢复取消设置前销毁。
 */
static void *consume(void *arg) {
    consumer_t const *c = arg;
    int old = 0;
    CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &old) == 0);
    for (unsigned attempts = 0; attempts < 2000000; ++attempts) {
        vireo_task_t *task = NULL;
        vireo_task_queue_transfer_report_t r;
        vireo_result_t const result = c->use_wait ? vireo_task_queue_wait_pop(c->queue, &task, &r) :
            vireo_task_queue_try_pop(c->queue, &task, &r);
        if (result == VIREO_RESULT_CANCELLED) {
            CHECK(task == NULL && !r.transferred);
            CHECK(pthread_setcancelstate(old, NULL) == 0);
            return NULL;
        }
        if (result == VIREO_RESULT_BUSY || result == VIREO_RESULT_NOT_FOUND) {
            CHECK(!c->use_wait && task == NULL);
            sched_yield();
            continue;
        }
        CHECK(result == VIREO_OK && task != NULL && r.transferred);
        uint64_t const id = task_id(task);
        CHECK(id > 0 && id <= TOTAL);
        CHECK(atomic_fetch_add_explicit(&c->seen[id - 1], 1, memory_order_relaxed) == 0);
        CHECK(vireo_task_destroy(&task) == VIREO_OK);
    }
    CHECK(false);
    return NULL;
}

/**
 * @brief
 *     真实并发提交及混合领取，独立核对120项内容、唯一性与最终全部join。
 *
 * @note
 *     公共prepare使用标准适配，不含故障；不宣称TSan或公平性。
 */
static void mixed_consumers(void) {
    vireo_task_queue_options_t const opts = {3, 4096};
    vireo_task_queue_t *q = NULL;
    CHECK(vireo_task_queue_create(&opts, &q) == VIREO_OK);
    CHECK(vireo_task_queue_prepare_wait(q) == VIREO_OK);
    atomic_uint seen[TOTAL];
    for (unsigned i = 0; i < TOTAL; ++i) {
        atomic_init(&seen[i], 0);
    }
    consumer_t c[4] = {{q, seen, true}, {q, seen, true}, {q, seen, false}, {q, seen, false}};
    pthread_t workers[4];
    for (unsigned i = 0; i < 4; ++i) {
        CHECK(pthread_create(&workers[i], NULL, consume, &c[i]) == 0);
    }
    for (uint64_t id = 1; id <= TOTAL; ++id) {
        vireo_task_t *task = new_task(id);
        push(q, &task);
    }
    close_queue(q, VIREO_TASK_QUEUE_DRAIN);
    for (unsigned i = 0; i < 4; ++i) {
        CHECK(pthread_join(workers[i], NULL) == 0);
    }
    for (unsigned i = 0; i < TOTAL; ++i) {
        CHECK(atomic_load_explicit(&seen[i], memory_order_relaxed) == 1);
    }
    CHECK(vireo_task_queue_destroy(&q) == VIREO_OK);
}

/**
 * @brief
 *     九组等待、唤醒、故障与拥有权测试入口。
 *
 * @return
 *     成功0，断言失败终止进程并输出位置；CTest提供外部30秒上限。
 */
int main(void) {
    int old = 0;
    CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &old) == 0);
    preparation();
    wait_failures();
    wake_failures();
    phased_destroy();
    signal_and_spurious();
    broadcast_shutdown();
    repeat_close_wakes();
    pending_and_fifo();
    mixed_consumers();
    CHECK(pthread_setcancelstate(old, NULL) == 0);
    puts("test_task_queue_wait: 9 groups");
    return 0;
}
