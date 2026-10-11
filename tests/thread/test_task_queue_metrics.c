/*
 * PROJECT : VIREO
 * FILE    : test_task_queue_metrics.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-12
 * BRIEF   : 指标口径、饱和、真实提交失败进度与多生产者精确累计
 */
#include "thread/task_queue_internal.h"

#include <errno.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 断言失败直接终止，避免存活线程访问已返回的栈上下文。 */
#define CHECK(c) do { if (!(c)) { \
    fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #c); abort(); \
} } while (0)

/**
 * @brief
 *     本测试局部故障记录，只在无并发访问期间改写或读取。
 */
typedef struct metric_fault {
    int lock_error; /**< trylock之前返回错误，不持锁。 */
    int unlock_error; /**< 真实解锁后注入报告错误。 */
    int signal_error; /**< 真实通知后注入报告错误，不撤销提交。 */
    int destroy_error; /**< mutex销毁之前返回错误，保留资源。 */
    unsigned allocations; /**< 自定义配对allocator申请次数，不含task申请。 */
    unsigned frees; /**< 配对释放次数，验证仅容器一次申请。 */
} metric_fault_t;

/**
 * @brief
 *     记录容器实际申请，context借至配对释放，不修改业务task。
 *
 * @param[in,out] context
 *     局部metric_fault，外部无并发写。
 * @param[in] bytes
 *     已受检正申请量。
 *
 * @return
 *     独占原块或NULL。
 */
static void *allocate(void *context, size_t bytes) {
    metric_fault_t *f = context;
    ++f->allocations;
    errno = EIO;
    return malloc(bytes);
}

/**
 * @brief
 *     配对释放无在途访问的容器原块。
 *
 * @param[in,out] context
 *     局部记录。
 * @param[in] block
 *     对应申请的原块。
 */
static void deallocate(void *context, void *block) {
    metric_fault_t *f = context;
    ++f->frees;
    free(block);
    errno = EIO;
}

/**
 * @brief
 *     同步初始化适配，操作表只供本核心故障测试。
 *
 * @param[in] context
 *     此适配不使用。
 * @param[out] mutex
 *     未初始化mutex。
 *
 * @return
 *     pthread直接错误。
 */
static int init(void *context, pthread_mutex_t *mutex) {
    (void)context;
    return pthread_mutex_init(mutex, NULL);
}

/**
 * @brief
 *     真实一次trylock或取得锁之前的故障。
 *
 * @param[in] context
 *     无并发写的局部故障记录。
 * @param[in,out] mutex
 *     存活mutex。
 *
 * @return
 *     直接错误码，非0未持锁。
 */
static int try_lock(void *context, pthread_mutex_t *mutex) {
    metric_fault_t const *f = context;
    errno = EIO;
    return f->lock_error != 0 ? f->lock_error : pthread_mutex_trylock(mutex);
}

/**
 * @brief
 *     真实释放后注入报告错误，不模拟未释放锁的损坏恢复。
 *
 * @param[in] context
 *     无并发写的局部故障记录。
 * @param[in,out] mutex
 *     当前线程持有mutex。
 *
 * @return
 *     真实错误优先，否则注入错误。
 */
static int unlock(void *context, pthread_mutex_t *mutex) {
    metric_fault_t const *f = context;
    int const code = pthread_mutex_unlock(mutex);
    errno = EIO;
    return code != 0 ? code : f->unlock_error;
}

/**
 * @brief
 *     无访问期间销毁mutex，故障不消耗资源。
 *
 * @param[in] context
 *     局部记录。
 * @param[in,out] mutex
 *     存活mutex。
 *
 * @return
 *     直接错误码。
 */
static int destroy_mutex(void *context, pthread_mutex_t *mutex) {
    metric_fault_t const *f = context;
    return f->destroy_error != 0 ? f->destroy_error : pthread_mutex_destroy(mutex);
}

/**
 * @brief
 *     未发布cond初始化，失败不留下半初始化资源。
 *
 * @param[in] context
 *     此适配不使用。
 * @param[out] cond
 *     未初始化cond。
 *
 * @return
 *     直接pthread错误。
 */
static int init_cond(void *context, pthread_cond_t *cond) {
    (void)context;
    return pthread_cond_init(cond, NULL);
}

/**
 * @brief
 *     prepared等待所用真实阻塞mutex适配。
 *
 * @param[in] context
 *     此适配不使用。
 * @param[in,out] mutex
 *     存活mutex。
 *
 * @return
 *     直接pthread错误。
 */
static int lock(void *context, pthread_mutex_t *mutex) {
    (void)context;
    return pthread_mutex_lock(mutex);
}

/**
 * @brief
 *     原mutex谓词等待适配，本测试仅立即领取不进入此等待。
 *
 * @param[in] context
 *     此适配不使用。
 * @param[in,out] cond
 *     存活cond。
 * @param[in,out] mutex
 *     当前持有mutex。
 *
 * @return
 *     直接pthread错误，返回仍持mutex。
 */
static int wait(void *context, pthread_cond_t *cond, pthread_mutex_t *mutex) {
    (void)context;
    return pthread_cond_wait(cond, mutex);
}

/**
 * @brief
 *     真实signal之后注入报告错误，提交状态已存在。
 *
 * @param[in] context
 *     局部记录，无并发写。
 * @param[in,out] cond
 *     存活cond。
 *
 * @return
 *     真实错误优先，否则注入错误。
 */
static int signal(void *context, pthread_cond_t *cond) {
    metric_fault_t const *f = context;
    int const code = pthread_cond_signal(cond);
    errno = EIO;
    return code != 0 ? code : f->signal_error;
}

/**
 * @brief
 *     真实广播适配，不增加指标。
 *
 * @param[in] context
 *     此适配不使用。
 * @param[in,out] cond
 *     存活cond。
 *
 * @return
 *     直接pthread错误。
 */
static int broadcast(void *context, pthread_cond_t *cond) {
    (void)context;
    return pthread_cond_broadcast(cond);
}

/**
 * @brief
 *     无访问时销毁cond，用于实际分阶段收尾测试。
 *
 * @param[in] context
 *     此适配不使用。
 * @param[in,out] cond
 *     存活cond。
 *
 * @return
 *     直接pthread错误。
 */
static int destroy_cond(void *context, pthread_cond_t *cond) {
    (void)context;
    return pthread_cond_destroy(cond);
}

/**
 * @brief
 *     创建显式预算的局部故障队列，context保活到销毁。
 *
 * @param[in] capacity
 *     正槽数。
 * @param[in,out] fault
 *     局部故障记录，无共享写。
 *
 * @return
 *     新队列唯一owner，测试失败直接终止。
 */
static vireo_task_queue_t *make_queue(size_t capacity, metric_fault_t *fault) {
    vireo_task_queue_options_t const options = {capacity, 4096};
    vireo_task_queue_allocator_t const allocator = {fault, allocate, deallocate};
    vireo_task_queue_sync_ops_t const sync = {fault, init, try_lock, unlock, destroy_mutex};
    vireo_task_queue_t *queue = NULL;
    CHECK(vireo_task_queue_create_with_ops(&options, &allocator, &sync, &queue) == VIREO_OK);
    return queue;
}

/**
 * @brief
 *     只依022公开合同创建独立输入，标签不代表运行中的网络请求。
 *
 * @param[in] id
 *     非零实例标签。
 *
 * @return
 *     新task唯一owner。
 */
static vireo_task_t *make_task(uint64_t id) {
    vireo_task_metadata_t const metadata = {{1, 0, 1, 1}, id, 7, 0};
    vireo_task_t *task = NULL;
    CHECK(vireo_task_create_copy(metadata, &id, sizeof(id), 1024, &task) == VIREO_OK);
    return task;
}

/**
 * @brief
 *     观测并核对逻辑字段，不比较成功输出的padding。
 *
 * @param[in] queue
 *     存活队列。
 * @param[in] depth
 *     预期仍拥有条数。
 * @param[in] peak
 *     预期历史峰值。
 * @param[in] full
 *     预期满拒绝累计。
 * @param[in] closed
 *     预期关闭拒绝累计。
 * @param[in] saturated
 *     预期粘性标志。
 */
static void expect(vireo_task_queue_t *queue, size_t depth, size_t peak,
    uint64_t full, uint64_t closed, bool saturated) {
    vireo_task_queue_metrics_t metrics;
    errno = EILSEQ;
    CHECK(vireo_task_queue_inspect_metrics(queue, &metrics) == VIREO_OK);
    CHECK(errno == EILSEQ && metrics.depth == depth && metrics.high_watermark == peak);
    CHECK(metrics.full_rejections == full && metrics.closed_rejections == closed);
    CHECK(metrics.rejection_count_saturated == saturated);
}

/**
 * @brief
 *     初值、三槽绕圈、FIFO、深度及历史峰值；多次观测不额外申请。
 */
static void flow(void) {
    metric_fault_t fault = {0};
    vireo_task_queue_t *queue = make_queue(3, &fault);
    vireo_task_queue_transfer_report_t report;
    expect(queue, 0, 0, 0, 0, false);
    for (uint64_t round = 0; round < 4; ++round) {
        for (size_t i = 0; i < 3; ++i) {
            vireo_task_t *task = make_task(round * 3 + (uint64_t)i + 1);
            CHECK(vireo_task_queue_try_push(queue, &task, &report) == VIREO_OK);
            CHECK(task == NULL && report.transferred);
            expect(queue, i + 1, round == 0 ? i + 1 : 3, 0, 0, false);
        }
        for (size_t i = 0; i < 3; ++i) {
            vireo_task_t *task = NULL;
            CHECK(vireo_task_queue_try_pop(queue, &task, &report) == VIREO_OK);
            vireo_task_info_t info;
            CHECK(vireo_task_inspect(task, &info) == VIREO_OK);
            CHECK(info.metadata.request_instance_id == round * 3 + (uint64_t)i + 1);
            expect(queue, 2 - i, 3, 0, 0, false);
            CHECK(vireo_task_destroy(&task) == VIREO_OK);
        }
    }
    CHECK(fault.allocations == 1 && fault.frees == 0);
    vireo_task_queue_info_t info;
    CHECK(vireo_task_queue_inspect(queue, &info) == VIREO_OK);
    CHECK(info.allocated_bytes == sizeof(vireo_task_queue_t) + 3 * sizeof(vireo_task_t *));
    vireo_task_queue_options_t const insufficient = {3, info.allocated_bytes - 1};
    vireo_task_queue_t *other = NULL;
    CHECK(vireo_task_queue_create(&insufficient, &other) == VIREO_RESULT_RANGE && other == NULL);
    CHECK(vireo_task_queue_destroy(&queue) == VIREO_OK && fault.frees == 1);
}

/**
 * @brief
 *     满拒绝与关闭优先，两种策略只改变深度，不重置累计。
 */
static void policies(void) {
    vireo_task_queue_state_t const modes[] = {VIREO_TASK_QUEUE_DRAIN, VIREO_TASK_QUEUE_CANCEL_PENDING};
    for (size_t i = 0; i < 2; ++i) {
        metric_fault_t fault = {0};
        vireo_task_queue_t *queue = make_queue(1, &fault);
        vireo_task_queue_transfer_report_t report;
        vireo_task_queue_close_report_t closed;
        vireo_task_t *task = make_task(1), *extra = make_task(2), *out = NULL;
        vireo_task_t *const original = extra;
        CHECK(vireo_task_queue_try_push(queue, &task, &report) == VIREO_OK);
        CHECK(vireo_task_queue_try_push(queue, &extra, &report) == VIREO_RESULT_BUSY);
        CHECK(extra == original && !report.transferred && report.stage == VIREO_TASK_QUEUE_STAGE_NONE);
        expect(queue, 1, 1, 1, 0, false);
        CHECK(vireo_task_queue_close(queue, modes[i], &closed) == VIREO_OK);
        CHECK(vireo_task_queue_close(queue, modes[i], &closed) == VIREO_OK && !closed.changed);
        CHECK(vireo_task_queue_try_push(queue, &extra, &report) == VIREO_RESULT_CANCELLED);
        CHECK(extra == original && !report.transferred);
        expect(queue, 1, 1, 1, 1, false);
        if (modes[i] == VIREO_TASK_QUEUE_DRAIN) {
            CHECK(vireo_task_queue_try_take_cancelled(queue, &out, &report) == VIREO_RESULT_BUSY);
            CHECK(vireo_task_queue_try_pop(queue, &out, &report) == VIREO_OK);
        } else {
            CHECK(vireo_task_queue_try_pop(queue, &out, &report) == VIREO_RESULT_CANCELLED);
            CHECK(vireo_task_queue_try_take_cancelled(queue, &out, &report) == VIREO_OK);
        }
        CHECK(vireo_task_destroy(&out) == VIREO_OK);
        CHECK(vireo_task_queue_try_push(queue, &extra, &report) == VIREO_RESULT_CANCELLED);
        expect(queue, 0, 1, 1, 2, false);
        CHECK(vireo_task_destroy(&extra) == VIREO_OK);
        CHECK(vireo_task_queue_destroy(&queue) == VIREO_OK);
    }
}

/**
 * @brief
 *     基本错误、空源与锁失败不计，观测失败保整个字节输出及errno。
 */
static void guards(void) {
    metric_fault_t fault = {0};
    vireo_task_queue_t *queue = make_queue(1, &fault);
    vireo_task_t *task = make_task(1), *empty = NULL;
    vireo_task_queue_transfer_report_t report;
    CHECK(vireo_task_queue_try_push(queue, &task, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_task_queue_try_push(queue, NULL, &report) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_task_queue_try_push(queue, &empty, &report) == VIREO_RESULT_NOT_FOUND);
    vireo_task_queue_metrics_t out;
    unsigned char before[sizeof(out)];
    memset(&out, 0xa5, sizeof(out));
    memcpy(before, &out, sizeof(out));
    errno = EILSEQ;
    CHECK(vireo_task_queue_inspect_metrics(NULL, &out) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_task_queue_inspect_metrics(queue, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(memcmp(before, &out, sizeof(out)) == 0 && errno == EILSEQ);
    int const errors[] = {EBUSY, EINVAL};
    for (size_t i = 0; i < 2; ++i) {
        fault.lock_error = errors[i];
        vireo_result_t const result = i == 0 ? VIREO_RESULT_BUSY : VIREO_RESULT_INTERNAL;
        CHECK(vireo_task_queue_inspect_metrics(queue, &out) == result);
        CHECK(memcmp(before, &out, sizeof(out)) == 0 && errno == EILSEQ);
        CHECK(vireo_task_queue_try_push(queue, &task, &report) == result);
        CHECK(!report.transferred && task != NULL && report.stage == VIREO_TASK_QUEUE_STAGE_LOCK);
    }
    fault.lock_error = 0;
    fault.unlock_error = EINVAL;
    CHECK(vireo_task_queue_inspect_metrics(queue, &out) == VIREO_RESULT_INTERNAL);
    CHECK(memcmp(before, &out, sizeof(out)) == 0 && errno == EILSEQ);
    fault.unlock_error = 0;
    expect(queue, 0, 0, 0, 0, false);
    CHECK(vireo_task_destroy(&task) == VIREO_OK);
    CHECK(vireo_task_queue_destroy(&queue) == VIREO_OK);
}

/**
 * @brief
 *     已提交之后的WAKE/UNLOCK失败，及已拒绝后的UNLOCK失败，不撤销指标。
 */
static void failure_progress(void) {
    metric_fault_t fault = {0};
    vireo_task_queue_t *queue = make_queue(2, &fault);
    vireo_task_queue_wait_ops_t const waits = {
        &fault, init_cond, lock, wait, signal, broadcast, destroy_cond
    };
    CHECK(vireo_task_queue_prepare_wait_with_ops(queue, &waits) == VIREO_OK);
    expect(queue, 0, 0, 0, 0, false);
    vireo_task_queue_transfer_report_t report;
    vireo_task_t *first = make_task(1), *second = make_task(2), *extra = make_task(3);
    fault.signal_error = EINVAL;
    errno = EILSEQ;
    CHECK(vireo_task_queue_try_push(queue, &first, &report) == VIREO_RESULT_INTERNAL);
    CHECK(first == NULL && report.transferred && report.stage == VIREO_TASK_QUEUE_STAGE_WAKE);
    CHECK(errno == EILSEQ);
    fault.signal_error = 0;
    expect(queue, 1, 1, 0, 0, false);
    fault.unlock_error = EPERM;
    CHECK(vireo_task_queue_try_push(queue, &second, &report) == VIREO_RESULT_INTERNAL);
    CHECK(second == NULL && report.transferred && report.stage == VIREO_TASK_QUEUE_STAGE_UNLOCK);
    CHECK(vireo_task_queue_try_push(queue, &extra, &report) == VIREO_RESULT_INTERNAL);
    CHECK(extra != NULL && !report.transferred && report.stage == VIREO_TASK_QUEUE_STAGE_UNLOCK);
    CHECK(errno == EILSEQ);
    fault.unlock_error = 0;
    expect(queue, 2, 2, 1, 0, false);
    /* wait_pop真实领取，但队列深度不包括已交出而尚未destroy的task。 */
    CHECK(vireo_task_queue_wait_pop(queue, &first, &report) == VIREO_OK);
    CHECK(vireo_task_queue_try_pop(queue, &second, &report) == VIREO_OK);
    expect(queue, 0, 2, 1, 0, false);
    vireo_task_queue_close_report_t closed;
    CHECK(vireo_task_queue_close(queue, VIREO_TASK_QUEUE_DRAIN, &closed) == VIREO_OK);
    fault.unlock_error = EPERM;
    CHECK(vireo_task_queue_try_push(queue, &extra, &report) == VIREO_RESULT_INTERNAL);
    CHECK(extra != NULL && !report.transferred && report.stage == VIREO_TASK_QUEUE_STAGE_UNLOCK);
    fault.unlock_error = 0;
    expect(queue, 0, 2, 1, 1, false);
    CHECK(vireo_task_destroy(&first) == VIREO_OK);
    CHECK(vireo_task_destroy(&second) == VIREO_OK);
    CHECK(vireo_task_destroy(&extra) == VIREO_OK);
    CHECK(vireo_task_queue_destroy(&queue) == VIREO_OK);
}

/**
 * @brief
 *     无并发时白盒设置边界，不伪称实际执行MAX次拒绝；两累计独立且flag粘性。
 */
static void saturation(void) {
    metric_fault_t fault = {0};
    vireo_task_queue_t *queue = make_queue(1, &fault);
    vireo_task_t *task = make_task(1), *extra = make_task(2), *out = NULL;
    vireo_task_queue_transfer_report_t report;
    CHECK(vireo_task_queue_try_push(queue, &task, &report) == VIREO_OK);
    queue->full_rejections = UINT64_MAX - 1;
    CHECK(vireo_task_queue_try_push(queue, &extra, &report) == VIREO_RESULT_BUSY);
    expect(queue, 1, 1, UINT64_MAX, 0, false);
    CHECK(vireo_task_queue_try_push(queue, &extra, &report) == VIREO_RESULT_BUSY);
    expect(queue, 1, 1, UINT64_MAX, 0, true);
    vireo_task_queue_close_report_t closed;
    CHECK(vireo_task_queue_close(queue, VIREO_TASK_QUEUE_DRAIN, &closed) == VIREO_OK);
    CHECK(vireo_task_queue_try_push(queue, &extra, &report) == VIREO_RESULT_CANCELLED);
    expect(queue, 1, 1, UINT64_MAX, 1, true);
    CHECK(vireo_task_queue_try_pop(queue, &out, &report) == VIREO_OK);
    CHECK(vireo_task_destroy(&out) == VIREO_OK);
    CHECK(vireo_task_destroy(&extra) == VIREO_OK);
    CHECK(vireo_task_queue_destroy(&queue) == VIREO_OK);
    /* 单独证明closed恰到MAX仍精确，下一次才饱和。 */
    queue = make_queue(1, &fault);
    extra = make_task(3);
    CHECK(vireo_task_queue_close(queue, VIREO_TASK_QUEUE_CANCEL_PENDING, &closed) == VIREO_OK);
    queue->closed_rejections = UINT64_MAX - 1;
    CHECK(vireo_task_queue_try_push(queue, &extra, &report) == VIREO_RESULT_CANCELLED);
    expect(queue, 0, 0, 0, UINT64_MAX, false);
    CHECK(vireo_task_queue_try_push(queue, &extra, &report) == VIREO_RESULT_CANCELLED);
    expect(queue, 0, 0, 0, UINT64_MAX, true);
    CHECK(vireo_task_destroy(&extra) == VIREO_OK);
    CHECK(vireo_task_queue_destroy(&queue) == VIREO_OK);
}

/**
 * @brief
 *     真实cond已消耗、mutex销毁失败的状态，只可重试destroy。
 */
static void retiring(void) {
    metric_fault_t fault = {0};
    vireo_task_queue_t *queue = make_queue(1, &fault);
    CHECK(vireo_task_queue_prepare_wait(queue) == VIREO_OK);
    fault.destroy_error = EINVAL;
    CHECK(vireo_task_queue_destroy(&queue) == VIREO_RESULT_INTERNAL && queue != NULL);
    vireo_task_t *task = make_task(1);
    vireo_task_queue_transfer_report_t report;
    vireo_task_queue_metrics_t out;
    unsigned char before[sizeof(out)];
    memset(&out, 0xa5, sizeof(out));
    memcpy(before, &out, sizeof(out));
    errno = EILSEQ;
    CHECK(vireo_task_queue_inspect_metrics(queue, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_task_queue_inspect_metrics(queue, &out) == VIREO_RESULT_CANCELLED);
    CHECK(memcmp(before, &out, sizeof(out)) == 0 && errno == EILSEQ);
    CHECK(vireo_task_queue_try_push(queue, &task, &report) == VIREO_RESULT_CANCELLED);
    CHECK(task != NULL && queue->closed_rejections == 0 && queue->full_rejections == 0);
    CHECK(vireo_task_destroy(&task) == VIREO_OK);
    fault.destroy_error = 0;
    CHECK(vireo_task_queue_destroy(&queue) == VIREO_OK);
}

/**
 * @brief
 *     一次实际竞争工作记录，main真实持mutex至join结束，不靠sleep。
 */
typedef struct contender {
    vireo_task_queue_t *queue; /**< 短借到join，main保证不销毁。 */
    vireo_task_t *task; /**< worker独占push源；未转移，join后main销毁。 */
} contender_t;

/**
 * @brief
 *     实际mutex竞争时观测保输出、push保owner，二者不增加拒绝数。
 *
 * @param[in,out] argument
 *     存活独占contender，join之后main读取。
 *
 * @return
 *     NULL，无额外owner。
 */
static void *contend(void *argument) {
    contender_t *c = argument;
    vireo_task_queue_metrics_t out;
    unsigned char before[sizeof(out)];
    memset(&out, 0xa5, sizeof(out));
    memcpy(before, &out, sizeof(out));
    errno = EILSEQ;
    CHECK(vireo_task_queue_inspect_metrics(c->queue, &out) == VIREO_RESULT_BUSY);
    CHECK(memcmp(before, &out, sizeof(out)) == 0 && errno == EILSEQ);
    vireo_task_queue_transfer_report_t report;
    CHECK(vireo_task_queue_try_push(c->queue, &c->task, &report) == VIREO_RESULT_BUSY);
    CHECK(c->task != NULL && !report.transferred && report.stage == VIREO_TASK_QUEUE_STAGE_LOCK);
    CHECK(errno == EILSEQ);
    return NULL;
}

/**
 * @brief
 *     多producer满表累计oracle，每worker只持自己task，queue始终满且OPEN。
 */
typedef struct producer {
    vireo_task_queue_t *queue; /**< 借至全部join，不销毁或关闭。 */
    atomic_bool *start; /**< main release开门，worker acquire等待，不用于队列发布。 */
    uint64_t id; /**< 非零独立task标签，每worker持有自己的task。 */
} producer_t;

/**
 * @brief
 *     完成1000次真正锁内满拒绝；竞争BUSY不计次数，不共享owner存储。
 *
 * @param[in] argument
 *     存活producer参数，只读至join。
 *
 * @return
 *     NULL，源task仍自有并已销毁。
 */
static void *produce(void *argument) {
    producer_t const *p = argument;
    vireo_task_t *task = make_task(p->id);
    while (!atomic_load_explicit(p->start, memory_order_acquire)) {
        sched_yield();
    }
    unsigned accepted_rejections = 0;
    while (accepted_rejections < 1000) {
        vireo_task_queue_transfer_report_t report;
        errno = EILSEQ;
        CHECK(vireo_task_queue_try_push(p->queue, &task, &report) == VIREO_RESULT_BUSY);
        CHECK(task != NULL && !report.transferred && errno == EILSEQ);
        if (report.stage == VIREO_TASK_QUEUE_STAGE_NONE) {
            CHECK(report.pthread_error == 0);
            ++accepted_rejections;
        } else {
            CHECK(report.stage == VIREO_TASK_QUEUE_STAGE_LOCK && report.pthread_error == EBUSY);
            sched_yield();
        }
        vireo_task_queue_metrics_t metrics;
        vireo_result_t const result = vireo_task_queue_inspect_metrics(p->queue, &metrics);
        CHECK(result == VIREO_OK || result == VIREO_RESULT_BUSY);
        if (result == VIREO_OK) {
            CHECK(metrics.depth == 3 && metrics.high_watermark == 3);
            CHECK(metrics.full_rejections > 0 && metrics.full_rejections <= 4000);
            CHECK(metrics.closed_rejections == 0 && !metrics.rejection_count_saturated);
        }
    }
    CHECK(vireo_task_destroy(&task) == VIREO_OK);
    return NULL;
}

/**
 * @brief
 *     真实锁竞争握手与四producer4000次精确oracle，所有线程实际join。
 */
static void concurrency(void) {
    vireo_task_queue_options_t const options = {3, 4096};
    vireo_task_queue_t *queue = NULL;
    CHECK(vireo_task_queue_create(&options, &queue) == VIREO_OK);
    contender_t contender = {queue, make_task(9)};
    CHECK(pthread_mutex_lock(&queue->mutex) == 0);
    pthread_t thread;
    CHECK(pthread_create(&thread, NULL, contend, &contender) == 0);
    CHECK(pthread_join(thread, NULL) == 0);
    CHECK(pthread_mutex_unlock(&queue->mutex) == 0);
    expect(queue, 0, 0, 0, 0, false);
    CHECK(vireo_task_destroy(&contender.task) == VIREO_OK);
    vireo_task_queue_transfer_report_t report;
    for (uint64_t i = 1; i <= 3; ++i) {
        vireo_task_t *task = make_task(i);
        CHECK(vireo_task_queue_try_push(queue, &task, &report) == VIREO_OK);
    }
    atomic_bool start;
    atomic_init(&start, false);
    producer_t producers[4];
    pthread_t threads[4];
    for (size_t i = 0; i < 4; ++i) {
        producers[i] = (producer_t){queue, &start, (uint64_t)i + 10};
        CHECK(pthread_create(&threads[i], NULL, produce, &producers[i]) == 0);
    }
    atomic_store_explicit(&start, true, memory_order_release);
    for (size_t i = 0; i < 4; ++i) {
        CHECK(pthread_join(threads[i], NULL) == 0);
    }
    expect(queue, 3, 3, 4000, 0, false);
    for (size_t i = 0; i < 3; ++i) {
        vireo_task_t *task = NULL;
        CHECK(vireo_task_queue_try_pop(queue, &task, &report) == VIREO_OK);
        CHECK(vireo_task_destroy(&task) == VIREO_OK);
    }
    CHECK(vireo_task_queue_destroy(&queue) == VIREO_OK);
}

int main(void) {
    int previous = 0;
    CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previous) == 0);
    flow();
    policies();
    guards();
    failure_progress();
    saturation();
    retiring();
    concurrency();
    CHECK(pthread_setcancelstate(previous, NULL) == 0);
    puts("test_task_queue_metrics: 7 groups");
    return 0;
}
