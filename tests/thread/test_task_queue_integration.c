/*
 * PROJECT : VIREO
 * FILE    : test_task_queue_integration.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-12
 * BRIEF   : 只依公开合同的task交接、取消寿命、关闭与指标完整链
 */
#include <vireo/thread/task_queue.h>

#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 失败直接终止，避免仍存活线程访问返回后的栈上下文。 */
#define CHECK(c) do { if (!(c)) { \
    fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #c); abort(); \
} } while (0)
#define ITEMS 16u
#define GUARD UINT64_C(0x9c875162de340abf)

/**
 * @brief
 *     测试有限输入字节，不是产品协议或网络身份。
 */
typedef struct test_payload {
    uint64_t id; /**< 非零测试标签，须等metadata实例号。 */
    uint64_t guard; /**< id异或固定校验字，核对独立复制/发布。 */
} test_payload_t;

/**
 * @brief
 *     创建唯一task，只依公开构造，原payload随后改写以验证复制。
 *
 * @param[in] id
 *     非零测试实例号，各组不复用，非客户当前性认证。
 * @param[in] deadline
 *     显式测试MONOTONIC域绝对纳秒数，0也为有限期限。
 * @param[in] cancel
 *     可空；非空由caller持有引用保活到返回，不消耗。
 *
 * @return
 *     新唯一owner，失败终止测试。
 */
static vireo_task_t *make_task(uint64_t id, uint64_t deadline, vireo_task_cancel_t *cancel) {
    vireo_task_route_t route;
    vireo_task_metadata_t metadata;
    CHECK(vireo_task_route_make(55, 0, 2, 17, &route) == VIREO_OK);
    CHECK(vireo_task_metadata_make(route, id, 7, deadline, &metadata) == VIREO_OK);
    test_payload_t payload = {id, id ^ GUARD};
    vireo_task_t *task = NULL;
    vireo_result_t const result = cancel == NULL ?
        vireo_task_create_copy(metadata, &payload, sizeof(payload), 1024, &task) :
        vireo_task_create_copy_with_cancel(metadata, &payload, sizeof(payload), 1024, cancel, &task);
    CHECK(result == VIREO_OK && task != NULL);
    payload.id = 0;
    payload.guard = 0;
    return task;
}

/**
 * @brief
 *     在本owner寿命内检查payload短借，返回独立metadata快照，不保存借用。
 *
 * @param[in] task
 *     调用线程唯一拥有task，无并发移动/销毁。
 *
 * @return
 *     三字段info按值，其中metadata保存原数值身份。
 */
static vireo_task_info_t inspect_task(vireo_task_t *task) {
    vireo_task_info_t info;
    vireo_task_payload_view_t view;
    CHECK(vireo_task_inspect(task, &info) == VIREO_OK);
    CHECK(vireo_task_borrow_payload(task, &view) == VIREO_OK);
    CHECK(view.size == sizeof(test_payload_t) && view.data != NULL);
    test_payload_t value;
    memcpy(&value, view.data, sizeof(value));
    CHECK(value.id == info.metadata.request_instance_id && value.guard == (value.id ^ GUARD));
    CHECK(info.metadata.route.client_owner_id == 55 && info.metadata.route.client_generation == 2);
    CHECK(info.metadata.route.request_sequence == 17 && info.metadata.operation == 7);
    /* 此后不再使用view地址，结束本次借用；调用者才可移动/销毁task。 */
    return info;
}

/**
 * @brief
 *     一次显式资源创建，容量允许非2幂，等待准备发生在共享访问前。
 *
 * @param[in] capacity
 *     正有限槽数。
 * @param[in] prepare
 *     是否在发布前初始化等待设施。
 *
 * @return
 *     新queue唯一owner，显式容器预算4096字节。
 */
static vireo_task_queue_t *make_queue(size_t capacity, bool prepare) {
    vireo_task_queue_options_t const options = {capacity, 4096};
    vireo_task_queue_t *queue = NULL;
    CHECK(vireo_task_queue_create(&options, &queue) == VIREO_OK);
    if (prepare) {
        CHECK(vireo_task_queue_prepare_wait(queue) == VIREO_OK);
    }
    return queue;
}

/**
 * @brief
 *     测试producer可重试尚未提交的BUSY，产品入口本身没有等待/重试。
 *
 * @param[in,out] queue
 *     存活OPEN对象，caller保活到线程join。
 * @param[in,out] task
 *     本线程独占非空owner，成功清空。
 * @param[in,out] full
 *     本producer局部满拒绝oracle；不计LOCK竞争，无并发写。
 */
static void submit(vireo_task_queue_t *queue, vireo_task_t **task, uint64_t *full) {
    vireo_task_t *const original = *task;
    for (;;) {
        vireo_task_queue_transfer_report_t report;
        errno = EILSEQ;
        vireo_result_t const result = vireo_task_queue_try_push(queue, task, &report);
        CHECK(errno == EILSEQ);
        if (result == VIREO_OK) {
            CHECK(*task == NULL && report.transferred && report.stage == VIREO_TASK_QUEUE_STAGE_NONE);
            return;
        }
        CHECK(result == VIREO_RESULT_BUSY && !report.transferred && *task == original);
        if (report.stage == VIREO_TASK_QUEUE_STAGE_NONE) {
            CHECK(report.pthread_error == 0 && *full < UINT64_MAX);
            ++*full;
        } else {
            CHECK(report.stage == VIREO_TASK_QUEUE_STAGE_LOCK && report.pthread_error == EBUSY);
        }
        sched_yield();
    }
}

/**
 * @brief
 *     测试caller关闭；只有未提交的锁竞争可重试，不掩盖已关闭或同步异常。
 *
 * @param[in,out] queue
 *     原OPEN对象，别线程不会close，不并发销毁。
 * @param[in] mode
 *     DRAIN或CANCEL_PENDING。
 */
static void close_queue(vireo_task_queue_t *queue, vireo_task_queue_state_t mode) {
    for (;;) {
        vireo_task_queue_close_report_t report;
        errno = EILSEQ;
        vireo_result_t const result = vireo_task_queue_close(queue, mode, &report);
        CHECK(errno == EILSEQ);
        if (result == VIREO_OK) {
            CHECK(report.changed && report.stage == VIREO_TASK_QUEUE_STAGE_NONE);
            return;
        }
        CHECK(result == VIREO_RESULT_BUSY && !report.changed);
        CHECK(report.stage == VIREO_TASK_QUEUE_STAGE_LOCK && report.pthread_error == EBUSY);
        sched_yield();
    }
}

/**
 * @brief
 *     FIFO、独立payload和旧快照的固定值，期限0不会让队列自动拒绝/跳过。
 */
static void fifo_snapshot(void) {
    vireo_task_queue_t *queue = make_queue(3, false);
    uint64_t full = 0;
    for (uint64_t id = 101; id <= 103; ++id) {
        vireo_task_t *task = make_task(id, 0, NULL);
        submit(queue, &task, &full);
    }
    vireo_task_queue_metrics_t earlier;
    CHECK(vireo_task_queue_inspect_metrics(queue, &earlier) == VIREO_OK);
    CHECK(earlier.depth == 3 && earlier.high_watermark == 3 && full == 0);
    for (uint64_t id = 101; id <= 103; ++id) {
        vireo_task_t *task = NULL;
        vireo_task_queue_transfer_report_t report;
        CHECK(vireo_task_queue_try_pop(queue, &task, &report) == VIREO_OK && report.transferred);
        vireo_task_info_t const info = inspect_task(task);
        CHECK(info.metadata.request_instance_id == id);
        bool expired = false, cancelled = true;
        CHECK(vireo_task_metadata_deadline_expired(info.metadata, 0, &expired) == VIREO_OK && expired);
        CHECK(vireo_task_is_cancel_requested(task, &cancelled) == VIREO_OK && !cancelled);
        vireo_task_queue_metrics_t current;
        CHECK(vireo_task_queue_inspect_metrics(queue, &current) == VIREO_OK);
        CHECK(current.depth == (size_t)(103 - id) && current.high_watermark == 3);
        CHECK(earlier.depth == 3 && earlier.high_watermark == 3);
        CHECK(vireo_task_destroy(&task) == VIREO_OK);
    }
    CHECK(vireo_task_queue_destroy(&queue) == VIREO_OK && queue == NULL);
}

/**
 * @brief
 *     两worker公开等待的恰一次oracle，所有结果字段均原子访问。
 */
typedef struct drain_state {
    vireo_task_queue_t *queue; /**< 借至全部join，main唯一拥有且期间不销毁。 */
    atomic_uint ready; /**< worker release发布已到调用前位置；不证明cond已停泊。 */
    atomic_uint seen[ITEMS]; /**< 每非零标签恰一次领取，数组每项显式初0。 */
    atomic_uint completed; /**< 测试显式未取消/未到期分类数，最多16，不是产品进度。 */
    atomic_uint expired; /**< 测试显式now100纳秒时到期分类数，最多16。 */
    atomic_uint cancelled; /**< 测试显式观测取消标志的分类数，最多16。 */
} drain_state_t;

/**
 * @brief
 *     公开wait_pop交接后由使用者查询任务，DRAIN空退出，再归还POSIX取消设置。
 *
 * @param[in,out] argument
 *     存活drain_state；queue借用及原子存储保持到join。
 *
 * @return
 *     NULL，所有本线程取得task都已结束借用并销毁。
 */
static void *drain_worker(void *argument) {
    drain_state_t *state = argument;
    int previous = 0;
    CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previous) == 0);
    (void)atomic_fetch_add_explicit(&state->ready, 1, memory_order_release);
    for (;;) {
        vireo_task_t *task = NULL;
        vireo_task_queue_transfer_report_t report;
        errno = EILSEQ;
        vireo_result_t const result = vireo_task_queue_wait_pop(state->queue, &task, &report);
        CHECK(errno == EILSEQ && report.stage == VIREO_TASK_QUEUE_STAGE_NONE);
        if (result == VIREO_RESULT_CANCELLED) {
            CHECK(task == NULL && !report.transferred);
            break;
        }
        CHECK(result == VIREO_OK && task != NULL && report.transferred);
        vireo_task_info_t const info = inspect_task(task);
        uint64_t const id = info.metadata.request_instance_id;
        CHECK(id >= 1 && id <= ITEMS);
        CHECK(atomic_fetch_add_explicit(&state->seen[(unsigned)(id - 1)], 1,
            memory_order_relaxed) == 0);
        bool cancelled = false, expired = false;
        CHECK(vireo_task_is_cancel_requested(task, &cancelled) == VIREO_OK);
        CHECK(vireo_task_metadata_deadline_expired(info.metadata, 100, &expired) == VIREO_OK);
        if (cancelled) {
            (void)atomic_fetch_add_explicit(&state->cancelled, 1, memory_order_relaxed);
        } else if (expired) {
            (void)atomic_fetch_add_explicit(&state->expired, 1, memory_order_relaxed);
        } else {
            (void)atomic_fetch_add_explicit(&state->completed, 1, memory_order_relaxed);
        }
        CHECK(vireo_task_destroy(&task) == VIREO_OK && task == NULL);
    }
    CHECK(pthread_setcancelstate(previous, NULL) == 0);
    return NULL;
}

/**
 * @brief
 *     SPMC部署角色：16项、两真实worker、已取消/已到期项也由queue原样交接。
 */
static void spmc_drain(void) {
    vireo_task_queue_t *queue = make_queue(3, true);
    vireo_task_cancel_t *cancel = NULL;
    CHECK(vireo_task_cancel_create(1024, &cancel) == VIREO_OK);
    CHECK(vireo_task_cancel_request(cancel) == VIREO_OK);
    drain_state_t state;
    state.queue = queue;
    atomic_init(&state.ready, 0);
    atomic_init(&state.completed, 0);
    atomic_init(&state.expired, 0);
    atomic_init(&state.cancelled, 0);
    for (unsigned i = 0; i < ITEMS; ++i) {
        atomic_init(&state.seen[i], 0);
    }
    pthread_t threads[2];
    for (unsigned i = 0; i < 2; ++i) {
        CHECK(pthread_create(&threads[i], NULL, drain_worker, &state) == 0);
    }
    while (atomic_load_explicit(&state.ready, memory_order_acquire) != 2) {
        sched_yield();
    }
    uint64_t full = 0;
    for (uint64_t id = 1; id <= ITEMS; ++id) {
        vireo_task_t *task = make_task(id, id >= 9 && id <= 12 ? 100 : 200,
            id >= 13 ? cancel : NULL);
        submit(queue, &task, &full);
    }
    CHECK(vireo_task_cancel_destroy(&cancel) == VIREO_OK && cancel == NULL);
    close_queue(queue, VIREO_TASK_QUEUE_DRAIN);
    vireo_task_t *extra = make_task(104, 200, NULL);
    vireo_task_t *const original = extra;
    for (;;) {
        vireo_task_queue_transfer_report_t report;
        vireo_result_t const result = vireo_task_queue_try_push(queue, &extra, &report);
        CHECK(extra == original && !report.transferred);
        if (result == VIREO_RESULT_CANCELLED) {
            CHECK(report.stage == VIREO_TASK_QUEUE_STAGE_NONE);
            break;
        }
        CHECK(result == VIREO_RESULT_BUSY && report.stage == VIREO_TASK_QUEUE_STAGE_LOCK);
        CHECK(report.pthread_error == EBUSY);
        sched_yield();
    }
    CHECK(vireo_task_destroy(&extra) == VIREO_OK);
    for (unsigned i = 0; i < 2; ++i) {
        CHECK(pthread_join(threads[i], NULL) == 0);
    }
    for (unsigned i = 0; i < ITEMS; ++i) {
        CHECK(atomic_load_explicit(&state.seen[i], memory_order_relaxed) == 1);
    }
    CHECK(atomic_load_explicit(&state.completed, memory_order_relaxed) == 8);
    CHECK(atomic_load_explicit(&state.expired, memory_order_relaxed) == 4);
    CHECK(atomic_load_explicit(&state.cancelled, memory_order_relaxed) == 4);
    vireo_task_queue_info_t info;
    vireo_task_queue_metrics_t metrics;
    CHECK(vireo_task_queue_inspect(queue, &info) == VIREO_OK);
    CHECK(vireo_task_queue_inspect_metrics(queue, &metrics) == VIREO_OK);
    CHECK(info.state == VIREO_TASK_QUEUE_DRAIN && info.count == 0 && info.wait_prepared);
    CHECK(metrics.depth == 0 && metrics.high_watermark >= 1 && metrics.high_watermark <= 3);
    CHECK(metrics.full_rejections == full && metrics.closed_rejections == 1);
    CHECK(!metrics.rejection_count_saturated);
    CHECK(vireo_task_queue_destroy(&queue) == VIREO_OK && queue == NULL);
}

/**
 * @brief
 *     一项已领取task的测试安全点，只以原子门传进度，不公开/共享task owner。
 */
typedef struct leased_task {
    vireo_task_queue_t *queue; /**< 借至join；worker只调用一次wait_pop。 */
    atomic_bool leased; /**< task已领取且原wait_pop返回后release发布。 */
    atomic_bool finish_allowed; /**< main释放根引用后release开门，worker acquire重检。 */
    atomic_bool finished; /**< task清理完成才release置true，不由close设置。 */
} leased_task_t;

/**
 * @brief
 *     已领取任务停在测试安全点，close之后仍由worker自己观察取消并释放。
 *
 * @param[in,out] argument
 *     存活leased_task，main只能通过原子字段观察进度。
 *
 * @return
 *     NULL，任务唯一owner清空后才发布finished，caller仍须join。
 */
static void *leased_worker(void *argument) {
    leased_task_t *state = argument;
    int previous = 0;
    CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previous) == 0);
    vireo_task_t *task = NULL;
    vireo_task_queue_transfer_report_t report;
    CHECK(vireo_task_queue_wait_pop(state->queue, &task, &report) == VIREO_OK && report.transferred);
    vireo_task_info_t const info = inspect_task(task);
    CHECK(info.metadata.request_instance_id == 1001);
    bool requested = true;
    CHECK(vireo_task_is_cancel_requested(task, &requested) == VIREO_OK && !requested);
    atomic_store_explicit(&state->leased, true, memory_order_release);
    while (!atomic_load_explicit(&state->finish_allowed, memory_order_acquire)) {
        sched_yield();
    }
    CHECK(vireo_task_is_cancel_requested(task, &requested) == VIREO_OK && requested);
    CHECK(vireo_task_destroy(&task) == VIREO_OK && task == NULL);
    atomic_store_explicit(&state->finished, true, memory_order_release);
    CHECK(pthread_setcancelstate(previous, NULL) == 0);
    return NULL;
}

/**
 * @brief
 *     CANCEL_PENDING只处理queue拥有项；depth0时已有leased项仍未清理。
 */
static void cancel_pending_inflight(void) {
    vireo_task_queue_t *queue = make_queue(3, true);
    vireo_task_cancel_t *cancel = NULL;
    CHECK(vireo_task_cancel_create(1024, &cancel) == VIREO_OK);
    uint64_t full = 0;
    for (uint64_t id = 1001; id <= 1003; ++id) {
        vireo_task_t *task = make_task(id, 200, cancel);
        submit(queue, &task, &full);
    }
    leased_task_t state;
    state.queue = queue;
    atomic_init(&state.leased, false);
    atomic_init(&state.finish_allowed, false);
    atomic_init(&state.finished, false);
    pthread_t worker;
    CHECK(pthread_create(&worker, NULL, leased_worker, &state) == 0);
    while (!atomic_load_explicit(&state.leased, memory_order_acquire)) {
        sched_yield();
    }
    close_queue(queue, VIREO_TASK_QUEUE_CANCEL_PENDING);
    bool requested = true;
    CHECK(vireo_task_cancel_is_requested(cancel, &requested) == VIREO_OK && !requested);
    vireo_task_queue_metrics_t metrics;
    CHECK(vireo_task_queue_inspect_metrics(queue, &metrics) == VIREO_OK);
    CHECK(metrics.depth == 2 && metrics.high_watermark == 3);
    vireo_task_queue_transfer_report_t report;
    vireo_task_t *out = NULL;
    CHECK(vireo_task_queue_try_pop(queue, &out, &report) == VIREO_RESULT_CANCELLED);
    CHECK(out == NULL && !report.transferred);
    bool seen[2] = {false, false};
    for (unsigned i = 0; i < 2; ++i) {
        CHECK(vireo_task_queue_try_take_cancelled(queue, &out, &report) == VIREO_OK);
        CHECK(out != NULL && report.transferred);
        vireo_task_info_t const info = inspect_task(out);
        uint64_t const id = info.metadata.request_instance_id;
        CHECK(id >= 1002 && id <= 1003 && !seen[(unsigned)(id - 1002)]);
        seen[(unsigned)(id - 1002)] = true;
        CHECK(vireo_task_is_cancel_requested(out, &requested) == VIREO_OK && !requested);
        CHECK(vireo_task_destroy(&out) == VIREO_OK && out == NULL);
    }
    CHECK(vireo_task_queue_try_take_cancelled(queue, &out, &report) == VIREO_RESULT_NOT_FOUND);
    CHECK(vireo_task_queue_inspect_metrics(queue, &metrics) == VIREO_OK && metrics.depth == 0);
    CHECK(!atomic_load_explicit(&state.finished, memory_order_acquire));
    CHECK(vireo_task_cancel_request(cancel) == VIREO_OK);
    CHECK(vireo_task_cancel_destroy(&cancel) == VIREO_OK && cancel == NULL);
    /* 根引用已归还，leased task仍持最后一份；不能靠depth0提前销毁借用queue。 */
    atomic_store_explicit(&state.finish_allowed, true, memory_order_release);
    CHECK(pthread_join(worker, NULL) == 0);
    CHECK(atomic_load_explicit(&state.finished, memory_order_acquire));
    CHECK(vireo_task_queue_destroy(&queue) == VIREO_OK && queue == NULL);
}

/**
 * @brief
 *     满/关闭失败仍由producer清理，两个task各持cancel引用，根释放不提前free。
 */
static void rejected_owner_cleanup(void) {
    vireo_task_queue_t *queue = make_queue(1, false);
    vireo_task_cancel_t *cancel = NULL;
    CHECK(vireo_task_cancel_create(1024, &cancel) == VIREO_OK);
    vireo_task_t *first = make_task(2001, 200, cancel), *second = make_task(2002, 200, cancel);
    vireo_task_t *const original = second;
    vireo_task_queue_transfer_report_t report;
    CHECK(vireo_task_queue_try_push(queue, &first, &report) == VIREO_OK && first == NULL);
    errno = EILSEQ;
    CHECK(vireo_task_queue_try_push(queue, &second, &report) == VIREO_RESULT_BUSY);
    CHECK(second == original && !report.transferred && errno == EILSEQ);
    /* 本组没有并发访问，非空destroy合法拒绝并保持owner。 */
    vireo_task_queue_t *const original_queue = queue;
    CHECK(vireo_task_queue_destroy(&queue) == VIREO_RESULT_BUSY && queue == original_queue);
    close_queue(queue, VIREO_TASK_QUEUE_DRAIN);
    CHECK(vireo_task_queue_try_push(queue, &second, &report) == VIREO_RESULT_CANCELLED);
    CHECK(second == original && !report.transferred && errno == EILSEQ);
    CHECK(vireo_task_cancel_request(cancel) == VIREO_OK);
    CHECK(vireo_task_cancel_destroy(&cancel) == VIREO_OK && cancel == NULL);
    bool requested = false;
    CHECK(vireo_task_is_cancel_requested(second, &requested) == VIREO_OK && requested);
    CHECK(inspect_task(second).metadata.request_instance_id == 2002);
    CHECK(vireo_task_destroy(&second) == VIREO_OK);
    CHECK(vireo_task_queue_try_pop(queue, &first, &report) == VIREO_OK && report.transferred);
    CHECK(vireo_task_is_cancel_requested(first, &requested) == VIREO_OK && requested);
    CHECK(inspect_task(first).metadata.request_instance_id == 2001);
    CHECK(vireo_task_destroy(&first) == VIREO_OK);
    CHECK(vireo_task_queue_try_pop(queue, &first, &report) == VIREO_RESULT_CANCELLED && first == NULL);
    vireo_task_queue_metrics_t metrics;
    CHECK(vireo_task_queue_inspect_metrics(queue, &metrics) == VIREO_OK);
    CHECK(metrics.depth == 0 && metrics.high_watermark == 1);
    CHECK(metrics.full_rejections == 1 && metrics.closed_rejections == 1);
    CHECK(vireo_task_queue_destroy(&queue) == VIREO_OK && queue == NULL);
}

int main(void) {
    fifo_snapshot();
    spmc_drain();
    cancel_pending_inflight();
    rejected_owner_cleanup();
    puts("test_task_queue_integration: 4 groups; public interfaces only; 3 pthread create/join");
    return 0;
}
