/*
 * PROJECT : VIREO
 * FILE    : test_task_queue_transfer.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-11
 * BRIEF   : 唯一交接、FIFO环绕、真实竞争及同步异常进度
 */

#include "thread/task_queue_internal.h"

#include <errno.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #condition); \
        return 1; \
    } \
} while (0)

static vireo_task_metadata_t metadata(uint64_t id) {
    vireo_task_metadata_t const value = {{1, 0, 1, 1}, id, 7, 0};
    return value;
}

/**
 * @brief
 *     通过公开合同复制两个独立校验字，来源随后改写，检验真实发布内容。
 *
 * @param[in] id
 *     非零实例标签，只用于测试，不访问task私有布局。
 * @param[out] out
 *     必需独占空task owner，成功由测试拥有。
 *
 * @return
 *     task公开创建结果，无未返回的拥有者。
 */
static vireo_result_t make_task(uint64_t id, vireo_task_t **out) {
    uint64_t data[] = {id, id ^ UINT64_C(0xdeadbeef12345678)};
    vireo_result_t const result = vireo_task_create_copy(metadata(id), data, sizeof(data), 1024, out);
    memset(data, 0xff, sizeof(data));
    return result;
}

/**
 * @brief
 *     短借领取后的task，独立核对元数据和两个payload字，不保留view。
 *
 * @param[in] task
 *     测试已领取且唯一拥有的存活对象。
 * @param[in] id
 *     预期非零标签。
 *
 * @return
 *     0内容匹配，1公开读取或内容失败；不消费task。
 */
static int verify_task(vireo_task_t *task, uint64_t id) {
    vireo_task_info_t info;
    vireo_task_payload_view_t view;
    uint64_t words[2];
    CHECK(vireo_task_inspect(task, &info) == VIREO_OK);
    CHECK(info.metadata.request_instance_id == id && info.metadata.operation == 7);
    CHECK(info.metadata.deadline_ns == 0 && info.payload_size == sizeof(words));
    CHECK(vireo_task_borrow_payload(task, &view) == VIREO_OK && view.size == sizeof(words));
    memcpy(words, view.data, sizeof(words));
    CHECK(words[0] == id && words[1] == (id ^ UINT64_C(0xdeadbeef12345678)));
    return 0;
}

static bool clean_report(vireo_task_queue_transfer_report_t report, bool transferred) {
    return report.stage == VIREO_TASK_QUEUE_STAGE_NONE && report.transferred == transferred &&
        report.pthread_error == 0;
}

static int fifo_and_wrap(void) {
    size_t const capacities[] = {1, 3, 17};
    for (size_t c = 0; c < sizeof(capacities) / sizeof(capacities[0]); ++c) {
        vireo_task_queue_options_t const options = {capacities[c], 4096};
        vireo_task_queue_t *queue = NULL;
        CHECK(vireo_task_queue_create(&options, &queue) == VIREO_OK);
        vireo_task_queue_transfer_report_t report;
        uint64_t next = 1;
        for (size_t i = 0; i < capacities[c]; ++i) {
            vireo_task_t *task = NULL;
            CHECK(make_task(next++, &task) == VIREO_OK);
            errno = EDOM;
            CHECK(vireo_task_queue_try_push(queue, &task, &report) == VIREO_OK);
            CHECK(task == NULL && clean_report(report, true) && errno == EDOM);
        }
        uint64_t expected = 1;
        /* 每轮先领取再填回，保持满环并反复跨边界，序号独立作oracle。 */
        for (size_t i = 0; i < capacities[c] * 5 + 2; ++i) {
            vireo_task_t *task = NULL;
            CHECK(vireo_task_queue_try_pop(queue, &task, &report) == VIREO_OK);
            CHECK(task != NULL && clean_report(report, true) && errno == EDOM);
            CHECK(verify_task(task, expected++) == 0);
            CHECK(vireo_task_destroy(&task) == VIREO_OK);
            CHECK(make_task(next++, &task) == VIREO_OK);
            CHECK(vireo_task_queue_try_push(queue, &task, &report) == VIREO_OK && task == NULL);
        }
        while (expected < next) {
            vireo_task_t *task = NULL;
            CHECK(vireo_task_queue_try_pop(queue, &task, &report) == VIREO_OK);
            CHECK(verify_task(task, expected++) == 0);
            CHECK(vireo_task_destroy(&task) == VIREO_OK);
        }
        vireo_task_queue_info_t info;
        CHECK(vireo_task_queue_inspect(queue, &info) == VIREO_OK && info.count == 0);
        CHECK(vireo_task_queue_destroy(&queue) == VIREO_OK && queue == NULL);
    }
    return 0;
}

static int full_empty_and_nonempty_destroy(void) {
    vireo_task_queue_options_t const options = {1, 4096};
    vireo_task_queue_t *queue = NULL;
    vireo_task_t *task = NULL;
    vireo_task_t *extra = NULL;
    vireo_task_queue_transfer_report_t report;
    CHECK(vireo_task_queue_create(&options, &queue) == VIREO_OK);
    errno = EILSEQ;
    CHECK(vireo_task_queue_try_pop(queue, &task, &report) == VIREO_RESULT_NOT_FOUND);
    CHECK(task == NULL && clean_report(report, false) && errno == EILSEQ);
    CHECK(make_task(1, &task) == VIREO_OK && make_task(2, &extra) == VIREO_OK);
    CHECK(vireo_task_queue_try_push(queue, &task, &report) == VIREO_OK && task == NULL);
    vireo_task_t *const original_extra = extra;
    CHECK(vireo_task_queue_try_push(queue, &extra, &report) == VIREO_RESULT_BUSY);
    CHECK(extra == original_extra && clean_report(report, false) && errno == EILSEQ);
    vireo_task_queue_t *const original_queue = queue;
    CHECK(vireo_task_queue_destroy(&queue) == VIREO_RESULT_BUSY && queue == original_queue);
    vireo_task_queue_info_t info;
    CHECK(vireo_task_queue_inspect(queue, &info) == VIREO_OK && info.count == 1 && info.capacity == 1);
    CHECK(vireo_task_queue_try_pop(queue, &task, &report) == VIREO_OK);
    CHECK(verify_task(task, 1) == 0 && verify_task(extra, 2) == 0);
    CHECK(vireo_task_destroy(&task) == VIREO_OK && vireo_task_destroy(&extra) == VIREO_OK);
    CHECK(vireo_task_queue_destroy(&queue) == VIREO_OK && errno == EILSEQ);
    return 0;
}

static int basic_guards_and_report(void) {
    vireo_task_queue_options_t const options = {1, 4096};
    vireo_task_queue_t *queue = NULL;
    vireo_task_t *task = NULL;
    vireo_task_t *empty = NULL;
    vireo_task_queue_transfer_report_t report;
    CHECK(vireo_task_queue_create(&options, &queue) == VIREO_OK);
    CHECK(make_task(1, &task) == VIREO_OK);
    vireo_task_t *const original = task;
    errno = ERANGE;
    CHECK(vireo_task_queue_try_push(NULL, &task, &report) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(clean_report(report, false) && task == original);
    CHECK(vireo_task_queue_try_push(queue, NULL, &report) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(clean_report(report, false));
    CHECK(vireo_task_queue_try_push(queue, &task, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(task == original);
    CHECK(vireo_task_queue_try_push(queue, &empty, &report) == VIREO_RESULT_NOT_FOUND);
    CHECK(clean_report(report, false));
    CHECK(vireo_task_queue_try_pop(NULL, &empty, &report) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(clean_report(report, false) && empty == NULL);
    CHECK(vireo_task_queue_try_pop(queue, NULL, &report) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(clean_report(report, false));
    CHECK(vireo_task_queue_try_pop(queue, &task, &report) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(task == original && clean_report(report, false));
    CHECK(vireo_task_queue_try_pop(queue, &empty, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(empty == NULL && errno == ERANGE);
    CHECK(vireo_task_destroy(&task) == VIREO_OK && vireo_task_queue_destroy(&queue) == VIREO_OK);
    return 0;
}

static int cancellation_and_expired_payload(void) {
    vireo_task_queue_options_t const options = {3, 4096};
    vireo_task_queue_t *queue = NULL;
    vireo_task_cancel_t *cancel = NULL;
    vireo_task_t *task = NULL;
    unsigned char data[] = {0, 0xff, 0x42};
    CHECK(vireo_task_queue_create(&options, &queue) == VIREO_OK);
    CHECK(vireo_task_cancel_create(1024, &cancel) == VIREO_OK);
    CHECK(vireo_task_create_copy_with_cancel(metadata(9), data, sizeof(data), 1024, cancel,
                                            &task) == VIREO_OK);
    memset(data, 0x77, sizeof(data));
    vireo_task_queue_transfer_report_t report;
    CHECK(vireo_task_queue_try_push(queue, &task, &report) == VIREO_OK && task == NULL);
    CHECK(vireo_task_cancel_request(cancel) == VIREO_OK);
    CHECK(vireo_task_cancel_destroy(&cancel) == VIREO_OK);
    CHECK(vireo_task_queue_try_pop(queue, &task, &report) == VIREO_OK);
    bool requested = false;
    CHECK(vireo_task_is_cancel_requested(task, &requested) == VIREO_OK && requested);
    vireo_task_payload_view_t view;
    CHECK(vireo_task_borrow_payload(task, &view) == VIREO_OK && view.size == 3);
    CHECK(view.data[0] == 0 && view.data[1] == 0xff && view.data[2] == 0x42);
    CHECK(vireo_task_destroy(&task) == VIREO_OK && vireo_task_queue_destroy(&queue) == VIREO_OK);
    return 0;
}

/**
 * @brief
 *     只在主线程独占使用的配对资源与pthread直接错误模型。
 */
typedef struct fault_trace {
    size_t allocations; /**< 真实原块申请次数。 */
    size_t releases; /**< 真实原块释放次数。 */
    void *live; /**< 活跃原块观测别名，不额外拥有。 */
    int init_error; /**< 非0时不初始化mutex，直接失败。 */
    int lock_error; /**< 非0时不获取mutex，直接失败。 */
    int unlock_error; /**< 真实unlock成功后覆盖报告，用于commit异常。 */
    int destroy_error; /**< 非0时不销毁mutex，直接失败。 */
    size_t init_calls; /**< 初始化操作次数。 */
    size_t lock_calls; /**< 一次try操作次数。 */
    size_t unlock_calls; /**< 成功取得锁后的释放尝试次数。 */
    size_t destroy_calls; /**< 空对象销毁mutex的尝试次数。 */
} fault_trace_t;

/**
 * @brief
 *     真实分配独占原块并留观测别名，context活到配对释放。
 *
 * @param[in,out] context
 *     主线程独占trace，不保存之外的借用地址。
 * @param[in] bytes
 *     受检正请求量。
 *
 * @return
 *     新块或NULL，errno故意扰动。
 */
static void *fault_allocate(void *context, size_t bytes) {
    fault_trace_t *trace = context;
    ++trace->allocations;
    trace->live = malloc(bytes);
    errno = EAGAIN;
    return trace->live;
}

/**
 * @brief
 *     配对free原块，不释放trace，调用后清其观测别名。
 *
 * @param[in,out] context
 *     持有该唯一活跃申请观测的独占trace。
 * @param[in] allocation
 *     配对原地址，没有未销毁mutex或task。
 *
 * @note
 *     无失败返回，故意扰动errno由产品外层恢复。
 */
static void fault_free(void *context, void *allocation) {
    fault_trace_t *trace = context;
    ++trace->releases;
    if (allocation != trace->live) { abort(); }
    free(allocation);
    trace->live = NULL;
    errno = EILSEQ;
}

/**
 * @brief
 *     未发布mutex真实初始化或在获取之前直接注入失败。
 *
 * @param[in,out] context
 *     独占trace，错误开关不会被其他线程改变。
 * @param[out] mutex
 *     产品尚未初始化的存活内存，短借。
 *
 * @return
 *     非0未初始化、0实际完成初始化，扰动errno。
 */
static int fault_init(void *context, pthread_mutex_t *mutex) {
    fault_trace_t *trace = context;
    ++trace->init_calls;
    errno = EIO;
    return trace->init_error != 0 ? trace->init_error : pthread_mutex_init(mutex, NULL);
}

/**
 * @brief
 *     一次真实trylock，或在未取锁时注入直接错误。
 *
 * @param[in,out] context
 *     独占trace，存活至销毁。
 * @param[in,out] mutex
 *     已初始化对象，0返回后当前线程负责解锁。
 *
 * @return
 *     pthread或局部非0错误，不通过errno表达原因。
 */
static int fault_lock(void *context, pthread_mutex_t *mutex) {
    fault_trace_t *trace = context;
    ++trace->lock_calls;
    errno = EIO;
    return trace->lock_error != 0 ? trace->lock_error : pthread_mutex_trylock(mutex);
}

/**
 * @brief
 *     总是先真实释放，再可注入“报告异常”，检验不可回滚的commit。
 *
 * @param[in,out] context
 *     独占trace，开关不等实际glibc故障。
 * @param[in,out] mutex
 *     当前线程已持有，短借。
 *
 * @return
 *     真实释放错误优先，否则返回局部报告错误或0。
 */
static int fault_unlock(void *context, pthread_mutex_t *mutex) {
    fault_trace_t *trace = context;
    ++trace->unlock_calls;
    int const code = pthread_mutex_unlock(mutex);
    errno = EIO;
    return code != 0 ? code : trace->unlock_error;
}

/**
 * @brief
 *     空且静止资源真实销毁，或不改变mutex并注入失败。
 *
 * @param[in,out] context
 *     独占trace，存活至释放原块。
 * @param[in,out] mutex
 *     无锁持有者或其他在途访问的存活mutex。
 *
 * @return
 *     0真实销毁，非0保留mutex，故意扰动errno。
 */
static int fault_destroy(void *context, pthread_mutex_t *mutex) {
    fault_trace_t *trace = context;
    ++trace->destroy_calls;
    errno = EIO;
    return trace->destroy_error != 0 ? trace->destroy_error : pthread_mutex_destroy(mutex);
}

/**
 * @brief
 *     用本函数短期操作表创建对象，借用trace持续到最终释放。
 *
 * @param[in,out] trace
 *     主线程独占且存活的故障上下文，不由queue释放。
 * @param[out] out
 *     合法空queue owner，成功测试接管。
 *
 * @return
 *     私有创建实际结果，失败无新owner。
 */
static vireo_result_t fault_queue(fault_trace_t *trace, vireo_task_queue_t **out) {
    vireo_task_queue_options_t const options = {1, 4096};
    vireo_task_queue_allocator_t const allocator = {trace, fault_allocate, fault_free};
    vireo_task_queue_sync_ops_t const sync = {
        trace, fault_init, fault_lock, fault_unlock, fault_destroy
    };
    return vireo_task_queue_create_with_ops(&options, &allocator, &sync, out);
}

static int initialization_rollback(void) {
    int const errors[] = {ENOMEM, EAGAIN, EINVAL};
    for (size_t i = 0; i < sizeof(errors) / sizeof(errors[0]); ++i) {
        fault_trace_t trace = {.init_error = errors[i]};
        vireo_task_queue_t *queue = NULL;
        errno = EDOM;
        CHECK(fault_queue(&trace, &queue) ==
              (errors[i] == ENOMEM ? VIREO_RESULT_NO_MEMORY : VIREO_RESULT_INTERNAL));
        CHECK(queue == NULL && trace.live == NULL && trace.allocations == 1 && trace.releases == 1);
        CHECK(trace.init_calls == 1 && trace.destroy_calls == 0 && errno == EDOM);
        trace.init_error = 0;
        CHECK(fault_queue(&trace, &queue) == VIREO_OK);
        CHECK(vireo_task_queue_destroy(&queue) == VIREO_OK);
        CHECK(trace.allocations == 2 && trace.releases == 2 && trace.destroy_calls == 1);
    }
    return 0;
}

static int lock_failures_and_priority(void) {
    fault_trace_t trace = {0};
    vireo_task_queue_t *queue = NULL;
    vireo_task_t *task = NULL;
    vireo_task_t *empty = NULL;
    CHECK(fault_queue(&trace, &queue) == VIREO_OK && make_task(1, &task) == VIREO_OK);
    vireo_task_t *const original = task;
    vireo_task_queue_transfer_report_t report;
    int const codes[] = {EBUSY, EINVAL};
    for (size_t i = 0; i < sizeof(codes) / sizeof(codes[0]); ++i) {
        trace.lock_error = codes[i];
        vireo_result_t const expected = i == 0 ? VIREO_RESULT_BUSY : VIREO_RESULT_INTERNAL;
        errno = ERANGE;
        CHECK(vireo_task_queue_try_push(queue, &task, &report) == expected);
        CHECK(task == original && report.stage == VIREO_TASK_QUEUE_STAGE_LOCK);
        CHECK(!report.transferred && report.pthread_error == codes[i] && errno == ERANGE);
        CHECK(vireo_task_queue_try_pop(queue, &empty, &report) == expected && empty == NULL);
        CHECK(report.stage == VIREO_TASK_QUEUE_STAGE_LOCK && !report.transferred);
        vireo_task_queue_info_t info;
        unsigned char saved[sizeof(info)];
        memset(&info, 0xa5, sizeof(info)); memcpy(saved, &info, sizeof(info));
        CHECK(vireo_task_queue_inspect(queue, &info) == expected);
        CHECK(memcmp(saved, &info, sizeof(info)) == 0 && trace.unlock_calls == 0);
        size_t const calls = trace.lock_calls;
        CHECK(vireo_task_queue_try_push(queue, &empty, &report) == VIREO_RESULT_NOT_FOUND);
        CHECK(clean_report(report, false) && trace.lock_calls == calls);
        CHECK(vireo_task_queue_try_pop(queue, &task, &report) == VIREO_RESULT_INVALID_ARGUMENT);
        CHECK(clean_report(report, false) && task == original && trace.lock_calls == calls);
    }
    trace.lock_error = 0;
    CHECK(vireo_task_destroy(&task) == VIREO_OK && vireo_task_queue_destroy(&queue) == VIREO_OK);
    return 0;
}

static int unlock_progress(void) {
    fault_trace_t trace = {0};
    vireo_task_queue_t *queue = NULL;
    vireo_task_t *task = NULL;
    CHECK(fault_queue(&trace, &queue) == VIREO_OK && make_task(1, &task) == VIREO_OK);
    vireo_task_queue_transfer_report_t report;
    trace.unlock_error = EIO;
    errno = EDOM;
    CHECK(vireo_task_queue_try_push(queue, &task, &report) == VIREO_RESULT_INTERNAL);
    CHECK(task == NULL && report.transferred && report.stage == VIREO_TASK_QUEUE_STAGE_UNLOCK);
    CHECK(report.pthread_error == EIO && errno == EDOM);
    CHECK(vireo_task_queue_try_pop(queue, &task, &report) == VIREO_RESULT_INTERNAL);
    CHECK(task != NULL && report.transferred && report.stage == VIREO_TASK_QUEUE_STAGE_UNLOCK);
    CHECK(report.pthread_error == EIO && verify_task(task, 1) == 0);
    CHECK(vireo_task_destroy(&task) == VIREO_OK);
    trace.unlock_error = 0;
    vireo_task_queue_info_t info;
    CHECK(vireo_task_queue_inspect(queue, &info) == VIREO_OK && info.count == 0);
    CHECK(vireo_task_queue_destroy(&queue) == VIREO_OK && errno == EDOM);
    return 0;
}

static int unlock_rejections_and_snapshot(void) {
    fault_trace_t trace = {0};
    vireo_task_queue_t *queue = NULL;
    vireo_task_t *task = NULL;
    vireo_task_t *extra = NULL;
    vireo_task_queue_transfer_report_t report;
    CHECK(fault_queue(&trace, &queue) == VIREO_OK && make_task(1, &task) == VIREO_OK);
    trace.unlock_error = EPERM;
    errno = EDOM;
    CHECK(vireo_task_queue_try_pop(queue, &extra, &report) == VIREO_RESULT_INTERNAL);
    CHECK(extra == NULL && !report.transferred && report.pthread_error == EPERM);
    CHECK(report.stage == VIREO_TASK_QUEUE_STAGE_UNLOCK);
    trace.unlock_error = 0;
    CHECK(vireo_task_queue_try_push(queue, &task, &report) == VIREO_OK);
    CHECK(make_task(2, &extra) == VIREO_OK);
    vireo_task_t *const original = extra;
    trace.unlock_error = EPERM;
    CHECK(vireo_task_queue_try_push(queue, &extra, &report) == VIREO_RESULT_INTERNAL);
    CHECK(extra == original && !report.transferred && report.stage == VIREO_TASK_QUEUE_STAGE_UNLOCK);
    vireo_task_queue_info_t info;
    unsigned char saved[sizeof(info)];
    memset(&info, 0x5a, sizeof(info)); memcpy(saved, &info, sizeof(info));
    CHECK(vireo_task_queue_inspect(queue, &info) == VIREO_RESULT_INTERNAL);
    CHECK(memcmp(saved, &info, sizeof(info)) == 0 && errno == EDOM);
    trace.unlock_error = 0;
    CHECK(vireo_task_queue_try_pop(queue, &task, &report) == VIREO_OK);
    CHECK(verify_task(task, 1) == 0 && verify_task(extra, 2) == 0);
    CHECK(vireo_task_destroy(&task) == VIREO_OK && vireo_task_destroy(&extra) == VIREO_OK);
    CHECK(vireo_task_queue_destroy(&queue) == VIREO_OK);
    return 0;
}

static int destruction_and_ops_copy(void) {
    fault_trace_t trace = {0};
    vireo_task_queue_options_t const options = {1, 4096};
    vireo_task_queue_allocator_t allocator = {&trace, fault_allocate, fault_free};
    vireo_task_queue_sync_ops_t sync = {
        &trace, fault_init, fault_lock, fault_unlock, fault_destroy
    };
    vireo_task_queue_t *queue = NULL;
    CHECK(vireo_task_queue_create_with_ops(&options, &allocator, &sync, &queue) == VIREO_OK);
    /* 操作表来源可结束/改写；context仍借至销毁。 */
    memset(&sync, 0, sizeof(sync)); memset(&allocator, 0, sizeof(allocator));
    vireo_task_t *task = NULL;
    vireo_task_queue_transfer_report_t report;
    CHECK(make_task(1, &task) == VIREO_OK);
    CHECK(vireo_task_queue_try_push(queue, &task, &report) == VIREO_OK);
    errno = EILSEQ;
    CHECK(vireo_task_queue_destroy(&queue) == VIREO_RESULT_BUSY && trace.destroy_calls == 0);
    CHECK(vireo_task_queue_try_pop(queue, &task, &report) == VIREO_OK);
    CHECK(vireo_task_destroy(&task) == VIREO_OK);
    vireo_task_queue_t *const original = queue;
    trace.destroy_error = EBUSY;
    CHECK(vireo_task_queue_destroy(&queue) == VIREO_RESULT_BUSY && queue == original);
    trace.destroy_error = EINVAL;
    CHECK(vireo_task_queue_destroy(&queue) == VIREO_RESULT_INTERNAL && queue == original);
    CHECK(trace.live == original && trace.releases == 0 && errno == EILSEQ);
    trace.destroy_error = 0;
    CHECK(vireo_task_queue_destroy(&queue) == VIREO_OK && queue == NULL);
    CHECK(trace.destroy_calls == 3 && trace.releases == 1 && trace.live == NULL);
    CHECK(vireo_task_queue_destroy(&queue) == VIREO_OK && trace.releases == 1 && errno == EILSEQ);
    return 0;
}

static int private_sync_guards(void) {
    fault_trace_t trace = {0};
    vireo_task_queue_options_t const options = {1, 4096};
    vireo_task_queue_allocator_t const allocator = {&trace, fault_allocate, fault_free};
    vireo_task_queue_sync_ops_t const valid = {
        &trace, fault_init, fault_lock, fault_unlock, fault_destroy
    };
    vireo_task_queue_t *queue = NULL;
    errno = EDOM;
    CHECK(vireo_task_queue_create_with_ops(&options, &allocator, NULL, &queue) ==
          VIREO_RESULT_INVALID_ARGUMENT);
    for (size_t i = 0; i < 4; ++i) {
        vireo_task_queue_sync_ops_t invalid = valid;
        if (i == 0) { invalid.init = NULL; }
        if (i == 1) { invalid.try_lock = NULL; }
        if (i == 2) { invalid.unlock = NULL; }
        if (i == 3) { invalid.destroy = NULL; }
        CHECK(vireo_task_queue_create_with_ops(&options, &allocator, &invalid, &queue) ==
              VIREO_RESULT_INVALID_ARGUMENT);
    }
    CHECK(queue == NULL && trace.allocations == 0 && trace.init_calls == 0 && errno == EDOM);
    return 0;
}

/**
 * @brief
 *     主线程创建后发布给一次竞争线程，join后再收回访问。
 */
typedef struct contender {
    vireo_task_queue_t *queue; /**< 存活queue短借到join，不负责释放。 */
    vireo_task_t *task; /**< 此独立owner提交失败后仍持有，join后主线程释放。 */
    bool ok; /**< worker写、join后main读的全部竞争断言结果。 */
} contender_t;

/**
 * @brief
 *     在main实际持有mutex期间核对三入口均立即拒绝，而非阻塞join。
 *
 * @param[in,out] context
 *     pthread_create发布的独占contender，借到线程返回。
 *
 * @return
 *     NULL；实际结论由join后的ok返回，不共享线程的errno。
 */
static void *contend(void *context) {
    contender_t *args = context;
    vireo_task_t *const original = args->task;
    vireo_task_t *out = NULL;
    vireo_task_queue_transfer_report_t report;
    vireo_task_queue_info_t info;
    unsigned char saved[sizeof(info)];
    memset(&info, 0xa5, sizeof(info)); memcpy(saved, &info, sizeof(info));
    errno = EDOM;
    bool ok = vireo_task_queue_try_push(args->queue, &args->task, &report) == VIREO_RESULT_BUSY;
    ok = ok && args->task == original && report.stage == VIREO_TASK_QUEUE_STAGE_LOCK &&
        !report.transferred && report.pthread_error == EBUSY;
    ok = ok && vireo_task_queue_try_pop(args->queue, &out, &report) == VIREO_RESULT_BUSY;
    ok = ok && out == NULL && report.stage == VIREO_TASK_QUEUE_STAGE_LOCK &&
        !report.transferred && report.pthread_error == EBUSY;
    ok = ok && vireo_task_queue_inspect(args->queue, &info) == VIREO_RESULT_BUSY;
    args->ok = ok && memcmp(saved, &info, sizeof(info)) == 0 && errno == EDOM;
    return NULL;
}

static int real_mutex_contention(void) {
    vireo_task_queue_options_t const options = {3, 4096};
    vireo_task_queue_t *queue = NULL;
    contender_t args = {NULL, NULL, false};
    CHECK(vireo_task_queue_create(&options, &queue) == VIREO_OK);
    args.queue = queue;
    CHECK(make_task(1, &args.task) == VIREO_OK);
    CHECK(pthread_mutex_lock(&queue->mutex) == 0);
    pthread_t thread;
    int const create_code = pthread_create(&thread, NULL, contend, &args);
    if (create_code != 0) {
        if (pthread_mutex_unlock(&queue->mutex) != 0) { abort(); }
        (void)vireo_task_destroy(&args.task);
        (void)vireo_task_queue_destroy(&queue);
        CHECK(create_code == 0);
    }
    /* 错用阻塞lock会卡住这里，由CTest时限显式失败；不依赖sleep。 */
    if (pthread_join(thread, NULL) != 0) { abort(); }
    CHECK(pthread_mutex_unlock(&queue->mutex) == 0);
    CHECK(args.ok && verify_task(args.task, 1) == 0);
    vireo_task_queue_info_t info;
    CHECK(vireo_task_queue_inspect(queue, &info) == VIREO_OK && info.count == 0);
    CHECK(vireo_task_destroy(&args.task) == VIREO_OK);
    CHECK(vireo_task_queue_destroy(&queue) == VIREO_OK);
    return 0;
}

enum { PRODUCERS = 4, CONSUMERS = 3, PER_PRODUCER = 64,
       TOTAL = PRODUCERS * PER_PRODUCER, ATTEMPT_LIMIT = 2000000 };

/**
 * @brief
 *     并发测试控制与独立oracle，不给产品payload建立旁路发布。
 */
typedef struct mpmc_state {
    vireo_task_queue_t *queue; /**< 全部join前借用存活queue，不在worker销毁。 */
    atomic_bool start; /**< task创建之前唯一release启动门，worker acquire进入。 */
    atomic_bool failed; /**< relaxed失败停止标志，不发布task或非原子诊断。 */
    atomic_size_t consumed; /**< relaxed完成计数，仅用于有界退出，不发布payload。 */
    atomic_uint seen[TOTAL]; /**< 每标签relaxed领取次数oracle，main只在join后核对。 */
} mpmc_state_t;

/**
 * @brief
 *     pthread_create发布的producer角色，不携带预制task或payload。
 */
typedef struct producer_args {
    mpmc_state_t *state; /**< 借用共享控制，main保持到全部join。 */
    size_t index; /**< 0..PRODUCERS-1，决定本线程独立标签范围。 */
} producer_args_t;

/**
 * @brief
 *     等启动门或测试失败，不传递任何创建之后的task内容。
 *
 * @param[in] state
 *     已发布且存活共享测试控制，原子字段访问。
 *
 * @return
 *     true可以开始，false创建线程失败或其他测试错误；CTest限制整体时长。
 */
static bool await_start(mpmc_state_t *state) {
    while (!atomic_load_explicit(&state->start, memory_order_acquire)) {
        if (atomic_load_explicit(&state->failed, memory_order_relaxed)) { return false; }
        if (sched_yield() != 0) {
            atomic_store_explicit(&state->failed, true, memory_order_relaxed);
            return false;
        }
    }
    return !atomic_load_explicit(&state->failed, memory_order_relaxed);
}

/**
 * @brief
 *     启动后逐项创建并交接独立task；BUSY由测试caller有界让出后重试。
 *
 * @param[in] context
 *     存活producer_args，pthread_create发布，不保存超出线程返回。
 *
 * @return
 *     NULL；失败relaxed置failed，本线程未交出的owner仍配对释放。
 */
static void *produce(void *context) {
    producer_args_t *args = context;
    mpmc_state_t *state = args->state;
    if (!await_start(state)) { return NULL; }
    for (size_t j = 0; j < PER_PRODUCER; ++j) {
        if (atomic_load_explicit(&state->failed, memory_order_relaxed)) { break; }
        vireo_task_t *task = NULL;
        uint64_t const id = (uint64_t)(args->index * PER_PRODUCER + j + 1);
        errno = EDOM;
        if (make_task(id, &task) != VIREO_OK) {
            atomic_store_explicit(&state->failed, true, memory_order_relaxed);
            break;
        }
        for (size_t attempt = 0; task != NULL && attempt < ATTEMPT_LIMIT; ++attempt) {
            if (atomic_load_explicit(&state->failed, memory_order_relaxed)) { break; }
            vireo_task_queue_transfer_report_t report;
            errno = EDOM;
            vireo_result_t const result = vireo_task_queue_try_push(state->queue, &task, &report);
            if (result == VIREO_OK) {
                if (task != NULL || !clean_report(report, true) || errno != EDOM) {
                    atomic_store_explicit(&state->failed, true, memory_order_relaxed);
                }
            } else if (result == VIREO_RESULT_BUSY && !report.transferred && task != NULL &&
                       errno == EDOM) {
                if (sched_yield() != 0) {
                    atomic_store_explicit(&state->failed, true, memory_order_relaxed);
                    break;
                }
            } else {
                atomic_store_explicit(&state->failed, true, memory_order_relaxed);
                break;
            }
        }
        if (task != NULL) {
            atomic_store_explicit(&state->failed, true, memory_order_relaxed);
            if (vireo_task_destroy(&task) != VIREO_OK) { abort(); }
            break;
        }
    }
    return NULL;
}

/**
 * @brief
 *     仅靠产品交接获得新创建task，再检查独立标签和payload并释放。
 *
 * @param[in,out] context
 *     存活共享测试控制；seen/consumed全用relaxed，不替queue发布数据。
 *
 * @return
 *     NULL；失败设置原子标志，任何实际输出owner先清理。
 */
static void *consume(void *context) {
    mpmc_state_t *state = context;
    if (!await_start(state)) { return NULL; }
    size_t attempts = 0;
    while (!atomic_load_explicit(&state->failed, memory_order_relaxed) &&
           atomic_load_explicit(&state->consumed, memory_order_relaxed) < TOTAL &&
           attempts++ < ATTEMPT_LIMIT) {
        vireo_task_t *task = NULL;
        vireo_task_queue_transfer_report_t report;
        errno = EILSEQ;
        vireo_result_t const result = vireo_task_queue_try_pop(state->queue, &task, &report);
        if (result == VIREO_OK && task != NULL && clean_report(report, true) && errno == EILSEQ) {
            vireo_task_info_t info;
            bool ok = vireo_task_inspect(task, &info) == VIREO_OK;
            uint64_t const id = ok ? info.metadata.request_instance_id : 0;
            ok = ok && id > 0 && id <= TOTAL && verify_task(task, id) == 0;
            if (ok) {
                unsigned int const previous = atomic_fetch_add_explicit(&state->seen[id - 1],
                    1, memory_order_relaxed);
                ok = previous == 0;
            }
            if (vireo_task_destroy(&task) != VIREO_OK) { abort(); }
            if (!ok || errno != EILSEQ) {
                atomic_store_explicit(&state->failed, true, memory_order_relaxed);
                break;
            }
            (void)atomic_fetch_add_explicit(&state->consumed, 1, memory_order_relaxed);
        } else if ((result == VIREO_RESULT_BUSY || result == VIREO_RESULT_NOT_FOUND) &&
                   task == NULL && !report.transferred && errno == EILSEQ) {
            if (sched_yield() != 0) {
                atomic_store_explicit(&state->failed, true, memory_order_relaxed);
                break;
            }
        } else {
            /* 同步异常若已转出，也不能因result非OK而丢弃实际owner。 */
            if (task != NULL && vireo_task_destroy(&task) != VIREO_OK) { abort(); }
            atomic_store_explicit(&state->failed, true, memory_order_relaxed);
            break;
        }
    }
    if (atomic_load_explicit(&state->consumed, memory_order_relaxed) != TOTAL &&
        attempts >= ATTEMPT_LIMIT) {
        atomic_store_explicit(&state->failed, true, memory_order_relaxed);
    }
    return NULL;
}

static int mpmc_publication_and_unique_take(void) {
    size_t const capacities[] = {3, 17};
    for (size_t c = 0; c < sizeof(capacities) / sizeof(capacities[0]); ++c) {
        vireo_task_queue_t *queue = NULL;
        vireo_task_queue_options_t const options = {capacities[c], 4096};
        CHECK(vireo_task_queue_create(&options, &queue) == VIREO_OK);
        mpmc_state_t state;
        state.queue = queue;
        atomic_init(&state.start, false); atomic_init(&state.failed, false);
        atomic_init(&state.consumed, 0);
        for (size_t i = 0; i < TOTAL; ++i) { atomic_init(&state.seen[i], 0); }
        pthread_t producers[PRODUCERS];
        pthread_t consumers[CONSUMERS];
        producer_args_t args[PRODUCERS];
        size_t producer_count = 0;
        size_t consumer_count = 0;
        for (size_t i = 0; i < PRODUCERS; ++i) {
            args[i].state = &state; args[i].index = i;
            if (pthread_create(&producers[i], NULL, produce, &args[i]) != 0) {
                atomic_store_explicit(&state.failed, true, memory_order_relaxed); break;
            }
            ++producer_count;
        }
        if (!atomic_load_explicit(&state.failed, memory_order_relaxed)) {
            for (size_t i = 0; i < CONSUMERS; ++i) {
                if (pthread_create(&consumers[i], NULL, consume, &state) != 0) {
                    atomic_store_explicit(&state.failed, true, memory_order_relaxed); break;
                }
                ++consumer_count;
            }
        }
        /* 全部task都在此之后创建；启动门不会发布后来的metadata/payload。 */
        atomic_store_explicit(&state.start, true, memory_order_release);
        for (size_t i = 0; i < producer_count; ++i) {
            if (pthread_join(producers[i], NULL) != 0) { abort(); }
        }
        for (size_t i = 0; i < consumer_count; ++i) {
            if (pthread_join(consumers[i], NULL) != 0) { abort(); }
        }
        bool ok = !atomic_load(&state.failed) && atomic_load(&state.consumed) == TOTAL;
        for (size_t i = 0; i < TOTAL; ++i) { ok = ok && atomic_load(&state.seen[i]) == 1; }
        vireo_task_queue_info_t info;
        ok = ok && vireo_task_queue_inspect(queue, &info) == VIREO_OK && info.count == 0;
        /* 创建/断言失败也在join后收回所有留在queue内的实际owner。 */
        vireo_task_t *left = NULL;
        vireo_task_queue_transfer_report_t report;
        vireo_result_t result;
        while ((result = vireo_task_queue_try_pop(queue, &left, &report)) == VIREO_OK) {
            if (vireo_task_destroy(&left) != VIREO_OK) { abort(); }
        }
        if (result != VIREO_RESULT_NOT_FOUND || left != NULL ||
            vireo_task_queue_destroy(&queue) != VIREO_OK) { abort(); }
        CHECK(ok && producer_count == PRODUCERS && consumer_count == CONSUMERS);
    }
    return 0;
}

int main(void) {
    int (*const cases[])(void) = {
        fifo_and_wrap, full_empty_and_nonempty_destroy, basic_guards_and_report,
        cancellation_and_expired_payload, initialization_rollback, lock_failures_and_priority,
        unlock_progress, unlock_rejections_and_snapshot, destruction_and_ops_copy,
        private_sync_guards, real_mutex_contention, mpmc_publication_and_unique_take
    };
    char const *const names[] = {
        "fifo_and_wrap", "full_empty_and_nonempty_destroy", "basic_guards_and_report",
        "cancellation_and_expired_payload", "initialization_rollback", "lock_failures_and_priority",
        "unlock_progress", "unlock_rejections_and_snapshot", "destruction_and_ops_copy",
        "private_sync_guards", "real_mutex_contention", "mpmc_publication_and_unique_take"
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        if (cases[i]() != 0) { return EXIT_FAILURE; }
        printf("PASS %s\n", names[i]);
    }
    puts("task queue transfer: 12 groups passed");
    return EXIT_SUCCESS;
}
