/*
 * PROJECT : VIREO
 * FILE    : test_task_queue_close.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-11
 * BRIEF   : 永久关闭、逐项交还、真实竞争和同步异常拥有权
 */

#include "thread/task_queue_internal.h"

#include <errno.h>
#include <limits.h>
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

/**
 * @brief
 *     构造公开有效metadata，只作独立测试标签。
 *
 * @param[in] id
 *     非零请求实例标签。
 *
 * @return
 *     按值元数据，无资源拥有或当前性认证。
 */
static vireo_task_metadata_t metadata(uint64_t id) {
    vireo_task_metadata_t const value = {{1, 0, 1, 1}, id, 7, 0};
    return value;
}

/**
 * @brief
 *     通过公开task复制校验字，来源随后改写，不包含task私有头。
 *
 * @param[in] id
 *     非零标签，用于metadata和payload独立校验。
 * @param[out] out
 *     独占空owner，成功由测试承担task拥有权。
 *
 * @return
 *     原task创建结果，无隐式提交。
 */
static vireo_result_t make_task(uint64_t id, vireo_task_t **out) {
    uint64_t data[] = {id, id ^ UINT64_C(0x3157abcdef123456)};
    vireo_result_t const result = vireo_task_create_copy(metadata(id), data, sizeof(data), 1024, out);
    memset(data, 0xff, sizeof(data));
    return result;
}

/**
 * @brief
 *     短借领取后的task校验内容，返回前结束payload view借用。
 *
 * @param[in] task
 *     测试当前唯一拥有的存活task。
 * @param[in] id
 *     预期实例及payload标签。
 *
 * @return
 *     0内容匹配，1公开读取或断言失败，不消费task。
 */
static int verify_task(vireo_task_t *task, uint64_t id) {
    vireo_task_info_t info;
    vireo_task_payload_view_t view;
    uint64_t words[2];
    CHECK(vireo_task_inspect(task, &info) == VIREO_OK);
    CHECK(info.metadata.request_instance_id == id && info.metadata.operation == 7);
    CHECK(vireo_task_borrow_payload(task, &view) == VIREO_OK && view.size == sizeof(words));
    memcpy(words, view.data, sizeof(words));
    CHECK(words[0] == id && words[1] == (id ^ UINT64_C(0x3157abcdef123456)));
    return 0;
}

/**
 * @brief
 *     核对正常交接报告，不只根据返回值推断拥有权。
 *
 * @param[in] report
 *     本次独立报告值。
 * @param[in] transferred
 *     预期本次拥有权是否转移。
 *
 * @return
 *     所有逻辑字段均匹配时true。
 */
static bool clean_transfer(vireo_task_queue_transfer_report_t report, bool transferred) {
    return report.stage == VIREO_TASK_QUEUE_STAGE_NONE && report.transferred == transferred &&
        report.pthread_error == 0;
}

/**
 * @brief
 *     核对正常关闭报告，重复关闭不应伪造首次提交。
 *
 * @param[in] report
 *     本次关闭报告值。
 * @param[in] changed
 *     预期本次是否首次关闭。
 *
 * @return
 *     所有逻辑字段均匹配时true。
 */
static bool clean_close(vireo_task_queue_close_report_t report, bool changed) {
    return report.stage == VIREO_TASK_QUEUE_STAGE_NONE && report.changed == changed &&
        report.pthread_error == 0;
}

static int empty_modes_and_repetition(void) {
    vireo_task_queue_state_t const modes[] = {
        VIREO_TASK_QUEUE_DRAIN, VIREO_TASK_QUEUE_CANCEL_PENDING
    };
    for (size_t i = 0; i < 2; ++i) {
        vireo_task_queue_options_t const options = {1, 4096};
        vireo_task_queue_t *queue = NULL;
        vireo_task_t *out = NULL;
        vireo_task_queue_close_report_t close_report;
        vireo_task_queue_transfer_report_t report;
        vireo_task_queue_info_t info;
        CHECK(vireo_task_queue_create(&options, &queue) == VIREO_OK);
        errno = EDOM;
        CHECK(vireo_task_queue_inspect(queue, &info) == VIREO_OK);
        CHECK(info.state == VIREO_TASK_QUEUE_OPEN && info.count == 0);
        CHECK(vireo_task_queue_try_take_cancelled(queue, &out, &report) == VIREO_RESULT_BUSY);
        CHECK(out == NULL && clean_transfer(report, false));
        CHECK(vireo_task_queue_try_pop(queue, &out, &report) == VIREO_RESULT_NOT_FOUND);
        CHECK(vireo_task_queue_close(queue, modes[i], &close_report) == VIREO_OK);
        CHECK(clean_close(close_report, true));
        CHECK(vireo_task_queue_close(queue, modes[i], &close_report) == VIREO_OK);
        CHECK(clean_close(close_report, false));
        CHECK(vireo_task_queue_close(queue, modes[1 - i], &close_report) == VIREO_RESULT_BUSY);
        CHECK(clean_close(close_report, false));
        CHECK(vireo_task_queue_try_pop(queue, &out, &report) == VIREO_RESULT_CANCELLED);
        CHECK(out == NULL && clean_transfer(report, false));
        vireo_result_t const expected = modes[i] == VIREO_TASK_QUEUE_DRAIN ?
            VIREO_RESULT_BUSY : VIREO_RESULT_NOT_FOUND;
        CHECK(vireo_task_queue_try_take_cancelled(queue, &out, &report) == expected);
        CHECK(out == NULL && clean_transfer(report, false));
        CHECK(vireo_task_queue_inspect(queue, &info) == VIREO_OK);
        CHECK(info.state == modes[i] && info.count == 0 && info.capacity == 1);
        CHECK(vireo_task_queue_destroy(&queue) == VIREO_OK && queue == NULL && errno == EDOM);
        CHECK(vireo_task_queue_destroy(&queue) == VIREO_OK);
    }
    return 0;
}

static int fifo_wrap_and_closed_push(void) {
    vireo_task_queue_state_t const modes[] = {
        VIREO_TASK_QUEUE_DRAIN, VIREO_TASK_QUEUE_CANCEL_PENDING
    };
    for (size_t m = 0; m < 2; ++m) {
        vireo_task_queue_options_t const options = {3, 4096};
        vireo_task_queue_t *queue = NULL;
        vireo_task_t *task = NULL;
        vireo_task_queue_transfer_report_t report;
        vireo_task_queue_close_report_t close_report;
        CHECK(vireo_task_queue_create(&options, &queue) == VIREO_OK);
        for (uint64_t id = 1; id <= 3; ++id) {
            CHECK(make_task(id, &task) == VIREO_OK);
            CHECK(vireo_task_queue_try_push(queue, &task, &report) == VIREO_OK && task == NULL);
        }
        CHECK(vireo_task_queue_try_pop(queue, &task, &report) == VIREO_OK);
        CHECK(verify_task(task, 1) == 0 && vireo_task_destroy(&task) == VIREO_OK);
        CHECK(make_task(4, &task) == VIREO_OK);
        CHECK(vireo_task_queue_try_push(queue, &task, &report) == VIREO_OK);
        CHECK(vireo_task_queue_close(queue, modes[m], &close_report) == VIREO_OK);
        CHECK(make_task(5, &task) == VIREO_OK);
        vireo_task_t *const original = task;
        errno = EILSEQ;
        /* 满环已关闭时优先CANCELLED，绝不能错误接管拒绝项。 */
        CHECK(vireo_task_queue_try_push(queue, &task, &report) == VIREO_RESULT_CANCELLED);
        CHECK(task == original && clean_transfer(report, false) && errno == EILSEQ);
        CHECK(verify_task(task, 5) == 0 && vireo_task_destroy(&task) == VIREO_OK);
        vireo_task_queue_t *const owner = queue;
        CHECK(vireo_task_queue_destroy(&queue) == VIREO_RESULT_BUSY && queue == owner);
        for (uint64_t id = 2; id <= 4; ++id) {
            vireo_task_queue_info_t info;
            CHECK(vireo_task_queue_inspect(queue, &info) == VIREO_OK);
            CHECK(info.state == modes[m] && info.count == (size_t)(5 - id));
            CHECK(vireo_task_queue_close(queue, modes[m], &close_report) == VIREO_OK);
            CHECK(clean_close(close_report, false));
            if (modes[m] == VIREO_TASK_QUEUE_DRAIN) {
                CHECK(vireo_task_queue_try_take_cancelled(queue, &task, &report) == VIREO_RESULT_BUSY);
                CHECK(task == NULL && clean_transfer(report, false));
                CHECK(vireo_task_queue_try_pop(queue, &task, &report) == VIREO_OK);
            } else {
                CHECK(vireo_task_queue_try_pop(queue, &task, &report) == VIREO_RESULT_CANCELLED);
                CHECK(task == NULL && clean_transfer(report, false));
                CHECK(vireo_task_queue_try_take_cancelled(queue, &task, &report) == VIREO_OK);
            }
            CHECK(clean_transfer(report, true) && errno == EILSEQ);
            CHECK(verify_task(task, id) == 0 && vireo_task_destroy(&task) == VIREO_OK);
        }
        CHECK(vireo_task_queue_try_pop(queue, &task, &report) == VIREO_RESULT_CANCELLED);
        CHECK(make_task(6, &task) == VIREO_OK);
        CHECK(vireo_task_queue_try_push(queue, &task, &report) == VIREO_RESULT_CANCELLED);
        CHECK(verify_task(task, 6) == 0 && vireo_task_destroy(&task) == VIREO_OK);
        CHECK(vireo_task_queue_destroy(&queue) == VIREO_OK && errno == EILSEQ);
    }
    return 0;
}

static int cancellation_flag_is_explicit(void) {
    vireo_task_queue_options_t const options = {1, 4096};
    vireo_task_queue_t *queue = NULL;
    vireo_task_cancel_t *cancel = NULL;
    vireo_task_t *task = NULL;
    CHECK(vireo_task_queue_create(&options, &queue) == VIREO_OK);
    CHECK(vireo_task_cancel_create(1024, &cancel) == VIREO_OK);
    CHECK(vireo_task_create_copy_with_cancel(metadata(1), NULL, 0, 1024, cancel, &task) == VIREO_OK);
    vireo_task_queue_transfer_report_t report;
    vireo_task_queue_close_report_t close_report;
    CHECK(vireo_task_queue_try_push(queue, &task, &report) == VIREO_OK);
    CHECK(vireo_task_queue_close(queue, VIREO_TASK_QUEUE_CANCEL_PENDING, &close_report) == VIREO_OK);
    bool requested = true;
    CHECK(vireo_task_cancel_is_requested(cancel, &requested) == VIREO_OK && !requested);
    CHECK(vireo_task_queue_try_take_cancelled(queue, &task, &report) == VIREO_OK);
    CHECK(vireo_task_is_cancel_requested(task, &requested) == VIREO_OK && !requested);
    CHECK(vireo_task_cancel_destroy(&cancel) == VIREO_OK);
    /* task仍保自己的强引用；caller在取回以后才决定发出取消。 */
    CHECK(vireo_task_retain_cancel(task, &cancel) == VIREO_OK);
    CHECK(vireo_task_cancel_request(cancel) == VIREO_OK);
    CHECK(vireo_task_is_cancel_requested(task, &requested) == VIREO_OK && requested);
    CHECK(vireo_task_destroy(&task) == VIREO_OK);
    CHECK(vireo_task_cancel_is_requested(cancel, &requested) == VIREO_OK && requested);
    CHECK(vireo_task_cancel_destroy(&cancel) == VIREO_OK);
    CHECK(vireo_task_queue_destroy(&queue) == VIREO_OK);
    return 0;
}

static int taken_task_outlives_queue(void) {
    vireo_task_queue_state_t const modes[] = {
        VIREO_TASK_QUEUE_DRAIN, VIREO_TASK_QUEUE_CANCEL_PENDING
    };
    for (size_t i = 0; i < 2; ++i) {
        vireo_task_queue_options_t const options = {1, 4096};
        vireo_task_queue_t *queue = NULL;
        vireo_task_t *task = NULL;
        vireo_task_queue_transfer_report_t report;
        vireo_task_queue_close_report_t close_report;
        CHECK(vireo_task_queue_create(&options, &queue) == VIREO_OK);
        CHECK(make_task(19, &task) == VIREO_OK);
        CHECK(vireo_task_queue_try_push(queue, &task, &report) == VIREO_OK);
        CHECK(vireo_task_queue_try_pop(queue, &task, &report) == VIREO_OK);
        CHECK(vireo_task_queue_close(queue, modes[i], &close_report) == VIREO_OK);
        CHECK(vireo_task_queue_destroy(&queue) == VIREO_OK);
        CHECK(verify_task(task, 19) == 0 && vireo_task_destroy(&task) == VIREO_OK);
    }
    return 0;
}

/**
 * @brief
 *     主线程独占同步错误模型，真实unlock后可覆盖报告，不模拟未知锁状态恢复。
 */
typedef struct sync_fault {
    int lock_error; /**< 非0直接返回，不取得mutex。 */
    int unlock_error; /**< 真实unlock成功后覆盖报告。 */
    int destroy_error; /**< 非0直接失败，不销毁mutex。 */
    size_t lock_calls; /**< try_lock调用次数，核参数优先和一次尝试。 */
    size_t unlock_calls; /**< 获得锁后释放次数，核拒绝分支仍释放。 */
} sync_fault_t;

/**
 * @brief
 *     真实申请队列原块，故意扰动errno以核对外层保持。
 *
 * @param[in] context
 *     不用，允许NULL。
 * @param[in] bytes
 *     已受检正申请字节。
 *
 * @return
 *     正确对齐足量新块或NULL。
 */
static void *fault_allocate(void *context, size_t bytes) {
    (void)context;
    errno = EAGAIN;
    return malloc(bytes);
}

/**
 * @brief
 *     配对free原块，不释放借用上下文。
 *
 * @param[in] context
 *     不用，允许NULL。
 * @param[in] allocation
 *     队列原申请块，无在途访问。
 *
 * @note
 *     无失败返回，errno故意扰动，由外层恢复。
 */
static void fault_deallocate(void *context, void *allocation) {
    (void)context;
    free(allocation);
    errno = EAGAIN;
}

/**
 * @brief
 *     真实初始化默认非robust mutex，本项不注入初始化失败。
 *
 * @param[in] context
 *     不用，允许NULL。
 * @param[out] mutex
 *     尚未初始化的队列内存。
 *
 * @return
 *     pthread直接错误，成功后须配对destroy。
 */
static int fault_init(void *context, pthread_mutex_t *mutex) {
    (void)context;
    return pthread_mutex_init(mutex, NULL);
}

/**
 * @brief
 *     记录一次try操作，注入失败时不获得mutex。
 *
 * @param[in,out] context
 *     主线程独占且存活的sync_fault。
 * @param[in,out] mutex
 *     已初始化的存活mutex。
 *
 * @return
 *     注入直接错误或一次真实pthread trylock结果。
 */
static int fault_try_lock(void *context, pthread_mutex_t *mutex) {
    sync_fault_t *fault = context;
    ++fault->lock_calls;
    errno = EAGAIN;
    return fault->lock_error != 0 ? fault->lock_error : pthread_mutex_trylock(mutex);
}

/**
 * @brief
 *     先真实释放锁，再可覆盖返回错误以核对已提交进度。
 *
 * @param[in,out] context
 *     主线程独占sync_fault。
 * @param[in,out] mutex
 *     本线程已获取的存活mutex。
 *
 * @return
 *     真实释放错误优先，否则注入报告错误。
 *
 * @note
 *     不是未知同步损坏的实际恢复证明。
 */
static int fault_unlock(void *context, pthread_mutex_t *mutex) {
    sync_fault_t *fault = context;
    ++fault->unlock_calls;
    int const code = pthread_mutex_unlock(mutex);
    errno = EAGAIN;
    return code != 0 ? code : fault->unlock_error;
}

/**
 * @brief
 *     注入失败不销毁mutex，正常执行真实配对销毁。
 *
 * @param[in] context
 *     独占sync_fault，借至返回。
 * @param[in,out] mutex
 *     无访问或持有者的已初始化mutex。
 *
 * @return
 *     直接错误，失败保原资源。
 */
static int fault_destroy(void *context, pthread_mutex_t *mutex) {
    sync_fault_t *fault = context;
    return fault->destroy_error != 0 ? fault->destroy_error : pthread_mutex_destroy(mutex);
}

/**
 * @brief
 *     仅本核心创建固定单槽同步错误模型，无全局fault。
 *
 * @param[in,out] fault
 *     主线程独占存活上下文，借至队列销毁。
 * @param[out] out
 *     独占空队列owner。
 *
 * @return
 *     本核心private create结果，表按值复制。
 */
static vireo_result_t make_fault_queue(sync_fault_t *fault, vireo_task_queue_t **out) {
    vireo_task_queue_options_t const options = {1, 4096};
    vireo_task_queue_allocator_t const allocator = {NULL, fault_allocate, fault_deallocate};
    vireo_task_queue_sync_ops_t const sync = {
        fault, fault_init, fault_try_lock, fault_unlock, fault_destroy
    };
    return vireo_task_queue_create_with_ops(&options, &allocator, &sync, out);
}

static int basic_priority_and_reports(void) {
    sync_fault_t fault = {EBUSY, 0, 0, 0, 0};
    vireo_task_queue_t *queue = NULL;
    vireo_task_t *task = NULL;
    vireo_task_t *empty = NULL;
    vireo_task_queue_close_report_t close_report;
    vireo_task_queue_transfer_report_t report;
    CHECK(make_fault_queue(&fault, &queue) == VIREO_OK);
    CHECK(make_task(1, &task) == VIREO_OK);
    vireo_task_t *const original = task;
    errno = ERANGE;
    CHECK(vireo_task_queue_close(NULL, VIREO_TASK_QUEUE_DRAIN, &close_report) ==
        VIREO_RESULT_INVALID_ARGUMENT && clean_close(close_report, false));
    CHECK(vireo_task_queue_close(queue, VIREO_TASK_QUEUE_DRAIN, NULL) ==
        VIREO_RESULT_INVALID_ARGUMENT);
    int const bad_modes[] = {-1, 0, 3, INT_MAX};
    for (size_t i = 0; i < sizeof(bad_modes) / sizeof(bad_modes[0]); ++i) {
        close_report.changed = true;
        CHECK(vireo_task_queue_close(queue, (vireo_task_queue_state_t)bad_modes[i], &close_report) ==
            VIREO_RESULT_INVALID_ARGUMENT && clean_close(close_report, false));
    }
    CHECK(vireo_task_queue_try_take_cancelled(NULL, &empty, &report) ==
        VIREO_RESULT_INVALID_ARGUMENT && clean_transfer(report, false));
    CHECK(vireo_task_queue_try_take_cancelled(queue, NULL, &report) ==
        VIREO_RESULT_INVALID_ARGUMENT && clean_transfer(report, false));
    CHECK(vireo_task_queue_try_take_cancelled(queue, &task, &report) ==
        VIREO_RESULT_INVALID_ARGUMENT && clean_transfer(report, false) && task == original);
    CHECK(vireo_task_queue_try_take_cancelled(queue, &empty, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_task_queue_try_push(queue, &empty, &report) == VIREO_RESULT_NOT_FOUND);
    CHECK(fault.lock_calls == 0 && fault.unlock_calls == 0 && errno == ERANGE);
    fault.lock_error = 0;
    CHECK(vireo_task_queue_close(queue, VIREO_TASK_QUEUE_CANCEL_PENDING, &close_report) == VIREO_OK);
    size_t const calls = fault.lock_calls;
    CHECK(vireo_task_queue_try_push(queue, &empty, &report) == VIREO_RESULT_NOT_FOUND);
    CHECK(vireo_task_queue_try_pop(queue, &task, &report) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_task_queue_try_take_cancelled(queue, &task, &report) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(fault.lock_calls == calls && task == original && errno == ERANGE);
    CHECK(vireo_task_destroy(&task) == VIREO_OK && vireo_task_queue_destroy(&queue) == VIREO_OK);
    return 0;
}

static int lock_errors_hold_state_and_owners(void) {
    sync_fault_t fault = {0, 0, 0, 0, 0};
    vireo_task_queue_t *queue = NULL;
    vireo_task_queue_close_report_t close_report;
    vireo_task_queue_transfer_report_t report;
    CHECK(make_fault_queue(&fault, &queue) == VIREO_OK);
    int const errors[] = {EBUSY, EINVAL};
    for (size_t i = 0; i < 2; ++i) {
        fault.lock_error = errors[i];
        vireo_result_t const expected = i == 0 ? VIREO_RESULT_BUSY : VIREO_RESULT_INTERNAL;
        size_t const calls = fault.lock_calls;
        errno = EDOM;
        CHECK(vireo_task_queue_close(queue, VIREO_TASK_QUEUE_DRAIN, &close_report) == expected);
        CHECK(close_report.stage == VIREO_TASK_QUEUE_STAGE_LOCK && !close_report.changed &&
            close_report.pthread_error == errors[i]);
        vireo_task_t *task = NULL;
        CHECK(vireo_task_queue_try_take_cancelled(queue, &task, &report) == expected);
        CHECK(task == NULL && report.stage == VIREO_TASK_QUEUE_STAGE_LOCK &&
            !report.transferred && report.pthread_error == errors[i]);
        CHECK(fault.lock_calls == calls + 2 && fault.unlock_calls == 0 && errno == EDOM);
    }
    fault.lock_error = 0;
    vireo_task_queue_info_t info;
    CHECK(vireo_task_queue_inspect(queue, &info) == VIREO_OK);
    CHECK(info.state == VIREO_TASK_QUEUE_OPEN && info.count == 0);
    CHECK(vireo_task_queue_close(queue, VIREO_TASK_QUEUE_CANCEL_PENDING, &close_report) == VIREO_OK);
    fault.lock_error = EBUSY;
    CHECK(vireo_task_queue_close(queue, VIREO_TASK_QUEUE_DRAIN, &close_report) == VIREO_RESULT_BUSY);
    CHECK(close_report.stage == VIREO_TASK_QUEUE_STAGE_LOCK);
    fault.lock_error = 0;
    CHECK(vireo_task_queue_close(queue, VIREO_TASK_QUEUE_DRAIN, &close_report) == VIREO_RESULT_BUSY);
    CHECK(clean_close(close_report, false));
    CHECK(vireo_task_queue_destroy(&queue) == VIREO_OK);
    return 0;
}

static int unlock_progress_and_snapshot(void) {
    sync_fault_t fault = {0, 0, 0, 0, 0};
    vireo_task_queue_t *queue = NULL;
    vireo_task_t *task = NULL;
    vireo_task_queue_close_report_t close_report;
    vireo_task_queue_transfer_report_t report;
    CHECK(make_fault_queue(&fault, &queue) == VIREO_OK);
    CHECK(make_task(1, &task) == VIREO_OK);
    CHECK(vireo_task_queue_try_push(queue, &task, &report) == VIREO_OK);
    fault.unlock_error = EIO;
    errno = EILSEQ;
    CHECK(vireo_task_queue_close(queue, VIREO_TASK_QUEUE_CANCEL_PENDING, &close_report) ==
        VIREO_RESULT_INTERNAL);
    CHECK(close_report.stage == VIREO_TASK_QUEUE_STAGE_UNLOCK && close_report.changed &&
        close_report.pthread_error == EIO && errno == EILSEQ);
    CHECK(vireo_task_queue_close(queue, VIREO_TASK_QUEUE_CANCEL_PENDING, &close_report) ==
        VIREO_RESULT_INTERNAL && !close_report.changed);
    CHECK(vireo_task_queue_close(queue, VIREO_TASK_QUEUE_DRAIN, &close_report) ==
        VIREO_RESULT_INTERNAL && !close_report.changed);
    CHECK(close_report.stage == VIREO_TASK_QUEUE_STAGE_UNLOCK && close_report.pthread_error == EIO);
    vireo_task_queue_info_t info;
    memset(&info, 0x5b, sizeof(info));
    unsigned char saved[sizeof(info)];
    memcpy(saved, &info, sizeof(info));
    CHECK(vireo_task_queue_inspect(queue, &info) == VIREO_RESULT_INTERNAL);
    CHECK(memcmp(saved, &info, sizeof(info)) == 0);
    CHECK(vireo_task_queue_try_pop(queue, &task, &report) == VIREO_RESULT_INTERNAL);
    CHECK(task == NULL && !report.transferred && report.stage == VIREO_TASK_QUEUE_STAGE_UNLOCK);
    CHECK(vireo_task_queue_try_take_cancelled(queue, &task, &report) == VIREO_RESULT_INTERNAL);
    CHECK(task != NULL && report.transferred && report.stage == VIREO_TASK_QUEUE_STAGE_UNLOCK &&
        report.pthread_error == EIO && errno == EILSEQ);
    CHECK(verify_task(task, 1) == 0 && vireo_task_destroy(&task) == VIREO_OK);
    CHECK(vireo_task_queue_try_take_cancelled(queue, &task, &report) == VIREO_RESULT_INTERNAL);
    CHECK(task == NULL && !report.transferred);
    CHECK(make_task(2, &task) == VIREO_OK);
    vireo_task_t *const original = task;
    CHECK(vireo_task_queue_try_push(queue, &task, &report) == VIREO_RESULT_INTERNAL);
    CHECK(task == original && !report.transferred && report.pthread_error == EIO);
    CHECK(vireo_task_destroy(&task) == VIREO_OK);
    fault.unlock_error = 0;
    CHECK(vireo_task_queue_inspect(queue, &info) == VIREO_OK);
    CHECK(info.state == VIREO_TASK_QUEUE_CANCEL_PENDING && info.count == 0);
    fault.destroy_error = EBUSY;
    vireo_task_queue_t *const owner = queue;
    CHECK(vireo_task_queue_destroy(&queue) == VIREO_RESULT_BUSY && queue == owner);
    fault.destroy_error = 0;
    CHECK(vireo_task_queue_destroy(&queue) == VIREO_OK && errno == EILSEQ);
    /* DRAIN空与专用入口拒绝也必须检查unlock，并保留未转移事实。 */
    CHECK(make_fault_queue(&fault, &queue) == VIREO_OK);
    CHECK(vireo_task_queue_close(queue, VIREO_TASK_QUEUE_DRAIN, &close_report) == VIREO_OK);
    fault.unlock_error = EPERM;
    CHECK(vireo_task_queue_try_pop(queue, &task, &report) == VIREO_RESULT_INTERNAL);
    CHECK(task == NULL && !report.transferred && report.pthread_error == EPERM);
    CHECK(vireo_task_queue_try_take_cancelled(queue, &task, &report) == VIREO_RESULT_INTERNAL);
    CHECK(task == NULL && !report.transferred && report.stage == VIREO_TASK_QUEUE_STAGE_UNLOCK);
    fault.unlock_error = 0;
    CHECK(vireo_task_queue_destroy(&queue) == VIREO_OK);
    return 0;
}

/**
 * @brief
 *     真实锁竞争线程的独立结果存储，main join后才读取。
 */
typedef struct contender {
    vireo_task_queue_t *queue; /**< 短借到线程结束，main持锁时对象存活。 */
    bool ok; /**< 本线程写、main join后读，不用原子替队列同步。 */
} contender_t;

/**
 * @brief
 *     在main真实持锁期间尝试关闭和取回，必须立即返回竞争。
 *
 * @param[in,out] context
 *     存活contender，输入create发布，结果main join后读。
 *
 * @return
 *     NULL，诊断写独立ok，不自动释放queue。
 */
static void *contend(void *context) {
    contender_t *args = context;
    vireo_task_queue_close_report_t close_report;
    vireo_task_queue_transfer_report_t report;
    vireo_task_t *task = NULL;
    errno = EDOM;
    bool ok = vireo_task_queue_close(args->queue, VIREO_TASK_QUEUE_CANCEL_PENDING,
        &close_report) == VIREO_RESULT_BUSY;
    ok = ok && close_report.stage == VIREO_TASK_QUEUE_STAGE_LOCK && !close_report.changed &&
        close_report.pthread_error == EBUSY;
    ok = ok && vireo_task_queue_try_take_cancelled(args->queue, &task, &report) == VIREO_RESULT_BUSY;
    args->ok = ok && task == NULL && !report.transferred &&
        report.stage == VIREO_TASK_QUEUE_STAGE_LOCK && report.pthread_error == EBUSY && errno == EDOM;
    return NULL;
}

static int real_lock_contention(void) {
    vireo_task_queue_options_t const options = {1, 4096};
    vireo_task_queue_t *queue = NULL;
    CHECK(vireo_task_queue_create(&options, &queue) == VIREO_OK);
    CHECK(pthread_mutex_lock(&queue->mutex) == 0);
    contender_t args = {queue, false};
    pthread_t thread;
    int const code = pthread_create(&thread, NULL, contend, &args);
    if (code != 0) {
        if (pthread_mutex_unlock(&queue->mutex) != 0) { abort(); }
        if (vireo_task_queue_destroy(&queue) != VIREO_OK) { abort(); }
        CHECK(code == 0);
    }
    /* 在main解锁前join：误用等待锁由CTest timeout失败，不依赖sleep。 */
    if (pthread_join(thread, NULL) != 0) { abort(); }
    CHECK(pthread_mutex_unlock(&queue->mutex) == 0);
    CHECK(args.ok && vireo_task_queue_destroy(&queue) == VIREO_OK);
    return 0;
}

enum { ATTEMPT_LIMIT = 2000000, PRODUCERS = 3, PER_PRODUCER = 32,
       TOTAL = PRODUCERS * PER_PRODUCER, CONSUMERS = 3 };

/**
 * @brief
 *     线程启动与失败控制，queue对象由main保活到所有join。
 */
typedef struct race_control {
    vireo_task_queue_t *queue; /**< 借用队列，不由线程销毁。 */
    atomic_bool start; /**< main release、线程acquire的启动门，不控制产品提交先后。 */
    atomic_bool failed; /**< relaxed失败标志，只控制测试停止。 */
} race_control_t;

/**
 * @brief
 *     单次关闭线程独立输入/输出，main join以后消费结果。
 */
typedef struct close_args {
    race_control_t *control; /**< 借用存活启动控制。 */
    vireo_task_queue_state_t mode; /**< DRAIN或CANCEL_PENDING，创建前设置。 */
    vireo_result_t result; /**< 终次close返回，初始INTERNAL。 */
    vireo_task_queue_close_report_t report; /**< 真实最后报告；非原子，由本线程独写。 */
} close_args_t;

/**
 * @brief
 *     等测试启动门或失败，产品入口本身不等待。
 *
 * @param[in,out] control
 *     存活共享原子启动/失败控制。
 *
 * @return
 *     true已启动且无失败，false停止。
 *
 * @note
 *     CTest限制整体时长，yield失败也记录真实失败。
 */
static bool await_start(race_control_t *control) {
    while (!atomic_load_explicit(&control->start, memory_order_acquire)) {
        if (atomic_load_explicit(&control->failed, memory_order_relaxed)) { return false; }
        if (sched_yield() != 0) {
            atomic_store_explicit(&control->failed, true, memory_order_relaxed);
            return false;
        }
    }
    return !atomic_load_explicit(&control->failed, memory_order_relaxed);
}

/**
 * @brief
 *     竞争首次关闭；caller仅对锁竞争有界重试，模式冲突直接结束。
 *
 * @param[in,out] context
 *     独立close_args与存活借用control，main join后读取。
 *
 * @return
 *     NULL，保存最后result/report；失败置原子标志。
 */
static void *close_racer(void *context) {
    close_args_t *args = context;
    if (!await_start(args->control)) { return NULL; }
    for (size_t i = 0; i < ATTEMPT_LIMIT; ++i) {
        errno = EDOM;
        args->result = vireo_task_queue_close(args->control->queue, args->mode, &args->report);
        if (errno != EDOM) { break; }
        if (args->result == VIREO_OK || (args->result == VIREO_RESULT_BUSY &&
            args->report.stage == VIREO_TASK_QUEUE_STAGE_NONE)) { return NULL; }
        if (args->result != VIREO_RESULT_BUSY || args->report.changed ||
            args->report.pthread_error != EBUSY || sched_yield() != 0) { break; }
    }
    atomic_store_explicit(&args->control->failed, true, memory_order_relaxed);
    return NULL;
}

static int concurrent_first_mode_wins(void) {
    for (size_t round = 0; round < 32; ++round) {
        vireo_task_queue_options_t const options = {1, 4096};
        vireo_task_queue_t *queue = NULL;
        CHECK(vireo_task_queue_create(&options, &queue) == VIREO_OK);
        race_control_t control;
        control.queue = queue;
        atomic_init(&control.start, false); atomic_init(&control.failed, false);
        close_args_t args[2] = {
            {&control, VIREO_TASK_QUEUE_DRAIN, VIREO_RESULT_INTERNAL, {0, false, 0}},
            {&control, VIREO_TASK_QUEUE_CANCEL_PENDING, VIREO_RESULT_INTERNAL, {0, false, 0}}
        };
        pthread_t threads[2];
        size_t created = 0;
        for (; created < 2; ++created) {
            if (pthread_create(&threads[created], NULL, close_racer, &args[created]) != 0) {
                atomic_store_explicit(&control.failed, true, memory_order_relaxed); break;
            }
        }
        atomic_store_explicit(&control.start, true, memory_order_release);
        for (size_t i = 0; i < created; ++i) {
            if (pthread_join(threads[i], NULL) != 0) { abort(); }
        }
        bool ok = created == 2 && !atomic_load(&control.failed);
        size_t const winner = args[0].result == VIREO_OK ? 0 : 1;
        ok = ok && args[winner].result == VIREO_OK && clean_close(args[winner].report, true);
        ok = ok && args[1 - winner].result == VIREO_RESULT_BUSY &&
            clean_close(args[1 - winner].report, false);
        vireo_task_queue_info_t info;
        ok = ok && vireo_task_queue_inspect(queue, &info) == VIREO_OK &&
            info.state == args[winner].mode && info.count == 0;
        CHECK(vireo_task_queue_destroy(&queue) == VIREO_OK);
        CHECK(ok);
    }
    return 0;
}

/**
 * @brief
 *     提交与关闭竞争的独立oracle，main先join producer再启动收尾消费者。
 */
typedef struct submit_race {
    race_control_t control; /**< 产品队列借用及线程启动/失败控制。 */
    bool accepted[TOTAL]; /**< 每producer写各自不重叠范围，main join后读。 */
    atomic_uint seen[TOTAL + 1]; /**< 收尾消费者领取次数，relaxed，main join后核对。 */
    vireo_task_queue_state_t mode; /**< 选定关闭模式，consumer创建之前稳定。 */
} submit_race_t;

/**
 * @brief
 *     producer独立角色，范围不重叠且本地owner不被其他线程访问。
 */
typedef struct producer_args {
    submit_race_t *race; /**< 借用存活oracle到join。 */
    size_t index; /**< 0..PRODUCERS-1，决定32项独立标签。 */
} producer_args_t;

/**
 * @brief
 *     逐项竞争提交或关闭拒绝，每个本地owner仅有一个责任方。
 *
 * @param[in,out] context
 *     producer独立标签范围，借用race到join。
 *
 * @return
 *     NULL；未提交owner由本线程释放，提交项由queue拥有。
 *
 * @note
 *     caller有界重试BUSY，所有异常根据实际owner清理，不在产品内部重试。
 */
static void *submit_racer(void *context) {
    producer_args_t *args = context;
    submit_race_t *race = args->race;
    if (!await_start(&race->control)) { return NULL; }
    for (size_t j = 0; j < PER_PRODUCER; ++j) {
        size_t const index = args->index * PER_PRODUCER + j;
        vireo_task_t *task = NULL;
        if (make_task((uint64_t)(index + 1), &task) != VIREO_OK) {
            atomic_store_explicit(&race->control.failed, true, memory_order_relaxed); break;
        }
        bool decided = false;
        for (size_t attempt = 0; attempt < ATTEMPT_LIMIT; ++attempt) {
            if (atomic_load_explicit(&race->control.failed, memory_order_relaxed)) { break; }
            vireo_task_queue_transfer_report_t report;
            errno = EILSEQ;
            vireo_result_t const result = vireo_task_queue_try_push(race->control.queue, &task, &report);
            if (result == VIREO_OK && task == NULL && clean_transfer(report, true) && errno == EILSEQ) {
                race->accepted[index] = true; decided = true; break;
            }
            if (result == VIREO_RESULT_CANCELLED && task != NULL && clean_transfer(report, false) &&
                errno == EILSEQ && verify_task(task, (uint64_t)(index + 1)) == 0) {
                decided = true; break;
            }
            if (result != VIREO_RESULT_BUSY || task == NULL || report.transferred ||
                errno != EILSEQ || sched_yield() != 0) { break; }
        }
        if (task != NULL && vireo_task_destroy(&task) != VIREO_OK) { abort(); }
        if (!decided) {
            atomic_store_explicit(&race->control.failed, true, memory_order_relaxed); break;
        }
    }
    return NULL;
}

/**
 * @brief
 *     按已关闭模式竞争单项领取，独立oracle检查每个接受项恰一次。
 *
 * @param[in,out] context
 *     存活submit_race，seen原子、mode稳定。
 *
 * @return
 *     NULL，完成释放本线程owner，错误置failed。
 *
 * @note
 *     producer先join后创建consumer，此组证明关闭拥有权，旧transfer组独立证明发布。
 */
static void *finish_racer(void *context) {
    submit_race_t *race = context;
    for (size_t attempt = 0; attempt < ATTEMPT_LIMIT; ++attempt) {
        vireo_task_t *task = NULL;
        vireo_task_queue_transfer_report_t report;
        errno = EDOM;
        vireo_result_t const result = race->mode == VIREO_TASK_QUEUE_DRAIN ?
            vireo_task_queue_try_pop(race->control.queue, &task, &report) :
            vireo_task_queue_try_take_cancelled(race->control.queue, &task, &report);
        if (result == VIREO_OK && task != NULL && clean_transfer(report, true) && errno == EDOM) {
            vireo_task_info_t info;
            bool ok = vireo_task_inspect(task, &info) == VIREO_OK;
            uint64_t const id = ok ? info.metadata.request_instance_id : 0;
            ok = ok && id > 0 && id <= TOTAL + 1 && verify_task(task, id) == 0;
            if (ok) {
                ok = atomic_fetch_add_explicit(&race->seen[id - 1], 1, memory_order_relaxed) == 0;
            }
            if (vireo_task_destroy(&task) != VIREO_OK) { abort(); }
            if (ok) { continue; }
        } else if (task == NULL && !report.transferred && errno == EDOM) {
            vireo_result_t const end = race->mode == VIREO_TASK_QUEUE_DRAIN ?
                VIREO_RESULT_CANCELLED : VIREO_RESULT_NOT_FOUND;
            if (result == end && clean_transfer(report, false)) { return NULL; }
            if (result == VIREO_RESULT_BUSY && sched_yield() == 0) { continue; }
        }
        if (task != NULL && vireo_task_destroy(&task) != VIREO_OK) { abort(); }
        atomic_store_explicit(&race->control.failed, true, memory_order_relaxed);
        return NULL;
    }
    atomic_store_explicit(&race->control.failed, true, memory_order_relaxed);
    return NULL;
}

/**
 * @brief
 *     所有线程join后收回仍在队列的owner，失败也不留下后台访问。
 *
 * @param[in,out] queue
 *     测试独占、无在途访问的存活队列。
 *
 * @note
 *     仅测试善后可逐项循环；意外同步异常非零终止，不假装已清理成功。
 */
static void cleanup_queue(vireo_task_queue_t **queue) {
    vireo_task_queue_info_t info;
    if (vireo_task_queue_inspect(*queue, &info) != VIREO_OK) { abort(); }
    if (info.state == VIREO_TASK_QUEUE_OPEN) {
        vireo_task_queue_close_report_t close_report;
        if (vireo_task_queue_close(*queue, VIREO_TASK_QUEUE_CANCEL_PENDING, &close_report) != VIREO_OK) {
            abort();
        }
        info.state = VIREO_TASK_QUEUE_CANCEL_PENDING;
    }
    for (;;) {
        vireo_task_t *task = NULL;
        vireo_task_queue_transfer_report_t report;
        vireo_result_t const result = info.state == VIREO_TASK_QUEUE_DRAIN ?
            vireo_task_queue_try_pop(*queue, &task, &report) :
            vireo_task_queue_try_take_cancelled(*queue, &task, &report);
        if (result == VIREO_OK && task != NULL) {
            if (vireo_task_destroy(&task) != VIREO_OK) { abort(); }
            continue;
        }
        vireo_result_t const end = info.state == VIREO_TASK_QUEUE_DRAIN ?
            VIREO_RESULT_CANCELLED : VIREO_RESULT_NOT_FOUND;
        if (result != end || task != NULL) { abort(); }
        break;
    }
    if (vireo_task_queue_destroy(queue) != VIREO_OK) { abort(); }
}

static int submit_close_and_concurrent_finish(void) {
    vireo_task_queue_state_t const modes[] = {
        VIREO_TASK_QUEUE_DRAIN, VIREO_TASK_QUEUE_CANCEL_PENDING
    };
    for (size_t m = 0; m < 2; ++m) {
        vireo_task_queue_t *queue = NULL;
        vireo_task_queue_options_t const options = {TOTAL + 1, 4096};
        CHECK(vireo_task_queue_create(&options, &queue) == VIREO_OK);
        /* 保证一个close前接受项；竞争项可合法全被拒绝，不依赖调度偏向。 */
        vireo_task_t *task = NULL;
        vireo_task_queue_transfer_report_t report;
        CHECK(make_task(TOTAL + 1, &task) == VIREO_OK);
        CHECK(vireo_task_queue_try_push(queue, &task, &report) == VIREO_OK);
        submit_race_t race;
        race.control.queue = queue;
        atomic_init(&race.control.start, false); atomic_init(&race.control.failed, false);
        race.mode = modes[m];
        for (size_t i = 0; i < TOTAL; ++i) { race.accepted[i] = false; }
        for (size_t i = 0; i <= TOTAL; ++i) { atomic_init(&race.seen[i], 0); }
        producer_args_t args[PRODUCERS];
        pthread_t producers[PRODUCERS];
        pthread_t closer;
        size_t created = 0;
        for (; created < PRODUCERS; ++created) {
            args[created].race = &race; args[created].index = created;
            if (pthread_create(&producers[created], NULL, submit_racer, &args[created]) != 0) {
                atomic_store_explicit(&race.control.failed, true, memory_order_relaxed); break;
            }
        }
        close_args_t close_args = {&race.control, modes[m], VIREO_RESULT_INTERNAL, {0, false, 0}};
        bool const closer_created = created == PRODUCERS &&
            pthread_create(&closer, NULL, close_racer, &close_args) == 0;
        if (!closer_created) { atomic_store_explicit(&race.control.failed, true, memory_order_relaxed); }
        atomic_store_explicit(&race.control.start, true, memory_order_release);
        for (size_t i = 0; i < created; ++i) {
            if (pthread_join(producers[i], NULL) != 0) { abort(); }
        }
        if (closer_created && pthread_join(closer, NULL) != 0) { abort(); }
        bool ok = created == PRODUCERS && closer_created && !atomic_load(&race.control.failed) &&
            close_args.result == VIREO_OK && clean_close(close_args.report, true);
        size_t accepted = 1;
        for (size_t i = 0; i < TOTAL; ++i) { if (race.accepted[i]) { ++accepted; } }
        vireo_task_queue_info_t info;
        ok = ok && vireo_task_queue_inspect(queue, &info) == VIREO_OK &&
            info.state == modes[m] && info.count == accepted;
        if (ok) {
            /* 保证一个close后拒绝项，owner仍归main，不拿旧裸别名。 */
            CHECK(make_task(TOTAL + 2, &task) == VIREO_OK);
            ok = vireo_task_queue_try_push(queue, &task, &report) == VIREO_RESULT_CANCELLED &&
                task != NULL && clean_transfer(report, false);
            if (task != NULL && vireo_task_destroy(&task) != VIREO_OK) { abort(); }
            pthread_t consumers[CONSUMERS];
            size_t consumers_created = 0;
            if (ok) {
                for (; consumers_created < CONSUMERS; ++consumers_created) {
                    if (pthread_create(&consumers[consumers_created], NULL, finish_racer, &race) != 0) {
                        atomic_store_explicit(&race.control.failed, true, memory_order_relaxed); break;
                    }
                }
            }
            for (size_t i = 0; i < consumers_created; ++i) {
                if (pthread_join(consumers[i], NULL) != 0) { abort(); }
            }
            ok = ok && consumers_created == CONSUMERS && !atomic_load(&race.control.failed);
            for (size_t i = 0; i < TOTAL; ++i) {
                ok = ok && atomic_load(&race.seen[i]) == (race.accepted[i] ? 1U : 0U);
            }
            ok = ok && atomic_load(&race.seen[TOTAL]) == 1;
            ok = ok && vireo_task_queue_inspect(queue, &info) == VIREO_OK && info.count == 0;
        }
        cleanup_queue(&queue);
        CHECK(ok);
    }
    return 0;
}

int main(void) {
    int (*const cases[])(void) = {
        empty_modes_and_repetition, fifo_wrap_and_closed_push, cancellation_flag_is_explicit,
        taken_task_outlives_queue, basic_priority_and_reports, lock_errors_hold_state_and_owners,
        unlock_progress_and_snapshot, real_lock_contention, concurrent_first_mode_wins,
        submit_close_and_concurrent_finish
    };
    char const *const names[] = {
        "empty_modes_and_repetition", "fifo_wrap_and_closed_push", "cancellation_flag_is_explicit",
        "taken_task_outlives_queue", "basic_priority_and_reports", "lock_errors_hold_state_and_owners",
        "unlock_progress_and_snapshot", "real_lock_contention", "concurrent_first_mode_wins",
        "submit_close_and_concurrent_finish"
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        if (cases[i]() != 0) { return EXIT_FAILURE; }
        printf("PASS %s\n", names[i]);
    }
    puts("task queue close: 10 groups passed");
    return EXIT_SUCCESS;
}
