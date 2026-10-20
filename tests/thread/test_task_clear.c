/*
 * PROJECT : VIREO
 * FILE    : test_task_clear.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-19
 * BRIEF   : task配对释放前全块观察及公开队列/真实worker生命周期
 */
#define _POSIX_C_SOURCE 200809L
#include "task_internal.h"

#include <vireo/thread/thread_pool.h>

#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(c) do { if (!(c)) { fprintf(stderr, "line %d: %s\n", __LINE__, #c); exit(1); } } while (0)
#define EXPECT(call, value) do { errno = EDOM; CHECK((call) == (value)); CHECK(errno == EDOM); } while (0)

/** 单块测试账本；交给worker后main只在join后读取，context始终在被清块之外。 */
typedef struct probe {
    void *live; /**< 当前块，只在其存活期内观测，非额外owner。 */
    size_t bytes; /**< allocate收到的精确申请量，供free前观察。 */
    size_t attempts; /**< 包含失败的申请次数。 */
    size_t releases; /**< 已观察全零且执行free的次数。 */
    size_t calls; /**< 单worker callback次数，join后读。 */
    bool fail; /**< 仅本上下文的分配失败注入。 */
} probe_t;

/** @brief 分配真实独占块并预填非零，保证连padding漏清也会被观察。 */
static void *allocate(void *context, size_t bytes) {
    probe_t *p = context;
    CHECK(p->live == NULL);
    ++p->attempts;
    p->bytes = bytes;
    if (p->fail) { return NULL; }
    p->live = malloc(bytes);
    CHECK(p->live != NULL);
    memset(p->live, 0xa5, bytes);
    errno = EILSEQ;
    return p->live;
}

/** @brief 在真实free之前检查仍存活块；不读取已擦除的结构字段或释放后地址。 */
static void deallocate(void *context, void *allocation) {
    probe_t *p = context;
    CHECK(allocation == p->live && allocation != NULL);
    unsigned char const *bytes = allocation;
    for (size_t i = 0; i < p->bytes; ++i) { CHECK(bytes[i] == 0); }
    free(allocation);
    p->live = NULL;
    ++p->releases;
    errno = EILSEQ;
}

static vireo_task_metadata_t metadata(void) {
    vireo_task_metadata_t const value = {{7, 0, 3, 11}, 42, 1, UINT64_MAX};
    return value;
}

/** @brief 仅在合法借用期检查正文，返回后不保存view。 */
static void check_payload(vireo_task_t const *task, size_t length) {
    vireo_task_payload_view_t view = {0};
    EXPECT(vireo_task_borrow_payload(task, &view), VIREO_OK);
    CHECK(view.size == length);
    CHECK(length != 0 || view.data == NULL);
    for (size_t i = 0; i < length; ++i) { CHECK(view.data[i] == (unsigned char)(i % 256)); }
}

static void direct_lifetimes(void) {
    size_t const lengths[] = {0, 1, 64, 4097, 1048576};
    for (size_t j = 0; j < sizeof(lengths) / sizeof(lengths[0]); ++j) {
        size_t const length = lengths[j];
        unsigned char *input = malloc(length + 1);
        CHECK(input != NULL);
        for (size_t i = 0; i < length + 1; ++i) { input[i] = (unsigned char)(i % 256); }
        probe_t p = {0};
        vireo_task_allocator_t a = {&p, allocate, deallocate};
        vireo_task_cancel_t *cancel = NULL;
        EXPECT(vireo_task_cancel_create(4096, &cancel), VIREO_OK);
        vireo_task_t *task = NULL, *moved = NULL;
        EXPECT(vireo_task_create_copy_with_cancel_and_allocator(metadata(), input, length,
            VIREO_TASK_MAX_ALLOCATION_BYTES, cancel, &a, &task), VIREO_OK);
        check_payload(task, length);
        EXPECT(vireo_task_cancel_request(cancel), VIREO_OK);
        EXPECT(vireo_task_move(&task, &moved), VIREO_OK);
        CHECK(task == NULL && p.releases == 0);
        check_payload(moved, length);
        a = (vireo_task_allocator_t){0}; /* 对象须已保存配对表。 */
        EXPECT(vireo_task_destroy(&moved), VIREO_OK);
        CHECK(moved == NULL && p.releases == 1 && p.live == NULL);
        bool requested = false;
        EXPECT(vireo_task_cancel_is_requested(cancel, &requested), VIREO_OK);
        CHECK(requested); /* task清块不影响另一个取消引用。 */
        EXPECT(vireo_task_cancel_destroy(&cancel), VIREO_OK);
        EXPECT(vireo_task_destroy(&moved), VIREO_OK);
        CHECK(p.releases == 1);
        for (size_t i = 0; i < length + 1; ++i) { CHECK(input[i] == (unsigned char)(i % 256)); }
        free(input);
    }
}

static void failures_preserve_owner(void) {
    probe_t p = {0};
    vireo_task_allocator_t const a = {&p, allocate, deallocate};
    unsigned char input[] = {0, 1, 2};
    vireo_task_t *task = NULL;
    p.fail = true;
    EXPECT(vireo_task_create_copy_with_allocator(metadata(), input, sizeof(input), 4096,
        &a, &task), VIREO_RESULT_NO_MEMORY);
    CHECK(task == NULL && p.attempts == 1 && p.releases == 0 && input[2] == 2);
    p.fail = false;
    EXPECT(vireo_task_create_copy_with_allocator(metadata(), input, sizeof(input), 4096,
        &a, &task), VIREO_OK);
    EXPECT(vireo_task_create_copy(metadata(), input, sizeof(input), 4096, &task), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_task_move(&task, &task), VIREO_RESULT_INVALID_ARGUMENT);
    check_payload(task, sizeof(input));
    CHECK(p.releases == 0);
    EXPECT(vireo_task_destroy(NULL), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_task_destroy(&task), VIREO_OK);
    CHECK(p.releases == 1);
}

static void cancelled_queue(void) {
    probe_t p = {0};
    vireo_task_allocator_t const a = {&p, allocate, deallocate};
    unsigned char input[] = {0, 1, 2};
    vireo_task_t *task = NULL;
    EXPECT(vireo_task_create_copy_with_allocator(metadata(), input, sizeof(input), 4096, &a, &task), VIREO_OK);
    vireo_task_queue_t *queue = NULL;
    vireo_task_queue_options_t const options = {1, 65536};
    EXPECT(vireo_task_queue_create(&options, &queue), VIREO_OK);
    vireo_task_queue_transfer_report_t transfer = {0};
    EXPECT(vireo_task_queue_try_push(queue, &task, &transfer), VIREO_OK);
    CHECK(task == NULL && transfer.transferred);
    vireo_task_queue_close_report_t closed = {0};
    EXPECT(vireo_task_queue_close(queue, VIREO_TASK_QUEUE_CANCEL_PENDING, &closed), VIREO_OK);
    EXPECT(vireo_task_queue_destroy(&queue), VIREO_RESULT_BUSY);
    CHECK(p.releases == 0);
    EXPECT(vireo_task_queue_try_take_cancelled(queue, &task, &transfer), VIREO_OK);
    check_payload(task, sizeof(input));
    EXPECT(vireo_task_destroy(&task), VIREO_OK);
    CHECK(p.releases == 1);
    /* 关闭后的未交接owner同样由caller最终清理。 */
    EXPECT(vireo_task_create_copy_with_allocator(metadata(), input, sizeof(input), 4096, &a, &task), VIREO_OK);
    EXPECT(vireo_task_queue_try_push(queue, &task, &transfer), VIREO_RESULT_CANCELLED);
    CHECK(task != NULL && !transfer.transferred && p.releases == 1);
    check_payload(task, sizeof(input));
    EXPECT(vireo_task_destroy(&task), VIREO_OK);
    EXPECT(vireo_task_queue_destroy(&queue), VIREO_OK);
    CHECK(p.releases == 2);
}

/** @brief 单worker短借，pool在返回后必须调用真正task_destroy。 */
static vireo_result_t execute(void *context, vireo_task_t const *task) {
    probe_t *p = context;
    CHECK(p->releases == 0);
    check_payload(task, 3);
    ++p->calls;
    return VIREO_OK;
}

static void real_worker(void) {
    probe_t p = {0};
    vireo_task_allocator_t const a = {&p, allocate, deallocate};
    unsigned char input[] = {0, 1, 2};
    vireo_task_t *task = NULL;
    EXPECT(vireo_task_create_copy_with_allocator(metadata(), input, sizeof(input), 4096, &a, &task), VIREO_OK);
    vireo_task_queue_t *queue = NULL;
    vireo_task_queue_options_t const options = {1, 65536};
    EXPECT(vireo_task_queue_create(&options, &queue), VIREO_OK);
    EXPECT(vireo_task_queue_prepare_wait(queue), VIREO_OK);
    vireo_task_queue_transfer_report_t transfer = {0};
    vireo_thread_pool_t *pool = NULL;
    vireo_thread_pool_options_t const pool_options = {1, 65536};
    EXPECT(vireo_thread_pool_create(&pool_options, &pool), VIREO_OK);
    vireo_thread_pool_configuration_t const config = {queue, execute, &p};
    EXPECT(vireo_thread_pool_configure(pool, &config, NULL), VIREO_OK);
    /* configure要求专用队列为空，完成配置之后才交接任务。 */
    EXPECT(vireo_task_queue_try_push(queue, &task, &transfer), VIREO_OK);
    vireo_thread_pool_report_t started = {0};
    EXPECT(vireo_thread_pool_start(pool, &started), VIREO_OK);
    EXPECT(vireo_thread_pool_enable_execution(pool, &started), VIREO_OK);
    bool done = false;
    for (size_t i = 0; i < 100000; ++i) {
        vireo_thread_pool_shutdown_report_t report = {0};
        errno = EDOM;
        vireo_result_t const result = vireo_thread_pool_shutdown_and_join(pool, VIREO_TASK_QUEUE_DRAIN, &report);
        CHECK(errno == EDOM);
        bool const close_busy = report.stage == VIREO_THREAD_POOL_SHUTDOWN_STAGE_CLOSE_QUEUE &&
            report.close_report.stage == VIREO_TASK_QUEUE_STAGE_LOCK && report.close_report.pthread_error == EBUSY;
        bool const inspect_busy = report.stage == VIREO_THREAD_POOL_SHUTDOWN_STAGE_JOIN_WORKERS &&
            report.pool_report.stage == VIREO_THREAD_POOL_STAGE_CHECK_QUEUE;
        if (result == VIREO_RESULT_BUSY && (close_busy || inspect_busy)) { (void)sched_yield(); continue; }
        CHECK(result == VIREO_OK && report.pool_report.joined_count == 1);
        done = true;
        break;
    }
    CHECK(done && p.calls == 1 && p.releases == 1 && p.live == NULL);
    EXPECT(vireo_thread_pool_destroy(&pool), VIREO_OK);
    EXPECT(vireo_task_queue_destroy(&queue), VIREO_OK);
}

int main(void) {
    int previous = 0;
    CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previous) == 0);
    direct_lifetimes();
    failures_preserve_owner();
    cancelled_queue();
    real_worker();
    CHECK(pthread_setcancelstate(previous, NULL) == 0);
    puts("task clear: 5 sizes, move/cancel, failure retention, cancelled/closed queue and real worker passed");
    return 0;
}
