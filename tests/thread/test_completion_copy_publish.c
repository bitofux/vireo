/*
 * PROJECT : VIREO
 * FILE    : test_completion_copy_publish.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-14
 * BRIEF   : 独立字节、真实MPSC回投、未交接残留和031首帧worker协作
 */
#define _GNU_SOURCE
#include "completion_publish_internal.h"
#include <vireo/net/async_request_head.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); abort(); } } while (0)
#define EXPECT(x, y) do { errno = EDOM; vireo_result_t const got_ = (x); CHECK(got_ == (y) && errno == EDOM); } while (0)
#define LIMIT 1000000U
_Static_assert(VIREO_COMPLETION_PUBLISH_NONE == 0 && VIREO_COMPLETION_PUBLISH_INSPECT_TASK == 1 &&
 VIREO_COMPLETION_PUBLISH_MAKE_METADATA == 2 && VIREO_COMPLETION_PUBLISH_CREATE_COMPLETION == 3 &&
 VIREO_COMPLETION_PUBLISH_PUSH_QUEUE == 4 && VIREO_COMPLETION_PUBLISH_NOTIFY == 5, "new stable stages");
_Static_assert(VIREO_COMPLETION_QUEUE_TRANSFER_NONE == 0 && VIREO_NOTIFIER_STAGE_NOTIFY == 4,
 "old stable stages");

/** 单组串行拥有资源；生产者并发只借queue/notifier。 */
typedef struct basic {
    vireo_task_t *task; /**< 独立输入owner，销毁前结束全部借用。 */
    vireo_completion_queue_t *queue; /**< 固定容量结果owner，测试唯一consumer。 */
    vireo_notifier_t *notifier; /**< 独立eventfd owner，不直接读写fd。 */
} basic_t;
static vireo_task_metadata_t request(uint64_t id) {
    vireo_task_route_t route; vireo_task_metadata_t metadata;
    EXPECT(vireo_task_route_make(9, 3, 11, (uint32_t)id, &route), VIREO_OK);
    EXPECT(vireo_task_metadata_make(route, id, 9, id == 1 ? 0 : UINT64_MAX, &metadata), VIREO_OK);
    return metadata;
}
static vireo_task_t *make_task(uint64_t id) {
    unsigned char const payload[] = {9, 0, 7}; vireo_task_t *task = NULL;
    EXPECT(vireo_task_create_copy(request(id), payload, sizeof payload, 4096, &task), VIREO_OK);
    return task;
}
static void setup_basic(basic_t *b, bool prepared, size_t capacity) {
    *b = (basic_t){0}; b->task = make_task(1);
    vireo_completion_queue_options_t const qo = {capacity, 65536};
    vireo_notifier_options_t const no = {4096};
    EXPECT(vireo_completion_queue_create(&qo, &b->queue), VIREO_OK);
    if (prepared) { EXPECT(vireo_completion_queue_prepare_wait(b->queue), VIREO_OK); }
    EXPECT(vireo_notifier_create(&no, &b->notifier, NULL), VIREO_OK);
}
static void cleanup_basic(basic_t *b) {
    EXPECT(vireo_task_destroy(&b->task), VIREO_OK);
    EXPECT(vireo_completion_queue_destroy(&b->queue), VIREO_OK);
    EXPECT(vireo_notifier_destroy(&b->notifier, NULL), VIREO_OK);
}
static bool same(vireo_task_metadata_t a, vireo_task_metadata_t b) {
    bool equal; EXPECT(vireo_task_metadata_same_request(a, b, &equal), VIREO_OK);
    return equal && a.operation == b.operation && a.deadline_ns == b.deadline_ns;
}
static void verify(vireo_completion_t const *owner, vireo_task_metadata_t metadata,
                   void const *bytes, size_t size, vireo_result_t work, vireo_status_t status) {
    vireo_completion_info_t info; vireo_completion_payload_view_t view;
    EXPECT(vireo_completion_inspect(owner, &info), VIREO_OK);
    EXPECT(vireo_completion_borrow_payload(owner, &view), VIREO_OK);
    CHECK(same(info.metadata.request, metadata) && info.metadata.result == work &&
          info.metadata.suggested_status == status && info.payload_size == size && view.size == size);
    if (size == 0) { CHECK(view.data == NULL); } else { CHECK(!memcmp(view.data, bytes, size)); }
}
static vireo_completion_t *pop(vireo_completion_queue_t *queue) {
    vireo_completion_t *owner = NULL; vireo_completion_queue_transfer_report_t report;
    for (size_t i = 0; i < LIMIT; ++i) {
        errno = EDOM; vireo_result_t result = vireo_completion_queue_try_pop(queue, &owner, &report);
        CHECK(errno == EDOM);
        if (result == VIREO_OK) { CHECK(report.transferred && owner); return owner; }
        CHECK((result == VIREO_RESULT_BUSY || result == VIREO_RESULT_NOT_FOUND) && !report.transferred);
        sched_yield();
    }
    CHECK(false); return NULL;
}
static void empty(basic_t *b, uint64_t hints) {
    vireo_completion_t *owner = NULL; vireo_completion_queue_transfer_report_t report;
    EXPECT(vireo_completion_queue_try_pop(b->queue, &owner, &report), VIREO_RESULT_NOT_FOUND);
    uint64_t count; EXPECT(vireo_notifier_consume(b->notifier, &count, NULL), VIREO_OK); CHECK(count == hints);
}
static vireo_result_t publish(basic_t *b, void const *bytes, size_t size,
                              vireo_completion_t **remaining, vireo_completion_publish_report_t *report) {
    return vireo_completion_copy_wait_publish(b->task, VIREO_OK, VIREO_STATUS_OK,
        bytes, size, 4096, b->queue, b->notifier, remaining, report);
}
static void independent_copy(void) {
    basic_t b; setup_basic(&b, true, 1); unsigned char bytes[] = {1, 0, 3};
    unsigned char const expected[] = {1, 0, 3}; vireo_completion_t *remaining = NULL;
    vireo_completion_publish_report_t report;
    EXPECT(publish(&b, bytes, sizeof bytes, &remaining, &report), VIREO_OK);
    CHECK(report.stage == VIREO_COMPLETION_PUBLISH_NONE && report.task_inspected &&
      same(report.request_metadata, request(1)) && report.completion_created && report.push_called &&
      report.queue_report.transferred && report.completion_transferred && !report.completion_retained &&
      report.notify_called && report.notify_result == VIREO_OK && remaining == NULL);
    memset(bytes, 255, sizeof bytes); EXPECT(vireo_task_destroy(&b.task), VIREO_OK);
    vireo_completion_t *owner = pop(b.queue);
    verify(owner, request(1), expected, sizeof expected, VIREO_OK, VIREO_STATUS_OK);
    EXPECT(vireo_completion_destroy(&owner), VIREO_OK); empty(&b, 1); cleanup_basic(&b);
}
static void empty_response(void) {
    basic_t b; setup_basic(&b, true, 1); vireo_completion_t *remaining = NULL;
    vireo_completion_publish_report_t report; EXPECT(publish(&b, NULL, 0, &remaining, &report), VIREO_OK);
    vireo_completion_t *owner = pop(b.queue); verify(owner, request(1), NULL, 0, VIREO_OK, VIREO_STATUS_OK);
    EXPECT(vireo_completion_destroy(&owner), VIREO_OK); empty(&b, 1); cleanup_basic(&b);
}
static void failed_work(void) {
    basic_t b; setup_basic(&b, true, 1);
    vireo_result_t const results[] = {VIREO_RESULT_DATABASE, VIREO_RESULT_CANCELLED, VIREO_RESULT_TIMEOUT};
    vireo_status_t const statuses[] = {VIREO_STATUS_DB_ERROR, VIREO_STATUS_TASK_CANCELLED, VIREO_STATUS_TIMEOUT};
    for (size_t i = 0; i < 3; ++i) {
        vireo_completion_t *remaining = NULL; vireo_completion_publish_report_t report;
        EXPECT(vireo_completion_copy_wait_publish(b.task, results[i], statuses[i], NULL, 0, 4096,
          b.queue, b.notifier, &remaining, &report), VIREO_OK);
        vireo_completion_t *owner = pop(b.queue); verify(owner, request(1), NULL, 0, results[i], statuses[i]);
        EXPECT(vireo_completion_destroy(&owner), VIREO_OK);
    }
    empty(&b, 3); cleanup_basic(&b);
}
static void bad_arguments(void) {
    basic_t b; setup_basic(&b, true, 1); vireo_completion_t *owner = NULL; vireo_completion_publish_report_t report;
    for (unsigned int i = 0; i < 8; ++i) {
        memset(&report, 0xA5, sizeof report);
        EXPECT(vireo_completion_copy_wait_publish(i == 0 ? NULL : b.task, VIREO_OK, VIREO_STATUS_OK,
            NULL, i == 7 ? 1 : 0, i == 1 ? 0 : 4096, i == 2 ? NULL : b.queue,
            i == 3 ? NULL : b.notifier, i == 4 ? NULL : &owner, i == 5 ? NULL : &report),
            i == 6 ? VIREO_OK : VIREO_RESULT_INVALID_ARGUMENT);
        if (i == 6) { vireo_completion_t *taken = pop(b.queue); EXPECT(vireo_completion_destroy(&taken), VIREO_OK); }
        else if (i != 5) { CHECK(report.stage == VIREO_COMPLETION_PUBLISH_NONE && !report.task_inspected); }
        CHECK(owner == NULL);
    }
    /* 入口非空owner始终保留，不接管caller旧对象。 */
    vireo_completion_metadata_t md; EXPECT(vireo_completion_metadata_make(request(1), VIREO_OK, VIREO_STATUS_OK, &md), VIREO_OK);
    EXPECT(vireo_completion_create_copy(md, NULL, 0, 4096, &owner), VIREO_OK);
    vireo_completion_t *before = owner; EXPECT(publish(&b, NULL, 0, &owner, &report), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(owner == before && !report.task_inspected); EXPECT(vireo_completion_destroy(&owner), VIREO_OK);
    empty(&b, 1); cleanup_basic(&b);
}
static void bad_metadata(void) {
    basic_t b; setup_basic(&b, true, 1); vireo_completion_t *owner = NULL; vireo_completion_publish_report_t report;
    EXPECT(vireo_completion_copy_wait_publish(b.task, (vireo_result_t)99, VIREO_STATUS_OK, NULL, 0, 4096,
      b.queue, b.notifier, &owner, &report), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(report.task_inspected && report.stage == VIREO_COMPLETION_PUBLISH_MAKE_METADATA && !report.completion_created);
    EXPECT(vireo_completion_copy_wait_publish(b.task, VIREO_OK, (vireo_status_t)65535, NULL, 0, 4096,
      b.queue, b.notifier, &owner, &report), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(report.stage == VIREO_COMPLETION_PUBLISH_MAKE_METADATA && owner == NULL);
    empty(&b, 0); cleanup_basic(&b);
}
static void allocation_boundaries(void) {
    basic_t b; setup_basic(&b, true, 1); unsigned char const byte = 42;
    vireo_completion_t *owner = NULL; vireo_completion_publish_report_t report;
    size_t const budgets[] = {1, VIREO_COMPLETION_MAX_ALLOCATION_BYTES + 1, 4096};
    for (size_t i = 0; i < 3; ++i) {
        EXPECT(vireo_completion_copy_wait_publish(b.task, VIREO_OK, VIREO_STATUS_OK, &byte,
            i == 2 ? SIZE_MAX : 1, budgets[i], b.queue, b.notifier, &owner, &report),
            i == 2 ? VIREO_RESULT_OVERFLOW : VIREO_RESULT_RANGE);
        CHECK(report.stage == VIREO_COMPLETION_PUBLISH_CREATE_COMPLETION && !report.completion_created && !report.push_called && owner == NULL);
    }
    empty(&b, 0); cleanup_basic(&b);
}
static void not_prepared(void) {
    basic_t b; setup_basic(&b, false, 1); unsigned char const bytes[] = {4, 5};
    vireo_completion_t *remaining = NULL; vireo_completion_publish_report_t report;
    EXPECT(publish(&b, bytes, sizeof bytes, &remaining, &report), VIREO_RESULT_NOT_FOUND);
    CHECK(report.completion_created && report.completion_retained && !report.completion_transferred &&
          report.push_called && !report.notify_called && report.stage == VIREO_COMPLETION_PUBLISH_PUSH_QUEUE);
    verify(remaining, request(1), bytes, sizeof bytes, VIREO_OK, VIREO_STATUS_OK);
    EXPECT(vireo_completion_destroy(&remaining), VIREO_OK); empty(&b, 0); cleanup_basic(&b);
}
static void closed_queue(void) {
    basic_t b; setup_basic(&b, true, 1); vireo_completion_queue_close_report_t close_report;
    EXPECT(vireo_completion_queue_close(b.queue, &close_report), VIREO_OK);
    vireo_completion_t *remaining = NULL; vireo_completion_publish_report_t report;
    EXPECT(publish(&b, NULL, 0, &remaining, &report), VIREO_RESULT_CANCELLED);
    CHECK(report.completion_retained && !report.notify_called && !report.queue_report.transferred);
    EXPECT(vireo_completion_destroy(&remaining), VIREO_OK);
    uint64_t count; EXPECT(vireo_notifier_consume(b.notifier, &count, NULL), VIREO_OK); CHECK(count == 0);
    cleanup_basic(&b);
}

/** 串行模型每组独占；没有并发producer时才发布此测试上下文。 */
typedef struct model {
    unsigned int calls[5]; /**< inspect/make/create/push/notify每步实际次数。 */
    int fail_step; /**< -1为不提前拒绝，0/1/2分别模拟公开前段失败。 */
    bool reject_push; /**< 原WAIT异常未交接，保真实已创建owner。 */
    bool push_error; /**< 真实交接/解锁成功后改报原UNLOCK/EIO模型。 */
    bool notify_error; /**< 未执行内核write，报告公开IO/EINTR模型。 */
    bool already_pending; /**< 公开ALREADY_PENDING结果模型，不冒真实eventfd饱和。 */
    bool consume_before_notify; /**< 真实pop/destroy后才提示，检验转移后无对象访问。 */
    vireo_completion_queue_t *queue; /**< consume模型短借，非第二owner。 */
} model_t;
static model_t *active_model;
static vireo_result_t model_inspect(vireo_task_t const *task, vireo_task_info_t *info) {
    ++active_model->calls[0]; errno = EIO;
    return active_model->fail_step == 0 ? VIREO_RESULT_IO : vireo_task_inspect(task, info);
}
static vireo_result_t model_metadata(vireo_task_metadata_t request_value, vireo_result_t work,
                                     vireo_status_t status, vireo_completion_metadata_t *metadata) {
    ++active_model->calls[1]; errno = EIO;
    return active_model->fail_step == 1 ? VIREO_RESULT_INTERNAL
        : vireo_completion_metadata_make(request_value, work, status, metadata);
}
static vireo_result_t model_create(vireo_completion_metadata_t metadata, void const *data,
                                   size_t size, size_t budget, vireo_completion_t **owner) {
    ++active_model->calls[2]; errno = ENOMEM;
    return active_model->fail_step == 2 ? VIREO_RESULT_NO_MEMORY
        : vireo_completion_create_copy(metadata, data, size, budget, owner);
}
static vireo_result_t model_push(vireo_completion_queue_t *queue, vireo_completion_t **owner,
                                 vireo_completion_queue_transfer_report_t *report) {
    ++active_model->calls[3]; errno = EIO;
    if (active_model->reject_push) {
        *report = (vireo_completion_queue_transfer_report_t){VIREO_COMPLETION_QUEUE_TRANSFER_WAIT, false, EINVAL};
        return VIREO_RESULT_INTERNAL;
    }
    vireo_result_t result = vireo_completion_queue_wait_push(queue, owner, report);
    if (active_model->push_error) {
        CHECK(result == VIREO_OK && report->transferred && *owner == NULL);
        report->stage = VIREO_COMPLETION_QUEUE_TRANSFER_UNLOCK; report->pthread_error = EIO;
        return VIREO_RESULT_INTERNAL;
    }
    return result;
}
static vireo_result_t model_notify(vireo_notifier_t *notifier,
    vireo_notifier_notify_outcome_t *outcome, vireo_notifier_error_t *error) {
    ++active_model->calls[4]; errno = EIO;
    if (active_model->consume_before_notify) {
        vireo_completion_t *owner = pop(active_model->queue); EXPECT(vireo_completion_destroy(&owner), VIREO_OK);
    }
    if (active_model->notify_error) {
        *error = (vireo_notifier_error_t){VIREO_NOTIFIER_STAGE_NOTIFY, EINTR}; return VIREO_RESULT_IO;
    }
    if (active_model->already_pending) {
        *error = (vireo_notifier_error_t){0}; *outcome = VIREO_NOTIFIER_NOTIFY_ALREADY_PENDING; return VIREO_OK;
    }
    return vireo_notifier_notify(notifier, outcome, error);
}
static vireo_completion_publish_ops_t const model_ops = {
    model_inspect, model_metadata, model_create, model_push, model_notify
};
static vireo_result_t model_call(basic_t *b, vireo_completion_t **owner,
                                vireo_completion_publish_report_t *report) {
    return vireo_completion_publish_with_ops(b->task, VIREO_OK, VIREO_STATUS_OK, NULL, 0,
        4096, b->queue, b->notifier, owner, report, &model_ops);
}
static void early_failure(int step) {
    basic_t b; setup_basic(&b, true, 1); model_t m = {.fail_step = step}; active_model = &m;
    vireo_completion_t *owner = NULL; vireo_completion_publish_report_t report;
    vireo_result_t const expected[] = {VIREO_RESULT_IO, VIREO_RESULT_INTERNAL, VIREO_RESULT_NO_MEMORY};
    EXPECT(model_call(&b, &owner, &report), expected[step]);
    CHECK(report.stage == (vireo_completion_publish_stage_t)(step + 1) && owner == NULL && !report.completion_created);
    for (size_t i = 0; i < 5; ++i) { CHECK(m.calls[i] == (i <= (size_t)step ? 1U : 0U)); }
    empty(&b, 0); active_model = NULL; cleanup_basic(&b);
}
static void inspect_failure(void) { early_failure(0); }
static void metadata_failure(void) { early_failure(1); }
static void create_failure(void) { early_failure(2); }
static void untransferred_error(void) {
    basic_t b; setup_basic(&b, true, 1); model_t m = {.fail_step = -1, .reject_push = true}; active_model = &m;
    vireo_completion_t *owner = NULL; vireo_completion_publish_report_t report;
    EXPECT(model_call(&b, &owner, &report), VIREO_RESULT_INTERNAL);
    CHECK(owner && report.completion_retained && !report.completion_transferred && !report.notify_called &&
          report.queue_report.stage == VIREO_COMPLETION_QUEUE_TRANSFER_WAIT && m.calls[3] == 1 && m.calls[4] == 0);
    EXPECT(vireo_completion_destroy(&owner), VIREO_OK); empty(&b, 0); active_model = NULL; cleanup_basic(&b);
}
static void transferred_error(void) {
    basic_t b; setup_basic(&b, true, 1); model_t m = {.fail_step = -1, .push_error = true}; active_model = &m;
    vireo_completion_t *owner = NULL; vireo_completion_publish_report_t report;
    EXPECT(model_call(&b, &owner, &report), VIREO_RESULT_INTERNAL);
    CHECK(owner == NULL && report.completion_transferred && !report.completion_retained && report.notify_called &&
      report.notify_result == VIREO_OK && report.stage == VIREO_COMPLETION_PUBLISH_PUSH_QUEUE &&
      report.queue_report.pthread_error == EIO && m.calls[3] == 1 && m.calls[4] == 1);
    owner = pop(b.queue); EXPECT(vireo_completion_destroy(&owner), VIREO_OK);
    empty(&b, 1); active_model = NULL; cleanup_basic(&b);
}
static void notification_failure(bool push_error) {
    basic_t b; setup_basic(&b, true, 1); model_t m = {.fail_step = -1, .push_error = push_error, .notify_error = true}; active_model = &m;
    vireo_completion_t *owner = NULL; vireo_completion_publish_report_t report;
    EXPECT(model_call(&b, &owner, &report), push_error ? VIREO_RESULT_INTERNAL : VIREO_RESULT_IO);
    CHECK(owner == NULL && report.completion_transferred && report.notify_called && !report.completion_retained &&
      report.stage == (push_error ? VIREO_COMPLETION_PUBLISH_PUSH_QUEUE : VIREO_COMPLETION_PUBLISH_NOTIFY) &&
      report.notify_result == VIREO_RESULT_IO && report.notify_error.system_errno == EINTR && m.calls[4] == 1);
    uint64_t hints; EXPECT(vireo_notifier_consume(b.notifier, &hints, NULL), VIREO_OK); CHECK(hints == 0);
    /* caller主动查队列，绝不重新发布，即使提示计数为0。 */
    owner = pop(b.queue); verify(owner, request(1), NULL, 0, VIREO_OK, VIREO_STATUS_OK);
    EXPECT(vireo_completion_destroy(&owner), VIREO_OK); empty(&b, 0); active_model = NULL; cleanup_basic(&b);
}
static void notify_failure(void) { notification_failure(false); }
static void dual_failure(void) { notification_failure(true); }
static void already_pending(void) {
    basic_t b; setup_basic(&b, true, 1); model_t m = {.fail_step = -1, .already_pending = true}; active_model = &m;
    vireo_completion_t *owner = NULL; vireo_completion_publish_report_t report;
    EXPECT(model_call(&b, &owner, &report), VIREO_OK);
    CHECK(report.notify_outcome == VIREO_NOTIFIER_NOTIFY_ALREADY_PENDING && m.calls[4] == 1);
    owner = pop(b.queue); EXPECT(vireo_completion_destroy(&owner), VIREO_OK);
    empty(&b, 0); active_model = NULL; cleanup_basic(&b);
}
static void already_consumed(void) {
    basic_t b; setup_basic(&b, true, 1); model_t m = {.fail_step = -1, .consume_before_notify = true, .queue = b.queue}; active_model = &m;
    vireo_completion_t *owner = NULL; vireo_completion_publish_report_t report;
    EXPECT(model_call(&b, &owner, &report), VIREO_OK); CHECK(report.completion_transferred && owner == NULL);
    empty(&b, 1); active_model = NULL; cleanup_basic(&b);
}
static void invalid_ops(void) {
    basic_t b; setup_basic(&b, true, 1); model_t m = {.fail_step = -1}; active_model = &m;
    for (size_t i = 0; i < 6; ++i) {
        vireo_completion_publish_ops_t ops = model_ops;
        if (i == 0) ops.inspect = NULL;
        if (i == 1) ops.make_metadata = NULL;
        if (i == 2) ops.create_copy = NULL;
        if (i == 3) ops.wait_push = NULL;
        if (i == 4) ops.notify = NULL;
        vireo_completion_t *owner = NULL; vireo_completion_publish_report_t report;
        EXPECT(vireo_completion_publish_with_ops(b.task, VIREO_OK, VIREO_STATUS_OK, NULL, 0, 4096,
          b.queue, b.notifier, &owner, &report, i == 5 ? NULL : &ops), VIREO_RESULT_INVALID_ARGUMENT);
        CHECK(!report.task_inspected && owner == NULL);
    }
    for (size_t i = 0; i < 5; ++i) CHECK(m.calls[i] == 0);
    empty(&b, 0); active_model = NULL; cleanup_basic(&b);
}

/** 每生产者独占task、源字节、owner与报告，join后manager才读非原子结果。 */
typedef struct producer {
    vireo_task_t *task; /**< manager拥有，join后结束借用再destroy。 */
    vireo_completion_queue_t *queue; /**< 多producer短借，manager唯一拥有。 */
    vireo_notifier_t *notifier; /**< 多producer短借，禁止并发destroy。 */
    unsigned char bytes[3]; /**< 本线程响应输入，复制后可改写。 */
    vireo_completion_t *remaining; /**< 未交接的本线程唯一残留，manager join后接管。 */
    vireo_completion_publish_report_t report; /**< 本线程写，manager join后读。 */
    vireo_result_t result; /**< 本次helper结果，只在join后读。 */
    atomic_bool entered; /**< release/acquire仅发布线程进入，不假称cond_wait已执行。 */
    atomic_bool done; /**< 本线程返回helper后发布，非completion数量。 */
} producer_t;
static void *produce(void *argument) {
    producer_t *p = argument; int old_state;
    CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &old_state) == 0);
    atomic_store_explicit(&p->entered, true, memory_order_release);
    errno = EDOM;
    p->result = vireo_completion_copy_wait_publish(p->task, VIREO_OK, VIREO_STATUS_OK,
      p->bytes, sizeof p->bytes, 4096, p->queue, p->notifier, &p->remaining, &p->report);
    CHECK(errno == EDOM); memset(p->bytes, 255, sizeof p->bytes);
    atomic_store_explicit(&p->done, true, memory_order_release); return NULL;
}
static void init_producer(producer_t *p, basic_t *b, uint64_t id) {
    *p = (producer_t){.task = make_task(id), .queue = b->queue, .notifier = b->notifier,
                     .bytes = {(unsigned char)id, 0, 7}};
    atomic_init(&p->entered, false); atomic_init(&p->done, false);
}
static void await_entered(producer_t *p) {
    for (size_t i = 0; i < LIMIT; ++i) {
        if (atomic_load_explicit(&p->entered, memory_order_acquire)) return;
        sched_yield();
    }
    CHECK(false);
}
static void mpsc_small_capacity(void) {
    basic_t b; setup_basic(&b, true, 1); producer_t p[4]; pthread_t threads[4]; bool seen[4] = {0};
    for (size_t i = 0; i < 4; ++i) { init_producer(&p[i], &b, i + 1); CHECK(pthread_create(&threads[i], NULL, produce, &p[i]) == 0); }
    for (size_t i = 0; i < 4; ++i) {
        vireo_completion_t *owner = pop(b.queue); vireo_completion_info_t info;
        EXPECT(vireo_completion_inspect(owner, &info), VIREO_OK);
        uint64_t const id = info.metadata.request.request_instance_id; CHECK(id >= 1 && id <= 4 && !seen[id - 1]); seen[id - 1] = true;
        unsigned char const expected[] = {(unsigned char)id, 0, 7};
        verify(owner, request(id), expected, sizeof expected, VIREO_OK, VIREO_STATUS_OK);
        EXPECT(vireo_completion_destroy(&owner), VIREO_OK);
    }
    for (size_t i = 0; i < 4; ++i) {
        CHECK(pthread_join(threads[i], NULL) == 0 && p[i].result == VIREO_OK && p[i].remaining == NULL && p[i].report.completion_transferred);
        EXPECT(vireo_task_destroy(&p[i].task), VIREO_OK);
    }
    empty(&b, 4); cleanup_basic(&b);
}
static void full_queue(bool close_queue) {
    basic_t b; setup_basic(&b, true, 1); vireo_completion_t *remaining = NULL; vireo_completion_publish_report_t report;
    EXPECT(publish(&b, NULL, 0, &remaining, &report), VIREO_OK);
    producer_t p; init_producer(&p, &b, 2); pthread_t thread;
    CHECK(pthread_create(&thread, NULL, produce, &p) == 0); await_entered(&p);
    CHECK(!atomic_load_explicit(&p.done, memory_order_acquire));
    if (close_queue) {
        vireo_completion_queue_close_report_t close_report; bool closed = false;
        for (size_t i = 0; i < LIMIT; ++i) {
            errno = EDOM; vireo_result_t result = vireo_completion_queue_close(b.queue, &close_report); CHECK(errno == EDOM);
            if (result == VIREO_OK) { closed = true; break; } CHECK(result == VIREO_RESULT_BUSY); sched_yield();
        }
        CHECK(closed);
    } else {
        vireo_completion_t *owner = pop(b.queue); EXPECT(vireo_completion_destroy(&owner), VIREO_OK);
    }
    CHECK(pthread_join(thread, NULL) == 0);
    if (close_queue) {
        CHECK(p.result == VIREO_RESULT_CANCELLED && p.remaining && p.report.completion_retained && !p.report.notify_called);
        unsigned char const bytes[] = {2, 0, 7}; verify(p.remaining, request(2), bytes, sizeof bytes, VIREO_OK, VIREO_STATUS_OK);
        EXPECT(vireo_completion_destroy(&p.remaining), VIREO_OK);
    } else { CHECK(p.result == VIREO_OK && p.remaining == NULL); }
    vireo_completion_t *owner = pop(b.queue); EXPECT(vireo_completion_destroy(&owner), VIREO_OK);
    uint64_t count; EXPECT(vireo_notifier_consume(b.notifier, &count, NULL), VIREO_OK); CHECK(count == (close_queue ? 1U : 2U));
    EXPECT(vireo_task_destroy(&p.task), VIREO_OK); cleanup_basic(&b);
}
static void full_then_pop(void) { full_queue(false); }
static void full_then_close(void) { full_queue(true); }

/* 本测试的独立公开网络夹具，不包含net私有头。 */
/** 测试独占的真实 loopback 资源；只通过公开合同访问。 */
typedef struct fixture {
    vireo_tcp_server_t *server;           /**< 本客户及 listener 的资源根。 */
    vireo_tcp_server_t *other_server;     /**< 独立拥有域，用于跨域拒绝。 */
    vireo_connection_pool_lease_t client; /**< 当前客户值，归还后清零。 */
    int peer;                            /**< caller 的 TCP 对端，-1 为空。 */
    int listener_fd;                     /**< 构造期间 owner fd，转移后 -1。 */
    vireo_acceptor_t *listener;           /**< 构造期 owner，收纳后 NULL。 */
    struct sockaddr_in address;          /**< loopback 数值端点，供重接客户。 */
} fixture_t;

static bool add_client(fixture_t *f) {
    CHECK(f->peer == -1 && f->client.pool_id == 0);
    f->peer = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    CHECK(f->peer >= 0);
    CHECK(connect(f->peer, (struct sockaddr const *)&f->address, sizeof f->address) == 0);
    vireo_connection_options_t const options = {64, 64, 128};
    vireo_tcp_server_admit_budget_t const budget = {1, 1};
    vireo_tcp_server_admit_info_t info;
    CHECK(vireo_tcp_server_admit_batch(f->server, &options, &budget, &f->client, 1,
                                       &info, NULL) == VIREO_OK);
    CHECK(info.admitted_count == 1 && info.accepted_count == 1);
    return true;
}

static bool setup_capacity(fixture_t *f, size_t capacity) {
    *f = (fixture_t){.peer = -1, .listener_fd = -1};
    vireo_tcp_server_options_t const options = {capacity, 2, VIREO_TCP_SERVER_MAX_MEMORY, 256};
    CHECK(vireo_tcp_server_create(&options, &f->server, NULL) == VIREO_OK);
    CHECK(vireo_tcp_server_create(&options, &f->other_server, NULL) == VIREO_OK);
    f->listener_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    CHECK(f->listener_fd >= 0);
    f->address.sin_family = AF_INET;
    f->address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(bind(f->listener_fd, (struct sockaddr const *)&f->address, sizeof f->address) == 0);
    CHECK(listen(f->listener_fd, 4) == 0);
    socklen_t length = sizeof f->address;
    CHECK(getsockname(f->listener_fd, (struct sockaddr *)&f->address, &length) == 0);
    CHECK(length == sizeof f->address);
    vireo_acceptor_options_t const listener_options = {VIREO_ACCEPTOR_MAX_MEMORY};
    CHECK(vireo_acceptor_create(&listener_options, &f->listener_fd, &f->listener, NULL) == VIREO_OK);
    CHECK(vireo_tcp_server_adopt_listener(f->server, &f->listener, NULL) == VIREO_OK);
    return add_client(f);
}

static bool setup(fixture_t *f) {
    return setup_capacity(f, 1);
}

static bool release_client(fixture_t *f) {
    CHECK(vireo_tcp_server_release_client(f->server, &f->client, NULL) == VIREO_OK);
    CHECK(f->client.pool_id == 0 && f->client.slot_index == 0 && f->client.generation == 0);
    CHECK(close(f->peer) == 0);
    f->peer = -1;
    return true;
}

static bool cleanup(fixture_t *f) {
    if (f->client.pool_id != 0) CHECK(release_client(f));
    if (f->peer >= 0) CHECK(close(f->peer) == 0);
    if (f->listener_fd >= 0) CHECK(close(f->listener_fd) == 0);
    CHECK(vireo_acceptor_destroy(&f->listener, NULL) == VIREO_OK);
    CHECK(vireo_tcp_server_destroy(&f->server, NULL) == VIREO_OK);
    CHECK(vireo_tcp_server_destroy(&f->other_server, NULL) == VIREO_OK);
    CHECK(f->server == NULL && f->other_server == NULL);
    return true;
}


/** pool长借的测试worker上下文，不包含客户/server指针或fd。 */
typedef struct network_worker {
    vireo_completion_queue_t *queue; /**< manager拥有的结果队列，借至pool销毁。 */
    vireo_notifier_t *notifier; /**< 借至全部worker结束，不直接操作fd。 */
    pthread_barrier_t entered; /**< 原task已领取，manager可复用已消费读区。 */
    pthread_barrier_t release; /**< manager确认源区重写后才读取task副本。 */
    vireo_completion_publish_report_t report; /**< 本单worker写，仅join后观察。 */
    vireo_result_t result; /**< 本次真实helper结果，非业务结果。 */
} network_worker_t;
static void meet(pthread_barrier_t *barrier) {
    int const result = pthread_barrier_wait(barrier); CHECK(result == 0 || result == PTHREAD_BARRIER_SERIAL_THREAD);
}
static vireo_result_t execute_network(void *context, vireo_task_t const *task) {
    network_worker_t *worker = context; meet(&worker->entered); meet(&worker->release);
    vireo_task_payload_view_t view; EXPECT(vireo_task_borrow_payload(task, &view), VIREO_OK);
    CHECK(view.size == 35); vireo_protocol_header_t header; vireo_protocol_codec_issue_t issue;
    EXPECT(vireo_protocol_header_decode(view.data, view.size, &header, &issue), VIREO_OK);
    EXPECT(vireo_protocol_request_header_validate(&header, &issue), VIREO_OK);
    EXPECT(vireo_protocol_frame_crc32c_verify(view.data, 32, view.data + 32, 3, &issue), VIREO_OK);
    unsigned char const expected[] = {1, 2, 3};
    CHECK(header.sequence == 1 && header.command == VIREO_COMMAND_NODE_STAT && !memcmp(view.data + 32, expected, 3));
    vireo_completion_t *remaining = NULL; errno = EDOM;
    worker->result = vireo_completion_copy_wait_publish(task, VIREO_OK, VIREO_STATUS_OK,
        view.data + 32, 3, 4096, worker->queue, worker->notifier, &remaining, &worker->report);
    CHECK(errno == EDOM && remaining == NULL); return worker->result;
}
static void encode_request(unsigned char *wire, uint32_t sequence) {
    vireo_protocol_header_t h = {.command = VIREO_COMMAND_NODE_STAT, .body_len = 3,
      .sequence = sequence, .session_handle = 0x10203040, .task_handle = UINT32_MAX};
    wire[32] = (unsigned char)sequence; wire[33] = 2; wire[34] = 3;
    EXPECT(vireo_protocol_header_encode(&h, wire, 32), VIREO_OK);
    EXPECT(vireo_protocol_frame_crc32c_calculate(wire, 32, wire + 32, 3, &h.crc32c), VIREO_OK);
    EXPECT(vireo_protocol_header_encode(&h, wire, 32), VIREO_OK);
}
static void send_receive(fixture_t *fixture, unsigned char const *wire) {
    size_t sent = 0;
    while (sent < 35) { ssize_t n = send(fixture->peer, wire + sent, 35 - sent, MSG_NOSIGNAL); CHECK(n > 0); sent += (size_t)n; }
    vireo_connection_receive_budget_t const budget = {64, 8};
    for (size_t i = 0; i < LIMIT; ++i) {
        vireo_connection_receive_info_t info;
        EXPECT(vireo_tcp_server_client_receive(fixture->server, fixture->client, &budget, &info, NULL), VIREO_OK);
        uint8_t const *bytes; size_t size;
        EXPECT(vireo_tcp_server_client_read_peek(fixture->server, fixture->client, &bytes, &size, NULL), VIREO_OK);
        if (size == 35) { CHECK(!memcmp(bytes, wire, 35)); return; }
        CHECK(size < 35); sched_yield();
    }
    CHECK(false);
}
static void network_input_worker_publish(void) {
    fixture_t fixture; CHECK(setup(&fixture)); basic_t b; setup_basic(&b, true, 1);
    vireo_inflight_store_t *store = NULL; vireo_inflight_store_options_t const so = {4, 65536};
    EXPECT(vireo_inflight_store_create(&so, &store), VIREO_OK);
    vireo_task_queue_t *tasks = NULL; vireo_thread_pool_t *pool = NULL;
    vireo_task_queue_options_t const qo = {1, 65536}; vireo_thread_pool_options_t const po = {1, 65536};
    EXPECT(vireo_task_queue_create(&qo, &tasks), VIREO_OK); EXPECT(vireo_task_queue_prepare_wait(tasks), VIREO_OK);
    EXPECT(vireo_thread_pool_create(&po, &pool), VIREO_OK);
    network_worker_t worker = {.queue = b.queue, .notifier = b.notifier};
    CHECK(pthread_barrier_init(&worker.entered, NULL, 2) == 0 && pthread_barrier_init(&worker.release, NULL, 2) == 0);
    vireo_thread_pool_configuration_t const config = {tasks, execute_network, &worker};
    EXPECT(vireo_thread_pool_configure(pool, &config, NULL), VIREO_OK);
    vireo_thread_pool_report_t pr;
    EXPECT(vireo_thread_pool_start(pool, &pr), VIREO_OK); EXPECT(vireo_thread_pool_enable_execution(pool, &pr), VIREO_OK);
    unsigned char wire[35]; encode_request(wire, 1); send_receive(&fixture, wire);
    vireo_async_request_pending_t pending = {0}; vireo_async_request_head_report_t report;
    vireo_task_t *remaining_task = NULL; bool transferred = false;
    for (size_t i = 0; i < LIMIT; ++i) {
        errno = EDOM;
        vireo_result_t result = vireo_async_request_submit_read_head(fixture.server, fixture.client, store,
            pool, 64, 4096, 4, 9, 0, NULL, &pending, &remaining_task, &report);
        CHECK(errno == EDOM);
        if (report.submit_report.task_transferred) { CHECK(result == VIREO_OK && report.consume_result == VIREO_OK); transferred = true; break; }
        CHECK(result == VIREO_RESULT_BUSY && !report.submit_report.submit_report.record_retained);
        EXPECT(vireo_task_destroy(&remaining_task), VIREO_OK); sched_yield();
    }
    CHECK(transferred && pending.frame_bytes == 0 && remaining_task == NULL);
    meet(&worker.entered);
    vireo_task_metadata_t const original = report.submit_report.metadata;
    uint8_t const *bytes; size_t size;
    EXPECT(vireo_tcp_server_client_read_peek(fixture.server, fixture.client, &bytes, &size, NULL), VIREO_OK); CHECK(size == 0);
    /* 原网络读区已消费；收新帧复用该区，旧task只看独立副本。 */
    encode_request(wire, 2); send_receive(&fixture, wire); meet(&worker.release);
    vireo_completion_t *completion = pop(b.queue); unsigned char const expected[] = {1, 2, 3};
    verify(completion, original, expected, sizeof expected, VIREO_OK, VIREO_STATUS_OK);
    EXPECT(vireo_completion_destroy(&completion), VIREO_OK);
    vireo_task_queue_close_report_t close_report; bool closed = false;
    for (size_t i = 0; i < LIMIT; ++i) {
        vireo_result_t result = vireo_task_queue_close(tasks, VIREO_TASK_QUEUE_DRAIN, &close_report);
        if (result == VIREO_OK) { closed = true; break; } CHECK(result == VIREO_RESULT_BUSY); sched_yield();
    }
    CHECK(closed); vireo_result_t joined = VIREO_RESULT_BUSY;
    for (size_t i = 0; i < LIMIT && joined == VIREO_RESULT_BUSY; ++i) { joined = vireo_thread_pool_stop_and_join(pool, &pr); if (joined == VIREO_RESULT_BUSY) sched_yield(); }
    CHECK(joined == VIREO_OK && worker.result == VIREO_OK && worker.report.completion_transferred && same(worker.report.request_metadata, original));
    vireo_thread_pool_worker_result_t result; EXPECT(vireo_thread_pool_inspect_worker_result(pool, 0, &result), VIREO_OK); CHECK(result.result == VIREO_OK);
    vireo_task_metadata_t taken; EXPECT(vireo_inflight_store_take(store, original, &taken, NULL), VIREO_OK); CHECK(same(taken, original));
    EXPECT(vireo_thread_pool_destroy(&pool), VIREO_OK); EXPECT(vireo_task_queue_destroy(&tasks), VIREO_OK);
    CHECK(pthread_barrier_destroy(&worker.entered) == 0 && pthread_barrier_destroy(&worker.release) == 0);
    EXPECT(vireo_inflight_store_destroy(&store), VIREO_OK); empty(&b, 1); cleanup_basic(&b); CHECK(cleanup(&fixture));
}
static size_t fds(void) {
    DIR *dir = opendir("/proc/self/fd"); CHECK(dir); size_t count = 0; struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) { if (entry->d_name[0] != '.') ++count; }
    CHECK(closedir(dir) == 0); return count;
}
int main(void) {
    int state; CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &state) == 0);
    void (*const cases[])(void) = {independent_copy, empty_response, failed_work, bad_arguments,
      bad_metadata, allocation_boundaries, not_prepared, closed_queue, inspect_failure, metadata_failure,
      create_failure, untransferred_error, transferred_error, notify_failure, dual_failure, already_pending,
      already_consumed, invalid_ops, mpsc_small_capacity, full_then_pop, full_then_close, network_input_worker_publish};
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; ++i) { size_t const before = fds(); cases[i](); CHECK(fds() == before); }
    puts("completion copy publish: 22 groups passed"); return 0;
}
