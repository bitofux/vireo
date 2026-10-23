/* PROJECT : VIREO; FILE : test_directory_list_completion.c; AUTHOR : bitofux;
 * DATE : 2026-10-23; BRIEF : 真队列整页回投、最大响应、逻辑关联与原始事实投影。 */
#define _POSIX_C_SOURCE 200809L
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include "directory_list_bridge_test_support.h"
#include "directory_list_completion_internal.h"
#include "directory_list_task_internal.h"
static vireo_completion_queue_t *queue;
static vireo_notifier_t *notifier;
static vireo_directory_list_task_result_t result, backup;
static vireo_directory_list_completion_outcome_t output, sentinel;
static void publish_status(const vireo_task_t *t, vireo_status_t status) {
    vireo_completion_t *remaining = NULL;
    vireo_directory_list_completion_publish_report_t p;
    CHECK(vireo_directory_list_completion_publish(t, OP, &result, BUDGET, queue, notifier,
                                                  &remaining, &p),
          VIREO_OK);
    assert(!remaining && p.task_matched && p.result_validated && p.publish_called &&
           p.publication.completion_transferred);
    vireo_completion_t *c = pop(queue);
    CHECK(vireo_directory_list_completion_decode(c, OP, &output), VIREO_OK);
    assert(output.response.status == status && output.metadata.result == result.result &&
           output.actor.user_id == 7 && output.request_directory_id == 9 &&
           output.request_page_size == 64 && output.request_session_handle == 13);
    CHECK(vireo_completion_destroy(&c), VIREO_OK);
}
static void rejected(const vireo_task_t *t, vireo_result_t want) {
    vireo_completion_t *remaining = NULL;
    vireo_directory_list_completion_publish_report_t p;
    CHECK(vireo_directory_list_completion_publish(t, OP, &result, BUDGET, queue, notifier,
                                                  &remaining, &p),
          want);
    assert(!remaining && !p.publish_called);
}
static void mutate_input(size_t i) {
    vireo_directory_list_input_t *v = &result.input;
    switch (i) {
        case 0:
            ++v->metadata.route.client_owner_id;
            break;
        case 1:
            ++v->metadata.route.client_slot_index;
            break;
        case 2:
            ++v->metadata.route.client_generation;
            break;
        case 3:
            ++v->metadata.route.request_sequence;
            break;
        case 4:
            ++v->metadata.request_instance_id;
            break;
        case 5:
            ++v->metadata.operation;
            break;
        case 6:
            --v->metadata.deadline_ns;
            break;
        case 7:
            ++v->actor.user_id;
            break;
        case 8:
            ++v->actor.session_id;
            break;
        case 9:
            ++v->request.sequence;
            break;
        case 10:
            ++v->request.session_handle;
            break;
        case 11:
            ++v->request.directory_id;
            break;
        case 12:
            --v->request.page_size;
            break;
        case 13:
            v->request.has_page_token = !v->request.has_page_token;
            break;
        default:
            v->request.page_token[i - 14] ^= 1;
            break;
    }
}
static void malformed_completion(const vireo_task_t *t) {
    vireo_completion_t *remaining = NULL;
    vireo_directory_list_completion_publish_report_t report;
    CHECK(vireo_directory_list_completion_publish(t, OP, &result, BUDGET, queue, notifier,
                                                  &remaining, &report),
          VIREO_OK);
    vireo_completion_t *original = pop(queue);
    vireo_completion_info_t info;
    vireo_completion_payload_view_t view;
    CHECK(vireo_completion_inspect(original, &info), VIREO_OK);
    CHECK(vireo_completion_borrow_payload(original, &view), VIREO_OK);
    unsigned char *data = malloc(view.size + 1);
    assert(data);
    for (size_t i = 0; i < view.size + 50; ++i) {
        size_t size = view.size;
        memcpy(data, view.data, size);
        bool valid_actor = false;
        if (i < 48) {
            data[i] ^= 0x80;
            valid_actor = i >= 8 && i < 24;
        } else if (i == 48) {
            size = view.size + 1;
            data[view.size] = 0;
        } else {
            size = i - 49;
            if (size >= view.size)
                continue;
        }
        vireo_completion_t *bad = NULL;
        CHECK(vireo_completion_create_copy(info.metadata, data, size, BUDGET, &bad), VIREO_OK);
        memset(&output, 0xa5, sizeof(output));
        memcpy(&sentinel, &output, sizeof(output));
        vireo_result_t rc = vireo_directory_list_completion_decode(bad, OP, &output);
        if (valid_actor)
            assert(rc == VIREO_OK); /* 数值身份不是凭据。 */
        else
            assert(rc == VIREO_RESULT_PROTOCOL && !memcmp(&output, &sentinel, sizeof(output)));
        CHECK(vireo_completion_destroy(&bad), VIREO_OK);
    }
    /* 有效CRC并不允许metadata/status、operation或原请求关联错配。 */
    for (size_t i = 0; i < 4; ++i) {
        vireo_completion_metadata_t m = info.metadata;
        if (i == 0)
            ++m.request.route.request_sequence;
        if (i == 1)
            ++m.request.operation;
        if (i == 2)
            m.suggested_status = VIREO_STATUS_BUSY;
        if (i == 3)
            m.result = VIREO_RESULT_TIMEOUT;
        vireo_completion_t *bad = NULL;
        CHECK(vireo_completion_create_copy(m, view.data, view.size, BUDGET, &bad), VIREO_OK);
        CHECK(vireo_directory_list_completion_decode(bad, OP, &output), VIREO_RESULT_PROTOCOL);
        CHECK(vireo_completion_destroy(&bad), VIREO_OK);
    }
    free(data);
    CHECK(vireo_completion_destroy(&original), VIREO_OK);
}
typedef struct alloc_state {
    bool fail;
    size_t allocated, released, calls;
} alloc_state_t;
static void *allocate(void *c, size_t n) {
    alloc_state_t *s = c;
    ++s->calls;
    if (s->fail)
        return NULL;
    assert(n <= 65536);
    s->allocated = n;
    return malloc(n);
}
static void release(void *c, void *p) {
    alloc_state_t *s = c;
    assert(vireo_list_zero(p, s->allocated));
    ++s->released;
    free(p);
}
static vireo_result_t fail_notify(void *c, const vireo_task_t *t, vireo_result_t r,
                                  vireo_status_t s, const void *p, size_t n, size_t budget,
                                  vireo_completion_queue_t *q, vireo_notifier_t *f,
                                  vireo_completion_t **o,
                                  vireo_completion_publish_report_t *report) {
    (void)c;
    vireo_result_t rc = vireo_completion_copy_wait_publish(t, r, s, p, n, budget, q, f, o, report);
    assert(rc == VIREO_OK && report->completion_transferred && !*o);
    report->notify_result = VIREO_RESULT_IO;
    report->stage = VIREO_COMPLETION_PUBLISH_NOTIFY;
    return VIREO_RESULT_IO;
}
typedef struct blocked_producer {
    const vireo_task_t *task;
    atomic_bool entered, done;
    vireo_result_t rc;
    vireo_completion_t *remaining;
    vireo_directory_list_completion_publish_report_t report;
} blocked_producer_t;
static void *produce(void *c) {
    blocked_producer_t *p = c;
    int old_state;
    assert(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &old_state) == 0);
    atomic_store(&p->entered, true);
    p->rc = vireo_directory_list_completion_publish(p->task, OP, &result, BUDGET, queue, notifier,
                                                    &p->remaining, &p->report);
    atomic_store(&p->done, true);
    assert(pthread_setcancelstate(old_state, NULL) == 0);
    return NULL;
}
/* 只对公开try-lock的无交接竞争重试；关闭成功后不重放。 */
static void close_channel(void) {
    uint64_t start, now;
    CHECK(vireo_clock_monotonic_now(&start, NULL), VIREO_OK);
    for (;;) {
        vireo_completion_queue_close_report_t report;
        vireo_result_t rc = vireo_completion_queue_close(queue, &report);
        if (rc == VIREO_OK)
            return;
        assert(rc == VIREO_RESULT_BUSY && !report.changed &&
               report.stage == VIREO_COMPLETION_QUEUE_CLOSE_LOCK && report.pthread_error == EBUSY);
        CHECK(vireo_clock_monotonic_now(&now, NULL), VIREO_OK);
        assert(now - start < UINT64_C(5000000000));
        sched_yield();
    }
}
int main(void) {
    int old_state;
    assert(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &old_state) == 0);
    make_channels(1, &queue, &notifier);
    vireo_task_t *t = make_task(1, false, NULL), *token_task = make_task(2, true, NULL);
    make_page_result(t, 64, true, &result);
    publish_status(t, VIREO_STATUS_OK);
    assert(output.response.count == 64 && output.response.has_more &&
           output.response.entries[63].name_length == 255 &&
           output.response.entries[63].size == UINT64_MAX);
    /* 最大wire23510与内部23558实际发生；预算不能沿用ROOT的4096。 */
    vireo_completion_t *remaining = NULL;
    vireo_directory_list_completion_publish_report_t report;
    CHECK(vireo_directory_list_completion_publish(t, OP, &result, 4096, queue, notifier, &remaining,
                                                  &report),
          VIREO_RESULT_RANGE);
    CHECK(vireo_directory_list_completion_publish(t, OP, &result, BUDGET, queue, notifier,
                                                  &remaining, &report),
          VIREO_OK);
    vireo_completion_t *c = pop(queue);
    vireo_completion_info_t info;
    CHECK(vireo_completion_inspect(c, &info), VIREO_OK);
    assert(info.payload_size == 23558 && info.allocated_bytes > info.payload_size &&
           info.allocated_bytes <= 32768);
    CHECK(vireo_completion_destroy(&c), VIREO_OK);
    printf("maximum completion payload=%zu allocation=%zu\n", info.payload_size,
           info.allocated_bytes);
    make_page_result(t, 2, false, &result);
    result.service.page.nodes[0].kind = VIREO_MYSQL_NODE_DIRECTORY;
    result.service.page.nodes[0].has_object_hash = false;
    result.service.page.nodes[0].size = 0;
    result.service.page.nodes[1].name_length = 1;
    memset(result.service.page.nodes[1].name + 1, 0xee, 254);
    memset(&result.service.page.nodes[2], 0xa5, sizeof(result.service.page.nodes[2]));
    publish_status(t, VIREO_STATUS_OK);
    assert(output.response.entries[1].name[1] == 0 && output.response.entries[2].node_id == 0);
    make_page_result(t, 2, false, &result);
    backup = result;
    for (size_t i = 0; i < 21; ++i) {
        result = backup;
        vireo_mysql_node_value_t *v = &result.service.page.nodes[0];
        switch (i) {
            case 0:
                result.service.page.count = 65;
                break;
            case 1:
                ++v->owner_id;
                break;
            case 2:
                ++v->parent_id;
                break;
            case 3:
                v->has_parent = false;
                break;
            case 4:
                v->id = 9;
                break;
            case 5:
                v->id = 0;
                break;
            case 6:
                v->id = 102;
                break;
            case 7:
                v->name_length = 0;
                break;
            case 8:
                v->name_length = 256;
                break;
            case 9:
                v->name[0] = 0;
                break;
            case 10:
                v->name[0] = '/';
                break;
            case 11:
                v->name_length = 1;
                v->name[0] = '.';
                break;
            case 12:
                v->name_length = 2;
                v->name[0] = '.';
                v->name[1] = '.';
                break;
            case 13:
                v->updated_at_ms = 0;
                break;
            case 14:
                v->kind = VIREO_MYSQL_NODE_DIRECTORY;
                break;
            case 15:
                v->kind = (vireo_mysql_node_kind_t)3;
                break;
            case 16:
                v->has_object_hash = false;
                break;
            case 17:
                result.service.page.next_after_id = 100;
                break;
            case 18:
                result.service.page.has_more = true;
                result.service.page.next_after_id = 101;
                break;
            case 19:
                result.service.next_page_token.bytes[0] = 1;
                break;
            default:
                result.service.outcome = VIREO_DIRECTORY_LIST_NONE;
                result.result = VIREO_RESULT_DATABASE;
                break;
        }
        rejected(t, VIREO_RESULT_INVALID_ARGUMENT);
    }
    make_page_result(token_task, 0, false, &result);
    backup = result;
    for (size_t i = 0; i < 110; ++i) {
        result = backup;
        mutate_input(i);
        rejected(token_task, VIREO_RESULT_PROTOCOL);
    }
    result = backup;
    for (size_t i = 0; i < 16; ++i) {
        result = backup;
        switch (i) {
            case 0:
                result.result = VIREO_RESULT_DATABASE;
                break;
            case 1:
                result.service.repository.found = false;
                break;
            case 2:
                result.service.repository.rollback_confirmed = false;
                break;
            case 3:
                result.service.repository.cleanup_pending = true;
                break;
            case 4:
                result.error.repository.cleanup_result = VIREO_RESULT_IO;
                break;
            case 5:
                result.service.repository_operation = VIREO_DIRECTORY_LIST_REPOSITORY_AUTH_PROBE;
                break;
            case 6:
                result.service.token_result = VIREO_RESULT_PROTOCOL;
                break;
            case 7:
                result.service.token_checked = false;
                break;
            case 8:
                result.stage = (vireo_directory_list_task_stage_t)99;
                break;
            case 9:
                result.service.outcome = (vireo_directory_list_outcome_t)99;
                break;
            case 10:
                result.result = (vireo_result_t)99;
                break;
            case 11:
                result.error.stage = (vireo_directory_list_stage_t)99;
                break;
            case 12:
                result.service.repository_result = (vireo_result_t)99;
                break;
            case 13:
                result.service.token_result = (vireo_result_t)99;
                break;
            case 14:
                result.service.repository.issue = (vireo_mysql_node_issue_t)99;
                break;
            default:
                result.request_issue = VIREO_NODE_LIST_ISSUE_VALUE;
                break;
        }
        rejected(token_task, VIREO_RESULT_INVALID_ARGUMENT);
    }
    /* 完整service错误投影：身份优先、坏token初验/后续时间复核两来源。 */
    for (size_t i = 0; i < 5; ++i) {
        result = backup;
        result.service.outcome = VIREO_DIRECTORY_LIST_UNAUTHORIZED;
        result.result = VIREO_RESULT_NOT_FOUND;
        result.service.repository_result = VIREO_RESULT_NOT_FOUND;
        result.service.repository.found = false;
        result.service.repository.issue = VIREO_MYSQL_NODE_AUTH_REJECTED;
        vireo_status_t status = VIREO_STATUS_UNAUTHORIZED;
        if (i == 1) {
            result.service.outcome = VIREO_DIRECTORY_LIST_NOT_FOUND;
            result.service.repository.issue = VIREO_MYSQL_NODE_NOT_FOUND;
            status = VIREO_STATUS_NOT_FOUND;
        }
        if (i >= 2) {
            result.result = VIREO_RESULT_PROTOCOL;
            result.service.outcome = VIREO_DIRECTORY_LIST_BAD_TOKEN;
            status = VIREO_STATUS_BAD_REQUEST;
            if (i < 4) {
                result.service.token_result = VIREO_RESULT_PROTOCOL;
                result.service.repository_operation = VIREO_DIRECTORY_LIST_REPOSITORY_AUTH_PROBE;
                result.service.repository.issue = VIREO_MYSQL_NODE_NOT_FOUND;
                if (i == 2) {
                    result.service.repository_result = VIREO_OK;
                    result.service.repository.found = true;
                    result.service.repository.issue = 0;
                }
            } else {
                result.service.repository_result = VIREO_OK;
                result.service.repository.found = true;
                result.service.repository.issue = 0;
                result.error.stage = VIREO_DIRECTORY_LIST_STAGE_TOKEN_REVALIDATE;
            }
        }
        publish_status(token_task, status);
    }
    for (unsigned rc = 1; rc <= (unsigned)VIREO_RESULT_INTERNAL; ++rc) {
        memset(&result, 0, sizeof(result));
        result.input = backup.input;
        result.stage = VIREO_DIRECTORY_LIST_TASK_CONTEXT;
        result.result = (vireo_result_t)rc;
        vireo_status_t status = VIREO_STATUS_INTERNAL_ERROR;
        if (rc == VIREO_RESULT_BUSY)
            status = VIREO_STATUS_BUSY;
        if (rc == VIREO_RESULT_TIMEOUT)
            status = VIREO_STATUS_TIMEOUT;
        if (rc == VIREO_RESULT_CANCELLED)
            status = VIREO_STATUS_UNAVAILABLE;
        if (rc == VIREO_RESULT_NO_MEMORY)
            status = VIREO_STATUS_OVERLOADED;
        publish_status(token_task, status);
    }
    result = backup;
    result.service.outcome = VIREO_DIRECTORY_LIST_NONE;
    result.result = VIREO_RESULT_DATABASE;
    result.service.repository.cleanup_pending = true;
    result.error.repository.cleanup_result = VIREO_RESULT_DATABASE;
    publish_status(token_task, VIREO_STATUS_INTERNAL_ERROR);
    make_page_result(t, 0, false, &result);
    malformed_completion(t);
    alloc_state_t allocation = {.fail = true};
    const vireo_directory_list_completion_ops_t ops = {&allocation, allocate, release, fail_notify};
    CHECK(vireo_directory_list_completion_publish_with(t, OP, &result, BUDGET, queue, notifier,
                                                       &remaining, &report, &ops),
          VIREO_RESULT_NO_MEMORY);
    assert(!report.publish_called && !allocation.released);
    allocation.fail = false;
    CHECK(vireo_directory_list_completion_publish_with(t, OP, &result, BUDGET, queue, notifier,
                                                       &remaining, &report, &ops),
          VIREO_RESULT_IO);
    assert(!remaining && report.publication.completion_transferred && allocation.released == 1);
    printf("publication workspace=%zu; response=%zu; decoded outcome=%zu\n", allocation.allocated,
           sizeof(vireo_node_list_response_t), sizeof(vireo_directory_list_completion_outcome_t));
    c = pop(queue);
    CHECK(vireo_completion_destroy(&c), VIREO_OK);
    /* 满队列的producer在consumer腾空间后交接；关闭则保留未交接owner。 */
    for (size_t close = 0; close < 2; ++close) {
        CHECK(vireo_directory_list_completion_publish(t, OP, &result, BUDGET, queue, notifier,
                                                      &remaining, &report),
              VIREO_OK);
        blocked_producer_t producer = {.task = t};
        atomic_init(&producer.entered, false);
        atomic_init(&producer.done, false);
        pthread_t thread;
        assert(pthread_create(&thread, NULL, produce, &producer) == 0);
        while (!atomic_load(&producer.entered))
            sched_yield();
        if (close)
            close_channel();
        c = pop(queue);
        CHECK(vireo_completion_destroy(&c), VIREO_OK);
        assert(pthread_join(thread, NULL) == 0 && atomic_load(&producer.done));
        if (close) {
            assert(producer.rc == VIREO_RESULT_CANCELLED && producer.remaining);
            CHECK(vireo_completion_destroy(&producer.remaining), VIREO_OK);
        } else {
            assert(producer.rc == VIREO_OK && !producer.remaining);
            c = pop(queue);
            CHECK(vireo_completion_destroy(&c), VIREO_OK);
        }
    }
    CHECK(vireo_task_destroy(&t), VIREO_OK);
    CHECK(vireo_task_destroy(&token_task), VIREO_OK);
    destroy_channels(&queue, &notifier);
    assert(pthread_setcancelstate(old_state, NULL) == 0);
    printf(
        "PASS %zu LIST completion checks; max page, association, errors, strict decode, "
        "queue/owner\n",
        checks);
    return 0;
}
