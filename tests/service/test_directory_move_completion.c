/* PROJECT : VIREO; FILE : test_directory_move_completion.c; AUTHOR : bitofux;
 * DATE : 2026-10-25; BRIEF : 固定字节、写关系、完整关联与真实完成队列交接。 */
#include <pthread.h>
#include "directory_move_bridge_relations.h"
#include "directory_move_bridge_test_support.h"
#include "directory_move_bridge_test_vectors.h"
#include "directory_move_completion_internal.h"
static vireo_completion_t *copy(const unsigned char *bytes, size_t size, vireo_result_t rc,
                                vireo_status_t status, vireo_task_metadata_t m) {
    vireo_completion_metadata_t cm;
    CHECK(vireo_completion_metadata_make(m, rc, status, &cm), VIREO_OK);
    vireo_completion_t *c = NULL;
    CHECK(vireo_completion_create_copy(cm, bytes, size, 4096, &c), VIREO_OK);
    return c;
}
static void decode_check(vireo_completion_t **c, bool valid) {
    vireo_directory_move_completion_outcome_t out, old;
    memset(&out, 0xa5, sizeof(out));
    memcpy(&old, &out, sizeof(out));
    CHECK(vireo_directory_move_completion_decode(*c, 400, &out),
          valid ? VIREO_OK : VIREO_RESULT_PROTOCOL);
    if (!valid)
        assert(!memcmp(&out, &old, sizeof(out)));
    else
        assert(out.actor.user_id && out.actor.session_id && out.request_session_handle &&
               !memcmp(out.request_idempotency_key, test_key, 16));
    CHECK(vireo_completion_destroy(c), VIREO_OK);
}
/* Declarative decoder allowance, independent of the service projector. */
static bool allowed(int rc, vireo_status_t status) {
    static const vireo_status_t pairs[13][4] = {
        {VIREO_STATUS_OK},
        {VIREO_STATUS_INTERNAL_ERROR},
        {VIREO_STATUS_CONFLICT, VIREO_STATUS_INTERNAL_ERROR},
        {VIREO_STATUS_INTERNAL_ERROR},
        {VIREO_STATUS_OVERLOADED, VIREO_STATUS_INTERNAL_ERROR},
        {VIREO_STATUS_UNAUTHORIZED, VIREO_STATUS_NOT_FOUND, VIREO_STATUS_INTERNAL_ERROR},
        {VIREO_STATUS_BUSY, VIREO_STATUS_INTERNAL_ERROR},
        {VIREO_STATUS_TIMEOUT, VIREO_STATUS_INTERNAL_ERROR},
        {VIREO_STATUS_UNAVAILABLE, VIREO_STATUS_INTERNAL_ERROR},
        {VIREO_STATUS_INTERNAL_ERROR},
        {VIREO_STATUS_INVALID_PATH, VIREO_STATUS_INTERNAL_ERROR},
        {VIREO_STATUS_FORBIDDEN, VIREO_STATUS_CONFLICT, VIREO_STATUS_DB_ERROR,
         VIREO_STATUS_INTERNAL_ERROR},
        {VIREO_STATUS_INTERNAL_ERROR}};
    for (size_t i = 0; i < 4; ++i)
        if (pairs[rc][i] == status && (i == 0 || pairs[rc][i] != 0))
            return true;
    return false;
}
static void vectors(void) {
    for (size_t i = 4; i < sizeof(bridge_vectors) / sizeof(bridge_vectors[0]); ++i) {
        const bridge_vector_t *v = &bridge_vectors[i];
        assert(!v->task);
        vireo_status_t status = (vireo_status_t)(((unsigned)v->bytes[66] << 8) | v->bytes[67]);
        int selected = status == VIREO_STATUS_OK             ? 0
                       : status == VIREO_STATUS_INVALID_PATH ? 10
                       : status == VIREO_STATUS_UNAUTHORIZED || status == VIREO_STATUS_NOT_FOUND ? 5
                       : status == VIREO_STATUS_FORBIDDEN || status == VIREO_STATUS_CONFLICT ||
                               status == VIREO_STATUS_DB_ERROR
                           ? 11
                       : status == VIREO_STATUS_BUSY        ? 6
                       : status == VIREO_STATUS_TIMEOUT     ? 7
                       : status == VIREO_STATUS_UNAVAILABLE ? 8
                       : status == VIREO_STATUS_OVERLOADED  ? 4
                                                            : 9;
        vireo_completion_t *c =
            copy(v->bytes, v->size, (vireo_result_t)selected, status, metadata());
        decode_check(&c, allowed(selected, status));
        for (size_t n = 0; n < v->size; ++n) {
            c = copy(v->bytes, n, (vireo_result_t)selected, status, metadata());
            decode_check(&c, false);
        }
        for (int rc = 0; rc <= 12; ++rc) {
            c = copy(v->bytes, v->size, (vireo_result_t)rc, status, metadata());
            decode_check(&c, allowed(rc, status));
        }
    }
    const bridge_vector_t *v = &bridge_vectors[4];
    for (unsigned k = 0; k < 14; ++k) {
        unsigned char bytes[121] = {0};
        memcpy(bytes, v->bytes, v->size);
        vireo_task_metadata_t m = metadata();
        size_t n = v->size;
        switch (k) {
            case 0:
                bytes[0] ^= 1;
                break;
            case 1:
                bytes[4] = 1;
                break;
            case 2:
                memset(bytes + 8, 0, 8);
                break;
            case 3:
                memset(bytes + 16, 0, 8);
                break;
            case 4:
                memset(bytes + 24, 0, 4);
                break;
            case 5:
                put32_test(bytes + 28, 0xffffffff);
                break;
            case 6:
                memset(bytes + 40, 0, 16);
                break;
            case 7:
                bytes[40] ^= 1;
                break;
            case 8:
                bytes[87] ^= 1;
                break;
            case 9:
                ++m.operation;
                break;
            case 10:
                ++m.route.request_sequence;
                break;
            case 11:
                memset(bytes + 32, 0, 8);
                break;
            case 12:
                bytes[39] ^= 1;
                break;
            default:
                n = 121;
                break;
        }
        vireo_completion_t *c = copy(bytes, n, VIREO_OK, VIREO_STATUS_OK, m);
        decode_check(&c, false);
    }
}
static vireo_status_t publish_decode(vireo_task_t *t, const vireo_directory_move_task_result_t *r,
                                     vireo_completion_queue_t *q, vireo_notifier_t *n) {
    vireo_completion_t *left = NULL;
    vireo_directory_move_completion_publish_report_t p;
    CHECK(vireo_directory_move_completion_publish(t, 400, r, 4096, q, n, &left, &p), VIREO_OK);
    assert(!left && p.task_matched && p.result_validated && p.publish_called &&
           p.publication.completion_transferred);
    vireo_completion_t *c = pop(q);
    vireo_directory_move_completion_outcome_t out;
    CHECK(vireo_directory_move_completion_decode(c, 400, &out), VIREO_OK);
    assert(out.metadata.result == r->result && out.response.sequence == 11 &&
           out.actor.user_id == 7 && out.actor.session_id == 51);
    assert(!memcmp(out.request_idempotency_key, test_key, 16));
    if (out.response.status == VIREO_STATUS_OK)
        assert(out.response.node_id == 123 && !memcmp(out.response.idempotency_key, test_key, 16));
    else
        assert(!out.response.node_id && !out.response.session_handle);
    CHECK(vireo_completion_destroy(&c), VIREO_OK);
    return out.response.status;
}
static void projection(void) {
    vireo_completion_queue_t *q = NULL;
    vireo_notifier_t *n = NULL;
    queue_setup(&q, &n, true);
    vireo_task_t *t = make_task(100, NULL);
    for (size_t i = 0; i < sizeof(relations) / sizeof(relations[0]); ++i) {
        const relation_t *v = &relations[i];
        vireo_directory_move_task_result_t r = found_result(t);
        r.result = v->rc;
        r.error.cleanup_result = v->cleanup;
        r.error.cleanup_stage = v->cleanup_stage;
        r.service = v->service;
        if (v->status >= 0) {
            vireo_status_t got = publish_decode(t, &r, q, n);
            if (got != (vireo_status_t)v->status) {
                fprintf(stderr, "relation %s wrong status\n", v->name);
                abort();
            }
        } else {
            vireo_completion_t *left = NULL;
            vireo_directory_move_completion_publish_report_t p;
            CHECK(vireo_directory_move_completion_publish(t, 400, &r, 4096, q, n, &left, &p),
                  VIREO_RESULT_INVALID_ARGUMENT);
            assert(p.task_matched && !p.result_validated && !p.publish_called && !left);
            empty(q);
        }
    }
    for (unsigned k = 0; k < 15; ++k) {
        vireo_directory_move_task_result_t r = found_result(t);
        switch (k) {
            case 0:
                ++r.input.metadata.route.client_owner_id;
                break;
            case 1:
                ++r.input.metadata.route.client_slot_index;
                break;
            case 2:
                ++r.input.metadata.route.client_generation;
                break;
            case 3:
                ++r.input.metadata.route.request_sequence;
                break;
            case 4:
                ++r.input.metadata.request_instance_id;
                break;
            case 5:
                ++r.input.metadata.operation;
                break;
            case 6:
                ++r.input.metadata.deadline_ns;
                break;
            case 7:
                ++r.input.actor.user_id;
                break;
            case 8:
                ++r.input.actor.session_id;
                break;
            case 9:
                ++r.input.request.sequence;
                break;
            case 10:
                ++r.input.request.session_handle;
                break;
            case 11:
                ++r.input.request.new_parent_id;
                break;
            case 12:
                r.input.request.new_name[0] ^= 1;
                break;
            case 13:
                ++r.input.request.node_id;
                break;
            default:
                r.input.request.idempotency_key[15] ^= 1;
                break;
        }
        vireo_completion_t *left = NULL;
        vireo_directory_move_completion_publish_report_t p;
        CHECK(vireo_directory_move_completion_publish(t, 400, &r, 4096, q, n, &left, &p),
              VIREO_RESULT_PROTOCOL);
        assert(!p.task_matched && !left);
    }
    vireo_directory_move_task_result_t r = found_result(t);
    r.input.request.new_name[254] = 0xff;
    assert(publish_decode(t, &r, q, n) == VIREO_STATUS_OK); /* Unused bytes are not identity. */
    for (int stage = 0; stage <= 7; ++stage)
        for (int rc = 0; rc <= 12; ++rc) {
            r = found_result(t);
            r.service = (vireo_directory_move_result_t){0};
            r.stage = (vireo_directory_move_task_stage_t)stage;
            r.result = (vireo_result_t)rc;
            if (stage == 1 || stage == 4)
                memset(r.request_id, 0, 16);
            bool valid = (stage == 1 && rc != 0) || (stage == 4 && rc == 9) ||
                         (stage == 5 && rc == 8) || (stage == 6 && rc == 7);
            if (valid)
                (void)publish_decode(t, &r, q, n);
            else {
                vireo_completion_t *left = NULL;
                vireo_directory_move_completion_publish_report_t p;
                /* SERVICE/NONE permits no-repository name-validation technical errors. */
                if (stage == 7 && (rc == 4 || rc == 3 || rc == 12)) {
                    (void)publish_decode(t, &r, q, n);
                    continue;
                }
                CHECK(vireo_directory_move_completion_publish(t, 400, &r, 4096, q, n, &left, &p),
                      VIREO_RESULT_INVALID_ARGUMENT);
                assert(!left && !p.publish_called);
            }
        }
    /* Raw source/key corruption must be rejected, even if both success copies agree. */
    for (unsigned k = 0; k < 13; ++k) {
        r = found_result(t);
        if (k == 0) {
            ++r.service.node_id;
            ++r.service.repository.node_id;
        }
        if (k == 1) {
            r.service.idempotency_key[15] ^= 1;
            r.service.repository.idempotency_key[15] ^= 1;
        }
        if (k == 2)
            r.service.outcome = (vireo_directory_move_outcome_t)99;
        if (k == 3)
            r.service.repository.commit = (vireo_mysql_node_move_commit_t)99;
        if (k == 4)
            r.service.repository.effect = (vireo_mysql_node_move_effect_t)99;
        if (k == 5)
            r.service.repository.issue = (vireo_mysql_node_issue_t)99;
        if (k == 6)
            r.result = (vireo_result_t)99;
        if (k == 7)
            r.input.request.new_name_length = 256;
        if (k == 8)
            r.error.cleanup_result = (vireo_result_t)99;
        if (k == 9)
            r.error.cleanup_stage = (vireo_mysql_node_stage_t)99;
        if (k == 10)
            r.error.database.stage = (vireo_mysql_stage_t)99;
        if (k == 11)
            r.error.pool.stage = (vireo_mysql_pool_stage_t)99;
        if (k == 12) {
            r.result = VIREO_RESULT_IO;
            r.service.outcome = VIREO_DIRECTORY_MOVE_NONE;
            r.service.node_id = 0;
            memset(r.service.idempotency_key, 0, 16);
            r.service.repository.commit = VIREO_MYSQL_NODE_MOVE_NOT_COMMITTED;
            r.service.repository.effect = VIREO_MYSQL_NODE_MOVE_EFFECT_RECOVERED;
            r.error.cleanup_result = VIREO_RESULT_IO;
            r.error.cleanup_stage = VIREO_MYSQL_NODE_STAGE_RELEASE;
        }
        vireo_completion_t *pending = NULL;
        vireo_directory_move_completion_publish_report_t bad;
        CHECK(vireo_directory_move_completion_publish(t, 400, &r, 4096, q, n, &pending, &bad),
              k == 7 ? VIREO_RESULT_PROTOCOL : VIREO_RESULT_INVALID_ARGUMENT);
        assert(!pending && !bad.publish_called);
        empty(q);
    }
    r = found_result(t);
    vireo_completion_t *left = NULL;
    vireo_directory_move_completion_publish_report_t p;
    CHECK(vireo_directory_move_completion_publish(t, 400, &r, 1, q, n, &left, &p),
          VIREO_RESULT_RANGE);
    assert(!left);
    vireo_completion_queue_close_report_t closed;
    CHECK(vireo_completion_queue_close(q, &closed), VIREO_OK);
    CHECK(vireo_directory_move_completion_publish(t, 400, &r, 4096, q, n, &left, &p),
          VIREO_RESULT_CANCELLED);
    assert(left && !p.publication.completion_transferred);
    CHECK(vireo_task_destroy(&t), VIREO_OK);
    decode_check(&left, true);
    queue_teardown(&q, &n);
}
/* 注入公开publisher在真实转交后报告通知故障，验证上层保留已交接事实。 */
static vireo_result_t notify_fail(const vireo_task_t *t, vireo_result_t rc, vireo_status_t status,
                                  const void *data, size_t size, size_t budget,
                                  vireo_completion_queue_t *q, vireo_notifier_t *n,
                                  vireo_completion_t **left, vireo_completion_publish_report_t *p) {
    vireo_result_t got =
        vireo_completion_copy_wait_publish(t, rc, status, data, size, budget, q, n, left, p);
    assert(got == VIREO_OK);
    vireo_completion_t *consumed = pop(q);
    decode_check(&consumed, true);
    p->notify_result = VIREO_RESULT_IO;
    p->stage = VIREO_COMPLETION_PUBLISH_NOTIFY;
    errno = EIO;
    return VIREO_RESULT_IO;
}
static void transfer(void) {
    vireo_completion_queue_t *q = NULL;
    vireo_notifier_t *n = NULL;
    queue_setup(&q, &n, true);
    vireo_task_t *t = make_task(100, NULL);
    vireo_directory_move_task_result_t r = found_result(t);
    vireo_completion_t *left = NULL;
    vireo_directory_move_completion_publish_report_t p;
    CHECK(vireo_directory_move_completion_publish_with(t, 400, &r, 4096, q, n, &left, &p,
                                                       notify_fail),
          VIREO_RESULT_IO);
    assert(!left && p.publication.completion_transferred && !p.publication.completion_retained);
    CHECK(vireo_task_destroy(&t), VIREO_OK);
    memset(&r, 0, sizeof(r));
    empty(q);
    queue_teardown(&q, &n);
}
/* 队列已满后启动producer，consumer腾空间后再join，不依赖固定sleep。 */
typedef struct producer {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    bool entered;
    vireo_task_t *task;
    vireo_directory_move_task_result_t result;
    vireo_completion_queue_t *queue;
    vireo_notifier_t *notifier;
} producer_t;
static void *produce(void *context) {
    producer_t *p = context;
    int old = 0;
    assert(!pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &old));
    assert(!pthread_mutex_lock(&p->mutex));
    p->entered = true;
    assert(!pthread_cond_signal(&p->cond));
    assert(!pthread_mutex_unlock(&p->mutex));
    vireo_completion_t *left = NULL;
    vireo_directory_move_completion_publish_report_t report;
    CHECK(vireo_directory_move_completion_publish(p->task, 400, &p->result, 4096, p->queue,
                                                  p->notifier, &left, &report),
          VIREO_OK);
    assert(!left && report.publication.completion_transferred);
    return NULL;
}
static vireo_result_t no_memory(const vireo_task_t *t, vireo_result_t rc, vireo_status_t status,
                                const void *data, size_t size, size_t budget,
                                vireo_completion_queue_t *q, vireo_notifier_t *n,
                                vireo_completion_t **left, vireo_completion_publish_report_t *p) {
    (void)t;
    (void)rc;
    (void)status;
    (void)data;
    (void)size;
    (void)budget;
    (void)q;
    (void)n;
    assert(!*left);
    p->stage = VIREO_COMPLETION_PUBLISH_CREATE_COMPLETION;
    errno = ENOMEM;
    return VIREO_RESULT_NO_MEMORY;
}
static void pressure(void) {
    producer_t p = {.mutex = PTHREAD_MUTEX_INITIALIZER, .cond = PTHREAD_COND_INITIALIZER};
    queue_setup(&p.queue, &p.notifier, true);
    p.task = make_task(100, NULL);
    p.result = found_result(p.task);
    vireo_completion_t *left = NULL;
    vireo_directory_move_completion_publish_report_t report;
    CHECK(vireo_directory_move_completion_publish_with(p.task, 400, &p.result, 4096, p.queue,
                                                       p.notifier, &left, &report, no_memory),
          VIREO_RESULT_NO_MEMORY);
    assert(!left && report.result_validated && report.publish_called &&
           !report.publication.completion_created);
    empty(p.queue);
    const bridge_vector_t *g = &bridge_vectors[4];
    assert(!g->task && g->size == 120);
    vireo_task_metadata_t md = metadata();
    md.request_instance_id = 8;
    vireo_completion_t *first = copy(g->bytes, g->size, VIREO_OK, VIREO_STATUS_OK, md);
    vireo_completion_queue_transfer_report_t moved;
    CHECK(vireo_completion_queue_try_push(p.queue, &first, &moved), VIREO_OK);
    assert(!first && moved.transferred);
    pthread_t thread;
    assert(!pthread_create(&thread, NULL, produce, &p));
    assert(!pthread_mutex_lock(&p.mutex));
    while (!p.entered)
        assert(!pthread_cond_wait(&p.cond, &p.mutex));
    assert(!pthread_mutex_unlock(&p.mutex));
    vireo_result_t rc;
    do {
        rc = vireo_completion_queue_try_pop(p.queue, &first, &moved);
    } while (rc == VIREO_RESULT_BUSY);
    assert(rc == VIREO_OK && first && moved.transferred);
    CHECK(vireo_completion_destroy(&first), VIREO_OK);
    assert(!pthread_join(thread, NULL));
    vireo_completion_t *c = pop(p.queue);
    decode_check(&c, true);
    CHECK(vireo_task_destroy(&p.task), VIREO_OK);
    queue_teardown(&p.queue, &p.notifier);
    assert(!pthread_cond_destroy(&p.cond));
    assert(!pthread_mutex_destroy(&p.mutex));
}
int main(void) {
    int old = 0;
    assert(!pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &old));
    vectors();
    projection();
    transfer();
    pressure();
    printf(
        "PASS directory_move_completion: %zu checks; 406 relations, independent MVC1, all identity "
        "fields, 247 rc/status pairs, queue pressure and transfer\n",
        checks);
    return 0;
}
