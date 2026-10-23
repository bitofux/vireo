/* PROJECT : VIREO; FILE : directory_list_bridge_test_support.h; AUTHOR : bitofux;
 * DATE : 2026-10-23; BRIEF : LIST桥接测试的公开对象/原请求构造。 */
#ifndef VIREO_TEST_DIRECTORY_LIST_BRIDGE_SUPPORT_H
#define VIREO_TEST_DIRECTORY_LIST_BRIDGE_SUPPORT_H
#include <assert.h>
#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vireo/service/directory_list_worker.h>
static size_t checks;
#define CHECK(call, want)                                                                       \
    do {                                                                                        \
        errno = EDOM;                                                                           \
        vireo_result_t actual_ = (call);                                                        \
        if (actual_ != (want) || errno != EDOM) {                                               \
            fprintf(stderr, "line %d actual=%d expected=%d errno=%d\n", __LINE__, (int)actual_, \
                    (int)(want), errno);                                                        \
            abort();                                                                            \
        }                                                                                       \
        ++checks;                                                                               \
    } while (0)
#define OP UINT32_C(4407)
#define BUDGET ((size_t)65536)
static inline vireo_task_metadata_t metadata(uint32_t seq) {
    vireo_task_metadata_t m;
    vireo_task_route_t route = {11, 0, 12, seq};
    CHECK(vireo_task_metadata_make(route, seq, OP, UINT64_MAX, &m), VIREO_OK);
    return m;
}
static inline vireo_task_t *make_task(uint32_t seq, bool token, vireo_task_cancel_t *cancel) {
    vireo_node_list_request_t request = {.sequence = seq,
                                         .session_handle = 13,
                                         .directory_id = 9,
                                         .page_size = 64,
                                         .has_page_token = token};
    if (token)
        memset(request.page_token, 0x77, sizeof(request.page_token));
    unsigned char wire[150];
    size_t size = 0;
    CHECK(vireo_node_list_request_encode(&request, wire, sizeof(wire), &size), VIREO_OK);
    const vireo_mysql_node_actor_t actor = {7, 8};
    vireo_task_t *t = NULL;
    CHECK(
        vireo_directory_list_task_create(metadata(seq), OP, wire, size, &actor, BUDGET, cancel, &t),
        VIREO_OK);
    memset(wire, 0xcc, sizeof(wire));
    return t;
}
static inline void make_page_result(const vireo_task_t *t, size_t count, bool more,
                                    vireo_directory_list_task_result_t *r) {
    memset(r, 0, sizeof(*r));
    vireo_node_list_issue_t issue;
    CHECK(vireo_directory_list_task_read(t, OP, &r->input, &issue), VIREO_OK);
    r->stage = VIREO_DIRECTORY_LIST_TASK_SERVICE;
    r->service.outcome = VIREO_DIRECTORY_LIST_PAGE;
    r->service.repository_operation = VIREO_DIRECTORY_LIST_REPOSITORY_CHILDREN;
    r->service.repository.found = true;
    r->service.repository.rollback_confirmed = true;
    r->service.token_checked = r->input.request.has_page_token;
    r->service.page.count = count;
    r->service.page.has_more = more;
    for (size_t i = 0; i < count; ++i) {
        vireo_mysql_node_value_t *v = &r->service.page.nodes[i];
        v->id = 100 + i;
        v->owner_id = 7;
        v->parent_id = 9;
        v->has_parent = true;
        v->name_length = 255;
        memset(v->name, (int)('a' + (i % 26)), sizeof(v->name));
        v->kind = VIREO_MYSQL_NODE_FILE;
        v->has_object_hash = true;
        memset(v->object_hash, (int)i, 32);
        v->size = UINT64_MAX;
        v->created_at_ms = 1000;
        v->updated_at_ms = 1001;
    }
    if (more) {
        assert(count);
        r->service.page.next_after_id = r->service.page.nodes[count - 1].id;
        memset(r->service.next_page_token.bytes, 0xa7, 96);
    }
}
static inline void make_channels(size_t capacity, vireo_completion_queue_t **q,
                                 vireo_notifier_t **n) {
    const vireo_completion_queue_options_t qo = {capacity, BUDGET};
    const vireo_notifier_options_t no = {BUDGET};
    CHECK(vireo_completion_queue_create(&qo, q), VIREO_OK);
    CHECK(vireo_completion_queue_prepare_wait(*q), VIREO_OK);
    CHECK(vireo_notifier_create(&no, n, NULL), VIREO_OK);
}
static inline vireo_completion_t *pop(vireo_completion_queue_t *q) {
    vireo_completion_t *c = NULL;
    vireo_completion_queue_transfer_report_t report;
    uint64_t start, now;
    CHECK(vireo_clock_monotonic_now(&start, NULL), VIREO_OK);
    for (;;) {
        vireo_result_t rc = vireo_completion_queue_try_pop(q, &c, &report);
        if (rc == VIREO_OK)
            break;
        assert(rc == VIREO_RESULT_BUSY && report.stage == VIREO_COMPLETION_QUEUE_TRANSFER_LOCK &&
               report.pthread_error == EBUSY && !report.transferred && !c);
        CHECK(vireo_clock_monotonic_now(&now, NULL), VIREO_OK);
        assert(now - start < UINT64_C(5000000000));
        sched_yield();
    }
    assert(c && report.transferred);
    return c;
}
static inline void destroy_channels(vireo_completion_queue_t **q, vireo_notifier_t **n) {
    CHECK(vireo_completion_queue_destroy(q), VIREO_OK);
    CHECK(vireo_notifier_destroy(n, NULL), VIREO_OK);
}
#endif
