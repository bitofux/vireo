/*
 * PROJECT : VIREO
 * FILE    : directory_move_test_support.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-25
 * BRIEF   : 目录移动桥接边界与资源验证。
 */
#ifndef DIRECTORY_MOVE_BRIDGE_TEST_SUPPORT_H
#define DIRECTORY_MOVE_BRIDGE_TEST_SUPPORT_H
#include <assert.h>
#include <errno.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vireo/protocol/codec.h>
#include <vireo/service/directory_move_worker.h>
static _Atomic size_t checks;
#define CHECK(call, want)                                                                         \
    do {                                                                                          \
        errno = EDOM;                                                                             \
        vireo_result_t got_ = (call);                                                             \
        if (got_ != (want) || errno != EDOM) {                                                    \
            fprintf(stderr, "line %d rc=%d want=%d errno=%d\n", __LINE__, (int)got_, (int)(want), \
                    errno);                                                                       \
            abort();                                                                              \
        }                                                                                         \
        ++checks;                                                                                 \
    } while (0)
static inline vireo_task_metadata_t metadata(void) {
    return (vireo_task_metadata_t){
        .route = {1, 0, 3, 11}, .request_instance_id = 9, .operation = 400, .deadline_ns = 100};
}
static const unsigned char test_key[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
static const unsigned char test_event[16] = {0xe1};
static inline vireo_task_t *named_task(uint64_t deadline, vireo_task_cancel_t *cancel,
                                       const unsigned char *name, size_t length) {
    vireo_task_metadata_t m = metadata();
    m.deadline_ns = deadline;
    vireo_node_move_request_t req = {.sequence = 11,
                                     .session_handle = 9,
                                     .node_id = 123,
                                     .new_parent_id = 77,
                                     .new_name_length = length};
    assert(length <= 255);
    memcpy(req.new_name, name, length);
    memcpy(req.idempotency_key, test_key, 16);
    unsigned char wire[335];
    size_t size = 0;
    CHECK(vireo_node_move_request_encode(&req, wire, sizeof(wire), &size), VIREO_OK);
    vireo_mysql_node_actor_t actor = {7, 51};
    vireo_task_t *t = NULL;
    CHECK(vireo_directory_move_task_create(m, 400, wire, size, &actor, 4096, cancel, &t), VIREO_OK);
    memset(wire, 0, sizeof(wire));
    memset(&actor, 0, sizeof(actor));
    return t;
}
static inline vireo_task_t *make_task(uint64_t deadline, vireo_task_cancel_t *cancel) {
    return named_task(deadline, cancel, (const unsigned char *)"a", 1);
}
static inline vireo_directory_move_task_result_t found_result(const vireo_task_t *t) {
    vireo_directory_move_task_result_t r = {.stage = VIREO_DIRECTORY_MOVE_TASK_SERVICE};
    CHECK(vireo_directory_move_task_read(t, 400, &r.input, &r.request_issue), VIREO_OK);
    memcpy(r.request_id, test_event, 16);
    r.service = (vireo_directory_move_result_t){
        .outcome = VIREO_DIRECTORY_MOVE_APPLIED,
        .node_id = 123,
        .repository_called = true,
        .repository = {.commit = VIREO_MYSQL_NODE_MOVE_COMMITTED,
                       .effect = VIREO_MYSQL_NODE_MOVE_EFFECT_APPLIED,
                       .node_id = 123,
                       .audit_id = 234}};
    memcpy(r.service.idempotency_key, test_key, 16);
    memcpy(r.service.repository.idempotency_key, test_key, 16);
    return r;
}
static inline void queue_setup(vireo_completion_queue_t **q, vireo_notifier_t **n, bool prepared) {
    const vireo_completion_queue_options_t qo = {1, 65536};
    const vireo_notifier_options_t no = {4096};
    CHECK(vireo_completion_queue_create(&qo, q), VIREO_OK);
    if (prepared)
        CHECK(vireo_completion_queue_prepare_wait(*q), VIREO_OK);
    CHECK(vireo_notifier_create(&no, n, NULL), VIREO_OK);
}
static inline vireo_completion_t *pop(vireo_completion_queue_t *q) {
    vireo_completion_t *c = NULL;
    vireo_completion_queue_transfer_report_t p;
    CHECK(vireo_completion_queue_try_pop(q, &c, &p), VIREO_OK);
    assert(p.transferred && c);
    return c;
}
static inline void empty(vireo_completion_queue_t *q) {
    vireo_completion_t *c = NULL;
    vireo_completion_queue_transfer_report_t p;
    vireo_completion_queue_info_t info;
    CHECK(vireo_completion_queue_inspect(q, &info), VIREO_OK);
    CHECK(vireo_completion_queue_try_pop(q, &c, &p),
          info.closed ? VIREO_RESULT_CANCELLED : VIREO_RESULT_NOT_FOUND);
    assert(!c);
}
static inline void queue_teardown(vireo_completion_queue_t **q, vireo_notifier_t **n) {
    empty(*q);
    CHECK(vireo_completion_queue_destroy(q), VIREO_OK);
    CHECK(vireo_notifier_destroy(n, NULL), VIREO_OK);
}
static inline void put32_test(unsigned char *p, uint32_t v) {
    for (size_t i = 0; i < 4; ++i)
        p[i] = (unsigned char)(v >> ((3 - i) * 8));
}
static inline void crc_fix(unsigned char *p, size_t n) {
    uint32_t crc = 0;
    CHECK(vireo_protocol_frame_crc32c_calculate(p, 32, p + 32, n - 32, &crc), VIREO_OK);
    put32_test(p + 28, crc);
}
#endif
