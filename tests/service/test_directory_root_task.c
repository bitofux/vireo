/*
 * PROJECT : VIREO
 * FILE    : test_directory_root_task.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-22
 * BRIEF   : 根查询桥接边界与资源验证。
 */
#include <pthread.h>
#include "directory_root_task_internal.h"
#include "directory_root_test_support.h"
#include "directory_root_test_vectors.h"
static max_align_t marker;
#define REPO ((vireo_mysql_node_repository_t *)(void *)&marker)
static size_t calls;
static vireo_task_cancel_t *cancel_after;
static vireo_result_t service(void *c, vireo_mysql_node_repository_t *repo,
                              const vireo_mysql_node_actor_t *a, uint32_t timeout,
                              vireo_directory_root_result_t *out, vireo_mysql_node_error_t *e) {
    const vireo_directory_root_task_result_t *r = c;
    assert(repo == REPO && a->user_id == 7 && a->session_id == 99 && timeout == 17);
    ++calls;
    *out = r->service;
    *e = r->error;
    if (cancel_after)
        CHECK(vireo_task_cancel_request(cancel_after), VIREO_OK);
    errno = EIO;
    return r->result;
}
static void vectors(void) {
    for (size_t i = 0; i < sizeof(goldens) / sizeof(goldens[0]); ++i) {
        const golden_t *g = &goldens[i];
        if (!g->task)
            continue;
        vireo_task_t *t = NULL;
        CHECK(vireo_task_create_copy(metadata(), g->bytes, g->size, 4096, &t), VIREO_OK);
        vireo_directory_root_input_t out, old;
        memset(&out, 0xa5, sizeof(out));
        memcpy(&old, &out, sizeof(out));
        vireo_node_root_issue_t issue;
        CHECK(vireo_directory_root_task_read(t, 400, &out, &issue),
              g->valid ? VIREO_OK : VIREO_RESULT_PROTOCOL);
        if (g->valid)
            assert(out.actor.user_id && out.actor.session_id && out.request.session_handle);
        else
            assert(!memcmp(&out, &old, sizeof(out)) && issue != VIREO_NODE_ROOT_ISSUE_NONE);
        CHECK(vireo_task_destroy(&t), VIREO_OK);
    }
    const golden_t *g = &goldens[0];
    assert(g->task && g->size == 56);
    for (size_t n = 0; n < 56; ++n) {
        vireo_task_t *t = NULL;
        CHECK(vireo_task_create_copy(metadata(), g->bytes, n, 4096, &t), VIREO_OK);
        vireo_directory_root_input_t out;
        vireo_node_root_issue_t issue;
        CHECK(vireo_directory_root_task_read(t, 400, &out, &issue), VIREO_RESULT_PROTOCOL);
        assert(issue == VIREO_NODE_ROOT_ISSUE_ENVELOPE);
        CHECK(vireo_task_destroy(&t), VIREO_OK);
    }
}
static void create_read(void) {
    vireo_task_t *t = make_task(100, NULL);
    vireo_task_payload_view_t view;
    CHECK(vireo_task_borrow_payload(t, &view), VIREO_OK);
    assert(view.size == 56 && !memcmp(view.data, goldens[0].bytes, 56));
    vireo_directory_root_input_t out;
    vireo_node_root_issue_t issue;
    CHECK(vireo_directory_root_task_read(t, 400, &out, &issue), VIREO_OK);
    assert(out.actor.user_id == 7 && out.actor.session_id == 99);
    CHECK(vireo_directory_root_task_read(t, 401, &out, &issue), VIREO_RESULT_PROTOCOL);
    CHECK(vireo_directory_root_task_read(NULL, 400, &out, &issue), VIREO_RESULT_INVALID_ARGUMENT);
    assert(!issue);
    CHECK(vireo_directory_root_task_read(t, 0, &out, &issue), VIREO_RESULT_INVALID_ARGUMENT);
    unsigned char wire[32];
    memcpy(wire, goldens[0].bytes + 24, 32);
    const vireo_mysql_node_actor_t actor = {7, 99};
    for (unsigned i = 0; i < 9; ++i) {
        vireo_task_metadata_t m = metadata();
        vireo_mysql_node_actor_t a = actor;
        uint32_t op = 400;
        size_t budget = 4096;
        vireo_result_t want = VIREO_RESULT_INVALID_ARGUMENT;
        switch (i) {
            case 0:
                m.route.client_owner_id = 0;
                break;
            case 1:
                m.request_instance_id = 0;
                break;
            case 2:
                op = 401;
                break;
            case 3:
                a.user_id = 0;
                break;
            case 4:
                a.session_id = 0;
                break;
            case 5:
                m.route.request_sequence = 2;
                want = VIREO_RESULT_PROTOCOL;
                break;
            case 6:
                budget = 1;
                want = VIREO_RESULT_RANGE;
                break;
            case 7:
                budget = VIREO_TASK_MAX_ALLOCATION_BYTES + 1;
                want = VIREO_RESULT_RANGE;
                break;
            default:
                budget = 0;
                break;
        }
        vireo_task_t *bad = NULL;
        CHECK(vireo_directory_root_task_create(m, op, wire, 32, &a, budget, NULL, &bad), want);
        assert(!bad);
    }
    CHECK(vireo_directory_root_task_create(metadata(), 400, wire, 32, &actor, 4096, NULL, &t),
          VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_task_destroy(&t), VIREO_OK);
    for (unsigned i = 0; i < 4; ++i) {
        memcpy(wire, goldens[0].bytes + 24, 32);
        if (i == 0)
            wire[0] ^= 1;
        if (i == 1) {
            wire[23] = 0;
            crc_fix(wire, 32);
        }
        if (i == 2) {
            wire[7] = 3;
            crc_fix(wire, 32);
        }
        if (i == 3)
            wire[31] ^= 1;
        CHECK(vireo_directory_root_task_create(metadata(), 400, wire, 32, &actor, 4096, NULL, &t),
              i == 1 ? VIREO_RESULT_INVALID_ARGUMENT : VIREO_RESULT_PROTOCOL);
        assert(!t);
    }
}
static void execution(void) {
    vireo_task_t *t = make_task(100, NULL);
    vireo_directory_root_task_result_t model = found_result(t), out, old;
    const vireo_directory_root_task_ops_t ops = {&model, service};
    vireo_directory_root_task_options_t o = {400, 17};
    memset(&out, 0xa5, sizeof(out));
    memcpy(&old, &out, sizeof(out));
    CHECK(vireo_directory_root_task_execute_with(NULL, &o, REPO, 1, &out, &ops),
          VIREO_RESULT_INVALID_ARGUMENT);
    assert(!memcmp(&out, &old, sizeof(out)));
    CHECK(vireo_directory_root_task_execute_with(t, NULL, REPO, 1, &out, &ops),
          VIREO_RESULT_INVALID_ARGUMENT);
    assert(!memcmp(&out, &old, sizeof(out)));
    CHECK(vireo_directory_root_task_execute_with(t, &o, NULL, 1, &out, &ops),
          VIREO_RESULT_INVALID_ARGUMENT);
    assert(!memcmp(&out, &old, sizeof(out)));
    o.root_operation = 401;
    CHECK(vireo_directory_root_task_execute_with(t, &o, REPO, 1, &out, &ops),
          VIREO_RESULT_PROTOCOL);
    assert(out.stage == VIREO_DIRECTORY_ROOT_TASK_MATCH && !calls);
    o.root_operation = 400;
    o.root_operation = 0;
    CHECK(vireo_directory_root_task_execute_with(t, &o, REPO, 1, &out, &ops),
          VIREO_RESULT_INVALID_ARGUMENT);
    assert(out.stage == VIREO_DIRECTORY_ROOT_TASK_CONTEXT && !calls);
    o.root_operation = 400;
    o.pool_timeout_ms = 60001;
    CHECK(vireo_directory_root_task_execute_with(t, &o, REPO, 1, &out, &ops), VIREO_RESULT_RANGE);
    o.pool_timeout_ms = 17;
    CHECK(vireo_directory_root_task_execute_with(t, &o, REPO, 100, &out, &ops),
          VIREO_RESULT_TIMEOUT);
    assert(out.stage == VIREO_DIRECTORY_ROOT_TASK_DEADLINE && !calls);
    CHECK(vireo_directory_root_task_execute_with(t, &o, REPO, 99, &out, &ops), VIREO_OK);
    assert(calls == 1 && out.service.root_node_id == 42);
    for (int rc = 1; rc <= 12; ++rc) {
        model.result = (vireo_result_t)rc;
        model.service = (vireo_directory_root_result_t){0};
        model.error.cleanup_result = VIREO_RESULT_BUSY;
        CHECK(vireo_directory_root_task_execute_with(t, &o, REPO, 0, &out, &ops),
              (vireo_result_t)rc);
        assert(out.stage == VIREO_DIRECTORY_ROOT_TASK_SERVICE && out.result == (vireo_result_t)rc &&
               out.error.cleanup_result == VIREO_RESULT_BUSY);
    }
    CHECK(vireo_task_destroy(&t), VIREO_OK);
    vireo_task_cancel_t *cancel = NULL;
    CHECK(vireo_task_cancel_create(4096, &cancel), VIREO_OK);
    t = make_task(0, cancel);
    CHECK(vireo_task_cancel_request(cancel), VIREO_OK);
    CHECK(vireo_task_cancel_destroy(&cancel), VIREO_OK);
    CHECK(vireo_directory_root_task_execute_with(t, &o, REPO, UINT64_MAX, &out, &ops),
          VIREO_RESULT_CANCELLED);
    assert(out.stage == VIREO_DIRECTORY_ROOT_TASK_CANCEL);
    CHECK(vireo_task_destroy(&t), VIREO_OK);
    t = make_task(0, NULL);
    CHECK(vireo_directory_root_task_execute_with(t, &o, REPO, 0, &out, &ops), VIREO_RESULT_TIMEOUT);
    CHECK(vireo_task_destroy(&t), VIREO_OK);
    CHECK(vireo_task_cancel_create(4096, &cancel), VIREO_OK);
    t = make_task(UINT64_MAX, cancel);
    cancel_after = cancel;
    model = found_result(t);
    CHECK(vireo_directory_root_task_execute_with(t, &o, REPO, UINT64_MAX - 1, &out, &ops),
          VIREO_OK);
    assert(out.service.outcome == VIREO_DIRECTORY_ROOT_FOUND);
    cancel_after = NULL;
    CHECK(vireo_task_destroy(&t), VIREO_OK);
    CHECK(vireo_task_cancel_destroy(&cancel), VIREO_OK);
    t = make_task(UINT64_MAX, NULL);
    CHECK(vireo_directory_root_task_execute_with(t, &o, REPO, UINT64_MAX, &out, &ops),
          VIREO_RESULT_TIMEOUT);
    CHECK(vireo_task_destroy(&t), VIREO_OK);
}
int main(void) {
    int old_state = 0;
    assert(!pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &old_state));
    vectors();
    create_read();
    execution();
    printf(
        "PASS directory_root_task: %zu boundary calls; independent VRT1, cancel/deadline, exactly "
        "one service and original diagnostics\n",
        checks);
    return 0;
}
