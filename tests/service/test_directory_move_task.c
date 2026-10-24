/* PROJECT : VIREO; FILE : test_directory_move_task.c; AUTHOR : bitofux;
 * DATE : 2026-10-25; BRIEF : 原始载荷副本、事件、取消期限与一次服务。 */
#include <pthread.h>
#include "directory_move_bridge_test_support.h"
#include "directory_move_bridge_test_vectors.h"
#include "directory_move_task_internal.h"
static max_align_t marker;
#define REPO ((vireo_mysql_node_repository_t *)(void *)&marker)
static size_t calls;
static vireo_task_cancel_t *cancel_after;
static vireo_result_t service(void *c, vireo_mysql_node_repository_t *repo,
                              const vireo_mysql_node_actor_t *actor,
                              const vireo_mysql_node_move_once_input_t *in, uint32_t timeout,
                              vireo_directory_move_result_t *out, vireo_mysql_node_error_t *error) {
    const vireo_directory_move_task_result_t *model = c;
    assert(repo == REPO && actor->user_id == 7 && actor->session_id == 51 && timeout == 17);
    assert(in->node_id == 123 && in->new_parent_id == 77 && in->name_length == 1 &&
           in->name[0] == 'a');
    assert(!memcmp(in->idempotency_key, test_key, 16) && !memcmp(in->request_id, test_event, 16));
    ++calls;
    *out = model->service;
    *error = model->error;
    if (cancel_after)
        CHECK(vireo_task_cancel_request(cancel_after), VIREO_OK);
    errno = EIO;
    return model->result;
}
static void vectors(void) {
    for (size_t i = 0; i < sizeof(bridge_vectors) / sizeof(bridge_vectors[0]); ++i) {
        const bridge_vector_t *v = &bridge_vectors[i];
        if (!v->task)
            continue;
        for (size_t n = 0; n <= v->size; ++n) {
            vireo_task_t *t = NULL;
            CHECK(vireo_task_create_copy(metadata(), v->bytes, n, 4096, &t), VIREO_OK);
            vireo_directory_move_input_t out, old;
            memset(&out, 0xa5, sizeof(out));
            memcpy(&old, &out, sizeof(out));
            vireo_node_move_issue_t issue;
            CHECK(vireo_directory_move_task_read(t, 400, &out, &issue),
                  n == v->size ? VIREO_OK : VIREO_RESULT_PROTOCOL);
            if (n != v->size)
                assert(!memcmp(&old, &out, sizeof(out)) && issue);
            else
                assert(out.request.new_name_length == v->size - 104 && out.actor.user_id == 7 &&
                       out.actor.session_id == 51);
            CHECK(vireo_task_destroy(&t), VIREO_OK);
        }
    }
    /* Every inherited TLV ordering survives create byte-for-byte, without reencoding. */
    for (size_t i = 0; i < sizeof(order_vectors) / sizeof(order_vectors[0]); ++i) {
        const bridge_vector_t *v = &order_vectors[i];
        vireo_mysql_node_actor_t actor = {7, 51};
        vireo_task_t *ordered = NULL;
        CHECK(vireo_directory_move_task_create(metadata(), 400, v->bytes + 24, v->size - 24, &actor,
                                               4096, NULL, &ordered),
              VIREO_OK);
        vireo_task_payload_view_t raw;
        CHECK(vireo_task_borrow_payload(ordered, &raw), VIREO_OK);
        assert(raw.size == v->size && !memcmp(raw.data, v->bytes, v->size));
        vireo_directory_move_input_t input;
        vireo_node_move_issue_t issue;
        CHECK(vireo_directory_move_task_read(ordered, 400, &input, &issue), VIREO_OK);
        assert(input.request.node_id == 123 && input.request.new_parent_id == 77 &&
               input.request.new_name[0] == 'a');
        CHECK(vireo_task_destroy(&ordered), VIREO_OK);
    }
    vireo_task_t *t = make_task(100, NULL);
    vireo_task_payload_view_t view;
    CHECK(vireo_task_borrow_payload(t, &view), VIREO_OK);
    assert(view.size == 105 && !memcmp(view.data, bridge_vectors[0].bytes, 105));
    unsigned char bytes[360] = {0};
    memcpy(bytes, view.data, view.size);
    CHECK(vireo_task_destroy(&t), VIREO_OK);
    for (unsigned k = 0; k < 8; ++k) {
        unsigned char changed[360];
        memcpy(changed, bytes, sizeof(bytes));
        if (k == 0)
            changed[0] ^= 1;
        if (k == 1)
            changed[4] = 1;
        if (k == 2)
            memset(changed + 8, 0, 8);
        if (k == 3)
            memset(changed + 16, 0, 8);
        if (k == 4)
            changed[55] ^= 1;
        if (k == 5) {
            changed[47] = 0;
            crc_fix(changed + 24, 81);
        }
        vireo_task_metadata_t m = metadata();
        if (k == 6)
            m.operation = 401;
        CHECK(vireo_task_create_copy(m, changed, k == 7 ? 360 : 105, 4096, &t), VIREO_OK);
        vireo_directory_move_input_t out;
        vireo_node_move_issue_t issue;
        CHECK(vireo_directory_move_task_read(t, 400, &out, &issue), VIREO_RESULT_PROTOCOL);
        CHECK(vireo_task_destroy(&t), VIREO_OK);
    }
}
static void creation(void) {
    const bridge_vector_t *v = &bridge_vectors[0];
    const unsigned char *wire = v->bytes + 24;
    vireo_mysql_node_actor_t a = {7, 51};
    vireo_task_t *t = NULL;
    for (unsigned k = 0; k < 9; ++k) {
        vireo_task_metadata_t m = metadata();
        vireo_mysql_node_actor_t actor = a;
        size_t budget = 4096;
        uint32_t op = 400;
        vireo_result_t want = VIREO_RESULT_INVALID_ARGUMENT;
        switch (k) {
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
                actor.user_id = 0;
                break;
            case 4:
                actor.session_id = 0;
                break;
            case 5:
                ++m.route.request_sequence;
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
        CHECK(vireo_directory_move_task_create(m, op, wire, 81, &actor, budget, NULL, &t), want);
        assert(!t);
    }
    CHECK(vireo_directory_move_task_create(metadata(), 400, NULL, 81, &a, 4096, NULL, &t),
          VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_directory_move_task_create(metadata(), 400, wire, 80, &a, 4096, NULL, &t),
          VIREO_RESULT_PROTOCOL);
    unsigned char maxname[255];
    memset(maxname, 'a', sizeof(maxname));
    t = named_task(100, NULL, maxname, sizeof(maxname));
    vireo_directory_move_input_t out;
    vireo_node_move_issue_t issue;
    CHECK(vireo_directory_move_task_read(t, 400, &out, &issue), VIREO_OK);
    assert(out.request.new_name_length == 255 && !memcmp(out.request.new_name, maxname, 255));
    CHECK(vireo_directory_move_task_read(NULL, 400, &out, &issue), VIREO_RESULT_INVALID_ARGUMENT);
    assert(!issue);
    CHECK(vireo_directory_move_task_read(t, 0, &out, &issue), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_task_destroy(&t), VIREO_OK);
}
static void execution(void) {
    vireo_task_t *t = make_task(100, NULL);
    vireo_directory_move_task_result_t model = found_result(t), out, old;
    const vireo_directory_move_task_ops_t ops = {&model, service};
    vireo_directory_move_task_options_t options = {400, 17};
    memset(&out, 0xa5, sizeof(out));
    memcpy(&old, &out, sizeof(out));
    CHECK(vireo_directory_move_task_execute_with(t, &options, REPO, NULL, 1, &out, &ops),
          VIREO_RESULT_INVALID_ARGUMENT);
    assert(!memcmp(&out, &old, sizeof(out)));
    unsigned char event[16] = {0};
    CHECK(vireo_directory_move_task_execute_with(t, &options, REPO, event, 1, &out, &ops),
          VIREO_RESULT_INVALID_ARGUMENT);
    assert(out.stage == VIREO_DIRECTORY_MOVE_TASK_CONTEXT && !calls);
    options.move_operation = 401;
    CHECK(vireo_directory_move_task_execute_with(t, &options, REPO, test_event, 1, &out, &ops),
          VIREO_RESULT_PROTOCOL);
    assert(out.stage == VIREO_DIRECTORY_MOVE_TASK_MATCH && !calls);
    options.move_operation = 0;
    CHECK(vireo_directory_move_task_execute_with(t, &options, REPO, test_event, 1, &out, &ops),
          VIREO_RESULT_INVALID_ARGUMENT);
    options.move_operation = 400;
    options.pool_timeout_ms = 60001;
    CHECK(vireo_directory_move_task_execute_with(t, &options, REPO, test_event, 1, &out, &ops),
          VIREO_RESULT_RANGE);
    options.pool_timeout_ms = 17;
    CHECK(vireo_directory_move_task_execute_with(t, &options, REPO, test_event, 100, &out, &ops),
          VIREO_RESULT_TIMEOUT);
    assert(out.stage == VIREO_DIRECTORY_MOVE_TASK_DEADLINE && !calls);
    CHECK(vireo_directory_move_task_execute_with(t, &options, REPO, test_event, 99, &out, &ops),
          VIREO_OK);
    assert(calls == 1 && out.service.node_id == 123 && !memcmp(out.request_id, test_event, 16));
    for (int rc = 1; rc <= 12; ++rc) {
        model.result = (vireo_result_t)rc;
        model.service.outcome = VIREO_DIRECTORY_MOVE_NONE;
        model.service.node_id = 0;
        memset(model.service.idempotency_key, 0, 16);
        model.error.cleanup_result = (vireo_result_t)rc;
        CHECK(vireo_directory_move_task_execute_with(t, &options, REPO, test_event, 1, &out, &ops),
              (vireo_result_t)rc);
        assert(out.service.repository.node_id == 123 && out.service.repository.audit_id == 234 &&
               out.service.repository.commit == VIREO_MYSQL_NODE_MOVE_COMMITTED &&
               out.error.cleanup_result == (vireo_result_t)rc);
    }
    CHECK(vireo_task_destroy(&t), VIREO_OK);
    for (unsigned k = 0; k < 2; ++k) {
        uint64_t edge = k ? UINT64_MAX : 0;
        t = make_task(edge, NULL);
        size_t count = calls;
        CHECK(
            vireo_directory_move_task_execute_with(t, &options, REPO, test_event, edge, &out, &ops),
            VIREO_RESULT_TIMEOUT);
        assert(calls == count && out.stage == VIREO_DIRECTORY_MOVE_TASK_DEADLINE);
        CHECK(vireo_task_destroy(&t), VIREO_OK);
    }
    vireo_task_cancel_t *cancel = NULL;
    CHECK(vireo_task_cancel_create(4096, &cancel), VIREO_OK);
    t = make_task(0, cancel);
    CHECK(vireo_task_cancel_request(cancel), VIREO_OK);
    const size_t before = calls;
    CHECK(vireo_directory_move_task_execute_with(t, &options, REPO, test_event, UINT64_MAX, &out,
                                                 &ops),
          VIREO_RESULT_CANCELLED);
    assert(out.stage == VIREO_DIRECTORY_MOVE_TASK_CANCEL && calls == before);
    CHECK(vireo_task_destroy(&t), VIREO_OK);
    CHECK(vireo_task_cancel_destroy(&cancel), VIREO_OK);
    CHECK(vireo_task_cancel_create(4096, &cancel), VIREO_OK);
    t = make_task(UINT64_MAX, cancel);
    model = found_result(t);
    cancel_after = cancel;
    CHECK(vireo_directory_move_task_execute_with(t, &options, REPO, test_event, UINT64_MAX - 1,
                                                 &out, &ops),
          VIREO_OK);
    assert(out.service.outcome == VIREO_DIRECTORY_MOVE_APPLIED);
    cancel_after = NULL;
    CHECK(vireo_task_destroy(&t), VIREO_OK);
    CHECK(vireo_task_cancel_destroy(&cancel), VIREO_OK);
}
int main(void) {
    int old = 0;
    assert(!pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &old));
    vectors();
    creation();
    execution();
    printf(
        "PASS directory_move_task: %zu checks; independent MVT1, immutable bytes, event, "
        "cancel/deadline, raw writes\n",
        checks);
    return 0;
}
