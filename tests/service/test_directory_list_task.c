/* PROJECT : VIREO; FILE : test_directory_list_task.c; AUTHOR : bitofux;
 * DATE : 2026-10-23; BRIEF : 完整请求复制、输出保持、关联、取消优先与软期限门禁。 */
#include <pthread.h>
#include "directory_list_bridge_test_support.h"
#include "directory_list_task_internal.h"
static max_align_t repo_marker, key_marker;
#define REPO ((vireo_mysql_node_repository_t *)(void *)&repo_marker)
#define KEY ((const vireo_page_token_key_t *)(const void *)&key_marker)
static size_t service_calls;
static vireo_result_t service(vireo_mysql_node_repository_t *r, const vireo_page_token_key_t *k,
                              const vireo_mysql_node_actor_t *a,
                              const vireo_directory_list_query_t *q, uint32_t timeout,
                              vireo_directory_list_result_t *out, vireo_directory_list_error_t *e) {
    assert(r == REPO && k == KEY && a->user_id == 7 && a->session_id == 8 && q->directory_id == 9 &&
           q->page_size == 64 && timeout == 17);
    if (q->has_page_token)
        for (size_t i = 0; i < 96; ++i)
            assert(q->page_token.bytes[i] == 0x77);
    ++service_calls;
    errno = EIO;
    out->outcome = VIREO_DIRECTORY_LIST_NOT_FOUND;
    out->repository_operation = VIREO_DIRECTORY_LIST_REPOSITORY_CHILDREN;
    out->repository_result = VIREO_RESULT_NOT_FOUND;
    out->repository.issue = VIREO_MYSQL_NODE_NOT_FOUND;
    out->repository.rollback_confirmed = true;
    e->stage = VIREO_DIRECTORY_LIST_STAGE_REPOSITORY;
    return VIREO_RESULT_NOT_FOUND;
}
static void malformed(const vireo_task_t *source) {
    vireo_task_info_t info;
    vireo_task_payload_view_t view;
    CHECK(vireo_task_inspect(source, &info), VIREO_OK);
    CHECK(vireo_task_borrow_payload(source, &view), VIREO_OK);
    unsigned char data[183];
    memcpy(data, view.data, view.size);
    /* 每个封装字节、截断长度、尾随字节均走真实public task，不写opaque内存。 */
    for (size_t test = 0; test < 32 + view.size + 2; ++test) {
        memcpy(data, view.data, view.size);
        size_t size = view.size;
        if (test < 32)
            data[test] ^= 0xff;
        else
            size = test - 32;
        if (test >= 32 && size == view.size)
            continue;
        if (size > view.size)
            data[view.size] = 0;
        vireo_task_t *bad = NULL;
        CHECK(vireo_task_create_copy(info.metadata, data, size, BUDGET, &bad), VIREO_OK);
        vireo_directory_list_input_t value, before;
        memset(&value, 0xa5, sizeof(value));
        memcpy(&before, &value, sizeof(value));
        vireo_node_list_issue_t issue;
        vireo_result_t got = vireo_directory_list_task_read(bad, OP, &value, &issue);
        /* 修改非零actor值仍是合法可信值，magic不认证身份。 */
        bool actor_change = test >= 8 && test < 24;
        if (actor_change)
            assert(got == VIREO_OK);
        else
            assert(got == VIREO_RESULT_PROTOCOL && !memcmp(&value, &before, sizeof(value)));
        CHECK(vireo_task_destroy(&bad), VIREO_OK);
    }
}
int main(void) {
    int old_state;
    assert(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &old_state) == 0);
    vireo_task_t *t = make_task(1, true, NULL);
    vireo_directory_list_input_t input;
    vireo_node_list_issue_t issue;
    CHECK(vireo_directory_list_task_read(t, OP, &input, &issue), VIREO_OK);
    assert(input.request.has_page_token && input.request.page_token[95] == 0x77 &&
           input.actor.user_id == 7 && input.metadata.route.client_slot_index == 0);
    malformed(t);
    vireo_directory_list_input_t original;
    memset(&original, 0xaa, sizeof(original));
    memcpy(&input, &original, sizeof(input));
    CHECK(vireo_directory_list_task_read(t, OP + 1, &input, &issue), VIREO_RESULT_PROTOCOL);
    assert(!memcmp(&input, &original, sizeof(input)));
    vireo_directory_list_task_options_t options = {OP, 17};
    vireo_directory_list_task_result_t result, snapshot;
    memset(&result, 0xa5, sizeof(result));
    memcpy(&snapshot, &result, sizeof(result));
    CHECK(vireo_directory_list_task_execute(t, &options, NULL, KEY, 0, &result),
          VIREO_RESULT_INVALID_ARGUMENT);
    assert(!memcmp(&result, &snapshot, sizeof(result)));
    CHECK(vireo_directory_list_task_execute_with_service(t, &options, REPO, KEY, UINT64_MAX - 1,
                                                         &result, service),
          VIREO_RESULT_NOT_FOUND);
    assert(result.stage == VIREO_DIRECTORY_LIST_TASK_SERVICE && service_calls == 1 &&
           result.result == VIREO_RESULT_NOT_FOUND && result.service.repository.rollback_confirmed);
    CHECK(vireo_directory_list_task_execute_with_service(t, &options, REPO, KEY, UINT64_MAX,
                                                         &result, service),
          VIREO_RESULT_TIMEOUT);
    assert(result.stage == VIREO_DIRECTORY_LIST_TASK_DEADLINE && service_calls == 1);
    options.pool_timeout_ms = 60001;
    CHECK(
        vireo_directory_list_task_execute_with_service(t, &options, REPO, KEY, 0, &result, service),
        VIREO_RESULT_RANGE);
    assert(result.stage == VIREO_DIRECTORY_LIST_TASK_CONTEXT && !result.service.outcome);
    options.pool_timeout_ms = 17;
    vireo_task_cancel_t *cancel = NULL;
    CHECK(vireo_task_cancel_create(BUDGET, &cancel), VIREO_OK);
    vireo_task_t *cancelled = make_task(2, false, cancel);
    CHECK(vireo_task_cancel_request(cancel), VIREO_OK);
    CHECK(vireo_task_cancel_destroy(&cancel), VIREO_OK);
    CHECK(vireo_directory_list_task_execute_with_service(cancelled, &options, REPO, KEY, UINT64_MAX,
                                                         &result, service),
          VIREO_RESULT_CANCELLED);
    assert(result.stage == VIREO_DIRECTORY_LIST_TASK_CANCEL && service_calls == 1);
    CHECK(vireo_task_destroy(&cancelled), VIREO_OK);
    /* create拒绝非可信形态；元数据的operation与sequence分别核对。 */
    unsigned char wire[150];
    size_t size;
    vireo_node_list_request_t q = {
        .sequence = 3, .session_handle = 13, .directory_id = 9, .page_size = 1};
    CHECK(vireo_node_list_request_encode(&q, wire, sizeof(wire), &size), VIREO_OK);
    const vireo_mysql_node_actor_t actor = {7, 8};
    vireo_task_t *owner = NULL;
    CHECK(
        vireo_directory_list_task_create(metadata(4), OP, wire, size, &actor, BUDGET, NULL, &owner),
        VIREO_RESULT_PROTOCOL);
    q.session_handle = 0;
    CHECK(vireo_node_list_request_encode(&q, wire, sizeof(wire), &size), VIREO_OK);
    CHECK(
        vireo_directory_list_task_create(metadata(3), OP, wire, size, &actor, BUDGET, NULL, &owner),
        VIREO_RESULT_INVALID_ARGUMENT);
    q.session_handle = 13;
    CHECK(vireo_node_list_request_encode(&q, wire, sizeof(wire), &size), VIREO_OK);
    CHECK(vireo_directory_list_task_create(metadata(3), OP, wire, size, &actor, 1, NULL, &owner),
          VIREO_RESULT_RANGE);
    CHECK(vireo_task_destroy(&t), VIREO_OK);
    printf(
        "PASS %zu LIST task checks; copy, strict envelope, output preservation, cancel/deadline\n",
        checks);
    assert(pthread_setcancelstate(old_state, NULL) == 0);
    return 0;
}
