/* PROJECT : VIREO; FILE : directory_list_task.c; AUTHOR : bitofux;
 * DATE : 2026-10-23; BRIEF : 独立可信VLT1输入、取消/软期限与一次服务执行。 */
#include <errno.h>
#include <vireo/base/secure_clear.h>
#include "directory_list_task_internal.h"

vireo_result_t vireo_directory_list_task_create(vireo_task_metadata_t metadata, uint32_t operation,
                                                const unsigned char *wire, size_t size,
                                                const vireo_mysql_node_actor_t *actor,
                                                size_t budget, vireo_task_cancel_t *cancel,
                                                vireo_task_t **owner) {
    const int saved = errno;
    vireo_result_t rc = VIREO_RESULT_INVALID_ARGUMENT;
    unsigned char payload[VIREO_DIRECTORY_LIST_TASK_PAYLOAD_MAX] = {0};
    vireo_node_list_request_t request = {0};
    vireo_node_list_issue_t issue;
    vireo_task_metadata_t checked;
    if (!wire || !actor || !owner || *owner || !actor->user_id || !actor->session_id ||
        !operation || metadata.operation != operation || !budget)
        goto done;
    rc = vireo_task_metadata_make(metadata.route, metadata.request_instance_id, operation,
                                  metadata.deadline_ns, &checked);
    if (rc != VIREO_OK)
        goto done;
    if (size != VIREO_NODE_LIST_REQUEST_FRAME_MIN && size != VIREO_NODE_LIST_REQUEST_FRAME_MAX) {
        rc = VIREO_RESULT_PROTOCOL;
        goto done;
    }
    rc = vireo_node_list_request_decode(wire, size, &request, &issue);
    if (rc != VIREO_OK)
        goto done;
    if (!request.session_handle) {
        rc = VIREO_RESULT_INVALID_ARGUMENT;
        goto done;
    }
    if (request.sequence != metadata.route.request_sequence) {
        rc = VIREO_RESULT_PROTOCOL;
        goto done;
    }
    memcpy(payload, "VLT1", 4);
    vireo_list_write_be(payload + 8, 8, actor->user_id);
    vireo_list_write_be(payload + 16, 8, actor->session_id);
    vireo_list_write_be(payload + 24, 4, size);
    memcpy(payload + VIREO_DIRECTORY_LIST_TASK_PREFIX_SIZE, wire, size);
    rc = cancel ? vireo_task_create_copy_with_cancel(metadata, payload, 32 + size, budget, cancel,
                                                     owner)
                : vireo_task_create_copy(metadata, payload, 32 + size, budget, owner);
done:
    (void)vireo_secure_clear(payload, sizeof(payload));
    (void)vireo_secure_clear(&request, sizeof(request));
    errno = saved;
    return rc;
}

vireo_result_t vireo_directory_list_task_read(const vireo_task_t *task, uint32_t operation,
                                              vireo_directory_list_input_t *out,
                                              vireo_node_list_issue_t *issue) {
    const int saved = errno;
    vireo_result_t rc = VIREO_RESULT_INVALID_ARGUMENT;
    vireo_directory_list_input_t candidate = {0};
    vireo_task_info_t info;
    vireo_task_payload_view_t view;
    if (issue)
        *issue = VIREO_NODE_LIST_ISSUE_NONE;
    if (!task || !operation || !out || !issue)
        goto done;
    rc = vireo_task_inspect(task, &info);
    if (rc != VIREO_OK)
        goto done;
    rc = vireo_task_borrow_payload(task, &view);
    if (rc != VIREO_OK)
        goto done;
    rc = VIREO_RESULT_PROTOCOL;
    *issue = VIREO_NODE_LIST_ISSUE_ENVELOPE;
    if ((view.size != 82 && view.size != 182) || memcmp(view.data, "VLT1", 4) ||
        !vireo_list_zero(view.data + 4, 4) || !vireo_list_zero(view.data + 28, 4) ||
        vireo_list_read_be(view.data + 24, 4) != view.size - 32 ||
        info.metadata.operation != operation)
        goto done;
    candidate.metadata = info.metadata;
    candidate.actor.user_id = vireo_list_read_be(view.data + 8, 8);
    candidate.actor.session_id = vireo_list_read_be(view.data + 16, 8);
    if (!candidate.actor.user_id || !candidate.actor.session_id)
        goto done;
    rc = vireo_node_list_request_decode(view.data + 32, view.size - 32, &candidate.request, issue);
    if (rc != VIREO_OK)
        goto done;
    if (!candidate.request.session_handle ||
        candidate.request.sequence != info.metadata.route.request_sequence) {
        rc = VIREO_RESULT_PROTOCOL;
        *issue = VIREO_NODE_LIST_ISSUE_ENVELOPE;
        goto done;
    }
    *out = candidate;
done:
    (void)vireo_secure_clear(&candidate, sizeof(candidate));
    errno = saved;
    return rc;
}

vireo_result_t vireo_directory_list_task_execute_with_service(
    const vireo_task_t *task, const vireo_directory_list_task_options_t *options,
    vireo_mysql_node_repository_t *repository, const vireo_page_token_key_t *key, uint64_t now,
    vireo_directory_list_task_result_t *out, vireo_directory_list_service_fn service) {
    const int saved = errno;
    vireo_result_t rc = VIREO_RESULT_INVALID_ARGUMENT;
    vireo_directory_list_query_t query = {0};
    bool cancel = false;
    if (!task || !options || !repository || !key || !out || !service)
        goto done;
    memset(out, 0, sizeof(*out));
    out->stage = VIREO_DIRECTORY_LIST_TASK_CONTEXT;
    if (!options->list_operation)
        goto result;
    if (options->pool_timeout_ms > 60000) {
        rc = VIREO_RESULT_RANGE;
        goto result;
    }
    out->stage = VIREO_DIRECTORY_LIST_TASK_DECODE;
    rc = vireo_directory_list_task_read(task, options->list_operation, &out->input,
                                        &out->request_issue);
    if (rc != VIREO_OK) {
        if (out->request_issue == VIREO_NODE_LIST_ISSUE_ENVELOPE)
            out->stage = VIREO_DIRECTORY_LIST_TASK_MATCH;
        goto result;
    }
    out->stage = VIREO_DIRECTORY_LIST_TASK_CANCEL;
    rc = vireo_task_is_cancel_requested(task, &cancel);
    if (rc != VIREO_OK)
        goto result;
    if (cancel) {
        rc = VIREO_RESULT_CANCELLED;
        goto result;
    }
    out->stage = VIREO_DIRECTORY_LIST_TASK_DEADLINE;
    if (now >= out->input.metadata.deadline_ns) {
        rc = VIREO_RESULT_TIMEOUT;
        goto result;
    }
    query.directory_id = out->input.request.directory_id;
    query.page_size = out->input.request.page_size;
    query.has_page_token = out->input.request.has_page_token;
    memcpy(query.page_token.bytes, out->input.request.page_token, sizeof(query.page_token.bytes));
    out->stage = VIREO_DIRECTORY_LIST_TASK_SERVICE;
    rc = service(repository, key, &out->input.actor, &query, options->pool_timeout_ms,
                 &out->service, &out->error);
result:
    out->result = rc;
done:
    (void)vireo_secure_clear(&query, sizeof(query));
    errno = saved;
    return rc;
}

vireo_result_t vireo_directory_list_task_execute(const vireo_task_t *task,
                                                 const vireo_directory_list_task_options_t *options,
                                                 vireo_mysql_node_repository_t *repository,
                                                 const vireo_page_token_key_t *key, uint64_t now,
                                                 vireo_directory_list_task_result_t *out) {
    return vireo_directory_list_task_execute_with_service(task, options, repository, key, now, out,
                                                          vireo_directory_service_list);
}
