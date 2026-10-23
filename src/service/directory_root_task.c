/*
 * PROJECT : VIREO
 * FILE    : directory_root_task.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-22
 * BRIEF   : 根查询内部桥接与原线程所有权。
 */
#include <errno.h>
#include <string.h>
#include "directory_root_task_internal.h"

/* 固定边界在调用前核验；不依赖C布局。 */
static void put64(unsigned char *p, uint64_t v) {
    for (size_t i = 0; i < 8; ++i)
        p[i] = (unsigned char)(v >> ((7 - i) * 8));
}
static uint64_t get64(const unsigned char *p) {
    uint64_t v = 0;
    for (size_t i = 0; i < 8; ++i)
        v = (v << 8) | p[i];
    return v;
}

vireo_result_t vireo_directory_root_task_create(vireo_task_metadata_t m, uint32_t op,
                                                const unsigned char *wire, size_t size,
                                                const vireo_mysql_node_actor_t *actor,
                                                size_t budget, vireo_task_cancel_t *cancel,
                                                vireo_task_t **owner) {
    const int saved = errno;
    vireo_result_t rc = VIREO_RESULT_INVALID_ARGUMENT;
    vireo_task_metadata_t checked;
    if (!wire || !actor || !owner || *owner || !op || m.operation != op || !actor->user_id ||
        !actor->session_id || !budget)
        goto done;
    rc = vireo_task_metadata_make(m.route, m.request_instance_id, m.operation, m.deadline_ns,
                                  &checked);
    if (rc != VIREO_OK)
        goto done;
    vireo_node_root_request_t request;
    vireo_node_root_issue_t issue;
    rc = vireo_node_root_request_decode(wire, size, &request, &issue);
    if (rc != VIREO_OK)
        goto done;
    rc = VIREO_RESULT_INVALID_ARGUMENT;
    if (!request.session_handle)
        goto done;
    rc = VIREO_RESULT_PROTOCOL;
    if (request.sequence != m.route.request_sequence)
        goto done;
    unsigned char bytes[56] = {0};
    memcpy(bytes, "VRT1", 4);
    put64(bytes + 8, actor->user_id);
    put64(bytes + 16, actor->session_id);
    memcpy(bytes + 24, wire, 32);
    rc = cancel ? vireo_task_create_copy_with_cancel(m, bytes, sizeof(bytes), budget, cancel, owner)
                : vireo_task_create_copy(m, bytes, sizeof(bytes), budget, owner);
done:
    errno = saved;
    return rc;
}

vireo_result_t vireo_directory_root_task_read(const vireo_task_t *task, uint32_t op,
                                              vireo_directory_root_input_t *out,
                                              vireo_node_root_issue_t *issue) {
    const int saved = errno;
    vireo_result_t rc = VIREO_RESULT_INVALID_ARGUMENT;
    if (issue)
        *issue = VIREO_NODE_ROOT_ISSUE_NONE;
    if (!task || !out || !issue || !op)
        goto done;
    vireo_task_info_t info;
    vireo_task_payload_view_t view;
    rc = vireo_task_inspect(task, &info);
    if (rc != VIREO_OK)
        goto done;
    rc = vireo_task_borrow_payload(task, &view);
    if (rc != VIREO_OK)
        goto done;
    rc = VIREO_RESULT_PROTOCOL;
    *issue = VIREO_NODE_ROOT_ISSUE_ENVELOPE;
    if (view.size != 56 || info.metadata.operation != op || memcmp(view.data, "VRT1\0\0\0\0", 8))
        goto done;
    vireo_directory_root_input_t next = {.metadata = info.metadata,
                                         .actor = {get64(view.data + 8), get64(view.data + 16)}};
    if (!next.actor.user_id || !next.actor.session_id)
        goto done;
    rc = vireo_node_root_request_decode(view.data + 24, 32, &next.request, issue);
    if (rc != VIREO_OK)
        goto done;
    rc = VIREO_RESULT_PROTOCOL;
    if (!next.request.session_handle ||
        next.request.sequence != info.metadata.route.request_sequence) {
        *issue = VIREO_NODE_ROOT_ISSUE_ENVELOPE;
        goto done;
    }
    *out = next;
    rc = VIREO_OK;
done:
    errno = saved;
    return rc;
}

static vireo_result_t native_root(void *c, vireo_mysql_node_repository_t *r,
                                  const vireo_mysql_node_actor_t *a, uint32_t timeout,
                                  vireo_directory_root_result_t *out, vireo_mysql_node_error_t *e) {
    (void)c;
    return vireo_directory_service_root(r, a, timeout, out, e);
}

vireo_result_t vireo_directory_root_task_execute_with(const vireo_task_t *task,
                                                      const vireo_directory_root_task_options_t *o,
                                                      vireo_mysql_node_repository_t *repo,
                                                      uint64_t now,
                                                      vireo_directory_root_task_result_t *out,
                                                      const vireo_directory_root_task_ops_t *ops) {
    const int saved = errno;
    vireo_result_t rc = VIREO_RESULT_INVALID_ARGUMENT;
    if (!task || !o || !repo || !out || !ops || !ops->root)
        goto done;
    memset(out, 0, sizeof(*out));
    out->stage = VIREO_DIRECTORY_ROOT_TASK_CONTEXT;
    if (!o->root_operation)
        goto completed;
    if (o->pool_timeout_ms > 60000) {
        rc = VIREO_RESULT_RANGE;
        goto completed;
    }
    out->stage = VIREO_DIRECTORY_ROOT_TASK_DECODE;
    rc = vireo_directory_root_task_read(task, o->root_operation, &out->input, &out->request_issue);
    if (out->request_issue == VIREO_NODE_ROOT_ISSUE_ENVELOPE)
        out->stage = VIREO_DIRECTORY_ROOT_TASK_MATCH;
    if (rc != VIREO_OK)
        goto completed;
    out->stage = VIREO_DIRECTORY_ROOT_TASK_CANCEL;
    bool cancelled = false;
    rc = vireo_task_is_cancel_requested(task, &cancelled);
    if (rc != VIREO_OK)
        goto completed;
    if (cancelled) {
        rc = VIREO_RESULT_CANCELLED;
        goto completed;
    }
    out->stage = VIREO_DIRECTORY_ROOT_TASK_DEADLINE;
    if (now >= out->input.metadata.deadline_ns) {
        rc = VIREO_RESULT_TIMEOUT;
        goto completed;
    }
    out->stage = VIREO_DIRECTORY_ROOT_TASK_SERVICE;
    rc = ops->root(ops->context, repo, &out->input.actor, o->pool_timeout_ms, &out->service,
                   &out->error);
completed:
    out->result = rc;
done:
    errno = saved;
    return rc;
}

vireo_result_t vireo_directory_root_task_execute(const vireo_task_t *task,
                                                 const vireo_directory_root_task_options_t *o,
                                                 vireo_mysql_node_repository_t *repo, uint64_t now,
                                                 vireo_directory_root_task_result_t *out) {
    const vireo_directory_root_task_ops_t ops = {NULL, native_root};
    return vireo_directory_root_task_execute_with(task, o, repo, now, out, &ops);
}
