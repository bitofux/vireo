/*
 * PROJECT : VIREO
 * FILE    : directory_root_completion.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-22
 * BRIEF   : 根查询内部桥接与原线程所有权。
 */
#include <errno.h>
#include <string.h>
#include "directory_root_completion_internal.h"

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
static void put32(unsigned char *p, uint32_t v) {
    for (size_t i = 0; i < 4; ++i)
        p[i] = (unsigned char)(v >> ((3 - i) * 8));
}
static uint32_t get32(const unsigned char *p) {
    uint32_t v = 0;
    for (size_t i = 0; i < 4; ++i)
        v = (v << 8) | p[i];
    return v;
}
static bool zero(const unsigned char *p, size_t n) {
    for (size_t i = 0; i < n; ++i)
        if (p[i])
            return false;
    return true;
}
static bool known(vireo_result_t rc) {
    return rc >= VIREO_OK && rc <= VIREO_RESULT_INTERNAL;
}
static bool db_zero(const vireo_mysql_error_t *e) {
    return !e->stage && !e->system_error && !e->mysql_code &&
           zero((const unsigned char *)e->sqlstate, sizeof(e->sqlstate));
}
static bool pool_zero(const vireo_mysql_pool_error_t *e) {
    return !e->stage && !e->pthread_code && !e->system_error && db_zero(&e->database);
}
static bool error_zero(const vireo_mysql_node_error_t *e) {
    return !e->stage && !e->system_errno && db_zero(&e->database) && pool_zero(&e->pool) &&
           !e->cleanup_result && !e->cleanup_stage && db_zero(&e->cleanup_database) &&
           pool_zero(&e->cleanup_pool);
}
static bool report_zero(const vireo_mysql_node_report_t *r) {
    return !r->found && !r->issue && !r->rollback_confirmed && !r->cleanup_pending;
}
static bool service_zero(const vireo_directory_root_result_t *s) {
    return !s->outcome && !s->root_node_id && !s->repository_called && !s->repository_result &&
           report_zero(&s->repository);
}
static bool input_same(const vireo_directory_root_input_t *a,
                       const vireo_directory_root_input_t *b) {
    bool same = false;
    return vireo_task_metadata_same_request(a->metadata, b->metadata, &same) == VIREO_OK && same &&
           a->metadata.operation == b->metadata.operation &&
           a->metadata.deadline_ns == b->metadata.deadline_ns &&
           a->actor.user_id == b->actor.user_id && a->actor.session_id == b->actor.session_id &&
           a->request.sequence == b->request.sequence &&
           a->request.session_handle == b->request.session_handle;
}
static bool pair(vireo_result_t rc, vireo_status_t status) {
    switch (rc) {
        case VIREO_OK:
            return status == VIREO_STATUS_OK;
        case VIREO_RESULT_NOT_FOUND:
            return status == VIREO_STATUS_UNAUTHORIZED;
        case VIREO_RESULT_BUSY:
            return status == VIREO_STATUS_BUSY || status == VIREO_STATUS_INTERNAL_ERROR;
        case VIREO_RESULT_TIMEOUT:
            return status == VIREO_STATUS_TIMEOUT || status == VIREO_STATUS_INTERNAL_ERROR;
        case VIREO_RESULT_NO_MEMORY:
            return status == VIREO_STATUS_OVERLOADED || status == VIREO_STATUS_INTERNAL_ERROR;
        case VIREO_RESULT_CANCELLED:
            return status == VIREO_STATUS_UNAVAILABLE || status == VIREO_STATUS_INTERNAL_ERROR;
        default:
            return known(rc) && status == VIREO_STATUS_INTERNAL_ERROR;
    }
}
/* 完整成功/拒绝才允许业务投影；其余非OK保留基础设施语义。 */
static bool project(const vireo_directory_root_task_result_t *r, vireo_node_root_response_t *out) {
    if (!known(r->result) || r->request_issue != VIREO_NODE_ROOT_ISSUE_NONE)
        return false;
    switch (r->stage) {
        case VIREO_DIRECTORY_ROOT_TASK_CONTEXT:
            break;
        case VIREO_DIRECTORY_ROOT_TASK_CANCEL:
            if (r->result != VIREO_RESULT_CANCELLED)
                return false;
            break;
        case VIREO_DIRECTORY_ROOT_TASK_DEADLINE:
            if (r->result != VIREO_RESULT_TIMEOUT)
                return false;
            break;
        case VIREO_DIRECTORY_ROOT_TASK_SERVICE:
            break;
        default:
            return false;
    }
    const vireo_directory_root_result_t *s = &r->service;
    const bool cleanup = r->error.cleanup_result != VIREO_OK || s->repository.cleanup_pending;
    out->sequence = r->input.request.sequence;
    out->status = VIREO_STATUS_INTERNAL_ERROR;
    if (r->stage != VIREO_DIRECTORY_ROOT_TASK_SERVICE) {
        if (r->result == VIREO_OK || r->result == VIREO_RESULT_NOT_FOUND || !service_zero(s) ||
            !error_zero(&r->error))
            return false;
    } else {
        if (!known(s->repository_result) || !known(r->error.cleanup_result))
            return false;
        if (!s->repository_called &&
            (!report_zero(&s->repository) || s->repository_result != VIREO_OK))
            return false;
        if (r->result == VIREO_OK || r->result == VIREO_RESULT_NOT_FOUND) {
            if (!s->repository_called || cleanup || !s->repository.rollback_confirmed ||
                s->repository_result != r->result)
                return false;
            if (r->result == VIREO_OK) {
                if (s->outcome != VIREO_DIRECTORY_ROOT_FOUND || !s->root_node_id ||
                    !s->repository.found || s->repository.issue != VIREO_MYSQL_NODE_ISSUE_NONE)
                    return false;
                out->status = VIREO_STATUS_OK;
                out->session_handle = r->input.request.session_handle;
                out->root_node_id = s->root_node_id;
                return true;
            }
            if (s->root_node_id || s->repository.found ||
                s->outcome != VIREO_DIRECTORY_ROOT_UNAUTHORIZED ||
                s->repository.issue != VIREO_MYSQL_NODE_AUTH_REJECTED)
                return false;
            out->status = VIREO_STATUS_UNAUTHORIZED;
            return true;
        }
        if (s->outcome != VIREO_DIRECTORY_ROOT_NONE || s->root_node_id)
            return false;
    }
    if (!cleanup) {
        if (r->result == VIREO_RESULT_NO_MEMORY)
            out->status = VIREO_STATUS_OVERLOADED;
        if (r->result == VIREO_RESULT_BUSY)
            out->status = VIREO_STATUS_BUSY;
        if (r->result == VIREO_RESULT_TIMEOUT)
            out->status = VIREO_STATUS_TIMEOUT;
        if (r->result == VIREO_RESULT_CANCELLED)
            out->status = VIREO_STATUS_UNAVAILABLE;
    }
    return true;
}

vireo_result_t vireo_directory_root_completion_publish_with(
    const vireo_task_t *task, uint32_t op, const vireo_directory_root_task_result_t *result,
    size_t budget, vireo_completion_queue_t *queue, vireo_notifier_t *notifier,
    vireo_completion_t **remaining, vireo_directory_root_completion_publish_report_t *report,
    vireo_directory_root_publish_fn publish) {
    const int saved = errno;
    vireo_result_t rc = VIREO_RESULT_INVALID_ARGUMENT;
    if (report)
        memset(report, 0, sizeof(*report));
    if (!task || !op || !result || !budget || !queue || !notifier || !remaining || *remaining ||
        !report || !publish)
        goto done;
    vireo_directory_root_input_t input;
    vireo_node_root_issue_t issue;
    rc = vireo_directory_root_task_read(task, op, &input, &issue);
    if (rc != VIREO_OK)
        goto done;
    rc = VIREO_RESULT_PROTOCOL;
    if (!input_same(&input, &result->input))
        goto done;
    report->task_matched = true;
    vireo_node_root_response_t response = {0};
    rc = VIREO_RESULT_INVALID_ARGUMENT;
    if (!project(result, &response))
        goto done;
    unsigned char payload[76] = {0};
    size_t size = 0;
    rc = vireo_node_root_response_encode(&response, payload + 32, sizeof(payload) - 32, &size);
    if (rc != VIREO_OK)
        goto done;
    report->result_validated = true;
    memcpy(payload, "VRC1", 4);
    put64(payload + 8, input.actor.user_id);
    put64(payload + 16, input.actor.session_id);
    put32(payload + 24, input.request.session_handle);
    put32(payload + 28, (uint32_t)size);
    report->publish_called = true;
    rc = publish(task, result->result, response.status, payload, 32 + size, budget, queue, notifier,
                 remaining, &report->publication);
done:
    errno = saved;
    return rc;
}

vireo_result_t vireo_directory_root_completion_publish(
    const vireo_task_t *task, uint32_t op, const vireo_directory_root_task_result_t *result,
    size_t budget, vireo_completion_queue_t *queue, vireo_notifier_t *notifier,
    vireo_completion_t **remaining, vireo_directory_root_completion_publish_report_t *report) {
    return vireo_directory_root_completion_publish_with(task, op, result, budget, queue, notifier,
                                                        remaining, report,
                                                        vireo_completion_copy_wait_publish);
}

vireo_result_t vireo_directory_root_completion_decode(
    const vireo_completion_t *completion, uint32_t op,
    vireo_directory_root_completion_outcome_t *out) {
    const int saved = errno;
    vireo_result_t rc = VIREO_RESULT_INVALID_ARGUMENT;
    if (!completion || !op || !out)
        goto done;
    vireo_completion_info_t info;
    vireo_completion_payload_view_t view;
    rc = vireo_completion_inspect(completion, &info);
    if (rc != VIREO_OK)
        goto done;
    rc = vireo_completion_borrow_payload(completion, &view);
    if (rc != VIREO_OK)
        goto done;
    rc = VIREO_RESULT_PROTOCOL;
    if ((view.size != 64 && view.size != 76) || info.metadata.request.operation != op ||
        memcmp(view.data, "VRC1\0\0\0\0", 8))
        goto done;
    const uint32_t size = get32(view.data + 28);
    if ((size != 32 && size != 44) || view.size != 32 + (size_t)size)
        goto done;
    vireo_directory_root_completion_outcome_t next = {
        .metadata = info.metadata,
        .actor = {get64(view.data + 8), get64(view.data + 16)},
        .request_session_handle = get32(view.data + 24)};
    if (!next.actor.user_id || !next.actor.session_id || !next.request_session_handle)
        goto done;
    vireo_node_root_issue_t issue;
    rc = vireo_node_root_response_decode(view.data + 32, size, &next.response, &issue);
    if (rc != VIREO_OK)
        goto done;
    rc = VIREO_RESULT_PROTOCOL;
    if (next.response.sequence != info.metadata.request.route.request_sequence ||
        next.response.status != info.metadata.suggested_status ||
        !pair(info.metadata.result, next.response.status))
        goto done;
    if (next.response.status == VIREO_STATUS_OK &&
        (next.response.session_handle != next.request_session_handle ||
         !next.response.root_node_id))
        goto done;
    *out = next;
    rc = VIREO_OK;
done:
    errno = saved;
    return rc;
}
