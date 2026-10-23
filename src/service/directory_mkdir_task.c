/*
 * PROJECT : VIREO
 * FILE    : directory_mkdir_task.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-24
 * BRIEF   : 目录创建内部桥接与原线程所有权。
 */
#include <errno.h>
#include <string.h>
#include <vireo/base/secure_clear.h>
#include "directory_mkdir_task_internal.h"

/* 固定边界在调用前核验；不依赖C布局。 */
/** @brief 向已核定的8字节空间逐字节写大端整数。
 * @param[out] p 至少8字节，调用者持有。
 * @param[in] v 完整64位值，无窄化。
 * @note 仅同步借用有效独立地址，不保存指针；由外层入口保持errno。
 */
static void put64(unsigned char *p, uint64_t v) {
    for (size_t i = 0; i < 8; ++i)
        p[i] = (unsigned char)(v >> ((7 - i) * 8));
}
/** @brief 从已核定的8字节空间读取大端整数。
 * @param[in] p 至少8字节，无对齐要求。
 * @return 对应64位值，无失败路径。
 * @note 仅同步借用有效独立地址，不保存指针；由外层入口保持errno。
 */
static uint64_t get64(const unsigned char *p) {
    uint64_t v = 0;
    for (size_t i = 0; i < 8; ++i)
        v = (v << 8) | p[i];
    return v;
}

vireo_result_t vireo_directory_mkdir_task_create(vireo_task_metadata_t m, uint32_t op,
                                                 const unsigned char *wire, size_t size,
                                                 const vireo_mysql_node_actor_t *actor,
                                                 size_t budget, vireo_task_cancel_t *cancel,
                                                 vireo_task_t **owner) {
    const int saved = errno;
    vireo_result_t rc = VIREO_RESULT_INVALID_ARGUMENT;
    vireo_task_metadata_t checked;
    unsigned char bytes[347] = {0};
    vireo_node_mkdir_request_t request = {0};
    if (!wire || !actor || !owner || *owner || !op || m.operation != op || !actor->user_id ||
        !actor->session_id || !budget)
        goto done;
    rc = vireo_task_metadata_make(m.route, m.request_instance_id, m.operation, m.deadline_ns,
                                  &checked);
    if (rc != VIREO_OK)
        goto done;
    vireo_node_mkdir_issue_t issue;
    rc = vireo_node_mkdir_request_decode(wire, size, &request, &issue);
    if (rc != VIREO_OK)
        goto done;
    rc = VIREO_RESULT_INVALID_ARGUMENT;
    if (!request.session_handle)
        goto done;
    rc = VIREO_RESULT_PROTOCOL;
    if (request.sequence != m.route.request_sequence)
        goto done;
    memcpy(bytes, "VMT1", 4);
    put64(bytes + 8, actor->user_id);
    put64(bytes + 16, actor->session_id);
    memcpy(bytes + 24, wire, size);
    rc = cancel ? vireo_task_create_copy_with_cancel(m, bytes, 24 + size, budget, cancel, owner)
                : vireo_task_create_copy(m, bytes, 24 + size, budget, owner);
done:
    (void)vireo_secure_clear(bytes, sizeof(bytes));
    (void)vireo_secure_clear(&request, sizeof(request));
    errno = saved;
    return rc;
}

vireo_result_t vireo_directory_mkdir_task_read(const vireo_task_t *task, uint32_t op,
                                               vireo_directory_mkdir_input_t *out,
                                               vireo_node_mkdir_issue_t *issue) {
    const int saved = errno;
    vireo_directory_mkdir_input_t next = {0};
    vireo_result_t rc = VIREO_RESULT_INVALID_ARGUMENT;
    if (issue)
        *issue = VIREO_NODE_MKDIR_ISSUE_NONE;
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
    *issue = VIREO_NODE_MKDIR_ISSUE_ENVELOPE;
    if ((view.size < 93 || view.size > 347) || info.metadata.operation != op ||
        memcmp(view.data, "VMT1\0\0\0\0", 8))
        goto done;
    next = (vireo_directory_mkdir_input_t){.metadata = info.metadata,
                                           .actor = {get64(view.data + 8), get64(view.data + 16)}};
    if (!next.actor.user_id || !next.actor.session_id)
        goto done;
    rc = vireo_node_mkdir_request_decode(view.data + 24, view.size - 24, &next.request, issue);
    if (rc != VIREO_OK)
        goto done;
    rc = VIREO_RESULT_PROTOCOL;
    if (!next.request.session_handle ||
        next.request.sequence != info.metadata.route.request_sequence) {
        *issue = VIREO_NODE_MKDIR_ISSUE_ENVELOPE;
        goto done;
    }
    *out = next;
    rc = VIREO_OK;
done:
    (void)vireo_secure_clear(&next, sizeof(next));
    errno = saved;
    return rc;
}

/** @brief 私有注入接点转发到03公开服务，保持原报告与诊断。
 * @param[in] c 未使用的上下文；其余借用参数遵守03服务公共合同。
 * @param[out] out 原服务结果，不改变所有权。
 * @param[out] e 原去敏诊断。
 * @return 服务原rc；不重试或推断提交结局。
 * @note 仅同步借用有效独立地址，不保存指针；由外层入口保持errno。
 */
static vireo_result_t native_mkdir(void *c, vireo_mysql_node_repository_t *r,
                                   const vireo_mysql_node_actor_t *a,
                                   const vireo_mysql_node_mkdir_once_input_t *in, uint32_t timeout,
                                   vireo_directory_mkdir_result_t *out,
                                   vireo_mysql_node_error_t *e) {
    (void)c;
    return vireo_directory_service_mkdir(r, a, in, timeout, out, e);
}

vireo_result_t vireo_directory_mkdir_task_execute_with(
    const vireo_task_t *task, const vireo_directory_mkdir_task_options_t *o,
    vireo_mysql_node_repository_t *repo, const unsigned char request_id[16], uint64_t now,
    vireo_directory_mkdir_task_result_t *out, const vireo_directory_mkdir_task_ops_t *ops) {
    const int saved = errno;
    vireo_result_t rc = VIREO_RESULT_INVALID_ARGUMENT;
    if (!task || !o || !repo || !request_id || !out || !ops || !ops->mkdir)
        goto done;
    memset(out, 0, sizeof(*out));
    out->stage = VIREO_DIRECTORY_MKDIR_TASK_CONTEXT;
    unsigned char nonzero = 0;
    for (size_t i = 0; i < 16; ++i)
        nonzero |= request_id[i];
    if (!nonzero)
        goto completed;
    if (!o->mkdir_operation)
        goto completed;
    if (o->pool_timeout_ms > 60000) {
        rc = VIREO_RESULT_RANGE;
        goto completed;
    }
    out->stage = VIREO_DIRECTORY_MKDIR_TASK_DECODE;
    rc =
        vireo_directory_mkdir_task_read(task, o->mkdir_operation, &out->input, &out->request_issue);
    if (out->request_issue == VIREO_NODE_MKDIR_ISSUE_ENVELOPE)
        out->stage = VIREO_DIRECTORY_MKDIR_TASK_MATCH;
    if (rc != VIREO_OK)
        goto completed;
    memcpy(out->request_id, request_id, 16);
    out->stage = VIREO_DIRECTORY_MKDIR_TASK_CANCEL;
    bool cancelled = false;
    rc = vireo_task_is_cancel_requested(task, &cancelled);
    if (rc != VIREO_OK)
        goto completed;
    if (cancelled) {
        rc = VIREO_RESULT_CANCELLED;
        goto completed;
    }
    out->stage = VIREO_DIRECTORY_MKDIR_TASK_DEADLINE;
    if (now >= out->input.metadata.deadline_ns) {
        rc = VIREO_RESULT_TIMEOUT;
        goto completed;
    }
    out->stage = VIREO_DIRECTORY_MKDIR_TASK_SERVICE;
    vireo_mysql_node_mkdir_once_input_t in = {.parent_id = out->input.request.parent_id,
                                              .name = out->input.request.name,
                                              .name_length = out->input.request.name_length};
    memcpy(in.idempotency_key, out->input.request.idempotency_key, 16);
    memcpy(in.request_id, request_id, 16);
    rc = ops->mkdir(ops->context, repo, &out->input.actor, &in, o->pool_timeout_ms, &out->service,
                    &out->error);
    (void)vireo_secure_clear(&in, sizeof(in));
completed:
    out->result = rc;
done:
    errno = saved;
    return rc;
}

vireo_result_t vireo_directory_mkdir_task_execute(const vireo_task_t *task,
                                                  const vireo_directory_mkdir_task_options_t *o,
                                                  vireo_mysql_node_repository_t *repo,
                                                  const unsigned char request_id[16], uint64_t now,
                                                  vireo_directory_mkdir_task_result_t *out) {
    const vireo_directory_mkdir_task_ops_t ops = {NULL, native_mkdir};
    return vireo_directory_mkdir_task_execute_with(task, o, repo, request_id, now, out, &ops);
}
