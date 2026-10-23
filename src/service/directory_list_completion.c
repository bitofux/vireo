/* PROJECT : VIREO; FILE : directory_list_completion.c; AUTHOR : bitofux;
 * DATE : 2026-10-23; BRIEF : 原请求配对、领域事实核验及整页VLC1独立回投。 */
#include <errno.h>
#include <stdlib.h>
#include <vireo/base/secure_clear.h>
#include "directory_list_completion_internal.h"
#include "directory_list_task_internal.h"

typedef struct list_publication_workspace {
    vireo_node_list_response_t response; /**< 逐字段投影，不复制DB宿主表示。 */
    unsigned char payload[VIREO_DIRECTORY_LIST_COMPLETION_PAYLOAD_MAX]; /**< 内部前缀及wire。 */
} list_publication_workspace_t;
_Static_assert(sizeof(list_publication_workspace_t) <=
                   VIREO_DIRECTORY_LIST_COMPLETION_WORKSPACE_MAX,
               "LIST publication workspace hard bound");
_Static_assert(sizeof(list_publication_workspace_t) <= 49152, "LIST workspace target");
_Static_assert(sizeof(vireo_directory_list_completion_outcome_t) <= 24576, "LIST decode budget");

static bool known(vireo_result_t rc) {
    return (unsigned)rc <= (unsigned)VIREO_RESULT_INTERNAL;
}
static bool db_zero(const vireo_mysql_error_t *e) {
    return !e->stage && !e->system_error && !e->mysql_code &&
           vireo_list_zero(e->sqlstate, sizeof(e->sqlstate));
}
static bool pool_zero(const vireo_mysql_pool_error_t *e) {
    return !e->stage && !e->pthread_code && !e->system_error && db_zero(&e->database);
}
static bool node_error_zero(const vireo_mysql_node_error_t *e) {
    return !e->stage && !e->system_errno && db_zero(&e->database) && pool_zero(&e->pool) &&
           !e->cleanup_result && !e->cleanup_stage && db_zero(&e->cleanup_database) &&
           pool_zero(&e->cleanup_pool);
}
static bool report_zero(const vireo_mysql_node_report_t *p) {
    return !p->found && !p->issue && !p->rollback_confirmed && !p->cleanup_pending;
}
static bool node_zero(const vireo_mysql_node_value_t *v) {
    return !v->id && !v->owner_id && !v->parent_id && !v->has_parent && !v->name_length &&
           vireo_list_zero(v->name, sizeof(v->name)) && !v->kind && !v->has_object_hash &&
           vireo_list_zero(v->object_hash, sizeof(v->object_hash)) && !v->size &&
           !v->created_at_ms && !v->updated_at_ms;
}
static bool page_zero(const vireo_mysql_node_page_t *p) {
    if (p->count || p->has_more || p->next_after_id)
        return false;
    for (size_t i = 0; i < VIREO_MYSQL_NODE_PAGE_CAPACITY; ++i)
        if (!node_zero(&p->nodes[i]))
            return false;
    return true;
}
static bool db_known(const vireo_mysql_error_t *e) {
    return (unsigned)e->stage <= (unsigned)VIREO_MYSQL_STAGE_CONNECTION_RESET;
}
static bool pool_known(const vireo_mysql_pool_error_t *e) {
    return (unsigned)e->stage <= (unsigned)VIREO_MYSQL_POOL_STAGE_DESTROY && db_known(&e->database);
}
static bool error_known(const vireo_directory_list_error_t *e) {
    const vireo_mysql_node_error_t *n = &e->repository;
    return (unsigned)e->stage <= (unsigned)VIREO_DIRECTORY_LIST_STAGE_TOKEN_REVALIDATE &&
           (unsigned)n->stage <= (unsigned)VIREO_MYSQL_NODE_STAGE_OBJECT_UPDATE &&
           (unsigned)n->cleanup_stage <= (unsigned)VIREO_MYSQL_NODE_STAGE_OBJECT_UPDATE &&
           known(n->cleanup_result) && db_known(&n->database) && pool_known(&n->pool) &&
           db_known(&n->cleanup_database) && pool_known(&n->cleanup_pool);
}

static vireo_status_t base_status(vireo_result_t rc) {
    switch (rc) {
        case VIREO_RESULT_BUSY:
            return VIREO_STATUS_BUSY;
        case VIREO_RESULT_TIMEOUT:
            return VIREO_STATUS_TIMEOUT;
        case VIREO_RESULT_CANCELLED:
            return VIREO_STATUS_UNAVAILABLE;
        case VIREO_RESULT_NO_MEMORY:
            return VIREO_STATUS_OVERLOADED;
        default:
            return VIREO_STATUS_INTERNAL_ERROR;
    }
}

/**
 * @brief 核验阶段/初验token/repository/清理事实，给合法结果选择状态。
 * @param[in] r 稳定原执行值，借至返回；不重新查询身份或验MAC。
 * @param[out] status 仅true时写入；不是原执行返回码的强制转换。
 * @retval true 领域结果有匹配原始事实，或基础故障能安全投影。
 * @retval false 发现矛盾、未知枚举或半页，不允许降级后继续发布。
 * @note 无分配/I/O；不修改输入。清理历史先于业务投影，不抹去原首因。
 */
static bool project_status(const vireo_directory_list_task_result_t *r, vireo_status_t *status) {
    const vireo_directory_list_result_t *s = &r->service;
    const vireo_directory_list_error_t *e = &r->error;
    const vireo_mysql_node_report_t *p = &s->repository;
    const bool has_token = r->input.request.has_page_token;
    if (!known(r->result) || !known(s->repository_result) || !known(s->token_result) ||
        !error_known(e) || (unsigned)r->stage > (unsigned)VIREO_DIRECTORY_LIST_TASK_SERVICE ||
        (unsigned)r->request_issue > (unsigned)VIREO_NODE_LIST_ISSUE_VALUE ||
        (unsigned)s->outcome > (unsigned)VIREO_DIRECTORY_LIST_BAD_TOKEN ||
        (unsigned)s->repository_operation > (unsigned)VIREO_DIRECTORY_LIST_REPOSITORY_AUTH_PROBE ||
        (unsigned)p->issue > (unsigned)VIREO_MYSQL_NODE_OBJECT_REFERENCE_INVALID)
        return false;
    if (s->outcome != VIREO_DIRECTORY_LIST_PAGE &&
        (!page_zero(&s->page) || !vireo_list_zero(s->next_page_token.bytes, 96)))
        return false;
    if (r->stage != VIREO_DIRECTORY_LIST_TASK_SERVICE) {
        if (r->result == VIREO_OK || s->outcome || s->repository_operation ||
            s->repository_result || !report_zero(p) || s->token_checked || s->token_result ||
            e->stage || e->system_errno || !node_error_zero(&e->repository) || r->request_issue)
            return false;
        if (!((r->stage == VIREO_DIRECTORY_LIST_TASK_CONTEXT) ||
              (r->stage == VIREO_DIRECTORY_LIST_TASK_CANCEL &&
               r->result == VIREO_RESULT_CANCELLED) ||
              (r->stage == VIREO_DIRECTORY_LIST_TASK_DEADLINE &&
               r->result == VIREO_RESULT_TIMEOUT)))
            return false;
        *status = base_status(r->result);
        return true;
    }
    if (r->request_issue)
        return false;
    /* 初次verify、repo用途、是否实际查询构成一组事实。 */
    if (!has_token) {
        if (s->token_checked || s->token_result ||
            s->repository_operation == VIREO_DIRECTORY_LIST_REPOSITORY_AUTH_PROBE)
            return false;
    } else if (!s->token_checked) {
        if (s->token_result || s->repository_operation)
            return false;
    } else if (s->token_result == VIREO_RESULT_PROTOCOL) {
        if (s->repository_operation != VIREO_DIRECTORY_LIST_REPOSITORY_AUTH_PROBE)
            return false;
    } else if (s->token_result == VIREO_OK) {
        if (s->repository_operation != VIREO_DIRECTORY_LIST_REPOSITORY_CHILDREN)
            return false;
    } else if (s->repository_operation || s->outcome)
        return false;
    if (!s->repository_operation &&
        (s->repository_result || !report_zero(p) || !node_error_zero(&e->repository)))
        return false;
    const bool cleanup_bad = e->repository.cleanup_result != VIREO_OK || p->cleanup_pending;
    if (cleanup_bad) {
        if (s->outcome || r->result == VIREO_OK)
            return false;
        const vireo_result_t expected =
            e->repository.cleanup_result != VIREO_OK
                ? (e->repository.cleanup_result == VIREO_RESULT_NOT_FOUND
                       ? VIREO_RESULT_INTERNAL
                       : e->repository.cleanup_result)
                : ((s->repository_result == VIREO_OK ||
                    s->repository_result == VIREO_RESULT_NOT_FOUND)
                       ? VIREO_RESULT_INTERNAL
                       : s->repository_result);
        if (!s->repository_operation || r->result != expected)
            return false;
        *status = VIREO_STATUS_INTERNAL_ERROR;
        return true;
    }
    const bool read_ok = s->repository_operation && s->repository_result == VIREO_OK && p->found &&
                         !p->issue && p->rollback_confirmed;
    const bool missed = s->repository_operation && s->repository_result == VIREO_RESULT_NOT_FOUND &&
                        !p->found && p->rollback_confirmed;
    switch (s->outcome) {
        case VIREO_DIRECTORY_LIST_PAGE:
            if (r->result != VIREO_OK || !read_ok ||
                s->repository_operation != VIREO_DIRECTORY_LIST_REPOSITORY_CHILDREN || e->stage ||
                e->system_errno || !node_error_zero(&e->repository))
                return false;
            *status = VIREO_STATUS_OK;
            return true;
        case VIREO_DIRECTORY_LIST_UNAUTHORIZED:
            if (r->result != VIREO_RESULT_NOT_FOUND || !missed ||
                p->issue != VIREO_MYSQL_NODE_AUTH_REJECTED)
                return false;
            *status = VIREO_STATUS_UNAUTHORIZED;
            return true;
        case VIREO_DIRECTORY_LIST_NOT_FOUND:
            if (r->result != VIREO_RESULT_NOT_FOUND || !missed ||
                s->repository_operation != VIREO_DIRECTORY_LIST_REPOSITORY_CHILDREN ||
                p->issue != VIREO_MYSQL_NODE_NOT_FOUND)
                return false;
            *status = VIREO_STATUS_NOT_FOUND;
            return true;
        case VIREO_DIRECTORY_LIST_BAD_TOKEN:
            if (r->result != VIREO_RESULT_PROTOCOL || !has_token || !s->token_checked)
                return false;
            if (s->token_result == VIREO_RESULT_PROTOCOL) {
                if (!read_ok && !(missed && p->issue == VIREO_MYSQL_NODE_NOT_FOUND))
                    return false;
            } else if (s->token_result != VIREO_OK || !read_ok ||
                       e->stage != VIREO_DIRECTORY_LIST_STAGE_TOKEN_REVALIDATE)
                return false;
            *status = VIREO_STATUS_BAD_REQUEST;
            return true;
        case VIREO_DIRECTORY_LIST_NONE:
            if (r->result == VIREO_OK)
                return false;
            *status = base_status(r->result);
            return true;
    }
    return false;
}

/**
 * @brief 把有效页前缀逐字段投影到已清零的协议DTO。
 * @param[in] r 原SERVICE/PAGE结果，短借，先核count再索引末项。
 * @param[out] response 独占已清零工作区；false可保留本地部分投影，不得发布。
 * @retval true 通过本层owner/parent/页游标检查，其余形状还须公开codec确认。
 * @retval false 请求/页不配，caller须擦除整个临时工作区。
 * @note 不复制宿主padding、未用槽或名字尾部；无分配或跨线程发布。
 */
static bool project_page(const vireo_directory_list_task_result_t *r,
                         vireo_node_list_response_t *response) {
    const vireo_mysql_node_page_t *p = &r->service.page;
    const vireo_node_list_request_t *q = &r->input.request;
    if (p->count > q->page_size ||
        (p->has_more
             ? (!p->count || p->count != q->page_size ||
                p->next_after_id != p->nodes[p->count - 1].id)
             : (p->next_after_id || !vireo_list_zero(r->service.next_page_token.bytes, 96))))
        return false;
    response->session_handle = q->session_handle;
    response->directory_id = q->directory_id;
    response->page_size = q->page_size;
    response->count = p->count;
    response->has_more = p->has_more;
    if (p->has_more)
        memcpy(response->next_page_token, r->service.next_page_token.bytes, 96);
    for (size_t i = 0; i < p->count; ++i) {
        const vireo_mysql_node_value_t *v = &p->nodes[i];
        vireo_node_list_entry_t *d = &response->entries[i];
        if (v->owner_id != r->input.actor.user_id || !v->has_parent ||
            v->parent_id != q->directory_id || !v->name_length || v->name_length > 255 ||
            (v->kind != VIREO_MYSQL_NODE_DIRECTORY && v->kind != VIREO_MYSQL_NODE_FILE))
            return false;
        d->node_id = v->id;
        d->parent_id = v->parent_id;
        d->name_length = v->name_length;
        memcpy(d->name, v->name, v->name_length);
        d->type = v->kind == VIREO_MYSQL_NODE_DIRECTORY ? VIREO_NODE_LIST_DIRECTORY
                                                        : VIREO_NODE_LIST_FILE;
        d->size = v->size;
        d->created_at_ms = v->created_at_ms;
        d->updated_at_ms = v->updated_at_ms;
        d->has_object_hash = v->has_object_hash;
        memcpy(d->object_hash, v->object_hash, 32);
    }
    /* 其余顺序/名称/时间/类型/hash不变量交同一公开codec核验。 */
    return true;
}

static void *native_alloc(void *c, size_t n) {
    (void)c;
    return malloc(n);
}
static void native_free(void *c, void *p) {
    (void)c;
    free(p);
}
static vireo_result_t native_publish(void *c, const vireo_task_t *t, vireo_result_t r,
                                     vireo_status_t s, const void *p, size_t n, size_t b,
                                     vireo_completion_queue_t *q, vireo_notifier_t *f,
                                     vireo_completion_t **o,
                                     vireo_completion_publish_report_t *report) {
    (void)c;
    return vireo_completion_copy_wait_publish(t, r, s, p, n, b, q, f, o, report);
}
static const vireo_directory_list_completion_ops_t native_ops = {NULL, native_alloc, native_free,
                                                                 native_publish};

vireo_result_t vireo_directory_list_completion_publish_with(
    const vireo_task_t *task, uint32_t operation, const vireo_directory_list_task_result_t *result,
    size_t budget, vireo_completion_queue_t *queue, vireo_notifier_t *notifier,
    vireo_completion_t **remaining, vireo_directory_list_completion_publish_report_t *report,
    const vireo_directory_list_completion_ops_t *ops) {
    const int saved = errno;
    vireo_result_t rc = VIREO_RESULT_INVALID_ARGUMENT;
    vireo_directory_list_input_t input = {0};
    vireo_node_list_issue_t issue;
    vireo_status_t status = 0;
    list_publication_workspace_t *w = NULL;
    if (report)
        memset(report, 0, sizeof(*report));
    if (!task || !operation || !result || !budget || !queue || !notifier || !remaining ||
        *remaining || !report || !ops || !ops->allocate || !ops->release || !ops->publish)
        goto done;
    rc = vireo_directory_list_task_read(task, operation, &input, &issue);
    if (rc != VIREO_OK)
        goto done;
    if (!vireo_list_same_input(&input, &result->input)) {
        rc = VIREO_RESULT_PROTOCOL;
        goto done;
    }
    report->task_matched = true;
    rc = VIREO_RESULT_INVALID_ARGUMENT;
    if (!project_status(result, &status))
        goto done;
    w = ops->allocate(ops->context, sizeof(*w));
    if (!w) {
        rc = VIREO_RESULT_NO_MEMORY;
        goto done;
    }
    memset(w, 0, sizeof(*w));
    w->response.status = status;
    w->response.sequence = input.request.sequence;
    if (status == VIREO_STATUS_OK && !project_page(result, &w->response))
        goto done;
    size_t frame_size = 0;
    rc = vireo_node_list_response_encode(&w->response, w->payload + 48,
                                         VIREO_NODE_LIST_RESPONSE_FRAME_MAX, &frame_size);
    if (rc != VIREO_OK)
        goto done;
    report->result_validated = true;
    memcpy(w->payload, "VLC1", 4);
    vireo_list_write_be(w->payload + 8, 8, input.actor.user_id);
    vireo_list_write_be(w->payload + 16, 8, input.actor.session_id);
    vireo_list_write_be(w->payload + 24, 4, input.request.session_handle);
    vireo_list_write_be(w->payload + 28, 4, frame_size);
    vireo_list_write_be(w->payload + 32, 8, input.request.directory_id);
    vireo_list_write_be(w->payload + 40, 2, input.request.page_size);
    w->payload[42] = input.request.has_page_token ? 1 : 0;
    report->publish_called = true;
    rc = ops->publish(ops->context, task, result->result, status, w->payload, 48 + frame_size,
                      budget, queue, notifier, remaining, &report->publication);
done:
    if (w) {
        (void)vireo_secure_clear(w, sizeof(*w));
        ops->release(ops->context, w);
    }
    (void)vireo_secure_clear(&input, sizeof(input));
    errno = saved;
    return rc;
}

vireo_result_t vireo_directory_list_completion_publish(
    const vireo_task_t *task, uint32_t operation, const vireo_directory_list_task_result_t *result,
    size_t budget, vireo_completion_queue_t *queue, vireo_notifier_t *notifier,
    vireo_completion_t **remaining, vireo_directory_list_completion_publish_report_t *report) {
    return vireo_directory_list_completion_publish_with(task, operation, result, budget, queue,
                                                        notifier, remaining, report, &native_ops);
}

static bool status_pair(vireo_result_t rc, vireo_status_t status, bool token) {
    if (!known(rc))
        return false;
    if (rc == VIREO_OK)
        return status == VIREO_STATUS_OK;
    if (rc == VIREO_RESULT_NOT_FOUND)
        return status == VIREO_STATUS_NOT_FOUND || status == VIREO_STATUS_UNAUTHORIZED ||
               status == VIREO_STATUS_INTERNAL_ERROR;
    if (rc == VIREO_RESULT_PROTOCOL)
        return status == VIREO_STATUS_INTERNAL_ERROR ||
               (token && status == VIREO_STATUS_BAD_REQUEST);
    return status == VIREO_STATUS_INTERNAL_ERROR || status == base_status(rc);
}

vireo_result_t vireo_directory_list_completion_decode(
    const vireo_completion_t *completion, uint32_t operation,
    vireo_directory_list_completion_outcome_t *out) {
    const int saved = errno;
    vireo_result_t rc = VIREO_RESULT_INVALID_ARGUMENT;
    vireo_completion_info_t info;
    vireo_completion_payload_view_t view;
    vireo_directory_list_completion_outcome_t candidate = {0};
    vireo_node_list_issue_t issue;
    if (!completion || !operation || !out)
        goto done;
    rc = vireo_completion_inspect(completion, &info);
    if (rc != VIREO_OK)
        goto done;
    rc = vireo_completion_borrow_payload(completion, &view);
    if (rc != VIREO_OK)
        goto done;
    rc = VIREO_RESULT_PROTOCOL;
    if (view.size < 80 || view.size > VIREO_DIRECTORY_LIST_COMPLETION_PAYLOAD_MAX ||
        memcmp(view.data, "VLC1", 4) || !vireo_list_zero(view.data + 4, 4) ||
        !vireo_list_zero(view.data + 43, 5) || view.data[42] > 1 ||
        info.metadata.request.operation != operation)
        goto done;
    const uint64_t size = vireo_list_read_be(view.data + 28, 4);
    if (size != view.size - 48 || (size != 32 && (size < 50 || size > 23510)))
        goto done;
    candidate.metadata = info.metadata;
    candidate.actor.user_id = vireo_list_read_be(view.data + 8, 8);
    candidate.actor.session_id = vireo_list_read_be(view.data + 16, 8);
    candidate.request_session_handle = (uint32_t)vireo_list_read_be(view.data + 24, 4);
    candidate.request_directory_id = vireo_list_read_be(view.data + 32, 8);
    candidate.request_page_size = (uint16_t)vireo_list_read_be(view.data + 40, 2);
    candidate.request_has_page_token = view.data[42] == 1;
    if (!candidate.actor.user_id || !candidate.actor.session_id ||
        !candidate.request_session_handle || !candidate.request_directory_id ||
        !candidate.request_page_size || candidate.request_page_size > 64)
        goto done;
    rc = vireo_node_list_response_decode(view.data + 48, (size_t)size, &candidate.response, &issue);
    if (rc != VIREO_OK)
        goto done;
    rc = VIREO_RESULT_PROTOCOL;
    const vireo_node_list_response_t *p = &candidate.response;
    if (p->sequence != info.metadata.request.route.request_sequence ||
        p->status != info.metadata.suggested_status ||
        !status_pair(info.metadata.result, p->status, candidate.request_has_page_token))
        goto done;
    if (p->status == VIREO_STATUS_OK && (p->session_handle != candidate.request_session_handle ||
                                         p->directory_id != candidate.request_directory_id ||
                                         p->page_size != candidate.request_page_size))
        goto done;
    *out = candidate;
    rc = VIREO_OK;
done:
    (void)vireo_secure_clear(&candidate, sizeof(candidate));
    errno = saved;
    return rc;
}
