/*
 * PROJECT : VIREO
 * FILE    : directory_move_completion.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-25
 * BRIEF   : 目录移动内部桥接与原线程所有权。
 */
#include <errno.h>
#include <string.h>
#include <vireo/base/secure_clear.h>
#include "directory_move_completion_internal.h"

/** @brief 向调用者已核定的8字节空间写大端值。
 * @param[out] p 借用至少8字节；无对齐要求。
 * @param[in] v 完整值。
 * @note 仅同步借用有效独立地址，不保存指针；由外层入口保持errno。
 */
static void put64(unsigned char *p, uint64_t v) {
    for (size_t i = 0; i < 8; ++i)
        p[i] = (unsigned char)(v >> ((7 - i) * 8));
}
/** @brief 读取调用者已核定的8字节大端值。
 * @param[in] p 借用至少8字节；无对齐要求。
 * @return 完整值，无失败路径。
 * @note 仅同步借用有效独立地址，不保存指针；由外层入口保持errno。
 */
static uint64_t get64(const unsigned char *p) {
    uint64_t v = 0;
    for (size_t i = 0; i < 8; ++i)
        v = (v << 8) | p[i];
    return v;
}
/** @brief 向调用者已核定的4字节空间写大端值。
 * @param[out] p 借用至少4字节。
 * @param[in] v 已核帧长或句柄。
 * @note 仅同步借用有效独立地址，不保存指针；由外层入口保持errno。
 */
static void put32(unsigned char *p, uint32_t v) {
    for (size_t i = 0; i < 4; ++i)
        p[i] = (unsigned char)(v >> ((3 - i) * 8));
}
/** @brief 读取调用者已核定的4字节大端值。
 * @param[in] p 借用至少4字节。
 * @return 完整值，无失败路径。
 * @note 仅同步借用有效独立地址，不保存指针；由外层入口保持errno。
 */
static uint32_t get32(const unsigned char *p) {
    uint32_t v = 0;
    for (size_t i = 0; i < 4; ++i)
        v = (v << 8) | p[i];
    return v;
}
/** @brief 检查语义字段是否全零，不读取结构padding。
 * @param[in] p 借用至少n字节。
 * @param[in] n 有效空间长度。
 * @return 所有字节为零时true；不写输入。
 * @note 仅同步借用有效独立地址，不保存指针；由外层入口保持errno。
 */
static bool zero(const unsigned char *p, size_t n) {
    for (size_t i = 0; i < n; ++i)
        if (p[i])
            return false;
    return true;
}
static bool known(vireo_result_t rc) {
    return rc >= VIREO_OK && rc <= VIREO_RESULT_INTERNAL;
}
/** @brief 逐公开字段判断数据库诊断为空。
 * @param[in] e 有效只读诊断。
 * @return 所有诊断字段为空时true；忽略padding。
 * @note 仅同步借用有效独立地址，不保存指针；由外层入口保持errno。
 */
static bool db_zero(const vireo_mysql_error_t *e) {
    return !e->stage && !e->system_error && !e->mysql_code &&
           zero((const unsigned char *)e->sqlstate, sizeof(e->sqlstate));
}
/* Only declared diagnostic enum values may cross the projection gate. */
static bool db_known(const vireo_mysql_error_t *e) {
    return e->stage >= VIREO_MYSQL_STAGE_NONE && e->stage <= VIREO_MYSQL_STAGE_CONNECTION_RESET;
}
static bool pool_known(const vireo_mysql_pool_error_t *e) {
    return e->stage >= VIREO_MYSQL_POOL_STAGE_NONE && e->stage <= VIREO_MYSQL_POOL_STAGE_DESTROY &&
           db_known(&e->database);
}
static bool error_known(const vireo_mysql_node_error_t *e) {
    return e->stage >= VIREO_MYSQL_NODE_STAGE_NONE &&
           e->stage <= VIREO_MYSQL_NODE_STAGE_RECEIPT_INSERT &&
           e->cleanup_stage >= VIREO_MYSQL_NODE_STAGE_NONE &&
           e->cleanup_stage <= VIREO_MYSQL_NODE_STAGE_RECEIPT_INSERT && db_known(&e->database) &&
           db_known(&e->cleanup_database) && pool_known(&e->pool) && pool_known(&e->cleanup_pool);
}
/** @brief 逐字段判断池及内嵌数据库诊断为空。
 * @param[in] e 有效只读诊断。
 * @return 全空时true；不比较padding。
 * @note 仅同步借用有效独立地址，不保存指针；由外层入口保持errno。
 */
static bool pool_zero(const vireo_mysql_pool_error_t *e) {
    return !e->stage && !e->pthread_code && !e->system_error && db_zero(&e->database);
}
/** @brief 判断工作与历史清理诊断均为空。
 * @param[in] e 有效只读诊断。
 * @return 各语义字段为空时true。
 * @note 仅同步借用有效独立地址，不保存指针；由外层入口保持errno。
 */
static bool error_zero(const vireo_mysql_node_error_t *e) {
    return !e->stage && !e->system_errno && db_zero(&e->database) && pool_zero(&e->pool) &&
           !e->cleanup_result && !e->cleanup_stage && db_zero(&e->cleanup_database) &&
           pool_zero(&e->cleanup_pool);
}
/** @brief 判断未调用repo时应有的零写报告。
 * @param[in] r 有效只读报告。
 * @return 所有原写事实均为空时true。
 * @note 仅同步借用有效独立地址，不保存指针；由外层入口保持errno。
 */
static bool report_zero(const vireo_mysql_node_move_once_report_t *r) {
    return !r->commit && !r->effect && !r->issue && !r->node_id && !r->audit_id &&
           zero(r->idempotency_key, 16) && !r->rollback_confirmed && !r->cleanup_pending;
}
/** @brief 判断未进入服务的零结果关系。
 * @param[in] s 有效只读服务结果。
 * @return 全部语义字段为空时true。
 * @note 仅同步借用有效独立地址，不保存指针；由外层入口保持errno。
 */
static bool service_zero(const vireo_directory_move_result_t *s) {
    return !s->outcome && !s->name_issue && !s->node_id && zero(s->idempotency_key, 16) &&
           !s->repository_called && !s->repository_result && report_zero(&s->repository);
}
/** @brief 比较完整请求关联与有效名字字节。
 * @param[in] a 已解码可信task值。
 * @param[in] b 候选执行结果输入；长度先核界再读取名字。
 * @return 完整路由、实例、operation、deadline及业务输入均匹配时true。
 * @note 仅同步借用有效独立地址，不保存指针；由外层入口保持errno。
 */
static bool input_same(const vireo_directory_move_input_t *a,
                       const vireo_directory_move_input_t *b) {
    bool same = false;
    return vireo_task_metadata_same_request(a->metadata, b->metadata, &same) == VIREO_OK && same &&
           a->metadata.operation == b->metadata.operation &&
           a->metadata.deadline_ns == b->metadata.deadline_ns &&
           a->actor.user_id == b->actor.user_id && a->actor.session_id == b->actor.session_id &&
           a->request.sequence == b->request.sequence &&
           a->request.session_handle == b->request.session_handle &&
           a->request.node_id == b->request.node_id &&
           a->request.new_parent_id == b->request.new_parent_id &&
           a->request.new_name_length == b->request.new_name_length &&
           a->request.new_name_length <= VIREO_NODE_MOVE_NAME_CAPACITY &&
           !memcmp(a->request.new_name, b->request.new_name, a->request.new_name_length) &&
           !memcmp(a->request.idempotency_key, b->request.idempotency_key, 16);
}
static bool pair(vireo_result_t rc, vireo_status_t status) {
    switch (rc) {
        case VIREO_OK:
            return status == VIREO_STATUS_OK;
        case VIREO_RESULT_NOT_FOUND:
            return status == VIREO_STATUS_UNAUTHORIZED || status == VIREO_STATUS_NOT_FOUND ||
                   status == VIREO_STATUS_INTERNAL_ERROR;
        case VIREO_RESULT_PROTOCOL:
            return status == VIREO_STATUS_INVALID_PATH || status == VIREO_STATUS_INTERNAL_ERROR;
        case VIREO_RESULT_DATABASE:
            return status == VIREO_STATUS_FORBIDDEN || status == VIREO_STATUS_CONFLICT ||
                   status == VIREO_STATUS_DB_ERROR || status == VIREO_STATUS_INTERNAL_ERROR;
        case VIREO_RESULT_RANGE:
            return status == VIREO_STATUS_CONFLICT || status == VIREO_STATUS_INTERNAL_ERROR;
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
/* 原始写报告只校形状，不抹除已发布的历史成功。失败回滚与历史成功是独立事实。 */
/** @brief 核原始提交与effect关系，保留历史成功。
 * @param[in] r 有效只读task结果；原key必须与请求对应。
 * @return 关系成立时true；RECOVERED回滚失败须有历史清理错误。
 * @note 仅同步借用有效独立地址，不保存指针；由外层入口保持errno。
 */
static bool raw_valid(const vireo_directory_move_task_result_t *r) {
    const vireo_mysql_node_move_once_report_t *p = &r->service.repository;
    if (p->commit < VIREO_MYSQL_NODE_MOVE_NOT_COMMITTED ||
        p->commit > VIREO_MYSQL_NODE_MOVE_UNKNOWN ||
        p->effect < VIREO_MYSQL_NODE_MOVE_EFFECT_NONE ||
        p->effect > VIREO_MYSQL_NODE_MOVE_EFFECT_RECOVERED ||
        p->issue < VIREO_MYSQL_NODE_ISSUE_NONE || p->issue > VIREO_MYSQL_NODE_RECEIPT_INVALID)
        return false;
    if (p->effect == VIREO_MYSQL_NODE_MOVE_EFFECT_NONE)
        return p->commit != VIREO_MYSQL_NODE_MOVE_COMMITTED && !p->node_id && !p->audit_id &&
               zero(p->idempotency_key, 16) &&
               (p->commit != VIREO_MYSQL_NODE_MOVE_UNKNOWN || !p->rollback_confirmed);
    if (p->node_id != r->input.request.node_id || !p->audit_id ||
        p->issue != VIREO_MYSQL_NODE_ISSUE_NONE ||
        memcmp(p->idempotency_key, r->input.request.idempotency_key, 16))
        return false;
    if (p->effect == VIREO_MYSQL_NODE_MOVE_EFFECT_APPLIED)
        return p->commit == VIREO_MYSQL_NODE_MOVE_COMMITTED && !p->rollback_confirmed;
    return p->commit == VIREO_MYSQL_NODE_MOVE_NOT_COMMITTED &&
           (p->rollback_confirmed || (r->error.cleanup_result != VIREO_OK &&
                                      r->error.cleanup_stage == VIREO_MYSQL_NODE_STAGE_ROLLBACK));
}
/* 只生成已采用的技术建议；调用者已经验证阶段与业务关系。 */
static vireo_status_t technical(vireo_result_t rc) {
    switch (rc) {
        case VIREO_RESULT_NO_MEMORY:
            return VIREO_STATUS_OVERLOADED;
        case VIREO_RESULT_BUSY:
            return VIREO_STATUS_BUSY;
        case VIREO_RESULT_TIMEOUT:
            return VIREO_STATUS_TIMEOUT;
        case VIREO_RESULT_CANCELLED:
            return VIREO_STATUS_UNAVAILABLE;
        case VIREO_RESULT_DATABASE:
            return VIREO_STATUS_DB_ERROR;
        default:
            return VIREO_STATUS_INTERNAL_ERROR;
    }
}
/* 完整输入已匹配；未知枚举或矛盾关系拒绝，不用内部错误响应掩盖损坏。 */
/** @brief 验证完整写结果关系并投影可交付响应。
 * @param[in] r 已匹配原task的只读结果。
 * @param[out] out 调用者独占零初始化响应，失败允许部分修改。
 * @return 仅已知且一致的阶段、rc、原写事实成立时true。
 * @note 历史清理错误优先INTERNAL_ERROR；矛盾关系直接拒绝。
 * @note 仅同步借用有效独立地址，不保存指针；由外层入口保持errno。
 */
static bool project(const vireo_directory_move_task_result_t *r, vireo_node_move_response_t *out) {
    if (!known(r->result) || r->request_issue != VIREO_NODE_MOVE_ISSUE_NONE)
        return false;
    const vireo_directory_move_result_t *s = &r->service;
    const vireo_mysql_node_move_once_report_t *p = &s->repository;
    out->sequence = r->input.request.sequence;
    out->status = VIREO_STATUS_INTERNAL_ERROR;
    if (r->stage != VIREO_DIRECTORY_MOVE_TASK_SERVICE) {
        if (r->result == VIREO_OK || !service_zero(s) || !error_zero(&r->error))
            return false;
        switch (r->stage) {
            case VIREO_DIRECTORY_MOVE_TASK_CONTEXT:
                if (!zero(r->request_id, 16))
                    return false;
                break;
            case VIREO_DIRECTORY_MOVE_TASK_RANDOM:
                if (r->result != VIREO_RESULT_IO || !zero(r->request_id, 16))
                    return false;
                break;
            case VIREO_DIRECTORY_MOVE_TASK_CANCEL:
                if (r->result != VIREO_RESULT_CANCELLED || zero(r->request_id, 16))
                    return false;
                break;
            case VIREO_DIRECTORY_MOVE_TASK_DEADLINE:
                if (r->result != VIREO_RESULT_TIMEOUT || zero(r->request_id, 16))
                    return false;
                break;
            default:
                return false;
        }
        out->status = technical(r->result);
        return true;
    }
    if (zero(r->request_id, 16) || !known(s->repository_result) ||
        !known(r->error.cleanup_result) || !error_known(&r->error) ||
        s->outcome < VIREO_DIRECTORY_MOVE_NONE ||
        s->outcome > VIREO_DIRECTORY_MOVE_IDEMPOTENCY_CONFLICT ||
        s->name_issue < VIREO_DIRECTORY_NAME_ISSUE_NONE ||
        s->name_issue > VIREO_DIRECTORY_NAME_ISSUE_NOT_NFC || !raw_valid(r))
        return false;
    if (!s->repository_called &&
        (!report_zero(p) || s->repository_result != VIREO_OK || !error_zero(&r->error)))
        return false;
    const bool cleanup = r->error.cleanup_result != VIREO_OK || p->cleanup_pending;
    if (s->outcome == VIREO_DIRECTORY_MOVE_APPLIED ||
        s->outcome == VIREO_DIRECTORY_MOVE_RECOVERED) {
        const bool applied = s->outcome == VIREO_DIRECTORY_MOVE_APPLIED;
        if (r->result != VIREO_OK || s->repository_result != VIREO_OK || !s->repository_called ||
            cleanup || s->name_issue != VIREO_DIRECTORY_NAME_ISSUE_NONE ||
            s->node_id != p->node_id || memcmp(s->idempotency_key, p->idempotency_key, 16) ||
            p->effect != (applied ? VIREO_MYSQL_NODE_MOVE_EFFECT_APPLIED
                                  : VIREO_MYSQL_NODE_MOVE_EFFECT_RECOVERED) ||
            (!applied && !p->rollback_confirmed))
            return false;
        out->status = VIREO_STATUS_OK;
        out->session_handle = r->input.request.session_handle;
        out->node_id = s->node_id;
        memcpy(out->idempotency_key, s->idempotency_key, 16);
        return true;
    }
    if (s->node_id || !zero(s->idempotency_key, 16))
        return false;
    if (s->outcome == VIREO_DIRECTORY_MOVE_INVALID_NAME) {
        if (s->repository_called || cleanup || r->result != VIREO_RESULT_PROTOCOL ||
            s->name_issue != VIREO_DIRECTORY_NAME_ISSUE_NOT_NFC)
            return false;
        out->status = VIREO_STATUS_INVALID_PATH;
        return true;
    }
    if (s->name_issue != VIREO_DIRECTORY_NAME_ISSUE_NONE)
        return false;
    /* A domain rejection needs its exact repository rc/issue pair. */
    vireo_directory_move_outcome_t domain = VIREO_DIRECTORY_MOVE_NONE;
    vireo_status_t domain_status = VIREO_STATUS_INTERNAL_ERROR;
    if (s->repository_result == VIREO_RESULT_NOT_FOUND) {
        if (p->issue == VIREO_MYSQL_NODE_AUTH_REJECTED) {
            domain = VIREO_DIRECTORY_MOVE_UNAUTHORIZED;
            domain_status = VIREO_STATUS_UNAUTHORIZED;
        } else if (p->issue == VIREO_MYSQL_NODE_NOT_FOUND) {
            domain = VIREO_DIRECTORY_MOVE_NOT_FOUND;
            domain_status = VIREO_STATUS_NOT_FOUND;
        }
    } else if (s->repository_result == VIREO_RESULT_DATABASE) {
        switch (p->issue) {
            case VIREO_MYSQL_NODE_ROOT_IMMOVABLE:
                domain = VIREO_DIRECTORY_MOVE_ROOT_IMMOVABLE;
                domain_status = VIREO_STATUS_FORBIDDEN;
                break;
            case VIREO_MYSQL_NODE_NAME_CONFLICT:
                domain = VIREO_DIRECTORY_MOVE_NAME_CONFLICT;
                break;
            case VIREO_MYSQL_NODE_MOVE_CYCLE:
                domain = VIREO_DIRECTORY_MOVE_CYCLE;
                break;
            case VIREO_MYSQL_NODE_IDEMPOTENCY_CONFLICT:
                domain = VIREO_DIRECTORY_MOVE_IDEMPOTENCY_CONFLICT;
                break;
            default:
                break;
        }
        if (domain != VIREO_DIRECTORY_MOVE_NONE && domain != VIREO_DIRECTORY_MOVE_ROOT_IMMOVABLE)
            domain_status = VIREO_STATUS_CONFLICT;
    } else if (s->repository_result == VIREO_RESULT_RANGE &&
               p->issue == VIREO_MYSQL_NODE_ANCESTRY_LIMIT) {
        domain = VIREO_DIRECTORY_MOVE_ANCESTRY_LIMIT;
        domain_status = VIREO_STATUS_CONFLICT;
    }
    if (s->outcome != VIREO_DIRECTORY_MOVE_NONE) {
        if (!s->repository_called || cleanup || p->commit != VIREO_MYSQL_NODE_MOVE_NOT_COMMITTED ||
            p->effect != VIREO_MYSQL_NODE_MOVE_EFFECT_NONE || !p->rollback_confirmed ||
            r->result != s->repository_result || domain == VIREO_DIRECTORY_MOVE_NONE ||
            s->outcome != domain)
            return false;
        out->status = domain_status;
        return true;
    }
    if (!s->repository_called) {
        if (r->result != VIREO_RESULT_NO_MEMORY && r->result != VIREO_RESULT_OVERFLOW &&
            r->result != VIREO_RESULT_INTERNAL)
            return false;
        out->status = technical(r->result);
        return true;
    }
    if (r->result == VIREO_OK)
        return false;
    if (r->error.cleanup_result != VIREO_OK) {
        const vireo_result_t expected = r->error.cleanup_result == VIREO_RESULT_NOT_FOUND
                                            ? VIREO_RESULT_INTERNAL
                                            : r->error.cleanup_result;
        return r->result == expected;
    }
    if (p->cleanup_pending) {
        const vireo_result_t expected = s->repository_result == VIREO_OK ||
                                                s->repository_result == VIREO_RESULT_NOT_FOUND ||
                                                domain != VIREO_DIRECTORY_MOVE_NONE
                                            ? VIREO_RESULT_INTERNAL
                                            : s->repository_result;
        return r->result == expected;
    }
    if (p->effect != VIREO_MYSQL_NODE_MOVE_EFFECT_NONE || r->result == VIREO_RESULT_NOT_FOUND ||
        r->result == VIREO_RESULT_PROTOCOL)
        return false;
    if (s->repository_called) {
        const vireo_result_t expected = s->repository_result == VIREO_OK ||
                                                s->repository_result == VIREO_RESULT_NOT_FOUND ||
                                                s->repository_result == VIREO_RESULT_PROTOCOL ||
                                                domain != VIREO_DIRECTORY_MOVE_NONE
                                            ? VIREO_RESULT_INTERNAL
                                            : s->repository_result;
        if (r->result != expected)
            return false;
    }
    out->status = technical(r->result);
    return true;
}

vireo_result_t vireo_directory_move_completion_publish_with(
    const vireo_task_t *task, uint32_t op, const vireo_directory_move_task_result_t *result,
    size_t budget, vireo_completion_queue_t *queue, vireo_notifier_t *notifier,
    vireo_completion_t **remaining, vireo_directory_move_completion_publish_report_t *report,
    vireo_directory_move_publish_fn publish) {
    const int saved = errno;
    vireo_directory_move_input_t input = {0};
    vireo_node_move_response_t response = {0};
    unsigned char payload[120] = {0};
    vireo_result_t rc = VIREO_RESULT_INVALID_ARGUMENT;
    if (report)
        memset(report, 0, sizeof(*report));
    if (!task || !op || !result || !budget || !queue || !notifier || !remaining || *remaining ||
        !report || !publish)
        goto done;
    vireo_node_move_issue_t issue;
    rc = vireo_directory_move_task_read(task, op, &input, &issue);
    if (rc != VIREO_OK)
        goto done;
    rc = VIREO_RESULT_PROTOCOL;
    if (!input_same(&input, &result->input))
        goto done;
    report->task_matched = true;
    rc = VIREO_RESULT_INVALID_ARGUMENT;
    if (!project(result, &response))
        goto done;
    size_t size = 0;
    rc = vireo_node_move_response_encode(&response, payload + 56, sizeof(payload) - 56, &size);
    if (rc != VIREO_OK)
        goto done;
    report->result_validated = true;
    memcpy(payload, "MVC1", 4);
    put64(payload + 8, input.actor.user_id);
    put64(payload + 16, input.actor.session_id);
    put32(payload + 24, input.request.session_handle);
    put32(payload + 28, (uint32_t)size);
    put64(payload + 32, input.request.node_id);
    memcpy(payload + 40, input.request.idempotency_key, 16);
    report->publish_called = true;
    rc = publish(task, result->result, response.status, payload, 56 + size, budget, queue, notifier,
                 remaining, &report->publication);
done:
    (void)vireo_secure_clear(&input, sizeof(input));
    (void)vireo_secure_clear(&response, sizeof(response));
    (void)vireo_secure_clear(payload, sizeof(payload));
    errno = saved;
    return rc;
}

vireo_result_t vireo_directory_move_completion_publish(
    const vireo_task_t *task, uint32_t op, const vireo_directory_move_task_result_t *result,
    size_t budget, vireo_completion_queue_t *queue, vireo_notifier_t *notifier,
    vireo_completion_t **remaining, vireo_directory_move_completion_publish_report_t *report) {
    return vireo_directory_move_completion_publish_with(task, op, result, budget, queue, notifier,
                                                        remaining, report,
                                                        vireo_completion_copy_wait_publish);
}

vireo_result_t vireo_directory_move_completion_decode(
    const vireo_completion_t *completion, uint32_t op,
    vireo_directory_move_completion_outcome_t *out) {
    const int saved = errno;
    vireo_directory_move_completion_outcome_t next = {0};
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
    if ((view.size != 88 && view.size != 120) || info.metadata.request.operation != op ||
        memcmp(view.data, "MVC1\0\0\0\0", 8))
        goto done;
    const uint32_t size = get32(view.data + 28);
    if ((size != 32 && size != 64) || view.size != 56 + (size_t)size)
        goto done;
    next = (vireo_directory_move_completion_outcome_t){
        .metadata = info.metadata,
        .actor = {get64(view.data + 8), get64(view.data + 16)},
        .request_session_handle = get32(view.data + 24),
        .request_node_id = get64(view.data + 32)};
    memcpy(next.request_idempotency_key, view.data + 40, 16);
    if (zero(next.request_idempotency_key, 16) || !next.actor.user_id || !next.actor.session_id ||
        !next.request_session_handle || !next.request_node_id)
        goto done;
    vireo_node_move_issue_t issue;
    rc = vireo_node_move_response_decode(view.data + 56, size, &next.response, &issue);
    if (rc != VIREO_OK)
        goto done;
    rc = VIREO_RESULT_PROTOCOL;
    if (next.response.sequence != info.metadata.request.route.request_sequence ||
        next.response.status != info.metadata.suggested_status ||
        !pair(info.metadata.result, next.response.status))
        goto done;
    if (next.response.status == VIREO_STATUS_OK &&
        (next.response.session_handle != next.request_session_handle ||
         next.response.node_id != next.request_node_id ||
         memcmp(next.response.idempotency_key, next.request_idempotency_key, 16)))
        goto done;
    *out = next;
    rc = VIREO_OK;
done:
    (void)vireo_secure_clear(&next, sizeof(next));
    errno = saved;
    return rc;
}
