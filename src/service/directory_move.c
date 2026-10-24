/* PROJECT : VIREO; FILE : directory_move.c; AUTHOR : bitofux;
 * DATE : 2026-10-24; BRIEF : 单次可恢复移动，原始事实和可交付结果分离。 */
#include "directory_move_internal.h"
#include <errno.h>
#include <string.h>

static bool zero_key(const unsigned char key[16])
{
    unsigned char combined = 0;
    for (size_t i = 0; i < 16; ++i) { combined |= key[i]; }
    return combined == 0;
}

static vireo_result_t native_name(void *context, const unsigned char *name, size_t length,
    vireo_directory_name_issue_t *issue)
{
    (void)context;
    return vireo_directory_name_validate(name, length, issue);
}

static vireo_result_t native_move(void *context, vireo_mysql_node_repository_t *repository,
    const vireo_mysql_node_actor_t *actor, const vireo_mysql_node_move_once_input_t *input,
    uint32_t timeout_ms, vireo_mysql_node_move_once_report_t *report, vireo_mysql_node_error_t *error)
{
    (void)context;
    return vireo_mysql_node_repository_move_once(repository, actor, input, timeout_ms, report, error);
}

/* 仅精确的仓库rc/issue配对构成已确认领域拒绝，1062不是业务分类。 */
static vireo_directory_move_outcome_t domain_outcome(vireo_result_t rc, vireo_mysql_node_issue_t issue)
{
    if (rc == VIREO_RESULT_NOT_FOUND) {
        if (issue == VIREO_MYSQL_NODE_AUTH_REJECTED) { return VIREO_DIRECTORY_MOVE_UNAUTHORIZED; }
        if (issue == VIREO_MYSQL_NODE_NOT_FOUND) { return VIREO_DIRECTORY_MOVE_NOT_FOUND; }
    } else if (rc == VIREO_RESULT_DATABASE) {
        switch (issue) {
        case VIREO_MYSQL_NODE_ROOT_IMMOVABLE: return VIREO_DIRECTORY_MOVE_ROOT_IMMOVABLE;
        case VIREO_MYSQL_NODE_NAME_CONFLICT: return VIREO_DIRECTORY_MOVE_NAME_CONFLICT;
        case VIREO_MYSQL_NODE_MOVE_CYCLE: return VIREO_DIRECTORY_MOVE_CYCLE;
        case VIREO_MYSQL_NODE_IDEMPOTENCY_CONFLICT: return VIREO_DIRECTORY_MOVE_IDEMPOTENCY_CONFLICT;
        default: break;
        }
    } else if (rc == VIREO_RESULT_RANGE && issue == VIREO_MYSQL_NODE_ANCESTRY_LIMIT) {
        return VIREO_DIRECTORY_MOVE_ANCESTRY_LIMIT;
    }
    return VIREO_DIRECTORY_MOVE_NONE;
}

vireo_result_t vireo_directory_service_move_with_runtime(vireo_mysql_node_repository_t *repository,
    const vireo_mysql_node_actor_t *actor, const vireo_mysql_node_move_once_input_t *input,
    uint32_t timeout_ms, vireo_directory_move_result_t *result, vireo_mysql_node_error_t *error,
    const vireo_directory_move_runtime_t *runtime)
{
    const int saved_errno = errno;
    vireo_result_t rc = VIREO_RESULT_INVALID_ARGUMENT;
    if (repository == NULL || actor == NULL || input == NULL || input->name == NULL || result == NULL ||
        runtime == NULL || runtime->name_validate == NULL || runtime->move_once == NULL) { goto done; }
    memset(result, 0, sizeof(*result));
    if (error != NULL) { memset(error, 0, sizeof(*error)); }
    if (actor->user_id == 0 || actor->session_id == 0 || input->node_id == 0 || input->new_parent_id == 0 ||
        zero_key(input->idempotency_key) || zero_key(input->request_id)) { goto done; }
    if (timeout_ms > 60000) { rc = VIREO_RESULT_RANGE; goto done; }
    vireo_directory_name_issue_t issue = VIREO_DIRECTORY_NAME_ISSUE_NONE;
    rc = runtime->name_validate(runtime->context, input->name, input->name_length, &issue);
    if ((rc == VIREO_RESULT_RANGE && issue == VIREO_DIRECTORY_NAME_ISSUE_LENGTH) ||
        (rc == VIREO_RESULT_PROTOCOL && (issue == VIREO_DIRECTORY_NAME_ISSUE_UTF8 ||
            issue == VIREO_DIRECTORY_NAME_ISSUE_SYNTAX || issue == VIREO_DIRECTORY_NAME_ISSUE_NOT_NFC))) {
        result->outcome = VIREO_DIRECTORY_MOVE_INVALID_NAME;
        result->name_issue = issue;
        goto done;
    }
    if (rc != VIREO_OK || issue != VIREO_DIRECTORY_NAME_ISSUE_NONE) {
        if (issue != VIREO_DIRECTORY_NAME_ISSUE_NONE ||
            (rc != VIREO_RESULT_NO_MEMORY && rc != VIREO_RESULT_OVERFLOW && rc != VIREO_RESULT_INTERNAL)) {
            rc = VIREO_RESULT_INTERNAL;
        }
        goto done;
    }
    vireo_mysql_node_move_once_report_t report = {0};
    vireo_mysql_node_error_t diagnostic = {0};
    rc = runtime->move_once(runtime->context, repository, actor, input, timeout_ms, &report, &diagnostic);
    result->repository_called = true;
    result->repository_result = rc;
    result->repository = report;
    if (error != NULL) { *error = diagnostic; }
    const vireo_directory_move_outcome_t rejection = domain_outcome(rc, report.issue);
    if (diagnostic.cleanup_result != VIREO_OK) {
        rc = diagnostic.cleanup_result == VIREO_RESULT_NOT_FOUND ? VIREO_RESULT_INTERNAL : diagnostic.cleanup_result;
        goto done;
    }
    if (report.cleanup_pending) {
        if (rc == VIREO_OK || rc == VIREO_RESULT_NOT_FOUND || rejection != VIREO_DIRECTORY_MOVE_NONE) { rc = VIREO_RESULT_INTERNAL; }
        goto done;
    }
    if (rc == VIREO_OK) {
        if (report.issue != VIREO_MYSQL_NODE_ISSUE_NONE || report.node_id != input->node_id || report.audit_id == 0 ||
            memcmp(report.idempotency_key, input->idempotency_key, 16) != 0) {
            rc = VIREO_RESULT_INTERNAL; goto done;
        }
        if (report.commit == VIREO_MYSQL_NODE_MOVE_COMMITTED &&
            report.effect == VIREO_MYSQL_NODE_MOVE_EFFECT_APPLIED && !report.rollback_confirmed) {
            result->outcome = VIREO_DIRECTORY_MOVE_APPLIED;
        } else if (report.commit == VIREO_MYSQL_NODE_MOVE_NOT_COMMITTED &&
            report.effect == VIREO_MYSQL_NODE_MOVE_EFFECT_RECOVERED && report.rollback_confirmed) {
            result->outcome = VIREO_DIRECTORY_MOVE_RECOVERED;
        } else { rc = VIREO_RESULT_INTERNAL; goto done; }
        result->node_id = report.node_id;
        memcpy(result->idempotency_key, report.idempotency_key, 16);
    } else if (rc == VIREO_RESULT_NOT_FOUND || rejection != VIREO_DIRECTORY_MOVE_NONE) {
        if (report.commit != VIREO_MYSQL_NODE_MOVE_NOT_COMMITTED ||
            report.effect != VIREO_MYSQL_NODE_MOVE_EFFECT_NONE || report.node_id != 0 ||
            report.audit_id != 0 || !zero_key(report.idempotency_key) || !report.rollback_confirmed ||
            rejection == VIREO_DIRECTORY_MOVE_NONE) {
            rc = VIREO_RESULT_INTERNAL; goto done;
        }
        result->outcome = rejection;
    } else if (rc == VIREO_RESULT_PROTOCOL) { rc = VIREO_RESULT_INTERNAL; }
done:
    errno = saved_errno;
    return rc;
}

vireo_result_t vireo_directory_service_move(vireo_mysql_node_repository_t *repository,
    const vireo_mysql_node_actor_t *actor, const vireo_mysql_node_move_once_input_t *input,
    uint32_t timeout_ms, vireo_directory_move_result_t *result, vireo_mysql_node_error_t *error)
{
    const vireo_directory_move_runtime_t runtime = {NULL, native_name, native_move};
    return vireo_directory_service_move_with_runtime(repository, actor, input, timeout_ms, result, error, &runtime);
}
