/* PROJECT : VIREO; FILE : directory_mkdir.c; AUTHOR : bitofux;
 * DATE : 2026-10-24; BRIEF : 单次可恢复创建，原始事实和可交付结果分离。 */
#include "directory_mkdir_internal.h"
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

static vireo_result_t native_mkdir(void *context, vireo_mysql_node_repository_t *repository,
    const vireo_mysql_node_actor_t *actor, const vireo_mysql_node_mkdir_once_input_t *input,
    uint32_t timeout_ms, vireo_mysql_node_mkdir_once_report_t *report, vireo_mysql_node_error_t *error)
{
    (void)context;
    return vireo_mysql_node_repository_mkdir_once(repository, actor, input, timeout_ms, report, error);
}

vireo_result_t vireo_directory_service_mkdir_with_runtime(vireo_mysql_node_repository_t *repository,
    const vireo_mysql_node_actor_t *actor, const vireo_mysql_node_mkdir_once_input_t *input,
    uint32_t timeout_ms, vireo_directory_mkdir_result_t *result, vireo_mysql_node_error_t *error,
    const vireo_directory_mkdir_runtime_t *runtime)
{
    const int saved_errno = errno;
    vireo_result_t rc = VIREO_RESULT_INVALID_ARGUMENT;
    if (repository == NULL || actor == NULL || input == NULL || input->name == NULL || result == NULL ||
        runtime == NULL || runtime->name_validate == NULL || runtime->mkdir_once == NULL) { goto done; }
    memset(result, 0, sizeof(*result));
    if (error != NULL) { memset(error, 0, sizeof(*error)); }
    if (actor->user_id == 0 || actor->session_id == 0 || input->parent_id == 0 ||
        zero_key(input->idempotency_key) || zero_key(input->request_id)) { goto done; }
    if (timeout_ms > 60000) { rc = VIREO_RESULT_RANGE; goto done; }
    vireo_directory_name_issue_t issue = VIREO_DIRECTORY_NAME_ISSUE_NONE;
    rc = runtime->name_validate(runtime->context, input->name, input->name_length, &issue);
    if ((rc == VIREO_RESULT_RANGE && issue == VIREO_DIRECTORY_NAME_ISSUE_LENGTH) ||
        (rc == VIREO_RESULT_PROTOCOL && (issue == VIREO_DIRECTORY_NAME_ISSUE_UTF8 ||
            issue == VIREO_DIRECTORY_NAME_ISSUE_SYNTAX || issue == VIREO_DIRECTORY_NAME_ISSUE_NOT_NFC))) {
        result->outcome = VIREO_DIRECTORY_MKDIR_INVALID_NAME;
        result->name_issue = issue;
        goto done;
    }
    if (rc != VIREO_OK || issue != VIREO_DIRECTORY_NAME_ISSUE_NONE) {
        if (issue != VIREO_DIRECTORY_NAME_ISSUE_NONE || rc == VIREO_OK ||
            rc == VIREO_RESULT_RANGE || rc == VIREO_RESULT_PROTOCOL || rc == VIREO_RESULT_NOT_FOUND) {
            rc = VIREO_RESULT_INTERNAL;
        }
        goto done;
    }
    vireo_mysql_node_mkdir_once_report_t report = {0};
    vireo_mysql_node_error_t diagnostic = {0};
    rc = runtime->mkdir_once(runtime->context, repository, actor, input, timeout_ms, &report, &diagnostic);
    result->repository_called = true;
    result->repository_result = rc;
    result->repository = report;
    if (error != NULL) { *error = diagnostic; }
    bool conflict = rc == VIREO_RESULT_DATABASE &&
        (report.issue == VIREO_MYSQL_NODE_NAME_CONFLICT || report.issue == VIREO_MYSQL_NODE_IDEMPOTENCY_CONFLICT);
    if (diagnostic.cleanup_result != VIREO_OK) {
        rc = diagnostic.cleanup_result == VIREO_RESULT_NOT_FOUND ? VIREO_RESULT_INTERNAL : diagnostic.cleanup_result;
        goto done;
    }
    if (report.cleanup_pending) {
        if (rc == VIREO_OK || rc == VIREO_RESULT_NOT_FOUND || conflict) { rc = VIREO_RESULT_INTERNAL; }
        goto done;
    }
    if (rc == VIREO_OK) {
        if (report.issue != VIREO_MYSQL_NODE_ISSUE_NONE || report.node_id == 0 || report.audit_id == 0 ||
            memcmp(report.idempotency_key, input->idempotency_key, 16) != 0) {
            rc = VIREO_RESULT_INTERNAL; goto done;
        }
        if (report.commit == VIREO_MYSQL_NODE_MKDIR_COMMITTED &&
            report.effect == VIREO_MYSQL_NODE_MKDIR_EFFECT_CREATED && !report.rollback_confirmed) {
            result->outcome = VIREO_DIRECTORY_MKDIR_CREATED;
        } else if (report.commit == VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED &&
            report.effect == VIREO_MYSQL_NODE_MKDIR_EFFECT_RECOVERED && report.rollback_confirmed) {
            result->outcome = VIREO_DIRECTORY_MKDIR_RECOVERED;
        } else { rc = VIREO_RESULT_INTERNAL; goto done; }
        result->node_id = report.node_id;
        memcpy(result->idempotency_key, report.idempotency_key, 16);
    } else if (rc == VIREO_RESULT_NOT_FOUND || conflict) {
        if (report.commit != VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED ||
            report.effect != VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE || report.node_id != 0 ||
            report.audit_id != 0 || !zero_key(report.idempotency_key) || !report.rollback_confirmed) {
            rc = VIREO_RESULT_INTERNAL; goto done;
        }
        if (rc == VIREO_RESULT_NOT_FOUND && report.issue == VIREO_MYSQL_NODE_AUTH_REJECTED) {
            result->outcome = VIREO_DIRECTORY_MKDIR_UNAUTHORIZED;
        } else if (rc == VIREO_RESULT_NOT_FOUND && report.issue == VIREO_MYSQL_NODE_NOT_FOUND) {
            result->outcome = VIREO_DIRECTORY_MKDIR_PARENT_NOT_FOUND;
        } else if (conflict) {
            result->outcome = report.issue == VIREO_MYSQL_NODE_NAME_CONFLICT ?
                VIREO_DIRECTORY_MKDIR_NAME_CONFLICT : VIREO_DIRECTORY_MKDIR_IDEMPOTENCY_CONFLICT;
        } else { rc = VIREO_RESULT_INTERNAL; }
    } else if (rc == VIREO_RESULT_PROTOCOL) { rc = VIREO_RESULT_INTERNAL; }
done:
    errno = saved_errno;
    return rc;
}

vireo_result_t vireo_directory_service_mkdir(vireo_mysql_node_repository_t *repository,
    const vireo_mysql_node_actor_t *actor, const vireo_mysql_node_mkdir_once_input_t *input,
    uint32_t timeout_ms, vireo_directory_mkdir_result_t *result, vireo_mysql_node_error_t *error)
{
    const vireo_directory_mkdir_runtime_t runtime = {NULL, native_name, native_mkdir};
    return vireo_directory_service_mkdir_with_runtime(repository, actor, input, timeout_ms, result, error, &runtime);
}
