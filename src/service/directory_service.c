/* PROJECT : VIREO; FILE : directory_service.c; AUTHOR : bitofux;
 * DATE : 2026-10-22; BRIEF : 保留repo原始事实，完整清理后才发布STAT业务结果。 */
#include "directory_service_internal.h"
#include <errno.h>
#include <string.h>

/* 同repo公开stat的借用/线程合同；不持有context或任何输入输出地址。 */
static vireo_result_t native_stat(void *context, vireo_mysql_node_repository_t *repository,
    const vireo_mysql_node_actor_t *actor, uint64_t node_id, uint32_t timeout_ms,
    vireo_mysql_node_value_t *node, vireo_mysql_node_report_t *report,
    vireo_mysql_node_error_t *error)
{
    (void)context;
    return vireo_mysql_node_repository_stat(repository, actor, node_id, timeout_ms, node, report, error);
}

vireo_result_t vireo_directory_service_stat_with_runtime(vireo_mysql_node_repository_t *repository,
    const vireo_mysql_node_actor_t *actor, uint64_t node_id, uint32_t timeout_ms,
    vireo_directory_stat_result_t *result, vireo_mysql_node_error_t *error,
    const vireo_directory_service_runtime_t *runtime)
{
    const int saved_errno = errno;
    vireo_result_t rc = VIREO_RESULT_INVALID_ARGUMENT;
    if (repository == NULL || actor == NULL || result == NULL || runtime == NULL || runtime->stat == NULL) {
        goto done;
    }
    memset(result, 0, sizeof(*result));
    if (error != NULL) { memset(error, 0, sizeof(*error)); }
    if (actor->user_id == 0 || actor->session_id == 0 || node_id == 0) { goto done; }
    if (timeout_ms > 60000) { rc = VIREO_RESULT_RANGE; goto done; }

    vireo_mysql_node_value_t candidate = {0};
    vireo_mysql_node_report_t report = {0};
    vireo_mysql_node_error_t diagnostic = {0};
    rc = runtime->stat(runtime->context, repository, actor, node_id, timeout_ms,
        &candidate, &report, &diagnostic);
    result->repository_called = true;
    result->repository_result = rc;
    result->repository = report;
    if (error != NULL) { *error = diagnostic; }

    /* repo保持主因，故NOT_FOUND也可能伴随清理故障；先排除这种不可交付结果。 */
    if (diagnostic.cleanup_result != VIREO_OK) {
        rc = diagnostic.cleanup_result == VIREO_RESULT_NOT_FOUND ?
            VIREO_RESULT_INTERNAL : diagnostic.cleanup_result;
        goto done;
    }
    if (report.cleanup_pending) {
        if (rc == VIREO_OK || rc == VIREO_RESULT_NOT_FOUND) { rc = VIREO_RESULT_INTERNAL; }
        goto done;
    }
    if (rc == VIREO_OK) {
        if (!report.found || report.issue != VIREO_MYSQL_NODE_ISSUE_NONE ||
            !report.rollback_confirmed || candidate.id != node_id || candidate.owner_id != actor->user_id) {
            rc = VIREO_RESULT_INTERNAL;
            goto done;
        }
        result->outcome = VIREO_DIRECTORY_STAT_FOUND;
        result->node = candidate;
    } else if (rc == VIREO_RESULT_NOT_FOUND) {
        if (report.found || !report.rollback_confirmed ||
            (report.issue != VIREO_MYSQL_NODE_AUTH_REJECTED && report.issue != VIREO_MYSQL_NODE_NOT_FOUND)) {
            rc = VIREO_RESULT_INTERNAL;
            goto done;
        }
        result->outcome = report.issue == VIREO_MYSQL_NODE_AUTH_REJECTED ?
            VIREO_DIRECTORY_STAT_UNAUTHORIZED : VIREO_DIRECTORY_STAT_NOT_FOUND;
    }
done:
    errno = saved_errno;
    return rc;
}

vireo_result_t vireo_directory_service_stat(vireo_mysql_node_repository_t *repository,
    const vireo_mysql_node_actor_t *actor, uint64_t node_id, uint32_t timeout_ms,
    vireo_directory_stat_result_t *result, vireo_mysql_node_error_t *error)
{
    const vireo_directory_service_runtime_t runtime = {NULL, native_stat};
    return vireo_directory_service_stat_with_runtime(repository, actor, node_id, timeout_ms, result, error, &runtime);
}
