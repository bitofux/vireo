/* PROJECT : VIREO; FILE : directory_root.c; AUTHOR : bitofux;
 * DATE : 2026-10-22; BRIEF : 保留原查询事实，完整清理及根关联成立后发布ID。 */
#include "directory_root_internal.h"
#include <errno.h>
#include <string.h>

static vireo_result_t native_get_root(void *context, vireo_mysql_node_repository_t *repository,
    const vireo_mysql_node_actor_t *actor, uint32_t timeout_ms,
    vireo_mysql_node_value_t *node, vireo_mysql_node_report_t *report, vireo_mysql_node_error_t *error)
{
    (void)context;
    return vireo_mysql_node_repository_get_root(repository, actor, timeout_ms, node, report, error);
}

vireo_result_t vireo_directory_service_root_with_runtime(vireo_mysql_node_repository_t *repository,
    const vireo_mysql_node_actor_t *actor, uint32_t timeout_ms,
    vireo_directory_root_result_t *result, vireo_mysql_node_error_t *error,
    const vireo_directory_root_runtime_t *runtime)
{
    const int saved_errno = errno;
    vireo_result_t rc = VIREO_RESULT_INVALID_ARGUMENT;
    if (repository == NULL || actor == NULL || result == NULL ||
        runtime == NULL || runtime->get_root == NULL) { goto done; }
    memset(result, 0, sizeof(*result));
    if (error != NULL) { memset(error, 0, sizeof(*error)); }
    if (actor->user_id == 0 || actor->session_id == 0) { goto done; }
    if (timeout_ms > 60000) { rc = VIREO_RESULT_RANGE; goto done; }

    vireo_mysql_node_value_t candidate = {0};
    vireo_mysql_node_report_t report = {0};
    vireo_mysql_node_error_t diagnostic = {0};
    rc = runtime->get_root(runtime->context, repository, actor, timeout_ms,
        &candidate, &report, &diagnostic);
    result->repository_called = true;
    result->repository_result = rc;
    result->repository = report;
    if (error != NULL) { *error = diagnostic; }

    /* 首因留在repository_result；清理失败优先，不能误报成功或普通身份拒绝。 */
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
        if (!report.found || report.issue != VIREO_MYSQL_NODE_ISSUE_NONE || !report.rollback_confirmed ||
            candidate.id == 0 || candidate.owner_id != actor->user_id || candidate.has_parent ||
            candidate.parent_id != 0 || candidate.name_length != 0 ||
            candidate.kind != VIREO_MYSQL_NODE_DIRECTORY || candidate.size != 0 || candidate.has_object_hash) {
            rc = VIREO_RESULT_INTERNAL;
            goto done;
        }
        result->outcome = VIREO_DIRECTORY_ROOT_FOUND;
        result->root_node_id = candidate.id;
    } else if (rc == VIREO_RESULT_NOT_FOUND) {
        if (report.found || report.issue != VIREO_MYSQL_NODE_AUTH_REJECTED || !report.rollback_confirmed) {
            rc = VIREO_RESULT_INTERNAL;
            goto done;
        }
        result->outcome = VIREO_DIRECTORY_ROOT_UNAUTHORIZED;
    }
done:
    errno = saved_errno;
    return rc;
}

vireo_result_t vireo_directory_service_root(vireo_mysql_node_repository_t *repository,
    const vireo_mysql_node_actor_t *actor, uint32_t timeout_ms,
    vireo_directory_root_result_t *result, vireo_mysql_node_error_t *error)
{
    const vireo_directory_root_runtime_t runtime = {NULL, native_get_root};
    return vireo_directory_service_root_with_runtime(repository, actor, timeout_ms, result, error, &runtime);
}
