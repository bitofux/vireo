/* PROJECT : VIREO; FILE : directory_remove.c; BRIEF : 可恢复软删除薄服务。 */
#include <errno.h>
#include <string.h>
#include "directory_remove_internal.h"

static bool zero_bytes(const unsigned char *bytes, size_t length) {
    unsigned char value = 0;
    for (size_t i = 0; i < length; ++i) {
        value |= bytes[i];
    }
    return value == 0;
}

static vireo_result_t native_remove(void *context, vireo_mysql_node_repository_t *repository,
                                    const vireo_mysql_node_actor_t *actor,
                                    const vireo_mysql_node_remove_once_input_t *input,
                                    uint32_t timeout_ms,
                                    vireo_mysql_node_remove_once_report_t *report,
                                    vireo_mysql_node_error_t *error) {
    (void)context;
    return vireo_mysql_node_repository_soft_delete_once(repository, actor, input, timeout_ms,
                                                        report, error);
}

static vireo_directory_remove_outcome_t domain_outcome(vireo_result_t rc,
                                                       vireo_mysql_node_issue_t issue) {
    if (rc == VIREO_RESULT_NOT_FOUND) {
        if (issue == VIREO_MYSQL_NODE_AUTH_REJECTED) {
            return VIREO_DIRECTORY_REMOVE_UNAUTHORIZED;
        }
        if (issue == VIREO_MYSQL_NODE_NOT_FOUND) {
            return VIREO_DIRECTORY_REMOVE_NOT_FOUND;
        }
    }
    if (rc == VIREO_RESULT_RANGE && issue == VIREO_MYSQL_NODE_ANCESTRY_LIMIT) {
        return VIREO_DIRECTORY_REMOVE_ANCESTRY_LIMIT;
    }
    if (rc == VIREO_RESULT_DATABASE) {
        switch (issue) {
            case VIREO_MYSQL_NODE_ROOT_UNDELETABLE:
                return VIREO_DIRECTORY_REMOVE_ROOT_UNDELETABLE;
            case VIREO_MYSQL_NODE_DIRECTORY_NOT_EMPTY:
                return VIREO_DIRECTORY_REMOVE_DIRECTORY_NOT_EMPTY;
            case VIREO_MYSQL_NODE_OBJECT_REFERENCE_INVALID:
                return VIREO_DIRECTORY_REMOVE_OBJECT_REFERENCE_INVALID;
            case VIREO_MYSQL_NODE_IDEMPOTENCY_CONFLICT:
                return VIREO_DIRECTORY_REMOVE_IDEMPOTENCY_CONFLICT;
            case VIREO_MYSQL_NODE_RECEIPT_INVALID:
                return VIREO_DIRECTORY_REMOVE_RECEIPT_INVALID;
            default:
                break;
        }
    }
    return VIREO_DIRECTORY_REMOVE_NONE;
}

vireo_result_t vireo_directory_service_remove_with_runtime(
    vireo_mysql_node_repository_t *repository, const vireo_mysql_node_actor_t *actor,
    const vireo_mysql_node_remove_once_input_t *input, uint32_t timeout_ms,
    vireo_directory_remove_result_t *result, vireo_mysql_node_error_t *error,
    const vireo_directory_remove_runtime_t *runtime) {
    const int saved_errno = errno;
    vireo_result_t rc = VIREO_RESULT_INVALID_ARGUMENT;
    if (result == NULL) {
        goto done;
    }
    memset(result, 0, sizeof(*result));
    if (error != NULL) {
        memset(error, 0, sizeof(*error));
    }
    if (repository == NULL || actor == NULL || input == NULL || runtime == NULL ||
        runtime->remove_once == NULL) {
        goto done;
    }
    if (actor->user_id == 0 || actor->session_id == 0 || input->node_id == 0 ||
        zero_bytes(input->idempotency_key, sizeof(input->idempotency_key)) ||
        zero_bytes(input->request_id, sizeof(input->request_id))) {
        goto done;
    }
    if (timeout_ms > 60000) {
        rc = VIREO_RESULT_RANGE;
        goto done;
    }

    vireo_mysql_node_remove_once_report_t report = {0};
    vireo_mysql_node_error_t diagnostic = {0};
    rc = runtime->remove_once(runtime->context, repository, actor, input, timeout_ms, &report,
                              &diagnostic);
    result->repository_called = true;
    result->repository_result = rc;
    result->repository = report;
    if (error != NULL) {
        *error = diagnostic;
    }
    vireo_directory_remove_outcome_t rejected = domain_outcome(rc, report.issue);
    if (diagnostic.cleanup_result != VIREO_OK) {
        rc = diagnostic.cleanup_result == VIREO_RESULT_NOT_FOUND ? VIREO_RESULT_INTERNAL
                                                                 : diagnostic.cleanup_result;
        goto done;
    }
    if (report.cleanup_pending) {
        if (rc == VIREO_OK || rejected != VIREO_DIRECTORY_REMOVE_NONE) {
            rc = VIREO_RESULT_INTERNAL;
        }
        goto done;
    }
    if (rc == VIREO_OK) {
        if (report.issue != VIREO_MYSQL_NODE_ISSUE_NONE || report.node_id != input->node_id ||
            report.audit_id == 0) {
            rc = VIREO_RESULT_INTERNAL;
            goto done;
        }
        if (report.commit == VIREO_MYSQL_NODE_SOFT_DELETE_COMMITTED &&
            report.effect == VIREO_MYSQL_NODE_REMOVE_EFFECT_APPLIED && !report.rollback_confirmed) {
            result->outcome = VIREO_DIRECTORY_REMOVE_APPLIED;
        } else if (report.commit == VIREO_MYSQL_NODE_SOFT_DELETE_NOT_COMMITTED &&
                   report.effect == VIREO_MYSQL_NODE_REMOVE_EFFECT_RECOVERED &&
                   report.rollback_confirmed) {
            result->outcome = VIREO_DIRECTORY_REMOVE_RECOVERED;
        } else {
            rc = VIREO_RESULT_INTERNAL;
            goto done;
        }
        result->node_id = report.node_id;
        result->audit_id = report.audit_id;
        result->deleted_at_ms = report.deleted_at_ms;
        memcpy(result->idempotency_key, input->idempotency_key, sizeof(result->idempotency_key));
    } else if (rejected != VIREO_DIRECTORY_REMOVE_NONE) {
        if (report.commit != VIREO_MYSQL_NODE_SOFT_DELETE_NOT_COMMITTED ||
            report.effect != VIREO_MYSQL_NODE_REMOVE_EFFECT_NONE || report.node_id != 0 ||
            report.audit_id != 0 || report.deleted_at_ms != 0 || !report.rollback_confirmed) {
            rc = VIREO_RESULT_INTERNAL;
            goto done;
        }
        result->outcome = rejected;
    } else if (rc == VIREO_RESULT_PROTOCOL) {
        rc = VIREO_RESULT_INTERNAL;
    }
done:
    errno = saved_errno;
    return rc;
}

vireo_result_t vireo_directory_service_remove(vireo_mysql_node_repository_t *repository,
                                              const vireo_mysql_node_actor_t *actor,
                                              const vireo_mysql_node_remove_once_input_t *input,
                                              uint32_t timeout_ms,
                                              vireo_directory_remove_result_t *result,
                                              vireo_mysql_node_error_t *error) {
    const vireo_directory_remove_runtime_t runtime = {NULL, native_remove};
    return vireo_directory_service_remove_with_runtime(repository, actor, input, timeout_ms, result,
                                                       error, &runtime);
}
