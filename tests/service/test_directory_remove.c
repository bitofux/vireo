/* PROJECT : VIREO; FILE : test_directory_remove.c; BRIEF : NODE_REMOVE service关系与门禁。 */
#include <assert.h>
#include <errno.h>
#include <string.h>
#include "directory_remove_internal.h"

typedef struct fixture {
    vireo_result_t rc;
    vireo_mysql_node_remove_once_report_t report;
    vireo_mysql_node_error_t error;
    unsigned calls;
} fixture_t;

static vireo_result_t fake_remove(void *context, vireo_mysql_node_repository_t *repository,
                                  const vireo_mysql_node_actor_t *actor,
                                  const vireo_mysql_node_remove_once_input_t *input,
                                  uint32_t timeout_ms,
                                  vireo_mysql_node_remove_once_report_t *report,
                                  vireo_mysql_node_error_t *error) {
    fixture_t *f = context;
    assert(repository != NULL && actor->user_id == 1 && actor->session_id == 2);
    assert(input->node_id == 9 && timeout_ms <= 60000);
    ++f->calls;
    *report = f->report;
    *error = f->error;
    return f->rc;
}

static bool zero_bytes(const unsigned char *bytes, size_t length) {
    unsigned char combined = 0;
    for (size_t i = 0; i < length; ++i) {
        combined |= bytes[i];
    }
    return combined == 0;
}

static vireo_mysql_node_remove_once_report_t applied_report(void) {
    return (vireo_mysql_node_remove_once_report_t){.commit = VIREO_MYSQL_NODE_SOFT_DELETE_COMMITTED,
                                                   .effect = VIREO_MYSQL_NODE_REMOVE_EFFECT_APPLIED,
                                                   .node_id = 9,
                                                   .audit_id = 10,
                                                   .deleted_at_ms = 0};
}

static vireo_mysql_node_remove_once_report_t rejected_report(void) {
    return (vireo_mysql_node_remove_once_report_t){
        .commit = VIREO_MYSQL_NODE_SOFT_DELETE_NOT_COMMITTED, .rollback_confirmed = true};
}

static void assert_report(const vireo_mysql_node_remove_once_report_t *actual,
                          const vireo_mysql_node_remove_once_report_t *expected) {
    assert(actual->commit == expected->commit && actual->effect == expected->effect &&
           actual->issue == expected->issue && actual->node_id == expected->node_id &&
           actual->audit_id == expected->audit_id &&
           actual->deleted_at_ms == expected->deleted_at_ms &&
           actual->rollback_confirmed == expected->rollback_confirmed &&
           actual->cleanup_pending == expected->cleanup_pending);
}

static void run_case(vireo_result_t repo_rc, vireo_mysql_node_remove_once_report_t report,
                     vireo_mysql_node_error_t repo_error, vireo_result_t expected_rc,
                     vireo_directory_remove_outcome_t expected_outcome, bool called) {
    fixture_t f = {.rc = repo_rc, .report = report, .error = repo_error};
    const vireo_directory_remove_runtime_t runtime = {&f, fake_remove};
    const vireo_mysql_node_actor_t actor = {1, 2};
    const vireo_mysql_node_remove_once_input_t input = {
        .node_id = 9, .idempotency_key = {1}, .request_id = {2}};
    vireo_directory_remove_result_t result;
    vireo_mysql_node_error_t out_error;
    memset(&result, 0xa5, sizeof(result));
    memset(&out_error, 0xa5, sizeof(out_error));
    errno = EDOM;
    const vireo_result_t got = vireo_directory_service_remove_with_runtime(
        (void *)1, &actor, &input, 0, &result, &out_error, &runtime);
    assert(got == expected_rc && errno == EDOM && result.outcome == expected_outcome);
    assert(result.repository_called == called && f.calls == (called ? 1U : 0U));
    assert(result.repository_result == (called ? repo_rc : VIREO_OK));
    if (called) {
        assert_report(&result.repository, &report);
        assert(out_error.cleanup_result == repo_error.cleanup_result &&
               out_error.cleanup_stage == repo_error.cleanup_stage);
    } else {
        assert(zero_bytes((const unsigned char *)&result, sizeof(result)));
        assert(zero_bytes((const unsigned char *)&out_error, sizeof(out_error)));
    }
    if (expected_outcome == VIREO_DIRECTORY_REMOVE_APPLIED ||
        expected_outcome == VIREO_DIRECTORY_REMOVE_RECOVERED) {
        assert(result.node_id == 9 && result.audit_id == 10 &&
               result.deleted_at_ms == report.deleted_at_ms);
        assert(memcmp(result.idempotency_key, input.idempotency_key,
                      sizeof(input.idempotency_key)) == 0);
    } else {
        assert(result.node_id == 0 && result.audit_id == 0 && result.deleted_at_ms == 0);
        assert(zero_bytes(result.idempotency_key, sizeof(result.idempotency_key)));
    }
}

static void test_success_and_recovery(void) {
    const vireo_mysql_node_remove_once_report_t applied = applied_report();
    run_case(VIREO_OK, applied, (vireo_mysql_node_error_t){0}, VIREO_OK,
             VIREO_DIRECTORY_REMOVE_APPLIED, true);
    vireo_mysql_node_remove_once_report_t recovered = applied;
    recovered.commit = VIREO_MYSQL_NODE_SOFT_DELETE_NOT_COMMITTED;
    recovered.effect = VIREO_MYSQL_NODE_REMOVE_EFFECT_RECOVERED;
    recovered.rollback_confirmed = true;
    run_case(VIREO_OK, recovered, (vireo_mysql_node_error_t){0}, VIREO_OK,
             VIREO_DIRECTORY_REMOVE_RECOVERED, true);
}

static void test_domain_classifications(void) {
    const struct {
        vireo_result_t rc;
        vireo_mysql_node_issue_t issue;
        vireo_directory_remove_outcome_t outcome;
    } cases[] = {
        {VIREO_RESULT_NOT_FOUND, VIREO_MYSQL_NODE_AUTH_REJECTED,
         VIREO_DIRECTORY_REMOVE_UNAUTHORIZED},
        {VIREO_RESULT_NOT_FOUND, VIREO_MYSQL_NODE_NOT_FOUND, VIREO_DIRECTORY_REMOVE_NOT_FOUND},
        {VIREO_RESULT_DATABASE, VIREO_MYSQL_NODE_ROOT_UNDELETABLE,
         VIREO_DIRECTORY_REMOVE_ROOT_UNDELETABLE},
        {VIREO_RESULT_DATABASE, VIREO_MYSQL_NODE_DIRECTORY_NOT_EMPTY,
         VIREO_DIRECTORY_REMOVE_DIRECTORY_NOT_EMPTY},
        {VIREO_RESULT_DATABASE, VIREO_MYSQL_NODE_OBJECT_REFERENCE_INVALID,
         VIREO_DIRECTORY_REMOVE_OBJECT_REFERENCE_INVALID},
        {VIREO_RESULT_DATABASE, VIREO_MYSQL_NODE_IDEMPOTENCY_CONFLICT,
         VIREO_DIRECTORY_REMOVE_IDEMPOTENCY_CONFLICT},
        {VIREO_RESULT_DATABASE, VIREO_MYSQL_NODE_RECEIPT_INVALID,
         VIREO_DIRECTORY_REMOVE_RECEIPT_INVALID},
        {VIREO_RESULT_RANGE, VIREO_MYSQL_NODE_ANCESTRY_LIMIT,
         VIREO_DIRECTORY_REMOVE_ANCESTRY_LIMIT}};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        vireo_mysql_node_remove_once_report_t report = rejected_report();
        report.issue = cases[i].issue;
        run_case(cases[i].rc, report, (vireo_mysql_node_error_t){0}, cases[i].rc, cases[i].outcome,
                 true);
    }
}

static void test_unclassified_unknown_and_cleanup(void) {
    vireo_mysql_node_remove_once_report_t report = rejected_report();
    report.issue = VIREO_MYSQL_NODE_ISSUE_NONE;
    run_case(VIREO_RESULT_DATABASE, report, (vireo_mysql_node_error_t){0}, VIREO_RESULT_DATABASE,
             VIREO_DIRECTORY_REMOVE_NONE, true);

    report.commit = VIREO_MYSQL_NODE_SOFT_DELETE_UNKNOWN;
    report.rollback_confirmed = false;
    run_case(VIREO_RESULT_DATABASE, report, (vireo_mysql_node_error_t){0}, VIREO_RESULT_DATABASE,
             VIREO_DIRECTORY_REMOVE_NONE, true);

    report = applied_report();
    report.cleanup_pending = true;
    run_case(VIREO_OK, report, (vireo_mysql_node_error_t){0}, VIREO_RESULT_INTERNAL,
             VIREO_DIRECTORY_REMOVE_NONE, true);

    report = rejected_report();
    report.issue = VIREO_MYSQL_NODE_DIRECTORY_NOT_EMPTY;
    report.cleanup_pending = true;
    run_case(VIREO_RESULT_DATABASE, report, (vireo_mysql_node_error_t){0}, VIREO_RESULT_INTERNAL,
             VIREO_DIRECTORY_REMOVE_NONE, true);

    vireo_mysql_node_error_t cleanup = {.cleanup_result = VIREO_RESULT_BUSY,
                                        .cleanup_stage = VIREO_MYSQL_NODE_STAGE_RELEASE};
    run_case(VIREO_OK, applied_report(), cleanup, VIREO_RESULT_BUSY, VIREO_DIRECTORY_REMOVE_NONE,
             true);
    cleanup.cleanup_result = VIREO_RESULT_NOT_FOUND;
    run_case(VIREO_RESULT_DATABASE, applied_report(), cleanup, VIREO_RESULT_INTERNAL,
             VIREO_DIRECTORY_REMOVE_NONE, true);

    report = rejected_report();
    report.issue = VIREO_MYSQL_NODE_NOT_FOUND;
    run_case(VIREO_RESULT_DATABASE, report, (vireo_mysql_node_error_t){0}, VIREO_RESULT_DATABASE,
             VIREO_DIRECTORY_REMOVE_NONE, true);
    run_case(VIREO_RESULT_PROTOCOL, rejected_report(), (vireo_mysql_node_error_t){0},
             VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_REMOVE_NONE, true);
    run_case(VIREO_RESULT_RANGE, rejected_report(), (vireo_mysql_node_error_t){0},
             VIREO_RESULT_RANGE, VIREO_DIRECTORY_REMOVE_NONE, true);
}

static void test_bad_reports(void) {
    vireo_mysql_node_remove_once_report_t report = applied_report();
    report.node_id = 8;
    run_case(VIREO_OK, report, (vireo_mysql_node_error_t){0}, VIREO_RESULT_INTERNAL,
             VIREO_DIRECTORY_REMOVE_NONE, true);
    report = applied_report();
    report.audit_id = 0;
    run_case(VIREO_OK, report, (vireo_mysql_node_error_t){0}, VIREO_RESULT_INTERNAL,
             VIREO_DIRECTORY_REMOVE_NONE, true);
    report = applied_report();
    report.issue = VIREO_MYSQL_NODE_UNEXPECTED_RESULT;
    run_case(VIREO_OK, report, (vireo_mysql_node_error_t){0}, VIREO_RESULT_INTERNAL,
             VIREO_DIRECTORY_REMOVE_NONE, true);
    report = applied_report();
    report.rollback_confirmed = true;
    run_case(VIREO_OK, report, (vireo_mysql_node_error_t){0}, VIREO_RESULT_INTERNAL,
             VIREO_DIRECTORY_REMOVE_NONE, true);
    report = rejected_report();
    report.issue = VIREO_MYSQL_NODE_ROOT_UNDELETABLE;
    report.rollback_confirmed = false;
    run_case(VIREO_RESULT_DATABASE, report, (vireo_mysql_node_error_t){0}, VIREO_RESULT_INTERNAL,
             VIREO_DIRECTORY_REMOVE_NONE, true);
    report = rejected_report();
    report.issue = VIREO_MYSQL_NODE_ROOT_UNDELETABLE;
    report.node_id = 9;
    run_case(VIREO_RESULT_DATABASE, report, (vireo_mysql_node_error_t){0}, VIREO_RESULT_INTERNAL,
             VIREO_DIRECTORY_REMOVE_NONE, true);
}

static void test_argument_gates(void) {
    fixture_t f = {.rc = VIREO_OK, .report = applied_report()};
    const vireo_directory_remove_runtime_t runtime = {&f, fake_remove};
    const vireo_mysql_node_actor_t actor = {1, 2};
    const vireo_mysql_node_remove_once_input_t input = {
        .node_id = 9, .idempotency_key = {1}, .request_id = {2}};
    vireo_directory_remove_result_t result;
    vireo_mysql_node_error_t error;
    memset(&result, 0xa5, sizeof(result));
    memset(&error, 0xa5, sizeof(error));
    errno = EDOM;
    assert(vireo_directory_service_remove_with_runtime(NULL, &actor, &input, 0, &result, &error,
                                                       &runtime) == VIREO_RESULT_INVALID_ARGUMENT);
    assert(errno == EDOM && f.calls == 0 &&
           zero_bytes((const unsigned char *)&result, sizeof(result)) &&
           zero_bytes((const unsigned char *)&error, sizeof(error)));

    vireo_mysql_node_actor_t bad_actor = actor;
    bad_actor.session_id = 0;
    memset(&result, 0xa5, sizeof(result));
    assert(vireo_directory_service_remove_with_runtime((void *)1, &bad_actor, &input, 0, &result,
                                                       NULL,
                                                       &runtime) == VIREO_RESULT_INVALID_ARGUMENT);
    assert(f.calls == 0 && zero_bytes((const unsigned char *)&result, sizeof(result)));

    vireo_mysql_node_remove_once_input_t bad_input = input;
    memset(bad_input.idempotency_key, 0, sizeof(bad_input.idempotency_key));
    assert(vireo_directory_service_remove_with_runtime((void *)1, &actor, &bad_input, 0, &result,
                                                       NULL,
                                                       &runtime) == VIREO_RESULT_INVALID_ARGUMENT &&
           f.calls == 0);
    bad_input = input;
    memset(bad_input.request_id, 0, sizeof(bad_input.request_id));
    assert(vireo_directory_service_remove_with_runtime((void *)1, &actor, &bad_input, 0, &result,
                                                       NULL,
                                                       &runtime) == VIREO_RESULT_INVALID_ARGUMENT &&
           f.calls == 0);
    bad_input = input;
    bad_input.node_id = 0;
    assert(vireo_directory_service_remove_with_runtime((void *)1, &actor, &bad_input, 0, &result,
                                                       NULL,
                                                       &runtime) == VIREO_RESULT_INVALID_ARGUMENT &&
           f.calls == 0);
    assert(vireo_directory_service_remove_with_runtime((void *)1, &actor, &input, 60001, &result,
                                                       NULL, &runtime) == VIREO_RESULT_RANGE &&
           f.calls == 0);
    assert(vireo_directory_service_remove_with_runtime((void *)1, &actor, &input, 60000, &result,
                                                       NULL, &runtime) == VIREO_OK &&
           f.calls == 1);
    assert(vireo_directory_service_remove_with_runtime((void *)1, &actor, &input, 0, &result, NULL,
                                                       NULL) == VIREO_RESULT_INVALID_ARGUMENT &&
           f.calls == 1);
    assert(vireo_directory_service_remove_with_runtime((void *)1, &actor, &input, 0, NULL, &error,
                                                       &runtime) == VIREO_RESULT_INVALID_ARGUMENT);
}

int main(void) {
    test_success_and_recovery();
    test_domain_classifications();
    test_unclassified_unknown_and_cleanup();
    test_bad_reports();
    test_argument_gates();
    return 0;
}
