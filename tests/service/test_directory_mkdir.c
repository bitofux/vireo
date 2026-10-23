/* PROJECT : VIREO; FILE : test_directory_mkdir.c; AUTHOR : bitofux;
 * DATE : 2026-10-24; BRIEF : 独立设计样例、原始报告保留及调用门禁。 */
#include "directory_mkdir_internal.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct scenario {
    const char *label;
    vireo_result_t rc;
    vireo_mysql_node_mkdir_once_report_t report;
    vireo_result_t cleanup, want;
    vireo_directory_mkdir_outcome_t outcome;
};
static const struct scenario scenarios[] = {
    {"create", VIREO_OK, {.commit=VIREO_MYSQL_NODE_MKDIR_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_CREATED, .issue=VIREO_MYSQL_NODE_ISSUE_NONE, .node_id=101, .audit_id=88, .idempotency_key={1}, .rollback_confirmed=false, .cleanup_pending=false}, VIREO_OK, VIREO_OK, VIREO_DIRECTORY_MKDIR_CREATED},
    {"create-pending", VIREO_OK, {.commit=VIREO_MYSQL_NODE_MKDIR_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_CREATED, .issue=VIREO_MYSQL_NODE_ISSUE_NONE, .node_id=101, .audit_id=88, .idempotency_key={1}, .rollback_confirmed=false, .cleanup_pending=true}, VIREO_OK, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE},
    {"create-cleanup-NO_MEMORY", VIREO_OK, {.commit=VIREO_MYSQL_NODE_MKDIR_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_CREATED, .issue=VIREO_MYSQL_NODE_ISSUE_NONE, .node_id=101, .audit_id=88, .idempotency_key={1}, .rollback_confirmed=false, .cleanup_pending=false}, VIREO_RESULT_NO_MEMORY, VIREO_RESULT_NO_MEMORY, VIREO_DIRECTORY_MKDIR_NONE},
    {"create-cleanup-BUSY", VIREO_OK, {.commit=VIREO_MYSQL_NODE_MKDIR_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_CREATED, .issue=VIREO_MYSQL_NODE_ISSUE_NONE, .node_id=101, .audit_id=88, .idempotency_key={1}, .rollback_confirmed=false, .cleanup_pending=false}, VIREO_RESULT_BUSY, VIREO_RESULT_BUSY, VIREO_DIRECTORY_MKDIR_NONE},
    {"create-cleanup-DATABASE", VIREO_OK, {.commit=VIREO_MYSQL_NODE_MKDIR_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_CREATED, .issue=VIREO_MYSQL_NODE_ISSUE_NONE, .node_id=101, .audit_id=88, .idempotency_key={1}, .rollback_confirmed=false, .cleanup_pending=false}, VIREO_RESULT_DATABASE, VIREO_RESULT_DATABASE, VIREO_DIRECTORY_MKDIR_NONE},
    {"create-cleanup-IO", VIREO_OK, {.commit=VIREO_MYSQL_NODE_MKDIR_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_CREATED, .issue=VIREO_MYSQL_NODE_ISSUE_NONE, .node_id=101, .audit_id=88, .idempotency_key={1}, .rollback_confirmed=false, .cleanup_pending=false}, VIREO_RESULT_IO, VIREO_RESULT_IO, VIREO_DIRECTORY_MKDIR_NONE},
    {"create-cleanup-NOT_FOUND", VIREO_OK, {.commit=VIREO_MYSQL_NODE_MKDIR_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_CREATED, .issue=VIREO_MYSQL_NODE_ISSUE_NONE, .node_id=101, .audit_id=88, .idempotency_key={1}, .rollback_confirmed=false, .cleanup_pending=false}, VIREO_RESULT_NOT_FOUND, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE},
    {"recover", VIREO_OK, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_RECOVERED, .issue=VIREO_MYSQL_NODE_ISSUE_NONE, .node_id=101, .audit_id=88, .idempotency_key={1}, .rollback_confirmed=true, .cleanup_pending=false}, VIREO_OK, VIREO_OK, VIREO_DIRECTORY_MKDIR_RECOVERED},
    {"recover-pending", VIREO_OK, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_RECOVERED, .issue=VIREO_MYSQL_NODE_ISSUE_NONE, .node_id=101, .audit_id=88, .idempotency_key={1}, .rollback_confirmed=true, .cleanup_pending=true}, VIREO_OK, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE},
    {"recover-cleanup-NO_MEMORY", VIREO_OK, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_RECOVERED, .issue=VIREO_MYSQL_NODE_ISSUE_NONE, .node_id=101, .audit_id=88, .idempotency_key={1}, .rollback_confirmed=true, .cleanup_pending=false}, VIREO_RESULT_NO_MEMORY, VIREO_RESULT_NO_MEMORY, VIREO_DIRECTORY_MKDIR_NONE},
    {"recover-cleanup-BUSY", VIREO_OK, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_RECOVERED, .issue=VIREO_MYSQL_NODE_ISSUE_NONE, .node_id=101, .audit_id=88, .idempotency_key={1}, .rollback_confirmed=true, .cleanup_pending=false}, VIREO_RESULT_BUSY, VIREO_RESULT_BUSY, VIREO_DIRECTORY_MKDIR_NONE},
    {"recover-cleanup-DATABASE", VIREO_OK, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_RECOVERED, .issue=VIREO_MYSQL_NODE_ISSUE_NONE, .node_id=101, .audit_id=88, .idempotency_key={1}, .rollback_confirmed=true, .cleanup_pending=false}, VIREO_RESULT_DATABASE, VIREO_RESULT_DATABASE, VIREO_DIRECTORY_MKDIR_NONE},
    {"recover-cleanup-IO", VIREO_OK, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_RECOVERED, .issue=VIREO_MYSQL_NODE_ISSUE_NONE, .node_id=101, .audit_id=88, .idempotency_key={1}, .rollback_confirmed=true, .cleanup_pending=false}, VIREO_RESULT_IO, VIREO_RESULT_IO, VIREO_DIRECTORY_MKDIR_NONE},
    {"recover-cleanup-NOT_FOUND", VIREO_OK, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_RECOVERED, .issue=VIREO_MYSQL_NODE_ISSUE_NONE, .node_id=101, .audit_id=88, .idempotency_key={1}, .rollback_confirmed=true, .cleanup_pending=false}, VIREO_RESULT_NOT_FOUND, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE},
    {"AUTH_REJECTED", VIREO_RESULT_NOT_FOUND, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE, .issue=VIREO_MYSQL_NODE_AUTH_REJECTED, .node_id=0, .audit_id=0,  .rollback_confirmed=true, .cleanup_pending=false}, VIREO_OK, VIREO_RESULT_NOT_FOUND, VIREO_DIRECTORY_MKDIR_UNAUTHORIZED},
    {"AUTH_REJECTED-pending", VIREO_RESULT_NOT_FOUND, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE, .issue=VIREO_MYSQL_NODE_AUTH_REJECTED, .node_id=0, .audit_id=0,  .rollback_confirmed=true, .cleanup_pending=true}, VIREO_OK, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE},
    {"AUTH_REJECTED-cleanup-NO_MEMORY", VIREO_RESULT_NOT_FOUND, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE, .issue=VIREO_MYSQL_NODE_AUTH_REJECTED, .node_id=0, .audit_id=0,  .rollback_confirmed=true, .cleanup_pending=false}, VIREO_RESULT_NO_MEMORY, VIREO_RESULT_NO_MEMORY, VIREO_DIRECTORY_MKDIR_NONE},
    {"AUTH_REJECTED-cleanup-BUSY", VIREO_RESULT_NOT_FOUND, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE, .issue=VIREO_MYSQL_NODE_AUTH_REJECTED, .node_id=0, .audit_id=0,  .rollback_confirmed=true, .cleanup_pending=false}, VIREO_RESULT_BUSY, VIREO_RESULT_BUSY, VIREO_DIRECTORY_MKDIR_NONE},
    {"AUTH_REJECTED-cleanup-DATABASE", VIREO_RESULT_NOT_FOUND, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE, .issue=VIREO_MYSQL_NODE_AUTH_REJECTED, .node_id=0, .audit_id=0,  .rollback_confirmed=true, .cleanup_pending=false}, VIREO_RESULT_DATABASE, VIREO_RESULT_DATABASE, VIREO_DIRECTORY_MKDIR_NONE},
    {"AUTH_REJECTED-cleanup-IO", VIREO_RESULT_NOT_FOUND, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE, .issue=VIREO_MYSQL_NODE_AUTH_REJECTED, .node_id=0, .audit_id=0,  .rollback_confirmed=true, .cleanup_pending=false}, VIREO_RESULT_IO, VIREO_RESULT_IO, VIREO_DIRECTORY_MKDIR_NONE},
    {"AUTH_REJECTED-cleanup-NOT_FOUND", VIREO_RESULT_NOT_FOUND, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE, .issue=VIREO_MYSQL_NODE_AUTH_REJECTED, .node_id=0, .audit_id=0,  .rollback_confirmed=true, .cleanup_pending=false}, VIREO_RESULT_NOT_FOUND, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE},
    {"NODE_NOT_FOUND", VIREO_RESULT_NOT_FOUND, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE, .issue=VIREO_MYSQL_NODE_NOT_FOUND, .node_id=0, .audit_id=0,  .rollback_confirmed=true, .cleanup_pending=false}, VIREO_OK, VIREO_RESULT_NOT_FOUND, VIREO_DIRECTORY_MKDIR_PARENT_NOT_FOUND},
    {"NODE_NOT_FOUND-pending", VIREO_RESULT_NOT_FOUND, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE, .issue=VIREO_MYSQL_NODE_NOT_FOUND, .node_id=0, .audit_id=0,  .rollback_confirmed=true, .cleanup_pending=true}, VIREO_OK, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE},
    {"NODE_NOT_FOUND-cleanup-NO_MEMORY", VIREO_RESULT_NOT_FOUND, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE, .issue=VIREO_MYSQL_NODE_NOT_FOUND, .node_id=0, .audit_id=0,  .rollback_confirmed=true, .cleanup_pending=false}, VIREO_RESULT_NO_MEMORY, VIREO_RESULT_NO_MEMORY, VIREO_DIRECTORY_MKDIR_NONE},
    {"NODE_NOT_FOUND-cleanup-BUSY", VIREO_RESULT_NOT_FOUND, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE, .issue=VIREO_MYSQL_NODE_NOT_FOUND, .node_id=0, .audit_id=0,  .rollback_confirmed=true, .cleanup_pending=false}, VIREO_RESULT_BUSY, VIREO_RESULT_BUSY, VIREO_DIRECTORY_MKDIR_NONE},
    {"NODE_NOT_FOUND-cleanup-DATABASE", VIREO_RESULT_NOT_FOUND, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE, .issue=VIREO_MYSQL_NODE_NOT_FOUND, .node_id=0, .audit_id=0,  .rollback_confirmed=true, .cleanup_pending=false}, VIREO_RESULT_DATABASE, VIREO_RESULT_DATABASE, VIREO_DIRECTORY_MKDIR_NONE},
    {"NODE_NOT_FOUND-cleanup-IO", VIREO_RESULT_NOT_FOUND, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE, .issue=VIREO_MYSQL_NODE_NOT_FOUND, .node_id=0, .audit_id=0,  .rollback_confirmed=true, .cleanup_pending=false}, VIREO_RESULT_IO, VIREO_RESULT_IO, VIREO_DIRECTORY_MKDIR_NONE},
    {"NODE_NOT_FOUND-cleanup-NOT_FOUND", VIREO_RESULT_NOT_FOUND, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE, .issue=VIREO_MYSQL_NODE_NOT_FOUND, .node_id=0, .audit_id=0,  .rollback_confirmed=true, .cleanup_pending=false}, VIREO_RESULT_NOT_FOUND, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE},
    {"NAME_CONFLICT", VIREO_RESULT_DATABASE, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE, .issue=VIREO_MYSQL_NODE_NAME_CONFLICT, .node_id=0, .audit_id=0,  .rollback_confirmed=true, .cleanup_pending=false}, VIREO_OK, VIREO_RESULT_DATABASE, VIREO_DIRECTORY_MKDIR_NAME_CONFLICT},
    {"NAME_CONFLICT-pending", VIREO_RESULT_DATABASE, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE, .issue=VIREO_MYSQL_NODE_NAME_CONFLICT, .node_id=0, .audit_id=0,  .rollback_confirmed=true, .cleanup_pending=true}, VIREO_OK, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE},
    {"NAME_CONFLICT-cleanup-NO_MEMORY", VIREO_RESULT_DATABASE, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE, .issue=VIREO_MYSQL_NODE_NAME_CONFLICT, .node_id=0, .audit_id=0,  .rollback_confirmed=true, .cleanup_pending=false}, VIREO_RESULT_NO_MEMORY, VIREO_RESULT_NO_MEMORY, VIREO_DIRECTORY_MKDIR_NONE},
    {"NAME_CONFLICT-cleanup-BUSY", VIREO_RESULT_DATABASE, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE, .issue=VIREO_MYSQL_NODE_NAME_CONFLICT, .node_id=0, .audit_id=0,  .rollback_confirmed=true, .cleanup_pending=false}, VIREO_RESULT_BUSY, VIREO_RESULT_BUSY, VIREO_DIRECTORY_MKDIR_NONE},
    {"NAME_CONFLICT-cleanup-DATABASE", VIREO_RESULT_DATABASE, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE, .issue=VIREO_MYSQL_NODE_NAME_CONFLICT, .node_id=0, .audit_id=0,  .rollback_confirmed=true, .cleanup_pending=false}, VIREO_RESULT_DATABASE, VIREO_RESULT_DATABASE, VIREO_DIRECTORY_MKDIR_NONE},
    {"NAME_CONFLICT-cleanup-IO", VIREO_RESULT_DATABASE, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE, .issue=VIREO_MYSQL_NODE_NAME_CONFLICT, .node_id=0, .audit_id=0,  .rollback_confirmed=true, .cleanup_pending=false}, VIREO_RESULT_IO, VIREO_RESULT_IO, VIREO_DIRECTORY_MKDIR_NONE},
    {"NAME_CONFLICT-cleanup-NOT_FOUND", VIREO_RESULT_DATABASE, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE, .issue=VIREO_MYSQL_NODE_NAME_CONFLICT, .node_id=0, .audit_id=0,  .rollback_confirmed=true, .cleanup_pending=false}, VIREO_RESULT_NOT_FOUND, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE},
    {"IDEMPOTENCY_CONFLICT", VIREO_RESULT_DATABASE, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE, .issue=VIREO_MYSQL_NODE_IDEMPOTENCY_CONFLICT, .node_id=0, .audit_id=0,  .rollback_confirmed=true, .cleanup_pending=false}, VIREO_OK, VIREO_RESULT_DATABASE, VIREO_DIRECTORY_MKDIR_IDEMPOTENCY_CONFLICT},
    {"IDEMPOTENCY_CONFLICT-pending", VIREO_RESULT_DATABASE, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE, .issue=VIREO_MYSQL_NODE_IDEMPOTENCY_CONFLICT, .node_id=0, .audit_id=0,  .rollback_confirmed=true, .cleanup_pending=true}, VIREO_OK, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE},
    {"IDEMPOTENCY_CONFLICT-cleanup-NO_MEMORY", VIREO_RESULT_DATABASE, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE, .issue=VIREO_MYSQL_NODE_IDEMPOTENCY_CONFLICT, .node_id=0, .audit_id=0,  .rollback_confirmed=true, .cleanup_pending=false}, VIREO_RESULT_NO_MEMORY, VIREO_RESULT_NO_MEMORY, VIREO_DIRECTORY_MKDIR_NONE},
    {"IDEMPOTENCY_CONFLICT-cleanup-BUSY", VIREO_RESULT_DATABASE, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE, .issue=VIREO_MYSQL_NODE_IDEMPOTENCY_CONFLICT, .node_id=0, .audit_id=0,  .rollback_confirmed=true, .cleanup_pending=false}, VIREO_RESULT_BUSY, VIREO_RESULT_BUSY, VIREO_DIRECTORY_MKDIR_NONE},
    {"IDEMPOTENCY_CONFLICT-cleanup-DATABASE", VIREO_RESULT_DATABASE, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE, .issue=VIREO_MYSQL_NODE_IDEMPOTENCY_CONFLICT, .node_id=0, .audit_id=0,  .rollback_confirmed=true, .cleanup_pending=false}, VIREO_RESULT_DATABASE, VIREO_RESULT_DATABASE, VIREO_DIRECTORY_MKDIR_NONE},
    {"IDEMPOTENCY_CONFLICT-cleanup-IO", VIREO_RESULT_DATABASE, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE, .issue=VIREO_MYSQL_NODE_IDEMPOTENCY_CONFLICT, .node_id=0, .audit_id=0,  .rollback_confirmed=true, .cleanup_pending=false}, VIREO_RESULT_IO, VIREO_RESULT_IO, VIREO_DIRECTORY_MKDIR_NONE},
    {"IDEMPOTENCY_CONFLICT-cleanup-NOT_FOUND", VIREO_RESULT_DATABASE, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE, .issue=VIREO_MYSQL_NODE_IDEMPOTENCY_CONFLICT, .node_id=0, .audit_id=0,  .rollback_confirmed=true, .cleanup_pending=false}, VIREO_RESULT_NOT_FOUND, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE},
    {"create-contradiction-node", VIREO_OK, {.commit=VIREO_MYSQL_NODE_MKDIR_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_CREATED, .issue=VIREO_MYSQL_NODE_ISSUE_NONE, .node_id=0, .audit_id=88, .idempotency_key={1}, .rollback_confirmed=false, .cleanup_pending=false}, VIREO_OK, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE},
    {"create-contradiction-audit", VIREO_OK, {.commit=VIREO_MYSQL_NODE_MKDIR_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_CREATED, .issue=VIREO_MYSQL_NODE_ISSUE_NONE, .node_id=101, .audit_id=0, .idempotency_key={1}, .rollback_confirmed=false, .cleanup_pending=false}, VIREO_OK, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE},
    {"create-contradiction-key", VIREO_OK, {.commit=VIREO_MYSQL_NODE_MKDIR_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_CREATED, .issue=VIREO_MYSQL_NODE_ISSUE_NONE, .node_id=101, .audit_id=88, .idempotency_key={2}, .rollback_confirmed=false, .cleanup_pending=false}, VIREO_OK, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE},
    {"create-contradiction-issue", VIREO_OK, {.commit=VIREO_MYSQL_NODE_MKDIR_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_CREATED, .issue=VIREO_MYSQL_NODE_AUTH_REJECTED, .node_id=101, .audit_id=88, .idempotency_key={1}, .rollback_confirmed=false, .cleanup_pending=false}, VIREO_OK, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE},
    {"create-contradiction-commit", VIREO_OK, {.commit=VIREO_MYSQL_NODE_MKDIR_UNKNOWN, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_CREATED, .issue=VIREO_MYSQL_NODE_ISSUE_NONE, .node_id=101, .audit_id=88, .idempotency_key={1}, .rollback_confirmed=false, .cleanup_pending=false}, VIREO_OK, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE},
    {"create-contradiction-effect", VIREO_OK, {.commit=VIREO_MYSQL_NODE_MKDIR_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE, .issue=VIREO_MYSQL_NODE_ISSUE_NONE, .node_id=101, .audit_id=88, .idempotency_key={1}, .rollback_confirmed=false, .cleanup_pending=false}, VIREO_OK, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE},
    {"create-contradiction-rollback", VIREO_OK, {.commit=VIREO_MYSQL_NODE_MKDIR_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_CREATED, .issue=VIREO_MYSQL_NODE_ISSUE_NONE, .node_id=101, .audit_id=88, .idempotency_key={1}, .rollback_confirmed=true, .cleanup_pending=false}, VIREO_OK, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE},
    {"create-known-effect-but-DATABASE", VIREO_RESULT_DATABASE, {.commit=VIREO_MYSQL_NODE_MKDIR_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_CREATED, .issue=VIREO_MYSQL_NODE_ISSUE_NONE, .node_id=101, .audit_id=88, .idempotency_key={1}, .rollback_confirmed=false, .cleanup_pending=false}, VIREO_OK, VIREO_RESULT_DATABASE, VIREO_DIRECTORY_MKDIR_NONE},
    {"create-known-effect-but-NO_MEMORY", VIREO_RESULT_NO_MEMORY, {.commit=VIREO_MYSQL_NODE_MKDIR_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_CREATED, .issue=VIREO_MYSQL_NODE_ISSUE_NONE, .node_id=101, .audit_id=88, .idempotency_key={1}, .rollback_confirmed=false, .cleanup_pending=false}, VIREO_OK, VIREO_RESULT_NO_MEMORY, VIREO_DIRECTORY_MKDIR_NONE},
    {"create-known-effect-but-IO", VIREO_RESULT_IO, {.commit=VIREO_MYSQL_NODE_MKDIR_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_CREATED, .issue=VIREO_MYSQL_NODE_ISSUE_NONE, .node_id=101, .audit_id=88, .idempotency_key={1}, .rollback_confirmed=false, .cleanup_pending=false}, VIREO_OK, VIREO_RESULT_IO, VIREO_DIRECTORY_MKDIR_NONE},
    {"recover-contradiction-node", VIREO_OK, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_RECOVERED, .issue=VIREO_MYSQL_NODE_ISSUE_NONE, .node_id=0, .audit_id=88, .idempotency_key={1}, .rollback_confirmed=true, .cleanup_pending=false}, VIREO_OK, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE},
    {"recover-contradiction-audit", VIREO_OK, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_RECOVERED, .issue=VIREO_MYSQL_NODE_ISSUE_NONE, .node_id=101, .audit_id=0, .idempotency_key={1}, .rollback_confirmed=true, .cleanup_pending=false}, VIREO_OK, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE},
    {"recover-contradiction-key", VIREO_OK, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_RECOVERED, .issue=VIREO_MYSQL_NODE_ISSUE_NONE, .node_id=101, .audit_id=88, .idempotency_key={2}, .rollback_confirmed=true, .cleanup_pending=false}, VIREO_OK, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE},
    {"recover-contradiction-issue", VIREO_OK, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_RECOVERED, .issue=VIREO_MYSQL_NODE_AUTH_REJECTED, .node_id=101, .audit_id=88, .idempotency_key={1}, .rollback_confirmed=true, .cleanup_pending=false}, VIREO_OK, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE},
    {"recover-contradiction-commit", VIREO_OK, {.commit=VIREO_MYSQL_NODE_MKDIR_UNKNOWN, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_RECOVERED, .issue=VIREO_MYSQL_NODE_ISSUE_NONE, .node_id=101, .audit_id=88, .idempotency_key={1}, .rollback_confirmed=true, .cleanup_pending=false}, VIREO_OK, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE},
    {"recover-contradiction-effect", VIREO_OK, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE, .issue=VIREO_MYSQL_NODE_ISSUE_NONE, .node_id=101, .audit_id=88, .idempotency_key={1}, .rollback_confirmed=true, .cleanup_pending=false}, VIREO_OK, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE},
    {"recover-contradiction-rollback", VIREO_OK, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_RECOVERED, .issue=VIREO_MYSQL_NODE_ISSUE_NONE, .node_id=101, .audit_id=88, .idempotency_key={1}, .rollback_confirmed=false, .cleanup_pending=false}, VIREO_OK, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE},
    {"recover-known-effect-but-DATABASE", VIREO_RESULT_DATABASE, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_RECOVERED, .issue=VIREO_MYSQL_NODE_ISSUE_NONE, .node_id=101, .audit_id=88, .idempotency_key={1}, .rollback_confirmed=true, .cleanup_pending=false}, VIREO_OK, VIREO_RESULT_DATABASE, VIREO_DIRECTORY_MKDIR_NONE},
    {"recover-known-effect-but-NO_MEMORY", VIREO_RESULT_NO_MEMORY, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_RECOVERED, .issue=VIREO_MYSQL_NODE_ISSUE_NONE, .node_id=101, .audit_id=88, .idempotency_key={1}, .rollback_confirmed=true, .cleanup_pending=false}, VIREO_OK, VIREO_RESULT_NO_MEMORY, VIREO_DIRECTORY_MKDIR_NONE},
    {"recover-known-effect-but-IO", VIREO_RESULT_IO, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_RECOVERED, .issue=VIREO_MYSQL_NODE_ISSUE_NONE, .node_id=101, .audit_id=88, .idempotency_key={1}, .rollback_confirmed=true, .cleanup_pending=false}, VIREO_OK, VIREO_RESULT_IO, VIREO_DIRECTORY_MKDIR_NONE},
    {"AUTH_REJECTED-mutation-node", VIREO_RESULT_NOT_FOUND, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE, .issue=VIREO_MYSQL_NODE_AUTH_REJECTED, .node_id=1, .audit_id=0,  .rollback_confirmed=true, .cleanup_pending=false}, VIREO_OK, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE},
    {"AUTH_REJECTED-mutation-audit", VIREO_RESULT_NOT_FOUND, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE, .issue=VIREO_MYSQL_NODE_AUTH_REJECTED, .node_id=0, .audit_id=1,  .rollback_confirmed=true, .cleanup_pending=false}, VIREO_OK, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE},
    {"AUTH_REJECTED-mutation-key", VIREO_RESULT_NOT_FOUND, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE, .issue=VIREO_MYSQL_NODE_AUTH_REJECTED, .node_id=0, .audit_id=0, .idempotency_key={1}, .rollback_confirmed=true, .cleanup_pending=false}, VIREO_OK, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE},
    {"AUTH_REJECTED-mutation-commit", VIREO_RESULT_NOT_FOUND, {.commit=VIREO_MYSQL_NODE_MKDIR_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE, .issue=VIREO_MYSQL_NODE_AUTH_REJECTED, .node_id=0, .audit_id=0,  .rollback_confirmed=true, .cleanup_pending=false}, VIREO_OK, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE},
    {"AUTH_REJECTED-mutation-effect", VIREO_RESULT_NOT_FOUND, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_CREATED, .issue=VIREO_MYSQL_NODE_AUTH_REJECTED, .node_id=0, .audit_id=0,  .rollback_confirmed=true, .cleanup_pending=false}, VIREO_OK, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE},
    {"AUTH_REJECTED-mutation-rollback", VIREO_RESULT_NOT_FOUND, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE, .issue=VIREO_MYSQL_NODE_AUTH_REJECTED, .node_id=0, .audit_id=0,  .rollback_confirmed=false, .cleanup_pending=false}, VIREO_OK, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE},
    {"AUTH_REJECTED-mutation-issue", VIREO_RESULT_NOT_FOUND, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE, .issue=VIREO_MYSQL_NODE_ISSUE_NONE, .node_id=0, .audit_id=0,  .rollback_confirmed=true, .cleanup_pending=false}, VIREO_OK, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE},
    {"NODE_NOT_FOUND-mutation-node", VIREO_RESULT_NOT_FOUND, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE, .issue=VIREO_MYSQL_NODE_NOT_FOUND, .node_id=1, .audit_id=0,  .rollback_confirmed=true, .cleanup_pending=false}, VIREO_OK, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE},
    {"NODE_NOT_FOUND-mutation-audit", VIREO_RESULT_NOT_FOUND, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE, .issue=VIREO_MYSQL_NODE_NOT_FOUND, .node_id=0, .audit_id=1,  .rollback_confirmed=true, .cleanup_pending=false}, VIREO_OK, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE},
    {"NODE_NOT_FOUND-mutation-key", VIREO_RESULT_NOT_FOUND, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE, .issue=VIREO_MYSQL_NODE_NOT_FOUND, .node_id=0, .audit_id=0, .idempotency_key={1}, .rollback_confirmed=true, .cleanup_pending=false}, VIREO_OK, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE},
    {"NODE_NOT_FOUND-mutation-commit", VIREO_RESULT_NOT_FOUND, {.commit=VIREO_MYSQL_NODE_MKDIR_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE, .issue=VIREO_MYSQL_NODE_NOT_FOUND, .node_id=0, .audit_id=0,  .rollback_confirmed=true, .cleanup_pending=false}, VIREO_OK, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE},
    {"NODE_NOT_FOUND-mutation-effect", VIREO_RESULT_NOT_FOUND, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_CREATED, .issue=VIREO_MYSQL_NODE_NOT_FOUND, .node_id=0, .audit_id=0,  .rollback_confirmed=true, .cleanup_pending=false}, VIREO_OK, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE},
    {"NODE_NOT_FOUND-mutation-rollback", VIREO_RESULT_NOT_FOUND, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE, .issue=VIREO_MYSQL_NODE_NOT_FOUND, .node_id=0, .audit_id=0,  .rollback_confirmed=false, .cleanup_pending=false}, VIREO_OK, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE},
    {"NODE_NOT_FOUND-mutation-issue", VIREO_RESULT_NOT_FOUND, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE, .issue=VIREO_MYSQL_NODE_ISSUE_NONE, .node_id=0, .audit_id=0,  .rollback_confirmed=true, .cleanup_pending=false}, VIREO_OK, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE},
    {"NAME_CONFLICT-mutation-node", VIREO_RESULT_DATABASE, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE, .issue=VIREO_MYSQL_NODE_NAME_CONFLICT, .node_id=1, .audit_id=0,  .rollback_confirmed=true, .cleanup_pending=false}, VIREO_OK, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE},
    {"NAME_CONFLICT-mutation-audit", VIREO_RESULT_DATABASE, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE, .issue=VIREO_MYSQL_NODE_NAME_CONFLICT, .node_id=0, .audit_id=1,  .rollback_confirmed=true, .cleanup_pending=false}, VIREO_OK, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE},
    {"NAME_CONFLICT-mutation-key", VIREO_RESULT_DATABASE, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE, .issue=VIREO_MYSQL_NODE_NAME_CONFLICT, .node_id=0, .audit_id=0, .idempotency_key={1}, .rollback_confirmed=true, .cleanup_pending=false}, VIREO_OK, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE},
    {"NAME_CONFLICT-mutation-commit", VIREO_RESULT_DATABASE, {.commit=VIREO_MYSQL_NODE_MKDIR_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE, .issue=VIREO_MYSQL_NODE_NAME_CONFLICT, .node_id=0, .audit_id=0,  .rollback_confirmed=true, .cleanup_pending=false}, VIREO_OK, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE},
    {"NAME_CONFLICT-mutation-effect", VIREO_RESULT_DATABASE, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_CREATED, .issue=VIREO_MYSQL_NODE_NAME_CONFLICT, .node_id=0, .audit_id=0,  .rollback_confirmed=true, .cleanup_pending=false}, VIREO_OK, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE},
    {"NAME_CONFLICT-mutation-rollback", VIREO_RESULT_DATABASE, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE, .issue=VIREO_MYSQL_NODE_NAME_CONFLICT, .node_id=0, .audit_id=0,  .rollback_confirmed=false, .cleanup_pending=false}, VIREO_OK, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE},
    {"NAME_CONFLICT-mutation-issue", VIREO_RESULT_DATABASE, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE, .issue=VIREO_MYSQL_NODE_ISSUE_NONE, .node_id=0, .audit_id=0,  .rollback_confirmed=true, .cleanup_pending=false}, VIREO_OK, VIREO_RESULT_DATABASE, VIREO_DIRECTORY_MKDIR_NONE},
    {"IDEMPOTENCY_CONFLICT-mutation-node", VIREO_RESULT_DATABASE, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE, .issue=VIREO_MYSQL_NODE_IDEMPOTENCY_CONFLICT, .node_id=1, .audit_id=0,  .rollback_confirmed=true, .cleanup_pending=false}, VIREO_OK, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE},
    {"IDEMPOTENCY_CONFLICT-mutation-audit", VIREO_RESULT_DATABASE, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE, .issue=VIREO_MYSQL_NODE_IDEMPOTENCY_CONFLICT, .node_id=0, .audit_id=1,  .rollback_confirmed=true, .cleanup_pending=false}, VIREO_OK, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE},
    {"IDEMPOTENCY_CONFLICT-mutation-key", VIREO_RESULT_DATABASE, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE, .issue=VIREO_MYSQL_NODE_IDEMPOTENCY_CONFLICT, .node_id=0, .audit_id=0, .idempotency_key={1}, .rollback_confirmed=true, .cleanup_pending=false}, VIREO_OK, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE},
    {"IDEMPOTENCY_CONFLICT-mutation-commit", VIREO_RESULT_DATABASE, {.commit=VIREO_MYSQL_NODE_MKDIR_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE, .issue=VIREO_MYSQL_NODE_IDEMPOTENCY_CONFLICT, .node_id=0, .audit_id=0,  .rollback_confirmed=true, .cleanup_pending=false}, VIREO_OK, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE},
    {"IDEMPOTENCY_CONFLICT-mutation-effect", VIREO_RESULT_DATABASE, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_CREATED, .issue=VIREO_MYSQL_NODE_IDEMPOTENCY_CONFLICT, .node_id=0, .audit_id=0,  .rollback_confirmed=true, .cleanup_pending=false}, VIREO_OK, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE},
    {"IDEMPOTENCY_CONFLICT-mutation-rollback", VIREO_RESULT_DATABASE, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE, .issue=VIREO_MYSQL_NODE_IDEMPOTENCY_CONFLICT, .node_id=0, .audit_id=0,  .rollback_confirmed=false, .cleanup_pending=false}, VIREO_OK, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE},
    {"IDEMPOTENCY_CONFLICT-mutation-issue", VIREO_RESULT_DATABASE, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE, .issue=VIREO_MYSQL_NODE_ISSUE_NONE, .node_id=0, .audit_id=0,  .rollback_confirmed=true, .cleanup_pending=false}, VIREO_OK, VIREO_RESULT_DATABASE, VIREO_DIRECTORY_MKDIR_NONE},
    {"unknown-commit-not-failure-proof", VIREO_RESULT_DATABASE, {.commit=VIREO_MYSQL_NODE_MKDIR_UNKNOWN, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE, .issue=VIREO_MYSQL_NODE_ISSUE_NONE, .node_id=0, .audit_id=0,  .rollback_confirmed=false, .cleanup_pending=false}, VIREO_OK, VIREO_RESULT_DATABASE, VIREO_DIRECTORY_MKDIR_NONE},
    {"unknown-pending-not-replayed", VIREO_RESULT_DATABASE, {.commit=VIREO_MYSQL_NODE_MKDIR_UNKNOWN, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE, .issue=VIREO_MYSQL_NODE_ISSUE_NONE, .node_id=0, .audit_id=0,  .rollback_confirmed=false, .cleanup_pending=true}, VIREO_OK, VIREO_RESULT_DATABASE, VIREO_DIRECTORY_MKDIR_NONE},
    {"invalid-receipt-not-conflict", VIREO_RESULT_DATABASE, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE, .issue=VIREO_MYSQL_NODE_RECEIPT_INVALID, .node_id=0, .audit_id=0,  .rollback_confirmed=true, .cleanup_pending=false}, VIREO_OK, VIREO_RESULT_DATABASE, VIREO_DIRECTORY_MKDIR_NONE},
    {"native-1062-not-domain-conflict", VIREO_RESULT_DATABASE, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE, .issue=VIREO_MYSQL_NODE_ISSUE_NONE, .node_id=0, .audit_id=0,  .rollback_confirmed=true, .cleanup_pending=false}, VIREO_OK, VIREO_RESULT_DATABASE, VIREO_DIRECTORY_MKDIR_NONE},
    {"repo-PROTOCOL-after-local-name", VIREO_RESULT_PROTOCOL, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE, .issue=VIREO_MYSQL_NODE_ISSUE_NONE, .node_id=0, .audit_id=0,  .rollback_confirmed=true, .cleanup_pending=false}, VIREO_OK, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE},
    {"technical-INVALID_ARGUMENT", VIREO_RESULT_INVALID_ARGUMENT, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE, .issue=VIREO_MYSQL_NODE_ISSUE_NONE, .node_id=0, .audit_id=0,  .rollback_confirmed=true, .cleanup_pending=false}, VIREO_OK, VIREO_RESULT_INVALID_ARGUMENT, VIREO_DIRECTORY_MKDIR_NONE},
    {"technical-RANGE", VIREO_RESULT_RANGE, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE, .issue=VIREO_MYSQL_NODE_ISSUE_NONE, .node_id=0, .audit_id=0,  .rollback_confirmed=true, .cleanup_pending=false}, VIREO_OK, VIREO_RESULT_RANGE, VIREO_DIRECTORY_MKDIR_NONE},
    {"technical-BUSY", VIREO_RESULT_BUSY, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE, .issue=VIREO_MYSQL_NODE_ISSUE_NONE, .node_id=0, .audit_id=0,  .rollback_confirmed=true, .cleanup_pending=false}, VIREO_OK, VIREO_RESULT_BUSY, VIREO_DIRECTORY_MKDIR_NONE},
    {"technical-TIMEOUT", VIREO_RESULT_TIMEOUT, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE, .issue=VIREO_MYSQL_NODE_ISSUE_NONE, .node_id=0, .audit_id=0,  .rollback_confirmed=true, .cleanup_pending=false}, VIREO_OK, VIREO_RESULT_TIMEOUT, VIREO_DIRECTORY_MKDIR_NONE},
    {"technical-CANCELLED", VIREO_RESULT_CANCELLED, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE, .issue=VIREO_MYSQL_NODE_ISSUE_NONE, .node_id=0, .audit_id=0,  .rollback_confirmed=true, .cleanup_pending=false}, VIREO_OK, VIREO_RESULT_CANCELLED, VIREO_DIRECTORY_MKDIR_NONE},
    {"technical-IO", VIREO_RESULT_IO, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE, .issue=VIREO_MYSQL_NODE_ISSUE_NONE, .node_id=0, .audit_id=0,  .rollback_confirmed=true, .cleanup_pending=false}, VIREO_OK, VIREO_RESULT_IO, VIREO_DIRECTORY_MKDIR_NONE},
    {"technical-OVERFLOW", VIREO_RESULT_OVERFLOW, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE, .issue=VIREO_MYSQL_NODE_ISSUE_NONE, .node_id=0, .audit_id=0,  .rollback_confirmed=true, .cleanup_pending=false}, VIREO_OK, VIREO_RESULT_OVERFLOW, VIREO_DIRECTORY_MKDIR_NONE},
    {"technical-NO_MEMORY", VIREO_RESULT_NO_MEMORY, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE, .issue=VIREO_MYSQL_NODE_ISSUE_NONE, .node_id=0, .audit_id=0,  .rollback_confirmed=true, .cleanup_pending=false}, VIREO_OK, VIREO_RESULT_NO_MEMORY, VIREO_DIRECTORY_MKDIR_NONE},
    {"technical-INTERNAL", VIREO_RESULT_INTERNAL, {.commit=VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED, .effect=VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE, .issue=VIREO_MYSQL_NODE_ISSUE_NONE, .node_id=0, .audit_id=0,  .rollback_confirmed=true, .cleanup_pending=false}, VIREO_OK, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE},
};
static const struct relation {
    vireo_result_t rc;
    vireo_directory_name_issue_t issue;
    vireo_result_t want;
    vireo_directory_mkdir_outcome_t outcome;
    bool call;
} relations[] = {
    {VIREO_OK, VIREO_DIRECTORY_NAME_ISSUE_NONE, VIREO_OK, VIREO_DIRECTORY_MKDIR_CREATED, true},
    {VIREO_OK, VIREO_DIRECTORY_NAME_ISSUE_LENGTH, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE, false},
    {VIREO_OK, VIREO_DIRECTORY_NAME_ISSUE_UTF8, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE, false},
    {VIREO_OK, VIREO_DIRECTORY_NAME_ISSUE_SYNTAX, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE, false},
    {VIREO_OK, VIREO_DIRECTORY_NAME_ISSUE_NOT_NFC, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE, false},
    {VIREO_RESULT_RANGE, VIREO_DIRECTORY_NAME_ISSUE_NONE, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE, false},
    {VIREO_RESULT_RANGE, VIREO_DIRECTORY_NAME_ISSUE_LENGTH, VIREO_RESULT_RANGE, VIREO_DIRECTORY_MKDIR_INVALID_NAME, false},
    {VIREO_RESULT_RANGE, VIREO_DIRECTORY_NAME_ISSUE_UTF8, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE, false},
    {VIREO_RESULT_RANGE, VIREO_DIRECTORY_NAME_ISSUE_SYNTAX, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE, false},
    {VIREO_RESULT_RANGE, VIREO_DIRECTORY_NAME_ISSUE_NOT_NFC, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE, false},
    {VIREO_RESULT_PROTOCOL, VIREO_DIRECTORY_NAME_ISSUE_NONE, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE, false},
    {VIREO_RESULT_PROTOCOL, VIREO_DIRECTORY_NAME_ISSUE_LENGTH, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE, false},
    {VIREO_RESULT_PROTOCOL, VIREO_DIRECTORY_NAME_ISSUE_UTF8, VIREO_RESULT_PROTOCOL, VIREO_DIRECTORY_MKDIR_INVALID_NAME, false},
    {VIREO_RESULT_PROTOCOL, VIREO_DIRECTORY_NAME_ISSUE_SYNTAX, VIREO_RESULT_PROTOCOL, VIREO_DIRECTORY_MKDIR_INVALID_NAME, false},
    {VIREO_RESULT_PROTOCOL, VIREO_DIRECTORY_NAME_ISSUE_NOT_NFC, VIREO_RESULT_PROTOCOL, VIREO_DIRECTORY_MKDIR_INVALID_NAME, false},
    {VIREO_RESULT_NO_MEMORY, VIREO_DIRECTORY_NAME_ISSUE_NONE, VIREO_RESULT_NO_MEMORY, VIREO_DIRECTORY_MKDIR_NONE, false},
    {VIREO_RESULT_NO_MEMORY, VIREO_DIRECTORY_NAME_ISSUE_LENGTH, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE, false},
    {VIREO_RESULT_NO_MEMORY, VIREO_DIRECTORY_NAME_ISSUE_UTF8, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE, false},
    {VIREO_RESULT_NO_MEMORY, VIREO_DIRECTORY_NAME_ISSUE_SYNTAX, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE, false},
    {VIREO_RESULT_NO_MEMORY, VIREO_DIRECTORY_NAME_ISSUE_NOT_NFC, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE, false},
    {VIREO_RESULT_OVERFLOW, VIREO_DIRECTORY_NAME_ISSUE_NONE, VIREO_RESULT_OVERFLOW, VIREO_DIRECTORY_MKDIR_NONE, false},
    {VIREO_RESULT_OVERFLOW, VIREO_DIRECTORY_NAME_ISSUE_LENGTH, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE, false},
    {VIREO_RESULT_OVERFLOW, VIREO_DIRECTORY_NAME_ISSUE_UTF8, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE, false},
    {VIREO_RESULT_OVERFLOW, VIREO_DIRECTORY_NAME_ISSUE_SYNTAX, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE, false},
    {VIREO_RESULT_OVERFLOW, VIREO_DIRECTORY_NAME_ISSUE_NOT_NFC, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE, false},
    {VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_NAME_ISSUE_NONE, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE, false},
    {VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_NAME_ISSUE_LENGTH, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE, false},
    {VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_NAME_ISSUE_UTF8, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE, false},
    {VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_NAME_ISSUE_SYNTAX, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE, false},
    {VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_NAME_ISSUE_NOT_NFC, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_MKDIR_NONE, false},
};
struct context {
    const struct scenario *scenario;
    vireo_result_t name_rc;
    vireo_directory_name_issue_t name_issue;
    unsigned int names, repos;
    vireo_mysql_node_repository_t *repo;
    const vireo_mysql_node_actor_t *actor;
    const vireo_mysql_node_mkdir_once_input_t *input;
    uint32_t timeout;
};
static vireo_result_t name_callback(void *ctx, const unsigned char *name, size_t length,
    vireo_directory_name_issue_t *issue)
{
    struct context *c = ctx; ++c->names;
    assert(name == c->input->name && length == c->input->name_length);
    *issue = c->name_issue; errno = ERANGE; return c->name_rc;
}
static vireo_result_t repo_callback(void *ctx, vireo_mysql_node_repository_t *repo,
    const vireo_mysql_node_actor_t *actor, const vireo_mysql_node_mkdir_once_input_t *input,
    uint32_t timeout, vireo_mysql_node_mkdir_once_report_t *report, vireo_mysql_node_error_t *error)
{
    struct context *c = ctx; ++c->repos;
    assert(c->repos == 1 && repo == c->repo && actor == c->actor && input == c->input && timeout == c->timeout);
    assert(error != NULL); *report = c->scenario->report;
    error->cleanup_result = c->scenario->cleanup;
    error->database.mysql_code = 1062; /* 原生重复键也不自动变成领域冲突。 */
    error->system_errno = EIO; errno = EBUSY;
    return c->scenario->rc;
}
static bool zero(const void *p, size_t n)
{
    const unsigned char *b = p;
    for (size_t i = 0; i < n; ++i) { if (b[i] != 0) { return false; } }
    return true;
}
int main(void)
{
    unsigned char opaque = 0;
    vireo_mysql_node_repository_t *repo = (vireo_mysql_node_repository_t *)(void *)&opaque;
    vireo_mysql_node_actor_t actor = {1, 2};
    vireo_mysql_node_mkdir_once_input_t input = {.parent_id=3, .name=(const unsigned char *)"notes", .name_length=5,
        .idempotency_key={1}, .request_id={2}};
    const vireo_mysql_node_mkdir_once_input_t original = input;
    vireo_directory_mkdir_result_t out; vireo_mysql_node_error_t error;
    struct context c = {.scenario=&scenarios[0], .repo=repo, .actor=&actor, .input=&input, .timeout=60000};
    vireo_directory_mkdir_runtime_t rt = {&c, name_callback, repo_callback};
    for (size_t i = 0; i < sizeof(scenarios)/sizeof(scenarios[0]); ++i) {
        for (size_t diagnostics = 0; diagnostics < 2; ++diagnostics) {
            const struct scenario *s = &scenarios[i]; c.scenario=s; c.names=0; c.repos=0;
            memset(&out, 0xa5, sizeof(out)); memset(&error, 0xa5, sizeof(error)); errno = EDOM;
            vireo_result_t got = vireo_directory_service_mkdir_with_runtime(repo, &actor, &input, c.timeout,
                &out, diagnostics ? &error : NULL, &rt);
            if (got != s->want || out.outcome != s->outcome) {
                fprintf(stderr, "%s rc=%d outcome=%d expected=%d/%d\n", s->label, (int)got, (int)out.outcome,
                    (int)s->want, (int)s->outcome); abort();
            }
            assert(errno == EDOM && c.names == 1 && c.repos == 1 && out.repository_called);
            assert(out.repository_result == s->rc && memcmp(&out.repository, &s->report, sizeof(s->report)) == 0);
            assert(out.name_issue == VIREO_DIRECTORY_NAME_ISSUE_NONE);
            bool deliver = s->outcome == VIREO_DIRECTORY_MKDIR_CREATED || s->outcome == VIREO_DIRECTORY_MKDIR_RECOVERED;
            assert(out.node_id == (deliver ? s->report.node_id : 0));
            assert(deliver ? memcmp(out.idempotency_key, input.idempotency_key, 16) == 0 : zero(out.idempotency_key, 16));
            if (diagnostics) { assert(error.database.mysql_code == 1062 && error.system_errno == EIO && error.cleanup_result == s->cleanup); }
            assert(memcmp(&input, &original, sizeof(input)) == 0 && actor.user_id == 1 && actor.session_id == 2);
        }
    }
    c.scenario=&scenarios[0];
    for (size_t i = 0; i < sizeof(relations)/sizeof(relations[0]); ++i) {
        const struct relation *r=&relations[i]; c.name_rc=r->rc; c.name_issue=r->issue; c.names=0; c.repos=0;
        errno=EDOM;
        assert(vireo_directory_service_mkdir_with_runtime(repo, &actor, &input, c.timeout, &out, &error, &rt) == r->want);
        assert(errno == EDOM && out.outcome == r->outcome && c.names == 1 && c.repos == (r->call ? 1U : 0U));
        assert(out.repository_called == r->call);
        if (!r->call) { assert(zero(&out.repository, sizeof(out.repository)) && zero(&error, sizeof(error))); }
        assert(out.name_issue == (r->outcome == VIREO_DIRECTORY_MKDIR_INVALID_NAME ? r->issue : VIREO_DIRECTORY_NAME_ISSUE_NONE));
    }
    /* 必需指针缺失保持输出；结构非法则清输出且不调用任何依赖。 */
    c.name_rc=VIREO_OK; c.name_issue=VIREO_DIRECTORY_NAME_ISSUE_NONE; c.timeout=0;
    for (unsigned int bad = 0; bad < 9; ++bad) {
        c.names=0; c.repos=0; memset(&out, 0xa5, sizeof(out)); memset(&error, 0xa5, sizeof(error));
        vireo_directory_mkdir_result_t saved=out; vireo_mysql_node_error_t saved_error=error;
        vireo_directory_mkdir_runtime_t broken=rt;
        if (bad == 6) { broken.name_validate=NULL; }
        if (bad == 7) { broken.mkdir_once=NULL; }
        if (bad == 8) { input.name=NULL; }
        errno=EDOM;
        assert(vireo_directory_service_mkdir_with_runtime(bad == 0 ? NULL : repo, bad == 1 ? NULL : &actor,
            bad == 2 ? NULL : &input, 0, bad == 3 ? NULL : &out, &error, bad == 4 ? NULL : &broken) ==
            (bad == 5 ? VIREO_OK : VIREO_RESULT_INVALID_ARGUMENT));
        if (bad != 5) { assert(memcmp(&out, &saved, sizeof(out)) == 0 && memcmp(&error, &saved_error, sizeof(error)) == 0); }
        assert(errno == EDOM);
        input=original;
    }
    for (unsigned int bad = 0; bad < 6; ++bad) {
        c.names=0; c.repos=0; input=original; actor=(vireo_mysql_node_actor_t){1,2};
        if (bad == 0) { actor.user_id=0; }
        if (bad == 1) { actor.session_id=0; }
        if (bad == 2) { input.parent_id=0; }
        if (bad == 3) { memset(input.idempotency_key, 0, 16); }
        if (bad == 4) { memset(input.request_id, 0, 16); }
        assert(vireo_directory_service_mkdir_with_runtime(repo, &actor, &input, bad == 5 ? 60001 : 0, &out, &error, &rt) ==
            (bad == 5 ? VIREO_RESULT_RANGE : VIREO_RESULT_INVALID_ARGUMENT));
        assert(c.names == 0 && c.repos == 0 && zero(&out, sizeof(out)) && zero(&error, sizeof(error)));
    }
    puts("PASS 104 independent report cases x diagnostics present/NULL, 30 name relations, pointer/structure gates, raw preservation/at-most-once/errno");
    return 0;
}
