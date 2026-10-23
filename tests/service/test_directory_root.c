/* PROJECT : VIREO; FILE : test_directory_root.c; AUTHOR : bitofux;
 * DATE : 2026-10-22; BRIEF : 根交付安全、清理优先、原始事实与调用责任。 */
#include "directory_root_internal.h"
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

static max_align_t marker;
#define REPO ((vireo_mysql_node_repository_t *)(void *)&marker)
static const vireo_mysql_node_actor_t actor = {7, 51};
static size_t checks;
#define CHECK(call, want) do { errno = EDOM; vireo_result_t got_ = (call); \
    if (got_ != (want)) { fprintf(stderr, "line %d got %d want %d\n", __LINE__, (int)got_, (int)(want)); } \
    assert(got_ == (want) && errno == EDOM); ++checks; } while (0)

typedef struct scenario {
    vireo_result_t rc;
    vireo_mysql_node_value_t node;
    vireo_mysql_node_report_t report;
    vireo_mysql_node_error_t error;
    uint32_t timeout;
    size_t calls;
} scenario_t;

/* 即便失败也提供candidate并改errno，检测过早发布与未保存入口errno。 */
static vireo_result_t query(void *context, vireo_mysql_node_repository_t *repo,
    const vireo_mysql_node_actor_t *who, uint32_t timeout, vireo_mysql_node_value_t *node,
    vireo_mysql_node_report_t *report, vireo_mysql_node_error_t *error)
{
    scenario_t *s = context;
    assert(repo == REPO && who == &actor && who->user_id == 7 && who->session_id == 51);
    assert(timeout == s->timeout && node != NULL && report != NULL && error != NULL);
    *node = s->node; *report = s->report; *error = s->error;
    ++s->calls; errno = EIO; return s->rc;
}

static scenario_t valid(void)
{
    scenario_t s = {.rc = VIREO_OK, .node = {.id = UINT64_MAX, .owner_id = 7,
        .kind = VIREO_MYSQL_NODE_DIRECTORY}, .report = {.found = true, .rollback_confirmed = true},
        .timeout = 17};
    return s;
}

static void zeroed(const void *value, size_t size)
{
    const unsigned char *p = value;
    for (size_t i = 0; i < size; ++i) { assert(p[i] == 0); }
}

static void same_database(vireo_mysql_error_t a, vireo_mysql_error_t b)
{
    assert(a.stage == b.stage && a.system_error == b.system_error && a.mysql_code == b.mysql_code &&
        !memcmp(a.sqlstate, b.sqlstate, sizeof(a.sqlstate)));
}

static void same_pool(vireo_mysql_pool_error_t a, vireo_mysql_pool_error_t b)
{
    assert(a.stage == b.stage && a.pthread_code == b.pthread_code && a.system_error == b.system_error);
    same_database(a.database, b.database);
}

static void run(scenario_t *s, vireo_result_t want, vireo_directory_root_outcome_t outcome)
{
    vireo_directory_root_runtime_t rt = {s, query};
    /* 同一报告先有成功旧值，再失败覆盖；可选诊断两条路径应完全等价。 */
    vireo_directory_root_result_t out = {.outcome = VIREO_DIRECTORY_ROOT_FOUND, .root_node_id = 888};
    for (unsigned diagnostics = 0; diagnostics < 2; ++diagnostics) {
        vireo_mysql_node_error_t error; memset(&error, 0x5a, sizeof(error));
        size_t before = s->calls;
        CHECK(vireo_directory_service_root_with_runtime(REPO, &actor, s->timeout, &out,
            diagnostics != 0 ? &error : NULL, &rt), want);
        assert(s->calls == before + 1 && out.repository_called && out.repository_result == s->rc);
        assert(out.repository.found == s->report.found && out.repository.issue == s->report.issue &&
            out.repository.rollback_confirmed == s->report.rollback_confirmed &&
            out.repository.cleanup_pending == s->report.cleanup_pending && out.outcome == outcome);
        assert(out.root_node_id == (outcome == VIREO_DIRECTORY_ROOT_FOUND ? s->node.id : 0));
        if (diagnostics != 0) {
            assert(error.stage == s->error.stage && error.system_errno == s->error.system_errno &&
                error.cleanup_result == s->error.cleanup_result && error.cleanup_stage == s->error.cleanup_stage);
            same_database(error.database, s->error.database); same_pool(error.pool, s->error.pool);
            same_database(error.cleanup_database, s->error.cleanup_database);
            same_pool(error.cleanup_pool, s->error.cleanup_pool);
        }
        uint64_t saved = out.root_node_id; s->node.id ^= 1;
        assert(out.root_node_id == saved); s->node.id ^= 1;
    }
}

static void validation(void)
{
    scenario_t s = valid(); vireo_directory_root_runtime_t rt = {&s, query}, empty = {0};
    vireo_directory_root_result_t out, saved; vireo_mysql_node_error_t error, old_error;
    memset(&out, 0xa5, sizeof(out)); memcpy(&saved, &out, sizeof(out));
    memset(&error, 0x5a, sizeof(error)); memcpy(&old_error, &error, sizeof(error));
    CHECK(vireo_directory_service_root(NULL, &actor, 0, &out, &error), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_directory_service_root(REPO, NULL, 0, &out, &error), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_directory_service_root(REPO, &actor, 0, NULL, &error), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_directory_service_root_with_runtime(REPO, &actor, 0, &out, &error, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_directory_service_root_with_runtime(REPO, &actor, 0, &out, &error, &empty), VIREO_RESULT_INVALID_ARGUMENT);
    assert(!memcmp(&out, &saved, sizeof(out)) && !memcmp(&error, &old_error, sizeof(error)));
    const vireo_mysql_node_actor_t invalid[] = {{0, 51}, {7, 0}, {0, 0}};
    for (size_t i = 0; i < sizeof(invalid)/sizeof(invalid[0]); ++i) {
        memset(&out, 0xa5, sizeof(out)); memset(&error, 0x5a, sizeof(error));
        CHECK(vireo_directory_service_root_with_runtime(REPO, &invalid[i], 0, &out, &error, &rt), VIREO_RESULT_INVALID_ARGUMENT);
        zeroed(&out, sizeof(out)); zeroed(&error, sizeof(error));
    }
    const uint32_t budgets[] = {60001, UINT32_MAX};
    for (size_t i = 0; i < sizeof(budgets)/sizeof(budgets[0]); ++i) {
        memset(&out, 0xa5, sizeof(out)); memset(&error, 0x5a, sizeof(error));
        CHECK(vireo_directory_service_root_with_runtime(REPO, &actor, budgets[i], &out, &error, &rt), VIREO_RESULT_RANGE);
        zeroed(&out, sizeof(out)); zeroed(&error, sizeof(error));
    }
    assert(s.calls == 0 && actor.user_id == 7 && actor.session_id == 51);
}

int main(void)
{
    validation(); scenario_t s = valid();
    s.timeout = 0; s.node.id = 1; run(&s, VIREO_OK, VIREO_DIRECTORY_ROOT_FOUND);
    s = valid(); s.timeout = 60000; run(&s, VIREO_OK, VIREO_DIRECTORY_ROOT_FOUND);
    /* 未用数组不属于本层门禁，042负责实际行解析；不重复扫描尾字节。 */
    memset(s.node.name, 0xa5, sizeof(s.node.name)); memset(s.node.object_hash, 0xa5, sizeof(s.node.object_hash));
    run(&s, VIREO_OK, VIREO_DIRECTORY_ROOT_FOUND);
    for (unsigned bad = 0; bad < 11; ++bad) {
        s = valid();
        switch (bad) {
        case 0: s.node.id = 0; break;
        case 1: s.node.owner_id = 8; break;
        case 2: s.node.has_parent = true; break;
        case 3: s.node.parent_id = 1; break;
        case 4: s.node.name_length = 1; break;
        case 5: s.node.kind = VIREO_MYSQL_NODE_FILE; break;
        case 6: s.node.size = 1; break;
        case 7: s.node.has_object_hash = true; break;
        case 8: s.report.found = false; break;
        case 9: s.report.issue = VIREO_MYSQL_NODE_ROOT_INVARIANT; break;
        default: s.report.rollback_confirmed = false; break;
        }
        run(&s, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_ROOT_NONE);
    }
    s = valid(); s.rc = VIREO_RESULT_NOT_FOUND; s.report.found = false;
    s.report.issue = VIREO_MYSQL_NODE_AUTH_REJECTED;
    run(&s, VIREO_RESULT_NOT_FOUND, VIREO_DIRECTORY_ROOT_UNAUTHORIZED);
    for (unsigned bad = 0; bad < 5; ++bad) {
        scenario_t rejected = s;
        switch (bad) {
        case 0: rejected.report.found = true; break;
        case 1: rejected.report.rollback_confirmed = false; break;
        case 2: rejected.report.issue = VIREO_MYSQL_NODE_ISSUE_NONE; break;
        case 3: rejected.report.issue = VIREO_MYSQL_NODE_NOT_FOUND; break;
        default: rejected.report.issue = VIREO_MYSQL_NODE_ROOT_INVARIANT; break;
        }
        run(&rejected, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_ROOT_NONE);
    }
    /* 所有稳定结果和未知扩展码：首清理/残留/业务事实交叉，原事实不得覆盖。 */
    const vireo_result_t codes[] = {VIREO_OK, VIREO_RESULT_NOT_FOUND, VIREO_RESULT_INVALID_ARGUMENT,
        VIREO_RESULT_RANGE, VIREO_RESULT_OVERFLOW, VIREO_RESULT_NO_MEMORY, VIREO_RESULT_BUSY,
        VIREO_RESULT_TIMEOUT, VIREO_RESULT_CANCELLED, VIREO_RESULT_IO, VIREO_RESULT_PROTOCOL,
        VIREO_RESULT_DATABASE, VIREO_RESULT_INTERNAL, (vireo_result_t)777};
    for (size_t i = 0; i < sizeof(codes)/sizeof(codes[0]); ++i) {
        for (size_t j = 0; j < sizeof(codes)/sizeof(codes[0]); ++j) {
            for (unsigned pending = 0; pending < 2; ++pending) {
                s = valid(); s.rc = codes[i]; s.error.cleanup_result = codes[j];
                s.report.cleanup_pending = pending != 0;
                if (s.rc == VIREO_RESULT_NOT_FOUND) {
                    s.report.found = false; s.report.issue = VIREO_MYSQL_NODE_AUTH_REJECTED;
                } else if (s.rc == VIREO_RESULT_DATABASE) { s.report.issue = VIREO_MYSQL_NODE_ROOT_INVARIANT; }
                s.error.stage = VIREO_MYSQL_NODE_STAGE_SESSION; s.error.system_errno = ERANGE;
                s.error.database = (vireo_mysql_error_t){.mysql_code = 7, .system_error = EIO, .sqlstate = "HY000"};
                s.error.pool = (vireo_mysql_pool_error_t){.pthread_code = 9, .system_error = EBUSY, .database = s.error.database};
                s.error.cleanup_stage = VIREO_MYSQL_NODE_STAGE_RELEASE;
                s.error.cleanup_database = (vireo_mysql_error_t){.mysql_code = 2013, .sqlstate = "HY001"};
                s.error.cleanup_pool = (vireo_mysql_pool_error_t){.pthread_code = 3, .system_error = EIO,
                    .database = s.error.cleanup_database};
                vireo_result_t want = s.rc; vireo_directory_root_outcome_t outcome = VIREO_DIRECTORY_ROOT_NONE;
                if (codes[j] != VIREO_OK) { want = codes[j] == VIREO_RESULT_NOT_FOUND ? VIREO_RESULT_INTERNAL : codes[j]; }
                else if (pending != 0 && (s.rc == VIREO_OK || s.rc == VIREO_RESULT_NOT_FOUND)) { want = VIREO_RESULT_INTERNAL; }
                else if (pending == 0 && s.rc == VIREO_OK) { outcome = VIREO_DIRECTORY_ROOT_FOUND; }
                else if (pending == 0 && s.rc == VIREO_RESULT_NOT_FOUND) { outcome = VIREO_DIRECTORY_ROOT_UNAUTHORIZED; }
                run(&s, want, outcome);
            }
        }
    }
    printf("PASS %zu root boundary calls; shape, authorization, cleanup priority, raw facts, optional diagnostics, once, errno\n", checks);
    return 0;
}
