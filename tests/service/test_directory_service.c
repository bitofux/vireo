/* PROJECT : VIREO; FILE : test_directory_service.c; AUTHOR : bitofux;
 * DATE : 2026-10-22; BRIEF : 业务交付与清理故障边界、独立输出及一次调用约束。 */
#include "directory_service_internal.h"
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
    if (got_ != (want)) { fprintf(stderr, "line %d result %d want %d\n", __LINE__, (int)got_, (int)(want)); } \
    assert(got_ == (want) && errno == EDOM); ++checks; } while (0)

typedef struct scenario {
    vireo_result_t rc;
    vireo_mysql_node_report_t report;
    vireo_mysql_node_value_t node;
    vireo_mysql_node_error_t error;
    uint32_t timeout;
    size_t calls;
} scenario_t;

/* 故意在失败时也写候选节点并改errno，检验服务是否泄漏候选或隐式重试。 */
static vireo_result_t fake_stat(void *context, vireo_mysql_node_repository_t *repo,
    const vireo_mysql_node_actor_t *who, uint64_t id, uint32_t timeout,
    vireo_mysql_node_value_t *node, vireo_mysql_node_report_t *report, vireo_mysql_node_error_t *error)
{
    scenario_t *s = context;
    assert(repo == REPO && who == &actor && who->user_id == 7 && who->session_id == 51);
    assert(id == 42 && timeout == s->timeout && error != NULL);
    ++s->calls;
    *node = s->node; *report = s->report; *error = s->error;
    errno = EIO;
    return s->rc;
}

static void zeroed(const void *value, size_t size)
{
    const unsigned char *p = value;
    for (size_t i = 0; i < size; ++i) { assert(p[i] == 0); }
}

static scenario_t found(void)
{
    scenario_t s = {.rc = VIREO_OK, .report = {.found = true, .rollback_confirmed = true},
        .node = {.id = 42, .owner_id = 7, .kind = VIREO_MYSQL_NODE_DIRECTORY,
            .created_at_ms = 1000, .updated_at_ms = 2000}, .timeout = 17};
    return s;
}

/* 返回值、原始事实与输出同时核验；同一个result重复使用以发现旧成功值泄漏。 */
static void run(scenario_t *s, vireo_result_t want, vireo_directory_stat_outcome_t outcome, bool diagnostics)
{
    vireo_directory_service_runtime_t rt = {s, fake_stat};
    vireo_directory_stat_result_t out;
    vireo_mysql_node_error_t error;
    memset(&out, 0xa5, sizeof(out)); memset(&error, 0x5a, sizeof(error));
    size_t before = s->calls;
    CHECK(vireo_directory_service_stat_with_runtime(REPO, &actor, 42, s->timeout,
        &out, diagnostics ? &error : NULL, &rt), want);
    assert(s->calls == before + 1 && out.repository_called && out.repository_result == s->rc);
    assert(out.repository.found == s->report.found && out.repository.issue == s->report.issue &&
        out.repository.rollback_confirmed == s->report.rollback_confirmed &&
        out.repository.cleanup_pending == s->report.cleanup_pending && out.outcome == outcome);
    if (diagnostics) {
        assert(error.stage == s->error.stage && error.system_errno == s->error.system_errno &&
            error.database.mysql_code == s->error.database.mysql_code &&
            error.cleanup_result == s->error.cleanup_result && error.cleanup_stage == s->error.cleanup_stage &&
            error.cleanup_database.mysql_code == s->error.cleanup_database.mysql_code);
    }
    if (outcome == VIREO_DIRECTORY_STAT_FOUND) {
        assert(out.node.id == 42 && out.node.owner_id == 7 && out.node.parent_id == s->node.parent_id &&
            out.node.has_parent == s->node.has_parent && out.node.name_length == s->node.name_length &&
            out.node.kind == s->node.kind && out.node.has_object_hash == s->node.has_object_hash &&
            out.node.size == s->node.size && out.node.created_at_ms == 1000 && out.node.updated_at_ms == 2000);
        assert(!memcmp(out.node.name, s->node.name, sizeof(out.node.name)) &&
            !memcmp(out.node.object_hash, s->node.object_hash, sizeof(out.node.object_hash)));
        /* 原候选之后被改写，已发布值不随依赖内存变化。 */
        s->node.name[0] ^= 1;
        assert(out.node.name[0] != s->node.name[0]); s->node.name[0] ^= 1;
        s->rc = VIREO_RESULT_NOT_FOUND; s->report.found = false; s->report.issue = VIREO_MYSQL_NODE_NOT_FOUND;
        CHECK(vireo_directory_service_stat_with_runtime(REPO, &actor, 42, s->timeout, &out, NULL, &rt), VIREO_RESULT_NOT_FOUND);
        assert(out.outcome == VIREO_DIRECTORY_STAT_NOT_FOUND && s->calls == before + 2);
        zeroed(&out.node, sizeof(out.node));
    } else { zeroed(&out.node, sizeof(out.node)); }
}

static void validation(void)
{
    scenario_t s = found(); vireo_directory_service_runtime_t rt = {&s, fake_stat};
    vireo_directory_stat_result_t out, saved; vireo_mysql_node_error_t error, old_error;
    memset(&out, 0xa5, sizeof(out)); memcpy(&saved, &out, sizeof(out));
    memset(&error, 0x5a, sizeof(error)); memcpy(&old_error, &error, sizeof(error));
    CHECK(vireo_directory_service_stat(NULL, &actor, 42, 0, &out, &error), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_directory_service_stat(REPO, NULL, 42, 0, &out, &error), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_directory_service_stat(REPO, &actor, 42, 0, NULL, &error), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_directory_service_stat_with_runtime(REPO, &actor, 42, 0, &out, &error, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    vireo_directory_service_runtime_t empty = {0};
    CHECK(vireo_directory_service_stat_with_runtime(REPO, &actor, 42, 0, &out, &error, &empty), VIREO_RESULT_INVALID_ARGUMENT);
    assert(!memcmp(&out, &saved, sizeof(out)) && !memcmp(&error, &old_error, sizeof(error)));
    const vireo_mysql_node_actor_t invalid[] = {{0, 51}, {7, 0}};
    for (size_t i = 0; i < 2; ++i) {
        memset(&out, 0xa5, sizeof(out)); memset(&error, 0x5a, sizeof(error));
        CHECK(vireo_directory_service_stat_with_runtime(REPO, &invalid[i], 42, 0, &out, &error, &rt), VIREO_RESULT_INVALID_ARGUMENT);
        zeroed(&out, sizeof(out)); zeroed(&error, sizeof(error));
    }
    CHECK(vireo_directory_service_stat_with_runtime(REPO, &actor, 0, 0, &out, &error, &rt), VIREO_RESULT_INVALID_ARGUMENT);
    zeroed(&out, sizeof(out)); zeroed(&error, sizeof(error));
    CHECK(vireo_directory_service_stat_with_runtime(REPO, &actor, 42, 60001, &out, &error, &rt), VIREO_RESULT_RANGE);
    zeroed(&out, sizeof(out)); zeroed(&error, sizeof(error));
    assert(s.calls == 0 && actor.user_id == 7 && actor.session_id == 51);
}

int main(void)
{
    validation();
    scenario_t s = found(); s.timeout = 0; run(&s, VIREO_OK, VIREO_DIRECTORY_STAT_FOUND, true);
    s = found(); s.timeout = 60000; s.node.has_parent = true; s.node.parent_id = 9;
    s.node.name_length = sizeof(s.node.name); memset(s.node.name, 0x80, sizeof(s.node.name));
    run(&s, VIREO_OK, VIREO_DIRECTORY_STAT_FOUND, false);
    s = found(); s.node.has_parent = true; s.node.parent_id = 9; s.node.name[0] = 0xff; s.node.name_length = 1;
    s.node.kind = VIREO_MYSQL_NODE_FILE; s.node.has_object_hash = true; s.node.size = UINT64_MAX;
    for (size_t i = 0; i < sizeof(s.node.object_hash); ++i) { s.node.object_hash[i] = (unsigned char)(i * 7); }
    run(&s, VIREO_OK, VIREO_DIRECTORY_STAT_FOUND, true);

    for (unsigned i = 0; i < 2; ++i) {
        s = found(); s.rc = VIREO_RESULT_NOT_FOUND; s.report.found = false;
        s.report.issue = i == 0 ? VIREO_MYSQL_NODE_AUTH_REJECTED : VIREO_MYSQL_NODE_NOT_FOUND;
        run(&s, VIREO_RESULT_NOT_FOUND, i == 0 ? VIREO_DIRECTORY_STAT_UNAUTHORIZED : VIREO_DIRECTORY_STAT_NOT_FOUND, true);
        const vireo_result_t cleanup[] = {VIREO_RESULT_DATABASE, VIREO_RESULT_BUSY, VIREO_RESULT_NOT_FOUND};
        for (size_t j = 0; j < sizeof(cleanup)/sizeof(cleanup[0]); ++j) {
            s.error = (vireo_mysql_node_error_t){.stage = VIREO_MYSQL_NODE_STAGE_SESSION,
                .database = {.mysql_code = 7}, .cleanup_result = cleanup[j],
                .cleanup_stage = VIREO_MYSQL_NODE_STAGE_RELEASE, .cleanup_database = {.mysql_code = 2013}};
            vireo_result_t want = cleanup[j] == VIREO_RESULT_NOT_FOUND ? VIREO_RESULT_INTERNAL : cleanup[j];
            run(&s, want, VIREO_DIRECTORY_STAT_NONE, true);
            run(&s, want, VIREO_DIRECTORY_STAT_NONE, false);
        }
    }
    s = found(); s.error.cleanup_result = VIREO_RESULT_IO; run(&s, VIREO_RESULT_IO, VIREO_DIRECTORY_STAT_NONE, false);
    /* 可交付路径的每个关联或报告矛盾均须关闭交付。 */
    for (unsigned i = 0; i < 6; ++i) {
        s = found();
        switch (i) {
        case 0: s.report.found = false; break;
        case 1: s.report.issue = VIREO_MYSQL_NODE_NOT_FOUND; break;
        case 2: s.report.rollback_confirmed = false; break;
        case 3: s.report.cleanup_pending = true; break;
        case 4: ++s.node.id; break;
        default: ++s.node.owner_id; break;
        }
        run(&s, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_STAT_NONE, true);
    }
    for (unsigned i = 0; i < 4; ++i) {
        s = found(); s.rc = VIREO_RESULT_NOT_FOUND; s.report.found = false; s.report.issue = VIREO_MYSQL_NODE_AUTH_REJECTED;
        switch (i) {
        case 0: s.report.found = true; break;
        case 1: s.report.rollback_confirmed = false; break;
        case 2: s.report.issue = VIREO_MYSQL_NODE_ISSUE_NONE; break;
        default: s.report.cleanup_pending = true; break;
        }
        run(&s, VIREO_RESULT_INTERNAL, VIREO_DIRECTORY_STAT_NONE, false);
    }
    const vireo_result_t failures[] = {VIREO_RESULT_DATABASE, VIREO_RESULT_BUSY, VIREO_RESULT_TIMEOUT,
        VIREO_RESULT_CANCELLED, VIREO_RESULT_NO_MEMORY, VIREO_RESULT_IO, VIREO_RESULT_OVERFLOW,
        VIREO_RESULT_INTERNAL, VIREO_RESULT_RANGE, VIREO_RESULT_INVALID_ARGUMENT};
    for (size_t i = 0; i < sizeof(failures)/sizeof(failures[0]); ++i) {
        s = found(); s.rc = failures[i];
        run(&s, failures[i], VIREO_DIRECTORY_STAT_NONE, true);
        s.report.cleanup_pending = true; run(&s, failures[i], VIREO_DIRECTORY_STAT_NONE, false);
        s.error.cleanup_result = VIREO_RESULT_DATABASE;
        run(&s, VIREO_RESULT_DATABASE, VIREO_DIRECTORY_STAT_NONE, true);
    }
    printf("PASS %zu STAT boundary calls; cleanup priority, NULL diagnostics, raw facts, no retry, independent values, errno\n", checks);
    return 0;
}
