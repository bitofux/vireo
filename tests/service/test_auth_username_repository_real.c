/*
- PROJECT : VIREO
- FILE    : test_auth_username_repository_real.c
- AUTHOR  : bitofux
- DATE    : 2026-10-19
- BRIEF   : 此模块负责：
- -- 真实MySQL验证同一用户名产物的注册/查找、唯一冲突原子性与身份隔离
 */
#define _POSIX_C_SOURCE 200809L
#include <vireo/service/auth_username.h>
#include <vireo/persistence/mysql_user_repository.h>
#include <vireo/persistence/mysql_schema.h>
#include <vireo/persistence/mysql_statement.h>
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(call, expected) do { errno = EDOM; vireo_result_t got_ = (call); \
    if (got_ != (expected)) { fprintf(stderr, "line %d result %d wanted %d\n", \
        __LINE__, (int)got_, (int)(expected)); abort(); } assert(errno == EDOM); } while (0)

static vireo_mysql_thread_t *thread;
static vireo_mysql_connection_t *observer;
static vireo_mysql_user_repository_t *repo;
static const vireo_password_policy_t policy = VIREO_PASSWORD_POLICY_DEFAULT;
static unsigned char serial;
static size_t cases;

/* 可信固定SELECT，使用公共资源API；借用结果仅到下一fetch/destroy。 */
static vireo_mysql_statement_t *query(const char *sql)
{
    const vireo_mysql_statement_limits_t limits = {0, 16, 0, 2048, 131072};
    vireo_mysql_statement_t *s = NULL;
    vireo_mysql_execution_t execution;
    CHECK(vireo_mysql_statement_prepare(thread, observer, sql, strlen(sql), &limits, &s, NULL), VIREO_OK);
    CHECK(vireo_mysql_statement_execute(thread, s, NULL, 0, &execution, NULL), VIREO_OK);
    assert(execution.has_result);
    return s;
}

/* 捕获三表所有行/列及NULL、长度边界；只在内存比较，绝不输出认证数据。 */
static size_t snapshot(unsigned char out[32768])
{
    const char *sql[] = {"SELECT * FROM users ORDER BY id", "SELECT * FROM file_nodes ORDER BY id",
        "SELECT * FROM operation_audits ORDER BY id"};
    size_t used = 0;
    for (size_t t = 0; t < 3; ++t) {
        vireo_mysql_statement_t *s = query(sql[t]);
        vireo_mysql_statement_info_t info;
        CHECK(vireo_mysql_statement_inspect(thread, s, &info), VIREO_OK);
        for (;;) {
            vireo_mysql_fetch_outcome_t outcome;
            CHECK(vireo_mysql_statement_fetch(thread, s, &outcome, NULL), VIREO_OK);
            if (outcome == VIREO_MYSQL_FETCH_DONE) { break; }
            for (size_t col = 0; col < info.column_count; ++col) {
                vireo_mysql_cell_view_t cell;
                CHECK(vireo_mysql_statement_column(thread, s, col, &cell), VIREO_OK);
                assert(used + 1 + sizeof(cell.length) + cell.length < 32768);
                out[used++] = cell.is_null ? 1 : 0;
                memcpy(out + used, &cell.length, sizeof(cell.length)); used += sizeof(cell.length);
                if (cell.length != 0) { memcpy(out + used, cell.data, cell.length); used += cell.length; }
            }
            out[used++] = 0xfe;
        }
        out[used++] = 0xff;
        CHECK(vireo_mysql_statement_destroy(thread, &s, NULL), VIREO_OK);
    }
    return used;
}

static vireo_mysql_registration_report_t registration(
    const vireo_auth_username_t *name, const char *phc, size_t length, vireo_result_t expected)
{
    vireo_mysql_registration_input_t input = {.username = name->username, .username_length = name->length,
        .username_key = name->key, .username_key_length = name->length,
        .password_hash = phc, .password_hash_length = length, .occurred_at_ms = 1000};
    assert(serial < 250); input.request_id[15] = ++serial;
    vireo_mysql_registration_report_t report;
    CHECK(vireo_mysql_user_repository_register(repo, &input, 0, &report, NULL), expected);
    assert(!report.cleanup_pending);
    if (expected == VIREO_OK) {
        assert(report.commit == VIREO_MYSQL_REGISTRATION_COMMITTED && report.user_id &&
            report.root_node_id && report.audit_id);
    } else {
        assert(report.commit == VIREO_MYSQL_REGISTRATION_NOT_COMMITTED && report.rollback_confirmed &&
            report.conflict == VIREO_MYSQL_REGISTRATION_USERNAME_CONFLICT &&
            !report.user_id && !report.root_node_id && !report.audit_id);
    }
    ++cases;
    return report;
}

/* 查询后先确认租约已释放，再验证实际密码，保持040的事务外KDF边界。 */
static void lookup(const char *raw, size_t length, uint64_t id, vireo_mysql_pool_t *pool,
    const void *password, size_t password_length)
{
    vireo_auth_username_t name;
    CHECK(vireo_auth_username_prepare(raw, length, &name), VIREO_OK);
    vireo_mysql_user_credentials_t credentials;
    vireo_mysql_credentials_report_t report;
    CHECK(vireo_mysql_user_repository_find_credentials(repo, name.key, name.length, 0,
        &credentials, &report, NULL), VIREO_OK);
    assert(report.found && !report.cleanup_pending && credentials.user_id == id &&
        credentials.status == VIREO_MYSQL_USER_STATUS_ACTIVE);
    vireo_mysql_pool_info_t info;
    CHECK(vireo_mysql_pool_inspect(pool, &info), VIREO_OK); assert(info.leased == 0);
    bool matches = false;
    CHECK(vireo_password_hash_verify(&policy, password, password_length,
        credentials.password_hash, credentials.password_hash_length, &matches), VIREO_OK);
    assert(matches);
    CHECK(vireo_password_hash_verify(&policy, "wrong", 5,
        credentials.password_hash, credentials.password_hash_length, &matches), VIREO_OK);
    assert(!matches);
    CHECK(vireo_mysql_user_credentials_clear(&credentials), VIREO_OK);
    ++cases;
}

static size_t fd_count(void)
{
    DIR *d = opendir("/proc/self/fd"); assert(d != NULL);
    size_t count = 0; while (readdir(d) != NULL) { ++count; }
    assert(closedir(d) == 0); return count;
}

int main(int argc, char **argv)
{
    assert(argc == 5);
    char db_password[1026];
    FILE *f = fopen(argv[3], "r");
    assert(f != NULL && fgets(db_password, (int)sizeof(db_password), f) != NULL && fclose(f) == 0);
    db_password[strcspn(db_password, "\n")] = 0;
    struct sigaction action = {0}; action.sa_handler = SIG_IGN;
    assert(sigemptyset(&action.sa_mask) == 0 && sigaction(SIGPIPE, &action, NULL) == 0);
    size_t fd = fd_count();
    vireo_mysql_runtime_t *runtime = NULL;
    CHECK(vireo_mysql_runtime_create(&runtime, NULL), VIREO_OK);
    CHECK(vireo_mysql_thread_attach(runtime, &thread, NULL), VIREO_OK);
    vireo_mysql_connection_options_t options = {argv[1], argv[2], db_password, argv[4], 3, 3, 3};
    const vireo_mysql_migration_t *catalog = NULL; size_t count = 0;
    CHECK(vireo_mysql_schema_catalog(&catalog, &count), VIREO_OK);
    vireo_mysql_migration_report_t migration;
    CHECK(vireo_mysql_migration_apply(thread, &options, catalog, count, &migration, NULL), VIREO_OK);
    assert(migration.ready && migration.steps_completed == 14);
    CHECK(vireo_mysql_connection_open(thread, &options, &observer, NULL), VIREO_OK);
    vireo_mysql_pool_options_t pool_options = {options, 1, 1, VIREO_MYSQL_POOL_MEMORY_MAX};
    vireo_mysql_pool_t *pool = NULL;
    CHECK(vireo_mysql_pool_create(thread, &pool_options, &pool, NULL), VIREO_OK);
    CHECK(vireo_mysql_user_repository_create(thread, pool, &policy, &repo, NULL), VIREO_OK);

    const unsigned char raw_password[] = {'S', 'e', 'c', 0, 'R', 'e', 't'};
    char phc[VIREO_PASSWORD_ENCODED_CAPACITY]; size_t phc_length = 0;
    CHECK(vireo_password_hash_create(&policy, raw_password, sizeof(raw_password), phc, sizeof(phc), &phc_length), VIREO_OK);
    vireo_auth_username_t alice, duplicate, other;
    CHECK(vireo_auth_username_prepare("Alice_7", 7, &alice), VIREO_OK);
    uint64_t alice_id = registration(&alice, phc, phc_length, VIREO_OK).user_id;
    lookup("ALICE_7", 7, alice_id, pool, raw_password, sizeof(raw_password));
    lookup("alice_7", 7, alice_id, pool, raw_password, sizeof(raw_password));

    vireo_mysql_statement_t *s = query("SELECT username,username_key FROM users ORDER BY id");
    vireo_mysql_fetch_outcome_t outcome;
    CHECK(vireo_mysql_statement_fetch(thread, s, &outcome, NULL), VIREO_OK); assert(outcome == VIREO_MYSQL_FETCH_ROW);
    for (size_t col = 0; col < 2; ++col) {
        vireo_mysql_cell_view_t cell; CHECK(vireo_mysql_statement_column(thread, s, col, &cell), VIREO_OK);
        assert(!cell.is_null && cell.length == 7 && !memcmp(cell.data, col == 0 ? "Alice_7" : "alice_7", 7));
    }
    CHECK(vireo_mysql_statement_fetch(thread, s, &outcome, NULL), VIREO_OK); assert(outcome == VIREO_MYSQL_FETCH_DONE);
    CHECK(vireo_mysql_statement_destroy(thread, &s, NULL), VIREO_OK); ++cases;

    unsigned char before[32768], after[32768]; size_t n = snapshot(before);
    CHECK(vireo_auth_username_prepare("ALIce_7", 7, &duplicate), VIREO_OK);
    (void)registration(&duplicate, phc, phc_length, VIREO_RESULT_DATABASE);
    assert(snapshot(after) == n && !memcmp(before, after, n)); ++cases;
    CHECK(vireo_auth_username_prepare(" Alice_7", 8, &duplicate), VIREO_RESULT_PROTOCOL);
    assert(snapshot(after) == n && !memcmp(before, after, n)); ++cases;

    /* 不同账号使用不同密码，防止错误查找仍通过“相同PHC”的弱测试。 */
    CHECK(vireo_password_hash_create(&policy, "Different", 9, phc, sizeof(phc), &phc_length), VIREO_OK);
    CHECK(vireo_auth_username_prepare("Bob_007", 7, &other), VIREO_OK);
    uint64_t other_id = registration(&other, phc, phc_length, VIREO_OK).user_id;
    assert(other_id != alice_id);
    lookup("BOB_007", 7, other_id, pool, "Different", 9);
    lookup("Alice_7", 7, alice_id, pool, raw_password, sizeof(raw_password));
    vireo_mysql_user_credentials_t missing; vireo_mysql_credentials_report_t report;
    CHECK(vireo_auth_username_prepare("Nobody_7", 8, &other), VIREO_OK);
    CHECK(vireo_mysql_user_repository_find_credentials(repo, other.key, other.length, 0, &missing, &report, NULL), VIREO_RESULT_NOT_FOUND);
    assert(!report.found && !report.cleanup_pending); CHECK(vireo_mysql_user_credentials_clear(&missing), VIREO_OK); ++cases;

    char maximum[32]; memset(maximum, 'Z', sizeof(maximum));
    CHECK(vireo_auth_username_prepare(maximum, sizeof(maximum), &other), VIREO_OK);
    other_id = registration(&other, phc, phc_length, VIREO_OK).user_id;
    memset(maximum, 'z', sizeof(maximum)); lookup(maximum, sizeof(maximum), other_id, pool, "Different", 9);
    CHECK(vireo_auth_username_prepare("_A1", 3, &other), VIREO_OK);
    other_id = registration(&other, phc, phc_length, VIREO_OK).user_id;
    lookup("_a1", 3, other_id, pool, "Different", 9);

    CHECK(vireo_mysql_user_repository_destroy(&repo, NULL), VIREO_OK);
    bool closed = false; CHECK(vireo_mysql_pool_close(pool, &closed, NULL), VIREO_OK); assert(closed);
    CHECK(vireo_mysql_pool_destroy(thread, &pool, NULL), VIREO_OK);
    CHECK(vireo_mysql_connection_destroy(thread, &observer), VIREO_OK);
    CHECK(vireo_mysql_thread_detach(&thread), VIREO_OK);
    CHECK(vireo_mysql_runtime_destroy(&runtime), VIREO_OK);
    assert(fd_count() == fd);
    memset(db_password, 0, sizeof(db_password)); memset(phc, 0, sizeof(phc));
    memset(before, 0, sizeof(before)); memset(after, 0, sizeof(after));
    printf("PASS %zu real username observations; case lookup/PHC, exact display, duplicate three-table snapshot, account isolation, 3/32 bytes; FD %zu->%zu\n", cases, fd, fd_count());
    return 0;
}
