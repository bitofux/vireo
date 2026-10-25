/* PROJECT : VIREO; FILE : test_directory_root_real.c; AUTHOR : bitofux;
 * DATE : 2026-10-22; BRIEF : 公开service/仓库API、原生UTC、真实授权及只读快照。 */
#define _POSIX_C_SOURCE 200809L
#include <vireo/service/directory_root.h>
#include <vireo/persistence/mysql_schema.h>
#include <vireo/persistence/mysql_statement.h>
#include <vireo/persistence/mysql_user_repository.h>
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define CHECK(call, want) do { errno = EDOM; vireo_result_t got_ = (call); \
    if (got_ != (want)) { fprintf(stderr, "line %d result %d want %d\n", __LINE__, (int)got_, (int)(want)); abort(); } \
    assert(errno == EDOM); } while (0)
static vireo_mysql_thread_t *thread;
static vireo_mysql_connection_t *observer;
static vireo_mysql_user_repository_t *users;
static vireo_mysql_node_repository_t *nodes;
static const vireo_password_policy_t policy = VIREO_PASSWORD_POLICY_DEFAULT;
static char phc[VIREO_PASSWORD_ENCODED_CAPACITY];
static size_t phc_length, cases;
static unsigned char serial;
static uint64_t issued_at;

static uint64_t now_ms(void)
{
    struct timespec t; assert(clock_gettime(CLOCK_REALTIME, &t) == 0 && t.tv_sec > 0);
    return (uint64_t)t.tv_sec * 1000 + (uint64_t)t.tv_nsec / 1000000;
}

/* SQL仅为受控fixture；不拼接客户端名字、密码或token。返回owner由caller销毁。 */
static vireo_mysql_statement_t *execute_sql(const char *sql, bool rows)
{
    const vireo_mysql_statement_limits_t limits = {0, 32, 0, 2048, 131072};
    vireo_mysql_statement_t *s = NULL; vireo_mysql_execution_t execution;
    CHECK(vireo_mysql_statement_prepare(thread, observer, sql, strlen(sql), &limits, &s, NULL), VIREO_OK);
    CHECK(vireo_mysql_statement_execute(thread, s, NULL, 0, &execution, NULL), VIREO_OK);
    assert(execution.has_result == rows); return s;
}

static void mutate(const char *sql)
{
    vireo_mysql_statement_t *s = execute_sql(sql, false);
    CHECK(vireo_mysql_statement_destroy(thread, &s, NULL), VIREO_OK);
}

/* 全列快照保留长度、NULL与表/行边界；只在内存比较，绝不输出秘密。 */
static size_t snapshot(unsigned char out[65536])
{
    const char *sql[] = {"SELECT * FROM users ORDER BY id", "SELECT * FROM sessions ORDER BY id",
        "SELECT * FROM file_nodes ORDER BY id", "SELECT * FROM objects ORDER BY object_hash",
        "SELECT * FROM operation_audits ORDER BY id"};
    size_t used = 0;
    for (size_t t = 0; t < sizeof(sql)/sizeof(sql[0]); ++t) {
        vireo_mysql_statement_t *s = execute_sql(sql[t], true); vireo_mysql_statement_info_t info;
        CHECK(vireo_mysql_statement_inspect(thread, s, &info), VIREO_OK);
        for (;;) {
            vireo_mysql_fetch_outcome_t fetched;
            CHECK(vireo_mysql_statement_fetch(thread, s, &fetched, NULL), VIREO_OK);
            if (fetched == VIREO_MYSQL_FETCH_DONE) { break; }
            for (size_t col = 0; col < info.column_count; ++col) {
                vireo_mysql_cell_view_t cell;
                CHECK(vireo_mysql_statement_column(thread, s, col, &cell), VIREO_OK);
                assert(used + 2 + sizeof(cell.length) + cell.length < 65536);
                out[used++] = cell.is_null ? 1 : 0;
                memcpy(out + used, &cell.length, sizeof(cell.length)); used += sizeof(cell.length);
                if (cell.length != 0) { memcpy(out + used, cell.data, cell.length); used += cell.length; }
            }
            out[used++] = 0xfe;
        }
        out[used++] = 0xff; CHECK(vireo_mysql_statement_destroy(thread, &s, NULL), VIREO_OK);
    }
    return used;
}

static vireo_mysql_node_actor_t account(const char *name, uint64_t *root)
{
    vireo_mysql_registration_input_t registration = {.username = name, .username_length = strlen(name),
        .username_key = name, .username_key_length = strlen(name), .password_hash = phc,
        .password_hash_length = phc_length, .occurred_at_ms = issued_at - 1000};
    registration.request_id[15] = ++serial; vireo_mysql_registration_report_t reg;
    CHECK(vireo_mysql_user_repository_register(users, &registration, 0, &reg, NULL), VIREO_OK);
    assert(reg.commit == VIREO_MYSQL_REGISTRATION_COMMITTED && !reg.cleanup_pending); *root = reg.root_node_id;
    vireo_mysql_login_input_t login = {.user_id = reg.user_id, .verified_password_hash = phc,
        .verified_password_hash_length = phc_length, .issued_at_ms = issued_at,
        .expires_at_ms = issued_at + 3600000};
    login.token_digest.bytes[0] = serial; login.request_id[15] = ++serial;
    vireo_mysql_login_report_t logged;
    CHECK(vireo_mysql_user_repository_login(users, &login, 0, &logged, NULL), VIREO_OK);
    assert(logged.commit == VIREO_MYSQL_LOGIN_COMMITTED && !logged.cleanup_pending);
    return (vireo_mysql_node_actor_t){reg.user_id, logged.session_id};
}

/* 每次根查询前后比较五表全列，证明不改last_seen/审计且缺根不补写。 */
static vireo_directory_root_result_t root_query(vireo_mysql_node_actor_t actor,
    vireo_result_t rc, vireo_directory_root_outcome_t outcome, uint64_t root_id,
    vireo_mysql_node_issue_t issue, bool diagnostics)
{
    unsigned char before[65536], after[65536]; size_t length = snapshot(before);
    vireo_directory_root_result_t out; vireo_mysql_node_error_t error;
    memset(&out, 0xa5, sizeof(out)); memset(&error, 0, sizeof(error));
    const vireo_mysql_node_actor_t saved = actor;
    CHECK(vireo_directory_service_root(nodes, &actor, 0, &out, diagnostics ? &error : NULL), rc);
    assert(actor.user_id == saved.user_id && actor.session_id == saved.session_id);
    assert(out.outcome == outcome && out.root_node_id == root_id && out.repository_called &&
        out.repository_result == rc && out.repository.rollback_confirmed && !out.repository.cleanup_pending &&
        out.repository.issue == issue && out.repository.found == (outcome == VIREO_DIRECTORY_ROOT_FOUND));
    if (diagnostics) { assert(error.cleanup_result == VIREO_OK); }
    assert(snapshot(after) == length && !memcmp(before, after, length));
    memset(before, 0, sizeof(before)); memset(after, 0, sizeof(after)); ++cases; return out;
}

/* 真repo在非创建线程应前置拒绝；called=true不等于SQL已执行。 */
static void *wrong_worker(void *context)
{
    const vireo_mysql_node_actor_t *actor = context;
    vireo_directory_root_result_t out; vireo_mysql_node_error_t error;
    CHECK(vireo_directory_service_root(nodes, actor, 0, &out, &error), VIREO_RESULT_INVALID_ARGUMENT);
    assert(out.repository_called && out.repository_result == VIREO_RESULT_INVALID_ARGUMENT &&
        out.outcome == VIREO_DIRECTORY_ROOT_NONE && out.root_node_id == 0 &&
        !out.repository.cleanup_pending && error.stage == VIREO_MYSQL_NODE_STAGE_VALIDATE);
    return NULL;
}

static size_t fd_count(void)
{
    DIR *d = opendir("/proc/self/fd"); assert(d != NULL); size_t n = 0;
    while (readdir(d) != NULL) { ++n; } assert(closedir(d) == 0); return n;
}

int main(int argc, char **argv)
{
    assert(argc == 5); char db_password[1026]; FILE *f = fopen(argv[3], "r");
    assert(f != NULL && fgets(db_password, (int)sizeof(db_password), f) != NULL && fclose(f) == 0);
    db_password[strcspn(db_password, "\n")] = 0;
    struct sigaction action = {0}; action.sa_handler = SIG_IGN;
    assert(sigemptyset(&action.sa_mask) == 0 && sigaction(SIGPIPE, &action, NULL) == 0);
    size_t fds = fd_count(); vireo_mysql_runtime_t *runtime = NULL;
    CHECK(vireo_mysql_runtime_create(&runtime, NULL), VIREO_OK);
    CHECK(vireo_mysql_thread_attach(runtime, &thread, NULL), VIREO_OK);
    vireo_mysql_connection_options_t options = {argv[1], argv[2], db_password, argv[4], 3, 3, 3};
    const vireo_mysql_migration_t *catalog = NULL; size_t count = 0;
    CHECK(vireo_mysql_schema_catalog(&catalog, &count), VIREO_OK); vireo_mysql_migration_report_t migration;
    CHECK(vireo_mysql_migration_apply(thread, &options, catalog, count, &migration, NULL), VIREO_OK);
    assert(migration.ready && migration.steps_completed==17);
    CHECK(vireo_mysql_connection_open(thread, &options, &observer, NULL), VIREO_OK);
    vireo_mysql_pool_t *pool = NULL;
    /* 两次ROOT_INVARIANT各按042策略discard一连接；保留第三个供后续真实授权读。 */
    const vireo_mysql_pool_options_t pool_options = {options, 3, 3, VIREO_MYSQL_POOL_MEMORY_MAX};
    CHECK(vireo_mysql_pool_create(thread, &pool_options, &pool, NULL), VIREO_OK);
    CHECK(vireo_mysql_user_repository_create(thread, pool, &policy, &users, NULL), VIREO_OK);
    CHECK(vireo_mysql_node_repository_create(thread, pool, &nodes, NULL), VIREO_OK);
    CHECK(vireo_password_hash_create(&policy, "Correct!7", 9, phc, sizeof(phc), &phc_length), VIREO_OK);
    issued_at = now_ms() - 10000; uint64_t alice_root, bob_root;
    vireo_mysql_node_actor_t alice = account("alice_root", &alice_root), bob = account("bob_root", &bob_root);
    assert(alice_root != bob_root && alice_root != 0 && bob_root != 0);
    vireo_directory_root_result_t root = root_query(alice, VIREO_OK, VIREO_DIRECTORY_ROOT_FOUND,
        alice_root, VIREO_MYSQL_NODE_ISSUE_NONE, true);
    (void)root_query(bob, VIREO_OK, VIREO_DIRECTORY_ROOT_FOUND, bob_root, VIREO_MYSQL_NODE_ISSUE_NONE, false);
    vireo_mysql_node_actor_t mixed = {alice.user_id, bob.session_id};
    (void)root_query(mixed, VIREO_RESULT_NOT_FOUND, VIREO_DIRECTORY_ROOT_UNAUTHORIZED, 0,
        VIREO_MYSQL_NODE_AUTH_REJECTED, true);
    pthread_t other;
    assert(pthread_create(&other, NULL, wrong_worker, &alice) == 0 && pthread_join(other, NULL) == 0);
    (void)root_query(alice, VIREO_OK, VIREO_DIRECTORY_ROOT_FOUND, alice_root, VIREO_MYSQL_NODE_ISSUE_NONE, true);

    /* 禁用用户是授权拒绝，恢复后同一session仍可读；服务不会缓存根或授权。 */
    mutate("UPDATE users SET status=2 WHERE username_key='alice_root'");
    (void)root_query(alice, VIREO_RESULT_NOT_FOUND, VIREO_DIRECTORY_ROOT_UNAUTHORIZED, 0,
        VIREO_MYSQL_NODE_AUTH_REJECTED, false);
    mutate("UPDATE users SET status=1 WHERE username_key='alice_root'");
    (void)root_query(alice, VIREO_OK, VIREO_DIRECTORY_ROOT_FOUND, alice_root, VIREO_MYSQL_NODE_ISSUE_NONE, true);

    /* schema禁止非活动根；在隔离fixture中删除无孩子的根制造真实缺根。 */
    uint64_t missing_root;
    vireo_mysql_node_actor_t broken = account("broken_root", &missing_root);
    char sql[512];
    int n = snprintf(sql, sizeof(sql), "DELETE FROM file_nodes WHERE id=%llu",
        (unsigned long long)missing_root);
    assert(n > 0 && (size_t)n < sizeof(sql)); mutate(sql);
    (void)root_query(broken, VIREO_RESULT_DATABASE, VIREO_DIRECTORY_ROOT_NONE, 0,
        VIREO_MYSQL_NODE_ROOT_INVARIANT, true);
    (void)root_query(broken, VIREO_RESULT_DATABASE, VIREO_DIRECTORY_ROOT_NONE, 0,
        VIREO_MYSQL_NODE_ROOT_INVARIANT, false);
    (void)root_query(bob, VIREO_OK, VIREO_DIRECTORY_ROOT_FOUND, bob_root, VIREO_MYSQL_NODE_ISSUE_NONE, true);

    vireo_mysql_logout_input_t logout = {.user_id = alice.user_id, .session_id = alice.session_id,
        .occurred_at_ms = now_ms()}; logout.request_id[15] = ++serial;
    vireo_mysql_logout_report_t logged_out;
    CHECK(vireo_mysql_user_repository_logout(users, &logout, 0, &logged_out, NULL), VIREO_OK);
    assert(logged_out.commit == VIREO_MYSQL_LOGOUT_COMMITTED && !logged_out.cleanup_pending);
    (void)root_query(alice, VIREO_RESULT_NOT_FOUND, VIREO_DIRECTORY_ROOT_UNAUTHORIZED, 0,
        VIREO_MYSQL_NODE_AUTH_REJECTED, true);
    (void)root_query(bob, VIREO_OK, VIREO_DIRECTORY_ROOT_FOUND, bob_root, VIREO_MYSQL_NODE_ISSUE_NONE, true);
    assert(now_ms() > issued_at + 1);
    n = snprintf(sql, sizeof(sql), "UPDATE sessions SET expires_at_ms=issued_at_ms+1 WHERE id=%llu",
        (unsigned long long)bob.session_id);
    assert(n > 0 && (size_t)n < sizeof(sql)); mutate(sql);
    (void)root_query(bob, VIREO_RESULT_NOT_FOUND, VIREO_DIRECTORY_ROOT_UNAUTHORIZED, 0,
        VIREO_MYSQL_NODE_AUTH_REJECTED, false);
    vireo_mysql_pool_info_t pool_info; CHECK(vireo_mysql_pool_inspect(pool, &pool_info), VIREO_OK);
    assert(pool_info.leased == 0 && pool_info.vacant == 2 && pool_info.idle == 1 && pool_info.returning == 0);
    CHECK(vireo_mysql_node_repository_destroy(&nodes, NULL), VIREO_OK);
    CHECK(vireo_mysql_user_repository_destroy(&users, NULL), VIREO_OK);
    bool closed = false; CHECK(vireo_mysql_pool_close(pool, &closed, NULL), VIREO_OK); assert(closed);
    CHECK(vireo_mysql_pool_destroy(thread, &pool, NULL), VIREO_OK);
    CHECK(vireo_mysql_connection_destroy(thread, &observer), VIREO_OK);
    CHECK(vireo_mysql_thread_detach(&thread), VIREO_OK);
    CHECK(vireo_mysql_runtime_destroy(&runtime), VIREO_OK);
    assert(root.outcome == VIREO_DIRECTORY_ROOT_FOUND && root.root_node_id == alice_root && root.repository.found);
    assert(fd_count() == fds); memset(db_password, 0, sizeof(db_password)); memset(phc, 0, sizeof(phc));
    printf("PASS %zu real root observations; native UTC, Alice/Bob, wrong worker, disable/revoke/expiry, missing-root invariant, five-table read-only snapshots, independent ID; FD %zu->%zu\n", cases, fds, fd_count());
    return 0;
}
