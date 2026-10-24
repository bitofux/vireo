/* PROJECT : VIREO; FILE : test_directory_service_real.c; AUTHOR : bitofux;
 * DATE : 2026-10-22; BRIEF : 公开service/仓库API、原生UTC、真实授权及只读快照。 */
#define _POSIX_C_SOURCE 200809L
#include <vireo/service/directory_service.h>
#include <vireo/persistence/mysql_schema.h>
#include <vireo/persistence/mysql_statement.h>
#include <vireo/persistence/mysql_user_repository.h>
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <signal.h>
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

static void zeroed(const void *value, size_t size)
{
    const unsigned char *p = value;
    for (size_t i = 0; i < size; ++i) { assert(p[i] == 0); }
}

/* 每次读前后观察五表所有值，覆盖审计、Session last_seen及业务元数据无变化。 */
static vireo_directory_stat_result_t stat_node(vireo_mysql_node_actor_t actor, uint64_t id,
    vireo_directory_stat_outcome_t want)
{
    unsigned char before[65536], after[65536]; size_t length = snapshot(before);
    vireo_directory_stat_result_t out; vireo_mysql_node_error_t error;
    memset(&out, 0xa5, sizeof(out)); memset(&error, 0x5a, sizeof(error));
    const vireo_mysql_node_actor_t saved = actor;
    CHECK(vireo_directory_service_stat(nodes, &actor, id, 0, &out, &error),
        want == VIREO_DIRECTORY_STAT_FOUND ? VIREO_OK : VIREO_RESULT_NOT_FOUND);
    assert(actor.user_id == saved.user_id && actor.session_id == saved.session_id);
    assert(out.outcome == want && out.repository_called && out.repository.rollback_confirmed &&
        !out.repository.cleanup_pending && error.cleanup_result == VIREO_OK);
    if (want == VIREO_DIRECTORY_STAT_FOUND) {
        assert(out.repository_result == VIREO_OK && out.repository.found &&
            out.repository.issue == VIREO_MYSQL_NODE_ISSUE_NONE && out.node.id == id && out.node.owner_id == actor.user_id);
    } else {
        assert(out.repository_result == VIREO_RESULT_NOT_FOUND && !out.repository.found &&
            out.repository.issue == (want == VIREO_DIRECTORY_STAT_UNAUTHORIZED ? VIREO_MYSQL_NODE_AUTH_REJECTED : VIREO_MYSQL_NODE_NOT_FOUND));
        zeroed(&out.node, sizeof(out.node));
    }
    assert(snapshot(after) == length && !memcmp(before, after, length));
    memset(before, 0, sizeof(before)); memset(after, 0, sizeof(after)); ++cases; return out;
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
    assert(migration.ready && migration.steps_completed==16);
    CHECK(vireo_mysql_connection_open(thread, &options, &observer, NULL), VIREO_OK);
    vireo_mysql_pool_t *pool = NULL;
    const vireo_mysql_pool_options_t pool_options = {options, 1, 1, VIREO_MYSQL_POOL_MEMORY_MAX};
    CHECK(vireo_mysql_pool_create(thread, &pool_options, &pool, NULL), VIREO_OK);
    CHECK(vireo_mysql_user_repository_create(thread, pool, &policy, &users, NULL), VIREO_OK);
    CHECK(vireo_mysql_node_repository_create(thread, pool, &nodes, NULL), VIREO_OK);
    CHECK(vireo_password_hash_create(&policy, "Correct!7", 9, phc, sizeof(phc), &phc_length), VIREO_OK);
    issued_at = now_ms() - 10000; uint64_t alice_root, bob_root;
    vireo_mysql_node_actor_t alice = account("alice_stat", &alice_root), bob = account("bob_stat", &bob_root);
    vireo_directory_stat_result_t root = stat_node(alice, alice_root, VIREO_DIRECTORY_STAT_FOUND);
    assert(!root.node.has_parent && !root.node.parent_id && !root.node.name_length &&
        root.node.kind == VIREO_MYSQL_NODE_DIRECTORY && !root.node.has_object_hash && !root.node.size);
    zeroed(root.node.name, sizeof(root.node.name)); zeroed(root.node.object_hash, sizeof(root.node.object_hash));
    (void)stat_node(bob, bob_root, VIREO_DIRECTORY_STAT_FOUND);
    (void)stat_node(alice, bob_root, VIREO_DIRECTORY_STAT_NOT_FOUND);
    (void)stat_node(bob, alice_root, VIREO_DIRECTORY_STAT_NOT_FOUND);
    (void)stat_node(alice, UINT64_MAX, VIREO_DIRECTORY_STAT_NOT_FOUND);

    /* 用公开mkdir生产目录，原始255字节非UTF8名字不被服务截断或重编码。 */
    unsigned char name[255]; memset(name, 0x80, sizeof(name));
    vireo_mysql_node_mkdir_input_t input = {.parent_id = alice_root, .name = name, .name_length = sizeof(name)};
    input.request_id[15] = ++serial; vireo_mysql_node_mkdir_report_t made;
    CHECK(vireo_mysql_node_repository_mkdir(nodes, &alice, &input, 0, &made, NULL), VIREO_OK);
    assert(made.commit == VIREO_MYSQL_NODE_MKDIR_COMMITTED && !made.cleanup_pending);
    vireo_directory_stat_result_t directory = stat_node(alice, made.node.id, VIREO_DIRECTORY_STAT_FOUND);
    assert(directory.node.has_parent && directory.node.parent_id == alice_root && directory.node.name_length == 255 &&
        !memcmp(directory.node.name, name, sizeof(name)) && directory.node.kind == VIREO_MYSQL_NODE_DIRECTORY);
    (void)stat_node(bob, made.node.id, VIREO_DIRECTORY_STAT_NOT_FOUND);

    /* 固定SQL只生产文件元数据fixture，不代表上传或CAS验证成功。 */
    mutate("INSERT INTO objects(object_hash,size,state,ref_count,storage_class,created_at_ms,updated_at_ms,verified_at_ms) VALUES(UNHEX(REPEAT('a5',32)),18446744073709551615,2,1,1,1000,1000,1000)");
    char sql[2048];
    int n = snprintf(sql, sizeof(sql), "INSERT INTO file_nodes(id,owner_id,parent_id,name,node_type,state,object_hash,size,created_at_ms,updated_at_ms,deleted_at_ms) VALUES(1001,%llu,%llu,0xFF,2,2,UNHEX(REPEAT('a5',32)),18446744073709551615,1000,1002,NULL),(1002,%llu,%llu,'pending',2,1,NULL,5,1000,1002,NULL),(1003,%llu,%llu,'deleted',2,3,NULL,7,1000,1002,1002)",
        (unsigned long long)alice.user_id, (unsigned long long)alice_root, (unsigned long long)alice.user_id,
        (unsigned long long)alice_root, (unsigned long long)alice.user_id, (unsigned long long)alice_root);
    assert(n > 0 && (size_t)n < sizeof(sql)); mutate(sql);
    vireo_directory_stat_result_t file = stat_node(alice, 1001, VIREO_DIRECTORY_STAT_FOUND);
    assert(file.node.kind == VIREO_MYSQL_NODE_FILE && file.node.has_object_hash && file.node.size == UINT64_MAX &&
        file.node.has_parent && file.node.parent_id == alice_root && file.node.name_length == 1 && file.node.name[0] == 0xff &&
        file.node.created_at_ms == 1000 && file.node.updated_at_ms == 1002);
    for (size_t i = 0; i < sizeof(file.node.object_hash); ++i) { assert(file.node.object_hash[i] == 0xa5); }
    (void)stat_node(bob, 1001, VIREO_DIRECTORY_STAT_NOT_FOUND);
    (void)stat_node(alice, 1002, VIREO_DIRECTORY_STAT_NOT_FOUND);
    (void)stat_node(alice, 1003, VIREO_DIRECTORY_STAT_NOT_FOUND);
    vireo_mysql_node_actor_t mixed = {alice.user_id, bob.session_id};
    (void)stat_node(mixed, alice_root, VIREO_DIRECTORY_STAT_UNAUTHORIZED);
    vireo_mysql_logout_input_t logout = {.user_id = alice.user_id, .session_id = alice.session_id,
        .occurred_at_ms = now_ms()}; logout.request_id[15] = ++serial;
    vireo_mysql_logout_report_t logged_out;
    CHECK(vireo_mysql_user_repository_logout(users, &logout, 0, &logged_out, NULL), VIREO_OK);
    assert(logged_out.commit == VIREO_MYSQL_LOGOUT_COMMITTED && !logged_out.cleanup_pending);
    (void)stat_node(alice, alice_root, VIREO_DIRECTORY_STAT_UNAUTHORIZED);
    (void)stat_node(bob, bob_root, VIREO_DIRECTORY_STAT_FOUND);
    /* 将Bob到期点设为已过去的issued+1；服务仍通过原生UTC判断，不注入时钟。 */
    assert(now_ms() > issued_at + 1);
    n = snprintf(sql, sizeof(sql), "UPDATE sessions SET expires_at_ms=issued_at_ms+1 WHERE id=%llu", (unsigned long long)bob.session_id);
    assert(n > 0 && (size_t)n < sizeof(sql)); mutate(sql);
    (void)stat_node(bob, bob_root, VIREO_DIRECTORY_STAT_UNAUTHORIZED);
    vireo_mysql_pool_info_t pool_info; CHECK(vireo_mysql_pool_inspect(pool, &pool_info), VIREO_OK);
    assert(pool_info.leased == 0);
    CHECK(vireo_mysql_node_repository_destroy(&nodes, NULL), VIREO_OK);
    CHECK(vireo_mysql_user_repository_destroy(&users, NULL), VIREO_OK);
    bool closed = false; CHECK(vireo_mysql_pool_close(pool, &closed, NULL), VIREO_OK); assert(closed);
    CHECK(vireo_mysql_pool_destroy(thread, &pool, NULL), VIREO_OK);
    CHECK(vireo_mysql_connection_destroy(thread, &observer), VIREO_OK);
    CHECK(vireo_mysql_thread_detach(&thread), VIREO_OK);
    CHECK(vireo_mysql_runtime_destroy(&runtime), VIREO_OK);
    /* 所有SQL/仓库资源已销毁，返回值的原始字节和标量仍有效。 */
    assert(root.node.id == alice_root && directory.node.name_length == sizeof(name) &&
        !memcmp(directory.node.name, name, sizeof(name)) && file.node.size == UINT64_MAX && file.node.object_hash[31] == 0xa5);
    assert(fd_count() == fds); memset(db_password, 0, sizeof(db_password)); memset(phc, 0, sizeof(phc));
    printf("PASS %zu real STAT observations; native UTC, root/mkdir/file, raw names, owner isolation, hidden rows, revoke/expiry, five-table read-only snapshots, independent values; FD %zu->%zu\n", cases, fds, fd_count());
    return 0;
}
