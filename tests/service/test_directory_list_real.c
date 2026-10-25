/* PROJECT : VIREO; FILE : test_directory_list_real.c; AUTHOR : bitofux;
 * DATE : 2026-10-22; BRIEF : 公开service/仓库API、原生UTC、真实授权及只读快照。 */
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <vireo/persistence/mysql_schema.h>
#include <vireo/persistence/mysql_statement.h>
#include <vireo/persistence/mysql_user_repository.h>
#include <vireo/service/directory_list.h>

#define CHECK(call, want)                                                                     \
    do {                                                                                      \
        errno = EDOM;                                                                         \
        vireo_result_t got_ = (call);                                                         \
        if (got_ != (want)) {                                                                 \
            fprintf(stderr, "line %d result %d want %d\n", __LINE__, (int)got_, (int)(want)); \
            abort();                                                                          \
        }                                                                                     \
        assert(errno == EDOM);                                                                \
    } while (0)
static vireo_mysql_thread_t *thread;
static vireo_mysql_connection_t *observer;
static vireo_mysql_user_repository_t *users;
static vireo_mysql_node_repository_t *nodes;
static vireo_page_token_key_t *key;
static const vireo_password_policy_t policy = VIREO_PASSWORD_POLICY_DEFAULT;
static char phc[VIREO_PASSWORD_ENCODED_CAPACITY];
static size_t phc_length, cases;
static unsigned char serial;
static uint64_t issued_at;

static uint64_t now_ms(void) {
    struct timespec t;
    assert(clock_gettime(CLOCK_REALTIME, &t) == 0 && t.tv_sec > 0);
    return (uint64_t)t.tv_sec * 1000 + (uint64_t)t.tv_nsec / 1000000;
}

/* SQL仅为受控fixture；不拼接客户端名字、密码或token。返回owner由caller销毁。 */
static vireo_mysql_statement_t *execute_sql(const char *sql, bool rows) {
    const vireo_mysql_statement_limits_t limits = {0, 32, 0, 2048, 131072};
    vireo_mysql_statement_t *s = NULL;
    vireo_mysql_execution_t execution;
    CHECK(vireo_mysql_statement_prepare(thread, observer, sql, strlen(sql), &limits, &s, NULL),
          VIREO_OK);
    CHECK(vireo_mysql_statement_execute(thread, s, NULL, 0, &execution, NULL), VIREO_OK);
    assert(execution.has_result == rows);
    return s;
}

static void mutate(const char *sql) {
    vireo_mysql_statement_t *s = execute_sql(sql, false);
    CHECK(vireo_mysql_statement_destroy(thread, &s, NULL), VIREO_OK);
}

/* 全列快照保留长度、NULL与表/行边界；只在内存比较，绝不输出秘密。 */
static size_t snapshot(unsigned char out[65536]) {
    const char *sql[] = {"SELECT * FROM users ORDER BY id", "SELECT * FROM sessions ORDER BY id",
                         "SELECT * FROM file_nodes ORDER BY id",
                         "SELECT * FROM objects ORDER BY object_hash",
                         "SELECT * FROM operation_audits ORDER BY id"};
    size_t used = 0;
    for (size_t t = 0; t < sizeof(sql) / sizeof(sql[0]); ++t) {
        vireo_mysql_statement_t *s = execute_sql(sql[t], true);
        vireo_mysql_statement_info_t info;
        CHECK(vireo_mysql_statement_inspect(thread, s, &info), VIREO_OK);
        for (;;) {
            vireo_mysql_fetch_outcome_t fetched;
            CHECK(vireo_mysql_statement_fetch(thread, s, &fetched, NULL), VIREO_OK);
            if (fetched == VIREO_MYSQL_FETCH_DONE) {
                break;
            }
            for (size_t col = 0; col < info.column_count; ++col) {
                vireo_mysql_cell_view_t cell;
                CHECK(vireo_mysql_statement_column(thread, s, col, &cell), VIREO_OK);
                assert(used + 2 + sizeof(cell.length) + cell.length < 65536);
                out[used++] = cell.is_null ? 1 : 0;
                memcpy(out + used, &cell.length, sizeof(cell.length));
                used += sizeof(cell.length);
                if (cell.length != 0) {
                    memcpy(out + used, cell.data, cell.length);
                    used += cell.length;
                }
            }
            out[used++] = 0xfe;
        }
        out[used++] = 0xff;
        CHECK(vireo_mysql_statement_destroy(thread, &s, NULL), VIREO_OK);
    }
    return used;
}

static vireo_mysql_node_actor_t account(const char *name, uint64_t *root) {
    vireo_mysql_registration_input_t registration = {.username = name,
                                                     .username_length = strlen(name),
                                                     .username_key = name,
                                                     .username_key_length = strlen(name),
                                                     .password_hash = phc,
                                                     .password_hash_length = phc_length,
                                                     .occurred_at_ms = issued_at - 1000};
    registration.request_id[15] = ++serial;
    vireo_mysql_registration_report_t reg;
    CHECK(vireo_mysql_user_repository_register(users, &registration, 0, &reg, NULL), VIREO_OK);
    assert(reg.commit == VIREO_MYSQL_REGISTRATION_COMMITTED && !reg.cleanup_pending);
    *root = reg.root_node_id;
    vireo_mysql_login_input_t login = {.user_id = reg.user_id,
                                       .verified_password_hash = phc,
                                       .verified_password_hash_length = phc_length,
                                       .issued_at_ms = issued_at,
                                       .expires_at_ms = issued_at + 3600000};
    login.token_digest.bytes[0] = serial;
    login.request_id[15] = ++serial;
    vireo_mysql_login_report_t logged;
    CHECK(vireo_mysql_user_repository_login(users, &login, 0, &logged, NULL), VIREO_OK);
    assert(logged.commit == VIREO_MYSQL_LOGIN_COMMITTED && !logged.cleanup_pending);
    return (vireo_mysql_node_actor_t){reg.user_id, logged.session_id};
}

static void zeroed(const void *p, size_t n) {
    const unsigned char *v = p;
    for (size_t i = 0; i < n; ++i) {
        assert(v[i] == 0);
    }
}

/* A query cannot mutate any of the five tables, including last_seen/audit. */
static vireo_directory_list_result_t query(vireo_mysql_node_actor_t actor, uint64_t directory,
                                           uint16_t size, const vireo_page_token_t *token,
                                           vireo_result_t want,
                                           vireo_directory_list_outcome_t outcome,
                                           bool diagnostic) {
    unsigned char before[65536], after[65536];
    size_t n = snapshot(before);
    vireo_directory_list_query_t q = {
        .directory_id = directory, .page_size = size, .has_page_token = token != NULL};
    if (token != NULL) {
        q.page_token = *token;
    }
    vireo_directory_list_result_t out;
    vireo_directory_list_error_t error;
    memset(&out, 0xa5, sizeof(out));
    CHECK(vireo_directory_service_list(nodes, key, &actor, &q, 0, &out, diagnostic ? &error : NULL),
          want);
    assert(out.outcome == outcome &&
           out.repository_operation != VIREO_DIRECTORY_LIST_REPOSITORY_NONE &&
           !out.repository.cleanup_pending && out.repository.rollback_confirmed);
    if (outcome != VIREO_DIRECTORY_LIST_PAGE) {
        zeroed(&out.page, sizeof(out.page));
        zeroed(&out.next_page_token, sizeof(out.next_page_token));
    } else {
        assert(out.page.count <= size);
        zeroed(out.page.nodes + out.page.count, (64 - out.page.count) * sizeof(out.page.nodes[0]));
        if (!out.page.has_more) {
            zeroed(&out.next_page_token, sizeof(out.next_page_token));
        }
    }
    if (diagnostic) {
        assert(error.repository.cleanup_result == VIREO_OK && error.system_errno == 0);
    }
    assert(snapshot(after) == n && !memcmp(before, after, n));
    memset(before, 0, sizeof(before));
    memset(after, 0, sizeof(after));
    ++cases;
    return out;
}

static void add_directory(uint64_t id, uint64_t owner, uint64_t parent) {
    char sql[1024];
    int n =
        snprintf(sql, sizeof(sql),
                 "INSERT INTO "
                 "file_nodes(id,owner_id,parent_id,name,node_type,state,object_hash,size,created_"
                 "at_ms,updated_at_ms) VALUES(%llu,%llu,%llu,'n%llu',1,2,NULL,0,1000,1000)",
                 (unsigned long long)id, (unsigned long long)owner, (unsigned long long)parent,
                 (unsigned long long)id);
    assert(n > 0 && (size_t)n < sizeof(sql));
    mutate(sql);
}
static void *wrong_worker(void *context) {
    const vireo_mysql_node_actor_t *actor = context;
    vireo_directory_list_query_t q = {.directory_id = 42, .page_size = 2};
    vireo_directory_list_result_t out;
    vireo_directory_list_error_t e;
    CHECK(vireo_directory_service_list(nodes, key, actor, &q, 0, &out, &e),
          VIREO_RESULT_INVALID_ARGUMENT);
    assert(out.repository_result == VIREO_RESULT_INVALID_ARGUMENT &&
           out.outcome == VIREO_DIRECTORY_LIST_NONE &&
           out.repository_operation == VIREO_DIRECTORY_LIST_REPOSITORY_CHILDREN &&
           e.repository.stage == VIREO_MYSQL_NODE_STAGE_VALIDATE);
    zeroed(&out.page, sizeof(out.page));
    return NULL;
}
static size_t fd_count(void) {
    DIR *d = opendir("/proc/self/fd");
    assert(d != NULL);
    size_t n = 0;
    while (readdir(d) != NULL) {
        ++n;
    }
    assert(closedir(d) == 0);
    return n;
}

int main(int argc, char **argv) {
    assert(argc == 5);
    char db_password[1026];
    FILE *f = fopen(argv[3], "r");
    assert(f != NULL && fgets(db_password, (int)sizeof(db_password), f) != NULL && fclose(f) == 0);
    db_password[strcspn(db_password, "\n")] = 0;
    struct sigaction action = {0};
    action.sa_handler = SIG_IGN;
    assert(sigemptyset(&action.sa_mask) == 0 && sigaction(SIGPIPE, &action, NULL) == 0);
    size_t fds = fd_count();
    vireo_mysql_runtime_t *runtime = NULL;
    CHECK(vireo_mysql_runtime_create(&runtime, NULL), VIREO_OK);
    CHECK(vireo_mysql_thread_attach(runtime, &thread, NULL), VIREO_OK);
    vireo_mysql_connection_options_t options = {argv[1], argv[2], db_password, argv[4], 3, 3, 3};
    const vireo_mysql_migration_t *catalog = NULL;
    size_t count = 0;
    CHECK(vireo_mysql_schema_catalog(&catalog, &count), VIREO_OK);
    vireo_mysql_migration_report_t migration;
    CHECK(vireo_mysql_migration_apply(thread, &options, catalog, count, &migration, NULL),
          VIREO_OK);
    assert(migration.ready && migration.steps_completed==17);
    CHECK(vireo_mysql_connection_open(thread, &options, &observer, NULL), VIREO_OK);
    vireo_mysql_pool_t *pool = NULL;
    const vireo_mysql_pool_options_t pool_options = {options, 2, 2, VIREO_MYSQL_POOL_MEMORY_MAX};
    CHECK(vireo_mysql_pool_create(thread, &pool_options, &pool, NULL), VIREO_OK);
    CHECK(vireo_mysql_user_repository_create(thread, pool, &policy, &users, NULL), VIREO_OK);
    CHECK(vireo_mysql_node_repository_create(thread, pool, &nodes, NULL), VIREO_OK);
    CHECK(vireo_page_token_key_create(&key), VIREO_OK);
    CHECK(vireo_password_hash_create(&policy, "Correct!7", 9, phc, sizeof(phc), &phc_length),
          VIREO_OK);
    issued_at = now_ms() - 10000;
    uint64_t alice_root, bob_root;
    vireo_mysql_node_actor_t alice = account("alice_list", &alice_root),
                             bob = account("bob_list", &bob_root);
    (void)query(alice, alice_root, 64, NULL, VIREO_OK, VIREO_DIRECTORY_LIST_PAGE, true);
    for (uint64_t id = 100; id < 170; ++id) {
        add_directory(id, alice.user_id, alice_root);
    }
    add_directory(10000, alice.user_id, 100);
    add_directory(800, bob.user_id, bob_root);
    mutate(
        "INSERT INTO "
        "objects(object_hash,size,state,ref_count,storage_class,created_at_ms,updated_at_ms,"
        "verified_at_ms) VALUES(UNHEX(REPEAT('00',32)),18446744073709551615,2,1,1,1000,1000,1000)");
    mutate(
        "UPDATE file_nodes SET "
        "node_type=2,object_hash=UNHEX(REPEAT('00',32)),size=18446744073709551615 WHERE id=165");
    mutate("UPDATE file_nodes SET name=UNHEX('FF') WHERE id=168");
    mutate("UPDATE file_nodes SET name=REPEAT('x',255) WHERE id=169");
    vireo_directory_list_result_t first =
        query(alice, alice_root, 64, NULL, VIREO_OK, VIREO_DIRECTORY_LIST_PAGE, true);
    assert(first.page.count == 64 && first.page.has_more && first.page.next_after_id == 163);
    vireo_page_token_context_t ctx = {alice.user_id, alice.session_id, alice_root, 64};
    vireo_page_token_claims_t claims;
    CHECK(vireo_page_token_verify(key, &ctx, &first.next_page_token, now_ms(), &claims), VIREO_OK);
    assert(claims.after_id == 163 && claims.expires_at_ms - claims.issued_at_ms == 600000);
    vireo_directory_list_result_t last = query(alice, alice_root, 64, &first.next_page_token,
                                               VIREO_OK, VIREO_DIRECTORY_LIST_PAGE, true);
    assert(last.page.count == 6 && !last.page.has_more && last.page.nodes[0].id == 164 &&
           last.page.nodes[5].id == 169);
    assert(last.page.nodes[1].has_object_hash && last.page.nodes[1].size == UINT64_MAX &&
           last.page.nodes[4].name[0] == 255 && last.page.nodes[5].name_length == 255);
    (void)query(alice, alice_root, 64, &first.next_page_token, VIREO_OK, VIREO_DIRECTORY_LIST_PAGE,
                false); /* replay */
    (void)query(alice, alice_root, 2, &first.next_page_token, VIREO_RESULT_PROTOCOL,
                VIREO_DIRECTORY_LIST_BAD_TOKEN, true);
    (void)query(alice, bob_root, 64, &first.next_page_token, VIREO_RESULT_PROTOCOL,
                VIREO_DIRECTORY_LIST_BAD_TOKEN, true);
    (void)query(bob, bob_root, 64, &first.next_page_token, VIREO_RESULT_PROTOCOL,
                VIREO_DIRECTORY_LIST_BAD_TOKEN, true);
    (void)query(alice, bob_root, 2, NULL, VIREO_RESULT_NOT_FOUND, VIREO_DIRECTORY_LIST_NOT_FOUND,
                true);
    (void)query(alice, 165, 2, NULL, VIREO_RESULT_NOT_FOUND, VIREO_DIRECTORY_LIST_NOT_FOUND, false);
    (void)query(alice, 9999, 2, NULL, VIREO_RESULT_NOT_FOUND, VIREO_DIRECTORY_LIST_NOT_FOUND, true);
    vireo_page_token_t bad = first.next_page_token;
    bad.bytes[95] ^= 1;
    vireo_directory_list_result_t denied = query(alice, alice_root, 64, &bad, VIREO_RESULT_PROTOCOL,
                                                 VIREO_DIRECTORY_LIST_BAD_TOKEN, true);
    assert(denied.repository_operation == VIREO_DIRECTORY_LIST_REPOSITORY_AUTH_PROBE &&
           denied.repository_result == VIREO_OK && denied.token_checked &&
           denied.token_result == VIREO_RESULT_PROTOCOL);
    (void)query(alice, 9999, 64, &bad, VIREO_RESULT_PROTOCOL, VIREO_DIRECTORY_LIST_BAD_TOKEN, true);
    vireo_mysql_node_actor_t mixed = {alice.user_id, bob.session_id};
    (void)query(mixed, alice_root, 64, &bad, VIREO_RESULT_NOT_FOUND,
                VIREO_DIRECTORY_LIST_UNAUTHORIZED, true);
    pthread_t other;
    assert(pthread_create(&other, NULL, wrong_worker, &alice) == 0 &&
           pthread_join(other, NULL) == 0);
    /* Restart key invalidates a correctly signed old token; SQL still authorizes its owner. */
    vireo_page_token_key_t *saved_key = key;
    key = NULL;
    CHECK(vireo_page_token_key_create(&key), VIREO_OK);
    (void)query(alice, alice_root, 64, &first.next_page_token, VIREO_RESULT_PROTOCOL,
                VIREO_DIRECTORY_LIST_BAD_TOKEN, true);
    CHECK(vireo_page_token_key_destroy(&key), VIREO_OK);
    key = saved_key;
    /* Mint validly authenticated but expired and future chains. */
    vireo_page_token_t stale, future;
    const uint64_t now = now_ms();
    claims.issued_at_ms = now - 600001;
    claims.expires_at_ms = now - 1;
    CHECK(vireo_page_token_sign(key, &claims, claims.issued_at_ms, &stale), VIREO_OK);
    (void)query(alice, alice_root, 64, &stale, VIREO_RESULT_PROTOCOL,
                VIREO_DIRECTORY_LIST_BAD_TOKEN, true);
    claims.issued_at_ms = now + 60000;
    claims.expires_at_ms = claims.issued_at_ms + 600000;
    CHECK(vireo_page_token_sign(key, &claims, claims.issued_at_ms, &future), VIREO_OK);
    (void)query(alice, alice_root, 64, &future, VIREO_RESULT_PROTOCOL,
                VIREO_DIRECTORY_LIST_BAD_TOKEN, true);
    /* Live keyset: deleting the cursor does not invalidate it; low-ID inserts are not revisited. */
    vireo_directory_list_result_t small =
        query(alice, alice_root, 2, NULL, VIREO_OK, VIREO_DIRECTORY_LIST_PAGE, true);
    assert(small.page.next_after_id == 101);
    mutate("DELETE FROM file_nodes WHERE id=101");
    mutate("UPDATE file_nodes SET parent_id=100 WHERE id=102");
    mutate("UPDATE file_nodes SET state=3,deleted_at_ms=1000 WHERE id=103");
    add_directory(99, alice.user_id, alice_root);
    add_directory(200, alice.user_id, alice_root);
    vireo_directory_list_result_t changed = query(alice, alice_root, 2, &small.next_page_token,
                                                  VIREO_OK, VIREO_DIRECTORY_LIST_PAGE, true);
    assert(changed.page.nodes[0].id == 104 && changed.page.nodes[1].id == 105);
    vireo_page_token_context_t small_ctx = {alice.user_id, alice.session_id, alice_root, 2};
    CHECK(vireo_page_token_verify(key, &small_ctx, &small.next_page_token, now_ms(), &claims),
          VIREO_OK);
    vireo_page_token_claims_t next_claims;
    CHECK(
        vireo_page_token_verify(key, &small_ctx, &changed.next_page_token, now_ms(), &next_claims),
        VIREO_OK);
    assert(claims.issued_at_ms == next_claims.issued_at_ms &&
           claims.expires_at_ms == next_claims.expires_at_ms && next_claims.after_id == 105);
    /* A newly logged-in persistent session cannot continue the previous session's chain. */
    vireo_mysql_login_input_t login = {.user_id = alice.user_id,
                                       .verified_password_hash = phc,
                                       .verified_password_hash_length = phc_length,
                                       .issued_at_ms = issued_at,
                                       .expires_at_ms = issued_at + 3600000};
    login.token_digest.bytes[0] = ++serial;
    login.request_id[15] = ++serial;
    vireo_mysql_login_report_t new_login;
    CHECK(vireo_mysql_user_repository_login(users, &login, 0, &new_login, NULL), VIREO_OK);
    assert(new_login.commit == VIREO_MYSQL_LOGIN_COMMITTED &&
           new_login.session_id != alice.session_id);
    vireo_mysql_node_actor_t new_actor = {alice.user_id, new_login.session_id};
    (void)query(new_actor, alice_root, 2, &small.next_page_token, VIREO_RESULT_PROTOCOL,
                VIREO_DIRECTORY_LIST_BAD_TOKEN, true);
    /* Disabled/revoked/expired persistent identities dominate bad-token errors. */
    mutate("UPDATE users SET status=2 WHERE username_key='alice_list'");
    (void)query(alice, alice_root, 64, &bad, VIREO_RESULT_NOT_FOUND,
                VIREO_DIRECTORY_LIST_UNAUTHORIZED, true);
    mutate("UPDATE users SET status=1 WHERE username_key='alice_list'");
    (void)query(alice, alice_root, 2, &small.next_page_token, VIREO_OK, VIREO_DIRECTORY_LIST_PAGE,
                true);
    vireo_mysql_logout_input_t logout = {
        .user_id = alice.user_id, .session_id = alice.session_id, .occurred_at_ms = now_ms()};
    logout.request_id[15] = ++serial;
    vireo_mysql_logout_report_t logged_out;
    CHECK(vireo_mysql_user_repository_logout(users, &logout, 0, &logged_out, NULL), VIREO_OK);
    assert(logged_out.commit == VIREO_MYSQL_LOGOUT_COMMITTED && !logged_out.cleanup_pending);
    (void)query(alice, alice_root, 2, &small.next_page_token, VIREO_RESULT_NOT_FOUND,
                VIREO_DIRECTORY_LIST_UNAUTHORIZED, true);
    (void)query(alice, alice_root, 64, &bad, VIREO_RESULT_NOT_FOUND,
                VIREO_DIRECTORY_LIST_UNAUTHORIZED, false);
    char sql[512];
    int n =
        snprintf(sql, sizeof(sql), "UPDATE sessions SET expires_at_ms=issued_at_ms+1 WHERE id=%llu",
                 (unsigned long long)bob.session_id);
    assert(n > 0 && (size_t)n < sizeof(sql));
    mutate(sql);
    (void)query(bob, bob_root, 64, &bad, VIREO_RESULT_NOT_FOUND, VIREO_DIRECTORY_LIST_UNAUTHORIZED,
                true);
    /* Maximum uint64 cursor is never incremented or wrapped. */
    add_directory(UINT64_MAX - 1, alice.user_id, alice_root);
    add_directory(UINT64_MAX, alice.user_id, alice_root);
    vireo_page_token_context_t edge_ctx = {new_actor.user_id, new_actor.session_id, alice_root, 1};
    vireo_page_token_claims_t edge = {edge_ctx, UINT64_MAX - 1, now_ms(), 0};
    edge.expires_at_ms = edge.issued_at_ms + 600000;
    vireo_page_token_t edge_token;
    CHECK(vireo_page_token_sign(key, &edge, edge.issued_at_ms, &edge_token), VIREO_OK);
    vireo_directory_list_result_t maximum =
        query(new_actor, alice_root, 1, &edge_token, VIREO_OK, VIREO_DIRECTORY_LIST_PAGE, true);
    assert(maximum.page.count == 1 && maximum.page.nodes[0].id == UINT64_MAX &&
           !maximum.page.has_more);
    edge.after_id = UINT64_MAX;
    CHECK(vireo_page_token_sign(key, &edge, edge.issued_at_ms, &edge_token), VIREO_OK);
    maximum =
        query(new_actor, alice_root, 1, &edge_token, VIREO_OK, VIREO_DIRECTORY_LIST_PAGE, true);
    assert(maximum.page.count == 0 && !maximum.page.has_more);
    vireo_mysql_pool_info_t info;
    CHECK(vireo_mysql_pool_inspect(pool, &info), VIREO_OK);
    assert(info.leased == 0 && info.vacant == 0 && info.idle == 2 && info.returning == 0);
    CHECK(vireo_mysql_node_repository_destroy(&nodes, NULL), VIREO_OK);
    CHECK(vireo_page_token_key_destroy(&key), VIREO_OK);
    CHECK(vireo_mysql_user_repository_destroy(&users, NULL), VIREO_OK);
    bool closed = false;
    CHECK(vireo_mysql_pool_close(pool, &closed, NULL), VIREO_OK);
    assert(closed);
    CHECK(vireo_mysql_pool_destroy(thread, &pool, NULL), VIREO_OK);
    CHECK(vireo_mysql_connection_destroy(thread, &observer), VIREO_OK);
    CHECK(vireo_mysql_thread_detach(&thread), VIREO_OK);
    CHECK(vireo_mysql_runtime_destroy(&runtime), VIREO_OK);
    assert(first.page.nodes[0].id == 100 && last.page.nodes[1].size == UINT64_MAX &&
           fd_count() == fds);
    memset(db_password, 0, sizeof(db_password));
    memset(phc, 0, sizeof(phc));
    printf(
        "PASS %zu real LIST observations; native UTC/HMAC, max page, live cursors, session/token "
        "isolation, identity precedence, five-table read-only and FD %zu->%zu\n",
        cases, fds, fd_count());
    return 0;
}
