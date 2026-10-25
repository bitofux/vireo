/*
 * PROJECT : VIREO
 * FILE    : test_auth_login_verifier_repository_real.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-19
 * BRIEF   : 两真实OS worker通过MySQL凭据查询与共享验证器决定是否进入登录事务。
 */
#define _POSIX_C_SOURCE 200809L
#include <vireo/service/auth_login_verifier.h>
#include <vireo/service/auth_username.h>
#include <vireo/persistence/mysql_schema.h>
#include <vireo/persistence/mysql_statement.h>
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <openssl/crypto.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(call, expected) do { errno = EDOM; vireo_result_t got_ = (call); \
    if (got_ != (expected)) { fprintf(stderr, "line %d result %d wanted %d\n", \
        __LINE__, (int)got_, (int)(expected)); abort(); } assert(errno == EDOM); } while (0)

static vireo_password_policy_t const policy = VIREO_PASSWORD_POLICY_DEFAULT;
typedef struct worker {
    vireo_mysql_runtime_t *runtime;
    vireo_mysql_pool_t *pool;
    vireo_auth_password_gate_t *gate;
    vireo_auth_login_verifier_t const *verifier;
    pthread_barrier_t *entered;
    pthread_barrier_t *leave;
    unsigned char id;
    size_t verified;
    size_t committed;
} worker_t;

static void wait_barrier(pthread_barrier_t *barrier)
{
    int const result = pthread_barrier_wait(barrier);
    assert(result == 0 || result == PTHREAD_BARRIER_SERIAL_THREAD);
}

/* 非敏感固定SQL经公开prepared statement执行；main独占observer。 */
static void sql(vireo_mysql_thread_t *thread, vireo_mysql_connection_t *connection,
    char const *text, char const *expected)
{
    vireo_mysql_statement_limits_t const limits = {0, 1, 0, 64, 8192};
    vireo_mysql_statement_t *statement = NULL;
    vireo_mysql_execution_t execution;
    CHECK(vireo_mysql_statement_prepare(thread, connection, text, strlen(text), &limits,
        &statement, NULL), VIREO_OK);
    CHECK(vireo_mysql_statement_execute(thread, statement, NULL, 0, &execution, NULL), VIREO_OK);
    if (expected != NULL) {
        assert(execution.has_result);
        vireo_mysql_fetch_outcome_t outcome;
        vireo_mysql_cell_view_t cell;
        CHECK(vireo_mysql_statement_fetch(thread, statement, &outcome, NULL), VIREO_OK);
        assert(outcome == VIREO_MYSQL_FETCH_ROW);
        CHECK(vireo_mysql_statement_column(thread, statement, 0, &cell), VIREO_OK);
        assert(!cell.is_null && cell.length == strlen(expected) && !memcmp(cell.data, expected, cell.length));
        CHECK(vireo_mysql_statement_fetch(thread, statement, &outcome, NULL), VIREO_OK);
        assert(outcome == VIREO_MYSQL_FETCH_DONE);
    } else { assert(!execution.has_result); }
    CHECK(vireo_mysql_statement_destroy(thread, &statement, NULL), VIREO_OK);
}

static void registration(vireo_mysql_user_repository_t *repo, vireo_auth_password_gate_t *gate,
    char const *name, char const *password, unsigned char event)
{
    vireo_auth_username_t username;
    CHECK(vireo_auth_username_prepare(name, strlen(name), &username), VIREO_OK);
    char phc[128]; size_t length = 0;
    CHECK(vireo_auth_password_hash_create(gate, password, strlen(password), phc, sizeof(phc),
        &length), VIREO_OK);
    vireo_mysql_registration_input_t input = {
        .username = username.username, .username_length = username.length,
        .username_key = username.key, .username_key_length = username.length,
        .password_hash = phc, .password_hash_length = length, .occurred_at_ms = 1000
    };
    input.request_id[15] = event;
    vireo_mysql_registration_report_t report;
    CHECK(vireo_mysql_user_repository_register(repo, &input, 0, &report, NULL), VIREO_OK);
    assert(report.commit == VIREO_MYSQL_REGISTRATION_COMMITTED && !report.cleanup_pending);
    OPENSSL_cleanse(phc, sizeof(phc));
}

static void *run(void *context)
{
    worker_t *worker = context;
    vireo_mysql_thread_t *thread = NULL;
    vireo_mysql_user_repository_t *repo = NULL;
    CHECK(vireo_mysql_thread_attach(worker->runtime, &thread, NULL), VIREO_OK);
    CHECK(vireo_mysql_user_repository_create(thread, worker->pool, &policy, &repo, NULL), VIREO_OK);
    char const *const names[2][3] = {{"ALICE_7", "Alice_7", "Nobody_7"}, {"Bob_007", "BOB_007", "alice_7"}};
    char const *const passwords[2][3] = {{"Correct!7", "incorrect", "Correct!7"}, {"BobPass!9", "incorrect", "Correct!7"}};
    for (size_t i = 0; i < 3; ++i) {
        vireo_auth_username_t username;
        CHECK(vireo_auth_username_prepare(names[worker->id][i], strlen(names[worker->id][i]),
            &username), VIREO_OK);
        vireo_mysql_user_credentials_t credentials;
        vireo_mysql_credentials_report_t report;
        vireo_result_t const found = worker->id == 0 && i == 2 ? VIREO_RESULT_NOT_FOUND : VIREO_OK;
        CHECK(vireo_mysql_user_repository_find_credentials(repo, username.key, username.length,
            5000, &credentials, &report, NULL), found);
        assert(!report.cleanup_pending && report.found == (found == VIREO_OK));
        /* 所有查询已归还连接后才放行KDF；main在两worker都到达时检查公开pool leased=0。 */
        wait_barrier(worker->entered); wait_barrier(worker->leave);
        bool authenticated = true;
        CHECK(vireo_auth_login_verifier_verify(worker->verifier, worker->gate,
            found == VIREO_OK ? &credentials : NULL, passwords[worker->id][i],
            strlen(passwords[worker->id][i]), &authenticated), VIREO_OK);
        bool const expected = (worker->id == 0 && i == 0) || (worker->id == 1 && i == 2);
        assert(authenticated == expected); ++worker->verified;
        if (authenticated) {
            vireo_session_token_t token;
            vireo_session_token_digest_t digest;
            CHECK(vireo_session_token_generate(&token, &digest), VIREO_OK);
            vireo_mysql_login_input_t input = {
                .user_id = credentials.user_id,
                .verified_password_hash = credentials.password_hash,
                .verified_password_hash_length = credentials.password_hash_length,
                .token_digest = digest, .issued_at_ms = 2000, .expires_at_ms = 5000
            };
            input.request_id[15] = (unsigned char)(worker->id + 17);
            vireo_mysql_login_report_t login;
            CHECK(vireo_mysql_user_repository_login(repo, &input, 5000, &login, NULL), VIREO_OK);
            assert(login.commit == VIREO_MYSQL_LOGIN_COMMITTED && login.session_id && !login.cleanup_pending);
            ++worker->committed;
            CHECK(vireo_session_token_clear(&token), VIREO_OK);
            OPENSSL_cleanse(&digest, sizeof(digest));
        }
        CHECK(vireo_mysql_user_credentials_clear(&credentials), VIREO_OK);
    }
    CHECK(vireo_mysql_user_repository_destroy(&repo, NULL), VIREO_OK);
    CHECK(vireo_mysql_thread_detach(&thread), VIREO_OK);
    return NULL;
}

static size_t fd_count(void)
{
    DIR *directory = opendir("/proc/self/fd"); assert(directory != NULL);
    size_t count = 0; while (readdir(directory) != NULL) { ++count; }
    assert(closedir(directory) == 0); return count;
}

int main(int argc, char **argv)
{
    assert(argc == 5);
    char db_password[1026];
    FILE *file = fopen(argv[3], "r");
    assert(file != NULL && fgets(db_password, (int)sizeof(db_password), file) != NULL && fclose(file) == 0);
    db_password[strcspn(db_password, "\n")] = 0;
    struct sigaction action = {0}; action.sa_handler = SIG_IGN;
    assert(sigemptyset(&action.sa_mask) == 0 && sigaction(SIGPIPE, &action, NULL) == 0);
    size_t const fd = fd_count();
    vireo_mysql_runtime_t *runtime = NULL;
    vireo_mysql_thread_t *thread = NULL;
    CHECK(vireo_mysql_runtime_create(&runtime, NULL), VIREO_OK);
    CHECK(vireo_mysql_thread_attach(runtime, &thread, NULL), VIREO_OK);
    vireo_mysql_connection_options_t const options = {argv[1], argv[2], db_password, argv[4], 3, 3, 3};
    vireo_mysql_migration_t const *catalog = NULL; size_t count = 0;
    CHECK(vireo_mysql_schema_catalog(&catalog, &count), VIREO_OK);
    vireo_mysql_migration_report_t migration;
    CHECK(vireo_mysql_migration_apply(thread, &options, catalog, count, &migration, NULL), VIREO_OK);
    assert(migration.ready && migration.steps_completed==17);
    vireo_mysql_connection_t *observer = NULL;
    CHECK(vireo_mysql_connection_open(thread, &options, &observer, NULL), VIREO_OK);
    vireo_mysql_pool_options_t const pool_options = {options, 1, 1, VIREO_MYSQL_POOL_MEMORY_MAX};
    vireo_mysql_pool_t *pool = NULL;
    CHECK(vireo_mysql_pool_create(thread, &pool_options, &pool, NULL), VIREO_OK);
    vireo_mysql_user_repository_t *repo = NULL;
    CHECK(vireo_mysql_user_repository_create(thread, pool, &policy, &repo, NULL), VIREO_OK);
    vireo_auth_password_gate_options_t const gate_options = VIREO_AUTH_PASSWORD_GATE_OPTIONS_DEFAULT;
    vireo_auth_password_gate_t *gate = NULL;
    vireo_auth_login_verifier_t *verifier = NULL;
    CHECK(vireo_auth_password_gate_create(&gate_options, &gate), VIREO_OK);
    CHECK(vireo_auth_login_verifier_create(gate, &verifier), VIREO_OK);
    registration(repo, gate, "Alice_7", "Correct!7", 1);
    registration(repo, gate, "Bob_007", "BobPass!9", 2);
    sql(thread, observer, "UPDATE users SET status=2 WHERE username_key='bob_007'", NULL);
    CHECK(vireo_mysql_user_repository_destroy(&repo, NULL), VIREO_OK);

    pthread_barrier_t entered, leave;
    assert(pthread_barrier_init(&entered, NULL, 3) == 0 && pthread_barrier_init(&leave, NULL, 3) == 0);
    worker_t workers[2] = {
        {runtime, pool, gate, verifier, &entered, &leave, 0, 0, 0},
        {runtime, pool, gate, verifier, &entered, &leave, 1, 0, 0}
    };
    pthread_t threads[2];
    for (size_t i = 0; i < 2; ++i) { assert(pthread_create(&threads[i], NULL, run, &workers[i]) == 0); }
    assert(!pthread_equal(threads[0], threads[1]) && !pthread_equal(threads[0], pthread_self()));
    for (size_t i = 0; i < 3; ++i) {
        wait_barrier(&entered);
        vireo_mysql_pool_info_t info;
        CHECK(vireo_mysql_pool_inspect(pool, &info), VIREO_OK); assert(info.leased == 0);
        wait_barrier(&leave);
    }
    for (size_t i = 0; i < 2; ++i) {
        assert(pthread_join(threads[i], NULL) == 0 && workers[i].verified == 3 && workers[i].committed == 1);
    }
    assert(pthread_barrier_destroy(&entered) == 0 && pthread_barrier_destroy(&leave) == 0);
    sql(thread, observer, "SELECT COUNT(*) FROM sessions", "2");
    sql(thread, observer, "SELECT COUNT(*) FROM operation_audits WHERE action=2", "2");
    sql(thread, observer, "SELECT COUNT(*) FROM sessions s JOIN users u ON u.id=s.user_id WHERE u.username_key='bob_007'", "0");
    CHECK(vireo_auth_login_verifier_destroy(&verifier), VIREO_OK);
    CHECK(vireo_auth_password_gate_close(gate), VIREO_OK);
    CHECK(vireo_auth_password_gate_destroy(&gate), VIREO_OK);
    bool closed = false;
    CHECK(vireo_mysql_pool_close(pool, &closed, NULL), VIREO_OK); assert(closed);
    CHECK(vireo_mysql_pool_destroy(thread, &pool, NULL), VIREO_OK);
    CHECK(vireo_mysql_connection_destroy(thread, &observer), VIREO_OK);
    CHECK(vireo_mysql_thread_detach(&thread), VIREO_OK);
    CHECK(vireo_mysql_runtime_destroy(&runtime), VIREO_OK);
    OPENSSL_cleanse(db_password, sizeof(db_password));
    assert(fd_count() == fd);
    printf("PASS real login verifier: 2 OS workers, 6 verifications, 2 committed sessions; absent/disabled/wrong no session; 3 pool releases before KDF; FD %zu->%zu\n", fd, fd_count());
    return 0;
}
