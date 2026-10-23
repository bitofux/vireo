/* PROJECT : VIREO; FILE : test_directory_list_worker_real.c; AUTHOR : bitofux;
 * DATE : 2026-10-23; BRIEF : 公开service/仓库API、原生UTC、真实授权及只读快照。 */
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <vireo/persistence/mysql_schema.h>
#include <vireo/persistence/mysql_statement.h>
#include <vireo/persistence/mysql_user_repository.h>
#include <vireo/service/directory_list_worker.h>
#include <vireo/thread/thread_pool.h>

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
static vireo_page_token_key_t *key;
static const vireo_password_policy_t policy = VIREO_PASSWORD_POLICY_DEFAULT;
static char phc[VIREO_PASSWORD_ENCODED_CAPACITY];
static size_t phc_length;
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
static size_t fd_count(void) {
    DIR *d = opendir("/proc/self/fd");
    assert(d != NULL);
    size_t n = 0;
    struct dirent *entry;
    while ((entry = readdir(d)) != NULL) {
        if (entry->d_name[0] != '.')
            ++n;
    }
    assert(closedir(d) == 0);
    return n;
}

static vireo_directory_list_worker_resources_t resources;
static vireo_thread_pool_t *workers;
static vireo_task_queue_t *tasks;
static pthread_barrier_t first_pair;
static atomic_uint calls;
static pthread_t first_threads[2];
static uint32_t sequence;
static vireo_result_t expected_rc[32];
static vireo_status_t expected_status[32];
static vireo_directory_list_worker_report_t reports[32];
static vireo_directory_list_completion_outcome_t observed[32];
static uint64_t monotonic(void) {
    uint64_t now;
    CHECK(vireo_clock_monotonic_now(&now, NULL), VIREO_OK);
    return now;
}
static vireo_result_t run_worker(void *context, const vireo_task_t *task) {
    (void)context;
    unsigned index = atomic_fetch_add(&calls, 1);
    if (index < 2) {
        first_threads[index] = pthread_self();
        int rc = pthread_barrier_wait(&first_pair);
        assert(rc == 0 || rc == PTHREAD_BARRIER_SERIAL_THREAD);
    }
    vireo_task_info_t info;
    CHECK(vireo_task_inspect(task, &info), VIREO_OK);
    uint32_t seq = info.metadata.route.request_sequence;
    assert(seq > 0 && seq < 32);
    const vireo_directory_list_worker_options_t options = {{4407, 1000}, 32768, 65536};
    vireo_directory_list_worker_t *owner = NULL;
    CHECK(vireo_directory_list_worker_create(&resources, &options, &owner), VIREO_OK);
    CHECK(vireo_directory_list_worker_run(owner, task, &reports[seq]), expected_rc[seq]);
    assert(reports[seq].execute_called && reports[seq].publish_called &&
           reports[seq].publication.publication.completion_transferred &&
           !reports[seq].cleanup.repository_pending && !reports[seq].cleanup.thread_pending);
    vireo_directory_list_worker_cleanup_report_t cleanup;
    CHECK(vireo_directory_list_worker_destroy(&owner, &cleanup), VIREO_OK);
    assert(!owner);
    return expected_rc[seq];
}
static uint32_t submit(vireo_mysql_node_actor_t actor, uint64_t directory,
                       const vireo_page_token_t *token, vireo_result_t rc, vireo_status_t status) {
    uint32_t seq = ++sequence;
    expected_rc[seq] = rc;
    expected_status[seq] = status;
    vireo_node_list_request_t q = {.sequence = seq,
                                   .session_handle = 13,
                                   .directory_id = directory,
                                   .page_size = 64,
                                   .has_page_token = token != NULL};
    if (token)
        memcpy(q.page_token, token->bytes, 96);
    unsigned char wire[150];
    size_t size;
    CHECK(vireo_node_list_request_encode(&q, wire, sizeof(wire), &size), VIREO_OK);
    vireo_task_metadata_t m;
    const vireo_task_route_t route = {55, 0, 91, seq};
    CHECK(vireo_task_metadata_make(route, seq, 4407, monotonic() + UINT64_C(10000000000), &m),
          VIREO_OK);
    vireo_task_t *task = NULL;
    CHECK(vireo_directory_list_task_create(m, 4407, wire, size, &actor, 4096, NULL, &task),
          VIREO_OK);
    uint64_t limit = monotonic() + UINT64_C(5000000000);
    for (;;) {
        vireo_thread_pool_submit_report_t report;
        vireo_result_t got = vireo_thread_pool_try_submit(workers, &task, &report);
        if (got == VIREO_OK) {
            assert(report.queue_report.transferred && !task);
            break;
        }
        assert(got == VIREO_RESULT_BUSY && !report.queue_report.transferred && task &&
               monotonic() < limit);
        sched_yield();
    }
    memset(wire, 0xcc, sizeof(wire));
    return seq;
}
static void receive_pair(void) {
    uint64_t limit = monotonic() + UINT64_C(10000000000);
    for (size_t i = 0; i < 2;) {
        vireo_completion_t *c = NULL;
        vireo_completion_queue_transfer_report_t transfer;
        vireo_result_t rc = vireo_completion_queue_try_pop(resources.queue, &c, &transfer);
        if (rc == VIREO_RESULT_NOT_FOUND || rc == VIREO_RESULT_BUSY) {
            assert(!c && !transfer.transferred && monotonic() < limit);
            sched_yield();
            continue;
        }
        assert(rc == VIREO_OK && c && transfer.transferred);
        vireo_completion_info_t info;
        CHECK(vireo_completion_inspect(c, &info), VIREO_OK);
        uint32_t seq = info.metadata.request.route.request_sequence;
        assert(seq > 0 && seq <= sequence &&
               observed[seq].metadata.request.request_instance_id == 0);
        CHECK(vireo_directory_list_completion_decode(c, 4407, &observed[seq]), VIREO_OK);
        assert(observed[seq].response.status == expected_status[seq] &&
               info.metadata.result == expected_rc[seq] &&
               observed[seq].metadata.request.route.client_owner_id == 55 &&
               observed[seq].metadata.request.route.client_generation == 91);
        CHECK(vireo_completion_destroy(&c), VIREO_OK);
        ++i;
    }
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
    assert(migration.ready && migration.steps_completed == 15);
    CHECK(vireo_mysql_connection_open(thread, &options, &observer, NULL), VIREO_OK);
    vireo_mysql_pool_t *pool = NULL;
    const vireo_mysql_pool_options_t pool_options = {options, 2, 2, VIREO_MYSQL_POOL_MEMORY_MAX};
    CHECK(vireo_mysql_pool_create(thread, &pool_options, &pool, NULL), VIREO_OK);
    CHECK(vireo_mysql_user_repository_create(thread, pool, &policy, &users, NULL), VIREO_OK);
    CHECK(vireo_page_token_key_create(&key), VIREO_OK);
    CHECK(vireo_password_hash_create(&policy, "Correct!7", 9, phc, sizeof(phc), &phc_length),
          VIREO_OK);
    issued_at = now_ms() - 10000;
    uint64_t alice_root, bob_root;
    vireo_mysql_node_actor_t alice = account("alice_list", &alice_root),
                             bob = account("bob_list", &bob_root);
    for (uint64_t id = 100; id < 170; ++id)
        add_directory(id, alice.user_id, alice_root);
    add_directory(800, bob.user_id, bob_root);
    mutate(
        "INSERT INTO "
        "objects(object_hash,size,state,ref_count,storage_class,created_at_ms,updated_at_ms,"
        "verified_at_ms) "
        "VALUES(UNHEX(REPEAT('00',32)),18446744073709551615,2,64,1,1000,1000,1000)");
    mutate(
        "UPDATE file_nodes SET name=CONCAT(LPAD(id,20,'0'),REPEAT('x',235)) WHERE id BETWEEN 100 "
        "AND 169");
    mutate(
        "UPDATE file_nodes SET "
        "node_type=2,object_hash=UNHEX(REPEAT('00',32)),size=18446744073709551615 WHERE id BETWEEN "
        "100 AND 163");
    unsigned char before[65536], after[65536];
    size_t before_size = snapshot(before);
    resources.runtime = runtime;
    resources.database = pool;
    resources.key = key;
    vireo_completion_queue_options_t cq = {1, 65536};
    vireo_notifier_options_t no = {65536};
    CHECK(vireo_completion_queue_create(&cq, &resources.queue), VIREO_OK);
    CHECK(vireo_completion_queue_prepare_wait(resources.queue), VIREO_OK);
    CHECK(vireo_notifier_create(&no, &resources.notifier, NULL), VIREO_OK);
    const vireo_task_queue_options_t tq = {8, 65536};
    CHECK(vireo_task_queue_create(&tq, &tasks), VIREO_OK);
    CHECK(vireo_task_queue_prepare_wait(tasks), VIREO_OK);
    const vireo_thread_pool_options_t wo = {2, 65536};
    CHECK(vireo_thread_pool_create(&wo, &workers), VIREO_OK);
    const vireo_thread_pool_configuration_t configuration = {tasks, run_worker, NULL};
    CHECK(vireo_thread_pool_configure(workers, &configuration, NULL), VIREO_OK);
    assert(pthread_barrier_init(&first_pair, NULL, 2) == 0);
    atomic_init(&calls, 0);
    vireo_thread_pool_report_t start;
    CHECK(vireo_thread_pool_start(workers, &start), VIREO_OK);
    CHECK(vireo_thread_pool_enable_execution(workers, &start), VIREO_OK);
    uint32_t first = submit(alice, alice_root, NULL, VIREO_OK, VIREO_STATUS_OK);
    (void)submit(alice, alice_root, NULL, VIREO_OK, VIREO_STATUS_OK);
    receive_pair();
    assert(observed[first].response.count == 64 && observed[first].response.has_more &&
           observed[first].response.entries[63].size == UINT64_MAX);
    vireo_page_token_t next;
    memcpy(next.bytes, observed[first].response.next_page_token, 96);
    vireo_page_token_context_t token_context = {alice.user_id, alice.session_id, alice_root, 64};
    vireo_page_token_claims_t claims;
    CHECK(vireo_page_token_verify(key, &token_context, &next, now_ms(), &claims), VIREO_OK);
    assert(claims.after_id == 163);
    uint32_t last = submit(alice, alice_root, &next, VIREO_OK, VIREO_STATUS_OK);
    (void)submit(bob, bob_root, &next, VIREO_RESULT_PROTOCOL, VIREO_STATUS_BAD_REQUEST);
    receive_pair();
    assert(observed[last].response.count == 6 && !observed[last].response.has_more &&
           observed[last].response.entries[0].node_id == 164 &&
           observed[last].response.entries[5].node_id == 169);
    vireo_page_token_t bad = next;
    bad.bytes[95] ^= 1;
    (void)submit(alice, alice_root, &bad, VIREO_RESULT_PROTOCOL, VIREO_STATUS_BAD_REQUEST);
    const vireo_mysql_node_actor_t mixed = {alice.user_id, bob.session_id};
    (void)submit(mixed, alice_root, &bad, VIREO_RESULT_NOT_FOUND, VIREO_STATUS_UNAUTHORIZED);
    receive_pair();
    (void)submit(alice, bob_root, NULL, VIREO_RESULT_NOT_FOUND, VIREO_STATUS_NOT_FOUND);
    uint32_t empty = submit(alice, 164, NULL, VIREO_OK, VIREO_STATUS_OK);
    receive_pair();
    assert(observed[empty].response.count == 0);
    claims.issued_at_ms = now_ms() - 600001;
    claims.expires_at_ms = claims.issued_at_ms + 600000;
    vireo_page_token_t expired;
    CHECK(vireo_page_token_sign(key, &claims, claims.issued_at_ms, &expired), VIREO_OK);
    (void)submit(alice, alice_root, &expired, VIREO_RESULT_PROTOCOL, VIREO_STATUS_BAD_REQUEST);
    (void)submit(alice, alice_root, &next, VIREO_OK, VIREO_STATUS_OK);
    receive_pair();
    assert(snapshot(after) == before_size && !memcmp(before, after, before_size));
    /* 持久身份撤销后即使携带错误token，也只能得到UNAUTHORIZED。 */
    mutate("UPDATE users SET status=2 WHERE username_key='alice_list'");
    before_size = snapshot(before);
    (void)submit(alice, alice_root, &bad, VIREO_RESULT_NOT_FOUND, VIREO_STATUS_UNAUTHORIZED);
    (void)submit(alice, alice_root, &next, VIREO_RESULT_NOT_FOUND, VIREO_STATUS_UNAUTHORIZED);
    receive_pair();
    assert(snapshot(after) == before_size && !memcmp(before, after, before_size));
    /* 完成队列已腾空，先关闭领取再join；仅CHECK_QUEUE/BUSY允许有界资格重查。 */
    vireo_thread_pool_shutdown_report_t shutdown;
    uint64_t limit = monotonic() + UINT64_C(5000000000);
    for (;;) {
        vireo_result_t rc =
            vireo_thread_pool_shutdown_and_join(workers, VIREO_TASK_QUEUE_DRAIN, &shutdown);
        if (shutdown.pool_report.joined_count == 2) {
            assert((rc == VIREO_RESULT_NOT_FOUND || rc == VIREO_RESULT_PROTOCOL) &&
                   shutdown.pool_report.stage == VIREO_THREAD_POOL_STAGE_EXECUTE_TASK);
            break; /* pool原样报告worker首个业务错误，不代表join失败。 */
        }
        if (rc == VIREO_OK)
            break;
        assert(rc == VIREO_RESULT_BUSY && monotonic() < limit &&
               (shutdown.stage == VIREO_THREAD_POOL_SHUTDOWN_STAGE_CLOSE_QUEUE ||
                shutdown.stage == VIREO_THREAD_POOL_SHUTDOWN_STAGE_JOIN_WORKERS));
        sched_yield();
    }
    assert(atomic_load(&calls) == sequence && !pthread_equal(first_threads[0], first_threads[1]));
    for (uint32_t i = 1; i <= sequence; ++i)
        assert(reports[i].publish_called && reports[i].work_result == expected_rc[i]);
    bool saw_worker_error = false;
    for (size_t i = 0; i < 2; ++i) {
        vireo_thread_pool_worker_result_t worker_result;
        CHECK(vireo_thread_pool_inspect_worker_result(workers, i, &worker_result), VIREO_OK);
        if (worker_result.result == VIREO_OK)
            assert(worker_result.stage == VIREO_THREAD_POOL_STAGE_NONE);
        else {
            assert(worker_result.stage == VIREO_THREAD_POOL_STAGE_EXECUTE_TASK &&
                   (worker_result.result == VIREO_RESULT_NOT_FOUND ||
                    worker_result.result == VIREO_RESULT_PROTOCOL));
            saw_worker_error = true;
        }
    }
    assert(saw_worker_error);
    CHECK(vireo_thread_pool_destroy(&workers), VIREO_OK);
    CHECK(vireo_task_queue_destroy(&tasks), VIREO_OK);
    assert(pthread_barrier_destroy(&first_pair) == 0);
    vireo_completion_t *left = NULL;
    vireo_completion_queue_transfer_report_t transfer;
    CHECK(vireo_completion_queue_try_pop(resources.queue, &left, &transfer),
          VIREO_RESULT_NOT_FOUND);
    CHECK(vireo_completion_queue_destroy(&resources.queue), VIREO_OK);
    CHECK(vireo_notifier_destroy(&resources.notifier, NULL), VIREO_OK);
    /* key确实晚于全部owner清理和worker join销毁。 */
    CHECK(vireo_page_token_key_destroy(&key), VIREO_OK);
    CHECK(vireo_mysql_user_repository_destroy(&users, NULL), VIREO_OK);
    vireo_mysql_pool_info_t info;
    CHECK(vireo_mysql_pool_inspect(pool, &info), VIREO_OK);
    assert(info.idle == 2 && !info.leased && !info.returning && !info.vacant);
    bool closed = false;
    CHECK(vireo_mysql_pool_close(pool, &closed, NULL), VIREO_OK);
    assert(closed);
    CHECK(vireo_mysql_pool_destroy(thread, &pool, NULL), VIREO_OK);
    CHECK(vireo_mysql_connection_destroy(thread, &observer), VIREO_OK);
    CHECK(vireo_mysql_thread_detach(&thread), VIREO_OK);
    CHECK(vireo_mysql_runtime_destroy(&runtime), VIREO_OK);
    assert(fd_count() == fds && observed[first].response.entries[63].size == UINT64_MAX);
    memset(db_password, 0, sizeof(db_password));
    memset(phc, 0, sizeof(phc));
    printf(
        "PASS %u real LIST worker observations; two fixed workers/shared key, full page, paging, "
        "auth/token precedence, five-table read-only and FD %zu->%zu\n",
        sequence, fds, fd_count());
    return 0;
}
