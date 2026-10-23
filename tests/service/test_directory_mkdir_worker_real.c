/* PROJECT : VIREO; FILE : test_directory_mkdir_real.c; AUTHOR : bitofux;
 * DATE : 2026-10-22; BRIEF : 公开MKDIR service、真实事务、拒绝六表快照及旧字节读取。 */
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <vireo/persistence/mysql_schema.h>
#include <vireo/persistence/mysql_statement.h>
#include <vireo/persistence/mysql_user_repository.h>
#include <vireo/service/directory_mkdir_worker.h>

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
static vireo_mysql_runtime_t *runtime;
static vireo_mysql_pool_t *pool;
static vireo_mysql_connection_t *observer;
static vireo_mysql_user_repository_t *users;
static vireo_mysql_node_repository_t *nodes;
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
    const char *sql[] = {
        "SELECT * FROM users ORDER BY id",
        "SELECT * FROM sessions ORDER BY id",
        "SELECT * FROM file_nodes ORDER BY id",
        "SELECT * FROM objects ORDER BY object_hash",
        "SELECT * FROM operation_audits ORDER BY id",
        "SELECT * FROM directory_write_receipts ORDER BY user_id,command,idempotency_key"};
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

static uint64_t scalar(const char *sql) {
    vireo_mysql_statement_t *s = execute_sql(sql, true);
    vireo_mysql_fetch_outcome_t fetched;
    vireo_mysql_cell_view_t cell;
    CHECK(vireo_mysql_statement_fetch(thread, s, &fetched, NULL), VIREO_OK);
    assert(fetched == VIREO_MYSQL_FETCH_ROW);
    CHECK(vireo_mysql_statement_column(thread, s, 0, &cell), VIREO_OK);
    assert(!cell.is_null && cell.length < 32);
    char bytes[32] = {0};
    memcpy(bytes, cell.data, cell.length);
    char *end;
    errno = 0;
    unsigned long long n = strtoull(bytes, &end, 10);
    assert(errno == 0 && *end == 0);
    CHECK(vireo_mysql_statement_destroy(thread, &s, NULL), VIREO_OK);
    return (uint64_t)n;
}
typedef struct job {
    vireo_directory_mkdir_worker_resources_t resources;
    vireo_task_t *task;
    vireo_result_t rc;
    vireo_directory_mkdir_worker_report_t report;
} job_t;
static void *run_worker(void *context) {
    job_t *j = context;
    int old = 0;
    assert(!pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &old));
    const vireo_directory_mkdir_worker_options_t options = {
        .execution = {400, 1000}, .completion_allocation_budget = 4096, .max_memory_bytes = 65536};
    vireo_directory_mkdir_worker_t *w = NULL;
    CHECK(vireo_directory_mkdir_worker_create(&j->resources, &options, &w), VIREO_OK);
    errno = EDOM;
    j->rc = vireo_directory_mkdir_worker_run(w, j->task, &j->report);
    assert(errno == EDOM);
    vireo_directory_mkdir_worker_cleanup_report_t clean;
    CHECK(vireo_directory_mkdir_worker_destroy(&w, &clean), VIREO_OK);
    assert(!w);
    return NULL;
}
static vireo_node_mkdir_request_t request(uint64_t parent, const unsigned char *name, size_t length,
                                          unsigned char key) {
    vireo_node_mkdir_request_t r = {.sequence = 7,
                                    .session_handle = 23,
                                    .parent_id = parent,
                                    .name_length = length,
                                    .idempotency_key = {0x22}};
    assert(length <= 255);
    memcpy(r.name, name, length);
    r.idempotency_key[15] = key;
    return r;
}
static void prepare(job_t *j, vireo_mysql_node_actor_t actor, const vireo_node_mkdir_request_t *req,
                    uint64_t deadline, bool cancel, size_t instance) {
    const vireo_task_metadata_t md = {.route = {1, 0, 3, 7},
                                      .request_instance_id = instance,
                                      .operation = 400,
                                      .deadline_ns = deadline};
    unsigned char wire[323];
    size_t length = 0;
    CHECK(vireo_node_mkdir_request_encode(req, wire, sizeof(wire), &length), VIREO_OK);
    vireo_task_cancel_t *c = NULL;
    if (cancel) {
        CHECK(vireo_task_cancel_create(4096, &c), VIREO_OK);
        CHECK(vireo_task_cancel_request(c), VIREO_OK);
    }
    CHECK(vireo_directory_mkdir_task_create(md, 400, wire, length, &actor, 4096, c, &j->task),
          VIREO_OK);
    CHECK(vireo_task_cancel_destroy(&c), VIREO_OK);
    memset(wire, 0, sizeof(wire));
}
/* Bounded consumer drains before join; never blocks the only consumer behind a producer. */
static vireo_directory_mkdir_completion_outcome_t receive(vireo_completion_queue_t *q) {
    vireo_completion_t *c = NULL;
    vireo_completion_queue_transfer_report_t moved;
    const uint64_t limit = now_ms() + 20000;
    for (;;) {
        errno = EDOM;
        vireo_result_t rc = vireo_completion_queue_try_pop(q, &c, &moved);
        assert(errno == EDOM);
        if (rc == VIREO_OK) {
            assert(c && moved.transferred);
            break;
        }
        assert((rc == VIREO_RESULT_BUSY || rc == VIREO_RESULT_NOT_FOUND) && now_ms() < limit);
        (void)sched_yield();
    }
    vireo_directory_mkdir_completion_outcome_t out;
    CHECK(vireo_directory_mkdir_completion_decode(c, 400, &out), VIREO_OK);
    CHECK(vireo_completion_destroy(&c), VIREO_OK);
    return out;
}
static void setup_queue(job_t *j, size_t capacity) {
    const vireo_completion_queue_options_t qo = {capacity, 65536};
    const vireo_notifier_options_t no = {4096};
    j->resources.runtime = runtime;
    j->resources.database = pool;
    CHECK(vireo_completion_queue_create(&qo, &j->resources.queue), VIREO_OK);
    CHECK(vireo_completion_queue_prepare_wait(j->resources.queue), VIREO_OK);
    CHECK(vireo_notifier_create(&no, &j->resources.notifier, NULL), VIREO_OK);
}
static void finish_queue(job_t *j) {
    vireo_completion_t *c = NULL;
    vireo_completion_queue_transfer_report_t moved;
    CHECK(vireo_completion_queue_try_pop(j->resources.queue, &c, &moved), VIREO_RESULT_NOT_FOUND);
    assert(!c);
    CHECK(vireo_completion_queue_destroy(&j->resources.queue), VIREO_OK);
    CHECK(vireo_notifier_destroy(&j->resources.notifier, NULL), VIREO_OK);
}
static vireo_directory_mkdir_worker_report_t bridge(vireo_mysql_node_actor_t actor,
                                                    const vireo_node_mkdir_request_t *req,
                                                    uint64_t deadline, bool cancel,
                                                    vireo_result_t rc,
                                                    vireo_directory_mkdir_outcome_t outcome,
                                                    vireo_status_t status) {
    unsigned char before[65536], after[65536];
    size_t n = snapshot(before);
    uint64_t nodes_before = scalar("SELECT COUNT(*) FROM file_nodes"),
             audits = scalar("SELECT COUNT(*) FROM operation_audits"),
             receipts = scalar("SELECT COUNT(*) FROM directory_write_receipts");
    job_t j = {0};
    setup_queue(&j, 1);
    prepare(&j, actor, req, deadline, cancel, cases + 1);
    pthread_t w;
    assert(!pthread_create(&w, NULL, run_worker, &j));
    vireo_directory_mkdir_completion_outcome_t out = receive(j.resources.queue);
    assert(!pthread_join(w, NULL));
    assert(j.rc == rc && out.metadata.result == rc && out.response.status == status &&
           out.actor.user_id == actor.user_id && out.actor.session_id == actor.session_id &&
           out.request_session_handle == 23 &&
           !memcmp(out.request_idempotency_key, req->idempotency_key, 16));
    assert(j.report.service.outcome == outcome && j.report.random_called &&
           j.report.random_result == VIREO_OK && j.report.clock_called && j.report.execute_called &&
           j.report.publication.publication.completion_transferred &&
           !j.report.publication_blocked_by_cleanup && !j.report.completion_pending &&
           !j.report.cleanup.repository_pending && !j.report.cleanup.thread_pending);
    const bool created = outcome == VIREO_DIRECTORY_MKDIR_CREATED;
    const bool success = created || outcome == VIREO_DIRECTORY_MKDIR_RECOVERED;
    assert(scalar("SELECT COUNT(*) FROM file_nodes") == nodes_before + (created ? 1u : 0u));
    assert(scalar("SELECT COUNT(*) FROM operation_audits") == audits + (created ? 1u : 0u));
    assert(scalar("SELECT COUNT(*) FROM directory_write_receipts") ==
           receipts + (created ? 1u : 0u));
    if (!created)
        assert(snapshot(after) == n && !memcmp(before, after, n));
    if (success) {
        assert(out.response.node_id == j.report.service.repository.node_id &&
               out.response.node_id &&
               !memcmp(out.response.idempotency_key, req->idempotency_key, 16));
        char sql[512];
        int z =
            snprintf(sql, sizeof(sql),
                     "SELECT COUNT(*) FROM operation_audits WHERE id=%llu AND target_id=%llu AND "
                     "action=5 AND status=0 AND request_id<>0x00000000000000000000000000000000",
                     (unsigned long long)j.report.service.repository.audit_id,
                     (unsigned long long)out.response.node_id);
        assert(z > 0 && (size_t)z < sizeof(sql));
        assert(scalar(sql) == 1);
    } else
        assert(!out.response.node_id && !out.response.session_handle);
    CHECK(vireo_task_destroy(&j.task), VIREO_OK);
    finish_queue(&j);
    ++cases;
    return j.report;
}
static void concurrent(vireo_mysql_node_actor_t actor, uint64_t root) {
    vireo_node_mkdir_request_t req = request(root, (const unsigned char *)"parallel", 8, 42);
    job_t j[2] = {0};
    setup_queue(&j[0], 2);
    j[1].resources = j[0].resources;
    prepare(&j[0], actor, &req, UINT64_MAX, false, 1001);
    prepare(&j[1], actor, &req, UINT64_MAX, false, 1002);
    uint64_t n = scalar("SELECT COUNT(*) FROM file_nodes"),
             a = scalar("SELECT COUNT(*) FROM operation_audits"),
             r = scalar("SELECT COUNT(*) FROM directory_write_receipts");
    pthread_t w[2];
    assert(!pthread_create(&w[0], NULL, run_worker, &j[0]));
    assert(!pthread_create(&w[1], NULL, run_worker, &j[1]));
    vireo_directory_mkdir_completion_outcome_t one = receive(j[0].resources.queue),
                                               two = receive(j[0].resources.queue);
    assert(!pthread_join(w[0], NULL) && !pthread_join(w[1], NULL));
    assert(j[0].rc == VIREO_OK && j[1].rc == VIREO_OK &&
           one.response.node_id == two.response.node_id && one.response.node_id);
    assert((j[0].report.service.outcome == VIREO_DIRECTORY_MKDIR_CREATED &&
            j[1].report.service.outcome == VIREO_DIRECTORY_MKDIR_RECOVERED) ||
           (j[1].report.service.outcome == VIREO_DIRECTORY_MKDIR_CREATED &&
            j[0].report.service.outcome == VIREO_DIRECTORY_MKDIR_RECOVERED));
    assert(scalar("SELECT COUNT(*) FROM file_nodes") == n + 1 &&
           scalar("SELECT COUNT(*) FROM operation_audits") == a + 1 &&
           scalar("SELECT COUNT(*) FROM directory_write_receipts") == r + 1);
    CHECK(vireo_task_destroy(&j[0].task), VIREO_OK);
    CHECK(vireo_task_destroy(&j[1].task), VIREO_OK);
    finish_queue(&j[0]);
    cases += 2;
}
static size_t fd_count(void) {
    DIR *d = opendir("/proc/self/fd");
    assert(d);
    size_t n = 0;
    while (readdir(d))
        ++n;
    assert(!closedir(d));
    return n;
}
int main(int argc, char **argv) {
    assert(argc == 5);
    char password[1026];
    FILE *f = fopen(argv[3], "r");
    assert(f && fgets(password, (int)sizeof(password), f) && !fclose(f));
    password[strcspn(password, "\n")] = 0;
    struct sigaction action = {0};
    action.sa_handler = SIG_IGN;
    assert(!sigemptyset(&action.sa_mask) && !sigaction(SIGPIPE, &action, NULL));
    int old = 0;
    assert(!pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &old));
    size_t fds = fd_count();
    CHECK(vireo_mysql_runtime_create(&runtime, NULL), VIREO_OK);
    CHECK(vireo_mysql_thread_attach(runtime, &thread, NULL), VIREO_OK);
    const vireo_mysql_connection_options_t options = {argv[1], argv[2], password, argv[4], 3, 3, 3};
    const vireo_mysql_migration_t *catalog = NULL;
    size_t count = 0;
    CHECK(vireo_mysql_schema_catalog(&catalog, &count), VIREO_OK);
    vireo_mysql_migration_report_t migration;
    CHECK(vireo_mysql_migration_apply(thread, &options, catalog, count, &migration, NULL),
          VIREO_OK);
    assert(migration.ready);
    CHECK(vireo_mysql_connection_open(thread, &options, &observer, NULL), VIREO_OK);
    const vireo_mysql_pool_options_t po = {options, 3, 3, VIREO_MYSQL_POOL_MEMORY_MAX};
    CHECK(vireo_mysql_pool_create(thread, &po, &pool, NULL), VIREO_OK);
    CHECK(vireo_mysql_user_repository_create(thread, pool, &policy, &users, NULL), VIREO_OK);
    CHECK(vireo_mysql_node_repository_create(thread, pool, &nodes, NULL), VIREO_OK);
    CHECK(vireo_password_hash_create(&policy, "Correct!7", 9, phc, sizeof(phc), &phc_length),
          VIREO_OK);
    issued_at = now_ms() - 10000;
    uint64_t ar, br;
    vireo_mysql_node_actor_t alice = account("alice_bridge", &ar), bob = account("bob_bridge", &br);
    vireo_node_mkdir_request_t req = request(ar, (const unsigned char *)"docs", 4, 1);
    vireo_directory_mkdir_worker_report_t first = bridge(
        alice, &req, UINT64_MAX, false, VIREO_OK, VIREO_DIRECTORY_MKDIR_CREATED, VIREO_STATUS_OK);
    vireo_directory_mkdir_worker_report_t recovered = bridge(
        alice, &req, UINT64_MAX, false, VIREO_OK, VIREO_DIRECTORY_MKDIR_RECOVERED, VIREO_STATUS_OK);
    assert(first.service.node_id == recovered.service.node_id &&
           first.service.repository.audit_id == recovered.service.repository.audit_id);
    vireo_node_mkdir_request_t other = req;
    other.idempotency_key[15] = 2;
    (void)bridge(alice, &other, UINT64_MAX, false, VIREO_RESULT_DATABASE,
                 VIREO_DIRECTORY_MKDIR_NAME_CONFLICT, VIREO_STATUS_CONFLICT);
    other = req;
    other.name[0] = 'D';
    (void)bridge(alice, &other, UINT64_MAX, false, VIREO_RESULT_DATABASE,
                 VIREO_DIRECTORY_MKDIR_IDEMPOTENCY_CONFLICT, VIREO_STATUS_CONFLICT);
    other = req;
    other.parent_id = br;
    (void)bridge(alice, &other, UINT64_MAX, false, VIREO_RESULT_DATABASE,
                 VIREO_DIRECTORY_MKDIR_IDEMPOTENCY_CONFLICT, VIREO_STATUS_CONFLICT);
    other.idempotency_key[15] = 3;
    (void)bridge(alice, &other, UINT64_MAX, false, VIREO_RESULT_NOT_FOUND,
                 VIREO_DIRECTORY_MKDIR_PARENT_NOT_FOUND, VIREO_STATUS_NOT_FOUND);
    vireo_mysql_node_actor_t mixed = {alice.user_id, bob.session_id};
    (void)bridge(mixed, &req, UINT64_MAX, false, VIREO_RESULT_NOT_FOUND,
                 VIREO_DIRECTORY_MKDIR_UNAUTHORIZED, VIREO_STATUS_UNAUTHORIZED);
    const unsigned char decomposed[] = {0x65, 0xcc, 0x81};
    other = request(ar, decomposed, sizeof(decomposed), 4);
    (void)bridge(alice, &other, UINT64_MAX, false, VIREO_RESULT_PROTOCOL,
                 VIREO_DIRECTORY_MKDIR_INVALID_NAME, VIREO_STATUS_INVALID_PATH);
    const unsigned char composed[] = {0xc3, 0xa9};
    other = request(ar, composed, sizeof(composed), 5);
    (void)bridge(alice, &other, UINT64_MAX, false, VIREO_OK, VIREO_DIRECTORY_MKDIR_CREATED,
                 VIREO_STATUS_OK);
    unsigned char maximum[255];
    memset(maximum, 'z', sizeof(maximum));
    other = request(ar, maximum, 255, 6);
    (void)bridge(alice, &other, UINT64_MAX, false, VIREO_OK, VIREO_DIRECTORY_MKDIR_CREATED,
                 VIREO_STATUS_OK);
    other = req;
    other.parent_id = br;
    (void)bridge(bob, &other, UINT64_MAX, false, VIREO_OK, VIREO_DIRECTORY_MKDIR_CREATED,
                 VIREO_STATUS_OK);
    other = request(ar, (const unsigned char *)"parent", 6, 7);
    vireo_directory_mkdir_worker_report_t parent = bridge(
        alice, &other, UINT64_MAX, false, VIREO_OK, VIREO_DIRECTORY_MKDIR_CREATED, VIREO_STATUS_OK);
    vireo_mysql_node_move_input_t move = {.node_id = first.service.node_id,
                                          .new_parent_id = parent.service.node_id,
                                          .name = (const unsigned char *)"moved",
                                          .name_length = 5,
                                          .request_id = {0x33}};
    vireo_mysql_node_move_report_t moved;
    CHECK(vireo_mysql_node_repository_move(nodes, &alice, &move, 0, &moved, NULL), VIREO_OK);
    assert(moved.changed);
    recovered = bridge(alice, &req, UINT64_MAX, false, VIREO_OK, VIREO_DIRECTORY_MKDIR_RECOVERED,
                       VIREO_STATUS_OK);
    assert(recovered.service.node_id == first.service.node_id);
    vireo_mysql_node_soft_delete_input_t del = {.node_id = first.service.node_id,
                                                .request_id = {0x34}};
    vireo_mysql_node_soft_delete_report_t deleted;
    CHECK(vireo_mysql_node_repository_soft_delete(nodes, &alice, &del, 0, &deleted, NULL),
          VIREO_OK);
    recovered = bridge(alice, &req, UINT64_MAX, false, VIREO_OK, VIREO_DIRECTORY_MKDIR_RECOVERED,
                       VIREO_STATUS_OK);
    assert(recovered.service.node_id == first.service.node_id &&
           recovered.service.repository.audit_id == first.service.repository.audit_id);
    other = req;
    other.idempotency_key[15] = 2;
    (void)bridge(alice, &other, UINT64_MAX, false, VIREO_OK, VIREO_DIRECTORY_MKDIR_CREATED,
                 VIREO_STATUS_OK);
    concurrent(alice, ar);
    vireo_mysql_login_input_t login = {.user_id = alice.user_id,
                                       .verified_password_hash = phc,
                                       .verified_password_hash_length = phc_length,
                                       .issued_at_ms = issued_at,
                                       .expires_at_ms = issued_at + 3600000,
                                       .request_id = {0x55},
                                       .token_digest = {.bytes = {0x77}}};
    vireo_mysql_login_report_t logged;
    CHECK(vireo_mysql_user_repository_login(users, &login, 0, &logged, NULL), VIREO_OK);
    char sql[256];
    int z =
        snprintf(sql, sizeof(sql), "UPDATE sessions SET status=2,revoked_at_ms=%llu WHERE id=%llu",
                 (unsigned long long)now_ms(), (unsigned long long)alice.session_id);
    assert(z > 0 && (size_t)z < sizeof(sql));
    mutate(sql);
    (void)bridge(alice, &req, UINT64_MAX, false, VIREO_RESULT_NOT_FOUND,
                 VIREO_DIRECTORY_MKDIR_UNAUTHORIZED, VIREO_STATUS_UNAUTHORIZED);
    vireo_mysql_node_actor_t renewed = {alice.user_id, logged.session_id};
    recovered = bridge(renewed, &req, UINT64_MAX, false, VIREO_OK, VIREO_DIRECTORY_MKDIR_RECOVERED,
                       VIREO_STATUS_OK);
    assert(recovered.service.node_id == first.service.node_id);
    (void)bridge(alice, &req, 0, true, VIREO_RESULT_CANCELLED, VIREO_DIRECTORY_MKDIR_NONE,
                 VIREO_STATUS_UNAVAILABLE);
    (void)bridge(alice, &req, 0, false, VIREO_RESULT_TIMEOUT, VIREO_DIRECTORY_MKDIR_NONE,
                 VIREO_STATUS_TIMEOUT);
    vireo_mysql_pool_info_t info;
    CHECK(vireo_mysql_pool_inspect(pool, &info), VIREO_OK);
    assert(!info.leased && !info.returning && info.idle == 3);
    CHECK(vireo_mysql_node_repository_destroy(&nodes, NULL), VIREO_OK);
    CHECK(vireo_mysql_user_repository_destroy(&users, NULL), VIREO_OK);
    bool closed = false;
    CHECK(vireo_mysql_pool_close(pool, &closed, NULL), VIREO_OK);
    assert(closed);
    CHECK(vireo_mysql_pool_destroy(thread, &pool, NULL), VIREO_OK);
    CHECK(vireo_mysql_connection_destroy(thread, &observer), VIREO_OK);
    CHECK(vireo_mysql_thread_detach(&thread), VIREO_OK);
    CHECK(vireo_mysql_runtime_destroy(&runtime), VIREO_OK);
    assert(fd_count() == fds);
    memset(password, 0, sizeof(password));
    memset(phc, 0, sizeof(phc));
    printf(
        "PASS %zu real MKDIR bridge observations; native random/clock, six-table snapshots, "
        "recovery/conflicts, two workers, move/delete and renewed session; FD %zu->%zu\n",
        cases, fds, fd_count());
    return 0;
}
