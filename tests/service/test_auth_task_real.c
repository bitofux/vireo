/* PROJECT : VIREO
 * FILE : test_auth_task_real.c
 * AUTHOR : bitofux
 * DATE : 2026-10-20
 * BRIEF : 真实线程池执行完整认证task并核对持久Session和审计可信字段。
 */
#define _POSIX_C_SOURCE 200809L
#include "auth_task_test_support.h"
#include <vireo/persistence/mysql_schema.h>
#include <vireo/persistence/mysql_statement.h>
#include <vireo/thread/thread_pool.h>
#include <dirent.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <time.h>

static void sql(vireo_mysql_thread_t *thread, vireo_mysql_connection_t *connection,
    const char *text, const char *expected)
{
    const vireo_mysql_statement_limits_t limits={0,1,0,64,8192};
    vireo_mysql_statement_t *s=NULL; vireo_mysql_execution_t ex;
    CHECK(vireo_mysql_statement_prepare(thread,connection,text,strlen(text),&limits,&s,NULL),VIREO_OK);
    CHECK(vireo_mysql_statement_execute(thread,s,NULL,0,&ex,NULL),VIREO_OK);
    if (expected!=NULL) {
        vireo_mysql_fetch_outcome_t fetched; vireo_mysql_cell_view_t cell;
        CHECK(vireo_mysql_statement_fetch(thread,s,&fetched,NULL),VIREO_OK); assert(fetched==VIREO_MYSQL_FETCH_ROW);
        CHECK(vireo_mysql_statement_column(thread,s,0,&cell),VIREO_OK);
        assert(!cell.is_null && cell.length==strlen(expected) && !memcmp(cell.data,expected,cell.length));
        CHECK(vireo_mysql_statement_fetch(thread,s,&fetched,NULL),VIREO_OK); assert(fetched==VIREO_MYSQL_FETCH_DONE);
    } else { assert(!ex.has_result); }
    CHECK(vireo_mysql_statement_destroy(thread,&s,NULL),VIREO_OK);
}

typedef struct worker_context {
    pthread_t manager;
    vireo_mysql_runtime_t *runtime;
    vireo_mysql_pool_t *pool;
    vireo_auth_password_gate_t *gate;
    vireo_auth_login_verifier_t const *verifier;
    vireo_auth_task_context_t trusted[4];
    vireo_auth_task_result_t results[4];
    unsigned completed[4];
} worker_context_t;
static vireo_auth_task_options_t const execution_options = {100, 101, 5000,102,103};

/** 每个callback在本OS线程独立attach/create/destroy，结果写不同槽，join发布给manager。 */
static vireo_result_t execute(void *context, vireo_task_t const *task)
{
    worker_context_t *f = context; assert(!pthread_equal(f->manager, pthread_self()));
    vireo_task_info_t info; CHECK(vireo_task_inspect(task, &info), VIREO_OK);
    assert(info.metadata.request_instance_id >= 1 && info.metadata.request_instance_id <= 4);
    size_t i = (size_t)(info.metadata.request_instance_id - 1);
    vireo_mysql_thread_t *thread = NULL; vireo_mysql_user_repository_t *repo = NULL;
    vireo_password_policy_t const policy = VIREO_PASSWORD_POLICY_DEFAULT;
    CHECK(vireo_mysql_thread_attach(f->runtime, &thread, NULL), VIREO_OK);
    CHECK(vireo_mysql_user_repository_create(thread, f->pool, &policy, &repo, NULL), VIREO_OK);
    vireo_result_t const expected = i == 2 ? VIREO_RESULT_NOT_FOUND : i == 3 ? VIREO_RESULT_TIMEOUT : VIREO_OK;
    CHECK(vireo_auth_task_execute(task, &f->trusted[i], &execution_options, repo, f->gate, f->verifier, &f->results[i]), expected);
    assert(!f->results[i].registration.cleanup_pending && !f->results[i].login.lookup.cleanup_pending &&
        !f->results[i].login.transaction.cleanup_pending);
    ++f->completed[i];
    CHECK(vireo_mysql_user_repository_destroy(&repo, NULL), VIREO_OK);
    CHECK(vireo_mysql_thread_detach(&thread), VIREO_OK);
    /* 预期业务结果已独立保存且资源收尾成功，callback本身执行成功。 */
    return VIREO_OK;
}

/** 仅测试manager有界等待公开队列的瞬时竞争，不重新执行认证业务。 */
static void contention_pause(struct timespec const *start)
{
    assert(sched_yield() == 0);
    struct timespec now;
    assert(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
    assert(now.tv_sec - start->tv_sec < 5);
}

/** 以公开try_submit发布完整wire副本；原缓冲立即擦除，pool负责callback后task销毁。 */
static void run(worker_context_t *f, size_t start, size_t count, size_t worker_count)
{
    vireo_task_queue_t *queue = NULL; vireo_thread_pool_t *pool = NULL;
    vireo_task_queue_options_t const qo = {4, 65536};
    vireo_thread_pool_options_t const po = {worker_count, 65536};
    CHECK(vireo_task_queue_create(&qo, &queue), VIREO_OK);
    CHECK(vireo_task_queue_prepare_wait(queue), VIREO_OK);
    CHECK(vireo_thread_pool_create(&po, &pool), VIREO_OK);
    vireo_thread_pool_configuration_t const config = {queue, execute, f};
    CHECK(vireo_thread_pool_configure(pool, &config, NULL), VIREO_OK);
    vireo_thread_pool_report_t report;
    CHECK(vireo_thread_pool_start(pool, &report), VIREO_OK);
    CHECK(vireo_thread_pool_enable_execution(pool, &report), VIREO_OK);
    for (size_t i = start; i < start + count; ++i) {
        unsigned char wire[156]; size_t n = frame(wire, i != 0, (uint32_t)(7 + i), i == 2);
        vireo_task_t *task = NULL;
        CHECK(vireo_task_create_copy(f->trusted[i].metadata, wire, n, 4096, &task), VIREO_OK);
        CHECK(vireo_secure_clear(wire, sizeof(wire)), VIREO_OK);
        vireo_thread_pool_submit_report_t submitted;
        struct timespec start_time;
        assert(clock_gettime(CLOCK_MONOTONIC, &start_time) == 0);
        for (;;) {
            errno = EDOM;
            vireo_result_t const rc = vireo_thread_pool_try_submit(pool, &task, &submitted);
            assert(errno == EDOM);
            if (submitted.queue_report.transferred) {
                assert(rc == VIREO_OK && task == NULL);
                break;
            }
            /* 未交接才可重试同一owner；满队列或其他失败仍是测试错误。 */
            assert(rc == VIREO_RESULT_BUSY && task != NULL && submitted.queue_called &&
                submitted.stage == VIREO_THREAD_POOL_SUBMIT_STAGE_SUBMIT_QUEUE &&
                submitted.queue_report.stage == VIREO_TASK_QUEUE_STAGE_LOCK &&
                submitted.queue_report.pthread_error == EBUSY);
            contention_pause(&start_time);
        }
    }
    vireo_thread_pool_shutdown_report_t shutdown;
    struct timespec start_time;
    assert(clock_gettime(CLOCK_MONOTONIC, &start_time) == 0);
    for (;;) {
        errno = EDOM;
        vireo_result_t const rc = vireo_thread_pool_shutdown_and_join(pool, VIREO_TASK_QUEUE_DRAIN, &shutdown);
        assert(errno == EDOM);
        if (rc == VIREO_OK) break;
        /* 只恢复关闭/回收资格观察的竞争，不重试pthread join或worker错误。 */
        assert(rc == VIREO_RESULT_BUSY &&
            ((shutdown.stage == VIREO_THREAD_POOL_SHUTDOWN_STAGE_CLOSE_QUEUE && !shutdown.join_called &&
              shutdown.close_report.stage == VIREO_TASK_QUEUE_STAGE_LOCK &&
              shutdown.close_report.pthread_error == EBUSY) ||
             (shutdown.stage == VIREO_THREAD_POOL_SHUTDOWN_STAGE_JOIN_WORKERS &&
              shutdown.pool_report.stage == VIREO_THREAD_POOL_STAGE_CHECK_QUEUE)));
        contention_pause(&start_time);
    }
    assert(shutdown.pool_report.joined_count == worker_count);
    for (size_t i = start; i < start + count; ++i) assert(f->completed[i] == 1);
    CHECK(vireo_thread_pool_destroy(&pool), VIREO_OK);
    CHECK(vireo_task_queue_destroy(&queue), VIREO_OK);
}
static size_t fd_count(void)
{
    DIR *dir = opendir("/proc/self/fd"); assert(dir); size_t n = 0;
    while (readdir(dir) != NULL) ++n;
    assert(closedir(dir) == 0); return n;
}
int main(int argc, char **argv)
{
    assert(argc == 5); char password[1026]; FILE *file = fopen(argv[3], "r");
    assert(file && fgets(password, (int)sizeof(password), file) != NULL && fclose(file) == 0);
    password[strcspn(password, "\n")] = 0;
    struct sigaction action = {0}; action.sa_handler = SIG_IGN;
    assert(sigemptyset(&action.sa_mask) == 0 && sigaction(SIGPIPE, &action, NULL) == 0);
    size_t before = fd_count();
    vireo_mysql_runtime_t *runtime = NULL; vireo_mysql_thread_t *thread = NULL;
    CHECK(vireo_mysql_runtime_create(&runtime, NULL), VIREO_OK);
    CHECK(vireo_mysql_thread_attach(runtime, &thread, NULL), VIREO_OK);
    vireo_mysql_connection_options_t const options = {argv[1], argv[2], password, argv[4], 3, 3, 3};
    vireo_mysql_migration_t const *catalog = NULL; size_t count = 0;
    CHECK(vireo_mysql_schema_catalog(&catalog, &count), VIREO_OK);
    vireo_mysql_migration_report_t migrated;
    CHECK(vireo_mysql_migration_apply(thread, &options, catalog, count, &migrated, NULL), VIREO_OK);
    assert(migrated.ready && migrated.steps_completed == 15);
    vireo_mysql_connection_t *observer = NULL;
    CHECK(vireo_mysql_connection_open(thread, &options, &observer, NULL), VIREO_OK);
    vireo_mysql_pool_options_t const po = {options, 2, 2, VIREO_MYSQL_POOL_MEMORY_MAX};
    vireo_mysql_pool_t *pool = NULL; CHECK(vireo_mysql_pool_create(thread, &po, &pool, NULL), VIREO_OK);
    vireo_auth_password_gate_options_t const go = VIREO_AUTH_PASSWORD_GATE_OPTIONS_DEFAULT;
    vireo_auth_password_gate_t *gate = NULL; vireo_auth_login_verifier_t *verifier = NULL;
    CHECK(vireo_auth_password_gate_create(&go, &gate), VIREO_OK);
    CHECK(vireo_auth_login_verifier_create(gate, &verifier), VIREO_OK);
    worker_context_t f = {.manager = pthread_self(), .runtime = runtime, .pool = pool, .gate = gate, .verifier = verifier};
    for (size_t i = 0; i < 4; ++i) f.trusted[i] = task_context((uint32_t)(7 + i), i + 1, i != 0);
    f.trusted[3].now_ns = 100;
    run(&f, 0, 1, 1); run(&f, 1, 3, 2);
    assert(f.results[0].stage == VIREO_AUTH_TASK_SERVICE &&
        f.results[0].registration.commit == VIREO_MYSQL_REGISTRATION_COMMITTED);
    assert(f.results[1].stage == VIREO_AUTH_TASK_SERVICE &&
        f.results[1].login.transaction.commit == VIREO_MYSQL_LOGIN_COMMITTED);
    assert(f.results[2].stage == VIREO_AUTH_TASK_SERVICE && f.results[2].login.user_id == 0);
    assert(f.results[3].stage == VIREO_AUTH_TASK_DEADLINE && f.results[3].login.user_id == 0);
    /* 从worker拥有型输出计算摘要，核对真实session；输出在task销毁后仍独立有效。 */
    vireo_mysql_user_repository_t *repo = NULL;
    vireo_password_policy_t const policy = VIREO_PASSWORD_POLICY_DEFAULT;
    CHECK(vireo_mysql_user_repository_create(thread, pool, &policy, &repo, NULL), VIREO_OK);
    vireo_session_token_digest_t digest;
    CHECK(vireo_session_token_digest(&f.results[1].login.token, &digest), VIREO_OK);
    vireo_mysql_session_identity_t identity; vireo_mysql_session_report_t found;
    CHECK(vireo_mysql_user_repository_find_session(repo, &digest, 2000, 5000, &identity, &found, NULL), VIREO_OK);
    assert(identity.user_id == f.results[0].registration.user_id && identity.user_id == f.results[1].login.user_id &&
        identity.session_id == f.results[1].login.transaction.session_id);
    CHECK(vireo_mysql_user_repository_find_session(repo, &digest, 5000, 5000, &identity, &found, NULL), VIREO_RESULT_NOT_FOUND);
    sql(thread, observer, "SELECT COUNT(*) FROM users", "1");
    sql(thread, observer, "SELECT COUNT(*) FROM file_nodes", "1");
    sql(thread, observer, "SELECT COUNT(*) FROM sessions", "1");
    sql(thread, observer, "SELECT COUNT(*) FROM operation_audits", "2");
    sql(thread, observer, "SELECT latency_us FROM operation_audits WHERE action=2", "13");
    sql(thread, observer, "SELECT occurred_at_ms FROM operation_audits WHERE action=1", "1000");
    sql(thread, observer, "SELECT occurred_at_ms FROM operation_audits WHERE action=2", "2000");
    sql(thread, observer, "SELECT COUNT(*) FROM operation_audits WHERE action=2 AND request_id=X'01000000000000000000000000000002'", "1");
    sql(thread, observer, "SELECT issued_at_ms FROM sessions", "2000");
    sql(thread, observer, "SELECT expires_at_ms FROM sessions", "5000");
    CHECK(vireo_secure_clear(&digest, sizeof(digest)), VIREO_OK);
    for (size_t i = 0; i < 4; ++i) CHECK(vireo_auth_task_result_clear(&f.results[i]), VIREO_OK);
    CHECK(vireo_mysql_user_repository_destroy(&repo, NULL), VIREO_OK);
    CHECK(vireo_auth_login_verifier_destroy(&verifier), VIREO_OK);
    CHECK(vireo_auth_password_gate_close(gate), VIREO_OK);
    CHECK(vireo_auth_password_gate_destroy(&gate), VIREO_OK);
    bool closed = false; CHECK(vireo_mysql_pool_close(pool, &closed, NULL), VIREO_OK); assert(closed);
    CHECK(vireo_mysql_pool_destroy(thread, &pool, NULL), VIREO_OK);
    CHECK(vireo_mysql_connection_destroy(thread, &observer), VIREO_OK);
    CHECK(vireo_mysql_thread_detach(&thread), VIREO_OK);
    CHECK(vireo_mysql_runtime_destroy(&runtime), VIREO_OK);
    CHECK(vireo_secure_clear(password, sizeof(password)), VIREO_OK);
    assert(fd_count() == before);
    printf("PASS real auth_task: 4 complete-frame tasks, register/login/wrong-password/deadline, 3 OS workers, persistent session/audits, FD %zu->%zu\n", before, fd_count());
    return 0;
}
