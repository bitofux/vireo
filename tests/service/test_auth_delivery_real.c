/* PROJECT : VIREO
 * FILE : test_auth_delivery_real.c
 * AUTHOR : bitofux
 * DATE : 2026-10-20
 * BRIEF : 真实采样、worker执行、专用completion回投并核对持久Session/审计。
 */
#define _POSIX_C_SOURCE 200809L
#include "auth_task_test_support.h"
#include <vireo/service/auth_task_context.h>
#include <vireo/service/auth_task.h>
static vireo_auth_task_options_t const context_registry={100,101,5000,102,103};
#include <vireo/service/auth_completion.h>
#include <vireo/persistence/mysql_schema.h>
#include <vireo/persistence/mysql_statement.h>
#include <vireo/thread/thread_pool.h>
#include <dirent.h>
#include <pthread.h>
#include <signal.h>

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
    vireo_auth_completion_outcome_t results[4];
    vireo_monotonic_ns_t received[4];
    vireo_completion_queue_t *completions;
    vireo_notifier_t *notifier;
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
    CHECK(vireo_auth_task_context_capture(task, f->received[i], 60000, &context_registry, &f->trusted[i], NULL), VIREO_OK);
    vireo_auth_task_result_t result = {0};
    vireo_result_t const expected = i == 2 ? VIREO_RESULT_NOT_FOUND : i == 3 ? VIREO_RESULT_TIMEOUT : VIREO_OK;
    CHECK(vireo_auth_task_execute(task, &f->trusted[i], &execution_options, repo, f->gate, f->verifier, &result), expected);
    assert(!result.registration.cleanup_pending && !result.login.lookup.cleanup_pending &&
        !result.login.transaction.cleanup_pending);
    vireo_completion_t *remaining = NULL; vireo_auth_completion_publish_report_t publication;
    CHECK(vireo_auth_completion_publish(task, &result, 4096, f->completions, f->notifier,
        &remaining, &publication), VIREO_OK);
    assert(!remaining && publication.publication.completion_transferred && publication.publication.notify_called);
    CHECK(vireo_auth_task_result_clear(&result), VIREO_OK);
    ++f->completed[i];
    CHECK(vireo_mysql_user_repository_destroy(&repo, NULL), VIREO_OK);
    CHECK(vireo_mysql_thread_detach(&thread), VIREO_OK);
    /* 预期业务结果已独立保存且资源收尾成功，callback本身执行成功。 */
    return VIREO_OK;
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
        CHECK(vireo_clock_monotonic_now(&f->received[i], NULL), VIREO_OK);
        vireo_thread_pool_submit_report_t submitted;
        CHECK(vireo_thread_pool_try_submit(pool, &task, &submitted), VIREO_OK); assert(task == NULL);
    }
    vireo_thread_pool_shutdown_report_t shutdown;
    CHECK(vireo_thread_pool_shutdown_and_join(pool, VIREO_TASK_QUEUE_DRAIN, &shutdown), VIREO_OK);
    assert(shutdown.pool_report.joined_count == worker_count);
    for (size_t i = start; i < start + count; ++i) assert(f->completed[i] == 1);
    /* 本测试容量>=本wave任务数，join前无producer因满表等待；生产consumer须并行腾空间。 */
    for (size_t n = 0; n < count; ++n) {
        vireo_completion_t *completion = NULL; vireo_completion_queue_transfer_report_t transfer;
        CHECK(vireo_completion_queue_try_pop(f->completions, &completion, &transfer), VIREO_OK);
        vireo_auth_completion_outcome_t output = {0};
        CHECK(vireo_auth_completion_decode(completion, &output), VIREO_OK);
        size_t i = (size_t)(output.metadata.request.request_instance_id - 1);
        assert(i >= start && i < start + count && f->results[i].command == 0);
        f->results[i] = output;
        CHECK(vireo_auth_completion_outcome_clear(&output), VIREO_OK);
        CHECK(vireo_completion_destroy(&completion), VIREO_OK);
    }
    uint64_t hints = 0; CHECK(vireo_notifier_consume(f->notifier, &hints, NULL), VIREO_OK); assert(hints > 0);
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
    int previous_cancel = 0; assert(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previous_cancel) == 0);
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
    assert(migrated.ready && migrated.steps_completed == 14);
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
    for (size_t i = 0; i < 4; ++i) f.trusted[i].metadata.deadline_ns = i == 3 ? 0 : UINT64_MAX;
    vireo_completion_queue_options_t const cqo = {4, 65536};
    vireo_notifier_options_t const no = {4096};
    CHECK(vireo_completion_queue_create(&cqo, &f.completions), VIREO_OK);
    CHECK(vireo_completion_queue_prepare_wait(f.completions), VIREO_OK);
    CHECK(vireo_notifier_create(&no, &f.notifier, NULL), VIREO_OK);
    run(&f, 0, 1, 1); run(&f, 1, 3, 2);
    assert(f.results[0].commit == VIREO_AUTH_COMMITTED && f.results[0].command == VIREO_COMMAND_REGISTER);
    assert(f.results[1].commit == VIREO_AUTH_COMMITTED && f.results[1].command == VIREO_COMMAND_LOGIN);
    assert(f.results[2].commit == VIREO_AUTH_NOT_COMMITTED && f.results[2].metadata.suggested_status == VIREO_STATUS_AUTHENTICATION_FAILED);
    assert(f.results[3].commit == VIREO_AUTH_NOT_COMMITTED && f.results[3].metadata.suggested_status == VIREO_STATUS_TIMEOUT);
    for (size_t i = 0; i < 4; ++i) {
        assert(f.trusted[i].now_ns >= f.received[i] && f.trusted[i].latency_us == (f.trusted[i].now_ns - f.received[i]) / 1000);
        assert(f.trusted[i].occurred_at_ms > 0);
        for (size_t j = 0; j < i; ++j) assert(memcmp(f.trusted[i].request_id, f.trusted[j].request_id, 16) != 0);
    }
    /* 从worker拥有型输出计算摘要，核对真实session；输出在task销毁后仍独立有效。 */
    vireo_mysql_user_repository_t *repo = NULL;
    vireo_password_policy_t const policy = VIREO_PASSWORD_POLICY_DEFAULT;
    CHECK(vireo_mysql_user_repository_create(thread, pool, &policy, &repo, NULL), VIREO_OK);
    vireo_session_token_digest_t digest;
    CHECK(vireo_session_token_digest(&f.results[1].token, &digest), VIREO_OK);
    vireo_mysql_session_identity_t identity; vireo_mysql_session_report_t found;
    CHECK(vireo_mysql_user_repository_find_session(repo, &digest, f.results[1].issued_at_ms, 5000, &identity, &found, NULL), VIREO_OK);
    assert(identity.user_id == f.results[0].user_id && identity.user_id == f.results[1].user_id &&
        identity.session_id == f.results[1].session_id);
    CHECK(vireo_mysql_user_repository_find_session(repo, &digest, f.results[1].expires_at_ms, 5000, &identity, &found, NULL), VIREO_RESULT_NOT_FOUND);
    sql(thread, observer, "SELECT COUNT(*) FROM users", "1");
    sql(thread, observer, "SELECT COUNT(*) FROM file_nodes", "1");
    sql(thread, observer, "SELECT COUNT(*) FROM sessions", "1");
    sql(thread, observer, "SELECT COUNT(*) FROM operation_audits", "2");
    /* 由真实采样值构造无秘密查询，核对UTC/延迟/ID进入同一事务审计。 */
    for (size_t i = 0; i < 2; ++i) {
        char query[512], expected[32], request_hex[33];
        for (size_t j = 0; j < 16; ++j) assert(snprintf(request_hex + j * 2, 3, "%02x", (unsigned)f.trusted[i].request_id[j]) == 2);
        int n = snprintf(query, sizeof(query), "SELECT COUNT(*) FROM operation_audits WHERE action=%u AND latency_us=%llu AND occurred_at_ms=%llu AND request_id=X'%s'",
            (unsigned)i + 1, (unsigned long long)f.trusted[i].latency_us, (unsigned long long)f.trusted[i].occurred_at_ms, request_hex);
        assert(n > 0 && (size_t)n < sizeof(query)); sql(thread, observer, query, "1");
        if (i == 1) {
            assert(f.results[i].issued_at_ms == f.trusted[i].occurred_at_ms &&
                f.results[i].expires_at_ms - f.results[i].issued_at_ms == 60000);
            n = snprintf(expected, sizeof(expected), "%llu", (unsigned long long)f.results[i].issued_at_ms);
            assert(n > 0 && (size_t)n < sizeof(expected)); sql(thread, observer, "SELECT issued_at_ms FROM sessions", expected);
            n = snprintf(expected, sizeof(expected), "%llu", (unsigned long long)f.results[i].expires_at_ms);
            assert(n > 0 && (size_t)n < sizeof(expected)); sql(thread, observer, "SELECT expires_at_ms FROM sessions", expected);
        }
    }
    CHECK(vireo_secure_clear(&digest, sizeof(digest)), VIREO_OK);
    for (size_t i = 0; i < 4; ++i) CHECK(vireo_auth_completion_outcome_clear(&f.results[i]), VIREO_OK);
    CHECK(vireo_completion_queue_destroy(&f.completions), VIREO_OK);
    CHECK(vireo_notifier_destroy(&f.notifier, NULL), VIREO_OK);
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
    printf("PASS real auth_delivery: 4 native contexts, register/login/wrong-password/deadline, 3 OS workers, VAC1 queue/decode, persistent session/audits, FD %zu->%zu\n", before, fd_count());
    assert(pthread_setcancelstate(previous_cancel, NULL) == 0);
    return 0;
}
