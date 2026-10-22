/* PROJECT : VIREO; FILE : test_directory_stat_worker_real.c; AUTHOR : bitofux;
 * DATE : 2026-10-22; BRIEF : 公开service/仓库API、原生UTC、真实授权及只读快照。 */
#define _POSIX_C_SOURCE 200809L
#include <vireo/service/directory_stat_worker.h>
#include <pthread.h>
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

/* 提交端持task；独立OS线程创建/运行/销毁worker，最后才结束task借用。 */
typedef struct job {
    vireo_directory_stat_worker_resources_t resources;
    vireo_task_t *task;
    vireo_result_t rc;
    vireo_directory_stat_worker_report_t report;
} job_t;
static void *run_worker(void *context)
{
    job_t *job=context;int old_state=0;
    assert(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,&old_state)==0);
    const vireo_directory_stat_worker_options_t o={.execution={400,1000},.completion_allocation_budget=4096,.max_memory_bytes=65536};
    vireo_directory_stat_worker_t *w=NULL;
    CHECK(vireo_directory_stat_worker_create(&job->resources,&o,&w),VIREO_OK);
    errno=EDOM;job->rc=vireo_directory_stat_worker_run(w,job->task,&job->report);assert(errno==EDOM);
    vireo_directory_stat_worker_cleanup_report_t cleanup;
    CHECK(vireo_directory_stat_worker_destroy(&w,&cleanup),VIREO_OK);assert(!w);
    assert(pthread_setcancelstate(old_state,NULL)==0);return NULL;
}
static vireo_directory_stat_completion_outcome_t bridge(vireo_mysql_node_actor_t actor,uint64_t id,uint64_t deadline,bool cancel)
{
    unsigned char before[65536],after[65536];const size_t length=snapshot(before);
    const vireo_completion_queue_options_t qo={1,65536};const vireo_notifier_options_t no={4096};
    job_t job={.resources={.runtime=runtime,.database=pool}};
    CHECK(vireo_completion_queue_create(&qo,&job.resources.queue),VIREO_OK);
    CHECK(vireo_completion_queue_prepare_wait(job.resources.queue),VIREO_OK);
    CHECK(vireo_notifier_create(&no,&job.resources.notifier,NULL),VIREO_OK);
    const vireo_task_metadata_t m={.route={1,0,3,7},.request_instance_id=cases+1,.operation=400,.deadline_ns=deadline};
    unsigned char wire[44];size_t size=0;const vireo_node_stat_request_t request={7,23,id};
    CHECK(vireo_node_stat_request_encode(&request,wire,sizeof(wire),&size),VIREO_OK);
    vireo_task_cancel_t *c=NULL;
    if(cancel){CHECK(vireo_task_cancel_create(4096,&c),VIREO_OK);CHECK(vireo_task_cancel_request(c),VIREO_OK);}
    CHECK(vireo_directory_stat_task_create(m,400,wire,size,&actor,4096,c,&job.task),VIREO_OK);
    CHECK(vireo_task_cancel_destroy(&c),VIREO_OK);memset(wire,0,sizeof(wire));
    pthread_t worker;assert(pthread_create(&worker,NULL,run_worker,&job)==0);
    assert(pthread_join(worker,NULL)==0);
    assert(job.report.task_validated && job.report.publish_called && job.report.publication.publication.completion_transferred &&
        !job.report.publication_blocked_by_cleanup && !job.report.completion_pending && !job.report.cleanup.repository_pending && !job.report.cleanup.thread_pending);
    if(cancel || !deadline)assert(job.report.work_stage==(cancel?VIREO_DIRECTORY_STAT_TASK_CANCEL:VIREO_DIRECTORY_STAT_TASK_DEADLINE) && job.report.outcome==VIREO_DIRECTORY_STAT_NONE);
    else assert(job.report.work_stage==VIREO_DIRECTORY_STAT_TASK_SERVICE && job.report.repository.rollback_confirmed && !job.report.repository.cleanup_pending);
    CHECK(vireo_task_destroy(&job.task),VIREO_OK);
    vireo_completion_t *completion=NULL;vireo_completion_queue_transfer_report_t transferred;
    CHECK(vireo_completion_queue_try_pop(job.resources.queue,&completion,&transferred),VIREO_OK);assert(transferred.transferred);
    vireo_directory_stat_completion_outcome_t out;
    CHECK(vireo_directory_stat_completion_decode(completion,400,&out),VIREO_OK);
    assert(out.actor.user_id==actor.user_id && out.actor.session_id==actor.session_id && out.requested_node_id==id &&
        out.request_session_handle==23 && out.response.sequence==7 && out.metadata.result==job.rc);
    CHECK(vireo_completion_destroy(&completion),VIREO_OK);
    CHECK(vireo_completion_queue_try_pop(job.resources.queue,&completion,&transferred),VIREO_RESULT_NOT_FOUND);
    CHECK(vireo_completion_queue_destroy(&job.resources.queue),VIREO_OK);
    CHECK(vireo_notifier_destroy(&job.resources.notifier,NULL),VIREO_OK);
    assert(snapshot(after)==length && !memcmp(before,after,length));
    memset(before,0,sizeof(before));memset(after,0,sizeof(after));++cases;return out;
}
static vireo_node_stat_response_t stat_node(vireo_mysql_node_actor_t actor,uint64_t id,vireo_directory_stat_outcome_t want)
{
    const vireo_directory_stat_completion_outcome_t out=bridge(actor,id,UINT64_MAX,false);
    assert(out.response.status==(want==VIREO_DIRECTORY_STAT_FOUND?VIREO_STATUS_OK:
        want==VIREO_DIRECTORY_STAT_UNAUTHORIZED?VIREO_STATUS_UNAUTHORIZED:VIREO_STATUS_NOT_FOUND));
    if(want==VIREO_DIRECTORY_STAT_FOUND)assert(out.response.metadata.node_id==id && out.response.session_handle==23);
    else {assert(!out.response.session_handle && !out.response.metadata.node_id && !out.response.metadata.type && !out.response.metadata.name_length);
        zeroed(out.response.metadata.name,sizeof(out.response.metadata.name));zeroed(out.response.metadata.object_hash,sizeof(out.response.metadata.object_hash));}
    return out.response;
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
    size_t fds = fd_count(); runtime = NULL;
    CHECK(vireo_mysql_runtime_create(&runtime, NULL), VIREO_OK);
    CHECK(vireo_mysql_thread_attach(runtime, &thread, NULL), VIREO_OK);
    vireo_mysql_connection_options_t options = {argv[1], argv[2], db_password, argv[4], 3, 3, 3};
    const vireo_mysql_migration_t *catalog = NULL; size_t count = 0;
    CHECK(vireo_mysql_schema_catalog(&catalog, &count), VIREO_OK); vireo_mysql_migration_report_t migration;
    CHECK(vireo_mysql_migration_apply(thread, &options, catalog, count, &migration, NULL), VIREO_OK);
    assert(migration.ready && migration.steps_completed == 14);
    CHECK(vireo_mysql_connection_open(thread, &options, &observer, NULL), VIREO_OK);
    pool = NULL;
    const vireo_mysql_pool_options_t pool_options = {options, 1, 1, VIREO_MYSQL_POOL_MEMORY_MAX};
    CHECK(vireo_mysql_pool_create(thread, &pool_options, &pool, NULL), VIREO_OK);
    CHECK(vireo_mysql_user_repository_create(thread, pool, &policy, &users, NULL), VIREO_OK);
    CHECK(vireo_mysql_node_repository_create(thread, pool, &nodes, NULL), VIREO_OK);
    CHECK(vireo_password_hash_create(&policy, "Correct!7", 9, phc, sizeof(phc), &phc_length), VIREO_OK);
    issued_at = now_ms() - 10000; uint64_t alice_root, bob_root;
    vireo_mysql_node_actor_t alice = account("alice_stat", &alice_root), bob = account("bob_stat", &bob_root);
    vireo_node_stat_response_t root = stat_node(alice, alice_root, VIREO_DIRECTORY_STAT_FOUND);
    assert(!root.metadata.has_parent && !root.metadata.parent_id && !root.metadata.name_length &&
        root.metadata.type == VIREO_MYSQL_NODE_DIRECTORY && !root.metadata.has_object_hash && !root.metadata.size);
    zeroed(root.metadata.name, sizeof(root.metadata.name)); zeroed(root.metadata.object_hash, sizeof(root.metadata.object_hash));
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
    vireo_node_stat_response_t directory = stat_node(alice, made.node.id, VIREO_DIRECTORY_STAT_FOUND);
    assert(directory.metadata.has_parent && directory.metadata.parent_id == alice_root && directory.metadata.name_length == 255 &&
        !memcmp(directory.metadata.name, name, sizeof(name)) && directory.metadata.type == VIREO_MYSQL_NODE_DIRECTORY);
    (void)stat_node(bob, made.node.id, VIREO_DIRECTORY_STAT_NOT_FOUND);

    /* 固定SQL只生产文件元数据fixture，不代表上传或CAS验证成功。 */
    mutate("INSERT INTO objects(object_hash,size,state,ref_count,storage_class,created_at_ms,updated_at_ms,verified_at_ms) VALUES(UNHEX(REPEAT('a5',32)),18446744073709551615,2,1,1,1000,1000,1000)");
    char sql[2048];
    int n = snprintf(sql, sizeof(sql), "INSERT INTO file_nodes(id,owner_id,parent_id,name,node_type,state,object_hash,size,created_at_ms,updated_at_ms,deleted_at_ms) VALUES(1001,%llu,%llu,0xFF,2,2,UNHEX(REPEAT('a5',32)),18446744073709551615,1000,1002,NULL),(1002,%llu,%llu,'pending',2,1,NULL,5,1000,1002,NULL),(1003,%llu,%llu,'deleted',2,3,NULL,7,1000,1002,1002)",
        (unsigned long long)alice.user_id, (unsigned long long)alice_root, (unsigned long long)alice.user_id,
        (unsigned long long)alice_root, (unsigned long long)alice.user_id, (unsigned long long)alice_root);
    assert(n > 0 && (size_t)n < sizeof(sql)); mutate(sql);
    vireo_node_stat_response_t file = stat_node(alice, 1001, VIREO_DIRECTORY_STAT_FOUND);
    assert(file.metadata.type == VIREO_MYSQL_NODE_FILE && file.metadata.has_object_hash && file.metadata.size == UINT64_MAX &&
        file.metadata.has_parent && file.metadata.parent_id == alice_root && file.metadata.name_length == 1 && file.metadata.name[0] == 0xff &&
        file.metadata.created_at_ms == 1000 && file.metadata.updated_at_ms == 1002);
    for (size_t i = 0; i < sizeof(file.metadata.object_hash); ++i) { assert(file.metadata.object_hash[i] == 0xa5); }
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
    const vireo_directory_stat_completion_outcome_t cancelled=bridge(bob,bob_root,0,true);
    assert(cancelled.metadata.result==VIREO_RESULT_CANCELLED && cancelled.response.status==VIREO_STATUS_UNAVAILABLE);
    const vireo_directory_stat_completion_outcome_t expired=bridge(bob,bob_root,0,false);
    assert(expired.metadata.result==VIREO_RESULT_TIMEOUT && expired.response.status==VIREO_STATUS_TIMEOUT);
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
    assert(root.metadata.node_id == alice_root && directory.metadata.name_length == sizeof(name) &&
        !memcmp(directory.metadata.name, name, sizeof(name)) && file.metadata.size == UINT64_MAX && file.metadata.object_hash[31] == 0xa5);
    assert(fd_count() == fds); memset(db_password, 0, sizeof(db_password)); memset(phc, 0, sizeof(phc));
    printf("PASS %zu real STAT bridge observations; cross-thread trusted task/worker/completion, native UTC, root/mkdir/file, raw names, owner isolation, hidden rows, revoke/expiry, five-table read-only snapshots, independent values; FD %zu->%zu\n", cases, fds, fd_count());
    return 0;
}
