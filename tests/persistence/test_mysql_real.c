#define _POSIX_C_SOURCE 200809L
#include "mysql_internal.h"
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(call, want) do { errno = EDOM; assert((call) == (want)); assert(errno == EDOM); } while (0)
static unsigned int query_failure;
static unsigned int query_number;
static bool bad_result;
static bool wrong_baseline;
static int query(MYSQL *n, const char *sql)
{
    ++query_number;
    if (query_failure == query_number) {
        /* 注入真实driver错误，证明诊断在close前保留。 */
        return mysql_query(n, "SELECT * FROM vireo_absent_failure_table");
    }
    if (wrong_baseline && query_number == 2) {
        return mysql_query(n, "SELECT 0,1,1,1,1,1,1");
    }
    return mysql_query(n, sql);
}
static MYSQL_RES *store_result(MYSQL *n)
{
    if (bad_result) {
        /* 模拟store_result失败；未消费结果由close收尾。 */
        return NULL;
    }
    return mysql_store_result(n);
}
static size_t fd_count(void)
{
    DIR *d = opendir("/proc/self/fd"); assert(d != NULL);
    size_t count = 0;
    while (readdir(d) != NULL) { ++count; }
    assert(closedir(d) == 0);
    return count;
}
static void verify_native(vireo_mysql_connection_t *c, const char *db)
{
    MYSQL *n = c->native;
    assert(mysql_query(n, "SELECT DATABASE(),@@autocommit,@@time_zone,"
        "@@character_set_client,@@character_set_connection,@@character_set_results,"
        "@@default_storage_engine,@@sql_mode") == 0);
    MYSQL_RES *res = mysql_store_result(n); assert(res != NULL);
    assert(mysql_num_fields(res) == 8 && mysql_num_rows(res) == 1);
    MYSQL_ROW row = mysql_fetch_row(res); assert(row != NULL);
    assert(strcmp(row[0], db) == 0 && strcmp(row[1], "1") == 0 && strcmp(row[2], "+00:00") == 0);
    for (unsigned int i = 3; i <= 5; ++i) { assert(strcmp(row[i], "utf8mb4") == 0); }
    assert(strcmp(row[6], "InnoDB") == 0);
    assert(strstr(row[7], "STRICT_TRANS_TABLES") != NULL &&
        strstr(row[7], "ERROR_FOR_DIVISION_BY_ZERO") != NULL &&
        strstr(row[7], "NO_ENGINE_SUBSTITUTION") != NULL);
    assert(mysql_fetch_row(res) == NULL); mysql_free_result(res);
    /* 实际选项与握手flag；不触碰已弃用MYSQL_OPT_RECONNECT。 */
    unsigned int protocol = 0, local = 1, timeout = 0;
    assert(mysql_get_option(n, MYSQL_OPT_PROTOCOL, &protocol) == 0 && protocol == MYSQL_PROTOCOL_SOCKET);
    assert(mysql_get_option(n, MYSQL_OPT_LOCAL_INFILE, &local) == 0 && local == 0);
    assert(mysql_get_option(n, MYSQL_OPT_CONNECT_TIMEOUT, &timeout) == 0 && timeout == 3);
    assert((n->client_flag & CLIENT_MULTI_STATEMENTS) == 0);
    assert(!n->reconnect); /* 测试私有观察，不将driver布局变为公开合同。 */
}
typedef struct worker_args {
    vireo_mysql_runtime_t *runtime;
    const vireo_mysql_connection_options_t *options;
    pthread_barrier_t *barrier;
    vireo_mysql_connection_t *handoff;
    uint64_t connection_id;
    bool consume;
} worker_args_t;
static void *worker(void *argument)
{
    worker_args_t *a = argument;
    vireo_mysql_thread_t *t = NULL;
    vireo_mysql_connection_t *c = NULL;
    CHECK(vireo_mysql_thread_attach(a->runtime, &t, NULL), VIREO_OK);
    if (a->consume) {
        c = a->handoff;
        vireo_mysql_connection_info_t info;
        CHECK(vireo_mysql_connection_inspect(t, c, &info), VIREO_OK);
        assert(info.connection_id == a->connection_id);
        verify_native(c, a->options->database);
        CHECK(vireo_mysql_connection_destroy(t, &c), VIREO_OK);
        a->handoff = NULL;
    } else {
        CHECK(vireo_mysql_connection_open(t, a->options, &c, NULL), VIREO_OK);
        vireo_mysql_connection_info_t info;
        CHECK(vireo_mysql_connection_inspect(t, c, &info), VIREO_OK);
        a->connection_id = info.connection_id;
        if (a->barrier != NULL) {
            int br = pthread_barrier_wait(a->barrier);
            assert(br == 0 || br == PTHREAD_BARRIER_SERIAL_THREAD);
            verify_native(c, a->options->database);
            CHECK(vireo_mysql_connection_destroy(t, &c), VIREO_OK);
        } else {
            a->handoff = c; /* pthread_join在main建立唯一owner交接的同步。 */
        }
    }
    CHECK(vireo_mysql_thread_detach(&t), VIREO_OK);
    return NULL;
}
static void bad_open(vireo_mysql_thread_t *t, const vireo_mysql_connection_options_t *o,
    vireo_mysql_stage_t stage, unsigned int code)
{
    vireo_mysql_connection_t *c = NULL;
    vireo_mysql_error_t e;
    CHECK(vireo_mysql_connection_open(t, o, &c, &e), VIREO_RESULT_DATABASE);
    assert(c == NULL && e.stage == stage && e.system_error == 0);
    assert(e.mysql_code == code);
    if (code != 0) { assert(strlen(e.sqlstate) == 5); }
    else { assert(e.sqlstate[0] == '\0'); }
    assert(atomic_load(&t->runtime->connections) == 0);
}
int main(int argc, char **argv)
{
    assert(argc == 5);
    char password[1026];
    FILE *f = fopen(argv[3], "r"); assert(f != NULL);
    assert(fgets(password, (int)sizeof(password), f) != NULL && fclose(f) == 0);
    password[strcspn(password, "\n")] = '\0';
    struct sigaction action = {0}; action.sa_handler = SIG_IGN;
    assert(sigemptyset(&action.sa_mask) == 0 && sigaction(SIGPIPE, &action, NULL) == 0);
    vireo_mysql_runtime_t *r = NULL;
    vireo_mysql_ops_t ops = vireo_mysql_native_ops;
    ops.query = query; ops.store_result = store_result;
    CHECK(vireo_mysql_runtime_create_with_ops(&r, NULL, &ops), VIREO_OK);
    vireo_mysql_thread_t *t = NULL;
    CHECK(vireo_mysql_thread_attach(r, &t, NULL), VIREO_OK);
    size_t before = fd_count();
    vireo_mysql_connection_options_t o = {argv[1], argv[2], password, argv[4], 3, 3, 3};
    vireo_mysql_connection_options_t bad = o;
    bad.password = "deliberately-wrong";
    bad_open(t, &bad, VIREO_MYSQL_STAGE_CONNECT, 1045);
    bad = o; bad.unix_socket = "/tmp/vireo-absent-03802/socket";
    bad_open(t, &bad, VIREO_MYSQL_STAGE_CONNECT, 2002);
    bad = o; bad.database = "vireo_missing_database";
    /* 账号只获本库权限，未知库在权限核对先失败1044。 */
    bad_open(t, &bad, VIREO_MYSQL_STAGE_CONNECT, 1044);
    for (unsigned int i = 1; i <= 2; ++i) {
        query_failure = i; query_number = 0;
        bad_open(t, &o, i == 1 ? VIREO_MYSQL_STAGE_SESSION_SETUP : VIREO_MYSQL_STAGE_SESSION_VERIFY, 1146);
    }
    query_failure = 0; query_number = 0; bad_result = true;
    bad_open(t, &o, VIREO_MYSQL_STAGE_SESSION_VERIFY, 0);
    bad_result = false; wrong_baseline = true; query_number = 0;
    bad_open(t, &o, VIREO_MYSQL_STAGE_SESSION_VERIFY, 0);
    wrong_baseline = false; query_number = 0;
    vireo_mysql_connection_t *c = NULL;
    CHECK(vireo_mysql_connection_open(t, &o, &c, NULL), VIREO_OK);
    verify_native(c, o.database);
    vireo_mysql_connection_info_t info;
    CHECK(vireo_mysql_connection_inspect(t, c, &info), VIREO_OK);
    assert(info.server_version >= 80000 && info.server_version < 80100 && info.connection_id != 0);
    CHECK(vireo_mysql_connection_destroy(NULL, &c), VIREO_RESULT_INVALID_ARGUMENT);
    assert(c != NULL);
    CHECK(vireo_mysql_connection_destroy(t, &c), VIREO_OK);
    CHECK(vireo_mysql_thread_detach(&t), VIREO_OK);
    assert(fd_count() == before);
    /* 并行线程使用无可变注入的原生表；只有本测试私有副本在无操作时改回。 */
    r->ops = vireo_mysql_native_ops;
    pthread_barrier_t barrier;
    assert(pthread_barrier_init(&barrier, NULL, 3) == 0);
    pthread_t workers[3]; worker_args_t args[3];
    for (size_t i = 0; i < 3; ++i) {
        args[i] = (worker_args_t){r, &o, &barrier, NULL, 0, false};
        assert(pthread_create(&workers[i], NULL, worker, &args[i]) == 0);
    }
    for (size_t i = 0; i < 3; ++i) { assert(pthread_join(workers[i], NULL) == 0); }
    assert(pthread_barrier_destroy(&barrier) == 0);
    assert(args[0].connection_id != args[1].connection_id && args[1].connection_id != args[2].connection_id && args[0].connection_id != args[2].connection_id);
    worker_args_t handoff = {r, &o, NULL, NULL, 0, false};
    pthread_t a, b;
    assert(pthread_create(&a, NULL, worker, &handoff) == 0 && pthread_join(a, NULL) == 0);
    assert(handoff.handoff != NULL && atomic_load(&r->guards) == 0 && atomic_load(&r->connections) == 1);
    CHECK(vireo_mysql_runtime_destroy(&r), VIREO_RESULT_BUSY);
    handoff.consume = true;
    assert(pthread_create(&b, NULL, worker, &handoff) == 0 && pthread_join(b, NULL) == 0);
    assert(handoff.handoff == NULL && atomic_load(&r->connections) == 0 && atomic_load(&r->guards) == 0);
    assert(fd_count() == before);
    CHECK(vireo_mysql_runtime_destroy(&r), VIREO_OK);
    assert(fd_count() == before);
    memset(password, 0, sizeof(password));
    printf("PASS real MySQL %u, baseline/options, bad credentials/socket/database, session failure cleanup, 3 parallel threads, synchronized handoff, fd %zu -> %zu\n", info.server_version, before, fd_count());
    return 0;
}
