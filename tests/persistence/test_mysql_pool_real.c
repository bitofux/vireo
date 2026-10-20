#define _POSIX_C_SOURCE 200809L
#include "mysql_pool_internal.h"
#include <vireo/persistence/mysql_statement.h>
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#define CHECK(call, want) do { errno = EDOM; vireo_result_t actual = (call); if (actual != (want)) { fprintf(stderr, "line %d: got %d expected %d\n", __LINE__, (int)actual, (int)(want)); abort(); } assert(errno == EDOM); } while (0)
static size_t fd_count(void)
{
    DIR *d = opendir("/proc/self/fd"); assert(d != NULL); size_t n = 0;
    while (readdir(d) != NULL) { ++n; } assert(closedir(d) == 0); return n;
}
static void sql(vireo_mysql_connection_t *c, const char *query)
{ assert(mysql_query(c->native, query) == 0); }
static void scalar(vireo_mysql_connection_t *c, const char *query, const char *expected)
{
    sql(c, query); MYSQL_RES *res = mysql_store_result(c->native); assert(res != NULL);
    MYSQL_ROW row = mysql_fetch_row(res); assert(row != NULL);
    assert((expected == NULL && row[0] == NULL) ||
        (expected != NULL && row[0] != NULL && strcmp(row[0], expected) == 0));
    assert(mysql_fetch_row(res) == NULL); mysql_free_result(res);
}
static vireo_mysql_lease_t acquire(vireo_mysql_thread_t *t, vireo_mysql_pool_t *p)
{
    vireo_mysql_lease_t l = {0}; vireo_mysql_pool_acquisition_t report;
    CHECK(vireo_mysql_pool_acquire(t, p, 1000, &l, &report, NULL), VIREO_OK);
    assert(report.acquired); return l;
}
static vireo_mysql_connection_t *borrow(vireo_mysql_thread_t *t, vireo_mysql_pool_t *p,
    const vireo_mysql_lease_t *l)
{
    vireo_mysql_connection_t *c = NULL; CHECK(vireo_mysql_pool_borrow(t, p, l, &c), VIREO_OK); return c;
}
static void release(vireo_mysql_thread_t *t, vireo_mysql_pool_t *p,
    vireo_mysql_lease_t *l, vireo_mysql_pool_disposition_t disposition, bool reusable)
{
    vireo_mysql_pool_release_t report;
    CHECK(vireo_mysql_pool_release(t, p, l, disposition, &report, NULL), VIREO_OK);
    assert(report.released && report.reusable == reusable && l->owner == NULL);
}
static vireo_mysql_pool_t *create(vireo_mysql_thread_t *t,
    const vireo_mysql_connection_options_t *o, size_t capacity, size_t max_waiters)
{
    vireo_mysql_pool_options_t options = {*o, capacity, max_waiters, VIREO_MYSQL_POOL_MEMORY_MAX};
    vireo_mysql_pool_t *p = NULL; CHECK(vireo_mysql_pool_create(t, &options, &p, NULL), VIREO_OK); return p;
}
static void destroy(vireo_mysql_thread_t *t, vireo_mysql_pool_t **p)
{
    bool closed; CHECK(vireo_mysql_pool_close(*p, &closed, NULL), VIREO_OK); assert(closed);
    CHECK(vireo_mysql_pool_destroy(t, p, NULL), VIREO_OK); assert(*p == NULL);
}
static vireo_mysql_statement_t *prepare(vireo_mysql_thread_t *t, vireo_mysql_connection_t *c)
{
    vireo_mysql_statement_t *s = NULL;
    vireo_mysql_statement_limits_t limits = {0, 1, 0, 32, VIREO_MYSQL_STATEMENT_MEMORY_MAX};
    CHECK(vireo_mysql_statement_prepare(t, c, "SELECT 1", 8, &limits, &s, NULL), VIREO_OK); return s;
}
static void reset_session(vireo_mysql_thread_t *t, const vireo_mysql_connection_options_t *o)
{
    vireo_mysql_pool_t *p = create(t, o, 1, 1); vireo_mysql_lease_t l = acquire(t, p), stale = l;
    vireo_mysql_connection_t *c = borrow(t, p, &l); uint64_t id = c->info.connection_id;
    CHECK(vireo_mysql_connection_destroy(t, &c), VIREO_RESULT_BUSY); assert(c != NULL);
    vireo_mysql_statement_t *s = prepare(t, c); vireo_mysql_pool_release_t report;
    CHECK(vireo_mysql_pool_release(t, p, &l, VIREO_MYSQL_POOL_RECYCLE, &report, NULL), VIREO_RESULT_BUSY);
    assert(!report.released && l.owner == p);
    CHECK(vireo_mysql_statement_destroy(t, &s, NULL), VIREO_OK);
    sql(c, "CREATE TEMPORARY TABLE pool_temporary(value INT)");
    scalar(c, "SELECT GET_LOCK('vireo_pool_reset_lock',0)", "1");
    sql(c, "SET @vireo_pool_user='secret'");
    sql(c, "SET autocommit=0"); sql(c, "INSERT INTO pool_values VALUES(2)");
    scalar(c, "SELECT COUNT(*) FROM pool_values", "2");
    sql(c, "SET time_zone='+08:00',sql_mode='',default_storage_engine='MyISAM'");
    assert(mysql_set_character_set(c->native, "latin1") == 0);
    assert(mysql_select_db(c->native, "vireo_pool_other") == 0);
    release(t, p, &l, VIREO_MYSQL_POOL_RECYCLE, true);
    CHECK(vireo_mysql_pool_borrow(NULL, p, &stale, &c), VIREO_RESULT_NOT_FOUND);
    l = acquire(t, p); c = borrow(t, p, &l); assert(c->info.connection_id == id);
    scalar(c, "SELECT DATABASE()", o->database);
    scalar(c, "SELECT COUNT(*) FROM pool_values", "1");
    scalar(c, "SELECT @vireo_pool_user", NULL);
    scalar(c, "SELECT IS_FREE_LOCK('vireo_pool_reset_lock')", "1");
    scalar(c, "SELECT @@autocommit=1 AND @@time_zone='+00:00' AND "
        "@@character_set_client='utf8mb4' AND @@character_set_connection='utf8mb4' AND "
        "@@character_set_results='utf8mb4' AND @@default_storage_engine='InnoDB' AND "
        "FIND_IN_SET('STRICT_TRANS_TABLES',@@sql_mode)>0", "1");
    assert(mysql_query(c->native, "SELECT * FROM pool_temporary") != 0 && mysql_errno(c->native) == 1146);
    release(t, p, &l, VIREO_MYSQL_POOL_RECYCLE, true);
    l = acquire(t, p); c = borrow(t, p, &l); s = prepare(t, c);
    /* 杀自己的连接，无额外权限或管理账号进入测试程序。 */
    int killed = mysql_query(c->native, "KILL CONNECTION_ID()"); (void)killed;
    vireo_mysql_execution_t execution; vireo_mysql_error_t e;
    CHECK(vireo_mysql_statement_execute(t, s, NULL, 0, &execution, &e), VIREO_RESULT_DATABASE);
    assert(c->unusable && execution.execution_started);
    vireo_result_t cleaned = vireo_mysql_statement_destroy(t, &s, NULL);
    assert((cleaned == VIREO_OK || cleaned == VIREO_RESULT_DATABASE) && s == NULL);
    release(t, p, &l, VIREO_MYSQL_POOL_RECYCLE, false);
    vireo_mysql_pool_acquisition_t acquired;
    CHECK(vireo_mysql_pool_acquire(t, p, 0, &l, &acquired, NULL), VIREO_RESULT_BUSY);
    vireo_mysql_pool_refill_t refill; CHECK(vireo_mysql_pool_refill(t, p, &refill, NULL), VIREO_OK); assert(refill.restored);
    l = acquire(t, p); c = borrow(t, p, &l); assert(c->info.connection_id != id);
    release(t, p, &l, VIREO_MYSQL_POOL_RECYCLE, true); destroy(t, &p);
    puts("real reset: rollback/temp/GET_LOCK/user variables/charset/session/database; healthy same id; killed connection discard and explicit new-id refill");
}
static int native_failure;
static int fail_reset(MYSQL *n)
{
    if (native_failure == 1) { return mysql_query(n, "SELECT * FROM vireo_reset_absent"); }
    return mysql_reset_connection(n);
}
static int fail_select(MYSQL *n, const char *db)
{ return mysql_select_db(n, native_failure == 2 ? "vireo_pool_absent" : db); }
static int fail_charset(MYSQL *n, const char *charset)
{ return mysql_set_character_set(n, native_failure == 3 ? "vireo_invalid_charset" : charset); }
static int fail_query(MYSQL *n, const char *query)
{
    if (native_failure == 4 && strncmp(query, "SET SESSION", 11) == 0) {
        return mysql_query(n, "SELECT * FROM vireo_reset_absent");
    }
    if (native_failure == 5 && strncmp(query, "SELECT @@autocommit", 19) == 0) {
        return mysql_query(n, "SELECT 0,1,1,1,1,1,1");
    }
    if (native_failure == 6 && strcmp(query, "SELECT DATABASE()") == 0) {
        return mysql_query(n, "SELECT 'wrong_database'");
    }
    return mysql_query(n, query);
}
static void reset_failures(vireo_mysql_thread_t *t, const vireo_mysql_connection_options_t *o)
{
    vireo_mysql_pool_t *p = create(t, o, 1, 1);
    const vireo_mysql_session_ops_t session = {fail_reset, fail_select, fail_charset};
    t->runtime->ops.query = fail_query; /* 所有worker静止，仅本线程原生边界验证。 */
    for (int i = 1; i <= 6; ++i) {
        vireo_mysql_lease_t l = acquire(t, p); vireo_mysql_connection_t *c = borrow(t, p, &l);
        c->session_ops = &session; native_failure = i;
        vireo_mysql_pool_release_t report; vireo_mysql_pool_error_t error;
        CHECK(vireo_mysql_pool_release(t, p, &l, VIREO_MYSQL_POOL_RECYCLE, &report, &error), VIREO_RESULT_DATABASE);
        assert(report.released && !report.reusable && l.owner == NULL);
        assert(error.stage == (i == 1 ? VIREO_MYSQL_POOL_STAGE_RESET : VIREO_MYSQL_POOL_STAGE_SESSION));
        if (i <= 4) { assert(error.database.mysql_code != 0); }
        native_failure = 0; vireo_mysql_pool_refill_t refill;
        CHECK(vireo_mysql_pool_refill(t, p, &refill, NULL), VIREO_OK); assert(refill.restored);
    }
    t->runtime->ops.query = vireo_mysql_native_ops.query; destroy(t, &p);
    puts("real reset failure boundaries: reset/select_db/charset/SET/baseline verification/database verification diagnosed, consumed, discarded, refilled");
}
/* 主线程轮询只读池计数，条件由真实pthread同步；失败有单调2秒上界。 */
static void wait_for_waiters(vireo_mysql_pool_t *p, size_t expected)
{
    struct timespec start, time; assert(clock_gettime(CLOCK_MONOTONIC, &start) == 0);
    for (;;) {
        vireo_mysql_pool_info_t info; CHECK(vireo_mysql_pool_inspect(p, &info), VIREO_OK);
        if (info.waiters == expected) { return; }
        assert(clock_gettime(CLOCK_MONOTONIC, &time) == 0 && time.tv_sec - start.tv_sec < 3);
        const struct timespec pause = {0, 1000000}; assert(nanosleep(&pause, NULL) == 0);
    }
}
typedef struct worker_args {
    vireo_mysql_runtime_t *runtime;
    vireo_mysql_pool_t *pool;
    vireo_mysql_lease_t identity;
    vireo_mysql_connection_t *connection;
    vireo_mysql_statement_t *statement;
    vireo_result_t expected;
    int mode;
} worker_args_t;
static pthread_mutex_t overlap_mutex = PTHREAD_MUTEX_INITIALIZER;
static uint64_t active[4];
static void *worker(void *argument)
{
    worker_args_t *a = argument; vireo_mysql_thread_t *t = NULL;
    CHECK(vireo_mysql_thread_attach(a->runtime, &t, NULL), VIREO_OK);
    if (a->mode == 1) {
        vireo_mysql_connection_t *out = NULL;
        CHECK(vireo_mysql_pool_borrow(t, a->pool, &a->identity, &out), a->expected);
        vireo_mysql_pool_release_t report;
        CHECK(vireo_mysql_pool_release(t, a->pool, &a->identity, VIREO_MYSQL_POOL_DISCARD, &report, NULL), a->expected);
        assert(!report.released);
        if (a->connection != NULL) {
            vireo_mysql_connection_info_t info;
            CHECK(vireo_mysql_connection_inspect(t, a->connection, &info), VIREO_RESULT_INVALID_ARGUMENT);
            vireo_mysql_statement_info_t si;
            CHECK(vireo_mysql_statement_inspect(t, a->statement, &si), VIREO_RESULT_INVALID_ARGUMENT);
        }
    } else if (a->mode == 2) {
        vireo_mysql_lease_t l = {0}; vireo_mysql_pool_acquisition_t report;
        CHECK(vireo_mysql_pool_acquire(t, a->pool, 2000, &l, &report, NULL), a->expected);
        if (report.acquired) { release(t, a->pool, &l, VIREO_MYSQL_POOL_RECYCLE, true); }
    } else if (a->mode == 3) {
        vireo_mysql_pool_refill_t report;
        CHECK(vireo_mysql_pool_refill(t, a->pool, &report, NULL), VIREO_RESULT_CANCELLED); assert(!report.restored);
    } else if (a->mode == 4) {
        vireo_mysql_lease_t l = acquire(t, a->pool);
        release(t, a->pool, &l, VIREO_MYSQL_POOL_RECYCLE, false);
    } else {
        for (size_t n = 0; n < 30; ++n) {
            vireo_mysql_lease_t l = acquire(t, a->pool); vireo_mysql_connection_t *c = borrow(t, a->pool, &l);
            uint64_t id = c->info.connection_id;
            assert(pthread_mutex_lock(&overlap_mutex) == 0);
            for (size_t k = 0; k < 4; ++k) { assert(active[k] != id); }
            size_t at = 0; for (; at < 4 && active[at] != 0; ++at) { }
            assert(at < 4); active[at] = id; assert(pthread_mutex_unlock(&overlap_mutex) == 0);
            vireo_mysql_statement_t *s = prepare(t, c); vireo_mysql_execution_t execution;
            CHECK(vireo_mysql_statement_execute(t, s, NULL, 0, &execution, NULL), VIREO_OK);
            vireo_mysql_fetch_outcome_t outcome;
            CHECK(vireo_mysql_statement_fetch(t, s, &outcome, NULL), VIREO_OK); assert(outcome == VIREO_MYSQL_FETCH_ROW);
            CHECK(vireo_mysql_statement_destroy(t, &s, NULL), VIREO_OK);
            assert(pthread_mutex_lock(&overlap_mutex) == 0); active[at] = 0;
            assert(pthread_mutex_unlock(&overlap_mutex) == 0);
            release(t, a->pool, &l, VIREO_MYSQL_POOL_RECYCLE, true);
        }
    }
    CHECK(vireo_mysql_thread_detach(&t), VIREO_OK); return NULL;
}
static void threaded(vireo_mysql_thread_t *t, const vireo_mysql_connection_options_t *o)
{
    vireo_mysql_pool_t *p = create(t, o, 2, 4); pthread_t workers[4]; worker_args_t args[4];
    for (size_t i = 0; i < 4; ++i) {
        args[i] = (worker_args_t){.runtime=t->runtime,.pool=p};
        assert(pthread_create(&workers[i], NULL, worker, &args[i]) == 0);
    }
    for (size_t i = 0; i < 4; ++i) { assert(pthread_join(workers[i], NULL) == 0); }
    vireo_mysql_pool_info_t info; CHECK(vireo_mysql_pool_inspect(p, &info), VIREO_OK);
    assert(info.idle == 2 && info.leased == 0 && info.high_watermark <= 2 && info.waiters == 0);
    destroy(t, &p); p = create(t, o, 1, 1);
    vireo_mysql_lease_t l = acquire(t, p), out = {0}; vireo_mysql_pool_acquisition_t acquisition;
    CHECK(vireo_mysql_pool_acquire(t, p, 0, &out, &acquisition, NULL), VIREO_RESULT_BUSY);
    CHECK(vireo_mysql_pool_acquire(t, p, 25, &out, &acquisition, NULL), VIREO_RESULT_TIMEOUT);
    vireo_mysql_connection_t *c = borrow(t, p, &l); vireo_mysql_statement_t *s = prepare(t, c);
    worker_args_t a = {.runtime=t->runtime,.pool=p,.identity=l,.connection=c,.statement=s,
        .expected=VIREO_RESULT_INVALID_ARGUMENT,.mode=1};
    assert(pthread_create(&workers[0], NULL, worker, &a) == 0 && pthread_join(workers[0], NULL) == 0);
    CHECK(vireo_mysql_statement_destroy(t, &s, NULL), VIREO_OK);
    vireo_mysql_pool_t *other = create(t, o, 1, 0);
    CHECK(vireo_mysql_pool_borrow(t, other, &l, &c), VIREO_RESULT_INVALID_ARGUMENT); destroy(t, &other);
    a = (worker_args_t){.runtime=t->runtime,.pool=p,.expected=VIREO_OK,.mode=2};
    assert(pthread_create(&workers[0], NULL, worker, &a) == 0); wait_for_waiters(p, 1);
    CHECK(vireo_mysql_pool_acquire(t, p, 100, &out, &acquisition, NULL), VIREO_RESULT_BUSY);
    vireo_mysql_lease_t stale = l;
    release(t, p, &l, VIREO_MYSQL_POOL_RECYCLE, true);
    assert(pthread_join(workers[0], NULL) == 0); l = acquire(t, p);
    a = (worker_args_t){.runtime=t->runtime,.pool=p,.identity=stale,.expected=VIREO_RESULT_NOT_FOUND,.mode=1};
    assert(pthread_create(&workers[0], NULL, worker, &a) == 0 && pthread_join(workers[0], NULL) == 0);
    a = (worker_args_t){.runtime=t->runtime,.pool=p,.expected=VIREO_RESULT_CANCELLED,.mode=2};
    assert(pthread_create(&workers[0], NULL, worker, &a) == 0); wait_for_waiters(p, 1);
    bool closed; CHECK(vireo_mysql_pool_close(p, &closed, NULL), VIREO_OK);
    CHECK(vireo_mysql_pool_destroy(t, &p, NULL), VIREO_RESULT_BUSY);
    assert(pthread_join(workers[0], NULL) == 0);
    c = borrow(t, p, &l); s = prepare(t, c); /* 关闭不撤销有效租约。 */
    vireo_mysql_pool_release_t report;
    CHECK(vireo_mysql_pool_release(t, p, &l, VIREO_MYSQL_POOL_RECYCLE, &report, NULL), VIREO_RESULT_BUSY);
    CHECK(vireo_mysql_statement_destroy(t, &s, NULL), VIREO_OK);
    release(t, p, &l, VIREO_MYSQL_POOL_RECYCLE, false); destroy(t, &p);
    puts("pthread: four workers/120 SQL leases, no same-id overlap; exhaustion/timeout/quota/wake/close; thread/guard/pool/stale identity; active destroy BUSY");
}
static pthread_mutex_t gate_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t gate_cond = PTHREAD_COND_INITIALIZER;
static bool gate_entered, gate_continue;
static void gate(void)
{
    assert(pthread_mutex_lock(&gate_mutex) == 0); gate_entered = true;
    assert(pthread_cond_broadcast(&gate_cond) == 0);
    while (!gate_continue) { assert(pthread_cond_wait(&gate_cond, &gate_mutex) == 0); }
    assert(pthread_mutex_unlock(&gate_mutex) == 0);
}
static vireo_result_t gated_restore(vireo_mysql_connection_t *c, const char *db, vireo_mysql_error_t *e)
{ gate(); return vireo_mysql_connection_restore(c, db, e); }
static vireo_result_t gated_open(vireo_mysql_thread_t *t, const vireo_mysql_connection_options_t *o,
    vireo_mysql_connection_t **out, vireo_mysql_error_t *e)
{ gate(); return vireo_mysql_connection_open(t, o, out, e); }
static void close_during_io(vireo_mysql_thread_t *t, const vireo_mysql_connection_options_t *o, bool refill)
{
    vireo_mysql_pool_t *p = create(t, o, 2, 1);
    gate_entered = false; gate_continue = false;
    if (refill) {
        vireo_mysql_lease_t l = acquire(t, p); release(t, p, &l, VIREO_MYSQL_POOL_DISCARD, false);
        p->ops.open = gated_open;
    } else { p->ops.restore = gated_restore; }
    worker_args_t a = {.runtime=t->runtime,.pool=p,.mode=refill ? 3 : 4}; pthread_t id;
    assert(pthread_create(&id, NULL, worker, &a) == 0);
    assert(pthread_mutex_lock(&gate_mutex) == 0);
    while (!gate_entered) { assert(pthread_cond_wait(&gate_cond, &gate_mutex) == 0); }
    assert(pthread_mutex_unlock(&gate_mutex) == 0);
    vireo_mysql_pool_info_t info; CHECK(vireo_mysql_pool_inspect(p, &info), VIREO_OK);
    assert((refill ? info.refilling : info.returning) == 1 && info.idle == 1);
    vireo_mysql_lease_t l = acquire(t, p); /* 证明清理/建连中其他槽仍可借。 */
    release(t, p, &l, VIREO_MYSQL_POOL_DISCARD, false);
    bool closed; CHECK(vireo_mysql_pool_close(p, &closed, NULL), VIREO_OK);
    CHECK(vireo_mysql_pool_destroy(t, &p, NULL), VIREO_RESULT_BUSY);
    assert(pthread_mutex_lock(&gate_mutex) == 0); gate_continue = true;
    assert(pthread_cond_broadcast(&gate_cond) == 0 && pthread_mutex_unlock(&gate_mutex) == 0);
    assert(pthread_join(id, NULL) == 0);
    CHECK(vireo_mysql_pool_inspect(p, &info), VIREO_OK);
    assert(info.vacant == 2 && info.returning == 0 && info.refilling == 0 && info.idle == 0);
    destroy(t, &p);
}
int main(int argc, char **argv)
{
    assert(argc == 5); char password[1026]; FILE *f = fopen(argv[3], "r"); assert(f != NULL);
    assert(fgets(password, (int)sizeof(password), f) != NULL && fclose(f) == 0);
    password[strcspn(password, "\n")] = '\0';
    struct sigaction sa = {0}; sa.sa_handler = SIG_IGN;
    assert(sigemptyset(&sa.sa_mask) == 0 && sigaction(SIGPIPE, &sa, NULL) == 0);
    vireo_mysql_runtime_t *r = NULL; vireo_mysql_thread_t *t = NULL;
    CHECK(vireo_mysql_runtime_create(&r, NULL), VIREO_OK);
    CHECK(vireo_mysql_thread_attach(r, &t, NULL), VIREO_OK); size_t before = fd_count();
    vireo_mysql_connection_options_t o = {argv[1], argv[2], password, argv[4], 3, 3, 3};
    reset_session(t, &o); reset_failures(t, &o); threaded(t, &o);
    close_during_io(t, &o, false); close_during_io(t, &o, true);
    assert(atomic_load(&r->connections) == 0 && atomic_load(&r->pools) == 0);
    CHECK(vireo_mysql_thread_detach(&t), VIREO_OK);
    assert(atomic_load(&r->guards) == 0 && fd_count() == before);
    CHECK(vireo_mysql_runtime_destroy(&r), VIREO_OK); assert(fd_count() == before);
    memset(password, 0, sizeof(password));
    printf("PASS real MySQL pool: close during RETURNING/REFILLING, owners/counts/FD balanced %zu -> %zu\n", before, fd_count());
    return 0;
}
