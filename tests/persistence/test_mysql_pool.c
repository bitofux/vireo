#define _POSIX_C_SOURCE 200809L
#include "mysql_pool_internal.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(call, want) do { errno = EDOM; assert((call) == (want)); assert(errno == EDOM); } while (0)
static size_t allocations, open_calls, live_connections, fail_open, disposed;
static bool fail_allocate;
static int fail_phase, phase_calls, fail_lock, fail_unlock, fail_signal, fail_destroy;
static int restore_failure, wait_mode, clock_failure, fail_cond_destroy;
static void *pool_block;
static size_t wipe_checks;
static unsigned int waits;
static struct timespec fake_time;
static vireo_mysql_pool_t *observed;
static void *allocate(size_t bytes)
{
    if (fail_allocate) { return NULL; }
    void *p = malloc(bytes); assert(p != NULL); ++allocations;
    if (bytes >= sizeof(vireo_mysql_pool_t)) { assert(pool_block == NULL); pool_block = p; }
    return p;
}
static void release_memory(void *memory)
{
    assert(memory != NULL && allocations > 0);
    if (memory == pool_block) {
        vireo_mysql_pool_t *p = memory;
        for (size_t i = 0; i < p->string_bytes; ++i) { assert(p->strings[i] == 0); }
        pool_block = NULL; ++wipe_checks;
    }
    --allocations; free(memory);
}
static int phase(void) { return ++phase_calls == fail_phase ? ENOMEM : 0; }
static int mutex_init(pthread_mutex_t *m, const pthread_mutexattr_t *a)
{ int code = phase(); return code != 0 ? code : pthread_mutex_init(m, a); }
static int attr_init(pthread_condattr_t *a)
{ int code = phase(); return code != 0 ? code : pthread_condattr_init(a); }
static int attr_clock(pthread_condattr_t *a, clockid_t c)
{ int code = phase(); return code != 0 ? code : pthread_condattr_setclock(a, c); }
static int cond_init(pthread_cond_t *c, const pthread_condattr_t *a)
{ int code = phase(); return code != 0 ? code : pthread_cond_init(c, a); }
static int attr_destroy(pthread_condattr_t *a)
{ int code = phase(); return code != 0 ? code : pthread_condattr_destroy(a); }
static int lock(pthread_mutex_t *m)
{ if (fail_lock != 0) { --fail_lock; return EINVAL; } return pthread_mutex_lock(m); }
/* 注入unlock错误发生在真实unlock成功之后；仅验证已提交报告，不推广任意同步失败恢复。 */
static int unlock(pthread_mutex_t *m)
{
    int code = pthread_mutex_unlock(m); assert(code == 0);
    if (fail_unlock != 0) { --fail_unlock; return EINVAL; } return 0;
}
static int broadcast(pthread_cond_t *c)
{ if (fail_signal != 0) { --fail_signal; return EINVAL; } return pthread_cond_broadcast(c); }
static int mutex_destroy(pthread_mutex_t *m)
{ if (fail_destroy != 0) { --fail_destroy; return EBUSY; } return pthread_mutex_destroy(m); }
static int cond_destroy(pthread_cond_t *c)
{ if (fail_cond_destroy != 0) { --fail_cond_destroy; return EBUSY; } return pthread_cond_destroy(c); }
static int clock_now(clockid_t c, struct timespec *time)
{
    assert(c == CLOCK_MONOTONIC);
    if (clock_failure != 0) { errno = EIO; return -1; }
    *time = fake_time; return 0;
}
static int wait_cond(pthread_cond_t *c, pthread_mutex_t *m, const struct timespec *deadline)
{
    (void)c; (void)m; ++waits;
    assert(observed != NULL && observed->waiters == 1);
    if (wait_mode == 1) { return EINVAL; } /* mutex仍持有。 */
    if (wait_mode == 2) { observed->state = VIREO_MYSQL_POOL_CLOSED; }
    if (wait_mode == 3) { observed->slots[0].state = MYSQL_SLOT_IDLE; }
    if (wait_mode == 4 && waits == 1) { clock_failure = 1; return 0; }
    if (waits < 3 && wait_mode == 0) { return 0; } /* 两次虚假唤醒，deadline不变。 */
    fake_time = *deadline;
    return ETIMEDOUT;
}
static void unlocked_io(void)
{
    if (observed != NULL) {
        assert(pthread_mutex_trylock(&observed->mutex) == 0);
        assert(pthread_mutex_unlock(&observed->mutex) == 0);
    }
}
static vireo_result_t open_connection(vireo_mysql_thread_t *t,
    const vireo_mysql_connection_options_t *o, vireo_mysql_connection_t **out,
    vireo_mysql_error_t *e)
{
    unlocked_io(); ++open_calls;
    assert(strcmp(o->password, "model-secret") == 0);
    if (open_calls == fail_open) {
        e->stage = VIREO_MYSQL_STAGE_CONNECT; e->mysql_code = 1045;
        memcpy(e->sqlstate, "28000", 6); return VIREO_RESULT_DATABASE;
    }
    vireo_mysql_connection_t *c = t->runtime->ops.allocate(sizeof(*c));
    assert(c != NULL); memset(c, 0, sizeof(*c));
    c->runtime = t->runtime; c->statement_ops = &vireo_mysql_statement_native_ops;
    c->info.connection_id = (uint64_t)open_calls;
    (void)atomic_fetch_add(&t->runtime->connections, 1);
    ++live_connections; *out = c; return VIREO_OK;
}
static vireo_result_t restore(vireo_mysql_connection_t *c, const char *database,
    vireo_mysql_error_t *e)
{
    (void)c; unlocked_io(); assert(strcmp(database, "db") == 0);
    if (restore_failure != 0) {
        e->stage = restore_failure == 1 ? VIREO_MYSQL_STAGE_CONNECTION_RESET : VIREO_MYSQL_STAGE_SESSION_SETUP;
        e->mysql_code = 2013; memcpy(e->sqlstate, "HY000", 6); return VIREO_RESULT_DATABASE;
    }
    return VIREO_OK;
}
static void dispose(vireo_mysql_connection_t *c)
{
    unlocked_io(); assert(live_connections > 0); --live_connections; ++disposed;
    (void)atomic_fetch_sub(&c->runtime->connections, 1); c->runtime->ops.release(c);
}
static vireo_mysql_pool_ops_t pool_ops(void)
{
    vireo_mysql_pool_ops_t o = vireo_mysql_pool_native_ops;
    o.mutex_init = mutex_init; o.mutex_destroy = mutex_destroy; o.lock = lock; o.unlock = unlock;
    o.attr_init = attr_init; o.attr_clock = attr_clock; o.attr_destroy = attr_destroy;
    o.cond_destroy = cond_destroy; o.cond_init = cond_init; o.wait = wait_cond; o.clock_now = clock_now; o.broadcast = broadcast;
    o.open = open_connection; o.restore = restore; o.dispose = dispose; return o;
}
static vireo_mysql_pool_options_t options(void)
{
    return (vireo_mysql_pool_options_t){{"/model/socket", "user", "model-secret", "db", 1, 1, 1},
        2, 1, VIREO_MYSQL_POOL_MEMORY_MAX};
}
static vireo_mysql_pool_t *create(vireo_mysql_thread_t *t, size_t capacity)
{
    vireo_mysql_pool_t *p = NULL; vireo_mysql_pool_options_t o = options(); o.capacity = capacity;
    vireo_mysql_pool_ops_t ops = pool_ops();
    CHECK(vireo_mysql_pool_create_with_ops(t, &o, &p, NULL, &ops), VIREO_OK);
    observed = p; return p;
}
static void destroy(vireo_mysql_thread_t *t, vireo_mysql_pool_t **p)
{
    bool closed; CHECK(vireo_mysql_pool_close(*p, &closed, NULL), VIREO_OK); assert(closed);
    observed = NULL; CHECK(vireo_mysql_pool_destroy(t, p, NULL), VIREO_OK);
    assert(*p == NULL && live_connections == 0 && atomic_load(&t->runtime->pools) == 0);
}
static vireo_mysql_lease_t acquire(vireo_mysql_thread_t *t, vireo_mysql_pool_t *p)
{
    vireo_mysql_lease_t l = {0}; vireo_mysql_pool_acquisition_t a = {false};
    CHECK(vireo_mysql_pool_acquire(t, p, 0, &l, &a, NULL), VIREO_OK); assert(a.acquired); return l;
}
static void construction(vireo_mysql_thread_t *t)
{
    vireo_mysql_pool_t *p = NULL; vireo_mysql_pool_options_t o = options();
    vireo_mysql_pool_ops_t ops = pool_ops(); vireo_mysql_pool_error_t e;
    CHECK(vireo_mysql_pool_create(t, NULL, &p, &e), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_mysql_pool_create(NULL, &o, &p, &e), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_mysql_pool_create(t, &o, NULL, &e), VIREO_RESULT_INVALID_ARGUMENT);
    o.capacity = 0; CHECK(vireo_mysql_pool_create(t, &o, &p, &e), VIREO_RESULT_INVALID_ARGUMENT);
    o = options(); o.capacity = SIZE_MAX; CHECK(vireo_mysql_pool_create(t, &o, &p, &e), VIREO_RESULT_OVERFLOW);
    o.capacity = 65; CHECK(vireo_mysql_pool_create(t, &o, &p, &e), VIREO_RESULT_RANGE);
    o = options(); o.max_waiters = 1025; CHECK(vireo_mysql_pool_create(t, &o, &p, &e), VIREO_RESULT_RANGE);
    o = options(); o.max_memory_bytes = 0; CHECK(vireo_mysql_pool_create(t, &o, &p, &e), VIREO_RESULT_INVALID_ARGUMENT);
    o.max_memory_bytes = 1; CHECK(vireo_mysql_pool_create(t, &o, &p, &e), VIREO_RESULT_RANGE);
    o.max_memory_bytes = VIREO_MYSQL_POOL_MEMORY_MAX + 1; CHECK(vireo_mysql_pool_create(t, &o, &p, &e), VIREO_RESULT_RANGE);
    o = options(); o.connection.password = NULL; CHECK(vireo_mysql_pool_create(t, &o, &p, &e), VIREO_RESULT_INVALID_ARGUMENT);
    o = options(); atomic_store(&t->runtime->pools, SIZE_MAX);
    CHECK(vireo_mysql_pool_create(t, &o, &p, &e), VIREO_RESULT_OVERFLOW); atomic_store(&t->runtime->pools, 0);
    fail_allocate = true; CHECK(vireo_mysql_pool_create(t, &o, &p, &e), VIREO_RESULT_NO_MEMORY); fail_allocate = false;
    for (int i = 1; i <= 5; ++i) {
        phase_calls = 0; fail_phase = i;
        CHECK(vireo_mysql_pool_create_with_ops(t, &o, &p, &e, &ops), VIREO_RESULT_NO_MEMORY);
        assert(p == NULL && live_connections == 0 && atomic_load(&t->runtime->pools) == 0 && allocations == 2);
    }
    fail_phase = 0;
    for (size_t i = 1; i <= 2; ++i) {
        fail_open = open_calls + i;
        CHECK(vireo_mysql_pool_create_with_ops(t, &o, &p, &e, &ops), VIREO_RESULT_DATABASE);
        assert(p == NULL && e.database.mysql_code == 1045 && live_connections == 0 && allocations == 2);
    }
    fail_open = 0;
    p = create(t, 64); assert(live_connections == 64);
    vireo_mysql_pool_info_t info; CHECK(vireo_mysql_pool_inspect(p, &info), VIREO_OK);
    size_t exact = info.allocated_bytes; destroy(t, &p);
    o.capacity = 64; o.max_memory_bytes = exact - 1;
    CHECK(vireo_mysql_pool_create_with_ops(t, &o, &p, &e, &ops), VIREO_RESULT_RANGE);
    o.max_memory_bytes = exact; CHECK(vireo_mysql_pool_create_with_ops(t, &o, &p, &e, &ops), VIREO_OK);
    destroy(t, &p);
}
static void tokens_and_reports(vireo_mysql_thread_t *t)
{
    vireo_mysql_pool_t *p = create(t, 1); vireo_mysql_pool_error_t e;
    vireo_mysql_lease_t l = {0}; vireo_mysql_pool_acquisition_t a = {true};
    CHECK(vireo_mysql_pool_acquire(t, p, 60001, &l, &a, &e), VIREO_RESULT_RANGE); assert(!a.acquired);
    CHECK(vireo_mysql_pool_acquire(NULL, p, 0, &l, &a, &e), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_mysql_pool_acquire(t, p, 0, NULL, &a, &e), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_mysql_pool_acquire(t, p, 0, &l, NULL, &e), VIREO_RESULT_INVALID_ARGUMENT);
    fail_lock = 1; CHECK(vireo_mysql_pool_acquire(t, p, 0, &l, &a, &e), VIREO_RESULT_INTERNAL);
    assert(!a.acquired && e.stage == VIREO_MYSQL_POOL_STAGE_LOCK);
    fail_unlock = 1; CHECK(vireo_mysql_pool_acquire(t, p, 0, &l, &a, &e), VIREO_RESULT_INTERNAL);
    assert(a.acquired && l.owner == p && e.stage == VIREO_MYSQL_POOL_STAGE_UNLOCK);
    vireo_mysql_lease_t stale = l, bad = l;
    vireo_mysql_connection_t *c = NULL;
    CHECK(vireo_mysql_pool_borrow(t, p, &l, &c), VIREO_OK);
    CHECK(vireo_mysql_connection_destroy(t, &c), VIREO_RESULT_BUSY); assert(c != NULL);
    bad.generation = 0; CHECK(vireo_mysql_pool_borrow(t, p, &bad, &c), VIREO_RESULT_INVALID_ARGUMENT);
    bad = l; bad.slot = 1; CHECK(vireo_mysql_pool_borrow(t, p, &bad, &c), VIREO_RESULT_INVALID_ARGUMENT);
    bad = l; ++bad.generation; CHECK(vireo_mysql_pool_borrow(NULL, p, &bad, &c), VIREO_RESULT_NOT_FOUND);
    CHECK(vireo_mysql_pool_borrow(NULL, p, &l, &c), VIREO_RESULT_INVALID_ARGUMENT);
    vireo_mysql_pool_release_t r = {true, true};
    c->statement_count = 1;
    CHECK(vireo_mysql_pool_release(t, p, &l, VIREO_MYSQL_POOL_RECYCLE, &r, &e), VIREO_RESULT_BUSY);
    assert(!r.released && l.owner == p); c->statement_count = 0;
    fail_signal = 1;
    CHECK(vireo_mysql_pool_release(t, p, &l, VIREO_MYSQL_POOL_RECYCLE, &r, &e), VIREO_RESULT_INTERNAL);
    assert(r.released && r.reusable && l.owner == NULL);
    CHECK(vireo_mysql_pool_borrow(NULL, p, &stale, &c), VIREO_RESULT_NOT_FOUND);
    CHECK(vireo_mysql_pool_release(NULL, NULL, &l, VIREO_MYSQL_POOL_RECYCLE, &r, &e), VIREO_OK);
    assert(!r.released && !r.reusable);
    for (int i = 1; i <= 2; ++i) {
        l = acquire(t, p); restore_failure = i; fail_signal = 1;
        CHECK(vireo_mysql_pool_release(t, p, &l, VIREO_MYSQL_POOL_RECYCLE, &r, &e), VIREO_RESULT_DATABASE);
        assert(r.released && !r.reusable && e.database.mysql_code == 2013 && e.pthread_code == 0);
        restore_failure = 0; vireo_mysql_pool_refill_t f = {true};
        fail_open = open_calls + 1;
        CHECK(vireo_mysql_pool_refill(t, p, &f, &e), VIREO_RESULT_DATABASE); assert(!f.restored);
        fail_open = 0; fail_signal = 1;
        CHECK(vireo_mysql_pool_refill(t, p, &f, &e), VIREO_RESULT_INTERNAL); assert(f.restored);
    }
    l = acquire(t, p); CHECK(vireo_mysql_pool_borrow(t, p, &l, &c), VIREO_OK); c->unusable = true;
    CHECK(vireo_mysql_pool_release(t, p, &l, VIREO_MYSQL_POOL_RECYCLE, &r, &e), VIREO_OK);
    assert(r.released && !r.reusable);
    vireo_mysql_pool_refill_t f;
    CHECK(vireo_mysql_pool_refill(t, p, &f, NULL), VIREO_OK);
    CHECK(vireo_mysql_pool_refill(t, p, &f, NULL), VIREO_RESULT_BUSY); assert(!f.restored);
    p->slots[0].generation = UINT64_MAX - 1;
    l = acquire(t, p); assert(l.generation == UINT64_MAX);
    CHECK(vireo_mysql_pool_release(t, p, &l, VIREO_MYSQL_POOL_RECYCLE, &r, NULL), VIREO_OK);
    CHECK(vireo_mysql_pool_acquire(t, p, 1, &l, &a, NULL), VIREO_RESULT_OVERFLOW);
    vireo_mysql_pool_info_t info; CHECK(vireo_mysql_pool_inspect(p, &info), VIREO_OK);
    assert(info.retired == 1 && info.high_watermark == 1);
    destroy(t, &p);
}
static void waits_and_destroy(vireo_mysql_thread_t *t)
{
    vireo_mysql_pool_t *p = create(t, 1); vireo_mysql_lease_t l = acquire(t, p), out = {0};
    vireo_mysql_pool_acquisition_t a; vireo_mysql_pool_error_t e;
    CHECK(vireo_mysql_pool_destroy(t, &p, &e), VIREO_RESULT_BUSY);
    CHECK(vireo_mysql_pool_acquire(t, p, 0, &out, &a, &e), VIREO_RESULT_BUSY);
    p->waiters = 1; CHECK(vireo_mysql_pool_acquire(t, p, 1, &out, &a, &e), VIREO_RESULT_BUSY); p->waiters = 0;
    clock_failure = 1; CHECK(vireo_mysql_pool_acquire(t, p, 1, &out, &a, &e), VIREO_RESULT_IO);
    assert(e.system_error == EIO); clock_failure = 0;
    waits = 0; wait_mode = 0;
    CHECK(vireo_mysql_pool_acquire(t, p, 100, &out, &a, &e), VIREO_RESULT_TIMEOUT);
    assert(waits == 3 && p->waiters == 0);
    wait_mode = 1; CHECK(vireo_mysql_pool_acquire(t, p, 1, &out, &a, &e), VIREO_RESULT_INTERNAL);
    assert(e.stage == VIREO_MYSQL_POOL_STAGE_WAIT && p->waiters == 0);
    wait_mode = 4; waits = 0; CHECK(vireo_mysql_pool_acquire(t, p, 1, &out, &a, &e), VIREO_RESULT_IO); clock_failure = 0;
    wait_mode = 3;
    CHECK(vireo_mysql_pool_acquire(t, p, 1, &out, &a, &e), VIREO_RESULT_TIMEOUT);
    assert(!a.acquired); p->slots[0].state = MYSQL_SLOT_LEASED;
    wait_mode = 2;
    CHECK(vireo_mysql_pool_acquire(t, p, 1, &out, &a, &e), VIREO_RESULT_CANCELLED);
    bool closed = true; fail_signal = 1;
    CHECK(vireo_mysql_pool_close(p, &closed, &e), VIREO_RESULT_INTERNAL); assert(closed);
    CHECK(vireo_mysql_pool_destroy(t, &p, &e), VIREO_RESULT_BUSY);
    vireo_mysql_pool_release_t r;
    CHECK(vireo_mysql_pool_release(t, p, &l, VIREO_MYSQL_POOL_RECYCLE, &r, NULL), VIREO_OK);
    assert(r.released && !r.reusable);
    observed = NULL; fail_destroy = 1;
    CHECK(vireo_mysql_pool_destroy(t, &p, &e), VIREO_RESULT_INTERNAL);
    assert(p != NULL && p->cond_destroyed && live_connections == 0);
    vireo_mysql_pool_info_t info;
    CHECK(vireo_mysql_pool_inspect(p, &info), VIREO_RESULT_CANCELLED);
    CHECK(vireo_mysql_pool_close(p, &closed, &e), VIREO_RESULT_CANCELLED); assert(!closed);
    CHECK(vireo_mysql_pool_destroy(t, &p, &e), VIREO_OK);
    CHECK(vireo_mysql_pool_destroy(NULL, &p, NULL), VIREO_OK);
    CHECK(vireo_mysql_pool_destroy(NULL, NULL, NULL), VIREO_RESULT_INVALID_ARGUMENT);
}

static void invalid_outputs(vireo_mysql_thread_t *t)
{
    vireo_mysql_pool_t *p = create(t, 1); vireo_mysql_pool_error_t e;
    vireo_mysql_pool_options_t o = options();
    CHECK(vireo_mysql_pool_create(t, &o, &p, &e), VIREO_RESULT_INVALID_ARGUMENT);
    vireo_mysql_lease_t l = {0}; vireo_mysql_pool_acquisition_t a;
    CHECK(vireo_mysql_pool_acquire(t, NULL, 0, &l, &a, &e), VIREO_RESULT_INVALID_ARGUMENT);
    vireo_mysql_connection_t *c = NULL;
    CHECK(vireo_mysql_pool_borrow(t, p, &l, &c), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_mysql_pool_borrow(t, p, NULL, &c), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_mysql_pool_borrow(t, NULL, &l, &c), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_mysql_pool_borrow(t, p, &l, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    vireo_mysql_pool_release_t r = {true, true};
    CHECK(vireo_mysql_pool_release(t, p, NULL, VIREO_MYSQL_POOL_RECYCLE, &r, &e), VIREO_RESULT_INVALID_ARGUMENT);
    assert(!r.released && !r.reusable);
    CHECK(vireo_mysql_pool_release(t, p, &l, VIREO_MYSQL_POOL_RECYCLE, NULL, &e), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_mysql_pool_release(t, p, &l, (vireo_mysql_pool_disposition_t)99, &r, &e), VIREO_RESULT_INVALID_ARGUMENT);
    l.slot = 1;
    CHECK(vireo_mysql_pool_release(t, p, &l, VIREO_MYSQL_POOL_RECYCLE, &r, &e), VIREO_RESULT_INVALID_ARGUMENT);
    vireo_mysql_pool_refill_t f = {true};
    CHECK(vireo_mysql_pool_refill(t, NULL, &f, &e), VIREO_RESULT_INVALID_ARGUMENT); assert(!f.restored);
    CHECK(vireo_mysql_pool_refill(NULL, p, &f, &e), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_mysql_pool_refill(t, p, NULL, &e), VIREO_RESULT_INVALID_ARGUMENT);
    vireo_mysql_pool_info_t info = {.capacity=999};
    CHECK(vireo_mysql_pool_inspect(NULL, &info), VIREO_RESULT_INVALID_ARGUMENT); assert(info.capacity == 999);
    CHECK(vireo_mysql_pool_inspect(p, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    fail_unlock = 1; CHECK(vireo_mysql_pool_inspect(p, &info), VIREO_RESULT_INTERNAL); assert(info.capacity == 999);
    bool closed = true;
    CHECK(vireo_mysql_pool_close(NULL, &closed, &e), VIREO_RESULT_INVALID_ARGUMENT); assert(!closed);
    CHECK(vireo_mysql_pool_close(p, NULL, &e), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_mysql_pool_destroy(NULL, &p, &e), VIREO_RESULT_INVALID_ARGUMENT);
    l = acquire(t, p); p->max_waiters = 0;
    vireo_mysql_lease_t out = {0};
    CHECK(vireo_mysql_pool_acquire(t, p, 100, &out, &a, &e), VIREO_RESULT_BUSY);
    fail_unlock = 1;
    CHECK(vireo_mysql_pool_release(t, p, &l, VIREO_MYSQL_POOL_RECYCLE, &r, &e), VIREO_RESULT_INTERNAL);
    assert(r.released && !r.reusable && l.owner == NULL && p->slots[0].state == MYSQL_SLOT_RETURNING);
    /* 已停止所有共享访问，模型明确unlock已成功：只为释放测试资源手工完成预约。
     * 这不是公共API同步异常自动恢复承诺。 */
    p->slots[0].state = MYSQL_SLOT_IDLE;
    fail_unlock = 1;
    CHECK(vireo_mysql_pool_close(p, &closed, &e), VIREO_RESULT_INTERNAL); assert(closed);
    observed = NULL; fail_cond_destroy = 1;
    CHECK(vireo_mysql_pool_destroy(t, &p, &e), VIREO_RESULT_INTERNAL);
    assert(p != NULL && p->destroying && !p->cond_destroyed);
    CHECK(vireo_mysql_pool_acquire(t, p, 0, &out, &a, &e), VIREO_RESULT_CANCELLED);
    CHECK(vireo_mysql_pool_borrow(t, p, &out, &c), VIREO_RESULT_CANCELLED);
    out = (vireo_mysql_lease_t){p, 0, 1};
    CHECK(vireo_mysql_pool_release(t, p, &out, VIREO_MYSQL_POOL_RECYCLE, &r, &e), VIREO_RESULT_CANCELLED);
    CHECK(vireo_mysql_pool_refill(t, p, &f, &e), VIREO_RESULT_CANCELLED);
    CHECK(vireo_mysql_pool_destroy(t, &p, &e), VIREO_OK);
}

int main(void)
{
    struct sigaction sa = {0}; sa.sa_handler = SIG_IGN;
    assert(sigemptyset(&sa.sa_mask) == 0 && sigaction(SIGPIPE, &sa, NULL) == 0);
    vireo_mysql_runtime_t *runtime = NULL; vireo_mysql_thread_t *t = NULL;
    vireo_mysql_ops_t ops = vireo_mysql_native_ops; ops.allocate = allocate; ops.release = release_memory;
    CHECK(vireo_mysql_runtime_create_with_ops(&runtime, NULL, &ops), VIREO_OK);
    CHECK(vireo_mysql_thread_attach(runtime, &t, NULL), VIREO_OK);
    construction(t); tokens_and_reports(t); waits_and_destroy(t); invalid_outputs(t);
    vireo_mysql_pool_t *p = create(t, 1); vireo_mysql_lease_t l = acquire(t, p); vireo_mysql_pool_release_t report;
    CHECK(vireo_mysql_pool_release(t, p, &l, VIREO_MYSQL_POOL_DISCARD, &report, NULL), VIREO_OK);
    CHECK(vireo_mysql_thread_detach(&t), VIREO_OK);
    CHECK(vireo_mysql_runtime_destroy(&runtime), VIREO_RESULT_BUSY);
    CHECK(vireo_mysql_thread_attach(runtime, &t, NULL), VIREO_OK); destroy(t, &p);
    CHECK(vireo_mysql_thread_detach(&t), VIREO_OK);
    CHECK(vireo_mysql_runtime_destroy(&runtime), VIREO_OK);
    assert(allocations == 0 && live_connections == 0 && disposed > 0 && wipe_checks > 10);
    puts("PASS pool own: checked layout/budget, 64 slots, staged rollback, tokens/retirement, reports/primary diagnosis, bounded deadline/spurious wake, staged destroy, runtime pin, allocation balance");
    return 0;
}
