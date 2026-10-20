#define _POSIX_C_SOURCE 200809L
#include "mysql_pool_internal.h"
#include <vireo/base/checked.h>
#include <errno.h>
#include <string.h>

const vireo_mysql_pool_ops_t vireo_mysql_pool_native_ops = {
    pthread_mutex_init, pthread_mutex_destroy, pthread_mutex_lock, pthread_mutex_unlock,
    pthread_condattr_init, pthread_condattr_setclock, pthread_condattr_destroy,
    pthread_cond_init, pthread_cond_destroy, pthread_cond_timedwait,
    pthread_cond_broadcast, clock_gettime, vireo_mysql_connection_open,
    vireo_mysql_connection_restore, vireo_mysql_connection_dispose
};
static vireo_result_t finish(int saved, vireo_result_t result)
{
    errno = saved;
    return result;
}
static void reset_error(vireo_mysql_pool_error_t *e)
{
    if (e != NULL) { *e = (vireo_mysql_pool_error_t){0}; }
}
static void sync_error(vireo_mysql_pool_error_t *e, vireo_mysql_pool_stage_t stage, int code)
{
    if (e != NULL && e->stage == VIREO_MYSQL_POOL_STAGE_NONE) {
        e->stage = stage;
        e->pthread_code = code;
    }
}
static void database_error(vireo_mysql_pool_error_t *e, vireo_mysql_pool_stage_t stage,
    const vireo_mysql_error_t *database)
{
    if (e != NULL) { e->stage = stage; e->database = *database; }
}
static vireo_result_t lock_pool(vireo_mysql_pool_t *p, vireo_mysql_pool_error_t *e)
{
    int code = p->ops.lock(&p->mutex);
    if (code == 0) { return VIREO_OK; }
    sync_error(e, VIREO_MYSQL_POOL_STAGE_LOCK, code);
    return VIREO_RESULT_INTERNAL;
}
static vireo_result_t unlock_pool(vireo_mysql_pool_t *p, vireo_result_t result,
    vireo_mysql_pool_error_t *e)
{
    int code = p->ops.unlock(&p->mutex);
    if (code != 0) {
        sync_error(e, VIREO_MYSQL_POOL_STAGE_UNLOCK, code);
        if (result == VIREO_OK) { result = VIREO_RESULT_INTERNAL; }
    }
    return result;
}
static vireo_result_t notify(vireo_mysql_pool_t *p, vireo_result_t result,
    vireo_mysql_pool_error_t *e)
{
    int code = p->ops.broadcast(&p->cond);
    if (code != 0) {
        sync_error(e, VIREO_MYSQL_POOL_STAGE_SIGNAL, code);
        if (result == VIREO_OK) { result = VIREO_RESULT_INTERNAL; }
    }
    return result;
}
static bool guard(vireo_mysql_thread_t *t, const vireo_mysql_pool_t *p)
{
    return vireo_mysql_valid_guard(t) && t->runtime == p->runtime;
}
static bool empty(const vireo_mysql_lease_t *l)
{
    return l->owner == NULL && l->slot == 0 && l->generation == 0;
}
static void wipe(vireo_mysql_pool_t *p)
{
    volatile unsigned char *s = (volatile unsigned char *)p->strings;
    for (size_t i = 0; i < p->string_bytes; ++i) { s[i] = 0; }
}
static bool reserve_pool(vireo_mysql_runtime_t *r)
{
    size_t n = atomic_load_explicit(&r->pools, memory_order_relaxed);
    while (n != SIZE_MAX) {
        if (atomic_compare_exchange_weak_explicit(&r->pools, &n, n + 1,
                memory_order_relaxed, memory_order_relaxed)) { return true; }
    }
    return false;
}
static void unreserve_pool(vireo_mysql_runtime_t *r)
{
    (void)atomic_fetch_sub_explicit(&r->pools, 1, memory_order_relaxed);
}
static bool valid_ops(const vireo_mysql_pool_ops_t *o)
{
    return o != NULL && o->mutex_init != NULL && o->mutex_destroy != NULL &&
        o->lock != NULL && o->unlock != NULL && o->attr_init != NULL &&
        o->attr_clock != NULL && o->attr_destroy != NULL && o->cond_init != NULL &&
        o->cond_destroy != NULL && o->wait != NULL && o->broadcast != NULL &&
        o->clock_now != NULL && o->open != NULL && o->restore != NULL && o->dispose != NULL;
}
vireo_result_t vireo_mysql_pool_create_with_ops(vireo_mysql_thread_t *t,
    const vireo_mysql_pool_options_t *o, vireo_mysql_pool_t **out,
    vireo_mysql_pool_error_t *e, const vireo_mysql_pool_ops_t *ops)
{
    int saved = errno;
    reset_error(e);
    if (!vireo_mysql_valid_guard(t) || o == NULL || out == NULL || *out != NULL ||
        o->capacity == 0 || o->max_memory_bytes == 0 || !valid_ops(ops)) {
        return finish(saved, VIREO_RESULT_INVALID_ARGUMENT);
    }
    vireo_result_t result = vireo_mysql_validate_options(&o->connection);
    if (result != VIREO_OK) { return finish(saved, result); }
    size_t slot_offset, bytes, strings_offset, string_bytes = 0;
    const char *values[] = {o->connection.unix_socket, o->connection.username,
        o->connection.password, o->connection.database};
    if (vireo_checked_size_align_up(sizeof(vireo_mysql_pool_t),
            _Alignof(vireo_mysql_pool_slot_t), &slot_offset) != VIREO_OK ||
        vireo_checked_size_mul(o->capacity, sizeof(vireo_mysql_pool_slot_t), &bytes) != VIREO_OK ||
        vireo_checked_size_add(slot_offset, bytes, &strings_offset) != VIREO_OK) {
        return finish(saved, VIREO_RESULT_OVERFLOW);
    }
    for (size_t i = 0; i < 4; ++i) {
        if (vireo_checked_size_add(string_bytes, strlen(values[i]) + 1, &string_bytes) != VIREO_OK) {
            return finish(saved, VIREO_RESULT_OVERFLOW);
        }
    }
    if (vireo_checked_size_add(strings_offset, string_bytes, &bytes) != VIREO_OK) {
        return finish(saved, VIREO_RESULT_OVERFLOW);
    }
    if (o->capacity > VIREO_MYSQL_POOL_CAPACITY_MAX || o->max_waiters > VIREO_MYSQL_POOL_WAITERS_MAX ||
        o->max_memory_bytes > VIREO_MYSQL_POOL_MEMORY_MAX || bytes > o->max_memory_bytes) {
        return finish(saved, VIREO_RESULT_RANGE);
    }
    vireo_mysql_runtime_t *r = t->runtime;
    if (!reserve_pool(r)) { return finish(saved, VIREO_RESULT_OVERFLOW); }
    vireo_mysql_pool_t *p = r->ops.allocate(bytes);
    if (p == NULL) {
        if (e != NULL) { e->stage = VIREO_MYSQL_POOL_STAGE_ALLOCATE; }
        unreserve_pool(r);
        return finish(saved, VIREO_RESULT_NO_MEMORY);
    }
    memset(p, 0, bytes);
    p->runtime = r; p->ops = *ops; p->options = o->connection;
    p->capacity = o->capacity; p->max_waiters = o->max_waiters;
    p->allocated_bytes = bytes; p->state = VIREO_MYSQL_POOL_OPEN;
    p->slots = (vireo_mysql_pool_slot_t *)((unsigned char *)p + slot_offset);
    p->strings = (char *)p + strings_offset; p->string_bytes = string_bytes;
    const char **dest[] = {&p->options.unix_socket, &p->options.username,
        &p->options.password, &p->options.database};
    char *cursor = p->strings;
    for (size_t i = 0; i < 4; ++i) {
        size_t n = strlen(values[i]) + 1;
        memcpy(cursor, values[i], n); *dest[i] = cursor; cursor += n;
    }
    bool mutex_ready = false, attr_ready = false, cond_ready = false;
    pthread_condattr_t attr;
    size_t opened = 0;
    int code = ops->mutex_init(&p->mutex, NULL);
    if (code != 0) { goto sync_fail; }
    mutex_ready = true;
    code = ops->attr_init(&attr);
    if (code != 0) { goto sync_fail; }
    attr_ready = true;
    code = ops->attr_clock(&attr, CLOCK_MONOTONIC);
    if (code != 0) { goto sync_fail; }
    code = ops->cond_init(&p->cond, &attr);
    if (code != 0) { goto sync_fail; }
    cond_ready = true;
    code = ops->attr_destroy(&attr);
    if (code != 0) { goto sync_fail; }
    attr_ready = false;
    for (; opened < p->capacity; ++opened) {
        vireo_mysql_error_t database = {0};
        result = ops->open(t, &p->options, &p->slots[opened].connection, &database);
        if (result != VIREO_OK) {
            database_error(e, VIREO_MYSQL_POOL_STAGE_OPEN, &database);
            goto fail;
        }
        p->slots[opened].connection->pool = p;
        p->slots[opened].connection->pool_slot = opened;
        p->slots[opened].state = MYSQL_SLOT_IDLE;
    }
    *out = p;
    return finish(saved, VIREO_OK);
sync_fail:
    sync_error(e, VIREO_MYSQL_POOL_STAGE_INITIALIZE, code);
    result = code == ENOMEM ? VIREO_RESULT_NO_MEMORY : VIREO_RESULT_INTERNAL;
fail:
    while (opened > 0) { ops->dispose(p->slots[--opened].connection); }
    if (cond_ready) { (void)ops->cond_destroy(&p->cond); }
    if (attr_ready) { (void)ops->attr_destroy(&attr); }
    if (mutex_ready) { (void)ops->mutex_destroy(&p->mutex); }
    wipe(p); r->ops.release(p); unreserve_pool(r);
    return finish(saved, result);
}
vireo_result_t vireo_mysql_pool_create(vireo_mysql_thread_t *t,
    const vireo_mysql_pool_options_t *o, vireo_mysql_pool_t **out, vireo_mysql_pool_error_t *e)
{
    return vireo_mysql_pool_create_with_ops(t, o, out, e, &vireo_mysql_pool_native_ops);
}
static vireo_result_t now(vireo_mysql_pool_t *p, struct timespec *time,
    vireo_mysql_pool_error_t *e)
{
    if (p->ops.clock_now(CLOCK_MONOTONIC, time) == 0) { return VIREO_OK; }
    if (e != NULL && e->stage == VIREO_MYSQL_POOL_STAGE_NONE) {
        e->stage = VIREO_MYSQL_POOL_STAGE_CLOCK; e->system_error = errno;
    }
    return VIREO_RESULT_IO;
}
static bool expired(const struct timespec *time, const struct timespec *deadline)
{
    return time->tv_sec > deadline->tv_sec ||
        (time->tv_sec == deadline->tv_sec && time->tv_nsec >= deadline->tv_nsec);
}
vireo_result_t vireo_mysql_pool_acquire(vireo_mysql_thread_t *t, vireo_mysql_pool_t *p,
    uint32_t timeout_ms, vireo_mysql_lease_t *out, vireo_mysql_pool_acquisition_t *report,
    vireo_mysql_pool_error_t *e)
{
    int saved = errno;
    reset_error(e);
    if (report != NULL) { *report = (vireo_mysql_pool_acquisition_t){0}; }
    if (p == NULL || out == NULL || report == NULL || !empty(out) || !guard(t, p)) {
        return finish(saved, VIREO_RESULT_INVALID_ARGUMENT);
    }
    if (timeout_ms > VIREO_MYSQL_POOL_WAIT_MS_MAX) { return finish(saved, VIREO_RESULT_RANGE); }
    if (p->destroying) { return finish(saved, VIREO_RESULT_CANCELLED); }
    vireo_result_t result = lock_pool(p, e);
    if (result != VIREO_OK) { return finish(saved, result); }
    bool waiting = false;
    struct timespec deadline = {0};
    for (;;) {
        if (p->state == VIREO_MYSQL_POOL_CLOSED) { result = VIREO_RESULT_CANCELLED; break; }
        if (waiting) {
            struct timespec time;
            result = now(p, &time, e);
            if (result != VIREO_OK) { break; }
            if (expired(&time, &deadline)) { result = VIREO_RESULT_TIMEOUT; break; }
        }
        size_t retired = 0, idle = p->capacity;
        for (size_t i = 0; i < p->capacity; ++i) {
            if (p->slots[i].state == MYSQL_SLOT_IDLE && idle == p->capacity) { idle = i; }
            if (p->slots[i].state == MYSQL_SLOT_RETIRED) { ++retired; }
        }
        if (idle != p->capacity) {
            vireo_mysql_pool_slot_t *slot = &p->slots[idle];
            ++slot->generation; /* IDLE不含UINT64_MAX，归还耗尽代际永久退休。 */
            slot->state = MYSQL_SLOT_LEASED; slot->borrower = pthread_self();
            ++p->leased;
            if (p->leased > p->high_watermark) { p->high_watermark = p->leased; }
            *out = (vireo_mysql_lease_t){p, idle, slot->generation}; report->acquired = true;
            result = VIREO_OK; break;
        }
        if (retired == p->capacity) { result = VIREO_RESULT_OVERFLOW; break; }
        if (!waiting) {
            if (timeout_ms == 0 || p->waiters == p->max_waiters) { result = VIREO_RESULT_BUSY; break; }
            result = now(p, &deadline, e);
            if (result != VIREO_OK) { break; }
            /* CLOCK_MONOTONIC正常值为非负；先核time_t上界，避免绝对期限加法溢出。 */
            uintmax_t seconds = (uintmax_t)(timeout_ms / 1000U) + 1U;
            uintmax_t limit = (UINTMAX_C(1) << (sizeof(time_t) * 8U - 1U)) - 1U;
            if (deadline.tv_sec < 0 || (uintmax_t)deadline.tv_sec > limit - seconds) {
                if (e != NULL) { e->stage = VIREO_MYSQL_POOL_STAGE_CLOCK; }
                result = VIREO_RESULT_IO; break;
            }
            deadline.tv_sec += (time_t)(timeout_ms / 1000U);
            deadline.tv_nsec += (long)(timeout_ms % 1000U) * 1000000L;
            if (deadline.tv_nsec >= 1000000000L) { ++deadline.tv_sec; deadline.tv_nsec -= 1000000000L; }
            ++p->waiters; waiting = true;
        }
        int code = p->ops.wait(&p->cond, &p->mutex, &deadline);
        if (code != 0 && code != ETIMEDOUT) {
            sync_error(e, VIREO_MYSQL_POOL_STAGE_WAIT, code); result = VIREO_RESULT_INTERNAL; break;
        }
        /* 即使ETIMEDOUT也重查关闭/实际单调期限；虚假唤醒不重算deadline。 */
    }
    if (waiting) { --p->waiters; }
    return finish(saved, unlock_pool(p, result, e));
}
static vireo_result_t identity(vireo_mysql_thread_t *t, vireo_mysql_pool_t *p,
    const vireo_mysql_lease_t *l)
{
    if (l->owner != p || l->generation == 0 || l->slot >= p->capacity) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    const vireo_mysql_pool_slot_t *slot = &p->slots[l->slot];
    if (slot->state != MYSQL_SLOT_LEASED || slot->generation != l->generation) {
        return VIREO_RESULT_NOT_FOUND;
    }
    if (!guard(t, p) || pthread_equal(slot->borrower, pthread_self()) == 0) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    return VIREO_OK;
}
vireo_result_t vireo_mysql_pool_borrow(vireo_mysql_thread_t *t, vireo_mysql_pool_t *p,
    const vireo_mysql_lease_t *l, vireo_mysql_connection_t **out)
{
    int saved = errno;
    if (p == NULL || l == NULL || out == NULL) { return finish(saved, VIREO_RESULT_INVALID_ARGUMENT); }
    if (p->destroying) { return finish(saved, VIREO_RESULT_CANCELLED); }
    vireo_result_t result = lock_pool(p, NULL);
    if (result != VIREO_OK) { return finish(saved, result); }
    result = identity(t, p, l);
    vireo_mysql_connection_t *c = result == VIREO_OK ? p->slots[l->slot].connection : NULL;
    result = unlock_pool(p, result, NULL);
    if (result == VIREO_OK) { *out = c; }
    return finish(saved, result);
}
bool vireo_mysql_pool_connection_access(const vireo_mysql_thread_t *t,
    const vireo_mysql_connection_t *c)
{
    int saved = errno;
    vireo_mysql_pool_t *p = c->pool;
    bool ok = false;
    if (!p->destroying && lock_pool(p, NULL) == VIREO_OK) {
        const vireo_mysql_pool_slot_t *slot = &p->slots[c->pool_slot];
        ok = slot->connection == c && slot->state == MYSQL_SLOT_LEASED &&
            t->runtime == p->runtime && pthread_equal(slot->borrower, pthread_self()) != 0;
        if (unlock_pool(p, VIREO_OK, NULL) != VIREO_OK) { ok = false; }
    }
    errno = saved;
    return ok;
}
vireo_result_t vireo_mysql_pool_release(vireo_mysql_thread_t *t, vireo_mysql_pool_t *p,
    vireo_mysql_lease_t *l, vireo_mysql_pool_disposition_t disposition,
    vireo_mysql_pool_release_t *report, vireo_mysql_pool_error_t *e)
{
    int saved = errno;
    reset_error(e);
    if (report != NULL) { *report = (vireo_mysql_pool_release_t){0}; }
    if (l == NULL || report == NULL ||
        (disposition != VIREO_MYSQL_POOL_RECYCLE && disposition != VIREO_MYSQL_POOL_DISCARD)) {
        return finish(saved, VIREO_RESULT_INVALID_ARGUMENT);
    }
    if (empty(l)) { return finish(saved, VIREO_OK); }
    if (p == NULL) { return finish(saved, VIREO_RESULT_INVALID_ARGUMENT); }
    if (p->destroying) { return finish(saved, VIREO_RESULT_CANCELLED); }
    vireo_result_t result = lock_pool(p, e);
    if (result != VIREO_OK) { return finish(saved, result); }
    result = identity(t, p, l);
    if (result != VIREO_OK) { return finish(saved, unlock_pool(p, result, e)); }
    vireo_mysql_pool_slot_t *slot = &p->slots[l->slot];
    vireo_mysql_connection_t *c = slot->connection;
    if (c->statement_count != 0) { return finish(saved, unlock_pool(p, VIREO_RESULT_BUSY, e)); }
    bool recycle = disposition == VIREO_MYSQL_POOL_RECYCLE && !c->unusable &&
        p->state == VIREO_MYSQL_POOL_OPEN && slot->generation != UINT64_MAX;
    slot->state = MYSQL_SLOT_RETURNING; --p->leased;
    *l = (vireo_mysql_lease_t){0}; report->released = true;
    result = unlock_pool(p, VIREO_OK, e);
    if (result != VIREO_OK) { return finish(saved, result); }
    if (recycle) {
        vireo_mysql_error_t database = {0};
        result = p->ops.restore(c, p->options.database, &database);
        if (result != VIREO_OK) {
            database_error(e, database.stage == VIREO_MYSQL_STAGE_CONNECTION_RESET ?
                VIREO_MYSQL_POOL_STAGE_RESET : VIREO_MYSQL_POOL_STAGE_SESSION, &database);
            recycle = false;
        }
    }
    if (!recycle) { p->ops.dispose(c); c = NULL; }
    vireo_result_t locked = lock_pool(p, e);
    if (locked != VIREO_OK) { return finish(saved, result == VIREO_OK ? locked : result); }
    if (c != NULL && p->state == VIREO_MYSQL_POOL_CLOSED) {
        locked = unlock_pool(p, VIREO_OK, e);
        if (locked != VIREO_OK) { return finish(saved, result == VIREO_OK ? locked : result); }
        p->ops.dispose(c); c = NULL;
        locked = lock_pool(p, e);
        if (locked != VIREO_OK) { return finish(saved, result == VIREO_OK ? locked : result); }
    }
    slot->connection = c;
    slot->state = c != NULL ? MYSQL_SLOT_IDLE :
        (slot->generation == UINT64_MAX ? MYSQL_SLOT_RETIRED : MYSQL_SLOT_VACANT);
    report->reusable = c != NULL;
    result = notify(p, result, e);
    return finish(saved, unlock_pool(p, result, e));
}
vireo_result_t vireo_mysql_pool_refill(vireo_mysql_thread_t *t, vireo_mysql_pool_t *p,
    vireo_mysql_pool_refill_t *report, vireo_mysql_pool_error_t *e)
{
    int saved = errno;
    reset_error(e);
    if (report != NULL) { *report = (vireo_mysql_pool_refill_t){0}; }
    if (p == NULL || report == NULL || !guard(t, p)) { return finish(saved, VIREO_RESULT_INVALID_ARGUMENT); }
    if (p->destroying) { return finish(saved, VIREO_RESULT_CANCELLED); }
    vireo_result_t result = lock_pool(p, e);
    if (result != VIREO_OK) { return finish(saved, result); }
    if (p->state == VIREO_MYSQL_POOL_CLOSED) {
        return finish(saved, unlock_pool(p, VIREO_RESULT_CANCELLED, e));
    }
    size_t i = 0;
    for (; i < p->capacity && p->slots[i].state != MYSQL_SLOT_VACANT; ++i) { }
    if (i == p->capacity) { return finish(saved, unlock_pool(p, VIREO_RESULT_BUSY, e)); }
    vireo_mysql_pool_slot_t *slot = &p->slots[i]; slot->state = MYSQL_SLOT_REFILLING;
    result = unlock_pool(p, VIREO_OK, e);
    if (result != VIREO_OK) { return finish(saved, result); }
    vireo_mysql_error_t database = {0};
    vireo_mysql_connection_t *c = NULL;
    result = p->ops.open(t, &p->options, &c, &database);
    if (result != VIREO_OK) { database_error(e, VIREO_MYSQL_POOL_STAGE_OPEN, &database); }
    vireo_result_t locked = lock_pool(p, e);
    if (locked != VIREO_OK) {
        if (c != NULL) { p->ops.dispose(c); }
        return finish(saved, result == VIREO_OK ? locked : result);
    }
    if (p->state == VIREO_MYSQL_POOL_CLOSED) {
        if (c != NULL) {
            locked = unlock_pool(p, VIREO_OK, e);
            if (locked != VIREO_OK) { return finish(saved, locked); }
            p->ops.dispose(c); c = NULL;
            locked = lock_pool(p, e);
            if (locked != VIREO_OK) { return finish(saved, locked); }
        }
        if (result == VIREO_OK) { result = VIREO_RESULT_CANCELLED; }
    }
    if (c != NULL) { c->pool = p; c->pool_slot = i; }
    slot->connection = c; slot->state = c != NULL ? MYSQL_SLOT_IDLE : MYSQL_SLOT_VACANT;
    report->restored = c != NULL;
    result = notify(p, result, e);
    return finish(saved, unlock_pool(p, result, e));
}
vireo_result_t vireo_mysql_pool_inspect(const vireo_mysql_pool_t *pool, vireo_mysql_pool_info_t *out)
{
    int saved = errno;
    if (pool == NULL || out == NULL) { return finish(saved, VIREO_RESULT_INVALID_ARGUMENT); }
    /* const是只读公共视图；内部mutex的逻辑可变性不传播给调用者。 */
    vireo_mysql_pool_t *p = (vireo_mysql_pool_t *)pool;
    if (p->destroying) { return finish(saved, VIREO_RESULT_CANCELLED); }
    vireo_result_t result = lock_pool(p, NULL);
    if (result != VIREO_OK) { return finish(saved, result); }
    vireo_mysql_pool_info_t info = {0};
    info.state = p->state; info.capacity = p->capacity; info.waiters = p->waiters;
    info.max_waiters = p->max_waiters; info.high_watermark = p->high_watermark;
    info.allocated_bytes = p->allocated_bytes;
    for (size_t i = 0; i < p->capacity; ++i) {
        switch (p->slots[i].state) {
        case MYSQL_SLOT_IDLE: ++info.idle; break;
        case MYSQL_SLOT_LEASED: ++info.leased; break;
        case MYSQL_SLOT_RETURNING: ++info.returning; break;
        case MYSQL_SLOT_VACANT: ++info.vacant; break;
        case MYSQL_SLOT_REFILLING: ++info.refilling; break;
        case MYSQL_SLOT_RETIRED: ++info.retired; break;
        }
    }
    result = unlock_pool(p, VIREO_OK, NULL);
    if (result == VIREO_OK) { *out = info; }
    return finish(saved, result);
}
vireo_result_t vireo_mysql_pool_close(vireo_mysql_pool_t *p, bool *closed, vireo_mysql_pool_error_t *e)
{
    int saved = errno;
    reset_error(e);
    if (closed != NULL) { *closed = false; }
    if (p == NULL || closed == NULL) { return finish(saved, VIREO_RESULT_INVALID_ARGUMENT); }
    if (p->destroying) { return finish(saved, VIREO_RESULT_CANCELLED); }
    vireo_result_t result = lock_pool(p, e);
    if (result != VIREO_OK) { return finish(saved, result); }
    p->state = VIREO_MYSQL_POOL_CLOSED; *closed = true;
    result = notify(p, VIREO_OK, e);
    return finish(saved, unlock_pool(p, result, e));
}
vireo_result_t vireo_mysql_pool_destroy(vireo_mysql_thread_t *t,
    vireo_mysql_pool_t **owner, vireo_mysql_pool_error_t *e)
{
    int saved = errno;
    reset_error(e);
    if (owner == NULL) { return finish(saved, VIREO_RESULT_INVALID_ARGUMENT); }
    vireo_mysql_pool_t *p = *owner;
    if (p == NULL) { return finish(saved, VIREO_OK); }
    if (!guard(t, p)) { return finish(saved, VIREO_RESULT_INVALID_ARGUMENT); }
    if (!p->destroying) {
        vireo_result_t result = lock_pool(p, e);
        if (result != VIREO_OK) { return finish(saved, result); }
        bool busy = p->state != VIREO_MYSQL_POOL_CLOSED || p->waiters != 0;
        for (size_t i = 0; i < p->capacity; ++i) {
            vireo_mysql_slot_state_t s = p->slots[i].state;
            if (s == MYSQL_SLOT_LEASED || s == MYSQL_SLOT_RETURNING || s == MYSQL_SLOT_REFILLING) { busy = true; }
        }
        if (busy) { return finish(saved, unlock_pool(p, VIREO_RESULT_BUSY, e)); }
        p->destroying = true;
        result = unlock_pool(p, VIREO_OK, e);
        if (result != VIREO_OK) { return finish(saved, result); }
    }
    for (size_t i = p->capacity; i > 0; --i) {
        vireo_mysql_pool_slot_t *slot = &p->slots[i - 1];
        if (slot->connection != NULL) { p->ops.dispose(slot->connection); slot->connection = NULL; }
    }
    if (!p->cond_destroyed) {
        int code = p->ops.cond_destroy(&p->cond);
        if (code != 0) {
            sync_error(e, VIREO_MYSQL_POOL_STAGE_DESTROY, code);
            return finish(saved, VIREO_RESULT_INTERNAL);
        }
        p->cond_destroyed = true;
    }
    int code = p->ops.mutex_destroy(&p->mutex);
    if (code != 0) {
        sync_error(e, VIREO_MYSQL_POOL_STAGE_DESTROY, code);
        return finish(saved, VIREO_RESULT_INTERNAL);
    }
    vireo_mysql_runtime_t *r = p->runtime;
    wipe(p); r->ops.release(p); unreserve_pool(r); *owner = NULL;
    return finish(saved, VIREO_OK);
}
