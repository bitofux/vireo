/* PROJECT: VIREO; FILE: auth_failure_audit.c; AUTHOR: bitofux; DATE: 2026-10-20.
 * producer一次trylock；consumer条件等待不持锁执行外部工作。 */
#define _POSIX_C_SOURCE 200809L
#include "auth_failure_audit_internal.h"
#include <vireo/base/clock.h>
#include <vireo/base/secure_clear.h>
#include <errno.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

enum counter { QUEUED, TAKEN, RATE, FULL, CONTENTION, CLOSED, DISABLED, DISCARDED, COUNTERS };
struct vireo_auth_failure_audit {
    pthread_mutex_t mutex; /**< 只保护短队列操作和两个桶；无外部调用。 */
    pthread_cond_t changed; /**< 单调条件谓词为closed或(非空且有消费许可)。 */
    vireo_auth_failure_audit_options_t options; /**< 初始化后只读。 */
    size_t head, depth; /**< 环形队列读位置及有效元素数。 */
    bool condition_destroyed; /**< 部分销毁后只重试剩余mutex。 */
    bool closed, disabled; /**< 只在锁内单向推进。 */
    vireo_auth_failure_bucket_t offer, take; /**< 两份独立信用。 */
    _Atomic uint64_t counters[COUNTERS]; /**< lock-free、模2^64，仅观测。 */
    void (*wait_hook)(void *); void *wait_context; /**< 排他配置的本组件测试seam。 */
    vireo_auth_failure_event_t slots[]; /**< 全部自有独立纯值，非有效槽为零。 */
};
static vireo_result_t done(int saved, vireo_result_t rc) { errno=saved; return rc; }
static void count(vireo_auth_failure_audit_t *q, enum counter c, uint64_t n)
{ (void)atomic_fetch_add_explicit(&q->counters[c],n,memory_order_relaxed); }
static void copy_event(vireo_auth_failure_event_t *out, vireo_auth_failure_event_t const *in)
{
    memset(out,0,sizeof(*out)); memcpy(out->request_id,in->request_id,16);
    out->occurred_at_ms=in->occurred_at_ms; out->latency_us=in->latency_us;
    out->action=in->action; out->status=in->status; out->origin=in->origin;
}
static bool valid_event(vireo_auth_failure_event_t const *e)
{
    if (!e || e->action<1 || e->action>4 || (e->origin!=1 && e->origin!=2)) return false;
    unsigned bits=0; for (size_t i=0;i<16;++i) bits|=e->request_id[i];
    if ((e->origin==1 && bits) || (e->origin==2 && !bits)) return false;
    switch(e->status) {
    case 1001: case 1008: case 1104: case 1105: case 1106:
    case 1901: case 1902: case 1906: case 1907: case 1908: return true;
    default: return false;
    }
}
void vireo_auth_failure_bucket_refill(vireo_auth_failure_bucket_t *b,
    uint64_t now, uint64_t burst, uint64_t interval)
{
    if (now<b->last) now=b->last;
    uint64_t const delta=now-b->last;
    uint64_t const tail=b->remainder+delta%interval; /* <2*60e9。 */
    uint64_t const whole=delta/interval+tail/interval; /* interval=1时tail=0。 */
    b->last=now;
    if (whole>=burst-b->tokens) { b->tokens=burst; b->remainder=0; }
    else { b->tokens+=whole; b->remainder=tail%interval; }
}
vireo_result_t vireo_auth_failure_audit_create(vireo_auth_failure_audit_options_t const *o,
    uint64_t now, vireo_auth_failure_audit_t **out)
{
    int const saved=errno;
    if (!o || !out || *out) return done(saved,VIREO_RESULT_INVALID_ARGUMENT);
    if (!o->capacity || o->capacity>1024 || !o->max_memory_bytes || o->max_memory_bytes>1048576 ||
        !o->burst || o->burst>256 || !o->refill_ns || o->refill_ns>UINT64_C(60000000000))
        return done(saved,VIREO_RESULT_RANGE);
    size_t const bytes=sizeof(vireo_auth_failure_audit_t)+o->capacity*sizeof(vireo_auth_failure_event_t);
    if (bytes>o->max_memory_bytes) return done(saved,VIREO_RESULT_RANGE);
    vireo_auth_failure_audit_t *q=calloc(1,bytes);
    if (!q) return done(saved,VIREO_RESULT_NO_MEMORY);
    for (size_t i=0;i<COUNTERS;++i) {
        atomic_init(&q->counters[i],0);
        if (!atomic_is_lock_free(&q->counters[i])) { free(q); return done(saved,VIREO_RESULT_INTERNAL); }
    }
    if (pthread_mutex_init(&q->mutex,NULL)!=0) { free(q); return done(saved,VIREO_RESULT_INTERNAL); }
    pthread_condattr_t attr;
    if (pthread_condattr_init(&attr)!=0) { (void)pthread_mutex_destroy(&q->mutex); free(q); return done(saved,VIREO_RESULT_INTERNAL); }
    int rc=pthread_condattr_setclock(&attr,CLOCK_MONOTONIC);
    if (!rc) rc=pthread_cond_init(&q->changed,&attr);
    (void)pthread_condattr_destroy(&attr);
    if (rc) { (void)pthread_mutex_destroy(&q->mutex); free(q); return done(saved,VIREO_RESULT_INTERNAL); }
    q->options=*o; q->offer=q->take=(vireo_auth_failure_bucket_t){o->burst,0,now};
    *out=q; return done(saved,VIREO_OK);
}
vireo_result_t vireo_auth_failure_audit_try_offer(vireo_auth_failure_audit_t *q,
    vireo_auth_failure_event_t const *e, uint64_t now, vireo_auth_failure_disposition_t *out)
{
    int const saved=errno;
    if (!q || !out || !valid_event(e)) return done(saved,VIREO_RESULT_INVALID_ARGUMENT);
    int const locked=pthread_mutex_trylock(&q->mutex);
    if (locked==EBUSY) { count(q,CONTENTION,1); *out=VIREO_AUTH_FAILURE_DROP_CONTENTION; return done(saved,VIREO_OK); }
    if (locked) return done(saved,VIREO_RESULT_INTERNAL);
    vireo_auth_failure_disposition_t d;
    if (q->disabled) { d=VIREO_AUTH_FAILURE_DROP_DISABLED; count(q,DISABLED,1); }
    else if (q->closed) { d=VIREO_AUTH_FAILURE_DROP_CLOSED; count(q,CLOSED,1); }
    else {
        vireo_auth_failure_bucket_refill(&q->offer,now,q->options.burst,q->options.refill_ns);
        if (!q->offer.tokens) { d=VIREO_AUTH_FAILURE_DROP_RATE; count(q,RATE,1); }
        else if (q->depth==q->options.capacity) { d=VIREO_AUTH_FAILURE_DROP_FULL; count(q,FULL,1); }
        else {
            copy_event(&q->slots[(q->head+q->depth)%q->options.capacity],e);
            ++q->depth; --q->offer.tokens; count(q,QUEUED,1); d=VIREO_AUTH_FAILURE_QUEUED;
            (void)pthread_cond_signal(&q->changed);
        }
    }
    (void)pthread_mutex_unlock(&q->mutex); *out=d; return done(saved,VIREO_OK);
}
vireo_result_t vireo_auth_failure_audit_wait_take(vireo_auth_failure_audit_t *q,
    vireo_auth_failure_event_t *out)
{
    int const saved=errno;
    if (!q || !out) return done(saved,VIREO_RESULT_INVALID_ARGUMENT);
    if (pthread_mutex_lock(&q->mutex)!=0) return done(saved,VIREO_RESULT_INTERNAL);
    vireo_result_t rc=VIREO_OK;
    for (;;) {
        if (q->closed) { rc=VIREO_RESULT_NOT_FOUND; break; }
        uint64_t now=0; rc=vireo_clock_monotonic_now(&now,NULL); if (rc!=VIREO_OK) break;
        vireo_auth_failure_bucket_refill(&q->take,now,q->options.burst,q->options.refill_ns);
        if (q->depth && q->take.tokens) {
            copy_event(out,&q->slots[q->head]);
            (void)vireo_secure_clear(&q->slots[q->head],sizeof(*out));
            q->head=(q->head+1)%q->options.capacity; --q->depth; --q->take.tokens; count(q,TAKEN,1); break;
        }
        int waited;
        if (q->wait_hook) q->wait_hook(q->wait_context);
        if (!q->depth) waited=pthread_cond_wait(&q->changed,&q->mutex);
        else {
            uint64_t const add=q->options.refill_ns-q->take.remainder;
            if (q->take.last>UINT64_MAX-add) { rc=VIREO_RESULT_OVERFLOW; break; }
            uint64_t const until=q->take.last+add;
            struct timespec t={(time_t)(until/UINT64_C(1000000000)),(long)(until%UINT64_C(1000000000))};
            if (t.tv_sec<0 || (uint64_t)t.tv_sec!=until/UINT64_C(1000000000)) { rc=VIREO_RESULT_OVERFLOW; break; }
            waited=pthread_cond_timedwait(&q->changed,&q->mutex,&t);
        }
        if (waited && waited!=ETIMEDOUT) { rc=VIREO_RESULT_INTERNAL; break; }
    }
    (void)pthread_mutex_unlock(&q->mutex); return done(saved,rc);
}
vireo_result_t vireo_auth_failure_audit_close(vireo_auth_failure_audit_t *q,
    vireo_auth_failure_close_reason_t why)
{
    int const saved=errno;
    if (!q || (why!=VIREO_AUTH_FAILURE_STOP && why!=VIREO_AUTH_FAILURE_DISABLE)) return done(saved,VIREO_RESULT_INVALID_ARGUMENT);
    if (pthread_mutex_lock(&q->mutex)!=0) return done(saved,VIREO_RESULT_INTERNAL);
    q->closed=true; q->disabled=q->disabled || why==VIREO_AUTH_FAILURE_DISABLE;
    count(q,DISCARDED,(uint64_t)q->depth);
    (void)vireo_secure_clear(q->slots,q->options.capacity*sizeof(*q->slots)); q->depth=0;
    (void)pthread_cond_broadcast(&q->changed); (void)pthread_mutex_unlock(&q->mutex);
    return done(saved,VIREO_OK);
}
vireo_result_t vireo_auth_failure_audit_inspect(vireo_auth_failure_audit_t const *input,
    vireo_auth_failure_audit_info_t *out)
{
    int const saved=errno;
    if (!input || !out) return done(saved,VIREO_RESULT_INVALID_ARGUMENT);
    vireo_auth_failure_audit_t *q=(vireo_auth_failure_audit_t *)input;
    if (pthread_mutex_lock(&q->mutex)!=0) return done(saved,VIREO_RESULT_INTERNAL);
    vireo_auth_failure_audit_info_t v={.capacity=q->options.capacity,.depth=q->depth,.closed=q->closed,.disabled=q->disabled};
    v.queued=atomic_load_explicit(&q->counters[QUEUED],memory_order_relaxed);
    v.taken=atomic_load_explicit(&q->counters[TAKEN],memory_order_relaxed);
    v.dropped_rate=atomic_load_explicit(&q->counters[RATE],memory_order_relaxed);
    v.dropped_full=atomic_load_explicit(&q->counters[FULL],memory_order_relaxed);
    v.dropped_contention=atomic_load_explicit(&q->counters[CONTENTION],memory_order_relaxed);
    v.dropped_closed=atomic_load_explicit(&q->counters[CLOSED],memory_order_relaxed);
    v.dropped_disabled=atomic_load_explicit(&q->counters[DISABLED],memory_order_relaxed);
    v.discarded_on_close=atomic_load_explicit(&q->counters[DISCARDED],memory_order_relaxed);
    (void)pthread_mutex_unlock(&q->mutex); *out=v; return done(saved,VIREO_OK);
}
vireo_result_t vireo_auth_failure_audit_destroy(vireo_auth_failure_audit_t **owner)
{
    int const saved=errno;
    if (!owner) return done(saved,VIREO_RESULT_INVALID_ARGUMENT);
    if (!*owner) return done(saved,VIREO_OK);
    vireo_auth_failure_audit_t *q=*owner;
    if (!q->closed) return done(saved,VIREO_RESULT_BUSY);
    /* caller保证所有访问者退出，合法对象的destroy此时无BUSY资源。 */
    if (!q->condition_destroyed) {
        if (pthread_cond_destroy(&q->changed)!=0) return done(saved,VIREO_RESULT_INTERNAL);
        q->condition_destroyed=true;
    }
    if (pthread_mutex_destroy(&q->mutex)!=0) return done(saved,VIREO_RESULT_INTERNAL);
    size_t const bytes=sizeof(*q)+q->options.capacity*sizeof(*q->slots);
    (void)vireo_secure_clear(q,bytes); free(q); *owner=NULL; return done(saved,VIREO_OK);
}
vireo_result_t vireo_auth_failure_audit_test_lock(vireo_auth_failure_audit_t *q,bool lock)
{ return (lock?pthread_mutex_lock(&q->mutex):pthread_mutex_unlock(&q->mutex))?VIREO_RESULT_INTERNAL:VIREO_OK; }
void vireo_auth_failure_audit_test_wait_hook(vireo_auth_failure_audit_t *q,void (*hook)(void *),void *context)
{ q->wait_hook=hook; q->wait_context=context; }
