/* PROJECT: VIREO; FILE: test_auth_failure_audit.c; AUTHOR: bitofux; DATE: 2026-10-20. */
#define _POSIX_C_SOURCE 200809L
#include "auth_failure_audit_internal.h"
#include <vireo/base/clock.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdio.h>
#include <string.h>

static vireo_auth_failure_event_t event(uint64_t sequence)
{ return (vireo_auth_failure_event_t){.occurred_at_ms=17,.latency_us=sequence,.action=2,.status=1104,.origin=1}; }
static vireo_auth_failure_audit_t *create(size_t capacity,uint64_t burst,uint64_t interval,uint64_t now)
{
    vireo_auth_failure_audit_t *q=NULL;
    vireo_auth_failure_audit_options_t const o={capacity,65536,burst,interval};
    assert(vireo_auth_failure_audit_create(&o,now,&q)==VIREO_OK); return q;
}
static vireo_auth_failure_disposition_t offer(vireo_auth_failure_audit_t *q,uint64_t now,uint64_t sequence)
{
    vireo_auth_failure_event_t e=event(sequence);
    vireo_auth_failure_disposition_t d=0; errno=EDOM;
    assert(vireo_auth_failure_audit_try_offer(q,&e,now,&d)==VIREO_OK && errno==EDOM);
    memset(&e,0xa5,sizeof e); return d;
}
static void finish(vireo_auth_failure_audit_t **q)
{ assert(vireo_auth_failure_audit_close(*q,VIREO_AUTH_FAILURE_STOP)==VIREO_OK); assert(vireo_auth_failure_audit_destroy(q)==VIREO_OK && !*q); }
static void buckets(void)
{
    vireo_auth_failure_bucket_t b={0,0,0};
    vireo_auth_failure_bucket_refill(&b,9,8,10); assert(b.tokens==0 && b.remainder==9);
    vireo_auth_failure_bucket_refill(&b,9,8,10); assert(b.remainder==9);
    vireo_auth_failure_bucket_refill(&b,8,8,10); assert(b.last==9 && b.remainder==9);
    vireo_auth_failure_bucket_refill(&b,10,8,10); assert(b.tokens==1 && b.remainder==0);
    vireo_auth_failure_bucket_refill(&b,UINT64_MAX,8,10); assert(b.tokens==8 && !b.remainder);
    b=(vireo_auth_failure_bucket_t){0,0,0};
    vireo_auth_failure_bucket_refill(&b,UINT64_MAX,8,1); assert(b.tokens==8 && b.last==UINT64_MAX);
    b=(vireo_auth_failure_bucket_t){0,9,UINT64_MAX-1};
    vireo_auth_failure_bucket_refill(&b,UINT64_MAX,8,10); assert(b.tokens==1 && b.remainder==0);
    /* 独立信用模型逐纳秒核对，包括乱序输入；满桶不保留余数。 */
    uint64_t state=7;
    for(uint64_t interval=1;interval<24;++interval) {
        b=(vireo_auth_failure_bucket_t){8,0,0}; uint64_t credit=8*interval,last=0;
        for(size_t i=0;i<4000;++i) {
            state=state*UINT64_C(6364136223846793005)+1;
            uint64_t now=last+(state%41); if((state&7)==0 && last>9) now=last-9;
            uint64_t effective=now>last?now:last;
            uint64_t delta=effective-last;
            credit=credit+delta>8*interval?8*interval:credit+delta; last=effective;
            vireo_auth_failure_bucket_refill(&b,now,8,interval);
            assert(b.tokens==credit/interval && b.remainder==credit%interval && b.last==last);
            if((state&1) && b.tokens) { --b.tokens; credit-=interval; }
        }
    }
}
static void bounds(void)
{
    uint64_t now=0; assert(vireo_clock_monotonic_now(&now,NULL)==VIREO_OK);
    vireo_auth_failure_audit_t *q=create(256,256,1,now);
    assert(vireo_auth_failure_audit_destroy(&q)==VIREO_RESULT_BUSY);
    for(uint64_t i=0;i<256;++i) assert(offer(q,now+i,i)==VIREO_AUTH_FAILURE_QUEUED);
    assert(offer(q,now+256,999)==VIREO_AUTH_FAILURE_DROP_FULL);
    for(uint64_t i=0;i<256;++i) {
        vireo_auth_failure_event_t e={0}; assert(vireo_auth_failure_audit_wait_take(q,&e)==VIREO_OK);
        assert(e.latency_us==i && e.action==2 && e.status==1104 && e.occurred_at_ms==17);
    }
    assert(vireo_auth_failure_audit_test_lock(q,true)==VIREO_OK);
    assert(offer(q,now+300,1)==VIREO_AUTH_FAILURE_DROP_CONTENTION);
    assert(vireo_auth_failure_audit_test_lock(q,false)==VIREO_OK);
    vireo_auth_failure_event_t e=event(1); e.request_id[0]=1;
    vireo_auth_failure_disposition_t d=VIREO_AUTH_FAILURE_DROP_FULL;
    assert(vireo_auth_failure_audit_try_offer(q,&e,now,&d)==VIREO_RESULT_INVALID_ARGUMENT && d==VIREO_AUTH_FAILURE_DROP_FULL);
    e.origin=2; assert(vireo_auth_failure_audit_try_offer(q,&e,now+400,&d)==VIREO_OK && d==VIREO_AUTH_FAILURE_QUEUED);
    e.status=0; assert(vireo_auth_failure_audit_try_offer(q,&e,now,&d)==VIREO_RESULT_INVALID_ARGUMENT);
    finish(&q);
    q=create(2,1,1000,now);
    assert(offer(q,now,1)==VIREO_AUTH_FAILURE_QUEUED);
    assert(offer(q,now+999,2)==VIREO_AUTH_FAILURE_DROP_RATE);
    assert(offer(q,now+1000,2)==VIREO_AUTH_FAILURE_QUEUED);
    assert(offer(q,now+999,3)==VIREO_AUTH_FAILURE_DROP_RATE);
    assert(vireo_auth_failure_audit_close(q,VIREO_AUTH_FAILURE_STOP)==VIREO_OK);
    assert(offer(q,now,1)==VIREO_AUTH_FAILURE_DROP_CLOSED);
    assert(vireo_auth_failure_audit_close(q,VIREO_AUTH_FAILURE_DISABLE)==VIREO_OK);
    assert(offer(q,now,1)==VIREO_AUTH_FAILURE_DROP_DISABLED);
    vireo_auth_failure_audit_info_t info;
    assert(vireo_auth_failure_audit_inspect(q,&info)==VIREO_OK && info.queued==2 && info.discarded_on_close==2 && info.depth==0);
    e=event(999); assert(vireo_auth_failure_audit_wait_take(q,&e)==VIREO_RESULT_NOT_FOUND && e.latency_us==999);
    finish(&q);
}
typedef struct waiting { vireo_auth_failure_audit_t *q; sem_t ready; vireo_result_t result; } waiting_t;
static void waiting_hook(void *p) { assert(sem_post(&((waiting_t *)p)->ready)==0); }
static void *take_once(void *p)
{ waiting_t *w=p; vireo_auth_failure_event_t e=event(999); w->result=vireo_auth_failure_audit_wait_take(w->q,&e); assert(e.latency_us==999); return NULL; }
static void close_wait(bool rate)
{
    uint64_t now=0; assert(vireo_clock_monotonic_now(&now,NULL)==VIREO_OK);
    uint64_t future=now+UINT64_C(10000000000);
    waiting_t w={.q=create(2,1,UINT64_C(1000000000),future)};
    assert(sem_init(&w.ready,0,0)==0);
    if(rate) {
        assert(offer(w.q,future,1)==VIREO_AUTH_FAILURE_QUEUED);
        vireo_auth_failure_event_t e; assert(vireo_auth_failure_audit_wait_take(w.q,&e)==VIREO_OK);
        assert(offer(w.q,future+UINT64_C(1000000000),2)==VIREO_AUTH_FAILURE_QUEUED);
    }
    vireo_auth_failure_audit_test_wait_hook(w.q,waiting_hook,&w);
    pthread_t thread; assert(pthread_create(&thread,NULL,take_once,&w)==0);
    int rc; do { rc=sem_wait(&w.ready); } while(rc && errno==EINTR); assert(!rc);
    assert(vireo_auth_failure_audit_close(w.q,VIREO_AUTH_FAILURE_STOP)==VIREO_OK);
    assert(pthread_join(thread,NULL)==0 && w.result==VIREO_RESULT_NOT_FOUND);
    assert(sem_destroy(&w.ready)==0); finish(&w.q);
}
typedef struct concurrent { vireo_auth_failure_audit_t *q; size_t id; unsigned char *seen; } concurrent_t;
static void *produce(void *p)
{
    concurrent_t *c=p;
    for(size_t i=0;i<2000;++i) { uint64_t now=0; assert(vireo_clock_monotonic_now(&now,NULL)==VIREO_OK); (void)offer(c->q,now,c->id*2000+i); }
    return NULL;
}
static void *consume(void *p)
{
    concurrent_t *c=p; vireo_auth_failure_event_t e;
    for(;;) { vireo_result_t rc=vireo_auth_failure_audit_wait_take(c->q,&e); if(rc==VIREO_RESULT_NOT_FOUND) break;
        assert(rc==VIREO_OK && e.latency_us<8000 && !c->seen[e.latency_us]); c->seen[e.latency_us]=1; }
    return NULL;
}
static void concurrency(void)
{
    uint64_t now=0; assert(vireo_clock_monotonic_now(&now,NULL)==VIREO_OK);
    vireo_auth_failure_audit_t *q=create(256,256,1,now);
    unsigned char seen[8000]={0}; concurrent_t consumers={q,0,seen},producers[4]; pthread_t writer,threads[4];
    assert(pthread_create(&writer,NULL,consume,&consumers)==0);
    for(size_t i=0;i<4;++i) { producers[i]=(concurrent_t){q,i,NULL}; assert(pthread_create(&threads[i],NULL,produce,&producers[i])==0); }
    for(size_t i=0;i<4;++i) assert(pthread_join(threads[i],NULL)==0);
    assert(vireo_auth_failure_audit_close(q,VIREO_AUTH_FAILURE_STOP)==VIREO_OK); assert(pthread_join(writer,NULL)==0);
    vireo_auth_failure_audit_info_t info; assert(vireo_auth_failure_audit_inspect(q,&info)==VIREO_OK);
    assert(info.queued==info.taken+info.discarded_on_close);
    assert(info.queued+info.dropped_rate+info.dropped_full+info.dropped_contention==8000);
    size_t count=0; for(size_t i=0;i<8000;++i) count+=seen[i]; assert(count==info.taken); finish(&q);
}
int main(void)
{ buckets(); bounds(); close_wait(false); close_wait(true); concurrency(); puts("bounded failure audit queue passed"); return 0; }
