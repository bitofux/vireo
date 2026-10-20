/* PROJECT: VIREO; FILE: auth_failure_writer.c; AUTHOR: bitofux; DATE: 2026-10-20. */
#define _POSIX_C_SOURCE 200809L
#include "auth_failure_writer.h"
#include <vireo/base/secure_clear.h>
#include <openssl/rand.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

static vireo_result_t attach(void *c,vireo_mysql_runtime_t *r,vireo_mysql_thread_t **t)
{ (void)c;return vireo_mysql_thread_attach(r,t,NULL); }
static vireo_result_t create(void *c,vireo_mysql_thread_t *t,vireo_mysql_pool_t *p,vireo_mysql_user_repository_t **r)
{ (void)c;vireo_password_policy_t const policy=VIREO_PASSWORD_POLICY_DEFAULT;return vireo_mysql_user_repository_create(t,p,&policy,r,NULL); }
static vireo_result_t append(void *c,vireo_mysql_user_repository_t *r,vireo_mysql_auth_failure_input_t const *i,vireo_mysql_auth_failure_report_t *p)
{ (void)c;return vireo_mysql_user_repository_append_auth_failure(r,i,p,NULL); }
static vireo_result_t destroy(void *c,vireo_mysql_user_repository_t **r)
{ (void)c;return vireo_mysql_user_repository_destroy(r,NULL); }
static vireo_result_t detach(void *c,vireo_mysql_thread_t **t)
{ (void)c;return vireo_mysql_thread_detach(t); }
static vireo_result_t random_id(void *c,unsigned char id[16])
{ (void)c;return RAND_bytes(id,16)==1?VIREO_OK:VIREO_RESULT_IO; }
static vireo_auth_failure_writer_ops_t const native={NULL,attach,create,append,destroy,detach,random_id,NULL};
static void disable(vireo_auth_failure_writer_t *w,vireo_result_t rc)
{
    w->report.disabled=true;
    if(w->report.first_result==VIREO_OK) w->report.first_result=rc;
    if(vireo_auth_failure_audit_close(w->queue,VIREO_AUTH_FAILURE_DISABLE)!=VIREO_OK) _Exit(EXIT_FAILURE);
}
static void *execute(void *context)
{
    vireo_auth_failure_writer_t *w=context;
    if(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,NULL)!=0) _Exit(EXIT_FAILURE);
    vireo_mysql_thread_t *guard=NULL;
    vireo_mysql_user_repository_t *repository=NULL;
    vireo_result_t rc=w->ops.attach(w->ops.context,w->runtime,&guard);
    if(rc==VIREO_OK) {
        rc=w->ops.create(w->ops.context,guard,w->pool,&repository);
    }
    if(rc!=VIREO_OK) disable(w,rc);
    while(rc==VIREO_OK) {
        vireo_auth_failure_event_t event={0};
        rc=vireo_auth_failure_audit_wait_take(w->queue,&event);
        if(rc==VIREO_RESULT_NOT_FOUND) break;
        if(rc!=VIREO_OK) { disable(w,rc); break; }
        vireo_mysql_auth_failure_input_t input={0};
        memcpy(input.request_id,event.request_id,16);
        input.occurred_at_ms=event.occurred_at_ms; input.latency_us=event.latency_us;
        input.action=event.action; input.status=event.status; input.origin=event.origin;
        if(event.origin==VIREO_AUTH_FAILURE_REACTOR) {
            unsigned bits=0;
            rc=w->ops.random(w->ops.context,input.request_id);
            for(size_t i=0;i<16;++i) bits|=input.request_id[i];
            if(!bits) rc=VIREO_RESULT_INTERNAL;
        }
        vireo_mysql_auth_failure_report_t report={0};
        if(rc==VIREO_OK) rc=w->ops.append(w->ops.context,repository,&input,&report);
        if(report.commit==VIREO_MYSQL_AUTH_FAILURE_COMMITTED) ++w->report.committed;
        else if(report.commit==VIREO_MYSQL_AUTH_FAILURE_UNKNOWN) ++w->report.unknown;
        if(rc!=VIREO_OK) { ++w->report.failed; disable(w,rc); }
        (void)vireo_secure_clear(&input,sizeof input); (void)vireo_secure_clear(&event,sizeof event);
    }
    for(size_t i=0;i<3 && repository;++i) {
        vireo_result_t const cleaned=w->ops.destroy(w->ops.context,&repository);
        if(cleaned!=VIREO_OK) disable(w,cleaned);
    }
    if(repository) _Exit(EXIT_FAILURE);
    for(size_t i=0;i<3 && guard;++i) {
        vireo_result_t const cleaned=w->ops.detach(w->ops.context,&guard);
        if(cleaned!=VIREO_OK) disable(w,cleaned);
    }
    if(guard) _Exit(EXIT_FAILURE);
    if(w->ops.stopped) w->ops.stopped(w->ops.context);
    return NULL;
}
vireo_result_t vireo_auth_failure_writer_start_with(vireo_auth_failure_writer_t *w,
    vireo_mysql_runtime_t *runtime,vireo_mysql_pool_t *pool,vireo_auth_failure_audit_t *queue,
    vireo_auth_failure_writer_ops_t const *ops)
{
    int const saved=errno;
    if(!w || !runtime || !pool || !queue || !ops || !ops->attach || !ops->create ||
       !ops->append || !ops->destroy || !ops->detach || !ops->random) { errno=saved; return VIREO_RESULT_INVALID_ARGUMENT; }
    *w=(vireo_auth_failure_writer_t){.runtime=runtime,.pool=pool,.queue=queue,.ops=*ops};
    pthread_attr_t attr;
    int result=pthread_attr_init(&attr);
    if(!result) {
        result=pthread_attr_setstacksize(&attr,1048576);
        if(!result) result=pthread_create(&w->thread,&attr,execute,w);
        (void)pthread_attr_destroy(&attr);
    }
    if(result) disable(w,VIREO_RESULT_INTERNAL);
    else w->report.created=true;
    errno=saved; return result?VIREO_RESULT_INTERNAL:VIREO_OK;
}
vireo_result_t vireo_auth_failure_writer_join(vireo_auth_failure_writer_t *w)
{
    int const saved=errno;
    if(!w) return VIREO_RESULT_INVALID_ARGUMENT;
    if(w->report.created && !w->report.joined) {
        if(pthread_join(w->thread,NULL)!=0) { errno=saved; return VIREO_RESULT_INTERNAL; }
        w->report.joined=true;
    }
    errno=saved; return VIREO_OK;
}

vireo_result_t vireo_auth_failure_writer_start(vireo_auth_failure_writer_t *w,
    vireo_mysql_runtime_t *runtime,vireo_mysql_pool_t *pool,vireo_auth_failure_audit_t *queue)
{ return vireo_auth_failure_writer_start_with(w,runtime,pool,queue,&native); }
