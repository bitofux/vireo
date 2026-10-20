/* PROJECT: VIREO; FILE: test_auth_failure_writer.c; AUTHOR: bitofux; DATE: 2026-10-20. */
#define _POSIX_C_SOURCE 200809L
#include "auth_failure_writer.h"
#include <vireo/base/clock.h>
#include <assert.h>
#include <errno.h>
#include <semaphore.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
typedef struct model {
    pthread_t writer;
    sem_t called,stopped;
    unsigned attach,create,append,destroy,detach,random;
    unsigned mode;
    vireo_auth_failure_event_t expected;
} model_t;
static vireo_result_t attach(void *p,vireo_mysql_runtime_t *r,vireo_mysql_thread_t **t)
{
    model_t *m=p;assert(r && !*t);m->writer=pthread_self();++m->attach;
    *t=(vireo_mysql_thread_t *)m;return m->mode==4?VIREO_RESULT_DATABASE:VIREO_OK;
}
static vireo_result_t create(void *p,vireo_mysql_thread_t *t,vireo_mysql_pool_t *pool,vireo_mysql_user_repository_t **r)
{
    model_t *m=p;assert(pthread_equal(pthread_self(),m->writer) && t==(vireo_mysql_thread_t *)m && pool && !*r);
    ++m->create;*r=(vireo_mysql_user_repository_t *)m;return m->mode==5?VIREO_RESULT_NO_MEMORY:VIREO_OK;
}
static vireo_result_t random_id(void *p,unsigned char id[16])
{ model_t *m=p;++m->random;memset(id,m->mode==7?0:0x7a,16);return m->mode==6?VIREO_RESULT_IO:VIREO_OK; }
static vireo_result_t append(void *p,vireo_mysql_user_repository_t *r,vireo_mysql_auth_failure_input_t const *in,vireo_mysql_auth_failure_report_t *out)
{
    model_t *m=p;assert(pthread_equal(pthread_self(),m->writer) && r==(vireo_mysql_user_repository_t *)m);++m->append;
    assert(in->action==m->expected.action && in->status==m->expected.status && in->origin==m->expected.origin &&
        in->occurred_at_ms==m->expected.occurred_at_ms && in->latency_us==m->expected.latency_us);
    if(in->origin==1) for(size_t i=0;i<16;++i) assert(in->request_id[i]==0x7a);
    else assert(!memcmp(in->request_id,m->expected.request_id,16));
    *out=(vireo_mysql_auth_failure_report_t){.commit=m->mode==2?VIREO_MYSQL_AUTH_FAILURE_UNKNOWN:
        m->mode==3?VIREO_MYSQL_AUTH_FAILURE_NOT_COMMITTED:VIREO_MYSQL_AUTH_FAILURE_COMMITTED,.audit_id=m->mode<2?41:0};
    assert(!sem_post(&m->called)); return m->mode>=1 && m->mode<=3?VIREO_RESULT_DATABASE:VIREO_OK;
}
static vireo_result_t destroy(void *p,vireo_mysql_user_repository_t **r)
{
    model_t *m=p;assert(pthread_equal(pthread_self(),m->writer) && *r==(vireo_mysql_user_repository_t *)m);++m->destroy;
    if(m->mode==10) return VIREO_RESULT_BUSY;
    if(m->mode!=8 || m->destroy==3) *r=NULL;
    return m->mode==8?VIREO_RESULT_INTERNAL:VIREO_OK;
}
static vireo_result_t detach(void *p,vireo_mysql_thread_t **t)
{
    model_t *m=p;assert(pthread_equal(pthread_self(),m->writer) && *t==(vireo_mysql_thread_t *)m);++m->detach;
    if(m->mode!=9 || m->detach==3) *t=NULL;
    return m->mode==9?VIREO_RESULT_INTERNAL:VIREO_OK;
}
static void stopped(void *p) { assert(!sem_post(&((model_t *)p)->stopped)); }
static void wait_for(sem_t *s) { int rc;do { rc=sem_wait(s); } while(rc && errno==EINTR);assert(!rc); }
static void scenario(unsigned mode,unsigned origin)
{
    model_t m={.mode=mode,.expected={.occurred_at_ms=22,.latency_us=13,.action=4,.status=1104,.origin=(uint8_t)origin}};
    if(origin==2) m.expected.request_id[15]=5;
    assert(!sem_init(&m.called,0,0) && !sem_init(&m.stopped,0,0));
    vireo_auth_failure_audit_t *q=NULL;uint64_t now=0;assert(vireo_clock_monotonic_now(&now,NULL)==VIREO_OK);
    vireo_auth_failure_audit_options_t const options={256,65536,8,UINT64_C(1000000000)};
    assert(vireo_auth_failure_audit_create(&options,now,&q)==VIREO_OK);
    vireo_auth_failure_disposition_t d;assert(vireo_auth_failure_audit_try_offer(q,&m.expected,now,&d)==VIREO_OK && d==VIREO_AUTH_FAILURE_QUEUED);
    vireo_auth_failure_writer_ops_t const ops={&m,attach,create,append,destroy,detach,random_id,stopped};
    vireo_auth_failure_writer_t w;
    assert(vireo_auth_failure_writer_start_with(&w,(vireo_mysql_runtime_t *)&m,(vireo_mysql_pool_t *)&m,q,&ops)==VIREO_OK);
    if(mode==0 || mode>=8) { wait_for(&m.called);assert(vireo_auth_failure_audit_close(q,VIREO_AUTH_FAILURE_STOP)==VIREO_OK); }
    wait_for(&m.stopped); assert(vireo_auth_failure_writer_join(&w)==VIREO_OK && w.report.created && w.report.joined);
    assert(w.report.disabled==(mode!=0));
    assert(m.attach==1 && m.create==(mode!=4));
    assert(m.append==((mode>=4 && mode<=7)?0U:1U));
    assert(m.detach==(mode==9?3U:1U));assert(m.destroy==(mode==4?0U:mode==8?3U:1U));
    assert(w.report.committed==((mode==0 || mode==1 || mode>=8)?1U:0U));assert(w.report.unknown==(mode==2));
    assert(w.report.failed==((mode>=1 && mode<=3) || mode==6 || mode==7));
    assert(m.random==((origin==1 && mode!=4 && mode!=5)?1U:0U));
    vireo_auth_failure_audit_info_t info;assert(vireo_auth_failure_audit_inspect(q,&info)==VIREO_OK && info.closed && info.disabled==(mode!=0));
    assert(info.queued==info.taken+info.discarded_on_close);
    assert(vireo_auth_failure_audit_destroy(&q)==VIREO_OK && !q);
    assert(!sem_destroy(&m.called) && !sem_destroy(&m.stopped));
}
int main(void)
{
    for(unsigned mode=0;mode<=9;++mode) scenario(mode,1);
    scenario(0,2);scenario(1,2);
    pid_t child=fork();assert(child>=0);if(!child) { scenario(10,1);_exit(99); }
    int status=0;assert(waitpid(child,&status,0)==child && WIFEXITED(status) && WEXITSTATUS(status)==1);
    puts("PASS writer: one attempt, committed cleanup error, UNKNOWN, random/attach/create failures, owner retries, residual exit, no replay");return 0;
}
