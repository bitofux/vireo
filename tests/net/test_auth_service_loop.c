/* PROJECT : VIREO
 * FILE : test_auth_service_loop.c
 * AUTHOR : bitofux
 * DATE : 2026-10-20
 * BRIEF : 真实TLS自动接线、有限队列/回压/半帧/代次与停止。 */
#define _GNU_SOURCE
#include "auth_service_test_support.h"
#include <semaphore.h>
typedef struct worker {
    service_fixture_t *fixture;
    atomic_uint calls;
    atomic_bool hold;
    sem_t entered,release;
} worker_t;
static vireo_result_t execute(void *context,vireo_task_t const *task)
{
    worker_t *w=context;
    atomic_fetch_add(&w->calls,1);
    if(atomic_load(&w->hold)) {
        REQUIRE(sem_post(&w->entered)==0);
        int rc; do { rc=sem_wait(&w->release); } while(rc==-1 && errno==EINTR); REQUIRE(rc==0);
    }
    vireo_task_info_t info; EXPECT(vireo_task_inspect(task,&info),VIREO_OK);
    vireo_auth_task_result_t result={.stage=VIREO_AUTH_TASK_SERVICE,.result=VIREO_OK,.metadata=info.metadata,
        .command=info.metadata.operation==101?VIREO_COMMAND_LOGIN:VIREO_COMMAND_REGISTER};
    if(result.command==VIREO_COMMAND_REGISTER) {
        result.registration.commit=VIREO_MYSQL_REGISTRATION_COMMITTED;
        result.registration.user_id=7; result.registration.root_node_id=6; result.registration.audit_id=9;
    } else {
        result.login.transaction.commit=VIREO_MYSQL_LOGIN_COMMITTED; result.login.user_id=7;
        result.login.transaction.session_id=(uint64_t)info.metadata.route.request_sequence;
        result.login.transaction.audit_id=9; result.login.issued_at_ms=1; result.login.expires_at_ms=UINT64_MAX;
        memset(result.login.token.bytes,0xa7,32);
    }
    vireo_completion_t *left=NULL; vireo_auth_completion_publish_report_t published;
    EXPECT(vireo_auth_completion_publish(task,&result,4096,w->fixture->queue,w->fixture->notifier,&left,&published),VIREO_OK);
    REQUIRE(!left && published.publication.completion_transferred);
    EXPECT(vireo_auth_task_result_clear(&result),VIREO_OK); return VIREO_OK;
}
static void setup_worker(worker_t *w,service_fixture_t *t)
{
    *w=(worker_t){.fixture=t}; atomic_init(&w->calls,0); atomic_init(&w->hold,false);
    REQUIRE(sem_init(&w->entered,0,0)==0 && sem_init(&w->release,0,0)==0);
    service_setup(t,execute,w); service_create(t); peer_connect(t);
}
static void finish_worker(worker_t *w,service_fixture_t *t)
{ service_cleanup(t); REQUIRE(sem_destroy(&w->entered)==0 && sem_destroy(&w->release)==0); }
static void ordinary(void)
{
    worker_t w; service_fixture_t t; setup_worker(&w,&t);
    EXPECT(vireo_auth_service_destroy(&t.service),VIREO_RESULT_BUSY);
    unsigned char request[156]; size_t n=request_frame(request,false,10,false);
    peer_write(&t,request,15); for(size_t i=0;i<8;++i) (void)service_turn(&t);
    REQUIRE(!t.submitted && !atomic_load(&w.calls));
    peer_write(&t,request+15,n-15); vireo_auth_response_t v=service_response(&t,56);
    REQUIRE(v.sequence==10 && v.user_id==7 && v.root_node_id==6); EXPECT(vireo_auth_response_clear(&v),VIREO_OK);
    /* 一次写入两帧，验证缓存后缀在无新网络READ时自动续调度。 */
    unsigned char two[312]; n=request_frame(two,true,11,false); size_t second=request_frame(two+n,true,12,false);
    /* 容量1时先确认worker已取走首个LOGIN，再推进缓存后缀；否则合法OVERLOADED
     * 会使本“正常两帧”场景依赖OS调度，满队列拒绝由queue_full独立验证。 */
    atomic_store(&w.hold,true);
    peer_write(&t,two,n+second);
    for(size_t i=0;i<1024 && t.submitted<2;++i) (void)service_turn(&t);
    REQUIRE(t.submitted==2);
    int waited; do { waited=sem_wait(&w.entered); } while(waited==-1 && errno==EINTR); REQUIRE(waited==0);
    atomic_store(&w.hold,false); REQUIRE(sem_post(&w.release)==0);
    v=service_response(&t,104); REQUIRE(v.sequence==11); uint32_t const old_handle=v.session_handle;
    EXPECT(vireo_auth_response_clear(&v),VIREO_OK); v=service_response(&t,104); REQUIRE(v.sequence==12 && v.session_handle!=old_handle);
    vireo_auth_session_identity_t identity;
    EXPECT(vireo_auth_session_lookup(t.f.sessions,t.client,old_handle,2,&identity),VIREO_RESULT_NOT_FOUND);
    EXPECT(vireo_auth_session_lookup(t.f.sessions,t.client,v.session_handle,2,&identity),VIREO_OK); REQUIRE(identity.session_id==12);
    REQUIRE(t.submitted==3 && t.completed==3 && atomic_load(&w.calls)==3);
    vireo_connection_pool_lease_t old=t.client; service_disconnect(&t); peer_connect(&t);
    n=request_frame(request,false,20,false); peer_write(&t,request,n); vireo_auth_response_t next=service_response(&t,56);
    REQUIRE(t.client.slot_index==old.slot_index && t.client.generation!=old.generation);
    EXPECT(vireo_auth_service_disconnect(t.service,old),VIREO_RESULT_NOT_FOUND);
    EXPECT(vireo_auth_session_lookup(t.f.sessions,t.client,v.session_handle,2,&identity),VIREO_RESULT_NOT_FOUND);
    EXPECT(vireo_auth_response_clear(&next),VIREO_OK); EXPECT(vireo_auth_response_clear(&v),VIREO_OK);
    EXPECT(vireo_secure_clear(request,sizeof request),VIREO_OK); EXPECT(vireo_secure_clear(two,sizeof two),VIREO_OK);
    finish_worker(&w,&t);
}
static void queue_full(void)
{
    worker_t w; service_fixture_t t; setup_worker(&w,&t); atomic_store(&w.hold,true);
    unsigned char request[156]; size_t n=request_frame(request,false,30,false); peer_write(&t,request,n);
    for(size_t i=0;i<1024 && !atomic_load(&w.calls);++i) (void)service_turn(&t);
    REQUIRE(atomic_load(&w.calls)==1);
    int waited; do { waited=sem_wait(&w.entered); } while(waited==-1 && errno==EINTR); REQUIRE(waited==0);
    n=request_frame(request,false,31,false); peer_write(&t,request,n);
    for(size_t i=0;i<32 && t.submitted<2;++i) {
        (void)service_turn(&t);
    }
    REQUIRE(t.submitted==2);
    n=request_frame(request,false,32,false); peer_write(&t,request,n);
    vireo_auth_response_t v=service_response(&t,32); REQUIRE(v.sequence==32 && v.status==VIREO_STATUS_OVERLOADED);
    REQUIRE(t.rejected==1 && t.submitted==2 && atomic_load(&w.calls)==1);
    vireo_auth_failure_audit_info_t audit_info;
    EXPECT(vireo_auth_failure_audit_inspect(t.audit,&audit_info),VIREO_OK);REQUIRE(audit_info.queued==1);
    vireo_auth_failure_event_t audit_event;
    EXPECT(vireo_auth_failure_audit_wait_take(t.audit,&audit_event),VIREO_OK);
    REQUIRE(audit_event.origin==VIREO_AUTH_FAILURE_REACTOR && audit_event.action==1 &&
        audit_event.status==VIREO_STATUS_OVERLOADED && audit_event.latency_us==0 && audit_event.occurred_at_ms>0);
    for(size_t i=0;i<16;++i) REQUIRE(audit_event.request_id[i]==0);
    for(size_t i=0;i<4;++i) (void)service_turn(&t);
    EXPECT(vireo_auth_failure_audit_inspect(t.audit,&audit_info),VIREO_OK);REQUIRE(audit_info.queued==1);
    atomic_store(&w.hold,false); REQUIRE(sem_post(&w.release)==0);
    vireo_auth_response_t first=service_response(&t,56),second=service_response(&t,56);
    REQUIRE(first.sequence==30 && second.sequence==31 && atomic_load(&w.calls)==2);
    EXPECT(vireo_auth_response_clear(&v),VIREO_OK); EXPECT(vireo_auth_response_clear(&first),VIREO_OK);
    EXPECT(vireo_auth_response_clear(&second),VIREO_OK); EXPECT(vireo_secure_clear(request,sizeof request),VIREO_OK);
    finish_worker(&w,&t);
}
static void backpressure_and_quiesce(void)
{
    worker_t w; service_fixture_t t; setup_worker(&w,&t); atomic_store(&w.hold,true);
    unsigned char request[156]; size_t n=request_frame(request,true,40,false); peer_write(&t,request,n);
    for(size_t i=0;i<1024 && !atomic_load(&w.calls);++i) {
        (void)service_turn(&t);
    }
    REQUIRE(atomic_load(&w.calls)==1);
    int waited; do { waited=sem_wait(&w.entered); } while(waited==-1 && errno==EINTR); REQUIRE(waited==0);
    unsigned char filler[4096],copy[4096]; memset(filler,0xa5,sizeof filler);
    EXPECT(vireo_tcp_server_client_write_enqueue(t.f.server,t.client,filler,sizeof filler,NULL),VIREO_OK);
    vireo_tcp_server_tls_flow_info_t flow; EXPECT(vireo_tcp_server_client_tls_flow_refresh(t.f.server,t.client,&flow,NULL),VIREO_OK);
    atomic_store(&w.hold,false); REQUIRE(sem_post(&w.release)==0);
    /* 不运行服务轮，等producer完成交接。提示只供同步，不手工pop/consume。 */
    vireo_completion_queue_info_t q;
    for(size_t i=0;i<100000;++i) { vireo_result_t rc=vireo_completion_queue_inspect(t.queue,&q); if(rc==VIREO_RESULT_BUSY) continue; REQUIRE(rc==VIREO_OK); if(q.count) break; REQUIRE(sched_yield()==0); }
    REQUIRE(q.count==1);
    EXPECT(vireo_auth_service_quiesce(t.service),VIREO_OK); EXPECT(vireo_auth_service_quiesce(t.service),VIREO_OK);
    (void)service_turn(&t); REQUIRE(t.blocked && t.completed==0);
    peer_read(&t,copy,sizeof copy); REQUIRE(!memcmp(copy,filler,sizeof copy));
    vireo_auth_response_t v=service_response(&t,104); REQUIRE(v.sequence==40 && v.status==VIREO_STATUS_OK && t.completed==1);
    n=request_frame(request,false,41,false); peer_write(&t,request,n);
    for(size_t i=0;i<8;++i) { vireo_auth_service_report_t p=service_turn(&t); REQUIRE(p.quiescing); }
    REQUIRE(t.submitted==1 && atomic_load(&w.calls)==1);
    EXPECT(vireo_auth_response_clear(&v),VIREO_OK); EXPECT(vireo_secure_clear(request,sizeof request),VIREO_OK);
    finish_worker(&w,&t);
}
static void rejection_and_protocol(void)
{
    worker_t w; service_fixture_t t; setup_worker(&w,&t);
    vireo_auth_service_report_t p;
    EXPECT(vireo_auth_service_once(t.service,-1,&p),VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_auth_service_once(t.service,1001,&p),VIREO_RESULT_RANGE);
    unsigned char request[156]; size_t n=request_frame(request,false,50,false);
    /* 完整CRC合法，但USERNAME type未知；自动拒绝、不移交worker。 */
    request[33]=99; vireo_protocol_header_t h; vireo_protocol_codec_issue_t issue;
    EXPECT(vireo_protocol_header_decode(request,32,&h,&issue),VIREO_OK);
    EXPECT(vireo_protocol_frame_crc32c_calculate(request,32,request+32,n-32,&h.crc32c),VIREO_OK);
    EXPECT(vireo_protocol_header_encode(&h,request,32),VIREO_OK);
    peer_write(&t,request,n); vireo_auth_response_t v=service_response(&t,32);
    REQUIRE(v.sequence==50 && v.status==VIREO_STATUS_BAD_REQUEST && t.rejected==1 && !atomic_load(&w.calls));
    EXPECT(vireo_auth_response_clear(&v),VIREO_OK);
    /* CRC损坏属于framing失败，服务记录局部错误并有限清理，不反复解析同帧。 */
    n=request_frame(request,false,51,false); request[n-1]^=1; peer_write(&t,request,n);
    bool failed=false;
    for(size_t i=0;i<64 && !t.released;++i) {
        EXPECT(vireo_auth_service_once(t.service,2,&p),VIREO_OK);
        if(p.first_client_result) { REQUIRE(p.first_client_result==VIREO_RESULT_PROTOCOL); failed=true; }
        t.released+=p.released;
    }
    REQUIRE(failed && t.released==1 && !atomic_load(&w.calls)); peer_free(&t);
    EXPECT(vireo_secure_clear(request,sizeof request),VIREO_OK); finish_worker(&w,&t);
}
static void late_generation_and_stop(void)
{
    worker_t w; service_fixture_t t; setup_worker(&w,&t); atomic_store(&w.hold,true);
    unsigned char request[156]; size_t n=request_frame(request,true,60,false); peer_write(&t,request,n);
    for(size_t i=0;i<1024 && !atomic_load(&w.calls);++i) (void)service_turn(&t);
    REQUIRE(atomic_load(&w.calls)==1);
    int waited; do { waited=sem_wait(&w.entered); } while(waited==-1 && errno==EINTR); REQUIRE(waited==0);
    vireo_connection_pool_lease_t old=t.client; service_disconnect(&t); peer_connect(&t);
    atomic_store(&w.hold,false); REQUIRE(sem_post(&w.release)==0);
    n=request_frame(request,false,61,false); peer_write(&t,request,n);
    vireo_auth_response_t v=service_response(&t,56);
    REQUIRE(v.sequence==61 && t.completed==2 && t.client.generation!=old.generation);
    unsigned char extra; size_t amount=0; ERR_clear_error(); int rc=SSL_read_ex(t.f.ssl,&extra,1,&amount);
    REQUIRE(rc==0 && amount==0 && SSL_get_error(t.f.ssl,rc)==SSL_ERROR_WANT_READ);
    EXPECT(vireo_auth_response_clear(&v),VIREO_OK);
    /* server永久停止后仍可清理连接与迟到结果，不在唯一consumer上先join。 */
    atomic_store(&w.hold,true); n=request_frame(request,true,62,false); peer_write(&t,request,n);
    for(size_t i=0;i<1024 && atomic_load(&w.calls)<3;++i) (void)service_turn(&t);
    REQUIRE(atomic_load(&w.calls)==3);
    do { waited=sem_wait(&w.entered); } while(waited==-1 && errno==EINTR); REQUIRE(waited==0);
    EXPECT(vireo_tcp_server_request_stop(t.f.server,NULL),VIREO_OK);
    atomic_store(&w.hold,false); REQUIRE(sem_post(&w.release)==0);
    for(size_t i=0;i<1024 && (t.completed<3 || t.released<2);++i) { vireo_auth_service_report_t p=service_turn(&t); REQUIRE(p.stopped && p.quiescing); }
    REQUIRE(t.completed==3 && t.released==2); peer_free(&t);
    vireo_inflight_store_info_t inflight; EXPECT(vireo_inflight_store_inspect(t.f.store,&inflight),VIREO_OK); REQUIRE(!inflight.count);
    EXPECT(vireo_secure_clear(request,sizeof request),VIREO_OK); finish_worker(&w,&t);
}
int main(void)
{
    int previous; REQUIRE(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,&previous)==0);
    struct sigaction a={0}; a.sa_handler=SIG_IGN; REQUIRE(sigemptyset(&a.sa_mask)==0 && sigaction(SIGPIPE,&a,NULL)==0);
    size_t before=fds(); EXPECT(vireo_auth_service_create(NULL,NULL,NULL),VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_auth_service_once(NULL,0,NULL),VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_auth_service_quiesce(NULL),VIREO_RESULT_INVALID_ARGUMENT);
    ordinary(); queue_full(); backpressure_and_quiesce(); rejection_and_protocol(); late_generation_and_stop(); REQUIRE(fds()==before);
    REQUIRE(pthread_setcancelstate(previous,NULL)==0);
    printf("PASS auth_service: automatic TLS accept/handshake/fragment/coalescing, queue-full rejection, FIFO recovery, quiesce, malformed/schema/CRC, late generation and server stop, FD %zu->%zu\n",before,fds());
    return 0;
}
