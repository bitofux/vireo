/* PROJECT : VIREO
 * FILE : test_auth_service_deadline.c
 * AUTHOR : bitofux
 * DATE : 2026-10-23
 * BRIEF : 真实TLS收帧与自动回收；虚拟单调时间验证不可续命和完整代次，另测真实无事件等待。 */
#define _GNU_SOURCE
#include "auth_service_test_support.h"
#include "../../src/net/directory_stat_reactor_internal.h"
#include <semaphore.h>

#define SECOND UINT64_C(1000000000)
static uint64_t sample;
static vireo_result_t fake_now(uint64_t *out,vireo_clock_error_t *error)
{ *out=sample; if(error) *error=(vireo_clock_error_t){0}; return VIREO_OK; }
typedef struct worker {
    service_fixture_t *fixture;
    atomic_uint calls;
    atomic_bool hold;
    sem_t entered,release;
} worker_t;
static vireo_result_t execute(void *context,vireo_task_t const *task)
{
    worker_t *w=context; atomic_fetch_add(&w->calls,1);
    if(atomic_load(&w->hold)) {
        REQUIRE(sem_post(&w->entered)==0);
        int rc; do { rc=sem_wait(&w->release); } while(rc==-1 && errno==EINTR); REQUIRE(rc==0);
    }
    vireo_task_info_t info; EXPECT(vireo_task_inspect(task,&info),VIREO_OK);
    vireo_auth_task_result_t r={.stage=VIREO_AUTH_TASK_SERVICE,.result=VIREO_OK,.metadata=info.metadata};
    if(info.metadata.operation==100) {
        r.command=VIREO_COMMAND_REGISTER; r.registration.commit=VIREO_MYSQL_REGISTRATION_COMMITTED;
        r.registration.user_id=7; r.registration.root_node_id=6; r.registration.audit_id=9;
    } else if(info.metadata.operation==101) {
        r.command=VIREO_COMMAND_LOGIN; r.login.transaction.commit=VIREO_MYSQL_LOGIN_COMMITTED;
        r.login.user_id=7; r.login.transaction.session_id=info.metadata.route.request_sequence;
        r.login.transaction.audit_id=9; r.login.issued_at_ms=1; r.login.expires_at_ms=UINT64_MAX;
        memset(r.login.token.bytes,0xa7,32);
    } else if(info.metadata.operation==103) {
        r.command=VIREO_COMMAND_SESSION_RESUME; r.resume_report.valid=true;
        r.resume_identity=(vireo_mysql_session_identity_t){.user_id=7,.session_id=90,.issued_at_ms=1,.expires_at_ms=UINT64_MAX};
    } else {
        REQUIRE(info.metadata.operation==102); r.command=VIREO_COMMAND_LOGOUT;
        r.logout_target=(vireo_auth_logout_identity_t){7,90}; r.logout_report.commit=VIREO_MYSQL_LOGOUT_COMMITTED;
        r.logout_report.session_id=90; r.logout_report.audit_id=9; r.logout_report.revoked_at_ms=120;
    }
    vireo_completion_t *left=NULL; vireo_auth_completion_publish_report_t p;
    vireo_result_t rc=vireo_auth_completion_publish(task,&r,4096,w->fixture->queue,w->fixture->notifier,&left,&p);
    REQUIRE(rc==VIREO_OK && !left && p.publication.completion_transferred);
    EXPECT(vireo_auth_task_result_clear(&r),VIREO_OK); return VIREO_OK;
}
static vireo_auth_service_deadline_options_t options(void)
{ return (vireo_auth_service_deadline_options_t){3*SECOND,SECOND,6*SECOND,{64,64},1,65536}; }
static void prepare(worker_t *w,service_fixture_t *t,vireo_timer_wheel_t **wheel,bool fake)
{
    *w=(worker_t){.fixture=t}; atomic_init(&w->calls,0); atomic_init(&w->hold,false);
    REQUIRE(sem_init(&w->entered,0,0)==0 && sem_init(&w->release,0,0)==0);
    service_setup(t,execute,w); service_create(t);
    sample=io_now_ns();
    vireo_timer_wheel_options_t const wo={{sample,UINT64_C(10000000),16},65536};
    EXPECT(vireo_timer_wheel_create(&wo,wheel),VIREO_OK);
    vireo_auth_service_deadline_options_t o=options();
    EXPECT(vireo_auth_service_enable_deadlines(t->service,*wheel,&o),VIREO_RESULT_NOT_FOUND);
    vireo_timer_wheel_registry_options_t const ro={1,65536}; EXPECT(vireo_timer_wheel_prepare(*wheel,&ro),VIREO_OK);
    vireo_auth_service_deadline_options_t bad=o; bad.frame_timeout_ns=0;
    EXPECT(vireo_auth_service_enable_deadlines(t->service,*wheel,&bad),VIREO_RESULT_INVALID_ARGUMENT);
    bad=o; bad.max_memory_bytes=1;
    EXPECT(vireo_auth_service_enable_deadlines(t->service,*wheel,&bad),VIREO_RESULT_RANGE);
    bad=o; bad.advance.max_nodes=65537;
    EXPECT(vireo_auth_service_enable_deadlines(t->service,*wheel,&bad),VIREO_RESULT_RANGE);
    if(!fake) o.unauthenticated_timeout_ns=SECOND;
    EXPECT(vireo_auth_service_enable_deadlines(t->service,*wheel,&o),VIREO_OK);
    EXPECT(vireo_auth_service_enable_deadlines(t->service,*wheel,&o),VIREO_RESULT_BUSY);
    if(fake) t->service->deadline_now=fake_now;
}
static void connect_peer(service_fixture_t *t)
{ peer_connect(t); t->client=t->service->slots[0].client; REQUIRE(t->client.pool_id); }
static void finish(worker_t *w,service_fixture_t *t,vireo_timer_wheel_t **wheel)
{
    if(!t->service->active && t->f.peer>=0) peer_free(t);
    service_cleanup(t);
    vireo_timer_wheel_registry_info_t info;
    EXPECT(vireo_timer_wheel_registry_inspect(*wheel,&info),VIREO_OK); REQUIRE(!info.active_count);
    EXPECT(vireo_timer_wheel_destroy(wheel),VIREO_OK);
    REQUIRE(sem_destroy(&w->entered)==0 && sem_destroy(&w->release)==0);
}
static vireo_auth_service_report_t timed_turn(service_fixture_t *t,int wait)
{
    vireo_auth_service_report_t p;
    EXPECT(vireo_auth_service_once(t->service,wait,&p),VIREO_OK);
    REQUIRE(p.first_client_result==VIREO_OK || p.first_client_result==VIREO_RESULT_TIMEOUT);
    t->released+=p.released; t->completed+=p.completions; t->submitted+=p.submitted;
    return p;
}
static void expire_and_release(service_fixture_t *t,unsigned kind)
{
    size_t const released=t->released; size_t counts[3]={0};
    for(size_t i=0;i<128 && t->released==released;++i) {
        vireo_auth_service_report_t p=timed_turn(t,0);
        counts[0]+=p.unauthenticated_timeouts; counts[1]+=p.frame_timeouts; counts[2]+=p.idle_timeouts;
    }
    REQUIRE(t->released==released+1 && counts[kind]==1 && counts[(kind+1)%3]==0 && counts[(kind+2)%3]==0);
    vireo_tcp_server_info_t info; EXPECT(vireo_tcp_server_inspect(t->f.server,&info),VIREO_OK);
    REQUIRE(!info.connection_count);
    vireo_inflight_store_info_t inflight; EXPECT(vireo_inflight_store_inspect(t->f.store,&inflight),VIREO_OK);
    REQUIRE(!inflight.count); peer_free(t);
}
static void wait_partial(service_fixture_t *t,size_t bytes)
{
    for(size_t i=0;i<4096;++i) {
        (void)service_turn(t);
        unsigned char const *wire=NULL; size_t size=0;
        EXPECT(vireo_tcp_server_client_read_peek(t->f.server,t->client,&wire,&size,NULL),VIREO_OK);
        if(size==bytes && t->service->slots[0].deadline.frame_ns) return;
    }
    REQUIRE(false);
}
static vireo_auth_response_t login(service_fixture_t *t,uint32_t sequence)
{
    unsigned char request[156]; size_t const n=request_frame(request,true,sequence,false);
    peer_write(t,request,n); vireo_auth_response_t r=service_response(t,104);
    REQUIRE(r.status==VIREO_STATUS_OK && r.session_handle && t->service->slots[0].deadline.authenticated_handle==r.session_handle);
    EXPECT(vireo_secure_clear(request,sizeof request),VIREO_OK); return r;
}
static void no_request_and_reuse(void)
{
    worker_t w; service_fixture_t t; vireo_timer_wheel_t *wheel=NULL; prepare(&w,&t,&wheel,true); connect_peer(&t);
    vireo_auth_client_deadline_t const old=t.service->slots[0].deadline;
    REQUIRE(old.phase_ns==sample+3*SECOND && !old.authenticated_handle && !old.frame_ns);
    sample=old.phase_ns-1; for(size_t i=0;i<16;++i) (void)service_turn(&t);
    REQUIRE(t.service->slots[0].deadline.phase_ns==old.phase_ns && !atomic_load(&w.calls));
    /* 先保存一次真实take通知，再通过同一私有分发点处理；复用后重放历史值。 */
    sample=old.phase_ns; vireo_timer_wheel_advance_report_t advanced;
    EXPECT(vireo_timer_wheel_advance(wheel,sample,(vireo_timer_wheel_advance_budget_t){65536,1},&advanced),VIREO_OK);
    vireo_timer_wheel_expired_t historical;
    EXPECT(vireo_timer_wheel_take_expired(wheel,&historical),VIREO_OK);
    vireo_auth_service_report_t p={0};
    EXPECT(vireo_auth_deadline_expired(t.service,&historical,&p),VIREO_OK);
    REQUIRE(p.unauthenticated_timeouts==1 && t.service->closing_count==1);
    for(size_t i=0;i<32 && !t.released;++i) (void)timed_turn(&t,0);
    REQUIRE(t.released==1); peer_free(&t);
    connect_peer(&t); REQUIRE(t.client.generation!=old.binding.client.generation);
    p=(vireo_auth_service_report_t){0};
    EXPECT(vireo_auth_deadline_expired(t.service,&historical,&p),VIREO_OK);
    REQUIRE(!t.service->slots[0].closing && !p.unauthenticated_timeouts);
    EXPECT(vireo_auth_service_disconnect(t.service,old.binding.client),VIREO_RESULT_NOT_FOUND);
    vireo_auth_response_t r=login(&t,10); EXPECT(vireo_auth_response_clear(&r),VIREO_OK);
    finish(&w,&t,&wheel);
}
static void trickle_and_coalesced(void)
{
    worker_t w; service_fixture_t t; vireo_timer_wheel_t *wheel=NULL; prepare(&w,&t,&wheel,true); connect_peer(&t);
    unsigned char request[156]; size_t n=request_frame(request,true,11,false);
    peer_write(&t,request,1); wait_partial(&t,1); uint64_t const deadline=t.service->slots[0].deadline.frame_ns;
    sample+=SECOND/2; peer_write(&t,request+1,14); wait_partial(&t,15);
    REQUIRE(t.service->slots[0].deadline.frame_ns==deadline && !t.submitted);
    /* 到期时最后的body已经可读也不能先收齐/刷新而逃过原期限。 */
    sample=deadline; peer_write(&t,request+15,n-15); expire_and_release(&t,1);
    connect_peer(&t); vireo_auth_response_t r=login(&t,12); EXPECT(vireo_auth_response_clear(&r),VIREO_OK);
    unsigned char joined[312]; n=request_frame(joined,false,13,false);
    size_t const second=request_frame(joined+n,true,14,false);
    peer_write(&t,joined,n+15); r=service_response(&t,56); REQUIRE(r.sequence==13);
    wait_partial(&t,15); uint64_t const partial=t.service->slots[0].deadline.frame_ns;
    sample+=SECOND/2; peer_write(&t,joined+n+15,second-15); r=service_response(&t,104); REQUIRE(r.sequence==14);
    REQUIRE(!t.service->slots[0].deadline.frame_ns && sample<partial);
    /* 前一半帧完成后下一半帧获得自己的期限。 */
    n=request_frame(request,true,15,false); peer_write(&t,request,15); wait_partial(&t,15);
    REQUIRE(t.service->slots[0].deadline.frame_ns==sample+SECOND);
    uint64_t const previous=t.service->slots[0].deadline.frame_ns;
    sample+=SECOND/2;
    memcpy(joined,request+15,n-15); (void)request_frame(joined+n-15,true,16,false);
    peer_write(&t,joined,n); r=service_response(&t,104); REQUIRE(r.sequence==15); wait_partial(&t,15);
    REQUIRE(t.service->slots[0].deadline.frame_ns==sample+SECOND && t.service->slots[0].deadline.frame_ns>previous);
    sample=t.service->slots[0].deadline.frame_ns; expire_and_release(&t,1);
    EXPECT(vireo_auth_response_clear(&r),VIREO_OK); finish(&w,&t,&wheel);
}
static void unauthenticated_requests(void)
{
    worker_t w; service_fixture_t t; vireo_timer_wheel_t *wheel=NULL; prepare(&w,&t,&wheel,true); connect_peer(&t);
    uint64_t const original=t.service->slots[0].deadline.phase_ns;
    for(uint32_t i=0;i<2;++i) {
        sample+=SECOND; unsigned char request[156]; size_t const n=request_frame(request,false,60+i,false);
        peer_write(&t,request,n); vireo_auth_response_t r=service_response(&t,56); REQUIRE(r.status==VIREO_STATUS_OK);
        EXPECT(vireo_auth_response_clear(&r),VIREO_OK);
        REQUIRE(t.service->slots[0].deadline.phase_ns==original && !t.service->slots[0].deadline.authenticated_handle);
    }
    sample=original; expire_and_release(&t,0); finish(&w,&t,&wheel);
}
static void idle_and_valid_activity(void)
{
    worker_t w; service_fixture_t t; vireo_timer_wheel_t *wheel=NULL; prepare(&w,&t,&wheel,true); connect_peer(&t);
    vireo_auth_response_t r=login(&t,20); uint64_t const first=t.service->slots[0].deadline.phase_ns;
    REQUIRE(first==sample+6*SECOND);
    sample+=2*SECOND;
    unsigned char request[156]; size_t n=request_frame(request,false,21,false); peer_write(&t,request,n);
    r=service_response(&t,56); REQUIRE(r.sequence==21);
    uint64_t const refreshed=t.service->slots[0].deadline.phase_ns; REQUIRE(refreshed==sample+6*SECOND && refreshed>first);
    sample+=SECOND/2;
    /* schema拒绝和发送响应均不能延长空闲。 */
    n=request_frame(request,false,22,false); request[33]=99;
    vireo_protocol_header_t h; vireo_protocol_codec_issue_t issue;
    EXPECT(vireo_protocol_header_decode(request,32,&h,&issue),VIREO_OK);
    EXPECT(vireo_protocol_frame_crc32c_calculate(request,32,request+32,n-32,&h.crc32c),VIREO_OK);
    EXPECT(vireo_protocol_header_encode(&h,request,32),VIREO_OK);
    peer_write(&t,request,n); r=service_response(&t,32); REQUIRE(r.status==VIREO_STATUS_BAD_REQUEST);
    REQUIRE(t.service->slots[0].deadline.phase_ns==refreshed);
    /* 半帧也不能刷新idle；此例idle早于frame，按idle关闭。 */
    sample=refreshed-SECOND/2; n=request_frame(request,false,23,false); peer_write(&t,request,1); wait_partial(&t,1);
    REQUIRE(t.service->slots[0].deadline.phase_ns==refreshed);
    sample=refreshed; expire_and_release(&t,2); EXPECT(vireo_auth_response_clear(&r),VIREO_OK); finish(&w,&t,&wheel);
}
static void resume_logout_and_expired_identity(void)
{
    worker_t w; service_fixture_t t; vireo_timer_wheel_t *wheel=NULL; prepare(&w,&t,&wheel,true); connect_peer(&t);
    unsigned char wire[68]={0}; wire[33]=4; wire[35]=32; memset(wire+36,0x35,32);
    vireo_protocol_header_t h={.command=VIREO_COMMAND_SESSION_RESUME,.sequence=30,.body_len=36};
    EXPECT(vireo_protocol_header_encode(&h,wire,32),VIREO_OK);
    EXPECT(vireo_protocol_frame_crc32c_calculate(wire,32,wire+32,36,&h.crc32c),VIREO_OK);
    EXPECT(vireo_protocol_header_encode(&h,wire,32),VIREO_OK);
    peer_write(&t,wire,68); vireo_auth_response_t r=service_response(&t,68);
    REQUIRE(r.status==VIREO_STATUS_OK && t.service->slots[0].deadline.authenticated_handle==r.session_handle);
    sample+=SECOND/2;
    h=(vireo_protocol_header_t){.command=VIREO_COMMAND_LOGOUT,.sequence=31,.session_handle=r.session_handle};
    EXPECT(vireo_protocol_header_encode(&h,wire,32),VIREO_OK);
    EXPECT(vireo_protocol_frame_crc32c_calculate(wire,32,NULL,0,&h.crc32c),VIREO_OK);
    EXPECT(vireo_protocol_header_encode(&h,wire,32),VIREO_OK);
    peer_write(&t,wire,32); r=service_response(&t,32); REQUIRE(r.status==VIREO_STATUS_OK);
    for(size_t i=0;i<4;++i) (void)service_turn(&t);
    REQUIRE(!t.service->slots[0].deadline.authenticated_handle && t.service->slots[0].deadline.phase_ns==sample+3*SECOND);
    r=login(&t,32); EXPECT(vireo_auth_session_revoke(t.f.sessions,32),VIREO_OK);
    (void)service_turn(&t); REQUIRE(!t.service->slots[0].deadline.authenticated_handle);
    /* 用同一公开票据/commit边界置入已经过期的可信身份；不修改Session私有布局。 */
    r=login(&t,33);
    vireo_auth_session_identity_t const expired={7,33,1,2,false}; vireo_auth_session_ticket_t ticket;
    EXPECT(vireo_auth_session_reserve(t.f.sessions,t.client,&expired,&ticket),VIREO_OK);
    EXPECT(vireo_auth_session_commit(t.f.sessions,ticket),VIREO_OK);
    t.service->slots[0].deadline.authenticated_handle=ticket.handle;
    (void)service_turn(&t); REQUIRE(!t.service->slots[0].deadline.authenticated_handle);
    uint64_t const deadline=t.service->slots[0].deadline.phase_ns;
    sample=deadline; expire_and_release(&t,0); EXPECT(vireo_auth_response_clear(&r),VIREO_OK); finish(&w,&t,&wheel);
}
static void late_completion_and_stop(void)
{
    worker_t w; service_fixture_t t; vireo_timer_wheel_t *wheel=NULL; prepare(&w,&t,&wheel,true); connect_peer(&t);
    atomic_store(&w.hold,true); unsigned char request[156]; size_t n=request_frame(request,true,40,false); peer_write(&t,request,n);
    for(size_t i=0;i<4096 && !atomic_load(&w.calls);++i) (void)service_turn(&t);
    REQUIRE(atomic_load(&w.calls)==1);
    int rc; do { rc=sem_wait(&w.entered); } while(rc==-1 && errno==EINTR); REQUIRE(rc==0);
    vireo_connection_pool_lease_t const old=t.client;
    sample=t.service->slots[0].deadline.phase_ns; expire_and_release(&t,0); connect_peer(&t);
    atomic_store(&w.hold,false); REQUIRE(sem_post(&w.release)==0);
    vireo_auth_response_t r=login(&t,41); REQUIRE(t.completed==2 && t.client.generation!=old.generation);
    unsigned char extra; size_t amount=0; ERR_clear_error(); rc=SSL_read_ex(t.f.ssl,&extra,1,&amount);
    REQUIRE(rc==0 && amount==0 && SSL_get_error(t.f.ssl,rc)==SSL_ERROR_WANT_READ);
    EXPECT(vireo_auth_service_quiesce(t.service),VIREO_OK);
    sample=t.service->slots[0].deadline.phase_ns; expire_and_release(&t,2);
    EXPECT(vireo_tcp_server_request_stop(t.f.server,NULL),VIREO_OK);
    EXPECT(vireo_auth_response_clear(&r),VIREO_OK); finish(&w,&t,&wheel);
}
static void catchup_budget(void)
{
    worker_t w; service_fixture_t t; vireo_timer_wheel_t *wheel=NULL; prepare(&w,&t,&wheel,true); connect_peer(&t);
    t.service->deadline_options.advance=(vireo_timer_wheel_advance_budget_t){1,1};
    sample+=SECOND/2;
    unsigned char request[156]; size_t const n=request_frame(request,false,50,false); peer_write(&t,request,n);
    vireo_auth_service_report_t p=timed_turn(&t,1000);
    REQUIRE(p.timer_work_pending && !p.poll_called && !t.submitted);
    for(size_t i=0;i<128 && !t.submitted;++i) (void)service_turn(&t);
    REQUIRE(t.submitted==1); vireo_auth_response_t r=service_response(&t,56);
    REQUIRE(r.sequence==50); EXPECT(vireo_auth_response_clear(&r),VIREO_OK); finish(&w,&t,&wheel);
}
static void real_no_event_wait(void)
{
    worker_t w; service_fixture_t t; vireo_timer_wheel_t *wheel=NULL; prepare(&w,&t,&wheel,false); connect_peer(&t);
    uint64_t const begin=io_now_ns(); size_t timeouts=0;
    for(size_t i=0;i<1024 && !t.released && io_now_ns()-begin<3*SECOND;++i) {
        vireo_auth_service_report_t p=timed_turn(&t,1000); timeouts+=p.unauthenticated_timeouts;
    }
    if(t.released!=1 || timeouts!=1) fprintf(stderr,"real idle elapsed=%llu released=%zu timeouts=%zu active=%zu phase=%llu now=%llu\n",(unsigned long long)(io_now_ns()-begin),t.released,timeouts,t.service->active,(unsigned long long)t.service->slots[0].deadline.phase_ns,(unsigned long long)io_now_ns());
    REQUIRE(t.released==1 && timeouts==1 && !atomic_load(&w.calls));
    REQUIRE(io_now_ns()-begin<2*SECOND); peer_free(&t); finish(&w,&t,&wheel);
}
int main(void)
{
    int previous; REQUIRE(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,&previous)==0);
    struct sigaction a={0}; a.sa_handler=SIG_IGN; REQUIRE(sigemptyset(&a.sa_mask)==0 && sigaction(SIGPIPE,&a,NULL)==0);
    size_t const before=fds();
    EXPECT(vireo_auth_service_enable_deadlines(NULL,NULL,NULL),VIREO_RESULT_INVALID_ARGUMENT);
    no_request_and_reuse(); trickle_and_coalesced(); unauthenticated_requests(); idle_and_valid_activity(); resume_logout_and_expired_identity();
    late_completion_and_stop(); catchup_budget(); real_no_event_wait(); REQUIRE(fds()==before);
    REQUIRE(pthread_setcancelstate(previous,NULL)==0);
    printf("PASS auth deadlines: real TLS idle admission recovery, fixed trickle/coalesced frame limits, LOGIN/RESUME/LOGOUT, idle refresh policy, revocation/expiry, late worker and timer generation, catchup budgets, real no-event poll, FD %zu->%zu\n",before,fds());
    return 0;
}
