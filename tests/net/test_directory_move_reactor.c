/* PROJECT: VIREO; DATE: 2026-10-22.
 * 真实loopback TLS和公开task/completion；受控只读结果，不声称生产MySQL总装。 */
#define _GNU_SOURCE
#include "auth_service_test_support.h"
#include "directory_move_reactor_internal.h"
#include "auth_session_internal.h"
#include <vireo/net/timer_loop.h>

static atomic_bool allocation_probe;
static _Atomic size_t allocation_calls,allocation_failure;
void *__real_calloc(size_t,size_t);
/** 仅本测试链接层逐一拒绝factory申请，其他线程/阶段正常分配。 */
void *__wrap_calloc(size_t count,size_t size)
{
    if(atomic_load_explicit(&allocation_probe,memory_order_relaxed) &&
       atomic_fetch_add_explicit(&allocation_calls,1,memory_order_relaxed)+1==atomic_load_explicit(&allocation_failure,memory_order_relaxed)) {
        errno=ENOMEM;return NULL;
    }
    return __real_calloc(count,size);
}
static uint64_t deadline_sample;
static vireo_result_t deadline_clock(uint64_t *out,vireo_clock_error_t *error)
{ *out=deadline_sample; if(error) *error=(vireo_clock_error_t){0}; return VIREO_OK; }

static void setup_network(fixture_t *f,size_t read_capacity,size_t unit,size_t low,size_t write_capacity) {
    *f=(fixture_t){.peer=-1};
    vireo_tls_context_options_t const co={fixture_leaf,sizeof fixture_leaf-1,fixture_key,sizeof fixture_key-1,4096};
    vireo_tls_context_t *context=NULL;
    EXPECT(vireo_tls_context_create_server(&co,&context,NULL),VIREO_OK);
    vireo_tcp_server_options_t const so={2,4,1048576,2*(read_capacity+write_capacity)};
    vireo_tcp_server_tls_options_t const to={{read_capacity,write_capacity,read_capacity+write_capacity+32768,unit,low,read_capacity,0,write_capacity},
        4096,UINT64_C(5000000000),163840};
    EXPECT(vireo_tcp_server_create_tls_with_auxiliary_capacity(&so,&to,1,&context,&f->server,NULL),VIREO_OK);
    REQUIRE(context==NULL);
    int fd=socket(AF_INET,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0); REQUIRE(fd>=0);
    struct sockaddr_in address={.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
    REQUIRE(bind(fd,(struct sockaddr *)&address,sizeof address)==0 && listen(fd,4)==0);
    socklen_t n=sizeof address; REQUIRE(getsockname(fd,(struct sockaddr *)&address,&n)==0);
    vireo_acceptor_t *listener=NULL; vireo_acceptor_options_t const ao={4096};
    EXPECT(vireo_acceptor_create(&ao,&fd,&listener,NULL),VIREO_OK);
    EXPECT(vireo_tcp_server_adopt_listener(f->server,&listener,NULL),VIREO_OK);
    EXPECT(vireo_tcp_server_bind_listener(f->server,true,NULL),VIREO_OK);
    f->address=address;
    vireo_inflight_store_options_t const io={8,65536};
    EXPECT(vireo_inflight_store_create(&io,&f->store),VIREO_OK);
    vireo_auth_sessions_options_t const bo={65536};
    EXPECT(vireo_auth_sessions_create(f->server,&bo,&f->sessions),VIREO_OK);

}
static void setup_channels(service_fixture_t *t,vireo_thread_pool_execute_fn execute,void *context,size_t read_capacity,size_t unit,size_t low,size_t write_capacity)
{
    *t=(service_fixture_t){0}; setup_network(&t->f,read_capacity,unit,low,write_capacity);
    vireo_task_queue_options_t const qo={1,65536};
    EXPECT(vireo_task_queue_create(&qo,&t->tasks),VIREO_OK); EXPECT(vireo_task_queue_prepare_wait(t->tasks),VIREO_OK);
    vireo_thread_pool_options_t const wo={1,65536};
    EXPECT(vireo_thread_pool_create(&wo,&t->workers),VIREO_OK);
    vireo_completion_queue_options_t const co={1,65536};
    EXPECT(vireo_completion_queue_create(&co,&t->queue),VIREO_OK); EXPECT(vireo_completion_queue_prepare_wait(t->queue),VIREO_OK);
    vireo_notifier_options_t const no={4096}; EXPECT(vireo_notifier_create(&no,&t->notifier,NULL),VIREO_OK);
    uint64_t now=0; EXPECT(vireo_clock_monotonic_now(&now,NULL),VIREO_OK);
    vireo_auth_login_admission_options_t const ao=VIREO_AUTH_LOGIN_ADMISSION_OPTIONS_DEFAULT;
    EXPECT(vireo_auth_login_admission_create(&ao,now,&t->admission),VIREO_OK);
    vireo_auth_failure_audit_options_t const audit_options={256,65536,8,UINT64_C(1000000000)};
    EXPECT(vireo_auth_failure_audit_create(&audit_options,now,&t->audit),VIREO_OK);
    vireo_thread_pool_configuration_t const config={t->tasks,execute,context};
    vireo_thread_pool_report_t report;
    EXPECT(vireo_thread_pool_configure(t->workers,&config,NULL),VIREO_OK);
    EXPECT(vireo_thread_pool_start(t->workers,&report),VIREO_OK);
    EXPECT(vireo_thread_pool_enable_execution(t->workers,&report),VIREO_OK);
}
typedef struct model {
    service_fixture_t t;
    vireo_completion_queue_t *move, *stat, *root, *list, *mkdir;
    vireo_timer_wheel_t *wheel;
    atomic_uint captured_count;
    vireo_task_t *captured;
    vireo_task_t *captured_tasks[16]; /**< worker发布独立副本，main按release/acquire领取。 */
    vireo_move_reactor_ops_t native;
    unsigned enqueue_calls,refresh_calls,consume_calls,submit_calls;
    bool destroy_error,destroy_consumed;
    bool blocked,refresh_error,consume_error,submit_error,rollback_error,error_result,allocation_error;
    uint64_t utc,now;
    unsigned char expected_wire[335];size_t expected_wire_size;
} model_t;
static vireo_result_t execute(void *c,vireo_task_t const *task)
{
    model_t *m=c; vireo_task_info_t info; EXPECT(vireo_task_inspect(task,&info),VIREO_OK);
    if(info.metadata.operation==400) {
        vireo_directory_move_input_t in; vireo_node_move_issue_t issue;
        EXPECT(vireo_directory_move_task_read(task,400,&in,&issue),VIREO_OK);
        unsigned char wire[335]; size_t n=0;
        EXPECT(vireo_node_move_request_encode(&in.request,wire,sizeof wire,&n),VIREO_OK);
        unsigned const index=atomic_load_explicit(&m->captured_count,memory_order_relaxed); REQUIRE(index<16);
        EXPECT(vireo_directory_move_task_create(info.metadata,400,wire,n,&in.actor,4096,NULL,&m->captured_tasks[index]),VIREO_OK);
        (void)atomic_fetch_add_explicit(&m->captured_count,1,memory_order_release); return VIREO_OK;
    }
    vireo_auth_task_result_t result={.stage=VIREO_AUTH_TASK_SERVICE,.metadata=info.metadata,
        .command=info.metadata.operation==101?VIREO_COMMAND_LOGIN:VIREO_COMMAND_REGISTER};
    if(result.command==VIREO_COMMAND_LOGIN) {
        result.login.transaction.commit=VIREO_MYSQL_LOGIN_COMMITTED; result.login.user_id=7;
        result.login.transaction.session_id=99; result.login.transaction.audit_id=9;
        result.login.issued_at_ms=1; result.login.expires_at_ms=UINT64_MAX;
        memset(result.login.token.bytes,0xa7,32);
    } else {
        result.registration.commit=VIREO_MYSQL_REGISTRATION_COMMITTED;
        result.registration.user_id=7; result.registration.root_node_id=42; result.registration.audit_id=9;
    }
    vireo_completion_t *left=NULL; vireo_auth_completion_publish_report_t p;
    vireo_result_t rc=vireo_auth_completion_publish(task,&result,4096,m->t.queue,m->t.notifier,&left,&p);
    REQUIRE(rc==VIREO_OK || rc==VIREO_RESULT_CANCELLED);
    EXPECT(vireo_completion_destroy(&left),VIREO_OK); EXPECT(vireo_auth_task_result_clear(&result),VIREO_OK); return rc;
}
static vireo_result_t clock_utc(void *c,uint64_t *out) { *out=((model_t *)c)->utc; return VIREO_OK; }
static vireo_result_t clock_now(void *c,uint64_t *out) { *out=((model_t *)c)->now; return VIREO_OK; }
static vireo_result_t enqueue(void *c,vireo_tcp_server_t *s,vireo_connection_pool_lease_t l,unsigned char const *b,size_t n)
{
    model_t *m=c; ++m->enqueue_calls;
    return m->blocked?VIREO_RESULT_RANGE:m->native.enqueue(NULL,s,l,b,n);
}
static vireo_result_t refresh(void *c,vireo_tcp_server_t *s,vireo_connection_pool_lease_t l)
{ model_t *m=c; ++m->refresh_calls; return m->refresh_error?VIREO_RESULT_IO:m->native.refresh(NULL,s,l); }
static vireo_result_t consume(void *c,vireo_tcp_server_t *s,vireo_connection_pool_lease_t l,size_t n)
{ model_t *m=c; ++m->consume_calls; return m->consume_error?VIREO_RESULT_IO:m->native.consume(NULL,s,l,n); }
static vireo_result_t submit(void *c,vireo_inflight_store_t *s,vireo_tcp_server_t const *server,
    vireo_thread_pool_t *pool,size_t max,vireo_task_t **task,vireo_inflight_submit_report_t *p)
{
    model_t *m=c; ++m->submit_calls;
    if(m->rollback_error) {
        vireo_task_info_t info; EXPECT(vireo_task_inspect(*task,&info),VIREO_OK);
        EXPECT(vireo_inflight_store_register_task_limited(s,server,*task,max,NULL),VIREO_OK);
        *p=(vireo_inflight_submit_report_t){.task_inspected=true,.metadata=info.metadata,
            .registration_committed=true,.record_retained=true,.rollback_called=true,.rollback_result=VIREO_RESULT_IO};
        return VIREO_RESULT_BUSY;
    }
    vireo_result_t rc=m->native.submit(NULL,s,server,pool,max,task,p);
    return m->submit_error && p->pool_report.queue_report.transferred?VIREO_RESULT_IO:rc;
}
static vireo_result_t create_task(void *c,vireo_task_metadata_t meta,uint32_t operation,
    unsigned char const *wire,size_t n,vireo_mysql_node_actor_t const *actor,size_t budget,vireo_task_t **owner)
{
    model_t *m=c;
    REQUIRE(owner && !*owner && budget==4096);
    if(m->allocation_error) return VIREO_RESULT_NO_MEMORY;
    vireo_result_t const rc=m->native.create_task(NULL,meta,operation,wire,n,actor,budget,owner);
    if(rc==VIREO_OK && m->expected_wire_size) {
        vireo_task_payload_view_t view;EXPECT(vireo_task_borrow_payload(*owner,&view),VIREO_OK);
        REQUIRE(n==m->expected_wire_size && view.size==n+24 && !memcmp(view.data+24,m->expected_wire,n));
    }
    return rc;
}
/** fixture的成功认证也须读取实际帧长，并重试未移交任务的短暂OVERLOADED。 */
static vireo_auth_response_t auth_request(model_t *m,bool login,uint32_t sequence)
{
    uint64_t begin=0,now=0;
    EXPECT(vireo_clock_monotonic_now(&begin,NULL),VIREO_OK);
    for(;;) {
        unsigned char request_wire[156]; size_t n=request_frame(request_wire,login,sequence,false);
        peer_write(&m->t,request_wire,n);
        unsigned char wire[104]; peer_read(&m->t,wire,32);
        vireo_protocol_header_t header; vireo_protocol_codec_issue_t issue;
        EXPECT(vireo_protocol_header_decode(wire,32,&header,&issue),VIREO_OK);
        REQUIRE(header.body_len<=sizeof wire-32);
        peer_read(&m->t,wire+32,header.body_len);
        vireo_auth_response_t response={0};
        EXPECT(vireo_auth_response_decode(wire,32+header.body_len,&response),VIREO_OK);
        REQUIRE(response.sequence==sequence && response.command==(login?VIREO_COMMAND_LOGIN:VIREO_COMMAND_REGISTER));
        EXPECT(vireo_secure_clear(wire,sizeof wire),VIREO_OK);
        if(response.status!=VIREO_STATUS_OVERLOADED) return response;
        EXPECT(vireo_clock_monotonic_now(&now,NULL),VIREO_OK);
        if(now-begin>=UINT64_C(5000000000)) return response;
        EXPECT(vireo_auth_response_clear(&response),VIREO_OK);
    }
}
static vireo_result_t destroy_completion(void *context,vireo_completion_t **owner)
{
    model_t *m=context;
    if(m->destroy_consumed) { EXPECT(m->native.destroy_completion(NULL,owner),VIREO_OK); return VIREO_RESULT_IO; }
    return m->destroy_error?VIREO_RESULT_IO:m->native.destroy_completion(NULL,owner);
}
static void setup_model_mode(model_t *m,bool login,size_t queue_capacity,bool deadlines)
{
    *m=(model_t){.utc=2,.now=100}; atomic_init(&m->captured_count,0);
    setup_channels(&m->t,execute,m,4096,512,511,32768);
    vireo_completion_queue_options_t const qo={queue_capacity,65536};
    EXPECT(vireo_completion_queue_create(&qo,&m->move),VIREO_OK); EXPECT(vireo_completion_queue_prepare_wait(m->move),VIREO_OK);
    EXPECT(vireo_completion_queue_create(&qo,&m->mkdir),VIREO_OK); EXPECT(vireo_completion_queue_prepare_wait(m->mkdir),VIREO_OK);
    vireo_auth_service_resources_t const r={m->t.f.server,m->t.f.store,m->t.workers,m->t.admission,
        m->t.f.sessions,m->t.queue,m->t.notifier,m->t.audit};
    vireo_auth_service_options_t o=service_options(); o.send.max_bytes=16384; o.max_memory_bytes=1048576;
    EXPECT(vireo_completion_queue_create(&qo,&m->stat),VIREO_OK); EXPECT(vireo_completion_queue_prepare_wait(m->stat),VIREO_OK);
    EXPECT(vireo_completion_queue_create(&qo,&m->root),VIREO_OK); EXPECT(vireo_completion_queue_prepare_wait(m->root),VIREO_OK);
    EXPECT(vireo_completion_queue_create(&qo,&m->list),VIREO_OK); EXPECT(vireo_completion_queue_prepare_wait(m->list),VIREO_OK);
    EXPECT(vireo_directory_move_reactor_create(&r,&o,m->stat,401,m->root,402,m->list,403,65536,m->mkdir,404,m->move,400,&m->t.service),VIREO_OK);
    m->native=m->t.service->move->ops;
    m->t.service->move->ops=(vireo_move_reactor_ops_t){m,clock_utc,clock_now,consume,enqueue,refresh,submit,create_task,destroy_completion};
    if(deadlines) {
        deadline_sample=io_now_ns();
        vireo_timer_wheel_options_t const wo={{deadline_sample,UINT64_C(10000000),16},65536};
        EXPECT(vireo_timer_wheel_create(&wo,&m->wheel),VIREO_OK);
        vireo_timer_wheel_registry_options_t const registry={2,65536};
        EXPECT(vireo_timer_wheel_prepare(m->wheel,&registry),VIREO_OK);
        vireo_auth_service_deadline_options_t const options={UINT64_C(3000000000),UINT64_C(1000000000),UINT64_C(6000000000),{64,64},2,65536};
        EXPECT(vireo_auth_service_enable_deadlines(m->t.service,m->wheel,&options),VIREO_OK);
        m->t.service->deadline_now=deadline_clock;
    }
    peer_connect(&m->t); m->t.client=m->t.service->slots[0].client;
    if(login) {
        vireo_auth_response_t response=auth_request(m,true,1); REQUIRE(response.status==VIREO_STATUS_OK);
        EXPECT(vireo_auth_response_clear(&response),VIREO_OK);
    }
}
static void setup_model_channels(model_t *m,bool login,size_t queue_capacity)
{ setup_model_mode(m,login,queue_capacity,false); }
static void setup_model(model_t *m,bool login) { setup_model_channels(m,login,1); }
static uint32_t handle(model_t *m)
{
    /* Lookup的handle来自真实LOGIN网络响应；receipt结束后不从Session私有布局读取。 */
    vireo_auth_response_t r=auth_request(m,true,2); uint32_t h=r.session_handle;
    REQUIRE(r.status==VIREO_STATUS_OK && h); EXPECT(vireo_auth_response_clear(&r),VIREO_OK); return h;
}
/* 只用同net层既有随机接点强制数值handle重用，不读取Session私有布局。 */
static int same_handle(void *context,unsigned char bytes[4])
{
    uint32_t const h=*(uint32_t *)context;
    for(size_t i=0;i<4;++i) bytes[i]=(unsigned char)(h>>((3-i)*8));
    return 1;
}
static void rebind(model_t *m,uint32_t h,uint64_t user,uint64_t session)
{
    EXPECT(vireo_auth_session_forget(m->t.f.sessions,m->t.client),VIREO_OK);
    vireo_auth_session_identity_t identity={user,session,1,UINT64_MAX,false};
    vireo_auth_session_ticket_t ticket;
    EXPECT(vireo_auth_session_reserve_with(m->t.f.sessions,m->t.client,&identity,&ticket,same_handle,&h),VIREO_OK);
    REQUIRE(ticket.handle==h); EXPECT(vireo_auth_session_commit(m->t.f.sessions,ticket),VIREO_OK);
}
static void finish_model(model_t *m)
{
    service_fixture_t *t=&m->t;
    EXPECT(vireo_auth_service_quiesce(t->service),VIREO_OK);
    EXPECT(vireo_tcp_server_request_stop(t->f.server,NULL),VIREO_OK);
    vireo_task_queue_close_report_t tasks; vireo_completion_queue_close_report_t completions;
    vireo_result_t a=VIREO_RESULT_BUSY,b=a,c=a,d=a,f=a,g=a,k=a;
    for(size_t i=0;i<100000 && (a!=VIREO_OK || b!=VIREO_OK || c!=VIREO_OK || d!=VIREO_OK || f!=VIREO_OK || g!=VIREO_OK || k!=VIREO_OK);++i) {
        if(a!=VIREO_OK) a=vireo_task_queue_close(t->tasks,VIREO_TASK_QUEUE_CANCEL_PENDING,&tasks);
        if(b!=VIREO_OK) b=vireo_completion_queue_close(t->queue,&completions);
        if(c!=VIREO_OK) c=vireo_completion_queue_close(m->move,&completions);
        if(d!=VIREO_OK) d=vireo_completion_queue_close(m->stat,&completions);
        if(f!=VIREO_OK) f=vireo_completion_queue_close(m->root,&completions);
        if(g!=VIREO_OK) g=vireo_completion_queue_close(m->list,&completions);
        if(k!=VIREO_OK) k=vireo_completion_queue_close(m->mkdir,&completions);
        REQUIRE(k==VIREO_OK || k==VIREO_RESULT_BUSY);
        REQUIRE(g==VIREO_OK || g==VIREO_RESULT_BUSY);
        REQUIRE(f==VIREO_OK || f==VIREO_RESULT_BUSY);
        REQUIRE(d==VIREO_OK || d==VIREO_RESULT_BUSY);
        REQUIRE((a==VIREO_OK || a==VIREO_RESULT_BUSY) && (b==VIREO_OK || b==VIREO_RESULT_BUSY) && (c==VIREO_OK || c==VIREO_RESULT_BUSY));
        REQUIRE(sched_yield()==0);
    }
    REQUIRE(a==VIREO_OK && b==VIREO_OK && c==VIREO_OK && d==VIREO_OK && f==VIREO_OK && g==VIREO_OK && k==VIREO_OK);
    vireo_thread_pool_report_t joined; vireo_result_t join_result=VIREO_RESULT_BUSY;
    for(size_t i=0;i<100000 && join_result==VIREO_RESULT_BUSY;++i) {
        join_result=vireo_thread_pool_stop_and_join(t->workers,&joined);
        if(join_result==VIREO_RESULT_BUSY) {
            REQUIRE(joined.stage==VIREO_THREAD_POOL_STAGE_CHECK_QUEUE);
            REQUIRE(sched_yield()==0);
        }
    }
    REQUIRE((join_result==VIREO_OK || join_result==VIREO_RESULT_CANCELLED) && joined.joined_count==1);
    for(;;) {
        vireo_task_t *task=NULL; vireo_task_queue_transfer_report_t p;
        vireo_result_t rc=vireo_task_queue_try_take_cancelled(t->tasks,&task,&p);
        if(rc==VIREO_RESULT_NOT_FOUND) break;
        REQUIRE(rc==VIREO_OK); EXPECT(vireo_task_destroy(&task),VIREO_OK);
    }
    EXPECT(vireo_task_destroy(&m->captured),VIREO_OK);
    for(size_t i=0;i<16;++i) EXPECT(vireo_task_destroy(&m->captured_tasks[i]),VIREO_OK);
    m->blocked=m->refresh_error=m->consume_error=m->destroy_error=m->destroy_consumed=false;
    for(size_t i=0;i<100;++i) (void)service_turn(t); /* 六queue无条件final drain，包括hint0。 */
    REQUIRE(!t->service->active && !t->service->expected_count && !t->service->completion && (!t->service->move || !t->service->move->completion) && !t->service->stat_completion);
    EXPECT(vireo_auth_service_destroy(&t->service),VIREO_OK); peer_free(t);
    if(m->wheel) EXPECT(vireo_timer_wheel_destroy(&m->wheel),VIREO_OK);
    EXPECT(vireo_thread_pool_destroy(&t->workers),VIREO_OK); EXPECT(vireo_task_queue_destroy(&t->tasks),VIREO_OK);
    EXPECT(vireo_completion_queue_destroy(&m->mkdir),VIREO_OK);
    EXPECT(vireo_completion_queue_destroy(&m->list),VIREO_OK);
    EXPECT(vireo_completion_queue_destroy(&m->root),VIREO_OK);
    EXPECT(vireo_completion_queue_destroy(&m->stat),VIREO_OK);
    EXPECT(vireo_completion_queue_destroy(&m->move),VIREO_OK); EXPECT(vireo_completion_queue_destroy(&t->queue),VIREO_OK);
    EXPECT(vireo_notifier_destroy(&t->notifier,NULL),VIREO_OK);
    EXPECT(vireo_auth_failure_audit_close(t->audit,VIREO_AUTH_FAILURE_STOP),VIREO_OK);
    EXPECT(vireo_auth_failure_audit_destroy(&t->audit),VIREO_OK); EXPECT(vireo_auth_login_admission_destroy(&t->admission),VIREO_OK);
    cleanup(&t->f);
}
static void request(model_t *m,uint32_t seq,uint32_t h)
{
    vireo_node_move_request_t req={.sequence=seq,.session_handle=h,.node_id=123,.new_parent_id=77,.new_name_length=255};
    memset(req.new_name,'a',255); req.idempotency_key[0]=1;
    unsigned char wire[335]; size_t n=0;
    EXPECT(vireo_node_move_request_encode(&req,wire,sizeof wire,&n),VIREO_OK); REQUIRE(n==335); peer_write(&m->t,wire,n);
}
static void wait_task(model_t *m,unsigned count)
{
    for(size_t i=0;i<4096 && atomic_load_explicit(&m->captured_count,memory_order_acquire)<count;++i) (void)service_turn(&m->t);
    REQUIRE(atomic_load_explicit(&m->captured_count,memory_order_acquire)>=count && count && count<=16 && !m->captured);
    m->captured=m->captured_tasks[count-1]; m->captured_tasks[count-1]=NULL; REQUIRE(m->captured);
}
/** TLS写入成功不表示对端已收到；按单调期限等事件，不能用空转次数计时。 */
static vireo_result_t wait_error(vireo_auth_service_t *service,vireo_auth_service_report_t *report)
{
    uint64_t begin=0,now=0;
    EXPECT(vireo_clock_monotonic_now(&begin,NULL),VIREO_OK);
    do {
        vireo_result_t const rc=vireo_auth_service_once(service,2,report);
        if(rc!=VIREO_OK || report->first_client_result!=VIREO_OK) return rc;
        EXPECT(vireo_clock_monotonic_now(&now,NULL),VIREO_OK);
    } while(now-begin<UINT64_C(5000000000));
    return VIREO_OK; /* 调用方仍须断言原先预期的错误与状态。 */
}
static void publish(model_t *m)
{
    vireo_directory_move_task_result_t *r=calloc(1,sizeof(*r)); REQUIRE(r);
    EXPECT(vireo_directory_move_task_read(m->captured,400,&r->input,&r->request_issue),VIREO_OK);
    r->stage=VIREO_DIRECTORY_MOVE_TASK_SERVICE;
    r->request_id[0]=0xe1;
    r->service=(vireo_directory_move_result_t){.outcome=VIREO_DIRECTORY_MOVE_APPLIED,.node_id=123,.repository_called=true,
        .repository={.commit=VIREO_MYSQL_NODE_MOVE_COMMITTED,.effect=VIREO_MYSQL_NODE_MOVE_EFFECT_APPLIED,.node_id=123,.audit_id=234}};
    memcpy(r->service.idempotency_key,r->input.request.idempotency_key,16);
    memcpy(r->service.repository.idempotency_key,r->input.request.idempotency_key,16);
    if(m->error_result) { r->stage=VIREO_DIRECTORY_MOVE_TASK_CONTEXT; r->result=VIREO_RESULT_DATABASE; memset(r->request_id,0,16); memset(&r->service,0,sizeof(r->service)); }
    vireo_completion_t *left=NULL; vireo_directory_move_completion_publish_report_t p;
    EXPECT(vireo_directory_move_completion_publish(m->captured,400,r,32768,m->move,m->t.notifier,&left,&p),VIREO_OK);
    REQUIRE(!left && p.publication.completion_transferred); EXPECT(vireo_task_destroy(&m->captured),VIREO_OK);
    EXPECT(vireo_secure_clear(r,sizeof(*r)),VIREO_OK); free(r);
}
static vireo_node_move_response_t response(model_t *m,size_t n)
{
    unsigned char wire[VIREO_NODE_MOVE_RESPONSE_FRAME_MAX]; peer_read(&m->t,wire,n); vireo_node_move_response_t r; vireo_node_move_issue_t issue;
    EXPECT(vireo_node_move_response_decode(wire,n,&r,&issue),VIREO_OK); return r;
}
static void identity_and_deadline(void)
{
    for(unsigned kind=0;kind<10;++kind) {
        model_t m; setup_model(&m,true); uint32_t h=handle(&m); m.blocked=true;
        request(&m,20,h); wait_task(&m,1); m.error_result=kind==9; publish(&m);
        (void)service_turn(&m.t); REQUIRE(m.t.service->move->receipt.state==1 && m.t.service->expected_count==1);
        vireo_completion_info_t original; EXPECT(vireo_completion_inspect(m.t.service->move->completion,&original),VIREO_OK);
        if(kind==0) m.now=original.metadata.request.deadline_ns;
        if(kind==1) EXPECT(vireo_auth_session_revoke(m.t.f.sessions,99),VIREO_OK);
        if(kind==2) EXPECT(vireo_auth_session_forget(m.t.f.sessions,m.t.client),VIREO_OK);
        if(kind==3) { (void)handle(&m); } /* 替换handle，旧结果不能发给新绑定。 */
        if(kind==4) m.utc=UINT64_MAX; /* expires的闭区间边界。 */
        if(kind>=6) m.now=original.metadata.request.deadline_ns; /* 身份优先于期限。 */
        if(kind>=5) rebind(&m,h,kind==6 || kind==8 || kind==9?8:7,kind==7 || kind==8?100:99);
        bool const already_discarded=!m.t.service->move->completion;
        if(already_discarded) REQUIRE(kind==3); /* LOGIN的绑定决定点可在读auth响应时使STAT失效。 */
        m.blocked=false;
        if(kind==0 || kind==5) {
            vireo_node_move_response_t r=response(&m,kind==0?32:64);
            REQUIRE(r.status==(kind==0?VIREO_STATUS_TIMEOUT:VIREO_STATUS_OK));
        } else if(!already_discarded) {
            vireo_auth_service_report_t p=service_turn(&m.t); (void)p;
            vireo_directory_move_reactor_report_t stat; EXPECT(vireo_directory_move_reactor_inspect(m.t.service,&stat),VIREO_OK);
            REQUIRE(stat.identity_discarded==1 && !stat.completion_pending);
        }
        REQUIRE(!m.t.service->expected_count); finish_model(&m);
    }
}
static void stat_completion(model_t *m,uint32_t seq,uint32_t handle_value);
static void independent_and_resume(void)
{
    model_t m; setup_model(&m,true); uint32_t h=handle(&m);
    m.blocked=true; request(&m,30,h); wait_task(&m,1); publish(&m); (void)service_turn(&m.t);
    REQUIRE(m.t.service->move->receipt.state==1);
    vireo_auth_response_t auth=auth_request(&m,false,31); REQUIRE(auth.sequence==31 && auth.status==VIREO_STATUS_OK);
    REQUIRE(m.t.service->move->completion && m.t.service->expected_count==1);
    EXPECT(vireo_auth_response_clear(&auth),VIREO_OK);
    stat_completion(&m,34,h);
    unsigned char stat_wire[90]; peer_read(&m.t,stat_wire,sizeof stat_wire);
    vireo_node_stat_response_t stat_response; vireo_node_stat_issue_t stat_issue;
    EXPECT(vireo_node_stat_response_decode(stat_wire,sizeof stat_wire,&stat_response,&stat_issue),VIREO_OK);
    REQUIRE(stat_response.status==VIREO_STATUS_OK && stat_response.sequence==34);
    REQUIRE(m.t.service->move->completion && !m.t.service->stat_completion && m.t.service->expected_count==1);
    m.blocked=false; m.refresh_error=true;
    vireo_auth_service_report_t p; EXPECT(vireo_auth_service_once(m.t.service,0,&p),VIREO_RESULT_IO);
    REQUIRE(m.t.service->move->receipt.state==2); unsigned enqueued=m.enqueue_calls;
    rebind(&m,h,8,100); /* FIFO决定点之后只补refresh，不能重核并重复发送。 */
    m.refresh_error=false; (void)service_turn(&m.t);
    REQUIRE(m.enqueue_calls==enqueued && !m.t.service->move->completion);
    vireo_node_move_response_t r=response(&m,64); REQUIRE(r.status==VIREO_STATUS_OK);
    finish_model(&m);
}
/** 原auth结果占满FIFO并take后，STAT仍退还自己的登记/交付；不是单向公平。 */
static void stat_completion(model_t *m,uint32_t seq,uint32_t handle_value)
{
    vireo_auth_service_t *s=m->t.service; size_t index=SIZE_MAX;
    EXPECT(vireo_stat_reactor_reserve(s,m->t.client,seq,VIREO_COMMAND_NODE_STAT,&index),VIREO_OK); REQUIRE(index!=SIZE_MAX);
    vireo_task_metadata_t meta;
    EXPECT(vireo_inflight_metadata_make_next(m->t.f.server,m->t.client,seq,401,UINT64_MAX,&meta,NULL),VIREO_OK);
    EXPECT(vireo_inflight_store_register_limited(m->t.f.store,m->t.f.server,meta,8,NULL),VIREO_OK);
    s->expected[index]=(vireo_stat_expected_t){.command=VIREO_COMMAND_NODE_STAT,.committed=true,.metadata=meta,
        .request={seq,handle_value,42},.actor={7,99}}; ++s->expected_count;
    unsigned char wire[150]; size_t n=0; vireo_node_stat_request_t request_value={seq,handle_value,42};
    EXPECT(vireo_node_stat_request_encode(&request_value,wire,sizeof wire,&n),VIREO_OK);
    vireo_task_t *task=NULL; vireo_mysql_node_actor_t actor={7,99};
    EXPECT(vireo_directory_stat_task_create(meta,401,wire,n,&actor,4096,NULL,&task),VIREO_OK);
    vireo_directory_stat_task_result_t result={.stage=VIREO_DIRECTORY_STAT_TASK_SERVICE};vireo_node_stat_issue_t issue;
    EXPECT(vireo_directory_stat_task_read(task,401,&result.input,&issue),VIREO_OK);
    result.service=(vireo_directory_stat_result_t){.outcome=VIREO_DIRECTORY_STAT_FOUND,.repository_called=true,
        .repository={.found=true,.rollback_confirmed=true},
        .node={.id=42,.owner_id=7,.kind=VIREO_MYSQL_NODE_DIRECTORY,.created_at_ms=1,.updated_at_ms=2}};
    vireo_completion_t *left=NULL; vireo_directory_stat_completion_publish_report_t report;
    EXPECT(vireo_directory_stat_completion_publish(task,401,&result,4096,m->stat,m->t.notifier,&left,&report),VIREO_OK);
    REQUIRE(!left); EXPECT(vireo_task_destroy(&task),VIREO_OK);
}
static void mismatch_before_take(void)
{
    for(unsigned field=0;field<15;++field) {
        model_t m; setup_model(&m,true); uint32_t h=handle(&m);
        request(&m,40,h); wait_task(&m,1); publish(&m);
        vireo_stat_expected_t *e=NULL;
        for(size_t i=0;i<m.t.service->expected_capacity;++i) if(m.t.service->expected[i].command==VIREO_COMMAND_NODE_MOVE) e=&m.t.service->expected[i];
        REQUIRE(e); vireo_stat_expected_t saved=*e;
        size_t index=(size_t)(e-m.t.service->expected); vireo_move_request_key_t *q=&m.t.service->move->requests[index],saved_q=*q;
        switch(field) {
        case 0:e->metadata.request_instance_id++;break;case 1:q->session_handle++;break;
        case 2:e->actor.user_id++;break;case 3:e->actor.session_id++;break;
        case 4:e->metadata.deadline_ns++;break;case 5:e->metadata.operation++;break;
        case 6:e->metadata.route.request_sequence++;break;case 7:e->command=VIREO_COMMAND_LOGIN;break;
        case 8:e->committed=false;break;
        case 9:e->metadata.route.client_generation++;break;
        case 10:e->metadata.route.client_slot_index++;break;
        case 11:e->metadata.route.client_owner_id++;break;
        case 12:q->idempotency_key[0]^=1;break;
        case 13:q->idempotency_key[15]^=1;break;
        default:q->node_id++;break;
        }
        vireo_auth_service_report_t p; EXPECT(vireo_auth_service_once(m.t.service,0,&p),VIREO_RESULT_INTERNAL);
        vireo_inflight_store_info_t store; EXPECT(vireo_inflight_store_inspect(m.t.f.store,&store),VIREO_OK);
        REQUIRE(store.count==1 && m.t.service->move->completion && !m.enqueue_calls && !m.t.service->move->receipt.state);
        *e=saved; *q=saved_q; vireo_node_move_response_t r=response(&m,64); REQUIRE(r.status==VIREO_STATUS_OK); finish_model(&m);
    }
}
static void consume_and_transfer(void)
{
    for(unsigned kind=0;kind<3;++kind) {
        model_t m; setup_model(&m,true); uint32_t h=handle(&m);
        m.consume_error=kind==0; m.submit_error=kind==1; m.rollback_error=kind==2;
        request(&m,50,h); vireo_auth_service_report_t p;
        vireo_result_t const rc=wait_error(m.t.service,&p);
        REQUIRE(rc==(kind==2?VIREO_RESULT_BUSY:VIREO_RESULT_IO));
        REQUIRE(m.submit_calls==1 && m.t.service->expected_count==1);
        if(kind==0) {
            REQUIRE(m.t.service->move->heads[0].state==1); m.consume_error=false;
            (void)service_turn(&m.t); REQUIRE(!m.t.service->move->heads[0].state && m.submit_calls==1);
            wait_task(&m,1); publish(&m); REQUIRE(response(&m,64).status==VIREO_STATUS_OK);
        }
        finish_model(&m);
    }
}
/** 自洽的错误worker结果仍须被独立原请求拦下，不能只比内部重复字段。 */
static void local_rejection_resume(void)
{
    model_t m; setup_model(&m,false); m.blocked=true;
    request(&m,56,0);
    for(size_t i=0;i<4096 && !m.consume_calls;++i) (void)service_turn(&m.t);
    REQUIRE(m.consume_calls==1 && m.t.service->move->heads[0].state==2);
    for(size_t i=0;i<3;++i) (void)service_turn(&m.t);
    REQUIRE(m.consume_calls==1 && !m.submit_calls);
    m.blocked=false; m.refresh_error=true; vireo_auth_service_report_t p;
    EXPECT(vireo_auth_service_once(m.t.service,0,&p),VIREO_RESULT_IO);
    REQUIRE(m.t.service->move->heads[0].rejection==1 && p.rejected==1);
    unsigned enqueued=m.enqueue_calls; m.refresh_error=false;
    (void)service_turn(&m.t); REQUIRE(m.enqueue_calls==enqueued && m.consume_calls==1);
    REQUIRE(response(&m,32).status==VIREO_STATUS_UNAUTHORIZED); finish_model(&m);
}
static void duplicates(void)
{
    for(unsigned kind=0;kind<3;++kind) {
        model_t m; setup_model(&m,true); uint32_t h=handle(&m); m.blocked=true;
        request(&m,60,h); wait_task(&m,1);
        if(kind) { publish(&m); (void)service_turn(&m.t); REQUIRE(m.t.service->move->receipt.state==1); }
        if(kind==2) request(&m,60,h);
        else { unsigned char wire[156]; size_t n=request_frame(wire,true,60,false); peer_write(&m.t,wire,n); }
        vireo_auth_service_report_t p={0};
        EXPECT(wait_error(m.t.service,&p),VIREO_OK);
        REQUIRE(p.first_client_result==VIREO_RESULT_PROTOCOL && m.submit_calls==1);
        finish_model(&m);
    }
}
/** 关机无hint的两queue最终drain；auth迟到仍执行可信LOGOUT全服务效果。 */
static void shutdown_logout(void)
{
    model_t m; setup_model(&m,true); uint32_t handle_value=handle(&m);
    request(&m,94,handle_value); wait_task(&m,1); publish(&m);
    unsigned char wire[32]; vireo_protocol_header_t header={.command=VIREO_COMMAND_LOGOUT,.sequence=95,.session_handle=handle_value};
    EXPECT(vireo_protocol_header_encode(&header,wire,32),VIREO_OK);
    EXPECT(vireo_protocol_frame_crc32c_calculate(wire,32,NULL,0,&header.crc32c),VIREO_OK);
    EXPECT(vireo_protocol_header_encode(&header,wire,32),VIREO_OK);
    vireo_task_metadata_t metadata;
    EXPECT(vireo_inflight_metadata_make_next(m.t.f.server,m.t.client,95,102,UINT64_MAX,&metadata,NULL),VIREO_OK);
    EXPECT(vireo_auth_session_note_resume(m.t.f.sessions,metadata.request_instance_id),VIREO_OK);
    EXPECT(vireo_auth_session_check_resume(m.t.f.sessions,metadata.request_instance_id),VIREO_OK);
    vireo_auth_logout_identity_t target={7,99}; vireo_task_t *task=NULL;
    EXPECT(vireo_auth_task_create_logout(metadata,102,wire,32,&target,4096,NULL,&task),VIREO_OK);
    vireo_auth_task_result_t result={.stage=VIREO_AUTH_TASK_SERVICE,.metadata=metadata,.command=VIREO_COMMAND_LOGOUT,
        .logout_target=target,.logout_report={.commit=VIREO_MYSQL_LOGOUT_COMMITTED,.session_id=99,.audit_id=9,.revoked_at_ms=2}};
    vireo_completion_t *left=NULL; vireo_auth_completion_publish_report_t publication;
    EXPECT(vireo_auth_completion_publish(task,&result,4096,m.t.queue,m.t.notifier,&left,&publication),VIREO_OK);
    REQUIRE(!left); EXPECT(vireo_task_destroy(&task),VIREO_OK); EXPECT(vireo_auth_task_result_clear(&result),VIREO_OK);
    uint64_t hints=0; EXPECT(vireo_notifier_consume(m.t.notifier,&hints,NULL),VIREO_OK);
    EXPECT(vireo_auth_service_quiesce(m.t.service),VIREO_OK); EXPECT(vireo_tcp_server_request_stop(m.t.f.server,NULL),VIREO_OK);
    for(size_t i=0;i<64;++i) (void)service_turn(&m.t);
    EXPECT(vireo_auth_session_check_resume(m.t.f.sessions,metadata.request_instance_id),VIREO_RESULT_BUSY);
    vireo_completion_queue_info_t q;
    EXPECT(vireo_completion_queue_inspect(m.t.queue,&q),VIREO_OK); REQUIRE(!q.count);
    EXPECT(vireo_completion_queue_inspect(m.move,&q),VIREO_OK); REQUIRE(!q.count);
    REQUIRE(!m.t.service->expected_count && !m.enqueue_calls); finish_model(&m);
}
static void root_completion(model_t *m,uint32_t seq,uint32_t handle_value)
{
    vireo_auth_service_t *s=m->t.service; size_t index=SIZE_MAX;
    EXPECT(vireo_stat_reactor_reserve(s,m->t.client,seq,VIREO_COMMAND_NODE_ROOT,&index),VIREO_OK); REQUIRE(index!=SIZE_MAX);
    vireo_task_metadata_t meta;
    EXPECT(vireo_inflight_metadata_make_next(s->r.server,m->t.client,seq,402,UINT64_MAX,&meta,NULL),VIREO_OK);
    EXPECT(vireo_inflight_store_register_limited(s->r.store,s->r.server,meta,8,NULL),VIREO_OK);
    s->expected[index]=(vireo_stat_expected_t){.command=VIREO_COMMAND_NODE_ROOT,.committed=true,.metadata=meta,.root_request={seq,handle_value},.actor={7,99}}; ++s->expected_count;
    unsigned char wire[32]; size_t n=0; vireo_node_root_request_t request_value={seq,handle_value};
    EXPECT(vireo_node_root_request_encode(&request_value,wire,sizeof wire,&n),VIREO_OK);
    vireo_task_t *task=NULL; vireo_mysql_node_actor_t actor={7,99};
    EXPECT(vireo_directory_root_task_create(meta,402,wire,n,&actor,4096,NULL,&task),VIREO_OK);
    vireo_directory_root_task_result_t result={.stage=VIREO_DIRECTORY_ROOT_TASK_CONTEXT,.result=VIREO_RESULT_DATABASE}; vireo_node_root_issue_t issue;
    EXPECT(vireo_directory_root_task_read(task,402,&result.input,&issue),VIREO_OK);
    vireo_completion_t *left=NULL;vireo_directory_root_completion_publish_report_t publication;
    EXPECT(vireo_directory_root_completion_publish(task,402,&result,4096,m->root,m->t.notifier,&left,&publication),VIREO_OK);
    REQUIRE(!left); EXPECT(vireo_task_destroy(&task),VIREO_OK);
}
static void list_completion(model_t *m,uint32_t sequence,uint32_t handle_value)
{
    vireo_auth_service_t *s=m->t.service; size_t index=SIZE_MAX;
    EXPECT(vireo_stat_reactor_reserve(s,m->t.client,sequence,VIREO_COMMAND_NODE_LIST,&index),VIREO_OK); REQUIRE(index!=SIZE_MAX);
    vireo_task_metadata_t metadata;
    EXPECT(vireo_inflight_metadata_make_next(s->r.server,m->t.client,sequence,403,UINT64_MAX,&metadata,NULL),VIREO_OK);
    EXPECT(vireo_inflight_store_register_limited(s->r.store,s->r.server,metadata,8,NULL),VIREO_OK);
    vireo_node_list_request_t request_value={.sequence=sequence,.session_handle=handle_value,.directory_id=77,.page_size=1};
    s->expected[index]=(vireo_stat_expected_t){.command=VIREO_COMMAND_NODE_LIST,.committed=true,.metadata=metadata,.actor={7,99}};
    s->list->requests[index]=request_value; ++s->expected_count;
    unsigned char wire[64]; size_t size=0;
    EXPECT(vireo_node_list_request_encode(&request_value,wire,sizeof wire,&size),VIREO_OK);
    vireo_task_t *task=NULL; vireo_mysql_node_actor_t actor={7,99};
    EXPECT(vireo_directory_list_task_create(metadata,403,wire,size,&actor,4096,NULL,&task),VIREO_OK);
    vireo_directory_list_task_result_t *result=calloc(1,sizeof(*result)); REQUIRE(result);
    result->stage=VIREO_DIRECTORY_LIST_TASK_CONTEXT; result->result=VIREO_RESULT_DATABASE;
    EXPECT(vireo_directory_list_task_read(task,403,&result->input,&result->request_issue),VIREO_OK);
    vireo_completion_t *left=NULL; vireo_directory_list_completion_publish_report_t published;
    EXPECT(vireo_directory_list_completion_publish(task,403,result,32768,m->list,m->t.notifier,&left,&published),VIREO_OK);
    REQUIRE(!left); EXPECT(vireo_task_destroy(&task),VIREO_OK); free(result);
}
static void mkdir_completion(model_t *m,uint32_t sequence,uint32_t handle_value)
{
    vireo_auth_service_t *s=m->t.service;size_t index=SIZE_MAX;
    EXPECT(vireo_stat_reactor_reserve(s,m->t.client,sequence,VIREO_COMMAND_NODE_MKDIR,&index),VIREO_OK);REQUIRE(index!=SIZE_MAX);
    vireo_task_metadata_t meta;
    EXPECT(vireo_inflight_metadata_make_next(s->r.server,m->t.client,sequence,404,UINT64_MAX,&meta,NULL),VIREO_OK);
    EXPECT(vireo_inflight_store_register_limited(s->r.store,s->r.server,meta,8,NULL),VIREO_OK);
    vireo_node_mkdir_request_t q={.sequence=sequence,.session_handle=handle_value,.parent_id=77,.name_length=1,.name={'m'},.idempotency_key={1}};
    s->expected[index]=(vireo_stat_expected_t){.command=VIREO_COMMAND_NODE_MKDIR,.committed=true,.metadata=meta,.actor={7,99}};
    s->mkdir->requests[index].session_handle=handle_value;memcpy(s->mkdir->requests[index].idempotency_key,q.idempotency_key,16);++s->expected_count;
    unsigned char wire[323];size_t n=0;vireo_task_t *task=NULL;vireo_mysql_node_actor_t actor={7,99};
    EXPECT(vireo_node_mkdir_request_encode(&q,wire,sizeof wire,&n),VIREO_OK);
    EXPECT(vireo_directory_mkdir_task_create(meta,404,wire,n,&actor,4096,NULL,&task),VIREO_OK);
    vireo_directory_mkdir_task_result_t result={.stage=VIREO_DIRECTORY_MKDIR_TASK_CONTEXT,.result=VIREO_RESULT_DATABASE};
    EXPECT(vireo_directory_mkdir_task_read(task,404,&result.input,&result.request_issue),VIREO_OK);
    vireo_completion_t *left=NULL;vireo_directory_mkdir_completion_publish_report_t report;
    EXPECT(vireo_directory_mkdir_completion_publish(task,404,&result,4096,m->mkdir,m->t.notifier,&left,&report),VIREO_OK);
    REQUIRE(!left);EXPECT(vireo_task_destroy(&task),VIREO_OK);
}
static void six_pending_and_capacity(void)
{
    model_t m; setup_model(&m,true); uint32_t h=handle(&m); m.blocked=true;
    SSL *old_ssl=m.t.f.ssl; int old_peer=m.t.f.peer; vireo_connection_pool_lease_t old_client=m.t.client;
    peer_connect(&m.t); vireo_connection_pool_lease_t const second_client=m.t.service->slots[1].client;
    SSL *second_ssl=m.t.f.ssl; int second_peer=m.t.f.peer;
    m.t.f.ssl=old_ssl; m.t.f.peer=old_peer; m.t.client=old_client;
    request(&m,80,h); wait_task(&m,1); publish(&m); (void)service_turn(&m.t);
    stat_completion(&m,81,h); root_completion(&m,82,h); list_completion(&m,83,h); mkdir_completion(&m,85,h);
    vireo_auth_service_t *s=m.t.service; size_t index=SIZE_MAX;
    EXPECT(vireo_stat_reactor_reserve(s,m.t.client,84,VIREO_COMMAND_REGISTER,&index),VIREO_OK); REQUIRE(index!=SIZE_MAX);
    vireo_task_metadata_t metadata;
    EXPECT(vireo_inflight_metadata_make_next(s->r.server,m.t.client,84,100,UINT64_MAX,&metadata,NULL),VIREO_OK);
    EXPECT(vireo_inflight_store_register_limited(s->r.store,s->r.server,metadata,8,NULL),VIREO_OK);
    s->expected[index]=(vireo_stat_expected_t){.command=VIREO_COMMAND_REGISTER,.committed=true,.metadata=metadata}; ++s->expected_count;
    unsigned char wire[156]; size_t size=request_frame(wire,false,84,false); vireo_task_t *task=NULL;
    EXPECT(vireo_task_create_copy(metadata,wire,size,4096,&task),VIREO_OK); EXPECT(execute(&m,task),VIREO_OK); EXPECT(vireo_task_destroy(&task),VIREO_OK);
    unsigned char filler[32768]; memset(filler,0xa5,sizeof filler);
    EXPECT(vireo_tcp_server_client_write_enqueue(s->r.server,m.t.client,filler,sizeof filler,NULL),VIREO_OK);
    uint64_t hints=0; EXPECT(vireo_notifier_consume(m.t.notifier,&hints,NULL),VIREO_OK);
    (void)service_turn(&m.t);
    REQUIRE(s->completion && s->stat_completion && s->root_completion && s->list->completion && s->mkdir->completion && s->move->completion);
    REQUIRE(s->expected_count==6 && s->expected_capacity==14);
    vireo_inflight_store_info_t store; EXPECT(vireo_inflight_store_inspect(s->r.store,&store),VIREO_OK); REQUIRE(!store.count);
    /* A second real TLS lease can fill all C records while first lease owns six taken receipts. */
    m.t.client=second_client; REQUIRE(m.t.client.pool_id && m.t.client.slot_index==1);
    for(uint32_t sequence=100;sequence<108;++sequence) {
        EXPECT(vireo_stat_reactor_reserve(s,m.t.client,sequence,VIREO_COMMAND_REGISTER,&index),VIREO_OK); REQUIRE(index!=SIZE_MAX);
        EXPECT(vireo_inflight_metadata_make_next(s->r.server,m.t.client,sequence,100,UINT64_MAX,&metadata,NULL),VIREO_OK);
        EXPECT(vireo_inflight_store_register_limited(s->r.store,s->r.server,metadata,8,NULL),VIREO_OK);
        vireo_auth_request_submit_report_t submitted={.submit_report={.metadata=metadata,.metadata_created=true,.submit_report={.record_retained=true}}};
        EXPECT(vireo_stat_reactor_commit_auth(s,index,&submitted),VIREO_OK);
    }
    REQUIRE(s->expected_count==14); EXPECT(vireo_stat_reactor_reserve(s,m.t.client,108,VIREO_COMMAND_NODE_MKDIR,&index),VIREO_OK); REQUIRE(index==SIZE_MAX);
    EXPECT(vireo_auth_service_disconnect(s,second_client),VIREO_OK);
    SSL_free(second_ssl); REQUIRE(close(second_peer)==0); m.t.client=old_client;
    for(uint32_t sequence=80;sequence<=85;++sequence)
        EXPECT(vireo_stat_reactor_reserve(s,old_client,sequence,VIREO_COMMAND_NODE_MKDIR,&index),VIREO_RESULT_PROTOCOL);
    EXPECT(vireo_auth_service_disconnect(s,old_client),VIREO_OK);
    for(size_t i=0;i<100;++i) (void)service_turn(&m.t);
    REQUIRE(!s->active && !s->expected_count);
    for(size_t i=0;i<s->expected_capacity;++i) {
        vireo_move_request_key_t zero={0}; REQUIRE(!memcmp(&s->move->requests[i],&zero,sizeof zero));
        vireo_mkdir_request_key_t kz={0};REQUIRE(!memcmp(&s->mkdir->requests[i],&kz,sizeof kz));
        vireo_node_list_request_t empty={0}; REQUIRE(!memcmp(&s->list->requests[i],&empty,sizeof empty));
    }
    peer_free(&m.t); peer_connect(&m.t); m.t.client=s->slots[0].client;
    REQUIRE(m.t.client.slot_index==old_client.slot_index && m.t.client.generation!=old_client.generation);
    m.blocked=false; request(&m,80,0); REQUIRE(response(&m,32).status==VIREO_STATUS_UNAUTHORIZED);
    finish_model(&m);
}
static void destruction_progress(void)
{
    for(unsigned kind=0;kind<2;++kind) {
        model_t m; setup_model(&m,true); uint32_t h=handle(&m);
        request(&m,120,h); wait_task(&m,1); publish(&m);
        m.destroy_error=kind==0; m.destroy_consumed=kind==1;
        vireo_auth_service_report_t p; EXPECT(vireo_auth_service_once(m.t.service,0,&p),VIREO_RESULT_IO);
        REQUIRE(m.enqueue_calls==1 && m.refresh_calls==1);
        REQUIRE(m.t.service->expected_count==(kind==0?1u:0u));
        REQUIRE(p.completions==(kind==0?0u:1u));
        m.destroy_error=m.destroy_consumed=false; (void)service_turn(&m.t);
        REQUIRE(!m.t.service->move->completion && !m.t.service->expected_count && m.enqueue_calls==1);
        REQUIRE(response(&m,64).status==VIREO_STATUS_OK); finish_model(&m);
    }
}
static void shared_limit(void)
{
    for(unsigned auth=0;auth<2;++auth) {
        model_t m; setup_model(&m,true); uint32_t h=handle(&m); m.t.service->o.max_client_requests=1;
        if(auth) { m.t.service->mkdir->ops.context=&m;m.t.service->mkdir->ops.enqueue=enqueue; }
        m.blocked=true; request(&m,140,h); wait_task(&m,1); publish(&m); (void)service_turn(&m.t);
        REQUIRE(m.t.service->expected_count==1);
        if(auth) { unsigned char wire[156]; size_t n=request_frame(wire,false,141,false); peer_write(&m.t,wire,n); }
        else request(&m,141,h);
        uint64_t const until=io_now_ns()+UINT64_C(5000000000);
        while(!(auth?m.t.service->mkdir->heads[0].state:m.t.service->move->heads[0].state) && io_now_ns()<until) (void)service_turn(&m.t);
        REQUIRE(m.submit_calls==1 && (auth?m.t.service->mkdir->heads[0].status:m.t.service->move->heads[0].status)==VIREO_STATUS_OVERLOADED);
        m.blocked=false;
        /* Held completion is visited before client head, so its original success comes first. */
        REQUIRE(response(&m,64).status==VIREO_STATUS_OK);
        if(auth) { unsigned char wire[32];peer_read(&m.t,wire,32);vireo_auth_response_t r;
            EXPECT(vireo_auth_response_decode(wire,32,&r),VIREO_OK); REQUIRE(r.status==VIREO_STATUS_OVERLOADED); EXPECT(vireo_auth_response_clear(&r),VIREO_OK); }
        else REQUIRE(response(&m,32).status==VIREO_STATUS_OVERLOADED);
        finish_model(&m);
    }
}
/** 24种TLV排列在TLS准入后逐字节保持，不能在task创建前规范化重编码。 */
static void original_tlv_orders(void)
{
    for(unsigned a=0;a<4;++a) for(unsigned b=0;b<4;++b) for(unsigned c=0;c<4;++c) for(unsigned d=0;d<4;++d) {
        if(a==b || a==c || a==d || b==c || b==d || c==d) continue;
        model_t m;setup_model(&m,true);uint32_t h=handle(&m);
        vireo_node_move_request_t q={.sequence=170,.session_handle=h,.node_id=123,.new_parent_id=77,.new_name_length=1,.new_name={'x'}};
        for(size_t i=0;i<16;++i)q.idempotency_key[i]=(unsigned char)(i+1);
        unsigned char canonical[335];size_t n=0;EXPECT(vireo_node_move_request_encode(&q,canonical,sizeof canonical,&n),VIREO_OK);
        size_t offsets[4],lengths[4],offset=32;
        for(size_t i=0;i<4;++i) { offsets[i]=offset;lengths[i]=4+(size_t)canonical[offset+2]*256+canonical[offset+3];offset+=lengths[i]; }
        REQUIRE(offset==n);memcpy(m.expected_wire,canonical,32);unsigned order[]={a,b,c,d};offset=32;
        for(size_t i=0;i<4;++i) { memcpy(m.expected_wire+offset,canonical+offsets[order[i]],lengths[order[i]]);offset+=lengths[order[i]]; }
        vireo_protocol_header_t header;vireo_protocol_codec_issue_t issue;
        EXPECT(vireo_protocol_header_decode(m.expected_wire,n,&header,&issue),VIREO_OK);
        EXPECT(vireo_protocol_frame_crc32c_calculate(m.expected_wire,32,m.expected_wire+32,n-32,&header.crc32c),VIREO_OK);
        EXPECT(vireo_protocol_header_encode(&header,m.expected_wire,32),VIREO_OK);m.expected_wire_size=n;
        peer_write(&m.t,m.expected_wire,n);wait_task(&m,1);publish(&m);REQUIRE(response(&m,64).status==VIREO_STATUS_OK);finish_model(&m);
    }
}
/** 合法共同帧的错误schema返回BAD_REQUEST；CRC及逐命令超长直接关闭。 */
static void malformed_frames(void)
{
    for(unsigned kind=0;kind<5;++kind) {
        model_t m;setup_model(&m,false);unsigned char wire[335]={0};size_t n=32;
        vireo_protocol_header_t header={.command=kind==2?VIREO_COMMAND_NODE_MKDIR:kind==3?VIREO_COMMAND_NODE_STAT:VIREO_COMMAND_NODE_MOVE,.sequence=175,.body_len=kind==2?292:kind==3?125:kind==4?304:0};
        EXPECT(vireo_protocol_header_encode(&header,wire,32),VIREO_OK);
        if(kind<2) EXPECT(vireo_protocol_frame_crc32c_calculate(wire,32,NULL,0,&header.crc32c),VIREO_OK);
        if(kind==1)header.crc32c^=1;
        EXPECT(vireo_protocol_header_encode(&header,wire,32),VIREO_OK);peer_write(&m.t,wire,n);
        if(!kind)REQUIRE(response(&m,32).status==VIREO_STATUS_BAD_REQUEST);
        else { vireo_auth_service_report_t report;EXPECT(wait_error(m.t.service,&report),VIREO_OK);REQUIRE(report.first_client_result==VIREO_RESULT_PROTOCOL); }
        REQUIRE(!m.submit_calls);finish_model(&m);
    }
}
/** 一个已take结果加七个store记录时，store尚有一空位；第九项仍须共享限流。 */
static void shared_eight(void)
{
    model_t m;setup_model(&m,true);uint32_t h=handle(&m);m.blocked=true;
    request(&m,180,h);wait_task(&m,1);publish(&m);(void)service_turn(&m.t);
    for(uint32_t seq=181;seq<188;++seq) {
        size_t index=SIZE_MAX;vireo_task_metadata_t metadata;
        EXPECT(vireo_stat_reactor_reserve(m.t.service,m.t.client,seq,VIREO_COMMAND_REGISTER,&index),VIREO_OK);REQUIRE(index!=SIZE_MAX);
        EXPECT(vireo_inflight_metadata_make_next(m.t.f.server,m.t.client,seq,100,UINT64_MAX,&metadata,NULL),VIREO_OK);
        EXPECT(vireo_inflight_store_register_limited(m.t.f.store,m.t.f.server,metadata,8,NULL),VIREO_OK);
        vireo_auth_request_submit_report_t report={.submit_report={.metadata=metadata,.metadata_created=true,.submit_report={.record_retained=true}}};
        EXPECT(vireo_stat_reactor_commit_auth(m.t.service,index,&report),VIREO_OK);
    }
    vireo_inflight_store_info_t store;EXPECT(vireo_inflight_store_inspect(m.t.f.store,&store),VIREO_OK);REQUIRE(store.count==7 && m.t.service->expected_count==8);
    request(&m,188,h);uint64_t const until=io_now_ns()+UINT64_C(5000000000);
    while(!m.t.service->move->heads[0].state && io_now_ns()<until)(void)service_turn(&m.t);
    REQUIRE(m.submit_calls==1 && m.t.service->move->heads[0].status==VIREO_STATUS_OVERLOADED);
    m.blocked=false;REQUIRE(response(&m,64).status==VIREO_STATUS_OK);REQUIRE(response(&m,32).status==VIREO_STATUS_OVERLOADED);finish_model(&m);
}
static void framing_and_fragmentation(void)
{
    model_t m; setup_model(&m,true); uint32_t h=handle(&m);
    vireo_node_move_request_t q={.sequence=150,.session_handle=h,.node_id=123,.new_parent_id=77,.new_name_length=255};
    memset(q.new_name,'z',255); q.idempotency_key[0]=1;
    unsigned char wire[670];size_t size=0;
    EXPECT(vireo_node_move_request_encode(&q,wire,sizeof wire,&size),VIREO_OK); REQUIRE(size==335);
    peer_write(&m.t,wire,334); for(size_t i=0;i<3;++i)(void)service_turn(&m.t); REQUIRE(!atomic_load(&m.captured_count));
    peer_write(&m.t,wire+334,1); wait_task(&m,1); publish(&m); REQUIRE(response(&m,64).status==VIREO_STATUS_OK);
    q.sequence=151; EXPECT(vireo_node_move_request_encode(&q,wire,335,&size),VIREO_OK);
    q.sequence=152; EXPECT(vireo_node_move_request_encode(&q,wire+335,335,&size),VIREO_OK);
    peer_write(&m.t,wire,670); wait_task(&m,2);publish(&m);REQUIRE(response(&m,64).sequence==151);
    wait_task(&m,3);publish(&m);REQUIRE(response(&m,64).sequence==152);finish_model(&m);
    setup_model(&m,false);
    vireo_protocol_header_t header={.command=VIREO_COMMAND_NODE_STAT,.sequence=153,.body_len=125};
    EXPECT(vireo_protocol_header_encode(&header,wire,32),VIREO_OK); peer_write(&m.t,wire,32);
    vireo_auth_service_report_t p;EXPECT(wait_error(m.t.service,&p),VIREO_OK);REQUIRE(p.first_client_result==VIREO_RESULT_PROTOCOL);finish_model(&m);
}
/** 335上界也进入半帧扫描；固定期限不被追加字节延长，无新socket事件仍回收。 */
static void half_frame_deadline(void)
{
    for(unsigned complete=0;complete<2;++complete) {
        model_t m; setup_model_mode(&m,true,1,true);
        vireo_node_move_request_t q={.sequence=160,.session_handle=handle(&m),.node_id=123,.new_parent_id=77,.new_name_length=255};
        memset(q.new_name,'z',255);q.idempotency_key[0]=1;
        unsigned char wire[335];size_t n=0;
        EXPECT(vireo_node_move_request_encode(&q,wire,sizeof wire,&n),VIREO_OK);
        peer_write(&m.t,wire,333);
        uint64_t until=io_now_ns()+UINT64_C(5000000000);
        while(!m.t.service->slots[0].deadline.frame_ns && io_now_ns()<until) (void)service_turn(&m.t);
        uint64_t const fixed=m.t.service->slots[0].deadline.frame_ns;REQUIRE(fixed);
        deadline_sample+=UINT64_C(100000000);
        peer_write(&m.t,wire+333,1);
        size_t bytes=0;unsigned char const *view=NULL;
        while(bytes<334 && io_now_ns()<until) {
            (void)service_turn(&m.t);
            EXPECT(vireo_tcp_server_client_read_peek(m.t.f.server,m.t.client,&view,&bytes,NULL),VIREO_OK);
        }
        REQUIRE(bytes==334 && m.t.service->slots[0].deadline.frame_ns==fixed && !atomic_load(&m.captured_count));
        if(complete) {
            peer_write(&m.t,wire+334,1);wait_task(&m,1);publish(&m);
            REQUIRE(response(&m,64).status==VIREO_STATUS_OK && !m.t.service->slots[0].deadline.frame_ns);
        } else {
            deadline_sample=fixed;size_t expired=0,released=0;
            for(size_t i=0;i<4096 && m.t.service->active;++i) {
                vireo_auth_service_report_t p;
                EXPECT(vireo_auth_service_once(m.t.service,0,&p),VIREO_OK);
                REQUIRE(p.first_client_result==VIREO_OK || p.first_client_result==VIREO_RESULT_TIMEOUT);
                expired+=p.frame_timeouts;released+=p.released;
                REQUIRE(!p.unauthenticated_timeouts && !p.idle_timeouts);
            }
            REQUIRE(expired==1 && released==1 && !m.t.service->active && !atomic_load(&m.captured_count));
        }
        finish_model(&m);
    }
}
static void factories(void)
{
    size_t const profiles[][4]={{334,334,333,32768},{335,334,334,32768},{335,335,334,32768},{4096,334,333,32768},{4096,335,334,32768},{4096,512,511,23509},{4096,512,511,23510}};
    for(size_t profile=0;profile<sizeof profiles/sizeof profiles[0];++profile) {
        model_t m={0};atomic_init(&m.captured_count,0);
        setup_channels(&m.t,execute,&m,profiles[profile][0],profiles[profile][1],profiles[profile][2],profiles[profile][3]);
        vireo_completion_queue_options_t qo={1,65536};
        vireo_completion_queue_t **queues[]={&m.stat,&m.root,&m.list,&m.mkdir,&m.move};
        for(size_t i=0;i<5;++i) { EXPECT(vireo_completion_queue_create(&qo,queues[i]),VIREO_OK);EXPECT(vireo_completion_queue_prepare_wait(*queues[i]),VIREO_OK); }
        vireo_auth_service_resources_t r={m.t.f.server,m.t.f.store,m.t.workers,m.t.admission,m.t.f.sessions,m.t.queue,m.t.notifier,m.t.audit};
        vireo_auth_service_options_t o=service_options();o.send.max_bytes=16384;o.max_memory_bytes=1048576;
        for(uint32_t operation=100;operation<=107;++operation)
            EXPECT(vireo_directory_move_reactor_create(&r,&o,m.stat,104,m.root,105,m.list,106,65536,m.mkdir,107,m.move,operation,&m.t.service),VIREO_RESULT_INVALID_ARGUMENT);
        vireo_completion_queue_t *duplicates[]={m.t.queue,m.stat,m.root,m.list,m.mkdir};
        for(size_t i=0;i<5;++i) EXPECT(vireo_directory_move_reactor_create(&r,&o,m.stat,104,m.root,105,m.list,106,65536,m.mkdir,107,duplicates[i],108,&m.t.service),VIREO_RESULT_INVALID_ARGUMENT);
        if(profile==6) {
            for(unsigned mode=0;mode<5;++mode) {
                vireo_result_t rc=mode==0?vireo_auth_service_create(&r,&o,&m.t.service):
                    mode==1?vireo_directory_stat_reactor_create(&r,&o,m.stat,104,&m.t.service):
                    mode==2?vireo_directory_root_reactor_create(&r,&o,m.stat,104,m.root,105,&m.t.service):
                    mode==3?vireo_directory_list_reactor_create(&r,&o,m.stat,104,m.root,105,m.list,106,65536,&m.t.service):
                    vireo_directory_mkdir_reactor_create(&r,&o,m.stat,104,m.root,105,m.list,106,65536,m.mkdir,107,&m.t.service);
                EXPECT(rc,VIREO_OK);REQUIRE(!m.t.service->move && m.t.service->expected_capacity==(mode?9u+mode:0u));
                vireo_directory_move_reactor_report_t report;unsigned char saved[sizeof report];memset(&report,0x93,sizeof report);memcpy(saved,&report,sizeof report);
                EXPECT(vireo_directory_move_reactor_inspect(m.t.service,&report),VIREO_RESULT_NOT_FOUND);REQUIRE(!memcmp(saved,&report,sizeof report));
                EXPECT(vireo_auth_service_destroy(&m.t.service),VIREO_OK);
            }
            vireo_completion_queue_t *bad=NULL;EXPECT(vireo_completion_queue_create(&qo,&bad),VIREO_OK);
            EXPECT(vireo_directory_move_reactor_create(&r,&o,m.stat,104,m.root,105,m.list,106,65536,m.mkdir,107,bad,108,&m.t.service),VIREO_RESULT_NOT_FOUND);
            EXPECT(vireo_completion_queue_prepare_wait(bad),VIREO_OK);
            vireo_task_metadata_t meta={.route={1,0,1,1},.request_instance_id=1,.operation=108,.deadline_ns=100};
            vireo_completion_metadata_t cm={.request=meta,.result=VIREO_OK,.suggested_status=VIREO_STATUS_OK};vireo_completion_t *item=NULL;
            EXPECT(vireo_completion_create_copy(cm,"x",1,4096,&item),VIREO_OK);vireo_completion_queue_transfer_report_t transfer;
            EXPECT(vireo_completion_queue_try_push(bad,&item,&transfer),VIREO_OK);REQUIRE(!item);
            EXPECT(vireo_directory_move_reactor_create(&r,&o,m.stat,104,m.root,105,m.list,106,65536,m.mkdir,107,bad,108,&m.t.service),VIREO_RESULT_BUSY);
            EXPECT(vireo_completion_queue_try_pop(bad,&item,&transfer),VIREO_OK);EXPECT(vireo_completion_destroy(&item),VIREO_OK);
            vireo_completion_queue_close_report_t closed;EXPECT(vireo_completion_queue_close(bad,&closed),VIREO_OK);
            EXPECT(vireo_directory_move_reactor_create(&r,&o,m.stat,104,m.root,105,m.list,106,65536,m.mkdir,107,bad,108,&m.t.service),VIREO_RESULT_CANCELLED);
            EXPECT(vireo_completion_queue_destroy(&bad),VIREO_OK);REQUIRE(!m.t.service);
            size_t const total=sizeof(vireo_auth_service_t)+2*sizeof(client_slot_t)+o.max_clients*sizeof(vireo_tcp_server_ready_client_t)+o.admit.max_accepts*sizeof(vireo_connection_pool_lease_t)+14*sizeof(vireo_stat_expected_t)+sizeof(vireo_list_reactor_state_t)+2*sizeof(vireo_list_head_t)+14*sizeof(vireo_node_list_request_t)+sizeof(vireo_mkdir_reactor_state_t)+2*sizeof(vireo_mkdir_head_t)+14*sizeof(vireo_mkdir_request_key_t)+sizeof(vireo_move_reactor_state_t)+2*sizeof(vireo_move_head_t)+14*sizeof(vireo_move_request_key_t);
            REQUIRE(sizeof(vireo_move_request_key_t)==32);
            o.max_memory_bytes=total-1;
            EXPECT(vireo_directory_move_reactor_create(&r,&o,m.stat,104,m.root,105,m.list,106,65536,m.mkdir,107,m.move,108,&m.t.service),VIREO_RESULT_RANGE);REQUIRE(!m.t.service);
            o.max_memory_bytes=total;
            for(size_t failure=1;failure<=14;++failure) {
                atomic_store(&allocation_calls,0);atomic_store(&allocation_failure,failure);atomic_store(&allocation_probe,true);
                EXPECT(vireo_directory_move_reactor_create(&r,&o,m.stat,104,m.root,105,m.list,106,65536,m.mkdir,107,m.move,108,&m.t.service),VIREO_RESULT_NO_MEMORY);
                atomic_store(&allocation_probe,false);REQUIRE(!m.t.service && atomic_load(&allocation_calls)>=failure);
            }
        }
        vireo_result_t want=profile==2 || profile==4 || profile==6?VIREO_OK:VIREO_RESULT_RANGE;
        EXPECT(vireo_directory_move_reactor_create(&r,&o,m.stat,104,m.root,105,m.list,106,65536,m.mkdir,107,m.move,108,&m.t.service),want);
        if(want==VIREO_OK) { REQUIRE(m.t.service->expected_capacity==14);m.native=m.t.service->move->ops; }
        else {
            /* Legacy factory keeps its 156-byte minimum, with no MKDIR arrays. */
            EXPECT(vireo_auth_service_create(&r,&o,&m.t.service),VIREO_OK);
            vireo_directory_move_reactor_report_t report={.submitted=99};
            EXPECT(vireo_directory_move_reactor_inspect(m.t.service,&report),VIREO_RESULT_NOT_FOUND);REQUIRE(report.submitted==99);
        }
        finish_model(&m);
    }
}
int main(void)
{
    REQUIRE(signal(SIGPIPE,SIG_IGN)!=SIG_ERR);size_t before=fds();
    fputs("factories\n",stderr);factories();
    original_tlv_orders();malformed_frames();shared_eight();
    fputs("framing_and_fragmentation\n",stderr);framing_and_fragmentation();
    fputs("half_frame_deadline\n",stderr);half_frame_deadline();
    fputs("identity_and_deadline\n",stderr);identity_and_deadline();
    fputs("independent_and_resume\n",stderr);independent_and_resume();
    fputs("mismatch_before_take\n",stderr);mismatch_before_take();
    fputs("consume_and_transfer\n",stderr);consume_and_transfer();
    fputs("local_rejection_resume\n",stderr);local_rejection_resume();
    fputs("duplicates\n",stderr);duplicates();
    fputs("shutdown_logout\n",stderr);shutdown_logout();
    fputs("destruction_progress\n",stderr);destruction_progress();
    fputs("shared_limit\n",stderr);shared_limit();
    fputs("six_pending_and_capacity\n",stderr);six_pending_and_capacity();
    REQUIRE(fds()==before);
    puts("PASS directory_move_reactor: 335-byte fragmented/coalesced TLS, six pending + C capacity, shared limit, metadata/actor/key mutations, current identity before deadline, one enqueue/refresh/destroy progress, old-mode factory, seven queue closure and late LOGOUT, FD restored");return 0;
}
