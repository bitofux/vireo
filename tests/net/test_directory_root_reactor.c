/* PROJECT: VIREO; DATE: 2026-10-22.
 * 真实loopback TLS和公开task/completion；受控只读结果，不声称生产MySQL总装。 */
#define _GNU_SOURCE
#include "auth_service_test_support.h"
#include "directory_root_reactor_internal.h"
#include "auth_session_internal.h"

typedef struct model {
    service_fixture_t t;
    vireo_completion_queue_t *root, *stat;
    atomic_uint captured_count;
    vireo_task_t *captured;
    vireo_root_reactor_ops_t native;
    unsigned enqueue_calls,refresh_calls,consume_calls,submit_calls;
    bool blocked,refresh_error,consume_error,submit_error,rollback_error,error_result;
    uint64_t utc,now;
} model_t;
static vireo_result_t execute(void *c,vireo_task_t const *task)
{
    model_t *m=c; vireo_task_info_t info; EXPECT(vireo_task_inspect(task,&info),VIREO_OK);
    if(info.metadata.operation==400) {
        vireo_directory_root_input_t in; vireo_node_root_issue_t issue;
        EXPECT(vireo_directory_root_task_read(task,400,&in,&issue),VIREO_OK);
        unsigned char wire[44]; size_t n=0;
        EXPECT(vireo_node_root_request_encode(&in.request,wire,sizeof wire,&n),VIREO_OK);
        REQUIRE(!m->captured);
        EXPECT(vireo_directory_root_task_create(info.metadata,400,wire,n,&in.actor,4096,NULL,&m->captured),VIREO_OK);
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
static void setup_model(model_t *m,bool login)
{
    *m=(model_t){.utc=2,.now=100}; atomic_init(&m->captured_count,0);
    service_setup(&m->t,execute,m);
    vireo_completion_queue_options_t const qo={1,65536};
    EXPECT(vireo_completion_queue_create(&qo,&m->root),VIREO_OK); EXPECT(vireo_completion_queue_prepare_wait(m->root),VIREO_OK);
    vireo_auth_service_resources_t const r={m->t.f.server,m->t.f.store,m->t.workers,m->t.admission,
        m->t.f.sessions,m->t.queue,m->t.notifier,m->t.audit};
    vireo_auth_service_options_t const o=service_options();
    EXPECT(vireo_completion_queue_create(&qo,&m->stat),VIREO_OK); EXPECT(vireo_completion_queue_prepare_wait(m->stat),VIREO_OK);
    EXPECT(vireo_directory_root_reactor_create(&r,&o,m->stat,401,m->root,400,&m->t.service),VIREO_OK);
    m->native=m->t.service->root_ops;
    m->t.service->root_ops=(vireo_root_reactor_ops_t){m,clock_utc,clock_now,consume,enqueue,refresh,submit};
    peer_connect(&m->t); m->t.client=m->t.service->slots[0].client;
    if(login) {
        vireo_auth_response_t response=auth_request(m,true,1); REQUIRE(response.status==VIREO_STATUS_OK);
        EXPECT(vireo_auth_response_clear(&response),VIREO_OK);
    }
}
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
    vireo_result_t a=VIREO_RESULT_BUSY,b=a,c=a,d=a;
    for(size_t i=0;i<100000 && (a!=VIREO_OK || b!=VIREO_OK || c!=VIREO_OK || d!=VIREO_OK);++i) {
        if(a!=VIREO_OK) a=vireo_task_queue_close(t->tasks,VIREO_TASK_QUEUE_CANCEL_PENDING,&tasks);
        if(b!=VIREO_OK) b=vireo_completion_queue_close(t->queue,&completions);
        if(c!=VIREO_OK) c=vireo_completion_queue_close(m->root,&completions);
        if(d!=VIREO_OK) d=vireo_completion_queue_close(m->stat,&completions);
        REQUIRE(d==VIREO_OK || d==VIREO_RESULT_BUSY);
        REQUIRE((a==VIREO_OK || a==VIREO_RESULT_BUSY) && (b==VIREO_OK || b==VIREO_RESULT_BUSY) && (c==VIREO_OK || c==VIREO_RESULT_BUSY));
        REQUIRE(sched_yield()==0);
    }
    REQUIRE(a==VIREO_OK && b==VIREO_OK && c==VIREO_OK && d==VIREO_OK);
    vireo_thread_pool_report_t joined; vireo_result_t join_result=VIREO_RESULT_BUSY;
    for(size_t i=0;i<100000 && join_result==VIREO_RESULT_BUSY;++i) {
        join_result=vireo_thread_pool_stop_and_join(t->workers,&joined);
        if(join_result==VIREO_RESULT_BUSY) REQUIRE(sched_yield()==0);
    }
    REQUIRE((join_result==VIREO_OK || join_result==VIREO_RESULT_CANCELLED) && joined.joined_count==1);
    for(;;) {
        vireo_task_t *task=NULL; vireo_task_queue_transfer_report_t p;
        vireo_result_t rc=vireo_task_queue_try_take_cancelled(t->tasks,&task,&p);
        if(rc==VIREO_RESULT_NOT_FOUND) break;
        REQUIRE(rc==VIREO_OK); EXPECT(vireo_task_destroy(&task),VIREO_OK);
    }
    EXPECT(vireo_task_destroy(&m->captured),VIREO_OK);
    m->blocked=m->refresh_error=m->consume_error=false;
    for(size_t i=0;i<100;++i) (void)service_turn(t); /* 两queue无条件final drain，包括hint0。 */
    REQUIRE(!t->service->active && !t->service->expected_count && !t->service->completion && !t->service->root_completion && !t->service->stat_completion);
    EXPECT(vireo_auth_service_destroy(&t->service),VIREO_OK); peer_free(t);
    EXPECT(vireo_thread_pool_destroy(&t->workers),VIREO_OK); EXPECT(vireo_task_queue_destroy(&t->tasks),VIREO_OK);
    EXPECT(vireo_completion_queue_destroy(&m->stat),VIREO_OK);
    EXPECT(vireo_completion_queue_destroy(&m->root),VIREO_OK); EXPECT(vireo_completion_queue_destroy(&t->queue),VIREO_OK);
    EXPECT(vireo_notifier_destroy(&t->notifier,NULL),VIREO_OK);
    EXPECT(vireo_auth_failure_audit_close(t->audit,VIREO_AUTH_FAILURE_STOP),VIREO_OK);
    EXPECT(vireo_auth_failure_audit_destroy(&t->audit),VIREO_OK); EXPECT(vireo_auth_login_admission_destroy(&t->admission),VIREO_OK);
    cleanup(&t->f);
}
static void request(model_t *m,uint32_t seq,uint32_t h)
{
    vireo_node_root_request_t const req={seq,h}; unsigned char wire[32]; size_t n=0;
    EXPECT(vireo_node_root_request_encode(&req,wire,sizeof wire,&n),VIREO_OK); peer_write(&m->t,wire,n);
}
static void wait_task(model_t *m,unsigned count)
{
    for(size_t i=0;i<4096 && atomic_load_explicit(&m->captured_count,memory_order_acquire)<count;++i) (void)service_turn(&m->t);
    REQUIRE(atomic_load_explicit(&m->captured_count,memory_order_acquire)==count && m->captured);
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
    vireo_directory_root_task_result_t r={.stage=VIREO_DIRECTORY_ROOT_TASK_SERVICE};
    EXPECT(vireo_directory_root_task_read(m->captured,400,&r.input,&r.request_issue),VIREO_OK);
    r.service=(vireo_directory_root_result_t){.outcome=VIREO_DIRECTORY_ROOT_FOUND,.repository_called=true,
        .repository={.found=true,.rollback_confirmed=true},.root_node_id=42};
    if(m->error_result) r=(vireo_directory_root_task_result_t){.stage=VIREO_DIRECTORY_ROOT_TASK_CONTEXT,
        .input=r.input,.result=VIREO_RESULT_DATABASE};
    vireo_completion_t *left=NULL; vireo_directory_root_completion_publish_report_t p;
    EXPECT(vireo_directory_root_completion_publish(m->captured,400,&r,4096,m->root,m->t.notifier,&left,&p),VIREO_OK);
    REQUIRE(!left && p.publication.completion_transferred); EXPECT(vireo_task_destroy(&m->captured),VIREO_OK);
}
static vireo_node_root_response_t response(model_t *m,size_t n)
{
    unsigned char wire[393]; peer_read(&m->t,wire,n); vireo_node_root_response_t r; vireo_node_root_issue_t issue;
    EXPECT(vireo_node_root_response_decode(wire,n,&r,&issue),VIREO_OK); return r;
}
static void admission(void)
{
    model_t m; setup_model(&m,false);
    request(&m,10,0); vireo_node_root_response_t r=response(&m,32);
    REQUIRE(r.status==VIREO_STATUS_UNAUTHORIZED && !m.submit_calls && !atomic_load(&m.captured_count));
    uint32_t h=handle(&m);
    request(&m,11,h); wait_task(&m,1); publish(&m); r=response(&m,44);
    REQUIRE(r.status==VIREO_STATUS_OK && r.root_node_id==42 && r.session_handle==h);
    REQUIRE(m.submit_calls==1 && m.consume_calls==2 && m.t.service->expected_count==0);
    /* 合法共同framing但错误schema只给BAD_REQUEST，不发task。 */
    unsigned char wire[44]; size_t n=0; vireo_node_root_request_t req={12,h};
    EXPECT(vireo_node_root_request_encode(&req,wire,sizeof wire,&n),VIREO_OK);
    memset(wire+32,0,12); wire[15]=12; n=44; uint32_t crc=0; EXPECT(vireo_protocol_frame_crc32c_calculate(wire,32,wire+32,12,&crc),VIREO_OK);
    wire[28]=(unsigned char)(crc>>24); wire[29]=(unsigned char)(crc>>16); wire[30]=(unsigned char)(crc>>8); wire[31]=(unsigned char)crc;
    peer_write(&m.t,wire,n); r=response(&m,32); REQUIRE(r.status==VIREO_STATUS_BAD_REQUEST && m.submit_calls==1);
    request(&m,13,h+1); r=response(&m,32); REQUIRE(r.status==VIREO_STATUS_UNAUTHORIZED && m.submit_calls==1);
    m.t.service->o.task_allocation_budget=1;
    request(&m,14,h); r=response(&m,32); REQUIRE(r.status==VIREO_STATUS_OVERLOADED && m.submit_calls==1);
    m.t.service->o.task_allocation_budget=4096;
    finish_model(&m);
}
static void identity_and_deadline(void)
{
    for(unsigned kind=0;kind<10;++kind) {
        model_t m; setup_model(&m,true); uint32_t h=handle(&m); m.blocked=true;
        request(&m,20,h); wait_task(&m,1); m.error_result=kind==9; publish(&m);
        (void)service_turn(&m.t); REQUIRE(m.t.service->root_receipt.state==1 && m.t.service->expected_count==1);
        vireo_completion_info_t original; EXPECT(vireo_completion_inspect(m.t.service->root_completion,&original),VIREO_OK);
        if(kind==0) m.now=original.metadata.request.deadline_ns;
        if(kind==1) EXPECT(vireo_auth_session_revoke(m.t.f.sessions,99),VIREO_OK);
        if(kind==2) EXPECT(vireo_auth_session_forget(m.t.f.sessions,m.t.client),VIREO_OK);
        if(kind==3) { (void)handle(&m); } /* 替换handle，旧结果不能发给新绑定。 */
        if(kind==4) m.utc=UINT64_MAX; /* expires的闭区间边界。 */
        if(kind>=5) rebind(&m,h,kind==6 || kind==8 || kind==9?8:7,kind==7 || kind==8?100:99);
        bool const already_discarded=!m.t.service->root_completion;
        if(already_discarded) REQUIRE(kind==3); /* LOGIN的绑定决定点可在读auth响应时使STAT失效。 */
        m.blocked=false;
        if(kind==0 || kind==5) {
            vireo_node_root_response_t r=response(&m,kind==0?32:44);
            REQUIRE(r.status==(kind==0?VIREO_STATUS_TIMEOUT:VIREO_STATUS_OK));
        } else if(!already_discarded) {
            vireo_auth_service_report_t p=service_turn(&m.t); (void)p;
            vireo_directory_root_reactor_report_t stat; EXPECT(vireo_directory_root_reactor_inspect(m.t.service,&stat),VIREO_OK);
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
    REQUIRE(m.t.service->root_receipt.state==1);
    vireo_auth_response_t auth=auth_request(&m,false,31); REQUIRE(auth.sequence==31 && auth.status==VIREO_STATUS_OK);
    REQUIRE(m.t.service->root_completion && m.t.service->expected_count==1);
    EXPECT(vireo_auth_response_clear(&auth),VIREO_OK);
    stat_completion(&m,34,h);
    unsigned char stat_wire[90]; peer_read(&m.t,stat_wire,sizeof stat_wire);
    vireo_node_stat_response_t stat_response; vireo_node_stat_issue_t stat_issue;
    EXPECT(vireo_node_stat_response_decode(stat_wire,sizeof stat_wire,&stat_response,&stat_issue),VIREO_OK);
    REQUIRE(stat_response.status==VIREO_STATUS_OK && stat_response.sequence==34);
    REQUIRE(m.t.service->root_completion && !m.t.service->stat_completion && m.t.service->expected_count==1);
    m.blocked=false; m.refresh_error=true;
    vireo_auth_service_report_t p; EXPECT(vireo_auth_service_once(m.t.service,0,&p),VIREO_RESULT_IO);
    REQUIRE(m.t.service->root_receipt.state==2); unsigned enqueued=m.enqueue_calls;
    rebind(&m,h,8,100); /* FIFO决定点之后只补refresh，不能重核并重复发送。 */
    m.refresh_error=false; (void)service_turn(&m.t);
    REQUIRE(m.enqueue_calls==enqueued && !m.t.service->root_completion);
    vireo_node_root_response_t r=response(&m,44); REQUIRE(r.status==VIREO_STATUS_OK);
    finish_model(&m);
}
/** 原auth结果占满FIFO并take后，STAT仍退还自己的登记/交付；不是单向公平。 */
static void auth_blocked_stat_progress(void)
{
    model_t m; setup_model(&m,true); uint32_t h=handle(&m);
    request(&m,32,h); wait_task(&m,1);
    unsigned char wire[156]; size_t n=request_frame(wire,false,33,false); peer_write(&m.t,wire,n);
    for(size_t i=0;i<4096 && m.t.submitted<4;++i) (void)service_turn(&m.t);
    vireo_completion_queue_info_t q={0};
    for(size_t i=0;i<100000;++i) {
        vireo_result_t rc=vireo_completion_queue_inspect(m.t.queue,&q);
        if(rc==VIREO_RESULT_BUSY) continue;
        REQUIRE(rc==VIREO_OK); if(q.count) break; REQUIRE(sched_yield()==0);
    }
    REQUIRE(q.count==1);
    unsigned char filler[4096]; memset(filler,0xa5,sizeof filler);
    EXPECT(vireo_tcp_server_client_write_enqueue(m.t.f.server,m.t.client,filler,sizeof filler,NULL),VIREO_OK);
    vireo_auth_service_report_t p=service_turn(&m.t);
    REQUIRE(p.response_blocked && m.t.service->completion && m.t.service->receipt.state==VIREO_AUTH_CONSUMER_NEEDS_ENQUEUE);
    publish(&m);
    uint64_t hints=0; EXPECT(vireo_notifier_consume(m.t.notifier,&hints,NULL),VIREO_OK); /* hint0仍检查两queue。 */
    (void)service_turn(&m.t);
    REQUIRE(m.t.service->root_completion && m.t.service->root_receipt.state==1 && m.t.service->completion);
    vireo_inflight_store_info_t store; EXPECT(vireo_inflight_store_inspect(m.t.f.store,&store),VIREO_OK);
    REQUIRE(store.count==0 && m.t.service->expected_count==2); /* 两类都take，只有FIFO阻塞。 */
    finish_model(&m);
}
/** store.capacity + 两类已take恢复项的真实极限，reserve不改变LOGIN扣费路径。 */
static void stat_completion(model_t *m,uint32_t seq,uint32_t handle_value)
{
    vireo_auth_service_t *s=m->t.service; size_t index=SIZE_MAX;
    EXPECT(vireo_stat_reactor_reserve(s,m->t.client,seq,VIREO_COMMAND_NODE_STAT,&index),VIREO_OK); REQUIRE(index!=SIZE_MAX);
    vireo_task_metadata_t meta;
    EXPECT(vireo_inflight_metadata_make_next(m->t.f.server,m->t.client,seq,401,UINT64_MAX,&meta,NULL),VIREO_OK);
    EXPECT(vireo_inflight_store_register_limited(m->t.f.store,m->t.f.server,meta,8,NULL),VIREO_OK);
    s->expected[index]=(vireo_stat_expected_t){.command=VIREO_COMMAND_NODE_STAT,.committed=true,.metadata=meta,
        .request={seq,handle_value,42},.actor={7,99}}; ++s->expected_count;
    unsigned char wire[44]; size_t n=0; vireo_node_stat_request_t request_value={seq,handle_value,42};
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
static void mirror_capacity(void)
{
    model_t m; setup_model(&m,true); uint32_t h=handle(&m); m.blocked=true;
    request(&m,80,h); wait_task(&m,1); publish(&m); (void)service_turn(&m.t);
    REQUIRE(m.t.service->root_receipt.state==1);
    unsigned char wire[156]; size_t n=request_frame(wire,false,81,false); peer_write(&m.t,wire,n);
    for(size_t i=0;i<4096 && m.t.submitted<4;++i) (void)service_turn(&m.t);
    vireo_completion_queue_info_t q={0};
    for(size_t i=0;i<100000;++i) {
        vireo_result_t rc=vireo_completion_queue_inspect(m.t.queue,&q); if(rc==VIREO_RESULT_BUSY) continue;
        REQUIRE(rc==VIREO_OK); if(q.count) break; REQUIRE(sched_yield()==0);
    }
    unsigned char filler[4096]; memset(filler,0,sizeof filler);
    EXPECT(vireo_tcp_server_client_write_enqueue(m.t.f.server,m.t.client,filler,sizeof filler,NULL),VIREO_OK);
    (void)service_turn(&m.t);
    REQUIRE(m.t.service->completion && m.t.service->root_completion && m.t.service->expected_count==2);
    stat_completion(&m,91,h);
    (void)service_turn(&m.t);
    REQUIRE(m.t.service->stat_receipt.state==1 && m.t.service->expected_count==3);
    for(uint32_t seq=82;seq<90;++seq) {
        size_t index=SIZE_MAX;
        EXPECT(vireo_stat_reactor_reserve(m.t.service,m.t.client,seq,VIREO_COMMAND_REGISTER,&index),VIREO_OK);
        REQUIRE(index!=SIZE_MAX);
        vireo_task_metadata_t metadata;
        EXPECT(vireo_inflight_metadata_make_next(m.t.f.server,m.t.client,seq,100,1000,&metadata,NULL),VIREO_OK);
        EXPECT(vireo_inflight_store_register_limited(m.t.f.store,m.t.f.server,metadata,8,NULL),VIREO_OK);
        vireo_auth_request_submit_report_t r={.submit_report={.metadata=metadata,.metadata_created=true,
            .submit_report={.record_retained=true}}};
        EXPECT(vireo_stat_reactor_commit_auth(m.t.service,index,&r),VIREO_OK);
    }
    REQUIRE(m.t.service->expected_count==11 && m.t.service->expected_capacity==11);
    size_t index=0; EXPECT(vireo_stat_reactor_reserve(m.t.service,m.t.client,90,VIREO_COMMAND_LOGIN,&index),VIREO_OK);
    REQUIRE(index==SIZE_MAX);
    EXPECT(vireo_stat_reactor_reserve(m.t.service,m.t.client,80,VIREO_COMMAND_LOGIN,&index),VIREO_RESULT_PROTOCOL);
    EXPECT(vireo_stat_reactor_reserve(m.t.service,m.t.client,81,VIREO_COMMAND_NODE_ROOT,&index),VIREO_RESULT_PROTOCOL);
    /* 未结束的take后镜像仍查重；本轮cleanup_slots=2分阶段退出，无整表偷扫。 */
    EXPECT(vireo_auth_service_disconnect(m.t.service,m.t.client),VIREO_OK);
    (void)service_turn(&m.t); REQUIRE(m.t.service->active==1 && m.t.service->slots[0].cleanup_index==2);
    for(size_t i=0;i<3;++i) (void)service_turn(&m.t);
    REQUIRE(m.t.service->active==1 && m.t.service->slots[0].records_cleaned && m.t.service->slots[0].expected_cursor==2);
    finish_model(&m);
}
static void mismatch_before_take(void)
{
    for(unsigned field=0;field<12;++field) {
        model_t m; setup_model(&m,true); uint32_t h=handle(&m);
        request(&m,40,h); wait_task(&m,1); publish(&m);
        vireo_stat_expected_t *e=NULL;
        for(size_t i=0;i<m.t.service->expected_capacity;++i) if(m.t.service->expected[i].command==VIREO_COMMAND_NODE_ROOT) e=&m.t.service->expected[i];
        REQUIRE(e); vireo_stat_expected_t saved=*e;
        switch(field) {
        case 0:e->metadata.request_instance_id++;break;case 1:e->root_request.session_handle++;break;
        case 2:e->actor.user_id++;break;case 3:e->actor.session_id++;break;
        case 4:e->metadata.deadline_ns++;break;case 5:e->metadata.operation++;break;
        case 6:e->root_request.sequence++;break;case 7:e->command=VIREO_COMMAND_LOGIN;break;
        case 8:e->committed=false;break;
        case 9:e->metadata.route.client_generation++;break;
        case 10:e->metadata.route.client_slot_index++;break;
        default:e->metadata.route.request_sequence++;break;
        }
        vireo_auth_service_report_t p; EXPECT(vireo_auth_service_once(m.t.service,0,&p),VIREO_RESULT_INTERNAL);
        vireo_inflight_store_info_t store; EXPECT(vireo_inflight_store_inspect(m.t.f.store,&store),VIREO_OK);
        REQUIRE(store.count==1 && m.t.service->root_completion && !m.enqueue_calls && !m.t.service->root_receipt.state);
        *e=saved; vireo_node_root_response_t r=response(&m,44); REQUIRE(r.status==VIREO_STATUS_OK); finish_model(&m);
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
            REQUIRE(m.t.service->slots[0].root_head.state==1); m.consume_error=false;
            (void)service_turn(&m.t); REQUIRE(!m.t.service->slots[0].root_head.state && m.submit_calls==1);
            wait_task(&m,1); publish(&m); REQUIRE(response(&m,44).status==VIREO_STATUS_OK);
        }
        finish_model(&m);
    }
}
/** 自洽的错误worker结果仍须被独立原请求拦下，不能只比内部重复字段。 */
static void forged_result(void)
{
    for(unsigned kind=0;kind<3;++kind) {
        model_t m; setup_model(&m,true); uint32_t h=handle(&m);
        request(&m,55,h); wait_task(&m,1);
        vireo_directory_root_input_t input; vireo_node_root_issue_t issue;
        EXPECT(vireo_directory_root_task_read(m.captured,400,&input,&issue),VIREO_OK);
        if(kind==0) input.request.session_handle++;
        if(kind==1) input.actor.user_id++;
        if(kind==2) input.actor.session_id++;
        unsigned char wire[44]; size_t n=0; EXPECT(vireo_node_root_request_encode(&input.request,wire,sizeof wire,&n),VIREO_OK);
        EXPECT(vireo_task_destroy(&m.captured),VIREO_OK);
        EXPECT(vireo_directory_root_task_create(input.metadata,400,wire,n,&input.actor,4096,NULL,&m.captured),VIREO_OK);
        publish(&m); vireo_auth_service_report_t p;
        EXPECT(vireo_auth_service_once(m.t.service,0,&p),VIREO_RESULT_INTERNAL);
        vireo_inflight_store_info_t store; EXPECT(vireo_inflight_store_inspect(m.t.f.store,&store),VIREO_OK);
        REQUIRE(store.count==1 && m.t.service->root_completion && !m.enqueue_calls);
        finish_model(&m);
    }
}
static void local_rejection_resume(void)
{
    model_t m; setup_model(&m,false); m.blocked=true;
    request(&m,56,0);
    for(size_t i=0;i<4096 && !m.consume_calls;++i) (void)service_turn(&m.t);
    REQUIRE(m.consume_calls==1 && m.t.service->slots[0].root_head.state==2);
    for(size_t i=0;i<3;++i) (void)service_turn(&m.t);
    REQUIRE(m.consume_calls==1 && !m.submit_calls);
    m.blocked=false; m.refresh_error=true; vireo_auth_service_report_t p;
    EXPECT(vireo_auth_service_once(m.t.service,0,&p),VIREO_RESULT_IO);
    REQUIRE(m.t.service->slots[0].root_head.rejection==1 && p.rejected==1);
    unsigned enqueued=m.enqueue_calls; m.refresh_error=false;
    (void)service_turn(&m.t); REQUIRE(m.enqueue_calls==enqueued && m.consume_calls==1);
    REQUIRE(response(&m,32).status==VIREO_STATUS_UNAUTHORIZED); finish_model(&m);
}
static void duplicates(void)
{
    for(unsigned kind=0;kind<3;++kind) {
        model_t m; setup_model(&m,true); uint32_t h=handle(&m); m.blocked=true;
        request(&m,60,h); wait_task(&m,1);
        if(kind) { publish(&m); (void)service_turn(&m.t); REQUIRE(m.t.service->root_receipt.state==1); }
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
    EXPECT(vireo_completion_queue_inspect(m.root,&q),VIREO_OK); REQUIRE(!q.count);
    REQUIRE(!m.t.service->expected_count && !m.enqueue_calls); finish_model(&m);
}
static void factories(void)
{
    model_t m; setup_model(&m,false);
    vireo_directory_root_reactor_report_t out={.submitted=99};
    EXPECT(vireo_directory_root_reactor_inspect(NULL,&out),VIREO_RESULT_INVALID_ARGUMENT); REQUIRE(out.submitted==99);
    /* 原四命令factory的STAT不可用由旧模式单独验证；不改旧公共ABI。 */
    finish_model(&m);
    service_setup(&m.t,execute,&m);
    vireo_completion_queue_options_t const qo={1,65536}; EXPECT(vireo_completion_queue_create(&qo,&m.root),VIREO_OK);
    EXPECT(vireo_completion_queue_prepare_wait(m.root),VIREO_OK);
    EXPECT(vireo_completion_queue_create(&qo,&m.stat),VIREO_OK); EXPECT(vireo_completion_queue_prepare_wait(m.stat),VIREO_OK);
    vireo_auth_service_resources_t const r={m.t.f.server,m.t.f.store,m.t.workers,m.t.admission,m.t.f.sessions,m.t.queue,m.t.notifier,m.t.audit};
    vireo_auth_service_options_t o=service_options();
    vireo_completion_queue_t *unprepared=NULL;
    EXPECT(vireo_completion_queue_create(&qo,&unprepared),VIREO_OK);
    EXPECT(vireo_directory_root_reactor_create(&r,&o,m.stat,401,unprepared,400,&m.t.service),VIREO_RESULT_NOT_FOUND);
    vireo_completion_queue_close_report_t closed;
    EXPECT(vireo_completion_queue_close(unprepared,&closed),VIREO_OK);
    EXPECT(vireo_directory_root_reactor_create(&r,&o,m.stat,401,unprepared,400,&m.t.service),VIREO_RESULT_CANCELLED);
    EXPECT(vireo_completion_queue_destroy(&unprepared),VIREO_OK);
    for(uint32_t op=100;op<=103;++op) EXPECT(vireo_directory_root_reactor_create(&r,&o,m.stat,401,m.root,op,&m.t.service),VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_directory_root_reactor_create(&r,&o,m.stat,401,m.t.queue,400,&m.t.service),VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_directory_root_reactor_create(&r,&o,m.stat,401,m.root,401,&m.t.service),VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_directory_root_reactor_create(&r,&o,m.stat,401,m.stat,400,&m.t.service),VIREO_RESULT_INVALID_ARGUMENT);
    o.max_memory_bytes=1; EXPECT(vireo_directory_root_reactor_create(&r,&o,m.stat,401,m.root,400,&m.t.service),VIREO_RESULT_RANGE);
    service_create(&m.t); EXPECT(vireo_directory_root_reactor_inspect(m.t.service,&out),VIREO_RESULT_NOT_FOUND); REQUIRE(out.submitted==99);
    o=service_options(); vireo_auth_service_t *other=NULL;
    EXPECT(vireo_directory_root_reactor_create(&r,&o,m.stat,401,m.root,400,&other),VIREO_RESULT_BUSY); REQUIRE(!other);
    EXPECT(vireo_auth_service_destroy(&m.t.service),VIREO_OK); /* 失败factory没有注销原owner的唯一绑定。 */
    EXPECT(vireo_directory_stat_reactor_create(&r,&o,m.stat,401,&m.t.service),VIREO_OK);
    EXPECT(vireo_directory_root_reactor_inspect(m.t.service,&out),VIREO_RESULT_NOT_FOUND);
    REQUIRE(out.submitted==99); EXPECT(vireo_auth_service_destroy(&m.t.service),VIREO_OK);
    service_create(&m.t);
    peer_connect(&m.t); m.t.client=m.t.service->slots[0].client;
    vireo_node_root_request_t const req={70,0}; unsigned char wire[44]; size_t n=0;
    EXPECT(vireo_node_root_request_encode(&req,wire,sizeof wire,&n),VIREO_OK); peer_write(&m.t,wire,n);
    vireo_auth_service_report_t p={0};
    EXPECT(wait_error(m.t.service,&p),VIREO_OK);
    REQUIRE(p.first_client_result==VIREO_RESULT_PROTOCOL);
    for(size_t i=0;i<16;++i) (void)service_turn(&m.t);
    /* 复用本测试已确认三queue关闭后join的清理，处理worker短暂持锁。 */
    finish_model(&m);
}
int main(void)
{
    REQUIRE(signal(SIGPIPE,SIG_IGN)!=SIG_ERR); size_t before=fds();
    admission(); identity_and_deadline(); independent_and_resume(); auth_blocked_stat_progress(); mirror_capacity(); mismatch_before_take();
    consume_and_transfer(); forged_result(); local_rejection_resume(); duplicates(); shutdown_logout(); factories(); REQUIRE(fds()==before);
    puts("PASS directory_root_reactor: loopback TLS, admission, independent queues, identity/deadline retry, before-take association, consume/transfer/rollback, duplicate sequences, four-close/join/final-drain, fd cleanup");
    return 0;
}
