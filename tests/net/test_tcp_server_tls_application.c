/*
- PROJECT : VIREO
- FILE    : test_tcp_server_tls_application.c
- AUTHOR  : bitofux
- DATE    : 2026-10-18
- BRIEF   : 此模块负责：
- -- 本server TLS应用预算/关注/续调度及真实TCP应用闭环验证
 */
#define _GNU_SOURCE
#include "net/tcp_server_internal.h"
#include "tls_context_fixtures.h"
#include <vireo/protocol/codec.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

#define CHECK(c) do { if (!(c)) { fprintf(stderr,"%s:%d: %s\n",__FILE__,__LINE__,#c); abort(); } } while (0)
#define EXPECT(call, expected) do { errno=ECHILD; vireo_result_t observed=(call); \
    if (observed!=(expected)) fprintf(stderr,"result=%d expected=%d\n",(int)observed,(int)(expected)); \
    CHECK(observed==(expected)); CHECK(errno==ECHILD); } while (0)
static unsigned groups;
static vireo_tcp_server_options_t const root_options = {4,8,1048576,32768};
static vireo_tcp_server_tls_options_t const tls_options = {
    {4096,4096,40960,128,127,4096,0,4096},4096,UINT64_C(5000000000),163840
};

/** 仅观察本进程fd净变化，包含opendir自身，不冒作一般资源证明。 */
static size_t fd_count(void)
{
    DIR *d=opendir("/proc/self/fd"); CHECK(d!=NULL); size_t n=0; struct dirent *e;
    while ((e=readdir(d))!=NULL) if (strcmp(e->d_name,".") && strcmp(e->d_name,"..")) ++n;
    CHECK(closedir(d)==0); return n;
}
static vireo_tls_context_t *make_context(void)
{
    vireo_tls_context_options_t const o={fixture_leaf,sizeof(fixture_leaf)-1,
        fixture_key,sizeof(fixture_key)-1,4096};
    vireo_tls_context_t *c=NULL; EXPECT(vireo_tls_context_create_server(&o,&c,NULL),VIREO_OK); return c;
}
static bool same(vireo_connection_pool_lease_t a,vireo_connection_pool_lease_t b)
{ return a.pool_id==b.pool_id && a.slot_index==b.slot_index && a.generation==b.generation; }
static bool empty(vireo_connection_pool_lease_t a)
{ return a.pool_id==0 && a.slot_index==0 && a.generation==0; }

enum fault { F_NONE,F_ALLOC,F_LOOP,F_LOOP_INSPECT,F_POOL,F_POOL_INSPECT,F_ACCEPT,F_NOW,F_CREATE,
    F_PREPARE,F_ARM,F_ADOPT,F_LOOKUP,F_ATTACH,F_MOD,F_DETACH,F_WAIT,F_INSPECT,F_DEADLINE,F_IO_INSPECT,F_FLOW,F_RECEIVE,F_SEND,F_CLOSE_INSPECT,F_CONSUME,F_ENQUEUE,F_MAX };
/** 所有句柄仅属测试；objects/callbacks/fds均为短借，清理owner始终走公开server。 */
typedef struct fixture {
    vireo_tcp_server_t *server;
    struct sockaddr_in address;
    int peers[4];
    SSL *ssl[4];
    vireo_connection_pool_lease_t clients[4];
    vireo_connection_t *objects[8];
    vireo_connection_callback_t callbacks[8];
    void *callback_contexts[8];
    int accepted_fds[8];
    size_t created, attached, peers_count;
    enum fault fault;
    unsigned fail_on, calls[F_MAX];
    bool fake_clock, model_wait, probe, stop_in_wait, notify_in_wait, consume_release_io;
    uint64_t now, advance_ns;
    int waited_ms;
    size_t allocations;
    unsigned native_steps;
    unsigned receive_calls, send_calls, flow_calls, handler_calls, queue_calls;
    char sequence[32]; size_t sequence_size;
    bool model_write_retry, model_read_retry, model_io_failed, model_io_full, reject_native, fail_flow_after_data;
    bool model_send_clears, model_partial_failure, reenter, handler_fail;
    vireo_result_t model_failure;
    size_t response_body_size;
    vireo_tls_handshake_wait_t model_step_wait; /**< 非NONE时只为本server关注分支模型，不调用SSL。 */
} fixture_t;
static bool hit(fixture_t *f, enum fault point)
{ ++f->calls[point]; return f->fault==point && f->calls[point]==f->fail_on; }

/** 仅本server依赖故障，失败不调用下层成功交接，绝不注入外模块private。 */
static void *allocate(void *ctx,size_t n)
{ fixture_t *f=ctx; if(hit(f,F_ALLOC))return NULL; void *p=malloc(n); if(p)++f->allocations; return p; }
static void deallocate(void *ctx,void *p)
{ fixture_t *f=ctx; CHECK(f->allocations>0); --f->allocations; free(p); }
static vireo_result_t create_loop(void *ctx,vireo_event_loop_options_t const *o,
    vireo_event_loop_t **p,vireo_event_loop_error_t *e)
{ if(hit(ctx,F_LOOP))return VIREO_RESULT_IO; return vireo_event_loop_create(o,p,e); }
static vireo_result_t inspect_loop(void *ctx,vireo_event_loop_t const *p,vireo_event_loop_info_t *i)
{ if(hit(ctx,F_LOOP_INSPECT))return VIREO_RESULT_INTERNAL; return vireo_event_loop_inspect(p,i); }
static vireo_result_t destroy_loop(void *ctx,vireo_event_loop_t **p,vireo_event_loop_error_t *e)
{ (void)ctx; return vireo_event_loop_destroy(p,e); }
static vireo_result_t create_pool(void *ctx,vireo_connection_pool_options_t const *o,
    vireo_connection_pool_t **p,vireo_connection_pool_error_t *e)
{ if(hit(ctx,F_POOL))return VIREO_RESULT_NO_MEMORY; return vireo_connection_pool_create(o,p,e); }
static vireo_result_t inspect_pool(void *ctx,vireo_connection_pool_t const *p,vireo_connection_pool_info_t *i)
{ if(hit(ctx,F_POOL_INSPECT))return VIREO_RESULT_INTERNAL; return vireo_connection_pool_inspect(p,i); }
static vireo_result_t destroy_pool(void *ctx,vireo_connection_pool_t **p,vireo_connection_pool_error_t *e)
{ (void)ctx; return vireo_connection_pool_destroy(p,e); }
static vireo_tcp_server_ops_t base_ops(fixture_t *f)
{ return (vireo_tcp_server_ops_t){f,allocate,deallocate,create_loop,inspect_loop,destroy_loop,
    create_pool,inspect_pool,destroy_pool}; }

static vireo_result_t accept_one(void *ctx,vireo_acceptor_t *a,vireo_acceptor_accept_budget_t const *b,
    int *fd,size_t n,vireo_acceptor_accept_info_t *i,vireo_acceptor_error_t *e)
{
    if(hit(ctx,F_ACCEPT)) { *i=(vireo_acceptor_accept_info_t){.accept_calls=1};
        *e=(vireo_acceptor_error_t){VIREO_ACCEPTOR_STAGE_ACCEPT_CLIENT,EIO}; return VIREO_RESULT_IO; }
    return vireo_acceptor_accept_batch(a,b,fd,n,i,e);
}
static vireo_result_t create_raw(void *ctx,vireo_connection_options_t const *o,int *fd,
    vireo_connection_t **p,vireo_connection_error_t *e)
{ (void)ctx; return vireo_connection_create(o,fd,p,e); }
static vireo_result_t inspect_client(void *ctx,vireo_connection_t const *p,vireo_connection_info_t *i)
{ (void)ctx; return vireo_connection_inspect(p,i); }
static vireo_result_t adopt(void *ctx,vireo_connection_pool_t *p,vireo_connection_t **c,
    vireo_connection_pool_lease_t *l,vireo_connection_pool_operation_error_t *e)
{ if(hit(ctx,F_ADOPT))return VIREO_RESULT_NO_MEMORY; return vireo_connection_pool_adopt(p,c,l,e); }
static vireo_result_t lookup(void *ctx,vireo_connection_pool_t const *p,vireo_connection_pool_lease_t l,
    vireo_connection_t **c)
{ if(hit(ctx,F_LOOKUP))return VIREO_RESULT_INTERNAL; return vireo_connection_pool_lookup(p,l,c); }
static vireo_result_t attach(void *ctx,vireo_connection_t *c,vireo_event_loop_t *l,uint32_t m,
    vireo_connection_callback_t cb,void *arg,vireo_connection_loop_error_t *e)
{
    fixture_t *f=ctx; if(hit(f,F_ATTACH))return VIREO_RESULT_IO;
    vireo_result_t r=vireo_connection_attach(c,l,m,cb,arg,e);
    if(r==VIREO_OK) { CHECK(f->attached<8); f->objects[f->attached]=c;
        f->callbacks[f->attached]=cb; f->callback_contexts[f->attached++]=arg; }
    return r;
}
static vireo_result_t detach(void *ctx,vireo_connection_t *c,vireo_connection_loop_error_t *e)
{ if(hit(ctx,F_DETACH))return VIREO_RESULT_IO; return vireo_connection_detach(c,e); }
static vireo_result_t release(void *ctx,vireo_connection_pool_t *p,vireo_connection_pool_lease_t *l,
    vireo_connection_pool_operation_error_t *e)
{
    fixture_t *f=ctx; vireo_result_t r=vireo_connection_pool_release(p,l,e);
    if(r==VIREO_OK && f->consume_release_io) {
        f->consume_release_io=false; return VIREO_RESULT_IO; /* 真实消费后的清理IO模型，非内核close故障。 */
    }
    return r;
}
static vireo_result_t destroy_client(void *ctx,vireo_connection_t **c,vireo_connection_error_t *e)
{ (void)ctx; return vireo_connection_destroy(c,e); }
static int close_fd(void *ctx,int fd) { (void)ctx; return close(fd); }

/* 其余旧表仅做公共桥接，测试不会获得隐藏loop或外模块布局。 */
#define BRIDGE(name, parameters, expression) static vireo_result_t name parameters { (void)ctx; return (expression); }
BRIDGE(receive,(void *ctx,vireo_connection_t *c,vireo_connection_receive_budget_t const *b,
    vireo_connection_receive_info_t *i,vireo_connection_error_t *e),vireo_connection_receive(c,b,i,e))
BRIDGE(peek,(void *ctx,vireo_connection_t const *c,uint8_t const **p,size_t *n),vireo_connection_read_peek(c,p,n))
static vireo_result_t consume(void *ctx,vireo_connection_t *c,size_t n)
{ if(hit(ctx,F_CONSUME))return VIREO_RESULT_INTERNAL; return vireo_connection_read_consume(c,n); }
static vireo_result_t enqueue(void *ctx,vireo_connection_t *c,uint8_t const *p,size_t n,vireo_connection_error_t *e)
{ if(hit(ctx,F_ENQUEUE))return VIREO_RESULT_NO_MEMORY; return vireo_connection_write_enqueue(c,p,n,e); }
BRIDGE(send_bytes,(void *ctx,vireo_connection_t *c,vireo_connection_send_budget_t const *b,
    vireo_connection_send_info_t *i,vireo_connection_error_t *e),vireo_connection_send(c,b,i,e))
BRIDGE(frames,(void *ctx,vireo_connection_t const *c,vireo_connection_frame_options_t const *o,
    vireo_connection_frame_budget_t const *b,vireo_connection_frame_view_t *v,size_t n,
    vireo_connection_frame_info_t *i,vireo_connection_frame_error_t *e),vireo_connection_frames_peek(c,o,b,v,n,i,e))
BRIDGE(flow_configure,(void *ctx,vireo_connection_t *c,vireo_connection_flow_options_t const *o,
    vireo_connection_loop_error_t *e),vireo_connection_flow_configure(c,o,e))
BRIDGE(flow_refresh,(void *ctx,vireo_connection_t *c,vireo_connection_loop_error_t *e),vireo_connection_flow_refresh(c,e))
BRIDGE(flow_disable,(void *ctx,vireo_connection_t *c,vireo_connection_loop_error_t *e),vireo_connection_flow_disable(c,e))
BRIDGE(request_close,(void *ctx,vireo_connection_t *c,vireo_connection_close_mode_t m,
    vireo_connection_close_reason_t r,vireo_connection_loop_error_t *e),vireo_connection_request_close(c,m,r,e))
BRIDGE(close_refresh,(void *ctx,vireo_connection_t *c,vireo_connection_loop_error_t *e),vireo_connection_close_refresh(c,e))
#undef BRIDGE
static vireo_result_t set_interests(void *ctx,vireo_connection_t *c,uint32_t mask,vireo_connection_loop_error_t *e)
{
    if(hit(ctx,F_MOD)) { *e=(vireo_connection_loop_error_t){.stage=VIREO_CONNECTION_LOOP_STAGE_UPDATE,
        .loop_error={.stage=VIREO_EVENT_LOOP_STAGE_MOD,.epoll_error={VIREO_EPOLL_STAGE_MOD,EIO}}};
        return VIREO_RESULT_IO; }
    return vireo_connection_set_interests(c,mask,e);
}
static vireo_tcp_server_client_ops_t client_ops(fixture_t *f)
{ return (vireo_tcp_server_client_ops_t){f,accept_one,create_raw,inspect_client,adopt,lookup,attach,
    detach,release,destroy_client,close_fd,receive,peek,consume,enqueue,send_bytes,frames,set_interests,
    flow_configure,flow_refresh,flow_disable,request_close,close_refresh}; }

/** 模型时钟仅控制本server输入，原TLS仍通过公开arm/step；不改其私有字段。 */
static vireo_result_t now(void *ctx,vireo_monotonic_ns_t *n,vireo_clock_error_t *e)
{
    fixture_t *f=ctx; if(hit(f,F_NOW)) { *e=(vireo_clock_error_t){VIREO_CLOCK_STAGE_READ,EIO}; return VIREO_RESULT_IO; }
    if(f->fake_clock) { *n=f->now; *e=(vireo_clock_error_t){0}; return VIREO_OK; }
    return vireo_clock_monotonic_now(n,e);
}
static vireo_result_t create_tls(void *ctx,vireo_tls_context_t const *c,vireo_tls_connection_options_t const *o,
    int *fd,vireo_connection_t **p,vireo_connection_error_t *e)
{
    fixture_t *f=ctx; if(hit(f,F_CREATE))return VIREO_RESULT_NO_MEMORY;
    CHECK(f->created<8); int const observed_fd=*fd;
    vireo_result_t r=vireo_connection_create_tls_server(c,o,fd,p,e);
    if(r==VIREO_OK) f->accepted_fds[f->created++]=observed_fd;
    return r;
}
static vireo_result_t prepare(void *ctx,vireo_tls_connection_t *t,vireo_tls_io_options_t const *o,
    vireo_tls_connection_error_t *e)
{ if(hit(ctx,F_PREPARE))return VIREO_RESULT_NO_MEMORY; return vireo_tls_connection_io_prepare(t,o,e); }
static vireo_result_t arm(void *ctx,vireo_tls_connection_t *t,vireo_monotonic_ns_t n,vireo_monotonic_ns_t d,
    vireo_tls_connection_error_t *e)
{ if(hit(ctx,F_ARM))return VIREO_RESULT_INTERNAL; return vireo_tls_connection_handshake_deadline_arm(t,n,d,e); }
static vireo_result_t inspect_tls(void *ctx,vireo_tls_connection_t const *t,vireo_tls_connection_info_t *i,
    vireo_tls_connection_error_t *e)
{ if(hit(ctx,F_INSPECT))return VIREO_RESULT_INTERNAL; return vireo_tls_connection_inspect(t,i,e); }
static vireo_result_t deadline(void *ctx,vireo_tls_connection_t const *t,vireo_tls_handshake_deadline_info_t *i,
    vireo_tls_connection_error_t *e)
{ if(hit(ctx,F_DEADLINE))return VIREO_RESULT_INTERNAL; return vireo_tls_connection_handshake_deadline_inspect(t,i,e); }
static vireo_result_t step(void *ctx,vireo_tls_connection_t *t,vireo_monotonic_ns_t n,
    vireo_tls_handshake_info_t *i,vireo_tls_connection_error_t *e)
{
    fixture_t *f=ctx;
    if(f->model_step_wait!=VIREO_TLS_HANDSHAKE_WAIT_NONE) {
        *i=(vireo_tls_handshake_info_t){VIREO_TLS_HANDSHAKE_HANDSHAKING,f->model_step_wait,true};
        *e=(vireo_tls_connection_error_t){0}; return VIREO_OK; /* 仅依赖输出模型，不宣称native进度。 */
    }
    vireo_result_t r=vireo_tls_connection_handshake_step_at(t,n,i,e);
    if(i->native_called)++f->native_steps;
    return r;
}
/** 模型只改变本server公开依赖的返回/观察，不访问TLS布局，不伪造已发字节。 */
static vireo_result_t application_inspect(void *ctx,vireo_tls_connection_t const *t,vireo_tls_io_info_t *i,
    vireo_tls_connection_error_t *e)
{
    fixture_t *f=ctx; if(hit(f,F_IO_INSPECT))return VIREO_RESULT_INTERNAL;
    vireo_result_t r=vireo_tls_connection_io_inspect(t,i,e);
    if(r==VIREO_OK) {
        if(f->model_write_retry) { i->write_retry_bytes=32; i->write_wait=VIREO_TLS_IO_WAIT_READ; }
        if(f->model_read_retry) { i->read_retry_bytes=32; i->read_wait=VIREO_TLS_IO_WAIT_WRITE; }
        if(f->model_io_failed)i->state=VIREO_TLS_IO_FAILED;
    }
    return r;
}
static vireo_result_t application_flow(void *ctx,vireo_tls_connection_t *t,vireo_tls_io_flow_t *i,
    vireo_tls_connection_error_t *e)
{
    fixture_t *f=ctx; ++f->flow_calls;
    if(hit(f,F_FLOW) || (f->fail_flow_after_data && f->handler_calls!=0)) {
        *e=(vireo_tls_connection_error_t){.stage=VIREO_TLS_CONNECTION_STAGE_INSPECT,.system_errno=EIO};
        return VIREO_RESULT_INTERNAL;
    }
    vireo_result_t r=vireo_tls_connection_flow_refresh(t,i,e);
    if(r==VIREO_OK) {
        if(f->model_write_retry)*i=(vireo_tls_io_flow_t){.want_read=true,.write_pressure=true,
            .priority_retry=VIREO_TLS_IO_OPERATION_WRITE};
        if(f->model_read_retry)*i=(vireo_tls_io_flow_t){.want_write=true,.read_pressure=true,
            .priority_retry=VIREO_TLS_IO_OPERATION_READ};
        if(f->model_io_failed)*i=(vireo_tls_io_flow_t){0};
    }
    return r;
}
static vireo_result_t application_io(fixture_t *f,vireo_tls_connection_t *t,vireo_tls_io_budget_t const *b,
    vireo_tls_io_progress_t *i,vireo_tls_connection_error_t *e,bool writing)
{
    if(f->sequence_size<sizeof(f->sequence))f->sequence[f->sequence_size++]=writing?'W':'R';
    if(writing)++f->send_calls; else ++f->receive_calls;
    if(f->reject_native) {
        *e=(vireo_tls_connection_error_t){.stage=VIREO_TLS_CONNECTION_STAGE_SIGNAL_POLICY};
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    if(hit(f,writing?F_SEND:F_RECEIVE) || f->model_io_failed) {
        *e=(vireo_tls_connection_error_t){.stage=writing?VIREO_TLS_CONNECTION_STAGE_SEND:VIREO_TLS_CONNECTION_STAGE_RECEIVE,
            .system_errno=EPIPE};
        *i=(vireo_tls_io_progress_t){.stop_reason=VIREO_TLS_IO_STOP_ERROR};
        return f->model_failure!=VIREO_OK?f->model_failure:VIREO_RESULT_IO;
    }
    if((writing && f->model_write_retry) || (!writing && f->model_read_retry)) {
        *i=(vireo_tls_io_progress_t){.native_calls=1,.stop_reason=VIREO_TLS_IO_STOP_WOULD_BLOCK,
            .wait=writing?VIREO_TLS_IO_WAIT_READ:VIREO_TLS_IO_WAIT_WRITE};
        if(writing && f->model_send_clears)f->model_write_retry=false;
        return VIREO_OK;
    }
    return writing?vireo_tls_connection_send(t,b,i,e):vireo_tls_connection_receive(t,b,i,e);
}
static vireo_result_t application_receive(void *ctx,vireo_tls_connection_t *t,vireo_tls_io_budget_t const *b,
    vireo_tls_io_progress_t *i,vireo_tls_connection_error_t *e)
{ return application_io(ctx,t,b,i,e,false); }
static vireo_result_t application_send(void *ctx,vireo_tls_connection_t *t,vireo_tls_io_budget_t const *b,
    vireo_tls_io_progress_t *i,vireo_tls_connection_error_t *e)
{ return application_io(ctx,t,b,i,e,true); }
static vireo_result_t application_close_inspect(void *ctx,vireo_tls_connection_t const *t,vireo_tls_close_info_t *i,
    vireo_tls_connection_error_t *e)
{ if(hit(ctx,F_CLOSE_INSPECT))return VIREO_RESULT_INTERNAL; return vireo_tls_connection_close_inspect(t,i,e); }
/**
 * @brief 桥接原关闭请求，仅成功时封口。
 * @param[in] ctx 不用的短借上下文。
 * @param[in,out] tls 同Reactor存活对象短借。
 * @param[in] now 同域本次采时。
 * @param[in] due checked后的固定期限。
 * @param[out] error 可空独立TLS原因。
 * @return 原公开分类，无网络/owner交接，外层恢复errno。
 */
static vireo_result_t close_request_bridge(void *ctx, vireo_tls_connection_t *tls,
    vireo_monotonic_ns_t now, vireo_monotonic_ns_t due, vireo_tls_connection_error_t *error)
{ (void)ctx; return vireo_tls_connection_close_request(tls, now, due, error); }
/**
 * @brief 桥接原关闭单步，不额外重试。
 * @param[in] ctx 不用的短借上下文。
 * @param[in,out] tls 同Reactor存活对象短借。
 * @param[in] now 同域新采时，终态忽略。
 * @param[in] bytes 已核正字节预算。
 * @param[out] info 必需独立报告，原生前拒绝保持。
 * @param[out] error 可空独立TLS原因。
 * @return 原公开分类，至多一次native，无owner交接，外层恢复errno。
 */
static vireo_result_t close_step_bridge(void *ctx, vireo_tls_connection_t *tls,
    vireo_monotonic_ns_t now, size_t bytes, vireo_tls_close_progress_t *info,
    vireo_tls_connection_error_t *error)
{ (void)ctx; return vireo_tls_connection_close_step_at(tls, now, bytes, info, error); }

static vireo_tcp_server_tls_ops_t tls_ops(fixture_t *f)
{ return (vireo_tcp_server_tls_ops_t){f,now,create_tls,prepare,arm,inspect_tls,deadline,step,
    application_inspect,application_flow,application_receive,application_send,application_close_inspect,close_request_bridge,close_step_bridge}; }
static vireo_result_t wait_once(void *ctx,vireo_event_loop_t *l,int timeout,
    vireo_event_loop_run_info_t *i,vireo_event_loop_error_t *e)
{
    fixture_t *f=ctx; f->waited_ms=timeout;
    if(f->probe) {
        vireo_tcp_server_tls_handshake_info_t progress;
        EXPECT(vireo_tcp_server_client_tls_handshake_step(f->server,f->clients[0],&progress,NULL),VIREO_RESULT_BUSY);
        vireo_tls_connection_t *borrowed=NULL;
        EXPECT(vireo_tcp_server_client_tls_borrow(f->server,f->clients[0],&borrowed,NULL),VIREO_RESULT_BUSY);
        vireo_connection_pool_lease_t lease=f->clients[0];
        EXPECT(vireo_tcp_server_release_client(f->server,&lease,NULL),VIREO_RESULT_BUSY);
    }
    if(hit(f,F_WAIT))return VIREO_RESULT_IO;
    if(f->stop_in_wait) EXPECT(vireo_event_loop_request_stop(l,NULL),VIREO_OK);
    if(f->notify_in_wait) {
        CHECK(f->attached>0); f->callbacks[0](f->objects[0],VIREO_EPOLL_EVENT_READ,f->callback_contexts[0]);
    }
    if(f->model_wait) { f->now+=f->advance_ns; return vireo_event_loop_run_once(l,0,i,e); }
    return vireo_event_loop_run_once(l,timeout,i,e);
}

/** 真实TCP listener资源装配，成功后fd唯一归server，不借内部loop。 */
static void listen_local(fixture_t *f)
{
    int fd=socket(AF_INET,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0); CHECK(fd>=0);
    f->address=(struct sockaddr_in){.sin_family=AF_INET,.sin_addr={htonl(INADDR_LOOPBACK)}};
    CHECK(bind(fd,(struct sockaddr *)&f->address,(socklen_t)sizeof(f->address))==0);
    socklen_t n=(socklen_t)sizeof(f->address);
    CHECK(getsockname(fd,(struct sockaddr *)&f->address,&n)==0); CHECK(listen(fd,8)==0);
    vireo_acceptor_t *a=NULL; vireo_acceptor_options_t const o={4096};
    EXPECT(vireo_acceptor_create(&o,&fd,&a,NULL),VIREO_OK); CHECK(fd==-1);
    EXPECT(vireo_tcp_server_adopt_listener(f->server,&a,NULL),VIREO_OK); CHECK(a==NULL);
    EXPECT(vireo_tcp_server_bind_listener(f->server,true,NULL),VIREO_OK);
}
static void start(fixture_t *f,vireo_tcp_server_options_t const *base,
    vireo_tcp_server_tls_options_t const *options,bool own)
{
    *f=(fixture_t){.peers={-1,-1,-1,-1},.fail_on=1,.now=UINT64_C(1000000000)};
    vireo_tls_context_t *context=make_context();
    if(own) {
        vireo_tcp_server_client_ops_t c=client_ops(f); vireo_tcp_server_tls_ops_t t=tls_ops(f);
        vireo_tcp_server_scheduler_ops_t w={f,wait_once}; vireo_tcp_server_ops_t b=base_ops(f);
        EXPECT(vireo_tcp_server_create_tls_with_ops(base,options,&context,&b,&c,&w,&t,&f->server,NULL),VIREO_OK);
    } else EXPECT(vireo_tcp_server_create_tls(base,options,&context,&f->server,NULL),VIREO_OK);
    CHECK(context==NULL); listen_local(f);
}
static void connect_one(fixture_t *f)
{
    CHECK(f->peers_count<4); int fd=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0); CHECK(fd>=0);
    CHECK(connect(fd,(struct sockaddr *)&f->address,(socklen_t)sizeof(f->address))==0);
    int flags=fcntl(fd,F_GETFL); CHECK(flags>=0 && fcntl(fd,F_SETFL,flags|O_NONBLOCK)==0);
    f->peers[f->peers_count++]=fd;
}
static vireo_tcp_server_tls_admit_info_t admit(fixture_t *f,size_t count,vireo_result_t expected,
    vireo_tcp_server_tls_error_t *error)
{
    vireo_tcp_server_admit_budget_t b={count,count+1}; vireo_tcp_server_tls_admit_info_t i={0};
    EXPECT(vireo_tcp_server_tls_admit_batch(f->server,&b,f->clients,4,&i,error),expected); return i;
}
static vireo_tls_connection_t *borrow(fixture_t *f,size_t k)
{
    vireo_tls_connection_t *tls=NULL;
    EXPECT(vireo_tcp_server_client_tls_borrow(f->server,f->clients[k],&tls,NULL),VIREO_OK); return tls;
}
static void finish(fixture_t *f)
{
    f->fault=F_NONE;
    for(size_t k=0;k<4;++k) {
        if(!empty(f->clients[k])) EXPECT(vireo_tcp_server_release_client(f->server,&f->clients[k],NULL),VIREO_OK);
        SSL_free(f->ssl[k]); f->ssl[k]=NULL;
        if(f->peers[k]>=0) { CHECK(close(f->peers[k])==0); f->peers[k]=-1; }
    }
    EXPECT(vireo_tcp_server_destroy(&f->server,NULL),VIREO_OK); CHECK(f->allocations==0);
}

/** native客户端只供互操作；固定测试时间/名称/根，不改系统信任库。 */
static void make_ssl(fixture_t *f,size_t k,bool trusted)
{
    SSL_CTX *c=SSL_CTX_new(TLS_client_method()); CHECK(c!=NULL);
    CHECK(SSL_CTX_set_min_proto_version(c,TLS1_3_VERSION)==1);
    CHECK(SSL_CTX_set_max_proto_version(c,TLS1_3_VERSION)==1); SSL_CTX_set_verify(c,SSL_VERIFY_PEER,NULL);
    if(trusted) {
        BIO *b=BIO_new_mem_buf(fixture_root,(int)sizeof(fixture_root)-1); CHECK(b!=NULL);
        X509 *x=PEM_read_bio_X509(b,NULL,NULL,NULL); CHECK(x!=NULL);
        CHECK(X509_STORE_add_cert(SSL_CTX_get_cert_store(c),x)==1); X509_free(x); CHECK(BIO_free(b)==1);
    }
    SSL *s=SSL_new(c); CHECK(s!=NULL); SSL_CTX_free(c);
    CHECK(SSL_set1_host(s,"vireo-034-test.invalid")==1);
    X509_VERIFY_PARAM_set_time(SSL_get0_param(s),(time_t)1800000000);
    BIO *b=BIO_new_socket(f->peers[k],BIO_NOCLOSE); CHECK(b!=NULL);
    SSL_set_bio(s,b,b); SSL_set_connect_state(s); f->ssl[k]=s;
}
static bool client_step(SSL *s,bool allow_failure)
{
    ERR_clear_error(); errno=0; int r=SSL_do_handshake(s); int why=r==1?SSL_ERROR_NONE:SSL_get_error(s,r);
    if(!allow_failure) CHECK(why==SSL_ERROR_NONE || why==SSL_ERROR_WANT_READ || why==SSL_ERROR_WANT_WRITE);
    return r==1;
}
/** 必须通过新poll取得租约后才step；有限外层循环，不把caller组合冒成自动服务。 */
static void establish(fixture_t *f,size_t count)
{
    bool done[4]={false}; bool server_done[4]={false};
    for(size_t round=0;round<1024;++round) {
        for(size_t k=0;k<count;++k) if(!done[k])done[k]=client_step(f->ssl[k],false);
        vireo_tcp_server_ready_client_t ready[4]; vireo_tcp_server_tls_poll_report_t p;
        EXPECT(vireo_tcp_server_tls_poll_ready_once(f->server,5,4,ready,4,&p,NULL),VIREO_OK);
        CHECK(p.scanned_slots==2*root_options.connection_capacity);
        for(size_t j=0;j<p.poll.selected_count;++j) {
            size_t k=0; while(k<count && !same(ready[j].client,f->clients[k]))++k; CHECK(k<count);
            vireo_tcp_server_tls_handshake_info_t h;
            EXPECT(vireo_tcp_server_client_tls_handshake_step(f->server,ready[j].client,&h,NULL),VIREO_OK);
            CHECK(h.step_called && h.sampled);
            if(h.application_ready)server_done[k]=true;
            else CHECK(h.handshake.state==VIREO_TLS_HANDSHAKE_HANDSHAKING);
        }
        bool all=true;
        for(size_t k=0;k<count;++k)all=all && done[k] && server_done[k];
        if(all) {
            for(size_t k=0;k<count;++k) CHECK(SSL_version(f->ssl[k])==TLS1_3_VERSION &&
                SSL_get_verify_result(f->ssl[k])==X509_V_OK);
            return;
        }
    }
    CHECK(false);
}


static vireo_tcp_server_process_options_t const process_options={32,32};
static vireo_tcp_server_tls_drive_budget_t const drive_budget={{4096,8},{1,32,32},{4096,8}};

static void record(fixture_t *f,char c)
{ if(f->sequence_size<sizeof(f->sequence))f->sequence[f->sequence_size++]=c; }
static vireo_result_t handler(vireo_connection_frame_view_t const *v,uint8_t *p,size_t n,
    vireo_tcp_server_reply_t *reply,void *ctx)
{
    fixture_t *f=ctx; ++f->handler_calls; record(f,'H'); CHECK(v->wire_size>=32);
    if(f->reenter) {
        vireo_tcp_server_tls_flow_info_t flow;
        EXPECT(vireo_tcp_server_client_tls_flow_refresh(f->server,f->clients[0],&flow,NULL),VIREO_RESULT_BUSY);
        uint8_t work[32]; vireo_tcp_server_tls_drive_info_t di;
        EXPECT(vireo_tcp_server_client_tls_drive(f->server,f->clients[0],&process_options,&drive_budget,
            work,sizeof(work),handler,f,&di,NULL),VIREO_RESULT_BUSY);
        vireo_connection_pool_lease_t lease=f->clients[0];
        EXPECT(vireo_tcp_server_release_client(f->server,&lease,NULL),VIREO_RESULT_BUSY);
        EXPECT(vireo_tcp_server_schedule_client(f->server,lease,NULL),VIREO_RESULT_BUSY);
        EXPECT(vireo_tcp_server_destroy(&f->server,NULL),VIREO_RESULT_BUSY);
        vireo_tcp_server_info_t si; EXPECT(vireo_tcp_server_inspect(f->server,&si),VIREO_OK);
        CHECK(si.driving_active && si.processing_active);
    }
    if(f->handler_fail)return VIREO_RESULT_IO;
    reply->body_size=f->response_body_size;
    for(size_t k=0;k<f->response_body_size && k<n;++k)p[k]=0x5a;
    return VIREO_OK;
}
static void make_frame(uint8_t *out,uint32_t seq,bool response)
{
    vireo_protocol_header_t h={.command=VIREO_COMMAND_PING,.sequence=seq};
    if(response)h.flags=VIREO_PROTOCOL_FLAG_RESPONSE;
    EXPECT(vireo_protocol_header_encode(&h,out,32),VIREO_OK);
    EXPECT(vireo_protocol_frame_crc32c_calculate(out,32,NULL,0,&h.crc32c),VIREO_OK);
    EXPECT(vireo_protocol_header_encode(&h,out,32),VIREO_OK);
}
static vireo_tcp_server_tls_drive_info_t drive(fixture_t *f,size_t k,
    vireo_tcp_server_process_options_t const *o,vireo_tcp_server_tls_drive_budget_t const *b,
    vireo_result_t expected,vireo_tcp_server_tls_application_error_t *e)
{
    uint8_t work[256]; CHECK(o->max_response_frame_bytes<=sizeof(work));
    vireo_tcp_server_tls_drive_info_t i;
    EXPECT(vireo_tcp_server_client_tls_drive(f->server,f->clients[k],o,b,work,sizeof(work),handler,f,&i,e),expected);
    return i;
}
static void clear_queue(fixture_t *f)
{
    vireo_tcp_server_ready_client_t ready[4]; vireo_tcp_server_tls_poll_report_t p;
    EXPECT(vireo_tcp_server_tls_poll_ready_once(f->server,0,4,ready,4,&p,NULL),VIREO_OK);
    CHECK(p.poll.remaining_count==0);
}
static void open_clients(fixture_t *f,size_t count,bool own)
{
    start(f,&root_options,&tls_options,own);
    for(size_t k=0;k<count;++k) { connect_one(f); make_ssl(f,k,true); }
    CHECK(admit(f,count,VIREO_OK,NULL).admission.admitted_count==count);
    establish(f,count); clear_queue(f);
    f->receive_calls=f->send_calls=f->flow_calls=f->handler_calls=0; f->sequence_size=0;
}
static void client_write(fixture_t *f,size_t k,uint8_t const *p,size_t n)
{
    for(unsigned r=0;r<256;++r) {
        ERR_clear_error(); size_t written=0; int result=SSL_write_ex(f->ssl[k],p,n,&written);
        int why=result==1?SSL_ERROR_NONE:SSL_get_error(f->ssl[k],result);
        if(result==1) { CHECK(written==n); return; }
        CHECK(why==SSL_ERROR_WANT_READ || why==SSL_ERROR_WANT_WRITE);
        struct pollfd fd={f->peers[k],why==SSL_ERROR_WANT_READ?POLLIN:POLLOUT,0}; CHECK(poll(&fd,1,5)>=0);
    }
    CHECK(false);
}
static void read_exact(fixture_t *f,size_t k,uint8_t *p,size_t n)
{
    size_t offset=0;
    for(unsigned r=0;r<512 && offset<n;++r) {
        ERR_clear_error(); size_t got=0; int result=SSL_read_ex(f->ssl[k],p+offset,n-offset,&got);
        int why=result==1?SSL_ERROR_NONE:SSL_get_error(f->ssl[k],result);
        if(result==1) { CHECK(got>0 && got<=n-offset); offset+=got; }
        else {
            CHECK(why==SSL_ERROR_WANT_READ || why==SSL_ERROR_WANT_WRITE);
            struct pollfd fd={f->peers[k],why==SSL_ERROR_WANT_READ?POLLIN:POLLOUT,0}; CHECK(poll(&fd,1,5)>=0);
        }
    }
    CHECK(offset==n);
}
/** 准备真实已解密缓存；后续drive不得靠新网络事件才处理它。 */
static void cache_bytes(fixture_t *f,size_t k,uint8_t const *p,size_t n)
{
    client_write(f,k,p,n); vireo_tls_connection_t *t=borrow(f,k);
    vireo_tls_io_budget_t const b={16384,8};
    for(unsigned r=0;r<128;++r) {
        vireo_tls_io_progress_t progress;
        EXPECT(vireo_tls_connection_receive(t,&b,&progress,NULL),VIREO_OK);
        vireo_tls_io_info_t io; EXPECT(vireo_tls_connection_io_inspect(t,&io,NULL),VIREO_OK);
        if(io.read_size>=n)return;
        struct pollfd fd={f->accepted_fds[k],POLLIN,0}; CHECK(poll(&fd,1,5)>=0);
    }
    CHECK(false);
}
static void queue_state(fixture_t *f,size_t k,bool queued)
{
    vireo_tcp_server_client_info_t i;
    EXPECT(vireo_tcp_server_client_inspect(f->server,f->clients[k],&i),VIREO_OK); CHECK(i.queued==queued);
}

static void gates_and_budgets(void)
{
    fixture_t f; open_clients(&f,1,true); uint8_t work[128]; memset(work,0xa5,sizeof(work));
    vireo_tcp_server_tls_drive_info_t i; vireo_tcp_server_tls_application_error_t e;
    EXPECT(vireo_tcp_server_client_tls_drive(NULL,f.clients[0],&process_options,&drive_budget,
        work,sizeof(work),handler,&f,&i,&e),VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(!i.receive_called && !i.process_called && !i.send_called);
    vireo_tcp_server_tls_drive_budget_t b=drive_budget;
    b.receive.max_bytes=4095; (void)drive(&f,0,&process_options,&b,VIREO_RESULT_RANGE,&e);
    b=drive_budget; b.send.max_bytes=4095; (void)drive(&f,0,&process_options,&b,VIREO_RESULT_RANGE,&e);
    b=drive_budget; b.receive.max_native_calls=0; (void)drive(&f,0,&process_options,&b,VIREO_RESULT_RANGE,&e);
    b=drive_budget; b.process.max_messages=0; (void)drive(&f,0,&process_options,&b,VIREO_RESULT_RANGE,&e);
    vireo_tcp_server_process_options_t o={129,32};
    (void)drive(&f,0,&o,&drive_budget,VIREO_RESULT_RANGE,&e);
    EXPECT(vireo_tcp_server_client_tls_drive(f.server,f.clients[0],&process_options,&drive_budget,
        work,31,handler,&f,&i,&e),VIREO_RESULT_RANGE);
    vireo_connection_pool_lease_t old=f.clients[0]; ++old.generation;
    EXPECT(vireo_tcp_server_client_tls_drive(f.server,old,&process_options,&drive_budget,
        work,sizeof(work),handler,&f,&i,&e),VIREO_RESULT_NOT_FOUND);
    vireo_connection_pool_lease_t wrong=f.clients[0]; ++wrong.pool_id;
    EXPECT(vireo_tcp_server_client_tls_drive(f.server,wrong,&process_options,&drive_budget,
        work,sizeof(work),handler,&f,&i,&e),VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(f.receive_calls==0 && f.send_calls==0 && f.handler_calls==0);
    for(size_t k=0;k<sizeof(work);++k)CHECK(work[k]==0xa5);
    finish(&f); ++groups;
}
static void phase_gates(void)
{
    fixture_t f; start(&f,&root_options,&tls_options,true); connect_one(&f); make_ssl(&f,0,true);
    (void)admit(&f,1,VIREO_OK,NULL);
    (void)drive(&f,0,&process_options,&drive_budget,VIREO_RESULT_BUSY,NULL);
    vireo_tcp_server_tls_flow_info_t flow;
    EXPECT(vireo_tcp_server_client_tls_flow_refresh(f.server,f.clients[0],&flow,NULL),VIREO_RESULT_BUSY);
    establish(&f,1); clear_queue(&f); vireo_tls_connection_t *t=borrow(&f,0);
    vireo_monotonic_ns_t now_ns=0; EXPECT(vireo_clock_monotonic_now(&now_ns,NULL),VIREO_OK);
    EXPECT(vireo_tls_connection_close_request(t,now_ns,now_ns+UINT64_C(1000000000),NULL),VIREO_OK);
    (void)drive(&f,0,&process_options,&drive_budget,VIREO_RESULT_BUSY,NULL);
    EXPECT(vireo_tcp_server_client_tls_flow_refresh(f.server,f.clients[0],&flow,NULL),VIREO_RESULT_BUSY);
    CHECK(f.receive_calls==0 && f.send_calls==0 && f.handler_calls==0);
    finish(&f);
    vireo_tcp_server_t *raw=NULL; EXPECT(vireo_tcp_server_create(&root_options,&raw,NULL),VIREO_OK);
    EXPECT(vireo_tcp_server_client_tls_flow_refresh(raw,(vireo_connection_pool_lease_t){0},&flow,NULL),VIREO_RESULT_BUSY);
    uint8_t work[32]; vireo_tcp_server_tls_drive_info_t i;
    EXPECT(vireo_tcp_server_client_tls_drive(raw,(vireo_connection_pool_lease_t){0},&process_options,
        &drive_budget,work,sizeof(work),handler,NULL,&i,NULL),VIREO_RESULT_BUSY);
    EXPECT(vireo_tcp_server_destroy(&raw,NULL),VIREO_OK); ++groups;
}
static void cached_three_and_half(void)
{
    fixture_t f; open_clients(&f,1,true); uint8_t request[96],response[96],got[96];
    for(uint32_t k=0;k<3;++k) { make_frame(request+32*k,10+k,false); make_frame(response+32*k,10+k,true); }
    cache_bytes(&f,0,request,sizeof(request)); clear_queue(&f);
    for(size_t k=0;k<3;++k) {
        vireo_tcp_server_tls_drive_info_t i=drive(&f,0,&process_options,&drive_budget,VIREO_OK,NULL);
        CHECK(i.process.consumed_requests==1 && i.send.bytes==32);
        CHECK(i.needs_processing==(k<2)); queue_state(&f,0,k<2);
        if(k<2) {
            CHECK(i.sync.queue_called && i.sync.continuation_pending);
            vireo_tcp_server_ready_client_t ready; vireo_tcp_server_tls_poll_report_t p;
            EXPECT(vireo_tcp_server_tls_poll_ready_once(f.server,100,1,&ready,1,&p,NULL),VIREO_OK);
            CHECK(p.poll.selected_count==1 && same(ready.client,f.clients[0]) && ready.events==0);
            CHECK(p.poll.effective_timeout_ms==0);
        }
    }
    CHECK(f.handler_calls==3); read_exact(&f,0,got,sizeof(got)); CHECK(memcmp(got,response,sizeof(got))==0);
    cache_bytes(&f,0,request,7); clear_queue(&f);
    vireo_tcp_server_tls_drive_info_t i=drive(&f,0,&process_options,&drive_budget,VIREO_OK,NULL);
    CHECK(i.process.stop_reason==VIREO_TCP_SERVER_PROCESS_NEED_MORE && !i.needs_processing && !i.sync.queue_called);
    queue_state(&f,0,false);
    client_write(&f,0,request+7,25);
    for(unsigned n=0;n<128 && f.handler_calls==3;++n) {
        clear_queue(&f); (void)drive(&f,0,&process_options,&drive_budget,VIREO_OK,NULL);
        if(f.handler_calls==3) { struct pollfd p={f.accepted_fds[0],POLLIN,0}; CHECK(poll(&p,1,5)>=0); }
    }
    CHECK(f.handler_calls==4); read_exact(&f,0,got,32); CHECK(memcmp(got,response,32)==0);
    finish(&f); ++groups;
}
static void processing_byte_budgets(void)
{
    for(unsigned which=0;which<2;++which) {
        fixture_t f; open_clients(&f,1,true); uint8_t bytes[96];
        for(uint32_t k=0;k<3;++k)make_frame(bytes+32*k,20+k,false);
        cache_bytes(&f,0,bytes,sizeof(bytes)); clear_queue(&f);
        vireo_tcp_server_tls_drive_budget_t b=drive_budget; b.process=(vireo_tcp_server_process_budget_t){10,320,320};
        if(which==0)b.process.max_request_bytes=32; else b.process.max_response_bytes=32;
        vireo_tcp_server_tls_drive_info_t i=drive(&f,0,&process_options,&b,VIREO_OK,NULL);
        CHECK(i.process.consumed_requests==1 && i.needs_processing && i.sync.continuation_pending);
        CHECK(i.process.stop_reason==(which==0?VIREO_TCP_SERVER_PROCESS_REQUEST_BUDGET:VIREO_TCP_SERVER_PROCESS_RESPONSE_BUDGET));
        finish(&f); ++groups;
    }
}
static void native_call_budget(void)
{
    fixture_t f; open_clients(&f,1,true); uint8_t bytes[32]; make_frame(bytes,1,false);
    client_write(&f,0,bytes,32); make_frame(bytes,2,false); client_write(&f,0,bytes,32);
    vireo_tcp_server_tls_drive_budget_t b=drive_budget; b.receive.max_native_calls=1;
    vireo_tcp_server_tls_drive_info_t i={0};
    for(unsigned k=0;k<128;++k) {
        i=drive(&f,0,&process_options,&b,VIREO_OK,NULL);
        if(i.receive.bytes!=0)break;
        struct pollfd p={f.accepted_fds[0],POLLIN,0}; CHECK(poll(&p,1,5)>=0);
    }
    CHECK(i.receive.native_calls==1 && i.receive.bytes==32 && i.receive.stop_reason==VIREO_TLS_IO_STOP_CALL_BUDGET);
    CHECK(i.sync.flow.resume_read && i.sync.continuation_pending); finish(&f); ++groups;
}
static void library_pending(void)
{
    fixture_t f; open_clients(&f,1,true); uint8_t bytes[8192],expected[8192],got[8192];
    for(uint32_t k=0;k<256;++k) { make_frame(bytes+32*k,k+1,false); make_frame(expected+32*k,k+1,true); }
    client_write(&f,0,bytes,sizeof(bytes));
    vireo_tcp_server_tls_drive_budget_t b=drive_budget; b.process=(vireo_tcp_server_process_budget_t){128,4096,4096};
    vireo_tcp_server_tls_drive_info_t i={0};
    for(unsigned k=0;k<128;++k) {
        i=drive(&f,0,&process_options,&b,VIREO_OK,NULL);
        if(i.receive.bytes!=0)break;
        struct pollfd p={f.accepted_fds[0],POLLIN,0}; CHECK(poll(&p,1,5)>=0);
    }
    CHECK(i.receive.bytes==4096 && i.receive.stop_reason==VIREO_TLS_IO_STOP_BUFFER_FULL);
    CHECK(i.process.consumed_requests==128 && i.send.bytes==4096);
    CHECK(!i.needs_processing && i.sync.flow.resume_read && i.sync.continuation_pending);
    vireo_tcp_server_ready_client_t ready; vireo_tcp_server_tls_poll_report_t poll_report;
    EXPECT(vireo_tcp_server_tls_poll_ready_once(f.server,100,1,&ready,1,&poll_report,NULL),VIREO_OK);
    CHECK(poll_report.poll.selected_count==1 && ready.events==0);
    i=drive(&f,0,&process_options,&b,VIREO_OK,NULL);
    CHECK(i.receive.bytes==4096 && i.process.consumed_requests==128 && i.send.bytes==4096);
    read_exact(&f,0,got,sizeof(got)); CHECK(memcmp(got,expected,sizeof(got))==0);
    CHECK(f.handler_calls==256); finish(&f); ++groups;
}
static void large_byte_budget(void)
{
    fixture_t f; vireo_tcp_server_options_t root=root_options; root.max_buffer_bytes=262144;
    vireo_tcp_server_tls_options_t options=tls_options;
    options.io=(vireo_tls_io_options_t){32768,32768,98304,128,127,32768,0,32768};
    options.max_tls_resource_bytes=393216;
    start(&f,&root,&options,true); connect_one(&f); make_ssl(&f,0,true); (void)admit(&f,1,VIREO_OK,NULL);
    /* establish's scan count depends only on the unchanged root slot capacity. */
    establish(&f,1); clear_queue(&f); uint8_t bytes[16384];
    for(uint32_t k=0;k<512;++k)make_frame(bytes+32*k,k+1,false);
    client_write(&f,0,bytes,sizeof(bytes)); vireo_tcp_server_tls_drive_budget_t b=drive_budget;
    b.receive.max_bytes=16384; b.send.max_bytes=16384;
    vireo_tcp_server_tls_drive_info_t i={0};
    for(unsigned k=0;k<128;++k) {
        i=drive(&f,0,&process_options,&b,VIREO_OK,NULL);
        if(i.receive.bytes!=0)break;
        struct pollfd p={f.accepted_fds[0],POLLIN,0}; CHECK(poll(&p,1,5)>=0);
    }
    CHECK(i.receive.bytes==16384 && i.receive.stop_reason==VIREO_TLS_IO_STOP_BYTE_BUDGET);
    CHECK(i.receive.native_calls==1 && i.process.consumed_requests==1 && i.sync.continuation_pending);
    finish(&f); ++groups;
}
static void write_full_then_resume(void)
{
    fixture_t f; open_clients(&f,1,true); uint8_t frame[32]; make_frame(frame,91,false); cache_bytes(&f,0,frame,32);
    uint8_t fill[4096]; memset(fill,0xa7,sizeof(fill));
    EXPECT(vireo_tcp_server_client_write_enqueue(f.server,f.clients[0],fill,sizeof(fill),NULL),VIREO_OK);
    clear_queue(&f); vireo_tcp_server_process_options_t options={32,128};
    vireo_tcp_server_tls_drive_budget_t b=drive_budget; b.process.max_response_bytes=128;
    vireo_tcp_server_tls_drive_info_t i=drive(&f,0,&options,&b,VIREO_OK,NULL);
    CHECK(!i.receive_called && i.process.stop_reason==VIREO_TCP_SERVER_PROCESS_WRITE_FULL);
    CHECK(i.process.handler_calls==0 && i.send.bytes==4096 && i.needs_processing && i.sync.continuation_pending);
    clear_queue(&f); i=drive(&f,0,&options,&b,VIREO_OK,NULL);
    CHECK(i.process.consumed_requests==1 && f.handler_calls==1 && i.send.bytes==32);
    uint8_t got[4128]; read_exact(&f,0,got,sizeof(got)); CHECK(memcmp(got,fill,sizeof(fill))==0);
    make_frame(frame,91,true); CHECK(memcmp(got+4096,frame,32)==0); finish(&f); ++groups;
}
static void pure_flow_and_mod_recovery(void)
{
    fixture_t f; open_clients(&f,1,true); uint8_t request[32],got[32]; make_frame(request,44,false);
    cache_bytes(&f,0,request,32); clear_queue(&f);
    EXPECT(vireo_tcp_server_client_set_interests(f.server,f.clients[0],0,NULL),VIREO_OK);
    f.fault=F_MOD; f.fail_on=f.calls[F_MOD]+1; vireo_tcp_server_tls_application_error_t e;
    vireo_tcp_server_tls_drive_info_t i=drive(&f,0,&process_options,&drive_budget,VIREO_RESULT_IO,&e);
    CHECK(i.process.consumed_requests==1 && i.send.bytes==32 && i.sync.interests==0);
    CHECK(e.stage==VIREO_TCP_SERVER_TLS_APPLICATION_SYNC && e.sync_result==VIREO_RESULT_IO);
    CHECK(i.sync.continuation_pending && f.handler_calls==1);
    unsigned reads=f.receive_calls,writes=f.send_calls; f.fault=F_NONE;
    vireo_tcp_server_tls_flow_info_t flow;
    EXPECT(vireo_tcp_server_client_tls_flow_refresh(f.server,f.clients[0],&flow,&e),VIREO_OK);
    CHECK(flow.sync_called && flow.interests==(VIREO_EPOLL_INTEREST_READ|VIREO_EPOLL_INTEREST_PEER_WRITE_CLOSED));
    CHECK(f.handler_calls==1 && f.receive_calls==reads && f.send_calls==writes);
    clear_queue(&f); make_frame(request,44,true); read_exact(&f,0,got,32); CHECK(memcmp(got,request,32)==0);
    EXPECT(vireo_tcp_server_client_write_enqueue(f.server,f.clients[0],request,32,NULL),VIREO_OK);
    EXPECT(vireo_tcp_server_client_tls_flow_refresh(f.server,f.clients[0],&flow,NULL),VIREO_OK);
    CHECK(flow.flow.want_write && (flow.interests&VIREO_EPOLL_INTEREST_WRITE)!=0 && !flow.queue_called);
    CHECK(f.receive_calls==reads && f.send_calls==writes && f.handler_calls==1);
    finish(&f); ++groups;
}
static void cross_wants(void)
{
    for(unsigned mode=0;mode<3;++mode) {
        fixture_t f; open_clients(&f,1,true); uint8_t request[32]; make_frame(request,55,false);
        cache_bytes(&f,0,request,32); clear_queue(&f); f.sequence_size=0;
        f.model_write_retry=mode!=1; f.model_read_retry=mode==1; f.model_send_clears=mode==2;
        vireo_tcp_server_tls_drive_info_t i=drive(&f,0,&process_options,&drive_budget,VIREO_OK,NULL);
        CHECK(i.process.consumed_requests==1 && f.handler_calls==1);
        if(mode==0) {
            CHECK(i.send_called && !i.receive_called && f.send_calls==1 && f.receive_calls==0);
            CHECK(f.sequence_size==2 && f.sequence[0]=='W' && f.sequence[1]=='H');
            CHECK(i.sync.flow.priority_retry==VIREO_TLS_IO_OPERATION_WRITE && i.sync.flow.want_read);
            CHECK((i.sync.interests&VIREO_EPOLL_INTEREST_READ)!=0 && (i.sync.interests&VIREO_EPOLL_INTEREST_WRITE)==0);
        } else if(mode==1) {
            CHECK(i.receive_called && !i.send_called && f.send_calls==0 && f.receive_calls==1);
            CHECK(f.sequence_size==2 && f.sequence[0]=='R' && f.sequence[1]=='H');
            CHECK(i.sync.flow.priority_retry==VIREO_TLS_IO_OPERATION_READ && i.sync.flow.want_write);
        } else {
            CHECK(i.send_called && i.receive_called && f.send_calls==1 && f.receive_calls==1);
            CHECK(f.sequence_size==3 && f.sequence[0]=='W' && f.sequence[1]=='R' && f.sequence[2]=='H');
            CHECK(i.sync.flow.want_write); /* 首send已用过，新的响应等下一网络WRITE。 */
        }
        CHECK(!i.sync.queue_called); finish(&f); ++groups;
    }
}
static vireo_result_t reject_queue(void *ctx,vireo_tcp_server_t const *server,vireo_connection_pool_lease_t lease)
{
    fixture_t *f=ctx; CHECK(server==f->server && same(lease,f->clients[0])); ++f->queue_calls;
    return VIREO_RESULT_INTERNAL;
}
static void primary_and_secondary(void)
{
    fixture_t f; open_clients(&f,1,true); uint8_t frame[32],work[32]; make_frame(frame,77,false);
    cache_bytes(&f,0,frame,32); clear_queue(&f); f.handler_fail=true;
    EXPECT(vireo_tcp_server_client_set_interests(f.server,f.clients[0],0,NULL),VIREO_OK);
    f.fault=F_MOD; f.fail_on=f.calls[F_MOD]+1;
    vireo_tcp_server_tls_drive_info_t i; vireo_tcp_server_tls_application_error_t e;
    EXPECT(vireo_tcp_server_client_tls_drive_with_gate(f.server,f.clients[0],&process_options,&drive_budget,
        work,sizeof(work),handler,&f,&i,&e,reject_queue,&f),VIREO_RESULT_IO);
    CHECK(e.stage==VIREO_TCP_SERVER_TLS_APPLICATION_PROCESS && e.client_error.primary.stage==VIREO_TCP_SERVER_CLIENT_HANDLER);
    CHECK(e.sync_result==VIREO_RESULT_IO && e.sync_stage==VIREO_TCP_SERVER_TLS_APPLICATION_SYNC);
    CHECK(e.queue_result==VIREO_RESULT_INTERNAL && i.sync.queue_called && !i.sync.continuation_pending);
    CHECK(f.queue_calls==1 && i.process.consumed_requests==0 && !i.send_called);
    queue_state(&f,0,false); f.fault=F_NONE; unsigned reads=f.receive_calls;
    vireo_tcp_server_tls_flow_info_t flow;
    EXPECT(vireo_tcp_server_client_tls_flow_refresh(f.server,f.clients[0],&flow,NULL),VIREO_OK);
    CHECK(f.handler_calls==1 && f.receive_calls==reads); finish(&f); ++groups;
}
static void continuation_queue_failure(void)
{
    fixture_t f; open_clients(&f,1,true); uint8_t frames_bytes[64],work[32];
    make_frame(frames_bytes,1,false); make_frame(frames_bytes+32,2,false);
    cache_bytes(&f,0,frames_bytes,64); clear_queue(&f);
    vireo_tcp_server_tls_drive_info_t i; vireo_tcp_server_tls_application_error_t e;
    EXPECT(vireo_tcp_server_client_tls_drive_with_gate(f.server,f.clients[0],&process_options,&drive_budget,
        work,sizeof(work),handler,&f,&i,&e,reject_queue,&f),VIREO_RESULT_INTERNAL);
    CHECK(e.stage==VIREO_TCP_SERVER_TLS_APPLICATION_QUEUE && e.sync_result==VIREO_OK);
    CHECK(e.queue_result==VIREO_RESULT_INTERNAL && i.needs_processing && i.process.consumed_requests==1);
    CHECK(f.queue_calls==1 && i.send.bytes==32); queue_state(&f,0,false);
    EXPECT(vireo_tcp_server_schedule_client(f.server,f.clients[0],NULL),VIREO_OK);
    clear_queue(&f); i=drive(&f,0,&process_options,&drive_budget,VIREO_OK,NULL);
    CHECK(i.process.consumed_requests==1 && f.handler_calls==2); finish(&f); ++groups;
}
static void process_failures(void)
{
    enum fault const points[]={F_ENQUEUE,F_CONSUME};
    for(size_t n=0;n<2;++n) {
        fixture_t f; open_clients(&f,1,true); uint8_t frame[32]; make_frame(frame,99,false);
        cache_bytes(&f,0,frame,32); clear_queue(&f); f.fault=points[n]; f.fail_on=f.calls[points[n]]+1;
        vireo_tcp_server_tls_application_error_t e;
        vireo_tcp_server_tls_drive_info_t i=drive(&f,0,&process_options,&drive_budget,
            n==0?VIREO_RESULT_NO_MEMORY:VIREO_RESULT_INTERNAL,&e);
        CHECK(e.stage==VIREO_TCP_SERVER_TLS_APPLICATION_PROCESS && i.process.handler_calls==1);
        CHECK(i.process.enqueued_responses==(n==0?0:1) && i.process.consumed_requests==0 && !i.send_called);
        CHECK(!i.sync.queue_called && !i.needs_processing); queue_state(&f,0,false);
        vireo_tls_io_info_t io; EXPECT(vireo_tls_connection_io_inspect(borrow(&f,0),&io,NULL),VIREO_OK);
        CHECK(io.read_size==32 && io.write_size==(n==0?0:32)); finish(&f); ++groups;
    }
}
static void inspection_and_flow_failures(void)
{
    enum fault const points[]={F_INSPECT,F_IO_INSPECT,F_CLOSE_INSPECT,F_FLOW};
    for(size_t n=0;n<4;++n) {
        fixture_t f; open_clients(&f,1,true); f.fault=points[n]; f.fail_on=f.calls[points[n]]+1;
        vireo_tcp_server_tls_application_error_t e;
        vireo_tcp_server_tls_drive_info_t i=drive(&f,0,&process_options,&drive_budget,VIREO_RESULT_INTERNAL,&e);
        CHECK(f.handler_calls==0 && f.receive_calls==0 && f.send_calls==0 && !i.sync.queue_called);
        CHECK(e.stage==(n==3?VIREO_TCP_SERVER_TLS_APPLICATION_FLOW:VIREO_TCP_SERVER_TLS_APPLICATION_INSPECT));
        finish(&f); ++groups;
    }
    fixture_t f; open_clients(&f,1,true); uint8_t frame[32]; make_frame(frame,8,false); cache_bytes(&f,0,frame,32);
    clear_queue(&f); f.fail_flow_after_data=true; vireo_tcp_server_tls_application_error_t e;
    vireo_tcp_server_tls_drive_info_t i=drive(&f,0,&process_options,&drive_budget,VIREO_RESULT_INTERNAL,&e);
    CHECK(i.process.consumed_requests==1 && !i.send_called && !i.sync.flow_reported);
    CHECK(e.stage==VIREO_TCP_SERVER_TLS_APPLICATION_FLOW && e.sync_stage==VIREO_TCP_SERVER_TLS_APPLICATION_FLOW);
    CHECK(e.tls_error.system_errno==EIO && e.sync_tls_error.system_errno==EIO && !i.sync.queue_called);
    finish(&f); ++groups;
}
static void signal_report_and_failed_model(void)
{
    fixture_t f; open_clients(&f,1,true); f.reject_native=true;
    vireo_tcp_server_tls_application_error_t e;
    vireo_tcp_server_tls_drive_info_t i=drive(&f,0,&process_options,&drive_budget,VIREO_RESULT_INVALID_ARGUMENT,&e);
    CHECK(i.receive_called && !i.receive_reported && !i.process_called && i.receive.native_calls==0);
    CHECK(e.tls_error.stage==VIREO_TLS_CONNECTION_STAGE_SIGNAL_POLICY && !i.sync.queue_called);
    f.reject_native=false; f.model_io_failed=true; f.model_failure=VIREO_RESULT_PROTOCOL;
    i=drive(&f,0,&process_options,&drive_budget,VIREO_RESULT_PROTOCOL,&e);
    CHECK(i.receive_called && i.receive_reported && i.receive.native_calls==0 && !i.process_called);
    CHECK(i.sync.interests==0 && !i.sync.queue_called);
    unsigned reads=f.receive_calls,writes=f.send_calls; vireo_tcp_server_tls_flow_info_t flow;
    EXPECT(vireo_tcp_server_client_tls_flow_refresh(f.server,f.clients[0],&flow,NULL),VIREO_OK);
    CHECK(flow.interests==0 && f.receive_calls==reads && f.send_calls==writes); finish(&f); ++groups;
}
static void real_eof_and_truncation(void)
{
    for(unsigned mode=0;mode<4;++mode) {
        fixture_t f; open_clients(&f,1,true); uint8_t request[32],response[32],got[32]; make_frame(request,123,false);
        if(mode<2)client_write(&f,0,request,mode==0?32:7);
        if(mode<2) { ERR_clear_error(); int closed=SSL_shutdown(f.ssl[0]); CHECK(closed==0 || closed==1); }
        else if(mode==2) { CHECK(close(f.peers[0])==0); f.peers[0]=-1; }
        else { client_write(&f,0,request,32); CHECK(shutdown(f.peers[0],SHUT_WR)==0); }
        vireo_tcp_server_tls_drive_info_t i={0}; vireo_tcp_server_tls_application_error_t e;
        bool reached_terminal=false;
        for(unsigned k=0;k<128;++k) {
            uint8_t work[32]; errno=ECHILD;
            vireo_result_t r=vireo_tcp_server_client_tls_drive(f.server,f.clients[0],&process_options,&drive_budget,
                work,sizeof(work),handler,&f,&i,&e); CHECK(errno==ECHILD);
            if(mode==0) { CHECK(r==VIREO_OK); if(i.receive.stop_reason==VIREO_TLS_IO_STOP_PEER_EOF)reached_terminal=true; }
            else { CHECK(r==VIREO_OK || r==VIREO_RESULT_PROTOCOL || (mode==2 && r==VIREO_RESULT_IO));
                if(r!=VIREO_OK)reached_terminal=true; }
            if(reached_terminal)break;
            struct pollfd p={f.accepted_fds[0],POLLIN,0}; CHECK(poll(&p,1,5)>=0);
        }
        CHECK(reached_terminal && !i.sync.queue_called);
        if(mode==0) {
            CHECK(f.handler_calls==1); make_frame(response,123,true); read_exact(&f,0,got,32); CHECK(memcmp(got,response,32)==0);
            vireo_tls_close_info_t closed; EXPECT(vireo_tls_connection_close_inspect(borrow(&f,0),&closed,NULL),VIREO_OK);
            CHECK(closed.state==VIREO_TLS_CLOSE_NONE);
        } else if(mode==1) { CHECK(f.handler_calls==0 && e.stage==VIREO_TCP_SERVER_TLS_APPLICATION_PROCESS); }
        else {
            if(mode==3) { CHECK(i.receive.bytes==32 && i.receive.native_calls>=2); }
            CHECK(f.handler_calls==0 && i.sync.interests==0); vireo_tls_connection_error_t original=e.tls_error;
            vireo_result_t const failure=e.tls_error.system_errno!=0?VIREO_RESULT_IO:VIREO_RESULT_PROTOCOL;
            i=drive(&f,0,&process_options,&drive_budget,failure,&e);
            CHECK(i.receive_reported && i.receive.native_calls==0 && !i.process_called);
            CHECK(e.tls_error.stage==original.stage && e.tls_error.openssl_error_code==original.openssl_error_code);
        }
        finish(&f); ++groups;
    }
}
static void reentry_and_multi_client(void)
{
    fixture_t f; open_clients(&f,2,true); f.reenter=true; uint8_t request[32],expected[32],got[32];
    for(size_t k=0;k<2;++k) { make_frame(request,(uint32_t)(200+k),false); cache_bytes(&f,k,request,32); }
    clear_queue(&f);
    for(size_t k=0;k<2;++k) {
        vireo_tcp_server_tls_drive_info_t i=drive(&f,k,&process_options,&drive_budget,VIREO_OK,NULL);
        CHECK(i.process.consumed_requests==1); make_frame(expected,(uint32_t)(200+k),true);
        read_exact(&f,k,got,32); CHECK(memcmp(got,expected,32)==0);
    }
    CHECK(f.handler_calls==2); finish(&f); ++groups;
}
/** 本地TCP真实WRITE-WANT；精确核对enqueue追加后稳定重试没有重复或漏字节。 */
static void real_write_backpressure(void)
{
    fixture_t f; vireo_tcp_server_options_t root=root_options; root.max_buffer_bytes=1048576;
    vireo_tcp_server_tls_options_t options=tls_options;
    options.io=(vireo_tls_io_options_t){4096,131072,167936,128,127,4096,0,65536};
    options.max_tls_resource_bytes=671744;
    start(&f,&root,&options,true); connect_one(&f); make_ssl(&f,0,true); (void)admit(&f,1,VIREO_OK,NULL);
    establish(&f,1); clear_queue(&f);
    int small=1024,enabled=1;
    CHECK(setsockopt(f.accepted_fds[0],SOL_SOCKET,SO_SNDBUF,&small,(socklen_t)sizeof(small))==0);
    CHECK(setsockopt(f.accepted_fds[0],IPPROTO_TCP,TCP_NODELAY,&enabled,(socklen_t)sizeof(enabled))==0);
    CHECK(setsockopt(f.peers[0],IPPROTO_TCP,TCP_NODELAY,&enabled,(socklen_t)sizeof(enabled))==0);
    uint8_t bytes[65568],got[65568];
    for(size_t k=0;k<sizeof(bytes);++k)bytes[k]=(uint8_t)(k%251);
    EXPECT(vireo_tcp_server_client_write_enqueue(f.server,f.clients[0],bytes,65536,NULL),VIREO_OK);
    vireo_tcp_server_tls_drive_budget_t b=drive_budget; b.send.max_bytes=16384;
    size_t sent=0,wants=0;
    for(unsigned k=0;k<256;++k) {
        vireo_tcp_server_tls_drive_info_t i=drive(&f,0,&process_options,&b,VIREO_OK,NULL);
        sent+=i.send.bytes;
        if(i.send_reported && i.send.stop_reason==VIREO_TLS_IO_STOP_WOULD_BLOCK) {
            CHECK(i.send.wait==VIREO_TLS_IO_WAIT_WRITE && i.sync.flow.priority_retry==VIREO_TLS_IO_OPERATION_WRITE);
            CHECK((i.sync.interests&VIREO_EPOLL_INTEREST_WRITE)!=0 && !i.sync.queue_called);
            ++wants; break;
        }
    }
    CHECK(wants!=0 && sent<65536);
    EXPECT(vireo_tcp_server_client_write_enqueue(f.server,f.clients[0],bytes+65536,32,NULL),VIREO_OK);
    size_t received=0;
    for(unsigned k=0;k<4096 && (received<sizeof(got) || sent<sizeof(got));++k) {
        if(received<sizeof(got)) {
            size_t n=0; ERR_clear_error(); int r=SSL_read_ex(f.ssl[0],got+received,sizeof(got)-received,&n);
            int why=r==1?SSL_ERROR_NONE:SSL_get_error(f.ssl[0],r);
            if(r==1) { CHECK(n>0); received+=n; }
            else CHECK(why==SSL_ERROR_WANT_READ || why==SSL_ERROR_WANT_WRITE);
        }
        if(sent<sizeof(got)) {
            vireo_tcp_server_tls_drive_info_t i=drive(&f,0,&process_options,&b,VIREO_OK,NULL);
            sent+=i.send.bytes;
            if(i.send_reported && i.send.stop_reason==VIREO_TLS_IO_STOP_WOULD_BLOCK)++wants;
        }
        if(received<sizeof(got)) { struct pollfd p={f.peers[0],POLLIN,0}; CHECK(poll(&p,1,2)>=0); }
    }
    CHECK(sent==sizeof(got) && received==sizeof(got) && memcmp(got,bytes,sizeof(got))==0);
    CHECK(f.handler_calls==0);
    printf("real server write backpressure: %zu WANT_WRITE observations, %zu exact bytes after stable append\n",wants,received);
    finish(&f); ++groups;
}
static void actual_signal_rejection(void)
{
    fixture_t f; open_clients(&f,1,true);
    struct sigaction action={0}; action.sa_handler=SIG_DFL; CHECK(sigemptyset(&action.sa_mask)==0);
    CHECK(sigaction(SIGPIPE,&action,NULL)==0);
    vireo_tcp_server_tls_application_error_t e;
    vireo_tcp_server_tls_drive_info_t i=drive(&f,0,&process_options,&drive_budget,VIREO_RESULT_INVALID_ARGUMENT,&e);
    CHECK(i.receive_called && !i.receive_reported && i.receive.native_calls==0 && !i.process_called);
    CHECK(e.tls_error.stage==VIREO_TLS_CONNECTION_STAGE_SIGNAL_POLICY);
    finish(&f);
}
int main(int argc,char **argv)
{
    CHECK(signal(SIGPIPE,SIG_IGN)!=SIG_ERR);
    if(argc==2) { CHECK(strcmp(argv[1],"--signal")==0); actual_signal_rejection(); return 0; }
    size_t before=fd_count();
    gates_and_budgets(); phase_gates(); cached_three_and_half(); processing_byte_budgets();
    native_call_budget(); library_pending(); large_byte_budget(); write_full_then_resume();
    pure_flow_and_mod_recovery(); cross_wants(); primary_and_secondary(); continuation_queue_failure();
    process_failures(); inspection_and_flow_failures(); signal_report_and_failed_model();
    real_eof_and_truncation(); reentry_and_multi_client(); real_write_backpressure();
    pid_t child=fork(); CHECK(child>=0);
    if(child==0) { execl("/proc/self/exe","vireo_tcp_server_tls_application_test","--signal",(char *)NULL); _exit(127); }
    int status=0; CHECK(waitpid(child,&status,0)==child && WIFEXITED(status) && WEXITSTATUS(status)==0); ++groups;
    size_t after=fd_count(); CHECK(before==after);
    printf("test_tcp_server_tls_application: %u groups passed; fd %zu -> %zu; real trusted TCP/TLS1.3 exact replies, cached/pending continuation, EOF and separate own failure models\n",groups,before,after);
    return 0;
}
