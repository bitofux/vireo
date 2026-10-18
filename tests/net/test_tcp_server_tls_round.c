/*
- PROJECT : VIREO
- FILE    : test_tcp_server_tls_round.c
- AUTHOR  : bitofux
- DATE    : 2026-10-18
- BRIEF   : 此模块负责：
- -- 本server TLS三阶段客户轮/公平前缀/故障恢复及真实协议闭环验证
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
    F_PREPARE,F_ARM,F_ADOPT,F_LOOKUP,F_ATTACH,F_MOD,F_DETACH,F_WAIT,F_INSPECT,F_DEADLINE,F_IO_INSPECT,F_FLOW,F_RECEIVE,F_SEND,F_CLOSE_INSPECT,F_CONSUME,F_ENQUEUE,F_REQUEST,F_CLOSE_STEP,F_MAX };
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
    unsigned queue_calls;
    bool model_close, reenter_close, fail_inspect_after_step;
    vireo_tls_close_info_t close_model;
    unsigned close_requests, close_steps, close_native;
    vireo_tls_handshake_wait_t model_step_wait; /**< 非NONE时只为本server关注分支模型，不调用SSL。 */
    unsigned handler_calls, handler_fail_at;
    bool reenter_handler;
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
/** 应用桥接不注入TLS内核模型；本测试仅关闭组合层有故障门。 */
static vireo_result_t application_inspect(void *ctx,vireo_tls_connection_t const *t,vireo_tls_io_info_t *i,
    vireo_tls_connection_error_t *e)
{ (void)ctx;return vireo_tls_connection_io_inspect(t,i,e); }
static vireo_result_t application_flow(void *ctx,vireo_tls_connection_t *t,vireo_tls_io_flow_t *i,
    vireo_tls_connection_error_t *e)
{ (void)ctx;return vireo_tls_connection_flow_refresh(t,i,e); }
static vireo_result_t application_receive(void *ctx,vireo_tls_connection_t *t,vireo_tls_io_budget_t const *b,
    vireo_tls_io_progress_t *i,vireo_tls_connection_error_t *e)
{ (void)ctx;return vireo_tls_connection_receive(t,b,i,e); }
static vireo_result_t application_send(void *ctx,vireo_tls_connection_t *t,vireo_tls_io_budget_t const *b,
    vireo_tls_io_progress_t *i,vireo_tls_connection_error_t *e)
{ (void)ctx;return vireo_tls_connection_send(t,b,i,e); }
static vireo_result_t application_close_inspect(void *ctx,vireo_tls_connection_t const *t,vireo_tls_close_info_t *i,
    vireo_tls_connection_error_t *e)
{
    fixture_t *f=ctx;
    if(hit(f,F_CLOSE_INSPECT) || (f->fail_inspect_after_step && f->close_steps>0)) {
        *e=(vireo_tls_connection_error_t){.stage=VIREO_TLS_CONNECTION_STAGE_INSPECT,.system_errno=EIO};
        return VIREO_RESULT_INTERNAL;
    }
    vireo_result_t r=vireo_tls_connection_close_inspect(t,i,e);
    if(r==VIREO_OK && f->model_close)*i=f->close_model;
    return r;
}
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
{
    fixture_t *f=ctx; ++f->close_requests;
    if(hit(f,F_REQUEST))return VIREO_RESULT_IO;
    if(f->reenter_close) {
        vireo_tcp_server_tls_close_request_info_t ri;
        vireo_tcp_server_tls_close_step_info_t si;
        vireo_tcp_server_tls_close_flow_info_t fi;
        EXPECT(vireo_tcp_server_client_tls_close_request(f->server,f->clients[0],1,&ri,NULL),VIREO_RESULT_BUSY);
        EXPECT(vireo_tcp_server_client_tls_close_step(f->server,f->clients[0],4096,&si,NULL),VIREO_RESULT_BUSY);
        EXPECT(vireo_tcp_server_client_tls_close_flow_refresh(f->server,f->clients[0],&fi,NULL),VIREO_RESULT_BUSY);
        vireo_connection_pool_lease_t l=f->clients[0];
        EXPECT(vireo_tcp_server_release_client(f->server,&l,NULL),VIREO_RESULT_BUSY);
    }
    return vireo_tls_connection_close_request(tls, now, due, error);
}
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
{
    fixture_t *f=ctx; ++f->close_steps;
    if(hit(f,F_CLOSE_STEP)) {
        *error=(vireo_tls_connection_error_t){.stage=VIREO_TLS_CONNECTION_STAGE_CLOSE,.system_errno=EPIPE};
        return VIREO_RESULT_IO; /* 原生前拒绝模型，保持progress哨兵。 */
    }
    vireo_result_t r=vireo_tls_connection_close_step_at(tls, now, bytes, info, error);
    if(info->stop_reason!=(vireo_tls_close_stop_t)-1 && info->native_called)++f->close_native;
    return r;
}

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


/** 每例独立可信TCP/TLS1.3夹具，所有owner沿公开server清理。 */
static void open_clients(fixture_t *f,size_t count)
{
    start(f,&root_options,&tls_options,true);
    for(size_t k=0;k<count;++k)connect_one(f);
    CHECK(admit(f,count,VIREO_OK,NULL).admission.admitted_count==count);
    for(size_t k=0;k<count;++k)make_ssl(f,k,true);
    establish(f,count);
}

static vireo_tcp_server_tls_round_options_t const round_options = {
    0,{32,32},{{4096,8},{1,32,32},{4096,8}},{4},4096
};
static vireo_result_t handler(vireo_connection_frame_view_t const *v,uint8_t *body,size_t n,
    vireo_tcp_server_reply_t *reply,void *ctx)
{
    fixture_t *f=ctx; (void)body; (void)n; CHECK(v->wire_size==32); reply->body_size=0;
    ++f->handler_calls;
    if(f->reenter_handler) {
        uint8_t work[32];vireo_tcp_server_tls_turn_result_t turns[1];
        vireo_tcp_server_tls_round_info_t info;vireo_tcp_server_tls_round_error_t error;
        EXPECT(vireo_tcp_server_tls_run_once(f->server,&round_options,work,sizeof(work),handler,f,
            turns,1,&info,&error),VIREO_RESULT_BUSY);
        CHECK(!info.wait_called && info.turn_count==0);
        vireo_tcp_server_tls_poll_report_t p;vireo_tcp_server_ready_client_t ready[1];
        EXPECT(vireo_tcp_server_tls_poll_ready_once(f->server,0,1,ready,1,&p,NULL),VIREO_RESULT_BUSY);
        vireo_tcp_server_tls_drive_info_t di;
        EXPECT(vireo_tcp_server_client_tls_drive(f->server,f->clients[0],&round_options.process,
            &round_options.drive,work,sizeof(work),handler,f,&di,NULL),VIREO_RESULT_BUSY);
        vireo_tcp_server_tls_close_request_info_t ci;
        EXPECT(vireo_tcp_server_client_tls_close_request(f->server,f->clients[0],1,&ci,NULL),VIREO_RESULT_BUSY);
        vireo_connection_pool_lease_t lease=f->clients[0];
        EXPECT(vireo_tcp_server_release_client(f->server,&lease,NULL),VIREO_RESULT_BUSY);
        EXPECT(vireo_tcp_server_schedule_client(f->server,lease,NULL),VIREO_RESULT_BUSY);
        EXPECT(vireo_tcp_server_destroy(&f->server,NULL),VIREO_RESULT_BUSY);
        vireo_tcp_server_info_t si;EXPECT(vireo_tcp_server_inspect(f->server,&si),VIREO_OK);
        CHECK(si.scheduling_active && si.driving_active && si.processing_active);
        vireo_tcp_server_t *other=NULL;
        EXPECT(vireo_tcp_server_create(&root_options,&other,NULL),VIREO_OK);
        EXPECT(vireo_tcp_server_destroy(&other,NULL),VIREO_OK);
    }
    return f->handler_fail_at==f->handler_calls?VIREO_RESULT_IO:VIREO_OK;
}
static void make_frame(uint8_t *out,uint32_t seq,bool response)
{
    vireo_protocol_header_t h={.command=VIREO_COMMAND_PING,.sequence=seq};
    if(response)h.flags=VIREO_PROTOCOL_FLAG_RESPONSE;
    EXPECT(vireo_protocol_header_encode(&h,out,32),VIREO_OK);
    EXPECT(vireo_protocol_frame_crc32c_calculate(out,32,NULL,0,&h.crc32c),VIREO_OK);
    EXPECT(vireo_protocol_header_encode(&h,out,32),VIREO_OK);
}
static vireo_tcp_server_tls_round_info_t run(fixture_t *f,size_t limit,
    vireo_tcp_server_tls_turn_result_t *turns,size_t capacity,vireo_result_t expected,
    vireo_tcp_server_tls_round_error_t *error)
{
    uint8_t work[32];vireo_tcp_server_tls_round_options_t o=round_options;o.round.max_clients=limit;
    vireo_tcp_server_tls_round_info_t i;
    EXPECT(vireo_tcp_server_tls_run_once(f->server,&o,work,sizeof(work),handler,f,turns,capacity,&i,error),expected);
    CHECK(i.turn_count==i.succeeded_count+i.failed_count && i.failed_count<=1);
    CHECK(i.turn_count<=limit && i.turn_count<=capacity);return i;
}
static void silence(fixture_t *f)
{
    for(size_t k=0;k<f->attached;++k)EXPECT(vireo_connection_set_interests(f->objects[k],0,NULL),VIREO_OK);
    vireo_tcp_server_ready_client_t ready[4];vireo_tcp_server_tls_poll_report_t i;
    EXPECT(vireo_tcp_server_tls_poll_ready_once(f->server,0,4,ready,4,&i,NULL),VIREO_OK);
    CHECK(i.poll.remaining_count==0);
}
static void schedule(fixture_t *f,size_t k)
{ EXPECT(vireo_tcp_server_schedule_client(f->server,f->clients[k],NULL),VIREO_OK); }
static void request_close_client(fixture_t *f,size_t k,uint64_t duration)
{
    vireo_tcp_server_tls_close_request_info_t i;
    EXPECT(vireo_tcp_server_client_tls_close_request(f->server,f->clients[k],duration,&i,NULL),VIREO_OK);
    CHECK(i.requested);
}
static void inputs(void)
{
    fixture_t f;start(&f,&root_options,&tls_options,true);
    uint8_t work[32],original[32];memset(work,0xa5,sizeof(work));memcpy(original,work,sizeof(work));
    vireo_tcp_server_tls_turn_result_t turns[2],backup[2];memset(turns,0xa5,sizeof(turns));memcpy(backup,turns,sizeof(turns));
    vireo_tcp_server_tls_round_info_t i;vireo_tcp_server_tls_round_error_t e;
    EXPECT(vireo_tcp_server_tls_run_once(NULL,&round_options,work,32,handler,&f,turns,2,&i,&e),VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(!i.wait_called && i.turn_count==0 && e.stage==VIREO_TCP_SERVER_TLS_ROUND_NONE);++groups;
    for(unsigned k=0;k<9;++k) {
        vireo_tcp_server_tls_round_options_t o=round_options;
        switch(k) {
            case 0:o.timeout_ms=-1;break;case 1:o.round.max_clients=0;break;
            case 2:o.process.max_request_frame_bytes=4097;break;case 3:o.drive.receive.max_bytes=4095;break;
            case 4:o.drive.send.max_native_calls=0;break;case 5:o.close_max_bytes=4095;break;
            case 6:o.drive.process.max_messages=0;break;case 7:o.process.max_response_frame_bytes=33;break;
            default:o.round.max_clients=65536;break;
        }
        EXPECT(vireo_tcp_server_tls_run_once(f.server,&o,work,32,handler,&f,turns,2,&i,&e),
            k==0?VIREO_RESULT_INVALID_ARGUMENT:VIREO_RESULT_RANGE);
        CHECK(!i.wait_called && i.turn_count==0 && memcmp(turns,backup,sizeof(turns))==0 && memcmp(work,original,32)==0);
        ++groups;
    }
    EXPECT(vireo_tcp_server_request_stop(f.server,NULL),VIREO_OK);
    EXPECT(vireo_tcp_server_tls_run_once(f.server,&round_options,work,32,handler,&f,turns,2,&i,&e),VIREO_OK);
    CHECK(i.stopped && !i.wait_called && i.turn_count==0 && memcmp(turns,backup,sizeof(turns))==0);
    finish(&f);++groups;
    vireo_tcp_server_t *raw=NULL;EXPECT(vireo_tcp_server_create(&root_options,&raw,NULL),VIREO_OK);
    EXPECT(vireo_tcp_server_tls_run_once(raw,&round_options,work,32,handler,&f,turns,2,&i,&e),VIREO_RESULT_BUSY);
    EXPECT(vireo_tcp_server_destroy(&raw,NULL),VIREO_OK);++groups;
    vireo_tls_context_t *context=make_context();
    EXPECT(vireo_tcp_server_create_tls(&root_options,&tls_options,&context,&raw,NULL),VIREO_OK);
    EXPECT(vireo_tcp_server_tls_run_once(raw,&round_options,work,32,handler,&f,turns,2,&i,&e),VIREO_RESULT_NOT_FOUND);
    CHECK(!i.wait_called && i.turn_count==0);
    EXPECT(vireo_tcp_server_destroy(&raw,NULL),VIREO_OK);++groups;
}
/** 静默真实TLS客户，借模型调度注入控制首错时点，不伪造native进度。 */
static void wait_faults(void)
{
    enum fault points[]={F_INSPECT,F_NOW,F_WAIT,F_NOW,F_LOOKUP,F_INSPECT};
    for(size_t k=0;k<6;++k) {
        fixture_t f;open_clients(&f,1);silence(&f);schedule(&f,0);f.probe=true;
        f.fault=points[k];f.fail_on=f.calls[points[k]]+(k==3?2:k>=4?3:1);
        vireo_tcp_server_tls_turn_result_t t[2],copy[2];memset(t,0xa5,sizeof(t));memcpy(copy,t,sizeof(t));
        vireo_tcp_server_tls_round_error_t e;
        vireo_tcp_server_tls_round_info_t i=run(&f,2,t,2,k==1||k==2||k==3?VIREO_RESULT_IO:VIREO_RESULT_INTERNAL,&e);
        if(k<4) {
            CHECK(i.turn_count==0 && i.remaining_count==1 && memcmp(t,copy,sizeof(t))==0);
            CHECK(e.stage==VIREO_TCP_SERVER_TLS_ROUND_WAIT);
            CHECK(e.wait_error.stage==(k==0?VIREO_TCP_SERVER_TLS_SCAN_BEFORE:k==2?VIREO_TCP_SERVER_TLS_WAIT:VIREO_TCP_SERVER_TLS_CLOCK));
        } else {
            CHECK(i.turn_count==1 && i.failed_count==1 && i.remaining_count==0);
            CHECK(t[0].path==VIREO_TCP_SERVER_TLS_TURN_NONE && same(t[0].client,f.clients[0]));
            CHECK(e.stage==(k==4?VIREO_TCP_SERVER_TLS_ROUND_LOOKUP:VIREO_TCP_SERVER_TLS_ROUND_INSPECT));
        }
        CHECK(f.handler_calls==0);finish(&f);++groups;
    }
    fixture_t f;open_clients(&f,1);silence(&f);schedule(&f,0);f.stop_in_wait=true;
    vireo_tcp_server_tls_turn_result_t t[1];
    vireo_tcp_server_tls_round_info_t i=run(&f,1,t,1,VIREO_OK,NULL);
    CHECK(i.stopped && i.wait_called && i.turn_count==0 && i.remaining_count==1);finish(&f);++groups;
}
static void mixed_round(void)
{
    fixture_t f;open_clients(&f,2);request_close_client(&f,1,UINT64_C(5000000000));
    connect_one(&f);vireo_tcp_server_admit_budget_t b={1,2};vireo_tcp_server_tls_admit_info_t a;
    EXPECT(vireo_tcp_server_tls_admit_batch(f.server,&b,&f.clients[2],1,&a,NULL),VIREO_OK);
    CHECK(a.admission.admitted_count==1);silence(&f);
    schedule(&f,2);schedule(&f,0);schedule(&f,1);schedule(&f,2);
    vireo_tcp_server_tls_turn_result_t t[4];memset(t,0xa5,sizeof(t));
    vireo_tcp_server_tls_round_info_t i=run(&f,3,t,2,VIREO_OK,NULL);
    CHECK(i.queued_after_wait==3 && i.turn_count==2 && i.scanned_slots==8);
    CHECK(same(t[0].client,f.clients[2]) && t[0].path==VIREO_TCP_SERVER_TLS_TURN_HANDSHAKE && t[0].events==0);
    CHECK(same(t[1].client,f.clients[0]) && t[1].path==VIREO_TCP_SERVER_TLS_TURN_APPLICATION);
    CHECK(!t[0].application.process_called && !t[0].close.step_called && !t[1].handshake.step_called);
    i=run(&f,1,t,4,VIREO_OK,NULL);
    CHECK(i.turn_count==1 && same(t[0].client,f.clients[1]) && t[0].path==VIREO_TCP_SERVER_TLS_TURN_CLOSE);
    CHECK(!t[0].application.process_called && f.handler_calls==0);finish(&f);++groups;
}
static void due_round(bool partial)
{
    fixture_t f;open_clients(&f,2);silence(&f);
    f.fake_clock=true;f.model_wait=true;f.now=UINT64_C(100000000000);
    request_close_client(&f,0,20);request_close_client(&f,1,30);silence(&f);f.advance_ns=30;
    if(partial) {f.fault=F_CLOSE_INSPECT;f.fail_on=f.calls[F_CLOSE_INSPECT]+4;}
    vireo_tcp_server_tls_turn_result_t t[2];vireo_tcp_server_tls_round_error_t e;
    vireo_tcp_server_tls_round_options_t o=round_options;o.timeout_ms=100;
    uint8_t work[32];vireo_tcp_server_tls_round_info_t i;
    EXPECT(vireo_tcp_server_tls_run_once(f.server,&o,work,32,handler,&f,t,2,&i,&e),
        partial?VIREO_RESULT_INTERNAL:VIREO_RESULT_TIMEOUT);
    CHECK(i.has_deadline && i.nearest_deadline_ns==UINT64_C(100000000020) && f.waited_ms==1);
    if(partial) CHECK(i.turn_count==0 && i.expired_clients==1 && i.remaining_count==1 &&
        e.wait_error.stage==VIREO_TCP_SERVER_TLS_SCAN_AFTER);
    else CHECK(i.turn_count==1 && i.failed_count==1 && i.expired_clients==2 && i.remaining_count==1 &&
        t[0].path==VIREO_TCP_SERVER_TLS_TURN_CLOSE && !t[0].close.progress.native_called);
    CHECK(f.close_native==0);finish(&f);++groups;
}
static void cache_request(fixture_t *f,size_t k,uint32_t sequence)
{
    uint8_t wire[32];make_frame(wire,sequence,false);ERR_clear_error();CHECK(SSL_write(f->ssl[k],wire,32)==32);
    vireo_tls_io_budget_t b={4096,1};vireo_tls_io_progress_t p;
    for(size_t j=0;j<256;++j) {
        EXPECT(vireo_tls_connection_receive(borrow(f,k),&b,&p,NULL),VIREO_OK);
        if(p.bytes==32)return;
        struct pollfd fd={f->accepted_fds[k],POLLIN,0};CHECK(poll(&fd,1,1)>=0);
    }
    CHECK(false);
}
static void prefix_failure(void)
{
    fixture_t f;open_clients(&f,3);
    for(size_t k=0;k<3;++k)cache_request(&f,k,(uint32_t)k+1);
    silence(&f);for(size_t k=0;k<3;++k)schedule(&f,k);
    f.handler_fail_at=2;f.reenter_handler=true;
    vireo_tcp_server_tls_turn_result_t t[4],copy[4];memset(t,0xa5,sizeof(t));memcpy(copy,t,sizeof(t));
    vireo_tcp_server_tls_round_error_t e;
    vireo_tcp_server_tls_round_info_t i=run(&f,3,t,4,VIREO_RESULT_IO,&e);
    CHECK(i.turn_count==2 && i.succeeded_count==1 && i.failed_count==1 && f.handler_calls==2);
    CHECK(t[0].result==VIREO_OK && t[1].result==VIREO_RESULT_IO && same(t[1].client,f.clients[1]));
    CHECK(e.stage==VIREO_TCP_SERVER_TLS_ROUND_APPLICATION && same(e.client,t[1].client));
    CHECK(memcmp(&t[2],&copy[2],2*sizeof(t[2]))==0);
    vireo_tcp_server_ready_client_t ready[4];vireo_tcp_server_tls_poll_report_t p;
    EXPECT(vireo_tcp_server_tls_poll_ready_once(f.server,0,4,ready,4,&p,NULL),VIREO_OK);
    CHECK(p.poll.selected_count>=1 && same(ready[0].client,f.clients[2]));
    finish(&f);++groups;
}
static vireo_result_t reject_handoff(void *ctx,vireo_tcp_server_t const *server,vireo_connection_pool_lease_t lease)
{ fixture_t *f=ctx;CHECK(server==f->server && same(lease,f->clients[0]));++f->queue_calls;return VIREO_RESULT_NO_MEMORY; }
static void mod_recovery(void)
{
    fixture_t f;open_clients(&f,1);cache_request(&f,0,99);silence(&f);schedule(&f,0);
    f.fault=F_MOD;f.fail_on=f.calls[F_MOD]+1;
    vireo_tcp_server_tls_turn_result_t t[1];vireo_tcp_server_tls_round_error_t e;
    vireo_tcp_server_tls_round_info_t i=run(&f,1,t,1,VIREO_RESULT_IO,&e);
    CHECK(i.turn_count==1 && f.handler_calls==1 && t[0].application.process.handler_calls==1);
    CHECK(t[0].application.process.consumed_requests==1 && t[0].application.sync.sync_called &&
        t[0].application.sync.continuation_pending && t[0].application.sync.interests==0);
    CHECK(e.application_error.sync_result==VIREO_RESULT_IO &&
        e.application_error.sync_loop_error.loop_error.epoll_error.system_errno==EIO);
    f.fault=F_NONE;vireo_tcp_server_tls_flow_info_t flow;
    EXPECT(vireo_tcp_server_client_tls_flow_refresh(f.server,f.clients[0],&flow,NULL),VIREO_OK);
    CHECK(flow.interests!=0 && f.handler_calls==1);i=run(&f,1,t,1,VIREO_OK,NULL);
    CHECK(f.handler_calls==1);finish(&f);++groups;
    open_clients(&f,1);f.fake_clock=true;f.now=UINT64_C(100000000000);
    request_close_client(&f,0,1);silence(&f);
    EXPECT(vireo_connection_set_interests(f.objects[0],VIREO_EPOLL_INTEREST_READ,NULL),VIREO_OK);
    schedule(&f,0);++f.now;f.fault=F_MOD;f.fail_on=f.calls[F_MOD]+1;
    i=run(&f,1,t,1,VIREO_RESULT_TIMEOUT,&e);
    CHECK(i.turn_count==1 && e.close_error.sync_result==VIREO_RESULT_IO &&
        t[0].close.sync.continuation_pending && !t[0].close.progress.native_called);
    CHECK(t[0].close.sync.interests==VIREO_EPOLL_INTEREST_READ && f.handler_calls==0);
    f.fault=F_NONE;vireo_tcp_server_tls_close_flow_info_t close_flow;
    EXPECT(vireo_tcp_server_client_tls_close_flow_refresh(f.server,f.clients[0],&close_flow,NULL),VIREO_OK);
    CHECK(close_flow.interests==0);unsigned steps=f.close_native;
    i=run(&f,1,t,1,VIREO_RESULT_TIMEOUT,NULL);
    CHECK(i.turn_count==1 && !t[0].close.sampled && f.close_native==steps && f.handler_calls==0);
    finish(&f);++groups;
}
static void failed_handshake(void)
{
    fixture_t f;start(&f,&root_options,&tls_options,true);f.fake_clock=true;f.model_wait=true;
    connect_one(&f);CHECK(admit(&f,1,VIREO_OK,NULL).admission.admitted_count==1);
    f.advance_ns=tls_options.handshake_timeout_ns;
    vireo_tcp_server_tls_turn_result_t t[1];vireo_tcp_server_tls_round_error_t e;
    vireo_tcp_server_tls_round_info_t i=run(&f,1,t,1,VIREO_RESULT_TIMEOUT,&e);
    CHECK(i.expired_clients==1 && t[0].path==VIREO_TCP_SERVER_TLS_TURN_HANDSHAKE && !t[0].handshake.handshake.native_called);
    f.advance_ns=0;schedule(&f,0);i=run(&f,1,t,1,VIREO_RESULT_TIMEOUT,&e);
    CHECK(!i.has_deadline && i.turn_count==1 && !t[0].handshake.handshake.native_called && f.native_steps==0);
    finish(&f);++groups;
}
/** 真实8192尾部填满4096读FIFO；新轮必须返回消费责任而非偷偷运行业务。 */
static void need_consume(void)
{
    fixture_t f;open_clients(&f,1);uint8_t tail[8192];
    for(size_t k=0;k<sizeof(tail);++k)tail[k]=(uint8_t)(k%251);
    ERR_clear_error();CHECK(SSL_write(f.ssl[0],tail,(int)sizeof(tail))==(int)sizeof(tail));
    request_close_client(&f,0,UINT64_C(5000000000));
    ERR_clear_error();CHECK(SSL_shutdown(f.ssl[0])==0);
    vireo_tcp_server_tls_turn_result_t t[1];bool needed=false,complete=false;size_t consumed=0;
    for(size_t k=0;k<1024 && !complete;++k) {
        vireo_tcp_server_tls_round_info_t i=run(&f,1,t,1,VIREO_OK,NULL);
        if(!i.turn_count)continue;
        CHECK(t[0].path==VIREO_TCP_SERVER_TLS_TURN_CLOSE && f.handler_calls==0);
        if(t[0].close.sync.close.needs_consume) {
            CHECK(!t[0].close.sync.queue_called && t[0].close.sync.interests==0);
            needed=true;
        }
        complete=t[0].close.progress.info.state==VIREO_TLS_CLOSE_COMPLETE;
        if(needed || complete) {
            uint8_t const *bytes=NULL;size_t count=0;
            EXPECT(vireo_tls_connection_read_peek(borrow(&f,0),&bytes,&count,NULL),VIREO_OK);
            CHECK(consumed+count<=sizeof(tail) && (count==0 || memcmp(bytes,tail+consumed,count)==0));
            consumed+=count;
            EXPECT(vireo_tls_connection_read_consume(borrow(&f,0),count,NULL),VIREO_OK);
            vireo_tcp_server_tls_close_flow_info_t flow;
            EXPECT(vireo_tcp_server_client_tls_close_flow_refresh(f.server,f.clients[0],&flow,NULL),VIREO_OK);
        }
    }
    CHECK(needed && complete && consumed==sizeof(tail) && f.handler_calls==0);
    CHECK(fcntl(f.accepted_fds[0],F_GETFD)>=0);finish(&f);++groups;
}
/** 真实握手始终通过新轮；交接故障由本server门单独标记。 */
static void real_round(bool handoff_fault)
{
    fixture_t f;start(&f,&root_options,&tls_options,true);connect_one(&f);
    CHECK(admit(&f,1,VIREO_OK,NULL).admission.admitted_count==1);make_ssl(&f,0,true);
    bool peer_ready=false,server_ready=false;
    uint8_t work[32];vireo_tcp_server_tls_turn_result_t t[1];vireo_tcp_server_tls_round_info_t i;
    vireo_tcp_server_tls_round_error_t e;
    vireo_tcp_server_tls_round_options_t o=round_options;o.timeout_ms=2;
    for(size_t k=0;k<1024 && (!peer_ready||!server_ready);++k) {
        if(!peer_ready)peer_ready=client_step(f.ssl[0],false);
        errno=ECHILD;
        vireo_result_t r=vireo_tcp_server_tls_run_once_with_gate(f.server,&o,work,32,handler,&f,t,1,&i,&e,
            handoff_fault?reject_handoff:NULL,&f);
        CHECK(errno==ECHILD);
        if(r==VIREO_RESULT_NO_MEMORY) {
            CHECK(handoff_fault && i.turn_count==1 && t[0].handshake.application_ready);
            CHECK(e.stage==VIREO_TCP_SERVER_TLS_ROUND_HANDOFF_QUEUE && i.remaining_count==0);
            CHECK(f.queue_calls==1 && f.handler_calls==0);schedule(&f,0);server_ready=true;
        } else CHECK(r==VIREO_OK);
        if(i.turn_count && t[0].path==VIREO_TCP_SERVER_TLS_TURN_HANDSHAKE) {
            CHECK(!t[0].application.process_called);
            if(t[0].handshake.application_ready) {server_ready=true;if(!handoff_fault)CHECK(i.remaining_count==1);}
        }
    }
    CHECK(peer_ready && server_ready && f.handler_calls==0 && SSL_version(f.ssl[0])==TLS1_3_VERSION);
    CHECK(SSL_get_verify_result(f.ssl[0])==X509_V_OK);
    if(handoff_fault) {finish(&f);++groups;return;}
    uint8_t frames[96],expected[96],received[96];
    for(size_t k=0;k<3;++k) {make_frame(frames+32*k,(uint32_t)k+10,false);make_frame(expected+32*k,(uint32_t)k+10,true);}
    ERR_clear_error();CHECK(SSL_write(f.ssl[0],frames,96)==96);size_t got=0;
    f.reenter_handler=true;
    for(size_t k=0;k<1024 && got<96;++k) {
        i=run(&f,1,t,1,VIREO_OK,NULL);
        if(i.turn_count)CHECK(t[0].path==VIREO_TCP_SERVER_TLS_TURN_APPLICATION && t[0].application.process.handler_calls<=1);
        ERR_clear_error();int n=SSL_read(f.ssl[0],received+got,(int)(96-got));
        if(n>0)got+=(size_t)n;
        else {int why=SSL_get_error(f.ssl[0],n);CHECK(why==SSL_ERROR_WANT_READ||why==SSL_ERROR_WANT_WRITE);}
        if(got<96) {struct pollfd fd={f.peers[0],POLLIN,0};CHECK(poll(&fd,1,1)>=0);}
    }
    CHECK(got==96 && memcmp(expected,received,96)==0 && f.handler_calls==3);
    uint8_t const tail[7]={1,0,2,3,0,4,5};ERR_clear_error();CHECK(SSL_write(f.ssl[0],tail,7)==7);
    request_close_client(&f,0,UINT64_C(5000000000));
    bool complete=false,peer_closed=false;
    for(size_t k=0;k<1024 && (!complete||!peer_closed);++k) {
        if(!peer_closed) {ERR_clear_error();int n=SSL_shutdown(f.ssl[0]);
            if(n==1)peer_closed=true;else if(n<0) {int why=SSL_get_error(f.ssl[0],n);CHECK(why==SSL_ERROR_WANT_READ||why==SSL_ERROR_WANT_WRITE);}}
        i=run(&f,1,t,1,VIREO_OK,NULL);
        if(i.turn_count) {CHECK(t[0].path==VIREO_TCP_SERVER_TLS_TURN_CLOSE && !t[0].application.process_called);
            if(t[0].close.progress.info.state==VIREO_TLS_CLOSE_COMPLETE)complete=true;}
        if(!complete||!peer_closed) {struct pollfd fd={f.peers[0],POLLIN|POLLOUT,0};CHECK(poll(&fd,1,1)>=0);}
    }
    CHECK(complete && peer_closed && f.handler_calls==3 && fcntl(f.accepted_fds[0],F_GETFD)>=0);
    uint8_t const *bytes=NULL;size_t count=0;
    EXPECT(vireo_tls_connection_read_peek(borrow(&f,0),&bytes,&count,NULL),VIREO_OK);
    CHECK(count==7 && memcmp(bytes,tail,7)==0);
    EXPECT(vireo_tls_connection_read_consume(borrow(&f,0),count,NULL),VIREO_OK);
    schedule(&f,0);unsigned clocks=f.calls[F_NOW];i=run(&f,1,t,1,VIREO_OK,NULL);
    CHECK(i.turn_count==1 && !t[0].close.sampled && !t[0].close.progress.native_called && f.calls[F_NOW]==clocks+2);
    int fd=f.accepted_fds[0];finish(&f);CHECK(fcntl(fd,F_GETFD)==-1 && errno==EBADF);++groups;
}
int main(void)
{
    struct sigaction action={0};action.sa_handler=SIG_IGN;CHECK(sigemptyset(&action.sa_mask)==0);
    CHECK(sigaction(SIGPIPE,&action,NULL)==0);size_t before=fd_count();
    inputs();wait_faults();mixed_round();due_round(false);due_round(true);prefix_failure();
    mod_recovery();failed_handshake();need_consume();real_round(true);real_round(false);
    size_t after=fd_count();CHECK(before==after);
    printf("test_tcp_server_tls_round: %u groups passed; fd %zu -> %zu; bounded FIFO/stages/prefix, own wait/lookup/handoff faults, real trusted TLS1.3 exact responses and retained close tail\n",groups,before,after);
    return 0;
}
