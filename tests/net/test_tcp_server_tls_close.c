/*
- PROJECT : VIREO
- FILE    : test_tcp_server_tls_close.c
- AUTHOR  : bitofux
- DATE    : 2026-10-18
- BRIEF   : 此模块负责：
- -- 本server TLS关闭调度/期限/恢复及真实双向通知验证
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
static void fault_next(fixture_t *f,enum fault p)
{ f->fault=p; f->fail_on=f->calls[p]+1; }
static vireo_tcp_server_tls_close_request_info_t request(fixture_t *f,size_t k,uint64_t duration)
{
    vireo_tcp_server_tls_close_request_info_t i;
    EXPECT(vireo_tcp_server_client_tls_close_request(f->server,f->clients[k],duration,&i,NULL),VIREO_OK);
    CHECK(i.sampled && i.deadline_computed && i.request_called && i.requested && i.sync.close_reported);
    CHECK(i.deadline_ns==i.now_ns+duration); return i;
}
static vireo_tcp_server_tls_close_step_info_t close_step(fixture_t *f,size_t k,vireo_result_t result)
{
    vireo_tcp_server_tls_close_step_info_t i;
    EXPECT(vireo_tcp_server_client_tls_close_step(f->server,f->clients[k],4096,&i,NULL),result);
    CHECK(i.step_called && i.progress_reported && i.sync.close_reported);
    return i;
}
static vireo_result_t queue_fail(void *ctx,vireo_tcp_server_t const *server,vireo_connection_pool_lease_t l)
{
    fixture_t *f=ctx; CHECK(server==f->server && same(l,f->clients[0])); ++f->queue_calls;
    return VIREO_RESULT_NO_MEMORY;
}
static void drain_ready(fixture_t *f)
{
    vireo_tcp_server_ready_client_t r[4];vireo_tcp_server_tls_poll_report_t p;
    EXPECT(vireo_tcp_server_tls_poll_ready_once(f->server,0,4,r,4,&p,NULL),VIREO_OK);
}
static void inputs(void)
{
    vireo_connection_pool_lease_t z={0}; vireo_tcp_server_tls_close_request_info_t r;
    vireo_tcp_server_tls_close_step_info_t s;vireo_tcp_server_tls_close_flow_info_t flow;
    vireo_tcp_server_tls_close_error_t e;
    memset(&r,0xa5,sizeof(r));memset(&e,0xa5,sizeof(e));
    EXPECT(vireo_tcp_server_client_tls_close_request(NULL,z,1,&r,&e),VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(!r.request_called && !r.requested && !r.sampled && e.stage==VIREO_TCP_SERVER_TLS_CLOSE_NONE);
    EXPECT(vireo_tcp_server_client_tls_close_step(NULL,z,4096,&s,NULL),VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(!s.step_called && !s.progress_reported);
    EXPECT(vireo_tcp_server_client_tls_close_flow_refresh(NULL,z,&flow,NULL),VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(!flow.close_reported);++groups;
    vireo_tcp_server_t *raw=NULL; EXPECT(vireo_tcp_server_create(&root_options,&raw,NULL),VIREO_OK);
    EXPECT(vireo_tcp_server_client_tls_close_request(raw,z,1,&r,NULL),VIREO_RESULT_BUSY);
    EXPECT(vireo_tcp_server_client_tls_close_step(raw,z,4096,&s,NULL),VIREO_RESULT_BUSY);
    EXPECT(vireo_tcp_server_client_tls_close_flow_refresh(raw,z,&flow,NULL),VIREO_RESULT_BUSY);
    EXPECT(vireo_tcp_server_destroy(&raw,NULL),VIREO_OK);++groups;
    fixture_t f;start(&f,&root_options,&tls_options,true);connect_one(&f);
    CHECK(admit(&f,1,VIREO_OK,NULL).admission.admitted_count==1);
    EXPECT(vireo_tcp_server_client_tls_close_request(f.server,f.clients[0],1,&r,NULL),VIREO_RESULT_BUSY);
    EXPECT(vireo_tcp_server_client_tls_close_step(f.server,f.clients[0],4096,&s,NULL),VIREO_RESULT_BUSY);
    CHECK(f.close_requests==0 && f.close_steps==0);finish(&f);++groups;
    open_clients(&f,1);
    EXPECT(vireo_tcp_server_client_tls_close_request(f.server,z,1,&r,NULL),VIREO_RESULT_NOT_FOUND);
    vireo_connection_pool_lease_t bad=f.clients[0];++bad.pool_id;
    EXPECT(vireo_tcp_server_client_tls_close_request(f.server,bad,1,&r,NULL),VIREO_RESULT_INVALID_ARGUMENT);
    bad=f.clients[0];bad.slot_index=4;
    EXPECT(vireo_tcp_server_client_tls_close_request(f.server,bad,1,&r,NULL),VIREO_RESULT_RANGE);
    bad=f.clients[0];++bad.generation;
    EXPECT(vireo_tcp_server_client_tls_close_request(f.server,bad,1,&r,NULL),VIREO_RESULT_NOT_FOUND);
    EXPECT(vireo_tcp_server_client_tls_close_request(f.server,f.clients[0],0,&r,NULL),VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_tcp_server_client_tls_close_request(f.server,f.clients[0],1,NULL,NULL),VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_tcp_server_client_tls_close_step(f.server,f.clients[0],4096,&s,NULL),VIREO_RESULT_BUSY);
    EXPECT(vireo_tcp_server_client_tls_close_flow_refresh(f.server,f.clients[0],&flow,NULL),VIREO_RESULT_BUSY);
    bad=f.clients[0];EXPECT(vireo_tcp_server_release_client(f.server,&f.clients[0],NULL),VIREO_OK);
    EXPECT(vireo_tcp_server_client_tls_close_flow_refresh(f.server,bad,&flow,NULL),VIREO_RESULT_NOT_FOUND);
    finish(&f);++groups;
}
static void request_boundaries(void)
{
    fixture_t f;open_clients(&f,1);f.fake_clock=true;f.now=UINT64_MAX-1;
    vireo_tcp_server_tls_close_request_info_t i;vireo_tcp_server_tls_close_error_t e;
    EXPECT(vireo_tcp_server_client_tls_close_request(f.server,f.clients[0],2,&i,&e),VIREO_RESULT_OVERFLOW);
    CHECK(i.sampled && !i.deadline_computed && !i.request_called && !i.requested);
    CHECK(e.stage==VIREO_TCP_SERVER_TLS_CLOSE_DEADLINE);++groups;
    fault_next(&f,F_NOW);
    EXPECT(vireo_tcp_server_client_tls_close_request(f.server,f.clients[0],1,&i,&e),VIREO_RESULT_IO);
    CHECK(!i.sampled && !i.requested && e.clock_error.system_errno==EIO);++groups;
    f.fault=F_NONE; f.now=UINT64_C(100000000000);fault_next(&f,F_REQUEST);
    EXPECT(vireo_tcp_server_client_tls_close_request(f.server,f.clients[0],10,&i,&e),VIREO_RESULT_IO);
    CHECK(i.request_called && !i.requested && e.stage==VIREO_TCP_SERVER_TLS_CLOSE_REQUEST);++groups;
    f.fault=F_NONE;f.reenter_close=true;i=request(&f,0,10);f.reenter_close=false;
    CHECK(i.sync.queue_called && i.sync.continuation_pending && f.close_native==0);++groups;
    unsigned calls=f.calls[F_NOW]; fault_next(&f,F_NOW);
    EXPECT(vireo_tcp_server_client_tls_close_request(f.server,f.clients[0],100,&i,&e),VIREO_RESULT_BUSY);
    CHECK(!i.sampled && !i.request_called && f.calls[F_NOW]==calls);
    uint8_t b=0;EXPECT(vireo_tls_connection_enqueue(borrow(&f,0),&b,1,NULL),VIREO_RESULT_BUSY);
    vireo_tcp_server_tls_flow_info_t oldflow;
    EXPECT(vireo_tcp_server_client_tls_flow_refresh(f.server,f.clients[0],&oldflow,NULL),VIREO_RESULT_BUSY);
    vireo_tcp_server_tls_close_flow_info_t flow;
    EXPECT(vireo_tcp_server_client_tls_close_flow_refresh(f.server,f.clients[0],&flow,NULL),VIREO_OK);
    CHECK(flow.close.deadline_ns==UINT64_C(100000000010) && f.calls[F_NOW]==calls);++groups;
    f.fault=F_NONE;vireo_tcp_server_tls_close_step_info_t stepinfo;
    EXPECT(vireo_tcp_server_client_tls_close_step(f.server,f.clients[0],0,&stepinfo,NULL),VIREO_RESULT_RANGE);
    EXPECT(vireo_tcp_server_client_tls_close_step(f.server,f.clients[0],4095,&stepinfo,NULL),VIREO_RESULT_RANGE);
    CHECK(!stepinfo.step_called && !stepinfo.sampled && f.close_steps==0);++groups;
    --f.now;
    EXPECT(vireo_tcp_server_client_tls_close_step(f.server,f.clients[0],4096,&stepinfo,&e),VIREO_RESULT_RANGE);
    CHECK(stepinfo.step_called && !stepinfo.progress_reported && stepinfo.sync.close_reported);
    CHECK(!stepinfo.sync.queue_called && f.close_native==0);finish(&f);++groups;
}
/** 明确区分依赖输出方向模型与真实SSL网络证据。 */
static void sync_models(void)
{
    fixture_t f;open_clients(&f,1);request(&f,0,UINT64_C(5000000000));
    f.model_close=true; f.close_model=(vireo_tls_close_info_t){.state=VIREO_TLS_CLOSE_DRAINING,
        .operation=VIREO_TLS_IO_OPERATION_WRITE,.wait=VIREO_TLS_IO_WAIT_READ};
    vireo_tcp_server_tls_close_flow_info_t i;vireo_tcp_server_tls_close_error_t e;
    EXPECT(vireo_tcp_server_client_tls_close_flow_refresh(f.server,f.clients[0],&i,NULL),VIREO_OK);
    CHECK(i.interests==(VIREO_EPOLL_INTEREST_READ|VIREO_EPOLL_INTEREST_PEER_WRITE_CLOSED) && !i.queue_called);
    /* 模型WRITE需要协议READ，即使真实普通读FIFO在其他场景满也不能按READ操作猜方向。 */
    f.close_model.wait=VIREO_TLS_IO_WAIT_WRITE;
    EXPECT(vireo_tcp_server_client_tls_close_flow_refresh(f.server,f.clients[0],&i,NULL),VIREO_OK);
    CHECK(i.interests==(VIREO_EPOLL_INTEREST_WRITE|VIREO_EPOLL_INTEREST_PEER_WRITE_CLOSED));++groups;
    f.close_model.needs_consume=true;f.close_model.resume=true;
    EXPECT(vireo_tcp_server_client_tls_close_flow_refresh(f.server,f.clients[0],&i,NULL),VIREO_OK);
    CHECK(i.interests==0 && !i.queue_called);++groups;
    f.close_model.needs_consume=false; f.close_model.wait=VIREO_TLS_IO_WAIT_NONE;
    EXPECT(vireo_tcp_server_client_tls_close_flow_refresh_with_gate(f.server,f.clients[0],&i,&e,queue_fail,&f),VIREO_RESULT_NO_MEMORY);
    CHECK(i.interests==VIREO_EPOLL_INTEREST_PEER_WRITE_CLOSED && i.queue_called && !i.continuation_pending);
    CHECK(e.sync_result==VIREO_OK && e.queue_result==VIREO_RESULT_NO_MEMORY && e.stage==VIREO_TCP_SERVER_TLS_CLOSE_QUEUE);++groups;
    f.close_model.wait=VIREO_TLS_IO_WAIT_READ;f.close_model.resume=false;fault_next(&f,F_MOD);
    EXPECT(vireo_tcp_server_client_tls_close_flow_refresh_with_gate(f.server,f.clients[0],&i,&e,queue_fail,&f),VIREO_RESULT_IO);
    CHECK(i.interests==VIREO_EPOLL_INTEREST_PEER_WRITE_CLOSED && i.sync_called && i.queue_called);
    CHECK(e.sync_result==VIREO_RESULT_IO && e.queue_result==VIREO_RESULT_NO_MEMORY && e.sync_loop_error.loop_error.epoll_error.system_errno==EIO);++groups;
    f.fault=F_NONE;unsigned steps=f.close_steps,requests=f.close_requests,clocks=f.calls[F_NOW];
    EXPECT(vireo_tcp_server_client_tls_close_flow_refresh(f.server,f.clients[0],&i,NULL),VIREO_OK);
    CHECK(i.sync_called && !i.queue_called && f.close_steps==steps && f.close_requests==requests && f.calls[F_NOW]==clocks);
    EXPECT(vireo_tcp_server_client_tls_close_flow_refresh(f.server,f.clients[0],&i,NULL),VIREO_OK);
    CHECK(!i.sync_called);++groups;
    f.model_close=false;fault_next(&f,F_CLOSE_STEP);f.fail_inspect_after_step=true;
    vireo_tcp_server_tls_close_step_info_t si;
    EXPECT(vireo_tcp_server_client_tls_close_step(f.server,f.clients[0],4096,&si,&e),VIREO_RESULT_IO);
    CHECK(si.step_called && !si.progress_reported && !si.sync.close_reported);
    CHECK(e.stage==VIREO_TCP_SERVER_TLS_CLOSE_STEP && e.tls_error.system_errno==EPIPE && e.sync_result==VIREO_RESULT_INTERNAL);
    f.fail_inspect_after_step=false;finish(&f);++groups;
    open_clients(&f,1);fault_next(&f,F_MOD);
    vireo_tcp_server_tls_close_request_info_t ri;
    EXPECT(vireo_tcp_server_client_tls_close_request(f.server,f.clients[0],UINT64_C(5000000000),&ri,&e),VIREO_RESULT_IO);
    CHECK(ri.requested && ri.sync.sync_called && ri.sync.queue_called && ri.sync.continuation_pending);
    f.fault=F_NONE;EXPECT(vireo_tcp_server_client_tls_close_flow_refresh(f.server,f.clients[0],&i,NULL),VIREO_OK);
    CHECK(f.close_requests==1 && f.close_steps==0);finish(&f);++groups;
}
/** 真正静默TCP对端；模型同域时钟控制期限，不冒称墙钟延迟测量。 */
static void expiry(void)
{
    fixture_t f;open_clients(&f,1);f.fake_clock=true;f.model_wait=true;f.now=UINT64_C(100000000000);
    vireo_tcp_server_tls_close_request_info_t ri=request(&f,0,UINT64_C(1000001));
    vireo_tcp_server_tls_close_step_info_t si=close_step(&f,0,VIREO_OK);
    CHECK(si.progress.native_called && si.progress.info.local_notify_sent);
    si=close_step(&f,0,VIREO_OK); CHECK(si.progress.info.wait==VIREO_TLS_IO_WAIT_READ);
    drain_ready(&f);f.advance_ns=UINT64_C(1000001);
    vireo_tcp_server_ready_client_t ready[4];vireo_tcp_server_tls_poll_report_t p;
    EXPECT(vireo_tcp_server_tls_poll_ready_once(f.server,100,1,ready,4,&p,NULL),VIREO_OK);
    CHECK(p.has_deadline && p.nearest_deadline_ns==ri.deadline_ns && p.expired_clients==1);
    CHECK(p.poll.selected_count==1 && same(ready[0].client,f.clients[0]) && ready[0].events==0);
    CHECK(f.waited_ms==2 && p.scanned_slots==8);++groups;
    unsigned natives=f.close_native;si=close_step(&f,0,VIREO_RESULT_TIMEOUT);
    CHECK(si.sampled && !si.progress.native_called && si.progress.info.state==VIREO_TLS_CLOSE_FAILED);
    CHECK(si.sync.interests==0 && !si.sync.queue_called && f.close_native==natives);++groups;
    unsigned clocks=f.calls[F_NOW]; fault_next(&f,F_NOW);
    si=close_step(&f,0,VIREO_RESULT_TIMEOUT);CHECK(!si.sampled && f.calls[F_NOW]==clocks && !si.progress.native_called);
    vireo_tcp_server_tls_close_flow_info_t flow;
    EXPECT(vireo_tcp_server_client_tls_close_flow_refresh(f.server,f.clients[0],&flow,NULL),VIREO_OK);
    CHECK(flow.close.state==VIREO_TLS_CLOSE_FAILED && f.calls[F_NOW]==clocks);
    vireo_tcp_server_tls_info_t resources;EXPECT(vireo_tcp_server_tls_inspect(f.server,&resources,NULL),VIREO_OK);
    CHECK(resources.resource_bytes==resources.per_connection_resource_bytes);finish(&f);++groups;
}
/** 实际明文、通知和未消费尾部；不使用模型快照。 */
static void bilateral(bool peer_first,bool fill_read)
{
    fixture_t f;open_clients(&f,1);
    uint8_t response[32];for(size_t k=0;k<sizeof(response);++k)response[k]=(uint8_t)k;
    EXPECT(vireo_tls_connection_enqueue(borrow(&f,0),response,sizeof(response),NULL),VIREO_OK);
    uint8_t tail[4096];for(size_t k=0;k<sizeof(tail);++k)tail[k]=(uint8_t)(k%251);
    size_t tail_size=fill_read?sizeof(tail):7,written=0;
    CHECK(SSL_write_ex(f.ssl[0],tail,tail_size,&written)==1 && written==tail_size);
    if(peer_first) { int r=SSL_shutdown(f.ssl[0]);CHECK(r==0); }
    request(&f,0,UINT64_C(5000000000));
    uint8_t received[32];size_t total=0;bool notified=peer_first,done=false,saw_consume=false;
    size_t total_consumed=0;
    for(size_t n=0;n<1024 && !done;++n) {
        vireo_tcp_server_tls_close_step_info_t si=close_step(&f,0,VIREO_OK);
        CHECK(si.progress.read_bytes<=4096 && si.progress.write_bytes<=4096);
        if(total<sizeof(received)) {
            size_t got=0;ERR_clear_error();int rc=SSL_read_ex(f.ssl[0],received+total,sizeof(received)-total,&got);
            int why=rc==1?SSL_ERROR_NONE:SSL_get_error(f.ssl[0],rc);
            CHECK(why==SSL_ERROR_NONE || why==SSL_ERROR_WANT_READ || why==SSL_ERROR_WANT_WRITE || why==SSL_ERROR_ZERO_RETURN);
            total+=got;
        }
        if(si.progress.info.needs_consume) {
            CHECK(fill_read && si.sync.interests==0 && !si.sync.queue_called);saw_consume=true;
            /* 真读FIFO满 + 仅关闭snapshot模型：优先WRITE需要READ不能被普通读满屏蔽。 */
            f.model_close=true;f.close_model=si.progress.info;
            f.close_model.operation=VIREO_TLS_IO_OPERATION_WRITE;f.close_model.wait=VIREO_TLS_IO_WAIT_READ;
            f.close_model.needs_consume=false;f.close_model.resume=false;
            vireo_tcp_server_tls_close_flow_info_t priority;
            EXPECT(vireo_tcp_server_client_tls_close_flow_refresh(f.server,f.clients[0],&priority,NULL),VIREO_OK);
            CHECK(priority.interests==(VIREO_EPOLL_INTEREST_READ|VIREO_EPOLL_INTEREST_PEER_WRITE_CLOSED));
            f.model_close=false;
            uint8_t const *p=NULL;size_t size=0;
            EXPECT(vireo_tls_connection_read_peek(borrow(&f,0),&p,&size,NULL),VIREO_OK);
            CHECK(size==sizeof(tail) && memcmp(p,tail,size)==0);
            EXPECT(vireo_tls_connection_read_consume(borrow(&f,0),size,NULL),VIREO_OK);total_consumed+=size;
            unsigned native=f.close_native;
            vireo_tcp_server_tls_close_flow_info_t fi;
            EXPECT(vireo_tcp_server_client_tls_close_flow_refresh(f.server,f.clients[0],&fi,NULL),VIREO_OK);
            CHECK(fi.interests!=0 && f.close_native==native);
        }
        if(!notified && total==sizeof(received) && (!fill_read || saw_consume)) {
            ERR_clear_error();int rc=SSL_shutdown(f.ssl[0]);
            if(rc<0) { int why=SSL_get_error(f.ssl[0],rc);CHECK(why==SSL_ERROR_WANT_READ || why==SSL_ERROR_WANT_WRITE); }
            else notified=true;
        }
        done=si.progress.info.state==VIREO_TLS_CLOSE_COMPLETE;
        if(!done) {struct pollfd pollfd={f.peers[0],POLLIN|POLLOUT,0};CHECK(poll(&pollfd,1,1)>=0);}
    }
    CHECK(done && notified && total==sizeof(response) && memcmp(response,received,sizeof(response))==0);
    CHECK(!fill_read || saw_consume);
    uint8_t const *p=NULL;size_t size=0;
    EXPECT(vireo_tls_connection_read_peek(borrow(&f,0),&p,&size,NULL),VIREO_OK);
    CHECK(size+total_consumed==tail_size);
    if(size)CHECK(memcmp(p,tail,size)==0);
    /* COMPLETE仍持fd与读尾部，不偷偷归还。终态不采时/网络。 */
    CHECK(fcntl(f.accepted_fds[0],F_GETFD)>=0);
    unsigned natives=f.close_native,clocks=f.calls[F_NOW];fault_next(&f,F_NOW);
    vireo_tcp_server_tls_close_step_info_t si=close_step(&f,0,VIREO_OK);
    CHECK(!si.sampled && !si.progress.native_called && f.close_native==natives && f.calls[F_NOW]==clocks);
    EXPECT(vireo_tls_connection_read_consume(borrow(&f,0),size,NULL),VIREO_OK);
    int fd=f.accepted_fds[0];finish(&f);CHECK(fcntl(fd,F_GETFD)==-1 && errno==EBADF);++groups;
}
static void committed_failure_recovery(void)
{
    fixture_t f;open_clients(&f,1);
    /* 请求已提交，末尾观察失败；纯刷新修复不重装期限。 */
    f.fault=F_CLOSE_INSPECT;f.fail_on=f.calls[F_CLOSE_INSPECT]+2;
    vireo_tcp_server_tls_close_request_info_t ri;vireo_tcp_server_tls_close_error_t e;
    EXPECT(vireo_tcp_server_client_tls_close_request(f.server,f.clients[0],UINT64_C(5000000000),&ri,&e),VIREO_RESULT_INTERNAL);
    CHECK(ri.requested && !ri.sync.close_reported && e.sync_result==VIREO_RESULT_INTERNAL);
    CHECK(e.stage==VIREO_TCP_SERVER_TLS_CLOSE_INSPECT);f.fault=F_NONE;
    vireo_tcp_server_tls_close_flow_info_t fi;
    EXPECT(vireo_tcp_server_client_tls_close_flow_refresh(f.server,f.clients[0],&fi,NULL),VIREO_OK);
    CHECK(fi.close.deadline_ns==ri.deadline_ns && f.close_requests==1 && f.close_steps==0);
    fault_next(&f,F_NOW);vireo_tcp_server_tls_close_step_info_t si;
    EXPECT(vireo_tcp_server_client_tls_close_step(f.server,f.clients[0],4096,&si,&e),VIREO_RESULT_IO);
    CHECK(!si.sampled && !si.step_called && !si.sync.close_reported);finish(&f);++groups;
    /* 真实TIMEOUT首因、MOD与队列两个模型次因同时保留。 */
    open_clients(&f,1);f.fake_clock=true;f.now=UINT64_C(100000000000);ri=request(&f,0,1);
    ++f.now;fault_next(&f,F_MOD);
    EXPECT(vireo_tcp_server_client_tls_close_step_with_gate(f.server,f.clients[0],4096,&si,&e,queue_fail,&f),VIREO_RESULT_TIMEOUT);
    CHECK(si.progress_reported && !si.progress.native_called && si.sync.sync_called && si.sync.queue_called);
    CHECK(e.stage==VIREO_TCP_SERVER_TLS_CLOSE_STEP && e.sync_result==VIREO_RESULT_IO && e.queue_result==VIREO_RESULT_NO_MEMORY);
    CHECK(si.sync.interests==ri.sync.interests && !si.sync.continuation_pending);
    f.fault=F_NONE;EXPECT(vireo_tcp_server_client_tls_close_flow_refresh(f.server,f.clients[0],&fi,NULL),VIREO_OK);
    CHECK(fi.interests==0 && !fi.queue_called && f.close_native==0 && f.close_steps==1);
    finish(&f);++groups;
}
/** 四客户同时处于closing/closing/application/handshake；同FIFO不分阶段。 */
static void mixed_poll(bool partial_failure)
{
    fixture_t f;open_clients(&f,3);f.fake_clock=true;f.model_wait=true;f.now=UINT64_C(100000000000);
    request(&f,0,20);request(&f,1,30);
    connect_one(&f);
    vireo_tcp_server_admit_budget_t b={1,2};vireo_tcp_server_tls_admit_info_t ai;
    EXPECT(vireo_tcp_server_tls_admit_batch(f.server,&b,&f.clients[3],1,&ai,NULL),VIREO_OK);
    CHECK(ai.admission.admitted_count==1);
    for(size_t k=0;k<4;++k)EXPECT(vireo_connection_set_interests(f.objects[k],0,NULL),VIREO_OK);
    /* 取出已排待办；不驱动SSL，静默peer没有HUP/ERR。 */
    vireo_tcp_server_ready_client_t ready[4];vireo_tcp_server_tls_poll_report_t p;
    EXPECT(vireo_tcp_server_tls_poll_ready_once(f.server,0,4,ready,4,&p,NULL),VIREO_OK);
    CHECK(p.poll.remaining_count==0);
    f.advance_ns=30;
    vireo_tcp_server_tls_error_t e;
    if(partial_failure) {f.fault=F_CLOSE_INSPECT;f.fail_on=f.calls[F_CLOSE_INSPECT]+5;}
    EXPECT(vireo_tcp_server_tls_poll_ready_once(f.server,100,1,ready,4,&p,&e),
        partial_failure?VIREO_RESULT_INTERNAL:VIREO_OK);
    CHECK(p.has_deadline && p.nearest_deadline_ns==UINT64_C(100000000020) && f.waited_ms==1);
    if(partial_failure) {
        CHECK(e.stage==VIREO_TCP_SERVER_TLS_SCAN_AFTER && p.expired_clients==1);
        CHECK(p.poll.selected_count==0 && p.poll.queued_after_wait==1 && p.poll.remaining_count==1);
        f.fault=F_NONE;
    } else {
        CHECK(p.expired_clients==2 && p.poll.selected_count==1 && p.poll.remaining_count==1);
        CHECK(same(ready[0].client,f.clients[0]) && ready[0].events==0 && p.scanned_slots==8);
    }
    f.advance_ns=0;
    EXPECT(vireo_tcp_server_tls_poll_ready_once(f.server,100,1,ready,4,&p,NULL),VIREO_OK);
    CHECK(p.expired_clients==2 && p.poll.selected_count==1 && p.poll.remaining_count==1);
    CHECK(same(ready[0].client,f.clients[partial_failure?0:1]));
    close_step(&f,0,VIREO_RESULT_TIMEOUT);close_step(&f,1,VIREO_RESULT_TIMEOUT);
    EXPECT(vireo_tcp_server_tls_poll_ready_once(f.server,0,4,ready,4,&p,NULL),VIREO_OK);
    CHECK(p.has_deadline && p.nearest_deadline_ns==UINT64_C(105000000000) && p.expired_clients==0);
    finish(&f);++groups;
}
static void poll_faults(void)
{
    fixture_t f;open_clients(&f,1);f.fake_clock=true;f.model_wait=true;f.now=UINT64_C(100000000000);
    request(&f,0,100);vireo_tcp_server_ready_client_t ready[4];
    vireo_tcp_server_tls_poll_report_t p;vireo_tcp_server_tls_error_t e;
    enum fault points[]={F_CLOSE_INSPECT,F_NOW,F_WAIT};
    for(size_t k=0;k<3;++k) {
        fault_next(&f,points[k]);
        EXPECT(vireo_tcp_server_tls_poll_ready_once(f.server,0,4,ready,4,&p,&e),
            k==0?VIREO_RESULT_INTERNAL:VIREO_RESULT_IO);
        CHECK(p.poll.selected_count==0 && p.poll.wait_called==(k==2));
        CHECK(e.stage==(k==0?VIREO_TCP_SERVER_TLS_SCAN_BEFORE:k==1?VIREO_TCP_SERVER_TLS_CLOCK:VIREO_TCP_SERVER_TLS_WAIT));
        f.fault=F_NONE;++groups;
    }
    f.fault=F_NOW;f.fail_on=f.calls[F_NOW]+2;f.notify_in_wait=true;
    EXPECT(vireo_tcp_server_tls_poll_ready_once(f.server,0,4,ready,4,&p,&e),VIREO_RESULT_IO);
    CHECK(p.poll.wait_called && p.poll.selected_count==0 && p.poll.queued_after_wait==1);
    f.notify_in_wait=false;f.fault=F_NONE;f.stop_in_wait=true;
    EXPECT(vireo_tcp_server_tls_poll_ready_once(f.server,0,4,ready,4,&p,NULL),VIREO_OK);
    CHECK(p.poll.stopped && p.poll.selected_count==0 && fcntl(f.accepted_fds[0],F_GETFD)>=0);
    finish(&f);++groups;
}
/** 真实裸EOF产生应用首错；request仅调用原入口重现，不采时或封口。 */
static void failed_application(void)
{
    fixture_t f;open_clients(&f,1);CHECK(close(f.peers[0])==0);f.peers[0]=-1;
    vireo_tls_io_budget_t b={4096,1};vireo_tls_io_progress_t p;
    vireo_tls_connection_error_t original;vireo_result_t result=VIREO_OK;
    for(size_t k=0;k<1024 && result==VIREO_OK;++k)
        result=vireo_tls_connection_receive(borrow(&f,0),&b,&p,&original);
    CHECK(result==VIREO_RESULT_PROTOCOL || result==VIREO_RESULT_IO);
    unsigned clocks=f.calls[F_NOW];fault_next(&f,F_NOW);
    vireo_tcp_server_tls_close_request_info_t i;vireo_tcp_server_tls_close_error_t e;
    EXPECT(vireo_tcp_server_client_tls_close_request(f.server,f.clients[0],1,&i,&e),result);
    CHECK(!i.sampled && i.request_called && !i.requested && f.calls[F_NOW]==clocks);
    CHECK(e.tls_error.stage==original.stage && e.tls_error.system_errno==original.system_errno);
    vireo_tls_close_info_t close;
    EXPECT(vireo_tls_connection_close_inspect(borrow(&f,0),&close,NULL),VIREO_OK);
    CHECK(close.state==VIREO_TLS_CLOSE_NONE);finish(&f);++groups;
}
static void signal_child(bool expired)
{
    fixture_t f;open_clients(&f,1);f.fake_clock=true;f.now=UINT64_C(100000000000);
    request(&f,0,10);if(expired)f.now+=10;
    struct sigaction action={0};action.sa_handler=SIG_DFL;CHECK(sigemptyset(&action.sa_mask)==0);
    CHECK(sigaction(SIGPIPE,&action,NULL)==0);
    vireo_tcp_server_tls_close_step_info_t i;vireo_tcp_server_tls_close_error_t e;
    EXPECT(vireo_tcp_server_client_tls_close_step(f.server,f.clients[0],4096,&i,&e),expired?VIREO_RESULT_TIMEOUT:VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(i.step_called && i.progress_reported==expired && f.close_native==0 && i.sync.close_reported);
    if(!expired)CHECK(e.tls_error.stage==VIREO_TLS_CONNECTION_STAGE_SIGNAL_POLICY);
    finish(&f);
}
static void signals(char const *path)
{
    for(unsigned k=0;k<2;++k) {
        pid_t p=fork();CHECK(p>=0);
        if(p==0) {execl(path,path,k?"--expired-signal":"--signal",(char *)NULL);_exit(127);}
        int status=0;CHECK(waitpid(p,&status,0)==p && WIFEXITED(status) && WEXITSTATUS(status)==0);++groups;
    }
}
int main(int argc,char **argv)
{
    struct sigaction a={0};a.sa_handler=SIG_IGN;CHECK(sigemptyset(&a.sa_mask)==0);CHECK(sigaction(SIGPIPE,&a,NULL)==0);
    if(argc==2) {signal_child(strcmp(argv[1],"--expired-signal")==0);return 0;}
    size_t before=fd_count(); inputs();request_boundaries();sync_models();expiry();
    bilateral(false,false);bilateral(true,false);bilateral(false,true);
    committed_failure_recovery();mixed_poll(false);mixed_poll(true);poll_faults();failed_application();signals(argv[0]);
    size_t after=fd_count();CHECK(before==after);
    printf("test_tcp_server_tls_close: %u groups passed; fd %zu -> %zu; real trusted TCP/TLS1.3 bilateral notify, exact drain/tail and separate own faults/directions/time inputs\n",groups,before,after);
    return 0;
}
