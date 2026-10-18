/*
- PROJECT : VIREO
- FILE    : test_tcp_server_tls_serve.c
- AUTHOR  : bitofux
- DATE    : 2026-10-18
- BRIEF   : 此模块负责：
- -- 本server TLS有限服务/容量监听/两前缀与主次失败及真实协议验证
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
    vireo_acceptor_t *listener_object;
    vireo_acceptor_callback_t listener_callback;
    void *listener_context;
    unsigned mod_calls, fail_mod_on;
    uint32_t injected_listener_events;
    bool probe_mod, stop_in_handler, stop_in_accept;
    unsigned handler_calls, handler_fail_at;
    bool reenter_handler;
} fixture_t;
static void probe_all(fixture_t *f);
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
    fixture_t *f=ctx;
    if(f->stop_in_accept) EXPECT(vireo_tcp_server_request_stop(f->server,NULL),VIREO_OK);
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
    if(f->probe) probe_all(f);
    if(f->injected_listener_events) {
        f->listener_callback(f->listener_object,f->injected_listener_events,f->listener_context);
    }
    if(hit(f,F_WAIT))return VIREO_RESULT_IO;
    if(f->stop_in_wait) EXPECT(vireo_event_loop_request_stop(l,NULL),VIREO_OK);
    if(f->notify_in_wait) {
        CHECK(f->attached>0); f->callbacks[0](f->objects[0],VIREO_EPOLL_EVENT_READ,f->callback_contexts[0]);
    }
    if(f->model_wait) { f->now+=f->advance_ns; return vireo_event_loop_run_once(l,0,i,e); }
    return vireo_event_loop_run_once(l,timeout,i,e);
}

/* 仅本核心逐对象监听桥接；模型错误不冒充真实内核MOD失败。 */
static vireo_result_t listener_inspect(void *ctx,vireo_acceptor_t const *a,vireo_acceptor_info_t *i)
{ (void)ctx;return vireo_acceptor_inspect(a,i); }
static vireo_result_t listener_attach(void *ctx,vireo_acceptor_t *a,vireo_event_loop_t *l,
    bool enabled,vireo_acceptor_callback_t cb,void *arg,vireo_acceptor_loop_error_t *e)
{
    fixture_t *f=ctx;vireo_result_t r=vireo_acceptor_attach(a,l,enabled,cb,arg,e);
    if(r==VIREO_OK) {f->listener_object=a;f->listener_callback=cb;f->listener_context=arg;}return r;
}
static vireo_result_t listener_read(void *ctx,vireo_acceptor_t *a,bool enabled,vireo_acceptor_loop_error_t *e)
{
    fixture_t *f=ctx;++f->mod_calls;if(f->probe_mod)probe_all(f);
    if(f->mod_calls==f->fail_mod_on) {
        *e=(vireo_acceptor_loop_error_t){.stage=VIREO_ACCEPTOR_LOOP_STAGE_UPDATE,
            .loop_error={.stage=VIREO_EVENT_LOOP_STAGE_MOD,.epoll_error={VIREO_EPOLL_STAGE_MOD,EIO}}};
        return VIREO_RESULT_IO;
    }
    return vireo_acceptor_set_read_enabled(a,enabled,e);
}
static vireo_result_t listener_detach(void *ctx,vireo_acceptor_t *a,vireo_acceptor_loop_error_t *e)
{ (void)ctx;return vireo_acceptor_detach(a,e); }
static vireo_result_t listener_forget(void *ctx,vireo_acceptor_t *a)
{ (void)ctx;return vireo_acceptor_forget_destroyed_loop(a,NULL); }
static vireo_result_t listener_destroy(void *ctx,vireo_acceptor_t **a,vireo_acceptor_error_t *e)
{ (void)ctx;return vireo_acceptor_destroy(a,e); }
static vireo_tcp_server_listener_ops_t listener_ops(fixture_t *f)
{ return (vireo_tcp_server_listener_ops_t){f,listener_inspect,listener_attach,listener_read,
    listener_detach,listener_forget,listener_destroy}; }

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
        vireo_tcp_server_listener_ops_t a=listener_ops(f);
        EXPECT(vireo_tcp_server_create_tls_with_all_ops(base,options,&context,&b,&a,&c,&w,&t,&f->server,NULL),VIREO_OK);
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
    if(f->stop_in_handler) EXPECT(vireo_tcp_server_request_stop(f->server,NULL),VIREO_OK);
    if(f->reenter_handler) {
        probe_all(f);
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
        CHECK(si.serving_active && si.scheduling_active && si.driving_active && si.processing_active);
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
static vireo_tcp_server_tls_serve_options_t const serve_options = {
    {0,{32,32},{{4096,8},{1,32,32},{4096,8}},{4},4096},{1,4}
};
/** 同根所有可变入口在监听依赖/wait/handler回调内均拒绝；观察仍允许。 */
static void probe_all(fixture_t *f)
{
    uint8_t work[32];vireo_tcp_server_tls_turn_result_t t[1];
    vireo_connection_pool_lease_t l[1]={{0}};
    vireo_tcp_server_tls_serve_info_t i;vireo_tcp_server_tls_admission_info_t a;
    EXPECT(vireo_tcp_server_tls_serve_once(f->server,&serve_options,work,32,handler,f,t,1,l,1,&i,NULL),VIREO_RESULT_BUSY);
    EXPECT(vireo_tcp_server_tls_admission_refresh(f->server,&a,NULL),VIREO_RESULT_BUSY);
    vireo_tcp_server_tls_admit_info_t ad;
    EXPECT(vireo_tcp_server_tls_admit_batch(f->server,&serve_options.admit,l,1,&ad,NULL),VIREO_RESULT_BUSY);
    vireo_tcp_server_tls_round_info_t ri;
    EXPECT(vireo_tcp_server_tls_run_once(f->server,&round_options,work,32,handler,f,t,1,&ri,NULL),VIREO_RESULT_BUSY);
    EXPECT(vireo_tcp_server_set_listener_read_enabled(f->server,false,NULL),VIREO_RESULT_BUSY);
    EXPECT(vireo_tcp_server_destroy(&f->server,NULL),VIREO_RESULT_BUSY);
    vireo_tcp_server_info_t state;EXPECT(vireo_tcp_server_inspect(f->server,&state),VIREO_OK);
    CHECK(state.serving_active && !state.admission_enabled);
}
/** 新lease只保存已发布前缀到指定空位置，非OK也必须维持可达owner。 */
static vireo_tcp_server_tls_serve_info_t serve(fixture_t *f,
    vireo_tcp_server_tls_serve_options_t const *o,vireo_tcp_server_tls_turn_result_t *t,
    size_t capacity,size_t output_slot,vireo_result_t expected,vireo_tcp_server_tls_serve_error_t *error)
{
    uint8_t work[32];vireo_connection_pool_lease_t l[4]={{0}};
    vireo_tcp_server_tls_serve_info_t i;
    EXPECT(vireo_tcp_server_tls_serve_once(f->server,o,work,32,handler,f,t,capacity,l,4,&i,error),expected);
    CHECK(i.round.turn_count==i.round.succeeded_count+i.round.failed_count);
    CHECK(i.round.turn_count<=capacity && i.round.turn_count<=o->round.round.max_clients);
    for(size_t k=0;k<i.admission.admission.admitted_count;++k) {
        CHECK(output_slot+k<4 && empty(f->clients[output_slot+k]));f->clients[output_slot+k]=l[k];
    }
    return i;
}
static void inputs(void)
{
    fixture_t f;start(&f,&root_options,&tls_options,true);
    uint8_t w[32],backup[32];memset(w,0xa5,32);memcpy(backup,w,32);
    vireo_tcp_server_tls_turn_result_t t[2],old[2];memset(t,0xa5,sizeof(t));memcpy(old,t,sizeof(t));
    for(unsigned k=0;k<17;++k) {
        vireo_tcp_server_tls_serve_options_t o=serve_options;size_t tc=2,lc=2;
        vireo_connection_pool_lease_t l[2]={{0}};vireo_result_t expected=VIREO_RESULT_RANGE;
        switch(k) {
        case 0:o.round.timeout_ms=-1;expected=VIREO_RESULT_INVALID_ARGUMENT;break;
        case 1:o.admit.max_accepts=0;expected=VIREO_RESULT_INVALID_ARGUMENT;break;
        case 2:o.admit.max_accept_syscalls=0;expected=VIREO_RESULT_INVALID_ARGUMENT;break;
        case 3:tc=0;break;case 4:lc=0;break;case 5:o.round.round.max_clients=0;break;
        case 6:o.round.round.max_clients=65536;break;case 7:o.admit.max_accepts=65536;break;
        case 8:o.round.drive.receive.max_bytes=4095;break;case 9:o.round.close_max_bytes=4095;break;
        case 10:o.round.drive.send.max_native_calls=0;break;
        case 11:o.round.process.max_request_frame_bytes=4097;break;
        case 12:o.round.process.max_response_frame_bytes=33;break;
        case 13:o.round.drive.process.max_messages=0;break;case 14:lc=65536;break;case 15:tc=65536;break;
        default:l[0].pool_id=1;expected=VIREO_RESULT_INVALID_ARGUMENT;break;
        }
        vireo_connection_pool_lease_t lb[2];memcpy(lb,l,sizeof(l));
        vireo_tcp_server_tls_serve_info_t i;vireo_tcp_server_tls_serve_error_t e;
        EXPECT(vireo_tcp_server_tls_serve_once(f.server,&o,w,32,handler,&f,t,tc,l,lc,&i,&e),expected);
        CHECK(!i.pre_sync_called && !i.round.wait_called && !i.admission_called && !i.post_sync_called);
        CHECK(e.stage==VIREO_TCP_SERVER_TLS_SERVE_NONE && f.mod_calls==0 && f.calls[F_WAIT]==0 && f.calls[F_ACCEPT]==0);
        CHECK(memcmp(t,old,sizeof(t))==0 && memcmp(w,backup,32)==0 && memcmp(l,lb,sizeof(l))==0);++groups;
    }
    for(unsigned k=0;k<7;++k) {
        vireo_connection_pool_lease_t l[1]={{0}};vireo_tcp_server_tls_serve_info_t i;
        EXPECT(vireo_tcp_server_tls_serve_once(k==0?NULL:f.server,k==1?NULL:&serve_options,
            k==2?NULL:w,32,k==3?NULL:handler,&f,k==4?NULL:t,1,k==5?NULL:l,1,k==6?NULL:&i,NULL),VIREO_RESULT_INVALID_ARGUMENT);
        CHECK(f.mod_calls==0 && f.calls[F_WAIT]==0);++groups;
    }
    vireo_tcp_server_tls_admission_info_t ai;
    EXPECT(vireo_tcp_server_tls_admission_refresh(NULL,&ai,NULL),VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_tcp_server_tls_admission_refresh(f.server,NULL,NULL),VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_tcp_server_unbind_listener(f.server,NULL),VIREO_OK);
    EXPECT(vireo_tcp_server_tls_admission_refresh(f.server,&ai,NULL),VIREO_RESULT_NOT_FOUND);
    vireo_connection_pool_lease_t l[1]={{0}};vireo_tcp_server_tls_serve_info_t i;
    EXPECT(vireo_tcp_server_tls_serve_once(f.server,&serve_options,w,32,handler,&f,t,1,l,1,&i,NULL),VIREO_RESULT_NOT_FOUND);
    finish(&f);++groups;
    vireo_tcp_server_t *raw=NULL;EXPECT(vireo_tcp_server_create(&root_options,&raw,NULL),VIREO_OK);
    EXPECT(vireo_tcp_server_tls_admission_refresh(raw,&ai,NULL),VIREO_RESULT_BUSY);
    EXPECT(vireo_tcp_server_tls_serve_once(raw,&serve_options,w,32,handler,&f,t,1,l,1,&i,NULL),VIREO_RESULT_BUSY);
    EXPECT(vireo_tcp_server_destroy(&raw,NULL),VIREO_OK);++groups;
}
/** 分别触发三额度、恰好/差一字节与同时多因，退款只发生在真实release。 */
static void capacities(void)
{
    for(unsigned k=0;k<6;++k) {
        fixture_t f;vireo_tcp_server_options_t base=root_options;vireo_tcp_server_tls_options_t tls=tls_options;
        size_t n=k>=4?2:1;
        if(k==0)base.connection_capacity=1;
        if(k==1)base.max_buffer_bytes=16383;
        if(k==2)tls.max_tls_resource_bytes=81919;
        if(k==3) {base.connection_capacity=1;base.max_buffer_bytes=8192;tls.max_tls_resource_bytes=40960;}
        if(k==4)tls.max_tls_resource_bytes=81920;
        if(k==5)base.max_buffer_bytes=16384;
        start(&f,&base,&tls,true);for(size_t j=0;j<n;++j)connect_one(&f);
        CHECK(admit(&f,n,VIREO_OK,NULL).admission.admitted_count==n);
        vireo_tcp_server_info_t si;EXPECT(vireo_tcp_server_inspect(f.server,&si),VIREO_OK);
        CHECK(si.listener_read_enabled && !si.admission_enabled); /* 旧admit不隐式MOD。 */
        vireo_tcp_server_tls_admission_info_t i;f.probe_mod=true;
        EXPECT(vireo_tcp_server_tls_admission_refresh(f.server,&i,NULL),VIREO_OK);
        CHECK(i.connection_limited==(k==0||k==3));CHECK(i.buffer_limited==(k==1||k==3||k==5));
        CHECK(i.tls_resource_limited==(k==2||k==3||k==4));CHECK(i.sync_called && !i.listener_read_enabled);
        unsigned calls=f.mod_calls;
        EXPECT(vireo_tcp_server_tls_admission_refresh(f.server,&i,NULL),VIREO_OK);
        CHECK(!i.sync_called && f.mod_calls==calls);
        EXPECT(vireo_tcp_server_release_client(f.server,&f.clients[0],NULL),VIREO_OK);
        EXPECT(vireo_tcp_server_tls_admission_refresh(f.server,&i,NULL),VIREO_OK);
        CHECK(i.sync_called && i.listener_read_enabled && !i.connection_limited && !i.buffer_limited && !i.tls_resource_limited);
        finish(&f);++groups;
    }
}
static void refresh_faults(void)
{
    fixture_t f;start(&f,&root_options,&tls_options,true);
    EXPECT(vireo_tcp_server_set_listener_read_enabled(f.server,false,NULL),VIREO_OK);
    f.fail_mod_on=f.mod_calls+1;f.probe_mod=true;
    vireo_tcp_server_tls_admission_info_t i;vireo_tcp_server_listener_error_t e;
    EXPECT(vireo_tcp_server_tls_admission_refresh(f.server,&i,&e),VIREO_RESULT_IO);
    CHECK(i.sync_called && !i.listener_read_enabled && e.stage==VIREO_TCP_SERVER_LISTENER_UPDATE);
    CHECK(e.acceptor_error.loop_error.epoll_error.system_errno==EIO);
    f.fail_mod_on=0;EXPECT(vireo_tcp_server_tls_admission_refresh(f.server,&i,&e),VIREO_OK);
    CHECK(i.listener_read_enabled && i.sync_called && e.stage==VIREO_TCP_SERVER_LISTENER_NONE);
    EXPECT(vireo_tcp_server_request_stop(f.server,NULL),VIREO_OK);
    f.probe_mod=false; /* 下面手动入口本身不是有限阶段，不能冒充在途回调测试。 */
    EXPECT(vireo_tcp_server_set_listener_read_enabled(f.server,false,NULL),VIREO_OK);
    EXPECT(vireo_tcp_server_tls_admission_refresh(f.server,&i,NULL),VIREO_OK);CHECK(i.listener_read_enabled);
    finish(&f);++groups;
}
static vireo_result_t reject_admission_queue(void *ctx,vireo_tcp_server_t const *s,vireo_connection_pool_lease_t l)
{
    fixture_t *f=ctx;CHECK(s==f->server && !empty(l));++f->queue_calls;
    return f->queue_calls==2?VIREO_RESULT_NO_MEMORY:VIREO_OK;
}
/** 接入后失败及末尾MOD错误保留两项已发布租约，独立恢复不会重新accept。 */
static void admission_errors(void)
{
    for(unsigned k=0;k<7;++k) {
        fixture_t f;start(&f,&root_options,&tls_options,true);connect_one(&f);connect_one(&f);
        enum fault const points[]={F_ACCEPT,F_NOW,F_CREATE,F_PREPARE,F_ARM,F_ADOPT,F_ATTACH};
        vireo_result_t const results[]={VIREO_RESULT_IO,VIREO_RESULT_IO,VIREO_RESULT_NO_MEMORY,
            VIREO_RESULT_NO_MEMORY,VIREO_RESULT_INTERNAL,VIREO_RESULT_NO_MEMORY,VIREO_RESULT_IO};
        f.fault=points[k];f.fail_on=2;
        if(k==1)f.fail_on=4; /* round前后采时2次，第二个accept后第4次采样。 */
        vireo_tcp_server_tls_serve_options_t o=serve_options;o.admit.max_accepts=2;
        vireo_tcp_server_tls_turn_result_t t[1];vireo_tcp_server_tls_serve_error_t e;
        vireo_tcp_server_tls_serve_info_t i=serve(&f,&o,t,1,0,results[k],&e);
        CHECK(e.stage==VIREO_TCP_SERVER_TLS_SERVE_ADMIT && i.pre_sync_called && i.post_sync_called && i.admission_called);
        CHECK(i.admission.admission.admitted_count==1 && !empty(f.clients[0]) && empty(f.clients[1]));
        CHECK(i.admission.admission.accepted_count==i.admission.admission.admitted_count+i.admission.admission.rejected_count);
        CHECK(e.sync_result==VIREO_OK && i.round.turn_count==0);finish(&f);++groups;
    }
    fixture_t f;vireo_tcp_server_options_t base=root_options;base.connection_capacity=2;
    start(&f,&base,&tls_options,true);connect_one(&f);connect_one(&f);f.fail_mod_on=1;
    vireo_tcp_server_tls_serve_options_t o=serve_options;o.admit.max_accepts=2;
    uint8_t w[32];vireo_tcp_server_tls_turn_result_t t[1];vireo_connection_pool_lease_t l[4]={{0}};
    vireo_tcp_server_tls_serve_info_t i;vireo_tcp_server_tls_serve_error_t e;
    EXPECT(vireo_tcp_server_tls_serve_once_with_gate(f.server,&o,w,32,handler,&f,t,1,l,4,&i,&e,reject_admission_queue,&f),VIREO_RESULT_NO_MEMORY);
    CHECK(i.admission.admission.admitted_count==2 && !empty(l[0]) && !empty(l[1]));
    f.clients[0]=l[0];f.clients[1]=l[1];CHECK(i.round.turn_count==0 && i.round.remaining_count==0);
    CHECK(e.stage==VIREO_TCP_SERVER_TLS_SERVE_ADMIT && e.admission_error.stage==VIREO_TCP_SERVER_TLS_QUEUE);
    CHECK(e.sync_result==VIREO_RESULT_IO && e.sync_error.stage==VIREO_TCP_SERVER_LISTENER_UPDATE);
    CHECK(i.post_sync.sync_called && i.post_sync.listener_read_enabled && f.queue_calls==2);
    f.fail_mod_on=0;vireo_tcp_server_tls_admission_info_t a;unsigned accepts=f.calls[F_ACCEPT];
    EXPECT(vireo_tcp_server_tls_admission_refresh(f.server,&a,NULL),VIREO_OK);
    CHECK(!a.listener_read_enabled && f.calls[F_ACCEPT]==accepts);schedule(&f,1);
    vireo_tcp_server_info_t state;EXPECT(vireo_tcp_server_inspect(f.server,&state),VIREO_OK);CHECK(state.pending_clients==2);
    finish(&f);++groups;
}
static void serve_boundaries(void)
{
    fixture_t f;start(&f,&root_options,&tls_options,true);
    vireo_tcp_server_tls_turn_result_t t[4];vireo_tcp_server_tls_serve_error_t e;
    vireo_tcp_server_tls_serve_info_t i=serve(&f,&serve_options,t,4,0,VIREO_OK,&e);
    CHECK(i.pre_sync_called && i.post_sync_called && !i.admission_called && i.round.wait_called && e.stage==VIREO_TCP_SERVER_TLS_SERVE_NONE);++groups;
    /* 预同步失败：不能为形式完整立刻重复同一MOD。 */
    EXPECT(vireo_tcp_server_set_listener_read_enabled(f.server,false,NULL),VIREO_OK);
    f.fail_mod_on=f.mod_calls+1;unsigned waits=f.calls[F_WAIT];
    i=serve(&f,&serve_options,t,4,0,VIREO_RESULT_IO,&e);
    CHECK(e.stage==VIREO_TCP_SERVER_TLS_SERVE_PRE_SYNC && !i.post_sync_called && f.calls[F_WAIT]==waits);
    f.fail_mod_on=0;++groups;
    for(unsigned k=0;k<3;++k) {
        f.fault=k==0?F_INSPECT:k==1?F_NOW:F_WAIT;f.fail_on=f.calls[f.fault]+1;
        /* 空根无TLS扫描客户，INSPECT故障以接入一个客户后单独覆盖。 */
        if(k==0)continue;
        i=serve(&f,&serve_options,t,4,0,VIREO_RESULT_IO,&e);
        CHECK(e.stage==VIREO_TCP_SERVER_TLS_SERVE_ROUND && i.post_sync_called && !i.admission_called && i.round.turn_count==0);++groups;
    }
    f.fault=F_NONE;
    for(unsigned k=0;k<2;++k) {
        f.injected_listener_events=VIREO_EPOLL_EVENT_READ|(k==0?VIREO_EPOLL_EVENT_ERROR:VIREO_EPOLL_EVENT_HANGUP);
        i=serve(&f,&serve_options,t,4,0,VIREO_RESULT_IO,&e);
        CHECK(e.stage==VIREO_TCP_SERVER_TLS_SERVE_LISTENER_EVENT && !i.admission_called && i.post_sync_called);++groups;
    }
    f.injected_listener_events=0;connect_one(&f);
    f.stop_in_accept=true;i=serve(&f,&serve_options,t,4,0,VIREO_OK,&e);
    CHECK(i.admission.admission.admitted_count==1 && !i.stopped && i.post_sync_called); /* stop晚于边界，有限批次可完成。 */
    CHECK(f.native_steps==0 && i.round.turn_count==0);unsigned mod=f.mod_calls;waits=f.calls[F_WAIT];
    i=serve(&f,&serve_options,t,4,1,VIREO_OK,&e);
    CHECK(i.stopped && !i.pre_sync_called && !i.post_sync_called && f.mod_calls==mod && f.calls[F_WAIT]==waits);
    finish(&f);++groups;
    start(&f,&root_options,&tls_options,true);connect_one(&f);CHECK(admit(&f,1,VIREO_OK,NULL).admission.admitted_count==1);
    f.stop_in_wait=true;f.probe=true;i=serve(&f,&serve_options,t,4,1,VIREO_OK,&e);
    CHECK(i.stopped && i.round.stopped && i.round.turn_count==0 && i.round.remaining_count==1 && !i.admission_called && i.post_sync_called);
    finish(&f);++groups;
    start(&f,&root_options,&tls_options,true);connect_one(&f);CHECK(admit(&f,1,VIREO_OK,NULL).admission.admitted_count==1);
    f.fault=F_INSPECT;f.fail_on=f.calls[F_INSPECT]+1;i=serve(&f,&serve_options,t,4,1,VIREO_RESULT_INTERNAL,&e);
    CHECK(e.stage==VIREO_TCP_SERVER_TLS_SERVE_ROUND && i.post_sync_called && !i.round.wait_called && i.round.turn_count==0);
    finish(&f);++groups;
}
/** 客户业务首错保留suffix且不接入；停止发生在handler内同样不接入。 */
static void customer_boundaries(bool stop)
{
    fixture_t f;open_clients(&f,2);silence(&f);
    uint8_t w[32];make_frame(w,90,false);CHECK(SSL_write(f.ssl[0],w,32)==32);
    /* SSL_write成功不保证另一端此刻已读到；先有界收进真实TLS FIFO再测handler边界。 */
    bool cached=false;
    for(size_t k=0;k<256 && !cached;++k) {
        vireo_tls_io_budget_t b={4096,1};vireo_tls_io_progress_t p;
        EXPECT(vireo_tls_connection_receive(borrow(&f,0),&b,&p,NULL),VIREO_OK);
        cached=p.bytes==32;
        if(!cached) {struct pollfd fd={f.accepted_fds[0],POLLIN,0};CHECK(poll(&fd,1,1)>=0);}
    }
    CHECK(cached);
    schedule(&f,0);schedule(&f,1);connect_one(&f);f.injected_listener_events=VIREO_EPOLL_EVENT_READ;
    f.handler_fail_at=stop?0:1;f.stop_in_handler=stop;f.reenter_handler=true;
    vireo_tcp_server_tls_serve_options_t o=serve_options;o.round.round.max_clients=1;
    vireo_tcp_server_tls_turn_result_t t[2];vireo_tcp_server_tls_serve_error_t e;
    vireo_tcp_server_tls_serve_info_t i=serve(&f,&o,t,2,2,stop?VIREO_OK:VIREO_RESULT_IO,&e);
    CHECK(f.handler_calls==1 && i.round.turn_count==1 && same(t[0].client,f.clients[0]));
    CHECK(!i.admission_called && i.post_sync_called && empty(f.clients[2]));
    CHECK(i.stopped==stop && e.stage==(stop?VIREO_TCP_SERVER_TLS_SERVE_NONE:VIREO_TCP_SERVER_TLS_SERVE_ROUND));
    vireo_tcp_server_info_t si;EXPECT(vireo_tcp_server_inspect(f.server,&si),VIREO_OK);CHECK(si.pending_clients>=1);
    finish(&f);++groups;
}
/** 最终POST_SYNC为主错也保留已发布客户，单独刷新不重复接入。 */
static void post_primary(void)
{
    fixture_t f;vireo_tcp_server_options_t base=root_options;base.connection_capacity=1;
    start(&f,&base,&tls_options,true);connect_one(&f);f.fail_mod_on=1;
    vireo_tcp_server_tls_turn_result_t t[1];vireo_tcp_server_tls_serve_error_t e;
    vireo_tcp_server_tls_serve_info_t i=serve(&f,&serve_options,t,1,0,VIREO_RESULT_IO,&e);
    CHECK(e.stage==VIREO_TCP_SERVER_TLS_SERVE_POST_SYNC && e.sync_result==VIREO_OK);
    CHECK(i.admission.admission.admitted_count==1 && i.post_sync.listener_read_enabled && i.post_sync.sync_called);
    f.fail_mod_on=0;vireo_tcp_server_tls_admission_info_t a;
    EXPECT(vireo_tcp_server_tls_admission_refresh(f.server,&a,NULL),VIREO_OK);CHECK(!a.listener_read_enabled);
    finish(&f);++groups;
}
/** 过期READ仅作为提示，EAGAIN/调用预算短进度和本轮事件清零均独立验证。 */
static void admission_budgets(void)
{
    fixture_t f;start(&f,&root_options,&tls_options,true);
    f.injected_listener_events=VIREO_EPOLL_EVENT_READ;
    vireo_tcp_server_tls_turn_result_t t[1];vireo_tcp_server_tls_serve_info_t i;
    i=serve(&f,&serve_options,t,1,0,VIREO_OK,NULL);
    CHECK(i.admission_called && i.admission.admission.admitted_count==0 &&
        i.admission.admission.stop_reason==VIREO_TCP_SERVER_ADMIT_WOULD_BLOCK);++groups;
    f.injected_listener_events=0;i=serve(&f,&serve_options,t,1,0,VIREO_OK,NULL);
    CHECK(!i.admission_called && i.round.listener_events==0);++groups;
    connect_one(&f);connect_one(&f);
    vireo_tcp_server_tls_serve_options_t o=serve_options;o.admit.max_accepts=2;o.admit.max_accept_syscalls=1;
    i=serve(&f,&o,t,1,0,VIREO_OK,NULL);
    CHECK(i.admission.admission.admitted_count==1 && i.admission.admission.accept_calls==1 &&
        i.admission.admission.stop_reason==VIREO_TCP_SERVER_ADMIT_CALL_LIMIT);
    CHECK(i.round.turn_count==0 && f.native_steps==0);finish(&f);++groups;
}
/** 真实backlog/两客户TLS1.3与精确业务/关闭尾部，归还后由下一serve恢复监听。 */
static void real_service(void)
{
    fixture_t f;vireo_tcp_server_options_t base=root_options;base.connection_capacity=2;
    start(&f,&base,&tls_options,true);connect_one(&f);connect_one(&f);connect_one(&f);
    vireo_tcp_server_tls_serve_options_t o=serve_options;o.admit.max_accepts=2;o.round.timeout_ms=2;
    o.round.round.max_clients=1;
    uint8_t work[32];vireo_tcp_server_tls_turn_result_t t[1];vireo_connection_pool_lease_t l[2]={{0},{.pool_id=999}};
    vireo_tcp_server_tls_serve_info_t i;
    /* client_capacity=1与max_accepts=2：只检查/写一个元素，未用suffix保持。 */
    EXPECT(vireo_tcp_server_tls_serve_once(f.server,&o,work,32,handler,&f,t,1,l,1,&i,NULL),VIREO_OK);
    CHECK(i.admission.admission.admitted_count==1 && i.round.turn_count==0 && f.native_steps==0 && l[1].pool_id==999);
    f.clients[0]=l[0];i=serve(&f,&o,t,1,1,VIREO_OK,NULL);
    CHECK(i.admission.admission.admitted_count==1 && f.created==2 && !i.post_sync.listener_read_enabled);
    CHECK(i.round.turn_count==1 && same(t[0].client,f.clients[0]) && t[0].path==VIREO_TCP_SERVER_TLS_TURN_HANDSHAKE);
    CHECK(i.round.remaining_count==0); /* 随后接入B的Q不能篡改round报告。 */
    make_ssl(&f,0,true);make_ssl(&f,1,true);bool ready[2]={false},established[2]={false};
    f.probe=true;
    for(size_t round=0;round<1024 && (!ready[0]||!ready[1]||!established[0]||!established[1]);++round) {
        for(size_t k=0;k<2;++k)if(!ready[k])ready[k]=client_step(f.ssl[k],false);
        i=serve(&f,&o,t,1,2,VIREO_OK,NULL);
        CHECK(i.admission.admission.admitted_count==0 && !i.admission_called && f.created==2);
        if(i.round.turn_count && t[0].path==VIREO_TCP_SERVER_TLS_TURN_HANDSHAKE) {
            CHECK(!t[0].application.process_called);
            if(t[0].handshake.application_ready) {
                size_t which=same(t[0].client,f.clients[0])?0:1;established[which]=true;
            }
        }
    }
    CHECK(ready[0]&&ready[1]&&established[0]&&established[1]&&f.handler_calls==0);
    for(size_t k=0;k<2;++k)CHECK(SSL_version(f.ssl[k])==TLS1_3_VERSION && SSL_get_verify_result(f.ssl[k])==X509_V_OK);
    /* 原独立客户轮仍可调用，保持原显式语义，不新增监听同步。 */
    f.probe=false;
    unsigned mods=f.mod_calls;CHECK(run(&f,1,t,1,VIREO_OK,NULL).turn_count<=1);CHECK(f.mod_calls==mods);
    f.probe=true;
    uint8_t frames[96],expected[96],received[96];
    for(size_t k=0;k<3;++k) {make_frame(frames+32*k,(uint32_t)k+100,false);make_frame(expected+32*k,(uint32_t)k+100,true);}
    CHECK(SSL_write(f.ssl[0],frames,96)==96);size_t got=0;f.reenter_handler=true;
    for(size_t round=0;round<1024 && got<96;++round) {
        i=serve(&f,&o,t,1,2,VIREO_OK,NULL);CHECK(!i.admission_called);
        ERR_clear_error();int n=SSL_read(f.ssl[0],received+got,(int)(96-got));
        if(n>0)got+=(size_t)n;
        else {int why=SSL_get_error(f.ssl[0],n);CHECK(why==SSL_ERROR_WANT_READ||why==SSL_ERROR_WANT_WRITE);}
        if(got<96) {struct pollfd p={f.peers[0],POLLIN,0};CHECK(poll(&p,1,1)>=0);}
    }
    CHECK(got==96 && memcmp(received,expected,96)==0 && f.handler_calls==3);
    uint8_t tail[7]={1,0,2,3,0,4,5};CHECK(SSL_write(f.ssl[0],tail,7)==7);
    request_close_client(&f,0,UINT64_C(5000000000));bool complete=false,peer_closed=false;
    for(size_t round=0;round<1024 && (!complete||!peer_closed);++round) {
        if(!peer_closed) {
            ERR_clear_error();int n=SSL_shutdown(f.ssl[0]);
            if(n==1)peer_closed=true;
            else if(n<0) {int why=SSL_get_error(f.ssl[0],n);CHECK(why==SSL_ERROR_WANT_READ||why==SSL_ERROR_WANT_WRITE);}
        }
        i=serve(&f,&o,t,1,2,VIREO_OK,NULL);
        if(i.round.turn_count && same(t[0].client,f.clients[0])) {
            CHECK(t[0].path==VIREO_TCP_SERVER_TLS_TURN_CLOSE);
            complete=t[0].close.sync.close.state==VIREO_TLS_CLOSE_COMPLETE;
        }
        CHECK(!i.admission_called && !i.post_sync.listener_read_enabled);
    }
    CHECK(complete && peer_closed && f.created==2 && f.handler_calls==3 && fcntl(f.accepted_fds[0],F_GETFD)>=0);
    vireo_tcp_server_tls_admission_info_t a;EXPECT(vireo_tcp_server_tls_admission_refresh(f.server,&a,NULL),VIREO_OK);
    CHECK(a.connection_limited && !a.listener_read_enabled && !a.sync_called);
    uint8_t const *bytes=NULL;size_t count=0;
    EXPECT(vireo_tls_connection_read_peek(borrow(&f,0),&bytes,&count,NULL),VIREO_OK);
    CHECK(count==7 && memcmp(bytes,tail,7)==0);EXPECT(vireo_tls_connection_read_consume(borrow(&f,0),count,NULL),VIREO_OK);
    EXPECT(vireo_tcp_server_release_client(f.server,&f.clients[0],NULL),VIREO_OK);
    CHECK(fcntl(f.accepted_fds[0],F_GETFD)==-1 && errno==EBADF);
    unsigned natives=f.native_steps;i=serve(&f,&o,t,1,2,VIREO_OK,NULL);
    CHECK(i.pre_sync.sync_called && i.pre_sync.listener_read_enabled && i.admission.admission.admitted_count==1);
    CHECK(!i.post_sync.listener_read_enabled && f.created==3 && f.native_steps==natives);
    vireo_tls_connection_info_t state;EXPECT(vireo_tls_connection_inspect(borrow(&f,2),&state,NULL),VIREO_OK);
    CHECK(state.handshake_state==VIREO_TLS_HANDSHAKE_INITIAL); /* C只在下一轮开始TLS。 */
    make_ssl(&f,2,true);bool third_ready=false,third_established=false;
    for(size_t round=0;round<1024 && (!third_ready||!third_established);++round) {
        if(!third_ready)third_ready=client_step(f.ssl[2],false);
        i=serve(&f,&o,t,1,0,VIREO_OK,NULL);
        if(i.round.turn_count && same(t[0].client,f.clients[2]) && t[0].path==VIREO_TCP_SERVER_TLS_TURN_HANDSHAKE)
            third_established=t[0].handshake.application_ready;
    }
    CHECK(third_ready && third_established && f.handler_calls==3);finish(&f);++groups;
}
int main(void)
{
    struct sigaction action={0};action.sa_handler=SIG_IGN;CHECK(sigemptyset(&action.sa_mask)==0);
    CHECK(sigaction(SIGPIPE,&action,NULL)==0);size_t before=fd_count();
    inputs();capacities();refresh_faults();admission_errors();serve_boundaries();
    customer_boundaries(false);customer_boundaries(true);post_primary();admission_budgets();real_service();
    size_t after=fd_count();CHECK(before==after);
    printf("test_tcp_server_tls_serve: %u groups passed; fd %zu -> %zu; three capacities, bounded accept/round, stop/reentry, owner prefixes and primary/secondary errors, real trusted TLS1.3/backlog/96 response bytes/retained tail\n",groups,before,after);
    return 0;
}
