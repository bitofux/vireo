/*
- PROJECT : VIREO
- FILE    : test_tcp_server_tls.c
- AUTHOR  : bitofux
- DATE    : 2026-10-17
- BRIEF   : 此模块负责：
- -- 本server自有故障边界及公开真实TCP/TLS准入/期限/同租约业务验证
 */
#define _GNU_SOURCE
#include "net/tcp_server_internal.h"
#include "tls_context_fixtures.h"
#include <vireo/protocol/codec.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
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
    F_PREPARE,F_ARM,F_ADOPT,F_LOOKUP,F_ATTACH,F_MOD,F_DETACH,F_WAIT,F_INSPECT,F_DEADLINE,F_MAX };
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
BRIDGE(consume,(void *ctx,vireo_connection_t *c,size_t n),vireo_connection_read_consume(c,n))
BRIDGE(enqueue,(void *ctx,vireo_connection_t *c,uint8_t const *p,size_t n,vireo_connection_error_t *e),
    vireo_connection_write_enqueue(c,p,n,e))
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
BRIDGE(application_inspect,(void *ctx,vireo_tls_connection_t const *t,vireo_tls_io_info_t *i,
    vireo_tls_connection_error_t *e),vireo_tls_connection_io_inspect(t,i,e))
BRIDGE(application_flow,(void *ctx,vireo_tls_connection_t *t,vireo_tls_io_flow_t *i,
    vireo_tls_connection_error_t *e),vireo_tls_connection_flow_refresh(t,i,e))
BRIDGE(application_receive,(void *ctx,vireo_tls_connection_t *t,vireo_tls_io_budget_t const *b,
    vireo_tls_io_progress_t *i,vireo_tls_connection_error_t *e),vireo_tls_connection_receive(t,b,i,e))
BRIDGE(application_send,(void *ctx,vireo_tls_connection_t *t,vireo_tls_io_budget_t const *b,
    vireo_tls_io_progress_t *i,vireo_tls_connection_error_t *e),vireo_tls_connection_send(t,b,i,e))
BRIDGE(application_close_inspect,(void *ctx,vireo_tls_connection_t const *t,vireo_tls_close_info_t *i,
    vireo_tls_connection_error_t *e),vireo_tls_connection_close_inspect(t,i,e))
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
{ return (vireo_tcp_server_tls_ops_t){.context=f,.now=now,.create=create_tls,.prepare=prepare,
    .arm=arm,.inspect=inspect_tls,.deadline=deadline,.step=step,.io_inspect=application_inspect,
    .flow_refresh=application_flow,.receive=application_receive,.send=application_send,
    .close_inspect=application_close_inspect,.close_request=close_request_bridge,.close_step_at=close_step_bridge}; }
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

static void construction(void)
{
    enum fault const points[]={F_ALLOC,F_LOOP,F_LOOP_INSPECT,F_POOL,F_POOL_INSPECT};
    vireo_result_t const results[]={VIREO_RESULT_NO_MEMORY,VIREO_RESULT_IO,VIREO_RESULT_INTERNAL,
        VIREO_RESULT_NO_MEMORY,VIREO_RESULT_INTERNAL};
    for(size_t k=0;k<sizeof(points)/sizeof(points[0]);++k) {
        fixture_t f={.fault=points[k],.fail_on=1}; vireo_tcp_server_ops_t b=base_ops(&f);
        vireo_tls_context_t *c=make_context(),*original=c; vireo_tcp_server_t *s=NULL;
        vireo_tcp_server_tls_error_t e;
        EXPECT(vireo_tcp_server_create_tls_with_ops(&root_options,&tls_options,&c,&b,NULL,NULL,NULL,&s,&e),results[k]);
        CHECK(c==original && s==NULL && f.allocations==0 && e.stage==VIREO_TCP_SERVER_TLS_CREATE_SERVER);
        EXPECT(vireo_tls_context_destroy(&c,NULL),VIREO_OK);
    }
    vireo_tls_context_t *c=make_context(); vireo_tls_context_info_t ci;
    EXPECT(vireo_tls_context_inspect(c,&ci,NULL),VIREO_OK);
    fixture_t f; start(&f,&root_options,&tls_options,false); vireo_tcp_server_info_t base;
    EXPECT(vireo_tcp_server_inspect(f.server,&base),VIREO_OK);
    vireo_tcp_server_tls_info_t ti; EXPECT(vireo_tcp_server_tls_inspect(f.server,&ti,NULL),VIREO_OK);
    CHECK(ti.context_wrapper_bytes==ci.wrapper_bytes && ti.resource_bytes==0);
    CHECK(base.allocation_bytes==base.server_allocation_bytes+base.loop_allocation_bytes+
        base.pool_allocation_bytes+base.listener_allocation_bytes+ci.wrapper_bytes);
    CHECK(base.max_memory_bytes==root_options.max_memory_bytes);
    finish(&f);
    vireo_tcp_server_options_t tiny=root_options; tiny.max_memory_bytes=ci.wrapper_bytes;
    vireo_tcp_server_t *s=NULL; vireo_tls_context_t *original=c;
    EXPECT(vireo_tcp_server_create_tls(&tiny,&tls_options,&c,&s,NULL),VIREO_RESULT_RANGE);
    CHECK(c==original && s==NULL); EXPECT(vireo_tls_context_destroy(&c,NULL),VIREO_OK);
    ++groups;
}
static void invalid_options(void)
{
    vireo_tls_context_t *c=make_context(),*original=c; vireo_tcp_server_t *s=NULL;
    for(unsigned k=0;k<13;++k) {
        vireo_tcp_server_tls_options_t o=tls_options;
        vireo_result_t result=VIREO_RESULT_RANGE;
        switch(k) {
        case 0:o.handshake_timeout_ns=0;result=VIREO_RESULT_INVALID_ARGUMENT;break;
        case 1:o.max_wrapper_bytes=SIZE_MAX;break;
        case 2:o.max_tls_resource_bytes=40959;break;
        case 3:o.io.max_buffer_bytes=40959;break;
        case 4:o.io.max_read_unit_bytes=31;break;
        case 5:o.io.read_low=126;break;
        case 6:o.io.write_high=4097;break;
        case 7:o.io.read_capacity=SIZE_MAX;result=VIREO_RESULT_OVERFLOW;break;
        case 8:o.io.read_capacity=31;break;
        case 9:o.max_tls_resource_bytes=VIREO_TLS_IO_MAX_BUFFER_BYTES+1;break;
        case 10:o.io.read_capacity=0;break;
        case 11:o.io.write_low=o.io.write_high;break;
        default:o.max_wrapper_bytes=0;result=VIREO_RESULT_INVALID_ARGUMENT;break;
        }
        EXPECT(vireo_tcp_server_create_tls(&root_options,&o,&c,&s,NULL),result); CHECK(c==original && s==NULL);
    }
    EXPECT(vireo_tcp_server_create_tls(&root_options,&tls_options,NULL,&s,NULL),VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_tls_context_destroy(&c,NULL),VIREO_OK);
    EXPECT(vireo_tcp_server_create(&root_options,&s,NULL),VIREO_OK);
    vireo_tcp_server_tls_info_t info; memset(&info,0x5a,sizeof(info));
    vireo_tcp_server_tls_info_t before=info;
    EXPECT(vireo_tcp_server_tls_inspect(s,&info,NULL),VIREO_RESULT_BUSY); CHECK(memcmp(&info,&before,sizeof(info))==0);
    vireo_tcp_server_ready_client_t ready; vireo_tcp_server_tls_poll_report_t p;
    EXPECT(vireo_tcp_server_tls_poll_ready_once(s,0,1,&ready,1,&p,NULL),VIREO_RESULT_BUSY);
    CHECK(!p.poll.wait_called && p.poll.selected_count==0);
    EXPECT(vireo_tcp_server_destroy(&s,NULL),VIREO_OK); ++groups;
}
static void admission_failures(void)
{
    enum fault const points[]={F_ACCEPT,F_NOW,F_CREATE,F_PREPARE,F_ARM,F_ADOPT,F_LOOKUP,F_ATTACH};
    vireo_result_t const results[]={VIREO_RESULT_IO,VIREO_RESULT_IO,VIREO_RESULT_NO_MEMORY,
        VIREO_RESULT_NO_MEMORY,VIREO_RESULT_INTERNAL,VIREO_RESULT_NO_MEMORY,VIREO_RESULT_INTERNAL,VIREO_RESULT_IO};
    for(size_t k=0;k<sizeof(points)/sizeof(points[0]);++k) {
        fixture_t f; start(&f,&root_options,&tls_options,true); connect_one(&f);
        f.fault=points[k]; f.fail_on=1; memset(f.calls,0,sizeof(f.calls));
        vireo_tcp_server_tls_error_t e; vireo_tcp_server_tls_admit_info_t p=admit(&f,1,results[k],&e);
        CHECK(p.admission.admitted_count==0 && empty(f.clients[0]));
        CHECK(p.admission.accepted_count==(points[k]==F_ACCEPT?0U:1U));
        CHECK(p.admission.rejected_count==p.admission.accepted_count && e.stage!=VIREO_TCP_SERVER_TLS_NONE);
        f.fault=F_NONE; vireo_tcp_server_info_t info; EXPECT(vireo_tcp_server_inspect(f.server,&info),VIREO_OK);
        CHECK(info.connection_count==0 && info.buffer_capacity_bytes==0 && info.pending_clients==0);
        for(size_t j=0;j<f.created;++j) CHECK(fcntl(f.accepted_fds[j],F_GETFD)==-1 && errno==EBADF);
        finish(&f);
    }
    ++groups;
}
static void partial_prefix(void)
{
    fixture_t f; start(&f,&root_options,&tls_options,true); connect_one(&f); connect_one(&f);
    f.fault=F_PREPARE; f.fail_on=2;
    vireo_tcp_server_tls_error_t e; vireo_tcp_server_tls_admit_info_t p=admit(&f,2,VIREO_RESULT_NO_MEMORY,&e);
    CHECK(p.admission.accepted_count==2 && p.admission.admitted_count==1 && p.admission.rejected_count==1);
    CHECK(!empty(f.clients[0]) && empty(f.clients[1]) && e.stage==VIREO_TCP_SERVER_TLS_PREPARE);
    CHECK(fcntl(f.accepted_fds[0],F_GETFD)>=0 && fcntl(f.accepted_fds[1],F_GETFD)==-1 && errno==EBADF);
    vireo_tcp_server_tls_info_t info; EXPECT(vireo_tcp_server_tls_inspect(f.server,&info,NULL),VIREO_OK);
    CHECK(info.resource_bytes==40960); finish(&f); ++groups;
}
/** 清理IO必须真实消费，主attach失败仍保持第一阶段，不伪造close(EINTR)。 */
static void cleanup_secondary(void)
{
    fixture_t f; start(&f,&root_options,&tls_options,true); connect_one(&f);
    f.fault=F_ATTACH; f.consume_release_io=true;
    vireo_tcp_server_tls_error_t e;
    vireo_tcp_server_tls_admit_info_t p=admit(&f,1,VIREO_RESULT_IO,&e);
    CHECK(p.admission.rejected_count==1 && e.stage==VIREO_TCP_SERVER_TLS_ATTACH);
    CHECK(e.client_error.cleanup_result==VIREO_RESULT_IO && empty(f.clients[0]));
    CHECK(fcntl(f.accepted_fds[0],F_GETFD)==-1 && errno==EBADF);
    finish(&f); ++groups;
}

static void resource_limits(void)
{
    for(unsigned k=0;k<3;++k) {
        fixture_t f; vireo_tcp_server_options_t base=root_options; vireo_tcp_server_tls_options_t o=tls_options;
        if(k==0)o.max_tls_resource_bytes=40960;
        else if(k==1)base.max_buffer_bytes=8192;
        else base.connection_capacity=1;
        start(&f,&base,&o,true); connect_one(&f); connect_one(&f);
        vireo_tcp_server_tls_admit_info_t p=admit(&f,2,VIREO_OK,NULL);
        CHECK(p.admission.accepted_count==1 && p.admission.admitted_count==1 && f.calls[F_ACCEPT]==1);
        CHECK(p.tls_resource_limited==(k==0));
        CHECK(p.admission.stop_reason==(k==2?VIREO_TCP_SERVER_ADMIT_CONNECTION_LIMIT:VIREO_TCP_SERVER_ADMIT_BUFFER_LIMIT));
        EXPECT(vireo_tcp_server_set_listener_read_enabled(f.server,false,NULL),VIREO_OK);
        vireo_connection_pool_lease_t old=f.clients[0]; int fd=f.accepted_fds[0];
        EXPECT(vireo_tcp_server_release_client(f.server,&f.clients[0],NULL),VIREO_OK);
        CHECK(fcntl(fd,F_GETFD)==-1 && errno==EBADF);
        EXPECT(vireo_tcp_server_set_listener_read_enabled(f.server,true,NULL),VIREO_OK);
        p=admit(&f,1,VIREO_OK,NULL); CHECK(p.admission.admitted_count==1 && !same(old,f.clients[0]));
        vireo_tls_connection_t *t=NULL;
        EXPECT(vireo_tcp_server_client_tls_borrow(f.server,old,&t,NULL),VIREO_RESULT_NOT_FOUND);
        finish(&f);
    }
    ++groups;
}
static void overflow_and_clock(void)
{
    fixture_t f; start(&f,&root_options,&tls_options,true); connect_one(&f);
    f.fake_clock=true; f.now=UINT64_MAX-1; vireo_tcp_server_tls_error_t e;
    vireo_tcp_server_tls_admit_info_t p=admit(&f,1,VIREO_RESULT_OVERFLOW,&e);
    CHECK(p.admission.accepted_count==1 && p.admission.rejected_count==1 && f.created==0);
    CHECK(e.stage==VIREO_TCP_SERVER_TLS_DEADLINE); finish(&f); ++groups;
}
static void no_event_deadline(void)
{
    fixture_t f; start(&f,&root_options,&tls_options,true); f.fake_clock=true; f.model_wait=true;
    connect_one(&f); CHECK(admit(&f,1,VIREO_OK,NULL).admission.admitted_count==1);
    vireo_tcp_server_ready_client_t ready[4]; vireo_tcp_server_tls_poll_report_t p;
    f.probe=true;
    EXPECT(vireo_tcp_server_tls_poll_ready_once(f.server,30000,4,ready,4,&p,NULL),VIREO_OK);
    CHECK(p.poll.selected_count==1 && p.poll.effective_timeout_ms==0 && ready[0].events==0 && p.scanned_slots==8);
    vireo_tcp_server_tls_handshake_info_t h;
    EXPECT(vireo_tcp_server_client_tls_handshake_step(f.server,ready[0].client,&h,NULL),VIREO_OK);
    CHECK(h.handshake.wait==VIREO_TLS_HANDSHAKE_WAIT_READ && h.handshake.native_called && !h.sync_called);
    f.advance_ns=UINT64_C(5000000000); f.notify_in_wait=false;
    EXPECT(vireo_tcp_server_tls_poll_ready_once(f.server,30000,4,ready,4,&p,NULL),VIREO_OK);
    CHECK(f.waited_ms==5000 && p.expired_clients==1 && p.poll.selected_count==1 && ready[0].events==0);
    CHECK(p.poll.wait.ready_count==0 && p.after_wait_ns==p.nearest_deadline_ns);
    vireo_tcp_server_tls_error_t e;
    EXPECT(vireo_tcp_server_client_tls_handshake_step(f.server,ready[0].client,&h,&e),VIREO_RESULT_TIMEOUT);
    CHECK(!h.handshake.native_called && h.handshake.state==VIREO_TLS_HANDSHAKE_FAILED && h.sync_called && h.interests==0);
    vireo_tcp_server_tls_info_t resources; EXPECT(vireo_tcp_server_tls_inspect(f.server,&resources,NULL),VIREO_OK);
    CHECK(resources.resource_bytes==40960);
    unsigned calls=f.native_steps;
    EXPECT(vireo_tcp_server_client_tls_handshake_step(f.server,f.clients[0],&h,&e),VIREO_RESULT_TIMEOUT);
    CHECK(!h.handshake.native_called && !h.sync_called && f.native_steps==calls);
    f.advance_ns=0;
    EXPECT(vireo_tcp_server_tls_poll_ready_once(f.server,17,4,ready,4,&p,NULL),VIREO_OK);
    CHECK(!p.has_deadline && f.waited_ms==17 && p.poll.selected_count==0);
    finish(&f); ++groups;
}
static void fifo_deadline_and_ceil(void)
{
    fixture_t f; start(&f,&root_options,&tls_options,true); f.fake_clock=true; f.model_wait=true;
    for(unsigned k=0;k<3;++k)connect_one(&f);
    CHECK(admit(&f,3,VIREO_OK,NULL).admission.admitted_count==3);
    vireo_tcp_server_ready_client_t ready[4]; vireo_tcp_server_tls_poll_report_t p;
    EXPECT(vireo_tcp_server_tls_poll_ready_once(f.server,30000,1,ready,4,&p,NULL),VIREO_OK);
    CHECK(p.poll.selected_count==1 && same(ready[0].client,f.clients[0]) && p.poll.remaining_count==2);
    f.now+=UINT64_C(5000000000); f.notify_in_wait=true;
    EXPECT(vireo_tcp_server_tls_poll_ready_once(f.server,30000,4,ready,4,&p,NULL),VIREO_OK);
    CHECK(p.poll.selected_count==3 && p.expired_clients==3 && p.scanned_slots==8);
    CHECK(same(ready[0].client,f.clients[1]) && same(ready[1].client,f.clients[2]) && same(ready[2].client,f.clients[0]));
    CHECK((ready[2].events&VIREO_EPOLL_EVENT_READ)!=0);
    finish(&f);
    start(&f,&root_options,&tls_options,true); f.fake_clock=true; f.model_wait=true; connect_one(&f);
    (void)admit(&f,1,VIREO_OK,NULL);
    EXPECT(vireo_tcp_server_tls_poll_ready_once(f.server,0,1,ready,1,&p,NULL),VIREO_OK);
    f.now+=UINT64_C(4999999999); /* due-1ns，需要ceil为1ms，而不是无限等待或截成0。 */
    EXPECT(vireo_tcp_server_tls_poll_ready_once(f.server,30000,1,ready,1,&p,NULL),VIREO_OK);
    CHECK(f.waited_ms==1 && p.expired_clients==0 && p.poll.selected_count==0);
    f.now+=1;
    EXPECT(vireo_tcp_server_tls_poll_ready_once(f.server,30000,1,ready,1,&p,NULL),VIREO_OK);
    CHECK(f.waited_ms==0 && p.expired_clients==1 && p.poll.selected_count==1);
    finish(&f); ++groups;
}
static void poll_failures(void)
{
    enum fault const points[]={F_INSPECT,F_DEADLINE,F_NOW,F_WAIT};
    for(size_t k=0;k<4;++k) {
        fixture_t f; start(&f,&root_options,&tls_options,true); f.fake_clock=true; f.model_wait=true;
        connect_one(&f); (void)admit(&f,1,VIREO_OK,NULL); memset(f.calls,0,sizeof(f.calls));
        f.fault=points[k]; f.fail_on=(points[k]==F_DEADLINE || points[k]==F_NOW)?2U:1U;
        vireo_tcp_server_ready_client_t ready; memset(&ready,0x5a,sizeof(ready));
        vireo_tcp_server_ready_client_t before=ready;
        vireo_tcp_server_tls_poll_report_t p; vireo_tcp_server_tls_error_t e;
        vireo_result_t result=(points[k]==F_INSPECT || points[k]==F_DEADLINE)?VIREO_RESULT_INTERNAL:VIREO_RESULT_IO;
        EXPECT(vireo_tcp_server_tls_poll_ready_once(f.server,30,1,&ready,1,&p,&e),result);
        CHECK(p.poll.selected_count==0 && p.poll.remaining_count==1 && memcmp(&ready,&before,sizeof(ready))==0);
        CHECK(p.poll.wait_called==(points[k]!=F_INSPECT));
        if(points[k]==F_NOW || points[k]==F_DEADLINE)CHECK(p.poll.queued_after_wait==1);
        f.fault=F_NONE;
        EXPECT(vireo_tcp_server_tls_poll_ready_once(f.server,0,1,&ready,1,&p,NULL),VIREO_OK);
        CHECK(p.poll.selected_count==1 && same(ready.client,f.clients[0])); finish(&f);
    }
    ++groups;
}
/** 后扫描前缀已入队后依赖拒绝，不能回滚该客户或偷取未披露租约。 */
static void partial_due_scan_failure(void)
{
    fixture_t f; start(&f,&root_options,&tls_options,true); f.fake_clock=true; f.model_wait=true;
    for(unsigned k=0;k<3;++k)connect_one(&f);
    (void)admit(&f,3,VIREO_OK,NULL);
    vireo_tcp_server_ready_client_t ready[4]; vireo_tcp_server_tls_poll_report_t p;
    EXPECT(vireo_tcp_server_tls_poll_ready_once(f.server,0,4,ready,4,&p,NULL),VIREO_OK);
    CHECK(p.poll.selected_count==3);
    f.now+=UINT64_C(5000000000); memset(f.calls,0,sizeof(f.calls));
    f.fault=F_DEADLINE; f.fail_on=5;
    vireo_tcp_server_tls_error_t e;
    EXPECT(vireo_tcp_server_tls_poll_ready_once(f.server,30000,4,ready,4,&p,&e),VIREO_RESULT_INTERNAL);
    CHECK(e.stage==VIREO_TCP_SERVER_TLS_SCAN_AFTER && p.poll.wait_called && p.poll.selected_count==0);
    CHECK(p.expired_clients==1 && p.poll.remaining_count==1 && p.poll.queued_after_wait==1 && p.scanned_slots==6);
    f.fault=F_NONE;
    EXPECT(vireo_tcp_server_tls_poll_ready_once(f.server,30000,4,ready,4,&p,NULL),VIREO_OK);
    CHECK(p.poll.selected_count==3 && same(ready[0].client,f.clients[0]));
    finish(&f); ++groups;
}

static void mod_recovery_and_release(void)
{
    fixture_t f; start(&f,&root_options,&tls_options,true); f.fake_clock=true; f.model_wait=true;
    connect_one(&f); (void)admit(&f,1,VIREO_OK,NULL);
    vireo_tcp_server_ready_client_t ready; vireo_tcp_server_tls_poll_report_t p;
    EXPECT(vireo_tcp_server_tls_poll_ready_once(f.server,0,1,&ready,1,&p,NULL),VIREO_OK);
    f.now+=UINT64_C(5000000000); f.fault=F_MOD; f.fail_on=1;
    vireo_tcp_server_tls_handshake_info_t h; vireo_tcp_server_tls_error_t e;
    EXPECT(vireo_tcp_server_client_tls_handshake_step(f.server,f.clients[0],&h,&e),VIREO_RESULT_TIMEOUT);
    CHECK(h.handshake.state==VIREO_TLS_HANDSHAKE_FAILED && !h.handshake.native_called && h.retry_pending);
    CHECK(e.stage==VIREO_TCP_SERVER_TLS_HANDSHAKE && e.sync_result==VIREO_RESULT_IO && e.queue_result==VIREO_OK);
    CHECK(h.interests==(VIREO_EPOLL_INTEREST_READ|VIREO_EPOLL_INTEREST_PEER_WRITE_CLOSED));
    EXPECT(vireo_tcp_server_tls_poll_ready_once(f.server,30000,1,&ready,1,&p,NULL),VIREO_OK);
    CHECK(p.poll.selected_count==1 && !p.has_deadline && p.poll.effective_timeout_ms==0);
    f.fault=F_NONE;
    EXPECT(vireo_tcp_server_client_tls_handshake_step(f.server,ready.client,&h,&e),VIREO_RESULT_TIMEOUT);
    CHECK(!h.handshake.native_called && h.interests==0 && e.sync_result==VIREO_OK);
    f.fault=F_DETACH; f.fail_on=1; vireo_connection_pool_lease_t old=f.clients[0];
    EXPECT(vireo_tcp_server_release_client(f.server,&f.clients[0],NULL),VIREO_RESULT_IO);
    CHECK(same(old,f.clients[0]));
    vireo_tcp_server_tls_info_t resources; EXPECT(vireo_tcp_server_tls_inspect(f.server,&resources,NULL),VIREO_OK);
    CHECK(resources.resource_bytes==40960 && fcntl(f.accepted_fds[0],F_GETFD)>=0);
    finish(&f); ++groups;
}

/** 两方向为本server依赖输出模型；真实WANT_WRITE不在此用例制造。 */
static void want_direction_model(void)
{
    fixture_t f; start(&f,&root_options,&tls_options,true); f.fake_clock=true; f.model_wait=true;
    connect_one(&f); (void)admit(&f,1,VIREO_OK,NULL);
    vireo_tcp_server_ready_client_t ready; vireo_tcp_server_tls_poll_report_t p;
    EXPECT(vireo_tcp_server_tls_poll_ready_once(f.server,0,1,&ready,1,&p,NULL),VIREO_OK);
    f.model_step_wait=VIREO_TLS_HANDSHAKE_WAIT_WRITE;
    vireo_tcp_server_tls_handshake_info_t h;
    EXPECT(vireo_tcp_server_client_tls_handshake_step(f.server,f.clients[0],&h,NULL),VIREO_OK);
    CHECK(h.handshake_reported && h.sync_called && !h.retry_pending && !h.application_ready);
    CHECK(h.interests==(VIREO_EPOLL_INTEREST_WRITE|VIREO_EPOLL_INTEREST_PEER_WRITE_CLOSED));
    vireo_tcp_server_info_t base; EXPECT(vireo_tcp_server_inspect(f.server,&base),VIREO_OK);
    CHECK(base.pending_clients==0 && f.native_steps==0);
    f.model_step_wait=VIREO_TLS_HANDSHAKE_WAIT_READ;
    EXPECT(vireo_tcp_server_client_tls_handshake_step(f.server,f.clients[0],&h,NULL),VIREO_OK);
    CHECK(h.sync_called && h.interests==(VIREO_EPOLL_INTEREST_READ|VIREO_EPOLL_INTEREST_PEER_WRITE_CLOSED));
    f.fault=F_NOW; f.fail_on=f.calls[F_NOW]+1;
    EXPECT(vireo_tcp_server_client_tls_handshake_step(f.server,f.clients[0],&h,NULL),VIREO_RESULT_IO);
    CHECK(!h.sampled && !h.step_called && !h.handshake_reported && !h.sync_called);
    finish(&f); ++groups;
}

static vireo_result_t unused_handler(vireo_connection_frame_view_t const *v,uint8_t *p,size_t n,
    vireo_tcp_server_reply_t *r,void *ctx)
{ (void)v;(void)p;(void)n;(void)r;(void)ctx; CHECK(false); return VIREO_RESULT_INTERNAL; }
static void unused_round(vireo_tcp_server_t *s,vireo_result_t r,vireo_tcp_server_serve_info_t const *i,
    vireo_tcp_server_turn_result_t const *t,vireo_connection_pool_lease_t const *l,
    vireo_tcp_server_serve_error_t const *e,void *ctx)
{ (void)s;(void)r;(void)i;(void)t;(void)l;(void)e;(void)ctx; CHECK(false); }
static void raw_gates(void)
{
    fixture_t f; start(&f,&root_options,&tls_options,true); connect_one(&f); (void)admit(&f,1,VIREO_OK,NULL);
    vireo_connection_options_t c={128,128,256}; vireo_tcp_server_admit_budget_t b={1,1};
    vireo_connection_pool_lease_t lease={0}; vireo_tcp_server_admit_info_t i;
    EXPECT(vireo_tcp_server_admit_batch(f.server,&c,&b,&lease,1,&i,NULL),VIREO_RESULT_BUSY);
    vireo_tcp_server_admission_options_t a={0};
    EXPECT(vireo_tcp_server_admission_configure(f.server,&a,NULL),VIREO_RESULT_BUSY);
    EXPECT(vireo_tcp_server_admission_refresh(f.server,NULL),VIREO_RESULT_BUSY);
    EXPECT(vireo_tcp_server_admission_disable(f.server,NULL),VIREO_RESULT_BUSY);
    EXPECT(vireo_tcp_server_set_auto_close_policy(f.server,true,NULL),VIREO_RESULT_BUSY);
    vireo_tcp_server_ready_client_t ready; vireo_tcp_server_poll_report_t poll_report;
    EXPECT(vireo_tcp_server_poll_ready_once(f.server,0,1,&ready,1,&poll_report),VIREO_RESULT_BUSY);
    CHECK(!poll_report.wait_called && poll_report.selected_count==0);
    vireo_tcp_server_listener_poll_report_t lp;
    EXPECT(vireo_tcp_server_poll_with_listener_once(f.server,0,1,&ready,1,&lp),VIREO_RESULT_BUSY);
    vireo_tcp_server_process_options_t process={128,128}; vireo_tcp_server_drive_budget_t drive={0};
    vireo_tcp_server_drive_info_t di; uint8_t workspace[128];
    EXPECT(vireo_tcp_server_client_drive(f.server,f.clients[0],&process,&drive,workspace,sizeof(workspace),
        unused_handler,NULL,&di,NULL),VIREO_RESULT_BUSY);
    vireo_tcp_server_round_budget_t rb={1}; vireo_tcp_server_turn_result_t turn; vireo_tcp_server_round_info_t ri;
    EXPECT(vireo_tcp_server_run_once(f.server,0,&process,&drive,&rb,workspace,sizeof(workspace),
        unused_handler,NULL,&turn,1,&ri,NULL),VIREO_RESULT_BUSY);
    vireo_tcp_server_serve_options_t so={0}; vireo_tcp_server_serve_info_t si;
    EXPECT(vireo_tcp_server_serve_once(f.server,&so,workspace,sizeof(workspace),unused_handler,NULL,
        &turn,1,&lease,1,&si,NULL),VIREO_RESULT_BUSY);
    vireo_tcp_server_run_options_t ro={0};
    EXPECT(vireo_tcp_server_run(f.server,&ro,workspace,sizeof(workspace),unused_handler,NULL,&turn,1,
        &lease,1,unused_round,NULL,NULL),VIREO_RESULT_BUSY);
    vireo_tcp_server_close_batch_budget_t cb={1}; vireo_tcp_server_close_batch_result_t cr;
    vireo_tcp_server_close_batch_info_t ci;
    EXPECT(vireo_tcp_server_close_batch(f.server,VIREO_CONNECTION_CLOSE_MODE_IMMEDIATE,&cb,&cr,1,&ci,NULL),VIREO_RESULT_BUSY);
    CHECK(f.calls[F_ACCEPT]==1 && f.calls[F_WAIT]==0 && f.native_steps==0);
    vireo_tcp_server_client_info_t before; EXPECT(vireo_tcp_server_client_inspect(f.server,f.clients[0],&before),VIREO_OK);
    CHECK(before.queued); finish(&f); ++groups;
}
static void make_frame(uint8_t out[32],uint32_t sequence,bool response)
{
    vireo_protocol_header_t h={0}; h.command=VIREO_COMMAND_PING; h.sequence=sequence;
    if(response)h.flags=VIREO_PROTOCOL_FLAG_RESPONSE;
    EXPECT(vireo_protocol_header_encode(&h,out,32),VIREO_OK);
    EXPECT(vireo_protocol_frame_crc32c_calculate(out,32,NULL,0,&h.crc32c),VIREO_OK);
    EXPECT(vireo_protocol_header_encode(&h,out,32),VIREO_OK);
}
static void real_multi_ping(void)
{
    fixture_t f; start(&f,&root_options,&tls_options,false);
    for(size_t k=0;k<2;++k) { connect_one(&f); make_ssl(&f,k,true); }
    CHECK(admit(&f,2,VIREO_OK,NULL).admission.admitted_count==2);
    vireo_connection_pool_lease_t original[2]={f.clients[0],f.clients[1]};
    establish(&f,2);
    for(size_t k=0;k<2;++k) {
        CHECK(same(original[k],f.clients[k])); vireo_tls_connection_t *t=borrow(&f,k);
        vireo_tls_io_info_t io; EXPECT(vireo_tls_connection_io_inspect(t,&io,NULL),VIREO_OK);
        CHECK(io.state==VIREO_TLS_IO_OPEN && io.read_buffer.capacity==4096 && io.write_buffer.capacity==4096);
        uint8_t request[32],response[32],received[32]; make_frame(request,(uint32_t)(73+k),false);
        make_frame(response,(uint32_t)(73+k),true);
        size_t written=0; ERR_clear_error(); CHECK(SSL_write_ex(f.ssl[k],request,sizeof(request),&written)==1 && written==32);
        vireo_tls_io_budget_t budget={4096,8}; vireo_tls_io_progress_t progress={0};
        vireo_connection_frame_options_t options={VIREO_CONNECTION_FRAME_REQUEST,128};
        vireo_connection_frame_budget_t fb={1,128}; vireo_connection_frame_view_t view;
        vireo_connection_frame_info_t fi;
        for(unsigned r=0;r<128;++r) {
            vireo_tcp_server_ready_client_t ready[4]; vireo_tcp_server_tls_poll_report_t waiting;
            EXPECT(vireo_tcp_server_tls_poll_ready_once(f.server,10,4,ready,4,&waiting,NULL),VIREO_OK);
            EXPECT(vireo_tls_connection_receive(t,&budget,&progress,NULL),VIREO_OK);
            EXPECT(vireo_tcp_server_client_frames_peek(f.server,f.clients[k],&options,&fb,&view,1,&fi,NULL),VIREO_OK);
            if(fi.frame_count==1)break;
        }
        CHECK(fi.frame_count==1 && view.header.command==VIREO_COMMAND_PING && view.header.sequence==(uint32_t)(73+k));
        EXPECT(vireo_tcp_server_client_read_consume(f.server,f.clients[k],32,NULL),VIREO_OK);
        EXPECT(vireo_tcp_server_client_write_enqueue(f.server,f.clients[k],response,32,NULL),VIREO_OK);
        EXPECT(vireo_tls_connection_send(t,&budget,&progress,NULL),VIREO_OK); CHECK(progress.bytes==32);
        size_t n=0;
        for(unsigned r=0;r<128 && n==0;++r) {
            struct pollfd readable={f.peers[k],POLLIN,0}; CHECK(poll(&readable,1,10)>=0);
            ERR_clear_error(); int returned=SSL_read_ex(f.ssl[k],received,sizeof(received),&n);
            int why=returned==1?SSL_ERROR_NONE:SSL_get_error(f.ssl[k],returned);
            CHECK(why==SSL_ERROR_NONE || why==SSL_ERROR_WANT_READ || why==SSL_ERROR_WANT_WRITE);
        }
        CHECK(n==32 && memcmp(received,response,32)==0);
    }
    vireo_tcp_server_tls_info_t info; EXPECT(vireo_tcp_server_tls_inspect(f.server,&info,NULL),VIREO_OK);
    CHECK(info.resource_bytes==81920);
    printf("real TCP trusted TLS1.3: 2 clients, same leases, 64 exact PING response bytes\n");
    finish(&f); ++groups;
}
static void established_mod_failure(void)
{
    fixture_t f; start(&f,&root_options,&tls_options,true); connect_one(&f); make_ssl(&f,0,true);
    (void)admit(&f,1,VIREO_OK,NULL); establish(&f,1);
    EXPECT(vireo_tcp_server_client_set_interests(f.server,f.clients[0],0,NULL),VIREO_OK);
    f.fault=F_MOD; f.fail_on=f.calls[F_MOD]+1;
    vireo_tcp_server_tls_handshake_info_t h; vireo_tcp_server_tls_error_t e; unsigned native=f.native_steps;
    EXPECT(vireo_tcp_server_client_tls_handshake_step(f.server,f.clients[0],&h,&e),VIREO_RESULT_IO);
    CHECK(h.application_ready && !h.handshake.native_called && h.interests==0 && h.retry_pending);
    CHECK(e.stage==VIREO_TCP_SERVER_TLS_SYNC && e.sync_result==VIREO_RESULT_IO && f.native_steps==native);
    vireo_tcp_server_ready_client_t ready; vireo_tcp_server_tls_poll_report_t p;
    EXPECT(vireo_tcp_server_tls_poll_ready_once(f.server,100,1,&ready,1,&p,NULL),VIREO_OK);
    CHECK(p.poll.selected_count==1 && p.poll.effective_timeout_ms==0 && !p.has_deadline);
    f.fault=F_NONE;
    EXPECT(vireo_tcp_server_client_tls_handshake_step(f.server,ready.client,&h,NULL),VIREO_OK);
    CHECK(h.application_ready && !h.handshake.native_called && h.sync_called && f.native_steps==native);
    CHECK(h.interests==(VIREO_EPOLL_INTEREST_READ|VIREO_EPOLL_INTEREST_PEER_WRITE_CLOSED));
    finish(&f); ++groups;
}
static void real_silent_timeout(void)
{
    fixture_t f; vireo_tcp_server_tls_options_t o=tls_options; o.handshake_timeout_ns=UINT64_C(50000000);
    start(&f,&root_options,&o,false); connect_one(&f); (void)admit(&f,1,VIREO_OK,NULL);
    vireo_tcp_server_tls_handshake_info_t h={0}; vireo_tcp_server_tls_poll_report_t p;
    vireo_tcp_server_ready_client_t ready; vireo_tls_handshake_deadline_info_t due;
    EXPECT(vireo_tls_connection_handshake_deadline_inspect(borrow(&f,0),&due,NULL),VIREO_OK);
    bool timed_out=false;
    for(unsigned k=0;k<8;++k) {
        EXPECT(vireo_tcp_server_tls_poll_ready_once(f.server,30000,1,&ready,1,&p,NULL),VIREO_OK);
        CHECK(p.poll.effective_timeout_ms<=50);
        if(p.poll.selected_count==0)continue;
        errno=ECHILD; vireo_result_t r=vireo_tcp_server_client_tls_handshake_step(f.server,ready.client,&h,NULL);
        CHECK(errno==ECHILD);
        if(r==VIREO_RESULT_TIMEOUT) {
            CHECK(!h.handshake.native_called && h.now_ns>=due.deadline_ns);
            CHECK(p.expired_clients==1 && ready.events==0 && p.poll.wait.ready_count==0);
            timed_out=true;break;
        }
        CHECK(r==VIREO_OK && h.handshake.wait==VIREO_TLS_HANDSHAKE_WAIT_READ);
    }
    CHECK(timed_out); make_ssl(&f,0,true); (void)client_step(f.ssl[0],false);
    EXPECT(vireo_tcp_server_client_tls_handshake_step(f.server,f.clients[0],&h,NULL),VIREO_RESULT_TIMEOUT);
    CHECK(!h.handshake.native_called);
    printf("real TCP silent peer: no new fd event, clipped wait, TIMEOUT, late ClientHello rejected\n");
    finish(&f); ++groups;
}
static void protocol_and_eof(void)
{
    for(unsigned k=0;k<2;++k) {
        fixture_t f; start(&f,&root_options,&tls_options,false); connect_one(&f); (void)admit(&f,1,VIREO_OK,NULL);
        if(k==0) { char const bad[]="HTTP/1.1 200 This is not TLS\r\n\r\n";
            CHECK(send(f.peers[0],bad,sizeof(bad),MSG_NOSIGNAL)==(ssize_t)sizeof(bad)); }
        else { CHECK(close(f.peers[0])==0);f.peers[0]=-1; }
        vireo_tcp_server_tls_handshake_info_t h; vireo_tcp_server_tls_error_t first,again;
        errno=ECHILD; vireo_result_t r=vireo_tcp_server_client_tls_handshake_step(f.server,f.clients[0],&h,&first);
        CHECK(errno==ECHILD && (r==VIREO_RESULT_PROTOCOL || r==VIREO_RESULT_IO));
        CHECK(h.handshake.state==VIREO_TLS_HANDSHAKE_FAILED && h.handshake.native_called && h.interests==0);
        EXPECT(vireo_tcp_server_client_tls_handshake_step(f.server,f.clients[0],&h,&again),r);
        CHECK(!h.handshake.native_called && first.tls_error.stage==again.tls_error.stage &&
            first.tls_error.openssl_error_code==again.tls_error.openssl_error_code);
        finish(&f);
    }
    ++groups;
}
static void stopped_shutdown(void)
{
    fixture_t f; start(&f,&root_options,&tls_options,true); connect_one(&f); connect_one(&f);
    (void)admit(&f,2,VIREO_OK,NULL); f.stop_in_wait=true;
    vireo_tcp_server_ready_client_t ready[4]; vireo_tcp_server_tls_poll_report_t p;
    EXPECT(vireo_tcp_server_tls_poll_ready_once(f.server,0,4,ready,4,&p,NULL),VIREO_OK);
    CHECK(p.poll.stopped && p.poll.selected_count==0 && p.poll.remaining_count==2 && p.poll.queued_after_wait==2);
    vireo_tcp_server_tls_info_t info; EXPECT(vireo_tcp_server_tls_inspect(f.server,&info,NULL),VIREO_OK);
    CHECK(info.resource_bytes==81920);
    vireo_tcp_server_shutdown_budget_t budget={4}; vireo_tcp_server_shutdown_result_t rows[4];
    vireo_tcp_server_shutdown_info_t si;
    EXPECT(vireo_tcp_server_shutdown_batch(f.server,&budget,rows,4,&si,NULL),VIREO_OK);
    CHECK(si.released_clients==2 && si.remaining_clients==0);
    for(size_t k=0;k<2;++k) {
        CHECK(fcntl(f.accepted_fds[k],F_GETFD)==-1 && errno==EBADF);
        f.clients[k]=(vireo_connection_pool_lease_t){0};
    }
    EXPECT(vireo_tcp_server_tls_inspect(f.server,&info,NULL),VIREO_OK); CHECK(info.resource_bytes==0);
    finish(&f); ++groups;
}
/** 在新exec进程中验证默认SIGPIPE拒绝，父进程策略不受影响。 */
static int signal_preflight(void)
{
    struct sigaction action={0}; action.sa_handler=SIG_DFL; CHECK(sigemptyset(&action.sa_mask)==0);
    CHECK(sigaction(SIGPIPE,&action,NULL)==0);
    fixture_t f; start(&f,&root_options,&tls_options,true); connect_one(&f); (void)admit(&f,1,VIREO_OK,NULL);
    vireo_tcp_server_tls_handshake_info_t h; vireo_tcp_server_tls_error_t e;
    EXPECT(vireo_tcp_server_client_tls_handshake_step(f.server,f.clients[0],&h,&e),VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(h.sampled && h.step_called && !h.handshake_reported && !h.handshake.native_called && !h.sync_called);
    CHECK(h.interests==(VIREO_EPOLL_INTEREST_READ|VIREO_EPOLL_INTEREST_PEER_WRITE_CLOSED));
    CHECK(f.native_steps==0 && e.tls_error.stage==VIREO_TLS_CONNECTION_STAGE_SIGNAL_POLICY);
    CHECK(sigaction(SIGPIPE,NULL,&action)==0 && action.sa_handler==SIG_DFL);
    finish(&f); puts("default SIGPIPE exec: zero native/zero MOD, report not published"); return 0;
}
static void signal_exec(void)
{
    pid_t pid=fork(); CHECK(pid>=0);
    if(pid==0) { execl("/proc/self/exe","test_tcp_server_tls","--signal-preflight",(char *)NULL); _exit(127); }
    int status; CHECK(waitpid(pid,&status,0)==pid && WIFEXITED(status) && WEXITSTATUS(status)==0);
    ++groups;
}
int main(int argc,char **argv)

{
    if(argc==2 && strcmp(argv[1],"--signal-preflight")==0)return signal_preflight();
    CHECK(argc==1);
    struct sigaction original,ignore={0}; CHECK(sigaction(SIGPIPE,NULL,&original)==0);
    ignore.sa_handler=SIG_IGN; CHECK(sigemptyset(&ignore.sa_mask)==0 && sigaction(SIGPIPE,&ignore,NULL)==0);
    size_t before=fd_count();
    construction(); invalid_options(); admission_failures(); partial_prefix(); cleanup_secondary(); resource_limits();
    overflow_and_clock(); no_event_deadline(); fifo_deadline_and_ceil(); poll_failures(); partial_due_scan_failure();
    mod_recovery_and_release(); want_direction_model(); raw_gates(); real_multi_ping(); established_mod_failure();
    real_silent_timeout(); protocol_and_eof(); stopped_shutdown(); signal_exec();
    size_t after=fd_count(); CHECK(after==before); CHECK(sigaction(SIGPIPE,&original,NULL)==0);
    printf("tcp_server TLS: %u groups, fd %zu -> %zu\n",groups,before,after); return 0;
}
