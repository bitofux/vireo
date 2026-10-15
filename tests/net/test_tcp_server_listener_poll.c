/*
 * PROJECT : VIREO
 * FILE    : test_tcp_server_listener_poll.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-15
 * BRIEF   : 同次通知/FIFO/接入窗口、LT压力与原监听通路隔离
 */
#define _GNU_SOURCE
#include "net/tcp_server_internal.h" /* 仅被测server自身私有测试边界。 */
#include <vireo/net/async_admission.h>
#include <vireo/net/async_admission_pressure.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"%s:%d: %s\n",__FILE__,__LINE__,#x); abort(); } } while (0)
#define EXPECT(x,y) do { errno=EDOM; vireo_result_t const got_=(x); CHECK(got_==(y) && errno==EDOM); } while (0)

/** 单Reactor测试资源根与本server边界上下文，借用至destroy结束。 */
typedef struct fixture {
    vireo_tcp_server_t *server; /**< 唯一网络资源根owner。 */
    struct sockaddr_in address; /**< 临时loopback端点，非持久配置。 */
    int peers[4]; /**< 测试对端fd owner，-1为空。 */
    size_t connected; /**< peers有效前缀，≤4。 */
    vireo_connection_pool_lease_t clients[4]; /**< 已交出的完整lease，release清值，副本不保活。 */
    size_t count; /**< clients历史前缀，含后来清空位置，≤4。 */
    vireo_acceptor_t *listener; /**< 从本层attach捕获的短期测试借用，server owns。 */
    vireo_acceptor_callback_t callback; /**< 原内部观察函数，仅模型窗口调用，不是用户业务。 */
    void *callback_context; /**< 原root地址借用，到成功detach或destroy结束。 */
    size_t waits; /**< scheduler本次尝试累计数，非真实epoll系统次数。 */
    int timeout; /**< 最近计划的非负等待毫秒。 */
    bool wait_io; /**< 等待前拒绝EINTR模型，不先执行回调。 */
    uint32_t notices[3]; /**< 合成监听通知位序列，明确不是内核事件。 */
    size_t notice_count; /**< 0实际loop，1..3合成成功wait回调/统计模型。 */
    bool probe; /**< 模型/实际wait内检查同root可变重入拒绝。 */
    size_t fail_at; /**< 取出前gate拒绝下标，SIZE_MAX不拒绝。 */
    bool stop_during_wait; /**< 已开始wait后调用真的public永久停止。 */
    vireo_tcp_server_t *other; /**< 独立server短借，用于嵌套窗口隔离，非owner。 */
} fixture_t;
static vireo_connection_options_t const connection={256,128,384};
static vireo_connection_flow_options_t const flow={64,63,192,32,96};
static unsigned fd_count(void) {
    DIR *d=opendir("/proc/self/fd"); CHECK(d!=NULL); unsigned n=0; struct dirent *p;
    while ((p=readdir(d))!=NULL) if (p->d_name[0]!='.') ++n;
    CHECK(closedir(d)==0); return n;
}
static bool same(vireo_connection_pool_lease_t a,vireo_connection_pool_lease_t b) {
    return a.pool_id==b.pool_id && a.slot_index==b.slot_index && a.generation==b.generation;
}
static vireo_tcp_server_info_t state(fixture_t *f) {
    vireo_tcp_server_info_t i; EXPECT(vireo_tcp_server_inspect(f->server,&i),VIREO_OK); return i;
}
static vireo_result_t listener_inspect(void *context,vireo_acceptor_t const *a,vireo_acceptor_info_t *i) {
    (void)context; return vireo_acceptor_inspect(a,i);
}
static vireo_result_t listener_attach(void *context,vireo_acceptor_t *a,vireo_event_loop_t *loop,bool enabled,
    vireo_acceptor_callback_t callback,void *cb_context,vireo_acceptor_loop_error_t *error) {
    fixture_t *f=context; vireo_result_t const result=vireo_acceptor_attach(a,loop,enabled,callback,cb_context,error);
    if (result==VIREO_OK) { f->listener=a; f->callback=callback; f->callback_context=cb_context; } return result;
}
static vireo_result_t listener_set(void *context,vireo_acceptor_t *a,bool enabled,vireo_acceptor_loop_error_t *e) {
    (void)context; return vireo_acceptor_set_read_enabled(a,enabled,e);
}
static vireo_result_t listener_detach(void *context,vireo_acceptor_t *a,vireo_acceptor_loop_error_t *e) {
    fixture_t *f=context; vireo_result_t const result=vireo_acceptor_detach(a,e);
    if (result==VIREO_OK) { f->listener=NULL; f->callback=NULL; f->callback_context=NULL; } return result;
}
static vireo_result_t listener_forget(void *context,vireo_acceptor_t *a) {
    fixture_t *f=context; vireo_result_t const result=vireo_acceptor_forget_destroyed_loop(a,NULL);
    if (result==VIREO_OK) { f->listener=NULL; f->callback=NULL; f->callback_context=NULL; } return result;
}
static vireo_result_t listener_destroy(void *context,vireo_acceptor_t **a,vireo_acceptor_error_t *e) {
    (void)context; return vireo_acceptor_destroy(a,e);
}
static void probe(fixture_t *f) {
    vireo_tcp_server_ready_client_t item={0}, old=item;
    vireo_tcp_server_listener_poll_report_t report;
    EXPECT(vireo_tcp_server_poll_with_listener_once(f->server,0,1,&item,1,&report),VIREO_RESULT_BUSY);
    CHECK(!report.poll.wait_called && report.listener_events==0 && memcmp(&item,&old,sizeof old)==0);
    vireo_tcp_server_poll_report_t legacy;
    EXPECT(vireo_tcp_server_poll_ready_once(f->server,0,1,&item,1,&legacy),VIREO_RESULT_BUSY);
    EXPECT(vireo_tcp_server_set_listener_read_enabled(f->server,false,NULL),VIREO_RESULT_BUSY);
    EXPECT(vireo_tcp_server_unbind_listener(f->server,NULL),VIREO_RESULT_BUSY);
    vireo_tcp_server_t *owner=f->server; EXPECT(vireo_tcp_server_destroy(&owner,NULL),VIREO_RESULT_BUSY); CHECK(owner==f->server);
    CHECK(state(f).scheduling_active);
    if (f->other!=NULL) {
        EXPECT(vireo_tcp_server_poll_with_listener_once(f->other,0,1,&item,1,&report),VIREO_OK);
        CHECK(report.listener_events==VIREO_EPOLL_EVENT_HANGUP);
    }
}
static vireo_result_t wait_once(void *context,vireo_event_loop_t *loop,int timeout,
    vireo_event_loop_run_info_t *info,vireo_event_loop_error_t *error) {
    fixture_t *f=context; ++f->waits; f->timeout=timeout;
    if (f->wait_io) {
        if (f->probe) probe(f);
        *error=(vireo_event_loop_error_t){.stage=VIREO_EVENT_LOOP_STAGE_WAIT,.epoll_error={VIREO_EPOLL_STAGE_WAIT,EINTR}};
        errno=ERANGE; return VIREO_RESULT_IO;
    }
    if (f->stop_during_wait) EXPECT(vireo_tcp_server_request_stop(f->server,NULL),VIREO_OK);
    if (f->notice_count!=0) {
        CHECK(f->notice_count<=3 && f->callback!=NULL);
        for (size_t i=0;i<f->notice_count;++i) {
            f->callback(f->listener,f->notices[i],f->callback_context);
            if (i==0 && f->probe) probe(f);
        }
        *info=(vireo_event_loop_run_info_t){.ready_count=f->notice_count,.dispatched_count=f->notice_count};
        *error=(vireo_event_loop_error_t){0}; errno=ERANGE; return VIREO_OK;
    }
    if (f->probe) probe(f);
    vireo_result_t const result=vireo_event_loop_run_once(loop,timeout,info,error); errno=ERANGE; return result;
}
static void prepare(fixture_t *f,size_t slots,size_t bytes,bool owns_listener,bool bound) {
    *f=(fixture_t){.peers={-1,-1,-1,-1},.fail_at=SIZE_MAX};
    vireo_tcp_server_options_t const o={slots,8,1048576,bytes};
    vireo_tcp_server_scheduler_ops_t const scheduler={f,wait_once};
    vireo_tcp_server_listener_ops_t const listeners={f,listener_inspect,listener_attach,listener_set,listener_detach,listener_forget,listener_destroy};
    EXPECT(vireo_tcp_server_create_with_scheduler_ops(&o,NULL,&listeners,NULL,&scheduler,&f->server,NULL),VIREO_OK);
    if (!owns_listener) return;
    int fd=socket(AF_INET,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0); CHECK(fd>=0);
    f->address=(struct sockaddr_in){.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
    CHECK(bind(fd,(struct sockaddr *)&f->address,sizeof f->address)==0 && listen(fd,8)==0);
    socklen_t size=sizeof f->address; CHECK(getsockname(fd,(struct sockaddr *)&f->address,&size)==0);
    vireo_acceptor_t *a=NULL; vireo_acceptor_options_t const ao={4096}; EXPECT(vireo_acceptor_create(&ao,&fd,&a,NULL),VIREO_OK);
    EXPECT(vireo_tcp_server_adopt_listener(f->server,&a,NULL),VIREO_OK);
    if (bound) EXPECT(vireo_tcp_server_bind_listener(f->server,true,NULL),VIREO_OK);
}
static void connect_clients(fixture_t *f,size_t n) {
    CHECK(f->connected+n<=4);
    for (size_t i=0;i<n;++i) { size_t const k=f->connected; f->peers[k]=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0); CHECK(f->peers[k]>=0);
        CHECK(connect(f->peers[k],(struct sockaddr *)&f->address,sizeof f->address)==0); ++f->connected; }
}
/** 保存全部真正admitted身份，资源仍server拥有；不丢失败前缀。 */
static void remember(fixture_t *f,vireo_connection_pool_lease_t const *leases,size_t n) {
    CHECK(f->count+n<=4); for (size_t i=0;i<n;++i) f->clients[f->count++]=leases[i];
}
static void admit(fixture_t *f,size_t n) {
    vireo_connection_pool_lease_t leases[4]={0}; vireo_async_admission_turn_t turns[4]; vireo_async_admission_report_t report;
    vireo_tcp_server_admit_budget_t const b={n,8};
    EXPECT(vireo_async_admission_once(f->server,&connection,&flow,&b,leases,4,turns,4,&report),VIREO_OK);
    remember(f,leases,report.admission.admitted_count); CHECK(report.admission.admitted_count==n && report.scheduled_count==n);
}
/** 测试caller示例，不是新增生产自动准入策略。 */
static vireo_result_t caller_admit(fixture_t *f,vireo_tcp_server_listener_poll_report_t const *poll,bool *called) {
    *called=false;
    CHECK(poll->poll.stage==VIREO_TCP_SERVER_POLL_NONE);
    if ((poll->listener_events&(VIREO_EPOLL_EVENT_ERROR|VIREO_EPOLL_EVENT_HANGUP))!=0) return VIREO_RESULT_IO;
    if ((poll->listener_events&VIREO_EPOLL_EVENT_READ)==0) return VIREO_OK;
    *called=true; vireo_connection_pool_lease_t leases[4]={0}; vireo_async_admission_turn_t turns[4];
    vireo_async_admission_report_t report; vireo_tcp_server_admit_budget_t const b={1,1};
    vireo_result_t const result=vireo_async_admission_once(f->server,&connection,&flow,&b,leases,4,turns,4,&report);
    remember(f,leases,report.admission.admitted_count);
    if (report.admission.admitted_count==0) CHECK(report.admission.stop_reason==VIREO_TCP_SERVER_ADMIT_WOULD_BLOCK);
    return result;
}
static void pressure(fixture_t *f) {
    vireo_async_admission_pressure_report_t report;
    EXPECT(vireo_async_admission_pressure_refresh(f->server,&connection,&report),VIREO_OK);
    CHECK(report.read_after==state(f).listener_read_enabled);
}
static void poll_once(fixture_t *f,int timeout,size_t max,vireo_tcp_server_ready_client_t *out,size_t cap,
    vireo_tcp_server_listener_poll_report_t *report,vireo_result_t expected) {
    EXPECT(vireo_tcp_server_poll_with_listener_once(f->server,timeout,max,out,cap,report),expected);
    CHECK(!state(f).scheduling_active);
}
static void finish(fixture_t *f) {
    for (size_t i=0;i<f->count;++i) if (f->clients[i].pool_id!=0)
        EXPECT(vireo_tcp_server_release_client(f->server,&f->clients[i],NULL),VIREO_OK);
    for (size_t i=0;i<f->connected;++i) CHECK(close(f->peers[i])==0);
    EXPECT(vireo_tcp_server_destroy(&f->server,NULL),VIREO_OK);
}
static void parameters(void) {
    fixture_t f; prepare(&f,3,1152,true,true); vireo_tcp_server_ready_client_t out[2]; memset(out,0xA5,sizeof out);
    unsigned char old[sizeof out]; memcpy(old,out,sizeof old); vireo_tcp_server_listener_poll_report_t report;
    EXPECT(vireo_tcp_server_poll_with_listener_once(NULL,0,1,out,2,&report),VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_tcp_server_poll_with_listener_once(f.server,0,1,NULL,2,&report),VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_tcp_server_poll_with_listener_once(f.server,0,1,out,2,NULL),VIREO_RESULT_INVALID_ARGUMENT);
    poll_once(&f,-1,1,out,2,&report,VIREO_RESULT_INVALID_ARGUMENT);
    poll_once(&f,0,0,out,2,&report,VIREO_RESULT_INVALID_ARGUMENT);
    poll_once(&f,0,1,out,0,&report,VIREO_RESULT_INVALID_ARGUMENT);
    poll_once(&f,0,65536,out,2,&report,VIREO_RESULT_RANGE);
    poll_once(&f,0,1,out,65536,&report,VIREO_RESULT_RANGE);
    CHECK(report.listener_events==0 && !report.poll.wait_called && f.waits==0 && memcmp(out,old,sizeof out)==0); finish(&f);
}
static void fresh_read_window(void) {
    fixture_t f; prepare(&f,3,1152,true,true); connect_clients(&f,1); pressure(&f);
    vireo_tcp_server_ready_client_t out[4]; vireo_tcp_server_listener_poll_report_t report;
    poll_once(&f,1000,3,out,4,&report,VIREO_OK);
    CHECK(report.listener_events==VIREO_EPOLL_EVENT_READ && report.poll.wait.dispatched_count==1 && report.poll.selected_count==0);
    CHECK(state(&f).connection_count==0); bool called;
    EXPECT(caller_admit(&f,&report,&called),VIREO_OK); CHECK(called && f.count==1);
    vireo_tcp_server_client_info_t info; EXPECT(vireo_tcp_server_client_inspect(f.server,f.clients[0],&info),VIREO_OK);
    CHECK(info.queued && info.connection_info.read_buffer.readable_size==0 && info.connection_info.flow_enabled);
    pressure(&f); finish(&f); /* caller此窗口之后才准备pending/provider，未驱动。 */
}
static void history_is_not_current(void) {
    fixture_t f; prepare(&f,3,1152,true,true); connect_clients(&f,1);
    vireo_tcp_server_ready_client_t out[4]; vireo_tcp_server_listener_poll_report_t report;
    poll_once(&f,1000,3,out,4,&report,VIREO_OK); admit(&f,1);
    CHECK(state(&f).listener_last_events==VIREO_EPOLL_EVENT_READ);
    poll_once(&f,1000,3,out,4,&report,VIREO_OK);
    CHECK(report.listener_events==0 && report.poll.selected_count==1 && report.poll.effective_timeout_ms==0);
    CHECK(state(&f).listener_last_events==VIREO_EPOLL_EVENT_READ); bool called;
    EXPECT(caller_admit(&f,&report,&called),VIREO_OK); CHECK(!called && f.count==1); finish(&f);
}
static void lt_budget_batches(void) {
    fixture_t f; prepare(&f,3,1152,true,true); connect_clients(&f,3);
    vireo_tcp_server_ready_client_t out[4]; vireo_tcp_server_listener_poll_report_t report;
    for (size_t i=0;i<3;++i) {
        poll_once(&f,1000,3,out,4,&report,VIREO_OK); CHECK(report.listener_events==VIREO_EPOLL_EVENT_READ);
        bool called; EXPECT(caller_admit(&f,&report,&called),VIREO_OK); CHECK(called && f.count==i+1); pressure(&f);
    }
    CHECK(!state(&f).listener_read_enabled);
    poll_once(&f,1000,3,out,4,&report,VIREO_OK); CHECK(report.listener_events==0 && report.poll.selected_count==1); finish(&f);
}
static void pressure_refund_resume(void) {
    fixture_t f; prepare(&f,1,384,true,true); connect_clients(&f,2);
    vireo_tcp_server_ready_client_t out[4]; vireo_tcp_server_listener_poll_report_t report;
    poll_once(&f,1000,1,out,4,&report,VIREO_OK); bool called; EXPECT(caller_admit(&f,&report,&called),VIREO_OK); CHECK(called);
    pressure(&f); CHECK(!state(&f).listener_read_enabled);
    poll_once(&f,1000,1,out,4,&report,VIREO_OK); CHECK(report.listener_events==0);
    vireo_connection_pool_lease_t const old=f.clients[0]; EXPECT(vireo_tcp_server_release_client(f.server,&f.clients[0],NULL),VIREO_OK);
    CHECK(!state(&f).listener_read_enabled); pressure(&f); CHECK(state(&f).listener_read_enabled);
    poll_once(&f,1000,1,out,4,&report,VIREO_OK); CHECK(report.listener_events==VIREO_EPOLL_EVENT_READ);
    EXPECT(caller_admit(&f,&report,&called),VIREO_OK); CHECK(called && old.slot_index==f.clients[1].slot_index && old.generation!=f.clients[1].generation);
    vireo_tcp_server_client_info_t info; EXPECT(vireo_tcp_server_client_inspect(f.server,old,&info),VIREO_RESULT_NOT_FOUND); finish(&f);
}
static void missing_binding(void) {
    for (unsigned owned=0;owned<2;++owned) {
        fixture_t f; prepare(&f,3,1152,owned!=0,false);
        if (owned!=0) connect_clients(&f,1);
        vireo_tcp_server_ready_client_t out[1]; vireo_tcp_server_listener_poll_report_t report;
        poll_once(&f,0,1,out,1,&report,VIREO_OK); CHECK(report.listener_events==0 && report.poll.selected_count==0); finish(&f);
    }
}
static void legacy_poll_isolation(void) {
    fixture_t f; prepare(&f,3,1152,true,true); connect_clients(&f,1);
    vireo_tcp_server_ready_client_t out[4]; vireo_tcp_server_poll_report_t legacy;
    EXPECT(vireo_tcp_server_poll_ready_once(f.server,1000,3,out,4,&legacy),VIREO_OK);
    CHECK(state(&f).listener_last_events==VIREO_EPOLL_EVENT_READ); admit(&f,1);
    vireo_tcp_server_listener_poll_report_t report; poll_once(&f,0,3,out,4,&report,VIREO_OK); CHECK(report.listener_events==0); finish(&f);
}
static vireo_result_t unused_handler(vireo_connection_frame_view_t const *request,uint8_t *body,size_t size,
    vireo_tcp_server_reply_t *reply,void *context) {
    (void)request; (void)body; (void)size; (void)reply; (void)context; CHECK(false); return VIREO_RESULT_INTERNAL;
}
static void synchronous_isolation(void) {
    fixture_t f; prepare(&f,3,1152,true,true); connect_clients(&f,1);
    vireo_tcp_server_admission_options_t const a={connection,flow}; EXPECT(vireo_tcp_server_admission_configure(f.server,&a,NULL),VIREO_OK);
    vireo_tcp_server_serve_options_t const o={.timeout_ms=0,.process={64,64},.drive={{64,2},{1,64,64},{64,2}},.round={1},.admit={1,4}};
    uint8_t workspace[64]; vireo_tcp_server_turn_result_t turns[3]; vireo_connection_pool_lease_t leases[3]={0};
    vireo_tcp_server_serve_info_t info; vireo_tcp_server_serve_error_t error;
    EXPECT(vireo_tcp_server_serve_once(f.server,&o,workspace,64,unused_handler,NULL,turns,3,leases,3,&info,&error),VIREO_OK);
    CHECK(info.listener_events==VIREO_EPOLL_EVENT_READ && info.admission.admitted_count==1); remember(&f,leases,1);
    vireo_tcp_server_ready_client_t out[4]; vireo_tcp_server_listener_poll_report_t report;
    poll_once(&f,0,3,out,4,&report,VIREO_OK); CHECK(report.listener_events==0 && state(&f).admission_enabled);
    /* 新poll只机械观察，不暗中disable旧auto。 */
    EXPECT(vireo_tcp_server_admission_disable(f.server,NULL),VIREO_OK); finish(&f);
}
static void fifo_with_listener(void) {
    fixture_t f; prepare(&f,3,1152,true,true); connect_clients(&f,3); admit(&f,2);
    vireo_tcp_server_ready_client_t out[4]; memset(out,0xA5,sizeof out); unsigned char old[sizeof out]; memcpy(old,out,sizeof old);
    vireo_tcp_server_listener_poll_report_t report;
    poll_once(&f,INT_MAX,1,out,2,&report,VIREO_OK);
    CHECK(report.listener_events==VIREO_EPOLL_EVENT_READ && report.poll.effective_timeout_ms==0 && f.timeout==0);
    CHECK(report.poll.selected_count==1 && report.poll.remaining_count==1 && same(out[0].client,f.clients[0]));
    CHECK(memcmp((unsigned char *)out+sizeof out[0],old+sizeof out[0],sizeof out-sizeof out[0])==0);
    poll_once(&f,999,3,out,1,&report,VIREO_OK); CHECK(report.poll.selected_count==1 && same(out[0].client,f.clients[1]));
    CHECK(report.listener_events==VIREO_EPOLL_EVENT_READ); admit(&f,1); finish(&f);
}
static void client_and_listener(void) {
    fixture_t f; prepare(&f,3,1152,true,true); connect_clients(&f,1); admit(&f,1);
    vireo_tcp_server_ready_client_t out[4]; vireo_tcp_server_listener_poll_report_t report; poll_once(&f,0,3,out,4,&report,VIREO_OK);
    uint8_t const bytes[4]={4,3,2,1}; CHECK(send(f.peers[0],bytes,4,MSG_NOSIGNAL)==4); connect_clients(&f,1);
    poll_once(&f,1000,3,out,4,&report,VIREO_OK);
    CHECK(report.listener_events==VIREO_EPOLL_EVENT_READ && report.poll.selected_count==1 && same(out[0].client,f.clients[0]));
    CHECK((out[0].events&VIREO_EPOLL_EVENT_READ)!=0);
    vireo_tcp_server_client_info_t info; EXPECT(vireo_tcp_server_client_inspect(f.server,f.clients[0],&info),VIREO_OK); CHECK(info.connection_info.read_buffer.readable_size==0);
    vireo_connection_receive_budget_t const b={4,2}; vireo_connection_receive_info_t ri;
    EXPECT(vireo_tcp_server_client_receive(f.server,f.clients[0],&b,&ri,NULL),VIREO_OK); CHECK(ri.received_bytes==4);
    EXPECT(vireo_tcp_server_client_read_consume(f.server,f.clients[0],4,NULL),VIREO_OK); admit(&f,1); finish(&f);
}
static void or_error_model(void) {
    fixture_t f; prepare(&f,3,1152,true,true); f.notices[0]=VIREO_EPOLL_EVENT_READ; f.notices[1]=VIREO_EPOLL_EVENT_ERROR; f.notices[2]=VIREO_EPOLL_EVENT_HANGUP; f.notice_count=3;
    vireo_tcp_server_ready_client_t out[4]; vireo_tcp_server_listener_poll_report_t report;
    poll_once(&f,0,3,out,4,&report,VIREO_OK);
    CHECK(report.listener_events==(VIREO_EPOLL_EVENT_READ|VIREO_EPOLL_EVENT_ERROR|VIREO_EPOLL_EVENT_HANGUP));
    CHECK(report.poll.wait.dispatched_count==3 && state(&f).listener_last_events==VIREO_EPOLL_EVENT_HANGUP);
    bool called; EXPECT(caller_admit(&f,&report,&called),VIREO_RESULT_IO); CHECK(!called && f.count==0);
    f.notice_count=0; poll_once(&f,0,3,out,4,&report,VIREO_OK); CHECK(report.listener_events==0); finish(&f);
}
static void reentry_window(void) {
    fixture_t f; prepare(&f,3,1152,true,true); f.probe=true; f.notice_count=2;
    f.notices[0]=VIREO_EPOLL_EVENT_READ; f.notices[1]=VIREO_EPOLL_EVENT_HANGUP;
    vireo_tcp_server_ready_client_t out[4]; vireo_tcp_server_listener_poll_report_t report;
    poll_once(&f,0,3,out,4,&report,VIREO_OK); CHECK(report.listener_events==(VIREO_EPOLL_EVENT_READ|VIREO_EPOLL_EVENT_HANGUP)); finish(&f);
}
static void wait_error_cleanup(void) {
    fixture_t f; prepare(&f,3,1152,true,true); connect_clients(&f,1); admit(&f,1); f.wait_io=true; f.probe=true;
    vireo_tcp_server_ready_client_t out[4]; memset(out,0xA5,sizeof out); unsigned char old[sizeof out]; memcpy(old,out,sizeof old);
    vireo_tcp_server_listener_poll_report_t report; poll_once(&f,0,3,out,4,&report,VIREO_RESULT_IO);
    CHECK(report.listener_events==0 && report.poll.stage==VIREO_TCP_SERVER_POLL_WAIT && report.poll.loop_error.epoll_error.system_errno==EINTR);
    CHECK(report.poll.selected_count==0 && state(&f).pending_clients==1 && memcmp(out,old,sizeof out)==0);
    f.wait_io=false; f.probe=false; poll_once(&f,0,3,out,4,&report,VIREO_OK); CHECK(report.listener_events==0 && report.poll.selected_count==1); finish(&f);
}
static vireo_result_t gate(void *context,vireo_tcp_server_t const *server,vireo_connection_pool_lease_t client,size_t selected) {
    fixture_t *f=context; (void)server; (void)client; errno=ERANGE;
    return selected==f->fail_at?VIREO_RESULT_IO:VIREO_OK; /* 不改root/当前项，非真损坏FIFO。 */
}
static void queue_error_prefix(void) {
    fixture_t f; prepare(&f,3,1152,true,true); connect_clients(&f,3); admit(&f,2); f.fail_at=1;
    vireo_tcp_server_ready_client_t out[4]; memset(out,0xA5,sizeof out); unsigned char old[sizeof out]; memcpy(old,out,sizeof old);
    vireo_tcp_server_listener_poll_report_t report;
    EXPECT(vireo_tcp_server_poll_with_listener_once_with_gate(f.server,0,3,out,4,&report,gate,&f),VIREO_RESULT_IO);
    CHECK(report.poll.stage==VIREO_TCP_SERVER_POLL_QUEUE && report.listener_events==VIREO_EPOLL_EVENT_READ);
    CHECK(report.poll.selected_count==1 && report.poll.remaining_count==1 && same(out[0].client,f.clients[0]));
    CHECK(memcmp((unsigned char *)out+sizeof out[0],old+sizeof out[0],sizeof out-sizeof out[0])==0);
    CHECK(!state(&f).scheduling_active); EXPECT(vireo_tcp_server_schedule_client(f.server,f.clients[0],NULL),VIREO_OK);
    poll_once(&f,0,3,out,4,&report,VIREO_OK); CHECK(report.poll.selected_count==2 && same(out[0].client,f.clients[1]) && same(out[1].client,f.clients[0]));
    admit(&f,1); finish(&f);
}
static void unbind_rebind(void) {
    fixture_t f; prepare(&f,3,1152,true,true); connect_clients(&f,1);
    vireo_tcp_server_ready_client_t out[4]; vireo_tcp_server_listener_poll_report_t report; poll_once(&f,1000,3,out,4,&report,VIREO_OK); CHECK(report.listener_events!=0);
    EXPECT(vireo_tcp_server_unbind_listener(f.server,NULL),VIREO_OK); poll_once(&f,0,3,out,4,&report,VIREO_OK); CHECK(report.listener_events==0);
    EXPECT(vireo_tcp_server_bind_listener(f.server,true,NULL),VIREO_OK); poll_once(&f,1000,3,out,4,&report,VIREO_OK); CHECK(report.listener_events==VIREO_EPOLL_EVENT_READ);
    admit(&f,1); finish(&f);
}
static void pre_stopped(void) {
    fixture_t f; prepare(&f,3,1152,true,true); connect_clients(&f,2); admit(&f,1);
    EXPECT(vireo_tcp_server_request_stop(f.server,NULL),VIREO_OK); size_t const waits=f.waits;
    vireo_tcp_server_ready_client_t out[4]; memset(out,0xA5,sizeof out); unsigned char old[sizeof out]; memcpy(old,out,sizeof old);
    vireo_tcp_server_listener_poll_report_t report; poll_once(&f,0,3,out,4,&report,VIREO_OK);
    CHECK(report.poll.stopped && !report.poll.wait_called && report.listener_events==0 && f.waits==waits && state(&f).pending_clients==1);
    CHECK(memcmp(out,old,sizeof out)==0); finish(&f);
}
static void late_stop(void) {
    fixture_t f; prepare(&f,3,1152,true,true); connect_clients(&f,1); admit(&f,1); f.stop_during_wait=true;
    vireo_tcp_server_ready_client_t out[4]; vireo_tcp_server_listener_poll_report_t report; poll_once(&f,0,3,out,4,&report,VIREO_OK);
    CHECK(report.poll.wait_called && !report.poll.stopped && report.poll.selected_count==1 && report.listener_events==0 && state(&f).stop_requested);
    poll_once(&f,0,3,out,4,&report,VIREO_OK); CHECK(report.poll.stopped && !report.poll.wait_called); finish(&f);
}
static void independent_windows(void) {
    fixture_t a,b; prepare(&a,3,1152,true,true); prepare(&b,3,1152,true,true);
    a.other=b.server; a.probe=true; a.notice_count=2; a.notices[0]=VIREO_EPOLL_EVENT_READ; a.notices[1]=VIREO_EPOLL_EVENT_ERROR;
    b.notice_count=1; b.notices[0]=VIREO_EPOLL_EVENT_HANGUP;
    vireo_tcp_server_ready_client_t out[4]; vireo_tcp_server_listener_poll_report_t report; poll_once(&a,0,3,out,4,&report,VIREO_OK);
    CHECK(report.listener_events==(VIREO_EPOLL_EVENT_READ|VIREO_EPOLL_EVENT_ERROR)); b.notice_count=0;
    poll_once(&b,0,3,out,4,&report,VIREO_OK); CHECK(report.listener_events==0); a.other=NULL; finish(&a); finish(&b);
}
static void read_attempt_eagain(void) {
    fixture_t f; prepare(&f,3,1152,true,true); f.notice_count=1; f.notices[0]=VIREO_EPOLL_EVENT_READ;
    vireo_tcp_server_ready_client_t out[4]; vireo_tcp_server_listener_poll_report_t report; poll_once(&f,0,3,out,4,&report,VIREO_OK);
    bool called; EXPECT(caller_admit(&f,&report,&called),VIREO_OK); CHECK(called && f.count==0); finish(&f);
}
static void actual_control_budget(void) {
    vireo_tcp_server_t *server=NULL; vireo_tcp_server_options_t o={3,8,1048576,1152}; vireo_tcp_server_info_t info;
    EXPECT(vireo_tcp_server_create(&o,&server,NULL),VIREO_OK); EXPECT(vireo_tcp_server_inspect(server,&info),VIREO_OK);
    CHECK(info.allocation_bytes==info.server_allocation_bytes+info.loop_allocation_bytes+info.pool_allocation_bytes);
    o.max_memory_bytes=info.allocation_bytes; EXPECT(vireo_tcp_server_destroy(&server,NULL),VIREO_OK);
    EXPECT(vireo_tcp_server_create(&o,&server,NULL),VIREO_OK); EXPECT(vireo_tcp_server_destroy(&server,NULL),VIREO_OK);
    --o.max_memory_bytes; EXPECT(vireo_tcp_server_create(&o,&server,NULL),VIREO_RESULT_RANGE); CHECK(server==NULL);
}
int main(void) {
    int old; CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,&old)==0);
    void (*const tests[])(void)={parameters,fresh_read_window,history_is_not_current,lt_budget_batches,pressure_refund_resume,
        missing_binding,legacy_poll_isolation,synchronous_isolation,fifo_with_listener,client_and_listener,or_error_model,
        reentry_window,wait_error_cleanup,queue_error_prefix,unbind_rebind,pre_stopped,late_stop,independent_windows,
        read_attempt_eagain,actual_control_budget};
    for (size_t i=0;i<sizeof tests/sizeof tests[0];++i) { unsigned const before=fd_count(); tests[i](); CHECK(fd_count()==before); }
    CHECK(pthread_setcancelstate(old,NULL)==0); puts("listener poll: 20 groups, 0 failures"); return 0;
}
