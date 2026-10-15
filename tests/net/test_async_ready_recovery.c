/*
 * PROJECT : VIREO
 * FILE    : test_async_ready_recovery.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-15
 * BRIEF   : 真实FIFO/代际/有界恢复与03307失败后缀，只有本层seam
 */
#define _GNU_SOURCE
#include "net/async_ready_recovery_internal.h"
#include <vireo/net/async_service.h>
#include <vireo/net/notifier_server.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"%s:%d: %s\n",__FILE__,__LINE__,#x); abort(); } } while (0)
#define EXPECT(x,y) do { errno=EDOM; vireo_result_t const result_=(x); CHECK(result_==(y) && errno==EDOM); } while (0)

/** main拥有网络root/peer；完整客户租约是数值，实际资源由server拥有。 */
typedef struct fixture {
    vireo_tcp_server_t *server; /**< 唯一资源根owner，预留一个辅助注册位。 */
    struct sockaddr_in address; /**< 原位loopback监听端点，临时端口。 */
    int peers[4]; /**< 测试对端owner，最多第四项验证槽位复用。 */
    size_t peer_count; /**< 已打开对端的有效前缀。 */
    vireo_connection_pool_lease_t clients[3]; /**< 当前三个槽客户身份，release清值。 */
    vireo_tcp_server_ready_client_t ready[3]; /**< 已真实poll取出的历史有效前缀。 */
    size_t count; /**< ready有效元素数，≤3。 */
    vireo_async_ready_recovery_report_t report; /**< 本次完整恢复进度，不保活客户。 */
} fixture_t;
/** 只在本层公开schedule边界注入，不打开server私有布局。 */
typedef struct fault {
    size_t calls; /**< 实际依赖尝试数。 */
    size_t fail_at; /**< Nth无变更错误，0不注入。 */
    vireo_result_t result; /**< 要透传的公开结果分类。 */
} fault_t;
/** 真实03307使用的caller配置；失败是实际配置回调返回，不模拟整个service。 */
typedef struct provider {
    fixture_t *fixture; /**< main短借，仅读取保存的完整租约值。 */
    vireo_async_request_pending_t pending[3]; /**< 每完整客户唯一caller记录，原位稳定。 */
    size_t calls; /**< 实际配置次数，用于证明重排没有执行driver。 */
    size_t fail_at; /**< 指定配置项返回PROTOCOL；0为正常配置。 */
} provider_t;
static vireo_connection_options_t const connection={256,128,384};
static vireo_connection_flow_options_t const flow={64,63,192,32,96};
static bool same(vireo_connection_pool_lease_t a,vireo_connection_pool_lease_t b) {
    return a.pool_id==b.pool_id && a.slot_index==b.slot_index && a.generation==b.generation;
}
static unsigned fd_count(void) {
    DIR *d=opendir("/proc/self/fd"); CHECK(d!=NULL); unsigned n=0; struct dirent *p;
    while ((p=readdir(d))!=NULL) if (p->d_name[0]!='.') ++n;
    CHECK(closedir(d)==0); return n;
}
static vireo_tcp_server_info_t state(fixture_t *f) {
    vireo_tcp_server_info_t info; EXPECT(vireo_tcp_server_inspect(f->server,&info),VIREO_OK); return info;
}
static vireo_tcp_server_client_info_t client_info(fixture_t *f,size_t i) {
    vireo_tcp_server_client_info_t info; EXPECT(vireo_tcp_server_client_inspect(f->server,f->clients[i],&info),VIREO_OK); return info;
}
static void connect_peer(fixture_t *f) {
    CHECK(f->peer_count<4); int const fd=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0); CHECK(fd>=0);
    CHECK(connect(fd,(struct sockaddr *)&f->address,sizeof f->address)==0); f->peers[f->peer_count++]=fd;
}
static void prepare(fixture_t *f,size_t clients) {
    *f=(fixture_t){.peers={-1,-1,-1,-1}};
    vireo_tcp_server_options_t const o={3,8,1048576,1152};
    EXPECT(vireo_tcp_server_create_with_auxiliary_capacity(&o,1,&f->server,NULL),VIREO_OK);
    int fd=socket(AF_INET,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0); CHECK(fd>=0);
    f->address=(struct sockaddr_in){.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
    CHECK(bind(fd,(struct sockaddr *)&f->address,sizeof f->address)==0 && listen(fd,4)==0);
    socklen_t len=sizeof f->address; CHECK(getsockname(fd,(struct sockaddr *)&f->address,&len)==0);
    vireo_acceptor_t *a=NULL; vireo_acceptor_options_t const ao={4096}; EXPECT(vireo_acceptor_create(&ao,&fd,&a,NULL),VIREO_OK);
    EXPECT(vireo_tcp_server_adopt_listener(f->server,&a,NULL),VIREO_OK); EXPECT(vireo_tcp_server_bind_listener(f->server,true,NULL),VIREO_OK);
    for (size_t i=0;i<clients;++i) connect_peer(f);
    if (clients!=0) {
        vireo_tcp_server_admit_budget_t const b={clients,4}; vireo_async_admission_turn_t turns[3]; vireo_async_admission_report_t report;
        EXPECT(vireo_async_admission_once(f->server,&connection,&flow,&b,f->clients,3,turns,3,&report),VIREO_OK);
        CHECK(report.admission.admitted_count==clients && report.scheduled_count==clients);
    }
}
static void freeze(fixture_t *f,size_t expected) {
    vireo_tcp_server_poll_report_t report;
    EXPECT(vireo_tcp_server_poll_ready_once(f->server,0,3,f->ready,3,&report),VIREO_OK);
    f->count=report.selected_count; CHECK(f->count==expected && state(f).pending_clients==0);
}
static void finish(fixture_t *f) {
    for (size_t i=0;i<3;++i) if (f->clients[i].pool_id!=0) EXPECT(vireo_tcp_server_release_client(f->server,&f->clients[i],NULL),VIREO_OK);
    for (size_t i=0;i<f->peer_count;++i) CHECK(close(f->peers[i])==0);
    EXPECT(vireo_tcp_server_destroy(&f->server,NULL),VIREO_OK);
}
static void recover(fixture_t *f,size_t count,size_t begin,size_t max,vireo_result_t result) {
    EXPECT(vireo_async_service_reschedule_ready(f->server,f->ready,count,begin,max,&f->report),result);
}
static void check_zero(vireo_async_ready_recovery_report_t r) {
    CHECK(r.stage==VIREO_ASYNC_READY_RECOVERY_NONE && r.stop_reason==VIREO_ASYNC_READY_RECOVERY_STOP_NONE);
    CHECK(r.attempted_count==0 && r.scheduled_count==0 && r.next_index==0);
    CHECK(same(r.last_client,(vireo_connection_pool_lease_t){0}) && r.client_error.primary.stage==VIREO_TCP_SERVER_CLIENT_NONE);
}
static void check_order(fixture_t *f,size_t const *indices,size_t count) {
    vireo_tcp_server_ready_client_t out[3]; vireo_tcp_server_poll_report_t r;
    EXPECT(vireo_tcp_server_poll_ready_once(f->server,0,3,out,3,&r),VIREO_OK); CHECK(r.selected_count==count);
    for (size_t i=0;i<count;++i) CHECK(same(out[i].client,f->clients[indices[i]]) && out[i].events==0);
}
static vireo_result_t fault_schedule(void *context,vireo_tcp_server_t *s,vireo_connection_pool_lease_t client,
    vireo_tcp_server_client_error_t *error) {
    fault_t *f=context; ++f->calls;
    if (f->calls==f->fail_at) {
        *error=(vireo_tcp_server_client_error_t){0}; error->primary.stage=VIREO_TCP_SERVER_CLIENT_LOOKUP;
        errno=ERANGE; return f->result; /* 原公开边界无变更模型，非真实内核或allocator故障。 */
    }
    vireo_result_t const r=vireo_tcp_server_schedule_client(s,client,error); errno=ERANGE; return r;
}
static vireo_async_ready_recovery_ops_t const fault_ops={fault_schedule};
static void parameters(void) {
    fixture_t f; prepare(&f,0); vireo_async_ready_recovery_ops_t const broken={NULL}; fault_t fault={0};
    EXPECT(vireo_async_service_reschedule_ready(NULL,NULL,0,0,1,&f.report),VIREO_RESULT_INVALID_ARGUMENT); check_zero(f.report);
    EXPECT(vireo_async_service_reschedule_ready(f.server,NULL,0,0,1,NULL),VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_async_service_reschedule_ready(f.server,NULL,1,0,1,&f.report),VIREO_RESULT_INVALID_ARGUMENT); check_zero(f.report);
    EXPECT(vireo_async_service_reschedule_ready(f.server,NULL,0,0,0,&f.report),VIREO_RESULT_INVALID_ARGUMENT); check_zero(f.report);
    EXPECT(vireo_async_ready_recovery_with_ops(f.server,NULL,0,0,1,&f.report,NULL,&fault),VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_async_ready_recovery_with_ops(f.server,NULL,0,0,1,&f.report,&broken,&fault),VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(fault.calls==0 && state(&f).pending_clients==0); check_zero(f.report); finish(&f);
}
static void ranges(void) {
    fixture_t f; prepare(&f,3); freeze(&f,3);
    recover(&f,65536,0,1,VIREO_RESULT_RANGE); check_zero(f.report);
    recover(&f,3,0,65536,VIREO_RESULT_RANGE); check_zero(f.report);
    recover(&f,3,4,1,VIREO_RESULT_RANGE); check_zero(f.report);
    EXPECT(vireo_async_service_reschedule_ready(f.server,NULL,0,SIZE_MAX,1,&f.report),VIREO_RESULT_RANGE); check_zero(f.report);
    CHECK(state(&f).pending_clients==0); finish(&f);
}
static void empty_ranges(void) {
    fixture_t f; prepare(&f,3); freeze(&f,3); fault_t fault={0};
    EXPECT(vireo_async_ready_recovery_with_ops(f.server,NULL,0,0,65535,&f.report,&fault_ops,&fault),VIREO_OK);
    CHECK(f.report.stop_reason==VIREO_ASYNC_READY_RECOVERY_COMPLETE && f.report.next_index==0 && fault.calls==0);
    recover(&f,3,3,1,VIREO_OK); CHECK(f.report.next_index==3 && f.report.attempted_count==0 && f.report.scheduled_count==0);
    CHECK(same(f.report.last_client,(vireo_connection_pool_lease_t){0}) && state(&f).pending_clients==0); finish(&f);
}
static void fifo_complete(void) {
    fixture_t f; prepare(&f,3); freeze(&f,3);
    unsigned char before[sizeof f.ready]; memcpy(before,f.ready,sizeof before); recover(&f,3,0,3,VIREO_OK);
    CHECK(f.report.stage==VIREO_ASYNC_READY_RECOVERY_NONE && f.report.stop_reason==VIREO_ASYNC_READY_RECOVERY_COMPLETE);
    CHECK(f.report.attempted_count==3 && f.report.scheduled_count==3 && f.report.next_index==3 && same(f.report.last_client,f.clients[2]));
    CHECK(memcmp(before,f.ready,sizeof before)==0 && state(&f).pending_clients==3);
    size_t const order[]={0,1,2}; check_order(&f,order,3); finish(&f);
}
static void budget_resume(void) {
    fixture_t f; prepare(&f,3); freeze(&f,3);
    recover(&f,3,0,1,VIREO_OK); CHECK(f.report.stop_reason==VIREO_ASYNC_READY_RECOVERY_BUDGET && f.report.next_index==1 && f.report.attempted_count==1);
    recover(&f,3,f.report.next_index,1,VIREO_OK); CHECK(f.report.next_index==2 && state(&f).pending_clients==2);
    recover(&f,3,f.report.next_index,1,VIREO_OK); CHECK(f.report.next_index==3 && f.report.stop_reason==VIREO_ASYNC_READY_RECOVERY_COMPLETE);
    size_t const order[]={0,1,2}; check_order(&f,order,3); finish(&f);
}
static void explicit_suffix(void) {
    fixture_t f; prepare(&f,3); freeze(&f,3); recover(&f,3,1,65535,VIREO_OK);
    CHECK(f.report.attempted_count==2 && f.report.scheduled_count==2 && f.report.next_index==3 && !client_info(&f,0).queued);
    size_t const order[]={1,2}; check_order(&f,order,2); finish(&f);
}
static void already_queued(void) {
    fixture_t f; prepare(&f,3); freeze(&f,3); EXPECT(vireo_tcp_server_schedule_client(f.server,f.clients[1],NULL),VIREO_OK);
    recover(&f,3,0,3,VIREO_OK); CHECK(f.report.scheduled_count==3 && state(&f).pending_clients==3);
    recover(&f,3,0,3,VIREO_OK); CHECK(f.report.scheduled_count==3 && state(&f).pending_clients==3);
    size_t const order[]={1,0,2}; check_order(&f,order,3); finish(&f);
}
static void duplicate_values(void) {
    fixture_t f; prepare(&f,3); freeze(&f,3); f.ready[1]=f.ready[0]; recover(&f,3,0,3,VIREO_OK);
    CHECK(f.report.attempted_count==3 && f.report.scheduled_count==3 && state(&f).pending_clients==2);
    size_t const order[]={0,2}; check_order(&f,order,2); finish(&f);
}
static void stale_middle(void) {
    fixture_t f; prepare(&f,3); freeze(&f,3); EXPECT(vireo_tcp_server_release_client(f.server,&f.clients[1],NULL),VIREO_OK);
    recover(&f,3,0,3,VIREO_RESULT_NOT_FOUND);
    CHECK(f.report.stage==VIREO_ASYNC_READY_RECOVERY_SCHEDULE && f.report.stop_reason==VIREO_ASYNC_READY_RECOVERY_ERROR);
    CHECK(f.report.attempted_count==2 && f.report.scheduled_count==1 && f.report.next_index==1 && same(f.report.last_client,f.ready[1].client));
    CHECK(f.report.client_error.primary.stage==VIREO_TCP_SERVER_CLIENT_LOOKUP && !client_info(&f,2).queued);
    /* caller核实旧客户已归还，显式跳过；入口没有自动跳过。 */
    recover(&f,3,2,1,VIREO_OK); size_t const order[]={0,2}; check_order(&f,order,2); finish(&f);
}
static void budget_does_not_probe(void) {
    fixture_t f; prepare(&f,3); freeze(&f,3); EXPECT(vireo_tcp_server_release_client(f.server,&f.clients[1],NULL),VIREO_OK);
    recover(&f,3,0,1,VIREO_OK); CHECK(f.report.stop_reason==VIREO_ASYNC_READY_RECOVERY_BUDGET && f.report.next_index==1);
    recover(&f,3,1,1,VIREO_RESULT_NOT_FOUND); CHECK(f.report.scheduled_count==0 && f.report.attempted_count==1 && f.report.next_index==1);
    CHECK(state(&f).pending_clients==1); finish(&f);
}
static void lookup_classes(void) {
    fixture_t f,other; prepare(&f,1); freeze(&f,1); prepare(&other,1); freeze(&other,1);
    vireo_connection_pool_lease_t const original=f.ready[0].client;
    f.ready[0].client=(vireo_connection_pool_lease_t){0}; recover(&f,1,0,1,VIREO_RESULT_NOT_FOUND);
    f.ready[0].client=other.clients[0]; recover(&f,1,0,1,VIREO_RESULT_INVALID_ARGUMENT);
    f.ready[0].client=original; f.ready[0].client.slot_index=65535; recover(&f,1,0,1,VIREO_RESULT_RANGE);
    f.ready[0].client=original; f.ready[0].client.generation=0; recover(&f,1,0,1,VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(f.report.next_index==0 && f.report.attempted_count==1 && f.report.scheduled_count==0 && state(&f).pending_clients==0);
    finish(&other); finish(&f);
}
static void reuse_generation(void) {
    fixture_t f; prepare(&f,1); freeze(&f,1); vireo_connection_pool_lease_t const old=f.clients[0];
    EXPECT(vireo_tcp_server_release_client(f.server,&f.clients[0],NULL),VIREO_OK); connect_peer(&f);
    vireo_tcp_server_admit_budget_t const b={1,4}; vireo_tcp_server_admit_info_t info;
    EXPECT(vireo_tcp_server_admit_batch(f.server,&connection,&b,&f.clients[0],1,&info,NULL),VIREO_OK); CHECK(info.admitted_count==1);
    CHECK(old.pool_id==f.clients[0].pool_id && old.slot_index==f.clients[0].slot_index && old.generation!=f.clients[0].generation);
    recover(&f,1,0,1,VIREO_RESULT_NOT_FOUND); CHECK(!client_info(&f,0).queued && state(&f).pending_clients==0);
    f.ready[0].client=f.clients[0]; recover(&f,1,0,1,VIREO_OK); CHECK(client_info(&f,0).queued); finish(&f);
}
static void dependency_errors(void) {
    vireo_result_t const results[]={VIREO_RESULT_BUSY,VIREO_RESULT_IO,VIREO_RESULT_INTERNAL};
    for (size_t j=0;j<sizeof results/sizeof results[0];++j) {
        fixture_t f; prepare(&f,3); freeze(&f,3); fault_t fault={.fail_at=2,.result=results[j]};
        EXPECT(vireo_async_ready_recovery_with_ops(f.server,f.ready,3,0,3,&f.report,&fault_ops,&fault),results[j]);
        CHECK(fault.calls==2 && f.report.attempted_count==2 && f.report.scheduled_count==1 && f.report.next_index==1);
        CHECK(f.report.client_error.primary.stage==VIREO_TCP_SERVER_CLIENT_LOOKUP && state(&f).pending_clients==1 && !client_info(&f,2).queued);
        recover(&f,3,f.report.next_index,3,VIREO_OK); CHECK(f.report.scheduled_count==2 && f.report.next_index==3);
        size_t const order[]={0,1,2}; check_order(&f,order,3); finish(&f);
    }
}
static void stopped_mechanical(void) {
    fixture_t f; prepare(&f,3); freeze(&f,3); EXPECT(vireo_tcp_server_request_stop(f.server,NULL),VIREO_OK);
    recover(&f,3,0,3,VIREO_OK); CHECK(state(&f).stop_requested && state(&f).pending_clients==3);
    vireo_tcp_server_ready_client_t out[3]; vireo_tcp_server_poll_report_t report;
    EXPECT(vireo_tcp_server_poll_ready_once(f.server,0,3,out,3,&report),VIREO_OK);
    CHECK(report.stopped && report.selected_count==0 && state(&f).pending_clients==3); finish(&f);
}
static void closing_mechanical(void) {
    fixture_t f; prepare(&f,3); freeze(&f,3);
    EXPECT(vireo_tcp_server_client_request_close(f.server,f.clients[0],VIREO_CONNECTION_CLOSE_MODE_DRAIN,VIREO_CONNECTION_CLOSE_REASON_SERVER_STOP,NULL),VIREO_OK);
    recover(&f,3,0,1,VIREO_OK); CHECK(client_info(&f,0).queued);
    CHECK(!client_info(&f,1).queued && !client_info(&f,2).queued); finish(&f);
}
static vireo_result_t never_execute(void *context,vireo_task_t const *task) {
    (void)context; (void)task; CHECK(false); return VIREO_RESULT_INTERNAL;
}
static vireo_result_t never_resolve(void *context,vireo_completion_t const *completion,
    vireo_inflight_completion_match_t match,vireo_completion_response_descriptor_t *out) {
    (void)context; (void)completion; (void)match; (void)out; CHECK(false); return VIREO_RESULT_INTERNAL;
}
static vireo_result_t configure(void *context,vireo_tcp_server_ready_client_t client,vireo_async_round_config_t *out) {
    provider_t *p=context; ++p->calls;
    if (p->calls==p->fail_at) return VIREO_RESULT_PROTOCOL;
    size_t i=0; while (i<3 && !same(client.client,p->fixture->clients[i])) ++i; CHECK(i<3);
    *out=(vireo_async_round_config_t){{64,4096,3,9,UINT64_MAX},{{128,4},{128,4}},NULL,&p->pending[i]}; return VIREO_OK;
}
static void service_suffix_and_events(void) {
    fixture_t f; prepare(&f,3); /* 保原接入FIFO，使A/B/C先后顺序确定。 */
    uint8_t const partial=0xA5; CHECK(send(f.peers[0],&partial,1,MSG_NOSIGNAL)==1);
    vireo_inflight_store_t *store=NULL; vireo_inflight_store_options_t const so={3,65536}; EXPECT(vireo_inflight_store_create(&so,&store),VIREO_OK);
    vireo_task_queue_t *tasks=NULL; vireo_task_queue_options_t const tq={3,65536}; EXPECT(vireo_task_queue_create(&tq,&tasks),VIREO_OK); EXPECT(vireo_task_queue_prepare_wait(tasks),VIREO_OK);
    vireo_thread_pool_t *pool=NULL; vireo_thread_pool_options_t const po={1,65536}; EXPECT(vireo_thread_pool_create(&po,&pool),VIREO_OK);
    vireo_thread_pool_configuration_t const pc={tasks,never_execute,NULL}; EXPECT(vireo_thread_pool_configure(pool,&pc,NULL),VIREO_OK);
    vireo_completion_queue_t *queue=NULL; vireo_completion_queue_options_t const qo={3,65536}; EXPECT(vireo_completion_queue_create(&qo,&queue),VIREO_OK); EXPECT(vireo_completion_queue_prepare_wait(queue),VIREO_OK);
    vireo_notifier_t *notifier=NULL; vireo_notifier_options_t const no={4096}; EXPECT(vireo_notifier_create(&no,&notifier,NULL),VIREO_OK);
    vireo_event_loop_handle_t h={0}; EXPECT(vireo_notifier_server_register(f.server,notifier,&h,NULL),VIREO_OK);
    vireo_async_service_options_t const o={0,3,connection,flow,{1,4},1,64,64};
    vireo_async_round_turn_t turns[3]; vireo_connection_pool_lease_t admitted[3]={0}; vireo_async_admission_turn_t admission_turns[3]; uint8_t scratch[64];
    vireo_async_service_workspace_t const w={f.ready,3,turns,3,admitted,3,admission_turns,3,scratch,sizeof scratch};
    vireo_async_service_report_t report; provider_t provider={.fixture=&f,.fail_at=2};
    vireo_task_t *remaining_task=NULL; vireo_completion_t *remaining_completion=NULL;
    EXPECT(vireo_async_service_once(f.server,store,pool,notifier,queue,h,&o,&w,configure,&provider,never_resolve,NULL,
        &remaining_task,&remaining_completion,&report),VIREO_RESULT_PROTOCOL);
    f.count=report.poll_report.poll.selected_count;
    CHECK(f.count==3 && report.stage==VIREO_ASYNC_SERVICE_CLIENTS && report.clients.turn_count==2 && report.clients.unprocessed_begin==2);
    CHECK(report.clients.drive_calls==1 && turns[0].drive_report.receive.received_bytes==1 && provider.calls==2);
    CHECK((f.ready[0].events&VIREO_EPOLL_EVENT_READ)!=0 && client_info(&f,0).connection_info.read_buffer.readable_size==1);
    CHECK(remaining_task==NULL && remaining_completion==NULL && state(&f).pending_clients==0);
    unsigned char old[sizeof f.ready]; memcpy(old,f.ready,sizeof old);
    recover(&f,f.count,report.clients.unprocessed_begin,1,VIREO_OK);
    CHECK(f.report.next_index==3 && f.report.scheduled_count==1 && provider.calls==2 && state(&f).pending_clients==1);
    CHECK(!client_info(&f,0).queued && !client_info(&f,1).queued && client_info(&f,2).queued);
    CHECK(memcmp(old,f.ready,sizeof old)==0 && client_info(&f,0).connection_info.read_buffer.readable_size==1);
    /* caller已核对A只收到半头、无移交/pending，另外显式选择A；原READ历史不注入队列。 */
    recover(&f,1,0,1,VIREO_OK); CHECK(client_info(&f,0).pending_events==0 && client_info(&f,2).pending_events==0);
    size_t const order[]={2,0}; check_order(&f,order,2);
    CHECK(client_info(&f,0).connection_info.read_buffer.readable_size==1 && provider.calls==2);
    vireo_inflight_store_info_t si; EXPECT(vireo_inflight_store_inspect(store,&si),VIREO_OK); CHECK(si.count==0);
    EXPECT(vireo_thread_pool_destroy(&pool),VIREO_OK); EXPECT(vireo_task_queue_destroy(&tasks),VIREO_OK);
    EXPECT(vireo_completion_queue_destroy(&queue),VIREO_OK); EXPECT(vireo_inflight_store_destroy(&store),VIREO_OK);
    EXPECT(vireo_notifier_server_unregister(f.server,&h,NULL),VIREO_OK); EXPECT(vireo_notifier_destroy(&notifier,NULL),VIREO_OK); finish(&f);
}
int main(void) {
    int old; CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,&old)==0);
    void (*const tests[])(void)={parameters,ranges,empty_ranges,fifo_complete,budget_resume,explicit_suffix,already_queued,
        duplicate_values,stale_middle,budget_does_not_probe,lookup_classes,reuse_generation,dependency_errors,stopped_mechanical,
        closing_mechanical,service_suffix_and_events};
    for (size_t i=0;i<sizeof tests/sizeof tests[0];++i) { unsigned const n=fd_count(); tests[i](); CHECK(fd_count()==n); }
    CHECK(pthread_setcancelstate(old,NULL)==0); puts("async ready recovery: 16 groups, 0 failures"); return 0;
}
