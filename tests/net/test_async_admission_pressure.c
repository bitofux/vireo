/*
 * PROJECT : VIREO
 * FILE    : test_async_admission_pressure.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-14
 * BRIEF   : 真实名额/固定额度/退款、公开接入链及单次更新错误模型
 */
#define _GNU_SOURCE
#include "net/async_admission_pressure_internal.h" /* 仅本层私有头。 */
#include <vireo/net/async_admission.h>
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
#define EXPECT(x,y) do { errno=EDOM; vireo_result_t const got_=(x); CHECK(got_==(y) && errno==EDOM); } while (0)

/** 测试唯一资源拥有者，所有操作用公开接口。 */
typedef struct fixture {
    vireo_tcp_server_t *server; /**< 单Reactor拥有的网络根。 */
    struct sockaddr_in address; /**< 临时loopback端点，非持久配置。 */
    int peers[3]; /**< 测试对端fd owner，-1为空。 */
    size_t connected; /**< peers有效前缀，≤3。 */
    vireo_connection_pool_lease_t live[3]; /**< caller保存的历史租约前缀，归还清具体值。 */
    size_t live_count; /**< 已保存条目数，含后来清空的位置。 */
    vireo_async_admission_pressure_report_t report; /**< 本项当次报告，不保活资源。 */
} fixture_t;
/** 只注入本层公开边界，不修改外组件私有状态。 */
typedef struct fault {
    unsigned active_mask; /**< 七在途标记的快照模型。 */
    unsigned ledger; /**< 0真实账，1..3分别模拟count/available/reserved异常。 */
    bool inspect_error; /**< 模拟观察IO，不发布输出。 */
    bool update_error; /**< 模拟MOD拒绝，不实际调用set。 */
    bool stop_after_inspect; /**< 返回原快照后真实request_stop。 */
    size_t inspect_calls; /**< 本层观察尝试数。 */
    size_t set_calls; /**< 本层更新尝试数。 */
    bool requested; /**< 最后传入set的READ期望值。 */
} fault_t;
static vireo_connection_options_t const connection={256,128,384};
static vireo_connection_flow_options_t const flow={64,63,192,32,96};
static unsigned fd_count(void) {
    DIR *d=opendir("/proc/self/fd"); CHECK(d!=NULL); unsigned n=0; struct dirent *p;
    while ((p=readdir(d))!=NULL) if (p->d_name[0]!='.') ++n;
    CHECK(closedir(d)==0); return n;
}
static void prepare(fixture_t *f,size_t capacity,size_t bytes,bool bind_listener) {
    *f=(fixture_t){.peers={-1,-1,-1}};
    vireo_tcp_server_options_t const o={capacity,8,1048576,bytes};
    EXPECT(vireo_tcp_server_create(&o,&f->server,NULL),VIREO_OK);
    int fd=socket(AF_INET,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0); CHECK(fd>=0);
    f->address=(struct sockaddr_in){.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
    CHECK(bind(fd,(struct sockaddr *)&f->address,sizeof f->address)==0 && listen(fd,4)==0);
    socklen_t size=sizeof f->address; CHECK(getsockname(fd,(struct sockaddr *)&f->address,&size)==0);
    vireo_acceptor_t *a=NULL; vireo_acceptor_options_t const ao={4096};
    EXPECT(vireo_acceptor_create(&ao,&fd,&a,NULL),VIREO_OK);
    EXPECT(vireo_tcp_server_adopt_listener(f->server,&a,NULL),VIREO_OK);
    if (bind_listener) EXPECT(vireo_tcp_server_bind_listener(f->server,true,NULL),VIREO_OK);
}
static vireo_tcp_server_info_t state(fixture_t *f) {
    vireo_tcp_server_info_t info; EXPECT(vireo_tcp_server_inspect(f->server,&info),VIREO_OK); return info;
}
static void connect_clients(fixture_t *f,size_t n) {
    CHECK(f->connected+n<=3);
    for (size_t i=0;i<n;++i) {
        size_t const k=f->connected; f->peers[k]=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0); CHECK(f->peers[k]>=0);
        CHECK(connect(f->peers[k],(struct sockaddr *)&f->address,sizeof f->address)==0); ++f->connected;
    }
}
/** 真实03304单批准备，返回后caller先保存全部admitted，再做压力刷新。 */
static void admit(fixture_t *f,size_t n) {
    vireo_connection_pool_lease_t out[3]={0}; vireo_async_admission_turn_t turns[3];
    vireo_async_admission_report_t report; vireo_tcp_server_admit_budget_t const b={n,8};
    EXPECT(vireo_async_admission_once(f->server,&connection,&flow,&b,out,3,turns,3,&report),VIREO_OK);
    CHECK(report.admission.admitted_count==n && report.scheduled_count==n && f->live_count+n<=3);
    for (size_t i=0;i<n;++i) f->live[f->live_count++]=out[i];
}
static void finish_fixture(fixture_t *f) {
    for (size_t i=0;i<f->live_count;++i) if (f->live[i].pool_id!=0)
        EXPECT(vireo_tcp_server_release_client(f->server,&f->live[i],NULL),VIREO_OK);
    for (size_t i=0;i<f->connected;++i) CHECK(close(f->peers[i])==0);
    EXPECT(vireo_tcp_server_destroy(&f->server,NULL),VIREO_OK);
}
static void refresh(fixture_t *f,vireo_connection_options_t const *c,vireo_result_t expected) {
    memset(&f->report,0xA5,sizeof f->report);
    EXPECT(vireo_async_admission_pressure_refresh(f->server,c,&f->report),expected);
    CHECK(f->report.read_after==state(f).listener_read_enabled || !f->report.server_inspected);
}
static vireo_result_t model_inspect(void *context,vireo_tcp_server_t const *s,vireo_tcp_server_info_t *out) {
    fault_t *m=context; ++m->inspect_calls; errno=EIO;
    if (m->inspect_error) return VIREO_RESULT_IO;
    vireo_result_t const result=vireo_tcp_server_inspect(s,out);
    if (result==VIREO_OK) {
        out->processing_active=(m->active_mask&1U)!=0; out->driving_active=(m->active_mask&2U)!=0;
        out->scheduling_active=(m->active_mask&4U)!=0; out->serving_active=(m->active_mask&8U)!=0;
        out->shutdown_active=(m->active_mask&16U)!=0; out->closing_active=(m->active_mask&32U)!=0;
        out->running_active=(m->active_mask&64U)!=0;
        if (m->ledger==1) out->connection_count=out->connection_capacity+1;
        if (m->ledger==2) ++out->available_connections;
        if (m->ledger==3) out->buffer_capacity_bytes=out->max_buffer_bytes+1;
        if (m->stop_after_inspect) EXPECT(vireo_tcp_server_request_stop((vireo_tcp_server_t *)s,NULL),VIREO_OK);
    }
    return result;
}
static vireo_result_t model_set(void *context,vireo_tcp_server_t *s,bool enabled,vireo_tcp_server_listener_error_t *error) {
    fault_t *m=context; ++m->set_calls; m->requested=enabled; errno=EIO;
    if (m->update_error) {
        *error=(vireo_tcp_server_listener_error_t){.stage=VIREO_TCP_SERVER_LISTENER_UPDATE,
            .acceptor_error.loop_error.epoll_error.system_errno=EBADF};
        return VIREO_RESULT_IO; /* 仅拒绝模型，非真的损坏内核MOD。 */
    }
    return vireo_tcp_server_set_listener_read_enabled(s,enabled,error);
}
static vireo_async_admission_pressure_ops_t const model_ops={model_inspect,model_set};
static void model(fixture_t *f,fault_t *m,vireo_result_t expected) {
    EXPECT(vireo_async_admission_pressure_with_ops(f->server,&connection,&f->report,&model_ops,m),expected);
    CHECK(f->report.read_after==state(f).listener_read_enabled || !f->report.server_inspected);
}
static void parameters(void) {
    fixture_t f; prepare(&f,3,1152,true);
    EXPECT(vireo_async_admission_pressure_refresh(NULL,&connection,&f.report),VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(!f.report.server_inspected && !f.report.pressure_calculated && !f.report.update_called && f.report.pair_bytes==0);
    EXPECT(vireo_async_admission_pressure_refresh(f.server,NULL,&f.report),VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_async_admission_pressure_refresh(f.server,&connection,NULL),VIREO_RESULT_INVALID_ARGUMENT);
    fault_t m={0}; vireo_async_admission_pressure_ops_t bad=model_ops; bad.inspect=NULL;
    EXPECT(vireo_async_admission_pressure_with_ops(f.server,&connection,&f.report,&bad,&m),VIREO_RESULT_INVALID_ARGUMENT);
    bad=model_ops; bad.set_read=NULL;
    EXPECT(vireo_async_admission_pressure_with_ops(f.server,&connection,&f.report,&bad,&m),VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_async_admission_pressure_with_ops(f.server,&connection,&f.report,NULL,&m),VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(m.inspect_calls==0 && state(&f).listener_read_enabled && state(&f).connection_count==0); finish_fixture(&f);
}
static void connection_ranges(void) {
    fixture_t f; prepare(&f,3,1152,true);
    vireo_connection_options_t cases[]={{SIZE_MAX,1,SIZE_MAX},{0,128,384},{256,0,384},{256,128,0},
        {VIREO_BUFFER_MAX_CAPACITY+1,1,384},{1,VIREO_BUFFER_MAX_CAPACITY+1,384},
        {256,128,VIREO_CONNECTION_MAX_BUFFER_BYTES+1},{256,128,383},{1024,256,1280}};
    for (size_t i=0;i<sizeof cases/sizeof cases[0];++i) {
        refresh(&f,&cases[i],i==0?VIREO_RESULT_OVERFLOW:VIREO_RESULT_RANGE);
        CHECK(!f.report.pressure_calculated && !f.report.update_called && state(&f).listener_read_enabled);
        if (i<8) CHECK(!f.report.server_inspected && f.report.pair_bytes==0 && f.report.stage==VIREO_ASYNC_ADMISSION_PRESSURE_VALIDATE_OPTIONS);
        else CHECK(f.report.server_inspected && f.report.pair_bytes==1280 && f.report.stage==VIREO_ASYNC_ADMISSION_PRESSURE_CHECK_CAPACITY);
    }
    finish_fixture(&f);
    prepare(&f,1,VIREO_CONNECTION_MAX_BUFFER_BYTES,true);
    vireo_connection_options_t const max={VIREO_BUFFER_MAX_CAPACITY-1,1,VIREO_CONNECTION_MAX_BUFFER_BYTES};
    refresh(&f,&max,VIREO_OK); CHECK(f.report.pair_bytes==VIREO_CONNECTION_MAX_BUFFER_BYTES && !f.report.buffer_limited);
    vireo_connection_options_t const min={1,1,2}; refresh(&f,&min,VIREO_OK); CHECK(f.report.pair_bytes==2);
    finish_fixture(&f); /* 本层不验证flow，不申请这些大buffer。 */
}
static void no_change_and_restore(void) {
    fixture_t f; prepare(&f,3,1152,true); fault_t m={0}; model(&f,&m,VIREO_OK);
    CHECK(m.inspect_calls==1 && m.set_calls==0 && f.report.pressure_calculated && f.report.read_before && f.report.read_after);
    CHECK(f.report.available_connections==3 && f.report.available_buffer_bytes==1152);
    EXPECT(vireo_tcp_server_set_listener_read_enabled(f.server,false,NULL),VIREO_OK);
    model(&f,&m,VIREO_OK); CHECK(m.set_calls==1 && m.requested && !f.report.read_before && f.report.read_after && f.report.update_called);
    model(&f,&m,VIREO_OK); CHECK(m.set_calls==1 && !f.report.update_called); finish_fixture(&f);
}
static void connection_full_and_reuse(void) {
    for (size_t bytes=384;bytes<=768;bytes+=384) {
        fixture_t f; prepare(&f,1,bytes,true); connect_clients(&f,2); admit(&f,1);
        refresh(&f,&connection,VIREO_OK); CHECK(f.report.connection_limited && f.report.buffer_limited==(bytes==384));
        CHECK(f.report.update_called && !f.report.read_after && !state(&f).listener_read_enabled);
        refresh(&f,&connection,VIREO_OK); CHECK(!f.report.update_called);
        vireo_connection_pool_lease_t const old=f.live[0];
        EXPECT(vireo_tcp_server_release_client(f.server,&f.live[0],NULL),VIREO_OK);
        CHECK(!state(&f).listener_read_enabled && state(&f).buffer_capacity_bytes==0);
        refresh(&f,&connection,VIREO_OK); CHECK(f.report.update_called && f.report.read_after);
        admit(&f,1); CHECK(old.slot_index==f.live[1].slot_index && old.generation!=f.live[1].generation);
        vireo_tcp_server_client_info_t info; EXPECT(vireo_tcp_server_client_inspect(f.server,old,&info),VIREO_RESULT_NOT_FOUND);
        refresh(&f,&connection,VIREO_OK); CHECK(!f.report.read_after); finish_fixture(&f);
    }
}
static void buffer_quota(void) {
    fixture_t f; prepare(&f,3,767,true); connect_clients(&f,2); admit(&f,1);
    refresh(&f,&connection,VIREO_OK); CHECK(!f.report.connection_limited && f.report.buffer_limited && f.report.available_buffer_bytes==383);
    CHECK(!f.report.read_after && f.report.update_called);
    EXPECT(vireo_tcp_server_release_client(f.server,&f.live[0],NULL),VIREO_OK);
    refresh(&f,&connection,VIREO_OK); CHECK(f.report.read_after && f.report.available_buffer_bytes==767);
    admit(&f,1); refresh(&f,&connection,VIREO_OK); CHECK(!f.report.read_after); finish_fixture(&f);
    prepare(&f,3,768,true); connect_clients(&f,2); admit(&f,1);
    refresh(&f,&connection,VIREO_OK); CHECK(f.report.available_buffer_bytes==384 && !f.report.buffer_limited && f.report.read_after);
    admit(&f,1); refresh(&f,&connection,VIREO_OK); CHECK(f.report.buffer_limited && !f.report.connection_limited); finish_fixture(&f);
}
static void explicit_next_capacity(void) {
    fixture_t f; prepare(&f,3,768,true); connect_clients(&f,1); admit(&f,1);
    vireo_connection_options_t const larger={384,128,512};
    refresh(&f,&larger,VIREO_OK); CHECK(f.report.buffer_limited && !f.report.read_after && f.report.pair_bytes==512);
    refresh(&f,&connection,VIREO_OK); CHECK(!f.report.buffer_limited && f.report.read_after && f.report.pair_bytes==384);
    CHECK(state(&f).buffer_capacity_bytes==384); finish_fixture(&f);
}
static void io_no_refund(void) {
    fixture_t f; prepare(&f,3,384,true); connect_clients(&f,1); admit(&f,1); refresh(&f,&connection,VIREO_OK);
    uint8_t const bytes[4]={1,2,3,4}; CHECK(send(f.peers[0],bytes,4,MSG_NOSIGNAL)==4);
    vireo_connection_receive_budget_t const rb={4,2}; vireo_connection_receive_info_t ri;
    EXPECT(vireo_tcp_server_client_receive(f.server,f.live[0],&rb,&ri,NULL),VIREO_OK); CHECK(ri.received_bytes==4);
    EXPECT(vireo_tcp_server_client_read_consume(f.server,f.live[0],4,NULL),VIREO_OK);
    EXPECT(vireo_tcp_server_client_write_enqueue(f.server,f.live[0],bytes,4,NULL),VIREO_OK);
    vireo_connection_send_budget_t const sb={4,2}; vireo_connection_send_info_t si;
    EXPECT(vireo_tcp_server_client_send(f.server,f.live[0],&sb,&si,NULL),VIREO_OK); CHECK(si.sent_bytes==4);
    uint8_t actual[4]; CHECK(recv(f.peers[0],actual,4,MSG_WAITALL)==4 && memcmp(actual,bytes,4)==0);
    CHECK(shutdown(f.peers[0],SHUT_WR)==0);
    EXPECT(vireo_tcp_server_client_receive(f.server,f.live[0],&rb,&ri,NULL),VIREO_OK);
    CHECK(ri.stop_reason==VIREO_CONNECTION_RECEIVE_STOP_EOF && ri.received_bytes==0);
    refresh(&f,&connection,VIREO_OK); CHECK(!f.report.read_after && f.report.buffer_limited && f.report.available_buffer_bytes==0);
    CHECK(state(&f).buffer_capacity_bytes==384 && state(&f).connection_count==1); finish_fixture(&f);
}
static void close_no_refund(void) {
    fixture_t f; prepare(&f,3,384,true); connect_clients(&f,1); admit(&f,1);
    EXPECT(vireo_tcp_server_client_request_close(f.server,f.live[0],VIREO_CONNECTION_CLOSE_MODE_IMMEDIATE,
        VIREO_CONNECTION_CLOSE_REASON_APPLICATION,NULL),VIREO_OK);
    refresh(&f,&connection,VIREO_OK); CHECK(f.report.buffer_limited && !f.report.read_after && state(&f).connection_count==1);
    EXPECT(vireo_tcp_server_release_client(f.server,&f.live[0],NULL),VIREO_OK);
    refresh(&f,&connection,VIREO_OK); CHECK(f.report.read_after && state(&f).connection_count==0); finish_fixture(&f);
}
static void missing_listener(void) {
    fixture_t f; prepare(&f,3,1152,false); refresh(&f,&connection,VIREO_RESULT_NOT_FOUND);
    CHECK(f.report.server_inspected && !f.report.pressure_calculated && !f.report.update_called); finish_fixture(&f);
    f=(fixture_t){0}; vireo_tcp_server_options_t const o={1,2,1048576,384};
    EXPECT(vireo_tcp_server_create(&o,&f.server,NULL),VIREO_OK); refresh(&f,&connection,VIREO_RESULT_NOT_FOUND); finish_fixture(&f);
}
static void automatic_policy(void) {
    fixture_t f; prepare(&f,3,1152,true); vireo_tcp_server_admission_options_t const o={connection,flow};
    EXPECT(vireo_tcp_server_admission_configure(f.server,&o,NULL),VIREO_OK);
    refresh(&f,&connection,VIREO_RESULT_BUSY); CHECK(!f.report.pressure_calculated && state(&f).admission_enabled);
    EXPECT(vireo_tcp_server_admission_disable(f.server,NULL),VIREO_OK);
    refresh(&f,&connection,VIREO_OK); CHECK(f.report.read_after && !state(&f).admission_enabled); finish_fixture(&f);
}
static void stopped_server(void) {
    fixture_t f; prepare(&f,3,1152,true); EXPECT(vireo_tcp_server_request_stop(f.server,NULL),VIREO_OK);
    refresh(&f,&connection,VIREO_RESULT_CANCELLED); CHECK(f.report.read_after && !f.report.update_called);
    vireo_connection_options_t const bad={0,128,384}; refresh(&f,&bad,VIREO_RESULT_RANGE); CHECK(!f.report.server_inspected);
    fault_t m={.active_mask=1}; model(&f,&m,VIREO_RESULT_BUSY); CHECK(m.set_calls==0); finish_fixture(&f);
}
static void active_and_inspect_error(void) {
    fixture_t f; prepare(&f,3,1152,true);
    for (unsigned bit=1;bit<=64;bit*=2) { fault_t m={.active_mask=bit}; model(&f,&m,VIREO_RESULT_BUSY);
        CHECK(m.inspect_calls==1 && m.set_calls==0 && !f.report.pressure_calculated && f.report.server_inspected); }
    fault_t m={.inspect_error=true}; model(&f,&m,VIREO_RESULT_IO);
    CHECK(!f.report.server_inspected && f.report.stage==VIREO_ASYNC_ADMISSION_PRESSURE_CHECK_SERVER && !f.report.pressure_calculated);
    finish_fixture(&f);
}
static void ledger_models(void) {
    fixture_t f; prepare(&f,3,1152,true);
    for (unsigned i=1;i<=3;++i) { fault_t m={.ledger=i}; model(&f,&m,VIREO_RESULT_INTERNAL);
        CHECK(f.report.stage==VIREO_ASYNC_ADMISSION_PRESSURE_CHECK_CAPACITY && !f.report.pressure_calculated && m.set_calls==0); }
    CHECK(state(&f).connection_count==0 && state(&f).listener_read_enabled); finish_fixture(&f);
}
static void update_error(void) {
    fixture_t f; prepare(&f,3,384,true); connect_clients(&f,1); admit(&f,1);
    fault_t m={.update_error=true}; model(&f,&m,VIREO_RESULT_IO);
    CHECK(m.set_calls==1 && !m.requested && f.report.update_called && f.report.pressure_calculated);
    CHECK(f.report.read_before && f.report.read_after && !f.report.read_desired && f.report.buffer_limited);
    CHECK(f.report.stage==VIREO_ASYNC_ADMISSION_PRESSURE_UPDATE_READ &&
        f.report.listener_error.stage==VIREO_TCP_SERVER_LISTENER_UPDATE &&
        f.report.listener_error.acceptor_error.loop_error.epoll_error.system_errno==EBADF);
    m.update_error=false; model(&f,&m,VIREO_OK); CHECK(m.set_calls==2 && !f.report.read_after);
    EXPECT(vireo_tcp_server_release_client(f.server,&f.live[0],NULL),VIREO_OK);
    m.update_error=true; model(&f,&m,VIREO_RESULT_IO);
    CHECK(m.set_calls==3 && m.requested && !f.report.read_before && !f.report.read_after && f.report.read_desired);
    m.update_error=false; model(&f,&m,VIREO_OK); CHECK(m.set_calls==4 && f.report.read_after); finish_fixture(&f);
}
static void late_stop(void) {
    fixture_t f; prepare(&f,3,1152,true);
    EXPECT(vireo_tcp_server_set_listener_read_enabled(f.server,false,NULL),VIREO_OK);
    fault_t m={.stop_after_inspect=true}; model(&f,&m,VIREO_OK);
    CHECK(m.set_calls==1 && f.report.read_after && state(&f).stop_requested); /* 真stop不恢复loop。 */
    refresh(&f,&connection,VIREO_RESULT_CANCELLED); CHECK(!f.report.update_called); finish_fixture(&f);
}
int main(void) {
    int old; CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,&old)==0);
    void (*const tests[])(void)={parameters,connection_ranges,no_change_and_restore,connection_full_and_reuse,
        buffer_quota,explicit_next_capacity,io_no_refund,close_no_refund,missing_listener,automatic_policy,
        stopped_server,active_and_inspect_error,ledger_models,update_error,late_stop};
    for (size_t i=0;i<sizeof tests/sizeof tests[0];++i) { unsigned const before=fd_count(); tests[i](); CHECK(fd_count()==before); }
    CHECK(pthread_setcancelstate(old,NULL)==0);
    puts("async admission pressure: 15 groups, 0 failures"); return 0;
}
