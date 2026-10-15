/*
 * PROJECT : VIREO
 * FILE    : test_async_pending_recovery.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-15
 * BRIEF   : 三阶段续接、真实消费/流控/FIFO及清楚标记的故障前沿模型
 */
#define _GNU_SOURCE
#include "net/async_pending_recovery_internal.h"
#include <vireo/net/async_admission.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"%s:%d: %s\n",__FILE__,__LINE__,#x); abort(); } } while (0)
#define EXPECT(x,y) do { errno=EDOM; vireo_result_t const result_=(x); CHECK(result_==(y) && errno==EDOM); } while (0)
#define CONSUME VIREO_ASYNC_PENDING_STEP_CONSUME
#define REFRESH VIREO_ASYNC_PENDING_STEP_REFRESH
#define SCHEDULE VIREO_ASYNC_PENDING_STEP_SCHEDULE
#define DONE VIREO_ASYNC_PENDING_STEP_DONE

/** worker仅独立task/不可变预期，不持有server或客户fd。 */
typedef struct worker {
    pthread_barrier_t entered; /**< 空预热任务已领取、队列锁已释放。 */
    pthread_barrier_t released; /**< main允许预热返回，再执行真实数据副本。 */
    uint8_t expected[35]; /**< 首个原wire帧的独立预期，启动前填写，不再改。 */
    unsigned calls; /**< 数据回调次数，仅worker写、join后main读。 */
    vireo_task_metadata_t seen; /**< 数据task原metadata，join后才观察。 */
} worker_t;
/** main所有公开资源和源字节；pending来源模型在prepare_at明确区分。 */
typedef struct fixture {
    vireo_tcp_server_t *server; /**< 唯一网络root owner。 */
    struct sockaddr_in address; /**< 真实临时loopback监听端点。 */
    int peers[2]; /**< main对端fd owner，第二项仅代际复用测试。 */
    size_t peer_count; /**< 已打开peer前缀，≤2。 */
    vireo_connection_pool_lease_t client; /**< 当前客户完整数值，release清值。 */
    uint8_t wire[70]; /**< 两个35字节有效REQUEST，caller独立原文。 */
    vireo_async_request_pending_t pending; /**< 测试消费前沿模型；真实独立task转移但未consume。 */
    vireo_task_metadata_t original; /**< 真实转移metadata或纯形态模型，清pending后仍保。 */
    vireo_inflight_store_t *store; /**< 仅真实转移组有的固定登记表owner。 */
    vireo_task_queue_t *tasks; /**< 专用固定task queue owner，pool借用。 */
    vireo_thread_pool_t *pool; /**< 真实固定单worker，先停驻预热。 */
    worker_t worker; /**< 原位稳定上下文，pool销毁后才销毁barrier。 */
    bool record_taken; /**< caller是否已显式take原登记，cleanup不重复take。 */
    vireo_async_pending_recovery_report_t report; /**< 当前调用完整报告，不保活资源。 */
} fixture_t;
/** 只本层公开三边界故障，不包含外模块private。 */
typedef struct fault {
    char order[8]; /**< C/F/S调用轨迹，尾保持零。 */
    size_t calls; /**< 轨迹有效长度，本次≤3。 */
    unsigned consumes; /**< consume边界调用累计数。 */
    unsigned refreshes; /**< flow边界调用累计数。 */
    unsigned schedules; /**< schedule边界调用累计数。 */
    vireo_result_t consume_error; /**< 无变更消费错误模型，0不注入。 */
    vireo_result_t refresh_error; /**< 无变更刷新错误模型，0不注入。 */
    vireo_result_t schedule_error; /**< 无变更排队错误模型，0不注入。 */
} fault_t;
static vireo_connection_options_t const connection={128,128,256};
static vireo_connection_flow_options_t const flow={64,63,64,32,96};
static bool same(vireo_connection_pool_lease_t a,vireo_connection_pool_lease_t b) {
    return a.pool_id==b.pool_id && a.slot_index==b.slot_index && a.generation==b.generation;
}
static bool metadata_same(vireo_task_metadata_t a,vireo_task_metadata_t b) {
    bool yes=false; EXPECT(vireo_task_metadata_same_request(a,b,&yes),VIREO_OK);
    return yes && a.operation==b.operation && a.deadline_ns==b.deadline_ns;
}
static bool empty(vireo_async_request_pending_t const *p) {
    vireo_task_metadata_t const m=p->metadata;
    return p->frame_bytes==0 && m.route.client_owner_id==0 && m.route.client_slot_index==0 &&
        m.route.client_generation==0 && m.route.request_sequence==0 && m.request_instance_id==0 && m.operation==0 && m.deadline_ns==0;
}
static unsigned fd_count(void) {
    DIR *d=opendir("/proc/self/fd"); CHECK(d!=NULL); unsigned n=0; struct dirent *p;
    while ((p=readdir(d))!=NULL) if (p->d_name[0]!='.') ++n;
    CHECK(closedir(d)==0); return n;
}
static void meet(pthread_barrier_t *b) { int const r=pthread_barrier_wait(b); CHECK(r==0 || r==PTHREAD_BARRIER_SERIAL_THREAD); }
static vireo_result_t execute(void *context,vireo_task_t const *task) {
    worker_t *w=context; vireo_task_payload_view_t v; EXPECT(vireo_task_borrow_payload(task,&v),VIREO_OK);
    if (v.size==0) { meet(&w->entered); meet(&w->released); return VIREO_OK; }
    CHECK(v.size==35 && memcmp(v.data,w->expected,35)==0);
    vireo_task_info_t info; EXPECT(vireo_task_inspect(task,&info),VIREO_OK); ++w->calls; w->seen=info.metadata;
    return VIREO_OK;
}
static vireo_result_t shutdown_pool(vireo_thread_pool_t *pool,vireo_thread_pool_shutdown_report_t *report) {
    int const saved=errno;
    for (size_t i=0;i<1000000;++i) {
        vireo_result_t const result=vireo_thread_pool_shutdown_and_join(pool,VIREO_TASK_QUEUE_DRAIN,report);
        bool const close_busy=result==VIREO_RESULT_BUSY && report->stage==VIREO_THREAD_POOL_SHUTDOWN_STAGE_CLOSE_QUEUE &&
            report->close_called && !report->join_called && !report->close_report.changed &&
            report->close_report.stage==VIREO_TASK_QUEUE_STAGE_LOCK && report->close_report.pthread_error==EBUSY;
        bool const inspect_busy=result==VIREO_RESULT_BUSY && report->stage==VIREO_THREAD_POOL_SHUTDOWN_STAGE_JOIN_WORKERS &&
            report->close_called && report->join_called && report->close_report.stage==VIREO_TASK_QUEUE_STAGE_NONE &&
            report->close_report.pthread_error==0 && report->pool_report.stage==VIREO_THREAD_POOL_STAGE_CHECK_QUEUE &&
            !report->pool_report.stop_requested && report->pool_report.joined_count==0 && report->pool_report.pthread_error==0;
        bool const retry=close_busy || inspect_busy;
        if (!retry) {
            if (result!=VIREO_OK) fprintf(stderr,"shutdown result=%d stage=%d close=%d changed=%d lockstage=%d pthread=%d join=%d\n",
                (int)result,(int)report->stage,(int)report->close_called,(int)report->close_report.changed,
                (int)report->close_report.stage,report->close_report.pthread_error,(int)report->join_called);
            errno=saved; return result;
        }
        if (i==0) fputs("test caller: confirmed close/queue-inspect contention before worker stop/join, bounded retry\n",stderr);
        sched_yield();
    }
    errno=saved; return VIREO_RESULT_BUSY;
}

static vireo_tcp_server_client_info_t info(fixture_t *f) {
    vireo_tcp_server_client_info_t i; EXPECT(vireo_tcp_server_client_inspect(f->server,f->client,&i),VIREO_OK); return i;
}
static void bytes_are(fixture_t *f,size_t count,size_t offset) {
    uint8_t const *data=NULL; size_t size=0;
    EXPECT(vireo_tcp_server_client_read_peek(f->server,f->client,&data,&size,NULL),VIREO_OK);
    CHECK(size==count && (count==0 || memcmp(data,f->wire+offset,count)==0)); /* 借用在返回前结束。 */
}
static void encode(uint8_t *out,uint32_t sequence) {
    vireo_protocol_header_t h={.command=VIREO_COMMAND_NODE_STAT,.sequence=sequence,.body_len=3};
    out[32]=(uint8_t)sequence; out[33]=0; out[34]=0xA5;
    EXPECT(vireo_protocol_header_encode(&h,out,32),VIREO_OK);
    EXPECT(vireo_protocol_frame_crc32c_calculate(out,32,out+32,3,&h.crc32c),VIREO_OK);
    EXPECT(vireo_protocol_header_encode(&h,out,32),VIREO_OK);
}
static void connect_peer(fixture_t *f) {
    CHECK(f->peer_count<2); int const fd=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0); CHECK(fd>=0);
    CHECK(connect(fd,(struct sockaddr *)&f->address,sizeof f->address)==0); f->peers[f->peer_count++]=fd;
}
static void setup_pool(fixture_t *f) {
    vireo_inflight_store_options_t const so={2,65536}; EXPECT(vireo_inflight_store_create(&so,&f->store),VIREO_OK);
    vireo_task_queue_options_t const qo={3,65536}; EXPECT(vireo_task_queue_create(&qo,&f->tasks),VIREO_OK); EXPECT(vireo_task_queue_prepare_wait(f->tasks),VIREO_OK);
    CHECK(pthread_barrier_init(&f->worker.entered,NULL,2)==0 && pthread_barrier_init(&f->worker.released,NULL,2)==0);
    memcpy(f->worker.expected,f->wire,35);
    vireo_thread_pool_options_t const po={1,65536}; EXPECT(vireo_thread_pool_create(&po,&f->pool),VIREO_OK);
    vireo_thread_pool_configuration_t const config={f->tasks,execute,&f->worker}; EXPECT(vireo_thread_pool_configure(f->pool,&config,NULL),VIREO_OK);
    vireo_task_route_t route; vireo_task_metadata_t metadata; vireo_task_t *warm=NULL;
    EXPECT(vireo_task_route_make(UINT64_MAX,0,1,1,&route),VIREO_OK); EXPECT(vireo_task_metadata_make(route,1,1,UINT64_MAX,&metadata),VIREO_OK);
    EXPECT(vireo_task_create_copy(metadata,NULL,0,4096,&warm),VIREO_OK); vireo_task_queue_transfer_report_t qr;
    EXPECT(vireo_task_queue_try_push(f->tasks,&warm,&qr),VIREO_OK); vireo_thread_pool_report_t pr;
    EXPECT(vireo_thread_pool_start(f->pool,&pr),VIREO_OK); EXPECT(vireo_thread_pool_enable_execution(f->pool,&pr),VIREO_OK); meet(&f->worker.entered);
}
static void prepare_at(fixture_t *f,bool transferred,uint64_t deadline) {
    *f=(fixture_t){.peers={-1,-1}}; encode(f->wire,101); encode(f->wire+35,102);
    vireo_tcp_server_options_t const so={1,4,1048576,256}; EXPECT(vireo_tcp_server_create(&so,&f->server,NULL),VIREO_OK);
    int fd=socket(AF_INET,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0); CHECK(fd>=0);
    f->address=(struct sockaddr_in){.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
    CHECK(bind(fd,(struct sockaddr *)&f->address,sizeof f->address)==0 && listen(fd,2)==0);
    socklen_t len=sizeof f->address; CHECK(getsockname(fd,(struct sockaddr *)&f->address,&len)==0);
    vireo_acceptor_t *a=NULL; vireo_acceptor_options_t const ao={4096}; EXPECT(vireo_acceptor_create(&ao,&fd,&a,NULL),VIREO_OK);
    EXPECT(vireo_tcp_server_adopt_listener(f->server,&a,NULL),VIREO_OK); EXPECT(vireo_tcp_server_bind_listener(f->server,true,NULL),VIREO_OK);
    connect_peer(f); vireo_tcp_server_admit_budget_t const b={1,2}; vireo_async_admission_turn_t turn; vireo_async_admission_report_t ar;
    EXPECT(vireo_async_admission_once(f->server,&connection,&flow,&b,&f->client,1,&turn,1,&ar),VIREO_OK); CHECK(ar.scheduled_count==1);
    vireo_tcp_server_ready_client_t ready; vireo_tcp_server_poll_report_t poll;
    EXPECT(vireo_tcp_server_poll_ready_once(f->server,0,1,&ready,1,&poll),VIREO_OK); CHECK(poll.selected_count==1);
    CHECK(send(f->peers[0],f->wire,70,MSG_NOSIGNAL)==70);
    vireo_connection_receive_budget_t const rb={70,4}; vireo_connection_receive_info_t received;
    EXPECT(vireo_tcp_server_client_receive(f->server,f->client,&rb,&received,NULL),VIREO_OK); CHECK(received.received_bytes==70);
    EXPECT(vireo_tcp_server_client_flow_refresh(f->server,f->client,NULL),VIREO_OK); CHECK(info(f).connection_info.read_pressure);
    if (transferred) {
        setup_pool(f); uint8_t const *data=NULL; size_t size=0;
        EXPECT(vireo_tcp_server_client_read_peek(f->server,f->client,&data,&size,NULL),VIREO_OK); CHECK(size==70);
        vireo_task_t *remaining=NULL; vireo_async_request_report_t report;
        EXPECT(vireo_async_request_copy_try_submit(f->server,f->client,f->store,f->pool,data,35,64,4096,2,9,deadline,NULL,&remaining,&report),VIREO_OK);
        CHECK(remaining==NULL && report.task_transferred); f->original=report.metadata;
        /* 真实03101已复制/登记/移交，输入未消费。以下仅模型03102消费失败前沿，
         * 没有声称03102自然返回错误，不包含其private或篡改已消费源。 */
    } else {
        EXPECT(vireo_inflight_metadata_make_next(f->server,f->client,101,9,deadline,&f->original,NULL),VIREO_OK);
        /* 仅纯形态/基本拒绝组，不声称任务移交；资源边界由本层seam阻止。 */
    }
    f->pending=(vireo_async_request_pending_t){f->original,35}; bytes_are(f,70,0);
}
static void prepare(fixture_t *f,bool transferred) { prepare_at(f,transferred,UINT64_MAX); }
static void take_record(fixture_t *f) {
    CHECK(f->store!=NULL && !f->record_taken); vireo_task_metadata_t out;
    EXPECT(vireo_inflight_store_take(f->store,f->original,&out,NULL),VIREO_OK); CHECK(metadata_same(out,f->original)); f->record_taken=true;
}
static void finish(fixture_t *f) {
    if (f->pool!=NULL) {
        meet(&f->worker.released); vireo_thread_pool_shutdown_report_t sr; EXPECT(shutdown_pool(f->pool,&sr),VIREO_OK);
        CHECK(f->worker.calls==1 && metadata_same(f->worker.seen,f->original));
        vireo_thread_pool_worker_result_t wr; EXPECT(vireo_thread_pool_inspect_worker_result(f->pool,0,&wr),VIREO_OK); CHECK(wr.result==VIREO_OK);
        if (!f->record_taken) take_record(f);
        EXPECT(vireo_thread_pool_destroy(&f->pool),VIREO_OK); EXPECT(vireo_task_queue_destroy(&f->tasks),VIREO_OK);
        EXPECT(vireo_inflight_store_destroy(&f->store),VIREO_OK);
        CHECK(pthread_barrier_destroy(&f->worker.entered)==0 && pthread_barrier_destroy(&f->worker.released)==0);
    }
    if (f->client.pool_id!=0) EXPECT(vireo_tcp_server_release_client(f->server,&f->client,NULL),VIREO_OK);
    /* 客户已明确归还，原pending模型/审计original随夹具退出，不伪称消费成功。 */
    for (size_t i=0;i<f->peer_count;++i) CHECK(close(f->peers[i])==0);
    EXPECT(vireo_tcp_server_destroy(&f->server,NULL),VIREO_OK);
}
static void trace(fault_t *f,char c) { CHECK(f->calls+1<sizeof f->order); f->order[f->calls++]=c; errno=ERANGE; }
static vireo_result_t fault_consume(void *ctx,vireo_tcp_server_t *s,vireo_async_request_pending_t *p,vireo_async_request_head_report_t *r) {
    fault_t *f=ctx; trace(f,'C'); ++f->consumes;
    if (f->consume_error!=VIREO_OK) {
        *r=(vireo_async_request_head_report_t){.stage=VIREO_ASYNC_REQUEST_HEAD_CONSUME,.frame_bytes=p->frame_bytes,
            .pending_retained=true,.consume_called=true,.consume_result=f->consume_error,.pending_snapshot=*p};
        r->consume_error.primary.stage=VIREO_TCP_SERVER_CLIENT_READ_CONSUME; return f->consume_error;
    }
    return vireo_async_request_resume_consume(s,p,r);
}
static vireo_result_t fault_refresh(void *ctx,vireo_tcp_server_t *s,vireo_connection_pool_lease_t c,vireo_tcp_server_client_error_t *e) {
    fault_t *f=ctx; trace(f,'F'); ++f->refreshes;
    if (f->refresh_error!=VIREO_OK) {
        *e=(vireo_tcp_server_client_error_t){0}; e->primary.stage=VIREO_TCP_SERVER_CLIENT_FLOW_REFRESH;
        e->primary.loop_error.stage=VIREO_CONNECTION_LOOP_STAGE_FLOW_REFRESH;
        e->primary.loop_error.loop_error.stage=VIREO_EVENT_LOOP_STAGE_MOD;
        e->primary.loop_error.loop_error.epoll_error.stage=VIREO_EPOLL_STAGE_MOD;
        e->primary.loop_error.loop_error.epoll_error.system_errno=EIO;
        return f->refresh_error; /* 模型MOD诊断，未实际破坏内核注册。 */
    }
    return vireo_tcp_server_client_flow_refresh(s,c,e);
}
static vireo_result_t fault_schedule(void *ctx,vireo_tcp_server_t *s,vireo_connection_pool_lease_t c,vireo_tcp_server_client_error_t *e) {
    fault_t *f=ctx; trace(f,'S'); ++f->schedules;
    if (f->schedule_error!=VIREO_OK) { *e=(vireo_tcp_server_client_error_t){0}; return f->schedule_error; } /* 原在途BUSY无lookup诊断。 */
    return vireo_tcp_server_schedule_client(s,c,e);
}
static vireo_async_pending_recovery_ops_t const ops={fault_consume,fault_refresh,fault_schedule};
static void call(fixture_t *f,vireo_async_pending_recovery_step_t step,vireo_result_t result) {
    EXPECT(vireo_async_client_resume_pending(f->server,f->client,&f->pending,step,&f->report),result);
}
static void model(fixture_t *f,fault_t *fault,vireo_async_pending_recovery_step_t step,vireo_result_t result) {
    EXPECT(vireo_async_pending_recovery_with_ops(f->server,f->client,&f->pending,step,&f->report,&ops,fault),result);
}
static void no_calls(vireo_async_pending_recovery_report_t r) {
    CHECK(!r.consume_called && !r.refresh_called && !r.schedule_called && r.next_step==VIREO_ASYNC_PENDING_STEP_NONE);
    CHECK(same(r.client,(vireo_connection_pool_lease_t){0}));
}
static void done(fixture_t *f) {
    CHECK(f->report.stage==VIREO_ASYNC_PENDING_RECOVERY_NONE && f->report.next_step==DONE && same(f->report.client,f->client));
    CHECK(empty(&f->pending) && info(f).queued && !info(f).connection_info.read_pressure);
    bytes_are(f,35,35);
}

static void parameters(void) {
    fixture_t f; prepare(&f,false); fault_t fault={.consume_error=VIREO_RESULT_BUSY};
    EXPECT(vireo_async_client_resume_pending(NULL,f.client,&f.pending,CONSUME,&f.report),VIREO_RESULT_INVALID_ARGUMENT); no_calls(f.report);
    EXPECT(vireo_async_client_resume_pending(f.server,f.client,NULL,CONSUME,&f.report),VIREO_RESULT_INVALID_ARGUMENT); no_calls(f.report);
    EXPECT(vireo_async_client_resume_pending(f.server,f.client,&f.pending,CONSUME,NULL),VIREO_RESULT_INVALID_ARGUMENT);
    for (unsigned i=0;i<4;++i) {
        vireo_async_pending_recovery_ops_t broken=ops;
        if (i==0) broken.consume=NULL; else if (i==1) broken.refresh=NULL; else broken.schedule=NULL;
        EXPECT(vireo_async_pending_recovery_with_ops(f.server,f.client,&f.pending,CONSUME,&f.report,i==3?NULL:&broken,&fault),VIREO_RESULT_INVALID_ARGUMENT);
        no_calls(f.report); CHECK(f.report.stage==VIREO_ASYNC_PENDING_RECOVERY_NONE);
    }
    CHECK(fault.calls==0); bytes_are(&f,70,0); finish(&f);
}
static void invalid_starts(void) {
    fixture_t f; prepare(&f,false); fault_t fault={0};
    vireo_async_pending_recovery_step_t const steps[]={VIREO_ASYNC_PENDING_STEP_NONE,DONE,(vireo_async_pending_recovery_step_t)99};
    for (size_t i=0;i<sizeof steps/sizeof steps[0];++i) { model(&f,&fault,steps[i],VIREO_RESULT_INVALID_ARGUMENT); no_calls(f.report); }
    CHECK(fault.calls==0); finish(&f);
}
static void client_shapes(void) {
    fixture_t f; prepare(&f,false); fault_t fault={0};
    for (unsigned i=0;i<4;++i) {
        vireo_connection_pool_lease_t c=f.client;
        if (i==0) c=(vireo_connection_pool_lease_t){0}; else if (i==1) c.pool_id=0; else if (i==2) c.generation=0;
        else c=(vireo_connection_pool_lease_t){0,1,0};
        EXPECT(vireo_async_pending_recovery_with_ops(f.server,c,&f.pending,CONSUME,&f.report,&ops,&fault),i==0?VIREO_RESULT_NOT_FOUND:VIREO_RESULT_INVALID_ARGUMENT);
        no_calls(f.report); CHECK(f.report.stage==VIREO_ASYNC_PENDING_RECOVERY_CHECK_PENDING);
    }
    CHECK(fault.calls==0); finish(&f);
}
static void pending_shapes(void) {
    fixture_t f; prepare(&f,false); vireo_async_request_pending_t const saved=f.pending; fault_t fault={0};
    for (unsigned i=0;i<10;++i) {
        f.pending=saved;
        if (i==0) f.pending.frame_bytes=0; else if (i==1) f.pending.frame_bytes=31;
        else if (i==2) f.pending.frame_bytes=VIREO_ASYNC_REQUEST_MAX_FRAME_BYTES+1;
        else if (i==3) f.pending.metadata.route.client_owner_id=0; else if (i==4) f.pending.metadata.route.client_generation=0;
        else if (i==5) f.pending.metadata.route.request_sequence=0; else if (i==6) f.pending.metadata.request_instance_id=0;
        else if (i==7) f.pending.metadata.operation=0; else if (i==8) f.pending.metadata=(vireo_task_metadata_t){0};
        else { f.pending=(vireo_async_request_pending_t){0}; f.pending.metadata.deadline_ns=1; }
        vireo_async_request_pending_t const before=f.pending; model(&f,&fault,CONSUME,VIREO_RESULT_INVALID_ARGUMENT);
        no_calls(f.report); CHECK(memcmp(&before,&f.pending,sizeof before)==0 && fault.calls==0);
    }
    f.pending=saved; finish(&f);
}
static void empty_and_busy(void) {
    fixture_t f; prepare(&f,false); fault_t fault={0};
    model(&f,&fault,REFRESH,VIREO_RESULT_BUSY); no_calls(f.report);
    model(&f,&fault,SCHEDULE,VIREO_RESULT_BUSY); no_calls(f.report); f.pending=(vireo_async_request_pending_t){0};
    model(&f,&fault,CONSUME,VIREO_RESULT_NOT_FOUND); no_calls(f.report); CHECK(fault.calls==0); finish(&f);
}
static void association_priority(void) {
    fixture_t f; prepare(&f,false); fault_t fault={0}; vireo_async_request_pending_t const saved=f.pending;
    for (unsigned i=0;i<3;++i) {
        f.pending=saved;
        if (i==0) ++f.pending.metadata.route.client_owner_id; else if (i==1) ++f.pending.metadata.route.client_slot_index;
        else ++f.pending.metadata.route.client_generation;
        model(&f,&fault,REFRESH,VIREO_RESULT_INVALID_ARGUMENT); no_calls(f.report); CHECK(fault.calls==0);
    }
    f.pending=saved; finish(&f);
}
static void valid_numeric_frontier(void) {
    fixture_t f; prepare(&f,false); vireo_async_request_pending_t const saved=f.pending;
    for (unsigned i=0;i<4;++i) {
        f.pending=saved; f.pending.frame_bytes=i<2?32:VIREO_ASYNC_REQUEST_MAX_FRAME_BYTES;
        f.pending.metadata.deadline_ns=(i%2)==0?0:UINT64_MAX;
        fault_t fault={.consume_error=VIREO_RESULT_BUSY}; model(&f,&fault,CONSUME,VIREO_RESULT_BUSY);
        CHECK(fault.consumes==1 && fault.refreshes==0 && f.report.next_step==CONSUME);
        /* 只纯形态前沿模型，未按伪造帧长消费真实源。 */
    }
    f.pending=saved; finish(&f);
}
static void full_success(void) {
    fixture_t f; prepare(&f,true); vireo_async_request_pending_t const before=f.pending;
    call(&f,CONSUME,VIREO_OK); done(&f);
    CHECK(f.report.consume_called && f.report.refresh_called && f.report.schedule_called);
    CHECK(f.report.consume_result==VIREO_OK && f.report.refresh_result==VIREO_OK && f.report.schedule_result==VIREO_OK);
    CHECK(f.report.consume_report.consume_called && !f.report.consume_report.submit_called && !f.report.consume_report.frame_peek_called);
    CHECK(f.report.consume_report.pending_snapshot.frame_bytes==35 && metadata_same(f.report.consume_report.pending_snapshot.metadata,before.metadata));
    vireo_task_queue_info_t q; EXPECT(vireo_task_queue_inspect(f.tasks,&q),VIREO_OK); CHECK(q.count==1); finish(&f);
}
static void consume_failure(void) {
    fixture_t f; prepare(&f,true); vireo_async_request_pending_t const before=f.pending;
    fault_t fault={.consume_error=VIREO_RESULT_INTERNAL}; model(&f,&fault,CONSUME,VIREO_RESULT_INTERNAL);
    CHECK(strcmp(fault.order,"C")==0 && f.report.stage==VIREO_ASYNC_PENDING_RECOVERY_CONSUME && f.report.next_step==CONSUME);
    CHECK(memcmp(&before,&f.pending,sizeof before)==0 && !f.report.refresh_called && !f.report.schedule_called);
    CHECK(f.report.consume_report.consume_error.primary.stage==VIREO_TCP_SERVER_CLIENT_READ_CONSUME);
    bytes_are(&f,70,0); CHECK(info(&f).connection_info.read_pressure && !info(&f).queued);
    fault.consume_error=VIREO_OK; model(&f,&fault,f.report.next_step,VIREO_OK); done(&f); CHECK(fault.consumes==2); finish(&f);
}
static void refresh_failure_resume(void) {
    fixture_t f; prepare(&f,true); fault_t fault={.refresh_error=VIREO_RESULT_IO};
    model(&f,&fault,CONSUME,VIREO_RESULT_IO);
    CHECK(strcmp(fault.order,"CF")==0 && f.report.stage==VIREO_ASYNC_PENDING_RECOVERY_REFRESH && f.report.next_step==REFRESH);
    CHECK(empty(&f.pending) && f.report.consume_report.consume_called && !f.report.schedule_called);
    CHECK(f.report.refresh_error.primary.stage==VIREO_TCP_SERVER_CLIENT_FLOW_REFRESH &&
        f.report.refresh_error.primary.loop_error.loop_error.epoll_error.system_errno==EIO);
    CHECK(info(&f).connection_info.read_pressure && !info(&f).queued); bytes_are(&f,35,35);
    vireo_connection_pool_lease_t const remembered=f.report.client;
    fault.refresh_error=VIREO_OK; model(&f,&fault,f.report.next_step,VIREO_OK); done(&f);
    CHECK(same(remembered,f.report.client) && strcmp(fault.order,"CFFS")==0 && fault.consumes==1 && fault.refreshes==2);
    CHECK(!f.report.consume_called && !f.report.consume_report.consume_called); finish(&f);
}
static void schedule_failure_resume(void) {
    fixture_t f; prepare(&f,true); fault_t fault={.schedule_error=VIREO_RESULT_BUSY};
    model(&f,&fault,CONSUME,VIREO_RESULT_BUSY);
    CHECK(strcmp(fault.order,"CFS")==0 && f.report.stage==VIREO_ASYNC_PENDING_RECOVERY_SCHEDULE && f.report.next_step==SCHEDULE);
    CHECK(empty(&f.pending) && !info(&f).queued && !info(&f).connection_info.read_pressure); bytes_are(&f,35,35);
    CHECK(f.report.schedule_error.primary.stage==VIREO_TCP_SERVER_CLIENT_NONE);
    fault.schedule_error=VIREO_OK; model(&f,&fault,f.report.next_step,VIREO_OK); done(&f);
    CHECK(strcmp(fault.order,"CFSS")==0 && fault.consumes==1 && fault.refreshes==1 && fault.schedules==2);
    CHECK(!f.report.consume_called && !f.report.refresh_called); finish(&f);
}
static void explicit_tail_starts(void) {
    for (unsigned i=0;i<2;++i) {
        fixture_t f; prepare(&f,true); vireo_async_request_head_report_t old;
        EXPECT(vireo_async_request_resume_consume(f.server,&f.pending,&old),VIREO_OK); bytes_are(&f,35,35);
        if (i==1) EXPECT(vireo_tcp_server_client_flow_refresh(f.server,f.client,NULL),VIREO_OK);
        fault_t fault={0}; model(&f,&fault,i==0?REFRESH:SCHEDULE,VIREO_OK); done(&f);
        CHECK(strcmp(fault.order,i==0?"FS":"S")==0 && !f.report.consume_called); finish(&f);
    }
}
static void reports_overwrite(void) {
    fixture_t f; prepare(&f,true); fault_t fault={.refresh_error=VIREO_RESULT_IO};
    model(&f,&fault,CONSUME,VIREO_RESULT_IO); CHECK(f.report.refresh_error.primary.stage==VIREO_TCP_SERVER_CLIENT_FLOW_REFRESH);
    fault.refresh_error=VIREO_OK; model(&f,&fault,REFRESH,VIREO_OK); done(&f);
    CHECK(f.report.refresh_error.primary.stage==VIREO_TCP_SERVER_CLIENT_NONE && f.report.consume_report.stage==VIREO_ASYNC_REQUEST_HEAD_NONE);
    CHECK(!f.report.consume_called && !f.report.consume_report.consume_called); call(&f,CONSUME,VIREO_RESULT_NOT_FOUND); no_calls(f.report);
    CHECK(f.report.refresh_error.primary.stage==VIREO_TCP_SERVER_CLIENT_NONE && !f.report.schedule_called); finish(&f);
}
static void closing_after_consume(void) {
    fixture_t f; prepare(&f,true);
    EXPECT(vireo_tcp_server_client_request_close(f.server,f.client,VIREO_CONNECTION_CLOSE_MODE_DRAIN,VIREO_CONNECTION_CLOSE_REASON_SERVER_STOP,NULL),VIREO_OK);
    call(&f,CONSUME,VIREO_RESULT_BUSY);
    CHECK(empty(&f.pending) && f.report.consume_called && f.report.refresh_called && !f.report.schedule_called && f.report.next_step==REFRESH);
    CHECK(f.report.stage==VIREO_ASYNC_PENDING_RECOVERY_REFRESH); bytes_are(&f,35,35);
    CHECK(info(&f).connection_info.close_state!=VIREO_CONNECTION_CLOSE_OPEN); finish(&f);
}
static void stopped_mechanical(void) {
    fixture_t f; prepare(&f,true); EXPECT(vireo_tcp_server_request_stop(f.server,NULL),VIREO_OK);
    call(&f,CONSUME,VIREO_OK); done(&f); vireo_tcp_server_ready_client_t ready; vireo_tcp_server_poll_report_t pr;
    EXPECT(vireo_tcp_server_poll_ready_once(f.server,0,1,&ready,1,&pr),VIREO_OK); CHECK(pr.stopped && pr.selected_count==0 && info(&f).queued); finish(&f);
}
static void flow_disabled(void) {
    fixture_t f; prepare(&f,true); EXPECT(vireo_tcp_server_client_flow_disable(f.server,f.client,NULL),VIREO_OK);
    call(&f,CONSUME,VIREO_RESULT_NOT_FOUND);
    CHECK(empty(&f.pending) && f.report.next_step==REFRESH && !f.report.schedule_called); bytes_are(&f,35,35);
    EXPECT(vireo_tcp_server_client_flow_configure(f.server,f.client,&flow,NULL),VIREO_OK);
    call(&f,REFRESH,VIREO_OK); done(&f); finish(&f);
}
static void stale_pending(void) {
    fixture_t f; prepare(&f,true); vireo_connection_pool_lease_t const old=f.client; vireo_async_request_pending_t const before=f.pending;
    EXPECT(vireo_tcp_server_release_client(f.server,&f.client,NULL),VIREO_OK);
    EXPECT(vireo_async_client_resume_pending(f.server,old,&f.pending,CONSUME,&f.report),VIREO_RESULT_NOT_FOUND);
    CHECK(f.report.consume_called && !f.report.refresh_called && f.report.next_step==CONSUME && memcmp(&before,&f.pending,sizeof before)==0);
    finish(&f);
}
static void reused_client(void) {
    fixture_t f; prepare(&f,true); vireo_connection_pool_lease_t const old=f.client;
    EXPECT(vireo_tcp_server_release_client(f.server,&f.client,NULL),VIREO_OK); connect_peer(&f);
    vireo_tcp_server_admit_budget_t const ab={1,2}; vireo_tcp_server_admit_info_t ai;
    EXPECT(vireo_tcp_server_admit_batch(f.server,&connection,&ab,&f.client,1,&ai,NULL),VIREO_OK); CHECK(ai.admitted_count==1);
    CHECK(old.pool_id==f.client.pool_id && old.slot_index==f.client.slot_index && old.generation!=f.client.generation);
    EXPECT(vireo_async_client_resume_pending(f.server,old,&f.pending,CONSUME,&f.report),VIREO_RESULT_NOT_FOUND);
    CHECK(f.report.next_step==CONSUME && !info(&f).queued);
    call(&f,CONSUME,VIREO_RESULT_INVALID_ARGUMENT); no_calls(f.report); CHECK(!info(&f).queued); finish(&f);
}
static void ended_registration(void) {
    fixture_t f; prepare(&f,true); take_record(&f);
    call(&f,CONSUME,VIREO_OK); done(&f); vireo_inflight_store_info_t si;
    EXPECT(vireo_inflight_store_inspect(f.store,&si),VIREO_OK); CHECK(si.count==0); finish(&f);
}
static void deadline_extremes(void) {
    for (unsigned i=0;i<2;++i) {
        fixture_t f; prepare_at(&f,true,i==0?0:UINT64_MAX);
        call(&f,CONSUME,VIREO_OK); done(&f); CHECK(f.report.consume_report.pending_snapshot.metadata.deadline_ns==(i==0?0:UINT64_MAX)); finish(&f);
    }
}
int main(void) {
    int old; CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,&old)==0);
    void (*const tests[])(void)={parameters,invalid_starts,client_shapes,pending_shapes,empty_and_busy,association_priority,
        valid_numeric_frontier,full_success,consume_failure,refresh_failure_resume,schedule_failure_resume,explicit_tail_starts,
        reports_overwrite,closing_after_consume,stopped_mechanical,flow_disabled,stale_pending,reused_client,ended_registration,deadline_extremes};
    for (size_t i=0;i<sizeof tests/sizeof tests[0];++i) { unsigned const n=fd_count(); tests[i](); CHECK(fd_count()==n); }
    CHECK(pthread_setcancelstate(old,NULL)==0); puts("async pending recovery: 20 groups, 0 failures"); return 0;
}
