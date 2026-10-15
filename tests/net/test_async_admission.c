/*
 * PROJECT : VIREO
 * FILE    : test_async_admission.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-14
 * BRIEF   : 真实接入/流控/FIFO与完整失败前缀，公开异步链核验
 */
#define _GNU_SOURCE
#include "net/async_admission_internal.h" /* 仅本层seam，无外private。 */
#include <vireo/net/async_round.h>
#include <vireo/net/completion_response_dispatch.h>
#include <vireo/net/notifier_server.h>
#include <vireo/thread/completion_publish.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"%s:%d: %s\n",__FILE__,__LINE__,#x); abort(); } } while (0)
#define EXPECT(x,y) do { errno=EDOM; vireo_result_t const result_=(x); CHECK(result_==(y) && errno==EDOM); } while (0)

/** main唯一持有的TCP夹具和客户数值记录，全部公开调用。 */
typedef struct fixture {
    vireo_tcp_server_t *server; /**< 唯一网络资源根owner。 */
    struct sockaddr_in address; /**< 临时loopback监听端点。 */
    int peers[3]; /**< 测试对端fd owner，-1为空。 */
    size_t connected; /**< peers有效前缀，≤3。 */
    vireo_connection_pool_lease_t live[3]; /**< 每次真实admitted保存，release清具体值。 */
    size_t live_count; /**< 已记录前缀，包含后来归还清空的位置。 */
    vireo_connection_pool_lease_t out[4]; /**< 本次全部admitted前缀，caller独立目标。 */
    vireo_async_admission_turn_t turns[4]; /**< 本次实际准备前缀，尾哨兵仅memcmp字节。 */
    vireo_async_admission_report_t report; /**< 新入口原进度，不保活资源。 */
} fixture_t;
/** 只新接线层公开边界模型，不改变外组件私有状态。 */
typedef struct fault {
    unsigned active_mask; /**< 七在途快照位模型；真实server不改变。 */
    bool inspect_error; /**< 公开只读观察错误模型。 */
    bool stop_after_inspect; /**< 快照后调用真实公开stop，验证不抢占批次。 */
    bool partial_admit; /**< 实际接入1项后呈现模拟第二次accept IO，非真实EMFILE。 */
    size_t flow_fail_at; /**< 0不注入，Nth flow无变更IO模型。 */
    size_t schedule_fail_at; /**< 0不注入，Nth排队无变更BUSY模型。 */
    size_t inspect_calls; /**< 本次公开边界尝试数。 */
    size_t flow_calls; /**< 原flow边界实际尝试数。 */
    size_t schedule_calls; /**< 原排队边界实际尝试数。 */
} fault_t;
/** caller按真实task移交保存原请求关联。 */
typedef struct entry {
    bool valid; /**< 已真实移交，非当前inflight证明。 */
    vireo_task_metadata_t metadata; /**< 原完整route/instance/固定快照。 */
    vireo_protocol_header_t header; /**< 原wire描述，非operation猜测。 */
    unsigned resolved; /**< 描述次数，仅main写。 */
} entry_t;
/** pool长期借用的worker上下文，绝无server/网络fd。 */
typedef struct worker {
    vireo_completion_queue_t *outputs; /**< caller owns，consumer配合，借至pool销毁。 */
    vireo_notifier_t *notifier; /**< 提示对象借到所有producer结束。 */
    pthread_barrier_t entered; /**< 空预热已领取且queue锁已释放。 */
    pthread_barrier_t release; /**< main允许预热callback返回。 */
    atomic_uint published; /**< release/acquire仅helper返回数，不等join。 */
    vireo_completion_publish_report_t reports[9]; /**< 每tag独立worker写，仅join后main读。 */
} worker_t;
/** 单Reactor/串行manager持有的完整公开接线夹具。 */
typedef struct world {
    fixture_t net; /**< 网络root、客户输出和对端都main owns。 */
    worker_t worker; /**< 原位稳定context，pool销毁后结束barriers。 */
    vireo_inflight_store_t *store; /**< 固定在途登记owner。 */
    vireo_task_queue_t *tasks; /**< 专用task queue owner，已prepare。 */
    vireo_thread_pool_t *pool; /**< 一个真实固定worker的owner。 */
    vireo_completion_queue_t *outputs; /**< main唯一consumer，8槽。 */
    vireo_notifier_t *notifier; /**< 先注销借用后destroy。 */
    vireo_event_loop_handle_t handle; /**< 原辅助注册完整数值。 */
    vireo_async_request_pending_t pending[3]; /**< 返回接入后caller为完整lease建立唯一稳定gate。 */
    entry_t entries[9]; /**< 原请求metadata/header账本，仅main使用。 */
    unsigned submitted; /**< 确认真实数据task转移数，非原admit数量。 */
    vireo_task_t *remaining; /**< 未转移task caller owner。 */
    vireo_completion_t *remaining_completion; /**< 原分发失败残留owner。 */
    uint8_t scratch[64]; /**< 响应编码workspace，main独占。 */
} world_t;
static vireo_connection_options_t const connection={256,128,384};
static vireo_connection_flow_options_t const flow={64,63,192,32,96};
static vireo_tcp_server_admit_budget_t const budget={3,8};
static bool lease_same(vireo_connection_pool_lease_t a, vireo_connection_pool_lease_t b) {
    return a.pool_id == b.pool_id && a.slot_index == b.slot_index && a.generation == b.generation;
}
static bool metadata_same(vireo_task_metadata_t a, vireo_task_metadata_t b) {
    bool same; EXPECT(vireo_task_metadata_same_request(a,b,&same), VIREO_OK);
    return same && a.operation == b.operation && a.deadline_ns == b.deadline_ns;
}
static unsigned fd_count(void) {
    DIR *d=opendir("/proc/self/fd"); CHECK(d != NULL); unsigned n=0; struct dirent *p;
    while ((p=readdir(d)) != NULL) if (p->d_name[0] != '.') ++n;
    CHECK(closedir(d)==0); return n;
}
static void meet(pthread_barrier_t *barrier) {
    int const r=pthread_barrier_wait(barrier); CHECK(r==0 || r==PTHREAD_BARRIER_SERIAL_THREAD);
}
static vireo_result_t execute(void *context,vireo_task_t const *task) {
    worker_t *w=context; vireo_task_payload_view_t view;
    EXPECT(vireo_task_borrow_payload(task,&view),VIREO_OK);
    if (view.size==0) { meet(&w->entered); meet(&w->release); return VIREO_OK; }
    CHECK(view.size==35 && view.data[32]>=1 && view.data[32]<=8);
    unsigned const tag=view.data[32]; vireo_protocol_header_t h; vireo_protocol_codec_issue_t issue;
    EXPECT(vireo_protocol_header_decode(view.data,32,&h,&issue),VIREO_OK);
    EXPECT(vireo_protocol_request_header_validate(&h,&issue),VIREO_OK);
    EXPECT(vireo_protocol_frame_crc32c_verify(view.data,32,view.data+32,3,&issue),VIREO_OK);
    CHECK(h.sequence==100+tag && h.command==(tag==2?VIREO_COMMAND_UPLOAD_STATUS:VIREO_COMMAND_NODE_STAT));
    CHECK(h.session_handle==0x12340000U+tag && h.task_handle==0x56780000U+tag && view.data[33]==0 && view.data[34]==0xA5);
    uint8_t const bytes[3]={(uint8_t)(tag^0x5AU),0x5A,0xFF}; vireo_completion_t *remaining=NULL;
    EXPECT(vireo_completion_copy_wait_publish(task,VIREO_OK,VIREO_STATUS_OK,bytes,3,4096,
        w->outputs,w->notifier,&remaining,&w->reports[tag]),VIREO_OK); CHECK(remaining==NULL);
    (void)atomic_fetch_add_explicit(&w->published,1,memory_order_release); return VIREO_OK;
}
static void published(world_t *w) {
    for (size_t i=0;i<1000000;++i) {
        if (atomic_load_explicit(&w->worker.published,memory_order_acquire)==w->submitted) return;
        sched_yield();
    }
    CHECK(false);
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
static void encode(uint8_t *wire,unsigned tag) {
    vireo_protocol_header_t h={.command=tag==2?VIREO_COMMAND_UPLOAD_STATUS:VIREO_COMMAND_NODE_STAT,
        .flags=tag==2?VIREO_PROTOCOL_FLAG_LONG_COMMAND:0,.body_len=3,.sequence=100+tag,
        .session_handle=0x12340000U+tag,.task_handle=0x56780000U+tag};
    wire[32]=(uint8_t)tag; wire[33]=0; wire[34]=0xA5;
    EXPECT(vireo_protocol_header_encode(&h,wire,32),VIREO_OK);
    EXPECT(vireo_protocol_frame_crc32c_calculate(wire,32,wire+32,3,&h.crc32c),VIREO_OK);
    EXPECT(vireo_protocol_header_encode(&h,wire,32),VIREO_OK);
}
static void send_all(int fd,uint8_t const *bytes,size_t count) {
    size_t n=0; while (n<count) { ssize_t const k=send(fd,bytes+n,count-n,MSG_NOSIGNAL); CHECK(k>0); n+=(size_t)k; }
}
static vireo_result_t resolve(void *context,vireo_completion_t const *completion,
    vireo_inflight_completion_match_t match,vireo_completion_response_descriptor_t *descriptor) {
    world_t *w=context; vireo_completion_info_t info; EXPECT(vireo_completion_inspect(completion,&info),VIREO_OK);
    CHECK(metadata_same(info.metadata.request,match.metadata));
    for (size_t i=1;i<=8;++i) if (w->entries[i].valid && metadata_same(w->entries[i].metadata,match.metadata)) {
        vireo_protocol_header_t const h=w->entries[i].header; ++w->entries[i].resolved;
        *descriptor=(vireo_completion_response_descriptor_t){h.command,h.flags,h.session_handle,h.task_handle}; return VIREO_OK;
    }
    CHECK(false); return VIREO_RESULT_NOT_FOUND;
}
static void check_response(world_t *w,size_t client,unsigned tag) {
    uint8_t bytes[35]; size_t n=0;
    for (size_t i=0;n<sizeof bytes && i<8;++i) {
        struct pollfd fd={w->net.peers[client],POLLIN,0}; CHECK(poll(&fd,1,1000)==1);
        ssize_t const k=recv(w->net.peers[client],bytes+n,sizeof bytes-n,MSG_DONTWAIT); CHECK(k>0); n+=(size_t)k;
    }
    CHECK(n==sizeof bytes); vireo_protocol_header_t h; vireo_protocol_codec_issue_t issue;
    EXPECT(vireo_protocol_header_decode(bytes,32,&h,&issue),VIREO_OK);
    EXPECT(vireo_protocol_frame_crc32c_verify(bytes,32,bytes+32,3,&issue),VIREO_OK);
    CHECK(h.sequence==100+tag && h.command==(tag==2?VIREO_COMMAND_UPLOAD_STATUS:VIREO_COMMAND_NODE_STAT));
    CHECK(h.flags==(uint16_t)((tag==2?VIREO_PROTOCOL_FLAG_LONG_COMMAND:0)|VIREO_PROTOCOL_FLAG_RESPONSE));
    CHECK(h.session_handle==0x12340000U+tag && h.task_handle==0x56780000U+tag && h.body_len==3 && h.status==VIREO_STATUS_OK);
    CHECK(bytes[32]==(uint8_t)(tag^0x5AU) && bytes[33]==0x5A && bytes[34]==0xFF && w->entries[tag].resolved==1);
}

static void prepare(fixture_t *f,size_t capacity,size_t buffer_budget,bool bind_listener) {
    *f=(fixture_t){.peers={-1,-1,-1}};
    vireo_tcp_server_options_t const options={capacity,8,1048576,buffer_budget};
    EXPECT(vireo_tcp_server_create_with_auxiliary_capacity(&options,1,&f->server,NULL),VIREO_OK);
    int fd=socket(AF_INET,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0); CHECK(fd>=0);
    f->address=(struct sockaddr_in){.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
    CHECK(bind(fd,(struct sockaddr *)&f->address,sizeof f->address)==0 && listen(fd,4)==0);
    socklen_t size=sizeof f->address; CHECK(getsockname(fd,(struct sockaddr *)&f->address,&size)==0);
    vireo_acceptor_t *listener=NULL; vireo_acceptor_options_t const ao={4096};
    EXPECT(vireo_acceptor_create(&ao,&fd,&listener,NULL),VIREO_OK);
    EXPECT(vireo_tcp_server_adopt_listener(f->server,&listener,NULL),VIREO_OK);
    if (bind_listener) EXPECT(vireo_tcp_server_bind_listener(f->server,true,NULL),VIREO_OK);
}
static void connect_clients(fixture_t *f,size_t count) {
    CHECK(f->connected+count<=3);
    for (size_t i=0;i<count;++i) {
        size_t const n=f->connected; f->peers[n]=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0); CHECK(f->peers[n]>=0);
        CHECK(connect(f->peers[n],(struct sockaddr *)&f->address,sizeof f->address)==0); ++f->connected;
    }
}
static vireo_tcp_server_info_t state(fixture_t *f) {
    vireo_tcp_server_info_t info; EXPECT(vireo_tcp_server_inspect(f->server,&info),VIREO_OK); return info;
}
static vireo_tcp_server_client_info_t client_info(fixture_t *f,size_t i) {
    vireo_tcp_server_client_info_t info; EXPECT(vireo_tcp_server_client_inspect(f->server,f->live[i],&info),VIREO_OK); return info;
}
static void remember(fixture_t *f) {
    CHECK(f->live_count+f->report.admission.admitted_count<=3);
    for (size_t i=0;i<f->report.admission.admitted_count;++i) {
        CHECK(f->out[i].pool_id!=0 && f->out[i].generation!=0);
        f->live[f->live_count++]=f->out[i];
    }
}
static void clear_output(fixture_t *f) {
    memset(f->out,0,sizeof f->out); /* 数值副本重置，既有资源身份已由live保存。 */
}
static void call(fixture_t *f,vireo_connection_options_t const *co,vireo_connection_flow_options_t const *fo,
    vireo_tcp_server_admit_budget_t const *b,size_t lease_cap,size_t turn_cap,vireo_result_t expected) {
    EXPECT(vireo_async_admission_once(f->server,co,fo,b,f->out,lease_cap,f->turns,turn_cap,&f->report),expected);
    remember(f);
}
static void finish(fixture_t *f) {
    for (size_t i=0;i<f->live_count;++i) if (f->live[i].pool_id!=0)
        EXPECT(vireo_tcp_server_release_client(f->server,&f->live[i],NULL),VIREO_OK);
    for (size_t i=0;i<f->connected;++i) CHECK(close(f->peers[i])==0);
    EXPECT(vireo_tcp_server_destroy(&f->server,NULL),VIREO_OK);
}
static vireo_result_t model_inspect(void *context,vireo_tcp_server_t const *s,vireo_tcp_server_info_t *info) {
    fault_t *f=context; ++f->inspect_calls; errno=ERANGE;
    if (f->inspect_error) return VIREO_RESULT_IO;
    vireo_result_t const result=vireo_tcp_server_inspect(s,info);
    if (result==VIREO_OK) {
        info->processing_active=(f->active_mask&1U)!=0; info->driving_active=(f->active_mask&2U)!=0;
        info->scheduling_active=(f->active_mask&4U)!=0; info->serving_active=(f->active_mask&8U)!=0;
        info->shutdown_active=(f->active_mask&16U)!=0; info->closing_active=(f->active_mask&32U)!=0;
        info->running_active=(f->active_mask&64U)!=0;
        if (f->stop_after_inspect) EXPECT(vireo_tcp_server_request_stop((vireo_tcp_server_t *)s,NULL),VIREO_OK);
    }
    return result;
}
static vireo_result_t model_admit(void *context,vireo_tcp_server_t *s,vireo_connection_options_t const *co,
    vireo_tcp_server_admit_budget_t const *b,vireo_connection_pool_lease_t *clients,size_t capacity,
    vireo_tcp_server_admit_info_t *info,vireo_tcp_server_client_error_t *error) {
    fault_t *f=context; vireo_tcp_server_admit_budget_t small=*b;
    if (f->partial_admit) small.max_accepts=1;
    vireo_result_t const result=vireo_tcp_server_admit_batch(s,co,&small,clients,capacity,info,error);
    if (result==VIREO_OK && f->partial_admit) {
        CHECK(info->admitted_count==1 && info->accept_calls<b->max_accept_syscalls);
        /* 真实前缀不伪造；第二次accept IO及其计数仅模型，未实际耗尽fd。 */
        ++info->accept_calls; info->stop_reason=VIREO_TCP_SERVER_ADMIT_ERROR;
        *error=(vireo_tcp_server_client_error_t){.primary={.stage=VIREO_TCP_SERVER_CLIENT_ACCEPT,
            .acceptor_error={VIREO_ACCEPTOR_STAGE_ACCEPT_CLIENT,EMFILE}}}; errno=ERANGE; return VIREO_RESULT_IO;
    }
    return result;
}
static vireo_result_t model_flow(void *context,vireo_tcp_server_t *s,vireo_connection_pool_lease_t c,
    vireo_connection_flow_options_t const *fo,vireo_tcp_server_client_error_t *error) {
    fault_t *f=context; ++f->flow_calls;
    if (f->flow_fail_at==f->flow_calls) {
        *error=(vireo_tcp_server_client_error_t){.primary={.stage=VIREO_TCP_SERVER_CLIENT_FLOW_CONFIGURE,
            .loop_error.loop_error.epoll_error.system_errno=EBADF}}; errno=ERANGE; return VIREO_RESULT_IO;
    }
    return vireo_tcp_server_client_flow_configure(s,c,fo,error);
}
static vireo_result_t model_schedule(void *context,vireo_tcp_server_t *s,vireo_connection_pool_lease_t c,
    vireo_tcp_server_client_error_t *error) {
    fault_t *f=context; ++f->schedule_calls;
    if (f->schedule_fail_at==f->schedule_calls) { *error=(vireo_tcp_server_client_error_t){0}; errno=ERANGE; return VIREO_RESULT_BUSY; }
    return vireo_tcp_server_schedule_client(s,c,error);
}
static vireo_async_admission_ops_t const model_ops={model_inspect,model_admit,model_flow,model_schedule};
static void model_call(fixture_t *f,fault_t *fault,vireo_result_t expected) {
    EXPECT(vireo_async_admission_with_ops(f->server,&connection,&flow,&budget,f->out,4,f->turns,4,&f->report,
        &model_ops,fault),expected); remember(f);
}
static void parameters(void) {
    fixture_t f; prepare(&f,3,1152,true); connect_clients(&f,3);
    memset(f.turns,0xA5,sizeof f.turns); unsigned char tail[sizeof f.turns]; memcpy(tail,f.turns,sizeof tail);
    EXPECT(vireo_async_admission_once(NULL,&connection,&flow,&budget,f.out,4,f.turns,4,&f.report),VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_async_admission_once(f.server,NULL,&flow,&budget,f.out,4,f.turns,4,&f.report),VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_async_admission_once(f.server,&connection,NULL,&budget,f.out,4,f.turns,4,&f.report),VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_async_admission_once(f.server,&connection,&flow,NULL,f.out,4,f.turns,4,&f.report),VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_async_admission_once(f.server,&connection,&flow,&budget,NULL,4,f.turns,4,&f.report),VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_async_admission_once(f.server,&connection,&flow,&budget,f.out,4,NULL,4,&f.report),VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_async_admission_once(f.server,&connection,&flow,&budget,f.out,4,f.turns,4,NULL),VIREO_RESULT_INVALID_ARGUMENT);
    vireo_tcp_server_admit_budget_t b=budget; b.max_accepts=0; call(&f,&connection,&flow,&b,4,4,VIREO_RESULT_INVALID_ARGUMENT);
    b=budget; b.max_accept_syscalls=0; call(&f,&connection,&flow,&b,4,4,VIREO_RESULT_INVALID_ARGUMENT);
    call(&f,&connection,&flow,&budget,0,4,VIREO_RESULT_INVALID_ARGUMENT); call(&f,&connection,&flow,&budget,4,0,VIREO_RESULT_INVALID_ARGUMENT);
    b=budget; b.max_accepts=65536; call(&f,&connection,&flow,&b,4,4,VIREO_RESULT_RANGE);
    call(&f,&connection,&flow,&budget,65536,4,VIREO_RESULT_RANGE); call(&f,&connection,&flow,&budget,4,65536,VIREO_RESULT_RANGE);
    for (size_t i=0;i<3;++i) {
        f.out[0]=(vireo_connection_pool_lease_t){0};
        if (i==0) f.out[0].pool_id=1; else if (i==1) f.out[0].slot_index=1; else f.out[0].generation=1;
        vireo_connection_pool_lease_t const before=f.out[0]; call(&f,&connection,&flow,&budget,4,4,VIREO_RESULT_INVALID_ARGUMENT);
        CHECK(lease_same(before,f.out[0]) && f.report.effective_max_accepts==0);
    }
    clear_output(&f); vireo_async_admission_ops_t broken=model_ops; broken.flow=NULL; fault_t fault={0};
    EXPECT(vireo_async_admission_with_ops(f.server,&connection,&flow,&budget,f.out,4,f.turns,4,&f.report,&broken,&fault),VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(!f.report.admit_called && fault.inspect_calls==0 && memcmp(tail,f.turns,sizeof tail)==0 && state(&f).connection_count==0); finish(&f);
}
static void connection_ranges(void) {
    fixture_t f; prepare(&f,3,1152,true); connect_clients(&f,1);
    vireo_connection_options_t co=connection; co.read_capacity=SIZE_MAX; co.write_capacity=1;
    call(&f,&co,&flow,&budget,4,4,VIREO_RESULT_OVERFLOW); CHECK(f.report.stage==VIREO_ASYNC_ADMISSION_VALIDATE_OPTIONS && !f.report.admit_called);
    for (size_t i=0;i<6;++i) {
        co=connection;
        if (i==0) co.read_capacity=0; else if (i==1) co.write_capacity=0; else if (i==2) co.max_buffer_bytes=0;
        else if (i==3) co.read_capacity=VIREO_BUFFER_MAX_CAPACITY+1; else if (i==4) co.max_buffer_bytes=VIREO_CONNECTION_MAX_BUFFER_BYTES+1;
        else co.max_buffer_bytes=383;
        call(&f,&co,&flow,&budget,4,4,VIREO_RESULT_RANGE); CHECK(!f.report.admit_called && state(&f).connection_count==0);
    }
    call(&f,&connection,&flow,&budget,4,4,VIREO_OK); CHECK(f.report.admission.admitted_count==1); finish(&f);
}
static void flow_ranges(void) {
    fixture_t f; prepare(&f,3,1152,true); connect_clients(&f,1);
    for (size_t i=0;i<8;++i) {
        vireo_connection_flow_options_t fo=flow;
        if (i==0) fo.max_frame_bytes=0; else if (i==1) fo.max_frame_bytes=31; else if (i==2) fo.max_frame_bytes=257;
        else if (i==3) fo.max_frame_bytes=16777249; else if (i==4) fo.read_low=62; else if (i==5) fo.read_high=63;
        else if (i==6) fo.read_high=257; else fo.write_high=32;
        call(&f,&connection,&fo,&budget,4,4,VIREO_RESULT_RANGE); CHECK(!f.report.admit_called && state(&f).connection_count==0);
    }
    vireo_connection_flow_options_t fo=flow; fo.write_high=129; call(&f,&connection,&fo,&budget,4,4,VIREO_RESULT_RANGE);
    fo=(vireo_connection_flow_options_t){32,31,32,0,1}; call(&f,&connection,&fo,&budget,4,4,VIREO_OK);
    CHECK(client_info(&f,0).connection_info.flow_enabled && client_info(&f,0).connection_info.flow_options.max_frame_bytes==32); finish(&f);
}
static void capacity_minimum(void) {
    fixture_t f; prepare(&f,3,1152,true); connect_clients(&f,3);
    f.out[2]=(vireo_connection_pool_lease_t){UINT64_MAX,SIZE_MAX,UINT64_MAX};
    memset(f.turns,0xA5,sizeof f.turns); unsigned char oldturn[sizeof f.turns[2]]; memcpy(oldturn,&f.turns[2],sizeof oldturn);
    vireo_connection_pool_lease_t const oldlease=f.out[2];
    call(&f,&connection,&flow,&budget,4,2,VIREO_OK);
    CHECK(f.report.effective_max_accepts==2 && f.report.admission.admitted_count==2 && f.report.scheduled_count==2);
    CHECK(lease_same(oldlease,f.out[2]) && memcmp(oldturn,&f.turns[2],sizeof oldturn)==0 && state(&f).pending_clients==2);
    clear_output(&f); call(&f,&connection,&flow,&budget,1,4,VIREO_OK); CHECK(f.report.effective_max_accepts==1 && f.live_count==3); finish(&f);
    prepare(&f,3,1152,true); connect_clients(&f,3); vireo_tcp_server_admit_budget_t const b={1,SIZE_MAX};
    call(&f,&connection,&flow,&b,4,4,VIREO_OK); CHECK(f.report.effective_max_accepts==1 && f.report.admission.accept_calls==1); finish(&f);
}
static void syscall_limit(void) {
    fixture_t f; prepare(&f,3,1152,true); connect_clients(&f,3); vireo_tcp_server_admit_budget_t const b={3,1};
    call(&f,&connection,&flow,&b,4,4,VIREO_OK);
    CHECK(f.report.admission.admitted_count==1 && f.report.admission.accept_calls==1 && f.report.admission.stop_reason==VIREO_TCP_SERVER_ADMIT_CALL_LIMIT);
    CHECK(f.report.initialized_count==1 && f.report.scheduled_count==1); finish(&f);
}
static void empty_accept(void) {
    fixture_t f; prepare(&f,3,1152,true); memset(f.turns,0xA5,sizeof f.turns); unsigned char old[sizeof f.turns]; memcpy(old,f.turns,sizeof old);
    call(&f,&connection,&flow,&budget,4,4,VIREO_OK);
    CHECK(f.report.admit_called && f.report.admission.accept_calls==1 && f.report.admission.stop_reason==VIREO_TCP_SERVER_ADMIT_WOULD_BLOCK);
    CHECK(f.report.turn_count==0 && f.report.unprocessed_begin==0 && f.report.admission.admitted_count==0 && memcmp(old,f.turns,sizeof old)==0); finish(&f);
}
static void connection_limit_and_reuse(void) {
    fixture_t f; prepare(&f,1,768,true); connect_clients(&f,2); call(&f,&connection,&flow,&budget,4,4,VIREO_OK);
    CHECK(f.report.admission.admitted_count==1 && f.report.admission.stop_reason==VIREO_TCP_SERVER_ADMIT_CONNECTION_LIMIT);
    vireo_connection_pool_lease_t const old=f.live[0]; EXPECT(vireo_tcp_server_release_client(f.server,&f.live[0],NULL),VIREO_OK);
    clear_output(&f); call(&f,&connection,&flow,&budget,4,4,VIREO_OK); CHECK(f.report.admission.admitted_count==1);
    CHECK(old.pool_id==f.live[1].pool_id && old.slot_index==f.live[1].slot_index && old.generation!=f.live[1].generation);
    vireo_tcp_server_client_info_t info; EXPECT(vireo_tcp_server_client_inspect(f.server,old,&info),VIREO_RESULT_NOT_FOUND); finish(&f);
}
static void buffer_limit(void) {
    fixture_t f; prepare(&f,3,384,true); connect_clients(&f,2); call(&f,&connection,&flow,&budget,4,4,VIREO_OK);
    CHECK(f.report.admission.admitted_count==1 && f.report.admission.stop_reason==VIREO_TCP_SERVER_ADMIT_BUFFER_LIMIT);
    CHECK(state(&f).buffer_capacity_bytes==384 && state(&f).listener_read_enabled && !state(&f).admission_enabled);
    clear_output(&f); call(&f,&connection,&flow,&budget,4,4,VIREO_OK); CHECK(f.report.admission.accept_calls==0 && f.report.turn_count==0); finish(&f);
}
static void automatic_policy(void) {
    fixture_t f; prepare(&f,3,1152,true); connect_clients(&f,1); vireo_tcp_server_admission_options_t const options={connection,flow};
    EXPECT(vireo_tcp_server_admission_configure(f.server,&options,NULL),VIREO_OK);
    call(&f,&connection,&flow,&budget,4,4,VIREO_RESULT_BUSY);
    CHECK(f.report.stage==VIREO_ASYNC_ADMISSION_CHECK_SERVER && !f.report.admit_called && state(&f).admission_enabled && state(&f).connection_count==0);
    EXPECT(vireo_tcp_server_admission_disable(f.server,NULL),VIREO_OK);
    call(&f,&connection,&flow,&budget,4,4,VIREO_OK); CHECK(f.report.admission.admitted_count==1); finish(&f);
}
static void stopped_server(void) {
    fixture_t f; prepare(&f,3,1152,true); connect_clients(&f,1); EXPECT(vireo_tcp_server_request_stop(f.server,NULL),VIREO_OK);
    call(&f,&connection,&flow,&budget,4,4,VIREO_RESULT_CANCELLED); CHECK(!f.report.admit_called && state(&f).connection_count==0);
    vireo_connection_flow_options_t bad=flow; bad.read_low=62; call(&f,&connection,&bad,&budget,4,4,VIREO_RESULT_RANGE);
    CHECK(f.report.stage==VIREO_ASYNC_ADMISSION_VALIDATE_OPTIONS); finish(&f);
}
static void active_and_inspect_error(void) {
    fixture_t f; prepare(&f,3,1152,true); connect_clients(&f,1);
    for (unsigned bit=1;bit<=64;bit*=2) {
        fault_t fault={.active_mask=bit}; model_call(&f,&fault,VIREO_RESULT_BUSY);
        CHECK(f.report.stage==VIREO_ASYNC_ADMISSION_CHECK_SERVER && !f.report.admit_called && fault.inspect_calls==1 && state(&f).connection_count==0);
    }
    fault_t fault={.inspect_error=true}; model_call(&f,&fault,VIREO_RESULT_IO); CHECK(!f.report.admit_called); finish(&f);
}
static void missing_listener(void) {
    fixture_t f={.peers={-1,-1,-1}}; vireo_tcp_server_options_t const options={3,8,1048576,1152};
    EXPECT(vireo_tcp_server_create(&options,&f.server,NULL),VIREO_OK);
    call(&f,&connection,&flow,&budget,4,4,VIREO_RESULT_NOT_FOUND);
    CHECK(f.report.admit_called && f.report.admit_result==VIREO_RESULT_NOT_FOUND && f.report.turn_count==0); finish(&f);
    prepare(&f,3,1152,false); connect_clients(&f,1);
    call(&f,&connection,&flow,&budget,4,4,VIREO_OK);
    CHECK(!state(&f).listener_bound && client_info(&f,0).connection_info.loop_attached &&
        client_info(&f,0).connection_info.flow_enabled && client_info(&f,0).queued); finish(&f);
}
static void partial_admit_error(void) {
    fixture_t f; prepare(&f,3,1152,true); connect_clients(&f,3); fault_t fault={.partial_admit=true};
    memset(f.turns,0xA5,sizeof f.turns); unsigned char old[sizeof f.turns]; memcpy(old,f.turns,sizeof old);
    model_call(&f,&fault,VIREO_RESULT_IO);
    CHECK(f.report.stage==VIREO_ASYNC_ADMISSION_ADMIT && f.report.admission.admitted_count==1 && f.report.admission.accept_calls==2);
    CHECK(f.report.admit_error.primary.acceptor_error.system_errno==EMFILE && f.report.turn_count==0 && f.report.unprocessed_begin==0);
    CHECK(fault.flow_calls==0 && fault.schedule_calls==0 && !client_info(&f,0).connection_info.flow_enabled && memcmp(old,f.turns,sizeof old)==0);
    EXPECT(vireo_tcp_server_client_flow_configure(f.server,f.live[0],&flow,NULL),VIREO_OK);
    EXPECT(vireo_tcp_server_schedule_client(f.server,f.live[0],NULL),VIREO_OK); clear_output(&f);
    call(&f,&connection,&flow,&budget,4,4,VIREO_OK); CHECK(f.live_count==3 && state(&f).pending_clients==3); finish(&f);
}
static void verify_fifo(fixture_t *f) {
    vireo_tcp_server_ready_client_t ready[3]; vireo_tcp_server_poll_report_t report;
    EXPECT(vireo_tcp_server_poll_ready_once(f->server,0,3,ready,3,&report),VIREO_OK); CHECK(report.selected_count==3);
    for (size_t i=0;i<3;++i) CHECK(lease_same(ready[i].client,f->live[i]));
}
static void flow_error(void) {
    for (size_t fail=1;fail<=2;++fail) {
        fixture_t f; prepare(&f,3,1152,true); connect_clients(&f,3); fault_t fault={.flow_fail_at=fail};
        memset(f.turns,0xA5,sizeof f.turns); unsigned char old[sizeof f.turns[2]]; memcpy(old,&f.turns[2],sizeof old);
        model_call(&f,&fault,VIREO_RESULT_IO);
        CHECK(f.report.admission.admitted_count==3 && f.report.turn_count==fail && f.report.unprocessed_begin==fail);
        CHECK(f.report.initialized_count==fail-1 && f.report.scheduled_count==fail-1 && fault.schedule_calls==fail-1);
        CHECK(f.turns[fail-1].flow_error.primary.loop_error.loop_error.epoll_error.system_errno==EBADF && !f.turns[fail-1].schedule_called);
        CHECK(!client_info(&f,fail-1).connection_info.flow_enabled && !client_info(&f,2).connection_info.flow_enabled && memcmp(old,&f.turns[2],sizeof old)==0);
        for (size_t i=fail-1;i<3;++i) {
            EXPECT(vireo_tcp_server_client_flow_configure(f.server,f.live[i],&flow,NULL),VIREO_OK);
            EXPECT(vireo_tcp_server_schedule_client(f.server,f.live[i],NULL),VIREO_OK);
        }
        verify_fifo(&f); finish(&f);
    }
}
static void schedule_error(void) {
    fixture_t f; prepare(&f,3,1152,true); connect_clients(&f,3); fault_t fault={.schedule_fail_at=2}; model_call(&f,&fault,VIREO_RESULT_BUSY);
    CHECK(f.report.stage==VIREO_ASYNC_ADMISSION_SCHEDULE && f.report.admission.admitted_count==3 && f.report.turn_count==2 && f.report.unprocessed_begin==2);
    CHECK(f.report.initialized_count==2 && f.report.scheduled_count==1 && client_info(&f,1).connection_info.flow_enabled && !client_info(&f,1).queued);
    CHECK(!client_info(&f,2).connection_info.flow_enabled);
    EXPECT(vireo_tcp_server_schedule_client(f.server,f.live[1],NULL),VIREO_OK);
    EXPECT(vireo_tcp_server_client_flow_configure(f.server,f.live[2],&flow,NULL),VIREO_OK);
    EXPECT(vireo_tcp_server_schedule_client(f.server,f.live[2],NULL),VIREO_OK); verify_fifo(&f); finish(&f);
}
static void late_stop(void) {
    fixture_t f; prepare(&f,3,1152,true); connect_clients(&f,3); fault_t fault={.stop_after_inspect=true}; model_call(&f,&fault,VIREO_OK);
    CHECK(state(&f).stop_requested && f.report.admission.admitted_count==3 && f.report.scheduled_count==3); finish(&f);
}
static size_t client_index(world_t *w,vireo_connection_pool_lease_t c) {
    for (size_t i=0;i<w->net.live_count;++i) if (lease_same(c,w->net.live[i])) return i;
    CHECK(false); return 0;
}
static vireo_result_t configure(void *context,vireo_tcp_server_ready_client_t client,vireo_async_round_config_t *out) {
    world_t *w=context; size_t const i=client_index(w,client.client);
    *out=(vireo_async_round_config_t){{64,4096,8,(uint32_t)(9+i),UINT64_MAX-i},{{128,8},{128,8}},NULL,&w->pending[i]}; return VIREO_OK;
}
static void round_once(world_t *w,int timeout) {
    vireo_tcp_server_ready_client_t ready[4]; vireo_async_round_turn_t turns[4]; vireo_async_round_report_t report;
    EXPECT(vireo_async_round_once(w->net.server,w->store,w->pool,timeout,3,configure,w,ready,4,turns,4,&w->remaining,&report),VIREO_OK);
    for (size_t i=0;i<report.turn_count;++i) {
        vireo_async_round_turn_t const t=turns[i];
        if (!t.drive_report.head_report.submit_report.task_transferred) continue;
        CHECK(t.drive_report.request_header_available); vireo_protocol_header_t const h=t.drive_report.request_header;
        unsigned const tag=h.sequence-100; CHECK(tag>=1 && tag<=3 && !w->entries[tag].valid);
        size_t const ci=client_index(w,t.client.client); vireo_task_metadata_t const m=t.drive_report.head_report.submit_report.metadata;
        CHECK(m.operation==9+ci && m.deadline_ns==UINT64_MAX-ci && m.route.client_owner_id==t.client.client.pool_id &&
            m.route.client_slot_index==t.client.client.slot_index && m.route.client_generation==t.client.client.generation);
        CHECK(h.command==(tag==2?VIREO_COMMAND_UPLOAD_STATUS:VIREO_COMMAND_NODE_STAT) && h.flags==(tag==2?VIREO_PROTOCOL_FLAG_LONG_COMMAND:0));
        CHECK(h.session_handle==0x12340000U+tag && h.task_handle==0x56780000U+tag && h.body_len==3);
        w->entries[tag]=(entry_t){true,m,h,0}; ++w->submitted;
    }
}
static void setup_worker(world_t *w) {
    atomic_init(&w->worker.published,0);
    vireo_inflight_store_options_t const io={8,65536}; EXPECT(vireo_inflight_store_create(&io,&w->store),VIREO_OK);
    vireo_task_queue_options_t const tq={8,65536}; EXPECT(vireo_task_queue_create(&tq,&w->tasks),VIREO_OK); EXPECT(vireo_task_queue_prepare_wait(w->tasks),VIREO_OK);
    vireo_completion_queue_options_t const cq={8,65536}; EXPECT(vireo_completion_queue_create(&cq,&w->outputs),VIREO_OK); EXPECT(vireo_completion_queue_prepare_wait(w->outputs),VIREO_OK);
    vireo_notifier_options_t const no={4096}; EXPECT(vireo_notifier_create(&no,&w->notifier,NULL),VIREO_OK);
    EXPECT(vireo_notifier_server_register(w->net.server,w->notifier,&w->handle,NULL),VIREO_OK);
    w->worker.outputs=w->outputs; w->worker.notifier=w->notifier;
    CHECK(pthread_barrier_init(&w->worker.entered,NULL,2)==0 && pthread_barrier_init(&w->worker.release,NULL,2)==0);
    vireo_thread_pool_options_t const po={1,65536}; EXPECT(vireo_thread_pool_create(&po,&w->pool),VIREO_OK);
    vireo_thread_pool_configuration_t const config={w->tasks,execute,&w->worker}; EXPECT(vireo_thread_pool_configure(w->pool,&config,NULL),VIREO_OK);
    vireo_task_route_t route; vireo_task_metadata_t metadata; vireo_task_t *warm=NULL;
    EXPECT(vireo_task_route_make(UINT64_MAX,0,1,1,&route),VIREO_OK); EXPECT(vireo_task_metadata_make(route,1,1,UINT64_MAX,&metadata),VIREO_OK);
    EXPECT(vireo_task_create_copy(metadata,NULL,0,4096,&warm),VIREO_OK);
    vireo_task_queue_transfer_report_t qr; EXPECT(vireo_task_queue_try_push(w->tasks,&warm,&qr),VIREO_OK);
    vireo_thread_pool_report_t pr; EXPECT(vireo_thread_pool_start(w->pool,&pr),VIREO_OK); EXPECT(vireo_thread_pool_enable_execution(w->pool,&pr),VIREO_OK); meet(&w->worker.entered);
}
static void integration(void) {
    world_t w={0}; prepare(&w.net,3,1152,true); connect_clients(&w.net,3);
    for (unsigned tag=1;tag<=3;++tag) { uint8_t wire[35]; encode(wire,tag); send_all(w.net.peers[tag-1],wire,sizeof wire); }
    call(&w.net,&connection,&flow,&budget,4,4,VIREO_OK);
    CHECK(w.net.report.admission.admitted_count==3 && w.net.report.initialized_count==3 && w.net.report.scheduled_count==3);
    for (size_t i=0;i<3;++i) CHECK(client_info(&w.net,i).connection_info.read_buffer.readable_size==0);
    /* 返回后caller建立稳定pending/完整lease映射和worker依赖，再首次驱动；没有早收/早提交。 */
    setup_worker(&w); round_once(&w,0); CHECK(w.submitted==3 && w.remaining==NULL);
    CHECK(w.entries[1].metadata.request_instance_id!=w.entries[2].metadata.request_instance_id && w.entries[2].metadata.request_instance_id!=w.entries[3].metadata.request_instance_id);
    meet(&w.worker.release); published(&w); size_t finished=0;
    for (size_t i=0;i<24 && finished<3;++i) {
        round_once(&w,1000); vireo_completion_response_dispatch_report_t report;
        EXPECT(vireo_completion_response_dispatch_ready(w.net.server,w.handle,w.notifier,w.store,w.outputs,1,64,64,
            w.scratch,sizeof w.scratch,resolve,&w,&w.remaining_completion,&report),VIREO_OK);
        finished+=report.dispatch_report.dispatch_report.drain_report.finished;
    }
    CHECK(finished==3 && w.remaining_completion==NULL);
    for (size_t i=0;i<3;++i) EXPECT(vireo_tcp_server_schedule_client(w.net.server,w.net.live[i],NULL),VIREO_OK);
    round_once(&w,0); for (size_t i=0;i<3;++i) check_response(&w,i,(unsigned)i+1);
    vireo_thread_pool_shutdown_report_t sr; EXPECT(shutdown_pool(w.pool,&sr),VIREO_OK);
    vireo_thread_pool_worker_result_t wr; EXPECT(vireo_thread_pool_inspect_worker_result(w.pool,0,&wr),VIREO_OK); CHECK(wr.result==VIREO_OK);
    for (size_t i=1;i<=3;++i) CHECK(w.worker.reports[i].completion_transferred && w.worker.reports[i].notify_called);
    vireo_completion_queue_close_report_t cr; EXPECT(vireo_completion_queue_close(w.outputs,&cr),VIREO_OK);
    vireo_completion_t *last=NULL; vireo_completion_queue_transfer_report_t qr;
    EXPECT(vireo_completion_queue_try_pop(w.outputs,&last,&qr),VIREO_RESULT_CANCELLED); CHECK(last==NULL);
    vireo_inflight_store_info_t si; EXPECT(vireo_inflight_store_inspect(w.store,&si),VIREO_OK); CHECK(si.count==0);
    EXPECT(vireo_task_destroy(&w.remaining),VIREO_OK); EXPECT(vireo_completion_destroy(&w.remaining_completion),VIREO_OK);
    EXPECT(vireo_thread_pool_destroy(&w.pool),VIREO_OK); EXPECT(vireo_task_queue_destroy(&w.tasks),VIREO_OK);
    EXPECT(vireo_completion_queue_destroy(&w.outputs),VIREO_OK); EXPECT(vireo_inflight_store_destroy(&w.store),VIREO_OK);
    EXPECT(vireo_notifier_server_unregister(w.net.server,&w.handle,NULL),VIREO_OK); EXPECT(vireo_notifier_destroy(&w.notifier,NULL),VIREO_OK);
    CHECK(pthread_barrier_destroy(&w.worker.entered)==0 && pthread_barrier_destroy(&w.worker.release)==0); finish(&w.net);
}
int main(void) {
    int old; CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,&old)==0);
    void (*const tests[])(void)={parameters,connection_ranges,flow_ranges,capacity_minimum,syscall_limit,empty_accept,
        connection_limit_and_reuse,buffer_limit,automatic_policy,stopped_server,active_and_inspect_error,missing_listener,
        partial_admit_error,flow_error,schedule_error,late_stop,integration};
    for (size_t i=0;i<sizeof tests/sizeof tests[0];++i) { unsigned const n=fd_count(); tests[i](); CHECK(fd_count()==n); }
    CHECK(pthread_setcancelstate(old,NULL)==0); puts("async admission: 17 groups, 0 failures"); return 0;
}
