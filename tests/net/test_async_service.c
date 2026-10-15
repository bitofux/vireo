/*
 * PROJECT : VIREO
 * FILE    : test_async_service.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-14
 * BRIEF   : 有限服务轮真实回写与公开边界故障隔离
 */
#define _GNU_SOURCE
#include "net/async_service_internal.h" /* 仅本层seam，无外private。 */
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
    bool released; /**< main是否已放行预热，避免清理时重复等待barrier。 */
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
static void finish(fixture_t *f) {
    for (size_t i=0;i<f->live_count;++i) if (f->live[i].pool_id!=0)
        EXPECT(vireo_tcp_server_release_client(f->server,&f->live[i],NULL),VIREO_OK);
    for (size_t i=0;i<f->connected;++i) CHECK(close(f->peers[i])==0);
    EXPECT(vireo_tcp_server_destroy(&f->server,NULL),VIREO_OK);
}
static size_t client_index(world_t *w,vireo_connection_pool_lease_t c) {
    for (size_t i=0;i<w->net.live_count;++i) if (lease_same(c,w->net.live[i])) return i;
    CHECK(false); return 0;
}
static vireo_result_t configure(void *context,vireo_tcp_server_ready_client_t client,vireo_async_round_config_t *out) {
    world_t *w=context; size_t const i=client_index(w,client.client);
    *out=(vireo_async_round_config_t){{64,4096,8,(uint32_t)(9+i),UINT64_MAX-i},{{128,8},{128,8}},NULL,&w->pending[i]}; return VIREO_OK;
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

/** 单次caller工作区，数组原位稳定，尾部允许放字节哨兵。 */
typedef struct batch {
    vireo_tcp_server_ready_client_t ready[4]; /**< 全部已取出客户前缀。 */
    vireo_async_round_turn_t turns[4]; /**< 实际配置尝试前缀。 */
    vireo_async_service_options_t options; /**< 每次显式值，测试可改边界。 */
    vireo_async_service_workspace_t workspace; /**< 短借本结构和world数组。 */
    vireo_async_service_report_t report; /**< 每路径完整真实进度。 */
} batch_t;
static void prepare_batch(world_t *w,batch_t *b) {
    *b=(batch_t){0}; clear_output(&w->net);
    b->options=(vireo_async_service_options_t){0,3,connection,flow,budget,1,64,64};
    b->workspace=(vireo_async_service_workspace_t){b->ready,4,b->turns,4,w->net.out,4,w->net.turns,4,w->scratch,64};
}
/** 返回后先保存全部新客户，再保存新提交的原wire关联；下一次分发之前完成。 */
static void save_return(world_t *w,batch_t *b) {
    w->net.report=b->report.admission_report; remember(&w->net);
    for (size_t i=0;i<b->report.clients.turn_count;++i) {
        vireo_async_round_turn_t const t=b->turns[i];
        if (!t.drive_report.head_report.submit_report.task_transferred) continue;
        CHECK(t.drive_report.request_header_available); vireo_protocol_header_t const h=t.drive_report.request_header;
        unsigned const tag=h.sequence-100; CHECK(tag>=1 && tag<=3 && !w->entries[tag].valid);
        size_t const ci=client_index(w,t.client.client); vireo_task_metadata_t const m=t.drive_report.head_report.submit_report.metadata;
        CHECK(m.operation==9+ci && m.deadline_ns==UINT64_MAX-ci && m.route.client_owner_id==t.client.client.pool_id &&
            m.route.client_slot_index==t.client.client.slot_index && m.route.client_generation==t.client.client.generation);
        CHECK(h.command==(tag==2?VIREO_COMMAND_UPLOAD_STATUS:VIREO_COMMAND_NODE_STAT) && h.flags==(tag==2?VIREO_PROTOCOL_FLAG_LONG_COMMAND:0));
        w->entries[tag]=(entry_t){true,m,h,0}; ++w->submitted;
    }
}
static void service(world_t *w,batch_t *b,int timeout) {
    prepare_batch(w,b); b->options.timeout_ms=timeout;
    EXPECT(vireo_async_service_once(w->net.server,w->store,w->pool,w->notifier,w->outputs,w->handle,
        &b->options,&b->workspace,configure,w,resolve,w,&w->remaining,&w->remaining_completion,&b->report),VIREO_OK);
    CHECK(b->report.pre_pressure_called && b->report.poll_called && b->report.dispatch_called && b->report.post_pressure_called);
    CHECK(b->report.stage==VIREO_ASYNC_SERVICE_NONE && b->report.post_pressure_result==VIREO_OK); save_return(w,b);
}
static void release_worker(world_t *w) {
    CHECK(!w->released); meet(&w->worker.release); w->released=true;
}
static void cleanup(world_t *w) {
    if (!w->released) release_worker(w);
    vireo_thread_pool_shutdown_report_t sr; EXPECT(shutdown_pool(w->pool,&sr),VIREO_OK);
    vireo_thread_pool_worker_result_t wr; EXPECT(vireo_thread_pool_inspect_worker_result(w->pool,0,&wr),VIREO_OK); CHECK(wr.result==VIREO_OK);
    for (size_t i=1;i<=w->submitted;++i) CHECK(w->worker.reports[i].completion_transferred && w->worker.reports[i].notify_called);
    vireo_completion_queue_close_report_t cr; EXPECT(vireo_completion_queue_close(w->outputs,&cr),VIREO_OK);
    vireo_completion_t *last=NULL; vireo_completion_queue_transfer_report_t qr;
    EXPECT(vireo_completion_queue_try_pop(w->outputs,&last,&qr),VIREO_RESULT_CANCELLED); CHECK(last==NULL);
    vireo_inflight_store_info_t si; EXPECT(vireo_inflight_store_inspect(w->store,&si),VIREO_OK); CHECK(si.count==0);
    EXPECT(vireo_task_destroy(&w->remaining),VIREO_OK); EXPECT(vireo_completion_destroy(&w->remaining_completion),VIREO_OK);
    EXPECT(vireo_thread_pool_destroy(&w->pool),VIREO_OK); EXPECT(vireo_task_queue_destroy(&w->tasks),VIREO_OK);
    EXPECT(vireo_completion_queue_destroy(&w->outputs),VIREO_OK); EXPECT(vireo_inflight_store_destroy(&w->store),VIREO_OK);
    EXPECT(vireo_notifier_server_unregister(w->net.server,&w->handle,NULL),VIREO_OK); EXPECT(vireo_notifier_destroy(&w->notifier,NULL),VIREO_OK);
    CHECK(pthread_barrier_destroy(&w->worker.entered)==0 && pthread_barrier_destroy(&w->worker.release)==0); finish(&w->net);
}
static void setup(world_t *w,size_t count) {
    *w=(world_t){0}; prepare(&w->net,3,1152,true); setup_worker(w);
    if (count!=0) {
        connect_clients(&w->net,count);
        EXPECT(vireo_async_admission_once(w->net.server,&connection,&flow,&budget,w->net.out,4,w->net.turns,4,&w->net.report),VIREO_OK);
        remember(&w->net); clear_output(&w->net);
    }
}
/** 仅本层公开边界故障模型；实际poll/驱动/接入默认仍调公开实现。 */
typedef struct model {
    world_t *world; /**< main短借真实资源，回调不跨线程保存。 */
    char order[64]; /**< 边界调用轨迹，P/W/D/C/V/S/A/Z。 */
    size_t count; /**< 轨迹有效字节数，尾部保持零。 */
    size_t pressures; /**< pre/post实际尝试次数，最多2。 */
    vireo_result_t pre_error; /**< 0不注入；入口压力失败模型。 */
    vireo_result_t post_error; /**< 0不注入；末压力失败模型。 */
    vireo_result_t poll_error; /**< 实际poll后呈现错误，保真selected前缀。 */
    bool stopped; /**< 模型poll报告stopped，不停止真实server。 */
    uint32_t listener; /**< 在实际poll后替换监听位，仅模型，非真实内核异常。 */
    bool override_listener; /**< 是否替换原监听位，0也可显式覆盖。 */
    bool dispatch_error; /**< 真实创建completion交remaining，再返回IO模型。 */
    size_t configure_at; /**< Nth配置失败，0禁用。 */
    size_t configured; /**< 实际配置回调数。 */
    size_t drive_at; /**< Nth驱动故障并返回task owner模型。 */
    size_t driven; /**< 实际drive边界数。 */
    bool reschedule; /**< 成功真实空driver后模拟缓存续排提示。 */
    size_t schedule_at; /**< Nth排尾无变更BUSY模型。 */
    size_t scheduled; /**< 实际schedule边界数。 */
    bool admit_error; /**< 真接入1项/flow/排队后IO模型，保完整前缀。 */
} model_t;
static void trace(model_t *m,char c) { CHECK(m->count+1<sizeof m->order); m->order[m->count++]=c; errno=ERANGE; }
static vireo_result_t model_pressure(void *ctx,vireo_tcp_server_t *s,vireo_connection_options_t const *o,
    vireo_async_admission_pressure_report_t *r) {
    model_t *m=ctx; trace(m,m->pressures==0?'P':'Z'); ++m->pressures;
    vireo_result_t const fail=m->pressures==1?m->pre_error:m->post_error;
    if (fail!=VIREO_OK) { *r=(vireo_async_admission_pressure_report_t){.stage=VIREO_ASYNC_ADMISSION_PRESSURE_UPDATE_READ}; return fail; }
    return vireo_async_admission_pressure_refresh(s,o,r);
}
static vireo_result_t model_poll(void *ctx,vireo_tcp_server_t *s,int timeout,size_t max,
    vireo_tcp_server_ready_client_t *ready,size_t capacity,vireo_tcp_server_listener_poll_report_t *r) {
    model_t *m=ctx; trace(m,'W'); vireo_result_t const result=vireo_tcp_server_poll_with_listener_once(s,timeout,max,ready,capacity,r);
    CHECK(result==VIREO_OK); if (m->override_listener) r->listener_events=m->listener;
    r->poll.stopped=m->stopped; return m->poll_error;
}
static vireo_task_metadata_t numeric_metadata(void) {
    vireo_task_route_t route; vireo_task_metadata_t metadata;
    EXPECT(vireo_task_route_make(UINT64_MAX,0,1,77,&route),VIREO_OK);
    EXPECT(vireo_task_metadata_make(route,77,9,UINT64_MAX,&metadata),VIREO_OK); return metadata;
}
static vireo_result_t model_dispatch(void *ctx,vireo_tcp_server_t *s,vireo_event_loop_handle_t h,
    vireo_notifier_t *n,vireo_inflight_store_t *store,vireo_completion_queue_t *q,size_t max,size_t frame,size_t batch,
    uint8_t *bytes,size_t capacity,vireo_completion_response_resolve_fn resolve_fn,void *context,
    vireo_completion_t **owner,vireo_completion_response_dispatch_report_t *r) {
    model_t *m=ctx; trace(m,'D');
    if (m->dispatch_error) {
        vireo_completion_metadata_t metadata;
        EXPECT(vireo_completion_metadata_make(numeric_metadata(),VIREO_OK,VIREO_STATUS_OK,&metadata),VIREO_OK);
        EXPECT(vireo_completion_create_copy(metadata,NULL,0,4096,owner),VIREO_OK);
        *r=(vireo_completion_response_dispatch_report_t){.stage=VIREO_COMPLETION_RESPONSE_DISPATCH_RESOLVE_DESCRIPTOR,.resolve_calls=1};
        return VIREO_RESULT_IO; /* 模拟依赖已领取但未交付结果；未伪造真实queue领取。 */
    }
    return vireo_completion_response_dispatch_ready(s,h,n,store,q,max,frame,batch,bytes,capacity,resolve_fn,context,owner,r);
}
static vireo_result_t model_configure(void *ctx,vireo_tcp_server_ready_client_t c,vireo_async_round_config_t *out) {
    model_t *m=ctx; trace(m,'C'); ++m->configured;
    if (m->configure_at==m->configured) return VIREO_RESULT_PROTOCOL;
    return configure(m->world,c,out);
}
static vireo_result_t model_drive(void *ctx,vireo_tcp_server_t *s,vireo_connection_pool_lease_t c,
    vireo_inflight_store_t *store,vireo_thread_pool_t *pool,vireo_async_client_drive_options_t const *o,
    vireo_async_client_drive_budget_t const *b,vireo_task_cancel_t *cancel,vireo_async_request_pending_t *pending,
    vireo_task_t **owner,vireo_async_client_drive_report_t *r) {
    model_t *m=ctx; trace(m,'V'); ++m->driven;
    if (m->drive_at==m->driven) {
        EXPECT(vireo_task_create_copy(numeric_metadata(),NULL,0,4096,owner),VIREO_OK);
        return VIREO_RESULT_NO_MEMORY; /* 模型原接线层复制后提交失败，task仍属caller。 */
    }
    vireo_result_t const result=vireo_async_client_drive_once(s,c,store,pool,o,b,cancel,pending,owner,r);
    if (result==VIREO_OK && m->reschedule) r->needs_reschedule=true;
    return result;
}
static vireo_result_t model_schedule(void *ctx,vireo_tcp_server_t *s,vireo_connection_pool_lease_t c,
    vireo_tcp_server_client_error_t *e) {
    model_t *m=ctx; trace(m,'S'); ++m->scheduled;
    if (m->schedule_at==m->scheduled) return VIREO_RESULT_BUSY;
    return vireo_tcp_server_schedule_client(s,c,e);
}
static vireo_result_t model_admit(void *ctx,vireo_tcp_server_t *s,vireo_connection_options_t const *co,
    vireo_connection_flow_options_t const *fo,vireo_tcp_server_admit_budget_t const *budget_arg,
    vireo_connection_pool_lease_t *clients,size_t capacity,vireo_async_admission_turn_t *turns,size_t turns_capacity,
    vireo_async_admission_report_t *r) {
    model_t *m=ctx; trace(m,'A');
    if (m->admit_error) {
        vireo_tcp_server_admit_budget_t b=*budget_arg; b.max_accepts=1;
        *r=(vireo_async_admission_report_t){.stage=VIREO_ASYNC_ADMISSION_ADMIT,
            .effective_max_accepts=1,.admit_called=true,.admit_result=VIREO_RESULT_IO};
        EXPECT(vireo_tcp_server_admit_batch(s,co,&b,clients,capacity,&r->admission,&r->admit_error),VIREO_OK);
        CHECK(r->admission.admitted_count==1);
        return VIREO_RESULT_IO; /* 真接入前缀，后续依赖IO仅模型，没有flow或排队。 */
    }
    return vireo_async_admission_once(s,co,fo,budget_arg,clients,capacity,turns,turns_capacity,r);
}
static vireo_async_service_ops_t const model_ops={model_pressure,model_poll,model_dispatch,model_drive,model_schedule,model_admit};
static vireo_result_t invoke(world_t *w,batch_t *b,model_t *m,vireo_event_loop_handle_t handle,
    vireo_async_service_ops_t const *ops) {
    return vireo_async_service_with_ops(w->net.server,w->store,w->pool,w->notifier,w->outputs,handle,
        &b->options,&b->workspace,model_configure,m,resolve,w,&w->remaining,&w->remaining_completion,&b->report,ops,m);
}
static void model_call(world_t *w,batch_t *b,model_t *m,vireo_result_t expected) {
    m->world=w; EXPECT(invoke(w,b,m,w->handle,&model_ops),expected);
    w->net.report=b->report.admission_report; remember(&w->net);
}

static void parameters(void) {
    world_t w; setup(&w,0); batch_t b; prepare_batch(&w,&b); model_t m={.world=&w};
    for (unsigned i=0;i<15;++i) {
        errno=EDOM;
        vireo_result_t const r=vireo_async_service_once(i==0?NULL:w.net.server,i==1?NULL:w.store,i==2?NULL:w.pool,
            i==3?NULL:w.notifier,i==4?NULL:w.outputs,w.handle,i==5?NULL:&b.options,i==6?NULL:&b.workspace,
            i==7?NULL:configure,&w,i==8?NULL:resolve,&w,i==9?NULL:&w.remaining,
            i==10?NULL:&w.remaining_completion,i==11?NULL:&b.report);
        if (i<12) CHECK(r==VIREO_RESULT_INVALID_ARGUMENT && errno==EDOM);
        else CHECK(r==VIREO_OK && errno==EDOM); /* 完整公共入口空轮真实运行。 */
    }
    for (unsigned i=0;i<7;++i) {
        vireo_async_service_ops_t op=model_ops;
        if (i==0) op.pressure=NULL; else if (i==1) op.poll=NULL; else if (i==2) op.dispatch=NULL;
        else if (i==3) op.drive=NULL; else if (i==4) op.schedule=NULL; else if (i==5) op.admit=NULL;
        EXPECT(invoke(&w,&b,&m,w.handle,i==6?NULL:&op),VIREO_RESULT_INVALID_ARGUMENT); CHECK(m.count==0);
    }
    for (unsigned i=0;i<5;++i) {
        prepare_batch(&w,&b);
        if (i==0) b.workspace.ready=NULL; else if (i==1) b.workspace.turns=NULL; else if (i==2) b.workspace.clients=NULL;
        else if (i==3) b.workspace.admission_turns=NULL; else b.workspace.response_bytes=NULL;
        model_call(&w,&b,&m,VIREO_RESULT_INVALID_ARGUMENT); CHECK(m.count==0 && !b.report.pre_pressure_called);
    }
    cleanup(&w);
}
static void zero_budgets(void) {
    world_t w; setup(&w,0); batch_t b; model_t m={.world=&w};
    for (unsigned i=0;i<10;++i) {
        prepare_batch(&w,&b);
        if (i==0) b.options.timeout_ms=-1; else if (i==1) b.options.max_clients=0;
        else if (i==2) b.options.admit.max_accepts=0; else if (i==3) b.options.admit.max_accept_syscalls=0;
        else if (i==4) b.options.max_completion_items=0; else if (i==5) b.options.max_response_batch_bytes=0;
        else if (i==6) b.workspace.ready_capacity=0; else if (i==7) b.workspace.turn_capacity=0;
        else if (i==8) b.workspace.client_capacity=0; else b.workspace.admission_turn_capacity=0;
        model_call(&w,&b,&m,VIREO_RESULT_INVALID_ARGUMENT); CHECK(m.count==0 && b.report.stage==VIREO_ASYNC_SERVICE_NONE);
    }
    cleanup(&w);
}
static void count_ranges(void) {
    world_t w; setup(&w,0); batch_t b; model_t m={.world=&w};
    for (unsigned i=0;i<7;++i) {
        prepare_batch(&w,&b);
        if (i==0) b.options.max_clients=65536; else if (i==1) b.options.admit.max_accepts=65536;
        else if (i==2) b.workspace.ready_capacity=65536; else if (i==3) b.workspace.turn_capacity=65536;
        else if (i==4) b.workspace.client_capacity=65536; else if (i==5) b.workspace.admission_turn_capacity=65536;
        else b.options.max_completion_items=65537;
        model_call(&w,&b,&m,VIREO_RESULT_RANGE); CHECK(m.count==0);
    }
    prepare_batch(&w,&b); b.options.admit.max_accept_syscalls=SIZE_MAX;
    b.options.max_completion_items=65536; b.options.max_clients=65535;
    model_call(&w,&b,&m,VIREO_OK); CHECK(b.report.clients.effective_max_clients==4 && strcmp(m.order,"PWDZ")==0); cleanup(&w);
}
static void output_guards(void) {
    world_t w; setup(&w,0); batch_t b; model_t m={.world=&w};
    for (unsigned i=0;i<3;++i) {
        prepare_batch(&w,&b);
        if (i==0) w.net.out[0].pool_id=1; else if (i==1) w.net.out[0].slot_index=1; else w.net.out[0].generation=1;
        vireo_connection_pool_lease_t const old=w.net.out[0]; model_call(&w,&b,&m,VIREO_RESULT_INVALID_ARGUMENT);
        CHECK(lease_same(old,w.net.out[0]) && m.count==0);
    }
    prepare_batch(&w,&b); EXPECT(vireo_task_create_copy(numeric_metadata(),NULL,0,4096,&w.remaining),VIREO_OK);
    vireo_task_t *const old=w.remaining; model_call(&w,&b,&m,VIREO_RESULT_INVALID_ARGUMENT); CHECK(w.remaining==old);
    EXPECT(vireo_task_destroy(&w.remaining),VIREO_OK);
    vireo_completion_metadata_t meta; EXPECT(vireo_completion_metadata_make(numeric_metadata(),VIREO_OK,VIREO_STATUS_OK,&meta),VIREO_OK);
    EXPECT(vireo_completion_create_copy(meta,NULL,0,4096,&w.remaining_completion),VIREO_OK);
    vireo_completion_t *const oldc=w.remaining_completion; model_call(&w,&b,&m,VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(w.remaining_completion==oldc && m.count==0); cleanup(&w);
}
static void numeric_ranges(void) {
    world_t w; setup(&w,0); batch_t b; model_t m={.world=&w};
    for (unsigned i=0;i<8;++i) {
        prepare_batch(&w,&b);
        if (i==0) b.options.connection.read_capacity=0; else if (i==1) b.options.connection.write_capacity=0;
        else if (i==2) b.options.connection.max_buffer_bytes=0; else if (i==3) b.options.connection.read_capacity=VIREO_BUFFER_MAX_CAPACITY+1;
        else if (i==4) b.options.connection.write_capacity=VIREO_BUFFER_MAX_CAPACITY+1;
        else if (i==5) b.options.connection.max_buffer_bytes=VIREO_CONNECTION_MAX_BUFFER_BYTES+1;
        else if (i==6) b.options.connection.max_buffer_bytes=383;
        else { b.options.connection.read_capacity=SIZE_MAX; b.options.connection.write_capacity=1; }
        model_call(&w,&b,&m,i==7?VIREO_RESULT_OVERFLOW:VIREO_RESULT_RANGE);
        CHECK(m.count==0 && b.report.stage==VIREO_ASYNC_SERVICE_VALIDATE);
    }
    cleanup(&w);
}
static void flow_ranges(void) {
    world_t w; setup(&w,0); batch_t b; model_t m={.world=&w};
    for (unsigned i=0;i<9;++i) {
        prepare_batch(&w,&b);
        if (i==0) b.options.flow.max_frame_bytes=0; else if (i==1) b.options.flow.max_frame_bytes=31;
        else if (i==2) b.options.flow.max_frame_bytes=16777249; else if (i==3) b.options.flow.max_frame_bytes=257;
        else if (i==4) b.options.flow.read_low=62; else if (i==5) b.options.flow.read_high=63;
        else if (i==6) b.options.flow.read_high=257; else if (i==7) b.options.flow.write_high=32;
        else b.options.flow.write_high=129;
        model_call(&w,&b,&m,VIREO_RESULT_RANGE); CHECK(m.count==0);
    }
    cleanup(&w);
}
static void response_ranges(void) {
    world_t w; setup(&w,0); batch_t b; model_t m={.world=&w};
    for (unsigned i=0;i<5;++i) {
        prepare_batch(&w,&b);
        if (i==0) b.options.max_response_frame_bytes=31; else if (i==1) b.options.max_response_frame_bytes=16777249;
        else if (i==2) b.options.max_response_batch_bytes=VIREO_COMPLETION_RESPONSE_DISPATCH_MAX_BATCH_BYTES+1;
        else if (i==3) b.options.max_response_batch_bytes=63; else b.workspace.response_capacity=63;
        model_call(&w,&b,&m,VIREO_RESULT_RANGE); CHECK(m.count==0);
    }
    cleanup(&w);
}
static void handle_priority(void) {
    world_t w; setup(&w,0); batch_t b; prepare_batch(&w,&b); model_t m={.world=&w};
    EXPECT(invoke(&w,&b,&m,(vireo_event_loop_handle_t){0},&model_ops),VIREO_RESULT_NOT_FOUND);
    EXPECT(invoke(&w,&b,&m,(vireo_event_loop_handle_t){1,0},&model_ops),VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(invoke(&w,&b,&m,(vireo_event_loop_handle_t){0,1},&model_ops),VIREO_RESULT_INVALID_ARGUMENT);
    b.options.connection.read_capacity=SIZE_MAX; b.options.connection.write_capacity=1;
    EXPECT(invoke(&w,&b,&m,(vireo_event_loop_handle_t){0},&model_ops),VIREO_RESULT_OVERFLOW);
    CHECK(m.count==0); cleanup(&w);
}
static void no_work(void) {
    world_t w; setup(&w,0); batch_t b; prepare_batch(&w,&b); model_t m={0};
    memset(b.ready,0xA5,sizeof b.ready); memset(b.turns,0xA5,sizeof b.turns);
    unsigned char ready[sizeof b.ready],turns[sizeof b.turns]; memcpy(ready,b.ready,sizeof ready); memcpy(turns,b.turns,sizeof turns);
    model_call(&w,&b,&m,VIREO_OK); CHECK(strcmp(m.order,"PWDZ")==0 && m.pressures==2);
    CHECK(b.report.poll_report.poll.selected_count==0 && !b.report.admission_called && b.report.clients.turn_count==0);
    CHECK(memcmp(ready,b.ready,sizeof ready)==0 && memcmp(turns,b.turns,sizeof turns)==0); cleanup(&w);
}
static void stage_order(void) {
    world_t w; setup(&w,3); batch_t b; prepare_batch(&w,&b); model_t m={.reschedule=true};
    model_call(&w,&b,&m,VIREO_OK); CHECK(strcmp(m.order,"PWDCVSCVSCVSZ")==0);
    CHECK(b.report.poll_report.poll.selected_count==3 && b.report.clients.drive_calls==3 && b.report.clients.requeued_count==3);
    CHECK(state(&w.net).pending_clients==3 && b.report.clients.poll_report.effective_timeout_ms==0 && !b.report.admission_called); cleanup(&w);
}
static void effective_min_and_tail(void) {
    world_t w; setup(&w,3); batch_t b; prepare_batch(&w,&b); model_t m={0};
    b.workspace.turn_capacity=2; b.options.admit.max_accepts=1;
    w.net.out[1]=(vireo_connection_pool_lease_t){1,1,1};
    memset(&b.ready[2],0xA5,sizeof b.ready[2]); memset(&b.turns[2],0xA5,sizeof b.turns[2]);
    unsigned char rt[sizeof b.ready[2]],tt[sizeof b.turns[2]]; memcpy(rt,&b.ready[2],sizeof rt); memcpy(tt,&b.turns[2],sizeof tt);
    model_call(&w,&b,&m,VIREO_OK); CHECK(b.report.clients.effective_max_clients==2 && b.report.clients.turn_count==2);
    CHECK(state(&w.net).pending_clients==1 && memcmp(rt,&b.ready[2],sizeof rt)==0 && memcmp(tt,&b.turns[2],sizeof tt)==0);
    CHECK(w.net.out[1].generation==1 && strcmp(m.order,"PWDCVCVZ")==0); cleanup(&w);
}
static void pressure_failure(void) {
    world_t w; setup(&w,0); batch_t b; prepare_batch(&w,&b); model_t m={.pre_error=VIREO_RESULT_IO};
    model_call(&w,&b,&m,VIREO_RESULT_IO); CHECK(strcmp(m.order,"P")==0 && !b.report.post_pressure_called && !b.report.poll_called);
    CHECK(b.report.stage==VIREO_ASYNC_SERVICE_PRE_PRESSURE); cleanup(&w);
}
static void poll_failure_prefix(void) {
    world_t w; setup(&w,3); batch_t b; prepare_batch(&w,&b); model_t m={.poll_error=VIREO_RESULT_IO,.post_error=VIREO_RESULT_NO_MEMORY};
    b.options.max_clients=2; model_call(&w,&b,&m,VIREO_RESULT_IO);
    CHECK(strcmp(m.order,"PWZ")==0 && b.report.stage==VIREO_ASYNC_SERVICE_POLL && b.report.post_pressure_result==VIREO_RESULT_NO_MEMORY);
    CHECK(b.report.poll_report.poll.selected_count==2 && b.report.clients.poll_result==VIREO_RESULT_IO && b.report.clients.unprocessed_begin==0);
    CHECK(lease_same(b.ready[0].client,w.net.live[0]) && lease_same(b.ready[1].client,w.net.live[1]) && state(&w.net).pending_clients==1); cleanup(&w);
}
static void poll_stopped(void) {
    world_t w; setup(&w,0); batch_t b; prepare_batch(&w,&b); model_t m={.stopped=true};
    model_call(&w,&b,&m,VIREO_RESULT_CANCELLED); CHECK(strcmp(m.order,"PWZ")==0 && b.report.stage==VIREO_ASYNC_SERVICE_POLL);
    CHECK(b.report.poll_report.poll.stopped && b.report.clients.poll_result==VIREO_OK && b.report.post_pressure_called); cleanup(&w);
}
static void listener_errors(void) {
    uint32_t const bits[]={VIREO_EPOLL_EVENT_ERROR,VIREO_EPOLL_EVENT_HANGUP,VIREO_EPOLL_EVENT_READ|VIREO_EPOLL_EVENT_ERROR,
        VIREO_EPOLL_EVENT_WRITE,VIREO_EPOLL_EVENT_READ|VIREO_EPOLL_EVENT_HANGUP|VIREO_EPOLL_EVENT_WRITE};
    for (size_t i=0;i<sizeof bits/sizeof bits[0];++i) {
        world_t w; setup(&w,3); batch_t b; prepare_batch(&w,&b); model_t m={.override_listener=true,.listener=bits[i]};
        model_call(&w,&b,&m,i==3?VIREO_RESULT_INTERNAL:VIREO_RESULT_IO);
        CHECK(strcmp(m.order,"PWZ")==0 && b.report.stage==VIREO_ASYNC_SERVICE_LISTENER_EVENT && !b.report.dispatch_called);
        CHECK(b.report.poll_report.listener_events==bits[i] && b.report.poll_report.poll.selected_count==3 && b.report.clients.turn_count==0); cleanup(&w);
    }
}
static void dispatch_failure_owner(void) {
    world_t w; setup(&w,3); batch_t b; prepare_batch(&w,&b); model_t m={.dispatch_error=true,.post_error=VIREO_RESULT_RANGE};
    model_call(&w,&b,&m,VIREO_RESULT_IO); CHECK(strcmp(m.order,"PWDZ")==0 && b.report.stage==VIREO_ASYNC_SERVICE_DISPATCH);
    CHECK(w.remaining_completion!=NULL && b.report.clients.turn_count==0 && b.report.post_pressure_result==VIREO_RESULT_RANGE);
    vireo_completion_info_t info; EXPECT(vireo_completion_inspect(w.remaining_completion,&info),VIREO_OK);
    CHECK(metadata_same(info.metadata.request,numeric_metadata())); cleanup(&w);
}
static void configure_failure(void) {
    world_t w; setup(&w,3); batch_t b; prepare_batch(&w,&b); model_t m={.configure_at=2,.post_error=VIREO_RESULT_IO};
    memset(&b.turns[2],0xA5,sizeof b.turns[2]); unsigned char tail[sizeof b.turns[2]]; memcpy(tail,&b.turns[2],sizeof tail);
    model_call(&w,&b,&m,VIREO_RESULT_PROTOCOL); CHECK(strcmp(m.order,"PWDCVCZ")==0 && b.report.stage==VIREO_ASYNC_SERVICE_CLIENTS);
    CHECK(b.report.clients.stage==VIREO_ASYNC_ROUND_CONFIGURE && b.report.clients.turn_count==2 && b.report.clients.unprocessed_begin==2);
    CHECK(b.report.clients.drive_calls==1 && !b.turns[1].drive_called && memcmp(tail,&b.turns[2],sizeof tail)==0);
    CHECK(lease_same(b.ready[2].client,w.net.live[2]) && b.report.post_pressure_result==VIREO_RESULT_IO); cleanup(&w);
}
static void drive_failure_owner(void) {
    world_t w; setup(&w,3); batch_t b; prepare_batch(&w,&b); model_t m={.drive_at=2};
    model_call(&w,&b,&m,VIREO_RESULT_NO_MEMORY); CHECK(strcmp(m.order,"PWDCVCVZ")==0 && b.report.clients.stage==VIREO_ASYNC_ROUND_DRIVE);
    CHECK(b.report.clients.turn_count==2 && b.report.clients.drive_calls==2 && w.remaining!=NULL && b.report.clients.unprocessed_begin==2);
    vireo_task_info_t info; EXPECT(vireo_task_inspect(w.remaining,&info),VIREO_OK); CHECK(metadata_same(info.metadata,numeric_metadata())); cleanup(&w);
}
static void schedule_failure(void) {
    world_t w; setup(&w,3); batch_t b; prepare_batch(&w,&b); model_t m={.reschedule=true,.schedule_at=2};
    model_call(&w,&b,&m,VIREO_RESULT_BUSY); CHECK(strcmp(m.order,"PWDCVSCVSZ")==0 && b.report.clients.stage==VIREO_ASYNC_ROUND_SCHEDULE);
    CHECK(b.report.clients.turn_count==2 && b.report.clients.requeued_count==1 && state(&w.net).pending_clients==1);
    CHECK(b.turns[1].schedule_called && b.turns[1].schedule_result==VIREO_RESULT_BUSY); cleanup(&w);
}
static void admission_partial(void) {
    world_t w; setup(&w,0); connect_clients(&w.net,3); batch_t b; prepare_batch(&w,&b); model_t m={.admit_error=true};
    model_call(&w,&b,&m,VIREO_RESULT_IO); CHECK(strcmp(m.order,"PWDAZ")==0 && b.report.stage==VIREO_ASYNC_SERVICE_ADMIT);
    CHECK(b.report.admission_called && b.report.admission_report.admission.admitted_count==1 && w.net.live_count==1);
    CHECK(b.report.clients.drive_calls==0 && lease_same(w.net.live[0],w.net.out[0]) && b.report.post_pressure_called); cleanup(&w);
}
static void post_only_failure(void) {
    world_t w; setup(&w,0); batch_t b; prepare_batch(&w,&b); model_t m={.post_error=VIREO_RESULT_IO};
    model_call(&w,&b,&m,VIREO_RESULT_IO); CHECK(strcmp(m.order,"PWDZ")==0 && b.report.stage==VIREO_ASYNC_SERVICE_POST_PRESSURE);
    CHECK(b.report.post_pressure_result==VIREO_RESULT_IO && b.report.post_pressure_report.stage==VIREO_ASYNC_ADMISSION_PRESSURE_UPDATE_READ); cleanup(&w);
}
static void real_stop_and_auto(void) {
    world_t w; setup(&w,0); batch_t b; prepare_batch(&w,&b);
    vireo_tcp_server_admission_options_t const o={connection,flow}; EXPECT(vireo_tcp_server_admission_configure(w.net.server,&o,NULL),VIREO_OK);
    EXPECT(vireo_async_service_once(w.net.server,w.store,w.pool,w.notifier,w.outputs,w.handle,&b.options,&b.workspace,
        configure,&w,resolve,&w,&w.remaining,&w.remaining_completion,&b.report),VIREO_RESULT_BUSY);
    CHECK(!b.report.poll_called && !b.report.post_pressure_called); EXPECT(vireo_tcp_server_admission_disable(w.net.server,NULL),VIREO_OK);
    EXPECT(vireo_tcp_server_request_stop(w.net.server,NULL),VIREO_OK);
    EXPECT(vireo_async_service_once(w.net.server,w.store,w.pool,w.notifier,w.outputs,w.handle,&b.options,&b.workspace,
        configure,&w,resolve,&w,&w.remaining,&w.remaining_completion,&b.report),VIREO_RESULT_CANCELLED);
    CHECK(b.report.pre_pressure_called && !b.report.poll_called && !b.report.post_pressure_called); cleanup(&w);
}
static void real_pressure_restore(void) {
    world_t w; setup(&w,0); connect_clients(&w.net,3); batch_t b; service(&w,&b,1000);
    CHECK(w.net.live_count==3 && b.report.clients.drive_calls==0 && b.report.post_pressure_report.connection_limited);
    CHECK(!state(&w.net).listener_read_enabled);
    EXPECT(vireo_tcp_server_release_client(w.net.server,&w.net.live[2],NULL),VIREO_OK);
    service(&w,&b,0); CHECK(b.report.pre_pressure_report.update_called && b.report.pre_pressure_report.read_after);
    CHECK(state(&w.net).connection_count==2 && state(&w.net).listener_read_enabled); cleanup(&w);
}
static void integration(void) {
    world_t w; setup(&w,0); connect_clients(&w.net,3);
    for (unsigned tag=1;tag<=3;++tag) { uint8_t wire[35]; encode(wire,tag); send_all(w.net.peers[tag-1],wire,sizeof wire); }
    batch_t b; service(&w,&b,1000);
    CHECK(w.net.live_count==3 && b.report.clients.drive_calls==0 && b.report.admission_report.scheduled_count==3 && w.submitted==0);
    for (size_t i=0;i<3;++i) CHECK(client_info(&w.net,i).connection_info.read_buffer.readable_size==0);
    service(&w,&b,0); CHECK(w.submitted==3 && b.report.clients.drive_calls==3 && w.remaining==NULL);
    CHECK(w.entries[1].metadata.request_instance_id!=w.entries[2].metadata.request_instance_id && w.entries[2].metadata.request_instance_id!=w.entries[3].metadata.request_instance_id);
    CHECK(b.report.dispatch_report.enqueued_responses==0); /* 旧结果先消费，本轮新任务尚由caller保存关联。 */
    release_worker(&w); published(&w); size_t finished=0,bytes=0;
    for (size_t i=0;i<24 && finished<3;++i) {
        service(&w,&b,1000); size_t const n=b.report.dispatch_report.dispatch_report.dispatch_report.drain_report.finished;
        CHECK(n<=1 && b.report.dispatch_report.enqueued_bytes<=64); finished+=n; bytes+=b.report.dispatch_report.enqueued_bytes;
    }
    CHECK(finished==3 && bytes==105 && w.remaining_completion==NULL);
    for (size_t i=0;i<3;++i) EXPECT(vireo_tcp_server_schedule_client(w.net.server,w.net.live[i],NULL),VIREO_OK);
    service(&w,&b,0); for (size_t i=0;i<3;++i) check_response(&w,i,(unsigned)i+1); cleanup(&w);
}
int main(void) {
    int old; CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,&old)==0);
    void (*const tests[])(void)={parameters,zero_budgets,count_ranges,output_guards,numeric_ranges,flow_ranges,response_ranges,
        handle_priority,no_work,stage_order,effective_min_and_tail,pressure_failure,poll_failure_prefix,poll_stopped,listener_errors,
        dispatch_failure_owner,configure_failure,drive_failure_owner,schedule_failure,admission_partial,post_only_failure,
        real_stop_and_auto,real_pressure_restore,integration};
    for (size_t i=0;i<sizeof tests/sizeof tests[0];++i) { unsigned const n=fd_count(); tests[i](); CHECK(fd_count()==n); }
    CHECK(pthread_setcancelstate(old,NULL)==0); puts("async service: 24 groups, 0 failures"); return 0;
}
