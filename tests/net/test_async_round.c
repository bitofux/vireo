/*
 * PROJECT : VIREO
 * FILE    : test_async_round.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-14
 * BRIEF   : 多客户真实链、逐项预算与失败后缀/残留责任
 */
#define _GNU_SOURCE
#include "net/async_round_internal.h" /* 仅本轮接线层seam。 */
#include <vireo/net/completion_response_dispatch.h>
#include <vireo/net/notifier_server.h>
#include <vireo/thread/completion_publish.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); abort(); } } while (0)
#define EXPECT(x,y) do { errno = EDOM; vireo_result_t const result_ = (x); CHECK(result_ == (y) && errno == EDOM); } while (0)

/** caller保存每个真实移交请求的原关联。 */
typedef struct entry {
    bool valid; /**< 真实transfer后设置，非inflight当前性证明。 */
    vireo_task_metadata_t metadata; /**< 原完整请求身份/固定快照。 */
    vireo_protocol_header_t header; /**< 原wire头，响应不从operation猜。 */
    unsigned resolved; /**< 描述次数，只main写。 */
} entry_t;
/** 真实固定worker的独立context，没有server或网络fd。 */
typedef struct worker {
    vireo_completion_queue_t *outputs; /**< 借到pool销毁，consumer须配合。 */
    vireo_notifier_t *notifier; /**< eventfd借到全部producer结束。 */
    pthread_barrier_t entered; /**< 预热已领取且queue锁已释放。 */
    pthread_barrier_t release; /**< main放行预热，不抢占callback。 */
    atomic_uint published; /**< release/acquire统计helper返回，不代替join。 */
    vireo_completion_publish_report_t reports[9]; /**< worker按tag独立写，main只join后读。 */
} worker_t;
/** 测试Reactor独占的实际资源与caller配置/关联。 */
typedef struct world {
    vireo_tcp_server_t *server; /**< 网络root owner，辅助预留1项。 */
    vireo_connection_pool_lease_t clients[3]; /**< 三个完整当前租约，不拥有fd。 */
    int peers[3]; /**< 对端fd owner，-1为空。 */
    struct sockaddr_in address; /**< 临时loopback端点。 */
    vireo_inflight_store_t *store; /**< 固定登记owner，结束时显式take。 */
    vireo_task_queue_t *tasks; /**< 专用于pool的task queue owner。 */
    vireo_thread_pool_t *pool; /**< 一个真实worker，管理main串行。 */
    vireo_completion_queue_t *outputs; /**< 单main消费者，8槽。 */
    vireo_notifier_t *notifier; /**< 先注销借用再destroy。 */
    vireo_event_loop_handle_t handle; /**< 原辅助完整注册身份。 */
    worker_t worker; /**< 原位长期执行context。 */
    bool released; /**< 预热只释放一次。 */
    unsigned submitted; /**< 已确认实际数据task移交数，不含预热。 */
    entry_t entries[9]; /**< 原header与metadata账本，main维护。 */
    vireo_async_request_pending_t pending[3]; /**< 每完整租约唯一稳定gate。 */
    vireo_task_cancel_t *cancel; /**< 可空caller来源强引用，config仅借。 */
    vireo_task_t *remaining; /**< 未转移task owner。 */
    vireo_completion_t *remaining_completion; /**< 原分发失败残留owner。 */
    vireo_tcp_server_ready_client_t ready[4]; /**< poll完整有效前缀和未处理后缀。 */
    vireo_async_round_turn_t turns[4]; /**< 实际尝试前缀，尾哨兵不读为逻辑字段。 */
    vireo_async_round_report_t report; /**< 原轮次真实进度。 */
    size_t configured; /**< 配置尝试累计数，callback只main写。 */
    size_t fail_configure_at; /**< 0不注入，指定配置次数返回IO/不读半成品。 */
    size_t bad_configure_at; /**< 指定次数返回OK但pending=NULL，沿driver拒绝。 */
    bool tiny_send; /**< 固定测试策略，各客户send预算1/2/3字节。 */
    uint8_t scratch[64]; /**< 响应单帧scratch，main独占。 */
} world_t;
/** 仅本层公开边界模型，真实转移与模型错误分开。 */
typedef struct fault {
    bool poll_io; /**< 无进度poll失败模型，不操作真实Q。 */
    bool partial_poll; /**< 实际公开取一项后报告QUEUE IO模型。 */
    bool stop_after_poll; /**< 实际公开poll后公开request_stop。 */
    bool transferred_error; /**< 实际driver转移后给末刷新IO模型，不破坏内核。 */
    bool schedule_busy; /**< 一次排尾BUSY无变更模型。 */
    size_t schedule_calls; /**< 本次模型尝试数。 */
} fault_t;
static vireo_connection_options_t const connection = {256,128,384};
static vireo_connection_flow_options_t const flow = {64,63,192,32,96};
static bool lease_same(vireo_connection_pool_lease_t a, vireo_connection_pool_lease_t b) {
    return a.pool_id == b.pool_id && a.slot_index == b.slot_index && a.generation == b.generation;
}
static bool metadata_same(vireo_task_metadata_t a, vireo_task_metadata_t b) {
    bool same; EXPECT(vireo_task_metadata_same_request(a,b,&same), VIREO_OK);
    return same && a.operation == b.operation && a.deadline_ns == b.deadline_ns;
}
static size_t client_index(world_t *w, vireo_connection_pool_lease_t client) {
    for (size_t i=0;i<3;++i) if (lease_same(w->clients[i],client)) return i;
    CHECK(false); return 0;
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
static void prepare(world_t *w,size_t capacity) {
    *w=(world_t){.peers={-1,-1,-1}}; atomic_init(&w->worker.published,0);
    vireo_tcp_server_options_t const so={3,8,1048576,4096};
    EXPECT(vireo_tcp_server_create_with_auxiliary_capacity(&so,1,&w->server,NULL),VIREO_OK);
    int fd=socket(AF_INET,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0); CHECK(fd>=0);
    w->address=(struct sockaddr_in){.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
    CHECK(bind(fd,(struct sockaddr *)&w->address,sizeof w->address)==0 && listen(fd,4)==0);
    socklen_t n=sizeof w->address; CHECK(getsockname(fd,(struct sockaddr *)&w->address,&n)==0);
    vireo_acceptor_t *listener=NULL; vireo_acceptor_options_t const ao={4096};
    EXPECT(vireo_acceptor_create(&ao,&fd,&listener,NULL),VIREO_OK);
    EXPECT(vireo_tcp_server_adopt_listener(w->server,&listener,NULL),VIREO_OK);
    for (size_t i=0;i<3;++i) {
        w->peers[i]=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0); CHECK(w->peers[i]>=0);
        CHECK(connect(w->peers[i],(struct sockaddr *)&w->address,sizeof w->address)==0);
        vireo_tcp_server_admit_budget_t const ab={1,2}; vireo_tcp_server_admit_info_t info;
        EXPECT(vireo_tcp_server_admit_batch(w->server,&connection,&ab,&w->clients[i],1,&info,NULL),VIREO_OK);
        CHECK(info.admitted_count==1);
        EXPECT(vireo_tcp_server_client_flow_configure(w->server,w->clients[i],&flow,NULL),VIREO_OK);
    }
    vireo_inflight_store_options_t const io={8,65536}; EXPECT(vireo_inflight_store_create(&io,&w->store),VIREO_OK);
    vireo_task_queue_options_t const tq={capacity,65536}; EXPECT(vireo_task_queue_create(&tq,&w->tasks),VIREO_OK);
    EXPECT(vireo_task_queue_prepare_wait(w->tasks),VIREO_OK);
    vireo_completion_queue_options_t const cq={8,65536}; EXPECT(vireo_completion_queue_create(&cq,&w->outputs),VIREO_OK);
    EXPECT(vireo_completion_queue_prepare_wait(w->outputs),VIREO_OK);
    vireo_notifier_options_t const no={4096}; EXPECT(vireo_notifier_create(&no,&w->notifier,NULL),VIREO_OK);
    EXPECT(vireo_notifier_server_register(w->server,w->notifier,&w->handle,NULL),VIREO_OK);
    w->worker.outputs=w->outputs; w->worker.notifier=w->notifier;
    CHECK(pthread_barrier_init(&w->worker.entered,NULL,2)==0 && pthread_barrier_init(&w->worker.release,NULL,2)==0);
    vireo_thread_pool_options_t const po={1,65536}; EXPECT(vireo_thread_pool_create(&po,&w->pool),VIREO_OK);
    vireo_thread_pool_configuration_t const config={w->tasks,execute,&w->worker};
    EXPECT(vireo_thread_pool_configure(w->pool,&config,NULL),VIREO_OK);
    vireo_task_route_t route; vireo_task_metadata_t metadata; vireo_task_t *warm=NULL;
    EXPECT(vireo_task_route_make(UINT64_MAX,0,1,1,&route),VIREO_OK);
    EXPECT(vireo_task_metadata_make(route,1,1,UINT64_MAX,&metadata),VIREO_OK);
    EXPECT(vireo_task_create_copy(metadata,NULL,0,4096,&warm),VIREO_OK);
    vireo_task_queue_transfer_report_t qr; EXPECT(vireo_task_queue_try_push(w->tasks,&warm,&qr),VIREO_OK);
    vireo_thread_pool_report_t pr; EXPECT(vireo_thread_pool_start(w->pool,&pr),VIREO_OK);
    EXPECT(vireo_thread_pool_enable_execution(w->pool,&pr),VIREO_OK); meet(&w->worker.entered);
}
static void release_worker(world_t *w) {
    if (!w->released) { meet(&w->worker.release); w->released=true; }
}
static void published(world_t *w) {
    for (size_t i=0;i<1000000;++i) {
        if (atomic_load_explicit(&w->worker.published,memory_order_acquire)==w->submitted) return;
        sched_yield();
    }
    CHECK(false);
}
static vireo_tcp_server_info_t server_info(world_t *w) {
    vireo_tcp_server_info_t info; EXPECT(vireo_tcp_server_inspect(w->server,&info),VIREO_OK); return info;
}
static vireo_tcp_server_client_info_t client_info(world_t *w,size_t i) {
    vireo_tcp_server_client_info_t info; EXPECT(vireo_tcp_server_client_inspect(w->server,w->clients[i],&info),VIREO_OK); return info;
}
/** 仅测试caller恢复关闭锁/回收前观测竞争；实际停止或join错误仍失败。 */
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
static void finish(world_t *w) {
    for (size_t i=0;i<3;++i) if (w->pending[i].frame_bytes!=0) {
        vireo_async_request_head_report_t r; EXPECT(vireo_async_request_resume_consume(w->server,&w->pending[i],&r),VIREO_OK);
    }
    EXPECT(vireo_task_destroy(&w->remaining),VIREO_OK); EXPECT(vireo_completion_destroy(&w->remaining_completion),VIREO_OK);
    release_worker(w); published(w); /* 每组最多4项，8输出槽；完整任意负载停机不是本测试结论。 */
    vireo_thread_pool_shutdown_report_t sr;
    EXPECT(shutdown_pool(w->pool,&sr),VIREO_OK);
    vireo_thread_pool_worker_result_t wr; EXPECT(vireo_thread_pool_inspect_worker_result(w->pool,0,&wr),VIREO_OK); CHECK(wr.result==VIREO_OK);
    vireo_completion_queue_close_report_t cr; EXPECT(vireo_completion_queue_close(w->outputs,&cr),VIREO_OK);
    for (;;) {
        vireo_completion_t *result=NULL; vireo_completion_queue_transfer_report_t qr;
        vireo_result_t const k=vireo_completion_queue_try_pop(w->outputs,&result,&qr);
        if (k==VIREO_RESULT_CANCELLED) break;
        CHECK(k==VIREO_OK && qr.transferred); EXPECT(vireo_completion_destroy(&result),VIREO_OK);
    }
    for (size_t tag=1;tag<=8;++tag) if (w->entries[tag].valid) {
        vireo_task_metadata_t metadata; vireo_result_t const k=vireo_inflight_store_take(w->store,w->entries[tag].metadata,&metadata,NULL);
        CHECK(k==VIREO_OK || k==VIREO_RESULT_NOT_FOUND);
        CHECK(w->worker.reports[tag].completion_transferred && w->worker.reports[tag].notify_called);
    }
    EXPECT(vireo_thread_pool_destroy(&w->pool),VIREO_OK); EXPECT(vireo_task_queue_destroy(&w->tasks),VIREO_OK);
    EXPECT(vireo_completion_queue_destroy(&w->outputs),VIREO_OK); EXPECT(vireo_inflight_store_destroy(&w->store),VIREO_OK);
    EXPECT(vireo_task_cancel_destroy(&w->cancel),VIREO_OK);
    EXPECT(vireo_notifier_server_unregister(w->server,&w->handle,NULL),VIREO_OK);
    EXPECT(vireo_notifier_destroy(&w->notifier,NULL),VIREO_OK);
    for (size_t i=0;i<3;++i) {
        EXPECT(vireo_tcp_server_release_client(w->server,&w->clients[i],NULL),VIREO_OK); CHECK(close(w->peers[i])==0);
    }
    EXPECT(vireo_tcp_server_destroy(&w->server,NULL),VIREO_OK);
    CHECK(pthread_barrier_destroy(&w->worker.entered)==0 && pthread_barrier_destroy(&w->worker.release)==0);
}
static vireo_result_t configure(void *context,vireo_tcp_server_ready_client_t client,vireo_async_round_config_t *out) {
    world_t *w=context; CHECK(out->pending==NULL && out->cancel==NULL && out->options.operation==0);
    ++w->configured; errno=ERANGE;
    if (w->configured==w->fail_configure_at) { out->options.operation=1; return VIREO_RESULT_IO; }
    size_t const i=client_index(w,client.client);
    *out=(vireo_async_round_config_t){{64,4096,8,(uint32_t)(9+i),UINT64_MAX-i},{{128,8},{128,8}},w->cancel,&w->pending[i]};
    if (w->tiny_send) out->budget.send=(vireo_connection_send_budget_t){i+1,1};
    if (w->configured==w->bad_configure_at) out->pending=NULL;
    return VIREO_OK;
}
static void schedule_order(world_t *w,size_t a,size_t b,size_t c) {
    size_t const order[3]={a,b,c};
    for (size_t i=0;i<3;++i) EXPECT(vireo_tcp_server_schedule_client(w->server,w->clients[order[i]],NULL),VIREO_OK);
}
static void book(world_t *w) {
    for (size_t i=0;i<w->report.turn_count;++i) {
        vireo_async_round_turn_t const t=w->turns[i];
        if (!t.drive_called || !t.drive_report.head_report.submit_report.task_transferred) continue;
        CHECK(t.drive_report.request_header_available); vireo_protocol_header_t const h=t.drive_report.request_header;
        unsigned const tag=h.sequence-100; CHECK(tag>=1 && tag<=8 && !w->entries[tag].valid);
        size_t const ci=client_index(w,t.client.client); vireo_task_metadata_t const m=t.drive_report.head_report.submit_report.metadata;
        CHECK(h.command==(tag==2?VIREO_COMMAND_UPLOAD_STATUS:VIREO_COMMAND_NODE_STAT));
        CHECK(h.flags==(tag==2?VIREO_PROTOCOL_FLAG_LONG_COMMAND:0) && h.body_len==3);
        CHECK(h.session_handle==0x12340000U+tag && h.task_handle==0x56780000U+tag);
        CHECK(m.route.client_owner_id==t.client.client.pool_id && m.route.client_slot_index==t.client.client.slot_index);
        CHECK(m.route.client_generation==t.client.client.generation && m.route.request_sequence==100+tag);
        CHECK(m.operation==9+ci && m.deadline_ns==UINT64_MAX-ci);
        w->entries[tag]=(entry_t){true,m,h,0}; ++w->submitted;
    }
}
static void round_once(world_t *w,int timeout,size_t max,size_t ready_cap,size_t turn_cap,vireo_result_t expected) {
    EXPECT(vireo_async_round_once(w->server,w->store,w->pool,timeout,max,configure,w,w->ready,ready_cap,
        w->turns,turn_cap,&w->remaining,&w->report),expected); book(w);
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
static void send_request(world_t *w,size_t i,unsigned tag) {
    uint8_t wire[35]; encode(wire,tag); send_all(w->peers[i],wire,sizeof wire);
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
static void respond(world_t *w) {
    release_worker(w); published(w); size_t finished=0;
    for (size_t i=0;i<24 && finished<w->submitted;++i) {
        round_once(w,1000,3,4,4,VIREO_OK);
        vireo_completion_response_dispatch_report_t report;
        EXPECT(vireo_completion_response_dispatch_ready(w->server,w->handle,w->notifier,w->store,w->outputs,
            1,64,64,w->scratch,sizeof w->scratch,resolve,w,&w->remaining_completion,&report),VIREO_OK);
        finished+=report.dispatch_report.dispatch_report.drain_report.finished;
    }
    CHECK(finished==w->submitted && w->remaining_completion==NULL);
    schedule_order(w,0,1,2); round_once(w,0,3,4,4,VIREO_OK);
}
static void check_response(world_t *w,size_t client,unsigned tag) {
    uint8_t bytes[35]; size_t n=0;
    for (size_t i=0;n<sizeof bytes && i<8;++i) {
        struct pollfd fd={w->peers[client],POLLIN,0}; CHECK(poll(&fd,1,1000)==1);
        ssize_t const k=recv(w->peers[client],bytes+n,sizeof bytes-n,MSG_DONTWAIT); CHECK(k>0); n+=(size_t)k;
    }
    CHECK(n==sizeof bytes); vireo_protocol_header_t h; vireo_protocol_codec_issue_t issue;
    EXPECT(vireo_protocol_header_decode(bytes,32,&h,&issue),VIREO_OK);
    EXPECT(vireo_protocol_frame_crc32c_verify(bytes,32,bytes+32,3,&issue),VIREO_OK);
    CHECK(h.sequence==100+tag && h.command==(tag==2?VIREO_COMMAND_UPLOAD_STATUS:VIREO_COMMAND_NODE_STAT));
    CHECK(h.flags==(uint16_t)((tag==2?VIREO_PROTOCOL_FLAG_LONG_COMMAND:0)|VIREO_PROTOCOL_FLAG_RESPONSE));
    CHECK(h.session_handle==0x12340000U+tag && h.task_handle==0x56780000U+tag && h.body_len==3 && h.status==VIREO_STATUS_OK);
    CHECK(bytes[32]==(uint8_t)(tag^0x5AU) && bytes[33]==0x5A && bytes[34]==0xFF && w->entries[tag].resolved==1);
}
static vireo_result_t model_poll(void *context,vireo_tcp_server_t *s,int timeout,size_t max,
    vireo_tcp_server_ready_client_t *ready,size_t capacity,vireo_tcp_server_poll_report_t *report) {
    fault_t *f=context; errno=ERANGE;
    if (f->poll_io) { *report=(vireo_tcp_server_poll_report_t){.stage=VIREO_TCP_SERVER_POLL_WAIT,.wait_called=true,
        .loop_error={.stage=VIREO_EVENT_LOOP_STAGE_WAIT,.epoll_error={VIREO_EPOLL_STAGE_WAIT,EINTR}}}; return VIREO_RESULT_IO; }
    vireo_result_t const result=vireo_tcp_server_poll_ready_once(s,timeout,f->partial_poll?1:max,ready,capacity,report);
    if (result!=VIREO_OK) return result;
    if (f->stop_after_poll) EXPECT(vireo_tcp_server_request_stop(s,NULL),VIREO_OK);
    if (f->partial_poll) { CHECK(report->selected_count==1); report->stage=VIREO_TCP_SERVER_POLL_QUEUE; return VIREO_RESULT_IO; }
    return VIREO_OK;
}
static vireo_result_t model_drive(void *context,vireo_tcp_server_t *s,vireo_connection_pool_lease_t c,
    vireo_inflight_store_t *store,vireo_thread_pool_t *pool,vireo_async_client_drive_options_t const *o,
    vireo_async_client_drive_budget_t const *b,vireo_task_cancel_t *cancel,vireo_async_request_pending_t *pending,
    vireo_task_t **owner,vireo_async_client_drive_report_t *report) {
    fault_t *f=context;
    vireo_result_t const result=vireo_async_client_drive_once(s,c,store,pool,o,b,cancel,pending,owner,report);
    if (result==VIREO_OK && f->transferred_error && report->head_report.submit_report.task_transferred) {
        report->stage=VIREO_ASYNC_CLIENT_DRIVE_FINAL_REFRESH; report->final_refresh_result=VIREO_RESULT_IO;
        report->final_refresh_error=(vireo_tcp_server_client_error_t){.primary.stage=VIREO_TCP_SERVER_CLIENT_FLOW_REFRESH};
        report->final_inspect_called=false; report->needs_reschedule=false; errno=ERANGE; return VIREO_RESULT_IO;
    }
    return result;
}
static vireo_result_t model_schedule(void *context,vireo_tcp_server_t *s,vireo_connection_pool_lease_t c,
    vireo_tcp_server_client_error_t *error) {
    fault_t *f=context; ++f->schedule_calls;
    if (f->schedule_busy) { *error=(vireo_tcp_server_client_error_t){0}; errno=ERANGE; return VIREO_RESULT_BUSY; }
    return vireo_tcp_server_schedule_client(s,c,error);
}
static vireo_async_round_ops_t const model_ops={model_poll,model_drive,model_schedule};
static void model_round(world_t *w,fault_t *f,vireo_result_t expected) {
    EXPECT(vireo_async_round_with_ops(w->server,w->store,w->pool,0,3,configure,w,w->ready,4,w->turns,4,
        &w->remaining,&w->report,&model_ops,f),expected); book(w);
}
static void parameters(void) {
    world_t w; prepare(&w,8); schedule_order(&w,0,1,2);
    memset(w.ready,0xA5,sizeof w.ready); memset(w.turns,0x5A,sizeof w.turns);
    unsigned char oldready[sizeof w.ready],oldturns[sizeof w.turns]; memcpy(oldready,w.ready,sizeof oldready); memcpy(oldturns,w.turns,sizeof oldturns);
    EXPECT(vireo_async_round_once(NULL,w.store,w.pool,0,1,configure,&w,w.ready,4,w.turns,4,&w.remaining,&w.report),VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_async_round_once(w.server,NULL,w.pool,0,1,configure,&w,w.ready,4,w.turns,4,&w.remaining,&w.report),VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_async_round_once(w.server,w.store,NULL,0,1,configure,&w,w.ready,4,w.turns,4,&w.remaining,&w.report),VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_async_round_once(w.server,w.store,w.pool,-1,1,configure,&w,w.ready,4,w.turns,4,&w.remaining,&w.report),VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_async_round_once(w.server,w.store,w.pool,0,0,configure,&w,w.ready,4,w.turns,4,&w.remaining,&w.report),VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_async_round_once(w.server,w.store,w.pool,0,1,NULL,&w,w.ready,4,w.turns,4,&w.remaining,&w.report),VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_async_round_once(w.server,w.store,w.pool,0,1,configure,&w,NULL,4,w.turns,4,&w.remaining,&w.report),VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_async_round_once(w.server,w.store,w.pool,0,1,configure,&w,w.ready,0,w.turns,4,&w.remaining,&w.report),VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_async_round_once(w.server,w.store,w.pool,0,1,configure,&w,w.ready,4,NULL,4,&w.remaining,&w.report),VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_async_round_once(w.server,w.store,w.pool,0,1,configure,&w,w.ready,4,w.turns,0,&w.remaining,&w.report),VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_async_round_once(w.server,w.store,w.pool,0,1,configure,&w,w.ready,4,w.turns,4,NULL,&w.report),VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_async_round_once(w.server,w.store,w.pool,0,1,configure,&w,w.ready,4,w.turns,4,&w.remaining,NULL),VIREO_RESULT_INVALID_ARGUMENT);
    for (size_t i=0;i<3;++i) round_once(&w,0,i==0?65536:1,i==1?65536:4,i==2?65536:4,VIREO_RESULT_RANGE);
    vireo_async_round_ops_t broken=model_ops; broken.drive=NULL; fault_t f={0};
    EXPECT(vireo_async_round_with_ops(w.server,w.store,w.pool,0,1,configure,&w,w.ready,4,w.turns,4,&w.remaining,&w.report,&broken,&f),VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(w.configured==0 && !w.report.poll_called && w.report.effective_max_clients==0);
    CHECK(memcmp(oldready,w.ready,sizeof oldready)==0 && memcmp(oldturns,w.turns,sizeof oldturns)==0 && server_info(&w).pending_clients==3);
    finish(&w);
}
static void fifo_and_capacity(void) {
    world_t w; prepare(&w,8); schedule_order(&w,2,0,1);
    memset(w.ready,0xA5,sizeof w.ready); memset(w.turns,0x5A,sizeof w.turns);
    unsigned char tailready[sizeof w.ready[2]],tailturn[sizeof w.turns[2]];
    memcpy(tailready,&w.ready[2],sizeof tailready); memcpy(tailturn,&w.turns[2],sizeof tailturn);
    round_once(&w,INT_MAX,65535,4,2,VIREO_OK);
    CHECK(w.report.effective_max_clients==2 && w.report.poll_report.effective_timeout_ms==0 && w.report.turn_count==2 && w.report.drive_calls==2);
    CHECK(lease_same(w.ready[0].client,w.clients[2]) && lease_same(w.ready[1].client,w.clients[0]));
    CHECK(memcmp(tailready,&w.ready[2],sizeof tailready)==0 && memcmp(tailturn,&w.turns[2],sizeof tailturn)==0);
    CHECK(w.report.unprocessed_begin==2 && server_info(&w).pending_clients==1 && !w.turns[0].drive_report.head_called);
    round_once(&w,0,3,1,4,VIREO_OK); CHECK(w.report.effective_max_clients==1 && lease_same(w.ready[0].client,w.clients[1]));
    schedule_order(&w,2,0,1); round_once(&w,0,1,4,4,VIREO_OK);
    CHECK(w.report.effective_max_clients==1 && w.report.turn_count==1 && lease_same(w.ready[0].client,w.clients[2]));
    finish(&w);
}
static void multi_roundtrip(void) {
    world_t w; prepare(&w,8); EXPECT(vireo_task_cancel_create(4096,&w.cancel),VIREO_OK);
    for (size_t i=0;i<3;++i) send_request(&w,i,(unsigned)i+1);
    schedule_order(&w,2,0,1); round_once(&w,0,3,4,4,VIREO_OK);
    CHECK(w.report.turn_count==3 && w.report.drive_calls==3 && w.submitted==3 && w.report.requeued_count==0);
    CHECK(lease_same(w.turns[0].client.client,w.clients[2]) && lease_same(w.turns[1].client.client,w.clients[0]));
    CHECK(w.entries[1].metadata.request_instance_id!=w.entries[2].metadata.request_instance_id && w.entries[2].metadata.request_instance_id!=w.entries[3].metadata.request_instance_id);
    vireo_task_cancel_t *reference=NULL; EXPECT(vireo_inflight_store_retain_cancel(w.store,w.entries[2].metadata,&reference,NULL),VIREO_OK);
    CHECK(reference==w.cancel); EXPECT(vireo_task_cancel_destroy(&reference),VIREO_OK);
    respond(&w); for (size_t i=0;i<3;++i) check_response(&w,i,(unsigned)i+1); finish(&w);
}
static void cached_tail(void) {
    world_t w; prepare(&w,8); uint8_t two[70]; encode(two,1); encode(two+35,4); send_all(w.peers[0],two,sizeof two);
    send_request(&w,1,2); send_request(&w,2,3); schedule_order(&w,0,1,2);
    round_once(&w,0,3,4,4,VIREO_OK);
    CHECK(w.report.turn_count==3 && w.report.requeued_count==1 && w.submitted==3 && !w.entries[4].valid && server_info(&w).pending_clients==1);
    CHECK(w.turns[0].schedule_called && w.turns[0].drive_report.needs_reschedule && client_info(&w,0).connection_info.read_buffer.readable_size==35);
    round_once(&w,0,3,4,4,VIREO_OK);
    CHECK(w.report.turn_count==1 && lease_same(w.ready[0].client,w.clients[0]) && w.submitted==4 && w.report.requeued_count==0);
    CHECK(w.entries[1].metadata.request_instance_id!=w.entries[4].metadata.request_instance_id);
    respond(&w); check_response(&w,0,1); check_response(&w,0,4); check_response(&w,1,2); check_response(&w,2,3); finish(&w);
}
/** 空context合法；配置错误不读取半成品，不驱动或吞后缀。 */
static vireo_result_t reject_configuration(void *context,vireo_tcp_server_ready_client_t client,vireo_async_round_config_t *out) {
    CHECK(context==NULL && client.client.pool_id!=0 && out->pending==NULL);
    out->options.operation=1; errno=ERANGE; return VIREO_RESULT_PROTOCOL;
}
static void configuration_failure(void) {
    world_t w; prepare(&w,8); schedule_order(&w,0,1,2); w.fail_configure_at=2;
    memset(w.turns,0x5A,sizeof w.turns); unsigned char tail[sizeof w.turns[2]]; memcpy(tail,&w.turns[2],sizeof tail);
    round_once(&w,0,3,4,4,VIREO_RESULT_IO);
    CHECK(w.report.stage==VIREO_ASYNC_ROUND_CONFIGURE && w.report.turn_count==2 && w.report.drive_calls==1 && w.report.unprocessed_begin==2);
    CHECK(w.turns[1].configure_result==VIREO_RESULT_IO && !w.turns[1].drive_called && !w.turns[1].schedule_called);
    CHECK(lease_same(w.ready[2].client,w.clients[2]) && memcmp(tail,&w.turns[2],sizeof tail)==0 && server_info(&w).pending_clients==0);
    /* caller显式恢复失败项和全部未处理后缀，不重复已成功项。 */
    EXPECT(vireo_tcp_server_schedule_client(w.server,w.ready[1].client,NULL),VIREO_OK);
    EXPECT(vireo_tcp_server_schedule_client(w.server,w.ready[2].client,NULL),VIREO_OK); w.fail_configure_at=0;
    round_once(&w,0,3,4,4,VIREO_OK); CHECK(w.report.turn_count==2 && lease_same(w.ready[0].client,w.clients[1])); finish(&w);
    prepare(&w,8); schedule_order(&w,0,1,2);
    EXPECT(vireo_async_round_once(w.server,w.store,w.pool,0,3,reject_configuration,NULL,w.ready,4,
        w.turns,4,&w.remaining,&w.report),VIREO_RESULT_PROTOCOL);
    CHECK(w.report.turn_count==1 && w.report.drive_calls==0 && w.report.unprocessed_begin==1 && w.report.poll_report.selected_count==3);
    CHECK(w.turns[0].configure_result==VIREO_RESULT_PROTOCOL && !w.turns[0].drive_called && lease_same(w.ready[2].client,w.clients[2])); finish(&w);
}
static void invalid_configuration(void) {
    world_t w; prepare(&w,8); schedule_order(&w,0,1,2); w.bad_configure_at=2;
    round_once(&w,0,3,4,4,VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(w.report.stage==VIREO_ASYNC_ROUND_DRIVE && w.report.turn_count==2 && w.report.drive_calls==2 && w.report.unprocessed_begin==2);
    CHECK(w.turns[1].configure_result==VIREO_OK && w.turns[1].drive_called && !w.turns[1].drive_report.pre_refresh_called && w.remaining==NULL);
    finish(&w);
}
static void full_queue_residual(void) {
    world_t w; prepare(&w,1); for (size_t i=0;i<3;++i) send_request(&w,i,(unsigned)i+1); schedule_order(&w,0,1,2);
    round_once(&w,0,3,4,4,VIREO_RESULT_BUSY);
    CHECK(w.report.turn_count==2 && w.report.drive_calls==2 && w.report.unprocessed_begin==2 && w.submitted==1 && w.remaining!=NULL);
    CHECK(w.turns[0].drive_report.head_report.submit_report.task_transferred && !w.turns[1].drive_report.head_report.submit_report.task_transferred);
    CHECK(w.turns[1].drive_report.head_report.submit_report.submit_report.rollback_called && !w.turns[1].drive_report.head_report.pending_committed);
    CHECK(client_info(&w,1).connection_info.read_buffer.readable_size==35 && client_info(&w,2).connection_info.read_buffer.readable_size==0);
    vireo_inflight_store_info_t info; EXPECT(vireo_inflight_store_inspect(w.store,&info),VIREO_OK); CHECK(info.count==1);
    vireo_task_t *held=w.remaining; round_once(&w,0,3,4,4,VIREO_RESULT_INVALID_ARGUMENT); CHECK(w.remaining==held && !w.report.poll_called);
    finish(&w);
}
static void schedule_failure(void) {
    world_t w; prepare(&w,8); uint8_t two[70]; encode(two,1); encode(two+35,4); send_all(w.peers[0],two,sizeof two);
    send_request(&w,1,2); send_request(&w,2,3); schedule_order(&w,0,1,2); fault_t f={.schedule_busy=true};
    model_round(&w,&f,VIREO_RESULT_BUSY);
    CHECK(w.report.stage==VIREO_ASYNC_ROUND_SCHEDULE && w.report.turn_count==1 && w.report.unprocessed_begin==1 && w.report.requeued_count==0);
    CHECK(f.schedule_calls==1 && w.turns[0].drive_result==VIREO_OK && w.turns[0].schedule_called && w.submitted==1 && server_info(&w).pending_clients==0);
    schedule_order(&w,0,1,2); round_once(&w,0,3,4,4,VIREO_OK); CHECK(w.submitted==4);
    respond(&w); check_response(&w,0,1); check_response(&w,0,4); check_response(&w,1,2); check_response(&w,2,3); finish(&w);
}
static void poll_failure(void) {
    world_t w; prepare(&w,8); schedule_order(&w,0,1,2); fault_t f={.poll_io=true};
    memset(w.ready,0xA5,sizeof w.ready); memset(w.turns,0x5A,sizeof w.turns);
    unsigned char oldready[sizeof w.ready],oldturns[sizeof w.turns]; memcpy(oldready,w.ready,sizeof oldready); memcpy(oldturns,w.turns,sizeof oldturns);
    model_round(&w,&f,VIREO_RESULT_IO);
    CHECK(w.report.stage==VIREO_ASYNC_ROUND_POLL && w.report.poll_result==VIREO_RESULT_IO && w.report.turn_count==0 && w.configured==0);
    CHECK(w.report.poll_report.loop_error.epoll_error.system_errno==EINTR && w.report.unprocessed_begin==0);
    CHECK(memcmp(oldready,w.ready,sizeof oldready)==0 && memcmp(oldturns,w.turns,sizeof oldturns)==0 && server_info(&w).pending_clients==3); finish(&w);
}
static void partial_poll_failure(void) {
    world_t w; prepare(&w,8); schedule_order(&w,0,1,2); fault_t f={.partial_poll=true};
    memset(w.turns,0x5A,sizeof w.turns); unsigned char oldturns[sizeof w.turns]; memcpy(oldturns,w.turns,sizeof oldturns);
    model_round(&w,&f,VIREO_RESULT_IO);
    CHECK(w.report.poll_report.selected_count==1 && w.report.poll_report.remaining_count==2 && w.report.unprocessed_begin==0 && w.configured==0);
    CHECK(lease_same(w.ready[0].client,w.clients[0]) && memcmp(oldturns,w.turns,sizeof oldturns)==0 && server_info(&w).pending_clients==2);
    EXPECT(vireo_tcp_server_schedule_client(w.server,w.ready[0].client,NULL),VIREO_OK); round_once(&w,0,3,4,4,VIREO_OK);
    CHECK(lease_same(w.ready[0].client,w.clients[1]) && lease_same(w.ready[2].client,w.clients[0])); finish(&w);
}
static void transferred_error(void) {
    world_t w; prepare(&w,8); for (size_t i=0;i<3;++i) send_request(&w,i,(unsigned)i+1); schedule_order(&w,0,1,2);
    fault_t f={.transferred_error=true}; model_round(&w,&f,VIREO_RESULT_IO);
    CHECK(w.report.stage==VIREO_ASYNC_ROUND_DRIVE && w.report.turn_count==1 && w.report.unprocessed_begin==1 && w.submitted==1 && w.remaining==NULL);
    CHECK(w.turns[0].drive_report.head_report.submit_report.task_transferred && w.turns[0].drive_report.head_report.consume_result==VIREO_OK);
    CHECK(w.turns[0].drive_report.final_refresh_result==VIREO_RESULT_IO && w.pending[0].frame_bytes==0 && client_info(&w,0).connection_info.read_buffer.readable_size==0);
    vireo_inflight_store_info_t info; EXPECT(vireo_inflight_store_inspect(w.store,&info),VIREO_OK); CHECK(info.count==1); finish(&w);
}
static void stopped_entry(void) {
    world_t w; prepare(&w,8); schedule_order(&w,0,1,2); EXPECT(vireo_tcp_server_request_stop(w.server,NULL),VIREO_OK);
    memset(w.ready,0xA5,sizeof w.ready); memset(w.turns,0x5A,sizeof w.turns);
    unsigned char oldready[sizeof w.ready],oldturns[sizeof w.turns]; memcpy(oldready,w.ready,sizeof oldready); memcpy(oldturns,w.turns,sizeof oldturns);
    round_once(&w,INT_MAX,3,4,4,VIREO_OK);
    CHECK(w.report.poll_report.stopped && !w.report.poll_report.wait_called && w.report.turn_count==0 && w.configured==0 && server_info(&w).pending_clients==3);
    CHECK(memcmp(oldready,w.ready,sizeof oldready)==0 && memcmp(oldturns,w.turns,sizeof oldturns)==0); finish(&w);
}
static void stopped_after_selection(void) {
    world_t w; prepare(&w,8); schedule_order(&w,0,1,2); fault_t f={.stop_after_poll=true}; model_round(&w,&f,VIREO_RESULT_CANCELLED);
    CHECK(w.report.turn_count==1 && w.report.drive_calls==1 && w.report.poll_report.selected_count==3 && w.report.unprocessed_begin==1);
    CHECK(w.turns[0].drive_report.stage==VIREO_ASYNC_CLIENT_DRIVE_CHECK_SERVER && !w.turns[0].drive_report.pre_refresh_called); finish(&w);
}
static void per_client_io_budget(void) {
    world_t w; prepare(&w,8); w.tiny_send=true; uint8_t const bytes[3]={0xAA,0xBB,0xCC};
    for (size_t i=0;i<3;++i) EXPECT(vireo_tcp_server_client_write_enqueue(w.server,w.clients[i],bytes,3,NULL),VIREO_OK);
    schedule_order(&w,0,1,2); round_once(&w,0,3,4,4,VIREO_OK);
    for (size_t i=0;i<3;++i) {
        CHECK(w.turns[i].drive_report.send.sent_bytes==i+1 && w.turns[i].drive_report.send.send_calls==1);
        CHECK(client_info(&w,i).connection_info.write_buffer.readable_size==2-i);
        uint8_t received[3]={0}; struct pollfd fd={w.peers[i],POLLIN,0}; CHECK(poll(&fd,1,1000)==1);
        CHECK(recv(w.peers[i],received,i+1,MSG_DONTWAIT)==(ssize_t)(i+1) && memcmp(received,bytes,i+1)==0);
    }
    finish(&w);
}
static void empty_round(void) {
    world_t w; prepare(&w,8); memset(w.turns,0x5A,sizeof w.turns); unsigned char old[sizeof w.turns]; memcpy(old,w.turns,sizeof old);
    round_once(&w,0,3,4,4,VIREO_OK); CHECK(w.report.poll_called && w.report.poll_report.wait_called && w.report.turn_count==0 && w.configured==0);
    CHECK(memcmp(old,w.turns,sizeof old)==0); finish(&w);
}
int main(void) {
    int old; CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,&old)==0);
    void (*const tests[])(void)={parameters,fifo_and_capacity,multi_roundtrip,cached_tail,configuration_failure,
        invalid_configuration,full_queue_residual,schedule_failure,poll_failure,partial_poll_failure,
        transferred_error,stopped_entry,stopped_after_selection,per_client_io_budget,empty_round};
    for (size_t i=0;i<sizeof tests/sizeof tests[0];++i) { unsigned const n=fd_count(); tests[i](); CHECK(fd_count()==n); }
    CHECK(pthread_setcancelstate(old,NULL)==0); puts("async round: 15 groups, 0 failures"); return 0;
}
