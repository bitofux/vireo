/*
 * PROJECT : VIREO
 * FILE    : test_async_completion_recovery.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-15
 * BRIEF   : 实际独立帧/登记结束/原回调残留与明确标记的刷新前沿模型
 */
#define _GNU_SOURCE
#include "net/async_completion_recovery_internal.h"
#include <vireo/net/completion_response.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"%s:%d: %s\n",__FILE__,__LINE__,#x); abort(); } } while (0)
#define EXPECT(x,y) do { errno=EDOM; vireo_result_t const result_=(x); CHECK(result_==(y) && errno==EDOM); } while (0)
#define REFRESH VIREO_ASYNC_COMPLETION_STEP_REFRESH
#define DESTROY VIREO_ASYNC_COMPLETION_STEP_DESTROY
#define DONE VIREO_ASYNC_COMPLETION_STEP_DONE
_Static_assert(REFRESH==1 && DESTROY==2 && DONE==3 && VIREO_ASYNC_COMPLETION_RECOVERY_DESTROY==5,"new enums");
_Static_assert(VIREO_COMPLETION_RESPONSE_REFRESH==10 && VIREO_INFLIGHT_RELEASE_CANCEL==9,"old enums held");

/** main独占资源和原同项证据，worker不接触；无外private布局。 */
typedef struct fixture {
    vireo_tcp_server_t *server; /**< 真实客户/listener资源根。 */
    vireo_connection_pool_lease_t client; /**< 当前完整lease，复用时可不同于旧metadata。 */
    int peer; /**< caller对端fd，-1为空。 */
    struct sockaddr_in address; /**< 临时loopback数值端点。 */
    vireo_inflight_store_t *store; /**< 4槽表owner，原consume已take本项。 */
    vireo_completion_t *completion; /**< 原deliver失败真实保留的唯一owner。 */
    vireo_completion_metadata_t metadata; /**< 原同项预期，销毁后仍保审计数值。 */
    uint8_t wire[128]; /**< 编码scratch及本组原完整帧字节副本。 */
    size_t wire_size; /**< 本次32头+0或3字节body，≤128。 */
    vireo_inflight_completion_consume_report_t consumed; /**< 实际原consume的12字段，不伪造take。 */
    bool use_response_helper; /**< true实际030已刷新，false模型未刷新前沿。 */
    bool enqueued; /**< 原public写入OK事实，不冒030报告来源。 */
    vireo_completion_response_report_t response_report; /**< 仅use_response_helper时原030报告。 */
} fixture_t;
/** 仅本层公开refresh错误模型，I/F/D为实际边界轨迹。 */
typedef struct fault {
    char order[16]; /**< 轨迹尾保持0，写前检查预算。 */
    size_t calls; /**< 本组跨次边界调用字符数。 */
    vireo_result_t refresh_error; /**< IO模拟不修改原策略/关注；OK调真实公开flow。 */
    vireo_connection_pool_lease_t last_client; /**< 本次实际传入refresh的完整lease快照。 */
} fault_t;
static vireo_connection_options_t const connection={256,128,384};
static vireo_connection_flow_options_t const flow={128,127,128,32,96};
static bool same(vireo_completion_metadata_t a,vireo_completion_metadata_t b) {
    return a.request.route.client_owner_id==b.request.route.client_owner_id && a.request.route.client_slot_index==b.request.route.client_slot_index &&
        a.request.route.client_generation==b.request.route.client_generation && a.request.route.request_sequence==b.request.route.request_sequence &&
        a.request.request_instance_id==b.request.request_instance_id && a.request.operation==b.request.operation &&
        a.request.deadline_ns==b.request.deadline_ns && a.result==b.result && a.suggested_status==b.suggested_status;
}
static bool zero_metadata(vireo_completion_metadata_t m) {
    return m.request.route.client_owner_id==0 && m.request.route.client_slot_index==0 && m.request.route.client_generation==0 &&
        m.request.route.request_sequence==0 && m.request.request_instance_id==0 && m.request.operation==0 && m.request.deadline_ns==0 &&
        m.result==0 && m.suggested_status==0;
}
static size_t fd_count(void) {
    DIR *d=opendir("/proc/self/fd"); CHECK(d!=NULL); size_t n=0; struct dirent *p;
    while ((p=readdir(d))!=NULL) if (p->d_name[0]!='.') ++n;
    CHECK(closedir(d)==0); return n;
}
static void connect_client(fixture_t *f) {
    CHECK(f->peer==-1 && f->client.pool_id==0);
    f->peer=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0); CHECK(f->peer>=0);
    CHECK(connect(f->peer,(struct sockaddr *)&f->address,sizeof f->address)==0);
    vireo_tcp_server_admit_budget_t const ab={1,2}; vireo_tcp_server_admit_info_t ai;
    EXPECT(vireo_tcp_server_admit_batch(f->server,&connection,&ab,&f->client,1,&ai,NULL),VIREO_OK); CHECK(ai.admitted_count==1);
    EXPECT(vireo_tcp_server_client_flow_configure(f->server,f->client,&flow,NULL),VIREO_OK);
}
static void release_client(fixture_t *f) {
    EXPECT(vireo_tcp_server_release_client(f->server,&f->client,NULL),VIREO_OK);
    CHECK(close(f->peer)==0); f->peer=-1;
}
static vireo_tcp_server_client_info_t state(fixture_t *f) {
    vireo_tcp_server_client_info_t out; EXPECT(vireo_tcp_server_client_inspect(f->server,f->client,&out),VIREO_OK); return out;
}
static void count_is(fixture_t *f,size_t n) {
    vireo_inflight_store_info_t info; EXPECT(vireo_inflight_store_inspect(f->store,&info),VIREO_OK); CHECK(info.count==n);
}
/** 实际原consume已结束登记；这里仅以公开操作建立“已入队/未刷新”前沿或原030已刷新状态。 */
static vireo_result_t delivery(void *ctx,vireo_completion_t const *c,vireo_inflight_completion_match_t match) {
    fixture_t *f=ctx; CHECK(same(f->metadata,(vireo_completion_metadata_t){match.metadata,f->metadata.result,f->metadata.suggested_status}));
    if (f->use_response_helper) {
        vireo_completion_response_descriptor_t const d={VIREO_COMMAND_NODE_STAT,0,17,23};
        EXPECT(vireo_completion_response_enqueue(f->server,c,match,d,128,f->wire,sizeof f->wire,&f->response_report),VIREO_OK);
        f->wire_size=f->response_report.frame_bytes; f->enqueued=f->response_report.enqueued;
    } else {
        /* 模型前沿：真实编码/复制，未调用030及其refresh；不冒原030自然MOD失败。 */
        vireo_completion_payload_view_t view; EXPECT(vireo_completion_borrow_payload(c,&view),VIREO_OK);
        CHECK(view.size<=3); f->wire_size=32+view.size;
        vireo_protocol_header_t h={.command=VIREO_COMMAND_NODE_STAT,.flags=VIREO_PROTOCOL_FLAG_RESPONSE,
            .status=f->metadata.suggested_status,.body_len=(uint32_t)view.size,.sequence=match.metadata.route.request_sequence,
            .session_handle=17,.task_handle=23};
        EXPECT(vireo_protocol_header_encode(&h,f->wire,sizeof f->wire),VIREO_OK);
        if (view.size!=0) memcpy(f->wire+32,view.data,view.size);
        EXPECT(vireo_protocol_frame_crc32c_calculate(f->wire,32,f->wire+32,view.size,&h.crc32c),VIREO_OK);
        EXPECT(vireo_protocol_header_encode(&h,f->wire,sizeof f->wire),VIREO_OK);
        EXPECT(vireo_tcp_server_client_write_enqueue(f->server,f->client,f->wire,f->wire_size,NULL),VIREO_OK); f->enqueued=true;
    }
    CHECK(f->enqueued); return VIREO_RESULT_IO; /* 明确交付后错误模型；借用此处结束，结果保owner。 */
}
static void prepare(fixture_t *f,bool response_helper,size_t size,uint64_t deadline) {
    *f=(fixture_t){.peer=-1,.use_response_helper=response_helper}; CHECK(size==0 || size==3);
    vireo_tcp_server_options_t const so={1,2,1048576,1024}; EXPECT(vireo_tcp_server_create(&so,&f->server,NULL),VIREO_OK);
    int fd=socket(AF_INET,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0); CHECK(fd>=0);
    f->address=(struct sockaddr_in){.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
    CHECK(bind(fd,(struct sockaddr *)&f->address,sizeof f->address)==0 && listen(fd,2)==0);
    socklen_t length=sizeof f->address; CHECK(getsockname(fd,(struct sockaddr *)&f->address,&length)==0);
    vireo_acceptor_t *a=NULL; vireo_acceptor_options_t const ao={4096}; EXPECT(vireo_acceptor_create(&ao,&fd,&a,NULL),VIREO_OK);
    EXPECT(vireo_tcp_server_adopt_listener(f->server,&a,NULL),VIREO_OK); connect_client(f);
    vireo_inflight_store_options_t const io={4,65536}; EXPECT(vireo_inflight_store_create(&io,&f->store),VIREO_OK);
    vireo_task_metadata_t request; EXPECT(vireo_inflight_metadata_make_next(f->server,f->client,101,9,deadline,&request,NULL),VIREO_OK);
    EXPECT(vireo_inflight_store_register(f->store,f->server,request,NULL),VIREO_OK);
    EXPECT(vireo_completion_metadata_make(request,VIREO_RESULT_DATABASE,VIREO_STATUS_INTERNAL_ERROR,&f->metadata),VIREO_OK);
    uint8_t const body[]={0x52,0,0xff}; EXPECT(vireo_completion_create_copy(f->metadata,body,size,4096,&f->completion),VIREO_OK);
    EXPECT(vireo_inflight_store_consume_completion(f->store,f->server,&f->completion,delivery,f,&f->consumed),VIREO_RESULT_IO);
    CHECK(f->consumed.record_consumed && f->consumed.delivery_called && f->consumed.delivery_result==VIREO_RESULT_IO &&
        !f->consumed.destroy_called && !f->consumed.completion_consumed && f->completion!=NULL &&
        same(f->consumed.completion_metadata,f->metadata)); count_is(f,0);
    CHECK(state(f).connection_info.write_buffer.readable_size==f->wire_size);
}
static void setup(fixture_t *f) { prepare(f,false,3,UINT64_MAX); }
static void completion_is(fixture_t *f) {
    vireo_completion_info_t i; EXPECT(vireo_completion_inspect(f->completion,&i),VIREO_OK); CHECK(same(i.metadata,f->metadata));
    vireo_completion_payload_view_t v; EXPECT(vireo_completion_borrow_payload(f->completion,&v),VIREO_OK);
    CHECK(v.size==f->wire_size-32 && (v.size==0 || (v.data[0]==0x52 && v.data[1]==0 && v.data[2]==0xff)));
}
static void cleanup(fixture_t *f) {
    CHECK(f->completion==NULL); count_is(f,0); EXPECT(vireo_inflight_store_destroy(&f->store),VIREO_OK);
    if (f->client.pool_id!=0) release_client(f);
    EXPECT(vireo_tcp_server_destroy(&f->server,NULL),VIREO_OK);
}
static void report_done(vireo_async_completion_recovery_report_t const *r,bool refreshed) {
    CHECK(r->stage==0 && r->next_step==DONE && r->completion_inspected && r->refresh_called==refreshed &&
        r->refresh_result==VIREO_OK && r->client_error.primary.stage==0 && r->destroy_called && r->destroy_result==VIREO_OK && r->completion_consumed);
}
static void recover(fixture_t *f,vireo_async_completion_recovery_step_t from) {
    vireo_async_completion_recovery_report_t r;
    EXPECT(vireo_async_completion_resume_enqueued(f->server,f->metadata,&f->completion,from,&r),VIREO_OK);
    report_done(&r,from==REFRESH); CHECK(same(r.metadata,f->metadata) && f->completion==NULL); count_is(f,0);
}
static void send_bytes(fixture_t *f,size_t n) {
    vireo_connection_send_budget_t const b={n,8}; vireo_connection_send_info_t info;
    EXPECT(vireo_tcp_server_client_send(f->server,f->client,&b,&info,NULL),VIREO_OK); CHECK(info.sent_bytes==n);
}
static void read_one_frame(fixture_t *f) {
    uint8_t got[128]; size_t have=0;
    for (unsigned tries=0; have<f->wire_size && tries<8; ++tries) {
        struct pollfd p={.fd=f->peer,.events=POLLIN}; CHECK(poll(&p,1,1000)==1 && (p.revents&POLLIN));
        ssize_t const n=recv(f->peer,got+have,f->wire_size-have,MSG_DONTWAIT); CHECK(n>0); have+=(size_t)n;
    }
    CHECK(have==f->wire_size && memcmp(got,f->wire,have)==0 && memcmp(got,"VIRE",4)==0);
    vireo_protocol_header_t header; vireo_protocol_codec_issue_t issue;
    EXPECT(vireo_protocol_header_decode(got,32,&header,&issue),VIREO_OK); CHECK(issue==VIREO_PROTOCOL_CODEC_ISSUE_NONE);
    CHECK(header.sequence==101 && header.status==VIREO_STATUS_INTERNAL_ERROR && header.command==VIREO_COMMAND_NODE_STAT &&
        header.session_handle==17 && header.task_handle==23 && header.body_len==f->wire_size-32);
    EXPECT(vireo_protocol_frame_crc32c_verify(got,32,got+32,f->wire_size-32,&issue),VIREO_OK);
    CHECK(issue==VIREO_PROTOCOL_CODEC_ISSUE_NONE);
    CHECK(state(f).connection_info.write_buffer.readable_size==0);
    uint8_t extra; errno=0; CHECK(recv(f->peer,&extra,1,MSG_DONTWAIT)==-1 && (errno==EAGAIN || errno==EWOULDBLOCK));
}
static void send_one_frame(fixture_t *f) { send_bytes(f,state(f).connection_info.write_buffer.readable_size); read_one_frame(f); }
static void mark(fault_t *t,char c) { CHECK(t->calls+1<sizeof t->order); t->order[t->calls++]=c; }
static vireo_result_t inspect_op(void *ctx,vireo_completion_t const *c,vireo_completion_info_t *out) {
    mark(ctx,'I'); return vireo_completion_inspect(c,out);
}
static vireo_result_t refresh_op(void *ctx,vireo_tcp_server_t *s,vireo_connection_pool_lease_t c,vireo_tcp_server_client_error_t *e) {
    fault_t *t=ctx; mark(t,'F'); t->last_client=c;
    if (t->refresh_error!=VIREO_OK) {
        *e=(vireo_tcp_server_client_error_t){0}; e->primary.stage=VIREO_TCP_SERVER_CLIENT_FLOW_REFRESH;
        e->primary.loop_error.stage=VIREO_CONNECTION_LOOP_STAGE_FLOW_REFRESH;
        e->primary.loop_error.loop_error.stage=VIREO_EVENT_LOOP_STAGE_MOD;
        e->primary.loop_error.loop_error.epoll_error.stage=VIREO_EPOLL_STAGE_MOD;
        e->primary.loop_error.loop_error.epoll_error.system_errno=EIO; errno=EINTR;
        return t->refresh_error; /* 仅IO模型，无真实MOD失败或外private损坏。 */
    }
    return vireo_tcp_server_client_flow_refresh(s,c,e);
}
static vireo_result_t destroy_op(void *ctx,vireo_completion_t **owner) { mark(ctx,'D'); return vireo_completion_destroy(owner); }
static vireo_async_completion_recovery_ops_t const ops={inspect_op,refresh_op,destroy_op};
static vireo_result_t modeled(fixture_t *f,fault_t *t,vireo_async_completion_recovery_step_t from,vireo_async_completion_recovery_report_t *r) {
    return vireo_async_completion_recovery_with_ops(f->server,f->metadata,&f->completion,from,r,&ops,t);
}
static void basic_rejections(void) {
    fixture_t f; setup(&f); vireo_async_completion_recovery_report_t r; memset(&r,0xa5,sizeof r);
    EXPECT(vireo_async_completion_resume_enqueued(NULL,f.metadata,&f.completion,REFRESH,&r),VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(r.stage==0 && r.next_step==0 && !r.completion_inspected && zero_metadata(r.metadata) && !r.destroy_called);
    EXPECT(vireo_async_completion_resume_enqueued(f.server,f.metadata,NULL,REFRESH,&r),VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_async_completion_resume_enqueued(f.server,f.metadata,&f.completion,REFRESH,NULL),VIREO_RESULT_INVALID_ARGUMENT);
    int const bad[]={0,3,-1,4}; for (size_t i=0;i<sizeof bad/sizeof bad[0];++i)
        EXPECT(vireo_async_completion_resume_enqueued(f.server,f.metadata,&f.completion,(vireo_async_completion_recovery_step_t)bad[i],&r),VIREO_RESULT_INVALID_ARGUMENT);
    completion_is(&f); recover(&f,REFRESH);
    EXPECT(vireo_async_completion_resume_enqueued(f.server,(vireo_completion_metadata_t){0},&f.completion,DESTROY,&r),VIREO_RESULT_NOT_FOUND);
    CHECK(r.stage==0 && r.next_step==0 && !r.completion_inspected); cleanup(&f);
}
static void invalid_operations(void) {
    fixture_t f; setup(&f); fault_t t={0}; vireo_async_completion_recovery_report_t r;
    EXPECT(vireo_async_completion_recovery_with_ops(f.server,f.metadata,&f.completion,REFRESH,&r,NULL,&t),VIREO_RESULT_INVALID_ARGUMENT);
    for (unsigned i=0;i<3;++i) {
        vireo_async_completion_recovery_ops_t bad=ops; if (i==0) bad.inspect=NULL; else if (i==1) bad.refresh=NULL; else bad.destroy=NULL;
        EXPECT(vireo_async_completion_recovery_with_ops(f.server,f.metadata,&f.completion,REFRESH,&r,&bad,&t),VIREO_RESULT_INVALID_ARGUMENT);
        CHECK(t.calls==0 && r.next_step==0);
    }
    completion_is(&f); recover(&f,REFRESH); cleanup(&f);
}
static void invalid_metadata(void) {
    fixture_t f; setup(&f); vireo_async_completion_recovery_report_t r;
    for (unsigned i=0;i<8;++i) {
        vireo_completion_metadata_t m=f.metadata;
        if (i==0) m.request.route.client_owner_id=0; else if (i==1) m.request.route.client_generation=0;
        else if (i==2) m.request.route.request_sequence=0; else if (i==3) m.request.request_instance_id=0;
        else if (i==4) m.request.operation=0; else if (i==5) m.result=(vireo_result_t)12345;
        else if (i==6) m.suggested_status=UINT16_MAX; else m=(vireo_completion_metadata_t){0};
        EXPECT(vireo_async_completion_resume_enqueued(f.server,m,&f.completion,REFRESH,&r),VIREO_RESULT_INVALID_ARGUMENT);
        CHECK(r.stage==VIREO_ASYNC_COMPLETION_RECOVERY_CHECK_METADATA && r.next_step==0 && !r.completion_inspected && !r.refresh_called && !r.destroy_called);
        completion_is(&f); CHECK(state(&f).connection_info.write_buffer.readable_size==f.wire_size);
    }
    recover(&f,REFRESH); cleanup(&f);
}
static void metadata_all_fields(void) {
    fixture_t f; setup(&f); vireo_async_completion_recovery_report_t r;
    for (unsigned i=0;i<9;++i) {
        vireo_completion_metadata_t m=f.metadata;
        if (i==0) ++m.request.route.client_owner_id; else if (i==1) ++m.request.route.client_slot_index;
        else if (i==2) ++m.request.route.client_generation; else if (i==3) ++m.request.route.request_sequence;
        else if (i==4) ++m.request.request_instance_id; else if (i==5) ++m.request.operation;
        else if (i==6) m.request.deadline_ns=0; else if (i==7) m.result=VIREO_OK; else m.suggested_status=VIREO_STATUS_OK;
        EXPECT(vireo_async_completion_resume_enqueued(f.server,m,&f.completion,REFRESH,&r),VIREO_RESULT_INVALID_ARGUMENT);
        CHECK(r.stage==VIREO_ASYNC_COMPLETION_RECOVERY_MATCH_COMPLETION && r.next_step==0 && r.completion_inspected &&
            same(r.metadata,f.metadata) && !r.refresh_called && !r.destroy_called);
        completion_is(&f); CHECK(state(&f).connection_info.write_buffer.readable_size==f.wire_size);
    }
    recover(&f,REFRESH); cleanup(&f);
}
static void refresh_one_frame(void) {
    fixture_t f; setup(&f); CHECK(!(state(&f).connection_info.loop_interests&VIREO_EPOLL_INTEREST_WRITE));
    recover(&f,REFRESH); CHECK(state(&f).connection_info.write_buffer.readable_size==f.wire_size &&
        (state(&f).connection_info.loop_interests&VIREO_EPOLL_INTEREST_WRITE)); send_one_frame(&f); cleanup(&f);
}
static void explicit_destroy(void) {
    fixture_t f; setup(&f); EXPECT(vireo_tcp_server_client_flow_refresh(f.server,f.client,NULL),VIREO_OK);
    fault_t t={.refresh_error=VIREO_RESULT_IO}; vireo_async_completion_recovery_report_t r;
    EXPECT(modeled(&f,&t,DESTROY,&r),VIREO_OK); CHECK(strcmp(t.order,"ID")==0); report_done(&r,false);
    send_one_frame(&f); cleanup(&f);
}
static void original_response_callback_failure(void) {
    fixture_t f; prepare(&f,true,3,UINT64_MAX);
    CHECK(f.response_report.enqueued && f.response_report.refresh_called && f.response_report.stage==0 && f.consumed.record_consumed);
    recover(&f,DESTROY); send_one_frame(&f); cleanup(&f);
}
static void io_failure_resume(void) {
    fixture_t f; setup(&f); fault_t t={.refresh_error=VIREO_RESULT_IO}; vireo_async_completion_recovery_report_t r;
    vireo_completion_t *original=f.completion; uint32_t const interests=state(&f).connection_info.loop_interests;
    EXPECT(modeled(&f,&t,REFRESH,&r),VIREO_RESULT_IO);
    CHECK(strcmp(t.order,"IF")==0 && r.stage==VIREO_ASYNC_COMPLETION_RECOVERY_REFRESH && r.next_step==REFRESH &&
        r.refresh_called && r.refresh_result==VIREO_RESULT_IO && !r.destroy_called && !r.completion_consumed &&
        r.client_error.primary.stage==VIREO_TCP_SERVER_CLIENT_FLOW_REFRESH &&
        r.client_error.primary.loop_error.loop_error.epoll_error.system_errno==EIO && f.completion==original);
    CHECK(t.last_client.pool_id==f.client.pool_id && t.last_client.slot_index==f.client.slot_index && t.last_client.generation==f.client.generation);
    CHECK(state(&f).connection_info.loop_interests==interests && state(&f).connection_info.write_buffer.readable_size==f.wire_size);
    completion_is(&f); t.refresh_error=VIREO_OK; EXPECT(modeled(&f,&t,r.next_step,&r),VIREO_OK);
    CHECK(strcmp(t.order,"IFIFD")==0); report_done(&r,true); send_one_frame(&f); cleanup(&f);
}
static void disabled_flow_resume(void) {
    fixture_t f; setup(&f); EXPECT(vireo_tcp_server_client_flow_disable(f.server,f.client,NULL),VIREO_OK);
    vireo_async_completion_recovery_report_t r;
    EXPECT(vireo_async_completion_resume_enqueued(f.server,f.metadata,&f.completion,REFRESH,&r),VIREO_RESULT_NOT_FOUND);
    CHECK(r.refresh_called && r.next_step==REFRESH && !r.destroy_called); completion_is(&f);
    EXPECT(vireo_tcp_server_client_flow_configure(f.server,f.client,&flow,NULL),VIREO_OK);
    recover(&f,REFRESH); send_one_frame(&f); cleanup(&f);
}
static void closing_keeps_result(void) {
    fixture_t f; setup(&f); EXPECT(vireo_tcp_server_client_request_close(f.server,f.client,VIREO_CONNECTION_CLOSE_MODE_DRAIN,
        VIREO_CONNECTION_CLOSE_REASON_SERVER_STOP,NULL),VIREO_OK);
    vireo_async_completion_recovery_report_t r;
    EXPECT(vireo_async_completion_resume_enqueued(f.server,f.metadata,&f.completion,REFRESH,&r),VIREO_RESULT_BUSY);
    CHECK(r.next_step==REFRESH && !r.destroy_called); completion_is(&f);
    recover(&f,DESTROY); /* caller显式采用原DRAIN关闭发送政策，结束本层flow恢复。 */
    send_one_frame(&f); cleanup(&f);
}
static void released_client(void) {
    fixture_t f; setup(&f); release_client(&f); vireo_async_completion_recovery_report_t r;
    EXPECT(vireo_async_completion_resume_enqueued(f.server,f.metadata,&f.completion,REFRESH,&r),VIREO_RESULT_NOT_FOUND);
    CHECK(r.next_step==REFRESH && !r.destroy_called); completion_is(&f); recover(&f,DESTROY); cleanup(&f);
}
static void reused_client_slot(void) {
    fixture_t f; setup(&f); vireo_connection_pool_lease_t old=f.client; release_client(&f); connect_client(&f);
    CHECK(old.pool_id==f.client.pool_id && old.slot_index==f.client.slot_index && old.generation!=f.client.generation);
    uint32_t const interests=state(&f).connection_info.loop_interests; vireo_async_completion_recovery_report_t r;
    EXPECT(vireo_async_completion_resume_enqueued(f.server,f.metadata,&f.completion,REFRESH,&r),VIREO_RESULT_NOT_FOUND);
    CHECK(!r.destroy_called && r.next_step==REFRESH && state(&f).connection_info.write_buffer.readable_size==0 &&
        state(&f).connection_info.loop_interests==interests); recover(&f,DESTROY); cleanup(&f);
}
static void wrong_server(void) {
    fixture_t f; setup(&f); vireo_tcp_server_t *other=NULL; vireo_tcp_server_options_t const so={1,2,1048576,1024};
    EXPECT(vireo_tcp_server_create(&so,&other,NULL),VIREO_OK); vireo_async_completion_recovery_report_t r;
    EXPECT(vireo_async_completion_resume_enqueued(other,f.metadata,&f.completion,REFRESH,&r),VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(r.stage==VIREO_ASYNC_COMPLETION_RECOVERY_REFRESH && r.next_step==REFRESH && !r.destroy_called);
    EXPECT(vireo_tcp_server_destroy(&other,NULL),VIREO_OK); recover(&f,REFRESH); send_one_frame(&f); cleanup(&f);
}
static void partial_send_before_recovery(void) {
    fixture_t f; setup(&f); send_bytes(&f,7); CHECK(state(&f).connection_info.write_buffer.readable_size==f.wire_size-7);
    recover(&f,REFRESH); CHECK(state(&f).connection_info.write_buffer.readable_size==f.wire_size-7); send_one_frame(&f); cleanup(&f);
}
static void sent_before_recovery(void) {
    fixture_t f; setup(&f); send_bytes(&f,f.wire_size); recover(&f,REFRESH);
    CHECK(!(state(&f).connection_info.loop_interests&VIREO_EPOLL_INTEREST_WRITE)); read_one_frame(&f); cleanup(&f);
}
static void stopped_mechanical(void) {
    fixture_t f; setup(&f); EXPECT(vireo_tcp_server_request_stop(f.server,NULL),VIREO_OK); recover(&f,REFRESH);
    vireo_tcp_server_ready_client_t ready; vireo_tcp_server_poll_report_t report;
    EXPECT(vireo_tcp_server_poll_ready_once(f.server,0,1,&ready,1,&report),VIREO_OK);
    CHECK(report.stopped && !report.wait_called && report.selected_count==0 && state(&f).connection_info.write_buffer.readable_size==f.wire_size);
    cleanup(&f); /* 已明确整体停止，未声称恢复发送或对端收到。 */
}
static void zero_deadline(void) { fixture_t f; prepare(&f,false,3,0); recover(&f,REFRESH); send_one_frame(&f); cleanup(&f); }
static void empty_body(void) { fixture_t f; prepare(&f,false,0,UINT64_MAX); recover(&f,REFRESH); send_one_frame(&f); cleanup(&f); }
static void unrelated_record(void) {
    fixture_t f; setup(&f); vireo_task_metadata_t other;
    EXPECT(vireo_inflight_metadata_make_next(f.server,f.client,102,9,UINT64_MAX,&other,NULL),VIREO_OK);
    EXPECT(vireo_inflight_store_register(f.store,f.server,other,NULL),VIREO_OK); vireo_async_completion_recovery_report_t r;
    EXPECT(vireo_async_completion_resume_enqueued(f.server,f.metadata,&f.completion,REFRESH,&r),VIREO_OK); report_done(&r,true);
    count_is(&f,1); vireo_task_metadata_t out; EXPECT(vireo_inflight_store_take(f.store,other,&out,NULL),VIREO_OK);
    CHECK(out.request_instance_id==other.request_instance_id); send_one_frame(&f); cleanup(&f);
}
static void reused_report_clears(void) {
    fixture_t f; setup(&f); fault_t t={.refresh_error=VIREO_RESULT_IO}; vireo_async_completion_recovery_report_t r;
    EXPECT(modeled(&f,&t,REFRESH,&r),VIREO_RESULT_IO);
    EXPECT(vireo_tcp_server_client_flow_refresh(f.server,f.client,NULL),VIREO_OK);
    EXPECT(modeled(&f,&t,DESTROY,&r),VIREO_OK); CHECK(strcmp(t.order,"IFID")==0); report_done(&r,false);
    EXPECT(modeled(&f,&t,DESTROY,&r),VIREO_RESULT_NOT_FOUND);
    CHECK(r.stage==0 && r.next_step==0 && zero_metadata(r.metadata) && !r.completion_inspected && !r.refresh_called &&
        r.refresh_result==0 && r.client_error.primary.stage==0 && !r.destroy_called && !r.completion_consumed);
    send_one_frame(&f); cleanup(&f);
}
int main(void) {
    int old=0; CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,&old)==0);
    void (*const tests[])(void)={basic_rejections,invalid_operations,invalid_metadata,metadata_all_fields,refresh_one_frame,explicit_destroy,
        original_response_callback_failure,io_failure_resume,disabled_flow_resume,closing_keeps_result,released_client,reused_client_slot,
        wrong_server,partial_send_before_recovery,sent_before_recovery,stopped_mechanical,zero_deadline,empty_body,unrelated_record,reused_report_clears};
    for (size_t i=0;i<sizeof tests/sizeof tests[0];++i) { size_t const before=fd_count(); tests[i](); CHECK(fd_count()==before); }
    CHECK(pthread_setcancelstate(old,NULL)==0); printf("async completion recovery: %zu groups, 0 failures\n",sizeof tests/sizeof tests[0]); return 0;
}
