/*
 * PROJECT : VIREO
 * FILE    : test_async_task_recovery.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-15
 * BRIEF   : 真实未转移剩余输入、显式退款释放及本层只读/取出错误模型
 */
#define _GNU_SOURCE
#include "net/async_task_recovery_internal.h"
#include <vireo/net/async_request.h>
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
#define TAKE VIREO_ASYNC_TASK_STEP_TAKE_RECORD
#define DESTROY VIREO_ASYNC_TASK_STEP_DESTROY_TASK
#define DONE VIREO_ASYNC_TASK_STEP_DONE
_Static_assert(TAKE==1 && DESTROY==2 && DONE==3 && VIREO_ASYNC_TASK_RECOVERY_DESTROY_TASK==7,"new enums");
_Static_assert(VIREO_INFLIGHT_RELEASE_CANCEL==9 && VIREO_INFLIGHT_SUBMIT_SUBMIT_TASK==3,"old enums");

/** 仅main通过公开接口拥有资源，未向worker发布task。 */
typedef struct fixture {
    vireo_tcp_server_t *server; /**< 客户/listener资源根。 */
    vireo_connection_pool_lease_t client; /**< 当前客户完整租约。 */
    int peer; /**< caller对端fd，-1为空。 */
    struct sockaddr_in address; /**< loopback数值端点，用于同槽重接。 */
    vireo_inflight_store_t *store; /**< 固定4槽表唯一owner。 */
    vireo_task_t *task; /**< 真正未交接的独立task唯一owner。 */
    vireo_task_metadata_t metadata; /**< 原完整预期，task销毁后仍可审计。 */
    uint8_t wire[35]; /**< caller稳定原帧，公开031测试接收/复制后核对。 */
} fixture_t;
/** 本层公开get/take错误模型，始终保持原资源；I/G/T/D记录调用顺序。 */
typedef struct fault {
    char order[16]; /**< 有效轨迹后保持0，最多本组两次调用。 */
    size_t calls; /**< 轨迹字符数。 */
    vireo_result_t get_error; /**< 非OK时模拟未找到，不查询或改真实表。 */
    vireo_result_t take_error; /**< 非OK时模拟原CHECK_RECORD错误，不改真实表。 */
} fault_t;
static bool same(vireo_task_metadata_t a,vireo_task_metadata_t b) {
    return a.route.client_owner_id==b.route.client_owner_id && a.route.client_slot_index==b.route.client_slot_index &&
        a.route.client_generation==b.route.client_generation && a.route.request_sequence==b.route.request_sequence &&
        a.request_instance_id==b.request_instance_id && a.operation==b.operation && a.deadline_ns==b.deadline_ns;
}
static bool zero_metadata(vireo_task_metadata_t m) {
    return m.route.client_owner_id==0 && m.route.client_slot_index==0 && m.route.client_generation==0 &&
        m.route.request_sequence==0 && m.request_instance_id==0 && m.operation==0 && m.deadline_ns==0;
}
static unsigned fd_count(void) {
    DIR *d=opendir("/proc/self/fd"); CHECK(d!=NULL); unsigned n=0; struct dirent *p;
    while ((p=readdir(d))!=NULL) if (p->d_name[0]!='.') ++n;
    CHECK(closedir(d)==0); return n;
}
static void encode(uint8_t out[35]) {
    vireo_protocol_header_t h={.command=VIREO_COMMAND_NODE_STAT,.sequence=101,.body_len=3};
    out[32]=0x52; out[33]=0; out[34]=0xff;
    EXPECT(vireo_protocol_header_encode(&h,out,32),VIREO_OK);
    EXPECT(vireo_protocol_frame_crc32c_calculate(out,32,out+32,3,&h.crc32c),VIREO_OK);
    EXPECT(vireo_protocol_header_encode(&h,out,32),VIREO_OK);
}
static void connect_client(fixture_t *f) {
    CHECK(f->peer==-1 && f->client.pool_id==0);
    f->peer=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0); CHECK(f->peer>=0);
    CHECK(connect(f->peer,(struct sockaddr *)&f->address,sizeof f->address)==0);
    vireo_connection_options_t const co={64,64,128}; vireo_tcp_server_admit_budget_t const ab={1,1};
    vireo_tcp_server_admit_info_t ai;
    EXPECT(vireo_tcp_server_admit_batch(f->server,&co,&ab,&f->client,1,&ai,NULL),VIREO_OK);
    CHECK(ai.admitted_count==1);
}
static void release_client(fixture_t *f) {
    EXPECT(vireo_tcp_server_release_client(f->server,&f->client,NULL),VIREO_OK);
    CHECK(f->client.pool_id==0 && close(f->peer)==0); f->peer=-1;
}
static vireo_task_metadata_t make_metadata(fixture_t *f,uint32_t seq) {
    vireo_task_metadata_t m;
    EXPECT(vireo_inflight_metadata_make_next(f->server,f->client,seq,9,UINT64_MAX,&m,NULL),VIREO_OK); return m;
}
static void prepare(fixture_t *f,bool registered) {
    *f=(fixture_t){.peer=-1}; vireo_tcp_server_options_t const so={1,2,1048576,256};
    EXPECT(vireo_tcp_server_create(&so,&f->server,NULL),VIREO_OK);
    int fd=socket(AF_INET,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0); CHECK(fd>=0);
    f->address=(struct sockaddr_in){.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
    CHECK(bind(fd,(struct sockaddr *)&f->address,sizeof f->address)==0 && listen(fd,2)==0);
    socklen_t length=sizeof f->address; CHECK(getsockname(fd,(struct sockaddr *)&f->address,&length)==0);
    vireo_acceptor_t *a=NULL; vireo_acceptor_options_t const ao={4096};
    EXPECT(vireo_acceptor_create(&ao,&fd,&a,NULL),VIREO_OK);
    EXPECT(vireo_tcp_server_adopt_listener(f->server,&a,NULL),VIREO_OK); connect_client(f);
    vireo_inflight_store_options_t const io={4,65536}; EXPECT(vireo_inflight_store_create(&io,&f->store),VIREO_OK);
    encode(f->wire); f->metadata=make_metadata(f,101);
    EXPECT(vireo_task_create_copy(f->metadata,f->wire,35,4096,&f->task),VIREO_OK);
    /* registered=true明确构造未交接且登记残留前沿；不是原自动撤销自然失败。 */
    if (registered) EXPECT(vireo_inflight_store_register_task_limited(f->store,f->server,f->task,4,NULL),VIREO_OK);
}
static void count_is(fixture_t *f,size_t n) {
    vireo_inflight_store_info_t i; EXPECT(vireo_inflight_store_inspect(f->store,&i),VIREO_OK); CHECK(i.count==n);
}
static void task_is(fixture_t *f) {
    vireo_task_info_t i; EXPECT(vireo_task_inspect(f->task,&i),VIREO_OK); CHECK(same(i.metadata,f->metadata));
    vireo_task_payload_view_t v; EXPECT(vireo_task_borrow_payload(f->task,&v),VIREO_OK);
    CHECK(v.size==35 && memcmp(v.data,f->wire,35)==0); /* 借用到本helper返回前结束。 */
}
static void cleanup(fixture_t *f) {
    CHECK(f->task==NULL); count_is(f,0); EXPECT(vireo_inflight_store_destroy(&f->store),VIREO_OK);
    if (f->client.pool_id!=0) release_client(f);
    EXPECT(vireo_tcp_server_destroy(&f->server,NULL),VIREO_OK);
}
static void remove_record(fixture_t *f,vireo_task_metadata_t m) {
    vireo_task_metadata_t out; EXPECT(vireo_inflight_store_take(f->store,m,&out,NULL),VIREO_OK); CHECK(same(out,m));
}
static void discarded(vireo_async_task_recovery_report_t const *r,bool took) {
    CHECK(r->stage==VIREO_ASYNC_TASK_RECOVERY_NONE && r->next_step==DONE && r->task_inspected &&
        r->destroy_called && r->destroy_result==VIREO_OK && r->task_consumed && r->record_checked==took &&
        r->take_called==took && r->record_consumed==took && r->take_result==VIREO_OK && r->inflight_stage==VIREO_INFLIGHT_NONE);
}
static void discard(fixture_t *f,vireo_async_task_recovery_step_t step) {
    vireo_async_task_recovery_report_t r;
    EXPECT(vireo_async_request_discard_remaining(f->store,f->metadata,&f->task,step,&r),VIREO_OK);
    discarded(&r,step==TAKE); CHECK(same(r.metadata,f->metadata) && f->task==NULL);
}
static void mark(fault_t *t,char c) { CHECK(t->calls+1<sizeof t->order); t->order[t->calls++]=c; }
static vireo_result_t inspect_op(void *ctx,vireo_task_t const *task,vireo_task_info_t *out) {
    mark(ctx,'I'); return vireo_task_inspect(task,out);
}
static vireo_result_t get_op(void *ctx,vireo_inflight_store_t const *s,vireo_task_metadata_t key,
    vireo_task_metadata_t *out,vireo_inflight_stage_t *stage) {
    fault_t *t=ctx; mark(t,'G'); if (t->get_error!=VIREO_OK) {
        *stage=VIREO_INFLIGHT_CHECK_RECORD; errno=EIO; return t->get_error;
    }
    return vireo_inflight_store_get(s,key,out,stage);
}
static vireo_result_t take_op(void *ctx,vireo_inflight_store_t *s,vireo_task_metadata_t key,
    vireo_task_metadata_t *out,vireo_inflight_stage_t *stage) {
    fault_t *t=ctx; mark(t,'T'); if (t->take_error!=VIREO_OK) {
        *stage=VIREO_INFLIGHT_CHECK_RECORD; errno=EIO; return t->take_error;
    }
    return vireo_inflight_store_take(s,key,out,stage);
}
static vireo_result_t destroy_op(void *ctx,vireo_task_t **owner) {
    mark(ctx,'D'); return vireo_task_destroy(owner); /* 不制造原公开合同不存在的合法销毁错误。 */
}
static vireo_async_task_recovery_ops_t const ops={inspect_op,get_op,take_op,destroy_op};
static vireo_result_t modeled(fixture_t *f,fault_t *t,vireo_async_task_recovery_step_t from,
    vireo_async_task_recovery_report_t *r) {
    return vireo_async_task_recovery_with_ops(f->store,f->metadata,&f->task,from,r,&ops,t);
}
static void basic_rejections(void) {
    fixture_t f; prepare(&f,false); vireo_task_t *original=f.task; vireo_async_task_recovery_report_t r;
    memset(&r,0xa5,sizeof r);
    EXPECT(vireo_async_request_discard_remaining(NULL,f.metadata,&f.task,DESTROY,&r),VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(r.stage==0 && r.next_step==0 && !r.task_inspected && zero_metadata(r.metadata) && !r.destroy_called);
    EXPECT(vireo_async_request_discard_remaining(f.store,f.metadata,NULL,DESTROY,&r),VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_async_request_discard_remaining(f.store,f.metadata,&f.task,DESTROY,NULL),VIREO_RESULT_INVALID_ARGUMENT);
    int const invalid[]={0,3,-1,4};
    for (size_t i=0;i<sizeof invalid/sizeof invalid[0];++i)
        EXPECT(vireo_async_request_discard_remaining(f.store,f.metadata,&f.task,(vireo_async_task_recovery_step_t)invalid[i],&r),VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(f.task==original); task_is(&f); discard(&f,DESTROY);
    EXPECT(vireo_async_request_discard_remaining(f.store,(vireo_task_metadata_t){0},&f.task,DESTROY,&r),VIREO_RESULT_NOT_FOUND);
    CHECK(r.stage==0 && r.next_step==0 && !r.task_inspected && !r.destroy_called); cleanup(&f);
}
static void invalid_operations(void) {
    fixture_t f; prepare(&f,true); vireo_async_task_recovery_report_t r; fault_t t={0};
    EXPECT(vireo_async_task_recovery_with_ops(f.store,f.metadata,&f.task,TAKE,&r,NULL,&t),VIREO_RESULT_INVALID_ARGUMENT);
    for (unsigned i=0;i<4;++i) {
        vireo_async_task_recovery_ops_t bad=ops;
        if (i==0) bad.inspect=NULL; else if (i==1) bad.get=NULL; else if (i==2) bad.take=NULL; else bad.destroy=NULL;
        EXPECT(vireo_async_task_recovery_with_ops(f.store,f.metadata,&f.task,TAKE,&r,&bad,&t),VIREO_RESULT_INVALID_ARGUMENT);
        CHECK(r.stage==0 && r.next_step==0 && t.calls==0);
    }
    task_is(&f); count_is(&f,1); discard(&f,TAKE); cleanup(&f);
}
static void invalid_metadata(void) {
    fixture_t f; prepare(&f,true); vireo_async_task_recovery_report_t r;
    for (unsigned i=0;i<6;++i) {
        vireo_task_metadata_t m=f.metadata;
        if (i==0) m.route.client_owner_id=0; else if (i==1) m.route.client_generation=0;
        else if (i==2) m.route.request_sequence=0; else if (i==3) m.request_instance_id=0;
        else if (i==4) m.operation=0; else m=(vireo_task_metadata_t){0};
        EXPECT(vireo_async_request_discard_remaining(f.store,m,&f.task,TAKE,&r),VIREO_RESULT_INVALID_ARGUMENT);
        CHECK(r.stage==VIREO_ASYNC_TASK_RECOVERY_CHECK_METADATA && r.next_step==0 && !r.task_inspected && !r.take_called && !r.destroy_called);
        task_is(&f); count_is(&f,1);
    }
    discard(&f,TAKE); cleanup(&f);
}
static void mismatched_task(void) {
    fixture_t f; prepare(&f,true); vireo_async_task_recovery_report_t r;
    for (unsigned i=0;i<7;++i) {
        vireo_task_metadata_t m=f.metadata;
        if (i==0) ++m.route.client_owner_id; else if (i==1) ++m.route.client_slot_index;
        else if (i==2) ++m.route.client_generation; else if (i==3) ++m.route.request_sequence;
        else if (i==4) ++m.request_instance_id; else if (i==5) ++m.operation; else m.deadline_ns=0;
        EXPECT(vireo_async_request_discard_remaining(f.store,m,&f.task,TAKE,&r),VIREO_RESULT_INVALID_ARGUMENT);
        CHECK(r.stage==VIREO_ASYNC_TASK_RECOVERY_MATCH_TASK && r.next_step==0 && r.task_inspected &&
            same(r.metadata,f.metadata) && !r.record_checked && !r.take_called && !r.destroy_called);
        task_is(&f); count_is(&f,1);
    }
    discard(&f,TAKE); cleanup(&f);
}
static void no_record_destroy(void) { fixture_t f; prepare(&f,false); discard(&f,DESTROY); cleanup(&f); }
static void leftover_pair(void) { fixture_t f; prepare(&f,true); discard(&f,TAKE); cleanup(&f); }
static void cancel_pair(bool requested) {
    fixture_t f; prepare(&f,false); EXPECT(vireo_task_destroy(&f.task),VIREO_OK);
    vireo_task_cancel_t *cancel=NULL; EXPECT(vireo_task_cancel_create(4096,&cancel),VIREO_OK);
    if (requested) EXPECT(vireo_task_cancel_request(cancel),VIREO_OK);
    EXPECT(vireo_task_create_copy_with_cancel(f.metadata,f.wire,35,4096,cancel,&f.task),VIREO_OK);
    EXPECT(vireo_inflight_store_register_task_limited(f.store,f.server,f.task,4,NULL),VIREO_OK);
    discard(&f,TAKE); bool yes=!requested; EXPECT(vireo_task_cancel_is_requested(cancel,&yes),VIREO_OK); CHECK(yes==requested);
    vireo_task_cancel_t *extra=NULL; EXPECT(vireo_task_cancel_retain(cancel,&extra),VIREO_OK);
    EXPECT(vireo_task_cancel_destroy(&extra),VIREO_OK); EXPECT(vireo_task_cancel_destroy(&cancel),VIREO_OK); cleanup(&f);
}
static void unrequested_cancel(void) { cancel_pair(false); }
static void requested_cancel(void) { cancel_pair(true); }
static void missing_record(void) {
    fixture_t f; prepare(&f,false); vireo_async_task_recovery_report_t r;
    EXPECT(vireo_async_request_discard_remaining(f.store,f.metadata,&f.task,TAKE,&r),VIREO_RESULT_NOT_FOUND);
    CHECK(r.stage==VIREO_ASYNC_TASK_RECOVERY_CHECK_RECORD && r.next_step==TAKE && r.task_inspected &&
        !r.record_checked && !r.take_called && !r.destroy_called && r.inflight_stage==VIREO_INFLIGHT_CHECK_RECORD);
    task_is(&f); count_is(&f,0); discard(&f,DESTROY); cleanup(&f);
}
static void mismatched_record(bool operation) {
    fixture_t f; prepare(&f,false); vireo_task_metadata_t m=f.metadata;
    if (operation) ++m.operation; else m.deadline_ns=0;
    EXPECT(vireo_inflight_store_register(f.store,f.server,m,NULL),VIREO_OK);
    vireo_async_task_recovery_report_t r;
    EXPECT(vireo_async_request_discard_remaining(f.store,f.metadata,&f.task,TAKE,&r),VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(r.stage==VIREO_ASYNC_TASK_RECOVERY_MATCH_RECORD && r.next_step==TAKE && r.task_inspected &&
        !r.record_checked && !r.take_called && !r.destroy_called && r.inflight_stage==VIREO_INFLIGHT_NONE);
    task_is(&f); count_is(&f,1); remove_record(&f,m); discard(&f,DESTROY); cleanup(&f);
}
static void mismatched_record_operation(void) { mismatched_record(true); }
static void mismatched_record_deadline(void) { mismatched_record(false); }
static void unrelated_records(void) {
    fixture_t f; prepare(&f,true); vireo_task_metadata_t other=make_metadata(&f,102);
    EXPECT(vireo_inflight_store_register(f.store,f.server,other,NULL),VIREO_OK);
    discard(&f,TAKE); count_is(&f,1); vireo_task_metadata_t out;
    EXPECT(vireo_inflight_store_get(f.store,other,&out,NULL),VIREO_OK); CHECK(same(out,other));
    remove_record(&f,other); cleanup(&f);
}
static void get_failure_resume(void) {
    fixture_t f; prepare(&f,true); fault_t t={.get_error=VIREO_RESULT_NOT_FOUND}; vireo_async_task_recovery_report_t r;
    EXPECT(modeled(&f,&t,TAKE,&r),VIREO_RESULT_NOT_FOUND); CHECK(strcmp(t.order,"IG")==0 && r.next_step==TAKE &&
        r.stage==VIREO_ASYNC_TASK_RECOVERY_CHECK_RECORD && !r.record_checked && !r.take_called && !r.destroy_called &&
        r.inflight_stage==VIREO_INFLIGHT_CHECK_RECORD); count_is(&f,1); task_is(&f);
    t.get_error=VIREO_OK; EXPECT(modeled(&f,&t,r.next_step,&r),VIREO_OK);
    CHECK(strcmp(t.order,"IGIGTD")==0); discarded(&r,true); cleanup(&f);
}
static void take_failure_resume(void) {
    fixture_t f; prepare(&f,true); fault_t t={.take_error=VIREO_RESULT_INTERNAL}; vireo_async_task_recovery_report_t r;
    EXPECT(modeled(&f,&t,TAKE,&r),VIREO_RESULT_INTERNAL); CHECK(strcmp(t.order,"IGT")==0 && r.next_step==TAKE &&
        r.stage==VIREO_ASYNC_TASK_RECOVERY_TAKE_RECORD && r.record_checked && r.take_called &&
        r.take_result==VIREO_RESULT_INTERNAL && !r.record_consumed && !r.destroy_called &&
        r.inflight_stage==VIREO_INFLIGHT_CHECK_RECORD); count_is(&f,1); task_is(&f);
    t.take_error=VIREO_OK; EXPECT(modeled(&f,&t,r.next_step,&r),VIREO_OK);
    CHECK(strcmp(t.order,"IGTIGTD")==0); discarded(&r,true); cleanup(&f);
}
static void destroy_skips_table(void) {
    fixture_t f; prepare(&f,false); fault_t t={.get_error=VIREO_RESULT_NOT_FOUND,.take_error=VIREO_RESULT_INTERNAL};
    vireo_async_task_recovery_report_t r; EXPECT(modeled(&f,&t,DESTROY,&r),VIREO_OK);
    CHECK(strcmp(t.order,"ID")==0); discarded(&r,false); cleanup(&f);
}
static void historical_client(void) {
    fixture_t f; prepare(&f,true); release_client(&f); discard(&f,TAKE); cleanup(&f);
}
static void reused_client_slot(void) {
    fixture_t f; prepare(&f,true); vireo_connection_pool_lease_t old=f.client; release_client(&f); connect_client(&f);
    CHECK(f.client.slot_index==old.slot_index && f.client.pool_id==old.pool_id && f.client.generation!=old.generation);
    vireo_task_metadata_t newer=make_metadata(&f,101); EXPECT(vireo_inflight_store_register(f.store,f.server,newer,NULL),VIREO_OK);
    discard(&f,TAKE); count_is(&f,1); vireo_tcp_server_client_info_t info;
    EXPECT(vireo_tcp_server_client_inspect(f.server,f.client,&info),VIREO_OK);
    remove_record(&f,newer); cleanup(&f);
}
static void stopped_server(void) {
    fixture_t f; prepare(&f,true); EXPECT(vireo_tcp_server_request_stop(f.server,NULL),VIREO_OK); discard(&f,TAKE); cleanup(&f);
}
static void source_bytes(fixture_t *f) {
    uint8_t const *data=NULL; size_t size=0;
    EXPECT(vireo_tcp_server_client_read_peek(f->server,f->client,&data,&size,NULL),VIREO_OK);
    CHECK(size==35 && memcmp(data,f->wire,35)==0);
}
static void original_submit_failure(bool conflict) {
    fixture_t f; prepare(&f,false); EXPECT(vireo_task_destroy(&f.task),VIREO_OK);
    CHECK(send(f.peer,f.wire,35,MSG_NOSIGNAL)==35);
    vireo_connection_receive_budget_t const b={35,4}; vireo_connection_receive_info_t ri;
    EXPECT(vireo_tcp_server_client_receive(f.server,f.client,&b,&ri,NULL),VIREO_OK); CHECK(ri.received_bytes==35);
    if (conflict) EXPECT(vireo_inflight_store_register(f.store,f.server,f.metadata,NULL),VIREO_OK);
    vireo_thread_pool_t *pool=NULL; vireo_thread_pool_options_t const po={1,65536};
    EXPECT(vireo_thread_pool_create(&po,&pool),VIREO_OK); /* 故意尚未配置/启动，原准入NOT_FOUND，不启动线程。 */
    uint8_t const *data=NULL; size_t size=0; EXPECT(vireo_tcp_server_client_read_peek(f.server,f.client,&data,&size,NULL),VIREO_OK);
    vireo_async_request_report_t report;
    EXPECT(vireo_async_request_copy_try_submit(f.server,f.client,f.store,pool,data,size,64,4096,4,9,UINT64_MAX,NULL,
        &f.task,&report),conflict ? VIREO_RESULT_BUSY : VIREO_RESULT_NOT_FOUND);
    CHECK(report.task_created && report.task_retained && !report.task_transferred && report.submit_called && f.task!=NULL);
    CHECK(report.submit_report.registration_committed==!conflict && !report.submit_report.record_retained &&
        report.submit_report.submit_called==!conflict && report.submit_report.rollback_called==!conflict);
    if (!conflict) CHECK(report.submit_report.rollback_result==VIREO_OK);
    vireo_task_metadata_t const previous=f.metadata; f.metadata=report.metadata;
    source_bytes(&f); count_is(&f,conflict ? 1 : 0); discard(&f,DESTROY); source_bytes(&f);
    if (conflict) remove_record(&f,previous);
    EXPECT(vireo_thread_pool_destroy(&pool),VIREO_OK); cleanup(&f);
}
static void original_refund_ok(void) { original_submit_failure(false); }
static void original_registration_rejected(void) { original_submit_failure(true); }
static void external_refund_then_destroy(void) {
    fixture_t f; prepare(&f,true); remove_record(&f,f.metadata); discard(&f,DESTROY); cleanup(&f);
}
static void finite_extremes_empty_payload(void) {
    fixture_t f; prepare(&f,false); EXPECT(vireo_task_destroy(&f.task),VIREO_OK);
    for (unsigned i=0;i<2;++i) {
        vireo_task_route_t route; EXPECT(vireo_task_route_make(UINT64_MAX,SIZE_MAX,UINT64_MAX,UINT32_MAX,&route),VIREO_OK);
        EXPECT(vireo_task_metadata_make(route,UINT64_MAX,UINT32_MAX,i==0 ? 0 : UINT64_MAX,&f.metadata),VIREO_OK);
        EXPECT(vireo_task_create_copy(f.metadata,NULL,0,4096,&f.task),VIREO_OK); discard(&f,DESTROY);
    }
    cleanup(&f); /* 数值边界模型，没有宣称此route是当前客户。 */
}
static void reused_report_clears(void) {
    fixture_t f; prepare(&f,true); vireo_async_task_recovery_report_t r;
    EXPECT(vireo_async_request_discard_remaining(f.store,f.metadata,&f.task,TAKE,&r),VIREO_OK); discarded(&r,true);
    EXPECT(vireo_task_create_copy(f.metadata,f.wire,35,4096,&f.task),VIREO_OK);
    EXPECT(vireo_async_request_discard_remaining(f.store,f.metadata,&f.task,DESTROY,&r),VIREO_OK); discarded(&r,false);
    EXPECT(vireo_async_request_discard_remaining(f.store,f.metadata,&f.task,DESTROY,&r),VIREO_RESULT_NOT_FOUND);
    CHECK(r.stage==0 && r.next_step==0 && zero_metadata(r.metadata) && !r.task_inspected && !r.record_checked &&
        !r.take_called && !r.record_consumed && r.inflight_stage==0 && !r.destroy_called && !r.task_consumed);
    cleanup(&f);
}
int main(void) {
    int old=0; CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,&old)==0);
    void (*const tests[])(void)={basic_rejections,invalid_operations,invalid_metadata,mismatched_task,no_record_destroy,
        leftover_pair,unrequested_cancel,requested_cancel,missing_record,mismatched_record_operation,mismatched_record_deadline,
        unrelated_records,get_failure_resume,take_failure_resume,destroy_skips_table,historical_client,reused_client_slot,
        stopped_server,original_refund_ok,original_registration_rejected,external_refund_then_destroy,
        finite_extremes_empty_payload,reused_report_clears};
    for (size_t i=0;i<sizeof tests/sizeof tests[0];++i) { unsigned const before=fd_count(); tests[i](); CHECK(fd_count()==before); }
    CHECK(pthread_setcancelstate(old,NULL)==0);
    printf("async task recovery: %zu groups, 0 failures\n",sizeof tests/sizeof tests[0]); return 0;
}
