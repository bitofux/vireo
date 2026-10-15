/*
 * PROJECT : VIREO
 * FILE    : test_async_client_termination_policy.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-15
 * BRIEF   : 纯值来源矩阵、失败保持及真实TCP到显式终止的协作
 */
#define _GNU_SOURCE
#include <vireo/net/async_client_termination_policy.h>
#include <vireo/net/async_client_termination.h>
#include <vireo/net/inflight_completion.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#define CHECK(e) do { if (!(e)) { fprintf(stderr,"%s:%d: %s\n",__FILE__,__LINE__,#e); exit(1); } } while (0)
typedef vireo_async_client_drive_report_t report_t;
typedef vireo_async_client_termination_plan_t plan_t;
/** 测试独占的真实 loopback 资源；只通过公开合同访问。 */
typedef struct fixture {
    vireo_tcp_server_t *server;           /**< 本客户及 listener 的资源根。 */
    vireo_tcp_server_t *other_server;     /**< 独立拥有域，用于跨域拒绝。 */
    vireo_connection_pool_lease_t client; /**< 当前客户值，归还后清零。 */
    int peer;                            /**< caller 的 TCP 对端，-1 为空。 */
    int listener_fd;                     /**< 构造期间 owner fd，转移后 -1。 */
    vireo_acceptor_t *listener;           /**< 构造期 owner，收纳后 NULL。 */
    struct sockaddr_in address;          /**< loopback 数值端点，供重接客户。 */
} fixture_t;

static bool add_client(fixture_t *f) {
    CHECK(f->peer == -1 && f->client.pool_id == 0);
    f->peer = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    CHECK(f->peer >= 0);
    CHECK(connect(f->peer, (struct sockaddr const *)&f->address, sizeof f->address) == 0);
    vireo_connection_options_t const options = {64, 64, 128};
    vireo_tcp_server_admit_budget_t const budget = {1, 1};
    vireo_tcp_server_admit_info_t info;
    CHECK(vireo_tcp_server_admit_batch(f->server, &options, &budget, &f->client, 1,
                                       &info, NULL) == VIREO_OK);
    CHECK(info.admitted_count == 1 && info.accepted_count == 1);
    return true;
}

static bool setup_capacity(fixture_t *f, size_t capacity) {
    *f = (fixture_t){.peer = -1, .listener_fd = -1};
    vireo_tcp_server_options_t const options = {capacity, 2, VIREO_TCP_SERVER_MAX_MEMORY, 256};
    CHECK(vireo_tcp_server_create(&options, &f->server, NULL) == VIREO_OK);
    CHECK(vireo_tcp_server_create(&options, &f->other_server, NULL) == VIREO_OK);
    f->listener_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    CHECK(f->listener_fd >= 0);
    f->address.sin_family = AF_INET;
    f->address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(bind(f->listener_fd, (struct sockaddr const *)&f->address, sizeof f->address) == 0);
    CHECK(listen(f->listener_fd, 4) == 0);
    socklen_t length = sizeof f->address;
    CHECK(getsockname(f->listener_fd, (struct sockaddr *)&f->address, &length) == 0);
    CHECK(length == sizeof f->address);
    vireo_acceptor_options_t const listener_options = {VIREO_ACCEPTOR_MAX_MEMORY};
    CHECK(vireo_acceptor_create(&listener_options, &f->listener_fd, &f->listener, NULL) == VIREO_OK);
    CHECK(vireo_tcp_server_adopt_listener(f->server, &f->listener, NULL) == VIREO_OK);
    return add_client(f);
}

static bool setup(fixture_t *f) {
    return setup_capacity(f, 1);
}

static bool release_client(fixture_t *f) {
    CHECK(vireo_tcp_server_release_client(f->server, &f->client, NULL) == VIREO_OK);
    CHECK(f->client.pool_id == 0 && f->client.slot_index == 0 && f->client.generation == 0);
    CHECK(close(f->peer) == 0);
    f->peer = -1;
    return true;
}

static bool cleanup(fixture_t *f) {
    if (f->client.pool_id != 0) CHECK(release_client(f));
    if (f->peer >= 0) CHECK(close(f->peer) == 0);
    if (f->listener_fd >= 0) CHECK(close(f->listener_fd) == 0);
    CHECK(vireo_acceptor_destroy(&f->listener, NULL) == VIREO_OK);
    CHECK(vireo_tcp_server_destroy(&f->server, NULL) == VIREO_OK);
    CHECK(vireo_tcp_server_destroy(&f->other_server, NULL) == VIREO_OK);
    CHECK(f->server == NULL && f->other_server == NULL);
    return true;
}

static vireo_task_t *task_create(fixture_t *f, unsigned seq, uint64_t deadline,
    vireo_task_cancel_t *cancel, vireo_task_metadata_t *metadata) {
    CHECK(vireo_inflight_metadata_make_next(f->server, f->client, seq, 9, deadline, metadata, NULL) == VIREO_OK);
    unsigned char data[] = {(unsigned char)seq, 0, 255};
    vireo_task_t *task = NULL;
    CHECK((cancel == NULL ? vireo_task_create_copy(*metadata, data, sizeof data, 65536, &task) :
        vireo_task_create_copy_with_cancel(*metadata, data, sizeof data, 65536, cancel, &task)) == VIREO_OK);
    data[0] = 99;
    return task;
}

static bool same(vireo_task_metadata_t a, vireo_task_metadata_t b) {
    return a.route.client_owner_id == b.route.client_owner_id &&
        a.route.client_slot_index == b.route.client_slot_index &&
        a.route.client_generation == b.route.client_generation &&
        a.route.request_sequence == b.route.request_sequence &&
        a.request_instance_id == b.request_instance_id && a.operation == b.operation && a.deadline_ns == b.deadline_ns;
}

static void count_is(vireo_inflight_store_t *store, size_t count) {
    vireo_inflight_store_info_t info;
    CHECK(vireo_inflight_store_inspect(store, &info) == VIREO_OK && info.count == count);
}

static void remove_record(vireo_inflight_store_t *store, vireo_task_metadata_t key) {
    vireo_task_metadata_t record;
    CHECK(vireo_inflight_store_get(store, key, &record, NULL) == VIREO_OK && same(record, key));
    CHECK(vireo_inflight_store_take(store, key, &record, NULL) == VIREO_OK && same(record, key));
}


static size_t fds(void) {
    DIR *d=opendir("/proc/self/fd"); CHECK(d!=NULL); size_t n=0; struct dirent *p;
    while ((p=readdir(d))!=NULL) if (p->d_name[0]!='.') ++n;
    CHECK(closedir(d)==0); return n;
}
static vireo_inflight_store_t *store_create(size_t n) {
    vireo_inflight_store_t *s=NULL; vireo_inflight_store_options_t const o={n,67108864};
    CHECK(vireo_inflight_store_create(&o,&s)==VIREO_OK); return s;
}
static vireo_task_cancel_t *cancel_create(void) {
    vireo_task_cancel_t *p=NULL; CHECK(vireo_task_cancel_create(65536,&p)==VIREO_OK); return p;
}
static bool requested(vireo_task_t const *t) {
    bool b=false; CHECK(vireo_task_is_cancel_requested(t,&b)==VIREO_OK); return b;
}
static void add(vireo_inflight_store_t *s,fixture_t *f,vireo_task_t *t) {
    CHECK(vireo_inflight_store_register_task_limited(s,f->server,t,8,NULL)==VIREO_OK);
}

/** 完整值模型仅用于分类分支，不冒一次实际driver或内核故障运行。 */
static report_t protocol_report(void) {
    report_t p={0}; p.stage=VIREO_ASYNC_CLIENT_DRIVE_PEEK_FRAME; p.pre_refresh_called=true;
    p.frame_peek_called=true; p.frame_info.stop_reason=VIREO_CONNECTION_FRAME_STOP_ERROR;
    p.client_error.primary.stage=VIREO_TCP_SERVER_CLIENT_FRAMES_PEEK;
    p.client_error.primary.frame_error.issue=VIREO_CONNECTION_FRAME_ISSUE_TRUNCATED;
    p.final_refresh_called=true; return p;
}
static report_t socket_report(bool sending) {
    report_t p={0}; p.pre_refresh_called=true; p.final_refresh_called=true;
    p.stage=sending?VIREO_ASYNC_CLIENT_DRIVE_SEND:VIREO_ASYNC_CLIENT_DRIVE_RECEIVE;
    p.send_called=sending; p.receive_called=!sending;
    p.send.stop_reason=VIREO_CONNECTION_SEND_STOP_ERROR;
    p.receive.stop_reason=VIREO_CONNECTION_RECEIVE_STOP_ERROR;
    p.client_error.primary.stage=sending?VIREO_TCP_SERVER_CLIENT_SEND:VIREO_TCP_SERVER_CLIENT_RECEIVE;
    p.client_error.primary.connection_error.stage=sending?VIREO_CONNECTION_STAGE_SEND:VIREO_CONNECTION_STAGE_RECEIVE;
    p.client_error.primary.connection_error.system_errno=sending?EPIPE:ECONNRESET; return p;
}
static plan_t classify(vireo_result_t result,report_t const *report,bool wanted,vireo_connection_close_reason_t reason) {
    plan_t p; memset(&p,0xA5,sizeof p); report_t before; memcpy(&before,report,sizeof before); errno=EDOM;
    CHECK(vireo_async_client_termination_classify(result,report,&p)==VIREO_OK && errno==EDOM);
    CHECK(p.terminate_recommended==wanted && p.reason==reason && memcmp(&before,report,sizeof before)==0); return p;
}
static void rejected(vireo_result_t result,report_t const *report) {
    plan_t p,before; memset(&p,0xA5,sizeof p); memcpy(&before,&p,sizeof p); errno=EDOM;
    CHECK(vireo_async_client_termination_classify(result,report,&p)==VIREO_RESULT_INVALID_ARGUMENT && errno==EDOM && memcmp(&p,&before,sizeof p)==0);
}
static void arguments(void) {
    report_t r=protocol_report(); rejected(VIREO_RESULT_PROTOCOL,NULL);
    rejected((vireo_result_t)-1,&r); rejected((vireo_result_t)99,&r);
    r.stage=(vireo_async_client_drive_stage_t)-1; rejected(VIREO_OK,&r);
    r.stage=(vireo_async_client_drive_stage_t)99; rejected(VIREO_OK,&r);
    errno=EDOM; CHECK(vireo_async_client_termination_classify((vireo_result_t)99,NULL,NULL)==VIREO_RESULT_INVALID_ARGUMENT && errno==EDOM);
    r=protocol_report(); errno=EDOM; CHECK(vireo_async_client_termination_classify(VIREO_RESULT_PROTOCOL,&r,NULL)==VIREO_RESULT_INVALID_ARGUMENT && errno==EDOM);
}
static void known_results(void) {
    vireo_result_t const values[]={VIREO_OK,VIREO_RESULT_INVALID_ARGUMENT,VIREO_RESULT_RANGE,VIREO_RESULT_OVERFLOW,
        VIREO_RESULT_NO_MEMORY,VIREO_RESULT_NOT_FOUND,VIREO_RESULT_BUSY,VIREO_RESULT_TIMEOUT,VIREO_RESULT_CANCELLED,
        VIREO_RESULT_IO,VIREO_RESULT_PROTOCOL,VIREO_RESULT_DATABASE,VIREO_RESULT_INTERNAL}; report_t r=protocol_report();
    for(size_t n=0;n<sizeof values/sizeof values[0];++n) {
        bool const yes=values[n]==VIREO_RESULT_PROTOCOL;
        (void)classify(values[n],&r,yes,yes?VIREO_CONNECTION_CLOSE_REASON_PROTOCOL:VIREO_CONNECTION_CLOSE_REASON_NONE);
    }
}
static void known_stages(void) {
    vireo_async_client_drive_stage_t const stages[]={VIREO_ASYNC_CLIENT_DRIVE_NONE,VIREO_ASYNC_CLIENT_DRIVE_CHECK_PENDING,
        VIREO_ASYNC_CLIENT_DRIVE_CHECK_SERVER,VIREO_ASYNC_CLIENT_DRIVE_CHECK_CLIENT,VIREO_ASYNC_CLIENT_DRIVE_PRE_REFRESH,
        VIREO_ASYNC_CLIENT_DRIVE_RECEIVE,VIREO_ASYNC_CLIENT_DRIVE_PEEK_FRAME,VIREO_ASYNC_CLIENT_DRIVE_SUBMIT,
        VIREO_ASYNC_CLIENT_DRIVE_SEND,VIREO_ASYNC_CLIENT_DRIVE_FINAL_REFRESH,VIREO_ASYNC_CLIENT_DRIVE_FINAL_INSPECT};
    report_t r=socket_report(false);
    for(size_t n=0;n<sizeof stages/sizeof stages[0];++n) {
        r.stage=stages[n]; bool const yes=stages[n]==VIREO_ASYNC_CLIENT_DRIVE_RECEIVE;
        (void)classify(VIREO_RESULT_IO,&r,yes,yes?VIREO_CONNECTION_CLOSE_REASON_IO:VIREO_CONNECTION_CLOSE_REASON_NONE);
    }
}
static void protocol_source(void) {
    report_t r=protocol_report(); (void)classify(VIREO_RESULT_PROTOCOL,&r,true,VIREO_CONNECTION_CLOSE_REASON_PROTOCOL);
    r.frame_peek_called=false; (void)classify(VIREO_RESULT_PROTOCOL,&r,false,VIREO_CONNECTION_CLOSE_REASON_NONE);
    r=protocol_report(); r.client_error.primary.stage=VIREO_TCP_SERVER_CLIENT_HANDLER;
    (void)classify(VIREO_RESULT_PROTOCOL,&r,false,VIREO_CONNECTION_CLOSE_REASON_NONE);
    r=protocol_report(); r.stage=VIREO_ASYNC_CLIENT_DRIVE_SUBMIT;
    (void)classify(VIREO_RESULT_PROTOCOL,&r,false,VIREO_CONNECTION_CLOSE_REASON_NONE);
}
static void socket_source(bool sending) {
    report_t r=socket_report(sending); (void)classify(VIREO_RESULT_IO,&r,true,VIREO_CONNECTION_CLOSE_REASON_IO);
    if(sending) r.send_called=false; else r.receive_called=false;
    (void)classify(VIREO_RESULT_IO,&r,false,VIREO_CONNECTION_CLOSE_REASON_NONE);
    r=socket_report(sending); r.client_error.primary.stage=VIREO_TCP_SERVER_CLIENT_FLOW_REFRESH;
    (void)classify(VIREO_RESULT_IO,&r,false,VIREO_CONNECTION_CLOSE_REASON_NONE);
    r=socket_report(sending); r.client_error.primary.connection_error.stage=VIREO_CONNECTION_STAGE_NONE;
    (void)classify(VIREO_RESULT_IO,&r,false,VIREO_CONNECTION_CLOSE_REASON_NONE);
    r=socket_report(sending); r.client_error.primary.connection_error.stage=sending?VIREO_CONNECTION_STAGE_RECEIVE:VIREO_CONNECTION_STAGE_SEND;
    (void)classify(VIREO_RESULT_IO,&r,false,VIREO_CONNECTION_CLOSE_REASON_NONE);
    r=socket_report(sending); r.stage=VIREO_ASYNC_CLIENT_DRIVE_SUBMIT;
    (void)classify(VIREO_RESULT_IO,&r,false,VIREO_CONNECTION_CLOSE_REASON_NONE);
}
static void receive_source(void) { socket_source(false); }
static void send_source(void) { socket_source(true); }
static void errno_boundaries(void) {
    int const values[]={0,-1,EINTR};
    for(size_t n=0;n<sizeof values/sizeof values[0];++n) {
        report_t r=socket_report(false); r.client_error.primary.connection_error.system_errno=values[n];
        (void)classify(VIREO_RESULT_IO,&r,false,VIREO_CONNECTION_CLOSE_REASON_NONE);
        r=socket_report(true); r.client_error.primary.connection_error.system_errno=values[n];
        (void)classify(VIREO_RESULT_IO,&r,false,VIREO_CONNECTION_CLOSE_REASON_NONE);
    }
    report_t r=socket_report(false); plan_t p; errno=EINTR;
    CHECK(vireo_async_client_termination_classify(VIREO_RESULT_IO,&r,&p)==VIREO_OK && p.terminate_recommended && errno==EINTR);
    r.client_error.primary.connection_error.system_errno=EINTR; errno=ECONNRESET;
    CHECK(vireo_async_client_termination_classify(VIREO_RESULT_IO,&r,&p)==VIREO_OK && !p.terminate_recommended && errno==ECONNRESET);
}
static void secondary_error(void) {
    report_t r=socket_report(false); r.final_refresh_result=VIREO_RESULT_IO;
    r.final_refresh_error.primary.stage=VIREO_TCP_SERVER_CLIENT_FLOW_REFRESH;
    r.final_refresh_error.primary.loop_error.loop_error.epoll_error.system_errno=EBADF;
    (void)classify(VIREO_RESULT_IO,&r,true,VIREO_CONNECTION_CLOSE_REASON_IO);
    r=protocol_report(); r.final_refresh_result=VIREO_RESULT_IO;
    r.final_refresh_error.primary.connection_error.system_errno=EPIPE;
    (void)classify(VIREO_RESULT_PROTOCOL,&r,true,VIREO_CONNECTION_CLOSE_REASON_PROTOCOL);
    r=socket_report(false); r.stage=VIREO_ASYNC_CLIENT_DRIVE_FINAL_REFRESH;
    (void)classify(VIREO_RESULT_IO,&r,false,VIREO_CONNECTION_CLOSE_REASON_NONE);
    r=socket_report(false); r.client_error.primary.connection_error.system_errno=EINTR; r.final_refresh_result=VIREO_RESULT_IO;
    r.final_refresh_error.primary.connection_error.system_errno=EPIPE;
    (void)classify(VIREO_RESULT_IO,&r,false,VIREO_CONNECTION_CLOSE_REASON_NONE);
}
static void unclassified_is_not_retry_permission(void) {
    report_t r=socket_report(false); r.stage=VIREO_ASYNC_CLIENT_DRIVE_SUBMIT; r.head_called=true;
    r.head_report.submit_called=true; r.head_report.submit_report.task_transferred=true; r.pending_retained=true;
    (void)classify(VIREO_RESULT_INTERNAL,&r,false,VIREO_CONNECTION_CLOSE_REASON_NONE);
    CHECK(r.head_report.submit_report.task_transferred && r.pending_retained);
    r=(report_t){0}; r.stage=VIREO_ASYNC_CLIENT_DRIVE_CHECK_PENDING; r.pending_retained=true;
    (void)classify(VIREO_RESULT_BUSY,&r,false,VIREO_CONNECTION_CLOSE_REASON_NONE); CHECK(r.pending_retained);
}
static void repeated_values(void) {
    report_t r=protocol_report(); plan_t p={false,VIREO_CONNECTION_CLOSE_REASON_IO};
    CHECK(vireo_async_client_termination_classify(VIREO_RESULT_PROTOCOL,&r,&p)==VIREO_OK && p.terminate_recommended && p.reason==VIREO_CONNECTION_CLOSE_REASON_PROTOCOL);
    CHECK(vireo_async_client_termination_classify(VIREO_OK,&r,&p)==VIREO_OK && !p.terminate_recommended && p.reason==VIREO_CONNECTION_CLOSE_REASON_NONE);
    (void)classify(VIREO_RESULT_PROTOCOL,&r,true,VIREO_CONNECTION_CLOSE_REASON_PROTOCOL);
}
static void wait_ready(fixture_t *f) {
    vireo_tcp_server_ready_client_t ready[1]; vireo_tcp_server_poll_report_t p;
    CHECK(vireo_tcp_server_poll_ready_once(f->server,1000,1,ready,1,&p)==VIREO_OK && p.selected_count==1);
}
static void configure_flow(fixture_t *f) {
    vireo_connection_flow_options_t const o={64,63,64,0,64};
    CHECK(vireo_tcp_server_client_flow_configure(f->server,f->client,&o,NULL)==VIREO_OK);
}
static vireo_thread_pool_t *unstarted_pool(void) {
    vireo_thread_pool_t *p=NULL; vireo_thread_pool_options_t const o={1,65536};
    CHECK(vireo_thread_pool_create(&o,&p)==VIREO_OK); return p;
}
static report_t drive(fixture_t *f,vireo_inflight_store_t *s,vireo_thread_pool_t *pool,vireo_result_t expected) {
    vireo_async_client_drive_options_t const o={64,65536,8,9,UINT64_MAX};
    vireo_async_client_drive_budget_t const b={{64,4},{64,4}};
    vireo_async_request_pending_t pending={0}; vireo_task_t *remaining=NULL; report_t p; errno=EDOM;
    CHECK(vireo_async_client_drive_once(f->server,f->client,s,pool,&o,&b,NULL,&pending,&remaining,&p)==expected && errno==EDOM);
    CHECK(!remaining && !pending.frame_bytes && !p.head_called); return p;
}
static void wire(uint8_t *bytes) {
    vireo_protocol_header_t h={.command=VIREO_COMMAND_NODE_STAT,.body_len=3,.sequence=2};
    bytes[32]=1; bytes[33]=2; bytes[34]=3;
    CHECK(vireo_protocol_header_encode(&h,bytes,32)==VIREO_OK);
    CHECK(vireo_protocol_frame_crc32c_calculate(bytes,32,bytes+32,3,&h.crc32c)==VIREO_OK);
    CHECK(vireo_protocol_header_encode(&h,bytes,32)==VIREO_OK);
}
static vireo_result_t delivery(void *context,vireo_completion_t const *c,vireo_inflight_completion_match_t m) {
    (void)c; (void)m; size_t *calls=context; ++*calls; return VIREO_OK;
}
static void real_protocol(bool truncated) {
    fixture_t f; CHECK(setup(&f)); configure_flow(&f); vireo_inflight_store_t *s=store_create(8); vireo_thread_pool_t *pool=unstarted_pool();
    vireo_task_cancel_t *cancel=cancel_create(); vireo_task_metadata_t metadata;
    vireo_task_t *task=task_create(&f,1,UINT64_MAX,cancel,&metadata); add(s,&f,task);
    uint8_t bytes[35]; wire(bytes);
    if(!truncated) bytes[34]^=1;
    size_t const length=truncated?5:sizeof bytes;
    CHECK(send(f.peer,bytes,length,MSG_NOSIGNAL)==(ssize_t)length);
    if(truncated) CHECK(shutdown(f.peer,SHUT_WR)==0);
    wait_ready(&f); report_t report=drive(&f,s,pool,VIREO_RESULT_PROTOCOL);
    CHECK(report.stage==VIREO_ASYNC_CLIENT_DRIVE_PEEK_FRAME && report.frame_peek_called);
    plan_t plan=classify(VIREO_RESULT_PROTOCOL,&report,true,VIREO_CONNECTION_CLOSE_REASON_PROTOCOL);
    vireo_tcp_server_client_info_t client;
    CHECK(vireo_tcp_server_client_inspect(f.server,f.client,&client)==VIREO_OK && client.connection_info.close_state==VIREO_CONNECTION_CLOSE_OPEN);
    CHECK(!requested(task)); count_is(s,1); vireo_connection_pool_lease_t old=f.client;
    vireo_async_client_termination_report_t termination; errno=EDOM;
    CHECK(vireo_async_client_terminate_once(f.server,s,old,plan.reason,VIREO_ASYNC_CLIENT_TERMINATION_STEP_CLOSE,0,8,&termination)==VIREO_OK && errno==EDOM);
    CHECK(termination.client_consumed && termination.next_step==VIREO_ASYNC_CLIENT_TERMINATION_STEP_DONE && termination.cleanup_report.removed_records==1 && requested(task)); count_is(s,0);
    CHECK(vireo_tcp_server_client_inspect(f.server,old,&client)==VIREO_RESULT_NOT_FOUND);
    f.client=(vireo_connection_pool_lease_t){0}; CHECK(close(f.peer)==0); f.peer=-1; CHECK(add_client(&f));
    CHECK(f.client.pool_id==old.pool_id && f.client.slot_index==old.slot_index && f.client.generation!=old.generation);
    vireo_task_metadata_t current; vireo_task_t *next=task_create(&f,1,0,NULL,&current); add(s,&f,next);
    vireo_completion_metadata_t cm; vireo_completion_t *completion=NULL;
    CHECK(vireo_completion_metadata_make(metadata,VIREO_OK,VIREO_STATUS_OK,&cm)==VIREO_OK && vireo_completion_create_copy(cm,NULL,0,4096,&completion)==VIREO_OK);
    size_t calls=0; vireo_inflight_completion_consume_report_t consumed;
    CHECK(vireo_inflight_store_consume_completion(s,f.server,&completion,delivery,&calls,&consumed)==VIREO_OK && !completion && !calls && consumed.disposition==VIREO_INFLIGHT_COMPLETION_CLIENT_GONE);
    count_is(s,1); remove_record(s,current);
    CHECK(vireo_task_destroy(&task)==VIREO_OK && vireo_task_destroy(&next)==VIREO_OK && vireo_task_cancel_destroy(&cancel)==VIREO_OK);
    CHECK(vireo_thread_pool_destroy(&pool)==VIREO_OK && vireo_inflight_store_destroy(&s)==VIREO_OK && cleanup(&f));
}
static void real_bad_crc(void) { real_protocol(false); }
static void real_truncated_eof(void) { real_protocol(true); }
static void real_half_close(void) {
    fixture_t f; CHECK(setup(&f)); configure_flow(&f); vireo_inflight_store_t *s=store_create(8); vireo_thread_pool_t *pool=unstarted_pool();
    vireo_task_cancel_t *cancel=cancel_create(); vireo_task_metadata_t key;
    vireo_task_t *task=task_create(&f,1,0,cancel,&key); add(s,&f,task); CHECK(shutdown(f.peer,SHUT_WR)==0); wait_ready(&f);
    report_t r=drive(&f,s,pool,VIREO_OK); (void)classify(VIREO_OK,&r,false,VIREO_CONNECTION_CLOSE_REASON_NONE);
    vireo_tcp_server_client_info_t i; CHECK(vireo_tcp_server_client_inspect(f.server,f.client,&i)==VIREO_OK && i.connection_info.read_eof && i.connection_info.close_state==VIREO_CONNECTION_CLOSE_OPEN);
    count_is(s,1); CHECK(!requested(task)); uint8_t byte=9;
    CHECK(vireo_tcp_server_client_write_enqueue(f.server,f.client,&byte,1,NULL)==VIREO_OK);
    r=drive(&f,s,pool,VIREO_OK); CHECK(r.send_called && r.send.sent_bytes==1);
    (void)classify(VIREO_OK,&r,false,VIREO_CONNECTION_CLOSE_REASON_NONE); uint8_t got=0; CHECK(recv(f.peer,&got,1,0)==1 && got==byte);
    CHECK(!requested(task)); count_is(s,1); remove_record(s,key);
    CHECK(vireo_task_destroy(&task)==VIREO_OK && vireo_task_cancel_destroy(&cancel)==VIREO_OK && vireo_thread_pool_destroy(&pool)==VIREO_OK && vireo_inflight_store_destroy(&s)==VIREO_OK && cleanup(&f));
}
int main(void) {
    CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,NULL)==0);
    void (*const tests[])(void)={arguments,known_results,known_stages,protocol_source,receive_source,send_source,
        errno_boundaries,secondary_error,unclassified_is_not_retry_permission,repeated_values,real_bad_crc,real_truncated_eof,real_half_close};
    for(size_t n=0;n<sizeof tests/sizeof tests[0];++n) { size_t before=fds(); tests[n](); CHECK(fds()==before); }
    puts("async client termination policy: 13 groups, 0 failures"); return 0;
}
