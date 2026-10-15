/* PROJECT : VIREO
 * FILE    : test_async_client_termination.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-15
 * BRIEF   : 真实客户消费、恢复起点、槽预算、旧代结果及公开依赖故障模型
 */
#define _GNU_SOURCE
#include "net/async_client_termination_internal.h"
#include <vireo/net/inflight_completion.h>
#include <vireo/thread/thread_pool.h>
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
#define CHECK(e) do { if (!(e)) { fprintf(stderr,"%s:%d: %s\n",__FILE__,__LINE__,#e); exit(1); } } while (0)
typedef vireo_async_client_termination_report_t report_t;
#define STEP(n) VIREO_ASYNC_CLIENT_TERMINATION_STEP_ ## n
#define STAGE(n) VIREO_ASYNC_CLIENT_TERMINATION_ ## n
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
    vireo_inflight_store_info_t info;
    CHECK(vireo_inflight_store_inspect(s,&info)==VIREO_OK);
    CHECK(vireo_inflight_store_register_task_limited(s,f->server,t,info.capacity<8?info.capacity:8,NULL)==VIREO_OK);
}

static report_t call(vireo_tcp_server_t *server,vireo_inflight_store_t *s,vireo_connection_pool_lease_t client,
    vireo_async_client_termination_step_t from,size_t begin,size_t max,vireo_result_t want) {
    report_t p; memset(&p,0xA5,sizeof p); errno=EDOM;
    CHECK(vireo_async_client_terminate_once(server,s,client,VIREO_CONNECTION_CLOSE_REASON_IO,from,begin,max,&p)==want && errno==EDOM);
    return p;
}
static vireo_tcp_server_client_info_t client_info(fixture_t *f) {
    vireo_tcp_server_client_info_t i; CHECK(vireo_tcp_server_client_inspect(f->server,f->client,&i)==VIREO_OK); return i;
}
static void consumed(fixture_t *f) {
    vireo_tcp_server_client_info_t i; CHECK(vireo_tcp_server_client_inspect(f->server,f->client,&i)==VIREO_RESULT_NOT_FOUND);
    f->client=(vireo_connection_pool_lease_t){0}; CHECK(close(f->peer)==0); f->peer=-1;
}
static void drop(vireo_inflight_store_t **s,fixture_t *f) {
    count_is(*s,0); CHECK(vireo_inflight_store_destroy(s)==VIREO_OK); CHECK(cleanup(f));
}
static bool same_client(vireo_connection_pool_lease_t a,vireo_connection_pool_lease_t b) {
    return a.pool_id==b.pool_id && a.slot_index==b.slot_index && a.generation==b.generation;
}
static void no_progress(report_t p) {
    CHECK(p.next_step==STEP(NONE) && same_client(p.client,(vireo_connection_pool_lease_t){0}) &&
        !p.close_called && p.close_result==VIREO_OK && !p.release_called && p.release_result==VIREO_OK &&
        !p.client_consumed && !p.cleanup_called && p.cleanup_result==VIREO_OK && !p.cleanup_report.scanned_slots);
}
static void arguments(void) {
    fixture_t f; CHECK(setup(&f)); vireo_inflight_store_t *s=store_create(3); report_t p;
    no_progress(call(NULL,s,f.client,STEP(CLOSE),0,1,VIREO_RESULT_INVALID_ARGUMENT));
    no_progress(call(f.server,NULL,f.client,STEP(CLOSE),0,1,VIREO_RESULT_INVALID_ARGUMENT));
    no_progress(call(f.server,s,f.client,STEP(NONE),0,1,VIREO_RESULT_INVALID_ARGUMENT));
    no_progress(call(f.server,s,f.client,STEP(DONE),0,1,VIREO_RESULT_INVALID_ARGUMENT));
    no_progress(call(f.server,s,f.client,(vireo_async_client_termination_step_t)99,0,1,VIREO_RESULT_INVALID_ARGUMENT));
    no_progress(call(f.server,s,f.client,STEP(CLOSE),0,0,VIREO_RESULT_INVALID_ARGUMENT));
    no_progress(call(f.server,s,f.client,STEP(CLOSE),1,3,VIREO_RESULT_INVALID_ARGUMENT));
    no_progress(call(f.server,s,f.client,STEP(RELEASE),1,3,VIREO_RESULT_INVALID_ARGUMENT));
    no_progress(call(f.server,s,f.client,STEP(CLOSE),0,65537,VIREO_RESULT_RANGE));
    no_progress(call(f.server,s,(vireo_connection_pool_lease_t){0},STEP(CLOSE),0,1,VIREO_RESULT_NOT_FOUND));
    no_progress(call(f.server,s,(vireo_connection_pool_lease_t){0,1,1},STEP(CLOSE),0,1,VIREO_RESULT_INVALID_ARGUMENT));
    no_progress(call(f.server,s,(vireo_connection_pool_lease_t){1,0,0},STEP(CLOSE),0,1,VIREO_RESULT_INVALID_ARGUMENT));
    p=call(f.server,s,f.client,STEP(CLEANUP),4,1,VIREO_RESULT_RANGE); no_progress(p); CHECK(p.stage==STAGE(CHECK_STORE));
    errno=EDOM; CHECK(vireo_async_client_terminate_once(f.server,s,f.client,VIREO_CONNECTION_CLOSE_REASON_IO,STEP(CLOSE),0,1,NULL)==VIREO_RESULT_INVALID_ARGUMENT && errno==EDOM);
    for(int n=0;n<2;++n) { errno=EDOM; CHECK(vireo_async_client_terminate_once(f.server,s,f.client,
        n?(vireo_connection_close_reason_t)99:VIREO_CONNECTION_CLOSE_REASON_NONE,STEP(CLOSE),0,1,&p)==VIREO_RESULT_INVALID_ARGUMENT && errno==EDOM); no_progress(p); }
    CHECK(client_info(&f).connection_info.close_state==VIREO_CONNECTION_CLOSE_OPEN); drop(&s,&f);
}
static void budgets_and_identity(void) {
    fixture_t f; CHECK(setup(&f)); vireo_inflight_store_t *s=store_create(3); vireo_connection_pool_lease_t old=f.client;
    report_t p=call(f.server,s,old,STEP(CLOSE),0,1,VIREO_OK);
    CHECK(p.stage==0 && p.next_step==STEP(CLEANUP) && p.close_called && p.release_called && p.client_consumed && p.cleanup_called &&
        p.cleanup_report.scanned_slots==1 && p.cleanup_report.next_index==1 && same_client(p.client,old) && same_client(f.client,old)); consumed(&f);
    p=call(f.server,s,old,STEP(CLEANUP),p.cleanup_report.next_index,1,VIREO_OK);
    CHECK(!p.close_called && !p.release_called && !p.client_consumed && p.next_step==STEP(CLEANUP) && p.cleanup_report.next_index==2);
    p=call(f.server,s,old,STEP(CLEANUP),2,1,VIREO_OK); CHECK(p.next_step==STEP(DONE) && p.cleanup_report.next_index==3);
    p=call(f.server,s,old,STEP(CLEANUP),3,1,VIREO_OK); CHECK(p.next_step==STEP(DONE) && !p.cleanup_report.scanned_slots);
    p=call(f.server,s,old,STEP(CLOSE),0,3,VIREO_RESULT_NOT_FOUND); CHECK(p.stage==STAGE(CLOSE_CLIENT) && !p.release_called && !p.cleanup_called);
    p=call(f.server,s,old,STEP(RELEASE),0,3,VIREO_RESULT_NOT_FOUND); CHECK(!p.close_called && !p.cleanup_called && !p.client_consumed && p.next_step==STEP(RELEASE));
    drop(&s,&f);
}
static void reasons(void) {
    vireo_connection_close_reason_t const reasons[]={VIREO_CONNECTION_CLOSE_REASON_APPLICATION,VIREO_CONNECTION_CLOSE_REASON_PEER_EOF,
        VIREO_CONNECTION_CLOSE_REASON_PROTOCOL,VIREO_CONNECTION_CLOSE_REASON_IO,VIREO_CONNECTION_CLOSE_REASON_SERVER_STOP,VIREO_CONNECTION_CLOSE_REASON_RESOURCE_LIMIT};
    for(size_t n=0;n<sizeof reasons/sizeof reasons[0];++n) {
        fixture_t f; CHECK(setup(&f)); vireo_inflight_store_t *s=store_create(1); report_t p; errno=EDOM;
        CHECK(vireo_async_client_terminate_once(f.server,s,f.client,reasons[n],STEP(CLOSE),0,1,&p)==VIREO_OK && errno==EDOM);
        CHECK(p.client_consumed && p.next_step==STEP(DONE)); consumed(&f); drop(&s,&f);
    }
}
static void half_close_is_explicit(void) {
    fixture_t f; CHECK(setup(&f)); vireo_inflight_store_t *s=store_create(2); vireo_task_metadata_t key;
    vireo_task_cancel_t *c=cancel_create(); vireo_task_t *t=task_create(&f,1,0,c,&key); add(s,&f,t);
    CHECK(shutdown(f.peer,SHUT_WR)==0); vireo_connection_receive_budget_t const budget={64,1}; vireo_connection_receive_info_t received;
    CHECK(vireo_tcp_server_client_receive(f.server,f.client,&budget,&received,NULL)==VIREO_OK && received.stop_reason==VIREO_CONNECTION_RECEIVE_STOP_EOF);
    CHECK(client_info(&f).connection_info.read_eof && client_info(&f).connection_info.close_state==VIREO_CONNECTION_CLOSE_OPEN && !requested(t)); count_is(s,1);
    uint8_t const bytes[]={1,2,3}; CHECK(vireo_tcp_server_client_write_enqueue(f.server,f.client,bytes,sizeof bytes,NULL)==VIREO_OK);
    CHECK(client_info(&f).connection_info.write_buffer.readable_size==sizeof bytes);
    report_t p=call(f.server,s,f.client,STEP(CLOSE),0,2,VIREO_OK); CHECK(p.next_step==STEP(DONE) && p.cleanup_report.cancel_requests==1 && requested(t));
    uint8_t x; CHECK(recv(f.peer,&x,1,0)==0); consumed(&f);
    CHECK(vireo_task_destroy(&t)==VIREO_OK && vireo_task_cancel_destroy(&c)==VIREO_OK); drop(&s,&f);
}
/** 故障只在本层公开调用边界；COMMITTED/CONSUMED使用真实动作后模型报错。 */
typedef enum fault_mode { F_NONE,F_INSPECT,F_CLOSE,F_CLOSE_COMMITTED,F_RELEASE,F_RELEASE_CONSUMED,F_CLEANUP_PREFIX } fault_mode_t;
/** 不含资源owner，仅本测试同步使用的故障与调用计数。 */
typedef struct fault {
    fault_mode_t mode; /**< 明确的单一故障模型。 */
    size_t inspections; /**< 本次公开表观测调用数。 */
    size_t closes; /**< 本次关闭调用数。 */
    size_t releases; /**< 本次归还调用数。 */
    size_t cleanups; /**< 本次预算清退调用数。 */
    vireo_task_metadata_t failed_metadata; /**< 清退失败模型的当前目标快照，仅PREFIX模式使用。 */
} fault_t;
static vireo_result_t inspect_model(void *context,vireo_inflight_store_t const *s,vireo_inflight_store_info_t *out) {
    fault_t *f=context; ++f->inspections; errno=ENOSPC;
    return f->mode==F_INSPECT?VIREO_RESULT_INTERNAL:vireo_inflight_store_inspect(s,out);
}
static vireo_result_t close_model(void *context,vireo_tcp_server_t *s,vireo_connection_pool_lease_t c,
    vireo_connection_close_mode_t mode,vireo_connection_close_reason_t reason,vireo_tcp_server_client_error_t *error) {
    fault_t *f=context; ++f->closes; CHECK(mode==VIREO_CONNECTION_CLOSE_MODE_IMMEDIATE); errno=ENOSPC;
    if(f->mode==F_CLOSE) { *error=(vireo_tcp_server_client_error_t){0}; return VIREO_RESULT_BUSY; }
    if(f->mode==F_CLOSE_COMMITTED) {
        CHECK(vireo_tcp_server_client_request_close(s,c,mode,reason,error)==VIREO_OK);
        *error=(vireo_tcp_server_client_error_t){0}; error->primary.stage=VIREO_TCP_SERVER_CLIENT_REQUEST_CLOSE;
        error->primary.loop_error.stage=VIREO_CONNECTION_LOOP_STAGE_REQUEST_CLOSE;
        error->primary.loop_error.loop_error.stage=VIREO_EVENT_LOOP_STAGE_MOD;
        error->primary.loop_error.loop_error.epoll_error.stage=VIREO_EPOLL_STAGE_MOD;
        error->primary.loop_error.loop_error.epoll_error.system_errno=EIO; return VIREO_RESULT_IO;
    }
    return vireo_tcp_server_client_request_close(s,c,mode,reason,error);
}
static vireo_result_t release_model(void *context,vireo_tcp_server_t *s,vireo_connection_pool_lease_t *c,vireo_tcp_server_client_error_t *error) {
    fault_t *f=context; ++f->releases; errno=ENOSPC;
    if(f->mode==F_RELEASE || f->mode==F_RELEASE_CONSUMED) {
        if(f->mode==F_RELEASE_CONSUMED) CHECK(vireo_tcp_server_release_client(s,c,error)==VIREO_OK);
        *error=(vireo_tcp_server_client_error_t){0};
        if(f->mode==F_RELEASE_CONSUMED) {
            error->primary.stage=VIREO_TCP_SERVER_CLIENT_RELEASE;
            error->primary.system_errno=EIO;
        } else {
            error->primary.stage=VIREO_TCP_SERVER_CLIENT_DETACH;
            error->primary.loop_error.stage=VIREO_CONNECTION_LOOP_STAGE_DETACH;
            error->primary.loop_error.loop_error.stage=VIREO_EVENT_LOOP_STAGE_DEL;
            error->primary.loop_error.loop_error.epoll_error.stage=VIREO_EPOLL_STAGE_DEL;
            error->primary.loop_error.loop_error.epoll_error.system_errno=EIO;
        }
        return VIREO_RESULT_IO;
    }
    return vireo_tcp_server_release_client(s,c,error);
}
static vireo_result_t cleanup_model(void *context,vireo_inflight_store_t *s,vireo_connection_pool_lease_t c,size_t begin,size_t max,
    vireo_inflight_client_cleanup_report_t *out) {
    fault_t *f=context; ++f->cleanups; errno=ENOSPC;
    if(f->mode==F_CLEANUP_PREFIX) {
        CHECK(max>1 && vireo_inflight_store_cancel_client_batch(s,c,begin,1,out)==VIREO_OK);
        vireo_task_metadata_t checked;
        CHECK(vireo_inflight_store_get(s,f->failed_metadata,&checked,NULL)==VIREO_OK && same(checked,f->failed_metadata));
        ++out->scanned_slots;
        ++out->matched_records;
        out->last_metadata=checked;
        out->last_cancel_requested=false;
        out->stage=VIREO_INFLIGHT_CLIENT_CLEANUP_REQUEST_CANCEL; out->stop_reason=VIREO_INFLIGHT_CLIENT_CLEANUP_ERROR;
        return VIREO_RESULT_INTERNAL;
    }
    return vireo_inflight_store_cancel_client_batch(s,c,begin,max,out);
}
static vireo_async_client_termination_ops_t const ops={inspect_model,close_model,release_model,cleanup_model};
static report_t model(fixture_t *f,vireo_inflight_store_t *s,fault_t *fault,vireo_result_t want) {
    report_t p; memset(&p,0xA5,sizeof p); errno=EDOM;
    CHECK(vireo_async_client_termination_with_ops(f->server,s,f->client,VIREO_CONNECTION_CLOSE_REASON_IO,STEP(CLOSE),0,8,&p,&ops,fault)==want && errno==EDOM);
    return p;
}
static void store_failure(void) {
    fixture_t f; CHECK(setup(&f)); vireo_inflight_store_t *s=store_create(8); fault_t fault={.mode=F_INSPECT};
    report_t p=model(&f,s,&fault,VIREO_RESULT_INTERNAL); no_progress(p); CHECK(p.stage==STAGE(CHECK_STORE) && fault.inspections==1 && !fault.closes && !fault.releases && !fault.cleanups);
    CHECK(client_info(&f).connection_info.close_state==VIREO_CONNECTION_CLOSE_OPEN); drop(&s,&f);
}
static void close_failure_common(bool committed) {
    fixture_t f; CHECK(setup(&f)); vireo_inflight_store_t *s=store_create(8); fault_t fault={.mode=committed?F_CLOSE_COMMITTED:F_CLOSE};
    report_t p=model(&f,s,&fault,committed?VIREO_RESULT_IO:VIREO_RESULT_BUSY);
    CHECK(p.stage==STAGE(CLOSE_CLIENT) && p.next_step==STEP(CLOSE) && p.close_called && !p.release_called && !p.cleanup_called &&
        p.client_error.primary.loop_error.loop_error.epoll_error.system_errno==(committed?EIO:0));
    CHECK(fault.inspections==1 && fault.closes==1 && !fault.releases && !fault.cleanups);
    CHECK(client_info(&f).connection_info.close_state==(committed?VIREO_CONNECTION_CLOSE_READY:VIREO_CONNECTION_CLOSE_OPEN));
    p=call(f.server,s,f.client,p.next_step,0,8,VIREO_OK); CHECK(p.client_consumed && p.next_step==STEP(DONE)); consumed(&f); drop(&s,&f);
}
static void close_failure(void) { close_failure_common(false); }
static void close_committed_failure(void) { close_failure_common(true); }
static void release_failure_common(bool did_consume) {
    fixture_t f; CHECK(setup(&f)); vireo_inflight_store_t *s=store_create(8); vireo_task_cancel_t *c=cancel_create();
    vireo_task_metadata_t key; vireo_task_t *t=task_create(&f,1,0,c,&key); add(s,&f,t); vireo_connection_pool_lease_t old=f.client;
    fault_t fault={.mode=did_consume?F_RELEASE_CONSUMED:F_RELEASE}; report_t p=model(&f,s,&fault,VIREO_RESULT_IO);
    CHECK(p.stage==STAGE(RELEASE_CLIENT) && p.close_called && p.release_called && !p.cleanup_called && p.client_consumed==did_consume &&
        p.next_step==(did_consume?STEP(CLEANUP):STEP(RELEASE)) && p.release_result==VIREO_RESULT_IO &&
        (did_consume?p.client_error.primary.system_errno:p.client_error.primary.loop_error.loop_error.epoll_error.system_errno)==EIO);
    CHECK(fault.inspections==1 && fault.closes==1 && fault.releases==1 && !fault.cleanups && !requested(t)); count_is(s,1);
    if(did_consume) consumed(&f);
    else { CHECK(client_info(&f).connection_info.close_state==VIREO_CONNECTION_CLOSE_READY);
        vireo_task_metadata_t extra; CHECK(vireo_inflight_metadata_make_next(f.server,f.client,2,1,0,&extra,NULL)==VIREO_OK);
        CHECK(vireo_inflight_store_register(s,f.server,extra,NULL)==VIREO_RESULT_BUSY); }
    p=call(f.server,s,old,p.next_step,0,8,VIREO_OK); CHECK(!p.close_called && p.release_called==!did_consume && p.next_step==STEP(DONE) && p.cleanup_report.removed_records==1 && requested(t));
    if(!did_consume) consumed(&f);
    CHECK(vireo_task_destroy(&t)==VIREO_OK && vireo_task_cancel_destroy(&c)==VIREO_OK); drop(&s,&f);
}
static void release_failure(void) { release_failure_common(false); }
static void release_consumed_failure(void) { release_failure_common(true); }
static void cleanup_prefix_failure(void) {
    fixture_t f; CHECK(setup(&f)); vireo_inflight_store_t *s=store_create(8); vireo_task_metadata_t keys[2];
    vireo_task_cancel_t *c[2]={cancel_create(),cancel_create()}; vireo_task_t *t[2];
    for(size_t n=0;n<2;++n) { t[n]=task_create(&f,(unsigned)n+1,0,c[n],&keys[n]); add(s,&f,t[n]); }
    vireo_connection_pool_lease_t old=f.client; fault_t fault={.mode=F_CLEANUP_PREFIX,.failed_metadata=keys[1]}; report_t p=model(&f,s,&fault,VIREO_RESULT_INTERNAL);
    CHECK(p.stage==STAGE(CLEAN_INFLIGHT) && p.next_step==STEP(CLEANUP) && p.client_consumed && p.cleanup_called && p.cleanup_result==VIREO_RESULT_INTERNAL &&
        p.cleanup_report.next_index==1 && p.cleanup_report.scanned_slots==2 && p.cleanup_report.matched_records==2 &&
        same(p.cleanup_report.last_metadata,keys[1]) && !p.cleanup_report.last_cancel_requested &&
        p.cleanup_report.removed_records==1 && p.cleanup_report.cancel_requests==1 && requested(t[0]) && !requested(t[1]));
    CHECK(fault.inspections==1 && fault.closes==1 && fault.releases==1 && fault.cleanups==1); consumed(&f); count_is(s,1);
    p=call(f.server,s,old,p.next_step,p.cleanup_report.next_index,8,VIREO_OK); CHECK(p.next_step==STEP(DONE) && !p.close_called && !p.release_called && p.cleanup_report.removed_records==1 && requested(t[1]));
    for(size_t n=0;n<2;++n) {
        CHECK(vireo_task_destroy(&t[n])==VIREO_OK && vireo_task_cancel_destroy(&c[n])==VIREO_OK);
    }
    drop(&s,&f);
}
static void resume_release_and_first_reason(void) {
    fixture_t f; CHECK(setup(&f)); vireo_inflight_store_t *s=store_create(8); uint8_t byte=1;
    CHECK(vireo_tcp_server_client_write_enqueue(f.server,f.client,&byte,1,NULL)==VIREO_OK);
    CHECK(vireo_tcp_server_client_request_close(f.server,f.client,VIREO_CONNECTION_CLOSE_MODE_DRAIN,VIREO_CONNECTION_CLOSE_REASON_APPLICATION,NULL)==VIREO_OK);
    CHECK(client_info(&f).connection_info.close_state==VIREO_CONNECTION_CLOSE_DRAINING);
    fault_t fault={.mode=F_RELEASE}; report_t p=model(&f,s,&fault,VIREO_RESULT_IO);
    CHECK(p.next_step==STEP(RELEASE) && client_info(&f).connection_info.close_state==VIREO_CONNECTION_CLOSE_READY &&
        client_info(&f).connection_info.close_reason==VIREO_CONNECTION_CLOSE_REASON_APPLICATION);
    p=call(f.server,s,f.client,STEP(RELEASE),0,8,VIREO_OK); CHECK(!p.close_called && p.client_consumed && p.next_step==STEP(DONE)); consumed(&f); drop(&s,&f);
}
static void wrong_client(void) {
    fixture_t f; CHECK(setup(&f)); vireo_inflight_store_t *s=store_create(8);
    report_t p=call(f.other_server,s,f.client,STEP(CLOSE),0,8,VIREO_RESULT_INVALID_ARGUMENT); CHECK(p.stage==STAGE(CLOSE_CLIENT) && !p.release_called && !p.cleanup_called);
    vireo_connection_pool_lease_t invalid=f.client; invalid.slot_index=SIZE_MAX;
    p=call(f.server,s,invalid,STEP(CLOSE),0,8,VIREO_RESULT_RANGE); CHECK(p.stage==STAGE(CLOSE_CLIENT) && !p.cleanup_called);
    CHECK(client_info(&f).connection_info.close_state==VIREO_CONNECTION_CLOSE_OPEN); drop(&s,&f);
}
static void stopped(void) {
    fixture_t f; CHECK(setup(&f)); vireo_inflight_store_t *s=store_create(8);
    CHECK(vireo_tcp_server_request_stop(f.server,NULL)==VIREO_OK);
    report_t p=call(f.server,s,f.client,STEP(CLOSE),0,8,VIREO_OK); CHECK(p.client_consumed && p.next_step==STEP(DONE)); consumed(&f); drop(&s,&f);
}
static void max_scan(void) {
    fixture_t f; CHECK(setup(&f)); vireo_inflight_store_t *s=store_create(65536); vireo_inflight_store_info_t before,after;
    CHECK(vireo_inflight_store_inspect(s,&before)==VIREO_OK);
    report_t p=call(f.server,s,f.client,STEP(CLOSE),0,65536,VIREO_OK); CHECK(p.next_step==STEP(DONE) && p.cleanup_report.scanned_slots==65536 && p.cleanup_report.next_index==65536); consumed(&f);
    CHECK(vireo_inflight_store_inspect(s,&after)==VIREO_OK && before.allocated_bytes==after.allocated_bytes && before.max_memory_bytes==after.max_memory_bytes); drop(&s,&f);
}
static void other_client(void) {
    fixture_t a,b; CHECK(setup(&a) && setup(&b)); vireo_inflight_store_t *s=store_create(8); vireo_task_metadata_t x,y;
    vireo_task_cancel_t *ca=cancel_create(),*cb=cancel_create(); vireo_task_t *ta=task_create(&a,1,0,ca,&x),*tb=task_create(&b,1,0,cb,&y); add(s,&a,ta); add(s,&b,tb);
    report_t p=call(a.server,s,a.client,STEP(CLOSE),0,8,VIREO_OK); CHECK(p.cleanup_report.removed_records==1 && requested(ta) && !requested(tb)); consumed(&a); count_is(s,1);
    CHECK(client_info(&b).connection_info.close_state==VIREO_CONNECTION_CLOSE_OPEN); remove_record(s,y);
    CHECK(vireo_task_destroy(&ta)==VIREO_OK && vireo_task_destroy(&tb)==VIREO_OK && vireo_task_cancel_destroy(&ca)==VIREO_OK && vireo_task_cancel_destroy(&cb)==VIREO_OK); drop(&s,&a); CHECK(cleanup(&b));
}
static vireo_completion_t *completion(vireo_task_metadata_t key) {
    vireo_completion_metadata_t m; vireo_completion_t *c=NULL;
    CHECK(vireo_completion_metadata_make(key,VIREO_OK,VIREO_STATUS_OK,&m)==VIREO_OK);
    CHECK(vireo_completion_create_copy(m,NULL,0,4096,&c)==VIREO_OK); return c;
}
static vireo_result_t deliver(void *context,vireo_completion_t const *c,vireo_inflight_completion_match_t m) {
    size_t *calls=context; ++*calls; vireo_completion_info_t info;
    CHECK(vireo_completion_inspect(c,&info)==VIREO_OK && same(info.metadata.request,m.metadata)); return VIREO_OK;
}
static void generation_late_result(void) {
    fixture_t f; CHECK(setup(&f)); vireo_inflight_store_t *s=store_create(8); vireo_task_metadata_t old_key,new_key;
    vireo_task_t *old_task=task_create(&f,1,0,NULL,&old_key); add(s,&f,old_task); vireo_connection_pool_lease_t old=f.client;
    report_t p=call(f.server,s,old,STEP(CLOSE),0,1,VIREO_OK); CHECK(p.client_consumed && p.next_step==STEP(CLEANUP)); consumed(&f); CHECK(add_client(&f));
    CHECK(f.client.pool_id==old.pool_id && f.client.slot_index==old.slot_index && f.client.generation!=old.generation);
    vireo_task_cancel_t *nc=cancel_create(); vireo_task_t *new_task=task_create(&f,1,UINT64_MAX,nc,&new_key); add(s,&f,new_task);
    p=call(f.server,s,old,STEP(CLEANUP),p.cleanup_report.next_index,8,VIREO_OK); CHECK(p.next_step==STEP(DONE) && !requested(new_task)); count_is(s,1);
    p=call(f.server,s,old,STEP(CLEANUP),0,8,VIREO_OK); CHECK(!p.cleanup_report.matched_records && !requested(new_task)); count_is(s,1);
    vireo_completion_t *out=completion(old_key); size_t calls=0; vireo_inflight_completion_consume_report_t report;
    CHECK(vireo_inflight_store_consume_completion(s,f.server,&out,deliver,&calls,&report)==VIREO_OK && !out && !calls && report.disposition==VIREO_INFLIGHT_COMPLETION_CLIENT_GONE); count_is(s,1);
    out=completion(new_key); CHECK(vireo_inflight_store_consume_completion(s,f.server,&out,deliver,&calls,&report)==VIREO_OK && !out && calls==1);
    CHECK(vireo_task_destroy(&old_task)==VIREO_OK && vireo_task_destroy(&new_task)==VIREO_OK && vireo_task_cancel_destroy(&nc)==VIREO_OK); drop(&s,&f);
}
static void invalid_ops(void) {
    fixture_t f; CHECK(setup(&f)); vireo_inflight_store_t *s=store_create(8); fault_t fault={0}; report_t p;
    for(size_t n=0;n<5;++n) { vireo_async_client_termination_ops_t bad=ops;
        if(n==1) bad.inspect=NULL;
        if(n==2) bad.close=NULL;
        if(n==3) bad.release=NULL;
        if(n==4) bad.cleanup=NULL;
        errno=EDOM; CHECK(vireo_async_client_termination_with_ops(f.server,s,f.client,VIREO_CONNECTION_CLOSE_REASON_IO,STEP(CLOSE),0,8,&p,n?&bad:NULL,&fault)==VIREO_RESULT_INVALID_ARGUMENT && errno==EDOM); no_progress(p);
    }
    CHECK(!fault.inspections && !fault.closes && !fault.releases && !fault.cleanups); drop(&s,&f);
}
/** worker无server/store借用，join后才读结果和标志。 */
typedef struct worker {
    pthread_barrier_t entered; /**< task已领取，manager才可终止客户。 */
    pthread_barrier_t released; /**< 清退完成后worker继续产生迟到结果。 */
    bool saw_cancel; /**< 只由worker写，join后manager读。 */
    vireo_completion_t *result; /**< worker创建，join后唯一交给manager的结果owner。 */
} worker_t;
static void meet(pthread_barrier_t *b) { int n=pthread_barrier_wait(b); CHECK(n==0 || n==PTHREAD_BARRIER_SERIAL_THREAD); }
static vireo_result_t execute(void *context,vireo_task_t const *task) {
    worker_t *w=context; meet(&w->entered); meet(&w->released); w->saw_cancel=requested(task);
    vireo_task_info_t i; CHECK(vireo_task_inspect(task,&i)==VIREO_OK); w->result=completion(i.metadata); return VIREO_OK;
}
static void real_worker(void) {
    fixture_t f; CHECK(setup(&f)); vireo_inflight_store_t *s=store_create(8); vireo_task_cancel_t *c=cancel_create(); vireo_task_metadata_t key;
    vireo_task_t *task=task_create(&f,1,0,c,&key); add(s,&f,task); CHECK(vireo_task_cancel_destroy(&c)==VIREO_OK);
    worker_t w={0}; CHECK(pthread_barrier_init(&w.entered,NULL,2)==0 && pthread_barrier_init(&w.released,NULL,2)==0);
    vireo_task_queue_t *q=NULL; vireo_task_queue_options_t const qo={2,65536}; CHECK(vireo_task_queue_create(&qo,&q)==VIREO_OK && vireo_task_queue_prepare_wait(q)==VIREO_OK);
    vireo_thread_pool_t *pool=NULL; vireo_thread_pool_options_t const po={1,65536}; CHECK(vireo_thread_pool_create(&po,&pool)==VIREO_OK);
    vireo_thread_pool_configuration_t const config={q,execute,&w}; CHECK(vireo_thread_pool_configure(pool,&config,NULL)==VIREO_OK);
    vireo_task_queue_transfer_report_t tr; CHECK(vireo_task_queue_try_push(q,&task,&tr)==VIREO_OK && !task && tr.transferred);
    vireo_thread_pool_report_t pr; CHECK(vireo_thread_pool_start(pool,&pr)==VIREO_OK && vireo_thread_pool_enable_execution(pool,&pr)==VIREO_OK); meet(&w.entered);
    report_t p=call(f.server,s,f.client,STEP(CLOSE),0,8,VIREO_OK); CHECK(p.next_step==STEP(DONE) && p.cleanup_report.cancel_requests==1 && p.cleanup_report.removed_records==1); consumed(&f);
    vireo_task_queue_close_report_t cr; CHECK(vireo_task_queue_close(q,VIREO_TASK_QUEUE_DRAIN,&cr)==VIREO_OK); meet(&w.released);
    bool joined=false;
    /* 只对公开CHECK_QUEUE观测锁竞争做caller有界重试；真实停止/join错误保持失败。 */
    for(size_t n=0;n<100000;++n) { vireo_result_t result=vireo_thread_pool_stop_and_join(pool,&pr);
        if(result==VIREO_OK) { joined=true; break; }
        CHECK(result==VIREO_RESULT_BUSY && pr.stage==VIREO_THREAD_POOL_STAGE_CHECK_QUEUE && !pr.stop_requested && !pr.joined_count && !pr.pthread_error); sched_yield(); }
    CHECK(joined && pr.joined_count==1 && w.saw_cancel && w.result);
    size_t calls=0; vireo_inflight_completion_consume_report_t consumed_report;
    CHECK(vireo_inflight_store_consume_completion(s,f.server,&w.result,deliver,&calls,&consumed_report)==VIREO_OK && !w.result && !calls && consumed_report.disposition==VIREO_INFLIGHT_COMPLETION_CLIENT_GONE);
    CHECK(vireo_thread_pool_destroy(&pool)==VIREO_OK && vireo_task_queue_destroy(&q)==VIREO_OK);
    CHECK(pthread_barrier_destroy(&w.entered)==0 && pthread_barrier_destroy(&w.released)==0); drop(&s,&f);
}
int main(void) {
    CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,NULL)==0);
    void (*const tests[])(void)={arguments,budgets_and_identity,reasons,half_close_is_explicit,store_failure,
        close_failure,close_committed_failure,release_failure,release_consumed_failure,cleanup_prefix_failure,
        resume_release_and_first_reason,wrong_client,stopped,max_scan,other_client,generation_late_result,invalid_ops,real_worker};
    for(size_t n=0;n<sizeof tests/sizeof tests[0];++n) { size_t before=fds(); tests[n](); CHECK(fds()==before); }
    puts("async client termination: 18 groups, 0 failures"); return 0;
}
