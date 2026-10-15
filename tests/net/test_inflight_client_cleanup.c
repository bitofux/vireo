/* PROJECT : VIREO
 * FILE    : test_inflight_client_cleanup.c
 * BRIEF   : 槽预算、真实历史客户、协作引用及清退部分进度
 */
#define _GNU_SOURCE
#include "net/inflight_client_cleanup_internal.h"
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
typedef vireo_inflight_client_cleanup_report_t report_t;
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
static report_t call(vireo_inflight_store_t *s,vireo_connection_pool_lease_t c,size_t from,size_t max,vireo_result_t want) {
    report_t p; memset(&p,0xA5,sizeof p); errno=EDOM;
    CHECK(vireo_inflight_store_cancel_client_batch(s,c,from,max,&p)==want && errno==EDOM); return p;
}
static void zero(report_t p) {
    CHECK(p.stage==0 && p.stop_reason==0 && p.next_index==0 && p.scanned_slots==0 &&
        p.matched_records==0 && p.cancel_requests==0 && p.without_cancel==0 && p.removed_records==0 &&
        same(p.last_metadata,(vireo_task_metadata_t){0}) && !p.last_cancel_requested);
}
static void drop(vireo_inflight_store_t **s,fixture_t *f) {
    count_is(*s,0); CHECK(vireo_inflight_store_destroy(s)==VIREO_OK); CHECK(cleanup(f));
}
static void arguments(void) {
    fixture_t f; CHECK(setup(&f)); vireo_inflight_store_t *s=store_create(8); vireo_task_cancel_t *c=cancel_create();
    vireo_task_metadata_t key; vireo_task_t *t=task_create(&f,1,0,c,&key); add(s,&f,t);
    zero(call(NULL,f.client,0,8,VIREO_RESULT_INVALID_ARGUMENT)); zero(call(s,f.client,0,0,VIREO_RESULT_INVALID_ARGUMENT));
    zero(call(s,f.client,0,65537,VIREO_RESULT_RANGE)); zero(call(s,f.client,9,1,VIREO_RESULT_RANGE));
    zero(call(s,(vireo_connection_pool_lease_t){0},0,8,VIREO_RESULT_NOT_FOUND));
    zero(call(s,(vireo_connection_pool_lease_t){0,1,1},0,8,VIREO_RESULT_INVALID_ARGUMENT));
    zero(call(s,(vireo_connection_pool_lease_t){1,0,0},0,8,VIREO_RESULT_INVALID_ARGUMENT));
    zero(call(s,(vireo_connection_pool_lease_t){0},9,0,VIREO_RESULT_INVALID_ARGUMENT));
    errno=EDOM; CHECK(vireo_inflight_store_cancel_client_batch(s,f.client,0,8,NULL)==VIREO_RESULT_INVALID_ARGUMENT && errno==EDOM);
    CHECK(!requested(t)); count_is(s,1); CHECK(call(s,f.client,0,8,VIREO_OK).removed_records==1);
    CHECK(requested(t)); CHECK(vireo_task_destroy(&t)==VIREO_OK && vireo_task_cancel_destroy(&c)==VIREO_OK); drop(&s,&f);
}
static void empty_cursor(void) {
    fixture_t f; CHECK(setup(&f)); vireo_inflight_store_t *s=store_create(5);
    report_t p=call(s,f.client,1,2,VIREO_OK); CHECK(p.stop_reason==VIREO_INFLIGHT_CLIENT_CLEANUP_BUDGET && p.next_index==3 && p.scanned_slots==2 && !p.matched_records);
    p=call(s,f.client,p.next_index,2,VIREO_OK); CHECK(p.stop_reason==VIREO_INFLIGHT_CLIENT_CLEANUP_COMPLETE && p.next_index==5 && p.scanned_slots==2);
    p=call(s,f.client,5,1,VIREO_OK); CHECK(p.stop_reason==VIREO_INFLIGHT_CLIENT_CLEANUP_COMPLETE && !p.scanned_slots);
    p=call(s,(vireo_connection_pool_lease_t){UINT64_MAX,SIZE_MAX,UINT64_MAX},0,5,VIREO_OK);
    CHECK(p.scanned_slots==5 && !p.matched_records && same(p.last_metadata,(vireo_task_metadata_t){0})); drop(&s,&f);
}
static void mixed_and_segmented(void) {
    fixture_t a,b; CHECK(setup(&a) && setup(&b)); vireo_inflight_store_t *s=store_create(8);
    vireo_task_cancel_t *c=cancel_create(); vireo_task_metadata_t keys[4];
    vireo_task_t *t[4]={task_create(&a,1,0,c,&keys[0]),task_create(&b,1,UINT64_MAX,NULL,&keys[1]),
        task_create(&a,2,UINT64_MAX,NULL,&keys[2]),task_create(&a,3,1,c,&keys[3])};
    for (size_t i=0;i<4;++i) add(s,i==1?&b:&a,t[i]);
    size_t next=0,scanned=0,removed=0,requests=0,without=0;
    for (size_t i=0;i<8;++i) {
        report_t p=call(s,a.client,next,1,VIREO_OK); CHECK(p.scanned_slots==1 && p.removed_records<=1 && p.next_index==next+1);
        next=p.next_index; scanned+=p.scanned_slots; removed+=p.removed_records; requests+=p.cancel_requests; without+=p.without_cancel;
        CHECK(p.stop_reason==(i==7?VIREO_INFLIGHT_CLIENT_CLEANUP_COMPLETE:VIREO_INFLIGHT_CLIENT_CLEANUP_BUDGET));
    }
    CHECK(scanned==8 && removed==3 && requests==2 && without==1 && requested(t[0]) && !requested(t[1]) && !requested(t[2]) && requested(t[3]));
    count_is(s,1); remove_record(s,keys[1]);
    report_t p=call(s,a.client,0,8,VIREO_OK); CHECK(p.scanned_slots==8 && !p.matched_records && !p.cancel_requests);
    for(size_t i=0;i<4;++i) CHECK(vireo_task_destroy(&t[i])==VIREO_OK);
    CHECK(vireo_task_cancel_destroy(&c)==VIREO_OK); drop(&s,&a); CHECK(cleanup(&b));
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
static void generation_and_late_result(void) {
    fixture_t f; CHECK(setup(&f)); vireo_inflight_store_t *s=store_create(8); vireo_task_cancel_t *c=cancel_create();
    vireo_task_metadata_t old,current; vireo_task_t *t=task_create(&f,1,0,c,&old); add(s,&f,t);
    vireo_connection_pool_lease_t lease=f.client; CHECK(release_client(&f) && add_client(&f));
    CHECK(f.client.pool_id==lease.pool_id && f.client.slot_index==lease.slot_index && f.client.generation!=lease.generation);
    vireo_task_cancel_t *newcancel=cancel_create();
    vireo_task_t *newtask=task_create(&f,1,UINT64_MAX,newcancel,&current); add(s,&f,newtask);
    report_t p=call(s,lease,0,8,VIREO_OK); CHECK(p.removed_records==1 && p.cancel_requests==1 && same(p.last_metadata,old));
    CHECK(requested(t) && !requested(newtask)); count_is(s,1);
    size_t calls=0; vireo_completion_t *out=completion(old); vireo_inflight_completion_consume_report_t consumed;
    CHECK(vireo_inflight_store_consume_completion(s,f.server,&out,deliver,&calls,&consumed)==VIREO_OK);
    CHECK(!out && !calls && !consumed.record_consumed && consumed.disposition==VIREO_INFLIGHT_COMPLETION_CLIENT_GONE);
    count_is(s,1); out=completion(current);
    CHECK(vireo_inflight_store_consume_completion(s,f.server,&out,deliver,&calls,&consumed)==VIREO_OK && !out && calls==1 && consumed.record_consumed);
    CHECK(vireo_task_destroy(&t)==VIREO_OK && vireo_task_destroy(&newtask)==VIREO_OK && vireo_task_cancel_destroy(&c)==VIREO_OK && vireo_task_cancel_destroy(&newcancel)==VIREO_OK); drop(&s,&f);
}
static void request_gone_and_numeric(void) {
    fixture_t f; CHECK(setup(&f)); vireo_inflight_store_t *s=store_create(8);
    vireo_task_metadata_t key; CHECK(vireo_inflight_metadata_make_next(f.server,f.client,2,1,UINT64_MAX,&key,NULL)==VIREO_OK);
    CHECK(vireo_inflight_store_register(s,f.server,key,NULL)==VIREO_OK);
    report_t p=call(s,f.client,0,8,VIREO_OK); CHECK(p.without_cancel==1 && p.removed_records==1 && !p.last_cancel_requested);
    vireo_completion_t *out=completion(key); size_t calls=0; vireo_inflight_completion_consume_report_t consumed;
    CHECK(vireo_inflight_store_consume_completion(s,f.server,&out,deliver,&calls,&consumed)==VIREO_OK && !out);
    CHECK(!calls && consumed.disposition==VIREO_INFLIGHT_COMPLETION_REQUEST_GONE); drop(&s,&f);
}
static void shared_cancel_group(void) {
    fixture_t a,b; CHECK(setup(&a) && setup(&b)); vireo_inflight_store_t *s=store_create(8); vireo_task_cancel_t *c=cancel_create();
    vireo_task_metadata_t x,y; vireo_task_t *ta=task_create(&a,1,0,c,&x),*tb=task_create(&b,1,0,c,&y); add(s,&a,ta); add(s,&b,tb);
    CHECK(!requested(ta) && !requested(tb)); report_t p=call(s,a.client,0,8,VIREO_OK);
    CHECK(p.cancel_requests==1 && p.removed_records==1 && requested(ta) && requested(tb)); count_is(s,1); remove_record(s,y);
    CHECK(vireo_task_destroy(&ta)==VIREO_OK && vireo_task_destroy(&tb)==VIREO_OK && vireo_task_cancel_destroy(&c)==VIREO_OK);
    drop(&s,&a); CHECK(cleanup(&b));
}
static void last_reference(void) {
    fixture_t f; CHECK(setup(&f)); vireo_inflight_store_t *s=store_create(8); vireo_task_cancel_t *c=cancel_create();
    vireo_task_metadata_t key; vireo_task_t *t=task_create(&f,1,0,c,&key); add(s,&f,t);
    CHECK(vireo_task_destroy(&t)==VIREO_OK && vireo_task_cancel_destroy(&c)==VIREO_OK);
    report_t p=call(s,f.client,0,8,VIREO_OK); CHECK(p.cancel_requests==1 && p.removed_records==1); drop(&s,&f);
}
/** 本层模型不破坏真实取消对象；request失败不写，release失败不消费表份。 */
typedef struct fault {
    size_t requests; /**< 本次request尝试数，含失败。 */
    size_t releases; /**< 本次release尝试数，含失败。 */
    size_t fail_request; /**< 第几次request返回模型IO，0不失败。 */
    size_t fail_release; /**< 第几次release返回模型INTERNAL，0不失败。 */
} fault_t;
static vireo_result_t request_model(void *ctx,vireo_task_cancel_t *c) {
    fault_t *f=ctx; ++f->requests; errno=ENOSPC;
    if (f->requests==f->fail_request) return VIREO_RESULT_IO;
    return vireo_task_cancel_request(c);
}
static vireo_result_t release_model(void *ctx,vireo_task_cancel_t **c) {
    fault_t *f=ctx; ++f->releases; errno=ENOSPC;
    if (f->releases==f->fail_release) return VIREO_RESULT_INTERNAL;
    return vireo_task_cancel_destroy(c);
}
static void failures(bool releasing) {
    fixture_t f; CHECK(setup(&f)); vireo_inflight_store_t *s=store_create(8);
    vireo_task_cancel_t *c[3]; vireo_task_t *t[3]; vireo_task_metadata_t key[3];
    for(size_t i=0;i<3;++i) { c[i]=cancel_create(); t[i]=task_create(&f,(unsigned)i+1,0,c[i],&key[i]); add(s,&f,t[i]); }
    fault_t fault={0}; if (releasing) fault.fail_release=2; else fault.fail_request=2;
    vireo_inflight_client_cleanup_ops_t const ops={&fault,request_model,release_model}; report_t p;
    errno=EDOM; CHECK(vireo_inflight_client_cleanup_with_ops(s,f.client,0,8,&p,&ops)==(releasing?VIREO_RESULT_INTERNAL:VIREO_RESULT_IO) && errno==EDOM);
    CHECK(p.stop_reason==VIREO_INFLIGHT_CLIENT_CLEANUP_ERROR && p.scanned_slots==2 && p.matched_records==2 && p.next_index==1 && p.removed_records==1);
    CHECK(p.stage==(releasing?VIREO_INFLIGHT_CLIENT_CLEANUP_RELEASE_CANCEL:VIREO_INFLIGHT_CLIENT_CLEANUP_REQUEST_CANCEL));
    CHECK(p.cancel_requests==(releasing?2U:1U) && p.last_cancel_requested==releasing && same(p.last_metadata,key[1]));
    CHECK(requested(t[0]) && requested(t[1])==releasing && !requested(t[2])); count_is(s,2);
    vireo_task_metadata_t stored; CHECK(vireo_inflight_store_get(s,key[1],&stored,NULL)==VIREO_OK && same(stored,key[1]));
    p=call(s,f.client,p.next_index,8,VIREO_OK); CHECK(p.removed_records==2 && p.cancel_requests==2 && p.scanned_slots==7 && p.next_index==8);
    for(size_t i=0;i<3;++i) CHECK(vireo_task_destroy(&t[i])==VIREO_OK && vireo_task_cancel_destroy(&c[i])==VIREO_OK);
    drop(&s,&f);
}
static void request_failure(void) { failures(false); }
static void release_failure(void) { failures(true); }
static void invalid_ops(void) {
    fixture_t f; CHECK(setup(&f)); vireo_inflight_store_t *s=store_create(8); fault_t fault={0};
    vireo_inflight_client_cleanup_ops_t ops={&fault,request_model,release_model}; report_t p;
    CHECK(vireo_inflight_client_cleanup_with_ops(s,f.client,0,8,&p,NULL)==VIREO_RESULT_INVALID_ARGUMENT); zero(p);
    ops.request=NULL; CHECK(vireo_inflight_client_cleanup_with_ops(s,f.client,0,8,&p,&ops)==VIREO_RESULT_INVALID_ARGUMENT); zero(p);
    ops.request=request_model; ops.release=NULL; CHECK(vireo_inflight_client_cleanup_with_ops(s,f.client,0,8,&p,&ops)==VIREO_RESULT_INVALID_ARGUMENT); zero(p);
    CHECK(!fault.requests && !fault.releases); drop(&s,&f);
}
static void nonzero_begin(void) {
    fixture_t f; CHECK(setup(&f)); vireo_inflight_store_t *s=store_create(8); vireo_task_metadata_t key;
    vireo_task_t *t=task_create(&f,1,0,NULL,&key); add(s,&f,t);
    report_t p=call(s,f.client,1,8,VIREO_OK); CHECK(p.next_index==8 && p.scanned_slots==7 && !p.matched_records); count_is(s,1);
    p=call(s,f.client,0,8,VIREO_OK); CHECK(p.removed_records==1 && same(p.last_metadata,key));
    CHECK(vireo_task_destroy(&t)==VIREO_OK); drop(&s,&f);
}
static void max_scan(void) {
    fixture_t f; CHECK(setup(&f)); vireo_inflight_store_t *s=store_create(65536); vireo_inflight_store_info_t before,after;
    CHECK(vireo_inflight_store_inspect(s,&before)==VIREO_OK);
    report_t p=call(s,f.client,0,65536,VIREO_OK); CHECK(p.scanned_slots==65536 && p.next_index==65536 && !p.matched_records);
    CHECK(vireo_inflight_store_inspect(s,&after)==VIREO_OK && after.allocated_bytes==before.allocated_bytes && after.max_memory_bytes==before.max_memory_bytes); drop(&s,&f);
}
/** worker只借独立task及本地屏障，不持server/store/fd。 */
typedef struct worker {
    pthread_barrier_t entered; /**< 已领取，manager可安全清退的会合点。 */
    pthread_barrier_t released; /**< 清退及store销毁后允许worker继续。 */
    bool saw_cancel; /**< 仅worker写，成功join后manager读取。 */
} worker_t;
static void meet(pthread_barrier_t *b) { int n=pthread_barrier_wait(b); CHECK(n==0 || n==PTHREAD_BARRIER_SERIAL_THREAD); }
static vireo_result_t execute(void *ctx,vireo_task_t const *task) {
    worker_t *w=ctx; meet(&w->entered); meet(&w->released); w->saw_cancel=requested(task); return VIREO_OK;
}
static void real_worker(void) {
    fixture_t f; CHECK(setup(&f)); vireo_inflight_store_t *s=store_create(8); vireo_task_cancel_t *c=cancel_create();
    vireo_task_metadata_t key; vireo_task_t *task=task_create(&f,1,0,c,&key); add(s,&f,task); CHECK(vireo_task_cancel_destroy(&c)==VIREO_OK);
    worker_t w={0}; CHECK(pthread_barrier_init(&w.entered,NULL,2)==0 && pthread_barrier_init(&w.released,NULL,2)==0);
    vireo_task_queue_t *q=NULL; vireo_task_queue_options_t const qo={2,65536}; CHECK(vireo_task_queue_create(&qo,&q)==VIREO_OK && vireo_task_queue_prepare_wait(q)==VIREO_OK);
    vireo_thread_pool_t *pool=NULL; vireo_thread_pool_options_t const po={1,65536}; CHECK(vireo_thread_pool_create(&po,&pool)==VIREO_OK);
    vireo_thread_pool_configuration_t const config={q,execute,&w}; CHECK(vireo_thread_pool_configure(pool,&config,NULL)==VIREO_OK);
    vireo_task_queue_transfer_report_t tr; CHECK(vireo_task_queue_try_push(q,&task,&tr)==VIREO_OK && !task && tr.transferred);
    vireo_thread_pool_report_t pr; CHECK(vireo_thread_pool_start(pool,&pr)==VIREO_OK && vireo_thread_pool_enable_execution(pool,&pr)==VIREO_OK); meet(&w.entered);
    vireo_connection_pool_lease_t old=f.client; CHECK(release_client(&f)); report_t p=call(s,old,0,8,VIREO_OK);
    CHECK(p.cancel_requests==1 && p.removed_records==1 && vireo_inflight_store_destroy(&s)==VIREO_OK);
    meet(&w.released);
    /* caller仅对公开trylock竞争有界重试，未提交关闭和未提交停止/join的BUSY之外不重试。 */
    bool closed=false;
    for(size_t i=0;i<100000;++i) { vireo_task_queue_close_report_t cr; vireo_result_t result=vireo_task_queue_close(q,VIREO_TASK_QUEUE_DRAIN,&cr);
        if(result==VIREO_OK) { closed=true; break; }
        CHECK(result==VIREO_RESULT_BUSY && cr.stage==VIREO_TASK_QUEUE_STAGE_LOCK && cr.pthread_error==EBUSY && !cr.changed); sched_yield(); }
    CHECK(closed); bool joined=false;
    for(size_t i=0;i<100000;++i) { vireo_result_t result=vireo_thread_pool_stop_and_join(pool,&pr);
        if(result==VIREO_OK) { joined=true; break; }
        CHECK(result==VIREO_RESULT_BUSY && pr.stage==VIREO_THREAD_POOL_STAGE_CHECK_QUEUE && !pr.stop_requested && !pr.joined_count && !pr.pthread_error); sched_yield(); }
    CHECK(joined && pr.joined_count==1 && w.saw_cancel);
    CHECK(vireo_thread_pool_destroy(&pool)==VIREO_OK && vireo_task_queue_destroy(&q)==VIREO_OK);
    CHECK(pthread_barrier_destroy(&w.entered)==0 && pthread_barrier_destroy(&w.released)==0); CHECK(cleanup(&f));
}
int main(void) {
    CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,NULL)==0);
    void (*const tests[])(void)={arguments,empty_cursor,mixed_and_segmented,generation_and_late_result,request_gone_and_numeric,
        shared_cancel_group,last_reference,request_failure,release_failure,invalid_ops,nonzero_begin,max_scan,real_worker};
    for(size_t i=0;i<sizeof tests/sizeof tests[0];++i) { size_t before=fds(); tests[i](); CHECK(fds()==before); }
    puts("inflight client cleanup: 13 groups, 0 failures"); return 0;
}
