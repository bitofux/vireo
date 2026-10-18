/* TLS异步单客户真实链与own故障边界。 */
#define _GNU_SOURCE
#include "async_round_tls_internal.h"
#include <vireo/net/completion_response_tls.h>
#include "tls_context_fixtures.h"
#include <vireo/net/async_request_head.h>
#include <vireo/net/notifier_server.h>
#include <vireo/net/notifier_server_dispatch.h>
#include <vireo/thread/completion_publish.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#define CHECK(c) do { if (!(c)) { fprintf(stderr,"%s:%d: %s\n",__FILE__,__LINE__,#c); abort(); } } while (0)
#define EXPECT(c, e) do { errno=EDOM; vireo_result_t const got_=(c); \
    if(got_!=(e)) fprintf(stderr,"result %d expected %d\n",(int)got_,(int)(e)); \
    CHECK(got_==(e) && errno==EDOM); } while (0)

/** worker只持跨线程资源；manager在join后读统计。 */
typedef struct worker {
    vireo_completion_queue_t *queue; /**< 固定8槽结果队列借至join。 */
    vireo_notifier_t *notifier; /**< 提示源借至join。 */
    pthread_barrier_t entered; /**< 空预热回调进入会合。 */
    pthread_barrier_t release; /**< worker释放会合，隔离queue竞争。 */
    unsigned executed; /**< 实际数据task执行数，join后读。 */
    atomic_uint published; /**< release/acquire确认全部producer已离开completion入队边界，不代替join。 */
} worker_t;
/** Reactor唯一拥有的真实TLS与异步资源。 */
typedef struct fixture {
    vireo_tcp_server_t *server; /**< TLS根owner。 */
    vireo_connection_pool_lease_t clients[3]; /**< 三个当前完整租约。 */
    size_t count; /**< 本组已接入客户数。 */
    size_t at; /**< 只用于peer测试helper的当前索引。 */
    struct sockaddr_in address; /**< 临时loopback监听地址。 */
    int peers[3]; /**< 三个peer fd owner，-1为空。 */
    SSL *ssls[3]; /**< 三个可信TLS1.3 peer owner。 */
    vireo_inflight_store_t *store; /**< 8条在途表owner。 */
    vireo_task_queue_t *tasks; /**< 固定任务队列owner。 */
    vireo_thread_pool_t *pool; /**< 单worker池owner。 */
    worker_t worker; /**< 稳定长借context，join后销毁。 */
    bool released; /**< 预热worker已释放。 */
    vireo_event_loop_handle_t handle; /**< notifier完整注册值。 */
    vireo_async_request_pending_t pending[3]; /**< 每客户唯一防重gate。 */
    vireo_task_t *remaining; /**< 未移交task owner。 */
    vireo_task_metadata_t accepted[8]; /**< 真实移交身份，清理时核对。 */
    unsigned submitted; /**< 实际数据task移交数量。 */
    unsigned delivered; /**< 完成回调次数。 */
    vireo_tcp_server_ready_client_t ready[4]; /**< poll全部已取前缀，尾部哨兵。 */
    vireo_async_round_tls_turn_t turns[4]; /**< 实际turn前缀与尾部哨兵。 */
    vireo_async_round_tls_report_t report; /**< 本轮真实进度。 */
    unsigned configured; /**< callback累计次数。 */
    unsigned fail_configure; /**< 指定callback次数返回IO。 */
    unsigned bad_configure; /**< 指定callback次数返回OK但pending NULL。 */
} fixture_t;
static vireo_completion_response_descriptor_t const descriptor = {
    VIREO_COMMAND_NODE_STAT,0,UINT32_C(0x10203040),UINT32_MAX};
static vireo_tls_io_budget_t const io_budget = {4096,8};
static vireo_async_client_drive_options_t const options = {128,65536,8,9,UINT64_MAX};
static vireo_async_client_drive_tls_budget_t const budget = {{4096,8},{4096,8}};
static unsigned groups;

static size_t fds(void) {
    DIR *d=opendir("/proc/self/fd"); CHECK(d); size_t n=0; struct dirent *p;
    while((p=readdir(d))!=NULL) if(p->d_name[0]!='.') ++n;
    CHECK(closedir(d)==0); return n;
}
static vireo_tls_connection_t *tls(fixture_t *f) {
    vireo_tls_connection_t *t=NULL;
    EXPECT(vireo_tcp_server_client_tls_borrow(f->server,f->clients[f->at],&t,NULL),VIREO_OK); return t;
}
static vireo_tcp_server_client_info_t state(fixture_t *f) {
    vireo_tcp_server_client_info_t i;
    EXPECT(vireo_tcp_server_client_inspect(f->server,f->clients[f->at],&i),VIREO_OK); return i;
}
static void refresh(fixture_t *f) {
    vireo_tcp_server_tls_flow_info_t i;
    EXPECT(vireo_tcp_server_client_tls_flow_refresh(f->server,f->clients[f->at],&i,NULL),VIREO_OK);
}
static void setup_root(fixture_t *f,uint64_t handshake_timeout) {
    *f=(fixture_t){.peers={-1,-1,-1}};
    vireo_tls_context_options_t const co={fixture_leaf,sizeof fixture_leaf-1,fixture_key,sizeof fixture_key-1,4096};
    vireo_tls_context_t *context=NULL;
    EXPECT(vireo_tls_context_create_server(&co,&context,NULL),VIREO_OK);
    vireo_tcp_server_options_t const so={3,8,1048576,32768};
    vireo_tcp_server_tls_options_t const to={{4096,4096,40960,128,127,4096,0,4096},
        4096,handshake_timeout,163840};
    EXPECT(vireo_tcp_server_create_tls_with_auxiliary_capacity(&so,&to,1,&context,&f->server,NULL),VIREO_OK);
    CHECK(context==NULL);
    int fd=socket(AF_INET,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0); CHECK(fd>=0);
    struct sockaddr_in address={.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
    CHECK(bind(fd,(struct sockaddr *)&address,sizeof address)==0 && listen(fd,4)==0);
    socklen_t n=sizeof address; CHECK(getsockname(fd,(struct sockaddr *)&address,&n)==0);
    vireo_acceptor_t *listener=NULL; vireo_acceptor_options_t const ao={4096};
    EXPECT(vireo_acceptor_create(&ao,&fd,&listener,NULL),VIREO_OK);
    EXPECT(vireo_tcp_server_adopt_listener(f->server,&listener,NULL),VIREO_OK);
    EXPECT(vireo_tcp_server_bind_listener(f->server,true,NULL),VIREO_OK);
    f->address=address; f->count=1;
    f->peers[f->at]=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0); CHECK(f->peers[f->at]>=0);
    CHECK(connect(f->peers[f->at],(struct sockaddr *)&address,sizeof address)==0);
    int flags=fcntl(f->peers[f->at],F_GETFL); CHECK(flags>=0 && fcntl(f->peers[f->at],F_SETFL,flags|O_NONBLOCK)==0);
    vireo_tcp_server_admit_budget_t const ab={1,2}; vireo_tcp_server_tls_admit_info_t ai;
    EXPECT(vireo_tcp_server_tls_admit_batch(f->server,&ab,&f->clients[f->at],1,&ai,NULL),VIREO_OK); CHECK(ai.admission.admitted_count==1);
    vireo_inflight_store_options_t const io={8,65536};
    EXPECT(vireo_inflight_store_create(&io,&f->store),VIREO_OK);
}
static void prepare_peer_tls(fixture_t *f) {
    SSL_CTX *c=SSL_CTX_new(TLS_client_method()); CHECK(c);
    CHECK(SSL_CTX_set_min_proto_version(c,TLS1_3_VERSION)==1 && SSL_CTX_set_max_proto_version(c,TLS1_3_VERSION)==1);
    SSL_CTX_set_verify(c,SSL_VERIFY_PEER,NULL);
    BIO *b=BIO_new_mem_buf(fixture_root,(int)sizeof fixture_root-1); CHECK(b);
    X509 *cert=PEM_read_bio_X509(b,NULL,NULL,NULL); CHECK(cert);
    CHECK(X509_STORE_add_cert(SSL_CTX_get_cert_store(c),cert)==1); X509_free(cert); CHECK(BIO_free(b)==1);
    f->ssls[f->at]=SSL_new(c); CHECK(f->ssls[f->at]); SSL_CTX_free(c);
    CHECK(SSL_set1_host(f->ssls[f->at],"vireo-034-test.invalid")==1);
    X509_VERIFY_PARAM_set_time(SSL_get0_param(f->ssls[f->at]),(time_t)1800000000);
    b=BIO_new_socket(f->peers[f->at],BIO_NOCLOSE); CHECK(b); SSL_set_bio(f->ssls[f->at],b,b); SSL_set_connect_state(f->ssls[f->at]);
}
static void establish_peer(fixture_t *f) {
    prepare_peer_tls(f);
    bool client_done=false,server_done=false;
    for(unsigned k=0;k<1024;++k) {
        if(!client_done) {
            ERR_clear_error(); int rc=SSL_do_handshake(f->ssls[f->at]); int why=rc==1?SSL_ERROR_NONE:SSL_get_error(f->ssls[f->at],rc);
            CHECK(why==SSL_ERROR_NONE || why==SSL_ERROR_WANT_READ || why==SSL_ERROR_WANT_WRITE); client_done=rc==1;
        }
        vireo_tcp_server_ready_client_t ready[1]; vireo_tcp_server_tls_poll_report_t p;
        EXPECT(vireo_tcp_server_tls_poll_ready_once(f->server,2,1,ready,1,&p,NULL),VIREO_OK);
        if(p.poll.selected_count && !server_done && ready[0].client.slot_index==f->clients[f->at].slot_index) {
            vireo_tcp_server_tls_handshake_info_t h;
            EXPECT(vireo_tcp_server_client_tls_handshake_step(f->server,ready[0].client,&h,NULL),VIREO_OK);
            server_done=h.application_ready;
        }
        if(client_done && server_done) break;
    }
    CHECK(client_done && server_done && SSL_version(f->ssls[f->at])==TLS1_3_VERSION && SSL_get_verify_result(f->ssls[f->at])==X509_V_OK);
}
static void setup(fixture_t *f,size_t count,bool establish) {
    setup_root(f,UINT64_C(5000000000));
    if(establish) establish_peer(f);
    for(size_t k=1;k<count;++k) {
        f->at=k; f->count=k+1;
        f->peers[k]=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0); CHECK(f->peers[k]>=0);
        CHECK(connect(f->peers[k],(struct sockaddr *)&f->address,sizeof f->address)==0);
        int flags=fcntl(f->peers[k],F_GETFL); CHECK(flags>=0 && fcntl(f->peers[k],F_SETFL,flags|O_NONBLOCK)==0);
        vireo_tcp_server_admit_budget_t const ab={1,2}; vireo_tcp_server_tls_admit_info_t ai;
        EXPECT(vireo_tcp_server_tls_admit_batch(f->server,&ab,&f->clients[k],1,&ai,NULL),VIREO_OK);
        if(establish) establish_peer(f);
    }
    f->at=0;
}
/** 经公开server等待真实网络；不拿对端POLLOUT冒充服务端可读。 */
static void wait_network(fixture_t *f) {
    vireo_tcp_server_ready_client_t ready[1]; vireo_tcp_server_tls_poll_report_t report;
    EXPECT(vireo_tcp_server_tls_poll_ready_once(f->server,5,1,ready,1,&report,NULL),VIREO_OK);
}
static void read_exact(fixture_t *f,uint8_t *bytes,size_t size) {
    size_t have=0;
    for(unsigned k=0;k<1024 && have<size;++k) {
        size_t n=0; ERR_clear_error(); int rc=SSL_read_ex(f->ssls[f->at],bytes+have,size-have,&n);
        int why=rc==1?SSL_ERROR_NONE:SSL_get_error(f->ssls[f->at],rc);
        if(rc==1) { CHECK(n>0); have+=n; }
        else {
            CHECK(why==SSL_ERROR_WANT_READ || why==SSL_ERROR_WANT_WRITE);
            struct pollfd fd={f->peers[f->at],why==SSL_ERROR_WANT_READ?POLLIN:POLLOUT,0}; CHECK(poll(&fd,1,2)>=0);
        }
    }
    CHECK(have==size);
}
static void wire_is(uint8_t const *wire,size_t size,uint8_t const *body,size_t n,vireo_status_t status) {
    CHECK(size==32+n); vireo_protocol_header_t h; vireo_protocol_codec_issue_t issue;
    EXPECT(vireo_protocol_header_decode(wire,size,&h,&issue),VIREO_OK);
    CHECK(h.command==descriptor.command && h.flags==VIREO_PROTOCOL_FLAG_RESPONSE && h.sequence==101 &&
        h.status==status && h.session_handle==descriptor.session_handle && h.task_handle==descriptor.task_handle && h.body_len==n);
    EXPECT(vireo_protocol_response_header_validate(&h,&issue),VIREO_OK);
    EXPECT(vireo_protocol_frame_crc32c_verify(wire,32,wire+32,n,&issue),VIREO_OK);
    if(n) CHECK(!memcmp(wire+32,body,n));
}
static void meet(pthread_barrier_t *b) {
    int rc=pthread_barrier_wait(b); CHECK(rc==0 || rc==PTHREAD_BARRIER_SERIAL_THREAD);
}
static vireo_result_t execute(void *context,vireo_task_t const *task) {
    worker_t *w=context; vireo_task_payload_view_t view;
    EXPECT(vireo_task_borrow_payload(task,&view),VIREO_OK);
    if(view.size==0) { meet(&w->entered); meet(&w->release); return VIREO_OK; }
    ++w->executed; CHECK(view.size==35 && view.data[32]==0 && view.data[33]==255 && view.data[34]==42);
    vireo_protocol_header_t h; vireo_protocol_codec_issue_t issue;
    EXPECT(vireo_protocol_header_decode(view.data,view.size,&h,&issue),VIREO_OK);
    EXPECT(vireo_protocol_request_header_validate(&h,&issue),VIREO_OK);
    EXPECT(vireo_protocol_frame_crc32c_verify(view.data,32,view.data+32,3,&issue),VIREO_OK);
    uint8_t body[]={42,0,255}; vireo_completion_t *remaining=NULL; vireo_completion_publish_report_t p;
    EXPECT(vireo_completion_copy_wait_publish(task,VIREO_OK,VIREO_STATUS_OK,body,3,65536,w->queue,w->notifier,&remaining,&p),VIREO_OK);
    CHECK(!remaining && p.completion_transferred);
    (void)atomic_fetch_add_explicit(&w->published,1,memory_order_release); return VIREO_OK;
}
static void pool_setup(fixture_t *f,size_t capacity) {
    atomic_init(&f->worker.published,0);
    vireo_task_queue_options_t const tq={capacity,65536}; vireo_thread_pool_options_t const po={1,65536};
    vireo_completion_queue_options_t const cq={8,65536}; vireo_notifier_options_t const no={4096};
    EXPECT(vireo_task_queue_create(&tq,&f->tasks),VIREO_OK); EXPECT(vireo_task_queue_prepare_wait(f->tasks),VIREO_OK);
    EXPECT(vireo_completion_queue_create(&cq,&f->worker.queue),VIREO_OK);
    EXPECT(vireo_completion_queue_prepare_wait(f->worker.queue),VIREO_OK);
    EXPECT(vireo_notifier_create(&no,&f->worker.notifier,NULL),VIREO_OK);
    EXPECT(vireo_notifier_server_register(f->server,f->worker.notifier,&f->handle,NULL),VIREO_OK);
    CHECK(pthread_barrier_init(&f->worker.entered,NULL,2)==0 && pthread_barrier_init(&f->worker.release,NULL,2)==0);
    EXPECT(vireo_thread_pool_create(&po,&f->pool),VIREO_OK);
    vireo_thread_pool_configuration_t const config={f->tasks,execute,&f->worker};
    EXPECT(vireo_thread_pool_configure(f->pool,&config,NULL),VIREO_OK);
    vireo_task_route_t route; vireo_task_metadata_t metadata; vireo_task_t *warm=NULL;
    EXPECT(vireo_task_route_make(UINT64_MAX,0,1,1,&route),VIREO_OK);
    EXPECT(vireo_task_metadata_make(route,1,1,UINT64_MAX,&metadata),VIREO_OK);
    EXPECT(vireo_task_create_copy(metadata,NULL,0,4096,&warm),VIREO_OK);
    vireo_task_queue_transfer_report_t qr; EXPECT(vireo_task_queue_try_push(f->tasks,&warm,&qr),VIREO_OK);
    vireo_thread_pool_report_t pr; EXPECT(vireo_thread_pool_start(f->pool,&pr),VIREO_OK);
    EXPECT(vireo_thread_pool_enable_execution(f->pool,&pr),VIREO_OK); meet(&f->worker.entered);
}
static void release_worker(fixture_t *f) {
    if(!f->released) { meet(&f->worker.release); f->released=true; }
}
static void cleanup(fixture_t *f) {
    for(size_t k=0;k<f->count;++k) if(f->pending[k].frame_bytes) { vireo_async_request_head_report_t p;
        EXPECT(vireo_async_request_resume_consume(f->server,&f->pending[k],&p),VIREO_OK); }
    EXPECT(vireo_task_destroy(&f->remaining),VIREO_OK);
    release_worker(f); vireo_task_queue_close_report_t cr; vireo_result_t result=VIREO_RESULT_BUSY;
    for(unsigned k=0;k<1000000 && result==VIREO_RESULT_BUSY;++k) {
        result=vireo_task_queue_close(f->tasks,VIREO_TASK_QUEUE_DRAIN,&cr); if(result==VIREO_RESULT_BUSY) sched_yield();
    }
    CHECK(result==VIREO_OK); vireo_thread_pool_report_t pr; result=VIREO_RESULT_BUSY;
    for(unsigned k=0;k<1000000 && result==VIREO_RESULT_BUSY;++k) {
        result=vireo_thread_pool_stop_and_join(f->pool,&pr); if(result==VIREO_RESULT_BUSY) sched_yield();
    }
    CHECK(result==VIREO_OK && f->worker.executed==f->submitted);
    vireo_completion_queue_close_report_t ccr; EXPECT(vireo_completion_queue_close(f->worker.queue,&ccr),VIREO_OK);
    for(;;) {
        vireo_completion_t *c=NULL; vireo_completion_queue_transfer_report_t qr;
        result=vireo_completion_queue_try_pop(f->worker.queue,&c,&qr);
        if(result==VIREO_RESULT_CANCELLED) break;
        CHECK(result==VIREO_OK && c); EXPECT(vireo_completion_destroy(&c),VIREO_OK);
    }
    for(unsigned k=0;k<f->submitted;++k) {
        vireo_task_metadata_t removed; result=vireo_inflight_store_take(f->store,f->accepted[k],&removed,NULL);
        CHECK(result==VIREO_OK || result==VIREO_RESULT_NOT_FOUND);
    }
    vireo_inflight_store_info_t si; EXPECT(vireo_inflight_store_inspect(f->store,&si),VIREO_OK); CHECK(si.count==0);
    EXPECT(vireo_thread_pool_destroy(&f->pool),VIREO_OK); EXPECT(vireo_task_queue_destroy(&f->tasks),VIREO_OK);
    EXPECT(vireo_notifier_server_unregister(f->server,&f->handle,NULL),VIREO_OK);
    EXPECT(vireo_completion_queue_destroy(&f->worker.queue),VIREO_OK);
    EXPECT(vireo_notifier_destroy(&f->worker.notifier,NULL),VIREO_OK);
    CHECK(pthread_barrier_destroy(&f->worker.entered)==0 && pthread_barrier_destroy(&f->worker.release)==0);
    EXPECT(vireo_inflight_store_destroy(&f->store),VIREO_OK);
    for(size_t k=0;k<f->count;++k) {
        if(f->clients[k].pool_id) EXPECT(vireo_tcp_server_release_client(f->server,&f->clients[k],NULL),VIREO_OK);
        SSL_free(f->ssls[k]); if(f->peers[k]>=0) CHECK(close(f->peers[k])==0);
    }
    EXPECT(vireo_tcp_server_destroy(&f->server,NULL),VIREO_OK);
}
static void make_request(uint8_t *wire,uint32_t sequence) {
    memset(wire,0,35); wire[33]=255; wire[34]=42;
    vireo_protocol_header_t h={.command=descriptor.command,.sequence=sequence,.body_len=3,
        .session_handle=descriptor.session_handle,.task_handle=descriptor.task_handle};
    EXPECT(vireo_protocol_header_encode(&h,wire,35),VIREO_OK);
    EXPECT(vireo_protocol_frame_crc32c_calculate(wire,32,wire+32,3,&h.crc32c),VIREO_OK);
    EXPECT(vireo_protocol_header_encode(&h,wire,35),VIREO_OK);
}
static void peer_write(fixture_t *f,uint8_t const *p,size_t n) {
    size_t sent=0; ERR_clear_error(); CHECK(SSL_write_ex(f->ssls[f->at],p,n,&sent)==1 && sent==n);
}
/** 仅为锁定故障/缓存边界预装输入；真实全链用新drive自己receive。 */
static void cache_input(fixture_t *f,size_t n) {
    for(unsigned k=0;k<1024 && state(f).connection_info.read_buffer.readable_size<n;++k) {
        vireo_tls_io_progress_t p; EXPECT(vireo_tls_connection_receive(tls(f),&io_budget,&p,NULL),VIREO_OK);
        if(!p.bytes) wait_network(f);
    }
    CHECK(state(f).connection_info.read_buffer.readable_size==n); refresh(f);
}
static void record(fixture_t *f,vireo_async_client_drive_tls_report_t p) {
    if(p.head_report.submit_report.task_transferred) {
        CHECK(f->submitted<8); f->accepted[f->submitted++]=p.head_report.submit_report.metadata;
    }
}
static bool same(vireo_connection_pool_lease_t a,vireo_connection_pool_lease_t b) {
    return a.pool_id==b.pool_id && a.slot_index==b.slot_index && a.generation==b.generation;
}
static size_t index_of(fixture_t *f,vireo_connection_pool_lease_t client) {
    for(size_t k=0;k<f->count;++k) if(same(f->clients[k],client)) return k;
    CHECK(false); return 0;
}
static vireo_result_t configure(void *context,vireo_tcp_server_ready_client_t client,vireo_async_round_tls_config_t *out) {
    fixture_t *f=context; ++f->configured; size_t k=index_of(f,client.client);
    CHECK(out->pending==NULL && out->options.operation==0 && out->cancel==NULL);
    if(f->configured==f->fail_configure) { out->options.operation=99; return VIREO_RESULT_IO; }
    *out=(vireo_async_round_tls_config_t){options,budget,NULL,&f->pending[k]};
    if(f->configured==f->bad_configure) out->pending=NULL;
    return VIREO_OK;
}
static vireo_async_round_tls_options_t const round_options={5,3,4096};
static void collect(fixture_t *f) {
    CHECK(f->report.unprocessed_begin==f->report.turn_count);
    for(size_t k=0;k<f->report.turn_count;++k) record(f,f->turns[k].drive_report);
}
static void round_once(fixture_t *f,size_t max,size_t ready_cap,size_t turn_cap,vireo_result_t expected) {
    vireo_async_round_tls_options_t o=round_options; o.max_clients=max;
    EXPECT(vireo_async_round_tls_once(f->server,f->store,f->pool,&o,configure,f,f->ready,ready_cap,f->turns,turn_cap,
        &f->remaining,&f->report),expected); collect(f);
}
static void schedule_all(fixture_t *f) {
    for(size_t k=0;k<f->count;++k) EXPECT(vireo_tcp_server_schedule_client(f->server,f->clients[k],NULL),VIREO_OK);
}
/** 清空无事件缓存排队后再按指定顺序排；不调用async业务。 */
static void reset_queue(fixture_t *f) {
    for(unsigned k=0;k<32;++k) {
        vireo_tcp_server_ready_client_t ready[3]; vireo_tcp_server_tls_poll_report_t p;
        EXPECT(vireo_tcp_server_tls_poll_ready_once(f->server,0,3,ready,3,&p,NULL),VIREO_OK);
        if(!p.poll.remaining_count) return;
    }
    CHECK(false);
}
static vireo_result_t deliver(void *context,vireo_completion_t const *c,vireo_inflight_completion_match_t match) {
    fixture_t *f=context; ++f->delivered; uint8_t work[128]; vireo_completion_response_tls_report_t p;
    CHECK(match.metadata.route.request_sequence==101 && match.metadata.operation==9);
    (void)index_of(f,(vireo_connection_pool_lease_t){match.metadata.route.client_owner_id,
        match.metadata.route.client_slot_index,match.metadata.route.client_generation});
    EXPECT(vireo_completion_response_tls_enqueue(f->server,c,match,descriptor,128,work,sizeof work,&p),VIREO_OK);
    CHECK(p.response.enqueued); return VIREO_OK;
}
static void real_multi_chain(void) {
    fixture_t f; setup(&f,3,true); pool_setup(&f,8); uint8_t req[35]; make_request(req,101);
    for(size_t k=0;k<3;++k) { f.at=k; peer_write(&f,req,35); }
    schedule_all(&f);
    for(unsigned k=0;k<1024 && f.submitted<3;++k) {
        unsigned before=f.submitted; round_once(&f,3,3,3,VIREO_OK);
        CHECK(f.submitted-before<=3 && f.report.drive_calls<=3 && f.report.handshake_calls==0);
        for(size_t i=0;i<f.report.turn_count;++i) {
            CHECK(f.turns[i].path==VIREO_TCP_SERVER_TLS_TURN_APPLICATION);
            if(f.turns[i].drive_report.head_called) CHECK(f.turns[i].drive_report.request_header.sequence==101);
        }
    }
    CHECK(f.submitted==3); release_worker(&f);
    unsigned spins=0;
    while(atomic_load_explicit(&f.worker.published,memory_order_acquire)!=3 && spins++<1000000) sched_yield();
    CHECK(atomic_load_explicit(&f.worker.published,memory_order_acquire)==3);
    for(unsigned k=0;k<1024 && f.delivered<3;++k) {
        round_once(&f,3,3,3,VIREO_OK); vireo_completion_t *remaining=NULL; vireo_notifier_server_dispatch_report_t p;
        EXPECT(vireo_notifier_server_dispatch_ready(f.server,f.handle,f.worker.notifier,f.store,f.worker.queue,3,
            deliver,&f,&remaining,&p),VIREO_OK); CHECK(!remaining);
    }
    CHECK(f.delivered==3);
    for(unsigned k=0;k<1024;++k) {
        round_once(&f,3,3,3,VIREO_OK); size_t queued=0;
        for(size_t i=0;i<3;++i) { f.at=i; queued+=state(&f).connection_info.write_buffer.readable_size; }
        if(!queued) break;
        CHECK(k!=1023);
    }
    for(size_t k=0;k<3;++k) {
        f.at=k; uint8_t wire[35],body[]={42,0,255}; read_exact(&f,wire,35); wire_is(wire,35,body,3,VIREO_STATUS_OK);
    }
    CHECK(f.submitted==3); cleanup(&f); ++groups;
}
static void fairness_and_caps(void) {
    fixture_t f; setup(&f,3,true); pool_setup(&f,8); uint8_t req[71]; make_request(req,101); make_request(req+35,102); req[70]=0;
    for(size_t k=0;k<3;++k) { f.at=k; peer_write(&f,req,k==0?71:35); cache_input(&f,k==0?71:35); }
    reset_queue(&f); schedule_all(&f); memset(&f.turns[2],0xA5,sizeof f.turns[2]); vireo_async_round_tls_turn_t sentinel=f.turns[2];
    round_once(&f,3,3,2,VIREO_OK);
    CHECK(f.report.effective_max_clients==2 && f.report.turn_count==2 && f.report.drive_calls==2 && f.submitted==2);
    CHECK(same(f.turns[0].client.client,f.clients[0]) && same(f.turns[1].client.client,f.clients[1]));
    CHECK(f.turns[0].drive_report.needs_reschedule && f.turns[0].schedule_called && f.report.requeued_count==1);
    CHECK(!memcmp(&sentinel,&f.turns[2],sizeof sentinel));
    round_once(&f,2,3,3,VIREO_OK);
    CHECK(f.report.turn_count==2 && same(f.turns[0].client.client,f.clients[2]) && same(f.turns[1].client.client,f.clients[0]));
    CHECK(f.submitted==4 && f.turns[1].drive_report.request_header.sequence==102 && f.turns[1].drive_report.needs_reschedule);
    round_once(&f,3,1,3,VIREO_OK);
    CHECK(f.report.effective_max_clients==1 && f.report.turn_count==1 && !f.turns[0].drive_report.head_called && !f.turns[0].schedule_called);
    CHECK(f.submitted==4); cleanup(&f); ++groups;
}
static void config_suffix(void) {
    for(unsigned k=0;k<2;++k) {
        fixture_t f; setup(&f,3,true); pool_setup(&f,8); reset_queue(&f); schedule_all(&f);
        if(k==0) f.fail_configure=2; else f.bad_configure=2;
        memset(&f.turns[2],0x5A,sizeof f.turns[2]); vireo_async_round_tls_turn_t sentinel=f.turns[2];
        round_once(&f,3,3,3,k==0?VIREO_RESULT_IO:VIREO_RESULT_INVALID_ARGUMENT);
        CHECK(f.report.poll_report.poll.selected_count==3 && f.report.turn_count==2 && f.report.unprocessed_begin==2);
        CHECK(f.report.drive_calls==(k==0?1U:2U) && f.report.stage==(k==0?VIREO_ASYNC_ROUND_TLS_CONFIGURE:VIREO_ASYNC_ROUND_TLS_DRIVE));
        CHECK(same(f.ready[2].client,f.clients[2]) && !memcmp(&sentinel,&f.turns[2],sizeof sentinel));
        CHECK(f.report.poll_report.poll.remaining_count==0); /* 后缀已取出，不在原Q。 */
        f.fail_configure=0; f.bad_configure=0;
        EXPECT(vireo_tcp_server_schedule_client(f.server,f.ready[1].client,NULL),VIREO_OK);
        EXPECT(vireo_tcp_server_schedule_client(f.server,f.ready[2].client,NULL),VIREO_OK);
        round_once(&f,3,3,3,VIREO_OK); CHECK(f.report.turn_count>=2);
        cleanup(&f); ++groups;
    }
}
static void task_full_suffix(void) {
    fixture_t f; setup(&f,3,true); pool_setup(&f,1); uint8_t req[35]; make_request(req,101);
    for(size_t k=0;k<3;++k) { f.at=k; peer_write(&f,req,35); cache_input(&f,35); }
    reset_queue(&f); schedule_all(&f); round_once(&f,3,3,3,VIREO_RESULT_BUSY);
    CHECK(f.report.turn_count==2 && f.report.unprocessed_begin==2 && f.submitted==1 && f.remaining);
    CHECK(f.turns[0].drive_report.head_report.submit_report.task_transferred && !f.turns[1].drive_report.head_report.submit_report.task_transferred);
    f.at=1; CHECK(state(&f).connection_info.read_buffer.readable_size==35);
    f.at=2; CHECK(state(&f).connection_info.read_buffer.readable_size==35);
    cleanup(&f); ++groups;
}
static void handshake_handoff(void) {
    fixture_t f; setup(&f,2,false); pool_setup(&f,8); f.at=0; prepare_peer_tls(&f);
    bool client_done=false,server_done=false;
    for(unsigned k=0;k<1024;++k) {
        if(!client_done) {
            ERR_clear_error(); int rc=SSL_do_handshake(f.ssls[0]); int why=rc==1?SSL_ERROR_NONE:SSL_get_error(f.ssls[0],rc);
            CHECK(why==SSL_ERROR_NONE || why==SSL_ERROR_WANT_READ || why==SSL_ERROR_WANT_WRITE); client_done=rc==1;
        }
        round_once(&f,2,3,3,VIREO_OK);
        for(size_t i=0;i<f.report.turn_count;++i) if(f.turns[i].handshake_called) {
            CHECK(!f.turns[i].configure_called && !f.turns[i].drive_called);
            if(f.turns[i].handshake.application_ready) {
                CHECK(same(f.turns[i].client.client,f.clients[0]) && f.turns[i].schedule_called && f.turns[i].schedule_result==VIREO_OK);
                server_done=true;
            }
        }
        if(client_done && server_done) break;
    }
    CHECK(client_done && server_done && f.submitted==0 && SSL_get_verify_result(f.ssls[0])==X509_V_OK);
    vireo_tls_connection_info_t info; f.at=1; EXPECT(vireo_tls_connection_inspect(tls(&f),&info,NULL),VIREO_OK);
    CHECK(info.handshake_state!=VIREO_TLS_HANDSHAKE_ESTABLISHED);
    f.at=0; uint8_t req[35]; make_request(req,101); peer_write(&f,req,35);
    for(unsigned k=0;k<1024 && f.submitted==0;++k) round_once(&f,2,3,3,VIREO_OK);
    CHECK(f.submitted==1); cleanup(&f); ++groups;
}
static void deadlines_and_close_tail(void) {
    fixture_t f; setup_root(&f,1); pool_setup(&f,8);
    round_once(&f,3,3,3,VIREO_RESULT_TIMEOUT);
    CHECK(f.report.handshake_calls==1 && f.report.drive_calls==0 && f.configured==0);
    CHECK(f.report.stage==VIREO_ASYNC_ROUND_TLS_HANDSHAKE && f.report.poll_report.expired_clients==1);
    cleanup(&f); ++groups;
    setup(&f,1,true); pool_setup(&f,8); vireo_tcp_server_tls_close_request_info_t r;
    EXPECT(vireo_tcp_server_client_tls_close_request(f.server,f.clients[0],1,&r,NULL),VIREO_OK);
    round_once(&f,3,3,3,VIREO_RESULT_TIMEOUT);
    CHECK(f.report.close_calls==1 && f.report.drive_calls==0 && f.report.stage==VIREO_ASYNC_ROUND_TLS_CLOSE);
    cleanup(&f); ++groups;
    setup(&f,1,true); pool_setup(&f,8); uint8_t tail[4096]; memset(tail,0xA5,sizeof tail); tail[0]=0; tail[1]=255;
    peer_write(&f,tail,sizeof tail); cache_input(&f,sizeof tail);
    EXPECT(vireo_tcp_server_client_tls_close_request(f.server,f.clients[0],UINT64_C(1000000000),&r,NULL),VIREO_OK);
    EXPECT(vireo_tcp_server_schedule_client(f.server,f.clients[0],NULL),VIREO_OK);
    round_once(&f,3,3,3,VIREO_OK);
    CHECK(f.report.close_calls==1 && f.configured==0 && !f.turns[0].drive_called);
    CHECK(f.turns[0].close.sync.close.needs_consume);
    uint8_t const *p=NULL; size_t n=0; EXPECT(vireo_tcp_server_client_read_peek(f.server,f.clients[0],&p,&n,NULL),VIREO_OK);
    CHECK(n==sizeof tail && !memcmp(p,tail,sizeof tail));
    EXPECT(vireo_tcp_server_client_read_consume(f.server,f.clients[0],sizeof tail,NULL),VIREO_OK);
    vireo_tcp_server_tls_close_flow_info_t flow;
    EXPECT(vireo_tcp_server_client_tls_close_flow_refresh(f.server,f.clients[0],&flow,NULL),VIREO_OK);
    bool peer_closed=false,done=false;
    for(unsigned k=0;k<1024;++k) {
        round_once(&f,3,3,3,VIREO_OK);
        size_t got=0; uint8_t byte; ERR_clear_error(); int rc=SSL_read_ex(f.ssls[0],&byte,1,&got);
        int why=rc==1?SSL_ERROR_NONE:SSL_get_error(f.ssls[0],rc);
        CHECK(why==SSL_ERROR_ZERO_RETURN || why==SSL_ERROR_WANT_READ || why==SSL_ERROR_WANT_WRITE);
        if(why==SSL_ERROR_ZERO_RETURN && !peer_closed) { peer_closed=true; ERR_clear_error(); rc=SSL_shutdown(f.ssls[0]); CHECK(rc==0 || rc==1); }
        vireo_tls_close_info_t close; EXPECT(vireo_tls_connection_close_inspect(tls(&f),&close,NULL),VIREO_OK);
        if(close.state==VIREO_TLS_CLOSE_COMPLETE) { done=true; break; }
    }
    CHECK(peer_closed && done && f.submitted==0 && f.configured==0); cleanup(&f); ++groups;
}
/** 本轮公开边界故障，原资源仍通过public操作，不访问外模块private。 */
typedef struct fault {
    bool poll_io; /**< 原生前无进度poll IO模型。 */
    bool partial_poll; /**< 实际只取一项后返回模型QUEUE IO。 */
    bool bad_count; /**< OK但selected超过授予上限的依赖违约模型。 */
    bool stop_after_poll; /**< 真实poll后公开request_stop。 */
    bool transferred_error; /**< 原driver移交后模型final错误，不伪造task。 */
    bool schedule_busy; /**< 排尾前模型BUSY，无队列提交。 */
    unsigned schedules; /**< 实际排尾尝试次数。 */
    unsigned drives; /**< 实际driver尝试次数。 */
} fault_t;
static vireo_result_t poll_hook(void *c,vireo_tcp_server_t *s,int timeout,size_t max,
    vireo_tcp_server_ready_client_t *ready,size_t cap,vireo_tcp_server_tls_poll_report_t *r,vireo_tcp_server_tls_error_t *e) {
    fault_t *f=c; if(f->poll_io) return VIREO_RESULT_IO;
    vireo_result_t result=vireo_tcp_server_tls_poll_ready_once(s,timeout,f->partial_poll?1:max,ready,cap,r,e);
    if(result==VIREO_OK && f->partial_poll) { e->stage=VIREO_TCP_SERVER_TLS_QUEUE; return VIREO_RESULT_IO; }
    if(result==VIREO_OK && f->bad_count) r->poll.selected_count=max+1;
    if(result==VIREO_OK && f->stop_after_poll) EXPECT(vireo_tcp_server_request_stop(s,NULL),VIREO_OK);
    return result;
}
static vireo_result_t handshake_hook(void *c,vireo_tcp_server_t *s,vireo_connection_pool_lease_t l,
    vireo_tcp_server_tls_handshake_info_t *r,vireo_tcp_server_tls_error_t *e) {
    (void)c; return vireo_tcp_server_client_tls_handshake_step(s,l,r,e);
}
static vireo_result_t close_hook(void *c,vireo_tcp_server_t *s,vireo_connection_pool_lease_t l,size_t bytes,
    vireo_tcp_server_tls_close_step_info_t *r,vireo_tcp_server_tls_close_error_t *e) {
    (void)c; return vireo_tcp_server_client_tls_close_step(s,l,bytes,r,e);
}
static vireo_result_t drive_hook(void *c,vireo_tcp_server_t *s,vireo_connection_pool_lease_t l,
    vireo_inflight_store_t *store,vireo_thread_pool_t *pool,vireo_async_client_drive_options_t const *o,
    vireo_async_client_drive_tls_budget_t const *b,vireo_task_cancel_t *cancel,vireo_async_request_pending_t *pending,
    vireo_task_t **owner,vireo_async_client_drive_tls_report_t *r) {
    fault_t *f=c; ++f->drives;
    vireo_result_t result=vireo_async_client_drive_tls_once(s,l,store,pool,o,b,cancel,pending,owner,r);
    if(result==VIREO_OK && f->transferred_error) {
        CHECK(r->head_report.submit_report.task_transferred && r->head_report.consume_result==VIREO_OK);
        r->stage=VIREO_ASYNC_CLIENT_DRIVE_TLS_FINAL_REFRESH; r->final_refresh_result=VIREO_RESULT_IO;
        r->final_error.stage=VIREO_TCP_SERVER_TLS_APPLICATION_SYNC; r->final_error.sync_result=VIREO_RESULT_IO;
        r->needs_reschedule=false; return VIREO_RESULT_IO; /* 最终同步失败公开前缀模型，非真实MOD故障。 */
    }
    return result;
}
static vireo_result_t schedule_hook(void *c,vireo_tcp_server_t *s,vireo_connection_pool_lease_t l,vireo_tcp_server_client_error_t *e) {
    fault_t *f=c; ++f->schedules; if(f->schedule_busy) return VIREO_RESULT_BUSY;
    return vireo_tcp_server_schedule_client(s,l,e);
}
static vireo_async_round_tls_ops_t const ops={poll_hook,handshake_hook,close_hook,drive_hook,schedule_hook};
static void model(fixture_t *f,fault_t *fault,vireo_result_t expected) {
    EXPECT(vireo_async_round_tls_with_ops(f->server,f->store,f->pool,&round_options,configure,f,
        f->ready,3,f->turns,3,&f->remaining,&f->report,&ops,fault),expected); collect(f);
}
static void failure_models(void) {
    for(unsigned k=0;k<4;++k) {
        fixture_t f; setup(&f,3,true); pool_setup(&f,8); reset_queue(&f); schedule_all(&f); fault_t fault={0};
        if(k==0) fault.poll_io=true;
        if(k==1) fault.partial_poll=true;
        if(k==2) fault.bad_count=true;
        if(k==3) fault.stop_after_poll=true;
        model(&f,&fault,k==2?VIREO_RESULT_INTERNAL:(k==3?VIREO_RESULT_CANCELLED:VIREO_RESULT_IO));
        CHECK(f.report.poll_called && f.submitted==0);
        if(k!=3) CHECK(f.report.turn_count==0 && f.report.unprocessed_begin==0 && f.configured==0);
        if(k==1) CHECK(f.report.poll_report.poll.selected_count==1 && f.report.poll_report.poll.remaining_count==2);
        if(k==3) CHECK(f.report.turn_count==1 && f.report.unprocessed_begin==1 && f.report.poll_report.poll.selected_count==3);
        cleanup(&f); ++groups;
    }
    for(unsigned k=0;k<2;++k) {
        fixture_t f; setup(&f,3,true); pool_setup(&f,8); uint8_t req[70]; make_request(req,101); make_request(req+35,102);
        peer_write(&f,req,k==0?35:70); cache_input(&f,k==0?35:70); reset_queue(&f); schedule_all(&f);
        fault_t fault={.transferred_error=k==0,.schedule_busy=k==1}; model(&f,&fault,k==0?VIREO_RESULT_IO:VIREO_RESULT_BUSY);
        CHECK(f.report.turn_count==1 && f.report.unprocessed_begin==1 && f.report.poll_report.poll.selected_count==3 && f.submitted==1);
        CHECK(f.turns[0].drive_report.head_report.submit_report.task_transferred && f.pending[0].frame_bytes==0);
        CHECK(f.report.stage==(k==0?VIREO_ASYNC_ROUND_TLS_DRIVE:VIREO_ASYNC_ROUND_TLS_SCHEDULE));
        CHECK(fault.schedules==(k==0?0U:1U));
        f.at=0; refresh(&f); EXPECT(vireo_tcp_server_schedule_client(f.server,f.clients[0],NULL),VIREO_OK);
        round_once(&f,1,3,3,VIREO_OK); CHECK(f.submitted==(k==0?1U:2U));
        cleanup(&f); ++groups;
    }
}
static void stop_and_validation(void) {
    fixture_t f; setup(&f,1,true); pool_setup(&f,8); reset_queue(&f); schedule_all(&f);
    memset(f.ready,0xA5,sizeof f.ready); memset(f.turns,0x5A,sizeof f.turns);
    unsigned char ready_before[sizeof f.ready],turns_before[sizeof f.turns];
    memcpy(ready_before,f.ready,sizeof f.ready); memcpy(turns_before,f.turns,sizeof f.turns);
    for(unsigned k=0;k<8;++k) {
        vireo_async_round_tls_options_t o=round_options; size_t rc=3,tc=3; vireo_result_t expected=VIREO_RESULT_INVALID_ARGUMENT;
        if(k==0) o.timeout_ms=-1;
        if(k==1) o.max_clients=0;
        if(k==2) rc=0;
        if(k==3) tc=0;
        if(k==4) o.close_max_bytes=0;
        if(k==5) { o.close_max_bytes=4095; expected=VIREO_RESULT_RANGE; }
        if(k==6) { o.max_clients=65536; expected=VIREO_RESULT_RANGE; }
        if(k==7) { tc=65536; expected=VIREO_RESULT_RANGE; }
        EXPECT(vireo_async_round_tls_once(f.server,f.store,f.pool,&o,configure,&f,f.ready,rc,f.turns,tc,&f.remaining,&f.report),expected);
        CHECK(!f.report.poll_called && f.report.turn_count==0);
        CHECK(!memcmp(ready_before,f.ready,sizeof f.ready) && !memcmp(turns_before,f.turns,sizeof f.turns));
    }
    EXPECT(vireo_async_round_tls_once(NULL,f.store,f.pool,&round_options,configure,&f,f.ready,3,f.turns,3,&f.remaining,&f.report),VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_async_round_tls_once(f.server,f.store,f.pool,&round_options,NULL,&f,f.ready,3,f.turns,3,&f.remaining,&f.report),VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_async_round_tls_once(f.server,f.store,f.pool,&round_options,configure,&f,f.ready,3,f.turns,3,&f.remaining,NULL),VIREO_RESULT_INVALID_ARGUMENT);
    for(unsigned k=0;k<5;++k) {
        vireo_async_round_tls_ops_t bad=ops;
        switch(k) { case 0: bad.poll=NULL; break; case 1: bad.handshake=NULL; break; case 2: bad.close=NULL; break;
        case 3: bad.drive=NULL; break; default: bad.schedule=NULL; break; }
        EXPECT(vireo_async_round_tls_with_ops(f.server,f.store,f.pool,&round_options,configure,&f,f.ready,3,f.turns,3,
            &f.remaining,&f.report,&bad,NULL),VIREO_RESULT_INVALID_ARGUMENT);
    }
    EXPECT(vireo_tcp_server_request_stop(f.server,NULL),VIREO_OK); round_once(&f,3,3,3,VIREO_OK);
    CHECK(f.report.poll_called && f.report.poll_report.poll.stopped && f.report.turn_count==0 && f.configured==0);
    CHECK(!memcmp(ready_before,f.ready,sizeof f.ready) && !memcmp(turns_before,f.turns,sizeof f.turns));
    cleanup(&f); ++groups;
    fixture_t raw={.peers={-1,-1,-1}}; vireo_tcp_server_options_t const so={3,8,1048576,32768};
    EXPECT(vireo_tcp_server_create_with_auxiliary_capacity(&so,1,&raw.server,NULL),VIREO_OK);
    vireo_inflight_store_options_t const io={8,65536}; EXPECT(vireo_inflight_store_create(&io,&raw.store),VIREO_OK);
    pool_setup(&raw,8); round_once(&raw,3,3,3,VIREO_RESULT_BUSY); CHECK(!raw.report.poll_called);
    cleanup(&raw); ++groups;
}
int main(void) {
    CHECK(signal(SIGPIPE,SIG_IGN)!=SIG_ERR); int old;
    CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,&old)==0); size_t before=fds();
    real_multi_chain(); fairness_and_caps(); config_suffix(); task_full_suffix(); handshake_handoff();
    deadlines_and_close_tail(); failure_models(); stop_and_validation();
    CHECK(fds()==before); printf("TLS async round: %u groups passed, fd %zu -> %zu\n",groups,before,fds()); return 0;
}
