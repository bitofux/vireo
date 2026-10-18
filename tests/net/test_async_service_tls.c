/* TLS异步单客户真实链与own故障边界。 */
#define _GNU_SOURCE
#include "async_service_tls_internal.h"
#include "completion_response_dispatch_tls_internal.h"
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
    vireo_completion_t *remaining_completion; /**< 分发失败结果owner，显式恢复后清空。 */
    vireo_task_t *remaining; /**< 未移交task owner。 */
    vireo_task_metadata_t accepted[8]; /**< 真实移交身份，清理时核对。 */
    unsigned submitted; /**< 实际数据task移交数量。 */
    unsigned delivered; /**< resolve尝试数，仅找到已保存请求后计数。 */
    unsigned fail_resolve; /**< 指定resolve尝试返回IO，无响应提交。 */
    vireo_tcp_server_ready_client_t ready[4]; /**< poll全部已取前缀，尾部哨兵。 */
    vireo_async_round_tls_turn_t turns[4]; /**< 实际turn前缀与尾部哨兵。 */
    vireo_async_service_tls_report_t report; /**< 本轮真实进度。 */
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
static void setup_root(fixture_t *f,uint64_t handshake_timeout,size_t slots,size_t buffers,size_t tls_bytes) {
    *f=(fixture_t){.peers={-1,-1,-1}};
    vireo_tls_context_options_t const co={fixture_leaf,sizeof fixture_leaf-1,fixture_key,sizeof fixture_key-1,4096};
    vireo_tls_context_t *context=NULL;
    EXPECT(vireo_tls_context_create_server(&co,&context,NULL),VIREO_OK);
    vireo_tcp_server_options_t const so={slots,8,1048576,buffers};
    vireo_tcp_server_tls_options_t const to={{4096,4096,40960,128,127,4096,0,4096},
        4096,handshake_timeout,tls_bytes};
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
    f->address=address;
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
static void wire_is(uint8_t const *wire,size_t size,uint8_t const *body,size_t n,vireo_status_t status,uint32_t sequence) {
    CHECK(size==32+n); vireo_protocol_header_t h; vireo_protocol_codec_issue_t issue;
    EXPECT(vireo_protocol_header_decode(wire,size,&h,&issue),VIREO_OK);
    CHECK(h.command==descriptor.command && h.flags==VIREO_PROTOCOL_FLAG_RESPONSE && h.sequence==sequence &&
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
    EXPECT(vireo_completion_destroy(&f->remaining_completion),VIREO_OK);
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
static vireo_async_service_tls_options_t const service_options={{2,3,4096},{3,4},3,128,128};
static void connect_peer(fixture_t *f) {
    CHECK(f->count<3); size_t k=f->count++;
    f->peers[k]=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0); CHECK(f->peers[k]>=0);
    CHECK(connect(f->peers[k],(struct sockaddr *)&f->address,sizeof f->address)==0);
    int flags=fcntl(f->peers[k],F_GETFL); CHECK(flags>=0 && fcntl(f->peers[k],F_SETFL,flags|O_NONBLOCK)==0);
}
static vireo_result_t resolve(void *context,vireo_completion_t const *c,vireo_inflight_completion_match_t match,
    vireo_completion_response_descriptor_t *out) {
    fixture_t *f=context; vireo_completion_info_t ci; EXPECT(vireo_completion_inspect(c,&ci),VIREO_OK);
    bool found=false;
    for(unsigned k=0;k<f->submitted;++k) {
        bool equal=false; EXPECT(vireo_task_route_equal(f->accepted[k].route,match.metadata.route,&equal),VIREO_OK);
        if(equal) { CHECK(f->accepted[k].request_instance_id==match.metadata.request_instance_id &&
            f->accepted[k].operation==match.metadata.operation && f->accepted[k].deadline_ns==match.metadata.deadline_ns); found=true; }
    }
    CHECK(found && ci.metadata.request.request_instance_id==match.metadata.request_instance_id); ++f->delivered;
    if(f->fail_resolve==f->delivered) return VIREO_RESULT_IO;
    *out=descriptor; return VIREO_OK;
}
static void collect(fixture_t *f,vireo_connection_pool_lease_t const *admitted) {
    CHECK(!f->report.clients.poll_called);
    CHECK(f->report.clients.unprocessed_begin==f->report.clients.turn_count);
    for(size_t k=0;k<f->report.clients.turn_count;++k) record(f,f->turns[k].drive_report);
    for(size_t k=0;k<f->report.admission.admission.admitted_count;++k) {
        size_t i=0; while(i<f->count && f->clients[i].pool_id) ++i;
        CHECK(i<f->count); f->clients[i]=admitted[k];
    }
}
static void service_with(fixture_t *f,vireo_async_service_tls_options_t const *o,size_t ready_cap,size_t turn_cap,
    size_t admit_cap,vireo_async_service_tls_ops_t const *ops,void *context,vireo_result_t expected) {
    vireo_connection_pool_lease_t admitted[3]={{0}}; uint8_t scratch[128];
    vireo_async_service_tls_workspace_t const w={f->ready,ready_cap,f->turns,turn_cap,admitted,admit_cap,scratch,sizeof scratch};
    if(ops) EXPECT(vireo_async_service_tls_with_ops(f->server,f->store,f->pool,f->worker.notifier,f->worker.queue,
        f->handle,o,&w,configure,f,resolve,f,&f->remaining,&f->remaining_completion,&f->report,ops,context),expected);
    else EXPECT(vireo_async_service_tls_once(f->server,f->store,f->pool,f->worker.notifier,f->worker.queue,
        f->handle,o,&w,configure,f,resolve,f,&f->remaining,&f->remaining_completion,&f->report),expected);
    collect(f,admitted);
}
static void service(fixture_t *f,vireo_result_t expected) { service_with(f,&service_options,3,3,3,NULL,NULL,expected); }
static void setup(fixture_t *f,size_t count,bool establish);
static void establish_all(fixture_t *f) {
    bool done[3]={false};
    for(size_t i=0;i<f->count;++i) { f->at=i; prepare_peer_tls(f); }
    for(unsigned k=0;k<1024;++k) {
        bool complete=true;
        for(size_t i=0;i<f->count;++i) {
            if(!done[i]) {
                ERR_clear_error(); int rc=SSL_do_handshake(f->ssls[i]); int why=rc==1?SSL_ERROR_NONE:SSL_get_error(f->ssls[i],rc);
                CHECK(why==SSL_ERROR_NONE || why==SSL_ERROR_WANT_READ || why==SSL_ERROR_WANT_WRITE); done[i]=rc==1;
            }
        }
        service(f,VIREO_OK);
        for(size_t i=0;i<f->report.clients.turn_count;++i) {
            vireo_async_round_tls_turn_t const t=f->turns[i];
            CHECK(!t.handshake_called || (!t.configure_called && !t.drive_called));
            if(t.handshake_called && t.handshake.application_ready) CHECK(t.schedule_called);
        }
        for(size_t i=0;i<f->count;++i) {
            f->at=i; vireo_tls_connection_info_t ti; EXPECT(vireo_tls_connection_inspect(tls(f),&ti,NULL),VIREO_OK);
            complete=complete && done[i] && ti.handshake_state==VIREO_TLS_HANDSHAKE_ESTABLISHED;
        }
        if(complete) {
            for(size_t i=0;i<f->count;++i) CHECK(SSL_version(f->ssls[i])==TLS1_3_VERSION && SSL_get_verify_result(f->ssls[i])==X509_V_OK);
            f->at=0; return;
        }
    }
    CHECK(false);
}
static void setup(fixture_t *f,size_t count,bool establish) {
    setup_root(f,UINT64_C(5000000000),3,32768,163840); pool_setup(f,8);
    for(size_t i=0;i<count;++i) connect_peer(f);
    for(unsigned k=0;k<64;++k) {
        service(f,VIREO_OK); if(f->report.admission.admission.admitted_count==count) break;
        CHECK(k!=63);
    }
    CHECK(f->submitted==0 && f->report.clients.handshake_calls==0); /* 新连接不在本次冻结批次。 */
    if(establish) establish_all(f);
}
static void schedule_all(fixture_t *f) {
    for(size_t k=0;k<f->count;++k) if(f->clients[k].pool_id)
        EXPECT(vireo_tcp_server_schedule_client(f->server,f->clients[k],NULL),VIREO_OK);
}
static void reset_queue(fixture_t *f) {
    for(unsigned k=0;k<32;++k) {
        vireo_tcp_server_ready_client_t ready[3]; vireo_tcp_server_tls_poll_report_t p;
        EXPECT(vireo_tcp_server_tls_poll_ready_once(f->server,0,3,ready,3,&p,NULL),VIREO_OK);
        if(!p.poll.remaining_count) return;
    }
    CHECK(false);
}
static void publish_all(fixture_t *f) {
    release_worker(f); unsigned k=0;
    while(atomic_load_explicit(&f->worker.published,memory_order_acquire)!=f->submitted && k++<1000000) sched_yield();
    CHECK(atomic_load_explicit(&f->worker.published,memory_order_acquire)==f->submitted);
}
static void submit_one(fixture_t *f) {
    uint8_t req[35]; make_request(req,101); peer_write(f,req,35);
    for(unsigned k=0;k<1024 && f->submitted==0;++k) service(f,VIREO_OK);
    CHECK(f->submitted==1);
}
static void send_queued(fixture_t *f) {
    for(unsigned k=0;k<1024;++k) {
        service(f,VIREO_OK); size_t queued=0;
        for(size_t i=0;i<f->count;++i) { f->at=i; queued+=state(f).connection_info.write_buffer.readable_size; }
        if(!queued) return;
    }
    CHECK(false);
}
static void real_service_chain(void) {
    fixture_t f; setup(&f,3,true); uint8_t req[35]; make_request(req,101);
    for(size_t i=0;i<3;++i) { f.at=i; peer_write(&f,req,35); }
    for(unsigned k=0;k<1024 && f.submitted<3;++k) {
        unsigned before=f.submitted; service(&f,VIREO_OK);
        CHECK(f.submitted-before<=3 && f.report.clients.drive_calls<=3 && f.delivered==0);
        CHECK(f.report.post_pressure_called && f.report.pre_pressure_called);
    }
    CHECK(f.submitted==3); publish_all(&f);
    for(unsigned k=0;k<1024 && f.delivered<3;++k) {
        unsigned before=f.delivered; service(&f,VIREO_OK);
        CHECK(f.delivered-before<=1 && f.report.dispatch.effective_max_items==1 &&
            f.report.dispatch.reserved_frame_bytes==128 && f.report.dispatch.enqueued_responses<=1 &&
            f.report.dispatch.enqueued_bytes<=128 && !f.remaining_completion);
    }
    CHECK(f.delivered==3); send_queued(&f);
    for(size_t i=0;i<3;++i) {
        f.at=i; uint8_t wire[35],body[]={42,0,255}; read_exact(&f,wire,35); wire_is(wire,35,body,3,VIREO_STATUS_OK,101);
    }
    CHECK(f.submitted==3); cleanup(&f); ++groups;
}
static void fairness_and_suffix(void) {
    fixture_t f; setup(&f,3,true); uint8_t req[71]; make_request(req,101); make_request(req+35,102); req[70]=0;
    for(size_t i=0;i<3;++i) { f.at=i; peer_write(&f,req,i==0?71:35); cache_input(&f,i==0?71:35); }
    reset_queue(&f); schedule_all(&f);
    vireo_async_service_tls_options_t o=service_options; o.round.max_clients=1;
    for(size_t i=0;i<3;++i) {
        service_with(&f,&o,3,3,3,NULL,NULL,VIREO_OK);
        CHECK(f.report.poll.poll.selected_count==1 && f.report.clients.turn_count==1 && same(f.turns[0].client.client,f.clients[i]));
        CHECK(f.turns[0].drive_report.head_report.submit_report.task_transferred);
    }
    service_with(&f,&service_options,1,3,3,NULL,NULL,VIREO_OK);
    CHECK(f.report.effective_max_clients==1 && f.submitted==4 && f.turns[0].drive_report.request_header.sequence==102);
    service_with(&f,&service_options,3,1,3,NULL,NULL,VIREO_OK);
    CHECK(f.report.effective_max_clients==1 && f.submitted==4);
    cleanup(&f); ++groups;

    setup(&f,3,true); f.configured=0; reset_queue(&f); schedule_all(&f); f.fail_configure=2;
    service(&f,VIREO_RESULT_IO);
    CHECK(f.report.stage==VIREO_ASYNC_SERVICE_TLS_CLIENTS && f.report.clients.turn_count==2 &&
        f.report.clients.unprocessed_begin==2 && f.report.poll.poll.selected_count==3 && f.report.post_pressure_called);
    CHECK(same(f.ready[2].client,f.clients[2])); f.fail_configure=0;
    vireo_async_round_tls_report_t r; vireo_async_round_tls_turn_t turns[2];
    EXPECT(vireo_async_round_tls_process_ready(f.server,f.store,f.pool,4096,configure,&f,f.ready+1,2,turns,2,&f.remaining,&r),VIREO_OK);
    CHECK(r.turn_count==2 && !r.poll_called && r.effective_max_clients==2);
    cleanup(&f); ++groups;
}
static void pressure_and_backlog(void) {
    for(unsigned kind=0;kind<3;++kind) {
        fixture_t f; setup_root(&f,UINT64_C(5000000000),kind==0?1:3,kind==1?8192:32768,kind==2?40960:163840);
        pool_setup(&f,8); connect_peer(&f); connect_peer(&f);
        vireo_async_service_tls_options_t o=service_options; o.admit.max_accepts=1;
        service_with(&f,&o,3,3,3,NULL,NULL,VIREO_OK);
        CHECK(f.report.admission_called && f.report.admission.admission.admitted_count==1 &&
            f.report.admission.admission.accept_calls<=4 && f.report.clients.turn_count==0);
        CHECK(!f.report.post_pressure.listener_read_enabled && f.report.post_pressure.sync_called);
        CHECK((kind!=0 || f.report.post_pressure.connection_limited) &&
            (kind!=1 || f.report.post_pressure.buffer_limited) && (kind!=2 || f.report.post_pressure.tls_resource_limited));
        uint64_t old_generation=f.clients[0].generation;
        service(&f,VIREO_OK); CHECK(!f.report.admission_called && !f.report.pre_pressure.listener_read_enabled);
        EXPECT(vireo_tcp_server_release_client(f.server,&f.clients[0],NULL),VIREO_OK);
        service_with(&f,&o,3,3,1,NULL,NULL,VIREO_OK);
        CHECK(f.report.pre_pressure.sync_called && f.report.pre_pressure.listener_read_enabled &&
            f.report.admission.admission.admitted_count==1 && f.clients[0].generation>old_generation);
        CHECK(!f.report.post_pressure.listener_read_enabled);
        cleanup(&f); ++groups;
    }
}
static vireo_inflight_completion_consume_report_t last_consume(fixture_t *f) {
    return f->report.dispatch.dispatch_report.dispatch_report.drain_report.consume_report;
}
static void restore_taken(fixture_t *f) {
    vireo_async_round_tls_report_t r;
    EXPECT(vireo_async_round_tls_process_ready(f->server,f->store,f->pool,4096,configure,f,f->ready,
        f->report.poll.poll.selected_count,f->turns,3,&f->remaining,&r),VIREO_OK);
    for(size_t i=0;i<r.turn_count;++i) record(f,f->turns[i].drive_report);
}
static void response_capacity_and_resolve(void) {
    fixture_t f; setup(&f,1,true); submit_one(&f); publish_all(&f);
    uint8_t filler[4096]; memset(filler,0xA5,sizeof filler);
    EXPECT(vireo_tcp_server_client_write_enqueue(f.server,f.clients[0],filler,sizeof filler,NULL),VIREO_OK);
    refresh(&f); reset_queue(&f); schedule_all(&f);
    service(&f,VIREO_RESULT_RANGE);
    vireo_inflight_completion_consume_report_t c=last_consume(&f);
    CHECK(f.report.stage==VIREO_ASYNC_SERVICE_TLS_DISPATCH && !f.report.clients_called &&
        f.report.poll.poll.selected_count==1 && f.remaining_completion && c.record_consumed && c.delivery_called);
    CHECK(f.report.dispatch.last_response_report.response.stage==VIREO_COMPLETION_RESPONSE_ENQUEUE &&
        !f.report.dispatch.last_response_report.response.enqueued && f.report.dispatch.enqueued_responses==0 && f.delivered==1);
    vireo_inflight_store_info_t si; EXPECT(vireo_inflight_store_inspect(f.store,&si),VIREO_OK); CHECK(si.count==0);
    vireo_tls_io_progress_t progress; EXPECT(vireo_tls_connection_send(tls(&f),&io_budget,&progress,NULL),VIREO_OK);
    CHECK(progress.bytes==sizeof filler); uint8_t wire_fill[4096]; read_exact(&f,wire_fill,sizeof wire_fill);
    CHECK(!memcmp(filler,wire_fill,sizeof filler));
    uint8_t scratch[128]; vireo_completion_response_tls_report_t response;
    EXPECT(vireo_completion_response_tls_enqueue(f.server,f.remaining_completion,c.match,descriptor,128,scratch,sizeof scratch,&response),VIREO_OK);
    CHECK(response.response.enqueued); EXPECT(vireo_completion_destroy(&f.remaining_completion),VIREO_OK);
    restore_taken(&f); send_queued(&f); uint8_t wire[35],body[]={42,0,255};
    read_exact(&f,wire,35); wire_is(wire,35,body,3,VIREO_STATUS_OK,101);
    CHECK(f.submitted==1 && f.delivered==1); cleanup(&f); ++groups;

    setup(&f,1,true); submit_one(&f); publish_all(&f); f.fail_resolve=1;
    service(&f,VIREO_RESULT_IO); c=last_consume(&f);
    CHECK(f.remaining_completion && c.record_consumed && f.report.dispatch.resolve_calls==1 &&
        !f.report.dispatch.last_response_called && f.report.dispatch.response_calls==0 && !f.report.clients_called);
    EXPECT(vireo_completion_response_tls_enqueue(f.server,f.remaining_completion,c.match,descriptor,128,scratch,sizeof scratch,&response),VIREO_OK);
    EXPECT(vireo_completion_destroy(&f.remaining_completion),VIREO_OK); restore_taken(&f); send_queued(&f);
    read_exact(&f,wire,35); wire_is(wire,35,body,3,VIREO_STATUS_OK,101);
    CHECK(f.delivered==1); cleanup(&f); ++groups;
}
static void stale_generation(void) {
    fixture_t f; setup(&f,1,true); submit_one(&f);
    uint64_t old=f.clients[0].generation; EXPECT(vireo_tcp_server_release_client(f.server,&f.clients[0],NULL),VIREO_OK);
    SSL_free(f.ssls[0]); f.ssls[0]=NULL; CHECK(close(f.peers[0])==0); f.peers[0]=-1; f.count=0;
    connect_peer(&f); service(&f,VIREO_OK);
    CHECK(f.report.admission.admission.admitted_count==1 && f.clients[0].generation>old);
    publish_all(&f); service(&f,VIREO_OK);
    CHECK(f.delivered==0 && !f.remaining_completion && f.report.dispatch.resolve_calls==0 &&
        f.report.dispatch.dispatch_report.dispatch_report.drain_report.late_cleaned==1);
    f.at=0; CHECK(state(&f).connection_info.write_buffer.readable_size==0);
    cleanup(&f); ++groups;
}
static void deadlines_and_close(void) {
    fixture_t f; setup_root(&f,1,3,32768,163840); pool_setup(&f,8); connect_peer(&f); service(&f,VIREO_OK);
    service(&f,VIREO_RESULT_TIMEOUT);
    CHECK(f.report.clients.handshake_calls==1 && f.report.poll.expired_clients==1 && f.report.post_pressure_called &&
        f.report.clients.stage==VIREO_ASYNC_ROUND_TLS_HANDSHAKE && f.configured==0);
    cleanup(&f); ++groups;
    setup(&f,1,true); vireo_tcp_server_tls_close_request_info_t r;
    EXPECT(vireo_tcp_server_client_tls_close_request(f.server,f.clients[0],1,&r,NULL),VIREO_OK);
    service(&f,VIREO_RESULT_TIMEOUT);
    CHECK(f.report.clients.close_calls==1 && f.report.clients.stage==VIREO_ASYNC_ROUND_TLS_CLOSE && f.report.post_pressure_called);
    cleanup(&f); ++groups;
    setup(&f,1,true); f.configured=0; uint8_t tail[4096]; memset(tail,0xA5,sizeof tail); tail[0]=0; tail[1]=255;
    peer_write(&f,tail,sizeof tail); cache_input(&f,sizeof tail);
    EXPECT(vireo_tcp_server_client_tls_close_request(f.server,f.clients[0],UINT64_C(1000000000),&r,NULL),VIREO_OK);
    schedule_all(&f); service(&f,VIREO_OK);
    CHECK(f.report.clients.close_calls==1 && f.configured==0 && f.turns[0].close.sync.close.needs_consume);
    uint8_t const *p=NULL; size_t n=0; EXPECT(vireo_tcp_server_client_read_peek(f.server,f.clients[0],&p,&n,NULL),VIREO_OK);
    CHECK(n==sizeof tail && !memcmp(p,tail,n));
    EXPECT(vireo_tcp_server_client_read_consume(f.server,f.clients[0],n,NULL),VIREO_OK);
    vireo_tcp_server_tls_close_flow_info_t flow; EXPECT(vireo_tcp_server_client_tls_close_flow_refresh(f.server,f.clients[0],&flow,NULL),VIREO_OK);
    bool peer_closed=false,done=false;
    for(unsigned k=0;k<1024;++k) {
        service(&f,VIREO_OK);
        size_t got=0; uint8_t byte; ERR_clear_error(); int rc=SSL_read_ex(f.ssls[0],&byte,1,&got);
        int why=rc==1?SSL_ERROR_NONE:SSL_get_error(f.ssls[0],rc);
        CHECK(why==SSL_ERROR_ZERO_RETURN || why==SSL_ERROR_WANT_READ || why==SSL_ERROR_WANT_WRITE);
        if(why==SSL_ERROR_ZERO_RETURN && !peer_closed) { peer_closed=true; ERR_clear_error(); rc=SSL_shutdown(f.ssls[0]); CHECK(rc==0 || rc==1); }
        vireo_tls_close_info_t close; EXPECT(vireo_tls_connection_close_inspect(tls(&f),&close,NULL),VIREO_OK);
        if(close.state==VIREO_TLS_CLOSE_COMPLETE) { done=true; break; }
    }
    CHECK(peer_closed && done && f.submitted==0 && f.configured==0);
    CHECK(state(&f).connection_info.loop_attached); /* COMPLETE仍持fd，由caller归还。 */
    cleanup(&f); ++groups;
}
/** 只替换当前组合公开边界；全部资源操作仍走public。 */
typedef struct fault {
    unsigned pressures; /**< pressure调用次数，确定pre/post。 */
    unsigned inspections; /**< inspect调用次数，确定入口/接入前。 */
    vireo_result_t pre; /**< pre模型返回，非OK无实际MOD。 */
    vireo_result_t post; /**< post模型返回，非OK无实际MOD。 */
    bool poll_io; /**< poll模型原生前失败。 */
    bool partial_poll; /**< 实际poll撤取一项后追加模型失败。 */
    bool bad_count; /**< 依赖selected越界模型。 */
    uint32_t listener_events; /**< 模型本次listener位，零则保真实值。 */
    bool dispatch_io; /**< 分发前模型IO，无消费。 */
    bool response_io; /**< 真实enqueue/refresh之后模型最终同步失败。 */
    bool stop_after_poll; /**< 实际poll后公开request_stop。 */
    bool stop_before_admit; /**< 客户处理后公开request_stop。 */
    bool admission_io; /**< 真实admit发布前缀后模型IO。 */
    bool entry_io; /**< 入口inspect模型IO。 */
    bool admission_check_io; /**< 接入前inspect模型IO。 */
} fault_t;
static vireo_result_t inspect_hook(void *context,vireo_tcp_server_t const *s,vireo_tcp_server_info_t *r) {
    fault_t *f=context; ++f->inspections;
    if(f->entry_io || (f->admission_check_io && f->inspections==2)) return VIREO_RESULT_IO;
    return vireo_tcp_server_inspect(s,r);
}
static vireo_result_t pressure_hook(void *context,vireo_tcp_server_t *s,vireo_tcp_server_tls_admission_info_t *r,
    vireo_tcp_server_listener_error_t *e) {
    fault_t *f=context; ++f->pressures; vireo_result_t result=f->pressures==1?f->pre:f->post;
    if(result!=VIREO_OK) { e->stage=VIREO_TCP_SERVER_LISTENER_UPDATE; return result; }
    return vireo_tcp_server_tls_admission_refresh(s,r,e);
}
static vireo_result_t poll_hook(void *context,vireo_tcp_server_t *s,int timeout,size_t max,
    vireo_tcp_server_ready_client_t *ready,size_t cap,vireo_tcp_server_tls_poll_report_t *r,vireo_tcp_server_tls_error_t *e) {
    fault_t *f=context;
    if(f->poll_io) { e->stage=VIREO_TCP_SERVER_TLS_WAIT; return VIREO_RESULT_IO; }
    vireo_result_t result=vireo_tcp_server_tls_poll_ready_once(s,timeout,f->partial_poll?1:max,ready,cap,r,e);
    if(result!=VIREO_OK) return result;
    if(f->stop_after_poll) EXPECT(vireo_tcp_server_request_stop(s,NULL),VIREO_OK);
    if(f->partial_poll) { e->stage=VIREO_TCP_SERVER_TLS_QUEUE; return VIREO_RESULT_IO; }
    if(f->bad_count) r->poll.selected_count=max+1;
    if(f->listener_events) r->listener_events=f->listener_events;
    return VIREO_OK;
}
static vireo_result_t dispatch_inspect(void *context,vireo_tcp_server_t const *s,vireo_tcp_server_info_t *r,
    vireo_tcp_server_tls_error_t *e) {
    (void)context; vireo_tcp_server_tls_info_t ti;
    vireo_result_t result=vireo_tcp_server_tls_inspect(s,&ti,e);
    return result==VIREO_OK?vireo_tcp_server_inspect(s,r):result;
}
static vireo_result_t dispatch_original(void *context,vireo_tcp_server_t *s,vireo_event_loop_handle_t h,
    vireo_notifier_t *n,vireo_inflight_store_t *store,vireo_completion_queue_t *q,size_t max,
    vireo_inflight_completion_deliver_fn deliver,void *c,vireo_completion_t **owner,vireo_notifier_server_dispatch_report_t *r) {
    (void)context; return vireo_notifier_server_dispatch_ready(s,h,n,store,q,max,deliver,c,owner,r);
}
static vireo_result_t response_hook(void *context,vireo_tcp_server_t *s,vireo_completion_t const *completion,
    vireo_inflight_completion_match_t match,vireo_completion_response_descriptor_t d,size_t max,
    uint8_t *scratch,size_t cap,vireo_completion_response_tls_report_t *r) {
    fault_t *f=context;
    vireo_result_t result=vireo_completion_response_tls_enqueue(s,completion,match,d,max,scratch,cap,r);
    if(result==VIREO_OK && f->response_io) {
        r->response.stage=VIREO_COMPLETION_RESPONSE_REFRESH; return VIREO_RESULT_IO;
    }
    return result;
}
static vireo_completion_response_dispatch_tls_ops_t const dispatch_ops={dispatch_inspect,dispatch_original,response_hook};
static vireo_result_t dispatch_hook(void *context,vireo_tcp_server_t *s,vireo_event_loop_handle_t h,vireo_notifier_t *n,
    vireo_inflight_store_t *store,vireo_completion_queue_t *q,size_t max,size_t frame,size_t batch,
    uint8_t *scratch,size_t cap,vireo_completion_response_resolve_fn res,void *c,vireo_completion_t **owner,
    vireo_completion_response_dispatch_tls_report_t *r) {
    fault_t *f=context;
    if(f->dispatch_io) return VIREO_RESULT_IO;
    return vireo_completion_response_dispatch_tls_with_ops(s,h,n,store,q,max,frame,batch,scratch,cap,res,c,owner,r,&dispatch_ops,f);
}
static vireo_result_t clients_hook(void *context,vireo_tcp_server_t *s,vireo_inflight_store_t *store,vireo_thread_pool_t *p,
    size_t close_bytes,vireo_async_round_tls_configure_fn cfg,void *c,vireo_tcp_server_ready_client_t const *ready,
    size_t count,vireo_async_round_tls_turn_t *turns,size_t cap,vireo_task_t **owner,vireo_async_round_tls_report_t *r) {
    fault_t *f=context;
    vireo_result_t result=vireo_async_round_tls_process_ready(s,store,p,close_bytes,cfg,c,ready,count,turns,cap,owner,r);
    if(f->stop_before_admit) EXPECT(vireo_tcp_server_request_stop(s,NULL),VIREO_OK);
    return result;
}
static vireo_result_t admit_hook(void *context,vireo_tcp_server_t *s,vireo_tcp_server_admit_budget_t const *b,
    vireo_connection_pool_lease_t *clients,size_t cap,vireo_tcp_server_tls_admit_info_t *r,vireo_tcp_server_tls_error_t *e) {
    fault_t *f=context; vireo_result_t result=vireo_tcp_server_tls_admit_batch(s,b,clients,cap,r,e);
    if(result==VIREO_OK && f->admission_io) { e->stage=VIREO_TCP_SERVER_TLS_QUEUE; return VIREO_RESULT_IO; }
    return result;
}
static vireo_async_service_tls_ops_t const ops={inspect_hook,pressure_hook,poll_hook,dispatch_hook,clients_hook,admit_hook};
static void model(fixture_t *f,fault_t *fault,vireo_result_t result) { service_with(f,&service_options,3,3,3,&ops,fault,result); }
static void error_models(void) {
    fixture_t f; setup(&f,1,true); reset_queue(&f); schedule_all(&f);
    fault_t fault={.pre=VIREO_RESULT_IO}; model(&f,&fault,VIREO_RESULT_IO);
    CHECK(fault.pressures==1 && !f.report.post_pressure_called && !f.report.poll_called); ++groups;
    fault=(fault_t){.poll_io=true,.post=VIREO_RESULT_BUSY}; model(&f,&fault,VIREO_RESULT_IO);
    CHECK(f.report.stage==VIREO_ASYNC_SERVICE_TLS_POLL && f.report.post_pressure_result==VIREO_RESULT_BUSY &&
        f.report.poll_error.stage==VIREO_TCP_SERVER_TLS_WAIT && !f.report.dispatch_called && fault.pressures==2); ++groups;
    fault=(fault_t){.partial_poll=true}; model(&f,&fault,VIREO_RESULT_IO);
    CHECK(f.report.poll.poll.selected_count==1 && !f.report.clients_called && f.report.clients.turn_count==0);
    restore_taken(&f); ++groups;
    schedule_all(&f); fault=(fault_t){.dispatch_io=true,.post=VIREO_RESULT_BUSY}; model(&f,&fault,VIREO_RESULT_IO);
    CHECK(f.report.stage==VIREO_ASYNC_SERVICE_TLS_DISPATCH && !f.report.clients_called &&
        f.report.poll.poll.selected_count==1 && f.report.post_pressure_result==VIREO_RESULT_BUSY);
    restore_taken(&f); ++groups;
    fault=(fault_t){.post=VIREO_RESULT_IO}; model(&f,&fault,VIREO_RESULT_IO);
    CHECK(f.report.stage==VIREO_ASYNC_SERVICE_TLS_POST_PRESSURE && f.report.clients_called && fault.pressures==2); ++groups;
    for(unsigned k=0;k<3;++k) {
        schedule_all(&f); fault=(fault_t){.listener_events=k==0?VIREO_EPOLL_EVENT_READ|VIREO_EPOLL_EVENT_ERROR:
            k==1?VIREO_EPOLL_EVENT_READ|VIREO_EPOLL_EVENT_HANGUP:VIREO_EPOLL_EVENT_WRITE};
        model(&f,&fault,k<2?VIREO_RESULT_IO:VIREO_RESULT_INTERNAL);
        CHECK(f.report.stage==VIREO_ASYNC_SERVICE_TLS_LISTENER_EVENT && !f.report.dispatch_called && !f.report.admission_called);
        restore_taken(&f); ++groups;
    }
    fault=(fault_t){.bad_count=true}; model(&f,&fault,VIREO_RESULT_INTERNAL);
    CHECK(!f.report.clients_called && f.report.stage==VIREO_ASYNC_SERVICE_TLS_POLL); /* 不恢复伪造数量。 */
    cleanup(&f); ++groups;

    setup(&f,1,true); fault=(fault_t){.stop_after_poll=true}; model(&f,&fault,VIREO_RESULT_CANCELLED);
    CHECK(f.report.stage==VIREO_ASYNC_SERVICE_TLS_DISPATCH && !f.report.clients_called && f.report.post_pressure_called);
    cleanup(&f); ++groups;
    setup_root(&f,UINT64_C(5000000000),3,32768,163840); pool_setup(&f,8); connect_peer(&f);
    fault=(fault_t){.stop_before_admit=true}; model(&f,&fault,VIREO_RESULT_CANCELLED);
    CHECK(f.report.admission_checked && f.report.stopped && !f.report.admission_called && f.report.post_pressure_called);
    cleanup(&f); ++groups;
    setup_root(&f,UINT64_C(5000000000),3,32768,163840); pool_setup(&f,8); connect_peer(&f);
    fault=(fault_t){.admission_io=true,.post=VIREO_RESULT_BUSY}; model(&f,&fault,VIREO_RESULT_IO);
    CHECK(f.report.admission.admission.admitted_count==1 && f.clients[0].pool_id &&
        f.report.stage==VIREO_ASYNC_SERVICE_TLS_ADMIT && f.report.post_pressure_result==VIREO_RESULT_BUSY);
    cleanup(&f); ++groups;
    setup_root(&f,UINT64_C(5000000000),3,32768,163840); pool_setup(&f,8); connect_peer(&f);
    fault=(fault_t){.admission_check_io=true}; model(&f,&fault,VIREO_RESULT_IO);
    CHECK(f.report.stage==VIREO_ASYNC_SERVICE_TLS_CHECK_ADMISSION && !f.report.admission_called && f.report.post_pressure_called);
    cleanup(&f); ++groups;
    setup(&f,1,true); fault=(fault_t){.entry_io=true}; model(&f,&fault,VIREO_RESULT_IO);
    CHECK(f.report.entry_checked && !f.report.pre_pressure_called && !f.report.post_pressure_called);
    cleanup(&f); ++groups;
}
static void enqueued_error_model(void) {
    fixture_t f; setup(&f,1,true); submit_one(&f); publish_all(&f); schedule_all(&f);
    fault_t fault={.response_io=true}; model(&f,&fault,VIREO_RESULT_IO);
    vireo_inflight_completion_consume_report_t c=last_consume(&f);
    CHECK(f.remaining_completion && c.record_consumed && f.report.dispatch.last_response_report.response.enqueued &&
        f.report.dispatch.enqueued_responses==1 && f.report.dispatch.enqueued_bytes==35 && !f.report.clients_called);
    refresh(&f); EXPECT(vireo_completion_destroy(&f.remaining_completion),VIREO_OK);
    restore_taken(&f); send_queued(&f);
    uint8_t wire[35],body[]={42,0,255}; read_exact(&f,wire,35); wire_is(wire,35,body,3,VIREO_STATUS_OK,101);
    size_t got=0; uint8_t byte; ERR_clear_error(); int rc=SSL_read_ex(f.ssls[0],&byte,1,&got);
    CHECK(rc!=1 && SSL_get_error(f.ssls[0],rc)==SSL_ERROR_WANT_READ && got==0);
    CHECK(f.delivered==1 && f.submitted==1); cleanup(&f); ++groups;
}
static void validation(void) {
    fixture_t f; setup(&f,1,true); reset_queue(&f); schedule_all(&f);
    memset(f.ready,0xA5,sizeof f.ready); memset(f.turns,0x5A,sizeof f.turns);
    unsigned char ready_before[sizeof f.ready],turns_before[sizeof f.turns];
    memcpy(ready_before,f.ready,sizeof f.ready); memcpy(turns_before,f.turns,sizeof f.turns);
    for(unsigned k=0;k<15;++k) {
        vireo_async_service_tls_options_t o=service_options; vireo_result_t result=VIREO_RESULT_INVALID_ARGUMENT;
        size_t ready_cap=3,turn_cap=3,admit_cap=3;
        if(k==0) o.round.timeout_ms=-1;
        if(k==1) o.round.max_clients=0;
        if(k==2) o.round.close_max_bytes=0;
        if(k==3) o.admit.max_accepts=0;
        if(k==4) o.admit.max_accept_syscalls=0;
        if(k==5) o.max_completion_items=0;
        if(k==6) o.max_response_batch_bytes=0;
        if(k==7) ready_cap=0;
        if(k==8) turn_cap=0;
        if(k==9) admit_cap=0;
        if(k==10) { o.round.close_max_bytes=4095; result=VIREO_RESULT_RANGE; }
        if(k==11) { o.max_response_batch_bytes=127; result=VIREO_RESULT_RANGE; }
        if(k==12) { o.max_response_frame_bytes=129; o.max_response_batch_bytes=129; result=VIREO_RESULT_RANGE; }
        if(k==13) { o.max_completion_items=65537; result=VIREO_RESULT_RANGE; }
        if(k==14) { ready_cap=65536; result=VIREO_RESULT_RANGE; }
        service_with(&f,&o,ready_cap,turn_cap,admit_cap,NULL,NULL,result);
        CHECK(!f.report.pre_pressure_called && !f.report.poll_called && !f.report.post_pressure_called);
        CHECK(!memcmp(ready_before,f.ready,sizeof f.ready) && !memcmp(turns_before,f.turns,sizeof f.turns));
    }
    for(unsigned k=0;k<7;++k) {
        vireo_async_service_tls_ops_t broken=ops; fault_t fault={0};
        if(k==0) broken.inspect=NULL;
        if(k==1) broken.pressure=NULL;
        if(k==2) broken.poll=NULL;
        if(k==3) broken.dispatch=NULL;
        if(k==4) broken.clients=NULL;
        if(k==5) broken.admit=NULL;
        if(k==6) { broken=ops; }
        if(k<6) service_with(&f,&service_options,3,3,3,&broken,&fault,VIREO_RESULT_INVALID_ARGUMENT);
        else {
            vireo_task_t *nonempty=(vireo_task_t *)&fault;
            vireo_connection_pool_lease_t admitted[3]={{0}}; uint8_t scratch[128];
            vireo_async_service_tls_workspace_t w={f.ready,3,f.turns,3,admitted,3,scratch,sizeof scratch};
            EXPECT(vireo_async_service_tls_once(f.server,f.store,f.pool,f.worker.notifier,f.worker.queue,f.handle,
                &service_options,&w,configure,&f,resolve,&f,&nonempty,&f.remaining_completion,&f.report),VIREO_RESULT_INVALID_ARGUMENT);
            CHECK(nonempty==(vireo_task_t *)&fault);
            admitted[0]=f.clients[0];
            EXPECT(vireo_async_service_tls_once(f.server,f.store,f.pool,f.worker.notifier,f.worker.queue,f.handle,
                &service_options,&w,configure,&f,resolve,&f,&f.remaining,&f.remaining_completion,&f.report),VIREO_RESULT_INVALID_ARGUMENT);
        }
        CHECK(fault.pressures==0 && fault.inspections==0);
    }
    vireo_async_round_tls_report_t r;
    EXPECT(vireo_async_round_tls_process_ready(f.server,f.store,f.pool,4096,configure,&f,f.ready,4,f.turns,3,&f.remaining,&r),VIREO_RESULT_RANGE);
    EXPECT(vireo_async_round_tls_process_ready(f.server,f.store,f.pool,4096,configure,&f,f.ready,0,f.turns,3,&f.remaining,&r),VIREO_OK);
    CHECK(r.turn_count==0 && !r.poll_called && !memcmp(turns_before,f.turns,sizeof f.turns));
    uint8_t scratch[128]; vireo_completion_response_dispatch_tls_report_t d;
    for(unsigned k=0;k<7;++k) {
        size_t items=3,frame=128,batch=256,cap=128; vireo_event_loop_handle_t h=f.handle;
        vireo_result_t result=VIREO_RESULT_RANGE;
        if(k==0) items=65537;
        if(k==1) frame=31;
        if(k==2) batch=127;
        if(k==3) cap=127;
        if(k==4) { h=(vireo_event_loop_handle_t){0}; result=VIREO_RESULT_NOT_FOUND; }
        if(k==5) { h.token=0; result=VIREO_RESULT_INVALID_ARGUMENT; }
        if(k==6) { items=0; result=VIREO_RESULT_INVALID_ARGUMENT; }
        EXPECT(vireo_completion_response_dispatch_tls_ready(f.server,h,f.worker.notifier,f.store,f.worker.queue,
            items,frame,batch,scratch,cap,resolve,&f,&f.remaining_completion,&d),result);
        CHECK(!d.dispatch_called);
    }
    for(unsigned k=0;k<3;++k) {
        vireo_completion_response_dispatch_tls_ops_t broken=dispatch_ops; fault_t fault={0};
        if(k==0) broken.inspect=NULL;
        if(k==1) broken.dispatch=NULL;
        if(k==2) broken.response=NULL;
        EXPECT(vireo_completion_response_dispatch_tls_with_ops(f.server,f.handle,f.worker.notifier,f.store,f.worker.queue,
            3,128,256,scratch,sizeof scratch,resolve,&f,&f.remaining_completion,&d,&broken,&fault),VIREO_RESULT_INVALID_ARGUMENT);
    }
    EXPECT(vireo_completion_response_dispatch_tls_ready(f.server,f.handle,f.worker.notifier,f.store,f.worker.queue,
        3,128,256,scratch,sizeof scratch,resolve,&f,&f.remaining_completion,&d),VIREO_OK);
    CHECK(d.effective_max_items==2 && d.reserved_frame_bytes==256 && d.resolve_calls==0);
    EXPECT(vireo_tcp_server_request_stop(f.server,NULL),VIREO_OK); service(&f,VIREO_RESULT_CANCELLED);
    CHECK(f.report.stopped && f.report.entry_checked && !f.report.pre_pressure_called && !f.report.poll_called && !f.report.post_pressure_called);
    cleanup(&f); ++groups;

    fixture_t raw={.peers={-1,-1,-1}}; vireo_tcp_server_options_t const so={3,8,1048576,32768};
    EXPECT(vireo_tcp_server_create_with_auxiliary_capacity(&so,1,&raw.server,NULL),VIREO_OK);
    vireo_inflight_store_options_t const io={8,65536}; EXPECT(vireo_inflight_store_create(&io,&raw.store),VIREO_OK);
    pool_setup(&raw,8); service(&raw,VIREO_RESULT_BUSY); CHECK(!raw.report.pre_pressure_called);
    EXPECT(vireo_completion_response_dispatch_tls_ready(raw.server,raw.handle,raw.worker.notifier,raw.store,raw.worker.queue,
        3,128,256,scratch,sizeof scratch,resolve,&raw,&raw.remaining_completion,&d),VIREO_RESULT_BUSY);
    CHECK(!d.dispatch_called); cleanup(&raw); ++groups;
}
int main(void) {
    CHECK(signal(SIGPIPE,SIG_IGN)!=SIG_ERR); int old;
    CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,&old)==0); size_t before=fds();
    real_service_chain(); fairness_and_suffix(); pressure_and_backlog(); response_capacity_and_resolve();
    stale_generation(); deadlines_and_close(); error_models(); enqueued_error_model(); validation();
    CHECK(fds()==before); printf("TLS async service: %u groups passed, fd %zu -> %zu\n",groups,before,fds()); return 0;
}
