/* TLS异步单客户真实链与own故障边界。 */
#define _GNU_SOURCE
#include "async_client_drive_tls_internal.h"
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
} worker_t;
/** Reactor唯一拥有的真实TLS与异步资源。 */
typedef struct fixture {
    vireo_tcp_server_t *server; /**< TLS根owner。 */
    vireo_connection_pool_lease_t client; /**< 当前完整租约。 */
    int peer; /**< 对端fd owner，-1为空。 */
    SSL *ssl; /**< 可信TLS1.3 peer owner。 */
    vireo_inflight_store_t *store; /**< 8条在途表owner。 */
    vireo_task_queue_t *tasks; /**< 固定任务队列owner。 */
    vireo_thread_pool_t *pool; /**< 单worker池owner。 */
    worker_t worker; /**< 稳定长借context，join后销毁。 */
    bool released; /**< 预热worker已释放。 */
    vireo_event_loop_handle_t handle; /**< notifier完整注册值。 */
    vireo_async_request_pending_t pending; /**< 每客户唯一防重gate。 */
    vireo_task_t *remaining; /**< 未移交task owner。 */
    vireo_task_metadata_t accepted[8]; /**< 真实移交身份，清理时核对。 */
    unsigned submitted; /**< 实际数据task移交数量。 */
    unsigned delivered; /**< 完成回调次数。 */
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
    EXPECT(vireo_tcp_server_client_tls_borrow(f->server,f->client,&t,NULL),VIREO_OK); return t;
}
static vireo_tcp_server_client_info_t state(fixture_t *f) {
    vireo_tcp_server_client_info_t i;
    EXPECT(vireo_tcp_server_client_inspect(f->server,f->client,&i),VIREO_OK); return i;
}
static void refresh(fixture_t *f) {
    vireo_tcp_server_tls_flow_info_t i;
    EXPECT(vireo_tcp_server_client_tls_flow_refresh(f->server,f->client,&i,NULL),VIREO_OK);
}
static void setup(fixture_t *f,bool establish) {
    *f=(fixture_t){.peer=-1};
    vireo_tls_context_options_t const co={fixture_leaf,sizeof fixture_leaf-1,fixture_key,sizeof fixture_key-1,4096};
    vireo_tls_context_t *context=NULL;
    EXPECT(vireo_tls_context_create_server(&co,&context,NULL),VIREO_OK);
    vireo_tcp_server_options_t const so={1,4,1048576,32768};
    vireo_tcp_server_tls_options_t const to={{4096,4096,40960,128,127,4096,0,4096},
        4096,UINT64_C(5000000000),163840};
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
    f->peer=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0); CHECK(f->peer>=0);
    CHECK(connect(f->peer,(struct sockaddr *)&address,sizeof address)==0);
    int flags=fcntl(f->peer,F_GETFL); CHECK(flags>=0 && fcntl(f->peer,F_SETFL,flags|O_NONBLOCK)==0);
    vireo_tcp_server_admit_budget_t const ab={1,2}; vireo_tcp_server_tls_admit_info_t ai;
    EXPECT(vireo_tcp_server_tls_admit_batch(f->server,&ab,&f->client,1,&ai,NULL),VIREO_OK); CHECK(ai.admission.admitted_count==1);
    vireo_inflight_store_options_t const io={8,65536};
    EXPECT(vireo_inflight_store_create(&io,&f->store),VIREO_OK);
    if(!establish) return;
    SSL_CTX *c=SSL_CTX_new(TLS_client_method()); CHECK(c);
    CHECK(SSL_CTX_set_min_proto_version(c,TLS1_3_VERSION)==1 && SSL_CTX_set_max_proto_version(c,TLS1_3_VERSION)==1);
    SSL_CTX_set_verify(c,SSL_VERIFY_PEER,NULL);
    BIO *b=BIO_new_mem_buf(fixture_root,(int)sizeof fixture_root-1); CHECK(b);
    X509 *cert=PEM_read_bio_X509(b,NULL,NULL,NULL); CHECK(cert);
    CHECK(X509_STORE_add_cert(SSL_CTX_get_cert_store(c),cert)==1); X509_free(cert); CHECK(BIO_free(b)==1);
    f->ssl=SSL_new(c); CHECK(f->ssl); SSL_CTX_free(c);
    CHECK(SSL_set1_host(f->ssl,"vireo-034-test.invalid")==1);
    X509_VERIFY_PARAM_set_time(SSL_get0_param(f->ssl),(time_t)1800000000);
    b=BIO_new_socket(f->peer,BIO_NOCLOSE); CHECK(b); SSL_set_bio(f->ssl,b,b); SSL_set_connect_state(f->ssl);
    bool client_done=false,server_done=false;
    for(unsigned k=0;k<1024;++k) {
        if(!client_done) {
            ERR_clear_error(); int rc=SSL_do_handshake(f->ssl); int why=rc==1?SSL_ERROR_NONE:SSL_get_error(f->ssl,rc);
            CHECK(why==SSL_ERROR_NONE || why==SSL_ERROR_WANT_READ || why==SSL_ERROR_WANT_WRITE); client_done=rc==1;
        }
        vireo_tcp_server_ready_client_t ready[1]; vireo_tcp_server_tls_poll_report_t p;
        EXPECT(vireo_tcp_server_tls_poll_ready_once(f->server,2,1,ready,1,&p,NULL),VIREO_OK);
        if(p.poll.selected_count && !server_done) {
            vireo_tcp_server_tls_handshake_info_t h;
            EXPECT(vireo_tcp_server_client_tls_handshake_step(f->server,ready[0].client,&h,NULL),VIREO_OK);
            server_done=h.application_ready;
        }
        if(client_done && server_done) break;
    }
    CHECK(client_done && server_done && SSL_version(f->ssl)==TLS1_3_VERSION && SSL_get_verify_result(f->ssl)==X509_V_OK);
}
/** 经公开server等待真实网络；不拿对端POLLOUT冒充服务端可读。 */
static void wait_network(fixture_t *f) {
    vireo_tcp_server_ready_client_t ready[1]; vireo_tcp_server_tls_poll_report_t report;
    EXPECT(vireo_tcp_server_tls_poll_ready_once(f->server,5,1,ready,1,&report,NULL),VIREO_OK);
}
static void read_exact(fixture_t *f,uint8_t *bytes,size_t size) {
    size_t have=0;
    for(unsigned k=0;k<1024 && have<size;++k) {
        size_t n=0; ERR_clear_error(); int rc=SSL_read_ex(f->ssl,bytes+have,size-have,&n);
        int why=rc==1?SSL_ERROR_NONE:SSL_get_error(f->ssl,rc);
        if(rc==1) { CHECK(n>0); have+=n; }
        else {
            CHECK(why==SSL_ERROR_WANT_READ || why==SSL_ERROR_WANT_WRITE);
            struct pollfd fd={f->peer,why==SSL_ERROR_WANT_READ?POLLIN:POLLOUT,0}; CHECK(poll(&fd,1,2)>=0);
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
    CHECK(!remaining && p.completion_transferred); return VIREO_OK;
}
static void pool_setup(fixture_t *f,size_t capacity) {
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
    if(f->pending.frame_bytes) { vireo_async_request_head_report_t p;
        EXPECT(vireo_async_request_resume_consume(f->server,&f->pending,&p),VIREO_OK); }
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
    if(f->client.pool_id) EXPECT(vireo_tcp_server_release_client(f->server,&f->client,NULL),VIREO_OK);
    SSL_free(f->ssl); CHECK(close(f->peer)==0); EXPECT(vireo_tcp_server_destroy(&f->server,NULL),VIREO_OK);
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
    size_t sent=0; ERR_clear_error(); CHECK(SSL_write_ex(f->ssl,p,n,&sent)==1 && sent==n);
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
static vireo_async_client_drive_tls_report_t drive(fixture_t *f,vireo_result_t result) {
    vireo_async_client_drive_tls_report_t p; memset(&p,0xa5,sizeof p);
    EXPECT(vireo_async_client_drive_tls_once(f->server,f->client,f->store,f->pool,&options,&budget,NULL,&f->pending,&f->remaining,&p),result);
    record(f,p); return p;
}
static vireo_result_t deliver(void *context,vireo_completion_t const *c,vireo_inflight_completion_match_t match) {
    fixture_t *f=context; ++f->delivered; uint8_t work[128]; vireo_completion_response_tls_report_t p;
    CHECK(match.metadata.route.request_sequence==101 && match.metadata.operation==9 && match.metadata.deadline_ns==UINT64_MAX);
    EXPECT(vireo_completion_response_tls_enqueue(f->server,c,match,descriptor,128,work,sizeof work,&p),VIREO_OK);
    CHECK(p.response.enqueued); return VIREO_OK;
}
static void real_chain(void) {
    fixture_t f; setup(&f,true); pool_setup(&f,4); uint8_t request[35]; make_request(request,101); peer_write(&f,request,35);
    bool transferred=false;
    for(unsigned k=0;k<1024;++k) {
        vireo_async_client_drive_tls_report_t p=drive(&f,VIREO_OK);
        CHECK(p.pre_refresh_called && p.final_refresh_called && p.final_inspect_called && !p.pending_retained);
        if(p.head_called) {
            CHECK(p.receive_called && p.receive_reported && p.request_header_available && p.request_header.sequence==101);
            CHECK(p.head_report.submit_report.task_transferred && p.head_report.consume_result==VIREO_OK && !p.needs_reschedule);
            transferred=true; break;
        }
        wait_network(&f);
    }
    CHECK(transferred && !f.remaining && f.pending.frame_bytes==0);
    release_worker(&f); bool finished=false; vireo_completion_t *remaining=NULL;
    for(unsigned k=0;k<1024;++k) {
        wait_network(&f); vireo_notifier_server_dispatch_report_t p;
        EXPECT(vireo_notifier_server_dispatch_ready(f.server,f.handle,f.worker.notifier,f.store,f.worker.queue,1,
            deliver,&f,&remaining,&p),VIREO_OK); CHECK(!remaining);
        if(p.dispatch_report.drain_report.finished==1) { CHECK(p.ready_taken); finished=true; break; }
    }
    CHECK(finished && f.delivered==1);
    vireo_async_client_drive_tls_report_t p=drive(&f,VIREO_OK);
    CHECK(p.send_called && p.send_reported && p.send.bytes==35 && !p.head_called);
    uint8_t response[35],body[]={42,0,255}; read_exact(&f,response,35); wire_is(response,35,body,3,VIREO_STATUS_OK);
    CHECK(f.submitted==1); cleanup(&f); ++groups;
}
static void fairness_and_partial(void) {
    fixture_t f; setup(&f,true); pool_setup(&f,4); uint8_t req[71]; make_request(req,101); make_request(req+35,102); req[70]=0;
    peer_write(&f,req,71); cache_input(&f,71);
    vireo_async_client_drive_tls_report_t p=drive(&f,VIREO_OK);
    CHECK(p.request_header.sequence==101 && p.needs_reschedule && f.submitted==1 && state(&f).connection_info.read_buffer.readable_size==36);
    p=drive(&f,VIREO_OK); CHECK(p.request_header.sequence==102 && p.needs_reschedule && f.submitted==2);
    CHECK(state(&f).connection_info.read_buffer.readable_size==1);
    p=drive(&f,VIREO_OK); CHECK(!p.head_called && !p.needs_reschedule && f.submitted==2);
    cleanup(&f); ++groups;
    setup(&f,true); pool_setup(&f,4); make_request(req,101); peer_write(&f,req,17); cache_input(&f,17);
    p=drive(&f,VIREO_OK); CHECK(!p.head_called && !p.request_header_available);
    peer_write(&f,req+17,18); cache_input(&f,35); p=drive(&f,VIREO_OK);
    CHECK(p.head_called && f.submitted==1 && !p.needs_reschedule); cleanup(&f); ++groups;
}
static void full_queue(void) {
    fixture_t f; setup(&f,true); pool_setup(&f,1); uint8_t req[70]; make_request(req,101); make_request(req+35,102);
    peer_write(&f,req,70); cache_input(&f,70); vireo_async_client_drive_tls_report_t p=drive(&f,VIREO_OK);
    CHECK(p.needs_reschedule && f.submitted==1);
    p=drive(&f,VIREO_RESULT_BUSY);
    CHECK(p.stage==VIREO_ASYNC_CLIENT_DRIVE_TLS_SUBMIT && p.head_called && !p.head_report.submit_report.task_transferred);
    CHECK(!p.head_report.consume_called && !p.pending_retained && p.final_refresh_called && f.remaining);
    CHECK(state(&f).connection_info.read_buffer.readable_size==35);
    vireo_inflight_store_info_t si; EXPECT(vireo_inflight_store_inspect(f.store,&si),VIREO_OK); CHECK(si.count==1);
    cleanup(&f); ++groups;
}
/** 仅本层公开边界模型，真实TLS资格/资源仍由public核验。 */
typedef struct fault {
    unsigned syncs; /**< pre/final尝试次数。 */
    unsigned flows; /**< pure flow尝试次数。 */
    unsigned receives; /**< native receive边界次数。 */
    unsigned sends; /**< native send边界次数。 */
    unsigned heads; /**< head边界次数。 */
    unsigned inspections; /**< 初始/最终IO观察次数。 */
    unsigned fail_sync; /**< 1 pre或2 final返回模型IO。 */
    bool consume_busy; /**< 实际copy移交后保留消费义务的head模型。 */
    bool receive_io; /**< receive原生前拒绝，保持报告。 */
    bool send_io; /**< send原生前拒绝，保持报告。 */
    bool final_inspect_io; /**< 最后IO观察模型失败。 */
    bool bad_report; /**< 模拟预算违约报告，不制造真实进度。 */
    bool missing_report; /**< 模型OK却未发布报告。 */
    bool flow_io; /**< 纯flow原生前模型IO。 */
    bool mock_io; /**< 零字节WANT模型；不称真实交叉WANT。 */
    bool release_retry; /**< 模型write重试成功释放，随后允许read。 */
    bool retry_range; /**< 只读IO观察模型锁定长度超过本次预算。 */
    vireo_tls_io_operation_t priority; /**< pre及tail模型锁定原操作。 */
    char order[8]; /**< 模型IO执行顺序，非网络syscall日志。 */
    unsigned order_size; /**< 已记录次数，最多2。 */
} fault_t;
static vireo_result_t inspect_hook(void *c,vireo_tls_connection_t const *t,vireo_tls_io_info_t *i,vireo_tls_connection_error_t *e) {
    fault_t *f=c; ++f->inspections;
    if(f->final_inspect_io && f->inspections==2) return VIREO_RESULT_IO;
    vireo_result_t r=vireo_tls_connection_io_inspect(t,i,e);
    if(r==VIREO_OK && f->retry_range) i->write_retry_bytes=4097;
    return r;
}
static vireo_result_t flow_hook(void *c,vireo_tls_connection_t *t,vireo_tls_io_flow_t *i,vireo_tls_connection_error_t *e) {
    fault_t *f=c; ++f->flows; if(f->flow_io) return VIREO_RESULT_IO;
    vireo_result_t r=vireo_tls_connection_flow_refresh(t,i,e);
    if(r==VIREO_OK && f->mock_io) {
        vireo_tls_io_operation_t priority=f->release_retry?VIREO_TLS_IO_OPERATION_NONE:f->priority;
        *i=(vireo_tls_io_flow_t){.application_read_enabled=priority==VIREO_TLS_IO_OPERATION_NONE,
            .want_read=priority!=VIREO_TLS_IO_OPERATION_READ,.want_write=priority!=VIREO_TLS_IO_OPERATION_WRITE,.priority_retry=priority};
    }
    return r;
}
static vireo_result_t receive_hook(void *c,vireo_tls_connection_t *t,vireo_tls_io_budget_t const *b,vireo_tls_io_progress_t *p,vireo_tls_connection_error_t *e) {
    fault_t *f=c; ++f->receives; CHECK(f->receives==1); f->order[f->order_size++]='R';
    CHECK(b->max_bytes==4096 && b->max_native_calls==8);
    if(f->receive_io) return VIREO_RESULT_IO;
    if(f->missing_report) return VIREO_OK;
    if(f->bad_report) { *p=(vireo_tls_io_progress_t){.native_calls=b->max_native_calls+1}; return VIREO_OK; }
    if(f->mock_io) { *p=(vireo_tls_io_progress_t){.native_calls=1,.stop_reason=VIREO_TLS_IO_STOP_WOULD_BLOCK,
        .wait=f->priority==VIREO_TLS_IO_OPERATION_READ?VIREO_TLS_IO_WAIT_WRITE:VIREO_TLS_IO_WAIT_READ}; return VIREO_OK; }
    return vireo_tls_connection_receive(t,b,p,e);
}
static vireo_result_t send_hook(void *c,vireo_tls_connection_t *t,vireo_tls_io_budget_t const *b,vireo_tls_io_progress_t *p,vireo_tls_connection_error_t *e) {
    fault_t *f=c; ++f->sends; CHECK(f->sends==1); f->order[f->order_size++]='W';
    CHECK(b->max_bytes==4096 && b->max_native_calls==8);
    if(f->send_io) return VIREO_RESULT_IO;
    if(f->mock_io) { *p=(vireo_tls_io_progress_t){.native_calls=1,.stop_reason=VIREO_TLS_IO_STOP_WOULD_BLOCK,
        .wait=VIREO_TLS_IO_WAIT_READ}; return VIREO_OK; }
    return vireo_tls_connection_send(t,b,p,e);
}
static vireo_result_t frames_hook(void *c,vireo_tcp_server_t const *s,vireo_connection_pool_lease_t l,
    vireo_connection_frame_options_t const *o,vireo_connection_frame_budget_t const *b,vireo_connection_frame_view_t *v,
    size_t n,vireo_connection_frame_info_t *i,vireo_tcp_server_client_error_t *e) {
    (void)c; CHECK(b->max_messages==1 && n==1); return vireo_tcp_server_client_frames_peek(s,l,o,b,v,n,i,e);
}
static vireo_result_t head_hook(void *c,vireo_tcp_server_t *s,vireo_connection_pool_lease_t l,
    vireo_inflight_store_t *store,vireo_thread_pool_t *pool,size_t cap,size_t allocation,size_t limit,
    uint32_t operation,uint64_t deadline,vireo_task_cancel_t *cancel,vireo_async_request_pending_t *pending,
    vireo_task_t **owner,vireo_async_request_head_report_t *p) {
    fault_t *f=c; ++f->heads; CHECK(f->heads==1);
    if(!f->consume_busy) return vireo_async_request_submit_read_head(s,l,store,pool,cap,allocation,limit,operation,deadline,cancel,pending,owner,p);
    /* own head模型：真实公开copy/transfer，consume拒绝不修改源；没有别模块private。 */
    vireo_connection_frame_options_t const fo={VIREO_CONNECTION_FRAME_REQUEST,cap};
    vireo_connection_frame_budget_t const fb={1,cap}; vireo_connection_frame_view_t view;
    vireo_connection_frame_info_t fi;
    EXPECT(vireo_tcp_server_client_frames_peek(s,l,&fo,&fb,&view,1,&fi,NULL),VIREO_OK); CHECK(fi.frame_count==1);
    uint8_t const *data=NULL; size_t n=0;
    EXPECT(vireo_tcp_server_client_read_peek(s,l,&data,&n,NULL),VIREO_OK); CHECK(n>=35);
    *p=(vireo_async_request_head_report_t){.stage=VIREO_ASYNC_REQUEST_HEAD_CONSUME,.frame_found=true,
        .frame_peek_called=true,.frame_info=fi,.frame_bytes=35,.read_peek_called=true,.submit_called=true};
    p->submit_result=vireo_async_request_copy_try_submit(s,l,store,pool,data,35,cap,allocation,limit,operation,deadline,cancel,owner,&p->submit_report);
    CHECK(p->submit_result==VIREO_OK && p->submit_report.task_transferred);
    *pending=(vireo_async_request_pending_t){p->submit_report.metadata,35};
    p->pending_committed=true; p->pending_retained=true; p->consume_called=true;
    p->consume_result=VIREO_RESULT_BUSY; p->pending_snapshot=*pending; return VIREO_RESULT_BUSY;
}
static vireo_result_t sync_hook(void *c,vireo_tcp_server_t *s,vireo_connection_pool_lease_t l,
    vireo_tcp_server_tls_flow_info_t *i,vireo_tcp_server_tls_application_error_t *e) {
    fault_t *f=c; ++f->syncs; CHECK(f->syncs<=2);
    if(f->syncs==f->fail_sync) {
        *e=(vireo_tcp_server_tls_application_error_t){.stage=VIREO_TCP_SERVER_TLS_APPLICATION_SYNC,
            .sync_stage=VIREO_TCP_SERVER_TLS_APPLICATION_SYNC,.sync_result=VIREO_RESULT_IO,.queue_result=VIREO_RESULT_INTERNAL};
        return VIREO_RESULT_IO; /* 模型同步拒绝，不声称真实epoll MOD故障。 */
    }
    vireo_result_t r=vireo_tcp_server_client_tls_flow_refresh(s,l,i,e);
    if(r==VIREO_OK && f->mock_io) i->flow=(vireo_tls_io_flow_t){.application_read_enabled=f->priority==VIREO_TLS_IO_OPERATION_NONE,
        .want_read=f->priority!=VIREO_TLS_IO_OPERATION_READ,.want_write=f->priority!=VIREO_TLS_IO_OPERATION_WRITE,.priority_retry=f->priority};
    return r;
}
static vireo_async_client_drive_tls_ops_t const ops={inspect_hook,flow_hook,receive_hook,send_hook,frames_hook,head_hook,sync_hook};
static vireo_async_client_drive_tls_report_t model(fixture_t *f,fault_t *fault,vireo_result_t result) {
    vireo_async_client_drive_tls_report_t p;
    EXPECT(vireo_async_client_drive_tls_with_ops(f->server,f->client,f->store,f->pool,&options,&budget,NULL,
        &f->pending,&f->remaining,&p,&ops,fault),result); record(f,p); return p;
}
static void want_order(void) {
    vireo_tls_io_operation_t priorities[]={VIREO_TLS_IO_OPERATION_WRITE,VIREO_TLS_IO_OPERATION_READ,VIREO_TLS_IO_OPERATION_NONE,VIREO_TLS_IO_OPERATION_WRITE};
    for(unsigned k=0;k<4;++k) {
        fixture_t f; setup(&f,true); pool_setup(&f,4);
        fault_t fault={.mock_io=true,.priority=priorities[k],.release_retry=k==0}; vireo_async_client_drive_tls_report_t p=model(&f,&fault,VIREO_OK);
        CHECK(!p.head_called);
        if(k!=3) CHECK(p.receive_reported && p.receive.native_calls==1 && fault.receives==1);
        else CHECK(!p.receive_called && fault.receives==0 && fault.sends==1 && fault.order_size==1 && fault.order[0]=='W');
        if(k==0) CHECK(fault.sends==1 && fault.order_size==2 && !memcmp(fault.order,"WR",2));
        if(k==1) CHECK(fault.sends==0 && fault.order_size==1 && fault.order[0]=='R');
        if(k==2) CHECK(fault.sends==1 && fault.order_size==2 && !memcmp(fault.order,"RW",2));
        CHECK(fault.syncs==2); cleanup(&f); ++groups;
    }
}
static void error_prefixes(void) {
    for(unsigned k=0;k<8;++k) {
        fixture_t f; setup(&f,true); pool_setup(&f,4); fault_t fault={0}; vireo_result_t expected=VIREO_RESULT_IO;
        if(k==0) fault.fail_sync=1;
        if(k==1) { fault.receive_io=true; fault.fail_sync=2; }
        if(k==2) { fault.mock_io=true; fault.priority=VIREO_TLS_IO_OPERATION_WRITE; fault.send_io=true; }
        if(k==3) fault.fail_sync=2;
        if(k==4) fault.final_inspect_io=true;
        if(k==5) { fault.bad_report=true; expected=VIREO_RESULT_INTERNAL; }
        if(k==6) { fault.missing_report=true; expected=VIREO_RESULT_INTERNAL; }
        if(k==7) fault.flow_io=true;
        vireo_async_client_drive_tls_report_t p=model(&f,&fault,expected);
        CHECK(p.pre_refresh_called && !p.head_called && !p.needs_reschedule);
        CHECK(p.final_refresh_called==(k!=0) && fault.syncs==(k==0?1U:2U));
        if(k==1) CHECK(p.stage==VIREO_ASYNC_CLIENT_DRIVE_TLS_RECEIVE && !p.receive_reported && p.receive.native_calls==0 &&
            p.final_refresh_result==VIREO_RESULT_IO && p.final_error.queue_result==VIREO_RESULT_INTERNAL);
        if(k==2) CHECK(p.stage==VIREO_ASYNC_CLIENT_DRIVE_TLS_SEND && !p.send_reported && !p.receive_called);
        if(k==3) CHECK(p.stage==VIREO_ASYNC_CLIENT_DRIVE_TLS_FINAL_REFRESH);
        if(k==4) CHECK(p.stage==VIREO_ASYNC_CLIENT_DRIVE_TLS_FINAL_INSPECT);
        if(k==5 || k==6) CHECK(!p.receive_reported && p.receive.native_calls==0);
        cleanup(&f); ++groups;
    }
}
static void committed_recovery(void) {
    for(unsigned k=0;k<2;++k) {
        fixture_t f; setup(&f,true); pool_setup(&f,4); uint8_t request[35]; make_request(request,101); peer_write(&f,request,35); cache_input(&f,35);
        fault_t fault={.consume_busy=k==0,.fail_sync=2};
        vireo_async_client_drive_tls_report_t p=model(&f,&fault,k==0?VIREO_RESULT_BUSY:VIREO_RESULT_IO);
        CHECK(p.head_called && p.head_report.submit_report.task_transferred && f.submitted==1 && fault.heads==1);
        CHECK(p.final_refresh_result==VIREO_RESULT_IO && !p.needs_reschedule && f.remaining==NULL);
        if(k==0) {
            CHECK(p.stage==VIREO_ASYNC_CLIENT_DRIVE_TLS_SUBMIT && p.pending_retained && f.pending.frame_bytes==35);
            CHECK(state(&f).connection_info.read_buffer.readable_size==35);
            p=drive(&f,VIREO_RESULT_BUSY); CHECK(p.stage==VIREO_ASYNC_CLIENT_DRIVE_TLS_CHECK_PENDING && !p.pre_refresh_called && !p.head_called);
            vireo_async_request_head_report_t resume;
            EXPECT(vireo_async_request_resume_consume(f.server,&f.pending,&resume),VIREO_OK);
            CHECK(!resume.submit_called && resume.consume_called && f.pending.frame_bytes==0);
        } else CHECK(p.stage==VIREO_ASYNC_CLIENT_DRIVE_TLS_FINAL_REFRESH && f.pending.frame_bytes==0);
        refresh(&f); p=drive(&f,VIREO_OK); CHECK(!p.head_called && f.submitted==1);
        cleanup(&f); ++groups;
    }
}
static void pressure_and_eof(void) {
    for(unsigned k=0;k<2;++k) {
        fixture_t f; setup(&f,true); pool_setup(&f,4); uint8_t bytes[4096]={0}; make_request(bytes,101);
        size_t n=k==0?sizeof bytes:35; peer_write(&f,bytes,n); cache_input(&f,n);
        if(k==1) EXPECT(vireo_tcp_server_client_write_enqueue(f.server,f.client,bytes,sizeof bytes,NULL),VIREO_OK);
        vireo_async_client_drive_tls_report_t p=drive(&f,VIREO_OK);
        CHECK(!p.receive_called && p.head_called && f.submitted==1 && p.pre_flow.flow.application_read_enabled==false);
        if(k==0) CHECK(p.pre_flow.flow.read_pressure && p.needs_reschedule);
        else { CHECK(p.pre_flow.flow.write_pressure && p.send_called && p.send.bytes==4096);
            uint8_t wire[4096]; read_exact(&f,wire,sizeof wire); CHECK(!memcmp(bytes,wire,sizeof wire)); }
        cleanup(&f); ++groups;
    }
    for(unsigned k=0;k<2;++k) {
        fixture_t f; setup(&f,true); pool_setup(&f,4); uint8_t bytes[35]; make_request(bytes,101);
        size_t n=k==0?35:17; peer_write(&f,bytes,n); cache_input(&f,n);
        ERR_clear_error(); int rc=SSL_shutdown(f.ssl); CHECK(rc==0 || rc==1); bool eof=false;
        for(unsigned j=0;j<1024;++j) {
            vireo_tls_io_progress_t p; EXPECT(vireo_tls_connection_receive(tls(&f),&io_budget,&p,NULL),VIREO_OK);
            vireo_tls_io_info_t io; EXPECT(vireo_tls_connection_io_inspect(tls(&f),&io,NULL),VIREO_OK);
            if(io.read_eof) { eof=true; break; } wait_network(&f);
        }
        CHECK(eof); vireo_async_client_drive_tls_report_t p=drive(&f,k==0?VIREO_OK:VIREO_RESULT_PROTOCOL);
        CHECK(!p.receive_called && p.frame_peek_called && p.head_called==(k==0));
        if(k==0) { p=drive(&f,VIREO_OK); CHECK(!p.head_called); }
        cleanup(&f); ++groups;
    }
}
static void gates_and_failed(void) {
    fixture_t f; setup(&f,false); pool_setup(&f,4);
    vireo_async_client_drive_tls_report_t p=drive(&f,VIREO_RESULT_BUSY);
    CHECK(p.stage==VIREO_ASYNC_CLIENT_DRIVE_TLS_CHECK_CLIENT && !p.pre_refresh_called); cleanup(&f); ++groups;
    setup(&f,true); pool_setup(&f,4);
    vireo_tcp_server_tls_close_request_info_t closing;
    EXPECT(vireo_tcp_server_client_tls_close_request(f.server,f.client,UINT64_C(1000000000),&closing,NULL),VIREO_OK);
    p=drive(&f,VIREO_RESULT_BUSY); CHECK(!p.pre_refresh_called); cleanup(&f); ++groups;
    setup(&f,true); pool_setup(&f,4); EXPECT(vireo_tcp_server_request_stop(f.server,NULL),VIREO_OK);
    p=drive(&f,VIREO_RESULT_CANCELLED); CHECK(p.stage==VIREO_ASYNC_CLIENT_DRIVE_TLS_CHECK_SERVER && !p.pre_refresh_called); cleanup(&f); ++groups;
    setup(&f,true); pool_setup(&f,4); vireo_connection_pool_lease_t stale=f.client;
    EXPECT(vireo_tcp_server_release_client(f.server,&f.client,NULL),VIREO_OK);
    EXPECT(vireo_async_client_drive_tls_once(f.server,stale,f.store,f.pool,&options,&budget,NULL,&f.pending,&f.remaining,&p),VIREO_RESULT_NOT_FOUND);
    CHECK(!p.pre_refresh_called);
    struct sockaddr_in address; socklen_t n=sizeof address;
    CHECK(getpeername(f.peer,(struct sockaddr *)&address,&n)==0);
    SSL_free(f.ssl); f.ssl=NULL; CHECK(close(f.peer)==0);
    f.peer=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0); CHECK(f.peer>=0);
    CHECK(connect(f.peer,(struct sockaddr *)&address,sizeof address)==0);
    vireo_tcp_server_admit_budget_t const ab={1,2}; vireo_tcp_server_tls_admit_info_t ai;
    EXPECT(vireo_tcp_server_tls_admit_batch(f.server,&ab,&f.client,1,&ai,NULL),VIREO_OK);
    CHECK(f.client.slot_index==stale.slot_index && f.client.generation!=stale.generation);
    EXPECT(vireo_async_client_drive_tls_once(f.server,stale,f.store,f.pool,&options,&budget,NULL,&f.pending,&f.remaining,&p),VIREO_RESULT_NOT_FOUND);
    CHECK(!p.pre_refresh_called); cleanup(&f); ++groups;
    setup(&f,true); pool_setup(&f,4); CHECK(shutdown(f.peer,SHUT_WR)==0); bool failed=false;
    for(unsigned k=0;k<1024;++k) {
        vireo_tls_io_progress_t progress; errno=EDOM;
        vireo_result_t result=vireo_tls_connection_receive(tls(&f),&io_budget,&progress,NULL); CHECK(errno==EDOM);
        if(result==VIREO_RESULT_PROTOCOL) { failed=true; break; } CHECK(result==VIREO_OK); wait_network(&f);
    }
    CHECK(failed); p=drive(&f,VIREO_RESULT_PROTOCOL);
    CHECK(p.receive_called && p.receive_reported && p.receive.native_calls==0 && !p.frame_peek_called && !p.head_called && p.final_refresh_called);
    CHECK(p.final_flow.interests==0); cleanup(&f); ++groups;
}
static void arguments_and_budgets(void) {
    fixture_t f; setup(&f,true); pool_setup(&f,4); vireo_async_client_drive_tls_report_t p;
    EXPECT(vireo_async_client_drive_tls_once(NULL,f.client,f.store,f.pool,&options,&budget,NULL,&f.pending,&f.remaining,&p),VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(!p.pre_refresh_called && !p.head_called);
    EXPECT(vireo_async_client_drive_tls_once(f.server,f.client,f.store,f.pool,&options,&budget,NULL,&f.pending,&f.remaining,NULL),VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_async_client_drive_tls_with_ops(f.server,f.client,f.store,f.pool,&options,&budget,NULL,&f.pending,&f.remaining,&p,NULL,NULL),VIREO_RESULT_INVALID_ARGUMENT);
    for(unsigned k=0;k<7;++k) {
        vireo_async_client_drive_tls_ops_t bad=ops;
        switch(k) { case 0: bad.io_inspect=NULL; break; case 1: bad.flow=NULL; break; case 2: bad.receive=NULL; break;
        case 3: bad.send=NULL; break; case 4: bad.frames=NULL; break; case 5: bad.head=NULL; break; default: bad.sync=NULL; break; }
        EXPECT(vireo_async_client_drive_tls_with_ops(f.server,f.client,f.store,f.pool,&options,&budget,NULL,&f.pending,&f.remaining,&p,&bad,NULL),VIREO_RESULT_INVALID_ARGUMENT);
        CHECK(!p.pre_refresh_called);
    }
    for(unsigned k=0;k<8;++k) {
        vireo_async_client_drive_options_t o=options; vireo_async_client_drive_tls_budget_t b=budget; vireo_result_t expected=VIREO_RESULT_RANGE;
        switch(k) { case 0: b.receive.max_bytes=4095; break; case 1: b.send.max_bytes=4095; break;
        case 2: o.max_frame_bytes=129; break; case 3: o.max_frame_bytes=31; break;
        case 4: b.receive.max_native_calls=0; expected=VIREO_RESULT_INVALID_ARGUMENT; break;
        case 5: o.operation=0; expected=VIREO_RESULT_INVALID_ARGUMENT; break;
        case 6: o.task_allocation_budget=67108865; break;
        default: o.max_client_requests=0; expected=VIREO_RESULT_INVALID_ARGUMENT; break; }
        EXPECT(vireo_async_client_drive_tls_once(f.server,f.client,f.store,f.pool,&o,&b,NULL,&f.pending,&f.remaining,&p),expected);
        CHECK(!p.pre_refresh_called && !p.receive_called && !p.head_called);
    }
    fault_t fault={.retry_range=true}; p=model(&f,&fault,VIREO_RESULT_RANGE);
    CHECK(p.stage==VIREO_ASYNC_CLIENT_DRIVE_TLS_CHECK_BUDGET && !p.pre_refresh_called && fault.syncs==0);
    f.pending.frame_bytes=1; p=drive(&f,VIREO_RESULT_INVALID_ARGUMENT); CHECK(p.stage==VIREO_ASYNC_CLIENT_DRIVE_TLS_CHECK_PENDING);
    f.pending=(vireo_async_request_pending_t){0}; cleanup(&f); ++groups;
}
static void signal_gate(void) {
    fixture_t f; setup(&f,true); pool_setup(&f,4); CHECK(signal(SIGPIPE,SIG_DFL)!=SIG_ERR);
    vireo_async_client_drive_tls_report_t p=drive(&f,VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(p.receive_called && !p.receive_reported && p.final_refresh_called && !p.head_called);
    CHECK(signal(SIGPIPE,SIG_IGN)!=SIG_ERR); cleanup(&f); ++groups;
}
static void raw_gate(void) {
    fixture_t f={.peer=-1}; vireo_tcp_server_options_t const so={1,4,1048576,32768};
    EXPECT(vireo_tcp_server_create_with_auxiliary_capacity(&so,1,&f.server,NULL),VIREO_OK);
    int fd=socket(AF_INET,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0); CHECK(fd>=0);
    struct sockaddr_in address={.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
    CHECK(bind(fd,(struct sockaddr *)&address,sizeof address)==0 && listen(fd,4)==0);
    socklen_t n=sizeof address; CHECK(getsockname(fd,(struct sockaddr *)&address,&n)==0);
    vireo_acceptor_t *a=NULL; vireo_acceptor_options_t const ao={4096};
    EXPECT(vireo_acceptor_create(&ao,&fd,&a,NULL),VIREO_OK);
    EXPECT(vireo_tcp_server_adopt_listener(f.server,&a,NULL),VIREO_OK);
    f.peer=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0); CHECK(f.peer>=0);
    CHECK(connect(f.peer,(struct sockaddr *)&address,sizeof address)==0);
    vireo_connection_options_t const co={128,128,256}; vireo_tcp_server_admit_budget_t const ab={1,2};
    vireo_tcp_server_admit_info_t ai;
    EXPECT(vireo_tcp_server_admit_batch(f.server,&co,&ab,&f.client,1,&ai,NULL),VIREO_OK);
    vireo_connection_flow_options_t const flow={128,127,128,32,96};
    EXPECT(vireo_tcp_server_client_flow_configure(f.server,f.client,&flow,NULL),VIREO_OK);
    vireo_inflight_store_options_t const io={8,65536}; EXPECT(vireo_inflight_store_create(&io,&f.store),VIREO_OK);
    pool_setup(&f,4);
    vireo_async_client_drive_tls_report_t p=drive(&f,VIREO_RESULT_BUSY);
    CHECK(!p.pre_refresh_called && !p.head_called); cleanup(&f); ++groups;
}
static void corrupt_frame(void) {
    fixture_t f; setup(&f,true); pool_setup(&f,4); uint8_t request[35]; make_request(request,101); request[34]^=1;
    peer_write(&f,request,35); cache_input(&f,35);
    vireo_async_client_drive_tls_report_t p=drive(&f,VIREO_RESULT_PROTOCOL);
    CHECK(p.stage==VIREO_ASYNC_CLIENT_DRIVE_TLS_PEEK_FRAME && p.frame_peek_called && !p.head_called && p.final_refresh_called);
    CHECK(state(&f).connection_info.read_buffer.readable_size==35 && f.submitted==0); cleanup(&f); ++groups;
}
int main(void) {
    CHECK(signal(SIGPIPE,SIG_IGN)!=SIG_ERR); int old;
    CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,&old)==0);
    size_t before=fds();
    real_chain(); fairness_and_partial(); full_queue(); want_order(); error_prefixes(); committed_recovery();
    pressure_and_eof(); gates_and_failed(); arguments_and_budgets(); signal_gate(); raw_gate(); corrupt_frame();
    CHECK(fds()==before); printf("TLS async client drive: %u groups passed, fd %zu -> %zu\n",groups,before,fds()); return 0;
}
