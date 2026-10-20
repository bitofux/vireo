/* PROJECT: VIREO; FILE: test_auth_request_rejection.c; AUTHOR: bitofux; DATE: 2026-10-20.
 * 真实TLS FIFO/任务/worker组合，以及本组件消费失败恢复实验。 */
#define _GNU_SOURCE
#include "auth_request_rejection_internal.h"
#include "tls_context_fixtures.h"
#include <vireo/protocol/tlv.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>

static atomic_uint checks;
static unsigned groups;
#define CHECK(x) do { atomic_fetch_add_explicit(&checks,1U,memory_order_relaxed); if (!(x)) { fprintf(stderr,"%s:%d: %s\n",__FILE__,__LINE__,#x); exit(1); } } while (0)
#define EXPECT(x,r) do { errno=EDOM; CHECK((x)==(r)); CHECK(errno==EDOM); } while (0)
_Static_assert(VIREO_AUTH_REQUEST_DEVICE_SIZE==VIREO_AUTH_LOGIN_DEVICE_BYTES,"device width drift");
static vireo_auth_request_submit_options_t const options={65536,8,101,102,UINT64_MAX,103,104};

typedef struct worker {
    pthread_barrier_t entered, release;
    uint8_t expected[156]; size_t size;
    unsigned executed; vireo_command_t command;
} worker_t;
typedef struct fixture {
    vireo_tcp_server_t *server;
    vireo_connection_pool_lease_t client;
    int peer; SSL *ssl;
    vireo_inflight_store_t *store;
    vireo_task_queue_t *tasks; vireo_thread_pool_t *pool;
    vireo_auth_login_admission_t *admission;
    vireo_auth_sessions_t *sessions;
    worker_t worker; bool started, released;
    vireo_task_t *remaining;
    vireo_task_metadata_t accepted[8]; unsigned submitted;
} fixture_t;

static size_t fds(void) {
    DIR *d=opendir("/proc/self/fd"); CHECK(d); size_t n=0; struct dirent *p;
    while((p=readdir(d))!=NULL) if(p->d_name[0]!='.') ++n;
    CHECK(closedir(d)==0); return n;
}
static void meet(pthread_barrier_t *b) {
    int const rc=pthread_barrier_wait(b); CHECK(rc==0 || rc==PTHREAD_BARRIER_SERIAL_THREAD);
}
static vireo_result_t execute(void *context,vireo_task_t const *task) {
    worker_t *w=context; vireo_task_payload_view_t p;
    CHECK(vireo_task_borrow_payload(task,&p)==VIREO_OK);
    if(p.size==0) { meet(&w->entered); meet(&w->release); return VIREO_OK; }
    CHECK(p.size==w->size && memcmp(p.data,w->expected,p.size)==0);
    vireo_auth_request_view_t v; vireo_auth_request_issue_t issue;
    CHECK(vireo_auth_request_decode(p.data,p.size,&v,&issue)==VIREO_OK);
    vireo_task_info_t info; CHECK(vireo_task_inspect(task,&info)==VIREO_OK);
    CHECK(info.metadata.route.request_sequence==v.sequence);
    CHECK(info.metadata.operation==(v.command==VIREO_COMMAND_LOGIN ? 102U : 101U));
    CHECK(info.metadata.deadline_ns==UINT64_MAX);
    w->command=v.command; ++w->executed; return VIREO_OK;
}
static vireo_tls_connection_t *tls(fixture_t *f) {
    vireo_tls_connection_t *t=NULL;
    EXPECT(vireo_tcp_server_client_tls_borrow(f->server,f->client,&t,NULL),VIREO_OK); return t;
}
static void fresh_admission(fixture_t *f,uint32_t account) {
    EXPECT(vireo_auth_login_admission_destroy(&f->admission),VIREO_OK);
    vireo_auth_login_admission_options_t o=VIREO_AUTH_LOGIN_ADMISSION_OPTIONS_DEFAULT;
    o.account.burst_tokens=account;
    EXPECT(vireo_auth_login_admission_create(&o,0,&f->admission),VIREO_OK);
}
static void setup(fixture_t *f,bool establish) {
    *f=(fixture_t){.peer=-1};
    vireo_tls_context_options_t const co={fixture_leaf,sizeof fixture_leaf-1,fixture_key,sizeof fixture_key-1,4096};
    vireo_tls_context_t *context=NULL;
    EXPECT(vireo_tls_context_create_server(&co,&context,NULL),VIREO_OK);
    vireo_tcp_server_options_t const so={1,4,1048576,32768};
    vireo_tcp_server_tls_options_t const to={{4096,4096,40960,256,255,4096,0,4096},
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
    vireo_task_queue_options_t const qo={1,65536};
    vireo_thread_pool_options_t const po={1,65536};
    EXPECT(vireo_task_queue_create(&qo,&f->tasks),VIREO_OK);
    EXPECT(vireo_task_queue_prepare_wait(f->tasks),VIREO_OK);
    EXPECT(vireo_thread_pool_create(&po,&f->pool),VIREO_OK);
    vireo_thread_pool_configuration_t const config={f->tasks,execute,&f->worker};
    EXPECT(vireo_thread_pool_configure(f->pool,&config,NULL),VIREO_OK);
    CHECK(pthread_barrier_init(&f->worker.entered,NULL,2)==0);
    CHECK(pthread_barrier_init(&f->worker.release,NULL,2)==0);
    vireo_auth_sessions_options_t const session_options={65536};
    EXPECT(vireo_auth_sessions_create(f->server,&session_options,&f->sessions),VIREO_OK);
    fresh_admission(f,2);
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
static void start_worker(fixture_t *f) {
    vireo_task_route_t route; vireo_task_metadata_t m; vireo_task_t *warm=NULL;
    EXPECT(vireo_task_route_make(UINT64_MAX,0,1,1,&route),VIREO_OK);
    EXPECT(vireo_task_metadata_make(route,1,1,UINT64_MAX,&m),VIREO_OK);
    EXPECT(vireo_task_create_copy(m,NULL,0,4096,&warm),VIREO_OK);
    vireo_task_queue_transfer_report_t qr;
    EXPECT(vireo_task_queue_try_push(f->tasks,&warm,&qr),VIREO_OK);
    vireo_thread_pool_report_t pr;
    EXPECT(vireo_thread_pool_start(f->pool,&pr),VIREO_OK);
    EXPECT(vireo_thread_pool_enable_execution(f->pool,&pr),VIREO_OK);
    f->started=true; meet(&f->worker.entered);
}
static void end_worker(fixture_t *f) {
    if(!f->started) return;
    if(!f->released) { meet(&f->worker.release); f->released=true; }
    vireo_task_queue_close_report_t cr; vireo_result_t rc=VIREO_RESULT_BUSY;
    for(unsigned k=0;k<1000000 && rc==VIREO_RESULT_BUSY;++k) {
        rc=vireo_task_queue_close(f->tasks,VIREO_TASK_QUEUE_DRAIN,&cr);
        if(rc==VIREO_RESULT_BUSY) sched_yield();
    }
    CHECK(rc==VIREO_OK); vireo_thread_pool_report_t pr; rc=VIREO_RESULT_BUSY;
    for(unsigned k=0;k<1000000 && rc==VIREO_RESULT_BUSY;++k) {
        rc=vireo_thread_pool_stop_and_join(f->pool,&pr);
        if(rc==VIREO_RESULT_BUSY) sched_yield();
    }
    CHECK(rc==VIREO_OK); f->started=false;
}
static void cleanup(fixture_t *f) {
    EXPECT(vireo_auth_sessions_destroy(&f->sessions),VIREO_OK);
    EXPECT(vireo_task_destroy(&f->remaining),VIREO_OK); end_worker(f);
    for(unsigned i=0;i<f->submitted;++i) {
        vireo_task_metadata_t removed;
        EXPECT(vireo_inflight_store_take(f->store,f->accepted[i],&removed,NULL),VIREO_OK);
    }
    vireo_inflight_store_info_t info;
    EXPECT(vireo_inflight_store_inspect(f->store,&info),VIREO_OK); CHECK(info.count==0);
    EXPECT(vireo_thread_pool_destroy(&f->pool),VIREO_OK);
    EXPECT(vireo_task_queue_destroy(&f->tasks),VIREO_OK);
    EXPECT(vireo_inflight_store_destroy(&f->store),VIREO_OK);
    EXPECT(vireo_auth_login_admission_destroy(&f->admission),VIREO_OK);
    if(f->client.pool_id) EXPECT(vireo_tcp_server_release_client(f->server,&f->client,NULL),VIREO_OK);
    SSL_free(f->ssl); if(f->peer>=0) CHECK(close(f->peer)==0);
    EXPECT(vireo_tcp_server_destroy(&f->server,NULL),VIREO_OK);
    CHECK(pthread_barrier_destroy(&f->worker.entered)==0);
    CHECK(pthread_barrier_destroy(&f->worker.release)==0);
}
static size_t make_wire(uint8_t *wire,bool login,uint32_t sequence,char const *username,uint8_t label) {
    uint8_t const password[8]={'a','b','c','d','e','f','g','h'};
    uint8_t device[16]; memset(device,label,sizeof(device)); vireo_tlv_writer_t w;
    EXPECT(vireo_tlv_writer_init(&w,wire+32,124),VIREO_OK);
    EXPECT(vireo_tlv_writer_put(&w,1,(uint8_t const *)username,strlen(username)),VIREO_OK);
    EXPECT(vireo_tlv_writer_put(&w,2,password,sizeof(password)),VIREO_OK);
    if(login) EXPECT(vireo_tlv_writer_put(&w,3,device,sizeof(device)),VIREO_OK);
    vireo_protocol_header_t h={.command=login ? VIREO_COMMAND_LOGIN : VIREO_COMMAND_REGISTER,
        .sequence=sequence,.body_len=(uint32_t)w.used};
    EXPECT(vireo_protocol_header_encode(&h,wire,32),VIREO_OK);
    EXPECT(vireo_protocol_frame_crc32c_calculate(wire,32,wire+32,w.used,&h.crc32c),VIREO_OK);
    EXPECT(vireo_protocol_header_encode(&h,wire,32),VIREO_OK); return 32+w.used;
}
/* 网络完成有单调时间期限，不能从紧循环次数推定TLS记录应已到达。 */
static uint64_t io_now_ns(void) {
    struct timespec now;
    CHECK(clock_gettime(CLOCK_MONOTONIC,&now)==0);
    return (uint64_t)now.tv_sec*UINT64_C(1000000000)+(uint64_t)now.tv_nsec;
}
static void receive_wire(fixture_t *f,uint8_t const *wire,size_t n,uint8_t const **input) {
    size_t wrote=0;
    for(unsigned k=0;k<1024 && wrote<n;++k) {
        size_t amount=0; ERR_clear_error(); int rc=SSL_write_ex(f->ssl,wire+wrote,n-wrote,&amount);
        int why=rc==1?SSL_ERROR_NONE:SSL_get_error(f->ssl,rc);
        CHECK(why==SSL_ERROR_NONE || why==SSL_ERROR_WANT_READ || why==SSL_ERROR_WANT_WRITE);
        wrote+=amount;
    }
    CHECK(wrote==n);
    size_t have=0; uint64_t const deadline=io_now_ns()+UINT64_C(5000000000);
    while(have<n && io_now_ns()<deadline) {
        vireo_tls_io_budget_t const b={4096,8}; vireo_tls_io_progress_t progress;
        EXPECT(vireo_tls_connection_receive(tls(f),&b,&progress,NULL),VIREO_OK);
        EXPECT(vireo_tcp_server_client_read_peek(f->server,f->client,input,&have,NULL),VIREO_OK);
        if(have<n) {
            vireo_tcp_server_tls_flow_info_t flow;
            EXPECT(vireo_tcp_server_client_tls_flow_refresh(f->server,f->client,&flow,NULL),VIREO_OK);
            vireo_tcp_server_ready_client_t ready[1]; vireo_tcp_server_tls_poll_report_t p;
            EXPECT(vireo_tcp_server_tls_poll_ready_once(f->server,2,1,ready,1,&p,NULL),VIREO_OK);
        }
    }
    CHECK(have==n && memcmp(*input,wire,n)==0);
}

static vireo_auth_request_head_receipt_t head(fixture_t *f,vireo_result_t result) {
    vireo_auth_request_head_receipt_t h={0}; vireo_auth_request_head_report_t r;
    EXPECT(vireo_auth_request_submit_read_head(f->server,f->client,f->store,f->pool,f->admission,0,f->sessions,0,
        &options,NULL,&h,&f->remaining,&r),result);
    CHECK(h.state==VIREO_AUTH_REQUEST_HEAD_CONSUMED && r.consume_called);
    if(h.submit_report.submit_report.task_transferred) {
        CHECK(f->submitted<8); f->accepted[f->submitted++]=h.submit_report.submit_report.metadata;
    }
    return h;
}
static vireo_auth_request_head_receipt_t schema_rejected(fixture_t *f,uint32_t sequence) {
    uint8_t wire[156]; size_t n=make_wire(wire,true,sequence,"Alice_7",0);
    wire[36]='!'; vireo_protocol_header_t h; vireo_protocol_codec_issue_t issue;
    EXPECT(vireo_protocol_header_decode(wire,32,&h,&issue),VIREO_OK);
    EXPECT(vireo_protocol_frame_crc32c_calculate(wire,32,wire+32,n-32,&h.crc32c),VIREO_OK);
    EXPECT(vireo_protocol_header_encode(&h,wire,32),VIREO_OK);
    uint8_t const *p=NULL; receive_wire(f,wire,n,&p); p=NULL;
    return head(f,VIREO_RESULT_PROTOCOL);
}
/* 直接驱动真实TLS发送，再在可信客户端收明文；不把FIFO入队当作已送达。 */
static void drain(fixture_t *f,uint8_t *out,size_t size) {
    size_t received=0; uint64_t const deadline=io_now_ns()+UINT64_C(5000000000);
    while(received<size && io_now_ns()<deadline) {
        vireo_tls_io_budget_t const budget={4096,8}; vireo_tls_io_progress_t progress;
        EXPECT(vireo_tls_connection_send(tls(f),&budget,&progress,NULL),VIREO_OK);
        size_t amount=0; ERR_clear_error(); int rc=SSL_read_ex(f->ssl,out+received,size-received,&amount);
        int why=rc==1?SSL_ERROR_NONE:SSL_get_error(f->ssl,rc);
        CHECK(why==SSL_ERROR_NONE || why==SSL_ERROR_WANT_READ || why==SSL_ERROR_WANT_WRITE);
        received+=amount;
        if(!amount) {
            struct pollfd peer={f->peer,why==SSL_ERROR_WANT_WRITE?POLLOUT:POLLIN,0};
            int const polled=poll(&peer,1,5);
            CHECK(polled>=0 || errno==EINTR);
            CHECK(!(peer.revents&(POLLERR|POLLHUP|POLLNVAL)));
        }
    }
    CHECK(received==size);
}
static void check_response(fixture_t *f,uint32_t sequence,vireo_command_t command,vireo_status_t status) {
    uint8_t wire[32]; drain(f,wire,sizeof wire);
    vireo_protocol_header_t h; vireo_protocol_codec_issue_t issue;
    EXPECT(vireo_protocol_header_decode(wire,sizeof wire,&h,&issue),VIREO_OK);
    EXPECT(vireo_protocol_response_header_validate(&h,&issue),VIREO_OK);
    EXPECT(vireo_protocol_frame_crc32c_verify(wire,sizeof wire,NULL,0,&issue),VIREO_OK);
    CHECK(h.command==command && h.sequence==sequence && h.flags==VIREO_PROTOCOL_FLAG_RESPONSE &&
        h.status==status && h.body_len==0 && h.session_handle==0 && h.task_handle==0);
    vireo_tls_io_info_t io; EXPECT(vireo_tls_connection_io_inspect(tls(f),&io,NULL),VIREO_OK);
    CHECK(io.write_size==0);
    uint8_t extra; size_t n=0; ERR_clear_error(); int rc=SSL_read_ex(f->ssl,&extra,1,&n);
    CHECK(rc==0 && n==0 && SSL_get_error(f->ssl,rc)==SSL_ERROR_WANT_READ);
}
typedef struct script {
    unsigned enqueues,refreshes;
    vireo_result_t enqueue_error,refresh_error;
    vireo_auth_request_rejection_receipt_t *receipt;
} script_t;
static vireo_result_t enqueue_test(void *context,vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client,uint8_t const *wire,size_t n,vireo_tcp_server_client_error_t *error) {
    script_t *s=context; ++s->enqueues;
    CHECK(s->receipt->state==VIREO_AUTH_REQUEST_REJECTION_NEEDS_ENQUEUE && n==32);
    if(s->enqueue_error) { errno=EINTR; return s->enqueue_error; }
    return vireo_tcp_server_client_write_enqueue(server,client,wire,n,error);
}
static vireo_result_t refresh_test(void *context,vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client,vireo_tcp_server_tls_flow_info_t *info,
    vireo_tcp_server_tls_application_error_t *error) {
    script_t *s=context; ++s->refreshes;
    CHECK(s->receipt->state==VIREO_AUTH_REQUEST_REJECTION_NEEDS_REFRESH);
    if(s->refresh_error) { errno=EINTR; return s->refresh_error; }
    return vireo_tcp_server_client_tls_flow_refresh(server,client,info,error);
}
static vireo_auth_request_rejection_ops_t const ops={enqueue_test,refresh_test};
static void schema_response(void) {
    fixture_t f; setup(&f,true);
    vireo_auth_request_head_receipt_t h=schema_rejected(&f,101), before=h;
    vireo_auth_request_rejection_receipt_t receipt={0}; vireo_auth_request_rejection_report_t r;
    EXPECT(vireo_auth_request_rejection_acknowledge(&h,&receipt),VIREO_RESULT_NOT_FOUND);
    EXPECT(vireo_auth_request_rejection_step(f.server,&h,&receipt,&r),VIREO_OK);
    CHECK(r.enqueued && r.refresh_called && r.frame_encoded && r.receipt.state==VIREO_AUTH_REQUEST_REJECTION_READY);
    CHECK(receipt.status==VIREO_STATUS_BAD_REQUEST && memcmp(&h,&before,sizeof h)==0);
    for(unsigned i=0;i<3;++i) {
        EXPECT(vireo_auth_request_rejection_step(f.server,&h,&receipt,&r),VIREO_RESULT_NOT_FOUND);
        CHECK(!r.enqueue_called && !r.refresh_called);
    }
    check_response(&f,101,VIREO_COMMAND_LOGIN,VIREO_STATUS_BAD_REQUEST);
    EXPECT(vireo_auth_request_rejection_acknowledge(&h,&receipt),VIREO_OK);
    CHECK(h.state==VIREO_AUTH_REQUEST_HEAD_EMPTY && receipt.state==VIREO_AUTH_REQUEST_REJECTION_EMPTY);
    EXPECT(vireo_auth_request_rejection_acknowledge(&h,&receipt),VIREO_RESULT_NOT_FOUND);
    cleanup(&f); ++groups;
}
static void queue_and_refresh_recovery(void) {
    fixture_t f; setup(&f,true); start_worker(&f);
    uint8_t wire[156]; size_t n=make_wire(wire,true,201,"Alice_7",0);
    memcpy(f.worker.expected,wire,n); f.worker.size=n;
    uint8_t const *p=NULL; receive_wire(&f,wire,n,&p); p=NULL;
    vireo_auth_request_head_receipt_t h=head(&f,VIREO_OK);
    vireo_auth_request_rejection_receipt_t receipt={0}; vireo_auth_request_rejection_report_t r;
    EXPECT(vireo_auth_request_rejection_step(f.server,&h,&receipt,&r),VIREO_RESULT_NOT_FOUND);
    /* 交接后的异常返回仍不能拒绝；这是显式报告值模型，非真实queue解锁故障。 */
    h.submit_result=VIREO_RESULT_INTERNAL;
    EXPECT(vireo_auth_request_rejection_step(f.server,&h,&receipt,&r),VIREO_RESULT_NOT_FOUND);
    CHECK(!r.enqueue_called && !r.refresh_called && receipt.state==VIREO_AUTH_REQUEST_REJECTION_EMPTY);
    EXPECT(vireo_auth_request_head_acknowledge(&h),VIREO_OK);
    n=make_wire(wire,true,202,"ALICE_7",255); receive_wire(&f,wire,n,&p); p=NULL;
    h=head(&f,VIREO_RESULT_BUSY);
    CHECK(h.submit_report.login_charged && f.remaining && !h.submit_report.submit_report.task_transferred);
    EXPECT(vireo_task_destroy(&f.remaining),VIREO_OK);
    script_t s={.refresh_error=VIREO_RESULT_IO,.receipt=&receipt};
    EXPECT(vireo_auth_request_rejection_with(f.server,&h,&receipt,&r,&ops,&s),VIREO_RESULT_IO);
    CHECK(receipt.status==VIREO_STATUS_OVERLOADED && receipt.state==VIREO_AUTH_REQUEST_REJECTION_NEEDS_REFRESH &&
        r.enqueued && r.refresh_called && s.enqueues==1 && s.refreshes==1);
    EXPECT(vireo_auth_request_rejection_acknowledge(&h,&receipt),VIREO_RESULT_BUSY);
    EXPECT(vireo_auth_request_rejection_with(f.server,&h,&receipt,&r,&ops,&s),VIREO_RESULT_IO);
    CHECK(!r.enqueue_called && !r.enqueued && !r.frame_encoded && s.enqueues==1 && s.refreshes==2);
    vireo_auth_request_head_report_t hr;
    EXPECT(vireo_auth_request_submit_read_head(f.server,f.client,f.store,f.pool,f.admission,0,f.sessions,0,&options,NULL,
        &h,&f.remaining,&hr),VIREO_RESULT_BUSY); CHECK(!hr.frame_peek_called && !hr.submit_called);
    s.refresh_error=VIREO_OK;
    EXPECT(vireo_auth_request_rejection_with(f.server,&h,&receipt,&r,&ops,&s),VIREO_OK);
    CHECK(!r.enqueue_called && s.enqueues==1 && s.refreshes==3);
    check_response(&f,202,VIREO_COMMAND_LOGIN,VIREO_STATUS_OVERLOADED);
    EXPECT(vireo_auth_request_rejection_acknowledge(&h,&receipt),VIREO_OK);
    n=make_wire(wire,true,203,"alice_7",17); receive_wire(&f,wire,n,&p); p=NULL;
    h=head(&f,VIREO_RESULT_BUSY);
    CHECK(h.submit_report.admission_decided && !h.submit_report.login_charged && !h.submit_report.submit_called);
    EXPECT(vireo_auth_request_rejection_step(f.server,&h,&receipt,&r),VIREO_OK);
    CHECK(receipt.status==VIREO_STATUS_RATE_LIMITED);
    check_response(&f,203,VIREO_COMMAND_LOGIN,VIREO_STATUS_RATE_LIMITED);
    EXPECT(vireo_auth_request_rejection_acknowledge(&h,&receipt),VIREO_OK);
    end_worker(&f); CHECK(f.worker.executed==1); cleanup(&f); ++groups;
}
static void full_fifo(void) {
    fixture_t f; setup(&f,true); vireo_auth_request_head_receipt_t h=schema_rejected(&f,301);
    uint8_t full[4096],received[4096]; memset(full,0xa5,sizeof full);
    EXPECT(vireo_tcp_server_client_write_enqueue(f.server,f.client,full,sizeof full,NULL),VIREO_OK);
    vireo_auth_request_rejection_receipt_t receipt={0}; vireo_auth_request_rejection_report_t r;
    for(unsigned i=0;i<2;++i) {
        EXPECT(vireo_auth_request_rejection_step(f.server,&h,&receipt,&r),VIREO_RESULT_RANGE);
        CHECK(r.enqueue_called && !r.enqueued && !r.refresh_called &&
            receipt.state==VIREO_AUTH_REQUEST_REJECTION_NEEDS_ENQUEUE);
        EXPECT(vireo_auth_request_rejection_acknowledge(&h,&receipt),VIREO_RESULT_BUSY);
    }
    drain(&f,received,sizeof received); CHECK(memcmp(full,received,sizeof full)==0);
    EXPECT(vireo_auth_request_rejection_step(f.server,&h,&receipt,&r),VIREO_OK);
    check_response(&f,301,VIREO_COMMAND_LOGIN,VIREO_STATUS_BAD_REQUEST);
    EXPECT(vireo_auth_request_rejection_acknowledge(&h,&receipt),VIREO_OK);
    cleanup(&f); ++groups;
}
static void transport_and_stale(void) {
    fixture_t f; setup(&f,true); vireo_auth_request_head_receipt_t h=schema_rejected(&f,401);
    vireo_auth_request_rejection_receipt_t receipt={0}; vireo_auth_request_rejection_report_t r;
    script_t s={.refresh_error=VIREO_RESULT_IO,.receipt=&receipt};
    EXPECT(vireo_auth_request_rejection_with(f.server,&h,&receipt,&r,&ops,&s),VIREO_RESULT_IO);
    EXPECT(vireo_tcp_server_release_client(f.server,&f.client,NULL),VIREO_OK);
    EXPECT(vireo_auth_request_rejection_with(f.server,&h,&receipt,&r,&ops,&s),VIREO_RESULT_NOT_FOUND);
    CHECK(!r.enqueue_called && !r.refresh_called && s.enqueues==1 && s.refreshes==1 &&
        receipt.state==VIREO_AUTH_REQUEST_REJECTION_NEEDS_REFRESH);
    /* 明确归还后可审计保存并弃置；绝不把原凭据租约改成别的客户。 */
    cleanup(&f);
    setup(&f,false);
    h.client=f.client; receipt=(vireo_auth_request_rejection_receipt_t){0};
    EXPECT(vireo_auth_request_rejection_step(f.server,&h,&receipt,&r),VIREO_RESULT_BUSY);
    CHECK(!r.enqueue_called && receipt.state==VIREO_AUTH_REQUEST_REJECTION_NEEDS_ENQUEUE);
    cleanup(&f);
    setup(&f,true); h=schema_rejected(&f,402); receipt=(vireo_auth_request_rejection_receipt_t){0};
    s=(script_t){.refresh_error=VIREO_RESULT_IO,.receipt=&receipt};
    EXPECT(vireo_auth_request_rejection_with(f.server,&h,&receipt,&r,&ops,&s),VIREO_RESULT_IO);
    EXPECT(vireo_tcp_server_request_stop(f.server,NULL),VIREO_OK);
    s.refresh_error=VIREO_OK;
    EXPECT(vireo_auth_request_rejection_with(f.server,&h,&receipt,&r,&ops,&s),VIREO_OK);
    CHECK(!r.enqueue_called && s.enqueues==1);
    check_response(&f,402,VIREO_COMMAND_LOGIN,VIREO_STATUS_BAD_REQUEST);
    EXPECT(vireo_auth_request_rejection_acknowledge(&h,&receipt),VIREO_OK);
    cleanup(&f); ++groups;
}
static void classifications_and_arguments(void) {
    fixture_t f; setup(&f,true); vireo_auth_request_head_receipt_t h=schema_rejected(&f,501),original=h;
    vireo_auth_request_rejection_receipt_t receipt={0}; vireo_auth_request_rejection_report_t r;
    script_t s={.enqueue_error=VIREO_RESULT_NO_MEMORY,.receipt=&receipt};
    struct example { vireo_result_t result; vireo_auth_request_submit_stage_t stage;
        bool decided; vireo_rate_limit_outcome_t outcome; vireo_status_t status; } const examples[]={
        {VIREO_RESULT_PROTOCOL,VIREO_AUTH_REQUEST_SUBMIT_DECODE,false,0,VIREO_STATUS_BAD_REQUEST},
        {VIREO_RESULT_BUSY,VIREO_AUTH_REQUEST_SUBMIT_ADMISSION,true,VIREO_RATE_LIMIT_THROTTLED,VIREO_STATUS_RATE_LIMITED},
        {VIREO_RESULT_BUSY,VIREO_AUTH_REQUEST_SUBMIT_ADMISSION,true,VIREO_RATE_LIMIT_CAPACITY,VIREO_STATUS_OVERLOADED},
        {VIREO_RESULT_BUSY,VIREO_AUTH_REQUEST_SUBMIT_ADMISSION,false,0,VIREO_STATUS_INTERNAL_ERROR},
        {VIREO_RESULT_BUSY,VIREO_AUTH_REQUEST_SUBMIT_QUEUE,false,0,VIREO_STATUS_OVERLOADED},
        {VIREO_RESULT_CANCELLED,VIREO_AUTH_REQUEST_SUBMIT_QUEUE,false,0,VIREO_STATUS_UNAVAILABLE},
        {VIREO_RESULT_IO,VIREO_AUTH_REQUEST_SUBMIT_PEER,false,0,VIREO_STATUS_INTERNAL_ERROR},
        {VIREO_RESULT_NO_MEMORY,VIREO_AUTH_REQUEST_SUBMIT_QUEUE,false,0,VIREO_STATUS_INTERNAL_ERROR}
    };
    /* 纯映射模型；enqueue seam在复制前拒绝，不能当成真实CAPACITY/IO故障证据。 */
    for(size_t i=0;i<sizeof examples/sizeof examples[0];++i) {
        h=original; h.submit_result=examples[i].result; h.submit_report.stage=examples[i].stage;
        h.submit_report.admission_decided=examples[i].decided; h.submit_report.decision.outcome=examples[i].outcome;
        receipt=(vireo_auth_request_rejection_receipt_t){0};
        EXPECT(vireo_auth_request_rejection_with(f.server,&h,&receipt,&r,&ops,&s),VIREO_RESULT_NO_MEMORY);
        CHECK(receipt.status==examples[i].status && !r.enqueued && !r.refresh_called);
    }
    h=original; receipt=(vireo_auth_request_rejection_receipt_t){0};
    EXPECT(vireo_auth_request_rejection_step(NULL,&h,&receipt,&r),VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_auth_request_rejection_step(f.server,NULL,&receipt,&r),VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_auth_request_rejection_step(f.server,&h,NULL,&r),VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_auth_request_rejection_step(f.server,&h,&receipt,NULL),VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_auth_request_rejection_with(f.server,&h,&receipt,&r,NULL,&s),VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_auth_request_rejection_acknowledge(NULL,&receipt),VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_auth_request_rejection_acknowledge(&h,NULL),VIREO_RESULT_INVALID_ARGUMENT);
    h.state=VIREO_AUTH_REQUEST_HEAD_NEEDS_CONSUME;
    EXPECT(vireo_auth_request_rejection_step(f.server,&h,&receipt,&r),VIREO_RESULT_BUSY);
    h=original; h.command=VIREO_COMMAND_PING;
    EXPECT(vireo_auth_request_rejection_step(f.server,&h,&receipt,&r),VIREO_RESULT_INVALID_ARGUMENT);
    h=original; h.sequence=0;
    EXPECT(vireo_auth_request_rejection_step(f.server,&h,&receipt,&r),VIREO_RESULT_INVALID_ARGUMENT);
    h=original; h.submit_result=(vireo_result_t)99;
    EXPECT(vireo_auth_request_rejection_step(f.server,&h,&receipt,&r),VIREO_RESULT_INVALID_ARGUMENT);
    h=original; receipt.sequence=1;
    EXPECT(vireo_auth_request_rejection_step(f.server,&h,&receipt,&r),VIREO_RESULT_INVALID_ARGUMENT);
    receipt=(vireo_auth_request_rejection_receipt_t){0};
    EXPECT(vireo_auth_request_rejection_with(f.server,&h,&receipt,&r,&ops,&s),VIREO_RESULT_NO_MEMORY);
    receipt.client.generation++;
    EXPECT(vireo_auth_request_rejection_step(f.server,&h,&receipt,&r),VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_auth_request_rejection_acknowledge(&h,&receipt),VIREO_RESULT_INVALID_ARGUMENT);
    receipt.client.generation--; receipt.state=(vireo_auth_request_rejection_state_t)99;
    EXPECT(vireo_auth_request_rejection_step(f.server,&h,&receipt,&r),VIREO_RESULT_INVALID_ARGUMENT);
    receipt=(vireo_auth_request_rejection_receipt_t){0};
    EXPECT(vireo_tcp_server_request_stop(f.server,NULL),VIREO_OK);
    EXPECT(vireo_auth_request_rejection_step(f.server,&h,&receipt,&r),VIREO_RESULT_CANCELLED);
    CHECK(!r.enqueue_called && !r.refresh_called);
    cleanup(&f); ++groups;
}
int main(void) {
    CHECK(signal(SIGPIPE,SIG_IGN)!=SIG_ERR); size_t const before=fds();
    schema_response(); queue_and_refresh_recovery(); full_fifo(); transport_and_stale(); classifications_and_arguments();
    size_t const after=fds(); CHECK(before==after);
    printf("auth_request_rejection: %u groups, %u checks, fd %zu -> %zu\n",groups,
        atomic_load_explicit(&checks,memory_order_relaxed),before,after); return 0;
}

