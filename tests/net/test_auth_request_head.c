/* PROJECT: VIREO; FILE: test_auth_request_head.c; AUTHOR: bitofux; DATE: 2026-10-20.
 * 真实TLS FIFO/任务/worker组合，以及本组件消费失败恢复实验。 */
#define _GNU_SOURCE
#include "auth_request_head_internal.h"
#include "tls_context_fixtures.h"
#include <vireo/protocol/tlv.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
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
static void receive_wire(fixture_t *f,uint8_t const *wire,size_t n,uint8_t const **input) {
    size_t wrote=0;
    for(unsigned k=0;k<1024 && wrote<n;++k) {
        size_t amount=0; ERR_clear_error(); int rc=SSL_write_ex(f->ssl,wire+wrote,n-wrote,&amount);
        int why=rc==1?SSL_ERROR_NONE:SSL_get_error(f->ssl,rc);
        CHECK(why==SSL_ERROR_NONE || why==SSL_ERROR_WANT_READ || why==SSL_ERROR_WANT_WRITE);
        wrote+=amount;
    }
    CHECK(wrote==n);
    size_t have=0;
    for(unsigned k=0;k<1024 && have<n;++k) {
        vireo_tls_io_budget_t const b={4096,8}; vireo_tls_io_progress_t progress;
        EXPECT(vireo_tls_connection_receive(tls(f),&b,&progress,NULL),VIREO_OK);
        EXPECT(vireo_tcp_server_client_read_peek(f->server,f->client,input,&have,NULL),VIREO_OK);
        if(have<n) {
            vireo_tcp_server_ready_client_t ready[1]; vireo_tcp_server_tls_poll_report_t p;
            EXPECT(vireo_tcp_server_tls_poll_ready_once(f->server,2,1,ready,1,&p,NULL),VIREO_OK);
        }
    }
    CHECK(have==n && memcmp(*input,wire,n)==0);
}

/* 所有资源均真实创建；只隔离本组件的四个公开依赖，不接触其他组件私有布局。 */
typedef struct script {
    unsigned frames, reads, submits, consumes;
    vireo_result_t frame_error, read_error, consume_error, after_submit_error;
    bool bad_count, short_read, null_read;
    vireo_auth_request_head_receipt_t *receipt;
} script_t;
static vireo_result_t frames_test(void *context,vireo_tcp_server_t const *server,
    vireo_connection_pool_lease_t client,vireo_connection_frame_options_t const *o,
    vireo_connection_frame_budget_t const *b,vireo_connection_frame_view_t *v,size_t capacity,
    vireo_connection_frame_info_t *info,vireo_tcp_server_client_error_t *error) {
    script_t *s=context; ++s->frames;
    CHECK(o->direction==VIREO_CONNECTION_FRAME_REQUEST && o->max_frame_bytes==156);
    CHECK(b->max_messages==1 && b->max_bytes==156 && capacity==1);
    if(s->frame_error) { errno=EINTR; return s->frame_error; }
    vireo_result_t rc=vireo_tcp_server_client_frames_peek(server,client,o,b,v,capacity,info,error);
    if(s->bad_count) info->frame_count=2;
    return rc;
}
static vireo_result_t read_test(void *context,vireo_tcp_server_t const *server,
    vireo_connection_pool_lease_t client,uint8_t const **data,size_t *n,vireo_tcp_server_client_error_t *error) {
    script_t *s=context; ++s->reads;
    if(s->read_error) { errno=EINTR; return s->read_error; }
    vireo_result_t rc=vireo_tcp_server_client_read_peek(server,client,data,n,error);
    if(s->short_read) *n=1;
    if(s->null_read) *data=NULL;
    return rc;
}
static vireo_result_t submit_test(void *context,vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client,vireo_inflight_store_t *store,vireo_thread_pool_t *pool,
    vireo_auth_login_admission_t *admission,vireo_monotonic_ns_t now,vireo_auth_sessions_t *sessions,uint64_t utc,uint8_t const *wire,size_t n,
    vireo_auth_request_submit_options_t const *o,vireo_task_cancel_t *cancel,vireo_task_t **task,
    vireo_auth_request_submit_report_t *report) {
    script_t *s=context; ++s->submits;
    vireo_result_t rc=vireo_auth_request_copy_try_submit(server,client,store,pool,admission,now,sessions,utc,wire,n,o,cancel,task,report);
    if(s->after_submit_error && report->submit_report.task_transferred) rc=s->after_submit_error;
    return rc;
}
static vireo_result_t consume_test(void *context,vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client,size_t n,vireo_tcp_server_client_error_t *error) {
    script_t *s=context; ++s->consumes;
    CHECK(s->receipt!=NULL && s->receipt->state==VIREO_AUTH_REQUEST_HEAD_NEEDS_CONSUME);
    CHECK(s->receipt->frame_bytes==n && s->receipt->client.pool_id==client.pool_id &&
        s->receipt->client.slot_index==client.slot_index && s->receipt->client.generation==client.generation);
    if(s->consume_error) { errno=EINTR; return s->consume_error; }
    return vireo_tcp_server_client_read_consume(server,client,n,error);
}
static vireo_auth_request_head_ops_t const ops={frames_test,read_test,submit_test,consume_test};
static void accept_report(fixture_t *f,vireo_auth_request_head_report_t const *r) {
    if(r->submit_called && r->receipt.submit_report.submit_report.task_transferred) {
        CHECK(f->submitted<8); f->accepted[f->submitted++]=r->receipt.submit_report.submit_report.metadata;
    }
}
static vireo_auth_request_head_report_t head(fixture_t *f,vireo_auth_request_head_receipt_t *receipt,
    script_t *s,vireo_result_t expected) {
    vireo_auth_request_head_report_t r; memset(&r,0xa5,sizeof r);
    if(s) {
        s->receipt=receipt;
        EXPECT(vireo_auth_request_head_with(f->server,f->client,f->store,f->pool,f->admission,0,f->sessions,0,
            &options,NULL,receipt,&f->remaining,&r,&ops,s),expected);
    } else {
        EXPECT(vireo_auth_request_submit_read_head(f->server,f->client,f->store,f->pool,f->admission,0,f->sessions,0,
            &options,NULL,receipt,&f->remaining,&r),expected);
    }
    accept_report(f,&r); return r;
}
static void pending_bytes(fixture_t *f,uint8_t const *expected,size_t n) {
    uint8_t const *p=NULL; size_t size=0;
    EXPECT(vireo_tcp_server_client_read_peek(f->server,f->client,&p,&size,NULL),VIREO_OK);
    CHECK(size==n); if(n) CHECK(memcmp(p,expected,n)==0);
}
static void ack(vireo_auth_request_head_receipt_t *receipt) {
    EXPECT(vireo_auth_request_head_acknowledge(receipt),VIREO_OK);
    CHECK(receipt->state==VIREO_AUTH_REQUEST_HEAD_EMPTY && receipt->frame_bytes==0 &&
        receipt->sequence==0 && !receipt->submit_report.login_charged);
}

static void real_register(void) {
    fixture_t f; setup(&f,true); start_worker(&f);
    uint8_t wire[156]; size_t n=make_wire(wire,false,17,"Alice_7",0);
    memcpy(f.worker.expected,wire,n); f.worker.size=n;
    uint8_t const *p=NULL; receive_wire(&f,wire,n,&p); p=NULL;
    vireo_auth_request_head_receipt_t receipt={0};
    vireo_auth_request_head_report_t r=head(&f,&receipt,NULL,VIREO_OK);
    CHECK(r.submit_called && r.receipt_committed && r.consume_called && r.consume_result==VIREO_OK);
    CHECK(receipt.state==VIREO_AUTH_REQUEST_HEAD_CONSUMED && receipt.command==VIREO_COMMAND_REGISTER && receipt.sequence==17);
    CHECK(receipt.submit_report.submit_report.task_transferred && !receipt.submit_report.admission_called &&
        !receipt.submit_report.peer_called && !receipt.submit_report.login_charged);
    pending_bytes(&f,NULL,0); r=head(&f,&receipt,NULL,VIREO_RESULT_BUSY);
    CHECK(!r.frame_peek_called && !r.submit_called && !r.consume_called);
    EXPECT(vireo_auth_request_head_resume_consume(f.server,&receipt,&r),VIREO_RESULT_NOT_FOUND);
    CHECK(!r.consume_called && r.receipt.sequence==17); ack(&receipt);
    r=head(&f,&receipt,NULL,VIREO_OK); CHECK(r.frame_peek_called && !r.read_peek_called && !r.receipt_committed);
    memset(wire,0,sizeof wire); end_worker(&f);
    CHECK(f.worker.executed==1 && f.worker.command==VIREO_COMMAND_REGISTER);
    cleanup(&f); ++groups;
}

static void queue_consume_recovery(void) {
    fixture_t f; setup(&f,true); start_worker(&f);
    uint8_t first[156]; size_t n=make_wire(first,true,21,"Alice_7",0);
    memcpy(f.worker.expected,first,n); f.worker.size=n;
    uint8_t const *p=NULL; receive_wire(&f,first,n,&p); p=NULL;
    vireo_auth_request_head_receipt_t receipt={0}; script_t s={.consume_error=VIREO_RESULT_IO};
    vireo_auth_request_head_report_t r=head(&f,&receipt,&s,VIREO_RESULT_IO);
    CHECK(r.stage==VIREO_AUTH_REQUEST_HEAD_CONSUME && receipt.submit_result==VIREO_OK);
    CHECK(receipt.state==VIREO_AUTH_REQUEST_HEAD_NEEDS_CONSUME && receipt.submit_report.login_charged &&
        receipt.submit_report.submit_report.task_transferred && f.remaining==NULL);
    pending_bytes(&f,first,n);
    for(unsigned i=0;i<3;++i) {
        r=head(&f,&receipt,&s,VIREO_RESULT_BUSY); CHECK(!r.frame_peek_called && !r.submit_called);
        EXPECT(vireo_auth_request_head_acknowledge(&receipt),VIREO_RESULT_BUSY);
    }
    CHECK(s.frames==1 && s.reads==1 && s.submits==1 && s.consumes==1);
    /* 原登记已由caller取走也不影响消费恢复；这不是伪造worker完成。 */
    vireo_task_metadata_t taken;
    EXPECT(vireo_inflight_store_take(f.store,f.accepted[0],&taken,NULL),VIREO_OK); f.submitted=0;
    s.consume_error=VIREO_OK;
    EXPECT(vireo_auth_request_head_resume_with(f.server,&receipt,&r,&ops,&s),VIREO_OK);
    CHECK(!r.submit_called && s.submits==1 && s.consumes==2 && receipt.state==VIREO_AUTH_REQUEST_HEAD_CONSUMED);
    EXPECT(vireo_auth_request_head_resume_with(f.server,&receipt,&r,&ops,&s),VIREO_RESULT_NOT_FOUND);
    CHECK(s.consumes==2); pending_bytes(&f,NULL,0); ack(&receipt);

    uint8_t pipeline[312]; size_t second=make_wire(pipeline,true,22,"ALICE_7",255);
    size_t third=make_wire(pipeline+second,true,23,"alice_7",17);
    receive_wire(&f,pipeline,second+third,&p); p=NULL;
    s.consume_error=VIREO_RESULT_IO;
    r=head(&f,&receipt,&s,VIREO_RESULT_BUSY);
    CHECK(r.stage==VIREO_AUTH_REQUEST_HEAD_SUBMIT && r.consume_result==VIREO_RESULT_IO);
    CHECK(receipt.submit_result==VIREO_RESULT_BUSY && receipt.submit_report.login_charged &&
        receipt.submit_report.submit_report.task_retained && !receipt.submit_report.submit_report.task_transferred);
    CHECK(f.remaining!=NULL && receipt.sequence==22);
    EXPECT(vireo_task_destroy(&f.remaining),VIREO_OK);
    for(unsigned i=0;i<3;++i) (void)head(&f,&receipt,&s,VIREO_RESULT_BUSY);
    CHECK(s.submits==2 && s.consumes==3);
    pending_bytes(&f,pipeline,second+third);
    s.consume_error=VIREO_OK;
    EXPECT(vireo_auth_request_head_resume_with(f.server,&receipt,&r,&ops,&s),VIREO_OK);
    CHECK(receipt.submit_result==VIREO_RESULT_BUSY && receipt.submit_report.login_charged);
    pending_bytes(&f,pipeline+second,third); ack(&receipt);
    r=head(&f,&receipt,NULL,VIREO_RESULT_BUSY);
    CHECK(receipt.sequence==23 && receipt.state==VIREO_AUTH_REQUEST_HEAD_CONSUMED);
    CHECK(receipt.submit_report.admission_decided && receipt.submit_report.decision.outcome==VIREO_RATE_LIMIT_THROTTLED &&
        !receipt.submit_report.login_charged && !receipt.submit_report.submit_called && !receipt.submit_report.submit_report.metadata_created);
    CHECK(receipt.submit_report.decision.retry_after_ns==UINT64_C(30000000000));
    pending_bytes(&f,NULL,0); ack(&receipt);
    memset(first,0,sizeof first); memset(pipeline,0,sizeof pipeline);
    end_worker(&f); CHECK(f.worker.executed==1 && f.worker.command==VIREO_COMMAND_LOGIN);
    cleanup(&f); ++groups;
}

static void transferred_error_stale(void) {
    fixture_t f; setup(&f,true); start_worker(&f);
    uint8_t wire[156]; size_t n=make_wire(wire,true,31,"Alice_7",0);
    memcpy(f.worker.expected,wire,n); f.worker.size=n;
    uint8_t const *p=NULL; receive_wire(&f,wire,n,&p); p=NULL;
    vireo_auth_request_head_receipt_t receipt={0};
    script_t s={.consume_error=VIREO_RESULT_IO,.after_submit_error=VIREO_RESULT_INTERNAL};
    vireo_auth_request_head_report_t r=head(&f,&receipt,&s,VIREO_RESULT_INTERNAL);
    CHECK(r.stage==VIREO_AUTH_REQUEST_HEAD_SUBMIT && r.consume_result==VIREO_RESULT_IO &&
        receipt.submit_report.submit_report.task_transferred && receipt.submit_report.login_charged && f.remaining==NULL);
    vireo_auth_request_head_receipt_t before=receipt;
    EXPECT(vireo_tcp_server_release_client(f.server,&f.client,NULL),VIREO_OK);
    EXPECT(vireo_auth_request_head_resume_consume(f.server,&receipt,&r),VIREO_RESULT_NOT_FOUND);
    CHECK(receipt.state==before.state && receipt.client.pool_id==before.client.pool_id &&
        receipt.client.generation==before.client.generation && receipt.submit_result==VIREO_RESULT_INTERNAL);
    CHECK(r.consume_called && !r.submit_called); EXPECT(vireo_auth_request_head_acknowledge(&receipt),VIREO_RESULT_BUSY);
    /* 已明确归还原租约，保留before审计值后弃置门禁，不把NOT_FOUND当消费成功。 */
    receipt=(vireo_auth_request_head_receipt_t){0};
    end_worker(&f); CHECK(f.worker.executed==1); cleanup(&f); ++groups;
}

static void schema_framing_partial(void) {
    fixture_t f; setup(&f,true);
    uint8_t wire[156]; size_t n=make_wire(wire,true,41,"Alice_7",0);
    /* 认证schema非法但通用framing/CRC可信；拒绝仍消费且保command/sequence。 */
    wire[32+4]='!'; vireo_protocol_header_t h; vireo_protocol_codec_issue_t issue;
    EXPECT(vireo_protocol_header_decode(wire,32,&h,&issue),VIREO_OK);
    EXPECT(vireo_protocol_frame_crc32c_calculate(wire,32,wire+32,n-32,&h.crc32c),VIREO_OK);
    EXPECT(vireo_protocol_header_encode(&h,wire,32),VIREO_OK);
    uint8_t const *p=NULL; receive_wire(&f,wire,n,&p); p=NULL;
    vireo_auth_request_head_receipt_t receipt={0};
    vireo_auth_request_head_report_t r=head(&f,&receipt,NULL,VIREO_RESULT_PROTOCOL);
    CHECK(r.receipt_committed && receipt.state==VIREO_AUTH_REQUEST_HEAD_CONSUMED && receipt.sequence==41 &&
        receipt.command==VIREO_COMMAND_LOGIN && !receipt.submit_report.input_validated && !receipt.submit_report.admission_called);
    pending_bytes(&f,NULL,0); ack(&receipt);
    n=make_wire(wire,true,42,"Alice_7",0); wire[n-1]^=1;
    receive_wire(&f,wire,n,&p); p=NULL; r=head(&f,&receipt,NULL,VIREO_RESULT_PROTOCOL);
    CHECK(r.stage==VIREO_AUTH_REQUEST_HEAD_PEEK_FRAME && !r.submit_called && !r.consume_called && receipt.state==VIREO_AUTH_REQUEST_HEAD_EMPTY);
    pending_bytes(&f,wire,n); EXPECT(vireo_tcp_server_client_read_consume(f.server,f.client,n,NULL),VIREO_OK);
    n=make_wire(wire,true,43,"Alice_7",0);
    receive_wire(&f,wire,10,&p); p=NULL; r=head(&f,&receipt,NULL,VIREO_OK);
    CHECK(r.frame_info.frame_count==0 && !r.submit_called && !r.consume_called);
    pending_bytes(&f,wire,10); EXPECT(vireo_tcp_server_client_read_consume(f.server,f.client,10,NULL),VIREO_OK);
    cleanup(&f); ++groups;
}

static void dependency_and_arguments(void) {
    fixture_t f; setup(&f,true);
    uint8_t wire[156]; size_t n=make_wire(wire,false,51,"Alice_7",0); uint8_t const *p=NULL;
    receive_wire(&f,wire,n,&p); p=NULL;
    vireo_auth_request_head_receipt_t receipt={0}; script_t s={.frame_error=VIREO_RESULT_IO};
    vireo_auth_request_head_report_t r=head(&f,&receipt,&s,VIREO_RESULT_IO);
    CHECK(r.stage==VIREO_AUTH_REQUEST_HEAD_PEEK_FRAME && s.reads==0 && !r.receipt_committed);
    s=(script_t){.read_error=VIREO_RESULT_IO}; r=head(&f,&receipt,&s,VIREO_RESULT_IO);
    CHECK(r.stage==VIREO_AUTH_REQUEST_HEAD_PEEK_BYTES && s.submits==0 && s.consumes==0);
    s=(script_t){.bad_count=true}; (void)head(&f,&receipt,&s,VIREO_RESULT_INTERNAL); CHECK(s.reads==0);
    s=(script_t){.short_read=true}; (void)head(&f,&receipt,&s,VIREO_RESULT_INTERNAL); CHECK(s.submits==0);
    s=(script_t){.null_read=true}; (void)head(&f,&receipt,&s,VIREO_RESULT_INTERNAL); CHECK(s.submits==0);
    vireo_auth_request_submit_options_t o=options;
    for(unsigned i=0;i<6;++i) {
        o=options;
        if(i==0) o.task_allocation_budget=0;
        if(i==1) o.max_client_requests=0;
        if(i==2) o.register_operation=0;
        if(i==3) o.login_operation=0;
        if(i==4) o.login_operation=o.register_operation;
        if(i==5) o.task_allocation_budget=VIREO_TASK_MAX_ALLOCATION_BYTES+1;
        s=(script_t){0};
        EXPECT(vireo_auth_request_head_with(f.server,f.client,f.store,f.pool,f.admission,0,f.sessions,0,&o,NULL,
            &receipt,&f.remaining,&r,&ops,&s),i==5?VIREO_RESULT_RANGE:VIREO_RESULT_INVALID_ARGUMENT);
        CHECK(s.frames==0 && !r.submit_called && receipt.state==VIREO_AUTH_REQUEST_HEAD_EMPTY);
    }
    EXPECT(vireo_auth_request_head_acknowledge(NULL),VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_auth_request_head_acknowledge(&receipt),VIREO_RESULT_NOT_FOUND);
    EXPECT(vireo_auth_request_head_resume_consume(f.server,&receipt,&r),VIREO_RESULT_NOT_FOUND);
    for(unsigned i=0;i<5;++i) {
        receipt=(vireo_auth_request_head_receipt_t){.state=VIREO_AUTH_REQUEST_HEAD_NEEDS_CONSUME,
            .client=f.client,.frame_bytes=n,.sequence=51,.command=VIREO_COMMAND_REGISTER};
        if(i==0) receipt.state=(vireo_auth_request_head_state_t)99;
        if(i==1) receipt.client.pool_id=0;
        if(i==2) receipt.client.generation=0;
        if(i==3) receipt.frame_bytes=157;
        if(i==4) receipt.sequence=0;
        s=(script_t){0}; (void)head(&f,&receipt,&s,VIREO_RESULT_INVALID_ARGUMENT);
        EXPECT(vireo_auth_request_head_resume_consume(f.server,&receipt,&r),VIREO_RESULT_INVALID_ARGUMENT);
        EXPECT(vireo_auth_request_head_acknowledge(&receipt),VIREO_RESULT_INVALID_ARGUMENT);
        CHECK(s.frames==0);
    }
    receipt=(vireo_auth_request_head_receipt_t){0};
    EXPECT(vireo_auth_request_submit_read_head(NULL,f.client,f.store,f.pool,f.admission,0,f.sessions,0,&options,NULL,
        &receipt,&f.remaining,&r),VIREO_RESULT_INVALID_ARGUMENT); CHECK(!r.frame_peek_called);
    EXPECT(vireo_auth_request_head_resume_consume(NULL,&receipt,&r),VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_auth_request_head_resume_consume(f.server,NULL,&r),VIREO_RESULT_INVALID_ARGUMENT);
    pending_bytes(&f,wire,n); EXPECT(vireo_tcp_server_client_read_consume(f.server,f.client,n,NULL),VIREO_OK);
    cleanup(&f); ++groups;
}

int main(void) {
    CHECK(signal(SIGPIPE,SIG_IGN)!=SIG_ERR); size_t const before=fds();
    real_register(); queue_consume_recovery(); transferred_error_stale(); schema_framing_partial(); dependency_and_arguments();
    size_t const after=fds(); CHECK(before==after);
    printf("auth_request_head: %u groups, %u checks, fd %zu -> %zu\n",groups,
        atomic_load_explicit(&checks,memory_order_relaxed),before,after); return 0;
}
