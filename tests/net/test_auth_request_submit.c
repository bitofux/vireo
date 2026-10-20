#define _GNU_SOURCE
#include "auth_request_submit_internal.h"
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
static void consume(fixture_t *f,size_t n) {
    EXPECT(vireo_tcp_server_client_read_consume(f->server,f->client,n,NULL),VIREO_OK);
    uint8_t const *p; size_t bytes;
    EXPECT(vireo_tcp_server_client_read_peek(f->server,f->client,&p,&bytes,NULL),VIREO_OK); CHECK(bytes==0);
}
static vireo_auth_request_submit_report_t submit(fixture_t *f,uint8_t const *wire,size_t n,vireo_result_t rc) {
    vireo_auth_request_submit_report_t r; memset(&r,0xa5,sizeof(r));
    EXPECT(vireo_auth_request_copy_try_submit(f->server,f->client,f->store,f->pool,f->admission,0,f->sessions,0,
        wire,n,&options,NULL,&f->remaining,&r),rc);
    if(r.submit_report.task_transferred) {
        CHECK(f->submitted<8); f->accepted[f->submitted++]=r.submit_report.metadata;
    }
    return r;
}

static void real_register(void) {
    fixture_t f; setup(&f,true); start_worker(&f);
    uint8_t wire[156]; size_t const n=make_wire(wire,false,1,"Alice_7",0);
    memcpy(f.worker.expected,wire,n); f.worker.size=n;
    uint8_t const *input=NULL; receive_wire(&f,wire,n,&input);
    vireo_auth_request_submit_report_t r=submit(&f,input,n,VIREO_OK);
    CHECK(r.stage==VIREO_AUTH_REQUEST_SUBMIT_NONE && r.transport_ready && r.input_validated);
    CHECK(!r.peer_called && !r.admission_called && !r.admission_decided && !r.login_charged);
    CHECK(r.submit_called && r.submit_report.task_transferred && f.remaining==NULL);
    CHECK(r.submit_report.metadata.operation==101);
    uint8_t const *same=NULL; size_t bytes=0;
    EXPECT(vireo_tcp_server_client_read_peek(f.server,f.client,&same,&bytes,NULL),VIREO_OK);
    CHECK(same==input && bytes==n && memcmp(input,wire,n)==0);
    consume(&f,n); memset(wire,0,sizeof(wire)); end_worker(&f);
    CHECK(f.worker.executed==1 && f.worker.command==VIREO_COMMAND_REGISTER);
    cleanup(&f); ++groups;
}
static void real_queue_and_no_refund(void) {
    fixture_t f; setup(&f,true); start_worker(&f);
    uint8_t wire[156]; size_t n=make_wire(wire,true,1,"Alice_7",0);
    memcpy(f.worker.expected,wire,n); f.worker.size=n;
    uint8_t const *input=NULL; receive_wire(&f,wire,n,&input);
    vireo_auth_request_submit_report_t r=submit(&f,input,n,VIREO_OK);
    CHECK(r.peer_called && r.peer.family==4 && r.peer.address[0]==127 && r.peer.address[3]==1);
    CHECK(r.admission_decided && r.login_charged && r.decision.outcome==VIREO_RATE_LIMIT_ADMITTED);
    CHECK(r.submit_report.task_transferred && r.submit_report.metadata.operation==102);
    consume(&f,n);
    n=make_wire(wire,true,2,"ALICE_7",255); receive_wire(&f,wire,n,&input);
    r=submit(&f,input,n,VIREO_RESULT_BUSY);
    CHECK(r.stage==VIREO_AUTH_REQUEST_SUBMIT_QUEUE && r.login_charged && r.submit_called);
    CHECK(r.submit_report.task_created && !r.submit_report.task_transferred && r.submit_report.task_retained);
    CHECK(f.remaining!=NULL); EXPECT(vireo_task_destroy(&f.remaining),VIREO_OK); consume(&f,n);
    n=make_wire(wire,true,3,"alice_7",17); receive_wire(&f,wire,n,&input);
    r=submit(&f,input,n,VIREO_RESULT_BUSY);
    CHECK(r.stage==VIREO_AUTH_REQUEST_SUBMIT_ADMISSION && r.admission_decided);
    CHECK(r.decision.outcome==VIREO_RATE_LIMIT_THROTTLED && !r.login_charged && !r.submit_called);
    CHECK(r.decision.retry_after_ns==UINT64_C(30000000000)); consume(&f,n);
    memset(wire,0,sizeof(wire)); end_worker(&f);
    CHECK(f.worker.executed==1 && f.worker.command==VIREO_COMMAND_LOGIN);
    cleanup(&f); ++groups;
}

/* 本组件own seam：全部opaque资源仍是真实owner；模拟交接也保持唯一task owner。 */
typedef struct script {
    vireo_result_t ready_rc,peer_rc,submit_rc;
    char order[8]; unsigned calls;
    bool create,transfer;
    vireo_task_t *held;
    uint32_t operation;
} script_t;
static void trace(script_t *s,char c) { CHECK(s->calls<7); s->order[s->calls++]=c; s->order[s->calls]=0; }
static vireo_result_t mock_ready(void *context,vireo_tcp_server_t *server,vireo_connection_pool_lease_t client,
    vireo_tcp_server_tls_error_t *lookup,vireo_tls_connection_error_t *error) {
    script_t *s=context; CHECK(server!=NULL && client.pool_id!=0); trace(s,'R');
    *lookup=(vireo_tcp_server_tls_error_t){0}; *error=(vireo_tls_connection_error_t){0}; errno=EINTR; return s->ready_rc;
}
static vireo_result_t mock_peer(void *context,vireo_tcp_server_t const *server,vireo_connection_pool_lease_t client,
    vireo_connection_peer_t *peer,vireo_tcp_server_client_error_t *error) {
    script_t *s=context; CHECK(server!=NULL && client.pool_id!=0); trace(s,'P');
    *error=(vireo_tcp_server_client_error_t){0};
    if(s->peer_rc==VIREO_OK) *peer=(vireo_connection_peer_t){.family=4,.address={127,0,0,1}};
    else { error->primary.stage=VIREO_TCP_SERVER_CLIENT_QUERY_PEER; error->primary.connection_error.system_errno=EINTR; }
    errno=EIO; return s->peer_rc;
}
static vireo_result_t mock_submit(void *context,vireo_tcp_server_t const *server,vireo_connection_pool_lease_t client,
    vireo_inflight_store_t *store,vireo_thread_pool_t *pool,uint8_t const *wire,size_t n,size_t cap,
    size_t allocation,size_t limit,uint32_t operation,uint64_t deadline,vireo_task_cancel_t *cancel,
    vireo_task_t **owner,vireo_async_request_report_t *report) {
    script_t *s=context; CHECK(server && store && pool && cancel==NULL); trace(s,'S');
    CHECK(cap==156 && allocation==65536 && limit==8 && deadline==UINT64_MAX && *owner==NULL);
    *report=(vireo_async_request_report_t){0}; s->operation=operation;
    if(s->create) {
        vireo_auth_request_view_t v; vireo_auth_request_issue_t issue;
        CHECK(vireo_auth_request_decode(wire,n,&v,&issue)==VIREO_OK);
        vireo_task_route_t route; vireo_task_metadata_t m;
        CHECK(vireo_task_route_make(client.pool_id,client.slot_index,client.generation,v.sequence,&route)==VIREO_OK);
        CHECK(vireo_task_metadata_make(route,1,operation,deadline,&m)==VIREO_OK);
        CHECK(vireo_task_create_copy(m,wire,n,allocation,owner)==VIREO_OK);
        report->metadata=m; report->metadata_created=true; report->task_created=true;
        if(s->transfer) {
            CHECK(vireo_task_move(owner,&s->held)==VIREO_OK); report->task_transferred=true;
            report->submit_report.pool_report.queue_report.transferred=true;
        } else report->task_retained=true;
    }
    errno=EAGAIN; return s->submit_rc;
}
static vireo_auth_request_submit_ops_t const scripted={mock_ready,mock_peer,mock_submit};
static vireo_auth_request_submit_report_t injected(fixture_t *f,script_t *s,uint8_t const *wire,size_t n,
    vireo_monotonic_ns_t now,vireo_result_t result) {
    vireo_auth_request_submit_report_t report; memset(&report,0xa5,sizeof(report));
    EXPECT(vireo_auth_request_submit_with(f->server,f->client,f->store,f->pool,f->admission,now,f->sessions,0,
        wire,n,&options,NULL,&f->remaining,&report,&scripted,s),result); return report;
}
static void own_failures(void) {
    fixture_t f; setup(&f,false); uint8_t wire[156];
    vireo_result_t const failures[]={VIREO_RESULT_BUSY,VIREO_RESULT_NOT_FOUND,VIREO_RESULT_IO};
    for(size_t i=0;i<sizeof(failures)/sizeof(failures[0]);++i) {
        fresh_admission(&f,1);
        size_t n=make_wire(wire,true,1,"Alice_7",0);
        script_t s={.ready_rc=failures[i]};
        vireo_auth_request_submit_report_t r=injected(&f,&s,wire,n,0,failures[i]);
        CHECK(r.stage==VIREO_AUTH_REQUEST_SUBMIT_TRANSPORT && !r.peer_called && !r.admission_called && !r.submit_called);
        CHECK(strcmp(s.order,"R")==0);
        s=(script_t){.peer_rc=failures[i]};
        n=make_wire(wire,true,2,"Alice_7",0); r=injected(&f,&s,wire,n,0,failures[i]);
        CHECK(r.stage==VIREO_AUTH_REQUEST_SUBMIT_PEER && !r.admission_called && !r.submit_called);
        CHECK(strcmp(s.order,"RP")==0 && r.peer_error.primary.connection_error.system_errno==EINTR);
        s=(script_t){.submit_rc=VIREO_RESULT_NO_MEMORY};
        n=make_wire(wire,true,3,"ALICE_7",1); r=injected(&f,&s,wire,n,0,VIREO_RESULT_NO_MEMORY);
        CHECK(r.login_charged && r.admission_decided && r.stage==VIREO_AUTH_REQUEST_SUBMIT_QUEUE);
        CHECK(strcmp(s.order,"RPS")==0 && !r.submit_report.task_created && f.remaining==NULL);
        s=(script_t){0}; n=make_wire(wire,true,4,"alice_7",2); r=injected(&f,&s,wire,n,0,VIREO_RESULT_BUSY);
        CHECK(!r.login_charged && !r.submit_called && r.decision.outcome==VIREO_RATE_LIMIT_THROTTLED);
        CHECK(strcmp(s.order,"RP")==0);
    }
    for(unsigned transferred=0;transferred<2;++transferred) {
        fresh_admission(&f,1);
        size_t n=make_wire(wire,true,1,"Alice_7",0);
        script_t s={.submit_rc=VIREO_RESULT_IO,.create=true,.transfer=transferred!=0};
        vireo_auth_request_submit_report_t r=injected(&f,&s,wire,n,0,VIREO_RESULT_IO);
        CHECK(r.login_charged && r.submit_called && r.submit_report.task_created);
        CHECK(r.submit_report.task_transferred==(transferred!=0));
        CHECK((f.remaining!=NULL)==(transferred==0) && (s.held!=NULL)==(transferred!=0));
        EXPECT(vireo_task_destroy(&f.remaining),VIREO_OK); EXPECT(vireo_task_destroy(&s.held),VIREO_OK);
        s=(script_t){0}; n=make_wire(wire,true,2,"ALICE_7",4); r=injected(&f,&s,wire,n,0,VIREO_RESULT_BUSY);
        CHECK(!r.submit_called && r.decision.outcome==VIREO_RATE_LIMIT_THROTTLED);
    }
    fresh_admission(&f,1);
    script_t s={0}; size_t n=make_wire(wire,true,1,"Alice_7",0); wire[n-1]^=1;
    vireo_auth_request_submit_report_t r=injected(&f,&s,wire,n,0,VIREO_RESULT_PROTOCOL);
    CHECK(r.stage==VIREO_AUTH_REQUEST_SUBMIT_DECODE && !r.input_validated && s.calls==0);
    n=make_wire(wire,false,2,"Alice_7",0); s=(script_t){.submit_rc=VIREO_RESULT_NO_MEMORY};
    r=injected(&f,&s,wire,n,0,VIREO_RESULT_NO_MEMORY);
    CHECK(strcmp(s.order,"RS")==0 && s.operation==101 && !r.peer_called && !r.admission_called);
    n=make_wire(wire,true,3,"ALICE_7",0); s=(script_t){.submit_rc=VIREO_RESULT_NO_MEMORY};
    r=injected(&f,&s,wire,n,0,VIREO_RESULT_NO_MEMORY); CHECK(r.login_charged && s.operation==102);
    /* 过载容量是合法判定，不能因decision零初始化误以为ADMITTED。 */
    EXPECT(vireo_auth_login_admission_destroy(&f.admission),VIREO_OK);
    vireo_auth_login_admission_options_t a=VIREO_AUTH_LOGIN_ADMISSION_OPTIONS_DEFAULT; a.max_keys=2;
    EXPECT(vireo_auth_login_admission_create(&a,0,&f.admission),VIREO_OK);
    s=(script_t){0}; n=make_wire(wire,true,4,"Alice_7",0); r=injected(&f,&s,wire,n,0,VIREO_RESULT_BUSY);
    CHECK(r.admission_decided && r.decision.outcome==VIREO_RATE_LIMIT_CAPACITY && !r.login_charged && !r.submit_called);
    fresh_admission(&f,2); s=(script_t){.submit_rc=VIREO_RESULT_NO_MEMORY};
    n=make_wire(wire,true,5,"Alice_7",0); r=injected(&f,&s,wire,n,2,VIREO_RESULT_NO_MEMORY); CHECK(r.login_charged);
    s=(script_t){0}; n=make_wire(wire,true,6,"Alice_7",0); r=injected(&f,&s,wire,n,1,VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(r.admission_called && !r.admission_decided && !r.login_charged && !r.submit_called);
    cleanup(&f); ++groups;
}

static void argument_contracts(void) {
    fixture_t f; setup(&f,false); uint8_t wire[156]; size_t const n=make_wire(wire,true,1,"Alice_7",0);
    vireo_auth_request_submit_report_t report;
    for(unsigned which=0;which<13;++which) {
        vireo_auth_request_submit_options_t o=options;
        script_t s={0}; vireo_auth_request_submit_ops_t ops=scripted;
        if(which==8) o.task_allocation_budget=0;
        if(which==9) o.max_client_requests=0;
        if(which==10) o.register_operation=0;
        if(which==11) o.login_operation=0;
        if(which==12) o.login_operation=o.register_operation;
        memset(&report,0xa5,sizeof(report));
        EXPECT(vireo_auth_request_submit_with(which==0?NULL:f.server,f.client,which==1?NULL:f.store,
            which==2?NULL:f.pool,which==3?NULL:f.admission,0,f.sessions,0,which==4?NULL:wire,n,
            which==5?NULL:&o,NULL,which==6?NULL:&f.remaining,which==7?NULL:&report,&ops,&s),
            VIREO_RESULT_INVALID_ARGUMENT);
        CHECK(s.calls==0 && f.remaining==NULL);
        if(which!=7) CHECK(report.stage==VIREO_AUTH_REQUEST_SUBMIT_NONE && !report.input_validated && !report.login_charged);
    }
    vireo_auth_request_submit_options_t o=options; o.task_allocation_budget=VIREO_TASK_MAX_ALLOCATION_BYTES+1;
    script_t s={0};
    EXPECT(vireo_auth_request_submit_with(f.server,f.client,f.store,f.pool,f.admission,0,f.sessions,0,wire,n,&o,NULL,
        &f.remaining,&report,&scripted,&s),VIREO_RESULT_RANGE); CHECK(s.calls==0);
    vireo_auth_request_submit_ops_t bad=scripted; bad.peer=NULL;
    EXPECT(vireo_auth_request_submit_with(f.server,f.client,f.store,f.pool,f.admission,0,f.sessions,0,wire,n,&options,NULL,
        &f.remaining,&report,&bad,&s),VIREO_RESULT_INVALID_ARGUMENT); CHECK(s.calls==0);
    vireo_task_route_t route; vireo_task_metadata_t m;
    EXPECT(vireo_task_route_make(1,0,1,1,&route),VIREO_OK);
    EXPECT(vireo_task_metadata_make(route,1,101,1,&m),VIREO_OK);
    EXPECT(vireo_task_create_copy(m,wire,n,65536,&f.remaining),VIREO_OK);
    vireo_task_t *original=f.remaining;
    EXPECT(vireo_auth_request_submit_with(f.server,f.client,f.store,f.pool,f.admission,0,f.sessions,0,wire,n,&options,NULL,
        &f.remaining,&report,&scripted,&s),VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(f.remaining==original && s.calls==0); cleanup(&f); ++groups;
}
static void real_transport_rejections(void) {
    uint8_t wire[156]; size_t const n=make_wire(wire,true,1,"Alice_7",0);
    fixture_t f; setup(&f,false);
    vireo_auth_request_submit_report_t r=submit(&f,wire,n,VIREO_RESULT_BUSY);
    CHECK(r.stage==VIREO_AUTH_REQUEST_SUBMIT_TRANSPORT && !r.transport_ready && !r.admission_called);
    cleanup(&f);
    setup(&f,true); vireo_tcp_server_tls_close_request_info_t closing;
    EXPECT(vireo_tcp_server_client_tls_close_request(f.server,f.client,UINT64_C(1000000000),&closing,NULL),VIREO_OK);
    r=submit(&f,wire,n,VIREO_RESULT_BUSY); CHECK(!r.admission_called && !r.submit_called); cleanup(&f);
    setup(&f,true); EXPECT(vireo_tcp_server_request_stop(f.server,NULL),VIREO_OK);
    r=submit(&f,wire,n,VIREO_RESULT_CANCELLED); CHECK(!r.peer_called && !r.admission_called); cleanup(&f);
    setup(&f,true); vireo_connection_pool_lease_t stale=f.client;
    EXPECT(vireo_tcp_server_release_client(f.server,&f.client,NULL),VIREO_OK);
    EXPECT(vireo_auth_request_copy_try_submit(f.server,stale,f.store,f.pool,f.admission,0,f.sessions,0,wire,n,&options,NULL,
        &f.remaining,&r),VIREO_RESULT_NOT_FOUND);
    CHECK(!r.peer_called && !r.admission_called); cleanup(&f);
    setup(&f,false); EXPECT(vireo_tcp_server_release_client(f.server,&f.client,NULL),VIREO_OK);
    EXPECT(vireo_auth_sessions_destroy(&f.sessions),VIREO_OK);
    EXPECT(vireo_tcp_server_destroy(&f.server,NULL),VIREO_OK);
    vireo_tcp_server_options_t const raw={1,2,1048576,32768};
    EXPECT(vireo_tcp_server_create(&raw,&f.server,NULL),VIREO_OK);
    vireo_auth_sessions_options_t const session_options={65536};
    EXPECT(vireo_auth_sessions_create(f.server,&session_options,&f.sessions),VIREO_OK);
    r=submit(&f,wire,n,VIREO_RESULT_BUSY); CHECK(!r.admission_called && !r.submit_called); cleanup(&f); ++groups;
}
static void logout_local_rejections(void) {
    fixture_t f; setup(&f,true);
    vireo_auth_session_identity_t const identity={7,8,100,200,false}; vireo_auth_session_ticket_t ticket;
    EXPECT(vireo_auth_session_reserve(f.sessions,f.client,&identity,&ticket),VIREO_OK);
    EXPECT(vireo_auth_session_commit(f.sessions,ticket),VIREO_OK);
    uint8_t wire[32];
    for(unsigned mode=0;mode<3;++mode) {
        vireo_protocol_header_t h={.command=VIREO_COMMAND_LOGOUT,.sequence=1,.session_handle=mode==0?0:ticket.handle};
        EXPECT(vireo_protocol_header_encode(&h,wire,32),VIREO_OK);
        EXPECT(vireo_protocol_frame_crc32c_calculate(wire,32,NULL,0,&h.crc32c),VIREO_OK);
        EXPECT(vireo_protocol_header_encode(&h,wire,32),VIREO_OK);
        if(mode==2) EXPECT(vireo_auth_session_revoke(f.sessions,8),VIREO_OK);
        vireo_auth_request_submit_report_t report;
        EXPECT(vireo_auth_request_copy_try_submit(f.server,f.client,f.store,f.pool,f.admission,0,f.sessions,200,
            wire,32,&options,NULL,&f.remaining,&report),mode==0?VIREO_RESULT_PROTOCOL:mode==1?VIREO_RESULT_TIMEOUT:VIREO_RESULT_CANCELLED);
        CHECK(!f.remaining && !report.submit_called && !report.admission_called && !report.trusted_identity_attached);
        CHECK(report.stage==(mode==0?VIREO_AUTH_REQUEST_SUBMIT_DECODE:VIREO_AUTH_REQUEST_SUBMIT_SESSION));
    }
    cleanup(&f); ++groups;
}
int main(void) {
    atomic_init(&checks,0);
    struct sigaction ignore={0},previous;
    ignore.sa_handler=SIG_IGN; CHECK(sigemptyset(&ignore.sa_mask)==0);
    CHECK(sigaction(SIGPIPE,&ignore,&previous)==0);
    size_t const before=fds();
    logout_local_rejections(); argument_contracts(); own_failures(); real_transport_rejections(); real_register(); real_queue_and_no_refund();
    size_t const after=fds(); CHECK(before==after);
    CHECK(sigaction(SIGPIPE,&previous,NULL)==0);
    printf("auth_request_submit: %u groups, %u executed checks; real TLS/peer/admission/task/worker; FD %zu -> %zu\n",
        groups,atomic_load_explicit(&checks,memory_order_relaxed),before,after);
    return 0;
}
