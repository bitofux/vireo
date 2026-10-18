/*
 * PROJECT : VIREO
 * FILE    : test_completion_response_tls.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-18
 * BRIEF   : TLS真实单帧回写、提交前缀恢复及显式worker/notifier链
 */
#define _GNU_SOURCE
#include "completion_response_internal.h"
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

/** Reactor独占测试根，全部经公开接口创建/借用/回收。 */
typedef struct fixture {
    vireo_tcp_server_t *server; /**< 根owner，预留1辅助登记。 */
    vireo_connection_pool_lease_t client; /**< 当前客户完整租约，不保活。 */
    int peer; /**< 对端fd owner，-1为空。 */
    SSL *ssl; /**< 可信TLS1.3对端owner，不传worker。 */
    vireo_inflight_store_t *store; /**< 固定8条登记owner。 */
    vireo_completion_t *completion; /**< 当前结果owner，可空。 */
    vireo_inflight_completion_match_t match; /**< 本项原成功匹配值。 */
    unsigned enqueues; /**< own seam实际入队调用次数。 */
    unsigned refreshes; /**< own seam实际刷新调用次数。 */
    unsigned fault; /**< 0正常，1入队BUSY，2刷新IO并模型queue失败。 */
    unsigned delivered; /**< 真实消费链回调次数，验证恰好一次。 */
} fixture_t;
static vireo_completion_response_descriptor_t const descriptor = {
    VIREO_COMMAND_NODE_STAT,0,UINT32_C(0x10203040),UINT32_MAX};
static vireo_tls_io_budget_t const io_budget = {4096,8};
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
static void prepare(fixture_t *f,uint8_t const *body,size_t size) {
    CHECK(f->completion==NULL); vireo_task_metadata_t request;
    EXPECT(vireo_inflight_metadata_make_next(f->server,f->client,101,9,UINT64_MAX,&request,NULL),VIREO_OK);
    EXPECT(vireo_inflight_store_register(f->store,f->server,request,NULL),VIREO_OK);
    vireo_completion_metadata_t m;
    EXPECT(vireo_completion_metadata_make(request,VIREO_RESULT_DATABASE,VIREO_STATUS_INTERNAL_ERROR,&m),VIREO_OK);
    EXPECT(vireo_completion_create_copy(m,body,size,65536,&f->completion),VIREO_OK);
    EXPECT(vireo_inflight_store_check_completion(f->store,f->server,f->completion,&f->match,NULL),VIREO_OK);
}
static void cleanup(fixture_t *f) {
    if(f->completion) {
        vireo_task_metadata_t removed;
        EXPECT(vireo_inflight_store_take(f->store,f->match.metadata,&removed,NULL),VIREO_OK);
        EXPECT(vireo_completion_destroy(&f->completion),VIREO_OK);
    }
    EXPECT(vireo_inflight_store_destroy(&f->store),VIREO_OK);
    if(f->client.pool_id) EXPECT(vireo_tcp_server_release_client(f->server,&f->client,NULL),VIREO_OK);
    SSL_free(f->ssl); if(f->peer>=0) CHECK(close(f->peer)==0);
    EXPECT(vireo_tcp_server_destroy(&f->server,NULL),VIREO_OK);
}
static vireo_completion_response_tls_report_t response(fixture_t *f,size_t cap,uint8_t *work,size_t size,vireo_result_t result) {
    vireo_completion_response_tls_report_t p; memset(&p,0xa5,sizeof p);
    EXPECT(vireo_completion_response_tls_enqueue(f->server,f->completion,f->match,descriptor,cap,work,size,&p),result);
    return p;
}
static void no_commit(vireo_completion_response_tls_report_t p) {
    CHECK(!p.response.enqueue_called && !p.response.enqueued && !p.response.refresh_called && !p.flow.flow_reported);
}
static void send_all(fixture_t *f) {
    for(unsigned k=0;k<128 && state(f).connection_info.write_buffer.readable_size;++k) {
        vireo_tls_io_progress_t p;
        EXPECT(vireo_tls_connection_send(tls(f),&io_budget,&p,NULL),VIREO_OK);
        refresh(f);
    }
    CHECK(state(f).connection_info.write_buffer.readable_size==0);
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
static void real_wire(void) {
    size_t const sizes[]={0,3,4064};
    for(size_t k=0;k<3;++k) {
        fixture_t f; setup(&f,true); uint8_t body[4064],work[4096],wire[4096];
        for(size_t j=0;j<sizeof body;++j) body[j]=(uint8_t)j;
        prepare(&f,body,sizes[k]); vireo_completion_payload_view_t before,after;
        EXPECT(vireo_completion_borrow_payload(f.completion,&before),VIREO_OK);
        vireo_completion_response_tls_report_t p=response(&f,4096,work,sizeof work,VIREO_OK);
        CHECK(p.response.stage==0 && p.response.frame_encoded && p.response.enqueued && p.response.refresh_called && p.flow.flow_reported);
        CHECK(state(&f).connection_info.write_buffer.readable_size==32+sizes[k]);
        CHECK(!state(&f).connection_info.flow_enabled); /* 真实TLS资格，不能靠RAW占位字段。 */
        EXPECT(vireo_completion_borrow_payload(f.completion,&after),VIREO_OK); CHECK(before.data==after.data && before.size==after.size);
        memset(work,0xa5,sizeof work); send_all(&f); read_exact(&f,wire,32+sizes[k]);
        wire_is(wire,32+sizes[k],body,sizes[k],VIREO_STATUS_INTERNAL_ERROR); cleanup(&f); ++groups;
    }
}
static void ranges_and_atomic_full(void) {
    fixture_t f; setup(&f,true); uint8_t body[4065]={0},work[8192]; prepare(&f,body,sizeof body);
    vireo_completion_response_tls_report_t p=response(&f,sizeof work,work,sizeof work,VIREO_RESULT_RANGE);
    CHECK(p.response.stage==VIREO_COMPLETION_RESPONSE_CHECK_FRAME && p.response.frame_bytes==4097); no_commit(p);
    p=response(&f,4096,work,sizeof work,VIREO_RESULT_RANGE); no_commit(p);
    p=response(&f,31,work,sizeof work,VIREO_RESULT_RANGE); no_commit(p);
    p=response(&f,4096,work,4095,VIREO_RESULT_RANGE); no_commit(p); cleanup(&f); ++groups;
    setup(&f,true); uint8_t const body2[]={0,255,42}; prepare(&f,body2,sizeof body2);
    p=response(&f,34,work,sizeof work,VIREO_RESULT_RANGE); no_commit(p);
    uint8_t fill[4096],wire[4096]; memset(fill,0x4c,sizeof fill);
    EXPECT(vireo_tcp_server_client_write_enqueue(f.server,f.client,fill,sizeof fill,NULL),VIREO_OK);
    p=response(&f,4096,work,sizeof work,VIREO_RESULT_RANGE);
    CHECK(p.response.frame_encoded && p.response.enqueue_called && !p.response.enqueued && !p.response.refresh_called);
    CHECK(state(&f).connection_info.write_buffer.readable_size==4096);
    refresh(&f); send_all(&f); read_exact(&f,wire,sizeof wire); CHECK(!memcmp(fill,wire,sizeof wire));
    p=response(&f,4096,work,sizeof work,VIREO_OK); CHECK(p.response.enqueued);
    send_all(&f); read_exact(&f,wire,35); wire_is(wire,35,body2,3,VIREO_STATUS_INTERNAL_ERROR);
    cleanup(&f); ++groups;
}
static void peer_eof_and_failed(void) {
    fixture_t f; setup(&f,true); prepare(&f,NULL,0); uint8_t work[128],wire[32];
    ERR_clear_error(); int rc=SSL_shutdown(f.ssl); CHECK(rc==0 || rc==1);
    bool eof=false;
    for(unsigned k=0;k<1024;++k) {
        vireo_tls_io_progress_t progress;
        EXPECT(vireo_tls_connection_receive(tls(&f),&io_budget,&progress,NULL),VIREO_OK);
        vireo_tls_io_info_t info; EXPECT(vireo_tls_connection_io_inspect(tls(&f),&info,NULL),VIREO_OK);
        if(info.read_eof) { eof=true; break; }
        wait_network(&f);
    }
    CHECK(eof); vireo_completion_response_tls_report_t p=response(&f,128,work,sizeof work,VIREO_OK);
    CHECK(p.response.enqueued); send_all(&f); read_exact(&f,wire,sizeof wire);
    wire_is(wire,32,NULL,0,VIREO_STATUS_INTERNAL_ERROR); cleanup(&f); ++groups;
    setup(&f,true); prepare(&f,NULL,0);
    /* 裸TCP截断触发真实TLS FAILED，随后回写不得进入enqueue。 */
    CHECK(shutdown(f.peer,SHUT_WR)==0); bool failed=false;
    for(unsigned k=0;k<1024;++k) {
        vireo_tls_io_progress_t progress; errno=EDOM;
        vireo_result_t result=vireo_tls_connection_receive(tls(&f),&io_budget,&progress,NULL);
        CHECK(errno==EDOM);
        if(result==VIREO_RESULT_PROTOCOL) { failed=true; break; }
        CHECK(result==VIREO_OK); wait_network(&f);
    }
    CHECK(failed); p=response(&f,128,work,sizeof work,VIREO_RESULT_BUSY); no_commit(p); cleanup(&f); ++groups;
}
static void raw_gate(void) {
    fixture_t f={.peer=-1}; vireo_tcp_server_options_t const so={1,4,1048576,32768};
    EXPECT(vireo_tcp_server_create(&so,&f.server,NULL),VIREO_OK);
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
    prepare(&f,NULL,0); uint8_t work[128];
    vireo_completion_response_tls_report_t p=response(&f,128,work,sizeof work,VIREO_RESULT_BUSY);
    no_commit(p); CHECK(state(&f).connection_info.write_buffer.readable_size==0); cleanup(&f); ++groups;
}
static void long_descriptor(void) {
    fixture_t f; setup(&f,true); prepare(&f,NULL,0); uint8_t work[32],wire[32];
    vireo_completion_response_descriptor_t const d={VIREO_COMMAND_UPLOAD_INIT,VIREO_PROTOCOL_FLAG_LONG_COMMAND,17,23};
    vireo_completion_response_tls_report_t p;
    EXPECT(vireo_completion_response_tls_enqueue(f.server,f.completion,f.match,d,32,work,sizeof work,&p),VIREO_OK);
    send_all(&f); read_exact(&f,wire,sizeof wire); vireo_protocol_header_t h; vireo_protocol_codec_issue_t issue;
    EXPECT(vireo_protocol_header_decode(wire,sizeof wire,&h,&issue),VIREO_OK);
    CHECK(h.command==d.command && h.flags==(VIREO_PROTOCOL_FLAG_RESPONSE|VIREO_PROTOCOL_FLAG_LONG_COMMAND) &&
        h.session_handle==17 && h.task_handle==23 && h.sequence==101 && h.body_len==0);
    EXPECT(vireo_protocol_frame_crc32c_verify(wire,32,wire+32,0,&issue),VIREO_OK); cleanup(&f); ++groups;
}
static void gates(void) {
    uint8_t work[128]; fixture_t f; setup(&f,false); prepare(&f,NULL,0);
    vireo_completion_response_tls_report_t p=response(&f,128,work,sizeof work,VIREO_RESULT_BUSY);
    CHECK(p.response.stage==VIREO_COMPLETION_RESPONSE_CHECK_CLIENT); no_commit(p); cleanup(&f); ++groups;
    setup(&f,true); prepare(&f,NULL,0);
    vireo_tcp_server_tls_close_request_info_t closing;
    EXPECT(vireo_tcp_server_client_tls_close_request(f.server,f.client,UINT64_C(1000000000),&closing,NULL),VIREO_OK);
    p=response(&f,128,work,sizeof work,VIREO_RESULT_BUSY); no_commit(p); cleanup(&f); ++groups;
    setup(&f,true); prepare(&f,NULL,0);
    EXPECT(vireo_tcp_server_request_stop(f.server,NULL),VIREO_OK);
    p=response(&f,128,work,sizeof work,VIREO_RESULT_CANCELLED);
    CHECK(p.response.stage==VIREO_COMPLETION_RESPONSE_CHECK_SERVER); no_commit(p); cleanup(&f); ++groups;
    setup(&f,true); prepare(&f,NULL,0);
    vireo_task_metadata_t const original=f.match.metadata;
    ++f.match.metadata.operation;
    p=response(&f,128,work,sizeof work,VIREO_RESULT_INVALID_ARGUMENT); no_commit(p);
    f.match.metadata=original; --f.match.metadata.deadline_ns;
    p=response(&f,128,work,sizeof work,VIREO_RESULT_INVALID_ARGUMENT); no_commit(p);
    f.match.metadata=original; ++f.match.metadata.request_instance_id;
    p=response(&f,128,work,sizeof work,VIREO_RESULT_INVALID_ARGUMENT); no_commit(p);
    f.match.metadata=original;
    EXPECT(vireo_tcp_server_release_client(f.server,&f.client,NULL),VIREO_OK);
    p=response(&f,128,work,sizeof work,VIREO_RESULT_NOT_FOUND); no_commit(p);
    struct sockaddr_in address; socklen_t n=sizeof address;
    CHECK(getpeername(f.peer,(struct sockaddr *)&address,&n)==0);
    SSL_free(f.ssl); f.ssl=NULL; CHECK(close(f.peer)==0);
    f.peer=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0); CHECK(f.peer>=0);
    CHECK(connect(f.peer,(struct sockaddr *)&address,sizeof address)==0);
    vireo_tcp_server_admit_budget_t const ab={1,2}; vireo_tcp_server_tls_admit_info_t ai;
    EXPECT(vireo_tcp_server_tls_admit_batch(f.server,&ab,&f.client,1,&ai,NULL),VIREO_OK);
    CHECK(f.client.slot_index==original.route.client_slot_index && f.client.generation!=original.route.client_generation);
    p=response(&f,128,work,sizeof work,VIREO_RESULT_NOT_FOUND); no_commit(p);
    CHECK(state(&f).connection_info.write_buffer.readable_size==0); cleanup(&f); ++groups;
}
static vireo_result_t enqueue_hook(void *context,vireo_tcp_server_t *s,vireo_connection_pool_lease_t l,
    uint8_t const *bytes,size_t size,vireo_tcp_server_client_error_t *error) {
    fixture_t *f=context; ++f->enqueues;
    if(f->fault==1) return VIREO_RESULT_BUSY;
    return vireo_tcp_server_client_write_enqueue(s,l,bytes,size,error);
}
static vireo_result_t refresh_hook(void *context,vireo_tcp_server_t *s,vireo_connection_pool_lease_t l,
    vireo_tcp_server_tls_flow_info_t *info,vireo_tcp_server_tls_application_error_t *error) {
    fixture_t *f=context; ++f->refreshes;
    if(f->fault==2) {
        *info=(vireo_tcp_server_tls_flow_info_t){.flow={.want_read=true,.want_write=true},
            .interests=state(f).connection_info.loop_interests,.flow_reported=true,.sync_called=true,.queue_called=true};
        *error=(vireo_tcp_server_tls_application_error_t){.stage=VIREO_TCP_SERVER_TLS_APPLICATION_SYNC,
            .sync_stage=VIREO_TCP_SERVER_TLS_APPLICATION_SYNC,.sync_result=VIREO_RESULT_IO,.queue_result=VIREO_RESULT_INTERNAL};
        return VIREO_RESULT_IO; /* own适配故障模型，不冒充真实内核MOD失败。 */
    }
    return vireo_tcp_server_client_tls_flow_refresh(s,l,info,error);
}
static void failure_prefix(void) {
    fixture_t f; setup(&f,true); uint8_t body[]={0,255,42},work[128],wire[35]; prepare(&f,body,3);
    vireo_completion_response_tls_ops_t ops={enqueue_hook,refresh_hook}; vireo_completion_response_tls_report_t p;
    f.fault=1;
    EXPECT(vireo_completion_response_tls_with_ops(f.server,f.completion,f.match,descriptor,128,work,sizeof work,&p,&ops,&f),VIREO_RESULT_BUSY);
    CHECK(f.enqueues==1 && f.refreshes==0 && !p.response.enqueued && !p.response.refresh_called);
    CHECK(state(&f).connection_info.write_buffer.readable_size==0);
    f.fault=2;
    EXPECT(vireo_completion_response_tls_with_ops(f.server,f.completion,f.match,descriptor,128,work,sizeof work,&p,&ops,&f),VIREO_RESULT_IO);
    CHECK(f.enqueues==2 && f.refreshes==1 && p.response.enqueued && p.response.refresh_called && p.response.stage==VIREO_COMPLETION_RESPONSE_REFRESH);
    CHECK(p.flow.sync_called && p.flow.queue_called && p.error.stage==VIREO_TCP_SERVER_TLS_APPLICATION_SYNC &&
        p.error.sync_stage==VIREO_TCP_SERVER_TLS_APPLICATION_SYNC && p.error.sync_result==VIREO_RESULT_IO && p.error.queue_result==VIREO_RESULT_INTERNAL);
    CHECK(state(&f).connection_info.write_buffer.readable_size==35);
    f.fault=0; refresh(&f); CHECK(f.enqueues==2); send_all(&f); read_exact(&f,wire,sizeof wire);
    wire_is(wire,sizeof wire,body,3,VIREO_STATUS_INTERNAL_ERROR);
    CHECK(state(&f).connection_info.write_buffer.readable_size==0);
    size_t n=0; ERR_clear_error(); int rc=SSL_read_ex(f.ssl,wire,sizeof wire,&n);
    CHECK(rc==0 && SSL_get_error(f.ssl,rc)==SSL_ERROR_WANT_READ && n==0); /* 没有重复响应。 */
    cleanup(&f); ++groups;
}
static void basic_rejections(void) {
    fixture_t f; setup(&f,true); prepare(&f,NULL,0); uint8_t work[128]; vireo_completion_response_tls_report_t p;
    EXPECT(vireo_completion_response_tls_enqueue(NULL,f.completion,f.match,descriptor,128,work,sizeof work,&p),VIREO_RESULT_INVALID_ARGUMENT); no_commit(p);
    EXPECT(vireo_completion_response_tls_enqueue(f.server,NULL,f.match,descriptor,128,work,sizeof work,&p),VIREO_RESULT_INVALID_ARGUMENT); no_commit(p);
    EXPECT(vireo_completion_response_tls_enqueue(f.server,f.completion,f.match,descriptor,128,NULL,sizeof work,&p),VIREO_RESULT_INVALID_ARGUMENT); no_commit(p);
    EXPECT(vireo_completion_response_tls_enqueue(f.server,f.completion,f.match,descriptor,128,work,sizeof work,NULL),VIREO_RESULT_INVALID_ARGUMENT);
    vireo_completion_response_descriptor_t d=descriptor; d.extra_flags=VIREO_PROTOCOL_FLAG_MORE;
    EXPECT(vireo_completion_response_tls_enqueue(f.server,f.completion,f.match,d,128,work,sizeof work,&p),VIREO_RESULT_INVALID_ARGUMENT); no_commit(p);
    EXPECT(vireo_completion_response_tls_with_ops(f.server,f.completion,f.match,descriptor,128,work,sizeof work,&p,NULL,NULL),VIREO_RESULT_INVALID_ARGUMENT); no_commit(p);
    vireo_completion_response_tls_ops_t ops={enqueue_hook,NULL};
    EXPECT(vireo_completion_response_tls_with_ops(f.server,f.completion,f.match,descriptor,128,work,sizeof work,&p,&ops,&f),VIREO_RESULT_INVALID_ARGUMENT); no_commit(p);
    cleanup(&f); ++groups;
}

/** worker只借跨线程资源，不含server、租约、SSL或fd。 */
typedef struct worker {
    vireo_completion_queue_t *queue; /**< 固定结果队列长借至join。 */
    vireo_notifier_t *notifier; /**< producer提示源长借至join。 */
    vireo_completion_publish_report_t report; /**< manager仅成功join后读取。 */
    unsigned executed; /**< 仅worker写，manager在join后核恰好一次。 */
} worker_t;
static vireo_result_t execute(void *context,vireo_task_t const *task) {
    worker_t *w=context; ++w->executed;
    vireo_task_payload_view_t q; EXPECT(vireo_task_borrow_payload(task,&q),VIREO_OK);
    CHECK(q.size==35 && q.data[32]==0 && q.data[33]==255 && q.data[34]==42);
    vireo_protocol_codec_issue_t issue;
    EXPECT(vireo_protocol_frame_crc32c_verify(q.data,32,q.data+32,3,&issue),VIREO_OK);
    uint8_t const body[]={42,0,255}; vireo_completion_t *remaining=NULL;
    EXPECT(vireo_completion_copy_wait_publish(task,VIREO_OK,VIREO_STATUS_OK,body,sizeof body,65536,
        w->queue,w->notifier,&remaining,&w->report),VIREO_OK); CHECK(remaining==NULL); return VIREO_OK;
}
static vireo_result_t deliver(void *context,vireo_completion_t const *completion,vireo_inflight_completion_match_t match) {
    fixture_t *f=context; ++f->delivered; uint8_t work[128]; vireo_completion_response_tls_report_t p;
    EXPECT(vireo_completion_response_tls_enqueue(f->server,completion,match,descriptor,128,work,sizeof work,&p),VIREO_OK);
    CHECK(p.response.enqueued && p.flow.flow_reported); return VIREO_OK;
}
static void explicit_worker_chain(void) {
    fixture_t f; setup(&f,true);
    vireo_task_queue_t *tasks=NULL; vireo_thread_pool_t *pool=NULL;
    vireo_task_queue_options_t const tq={2,65536}; vireo_thread_pool_options_t const po={1,65536};
    vireo_completion_queue_options_t const cq={2,65536}; vireo_notifier_options_t const no={4096};
    worker_t w={0};
    EXPECT(vireo_task_queue_create(&tq,&tasks),VIREO_OK); EXPECT(vireo_task_queue_prepare_wait(tasks),VIREO_OK);
    EXPECT(vireo_completion_queue_create(&cq,&w.queue),VIREO_OK); EXPECT(vireo_completion_queue_prepare_wait(w.queue),VIREO_OK);
    EXPECT(vireo_notifier_create(&no,&w.notifier,NULL),VIREO_OK);
    vireo_event_loop_handle_t handle;
    EXPECT(vireo_notifier_server_register(f.server,w.notifier,&handle,NULL),VIREO_OK);
    EXPECT(vireo_thread_pool_create(&po,&pool),VIREO_OK);
    vireo_thread_pool_configuration_t const config={tasks,execute,&w};
    EXPECT(vireo_thread_pool_configure(pool,&config,NULL),VIREO_OK); vireo_thread_pool_report_t pr;
    EXPECT(vireo_thread_pool_start(pool,&pr),VIREO_OK); EXPECT(vireo_thread_pool_enable_execution(pool,&pr),VIREO_OK);
    uint8_t request[35]={0}; request[33]=255; request[34]=42;
    vireo_protocol_header_t h={.command=descriptor.command,.sequence=101,.body_len=3,
        .session_handle=descriptor.session_handle,.task_handle=descriptor.task_handle};
    EXPECT(vireo_protocol_header_encode(&h,request,sizeof request),VIREO_OK);
    EXPECT(vireo_protocol_frame_crc32c_calculate(request,32,request+32,3,&h.crc32c),VIREO_OK);
    EXPECT(vireo_protocol_header_encode(&h,request,sizeof request),VIREO_OK);
    size_t sent=0; ERR_clear_error(); CHECK(SSL_write_ex(f.ssl,request,sizeof request,&sent)==1 && sent==sizeof request);
    for(unsigned k=0;k<1024 && state(&f).connection_info.read_buffer.readable_size<35;++k) {
        vireo_tls_io_progress_t p; EXPECT(vireo_tls_connection_receive(tls(&f),&io_budget,&p,NULL),VIREO_OK);
        if(p.bytes==0) { wait_network(&f); }
    }
    CHECK(state(&f).connection_info.read_buffer.readable_size==35);
    vireo_async_request_pending_t pending={0}; vireo_task_t *remaining_task=NULL; vireo_async_request_head_report_t submit;
    EXPECT(vireo_async_request_submit_read_head(f.server,f.client,f.store,pool,128,65536,2,9,UINT64_MAX,NULL,
        &pending,&remaining_task,&submit),VIREO_OK);
    CHECK(submit.submit_report.task_transferred && submit.consume_called && pending.frame_bytes==0 && remaining_task==NULL);
    CHECK(state(&f).connection_info.read_buffer.readable_size==0); refresh(&f);
    vireo_completion_t *remaining=NULL; bool finished=false;
    for(unsigned k=0;k<1024;++k) {
        vireo_tcp_server_ready_client_t ready[1]; vireo_tcp_server_tls_poll_report_t p;
        EXPECT(vireo_tcp_server_tls_poll_ready_once(f.server,2,1,ready,1,&p,NULL),VIREO_OK);
        vireo_notifier_server_dispatch_report_t dispatch;
        EXPECT(vireo_notifier_server_dispatch_ready(f.server,handle,w.notifier,f.store,w.queue,1,deliver,&f,&remaining,&dispatch),VIREO_OK);
        CHECK(remaining==NULL);
        if(dispatch.dispatch_report.drain_report.finished==1) { CHECK(dispatch.ready_taken); finished=true; break; }
    }
    CHECK(finished && f.delivered==1);
    send_all(&f); uint8_t wire[35],body[]={42,0,255}; read_exact(&f,wire,sizeof wire); wire_is(wire,35,body,3,VIREO_STATUS_OK);
    vireo_task_queue_close_report_t cr; vireo_result_t result=VIREO_RESULT_BUSY;
    for(unsigned k=0;k<1000000 && result==VIREO_RESULT_BUSY;++k) { result=vireo_task_queue_close(tasks,VIREO_TASK_QUEUE_DRAIN,&cr); if(result==VIREO_RESULT_BUSY) sched_yield(); }
    CHECK(result==VIREO_OK); result=VIREO_RESULT_BUSY;
    for(unsigned k=0;k<1000000 && result==VIREO_RESULT_BUSY;++k) { result=vireo_thread_pool_stop_and_join(pool,&pr); if(result==VIREO_RESULT_BUSY) sched_yield(); }
    CHECK(result==VIREO_OK && w.executed==1 && w.report.completion_transferred);
    uint64_t hints; EXPECT(vireo_notifier_consume(w.notifier,&hints,NULL),VIREO_OK);
    vireo_completion_queue_close_report_t ccr; EXPECT(vireo_completion_queue_close(w.queue,&ccr),VIREO_OK);
    vireo_completion_queue_transfer_report_t qr;
    EXPECT(vireo_completion_queue_try_pop(w.queue,&remaining,&qr),VIREO_RESULT_CANCELLED); CHECK(!remaining);
    EXPECT(vireo_thread_pool_destroy(&pool),VIREO_OK); EXPECT(vireo_task_queue_destroy(&tasks),VIREO_OK);
    EXPECT(vireo_notifier_server_unregister(f.server,&handle,NULL),VIREO_OK);
    EXPECT(vireo_completion_queue_destroy(&w.queue),VIREO_OK); EXPECT(vireo_notifier_destroy(&w.notifier,NULL),VIREO_OK);
    vireo_inflight_store_info_t store; EXPECT(vireo_inflight_store_inspect(f.store,&store),VIREO_OK); CHECK(store.count==0);
    cleanup(&f); ++groups;
}
int main(void) {
    CHECK(signal(SIGPIPE,SIG_IGN)!=SIG_ERR); int old;
    CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,&old)==0);
    size_t const before=fds();
    real_wire(); ranges_and_atomic_full(); gates(); failure_prefix(); basic_rejections(); peer_eof_and_failed(); raw_gate(); long_descriptor(); explicit_worker_chain();
    CHECK(fds()==before); printf("TLS completion response: %u groups passed, fd %zu -> %zu\n",groups,before,fds()); return 0;
}
