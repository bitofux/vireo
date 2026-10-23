/* PROJECT: VIREO; FILE: auth_reactor_test_support.h; AUTHOR: bitofux; DATE: 2026-10-20.
 * 两个新测试共用真实TLS/loopback fixture，不进入产品target。 */
#ifndef VIREO_TEST_AUTH_REACTOR_SUPPORT_H
#define VIREO_TEST_AUTH_REACTOR_SUPPORT_H
#include "tls_context_fixtures.h"
#include <vireo/net/auth_response_consumer.h>
#include <vireo/protocol/codec.h>
#include <vireo/protocol/tlv.h>
#include <vireo/base/secure_clear.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#define REQUIRE(x) do { if (!(x)) { fprintf(stderr,"%s:%d: %s\n",__FILE__,__LINE__,#x); abort(); } } while(0)
#define EXPECT(x,r) do { errno=EDOM; vireo_result_t rc_=(x); if(rc_!=(r)) { fprintf(stderr,"%s:%d: result %d expected %d\n",__FILE__,__LINE__,(int)rc_,(int)(r)); abort(); } REQUIRE(errno==EDOM); } while(0)
typedef struct fixture {
    vireo_tcp_server_t *server;
    vireo_connection_pool_lease_t client;
    struct sockaddr_in address;
    int peer; SSL *ssl;
    vireo_inflight_store_t *store;
    vireo_auth_sessions_t *sessions;
} fixture_t;
static inline size_t fds(void) {
    DIR *d=opendir("/proc/self/fd"); REQUIRE(d); size_t n=0; struct dirent *p;
    while((p=readdir(d))!=NULL) if(p->d_name[0]!='.') ++n;
    REQUIRE(closedir(d)==0); return n;
}
static inline vireo_tls_connection_t *tls(fixture_t *f) {
    vireo_tls_connection_t *t=NULL;
    EXPECT(vireo_tcp_server_client_tls_borrow(f->server,f->client,&t,NULL),VIREO_OK); return t;
}
static inline void client_open(fixture_t *f,bool establish) {
    f->peer=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0); REQUIRE(f->peer>=0);
    REQUIRE(connect(f->peer,(struct sockaddr *)&f->address,sizeof f->address)==0);
    int flags=fcntl(f->peer,F_GETFL); REQUIRE(flags>=0 && fcntl(f->peer,F_SETFL,flags|O_NONBLOCK)==0);
    vireo_tcp_server_admit_budget_t const ab={1,2}; vireo_tcp_server_tls_admit_info_t ai;
    EXPECT(vireo_tcp_server_tls_admit_batch(f->server,&ab,&f->client,1,&ai,NULL),VIREO_OK); REQUIRE(ai.admission.admitted_count==1);
    if(!establish) return;
    SSL_CTX *c=SSL_CTX_new(TLS_client_method()); REQUIRE(c);
    REQUIRE(SSL_CTX_set_min_proto_version(c,TLS1_3_VERSION)==1 && SSL_CTX_set_max_proto_version(c,TLS1_3_VERSION)==1);
    SSL_CTX_set_verify(c,SSL_VERIFY_PEER,NULL);
    BIO *b=BIO_new_mem_buf(fixture_root,(int)sizeof fixture_root-1); REQUIRE(b);
    X509 *cert=PEM_read_bio_X509(b,NULL,NULL,NULL); REQUIRE(cert);
    REQUIRE(X509_STORE_add_cert(SSL_CTX_get_cert_store(c),cert)==1); X509_free(cert); REQUIRE(BIO_free(b)==1);
    f->ssl=SSL_new(c); REQUIRE(f->ssl); SSL_CTX_free(c);
    REQUIRE(SSL_set1_host(f->ssl,"vireo-034-test.invalid")==1);
    X509_VERIFY_PARAM_set_time(SSL_get0_param(f->ssl),(time_t)1800000000);
    b=BIO_new_socket(f->peer,BIO_NOCLOSE); REQUIRE(b); SSL_set_bio(f->ssl,b,b); SSL_set_connect_state(f->ssl);
    bool client_done=false,server_done=false;
    for(unsigned k=0;k<1024;++k) {
        if(!client_done) {
            ERR_clear_error(); int rc=SSL_do_handshake(f->ssl); int why=rc==1?SSL_ERROR_NONE:SSL_get_error(f->ssl,rc);
            REQUIRE(why==SSL_ERROR_NONE || why==SSL_ERROR_WANT_READ || why==SSL_ERROR_WANT_WRITE); client_done=rc==1;
        }
        vireo_tcp_server_ready_client_t ready[1]; vireo_tcp_server_tls_poll_report_t p;
        EXPECT(vireo_tcp_server_tls_poll_ready_once(f->server,2,1,ready,1,&p,NULL),VIREO_OK);
        if(p.poll.selected_count && !server_done && ready[0].client.slot_index==f->client.slot_index &&
           ready[0].client.generation==f->client.generation) {
            vireo_tcp_server_tls_handshake_info_t h;
            EXPECT(vireo_tcp_server_client_tls_handshake_step(f->server,ready[0].client,&h,NULL),VIREO_OK);
            server_done=h.application_ready;
        }
        if(client_done && server_done) break;
    }
    REQUIRE(client_done && server_done && SSL_version(f->ssl)==TLS1_3_VERSION && SSL_get_verify_result(f->ssl)==X509_V_OK);
}
static inline void setup_capacity_profile(fixture_t *f,bool establish,size_t capacity,size_t write_capacity) {
    *f=(fixture_t){.peer=-1};
    vireo_tls_context_options_t const co={fixture_leaf,sizeof fixture_leaf-1,fixture_key,sizeof fixture_key-1,4096};
    vireo_tls_context_t *context=NULL;
    EXPECT(vireo_tls_context_create_server(&co,&context,NULL),VIREO_OK);
    vireo_tcp_server_options_t const so={capacity,4,1048576,write_capacity>4096?4096+write_capacity:32768};
    vireo_tcp_server_tls_options_t const to={{4096,write_capacity,4096+write_capacity+32768,256,255,4096,0,write_capacity},
        4096,UINT64_C(5000000000),163840};
    EXPECT(vireo_tcp_server_create_tls_with_auxiliary_capacity(&so,&to,1,&context,&f->server,NULL),VIREO_OK);
    REQUIRE(context==NULL);
    int fd=socket(AF_INET,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0); REQUIRE(fd>=0);
    struct sockaddr_in address={.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
    REQUIRE(bind(fd,(struct sockaddr *)&address,sizeof address)==0 && listen(fd,4)==0);
    socklen_t n=sizeof address; REQUIRE(getsockname(fd,(struct sockaddr *)&address,&n)==0);
    vireo_acceptor_t *listener=NULL; vireo_acceptor_options_t const ao={4096};
    EXPECT(vireo_acceptor_create(&ao,&fd,&listener,NULL),VIREO_OK);
    EXPECT(vireo_tcp_server_adopt_listener(f->server,&listener,NULL),VIREO_OK);
    EXPECT(vireo_tcp_server_bind_listener(f->server,true,NULL),VIREO_OK);
    f->address=address;
    vireo_inflight_store_options_t const io={8,65536};
    EXPECT(vireo_inflight_store_create(&io,&f->store),VIREO_OK);
    vireo_auth_sessions_options_t const bo={65536};
    EXPECT(vireo_auth_sessions_create(f->server,&bo,&f->sessions),VIREO_OK);
    client_open(f,establish);
}
static inline void setup_capacity(fixture_t *f,bool establish,size_t capacity)
{ setup_capacity_profile(f,establish,capacity,4096); }
static inline void setup(fixture_t *f,bool establish) { setup_capacity(f,establish,1); }
static inline void client_close(fixture_t *f) {
    if(f->client.pool_id) EXPECT(vireo_tcp_server_release_client(f->server,&f->client,NULL),VIREO_OK);
    SSL_free(f->ssl); f->ssl=NULL;
    if(f->peer>=0) REQUIRE(close(f->peer)==0);
    f->peer=-1;
}
static inline void cleanup(fixture_t *f) {
    EXPECT(vireo_auth_sessions_destroy(&f->sessions),VIREO_OK);
    EXPECT(vireo_inflight_store_destroy(&f->store),VIREO_OK);
    client_close(f); EXPECT(vireo_tcp_server_destroy(&f->server,NULL),VIREO_OK);
}
static inline size_t request_frame(unsigned char wire[156],bool login,uint32_t sequence,bool wrong) {
    vireo_tlv_writer_t w; EXPECT(vireo_tlv_writer_init(&w,wire+32,124),VIREO_OK);
    EXPECT(vireo_tlv_writer_put(&w,1,(unsigned char const *)"Alice_7",7),VIREO_OK);
    EXPECT(vireo_tlv_writer_put(&w,2,(unsigned char const *)(wrong?"Incorrect":"Correct!7"),9),VIREO_OK);
    unsigned char const device[16]={0};
    if(login) EXPECT(vireo_tlv_writer_put(&w,3,device,16),VIREO_OK);
    vireo_protocol_header_t h={.command=login?VIREO_COMMAND_LOGIN:VIREO_COMMAND_REGISTER,.sequence=sequence,.body_len=(uint32_t)w.used};
    EXPECT(vireo_protocol_header_encode(&h,wire,32),VIREO_OK);
    EXPECT(vireo_protocol_frame_crc32c_calculate(wire,32,wire+32,w.used,&h.crc32c),VIREO_OK);
    EXPECT(vireo_protocol_header_encode(&h,wire,32),VIREO_OK); return 32+w.used;
}
/* TLS记录可受网络调度影响；轮数不是经过的时间。每次完整收发共用5秒期限。 */
static inline uint64_t io_now_ns(void) {
    struct timespec now;
    REQUIRE(clock_gettime(CLOCK_MONOTONIC,&now)==0);
    return (uint64_t)now.tv_sec*UINT64_C(1000000000)+(uint64_t)now.tv_nsec;
}
static inline void receive_wire(fixture_t *f,uint8_t const *wire,size_t n,uint8_t const **input) {
    size_t wrote=0;
    for(unsigned k=0;k<1024 && wrote<n;++k) {
        size_t amount=0; ERR_clear_error(); int rc=SSL_write_ex(f->ssl,wire+wrote,n-wrote,&amount);
        int why=rc==1?SSL_ERROR_NONE:SSL_get_error(f->ssl,rc);
        REQUIRE(why==SSL_ERROR_NONE || why==SSL_ERROR_WANT_READ || why==SSL_ERROR_WANT_WRITE);
        wrote+=amount;
    }
    REQUIRE(wrote==n);
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
    REQUIRE(have==n && memcmp(*input,wire,n)==0);
}

static inline void drain(fixture_t *f,uint8_t *out,size_t size) {
    size_t received=0; uint64_t const deadline=io_now_ns()+UINT64_C(5000000000);
    while(received<size && io_now_ns()<deadline) {
        vireo_tls_io_budget_t const budget={4096,8}; vireo_tls_io_progress_t progress;
        EXPECT(vireo_tls_connection_send(tls(f),&budget,&progress,NULL),VIREO_OK);
        size_t amount=0; ERR_clear_error(); int rc=SSL_read_ex(f->ssl,out+received,size-received,&amount);
        int why=rc==1?SSL_ERROR_NONE:SSL_get_error(f->ssl,rc);
        REQUIRE(why==SSL_ERROR_NONE || why==SSL_ERROR_WANT_READ || why==SSL_ERROR_WANT_WRITE);
        received+=amount;
        if(!amount) {
            struct pollfd peer={f->peer,why==SSL_ERROR_WANT_WRITE?POLLOUT:POLLIN,0};
            int const polled=poll(&peer,1,5);
            REQUIRE(polled>=0 || errno==EINTR);
            REQUIRE(!(peer.revents&(POLLERR|POLLHUP|POLLNVAL)));
        }
    }
    REQUIRE(received==size);
}

#endif
