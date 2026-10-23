/* PROJECT : VIREO
 * FILE : auth_service_test_support.h
 * AUTHOR : bitofux
 * DATE : 2026-10-20
 * BRIEF : 自动服务轮的真实TLS客户端；不手工head/pop/consume。 */
#ifndef VIREO_TEST_AUTH_SERVICE_SUPPORT_H
#define VIREO_TEST_AUTH_SERVICE_SUPPORT_H
#include "auth_reactor_test_support.h"
#include <vireo/net/auth_service.h>
#include <stdatomic.h>
#define REQUEST_TIMEOUT UINT64_C(10000000000)
typedef struct service_fixture {
    fixture_t f;
    vireo_task_queue_t *tasks;
    vireo_thread_pool_t *workers;
    vireo_completion_queue_t *queue;
    vireo_notifier_t *notifier;
    vireo_auth_login_admission_t *admission;
    vireo_auth_service_t *service;
    vireo_auth_failure_audit_t *audit;
    size_t submitted,rejected,completed,released;
    vireo_connection_pool_lease_t client;
    bool blocked;
} service_fixture_t;
static inline vireo_auth_service_options_t service_options(void)
{
    return (vireo_auth_service_options_t){.max_clients=1,.admit={1,2},.max_completions=1,
        .cleanup_slots=2,.receive={4096,8},.send={4096,8},.task_allocation_budget=4096,
        .max_client_requests=8,.register_operation=100,.login_operation=101,.logout_operation=102,.resume_operation=103,
        .request_timeout_ns=REQUEST_TIMEOUT,.max_memory_bytes=65536};
}
static inline void service_setup_profile(service_fixture_t *t,vireo_thread_pool_execute_fn execute,void *context,size_t write_capacity)
{
    *t=(service_fixture_t){0}; setup_capacity_profile(&t->f,false,1,write_capacity); client_close(&t->f);
    vireo_task_queue_options_t const qo={1,65536};
    EXPECT(vireo_task_queue_create(&qo,&t->tasks),VIREO_OK); EXPECT(vireo_task_queue_prepare_wait(t->tasks),VIREO_OK);
    vireo_thread_pool_options_t const wo={1,65536};
    EXPECT(vireo_thread_pool_create(&wo,&t->workers),VIREO_OK);
    vireo_completion_queue_options_t const co={1,65536};
    EXPECT(vireo_completion_queue_create(&co,&t->queue),VIREO_OK); EXPECT(vireo_completion_queue_prepare_wait(t->queue),VIREO_OK);
    vireo_notifier_options_t const no={4096}; EXPECT(vireo_notifier_create(&no,&t->notifier,NULL),VIREO_OK);
    uint64_t now=0; EXPECT(vireo_clock_monotonic_now(&now,NULL),VIREO_OK);
    vireo_auth_login_admission_options_t const ao=VIREO_AUTH_LOGIN_ADMISSION_OPTIONS_DEFAULT;
    EXPECT(vireo_auth_login_admission_create(&ao,now,&t->admission),VIREO_OK);
    vireo_auth_failure_audit_options_t const audit_options={256,65536,8,UINT64_C(1000000000)};
    EXPECT(vireo_auth_failure_audit_create(&audit_options,now,&t->audit),VIREO_OK);
    vireo_thread_pool_configuration_t const config={t->tasks,execute,context};
    vireo_thread_pool_report_t report;
    EXPECT(vireo_thread_pool_configure(t->workers,&config,NULL),VIREO_OK);
    EXPECT(vireo_thread_pool_start(t->workers,&report),VIREO_OK);
    EXPECT(vireo_thread_pool_enable_execution(t->workers,&report),VIREO_OK);
}
static inline void service_setup(service_fixture_t *t,vireo_thread_pool_execute_fn execute,void *context)
{ service_setup_profile(t,execute,context,4096); }
static inline void service_create(service_fixture_t *t)
{
    vireo_auth_service_resources_t const r={t->f.server,t->f.store,t->workers,t->admission,t->f.sessions,t->queue,t->notifier,t->audit};
    vireo_auth_service_options_t const o=service_options();
    EXPECT(vireo_auth_service_create(&r,&o,&t->service),VIREO_OK);
}
static inline vireo_auth_service_report_t service_turn(service_fixture_t *t)
{
    vireo_auth_service_report_t p;
    EXPECT(vireo_auth_service_once(t->service,2,&p),VIREO_OK);
    REQUIRE(p.first_client_result==VIREO_OK);
    t->submitted+=p.submitted; t->rejected+=p.rejected; t->completed+=p.completions; t->released+=p.released;
    t->blocked=t->blocked || p.response_blocked;
    if(p.head.receipt.client.pool_id) t->client=p.head.receipt.client;
    return p;
}
static inline void peer_free(service_fixture_t *t)
{
    SSL_free(t->f.ssl); t->f.ssl=NULL;
    if(t->f.peer>=0) REQUIRE(close(t->f.peer)==0);
    t->f.peer=-1;
}
static inline void peer_connect(service_fixture_t *t)
{
    t->f.peer=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0); REQUIRE(t->f.peer>=0);
    REQUIRE(connect(t->f.peer,(struct sockaddr *)&t->f.address,sizeof t->f.address)==0);
    int flags=fcntl(t->f.peer,F_GETFL); REQUIRE(flags>=0 && fcntl(t->f.peer,F_SETFL,flags|O_NONBLOCK)==0);
    SSL_CTX *c=SSL_CTX_new(TLS_client_method()); REQUIRE(c);
    REQUIRE(SSL_CTX_set_min_proto_version(c,TLS1_3_VERSION)==1 && SSL_CTX_set_max_proto_version(c,TLS1_3_VERSION)==1);
    SSL_CTX_set_verify(c,SSL_VERIFY_PEER,NULL);
    BIO *b=BIO_new_mem_buf(fixture_root,(int)sizeof fixture_root-1); REQUIRE(b);
    X509 *cert=PEM_read_bio_X509(b,NULL,NULL,NULL); REQUIRE(cert);
    REQUIRE(X509_STORE_add_cert(SSL_CTX_get_cert_store(c),cert)==1); X509_free(cert); REQUIRE(BIO_free(b)==1);
    t->f.ssl=SSL_new(c); REQUIRE(t->f.ssl); SSL_CTX_free(c);
    REQUIRE(SSL_set1_host(t->f.ssl,"vireo-034-test.invalid")==1);
    X509_VERIFY_PARAM_set_time(SSL_get0_param(t->f.ssl),(time_t)1800000000);
    b=BIO_new_socket(t->f.peer,BIO_NOCLOSE); REQUIRE(b); SSL_set_bio(t->f.ssl,b,b); SSL_set_connect_state(t->f.ssl);
    bool established=false;
    for(size_t i=0;i<4096 && !established;++i) {
        ERR_clear_error(); int rc=SSL_do_handshake(t->f.ssl); int why=rc==1?SSL_ERROR_NONE:SSL_get_error(t->f.ssl,rc);
        REQUIRE(why==SSL_ERROR_NONE || why==SSL_ERROR_WANT_READ || why==SSL_ERROR_WANT_WRITE);
        established=rc==1; (void)service_turn(t);
    }
    REQUIRE(established && SSL_get_verify_result(t->f.ssl)==X509_V_OK);
    for(size_t i=0;i<3;++i) (void)service_turn(t);
}
static inline void peer_write(service_fixture_t *t,unsigned char const *wire,size_t n)
{
    size_t sent=0;
    for(size_t i=0;i<4096 && sent<n;++i) {
        size_t amount=0; ERR_clear_error(); int rc=SSL_write_ex(t->f.ssl,wire+sent,n-sent,&amount);
        int why=rc==1?SSL_ERROR_NONE:SSL_get_error(t->f.ssl,rc);
        REQUIRE(why==SSL_ERROR_NONE || why==SSL_ERROR_WANT_READ || why==SSL_ERROR_WANT_WRITE); sent+=amount;
        if(sent<n) (void)service_turn(t);
    }
    REQUIRE(sent==n);
}
static inline void peer_read(service_fixture_t *t,unsigned char *wire,size_t n)
{
    size_t received=0;
    for(size_t i=0;i<8192 && received<n;++i) {
        (void)service_turn(t);
        size_t amount=0; ERR_clear_error(); int rc=SSL_read_ex(t->f.ssl,wire+received,n-received,&amount);
        int why=rc==1?SSL_ERROR_NONE:SSL_get_error(t->f.ssl,rc);
        REQUIRE(why==SSL_ERROR_NONE || why==SSL_ERROR_WANT_READ || why==SSL_ERROR_WANT_WRITE); received+=amount;
    }
    REQUIRE(received==n);
}
static inline vireo_auth_response_t service_response(service_fixture_t *t,size_t n)
{
    unsigned char wire[104]; REQUIRE(n<=sizeof wire); peer_read(t,wire,n);
    vireo_auth_response_t v={0}; EXPECT(vireo_auth_response_decode(wire,n,&v),VIREO_OK);
    EXPECT(vireo_secure_clear(wire,sizeof wire),VIREO_OK); return v;
}
static inline void service_disconnect(service_fixture_t *t)
{
    size_t const old=t->released;
    EXPECT(vireo_auth_service_disconnect(t->service,t->client),VIREO_OK);
    for(size_t i=0;i<32 && t->released==old;++i) (void)service_turn(t);
    REQUIRE(t->released==old+1); peer_free(t);
}
static inline void service_cleanup(service_fixture_t *t)
{
    EXPECT(vireo_auth_service_quiesce(t->service),VIREO_OK);
    vireo_thread_pool_shutdown_report_t shut;
    uint64_t begin=0,now=0;
    EXPECT(vireo_clock_monotonic_now(&begin,NULL),VIREO_OK);
    for(;;) {
        vireo_result_t const rc=vireo_thread_pool_shutdown_and_join(t->workers,VIREO_TASK_QUEUE_DRAIN,&shut);
        if(rc==VIREO_OK) break;
        /* 只恢复尚未join的关闭/资格观察竞争；不重试业务或pthread错误。 */
        REQUIRE(rc==VIREO_RESULT_BUSY &&
            ((shut.stage==VIREO_THREAD_POOL_SHUTDOWN_STAGE_CLOSE_QUEUE && !shut.join_called) ||
             (shut.stage==VIREO_THREAD_POOL_SHUTDOWN_STAGE_JOIN_WORKERS &&
              shut.pool_report.stage==VIREO_THREAD_POOL_STAGE_CHECK_QUEUE)));
        REQUIRE(sched_yield()==0);
        EXPECT(vireo_clock_monotonic_now(&now,NULL),VIREO_OK);
        REQUIRE(now-begin<UINT64_C(5000000000));
    }
    if(t->f.peer>=0) service_disconnect(t);
    for(size_t i=0;i<4;++i) (void)service_turn(t);
    EXPECT(vireo_auth_service_destroy(&t->service),VIREO_OK);
    EXPECT(vireo_thread_pool_destroy(&t->workers),VIREO_OK); EXPECT(vireo_task_queue_destroy(&t->tasks),VIREO_OK);
    EXPECT(vireo_completion_queue_destroy(&t->queue),VIREO_OK); EXPECT(vireo_notifier_destroy(&t->notifier,NULL),VIREO_OK);
    if(t->audit) {
        EXPECT(vireo_auth_failure_audit_close(t->audit,VIREO_AUTH_FAILURE_STOP),VIREO_OK);
        EXPECT(vireo_auth_failure_audit_destroy(&t->audit),VIREO_OK);
    }
    EXPECT(vireo_auth_login_admission_destroy(&t->admission),VIREO_OK); cleanup(&t->f);
}
#endif
