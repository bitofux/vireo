/* PROJECT: VIREO; FILE: test_auth_worker_real.c; AUTHOR: bitofux; DATE: 2026-10-20.
 * TLS客户端->认证head->真实worker/MySQL->队列->专用响应/绑定->TLS客户端。 */
#define _GNU_SOURCE
#include "auth_service_test_support.h"
#include <vireo/net/auth_request_head.h>
#include <vireo/service/auth_worker.h>
#include <vireo/persistence/mysql_schema.h>
#include <vireo/persistence/mysql_statement.h>
#include <semaphore.h>
static void sql(vireo_mysql_thread_t *thread, vireo_mysql_connection_t *connection,
    const char *text, const char *expected)
{
    const vireo_mysql_statement_limits_t limits={0,1,0,64,8192};
    vireo_mysql_statement_t *s=NULL; vireo_mysql_execution_t ex;
    EXPECT(vireo_mysql_statement_prepare(thread,connection,text,strlen(text),&limits,&s,NULL),VIREO_OK);
    EXPECT(vireo_mysql_statement_execute(thread,s,NULL,0,&ex,NULL),VIREO_OK);
    if (expected!=NULL) {
        vireo_mysql_fetch_outcome_t fetched; vireo_mysql_cell_view_t cell;
        EXPECT(vireo_mysql_statement_fetch(thread,s,&fetched,NULL),VIREO_OK); REQUIRE(fetched==VIREO_MYSQL_FETCH_ROW);
        EXPECT(vireo_mysql_statement_column(thread,s,0,&cell),VIREO_OK);
        REQUIRE(!cell.is_null && cell.length==strlen(expected) && !memcmp(cell.data,expected,cell.length));
        EXPECT(vireo_mysql_statement_fetch(thread,s,&fetched,NULL),VIREO_OK); REQUIRE(fetched==VIREO_MYSQL_FETCH_DONE);
    } else { REQUIRE(!ex.has_result); }
    EXPECT(vireo_mysql_statement_destroy(thread,&s,NULL),VIREO_OK);
}

typedef struct worker_context {
    pthread_t manager;
    vireo_mysql_runtime_t *runtime;
    vireo_mysql_pool_t *database;
    vireo_auth_password_gate_t *gate;
    vireo_auth_login_verifier_t *verifier;
    service_fixture_t *fixture;
    atomic_uint calls;
    sem_t started[2], release[2];
    pthread_t parallel_threads[2];
} worker_context_t;
/* callback只组合新生产入口；OS线程仍须在返回前完成同线程清理。 */
static vireo_result_t execute(void *context,vireo_task_t const *task)
{
    worker_context_t *w=context; REQUIRE(!pthread_equal(w->manager,pthread_self()));
    vireo_task_info_t info; EXPECT(vireo_task_inspect(task,&info),VIREO_OK);
    uint32_t const sequence=info.metadata.route.request_sequence; REQUIRE(sequence>=10 && sequence<=13);
    if(sequence>=12) {
        size_t const i=(size_t)(sequence-12); w->parallel_threads[i]=pthread_self();
        REQUIRE(sem_post(&w->started[i])==0);
        int rc; do { rc=sem_wait(&w->release[i]); } while(rc<0 && errno==EINTR);
        REQUIRE(rc==0);
    }
    vireo_auth_worker_resources_t const resources={w->runtime,w->database,w->gate,w->verifier,
        w->fixture->queue,w->fixture->notifier,NULL};
    vireo_auth_worker_options_t const options={.execution={100,101,5000,102,103},
        .password=VIREO_PASSWORD_POLICY_DEFAULT,.request_timeout_ns=REQUEST_TIMEOUT,
        .session_lifetime_ms=60000,.completion_allocation_budget=4096,.max_memory_bytes=65536};
    vireo_auth_worker_t *owner=NULL; EXPECT(vireo_auth_worker_create(&resources,&options,&owner),VIREO_OK);
    vireo_auth_worker_report_t report;
    vireo_result_t const expected=sequence==12?VIREO_RESULT_NOT_FOUND:sequence==13?VIREO_RESULT_DATABASE:VIREO_OK;
    EXPECT(vireo_auth_worker_run(owner,task,&report),expected);
    REQUIRE(report.execute_called && report.work_result==expected && report.publication.publication.completion_transferred);
    REQUIRE(!report.cleanup.repository_pending && !report.cleanup.thread_pending && !report.completion_pending);
    REQUIRE(report.cleanup.repository_called && report.cleanup.detach_called);
    /* 已运行对象即使仍借同task也不能再次执行/投递。 */
    EXPECT(vireo_auth_worker_run(owner,task,&report),VIREO_RESULT_BUSY);
    vireo_auth_worker_cleanup_report_t cleanup;
    EXPECT(vireo_auth_worker_destroy(&owner,&cleanup),VIREO_OK); REQUIRE(!owner);
    atomic_fetch_add(&w->calls,1); return VIREO_OK;
}
static void setup_workers(service_fixture_t *t,worker_context_t *w)
{
    *t=(service_fixture_t){0}; setup(&t->f,false); client_close(&t->f);
    vireo_task_queue_options_t const qo={1,65536};
    EXPECT(vireo_task_queue_create(&qo,&t->tasks),VIREO_OK); EXPECT(vireo_task_queue_prepare_wait(t->tasks),VIREO_OK);
    vireo_thread_pool_options_t const wo={2,65536}; EXPECT(vireo_thread_pool_create(&wo,&t->workers),VIREO_OK);
    vireo_completion_queue_options_t const co={1,65536};
    EXPECT(vireo_completion_queue_create(&co,&t->queue),VIREO_OK); EXPECT(vireo_completion_queue_prepare_wait(t->queue),VIREO_OK);
    vireo_notifier_options_t const no={4096}; EXPECT(vireo_notifier_create(&no,&t->notifier,NULL),VIREO_OK);
    uint64_t now=0; EXPECT(vireo_clock_monotonic_now(&now,NULL),VIREO_OK);
    vireo_auth_login_admission_options_t const ao=VIREO_AUTH_LOGIN_ADMISSION_OPTIONS_DEFAULT;
    EXPECT(vireo_auth_login_admission_create(&ao,now,&t->admission),VIREO_OK);
    vireo_thread_pool_configuration_t const configuration={t->tasks,execute,w};
    vireo_thread_pool_report_t report; EXPECT(vireo_thread_pool_configure(t->workers,&configuration,NULL),VIREO_OK);
    EXPECT(vireo_thread_pool_start(t->workers,&report),VIREO_OK);
    EXPECT(vireo_thread_pool_enable_execution(t->workers,&report),VIREO_OK);
}
static void await_started(service_fixture_t *t,sem_t *signal)
{
    bool started=false;
    for(size_t i=0;i<8192 && !started;++i) {
        int const rc=sem_trywait(signal);
        REQUIRE(rc==0 || errno==EAGAIN || errno==EINTR); started=rc==0;
        if(!started) (void)service_turn(t);
    }
    REQUIRE(started);
}
static uint64_t utc_ms(void)
{
    struct timespec now; REQUIRE(clock_gettime(CLOCK_REALTIME,&now)==0 && now.tv_sec>=0 && now.tv_nsec>=0);
    REQUIRE((uintmax_t)now.tv_sec<=UINT64_MAX/1000);
    return (uint64_t)now.tv_sec*1000+(uint64_t)now.tv_nsec/1000000;
}
int main(int argc,char **argv)
{
    REQUIRE(argc==5); int previous=0; REQUIRE(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,&previous)==0);
    struct sigaction action={0}; action.sa_handler=SIG_IGN; REQUIRE(sigemptyset(&action.sa_mask)==0 && sigaction(SIGPIPE,&action,NULL)==0);
    size_t const before=fds(); char password[1026]; FILE *file=fopen(argv[3],"r");
    REQUIRE(file && fgets(password,(int)sizeof(password),file) && fclose(file)==0); password[strcspn(password,"\n")]=0;
    vireo_mysql_runtime_t *runtime=NULL; vireo_mysql_thread_t *thread=NULL;
    EXPECT(vireo_mysql_runtime_create(&runtime,NULL),VIREO_OK); EXPECT(vireo_mysql_thread_attach(runtime,&thread,NULL),VIREO_OK);
    vireo_mysql_connection_options_t const connection={argv[1],argv[2],password,argv[4],3,3,3};
    vireo_mysql_migration_t const *catalog=NULL; size_t catalog_size=0;
    EXPECT(vireo_mysql_schema_catalog(&catalog,&catalog_size),VIREO_OK); vireo_mysql_migration_report_t migrated;
    EXPECT(vireo_mysql_migration_apply(thread,&connection,catalog,catalog_size,&migrated,NULL),VIREO_OK); REQUIRE(migrated.ready);
    vireo_mysql_connection_t *observer=NULL; EXPECT(vireo_mysql_connection_open(thread,&connection,&observer,NULL),VIREO_OK);
    vireo_mysql_pool_options_t const db_options={connection,2,2,VIREO_MYSQL_POOL_MEMORY_MAX};
    vireo_mysql_pool_t *database=NULL; EXPECT(vireo_mysql_pool_create(thread,&db_options,&database,NULL),VIREO_OK);
    vireo_auth_password_gate_options_t const gate_options=VIREO_AUTH_PASSWORD_GATE_OPTIONS_DEFAULT;
    vireo_auth_password_gate_t *gate=NULL; vireo_auth_login_verifier_t *verifier=NULL;
    EXPECT(vireo_auth_password_gate_create(&gate_options,&gate),VIREO_OK);
    EXPECT(vireo_auth_login_verifier_create(gate,&verifier),VIREO_OK);
    service_fixture_t t;
    worker_context_t w={.manager=pthread_self(),.runtime=runtime,.database=database,.gate=gate,.verifier=verifier,.fixture=&t};
    atomic_init(&w.calls,0);
    for(size_t i=0;i<2;++i) REQUIRE(sem_init(&w.started[i],0,0)==0 && sem_init(&w.release[i],0,0)==0);
    setup_workers(&t,&w); service_create(&t); peer_connect(&t);
    vireo_auth_response_t login={0}; uint64_t user=0; uint32_t handle=0;
    for(size_t i=0;i<2;++i) {
        unsigned char request[156]; size_t n=request_frame(request,i==1 || i==2,(uint32_t)i+10,i==2);
        peer_write(&t,request,n); EXPECT(vireo_secure_clear(request,sizeof request),VIREO_OK);
        vireo_auth_response_t value=service_response(&t,i==0?56:i==1?104:32);
        REQUIRE(value.sequence==i+10 && value.command==(i==1 || i==2?VIREO_COMMAND_LOGIN:VIREO_COMMAND_REGISTER));
        if(i==0) { REQUIRE(value.status==VIREO_STATUS_OK && value.root_node_id); user=value.user_id; }
        else if(i==1) { REQUIRE(value.status==VIREO_STATUS_OK && value.user_id==user && value.session_handle); login=value; handle=value.session_handle; }
        else REQUIRE(value.status==(i==2?VIREO_STATUS_AUTHENTICATION_FAILED:VIREO_STATUS_USER_EXISTS));
        if(i>=1) {
            vireo_auth_session_identity_t identity;
            EXPECT(vireo_auth_session_lookup(t.f.sessions,t.client,handle,utc_ms(),&identity),VIREO_OK);
            REQUIRE(identity.user_id==user && identity.expires_at_ms==login.expires_at_ms);
        }
        EXPECT(vireo_auth_response_clear(&value),VIREO_OK);
    }
    /* 两个任务同时被不同OS worker持有，管理端继续Reactor，不从唯一consumer阻塞join。 */
    for(size_t i=0;i<2;++i) {
        unsigned char request[156]; size_t const n=request_frame(request,i==0,(uint32_t)i+12,i==0);
        peer_write(&t,request,n); EXPECT(vireo_secure_clear(request,sizeof request),VIREO_OK);
        await_started(&t,&w.started[i]);
    }
    REQUIRE(!pthread_equal(w.parallel_threads[0],w.parallel_threads[1]));
    for(size_t i=0;i<2;++i) REQUIRE(sem_post(&w.release[i])==0);
    unsigned seen=0;
    for(size_t i=0;i<2;++i) {
        vireo_auth_response_t value=service_response(&t,32);
        REQUIRE(value.sequence==12 || value.sequence==13);
        unsigned const bit=1u<<(value.sequence-12); REQUIRE(!(seen&bit)); seen|=bit;
        REQUIRE(value.status==(value.sequence==12?VIREO_STATUS_AUTHENTICATION_FAILED:VIREO_STATUS_USER_EXISTS));
        EXPECT(vireo_auth_response_clear(&value),VIREO_OK);
    }
    REQUIRE(seen==3 && t.submitted==4 && t.completed==4 && !t.rejected);
    EXPECT(vireo_auth_service_quiesce(t.service),VIREO_OK);
    vireo_thread_pool_shutdown_report_t shutdown;
    EXPECT(vireo_thread_pool_shutdown_and_join(t.workers,VIREO_TASK_QUEUE_DRAIN,&shutdown),VIREO_OK);
    REQUIRE(shutdown.pool_report.joined_count==2 && atomic_load(&w.calls)==4);
    vireo_mysql_user_repository_t *repo=NULL; vireo_password_policy_t const policy=VIREO_PASSWORD_POLICY_DEFAULT;
    EXPECT(vireo_mysql_user_repository_create(thread,database,&policy,&repo,NULL),VIREO_OK);
    vireo_session_token_t token; memcpy(token.bytes,login.token,32); vireo_session_token_digest_t digest;
    EXPECT(vireo_session_token_digest(&token,&digest),VIREO_OK);
    vireo_mysql_session_identity_t persistent; vireo_mysql_session_report_t found;
    EXPECT(vireo_mysql_user_repository_find_session(repo,&digest,utc_ms(),5000,&persistent,&found,NULL),VIREO_OK);
    vireo_auth_session_identity_t bound;
    EXPECT(vireo_auth_session_lookup(t.f.sessions,t.client,handle,utc_ms(),&bound),VIREO_OK);
    REQUIRE(persistent.user_id==user && persistent.session_id==bound.session_id && login.expires_at_ms-login.issued_at_ms==60000);
    sql(thread,observer,"SELECT COUNT(*) FROM users","1"); sql(thread,observer,"SELECT COUNT(*) FROM file_nodes","1");
    sql(thread,observer,"SELECT COUNT(*) FROM sessions","1"); sql(thread,observer,"SELECT COUNT(*) FROM operation_audits","2");
    EXPECT(vireo_auth_session_revoke(t.f.sessions,bound.session_id),VIREO_OK);
    EXPECT(vireo_auth_session_lookup(t.f.sessions,t.client,handle,utc_ms(),&bound),VIREO_RESULT_CANCELLED);
    vireo_connection_pool_lease_t const old=t.client; service_disconnect(&t);
    EXPECT(vireo_auth_session_lookup(t.f.sessions,old,handle,utc_ms(),&bound),VIREO_RESULT_NOT_FOUND);
    EXPECT(vireo_auth_response_clear(&login),VIREO_OK); EXPECT(vireo_secure_clear(&token,sizeof(token)),VIREO_OK);
    EXPECT(vireo_secure_clear(&digest,sizeof(digest)),VIREO_OK);
    EXPECT(vireo_mysql_user_repository_destroy(&repo,NULL),VIREO_OK);
    service_cleanup(&t);
    EXPECT(vireo_auth_login_verifier_destroy(&verifier),VIREO_OK); EXPECT(vireo_auth_password_gate_close(gate),VIREO_OK);
    EXPECT(vireo_auth_password_gate_destroy(&gate),VIREO_OK);
    bool closed=false; EXPECT(vireo_mysql_pool_close(database,&closed,NULL),VIREO_OK); REQUIRE(closed);
    EXPECT(vireo_mysql_pool_destroy(thread,&database,NULL),VIREO_OK); EXPECT(vireo_mysql_connection_destroy(thread,&observer),VIREO_OK);
    EXPECT(vireo_mysql_thread_detach(&thread),VIREO_OK); EXPECT(vireo_mysql_runtime_destroy(&runtime),VIREO_OK);
    EXPECT(vireo_secure_clear(password,sizeof(password)),VIREO_OK);
    for(size_t i=0;i<2;++i) REQUIRE(sem_destroy(&w.started[i])==0 && sem_destroy(&w.release[i])==0);
    REQUIRE(fds()==before); REQUIRE(pthread_setcancelstate(previous,NULL)==0);
    printf("PASS auth_worker real: automatic TLS/4 requests, two concurrent OS workers via production run/cleanup receipt, capacity-one queues, persisted session matches client token/binding, no replay, quiesce/cleanup, FD %zu->%zu\n",before,fds());
    return 0;
}
