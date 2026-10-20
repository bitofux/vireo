/* PROJECT: VIREO; FILE: test_auth_worker_runtime_real.c; AUTHOR: bitofux; DATE: 2026-10-20.
 * TLS客户端->认证head->真实worker/MySQL->队列->专用响应/绑定->TLS客户端。 */
#define _GNU_SOURCE
#include "auth_service_test_support.h"
#include <vireo/net/auth_request_head.h>
#include "auth_worker_runtime.h"
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

typedef struct app_context {
    vireo_auth_worker_runtime_t runtime;
    atomic_uint entered,finished;
    sem_t release;
} app_context_t;
static vireo_result_t execute(void *context,vireo_task_t const *task)
{
    app_context_t *c=context;vireo_task_info_t info;EXPECT(vireo_task_inspect(task,&info),VIREO_OK);
    atomic_fetch_add(&c->entered,1);
    if(info.metadata.route.request_sequence==30) {
        int rc;do{rc=sem_wait(&c->release);}while(rc<0 && errno==EINTR);REQUIRE(rc==0);
    }
    vireo_result_t const result=vireo_auth_worker_runtime_execute(&c->runtime,task);
    atomic_fetch_add(&c->finished,1);return result;
}
static uint64_t utc_ms(void)
{
    struct timespec now;REQUIRE(clock_gettime(CLOCK_REALTIME,&now)==0 && now.tv_sec>=0);
    return (uint64_t)now.tv_sec*1000+(uint64_t)now.tv_nsec/1000000;
}
static unsigned faults(app_context_t const *c)
{ unsigned value=0;EXPECT(vireo_auth_worker_runtime_inspect_faults(&c->runtime,&value),VIREO_OK);return value; }
static void setup_app(service_fixture_t *t,app_context_t *c,vireo_mysql_runtime_t *runtime,
    vireo_mysql_pool_t *database,vireo_auth_password_gate_t *gate,vireo_auth_login_verifier_t *verifier,size_t budget)
{
    *t=(service_fixture_t){0};setup(&t->f,false);client_close(&t->f);
    vireo_task_queue_options_t const qo={2,65536};
    EXPECT(vireo_task_queue_create(&qo,&t->tasks),VIREO_OK);EXPECT(vireo_task_queue_prepare_wait(t->tasks),VIREO_OK);
    vireo_thread_pool_options_t const wo={1,65536};EXPECT(vireo_thread_pool_create(&wo,&t->workers),VIREO_OK);
    vireo_completion_queue_options_t const co={1,65536};
    EXPECT(vireo_completion_queue_create(&co,&t->queue),VIREO_OK);EXPECT(vireo_completion_queue_prepare_wait(t->queue),VIREO_OK);
    vireo_notifier_options_t const no={4096};EXPECT(vireo_notifier_create(&no,&t->notifier,NULL),VIREO_OK);
    uint64_t now=0;EXPECT(vireo_clock_monotonic_now(&now,NULL),VIREO_OK);
    vireo_auth_login_admission_options_t const ao=VIREO_AUTH_LOGIN_ADMISSION_OPTIONS_DEFAULT;
    EXPECT(vireo_auth_login_admission_create(&ao,now,&t->admission),VIREO_OK);
    atomic_init(&c->entered,0);atomic_init(&c->finished,0);REQUIRE(sem_init(&c->release,0,0)==0);
    vireo_auth_worker_resources_t const r={runtime,database,gate,verifier,t->queue,t->notifier,NULL};
    vireo_auth_worker_options_t const o={.execution={100,101,5000,102,103},.password=VIREO_PASSWORD_POLICY_DEFAULT,
        .request_timeout_ns=REQUEST_TIMEOUT,.session_lifetime_ms=60000,.completion_allocation_budget=budget,.max_memory_bytes=65536};
    EXPECT(vireo_auth_worker_runtime_init(&c->runtime,&r,&o,3),VIREO_OK);
    vireo_thread_pool_configuration_t const config={t->tasks,execute,c};vireo_thread_pool_report_t report;
    EXPECT(vireo_thread_pool_configure(t->workers,&config,NULL),VIREO_OK);
    EXPECT(vireo_thread_pool_start(t->workers,&report),VIREO_OK);
    EXPECT(vireo_thread_pool_enable_execution(t->workers,&report),VIREO_OK);
    service_create(t);peer_connect(t);
}
static void request(service_fixture_t *t,bool login,uint32_t seq,bool wrong)
{
    unsigned char wire[156];size_t n=request_frame(wire,login,seq,wrong);peer_write(t,wire,n);
    EXPECT(vireo_secure_clear(wire,sizeof wire),VIREO_OK);
}
static unsigned sessions(vireo_mysql_thread_t *thread,vireo_mysql_connection_t *connection)
{
    char const *text="SELECT COUNT(*) FROM sessions";
    vireo_mysql_statement_limits_t const limits={0,1,0,64,8192};
    vireo_mysql_statement_t *s=NULL;vireo_mysql_execution_t ex;
    EXPECT(vireo_mysql_statement_prepare(thread,connection,text,strlen(text),&limits,&s,NULL),VIREO_OK);
    EXPECT(vireo_mysql_statement_execute(thread,s,NULL,0,&ex,NULL),VIREO_OK);
    vireo_mysql_fetch_outcome_t fetched;vireo_mysql_cell_view_t cell;
    EXPECT(vireo_mysql_statement_fetch(thread,s,&fetched,NULL),VIREO_OK);REQUIRE(fetched==VIREO_MYSQL_FETCH_ROW);
    EXPECT(vireo_mysql_statement_column(thread,s,0,&cell),VIREO_OK);REQUIRE(!cell.is_null && cell.length<32);
    char value[32]={0};memcpy(value,cell.data,cell.length);unsigned result=(unsigned)strtoul(value,NULL,10);
    EXPECT(vireo_mysql_statement_destroy(thread,&s,NULL),VIREO_OK);return result;
}
/* 两队列各自确认成功后才离开服务阶段join，不依赖consumer继续腾容量。 */
static void stop_discard(service_fixture_t *t,vireo_result_t worker_result)
{
    EXPECT(vireo_auth_service_quiesce(t->service),VIREO_OK);
    EXPECT(vireo_tcp_server_request_stop(t->f.server,NULL),VIREO_OK);
    bool task_closed=false,completion_closed=false;
    for(size_t i=0;i<8192 && (!task_closed || !completion_closed);++i) {
        if(!task_closed) { vireo_task_queue_close_report_t p;vireo_result_t rc=vireo_task_queue_close(t->tasks,VIREO_TASK_QUEUE_CANCEL_PENDING,&p);REQUIRE(rc==VIREO_OK || rc==VIREO_RESULT_BUSY);task_closed=rc==VIREO_OK; }
        if(!completion_closed) { vireo_completion_queue_close_report_t p;vireo_result_t rc=vireo_completion_queue_close(t->queue,&p);REQUIRE(rc==VIREO_OK || rc==VIREO_RESULT_BUSY);completion_closed=rc==VIREO_OK; }
        /* 关闭尚竞争时继续有界Reactor；本例成功关闭同轮不提前pop，以检验join不需腾空间。 */
        if(!task_closed || !completion_closed)(void)service_turn(t);
    }
    REQUIRE(task_closed && completion_closed);
    vireo_thread_pool_report_t joined;EXPECT(vireo_thread_pool_stop_and_join(t->workers,&joined),worker_result);
    REQUIRE(joined.joined_count==1 && joined.created_count==1);
    vireo_thread_pool_worker_result_t result;EXPECT(vireo_thread_pool_inspect_worker_result(t->workers,0,&result),VIREO_OK);
    REQUIRE(result.result==worker_result);
    vireo_task_t *pending=NULL;vireo_task_queue_transfer_report_t moved;
    EXPECT(vireo_task_queue_try_take_cancelled(t->tasks,&pending,&moved),VIREO_RESULT_NOT_FOUND);REQUIRE(!pending);
    for(size_t i=0;i<64;++i)(void)service_turn(t);
    vireo_inflight_store_info_t store;EXPECT(vireo_inflight_store_inspect(t->f.store,&store),VIREO_OK);REQUIRE(!store.count && t->released==1);
    peer_free(t);
    EXPECT(vireo_auth_service_destroy(&t->service),VIREO_OK);
}
static void destroy_app(service_fixture_t *t,app_context_t *c)
{
    EXPECT(vireo_thread_pool_destroy(&t->workers),VIREO_OK);EXPECT(vireo_task_queue_destroy(&t->tasks),VIREO_OK);
    EXPECT(vireo_completion_queue_destroy(&t->queue),VIREO_OK);EXPECT(vireo_notifier_destroy(&t->notifier,NULL),VIREO_OK);
    EXPECT(vireo_auth_login_admission_destroy(&t->admission),VIREO_OK);cleanup(&t->f);
    REQUIRE(sem_destroy(&c->release)==0);
}
static void scenarios(vireo_mysql_runtime_t *runtime,vireo_mysql_thread_t *thread,vireo_mysql_pool_t *database,
    vireo_mysql_connection_t *observer,vireo_auth_password_gate_t *gate,vireo_auth_login_verifier_t *verifier)
{
    service_fixture_t t;app_context_t contexts[3];app_context_t *c=&contexts[0];
    setup_app(&t,c,runtime,database,gate,verifier,4096);
    request(&t,false,10,false);vireo_auth_response_t registered=service_response(&t,56);REQUIRE(registered.status==VIREO_STATUS_OK);
    EXPECT(vireo_auth_response_clear(&registered),VIREO_OK);
    request(&t,true,11,false);vireo_auth_response_t login=service_response(&t,104);REQUIRE(login.status==VIREO_STATUS_OK && login.session_handle);
    vireo_auth_session_identity_t bound;EXPECT(vireo_auth_session_lookup(t.f.sessions,t.client,login.session_handle,utc_ms(),&bound),VIREO_OK);
    vireo_mysql_user_repository_t *repo=NULL;vireo_password_policy_t const policy=VIREO_PASSWORD_POLICY_DEFAULT;
    EXPECT(vireo_mysql_user_repository_create(thread,database,&policy,&repo,NULL),VIREO_OK);
    vireo_session_token_t token;memcpy(token.bytes,login.token,32);vireo_session_token_digest_t digest;
    EXPECT(vireo_session_token_digest(&token,&digest),VIREO_OK);vireo_mysql_session_identity_t persisted;vireo_mysql_session_report_t found;
    EXPECT(vireo_mysql_user_repository_find_session(repo,&digest,utc_ms(),5000,&persisted,&found,NULL),VIREO_OK);
    REQUIRE(persisted.session_id==bound.session_id && persisted.user_id==bound.user_id);
    EXPECT(vireo_mysql_user_repository_destroy(&repo,NULL),VIREO_OK);
    EXPECT(vireo_secure_clear(&token,sizeof token),VIREO_OK);EXPECT(vireo_secure_clear(&digest,sizeof digest),VIREO_OK);
    request(&t,true,12,true);vireo_auth_response_t wrong=service_response(&t,32);REQUIRE(wrong.status==VIREO_STATUS_AUTHENTICATION_FAILED);
    EXPECT(vireo_auth_response_clear(&wrong),VIREO_OK);REQUIRE(!faults(c));
    /* 普通错密被pool保留为首错，非OK总rc与全部join进度独立。 */
    stop_discard(&t,VIREO_RESULT_NOT_FOUND);REQUIRE(!faults(c));
    EXPECT(vireo_auth_response_clear(&login),VIREO_OK);destroy_app(&t,c);

    /* 真实COMMITTED之后预算不足，无completion；不伪装成数据库未执行。 */
    unsigned baseline=sessions(thread,observer);c=&contexts[1];setup_app(&t,c,runtime,database,gate,verifier,1);
    request(&t,true,20,false);
    for(size_t i=0;i<8192 && !faults(c);++i)(void)service_turn(&t);
    REQUIRE(faults(c)==VIREO_AUTH_WORKER_FAULT_PUBLISH && !t.completed && t.submitted==1);
    vireo_inflight_store_info_t info;EXPECT(vireo_inflight_store_inspect(t.f.store,&info),VIREO_OK);REQUIRE(info.count==1);
    REQUIRE(sessions(thread,observer)==baseline+1);
    stop_discard(&t,VIREO_RESULT_RANGE);destroy_app(&t,c);

    /* 先有真实绑定；随后两个真实LOGIN提交后暂停consumer，容量1只容纳首个结果。 */
    c=&contexts[2];setup_app(&t,c,runtime,database,gate,verifier,4096);
    request(&t,true,25,false);login=service_response(&t,104);REQUIRE(login.status==VIREO_STATUS_OK);
    vireo_connection_pool_lease_t const old=t.client;uint32_t const handle=login.session_handle;
    EXPECT(vireo_auth_session_lookup(t.f.sessions,old,handle,utc_ms(),&bound),VIREO_OK);
    baseline=sessions(thread,observer);
    request(&t,true,30,false);request(&t,true,31,false);
    for(size_t i=0;i<4096 && t.submitted<3;++i) {
        (void)service_turn(&t);
    }
    REQUIRE(t.submitted==3);
    EXPECT(vireo_auth_service_quiesce(t.service),VIREO_OK);REQUIRE(sem_post(&c->release)==0);
    uint64_t now=0,until=0;EXPECT(vireo_clock_monotonic_now(&now,NULL),VIREO_OK);until=now+UINT64_C(10000000000);
    bool committed=false;
    while(now<until && !committed) {
        committed=sessions(thread,observer)==baseline+2;
        if(!committed) { (void)sched_yield();EXPECT(vireo_clock_monotonic_now(&now,NULL),VIREO_OK); }
    }
    REQUIRE(committed && atomic_load(&c->entered)==3 && atomic_load(&c->finished)==2 && !faults(c));
    vireo_completion_queue_info_t queue;vireo_result_t inspected;
    inspected=VIREO_RESULT_BUSY;
    for(size_t i=0;i<8192 && inspected==VIREO_RESULT_BUSY;++i) { inspected=vireo_completion_queue_inspect(t.queue,&queue);if(inspected==VIREO_RESULT_BUSY)(void)sched_yield(); }
    REQUIRE(inspected==VIREO_OK && queue.capacity==1 && queue.count==1 && !queue.closed);
    /* 不以快照宣称已进入cond_wait；观测仅证明队列满、第二事务已提交、producer尚未返回。 */
    stop_discard(&t,VIREO_RESULT_CANCELLED);
    REQUIRE(faults(c)==VIREO_AUTH_WORKER_FAULT_PUBLISH && atomic_load(&c->finished)==3);
    EXPECT(vireo_auth_session_lookup(t.f.sessions,old,handle,utc_ms(),&bound),VIREO_RESULT_NOT_FOUND);
    REQUIRE(sessions(thread,observer)==baseline+2);EXPECT(vireo_auth_response_clear(&login),VIREO_OK);destroy_app(&t,c);
    sql(thread,observer,"SELECT COUNT(*) FROM users","1");sql(thread,observer,"SELECT COUNT(*) FROM sessions","5");
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
    scenarios(runtime,thread,database,observer,gate,verifier);
    EXPECT(vireo_auth_login_verifier_destroy(&verifier),VIREO_OK); EXPECT(vireo_auth_password_gate_close(gate),VIREO_OK);
    EXPECT(vireo_auth_password_gate_destroy(&gate),VIREO_OK);
    bool closed=false; EXPECT(vireo_mysql_pool_close(database,&closed,NULL),VIREO_OK); REQUIRE(closed);
    EXPECT(vireo_mysql_pool_destroy(thread,&database,NULL),VIREO_OK); EXPECT(vireo_mysql_connection_destroy(thread,&observer),VIREO_OK);
    EXPECT(vireo_mysql_thread_detach(&thread),VIREO_OK); EXPECT(vireo_mysql_runtime_destroy(&runtime),VIREO_OK);
    EXPECT(vireo_secure_clear(password,sizeof(password)),VIREO_OK);
    REQUIRE(fds()==before);REQUIRE(pthread_setcancelstate(previous,NULL)==0);
    printf("PASS auth_worker_runtime real: TLS/MySQL callback, normal rejection/join progress, persisted token/binding, committed missing completion clears inflight, capacity-one full queue before close/join without consumer pop, binding forgotten, FD %zu->%zu\n",before,fds());
    return 0;
}
