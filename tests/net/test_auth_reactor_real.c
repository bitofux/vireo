/* PROJECT: VIREO; FILE: test_auth_reactor_real.c; AUTHOR: bitofux; DATE: 2026-10-20.
 * TLS客户端->认证head->真实worker/MySQL->队列->专用响应/绑定->TLS客户端。 */
#define _GNU_SOURCE
#include "auth_reactor_test_support.h"
#include <vireo/net/auth_request_head.h>
#include <vireo/service/auth_task_context.h>
#include <vireo/service/auth_task.h>
static vireo_auth_task_options_t const context_registry={100,101,5000,102,103};
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
    vireo_completion_queue_t *queue;
    vireo_notifier_t *notifier;
    uint64_t received[8];
    vireo_auth_task_context_t captured[8];
    sem_t completed[8];
    sem_t query_done, release_query;
} worker_context_t;
static vireo_result_t execute(void *context,vireo_task_t const *task)
{
    worker_context_t *w=context; REQUIRE(!pthread_equal(w->manager,pthread_self()));
    vireo_task_info_t info; EXPECT(vireo_task_inspect(task,&info),VIREO_OK);
    REQUIRE(info.metadata.route.request_sequence>=10 && info.metadata.route.request_sequence<=17);
    size_t i=(size_t)(info.metadata.route.request_sequence-10);
    vireo_mysql_thread_t *thread=NULL; vireo_mysql_user_repository_t *repo=NULL;
    vireo_password_policy_t const policy=VIREO_PASSWORD_POLICY_DEFAULT;
    EXPECT(vireo_mysql_thread_attach(w->runtime,&thread,NULL),VIREO_OK);
    EXPECT(vireo_mysql_user_repository_create(thread,w->database,&policy,&repo,NULL),VIREO_OK);
    EXPECT(vireo_auth_task_context_capture(task,w->received[i],60000, &context_registry,&w->captured[i],NULL),VIREO_OK);
    vireo_auth_task_options_t const options={100,101,5000,102,103}; vireo_auth_task_result_t result={0};
    vireo_result_t const expected=i==2?VIREO_RESULT_NOT_FOUND:i==3?VIREO_RESULT_DATABASE:i==7?VIREO_RESULT_NOT_FOUND:VIREO_OK;
    EXPECT(vireo_auth_task_execute(task,&w->captured[i],&options,repo,w->gate,w->verifier,&result),expected);
    REQUIRE(!result.registration.cleanup_pending && !result.login.lookup.cleanup_pending && !result.login.transaction.cleanup_pending);
    if(i==5) {
        REQUIRE(result.resume_report.valid && result.resume_identity.session_id);
        REQUIRE(sem_post(&w->query_done)==0);
        int rc; do { rc=sem_wait(&w->release_query); } while(rc==-1 && errno==EINTR); REQUIRE(rc==0);
    }
    vireo_completion_t *remaining=NULL; vireo_auth_completion_publish_report_t published;
    EXPECT(vireo_auth_completion_publish(task,&result,4096,w->queue,w->notifier,&remaining,&published),VIREO_OK);
    REQUIRE(!remaining && published.publication.completion_transferred);
    EXPECT(vireo_auth_task_result_clear(&result),VIREO_OK);
    EXPECT(vireo_mysql_user_repository_destroy(&repo,NULL),VIREO_OK);
    EXPECT(vireo_mysql_thread_detach(&thread),VIREO_OK);
    REQUIRE(sem_post(&w->completed[i])==0); return VIREO_OK;
}
static uint64_t utc_ms(void)
{
    struct timespec now; REQUIRE(clock_gettime(CLOCK_REALTIME,&now)==0 && now.tv_sec>=0 && now.tv_nsec>=0);
    REQUIRE((uintmax_t)now.tv_sec<=UINT64_MAX/1000);
    return (uint64_t)now.tv_sec*1000+(uint64_t)now.tv_nsec/1000000;
}
static void submit_session(fixture_t *f,worker_context_t *w,vireo_thread_pool_t *workers,
    vireo_auth_login_admission_t *admission,uint32_t sequence,bool logout,uint32_t handle,
    unsigned char const token[32])
{
    unsigned char wire[68]={0}; size_t n=logout?32:68;
    vireo_protocol_header_t h={.command=logout?VIREO_COMMAND_LOGOUT:VIREO_COMMAND_SESSION_RESUME,
        .sequence=sequence,.session_handle=logout?handle:0,.body_len=logout?0:36};
    if(!logout) { wire[33]=4; wire[35]=32; memcpy(wire+36,token,32); }
    EXPECT(vireo_protocol_header_encode(&h,wire,32),VIREO_OK);
    EXPECT(vireo_protocol_frame_crc32c_calculate(wire,32,wire+32,n-32,&h.crc32c),VIREO_OK);
    EXPECT(vireo_protocol_header_encode(&h,wire,32),VIREO_OK);
    uint64_t now; EXPECT(vireo_clock_monotonic_now(&now,NULL),VIREO_OK); w->received[sequence-10]=now;
    unsigned char const *input=NULL; receive_wire(f,wire,n,&input); input=NULL;
    vireo_auth_request_head_receipt_t head={0}; vireo_auth_request_head_report_t report; vireo_task_t *remaining=NULL;
    vireo_auth_request_submit_options_t const o={4096,4,100,101,UINT64_MAX,102,103};
    EXPECT(vireo_auth_request_submit_read_head(f->server,f->client,f->store,workers,admission,now,f->sessions,utc_ms(),
        &o,NULL,&head,&remaining,&report),VIREO_OK);
    REQUIRE(!remaining && head.submit_report.submit_report.task_transferred);
    EXPECT(vireo_auth_request_head_acknowledge(&head),VIREO_OK);
    EXPECT(vireo_secure_clear(wire,sizeof wire),VIREO_OK);
}
static void wait_sem(sem_t *s)
{ int rc; do { rc=sem_wait(s); } while(rc==-1 && errno==EINTR); REQUIRE(rc==0); }
static vireo_auth_response_t consume_session(fixture_t *f,worker_context_t *w,unsigned index,vireo_status_t status)
{
    wait_sem(&w->completed[index]);
    vireo_completion_t *owner=NULL; vireo_completion_queue_transfer_report_t moved;
    EXPECT(vireo_completion_queue_try_pop(w->queue,&owner,&moved),VIREO_OK);
    vireo_auth_response_consumer_receipt_t receipt={0}; vireo_auth_response_consumer_report_t report;
    vireo_auth_response_consumer_options_t const o={100,101,102,103};
    EXPECT(vireo_auth_response_consumer_step(f->server,f->store,f->sessions,&owner,&o,utc_ms(),&receipt,&report),VIREO_OK);
    unsigned char wire[104]; size_t n=index==4?68:32; drain(f,wire,n);
    vireo_auth_response_t v={0}; EXPECT(vireo_auth_response_decode(wire,n,&v),VIREO_OK);
    REQUIRE(v.status==status && v.sequence==index+10);
    EXPECT(vireo_auth_response_consumer_acknowledge(owner,&receipt),VIREO_OK);
    EXPECT(vireo_secure_clear(wire,sizeof wire),VIREO_OK); return v;
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
    fixture_t f; setup_capacity(&f,true,2);
    vireo_task_queue_t *tasks=NULL; vireo_thread_pool_t *workers=NULL;
    vireo_task_queue_options_t const task_options={4,65536}; vireo_thread_pool_options_t const pool_options={2,65536};
    EXPECT(vireo_task_queue_create(&task_options,&tasks),VIREO_OK); EXPECT(vireo_task_queue_prepare_wait(tasks),VIREO_OK);
    EXPECT(vireo_thread_pool_create(&pool_options,&workers),VIREO_OK);
    worker_context_t w={.manager=pthread_self(),.runtime=runtime,.database=database,.gate=gate,.verifier=verifier};
    vireo_completion_queue_options_t const completion_options={4,65536}; vireo_notifier_options_t const notifier_options={4096};
    EXPECT(vireo_completion_queue_create(&completion_options,&w.queue),VIREO_OK); EXPECT(vireo_completion_queue_prepare_wait(w.queue),VIREO_OK);
    EXPECT(vireo_notifier_create(&notifier_options,&w.notifier,NULL),VIREO_OK);
    for(size_t i=0;i<8;++i) REQUIRE(sem_init(&w.completed[i],0,0)==0);
    REQUIRE(sem_init(&w.query_done,0,0)==0 && sem_init(&w.release_query,0,0)==0);
    vireo_thread_pool_configuration_t const configuration={tasks,execute,&w}; vireo_thread_pool_report_t pool_report;
    EXPECT(vireo_thread_pool_configure(workers,&configuration,NULL),VIREO_OK);
    EXPECT(vireo_thread_pool_start(workers,&pool_report),VIREO_OK); EXPECT(vireo_thread_pool_enable_execution(workers,&pool_report),VIREO_OK);
    vireo_auth_login_admission_t *admission=NULL; vireo_auth_login_admission_options_t const admission_options=VIREO_AUTH_LOGIN_ADMISSION_OPTIONS_DEFAULT;
    uint64_t initial=0; EXPECT(vireo_clock_monotonic_now(&initial,NULL),VIREO_OK);
    EXPECT(vireo_auth_login_admission_create(&admission_options,initial,&admission),VIREO_OK);
    vireo_auth_request_submit_options_t const submit_options={4096,4,100,101,UINT64_MAX,102,103};
    vireo_auth_response_consumer_options_t const consumer_options={100,101,102,103};
    vireo_auth_response_t login={0}; uint64_t user=0; uint32_t handle=0;
    for(size_t i=0;i<4;++i) {
        unsigned char request[156]; size_t n=request_frame(request,i==1 || i==2,(uint32_t)i+10,i==2);
        EXPECT(vireo_clock_monotonic_now(&w.received[i],NULL),VIREO_OK);
        unsigned char const *input=NULL; receive_wire(&f,request,n,&input); input=NULL;
        vireo_auth_request_head_receipt_t head={0}; vireo_auth_request_head_report_t head_report; vireo_task_t *remaining=NULL;
        EXPECT(vireo_auth_request_submit_read_head(f.server,f.client,f.store,workers,admission,w.received[i],f.sessions,0,
            &submit_options,NULL,&head,&remaining,&head_report),VIREO_OK);
        REQUIRE(!remaining && head.submit_report.submit_report.task_transferred && head.state==VIREO_AUTH_REQUEST_HEAD_CONSUMED);
        EXPECT(vireo_auth_request_head_acknowledge(&head),VIREO_OK);
        EXPECT(vireo_secure_clear(request,sizeof(request)),VIREO_OK);
        int waited; do { waited=sem_wait(&w.completed[i]); } while(waited==-1 && errno==EINTR); REQUIRE(waited==0);
        vireo_completion_t *owner=NULL; vireo_completion_queue_transfer_report_t transfer;
        EXPECT(vireo_completion_queue_try_pop(w.queue,&owner,&transfer),VIREO_OK); REQUIRE(transfer.transferred && owner);
        uint64_t hints=0; EXPECT(vireo_notifier_consume(w.notifier,&hints,NULL),VIREO_OK); REQUIRE(hints>0);
        vireo_auth_response_consumer_receipt_t receipt={0}; vireo_auth_response_consumer_report_t report;
        EXPECT(vireo_auth_response_consumer_step(f.server,f.store,f.sessions,&owner,&consumer_options,utc_ms(),&receipt,&report),VIREO_OK);
        REQUIRE(!owner && report.enqueued && report.consumption.record_consumed && report.refresh_called);
        unsigned char reply[104]; size_t size=i==0?56:i==1?104:32; drain(&f,reply,size);
        vireo_auth_response_t value={0}; EXPECT(vireo_auth_response_decode(reply,size,&value),VIREO_OK);
        REQUIRE(value.sequence==i+10 && value.command==(i==1 || i==2?VIREO_COMMAND_LOGIN:VIREO_COMMAND_REGISTER));
        if(i==0) { REQUIRE(value.status==VIREO_STATUS_OK && value.root_node_id!=0 && !report.bound); user=value.user_id; }
        else if(i==1) {
            REQUIRE(value.status==VIREO_STATUS_OK && value.user_id==user && report.bound && value.session_handle!=0);
            login=value; handle=value.session_handle;
        } else REQUIRE(value.status==(i==2?VIREO_STATUS_AUTHENTICATION_FAILED:VIREO_STATUS_USER_EXISTS) && !report.bound);
        if(i>=1) {
            vireo_auth_session_identity_t identity;
            EXPECT(vireo_auth_session_lookup(f.sessions,f.client,handle,utc_ms(),&identity),VIREO_OK);
            REQUIRE(identity.user_id==user && identity.expires_at_ms==login.expires_at_ms && !identity.revoked);
        }
        EXPECT(vireo_auth_response_consumer_acknowledge(owner,&receipt),VIREO_OK);
        EXPECT(vireo_auth_response_clear(&value),VIREO_OK); EXPECT(vireo_secure_clear(reply,sizeof(reply)),VIREO_OK);
    }
    vireo_mysql_user_repository_t *repo=NULL; vireo_password_policy_t const policy=VIREO_PASSWORD_POLICY_DEFAULT;
    EXPECT(vireo_mysql_user_repository_create(thread,database,&policy,&repo,NULL),VIREO_OK);
    vireo_session_token_t token; memcpy(token.bytes,login.token,32); vireo_session_token_digest_t digest;
    EXPECT(vireo_session_token_digest(&token,&digest),VIREO_OK);
    vireo_mysql_session_identity_t persistent; vireo_mysql_session_report_t found;
    EXPECT(vireo_mysql_user_repository_find_session(repo,&digest,utc_ms(),5000,&persistent,&found,NULL),VIREO_OK);
    vireo_auth_session_identity_t bound;
    EXPECT(vireo_auth_session_lookup(f.sessions,f.client,handle,utc_ms(),&bound),VIREO_OK);
    REQUIRE(persistent.user_id==user && persistent.session_id==bound.session_id && login.expires_at_ms-login.issued_at_ms==60000);
    sql(thread,observer,"SELECT COUNT(*) FROM users","1"); sql(thread,observer,"SELECT COUNT(*) FROM file_nodes","1");
    sql(thread,observer,"SELECT COUNT(*) FROM sessions","1"); sql(thread,observer,"SELECT COUNT(*) FROM operation_audits","2");
    fixture_t g={.server=f.server,.store=f.store,.sessions=f.sessions,.address=f.address,.peer=-1}; client_open(&g,true);
    submit_session(&g,&w,workers,admission,14,false,0,login.token);
    vireo_auth_response_t restored=consume_session(&g,&w,4,VIREO_STATUS_OK);
    REQUIRE(restored.user_id==login.user_id && restored.issued_at_ms==login.issued_at_ms && restored.expires_at_ms==login.expires_at_ms);
    submit_session(&f,&w,workers,admission,15,false,0,login.token);
    wait_sem(&w.query_done); /* 已完成真实SQL验证，worker在发布前受控暂停。 */
    submit_session(&g,&w,workers,admission,16,true,restored.session_handle,NULL);
    vireo_auth_response_t logged_out=consume_session(&g,&w,6,VIREO_STATUS_OK);
    EXPECT(vireo_auth_session_lookup(f.sessions,f.client,handle,utc_ms(),&bound),VIREO_RESULT_CANCELLED);
    REQUIRE(sem_post(&w.release_query)==0);
    vireo_auth_response_t late=consume_session(&f,&w,5,VIREO_STATUS_BUSY);
    submit_session(&f,&w,workers,admission,17,false,0,login.token);
    vireo_auth_response_t revoked=consume_session(&f,&w,7,VIREO_STATUS_AUTHENTICATION_FAILED);
    sql(thread,observer,"SELECT COUNT(*) FROM sessions","1");
    sql(thread,observer,"SELECT COUNT(*) FROM operation_audits","3");
    sql(thread,observer,"SELECT COUNT(*) FROM sessions WHERE status=2","1");
    EXPECT(vireo_auth_response_clear(&restored),VIREO_OK); EXPECT(vireo_auth_response_clear(&logged_out),VIREO_OK);
    EXPECT(vireo_auth_response_clear(&late),VIREO_OK); EXPECT(vireo_auth_response_clear(&revoked),VIREO_OK);
    client_close(&g);
    vireo_thread_pool_shutdown_report_t shutdown;
    EXPECT(vireo_thread_pool_shutdown_and_join(workers,VIREO_TASK_QUEUE_DRAIN,&shutdown),VIREO_OK); REQUIRE(shutdown.pool_report.joined_count==2);
    EXPECT(vireo_auth_session_revoke(f.sessions,bound.session_id),VIREO_OK);
    EXPECT(vireo_auth_session_lookup(f.sessions,f.client,handle,utc_ms(),&bound),VIREO_RESULT_CANCELLED);
    vireo_connection_pool_lease_t const old=f.client; client_close(&f); client_open(&f,true);
    REQUIRE(f.client.slot_index==old.slot_index && f.client.generation!=old.generation);
    EXPECT(vireo_auth_session_lookup(f.sessions,f.client,handle,utc_ms(),&bound),VIREO_RESULT_NOT_FOUND);
    EXPECT(vireo_auth_session_lookup(f.sessions,old,handle,utc_ms(),&bound),VIREO_RESULT_NOT_FOUND);
    EXPECT(vireo_auth_session_forget(f.sessions,old),VIREO_OK);
    EXPECT(vireo_auth_response_clear(&login),VIREO_OK); EXPECT(vireo_secure_clear(&token,sizeof(token)),VIREO_OK);
    EXPECT(vireo_secure_clear(&digest,sizeof(digest)),VIREO_OK);
    EXPECT(vireo_mysql_user_repository_destroy(&repo,NULL),VIREO_OK);
    EXPECT(vireo_thread_pool_destroy(&workers),VIREO_OK); EXPECT(vireo_task_queue_destroy(&tasks),VIREO_OK);
    EXPECT(vireo_completion_queue_destroy(&w.queue),VIREO_OK); EXPECT(vireo_notifier_destroy(&w.notifier,NULL),VIREO_OK);
    EXPECT(vireo_auth_login_admission_destroy(&admission),VIREO_OK);
    for(size_t i=0;i<8;++i) REQUIRE(sem_destroy(&w.completed[i])==0);
    REQUIRE(sem_destroy(&w.query_done)==0 && sem_destroy(&w.release_query)==0);
    EXPECT(vireo_secure_clear(w.captured,sizeof w.captured),VIREO_OK);
    cleanup(&f);
    EXPECT(vireo_auth_login_verifier_destroy(&verifier),VIREO_OK); EXPECT(vireo_auth_password_gate_close(gate),VIREO_OK);
    EXPECT(vireo_auth_password_gate_destroy(&gate),VIREO_OK);
    bool closed=false; EXPECT(vireo_mysql_pool_close(database,&closed,NULL),VIREO_OK); REQUIRE(closed);
    EXPECT(vireo_mysql_pool_destroy(thread,&database,NULL),VIREO_OK); EXPECT(vireo_mysql_connection_destroy(thread,&observer),VIREO_OK);
    EXPECT(vireo_mysql_thread_detach(&thread),VIREO_OK); EXPECT(vireo_mysql_runtime_destroy(&runtime),VIREO_OK);
    EXPECT(vireo_secure_clear(password,sizeof(password)),VIREO_OK);
    REQUIRE(fds()==before); REQUIRE(pthread_setcancelstate(previous,NULL)==0);
    printf("PASS auth_reactor real: 8 TLS requests, real SQL resume held by semaphore before publication, another worker logout, old result BUSY/no revival, no new Session/audit for resume, register/login/wrong-password/duplicate, 2 workers/MySQL/queue/consumer, client token matches persistent session and binding, local revoke/stale-generation, FD %zu->%zu\n",before,fds());
    return 0;
}
