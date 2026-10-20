/* PROJECT: VIREO; FILE: test_auth_service_loop_real.c; AUTHOR: bitofux; DATE: 2026-10-20.
 * TLS客户端->认证head->真实worker/MySQL->队列->专用响应/绑定->TLS客户端。 */
#define _GNU_SOURCE
#include "auth_service_test_support.h"
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
    service_fixture_t *fixture;
    atomic_uint calls;
} worker_context_t;
/* 固定池的应用callback仍同OS worker attach/create/use/destroy/detach。
 * 提交端deadline减同一显式timeout恢复可信提交时刻，不读取跨线程可变客户槽。 */
static vireo_result_t execute(void *context,vireo_task_t const *task)
{
    worker_context_t *w=context; REQUIRE(!pthread_equal(w->manager,pthread_self()));
    vireo_task_info_t info; EXPECT(vireo_task_inspect(task,&info),VIREO_OK);
    uint32_t sequence=info.metadata.route.request_sequence; REQUIRE(sequence>=10 && sequence<=13);
    REQUIRE(info.metadata.deadline_ns>=REQUEST_TIMEOUT);
    vireo_mysql_thread_t *thread=NULL; vireo_mysql_user_repository_t *repo=NULL;
    vireo_password_policy_t const policy=VIREO_PASSWORD_POLICY_DEFAULT;
    EXPECT(vireo_mysql_thread_attach(w->runtime,&thread,NULL),VIREO_OK);
    EXPECT(vireo_mysql_user_repository_create(thread,w->database,&policy,&repo,NULL),VIREO_OK);
    vireo_auth_task_context_t captured;
    EXPECT(vireo_auth_task_context_capture(task,info.metadata.deadline_ns-REQUEST_TIMEOUT,60000, &context_registry,&captured,NULL),VIREO_OK);
    vireo_auth_task_options_t const options={100,101,5000,102,103}; vireo_auth_task_result_t result={0};
    vireo_result_t expected=sequence==12?VIREO_RESULT_NOT_FOUND:sequence==13?VIREO_RESULT_DATABASE:VIREO_OK;
    EXPECT(vireo_auth_task_execute(task,&captured,&options,repo,w->gate,w->verifier,&result),expected);
    REQUIRE(!result.registration.cleanup_pending && !result.login.lookup.cleanup_pending && !result.login.transaction.cleanup_pending);
    vireo_completion_t *remaining=NULL; vireo_auth_completion_publish_report_t published;
    EXPECT(vireo_auth_completion_publish(task,&result,4096,w->fixture->queue,w->fixture->notifier,&remaining,&published),VIREO_OK);
    REQUIRE(!remaining && published.publication.completion_transferred);
    EXPECT(vireo_auth_task_result_clear(&result),VIREO_OK); EXPECT(vireo_secure_clear(&captured,sizeof captured),VIREO_OK);
    EXPECT(vireo_mysql_user_repository_destroy(&repo,NULL),VIREO_OK); EXPECT(vireo_mysql_thread_detach(&thread),VIREO_OK);
    atomic_fetch_add(&w->calls,1); return VIREO_OK;
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
    atomic_init(&w.calls,0); service_setup(&t,execute,&w); service_create(&t); peer_connect(&t);
    vireo_auth_response_t login={0}; uint64_t user=0; uint32_t handle=0;
    for(size_t i=0;i<4;++i) {
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
    REQUIRE(t.submitted==4 && t.completed==4 && !t.rejected);
    EXPECT(vireo_auth_service_quiesce(t.service),VIREO_OK);
    vireo_thread_pool_shutdown_report_t shutdown;
    EXPECT(vireo_thread_pool_shutdown_and_join(t.workers,VIREO_TASK_QUEUE_DRAIN,&shutdown),VIREO_OK);
    REQUIRE(shutdown.pool_report.joined_count==1 && atomic_load(&w.calls)==4);
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
    REQUIRE(fds()==before); REQUIRE(pthread_setcancelstate(previous,NULL)==0);
    printf("PASS auth_service real: automatic TLS accept/handshake/4 requests/responses, configured worker/context/MySQL/queue/consumer, client token matches persistent session and binding, quiesce/cleanup, FD %zu->%zu\n",before,fds());
    return 0;
}
