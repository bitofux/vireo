/* PROJECT : VIREO
 * FILE : test_auth_service_real.c
 * AUTHOR : bitofux
 * DATE : 2026-10-19
 * BRIEF : 真实注册/登录/会话核对、行锁重核及Reactor准入后的真实线程池worker。
 */
#define _POSIX_C_SOURCE 200809L
#include "auth_service_internal.h"
#include <vireo/persistence/mysql_schema.h>
#include <vireo/persistence/mysql_statement.h>
#include <vireo/service/auth_login_admission.h>
#include <vireo/thread/thread_pool.h>
#include <vireo/base/secure_clear.h>
#include <vireo/base/clock.h>
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(call, expected) do { errno=EDOM; vireo_result_t code_=(call); \
    if (code_!=(expected)) { fprintf(stderr,"line %d got %d want %d\n",__LINE__,(int)code_,(int)(expected)); abort(); } \
    assert(errno==EDOM); } while (0)
static const vireo_password_policy_t policy=VIREO_PASSWORD_POLICY_DEFAULT;
static size_t observed_releases;

/* 所有SQL为固定非秘密语句；结果在下次fetch撤销view之前完成比较。 */
static void sql(vireo_mysql_thread_t *thread, vireo_mysql_connection_t *connection,
    const char *text, const char *expected)
{
    const vireo_mysql_statement_limits_t limits={0,1,0,64,8192};
    vireo_mysql_statement_t *s=NULL; vireo_mysql_execution_t ex;
    CHECK(vireo_mysql_statement_prepare(thread,connection,text,strlen(text),&limits,&s,NULL),VIREO_OK);
    CHECK(vireo_mysql_statement_execute(thread,s,NULL,0,&ex,NULL),VIREO_OK);
    if (expected!=NULL) {
        vireo_mysql_fetch_outcome_t fetched; vireo_mysql_cell_view_t cell;
        CHECK(vireo_mysql_statement_fetch(thread,s,&fetched,NULL),VIREO_OK); assert(fetched==VIREO_MYSQL_FETCH_ROW);
        CHECK(vireo_mysql_statement_column(thread,s,0,&cell),VIREO_OK);
        assert(!cell.is_null && cell.length==strlen(expected) && !memcmp(cell.data,expected,cell.length));
        CHECK(vireo_mysql_statement_fetch(thread,s,&fetched,NULL),VIREO_OK); assert(fetched==VIREO_MYSQL_FETCH_DONE);
    } else { assert(!ex.has_result); }
    CHECK(vireo_mysql_statement_destroy(thread,&s,NULL),VIREO_OK);
}
static void registration(vireo_mysql_user_repository_t *repo,vireo_auth_password_gate_t *gate,
    const char *name,unsigned char event,vireo_result_t expected)
{
    vireo_auth_registration_request_t q={.username=name,.username_length=strlen(name),
        .password="Correct!7",.password_length=9,.occurred_at_ms=1000,.latency_us=11};
    q.request_id[15]=event; vireo_mysql_registration_report_t report;
    CHECK(vireo_auth_service_register(repo,gate,&q,5000,&report,NULL),expected);
    assert(!report.cleanup_pending);
    if (expected==VIREO_OK) { assert(report.commit==VIREO_MYSQL_REGISTRATION_COMMITTED && report.user_id && report.root_node_id && report.audit_id); }
    else { assert(report.commit==VIREO_MYSQL_REGISTRATION_NOT_COMMITTED && report.conflict==VIREO_MYSQL_REGISTRATION_USERNAME_CONFLICT); }
}
static vireo_auth_login_request_t request(const char *name,const char *password,unsigned char event)
{
    vireo_auth_login_request_t q={.username=name,.username_length=strlen(name),.password=password,
        .password_length=strlen(password),.issued_at_ms=2000,.expires_at_ms=5000,.latency_us=13};
    q.request_id[15]=event; return q;
}
static void session(vireo_mysql_user_repository_t *repo,const vireo_auth_login_result_t *out)
{
    assert(out->transaction.commit==VIREO_MYSQL_LOGIN_COMMITTED && out->transaction.session_id && out->user_id);
    vireo_session_token_digest_t digest;
    CHECK(vireo_session_token_digest(&out->token,&digest),VIREO_OK);
    vireo_mysql_session_identity_t identity; vireo_mysql_session_report_t report;
    CHECK(vireo_mysql_user_repository_find_session(repo,&digest,2000,5000,&identity,&report,NULL),VIREO_OK);
    assert(report.valid && identity.user_id==out->user_id && identity.session_id==out->transaction.session_id);
    CHECK(vireo_mysql_user_repository_find_session(repo,&digest,5000,5000,&identity,&report,NULL),VIREO_RESULT_NOT_FOUND);
    assert(!report.valid && report.issue==VIREO_MYSQL_SESSION_EXPIRED);
    CHECK(vireo_secure_clear(&digest,sizeof(digest)),VIREO_OK);
}

typedef struct probe {
    vireo_mysql_pool_t *pool;
    vireo_mysql_thread_t *thread;
    vireo_mysql_connection_t *observer;
    unsigned change;
    size_t released;
} probe_t;
static vireo_result_t hash(void *c,vireo_auth_password_gate_t *g,const void *p,size_t n,char *h,size_t cap,size_t *len)
{ (void)c; return vireo_auth_password_hash_create(g,p,n,h,cap,len); }
static vireo_result_t reg(void *c,vireo_mysql_user_repository_t *r,const vireo_mysql_registration_input_t *in,
    uint32_t ms,vireo_mysql_registration_report_t *out,vireo_mysql_user_repository_error_t *e)
{ (void)c; return vireo_mysql_user_repository_register(r,in,ms,out,e); }
static vireo_result_t lookup(void *c,vireo_mysql_user_repository_t *r,const void *key,size_t n,uint32_t ms,
    vireo_mysql_user_credentials_t *out,vireo_mysql_credentials_report_t *report,vireo_mysql_user_repository_error_t *e)
{ (void)c; return vireo_mysql_user_repository_find_credentials(r,key,n,ms,out,report,e); }
static vireo_result_t verify(void *c,const vireo_auth_login_verifier_t *v,vireo_auth_password_gate_t *g,
    const vireo_mysql_user_credentials_t *in,const void *p,size_t n,bool *out)
{
    probe_t *probe=c; vireo_mysql_pool_info_t info;
    CHECK(vireo_mysql_pool_inspect(probe->pool,&info),VIREO_OK); assert(info.leased==0); ++probe->released;
    vireo_result_t result=vireo_auth_login_verifier_verify(v,g,in,p,n,out);
    if (result==VIREO_OK && *out && probe->change==1) {
        sql(probe->thread,probe->observer,"UPDATE users SET status=2 WHERE username_key='alice_7'",NULL);
    } else if (result==VIREO_OK && *out && probe->change==2) {
        sql(probe->thread,probe->observer,"UPDATE users a JOIN users b ON b.username_key='bob_007' SET a.password_hash=b.password_hash WHERE a.username_key='alice_7'",NULL);
    }
    return result;
}
static vireo_result_t token(void *c,vireo_session_token_t *t,vireo_session_token_digest_t *d)
{ (void)c; return vireo_session_token_generate(t,d); }
static vireo_result_t login(void *c,vireo_mysql_user_repository_t *r,const vireo_mysql_login_input_t *in,
    uint32_t ms,vireo_mysql_login_report_t *out,vireo_mysql_user_repository_error_t *e)
{ (void)c; return vireo_mysql_user_repository_login(r,in,ms,out,e); }

typedef struct worker_context {
    pthread_t manager;
    pthread_barrier_t entered;
    vireo_mysql_runtime_t *runtime;
    vireo_mysql_pool_t *pool;
    vireo_auth_password_gate_t *gate;
    const vireo_auth_login_verifier_t *verifier;
    size_t completed[2];
} worker_context_t;
static vireo_result_t execute(void *context,const vireo_task_t *task)
{
    worker_context_t *f=context; assert(!pthread_equal(f->manager,pthread_self()));
    vireo_task_info_t info; vireo_task_payload_view_t view;
    assert(vireo_task_inspect(task,&info)==VIREO_OK && vireo_task_borrow_payload(task,&view)==VIREO_OK);
    assert(info.metadata.request_instance_id>=1 && info.metadata.request_instance_id<=2 && view.size==9);
    size_t index=(size_t)(info.metadata.request_instance_id-1);
    vireo_mysql_thread_t *thread=NULL; vireo_mysql_user_repository_t *repo=NULL;
    CHECK(vireo_mysql_thread_attach(f->runtime,&thread,NULL),VIREO_OK);
    CHECK(vireo_mysql_user_repository_create(thread,f->pool,&policy,&repo,NULL),VIREO_OK);
    int code=pthread_barrier_wait(&f->entered); assert(code==0 || code==PTHREAD_BARRIER_SERIAL_THREAD);
    vireo_auth_login_request_t q=request("ALICE_7","Correct!7",(unsigned char)(40+index));
    q.password=view.data; q.password_length=view.size;
    vireo_auth_login_result_t out;
    CHECK(vireo_auth_service_login(repo,f->gate,f->verifier,&q,5000,&out,NULL),VIREO_OK);
    assert(!out.lookup.cleanup_pending && !out.transaction.cleanup_pending);
    session(repo,&out); CHECK(vireo_auth_login_result_clear(&out),VIREO_OK); f->completed[index]=1;
    CHECK(vireo_mysql_user_repository_destroy(&repo,NULL),VIREO_OK);
    CHECK(vireo_mysql_thread_detach(&thread),VIREO_OK); return VIREO_OK;
}
static size_t fd_count(void)
{ DIR *d=opendir("/proc/self/fd"); assert(d); size_t n=0; while(readdir(d)!=NULL){++n;} assert(closedir(d)==0); return n; }

int main(int argc,char **argv)
{
    assert(argc==5); char password[1026]; FILE *file=fopen(argv[3],"r");
    assert(file && fgets(password,(int)sizeof(password),file)!=NULL && fclose(file)==0);
    password[strcspn(password,"\n")]=0;
    struct sigaction action={0}; action.sa_handler=SIG_IGN;
    assert(sigemptyset(&action.sa_mask)==0 && sigaction(SIGPIPE,&action,NULL)==0);
    size_t before=fd_count(); vireo_mysql_runtime_t *runtime=NULL; vireo_mysql_thread_t *thread=NULL;
    CHECK(vireo_mysql_runtime_create(&runtime,NULL),VIREO_OK); CHECK(vireo_mysql_thread_attach(runtime,&thread,NULL),VIREO_OK);
    const vireo_mysql_connection_options_t options={argv[1],argv[2],password,argv[4],3,3,3};
    const vireo_mysql_migration_t *catalog=NULL; size_t count=0;
    CHECK(vireo_mysql_schema_catalog(&catalog,&count),VIREO_OK); vireo_mysql_migration_report_t migrated;
    CHECK(vireo_mysql_migration_apply(thread,&options,catalog,count,&migrated,NULL),VIREO_OK);
    assert(migrated.ready && migrated.steps_completed==15);
    vireo_mysql_connection_t *observer=NULL; CHECK(vireo_mysql_connection_open(thread,&options,&observer,NULL),VIREO_OK);
    const vireo_mysql_pool_options_t po={options,2,2,VIREO_MYSQL_POOL_MEMORY_MAX}; vireo_mysql_pool_t *pool=NULL;
    CHECK(vireo_mysql_pool_create(thread,&po,&pool,NULL),VIREO_OK);
    vireo_mysql_user_repository_t *repo=NULL; CHECK(vireo_mysql_user_repository_create(thread,pool,&policy,&repo,NULL),VIREO_OK);
    const vireo_auth_password_gate_options_t go=VIREO_AUTH_PASSWORD_GATE_OPTIONS_DEFAULT;
    vireo_auth_password_gate_t *gate=NULL; vireo_auth_login_verifier_t *verifier=NULL;
    CHECK(vireo_auth_password_gate_create(&go,&gate),VIREO_OK);
    CHECK(vireo_auth_login_verifier_create(gate,&verifier),VIREO_OK);
    registration(repo,gate,"Alice_7",1,VIREO_OK); registration(repo,gate,"Bob_007",2,VIREO_OK);
    registration(repo,gate,"ALICE_7",3,VIREO_RESULT_DATABASE);
    sql(thread,observer,"SELECT COUNT(*) FROM users","2");
    sql(thread,observer,"SELECT COUNT(*) FROM file_nodes","2");
    sql(thread,observer,"SELECT COUNT(*) FROM operation_audits WHERE action=1","2");
    sql(thread,observer,"UPDATE users SET status=2 WHERE username_key='bob_007'",NULL);
    const char *names[]={"ALICE_7","Alice_7","Nobody_7","Bob_007"};
    const char *passwords[]={"Correct!7","incorrect","Correct!7","Correct!7"};
    for(size_t i=0;i<4;++i){
        vireo_auth_login_request_t q=request(names[i],passwords[i],(unsigned char)(10+i)); vireo_auth_login_result_t out;
        CHECK(vireo_auth_service_login(repo,gate,verifier,&q,5000,&out,NULL),i==0 ? VIREO_OK : VIREO_RESULT_NOT_FOUND);
        if(i==0){session(repo,&out);}else{assert(out.transaction.commit==VIREO_MYSQL_LOGIN_NOT_COMMITTED && out.user_id==0);}
        CHECK(vireo_auth_login_result_clear(&out),VIREO_OK);
    }
    /* 同一次完整服务调用内，在真实验密后、登录事务前改变数据库，检验重核。 */
    probe_t probe={pool,thread,observer,0,0};
    const vireo_auth_service_runtime_t rt={&probe,hash,reg,lookup,verify,token,login,NULL};
    for(unsigned change=0;change<3;++change){
        probe.change=change; vireo_auth_login_request_t q=request("Alice_7","Correct!7",(unsigned char)(20+change));
        vireo_auth_login_result_t out;
        CHECK(vireo_auth_service_login_with_runtime(repo,gate,verifier,&q,5000,&out,NULL,&rt),change==0 ? VIREO_OK : VIREO_RESULT_NOT_FOUND);
        if(change==0){session(repo,&out);}else{
            assert(out.transaction.commit==VIREO_MYSQL_LOGIN_NOT_COMMITTED && out.user_id==0);
            assert(out.transaction.issue==(change==1 ? VIREO_MYSQL_LOGIN_USER_DISABLED : VIREO_MYSQL_LOGIN_PASSWORD_CHANGED));
        }
        CHECK(vireo_auth_login_result_clear(&out),VIREO_OK);
        if(change==1){sql(thread,observer,"UPDATE users SET status=1 WHERE username_key='alice_7'",NULL);}
    }
    observed_releases=probe.released; assert(observed_releases==3);
    CHECK(vireo_mysql_user_repository_destroy(&repo,NULL),VIREO_OK);
    /* 真实线程池：manager串行准入后才建task，两个OS worker各自attach/create/destroy。 */
    worker_context_t f={.manager=pthread_self(),.runtime=runtime,.pool=pool,.gate=gate,.verifier=verifier};
    assert(pthread_barrier_init(&f.entered,NULL,2)==0);
    vireo_task_queue_t *queue=NULL; vireo_thread_pool_t *workers=NULL;
    const vireo_task_queue_options_t qo={2,65536}; const vireo_thread_pool_options_t wo={2,65536};
    assert(vireo_task_queue_create(&qo,&queue)==VIREO_OK && vireo_task_queue_prepare_wait(queue)==VIREO_OK);
    assert(vireo_thread_pool_create(&wo,&workers)==VIREO_OK);
    const vireo_thread_pool_configuration_t configuration={queue,execute,&f}; vireo_thread_pool_report_t wr;
    assert(vireo_thread_pool_configure(workers,&configuration,NULL)==VIREO_OK);
    assert(vireo_thread_pool_start(workers,&wr)==VIREO_OK && wr.created_count==2);
    assert(vireo_thread_pool_enable_execution(workers,&wr)==VIREO_OK);
    vireo_auth_login_admission_options_t ao=VIREO_AUTH_LOGIN_ADMISSION_OPTIONS_DEFAULT;
    ao.account.burst_tokens=3;
    vireo_auth_login_admission_t *admission=NULL; CHECK(vireo_auth_login_admission_create(&ao,0,&admission),VIREO_OK);
    const vireo_auth_login_peer_t peer={VIREO_AUTH_LOGIN_PEER_IPV4,{127,0,0,1}}; const unsigned char device[16]={0};
    for(uint64_t i=1;i<=2;++i){
        vireo_rate_limit_decision_t decision;
        CHECK(vireo_auth_login_admission_check(admission,0,&peer,"Alice_7",7,device,&decision),VIREO_OK);
        assert(decision.outcome==VIREO_RATE_LIMIT_ADMITTED);
        vireo_task_route_t route; vireo_task_metadata_t metadata; vireo_task_t *task=NULL;
        assert(vireo_task_route_make(1,1,1,(uint32_t)i,&route)==VIREO_OK);
        assert(vireo_task_metadata_make(route,i,1,UINT64_MAX,&metadata)==VIREO_OK);
        assert(vireo_task_create_copy(metadata,"Correct!7",9,4096,&task)==VIREO_OK);
        vireo_thread_pool_submit_report_t submitted;
        /* try_submit允许worker并发领取时的瞬时锁竞争；只重试尚未交接的同一task，
         * 不重新准入/建task/执行业务，也不以错误码推翻真实transferred。 */
        for(size_t attempt=0;task!=NULL && attempt<100000;++attempt) {
            vireo_result_t const rc=vireo_thread_pool_try_submit(workers,&task,&submitted);
            if(submitted.queue_report.transferred) { assert(rc==VIREO_OK && task==NULL); break; }
            assert(rc==VIREO_RESULT_BUSY && task!=NULL); assert(sched_yield()==0);
        }
        assert(task==NULL);
    }
    vireo_thread_pool_shutdown_report_t shutdown;
    uint64_t join_begin=0,join_now=0;
    CHECK(vireo_clock_monotonic_now(&join_begin,NULL),VIREO_OK);
    for(;;) {
        vireo_result_t const join_rc=vireo_thread_pool_shutdown_and_join(workers,VIREO_TASK_QUEUE_DRAIN,&shutdown);
        if(join_rc==VIREO_OK) break;
        /* 只恢复公开关闭锁竞争/回收前资格观察，绝不重试业务或pthread join失败。 */
        assert(join_rc==VIREO_RESULT_BUSY &&
            ((shutdown.stage==VIREO_THREAD_POOL_SHUTDOWN_STAGE_CLOSE_QUEUE && !shutdown.join_called) ||
             (shutdown.stage==VIREO_THREAD_POOL_SHUTDOWN_STAGE_JOIN_WORKERS &&
              shutdown.pool_report.stage==VIREO_THREAD_POOL_STAGE_CHECK_QUEUE)));
        assert(sched_yield()==0);
        CHECK(vireo_clock_monotonic_now(&join_now,NULL),VIREO_OK);
        assert(join_now-join_begin<UINT64_C(5000000000));
    }
    assert(shutdown.pool_report.joined_count==2 && f.completed[0]==1 && f.completed[1]==1);
    vireo_rate_limit_decision_t decision;
    CHECK(vireo_auth_login_admission_check(admission,0,&peer,"ALICE_7",7,device,&decision),VIREO_OK);
    assert(decision.outcome==VIREO_RATE_LIMIT_ADMITTED); /* 两次service未复扣账号桶。 */
    CHECK(vireo_auth_login_admission_check(admission,0,&peer,"Alice_7",7,device,&decision),VIREO_OK);
    assert(decision.outcome==VIREO_RATE_LIMIT_THROTTLED);
    CHECK(vireo_auth_login_admission_destroy(&admission),VIREO_OK);
    assert(vireo_thread_pool_destroy(&workers)==VIREO_OK && vireo_task_queue_destroy(&queue)==VIREO_OK);
    assert(pthread_barrier_destroy(&f.entered)==0);
    sql(thread,observer,"SELECT COUNT(*) FROM sessions","4");
    sql(thread,observer,"SELECT COUNT(*) FROM operation_audits WHERE action=2","4");
    CHECK(vireo_auth_login_verifier_destroy(&verifier),VIREO_OK);
    CHECK(vireo_auth_password_gate_close(gate),VIREO_OK); CHECK(vireo_auth_password_gate_destroy(&gate),VIREO_OK);
    bool closed=false; CHECK(vireo_mysql_pool_close(pool,&closed,NULL),VIREO_OK); assert(closed);
    CHECK(vireo_mysql_pool_destroy(thread,&pool,NULL),VIREO_OK); CHECK(vireo_mysql_connection_destroy(thread,&observer),VIREO_OK);
    CHECK(vireo_mysql_thread_detach(&thread),VIREO_OK); CHECK(vireo_mysql_runtime_destroy(&runtime),VIREO_OK);
    CHECK(vireo_secure_clear(password,sizeof(password)),VIREO_OK); assert(fd_count()==before);
    printf("PASS real auth service: registration atomicity, 4 sessions, disabled/PHC recheck, %zu KDF-after-release probes, 2 thread-pool workers, single admission charge; FD %zu->%zu\n",observed_releases,before,fd_count());
    return 0;
}
