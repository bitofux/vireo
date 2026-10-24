/* PROJECT : VIREO; FILE : test_mysql_node_repository_real.c;
 * AUTHOR : bitofux; DATE : 2026-10-21; BRIEF : 真实MySQL的隔离、事务授权及双worker次序。 */
#define _POSIX_C_SOURCE 200809L
#include "mysql_node_repository_internal.h"
#include <vireo/persistence/mysql_schema.h>
#include <vireo/persistence/mysql_user_repository.h>
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(call,want) do { errno=EDOM; vireo_result_t got_=(call); if(got_!=(want)) { fprintf(stderr,"line %d result %d want %d\n",__LINE__,(int)got_,(int)(want)); abort(); } assert(errno==EDOM); } while(0)
static vireo_mysql_runtime_t *runtime;
static vireo_mysql_thread_t *thread;
static vireo_mysql_pool_t *pool;
static vireo_mysql_connection_t *observer;
static vireo_mysql_user_repository_t *users;
static vireo_mysql_node_repository_t *nodes;
static vireo_password_policy_t policy=VIREO_PASSWORD_POLICY_DEFAULT;
static char phc[VIREO_PASSWORD_ENCODED_CAPACITY];
static size_t phc_length,cases;
static unsigned char serial;
static _Thread_local uint64_t sample_ms=2000;
static vireo_mysql_node_actor_t alice,bob;
static uint64_t alice_root,bob_root;
static const vireo_mysql_statement_limits_t limits={0,3,0,1024,32768};
static pthread_mutex_t mutex=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t condition;
static unsigned phase;
static bool release_reader,writer_started,writer_done;
static struct timespec deadline(void)
{ struct timespec t;assert(!clock_gettime(CLOCK_MONOTONIC,&t));t.tv_sec+=10;return t; }
static void wait_flag(const bool *flag)
{ struct timespec t=deadline();while(!*flag) { assert(!pthread_cond_timedwait(&condition,&mutex,&t)); } }
static int fixed_utc(struct timespec *out)
{ *out=(struct timespec){.tv_sec=(time_t)(sample_ms/1000),.tv_nsec=(long)(sample_ms%1000)*1000000L};return 0; }
/* 本worker的所有共享锁仍在；用有界屏障固定读先/写先，避免sleep猜时序。 */
static int paused_utc(struct timespec *out)
{
    assert(!pthread_mutex_lock(&mutex));phase=1;assert(!pthread_cond_broadcast(&condition));wait_flag(&release_reader);
    assert(!writer_done);assert(!pthread_mutex_unlock(&mutex));return fixed_utc(out);
}
static vireo_mysql_statement_t *execute_sql(const char *sql,bool rows)
{
    vireo_mysql_statement_t *s=NULL;vireo_mysql_execution_t ex;
    CHECK(vireo_mysql_statement_prepare(thread,observer,sql,strlen(sql),&limits,&s,NULL),VIREO_OK);
    CHECK(vireo_mysql_statement_execute(thread,s,NULL,0,&ex,NULL),VIREO_OK);assert(ex.has_result==rows);return s;
}
static void mutate(const char *sql)
{ vireo_mysql_statement_t *s=execute_sql(sql,false);CHECK(vireo_mysql_statement_destroy(thread,&s,NULL),VIREO_OK); }
static uint64_t scalar(const char *sql)
{
    vireo_mysql_statement_t *s=execute_sql(sql,true);vireo_mysql_fetch_outcome_t fetched;vireo_mysql_cell_view_t c;
    CHECK(vireo_mysql_statement_fetch(thread,s,&fetched,NULL),VIREO_OK);assert(fetched==VIREO_MYSQL_FETCH_ROW);
    CHECK(vireo_mysql_statement_column(thread,s,0,&c),VIREO_OK);assert(!c.is_null && c.length<32);
    char b[32]={0};memcpy(b,c.data,c.length);char *end;errno=0;unsigned long long n=strtoull(b,&end,10);assert(!errno && !*end);
    CHECK(vireo_mysql_statement_fetch(thread,s,&fetched,NULL),VIREO_OK);assert(fetched==VIREO_MYSQL_FETCH_DONE);
    CHECK(vireo_mysql_statement_destroy(thread,&s,NULL),VIREO_OK);return (uint64_t)n;
}
static vireo_mysql_node_actor_t account(const char *name,uint64_t *root)
{
    vireo_mysql_registration_input_t in={.username=name,.username_length=strlen(name),.username_key=name,
        .username_key_length=strlen(name),.password_hash=phc,.password_hash_length=phc_length,.occurred_at_ms=1000};
    in.request_id[15]=++serial;vireo_mysql_registration_report_t reg;
    CHECK(vireo_mysql_user_repository_register(users,&in,0,&reg,NULL),VIREO_OK);assert(reg.commit==VIREO_MYSQL_REGISTRATION_COMMITTED);*root=reg.root_node_id;
    vireo_mysql_login_input_t login={.user_id=reg.user_id,.verified_password_hash=phc,.verified_password_hash_length=phc_length,.issued_at_ms=1000,.expires_at_ms=3000};
    login.token_digest.bytes[0]=serial;login.request_id[15]=++serial;vireo_mysql_login_report_t logged;
    CHECK(vireo_mysql_user_repository_login(users,&login,0,&logged,NULL),VIREO_OK);assert(logged.commit==VIREO_MYSQL_LOGIN_COMMITTED);
    return (vireo_mysql_node_actor_t){reg.user_id,logged.session_id};
}
static vireo_mysql_node_value_t read_node(vireo_mysql_node_actor_t actor,uint64_t id,vireo_result_t want,vireo_mysql_node_issue_t issue)
{
    uint64_t audits=scalar("SELECT COUNT(*) FROM operation_audits");vireo_mysql_node_value_t out;memset(&out,0xa5,sizeof(out));vireo_mysql_node_report_t r;
    CHECK(id ? vireo_mysql_node_repository_stat(nodes,&actor,id,0,&out,&r,NULL) : vireo_mysql_node_repository_get_root(nodes,&actor,0,&out,&r,NULL),want);
    assert(r.found==(want==VIREO_OK) && r.issue==issue && !r.cleanup_pending);
    if(want!=VIREO_OK) { const unsigned char *p=(const void *)&out;for(size_t i=0;i<sizeof(out);++i) { assert(!p[i]); } }
    assert(scalar("SELECT COUNT(*) FROM operation_audits")==audits);++cases;return out;
}
struct worker { bool reader;vireo_result_t result;vireo_mysql_node_report_t report;vireo_mysql_node_value_t out; };
static void *work(void *arg)
{
    struct worker *w=arg;vireo_mysql_thread_t *t=NULL;CHECK(vireo_mysql_thread_attach(runtime,&t,NULL),VIREO_OK);
    if(w->reader) {
        vireo_mysql_node_repository_t *r=NULL;vireo_mysql_node_ops_t ops=vireo_mysql_node_native_ops;ops.utc=paused_utc;
        CHECK(vireo_mysql_node_repository_create_with_ops(t,pool,&r,NULL,&ops),VIREO_OK);
        errno=EDOM;w->result=vireo_mysql_node_repository_get_root(r,&alice,0,&w->out,&w->report,NULL);assert(errno==EDOM);
        CHECK(vireo_mysql_node_repository_destroy(&r,NULL),VIREO_OK);
    } else {
        vireo_mysql_user_repository_t *r=NULL;CHECK(vireo_mysql_user_repository_create(t,pool,&policy,&r,NULL),VIREO_OK);
        assert(!pthread_mutex_lock(&mutex));writer_started=true;assert(!pthread_cond_broadcast(&condition));assert(!pthread_mutex_unlock(&mutex));
        vireo_mysql_logout_input_t input={.user_id=alice.user_id,.session_id=alice.session_id,.request_id={0x7f},.occurred_at_ms=2000};
        vireo_mysql_logout_report_t output;CHECK(vireo_mysql_user_repository_logout(r,&input,0,&output,NULL),VIREO_OK);
        assert(output.commit==VIREO_MYSQL_LOGOUT_COMMITTED);
        assert(!pthread_mutex_lock(&mutex));writer_done=true;assert(!pthread_cond_broadcast(&condition));assert(!pthread_mutex_unlock(&mutex));
        CHECK(vireo_mysql_user_repository_destroy(&r,NULL),VIREO_OK);
    }
    CHECK(vireo_mysql_thread_detach(&t),VIREO_OK);return NULL;
}
static void concurrent_logout(void)
{
    struct worker reader={.reader=true},writer={0};pthread_t read_thread,write_thread;
    assert(!pthread_create(&read_thread,NULL,work,&reader));assert(!pthread_mutex_lock(&mutex));
    struct timespec t=deadline();while(phase!=1) { assert(!pthread_cond_timedwait(&condition,&mutex,&t)); }assert(!pthread_mutex_unlock(&mutex));
    assert(!pthread_create(&write_thread,NULL,work,&writer));assert(!pthread_mutex_lock(&mutex));wait_flag(&writer_started);
    assert(!writer_done);release_reader=true;assert(!pthread_cond_broadcast(&condition));assert(!pthread_mutex_unlock(&mutex));
    assert(!pthread_join(read_thread,NULL) && !pthread_join(write_thread,NULL));
    assert(reader.result==VIREO_OK && reader.out.id==alice_root && writer_done);
    (void)read_node(alice,0,VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_NODE_AUTH_REJECTED);
    struct worker later={.reader=true};
    assert(!pthread_create(&read_thread,NULL,work,&later) && !pthread_join(read_thread,NULL));
    assert(later.result==VIREO_RESULT_NOT_FOUND && !later.report.found && later.report.issue==VIREO_MYSQL_NODE_AUTH_REJECTED);
    puts("PASS read-first two OS workers: shared-lock snapshot succeeds, logout commits after read transaction, old actor rejected");
}
/* 固定node execute前的真实SQL接点；时间先改变再执行锁读，最终UTC必须使用新值。 */
static vireo_result_t expiry_execute(vireo_mysql_thread_t *t,vireo_mysql_statement_t *s,
    const vireo_mysql_parameter_t *p,size_t n,vireo_mysql_execution_t *out,vireo_mysql_error_t *e)
{
    if(n==2) { sample_ms=3000; }
    return vireo_mysql_statement_execute(t,s,p,n,out,e);
}
static size_t fd_count(void)
{ DIR *d=opendir("/proc/self/fd");assert(d);size_t n=0;while(readdir(d)) { ++n; }assert(!closedir(d));return n; }
int main(int argc,char **argv)
{
    assert(argc==5 && !setvbuf(stdout,NULL,_IONBF,0));char password[1026];FILE *f=fopen(argv[3],"r");
    assert(f && fgets(password,(int)sizeof(password),f) && !fclose(f));password[strcspn(password,"\n")]=0;
    struct sigaction sa={0};sa.sa_handler=SIG_IGN;assert(!sigemptyset(&sa.sa_mask) && !sigaction(SIGPIPE,&sa,NULL));
    pthread_condattr_t attr;assert(!pthread_condattr_init(&attr) && !pthread_condattr_setclock(&attr,CLOCK_MONOTONIC));
    assert(!pthread_cond_init(&condition,&attr) && !pthread_condattr_destroy(&attr));size_t fd=fd_count();
    CHECK(vireo_mysql_runtime_create(&runtime,NULL),VIREO_OK);CHECK(vireo_mysql_thread_attach(runtime,&thread,NULL),VIREO_OK);
    vireo_mysql_connection_options_t options={argv[1],argv[2],password,argv[4],3,3,3};
    const vireo_mysql_migration_t *catalog;size_t count;CHECK(vireo_mysql_schema_catalog(&catalog,&count),VIREO_OK);vireo_mysql_migration_report_t migration;
    CHECK(vireo_mysql_migration_apply(thread,&options,catalog,count,&migration,NULL),VIREO_OK);assert(migration.ready && migration.steps_completed==16);
    CHECK(vireo_mysql_connection_open(thread,&options,&observer,NULL),VIREO_OK);
    vireo_mysql_pool_options_t config={options,4,4,VIREO_MYSQL_POOL_MEMORY_MAX};CHECK(vireo_mysql_pool_create(thread,&config,&pool,NULL),VIREO_OK);
    CHECK(vireo_mysql_user_repository_create(thread,pool,&policy,&users,NULL),VIREO_OK);
    const char pass[]="real-password";CHECK(vireo_password_hash_create(&policy,pass,sizeof(pass)-1,phc,sizeof(phc),&phc_length),VIREO_OK);
    bool matches=false;CHECK(vireo_password_hash_verify(&policy,pass,sizeof(pass)-1,phc,phc_length,&matches),VIREO_OK);assert(matches);
    alice=account("alice",&alice_root);bob=account("bob",&bob_root);
    vireo_mysql_node_ops_t ops=vireo_mysql_node_native_ops;ops.utc=fixed_utc;
    CHECK(vireo_mysql_node_repository_create_with_ops(thread,pool,&nodes,NULL,&ops),VIREO_OK);
    vireo_mysql_node_value_t root=read_node(alice,0,VIREO_OK,VIREO_MYSQL_NODE_ISSUE_NONE);assert(root.id==alice_root && !root.has_parent && root.name_length==0);
    (void)read_node(bob,0,VIREO_OK,VIREO_MYSQL_NODE_ISSUE_NONE);
    (void)read_node(alice,bob_root,VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_NODE_NOT_FOUND);
    (void)read_node(bob,alice_root,VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_NODE_NOT_FOUND);
    (void)read_node(alice,9999,VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_NODE_NOT_FOUND);
    char sql[2048];
    (void)snprintf(sql,sizeof(sql),"INSERT INTO file_nodes(id,owner_id,parent_id,name,node_type,state,object_hash,size,created_at_ms,updated_at_ms) VALUES(1001,%llu,%llu,REPEAT('x',255),1,2,NULL,0,1000,1000)",(unsigned long long)alice.user_id,(unsigned long long)alice_root);mutate(sql);
    vireo_mysql_node_value_t child=read_node(alice,1001,VIREO_OK,VIREO_MYSQL_NODE_ISSUE_NONE);assert(child.name_length==255 && child.has_parent && child.parent_id==alice_root);
    mutate("INSERT INTO objects(object_hash,size,state,ref_count,storage_class,created_at_ms,updated_at_ms,verified_at_ms) VALUES(UNHEX(REPEAT('00',32)),18446744073709551615,2,1,1,1000,1000,1000)");
    (void)snprintf(sql,sizeof(sql),"INSERT INTO file_nodes(id,owner_id,parent_id,name,node_type,state,object_hash,size,created_at_ms,updated_at_ms) VALUES(1002,%llu,%llu,'file',2,2,UNHEX(REPEAT('00',32)),18446744073709551615,1000,1000)",(unsigned long long)alice.user_id,(unsigned long long)alice_root);mutate(sql);
    vireo_mysql_node_value_t file=read_node(alice,1002,VIREO_OK,VIREO_MYSQL_NODE_ISSUE_NONE);assert(file.kind==VIREO_MYSQL_NODE_FILE && file.has_object_hash && file.size==UINT64_MAX);
    mutate("UPDATE file_nodes SET state=1,object_hash=NULL WHERE id=1002");(void)read_node(alice,1002,VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_NODE_NOT_FOUND);
    mutate("UPDATE file_nodes SET state=3,deleted_at_ms=1000 WHERE id=1002");(void)read_node(alice,1002,VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_NODE_NOT_FOUND);
    mutate("UPDATE file_nodes SET name=UNHEX('FF') WHERE id=1001");child=read_node(alice,1001,VIREO_OK,VIREO_MYSQL_NODE_ISSUE_NONE);assert(child.name_length==1 && child.name[0]==255);
    for(uint64_t now=999;now<=3000;++now) {
        if(now!=999 && now!=1000 && now!=2999 && now!=3000) { continue; }sample_ms=now;
        (void)read_node(alice,0,now<1000 || now>=3000 ? VIREO_RESULT_NOT_FOUND : VIREO_OK,
            now<1000 || now>=3000 ? VIREO_MYSQL_NODE_AUTH_REJECTED : VIREO_MYSQL_NODE_ISSUE_NONE);
    }
    sample_ms=2000;vireo_mysql_node_actor_t forged={bob.user_id,alice.session_id};
    (void)read_node(forged,0,VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_NODE_AUTH_REJECTED);
    mutate("UPDATE users SET status=2 WHERE username_key='alice'");(void)read_node(alice,0,VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_NODE_AUTH_REJECTED);
    mutate("UPDATE users SET status=1 WHERE username_key='alice'");
    CHECK(vireo_mysql_node_repository_destroy(&nodes,NULL),VIREO_OK);
    ops.execute=expiry_execute;CHECK(vireo_mysql_node_repository_create_with_ops(thread,pool,&nodes,NULL,&ops),VIREO_OK);
    (void)read_node(alice,1001,VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_NODE_AUTH_REJECTED);assert(sample_ms==3000);
    CHECK(vireo_mysql_node_repository_destroy(&nodes,NULL),VIREO_OK);ops.execute=vireo_mysql_statement_execute;sample_ms=2000;
    CHECK(vireo_mysql_node_repository_create_with_ops(thread,pool,&nodes,NULL,&ops),VIREO_OK);concurrent_logout();
    /* 同一旧身份在logout提交之后由另一个真实worker读取必拒绝；上面的主线程读取也独立验证。 */
    /* 无活动根不能在读入口修复；只删除没有子节点的Bob根。 */
    (void)snprintf(sql,sizeof(sql),"DELETE FROM file_nodes WHERE id=%llu",(unsigned long long)bob_root);mutate(sql);
    (void)read_node(bob,0,VIREO_RESULT_DATABASE,VIREO_MYSQL_NODE_ROOT_INVARIANT);
    /* 原生公开入口的真实CLOCK_REALTIME与SQL，不依赖测试时钟。 */
    (void)snprintf(sql,sizeof(sql),"UPDATE sessions SET expires_at_ms=18446744073709551615 WHERE id=%llu",(unsigned long long)bob.session_id);mutate(sql);
    CHECK(vireo_mysql_node_repository_destroy(&nodes,NULL),VIREO_OK);
    CHECK(vireo_mysql_node_repository_create(thread,pool,&nodes,NULL),VIREO_OK);
    (void)read_node(bob,alice_root,VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_NODE_NOT_FOUND);
    CHECK(vireo_mysql_node_repository_destroy(&nodes,NULL),VIREO_OK);assert(root.id==alice_root && file.size==UINT64_MAX);
    CHECK(vireo_mysql_user_repository_destroy(&users,NULL),VIREO_OK);
    bool closed=false;CHECK(vireo_mysql_pool_close(pool,&closed,NULL),VIREO_OK);assert(closed);
    CHECK(vireo_mysql_pool_destroy(thread,&pool,NULL),VIREO_OK);
    CHECK(vireo_mysql_connection_destroy(thread,&observer),VIREO_OK);CHECK(vireo_mysql_thread_detach(&thread),VIREO_OK);CHECK(vireo_mysql_runtime_destroy(&runtime),VIREO_OK);
    assert(!pthread_cond_destroy(&condition) && !pthread_mutex_destroy(&mutex));memset(password,0,sizeof(password));assert(fd_count()==fd);
    printf("PASS %zu real node observations: register/login/owner isolation, active-only nodes, exact expiry, shared-lock/logout ordering, native UTC, independent values, FD %zu -> %zu\n",cases,fd,fd_count());return 0;
}
