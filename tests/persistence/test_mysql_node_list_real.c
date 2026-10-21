/* PROJECT : VIREO; FILE : test_mysql_node_list_real.c;
 * AUTHOR : bitofux; DATE : 2026-10-21; BRIEF : 真实目录分页、页间变化、退出交错和独立资源闭环。 */
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
static void zeroed(const void *p,size_t n)
{ const unsigned char *s=p;for(size_t i=0;i<n;++i) { assert(!s[i]); } }
static vireo_mysql_node_page_t list(vireo_mysql_node_actor_t who,uint64_t parent,uint64_t after,size_t size,
    vireo_result_t want,vireo_mysql_node_issue_t issue)
{
    uint64_t audits=scalar("SELECT COUNT(*) FROM operation_audits");vireo_mysql_node_page_t out;memset(&out,0xa5,sizeof(out));
    vireo_mysql_node_list_query_t q={parent,after,size};vireo_mysql_node_report_t r;
    CHECK(vireo_mysql_node_repository_list_children(nodes,&who,&q,0,&out,&r,NULL),want);
    assert(r.found==(want==VIREO_OK) && r.issue==issue && !r.cleanup_pending);
    if(want!=VIREO_OK) { zeroed(&out,sizeof(out)); }
    else { assert(r.rollback_confirmed && out.count<=size);zeroed(out.nodes+out.count,(64-out.count)*sizeof(out.nodes[0])); }
    assert(scalar("SELECT COUNT(*) FROM operation_audits")==audits);++cases;return out;
}
static void add_directory(uint64_t id,uint64_t owner,uint64_t parent)
{
    char sql[1024];int n=snprintf(sql,sizeof(sql),"INSERT INTO file_nodes(id,owner_id,parent_id,name,node_type,state,object_hash,size,created_at_ms,updated_at_ms) VALUES(%llu,%llu,%llu,'n%llu',1,2,NULL,0,1000,1000)",(unsigned long long)id,(unsigned long long)owner,(unsigned long long)parent,(unsigned long long)id);
    assert(n>0 && (size_t)n<sizeof(sql));mutate(sql);
}
struct worker { bool reader;vireo_result_t result;vireo_mysql_node_report_t report;vireo_mysql_node_page_t out; };
static void *work(void *arg)
{
    struct worker *w=arg;vireo_mysql_thread_t *t=NULL;CHECK(vireo_mysql_thread_attach(runtime,&t,NULL),VIREO_OK);
    if(w->reader) {
        vireo_mysql_node_repository_t *r=NULL;vireo_mysql_node_ops_t ops=vireo_mysql_node_native_ops;ops.utc=paused_utc;
        CHECK(vireo_mysql_node_repository_create_with_ops(t,pool,&r,NULL,&ops),VIREO_OK);
        vireo_mysql_node_list_query_t q={alice_root,0,2};errno=EDOM;
        w->result=vireo_mysql_node_repository_list_children(r,&alice,&q,0,&w->out,&w->report,NULL);assert(errno==EDOM);
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
    assert(reader.result==VIREO_OK && reader.out.count==2 && writer_done);
    (void)list(alice,alice_root,reader.out.next_after_id,2,VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_NODE_AUTH_REJECTED);
    struct worker later={.reader=true};assert(!pthread_create(&read_thread,NULL,work,&later) && !pthread_join(read_thread,NULL));
    assert(later.result==VIREO_RESULT_NOT_FOUND && !later.report.found && later.report.issue==VIREO_MYSQL_NODE_AUTH_REJECTED);
    zeroed(&later.out,sizeof(later.out));
    puts("PASS two OS workers: list holds shared locks before logout; logout commits; later worker and next page reject old actor");
}
/* 受控接点在真实children SQL前推进时间，不冒充真实锁等待跨expiry。 */
static vireo_result_t expiry_execute(vireo_mysql_thread_t *t,vireo_mysql_statement_t *s,
    const vireo_mysql_parameter_t *p,size_t n,vireo_mysql_execution_t *out,vireo_mysql_error_t *e)
{
    if(n==4) { sample_ms=3000; }return vireo_mysql_statement_execute(t,s,p,n,out,e);
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
    CHECK(vireo_mysql_migration_apply(thread,&options,catalog,count,&migration,NULL),VIREO_OK);assert(migration.ready && migration.steps_completed==14);
    CHECK(vireo_mysql_connection_open(thread,&options,&observer,NULL),VIREO_OK);
    vireo_mysql_pool_options_t config={options,4,4,VIREO_MYSQL_POOL_MEMORY_MAX};CHECK(vireo_mysql_pool_create(thread,&config,&pool,NULL),VIREO_OK);
    CHECK(vireo_mysql_user_repository_create(thread,pool,&policy,&users,NULL),VIREO_OK);
    const char pass[]="real-password";CHECK(vireo_password_hash_create(&policy,pass,sizeof(pass)-1,phc,sizeof(phc),&phc_length),VIREO_OK);
    alice=account("alice",&alice_root);bob=account("bob",&bob_root);
    vireo_mysql_node_ops_t ops=vireo_mysql_node_native_ops;ops.utc=fixed_utc;
    CHECK(vireo_mysql_node_repository_create_with_ops(thread,pool,&nodes,NULL,&ops),VIREO_OK);
    vireo_mysql_node_value_t root;vireo_mysql_node_report_t rr;
    CHECK(vireo_mysql_node_repository_get_root(nodes,&alice,0,&root,&rr,NULL),VIREO_OK);assert(root.id==alice_root);
    vireo_mysql_node_page_t empty=list(alice,root.id,0,64,VIREO_OK,VIREO_MYSQL_NODE_ISSUE_NONE);assert(!empty.count && !empty.has_more);
    for(uint64_t id=100;id<170;++id) { add_directory(id,alice.user_id,alice_root); }
    add_directory(10000,alice.user_id,100);add_directory(800,bob.user_id,bob_root);
    char sql[2048];
    mutate("INSERT INTO objects(object_hash,size,state,ref_count,storage_class,created_at_ms,updated_at_ms,verified_at_ms) VALUES(UNHEX(REPEAT('00',32)),18446744073709551615,2,1,1,1000,1000,1000)");
    mutate("UPDATE file_nodes SET node_type=2,object_hash=UNHEX(REPEAT('00',32)),size=18446744073709551615 WHERE id=165");
    mutate("UPDATE file_nodes SET name=REPEAT('x',255) WHERE id=169");mutate("UPDATE file_nodes SET name=UNHEX('FF') WHERE id=168");
    (void)snprintf(sql,sizeof(sql),"INSERT INTO file_nodes(id,owner_id,parent_id,name,node_type,state,object_hash,size,created_at_ms,updated_at_ms,deleted_at_ms) VALUES(5000,%llu,%llu,'gone',1,3,NULL,0,1000,1000,1000),(5001,%llu,%llu,'pending',2,1,NULL,0,1000,1000,NULL)",(unsigned long long)alice.user_id,(unsigned long long)alice_root,(unsigned long long)alice.user_id,(unsigned long long)alice_root);mutate(sql);
    vireo_mysql_node_page_t first=list(alice,alice_root,0,64,VIREO_OK,VIREO_MYSQL_NODE_ISSUE_NONE);
    assert(first.count==64 && first.has_more && first.next_after_id==163);
    for(size_t i=0;i<64;++i) { assert(first.nodes[i].id==100+(uint64_t)i && first.nodes[i].parent_id==alice_root); }
    vireo_mysql_node_page_t last=list(alice,alice_root,first.next_after_id,64,VIREO_OK,VIREO_MYSQL_NODE_ISSUE_NONE);
    assert(last.count==6 && !last.has_more && !last.next_after_id && last.nodes[0].id==164 && last.nodes[5].id==169);
    assert(last.nodes[1].kind==VIREO_MYSQL_NODE_FILE && last.nodes[1].size==UINT64_MAX && last.nodes[1].has_object_hash);
    assert(last.nodes[4].name_length==1 && last.nodes[4].name[0]==255 && last.nodes[5].name_length==255);
    for(size_t size=1;size<=64;++size) {
        uint64_t after=0,next=100;size_t seen=0;
        do {
            vireo_mysql_node_page_t p=list(alice,alice_root,after,size,VIREO_OK,VIREO_MYSQL_NODE_ISSUE_NONE);
            for(size_t i=0;i<p.count;++i) { assert(p.nodes[i].id==next++);++seen; }
            if(!p.has_more) { break; }assert(p.count==size && p.next_after_id>after);after=p.next_after_id;
        } while(seen<=70);
        assert(seen==70 && next==170);
    }
    (void)list(alice,bob_root,0,2,VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_NODE_NOT_FOUND);
    (void)list(bob,alice_root,0,2,VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_NODE_NOT_FOUND);
    (void)list(alice,9999,0,2,VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_NODE_NOT_FOUND);
    (void)list(alice,165,0,2,VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_NODE_NOT_FOUND);
    (void)list(alice,5000,0,2,VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_NODE_NOT_FOUND);
    (void)list(alice,5001,0,2,VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_NODE_NOT_FOUND);
    vireo_mysql_node_page_t nested=list(alice,100,0,2,VIREO_OK,VIREO_MYSQL_NODE_ISSUE_NONE);assert(nested.count==1 && nested.nodes[0].id==10000 && !nested.has_more);
    vireo_mysql_node_page_t beyond=list(alice,alice_root,UINT64_MAX,2,VIREO_OK,VIREO_MYSQL_NODE_ISSUE_NONE);assert(!beyond.count);
    /* 页间真实移动、删除、改名、低ID插入：继续旧位置，不回头补低ID。 */
    vireo_mysql_node_page_t before=list(alice,alice_root,0,2,VIREO_OK,VIREO_MYSQL_NODE_ISSUE_NONE);assert(before.next_after_id==101);
    mutate("UPDATE file_nodes SET parent_id=100 WHERE id=102");mutate("UPDATE file_nodes SET state=3,deleted_at_ms=1000 WHERE id=103");
    mutate("DELETE FROM file_nodes WHERE id=101");mutate("UPDATE file_nodes SET name='renamed' WHERE id=104");add_directory(99,alice.user_id,alice_root);add_directory(200,alice.user_id,alice_root);
    vireo_mysql_node_page_t changed=list(alice,alice_root,before.next_after_id,3,VIREO_OK,VIREO_MYSQL_NODE_ISSUE_NONE);
    assert(changed.count==3 && changed.nodes[0].id==104 && changed.nodes[2].id==106 && changed.next_after_id==106);
    vireo_mysql_node_page_t high=list(alice,alice_root,169,2,VIREO_OK,VIREO_MYSQL_NODE_ISSUE_NONE);assert(high.count==1 && high.nodes[0].id==200 && !high.has_more);
    const uint64_t times[]={999,1000,2999,3000};
    for(size_t i=0;i<4;++i) {
        sample_ms=times[i];bool valid=sample_ms>=1000 && sample_ms<3000;
        (void)list(alice,alice_root,0,2,valid ? VIREO_OK : VIREO_RESULT_NOT_FOUND,valid ? VIREO_MYSQL_NODE_ISSUE_NONE : VIREO_MYSQL_NODE_AUTH_REJECTED);
    }
    (void)list(alice,9999,0,2,VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_NODE_AUTH_REJECTED);sample_ms=2000;
    vireo_mysql_node_actor_t forged={bob.user_id,alice.session_id};(void)list(forged,bob_root,0,2,VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_NODE_AUTH_REJECTED);
    mutate("UPDATE users SET status=2 WHERE username_key='alice'");(void)list(alice,alice_root,0,2,VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_NODE_AUTH_REJECTED);mutate("UPDATE users SET status=1 WHERE username_key='alice'");
    CHECK(vireo_mysql_node_repository_destroy(&nodes,NULL),VIREO_OK);ops.execute=expiry_execute;
    CHECK(vireo_mysql_node_repository_create_with_ops(thread,pool,&nodes,NULL,&ops),VIREO_OK);
    (void)list(alice,alice_root,0,2,VIREO_RESULT_NOT_FOUND,VIREO_MYSQL_NODE_AUTH_REJECTED);assert(sample_ms==3000);
    CHECK(vireo_mysql_node_repository_destroy(&nodes,NULL),VIREO_OK);ops.execute=vireo_mysql_statement_execute;sample_ms=2000;
    CHECK(vireo_mysql_node_repository_create_with_ops(thread,pool,&nodes,NULL,&ops),VIREO_OK);concurrent_logout();
    /* 最大ID不会+1回绕；所有新注册均已完成，再插入最大AUTO_INCREMENT主键。 */
    add_directory(UINT64_MAX-1,bob.user_id,bob_root);add_directory(UINT64_MAX,bob.user_id,bob_root);
    vireo_mysql_node_page_t edge=list(bob,bob_root,800,1,VIREO_OK,VIREO_MYSQL_NODE_ISSUE_NONE);assert(edge.count==1 && edge.next_after_id==UINT64_MAX-1);
    edge=list(bob,bob_root,edge.next_after_id,1,VIREO_OK,VIREO_MYSQL_NODE_ISSUE_NONE);assert(edge.count==1 && edge.nodes[0].id==UINT64_MAX && !edge.has_more);
    edge=list(bob,bob_root,UINT64_MAX,1,VIREO_OK,VIREO_MYSQL_NODE_ISSUE_NONE);assert(!edge.count);
    (void)snprintf(sql,sizeof(sql),"UPDATE sessions SET expires_at_ms=18446744073709551615 WHERE id=%llu",(unsigned long long)bob.session_id);mutate(sql);
    CHECK(vireo_mysql_node_repository_destroy(&nodes,NULL),VIREO_OK);CHECK(vireo_mysql_node_repository_create(thread,pool,&nodes,NULL),VIREO_OK);
    edge=list(bob,bob_root,0,64,VIREO_OK,VIREO_MYSQL_NODE_ISSUE_NONE);assert(edge.count==3);
    CHECK(vireo_mysql_node_repository_destroy(&nodes,NULL),VIREO_OK);assert(first.nodes[0].id==100 && last.nodes[1].size==UINT64_MAX);
    CHECK(vireo_mysql_user_repository_destroy(&users,NULL),VIREO_OK);bool closed=false;CHECK(vireo_mysql_pool_close(pool,&closed,NULL),VIREO_OK);assert(closed);
    CHECK(vireo_mysql_pool_destroy(thread,&pool,NULL),VIREO_OK);CHECK(vireo_mysql_connection_destroy(thread,&observer),VIREO_OK);
    CHECK(vireo_mysql_thread_detach(&thread),VIREO_OK);CHECK(vireo_mysql_runtime_destroy(&runtime),VIREO_OK);
    assert(!pthread_cond_destroy(&condition) && !pthread_mutex_destroy(&mutex));memset(password,0,sizeof(password));assert(fd_count()==fd);
    printf("PASS %zu real list observations: all 64 page sizes, owner/direct children, changed pages, maximum IDs, two workers/logout, native UTC; FD %zu -> %zu\n",cases,fd,fd_count());return 0;
}
