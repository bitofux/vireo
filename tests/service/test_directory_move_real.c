/* PROJECT : VIREO; FILE : test_directory_move_real.c; AUTHOR : bitofux;
 * DATE : 2026-10-24; BRIEF : 公开MOVE service、真实事务、拒绝六表快照及旧字节读取。 */
#define _POSIX_C_SOURCE 200809L
#include <vireo/service/directory_move.h>
#include "directory_name_test_vectors.h"
#include <vireo/persistence/mysql_schema.h>
#include <vireo/persistence/mysql_statement.h>
#include <vireo/persistence/mysql_user_repository.h>
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define CHECK(call, want) do { errno = EDOM; vireo_result_t got_ = (call); \
    if (got_ != (want)) { fprintf(stderr, "line %d result %d want %d\n", __LINE__, (int)got_, (int)(want)); abort(); } \
    assert(errno == EDOM); } while (0)
static vireo_mysql_thread_t *thread;
static vireo_mysql_connection_t *observer;
static vireo_mysql_user_repository_t *users;
static vireo_mysql_node_repository_t *nodes;
static const vireo_password_policy_t policy = VIREO_PASSWORD_POLICY_DEFAULT;
static char phc[VIREO_PASSWORD_ENCODED_CAPACITY];
static size_t phc_length, cases;
static unsigned char serial;
static uint64_t issued_at;

static uint64_t now_ms(void)
{
    struct timespec t; assert(clock_gettime(CLOCK_REALTIME, &t) == 0 && t.tv_sec > 0);
    return (uint64_t)t.tv_sec * 1000 + (uint64_t)t.tv_nsec / 1000000;
}

/* SQL仅为受控fixture；不拼接客户端名字、密码或token。返回owner由caller销毁。 */
static vireo_mysql_statement_t *execute_sql(const char *sql, bool rows)
{
    const vireo_mysql_statement_limits_t limits = {0, 32, 0, 2048, 131072};
    vireo_mysql_statement_t *s = NULL; vireo_mysql_execution_t execution;
    CHECK(vireo_mysql_statement_prepare(thread, observer, sql, strlen(sql), &limits, &s, NULL), VIREO_OK);
    vireo_mysql_error_t diagnostic;
    errno=EDOM;
    vireo_result_t rc=vireo_mysql_statement_execute(thread,s,NULL,0,&execution,&diagnostic);
    if(rc!=VIREO_OK) {
        fprintf(stderr,"fixture SQL execution failed after %zu service observations: rc=%d mysql=%u stage=%d\n",
            cases,(int)rc,diagnostic.mysql_code,(int)diagnostic.stage);abort();
    }
    assert(errno==EDOM);
    assert(execution.has_result == rows); return s;
}

static void mutate(const char *sql)
{
    vireo_mysql_statement_t *s = execute_sql(sql, false);
    CHECK(vireo_mysql_statement_destroy(thread, &s, NULL), VIREO_OK);
}

/* 全列快照保留长度、NULL与表/行边界；只在内存比较，绝不输出秘密。 */
static size_t snapshot(unsigned char out[65536])
{
    const char *sql[] = {"SELECT * FROM users ORDER BY id", "SELECT * FROM sessions ORDER BY id",
        "SELECT * FROM file_nodes ORDER BY id", "SELECT * FROM objects ORDER BY object_hash",
        "SELECT * FROM operation_audits ORDER BY id",
        "SELECT * FROM directory_write_receipts ORDER BY user_id,command,idempotency_key"};
    size_t used = 0;
    for (size_t t = 0; t < sizeof(sql)/sizeof(sql[0]); ++t) {
        vireo_mysql_statement_t *s = execute_sql(sql[t], true); vireo_mysql_statement_info_t info;
        CHECK(vireo_mysql_statement_inspect(thread, s, &info), VIREO_OK);
        for (;;) {
            vireo_mysql_fetch_outcome_t fetched;
            CHECK(vireo_mysql_statement_fetch(thread, s, &fetched, NULL), VIREO_OK);
            if (fetched == VIREO_MYSQL_FETCH_DONE) { break; }
            for (size_t col = 0; col < info.column_count; ++col) {
                vireo_mysql_cell_view_t cell;
                CHECK(vireo_mysql_statement_column(thread, s, col, &cell), VIREO_OK);
                assert(used + 2 + sizeof(cell.length) + cell.length < 65536);
                out[used++] = cell.is_null ? 1 : 0;
                memcpy(out + used, &cell.length, sizeof(cell.length)); used += sizeof(cell.length);
                if (cell.length != 0) { memcpy(out + used, cell.data, cell.length); used += cell.length; }
            }
            out[used++] = 0xfe;
        }
        out[used++] = 0xff; CHECK(vireo_mysql_statement_destroy(thread, &s, NULL), VIREO_OK);
    }
    return used;
}

static vireo_mysql_node_actor_t account(const char *name, uint64_t *root)
{
    vireo_mysql_registration_input_t registration = {.username = name, .username_length = strlen(name),
        .username_key = name, .username_key_length = strlen(name), .password_hash = phc,
        .password_hash_length = phc_length, .occurred_at_ms = issued_at - 1000};
    registration.request_id[15] = ++serial; vireo_mysql_registration_report_t reg;
    CHECK(vireo_mysql_user_repository_register(users, &registration, 0, &reg, NULL), VIREO_OK);
    assert(reg.commit == VIREO_MYSQL_REGISTRATION_COMMITTED && !reg.cleanup_pending); *root = reg.root_node_id;
    vireo_mysql_login_input_t login = {.user_id = reg.user_id, .verified_password_hash = phc,
        .verified_password_hash_length = phc_length, .issued_at_ms = issued_at,
        .expires_at_ms = issued_at + 3600000};
    login.token_digest.bytes[0] = serial; login.request_id[15] = ++serial;
    vireo_mysql_login_report_t logged;
    CHECK(vireo_mysql_user_repository_login(users, &login, 0, &logged, NULL), VIREO_OK);
    assert(logged.commit == VIREO_MYSQL_LOGIN_COMMITTED && !logged.cleanup_pending);
    return (vireo_mysql_node_actor_t){reg.user_id, logged.session_id};
}

static uint64_t scalar(const char *sql)
{
    vireo_mysql_statement_t *s = execute_sql(sql, true); vireo_mysql_fetch_outcome_t fetched;
    vireo_mysql_cell_view_t cell;
    CHECK(vireo_mysql_statement_fetch(thread, s, &fetched, NULL), VIREO_OK); assert(fetched == VIREO_MYSQL_FETCH_ROW);
    CHECK(vireo_mysql_statement_column(thread, s, 0, &cell), VIREO_OK); assert(!cell.is_null && cell.length < 32);
    char bytes[32] = {0}; memcpy(bytes, cell.data, cell.length); char *end; errno = 0;
    unsigned long long n = strtoull(bytes, &end, 10); assert(errno == 0 && *end == 0);
    CHECK(vireo_mysql_statement_destroy(thread, &s, NULL), VIREO_OK); return (uint64_t)n;
}
static vireo_mysql_node_move_once_input_t make_input(uint64_t source, uint64_t parent,
    const unsigned char *name, size_t length)
{
    vireo_mysql_node_move_once_input_t in={.node_id=source,.new_parent_id=parent,.name=name,
        .name_length=length,.idempotency_key={0x22},.request_id={0x11}};
    assert(serial<250);in.idempotency_key[15]=++serial;in.request_id[15]=++serial;return in;
}
static uint64_t seed(vireo_mysql_node_actor_t actor, uint64_t parent, const unsigned char *name, size_t length)
{
    vireo_mysql_node_mkdir_input_t in={.parent_id=parent,.name=name,.name_length=length,.request_id={0x33}};
    assert(serial<250);in.request_id[15]=++serial;vireo_mysql_node_mkdir_report_t out;
    CHECK(vireo_mysql_node_repository_mkdir(nodes,&actor,&in,0,&out,NULL),VIREO_OK);
    assert(out.commit==VIREO_MYSQL_NODE_MKDIR_COMMITTED && !out.cleanup_pending);return out.node.id;
}
static vireo_mysql_node_value_t stat_node(vireo_mysql_node_actor_t actor, uint64_t id)
{
    vireo_mysql_node_value_t out;vireo_mysql_node_report_t report;
    CHECK(vireo_mysql_node_repository_stat(nodes,&actor,id,0,&out,&report,NULL),VIREO_OK);
    assert(report.found && !report.cleanup_pending);return out;
}
static void position(vireo_mysql_node_actor_t actor, uint64_t id, uint64_t parent, const unsigned char *name, size_t length)
{
    vireo_mysql_node_value_t out=stat_node(actor,id);
    assert(out.id==id && out.parent_id==parent && out.has_parent && out.name_length==length && !memcmp(out.name,name,length));
}
static bool zero(const unsigned char *bytes, size_t length)
{ for(size_t i=0;i<length;++i) { if(bytes[i]) { return false; } } return true; }
static vireo_directory_move_result_t call(vireo_mysql_node_actor_t actor,
    const vireo_mysql_node_move_once_input_t *in, vireo_result_t expected, vireo_directory_move_outcome_t outcome)
{
    const uint64_t n=scalar("SELECT COUNT(*) FROM file_nodes"),a=scalar("SELECT COUNT(*) FROM operation_audits"),
        r=scalar("SELECT COUNT(*) FROM directory_write_receipts");
    unsigned char before[65536],after[65536];size_t length=snapshot(before);
    vireo_directory_move_result_t out;vireo_mysql_node_error_t error;
    CHECK(vireo_directory_service_move(nodes,&actor,in,0,&out,&error),expected);
    assert(out.outcome==outcome && !out.repository.cleanup_pending && error.cleanup_result==VIREO_OK);
    const bool applied=outcome==VIREO_DIRECTORY_MOVE_APPLIED;
    const bool success=applied || outcome==VIREO_DIRECTORY_MOVE_RECOVERED;
    assert(out.name_issue==VIREO_DIRECTORY_NAME_ISSUE_NONE || outcome==VIREO_DIRECTORY_MOVE_INVALID_NAME);
    if(success) {
        assert(out.node_id==in->node_id && out.node_id==out.repository.node_id && out.repository.audit_id);
        assert(!memcmp(out.idempotency_key,in->idempotency_key,16));
        assert(out.repository.effect==(applied ? VIREO_MYSQL_NODE_MOVE_EFFECT_APPLIED : VIREO_MYSQL_NODE_MOVE_EFFECT_RECOVERED));
        assert(out.repository.commit==(applied ? VIREO_MYSQL_NODE_MOVE_COMMITTED : VIREO_MYSQL_NODE_MOVE_NOT_COMMITTED));
        assert(out.repository.rollback_confirmed==!applied);
    } else { assert(!out.node_id && zero(out.idempotency_key,16)); }
    assert(out.repository_called==(outcome!=VIREO_DIRECTORY_MOVE_INVALID_NAME));
    if(out.repository_called) { assert(out.repository_result==expected); }
    if(outcome==VIREO_DIRECTORY_MOVE_NONE && expected==VIREO_RESULT_DATABASE) {
        assert(error.database.mysql_code==1062 && out.repository.rollback_confirmed);
    }
    assert(scalar("SELECT COUNT(*) FROM file_nodes")==n);
    assert(scalar("SELECT COUNT(*) FROM operation_audits")==a+(applied ? 1U : 0U));
    assert(scalar("SELECT COUNT(*) FROM directory_write_receipts")==r+(applied ? 1U : 0U));
    if(!applied) { assert(snapshot(after)==length && !memcmp(before,after,length)); }
    if(applied) {
        position(actor,in->node_id,in->new_parent_id,in->name,in->name_length);
        char sql[2048];int z=snprintf(sql,sizeof(sql),
            "SELECT COUNT(*) FROM operation_audits WHERE id=%llu AND user_id=%llu AND session_id=%llu AND target_id=%llu AND action=6 AND status=0 AND request_id=0x",
            (unsigned long long)out.repository.audit_id,(unsigned long long)actor.user_id,
            (unsigned long long)actor.session_id,(unsigned long long)out.node_id);
        assert(z>0 && (size_t)z+32<sizeof(sql));size_t used=(size_t)z;
        for(size_t i=0;i<16;++i) { assert(snprintf(sql+used,sizeof(sql)-used,"%02x",in->request_id[i])==2);used+=2; }
        assert(scalar(sql)==1);
        z=snprintf(sql,sizeof(sql),
            "SELECT COUNT(*) FROM directory_write_receipts WHERE user_id=%llu AND command=1029 AND format_version=1 AND request_node_id=%llu AND request_parent_id=%llu AND result_node_id=%llu AND audit_id=%llu AND idempotency_key=0x",
            (unsigned long long)actor.user_id,(unsigned long long)in->node_id,(unsigned long long)in->new_parent_id,
            (unsigned long long)in->node_id,(unsigned long long)out.repository.audit_id);
        assert(z>0 && (size_t)z+32+20+2*in->name_length<sizeof(sql));used=(size_t)z;
        for(size_t i=0;i<16;++i) { assert(snprintf(sql+used,sizeof(sql)-used,"%02x",in->idempotency_key[i])==2);used+=2; }
        memcpy(sql+used," AND request_name=0x",20);used+=20;
        for(size_t i=0;i<in->name_length;++i) { assert(snprintf(sql+used,sizeof(sql)-used,"%02x",in->name[i])==2);used+=2; }
        assert(scalar(sql)==1);
    }
    ++cases;return out;
}
static void *wrong_worker(void *context)
{
    const vireo_mysql_node_actor_t *actor=context;
    vireo_mysql_node_move_once_input_t in={.node_id=1,.new_parent_id=2,.name=(const unsigned char *)"legal",
        .name_length=5,.idempotency_key={0x77},.request_id={0x88}};
    vireo_directory_move_result_t out;
    CHECK(vireo_directory_service_move(nodes,actor,&in,0,&out,NULL),VIREO_RESULT_INVALID_ARGUMENT);
    assert(out.repository_called && out.repository_result==VIREO_RESULT_INVALID_ARGUMENT && out.outcome==VIREO_DIRECTORY_MOVE_NONE);
    return NULL;
}
static size_t fd_count(void)
{
    DIR *d=opendir("/proc/self/fd");assert(d);size_t n=0;
    while(readdir(d)) { ++n; }assert(!closedir(d));return n;
}
static void legacy_name(vireo_mysql_node_actor_t actor, uint64_t root, uint64_t destination)
{
    const unsigned char *decomposed=(const unsigned char *)"e\xcc\x81";
    uint64_t id=seed(actor,root,decomposed,3);position(actor,id,root,decomposed,3);
    vireo_mysql_node_list_query_t query={.directory_id=root,.page_size=64};
    vireo_mysql_node_page_t page;vireo_mysql_node_report_t report;
    CHECK(vireo_mysql_node_repository_list_children(nodes,&actor,&query,0,&page,&report,NULL),VIREO_OK);
    bool found=false;
    for(size_t i=0;i<page.count;++i) {
        if(page.nodes[i].id==id) { assert(page.nodes[i].name_length==3 && !memcmp(page.nodes[i].name,decomposed,3));found=true; }
    }
    assert(found);vireo_mysql_node_move_once_input_t in=make_input(id,destination,decomposed,3);
    (void)call(actor,&in,VIREO_RESULT_PROTOCOL,VIREO_DIRECTORY_MOVE_INVALID_NAME);
    /* 合法最终名字可以迁移旧非NFC节点，不按旧名字拒绝或全表回填。 */
    in.name=(const unsigned char *)"\xc3\xa9";in.name_length=2;
    (void)call(actor,&in,VIREO_OK,VIREO_DIRECTORY_MOVE_APPLIED);
}
static void business(vireo_mysql_node_actor_t alice, uint64_t root, vireo_mysql_node_actor_t bob, uint64_t bob_root)
{
    const unsigned char *source_name=(const unsigned char *)"source",*dest_name=(const unsigned char *)"destination";
    uint64_t source=seed(alice,root,source_name,6),destination=seed(alice,root,dest_name,11),
        later=seed(alice,root,(const unsigned char *)"later",5),child=seed(alice,source,(const unsigned char *)"child",5);
    vireo_mysql_node_value_t child_before=stat_node(alice,child),source_before=stat_node(alice,source);
    /* 同父改名、换父保名、同时变化；带后代目录的直接孩子保持原父。 */
    vireo_mysql_node_move_once_input_t first=make_input(source,root,(const unsigned char *)"renamed",7);
    vireo_directory_move_result_t applied=call(alice,&first,VIREO_OK,VIREO_DIRECTORY_MOVE_APPLIED);
    vireo_mysql_node_move_once_input_t second=make_input(source,destination,first.name,first.name_length);
    (void)call(alice,&second,VIREO_OK,VIREO_DIRECTORY_MOVE_APPLIED);
    vireo_mysql_node_move_once_input_t third=make_input(source,later,(const unsigned char *)"final",5);
    (void)call(alice,&third,VIREO_OK,VIREO_DIRECTORY_MOVE_APPLIED);
    vireo_mysql_node_value_t child_after=stat_node(alice,child),source_after=stat_node(alice,source);
    assert(child_after.parent_id==source && child_after.updated_at_ms==child_before.updated_at_ms && child_after.created_at_ms==child_before.created_at_ms);
    assert(child_after.name_length==5 && !memcmp(child_after.name,"child",5));
    assert(source_after.owner_id==source_before.owner_id && source_after.kind==source_before.kind && source_after.created_at_ms==source_before.created_at_ms);
    /* 新键首次不变操作仍审计/回执；文件节点时间完全保持。 */
    vireo_mysql_node_move_once_input_t noop=make_input(source,later,third.name,third.name_length);
    (void)call(alice,&noop,VIREO_OK,VIREO_DIRECTORY_MOVE_APPLIED);
    assert(stat_node(alice,source).updated_at_ms==source_after.updated_at_ms);
    first.request_id[14]=1;
    vireo_directory_move_result_t recovered=call(alice,&first,VIREO_OK,VIREO_DIRECTORY_MOVE_RECOVERED);
    assert(recovered.repository.audit_id==applied.repository.audit_id);position(alice,source,later,third.name,third.name_length);
    for(unsigned variant=0;variant<4;++variant) {
        vireo_mysql_node_move_once_input_t changed=first;
        if(variant==0) { changed.node_id=UINT64_MAX; }if(variant==1) { changed.new_parent_id=UINT64_MAX; }
        if(variant==2) { changed.name=(const unsigned char *)"renameX"; }if(variant==3) { changed.name_length=6; }
        (void)call(alice,&changed,VIREO_RESULT_DATABASE,VIREO_DIRECTORY_MOVE_IDEMPOTENCY_CONFLICT);
    }
    vireo_mysql_node_move_once_input_t in=make_input(root,later,(const unsigned char *)"root",4);
    (void)call(alice,&in,VIREO_RESULT_DATABASE,VIREO_DIRECTORY_MOVE_ROOT_IMMOVABLE);
    in=make_input(source,source,(const unsigned char *)"cycle",5);
    (void)call(alice,&in,VIREO_RESULT_DATABASE,VIREO_DIRECTORY_MOVE_CYCLE);
    in.new_parent_id=child;(void)call(alice,&in,VIREO_RESULT_DATABASE,VIREO_DIRECTORY_MOVE_CYCLE);
    (void)seed(alice,destination,(const unsigned char *)"occupied",8);
    in=make_input(source,destination,(const unsigned char *)"occupied",8);
    (void)call(alice,&in,VIREO_RESULT_DATABASE,VIREO_DIRECTORY_MOVE_NAME_CONFLICT);
    in=make_input(source,bob_root,(const unsigned char *)"foreign-parent",14);
    (void)call(alice,&in,VIREO_RESULT_NOT_FOUND,VIREO_DIRECTORY_MOVE_NOT_FOUND);
    in.node_id=bob_root;in.new_parent_id=root;
    (void)call(alice,&in,VIREO_RESULT_NOT_FOUND,VIREO_DIRECTORY_MOVE_NOT_FOUND);
    in.node_id=UINT64_MAX;(void)call(alice,&in,VIREO_RESULT_NOT_FOUND,VIREO_DIRECTORY_MOVE_NOT_FOUND);
    vireo_mysql_node_actor_t mixed={alice.user_id,bob.session_id};
    (void)call(mixed,&first,VIREO_RESULT_NOT_FOUND,VIREO_DIRECTORY_MOVE_UNAUTHORIZED);
    /* 文件大小/hash/对象引用不因改名、移动或恢复而变化。 */
    uint64_t file_id=seed(alice,root,(const unsigned char *)"file",4);
    mutate("INSERT INTO objects(object_hash,size,state,ref_count,storage_class,created_at_ms,updated_at_ms,verified_at_ms) VALUES(UNHEX(REPEAT('a5',32)),91,2,1,1,1000,1000,1000)");
    char sql[1024];int n=snprintf(sql,sizeof(sql),"UPDATE file_nodes SET node_type=2,object_hash=UNHEX(REPEAT('a5',32)),size=91 WHERE id=%llu",(unsigned long long)file_id);
    assert(n>0 && (size_t)n<sizeof(sql));mutate(sql);vireo_mysql_node_value_t file_before=stat_node(alice,file_id);
    in=make_input(file_id,destination,(const unsigned char *)"moved-file",10);
    (void)call(alice,&in,VIREO_OK,VIREO_DIRECTORY_MOVE_APPLIED);
    vireo_mysql_node_value_t file_after=stat_node(alice,file_id);
    assert(file_before.kind==file_after.kind && file_after.has_object_hash && file_after.size==91 && file_before.created_at_ms==file_after.created_at_ms);
    assert(!memcmp(file_before.object_hash,file_after.object_hash,32));
    assert(scalar("SELECT ref_count FROM objects WHERE object_hash=UNHEX(REPEAT('a5',32))")==1);
    (void)call(alice,&in,VIREO_OK,VIREO_DIRECTORY_MOVE_RECOVERED);
    in=make_input(source,file_id,(const unsigned char *)"file-parent",11);
    (void)call(alice,&in,VIREO_RESULT_NOT_FOUND,VIREO_DIRECTORY_MOVE_NOT_FOUND);
    /* 原生1062是技术错误：独立新键+重复审计事件，不伪装成占名。 */
    in=make_input(file_id,destination,(const unsigned char *)"different",9);memcpy(in.request_id,third.request_id,16);
    (void)call(alice,&in,VIREO_RESULT_DATABASE,VIREO_DIRECTORY_MOVE_NONE);
    position(alice,file_id,destination,(const unsigned char *)"moved-file",10);
    legacy_name(alice,root,destination);
    for(size_t i=0;i<sizeof(name_vectors)/sizeof(name_vectors[0]);++i) {
        const struct name_vector *v=&name_vectors[i];
        in=make_input(file_id,later,v->bytes,v->length);
        vireo_directory_move_result_t named=call(alice,&in,v->issue==VIREO_DIRECTORY_NAME_ISSUE_NONE ? VIREO_OK :
            v->issue==VIREO_DIRECTORY_NAME_ISSUE_LENGTH ? VIREO_RESULT_RANGE : VIREO_RESULT_PROTOCOL,
            v->issue==VIREO_DIRECTORY_NAME_ISSUE_NONE ? VIREO_DIRECTORY_MOVE_APPLIED : VIREO_DIRECTORY_MOVE_INVALID_NAME);
        assert(named.name_issue==v->issue);
    }
    /* 完整历史恢复无需源和原父仍活动；快照证明无业务写。 */
    const uint64_t deleted_at=now_ms();
    n=snprintf(sql,sizeof(sql),"UPDATE file_nodes SET state=3,updated_at_ms=GREATEST(updated_at_ms,%llu),deleted_at_ms=GREATEST(updated_at_ms,%llu) WHERE id IN (%llu,%llu)",
        (unsigned long long)deleted_at,(unsigned long long)deleted_at,(unsigned long long)source,(unsigned long long)destination);
    assert(n>0 && (size_t)n<sizeof(sql));mutate(sql);
    (void)call(alice,&second,VIREO_OK,VIREO_DIRECTORY_MOVE_RECOVERED);
    vireo_mysql_login_input_t login={.user_id=alice.user_id,.verified_password_hash=phc,
        .verified_password_hash_length=phc_length,.issued_at_ms=issued_at,.expires_at_ms=issued_at+3600000,.request_id={0x44}};
    login.token_digest.bytes[0]=0xfe;login.request_id[15]=++serial;vireo_mysql_login_report_t logged;
    CHECK(vireo_mysql_user_repository_login(users,&login,0,&logged,NULL),VIREO_OK);
    vireo_mysql_node_actor_t fresh={alice.user_id,logged.session_id};
    (void)call(fresh,&second,VIREO_OK,VIREO_DIRECTORY_MOVE_RECOVERED);
    vireo_mysql_logout_input_t logout={.user_id=alice.user_id,.session_id=alice.session_id,.occurred_at_ms=now_ms(),.request_id={0x55}};
    logout.request_id[15]=++serial;vireo_mysql_logout_report_t logged_out;
    CHECK(vireo_mysql_user_repository_logout(users,&logout,0,&logged_out,NULL),VIREO_OK);
    (void)call(alice,&second,VIREO_RESULT_NOT_FOUND,VIREO_DIRECTORY_MOVE_UNAUTHORIZED);
    in=make_input(source,root,(const unsigned char *)"e\xcc\x81",3);
    (void)call(alice,&in,VIREO_RESULT_PROTOCOL,VIREO_DIRECTORY_MOVE_INVALID_NAME);
    n=snprintf(sql,sizeof(sql),"UPDATE sessions SET expires_at_ms=issued_at_ms+1 WHERE id=%llu",(unsigned long long)bob.session_id);
    assert(n>0 && (size_t)n<sizeof(sql));mutate(sql);
    in=make_input(bob_root,bob_root,(const unsigned char *)"expired",7);
    (void)call(bob,&in,VIREO_RESULT_NOT_FOUND,VIREO_DIRECTORY_MOVE_UNAUTHORIZED);
    pthread_t other;assert(!pthread_create(&other,NULL,wrong_worker,&fresh) && !pthread_join(other,NULL));++cases;
    assert(scalar("SELECT COUNT(*) FROM operation_audits")==scalar("SELECT COUNT(DISTINCT request_id) FROM operation_audits"));
}
int main(int argc, char **argv)
{
    assert(argc == 5); char db_password[1026]; FILE *f = fopen(argv[3], "r");
    assert(f != NULL && fgets(db_password, (int)sizeof(db_password), f) != NULL && fclose(f) == 0);
    db_password[strcspn(db_password, "\n")] = 0;
    struct sigaction action = {0}; action.sa_handler = SIG_IGN;
    assert(sigemptyset(&action.sa_mask) == 0 && sigaction(SIGPIPE, &action, NULL) == 0);
    size_t fds = fd_count(); vireo_mysql_runtime_t *runtime = NULL;
    CHECK(vireo_mysql_runtime_create(&runtime, NULL), VIREO_OK);
    CHECK(vireo_mysql_thread_attach(runtime, &thread, NULL), VIREO_OK);
    vireo_mysql_connection_options_t options = {argv[1], argv[2], db_password, argv[4], 3, 3, 3};
    const vireo_mysql_migration_t *catalog = NULL; size_t count = 0;
    CHECK(vireo_mysql_schema_catalog(&catalog, &count), VIREO_OK); vireo_mysql_migration_report_t migration;
    CHECK(vireo_mysql_migration_apply(thread, &options, catalog, count, &migration, NULL), VIREO_OK);
    assert(migration.ready && migration.steps_completed==16 && migration.applied_after==10);
    CHECK(vireo_mysql_connection_open(thread, &options, &observer, NULL), VIREO_OK);
    vireo_mysql_pool_t *pool = NULL;
    const vireo_mysql_pool_options_t pool_options = {options, 3, 3, VIREO_MYSQL_POOL_MEMORY_MAX};
    CHECK(vireo_mysql_pool_create(thread, &pool_options, &pool, NULL), VIREO_OK);
    CHECK(vireo_mysql_user_repository_create(thread, pool, &policy, &users, NULL), VIREO_OK);
    CHECK(vireo_mysql_node_repository_create(thread, pool, &nodes, NULL), VIREO_OK);
    CHECK(vireo_password_hash_create(&policy, "Correct!7", 9, phc, sizeof(phc), &phc_length), VIREO_OK);
    issued_at=now_ms()-10000;uint64_t alice_root,bob_root;
    vireo_mysql_node_actor_t alice=account("alice_move",&alice_root),bob=account("bob_move",&bob_root);
    business(alice,alice_root,bob,bob_root);
    vireo_mysql_pool_info_t info;CHECK(vireo_mysql_pool_inspect(pool,&info),VIREO_OK);
    /* 技术SQL失败按仓库合同DISCARD，不自动补槽；测试管理方显式恢复容量。 */
    assert(!info.leased && !info.returning && !info.refilling && !info.retired && info.vacant==1 && info.idle==2);
    vireo_mysql_pool_refill_t refilled;
    CHECK(vireo_mysql_pool_refill(thread,pool,&refilled,NULL),VIREO_OK);assert(refilled.restored);
    CHECK(vireo_mysql_pool_inspect(pool,&info),VIREO_OK);
    assert(!info.leased && !info.vacant && !info.returning && info.idle==3);
    CHECK(vireo_mysql_node_repository_destroy(&nodes,NULL),VIREO_OK);
    CHECK(vireo_mysql_user_repository_destroy(&users,NULL),VIREO_OK);
    bool closed=false;CHECK(vireo_mysql_pool_close(pool,&closed,NULL),VIREO_OK);assert(closed);
    CHECK(vireo_mysql_pool_destroy(thread,&pool,NULL),VIREO_OK);
    CHECK(vireo_mysql_connection_destroy(thread,&observer),VIREO_OK);
    CHECK(vireo_mysql_thread_detach(&thread),VIREO_OK);
    CHECK(vireo_mysql_runtime_destroy(&runtime),VIREO_OK);
    memset(db_password,0,sizeof(db_password));memset(phc,0,sizeof(phc));assert(fd_count()==fds);
    printf("PASS %zu real MOVE service observations; rename/reparent/both/noop/history/auth/conflicts/legacy-NFC/file/descendants, six-table snapshots, worker qualification; FD %zu->%zu\n",cases,fds,fd_count());return 0;
}
