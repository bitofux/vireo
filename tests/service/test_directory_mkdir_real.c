/* PROJECT : VIREO; FILE : test_directory_mkdir_real.c; AUTHOR : bitofux;
 * DATE : 2026-10-22; BRIEF : 公开MKDIR service、真实事务、拒绝六表快照及旧字节读取。 */
#define _POSIX_C_SOURCE 200809L
#include <vireo/service/directory_mkdir.h>
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
    CHECK(vireo_mysql_statement_execute(thread, s, NULL, 0, &execution, NULL), VIREO_OK);
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
static vireo_mysql_node_mkdir_once_input_t make_input(uint64_t parent, const unsigned char *name, size_t length)
{
    vireo_mysql_node_mkdir_once_input_t in = {.parent_id=parent, .name=name, .name_length=length,
        .idempotency_key={0x22}, .request_id={0x11}};
    in.idempotency_key[15]=++serial; in.request_id[15]=++serial; return in;
}
static vireo_directory_mkdir_result_t call(vireo_mysql_node_actor_t actor,
    const vireo_mysql_node_mkdir_once_input_t *in, vireo_result_t rc, vireo_directory_mkdir_outcome_t outcome)
{
    uint64_t n=scalar("SELECT COUNT(*) FROM file_nodes"), a=scalar("SELECT COUNT(*) FROM operation_audits"),
        r=scalar("SELECT COUNT(*) FROM directory_write_receipts");
    unsigned char before[65536], after[65536]; size_t length=snapshot(before);
    vireo_directory_mkdir_result_t out; vireo_mysql_node_error_t error;
    CHECK(vireo_directory_service_mkdir(nodes, &actor, in, 0, &out, &error), rc);
    assert(out.outcome == outcome && !out.repository.cleanup_pending && error.cleanup_result == VIREO_OK);
    bool created=outcome == VIREO_DIRECTORY_MKDIR_CREATED;
    bool success=created || outcome == VIREO_DIRECTORY_MKDIR_RECOVERED;
    if (success) {
        assert(out.node_id != 0 && out.node_id == out.repository.node_id && out.repository.audit_id != 0);
        assert(memcmp(out.idempotency_key, in->idempotency_key, 16) == 0);
        assert(out.repository.effect == (created ? VIREO_MYSQL_NODE_MKDIR_EFFECT_CREATED : VIREO_MYSQL_NODE_MKDIR_EFFECT_RECOVERED));
        assert(out.repository.commit == (created ? VIREO_MYSQL_NODE_MKDIR_COMMITTED : VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED));
        assert(out.repository.rollback_confirmed == !created);
    } else { assert(out.node_id == 0); }
    assert(out.repository_called == (outcome != VIREO_DIRECTORY_MKDIR_INVALID_NAME));
    assert(scalar("SELECT COUNT(*) FROM file_nodes") == n + (created ? 1U : 0U));
    assert(scalar("SELECT COUNT(*) FROM operation_audits") == a + (created ? 1U : 0U));
    assert(scalar("SELECT COUNT(*) FROM directory_write_receipts") == r + (created ? 1U : 0U));
    if (!created) { assert(snapshot(after) == length && memcmp(before, after, length) == 0); }
    if (created) {
        char sql[512]; int z=snprintf(sql, sizeof(sql),
            "SELECT COUNT(*) FROM operation_audits WHERE id=%llu AND target_id=%llu AND action=5 AND status=0 AND request_id=0x",
            (unsigned long long)out.repository.audit_id, (unsigned long long)out.node_id);
        assert(z > 0 && (size_t)z+32 < sizeof(sql)); size_t used=(size_t)z;
        for (size_t i=0; i<16; ++i) { assert(snprintf(sql+used, sizeof(sql)-used, "%02x", in->request_id[i]) == 2); used+=2; }
        assert(scalar(sql) == 1);
    }
    ++cases; return out;
}
static void old_bytes(vireo_mysql_node_actor_t actor, uint64_t root, const unsigned char *name, size_t length)
{
    vireo_mysql_node_mkdir_input_t in={.parent_id=root, .name=name, .name_length=length, .request_id={0x33}};
    in.request_id[15]=++serial; vireo_mysql_node_mkdir_report_t written;
    CHECK(vireo_mysql_node_repository_mkdir(nodes, &actor, &in, 0, &written, NULL), VIREO_OK);
    assert(written.commit == VIREO_MYSQL_NODE_MKDIR_COMMITTED);
    vireo_mysql_node_value_t node; vireo_mysql_node_report_t report;
    CHECK(vireo_mysql_node_repository_stat(nodes, &actor, written.node.id, 0, &node, &report, NULL), VIREO_OK);
    assert(node.name_length == length && memcmp(node.name, name, length) == 0);
    vireo_mysql_node_list_query_t query={.directory_id=root, .after_id=0, .page_size=64};
    vireo_mysql_node_page_t page;
    CHECK(vireo_mysql_node_repository_list_children(nodes, &actor, &query, 0, &page, &report, NULL), VIREO_OK);
    bool found=false;
    for (size_t i=0; i<page.count; ++i) {
        if (page.nodes[i].id == written.node.id) { assert(page.nodes[i].name_length == length && memcmp(page.nodes[i].name, name, length) == 0); found=true; }
    }
    assert(found);
    vireo_mysql_node_mkdir_once_input_t fresh=make_input(root, name, length);
    (void)call(actor, &fresh, VIREO_RESULT_PROTOCOL, VIREO_DIRECTORY_MKDIR_INVALID_NAME);
    ++cases;
}
static void *wrong_worker(void *context)
{
    vireo_mysql_node_actor_t *actor=context;
    vireo_mysql_node_mkdir_once_input_t in=make_input(1, (const unsigned char *)"legal", 5);
    vireo_directory_mkdir_result_t out;
    CHECK(vireo_directory_service_mkdir(nodes, actor, &in, 0, &out, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    assert(out.repository_called && out.repository_result == VIREO_RESULT_INVALID_ARGUMENT && out.outcome == VIREO_DIRECTORY_MKDIR_NONE);
    return NULL;
}
static size_t fd_count(void)
{
    DIR *d=opendir("/proc/self/fd"); assert(d != NULL); size_t n=0;
    while (readdir(d) != NULL) { ++n; } assert(closedir(d) == 0); return n;
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
    assert(migration.ready && migration.steps_completed==16);
    CHECK(vireo_mysql_connection_open(thread, &options, &observer, NULL), VIREO_OK);
    vireo_mysql_pool_t *pool = NULL;
    const vireo_mysql_pool_options_t pool_options = {options, 3, 3, VIREO_MYSQL_POOL_MEMORY_MAX};
    CHECK(vireo_mysql_pool_create(thread, &pool_options, &pool, NULL), VIREO_OK);
    CHECK(vireo_mysql_user_repository_create(thread, pool, &policy, &users, NULL), VIREO_OK);
    CHECK(vireo_mysql_node_repository_create(thread, pool, &nodes, NULL), VIREO_OK);
    CHECK(vireo_password_hash_create(&policy, "Correct!7", 9, phc, sizeof(phc), &phc_length), VIREO_OK);
    issued_at = now_ms() - 10000; uint64_t alice_mkdir, bob_mkdir;
    vireo_mysql_node_actor_t alice = account("alice_mkdir", &alice_mkdir), bob = account("bob_mkdir", &bob_mkdir);
    assert(alice_mkdir != bob_mkdir && alice_mkdir != 0 && bob_mkdir != 0);
    vireo_mysql_node_mkdir_once_input_t in=make_input(alice_mkdir, (const unsigned char *)"original", 8);
    vireo_directory_mkdir_result_t first=call(alice, &in, VIREO_OK, VIREO_DIRECTORY_MKDIR_CREATED);
    in.request_id[15]=++serial;
    vireo_directory_mkdir_result_t recovered=call(alice, &in, VIREO_OK, VIREO_DIRECTORY_MKDIR_RECOVERED);
    assert(first.node_id == recovered.node_id && first.repository.audit_id == recovered.repository.audit_id);
    vireo_mysql_node_mkdir_once_input_t changed=in; changed.parent_id=bob_mkdir;
    (void)call(alice, &changed, VIREO_RESULT_DATABASE, VIREO_DIRECTORY_MKDIR_IDEMPOTENCY_CONFLICT);
    changed=in; changed.name=(const unsigned char *)"different"; changed.name_length=9;
    (void)call(alice, &changed, VIREO_RESULT_DATABASE, VIREO_DIRECTORY_MKDIR_IDEMPOTENCY_CONFLICT);
    changed=make_input(alice_mkdir, in.name, in.name_length);
    (void)call(alice, &changed, VIREO_RESULT_DATABASE, VIREO_DIRECTORY_MKDIR_NAME_CONFLICT);
    changed=make_input(bob_mkdir, (const unsigned char *)"foreign", 7);
    (void)call(alice, &changed, VIREO_RESULT_NOT_FOUND, VIREO_DIRECTORY_MKDIR_PARENT_NOT_FOUND);
    changed.parent_id=UINT64_MAX;
    (void)call(alice, &changed, VIREO_RESULT_NOT_FOUND, VIREO_DIRECTORY_MKDIR_PARENT_NOT_FOUND);
    vireo_mysql_node_actor_t mixed={alice.user_id, bob.session_id};
    (void)call(mixed, &in, VIREO_RESULT_NOT_FOUND, VIREO_DIRECTORY_MKDIR_UNAUTHORIZED);
    pthread_t other; assert(pthread_create(&other, NULL, wrong_worker, &alice) == 0 && pthread_join(other, NULL) == 0);
    vireo_mysql_node_mkdir_once_input_t destination=make_input(alice_mkdir, (const unsigned char *)"destination", 11);
    vireo_directory_mkdir_result_t target=call(alice, &destination, VIREO_OK, VIREO_DIRECTORY_MKDIR_CREATED);
    vireo_mysql_node_move_input_t move={.node_id=first.node_id, .new_parent_id=target.node_id,
        .name=(const unsigned char *)"moved", .name_length=5, .request_id={0x44}};
    move.request_id[15]=++serial; vireo_mysql_node_move_report_t moved;
    CHECK(vireo_mysql_node_repository_move(nodes, &alice, &move, 0, &moved, NULL), VIREO_OK);
    recovered=call(alice, &in, VIREO_OK, VIREO_DIRECTORY_MKDIR_RECOVERED); assert(recovered.node_id == first.node_id);
    vireo_mysql_node_soft_delete_input_t deletion={.node_id=first.node_id, .request_id={0x55}};
    deletion.request_id[15]=++serial; vireo_mysql_node_soft_delete_report_t deleted;
    CHECK(vireo_mysql_node_repository_soft_delete(nodes, &alice, &deletion, 0, &deleted, NULL), VIREO_OK);
    recovered=call(alice, &in, VIREO_OK, VIREO_DIRECTORY_MKDIR_RECOVERED); assert(recovered.node_id == first.node_id);
    changed=make_input(first.node_id, (const unsigned char *)"deleted-parent", 14);
    (void)call(alice, &changed, VIREO_RESULT_NOT_FOUND, VIREO_DIRECTORY_MKDIR_PARENT_NOT_FOUND);
    old_bytes(alice, alice_mkdir, (const unsigned char *)"e\xcc\x81", 3);
    old_bytes(alice, alice_mkdir, (const unsigned char *)"\xff", 1);
    /* 真实活动文件不能作为父目录；受控SQL仅构造fixture。 */
    mutate("INSERT INTO objects(object_hash,size,state,ref_count,storage_class,created_at_ms,updated_at_ms,verified_at_ms) VALUES(UNHEX(REPEAT('a5',32)),1,2,1,1,1000,1000,1000)");
    char sql[1024]; int n=snprintf(sql, sizeof(sql),
        "INSERT INTO file_nodes(id,owner_id,parent_id,name,node_type,state,object_hash,size,created_at_ms,updated_at_ms) VALUES(1001,%llu,%llu,'file',2,2,UNHEX(REPEAT('a5',32)),1,1000,1000)",
        (unsigned long long)alice.user_id, (unsigned long long)alice_mkdir);
    assert(n>0 && (size_t)n<sizeof(sql)); mutate(sql);
    changed=make_input(1001, (const unsigned char *)"child", 5);
    (void)call(alice, &changed, VIREO_RESULT_NOT_FOUND, VIREO_DIRECTORY_MKDIR_PARENT_NOT_FOUND);
    for (size_t i=0; i<sizeof(name_vectors)/sizeof(name_vectors[0]); ++i) {
        const struct name_vector *v=&name_vectors[i];
        if (v->issue == VIREO_DIRECTORY_NAME_ISSUE_NONE) { continue; }
        changed=make_input(alice_mkdir, v->bytes, v->length);
        vireo_directory_mkdir_result_t invalid=call(alice, &changed,
            v->issue == VIREO_DIRECTORY_NAME_ISSUE_LENGTH ? VIREO_RESULT_RANGE : VIREO_RESULT_PROTOCOL,
            VIREO_DIRECTORY_MKDIR_INVALID_NAME);
        assert(invalid.name_issue == v->issue);
    }
    mutate("UPDATE users SET status=2 WHERE username_key='alice_mkdir'");
    (void)call(alice, &in, VIREO_RESULT_NOT_FOUND, VIREO_DIRECTORY_MKDIR_UNAUTHORIZED);
    /* 已失效身份也先报告仅本地请求字节的名字错误，六表完全不变。 */
    changed=make_input(alice_mkdir, (const unsigned char *)"e\xcc\x81", 3);
    (void)call(alice, &changed, VIREO_RESULT_PROTOCOL, VIREO_DIRECTORY_MKDIR_INVALID_NAME);
    mutate("UPDATE users SET status=1 WHERE username_key='alice_mkdir'");
    vireo_mysql_logout_input_t logout={.user_id=alice.user_id, .session_id=alice.session_id, .occurred_at_ms=now_ms(), .request_id={0x66}};
    logout.request_id[15]=++serial; vireo_mysql_logout_report_t logged_out;
    CHECK(vireo_mysql_user_repository_logout(users, &logout, 0, &logged_out, NULL), VIREO_OK);
    (void)call(alice, &in, VIREO_RESULT_NOT_FOUND, VIREO_DIRECTORY_MKDIR_UNAUTHORIZED);
    n=snprintf(sql, sizeof(sql), "UPDATE sessions SET expires_at_ms=issued_at_ms+1 WHERE id=%llu", (unsigned long long)bob.session_id);
    assert(n>0 && (size_t)n<sizeof(sql)); mutate(sql);
    changed=make_input(bob_mkdir, (const unsigned char *)"expired", 7);
    (void)call(bob, &changed, VIREO_RESULT_NOT_FOUND, VIREO_DIRECTORY_MKDIR_UNAUTHORIZED);
    assert(scalar("SELECT COUNT(*) FROM operation_audits") == scalar("SELECT COUNT(DISTINCT request_id) FROM operation_audits"));
    vireo_mysql_pool_info_t info; CHECK(vireo_mysql_pool_inspect(pool, &info), VIREO_OK);
    assert(info.leased == 0 && info.vacant == 0 && info.returning == 0 && info.idle == 3);
    CHECK(vireo_mysql_node_repository_destroy(&nodes, NULL), VIREO_OK);
    CHECK(vireo_mysql_user_repository_destroy(&users, NULL), VIREO_OK);
    bool closed=false; CHECK(vireo_mysql_pool_close(pool, &closed, NULL), VIREO_OK); assert(closed);
    CHECK(vireo_mysql_pool_destroy(thread, &pool, NULL), VIREO_OK);
    CHECK(vireo_mysql_connection_destroy(thread, &observer), VIREO_OK);
    CHECK(vireo_mysql_thread_detach(&thread), VIREO_OK);
    CHECK(vireo_mysql_runtime_destroy(&runtime), VIREO_OK);
    assert(first.node_id == recovered.node_id && fd_count() == fds);
    memset(db_password, 0, sizeof(db_password)); memset(phc, 0, sizeof(phc));
    printf("PASS %zu real service observations; create/recover/conflicts/auth/parents, moved/deleted recovery, legacy STAT/LIST bytes, six-table snapshots, unique audit events; FD %zu->%zu\n", cases, fds, fd_count());
    return 0;
}
