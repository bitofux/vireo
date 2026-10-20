#define _POSIX_C_SOURCE 200809L
#include "mysql_user_repository_internal.h"
#include "mysql_pool_internal.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>

typedef vireo_mysql_user_repository_stage_t stage_t;
#define STAGE(n) VIREO_MYSQL_USER_REPOSITORY_STAGE_##n
#define U64(v) ((vireo_mysql_parameter_t){.kind=VIREO_MYSQL_PARAMETER_U64,.value.u64=(v)})
#define SPAN(k,p,n) ((vireo_mysql_parameter_t){.kind=(k),.value.span={(p),(n)}})

struct vireo_mysql_user_repository {
    vireo_mysql_thread_t *thread; /* 借用；guard本身验证当前OS线程。 */
    vireo_mysql_pool_t *pool; /* 借用，管理方在worker退出后销毁。 */
    vireo_password_policy_t policy; /* 复制值，不保存原policy地址。 */
    vireo_mysql_user_repository_ops_t ops; /* 固定资源边界。 */
    vireo_mysql_lease_t lease; /* 唯一权威token，失败也不能丢失。 */
    vireo_mysql_connection_t *connection; /* 有效lease内短借。 */
    vireo_mysql_statement_t *statement; /* 唯一子owner，归还前须清空。 */
};
const vireo_mysql_user_repository_ops_t vireo_mysql_user_repository_native_ops = {
    malloc, free, vireo_mysql_pool_acquire, vireo_mysql_pool_borrow, vireo_mysql_pool_release,
    vireo_mysql_statement_prepare, vireo_mysql_statement_execute, vireo_mysql_statement_destroy,
    vireo_mysql_statement_fetch, vireo_mysql_statement_column
};
static const char insert_user[] =
    "INSERT INTO users(username,username_key,password_hash,status,created_at_ms,updated_at_ms) "
    "VALUES(?,?,?,1,?,?)";
static const char insert_root[] =
    "INSERT INTO file_nodes(owner_id,parent_id,name,node_type,state,object_hash,size,"
    "created_at_ms,updated_at_ms,deleted_at_ms) VALUES(?,NULL,'',1,2,NULL,0,?,?,NULL)";
static const char insert_audit[] =
    "INSERT INTO operation_audits(request_id,user_id,session_id,action,target_type,target_id,"
    "target_hash,status,latency_us,detail,occurred_at_ms) VALUES(?,?,NULL,1,1,?,NULL,0,?,'',?)";
/* 固定写SQL至多6参数/655字节，不读取列；预算只约束statement wrapper。 */
static const vireo_mysql_statement_limits_t limits = {6, 0, 655, 1, 32768};

static vireo_result_t finish(int saved, vireo_result_t result)
{ errno = saved; return result; }
static bool valid(const vireo_mysql_user_repository_t *r)
{ return r != NULL && vireo_mysql_valid_guard(r->thread) && r->thread->runtime == r->pool->runtime; }
static bool pending(const vireo_mysql_user_repository_t *r)
{ return r->lease.owner != NULL || r->statement != NULL; }

/* 即使caller不需要诊断，入口也使用本地error保存主因/清理优先级。 */
static void diagnose(vireo_mysql_user_repository_error_t *e, stage_t stage,
    vireo_result_t result, const vireo_mysql_error_t *db, const vireo_mysql_pool_error_t *pool,
    bool cleanup)
{
    if (result == VIREO_OK) { return; }
    if (cleanup && e->cleanup_result == VIREO_OK) {
        e->cleanup_result = result; e->cleanup_stage = stage;
        if (db != NULL) { e->cleanup_database = *db; }
        if (pool != NULL) { e->cleanup_pool = *pool; }
    }
    if (e->stage == STAGE(NONE)) {
        e->stage = stage;
        if (db != NULL) { e->database = *db; }
        if (pool != NULL) { e->pool = *pool; }
    }
}
static vireo_result_t close_statement(vireo_mysql_user_repository_t *r,
    vireo_mysql_user_repository_error_t *e)
{
    if (r->statement == NULL) { return VIREO_OK; }
    vireo_mysql_error_t db = {0};
    vireo_result_t result = r->ops.close(r->thread, &r->statement, &db);
    diagnose(e, STAGE(STATEMENT_CLOSE), result, &db, NULL, true);
    return result;
}

/* replied保存execute成功及固定结果形状，与后续close是否成功严格分离。 */
static vireo_result_t command(vireo_mysql_user_repository_t *r, const char *sql,
    const vireo_mysql_parameter_t *parameters, size_t count, stage_t stage, bool insert,
    bool cleanup, vireo_mysql_execution_t *ex, bool *replied,
    vireo_mysql_user_repository_error_t *e)
{
    *ex = (vireo_mysql_execution_t){0}; *replied = false;
    vireo_mysql_error_t db = {0};
    vireo_result_t result = r->ops.prepare(r->thread, r->connection, sql, strlen(sql),
        &limits, &r->statement, &db);
    diagnose(e, stage, result, &db, NULL, cleanup);
    if (result == VIREO_OK) {
        result = r->ops.execute(r->thread, r->statement, parameters, count, ex, &db);
        /* 只在相应INSERT原生execute失败时分类，不解析错误文本/索引名。 */
        diagnose(e, stage, result, &db, NULL, cleanup);
        if (result == VIREO_OK) {
            if (ex->has_result || (insert && (ex->affected_rows != 1 || ex->insert_id == 0))) {
                result = VIREO_RESULT_DATABASE;
                diagnose(e, stage, result, NULL, NULL, cleanup);
            } else { *replied = true; }
        }
    }
    vireo_result_t closed = close_statement(r, e);
    return result == VIREO_OK ? closed : result;
}
static vireo_result_t release_lease(vireo_mysql_user_repository_t *r,
    vireo_mysql_pool_disposition_t disposition, vireo_mysql_user_repository_error_t *e)
{
    if (r->lease.owner == NULL || r->statement != NULL) { return VIREO_OK; }
    vireo_mysql_pool_error_t pool = {0}; vireo_mysql_pool_release_t report = {0};
    vireo_result_t result = r->ops.release(r->thread, r->pool, &r->lease, disposition, &report, &pool);
    if (report.released) { r->connection = NULL; }
    diagnose(e, STAGE(RELEASE), result, NULL, &pool, true);
    return result;
}

vireo_result_t vireo_mysql_user_repository_create_with_ops(vireo_mysql_thread_t *t,
    vireo_mysql_pool_t *p, const vireo_password_policy_t *policy,
    vireo_mysql_user_repository_t **out, vireo_mysql_user_repository_error_t *error,
    const vireo_mysql_user_repository_ops_t *ops)
{
    int saved = errno;
    vireo_mysql_user_repository_error_t local = {0};
    vireo_mysql_user_repository_error_t *e = error != NULL ? error : &local; *e = local;
    if (!vireo_mysql_valid_guard(t) || p == NULL || t->runtime != p->runtime ||
        policy == NULL || out == NULL || *out != NULL || ops == NULL ||
        ops->allocate == NULL || ops->release_memory == NULL || ops->acquire == NULL ||
        ops->borrow == NULL || ops->release == NULL || ops->prepare == NULL ||
        ops->execute == NULL || ops->close == NULL || ops->fetch == NULL || ops->column == NULL) {
        diagnose(e, STAGE(VALIDATE), VIREO_RESULT_INVALID_ARGUMENT, NULL, NULL, false);
        return finish(saved, VIREO_RESULT_INVALID_ARGUMENT);
    }
    /* 使用公共inspect校验policy，不复制密码模块的策略规则或引入私有依赖。
     * 此canonical探针不是用户密码记录；m/t在所有合法策略的允许范围内。 */
    static const char probe[] = "$argon2id$v=19$m=65536,t=3,p=1$"
        "AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    vireo_password_info_t info;
    vireo_result_t result = vireo_password_hash_inspect(policy, probe, sizeof(probe)-1, &info);
    if (result != VIREO_OK) {
        diagnose(e, STAGE(VALIDATE), result, NULL, NULL, false); return finish(saved, result);
    }
    vireo_mysql_user_repository_t *r = ops->allocate(sizeof(*r));
    if (r == NULL) {
        diagnose(e, STAGE(ALLOCATE), VIREO_RESULT_NO_MEMORY, NULL, NULL, false);
        return finish(saved, VIREO_RESULT_NO_MEMORY);
    }
    *r = (vireo_mysql_user_repository_t){.thread=t, .pool=p, .policy=*policy, .ops=*ops};
    *out = r; return finish(saved, VIREO_OK);
}
vireo_result_t vireo_mysql_user_repository_create(vireo_mysql_thread_t *t,
    vireo_mysql_pool_t *p, const vireo_password_policy_t *policy,
    vireo_mysql_user_repository_t **out, vireo_mysql_user_repository_error_t *error)
{
    return vireo_mysql_user_repository_create_with_ops(t, p, policy, out, error,
        &vireo_mysql_user_repository_native_ops);
}
static vireo_result_t validate_input(const vireo_mysql_registration_input_t *in, uint32_t wait,
    const vireo_password_policy_t *policy)
{
    if (in == NULL || in->username == NULL || in->username_key == NULL || in->password_hash == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    if (wait > VIREO_MYSQL_POOL_WAIT_MS_MAX || in->username_length == 0 || in->username_length > 256 ||
        in->username_key_length == 0 || in->username_key_length > 256 ||
        in->password_hash_length == 0 || in->password_hash_length >= VIREO_PASSWORD_ENCODED_CAPACITY) {
        return VIREO_RESULT_RANGE;
    }
    unsigned char any = 0;
    for (size_t i = 0; i < sizeof(in->request_id); ++i) { any |= in->request_id[i]; }
    if (any == 0) { return VIREO_RESULT_INVALID_ARGUMENT; }
    vireo_password_info_t info;
    vireo_result_t result = vireo_password_hash_inspect(policy, in->password_hash, in->password_hash_length, &info);
    if (result != VIREO_OK) { return result; }
    return info.memory_kib == policy->create_memory_kib && info.iterations == policy->create_iterations ?
        VIREO_OK : VIREO_RESULT_RANGE;
}
vireo_result_t vireo_mysql_user_repository_register(vireo_mysql_user_repository_t *r,
    const vireo_mysql_registration_input_t *in, uint32_t wait,
    vireo_mysql_registration_report_t *out, vireo_mysql_user_repository_error_t *error)
{
    int saved = errno;
    vireo_mysql_user_repository_error_t local = {0};
    vireo_mysql_user_repository_error_t *e = error != NULL ? error : &local; *e = local;
    if (out != NULL) { *out = (vireo_mysql_registration_report_t){0}; }
    if (!valid(r) || out == NULL) {
        diagnose(e, STAGE(VALIDATE), VIREO_RESULT_INVALID_ARGUMENT, NULL, NULL, false);
        return finish(saved, VIREO_RESULT_INVALID_ARGUMENT);
    }
    out->cleanup_pending = pending(r);
    vireo_result_t result = pending(r) ? VIREO_RESULT_BUSY : validate_input(in, wait, &r->policy);
    if (result != VIREO_OK) {
        diagnose(e, STAGE(VALIDATE), result, NULL, NULL, false); return finish(saved, result);
    }
    bool transaction_possible = false, replied = false;
    uint64_t user = 0, root = 0, audit = 0;
    vireo_mysql_execution_t ex = {0};
    vireo_mysql_pool_error_t pool = {0}; vireo_mysql_pool_acquisition_t acquired = {0};
    result = r->ops.acquire(r->thread, r->pool, wait, &r->lease, &acquired, &pool);
    diagnose(e, STAGE(ACQUIRE), result, NULL, &pool, false);
    if (result != VIREO_OK) { goto done; }
    result = r->ops.borrow(r->thread, r->pool, &r->lease, &r->connection);
    diagnose(e, STAGE(BORROW), result, NULL, NULL, false);
    if (result != VIREO_OK) { goto done; }
    result = command(r, "SET autocommit=0", NULL, 0, STAGE(BEGIN), false, false, &ex, &replied, e);
    transaction_possible = ex.execution_started;
    if (result != VIREO_OK) { goto done; }
    vireo_mysql_parameter_t u[] = {
        SPAN(VIREO_MYSQL_PARAMETER_TEXT, in->username, in->username_length),
        SPAN(VIREO_MYSQL_PARAMETER_BYTES, in->username_key, in->username_key_length),
        SPAN(VIREO_MYSQL_PARAMETER_BYTES, in->password_hash, in->password_hash_length),
        U64(in->occurred_at_ms), U64(in->occurred_at_ms)};
    result = command(r, insert_user, u, 5, STAGE(USER), true, false, &ex, &replied, e);
    if (result != VIREO_OK) {
        if (e->stage == STAGE(USER) && e->database.stage == VIREO_MYSQL_STAGE_STATEMENT_EXECUTE &&
            e->database.mysql_code == 1062) { out->conflict = VIREO_MYSQL_REGISTRATION_USERNAME_CONFLICT; }
        goto done;
    }
    user = ex.insert_id;
    vireo_mysql_parameter_t n[] = {U64(user), U64(in->occurred_at_ms), U64(in->occurred_at_ms)};
    result = command(r, insert_root, n, 3, STAGE(ROOT), true, false, &ex, &replied, e);
    if (result != VIREO_OK) { goto done; }
    root = ex.insert_id;
    vireo_mysql_parameter_t a[] = {
        SPAN(VIREO_MYSQL_PARAMETER_BYTES, in->request_id, sizeof(in->request_id)),
        U64(user), U64(user), U64(in->latency_us), U64(in->occurred_at_ms)};
    result = command(r, insert_audit, a, 5, STAGE(AUDIT), true, false, &ex, &replied, e);
    if (result != VIREO_OK) {
        if (e->stage == STAGE(AUDIT) && e->database.stage == VIREO_MYSQL_STAGE_STATEMENT_EXECUTE &&
            e->database.mysql_code == 1062) { out->conflict = VIREO_MYSQL_REGISTRATION_REQUEST_CONFLICT; }
        goto done;
    }
    audit = ex.insert_id;
    result = command(r, "COMMIT", NULL, 0, STAGE(COMMIT), false, false, &ex, &replied, e);
    if (replied) {
        out->commit = VIREO_MYSQL_REGISTRATION_COMMITTED;
        out->user_id = user; out->root_node_id = root; out->audit_id = audit;
    } else if (ex.execution_started) { out->commit = VIREO_MYSQL_REGISTRATION_UNKNOWN; }
done:
    if (transaction_possible && out->commit == VIREO_MYSQL_REGISTRATION_NOT_COMMITTED && r->statement == NULL) {
        vireo_result_t rolled = command(r, "ROLLBACK", NULL, 0, STAGE(ROLLBACK), false, true, &ex, &replied, e);
        out->rollback_confirmed = replied;
        if (result == VIREO_OK) { result = rolled; }
    }
    vireo_result_t released = release_lease(r,
        out->commit == VIREO_MYSQL_REGISTRATION_COMMITTED || out->rollback_confirmed ?
            VIREO_MYSQL_POOL_RECYCLE : VIREO_MYSQL_POOL_DISCARD, e);
    if (result == VIREO_OK) { result = released; }
    out->cleanup_pending = pending(r);
    return finish(saved, result);
}
/* 数字列由statement以十进制字节视图返回；不借助NUL或有符号窄化。 */
static bool unsigned_cell(const vireo_mysql_cell_view_t *c, uint64_t *out)
{
    if (c->is_null || c->data == NULL || c->length == 0 || c->length > 20) { return false; }
    uint64_t value = 0;
    for (size_t i = 0; i < c->length; ++i) {
        unsigned int digit = (unsigned int)c->data[i] - (unsigned int)'0';
        if (digit > 9 || value > (UINT64_MAX - digit) / 10) { return false; }
        value = value * 10 + digit;
    }
    *out = value; return true;
}
static vireo_result_t lock_account(vireo_mysql_user_repository_t *r,
    const vireo_mysql_login_input_t *in, vireo_mysql_login_report_t *out,
    vireo_mysql_user_repository_error_t *e)
{
    static const char sql[] = "SELECT password_hash,status,created_at_ms FROM users WHERE id=? FOR UPDATE";
    static const vireo_mysql_statement_limits_t read_limits = {1, 3, 0, 127, 32768};
    vireo_mysql_error_t db = {0}; vireo_mysql_execution_t ex = {0};
    vireo_mysql_parameter_t id = U64(in->user_id);
    vireo_result_t result = r->ops.prepare(r->thread, r->connection, sql, sizeof(sql)-1,
        &read_limits, &r->statement, &db);
    if (result != VIREO_OK) { goto done; }
    result = r->ops.execute(r->thread, r->statement, &id, 1, &ex, &db);
    if (result != VIREO_OK) { goto done; }
    if (!ex.has_result) { goto malformed; }
    vireo_mysql_fetch_outcome_t fetched;
    result = r->ops.fetch(r->thread, r->statement, &fetched, &db);
    if (result != VIREO_OK) { goto done; }
    if (fetched == VIREO_MYSQL_FETCH_DONE) {
        out->issue = VIREO_MYSQL_LOGIN_USER_NOT_FOUND; result = VIREO_RESULT_NOT_FOUND; goto done;
    }
    if (fetched != VIREO_MYSQL_FETCH_ROW) { goto malformed; }
    vireo_mysql_cell_view_t cells[3] = {{0}};
    for (size_t i = 0; i < 3; ++i) {
        result = r->ops.column(r->thread, r->statement, i, &cells[i]);
        if (result != VIREO_OK) { goto done; }
    }
    uint64_t status = 0, created = 0;
    if (cells[0].is_null || cells[0].data == NULL || cells[0].length == 0 || cells[0].length > 127 ||
        !unsigned_cell(&cells[1], &status) || (status != 1 && status != 2) ||
        !unsigned_cell(&cells[2], &created)) { goto malformed; }
    /* 视图在下一fetch失效，比较结果必须在这里保存。PHC不是明文密码。 */
    bool same = cells[0].length == in->verified_password_hash_length &&
        memcmp(cells[0].data, in->verified_password_hash, cells[0].length) == 0;
    result = r->ops.fetch(r->thread, r->statement, &fetched, &db);
    if (result != VIREO_OK) { goto done; }
    if (fetched != VIREO_MYSQL_FETCH_DONE) { goto malformed; }
    if (status != 1) { out->issue = VIREO_MYSQL_LOGIN_USER_DISABLED; result = VIREO_RESULT_NOT_FOUND; }
    else if (!same) { out->issue = VIREO_MYSQL_LOGIN_PASSWORD_CHANGED; result = VIREO_RESULT_NOT_FOUND; }
    else if (in->issued_at_ms < created) { out->issue = VIREO_MYSQL_LOGIN_TIME_BEFORE_USER; result = VIREO_RESULT_RANGE; }
    goto done;
malformed:
    out->issue = VIREO_MYSQL_LOGIN_UNEXPECTED_RESULT; result = VIREO_RESULT_DATABASE;
done:
    diagnose(e, STAGE(ACCOUNT), result, &db, NULL, false);
    vireo_result_t closed = close_statement(r, e);
    return result == VIREO_OK ? closed : result;
}
static vireo_result_t validate_login(const vireo_mysql_login_input_t *in, uint32_t wait,
    const vireo_password_policy_t *policy)
{
    if (in == NULL || in->verified_password_hash == NULL || in->user_id == 0) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    if (wait > VIREO_MYSQL_POOL_WAIT_MS_MAX || in->verified_password_hash_length == 0 ||
        in->verified_password_hash_length >= VIREO_PASSWORD_ENCODED_CAPACITY ||
        in->expires_at_ms <= in->issued_at_ms) { return VIREO_RESULT_RANGE; }
    unsigned char any = 0;
    for (size_t i = 0; i < sizeof(in->request_id); ++i) { any |= in->request_id[i]; }
    if (any == 0) { return VIREO_RESULT_INVALID_ARGUMENT; }
    vireo_password_info_t info;
    return vireo_password_hash_inspect(policy, in->verified_password_hash,
        in->verified_password_hash_length, &info);
}
vireo_result_t vireo_mysql_user_repository_login(vireo_mysql_user_repository_t *r,
    const vireo_mysql_login_input_t *in, uint32_t wait,
    vireo_mysql_login_report_t *out, vireo_mysql_user_repository_error_t *error)
{
    int saved = errno;
    vireo_mysql_user_repository_error_t local = {0};
    vireo_mysql_user_repository_error_t *e = error != NULL ? error : &local; *e = local;
    if (out != NULL) { *out = (vireo_mysql_login_report_t){0}; }
    if (!valid(r) || out == NULL) {
        diagnose(e, STAGE(VALIDATE), VIREO_RESULT_INVALID_ARGUMENT, NULL, NULL, false);
        return finish(saved, VIREO_RESULT_INVALID_ARGUMENT);
    }
    out->cleanup_pending = pending(r);
    vireo_result_t result = pending(r) ? VIREO_RESULT_BUSY : validate_login(in, wait, &r->policy);
    if (result != VIREO_OK) {
        diagnose(e, STAGE(VALIDATE), result, NULL, NULL, false); return finish(saved, result);
    }
    bool transaction_possible = false, replied = false;
    uint64_t session = 0, audit = 0;
    vireo_mysql_execution_t ex = {0};
    vireo_mysql_pool_error_t pool = {0}; vireo_mysql_pool_acquisition_t acquired = {0};
    result = r->ops.acquire(r->thread, r->pool, wait, &r->lease, &acquired, &pool);
    diagnose(e, STAGE(ACQUIRE), result, NULL, &pool, false);
    if (result != VIREO_OK) { goto done; }
    result = r->ops.borrow(r->thread, r->pool, &r->lease, &r->connection);
    diagnose(e, STAGE(BORROW), result, NULL, NULL, false);
    if (result != VIREO_OK) { goto done; }
    result = command(r, "SET autocommit=0", NULL, 0, STAGE(BEGIN), false, false, &ex, &replied, e);
    transaction_possible = ex.execution_started;
    if (result != VIREO_OK) { goto done; }
    result = lock_account(r, in, out, e);
    if (result != VIREO_OK) { goto done; }
    vireo_mysql_parameter_t s[] = {U64(in->user_id),
        SPAN(VIREO_MYSQL_PARAMETER_BYTES, in->token_digest.bytes, sizeof(in->token_digest.bytes)),
        U64(in->issued_at_ms), U64(in->expires_at_ms), U64(in->issued_at_ms)};
    result = command(r, "INSERT INTO sessions(user_id,token_digest,status,issued_at_ms,expires_at_ms,"
        "revoked_at_ms,last_seen_at_ms) VALUES(?,?,1,?,?,NULL,?)",
        s, 5, STAGE(SESSION), true, false, &ex, &replied, e);
    if (result != VIREO_OK) {
        if (e->stage == STAGE(SESSION) && e->database.stage == VIREO_MYSQL_STAGE_STATEMENT_EXECUTE &&
            e->database.mysql_code == 1062) { out->issue = VIREO_MYSQL_LOGIN_DIGEST_CONFLICT; }
        goto done;
    }
    session = ex.insert_id;
    vireo_mysql_parameter_t u[] = {U64(in->issued_at_ms), U64(in->issued_at_ms), U64(in->user_id)};
    result = command(r, "UPDATE users SET last_login_at_ms=GREATEST(COALESCE(last_login_at_ms,0),?),"
        "updated_at_ms=GREATEST(updated_at_ms,?) WHERE id=?",
        u, 3, STAGE(LOGIN_UPDATE), false, false, &ex, &replied, e);
    if (result == VIREO_OK && ex.affected_rows > 1) {
        result = VIREO_RESULT_DATABASE; out->issue = VIREO_MYSQL_LOGIN_UNEXPECTED_RESULT;
        diagnose(e, STAGE(LOGIN_UPDATE), result, NULL, NULL, false);
    }
    if (result != VIREO_OK) { goto done; }
    vireo_mysql_parameter_t a[] = {
        SPAN(VIREO_MYSQL_PARAMETER_BYTES, in->request_id, sizeof(in->request_id)),
        U64(in->user_id), U64(session), U64(session), U64(in->latency_us), U64(in->issued_at_ms)};
    result = command(r, "INSERT INTO operation_audits(request_id,user_id,session_id,action,target_type,"
        "target_id,target_hash,status,latency_us,detail,occurred_at_ms) VALUES(?,?,?,2,2,?,NULL,0,?,'',?)",
        a, 6, STAGE(AUDIT), true, false, &ex, &replied, e);
    if (result != VIREO_OK) {
        if (e->stage == STAGE(AUDIT) && e->database.stage == VIREO_MYSQL_STAGE_STATEMENT_EXECUTE &&
            e->database.mysql_code == 1062) { out->issue = VIREO_MYSQL_LOGIN_REQUEST_CONFLICT; }
        goto done;
    }
    audit = ex.insert_id;
    result = command(r, "COMMIT", NULL, 0, STAGE(COMMIT), false, false, &ex, &replied, e);
    if (replied) {
        out->commit = VIREO_MYSQL_LOGIN_COMMITTED; out->session_id = session; out->audit_id = audit;
    } else if (ex.execution_started) { out->commit = VIREO_MYSQL_LOGIN_UNKNOWN; }
done:
    if (result == VIREO_RESULT_DATABASE && out->issue == VIREO_MYSQL_LOGIN_ISSUE_NONE &&
        e->database.stage == VIREO_MYSQL_STAGE_NONE &&
        (e->stage == STAGE(BEGIN) || e->stage == STAGE(SESSION) ||
         e->stage == STAGE(LOGIN_UPDATE) || e->stage == STAGE(AUDIT) || e->stage == STAGE(COMMIT))) {
        out->issue = VIREO_MYSQL_LOGIN_UNEXPECTED_RESULT;
    }
    if (transaction_possible && out->commit == VIREO_MYSQL_LOGIN_NOT_COMMITTED && r->statement == NULL) {
        vireo_result_t rolled = command(r, "ROLLBACK", NULL, 0, STAGE(ROLLBACK), false, true, &ex, &replied, e);
        out->rollback_confirmed = replied;
        if (result == VIREO_OK) { result = rolled; }
    }
    vireo_result_t released = release_lease(r,
        out->commit == VIREO_MYSQL_LOGIN_COMMITTED || out->rollback_confirmed ?
            VIREO_MYSQL_POOL_RECYCLE : VIREO_MYSQL_POOL_DISCARD, e);
    if (result == VIREO_OK) { result = released; }
    out->cleanup_pending = pending(r);
    return finish(saved, result);
}
/* volatile使本次对象清除不能作为无用普通存储被消除；不承诺其他副本擦除。 */
static void wipe_credentials(vireo_mysql_user_credentials_t *value)
{
    volatile unsigned char *bytes = (volatile unsigned char *)value;
    for (size_t i = 0; i < sizeof(*value); ++i) { bytes[i] = 0; }
}
vireo_result_t vireo_mysql_user_credentials_clear(vireo_mysql_user_credentials_t *value)
{
    int saved = errno;
    if (value == NULL) { return finish(saved, VIREO_RESULT_INVALID_ARGUMENT); }
    wipe_credentials(value); return finish(saved, VIREO_OK);
}
/**
 * @brief 在已借连接上读唯一行；out是调用栈临时值，失败也由调用者擦除。
 * @param[in,out] r 当前worker R，无live statement，持有有效lease/connection。
 * @param[in] key 调用期只读精确span，不拼SQL。
 * @param[in] length 1..256字节，外层已校验。
 * @param[out] out 已全零的临时凭据，仅完整一行才有可用字段。
 * @param[in,out] e 首因/首清理诊断。
 * @return OK唯一合法快照，NOT_FOUND无行，DATABASE坏形状，其他沿statement/inspect。
 * @note 始终尝试close，失败可留statement在R；不release、不发布给caller。
 */
static vireo_result_t read_credentials(vireo_mysql_user_repository_t *r, const void *key,
    size_t length, vireo_mysql_user_credentials_t *out, vireo_mysql_user_repository_error_t *e)
{
    static const char sql[] = "SELECT id,status,password_hash FROM users WHERE username_key=?";
    static const vireo_mysql_statement_limits_t read_limits = {1, 3, 256, 127, 32768};
    vireo_mysql_error_t db = {0}; vireo_mysql_execution_t ex = {0};
    vireo_mysql_parameter_t parameter = SPAN(VIREO_MYSQL_PARAMETER_BYTES, key, length);
    vireo_result_t result = r->ops.prepare(r->thread, r->connection, sql, sizeof(sql)-1,
        &read_limits, &r->statement, &db);
    if (result != VIREO_OK) { goto done; }
    result = r->ops.execute(r->thread, r->statement, &parameter, 1, &ex, &db);
    if (result != VIREO_OK) { goto done; }
    if (!ex.has_result) { goto malformed; }
    vireo_mysql_fetch_outcome_t fetched;
    result = r->ops.fetch(r->thread, r->statement, &fetched, &db);
    if (result != VIREO_OK) { goto done; }
    if (fetched == VIREO_MYSQL_FETCH_DONE) { result = VIREO_RESULT_NOT_FOUND; goto done; }
    if (fetched != VIREO_MYSQL_FETCH_ROW) { goto malformed; }
    vireo_mysql_cell_view_t cells[3] = {{0}};
    for (size_t i = 0; i < 3; ++i) {
        result = r->ops.column(r->thread, r->statement, i, &cells[i]);
        if (result != VIREO_OK) { goto done; }
    }
    uint64_t status = 0;
    if (!unsigned_cell(&cells[0], &out->user_id) || out->user_id == 0 ||
        !unsigned_cell(&cells[1], &status) || (status != 1 && status != 2) ||
        cells[2].is_null || cells[2].data == NULL || cells[2].length == 0 ||
        cells[2].length >= sizeof(out->password_hash)) { goto malformed; }
    out->status = status == 1 ? VIREO_MYSQL_USER_STATUS_ACTIVE : VIREO_MYSQL_USER_STATUS_DISABLED;
    out->password_hash_length = cells[2].length;
    memcpy(out->password_hash, cells[2].data, cells[2].length);
    /* 临时值此前已全清零，尾NUL和未用数组字节不依赖行视图的终止符。 */
    result = r->ops.fetch(r->thread, r->statement, &fetched, &db);
    if (result != VIREO_OK) { goto done; }
    if (fetched != VIREO_MYSQL_FETCH_DONE) { goto malformed; }
    vireo_password_info_t info;
    result = vireo_password_hash_inspect(&r->policy, out->password_hash,
        out->password_hash_length, &info);
    goto done;
malformed:
    result = VIREO_RESULT_DATABASE;
done:
    diagnose(e, STAGE(CREDENTIALS), result, &db, NULL, false);
    vireo_result_t closed = close_statement(r, e);
    return result == VIREO_OK ? closed : result;
}
vireo_result_t vireo_mysql_user_repository_find_credentials(vireo_mysql_user_repository_t *r,
    const void *key, size_t length, uint32_t wait, vireo_mysql_user_credentials_t *out,
    vireo_mysql_credentials_report_t *report, vireo_mysql_user_repository_error_t *error)
{
    int saved = errno;
    vireo_mysql_user_repository_error_t local = {0};
    vireo_mysql_user_repository_error_t *e = error != NULL ? error : &local; *e = local;
    if (out != NULL) { wipe_credentials(out); }
    if (report != NULL) { *report = (vireo_mysql_credentials_report_t){0}; }
    if (!valid(r) || out == NULL || report == NULL) {
        diagnose(e, STAGE(VALIDATE), VIREO_RESULT_INVALID_ARGUMENT, NULL, NULL, false);
        return finish(saved, VIREO_RESULT_INVALID_ARGUMENT);
    }
    report->cleanup_pending = pending(r);
    vireo_result_t result = pending(r) ? VIREO_RESULT_BUSY :
        (key == NULL ? VIREO_RESULT_INVALID_ARGUMENT :
         (length == 0 || length > 256 || wait > VIREO_MYSQL_POOL_WAIT_MS_MAX ? VIREO_RESULT_RANGE : VIREO_OK));
    if (result != VIREO_OK) {
        diagnose(e, STAGE(VALIDATE), result, NULL, NULL, false); return finish(saved, result);
    }
    vireo_mysql_user_credentials_t value; wipe_credentials(&value);
    vireo_mysql_pool_error_t pool = {0}; vireo_mysql_pool_acquisition_t acquired = {0};
    vireo_result_t released;
    result = r->ops.acquire(r->thread, r->pool, wait, &r->lease, &acquired, &pool);
    diagnose(e, STAGE(ACQUIRE), result, NULL, &pool, false);
    if (result != VIREO_OK) { goto done; }
    result = r->ops.borrow(r->thread, r->pool, &r->lease, &r->connection);
    diagnose(e, STAGE(BORROW), result, NULL, NULL, false);
    if (result != VIREO_OK) { goto done; }
    result = read_credentials(r, key, length, &value, e);
done:
    /* 只有健康的完整读取/无行可复用；其他分支保守丢弃，无写操作可重放。 */
    released = release_lease(r,
        (result == VIREO_OK || result == VIREO_RESULT_NOT_FOUND) && e->cleanup_result == VIREO_OK ?
            VIREO_MYSQL_POOL_RECYCLE : VIREO_MYSQL_POOL_DISCARD, e);
    if (result == VIREO_OK) { result = released; }
    report->cleanup_pending = pending(r);
    if (result == VIREO_OK) { *out = value; report->found = true; }
    wipe_credentials(&value);
    return finish(saved, result);
}
/* 一条JOIN提供同一读视图；只读快照，不持锁跨越调用方的后续业务。 */
static vireo_result_t read_session(vireo_mysql_user_repository_t *r,
    const vireo_session_token_digest_t *digest, uint64_t now,
    vireo_mysql_session_identity_t *value, vireo_mysql_session_issue_t *issue,
    vireo_mysql_user_repository_error_t *e)
{
    static const char sql[] = "SELECT s.id,s.user_id,s.status,s.issued_at_ms,s.expires_at_ms,"
        "s.revoked_at_ms,s.last_seen_at_ms,u.status FROM sessions s "
        "JOIN users u ON u.id=s.user_id WHERE s.token_digest=?";
    static const vireo_mysql_statement_limits_t read_limits = {1, 8, 32, 20, 32768};
    vireo_mysql_error_t db = {0}; vireo_mysql_execution_t ex = {0};
    vireo_mysql_parameter_t parameter = SPAN(VIREO_MYSQL_PARAMETER_BYTES, digest->bytes, sizeof(digest->bytes));
    vireo_mysql_fetch_outcome_t fetched;
    uint64_t numbers[8] = {0};
    bool revoked_null = false;
    vireo_result_t result = r->ops.prepare(r->thread, r->connection, sql, sizeof(sql)-1,
        &read_limits, &r->statement, &db);
    if (result != VIREO_OK) { goto done; }
    result = r->ops.execute(r->thread, r->statement, &parameter, 1, &ex, &db);
    if (result != VIREO_OK) { goto done; }
    if (!ex.has_result) { goto malformed; }
    result = r->ops.fetch(r->thread, r->statement, &fetched, &db);
    if (result != VIREO_OK) { goto done; }
    if (fetched == VIREO_MYSQL_FETCH_DONE) {
        *issue = VIREO_MYSQL_SESSION_NOT_FOUND; result = VIREO_RESULT_NOT_FOUND; goto done;
    }
    if (fetched != VIREO_MYSQL_FETCH_ROW) { goto malformed; }
    for (size_t i = 0; i < 8; ++i) {
        vireo_mysql_cell_view_t cell = {0};
        result = r->ops.column(r->thread, r->statement, i, &cell);
        if (result != VIREO_OK) { goto done; }
        if (i == 5 && cell.is_null) { revoked_null = true; }
        else if (!unsigned_cell(&cell, &numbers[i])) { goto malformed; }
    }
    if (numbers[0] == 0 || numbers[1] == 0 || (numbers[2] != 1 && numbers[2] != 2) ||
        numbers[4] <= numbers[3] || numbers[6] < numbers[3] || numbers[6] > numbers[4] ||
        (numbers[7] != 1 && numbers[7] != 2) ||
        (numbers[2] == 1 ? !revoked_null : (revoked_null || numbers[5] < numbers[3]))) { goto malformed; }
    result = r->ops.fetch(r->thread, r->statement, &fetched, &db);
    if (result != VIREO_OK) { goto done; }
    if (fetched != VIREO_MYSQL_FETCH_DONE) { goto malformed; }
    *issue = numbers[2] == 2 ? VIREO_MYSQL_SESSION_REVOKED :
        (numbers[7] == 2 ? VIREO_MYSQL_SESSION_USER_DISABLED :
         (now < numbers[3] ? VIREO_MYSQL_SESSION_NOT_YET_VALID :
          (now >= numbers[4] ? VIREO_MYSQL_SESSION_EXPIRED : VIREO_MYSQL_SESSION_ISSUE_NONE)));
    if (*issue != VIREO_MYSQL_SESSION_ISSUE_NONE) { result = VIREO_RESULT_NOT_FOUND; goto done; }
    *value = (vireo_mysql_session_identity_t){numbers[0], numbers[1], numbers[3], numbers[4]};
    goto done;
malformed:
    result = VIREO_RESULT_DATABASE;
done:
    diagnose(e, STAGE(SESSION_LOOKUP), result, &db, NULL, false);
    vireo_result_t closed = close_statement(r, e);
    return result == VIREO_OK ? closed : result;
}
vireo_result_t vireo_mysql_user_repository_find_session(vireo_mysql_user_repository_t *r,
    const vireo_session_token_digest_t *digest, uint64_t now, uint32_t wait,
    vireo_mysql_session_identity_t *out, vireo_mysql_session_report_t *report,
    vireo_mysql_user_repository_error_t *error)
{
    int saved = errno;
    vireo_mysql_user_repository_error_t local = {0};
    vireo_mysql_user_repository_error_t *e = error != NULL ? error : &local; *e = local;
    if (out != NULL) { memset(out, 0, sizeof(*out)); }
    if (report != NULL) { *report = (vireo_mysql_session_report_t){0}; }
    if (!valid(r) || out == NULL || report == NULL) {
        diagnose(e, STAGE(VALIDATE), VIREO_RESULT_INVALID_ARGUMENT, NULL, NULL, false);
        return finish(saved, VIREO_RESULT_INVALID_ARGUMENT);
    }
    report->cleanup_pending = pending(r);
    vireo_result_t result = pending(r) ? VIREO_RESULT_BUSY :
        (digest == NULL ? VIREO_RESULT_INVALID_ARGUMENT :
         (wait > VIREO_MYSQL_POOL_WAIT_MS_MAX ? VIREO_RESULT_RANGE : VIREO_OK));
    if (result != VIREO_OK) {
        diagnose(e, STAGE(VALIDATE), result, NULL, NULL, false); return finish(saved, result);
    }
    vireo_mysql_session_identity_t value = {0};
    vireo_mysql_pool_error_t pool = {0}; vireo_mysql_pool_acquisition_t acquired = {0};
    vireo_result_t released;
    result = r->ops.acquire(r->thread, r->pool, wait, &r->lease, &acquired, &pool);
    diagnose(e, STAGE(ACQUIRE), result, NULL, &pool, false);
    if (result != VIREO_OK) { goto done; }
    result = r->ops.borrow(r->thread, r->pool, &r->lease, &r->connection);
    diagnose(e, STAGE(BORROW), result, NULL, NULL, false);
    if (result != VIREO_OK) { goto done; }
    result = read_session(r, digest, now, &value, &report->issue, e);
done:
    released = release_lease(r,
        (result == VIREO_OK || result == VIREO_RESULT_NOT_FOUND) && e->cleanup_result == VIREO_OK ?
            VIREO_MYSQL_POOL_RECYCLE : VIREO_MYSQL_POOL_DISCARD, e);
    if (result == VIREO_OK) { result = released; }
    report->cleanup_pending = pending(r);
    if (result == VIREO_OK) { *out = value; report->valid = true; }
    return finish(saved, result);
}
/* 两种固定锁读，不暴露通用查询；数字视图在下一fetch前全部解析。 */
static vireo_result_t logout_lock(vireo_mysql_user_repository_t *r, bool user, uint64_t id,
    uint64_t values[6], bool *revoked_null, vireo_mysql_user_repository_error_t *e)
{
    const char *sql = user ? "SELECT id FROM users WHERE id=? FOR UPDATE" :
        "SELECT user_id,status,issued_at_ms,expires_at_ms,revoked_at_ms,last_seen_at_ms "
        "FROM sessions WHERE id=? FOR UPDATE";
    stage_t stage = user ? STAGE(LOGOUT_USER) : STAGE(LOGOUT_SESSION);
    const size_t columns = user ? 1 : 6;
    vireo_mysql_statement_limits_t read_limits = {1, columns, 0, 20, 32768};
    vireo_mysql_error_t db = {0}; vireo_mysql_execution_t ex = {0};
    vireo_mysql_parameter_t parameter = U64(id);
    vireo_mysql_fetch_outcome_t fetched;
    memset(values, 0, 6*sizeof(*values)); *revoked_null = false;
    vireo_result_t result = r->ops.prepare(r->thread, r->connection, sql, strlen(sql),
        &read_limits, &r->statement, &db);
    if (result != VIREO_OK) { goto done; }
    result = r->ops.execute(r->thread, r->statement, &parameter, 1, &ex, &db);
    if (result != VIREO_OK) { goto done; }
    if (!ex.has_result) { goto malformed; }
    result = r->ops.fetch(r->thread, r->statement, &fetched, &db);
    if (result != VIREO_OK) { goto done; }
    if (fetched == VIREO_MYSQL_FETCH_DONE) { result = VIREO_RESULT_NOT_FOUND; goto done; }
    if (fetched != VIREO_MYSQL_FETCH_ROW) { goto malformed; }
    for (size_t i = 0; i < columns; ++i) {
        vireo_mysql_cell_view_t cell = {0};
        result = r->ops.column(r->thread, r->statement, i, &cell);
        if (result != VIREO_OK) { goto done; }
        if (!user && i == 4 && cell.is_null) { *revoked_null = true; }
        else if (!unsigned_cell(&cell, &values[i])) { goto malformed; }
    }
    if (values[0] == 0 || (user ? values[0] != id :
        ((values[1] != 1 && values[1] != 2) || values[3] <= values[2] ||
         values[5] < values[2] || values[5] > values[3] ||
         (values[1] == 1 ? !*revoked_null : (*revoked_null || values[4] < values[2]))))) { goto malformed; }
    result = r->ops.fetch(r->thread, r->statement, &fetched, &db);
    if (result != VIREO_OK) { goto done; }
    if (fetched != VIREO_MYSQL_FETCH_DONE) { goto malformed; }
    goto done;
malformed:
    result = VIREO_RESULT_DATABASE;
done:
    diagnose(e, stage, result, &db, NULL, false);
    vireo_result_t closed = close_statement(r, e);
    return result == VIREO_OK ? closed : result;
}
static vireo_result_t validate_logout(const vireo_mysql_logout_input_t *in, uint32_t wait)
{
    if (in == NULL || in->user_id == 0 || in->session_id == 0) { return VIREO_RESULT_INVALID_ARGUMENT; }
    if (wait > VIREO_MYSQL_POOL_WAIT_MS_MAX) { return VIREO_RESULT_RANGE; }
    unsigned char any = 0;
    for (size_t i = 0; i < sizeof(in->request_id); ++i) { any |= in->request_id[i]; }
    return any == 0 ? VIREO_RESULT_INVALID_ARGUMENT : VIREO_OK;
}
vireo_result_t vireo_mysql_user_repository_logout(vireo_mysql_user_repository_t *r,
    const vireo_mysql_logout_input_t *in, uint32_t wait,
    vireo_mysql_logout_report_t *out, vireo_mysql_user_repository_error_t *error)
{
    int saved = errno;
    vireo_mysql_user_repository_error_t local = {0};
    vireo_mysql_user_repository_error_t *e = error != NULL ? error : &local; *e = local;
    if (out != NULL) { *out = (vireo_mysql_logout_report_t){0}; }
    if (!valid(r) || out == NULL) {
        diagnose(e, STAGE(VALIDATE), VIREO_RESULT_INVALID_ARGUMENT, NULL, NULL, false);
        return finish(saved, VIREO_RESULT_INVALID_ARGUMENT);
    }
    out->cleanup_pending = pending(r);
    vireo_result_t result = pending(r) ? VIREO_RESULT_BUSY : validate_logout(in, wait);
    if (result != VIREO_OK) {
        diagnose(e, STAGE(VALIDATE), result, NULL, NULL, false); return finish(saved, result);
    }
    bool transaction_possible = false, replied = false, revoked_null = false, already = false;
    uint64_t values[6] = {0}, audit = 0, revoked = 0;
    vireo_mysql_execution_t ex = {0};
    vireo_mysql_pool_error_t pool = {0}; vireo_mysql_pool_acquisition_t acquired = {0};
    result = r->ops.acquire(r->thread, r->pool, wait, &r->lease, &acquired, &pool);
    diagnose(e, STAGE(ACQUIRE), result, NULL, &pool, false);
    if (result != VIREO_OK) { goto done; }
    result = r->ops.borrow(r->thread, r->pool, &r->lease, &r->connection);
    diagnose(e, STAGE(BORROW), result, NULL, NULL, false);
    if (result != VIREO_OK) { goto done; }
    result = command(r, "SET autocommit=0", NULL, 0, STAGE(BEGIN), false, false, &ex, &replied, e);
    transaction_possible = ex.execution_started;
    if (result != VIREO_OK) { goto done; }
    result = logout_lock(r, true, in->user_id, values, &revoked_null, e);
    if (result == VIREO_RESULT_NOT_FOUND) { out->issue = VIREO_MYSQL_LOGOUT_USER_NOT_FOUND; }
    if (result != VIREO_OK) { goto done; }
    result = logout_lock(r, false, in->session_id, values, &revoked_null, e);
    if (result == VIREO_RESULT_NOT_FOUND) { out->issue = VIREO_MYSQL_LOGOUT_SESSION_NOT_FOUND; }
    if (result != VIREO_OK) { goto done; }
    if (values[0] != in->user_id) {
        out->issue = VIREO_MYSQL_LOGOUT_OWNER_MISMATCH; result = VIREO_RESULT_NOT_FOUND;
        diagnose(e, STAGE(LOGOUT_SESSION), result, NULL, NULL, false); goto done;
    }
    if (in->occurred_at_ms < values[2]) {
        out->issue = VIREO_MYSQL_LOGOUT_TIME_BEFORE_ISSUED; result = VIREO_RESULT_RANGE;
        diagnose(e, STAGE(LOGOUT_SESSION), result, NULL, NULL, false); goto done;
    }
    already = values[1] == 2;
    revoked = already ? values[4] : in->occurred_at_ms;
    if (!already) {
        vireo_mysql_parameter_t u[] = {U64(revoked), U64(in->session_id), U64(in->user_id)};
        result = command(r, "UPDATE sessions SET status=2,revoked_at_ms=? WHERE id=? AND user_id=? AND status=1",
            u, 3, STAGE(SESSION_REVOKE), false, false, &ex, &replied, e);
        if (result == VIREO_OK && ex.affected_rows != 1) {
            result = VIREO_RESULT_DATABASE; diagnose(e, STAGE(SESSION_REVOKE), result, NULL, NULL, false);
        }
        if (result != VIREO_OK) { goto done; }
        vireo_mysql_parameter_t a[] = {
            SPAN(VIREO_MYSQL_PARAMETER_BYTES, in->request_id, sizeof(in->request_id)),
            U64(in->user_id), U64(in->session_id), U64(in->session_id), U64(in->latency_us), U64(in->occurred_at_ms)};
        result = command(r, "INSERT INTO operation_audits(request_id,user_id,session_id,action,target_type,"
            "target_id,target_hash,status,latency_us,detail,occurred_at_ms) VALUES(?,?,?,3,2,?,NULL,0,?,'',?)",
            a, 6, STAGE(AUDIT), true, false, &ex, &replied, e);
        if (result != VIREO_OK) {
            if (e->stage == STAGE(AUDIT) && e->database.stage == VIREO_MYSQL_STAGE_STATEMENT_EXECUTE &&
                e->database.mysql_code == 1062) { out->issue = VIREO_MYSQL_LOGOUT_REQUEST_CONFLICT; }
            goto done;
        }
        audit = ex.insert_id;
    }
    result = command(r, "COMMIT", NULL, 0, STAGE(COMMIT), false, false, &ex, &replied, e);
    if (replied) {
        out->commit = VIREO_MYSQL_LOGOUT_COMMITTED; out->session_id = in->session_id;
        out->audit_id = audit; out->revoked_at_ms = revoked; out->already_revoked = already;
    } else if (ex.execution_started) { out->commit = VIREO_MYSQL_LOGOUT_UNKNOWN; }
done:
    if (result == VIREO_RESULT_DATABASE && out->issue == VIREO_MYSQL_LOGOUT_ISSUE_NONE &&
        e->database.stage == VIREO_MYSQL_STAGE_NONE &&
        (e->stage == STAGE(BEGIN) || e->stage == STAGE(LOGOUT_USER) ||
         e->stage == STAGE(LOGOUT_SESSION) || e->stage == STAGE(SESSION_REVOKE) ||
         e->stage == STAGE(AUDIT) || e->stage == STAGE(COMMIT))) {
        out->issue = VIREO_MYSQL_LOGOUT_UNEXPECTED_RESULT;
    }
    if (transaction_possible && out->commit == VIREO_MYSQL_LOGOUT_NOT_COMMITTED && r->statement == NULL) {
        vireo_result_t rolled = command(r, "ROLLBACK", NULL, 0, STAGE(ROLLBACK), false, true, &ex, &replied, e);
        out->rollback_confirmed = replied;
        if (result == VIREO_OK) { result = rolled; }
    }
    vireo_result_t released = release_lease(r,
        out->commit == VIREO_MYSQL_LOGOUT_COMMITTED || out->rollback_confirmed ?
            VIREO_MYSQL_POOL_RECYCLE : VIREO_MYSQL_POOL_DISCARD, e);
    if (result == VIREO_OK) { result = released; }
    out->cleanup_pending = pending(r);
    return finish(saved, result);
}
vireo_result_t vireo_mysql_user_repository_destroy(vireo_mysql_user_repository_t **owner,
    vireo_mysql_user_repository_error_t *error)
{
    int saved = errno;
    vireo_mysql_user_repository_error_t local = {0};
    vireo_mysql_user_repository_error_t *e = error != NULL ? error : &local; *e = local;
    if (owner == NULL || (*owner != NULL && !valid(*owner))) {
        diagnose(e, STAGE(VALIDATE), VIREO_RESULT_INVALID_ARGUMENT, NULL, NULL, false);
        return finish(saved, VIREO_RESULT_INVALID_ARGUMENT);
    }
    if (*owner == NULL) { return finish(saved, VIREO_OK); }
    vireo_mysql_user_repository_t *r = *owner;
    vireo_result_t result = close_statement(r, e);
    vireo_result_t released = release_lease(r, VIREO_MYSQL_POOL_DISCARD, e);
    if (result == VIREO_OK) { result = released; }
    if (!pending(r)) {
        void (*release_memory)(void *) = r->ops.release_memory;
        memset(r, 0, sizeof(*r)); release_memory(r); *owner = NULL;
    }
    return finish(saved, result);
}


/* 独立失败事件：只写审计表，绝不据输入关联未认证用户或Session。 */
vireo_result_t vireo_mysql_user_repository_append_auth_failure(vireo_mysql_user_repository_t *r,
    vireo_mysql_auth_failure_input_t const *in, vireo_mysql_auth_failure_report_t *out,
    vireo_mysql_user_repository_error_t *error)
{
    int const saved=errno;
    vireo_mysql_user_repository_error_t local={0};
    vireo_mysql_user_repository_error_t *e=error?error:&local; *e=local;
    if (out) *out=(vireo_mysql_auth_failure_report_t){0};
    if (!valid(r) || !in || !out) {
        diagnose(e,STAGE(VALIDATE),VIREO_RESULT_INVALID_ARGUMENT,NULL,NULL,false);
        return finish(saved,VIREO_RESULT_INVALID_ARGUMENT);
    }
    out->cleanup_pending=pending(r);
    if (pending(r)) {
        diagnose(e,STAGE(VALIDATE),VIREO_RESULT_BUSY,NULL,NULL,false);
        return finish(saved,VIREO_RESULT_BUSY);
    }
    unsigned bits=0; for(size_t i=0;i<16;++i) bits|=in->request_id[i];
    bool status=false;
    switch(in->status) {
    case 1001: case 1008: case 1104: case 1105: case 1106:
    case 1901: case 1902: case 1906: case 1907: case 1908: status=true; break;
    default: break;
    }
    if (!bits || in->action<1 || in->action>4 || !status || (in->origin!=1 && in->origin!=2)) {
        diagnose(e,STAGE(VALIDATE),VIREO_RESULT_INVALID_ARGUMENT,NULL,NULL,false);
        return finish(saved,VIREO_RESULT_INVALID_ARGUMENT);
    }
    bool transaction=false, replied=false, rolled_back=false;
    uint64_t audit=0; vireo_mysql_execution_t ex={0};
    vireo_mysql_pool_error_t pool={0}; vireo_mysql_pool_acquisition_t acquired={0};
    vireo_result_t result=r->ops.acquire(r->thread,r->pool,0,&r->lease,&acquired,&pool);
    diagnose(e,STAGE(ACQUIRE),result,NULL,&pool,false);
    if(result!=VIREO_OK) goto done;
    result=r->ops.borrow(r->thread,r->pool,&r->lease,&r->connection);
    diagnose(e,STAGE(BORROW),result,NULL,NULL,false);
    if(result!=VIREO_OK) goto done;
    result=command(r,"SET autocommit=0",NULL,0,STAGE(BEGIN),false,false,&ex,&replied,e);
    transaction=ex.execution_started;
    if(result!=VIREO_OK) goto done;
    char const *detail=in->origin==1?"source=reactor":"source=worker";
    vireo_mysql_parameter_t a[]={SPAN(VIREO_MYSQL_PARAMETER_BYTES,in->request_id,16),
        U64(in->action),U64(in->status),U64(in->latency_us),
        SPAN(VIREO_MYSQL_PARAMETER_BYTES,detail,strlen(detail)),U64(in->occurred_at_ms)};
    result=command(r,"INSERT INTO operation_audits(request_id,user_id,session_id,action,target_type,target_id,"
        "target_hash,status,latency_us,detail,occurred_at_ms) VALUES(?,NULL,NULL,?,0,NULL,NULL,?,?,?,?)",
        a,6,STAGE(AUDIT),true,false,&ex,&replied,e);
    if(result!=VIREO_OK) goto done;
    audit=ex.insert_id;
    result=command(r,"COMMIT",NULL,0,STAGE(COMMIT),false,false,&ex,&replied,e);
    if(replied) { out->commit=VIREO_MYSQL_AUTH_FAILURE_COMMITTED; out->audit_id=audit; }
    else if(ex.execution_started) out->commit=VIREO_MYSQL_AUTH_FAILURE_UNKNOWN;
done:
    if(transaction && out->commit==VIREO_MYSQL_AUTH_FAILURE_NOT_COMMITTED && !r->statement) {
        vireo_result_t const rolled=command(r,"ROLLBACK",NULL,0,STAGE(ROLLBACK),false,true,&ex,&replied,e);
        rolled_back=replied; if(result==VIREO_OK) result=rolled;
    }
    vireo_result_t const released=release_lease(r,
        out->commit==VIREO_MYSQL_AUTH_FAILURE_COMMITTED || rolled_back?VIREO_MYSQL_POOL_RECYCLE:VIREO_MYSQL_POOL_DISCARD,e);
    if(result==VIREO_OK) result=released;
    out->cleanup_pending=pending(r);
    return finish(saved,result);
}
