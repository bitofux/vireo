/*
 * PROJECT : VIREO
 * FILE    : mysql_node_repository.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-21
 * BRIEF   : 共享锁序、锁后UTC与完整清理后发布的节点读取。
 * IMPLEMENTATION : 不访问其他模块私有布局；pool在租借时验证guard/runtime。
 */
#define _POSIX_C_SOURCE 200809L
#include "mysql_node_repository_internal.h"
#include <vireo/persistence/mysql_node_mkdir_receipt.h>
#include <vireo/base/checked.h>
#include <vireo/persistence/mysql_schema.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#define STAGE(n) VIREO_MYSQL_NODE_STAGE_##n
#define U64(n) ((vireo_mysql_parameter_t){.kind=VIREO_MYSQL_PARAMETER_U64,.value.u64=(n)})
struct vireo_mysql_node_repository {
    vireo_mysql_thread_t *thread; /**< caller保活的guard，不窥探其opaque布局。 */
    vireo_mysql_pool_t *pool; /**< 管理方保活至worker退出。 */
    pthread_t owner; /**< 仅创建OS线程可调用，避免向其他线程移动guard。 */
    vireo_mysql_node_ops_t ops; /**< 对象独立固定调用边界。 */
    vireo_mysql_lease_t lease; /**< 唯一租约，非OK也可能仍有owner。 */
    vireo_mysql_connection_t *connection; /**< lease内短借，不独立销毁。 */
    vireo_mysql_statement_t *statement; /**< 必须先消费再归还lease。 */
};
static int utc_native(struct timespec *out) { return clock_gettime(CLOCK_REALTIME, out); }
const vireo_mysql_node_ops_t vireo_mysql_node_native_ops = {
    malloc, free, vireo_mysql_pool_acquire, vireo_mysql_pool_borrow, vireo_mysql_pool_release,
    vireo_mysql_statement_prepare, vireo_mysql_statement_execute, vireo_mysql_statement_fetch,
    vireo_mysql_statement_column, vireo_mysql_statement_destroy, utc_native
};
static bool valid(const vireo_mysql_node_repository_t *r)
{ return r != NULL && pthread_equal(r->owner, pthread_self()) != 0; }
static bool pending(const vireo_mysql_node_repository_t *r)
{ return r->statement != NULL || r->lease.owner != NULL; }
static vireo_result_t finish(int saved, vireo_result_t result) { errno = saved; return result; }

/** @brief 保存首因及首清理故障；仅借数值诊断，不保存输入/SQL或对象指针。
 * @param[in,out] e 独占诊断，首因与首清理槽只写一次。
 * @param[in] stage 当前调用失败阶段。
 * @param[in] rc 原结果，OK不修改诊断。
 * @param[in] db 可NULL statement数值诊断，短借后按值复制。
 * @param[in] pool 可NULL pool数值诊断，短借后按值复制。
 * @param[in] cleanup 是否属于清理操作，首清理错误不覆盖已有首因。
 * @note 无I/O/分配，不保存借用。
 */
static void diagnose(vireo_mysql_node_error_t *e, vireo_mysql_node_stage_t stage,
    vireo_result_t rc, const vireo_mysql_error_t *db, const vireo_mysql_pool_error_t *pool, bool cleanup)
{
    if (rc == VIREO_OK) { return; }
    if (cleanup && e->cleanup_result == VIREO_OK) {
        e->cleanup_result = rc; e->cleanup_stage = stage;
        if (db != NULL) { e->cleanup_database = *db; }
        if (pool != NULL) { e->cleanup_pool = *pool; }
    }
    if (e->stage == STAGE(NONE)) {
        e->stage = stage;
        if (db != NULL) { e->database = *db; }
        if (pool != NULL) { e->pool = *pool; }
    }
}
/** @brief 先消费子owner；非OK也以实际owner判断剩余责任。
 * @param[in,out] r 创建worker独占repo，statement可空。
 * @param[in,out] e 独占数值诊断，记录首清理失败。
 * @return 空owner为OK，否则返回原close结果，可能仍持有statement。
 * @note 不归还lease，不把语句关闭误作事务结束。
 */
static vireo_result_t close_statement(vireo_mysql_node_repository_t *r, vireo_mysql_node_error_t *e)
{
    if (r->statement == NULL) { return VIREO_OK; }
    vireo_mysql_error_t db = {0};
    vireo_result_t rc = r->ops.close(r->thread, &r->statement, &db);
    diagnose(e, STAGE(STATEMENT_CLOSE), rc, &db, NULL, true);
    return rc;
}
/** @brief 固定语句prepare/execute；执行进度即使失败也交还caller，不关闭子owner。
 * @param[in,out] r 创建worker独占repo，connection在有效lease内且无statement。
 * @param[in] sql 内部可信NUL终止模板，调用期短借。
 * @param[in] p 参数短借，n为0允许NULL。
 * @param[in] n 参数条数，固定模板最多4。
 * @param[in] stage 失败阶段。
 * @param[out] execution 每次重置，即使非OK也保执行进度。
 * @param[in,out] e 首因/首清理独立诊断。
 * @param[in] cleanup 是否为回滚等清理调用。
 * @return prepare或execute结果，不隐式回滚或消费owner。
 * @note 可能阻塞；无重试；返回后caller必须close statement。
 */
static vireo_result_t execute(vireo_mysql_node_repository_t *r, const char *sql,
    const vireo_mysql_parameter_t *p, size_t n, vireo_mysql_node_stage_t stage,
    vireo_mysql_execution_t *execution, vireo_mysql_node_error_t *e, bool cleanup)
{
    static const vireo_mysql_statement_limits_t limits = {4, 11, 0, 255, 32768};
    *execution = (vireo_mysql_execution_t){0};
    vireo_mysql_error_t db = {0};
    vireo_result_t rc = r->ops.prepare(r->thread, r->connection, sql, strlen(sql), &limits, &r->statement, &db);
    if (rc == VIREO_RESULT_RANGE) { rc = VIREO_RESULT_DATABASE; }
    diagnose(e, stage, rc, &db, NULL, cleanup);
    if (rc == VIREO_OK) {
        rc = r->ops.execute(r->thread, r->statement, p, n, execution, &db);
        if (rc == VIREO_RESULT_RANGE) { rc = VIREO_RESULT_DATABASE; }
        diagnose(e, stage, rc, &db, NULL, cleanup);
    }
    return rc;
}
/** @brief 受检解析完整十进制u64；NULL/空/符号/溢出不发布输出。
 * @param[in] c 必需存活列视图，data在length内有效。
 * @param[out] out 必需独占值，失败保持，成功写入。
 * @retval true 完整0..UINT64_MAX十进制，无符号或空白。
 * @retval false NULL/长度/字节/溢出拒绝。
 * @note 不保存视图，不读取errno；MAX-minus避免乘加回绕。
 */
static bool number(const vireo_mysql_cell_view_t *c, uint64_t *out)
{
    if (c->is_null || c->data == NULL || c->length == 0 || c->length > 20) { return false; }
    uint64_t v = 0;
    for (size_t i = 0; i < c->length; ++i) {
        if (c->data[i] < '0' || c->data[i] > '9') { return false; }
        uint64_t digit = (uint64_t)(c->data[i] - '0');
        if (v > (UINT64_MAX - digit) / 10) { return false; }
        v = v * 10 + digit;
    }
    *out = v; return true;
}
/** @brief 取一个有界行的全部短借；caller必须在下一fetch/close前消费。
 * @param[in,out] r 当前worker独占活语句。
 * @param[in] count 固定2/5/7/11列，不接受外部任意查询。
 * @param[out] cells 至少count项的独占空间，仅found为true且OK时可读。
 * @param[out] found 每次清false，完整ROW才置true。
 * @param[in,out] e 失败数值诊断。
 * @return SQL/形状结果；列截断/缺列转换DATABASE，其他资源错误沿底层。
 * @note 视图由statement持有，不转移owner，不关闭语句。
 */
static vireo_result_t read_row(vireo_mysql_node_repository_t *r, size_t count,
    vireo_mysql_cell_view_t *cells, bool *found, vireo_mysql_node_error_t *e)
{
    vireo_mysql_error_t db = {0}; vireo_mysql_fetch_outcome_t outcome;
    *found = false;
    vireo_result_t rc = r->ops.fetch(r->thread, r->statement, &outcome, &db);
    if (rc == VIREO_OK && outcome == VIREO_MYSQL_FETCH_ROW) {
        *found = true;
        for (size_t i = 0; i < count && rc == VIREO_OK; ++i) {
            rc = r->ops.column(r->thread, r->statement, i, cells + i);
        }
    } else if (rc == VIREO_OK && outcome != VIREO_MYSQL_FETCH_DONE) { rc = VIREO_RESULT_DATABASE; }
    if (rc == VIREO_RESULT_RANGE) { rc = VIREO_RESULT_DATABASE; }
    diagnose(e, count == 2 ? STAGE(USER) : (count == 7 ? STAGE(SESSION) : (count == 5 ? STAGE(NAME_CHECK) : STAGE(NODE))), rc, &db, NULL, false);
    return rc;
}
/** @brief 第二次fetch必须结束；不通过LIMIT遮蔽重复行或坏schema。
 * @param[in,out] r 当前worker独占活语句，第一行已完全复制/解析。
 * @param[in] stage 固定SQL拥有阶段。
 * @param[in,out] e 去敏失败诊断。
 * @return DONE为OK，额外行为DATABASE，否则沿fetch错误。
 * @note 使上一行全部view失效，不得在返回后再访问其data。
 */
static vireo_result_t unique_end(vireo_mysql_node_repository_t *r,
    vireo_mysql_node_stage_t stage, vireo_mysql_node_error_t *e)
{
    vireo_mysql_fetch_outcome_t outcome; vireo_mysql_error_t db = {0};
    vireo_result_t rc = r->ops.fetch(r->thread, r->statement, &outcome, &db);
    if (rc == VIREO_RESULT_RANGE || (rc == VIREO_OK && outcome != VIREO_MYSQL_FETCH_DONE)) { rc = VIREO_RESULT_DATABASE; }
    diagnose(e, stage, rc, &db, NULL, false); return rc;
}
/** @brief 固定user锁读的形状/状态；只短借输入，错误由外层保留并清理。
 * @param[in,out] r 创建worker独占repo，事务已开始，无活statement。
 * @param[in] id 非零可信user ID。
 * @param[in,out] report 身份拒绝时写内部issue。
 * @param[in,out] e 去敏首因/首清理诊断。
 * @return OK为active用户行已锁，NOT_FOUND为领域拒绝，其他沿资源或形状错误。
 * @note 语句关闭不释放锁，锁仍归事务；本层不重试。
 */
static vireo_result_t lock_user(vireo_mysql_node_repository_t *r, uint64_t id,
    vireo_mysql_node_report_t *report, vireo_mysql_node_error_t *e)
{
    vireo_mysql_execution_t ex; vireo_mysql_parameter_t p = U64(id);
    vireo_result_t rc = execute(r, "SELECT id,status FROM users WHERE id=? FOR SHARE", &p, 1, STAGE(USER), &ex, e, false);
    vireo_mysql_cell_view_t cells[2]; bool found = false; uint64_t v[2];
    if (rc == VIREO_OK && !ex.has_result) { rc = VIREO_RESULT_DATABASE; }
    if (rc == VIREO_OK) { rc = read_row(r, 2, cells, &found, e); }
    if (rc == VIREO_OK && found) {
        if (!number(cells, v) || !number(cells + 1, v + 1) || v[0] != id || (v[1] != 1 && v[1] != 2)) {
            rc = VIREO_RESULT_DATABASE;
        } else { rc = unique_end(r, STAGE(USER), e); }
    }
    if (rc == VIREO_OK && (!found || v[1] != 1)) {
        report->issue = VIREO_MYSQL_NODE_AUTH_REJECTED; rc = VIREO_RESULT_NOT_FOUND;
    }
    diagnose(e, STAGE(USER), rc, NULL, NULL, false);
    vireo_result_t closed = close_statement(r, e); return rc == VIREO_OK ? closed : rc;
}
/** @brief user锁之后再核Session，复制issued/expiry；时效留到node锁后采样。
 * @param[in,out] r 当前worker独占已持user锁事务。
 * @param[in] actor 可信非零user/session值，调用期短借。
 * @param[out] issued 成功才写签发UTC毫秒。
 * @param[out] expires 成功才写严格大于issued的到期UTC毫秒。
 * @param[in,out] report 身份缺失/属主不符/撤销时写AUTH_REJECTED。
 * @param[in,out] e 首因/首清理数值诊断。
 * @return OK为Session可进行最终时效判断；其他沿领域/形状/资源失败。
 * @note 不刷新时间或续期；先验完整行形状再判断领域状态。
 */
static vireo_result_t lock_session(vireo_mysql_node_repository_t *r, const vireo_mysql_node_actor_t *actor,
    uint64_t *issued, uint64_t *expires, vireo_mysql_node_report_t *report, vireo_mysql_node_error_t *e)
{
    static const char sql[] = "SELECT id,user_id,status,issued_at_ms,expires_at_ms,revoked_at_ms,last_seen_at_ms "
        "FROM sessions WHERE id=? FOR SHARE";
    vireo_mysql_execution_t ex; vireo_mysql_parameter_t p = U64(actor->session_id);
    vireo_result_t rc = execute(r, sql, &p, 1, STAGE(SESSION), &ex, e, false);
    vireo_mysql_cell_view_t c[7]; bool found = false; uint64_t v[7] = {0};
    if (rc == VIREO_OK && !ex.has_result) { rc = VIREO_RESULT_DATABASE; }
    if (rc == VIREO_OK) { rc = read_row(r, 7, c, &found, e); }
    if (rc == VIREO_OK && found) {
        for (size_t i = 0; i < 7; ++i) {
            if (i == 5 && c[i].is_null) { continue; }
            if (!number(c + i, v + i)) { rc = VIREO_RESULT_DATABASE; break; }
        }
        if (rc == VIREO_OK && (v[0] != actor->session_id || v[1] == 0 ||
            (v[2] != 1 && v[2] != 2) || v[4] <= v[3] || v[6] < v[3] || v[6] > v[4] ||
            (v[2] == 1 ? !c[5].is_null : (c[5].is_null || v[5] < v[3])))) { rc = VIREO_RESULT_DATABASE; }
        if (rc == VIREO_OK) { rc = unique_end(r, STAGE(SESSION), e); }
    }
    if (rc == VIREO_OK && (!found || v[1] != actor->user_id || v[2] != 1)) {
        report->issue = VIREO_MYSQL_NODE_AUTH_REJECTED; rc = VIREO_RESULT_NOT_FOUND;
    }
    if (rc == VIREO_OK) { *issued = v[3]; *expires = v[4]; }
    diagnose(e, STAGE(SESSION), rc, NULL, NULL, false);
    vireo_result_t closed = close_statement(r, e); return rc == VIREO_OK ? closed : rc;
}
/** @brief 将短借行复制为独立ACTIVE节点；只执行DDL形状约束，不解释UTF8或CAS。
 * @param[in] c 至少11项、在当前ROW有效的只读短借。
 * @param[in] owner 必需匹配的非零可信owner。
 * @param[in] id 非零则须匹配node ID，0不要求特定ID，调用方另核root或parent谓词。
 * @param[in,out] v 初值全零的独立临时值；失败可能部分修改，严禁发布。
 * @retval true 已完整复制并验证类型、长度和NULL关系。
 * @retval false 固定行不变量不符。
 * @note 不分配、不保存视图；必须在下一fetch前调用。
 */
static bool node_value(const vireo_mysql_cell_view_t c[11], uint64_t owner, uint64_t id,
    vireo_mysql_node_value_t *v)
{
    uint64_t kind, state;
    if (!number(c, &v->id) || v->id == 0 || (id != 0 && v->id != id) ||
        !number(c + 1, &v->owner_id) || v->owner_id != owner ||
        !number(c + 4, &kind) || (kind != 1 && kind != 2) ||
        !number(c + 5, &state) || state != 2 || !number(c + 7, &v->size) ||
        !number(c + 8, &v->created_at_ms) || !number(c + 9, &v->updated_at_ms) ||
        v->updated_at_ms < v->created_at_ms || !c[10].is_null || c[3].is_null ||
        c[3].length > VIREO_MYSQL_NODE_NAME_CAPACITY || (c[3].length != 0 && c[3].data == NULL)) { return false; }
    v->has_parent = !c[2].is_null;
    if (v->has_parent && (!number(c + 2, &v->parent_id) || v->parent_id == 0)) { return false; }
    v->kind = (vireo_mysql_node_kind_t)kind; v->name_length = c[3].length;
    v->has_object_hash = !c[6].is_null;
    if (kind == 1 ? (v->has_object_hash || v->size != 0) :
        (!v->has_object_hash || c[6].length != 32 || c[6].data == NULL)) { return false; }
    if (!v->has_parent) {
        if (kind != 1 || v->name_length != 0) { return false; }
    } else {
        if (v->name_length == 0 || (v->name_length == 1 && c[3].data[0] == '.') ||
            (v->name_length == 2 && c[3].data[0] == '.' && c[3].data[1] == '.')) { return false; }
        for (size_t i = 0; i < v->name_length; ++i) {
            if (c[3].data[i] == 0 || c[3].data[i] == '/') { return false; }
        }
    }
    if (v->name_length != 0) { memcpy(v->name, c[3].data, v->name_length); }
    if (v->has_object_hash) { memcpy(v->object_hash, c[6].data, 32); }
    return true;
}
/** @brief 精确owner谓词锁读，零id仅内部表示专用root操作；不查别人的节点。
 * @param[in,out] r 当前worker独占已持user/session锁的事务。
 * @param[in] owner 非零可信user ID，所有SQL固定包含该谓词。
 * @param[in] id 内部0代表get_root，其他为stat非零ID。
 * @param[in,out] value 零初始化独立临时值，失败可部分修改，不直接发布。
 * @param[out] found 第一条完整行存在时true，失败值不供业务使用。
 * @param[in,out] e 去敏首因/清理错误。
 * @return SQL及形状结果，未命中本层仍OK，留最终UTC后判定领域结果。
 * @note statement关闭，事务锁保持；有界两次fetch验证唯一性。
 */
static vireo_result_t lock_node(vireo_mysql_node_repository_t *r, uint64_t owner, uint64_t id,
    vireo_mysql_node_value_t *value, bool *found, vireo_mysql_node_error_t *e)
{
    static const char root[] = "SELECT id,owner_id,parent_id,name,node_type,state,object_hash,size,"
        "created_at_ms,updated_at_ms,deleted_at_ms FROM file_nodes WHERE owner_id=? AND parent_id IS NULL AND state=2 FOR SHARE";
    static const char stat[] = "SELECT id,owner_id,parent_id,name,node_type,state,object_hash,size,"
        "created_at_ms,updated_at_ms,deleted_at_ms FROM file_nodes WHERE owner_id=? AND id=? AND state=2 FOR SHARE";
    vireo_mysql_parameter_t p[2] = {U64(owner), U64(id)}; vireo_mysql_execution_t ex;
    vireo_result_t rc = execute(r, id == 0 ? root : stat, p, id == 0 ? 1 : 2, STAGE(NODE), &ex, e, false);
    vireo_mysql_cell_view_t cells[11];
    if (rc == VIREO_OK && !ex.has_result) { rc = VIREO_RESULT_DATABASE; }
    if (rc == VIREO_OK) { rc = read_row(r, 11, cells, found, e); }
    if (rc == VIREO_OK && *found) {
        if (!node_value(cells, owner, id, value) || (id == 0 && value->has_parent)) { rc = VIREO_RESULT_DATABASE; }
        else { rc = unique_end(r, STAGE(NODE), e); }
    }
    diagnose(e, STAGE(NODE), rc, NULL, NULL, false);
    vireo_result_t closed = close_statement(r, e); return rc == VIREO_OK ? closed : rc;
}
/** @brief 持有事务锁时采UTC，用于读取最终检查或写入前后检查；失败不写now，原errno单独留数值诊断。
 * @param[in,out] r 当前worker独占、持有本次相关事务锁。
 * @param[out] now 独占UTC epoch毫秒，仅成功写入。
 * @param[in,out] e UTC失败数值诊断，原生-1时保存system_errno。
 * @return IO为原生失败，INTERNAL为非法返回/timespec，OVERFLOW为换算不可表示。
 * @note 不校正墙钟回拨；负秒或非法纳秒拒绝，除法向下取整。
 */
static vireo_result_t capture_utc(vireo_mysql_node_repository_t *r, uint64_t *now, vireo_mysql_node_error_t *e)
{
    struct timespec ts = {0}; int sampled = r->ops.utc(&ts); uint64_t seconds;
    vireo_result_t rc = VIREO_RESULT_INTERNAL;
    if (sampled == -1) { e->system_errno = errno; rc = VIREO_RESULT_IO; }
    else if (sampled == 0 && ts.tv_sec >= 0 && ts.tv_nsec >= 0 && ts.tv_nsec < 1000000000L) {
        rc = (uintmax_t)ts.tv_sec > UINT64_MAX ? VIREO_RESULT_OVERFLOW :
            vireo_checked_u64_mul((uint64_t)ts.tv_sec, UINT64_C(1000), &seconds);
        if (rc == VIREO_OK) { rc = vireo_checked_u64_add(seconds, (uint64_t)ts.tv_nsec / UINT64_C(1000000), now); }
    }
    diagnose(e, STAGE(UTC), rc, NULL, NULL, false); return rc;
}
/** @brief 关闭子owner后终止可能存在的事务并归还租约；失败不丢owner。
 * @param[in,out] r 当前worker唯一repo，子owner可部分存在。
 * @param[in] transaction BEGIN已进入execute，须尝试显式ROLLBACK。
 * @param[in] rc 原业务结果，非OK优先保留。
 * @param[in,out] report 保存回滚确认与最终残留，清理不发布node。
 * @param[in,out] e 首因与首清理独立保存。
 * @return 原非OK或首次清理错误，全部成功才OK。
 * @note 有statement不能还lease；状态不确定或清理故障一律DISCARD；不重试业务。
 */
static vireo_result_t cleanup(vireo_mysql_node_repository_t *r, bool transaction,
    vireo_result_t rc, vireo_mysql_node_report_t *report, vireo_mysql_node_error_t *e)
{
    vireo_result_t next = close_statement(r, e);
    if (rc == VIREO_OK) { rc = next; }
    if (transaction && r->statement == NULL && r->connection != NULL) {
        vireo_mysql_execution_t ex;
        next = execute(r, "ROLLBACK", NULL, 0, STAGE(ROLLBACK), &ex, e, true);
        if (next == VIREO_OK && ex.has_result) {
            next = VIREO_RESULT_DATABASE; diagnose(e, STAGE(ROLLBACK), next, NULL, NULL, true);
        }
        report->rollback_confirmed = next == VIREO_OK;
        if (rc == VIREO_OK) { rc = next; }
        next = close_statement(r, e);
        if (rc == VIREO_OK) { rc = next; }
    }
    if (r->statement == NULL && r->lease.owner != NULL) {
        bool healthy = report->rollback_confirmed && e->cleanup_result == VIREO_OK &&
            (rc == VIREO_OK || rc == VIREO_RESULT_NOT_FOUND);
        vireo_mysql_pool_error_t pe = {0}; vireo_mysql_pool_release_t released = {0};
        next = r->ops.release(r->thread, r->pool, &r->lease,
            healthy ? VIREO_MYSQL_POOL_RECYCLE : VIREO_MYSQL_POOL_DISCARD, &released, &pe);
        if (released.released) { r->connection = NULL; }
        diagnose(e, STAGE(RELEASE), next, NULL, &pe, true);
        if (rc == VIREO_OK) { rc = next; }
    }
    report->cleanup_pending = pending(r); return rc;
}

vireo_result_t vireo_mysql_node_repository_create_with_ops(vireo_mysql_thread_t *thread,
    vireo_mysql_pool_t *pool, vireo_mysql_node_repository_t **out, vireo_mysql_node_error_t *error,
    const vireo_mysql_node_ops_t *ops)
{
    int saved = errno; vireo_mysql_node_error_t local = {0};
    vireo_mysql_node_error_t *e = error != NULL ? error : &local; *e = local;
    if (thread == NULL || pool == NULL || out == NULL || *out != NULL || ops == NULL ||
        ops->allocate == NULL || ops->free_memory == NULL || ops->acquire == NULL ||
        ops->borrow == NULL || ops->release == NULL || ops->prepare == NULL || ops->execute == NULL ||
        ops->fetch == NULL || ops->column == NULL || ops->close == NULL || ops->utc == NULL) {
        e->stage = STAGE(VALIDATE); return finish(saved, VIREO_RESULT_INVALID_ARGUMENT);
    }
    vireo_mysql_node_repository_t *r = ops->allocate(sizeof(*r));
    if (r == NULL) { e->stage = STAGE(ALLOCATE); return finish(saved, VIREO_RESULT_NO_MEMORY); }
    *r = (vireo_mysql_node_repository_t){.thread=thread, .pool=pool, .owner=pthread_self(), .ops=*ops};
    *out = r; return finish(saved, VIREO_OK);
}
vireo_result_t vireo_mysql_node_repository_create(vireo_mysql_thread_t *thread,
    vireo_mysql_pool_t *pool, vireo_mysql_node_repository_t **out, vireo_mysql_node_error_t *error)
{ return vireo_mysql_node_repository_create_with_ops(thread, pool, out, error, &vireo_mysql_node_native_ops); }

/** @brief 两种公开读取共享资源闭环；仅完整成功发布独立值，输入失败也清主要输出。
 * @param[in,out] r 同创建worker独占repo。
 * @param[in] actor 可信持久user/session，短借至返回。
 * @param[in] id stat非零节点ID，root模式为0。
 * @param[in] root 是否专用根读取，内部唯一模式选择。
 * @param[in] timeout 池等待毫秒0..60000，不是SQL硬期限。
 * @param[out] out 独立节点，先全清零，仅整个调用OK发布。
 * @param[out] report 必需独立报告，非OK仍检查残留责任。
 * @param[out] error 可NULL独立去敏诊断，每次重置。
 * @return 公共合同规定的资源、领域或形状结果。
 * @note 保存并恢复errno，拒绝错OS线程；无重试、权限缓存或wire编码。
 */
static vireo_result_t read_node(vireo_mysql_node_repository_t *r, const vireo_mysql_node_actor_t *actor,
    uint64_t id, bool root, uint32_t timeout, vireo_mysql_node_value_t *out,
    vireo_mysql_node_report_t *report, vireo_mysql_node_error_t *error)
{
    int saved = errno; vireo_mysql_node_error_t local = {0};
    vireo_mysql_node_error_t *e = error != NULL ? error : &local; *e = local;
    if (out != NULL) { memset(out, 0, sizeof(*out)); }
    if (report != NULL) { *report = (vireo_mysql_node_report_t){0}; }
    if (!valid(r) || out == NULL || report == NULL) {
        e->stage = STAGE(VALIDATE); return finish(saved, VIREO_RESULT_INVALID_ARGUMENT);
    }
    report->cleanup_pending = pending(r);
    vireo_result_t rc = pending(r) ? VIREO_RESULT_BUSY :
        (actor == NULL || actor->user_id == 0 || actor->session_id == 0 || (!root && id == 0) ?
         VIREO_RESULT_INVALID_ARGUMENT : (timeout > VIREO_MYSQL_POOL_WAIT_MS_MAX ? VIREO_RESULT_RANGE : VIREO_OK));
    if (rc != VIREO_OK) { e->stage = STAGE(VALIDATE); return finish(saved, rc); }
    vireo_mysql_pool_acquisition_t acquired = {0}; vireo_mysql_pool_error_t pe = {0};
    bool transaction = false, found = false; vireo_mysql_node_value_t value = {0};
    uint64_t issued = 0, expires = 0, now = 0; vireo_mysql_execution_t ex;
    rc = r->ops.acquire(r->thread, r->pool, timeout, &r->lease, &acquired, &pe);
    diagnose(e, STAGE(ACQUIRE), rc, NULL, &pe, false);
    if (rc != VIREO_OK) { goto done; }
    rc = r->ops.borrow(r->thread, r->pool, &r->lease, &r->connection);
    diagnose(e, STAGE(BORROW), rc, NULL, NULL, false);
    if (rc != VIREO_OK) { goto done; }
    rc = execute(r, "SET autocommit=0", NULL, 0, STAGE(BEGIN), &ex, e, false);
    transaction = ex.execution_started;
    if (rc == VIREO_OK && ex.has_result) { rc = VIREO_RESULT_DATABASE; diagnose(e, STAGE(BEGIN), rc, NULL, NULL, false); }
    { vireo_result_t closed = close_statement(r, e); if (rc == VIREO_OK) { rc = closed; } }
    if (rc != VIREO_OK) { goto done; }
    rc = lock_user(r, actor->user_id, report, e);
    if (rc != VIREO_OK) { goto done; }
    rc = lock_session(r, actor, &issued, &expires, report, e);
    if (rc != VIREO_OK) { goto done; }
    rc = lock_node(r, actor->user_id, id, &value, &found, e);
    if (rc != VIREO_OK) { goto done; }
    rc = capture_utc(r, &now, e);
    if (rc != VIREO_OK) { goto done; }
    if (now < issued || now >= expires) {
        report->issue = VIREO_MYSQL_NODE_AUTH_REJECTED; rc = VIREO_RESULT_NOT_FOUND;
        diagnose(e, STAGE(SESSION), rc, NULL, NULL, false);
    } else if (!found) {
        report->issue = root ? VIREO_MYSQL_NODE_ROOT_INVARIANT : VIREO_MYSQL_NODE_NOT_FOUND;
        rc = root ? VIREO_RESULT_DATABASE : VIREO_RESULT_NOT_FOUND;
        diagnose(e, STAGE(NODE), rc, NULL, NULL, false);
    }
done:
    if (rc == VIREO_RESULT_DATABASE && report->issue == VIREO_MYSQL_NODE_ISSUE_NONE &&
        (e->stage == STAGE(USER) || e->stage == STAGE(SESSION) || e->stage == STAGE(NODE)) &&
        e->database.mysql_code == 0) { report->issue = VIREO_MYSQL_NODE_UNEXPECTED_RESULT; }
    rc = cleanup(r, transaction, rc, report, e);
    if (rc == VIREO_OK) { *out = value; report->found = true; }
    return finish(saved, rc);
}
vireo_result_t vireo_mysql_node_repository_get_root(vireo_mysql_node_repository_t *r,
    const vireo_mysql_node_actor_t *actor, uint32_t timeout, vireo_mysql_node_value_t *out,
    vireo_mysql_node_report_t *report, vireo_mysql_node_error_t *error)
{ return read_node(r, actor, 0, true, timeout, out, report, error); }
vireo_result_t vireo_mysql_node_repository_stat(vireo_mysql_node_repository_t *r,
    const vireo_mysql_node_actor_t *actor, uint64_t id, uint32_t timeout, vireo_mysql_node_value_t *out,
    vireo_mysql_node_report_t *report, vireo_mysql_node_error_t *error)
{ return read_node(r, actor, id, false, timeout, out, report, error); }

/**
 * @brief 在已锁父目录下取得一页及lookahead，所有SQL视图当行内消费
 *
 * @param[in,out] r
 *     同worker事务owner，已按user/session/parent锁读，无活statement。
 * @param[in] owner
 *     可信非零属主，固定SQL谓词仍再次限制owner。
 * @param[in] q
 *     已验证目录ID与1..64页限；after_id为严格下界。
 * @param[in,out] page
 *     本次调用拥有的全零固定暂存，失败内容不可发布。
 * @param[in,out] e
 *     首因/首清理诊断，语句关闭失败也保留剩余owner。
 *
 * @return SQL/行形状结果，完整读至DONE并关闭语句才OK。
 *
 * @note 多读项也完整验证；不把lookahead ID当续页位置。LIMIT约束结果，
 *     不约束InnoDB实际扫描、next-key/gap锁或等待；关闭语句不释放事务锁。
 */
static vireo_result_t lock_children(vireo_mysql_node_repository_t *r, uint64_t owner,
    const vireo_mysql_node_list_query_t *q, vireo_mysql_node_page_t *page,
    vireo_mysql_node_error_t *e)
{
    static const char sql[] = "SELECT id,owner_id,parent_id,name,node_type,state,object_hash,size,"
        "created_at_ms,updated_at_ms,deleted_at_ms FROM file_nodes "
        "WHERE owner_id=? AND parent_id=? AND state=2 AND id>? ORDER BY id ASC LIMIT ? FOR SHARE";
    vireo_mysql_parameter_t p[4] = {U64(owner), U64(q->directory_id), U64(q->after_id),
        U64((uint64_t)q->page_size + UINT64_C(1))};
    vireo_mysql_execution_t ex;
    vireo_result_t rc = execute(r, sql, p, 4, STAGE(NODE), &ex, e, false);
    if (rc == VIREO_OK && !ex.has_result) { rc = VIREO_RESULT_DATABASE; }
    size_t fetched = 0;
    uint64_t previous = q->after_id;
    while (rc == VIREO_OK) {
        vireo_mysql_cell_view_t cells[11];
        bool found = false;
        rc = read_row(r, 11, cells, &found, e);
        if (rc != VIREO_OK || !found) { break; }
        vireo_mysql_node_value_t v = {0};
        if (fetched >= q->page_size + 1 || !node_value(cells, owner, 0, &v) ||
            !v.has_parent || v.parent_id != q->directory_id || v.id <= previous) {
            rc = VIREO_RESULT_DATABASE;
            break;
        }
        previous = v.id;
        if (fetched < q->page_size) { page->nodes[page->count++] = v; }
        else { page->has_more = true; }
        ++fetched;
    }
    if (rc == VIREO_OK && page->has_more) { page->next_after_id = page->nodes[page->count - 1].id; }
    diagnose(e, STAGE(NODE), rc, NULL, NULL, false);
    vireo_result_t closed = close_statement(r, e);
    return rc == VIREO_OK ? closed : rc;
}

/* 页暂存与事务资源分开拥有：即使资源清理失败留在repo，暂存也本次释放。
 * 最终UTC在parent/children所有锁读后；缺父/非目录同样先判Session时间。 */
vireo_result_t vireo_mysql_node_repository_list_children(vireo_mysql_node_repository_t *r,
    const vireo_mysql_node_actor_t *actor, const vireo_mysql_node_list_query_t *query,
    uint32_t timeout, vireo_mysql_node_page_t *out, vireo_mysql_node_report_t *report,
    vireo_mysql_node_error_t *error)
{
    int saved = errno;
    vireo_mysql_node_error_t local = {0};
    vireo_mysql_node_error_t *e = error != NULL ? error : &local;
    *e = local;
    if (out != NULL) { memset(out, 0, sizeof(*out)); }
    if (report != NULL) { *report = (vireo_mysql_node_report_t){0}; }
    if (!valid(r) || out == NULL || report == NULL) {
        e->stage = STAGE(VALIDATE);
        return finish(saved, VIREO_RESULT_INVALID_ARGUMENT);
    }
    report->cleanup_pending = pending(r);
    vireo_result_t rc = pending(r) ? VIREO_RESULT_BUSY :
        (actor == NULL || actor->user_id == 0 || actor->session_id == 0 || query == NULL ||
         query->directory_id == 0 ? VIREO_RESULT_INVALID_ARGUMENT :
         (query->page_size == 0 || query->page_size > VIREO_MYSQL_NODE_PAGE_CAPACITY ||
          timeout > VIREO_MYSQL_POOL_WAIT_MS_MAX ? VIREO_RESULT_RANGE : VIREO_OK));
    if (rc != VIREO_OK) { e->stage = STAGE(VALIDATE); return finish(saved, rc); }
    vireo_mysql_node_page_t *page = r->ops.allocate(sizeof(*page));
    if (page == NULL) { e->stage = STAGE(ALLOCATE); return finish(saved, VIREO_RESULT_NO_MEMORY); }
    memset(page, 0, sizeof(*page));
    bool transaction = false, found = false;
    uint64_t issued = 0, expires = 0, now = 0;
    vireo_mysql_node_value_t parent = {0};
    vireo_mysql_pool_acquisition_t acquired = {0};
    vireo_mysql_pool_error_t pe = {0};
    vireo_mysql_execution_t ex;
    rc = r->ops.acquire(r->thread, r->pool, timeout, &r->lease, &acquired, &pe);
    diagnose(e, STAGE(ACQUIRE), rc, NULL, &pe, false);
    if (rc != VIREO_OK) { goto done; }
    rc = r->ops.borrow(r->thread, r->pool, &r->lease, &r->connection);
    diagnose(e, STAGE(BORROW), rc, NULL, NULL, false);
    if (rc != VIREO_OK) { goto done; }
    rc = execute(r, "SET autocommit=0", NULL, 0, STAGE(BEGIN), &ex, e, false);
    transaction = ex.execution_started;
    if (rc == VIREO_OK && ex.has_result) {
        rc = VIREO_RESULT_DATABASE;
        diagnose(e, STAGE(BEGIN), rc, NULL, NULL, false);
    }
    { vireo_result_t closed = close_statement(r, e); if (rc == VIREO_OK) { rc = closed; } }
    if (rc != VIREO_OK) { goto done; }
    rc = lock_user(r, actor->user_id, report, e);
    if (rc != VIREO_OK) { goto done; }
    rc = lock_session(r, actor, &issued, &expires, report, e);
    if (rc != VIREO_OK) { goto done; }
    rc = lock_node(r, actor->user_id, query->directory_id, &parent, &found, e);
    if (rc != VIREO_OK) { goto done; }
    if (found && parent.kind == VIREO_MYSQL_NODE_DIRECTORY) {
        rc = lock_children(r, actor->user_id, query, page, e);
        if (rc != VIREO_OK) { goto done; }
    }
    rc = capture_utc(r, &now, e);
    if (rc != VIREO_OK) { goto done; }
    if (now < issued || now >= expires) {
        report->issue = VIREO_MYSQL_NODE_AUTH_REJECTED;
        rc = VIREO_RESULT_NOT_FOUND;
        diagnose(e, STAGE(SESSION), rc, NULL, NULL, false);
    } else if (!found || parent.kind != VIREO_MYSQL_NODE_DIRECTORY) {
        report->issue = VIREO_MYSQL_NODE_NOT_FOUND;
        rc = VIREO_RESULT_NOT_FOUND;
        diagnose(e, STAGE(NODE), rc, NULL, NULL, false);
    }
done:
    if (rc == VIREO_RESULT_DATABASE && report->issue == VIREO_MYSQL_NODE_ISSUE_NONE &&
        (e->stage == STAGE(USER) || e->stage == STAGE(SESSION) || e->stage == STAGE(NODE)) &&
        e->database.mysql_code == 0) { report->issue = VIREO_MYSQL_NODE_UNEXPECTED_RESULT; }
    rc = cleanup(r, transaction, rc, report, e);
    if (rc == VIREO_OK) { memcpy(out, page, sizeof(*out)); report->found = true; }
    r->ops.free_memory(page);
    return finish(saved, rc);
}
/** @brief 写路径专用prepare/execute，保留旧读取limits；不关闭语句。
 * @param[in,out] r 同worker独占repo，活lease/connection且无statement。
 * @param[in] sql 固定内部模板，调用期短借。
 * @param[in] p 短借参数，n为0时可NULL。
 * @param[in] n 最多5参，每条最多255字节参数区。
 * @param[in] stage 原因归属。
 * @param[out] ex 即使失败也保留原生execution_started。
 * @param[in,out] e 首因/首清理独立数值诊断。
 * @param[in] cleanup 是否为ROLLBACK清理。
 * @return 底层结果，固定限额不符映射DATABASE。
 * @note SQL可同步阻塞；不重试、不释放owner。
 */
static vireo_result_t write_execute(vireo_mysql_node_repository_t *r, const char *sql,
    const vireo_mysql_parameter_t *p, size_t n, vireo_mysql_node_stage_t stage,
    vireo_mysql_execution_t *ex, vireo_mysql_node_error_t *e, bool cleanup)
{
    static const vireo_mysql_statement_limits_t limits = {5, 11, 255, 255, 32768};
    *ex = (vireo_mysql_execution_t){0};
    vireo_mysql_error_t db = {0};
    vireo_result_t rc = r->ops.prepare(r->thread, r->connection, sql, strlen(sql), &limits, &r->statement, &db);
    if (rc == VIREO_RESULT_RANGE) { rc = VIREO_RESULT_DATABASE; }
    diagnose(e, stage, rc, &db, NULL, cleanup);
    if (rc == VIREO_OK) {
        rc = r->ops.execute(r->thread, r->statement, p, n, ex, &db);
        if (rc == VIREO_RESULT_RANGE) { rc = VIREO_RESULT_DATABASE; }
        diagnose(e, stage, rc, &db, NULL, cleanup);
    }
    return rc;
}
/** @brief 写命令完整响应与close分报；COMMIT确认不能被close失败抹去。
 * @param[in,out] r 同worker独占repo，无活statement。
 * @param[in] sql 固定BEGIN/INSERT/COMMIT/ROLLBACK模板。
 * @param[in] p 调用期短借参数。
 * @param[in] n 固定模板参数数目。
 * @param[in] stage 数值诊断归属。
 * @param[in] insert 是否要求affected_rows=1与非零insert_id。
 * @param[in] cleanup 是否为回滚。
 * @param[out] ex 保留原生执行进度，即使close失败。
 * @param[out] replied 仅完整无结果成功响应且DML形状有效为true。
 * @param[in,out] e 首因与首清理。
 * @return 执行首错优先，否则close结果。
 * @note 始终尝试close；残留owner继续属于repo。
 */
static vireo_result_t write_command(vireo_mysql_node_repository_t *r, const char *sql,
    const vireo_mysql_parameter_t *p, size_t n, vireo_mysql_node_stage_t stage, bool insert,
    bool cleanup, vireo_mysql_execution_t *ex, bool *replied, vireo_mysql_node_error_t *e)
{
    *replied = false;
    vireo_result_t rc = write_execute(r, sql, p, n, stage, ex, e, cleanup);
    if (rc == VIREO_OK) {
        if (ex->has_result || (insert && (ex->affected_rows != 1 || ex->insert_id == 0))) {
            rc = VIREO_RESULT_DATABASE;
            diagnose(e, stage, rc, NULL, NULL, cleanup);
        } else { *replied = true; }
    }
    vireo_result_t closed = close_statement(r, e);
    return rc == VIREO_OK ? closed : rc;
}
/** @brief 从开始就取父X锁，避免同父创建先S后升级；不修改父时间。
 * @param[in,out] r 已锁user/session的worker事务owner。
 * @param[in] owner 非零可信属主。
 * @param[in] id 非零父节点ID。
 * @param[in,out] value 独立全零暂存，失败不得发布。
 * @param[out] found 完整行命中，领域类型判断在UTC后。
 * @param[in,out] e 首因/首清理诊断。
 * @return SQL/形状结果；未命中仍OK。
 * @note owner/active谓词固定，缺失也不探测他人；close不释放事务锁。
 */
static vireo_result_t lock_mkdir_parent(vireo_mysql_node_repository_t *r, uint64_t owner,
    uint64_t id, vireo_mysql_node_value_t *value, bool *found, vireo_mysql_node_error_t *e)
{
    static const char sql[] = "SELECT id,owner_id,parent_id,name,node_type,state,object_hash,size,"
        "created_at_ms,updated_at_ms,deleted_at_ms FROM file_nodes WHERE owner_id=? AND id=? AND state=2 FOR UPDATE";
    vireo_mysql_parameter_t p[2] = {U64(owner), U64(id)};
    vireo_mysql_execution_t ex;
    vireo_result_t rc = write_execute(r, sql, p, 2, STAGE(NODE), &ex, e, false);
    vireo_mysql_cell_view_t cells[11];
    if (rc == VIREO_OK && !ex.has_result) { rc = VIREO_RESULT_DATABASE; }
    if (rc == VIREO_OK) { rc = read_row(r, 11, cells, found, e); }
    if (rc == VIREO_OK && *found) {
        if (!node_value(cells, owner, id, value)) { rc = VIREO_RESULT_DATABASE; }
        else { rc = unique_end(r, STAGE(NODE), e); }
    }
    diagnose(e, STAGE(NODE), rc, NULL, NULL, false);
    vireo_result_t closed = close_statement(r, e);
    return rc == VIREO_OK ? closed : rc;
}
/** @brief 父X锁后按完整live_name锁读，验证占名而非解释1062文本。
 * @param[in,out] r 持有有效目录父X锁的worker事务。
 * @param[in] owner 可信属主。
 * @param[in] in 已验证单段输入，短借至返回。
 * @param[out] occupied 完整验证的一条state1/2行才表示占名。
 * @param[in,out] e 首因与首清理。
 * @return SQL/固定行形状结果，未命中也OK。
 * @note 最多一行且须DONE；视图在下一fetch前全部消费，不保存名字指针。
 */
static vireo_result_t lock_mkdir_name(vireo_mysql_node_repository_t *r, uint64_t owner,
    const vireo_mysql_node_mkdir_input_t *in, bool *occupied, vireo_mysql_node_error_t *e)
{
    static const char sql[] = "SELECT id,owner_id,parent_id,name,state FROM file_nodes "
        "WHERE owner_id=? AND parent_id=? AND live_name=? FOR UPDATE";
    vireo_mysql_parameter_t p[3] = {U64(owner), U64(in->parent_id),
        {.kind=VIREO_MYSQL_PARAMETER_BYTES, .value.span={in->name, in->name_length}}};
    vireo_mysql_execution_t ex;
    vireo_result_t rc = write_execute(r, sql, p, 3, STAGE(NAME_CHECK), &ex, e, false);
    vireo_mysql_cell_view_t c[5]; uint64_t v[4];
    *occupied = false;
    if (rc == VIREO_OK && !ex.has_result) { rc = VIREO_RESULT_DATABASE; }
    if (rc == VIREO_OK) { rc = read_row(r, 5, c, occupied, e); }
    if (rc == VIREO_OK && *occupied) {
        if (!number(c, v) || v[0] == 0 || !number(c + 1, v + 1) || v[1] != owner ||
            !number(c + 2, v + 2) || v[2] != in->parent_id || c[3].is_null ||
            c[3].data == NULL || c[3].length != in->name_length ||
            memcmp(c[3].data, in->name, in->name_length) != 0 || !number(c + 4, v + 3) ||
            (v[3] != 1 && v[3] != 2)) { rc = VIREO_RESULT_DATABASE; }
        else { rc = unique_end(r, STAGE(NAME_CHECK), e); }
    }
    diagnose(e, STAGE(NAME_CHECK), rc, NULL, NULL, false);
    vireo_result_t closed = close_statement(r, e);
    return rc == VIREO_OK ? closed : rc;
}
/** @brief 写入清理；提交事实不由ROLLBACK/close/release覆盖。
 * @param[in,out] r 创建worker持有的实际资源owner。
 * @param[in] transaction BEGIN可能已生效。
 * @param[in] rc 原首因结果。
 * @param[in,out] report 三态提交与回滚/残留事实，已提交值保持。
 * @param[in,out] e 首因/首清理独立诊断。
 * @return 原非OK优先，否则首次清理错误。
 * @note UNKNOWN只DISCARD，不回滚/重放；未消费子owner保留repo。
 */
static vireo_result_t cleanup_mkdir(vireo_mysql_node_repository_t *r, bool transaction,
    vireo_result_t rc, vireo_mysql_node_mkdir_report_t *report, vireo_mysql_node_error_t *e)
{
    vireo_result_t next = close_statement(r, e);
    if (rc == VIREO_OK) { rc = next; }
    if (transaction && report->commit == VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED &&
        r->statement == NULL && r->connection != NULL) {
        vireo_mysql_execution_t ex; bool replied;
        next = write_command(r, "ROLLBACK", NULL, 0, STAGE(ROLLBACK), false, true, &ex, &replied, e);
        report->rollback_confirmed = replied;
        if (rc == VIREO_OK) { rc = next; }
    }
    if (r->statement == NULL && r->lease.owner != NULL) {
        bool ended = report->commit == VIREO_MYSQL_NODE_MKDIR_COMMITTED || report->rollback_confirmed;
        bool healthy = ended && e->cleanup_result == VIREO_OK &&
            (rc == VIREO_OK || rc == VIREO_RESULT_NOT_FOUND || report->issue == VIREO_MYSQL_NODE_NAME_CONFLICT);
        vireo_mysql_pool_release_t released = {0}; vireo_mysql_pool_error_t pe = {0};
        next = r->ops.release(r->thread, r->pool, &r->lease,
            healthy ? VIREO_MYSQL_POOL_RECYCLE : VIREO_MYSQL_POOL_DISCARD, &released, &pe);
        if (released.released) { r->connection = NULL; }
        diagnose(e, STAGE(RELEASE), next, NULL, &pe, true);
        if (rc == VIREO_OK) { rc = next; }
    }
    report->cleanup_pending = pending(r);
    return rc;
}

vireo_result_t vireo_mysql_node_repository_mkdir(vireo_mysql_node_repository_t *r,
    const vireo_mysql_node_actor_t *actor, const vireo_mysql_node_mkdir_input_t *in,
    uint32_t timeout, vireo_mysql_node_mkdir_report_t *report, vireo_mysql_node_error_t *error)
{
    _Static_assert(VIREO_MYSQL_SCHEMA_AUDIT_ACTION_NODE_MKDIR == 5, "fixed mkdir audit SQL registry");
    int saved = errno;
    vireo_mysql_node_error_t local = {0};
    vireo_mysql_node_error_t *e = error != NULL ? error : &local;
    *e = local;
    if (report != NULL) { memset(report, 0, sizeof(*report)); }
    if (!valid(r) || report == NULL) {
        e->stage = STAGE(VALIDATE); return finish(saved, VIREO_RESULT_INVALID_ARGUMENT);
    }
    report->cleanup_pending = pending(r);
    if (pending(r)) { e->stage = STAGE(VALIDATE); return finish(saved, VIREO_RESULT_BUSY); }
    if (actor == NULL || actor->user_id == 0 || actor->session_id == 0 ||
        in == NULL || in->parent_id == 0 || in->name == NULL) {
        e->stage = STAGE(VALIDATE); return finish(saved, VIREO_RESULT_INVALID_ARGUMENT);
    }
    unsigned char event = 0;
    for (size_t i = 0; i < sizeof(in->request_id); ++i) { event |= in->request_id[i]; }
    if (event == 0) { e->stage = STAGE(VALIDATE); return finish(saved, VIREO_RESULT_INVALID_ARGUMENT); }
    if (in->name_length == 0 || in->name_length > VIREO_MYSQL_NODE_NAME_CAPACITY || timeout > VIREO_MYSQL_POOL_WAIT_MS_MAX) {
        e->stage = STAGE(VALIDATE); return finish(saved, VIREO_RESULT_RANGE);
    }
    bool bad = (in->name_length == 1 && in->name[0] == '.') ||
        (in->name_length == 2 && in->name[0] == '.' && in->name[1] == '.');
    for (size_t i = 0; i < in->name_length; ++i) { bad = bad || in->name[i] == 0 || in->name[i] == '/'; }
    if (bad) { e->stage = STAGE(VALIDATE); return finish(saved, VIREO_RESULT_PROTOCOL); }
    bool transaction = false, found = false, occupied = false, replied = false;
    uint64_t issued = 0, expires = 0, now = 0, audit = 0;
    vireo_mysql_node_value_t value = {0};
    vireo_mysql_node_report_t auth = {0};
    vireo_mysql_pool_acquisition_t acquired = {0}; vireo_mysql_pool_error_t pe = {0};
    vireo_mysql_execution_t ex;
    vireo_result_t rc = r->ops.acquire(r->thread, r->pool, timeout, &r->lease, &acquired, &pe);
    diagnose(e, STAGE(ACQUIRE), rc, NULL, &pe, false);
    if (rc != VIREO_OK) { goto done; }
    rc = r->ops.borrow(r->thread, r->pool, &r->lease, &r->connection);
    diagnose(e, STAGE(BORROW), rc, NULL, NULL, false);
    if (rc != VIREO_OK) { goto done; }
    rc = write_command(r, "SET autocommit=0", NULL, 0, STAGE(BEGIN), false, false, &ex, &replied, e);
    transaction = ex.execution_started;
    if (rc != VIREO_OK) { goto done; }
    rc = lock_user(r, actor->user_id, &auth, e);
    if (rc != VIREO_OK) { goto done; }
    rc = lock_session(r, actor, &issued, &expires, &auth, e);
    if (rc != VIREO_OK) { goto done; }
    rc = lock_mkdir_parent(r, actor->user_id, in->parent_id, &value, &found, e);
    if (rc != VIREO_OK) { goto done; }
    if (found && value.kind == VIREO_MYSQL_NODE_DIRECTORY) {
        rc = lock_mkdir_name(r, actor->user_id, in, &occupied, e);
        if (rc != VIREO_OK) { goto done; }
    }
    rc = capture_utc(r, &now, e);
    if (rc != VIREO_OK) { goto done; }
    if (now < issued || now >= expires) {
        report->issue = VIREO_MYSQL_NODE_AUTH_REJECTED; rc = VIREO_RESULT_NOT_FOUND;
        diagnose(e, STAGE(SESSION), rc, NULL, NULL, false); goto done;
    }
    if (!found || value.kind != VIREO_MYSQL_NODE_DIRECTORY) {
        report->issue = VIREO_MYSQL_NODE_NOT_FOUND; rc = VIREO_RESULT_NOT_FOUND;
        diagnose(e, STAGE(NODE), rc, NULL, NULL, false); goto done;
    }
    if (occupied) {
        report->issue = VIREO_MYSQL_NODE_NAME_CONFLICT; rc = VIREO_RESULT_DATABASE;
        diagnose(e, STAGE(NAME_CHECK), rc, NULL, NULL, false); goto done;
    }
    memset(&value, 0, sizeof(value));
    value.owner_id = actor->user_id; value.parent_id = in->parent_id; value.has_parent = true;
    value.kind = VIREO_MYSQL_NODE_DIRECTORY; value.name_length = in->name_length;
    memcpy(value.name, in->name, in->name_length); value.created_at_ms = now; value.updated_at_ms = now;
    static const char insert_node[] = "INSERT INTO file_nodes(owner_id,parent_id,name,node_type,state,object_hash,size,"
        "created_at_ms,updated_at_ms,deleted_at_ms) VALUES(?,?,?,1,2,NULL,0,?,?,NULL)";
    vireo_mysql_parameter_t n[5] = {U64(actor->user_id), U64(in->parent_id),
        {.kind=VIREO_MYSQL_PARAMETER_BYTES, .value.span={in->name, in->name_length}}, U64(now), U64(now)};
    rc = write_command(r, insert_node, n, 5, STAGE(INSERT), true, false, &ex, &replied, e);
    if (rc != VIREO_OK) { goto done; }
    value.id = ex.insert_id;
    static const char insert_audit[] = "INSERT INTO operation_audits(request_id,user_id,session_id,action,target_type,"
        "target_id,target_hash,status,latency_us,detail,occurred_at_ms) VALUES(?,?,?,5,3,?,NULL,0,0,'',?)";
    vireo_mysql_parameter_t a[5] = {
        {.kind=VIREO_MYSQL_PARAMETER_BYTES, .value.span={in->request_id, sizeof(in->request_id)}},
        U64(actor->user_id), U64(actor->session_id), U64(value.id), U64(now)};
    rc = write_command(r, insert_audit, a, 5, STAGE(AUDIT), true, false, &ex, &replied, e);
    if (rc != VIREO_OK) { goto done; }
    audit = ex.insert_id;
    rc = capture_utc(r, &now, e);
    if (rc != VIREO_OK) { goto done; }
    if (now < issued || now >= expires) {
        report->issue = VIREO_MYSQL_NODE_AUTH_REJECTED; rc = VIREO_RESULT_NOT_FOUND;
        diagnose(e, STAGE(SESSION), rc, NULL, NULL, false); goto done;
    }
    rc = write_command(r, "COMMIT", NULL, 0, STAGE(COMMIT), false, false, &ex, &replied, e);
    if (replied) {
        report->commit = VIREO_MYSQL_NODE_MKDIR_COMMITTED;
        memcpy(&report->node, &value, sizeof(value)); report->audit_id = audit;
    } else if (ex.execution_started) { report->commit = VIREO_MYSQL_NODE_MKDIR_UNKNOWN; }
done:
    if (report->issue == VIREO_MYSQL_NODE_ISSUE_NONE) { report->issue = auth.issue; }
    if (rc == VIREO_RESULT_DATABASE && report->issue == VIREO_MYSQL_NODE_ISSUE_NONE &&
        e->database.mysql_code == 0 && (e->stage == STAGE(USER) || e->stage == STAGE(SESSION) ||
        e->stage == STAGE(NODE) || e->stage == STAGE(NAME_CHECK) || e->stage == STAGE(INSERT) ||
        e->stage == STAGE(AUDIT) || e->stage == STAGE(COMMIT))) { report->issue = VIREO_MYSQL_NODE_UNEXPECTED_RESULT; }
    rc = cleanup_mkdir(r, transaction, rc, report, e);
    return finish(saved, rc);
}

/** @brief move专用user直接X；不改变旧入口user S及其限额。
 * @param[in,out] r 当前worker独占活事务，无statement。
 * @param[in] id 非零可信用户。
 * @param[in,out] report 身份拒绝暂存。
 * @param[in,out] e 去敏首因/清理。
 * @return 状态/形状或资源结果，关闭语句但保留事务锁。
 * @note 不先S再升级；全部树writer须遵守user先锁协议。
 */
static vireo_result_t lock_move_user(vireo_mysql_node_repository_t *r, uint64_t id,
    vireo_mysql_node_report_t *report, vireo_mysql_node_error_t *e)
{
    vireo_mysql_execution_t ex; vireo_mysql_parameter_t p = U64(id);
    vireo_result_t rc = write_execute(r, "SELECT id,status FROM users WHERE id=? FOR UPDATE", &p, 1, STAGE(USER), &ex, e, false);
    vireo_mysql_cell_view_t cells[2]; bool found = false; uint64_t v[2];
    if (rc == VIREO_OK && !ex.has_result) { rc = VIREO_RESULT_DATABASE; }
    if (rc == VIREO_OK) { rc = read_row(r, 2, cells, &found, e); }
    if (rc == VIREO_OK && found) {
        if (!number(cells, v) || !number(cells + 1, v + 1) || v[0] != id || (v[1] != 1 && v[1] != 2)) {
            rc = VIREO_RESULT_DATABASE;
        } else { rc = unique_end(r, STAGE(USER), e); }
    }
    if (rc == VIREO_OK && (!found || v[1] != 1)) {
        report->issue = VIREO_MYSQL_NODE_AUTH_REJECTED; rc = VIREO_RESULT_NOT_FOUND;
    }
    diagnose(e, STAGE(USER), rc, NULL, NULL, false);
    vireo_result_t closed = close_statement(r, e); return rc == VIREO_OK ? closed : rc;
}

/** @brief 回执专用有界执行；不扩大旧读写入口的参数预算。 */
static vireo_result_t receipt_execute(vireo_mysql_node_repository_t *r, const char *sql,
    const vireo_mysql_parameter_t *p, size_t n, vireo_mysql_node_stage_t stage,
    vireo_mysql_execution_t *ex, vireo_mysql_node_error_t *e)
{
    static const vireo_mysql_statement_limits_t limits = {7, 11, 271, 255, 32768};
    *ex = (vireo_mysql_execution_t){0};
    vireo_mysql_error_t db = {0};
    vireo_result_t rc = r->ops.prepare(r->thread, r->connection, sql, strlen(sql), &limits, &r->statement, &db);
    if (rc == VIREO_RESULT_RANGE) { rc = VIREO_RESULT_DATABASE; }
    diagnose(e, stage, rc, &db, NULL, false);
    if (rc == VIREO_OK) {
        rc = r->ops.execute(r->thread, r->statement, p, n, ex, &db);
        if (rc == VIREO_RESULT_RANGE) { rc = VIREO_RESULT_DATABASE; }
        diagnose(e, stage, rc, &db, NULL, false);
    }
    return rc;
}
/** @brief 仅复核DDL单段名字字节；调用方已检查地址及1..255长度。 */
static bool receipt_name_valid(const unsigned char *name, size_t n)
{
    if ((n == 1 && name[0] == '.') || (n == 2 && name[0] == '.' && name[1] == '.')) { return false; }
    for (size_t i = 0; i < n; ++i) { if (name[i] == 0 || name[i] == '/') { return false; } }
    return true;
}
/** @brief 当前锁读完整历史回执，在下一fetch前复制全部需要的字节和值。 */
typedef struct mkdir_receipt {
    uint64_t parent_id, node_id, audit_id;
    size_t name_length;
    unsigned char name[255];
} mkdir_receipt_t;
static vireo_result_t lock_mkdir_receipt(vireo_mysql_node_repository_t *r, uint64_t owner,
    const vireo_mysql_node_mkdir_once_input_t *in, mkdir_receipt_t *value, bool *found,
    vireo_mysql_node_mkdir_once_report_t *report, vireo_mysql_node_error_t *e)
{
    static const char sql[] = "SELECT user_id,command,idempotency_key,format_version,request_parent_id,"
        "request_name,result_node_id,audit_id,created_at_ms FROM directory_write_receipts "
        "WHERE user_id=? AND command=1027 AND idempotency_key=? FOR UPDATE";
    vireo_mysql_parameter_t p[2] = {U64(owner),
        {.kind=VIREO_MYSQL_PARAMETER_BYTES, .value.span={in->idempotency_key, 16}}};
    vireo_mysql_execution_t ex; vireo_mysql_error_t db = {0};
    vireo_result_t rc = receipt_execute(r, sql, p, 2, STAGE(RECEIPT_READ), &ex, e);
    bool malformed = rc == VIREO_OK && !ex.has_result;
    *found = false;
    if (malformed) { rc = VIREO_RESULT_DATABASE; }
    vireo_mysql_fetch_outcome_t outcome;
    if (rc == VIREO_OK) {
        rc = r->ops.fetch(r->thread, r->statement, &outcome, &db);
        if (rc == VIREO_OK && outcome == VIREO_MYSQL_FETCH_ROW) { *found = true; }
        else if (rc == VIREO_OK && outcome != VIREO_MYSQL_FETCH_DONE) { malformed = true; rc = VIREO_RESULT_DATABASE; }
    }
    vireo_mysql_cell_view_t c[9]; uint64_t v[9] = {0};
    if (rc == VIREO_OK && *found) {
        for (size_t i = 0; i < 9 && rc == VIREO_OK; ++i) {
            rc = r->ops.column(r->thread, r->statement, i, c + i);
        }
        if (rc == VIREO_OK) {
            for (size_t i = 0; i < 9; ++i) {
                if (i != 2 && i != 5 && !number(c + i, v + i)) { malformed = true; }
            }
            if (v[0] != owner || v[1] != 1027 || v[3] != 1 || v[4] == 0 || v[6] == 0 || v[7] == 0 ||
                c[2].is_null || c[2].data == NULL || c[2].length != 16 ||
                (c[2].length == 16 && c[2].data != NULL && memcmp(c[2].data, in->idempotency_key, 16) != 0) ||
                c[5].is_null || c[5].data == NULL || c[5].length == 0 || c[5].length > 255) { malformed = true; }
            if (!malformed && !receipt_name_valid(c[5].data, c[5].length)) { malformed = true; }
            if (malformed) { rc = VIREO_RESULT_DATABASE; }
            else {
                value->parent_id = v[4]; value->node_id = v[6]; value->audit_id = v[7];
                value->name_length = c[5].length; memcpy(value->name, c[5].data, c[5].length);
                rc = r->ops.fetch(r->thread, r->statement, &outcome, &db);
                if (rc == VIREO_OK && outcome != VIREO_MYSQL_FETCH_DONE) { malformed = true; rc = VIREO_RESULT_DATABASE; }
            }
        }
    }
    if (rc == VIREO_RESULT_RANGE) { malformed = true; rc = VIREO_RESULT_DATABASE; }
    if (malformed) { report->issue = VIREO_MYSQL_NODE_RECEIPT_INVALID; }
    diagnose(e, STAGE(RECEIPT_READ), rc, &db, NULL, false);
    vireo_result_t closed = close_statement(r, e);
    return rc == VIREO_OK ? closed : rc;
}
/** @brief 回执无自增ID；只要求单行DML确认，insert_id不参与解释。 */
static vireo_result_t insert_mkdir_receipt(vireo_mysql_node_repository_t *r, uint64_t owner,
    const vireo_mysql_node_mkdir_once_input_t *in, uint64_t node, uint64_t audit,
    uint64_t now, vireo_mysql_node_error_t *e)
{
    static const char sql[] = "INSERT INTO directory_write_receipts(user_id,command,idempotency_key,format_version,"
        "request_parent_id,request_name,result_node_id,audit_id,created_at_ms) VALUES(?,1027,?,1,?,?,?,?,?)";
    vireo_mysql_parameter_t p[7] = {U64(owner),
        {.kind=VIREO_MYSQL_PARAMETER_BYTES, .value.span={in->idempotency_key, 16}}, U64(in->parent_id),
        {.kind=VIREO_MYSQL_PARAMETER_BYTES, .value.span={in->name, in->name_length}}, U64(node), U64(audit), U64(now)};
    vireo_mysql_execution_t ex;
    vireo_result_t rc = receipt_execute(r, sql, p, 7, STAGE(RECEIPT_INSERT), &ex, e);
    if (rc == VIREO_OK && (ex.has_result || ex.affected_rows != 1)) { rc = VIREO_RESULT_DATABASE; }
    diagnose(e, STAGE(RECEIPT_INSERT), rc, NULL, NULL, false);
    vireo_result_t closed = close_statement(r, e);
    return rc == VIREO_OK ? closed : rc;
}

static vireo_result_t cleanup_mkdir_once(vireo_mysql_node_repository_t *r, bool transaction,
    vireo_result_t rc, vireo_mysql_node_mkdir_once_report_t *report, vireo_mysql_node_error_t *e)
{
    vireo_result_t next = close_statement(r, e);
    if (rc == VIREO_OK) { rc = next; }
    if (transaction && report->commit == VIREO_MYSQL_NODE_MKDIR_NOT_COMMITTED &&
        r->statement == NULL && r->connection != NULL) {
        vireo_mysql_execution_t ex; bool replied;
        next = write_command(r, "ROLLBACK", NULL, 0, STAGE(ROLLBACK), false, true, &ex, &replied, e);
        report->rollback_confirmed = replied;
        if (rc == VIREO_OK) { rc = next; }
    }
    if (r->statement == NULL && r->lease.owner != NULL) {
        bool ended = report->commit == VIREO_MYSQL_NODE_MKDIR_COMMITTED || report->rollback_confirmed;
        bool healthy = ended && e->cleanup_result == VIREO_OK &&
            (rc == VIREO_OK || rc == VIREO_RESULT_NOT_FOUND || report->issue == VIREO_MYSQL_NODE_NAME_CONFLICT ||
             report->issue == VIREO_MYSQL_NODE_IDEMPOTENCY_CONFLICT);
        vireo_mysql_pool_release_t released = {0}; vireo_mysql_pool_error_t pe = {0};
        next = r->ops.release(r->thread, r->pool, &r->lease,
            healthy ? VIREO_MYSQL_POOL_RECYCLE : VIREO_MYSQL_POOL_DISCARD, &released, &pe);
        if (released.released) { r->connection = NULL; }
        diagnose(e, STAGE(RELEASE), next, NULL, &pe, true);
        if (rc == VIREO_OK) { rc = next; }
    }
    report->cleanup_pending = pending(r);
    return rc;
}

vireo_result_t vireo_mysql_node_repository_mkdir_once(vireo_mysql_node_repository_t *r,
    const vireo_mysql_node_actor_t *actor, const vireo_mysql_node_mkdir_once_input_t *in,
    uint32_t timeout, vireo_mysql_node_mkdir_once_report_t *report, vireo_mysql_node_error_t *error)
{
    _Static_assert(VIREO_MYSQL_SCHEMA_AUDIT_ACTION_NODE_MKDIR == 5, "fixed mkdir audit SQL registry");
    int saved = errno;
    vireo_mysql_node_error_t local = {0};
    vireo_mysql_node_error_t *e = error != NULL ? error : &local;
    *e = local;
    if (report != NULL) { memset(report, 0, sizeof(*report)); }
    if (!valid(r) || report == NULL) {
        e->stage = STAGE(VALIDATE); return finish(saved, VIREO_RESULT_INVALID_ARGUMENT);
    }
    report->cleanup_pending = pending(r);
    if (pending(r)) { e->stage = STAGE(VALIDATE); return finish(saved, VIREO_RESULT_BUSY); }
    if (actor == NULL || actor->user_id == 0 || actor->session_id == 0 ||
        in == NULL || in->parent_id == 0 || in->name == NULL) {
        e->stage = STAGE(VALIDATE); return finish(saved, VIREO_RESULT_INVALID_ARGUMENT);
    }
    unsigned char event = 0, key = 0;
    for (size_t i = 0; i < sizeof(in->request_id); ++i) { event |= in->request_id[i]; key |= in->idempotency_key[i]; }
    if (event == 0 || key == 0) { e->stage = STAGE(VALIDATE); return finish(saved, VIREO_RESULT_INVALID_ARGUMENT); }
    if (in->name_length == 0 || in->name_length > VIREO_MYSQL_NODE_NAME_CAPACITY || timeout > VIREO_MYSQL_POOL_WAIT_MS_MAX) {
        e->stage = STAGE(VALIDATE); return finish(saved, VIREO_RESULT_RANGE);
    }
    bool bad = (in->name_length == 1 && in->name[0] == '.') ||
        (in->name_length == 2 && in->name[0] == '.' && in->name[1] == '.');
    for (size_t i = 0; i < in->name_length; ++i) { bad = bad || in->name[i] == 0 || in->name[i] == '/'; }
    if (bad) { e->stage = STAGE(VALIDATE); return finish(saved, VIREO_RESULT_PROTOCOL); }
    bool transaction = false, found = false, occupied = false, replied = false;
    uint64_t issued = 0, expires = 0, now = 0, audit = 0;
    vireo_mysql_node_value_t value = {0};
    vireo_mysql_node_report_t auth = {0};
    vireo_mysql_pool_acquisition_t acquired = {0}; vireo_mysql_pool_error_t pe = {0};
    vireo_mysql_execution_t ex;
    vireo_result_t rc = r->ops.acquire(r->thread, r->pool, timeout, &r->lease, &acquired, &pe);
    diagnose(e, STAGE(ACQUIRE), rc, NULL, &pe, false);
    if (rc != VIREO_OK) { goto done; }
    rc = r->ops.borrow(r->thread, r->pool, &r->lease, &r->connection);
    diagnose(e, STAGE(BORROW), rc, NULL, NULL, false);
    if (rc != VIREO_OK) { goto done; }
    rc = write_command(r, "SET autocommit=0", NULL, 0, STAGE(BEGIN), false, false, &ex, &replied, e);
    transaction = ex.execution_started;
    if (rc != VIREO_OK) { goto done; }
    rc = lock_move_user(r, actor->user_id, &auth, e);
    if (rc != VIREO_OK) { goto done; }
    rc = lock_session(r, actor, &issued, &expires, &auth, e);
    if (rc != VIREO_OK) { goto done; }
    mkdir_receipt_t receipt = {0};
    rc = lock_mkdir_receipt(r, actor->user_id, in, &receipt, &found, report, e);
    if (rc != VIREO_OK) { goto done; }
    if (found) {
        rc = capture_utc(r, &now, e);
        if (rc != VIREO_OK) { goto done; }
        if (now < issued || now >= expires) {
            report->issue = VIREO_MYSQL_NODE_AUTH_REJECTED; rc = VIREO_RESULT_NOT_FOUND;
            diagnose(e, STAGE(SESSION), rc, NULL, NULL, false); goto done;
        }
        if (receipt.parent_id != in->parent_id || receipt.name_length != in->name_length ||
            memcmp(receipt.name, in->name, in->name_length) != 0) {
            report->issue = VIREO_MYSQL_NODE_IDEMPOTENCY_CONFLICT; rc = VIREO_RESULT_DATABASE;
            diagnose(e, STAGE(RECEIPT_READ), rc, NULL, NULL, false); goto done;
        }
        report->effect = VIREO_MYSQL_NODE_MKDIR_EFFECT_RECOVERED;
        report->node_id = receipt.node_id; report->audit_id = receipt.audit_id;
        memcpy(report->idempotency_key, in->idempotency_key, 16);
        goto done;
    }
    vireo_mysql_node_mkdir_input_t name_input = {.parent_id=in->parent_id, .name=in->name, .name_length=in->name_length};
    rc = lock_mkdir_parent(r, actor->user_id, in->parent_id, &value, &found, e);
    if (rc != VIREO_OK) { goto done; }
    if (found && value.kind == VIREO_MYSQL_NODE_DIRECTORY) {
        rc = lock_mkdir_name(r, actor->user_id, &name_input, &occupied, e);
        if (rc != VIREO_OK) { goto done; }
    }
    rc = capture_utc(r, &now, e);
    if (rc != VIREO_OK) { goto done; }
    if (now < issued || now >= expires) {
        report->issue = VIREO_MYSQL_NODE_AUTH_REJECTED; rc = VIREO_RESULT_NOT_FOUND;
        diagnose(e, STAGE(SESSION), rc, NULL, NULL, false); goto done;
    }
    if (!found || value.kind != VIREO_MYSQL_NODE_DIRECTORY) {
        report->issue = VIREO_MYSQL_NODE_NOT_FOUND; rc = VIREO_RESULT_NOT_FOUND;
        diagnose(e, STAGE(NODE), rc, NULL, NULL, false); goto done;
    }
    if (occupied) {
        report->issue = VIREO_MYSQL_NODE_NAME_CONFLICT; rc = VIREO_RESULT_DATABASE;
        diagnose(e, STAGE(NAME_CHECK), rc, NULL, NULL, false); goto done;
    }
    memset(&value, 0, sizeof(value));
    value.owner_id = actor->user_id; value.parent_id = in->parent_id; value.has_parent = true;
    value.kind = VIREO_MYSQL_NODE_DIRECTORY; value.name_length = in->name_length;
    memcpy(value.name, in->name, in->name_length); value.created_at_ms = now; value.updated_at_ms = now;
    static const char insert_node[] = "INSERT INTO file_nodes(owner_id,parent_id,name,node_type,state,object_hash,size,"
        "created_at_ms,updated_at_ms,deleted_at_ms) VALUES(?,?,?,1,2,NULL,0,?,?,NULL)";
    vireo_mysql_parameter_t n[5] = {U64(actor->user_id), U64(in->parent_id),
        {.kind=VIREO_MYSQL_PARAMETER_BYTES, .value.span={in->name, in->name_length}}, U64(now), U64(now)};
    rc = write_command(r, insert_node, n, 5, STAGE(INSERT), true, false, &ex, &replied, e);
    if (rc != VIREO_OK) { goto done; }
    value.id = ex.insert_id;
    static const char insert_audit[] = "INSERT INTO operation_audits(request_id,user_id,session_id,action,target_type,"
        "target_id,target_hash,status,latency_us,detail,occurred_at_ms) VALUES(?,?,?,5,3,?,NULL,0,0,'',?)";
    vireo_mysql_parameter_t a[5] = {
        {.kind=VIREO_MYSQL_PARAMETER_BYTES, .value.span={in->request_id, sizeof(in->request_id)}},
        U64(actor->user_id), U64(actor->session_id), U64(value.id), U64(now)};
    rc = write_command(r, insert_audit, a, 5, STAGE(AUDIT), true, false, &ex, &replied, e);
    if (rc != VIREO_OK) { goto done; }
    audit = ex.insert_id;
    rc = insert_mkdir_receipt(r, actor->user_id, in, value.id, audit, now, e);
    if (rc != VIREO_OK) { goto done; }
    rc = capture_utc(r, &now, e);
    if (rc != VIREO_OK) { goto done; }
    if (now < issued || now >= expires) {
        report->issue = VIREO_MYSQL_NODE_AUTH_REJECTED; rc = VIREO_RESULT_NOT_FOUND;
        diagnose(e, STAGE(SESSION), rc, NULL, NULL, false); goto done;
    }
    rc = write_command(r, "COMMIT", NULL, 0, STAGE(COMMIT), false, false, &ex, &replied, e);
    if (replied) {
        report->commit = VIREO_MYSQL_NODE_MKDIR_COMMITTED;
        report->effect = VIREO_MYSQL_NODE_MKDIR_EFFECT_CREATED;
        report->node_id = value.id; report->audit_id = audit;
        memcpy(report->idempotency_key, in->idempotency_key, 16);
    } else if (ex.execution_started) { report->commit = VIREO_MYSQL_NODE_MKDIR_UNKNOWN; }
done:
    if (report->issue == VIREO_MYSQL_NODE_ISSUE_NONE) { report->issue = auth.issue; }
    if (rc == VIREO_RESULT_DATABASE && report->issue == VIREO_MYSQL_NODE_ISSUE_NONE &&
        e->database.mysql_code == 0 && (e->stage == STAGE(USER) || e->stage == STAGE(SESSION) ||
        e->stage == STAGE(NODE) || e->stage == STAGE(NAME_CHECK) || e->stage == STAGE(INSERT) ||
        e->stage == STAGE(AUDIT) || e->stage == STAGE(RECEIPT_INSERT) || e->stage == STAGE(COMMIT))) { report->issue = VIREO_MYSQL_NODE_UNEXPECTED_RESULT; }
    rc = cleanup_mkdir_once(r, transaction, rc, report, e);
    return finish(saved, rc);
}

/** @brief move当前锁读完整节点，关闭statement后仍持有行锁。
 * @param[in,out] r 当前worker已持user X与session S。
 * @param[in] owner 可信非零属主。
 * @param[in] id 必需非零节点ID。
 * @param[in] exclusive 源/目标true，祖先false，不使用普通快照SELECT。
 * @param[in] stage 本次源/目标/祖先诊断阶段。
 * @param[out] value 零初始化暂存，完整命中才可用于领域判断。
 * @param[out] found 未命中仍OK，交caller在UTC后发布拒绝。
 * @param[in,out] e 首因/清理数值诊断。
 * @return SQL/完整11列/唯一性/close结果。
 * @note owner/state固定谓词；不递归、不缓存SQL视图。
 */
static vireo_result_t lock_move_node(vireo_mysql_node_repository_t *r, uint64_t owner, uint64_t id,
    bool exclusive, vireo_mysql_node_stage_t stage, vireo_mysql_node_value_t *value,
    bool *found, vireo_mysql_node_error_t *e)
{
    static const char x[] = "SELECT id,owner_id,parent_id,name,node_type,state,object_hash,size,"
        "created_at_ms,updated_at_ms,deleted_at_ms FROM file_nodes WHERE owner_id=? AND id=? AND state=2 FOR UPDATE";
    static const char shared[] = "SELECT id,owner_id,parent_id,name,node_type,state,object_hash,size,"
        "created_at_ms,updated_at_ms,deleted_at_ms FROM file_nodes WHERE owner_id=? AND id=? AND state=2 FOR SHARE";
    vireo_mysql_parameter_t p[2] = {U64(owner), U64(id)}; vireo_mysql_execution_t ex;
    vireo_result_t rc = write_execute(r, exclusive ? x : shared, p, 2, stage, &ex, e, false);
    vireo_mysql_cell_view_t cells[11]; *found = false;
    if (rc == VIREO_OK && !ex.has_result) { rc = VIREO_RESULT_DATABASE; }
    if (rc == VIREO_OK) {
        rc = read_row(r, 11, cells, found, e);
        /* 共用解析器默认NODE；新入口把该次读取错误归属精确阶段。 */
        if (e->stage == STAGE(NODE)) { e->stage = stage; }
    }
    if (rc == VIREO_OK && *found) {
        if (!node_value(cells, owner, id, value)) { rc = VIREO_RESULT_DATABASE; }
        else { rc = unique_end(r, stage, e); }
    }
    diagnose(e, stage, rc, NULL, NULL, false);
    vireo_result_t closed = close_statement(r, e); return rc == VIREO_OK ? closed : rc;
}
/** @brief 延迟至锁后UTC再发布的领域判断；不是资源/行形状错误。 */
typedef struct move_domain {
    vireo_mysql_node_issue_t issue; /**< NONE表示尚无拒绝。 */
    vireo_mysql_node_stage_t stage; /**< UTC有效后才进入首因槽。 */
    vireo_result_t result; /**< DATABASE/NOT_FOUND/RANGE。 */
} move_domain_t;
/** @brief 固定数组检查一条活动目录祖先链，不扫描后代。
 * @param[in,out] r 已持user X，所有树writer共同协调。
 * @param[in] owner 可信属主。
 * @param[in] id 起点，源旧父或目标父，非零。
 * @param[in] forbidden 源目录ID仅目标链使用，源链/文件为0。
 * @param[out] domain 若链损坏/成环/超限保存领域拒绝，留UTC后发布。
 * @param[in,out] e 仅直接资源/行形状失败写首因。
 * @return OK含领域拒绝，其他为直接错误。
 * @note 每链256项含根；数组只在调用期使用，约2KiB，不分配/递归。
 */
static vireo_result_t move_chain(vireo_mysql_node_repository_t *r, uint64_t owner, uint64_t id,
    uint64_t forbidden, move_domain_t *domain, vireo_mysql_node_error_t *e)
{
    uint64_t visited[VIREO_MYSQL_NODE_MOVE_ANCESTOR_CAPACITY];
    for (size_t count = 0; count < VIREO_MYSQL_NODE_MOVE_ANCESTOR_CAPACITY; ++count) {
        if (id == forbidden) {
            *domain = (move_domain_t){VIREO_MYSQL_NODE_MOVE_CYCLE, STAGE(ANCESTOR), VIREO_RESULT_DATABASE};
            return VIREO_OK;
        }
        for (size_t i = 0; i < count; ++i) {
            if (visited[i] == id) {
                *domain = (move_domain_t){VIREO_MYSQL_NODE_TREE_INVALID, STAGE(ANCESTOR), VIREO_RESULT_DATABASE};
                return VIREO_OK;
            }
        }
        visited[count] = id;
        vireo_mysql_node_value_t value = {0}; bool found;
        vireo_result_t rc = lock_move_node(r, owner, id, false, STAGE(ANCESTOR), &value, &found, e);
        if (rc != VIREO_OK) { return rc; }
        if (!found || value.kind != VIREO_MYSQL_NODE_DIRECTORY) {
            *domain = (move_domain_t){VIREO_MYSQL_NODE_TREE_INVALID, STAGE(ANCESTOR), VIREO_RESULT_DATABASE};
            return VIREO_OK;
        }
        if (!value.has_parent) { return VIREO_OK; }
        id = value.parent_id;
    }
    *domain = (move_domain_t){VIREO_MYSQL_NODE_ANCESTRY_LIMIT, STAGE(ANCESTOR), VIREO_RESULT_RANGE};
    return VIREO_OK;
}
/** @brief 完整字节占名锁读；返回ID与state用于验证不变操作必须命中源自身。
 * @param[in,out] r 当前worker独占已完成两链的事务。
 * @param[in] owner 可信属主。
 * @param[in] in 已验证输入，短借至返回。
 * @param[out] id 未命中0，完整验证且唯一命中才非零。
 * @param[out] state 命中1或2；无命中0。
 * @param[in,out] e 首因/清理诊断。
 * @return SQL/形状/close结果，不猜测1062来源。
 * @note 不返回对方节点，不保存列view。
 */
static vireo_result_t lock_move_name(vireo_mysql_node_repository_t *r, uint64_t owner,
    const vireo_mysql_node_move_input_t *in, uint64_t *id, uint64_t *state, vireo_mysql_node_error_t *e)
{
    static const char sql[] = "SELECT id,owner_id,parent_id,name,state FROM file_nodes "
        "WHERE owner_id=? AND parent_id=? AND live_name=? FOR UPDATE";
    vireo_mysql_parameter_t p[3] = {U64(owner), U64(in->new_parent_id),
        {.kind=VIREO_MYSQL_PARAMETER_BYTES, .value.span={in->name, in->name_length}}};
    vireo_mysql_execution_t ex; bool found = false; vireo_mysql_cell_view_t c[5]; uint64_t v[4];
    *id = 0; *state = 0;
    vireo_result_t rc = write_execute(r, sql, p, 3, STAGE(NAME_CHECK), &ex, e, false);
    if (rc == VIREO_OK && !ex.has_result) { rc = VIREO_RESULT_DATABASE; }
    if (rc == VIREO_OK) { rc = read_row(r, 5, c, &found, e); }
    if (rc == VIREO_OK && found) {
        if (!number(c, v) || v[0] == 0 || !number(c + 1, v + 1) || v[1] != owner ||
            !number(c + 2, v + 2) || v[2] != in->new_parent_id || c[3].is_null ||
            c[3].data == NULL || c[3].length != in->name_length ||
            memcmp(c[3].data, in->name, in->name_length) != 0 || !number(c + 4, v + 3) ||
            (v[3] != 1 && v[3] != 2)) { rc = VIREO_RESULT_DATABASE; }
        else { rc = unique_end(r, STAGE(NAME_CHECK), e); }
        if (rc == VIREO_OK) { *id = v[0]; *state = v[3]; }
    }
    diagnose(e, STAGE(NAME_CHECK), rc, NULL, NULL, false);
    vireo_result_t closed = close_statement(r, e); return rc == VIREO_OK ? closed : rc;
}
/** @brief 单行UPDATE专用响应校验，insert_id可以为0。
 * @param[in,out] r 当前worker独占活事务。
 * @param[in] owner 可信属主。
 * @param[in] in 已验证最终位置/名字。
 * @param[in] updated 钳制到旧updated以上的UTC值。
 * @param[in,out] e 首因/清理诊断。
 * @return 无结果且affected_rows=1才成功；所有路径尝试close。
 * @note 不更改源身份/内容或父、子节点，不重试。
 */
static vireo_result_t update_move(vireo_mysql_node_repository_t *r, uint64_t owner,
    const vireo_mysql_node_move_input_t *in, uint64_t updated, vireo_mysql_node_error_t *e)
{
    static const char sql[] = "UPDATE file_nodes SET parent_id=?,name=?,updated_at_ms=? WHERE owner_id=? AND id=? AND state=2";
    vireo_mysql_parameter_t p[5] = {U64(in->new_parent_id),
        {.kind=VIREO_MYSQL_PARAMETER_BYTES, .value.span={in->name, in->name_length}},
        U64(updated), U64(owner), U64(in->node_id)};
    vireo_mysql_execution_t ex;
    vireo_result_t rc = write_execute(r, sql, p, 5, STAGE(UPDATE), &ex, e, false);
    if (rc == VIREO_OK && (ex.has_result || ex.affected_rows != 1)) { rc = VIREO_RESULT_DATABASE; }
    diagnose(e, STAGE(UPDATE), rc, NULL, NULL, false);
    vireo_result_t closed = close_statement(r, e); return rc == VIREO_OK ? closed : rc;
}
/** @brief move清理保留提交历史，仅确定未提交且可用连接才尝试ROLLBACK。
 * @param[in,out] r 当前worker实际子owner，残留不丢弃。
 * @param[in] transaction BEGIN原生执行可能已开始。
 * @param[in] rc 原首因结果优先。
 * @param[in,out] report 提交/回滚/残留分报，提交值保持。
 * @param[in,out] e 首因/首清理分别保存。
 * @return 原首因优先，否则首次清理错误。
 * @note UNKNOWN只DISCARD且不重放；残留owner保留repo/BUSY。
 */
static vireo_result_t cleanup_move(vireo_mysql_node_repository_t *r, bool transaction,
    vireo_result_t rc, vireo_mysql_node_move_report_t *report, vireo_mysql_node_error_t *e)
{
    vireo_result_t next = close_statement(r, e);
    if (rc == VIREO_OK) { rc = next; }
    if (transaction && report->commit == VIREO_MYSQL_NODE_MOVE_NOT_COMMITTED &&
        r->statement == NULL && r->connection != NULL) {
        vireo_mysql_execution_t ex; bool replied;
        next = write_command(r, "ROLLBACK", NULL, 0, STAGE(ROLLBACK), false, true, &ex, &replied, e);
        report->rollback_confirmed = replied;
        if (rc == VIREO_OK) { rc = next; }
    }
    if (r->statement == NULL && r->lease.owner != NULL) {
        bool ended = report->commit == VIREO_MYSQL_NODE_MOVE_COMMITTED || report->rollback_confirmed;
        bool healthy = ended && e->cleanup_result == VIREO_OK &&
            (rc == VIREO_OK || rc == VIREO_RESULT_NOT_FOUND || (report->issue == VIREO_MYSQL_NODE_NAME_CONFLICT || report->issue == VIREO_MYSQL_NODE_ROOT_IMMOVABLE ||
             report->issue == VIREO_MYSQL_NODE_MOVE_CYCLE || report->issue == VIREO_MYSQL_NODE_TREE_INVALID ||
             report->issue == VIREO_MYSQL_NODE_ANCESTRY_LIMIT));
        vireo_mysql_pool_release_t released = {0}; vireo_mysql_pool_error_t pe = {0};
        next = r->ops.release(r->thread, r->pool, &r->lease,
            healthy ? VIREO_MYSQL_POOL_RECYCLE : VIREO_MYSQL_POOL_DISCARD, &released, &pe);
        if (released.released) { r->connection = NULL; }
        diagnose(e, STAGE(RELEASE), next, NULL, &pe, true);
        if (rc == VIREO_OK) { rc = next; }
    }
    report->cleanup_pending = pending(r);
    return rc;
}

vireo_result_t vireo_mysql_node_repository_move(vireo_mysql_node_repository_t *r,
    const vireo_mysql_node_actor_t *actor, const vireo_mysql_node_move_input_t *in,
    uint32_t timeout, vireo_mysql_node_move_report_t *report, vireo_mysql_node_error_t *error)
{
    _Static_assert(VIREO_MYSQL_SCHEMA_AUDIT_ACTION_NODE_MOVE == 6, "fixed move audit SQL registry");
    int saved = errno; vireo_mysql_node_error_t local = {0};
    vireo_mysql_node_error_t *e = error != NULL ? error : &local; *e = local;
    if (report != NULL) { memset(report, 0, sizeof(*report)); }
    if (!valid(r) || report == NULL) {
        e->stage = STAGE(VALIDATE); return finish(saved, VIREO_RESULT_INVALID_ARGUMENT);
    }
    report->cleanup_pending = pending(r);
    if (pending(r)) { e->stage = STAGE(VALIDATE); return finish(saved, VIREO_RESULT_BUSY); }
    if (actor == NULL || actor->user_id == 0 || actor->session_id == 0 || in == NULL ||
        in->node_id == 0 || in->new_parent_id == 0 || in->name == NULL) {
        e->stage = STAGE(VALIDATE); return finish(saved, VIREO_RESULT_INVALID_ARGUMENT);
    }
    unsigned char event = 0;
    for (size_t i = 0; i < sizeof(in->request_id); ++i) { event |= in->request_id[i]; }
    if (event == 0) { e->stage = STAGE(VALIDATE); return finish(saved, VIREO_RESULT_INVALID_ARGUMENT); }
    if (in->name_length == 0 || in->name_length > VIREO_MYSQL_NODE_NAME_CAPACITY || timeout > VIREO_MYSQL_POOL_WAIT_MS_MAX) {
        e->stage = STAGE(VALIDATE); return finish(saved, VIREO_RESULT_RANGE);
    }
    bool bad = (in->name_length == 1 && in->name[0] == '.') ||
        (in->name_length == 2 && in->name[0] == '.' && in->name[1] == '.');
    for (size_t i = 0; i < in->name_length; ++i) { bad = bad || in->name[i] == 0 || in->name[i] == '/'; }
    if (bad) { e->stage = STAGE(VALIDATE); return finish(saved, VIREO_RESULT_PROTOCOL); }
    bool transaction = false, source_found = false, target_found = false, replied = false, changed = false;
    uint64_t issued = 0, expires = 0, now = 0, audit = 0, occupied = 0, occupancy_state = 0;
    vireo_mysql_node_value_t source = {0}, target = {0}; vireo_mysql_node_report_t auth = {0};
    move_domain_t domain = {0};
    vireo_mysql_pool_acquisition_t acquired = {0}; vireo_mysql_pool_error_t pe = {0}; vireo_mysql_execution_t ex;
    vireo_result_t rc = r->ops.acquire(r->thread, r->pool, timeout, &r->lease, &acquired, &pe);
    diagnose(e, STAGE(ACQUIRE), rc, NULL, &pe, false);
    if (rc != VIREO_OK) { goto done; }
    rc = r->ops.borrow(r->thread, r->pool, &r->lease, &r->connection);
    diagnose(e, STAGE(BORROW), rc, NULL, NULL, false);
    if (rc != VIREO_OK) { goto done; }
    rc = write_command(r, "SET autocommit=0", NULL, 0, STAGE(BEGIN), false, false, &ex, &replied, e);
    transaction = ex.execution_started;
    if (rc != VIREO_OK) { goto done; }
    rc = lock_move_user(r, actor->user_id, &auth, e);
    if (rc != VIREO_OK) { goto done; }
    rc = lock_session(r, actor, &issued, &expires, &auth, e);
    if (rc != VIREO_OK) { goto done; }
    rc = lock_move_node(r, actor->user_id, in->node_id, true, STAGE(SOURCE), &source, &source_found, e);
    if (rc != VIREO_OK) { goto done; }
    if (source_found) {
        rc = lock_move_node(r, actor->user_id, in->new_parent_id, true, STAGE(TARGET_PARENT), &target, &target_found, e);
        if (rc != VIREO_OK) { goto done; }
    }
    if (!source_found || !target_found || target.kind != VIREO_MYSQL_NODE_DIRECTORY) {
        domain = (move_domain_t){VIREO_MYSQL_NODE_NOT_FOUND,
            source_found ? STAGE(TARGET_PARENT) : STAGE(SOURCE), VIREO_RESULT_NOT_FOUND};
    } else if (!source.has_parent) {
        domain = (move_domain_t){VIREO_MYSQL_NODE_ROOT_IMMOVABLE, STAGE(SOURCE), VIREO_RESULT_DATABASE};
    } else {
        rc = move_chain(r, actor->user_id, source.parent_id, 0, &domain, e);
        if (rc != VIREO_OK) { goto done; }
        if (domain.issue == VIREO_MYSQL_NODE_ISSUE_NONE) {
            rc = move_chain(r, actor->user_id, in->new_parent_id,
                source.kind == VIREO_MYSQL_NODE_DIRECTORY ? source.id : 0, &domain, e);
            if (rc != VIREO_OK) { goto done; }
        }
        if (domain.issue == VIREO_MYSQL_NODE_ISSUE_NONE) {
            rc = lock_move_name(r, actor->user_id, in, &occupied, &occupancy_state, e);
            if (rc != VIREO_OK) { goto done; }
            changed = source.parent_id != in->new_parent_id || source.name_length != in->name_length ||
                memcmp(source.name, in->name, in->name_length) != 0;
            if (occupied != 0 && occupied != source.id) {
                domain = (move_domain_t){VIREO_MYSQL_NODE_NAME_CONFLICT, STAGE(NAME_CHECK), VIREO_RESULT_DATABASE};
            } else if ((!changed && (occupied != source.id || occupancy_state != 2)) || (changed && occupied == source.id)) {
                rc = VIREO_RESULT_DATABASE; diagnose(e, STAGE(NAME_CHECK), rc, NULL, NULL, false); goto done;
            }
        }
    }
    rc = capture_utc(r, &now, e);
    if (rc != VIREO_OK) { goto done; }
    if (now < issued || now >= expires) {
        report->issue = VIREO_MYSQL_NODE_AUTH_REJECTED; rc = VIREO_RESULT_NOT_FOUND;
        diagnose(e, STAGE(SESSION), rc, NULL, NULL, false); goto done;
    }
    if (domain.issue != VIREO_MYSQL_NODE_ISSUE_NONE) {
        report->issue = domain.issue; rc = domain.result;
        diagnose(e, domain.stage, rc, NULL, NULL, false); goto done;
    }
    if (changed) {
        source.updated_at_ms = now > source.updated_at_ms ? now : source.updated_at_ms;
        rc = update_move(r, actor->user_id, in, source.updated_at_ms, e);
        if (rc != VIREO_OK) { goto done; }
        source.parent_id = in->new_parent_id;
        memset(source.name, 0, sizeof(source.name)); memcpy(source.name, in->name, in->name_length);
        source.name_length = in->name_length;
    }
    static const char audit_sql[] = "INSERT INTO operation_audits(request_id,user_id,session_id,action,target_type,"
        "target_id,target_hash,status,latency_us,detail,occurred_at_ms) VALUES(?,?,?,6,3,?,NULL,0,0,'',?)";
    vireo_mysql_parameter_t a[5] = {
        {.kind=VIREO_MYSQL_PARAMETER_BYTES, .value.span={in->request_id, sizeof(in->request_id)}},
        U64(actor->user_id), U64(actor->session_id), U64(source.id), U64(now)};
    rc = write_command(r, audit_sql, a, 5, STAGE(AUDIT), true, false, &ex, &replied, e);
    if (rc != VIREO_OK) { goto done; }
    audit = ex.insert_id;
    rc = capture_utc(r, &now, e);
    if (rc != VIREO_OK) { goto done; }
    if (now < issued || now >= expires) {
        report->issue = VIREO_MYSQL_NODE_AUTH_REJECTED; rc = VIREO_RESULT_NOT_FOUND;
        diagnose(e, STAGE(SESSION), rc, NULL, NULL, false); goto done;
    }
    rc = write_command(r, "COMMIT", NULL, 0, STAGE(COMMIT), false, false, &ex, &replied, e);
    if (replied) {
        report->commit = VIREO_MYSQL_NODE_MOVE_COMMITTED;
        report->node = source; report->audit_id = audit; report->changed = changed;
    } else if (ex.execution_started) { report->commit = VIREO_MYSQL_NODE_MOVE_UNKNOWN; }
done:
    if (report->issue == VIREO_MYSQL_NODE_ISSUE_NONE) { report->issue = auth.issue; }
    if (rc == VIREO_RESULT_DATABASE && report->issue == VIREO_MYSQL_NODE_ISSUE_NONE &&
        e->database.mysql_code == 0 && (e->stage == STAGE(USER) || e->stage == STAGE(SESSION) ||
        e->stage == STAGE(SOURCE) || e->stage == STAGE(TARGET_PARENT) || e->stage == STAGE(ANCESTOR) ||
        e->stage == STAGE(NAME_CHECK) || e->stage == STAGE(UPDATE) || e->stage == STAGE(AUDIT) ||
        e->stage == STAGE(COMMIT))) { report->issue = VIREO_MYSQL_NODE_UNEXPECTED_RESULT; }
    rc = cleanup_move(r, transaction, rc, report, e);
    return finish(saved, rc);
}

/** @brief 新删除路径按实际阶段读取固定行，避免沿用旧读取的列数阶段推断。
 * @param[in,out] r 当前worker持有的活statement。
 * @param[in] count 固定5/8/11列。
 * @param[in] stage 当前锁读所属阶段。
 * @param[out] cells 至少count项短借，在下一fetch/close前消费。
 * @param[out] found 入口false，完整行才true。
 * @param[in,out] e 首因数值诊断。
 * @return 完整ROW/DONE为OK，列截断/异常fetch为DATABASE，其他沿依赖。
 * @note 不分配、不关闭或保存视图。
 */
static vireo_result_t delete_row(vireo_mysql_node_repository_t *r, size_t count,
    vireo_mysql_node_stage_t stage, vireo_mysql_cell_view_t *cells, bool *found, vireo_mysql_node_error_t *e)
{
    vireo_mysql_error_t db = {0}; vireo_mysql_fetch_outcome_t outcome;
    *found = false;
    vireo_result_t rc = r->ops.fetch(r->thread, r->statement, &outcome, &db);
    if (rc == VIREO_OK && outcome == VIREO_MYSQL_FETCH_ROW) {
        for (size_t i = 0; i < count && rc == VIREO_OK; ++i) {
            rc = r->ops.column(r->thread, r->statement, i, cells + i);
        }
        *found = rc == VIREO_OK;
    } else if (rc == VIREO_OK && outcome != VIREO_MYSQL_FETCH_DONE) { rc = VIREO_RESULT_DATABASE; }
    if (rc == VIREO_RESULT_RANGE) { rc = VIREO_RESULT_DATABASE; }
    diagnose(e, stage, rc, &db, NULL, false); return rc;
}
/** @brief 删除源/祖先锁定当前读，固定owner与ACTIVE谓词。
 * @param[in,out] r 已持user/Session锁的worker事务。
 * @param[in] owner 可信非零属主。
 * @param[in] id 精确非零节点ID。
 * @param[in] source true源直接X，false祖先S。
 * @param[out] value 独立零初始化暂存，仅成功命中可用。
 * @param[out] found 完整合法唯一行才可用。
 * @param[in,out] e 首因与首清理诊断。
 * @return 锁读/形状/close结果；未命中仍OK留UTC后判领域。
 * @note 语句close不释放事务锁，不改变旧move/read helper。
 */
static vireo_result_t lock_delete_node(vireo_mysql_node_repository_t *r, uint64_t owner,
    uint64_t id, bool source, vireo_mysql_node_value_t *value, bool *found, vireo_mysql_node_error_t *e)
{
    static const char x[] = "SELECT id,owner_id,parent_id,name,node_type,state,object_hash,size,"
        "created_at_ms,updated_at_ms,deleted_at_ms FROM file_nodes WHERE owner_id=? AND id=? AND state=2 FOR UPDATE";
    static const char s[] = "SELECT id,owner_id,parent_id,name,node_type,state,object_hash,size,"
        "created_at_ms,updated_at_ms,deleted_at_ms FROM file_nodes WHERE owner_id=? AND id=? AND state=2 FOR SHARE";
    vireo_mysql_node_stage_t stage = source ? STAGE(SOURCE) : STAGE(ANCESTOR);
    vireo_mysql_parameter_t p[2] = {U64(owner), U64(id)}; vireo_mysql_execution_t ex;
    vireo_mysql_cell_view_t c[11]; *found = false;
    vireo_result_t rc = write_execute(r, source ? x : s, p, 2, stage, &ex, e, false);
    if (rc == VIREO_OK && !ex.has_result) { rc = VIREO_RESULT_DATABASE; }
    if (rc == VIREO_OK) { rc = delete_row(r, 11, stage, c, found, e); }
    if (rc == VIREO_OK && *found) {
        if (!node_value(c, owner, id, value)) { rc = VIREO_RESULT_DATABASE; }
        else { rc = unique_end(r, stage, e); }
    }
    diagnose(e, stage, rc, NULL, NULL, false);
    vireo_result_t closed = close_statement(r, e); return rc == VIREO_OK ? closed : rc;
}
/** @brief 删除前验证源旧父到根，含根至多256项；领域拒绝暂存到UTC后。
 * @param[in,out] r user X已锁定的worker事务。
 * @param[in] owner 可信属主。
 * @param[in] id 源旧父非零ID。
 * @param[out] domain 仅遇链损坏/预算耗尽才写拒绝。
 * @param[in,out] e SQL/形状/清理首因。
 * @return OK包括暂存领域拒绝，其他为底层直接错误。
 * @note 固定约2KiB visited，非递归、不检查后代或自动修树。
 */
static vireo_result_t delete_chain(vireo_mysql_node_repository_t *r, uint64_t owner,
    uint64_t id, move_domain_t *domain, vireo_mysql_node_error_t *e)
{
    uint64_t visited[VIREO_MYSQL_NODE_MOVE_ANCESTOR_CAPACITY];
    for (size_t count = 0; count < VIREO_MYSQL_NODE_MOVE_ANCESTOR_CAPACITY; ++count) {
        for (size_t i = 0; i < count; ++i) {
            if (visited[i] == id) {
                *domain = (move_domain_t){VIREO_MYSQL_NODE_TREE_INVALID, STAGE(ANCESTOR), VIREO_RESULT_DATABASE};
                return VIREO_OK;
            }
        }
        visited[count] = id; vireo_mysql_node_value_t value = {0}; bool found;
        vireo_result_t rc = lock_delete_node(r, owner, id, false, &value, &found, e);
        if (rc != VIREO_OK) { return rc; }
        if (!found || value.kind != VIREO_MYSQL_NODE_DIRECTORY) {
            *domain = (move_domain_t){VIREO_MYSQL_NODE_TREE_INVALID, STAGE(ANCESTOR), VIREO_RESULT_DATABASE};
            return VIREO_OK;
        }
        if (!value.has_parent) { return VIREO_OK; }
        id = value.parent_id;
    }
    *domain = (move_domain_t){VIREO_MYSQL_NODE_ANCESTRY_LIMIT, STAGE(ANCESTOR), VIREO_RESULT_RANGE};
    return VIREO_OK;
}
/** @brief 查一个ACTIVE/UPLOADING直接孩子见证，不能漏掉上传中占位。
 * @param[in,out] r 已持user X/源X/祖先S的worker事务。
 * @param[in] owner 可信属主。
 * @param[in] id 源目录ID。
 * @param[out] occupied 合法唯一见证才为true。
 * @param[in,out] e 首因与清理数值诊断。
 * @return SQL/形状/close结果；非空领域留UTC后。
 * @note LIMIT1不限制扫描/隐式锁/墙钟；无视图借用外泄。
 */
static vireo_result_t lock_delete_children(vireo_mysql_node_repository_t *r, uint64_t owner,
    uint64_t id, bool *occupied, vireo_mysql_node_error_t *e)
{
    static const char sql[] = "SELECT id,owner_id,parent_id,node_type,state FROM file_nodes "
        "WHERE owner_id=? AND parent_id=? AND state IN (1,2) ORDER BY id LIMIT 1 FOR UPDATE";
    vireo_mysql_parameter_t p[2] = {U64(owner), U64(id)}; vireo_mysql_execution_t ex;
    vireo_mysql_cell_view_t c[5]; uint64_t v[5] = {0}; *occupied = false;
    vireo_result_t rc = write_execute(r, sql, p, 2, STAGE(CHILDREN), &ex, e, false);
    if (rc == VIREO_OK && !ex.has_result) { rc = VIREO_RESULT_DATABASE; }
    if (rc == VIREO_OK) { rc = delete_row(r, 5, STAGE(CHILDREN), c, occupied, e); }
    if (rc == VIREO_OK && *occupied) {
        for (size_t i = 0; i < 5; ++i) {
            if (!number(c + i, v + i)) { rc = VIREO_RESULT_DATABASE; break; }
        }
        if (rc == VIREO_OK && (v[0] == 0 || v[1] != owner || v[2] != id ||
            (v[3] != 1 && v[3] != 2) || (v[4] != 1 && v[4] != 2) ||
            (v[3] == 1 && v[4] == 1))) { rc = VIREO_RESULT_DATABASE; }
        if (rc == VIREO_OK) { rc = unique_end(r, STAGE(CHILDREN), e); }
    }
    diagnose(e, STAGE(CHILDREN), rc, NULL, NULL, false);
    vireo_result_t closed = close_statement(r, e); return rc == VIREO_OK ? closed : rc;
}
/** @brief 文件对象锁读后仅保留本事务减引用所需独立数值。 */
typedef struct delete_object {
    uint64_t ref_count; /**< 原活动引用，领域核验>0后才能减一。 */
    uint64_t state; /**< 完整合法原状态，UPDATE谓词重核，保持不改。 */
    uint64_t updated; /**< 原UTC毫秒，写入时与UTC1取max，避免回拨。 */
} delete_object_t;
/** @brief 完整八列object X锁读；合法引用问题暂存，畸形行直接失败。
 * @param[in,out] r 已按user→Session→节点/祖先锁定的worker事务。
 * @param[in] source 活动文件独立值，含完整hash与size。
 * @param[out] object 完整合法命中时发布独立原数值。
 * @param[in,out] domain 缺行/大小不符/ref0/DELETING为引用领域拒绝。
 * @param[in,out] e SQL/行形状/close诊断。
 * @return 形状和资源错误直接返回，领域结果等UTC后发布。
 * @note 不证明CAS可用，不扫描全库修计数，所有view在下一fetch前消费。
 */
static vireo_result_t lock_delete_object(vireo_mysql_node_repository_t *r,
    const vireo_mysql_node_value_t *source, delete_object_t *object, move_domain_t *domain,
    vireo_mysql_node_error_t *e)
{
    static const char sql[] = "SELECT object_hash,size,state,ref_count,storage_class,created_at_ms,"
        "updated_at_ms,verified_at_ms FROM objects WHERE object_hash=? FOR UPDATE";
    vireo_mysql_parameter_t p = {.kind=VIREO_MYSQL_PARAMETER_BYTES, .value.span={source->object_hash,32}};
    vireo_mysql_execution_t ex; vireo_mysql_cell_view_t c[8]; uint64_t v[8] = {0}; bool found = false;
    vireo_result_t rc = write_execute(r, sql, &p, 1, STAGE(OBJECT), &ex, e, false);
    if (rc == VIREO_OK && !ex.has_result) { rc = VIREO_RESULT_DATABASE; }
    if (rc == VIREO_OK) { rc = delete_row(r, 8, STAGE(OBJECT), c, &found, e); }
    if (rc == VIREO_OK && found) {
        for (size_t i = 1; i < 8; ++i) {
            if (i == 7 && c[i].is_null) { continue; }
            if (!number(c + i, v + i)) { rc = VIREO_RESULT_DATABASE; break; }
        }
        if (rc == VIREO_OK && (c[0].is_null || c[0].data == NULL || c[0].length != 32 ||
            memcmp(c[0].data, source->object_hash, 32) != 0 || v[2] < 1 || v[2] > 4 ||
            v[4] != 1 || v[6] < v[5] || (v[2] == 2 && c[7].is_null) ||
            (!c[7].is_null && (v[7] < v[5] || v[7] > v[6])) || (v[2] == 3 && v[3] != 0))) {
            rc = VIREO_RESULT_DATABASE;
        }
        if (rc == VIREO_OK) {
            *object = (delete_object_t){v[3],v[2],v[6]};
            rc = unique_end(r, STAGE(OBJECT), e);
        }
    }
    if (rc == VIREO_OK && (!found || v[1] != source->size || v[3] == 0 || v[2] == 3)) {
        *domain = (move_domain_t){VIREO_MYSQL_NODE_OBJECT_REFERENCE_INVALID, STAGE(OBJECT), VIREO_RESULT_DATABASE};
    }
    diagnose(e, STAGE(OBJECT), rc, NULL, NULL, false);
    vireo_result_t closed = close_statement(r, e); return rc == VIREO_OK ? closed : rc;
}
/** @brief 删除专用UPDATE校验，无结果且恰好修改一行，不要求insert_id。
 * @param[in,out] r 当前worker事务，无statement。
 * @param[in] sql 内部可信固定模板。
 * @param[in] p 调用期短借参数。
 * @param[in] n 固定4或5参。
 * @param[in] stage SOFT_DELETE或OBJECT_UPDATE。
 * @param[in,out] e 首因/首清理诊断。
 * @return execute/形状/close结果。
 * @note 不提交、不重试，所有路径尝试close。
 */
static vireo_result_t delete_update(vireo_mysql_node_repository_t *r, const char *sql,
    const vireo_mysql_parameter_t *p, size_t n, vireo_mysql_node_stage_t stage, vireo_mysql_node_error_t *e)
{
    vireo_mysql_execution_t ex;
    vireo_result_t rc = write_execute(r, sql, p, n, stage, &ex, e, false);
    if (rc == VIREO_OK && (ex.has_result || ex.affected_rows != 1)) { rc = VIREO_RESULT_DATABASE; }
    diagnose(e, stage, rc, NULL, NULL, false);
    vireo_result_t closed = close_statement(r, e); return rc == VIREO_OK ? closed : rc;
}
/** @brief 保留删除提交历史，未确认提交与清理责任分开处理。
 * @param[in,out] r worker独占实际资源owner。
 * @param[in] transaction BEGIN原生执行可能已开始。
 * @param[in] rc 原首因优先。
 * @param[in,out] report 提交/回滚/剩余责任分报，已确认提交值保持。
 * @param[in,out] e 首因/首清理诊断。
 * @return 原首错，否则首清理结果。
 * @note UNKNOWN只DISCARD，不重放；残留owner仍归repo/BUSY。
 */
static vireo_result_t cleanup_delete(vireo_mysql_node_repository_t *r, bool transaction,
    vireo_result_t rc, vireo_mysql_node_soft_delete_report_t *report, vireo_mysql_node_error_t *e)
{
    vireo_result_t next = close_statement(r, e);
    if (rc == VIREO_OK) { rc = next; }
    if (transaction && report->commit == VIREO_MYSQL_NODE_SOFT_DELETE_NOT_COMMITTED &&
        r->statement == NULL && r->connection != NULL) {
        vireo_mysql_execution_t ex; bool replied;
        next = write_command(r, "ROLLBACK", NULL, 0, STAGE(ROLLBACK), false, true, &ex, &replied, e);
        report->rollback_confirmed = replied;
        if (rc == VIREO_OK) { rc = next; }
    }
    if (r->statement == NULL && r->lease.owner != NULL) {
        bool ended = report->commit == VIREO_MYSQL_NODE_SOFT_DELETE_COMMITTED || report->rollback_confirmed;
        bool domain = report->issue == VIREO_MYSQL_NODE_ROOT_UNDELETABLE ||
            report->issue == VIREO_MYSQL_NODE_DIRECTORY_NOT_EMPTY || report->issue == VIREO_MYSQL_NODE_TREE_INVALID ||
            report->issue == VIREO_MYSQL_NODE_ANCESTRY_LIMIT || report->issue == VIREO_MYSQL_NODE_OBJECT_REFERENCE_INVALID;
        bool healthy = ended && e->cleanup_result == VIREO_OK &&
            (rc == VIREO_OK || rc == VIREO_RESULT_NOT_FOUND || domain);
        vireo_mysql_pool_release_t released = {0}; vireo_mysql_pool_error_t pe = {0};
        next = r->ops.release(r->thread, r->pool, &r->lease,
            healthy ? VIREO_MYSQL_POOL_RECYCLE : VIREO_MYSQL_POOL_DISCARD, &released, &pe);
        if (released.released) { r->connection = NULL; }
        diagnose(e, STAGE(RELEASE), next, NULL, &pe, true);
        if (rc == VIREO_OK) { rc = next; }
    }
    report->cleanup_pending = pending(r); return rc;
}

vireo_result_t vireo_mysql_node_repository_soft_delete(vireo_mysql_node_repository_t *r,
    const vireo_mysql_node_actor_t *actor, const vireo_mysql_node_soft_delete_input_t *in,
    uint32_t timeout, vireo_mysql_node_soft_delete_report_t *report, vireo_mysql_node_error_t *error)
{
    _Static_assert(VIREO_MYSQL_SCHEMA_AUDIT_ACTION_NODE_SOFT_DELETE == 7, "fixed delete audit SQL registry");
    int saved = errno; vireo_mysql_node_error_t local = {0};
    vireo_mysql_node_error_t *e = error != NULL ? error : &local; *e = local;
    if (report != NULL) { memset(report, 0, sizeof(*report)); }
    if (!valid(r) || report == NULL) {
        e->stage = STAGE(VALIDATE); return finish(saved, VIREO_RESULT_INVALID_ARGUMENT);
    }
    report->cleanup_pending = pending(r);
    if (pending(r)) { e->stage = STAGE(VALIDATE); return finish(saved, VIREO_RESULT_BUSY); }
    if (actor == NULL || actor->user_id == 0 || actor->session_id == 0 || in == NULL || in->node_id == 0) {
        e->stage = STAGE(VALIDATE); return finish(saved, VIREO_RESULT_INVALID_ARGUMENT);
    }
    unsigned char event = 0;
    for (size_t i = 0; i < sizeof(in->request_id); ++i) { event |= in->request_id[i]; }
    if (event == 0) { e->stage = STAGE(VALIDATE); return finish(saved, VIREO_RESULT_INVALID_ARGUMENT); }
    if (timeout > VIREO_MYSQL_POOL_WAIT_MS_MAX) { e->stage = STAGE(VALIDATE); return finish(saved, VIREO_RESULT_RANGE); }
    bool transaction = false, found = false, replied = false;
    uint64_t issued = 0, expires = 0, now = 0, audit = 0, deleted = 0;
    vireo_mysql_node_value_t source = {0}; vireo_mysql_node_report_t auth = {0};
    move_domain_t domain = {0}; delete_object_t object = {0};
    vireo_mysql_pool_acquisition_t acquired = {0}; vireo_mysql_pool_error_t pe = {0}; vireo_mysql_execution_t ex;
    vireo_result_t rc = r->ops.acquire(r->thread, r->pool, timeout, &r->lease, &acquired, &pe);
    diagnose(e, STAGE(ACQUIRE), rc, NULL, &pe, false);
    if (rc != VIREO_OK) { goto done; }
    rc = r->ops.borrow(r->thread, r->pool, &r->lease, &r->connection);
    diagnose(e, STAGE(BORROW), rc, NULL, NULL, false);
    if (rc != VIREO_OK) { goto done; }
    rc = write_command(r, "SET autocommit=0", NULL, 0, STAGE(BEGIN), false, false, &ex, &replied, e);
    transaction = ex.execution_started;
    if (rc != VIREO_OK) { goto done; }
    rc = lock_move_user(r, actor->user_id, &auth, e);
    if (rc != VIREO_OK) { goto done; }
    rc = lock_session(r, actor, &issued, &expires, &auth, e);
    if (rc != VIREO_OK) { goto done; }
    rc = lock_delete_node(r, actor->user_id, in->node_id, true, &source, &found, e);
    if (rc != VIREO_OK) { goto done; }
    if (!found) {
        domain = (move_domain_t){VIREO_MYSQL_NODE_NOT_FOUND, STAGE(SOURCE), VIREO_RESULT_NOT_FOUND};
    } else if (!source.has_parent) {
        domain = (move_domain_t){VIREO_MYSQL_NODE_ROOT_UNDELETABLE, STAGE(SOURCE), VIREO_RESULT_DATABASE};
    } else {
        rc = delete_chain(r, actor->user_id, source.parent_id, &domain, e);
        if (rc != VIREO_OK) { goto done; }
        if (domain.issue == VIREO_MYSQL_NODE_ISSUE_NONE) {
            if (source.kind == VIREO_MYSQL_NODE_DIRECTORY) {
                bool occupied = false;
                rc = lock_delete_children(r, actor->user_id, source.id, &occupied, e);
                if (rc == VIREO_OK && occupied) {
                    domain = (move_domain_t){VIREO_MYSQL_NODE_DIRECTORY_NOT_EMPTY, STAGE(CHILDREN), VIREO_RESULT_DATABASE};
                }
            } else { rc = lock_delete_object(r, &source, &object, &domain, e); }
            if (rc != VIREO_OK) { goto done; }
        }
    }
    rc = capture_utc(r, &now, e);
    if (rc != VIREO_OK) { goto done; }
    if (now < issued || now >= expires) {
        report->issue = VIREO_MYSQL_NODE_AUTH_REJECTED; rc = VIREO_RESULT_NOT_FOUND;
        diagnose(e, STAGE(SESSION), rc, NULL, NULL, false); goto done;
    }
    if (domain.issue != VIREO_MYSQL_NODE_ISSUE_NONE) {
        report->issue = domain.issue; rc = domain.result;
        diagnose(e, domain.stage, rc, NULL, NULL, false); goto done;
    }
    deleted = now > source.updated_at_ms ? now : source.updated_at_ms;
    static const char update_node[] = "UPDATE file_nodes SET state=3,updated_at_ms=?,deleted_at_ms=? "
        "WHERE owner_id=? AND id=? AND state=2";
    vireo_mysql_parameter_t n[4] = {U64(deleted), U64(deleted), U64(actor->user_id), U64(source.id)};
    rc = delete_update(r, update_node, n, 4, STAGE(SOFT_DELETE), e);
    if (rc != VIREO_OK) { goto done; }
    if (source.kind == VIREO_MYSQL_NODE_FILE) {
        static const char update_object[] = "UPDATE objects SET ref_count=?,updated_at_ms=? "
            "WHERE object_hash=? AND ref_count=? AND state=?";
        vireo_mysql_parameter_t o[5] = {U64(object.ref_count - 1), U64(now > object.updated ? now : object.updated),
            {.kind=VIREO_MYSQL_PARAMETER_BYTES, .value.span={source.object_hash,32}}, U64(object.ref_count), U64(object.state)};
        rc = delete_update(r, update_object, o, 5, STAGE(OBJECT_UPDATE), e);
        if (rc != VIREO_OK) { goto done; }
    }
    static const char insert_audit[] = "INSERT INTO operation_audits(request_id,user_id,session_id,action,target_type,"
        "target_id,target_hash,status,latency_us,detail,occurred_at_ms) VALUES(?,?,?,7,3,?,NULL,0,0,'',?)";
    vireo_mysql_parameter_t a[5] = {
        {.kind=VIREO_MYSQL_PARAMETER_BYTES, .value.span={in->request_id,sizeof(in->request_id)}},
        U64(actor->user_id), U64(actor->session_id), U64(source.id), U64(now)};
    rc = write_command(r, insert_audit, a, 5, STAGE(AUDIT), true, false, &ex, &replied, e);
    if (rc != VIREO_OK) { goto done; }
    audit = ex.insert_id;
    rc = capture_utc(r, &now, e);
    if (rc != VIREO_OK) { goto done; }
    if (now < issued || now >= expires) {
        report->issue = VIREO_MYSQL_NODE_AUTH_REJECTED; rc = VIREO_RESULT_NOT_FOUND;
        diagnose(e, STAGE(SESSION), rc, NULL, NULL, false); goto done;
    }
    rc = write_command(r, "COMMIT", NULL, 0, STAGE(COMMIT), false, false, &ex, &replied, e);
    if (replied) {
        report->commit = VIREO_MYSQL_NODE_SOFT_DELETE_COMMITTED;
        report->node_id = source.id; report->audit_id = audit; report->deleted_at_ms = deleted;
    } else if (ex.execution_started) { report->commit = VIREO_MYSQL_NODE_SOFT_DELETE_UNKNOWN; }
done:
    if (report->issue == VIREO_MYSQL_NODE_ISSUE_NONE) { report->issue = auth.issue; }
    if (rc == VIREO_RESULT_DATABASE && report->issue == VIREO_MYSQL_NODE_ISSUE_NONE && e->database.mysql_code == 0 &&
        (e->stage == STAGE(USER) || e->stage == STAGE(SESSION) || e->stage == STAGE(SOURCE) ||
         e->stage == STAGE(ANCESTOR) || e->stage == STAGE(CHILDREN) || e->stage == STAGE(OBJECT) ||
         e->stage == STAGE(SOFT_DELETE) || e->stage == STAGE(OBJECT_UPDATE) || e->stage == STAGE(AUDIT) ||
         e->stage == STAGE(COMMIT))) { report->issue = VIREO_MYSQL_NODE_UNEXPECTED_RESULT; }
    rc = cleanup_delete(r, transaction, rc, report, e); return finish(saved, rc);
}

vireo_result_t vireo_mysql_node_repository_destroy(vireo_mysql_node_repository_t **owner,
    vireo_mysql_node_error_t *error)
{
    int saved = errno; vireo_mysql_node_error_t local = {0};
    vireo_mysql_node_error_t *e = error != NULL ? error : &local; *e = local;
    if (owner == NULL || (*owner != NULL && !valid(*owner))) {
        e->stage = STAGE(VALIDATE); return finish(saved, VIREO_RESULT_INVALID_ARGUMENT);
    }
    if (*owner == NULL) { return finish(saved, VIREO_OK); }
    vireo_mysql_node_repository_t *r = *owner; vireo_mysql_node_report_t report = {0};
    vireo_result_t rc = cleanup(r, false, VIREO_OK, &report, e);
    if (!pending(r)) { void (*free_memory)(void *) = r->ops.free_memory; free_memory(r); *owner = NULL; }
    return finish(saved, rc);
}
