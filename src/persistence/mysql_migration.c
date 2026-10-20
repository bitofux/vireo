/*
 * PROJECT : VIREO
 * FILE    : mysql_migration.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-18
 * BRIEF   : 通过公共MySQL资源接口执行有界迁移。
 * IMPLEMENTATION: dirty先确认，多DDL无共同事务；完整历史校验，首因与清理分离。
 */
#include "mysql_migration_internal.h"
#include <vireo/base/checked.h>
#include <openssl/evp.h>
#include <errno.h>
#include <string.h>

typedef struct migration_context {
    const vireo_mysql_migration_ops_t *ops; /* 本次不可变，生产为公共API表。 */
    vireo_mysql_thread_t *thread; /* caller当前线程guard短借。 */
    vireo_mysql_connection_t *connection; /* 唯一自有专用连接。 */
    vireo_mysql_statement_t *statement; /* 至多一个，退出前必须消耗。 */
    vireo_mysql_migration_report_t *report; /* caller独占进度。 */
    vireo_mysql_migration_error_t error; /* 首因及首清理错误。 */
    vireo_mysql_migration_stage_t phase; /* 当前尚未失败的阶段。 */
    vireo_result_t result; /* 首错误，不被finally覆盖。 */
    bool execute_succeeded; /* 最近一次execute已收到成功响应，独立于后续inspect。 */
} migration_context_t;

/* 固定字节编码；不读取结构体padding或宿主字节序。 */
static void big_endian(uint32_t n, unsigned char b[4])
{
    b[0]=(unsigned char)(n>>24); b[1]=(unsigned char)(n>>16);
    b[2]=(unsigned char)(n>>8); b[3]=(unsigned char)n;
}
/* 私有：调用者已验证目录；输出仅在完整digest成功后提交。 */
vireo_result_t vireo_mysql_migration_hash(const vireo_mysql_migration_t *m, unsigned char out[32])
{
    static const unsigned char domain[]="vireo.mysql.migration.v1";
    EVP_MD_CTX *ctx=EVP_MD_CTX_new();
    if (!ctx) { return VIREO_RESULT_NO_MEMORY; }
    unsigned char b[4],digest[32]; unsigned int length=0;
    int ok=EVP_DigestInit_ex(ctx,EVP_sha256(),NULL);
    if (ok==1) { ok=EVP_DigestUpdate(ctx,domain,sizeof(domain)); }
    big_endian(m->version,b);
    if (ok==1) { ok=EVP_DigestUpdate(ctx,b,sizeof(b)); }
    big_endian((uint32_t)m->step_count,b);
    if (ok==1) { ok=EVP_DigestUpdate(ctx,b,sizeof(b)); }
    for (size_t i=0;ok==1 && i<m->step_count;++i) {
        big_endian((uint32_t)m->steps[i].sql_length,b);
        ok=EVP_DigestUpdate(ctx,b,sizeof(b));
        if (ok==1) { ok=EVP_DigestUpdate(ctx,m->steps[i].sql,m->steps[i].sql_length); }
    }
    if (ok==1) { ok=EVP_DigestFinal_ex(ctx,digest,&length); }
    EVP_MD_CTX_free(ctx);
    if (ok!=1 || length!=32) { return VIREO_RESULT_INTERNAL; }
    memcpy(out,digest,32); return VIREO_OK;
}
/* 私有：已验证规范ASCII库名；62字节锁名加NUL。 */
vireo_result_t vireo_mysql_migration_lock_name(const char *database, char out[63])
{
    static const char hex[]="0123456789abcdef";
    unsigned char digest[32]; unsigned int n=0;
    if (EVP_Digest(database,strlen(database),digest,&n,EVP_sha256(),NULL)!=1 || n!=32) {
        return VIREO_RESULT_INTERNAL;
    }
    memcpy(out,"vireo:migrate:",14);
    for (size_t i=0;i<24;++i) { out[14+i*2]=hex[digest[i]>>4]; out[15+i*2]=hex[digest[i]&15]; }
    out[62]='\0'; return VIREO_OK;
}
const vireo_mysql_migration_ops_t vireo_mysql_migration_native_ops={
    vireo_mysql_connection_open,vireo_mysql_connection_destroy,
    vireo_mysql_statement_prepare,vireo_mysql_statement_inspect,
    vireo_mysql_statement_execute,vireo_mysql_statement_fetch,
    vireo_mysql_statement_column,vireo_mysql_statement_destroy,vireo_mysql_migration_hash
};

/**
 * @brief 固定首因；数据库码短借复制，无SQL/错误文本。
 *
 * @param[in,out] c
 *     本次独占上下文；已有首因则保持。
 * @param[in] r
 *     本次结果，OK不更新。
 * @param[in] issue
 *     本层逻辑原因。
 * @param[in] database
 *     可选短借诊断，立即复制。
 *
 * @note 不分配；STEP之外清零failed_step。
 */
static void fail(migration_context_t *c, vireo_result_t r,
    vireo_mysql_migration_issue_t issue, const vireo_mysql_error_t *database)
{
    if (r==VIREO_OK || c->result!=VIREO_OK) { return; }
    c->result=r; c->error.stage=c->phase; c->error.issue=issue;
    if (database) { c->error.database=*database; }
    if (c->phase!=VIREO_MYSQL_MIGRATION_STAGE_STEP) { c->report->failed_step=0; }
}
/**
 * @brief 独立记录首清理错误，无主因才提升为返回错误。
 *
 * @param[in,out] c
 *     本次独占上下文。
 * @param[in] r
 *     清理结果，OK忽略。
 * @param[in] stage
 *     清理失败阶段。
 * @param[in] e
 *     可选短借诊断，立即复制。
 *
 * @note 保留既有主因与首清理错误，临时阶段在返回前恢复。
 */
static void cleanup_failure(migration_context_t *c,vireo_result_t r,
    vireo_mysql_migration_stage_t stage,const vireo_mysql_error_t *e)
{
    if (r==VIREO_OK) { return; }
    if (c->error.cleanup_result==VIREO_OK) {
        c->error.cleanup_result=r; c->error.cleanup_stage=stage;
        if (e) { c->error.cleanup_database=*e; }
    }
    vireo_mysql_migration_stage_t old=c->phase; c->phase=stage;
    fail(c,r,VIREO_MYSQL_MIGRATION_ISSUE_NONE,e); c->phase=old;
}
/**
 * @brief 销毁当前statement，错误纳入首清理诊断。
 *
 * @param[in,out] c
 *     本次独占上下文，statement可为空。
 *
 * @note 按底层返回后的实际owner判断，不能假定报错意味着未消耗。
 */
static void stop(migration_context_t *c)
{
    if (c->statement) {
        vireo_mysql_error_t e={0};
        vireo_result_t r=c->ops->destroy(c->thread,&c->statement,&e);
        cleanup_failure(c,r,VIREO_MYSQL_MIGRATION_STAGE_CLOSE,&e);
    }
}
/**
 * @brief 准备并执行一条固定SQL，检查结果形状。
 *
 * @param[in,out] c
 *     独占上下文；必须没有旧statement。
 * @param[in] sql
 *     调用期短借SQL字节，不要求NUL。
 * @param[in] length
 *     已验证的SQL字节长度。
 * @param[in] p
 *     短借参数数组，count为0可为空。
 * @param[in] count
 *     期望参数数。
 * @param[in] columns
 *     期望结果列数。
 * @param[in] write
 *     是否将execution_started计入写尝试。
 * @param[out] execution
 *     必需已清零执行报告，底层按其合同更新。
 *
 * @return true仅执行和形状检查全成功；false固定首因。
 *
 * @note statement保留在c中，由调用者stop；execute_succeeded保留成功响应事实。
 */
static bool start(migration_context_t *c,const char *sql,size_t length,
    const vireo_mysql_parameter_t *p,size_t count,size_t columns,bool write,
    vireo_mysql_execution_t *execution)
{
    c->execute_succeeded=false;
    vireo_mysql_statement_limits_t limits={count,columns,1024,4096,262144};
    vireo_mysql_error_t e={0}; vireo_mysql_statement_info_t info;
    vireo_result_t r=c->ops->prepare(c->thread,c->connection,sql,length,&limits,&c->statement,&e);
    if (r!=VIREO_OK) { fail(c,r,VIREO_MYSQL_MIGRATION_ISSUE_NONE,&e); return false; }
    r=c->ops->execute(c->thread,c->statement,p,count,execution,&e);
    if (write && execution->execution_started) { c->report->write_attempted=true; }
    if (r!=VIREO_OK) { fail(c,r,VIREO_MYSQL_MIGRATION_ISSUE_NONE,&e); return false; }
    c->execute_succeeded=true;
    r=c->ops->inspect(c->thread,c->statement,&info);
    if (r!=VIREO_OK) { fail(c,r,VIREO_MYSQL_MIGRATION_ISSUE_NONE,NULL); return false; }
    if (info.parameter_count!=count || info.column_count!=columns || execution->has_result!=(columns!=0)) {
        fail(c,VIREO_RESULT_DATABASE,VIREO_MYSQL_MIGRATION_ISSUE_UNEXPECTED_RESULT,NULL); return false;
    }
    return true;
}
/**
 * @brief 读取下一行并固定首个读取错误。
 *
 * @param[in,out] c
 *     独占上下文，必须持有结果statement。
 *
 * @return true表示一行；false表示EOF或错误，用c.result区分。
 *
 * @note 当前行借用视图在下一次fetch或stop失效。
 */
static bool next(migration_context_t *c)
{
    vireo_mysql_fetch_outcome_t outcome; vireo_mysql_error_t e={0};
    vireo_result_t r=c->ops->fetch(c->thread,c->statement,&outcome,&e);
    if (r!=VIREO_OK) { fail(c,r,VIREO_MYSQL_MIGRATION_ISSUE_NONE,&e); return false; }
    return outcome==VIREO_MYSQL_FETCH_ROW;
}
/**
 * @brief 读取当前单元格的只读短借视图。
 *
 * @param[in,out] c
 *     持有当前结果行的独占上下文。
 * @param[in] i
 *     已知结果形状内的0基列号。
 *
 * @return 成功返回底层视图；失败返回零视图并固定c.result。
 *
 * @note 不复制数据，视图在下一次fetch或stop失效；必须先检查c.result再信任值。
 */
static vireo_mysql_cell_view_t cell(migration_context_t *c,size_t i)
{
    vireo_mysql_cell_view_t v={0};
    vireo_result_t r=c->ops->column(c->thread,c->statement,i,&v);
    fail(c,r,VIREO_MYSQL_MIGRATION_ISSUE_NONE,NULL); return v;
}
/**
 * @brief 比较当前单元格与固定字节串。
 *
 * @param[in,out] c
 *     持有当前结果行的独占上下文；底层错误写入首因。
 * @param[in] i
 *     合法0基列号。
 * @param[in] s
 *     必需NUL结尾只读期望值。
 *
 * @return true仅非NULL且字节相同；false也可能有底层错误，查看c.result。
 *
 * @note 比较在短借视图有效期内完成，不保存地址。
 */
static bool equals(migration_context_t *c,size_t i,const char *s)
{
    vireo_mysql_cell_view_t v=cell(c,i); size_t n=strlen(s);
    return c->result==VIREO_OK && !v.is_null && v.length==n && (!n || memcmp(v.data,s,n)==0);
}
static void shape(migration_context_t *c,vireo_mysql_migration_issue_t issue)
{
    fail(c,VIREO_RESULT_DATABASE,issue,NULL);
}
/**
 * @brief 解析严格uint32十进制单元格。
 *
 * @param[in,out] c
 *     当前结果行上下文。
 * @param[in] i
 *     合法0基列号。
 * @param[out] out
 *     必需输出，仅成功写入。
 *
 * @return true解析成功；false包括底层错误、NULL、空、非数字和溢出。
 *
 * @note 解析拒绝由调用者按所在语义阶段设置shape首因。
 */
static bool number(migration_context_t *c,size_t i,uint32_t *out)
{
    vireo_mysql_cell_view_t v=cell(c,i); uint32_t n=0;
    if (c->result!=VIREO_OK || v.is_null || !v.length) { return false; }
    for (size_t j=0;j<v.length;++j) {
        if (v.data[j]<'0' || v.data[j]>'9' ||
            vireo_checked_u32_mul(n,10,&n)!=VIREO_OK ||
            vireo_checked_u32_add(n,(uint32_t)(v.data[j]-'0'),&n)!=VIREO_OK) { return false; }
    }
    *out=n; return true;
}
/**
 * @brief 执行恰一行一列整数查询并关闭statement。
 *
 * @param[in,out] c
 *     无旧statement的独占上下文。
 * @param[in] sql
 *     必需NUL结尾可信固定查询。
 * @param[in] p
 *     短借参数，count为0可为空。
 * @param[in] count
 *     参数数。
 * @param[out] out
 *     必需整数存储，失败时不可依赖。
 *
 * @return true表示值与行数均有效且语句清理成功；false固定首因。
 *
 * @note NULL/空结果/额外行均拒绝；准备失败遗留owner由外层finally处理。
 */
static bool scalar(migration_context_t *c,const char *sql,
    const vireo_mysql_parameter_t *p,size_t count,uint32_t *out)
{
    vireo_mysql_execution_t execution={0};
    if (!start(c,sql,strlen(sql),p,count,1,false,&execution)) { return false; }
    if (!next(c) || !number(c,0,out)) { shape(c,VIREO_MYSQL_MIGRATION_ISSUE_UNEXPECTED_RESULT); }
    if (c->result==VIREO_OK && next(c)) { shape(c,VIREO_MYSQL_MIGRATION_ISSUE_UNEXPECTED_RESULT); }
    stop(c); return c->result==VIREO_OK;
}
/**
 * @brief 为内部库名或锁名构造只读参数视图。
 *
 * @param[in] s
 *     必需NUL结尾字符串，须覆盖使用该参数的查询寿命。
 *
 * @return 不拥有s的TEXT参数值。
 *
 * @note 不分配或复制，不保留到本次调用之外。
 */
static vireo_mysql_parameter_t text(const char *s)
{
    vireo_mysql_parameter_t p={.kind=VIREO_MYSQL_PARAMETER_TEXT,.value.span={s,strlen(s)}}; return p;
}
/**
 * @brief 检查规范库名和全部目录，数据库副作用之前拒绝非法输入。
 *
 * @param[in] o
 *     必需连接options，库名只读短借。
 * @param[in] m
 *     完整只读目录，count为0可为空。
 * @param[in] count
 *     目录版本数。
 *
 * @retval VIREO_OK
 *     全部输入通过。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     地址/库名/序列/SQL字节非法。
 * @retval VIREO_RESULT_RANGE
 *     硬上限超出。
 * @retval VIREO_RESULT_OVERFLOW
 *     checked求和溢出。
 *
 * @note 不解析SQL语法；静态可信DDL是调用者前置。
 */
static vireo_result_t validate(const vireo_mysql_connection_options_t *o,
    const vireo_mysql_migration_t *m,size_t count)
{
    if (!o || !o->database || (count && !m)) { return VIREO_RESULT_INVALID_ARGUMENT; }
    if (count>VIREO_MYSQL_MIGRATIONS_MAX) { return VIREO_RESULT_RANGE; }
    size_t n=0;
    while (n<=64 && o->database[n]) {
        unsigned char ch=(unsigned char)o->database[n];
        if (!((ch>='a' && ch<='z') || (n && ((ch>='0' && ch<='9') || ch=='_')))) {
            return VIREO_RESULT_INVALID_ARGUMENT;
        }
        ++n;
    }
    if (!n || n>64) { return VIREO_RESULT_INVALID_ARGUMENT; }
    size_t total=0,bytes=0;
    for (size_t i=0;i<count;++i) {
        if (m[i].version!=i+1 || !m[i].steps || !m[i].step_count) { return VIREO_RESULT_INVALID_ARGUMENT; }
        vireo_result_t r=vireo_checked_size_add(total,m[i].step_count,&total);
        if (r!=VIREO_OK) { return r; }
        if (m[i].step_count>VIREO_MYSQL_MIGRATION_STEPS_MAX || total>VIREO_MYSQL_MIGRATION_TOTAL_STEPS_MAX) { return VIREO_RESULT_RANGE; }
        for (size_t j=0;j<m[i].step_count;++j) {
            const vireo_mysql_migration_step_t *s=&m[i].steps[j];
            if (!s->sql || !s->sql_length) { return VIREO_RESULT_INVALID_ARGUMENT; }
            r=vireo_checked_size_add(bytes,s->sql_length,&bytes);
            if (r!=VIREO_OK) { return r; }
            if (s->sql_length>VIREO_MYSQL_SQL_MAX || bytes>VIREO_MYSQL_MIGRATION_SQL_BYTES_MAX) { return VIREO_RESULT_RANGE; }
            if (memchr(s->sql,0,s->sql_length)) { return VIREO_RESULT_INVALID_ARGUMENT; }
        }
    }
    return VIREO_OK;
}
/**
 * @brief 读取保留版本表身份，存在时必须为精确命名的InnoDB基表。
 *
 * @param[in,out] c
 *     持锁专用连接上下文。
 * @param[in] p
 *     一个库名TEXT参数，只读短借。
 * @param[out] exists
 *     必需输出，仅成功时可信。
 *
 * @return true表示查询及语句关闭成功；false固定首因。
 *
 * @note 不存在允许bootstrap；同名view或不兼容表直接拒绝。
 */
static bool table(migration_context_t *c,const vireo_mysql_parameter_t *p,bool *exists)
{
    const char *sql="SELECT TABLE_TYPE,ENGINE,TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA=? AND TABLE_NAME='vireo_schema_migrations'";
    vireo_mysql_execution_t ex={0};
    if (!start(c,sql,strlen(sql),p,1,3,false,&ex)) { return false; }
    *exists=next(c);
    if (*exists && (!equals(c,0,"BASE TABLE") || !equals(c,1,"InnoDB") || !equals(c,2,"vireo_schema_migrations"))) {
        shape(c,VIREO_MYSQL_MIGRATION_ISSUE_METADATA_SHAPE);
    }
    if (c->result==VIREO_OK && *exists && next(c)) { shape(c,VIREO_MYSQL_MIGRATION_ISSUE_METADATA_SHAPE); }
    stop(c); return c->result==VIREO_OK;
}
/**
 * @brief 拒绝没有已应用历史却已有其他表或视图的未知基线。
 *
 * @param[in,out] c
 *     持锁专用连接上下文，无旧statement。
 * @param[in] p
 *     一个库名TEXT参数，只读短借。
 *
 * @return true表示查询及清理成功且计数为0；false固定首因。
 *
 * @note 只观察，不采纳已有结构、不删除用户数据。
 */
static bool empty_schema(migration_context_t *c,const vireo_mysql_parameter_t *p)
{
    uint32_t n=0;
    if (!scalar(c,"SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=? AND TABLE_NAME<>'vireo_schema_migrations'",p,1,&n)) { return false; }
    if (n) { shape(c,VIREO_MYSQL_MIGRATION_ISSUE_UNTRACKED_SCHEMA); }
    return c->result==VIREO_OK;
}
/**
 * @brief 核对保留版本表的完整可见结构。
 *
 * @param[in,out] c
 *     持锁专用连接上下文，表身份已验证。
 * @param[in] p
 *     一个库名TEXT参数，只读短借。
 *
 * @return true表示固定三列、唯一完整主键及全部附加结构检查通过；false停止。
 *
 * @note 每次只保留一个statement；账号的充分元数据可见性为前置。
 */
static bool metadata(migration_context_t *c,const vireo_mysql_parameter_t *p)
{
    static const char *const names[]={"version","checksum","state"};
    static const char *const types[]={"int unsigned","binary(32)","tinyint unsigned"};
    static const char *const legacy[]={"int(10) unsigned","binary(32)","tinyint(3) unsigned"};
    const char *sql="SELECT COLUMN_NAME,COLUMN_TYPE,IS_NULLABLE,COLUMN_DEFAULT,EXTRA,GENERATION_EXPRESSION FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=? AND TABLE_NAME='vireo_schema_migrations' ORDER BY ORDINAL_POSITION";
    vireo_mysql_execution_t ex={0};
    if (!start(c,sql,strlen(sql),p,1,6,false,&ex)) { return false; }
    size_t i=0;
    while (c->result==VIREO_OK && next(c)) {
        if (i==3 || !equals(c,0,names[i]) || (!equals(c,1,types[i]) && !equals(c,1,legacy[i])) ||
            !equals(c,2,"NO") || !cell(c,3).is_null || !equals(c,4,"") || !equals(c,5,"")) {
            shape(c,VIREO_MYSQL_MIGRATION_ISSUE_METADATA_SHAPE); break;
        }
        ++i;
    }
    if (i!=3) { shape(c,VIREO_MYSQL_MIGRATION_ISSUE_METADATA_SHAPE); }
    stop(c); if (c->result!=VIREO_OK) { return false; }
    sql="SELECT INDEX_NAME,NON_UNIQUE,SEQ_IN_INDEX,COLUMN_NAME,SUB_PART,INDEX_TYPE FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=? AND TABLE_NAME='vireo_schema_migrations' ORDER BY INDEX_NAME,SEQ_IN_INDEX";
    if (!start(c,sql,strlen(sql),p,1,6,false,&ex)) { return false; }
    if (!next(c) || !equals(c,0,"PRIMARY") || !equals(c,1,"0") || !equals(c,2,"1") ||
        !equals(c,3,"version") || !cell(c,4).is_null || !equals(c,5,"BTREE")) { shape(c,VIREO_MYSQL_MIGRATION_ISSUE_METADATA_SHAPE); }
    if (c->result==VIREO_OK && next(c)) { shape(c,VIREO_MYSQL_MIGRATION_ISSUE_METADATA_SHAPE); }
    stop(c); if (c->result!=VIREO_OK) { return false; }
    static const char *const checks[]={
        "SELECT COUNT(*) FROM information_schema.TABLE_CONSTRAINTS WHERE TABLE_SCHEMA=? AND TABLE_NAME='vireo_schema_migrations' AND CONSTRAINT_TYPE<>'PRIMARY KEY'",
        "SELECT COUNT(*) FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA=? AND EVENT_OBJECT_TABLE='vireo_schema_migrations'",
        "SELECT COUNT(*) FROM information_schema.PARTITIONS WHERE TABLE_SCHEMA=? AND TABLE_NAME='vireo_schema_migrations' AND PARTITION_NAME IS NOT NULL"};
    for (i=0;i<3;++i) {
        uint32_t n=0;
        if (!scalar(c,checks[i],p,1,&n)) { return false; }
        if (n) { shape(c,VIREO_MYSQL_MIGRATION_ISSUE_METADATA_SHAPE); return false; }
    }
    return true;
}
/**
 * @brief 执行单条无结果写，并保留成功响应确认的进度。
 *
 * @param[in,out] c
 *     独占持锁上下文，没有旧statement。
 * @param[in] sql
 *     可信SQL字节短借。
 * @param[in] length
 *     精确字节长度。
 * @param[in] p
 *     短借参数，count为0可为空。
 * @param[in] count
 *     参数数。
 * @param[in] one
 *     是否必须确认恰影响一行。
 * @param[in] ddl
 *     是否计入迁移步骤完成数。
 *
 * @return true仅写和清理全成功；false保留确认进度与首因。
 *
 * @note execute成功后inspect或destroy失败仍计入确认进度；回复未知不计入、不重试。
 */
static bool write_sql(migration_context_t *c,const char *sql,size_t length,
    const vireo_mysql_parameter_t *p,size_t count,bool one,bool ddl)
{
    vireo_mysql_execution_t ex={0};
    bool valid=start(c,sql,length,p,count,0,true,&ex);
    if (c->execute_succeeded && !ex.has_result && ddl) { ++c->report->steps_completed; }
    if (valid && one && ex.affected_rows!=1) { shape(c,VIREO_MYSQL_MIGRATION_ISSUE_UNEXPECTED_RESULT); }
    /* 完成标记的成功响应已收到，后续语句close失败也不抹去提交事实。 */
    if (c->execute_succeeded && !ex.has_result && one && ex.affected_rows==1 &&
        c->phase==VIREO_MYSQL_MIGRATION_STAGE_APPLIED) {
        ++c->report->migrations_applied; c->report->applied_after=c->report->failed_version;
    }
    stop(c); return c->result==VIREO_OK;
}
/**
 * @brief 流式核对完整连续历史及每项hash和状态。
 *
 * @param[in,out] c
 *     持锁上下文，无旧statement。
 * @param[in] hashes
 *     count个预计算32字节hash，只读短借。
 * @param[in] count
 *     完整目录长度0..128。
 * @param[in] database
 *     一个库名TEXT参数。
 *
 * @return true表示全部历史合法，报告前缀有效；false固定首因。
 *
 * @note 只有全部历史通过才设置history_validated；空历史还须拒绝未知基线。
 */
static bool history(migration_context_t *c,const unsigned char hashes[][32],size_t count,
    const vireo_mysql_parameter_t *database)
{
    const char *sql="SELECT version,checksum,state FROM vireo_schema_migrations ORDER BY version";
    vireo_mysql_execution_t ex={0}; uint32_t n=0;
    if (!start(c,sql,strlen(sql),NULL,0,3,false,&ex)) { return false; }
    while (c->result==VIREO_OK && next(c)) {
        uint32_t version=0,state=0;
        if (!number(c,0,&version)) { shape(c,VIREO_MYSQL_MIGRATION_ISSUE_HISTORY_SHAPE); break; }
        c->report->failed_version=version;
        if (version!=n+1) { shape(c,VIREO_MYSQL_MIGRATION_ISSUE_HISTORY_SHAPE); break; }
        if (version>count) { shape(c,VIREO_MYSQL_MIGRATION_ISSUE_VERSION_AHEAD); break; }
        if (!number(c,2,&state) || state>1) { shape(c,VIREO_MYSQL_MIGRATION_ISSUE_HISTORY_SHAPE); break; }
        if (!state) { shape(c,VIREO_MYSQL_MIGRATION_ISSUE_DIRTY); break; }
        vireo_mysql_cell_view_t checksum=cell(c,1);
        if (checksum.is_null || checksum.length!=32) { shape(c,VIREO_MYSQL_MIGRATION_ISSUE_HISTORY_SHAPE); break; }
        if (memcmp(checksum.data,hashes[n],32)) { shape(c,VIREO_MYSQL_MIGRATION_ISSUE_CHECKSUM); break; }
        ++n;
    }
    stop(c); if (c->result!=VIREO_OK) { return false; }
    c->report->failed_version=0;
    if (!n && !empty_schema(c,database)) { return false; }
    c->report->history_validated=true; c->report->applied_before=n; c->report->applied_after=n;
    return true;
}
/**
 * @brief 在持锁专用连接上校验历史并应用新增版本。
 *
 * @param[in,out] c
 *     已确认取锁的独占上下文。
 * @param[in] m
 *     完整已验证目录，只读短借。
 * @param[in] count
 *     目录长度0..128。
 * @param[in] hashes
 *     对应预计算hash，只读短借。
 * @param[in] database
 *     一个库名TEXT参数。
 *
 * @note 失败立即停止；dirty先确认，DDL全部成功后才写applied，最终owner由外层finally清理。
 */
static void run_locked(migration_context_t *c,const vireo_mysql_migration_t *m,size_t count,
    const unsigned char hashes[][32],const vireo_mysql_parameter_t *database)
{
    c->phase=VIREO_MYSQL_MIGRATION_STAGE_BOOTSTRAP; bool exists=false;
    if (!table(c,database,&exists)) { return; }
    if (!exists) {
        if (!empty_schema(c,database)) { return; }
        const char *sql="CREATE TABLE IF NOT EXISTS vireo_schema_migrations (version INT UNSIGNED NOT NULL,checksum BINARY(32) NOT NULL,state TINYINT UNSIGNED NOT NULL,PRIMARY KEY (version)) ENGINE=InnoDB";
        if (!write_sql(c,sql,strlen(sql),NULL,0,false,false) || !table(c,database,&exists)) { return; }
        if (!exists) { shape(c,VIREO_MYSQL_MIGRATION_ISSUE_METADATA_SHAPE); return; }
    }
    if (!metadata(c,database)) { return; }
    c->phase=VIREO_MYSQL_MIGRATION_STAGE_HISTORY;
    if (!history(c,hashes,count,database)) { return; }
    for (size_t i=c->report->applied_before;i<count;++i) {
        c->report->failed_version=m[i].version; c->phase=VIREO_MYSQL_MIGRATION_STAGE_DIRTY;
        vireo_mysql_parameter_t p[2]={
            {.kind=VIREO_MYSQL_PARAMETER_U64,.value.u64=m[i].version},
            {.kind=VIREO_MYSQL_PARAMETER_BYTES,.value.span={hashes[i],32}}};
        const char *sql="INSERT INTO vireo_schema_migrations(version,checksum,state) VALUES(?,?,0)";
        if (!write_sql(c,sql,strlen(sql),p,2,true,false)) { return; }
        c->phase=VIREO_MYSQL_MIGRATION_STAGE_STEP;
        for (size_t j=0;j<m[i].step_count;++j) {
            c->report->failed_step=(uint32_t)j+1;
            if (!write_sql(c,m[i].steps[j].sql,m[i].steps[j].sql_length,NULL,0,false,true)) { return; }
        }
        c->report->failed_step=0; c->phase=VIREO_MYSQL_MIGRATION_STAGE_APPLIED;
        sql="UPDATE vireo_schema_migrations SET state=1 WHERE version=? AND checksum=? AND state=0";
        if (!write_sql(c,sql,strlen(sql),p,2,true,false)) { return; }
    }
    c->report->failed_version=0;
}

vireo_result_t vireo_mysql_migration_apply_with_ops(vireo_mysql_thread_t *thread,
    const vireo_mysql_connection_options_t *options,const vireo_mysql_migration_t *m,size_t count,
    vireo_mysql_migration_report_t *report,vireo_mysql_migration_error_t *error,
    const vireo_mysql_migration_ops_t *ops)
{
    int saved=errno; vireo_mysql_migration_report_t dummy={0};
    if (report) { memset(report,0,sizeof(*report)); }
    if (error) { memset(error,0,sizeof(*error)); }
    migration_context_t c={.ops=ops,.thread=thread,.report=report ? report : &dummy,
        .phase=VIREO_MYSQL_MIGRATION_STAGE_VALIDATE};
    vireo_result_t r=(!thread || !report) ? VIREO_RESULT_INVALID_ARGUMENT : validate(options,m,count);
    fail(&c,r,VIREO_MYSQL_MIGRATION_ISSUE_NONE,NULL);
    unsigned char hashes[VIREO_MYSQL_MIGRATIONS_MAX][32]; char lock[63]; bool locked=false;
    if (c.result==VIREO_OK) {
        c.phase=VIREO_MYSQL_MIGRATION_STAGE_HASH;
        for (size_t i=0;c.result==VIREO_OK && i<count;++i) { fail(&c,ops->hash(&m[i],hashes[i]),VIREO_MYSQL_MIGRATION_ISSUE_NONE,NULL); }
        if (c.result==VIREO_OK) { fail(&c,vireo_mysql_migration_lock_name(options->database,lock),VIREO_MYSQL_MIGRATION_ISSUE_NONE,NULL); }
    }
    if (c.result==VIREO_OK) {
        c.phase=VIREO_MYSQL_MIGRATION_STAGE_OPEN; vireo_mysql_error_t e={0};
        r=ops->open(thread,options,&c.connection,&e); fail(&c,r,VIREO_MYSQL_MIGRATION_ISSUE_NONE,&e);
    }
    if (c.result==VIREO_OK) {
        c.phase=VIREO_MYSQL_MIGRATION_STAGE_LOCK;
        vireo_mysql_execution_t ex={0}; const char *sql="SELECT DATABASE()";
        if (start(&c,sql,strlen(sql),NULL,0,1,false,&ex)) {
            if (!next(&c) || !equals(&c,0,options->database)) { shape(&c,VIREO_MYSQL_MIGRATION_ISSUE_UNEXPECTED_RESULT); }
            if (c.result==VIREO_OK && next(&c)) { shape(&c,VIREO_MYSQL_MIGRATION_ISSUE_UNEXPECTED_RESULT); }
        }
        stop(&c);
        if (c.result==VIREO_OK) {
            vireo_mysql_parameter_t p=text(lock); uint32_t granted=0;
            if (scalar(&c,"SELECT GET_LOCK(?,0)",&p,1,&granted)) {
                if (granted==1) { locked=true; }
                else if (!granted) { fail(&c,VIREO_RESULT_BUSY,VIREO_MYSQL_MIGRATION_ISSUE_NONE,NULL); }
                else { shape(&c,VIREO_MYSQL_MIGRATION_ISSUE_UNEXPECTED_RESULT); }
            }
        }
        if (c.result==VIREO_OK) {
            vireo_mysql_parameter_t database=text(options->database);
            run_locked(&c,m,count,(const unsigned char (*)[32])hashes,&database);
        }
    }
    stop(&c);
    if (locked && !c.statement) {
        /* 清理路径暂时隔离主因，使解锁查询能运行并单独留存其失败。 */
        vireo_mysql_migration_report_t cleanup_report=*c.report;
        migration_context_t cleanup=c; cleanup.result=VIREO_OK; cleanup.report=&cleanup_report;
        memset(&cleanup.error,0,sizeof(cleanup.error)); cleanup.phase=VIREO_MYSQL_MIGRATION_STAGE_UNLOCK;
        uint32_t released=0; vireo_mysql_parameter_t p=text(lock);
        if (scalar(&cleanup,"SELECT RELEASE_LOCK(?)",&p,1,&released) && released!=1) {
            shape(&cleanup,VIREO_MYSQL_MIGRATION_ISSUE_UNEXPECTED_RESULT);
        }
        stop(&cleanup); c.statement=cleanup.statement;
        cleanup_failure(&c,cleanup.result,cleanup.error.stage,&cleanup.error.database);
    }
    if (c.connection) {
        r=ops->close(thread,&c.connection);
        cleanup_failure(&c,r,VIREO_MYSQL_MIGRATION_STAGE_CLOSE,NULL);
        c.report->connection_closed=!c.connection;
    }
    c.report->ready=c.result==VIREO_OK;
    if (error) { *error=c.error; }
    errno=saved; return c.result;
}

vireo_result_t vireo_mysql_migration_apply(vireo_mysql_thread_t *thread,
    const vireo_mysql_connection_options_t *connection,const vireo_mysql_migration_t *migrations,
    size_t count,vireo_mysql_migration_report_t *report,vireo_mysql_migration_error_t *error)
{
    return vireo_mysql_migration_apply_with_ops(thread,connection,migrations,count,report,error,
        &vireo_mysql_migration_native_ops);
}
