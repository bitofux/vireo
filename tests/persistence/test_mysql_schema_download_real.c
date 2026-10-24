/*
 * PROJECT : VIREO
 * FILE    : test_mysql_schema_download_real.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-19
 * BRIEF   : 真实v7下载快照/来源/ACK约束与含v6十一表数据升级。
 */
#define _POSIX_C_SOURCE 200809L
#include <vireo/persistence/mysql_schema.h>
#include <vireo/persistence/mysql_statement.h>
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(call) do { errno=EDOM; vireo_result_t result_=(call); if(result_!=VIREO_OK) { fprintf(stderr,"line %d result %d\n",__LINE__,(int)result_); abort(); } assert(errno==EDOM); } while(0)
#define U64(v) ((vireo_mysql_parameter_t){.kind=VIREO_MYSQL_PARAMETER_U64,.value.u64=(v)})
#define I64(v) ((vireo_mysql_parameter_t){.kind=VIREO_MYSQL_PARAMETER_I64,.value.i64=(v)})
#define NIL ((vireo_mysql_parameter_t){.kind=VIREO_MYSQL_PARAMETER_NULL})
#define BYTES(p,n) ((vireo_mysql_parameter_t){.kind=VIREO_MYSQL_PARAMETER_BYTES,.value.span={(p),(n)}})
#define SNAPSHOT_CAPACITY 32768
static vireo_mysql_thread_t *thread;
static vireo_mysql_connection_t *connection;
static const vireo_mysql_statement_limits_t limits={32,16,4096,4096,262144};
static size_t rejected;
static const char insert_task[]="INSERT INTO download_tasks(id,public_id,user_id,file_node_id,idempotency_key,object_hash,size,manifest_version,part_count,state,acked_bytes,version,cancel_requested,last_status,created_at_ms,updated_at_ms,expires_at_ms,finished_at_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";
static const char insert_part[]="INSERT INTO download_parts(task_id,part_index,byte_offset,byte_length,chunk_hash,state,acked_bytes,version,source_kind,source_node_id,source_node_generation,source_replica_generation,lease_id,lease_issued_at_ms,lease_expires_at_ms,created_at_ms,updated_at_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";
static const char snapshot_sql[]=
"SELECT CONCAT_WS('|','download_tasks',COALESCE(HEX(id),'N'),COALESCE(HEX(public_id),'N'),COALESCE(HEX(user_id),'N'),COALESCE(HEX(file_node_id),'N'),COALESCE(HEX(idempotency_key),'N'),COALESCE(HEX(object_hash),'N'),COALESCE(HEX(size),'N'),COALESCE(HEX(manifest_version),'N'),COALESCE(HEX(part_count),'N'),COALESCE(HEX(state),'N'),COALESCE(HEX(acked_bytes),'N'),COALESCE(HEX(version),'N'),COALESCE(HEX(cancel_requested),'N'),COALESCE(HEX(last_status),'N'),COALESCE(HEX(created_at_ms),'N'),COALESCE(HEX(updated_at_ms),'N'),COALESCE(HEX(expires_at_ms),'N'),COALESCE(HEX(finished_at_ms),'N')) AS v FROM download_tasks UNION ALL SELECT CONCAT_WS('|','download_parts',COALESCE(HEX(task_id),'N'),COALESCE(HEX(part_index),'N'),COALESCE(HEX(byte_offset),'N'),COALESCE(HEX(byte_length),'N'),COALESCE(HEX(chunk_hash),'N'),COALESCE(HEX(state),'N'),COALESCE(HEX(acked_bytes),'N'),COALESCE(HEX(version),'N'),COALESCE(HEX(source_kind),'N'),COALESCE(HEX(source_node_id),'N'),COALESCE(HEX(source_node_generation),'N'),COALESCE(HEX(source_replica_generation),'N'),COALESCE(HEX(lease_id),'N'),COALESCE(HEX(lease_issued_at_ms),'N'),COALESCE(HEX(lease_expires_at_ms),'N'),COALESCE(HEX(created_at_ms),'N'),COALESCE(HEX(updated_at_ms),'N')) AS v FROM download_parts ORDER BY v";
static const char seed_snapshot_sql[]=
"SELECT CONCAT_WS('|','users',COALESCE(HEX(id),'N'),COALESCE(HEX(username),'N'),COALESCE(HEX(username_key),'N'),COALESCE(HEX(password_hash),'N'),COALESCE(HEX(status),'N'),COALESCE(HEX(created_at_ms),'N'),COALESCE(HEX(updated_at_ms),'N'),COALESCE(HEX(last_login_at_ms),'N')) AS v FROM users UNION ALL SELECT CONCAT_WS('|','sessions',COALESCE(HEX(id),'N'),COALESCE(HEX(user_id),'N'),COALESCE(HEX(token_digest),'N'),COALESCE(HEX(status),'N'),COALESCE(HEX(issued_at_ms),'N'),COALESCE(HEX(expires_at_ms),'N'),COALESCE(HEX(revoked_at_ms),'N'),COALESCE(HEX(last_seen_at_ms),'N')) AS v FROM sessions UNION ALL SELECT CONCAT_WS('|','objects',COALESCE(HEX(object_hash),'N'),COALESCE(HEX(size),'N'),COALESCE(HEX(state),'N'),COALESCE(HEX(ref_count),'N'),COALESCE(HEX(storage_class),'N'),COALESCE(HEX(created_at_ms),'N'),COALESCE(HEX(updated_at_ms),'N'),COALESCE(HEX(verified_at_ms),'N')) AS v FROM objects UNION ALL SELECT CONCAT_WS('|','file_nodes',COALESCE(HEX(id),'N'),COALESCE(HEX(owner_id),'N'),COALESCE(HEX(parent_id),'N'),COALESCE(HEX(name),'N'),COALESCE(HEX(name_hash),'N'),COALESCE(HEX(node_type),'N'),COALESCE(HEX(state),'N'),COALESCE(HEX(object_hash),'N'),COALESCE(HEX(size),'N'),COALESCE(HEX(created_at_ms),'N'),COALESCE(HEX(updated_at_ms),'N'),COALESCE(HEX(deleted_at_ms),'N'),COALESCE(HEX(live_name),'N'),COALESCE(HEX(active_root_owner),'N')) AS v FROM file_nodes UNION ALL SELECT CONCAT_WS('|','operation_audits',COALESCE(HEX(id),'N'),COALESCE(HEX(request_id),'N'),COALESCE(HEX(user_id),'N'),COALESCE(HEX(session_id),'N'),COALESCE(HEX(action),'N'),COALESCE(HEX(target_type),'N'),COALESCE(HEX(target_id),'N'),COALESCE(HEX(target_hash),'N'),COALESCE(HEX(status),'N'),COALESCE(HEX(latency_us),'N'),COALESCE(HEX(detail),'N'),COALESCE(HEX(occurred_at_ms),'N')) AS v FROM operation_audits UNION ALL SELECT CONCAT_WS('|','upload_tasks',COALESCE(HEX(id),'N'),COALESCE(HEX(public_id),'N'),COALESCE(HEX(user_id),'N'),COALESCE(HEX(file_node_id),'N'),COALESCE(HEX(idempotency_key),'N'),COALESCE(HEX(expected_hash),'N'),COALESCE(HEX(size),'N'),COALESCE(HEX(mode),'N'),COALESCE(HEX(chunk_size),'N'),COALESCE(HEX(chunk_count),'N'),COALESCE(HEX(state),'N'),COALESCE(HEX(received_chunks),'N'),COALESCE(HEX(received_bytes),'N'),COALESCE(HEX(version),'N'),COALESCE(HEX(cancel_requested),'N'),COALESCE(HEX(last_status),'N'),COALESCE(HEX(created_at_ms),'N'),COALESCE(HEX(updated_at_ms),'N'),COALESCE(HEX(expires_at_ms),'N'),COALESCE(HEX(finished_at_ms),'N')) AS v FROM upload_tasks UNION ALL SELECT CONCAT_WS('|','upload_chunks',COALESCE(HEX(task_id),'N'),COALESCE(HEX(chunk_index),'N'),COALESCE(HEX(byte_offset),'N'),COALESCE(HEX(byte_length),'N'),COALESCE(HEX(chunk_hash),'N'),COALESCE(HEX(crc32c),'N'),COALESCE(HEX(state),'N'),COALESCE(HEX(received_at_ms),'N')) AS v FROM upload_chunks UNION ALL SELECT CONCAT_WS('|','chunks',COALESCE(HEX(chunk_hash),'N'),COALESCE(HEX(size),'N'),COALESCE(HEX(state),'N'),COALESCE(HEX(ref_count),'N'),COALESCE(HEX(created_at_ms),'N'),COALESCE(HEX(updated_at_ms),'N'),COALESCE(HEX(verified_at_ms),'N')) AS v FROM chunks UNION ALL SELECT CONCAT_WS('|','object_chunks',COALESCE(HEX(object_hash),'N'),COALESCE(HEX(chunk_index),'N'),COALESCE(HEX(byte_offset),'N'),COALESCE(HEX(byte_length),'N'),COALESCE(HEX(chunk_hash),'N')) AS v FROM object_chunks UNION ALL SELECT CONCAT_WS('|','storage_nodes',COALESCE(HEX(id),'N'),COALESCE(HEX(node_uuid),'N'),COALESCE(HEX(endpoint),'N'),COALESCE(HEX(zone),'N'),COALESCE(HEX(status),'N'),COALESCE(HEX(capacity_bytes),'N'),COALESCE(HEX(used_bytes),'N'),COALESCE(HEX(generation),'N'),COALESCE(HEX(created_at_ms),'N'),COALESCE(HEX(updated_at_ms),'N'),COALESCE(HEX(last_heartbeat_at_ms),'N')) AS v FROM storage_nodes UNION ALL SELECT CONCAT_WS('|','chunk_replicas',COALESCE(HEX(chunk_hash),'N'),COALESCE(HEX(node_id),'N'),COALESCE(HEX(state),'N'),COALESCE(HEX(generation),'N'),COALESCE(HEX(node_generation),'N'),COALESCE(HEX(created_at_ms),'N'),COALESCE(HEX(updated_at_ms),'N'),COALESCE(HEX(verified_at_ms),'N')) AS v FROM chunk_replicas ORDER BY v";
static vireo_mysql_statement_t *query(const char *sql)
{
    vireo_mysql_statement_t *s=NULL; vireo_mysql_error_t e={0};
    errno=EDOM;
    vireo_result_t r=vireo_mysql_statement_prepare(thread,connection,sql,strlen(sql),&limits,&s,&e);
    assert(errno==EDOM);
    if(r!=VIREO_OK) { fprintf(stderr,"query prepare result %d mysql %u\n",(int)r,e.mysql_code); abort(); }
    vireo_mysql_execution_t ex;
    CHECK(vireo_mysql_statement_execute(thread,s,NULL,0,&ex,NULL)); assert(ex.has_result);
    return s;
}
static void destroy(vireo_mysql_statement_t **s)
{
    CHECK(vireo_mysql_statement_destroy(thread,s,NULL)); assert(!*s);
}
static void row(vireo_mysql_statement_t *s,const char *expected)
{
    vireo_mysql_fetch_outcome_t outcome;
    CHECK(vireo_mysql_statement_fetch(thread,s,&outcome,NULL)); assert(outcome==VIREO_MYSQL_FETCH_ROW);
    vireo_mysql_cell_view_t c; CHECK(vireo_mysql_statement_column(thread,s,0,&c));
    if(c.is_null || c.length!=strlen(expected) || memcmp(c.data,expected,c.length)) {
        fprintf(stderr,"metadata/value mismatch expected %s\n",expected); abort();
    }
}
static void done(vireo_mysql_statement_t **s)
{
    vireo_mysql_fetch_outcome_t outcome;
    CHECK(vireo_mysql_statement_fetch(thread,*s,&outcome,NULL)); assert(outcome==VIREO_MYSQL_FETCH_DONE); destroy(s);
}
static void scalar(const char *sql,const char *expected)
{
    vireo_mysql_statement_t *s=query(sql); row(s,expected); done(&s);
}
/**
 * @brief 保存有序单列结果的全部字节，避免只比较行数或可碰撞计数摘要。
 *
 * @param[in] sql
 *     调用期借用可信SELECT，首列必须非NULL且不含换行。
 * @param[out] out
 *     独占SNAPSHOT_CAPACITY字节区；容量不足直接断言失败。
 *
 * @note 逐行view只借到下次fetch，立即复制；结束销毁statement。
 */
static void capture_one(const char *sql,char out[SNAPSHOT_CAPACITY])
{
    size_t used=0; out[0]=0; vireo_mysql_statement_t *s=query(sql);
    for(;;) {
        vireo_mysql_fetch_outcome_t outcome;
        CHECK(vireo_mysql_statement_fetch(thread,s,&outcome,NULL));
        if(outcome==VIREO_MYSQL_FETCH_DONE) { break; }
        assert(outcome==VIREO_MYSQL_FETCH_ROW);
        vireo_mysql_cell_view_t c; CHECK(vireo_mysql_statement_column(thread,s,0,&c));
        assert(!c.is_null && c.length<SNAPSHOT_CAPACITY-used-1);
        assert(!memchr(c.data,'\n',c.length));
        memcpy(out+used,c.data,c.length); used+=c.length; out[used++]='\n'; out[used]=0;
    }
    destroy(&s);
}
/**
 * @brief 组合新两表与旧十一表的完整有序字节快照，避免超长C11字符串字面量。
 *
 * @param[in] sql 借用SELECT；snapshot_sql身份要求同时保存旧十一表。
 * @param[out] out 独占SNAPSHOT_CAPACITY字节；测试数据有界，超出即断言。
 *
 * @note 同一测试连接串行，无并发writer；两段都有表名和NULL标记，不混淆行。
 */
static void capture(const char *sql,char out[SNAPSHOT_CAPACITY])
{
    capture_one(sql,out);
    if(sql==snapshot_sql) {
        char old[SNAPSHOT_CAPACITY]; capture_one(seed_snapshot_sql,old);
        size_t n=strlen(out),m=strlen(old); assert(m<SNAPSHOT_CAPACITY-n);
        memcpy(out+n,old,m+1);
    }
}
/**
 * @brief 执行一条DML；拒绝前后核全部十三业务表行保持。
 *
 * @param[in] sql
 *     可信SQL短借，不打印SQL或参数。
 * @param[in] p
 *     n个参数短借到execute返回；n0时可NULL。
 * @param[in] n
 *     参数数，不超过固定测试limits。
 * @param[in] code
 *     0要求成功；其他要求对应原生错误码，FK容许同SQLSTATE的通用形式。
 * @param[in] line
 *     调用点用于失败诊断。
 *
 * @return 成功执行报告；错误返回报告不作提交证明。
 *
 * @note prepare/execute均可能拒绝；所有活statement配对销毁，errno保持。
 */
static vireo_mysql_execution_t execute_at(const char *sql,const vireo_mysql_parameter_t *p,
    size_t n,unsigned int code,int line)
{
    char before[SNAPSHOT_CAPACITY]; if(code) { capture(snapshot_sql,before); }
    vireo_mysql_statement_t *s=NULL; vireo_mysql_error_t e={0}; vireo_mysql_execution_t ex={0};
    errno=EDOM;
    vireo_result_t result=vireo_mysql_statement_prepare(thread,connection,sql,strlen(sql),&limits,&s,&e);
    assert(errno==EDOM);
    if(result==VIREO_OK) { errno=EDOM; result=vireo_mysql_statement_execute(thread,s,p,n,&ex,&e); assert(errno==EDOM); }
    bool alias=(code==1452 && e.mysql_code==1216) || (code==1451 && e.mysql_code==1217);
    if(result!=(code ? VIREO_RESULT_DATABASE : VIREO_OK) || (e.mysql_code!=code && !alias)) {
        fprintf(stderr,"line %d result %d mysql %u expected %u\n",line,(int)result,e.mysql_code,code); abort();
    }
    if(code==1451 || code==1452 || code==1062 || code==1048) { assert(!memcmp(e.sqlstate,"23000",6)); }
    if(code==3819 || code==1690) { assert(!memcmp(e.sqlstate,code==1690 ? "22003" : "HY000",6)); }
    if(code==1264) { assert(!memcmp(e.sqlstate,"22003",6)); }
    if(code==1406) { assert(!memcmp(e.sqlstate,"22001",6)); }
    if(s) { destroy(&s); }
    if(code) { char after[SNAPSHOT_CAPACITY]; capture(snapshot_sql,after); assert(!strcmp(before,after)); ++rejected; }
    else { assert(!ex.has_result); }
    return ex;
}
#define execute(sql,p,n,code) execute_at((sql),(p),(n),(code),__LINE__)
static void command(const char *sql) { (void)execute(sql,NULL,0,0); }

static void metadata(void)
{
    scalar("SELECT VERSION() REGEXP '^8[.]0[.]'","1");
    scalar("SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE()","14");
    vireo_mysql_statement_t *s=query("SELECT CONCAT_WS('|',TABLE_NAME,ENGINE,TABLE_COLLATION) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME IN ('download_tasks','download_parts') ORDER BY TABLE_NAME");
    row(s,"download_parts|InnoDB|utf8mb4_bin"); row(s,"download_tasks|InnoDB|utf8mb4_bin"); done(&s);
    static const char *const columns[]={
        "download_parts|task_id|bigint unsigned|-|-|NO|NULL||-|-",
        "download_parts|part_index|int unsigned|-|-|NO|NULL||-|-",
        "download_parts|byte_offset|bigint unsigned|-|-|NO|NULL||-|-",
        "download_parts|byte_length|int unsigned|-|-|NO|NULL||-|-",
        "download_parts|chunk_hash|varbinary(32)|32|32|NO|NULL||-|-",
        "download_parts|state|tinyint unsigned|-|-|NO|NULL||-|-",
        "download_parts|acked_bytes|int unsigned|-|-|NO|NULL||-|-",
        "download_parts|version|bigint unsigned|-|-|NO|NULL||-|-",
        "download_parts|source_kind|tinyint unsigned|-|-|NO|NULL||-|-",
        "download_parts|source_node_id|bigint unsigned|-|-|YES|NULL||-|-",
        "download_parts|source_node_generation|bigint unsigned|-|-|YES|NULL||-|-",
        "download_parts|source_replica_generation|bigint unsigned|-|-|YES|NULL||-|-",
        "download_parts|lease_id|varbinary(16)|16|16|YES|NULL||-|-",
        "download_parts|lease_issued_at_ms|bigint unsigned|-|-|YES|NULL||-|-",
        "download_parts|lease_expires_at_ms|bigint unsigned|-|-|YES|NULL||-|-",
        "download_parts|created_at_ms|bigint unsigned|-|-|NO|NULL||-|-",
        "download_parts|updated_at_ms|bigint unsigned|-|-|NO|NULL||-|-",
        "download_tasks|id|bigint unsigned|-|-|NO|NULL|auto_increment|-|-",
        "download_tasks|public_id|varbinary(16)|16|16|NO|NULL||-|-",
        "download_tasks|user_id|bigint unsigned|-|-|NO|NULL||-|-",
        "download_tasks|file_node_id|bigint unsigned|-|-|NO|NULL||-|-",
        "download_tasks|idempotency_key|varbinary(16)|16|16|NO|NULL||-|-",
        "download_tasks|object_hash|binary(32)|32|32|NO|NULL||-|-",
        "download_tasks|size|bigint unsigned|-|-|NO|NULL||-|-",
        "download_tasks|manifest_version|bigint unsigned|-|-|NO|NULL||-|-",
        "download_tasks|part_count|bigint unsigned|-|-|NO|NULL||-|-",
        "download_tasks|state|tinyint unsigned|-|-|NO|NULL||-|-",
        "download_tasks|acked_bytes|bigint unsigned|-|-|NO|NULL||-|-",
        "download_tasks|version|bigint unsigned|-|-|NO|NULL||-|-",
        "download_tasks|cancel_requested|tinyint unsigned|-|-|NO|NULL||-|-",
        "download_tasks|last_status|smallint unsigned|-|-|NO|NULL||-|-",
        "download_tasks|created_at_ms|bigint unsigned|-|-|NO|NULL||-|-",
        "download_tasks|updated_at_ms|bigint unsigned|-|-|NO|NULL||-|-",
        "download_tasks|expires_at_ms|bigint unsigned|-|-|NO|NULL||-|-",
        "download_tasks|finished_at_ms|bigint unsigned|-|-|YES|NULL||-|-"};
    s=query("SELECT CONCAT_WS('|',TABLE_NAME,COLUMN_NAME,COLUMN_TYPE,COALESCE(CAST(CHARACTER_MAXIMUM_LENGTH AS CHAR),'-'),COALESCE(CAST(CHARACTER_OCTET_LENGTH AS CHAR),'-'),IS_NULLABLE,COALESCE(COLUMN_DEFAULT,'NULL'),EXTRA,COALESCE(CHARACTER_SET_NAME,'-'),COALESCE(COLLATION_NAME,'-')) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME IN ('download_tasks','download_parts') ORDER BY TABLE_NAME,ORDINAL_POSITION");
    for(size_t i=0;i<sizeof(columns)/sizeof(columns[0]);++i) { row(s,columns[i]); } done(&s);
    static const char *const indexes[]={
        "download_parts|download_parts_chunk|1|1|chunk_hash|BTREE|-|A|YES",
        "download_parts|download_parts_chunk|1|2|task_id|BTREE|-|A|YES",
        "download_parts|download_parts_chunk|1|3|part_index|BTREE|-|A|YES",
        "download_parts|download_parts_offset_unique|0|1|task_id|BTREE|-|A|YES",
        "download_parts|download_parts_offset_unique|0|2|byte_offset|BTREE|-|A|YES",
        "download_parts|download_parts_source_state|1|1|source_node_id|BTREE|-|A|YES",
        "download_parts|download_parts_source_state|1|2|state|BTREE|-|A|YES",
        "download_parts|download_parts_source_state|1|3|task_id|BTREE|-|A|YES",
        "download_parts|download_parts_source_state|1|4|part_index|BTREE|-|A|YES",
        "download_parts|download_parts_task_state|1|1|task_id|BTREE|-|A|YES",
        "download_parts|download_parts_task_state|1|2|state|BTREE|-|A|YES",
        "download_parts|download_parts_task_state|1|3|part_index|BTREE|-|A|YES",
        "download_parts|PRIMARY|0|1|task_id|BTREE|-|A|YES",
        "download_parts|PRIMARY|0|2|part_index|BTREE|-|A|YES",
        "download_tasks|download_tasks_object|1|1|object_hash|BTREE|-|A|YES",
        "download_tasks|download_tasks_object|1|2|id|BTREE|-|A|YES",
        "download_tasks|download_tasks_public_id_unique|0|1|public_id|BTREE|-|A|YES",
        "download_tasks|download_tasks_state_expiry|1|1|state|BTREE|-|A|YES",
        "download_tasks|download_tasks_state_expiry|1|2|expires_at_ms|BTREE|-|A|YES",
        "download_tasks|download_tasks_state_expiry|1|3|id|BTREE|-|A|YES",
        "download_tasks|download_tasks_user_idempotency_unique|0|1|user_id|BTREE|-|A|YES",
        "download_tasks|download_tasks_user_idempotency_unique|0|2|idempotency_key|BTREE|-|A|YES",
        "download_tasks|download_tasks_user_node|1|1|user_id|BTREE|-|A|YES",
        "download_tasks|download_tasks_user_node|1|2|file_node_id|BTREE|-|A|YES",
        "download_tasks|download_tasks_user_state|1|1|user_id|BTREE|-|A|YES",
        "download_tasks|download_tasks_user_state|1|2|state|BTREE|-|A|YES",
        "download_tasks|download_tasks_user_state|1|3|id|BTREE|-|A|YES",
        "download_tasks|PRIMARY|0|1|id|BTREE|-|A|YES"};
    s=query("SELECT CONCAT_WS('|',TABLE_NAME,INDEX_NAME,NON_UNIQUE,SEQ_IN_INDEX,COLUMN_NAME,INDEX_TYPE,COALESCE(CAST(SUB_PART AS CHAR),'-'),COLLATION,IS_VISIBLE) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME IN ('download_tasks','download_parts') ORDER BY TABLE_NAME,INDEX_NAME,SEQ_IN_INDEX");
    for(size_t i=0;i<sizeof(indexes)/sizeof(indexes[0]);++i) { row(s,indexes[i]); } done(&s);
    static const char *const checks[]={
        "download_parts|download_parts_hash_valid|YES",
        "download_parts|download_parts_length_valid|YES",
        "download_parts|download_parts_progress_valid|YES",
        "download_parts|download_parts_range_valid|YES",
        "download_parts|download_parts_source_kind_valid|YES",
        "download_parts|download_parts_source_valid|YES",
        "download_parts|download_parts_state_valid|YES",
        "download_parts|download_parts_task_valid|YES",
        "download_parts|download_parts_updated_order|YES",
        "download_parts|download_parts_version_valid|YES",
        "download_tasks|download_tasks_cancel_valid|YES",
        "download_tasks|download_tasks_complete_valid|YES",
        "download_tasks|download_tasks_expiry_order|YES",
        "download_tasks|download_tasks_finished_valid|YES",
        "download_tasks|download_tasks_geometry_valid|YES",
        "download_tasks|download_tasks_idempotency_valid|YES",
        "download_tasks|download_tasks_manifest_valid|YES",
        "download_tasks|download_tasks_owner_valid|YES",
        "download_tasks|download_tasks_progress_valid|YES",
        "download_tasks|download_tasks_public_id_valid|YES",
        "download_tasks|download_tasks_state_valid|YES",
        "download_tasks|download_tasks_updated_order|YES",
        "download_tasks|download_tasks_version_valid|YES"};
    s=query("SELECT CONCAT_WS('|',TABLE_NAME,CONSTRAINT_NAME,ENFORCED) FROM information_schema.TABLE_CONSTRAINTS WHERE CONSTRAINT_SCHEMA=DATABASE() AND TABLE_NAME IN ('download_tasks','download_parts') AND CONSTRAINT_TYPE='CHECK' ORDER BY TABLE_NAME,CONSTRAINT_NAME");
    for(size_t i=0;i<sizeof(checks)/sizeof(checks[0]);++i) { row(s,checks[i]); } done(&s);
    static const char *const fks[]={
        "download_parts_chunk_fk|chunk_hash|chunks|chunk_hash|RESTRICT|RESTRICT",
        "download_parts_source_fk|source_node_id|storage_nodes|id|RESTRICT|RESTRICT",
        "download_parts_task_fk|task_id|download_tasks|id|RESTRICT|RESTRICT",
        "download_tasks_node_fk|user_id|file_nodes|owner_id|RESTRICT|RESTRICT",
        "download_tasks_node_fk|file_node_id|file_nodes|id|RESTRICT|RESTRICT",
        "download_tasks_object_fk|object_hash|objects|object_hash|RESTRICT|RESTRICT"};
    s=query("SELECT CONCAT_WS('|',k.CONSTRAINT_NAME,k.COLUMN_NAME,k.REFERENCED_TABLE_NAME,k.REFERENCED_COLUMN_NAME,r.UPDATE_RULE,r.DELETE_RULE) FROM information_schema.KEY_COLUMN_USAGE k JOIN information_schema.REFERENTIAL_CONSTRAINTS r ON k.CONSTRAINT_SCHEMA=r.CONSTRAINT_SCHEMA AND k.CONSTRAINT_NAME=r.CONSTRAINT_NAME WHERE k.CONSTRAINT_SCHEMA=DATABASE() AND k.TABLE_NAME IN ('download_tasks','download_parts') ORDER BY k.CONSTRAINT_NAME,k.ORDINAL_POSITION");
    for(size_t i=0;i<sizeof(fks)/sizeof(fks[0]);++i) { row(s,fks[i]); } done(&s);
    scalar("SELECT COUNT(*) FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA=DATABASE() AND EVENT_OBJECT_TABLE IN ('download_tasks','download_parts')","0");
    scalar("SELECT COUNT(*) FROM information_schema.PARTITIONS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME IN ('download_tasks','download_parts') AND PARTITION_NAME IS NOT NULL","0");
    scalar("SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME IN ('download_tasks','download_parts') AND GENERATION_EXPRESSION<>''","0");
    puts("PASS complete v7 metadata: 35 columns, 12 full indexes, 5 RESTRICT FK, 23 enforced CHECK; no trigger/generated/partition");
}
static void seed(void)
{
    command("INSERT INTO users(username,username_key,password_hash,status,created_at_ms,updated_at_ms) VALUES('display',X'61006200','test-phc',1,0,0)");
    command("INSERT INTO sessions(user_id,token_digest,status,issued_at_ms,expires_at_ms,last_seen_at_ms) VALUES(1,REPEAT(X'BB',32),1,0,100,0)");
    command("INSERT INTO objects(object_hash,size,state,ref_count,storage_class,created_at_ms,updated_at_ms) VALUES(REPEAT(X'BB',32),11,1,0,1,0,0)");
    command("INSERT INTO file_nodes(owner_id,parent_id,name,node_type,state,size,created_at_ms,updated_at_ms) VALUES(1,NULL,'',1,2,0,0,0)");
    command("INSERT INTO file_nodes(owner_id,parent_id,name,node_type,state,size,created_at_ms,updated_at_ms) VALUES(1,1,'upload',2,1,11,0,0)");
    command("INSERT INTO operation_audits(request_id,user_id,session_id,action,target_type,target_id,status,latency_us,detail,occurred_at_ms) VALUES(REPEAT(X'BB',16),1,1,2,3,2,0,7,X'61006200',0)");
    command("INSERT INTO upload_tasks(public_id,user_id,file_node_id,idempotency_key,expected_hash,size,mode,chunk_size,chunk_count,state,received_chunks,received_bytes,version,cancel_requested,last_status,created_at_ms,updated_at_ms,expires_at_ms) VALUES(REPEAT(X'CC',16),1,2,REPEAT(X'DD',16),REPEAT(X'BB',32),11,1,4,3,2,1,4,2,0,0,0,0,100)");
    command("INSERT INTO upload_chunks(task_id,chunk_index,byte_offset,byte_length,chunk_hash,crc32c,state,received_at_ms) VALUES(1,0,0,4,REPEAT(X'EE',32),0,1,0)");
    command("INSERT INTO chunks(chunk_hash,size,state,ref_count,created_at_ms,updated_at_ms,verified_at_ms) VALUES(REPEAT(X'EE',32),4,2,1,0,0,0)");
    command("INSERT INTO object_chunks(object_hash,chunk_index,byte_offset,byte_length,chunk_hash) VALUES(REPEAT(X'BB',32),0,0,4,REPEAT(X'EE',32))");
    command("INSERT INTO storage_nodes(id,node_uuid,endpoint,zone,status,capacity_bytes,used_bytes,generation,created_at_ms,updated_at_ms,last_heartbeat_at_ms) VALUES(1,REPEAT(X'11',16),'vireo.example:7443','zone-a',1,100,4,3,10,20,15)");
    command("INSERT INTO chunk_replicas(chunk_hash,node_id,state,generation,node_generation,created_at_ms,updated_at_ms,verified_at_ms) VALUES(REPEAT(X'EE',32),1,2,9,3,10,20,15)");
}

/* 仅构造已知测试输入；指针借用到同步execute结束，长度由固定数组决定。 */
static void task_values(vireo_mysql_parameter_t p[18],const unsigned char uuid[16])
{
    static const unsigned char hash[32]={0xa0,0xa0,0xa0,0xa0,0xa0,0xa0,0xa0,0xa0,0xa0,0xa0,0xa0,0xa0,0xa0,0xa0,0xa0,0xa0,0xa0,0xa0,0xa0,0xa0,0xa0,0xa0,0xa0,0xa0,0xa0,0xa0,0xa0,0xa0,0xa0,0xa0,0xa0,0xa0};
    p[0]=U64(99); p[1]=BYTES(uuid,16); p[2]=U64(1); p[3]=U64(3); p[4]=BYTES(uuid,16);
    p[5]=BYTES(hash,32); p[6]=U64(8); p[7]=U64(1); p[8]=U64(2); p[9]=U64(2);
    p[10]=U64(0); p[11]=U64(1); p[12]=U64(0); p[13]=U64(0); p[14]=U64(10); p[15]=U64(20); p[16]=U64(100); p[17]=NIL;
}
static void add_task(uint64_t id,unsigned char tag,uint64_t state,uint64_t ack,uint64_t size,uint64_t count)
{
    unsigned char uuid[16]; memset(uuid,tag,16); vireo_mysql_parameter_t p[18]; task_values(p,uuid);
    p[0]=U64(id); p[6]=U64(size); p[8]=U64(count); p[9]=U64(state); p[10]=U64(ack); if(state>=6) { p[17]=U64(20); }
    (void)execute(insert_task,p,18,0);
}
static void part_values(vireo_mysql_parameter_t p[17])
{
    static const unsigned char hash[32]={0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee};
    p[0]=U64(10); p[1]=U64(9); p[2]=U64(100); p[3]=U64(4); p[4]=BYTES(hash,32);
    p[5]=U64(2); p[6]=U64(0); p[7]=U64(1); p[8]=U64(1);
    for(size_t i=9;i<15;++i) { p[i]=NIL; } p[15]=U64(10); p[16]=U64(20);
}
static void remote_values(vireo_mysql_parameter_t p[17])
{
    static const unsigned char lease[16]={0xa1,0xa1,0xa1,0xa1,0xa1,0xa1,0xa1,0xa1,0xa1,0xa1,0xa1,0xa1,0xa1,0xa1,0xa1,0xa1};
    part_values(p); p[8]=U64(2); p[9]=U64(1); p[10]=U64(3); p[11]=U64(9); p[12]=BYTES(lease,16); p[13]=U64(15); p[14]=U64(90);
}
static void business_data(void)
{
    command("INSERT INTO objects(object_hash,size,state,ref_count,storage_class,created_at_ms,updated_at_ms,verified_at_ms) VALUES(REPEAT(X'A0',32),8,2,1,1,10,20,15)");
    command("INSERT INTO file_nodes(id,owner_id,parent_id,name,node_type,state,object_hash,size,created_at_ms,updated_at_ms) VALUES(3,1,1,'download',2,2,REPEAT(X'A0',32),8,10,20)");
    command("INSERT INTO object_chunks(object_hash,chunk_index,byte_offset,byte_length,chunk_hash) VALUES(REPEAT(X'A0',32),0,0,4,REPEAT(X'EE',32)),(REPEAT(X'A0',32),1,4,4,REPEAT(X'EE',32))");
    command("INSERT INTO users(id,username,username_key,password_hash,status,created_at_ms,updated_at_ms) VALUES(2,'second','second','test-phc',1,0,0)");
    command("INSERT INTO file_nodes(id,owner_id,parent_id,name,node_type,state,size,created_at_ms,updated_at_ms) VALUES(4,2,NULL,'',1,2,0,0,0)");
}
static void task_rows(void)
{
    add_task(10,0x10,3,0,8,2); add_task(11,0x11,2,0,8,2);
    unsigned char uuid[17]; memset(uuid,0x99,sizeof(uuid)); vireo_mysql_parameter_t p[18];
    for(size_t i=1;i<17;++i) { task_values(p,uuid); p[i]=NIL; (void)execute(insert_task,p,18,1048); }
    for(size_t i=0;i<18;++i) {
        if(i==1 || i==4 || i==5) { continue; }
        task_values(p,uuid); p[i]=I64(-1); (void)execute(insert_task,p,18,1264);
    }
    for(size_t i=1;i<=4;i+=3) {
        for(size_t j=0;j<4;++j) {
            task_values(p,uuid); unsigned char zero[16]={0}; size_t n=j==0 ? 0U : j==1 ? 15U : j==2 ? 17U : 16U;
            p[i]=BYTES(j==3 ? zero : uuid,n); (void)execute(insert_task,p,18,n==17 ? 1406 : 3819);
        }
    }
    task_values(p,uuid); p[2]=U64(2); (void)execute(insert_task,p,18,1452);
    task_values(p,uuid); p[3]=U64(9999); (void)execute(insert_task,p,18,1452);
    unsigned char hash[33]; memset(hash,0xff,sizeof(hash)); task_values(p,uuid); p[5]=BYTES(hash,32); (void)execute(insert_task,p,18,1452);
    p[5]=BYTES(hash,33); (void)execute(insert_task,p,18,1406);
    const size_t indices[]={2,3,7,8,9,9,10,11,12,13,15,16};
    const uint64_t values[]={0,0,2,UINT64_C(4294967297),0,10,9,0,2,65536,9,10};
    const unsigned int errors[]={3819,3819,3819,3819,3819,3819,3819,3819,3819,1264,3819,3819};
    for(size_t i=0;i<sizeof(indices)/sizeof(indices[0]);++i) { task_values(p,uuid); p[indices[i]]=U64(values[i]); (void)execute(insert_task,p,18,errors[i]); }
    task_values(p,uuid); p[9]=U64(256); (void)execute(insert_task,p,18,1264);
    task_values(p,uuid); p[8]=U64(UINT64_MAX); (void)execute(insert_task,p,18,3819);
    task_values(p,uuid); p[8]=U64(0); (void)execute(insert_task,p,18,3819);
    task_values(p,uuid); p[6]=U64(0); (void)execute(insert_task,p,18,3819);
    task_values(p,uuid); p[6]=U64(1); (void)execute(insert_task,p,18,3819);
    task_values(p,uuid); p[6]=U64(33554321); (void)execute(insert_task,p,18,3819);
    task_values(p,uuid); p[6]=U64(UINT64_MAX); (void)execute(insert_task,p,18,3819);
    task_values(p,uuid); p[9]=U64(1); p[10]=U64(1); (void)execute(insert_task,p,18,3819);
    for(uint64_t state=5;state<=6;++state) { task_values(p,uuid); p[9]=U64(state); if(state==6) { p[17]=U64(20); } (void)execute(insert_task,p,18,3819); }
    for(uint64_t state=6;state<=9;++state) { task_values(p,uuid); p[9]=U64(state); p[10]=U64(8); (void)execute(insert_task,p,18,3819); }
    task_values(p,uuid); p[17]=U64(20); (void)execute(insert_task,p,18,3819);
    task_values(p,uuid); p[9]=U64(7); p[17]=U64(9); (void)execute(insert_task,p,18,3819);
    p[17]=U64(21); (void)execute(insert_task,p,18,3819);
    task_values(p,uuid); unsigned char duplicate[16]; memset(duplicate,0x10,16); p[1]=BYTES(duplicate,16); (void)execute(insert_task,p,18,1062);
    task_values(p,uuid); p[4]=BYTES(duplicate,16); (void)execute(insert_task,p,18,1062);
    for(uint64_t state=1;state<=9;++state) { add_task(20+state,(unsigned char)(20+state),state,state==5 || state==6 ? 8 : 0,8,2); }
    add_task(40,0x40,6,0,0,0);
    task_values(p,uuid); p[0]=U64(99); p[6]=U64(UINT64_C(4294967296)*16777160); p[8]=U64(UINT64_C(4294967296)); p[11]=U64(UINT64_MAX); p[13]=U64(65535); p[14]=U64(UINT64_MAX-1); p[15]=U64(UINT64_MAX); p[16]=U64(UINT64_MAX); (void)execute(insert_task,p,18,0);
    task_values(p,uuid); unsigned char second[16]; memset(second,0x98,16); p[0]=U64(100); p[1]=BYTES(second,16); p[2]=U64(2); p[3]=U64(4); /* 同key另user可存；目录并非合法业务输入但FK只核身份。 */
    (void)execute(insert_task,p,18,0);
    command("UPDATE download_tasks SET public_id=CONCAT(REPEAT(X'77',15),X'00'),idempotency_key=CONCAT(REPEAT(X'77',15),X'00') WHERE id=11");
    add_task(101,0x78,2,0,8,2); command("UPDATE download_tasks SET public_id=CONCAT(REPEAT(X'77',15),X'20'),idempotency_key=CONCAT(REPEAT(X'77',15),X'20') WHERE id=101");
    scalar("SELECT COUNT(*) FROM download_tasks WHERE LEFT(public_id,15)=REPEAT(X'77',15)","2");
    (void)execute("UPDATE download_tasks SET manifest_version=0 WHERE id=10",NULL,0,3819);
    (void)execute("UPDATE download_tasks SET acked_bytes=9 WHERE id=10",NULL,0,3819);
    (void)execute("UPDATE download_tasks SET version=version+1 WHERE id=99",NULL,0,1690);
    (void)execute("DELETE FROM file_nodes WHERE id=3",NULL,0,1451);
    (void)execute("DELETE FROM objects WHERE object_hash=REPEAT(X'A0',32)",NULL,0,1451);
    puts("PASS task whole-object snapshots, repeated node downloads, scoped identities, exact UUID/NUL/trailing bytes, empty/2^32 geometry, all states/NULL/uint/time/version/RESTRICT edges");
}
static void part_rows(void)
{
    vireo_mysql_parameter_t p[17]; part_values(p); p[1]=U64(0); p[2]=U64(0); (void)execute(insert_part,p,17,0);
    remote_values(p); p[1]=U64(1); p[2]=U64(4); p[5]=U64(3); (void)execute(insert_part,p,17,0);
    for(size_t i=0;i<17;++i) { if(i>=9 && i<15) { continue; } part_values(p); p[i]=NIL; (void)execute(insert_part,p,17,1048); }
    for(size_t i=0;i<17;++i) { if(i==4 || i==12) { continue; } remote_values(p); p[i]=I64(-1); (void)execute(insert_part,p,17,1264); }
    for(size_t i=9;i<15;++i) { remote_values(p); p[i]=NIL; (void)execute(insert_part,p,17,3819); }
    unsigned char bytes[33]; memset(bytes,0xee,sizeof(bytes));
    for(size_t i=9;i<15;++i) { part_values(p); p[i]=i==12 ? BYTES(bytes,16) : U64(1); (void)execute(insert_part,p,17,3819); }
    for(size_t n=0;n<3;++n) { part_values(p); size_t length=n==0 ? 0U : n==1 ? 31U : 33U; p[4]=BYTES(bytes,length); (void)execute(insert_part,p,17,length==33 ? 1406 : 3819); }
    memset(bytes,0xa1,sizeof(bytes));
    for(size_t n=0;n<4;++n) { remote_values(p); size_t length=n==0 ? 0U : n==1 ? 15U : n==2 ? 17U : 16U; if(n==3) { memset(bytes,0,16); } p[12]=BYTES(bytes,length); (void)execute(insert_part,p,17,length==17 ? 1406 : 3819); }
    const size_t indices[]={0,0,1,2,3,3,3,5,5,6,7,8,8,9,9,10,11,13,13,14,16};
    const uint64_t values[]={0,9999,UINT64_C(4294967296),UINT64_MAX,0,16777161,UINT64_C(4294967296),0,7,5,0,0,3,0,9999,0,0,9,21,15,9};
    const unsigned int errors[]={3819,1452,1264,3819,3819,3819,1264,3819,3819,3819,3819,3819,3819,3819,1452,3819,3819,3819,3819,3819,3819};
    for(size_t i=0;i<sizeof(indices)/sizeof(indices[0]);++i) { remote_values(p); p[indices[i]]=U64(values[i]); (void)execute(insert_part,p,17,errors[i]); }
    part_values(p); p[5]=U64(4); (void)execute(insert_part,p,17,3819);
    part_values(p); p[5]=U64(1); (void)execute(insert_part,p,17,3819);
    part_values(p); p[1]=U64(0); (void)execute(insert_part,p,17,1062);
    part_values(p); p[2]=U64(0); (void)execute(insert_part,p,17,1062);
    memset(bytes,0xff,32); part_values(p); p[4]=BYTES(bytes,32); (void)execute(insert_part,p,17,1452);
    for(uint64_t state=1;state<=6;++state) {
        part_values(p); p[0]=U64(11); p[1]=U64(state); p[2]=U64(state*4); p[5]=U64(state);
        if(state==1) { p[8]=U64(0); } if(state==4) { p[6]=U64(4); } (void)execute(insert_part,p,17,0);
    }
    remote_values(p); p[0]=U64(11); p[1]=U64(UINT32_MAX); p[2]=U64(UINT64_MAX-16777160); p[3]=U64(16777160);
    p[7]=U64(UINT64_MAX); p[10]=U64(UINT64_MAX); p[11]=U64(UINT64_MAX); p[14]=U64(UINT64_MAX); (void)execute(insert_part,p,17,0);
    (void)execute("UPDATE download_parts SET version=version+1 WHERE task_id=11 AND part_index=4294967295",NULL,0,1690);
    (void)execute("UPDATE download_parts SET acked_bytes=acked_bytes-1 WHERE task_id=10 AND part_index=0",NULL,0,1690);
    (void)execute("UPDATE download_parts SET source_node_id=99999 WHERE task_id=10 AND part_index=1",NULL,0,1452);
    (void)execute("DELETE FROM download_tasks WHERE id=10",NULL,0,1451);
    (void)execute("DELETE FROM storage_nodes WHERE id=1",NULL,0,1451);
    (void)execute("DELETE FROM chunks WHERE chunk_hash=REPEAT(X'EE',32)",NULL,0,1451);
    puts("PASS part range/ACK/hash/u32/u64, local/unassigned/complete remote source shape, NULL group/lease byte/time edges, all six states, duplicate index/offset and RESTRICT");
}

/* 合成可信writer的SQL示例：固定锁顺序与全身份谓词，不是生产repository。 */
static const char ack_remote[]=
    "UPDATE download_parts p JOIN download_tasks t ON t.id=p.task_id JOIN storage_nodes n ON n.id=p.source_node_id JOIN chunk_replicas r ON r.node_id=n.id AND r.chunk_hash=p.chunk_hash "
    "SET p.acked_bytes=2,p.version=p.version+1 WHERE p.task_id=10 AND p.part_index=1 AND t.user_id=1 AND t.state=3 AND t.cancel_requested=0 AND t.version=1 AND t.manifest_version=1 AND t.expires_at_ms>30 "
    "AND p.state=3 AND p.version=1 AND p.acked_bytes=0 AND p.source_kind=2 AND p.source_node_id=1 AND p.source_node_generation=3 AND p.source_replica_generation=9 "
    "AND p.lease_id=REPEAT(X'A1',16) AND p.lease_issued_at_ms<=30 AND p.lease_expires_at_ms>30 AND n.status=1 AND n.generation=3 AND r.state=2 AND r.generation=9 AND r.node_generation=3";
static void ack_transactions(void)
{
    char before[SNAPSHOT_CAPACITY],after[SNAPSHOT_CAPACITY]; capture(snapshot_sql,before);
    command("SET autocommit=0"); scalar("SELECT version FROM download_tasks WHERE id=10 FOR UPDATE","1");
    scalar("SELECT acked_bytes FROM download_parts WHERE task_id=10 AND part_index=1 FOR UPDATE","0");
    assert(execute(ack_remote,NULL,0,0).affected_rows==1);
    assert(execute("UPDATE download_tasks SET acked_bytes=acked_bytes+2,version=version+1 WHERE id=10 AND version=1 AND acked_bytes=0 AND state=3",NULL,0,0).affected_rows==1);
    command("ROLLBACK"); command("SET autocommit=1"); capture(snapshot_sql,after); assert(!strcmp(before,after));
    command("SET autocommit=0"); assert(execute(ack_remote,NULL,0,0).affected_rows==1);
    assert(execute("UPDATE download_tasks SET acked_bytes=acked_bytes+2,version=version+1 WHERE id=10 AND version=1 AND acked_bytes=0 AND state=3",NULL,0,0).affected_rows==1);
    command("COMMIT"); command("SET autocommit=1");
    scalar("SELECT CONCAT(acked_bytes,'|',version) FROM download_tasks WHERE id=10","2|2");
    assert(execute(ack_remote,NULL,0,0).affected_rows==0);
    /* 相同/较小prefix使用new>old guard；不产生负delta或再次增加总量。 */
    assert(execute("UPDATE download_parts SET acked_bytes=1,version=version+1 WHERE task_id=10 AND part_index=1 AND 1>acked_bytes",NULL,0,0).affected_rows==0);
    command("UPDATE download_parts SET lease_id=REPEAT(X'A2',16),version=version+1 WHERE task_id=10 AND part_index=1 AND version=2");
    assert(execute("UPDATE download_parts SET acked_bytes=4,version=version+1 WHERE task_id=10 AND part_index=1 AND version=2 AND lease_id=REPEAT(X'A1',16)",NULL,0,0).affected_rows==0);
    scalar("SELECT acked_bytes FROM download_parts WHERE task_id=10 AND part_index=1","2");
    command("UPDATE storage_nodes SET generation=4 WHERE id=1");
    scalar("SELECT COUNT(*) FROM download_parts WHERE task_id=10 AND part_index=1 AND source_node_generation=3","1");
    assert(execute("UPDATE download_parts p JOIN storage_nodes n ON n.id=p.source_node_id SET p.acked_bytes=4 WHERE p.task_id=10 AND p.part_index=1 AND p.source_node_generation=n.generation",NULL,0,0).affected_rows==0);
    command("UPDATE storage_nodes SET generation=3 WHERE id=1"); /* 仅测试复位，真实writer禁止代际倒退。 */
    assert(execute("UPDATE download_parts SET acked_bytes=4 WHERE task_id=10 AND part_index=1 AND lease_expires_at_ms>100",NULL,0,0).affected_rows==0);
    command("UPDATE chunk_replicas SET generation=10 WHERE node_id=1");
    assert(execute("UPDATE download_parts p JOIN chunk_replicas r ON r.chunk_hash=p.chunk_hash AND r.node_id=p.source_node_id SET p.acked_bytes=4 WHERE p.task_id=10 AND p.part_index=1 AND p.source_replica_generation=r.generation",NULL,0,0).affected_rows==0);
    command("UPDATE chunk_replicas SET generation=9 WHERE node_id=1");
    command("UPDATE download_tasks SET cancel_requested=1,version=version+1 WHERE id=10");
    assert(execute("UPDATE download_parts p JOIN download_tasks t ON t.id=p.task_id SET p.acked_bytes=4 WHERE p.task_id=10 AND p.part_index=1 AND t.state=3 AND t.cancel_requested=0",NULL,0,0).affected_rows==0);
    command("UPDATE download_tasks SET cancel_requested=0,version=version+1 WHERE id=10");
    command("SET autocommit=0");
    command("UPDATE download_parts SET state=4,acked_bytes=4,version=version+1 WHERE task_id=10");
    command("UPDATE download_tasks SET state=5,acked_bytes=8,version=version+1 WHERE id=10");
    command("COMMIT"); command("SET autocommit=1");
    scalar("SELECT CONCAT(t.acked_bytes,'|',SUM(p.acked_bytes)) FROM download_tasks t JOIN download_parts p ON p.task_id=t.id WHERE t.id=10 GROUP BY t.id","8|8");
    command("UPDATE download_tasks SET state=6,finished_at_ms=20,version=version+1 WHERE id=10");
    assert(execute("UPDATE download_parts p JOIN download_tasks t ON t.id=p.task_id SET p.version=p.version+1 WHERE p.task_id=10 AND t.state=3",NULL,0,0).affected_rows==0);
    puts("PASS synthetic ACK transaction rollback/commit, delta totals/duplicate/smaller prefix, old lease/epoch/replica/expiry/cancel/terminal guards, two reused-chunk positions counted independently");
}
static void counterexamples_and_cleanup(void)
{
    char before[SNAPSHOT_CAPACITY],after[SNAPSHOT_CAPACITY]; capture(snapshot_sql,before);
    command("SET autocommit=0");
    /* CHECK不维护快照不可变、跨表size、覆盖/不重叠/part_count、求和和状态转换边。 */
    command("UPDATE download_tasks SET size=9,part_count=2,acked_bytes=0,state=2,finished_at_ms=NULL,version=1 WHERE id=10");
    command("UPDATE download_parts SET byte_offset=1,byte_length=3,acked_bytes=3,state=4,source_replica_generation=999 WHERE task_id=10 AND part_index=1");
    scalar("SELECT CONCAT(t.acked_bytes,'|',SUM(p.acked_bytes)) FROM download_tasks t JOIN download_parts p ON p.task_id=t.id WHERE t.id=10 GROUP BY t.id","0|7");
    command("UPDATE file_nodes SET object_hash=REPEAT(X'BB',32),size=11 WHERE id=3");
    scalar("SELECT size FROM download_tasks WHERE id=10","9");
    command("ROLLBACK"); command("SET autocommit=1"); capture(snapshot_sql,after); assert(!strcmp(before,after));
    command("SET autocommit=0"); command("UPDATE download_tasks SET version=version+1 WHERE id=11");
    (void)execute("INSERT INTO download_parts SELECT * FROM download_parts WHERE task_id=10 AND part_index=0",NULL,0,1062);
    scalar("SELECT version FROM download_tasks WHERE id=11","2");
    command("ROLLBACK"); command("SET autocommit=1"); capture(snapshot_sql,after); assert(!strcmp(before,after));
    command("SET autocommit=0"); command("DELETE FROM download_parts WHERE task_id=11"); command("DELETE FROM download_tasks WHERE id=11"); command("COMMIT"); command("SET autocommit=1");
    scalar("SELECT COUNT(*) FROM download_tasks WHERE id=11","0");
    puts("PASS admitted immutable-snapshot/manifest/geometry/progress/state/CAS business counterexamples, node mutation leaves task snapshot, duplicate only rolls back statement, child-before-parent commit cleanup");
}
static void apply(const vireo_mysql_connection_options_t *options,const vireo_mysql_migration_t *catalog,
    size_t count,vireo_mysql_migration_report_t *report)
{
    vireo_mysql_migration_error_t error; errno=EDOM;
    vireo_result_t result=vireo_mysql_migration_apply(thread,options,catalog,count,report,&error);
    assert(errno==EDOM);
    if(result!=VIREO_OK) { fprintf(stderr,"migration result %d stage %d issue %d mysql %u version %u step %u\n",(int)result,(int)error.stage,(int)error.issue,error.database.mysql_code,report->failed_version,report->failed_step); abort(); }
    assert(report->ready && report->connection_closed);
}
static void ledger(size_t versions)
{
    vireo_mysql_statement_t *s=query("SELECT CONCAT(version,'|',state,'|',HEX(checksum)) FROM vireo_schema_migrations ORDER BY version");
    row(s,"1|1|58C6116C0920294129F40AFE777C4E3F616B4532393EF09B7FDDBC4822F688BE");
    row(s,"2|1|D8FC1A1E07981AF9D4C5DB32C9CB71D66CFD326B13E7EB771CB21723D96ED90C");
    row(s,"3|1|AAEF9451FC21B6DE65EF4BA447F63E7125CF9ECE1EB26A95A2627C77758885AE");
    row(s,"4|1|66687B2CEE61BC9BC506D89B6055F0A031D66C8634DAF5D432FF923E2C510276");
    if(versions>=5) { row(s,"5|1|CF344ED64B30B1F95926EC46BCC16C1AF1CDCBEE56BBF67C549B9172F2C423AF"); }
    if(versions>=6) { row(s,"6|1|B86F6818EFB6C65B264AAD10B09D7FF0EBA9F395FA87FD70939B680A4A0AA3D5"); }
    if(versions==7) { row(s,"7|1|8D6A75B694EADECB3EE8B62519759C33093D1655B3F74AC1325B2DB5C4D1C975"); } done(&s);
}
static size_t fd_count(void)
{
    DIR *d=opendir("/proc/self/fd"); assert(d); struct dirent *p; size_t n=0;
    while((p=readdir(d))) { if(strcmp(p->d_name,".") && strcmp(p->d_name,"..")) { ++n; } }
    assert(closedir(d)==0); return n;
}
int main(int argc,char **argv)
{
    assert(setvbuf(stdout,NULL,_IONBF,0)==0 && argc==5);
    char password[1026]; FILE *f=fopen(argv[3],"r"); assert(f);
    assert(fgets(password,(int)sizeof(password),f) && fclose(f)==0); password[strcspn(password,"\n")]=0;
    struct sigaction sa={0}; sa.sa_handler=SIG_IGN; assert(sigemptyset(&sa.sa_mask)==0 && sigaction(SIGPIPE,&sa,NULL)==0);
    vireo_mysql_runtime_t *runtime=NULL; CHECK(vireo_mysql_runtime_create(&runtime,NULL));
    CHECK(vireo_mysql_thread_attach(runtime,&thread,NULL)); size_t before_fd=fd_count();
    vireo_mysql_connection_options_t options={argv[1],argv[2],password,argv[4],3,3,3};
    const vireo_mysql_migration_t *catalog=NULL; size_t count=0; CHECK(vireo_mysql_schema_catalog(&catalog,&count)); assert(count==10); count=7; /* 保留v7完整下载结构/ACK与升级前缀回归。 */
    vireo_mysql_migration_report_t report; apply(&options,catalog,count,&report);
    assert(report.applied_before==0 && report.applied_after==7 && report.steps_completed==13 && report.migrations_applied==7 && report.write_attempted);
    CHECK(vireo_mysql_connection_open(thread,&options,&connection,NULL));
    metadata(); seed(); business_data(); task_rows(); part_rows(); ack_transactions(); counterexamples_and_cleanup(); ledger(7);
    char before[SNAPSHOT_CAPACITY],after[SNAPSHOT_CAPACITY]; capture(snapshot_sql,before);
    apply(&options,catalog,count,&report);
    assert(report.applied_before==7 && report.applied_after==7 && !report.steps_completed && !report.write_attempted && !report.migrations_applied);
    capture(snapshot_sql,after); assert(!strcmp(before,after)); ledger(7);
    CHECK(vireo_mysql_connection_destroy(thread,&connection));
    options.database="vireo_download_upgrade"; apply(&options,catalog,6,&report);
    assert(report.applied_before==0 && report.applied_after==6 && report.steps_completed==11 && report.migrations_applied==6);
    CHECK(vireo_mysql_connection_open(thread,&options,&connection,NULL)); seed(); capture(seed_snapshot_sql,before); ledger(6);
    apply(&options,catalog,count,&report);
    assert(report.applied_before==6 && report.applied_after==7 && report.steps_completed==2 && report.migrations_applied==1 && report.write_attempted);
    capture(seed_snapshot_sql,after); assert(!strcmp(before,after)); metadata(); ledger(7);
    scalar("SELECT COUNT(*) FROM download_tasks","0"); scalar("SELECT COUNT(*) FROM download_parts","0");
    business_data(); add_task(10,0x10,2,0,8,2); vireo_mysql_parameter_t parameters[17]; remote_values(parameters); (void)execute(insert_part,parameters,17,0);
    capture(snapshot_sql,before); apply(&options,catalog,count,&report);
    assert(report.applied_before==7 && report.applied_after==7 && !report.write_attempted && !report.steps_completed);
    capture(snapshot_sql,after); assert(!strcmp(before,after)); ledger(7);
    CHECK(vireo_mysql_connection_destroy(thread,&connection)); CHECK(vireo_mysql_thread_detach(&thread)); CHECK(vireo_mysql_runtime_destroy(&runtime));
    assert(fd_count()==before_fd); memset(password,0,sizeof(password));
    printf("PASS empty13/seeded-v6 eleven-table upgrade2/repeat seven hashes and exact rows, %zu rejected writes unchanged, FD %zu -> %zu\n",rejected,before_fd,fd_count());
    return 0;
}
