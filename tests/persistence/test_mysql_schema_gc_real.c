/*
 * PROJECT : VIREO
 * FILE    : test_mysql_schema_gc_real.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-19
 * BRIEF   : 真实gc_jobs身份/去重/claim/重试与含v7十三表升级。
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
static const char insert_job[]="INSERT INTO gc_jobs(id,resource_kind,resource_key,operation,state,attempts,version,next_run_at_ms,claim_id,claimed_at_ms,lease_expires_at_ms,last_error,created_at_ms,updated_at_ms,finished_at_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";
static const char snapshot_sql[]="SELECT CONCAT_WS('|','gc_jobs',COALESCE(HEX(id),'N'),COALESCE(HEX(resource_kind),'N'),COALESCE(HEX(resource_key),'N'),COALESCE(HEX(operation),'N'),COALESCE(HEX(state),'N'),COALESCE(HEX(attempts),'N'),COALESCE(HEX(version),'N'),COALESCE(HEX(next_run_at_ms),'N'),COALESCE(HEX(claim_id),'N'),COALESCE(HEX(claimed_at_ms),'N'),COALESCE(HEX(lease_expires_at_ms),'N'),COALESCE(HEX(last_error),'N'),COALESCE(HEX(created_at_ms),'N'),COALESCE(HEX(updated_at_ms),'N'),COALESCE(HEX(finished_at_ms),'N'),COALESCE(HEX(active_slot),'N')) AS v FROM gc_jobs ORDER BY v";
static const char seed_snapshot_sql[]=
"SELECT CONCAT_WS('|','users',COALESCE(HEX(id),'N'),COALESCE(HEX(username),'N'),COALESCE(HEX(username_key),'N'),COALESCE(HEX(password_hash),'N'),COALESCE(HEX(status),'N'),COALESCE(HEX(created_at_ms),'N'),COALESCE(HEX(updated_at_ms),'N'),COALESCE(HEX(last_login_at_ms),'N')) AS v FROM users UNION ALL SELECT CONCAT_WS('|','sessions',COALESCE(HEX(id),'N'),COALESCE(HEX(user_id),'N'),COALESCE(HEX(token_digest),'N'),COALESCE(HEX(status),'N'),COALESCE(HEX(issued_at_ms),'N'),COALESCE(HEX(expires_at_ms),'N'),COALESCE(HEX(revoked_at_ms),'N'),COALESCE(HEX(last_seen_at_ms),'N')) AS v FROM sessions UNION ALL SELECT CONCAT_WS('|','objects',COALESCE(HEX(object_hash),'N'),COALESCE(HEX(size),'N'),COALESCE(HEX(state),'N'),COALESCE(HEX(ref_count),'N'),COALESCE(HEX(storage_class),'N'),COALESCE(HEX(created_at_ms),'N'),COALESCE(HEX(updated_at_ms),'N'),COALESCE(HEX(verified_at_ms),'N')) AS v FROM objects UNION ALL SELECT CONCAT_WS('|','file_nodes',COALESCE(HEX(id),'N'),COALESCE(HEX(owner_id),'N'),COALESCE(HEX(parent_id),'N'),COALESCE(HEX(name),'N'),COALESCE(HEX(name_hash),'N'),COALESCE(HEX(node_type),'N'),COALESCE(HEX(state),'N'),COALESCE(HEX(object_hash),'N'),COALESCE(HEX(size),'N'),COALESCE(HEX(created_at_ms),'N'),COALESCE(HEX(updated_at_ms),'N'),COALESCE(HEX(deleted_at_ms),'N'),COALESCE(HEX(live_name),'N'),COALESCE(HEX(active_root_owner),'N')) AS v FROM file_nodes UNION ALL SELECT CONCAT_WS('|','operation_audits',COALESCE(HEX(id),'N'),COALESCE(HEX(request_id),'N'),COALESCE(HEX(user_id),'N'),COALESCE(HEX(session_id),'N'),COALESCE(HEX(action),'N'),COALESCE(HEX(target_type),'N'),COALESCE(HEX(target_id),'N'),COALESCE(HEX(target_hash),'N'),COALESCE(HEX(status),'N'),COALESCE(HEX(latency_us),'N'),COALESCE(HEX(detail),'N'),COALESCE(HEX(occurred_at_ms),'N')) AS v FROM operation_audits UNION ALL SELECT CONCAT_WS('|','upload_tasks',COALESCE(HEX(id),'N'),COALESCE(HEX(public_id),'N'),COALESCE(HEX(user_id),'N'),COALESCE(HEX(file_node_id),'N'),COALESCE(HEX(idempotency_key),'N'),COALESCE(HEX(expected_hash),'N'),COALESCE(HEX(size),'N'),COALESCE(HEX(mode),'N'),COALESCE(HEX(chunk_size),'N'),COALESCE(HEX(chunk_count),'N'),COALESCE(HEX(state),'N'),COALESCE(HEX(received_chunks),'N'),COALESCE(HEX(received_bytes),'N'),COALESCE(HEX(version),'N'),COALESCE(HEX(cancel_requested),'N'),COALESCE(HEX(last_status),'N'),COALESCE(HEX(created_at_ms),'N'),COALESCE(HEX(updated_at_ms),'N'),COALESCE(HEX(expires_at_ms),'N'),COALESCE(HEX(finished_at_ms),'N')) AS v FROM upload_tasks UNION ALL SELECT CONCAT_WS('|','upload_chunks',COALESCE(HEX(task_id),'N'),COALESCE(HEX(chunk_index),'N'),COALESCE(HEX(byte_offset),'N'),COALESCE(HEX(byte_length),'N'),COALESCE(HEX(chunk_hash),'N'),COALESCE(HEX(crc32c),'N'),COALESCE(HEX(state),'N'),COALESCE(HEX(received_at_ms),'N')) AS v FROM upload_chunks UNION ALL SELECT CONCAT_WS('|','chunks',COALESCE(HEX(chunk_hash),'N'),COALESCE(HEX(size),'N'),COALESCE(HEX(state),'N'),COALESCE(HEX(ref_count),'N'),COALESCE(HEX(created_at_ms),'N'),COALESCE(HEX(updated_at_ms),'N'),COALESCE(HEX(verified_at_ms),'N')) AS v FROM chunks UNION ALL SELECT CONCAT_WS('|','object_chunks',COALESCE(HEX(object_hash),'N'),COALESCE(HEX(chunk_index),'N'),COALESCE(HEX(byte_offset),'N'),COALESCE(HEX(byte_length),'N'),COALESCE(HEX(chunk_hash),'N')) AS v FROM object_chunks UNION ALL SELECT CONCAT_WS('|','storage_nodes',COALESCE(HEX(id),'N'),COALESCE(HEX(node_uuid),'N'),COALESCE(HEX(endpoint),'N'),COALESCE(HEX(zone),'N'),COALESCE(HEX(status),'N'),COALESCE(HEX(capacity_bytes),'N'),COALESCE(HEX(used_bytes),'N'),COALESCE(HEX(generation),'N'),COALESCE(HEX(created_at_ms),'N'),COALESCE(HEX(updated_at_ms),'N'),COALESCE(HEX(last_heartbeat_at_ms),'N')) AS v FROM storage_nodes UNION ALL SELECT CONCAT_WS('|','chunk_replicas',COALESCE(HEX(chunk_hash),'N'),COALESCE(HEX(node_id),'N'),COALESCE(HEX(state),'N'),COALESCE(HEX(generation),'N'),COALESCE(HEX(node_generation),'N'),COALESCE(HEX(created_at_ms),'N'),COALESCE(HEX(updated_at_ms),'N'),COALESCE(HEX(verified_at_ms),'N')) AS v FROM chunk_replicas ORDER BY v";
static const char download_snapshot_sql[]=
"SELECT CONCAT_WS('|','download_tasks',COALESCE(HEX(id),'N'),COALESCE(HEX(public_id),'N'),COALESCE(HEX(user_id),'N'),COALESCE(HEX(file_node_id),'N'),COALESCE(HEX(idempotency_key),'N'),COALESCE(HEX(object_hash),'N'),COALESCE(HEX(size),'N'),COALESCE(HEX(manifest_version),'N'),COALESCE(HEX(part_count),'N'),COALESCE(HEX(state),'N'),COALESCE(HEX(acked_bytes),'N'),COALESCE(HEX(version),'N'),COALESCE(HEX(cancel_requested),'N'),COALESCE(HEX(last_status),'N'),COALESCE(HEX(created_at_ms),'N'),COALESCE(HEX(updated_at_ms),'N'),COALESCE(HEX(expires_at_ms),'N'),COALESCE(HEX(finished_at_ms),'N')) AS v FROM download_tasks UNION ALL SELECT CONCAT_WS('|','download_parts',COALESCE(HEX(task_id),'N'),COALESCE(HEX(part_index),'N'),COALESCE(HEX(byte_offset),'N'),COALESCE(HEX(byte_length),'N'),COALESCE(HEX(chunk_hash),'N'),COALESCE(HEX(state),'N'),COALESCE(HEX(acked_bytes),'N'),COALESCE(HEX(version),'N'),COALESCE(HEX(source_kind),'N'),COALESCE(HEX(source_node_id),'N'),COALESCE(HEX(source_node_generation),'N'),COALESCE(HEX(source_replica_generation),'N'),COALESCE(HEX(lease_id),'N'),COALESCE(HEX(lease_issued_at_ms),'N'),COALESCE(HEX(lease_expires_at_ms),'N'),COALESCE(HEX(created_at_ms),'N'),COALESCE(HEX(updated_at_ms),'N')) AS v FROM download_parts ORDER BY v";
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
 * @brief 组合新表与旧十三表的完整有序字节快照，避免超长C11字符串字面量。
 *
 * @param[in] sql 借用SELECT；snapshot_sql身份要求同时保存旧十一表。
 * @param[out] out 独占SNAPSHOT_CAPACITY字节；测试数据有界，超出即断言。
 *
 * @note 同一测试连接串行，无并发writer；两段都有表名和NULL标记，不混淆行。
 */
static void capture(const char *sql,char out[SNAPSHOT_CAPACITY])
{
    capture_one(sql,out);
    if(sql==snapshot_sql || sql==seed_snapshot_sql) {
        char other[SNAPSHOT_CAPACITY];
        capture_one(download_snapshot_sql,other);
        size_t n=strlen(out),m=strlen(other); assert(m<SNAPSHOT_CAPACITY-n); memcpy(out+n,other,m+1);
        if(sql==snapshot_sql) {
            capture_one(seed_snapshot_sql,other);
            n=strlen(out); m=strlen(other); assert(m<SNAPSHOT_CAPACITY-n); memcpy(out+n,other,m+1);
        }
    }
}
/**
 * @brief 执行一条DML；拒绝前后核全部十四业务表行保持。
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
    scalar("SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE()","15");
    scalar("SELECT CONCAT_WS('|',ENGINE,TABLE_COLLATION) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='gc_jobs'","InnoDB|utf8mb4_bin");
    static const char *const columns[]={
        "id|bigint unsigned|-|-|NO|NULL|auto_increment|-|-",
        "resource_kind|tinyint unsigned|-|-|NO|NULL||-|-",
        "resource_key|varbinary(32)|32|32|NO|NULL||-|-",
        "operation|tinyint unsigned|-|-|NO|NULL||-|-",
        "state|tinyint unsigned|-|-|NO|NULL||-|-",
        "attempts|int unsigned|-|-|NO|NULL||-|-",
        "version|bigint unsigned|-|-|NO|NULL||-|-",
        "next_run_at_ms|bigint unsigned|-|-|YES|NULL||-|-",
        "claim_id|varbinary(16)|16|16|YES|NULL||-|-",
        "claimed_at_ms|bigint unsigned|-|-|YES|NULL||-|-",
        "lease_expires_at_ms|bigint unsigned|-|-|YES|NULL||-|-",
        "last_error|smallint unsigned|-|-|NO|NULL||-|-",
        "created_at_ms|bigint unsigned|-|-|NO|NULL||-|-",
        "updated_at_ms|bigint unsigned|-|-|NO|NULL||-|-",
        "finished_at_ms|bigint unsigned|-|-|YES|NULL||-|-",
        "active_slot|tinyint unsigned|-|-|YES|NULL|STORED GENERATED|-|-",
    };
    vireo_mysql_statement_t *s=query("SELECT CONCAT_WS('|',COLUMN_NAME,COLUMN_TYPE,COALESCE(CAST(CHARACTER_MAXIMUM_LENGTH AS CHAR),'-'),COALESCE(CAST(CHARACTER_OCTET_LENGTH AS CHAR),'-'),IS_NULLABLE,COALESCE(COLUMN_DEFAULT,'NULL'),EXTRA,COALESCE(CHARACTER_SET_NAME,'-'),COALESCE(COLLATION_NAME,'-')) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='gc_jobs' ORDER BY ORDINAL_POSITION");
    for(size_t i=0;i<sizeof(columns)/sizeof(columns[0]);++i) { row(s,columns[i]); } done(&s);
    static const char *const indexes[]={
        "PRIMARY|0|1|id|BTREE|-|A|YES",
        "gc_jobs_active_resource_unique|0|1|resource_kind|BTREE|-|A|YES",
        "gc_jobs_active_resource_unique|0|2|resource_key|BTREE|-|A|YES",
        "gc_jobs_active_resource_unique|0|3|operation|BTREE|-|A|YES",
        "gc_jobs_active_resource_unique|0|4|active_slot|BTREE|-|A|YES",
        "gc_jobs_claim_unique|0|1|claim_id|BTREE|-|A|YES",
        "gc_jobs_finished|1|1|state|BTREE|-|A|YES",
        "gc_jobs_finished|1|2|finished_at_ms|BTREE|-|A|YES",
        "gc_jobs_finished|1|3|id|BTREE|-|A|YES",
        "gc_jobs_state_lease|1|1|state|BTREE|-|A|YES",
        "gc_jobs_state_lease|1|2|lease_expires_at_ms|BTREE|-|A|YES",
        "gc_jobs_state_lease|1|3|id|BTREE|-|A|YES",
        "gc_jobs_state_next_run|1|1|state|BTREE|-|A|YES",
        "gc_jobs_state_next_run|1|2|next_run_at_ms|BTREE|-|A|YES",
        "gc_jobs_state_next_run|1|3|id|BTREE|-|A|YES",
    };
    s=query("SELECT CONCAT_WS('|',INDEX_NAME,NON_UNIQUE,SEQ_IN_INDEX,COLUMN_NAME,INDEX_TYPE,COALESCE(CAST(SUB_PART AS CHAR),'-'),COLLATION,IS_VISIBLE) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='gc_jobs' ORDER BY BINARY INDEX_NAME,SEQ_IN_INDEX");
    for(size_t i=0;i<sizeof(indexes)/sizeof(indexes[0]);++i) { row(s,indexes[i]); } done(&s);
    static const char *const checks[]={
        "gc_jobs_attempts_valid|YES",
        "gc_jobs_claim_valid|YES",
        "gc_jobs_error_valid|YES",
        "gc_jobs_finished_valid|YES",
        "gc_jobs_operation_valid|YES",
        "gc_jobs_resource_valid|YES",
        "gc_jobs_schedule_valid|YES",
        "gc_jobs_state_valid|YES",
        "gc_jobs_updated_order|YES",
        "gc_jobs_version_valid|YES",
    };
    s=query("SELECT CONCAT_WS('|',CONSTRAINT_NAME,ENFORCED) FROM information_schema.TABLE_CONSTRAINTS WHERE CONSTRAINT_SCHEMA=DATABASE() AND TABLE_NAME='gc_jobs' AND CONSTRAINT_TYPE='CHECK' ORDER BY BINARY CONSTRAINT_NAME");
    for(size_t i=0;i<sizeof(checks)/sizeof(checks[0]);++i) { row(s,checks[i]); } done(&s);
    scalar("SELECT COUNT(*) FROM information_schema.KEY_COLUMN_USAGE WHERE CONSTRAINT_SCHEMA=DATABASE() AND TABLE_NAME='gc_jobs' AND REFERENCED_TABLE_NAME IS NOT NULL","0");
    scalar("SELECT COUNT(*) FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA=DATABASE() AND EVENT_OBJECT_TABLE='gc_jobs'","0");
    scalar("SELECT COUNT(*) FROM information_schema.PARTITIONS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='gc_jobs' AND PARTITION_NAME IS NOT NULL","0");
    scalar("SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='gc_jobs' AND GENERATION_EXPRESSION<>''","1");
    puts("PASS GC metadata: 16 columns/one generated slot, six full indexes, ten enforced CHECK, no FK/trigger/partition");
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
    command("INSERT INTO download_tasks(id,public_id,user_id,file_node_id,idempotency_key,object_hash,size,manifest_version,part_count,state,acked_bytes,version,cancel_requested,last_status,created_at_ms,updated_at_ms,expires_at_ms) VALUES(1,REPEAT(X'D1',16),1,2,REPEAT(X'D2',16),REPEAT(X'BB',32),11,1,1,2,0,1,0,0,0,0,100)");
    command("INSERT INTO download_parts(task_id,part_index,byte_offset,byte_length,chunk_hash,state,acked_bytes,version,source_kind,created_at_ms,updated_at_ms) VALUES(1,0,0,4,REPEAT(X'EE',32),1,0,1,0,0,0)");
}

/* 固定参数由同步execute借用；没有从函数内栈返回悬空span。 */
static void values(vireo_mysql_parameter_t p[15],const unsigned char key[32])
{
    p[0]=U64(99); p[1]=U64(1); p[2]=BYTES(key,32); p[3]=U64(1); p[4]=U64(1);
    p[5]=U64(0); p[6]=U64(1); p[7]=U64(10); p[8]=NIL; p[9]=NIL; p[10]=NIL;
    p[11]=U64(0); p[12]=U64(10); p[13]=U64(20); p[14]=NIL;
}
static void add(uint64_t id,unsigned char tag,uint64_t kind,uint64_t state)
{
    unsigned char key[32],claim[16]; memset(key,tag,32); memset(claim,tag,16);
    vireo_mysql_parameter_t p[15]; values(p,key); p[0]=U64(id); p[1]=U64(kind); p[4]=U64(state);
    if(kind==3) { p[2]=BYTES(key,16); }
    if(state!=1) { p[7]=NIL; }
    if(state==2) { p[5]=U64(1); p[8]=BYTES(claim,16); p[9]=U64(20); p[10]=U64(100); }
    if(state>=3) { p[14]=U64(20); }
    if(state==5) { p[11]=U64(2); }
    (void)execute(insert_job,p,15,0);
}
static void rows(void)
{
    unsigned char key[33],zero[32]={0},claim[17]; memset(key,0x99,sizeof(key)); memset(claim,0x99,sizeof(claim));
    vireo_mysql_parameter_t p[15],base[15]; values(base,key);
    add(10,0x10,1,1); add(11,0x10,2,1); add(12,0x10,3,1);
    for(uint64_t state=2;state<=5;++state) { add(20+state,(unsigned char)(0x20+state),1,state); }
    scalar("SELECT GROUP_CONCAT(COALESCE(active_slot,'N') ORDER BY id) FROM gc_jobs","1,1,1,1,N,N,N");
    memcpy(p,base,sizeof(p)); p[2]=BYTES(zero,32); (void)execute(insert_job,p,15,0); command("DELETE FROM gc_jobs WHERE id=99");
    /* 精确binary身份覆盖内含NUL、尾NUL与尾空格，不经字符串规范化。 */
    command("INSERT INTO gc_jobs(resource_kind,resource_key,operation,state,attempts,version,next_run_at_ms,last_error,created_at_ms,updated_at_ms) VALUES(1,CONCAT(REPEAT(X'00',31),X'00'),1,1,0,1,0,0,0,0),(1,CONCAT(REPEAT(X'00',31),X'20'),1,1,0,1,0,0,0,0)");
    for(size_t i=1;i<15;++i) {
        if(i==7 || i==8 || i==9 || i==10 || i==14) { continue; }
        memcpy(p,base,sizeof(p)); p[i]=NIL; (void)execute(insert_job,p,15,1048);
    }
    static const size_t unsigned_columns[]={1,3,4,5,6,7,11,12,13};
    for(size_t i=0;i<sizeof(unsigned_columns)/sizeof(unsigned_columns[0]);++i) {
        memcpy(p,base,sizeof(p)); p[unsigned_columns[i]]=I64(-1); (void)execute(insert_job,p,15,1264);
    }
    for(uint64_t kind=0;kind<=4;kind+=4) { memcpy(p,base,sizeof(p)); p[1]=U64(kind); (void)execute(insert_job,p,15,3819); }
    for(size_t n=0;n<33;++n) {
        if(n==32) { continue; }
        memcpy(p,base,sizeof(p)); p[2]=BYTES(key,n); (void)execute(insert_job,p,15,3819);
    }
    memcpy(p,base,sizeof(p)); p[2]=BYTES(key,33); (void)execute(insert_job,p,15,1406);
    memcpy(p,base,sizeof(p)); p[1]=U64(3); p[2]=BYTES(zero,16); (void)execute(insert_job,p,15,3819);
    for(size_t n=15;n<=17;++n) { if(n==16) { continue; } memcpy(p,base,sizeof(p)); p[1]=U64(3); p[2]=BYTES(key,n); (void)execute(insert_job,p,15,3819); }
    static const uint64_t invalid_states[]={0,6,255};
    for(size_t i=0;i<3;++i) { memcpy(p,base,sizeof(p)); p[4]=U64(invalid_states[i]); (void)execute(insert_job,p,15,3819); }
    memcpy(p,base,sizeof(p)); p[3]=U64(0); (void)execute(insert_job,p,15,3819);
    memcpy(p,base,sizeof(p)); p[3]=U64(2); (void)execute(insert_job,p,15,3819);
    memcpy(p,base,sizeof(p)); p[5]=U64(1000000); (void)execute(insert_job,p,15,3819);
    memcpy(p,base,sizeof(p)); p[5]=U64(1000001); (void)execute(insert_job,p,15,3819);
    memcpy(p,base,sizeof(p)); p[6]=U64(0); (void)execute(insert_job,p,15,3819);
    memcpy(p,base,sizeof(p)); p[7]=NIL; (void)execute(insert_job,p,15,3819);
    memcpy(p,base,sizeof(p)); p[7]=U64(9); (void)execute(insert_job,p,15,3819);
    memcpy(p,base,sizeof(p)); p[11]=U64(6); (void)execute(insert_job,p,15,3819);
    memcpy(p,base,sizeof(p)); p[13]=U64(9); (void)execute(insert_job,p,15,3819);
    memcpy(p,base,sizeof(p)); p[14]=U64(20); (void)execute(insert_job,p,15,3819);
    for(size_t i=8;i<=10;++i) { memcpy(p,base,sizeof(p)); p[i]=(i==8 ? BYTES(claim,16) : U64(20)); (void)execute(insert_job,p,15,3819); }
    /* RUNNING完整claim组与所有缺项/长度/时间边界。 */
    memcpy(p,base,sizeof(p)); p[4]=U64(2); p[5]=U64(1); p[7]=NIL; p[8]=BYTES(claim,16); p[9]=U64(20); p[10]=U64(100);
    vireo_mysql_parameter_t running[15]; memcpy(running,p,sizeof(p));
    for(size_t i=8;i<=10;++i) { memcpy(p,running,sizeof(p)); p[i]=NIL; (void)execute(insert_job,p,15,3819); }
    for(size_t n=0;n<=17;++n) { if(n==16) { continue; } memcpy(p,running,sizeof(p)); p[8]=BYTES(claim,n); (void)execute(insert_job,p,15,n==17 ? 1406 : 3819); }
    memcpy(p,running,sizeof(p)); p[8]=BYTES(zero,16); (void)execute(insert_job,p,15,3819);
    memcpy(p,running,sizeof(p)); p[5]=U64(0); (void)execute(insert_job,p,15,3819);
    memcpy(p,running,sizeof(p)); p[9]=U64(9); (void)execute(insert_job,p,15,3819);
    memcpy(p,running,sizeof(p)); p[9]=U64(21); (void)execute(insert_job,p,15,3819);
    memcpy(p,running,sizeof(p)); p[10]=U64(20); (void)execute(insert_job,p,15,3819);
    memcpy(p,running,sizeof(p)); p[7]=U64(10); (void)execute(insert_job,p,15,3819);
    memcpy(p,running,sizeof(p)); p[5]=U64(1000000); p[6]=U64(UINT64_MAX); (void)execute(insert_job,p,15,0);
    (void)execute("UPDATE gc_jobs SET version=version+1 WHERE id=99",NULL,0,1690);
    (void)execute("UPDATE gc_jobs SET attempts=attempts+1 WHERE id=99",NULL,0,3819);
    (void)execute("UPDATE gc_jobs SET state=1,next_run_at_ms=100,claim_id=NULL,claimed_at_ms=NULL,lease_expires_at_ms=NULL WHERE id=99",NULL,0,3819);
    command("UPDATE gc_jobs SET state=5,last_error=2,claim_id=NULL,claimed_at_ms=NULL,lease_expires_at_ms=NULL,finished_at_ms=20 WHERE id=99");
    /* 三终态必须finished，成功无错/失败有错。 */
    for(uint64_t state=3;state<=5;++state) {
        memcpy(p,base,sizeof(p)); p[4]=U64(state); p[7]=NIL; p[11]=U64(state==5 ? 2 : 0);
        (void)execute(insert_job,p,15,3819); p[14]=U64(9); (void)execute(insert_job,p,15,3819);
        p[14]=U64(21); (void)execute(insert_job,p,15,3819);
    }
    (void)execute("UPDATE gc_jobs SET last_error=1 WHERE id=23",NULL,0,3819);
    (void)execute("UPDATE gc_jobs SET last_error=0 WHERE id=25",NULL,0,3819);
    (void)execute("UPDATE gc_jobs SET active_slot=2 WHERE id=10",NULL,0,3105);
    puts("PASS resource/operation/state/NULL/binary/attempt/version/schedule/claim/error/time boundaries and overflow");
}
static const char claim_a[]="UPDATE gc_jobs SET state=2,attempts=attempts+1,version=version+1,next_run_at_ms=NULL,claim_id=REPEAT(X'A1',16),claimed_at_ms=20,lease_expires_at_ms=30,updated_at_ms=20 WHERE id=10 AND state=1 AND version=1 AND next_run_at_ms<=20 AND attempts<1000000 AND version<18446744073709551615";
static const char finish_a[]="UPDATE gc_jobs SET state=3,last_error=0,version=version+1,claim_id=NULL,claimed_at_ms=NULL,lease_expires_at_ms=NULL,finished_at_ms=25,updated_at_ms=25 WHERE id=10 AND state=2 AND version=2 AND claim_id=REPEAT(X'A1',16) AND lease_expires_at_ms>25 AND version<18446744073709551615";
static void claims(const vireo_mysql_connection_options_t *options)
{
    vireo_mysql_connection_t *a=connection,*b=NULL; CHECK(vireo_mysql_connection_open(thread,options,&b,NULL));
    scalar("SELECT version FROM gc_jobs WHERE id=10","1"); connection=b;
    scalar("SELECT version FROM gc_jobs WHERE id=10","1"); connection=a;
    command("SET autocommit=0"); assert(execute(claim_a,NULL,0,0).affected_rows==1); command("ROLLBACK"); command("SET autocommit=1");
    scalar("SELECT CONCAT(state,'|',version,'|',attempts) FROM gc_jobs WHERE id=10","1|1|0");
    assert(execute(claim_a,NULL,0,0).affected_rows==1); connection=b;
    assert(execute(claim_a,NULL,0,0).affected_rows==0);
    assert(execute("UPDATE gc_jobs SET version=version+1 WHERE id=10 AND state=2 AND lease_expires_at_ms<=29",NULL,0,0).affected_rows==0);
    assert(execute("UPDATE gc_jobs SET attempts=attempts+1,version=version+1,claim_id=REPEAT(X'B1',16),claimed_at_ms=30,lease_expires_at_ms=40,updated_at_ms=30 WHERE id=10 AND state=2 AND version=2 AND lease_expires_at_ms<=30 AND attempts<1000000 AND version<18446744073709551615",NULL,0,0).affected_rows==1);
    connection=a; assert(execute(finish_a,NULL,0,0).affected_rows==0);
    /* 正确claim在expires瞬间也无完成资格。 */
    assert(execute("UPDATE gc_jobs SET version=version+1 WHERE id=10 AND state=2 AND version=3 AND claim_id=REPEAT(X'B1',16) AND lease_expires_at_ms>40",NULL,0,0).affected_rows==0);
    connection=b;
    assert(execute("UPDATE gc_jobs SET state=1,next_run_at_ms=50,version=version+1,claim_id=NULL,claimed_at_ms=NULL,lease_expires_at_ms=NULL,last_error=2,updated_at_ms=35 WHERE id=10 AND state=2 AND version=3 AND claim_id=REPEAT(X'B1',16) AND lease_expires_at_ms>35",NULL,0,0).affected_rows==1);
    assert(execute("UPDATE gc_jobs SET version=version+1 WHERE id=10 AND state=1 AND next_run_at_ms<=49",NULL,0,0).affected_rows==0);
    assert(execute("UPDATE gc_jobs SET state=2,next_run_at_ms=NULL,attempts=attempts+1,version=version+1,claim_id=REPEAT(X'C1',16),claimed_at_ms=50,lease_expires_at_ms=60,updated_at_ms=50 WHERE id=10 AND state=1 AND version=4 AND next_run_at_ms<=50 AND attempts<1000000 AND version<18446744073709551615",NULL,0,0).affected_rows==1);
    scalar("SELECT CONCAT(version,'|',attempts) FROM gc_jobs WHERE id=10","5|3");
    (void)execute("UPDATE gc_jobs SET claim_id=REPEAT(X'C1',16) WHERE id=22",NULL,0,1062);
    /* READY和RUNNING共用active slot。 */
    unsigned char key[32]; memset(key,0x10,32); vireo_mysql_parameter_t p[15]; values(p,key); p[0]=U64(1000);
    (void)execute(insert_job,p,15,1062);
    assert(execute("UPDATE gc_jobs SET state=3,version=version+1,last_error=0,claim_id=NULL,claimed_at_ms=NULL,lease_expires_at_ms=NULL,finished_at_ms=55,updated_at_ms=55 WHERE id=10 AND state=2 AND version=5 AND claim_id=REPEAT(X'C1',16) AND lease_expires_at_ms>55",NULL,0,0).affected_rows==1);
    p[0]=U64(1000); (void)execute(insert_job,p,15,0);
    p[0]=U64(1001); (void)execute(insert_job,p,15,1062);
    command("UPDATE gc_jobs SET state=4,next_run_at_ms=NULL,finished_at_ms=20,version=version+1 WHERE id=1000");
    (void)execute(insert_job,p,15,0); /* 第三次生命周期，两个旧终态仍保留。 */
    scalar("SELECT COUNT(*) FROM gc_jobs WHERE resource_kind=1 AND resource_key=REPEAT(X'10',32)","3");
    (void)execute("UPDATE gc_jobs SET state=1,finished_at_ms=NULL,next_run_at_ms=55 WHERE id=10",NULL,0,1062);
    connection=a; CHECK(vireo_mysql_connection_destroy(thread,&b));
    puts("PASS two real connections observed same version, single claim CAS, rollback, exact expiry/reclaim, stale completion zero, retry due/count/new token, active dedup and terminal histories/requeue");
}
static void counterexamples(void)
{
    char before[SNAPSHOT_CAPACITY],after[SNAPSHOT_CAPACITY]; capture(snapshot_sql,before);
    command("SET autocommit=0"); command("UPDATE objects SET ref_count=1 WHERE object_hash=REPEAT(X'BB',32)");
    add(2000,0xbb,1,1); scalar("SELECT ref_count FROM objects WHERE object_hash=REPEAT(X'BB',32)","1");
    /* DB允许仍被file_node/manifest/download保护的资源有GC意图，意图不是删除授权。 */
    scalar("SELECT COUNT(*) FROM gc_jobs WHERE id=2000","1");
    (void)execute("UPDATE gc_jobs SET version=0 WHERE id=2000",NULL,0,3819);
    scalar("SELECT ref_count FROM objects WHERE object_hash=REPEAT(X'BB',32)","1");
    command("ROLLBACK"); command("SET autocommit=1"); capture(snapshot_sql,after); assert(!strcmp(before,after));
    command("SET autocommit=0"); add(2001,0xfe,1,1); command("COMMIT"); command("SET autocommit=1");
    /* 无FK：不存在metadata也可持久化历史；但可信writer仍须核真实资源。 */
    scalar("SELECT COUNT(*) FROM objects WHERE object_hash=REPEAT(X'FE',32)","0");
    scalar("SELECT COUNT(*) FROM gc_jobs WHERE id=2001","1");
    command("UPDATE gc_jobs SET version=1 WHERE id=10"); /* CHECK不保证版本单调。 */
    scalar("SELECT version FROM gc_jobs WHERE id=10","1");
    /* 没有活等价任务时，SQL也容许复活旧终态；业务必须明确禁止。 */
    command("UPDATE gc_jobs SET state=1,finished_at_ms=NULL,next_run_at_ms=20 WHERE id=24");
    command("UPDATE gc_jobs SET state=4,finished_at_ms=20,next_run_at_ms=NULL WHERE id=24");
    command("DELETE FROM gc_jobs WHERE id=2001");
    puts("PASS intent+business transaction rollback/commit, rejected statement preserves prior DML until rollback, dangling resource history and unconstrained transition/version counterexamples; no physical deletion claim");
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
    if(versions>=7) { row(s,"7|1|8D6A75B694EADECB3EE8B62519759C33093D1655B3F74AC1325B2DB5C4D1C975"); }
    if(versions==8) { row(s,"8|1|4938132DDBFA2FD61BFE5D14A5262CEAEF8489AF8E7392307EC502870C9BB446"); } done(&s);
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
    const vireo_mysql_migration_t *catalog=NULL; size_t count=0; CHECK(vireo_mysql_schema_catalog(&catalog,&count)); assert(count==10); count=8; /* 独立保留v8前缀与升级验证。 */
    vireo_mysql_migration_report_t report; apply(&options,catalog,count,&report);
    assert(report.applied_before==0 && report.applied_after==8 && report.steps_completed==14 && report.migrations_applied==8 && report.write_attempted);
    CHECK(vireo_mysql_connection_open(thread,&options,&connection,NULL));
    metadata(); seed(); rows(); claims(&options); counterexamples(); ledger(8);
    char before[SNAPSHOT_CAPACITY],after[SNAPSHOT_CAPACITY]; capture(snapshot_sql,before);
    apply(&options,catalog,count,&report);
    assert(report.applied_before==8 && report.applied_after==8 && !report.steps_completed && !report.write_attempted && !report.migrations_applied);
    capture(snapshot_sql,after); assert(!strcmp(before,after)); ledger(8);
    CHECK(vireo_mysql_connection_destroy(thread,&connection));
    options.database="vireo_gc_upgrade"; apply(&options,catalog,7,&report);
    assert(report.applied_before==0 && report.applied_after==7 && report.steps_completed==13 && report.migrations_applied==7);
    CHECK(vireo_mysql_connection_open(thread,&options,&connection,NULL)); seed(); capture(seed_snapshot_sql,before); ledger(7);
    apply(&options,catalog,count,&report);
    assert(report.applied_before==7 && report.applied_after==8 && report.steps_completed==1 && report.migrations_applied==1 && report.write_attempted);
    capture(seed_snapshot_sql,after); assert(!strcmp(before,after)); metadata(); ledger(8);
    scalar("SELECT COUNT(*) FROM gc_jobs","0"); add(10,0x10,1,1);
    capture(snapshot_sql,before); apply(&options,catalog,count,&report);
    assert(report.applied_before==8 && report.applied_after==8 && !report.write_attempted && !report.steps_completed);
    capture(snapshot_sql,after); assert(!strcmp(before,after)); ledger(8);
    CHECK(vireo_mysql_connection_destroy(thread,&connection)); CHECK(vireo_mysql_thread_detach(&thread)); CHECK(vireo_mysql_runtime_destroy(&runtime));
    assert(fd_count()==before_fd); memset(password,0,sizeof(password));
    printf("PASS empty14/seeded-v7 thirteen-table upgrade1/repeat eight hashes and exact rows, %zu rejected writes unchanged across fourteen business tables, FD %zu -> %zu\n",rejected,before_fd,fd_count());
    return 0;
}
