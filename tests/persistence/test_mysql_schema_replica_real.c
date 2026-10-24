/*
 * PROJECT : VIREO
 * FILE    : test_mysql_schema_replica_real.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-19
 * BRIEF   : 真实v6节点/副本约束、双代际与含v5九表数据升级。
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
static const vireo_mysql_statement_limits_t limits={16,16,4096,4096,262144};
static size_t rejected;
static const char insert_node[]="INSERT INTO storage_nodes(node_uuid,endpoint,zone,status,capacity_bytes,used_bytes,generation,created_at_ms,updated_at_ms,last_heartbeat_at_ms) VALUES(?,?,?,?,?,?,?,?,?,?)";
static const char insert_replica[]="INSERT INTO chunk_replicas(chunk_hash,node_id,state,generation,node_generation,created_at_ms,updated_at_ms,verified_at_ms) VALUES(?,?,?,?,?,?,?,?)";
static const char snapshot_sql[]=
    "SELECT CONCAT_WS('|','N',id,HEX(node_uuid),HEX(endpoint),HEX(zone),status,capacity_bytes,used_bytes,generation,created_at_ms,updated_at_ms,COALESCE(last_heartbeat_at_ms,'N')) AS v FROM storage_nodes "
    "UNION ALL SELECT CONCAT_WS('|','R',HEX(chunk_hash),node_id,state,generation,node_generation,created_at_ms,updated_at_ms,COALESCE(verified_at_ms,'N')) FROM chunk_replicas "
    "UNION ALL SELECT CONCAT_WS('|','C',HEX(chunk_hash),size,state,ref_count,created_at_ms,updated_at_ms,COALESCE(verified_at_ms,'N')) FROM chunks ORDER BY v";

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
static void capture(const char *sql,char out[SNAPSHOT_CAPACITY])
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
 * @brief 执行一条DML；拒绝前后核完整节点/副本/块行保持。
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

static void node_values(vireo_mysql_parameter_t p[10],const unsigned char uuid[16])
{
    static const unsigned char endpoint[]="vireo.example:7443",zone[]="zone-a";
    p[0]=BYTES(uuid,16); p[1]=BYTES(endpoint,sizeof(endpoint)-1); p[2]=BYTES(zone,sizeof(zone)-1);
    p[3]=U64(1); p[4]=U64(100); p[5]=U64(4); p[6]=U64(3); p[7]=U64(10); p[8]=U64(20); p[9]=U64(15);
}
static void add_node(uint64_t id,unsigned char tag,uint64_t status,uint64_t capacity,uint64_t used,uint64_t generation)
{
    unsigned char uuid[16]; memset(uuid,tag,sizeof(uuid));
    vireo_mysql_parameter_t p[]={U64(id),BYTES(uuid,16),U64(status),U64(capacity),U64(used),U64(generation),status<=2 ? U64(15) : NIL};
    (void)execute("INSERT INTO storage_nodes(id,node_uuid,endpoint,zone,status,capacity_bytes,used_bytes,generation,created_at_ms,updated_at_ms,last_heartbeat_at_ms) VALUES(?,?,'vireo.example:7443','zone-a',?,?,?,?,10,20,?)",p,7,0);
}
static void add_chunk(unsigned char tag,uint64_t state)
{
    unsigned char hash[32]; memset(hash,tag,sizeof(hash));
    vireo_mysql_parameter_t p[]={BYTES(hash,32),U64(state),state==2 ? U64(15) : NIL};
    (void)execute("INSERT INTO chunks(chunk_hash,size,state,ref_count,created_at_ms,updated_at_ms,verified_at_ms) VALUES(?,4,?,0,10,20,?)",p,3,0);
}
static void replica_values(vireo_mysql_parameter_t p[8],const unsigned char hash[32])
{
    p[0]=BYTES(hash,32); p[1]=U64(1); p[2]=U64(2); p[3]=U64(9); p[4]=U64(3);
    p[5]=U64(10); p[6]=U64(20); p[7]=U64(15);
}
static void replica(unsigned char tag,uint64_t node,uint64_t state,uint64_t generation,uint64_t node_generation,unsigned int code)
{
    unsigned char hash[32]; memset(hash,tag,sizeof(hash)); vireo_mysql_parameter_t p[8]; replica_values(p,hash);
    p[1]=U64(node); p[2]=U64(state); p[3]=U64(generation); p[4]=U64(node_generation); if(state!=2) { p[7]=NIL; }
    (void)execute(insert_replica,p,8,code);
}
static void metadata(void)
{
    scalar("SELECT VERSION() REGEXP '^8[.]0[.]'","1");
    scalar("SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE()","12");
    vireo_mysql_statement_t *s=query("SELECT CONCAT_WS('|',TABLE_NAME,ENGINE,TABLE_COLLATION) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME IN ('storage_nodes','chunk_replicas') ORDER BY TABLE_NAME");
    row(s,"chunk_replicas|InnoDB|utf8mb4_bin"); row(s,"storage_nodes|InnoDB|utf8mb4_bin"); done(&s);
    static const char *const columns[]={
        "chunk_replicas|chunk_hash|varbinary(32)|32|32|NO|NULL||-|-",
        "chunk_replicas|node_id|bigint unsigned|-|-|NO|NULL||-|-",
        "chunk_replicas|state|tinyint unsigned|-|-|NO|NULL||-|-",
        "chunk_replicas|generation|bigint unsigned|-|-|NO|NULL||-|-",
        "chunk_replicas|node_generation|bigint unsigned|-|-|NO|NULL||-|-",
        "chunk_replicas|created_at_ms|bigint unsigned|-|-|NO|NULL||-|-",
        "chunk_replicas|updated_at_ms|bigint unsigned|-|-|NO|NULL||-|-",
        "chunk_replicas|verified_at_ms|bigint unsigned|-|-|YES|NULL||-|-",
        "storage_nodes|id|bigint unsigned|-|-|NO|NULL|auto_increment|-|-",
        "storage_nodes|node_uuid|varbinary(16)|16|16|NO|NULL||-|-",
        "storage_nodes|endpoint|varbinary(512)|512|512|NO|NULL||-|-",
        "storage_nodes|zone|varbinary(64)|64|64|NO|NULL||-|-",
        "storage_nodes|status|tinyint unsigned|-|-|NO|NULL||-|-",
        "storage_nodes|capacity_bytes|bigint unsigned|-|-|NO|NULL||-|-",
        "storage_nodes|used_bytes|bigint unsigned|-|-|NO|NULL||-|-",
        "storage_nodes|generation|bigint unsigned|-|-|NO|NULL||-|-",
        "storage_nodes|created_at_ms|bigint unsigned|-|-|NO|NULL||-|-",
        "storage_nodes|updated_at_ms|bigint unsigned|-|-|NO|NULL||-|-",
        "storage_nodes|last_heartbeat_at_ms|bigint unsigned|-|-|YES|NULL||-|-"};
    s=query("SELECT CONCAT_WS('|',TABLE_NAME,COLUMN_NAME,COLUMN_TYPE,COALESCE(CAST(CHARACTER_MAXIMUM_LENGTH AS CHAR),'-'),COALESCE(CAST(CHARACTER_OCTET_LENGTH AS CHAR),'-'),IS_NULLABLE,COALESCE(COLUMN_DEFAULT,'NULL'),EXTRA,COALESCE(CHARACTER_SET_NAME,'-'),COALESCE(COLLATION_NAME,'-')) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME IN ('storage_nodes','chunk_replicas') ORDER BY TABLE_NAME,ORDINAL_POSITION");
    for(size_t i=0;i<sizeof(columns)/sizeof(columns[0]);++i) { row(s,columns[i]); } done(&s);
    static const char *const indexes[]={
        "chunk_replicas|chunk_replicas_chunk_state|1|1|chunk_hash|BTREE|-|A|YES",
        "chunk_replicas|chunk_replicas_chunk_state|1|2|state|BTREE|-|A|YES",
        "chunk_replicas|chunk_replicas_chunk_state|1|3|node_id|BTREE|-|A|YES",
        "chunk_replicas|chunk_replicas_node_state|1|1|node_id|BTREE|-|A|YES",
        "chunk_replicas|chunk_replicas_node_state|1|2|state|BTREE|-|A|YES",
        "chunk_replicas|chunk_replicas_node_state|1|3|chunk_hash|BTREE|-|A|YES",
        "chunk_replicas|PRIMARY|0|1|chunk_hash|BTREE|-|A|YES",
        "chunk_replicas|PRIMARY|0|2|node_id|BTREE|-|A|YES",
        "storage_nodes|PRIMARY|0|1|id|BTREE|-|A|YES",
        "storage_nodes|storage_nodes_status_heartbeat|1|1|status|BTREE|-|A|YES",
        "storage_nodes|storage_nodes_status_heartbeat|1|2|last_heartbeat_at_ms|BTREE|-|A|YES",
        "storage_nodes|storage_nodes_status_heartbeat|1|3|id|BTREE|-|A|YES",
        "storage_nodes|storage_nodes_status_zone_capacity|1|1|status|BTREE|-|A|YES",
        "storage_nodes|storage_nodes_status_zone_capacity|1|2|zone|BTREE|-|A|YES",
        "storage_nodes|storage_nodes_status_zone_capacity|1|3|capacity_bytes|BTREE|-|A|YES",
        "storage_nodes|storage_nodes_status_zone_capacity|1|4|id|BTREE|-|A|YES",
        "storage_nodes|storage_nodes_uuid_unique|0|1|node_uuid|BTREE|-|A|YES"};
    s=query("SELECT CONCAT_WS('|',TABLE_NAME,INDEX_NAME,NON_UNIQUE,SEQ_IN_INDEX,COLUMN_NAME,INDEX_TYPE,COALESCE(CAST(SUB_PART AS CHAR),'-'),COLLATION,IS_VISIBLE) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME IN ('storage_nodes','chunk_replicas') ORDER BY TABLE_NAME,INDEX_NAME,SEQ_IN_INDEX");
    for(size_t i=0;i<sizeof(indexes)/sizeof(indexes[0]);++i) { row(s,indexes[i]); } done(&s);
    static const char *const checks[]={
        "chunk_replicas|chunk_replicas_generation_valid|YES",
        "chunk_replicas|chunk_replicas_hash_valid|YES",
        "chunk_replicas|chunk_replicas_node_generation_valid|YES",
        "chunk_replicas|chunk_replicas_state_valid|YES",
        "chunk_replicas|chunk_replicas_updated_order|YES",
        "chunk_replicas|chunk_replicas_verified_order|YES",
        "chunk_replicas|chunk_replicas_verified_required|YES",
        "storage_nodes|storage_nodes_capacity_valid|YES",
        "storage_nodes|storage_nodes_endpoint_valid|YES",
        "storage_nodes|storage_nodes_generation_valid|YES",
        "storage_nodes|storage_nodes_heartbeat_order|YES",
        "storage_nodes|storage_nodes_heartbeat_required|YES",
        "storage_nodes|storage_nodes_status_valid|YES",
        "storage_nodes|storage_nodes_updated_order|YES",
        "storage_nodes|storage_nodes_uuid_valid|YES",
        "storage_nodes|storage_nodes_zone_valid|YES"};
    s=query("SELECT CONCAT_WS('|',TABLE_NAME,CONSTRAINT_NAME,ENFORCED) FROM information_schema.TABLE_CONSTRAINTS WHERE CONSTRAINT_SCHEMA=DATABASE() AND TABLE_NAME IN ('storage_nodes','chunk_replicas') AND CONSTRAINT_TYPE='CHECK' ORDER BY TABLE_NAME,CONSTRAINT_NAME");
    for(size_t i=0;i<sizeof(checks)/sizeof(checks[0]);++i) { row(s,checks[i]); } done(&s);
    s=query("SELECT CONCAT_WS('|',k.CONSTRAINT_NAME,k.COLUMN_NAME,k.REFERENCED_TABLE_NAME,k.REFERENCED_COLUMN_NAME,r.UPDATE_RULE,r.DELETE_RULE) FROM information_schema.KEY_COLUMN_USAGE k JOIN information_schema.REFERENTIAL_CONSTRAINTS r ON k.CONSTRAINT_SCHEMA=r.CONSTRAINT_SCHEMA AND k.CONSTRAINT_NAME=r.CONSTRAINT_NAME WHERE k.CONSTRAINT_SCHEMA=DATABASE() AND k.TABLE_NAME='chunk_replicas' ORDER BY k.CONSTRAINT_NAME,k.ORDINAL_POSITION");
    row(s,"chunk_replicas_chunk_fk|chunk_hash|chunks|chunk_hash|RESTRICT|RESTRICT");
    row(s,"chunk_replicas_node_fk|node_id|storage_nodes|id|RESTRICT|RESTRICT"); done(&s);
    scalar("SELECT COUNT(*) FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA=DATABASE() AND EVENT_OBJECT_TABLE IN ('storage_nodes','chunk_replicas')","0");
    scalar("SELECT COUNT(*) FROM information_schema.PARTITIONS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME IN ('storage_nodes','chunk_replicas') AND PARTITION_NAME IS NOT NULL","0");
    scalar("SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME IN ('storage_nodes','chunk_replicas') AND GENERATION_EXPRESSION<>''","0");
    puts("PASS complete v6 metadata: nineteen columns, seven full indexes, two RESTRICT FK, sixteen enforced CHECK; no trigger/generated/partition");
}
static void node_rows(void)
{
    add_node(1,0x11,1,100,4,3); add_node(2,0x22,2,UINT64_MAX,UINT64_MAX,UINT64_MAX);
    add_node(3,0x33,3,0,0,1); add_node(4,0x44,4,1,0,1);
    unsigned char uuid[17]; memset(uuid,0x55,sizeof(uuid)); vireo_mysql_parameter_t p[10];
    for(size_t i=0;i<9;++i) { node_values(p,uuid); p[i]=NIL; (void)execute(insert_node,p,10,1048); }
    node_values(p,uuid); p[9]=NIL; (void)execute(insert_node,p,10,3819);
    for(size_t i=0;i<3;++i) {
        node_values(p,uuid); size_t length=i==0 ? 0U : i==1 ? 15U : 17U;
        p[0]=BYTES(uuid,length); (void)execute(insert_node,p,10,length==17 ? 1406 : 3819);
    }
    unsigned char locator[513]; memset(locator,'a',sizeof(locator));
    node_values(p,uuid); p[1]=BYTES(locator,0); (void)execute(insert_node,p,10,3819);
    p[1]=BYTES(locator,513); (void)execute(insert_node,p,10,1406);
    locator[1]=0; p[1]=BYTES(locator,2); (void)execute(insert_node,p,10,3819); locator[1]='a';
    node_values(p,uuid); p[2]=BYTES(locator,0); (void)execute(insert_node,p,10,3819);
    p[2]=BYTES(locator,65); (void)execute(insert_node,p,10,1406);
    locator[0]=0; p[2]=BYTES(locator,1); (void)execute(insert_node,p,10,3819); locator[0]='a';
    node_values(p,uuid); p[3]=U64(0); (void)execute(insert_node,p,10,3819);
    p[3]=U64(5); (void)execute(insert_node,p,10,3819); p[3]=U64(256); (void)execute(insert_node,p,10,1264);
    for(size_t i=3;i<10;++i) { node_values(p,uuid); p[i]=I64(-1); (void)execute(insert_node,p,10,1264); }
    node_values(p,uuid); p[5]=U64(101); (void)execute(insert_node,p,10,3819);
    node_values(p,uuid); p[6]=U64(0); (void)execute(insert_node,p,10,3819);
    node_values(p,uuid); p[8]=U64(9); (void)execute(insert_node,p,10,3819);
    node_values(p,uuid); p[9]=U64(9); (void)execute(insert_node,p,10,3819);
    p[9]=U64(21); (void)execute(insert_node,p,10,3819);
    node_values(p,uuid); p[3]=U64(2); p[9]=NIL; (void)execute(insert_node,p,10,3819);
    node_values(p,uuid); p[1]=BYTES(locator,512); p[2]=BYTES(locator,64); p[7]=U64(0); p[8]=U64(0); p[9]=U64(0);
    (void)execute(insert_node,p,10,0); (void)execute(insert_node,p,10,1062);
    add_node(10,0,3,0,0,1); add_node(11,0x41,3,0,0,1); add_node(12,0x61,3,0,0,1);
    memset(uuid,0x77,16); uuid[15]=0; node_values(p,uuid); (void)execute(insert_node,p,10,0);
    uuid[15]=0x20; (void)execute(insert_node,p,10,0);
    scalar("SELECT COUNT(*) FROM storage_nodes WHERE LEFT(node_uuid,15)=REPEAT(X'77',15)","2");
    scalar("SELECT COUNT(*) FROM storage_nodes WHERE node_uuid IN (REPEAT(X'41',16),REPEAT(X'61',16))","2");
    command("UPDATE storage_nodes SET zone=X'7A20' WHERE id=3");
    command("UPDATE storage_nodes SET zone=X'7A' WHERE id=4");
    scalar("SELECT COUNT(DISTINCT zone) FROM storage_nodes WHERE id IN (3,4)","2");
    (void)execute("UPDATE storage_nodes SET used_bytes=101 WHERE id=1",NULL,0,3819);
    (void)execute("UPDATE storage_nodes SET status=1 WHERE id=3",NULL,0,3819);
    (void)execute("UPDATE storage_nodes SET last_heartbeat_at_ms=NULL WHERE id=2",NULL,0,3819);
    (void)execute("UPDATE storage_nodes SET generation=0 WHERE id=1",NULL,0,3819);
    (void)execute("UPDATE storage_nodes SET node_uuid=REPEAT(X'11',16) WHERE id=2",NULL,0,1062);
    (void)execute("UPDATE storage_nodes SET id=-1 WHERE id=3",NULL,0,1264);
    node_values(p,uuid); memset(uuid,0x66,16); p[3]=U64(4); p[6]=U64(UINT64_MAX);
    p[7]=U64(UINT64_MAX); p[8]=U64(UINT64_MAX); p[9]=U64(UINT64_MAX); (void)execute(insert_node,p,10,0);
    puts("PASS node UUID exact bytes/zero/NUL/case/trailing-space; bounded non-NUL locator/zone; all statuses/capacity/time/generation/NULL/uint edges and rejected UPDATE");
}
static void replica_rows(void)
{
    add_chunk(0xa0,2); add_chunk(0xa1,1); add_chunk(0xa2,2); add_chunk(0,2);
    replica(0xa0,1,2,9,3,0); replica(0xa0,2,2,1,UINT64_MAX,0); replica(0xa1,1,1,1,3,0);
    replica(0xa0,1,2,9,3,1062); replica(0xff,1,1,1,3,1452); replica(0xa0,999999,1,1,1,1452);
    unsigned char hash[33]; memset(hash,0xa2,sizeof(hash)); vireo_mysql_parameter_t p[8];
    for(size_t i=0;i<7;++i) { replica_values(p,hash); p[i]=NIL; (void)execute(insert_replica,p,8,1048); }
    replica_values(p,hash); p[7]=NIL; (void)execute(insert_replica,p,8,3819);
    for(size_t i=0;i<3;++i) {
        replica_values(p,hash); size_t length=i==0 ? 0U : i==1 ? 31U : 33U;
        p[0]=BYTES(hash,length); (void)execute(insert_replica,p,8,length==33 ? 1406 : 3819);
    }
    for(size_t i=1;i<8;++i) { replica_values(p,hash); p[i]=I64(-1); (void)execute(insert_replica,p,8,1264); }
    replica_values(p,hash); p[2]=U64(0); (void)execute(insert_replica,p,8,3819);
    p[2]=U64(6); (void)execute(insert_replica,p,8,3819); p[2]=U64(256); (void)execute(insert_replica,p,8,1264);
    replica_values(p,hash); p[3]=U64(0); (void)execute(insert_replica,p,8,3819);
    replica_values(p,hash); p[4]=U64(0); (void)execute(insert_replica,p,8,3819);
    replica_values(p,hash); p[6]=U64(9); (void)execute(insert_replica,p,8,3819);
    replica_values(p,hash); p[7]=U64(9); (void)execute(insert_replica,p,8,3819);
    p[7]=U64(21); (void)execute(insert_replica,p,8,3819);
    replica(0xa2,1,3,UINT64_MAX,UINT64_MAX,0); replica(0xa2,2,4,1,1,0); replica(0xa2,3,5,1,1,0);
    memset(hash,0,32); replica_values(p,hash); p[3]=U64(UINT64_MAX); p[4]=U64(UINT64_MAX);
    p[5]=U64(UINT64_MAX); p[6]=U64(UINT64_MAX); p[7]=U64(UINT64_MAX); (void)execute(insert_replica,p,8,0);
    scalar("SELECT COUNT(*) FROM chunk_replicas WHERE chunk_hash=REPEAT(X'A0',32)","2");
    scalar("SELECT COUNT(*) FROM chunk_replicas WHERE node_id=1","4");
    scalar("SELECT ref_count FROM chunks WHERE chunk_hash=REPEAT(X'A0',32)","0");
    (void)execute("DELETE FROM storage_nodes WHERE id=1",NULL,0,1451);
    (void)execute("UPDATE storage_nodes SET id=1000 WHERE id=1",NULL,0,1451);
    (void)execute("DELETE FROM chunks WHERE chunk_hash=REPEAT(X'A0',32)",NULL,0,1451);
    (void)execute("UPDATE chunks SET chunk_hash=REPEAT(X'FF',32) WHERE chunk_hash=REPEAT(X'A0',32)",NULL,0,1451);
    (void)execute("UPDATE chunk_replicas SET node_id=999999 WHERE chunk_hash=REPEAT(X'A0',32)",NULL,0,1452);
    (void)execute("UPDATE chunk_replicas SET chunk_hash=REPEAT(X'FF',32) WHERE node_id=1",NULL,0,1452);
    (void)execute("UPDATE chunk_replicas SET verified_at_ms=NULL WHERE chunk_hash=REPEAT(X'A0',32)",NULL,0,3819);
    (void)execute("UPDATE chunk_replicas SET generation=0 WHERE node_id=1",NULL,0,3819);
    command("UPDATE chunk_replicas SET state=5 WHERE chunk_hash=REPEAT(X'A0',32) AND node_id=2");
    scalar("SELECT verified_at_ms FROM chunk_replicas WHERE chunk_hash=REPEAT(X'A0',32) AND node_id=2","15");
    puts("PASS replicas across nodes/multiple chunks on one node, row PK, both FK/RESTRICT, all states/NULL/time/uint/hash errors, retained verification evidence and unchanged manifest ref_count");
}
/* 这是结构的候选过滤示例，真实下载还须身份、lease与物理证据。 */
static const char candidate_count[]=
    "SELECT COUNT(*) FROM chunk_replicas r JOIN storage_nodes n ON n.id=r.node_id JOIN chunks c ON c.chunk_hash=r.chunk_hash "
    "WHERE r.chunk_hash=REPEAT(X'A0',32) AND r.state=2 AND n.status=1 AND c.state=2 AND r.node_generation=n.generation";
static void generations(void)
{
    scalar(candidate_count,"1");
    command("UPDATE storage_nodes SET generation=4 WHERE id=1");
    scalar("SELECT COUNT(*) FROM chunk_replicas WHERE chunk_hash=REPEAT(X'A0',32) AND node_id=1 AND state=2","1");
    scalar(candidate_count,"0");
    /* 模拟旧worker带节点第3代完成，合法SQL但当前节点第4代谓词保证零更新。 */
    vireo_mysql_execution_t ex=execute("UPDATE chunk_replicas r JOIN storage_nodes n ON n.id=r.node_id SET r.generation=r.generation+1 WHERE r.chunk_hash=REPEAT(X'A0',32) AND r.node_id=1 AND r.generation=9 AND r.node_generation=3 AND n.generation=3",NULL,0,0);
    assert(ex.affected_rows==0);
    command("SET autocommit=0");
    ex=execute("UPDATE chunk_replicas r JOIN storage_nodes n ON n.id=r.node_id SET r.generation=r.generation+1,r.node_generation=n.generation WHERE r.chunk_hash=REPEAT(X'A0',32) AND r.node_id=1 AND r.generation=9 AND n.generation=4",NULL,0,0);
    assert(ex.affected_rows==1); command("COMMIT"); command("SET autocommit=1");
    scalar("SELECT CONCAT(generation,'|',node_generation) FROM chunk_replicas WHERE chunk_hash=REPEAT(X'A0',32) AND node_id=1","10|4"); scalar(candidate_count,"1");
    ex=execute("UPDATE chunk_replicas SET state=3,generation=generation+1 WHERE chunk_hash=REPEAT(X'A0',32) AND node_id=1 AND generation=9",NULL,0,0); assert(ex.affected_rows==0);
    command("UPDATE storage_nodes SET status=4 WHERE id=1"); scalar(candidate_count,"0");
    command("UPDATE storage_nodes SET status=1 WHERE id=1"); scalar(candidate_count,"1");
    command("UPDATE chunks SET state=4 WHERE chunk_hash=REPEAT(X'A0',32)"); scalar(candidate_count,"0");
    command("UPDATE chunks SET state=2 WHERE chunk_hash=REPEAT(X'A0',32)"); scalar(candidate_count,"1");
    /* FK不核父状态/代际，CHECK不核单调性/地址语法/物理容量，保留实际反例。 */
    replica(0xa1,4,2,1,999,0);
    command("SET autocommit=0");
    command("UPDATE chunk_replicas SET generation=1,node_generation=999 WHERE chunk_hash=REPEAT(X'A0',32) AND node_id=1");
    command("UPDATE storage_nodes SET generation=1,endpoint='not a network endpoint',used_bytes=0 WHERE id=1");
    scalar(candidate_count,"0"); command("ROLLBACK"); command("SET autocommit=1"); scalar(candidate_count,"1");
    puts("PASS independent node epoch/replica version, epoch bump retains stale row but filters it, synthetic stale/current CAS, status/global-chunk filters, admitted business counterexamples");
}
static void transactions(void)
{
    char before[SNAPSHOT_CAPACITY],after[SNAPSHOT_CAPACITY]; capture(snapshot_sql,before);
    command("SET autocommit=0"); replica(0xa0,3,1,1,1,0);
    command("UPDATE storage_nodes SET used_bytes=used_bytes+1,capacity_bytes=1 WHERE id=3");
    command("ROLLBACK"); command("SET autocommit=1"); capture(snapshot_sql,after); assert(!strcmp(before,after));
    command("SET autocommit=0"); replica(0xa0,3,1,1,1,0);
    command("UPDATE storage_nodes SET used_bytes=used_bytes+1,capacity_bytes=1 WHERE id=3");
    replica(0xa0,3,1,1,1,1062); scalar("SELECT used_bytes FROM storage_nodes WHERE id=3","1");
    command("ROLLBACK"); command("SET autocommit=1"); capture(snapshot_sql,after); assert(!strcmp(before,after));
    command("SET autocommit=0"); replica(0xa0,3,1,1,1,0);
    (void)execute("UPDATE storage_nodes SET generation=generation+1 WHERE id=2",NULL,0,1690);
    scalar("SELECT COUNT(*) FROM chunk_replicas WHERE chunk_hash=REPEAT(X'A0',32) AND node_id=3","1");
    command("ROLLBACK"); command("SET autocommit=1"); capture(snapshot_sql,after); assert(!strcmp(before,after));
    (void)execute("UPDATE chunk_replicas SET generation=generation+1 WHERE chunk_hash=REPEAT(X'A2',32) AND node_id=1",NULL,0,1690);
    (void)execute("UPDATE chunk_replicas SET node_generation=node_generation+1 WHERE chunk_hash=REPEAT(X'A2',32) AND node_id=1",NULL,0,1690);
    (void)execute("UPDATE storage_nodes SET capacity_bytes=capacity_bytes+1 WHERE id=2",NULL,0,1690);
    (void)execute("UPDATE storage_nodes SET used_bytes=used_bytes-1 WHERE id=3",NULL,0,1690);
    add_node(200,0xcc,3,0,0,1); add_chunk(0xcc,2); replica(0xcc,200,2,1,1,0);
    command("SET autocommit=0"); command("DELETE FROM chunk_replicas WHERE node_id=200");
    command("DELETE FROM storage_nodes WHERE id=200"); command("DELETE FROM chunks WHERE chunk_hash=REPEAT(X'CC',32)");
    command("COMMIT"); command("SET autocommit=1"); scalar("SELECT COUNT(*) FROM storage_nodes WHERE id=200","0");
    puts("PASS explicit rollback/duplicate preserves prior DML, checked node/replica generations and capacity overflow/underflow, commit child-before-parent cleanup");
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
    if(versions==6) { row(s,"6|1|B86F6818EFB6C65B264AAD10B09D7FF0EBA9F395FA87FD70939B680A4A0AA3D5"); } done(&s);
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
}
/* 逐个旧九表保存全部字段，含生成列/NULL；升级前尚无新两表，不能用snapshot_sql。 */
static void seed_capture(char out[SNAPSHOT_CAPACITY])
{
    static const char *const selects[]={
        "SELECT CONCAT_WS('|',id,HEX(username),HEX(username_key),HEX(password_hash),status,created_at_ms,updated_at_ms,COALESCE(last_login_at_ms,'N')) FROM users ORDER BY id",
        "SELECT CONCAT_WS('|',id,user_id,HEX(token_digest),status,issued_at_ms,expires_at_ms,COALESCE(revoked_at_ms,'N'),last_seen_at_ms) FROM sessions ORDER BY id",
        "SELECT CONCAT_WS('|',HEX(object_hash),size,state,ref_count,storage_class,created_at_ms,updated_at_ms,COALESCE(verified_at_ms,'N')) FROM objects ORDER BY object_hash",
        "SELECT CONCAT_WS('|',id,owner_id,COALESCE(parent_id,'N'),HEX(name),HEX(name_hash),node_type,state,COALESCE(HEX(object_hash),'N'),size,created_at_ms,updated_at_ms,COALESCE(deleted_at_ms,'N'),COALESCE(HEX(live_name),'N'),COALESCE(active_root_owner,'N')) FROM file_nodes ORDER BY id",
        "SELECT CONCAT_WS('|',id,HEX(request_id),user_id,session_id,action,target_type,target_id,COALESCE(HEX(target_hash),'N'),status,latency_us,HEX(detail),occurred_at_ms) FROM operation_audits ORDER BY id",
        "SELECT CONCAT_WS('|',id,HEX(public_id),user_id,file_node_id,HEX(idempotency_key),HEX(expected_hash),size,mode,chunk_size,chunk_count,state,received_chunks,received_bytes,version,cancel_requested,last_status,created_at_ms,updated_at_ms,expires_at_ms,COALESCE(finished_at_ms,'N')) FROM upload_tasks ORDER BY id",
        "SELECT CONCAT_WS('|',task_id,chunk_index,byte_offset,byte_length,HEX(chunk_hash),crc32c,state,received_at_ms) FROM upload_chunks ORDER BY task_id,chunk_index",
        "SELECT CONCAT_WS('|',HEX(chunk_hash),size,state,ref_count,created_at_ms,updated_at_ms,COALESCE(verified_at_ms,'N')) FROM chunks ORDER BY chunk_hash",
        "SELECT CONCAT_WS('|',HEX(object_hash),chunk_index,byte_offset,byte_length,HEX(chunk_hash)) FROM object_chunks ORDER BY object_hash,chunk_index"};
    size_t used=0; out[0]=0;
    for(size_t i=0;i<sizeof(selects)/sizeof(selects[0]);++i) {
        char rows[SNAPSHOT_CAPACITY]; capture(selects[i],rows); size_t n=strlen(rows); assert(n>0 && n<SNAPSHOT_CAPACITY-used-2);
        out[used++]='\t'; memcpy(out+used,rows,n+1); used+=n;
    }
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
    const vireo_mysql_migration_t *catalog=NULL; size_t count=0; CHECK(vireo_mysql_schema_catalog(&catalog,&count)); assert(count==10); count=6; /* 保留v6完整结构/双代际与升级前缀回归。 */
    vireo_mysql_migration_report_t report; apply(&options,catalog,count,&report);
    assert(report.applied_before==0 && report.applied_after==6 && report.steps_completed==11 && report.migrations_applied==6 && report.write_attempted);
    CHECK(vireo_mysql_connection_open(thread,&options,&connection,NULL));
    metadata(); node_rows(); replica_rows(); generations(); transactions(); ledger(6);
    char before[SNAPSHOT_CAPACITY],after[SNAPSHOT_CAPACITY]; capture(snapshot_sql,before);
    apply(&options,catalog,count,&report);
    assert(report.applied_before==6 && report.applied_after==6 && !report.steps_completed && !report.write_attempted && !report.migrations_applied);
    capture(snapshot_sql,after); assert(!strcmp(before,after)); ledger(6);
    CHECK(vireo_mysql_connection_destroy(thread,&connection));
    options.database="vireo_replica_upgrade"; apply(&options,catalog,5,&report);
    assert(report.applied_before==0 && report.applied_after==5 && report.steps_completed==9 && report.migrations_applied==5);
    CHECK(vireo_mysql_connection_open(thread,&options,&connection,NULL)); seed(); seed_capture(before); ledger(5);
    apply(&options,catalog,count,&report);
    assert(report.applied_before==5 && report.applied_after==6 && report.steps_completed==2 && report.migrations_applied==1 && report.write_attempted);
    seed_capture(after); assert(!strcmp(before,after)); metadata(); ledger(6);
    scalar("SELECT COUNT(*) FROM storage_nodes","0"); scalar("SELECT COUNT(*) FROM chunk_replicas","0");
    add_node(1,0x11,1,100,4,3); replica(0xee,1,2,1,3,0);
    char old_rows[SNAPSHOT_CAPACITY]; seed_capture(old_rows); assert(!strcmp(before,old_rows));
    capture(snapshot_sql,before); apply(&options,catalog,count,&report);
    assert(report.applied_before==6 && report.applied_after==6 && !report.write_attempted && !report.steps_completed);
    capture(snapshot_sql,after); assert(!strcmp(before,after)); seed_capture(after); assert(!strcmp(old_rows,after)); ledger(6);
    CHECK(vireo_mysql_connection_destroy(thread,&connection)); CHECK(vireo_mysql_thread_detach(&thread)); CHECK(vireo_mysql_runtime_destroy(&runtime));
    assert(fd_count()==before_fd); memset(password,0,sizeof(password));
    printf("PASS empty11/seeded-v5 nine-table upgrade2/repeat six hashes and exact rows, %zu rejected writes unchanged, FD %zu -> %zu\n",rejected,before_fd,fd_count());
    return 0;
}
