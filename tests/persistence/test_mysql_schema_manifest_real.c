/*
 * PROJECT : VIREO
 * FILE    : test_mysql_schema_manifest_real.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-19
 * BRIEF   : 真实v5块/manifest元数据、约束、重复块计数与含v4七表数据升级。
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
static const char insert_chunk[]="INSERT INTO chunks(chunk_hash,size,state,ref_count,created_at_ms,updated_at_ms,verified_at_ms) VALUES(?,?,?,?,?,?,?)";
static const char insert_mapping[]="INSERT INTO object_chunks(object_hash,chunk_index,byte_offset,byte_length,chunk_hash) VALUES(?,?,?,?,?)";
static const char snapshot_sql[]=
    "SELECT CONCAT_WS('|','C',HEX(chunk_hash),size,state,ref_count,created_at_ms,updated_at_ms,COALESCE(verified_at_ms,'N')) AS v FROM chunks "
    "UNION ALL SELECT CONCAT_WS('|','M',HEX(object_hash),chunk_index,byte_offset,byte_length,HEX(chunk_hash)) FROM object_chunks "
    "UNION ALL SELECT CONCAT_WS('|','O',HEX(object_hash),size,state,ref_count,storage_class,created_at_ms,updated_at_ms,COALESCE(verified_at_ms,'N')) FROM objects ORDER BY v";

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
 * @brief 执行一条DML；拒绝前后核完整块/映射/对象行保持。
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

static void chunk_values(vireo_mysql_parameter_t p[7],const unsigned char hash[32])
{
    p[0]=BYTES(hash,32); p[1]=U64(4); p[2]=U64(1); p[3]=U64(0);
    p[4]=U64(10); p[5]=U64(20); p[6]=NIL;
}
static void add_chunk(unsigned char tag,uint64_t size,uint64_t state,uint64_t refs)
{
    unsigned char hash[32]; memset(hash,tag,sizeof(hash)); vireo_mysql_parameter_t p[7]; chunk_values(p,hash);
    p[1]=U64(size); p[2]=U64(state); p[3]=U64(refs); if(state==2) { p[6]=U64(15); }
    (void)execute(insert_chunk,p,7,0);
}
static void add_object(unsigned char tag,uint64_t size)
{
    unsigned char hash[32]; memset(hash,tag,sizeof(hash));
    vireo_mysql_parameter_t p[]={BYTES(hash,32),U64(size)};
    (void)execute("INSERT INTO objects(object_hash,size,state,ref_count,storage_class,created_at_ms,updated_at_ms) VALUES(?,?,1,0,1,0,0)",p,2,0);
}
static void mapping(unsigned char object,uint64_t index,uint64_t offset,uint64_t length,
    unsigned char chunk,unsigned int code)
{
    unsigned char o[32],c[32]; memset(o,object,sizeof(o)); memset(c,chunk,sizeof(c));
    vireo_mysql_parameter_t p[]={BYTES(o,32),U64(index),U64(offset),U64(length),BYTES(c,32)};
    (void)execute(insert_mapping,p,5,code);
}
static void metadata(void)
{
    scalar("SELECT VERSION() REGEXP '^8[.]0[.]'","1");
    scalar("SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE()","10");
    vireo_mysql_statement_t *s=query("SELECT CONCAT_WS('|',TABLE_NAME,ENGINE,TABLE_COLLATION) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME IN ('chunks','object_chunks') ORDER BY TABLE_NAME");
    row(s,"chunks|InnoDB|utf8mb4_bin"); row(s,"object_chunks|InnoDB|utf8mb4_bin"); done(&s);
    static const char *const columns[]={
        "chunks|chunk_hash|varbinary(32)|32|32|NO|NULL||-|-",
        "chunks|size|int unsigned|-|-|NO|NULL||-|-",
        "chunks|state|tinyint unsigned|-|-|NO|NULL||-|-",
        "chunks|ref_count|bigint unsigned|-|-|NO|NULL||-|-",
        "chunks|created_at_ms|bigint unsigned|-|-|NO|NULL||-|-",
        "chunks|updated_at_ms|bigint unsigned|-|-|NO|NULL||-|-",
        "chunks|verified_at_ms|bigint unsigned|-|-|YES|NULL||-|-",
        "object_chunks|object_hash|binary(32)|32|32|NO|NULL||-|-",
        "object_chunks|chunk_index|int unsigned|-|-|NO|NULL||-|-",
        "object_chunks|byte_offset|bigint unsigned|-|-|NO|NULL||-|-",
        "object_chunks|byte_length|int unsigned|-|-|NO|NULL||-|-",
        "object_chunks|chunk_hash|varbinary(32)|32|32|NO|NULL||-|-"};
    s=query("SELECT CONCAT_WS('|',TABLE_NAME,COLUMN_NAME,COLUMN_TYPE,COALESCE(CAST(CHARACTER_MAXIMUM_LENGTH AS CHAR),'-'),COALESCE(CAST(CHARACTER_OCTET_LENGTH AS CHAR),'-'),IS_NULLABLE,COALESCE(COLUMN_DEFAULT,'NULL'),EXTRA,COALESCE(CHARACTER_SET_NAME,'-'),COALESCE(COLLATION_NAME,'-')) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME IN ('chunks','object_chunks') ORDER BY TABLE_NAME,ORDINAL_POSITION");
    for(size_t i=0;i<sizeof(columns)/sizeof(columns[0]);++i) { row(s,columns[i]); } done(&s);
    static const char *const indexes[]={
        "chunks|chunks_refs_state|1|1|ref_count|BTREE|-|A|YES",
        "chunks|chunks_refs_state|1|2|state|BTREE|-|A|YES",
        "chunks|chunks_refs_state|1|3|chunk_hash|BTREE|-|A|YES",
        "chunks|chunks_state_updated|1|1|state|BTREE|-|A|YES",
        "chunks|chunks_state_updated|1|2|updated_at_ms|BTREE|-|A|YES",
        "chunks|chunks_state_updated|1|3|chunk_hash|BTREE|-|A|YES",
        "chunks|PRIMARY|0|1|chunk_hash|BTREE|-|A|YES",
        "object_chunks|object_chunks_chunk|1|1|chunk_hash|BTREE|-|A|YES",
        "object_chunks|object_chunks_chunk|1|2|object_hash|BTREE|-|A|YES",
        "object_chunks|object_chunks_chunk|1|3|chunk_index|BTREE|-|A|YES",
        "object_chunks|object_chunks_offset_unique|0|1|object_hash|BTREE|-|A|YES",
        "object_chunks|object_chunks_offset_unique|0|2|byte_offset|BTREE|-|A|YES",
        "object_chunks|PRIMARY|0|1|object_hash|BTREE|-|A|YES",
        "object_chunks|PRIMARY|0|2|chunk_index|BTREE|-|A|YES"};
    s=query("SELECT CONCAT_WS('|',TABLE_NAME,INDEX_NAME,NON_UNIQUE,SEQ_IN_INDEX,COLUMN_NAME,INDEX_TYPE,COALESCE(CAST(SUB_PART AS CHAR),'-'),COLLATION,IS_VISIBLE) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME IN ('chunks','object_chunks') ORDER BY TABLE_NAME,INDEX_NAME,SEQ_IN_INDEX");
    for(size_t i=0;i<sizeof(indexes)/sizeof(indexes[0]);++i) { row(s,indexes[i]); } done(&s);
    static const char *const checks[]={"chunks|chunks_deleting_unreferenced|YES","chunks|chunks_hash_valid|YES","chunks|chunks_size_valid|YES","chunks|chunks_state_valid|YES","chunks|chunks_updated_order|YES","chunks|chunks_verified_order|YES","chunks|chunks_verified_required|YES","object_chunks|object_chunks_hash_valid|YES","object_chunks|object_chunks_length_valid|YES","object_chunks|object_chunks_range_valid|YES"};
    s=query("SELECT CONCAT_WS('|',TABLE_NAME,CONSTRAINT_NAME,ENFORCED) FROM information_schema.TABLE_CONSTRAINTS WHERE CONSTRAINT_SCHEMA=DATABASE() AND TABLE_NAME IN ('chunks','object_chunks') AND CONSTRAINT_TYPE='CHECK' ORDER BY TABLE_NAME,CONSTRAINT_NAME");
    for(size_t i=0;i<sizeof(checks)/sizeof(checks[0]);++i) { row(s,checks[i]); } done(&s);
    s=query("SELECT CONCAT_WS('|',k.CONSTRAINT_NAME,k.COLUMN_NAME,k.REFERENCED_TABLE_NAME,k.REFERENCED_COLUMN_NAME,r.UPDATE_RULE,r.DELETE_RULE) FROM information_schema.KEY_COLUMN_USAGE k JOIN information_schema.REFERENTIAL_CONSTRAINTS r ON k.CONSTRAINT_SCHEMA=r.CONSTRAINT_SCHEMA AND k.CONSTRAINT_NAME=r.CONSTRAINT_NAME WHERE k.CONSTRAINT_SCHEMA=DATABASE() AND k.TABLE_NAME='object_chunks' ORDER BY k.CONSTRAINT_NAME,k.ORDINAL_POSITION");
    row(s,"object_chunks_chunk_fk|chunk_hash|chunks|chunk_hash|RESTRICT|RESTRICT");
    row(s,"object_chunks_object_fk|object_hash|objects|object_hash|RESTRICT|RESTRICT"); done(&s);
    scalar("SELECT COUNT(*) FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA=DATABASE() AND EVENT_OBJECT_TABLE IN ('chunks','object_chunks')","0");
    scalar("SELECT COUNT(*) FROM information_schema.PARTITIONS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME IN ('chunks','object_chunks') AND PARTITION_NAME IS NOT NULL","0");
    scalar("SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME IN ('chunks','object_chunks') AND GENERATION_EXPRESSION<>''","0");
    puts("PASS complete v5 metadata: 12 columns, six full indexes, two RESTRICT FK, ten enforced CHECK, no generated/trigger/partition");
}
static void chunk_rows(void)
{
    unsigned char hash[33]; memset(hash,0x30,sizeof(hash)); vireo_mysql_parameter_t p[7];
    for(size_t n=0;n<3;++n) {
        size_t length=n==0 ? 0U : n==1 ? 31U : 33U;
        chunk_values(p,hash); p[0]=BYTES(hash,length); (void)execute(insert_chunk,p,7,length==33 ? 1406 : 3819);
    }
    for(size_t i=0;i<6;++i) { chunk_values(p,hash); p[i]=NIL; (void)execute(insert_chunk,p,7,1048); }
    chunk_values(p,hash); p[1]=U64(0); (void)execute(insert_chunk,p,7,3819);
    p[1]=U64(16777161); (void)execute(insert_chunk,p,7,3819);
    p[1]=U64(UINT64_C(4294967296)); (void)execute(insert_chunk,p,7,1264);
    p[1]=I64(-1); (void)execute(insert_chunk,p,7,1264);
    chunk_values(p,hash); p[2]=U64(0); (void)execute(insert_chunk,p,7,3819);
    p[2]=U64(5); (void)execute(insert_chunk,p,7,3819);
    p[2]=U64(256); (void)execute(insert_chunk,p,7,1264);
    chunk_values(p,hash); p[3]=I64(-1); (void)execute(insert_chunk,p,7,1264);
    chunk_values(p,hash); p[5]=U64(9); (void)execute(insert_chunk,p,7,3819);
    chunk_values(p,hash); p[2]=U64(2); (void)execute(insert_chunk,p,7,3819);
    p[6]=U64(9); (void)execute(insert_chunk,p,7,3819);
    p[6]=U64(21); (void)execute(insert_chunk,p,7,3819);
    chunk_values(p,hash); p[2]=U64(3); p[3]=U64(1); (void)execute(insert_chunk,p,7,3819);
    chunk_values(p,hash); p[4]=I64(-1); (void)execute(insert_chunk,p,7,1264);
    chunk_values(p,hash); p[5]=I64(-1); (void)execute(insert_chunk,p,7,1264);
    chunk_values(p,hash); p[6]=I64(-1); (void)execute(insert_chunk,p,7,1264);
    add_chunk(0,4,1,0); add_chunk(0x41,1,2,0); add_chunk(0x61,16777160,2,0); add_chunk(0x62,4,3,0); add_chunk(0x63,4,4,0);
    add_chunk(0x64,4,1,UINT64_MAX);
    chunk_values(p,hash); p[2]=U64(2); p[3]=U64(UINT64_MAX); p[4]=U64(UINT64_MAX); p[5]=U64(UINT64_MAX); p[6]=U64(UINT64_MAX);
    (void)execute(insert_chunk,p,7,0);
    chunk_values(p,hash); (void)execute(insert_chunk,p,7,1062);
    memset(hash,0x77,32); hash[31]=0; chunk_values(p,hash); (void)execute(insert_chunk,p,7,0);
    hash[31]=0x20; (void)execute(insert_chunk,p,7,0);
    scalar("SELECT COUNT(*) FROM chunks WHERE LEFT(chunk_hash,31)=REPEAT(X'77',31)","2");
    scalar("SELECT COUNT(*) FROM chunks WHERE chunk_hash IN (REPEAT(X'41',32),REPEAT(X'61',32))","2");
    (void)execute("UPDATE chunks SET state=0 WHERE chunk_hash=REPEAT(X'00',32)",NULL,0,3819);
    (void)execute("UPDATE chunks SET state=2 WHERE chunk_hash=REPEAT(X'00',32)",NULL,0,3819);
    (void)execute("UPDATE chunks SET size=0 WHERE chunk_hash=REPEAT(X'00',32)",NULL,0,3819);
    command("UPDATE chunks SET state=4,verified_at_ms=15 WHERE chunk_hash=REPEAT(X'63',32)");
    puts("PASS exact binary identities, zero/NUL/trailing-space/case distinction, uint limits, nullable evidence, all chunk states and rejected INSERT/UPDATE");
}
static void manifest_rows(void)
{
    add_object(0xa0,11); add_object(0xa1,UINT64_MAX); add_object(0xa2,0); add_object(0xa3,1); add_object(0,11);
    add_chunk(0xb0,4,2,0); add_chunk(0xb1,3,2,0); add_chunk(0xb2,16777160,2,0);
    mapping(0xa0,0,0,4,0xb0,0); mapping(0xa0,1,4,4,0xb0,0); mapping(0xa0,2,8,3,0xb1,0);
    command("UPDATE chunks SET ref_count=2 WHERE chunk_hash=REPEAT(X'B0',32)");
    command("UPDATE chunks SET ref_count=1 WHERE chunk_hash=REPEAT(X'B1',32)");
    mapping(0xa0,0,0,4,0xb0,1062); mapping(0xa0,0,12,4,0xb0,1062); mapping(0xa0,3,4,4,0xb0,1062);
    mapping(0xff,0,0,4,0xb0,1452); mapping(0xa0,3,12,4,0xff,1452);
    mapping(0xa1,UINT64_C(4294967296),0,4,0xb0,1264);
    mapping(0xa1,10,0,0,0xb0,3819); mapping(0xa1,10,0,16777161,0xb0,3819);
    mapping(0xa1,10,0,UINT64_C(4294967296),0xb0,1264);
    mapping(0xa1,10,UINT64_MAX,1,0xb0,3819);
    mapping(0xa1,UINT32_MAX,UINT64_MAX-1,1,0x41,0);
    mapping(0xa1,UINT32_MAX-1,UINT64_MAX-16777160,16777160,0xb2,0);
    unsigned char object[33],chunk[33]; memset(object,0xa1,sizeof(object)); memset(chunk,0xb0,sizeof(chunk));
    vireo_mysql_parameter_t p[]={BYTES(object,32),U64(20),U64(20),U64(4),BYTES(chunk,32)};
    for(size_t i=0;i<5;++i) { vireo_mysql_parameter_t old=p[i]; p[i]=NIL; (void)execute(insert_mapping,p,5,1048); p[i]=old; }
    p[1]=I64(-1); (void)execute(insert_mapping,p,5,1264); p[1]=U64(20);
    p[2]=I64(-1); (void)execute(insert_mapping,p,5,1264); p[2]=U64(20);
    p[3]=I64(-1); (void)execute(insert_mapping,p,5,1264); p[3]=U64(4);
    p[4]=BYTES(chunk,31); (void)execute(insert_mapping,p,5,3819);
    p[4]=BYTES(chunk,33); (void)execute(insert_mapping,p,5,1406); p[4]=BYTES(chunk,32);
    p[0]=BYTES(object,33); (void)execute(insert_mapping,p,5,1406);
    memset(object,0,sizeof(object)); p[0]=BYTES(object,31); (void)execute(insert_mapping,p,5,0);
    scalar("SELECT OCTET_LENGTH(object_hash) FROM object_chunks WHERE chunk_index=20","32");
    (void)execute("DELETE FROM chunks WHERE chunk_hash=REPEAT(X'B0',32)",NULL,0,1451);
    (void)execute("UPDATE chunks SET chunk_hash=REPEAT(X'DD',32) WHERE chunk_hash=REPEAT(X'B0',32)",NULL,0,1451);
    (void)execute("DELETE FROM objects WHERE object_hash=REPEAT(X'A0',32)",NULL,0,1451);
    (void)execute("UPDATE objects SET object_hash=REPEAT(X'DD',32) WHERE object_hash=REPEAT(X'A0',32)",NULL,0,1451);
    (void)execute("UPDATE object_chunks SET chunk_hash=REPEAT(X'FF',32) WHERE object_hash=REPEAT(X'A0',32)",NULL,0,1452);
    (void)execute("UPDATE object_chunks SET byte_offset=18446744073709551615 WHERE object_hash=REPEAT(X'A0',32)",NULL,0,3819);
    (void)execute("UPDATE object_chunks SET chunk_index=0 WHERE object_hash=REPEAT(X'A0',32) AND chunk_index=1",NULL,0,1062);
    /* 有意存入不合法业务布局：FK与局部CHECK不能替代跨行/跨表验证。 */
    mapping(0xa3,7,1,3,0,0); mapping(0xa3,8,2,3,0,0); mapping(0xa2,17,5,3,0xb1,0);
    scalar("SELECT COUNT(*) FROM object_chunks WHERE object_hash=REPEAT(X'A3',32) AND byte_length=3","2");
    scalar("SELECT COUNT(*) FROM object_chunks WHERE object_hash=REPEAT(X'A2',32)","1");
    command("SET autocommit=0");
    command("UPDATE chunks SET ref_count=0,state=3 WHERE chunk_hash=REPEAT(X'B0',32)");
    (void)execute("DELETE FROM chunks WHERE chunk_hash=REPEAT(X'B0',32)",NULL,0,1451);
    command("ROLLBACK"); command("SET autocommit=1");
    scalar("SELECT CONCAT(ref_count,'|',state) FROM chunks WHERE chunk_hash=REPEAT(X'B0',32)","2|2");
    command("DELETE FROM object_chunks WHERE object_hash IN (REPEAT(X'A2',32),REPEAT(X'A3',32))");
    scalar("SELECT COUNT(*) FROM object_chunks WHERE object_hash=REPEAT(X'A2',32)","0");
    puts("PASS repeated chunk at two positions, PK/offset uniqueness, both FK and RESTRICT, uint32 index/uint64 end boundary, all required NULLs, BINARY padding and legal business counterexamples");
}
static void transactions(void)
{
    add_object(0xc0,8); add_chunk(0xc1,4,2,0);
    char before[SNAPSHOT_CAPACITY],after[SNAPSHOT_CAPACITY]; capture(snapshot_sql,before);
    command("SET autocommit=0"); mapping(0xc0,0,0,4,0xc1,0);
    command("UPDATE chunks SET ref_count=1 WHERE chunk_hash=REPEAT(X'C1',32)");
    command("ROLLBACK"); command("SET autocommit=1"); capture(snapshot_sql,after); assert(!strcmp(before,after));
    command("SET autocommit=0"); mapping(0xc0,0,0,4,0xc1,0); mapping(0xc0,1,4,4,0xc1,0);
    command("UPDATE chunks SET ref_count=2 WHERE chunk_hash=REPEAT(X'C1',32)");
    command("COMMIT"); command("SET autocommit=1");
    scalar("SELECT ref_count FROM chunks WHERE chunk_hash=REPEAT(X'C1',32)","2"); capture(snapshot_sql,before);
    command("SET autocommit=0"); command("UPDATE chunks SET ref_count=3 WHERE chunk_hash=REPEAT(X'C1',32)");
    mapping(0xc0,0,0,4,0xc1,1062);
    scalar("SELECT ref_count FROM chunks WHERE chunk_hash=REPEAT(X'C1',32)","3");
    command("ROLLBACK"); command("SET autocommit=1"); capture(snapshot_sql,after); assert(!strcmp(before,after));
    command("SET autocommit=0");
    command("DELETE FROM object_chunks WHERE object_hash=REPEAT(X'C0',32) AND chunk_index=0");
    command("UPDATE chunks SET ref_count=ref_count-1 WHERE chunk_hash=REPEAT(X'C1',32)");
    command("COMMIT"); command("SET autocommit=1");
    scalar("SELECT ref_count FROM chunks WHERE chunk_hash=REPEAT(X'C1',32)","1");
    command("SET autocommit=0"); command("DELETE FROM object_chunks WHERE object_hash=REPEAT(X'C0',32)");
    command("UPDATE chunks SET ref_count=ref_count-1,state=3 WHERE chunk_hash=REPEAT(X'C1',32)");
    command("DELETE FROM chunks WHERE chunk_hash=REPEAT(X'C1',32)");
    command("DELETE FROM objects WHERE object_hash=REPEAT(X'C0',32)"); command("COMMIT"); command("SET autocommit=1");
    scalar("SELECT COUNT(*) FROM chunks WHERE chunk_hash=REPEAT(X'C1',32)","0");
    add_object(0xd0,4); add_chunk(0xd1,4,2,UINT64_MAX); capture(snapshot_sql,before);
    command("SET autocommit=0"); mapping(0xd0,0,0,4,0xd1,0);
    (void)execute("UPDATE chunks SET ref_count=ref_count+1 WHERE chunk_hash=REPEAT(X'D1',32)",NULL,0,1690);
    scalar("SELECT COUNT(*) FROM object_chunks WHERE object_hash=REPEAT(X'D0',32)","1");
    command("ROLLBACK"); command("SET autocommit=1"); capture(snapshot_sql,after); assert(!strcmp(before,after));
    (void)execute("UPDATE chunks SET ref_count=ref_count-1 WHERE chunk_hash=REPEAT(X'00',32)",NULL,0,1690);
    puts("PASS synthetic manifest+row-count commit/rollback, duplicate preserves prior DML until explicit rollback, checked overflow/underflow, explicit mapping-before-chunk cleanup");
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
    if(versions==5) { row(s,"5|1|CF344ED64B30B1F95926EC46BCC16C1AF1CDCBEE56BBF67C549B9172F2C423AF"); } done(&s);
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
}
/* 逐个旧表保存全部字段，含生成列/NULL；升级前尚无新两表，不能用snapshot_sql。 */
static void seed_capture(char out[SNAPSHOT_CAPACITY])
{
    static const char *const selects[]={
        "SELECT CONCAT_WS('|',id,HEX(username),HEX(username_key),HEX(password_hash),status,created_at_ms,updated_at_ms,COALESCE(last_login_at_ms,'N')) FROM users ORDER BY id",
        "SELECT CONCAT_WS('|',id,user_id,HEX(token_digest),status,issued_at_ms,expires_at_ms,COALESCE(revoked_at_ms,'N'),last_seen_at_ms) FROM sessions ORDER BY id",
        "SELECT CONCAT_WS('|',HEX(object_hash),size,state,ref_count,storage_class,created_at_ms,updated_at_ms,COALESCE(verified_at_ms,'N')) FROM objects ORDER BY object_hash",
        "SELECT CONCAT_WS('|',id,owner_id,COALESCE(parent_id,'N'),HEX(name),HEX(name_hash),node_type,state,COALESCE(HEX(object_hash),'N'),size,created_at_ms,updated_at_ms,COALESCE(deleted_at_ms,'N'),COALESCE(HEX(live_name),'N'),COALESCE(active_root_owner,'N')) FROM file_nodes ORDER BY id",
        "SELECT CONCAT_WS('|',id,HEX(request_id),user_id,session_id,action,target_type,target_id,COALESCE(HEX(target_hash),'N'),status,latency_us,HEX(detail),occurred_at_ms) FROM operation_audits ORDER BY id",
        "SELECT CONCAT_WS('|',id,HEX(public_id),user_id,file_node_id,HEX(idempotency_key),HEX(expected_hash),size,mode,chunk_size,chunk_count,state,received_chunks,received_bytes,version,cancel_requested,last_status,created_at_ms,updated_at_ms,expires_at_ms,COALESCE(finished_at_ms,'N')) FROM upload_tasks ORDER BY id",
        "SELECT CONCAT_WS('|',task_id,chunk_index,byte_offset,byte_length,HEX(chunk_hash),crc32c,state,received_at_ms) FROM upload_chunks ORDER BY task_id,chunk_index"};
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
    const vireo_mysql_migration_t *catalog=NULL; size_t count=0; CHECK(vireo_mysql_schema_catalog(&catalog,&count)); assert(count==11); count=5; /* 保留v5完整结构/事务与升级前缀回归。 */
    vireo_mysql_migration_report_t report; apply(&options,catalog,count,&report);
    assert(report.applied_before==0 && report.applied_after==5 && report.steps_completed==9 && report.migrations_applied==5 && report.write_attempted);
    CHECK(vireo_mysql_connection_open(thread,&options,&connection,NULL));
    metadata(); chunk_rows(); manifest_rows(); transactions(); ledger(5);
    char before[SNAPSHOT_CAPACITY],after[SNAPSHOT_CAPACITY]; capture(snapshot_sql,before);
    apply(&options,catalog,count,&report);
    assert(report.applied_before==5 && report.applied_after==5 && !report.steps_completed && !report.write_attempted && !report.migrations_applied);
    capture(snapshot_sql,after); assert(!strcmp(before,after)); ledger(5);
    CHECK(vireo_mysql_connection_destroy(thread,&connection));
    options.database="vireo_manifest_upgrade"; apply(&options,catalog,4,&report);
    assert(report.applied_before==0 && report.applied_after==4 && report.steps_completed==7 && report.migrations_applied==4);
    CHECK(vireo_mysql_connection_open(thread,&options,&connection,NULL)); seed(); seed_capture(before); ledger(4);
    apply(&options,catalog,count,&report);
    assert(report.applied_before==4 && report.applied_after==5 && report.steps_completed==2 && report.migrations_applied==1 && report.write_attempted);
    seed_capture(after); assert(!strcmp(before,after)); metadata(); ledger(5);
    scalar("SELECT COUNT(*) FROM chunks","0"); scalar("SELECT COUNT(*) FROM object_chunks","0");
    add_chunk(0xee,4,2,1); mapping(0xbb,0,0,4,0xee,0);
    char old_rows[SNAPSHOT_CAPACITY]; seed_capture(old_rows); assert(!strcmp(before,old_rows));
    capture(snapshot_sql,before); apply(&options,catalog,count,&report);
    assert(report.applied_before==5 && report.applied_after==5 && !report.write_attempted && !report.steps_completed);
    capture(snapshot_sql,after); assert(!strcmp(before,after)); seed_capture(after); assert(!strcmp(old_rows,after)); ledger(5);
    CHECK(vireo_mysql_connection_destroy(thread,&connection)); CHECK(vireo_mysql_thread_detach(&thread)); CHECK(vireo_mysql_runtime_destroy(&runtime));
    assert(fd_count()==before_fd); memset(password,0,sizeof(password));
    printf("PASS empty9/seeded-v4 seven-table upgrade2/repeat five hashes and exact rows, %zu rejected writes unchanged, FD %zu -> %zu\n",rejected,before_fd,fd_count());
    return 0;
}
