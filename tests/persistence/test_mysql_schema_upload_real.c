/*
 * PROJECT : VIREO
 * FILE    : test_mysql_schema_upload_real.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-18
 * BRIEF   : 公共接口验证真实v4上传结构、整数几何、原子进度与含数据升级。
 */
#define _POSIX_C_SOURCE 200809L
#include <vireo/persistence/mysql_schema.h>
#include <vireo/persistence/mysql_statement.h>
#include <vireo/security/password.h>
#include <vireo/security/session_token.h>
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(call) do { errno=EDOM; vireo_result_t result_=(call); if(result_!=VIREO_OK) { fprintf(stderr,"line %d result %d\n",__LINE__,(int)result_); abort(); } assert(errno==EDOM); } while(0)
#define U64(v) ((vireo_mysql_parameter_t){.kind=VIREO_MYSQL_PARAMETER_U64,.value.u64=(v)})
#define NIL ((vireo_mysql_parameter_t){.kind=VIREO_MYSQL_PARAMETER_NULL})
#define BYTES(p,n) ((vireo_mysql_parameter_t){.kind=VIREO_MYSQL_PARAMETER_BYTES,.value.span={(p),(n)}})
#define TEXT(p,n) ((vireo_mysql_parameter_t){.kind=VIREO_MYSQL_PARAMETER_TEXT,.value.span={(p),(n)}})
static vireo_mysql_thread_t *thread;
static vireo_mysql_connection_t *connection;
static const vireo_mysql_statement_limits_t limits={32,16,4096,4096,262144};
static size_t rejected;
static uint64_t serial;
static unsigned char public_key[17],init_key[17];
static const unsigned char zero_hash[33]={0};
static uint64_t owner,root,other_owner,other_root,node_serial;
static const char insert_task[]="INSERT INTO upload_tasks(public_id,user_id,file_node_id,idempotency_key,expected_hash,size,mode,chunk_size,chunk_count,state,received_chunks,received_bytes,version,cancel_requested,last_status,created_at_ms,updated_at_ms,expires_at_ms,finished_at_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";
static const char insert_chunk[]="INSERT INTO upload_chunks(task_id,chunk_index,byte_offset,byte_length,chunk_hash,crc32c,state,received_at_ms) VALUES(?,?,?,?,?,?,?,?)";

static vireo_mysql_statement_t *prepare(const char *sql)
{
    vireo_mysql_statement_t *s=NULL; vireo_mysql_error_t e;
    errno=EDOM;
    vireo_result_t result=vireo_mysql_statement_prepare(thread,connection,sql,strlen(sql),&limits,&s,&e);
    assert(errno==EDOM);
    if(result!=VIREO_OK) { fprintf(stderr,"prepare result %d mysql %u\n",(int)result,e.mysql_code); abort(); }
    return s;
}
static void destroy(vireo_mysql_statement_t **s)
{
    CHECK(vireo_mysql_statement_destroy(thread,s,NULL)); assert(!*s);
}
static vireo_mysql_statement_t *query(const char *sql)
{
    vireo_mysql_statement_t *s=prepare(sql); vireo_mysql_execution_t ex;
    CHECK(vireo_mysql_statement_execute(thread,s,NULL,0,&ex,NULL)); assert(ex.has_result); return s;
}
static void row(vireo_mysql_statement_t *s,const char *expected)
{
    vireo_mysql_fetch_outcome_t outcome;
    CHECK(vireo_mysql_statement_fetch(thread,s,&outcome,NULL)); assert(outcome==VIREO_MYSQL_FETCH_ROW);
    vireo_mysql_cell_view_t cell; CHECK(vireo_mysql_statement_column(thread,s,0,&cell));
    if(cell.is_null || cell.length!=strlen(expected) || memcmp(cell.data,expected,cell.length)) {
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
/* 拒绝前后比较全部基础值的摘要和行数，避免只看错误码却遗漏写入副作用。 */
static void snapshot(char result[256])
{
    vireo_mysql_statement_t *s=query("SELECT CONCAT_WS('|',(SELECT COUNT(*) FROM upload_tasks),(SELECT COALESCE(SUM(CRC32(CONCAT_WS(':',id,HEX(public_id),user_id,file_node_id,HEX(idempotency_key),HEX(expected_hash),size,mode,chunk_size,chunk_count,state,received_chunks,received_bytes,version,cancel_requested,last_status,created_at_ms,updated_at_ms,expires_at_ms,COALESCE(finished_at_ms,'N')))),0) FROM upload_tasks),(SELECT COUNT(*) FROM upload_chunks),(SELECT COALESCE(SUM(CRC32(CONCAT_WS(':',task_id,chunk_index,byte_offset,byte_length,HEX(chunk_hash),crc32c,state,received_at_ms))),0) FROM upload_chunks))");
    vireo_mysql_fetch_outcome_t outcome; CHECK(vireo_mysql_statement_fetch(thread,s,&outcome,NULL)); assert(outcome==VIREO_MYSQL_FETCH_ROW);
    vireo_mysql_cell_view_t c; CHECK(vireo_mysql_statement_column(thread,s,0,&c)); assert(!c.is_null && c.length<256);
    memcpy(result,c.data,c.length); result[c.length]=0; done(&s);
}
static uint64_t execute(const char *sql,const vireo_mysql_parameter_t *p,size_t n,unsigned int code)
{
    char before[256]; if(code) { snapshot(before); }
    vireo_mysql_statement_t *s=NULL; vireo_mysql_error_t e={0}; vireo_mysql_execution_t ex={0};
    errno=EDOM;
    vireo_result_t r=vireo_mysql_statement_prepare(thread,connection,sql,strlen(sql),&limits,&s,&e);
    assert(errno==EDOM);
    /* 常量CHECK或显式写生成列可在prepare拒绝，不能假定所有SQL错误都在execute。 */
    if(r==VIREO_OK) { errno=EDOM; r=vireo_mysql_statement_execute(thread,s,p,n,&ex,&e); assert(errno==EDOM); }
    bool alias=(code==1452 && e.mysql_code==1216) || (code==1451 && e.mysql_code==1217);
    if(code && (code==1451 || code==1452 || code==1062 || code==1048)) { assert(!memcmp(e.sqlstate,"23000",6)); }
    if(code==3819) { assert(!memcmp(e.sqlstate,"HY000",6)); }
    if(code==1264) { assert(!memcmp(e.sqlstate,"22003",6)); }
    if(code==1406) { assert(!memcmp(e.sqlstate,"22001",6)); }
    if(r!=(code ? VIREO_RESULT_DATABASE : VIREO_OK) || (e.mysql_code!=code && !alias)) {
        fprintf(stderr,"case %llu result %d mysql %u expected %u\n",(unsigned long long)serial,(int)r,e.mysql_code,code); abort();
    }
    uint64_t id=ex.insert_id;
    if(s) { destroy(&s); }
    if(code) {
        ++rejected; char after[256]; snapshot(after); assert(!strcmp(before,after));
    } else { assert(!ex.has_result); }
    return id;
}
static void apply(const vireo_mysql_connection_options_t *options,
                  const vireo_mysql_migration_t *catalog,size_t count,
                  vireo_mysql_migration_report_t *report,vireo_mysql_migration_error_t *error)
{
    errno=EDOM;
    vireo_result_t result=vireo_mysql_migration_apply(thread,options,catalog,count,report,error);
    assert(errno==EDOM);
    if(result!=VIREO_OK) {
        fprintf(stderr,"migration result %d stage %d issue %d mysql %u version %u step %u\n",
                (int)result,(int)error->stage,(int)error->issue,error->database.mysql_code,
                report->failed_version,report->failed_step); abort();
    }
}
static void command(const char *sql) { (void)execute(sql,NULL,0,0); }
static uint64_t add_user(const char *key)
{
    vireo_mysql_parameter_t p=BYTES(key,strlen(key));
    return execute("INSERT INTO users(username,username_key,password_hash,status,created_at_ms,updated_at_ms) VALUES('display',?,'test-phc',1,0,0)",&p,1,0);
}
static uint64_t add_root(uint64_t user)
{
    vireo_mysql_parameter_t p=U64(user);
    return execute("INSERT INTO file_nodes(owner_id,parent_id,name,node_type,state,size,created_at_ms,updated_at_ms) VALUES(?,NULL,'',1,2,0,0,0)",&p,1,0);
}
static uint64_t add_session(uint64_t user,unsigned char tag)
{
    unsigned char digest[32]; memset(digest,tag,sizeof(digest));
    vireo_mysql_parameter_t p[]={U64(user),BYTES(digest,32)};
    return execute("INSERT INTO sessions(user_id,token_digest,status,issued_at_ms,expires_at_ms,last_seen_at_ms) VALUES(?,?,1,0,100,0)",p,2,0);
}
static uint64_t add_node(uint64_t user,uint64_t parent)
{
    char name[64]; int n=snprintf(name,sizeof(name),"upload-%llu",(unsigned long long)++node_serial);
    assert(n>0 && (size_t)n<sizeof(name));
    vireo_mysql_parameter_t p[]={U64(user),U64(parent),BYTES(name,(size_t)n)};
    return execute("INSERT INTO file_nodes(owner_id,parent_id,name,node_type,state,size,created_at_ms,updated_at_ms) VALUES(?,?,?,2,1,0,0,0)",p,3,0);
}
static void values(vireo_mysql_parameter_t p[19])
{
    ++serial; memset(public_key,0,sizeof(public_key)); memset(init_key,0,sizeof(init_key));
    for(size_t i=0;i<8;++i) { public_key[15-i]=(unsigned char)(serial>>(i*8)); }
    memcpy(init_key,public_key,16); init_key[0]=0x55;
    p[0]=BYTES(public_key,16); p[1]=U64(owner); p[2]=U64(add_node(owner,root)); p[3]=BYTES(init_key,16);
    p[4]=BYTES(zero_hash,32); p[5]=U64(11); p[6]=U64(1); p[7]=U64(4); p[8]=U64(3);
    p[9]=U64(1); p[10]=U64(0); p[11]=U64(0); p[12]=U64(1); p[13]=U64(0); p[14]=U64(0);
    p[15]=U64(0); p[16]=U64(0); p[17]=U64(100); p[18]=NIL;
}
static void chunk_values(vireo_mysql_parameter_t p[8],uint64_t task)
{
    p[0]=U64(task); p[1]=U64(0); p[2]=U64(0); p[3]=U64(4);
    p[4]=BYTES(zero_hash,32); p[5]=U64(0); p[6]=U64(1); p[7]=U64(0);
}
static void metadata(void)
{
    scalar("SELECT VERSION() REGEXP '^8[.]0[.]'","1");
    vireo_mysql_statement_t *s=NULL;
    scalar("SELECT CONCAT(ENGINE,'|',TABLE_COLLATION) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='upload_chunks'","InnoDB|utf8mb4_bin");
    {
        static const char *const expected[]={
            "task_id|bigint unsigned|-|-|NO|NULL||-|-",
            "chunk_index|int unsigned|-|-|NO|NULL||-|-",
            "byte_offset|bigint unsigned|-|-|NO|NULL||-|-",
            "byte_length|int unsigned|-|-|NO|NULL||-|-",
            "chunk_hash|varbinary(32)|32|32|NO|NULL||-|-",
            "crc32c|int unsigned|-|-|NO|NULL||-|-",
            "state|tinyint unsigned|-|-|NO|NULL||-|-",
            "received_at_ms|bigint unsigned|-|-|NO|NULL||-|-"};
        s=query("SELECT CONCAT_WS('|',COLUMN_NAME,COLUMN_TYPE,COALESCE(CAST(CHARACTER_MAXIMUM_LENGTH AS CHAR),'-'),COALESCE(CAST(CHARACTER_OCTET_LENGTH AS CHAR),'-'),IS_NULLABLE,COALESCE(COLUMN_DEFAULT,'NULL'),EXTRA,COALESCE(CHARACTER_SET_NAME,'-'),COALESCE(COLLATION_NAME,'-')) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='upload_chunks' ORDER BY ORDINAL_POSITION");
        for(size_t i=0;i<sizeof(expected)/sizeof(expected[0]);++i) { row(s,expected[i]); } done(&s);
    }
    {
        static const char *const expected[]={
            "PRIMARY|0|1|task_id|BTREE|-|A|YES",
            "PRIMARY|0|2|chunk_index|BTREE|-|A|YES",
            "upload_chunks_offset_unique|0|1|task_id|BTREE|-|A|YES",
            "upload_chunks_offset_unique|0|2|byte_offset|BTREE|-|A|YES",
            "upload_chunks_task_state|1|1|task_id|BTREE|-|A|YES",
            "upload_chunks_task_state|1|2|state|BTREE|-|A|YES",
            "upload_chunks_task_state|1|3|chunk_index|BTREE|-|A|YES"};
        s=query("SELECT CONCAT_WS('|',INDEX_NAME,NON_UNIQUE,SEQ_IN_INDEX,COLUMN_NAME,INDEX_TYPE,COALESCE(CAST(SUB_PART AS CHAR),'-'),COLLATION,IS_VISIBLE) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='upload_chunks' ORDER BY INDEX_NAME,SEQ_IN_INDEX");
        for(size_t i=0;i<sizeof(expected)/sizeof(expected[0]);++i) { row(s,expected[i]); } done(&s);
    }
    {
        static const char *const expected[]={
            "upload_chunks_hash_valid|YES",
            "upload_chunks_length_valid|YES",
            "upload_chunks_range_valid|YES",
            "upload_chunks_state_valid|YES",
            "upload_chunks_task_valid|YES"};
        s=query("SELECT CONCAT_WS('|',CONSTRAINT_NAME,ENFORCED) FROM information_schema.TABLE_CONSTRAINTS WHERE CONSTRAINT_SCHEMA=DATABASE() AND TABLE_NAME='upload_chunks' AND CONSTRAINT_TYPE='CHECK' ORDER BY CONSTRAINT_NAME");
        for(size_t i=0;i<sizeof(expected)/sizeof(expected[0]);++i) { row(s,expected[i]); } done(&s);
    }
    scalar("SELECT CONCAT(ENGINE,'|',TABLE_COLLATION) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='upload_tasks'","InnoDB|utf8mb4_bin");
    {
        static const char *const expected[]={
            "id|bigint unsigned|-|-|NO|NULL|auto_increment|-|-",
            "public_id|varbinary(16)|16|16|NO|NULL||-|-",
            "user_id|bigint unsigned|-|-|NO|NULL||-|-",
            "file_node_id|bigint unsigned|-|-|NO|NULL||-|-",
            "idempotency_key|varbinary(16)|16|16|NO|NULL||-|-",
            "expected_hash|varbinary(32)|32|32|NO|NULL||-|-",
            "size|bigint unsigned|-|-|NO|NULL||-|-",
            "mode|tinyint unsigned|-|-|NO|NULL||-|-",
            "chunk_size|int unsigned|-|-|NO|NULL||-|-",
            "chunk_count|bigint unsigned|-|-|NO|NULL||-|-",
            "state|tinyint unsigned|-|-|NO|NULL||-|-",
            "received_chunks|bigint unsigned|-|-|NO|NULL||-|-",
            "received_bytes|bigint unsigned|-|-|NO|NULL||-|-",
            "version|bigint unsigned|-|-|NO|NULL||-|-",
            "cancel_requested|tinyint unsigned|-|-|NO|NULL||-|-",
            "last_status|smallint unsigned|-|-|NO|NULL||-|-",
            "created_at_ms|bigint unsigned|-|-|NO|NULL||-|-",
            "updated_at_ms|bigint unsigned|-|-|NO|NULL||-|-",
            "expires_at_ms|bigint unsigned|-|-|NO|NULL||-|-",
            "finished_at_ms|bigint unsigned|-|-|YES|NULL||-|-"};
        s=query("SELECT CONCAT_WS('|',COLUMN_NAME,COLUMN_TYPE,COALESCE(CAST(CHARACTER_MAXIMUM_LENGTH AS CHAR),'-'),COALESCE(CAST(CHARACTER_OCTET_LENGTH AS CHAR),'-'),IS_NULLABLE,COALESCE(COLUMN_DEFAULT,'NULL'),EXTRA,COALESCE(CHARACTER_SET_NAME,'-'),COALESCE(COLLATION_NAME,'-')) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='upload_tasks' ORDER BY ORDINAL_POSITION");
        for(size_t i=0;i<sizeof(expected)/sizeof(expected[0]);++i) { row(s,expected[i]); } done(&s);
    }
    {
        static const char *const expected[]={
            "PRIMARY|0|1|id|BTREE|-|A|YES",
            "upload_tasks_node_unique|0|1|file_node_id|BTREE|-|A|YES",
            "upload_tasks_public_id_unique|0|1|public_id|BTREE|-|A|YES",
            "upload_tasks_state_expiry|1|1|state|BTREE|-|A|YES",
            "upload_tasks_state_expiry|1|2|expires_at_ms|BTREE|-|A|YES",
            "upload_tasks_state_expiry|1|3|id|BTREE|-|A|YES",
            "upload_tasks_user_idempotency_unique|0|1|user_id|BTREE|-|A|YES",
            "upload_tasks_user_idempotency_unique|0|2|idempotency_key|BTREE|-|A|YES",
            "upload_tasks_user_node|1|1|user_id|BTREE|-|A|YES",
            "upload_tasks_user_node|1|2|file_node_id|BTREE|-|A|YES",
            "upload_tasks_user_state|1|1|user_id|BTREE|-|A|YES",
            "upload_tasks_user_state|1|2|state|BTREE|-|A|YES",
            "upload_tasks_user_state|1|3|id|BTREE|-|A|YES"};
        s=query("SELECT CONCAT_WS('|',INDEX_NAME,NON_UNIQUE,SEQ_IN_INDEX,COLUMN_NAME,INDEX_TYPE,COALESCE(CAST(SUB_PART AS CHAR),'-'),COLLATION,IS_VISIBLE) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='upload_tasks' ORDER BY INDEX_NAME,SEQ_IN_INDEX");
        for(size_t i=0;i<sizeof(expected)/sizeof(expected[0]);++i) { row(s,expected[i]); } done(&s);
    }
    {
        static const char *const expected[]={
            "upload_tasks_cancel_valid|YES",
            "upload_tasks_complete_valid|YES",
            "upload_tasks_expiry_order|YES",
            "upload_tasks_fast_valid|YES",
            "upload_tasks_finished_valid|YES",
            "upload_tasks_geometry_valid|YES",
            "upload_tasks_hash_valid|YES",
            "upload_tasks_idempotency_valid|YES",
            "upload_tasks_mode_valid|YES",
            "upload_tasks_owner_valid|YES",
            "upload_tasks_progress_valid|YES",
            "upload_tasks_public_id_valid|YES",
            "upload_tasks_state_valid|YES",
            "upload_tasks_updated_order|YES",
            "upload_tasks_version_valid|YES"};
        s=query("SELECT CONCAT_WS('|',CONSTRAINT_NAME,ENFORCED) FROM information_schema.TABLE_CONSTRAINTS WHERE CONSTRAINT_SCHEMA=DATABASE() AND TABLE_NAME='upload_tasks' AND CONSTRAINT_TYPE='CHECK' ORDER BY CONSTRAINT_NAME");
        for(size_t i=0;i<sizeof(expected)/sizeof(expected[0]);++i) { row(s,expected[i]); } done(&s);
    }
    {
        static const char *const expected[]={
            "upload_chunks_task_fk|upload_chunks|task_id|1|upload_tasks|id|RESTRICT|RESTRICT",
            "upload_tasks_node_fk|upload_tasks|user_id|1|file_nodes|owner_id|RESTRICT|RESTRICT",
            "upload_tasks_node_fk|upload_tasks|file_node_id|2|file_nodes|id|RESTRICT|RESTRICT"};
        s=query("SELECT CONCAT_WS('|',k.CONSTRAINT_NAME,k.TABLE_NAME,k.COLUMN_NAME,k.ORDINAL_POSITION,k.REFERENCED_TABLE_NAME,k.REFERENCED_COLUMN_NAME,r.UPDATE_RULE,r.DELETE_RULE) FROM information_schema.KEY_COLUMN_USAGE k JOIN information_schema.REFERENTIAL_CONSTRAINTS r ON k.CONSTRAINT_SCHEMA=r.CONSTRAINT_SCHEMA AND k.CONSTRAINT_NAME=r.CONSTRAINT_NAME WHERE k.CONSTRAINT_SCHEMA=DATABASE() AND k.TABLE_NAME IN('upload_tasks','upload_chunks') ORDER BY k.CONSTRAINT_NAME,k.ORDINAL_POSITION");
        for(size_t i=0;i<sizeof(expected)/sizeof(expected[0]);++i) { row(s,expected[i]); } done(&s);
    }
    scalar("SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME IN('upload_tasks','upload_chunks') AND GENERATION_EXPRESSION<>''","0");
    scalar("SELECT COUNT(*) FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA=DATABASE()","0");
    scalar("SELECT COUNT(*) FROM information_schema.PARTITIONS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME IN('upload_tasks','upload_chunks') AND PARTITION_NAME IS NOT NULL","0");
    scalar("SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE()","8");
    scalar("SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME<>'vireo_schema_migrations'","78");
    scalar("SELECT COUNT(DISTINCT TABLE_NAME,INDEX_NAME) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME<>'vireo_schema_migrations'","33");
    scalar("SELECT COUNT(*) FROM information_schema.TABLE_CONSTRAINTS WHERE CONSTRAINT_SCHEMA=DATABASE() AND TABLE_NAME<>'vireo_schema_migrations' AND CONSTRAINT_TYPE='CHECK' AND ENFORCED='YES'","47");
    scalar("SELECT COUNT(*) FROM information_schema.REFERENTIAL_CONSTRAINTS WHERE CONSTRAINT_SCHEMA=DATABASE()","6");
    puts("PASS upload metadata: 28 base columns, 10 ordered full indexes, 2 RESTRICT FK, 20 enforced CHECK; cumulative 7 business tables/78 columns/33 indexes/6 FK/47 CHECK plus ledger");
}
static void task_boundaries(void)
{
    vireo_mysql_parameter_t p[19];
    values(p); p[0]=BYTES(public_key,15); (void)execute(insert_task,p,19,3819);
    p[0]=BYTES(public_key,17); (void)execute(insert_task,p,19,1406);
    p[0]=BYTES(zero_hash,16); (void)execute(insert_task,p,19,3819);
    values(p); p[3]=BYTES(init_key,15); (void)execute(insert_task,p,19,3819);
    p[3]=BYTES(init_key,17); (void)execute(insert_task,p,19,1406);
    p[3]=BYTES(zero_hash,16); (void)execute(insert_task,p,19,3819);
    values(p); p[4]=BYTES(zero_hash,31); (void)execute(insert_task,p,19,3819);
    p[4]=BYTES(zero_hash,33); (void)execute(insert_task,p,19,1406);
    values(p); memset(public_key,0,16); public_key[0]='A'; memset(init_key,0,16); init_key[0]='K';
    (void)execute(insert_task,p,19,0);
    p[2]=U64(add_node(owner,root)); (void)execute(insert_task,p,19,1062); /* public collision */
    public_key[0]='a'; (void)execute(insert_task,p,19,1062); /* same user+key, distinct public/node */
    init_key[0]='k'; (void)execute(insert_task,p,19,0); /* binary case, embedded/trailing NUL */
    public_key[15]=1; init_key[15]=1; p[2]=U64(add_node(owner,root)); (void)execute(insert_task,p,19,0);
    p[1]=U64(other_owner); p[2]=U64(add_node(other_owner,other_root)); public_key[14]=1;
    (void)execute(insert_task,p,19,0); /* same key across users is legal */
    scalar("SELECT COUNT(*) FROM upload_tasks WHERE idempotency_key=CONCAT(X'6B',REPEAT(X'00',14),X'01')","2");
    values(p); uint64_t node=p[2].value.u64; (void)execute(insert_task,p,19,0);
    values(p); p[2]=U64(node); (void)execute(insert_task,p,19,1062);
    values(p); p[1]=U64(other_owner); (void)execute(insert_task,p,19,1452);
    values(p); p[2]=U64(UINT64_MAX); (void)execute(insert_task,p,19,1452);
    values(p); p[1]=U64(0); (void)execute(insert_task,p,19,3819);
    values(p); p[2]=U64(0); (void)execute(insert_task,p,19,3819);
    for(size_t i=0;i<19;++i) {
        if(i==18) { continue; }
        values(p); p[i]=NIL; (void)execute(insert_task,p,19,1048);
    }
    static const struct {size_t field; uint64_t value; unsigned int code;} invalid[]={
        {6,0,3819},{6,3,3819},{6,256,1264},{7,0,3819},{7,16777161,3819},{7,UINT64_C(4294967296),1264},
        {8,0,3819},{8,2,3819},{8,4,3819},{9,0,3819},{9,10,3819},{9,256,1264},
        {10,1,3819},{10,4,3819},{11,1,3819},{11,12,3819},{12,0,3819},{13,2,3819},{13,256,1264},{14,65536,1264}};
    for(size_t i=0;i<sizeof(invalid)/sizeof(invalid[0]);++i) {
        values(p); p[invalid[i].field]=U64(invalid[i].value); (void)execute(insert_task,p,19,invalid[i].code);
    }
    values(p); p[15]=U64(1); p[16]=U64(0); (void)execute(insert_task,p,19,3819);
    values(p); p[17]=U64(0); (void)execute(insert_task,p,19,3819);
    values(p); p[15]=U64(10); p[16]=U64(10); p[17]=U64(10); (void)execute(insert_task,p,19,3819);
    values(p); p[18]=U64(0); (void)execute(insert_task,p,19,3819);
    for(uint64_t state=2;state<=9;++state) {
        values(p); p[9]=U64(state);
        if(state>=6) { (void)execute(insert_task,p,19,3819); p[18]=U64(0); }
        if(state>=4 && state<=6) {
            (void)execute(insert_task,p,19,3819); p[10]=U64(3); p[11]=U64(11);
        }
        (void)execute(insert_task,p,19,0);
    }
    values(p); p[9]=U64(7); p[15]=U64(10); p[16]=U64(20); p[18]=U64(9); (void)execute(insert_task,p,19,3819);
    p[18]=U64(21); (void)execute(insert_task,p,19,3819);
    values(p); p[9]=U64(2); p[10]=U64(2); p[11]=U64(1); (void)execute(insert_task,p,19,3819);
    p[11]=U64(7); p[12]=U64(UINT64_MAX); p[13]=U64(1); p[14]=U64(65535);
    p[16]=U64(UINT64_MAX); p[17]=U64(UINT64_MAX); (void)execute(insert_task,p,19,0);
    scalar("SELECT CONCAT(version,'|',cancel_requested,'|',last_status,'|',updated_at_ms,'|',expires_at_ms) FROM upload_tasks WHERE version=18446744073709551615","18446744073709551615|1|65535|18446744073709551615|18446744073709551615");
    values(p); p[5]=U64(0); p[7]=U64(1); p[8]=U64(0); (void)execute(insert_task,p,19,0);
    values(p); p[5]=U64(0); p[7]=U64(16777160); p[8]=U64(0); p[9]=U64(6); p[18]=U64(0); (void)execute(insert_task,p,19,0);
    values(p); p[5]=U64(1); p[7]=U64(1); p[8]=U64(1); (void)execute(insert_task,p,19,0);
    values(p); p[5]=U64(16777161); p[7]=U64(16777160); p[8]=U64(2); (void)execute(insert_task,p,19,0);
    values(p); p[5]=U64(UINT64_C(4294967296)); p[7]=U64(1); p[8]=U64(UINT64_C(4294967296)); (void)execute(insert_task,p,19,0);
    values(p); p[5]=U64(UINT64_C(4294967297)); p[7]=U64(1); p[8]=U64(UINT64_C(4294967297)); (void)execute(insert_task,p,19,3819);
    values(p); p[5]=U64(UINT64_C(72057353519759360)); p[7]=U64(16777160); p[8]=U64(UINT64_C(4294967296)); (void)execute(insert_task,p,19,0);
    values(p); p[5]=U64(UINT64_C(72057353519759361)); p[7]=U64(16777160); p[8]=U64(UINT64_C(4294967297)); (void)execute(insert_task,p,19,3819);
    values(p); p[5]=U64(UINT64_MAX); p[7]=U64(16777160); p[8]=U64(UINT64_C(4294967296)); (void)execute(insert_task,p,19,3819);
    values(p); p[5]=U64(UINT64_MAX); p[7]=U64(1); p[8]=U64(UINT64_MAX); (void)execute(insert_task,p,19,3819);
    values(p); p[6]=U64(2); p[7]=U64(0); p[8]=U64(0); (void)execute(insert_task,p,19,3819);
    p[9]=U64(6); p[18]=U64(0); p[5]=U64(UINT64_MAX); (void)execute(insert_task,p,19,0); /* FAST cannot prove CAS */
    values(p); p[6]=U64(2); p[7]=U64(0); p[8]=U64(0); p[9]=U64(6); p[18]=U64(0); p[10]=U64(1); (void)execute(insert_task,p,19,3819);
    values(p); p[6]=U64(2); p[7]=U64(1); p[8]=U64(0); p[9]=U64(6); p[18]=U64(0); (void)execute(insert_task,p,19,3819);
    values(p); p[9]=U64(9); p[15]=U64(UINT64_MAX-1); p[16]=U64(UINT64_MAX); p[17]=U64(UINT64_MAX); p[18]=U64(UINT64_MAX); (void)execute(insert_task,p,19,0);
    puts("PASS task binary/NULL/unique/owner/shape/TTL/state/FAST/progress and u32-index-count geometry boundaries");
}
static void chunk_boundaries(void)
{
    vireo_mysql_parameter_t t[19],p[8]; values(t); uint64_t task=execute(insert_task,t,19,0);
    chunk_values(p,task); (void)execute(insert_chunk,p,8,0);
    (void)execute(insert_chunk,p,8,1062); /* same index */
    p[1]=U64(1); (void)execute(insert_chunk,p,8,1062); /* distinct index, same offset */
    p[2]=U64(4); p[5]=U64(UINT32_MAX); p[6]=U64(2); p[7]=U64(UINT64_MAX); (void)execute(insert_chunk,p,8,0);
    scalar("SELECT CONCAT(crc32c,'|',state,'|',received_at_ms) FROM upload_chunks WHERE state=2","4294967295|2|18446744073709551615");
    chunk_values(p,task); p[1]=U64(UINT32_MAX); p[2]=U64(UINT64_MAX-1); p[3]=U64(1); (void)execute(insert_chunk,p,8,0);
    scalar("SELECT CONCAT(chunk_index,'|',byte_offset,'|',byte_length) FROM upload_chunks WHERE chunk_index=4294967295","4294967295|18446744073709551614|1");
    static const struct {size_t field; uint64_t value; unsigned int code;} invalid[]={
        {0,0,3819},{0,UINT64_MAX,1452},{1,UINT64_C(4294967296),1264},
        {2,UINT64_MAX,3819},{3,0,3819},{3,16777161,3819},{3,UINT64_C(4294967296),1264},
        {5,UINT64_C(4294967296),1264},{6,0,3819},{6,3,3819},{6,256,1264}};
    for(size_t i=0;i<sizeof(invalid)/sizeof(invalid[0]);++i) {
        chunk_values(p,task); p[1]=U64(2); p[2]=U64(8); p[invalid[i].field]=U64(invalid[i].value);
        (void)execute(insert_chunk,p,8,invalid[i].code);
    }
    for(size_t i=0;i<8;++i) { chunk_values(p,task); p[1]=U64(2); p[2]=U64(8); p[i]=NIL; (void)execute(insert_chunk,p,8,1048); }
    chunk_values(p,task); p[1]=U64(2); p[2]=U64(8); p[4]=BYTES(zero_hash,31); (void)execute(insert_chunk,p,8,3819);
    p[4]=BYTES(zero_hash,33); (void)execute(insert_chunk,p,8,1406);
    p[4]=BYTES(zero_hash,32); p[3]=U64(3); (void)execute(insert_chunk,p,8,0); /* actual last-block example */
    chunk_values(p,task); p[1]=U64(3); p[2]=U64(UINT64_MAX-16777160); p[3]=U64(16777160); (void)execute(insert_chunk,p,8,0);
    unsigned char hash[32]={0}; hash[0]='A'; hash[30]=0xff;
    chunk_values(p,task); p[1]=U64(5); p[2]=U64(20); p[4]=BYTES(hash,32); (void)execute(insert_chunk,p,8,0);
    scalar("SELECT HEX(chunk_hash) FROM upload_chunks WHERE chunk_index=5","410000000000000000000000000000000000000000000000000000000000FF00");
    vireo_mysql_parameter_t id=U64(task);
    (void)execute("DELETE FROM upload_tasks WHERE id=?",&id,1,1451);
    (void)execute("UPDATE upload_tasks SET id=18446744073709551615 WHERE id=?",&id,1,1451);
    id=t[2]; (void)execute("DELETE FROM file_nodes WHERE id=?",&id,1,1451);
    (void)execute("UPDATE file_nodes SET id=18446744073709551615 WHERE id=?",&id,1,1451);
    /* DB permits cross-row contradictions; later repository must reject them. */
    chunk_values(p,task); p[1]=U64(4); p[2]=U64(1); (void)execute(insert_chunk,p,8,0); /* overlaps */
    scalar("SELECT CONCAT(t.state,'|',t.received_chunks,'|',t.received_bytes,'|',COUNT(c.chunk_index)) FROM upload_tasks t JOIN upload_chunks c ON c.task_id=t.id WHERE c.task_id=(SELECT task_id FROM upload_chunks WHERE chunk_index=4294967295) GROUP BY t.id","1|0|0|7");
    values(t); t[2]=U64(root); t[9]=U64(6); t[10]=U64(3); t[11]=U64(11); t[18]=U64(0);
    task=execute(insert_task,t,19,0); /* root is DIRECTORY; shape-only task accepts it */
    chunk_values(p,task); (void)execute(insert_chunk,p,8,0);
    id=U64(task); (void)execute("UPDATE upload_tasks SET state=1,received_chunks=0,received_bytes=0,finished_at_ms=NULL,version=1 WHERE id=?",&id,1,0);
    /* Remove the DIRECTORY-node counterexample task, then test real node retention order. */
    (void)execute("DELETE FROM upload_chunks WHERE task_id=?",&id,1,0);
    (void)execute("DELETE FROM upload_tasks WHERE id=?",&id,1,0);
    values(t); task=execute(insert_task,t,19,0); chunk_values(p,task); (void)execute(insert_chunk,p,8,0);
    id=U64(task); vireo_mysql_parameter_t node=t[2];
    (void)execute("INSERT INTO operation_audits(request_id,action,target_type,target_id,status,latency_us,detail,occurred_at_ms) VALUES(REPEAT(X'CC',16),1,3,?,0,0,'',0)",&node,1,0);
    (void)execute("DELETE FROM file_nodes WHERE id=?",&node,1,1451);
    (void)execute("DELETE FROM upload_chunks WHERE task_id=?",&id,1,0);
    (void)execute("DELETE FROM upload_tasks WHERE id=?",&id,1,0);
    (void)execute("DELETE FROM file_nodes WHERE id=?",&node,1,0);
    scalar("SELECT COUNT(*) FROM operation_audits WHERE request_id=REPEAT(X'CC',16)","1");
    puts("PASS chunk exact binary/numeric/range/NULL/PK/offset/FK/RESTRICT; legal cross-row counterexamples, explicit child-before-parent cleanup and audit retention");
}
static void transactions(void)
{
    vireo_mysql_parameter_t t[19],p[8]; values(t); uint64_t task=execute(insert_task,t,19,0);
    char q[256]; int n=snprintf(q,sizeof(q),"SELECT CONCAT(state,'|',received_chunks,'|',received_bytes,'|',version) FROM upload_tasks WHERE id=%llu",(unsigned long long)task); assert(n>0 && (size_t)n<sizeof(q));
    char before[256],after[256]; snapshot(before);
    command("SET autocommit=0"); chunk_values(p,task); p[1]=U64(2); p[2]=U64(8); p[3]=U64(3); (void)execute(insert_chunk,p,8,0);
    vireo_mysql_parameter_t id=U64(task);
    (void)execute("UPDATE upload_tasks SET state=2,received_chunks=1,received_bytes=3,version=2 WHERE id=? AND version=1",&id,1,0);
    scalar(q,"2|1|3|2"); command("ROLLBACK"); command("SET autocommit=1"); snapshot(after); assert(!strcmp(before,after)); scalar(q,"1|0|0|1");
    command("SET autocommit=0"); (void)execute(insert_chunk,p,8,0);
    (void)execute("UPDATE upload_tasks SET state=2,received_chunks=1,received_bytes=3,version=2 WHERE id=? AND version=1",&id,1,0);
    command("COMMIT"); command("SET autocommit=1"); scalar(q,"2|1|3|2"); snapshot(before);
    command("SET autocommit=0");
    (void)execute("UPDATE upload_tasks SET received_chunks=2,received_bytes=7,version=3 WHERE id=? AND version=2",&id,1,0);
    (void)execute(insert_chunk,p,8,1062); scalar(q,"2|2|7|3"); /* failed statement does not roll back earlier DML */
    command("ROLLBACK"); command("SET autocommit=1"); scalar(q,"2|1|3|2"); snapshot(after); assert(!strcmp(before,after));
    vireo_mysql_statement_t *s=prepare("UPDATE upload_tasks SET version=3 WHERE id=? AND version=1"); vireo_mysql_execution_t ex;
    CHECK(vireo_mysql_statement_execute(thread,s,&id,1,&ex,NULL)); assert(!ex.has_result && ex.affected_rows==0); destroy(&s); snapshot(after); assert(!strcmp(before,after));
    puts("PASS synthetic chunk+progress+version commit/rollback, stale CAS zero rows, duplicate after earlier DML requires explicit rollback; no file IO/repository claim");
}
static void seed(void)
{
    uint64_t user=add_user("upgrade-user"); (void)add_root(user); (void)add_session(user,0xbb);
    command("INSERT INTO objects(object_hash,size,state,ref_count,storage_class,created_at_ms,updated_at_ms) VALUES(REPEAT(X'BB',32),17,1,1,1,0,0)");
    vireo_mysql_parameter_t p=U64(user);
    (void)execute("INSERT INTO file_nodes(owner_id,parent_id,name,node_type,state,object_hash,size,created_at_ms,updated_at_ms) VALUES(?,1,'seed-file',2,2,REPEAT(X'BB',32),17,0,0)",&p,1,0);
    command("INSERT INTO operation_audits(request_id,user_id,session_id,action,target_type,target_id,status,latency_us,detail,occurred_at_ms) VALUES(REPEAT(X'BB',16),1,1,2,2,1,0,7,'seed',0)");
}
static void seed_preserved(void)
{
    scalar("SELECT CONCAT_WS('|',u.id,HEX(u.username),HEX(u.username_key),HEX(u.password_hash),u.status,u.created_at_ms,u.updated_at_ms,u.last_login_at_ms IS NULL,s.id,s.user_id,HEX(s.token_digest),s.status,s.issued_at_ms,s.expires_at_ms,s.revoked_at_ms IS NULL,s.last_seen_at_ms) FROM users u JOIN sessions s ON s.user_id=u.id","1|646973706C6179|757067726164652D75736572|746573742D706863|1|0|0|1|1|1|BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB|1|0|100|1|0");
    scalar("SELECT CONCAT_WS('|',HEX(object_hash),size,state,ref_count,storage_class,created_at_ms,updated_at_ms,verified_at_ms IS NULL) FROM objects","BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB|17|1|1|1|0|0|1");
    vireo_mysql_statement_t *s=query("SELECT CONCAT_WS('|',id,owner_id,COALESCE(parent_id,'N'),HEX(name),node_type,state,COALESCE(HEX(object_hash),'N'),size,created_at_ms,updated_at_ms,deleted_at_ms IS NULL) FROM file_nodes WHERE id<=2 ORDER BY id");
    row(s,"1|1|N||1|2|N|0|0|0|1");
    row(s,"2|1|1|736565642D66696C65|2|2|BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB|17|0|0|1"); done(&s);
    scalar("SELECT CONCAT_WS('|',id,HEX(request_id),user_id,session_id,action,target_type,target_id,target_hash IS NULL,status,latency_us,HEX(detail),occurred_at_ms) FROM operation_audits","1|BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB|1|1|2|2|1|1|0|7|73656564|0");
    scalar("SELECT HEX(name_hash) FROM file_nodes WHERE id=1","E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855");
}
static size_t fd_count(void)
{
    DIR *d=opendir("/proc/self/fd"); assert(d); struct dirent *p; size_t n=0;
    while((p=readdir(d))) { if(strcmp(p->d_name,".") && strcmp(p->d_name,"..")) { ++n; } }
    assert(closedir(d)==0); return n;
}
static void ledger(size_t versions)
{
    vireo_mysql_statement_t *s=query("SELECT CONCAT(version,'|',state,'|',HEX(checksum)) FROM vireo_schema_migrations ORDER BY version");
    row(s,"1|1|58C6116C0920294129F40AFE777C4E3F616B4532393EF09B7FDDBC4822F688BE");
    row(s,"2|1|D8FC1A1E07981AF9D4C5DB32C9CB71D66CFD326B13E7EB771CB21723D96ED90C");
    row(s,"3|1|AAEF9451FC21B6DE65EF4BA447F63E7125CF9ECE1EB26A95A2627C77758885AE");
    if(versions==4) { row(s,"4|1|66687B2CEE61BC9BC506D89B6055F0A031D66C8634DAF5D432FF923E2C510276"); } done(&s);
}
int main(int argc,char **argv)
{
    assert(setvbuf(stdout,NULL,_IONBF,0)==0 && argc==5);
    char password[1026]; FILE *f=fopen(argv[3],"r"); assert(f);
    assert(fgets(password,(int)sizeof(password),f) && fclose(f)==0); password[strcspn(password,"\n")]=0;
    struct sigaction sa={0}; sa.sa_handler=SIG_IGN; assert(sigemptyset(&sa.sa_mask)==0 && sigaction(SIGPIPE,&sa,NULL)==0);
    vireo_mysql_runtime_t *runtime=NULL; CHECK(vireo_mysql_runtime_create(&runtime,NULL));
    CHECK(vireo_mysql_thread_attach(runtime,&thread,NULL)); size_t before=fd_count();
    vireo_mysql_connection_options_t options={argv[1],argv[2],password,argv[4],3,3,3};
    const vireo_mysql_migration_t *catalog=NULL; size_t count=0; CHECK(vireo_mysql_schema_catalog(&catalog,&count)); assert(count==10); count=4; /* 保留v4前缀元数据/约束及升级回归。 */
    vireo_mysql_migration_report_t report; vireo_mysql_migration_error_t error;
    apply(&options,catalog,count,&report,&error);
    assert(report.ready && report.connection_closed && report.applied_before==0 && report.applied_after==4 && report.steps_completed==7 && report.migrations_applied==4 && report.write_attempted);
    CHECK(vireo_mysql_connection_open(thread,&options,&connection,NULL)); metadata();
    owner=add_user("upload-owner"); root=add_root(owner); other_owner=add_user("other-owner"); other_root=add_root(other_owner);
    task_boundaries(); chunk_boundaries(); transactions(); ledger(4);
    char data_before[256],data_after[256]; snapshot(data_before);
    apply(&options,catalog,count,&report,&error);
    assert(report.ready && report.connection_closed && report.applied_before==4 && report.applied_after==4 && !report.steps_completed && !report.write_attempted && !report.migrations_applied);
    snapshot(data_after); assert(!strcmp(data_before,data_after)); ledger(4);
    CHECK(vireo_mysql_connection_destroy(thread,&connection));
    options.database="vireo_upload_upgrade";
    apply(&options,catalog,3,&report,&error);
    assert(report.ready && report.connection_closed && report.steps_completed==5 && report.applied_after==3);
    CHECK(vireo_mysql_connection_open(thread,&options,&connection,NULL)); seed(); seed_preserved(); ledger(3);
    apply(&options,catalog,count,&report,&error);
    assert(report.ready && report.connection_closed && report.applied_before==3 && report.applied_after==4 && report.steps_completed==2 && report.migrations_applied==1 && report.write_attempted);
    seed_preserved(); ledger(4); metadata(); scalar("SELECT COUNT(*) FROM upload_tasks","0"); scalar("SELECT COUNT(*) FROM upload_chunks","0");
    owner=1; root=1;
    vireo_mysql_parameter_t t[19],p[8]; values(t); uint64_t task=execute(insert_task,t,19,0); chunk_values(p,task); (void)execute(insert_chunk,p,8,0); snapshot(data_before);
    apply(&options,catalog,count,&report,&error);
    assert(report.ready && report.connection_closed && report.applied_before==4 && report.applied_after==4 && !report.steps_completed && !report.write_attempted && !report.migrations_applied);
    snapshot(data_after); assert(!strcmp(data_before,data_after)); ledger(4); seed_preserved();
    scalar("SELECT CONCAT_WS('|',id,HEX(request_id),user_id,session_id,action,target_type,target_id,target_hash IS NULL,status,latency_us,HEX(detail),occurred_at_ms) FROM operation_audits","1|BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB|1|1|2|2|1|1|0|7|73656564|0");
    CHECK(vireo_mysql_connection_destroy(thread,&connection)); CHECK(vireo_mysql_thread_detach(&thread)); CHECK(vireo_mysql_runtime_destroy(&runtime));
    assert(fd_count()==before); memset(password,0,sizeof(password));
    printf("PASS empty7/seeded-v3 upgrade2/repeat preserve data+four hashes, %zu rejected writes unchanged, FD %zu -> %zu\n",rejected,before,fd_count());
    return 0;
}
