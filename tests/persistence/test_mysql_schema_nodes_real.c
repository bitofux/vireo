/*
 * PROJECT : VIREO
 * FILE    : test_mysql_schema_nodes_real.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-18
 * BRIEF   : 公共接口验证真实v2元数据、约束、含数据升级及资源退出。
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
static const vireo_mysql_statement_limits_t limits={16,16,4096,4096,262144};
static size_t rejected;
static size_t generic_fk;
static unsigned int serial;
static unsigned char object_key[33];
static const char insert_object[]="INSERT INTO objects(object_hash,size,state,ref_count,storage_class,created_at_ms,updated_at_ms,verified_at_ms) VALUES(?,?,?,?,?,?,?,?)";
static const char insert_node[]="INSERT INTO file_nodes(owner_id,parent_id,name,node_type,state,object_hash,size,created_at_ms,updated_at_ms,deleted_at_ms) VALUES(?,?,?,?,?,?,?,?,?,?)";

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
    vireo_mysql_statement_t *s=query("SELECT CONCAT_WS('|',(SELECT COUNT(*) FROM objects),(SELECT COALESCE(SUM(CRC32(CONCAT_WS(':',HEX(object_hash),size,state,ref_count,storage_class,created_at_ms,updated_at_ms,COALESCE(verified_at_ms,'N')))),0) FROM objects),(SELECT COUNT(*) FROM file_nodes),(SELECT COALESCE(SUM(CRC32(CONCAT_WS(':',id,owner_id,COALESCE(parent_id,'N'),HEX(name),node_type,state,COALESCE(HEX(object_hash),'N'),size,created_at_ms,updated_at_ms,COALESCE(deleted_at_ms,'N')))),0) FROM file_nodes))");
    vireo_mysql_fetch_outcome_t outcome; CHECK(vireo_mysql_statement_fetch(thread,s,&outcome,NULL)); assert(outcome==VIREO_MYSQL_FETCH_ROW);
    vireo_mysql_cell_view_t c; CHECK(vireo_mysql_statement_column(thread,s,0,&c)); assert(!c.is_null && c.length<256);
    memcpy(result,c.data,c.length); result[c.length]=0; done(&s);
}
static uint64_t execute(const char *sql,const vireo_mysql_parameter_t *p,size_t n,unsigned int code)
{
    ++serial; char before[256]; if(code) { snapshot(before); }
    vireo_mysql_statement_t *s=NULL; vireo_mysql_error_t e={0}; vireo_mysql_execution_t ex={0};
    errno=EDOM;
    vireo_result_t r=vireo_mysql_statement_prepare(thread,connection,sql,strlen(sql),&limits,&s,&e);
    assert(errno==EDOM);
    /* 常量CHECK或显式写生成列可在prepare拒绝，不能假定所有SQL错误都在execute。 */
    if(r==VIREO_OK) { errno=EDOM; r=vireo_mysql_statement_execute(thread,s,p,n,&ex,&e); assert(errno==EDOM); }
    bool alias=(code==1452 && e.mysql_code==1216) || (code==1451 && e.mysql_code==1217);
    if(alias) { ++generic_fk; }
    if(r!=(code ? VIREO_RESULT_DATABASE : VIREO_OK) || (e.mysql_code!=code && !alias)) {
        fprintf(stderr,"case %u result %d mysql %u expected %u\n",serial,(int)r,e.mysql_code,code); abort();
    }
    if(code==1451 || code==1452) { assert(!memcmp(e.sqlstate,"23000",6)); }
    uint64_t id=ex.insert_id;
    if(s) { destroy(&s); }
    if(code) {
        ++rejected; char after[256]; snapshot(after); assert(!strcmp(before,after));
    } else { assert(!ex.has_result && ex.affected_rows==1); }
    return id;
}
static uint64_t add_user(const char *key)
{
    vireo_mysql_parameter_t p=BYTES(key,strlen(key));
    return execute("INSERT INTO users(username,username_key,password_hash,status,created_at_ms,updated_at_ms) VALUES('display',?,'test-phc',1,0,0)",&p,1,0);
}
static void object_values(vireo_mysql_parameter_t p[8])
{
    memset(object_key,0,sizeof(object_key)); ++serial; memcpy(object_key,&serial,sizeof(serial));
    p[0]=BYTES(object_key,32); p[1]=U64(10); p[2]=U64(1); p[3]=U64(0);
    p[4]=U64(1); p[5]=U64(10); p[6]=U64(20); p[7]=NIL;
}
static void node_values(vireo_mysql_parameter_t p[10],uint64_t owner,uint64_t parent,const char *name)
{
    p[0]=U64(owner); p[1]=parent ? U64(parent) : NIL; p[2]=BYTES(name,strlen(name));
    p[3]=U64(1); p[4]=U64(2); p[5]=NIL; p[6]=U64(0);
    p[7]=U64(10); p[8]=U64(20); p[9]=NIL;
}
static void metadata(void)
{
    scalar("SELECT VERSION() REGEXP '^8[.]0[.]'","1");
    vireo_mysql_statement_t *s=query("SELECT CONCAT(TABLE_NAME,'|',ENGINE,'|',TABLE_COLLATION) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME IN('objects','file_nodes') ORDER BY TABLE_NAME");
    row(s,"file_nodes|InnoDB|utf8mb4_bin"); row(s,"objects|InnoDB|utf8mb4_bin"); done(&s);
    static const char *const columns[]={
        "file_nodes|id|bigint unsigned|-|-|NO|NULL|auto_increment|-|-",
        "file_nodes|owner_id|bigint unsigned|-|-|NO|NULL||-|-",
        "file_nodes|parent_id|bigint unsigned|-|-|YES|NULL||-|-",
        "file_nodes|name|varbinary(255)|255|255|NO|NULL||-|-",
        "file_nodes|name_hash|binary(32)|32|32|YES|NULL|STORED GENERATED|-|-",
        "file_nodes|node_type|tinyint unsigned|-|-|NO|NULL||-|-",
        "file_nodes|state|tinyint unsigned|-|-|NO|NULL||-|-",
        "file_nodes|object_hash|binary(32)|32|32|YES|NULL||-|-",
        "file_nodes|size|bigint unsigned|-|-|NO|NULL||-|-",
        "file_nodes|created_at_ms|bigint unsigned|-|-|NO|NULL||-|-",
        "file_nodes|updated_at_ms|bigint unsigned|-|-|NO|NULL||-|-",
        "file_nodes|deleted_at_ms|bigint unsigned|-|-|YES|NULL||-|-",
        "file_nodes|live_name|varbinary(255)|255|255|YES|NULL|STORED GENERATED|-|-",
        "file_nodes|active_root_owner|bigint unsigned|-|-|YES|NULL|STORED GENERATED|-|-",
        "objects|object_hash|binary(32)|32|32|NO|NULL||-|-",
        "objects|size|bigint unsigned|-|-|NO|NULL||-|-",
        "objects|state|tinyint unsigned|-|-|NO|NULL||-|-",
        "objects|ref_count|bigint unsigned|-|-|NO|NULL||-|-",
        "objects|storage_class|tinyint unsigned|-|-|NO|NULL||-|-",
        "objects|created_at_ms|bigint unsigned|-|-|NO|NULL||-|-",
        "objects|updated_at_ms|bigint unsigned|-|-|NO|NULL||-|-",
        "objects|verified_at_ms|bigint unsigned|-|-|YES|NULL||-|-"};
    s=query("SELECT CONCAT_WS('|',TABLE_NAME,COLUMN_NAME,COLUMN_TYPE,COALESCE(CAST(CHARACTER_MAXIMUM_LENGTH AS CHAR),'-'),COALESCE(CAST(CHARACTER_OCTET_LENGTH AS CHAR),'-'),IS_NULLABLE,COALESCE(COLUMN_DEFAULT,'NULL'),EXTRA,COALESCE(CHARACTER_SET_NAME,'-'),COALESCE(COLLATION_NAME,'-')) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME IN('objects','file_nodes') ORDER BY TABLE_NAME,ORDINAL_POSITION");
    for(size_t i=0;i<sizeof(columns)/sizeof(columns[0]);++i) { row(s,columns[i]); } done(&s);
    s=query("SELECT CONCAT(COLUMN_NAME,'|',LOWER(REGEXP_REPLACE(GENERATION_EXPRESSION,'[[:space:]`()]',''))) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='file_nodes' AND GENERATION_EXPRESSION<>'' ORDER BY ORDINAL_POSITION");
    row(s,"name_hash|unhexsha2name,256");
    row(s,"live_name|casewhenparent_idisnotnullandstatein1,2thennameelsenullend");
    row(s,"active_root_owner|casewhenparent_idisnullandstate=2thenowner_idelsenullend"); done(&s);
    static const char *const indexes[]={
        "file_nodes|file_nodes_active_root_unique|0|1|active_root_owner|BTREE|-|A|YES",
        "file_nodes|file_nodes_live_name_unique|0|1|owner_id|BTREE|-|A|YES",
        "file_nodes|file_nodes_live_name_unique|0|2|parent_id|BTREE|-|A|YES",
        "file_nodes|file_nodes_live_name_unique|0|3|live_name|BTREE|-|A|YES",
        "file_nodes|file_nodes_object_id|1|1|object_hash|BTREE|-|A|YES",
        "file_nodes|file_nodes_object_id|1|2|id|BTREE|-|A|YES",
        "file_nodes|file_nodes_owner_id_unique|0|1|owner_id|BTREE|-|A|YES",
        "file_nodes|file_nodes_owner_id_unique|0|2|id|BTREE|-|A|YES",
        "file_nodes|file_nodes_owner_state_deleted|1|1|owner_id|BTREE|-|A|YES",
        "file_nodes|file_nodes_owner_state_deleted|1|2|state|BTREE|-|A|YES",
        "file_nodes|file_nodes_owner_state_deleted|1|3|deleted_at_ms|BTREE|-|A|YES",
        "file_nodes|file_nodes_owner_state_deleted|1|4|id|BTREE|-|A|YES",
        "file_nodes|file_nodes_parent_state_id|1|1|owner_id|BTREE|-|A|YES",
        "file_nodes|file_nodes_parent_state_id|1|2|parent_id|BTREE|-|A|YES",
        "file_nodes|file_nodes_parent_state_id|1|3|state|BTREE|-|A|YES",
        "file_nodes|file_nodes_parent_state_id|1|4|id|BTREE|-|A|YES",
        "file_nodes|PRIMARY|0|1|id|BTREE|-|A|YES",
        "objects|objects_refs_state|1|1|ref_count|BTREE|-|A|YES",
        "objects|objects_refs_state|1|2|state|BTREE|-|A|YES",
        "objects|objects_refs_state|1|3|object_hash|BTREE|-|A|YES",
        "objects|objects_state_updated|1|1|state|BTREE|-|A|YES",
        "objects|objects_state_updated|1|2|updated_at_ms|BTREE|-|A|YES",
        "objects|objects_state_updated|1|3|object_hash|BTREE|-|A|YES",
        "objects|PRIMARY|0|1|object_hash|BTREE|-|A|YES"};
    s=query("SELECT CONCAT_WS('|',TABLE_NAME,INDEX_NAME,NON_UNIQUE,SEQ_IN_INDEX,COLUMN_NAME,INDEX_TYPE,COALESCE(CAST(SUB_PART AS CHAR),'-'),COLLATION,IS_VISIBLE) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME IN('objects','file_nodes') ORDER BY TABLE_NAME,INDEX_NAME,SEQ_IN_INDEX");
    for(size_t i=0;i<sizeof(indexes)/sizeof(indexes[0]);++i) { row(s,indexes[i]); } done(&s);
    static const char *const checks[]={"file_nodes_deletion_valid|YES","file_nodes_location_valid|YES","file_nodes_payload_valid|YES","file_nodes_state_valid|YES","file_nodes_type_valid|YES","file_nodes_updated_order|YES","objects_deleting_unreferenced|YES","objects_state_valid|YES","objects_storage_class_valid|YES","objects_updated_order|YES","objects_verified_order|YES","objects_verified_required|YES"};
    s=query("SELECT CONCAT_WS('|',CONSTRAINT_NAME,ENFORCED) FROM information_schema.TABLE_CONSTRAINTS WHERE CONSTRAINT_SCHEMA=DATABASE() AND TABLE_NAME IN('objects','file_nodes') AND CONSTRAINT_TYPE='CHECK' ORDER BY CONSTRAINT_NAME");
    for(size_t i=0;i<sizeof(checks)/sizeof(checks[0]);++i) { row(s,checks[i]); } done(&s);
    s=query("SELECT CONCAT_WS('|',k.CONSTRAINT_NAME,k.TABLE_NAME,k.COLUMN_NAME,k.ORDINAL_POSITION,k.REFERENCED_TABLE_NAME,k.REFERENCED_COLUMN_NAME,r.UPDATE_RULE,r.DELETE_RULE) FROM information_schema.KEY_COLUMN_USAGE k JOIN information_schema.REFERENTIAL_CONSTRAINTS r ON k.CONSTRAINT_SCHEMA=r.CONSTRAINT_SCHEMA AND k.CONSTRAINT_NAME=r.CONSTRAINT_NAME WHERE k.CONSTRAINT_SCHEMA=DATABASE() AND k.TABLE_NAME IN('objects','file_nodes') ORDER BY k.CONSTRAINT_NAME,k.ORDINAL_POSITION");
    row(s,"file_nodes_object_fk|file_nodes|object_hash|1|objects|object_hash|RESTRICT|RESTRICT");
    row(s,"file_nodes_owner_fk|file_nodes|owner_id|1|users|id|RESTRICT|RESTRICT");
    row(s,"file_nodes_parent_fk|file_nodes|owner_id|1|file_nodes|owner_id|RESTRICT|RESTRICT");
    row(s,"file_nodes_parent_fk|file_nodes|parent_id|2|file_nodes|id|RESTRICT|RESTRICT"); done(&s);
    scalar("SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME IN('users','sessions','objects','file_nodes')","38");
    scalar("SELECT COUNT(*) FROM (SELECT DISTINCT TABLE_NAME,INDEX_NAME FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME IN('users','sessions','objects','file_nodes')) i","17");
    scalar("SELECT COUNT(*) FROM information_schema.TABLE_CONSTRAINTS WHERE CONSTRAINT_SCHEMA=DATABASE() AND CONSTRAINT_TYPE='CHECK'","23");
    scalar("SELECT COUNT(*) FROM information_schema.REFERENTIAL_CONSTRAINTS WHERE CONSTRAINT_SCHEMA=DATABASE()","4");
    scalar("SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE()","5");
    scalar("SELECT COUNT(*) FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA=DATABASE()","0");
    puts("PASS nodes metadata: 22 columns/3 generated expressions/10 ordered indexes/3 RESTRICT FK/12 enforced CHECK; cumulative 38/17/4/23 plus ledger, no triggers");
}
static void objects(void)
{
    vireo_mysql_parameter_t p[8];
    for(uint64_t state=1;state<=4;++state) {
        object_values(p); p[2]=U64(state); if(state==2) { p[7]=U64(10); }
        (void)execute(insert_object,p,8,0);
    }
    object_values(p); p[2]=U64(0); (void)execute(insert_object,p,8,3819);
    object_values(p); p[2]=U64(5); (void)execute(insert_object,p,8,3819);
    object_values(p); p[4]=U64(0); (void)execute(insert_object,p,8,3819);
    object_values(p); p[4]=U64(2); (void)execute(insert_object,p,8,3819);
    object_values(p); p[6]=U64(9); (void)execute(insert_object,p,8,3819);
    object_values(p); p[2]=U64(2); (void)execute(insert_object,p,8,3819);
    object_values(p); p[7]=U64(9); (void)execute(insert_object,p,8,3819);
    object_values(p); p[7]=U64(21); (void)execute(insert_object,p,8,3819);
    object_values(p); p[2]=U64(3); p[3]=U64(1); (void)execute(insert_object,p,8,3819);
    object_values(p); p[2]=U64(4); p[3]=U64(5); p[7]=U64(20); (void)execute(insert_object,p,8,0);
    object_values(p); p[0]=BYTES(NULL,0); p[1]=U64(0); p[5]=U64(0); p[6]=U64(UINT64_MAX); (void)execute(insert_object,p,8,0);
    scalar("SELECT CONCAT(size,'|',created_at_ms,'|',updated_at_ms,'|',verified_at_ms IS NULL) FROM objects WHERE object_hash=REPEAT(CHAR(0),32)","0|0|18446744073709551615|1");
    object_values(p); p[1]=U64(UINT64_MAX); p[2]=U64(2); p[3]=U64(UINT64_MAX); p[5]=U64(UINT64_MAX); p[6]=U64(UINT64_MAX); p[7]=U64(UINT64_MAX); (void)execute(insert_object,p,8,0);
    scalar("SELECT CONCAT(size,'|',ref_count,'|',verified_at_ms) FROM objects WHERE size=18446744073709551615","18446744073709551615|18446744073709551615|18446744073709551615");
    object_values(p); memset(object_key,0xab,31); p[0]=BYTES(object_key,31); (void)execute(insert_object,p,8,0);
    scalar("SELECT CONCAT(OCTET_LENGTH(object_hash),'|',HEX(RIGHT(object_hash,1))) FROM objects WHERE LEFT(object_hash,31)=REPEAT(X'AB',31)","32|00");
    object_values(p); p[0]=BYTES(object_key,33); (void)execute(insert_object,p,8,1406);
    for(size_t i=0;i<7;++i) { object_values(p); p[i]=NIL; (void)execute(insert_object,p,8,1048); }
    puts("PASS objects: state/class/verified/order/deleting checks, quarantine references, uint64/NULL/zero, BINARY31 padding and33 rejection (caller must validate exact32)");
}
static void nodes(void)
{
    uint64_t owner=add_user("owner-a"), other=add_user("owner-b");
    (void)add_user("no-root");
    vireo_mysql_parameter_t p[10]; node_values(p,owner,0,"");
    uint64_t root=execute(insert_node,p,10,0); (void)execute(insert_node,p,10,1062);
    node_values(p,other,0,""); uint64_t other_root=execute(insert_node,p,10,0);
    assert(root==1 && other_root>root);
    scalar("SELECT COUNT(*) FROM users u LEFT JOIN file_nodes n ON n.owner_id=u.id WHERE u.username_key=_binary'no-root' AND n.id IS NULL","1");
    node_values(p,owner,0,"bad-root"); (void)execute(insert_node,p,10,3819);
    node_values(p,owner,0,""); p[3]=U64(2); p[5]=BYTES(NULL,0); (void)execute(insert_node,p,10,3819);
    node_values(p,owner,0,""); p[4]=U64(3); p[9]=U64(10); (void)execute(insert_node,p,10,3819);
    node_values(p,other,root,"cross-owner"); (void)execute(insert_node,p,10,1452);
    node_values(p,owner,UINT64_MAX,"missing-parent"); (void)execute(insert_node,p,10,1452);
    node_values(p,UINT64_MAX,0,""); (void)execute(insert_node,p,10,1452);
    static const unsigned char missing[32]={0xff};
    node_values(p,owner,root,"missing-object"); p[3]=U64(2); p[5]=BYTES(missing,32); (void)execute(insert_node,p,10,1452);
    node_values(p,owner,root,"note"); p[3]=U64(2); p[4]=U64(1); p[6]=U64(100);
    uint64_t first=execute(insert_node,p,10,0);
    (void)execute(insert_node,p,10,1062); p[4]=U64(2); p[5]=BYTES(NULL,0); (void)execute(insert_node,p,10,1062);
    vireo_mysql_parameter_t id=U64(first);
    (void)execute("UPDATE file_nodes SET state=3,deleted_at_ms=20 WHERE id=?",&id,1,0);
    node_values(p,owner,root,"note"); uint64_t second=execute(insert_node,p,10,0);
    (void)execute("UPDATE file_nodes SET state=2,deleted_at_ms=NULL,object_hash=REPEAT(CHAR(0),32) WHERE id=?",&id,1,1062);
    id=U64(second); (void)execute("UPDATE file_nodes SET state=3,deleted_at_ms=10 WHERE id=?",&id,1,0);
    node_values(p,owner,root,"note"); (void)execute(insert_node,p,10,0);
    scalar("SELECT CONCAT(SUM(state=3),'|',SUM(live_name IS NOT NULL)) FROM file_nodes WHERE name=X'6E6F7465'","2|1");
    static const char *const names[]={"Note","note ","note  "};
    for(size_t i=0;i<3;++i) { node_values(p,owner,root,names[i]); (void)execute(insert_node,p,10,0); }
    node_values(p,other,other_root,"note"); (void)execute(insert_node,p,10,0);
    node_values(p,owner,root,"dir"); uint64_t dir=execute(insert_node,p,10,0);
    node_values(p,owner,dir,"note"); (void)execute(insert_node,p,10,0);
    scalar("SELECT HEX(name_hash) FROM file_nodes WHERE parent_id=1 AND name=X'6E6F7465' AND state=2","EDB465624291E4053C6C5EA4B7EB320DEC773E10A57D26B95DCF0564F8E310F8");
    static const char *const bad[]={"",".","..","a/b"};
    for(size_t i=0;i<4;++i) { node_values(p,owner,root,bad[i]); (void)execute(insert_node,p,10,3819); }
    static const unsigned char nul_name[]={'a',0,'b'};
    node_values(p,owner,root,"unused"); p[2]=BYTES(nul_name,sizeof(nul_name)); (void)execute(insert_node,p,10,3819);
    unsigned char utf8[256]; for(size_t i=0;i<85;++i) { memcpy(utf8+i*3,"\xe7\x95\x8c",3); } utf8[255]='a';
    node_values(p,owner,root,"unused"); p[2]=BYTES(utf8,255); (void)execute(insert_node,p,10,0);
    scalar("SELECT OCTET_LENGTH(name) FROM file_nodes WHERE OCTET_LENGTH(name)=255","255");
    p[2]=BYTES(utf8,256); (void)execute(insert_node,p,10,1406);
    /* 非法UTF-8和控制字符不是DB已验证的承诺，后续caller负责拒绝。 */
    static const unsigned char not_utf8[]={0xff,1};
    node_values(p,owner,root,"unused"); p[2]=BYTES(not_utf8,2); (void)execute(insert_node,p,10,0);
    node_values(p,owner,root,"bad-type"); p[3]=U64(0); (void)execute(insert_node,p,10,3819);
    node_values(p,owner,root,"bad-type"); p[3]=U64(3); (void)execute(insert_node,p,10,3819);
    node_values(p,owner,root,"bad-state"); p[4]=U64(0); (void)execute(insert_node,p,10,3819);
    node_values(p,owner,root,"bad-state"); p[4]=U64(4); (void)execute(insert_node,p,10,3819);
    node_values(p,owner,root,"dir-upload"); p[4]=U64(1); (void)execute(insert_node,p,10,3819);
    node_values(p,owner,root,"dir-object"); p[5]=BYTES(NULL,0); (void)execute(insert_node,p,10,3819);
    node_values(p,owner,root,"dir-size"); p[6]=U64(1); (void)execute(insert_node,p,10,3819);
    node_values(p,owner,root,"active-no-object"); p[3]=U64(2); (void)execute(insert_node,p,10,3819);
    node_values(p,owner,root,"updated"); p[8]=U64(9); (void)execute(insert_node,p,10,3819);
    node_values(p,owner,root,"deleted-time"); p[9]=U64(10); (void)execute(insert_node,p,10,3819);
    node_values(p,owner,root,"deleted-time"); p[4]=U64(3); (void)execute(insert_node,p,10,3819);
    p[9]=U64(9); (void)execute(insert_node,p,10,3819); p[9]=U64(21); (void)execute(insert_node,p,10,3819);
    p[9]=U64(10); (void)execute(insert_node,p,10,0);
    node_values(p,owner,root,"max-time"); p[7]=U64(0); p[8]=U64(UINT64_MAX); p[9]=U64(UINT64_MAX); p[4]=U64(3); (void)execute(insert_node,p,10,0);
    scalar("SELECT CONCAT(created_at_ms,'|',updated_at_ms,'|',deleted_at_ms) FROM file_nodes WHERE name=X'6D61782D74696D65'","0|18446744073709551615|18446744073709551615");
    static const size_t required[]={0,2,3,4,6,7,8};
    for(size_t i=0;i<sizeof(required)/sizeof(required[0]);++i) { node_values(p,owner,root,"null"); p[required[i]]=NIL; (void)execute(insert_node,p,10,1048); }
    id=U64(root);
    (void)execute("UPDATE file_nodes SET name_hash=X'00' WHERE id=?",&id,1,3105);
    (void)execute("UPDATE file_nodes SET live_name=X'00' WHERE id=?",&id,1,3105);
    (void)execute("UPDATE file_nodes SET active_root_owner=0 WHERE id=?",&id,1,3105);
    (void)execute("DELETE FROM file_nodes WHERE id=?",&id,1,1451);
    (void)execute("UPDATE file_nodes SET id=18446744073709551615 WHERE id=?",&id,1,1451);
    id=U64(owner); (void)execute("DELETE FROM users WHERE id=?",&id,1,1451);
    (void)execute("UPDATE users SET id=18446744073709551615 WHERE id=?",&id,1,1451);
    /* 对象存在但PENDING，且size=0/节点99；这是schema合法、业务必须继续核对的反例。 */
    node_values(p,owner,root,"pending-file"); p[3]=U64(2); p[5]=BYTES(NULL,0); p[6]=U64(99);
    uint64_t file=execute(insert_node,p,10,0);
    node_values(p,owner,file,"child-of-file"); (void)execute(insert_node,p,10,0);
    node_values(p,owner,second,"child-of-deleted"); (void)execute(insert_node,p,10,0);
    id=U64(file); (void)execute("UPDATE file_nodes SET state=3,deleted_at_ms=20 WHERE id=?",&id,1,0);
    (void)execute("UPDATE objects SET state=3 WHERE object_hash=REPEAT(CHAR(0),32)",NULL,0,0);
    (void)execute("DELETE FROM objects WHERE object_hash=REPEAT(CHAR(0),32)",NULL,0,1451);
    (void)execute("UPDATE objects SET object_hash=REPEAT(X'FF',32) WHERE object_hash=REPEAT(CHAR(0),32)",NULL,0,1451);
    scalar("SELECT COUNT(*) FROM file_nodes WHERE state=3 AND object_hash=REPEAT(CHAR(0),32)","1");
    scalar("SELECT COUNT(*) FROM objects WHERE state=3 AND ref_count=0 AND object_hash=REPEAT(CHAR(0),32)","1");
    puts("PASS nodes: roots/owner-parent/object FK+RESTRICT, upload name reservation, tombstones/reuse/restore conflict, binary case/spaces and hash, UTF8 bytes255/256, generated assignment and all row checks");
    puts("PASS explicit business boundaries: no-root user, invalid UTF8, file/deleted parent, pending/size-mismatch object allowed; deleted FK blocks GC despite ref_count0");
}
static void ledger(void)
{
    vireo_mysql_statement_t *s=query("SELECT CONCAT(version,'|',state,'|',HEX(checksum)) FROM vireo_schema_migrations ORDER BY version");
    row(s,"1|1|58C6116C0920294129F40AFE777C4E3F616B4532393EF09B7FDDBC4822F688BE");
    row(s,"2|1|D8FC1A1E07981AF9D4C5DB32C9CB71D66CFD326B13E7EB771CB21723D96ED90C"); done(&s);
}
static void seed(void)
{
    uint64_t owner=add_user("upgrade-user"); vireo_mysql_parameter_t p=U64(owner);
    (void)execute("INSERT INTO sessions(user_id,token_digest,status,issued_at_ms,expires_at_ms,last_seen_at_ms) VALUES(?,REPEAT(X'AC',32),1,0,18446744073709551615,0)",&p,1,0);
}
static void seed_preserved(void)
{
    scalar("SELECT CONCAT_WS('|',u.id,HEX(u.username),HEX(u.username_key),HEX(u.password_hash),u.status,u.created_at_ms,u.updated_at_ms,u.last_login_at_ms IS NULL,s.id,s.user_id,HEX(s.token_digest),s.status,s.issued_at_ms,s.expires_at_ms,s.revoked_at_ms IS NULL,s.last_seen_at_ms) FROM users u JOIN sessions s ON s.user_id=u.id WHERE u.username_key=X'757067726164652D75736572'","1|646973706C6179|757067726164652D75736572|746573742D706863|1|0|0|1|1|1|ACACACACACACACACACACACACACACACACACACACACACACACACACACACACACACACAC|1|0|18446744073709551615|1|0");
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
    CHECK(vireo_mysql_thread_attach(runtime,&thread,NULL)); size_t before=fd_count();
    vireo_mysql_connection_options_t options={argv[1],argv[2],password,argv[4],3,3,3};
    const vireo_mysql_migration_t *catalog=NULL; size_t count=0; CHECK(vireo_mysql_schema_catalog(&catalog,&count)); assert(count==11); count=2; /* 独立保留v2前缀元数据/约束回归。 */
    vireo_mysql_migration_report_t report; vireo_mysql_migration_error_t error;
    CHECK(vireo_mysql_migration_apply(thread,&options,catalog,count,&report,&error));
    assert(report.ready && report.connection_closed && report.applied_before==0 && report.applied_after==2 && report.steps_completed==4 && report.migrations_applied==2 && report.write_attempted);
    CHECK(vireo_mysql_connection_open(thread,&options,&connection,NULL)); metadata(); objects(); nodes(); ledger();
    char data_before[256],data_after[256]; snapshot(data_before);
    CHECK(vireo_mysql_migration_apply(thread,&options,catalog,count,&report,&error));
    assert(report.ready && report.connection_closed && report.applied_before==2 && report.applied_after==2 && !report.steps_completed && !report.write_attempted && !report.migrations_applied);
    snapshot(data_after); assert(!strcmp(data_before,data_after)); ledger();
    CHECK(vireo_mysql_connection_destroy(thread,&connection));
    options.database="vireo_nodes_upgrade";
    CHECK(vireo_mysql_migration_apply(thread,&options,catalog,1,&report,&error));
    assert(report.ready && report.connection_closed && report.steps_completed==2 && report.applied_after==1);
    CHECK(vireo_mysql_connection_open(thread,&options,&connection,NULL)); seed(); seed_preserved();
    scalar("SELECT HEX(checksum) FROM vireo_schema_migrations","58C6116C0920294129F40AFE777C4E3F616B4532393EF09B7FDDBC4822F688BE");
    CHECK(vireo_mysql_migration_apply(thread,&options,catalog,count,&report,&error));
    assert(report.ready && report.connection_closed && report.applied_before==1 && report.applied_after==2 && report.steps_completed==2 && report.migrations_applied==1 && report.write_attempted);
    seed_preserved(); ledger(); metadata();
    uint64_t owner=1; vireo_mysql_parameter_t p[10]; node_values(p,owner,0,""); (void)execute(insert_node,p,10,0);
    snapshot(data_before);
    CHECK(vireo_mysql_migration_apply(thread,&options,catalog,count,&report,&error));
    assert(report.ready && report.connection_closed && report.applied_before==2 && report.applied_after==2 && !report.steps_completed && !report.write_attempted && !report.migrations_applied);
    snapshot(data_after); assert(!strcmp(data_before,data_after)); seed_preserved(); ledger();
    CHECK(vireo_mysql_connection_destroy(thread,&connection)); CHECK(vireo_mysql_thread_detach(&thread)); CHECK(vireo_mysql_runtime_destroy(&runtime));
    assert(fd_count()==before); memset(password,0,sizeof(password));
    printf("PASS full/seeded-v1-upgrade/repeat preserve data+both hashes, %zu rejected writes unchanged, %zu generic FK forms SQLSTATE23000, FD %zu -> %zu\n",rejected,generic_fk,before,fd_count());
    return 0;
}
