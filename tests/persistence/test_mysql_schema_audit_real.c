/*
 * PROJECT : VIREO
 * FILE    : test_mysql_schema_audit_real.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-18
 * BRIEF   : 公共接口验证真实v3审计结构、历史快照、原子组合及含数据升级。
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
static uint64_t serial;
static unsigned char request_key[17];
static const unsigned char zero_hash[33]={0};
static const char insert_audit[]="INSERT INTO operation_audits(request_id,user_id,session_id,action,target_type,target_id,target_hash,status,latency_us,detail,occurred_at_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?)";

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
    vireo_mysql_statement_t *s=query("SELECT CONCAT_WS('|',COUNT(*),COALESCE(SUM(CRC32(CONCAT_WS(':',id,HEX(request_id),COALESCE(user_id,'N'),COALESCE(session_id,'N'),action,target_type,COALESCE(target_id,'N'),COALESCE(HEX(target_hash),'N'),status,latency_us,HEX(detail),occurred_at_ms))),0)) FROM operation_audits");
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
    if(r!=(code ? VIREO_RESULT_DATABASE : VIREO_OK) || e.mysql_code!=code) {
        fprintf(stderr,"case %llu result %d mysql %u expected %u\n",(unsigned long long)serial,(int)r,e.mysql_code,code); abort();
    }
    uint64_t id=ex.insert_id;
    if(s) { destroy(&s); }
    if(code) {
        ++rejected; char after[256]; snapshot(after); assert(!strcmp(before,after));
    } else { assert(!ex.has_result); }
    return id;
}
static void values(vireo_mysql_parameter_t p[11])
{
    memset(request_key,0,sizeof(request_key)); ++serial;
    for(size_t i=0;i<8;++i) { request_key[15-i]=(unsigned char)(serial>>(i*8)); }
    p[0]=BYTES(request_key,16); p[1]=NIL; p[2]=NIL; p[3]=U64(2);
    p[4]=U64(0); p[5]=NIL; p[6]=NIL; p[7]=U64(0); p[8]=U64(0);
    p[9]=BYTES(NULL,0); p[10]=U64(0);
}
static void command(const char *sql) { (void)execute(sql,NULL,0,0); }
static uint64_t add_user(const char *key)
{
    vireo_mysql_parameter_t p=BYTES(key,strlen(key));
    return execute("INSERT INTO users(username,username_key,password_hash,status,created_at_ms,updated_at_ms) VALUES('display',?,'test-phc',1,0,0)",&p,1,0);
}
static uint64_t add_root(uint64_t owner)
{
    vireo_mysql_parameter_t p=U64(owner);
    return execute("INSERT INTO file_nodes(owner_id,parent_id,name,node_type,state,size,created_at_ms,updated_at_ms) VALUES(?,NULL,'',1,2,0,0,0)",&p,1,0);
}
static uint64_t add_session(uint64_t owner,unsigned char tag)
{
    unsigned char digest[32]; memset(digest,tag,sizeof(digest));
    vireo_mysql_parameter_t p[]={U64(owner),BYTES(digest,32)};
    return execute("INSERT INTO sessions(user_id,token_digest,status,issued_at_ms,expires_at_ms,last_seen_at_ms) VALUES(?,?,1,0,100,0)",p,2,0);
}
static uint64_t audit_for(uint64_t owner,uint64_t session,uint64_t action,uint64_t type,uint64_t target)
{
    vireo_mysql_parameter_t p[11]; values(p); p[1]=U64(owner); p[2]=session ? U64(session) : NIL;
    p[3]=U64(action); p[4]=U64(type); p[5]=U64(target);
    return execute(insert_audit,p,11,0);
}
static void metadata(void)
{
    scalar("SELECT VERSION() REGEXP '^8[.]0[.]'","1");
    scalar("SELECT CONCAT(ENGINE,'|',TABLE_COLLATION) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='operation_audits'","InnoDB|utf8mb4_bin");
    static const char *const columns[]={
        "id|bigint unsigned|-|-|NO|NULL|auto_increment|-|-",
        "request_id|varbinary(16)|16|16|NO|NULL||-|-",
        "user_id|bigint unsigned|-|-|YES|NULL||-|-",
        "session_id|bigint unsigned|-|-|YES|NULL||-|-",
        "action|smallint unsigned|-|-|NO|NULL||-|-",
        "target_type|tinyint unsigned|-|-|NO|NULL||-|-",
        "target_id|bigint unsigned|-|-|YES|NULL||-|-",
        "target_hash|varbinary(32)|32|32|YES|NULL||-|-",
        "status|smallint unsigned|-|-|NO|NULL||-|-",
        "latency_us|bigint unsigned|-|-|NO|NULL||-|-",
        "detail|varbinary(1024)|1024|1024|NO|NULL||-|-",
        "occurred_at_ms|bigint unsigned|-|-|NO|NULL||-|-"};
    vireo_mysql_statement_t *s=query("SELECT CONCAT_WS('|',COLUMN_NAME,COLUMN_TYPE,COALESCE(CAST(CHARACTER_MAXIMUM_LENGTH AS CHAR),'-'),COALESCE(CAST(CHARACTER_OCTET_LENGTH AS CHAR),'-'),IS_NULLABLE,COALESCE(COLUMN_DEFAULT,'NULL'),EXTRA,COALESCE(CHARACTER_SET_NAME,'-'),COALESCE(COLLATION_NAME,'-')) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='operation_audits' ORDER BY ORDINAL_POSITION");
    for(size_t i=0;i<sizeof(columns)/sizeof(columns[0]);++i) { row(s,columns[i]); } done(&s);
    static const char *const indexes[]={
        "operation_audits_action_time|1|1|action|BTREE|-|A|YES",
        "operation_audits_action_time|1|2|occurred_at_ms|BTREE|-|A|YES",
        "operation_audits_action_time|1|3|id|BTREE|-|A|YES",
        "operation_audits_request_action_unique|0|1|request_id|BTREE|-|A|YES",
        "operation_audits_request_action_unique|0|2|action|BTREE|-|A|YES",
        "operation_audits_status_time|1|1|status|BTREE|-|A|YES",
        "operation_audits_status_time|1|2|occurred_at_ms|BTREE|-|A|YES",
        "operation_audits_status_time|1|3|id|BTREE|-|A|YES",
        "operation_audits_time|1|1|occurred_at_ms|BTREE|-|A|YES",
        "operation_audits_time|1|2|id|BTREE|-|A|YES",
        "operation_audits_user_time|1|1|user_id|BTREE|-|A|YES",
        "operation_audits_user_time|1|2|occurred_at_ms|BTREE|-|A|YES",
        "operation_audits_user_time|1|3|id|BTREE|-|A|YES",
        "PRIMARY|0|1|id|BTREE|-|A|YES"};
    s=query("SELECT CONCAT_WS('|',INDEX_NAME,NON_UNIQUE,SEQ_IN_INDEX,COLUMN_NAME,INDEX_TYPE,COALESCE(CAST(SUB_PART AS CHAR),'-'),COLLATION,IS_VISIBLE) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='operation_audits' ORDER BY INDEX_NAME,SEQ_IN_INDEX");
    for(size_t i=0;i<sizeof(indexes)/sizeof(indexes[0]);++i) { row(s,indexes[i]); } done(&s);
    s=query("SELECT CONCAT_WS('|',CONSTRAINT_NAME,ENFORCED) FROM information_schema.TABLE_CONSTRAINTS WHERE CONSTRAINT_SCHEMA=DATABASE() AND TABLE_NAME='operation_audits' AND CONSTRAINT_TYPE='CHECK' ORDER BY CONSTRAINT_NAME");
    row(s,"operation_audits_action_valid|YES"); row(s,"operation_audits_actor_valid|YES");
    row(s,"operation_audits_request_valid|YES"); row(s,"operation_audits_target_valid|YES"); done(&s);
    scalar("SELECT COUNT(*) FROM information_schema.KEY_COLUMN_USAGE WHERE CONSTRAINT_SCHEMA=DATABASE() AND TABLE_NAME='operation_audits' AND REFERENCED_TABLE_NAME IS NOT NULL","0");
    scalar("SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='operation_audits' AND GENERATION_EXPRESSION<>''","0");
    scalar("SELECT COUNT(*) FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA=DATABASE() AND EVENT_OBJECT_TABLE='operation_audits'","0");
    scalar("SELECT COUNT(*) FROM information_schema.PARTITIONS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='operation_audits' AND PARTITION_NAME IS NOT NULL","0");
    scalar("SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE()","6");
    scalar("SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME<>'vireo_schema_migrations'","50");
    scalar("SELECT COUNT(DISTINCT TABLE_NAME,INDEX_NAME) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME<>'vireo_schema_migrations'","23");
    scalar("SELECT COUNT(*) FROM information_schema.TABLE_CONSTRAINTS WHERE CONSTRAINT_SCHEMA=DATABASE() AND TABLE_NAME<>'vireo_schema_migrations' AND CONSTRAINT_TYPE='CHECK' AND ENFORCED='YES'","27");
    scalar("SELECT COUNT(*) FROM information_schema.REFERENTIAL_CONSTRAINTS WHERE CONSTRAINT_SCHEMA=DATABASE()","4");
    puts("PASS audit metadata: all 12 base columns, six full ordered indexes, four enforced checks, no FK/generated/trigger/partition; cumulative 5 tables/50 columns/23 indexes/4 FK/27 checks plus ledger");
}
static void boundaries(void)
{
    vireo_mysql_parameter_t p[11];
    values(p); p[0]=BYTES(request_key,15); (void)execute(insert_audit,p,11,3819);
    values(p); p[0]=BYTES(request_key,17); (void)execute(insert_audit,p,11,1406);
    values(p); memset(request_key,0,16); (void)execute(insert_audit,p,11,3819);
    values(p); memset(request_key,0,16); request_key[0]='A'; (void)execute(insert_audit,p,11,0);
    (void)execute(insert_audit,p,11,1062); /* Same key, even if facts differ. */
    p[7]=U64(1); (void)execute(insert_audit,p,11,1062);
    p[3]=U64(3); (void)execute(insert_audit,p,11,0);
    p[3]=U64(2); request_key[0]='a'; (void)execute(insert_audit,p,11,0);
    request_key[15]=1; (void)execute(insert_audit,p,11,0);
    scalar("SELECT COUNT(*) FROM operation_audits WHERE request_id=CONCAT(X'41',REPEAT(X'00',15))","2");
    scalar("SELECT COUNT(*) FROM operation_audits WHERE request_id=CONCAT(X'61',REPEAT(X'00',15))","1");
    scalar("SELECT COUNT(*) FROM operation_audits WHERE request_id=CONCAT(X'61',REPEAT(X'00',14),X'01')","1");
    values(p); p[1]=U64(0); (void)execute(insert_audit,p,11,3819);
    values(p); p[1]=U64(1); (void)execute(insert_audit,p,11,0);
    values(p); p[2]=U64(1); (void)execute(insert_audit,p,11,3819);
    values(p); p[1]=U64(1); p[2]=U64(0); (void)execute(insert_audit,p,11,3819);
    values(p); p[1]=U64(UINT64_MAX); p[2]=U64(UINT64_MAX); (void)execute(insert_audit,p,11,0);
    scalar("SELECT CONCAT(user_id,'|',session_id) FROM operation_audits WHERE user_id=18446744073709551615","18446744073709551615|18446744073709551615");
    values(p); p[3]=U64(0); (void)execute(insert_audit,p,11,3819);
    p[3]=U64(65536); (void)execute(insert_audit,p,11,1264);
    p[3]=U64(1); (void)execute(insert_audit,p,11,0);
    values(p); p[3]=U64(65535); p[7]=U64(65535); (void)execute(insert_audit,p,11,0);
    scalar("SELECT CONCAT(action,'|',status) FROM operation_audits WHERE action=65535","65535|65535");
    values(p); p[7]=U64(65536); (void)execute(insert_audit,p,11,1264);
    for(uint64_t type=1;type<=3;++type) {
        values(p); p[4]=U64(type); (void)execute(insert_audit,p,11,3819);
        p[5]=U64(0); (void)execute(insert_audit,p,11,3819);
        p[5]=U64(1); (void)execute(insert_audit,p,11,0);
        p[6]=BYTES(zero_hash,32); (void)execute(insert_audit,p,11,3819);
        values(p); p[4]=U64(type); p[5]=U64(UINT64_MAX); (void)execute(insert_audit,p,11,0);
    }
    values(p); p[5]=U64(1); (void)execute(insert_audit,p,11,3819);
    values(p); p[6]=BYTES(zero_hash,32); (void)execute(insert_audit,p,11,3819);
    values(p); p[4]=U64(4); (void)execute(insert_audit,p,11,3819);
    p[6]=BYTES(zero_hash,31); (void)execute(insert_audit,p,11,3819);
    p[6]=BYTES(zero_hash,33); (void)execute(insert_audit,p,11,1406);
    p[6]=BYTES(zero_hash,32); p[5]=U64(1); (void)execute(insert_audit,p,11,3819);
    p[5]=NIL; (void)execute(insert_audit,p,11,0);
    scalar("SELECT CONCAT(OCTET_LENGTH(target_hash),'|',target_hash=REPEAT(X'00',32)) FROM operation_audits WHERE target_type=4","32|1");
    values(p); p[4]=U64(5); (void)execute(insert_audit,p,11,3819);
    p[4]=U64(255); (void)execute(insert_audit,p,11,3819);
    p[4]=U64(256); (void)execute(insert_audit,p,11,1264);
    unsigned char detail[1025]; memset(detail,'d',sizeof(detail));
    values(p); p[9]=BYTES(detail,1024); (void)execute(insert_audit,p,11,0);
    p[9]=BYTES(detail,1025); (void)execute(insert_audit,p,11,1406);
    for(size_t i=0;i<341;++i) { memcpy(detail+i*3,"\xe7\x95\x8c",3); } detail[1023]='x';
    values(p); p[9]=BYTES(detail,1024); (void)execute(insert_audit,p,11,0);
    p[9]=BYTES(detail,1025); (void)execute(insert_audit,p,11,1406);
    scalar("SELECT COUNT(*) FROM operation_audits WHERE OCTET_LENGTH(detail)=1024","2");
    values(p); p[8]=U64(UINT64_MAX); p[10]=U64(UINT64_MAX); (void)execute(insert_audit,p,11,0);
    scalar("SELECT CONCAT(latency_us,'|',occurred_at_ms) FROM operation_audits WHERE latency_us=18446744073709551615","18446744073709551615|18446744073709551615");
    static const size_t required[]={0,3,4,7,8,9,10};
    for(size_t i=0;i<sizeof(required)/sizeof(required[0]);++i) { values(p); p[required[i]]=NIL; (void)execute(insert_audit,p,11,1048); }
    /* Explicitly demonstrate storage limits do not enforce future writer obligations. */
    static const unsigned char invalid_utf8[]={0xff,0,1};
    values(p); p[3]=U64(60000); p[7]=U64(60000); p[9]=BYTES(invalid_utf8,3); (void)execute(insert_audit,p,11,0);
    scalar("SELECT HEX(detail) FROM operation_audits WHERE action=60000","FF0001");
    puts("PASS request exact lengths/nonzero/binary case+NUL+trailing bytes, unique event/action, actors/targets/all NULL shapes, uint bounds, detail byte boundaries; invalid UTF8/unknown codes/missing live ids remain writer obligations");
}
static void retention(void)
{
    uint64_t owner=add_user("retention"),root=add_root(owner),session=add_session(owner,0x91);
    command("INSERT INTO objects(object_hash,size,state,ref_count,storage_class,created_at_ms,updated_at_ms) VALUES(REPEAT(X'91',32),0,1,0,1,0,0)");
    (void)audit_for(owner,session,2,1,owner); (void)audit_for(owner,session,2,2,session);
    (void)audit_for(owner,session,2,3,root);
    unsigned char hash[32]; memset(hash,0x91,sizeof(hash));
    vireo_mysql_parameter_t p[11]; values(p); p[1]=U64(owner); p[2]=U64(session); p[4]=U64(4); p[6]=BYTES(hash,32);
    (void)execute(insert_audit,p,11,0);
    char before[256],after[256]; snapshot(before);
    vireo_mysql_parameter_t id=U64(session); (void)execute("DELETE FROM sessions WHERE id=?",&id,1,0);
    id=U64(root); (void)execute("DELETE FROM file_nodes WHERE id=?",&id,1,0);
    id=U64(owner); (void)execute("DELETE FROM users WHERE id=?",&id,1,0);
    command("DELETE FROM objects WHERE object_hash=REPEAT(X'91',32)");
    snapshot(after); assert(!strcmp(before,after));
    scalar("SELECT COUNT(*) FROM operation_audits a LEFT JOIN users u ON u.id=a.user_id LEFT JOIN sessions s ON s.id=a.session_id WHERE a.session_id IS NOT NULL AND a.user_id<>18446744073709551615 AND u.id IS NULL AND s.id IS NULL","4");
    puts("PASS trusted synthetic user/session/node/object deletion retains all four audit rows and original identity bytes; no live FK and no inner join dropping history");
}
static void transactions(void)
{
    /* MySQL8.0 prepared START TRANSACTION返回1295；用支持的SET关闭autocommit，
     * 首条InnoDB DML启动事务，显式COMMIT/ROLLBACK后恢复会话默认。 */
    command("SET autocommit=0");
    uint64_t owner=add_user("registration-commit"); (void)add_root(owner);
    (void)audit_for(owner,0,1,1,owner); command("COMMIT"); command("SET autocommit=1");
    scalar("SELECT COUNT(*) FROM users u JOIN file_nodes n ON n.owner_id=u.id JOIN operation_audits a ON a.user_id=u.id AND a.target_id=u.id WHERE u.username_key='registration-commit' AND n.parent_id IS NULL AND a.action=1 AND a.target_type=1","1");
    char before[256],after[256]; snapshot(before);
    command("SET autocommit=0");
    uint64_t rolled=add_user("registration-rollback"); (void)add_root(rolled);
    (void)audit_for(rolled,0,1,1,rolled); command("ROLLBACK"); command("SET autocommit=1");
    scalar("SELECT COUNT(*) FROM users WHERE username_key='registration-rollback'","0");
    scalar("SELECT COUNT(*) FROM file_nodes n LEFT JOIN users u ON n.owner_id=u.id WHERE u.id IS NULL","0");
    snapshot(after); assert(!strcmp(before,after));
    /* A duplicate statement only rolls back that statement. Caller must roll back the transaction. */
    vireo_mysql_parameter_t conflict[11]; values(conflict); conflict[3]=U64(1);
    (void)execute(insert_audit,conflict,11,0); snapshot(before);
    command("SET autocommit=0");
    uint64_t failed=add_user("registration-conflict"); (void)add_root(failed);
    conflict[1]=U64(failed); conflict[4]=U64(1); conflict[5]=U64(failed);
    (void)execute(insert_audit,conflict,11,1062);
    scalar("SELECT COUNT(*) FROM users WHERE username_key='registration-conflict'","1");
    command("ROLLBACK"); command("SET autocommit=1");
    scalar("SELECT COUNT(*) FROM users WHERE username_key='registration-conflict'","0");
    scalar("SELECT COUNT(*) FROM file_nodes n LEFT JOIN users u ON n.owner_id=u.id WHERE u.id IS NULL","0");
    snapshot(after); assert(!strcmp(before,after));
    command("SET autocommit=0");
    uint64_t session=add_session(owner,0xa1); vireo_mysql_parameter_t id=U64(owner);
    (void)execute("UPDATE users SET last_login_at_ms=10,updated_at_ms=10 WHERE id=?",&id,1,0);
    (void)audit_for(owner,session,2,2,session); command("COMMIT"); command("SET autocommit=1");
    scalar("SELECT CONCAT(u.last_login_at_ms,'|',u.updated_at_ms,'|',a.target_id=s.id) FROM users u JOIN sessions s ON s.user_id=u.id JOIN operation_audits a ON a.session_id=s.id WHERE u.username_key='registration-commit' AND a.action=2","10|10|1");
    snapshot(before); command("SET autocommit=0");
    session=add_session(owner,0xa2);
    (void)execute("UPDATE users SET last_login_at_ms=20,updated_at_ms=20 WHERE id=?",&id,1,0);
    (void)audit_for(owner,session,2,2,session); command("ROLLBACK"); command("SET autocommit=1");
    scalar("SELECT COUNT(*) FROM sessions WHERE token_digest=REPEAT(X'A2',32)","0");
    scalar("SELECT last_login_at_ms FROM users WHERE username_key='registration-commit'","10");
    snapshot(after); assert(!strcmp(before,after));
    values(conflict); conflict[3]=U64(2); (void)execute(insert_audit,conflict,11,0); snapshot(before);
    command("SET autocommit=0"); session=add_session(owner,0xa3);
    (void)execute("UPDATE users SET last_login_at_ms=30,updated_at_ms=30 WHERE id=?",&id,1,0);
    conflict[1]=U64(owner); conflict[2]=U64(session); conflict[4]=U64(2); conflict[5]=U64(session);
    (void)execute(insert_audit,conflict,11,1062);
    scalar("SELECT last_login_at_ms FROM users WHERE username_key='registration-commit'","30");
    command("ROLLBACK"); command("SET autocommit=1");
    scalar("SELECT COUNT(*) FROM sessions WHERE token_digest=REPEAT(X'A3',32)","0");
    scalar("SELECT CONCAT(last_login_at_ms,'|',updated_at_ms) FROM users WHERE username_key='registration-commit'","10|10");
    snapshot(after); assert(!strcmp(before,after));
    puts("PASS InnoDB synthetic registration user/root/audit and login Session/last_login/audit commit/rollback; duplicate audit leaves earlier DML visible until explicit ROLLBACK, then no partial business changes");
}
static void ledger(size_t versions)
{
    vireo_mysql_statement_t *s=query("SELECT CONCAT(version,'|',state,'|',HEX(checksum)) FROM vireo_schema_migrations ORDER BY version");
    row(s,"1|1|58C6116C0920294129F40AFE777C4E3F616B4532393EF09B7FDDBC4822F688BE");
    row(s,"2|1|D8FC1A1E07981AF9D4C5DB32C9CB71D66CFD326B13E7EB771CB21723D96ED90C");
    if(versions==3) { row(s,"3|1|AAEF9451FC21B6DE65EF4BA447F63E7125CF9ECE1EB26A95A2627C77758885AE"); } done(&s);
}
static void seed(void)
{
    uint64_t owner=add_user("upgrade-user"); (void)add_root(owner); (void)add_session(owner,0xbb);
    command("INSERT INTO objects(object_hash,size,state,ref_count,storage_class,created_at_ms,updated_at_ms) VALUES(REPEAT(X'BB',32),17,1,1,1,0,0)");
    vireo_mysql_parameter_t p=U64(owner);
    (void)execute("INSERT INTO file_nodes(owner_id,parent_id,name,node_type,state,object_hash,size,created_at_ms,updated_at_ms) VALUES(?,1,'seed-file',2,2,REPEAT(X'BB',32),17,0,0)",&p,1,0);
}
static void seed_preserved(void)
{
    scalar("SELECT CONCAT_WS('|',u.id,HEX(u.username),HEX(u.username_key),HEX(u.password_hash),u.status,u.created_at_ms,u.updated_at_ms,u.last_login_at_ms IS NULL,s.id,s.user_id,HEX(s.token_digest),s.status,s.issued_at_ms,s.expires_at_ms,s.revoked_at_ms IS NULL,s.last_seen_at_ms) FROM users u JOIN sessions s ON s.user_id=u.id","1|646973706C6179|757067726164652D75736572|746573742D706863|1|0|0|1|1|1|BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB|1|0|100|1|0");
    scalar("SELECT CONCAT_WS('|',HEX(object_hash),size,state,ref_count,storage_class,created_at_ms,updated_at_ms,verified_at_ms IS NULL) FROM objects","BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB|17|1|1|1|0|0|1");
    vireo_mysql_statement_t *s=query("SELECT CONCAT_WS('|',id,owner_id,COALESCE(parent_id,'N'),HEX(name),node_type,state,COALESCE(HEX(object_hash),'N'),size,created_at_ms,updated_at_ms,deleted_at_ms IS NULL) FROM file_nodes ORDER BY id");
    row(s,"1|1|N||1|2|N|0|0|0|1");
    row(s,"2|1|1|736565642D66696C65|2|2|BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB|17|0|0|1"); done(&s);
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
    const vireo_mysql_migration_t *catalog=NULL; size_t count=0; CHECK(vireo_mysql_schema_catalog(&catalog,&count)); assert(count==11); count=3; /* 独立保留v3审计前缀回归。 */
    vireo_mysql_migration_report_t report; vireo_mysql_migration_error_t error;
    CHECK(vireo_mysql_migration_apply(thread,&options,catalog,count,&report,&error));
    assert(report.ready && report.connection_closed && report.applied_before==0 && report.applied_after==3 && report.steps_completed==5 && report.migrations_applied==3 && report.write_attempted);
    CHECK(vireo_mysql_connection_open(thread,&options,&connection,NULL)); metadata(); boundaries(); retention(); transactions(); ledger(3);
    char data_before[256],data_after[256]; snapshot(data_before);
    CHECK(vireo_mysql_migration_apply(thread,&options,catalog,count,&report,&error));
    assert(report.ready && report.connection_closed && report.applied_before==3 && report.applied_after==3 && !report.steps_completed && !report.write_attempted && !report.migrations_applied);
    snapshot(data_after); assert(!strcmp(data_before,data_after)); ledger(3);
    scalar("SELECT CONCAT(last_login_at_ms,'|',updated_at_ms) FROM users WHERE username_key='registration-commit'","10|10");
    CHECK(vireo_mysql_connection_destroy(thread,&connection));
    options.database="vireo_audit_upgrade";
    CHECK(vireo_mysql_migration_apply(thread,&options,catalog,2,&report,&error));
    assert(report.ready && report.connection_closed && report.steps_completed==4 && report.applied_after==2);
    CHECK(vireo_mysql_connection_open(thread,&options,&connection,NULL)); seed(); seed_preserved(); ledger(2);
    CHECK(vireo_mysql_migration_apply(thread,&options,catalog,count,&report,&error));
    assert(report.ready && report.connection_closed && report.applied_before==2 && report.applied_after==3 && report.steps_completed==1 && report.migrations_applied==1 && report.write_attempted);
    seed_preserved(); ledger(3); metadata(); scalar("SELECT COUNT(*) FROM operation_audits","0");
    (void)audit_for(1,1,2,2,1); snapshot(data_before);
    CHECK(vireo_mysql_migration_apply(thread,&options,catalog,count,&report,&error));
    assert(report.ready && report.connection_closed && report.applied_before==3 && report.applied_after==3 && !report.steps_completed && !report.write_attempted && !report.migrations_applied);
    snapshot(data_after); assert(!strcmp(data_before,data_after)); seed_preserved(); ledger(3);
    CHECK(vireo_mysql_connection_destroy(thread,&connection)); CHECK(vireo_mysql_thread_detach(&thread)); CHECK(vireo_mysql_runtime_destroy(&runtime));
    assert(fd_count()==before); memset(password,0,sizeof(password));
    printf("PASS empty full5/seeded-v2 upgrade1/repeat preserve data+three hashes, %zu rejected writes unchanged, FD %zu -> %zu\n",rejected,before,fd_count());
    return 0;
}
