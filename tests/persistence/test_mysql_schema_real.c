/*
 * PROJECT : VIREO
 * FILE    : test_mysql_schema_real.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-18
 * BRIEF   : 仅公共接口验证真实初始schema、约束、凭据及资源退出。
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
static const vireo_mysql_statement_limits_t limits={8,16,4096,4096,262144};
static unsigned int serial;
static char unique_key[32];
static char phc[VIREO_PASSWORD_ENCODED_CAPACITY];
static size_t phc_length;
static unsigned char digest[32];
static size_t rejected;
static size_t generic_fk;
static const char insert_user[]="INSERT INTO users(username,username_key,password_hash,status,created_at_ms,updated_at_ms,last_login_at_ms) VALUES(?,?,?,?,?,?,?)";
static const char insert_session[]="INSERT INTO sessions(user_id,token_digest,status,issued_at_ms,expires_at_ms,revoked_at_ms,last_seen_at_ms) VALUES(?,?,?,?,?,?,?)";

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
static uint64_t execute(const char *sql,const vireo_mysql_parameter_t *p,size_t n,unsigned int code)
{
    vireo_mysql_statement_t *s=prepare(sql); vireo_mysql_execution_t ex; vireo_mysql_error_t e;
    errno=EDOM; vireo_result_t r=vireo_mysql_statement_execute(thread,s,p,n,&ex,&e); assert(errno==EDOM);
    /* MySQL按父表权限可见性选择通用1216/1217或详细1452/1451；均是FK拒绝。
     * 官方create-table-foreign-keys的Warning；不扩大fixture权限索取详细信息。 */
    bool fk_alias=(code==1452 && e.mysql_code==1216) || (code==1451 && e.mysql_code==1217);
    if(fk_alias) { ++generic_fk; }
    if(code==1451 || code==1452) { assert(!memcmp(e.sqlstate,"23000",6)); }
    if(r!=(code ? VIREO_RESULT_DATABASE : VIREO_OK) || (e.mysql_code!=code && !fk_alias)) {
        fprintf(stderr,"case %u execute result %d mysql %u expected %u\n",serial,(int)r,e.mysql_code,code); abort();
    }
    if(code) { ++rejected; } else { assert(!ex.has_result && ex.affected_rows==1); }
    uint64_t id=ex.insert_id; destroy(&s); return id;
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
static void user_values(vireo_mysql_parameter_t p[7])
{
    int n=snprintf(unique_key,sizeof(unique_key),"key-%u",++serial); assert(n>0 && (size_t)n<sizeof(unique_key));
    p[0]=TEXT("display",7); p[1]=BYTES(unique_key,(size_t)n); p[2]=BYTES(phc,phc_length);
    p[3]=U64(1); p[4]=U64(10); p[5]=U64(10); p[6]=NIL;
}
static void session_values(vireo_mysql_parameter_t p[7],uint64_t user)
{
    ++serial; memset(digest,0,sizeof(digest)); memcpy(digest,&serial,sizeof(serial));
    p[0]=U64(user); p[1]=BYTES(digest,sizeof(digest)); p[2]=U64(1);
    p[3]=U64(10); p[4]=U64(20); p[5]=NIL; p[6]=U64(10);
}
static void metadata(void)
{
    scalar("SELECT VERSION() REGEXP '^8[.]0[.]'","1");
    scalar("SELECT (SUBSTRING_INDEX(VERSION(),'.',1)*10000+SUBSTRING_INDEX(SUBSTRING_INDEX(VERSION(),'.',2),'.',-1)*100+SUBSTRING_INDEX(SUBSTRING_INDEX(VERSION(),'-',1),'.',-1))>=80016","1");
    vireo_mysql_statement_t *s=query("SELECT CONCAT(TABLE_NAME,'|',ENGINE,'|',TABLE_COLLATION) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME IN('users','sessions') ORDER BY TABLE_NAME");
    row(s,"sessions|InnoDB|utf8mb4_bin"); row(s,"users|InnoDB|utf8mb4_bin"); done(&s);
    /* 每列完整类型、字符/字节上限、NULL、默认、extra和字符集/排序规则；额外列也失败。 */
    static const char *const columns[]={
        "sessions|id|bigint unsigned|-|-|NO|NULL|auto_increment|-|-",
        "sessions|user_id|bigint unsigned|-|-|NO|NULL||-|-",
        "sessions|token_digest|varbinary(32)|32|32|NO|NULL||-|-",
        "sessions|status|tinyint unsigned|-|-|NO|NULL||-|-",
        "sessions|issued_at_ms|bigint unsigned|-|-|NO|NULL||-|-",
        "sessions|expires_at_ms|bigint unsigned|-|-|NO|NULL||-|-",
        "sessions|revoked_at_ms|bigint unsigned|-|-|YES|NULL||-|-",
        "sessions|last_seen_at_ms|bigint unsigned|-|-|NO|NULL||-|-",
        "users|id|bigint unsigned|-|-|NO|NULL|auto_increment|-|-",
        "users|username|varchar(64)|64|256|NO|NULL||utf8mb4|utf8mb4_bin",
        "users|username_key|varbinary(256)|256|256|NO|NULL||-|-",
        "users|password_hash|varbinary(127)|127|127|NO|NULL||-|-",
        "users|status|tinyint unsigned|-|-|NO|NULL||-|-",
        "users|created_at_ms|bigint unsigned|-|-|NO|NULL||-|-",
        "users|updated_at_ms|bigint unsigned|-|-|NO|NULL||-|-",
        "users|last_login_at_ms|bigint unsigned|-|-|YES|NULL||-|-"};
    s=query("SELECT CONCAT_WS('|',TABLE_NAME,COLUMN_NAME,COLUMN_TYPE,COALESCE(CAST(CHARACTER_MAXIMUM_LENGTH AS CHAR),'-'),COALESCE(CAST(CHARACTER_OCTET_LENGTH AS CHAR),'-'),IS_NULLABLE,COALESCE(COLUMN_DEFAULT,'NULL'),EXTRA,COALESCE(CHARACTER_SET_NAME,'-'),COALESCE(COLLATION_NAME,'-')) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME IN('users','sessions') ORDER BY TABLE_NAME,ORDINAL_POSITION");
    for(size_t i=0;i<sizeof(columns)/sizeof(columns[0]);++i) { row(s,columns[i]); } done(&s);
    static const char *const indexes[]={
        "sessions|PRIMARY|0|1|id|BTREE|-|A|YES",
        "sessions|sessions_status_expiry|1|1|status|BTREE|-|A|YES",
        "sessions|sessions_status_expiry|1|2|expires_at_ms|BTREE|-|A|YES",
        "sessions|sessions_status_expiry|1|3|id|BTREE|-|A|YES",
        "sessions|sessions_token_digest_unique|0|1|token_digest|BTREE|-|A|YES",
        "sessions|sessions_user_status_expiry|1|1|user_id|BTREE|-|A|YES",
        "sessions|sessions_user_status_expiry|1|2|status|BTREE|-|A|YES",
        "sessions|sessions_user_status_expiry|1|3|expires_at_ms|BTREE|-|A|YES",
        "sessions|sessions_user_status_expiry|1|4|id|BTREE|-|A|YES",
        "users|PRIMARY|0|1|id|BTREE|-|A|YES",
        "users|users_status_id|1|1|status|BTREE|-|A|YES",
        "users|users_status_id|1|2|id|BTREE|-|A|YES",
        "users|users_username_key_unique|0|1|username_key|BTREE|-|A|YES"};
    s=query("SELECT CONCAT_WS('|',TABLE_NAME,INDEX_NAME,NON_UNIQUE,SEQ_IN_INDEX,COLUMN_NAME,INDEX_TYPE,COALESCE(CAST(SUB_PART AS CHAR),'-'),COLLATION,IS_VISIBLE) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME IN('users','sessions') ORDER BY TABLE_NAME,INDEX_NAME,SEQ_IN_INDEX");
    for(size_t i=0;i<sizeof(indexes)/sizeof(indexes[0]);++i) { row(s,indexes[i]); } done(&s);
    s=query("SELECT CONCAT_WS('|',CONSTRAINT_NAME,ENFORCED) FROM information_schema.TABLE_CONSTRAINTS WHERE CONSTRAINT_SCHEMA=DATABASE() AND CONSTRAINT_TYPE='CHECK' ORDER BY CONSTRAINT_NAME");
    static const char *const checks[]={"sessions_digest_length|YES","sessions_expiry_order|YES","sessions_last_seen_order|YES","sessions_revocation_valid|YES","sessions_status_valid|YES","users_last_login_order|YES","users_password_hash_length|YES","users_status_valid|YES","users_updated_order|YES","users_username_key_length|YES","users_username_length|YES"};
    for(size_t i=0;i<sizeof(checks)/sizeof(checks[0]);++i) { row(s,checks[i]); } done(&s);
    s=query("SELECT CONCAT_WS('|',k.CONSTRAINT_NAME,k.TABLE_NAME,k.COLUMN_NAME,k.ORDINAL_POSITION,k.REFERENCED_TABLE_NAME,k.REFERENCED_COLUMN_NAME,r.UPDATE_RULE,r.DELETE_RULE) FROM information_schema.KEY_COLUMN_USAGE k JOIN information_schema.REFERENTIAL_CONSTRAINTS r ON k.CONSTRAINT_SCHEMA=r.CONSTRAINT_SCHEMA AND k.CONSTRAINT_NAME=r.CONSTRAINT_NAME WHERE k.CONSTRAINT_SCHEMA=DATABASE()");
    row(s,"sessions_user_fk|sessions|user_id|1|users|id|RESTRICT|RESTRICT"); done(&s);
    scalar("SELECT COUNT(*) FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA=DATABASE()","0");
    puts("PASS schema metadata: MySQL8.0.16+, 16 columns, 7 ordered indexes, 11 ENFORCED CHECKs, RESTRICT FK, no raw token/defaults/triggers");
}
static uint64_t users(void)
{
    vireo_mysql_parameter_t p[7]; user_values(p); p[1]=BYTES("identity",8);
    uint64_t user=execute(insert_user,p,7,0);
    (void)execute(insert_user,p,7,1062);
    /* 展示名相同仍可有不同binary key；不代替后续规范化策略。 */
    static const char *const keys[]={"Identity","identity ","identity  "};
    for(size_t i=0;i<3;++i) { user_values(p); p[1]=BYTES(keys[i],strlen(keys[i])); (void)execute(insert_user,p,7,0); }
    scalar("SELECT COUNT(*) FROM users WHERE username='display'","4");
    user_values(p); p[0]=TEXT(NULL,0); (void)execute(insert_user,p,7,3819);
    user_values(p); p[1]=BYTES(NULL,0); (void)execute(insert_user,p,7,3819);
    user_values(p); p[2]=BYTES(NULL,0); (void)execute(insert_user,p,7,3819);
    user_values(p); p[3]=U64(0); (void)execute(insert_user,p,7,3819);
    user_values(p); p[3]=U64(3); (void)execute(insert_user,p,7,3819);
    user_values(p); p[5]=U64(9); (void)execute(insert_user,p,7,3819);
    user_values(p); p[6]=U64(9); (void)execute(insert_user,p,7,3819);
    user_values(p); p[3]=U64(2); p[4]=U64(0); p[5]=U64(UINT64_MAX); p[6]=U64(0); (void)execute(insert_user,p,7,0);
    scalar("SELECT CONCAT(created_at_ms,'|',updated_at_ms,'|',last_login_at_ms) FROM users WHERE status=2","0|18446744073709551615|0");
    unsigned char name[260]; for(size_t i=0;i<65;++i) { memcpy(name+4*i,"\xf0\x9f\x8c\xb1",4); }
    user_values(p); p[0]=TEXT(name,256); (void)execute(insert_user,p,7,0);
    scalar("SELECT CONCAT(CHAR_LENGTH(username),'|',OCTET_LENGTH(username)) FROM users WHERE OCTET_LENGTH(username)=256","64|256");
    user_values(p); p[0]=TEXT(name,260); (void)execute(insert_user,p,7,1406);
    unsigned char key[257]; memset(key,0xa5,sizeof(key));
    user_values(p); p[1]=BYTES(key,256); (void)execute(insert_user,p,7,0);
    user_values(p); p[1]=BYTES(key,257); (void)execute(insert_user,p,7,1406);
    char storage[128]; memset(storage,'x',sizeof(storage));
    user_values(p); p[2]=BYTES(storage,127); (void)execute(insert_user,p,7,0);
    /* 长度合法不等PHC合法，caller仍必须inspect。 */
    vireo_password_policy_t policy=VIREO_PASSWORD_POLICY_DEFAULT; vireo_password_info_t info;
    errno=EDOM; assert(vireo_password_hash_inspect(&policy,storage,127,&info)!=VIREO_OK && errno==EDOM);
    user_values(p); p[2]=BYTES(storage,128); (void)execute(insert_user,p,7,1406);
    for(size_t i=0;i<7;++i) { user_values(p); p[i]=NIL; (void)execute(insert_user,p,7,i==6 ? 0 : 1048); }
    scalar("SELECT COUNT(*) FROM users WHERE last_login_at_ms IS NULL","8");
    puts("PASS users: binary uniqueness/case/trailing spaces, Unicode64/65, key256/257, PHC127/128, empty/NULL/status/time, uint64 max");
    return user;
}
static void credentials(uint64_t user)
{
    vireo_mysql_statement_t *s=query("SELECT password_hash FROM users WHERE username_key=_binary'identity'");
    vireo_mysql_fetch_outcome_t outcome; CHECK(vireo_mysql_statement_fetch(thread,s,&outcome,NULL)); assert(outcome==VIREO_MYSQL_FETCH_ROW);
    vireo_mysql_cell_view_t c; CHECK(vireo_mysql_statement_column(thread,s,0,&c)); assert(!c.is_null && c.length==phc_length && !memcmp(c.data,phc,phc_length));
    vireo_password_policy_t policy=VIREO_PASSWORD_POLICY_DEFAULT; vireo_password_info_t info;
    CHECK(vireo_password_hash_inspect(&policy,(const char *)c.data,c.length,&info)); done(&s);
    vireo_session_token_t token; vireo_session_token_digest_t original,again;
    CHECK(vireo_session_token_generate(&token,&original)); CHECK(vireo_session_token_digest(&token,&again));
    bool same=false; CHECK(vireo_session_token_digest_equal(&original,&again,&same)); assert(same);
    vireo_mysql_parameter_t p[7]; session_values(p,user); p[1]=BYTES(original.bytes,sizeof(original.bytes));
    uint64_t id=execute(insert_session,p,7,0); assert(id==1);
    s=query("SELECT token_digest FROM sessions WHERE id=1");
    CHECK(vireo_mysql_statement_fetch(thread,s,&outcome,NULL)); assert(outcome==VIREO_MYSQL_FETCH_ROW);
    CHECK(vireo_mysql_statement_column(thread,s,0,&c)); assert(!c.is_null && c.length==32);
    memcpy(again.bytes,c.data,c.length); CHECK(vireo_session_token_digest_equal(&original,&again,&same)); assert(same); done(&s);
    user_values(p); uint64_t other=execute(insert_user,p,7,0);
    session_values(p,other); p[1]=BYTES(original.bytes,sizeof(original.bytes)); (void)execute(insert_session,p,7,1062);
    CHECK(vireo_session_token_clear(&token)); memset(&original,0,sizeof(original)); memset(&again,0,sizeof(again));
    puts("PASS real035 PHC and real036 random token/digest roundtrip, digest unique across users; secrets not printed");
}
static void sessions(uint64_t user)
{
    vireo_mysql_parameter_t p[7];
    unsigned char special[33]={0};
    session_values(p,user); p[1]=BYTES(special,32); (void)execute(insert_session,p,7,0);
    special[0]=0x80; special[15]=0x7f;
    session_values(p,user); p[1]=BYTES(special,32); p[6]=U64(20); (void)execute(insert_session,p,7,0);
    special[31]=1;
    session_values(p,user); p[1]=BYTES(special,32); (void)execute(insert_session,p,7,0);
    scalar("SELECT COUNT(*) FROM sessions WHERE token_digest=REPEAT(CHAR(0),32)","1");
    scalar("SELECT HEX(token_digest) FROM sessions WHERE SUBSTRING(token_digest,1,1)=X'80' AND SUBSTRING(token_digest,32,1)=X'00'","8000000000000000000000000000007F00000000000000000000000000000000");
    session_values(p,user); p[1]=BYTES(special,31); (void)execute(insert_session,p,7,3819);
    session_values(p,user); p[1]=BYTES(special,33); (void)execute(insert_session,p,7,1406);
    session_values(p,user); p[1]=BYTES(NULL,0); (void)execute(insert_session,p,7,3819);
    session_values(p,user); p[2]=U64(0); (void)execute(insert_session,p,7,3819);
    session_values(p,user); p[2]=U64(3); (void)execute(insert_session,p,7,3819);
    session_values(p,user); p[4]=U64(10); (void)execute(insert_session,p,7,3819);
    session_values(p,user); p[4]=U64(9); (void)execute(insert_session,p,7,3819);
    session_values(p,user); p[6]=U64(9); (void)execute(insert_session,p,7,3819);
    session_values(p,user); p[6]=U64(21); (void)execute(insert_session,p,7,3819);
    session_values(p,user); p[5]=U64(10); (void)execute(insert_session,p,7,3819);
    session_values(p,user); p[2]=U64(2); (void)execute(insert_session,p,7,3819);
    session_values(p,user); p[2]=U64(2); p[5]=U64(9); (void)execute(insert_session,p,7,3819);
    session_values(p,user); p[2]=U64(2); p[5]=U64(10); (void)execute(insert_session,p,7,0);
    session_values(p,user); p[2]=U64(2); p[5]=U64(21); (void)execute(insert_session,p,7,0);
    session_values(p,user); p[3]=U64(UINT64_MAX-1); p[4]=U64(UINT64_MAX); p[6]=U64(UINT64_MAX); (void)execute(insert_session,p,7,0);
    scalar("SELECT CONCAT(issued_at_ms,'|',expires_at_ms,'|',last_seen_at_ms,'|',revoked_at_ms IS NULL) FROM sessions WHERE expires_at_ms=18446744073709551615","18446744073709551614|18446744073709551615|18446744073709551615|1");
    session_values(p,user); p[3]=U64(0); p[4]=U64(1); p[6]=U64(0); (void)execute(insert_session,p,7,0);
    for(size_t i=0;i<7;++i) { session_values(p,user); p[i]=NIL; (void)execute(insert_session,p,7,i==5 ? 0 : 1048); }
    session_values(p,UINT64_MAX); (void)execute(insert_session,p,7,1452);
    vireo_mysql_parameter_t id=U64(user);
    (void)execute("DELETE FROM users WHERE id=?",&id,1,1451);
    (void)execute("UPDATE users SET id=18446744073709551615 WHERE id=?",&id,1,1451);
    /* 禁用用户和已到期ACTIVE行仍是合法存储；授权判断属于后续业务。 */
    (void)execute("UPDATE users SET status=2 WHERE id=?",&id,1,0);
    scalar("SELECT COUNT(*)>0 FROM sessions JOIN users ON users.id=sessions.user_id WHERE users.status=2 AND sessions.status=1 AND sessions.expires_at_ms<=20","1");
    scalar("SELECT COUNT(*) FROM sessions WHERE user_id=18446744073709551615","0");
    scalar("SELECT COUNT(*) FROM users WHERE username_key=_binary'identity'","1");
    printf("PASS FK generic-code form: %zu, SQLSTATE23000, rejected writes preserve rows\n",generic_fk);
    puts("PASS sessions: binary32 incl NUL/trailing/allzero,31/33 rejection,status/revocation/expiry/seen/null/uint64 boundaries,FK insert/delete/update");
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
    const vireo_mysql_migration_t *catalog=NULL; size_t count=0; CHECK(vireo_mysql_schema_catalog(&catalog,&count));
    assert(count==8); count=1; /* 独立保留v1认证结构验证，不应用后续版本。 */
    vireo_mysql_migration_report_t report; vireo_mysql_migration_error_t error;
    CHECK(vireo_mysql_migration_apply(thread,&options,catalog,count,&report,&error));
    assert(report.ready && report.connection_closed && report.applied_before==0 && report.applied_after==1 && report.steps_completed==2 && report.migrations_applied==1 && report.write_attempted);
    CHECK(vireo_mysql_connection_open(thread,&options,&connection,NULL)); metadata();
    vireo_password_policy_t policy=VIREO_PASSWORD_POLICY_DEFAULT;
    static const char test_password[]="schema-test-password";
    CHECK(vireo_password_hash_create(&policy,test_password,sizeof(test_password)-1,phc,sizeof(phc),&phc_length));
    uint64_t user=users(); credentials(user); sessions(user);
    scalar("SELECT CONCAT(version,'|',state,'|',HEX(checksum)) FROM vireo_schema_migrations","1|1|58C6116C0920294129F40AFE777C4E3F616B4532393EF09B7FDDBC4822F688BE");
    /* 重复迁移不能重放DDL或丢弃数据；记录精确行数后比较。 */
    vireo_mysql_statement_t *s=query("SELECT CONCAT((SELECT COUNT(*) FROM users),'|',(SELECT COUNT(*) FROM sessions))");
    vireo_mysql_fetch_outcome_t outcome; CHECK(vireo_mysql_statement_fetch(thread,s,&outcome,NULL)); assert(outcome==VIREO_MYSQL_FETCH_ROW);
    vireo_mysql_cell_view_t cell; CHECK(vireo_mysql_statement_column(thread,s,0,&cell)); assert(!cell.is_null && cell.length<64);
    char counts[64]; memcpy(counts,cell.data,cell.length); counts[cell.length]=0; done(&s);
    CHECK(vireo_mysql_migration_apply(thread,&options,catalog,count,&report,&error));
    assert(report.ready && report.connection_closed && report.applied_before==1 && report.applied_after==1 && !report.steps_completed && !report.write_attempted && !report.migrations_applied);
    scalar("SELECT CONCAT((SELECT COUNT(*) FROM users),'|',(SELECT COUNT(*) FROM sessions))",counts);
    scalar("SELECT HEX(checksum) FROM vireo_schema_migrations","58C6116C0920294129F40AFE777C4E3F616B4532393EF09B7FDDBC4822F688BE");
    CHECK(vireo_mysql_connection_destroy(thread,&connection)); CHECK(vireo_mysql_thread_detach(&thread)); CHECK(vireo_mysql_runtime_destroy(&runtime));
    assert(fd_count()==before); memset(password,0,sizeof(password)); memset(phc,0,sizeof(phc));
    printf("PASS schema repeat preserves rows/hash, %zu rejected illegal writes; owners/runtime/FD balanced %zu -> %zu\n",rejected,before,fd_count());
    return 0;
}
