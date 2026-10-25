/* PROJECT : VIREO; FILE : test_mysql_schema_directory_receipts_real.c;
 * AUTHOR : bitofux; DATE : 2026-10-23; BRIEF : v8到v9升级、真实回执DDL与边界。 */
#define _POSIX_C_SOURCE 200809L
#include <vireo/persistence/mysql_schema.h>
#include <vireo/persistence/mysql_statement.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(call) do { errno=EDOM;vireo_result_t r_=(call);if(r_!=VIREO_OK) { fprintf(stderr,"line %d result %d\n",__LINE__,(int)r_);abort(); }assert(errno==EDOM); } while(0)
#define U64(v) ((vireo_mysql_parameter_t){.kind=VIREO_MYSQL_PARAMETER_U64,.value.u64=(v)})
#define BYTES(p,n) ((vireo_mysql_parameter_t){.kind=VIREO_MYSQL_PARAMETER_BYTES,.value.span={(p),(n)}})
static vireo_mysql_thread_t *thread;
static vireo_mysql_connection_t *connection;
static const vireo_mysql_statement_limits_t limits={9,9,512,2048,65536};
static const char insert_sql[]="INSERT INTO directory_write_receipts(user_id,command,idempotency_key,format_version,request_parent_id,request_name,result_node_id,audit_id,created_at_ms) VALUES(?,?,?,?,?,?,?,?,?)";
static size_t rejected;
static vireo_mysql_statement_t *query(const char *sql)
{
    vireo_mysql_statement_t *s=NULL;vireo_mysql_execution_t ex;
    CHECK(vireo_mysql_statement_prepare(thread,connection,sql,strlen(sql),&limits,&s,NULL));
    CHECK(vireo_mysql_statement_execute(thread,s,NULL,0,&ex,NULL));assert(ex.has_result);return s;
}
static void scalar(const char *sql,const char *want)
{
    vireo_mysql_statement_t *s=query(sql);vireo_mysql_fetch_outcome_t f;vireo_mysql_cell_view_t c;
    CHECK(vireo_mysql_statement_fetch(thread,s,&f,NULL));assert(f==VIREO_MYSQL_FETCH_ROW);
    CHECK(vireo_mysql_statement_column(thread,s,0,&c));
    if(c.is_null || c.length!=strlen(want) || memcmp(c.data,want,c.length)) { fprintf(stderr,"scalar mismatch, expected %s\n",want);abort(); }
    CHECK(vireo_mysql_statement_fetch(thread,s,&f,NULL));assert(f==VIREO_MYSQL_FETCH_DONE);
    CHECK(vireo_mysql_statement_destroy(thread,&s,NULL));
}
static void command(const char *sql)
{
    vireo_mysql_statement_t *s=NULL;vireo_mysql_execution_t ex;
    CHECK(vireo_mysql_statement_prepare(thread,connection,sql,strlen(sql),&limits,&s,NULL));
    CHECK(vireo_mysql_statement_execute(thread,s,NULL,0,&ex,NULL));assert(!ex.has_result);
    CHECK(vireo_mysql_statement_destroy(thread,&s,NULL));
}
static void snapshot(char out[16384])
{
    vireo_mysql_statement_t *s=query("SELECT CONCAT_WS('|',user_id,command,HEX(idempotency_key),format_version,request_parent_id,HEX(request_name),result_node_id,audit_id,created_at_ms) FROM directory_write_receipts ORDER BY user_id,command,idempotency_key");
    size_t used=0;vireo_mysql_fetch_outcome_t f;
    for(;;) {
        CHECK(vireo_mysql_statement_fetch(thread,s,&f,NULL));if(f==VIREO_MYSQL_FETCH_DONE) { break; }assert(f==VIREO_MYSQL_FETCH_ROW);
        vireo_mysql_cell_view_t c;CHECK(vireo_mysql_statement_column(thread,s,0,&c));assert(!c.is_null && c.length<16384-used-1);
        memcpy(out+used,c.data,c.length);used+=c.length;out[used++]='\n';
    }
    out[used]=0;CHECK(vireo_mysql_statement_destroy(thread,&s,NULL));
}
static void insert(const vireo_mysql_parameter_t p[9],bool ok)
{
    char before[16384],after[16384];snapshot(before);
    vireo_mysql_statement_t *s=NULL;vireo_mysql_execution_t ex;vireo_mysql_error_t e={0};
    CHECK(vireo_mysql_statement_prepare(thread,connection,insert_sql,strlen(insert_sql),&limits,&s,NULL));
    errno=EDOM;vireo_result_t r=vireo_mysql_statement_execute(thread,s,p,9,&ex,&e);assert(errno==EDOM);
    if(ok) { assert(r==VIREO_OK && !ex.has_result && ex.affected_rows==1); }
    else { assert(r==VIREO_RESULT_DATABASE && e.mysql_code!=0);++rejected; }
    CHECK(vireo_mysql_statement_destroy(thread,&s,NULL));
    snapshot(after);if(!ok) { assert(!strcmp(before,after)); }
}
static void metadata(void)
{
    scalar("SELECT GROUP_CONCAT(CONCAT(column_name,':',column_type,':',is_nullable) ORDER BY ordinal_position SEPARATOR '|') FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name='directory_write_receipts'",
        "user_id:bigint unsigned:NO|command:smallint unsigned:NO|idempotency_key:varbinary(16):NO|format_version:smallint unsigned:NO|request_parent_id:bigint unsigned:NO|request_name:varbinary(255):NO|result_node_id:bigint unsigned:NO|audit_id:bigint unsigned:NO|created_at_ms:bigint unsigned:NO");
    scalar("SELECT COUNT(*) FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name='directory_write_receipts' AND (column_default IS NOT NULL OR extra<>'')","0");
    scalar("SELECT GROUP_CONCAT(column_name ORDER BY seq_in_index SEPARATOR ',') FROM information_schema.statistics WHERE table_schema=DATABASE() AND table_name='directory_write_receipts' AND index_name='PRIMARY'","user_id,command,idempotency_key");
    scalar("SELECT COUNT(DISTINCT index_name) FROM information_schema.statistics WHERE table_schema=DATABASE() AND table_name='directory_write_receipts'","1");
    scalar("SELECT COUNT(*) FROM information_schema.table_constraints WHERE table_schema=DATABASE() AND table_name='directory_write_receipts' AND constraint_type='CHECK' AND enforced='YES'","8");
    scalar("SELECT COUNT(*) FROM information_schema.table_constraints WHERE table_schema=DATABASE() AND table_name='directory_write_receipts' AND constraint_type='FOREIGN KEY'","0");
    scalar("SELECT COUNT(*) FROM information_schema.triggers WHERE trigger_schema=DATABASE() AND event_object_table='directory_write_receipts'","0");
}
static void boundaries(void)
{
    unsigned char key[17]={1},name[256];memset(name,'x',sizeof(name));name[0]=0xff;
    vireo_mysql_parameter_t base[9]={U64(7),U64(1027),BYTES(key,16),U64(1),U64(22),BYTES(name,255),U64(31),U64(51),U64(0)},p[9];
    insert(base,true);insert(base,false);
    for(size_t i=0;i<9;++i) {
        memcpy(p,base,sizeof(p));p[i]=(vireo_mysql_parameter_t){.kind=VIREO_MYSQL_PARAMETER_NULL};insert(p,false);
    }
    const size_t numeric[]={0,1,3,4,6,7};
    for(size_t j=0;j<sizeof(numeric)/sizeof(numeric[0]);++j) { memcpy(p,base,sizeof(p));p[numeric[j]]=U64(0);insert(p,false); }
    memcpy(p,base,sizeof(p));p[1]=U64(1028);insert(p,false);p[1]=U64(1027);p[3]=U64(2);insert(p,false);
    for(size_t n=0;n<=17;++n) { if(n==16) { continue; }memcpy(p,base,sizeof(p));p[2]=BYTES(key,n);insert(p,false); }
    unsigned char zero[16]={0};memcpy(p,base,sizeof(p));p[2]=BYTES(zero,16);insert(p,false);
    const unsigned char *bad[]={(const unsigned char *)"",(const unsigned char *)".",(const unsigned char *)"..",(const unsigned char *)"a/b",(const unsigned char *)"a\0b",name};
    const size_t n[]={0,1,2,3,3,256};
    for(size_t i=0;i<6;++i) { memcpy(p,base,sizeof(p));p[5]=BYTES(bad[i],n[i]);insert(p,false); }
    memcpy(p,base,sizeof(p));p[0]=U64(UINT64_MAX);p[4]=U64(UINT64_MAX);p[6]=U64(UINT64_MAX);p[7]=U64(UINT64_MAX);p[8]=U64(UINT64_MAX);insert(p,true);
    /* Binary identities distinguish trailing/embedded zero bytes, scoped by owner. No live FK targets exist. */
    memcpy(p,base,sizeof(p));key[15]=2;insert(p,true);key[8]=0x80;key[15]=0;insert(p,true);
    scalar("SELECT COUNT(*) FROM users","0");scalar("SELECT COUNT(*) FROM file_nodes","0");scalar("SELECT COUNT(*) FROM operation_audits","0");
    scalar("SELECT COUNT(*) FROM directory_write_receipts","4");
    char before[16384],after[16384];snapshot(before);command("SET autocommit=0");key[15]=3;insert(p,true);command("ROLLBACK");command("SET autocommit=1");snapshot(after);assert(!strcmp(before,after));
    command("SET autocommit=0");key[15]=4;insert(p,true);insert(p,false);command("ROLLBACK");command("SET autocommit=1");snapshot(after);assert(!strcmp(before,after));
}
int main(int argc,char **argv)
{
    assert(argc==5 && !setvbuf(stdout,NULL,_IONBF,0));char password[1026];FILE *f=fopen(argv[3],"r");assert(f && fgets(password,(int)sizeof(password),f) && !fclose(f));password[strcspn(password,"\n")]=0;
    struct sigaction sa={0};sa.sa_handler=SIG_IGN;assert(!sigemptyset(&sa.sa_mask) && !sigaction(SIGPIPE,&sa,NULL));
    vireo_mysql_runtime_t *runtime=NULL;CHECK(vireo_mysql_runtime_create(&runtime,NULL));CHECK(vireo_mysql_thread_attach(runtime,&thread,NULL));
    vireo_mysql_connection_options_t options={argv[1],argv[2],password,argv[4],3,3,3};
    const vireo_mysql_migration_t *catalog;size_t count;CHECK(vireo_mysql_schema_catalog(&catalog,&count));assert(count==11);count=9; /* 独立保留v8->v9原始DDL回归；v10另测。 */
    vireo_mysql_migration_report_t r;CHECK(vireo_mysql_migration_apply(thread,&options,catalog,8,&r,NULL));assert(r.ready && r.steps_completed==14 && r.applied_after==8);
    CHECK(vireo_mysql_connection_open(thread,&options,&connection,NULL));
    scalar("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name='directory_write_receipts'","0");
    CHECK(vireo_mysql_migration_apply(thread,&options,catalog,count,&r,NULL));assert(r.ready && r.applied_before==8 && r.applied_after==9 && r.migrations_applied==1 && r.steps_completed==1);
    metadata();boundaries();char before[16384],after[16384];snapshot(before);
    CHECK(vireo_mysql_migration_apply(thread,&options,catalog,count,&r,NULL));assert(r.ready && r.applied_before==9 && r.applied_after==9 && !r.write_attempted && !r.steps_completed);snapshot(after);assert(!strcmp(before,after));
    CHECK(vireo_mysql_connection_destroy(thread,&connection));CHECK(vireo_mysql_thread_detach(&thread));CHECK(vireo_mysql_runtime_destroy(&runtime));memset(password,0,sizeof(password));
    printf("PASS real v8->v9 one-step upgrade/repeat no writes; nine exact columns/PK/eight enforced checks/no FK or trigger; %zu rejected writes preserve bytes, binary/MAX/255/epoch0 and transactional rollback\n",rejected);return 0;
}
