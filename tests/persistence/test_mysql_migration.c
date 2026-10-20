/*
 * PROJECT : VIREO
 * FILE    : test_mysql_migration.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-18
 * BRIEF   : 公共资源边界模型，覆盖故障、提交不确定及owner退出。
 */
#include "mysql_migration_internal.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int identity;
static vireo_mysql_thread_t *guard=(vireo_mysql_thread_t *)&identity;
static vireo_mysql_connection_options_t options={"/tmp/model.sock","user","password","model_db",1,1,1};
static vireo_mysql_migration_step_t steps[]={{"CREATE TABLE a(id INT)",22},{"ALTER TABLE a ADD x INT",23}};
static vireo_mysql_migration_t plan[]={{1,steps,1},{2,steps+1,1}};
static bool exists,conn,stmt,held;
static uint32_t versions[129],states[129];
static unsigned char digests[129][32];
static size_t ledger,ddl,opens,closes,operation,fail_at,fail_seen;
static int uncertain; /* 1 dirty已提交但execute失败，2 applied已提交但execute失败。 */
static bool busy,wrong_database,extra_row,bad_marker,bad_result,zero_affected;
static bool hash_failure,cleanup_fault;
static const char *query;
static size_t columns,markers,row_count,cursor;
static vireo_mysql_cell_view_t rows[130][6];
static char integers[130][2][16];
static bool injected(vireo_mysql_error_t *e)
{
    ++operation;
    if (operation!=fail_at) { return false; }
    ++fail_seen;
    if(e) { *e=(vireo_mysql_error_t){.stage=VIREO_MYSQL_STAGE_STATEMENT_EXECUTE,.mysql_code=2013,.sqlstate="HY000"}; }
    errno=EIO; return true;
}
static vireo_mysql_cell_view_t string(const char *s)
{
    return (vireo_mysql_cell_view_t){(const unsigned char *)s,s ? strlen(s) : 0,s==NULL};
}
static void value(size_t row,size_t col,const char *s) { rows[row][col]=string(s); }
static vireo_result_t open_conn(vireo_mysql_thread_t *t,const vireo_mysql_connection_options_t *o,
    vireo_mysql_connection_t **out,vireo_mysql_error_t *e)
{
    assert(t==guard && o==&options && !conn && !*out); ++opens;
    if(injected(e)) { return VIREO_RESULT_DATABASE; }
    conn=true; *out=(vireo_mysql_connection_t *)&identity; return VIREO_OK;
}
static vireo_result_t close_conn(vireo_mysql_thread_t *t,vireo_mysql_connection_t **owner)
{
    assert(t==guard && conn && !stmt && *owner); conn=false; held=false; *owner=NULL; ++closes; return VIREO_OK;
}
static vireo_result_t prepare(vireo_mysql_thread_t *t,vireo_mysql_connection_t *c,const char *sql,size_t n,
    const vireo_mysql_statement_limits_t *limits,vireo_mysql_statement_t **out,vireo_mysql_error_t *e)
{
    assert(t==guard && c && conn && !stmt && !*out && n && limits->max_memory_bytes==262144);
    if(injected(e)) { return VIREO_RESULT_DATABASE; }
    query=sql; columns=0; markers=0;
    if(!strncmp(query,"SELECT",6)) {
        columns=1;
        if(strstr(query,"TABLE_TYPE")) { columns=3; }
        else if(strstr(query,"COLUMN_NAME,COLUMN_TYPE") || strstr(query,"INDEX_NAME,NON_UNIQUE")) { columns=6; }
        else if(strstr(query,"SELECT version,checksum,state")) { columns=3; }
    }
    for(size_t i=0;i<n;++i) { if(query[i]=='?') { ++markers; } }
    if(bad_marker && !strncmp(query,"CREATE TABLE a",14)) { markers=1; }
    if(bad_result && !strncmp(query,"CREATE TABLE a",14)) { columns=1; }
    if(markers>limits->max_parameters || columns>limits->max_columns) { return VIREO_RESULT_RANGE; }
    stmt=true; *out=(vireo_mysql_statement_t *)&identity; return VIREO_OK;
}
static vireo_result_t inspect(vireo_mysql_thread_t *t,const vireo_mysql_statement_t *s,vireo_mysql_statement_info_t *info)
{
    assert(t==guard && s && stmt); if(injected(NULL)) { return VIREO_RESULT_DATABASE; }
    *info=(vireo_mysql_statement_info_t){.column_count=columns,.parameter_count=markers}; return VIREO_OK;
}
static vireo_result_t execute(vireo_mysql_thread_t *t,vireo_mysql_statement_t *s,const vireo_mysql_parameter_t *p,
    size_t count,vireo_mysql_execution_t *ex,vireo_mysql_error_t *e)
{
    assert(t==guard && s && stmt && count==markers); memset(rows,0,sizeof(rows)); cursor=0; row_count=0;
    *ex=(vireo_mysql_execution_t){.execution_started=true,.has_result=columns!=0,.affected_rows=1};
    if(injected(e)) { return VIREO_RESULT_DATABASE; }
    if(!strcmp(query,"SELECT DATABASE()")) { row_count=1; value(0,0,wrong_database ? "other" : "model_db"); }
    else if(strstr(query,"GET_LOCK")) {
        assert(p && p[0].value.span.length==62); row_count=1; value(0,0,busy ? "0" : "1"); held=!busy;
    } else if(strstr(query,"RELEASE_LOCK")) { assert(held); held=false; row_count=1; value(0,0,"1"); }
    else if(strstr(query,"SELECT TABLE_TYPE")) {
        row_count=exists ? 1 : 0; value(0,0,"BASE TABLE"); value(0,1,"InnoDB"); value(0,2,"vireo_schema_migrations");
    } else if(strstr(query,"CREATE TABLE IF NOT EXISTS")) { assert(held); exists=true; }
    else if(strstr(query,"COLUMN_NAME,COLUMN_TYPE")) {
        row_count=3; const char *names[]={"version","checksum","state"},*types[]={"int unsigned","binary(32)","tinyint unsigned"};
        for(size_t i=0;i<3;++i) { value(i,0,names[i]); value(i,1,types[i]); value(i,2,"NO"); value(i,3,NULL); value(i,4,""); value(i,5,""); }
    } else if(strstr(query,"INDEX_NAME,NON_UNIQUE")) {
        row_count=1; const char *values[]={"PRIMARY","0","1","version",NULL,"BTREE"};
        for(size_t i=0;i<6;++i) { value(0,i,values[i]); }
    } else if(strstr(query,"SELECT COUNT(*)")) { row_count=1; value(0,0,"0"); }
    else if(strstr(query,"SELECT version,checksum,state")) {
        row_count=ledger;
        for(size_t i=0;i<ledger;++i) {
            assert(snprintf(integers[i][0],16,"%u",versions[i])>0); assert(snprintf(integers[i][1],16,"%u",states[i])>0);
            value(i,0,integers[i][0]); value(i,2,integers[i][1]); rows[i][1]=(vireo_mysql_cell_view_t){digests[i],32,false};
        }
    } else if(strstr(query,"INSERT INTO vireo_schema_migrations")) {
        assert(held && ledger<128); versions[ledger]=(uint32_t)p[0].value.u64; states[ledger]=0;
        memcpy(digests[ledger],p[1].value.span.data,32); ++ledger;
        if(uncertain==1) { e->mysql_code=2013; return VIREO_RESULT_DATABASE; }
    } else if(strstr(query,"UPDATE vireo_schema_migrations")) {
        assert(held && ledger && versions[ledger-1]==p[0].value.u64);
        if(zero_affected) { ex->affected_rows=0; }
        else { states[ledger-1]=1; }
        if(uncertain==2) { e->mysql_code=2013; return VIREO_RESULT_DATABASE; }
    } else {
        assert(held && ledger && !states[ledger-1]);
        if(uncertain==3) { e->mysql_code=2013; return VIREO_RESULT_DATABASE; }
        ++ddl;
    }
    if(extra_row && columns==1) { row_count=2; rows[1][0]=rows[0][0]; }
    return VIREO_OK;
}
static vireo_result_t fetch(vireo_mysql_thread_t *t,vireo_mysql_statement_t *s,vireo_mysql_fetch_outcome_t *out,vireo_mysql_error_t *e)
{
    assert(t==guard && s && stmt); if(injected(e)) { return VIREO_RESULT_DATABASE; }
    if(cursor<row_count) { ++cursor; *out=VIREO_MYSQL_FETCH_ROW; } else { *out=VIREO_MYSQL_FETCH_DONE; }
    return VIREO_OK;
}
static vireo_result_t column(vireo_mysql_thread_t *t,const vireo_mysql_statement_t *s,size_t i,vireo_mysql_cell_view_t *v)
{
    assert(t==guard && s && cursor && i<columns); if(injected(NULL)) { return VIREO_RESULT_DATABASE; }
    *v=rows[cursor-1][i]; return VIREO_OK;
}
static vireo_result_t destroy(vireo_mysql_thread_t *t,vireo_mysql_statement_t **s,vireo_mysql_error_t *e)
{
    assert(t==guard && *s && stmt); stmt=false; *s=NULL;
    if(cleanup_fault && !strncmp(query,"CREATE TABLE a",14)) { e->mysql_code=2027; return VIREO_RESULT_DATABASE; }
    return injected(e) ? VIREO_RESULT_DATABASE : VIREO_OK;
}
static vireo_result_t hash(const vireo_mysql_migration_t *m,unsigned char out[32])
{
    return hash_failure ? VIREO_RESULT_NO_MEMORY : vireo_mysql_migration_hash(m,out);
}
static const vireo_mysql_migration_ops_t ops={open_conn,close_conn,prepare,inspect,execute,fetch,column,destroy,hash};
static vireo_mysql_migration_report_t report;
static vireo_mysql_migration_error_t error;
static vireo_result_t apply(const vireo_mysql_migration_t *m,size_t n)
{
    errno=EDOM;
    vireo_result_t r=vireo_mysql_migration_apply_with_ops(guard,&options,m,n,&report,&error,&ops);
    assert(errno==EDOM && !conn && !stmt && !held && report.ready==(r==VIREO_OK)); return r;
}
static void reset(void)
{
    assert(!conn && !stmt); exists=false; ledger=ddl=opens=closes=operation=fail_at=fail_seen=0;
    uncertain=0; busy=wrong_database=extra_row=bad_marker=bad_result=zero_affected=false;
    hash_failure=cleanup_fault=false;
    steps[0].sql_length=strlen(steps[0].sql); steps[1].sql_length=strlen(steps[1].sql);
}
int main(void)
{
    reset(); assert(apply(plan,2)==VIREO_OK); assert(report.history_validated && report.applied_after==2 && report.steps_completed==2 && report.connection_closed);
    size_t boundaries=operation; assert(ddl==2 && ledger==2 && opens==closes);
    assert(apply(plan,2)==VIREO_OK && !report.steps_completed && !report.write_attempted && ddl==2);
    assert(apply(plan,1)==VIREO_RESULT_DATABASE && error.issue==VIREO_MYSQL_MIGRATION_ISSUE_VERSION_AHEAD);
    digests[0][0]^=1; assert(apply(plan,2)==VIREO_RESULT_DATABASE && error.issue==VIREO_MYSQL_MIGRATION_ISSUE_CHECKSUM); digests[0][0]^=1;
    versions[1]=4; assert(apply(plan,2)==VIREO_RESULT_DATABASE && error.issue==VIREO_MYSQL_MIGRATION_ISSUE_HISTORY_SHAPE);
    versions[1]=2; states[0]=2;
    assert(apply(plan,2)==VIREO_RESULT_DATABASE && error.issue==VIREO_MYSQL_MIGRATION_ISSUE_HISTORY_SHAPE);
    for(size_t i=1;i<=boundaries;++i) {
        reset(); fail_at=i; assert(apply(plan,2)!=VIREO_OK); assert(fail_seen && opens==closes+(closes==0 ? 1U : 0U));
        assert(report.steps_completed==ddl);
        assert(report.migrations_applied==(ledger ? states[0]+(ledger==2 ? states[1] : 0) : 0));
    }
    reset(); uncertain=1; assert(apply(plan,2)==VIREO_RESULT_DATABASE && ledger==1 && !states[0] && !ddl);
    uncertain=0; assert(apply(plan,2)==VIREO_RESULT_DATABASE && error.issue==VIREO_MYSQL_MIGRATION_ISSUE_DIRTY && !ddl);
    reset(); uncertain=2; assert(apply(plan,1)==VIREO_RESULT_DATABASE && states[0]==1 && ddl==1 && report.applied_after==0);
    uncertain=0; assert(apply(plan,1)==VIREO_OK && report.applied_before==1 && !report.steps_completed && ddl==1);
    reset(); uncertain=3; cleanup_fault=true;
    assert(apply(plan,1)==VIREO_RESULT_DATABASE && report.failed_step==1 && report.failed_version==1);
    assert(error.stage==VIREO_MYSQL_MIGRATION_STAGE_STEP && error.database.mysql_code==2013 &&
        error.cleanup_stage==VIREO_MYSQL_MIGRATION_STAGE_CLOSE && error.cleanup_database.mysql_code==2027);
    reset(); hash_failure=true; assert(apply(plan,2)==VIREO_RESULT_NO_MEMORY && !opens && error.stage==VIREO_MYSQL_MIGRATION_STAGE_HASH);
    reset(); busy=true; assert(apply(plan,2)==VIREO_RESULT_BUSY && !exists && !report.write_attempted);
    reset(); wrong_database=true; assert(apply(plan,2)==VIREO_RESULT_DATABASE && !exists);
    reset(); extra_row=true; assert(apply(plan,2)==VIREO_RESULT_DATABASE && !exists);
    reset(); bad_marker=true; assert(apply(plan,2)==VIREO_RESULT_RANGE && !ddl && ledger==1 && !states[0]);
    reset(); bad_result=true; assert(apply(plan,2)==VIREO_RESULT_RANGE && !ddl);
    reset(); zero_affected=true; assert(apply(plan,2)==VIREO_RESULT_DATABASE && !states[0] && ddl==1);
    reset(); assert(apply(NULL,0)==VIREO_OK && exists && !ledger && !ddl);
    reset(); assert(apply(plan,129)==VIREO_RESULT_RANGE && !opens);
    assert(apply(NULL,1)==VIREO_RESULT_INVALID_ARGUMENT && !opens);
    vireo_mysql_migration_t invalid={2,steps,1}; assert(apply(&invalid,1)==VIREO_RESULT_INVALID_ARGUMENT);
    invalid=(vireo_mysql_migration_t){1,steps,0}; assert(apply(&invalid,1)==VIREO_RESULT_INVALID_ARGUMENT);
    invalid.step_count=65; assert(apply(&invalid,1)==VIREO_RESULT_RANGE);
    const char *db=options.database; options.database="Upper"; assert(apply(plan,2)==VIREO_RESULT_INVALID_ARGUMENT); options.database=db;
    vireo_mysql_migration_step_t bad={"x",SIZE_MAX}; invalid=(vireo_mysql_migration_t){1,&bad,1}; assert(apply(&invalid,1)==VIREO_RESULT_RANGE);
    bad=(vireo_mysql_migration_step_t){"x\0y",3}; assert(apply(&invalid,1)==VIREO_RESULT_INVALID_ARGUMENT);
    reset();
    assert(vireo_mysql_migration_apply_with_ops(NULL,&options,plan,2,&report,&error,&ops)==VIREO_RESULT_INVALID_ARGUMENT && !opens);
    assert(vireo_mysql_migration_apply_with_ops(guard,&options,plan,2,NULL,&error,&ops)==VIREO_RESULT_INVALID_ARGUMENT && !opens);
    vireo_mysql_migration_step_t many_steps[64]; vireo_mysql_migration_t many_versions[17];
    for(size_t i=0;i<64;++i) { many_steps[i]=(vireo_mysql_migration_step_t){"x",1}; }
    for(size_t i=0;i<17;++i) { many_versions[i]=(vireo_mysql_migration_t){(uint32_t)i+1,many_steps,64}; }
    assert(apply(many_versions,17)==VIREO_RESULT_RANGE && !opens);
    many_versions[1].step_count=SIZE_MAX;
    assert(apply(many_versions,2)==VIREO_RESULT_OVERFLOW && !opens);
    many_versions[1].step_count=64;
    vireo_mysql_migration_step_t overflow_bytes[]={{"x",1},{"x",SIZE_MAX}};
    invalid=(vireo_mysql_migration_t){1,overflow_bytes,2};
    assert(apply(&invalid,1)==VIREO_RESULT_OVERFLOW && !opens);
    static char large_sql[65536]; memset(large_sql,'x',sizeof(large_sql));
    for(size_t i=0;i<64;++i) { many_steps[i]=(vireo_mysql_migration_step_t){large_sql,sizeof(large_sql)}; }
    assert(apply(many_versions,2)==VIREO_RESULT_RANGE && !opens);
    /* 独立固定向量由Python hashlib按公开编码预先生成，非调用本实现构造期望。 */
    unsigned char digest[32]; char hex[65]; static const char digits[]="0123456789abcdef";
    assert(vireo_mysql_migration_hash(plan,digest)==VIREO_OK);
    for(size_t i=0;i<32;++i) { hex[i*2]=digits[digest[i]>>4]; hex[i*2+1]=digits[digest[i]&15]; } hex[64]=0;
    assert(!strcmp(hex,"f758c0d1df84224d5a9beecd4be3344eb36acac9c3161d9c056c805e08077ae4"));
    printf("PASS migration model: %zu operation failures, unknown dirty/applied commits, history/checksum/ahead, bounds, owners and errno\n",boundaries);
    return 0;
}
