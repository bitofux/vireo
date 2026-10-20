/*
 * PROJECT : VIREO
 * FILE    : test_mysql_migration_real.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-18
 * BRIEF   : 隔离真实MySQL验证迁移历史、dirty、结构、锁及资源退出。
 */
#define _POSIX_C_SOURCE 200809L
#include "mysql_migration_internal.h"
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(call,want) do { errno=EDOM; vireo_result_t actual=(call); if(actual!=(want)) { fprintf(stderr,"line %d result %d expected %d\n",__LINE__,(int)actual,(int)(want)); abort(); } assert(errno==EDOM); } while(0)
#define STEP(s) {s,sizeof(s)-1}
static const vireo_mysql_migration_step_t first[]={STEP("CREATE TABLE migration_values(id BIGINT UNSIGNED PRIMARY KEY) ENGINE=InnoDB"),STEP("CREATE INDEX migration_id ON migration_values(id)")};
static const vireo_mysql_migration_step_t second[]={STEP("ALTER TABLE migration_values ADD COLUMN note VARBINARY(32)")};
static const vireo_mysql_migration_step_t third[]={STEP("ALTER TABLE migration_values ADD COLUMN flag INT NOT NULL DEFAULT 0")};
static const vireo_mysql_migration_t plan[]={{1,first,2},{2,second,1},{3,third,1}};
static vireo_mysql_statement_limits_t limits={4,16,1024,4096,262144};
static vireo_mysql_thread_t *thread;
static vireo_mysql_connection_t *control;
static vireo_mysql_migration_report_t report;
static vireo_mysql_migration_error_t error;
static vireo_mysql_statement_t *query(const char *sql,const vireo_mysql_parameter_t *p,size_t n)
{
    vireo_mysql_statement_t *s=NULL; vireo_mysql_execution_t ex;
    vireo_mysql_error_t e={0};
    errno=EDOM;
    vireo_result_t r=vireo_mysql_statement_prepare(thread,control,sql,strlen(sql),&limits,&s,&e);
    assert(errno==EDOM);
    if(r!=VIREO_OK) { fprintf(stderr,"control prepare result %d mysql %u SQL %s\n",(int)r,e.mysql_code,sql); abort(); }
    CHECK(vireo_mysql_statement_execute(thread,s,p,n,&ex,NULL),VIREO_OK); return s;
}
static void command(const char *sql)
{
    vireo_mysql_statement_t *s=query(sql,NULL,0);
    CHECK(vireo_mysql_statement_destroy(thread,&s,NULL),VIREO_OK); assert(!s);
}
static void scalar(const char *sql,const char *want)
{
    vireo_mysql_statement_t *s=query(sql,NULL,0); vireo_mysql_fetch_outcome_t outcome;
    CHECK(vireo_mysql_statement_fetch(thread,s,&outcome,NULL),VIREO_OK); assert(outcome==VIREO_MYSQL_FETCH_ROW);
    vireo_mysql_cell_view_t cell; CHECK(vireo_mysql_statement_column(thread,s,0,&cell),VIREO_OK);
    assert(!cell.is_null && cell.length==strlen(want) && !memcmp(cell.data,want,cell.length));
    CHECK(vireo_mysql_statement_fetch(thread,s,&outcome,NULL),VIREO_OK); assert(outcome==VIREO_MYSQL_FETCH_DONE);
    CHECK(vireo_mysql_statement_destroy(thread,&s,NULL),VIREO_OK);
}
static void reset(void)
{
    command("DROP TABLE IF EXISTS vireo_schema_migrations");
    command("DROP TABLE IF EXISTS migration_values");
    command("DROP TABLE IF EXISTS migration_anchor");
}
static void apply(const vireo_mysql_connection_options_t *o,const vireo_mysql_migration_t *m,size_t n,vireo_result_t want)
{
    CHECK(vireo_mysql_migration_apply(thread,o,m,n,&report,&error),want);
    assert(report.connection_closed && report.ready==(want==VIREO_OK));
    if(want!=VIREO_OK) { assert(error.stage!=VIREO_MYSQL_MIGRATION_STAGE_NONE); }
}
static void normal(const vireo_mysql_connection_options_t *o)
{
    reset(); apply(o,plan,2,VIREO_OK);
    assert(report.history_validated && report.applied_before==0 && report.applied_after==2 && report.migrations_applied==2 && report.steps_completed==3 && report.write_attempted);
    scalar("SELECT COUNT(*) FROM vireo_schema_migrations WHERE state=1","2");
    apply(o,plan,2,VIREO_OK); assert(report.applied_before==2 && !report.steps_completed && !report.write_attempted);
    apply(o,plan,3,VIREO_OK); assert(report.applied_after==3 && report.steps_completed==1 && report.migrations_applied==1);
    apply(o,plan,2,VIREO_RESULT_DATABASE); assert(error.issue==VIREO_MYSQL_MIGRATION_ISSUE_VERSION_AHEAD && report.failed_version==3 && !report.write_attempted);
    vireo_mysql_migration_step_t altered[2]={first[0],STEP("CREATE INDEX migration_id ON migration_values(id) ")};
    vireo_mysql_migration_t changed[3]={plan[0],plan[1],plan[2]}; changed[0].steps=altered;
    apply(o,changed,3,VIREO_RESULT_DATABASE); assert(error.issue==VIREO_MYSQL_MIGRATION_ISSUE_CHECKSUM && !report.write_attempted);
    command("UPDATE vireo_schema_migrations SET checksum=REPEAT(CHAR(0),32) WHERE version=1");
    apply(o,plan,3,VIREO_RESULT_DATABASE); assert(error.issue==VIREO_MYSQL_MIGRATION_ISSUE_CHECKSUM);
    command("DELETE FROM vireo_schema_migrations WHERE version=1");
    apply(o,plan,3,VIREO_RESULT_DATABASE); assert(error.issue==VIREO_MYSQL_MIGRATION_ISSUE_HISTORY_SHAPE);
    puts("PASS real migration: new/repeat/append, exact SQL checksum, ahead and gap rejection");
}
static void dirty(const vireo_mysql_connection_options_t *o)
{
    reset(); const vireo_mysql_migration_step_t bad[]={first[0],STEP("ALTER TABLE absent_table ADD COLUMN value INT")};
    const vireo_mysql_migration_t m={1,bad,2};
    apply(o,&m,1,VIREO_RESULT_DATABASE); assert(error.stage==VIREO_MYSQL_MIGRATION_STAGE_STEP && error.database.mysql_code==1146);
    assert(report.failed_version==1 && report.failed_step==2 && report.steps_completed==1 && report.applied_after==0);
    scalar("SELECT state FROM vireo_schema_migrations WHERE version=1","0");
    scalar("SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='migration_values'","1");
    apply(o,&m,1,VIREO_RESULT_DATABASE); assert(error.issue==VIREO_MYSQL_MIGRATION_ISSUE_DIRTY && !report.steps_completed && !report.write_attempted);
    puts("PASS real migration: partial DDL persists, dirty survives, next apply refuses replay");
}
static void shapes(const vireo_mysql_connection_options_t *o)
{
    reset(); command("CREATE TABLE migration_values(id INT) ENGINE=InnoDB");
    apply(o,plan,2,VIREO_RESULT_DATABASE); assert(error.issue==VIREO_MYSQL_MIGRATION_ISSUE_UNTRACKED_SCHEMA && !report.write_attempted);
    static const char *const variations[]={
        "ALTER TABLE vireo_schema_migrations MODIFY COLUMN checksum VARBINARY(32) NOT NULL",
        "ALTER TABLE vireo_schema_migrations MODIFY COLUMN state TINYINT UNSIGNED NULL",
        "ALTER TABLE vireo_schema_migrations ADD COLUMN unexpected INT",
        "ALTER TABLE vireo_schema_migrations ADD INDEX unexpected(state)",
        "ALTER TABLE vireo_schema_migrations ADD CONSTRAINT state_check CHECK(state IN(0,1))",
        "ALTER TABLE vireo_schema_migrations PARTITION BY HASH(version) PARTITIONS 2",
        "ALTER TABLE vireo_schema_migrations ENGINE=MEMORY"};
    for(size_t i=0;i<sizeof(variations)/sizeof(variations[0]);++i) {
        reset(); apply(o,NULL,0,VIREO_OK); command(variations[i]);
        apply(o,plan,2,VIREO_RESULT_DATABASE); assert(error.issue==VIREO_MYSQL_MIGRATION_ISSUE_METADATA_SHAPE && !report.write_attempted);
    }
    /* 该不兼容结构由fixture文本客户端建立；CREATE TRIGGER不能通过prepared执行。 */
    vireo_mysql_connection_options_t trigger_options=*o; trigger_options.database="vireo_migration_trigger";
    apply(&trigger_options,NULL,0,VIREO_RESULT_DATABASE);
    assert(error.issue==VIREO_MYSQL_MIGRATION_ISSUE_METADATA_SHAPE && !report.write_attempted);
    reset(); apply(o,NULL,0,VIREO_OK); command("CREATE TABLE migration_anchor(id INT UNSIGNED PRIMARY KEY) ENGINE=InnoDB");
    command("ALTER TABLE vireo_schema_migrations ADD CONSTRAINT migration_fk FOREIGN KEY(version) REFERENCES migration_anchor(id)");
    apply(o,plan,2,VIREO_RESULT_DATABASE); assert(error.issue==VIREO_MYSQL_MIGRATION_ISSUE_METADATA_SHAPE);
    reset(); apply(o,NULL,0,VIREO_OK); command("CREATE TABLE migration_values(id INT) ENGINE=InnoDB");
    apply(o,plan,2,VIREO_RESULT_DATABASE); assert(error.issue==VIREO_MYSQL_MIGRATION_ISSUE_UNTRACKED_SCHEMA);
    puts("PASS real migration: unknown baseline, empty ledger, column/index/check/trigger/FK/partition/engine shape rejection");
}
typedef struct worker { vireo_mysql_runtime_t *runtime; const vireo_mysql_connection_options_t *options; } worker_t;
static void *worker_run(void *arg)
{
    worker_t *w=arg; vireo_mysql_thread_t *t=NULL; vireo_mysql_migration_report_t out; vireo_mysql_migration_error_t e;
    CHECK(vireo_mysql_thread_attach(w->runtime,&t,NULL),VIREO_OK);
    CHECK(vireo_mysql_migration_apply(t,w->options,NULL,0,&out,&e),VIREO_RESULT_BUSY);
    assert(out.connection_closed && !out.write_attempted && !out.ready);
    CHECK(vireo_mysql_thread_detach(&t),VIREO_OK); return NULL;
}
static void locking(vireo_mysql_runtime_t *runtime,const vireo_mysql_connection_options_t *o)
{
    reset(); char lock[63],sql[128]; CHECK(vireo_mysql_migration_lock_name(o->database,lock),VIREO_OK);
    int n=snprintf(sql,sizeof(sql),"SELECT GET_LOCK('%s',0)",lock); assert(n>0 && (size_t)n<sizeof(sql)); scalar(sql,"1");
    command("SET @migration_control_marker=47");
    worker_t w={runtime,o}; pthread_t id; assert(pthread_create(&id,NULL,worker_run,&w)==0); assert(pthread_join(id,NULL)==0);
    vireo_mysql_connection_options_t other=*o; other.database="vireo_migration_other";
    apply(&other,NULL,0,VIREO_OK); /* 另一库的锁身份独立。 */
    n=snprintf(sql,sizeof(sql),"SELECT RELEASE_LOCK('%s')",lock); assert(n>0 && (size_t)n<sizeof(sql)); scalar(sql,"1");
    apply(o,plan,2,VIREO_OK); apply(o,plan,2,VIREO_OK);
    scalar("SELECT @migration_control_marker","47");
    n=snprintf(sql,sizeof(sql),"SELECT IS_FREE_LOCK('%s')",lock); assert(n>0 && (size_t)n<sizeof(sql)); scalar(sql,"1");
    puts("PASS real migration: independent OS guard/session BUSY, different schema, release and caller session unchanged");
}
static size_t fd_count(void)
{
    DIR *d=opendir("/proc/self/fd"); assert(d); size_t count=0; struct dirent *p;
    while((p=readdir(d))) { if(strcmp(p->d_name,".") && strcmp(p->d_name,"..")) { ++count; } }
    assert(closedir(d)==0); return count;
}
int main(int argc,char **argv)
{
    assert(setvbuf(stdout,NULL,_IONBF,0)==0);
    assert(argc==5); char password[1026]; FILE *f=fopen(argv[3],"r"); assert(f);
    assert(fgets(password,(int)sizeof(password),f) && fclose(f)==0); password[strcspn(password,"\n")]=0;
    struct sigaction sa={0}; sa.sa_handler=SIG_IGN; assert(sigemptyset(&sa.sa_mask)==0 && sigaction(SIGPIPE,&sa,NULL)==0);
    vireo_mysql_runtime_t *runtime=NULL; CHECK(vireo_mysql_runtime_create(&runtime,NULL),VIREO_OK);
    CHECK(vireo_mysql_thread_attach(runtime,&thread,NULL),VIREO_OK); size_t before=fd_count();
    vireo_mysql_connection_options_t options_real={argv[1],argv[2],password,argv[4],3,3,3};
    CHECK(vireo_mysql_connection_open(thread,&options_real,&control,NULL),VIREO_OK);
    normal(&options_real); dirty(&options_real); shapes(&options_real); locking(runtime,&options_real);
    CHECK(vireo_mysql_connection_destroy(thread,&control),VIREO_OK);
    CHECK(vireo_mysql_thread_detach(&thread),VIREO_OK); CHECK(vireo_mysql_runtime_destroy(&runtime),VIREO_OK);
    assert(fd_count()==before); memset(password,0,sizeof(password));
    printf("PASS migration real owners/runtime/FD balanced %zu -> %zu\n",before,fd_count()); return 0;
}
