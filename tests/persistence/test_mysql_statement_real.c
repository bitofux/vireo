#define _POSIX_C_SOURCE 200809L
#include "mysql_statement_internal.h"
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(call, want) do { errno=EDOM; vireo_result_t actual=(call); if(actual!=(want)) { fprintf(stderr,"line %d: got %d expected %d\n",__LINE__,(int)actual,(int)(want)); abort(); } assert(errno==EDOM); } while(0)
static const vireo_mysql_statement_limits_t limits={32,32,2048,128,1048576};
static size_t fd_count(void) { DIR *d=opendir("/proc/self/fd"); assert(d); size_t n=0; struct dirent *p; while((p=readdir(d))) { if(strcmp(p->d_name,".") && strcmp(p->d_name,"..")) { ++n; } } assert(closedir(d)==0); return n; }
static vireo_mysql_statement_t *prepare(vireo_mysql_thread_t *t,vireo_mysql_connection_t *c,const char *sql) {
    vireo_mysql_statement_t *s=NULL; vireo_mysql_error_t e;
    CHECK(vireo_mysql_statement_prepare(t,c,sql,strlen(sql),&limits,&s,&e),VIREO_OK); return s;
}
static vireo_mysql_execution_t execute(vireo_mysql_thread_t *t,vireo_mysql_statement_t *s,const vireo_mysql_parameter_t *p,size_t n) {
    vireo_mysql_execution_t report; vireo_mysql_error_t e;
    errno=EDOM; vireo_result_t r=vireo_mysql_statement_execute(t,s,p,n,&report,&e);
    if(r!=VIREO_OK) { fprintf(stderr,"execute result=%d stage=%d code=%u\n",(int)r,(int)e.stage,e.mysql_code); abort(); }
    assert(errno==EDOM && report.execution_started); return report;
}
static void fetch(vireo_mysql_thread_t *t,vireo_mysql_statement_t *s,vireo_mysql_fetch_outcome_t want) {
    vireo_mysql_fetch_outcome_t got; vireo_mysql_error_t e;
    CHECK(vireo_mysql_statement_fetch(t,s,&got,&e),VIREO_OK); assert(got==want);
}
static void cell(vireo_mysql_thread_t *t,vireo_mysql_statement_t *s,size_t i,const void *data,size_t length,bool null) {
    vireo_mysql_cell_view_t c;
    CHECK(vireo_mysql_statement_column(t,s,i,&c),VIREO_OK);
    assert(c.is_null==null && c.length==length);
    if(null) { assert(!c.data); } else { assert(c.data && (!length || memcmp(c.data,data,length)==0)); }
}
static void destroy(vireo_mysql_thread_t *t,vireo_mysql_statement_t **s) { CHECK(vireo_mysql_statement_destroy(t,s,NULL),VIREO_OK); assert(!*s); }
static void command(vireo_mysql_thread_t *t,vireo_mysql_connection_t *c,const char *sql) {
    vireo_mysql_statement_t *s=prepare(t,c,sql); vireo_mysql_execution_t r=execute(t,s,NULL,0); assert(!r.has_result); destroy(t,&s);
}
static void values(vireo_mysql_thread_t *t,vireo_mysql_connection_t *c) {
    vireo_mysql_statement_t *s=prepare(t,c,"SELECT CAST(? AS SIGNED),CAST(? AS UNSIGNED),?,?,?,?");
    const char injection[]="' OR 1=1; DROP TABLE statement_values; --";
    unsigned char binary[]={0,1,255,0,'z'};
    const char text[]="你好🌱";
    vireo_mysql_parameter_t p[]={
        {.kind=VIREO_MYSQL_PARAMETER_I64,.value.i64=INT64_MIN},
        {.kind=VIREO_MYSQL_PARAMETER_U64,.value.u64=UINT64_MAX},
        {.kind=VIREO_MYSQL_PARAMETER_NULL},
        {.kind=VIREO_MYSQL_PARAMETER_TEXT,.value.span={NULL,0}},
        {.kind=VIREO_MYSQL_PARAMETER_BYTES,.value.span={binary,sizeof(binary)}},
        {.kind=VIREO_MYSQL_PARAMETER_TEXT,.value.span={text,sizeof(text)-1}}};
    assert(execute(t,s,p,6).has_result);
    fetch(t,s,VIREO_MYSQL_FETCH_ROW);
    cell(t,s,0,"-9223372036854775808",20,false); cell(t,s,1,"18446744073709551615",20,false);
    cell(t,s,2,NULL,0,true); cell(t,s,3,"",0,false); cell(t,s,4,binary,sizeof(binary),false); cell(t,s,5,text,sizeof(text)-1,false);
    fetch(t,s,VIREO_MYSQL_FETCH_DONE); destroy(t,&s);
    s=prepare(t,c,"INSERT INTO statement_values(value) VALUES (?)");
    p[0]=(vireo_mysql_parameter_t){.kind=VIREO_MYSQL_PARAMETER_TEXT,.value.span={injection,sizeof(injection)-1}};
    vireo_mysql_execution_t report=execute(t,s,p,1); assert(!report.has_result && report.affected_rows==1 && report.insert_id>0); destroy(t,&s);
    s=prepare(t,c,"SELECT value FROM statement_values WHERE value=?"); execute(t,s,p,1); fetch(t,s,VIREO_MYSQL_FETCH_ROW); cell(t,s,0,injection,sizeof(injection)-1,false); fetch(t,s,VIREO_MYSQL_FETCH_DONE); destroy(t,&s);
    s=prepare(t,c,"UPDATE statement_values SET value=? WHERE value=?"); p[1]=p[0]; report=execute(t,s,p,2); assert(report.affected_rows==0); destroy(t,&s);
    s=prepare(t,c,"UPDATE statement_values SET value=? WHERE value=?"); p[0].value.span.data="changed"; p[0].value.span.length=7; report=execute(t,s,p,2); assert(report.affected_rows==1); destroy(t,&s);
    puts("values: injection literal, I64_MIN/U64_MAX, NULL/empty/utf8mb4/binary NUL, INSERT/changed UPDATE passed");
}
static void rows_and_recovery(vireo_mysql_thread_t *t,vireo_mysql_connection_t *c) {
    vireo_mysql_statement_t *a=prepare(t,c,"SELECT 'one' UNION ALL SELECT 'two' UNION ALL SELECT 'three'");
    vireo_mysql_statement_t *b=prepare(t,c,"SELECT 9 WHERE 0");
    execute(t,a,NULL,0); fetch(t,a,VIREO_MYSQL_FETCH_ROW); cell(t,a,0,"one",3,false);
    vireo_mysql_statement_t *blocked=NULL; vireo_mysql_execution_t report; vireo_mysql_error_t e;
    CHECK(vireo_mysql_statement_prepare(t,c,"SELECT 1",8,&limits,&blocked,&e),VIREO_RESULT_BUSY);
    CHECK(vireo_mysql_statement_execute(t,b,NULL,0,&report,&e),VIREO_RESULT_BUSY); assert(!report.execution_started);
    CHECK(vireo_mysql_statement_reset(t,b,&e),VIREO_RESULT_BUSY);
    CHECK(vireo_mysql_statement_destroy(t,&b,&e),VIREO_RESULT_BUSY);
    vireo_mysql_connection_t *owner=c; CHECK(vireo_mysql_connection_destroy(t,&owner),VIREO_RESULT_BUSY); assert(owner==c);
    CHECK(vireo_mysql_statement_reset(t,a,&e),VIREO_OK);
    execute(t,b,NULL,0); fetch(t,b,VIREO_MYSQL_FETCH_DONE); fetch(t,b,VIREO_MYSQL_FETCH_DONE);
    execute(t,a,NULL,0); for(int i=0;i<3;++i) { fetch(t,a,VIREO_MYSQL_FETCH_ROW); } fetch(t,a,VIREO_MYSQL_FETCH_DONE);
    CHECK(vireo_mysql_statement_reset(t,a,&e),VIREO_OK); execute(t,a,NULL,0); destroy(t,&a); /* unread close */
    CHECK(vireo_mysql_statement_reset(t,b,&e),VIREO_OK); execute(t,b,NULL,0); fetch(t,b,VIREO_MYSQL_FETCH_DONE); destroy(t,&b);
    vireo_mysql_statement_limits_t small=limits; small.max_cell_bytes=8;
    const char *queries[]={"SELECT '12345678'","SELECT '123456789'","SELECT REPEAT('a',1000)"};
    for(size_t i=0;i<3;++i) {
        a=NULL; CHECK(vireo_mysql_statement_prepare(t,c,queries[i],strlen(queries[i]),&small,&a,&e),VIREO_OK);
        execute(t,a,NULL,0);
        if(i==0) { fetch(t,a,VIREO_MYSQL_FETCH_ROW); cell(t,a,0,"12345678",8,false); fetch(t,a,VIREO_MYSQL_FETCH_DONE); }
        else {
            vireo_mysql_fetch_outcome_t outcome=VIREO_MYSQL_FETCH_DONE;
            CHECK(vireo_mysql_statement_fetch(t,a,&outcome,&e),VIREO_RESULT_RANGE); assert(outcome==VIREO_MYSQL_FETCH_DONE);
            vireo_mysql_cell_view_t view;
            CHECK(vireo_mysql_statement_column(t,a,0,&view),VIREO_RESULT_CANCELLED);
            CHECK(vireo_mysql_statement_reset(t,a,&e),VIREO_OK);
        }
        destroy(t,&a);
    }
    a=prepare(t,c,"INSERT INTO statement_unique(id) VALUES (?)");
    vireo_mysql_parameter_t p={.kind=VIREO_MYSQL_PARAMETER_I64,.value.i64=1}; execute(t,a,&p,1);
    CHECK(vireo_mysql_statement_reset(t,a,&e),VIREO_OK);
    CHECK(vireo_mysql_statement_execute(t,a,&p,1,&report,&e),VIREO_RESULT_DATABASE);
    assert(report.execution_started && e.mysql_code==1062 && !c->unusable);
    CHECK(vireo_mysql_statement_reset(t,a,&e),VIREO_OK); p.value.i64=2; execute(t,a,&p,1); destroy(t,&a);
    puts("rows: zero/multiple rows, occupancy, unread reset/close, exact cap/truncation rejection, 1062 reset recovery passed");
}
static void reprepare(vireo_mysql_thread_t *t,vireo_mysql_connection_t **owner,
    vireo_mysql_connection_t *control,const vireo_mysql_connection_options_t *options) {
    vireo_mysql_connection_t *c=*owner;
    vireo_mysql_statement_t *a=NULL; vireo_mysql_error_t e; vireo_mysql_execution_t report;
    vireo_mysql_statement_limits_t one=limits; one.max_columns=1;
    const char sql[]="SELECT * FROM statement_reprepare";
    CHECK(vireo_mysql_statement_prepare(t,c,sql,sizeof(sql)-1,&one,&a,&e),VIREO_OK);
    command(t,control,"ALTER TABLE statement_reprepare MODIFY COLUMN first BIGINT");
    execute(t,a,NULL,0); fetch(t,a,VIREO_MYSQL_FETCH_DONE);
    CHECK(vireo_mysql_statement_reset(t,a,&e),VIREO_OK);
    command(t,control,"ALTER TABLE statement_reprepare ADD COLUMN second INT");
    /* MySQL8.0.46在结果列数改变时先报CR_NEW_STMT_METADATA(2057)，不会成功返回execute。
     * 按已采用的2000..2999保守损坏门禁处理，不绕过原生失败自动重试。成功execute
     * 后列数变化的RANGE分支由own边界模型另行覆盖。 */
    CHECK(vireo_mysql_statement_execute(t,a,NULL,0,&report,&e),VIREO_RESULT_DATABASE);
    assert(report.execution_started && e.mysql_code==2057 && c->unusable);
    CHECK(vireo_mysql_statement_reset(t,a,&e),VIREO_RESULT_CANCELLED);
    errno=EDOM; vireo_result_t r=vireo_mysql_statement_destroy(t,&a,&e);
    assert(errno==EDOM && !a && (r==VIREO_OK || r==VIREO_RESULT_DATABASE));
    CHECK(vireo_mysql_connection_destroy(t,owner),VIREO_OK);
    CHECK(vireo_mysql_connection_open(t,options,owner,NULL),VIREO_OK); c=*owner;
    a=prepare(t,c,sql); vireo_mysql_statement_info_t info;
    CHECK(vireo_mysql_statement_inspect(t,a,&info),VIREO_OK); assert(info.column_count==2);
    execute(t,a,NULL,0); fetch(t,a,VIREO_MYSQL_FETCH_DONE); destroy(t,&a);
    puts("automatic reprepare: same-count type change succeeds; changed count returns native 2057, poisons connection; fresh prepare sees two columns");
}

typedef struct worker {
    vireo_mysql_runtime_t *runtime;
    vireo_mysql_connection_options_t options;
    vireo_mysql_connection_t *connection;
    vireo_mysql_statement_t *statement;
    vireo_mysql_thread_t *wrong_guard;
} worker_t;
static void *worker_run(void *arg) {
    worker_t *w=arg; vireo_mysql_thread_t *t=NULL;
    if(w->statement) { vireo_mysql_statement_info_t info; CHECK(vireo_mysql_statement_inspect(w->wrong_guard,w->statement,&info),VIREO_RESULT_INVALID_ARGUMENT); }
    CHECK(vireo_mysql_thread_attach(w->runtime,&t,NULL),VIREO_OK);
    if(!w->connection) { CHECK(vireo_mysql_connection_open(t,&w->options,&w->connection,NULL),VIREO_OK); }
    if(!w->statement) { w->statement=prepare(t,w->connection,"SELECT 'thread'"); }
    execute(t,w->statement,NULL,0); fetch(t,w->statement,VIREO_MYSQL_FETCH_ROW); cell(t,w->statement,0,"thread",6,false); fetch(t,w->statement,VIREO_MYSQL_FETCH_DONE);
    destroy(t,&w->statement); CHECK(vireo_mysql_connection_destroy(t,&w->connection),VIREO_OK);
    CHECK(vireo_mysql_thread_detach(&t),VIREO_OK); return NULL;
}
static void threads(vireo_mysql_runtime_t *r,vireo_mysql_thread_t *t,const vireo_mysql_connection_options_t *options) {
    worker_t w[3]; pthread_t ids[3];
    for(size_t i=0;i<3;++i) { w[i]=(worker_t){.runtime=r,.options=*options}; assert(pthread_create(&ids[i],NULL,worker_run,&w[i])==0); }
    for(size_t i=0;i<3;++i) { assert(pthread_join(ids[i],NULL)==0); assert(!w[i].connection && !w[i].statement); }
    worker_t handoff={.runtime=r,.options=*options,.wrong_guard=t};
    CHECK(vireo_mysql_connection_open(t,options,&handoff.connection,NULL),VIREO_OK);
    handoff.statement=prepare(t,handoff.connection,"SELECT 'thread'");
    /* pthread_create发布完整图，父线程在join前不再访问owner/借用。 */
    assert(pthread_create(&ids[0],NULL,worker_run,&handoff)==0); assert(pthread_join(ids[0],NULL)==0);
    assert(!handoff.connection && !handoff.statement);
    puts("pthread: three independent guard/connection/statements and synchronized full resource graph handoff passed");
}
static void protocol_failures(vireo_mysql_thread_t *t,vireo_mysql_connection_t *c,vireo_mysql_connection_t *control) {
    vireo_mysql_statement_t *a=prepare(t,c,"CALL statement_multiple()");
    vireo_mysql_error_t e; vireo_mysql_execution_t report;
    errno=EDOM; vireo_result_t r=vireo_mysql_statement_execute(t,a,NULL,0,&report,&e); assert(errno==EDOM);
    if(r==VIREO_OK) {
        vireo_mysql_fetch_outcome_t o;
        do { errno=EDOM; r=vireo_mysql_statement_fetch(t,a,&o,&e); assert(errno==EDOM); } while(r==VIREO_OK && o==VIREO_MYSQL_FETCH_ROW);
    }
    assert(r==VIREO_RESULT_DATABASE && c->unusable);
    CHECK(vireo_mysql_statement_reset(t,a,&e),VIREO_RESULT_CANCELLED);
    errno=EDOM; r=vireo_mysql_statement_destroy(t,&a,&e); assert(errno==EDOM && !a && (r==VIREO_OK || r==VIREO_RESULT_DATABASE));
    puts("multiple results rejected; connection unusable and owner cleanup passed");
    (void)control;
}
static void disconnect(vireo_mysql_thread_t *t,vireo_mysql_connection_t *victim,vireo_mysql_connection_t *control) {
    vireo_mysql_statement_t *a=prepare(t,victim,"SELECT 1"), *b=prepare(t,victim,"SELECT 2");
    char sql[80]; int n=snprintf(sql,sizeof(sql),"KILL CONNECTION %" PRIu64,victim->info.connection_id); assert(n>0 && (size_t)n<sizeof(sql));
    assert(mysql_query(control->native,sql)==0);
    vireo_mysql_execution_t report; vireo_mysql_error_t e;
    CHECK(vireo_mysql_statement_execute(t,a,NULL,0,&report,&e),VIREO_RESULT_DATABASE);
    assert(report.execution_started && victim->unusable && e.mysql_code>=2000 && e.mysql_code<=2999);
    CHECK(vireo_mysql_statement_execute(t,b,NULL,0,&report,&e),VIREO_RESULT_CANCELLED); assert(!report.execution_started);
    CHECK(vireo_mysql_statement_reset(t,a,&e),VIREO_RESULT_CANCELLED);
    errno=EDOM; vireo_result_t r=vireo_mysql_statement_destroy(t,&b,&e); assert(errno==EDOM && !b && (r==VIREO_OK || r==VIREO_RESULT_DATABASE));
    errno=EDOM; r=vireo_mysql_statement_destroy(t,&a,&e); assert(errno==EDOM && !a && (r==VIREO_OK || r==VIREO_RESULT_DATABASE));
    assert(!victim->statement_count && !victim->active_statement);
    puts("disconnect: client error poisons connection, other statements blocked, all owners consumed passed");
}
int main(int argc,char **argv) {
    assert(argc==5); size_t before=fd_count();
    FILE *f=fopen(argv[3],"r"); assert(f); char password[128]; assert(fgets(password,sizeof(password),f)); assert(fclose(f)==0); password[strcspn(password,"\n")]='\0';
    struct sigaction action={0}; action.sa_handler=SIG_IGN; assert(sigaction(SIGPIPE,&action,NULL)==0);
    vireo_mysql_connection_options_t options={argv[1],argv[2],password,argv[4],2,3,3};
    vireo_mysql_runtime_t *runtime=NULL; vireo_mysql_thread_t *t=NULL; vireo_mysql_connection_t *c=NULL,*control=NULL;
    CHECK(vireo_mysql_runtime_create(&runtime,NULL),VIREO_OK); CHECK(vireo_mysql_thread_attach(runtime,&t,NULL),VIREO_OK);
    CHECK(vireo_mysql_connection_open(t,&options,&c,NULL),VIREO_OK); CHECK(vireo_mysql_connection_open(t,&options,&control,NULL),VIREO_OK);
    values(t,c); rows_and_recovery(t,c); reprepare(t,&c,control,&options); threads(runtime,t,&options);
    protocol_failures(t,c,control); CHECK(vireo_mysql_connection_destroy(t,&c),VIREO_OK);
    CHECK(vireo_mysql_connection_open(t,&options,&c,NULL),VIREO_OK); disconnect(t,c,control);
    CHECK(vireo_mysql_connection_destroy(t,&c),VIREO_OK); CHECK(vireo_mysql_connection_destroy(t,&control),VIREO_OK);
    assert(atomic_load(&runtime->connections)==0);
    CHECK(vireo_mysql_thread_detach(&t),VIREO_OK); CHECK(vireo_mysql_runtime_destroy(&runtime),VIREO_OK);
    memset(password,0,sizeof(password)); size_t after=fd_count(); assert(before==after);
    printf("real statement cleanup: fd %zu -> %zu; all statement/connection/runtime owners released\n",before,after); return 0;
}
