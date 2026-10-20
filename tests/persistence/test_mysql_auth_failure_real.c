#define _POSIX_C_SOURCE 200809L
#include "mysql_user_repository_internal.h"
#include <vireo/persistence/mysql_schema.h>
#include <assert.h>
#include "auth_failure_writer.h"
#include <semaphore.h>
#include <vireo/base/clock.h>
#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(call,want) do { errno=EDOM; vireo_result_t got_=(call); if(got_!=(want)) { fprintf(stderr,"line %d result %d wanted %d\n",__LINE__,(int)got_,(int)(want)); abort(); } assert(errno==EDOM); } while(0)
static vireo_mysql_runtime_t *runtime;
static vireo_mysql_thread_t *thread;
static vireo_mysql_pool_t *pool;
static vireo_mysql_connection_t *observer;
static vireo_mysql_user_repository_t *repo;
static vireo_password_policy_t policy=VIREO_PASSWORD_POLICY_DEFAULT;

static const vireo_mysql_statement_limits_t query_limits={0,3,0,512,32768};
static vireo_mysql_statement_t *query(const char *sql)
{
    vireo_mysql_statement_t *s=NULL;vireo_mysql_execution_t ex;vireo_mysql_error_t error;
    CHECK(vireo_mysql_statement_prepare(thread,observer,sql,strlen(sql),&query_limits,&s,&error),VIREO_OK);
    CHECK(vireo_mysql_statement_execute(thread,s,NULL,0,&ex,&error),VIREO_OK);assert(ex.has_result);return s;
}
static void row(vireo_mysql_statement_t *s)
{ vireo_mysql_fetch_outcome_t out;CHECK(vireo_mysql_statement_fetch(thread,s,&out,NULL),VIREO_OK);assert(out==VIREO_MYSQL_FETCH_ROW); }
static void cell(vireo_mysql_statement_t *s,size_t col,const void *expected,size_t n)
{
    vireo_mysql_cell_view_t c;CHECK(vireo_mysql_statement_column(thread,s,col,&c),VIREO_OK);
    assert(!c.is_null && c.length==n && !memcmp(c.data,expected,n));
}
static void end(vireo_mysql_statement_t **s)
{
    vireo_mysql_fetch_outcome_t out;CHECK(vireo_mysql_statement_fetch(thread,*s,&out,NULL),VIREO_OK);
    assert(out==VIREO_MYSQL_FETCH_DONE);CHECK(vireo_mysql_statement_destroy(thread,s,NULL),VIREO_OK);assert(!*s);
}
static void scalar(const char *sql,const char *expected)
{ vireo_mysql_statement_t *s=query(sql);row(s);cell(s,0,expected,strlen(expected));end(&s); }
static size_t fd_count(void)
{ DIR *d=opendir("/proc/self/fd");assert(d);size_t n=0;while(readdir(d)) ++n;assert(!closedir(d));return n; }
int main(int argc,char **argv)
{
    assert(argc==5);char password[1026];FILE *f=fopen(argv[3],"r");assert(f && fgets(password,(int)sizeof password,f) && !fclose(f));password[strcspn(password,"\n")]=0;
    struct sigaction sa={0};sa.sa_handler=SIG_IGN;assert(!sigemptyset(&sa.sa_mask) && !sigaction(SIGPIPE,&sa,NULL));
    CHECK(vireo_mysql_runtime_create(&runtime,NULL),VIREO_OK);CHECK(vireo_mysql_thread_attach(runtime,&thread,NULL),VIREO_OK);size_t fd=fd_count();
    vireo_mysql_connection_options_t options={argv[1],argv[2],password,argv[4],3,3,3};const vireo_mysql_migration_t *catalog=NULL;size_t count=0;
    CHECK(vireo_mysql_schema_catalog(&catalog,&count),VIREO_OK);vireo_mysql_migration_report_t migration;CHECK(vireo_mysql_migration_apply(thread,&options,catalog,count,&migration,NULL),VIREO_OK);assert(migration.ready);
    CHECK(vireo_mysql_connection_open(thread,&options,&observer,NULL),VIREO_OK);vireo_mysql_pool_options_t config={options,1,1,VIREO_MYSQL_POOL_MEMORY_MAX};
    CHECK(vireo_mysql_pool_create(thread,&config,&pool,NULL),VIREO_OK);CHECK(vireo_mysql_user_repository_create(thread,pool,&policy,&repo,NULL),VIREO_OK);
    unsigned serial=0;
    unsigned const statuses[]={1001,1008,1104,1105,1106,1901,1902,1906,1907,1908};
    for(unsigned action=1;action<=4;++action) for(unsigned origin=1;origin<=2;++origin) for(size_t j=0;j<10;++j) {
        vireo_mysql_auth_failure_input_t in={.occurred_at_ms=UINT64_MAX,.latency_us=UINT64_MAX,
            .action=(uint16_t)action,.status=(uint16_t)statuses[j],.origin=(uint8_t)origin};
        in.request_id[15]=(unsigned char)++serial;
        vireo_mysql_auth_failure_report_t report;
        CHECK(vireo_mysql_user_repository_append_auth_failure(repo,&in,&report,NULL),VIREO_OK);
        assert(report.commit==VIREO_MYSQL_AUTH_FAILURE_COMMITTED && report.audit_id && !report.cleanup_pending);
        char sql[1024];snprintf(sql,sizeof sql,"SELECT COUNT(*) FROM operation_audits WHERE id=%llu AND user_id IS NULL AND session_id IS NULL AND target_type=0 AND target_id IS NULL AND target_hash IS NULL AND action=%u AND status=%u AND latency_us=18446744073709551615 AND occurred_at_ms=18446744073709551615 AND BINARY detail='source=%s'",(unsigned long long)report.audit_id,action,statuses[j],origin==1?"reactor":"worker");
        scalar(sql,"1");
        snprintf(sql,sizeof sql,"SELECT request_id FROM operation_audits WHERE id=%llu",(unsigned long long)report.audit_id);
        vireo_mysql_statement_t *s=query(sql);row(s);cell(s,0,in.request_id,16);end(&s);
        in.status=1001;in.latency_us=0;
        CHECK(vireo_mysql_user_repository_append_auth_failure(repo,&in,&report,NULL),VIREO_RESULT_DATABASE);
        assert(report.commit==VIREO_MYSQL_AUTH_FAILURE_NOT_COMMITTED && !report.audit_id && !report.cleanup_pending);
    }
    scalar("SELECT COUNT(*) FROM operation_audits","80");scalar("SELECT COUNT(*) FROM users","0");scalar("SELECT COUNT(*) FROM sessions","0");
    vireo_mysql_auth_failure_input_t in={.request_id={99},.action=4,.status=1104,.origin=2};
    vireo_mysql_auth_failure_report_t report;
    vireo_mysql_lease_t lease={0};vireo_mysql_pool_acquisition_t acquired;
    CHECK(vireo_mysql_pool_acquire(thread,pool,0,&lease,&acquired,NULL),VIREO_OK);
    CHECK(vireo_mysql_user_repository_append_auth_failure(repo,&in,&report,NULL),VIREO_RESULT_BUSY);assert(!report.cleanup_pending);
    vireo_mysql_pool_release_t released;CHECK(vireo_mysql_pool_release(thread,pool,&lease,VIREO_MYSQL_POOL_RECYCLE,&released,NULL),VIREO_OK);
    bool closed=false;CHECK(vireo_mysql_pool_close(pool,&closed,NULL),VIREO_OK);assert(closed);
    CHECK(vireo_mysql_user_repository_append_auth_failure(repo,&in,&report,NULL),VIREO_RESULT_CANCELLED);assert(!report.cleanup_pending);
    CHECK(vireo_mysql_user_repository_destroy(&repo,NULL),VIREO_OK);CHECK(vireo_mysql_pool_destroy(thread,&pool,NULL),VIREO_OK);
    CHECK(vireo_mysql_connection_destroy(thread,&observer),VIREO_OK);CHECK(vireo_mysql_thread_detach(&thread),VIREO_OK);CHECK(vireo_mysql_runtime_destroy(&runtime),VIREO_OK);
    assert(fd_count()==fd);memset(password,0,sizeof password);puts("PASS real failure audit: 80 action/status/origin rows, NULL identities, exact IDs/u64, duplicate unchanged, rollback, pool refusal, no business mutations, FD restored");return 0;
}
