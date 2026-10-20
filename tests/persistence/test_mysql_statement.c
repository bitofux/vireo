#define _POSIX_C_SOURCE 200809L
#include "mysql_statement_internal.h"
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(call, want) do { errno = EDOM; assert((call) == (want)); assert(errno == EDOM); } while (0)
enum failure { NONE, INIT, PREPARE, METADATA, PARAM_BIND, EXECUTE, RESULT_BIND, FETCH,
    FREE_RESULT, RESET, CLOSE };
static enum failure failure;
static bool fail_close, fail_alloc, extra_results, late_extra;
static unsigned int native_code;
static size_t allocations, statements, close_calls, execute_calls, fetch_calls;
static unsigned long markers;
static unsigned int fields, metadata_fields;
static int fetch_code;
static unsigned long row_length;
static bool row_null, row_error;
static bool check_five_parameters;
static void *release_target;
static size_t release_bytes, checked_releases, sensitive_cases;
static MYSQL_BIND *bound_parameters, *bound_columns;
static vireo_mysql_statement_t *current;
static void *allocate(size_t n) { if (fail_alloc) { return NULL; } void *p = malloc(n); if (p) { ++allocations; } return p; }
static void assert_zero(const void *p, size_t length) {
    const unsigned char *bytes=p;
    for(size_t i=0;i<length;++i) { assert(bytes[i]==0); }
}
static void parameters_zero(const vireo_mysql_statement_t *s) {
    assert_zero(s->numbers,sizeof(s->numbers));
    assert_zero(s->bytes,s->limits.max_parameter_bytes);
    assert_zero(s->parameter_lengths,sizeof(s->parameter_lengths));
    assert_zero(s->parameter_nulls,sizeof(s->parameter_nulls));
}
static void rows_zero(const vireo_mysql_statement_t *s) {
    assert_zero(s->bytes+s->limits.max_parameter_bytes,
        s->info.allocated_bytes-sizeof(*s)-s->limits.max_parameter_bytes);
}
static void release(void *p) {
    assert(allocations); --allocations;
    if(p==release_target) {
        assert_zero(p,release_bytes); release_target=NULL; ++checked_releases;
    }
    free(p); errno = EIO;
}
static MYSQL_STMT *stmt_init(MYSQL *n) { (void)n; if (failure == INIT) { return NULL; } ++statements; return (MYSQL_STMT *)malloc(1); }
static int prepare(MYSQL_STMT *n, const char *s, unsigned long l) { (void)n; assert(s && l); return failure == PREPARE; }
static unsigned long param_count(MYSQL_STMT *n) { (void)n; return markers; }
static unsigned int field_count(MYSQL_STMT *n) { (void)n; return fields; }
static MYSQL_RES *metadata(MYSQL_STMT *n) { (void)n; return failure == METADATA ? NULL : (MYSQL_RES *)&fields; }
static unsigned int num_fields(MYSQL_RES *r) { (void)r; return metadata_fields; }
static void metadata_free(MYSQL_RES *r) { (void)r; }
static bool bind_param(MYSQL_STMT *n, MYSQL_BIND *b) { (void)n; bound_parameters = b; assert(b == current->parameters); return failure == PARAM_BIND; }
static bool bind_result(MYSQL_STMT *n, MYSQL_BIND *b) { (void)n; bound_columns = b; return failure == RESULT_BIND; }
static int execute(MYSQL_STMT *n) {
    (void)n; ++execute_calls;
    if(check_five_parameters) {
        /* 只在同步驱动实际消费时检查原参数；返回后本层副本应已清零。 */
        assert(*bound_parameters[0].is_null && *(int64_t *)bound_parameters[1].buffer==INT64_MIN);
        assert(bound_parameters[2].is_unsigned && *(uint64_t *)bound_parameters[2].buffer==UINT64_MAX);
        static const unsigned char expected[]={'a',0,'b'};
        assert(*bound_parameters[4].length==3 && memcmp(bound_parameters[4].buffer,expected,3)==0);
    }
    return failure == EXECUTE;
}
static int fetch(MYSQL_STMT *n) {
    (void)n; ++fetch_calls;
    /* 每次合法fetch进入驱动之前，整个旧行区已擦除；不读失效的cell view。 */
    rows_zero(current);
    if (failure == FETCH) {
        memset(bound_columns[0].buffer,'!',bound_columns[0].buffer_length);
        return 1;
    }
    for (unsigned int i = 0; i < fields; ++i) {
        *bound_columns[i].length = row_length;
        *bound_columns[i].is_null = row_null;
        *bound_columns[i].error = row_error;
        memset(bound_columns[i].buffer, 'x', row_length < bound_columns[i].buffer_length ? row_length : bound_columns[i].buffer_length);
    }
    return fetch_code;
}
static bool free_result(MYSQL_STMT *n) { (void)n; if(late_extra) { extra_results=true; late_extra=false; } return failure == FREE_RESULT; }
static bool reset(MYSQL_STMT *n) { (void)n; return failure == RESET; }
static bool close_stmt(MYSQL_STMT *n) { assert(statements); --statements; ++close_calls; free(n); return failure == CLOSE || fail_close; }
static unsigned int stmt_errno(MYSQL_STMT *n) { (void)n; return native_code; }
static const char *stmt_state(MYSQL_STMT *n) { (void)n; return "HY001"; }
static unsigned int conn_errno(MYSQL *n) { (void)n; return 2013; }
static const char *conn_state(MYSQL *n) { (void)n; return "HY002"; }
static bool more(MYSQL *n) { (void)n; return extra_results; }
static my_ulonglong affected(MYSQL_STMT *n) { (void)n; return 3; }
static my_ulonglong insert_id(MYSQL_STMT *n) { (void)n; return 17; }
static const vireo_mysql_statement_ops_t test_ops = {
    stmt_init, prepare, param_count, field_count, metadata, num_fields, metadata_free,
    bind_param, bind_result, execute, fetch, free_result, reset, close_stmt,
    stmt_errno, stmt_state, conn_errno, conn_state, more, affected, insert_id
};
static vireo_mysql_statement_limits_t limits = {32,32,64,8,65536};
static vireo_mysql_error_t error;
static vireo_mysql_execution_t report;
static vireo_mysql_thread_t *thread;
static vireo_mysql_connection_t connection;
static vireo_mysql_statement_t *make(void) {
    vireo_mysql_statement_t *s = NULL;
    CHECK(vireo_mysql_statement_prepare(thread,&connection,"SELECT ?",8,&limits,&s,&error),VIREO_OK);
    assert(s && connection.statement_count && error.stage == VIREO_MYSQL_STAGE_NONE);
    current = s; return s;
}
static void clean(vireo_mysql_statement_t **s) {
    failure = NONE; fail_close = false; extra_results = false;
    CHECK(vireo_mysql_statement_destroy(thread,s,&error),VIREO_OK);
    assert(!*s && !connection.statement_count && !connection.active_statement && !statements);
    connection.unusable = false;
}
static void validation(void) {
    vireo_mysql_statement_t *s = NULL;
    CHECK(vireo_mysql_statement_prepare(NULL,&connection,"x",1,&limits,&s,&error),VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_mysql_statement_prepare(thread,NULL,"x",1,&limits,&s,&error),VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_mysql_statement_prepare(thread,&connection,NULL,1,&limits,&s,&error),VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_mysql_statement_prepare(thread,&connection,"x",0,&limits,&s,&error),VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_mysql_statement_prepare(thread,&connection,"x",1,NULL,&s,&error),VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_mysql_statement_prepare(thread,&connection,"x",1,&limits,NULL,&error),VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_mysql_statement_prepare(thread,&connection,"x\0y",3,&limits,&s,&error),VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_mysql_statement_prepare(thread,&connection,"x",65537,&limits,&s,&error),VIREO_RESULT_RANGE);
    size_t *members[] = {&limits.max_parameters,&limits.max_columns,&limits.max_parameter_bytes,&limits.max_cell_bytes,&limits.max_memory_bytes};
    size_t maxima[] = {32,32,1048576,65536,4194304};
    for (size_t i=0;i<5;++i) { size_t old=*members[i]; *members[i]=maxima[i]+1;
        CHECK(vireo_mysql_statement_prepare(thread,&connection,"x",1,&limits,&s,&error),VIREO_RESULT_RANGE); *members[i]=old; }
    size_t old=limits.max_cell_bytes; limits.max_cell_bytes=0;
    CHECK(vireo_mysql_statement_prepare(thread,&connection,"x",1,&limits,&s,&error),VIREO_RESULT_INVALID_ARGUMENT); limits.max_cell_bytes=old;
    old=limits.max_memory_bytes; limits.max_memory_bytes=0;
    CHECK(vireo_mysql_statement_prepare(thread,&connection,"x",1,&limits,&s,&error),VIREO_RESULT_INVALID_ARGUMENT);
    limits.max_memory_bytes=1;
    CHECK(vireo_mysql_statement_prepare(thread,&connection,"x",1,&limits,&s,&error),VIREO_RESULT_RANGE); limits.max_memory_bytes=old;
    size_t output=99;
    CHECK(vireo_mysql_statement_layout(SIZE_MAX,1,1,&output),VIREO_RESULT_OVERFLOW); assert(output==99);
    CHECK(vireo_mysql_statement_layout(0,SIZE_MAX,1,&output),VIREO_RESULT_OVERFLOW);
    CHECK(vireo_mysql_statement_layout(0,1,SIZE_MAX,&output),VIREO_RESULT_OVERFLOW);
    CHECK(vireo_mysql_statement_layout(0,0,0,NULL),VIREO_RESULT_INVALID_ARGUMENT);
    unsigned long length=0;
    CHECK(vireo_mysql_statement_native_length(0,&length),VIREO_OK);
    CHECK(vireo_mysql_statement_native_length(0,NULL),VIREO_RESULT_INVALID_ARGUMENT);
#if SIZE_MAX > ULONG_MAX
    CHECK(vireo_mysql_statement_native_length((size_t)ULONG_MAX+1,&length),VIREO_RESULT_OVERFLOW);
#endif
    connection.statement_count=SIZE_MAX;
    CHECK(vireo_mysql_statement_prepare(thread,&connection,"x",1,&limits,&s,&error),VIREO_RESULT_OVERFLOW); connection.statement_count=0;
    fail_alloc=true;
    CHECK(vireo_mysql_statement_prepare(thread,&connection,"x",1,&limits,&s,&error),VIREO_RESULT_NO_MEMORY); fail_alloc=false;
    assert(!s && error.stage==VIREO_MYSQL_STAGE_ALLOCATE);
    markers=33;
    CHECK(vireo_mysql_statement_prepare(thread,&connection,"x",1,&limits,&s,&error),VIREO_RESULT_RANGE); markers=0;
    fields=metadata_fields=33;
    CHECK(vireo_mysql_statement_prepare(thread,&connection,"x",1,&limits,&s,&error),VIREO_RESULT_RANGE); fields=metadata_fields=0;
    vireo_mysql_statement_limits_t saved_limits=limits;
    limits=(vireo_mysql_statement_limits_t){32,32,1048576,65536,4194304};
    char unterminated[1]={'x'};
    CHECK(vireo_mysql_statement_prepare(thread,&connection,unterminated,1,&limits,&s,&error),VIREO_OK);
    clean(&s);
    limits=(vireo_mysql_statement_limits_t){0,0,0,1,65536};
    s=make();
    CHECK(vireo_mysql_statement_execute(thread,s,NULL,0,&report,&error),VIREO_OK);
    clean(&s); limits=saved_limits;
    vireo_mysql_runtime_t *saved_runtime=connection.runtime;
    connection.runtime=(vireo_mysql_runtime_t *)&limits;
    CHECK(vireo_mysql_statement_prepare(thread,&connection,"x",1,&limits,&s,&error),VIREO_RESULT_INVALID_ARGUMENT);
    connection.runtime=saved_runtime;
    CHECK(vireo_mysql_statement_destroy(NULL,NULL,&error),VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_mysql_statement_destroy(NULL,&s,&error),VIREO_OK);
    CHECK(vireo_mysql_statement_reset(thread,NULL,&error),VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_mysql_statement_execute(thread,NULL,NULL,0,&report,&error),VIREO_RESULT_INVALID_ARGUMENT); assert(!report.execution_started);
    CHECK(vireo_mysql_statement_fetch(thread,NULL,NULL,&error),VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_mysql_statement_inspect(thread,NULL,NULL),VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_mysql_statement_column(thread,NULL,0,NULL),VIREO_RESULT_INVALID_ARGUMENT);
}
static void parameters_and_rows(void) {
    markers=5; fields=metadata_fields=1;
    vireo_mysql_statement_t *s=make(), *other=make(); current=s;
    vireo_mysql_connection_t *owner=&connection;
    CHECK(vireo_mysql_connection_destroy(thread,&owner),VIREO_RESULT_BUSY); assert(owner==&connection);
    vireo_mysql_statement_info_t info;
    CHECK(vireo_mysql_statement_inspect(NULL,s,&info),VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_mysql_statement_inspect(thread,s,NULL),VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_mysql_statement_prepare(thread,&connection,"x",1,&limits,&s,&error),VIREO_RESULT_INVALID_ARGUMENT);
    vireo_mysql_fetch_outcome_t outcome=VIREO_MYSQL_FETCH_DONE;
    CHECK(vireo_mysql_statement_fetch(thread,s,&outcome,&error),VIREO_RESULT_BUSY);
    vireo_mysql_cell_view_t cell={0};
    CHECK(vireo_mysql_statement_column(thread,s,0,&cell),VIREO_RESULT_BUSY);
    CHECK(vireo_mysql_statement_execute(NULL,s,NULL,0,&report,&error),VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_mysql_statement_execute(thread,s,NULL,0,&report,&error),VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_mysql_statement_execute(thread,s,NULL,5,&report,&error),VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_mysql_statement_execute(thread,s,NULL,0,NULL,&error),VIREO_RESULT_INVALID_ARGUMENT);
    unsigned char bytes[]={'a',0,'b'};
    vireo_mysql_parameter_t p[5] = {
        {.kind=VIREO_MYSQL_PARAMETER_NULL}, {.kind=VIREO_MYSQL_PARAMETER_I64,.value.i64=INT64_MIN},
        {.kind=VIREO_MYSQL_PARAMETER_U64,.value.u64=UINT64_MAX},
        {.kind=VIREO_MYSQL_PARAMETER_TEXT,.value.span={NULL,0}},
        {.kind=VIREO_MYSQL_PARAMETER_BYTES,.value.span={bytes,3}}};
    p[0].kind=(vireo_mysql_parameter_kind_t)99;
    CHECK(vireo_mysql_statement_execute(thread,s,p,5,&report,&error),VIREO_RESULT_INVALID_ARGUMENT); p[0].kind=VIREO_MYSQL_PARAMETER_NULL;
    p[3].value.span.length=1;
    CHECK(vireo_mysql_statement_execute(thread,s,p,5,&report,&error),VIREO_RESULT_INVALID_ARGUMENT); p[3].value.span.length=0;
    p[4].value.span.length=65;
    CHECK(vireo_mysql_statement_execute(thread,s,p,5,&report,&error),VIREO_RESULT_RANGE); p[4].value.span.length=3;
    p[3].value.span.data=bytes; p[3].value.span.length=62;
    CHECK(vireo_mysql_statement_execute(thread,s,p,5,&report,&error),VIREO_RESULT_RANGE); p[3].value.span.length=0;
    size_t calls=execute_calls;
    check_five_parameters=true;
    CHECK(vireo_mysql_statement_execute(thread,s,p,5,&report,&error),VIREO_OK);
    check_five_parameters=false;
    assert(report.execution_started && report.has_result && execute_calls==calls+1);
    parameters_zero(s);
    assert(bound_parameters[4].buffer!=bytes && bytes[0]=='a' && bytes[1]==0 && bytes[2]=='b');
    bytes[0]='z'; assert(((unsigned char *)bound_parameters[4].buffer)[0]==0);
    CHECK(vireo_mysql_statement_execute(thread,s,p,5,&report,&error),VIREO_RESULT_BUSY); assert(!report.execution_started);
    vireo_mysql_statement_t *third=NULL;
    CHECK(vireo_mysql_statement_prepare(thread,&connection,"x",1,&limits,&third,&error),VIREO_RESULT_BUSY);
    CHECK(vireo_mysql_statement_execute(thread,other,p,5,&report,&error),VIREO_RESULT_BUSY);
    CHECK(vireo_mysql_statement_reset(thread,other,&error),VIREO_RESULT_BUSY);
    CHECK(vireo_mysql_statement_destroy(thread,&other,&error),VIREO_RESULT_BUSY); assert(other);
    CHECK(vireo_mysql_statement_fetch(NULL,s,&outcome,&error),VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_mysql_statement_fetch(thread,s,NULL,&error),VIREO_RESULT_INVALID_ARGUMENT);
    row_length=8; fetch_code=0;
    CHECK(vireo_mysql_statement_fetch(thread,s,&outcome,&error),VIREO_OK); assert(outcome==VIREO_MYSQL_FETCH_ROW);
    CHECK(vireo_mysql_statement_column(NULL,s,0,&cell),VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_mysql_statement_column(thread,s,0,NULL),VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_mysql_statement_column(thread,s,1,&cell),VIREO_RESULT_RANGE);
    CHECK(vireo_mysql_statement_column(thread,s,0,&cell),VIREO_OK); assert(cell.length==8 && !cell.is_null);
    row_null=true; row_length=0;
    CHECK(vireo_mysql_statement_fetch(thread,s,&outcome,&error),VIREO_OK);
    CHECK(vireo_mysql_statement_column(thread,s,0,&cell),VIREO_OK); assert(cell.is_null && !cell.data && !cell.length);
    row_null=false;
    CHECK(vireo_mysql_statement_fetch(thread,s,&outcome,&error),VIREO_OK);
    CHECK(vireo_mysql_statement_column(thread,s,0,&cell),VIREO_OK); assert(!cell.is_null && cell.data && !cell.length);
    fetch_code=MYSQL_NO_DATA;
    CHECK(vireo_mysql_statement_fetch(thread,s,&outcome,&error),VIREO_OK); assert(outcome==VIREO_MYSQL_FETCH_DONE && !connection.active_statement);
    calls=fetch_calls;
    CHECK(vireo_mysql_statement_fetch(thread,s,&outcome,&error),VIREO_OK); assert(fetch_calls==calls);
    CHECK(vireo_mysql_statement_reset(NULL,s,&error),VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_mysql_statement_destroy(NULL,&s,&error),VIREO_RESULT_INVALID_ARGUMENT); assert(s);
    CHECK(vireo_mysql_statement_reset(thread,s,&error),VIREO_OK);
    for(size_t i=0;i<s->limits.max_parameter_bytes;++i) { assert(s->bytes[i]==0); }
    CHECK(vireo_mysql_statement_destroy(thread,&other,&error),VIREO_OK); clean(&s);
    markers=fields=metadata_fields=0;
    s=make();
    CHECK(vireo_mysql_statement_execute(thread,s,NULL,0,&report,&error),VIREO_OK);
    assert(!report.has_result && report.affected_rows==3 && report.insert_id==17);
    clean(&s);
}
static void failures(void) {
    for (int f=INIT; f<=METADATA; ++f) {
        for (int double_fail=0;double_fail<2;++double_fail) {
            failure=(enum failure)f; fail_close=double_fail!=0; native_code=1064; fields=metadata_fields=1;
            vireo_mysql_statement_t *s=NULL; size_t before=allocations;
            CHECK(vireo_mysql_statement_prepare(thread,&connection,"x",1,&limits,&s,&error),f==INIT?VIREO_RESULT_NO_MEMORY:VIREO_RESULT_DATABASE);
            assert(!s && allocations==before && !statements && !connection.statement_count);
            assert(error.mysql_code==(f==INIT?2013U:1064U));
            assert(error.stage==(f==INIT?VIREO_MYSQL_STAGE_STATEMENT_INIT:f==PREPARE?VIREO_MYSQL_STAGE_STATEMENT_PREPARE:VIREO_MYSQL_STAGE_STATEMENT_METADATA));
            connection.unusable=false;
        }
    }
    failure=NONE; fail_close=false; markers=1; fields=metadata_fields=1;
    vireo_mysql_parameter_t p={.kind=VIREO_MYSQL_PARAMETER_I64,.value.i64=1};
    for(int f=PARAM_BIND;f<=RESULT_BIND;++f) {
        vireo_mysql_statement_t *s=make(); failure=(enum failure)f; native_code=1062;
        CHECK(vireo_mysql_statement_execute(thread,s,&p,1,&report,&error),VIREO_RESULT_DATABASE);
        parameters_zero(s); rows_zero(s);
        assert(report.execution_started==(f!=PARAM_BIND) && error.mysql_code==1062 && !connection.unusable && connection.active_statement==s);
        CHECK(vireo_mysql_statement_execute(thread,s,&p,1,&report,&error),VIREO_RESULT_CANCELLED);
        failure=NONE;
        CHECK(vireo_mysql_statement_reset(thread,s,&error),VIREO_OK); clean(&s);
    }
    for(int mode=0;mode<10;++mode) {
        failure=NONE; native_code=0; row_length=1; row_error=false; fetch_code=0;
        vireo_mysql_statement_t *s=make();
        CHECK(vireo_mysql_statement_execute(thread,s,&p,1,&report,&error),VIREO_OK);
        vireo_mysql_fetch_outcome_t outcome=VIREO_MYSQL_FETCH_DONE;
        if(mode==0) { failure=FETCH; native_code=2013; }
        if(mode==1) { fetch_code=MYSQL_DATA_TRUNCATED; }
        if(mode==2) { row_error=true; }
        if(mode==3) { row_length=9; }
        if(mode==4) { failure=FREE_RESULT; fetch_code=MYSQL_NO_DATA; }
        if(mode==5) { extra_results=true; fetch_code=MYSQL_NO_DATA; }
        if(mode<6) {
            CHECK(vireo_mysql_statement_fetch(thread,s,&outcome,&error),mode>=1 && mode<=3?VIREO_RESULT_RANGE:VIREO_RESULT_DATABASE);
            rows_zero(s);
            assert(outcome==VIREO_MYSQL_FETCH_DONE && s->info.state==VIREO_MYSQL_STATEMENT_FAILED);
        } else {
            if(mode==6) { failure=FREE_RESULT; }
            if(mode==7) { failure=RESET; }
            if(mode==8) { extra_results=true; }
            if(mode==9) { failure=CLOSE; }
            if(mode!=9) { CHECK(vireo_mysql_statement_reset(thread,s,&error),VIREO_RESULT_DATABASE); }
            else {
                CHECK(vireo_mysql_statement_destroy(thread,&s,&error),VIREO_RESULT_DATABASE);
                assert(!s && error.mysql_code==2013 && strcmp(error.sqlstate,"HY002")==0);
            }
        }
        if(s) {
            vireo_mysql_cell_view_t sentinel={(const unsigned char *)"keep",42,false},cell=sentinel;
            CHECK(vireo_mysql_statement_column(thread,s,0,&cell),VIREO_RESULT_CANCELLED); assert(cell.data==sentinel.data && cell.length==42);
            CHECK(vireo_mysql_statement_fetch(thread,s,&outcome,&error),VIREO_RESULT_CANCELLED);
            if(connection.unusable) {
                CHECK(vireo_mysql_statement_reset(thread,s,&error),VIREO_RESULT_CANCELLED);
                vireo_mysql_statement_t *other=NULL;
                CHECK(vireo_mysql_statement_prepare(thread,&connection,"x",1,&limits,&other,&error),VIREO_RESULT_CANCELLED);
                CHECK(vireo_mysql_statement_inspect(thread,s,&(vireo_mysql_statement_info_t){0}),VIREO_OK);
            }
            clean(&s);
        } else { connection.unusable=false; }
    }
    failure=NONE; extra_results=false;
    vireo_mysql_statement_t *s=make(); fields=metadata_fields=33;
    CHECK(vireo_mysql_statement_execute(thread,s,&p,1,&report,&error),VIREO_RESULT_RANGE); assert(report.execution_started); clean(&s);
    fields=metadata_fields=1; s=make(); failure=METADATA; native_code=2008;
    CHECK(vireo_mysql_statement_execute(thread,s,&p,1,&report,&error),VIREO_RESULT_DATABASE); assert(connection.unusable); clean(&s);
    s=make(); extra_results=true;
    CHECK(vireo_mysql_statement_execute(thread,s,&p,1,&report,&error),VIREO_RESULT_DATABASE); assert(connection.unusable); clean(&s);
    s=make(); extra_results=true;
    CHECK(vireo_mysql_statement_destroy(thread,&s,&error),VIREO_RESULT_DATABASE); assert(!s && connection.unusable); connection.unusable=false; extra_results=false;
    s=make(); vireo_mysql_statement_t *other=make(); current=s;
    failure=EXECUTE; native_code=2013;
    CHECK(vireo_mysql_statement_execute(thread,s,&p,1,&report,&error),VIREO_RESULT_DATABASE);
    failure=NONE;
    CHECK(vireo_mysql_statement_destroy(thread,&other,&error),VIREO_OK); clean(&s);
    s=make(); CHECK(vireo_mysql_statement_execute(thread,s,&p,1,&report,&error),VIREO_OK);
    late_extra=true;
    CHECK(vireo_mysql_statement_reset(thread,s,&error),VIREO_RESULT_DATABASE); assert(connection.unusable); clean(&s);
    s=make(); CHECK(vireo_mysql_statement_execute(thread,s,&p,1,&report,&error),VIREO_OK);
    late_extra=true;
    CHECK(vireo_mysql_statement_destroy(thread,&s,&error),VIREO_RESULT_DATABASE); assert(!s && connection.unusable);
    connection.unusable=false; extra_results=false;
    s=make(); CHECK(vireo_mysql_statement_execute(thread,s,&p,1,&report,&error),VIREO_OK);
    failure=FREE_RESULT; native_code=1064; fail_close=true;
    CHECK(vireo_mysql_statement_destroy(thread,&s,&error),VIREO_RESULT_DATABASE);
    assert(!s && connection.unusable && error.stage==VIREO_MYSQL_STAGE_STATEMENT_RESET && error.mysql_code==1064);
    connection.unusable=false; failure=NONE; fail_close=false;
    fields=1; metadata_fields=2; s=NULL;
    CHECK(vireo_mysql_statement_prepare(thread,&connection,"x",1,&limits,&s,&error),VIREO_RESULT_DATABASE); assert(!s && connection.unusable); connection.unusable=false;
}
/* 用存活owner观察短行旧尾、无效调用保持及合法reset失败，拒绝free后读内存。 */
static void sensitive_values(void) {
    markers=1; fields=metadata_fields=1; native_code=1064;
    static const unsigned char input[]={0x51,0,0x7e,0xff};
    vireo_mysql_parameter_t p={.kind=VIREO_MYSQL_PARAMETER_BYTES,.value.span={input,sizeof(input)}};
    for(int mode=0;mode<4;++mode) {
        failure=NONE; fetch_code=0; row_null=false; row_error=false;
        vireo_mysql_statement_t *s=make();
        if(mode==1) { failure=PARAM_BIND; }
        if(mode==2) { failure=EXECUTE; }
        CHECK(vireo_mysql_statement_execute(thread,s,&p,1,&report,&error),
            mode==1 || mode==2 ? VIREO_RESULT_DATABASE : VIREO_OK);
        parameters_zero(s);
        assert(input[0]==0x51 && input[1]==0 && input[2]==0x7e && input[3]==0xff);
        ++sensitive_cases;
        if(mode==0 || mode==3) {
            vireo_mysql_fetch_outcome_t outcome=VIREO_MYSQL_FETCH_DONE;
            row_length=8;
            CHECK(vireo_mysql_statement_fetch(thread,s,&outcome,&error),VIREO_OK);
            unsigned char *owned=s->bytes+s->limits.max_parameter_bytes;
            assert(owned[0]=='x' && owned[7]=='x' && owned[8]==0);
            /* 门禁拒绝保留当前完整行；合法fetch才撤销。 */
            size_t calls=fetch_calls;
            CHECK(vireo_mysql_statement_fetch(thread,s,NULL,&error),VIREO_RESULT_INVALID_ARGUMENT);
            CHECK(vireo_mysql_statement_reset(NULL,s,&error),VIREO_RESULT_INVALID_ARGUMENT);
            assert(fetch_calls==calls && owned[0]=='x' && owned[7]=='x');
            ++sensitive_cases;
            if(mode==0) {
                row_length=2;
                CHECK(vireo_mysql_statement_fetch(thread,s,&outcome,&error),VIREO_OK);
                vireo_mysql_cell_view_t cell={0};
                CHECK(vireo_mysql_statement_column(thread,s,0,&cell),VIREO_OK);
                assert(cell.length==2 && cell.data[0]=='x' && cell.data[1]=='x');
                assert_zero(owned+2,limits.max_cell_bytes+1-2);
                ++sensitive_cases;
                row_length=0; row_null=true;
                CHECK(vireo_mysql_statement_fetch(thread,s,&outcome,&error),VIREO_OK);
                CHECK(vireo_mysql_statement_column(thread,s,0,&cell),VIREO_OK);
                assert(cell.is_null && cell.data==NULL); rows_zero(s); ++sensitive_cases;
                row_null=false;
                CHECK(vireo_mysql_statement_fetch(thread,s,&outcome,&error),VIREO_OK);
                CHECK(vireo_mysql_statement_column(thread,s,0,&cell),VIREO_OK);
                assert(!cell.is_null && cell.length==0); rows_zero(s); ++sensitive_cases;
                row_length=5; fetch_code=MYSQL_NO_DATA;
                CHECK(vireo_mysql_statement_fetch(thread,s,&outcome,&error),VIREO_OK);
                assert(outcome==VIREO_MYSQL_FETCH_DONE); rows_zero(s); ++sensitive_cases;
            } else {
                failure=RESET;
                CHECK(vireo_mysql_statement_reset(thread,s,&error),VIREO_RESULT_DATABASE);
                assert(s->info.state==VIREO_MYSQL_STATEMENT_FAILED && connection.unusable);
                parameters_zero(s); rows_zero(s); ++sensitive_cases;
            }
        }
        release_target=s; release_bytes=s->info.allocated_bytes;
        clean(&s); assert(release_target==NULL);
    }
    /* free_result及额外结果失败都发生在合法reset已撤销完整行之后。 */
    for(int mode=0;mode<2;++mode) {
        failure=NONE; fetch_code=0; row_length=8; row_null=false;
        vireo_mysql_statement_t *s=make();
        CHECK(vireo_mysql_statement_execute(thread,s,&p,1,&report,&error),VIREO_OK);
        vireo_mysql_fetch_outcome_t outcome;
        CHECK(vireo_mysql_statement_fetch(thread,s,&outcome,&error),VIREO_OK);
        if(mode==0) { failure=FREE_RESULT; } else { extra_results=true; }
        CHECK(vireo_mysql_statement_reset(thread,s,&error),VIREO_RESULT_DATABASE);
        rows_zero(s); parameters_zero(s); ++sensitive_cases;
        release_target=s; release_bytes=s->info.allocated_bytes; clean(&s);
    }
    assert(checked_releases==6 && !release_target);
}
int main(void) {
    struct sigaction action={0}; action.sa_handler=SIG_IGN; assert(sigaction(SIGPIPE,&action,NULL)==0);
    vireo_mysql_ops_t o=vireo_mysql_native_ops; o.allocate=allocate; o.release=release;
    vireo_mysql_runtime_t *runtime=NULL;
    CHECK(vireo_mysql_runtime_create_with_ops(&runtime,&error,&o),VIREO_OK);
    CHECK(vireo_mysql_thread_attach(runtime,&thread,&error),VIREO_OK);
    connection.runtime=runtime; connection.native=mysql_init(NULL); assert(connection.native); connection.statement_ops=&test_ops;
    validation(); parameters_and_rows(); failures(); sensitive_values();
    assert(!statements && !connection.statement_count && !connection.active_statement);
    mysql_close(connection.native);
    CHECK(vireo_mysql_thread_detach(&thread),VIREO_OK);
    CHECK(vireo_mysql_runtime_destroy(&runtime),VIREO_OK);
    assert(!allocations);
    printf("statement validation, owned binding, states, failure/cleanup matrix passed; closes=%zu execute=%zu fetch=%zu\n",close_calls,execute_calls,fetch_calls);
    printf("sensitive lifecycle scenarios=%zu; entire statement zero before free=%zu\n",sensitive_cases,checked_releases);
    return 0;
}
