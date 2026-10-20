#define _POSIX_C_SOURCE 200809L
#include "mysql_statement_internal.h"
#include <errno.h>
#include <errmsg.h>
#include <limits.h>
#include <string.h>

const vireo_mysql_statement_ops_t vireo_mysql_statement_native_ops = {
    mysql_stmt_init, mysql_stmt_prepare, mysql_stmt_param_count, mysql_stmt_field_count,
    mysql_stmt_result_metadata, mysql_num_fields, mysql_free_result,
    mysql_stmt_bind_param, mysql_stmt_bind_result, mysql_stmt_execute, mysql_stmt_fetch,
    mysql_stmt_free_result, mysql_stmt_reset, mysql_stmt_close, mysql_stmt_errno,
    mysql_stmt_sqlstate, mysql_errno, mysql_sqlstate, mysql_more_results,
    mysql_stmt_affected_rows, mysql_stmt_insert_id
};
static vireo_result_t finish(int saved, vireo_result_t result)
{
    errno = saved;
    return result;
}
static void error_reset(vireo_mysql_error_t *e)
{
    if (e != NULL) { *e = (vireo_mysql_error_t){0}; }
}
static void wipe(void *p, size_t bytes)
{
    volatile unsigned char *v = p;
    while (bytes != 0) { *v++ = 0; --bytes; }
}
vireo_result_t vireo_mysql_statement_native_length(size_t value, unsigned long *out)
{
    if (out == NULL) { return VIREO_RESULT_INVALID_ARGUMENT; }
    if (value > ULONG_MAX) { return VIREO_RESULT_OVERFLOW; }
    *out = (unsigned long)value;
    return VIREO_OK;
}
vireo_result_t vireo_mysql_statement_layout(size_t parameters, size_t columns,
    size_t cell, size_t *out)
{
    if (out == NULL) { return VIREO_RESULT_INVALID_ARGUMENT; }
    if (cell == SIZE_MAX || parameters > SIZE_MAX - sizeof(vireo_mysql_statement_t)) {
        return VIREO_RESULT_OVERFLOW;
    }
    size_t base = sizeof(vireo_mysql_statement_t) + parameters;
    if (columns > (SIZE_MAX - base) / (cell + 1)) { return VIREO_RESULT_OVERFLOW; }
    *out = base + columns * (cell + 1);
    return VIREO_OK;
}
static const vireo_mysql_statement_ops_t *ops(const vireo_mysql_statement_t *s)
{
    return s->connection->statement_ops;
}
static bool guard(vireo_mysql_thread_t *t, const vireo_mysql_connection_t *c)
{
    return vireo_mysql_connection_access(t, c);
}
static bool occupied(const vireo_mysql_statement_t *s)
{
    return s->connection->active_statement != NULL && s->connection->active_statement != s;
}
static void diagnostic(vireo_mysql_connection_t *c, MYSQL_STMT *n,
    vireo_mysql_stage_t stage, vireo_mysql_error_t *e)
{
    const vireo_mysql_statement_ops_t *o = c->statement_ops;
    unsigned int code = n != NULL ? o->stmt_errno(n) : o->conn_errno(c->native);
    if (code >= CR_MIN_ERROR && code <= CR_MAX_ERROR) { c->unusable = true; }
    if (e != NULL) {
        *e = (vireo_mysql_error_t){.stage = stage, .mysql_code = (uint32_t)code};
        if (code != 0) {
            memcpy(e->sqlstate, n != NULL ? o->stmt_sqlstate(n) : o->conn_sqlstate(c->native), 5);
        }
    }
}
/**
 * @brief 清同步execute已消费的自有参数，绑定地址继续存活到destroy。
 * @param[in,out] s 排他存活语句；native不再读取本次参数值。
 * @note 不清MYSQL_BIND和caller输入；后续execute总会重新复制并绑定参数。
 */
static void clear_parameters(vireo_mysql_statement_t *s)
{
    wipe(s->numbers, sizeof(s->numbers));
    wipe(s->bytes, s->limits.max_parameter_bytes);
    memset(s->parameter_lengths, 0, sizeof(s->parameter_lengths));
    memset(s->parameter_nulls, 0, sizeof(s->parameter_nulls));
}
/**
 * @brief 在合法行借用失效后清全部预留行区，包括较短新行未覆盖的旧尾部。
 * @param[in,out] s 排他存活语句，prepare已验证布局和完整申请量。
 * @note 保留所有原生绑定地址；不通过失效的外部view访问内存。
 */
static void clear_rows(vireo_mysql_statement_t *s)
{
    size_t const offset = s->limits.max_parameter_bytes;
    wipe(s->bytes + offset, s->info.allocated_bytes - sizeof(*s) - offset);
    memset(s->column_lengths, 0, sizeof(s->column_lengths));
    memset(s->column_nulls, 0, sizeof(s->column_nulls));
    memset(s->column_errors, 0, sizeof(s->column_errors));
}
/* 合法execute/reset或不可再借值的失败路径统一收尾；布局与绑定保持。 */
static void clear_values(vireo_mysql_statement_t *s)
{
    clear_parameters(s);
    clear_rows(s);
}
static vireo_result_t fail(vireo_mysql_statement_t *s, vireo_mysql_stage_t stage,
    vireo_mysql_error_t *e)
{
    diagnostic(s->connection, s->native, stage, e);
    s->info.state = VIREO_MYSQL_STATEMENT_FAILED;
    s->connection->active_statement = s;
    clear_values(s);
    return VIREO_RESULT_DATABASE;
}
static vireo_result_t extra(vireo_mysql_statement_t *s, vireo_mysql_stage_t stage,
    vireo_mysql_error_t *e)
{
    if (!ops(s)->more_results(s->connection->native)) { return VIREO_OK; }
    s->connection->unusable = true;
    return fail(s, stage, e);
}
static vireo_result_t metadata(vireo_mysql_statement_t *s, vireo_mysql_error_t *e)
{
    const vireo_mysql_statement_ops_t *o = ops(s);
    s->info.column_count = (size_t)o->field_count(s->native);
    if (s->info.column_count > s->limits.max_columns) { return VIREO_RESULT_RANGE; }
    if (s->info.column_count != 0) {
        MYSQL_RES *m = o->metadata(s->native);
        if (m == NULL) {
            diagnostic(s->connection, s->native, VIREO_MYSQL_STAGE_STATEMENT_METADATA, e);
            return VIREO_RESULT_DATABASE;
        }
        size_t count = (size_t)o->num_fields(m);
        o->metadata_free(m);
        if (count != s->info.column_count) {
            if (e != NULL) { e->stage = VIREO_MYSQL_STAGE_STATEMENT_METADATA; }
            s->connection->unusable = true;
            return VIREO_RESULT_DATABASE;
        }
    }
    return VIREO_OK;
}

vireo_result_t vireo_mysql_statement_prepare(vireo_mysql_thread_t *t,
    vireo_mysql_connection_t *c, const char *sql, size_t length,
    const vireo_mysql_statement_limits_t *l, vireo_mysql_statement_t **out,
    vireo_mysql_error_t *e)
{
    int saved = errno;
    error_reset(e);
    if (!guard(t, c) || sql == NULL || l == NULL || out == NULL || *out != NULL ||
        length == 0 || l->max_cell_bytes == 0 || l->max_memory_bytes == 0) {
        return finish(saved, VIREO_RESULT_INVALID_ARGUMENT);
    }
    if (c->unusable) { return finish(saved, VIREO_RESULT_CANCELLED); }
    if (c->active_statement != NULL) { return finish(saved, VIREO_RESULT_BUSY); }
    unsigned long native_length;
    size_t bytes;
    vireo_result_t r = vireo_mysql_statement_native_length(length, &native_length);
    if (r != VIREO_OK) { return finish(saved, r); }
    r = vireo_mysql_statement_layout(l->max_parameter_bytes, l->max_columns, l->max_cell_bytes, &bytes);
    if (r != VIREO_OK) { return finish(saved, r); }
    if (length > VIREO_MYSQL_SQL_MAX || l->max_parameters > VIREO_MYSQL_PARAMETERS_MAX ||
        l->max_columns > VIREO_MYSQL_COLUMNS_MAX || l->max_parameter_bytes > VIREO_MYSQL_PARAMETER_BYTES_MAX ||
        l->max_cell_bytes > VIREO_MYSQL_CELL_BYTES_MAX ||
        l->max_memory_bytes > VIREO_MYSQL_STATEMENT_MEMORY_MAX || bytes > l->max_memory_bytes) {
        return finish(saved, VIREO_RESULT_RANGE);
    }
    if (memchr(sql, '\0', length) != NULL) { return finish(saved, VIREO_RESULT_INVALID_ARGUMENT); }
    if (c->statement_count == SIZE_MAX) { return finish(saved, VIREO_RESULT_OVERFLOW); }
    vireo_mysql_statement_t *s = c->runtime->ops.allocate(bytes);
    if (s == NULL) {
        if (e != NULL) { e->stage = VIREO_MYSQL_STAGE_ALLOCATE; }
        return finish(saved, VIREO_RESULT_NO_MEMORY);
    }
    memset(s, 0, bytes);
    s->connection = c;
    s->limits = *l;
    s->info.allocated_bytes = bytes;
    s->native = ops(s)->init(c->native);
    if (s->native == NULL) {
        diagnostic(c, NULL, VIREO_MYSQL_STAGE_STATEMENT_INIT, e);
        r = VIREO_RESULT_NO_MEMORY;
        goto rollback;
    }
    if (ops(s)->prepare(s->native, sql, native_length) != 0) {
        diagnostic(c, s->native, VIREO_MYSQL_STAGE_STATEMENT_PREPARE, e);
        r = VIREO_RESULT_DATABASE;
        goto rollback;
    }
    unsigned long count = ops(s)->param_count(s->native);
    if (count > l->max_parameters) { r = VIREO_RESULT_RANGE; goto rollback; }
    s->info.parameter_count = (size_t)count;
    r = metadata(s, e);
    if (r != VIREO_OK) { goto rollback; }
    ++c->statement_count;
    *out = s;
    return finish(saved, VIREO_OK);
rollback:
    /* 保存的主诊断优先；close后禁止访问native，cleanup失败仅标损坏。 */
    if (s->native != NULL && ops(s)->close(s->native)) { c->unusable = true; }
    wipe(s, bytes);
    c->runtime->ops.release(s);
    return finish(saved, r);
}
vireo_result_t vireo_mysql_statement_inspect(vireo_mysql_thread_t *t,
    const vireo_mysql_statement_t *s, vireo_mysql_statement_info_t *out)
{
    int saved = errno;
    if (s == NULL || out == NULL || !guard(t, s->connection)) {
        return finish(saved, VIREO_RESULT_INVALID_ARGUMENT);
    }
    *out = s->info;
    return finish(saved, VIREO_OK);
}
vireo_result_t vireo_mysql_statement_execute(vireo_mysql_thread_t *t,
    vireo_mysql_statement_t *s, const vireo_mysql_parameter_t *p, size_t count,
    vireo_mysql_execution_t *out, vireo_mysql_error_t *e)
{
    int saved = errno;
    error_reset(e);
    if (out != NULL) { *out = (vireo_mysql_execution_t){0}; }
    if (s == NULL || out == NULL || !guard(t, s->connection)) {
        return finish(saved, VIREO_RESULT_INVALID_ARGUMENT);
    }
    if (s->connection->unusable || s->info.state == VIREO_MYSQL_STATEMENT_FAILED) {
        return finish(saved, VIREO_RESULT_CANCELLED);
    }
    if (occupied(s) || s->info.state != VIREO_MYSQL_STATEMENT_READY) {
        return finish(saved, VIREO_RESULT_BUSY);
    }
    if (count != s->info.parameter_count || (count != 0 && p == NULL)) {
        return finish(saved, VIREO_RESULT_INVALID_ARGUMENT);
    }
    size_t total = 0;
    for (size_t i = 0; i < count; ++i) {
        switch (p[i].kind) {
        case VIREO_MYSQL_PARAMETER_NULL:
        case VIREO_MYSQL_PARAMETER_I64:
        case VIREO_MYSQL_PARAMETER_U64: break;
        case VIREO_MYSQL_PARAMETER_TEXT:
        case VIREO_MYSQL_PARAMETER_BYTES:
            if (p[i].value.span.length != 0 && p[i].value.span.data == NULL) {
                return finish(saved, VIREO_RESULT_INVALID_ARGUMENT);
            }
            if (p[i].value.span.length > s->limits.max_parameter_bytes - total) {
                return finish(saved, VIREO_RESULT_RANGE);
            }
            total += p[i].value.span.length;
            break;
        default: return finish(saved, VIREO_RESULT_INVALID_ARGUMENT);
        }
    }
    clear_values(s);
    memset(s->parameters, 0, sizeof(s->parameters));
    size_t offset = 0;
    for (size_t i = 0; i < count; ++i) {
        MYSQL_BIND *b = &s->parameters[i];
        b->is_null = &s->parameter_nulls[i];
        b->length = &s->parameter_lengths[i];
        s->parameter_nulls[i] = p[i].kind == VIREO_MYSQL_PARAMETER_NULL;
        switch (p[i].kind) {
        case VIREO_MYSQL_PARAMETER_NULL: b->buffer_type = MYSQL_TYPE_NULL; break;
        case VIREO_MYSQL_PARAMETER_I64:
            s->numbers[i].i64 = p[i].value.i64;
            b->buffer_type = MYSQL_TYPE_LONGLONG;
            b->buffer = &s->numbers[i].i64;
            b->buffer_length = sizeof(int64_t);
            break;
        case VIREO_MYSQL_PARAMETER_U64:
            s->numbers[i].u64 = p[i].value.u64;
            b->buffer_type = MYSQL_TYPE_LONGLONG;
            b->is_unsigned = true;
            b->buffer = &s->numbers[i].u64;
            b->buffer_length = sizeof(uint64_t);
            break;
        case VIREO_MYSQL_PARAMETER_TEXT:
        case VIREO_MYSQL_PARAMETER_BYTES:
            b->buffer_type = p[i].kind == VIREO_MYSQL_PARAMETER_TEXT ? MYSQL_TYPE_STRING : MYSQL_TYPE_BLOB;
            b->buffer = s->bytes + offset;
            /* 总预算已核且硬上限小于ULONG_MAX；复制前仍使用统一受检转换。 */
            if (vireo_mysql_statement_native_length(p[i].value.span.length, &b->buffer_length) != VIREO_OK) {
                clear_parameters(s);
                return finish(saved, VIREO_RESULT_OVERFLOW);
            }
            s->parameter_lengths[i] = b->buffer_length;
            if (b->buffer_length != 0) { memcpy(b->buffer, p[i].value.span.data, p[i].value.span.length); }
            offset += p[i].value.span.length;
            break;
        }
    }
    if (count != 0 && ops(s)->bind_param(s->native, s->parameters)) {
        return finish(saved, fail(s, VIREO_MYSQL_STAGE_STATEMENT_BIND, e));
    }
    s->connection->active_statement = s;
    out->execution_started = true;
    int const executed = ops(s)->execute(s->native);
    /* 同步驱动已经消费参数；结果读取只使用另一个独立行区。 */
    clear_parameters(s);
    if (executed != 0) {
        return finish(saved, fail(s, VIREO_MYSQL_STAGE_STATEMENT_EXECUTE, e));
    }
    vireo_result_t r = metadata(s, e);
    if (r != VIREO_OK) {
        s->info.state = VIREO_MYSQL_STATEMENT_FAILED;
        return finish(saved, r);
    }
    r = extra(s, VIREO_MYSQL_STAGE_STATEMENT_EXECUTE, e);
    if (r != VIREO_OK) { return finish(saved, r); }
    if (s->info.column_count != 0) {
        memset(s->columns, 0, sizeof(s->columns));
        for (size_t i = 0; i < s->info.column_count; ++i) {
            MYSQL_BIND *b = &s->columns[i];
            b->buffer_type = MYSQL_TYPE_STRING;
            b->buffer = s->bytes + s->limits.max_parameter_bytes + i * (s->limits.max_cell_bytes + 1);
            b->buffer_length = (unsigned long)(s->limits.max_cell_bytes + 1);
            b->length = &s->column_lengths[i];
            b->is_null = &s->column_nulls[i];
            b->error = &s->column_errors[i];
        }
        if (ops(s)->bind_result(s->native, s->columns)) {
            return finish(saved, fail(s, VIREO_MYSQL_STAGE_STATEMENT_BIND, e));
        }
        s->info.state = VIREO_MYSQL_STATEMENT_ROWS;
        out->has_result = true;
    } else {
        out->affected_rows = (uint64_t)ops(s)->affected_rows(s->native);
        out->insert_id = (uint64_t)ops(s)->insert_id(s->native);
        s->info.state = VIREO_MYSQL_STATEMENT_DONE;
        s->connection->active_statement = NULL;
    }
    return finish(saved, VIREO_OK);
}
vireo_result_t vireo_mysql_statement_fetch(vireo_mysql_thread_t *t,
    vireo_mysql_statement_t *s, vireo_mysql_fetch_outcome_t *out, vireo_mysql_error_t *e)
{
    int saved = errno;
    error_reset(e);
    if (s == NULL || out == NULL || !guard(t, s->connection)) {
        return finish(saved, VIREO_RESULT_INVALID_ARGUMENT);
    }
    if (s->connection->unusable || s->info.state == VIREO_MYSQL_STATEMENT_FAILED) {
        return finish(saved, VIREO_RESULT_CANCELLED);
    }
    if (s->info.state == VIREO_MYSQL_STATEMENT_DONE) {
        *out = VIREO_MYSQL_FETCH_DONE;
        return finish(saved, VIREO_OK);
    }
    if (s->info.state != VIREO_MYSQL_STATEMENT_ROW && s->info.state != VIREO_MYSQL_STATEMENT_ROWS) {
        return finish(saved, VIREO_RESULT_BUSY);
    }
    s->info.state = VIREO_MYSQL_STATEMENT_ROWS; /* 旧行立即撤销，包括本次失败。 */
    clear_rows(s);
    int code = ops(s)->fetch(s->native);
    if (code == MYSQL_NO_DATA) {
        clear_rows(s); /* EOF不发布行，驱动即使写了部分值也不保留。 */
        vireo_result_t r = extra(s, VIREO_MYSQL_STAGE_STATEMENT_FETCH, e);
        if (r != VIREO_OK) { return finish(saved, r); }
        if (ops(s)->free_result(s->native)) {
            s->connection->unusable = true;
            return finish(saved, fail(s, VIREO_MYSQL_STAGE_STATEMENT_RESET, e));
        }
        r = extra(s, VIREO_MYSQL_STAGE_STATEMENT_FETCH, e);
        if (r != VIREO_OK) { return finish(saved, r); }
        s->info.state = VIREO_MYSQL_STATEMENT_DONE;
        s->connection->active_statement = NULL;
        *out = VIREO_MYSQL_FETCH_DONE;
        return finish(saved, VIREO_OK);
    }
    if (code != 0 && code != MYSQL_DATA_TRUNCATED) {
        return finish(saved, fail(s, VIREO_MYSQL_STAGE_STATEMENT_FETCH, e));
    }
    bool truncated = code == MYSQL_DATA_TRUNCATED;
    for (size_t i = 0; i < s->info.column_count; ++i) {
        truncated = truncated || s->column_errors[i] || s->column_lengths[i] > s->limits.max_cell_bytes;
    }
    if (truncated) {
        s->info.state = VIREO_MYSQL_STATEMENT_FAILED;
        clear_rows(s);
        return finish(saved, VIREO_RESULT_RANGE);
    }
    s->info.state = VIREO_MYSQL_STATEMENT_ROW;
    *out = VIREO_MYSQL_FETCH_ROW;
    return finish(saved, VIREO_OK);
}
vireo_result_t vireo_mysql_statement_column(vireo_mysql_thread_t *t,
    const vireo_mysql_statement_t *s, size_t index, vireo_mysql_cell_view_t *out)
{
    int saved = errno;
    if (s == NULL || out == NULL || !guard(t, s->connection)) {
        return finish(saved, VIREO_RESULT_INVALID_ARGUMENT);
    }
    if (s->connection->unusable || s->info.state == VIREO_MYSQL_STATEMENT_FAILED) {
        return finish(saved, VIREO_RESULT_CANCELLED);
    }
    if (s->info.state != VIREO_MYSQL_STATEMENT_ROW) { return finish(saved, VIREO_RESULT_BUSY); }
    if (index >= s->info.column_count) { return finish(saved, VIREO_RESULT_RANGE); }
    bool null = s->column_nulls[index];
    *out = (vireo_mysql_cell_view_t){null ? NULL : s->columns[index].buffer,
        null ? 0 : (size_t)s->column_lengths[index], null};
    return finish(saved, VIREO_OK);
}
vireo_result_t vireo_mysql_statement_reset(vireo_mysql_thread_t *t,
    vireo_mysql_statement_t *s, vireo_mysql_error_t *e)
{
    int saved = errno;
    error_reset(e);
    if (s == NULL || !guard(t, s->connection)) { return finish(saved, VIREO_RESULT_INVALID_ARGUMENT); }
    if (s->connection->unusable) { return finish(saved, VIREO_RESULT_CANCELLED); }
    if (occupied(s)) { return finish(saved, VIREO_RESULT_BUSY); }
    s->info.state = VIREO_MYSQL_STATEMENT_FAILED; /* 合法reset撤销当前行。 */
    clear_values(s); /* 后续free/reset失败也不能留下已撤销行。 */
    vireo_result_t r = extra(s, VIREO_MYSQL_STAGE_STATEMENT_RESET, e);
    if (r != VIREO_OK) { return finish(saved, r); }
    if (ops(s)->free_result(s->native)) {
        s->connection->unusable = true;
        return finish(saved, fail(s, VIREO_MYSQL_STAGE_STATEMENT_RESET, e));
    }
    /* free当前结果后可能才显露下一结果，不能让reset先静默取消它。 */
    r = extra(s, VIREO_MYSQL_STAGE_STATEMENT_RESET, e);
    if (r != VIREO_OK) { return finish(saved, r); }
    if (ops(s)->reset(s->native)) {
        s->connection->unusable = true;
        return finish(saved, fail(s, VIREO_MYSQL_STAGE_STATEMENT_RESET, e));
    }
    r = extra(s, VIREO_MYSQL_STAGE_STATEMENT_RESET, e);
    if (r != VIREO_OK) { return finish(saved, r); }
    s->info.state = VIREO_MYSQL_STATEMENT_READY;
    if (s->connection->active_statement == s) { s->connection->active_statement = NULL; }
    return finish(saved, VIREO_OK);
}
vireo_result_t vireo_mysql_statement_destroy(vireo_mysql_thread_t *t,
    vireo_mysql_statement_t **owner, vireo_mysql_error_t *e)
{
    int saved = errno;
    error_reset(e);
    if (owner == NULL) { return finish(saved, VIREO_RESULT_INVALID_ARGUMENT); }
    vireo_mysql_statement_t *s = *owner;
    if (s == NULL) { return finish(saved, VIREO_OK); }
    vireo_mysql_connection_t *c = s->connection;
    if (!guard(t, c)) { return finish(saved, VIREO_RESULT_INVALID_ARGUMENT); }
    if (!c->unusable && occupied(s)) { return finish(saved, VIREO_RESULT_BUSY); }
    /* 健康连接才检查额外结果；已损坏连接只做有限close清理。 */
    vireo_result_t r = VIREO_OK;
    if (!c->unusable) { r = extra(s, VIREO_MYSQL_STAGE_STATEMENT_CLOSE, e); }
    if (!c->unusable && c->active_statement == s) {
        if (ops(s)->free_result(s->native)) {
            c->unusable = true;
            r = fail(s, VIREO_MYSQL_STAGE_STATEMENT_RESET, e);
        } else {
            r = extra(s, VIREO_MYSQL_STAGE_STATEMENT_CLOSE, e);
        }
    }
    /* 即使前置结果清理失败也必须进入close；主诊断不被后续close错误覆盖。 */
    bool failed = ops(s)->close(s->native);
    if (failed) {
        c->unusable = true;
        if (r == VIREO_OK) { diagnostic(c, NULL, VIREO_MYSQL_STAGE_STATEMENT_CLOSE, e); }
        r = VIREO_RESULT_DATABASE;
    }
    if (!c->unusable && c->statement_ops->more_results(c->native)) {
        c->unusable = true;
        diagnostic(c, NULL, VIREO_MYSQL_STAGE_STATEMENT_CLOSE, e);
        r = VIREO_RESULT_DATABASE;
    }
    /* native在这里已失效，不能再读取stmt诊断。 */
    if (c->active_statement == s) { c->active_statement = NULL; }
    --c->statement_count;
    size_t bytes = s->info.allocated_bytes;
    wipe(s, bytes);
    c->runtime->ops.release(s);
    *owner = NULL;
    return finish(saved, r);
}
