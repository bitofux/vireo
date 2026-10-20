#define _POSIX_C_SOURCE 200809L
#include "mysql_internal.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>

const vireo_mysql_session_ops_t vireo_mysql_session_native_ops = {
    mysql_reset_connection, mysql_select_db, mysql_set_character_set
};
const vireo_mysql_ops_t vireo_mysql_native_ops = {
    malloc, free, sigaction, mysql_library_init, mysql_library_end,
    mysql_thread_init, mysql_thread_end, mysql_init, mysql_options,
    mysql_real_connect, mysql_query, mysql_store_result
};

/* 只在应用串行启动/停机时访问；不伪装支持并发global init/end。 */
static enum { PROCESS_NEW, PROCESS_ACTIVE, PROCESS_ENDED } process_state;
static _Thread_local vireo_mysql_thread_t *current_guard;

static vireo_result_t finish(int saved_errno, vireo_result_t result)
{
    errno = saved_errno;
    return result;
}
static void reset_error(vireo_mysql_error_t *error)
{
    if (error != NULL) {
        *error = (vireo_mysql_error_t){0};
    }
}
static void diagnose(vireo_mysql_error_t *error, vireo_mysql_stage_t stage,
    MYSQL *native)
{
    if (error == NULL) {
        return;
    }
    error->stage = stage;
    if (native != NULL) {
        error->mysql_code = (uint32_t)mysql_errno(native);
        /* 无原生错误时不把成功SQLSTATE误报为错误；逻辑核验失败只有stage。 */
        if (error->mysql_code != 0) {
            memcpy(error->sqlstate, mysql_sqlstate(native), 5);
            error->sqlstate[5] = '\0';
        }
    }
}
static bool reserve(atomic_size_t *count)
{
    size_t old = atomic_load_explicit(count, memory_order_relaxed);
    while (old != SIZE_MAX) {
        if (atomic_compare_exchange_weak_explicit(count, &old, old + 1,
                memory_order_relaxed, memory_order_relaxed)) {
            return true;
        }
    }
    return false;
}
static void unreserve(atomic_size_t *count)
{
    (void)atomic_fetch_sub_explicit(count, 1, memory_order_relaxed);
}
bool vireo_mysql_valid_guard(const vireo_mysql_thread_t *thread)
{
    /* 先核TLS地址，再读owner；错误线程不能冒充有效登记。 */
    return thread != NULL && thread == current_guard &&
        pthread_equal(thread->owner, pthread_self()) != 0;
}

vireo_result_t vireo_mysql_runtime_create_with_ops(vireo_mysql_runtime_t **out,
    vireo_mysql_error_t *error, const vireo_mysql_ops_t *ops)
{
    int saved = errno;
    reset_error(error);
    if (out == NULL || *out != NULL || ops == NULL ||
        ops->allocate == NULL || ops->release == NULL || ops->signal_read == NULL ||
        ops->library_init == NULL || ops->library_end == NULL ||
        ops->thread_init == NULL || ops->thread_end == NULL || ops->init == NULL ||
        ops->options == NULL || ops->connect == NULL || ops->query == NULL ||
        ops->store_result == NULL) {
        return finish(saved, VIREO_RESULT_INVALID_ARGUMENT);
    }
    if (process_state != PROCESS_NEW) {
        return finish(saved, process_state == PROCESS_ACTIVE ?
            VIREO_RESULT_BUSY : VIREO_RESULT_CANCELLED);
    }
    struct sigaction action;
    if (ops->signal_read(SIGPIPE, NULL, &action) != 0) {
        if (error != NULL) {
            error->stage = VIREO_MYSQL_STAGE_SIGNAL_POLICY;
            error->system_error = errno;
        }
        return finish(saved, VIREO_RESULT_IO);
    }
    if (action.sa_handler != SIG_IGN) {
        diagnose(error, VIREO_MYSQL_STAGE_SIGNAL_POLICY, NULL);
        return finish(saved, VIREO_RESULT_INVALID_ARGUMENT);
    }
    vireo_mysql_runtime_t *runtime = ops->allocate(sizeof(*runtime));
    if (runtime == NULL) {
        diagnose(error, VIREO_MYSQL_STAGE_ALLOCATE, NULL);
        return finish(saved, VIREO_RESULT_NO_MEMORY);
    }
    runtime->creator = pthread_self();
    atomic_init(&runtime->guards, 0);
    atomic_init(&runtime->connections, 0);
    atomic_init(&runtime->pools, 0);
    runtime->ops = *ops;
    /* 进入原生init即不可盲目重试；失败时不调用未成功初始化的library_end。 */
    process_state = PROCESS_ENDED;
    if (ops->library_init(0, NULL, NULL) != 0) {
        diagnose(error, VIREO_MYSQL_STAGE_LIBRARY_INIT, NULL);
        ops->release(runtime);
        return finish(saved, VIREO_RESULT_DATABASE);
    }
    ops->thread_end(); /* 归一化library_init隐式创建的caller线程状态。 */
    process_state = PROCESS_ACTIVE;
    *out = runtime;
    return finish(saved, VIREO_OK);
}
vireo_result_t vireo_mysql_runtime_create(vireo_mysql_runtime_t **out,
    vireo_mysql_error_t *error)
{
    return vireo_mysql_runtime_create_with_ops(out, error, &vireo_mysql_native_ops);
}
vireo_result_t vireo_mysql_runtime_destroy(vireo_mysql_runtime_t **owner)
{
    int saved = errno;
    if (owner == NULL) {
        return finish(saved, VIREO_RESULT_INVALID_ARGUMENT);
    }
    vireo_mysql_runtime_t *runtime = *owner;
    if (runtime == NULL) {
        return finish(saved, VIREO_OK);
    }
    if (pthread_equal(runtime->creator, pthread_self()) == 0) {
        return finish(saved, VIREO_RESULT_INVALID_ARGUMENT);
    }
    if (atomic_load_explicit(&runtime->guards, memory_order_relaxed) != 0 ||
        atomic_load_explicit(&runtime->connections, memory_order_relaxed) != 0 ||
        atomic_load_explicit(&runtime->pools, memory_order_relaxed) != 0) {
        return finish(saved, VIREO_RESULT_BUSY);
    }
    runtime->ops.library_end();
    runtime->ops.release(runtime);
    *owner = NULL;
    process_state = PROCESS_ENDED;
    return finish(saved, VIREO_OK);
}
vireo_result_t vireo_mysql_thread_attach(vireo_mysql_runtime_t *runtime,
    vireo_mysql_thread_t **out, vireo_mysql_error_t *error)
{
    int saved = errno;
    reset_error(error);
    if (runtime == NULL || out == NULL || *out != NULL) {
        return finish(saved, VIREO_RESULT_INVALID_ARGUMENT);
    }
    if (current_guard != NULL) {
        return finish(saved, VIREO_RESULT_BUSY);
    }
    if (!reserve(&runtime->guards)) {
        return finish(saved, VIREO_RESULT_OVERFLOW);
    }
    vireo_mysql_thread_t *thread = runtime->ops.allocate(sizeof(*thread));
    if (thread == NULL) {
        unreserve(&runtime->guards);
        diagnose(error, VIREO_MYSQL_STAGE_ALLOCATE, NULL);
        return finish(saved, VIREO_RESULT_NO_MEMORY);
    }
    if (runtime->ops.thread_init()) {
        runtime->ops.release(thread);
        unreserve(&runtime->guards);
        diagnose(error, VIREO_MYSQL_STAGE_THREAD_INIT, NULL);
        return finish(saved, VIREO_RESULT_DATABASE);
    }
    thread->runtime = runtime;
    thread->owner = pthread_self();
    current_guard = thread;
    *out = thread;
    return finish(saved, VIREO_OK);
}
vireo_result_t vireo_mysql_thread_detach(vireo_mysql_thread_t **owner)
{
    int saved = errno;
    if (owner == NULL) {
        return finish(saved, VIREO_RESULT_INVALID_ARGUMENT);
    }
    if (*owner == NULL) {
        return finish(saved, VIREO_OK);
    }
    vireo_mysql_thread_t *thread = *owner;
    if (!vireo_mysql_valid_guard(thread)) {
        return finish(saved, VIREO_RESULT_INVALID_ARGUMENT);
    }
    vireo_mysql_runtime_t *runtime = thread->runtime;
    runtime->ops.thread_end();
    current_guard = NULL;
    runtime->ops.release(thread);
    unreserve(&runtime->guards);
    *owner = NULL;
    return finish(saved, VIREO_OK);
}
static vireo_result_t string_range(const char *value, size_t minimum, size_t maximum)
{
    if (value == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    size_t length = strnlen(value, maximum + 1);
    if (length < minimum) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    return length > maximum ? VIREO_RESULT_RANGE : VIREO_OK;
}
vireo_result_t vireo_mysql_validate_options(const vireo_mysql_connection_options_t *o)
{
    if (o == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    const char *strings[] = {o->unix_socket, o->username, o->password, o->database};
    const size_t maxima[] = {VIREO_MYSQL_SOCKET_MAX, VIREO_MYSQL_USERNAME_MAX,
        VIREO_MYSQL_PASSWORD_MAX, VIREO_MYSQL_DATABASE_MAX};
    for (size_t i = 0; i < 4; ++i) {
        vireo_result_t result = string_range(strings[i], i == 2 ? 0 : 1, maxima[i]);
        if (result != VIREO_OK) {
            return result;
        }
    }
    if (o->unix_socket[0] != '/' || o->connect_timeout_seconds == 0 ||
        o->read_timeout_seconds == 0 || o->write_timeout_seconds == 0) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    if (o->connect_timeout_seconds > VIREO_MYSQL_TIMEOUT_MAX ||
        o->read_timeout_seconds > VIREO_MYSQL_TIMEOUT_MAX ||
        o->write_timeout_seconds > VIREO_MYSQL_TIMEOUT_MAX) {
        return VIREO_RESULT_RANGE;
    }
    return VIREO_OK;
}
static bool mysql80(unsigned long version)
{
    return version >= 80000UL && version < 80100UL;
}
static bool configure(vireo_mysql_runtime_t *r, MYSQL *n,
    const vireo_mysql_connection_options_t *o)
{
    unsigned int protocol = MYSQL_PROTOCOL_SOCKET;
    unsigned int infile = 0;
    unsigned int connect_timeout = (unsigned int)o->connect_timeout_seconds;
    unsigned int read_timeout = (unsigned int)o->read_timeout_seconds;
    unsigned int write_timeout = (unsigned int)o->write_timeout_seconds;
    return r->ops.options(n, MYSQL_OPT_PROTOCOL, &protocol) == 0 &&
        r->ops.options(n, MYSQL_SET_CHARSET_NAME, "utf8mb4") == 0 &&
        r->ops.options(n, MYSQL_OPT_LOCAL_INFILE, &infile) == 0 &&
        r->ops.options(n, MYSQL_OPT_CONNECT_TIMEOUT, &connect_timeout) == 0 &&
        r->ops.options(n, MYSQL_OPT_READ_TIMEOUT, &read_timeout) == 0 &&
        r->ops.options(n, MYSQL_OPT_WRITE_TIMEOUT, &write_timeout) == 0;
}
static bool session_setup(vireo_mysql_runtime_t *r, MYSQL *n)
{
    /* 固定SQL，无用户拼接；单条SET，不打开multi-statements。 */
    return r->ops.query(n,
        "SET SESSION autocommit=1,time_zone='+00:00',"
        "sql_mode='STRICT_TRANS_TABLES,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION',"
        "default_storage_engine='InnoDB'") == 0;
}
static bool session_verify(vireo_mysql_runtime_t *r, MYSQL *n)
{
    /* 服务端可能规范化sql_mode顺序，采用服务端精确集合判定。 */
    if (r->ops.query(n,
            "SELECT @@autocommit=1,@@time_zone='+00:00',"
            "@@default_storage_engine='InnoDB',"
            "@@character_set_client='utf8mb4',@@character_set_connection='utf8mb4',"
            "@@character_set_results='utf8mb4',"
            "FIND_IN_SET('STRICT_TRANS_TABLES',@@sql_mode)>0 AND "
            "FIND_IN_SET('ERROR_FOR_DIVISION_BY_ZERO',@@sql_mode)>0 AND "
            "FIND_IN_SET('NO_ENGINE_SUBSTITUTION',@@sql_mode)>0 AND "
            "LENGTH(@@sql_mode)-LENGTH(REPLACE(@@sql_mode,',',''))=2") != 0) {
        return false;
    }
    MYSQL_RES *result = r->ops.store_result(n);
    if (result == NULL) {
        return false;
    }
    bool ok = mysql_num_fields(result) == 7 && mysql_num_rows(result) == 1;
    MYSQL_ROW row = mysql_fetch_row(result);
    unsigned long *lengths = row == NULL ? NULL : mysql_fetch_lengths(result);
    for (unsigned int i = 0; ok && i < 7; ++i) {
        ok = row != NULL && lengths != NULL && row[i] != NULL &&
            lengths[i] == 1 && row[i][0] == '1';
    }
    /* store_result已完整缓冲；显式读至结束并释放，不留下未消费结果。 */
    while (mysql_fetch_row(result) != NULL) {
        ok = false;
    }
    if (mysql_errno(n) != 0) {
        ok = false;
    }
    mysql_free_result(result);
    return ok;
}
vireo_result_t vireo_mysql_connection_open(vireo_mysql_thread_t *thread,
    const vireo_mysql_connection_options_t *options,
    vireo_mysql_connection_t **out, vireo_mysql_error_t *error)
{
    int saved = errno;
    reset_error(error);
    if (out == NULL || *out != NULL || !vireo_mysql_valid_guard(thread)) {
        return finish(saved, VIREO_RESULT_INVALID_ARGUMENT);
    }
    vireo_result_t status = vireo_mysql_validate_options(options);
    if (status != VIREO_OK) {
        return finish(saved, status);
    }
    vireo_mysql_runtime_t *runtime = thread->runtime;
    if (!reserve(&runtime->connections)) {
        return finish(saved, VIREO_RESULT_OVERFLOW);
    }
    vireo_mysql_stage_t stage = VIREO_MYSQL_STAGE_ALLOCATE;
    vireo_mysql_connection_t *connection = runtime->ops.allocate(sizeof(*connection));
    MYSQL *native = NULL;
    status = VIREO_RESULT_NO_MEMORY;
    if (connection == NULL) {
        goto fail;
    }
    stage = VIREO_MYSQL_STAGE_NATIVE_INIT;
    native = runtime->ops.init(NULL);
    if (native == NULL) {
        goto fail;
    }
    status = VIREO_RESULT_DATABASE;
    stage = VIREO_MYSQL_STAGE_OPTIONS;
    if (!configure(runtime, native, options)) {
        goto fail;
    }
    stage = VIREO_MYSQL_STAGE_CONNECT;
    if (runtime->ops.connect(native, "localhost", options->username, options->password,
            options->database, 0, options->unix_socket, 0) == NULL) {
        goto fail;
    }
    stage = VIREO_MYSQL_STAGE_SESSION_VERIFY;
    unsigned long version = mysql_get_server_version(native);
    if (!mysql80(mysql_get_client_version()) || !mysql80(version)) {
        goto fail;
    }
    stage = VIREO_MYSQL_STAGE_SESSION_SETUP;
    if (!session_setup(runtime, native)) {
        goto fail;
    }
    stage = VIREO_MYSQL_STAGE_SESSION_VERIFY;
    if (!session_verify(runtime, native)) {
        goto fail;
    }
    connection->session_ops = &vireo_mysql_session_native_ops;
    connection->pool = NULL;
    connection->pool_slot = 0;
    connection->statement_count = 0;
    connection->active_statement = NULL;
    connection->unusable = false;
    connection->statement_ops = &vireo_mysql_statement_native_ops;
    connection->runtime = runtime;
    connection->native = native;
    connection->info = (vireo_mysql_connection_info_t){(uint32_t)version,
        (uint64_t)mysql_thread_id(native)};
    *out = connection;
    return finish(saved, VIREO_OK);
fail:
    diagnose(error, stage, native); /* 必须先于close，不能读已释放的driver诊断。 */
    if (native != NULL) {
        mysql_close(native);
    }
    if (connection != NULL) {
        runtime->ops.release(connection);
    }
    unreserve(&runtime->connections);
    return finish(saved, status);
}
vireo_result_t vireo_mysql_connection_inspect(vireo_mysql_thread_t *thread,
    const vireo_mysql_connection_t *connection, vireo_mysql_connection_info_t *out)
{
    int saved = errno;
    if (out == NULL || !vireo_mysql_connection_access(thread, connection)) {
        return finish(saved, VIREO_RESULT_INVALID_ARGUMENT);
    }
    *out = connection->info;
    return finish(saved, VIREO_OK);
}
vireo_result_t vireo_mysql_connection_destroy(vireo_mysql_thread_t *thread,
    vireo_mysql_connection_t **owner)
{
    int saved = errno;
    if (owner == NULL) {
        return finish(saved, VIREO_RESULT_INVALID_ARGUMENT);
    }
    vireo_mysql_connection_t *connection = *owner;
    if (connection == NULL) {
        return finish(saved, VIREO_OK);
    }
    if (!vireo_mysql_valid_guard(thread) || thread->runtime != connection->runtime) {
        return finish(saved, VIREO_RESULT_INVALID_ARGUMENT);
    }
    if (connection->pool != NULL || connection->statement_count != 0) {
        return finish(saved, VIREO_RESULT_BUSY);
    }
    vireo_mysql_connection_dispose(connection);
    *owner = NULL;
    return finish(saved, VIREO_OK);
}

bool vireo_mysql_connection_access(const vireo_mysql_thread_t *thread,
    const vireo_mysql_connection_t *connection)
{
    return vireo_mysql_valid_guard(thread) && connection != NULL &&
        thread->runtime == connection->runtime && (connection->pool == NULL ||
            vireo_mysql_pool_connection_access(thread, connection));
}
void vireo_mysql_connection_dispose(vireo_mysql_connection_t *connection)
{
    vireo_mysql_runtime_t *runtime = connection->runtime;
    mysql_close(connection->native);
    runtime->ops.release(connection);
    unreserve(&runtime->connections);
}
vireo_result_t vireo_mysql_connection_restore(vireo_mysql_connection_t *c,
    const char *database, vireo_mysql_error_t *error)
{
    reset_error(error);
    vireo_mysql_stage_t stage = VIREO_MYSQL_STAGE_CONNECTION_RESET;
    if (c->session_ops->reset(c->native) != 0) { goto fail; }
    stage = VIREO_MYSQL_STAGE_SESSION_SETUP;
    if (c->session_ops->select_database(c->native, database) != 0 ||
        c->session_ops->charset(c->native, "utf8mb4") != 0 ||
        !session_setup(c->runtime, c->native)) { goto fail; }
    stage = VIREO_MYSQL_STAGE_SESSION_VERIFY;
    if (!session_verify(c->runtime, c->native) ||
        c->runtime->ops.query(c->native, "SELECT DATABASE()") != 0) { goto fail; }
    MYSQL_RES *res = c->runtime->ops.store_result(c->native);
    if (res == NULL) { goto fail; }
    MYSQL_ROW row = mysql_fetch_row(res);
    unsigned long *lengths = row == NULL ? NULL : mysql_fetch_lengths(res);
    size_t length = strlen(database);
    bool ok = mysql_num_fields(res) == 1 && mysql_num_rows(res) == 1 &&
        row != NULL && row[0] != NULL && lengths != NULL &&
        lengths[0] == length && memcmp(row[0], database, length) == 0;
    while (mysql_fetch_row(res) != NULL) { ok = false; }
    if (mysql_errno(c->native) != 0) { ok = false; }
    mysql_free_result(res);
    if (ok) { return VIREO_OK; }
fail:
    diagnose(error, stage, c->native);
    c->unusable = true;
    return VIREO_RESULT_DATABASE;
}
