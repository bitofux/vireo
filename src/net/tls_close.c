/*
- PROJECT : VIREO
- FILE    : tls_close.c
- AUTHOR  : bitofux
- DATE    : 2026-10-17
- BRIEF   : 此模块负责：固定期限、单原生调用的TLS双向关闭及调度快照
 */
#include "tls_connection_internal.h"

#include <errno.h>
#include <openssl/err.h>

/**
 * @brief 发布独立诊断并恢复入口errno
 *
 * @param[out] error 可空caller诊断，只借到返回。
 * @param[in] diagnostic 本次已保存的诊断值，不持地址。
 * @param[in] result 本次已确定分类。
 * @param[in] saved_errno 外层入口值。
 * @param[in] clear 通过基本前置后为true；false保持原库队列。
 *
 * @return 原result，主报告由外层负责发布或保持。
 *
 * @note 无分配/网络；清理不覆盖首错，所有调用由同Reactor串行执行。
 */
static vireo_result_t finish(vireo_tls_connection_error_t *error,
    vireo_tls_connection_error_t diagnostic, vireo_result_t result, int saved_errno, bool clear)
{
    if (clear) { ERR_clear_error(); }
    if (error != NULL) { *error = diagnostic; }
    errno = saved_errno;
    return result;
}

/**
 * @brief 通过公开buffer快照取得当前FIFO占用
 *
 * @param[in] buffer 必需存活buffer，由同TLS owner长期保活；本次只读短借。
 *
 * @return 当前可读字节数，0合法，不授数据地址或未来容量。
 *
 * @note 内部已配置不变量排除错误；无分配/网络/view，保持errno。
 */
static size_t readable(vireo_buffer_t const *buffer)
{
    vireo_buffer_info_t info = {0};
    (void)vireo_buffer_inspect(buffer, &info);
    return info.readable_size;
}

/** 关闭终态不再选择网络操作；NONE也没有关闭调度。 */
static bool active(vireo_tls_close_state_t state)
{
    return state == VIREO_TLS_CLOSE_DRAINING || state == VIREO_TLS_CLOSE_NOTIFYING ||
        state == VIREO_TLS_CLOSE_WAIT_PEER;
}

/**
 * @brief 从唯一FIFO/重试/关闭历史派生下一操作，不推进协议或迟滞
 * @param[in] connection 串行存活对象；非NONE时有固定I/O资源。
 * @return 独立值快照；needs_consume不屏蔽优先write的协议READ。
 * @note read WANT_READ允许穿插首次notify；只有解密pending可越过其网络等待。
 */
static vireo_tls_close_info_t snapshot(vireo_tls_connection_t const *connection)
{
    vireo_tls_close_storage_t const *close = &connection->close;
    vireo_tls_io_storage_t const *io = &connection->io;
    vireo_tls_close_info_t info = {.state = close->state};
    if (close->state == VIREO_TLS_CLOSE_NONE) { return info; }
    info.deadline_ns = close->deadline_ns;
    info.last_now_ns = close->last_now_ns;
    info.local_notify_sent = close->local_notify_sent;
    info.peer_notify_received = io->read_eof;
    if (!active(close->state)) { return info; }
    if (close->shutdown_wait != VIREO_TLS_IO_WAIT_NONE) {
        info.operation = VIREO_TLS_IO_OPERATION_SHUTDOWN;
        info.wait = close->shutdown_wait;
    } else if (io->write_retry_bytes != 0 ||
        (io->read_wait != VIREO_TLS_IO_WAIT_WRITE && readable(io->write_buffer) != 0)) {
        info.operation = VIREO_TLS_IO_OPERATION_WRITE;
        info.wait = io->write_wait;
    } else if (io->read_wait == VIREO_TLS_IO_WAIT_WRITE) {
        info.operation = VIREO_TLS_IO_OPERATION_READ;
        info.wait = io->read_wait;
    } else if (!close->local_notify_sent) {
        info.operation = VIREO_TLS_IO_OPERATION_SHUTDOWN;
    } else {
        info.operation = VIREO_TLS_IO_OPERATION_READ;
        info.wait = io->read_wait;
    }
    if (info.operation == VIREO_TLS_IO_OPERATION_READ) {
        size_t space = io->options.read_capacity - readable(io->read_buffer);
        info.needs_consume = space == 0 || io->read_retry_bytes > space;
        if (info.needs_consume) {
            info.wait = VIREO_TLS_IO_WAIT_NONE;
            return info;
        }
        info.resume = info.wait == VIREO_TLS_IO_WAIT_NONE ||
            (info.wait == VIREO_TLS_IO_WAIT_READ && SSL_pending(connection->native) > 0);
    } else { info.resume = info.wait == VIREO_TLS_IO_WAIT_NONE; }
    return info;
}

vireo_result_t vireo_tls_connection_close_inspect(vireo_tls_connection_t const *connection,
    vireo_tls_close_info_t *out_info, vireo_tls_connection_error_t *error)
{
    int saved_errno = errno;
    vireo_tls_connection_error_t diagnostic = {0};
    if (connection == NULL || out_info == NULL) {
        return finish(error, diagnostic, VIREO_RESULT_INVALID_ARGUMENT, saved_errno, false);
    }
    ERR_clear_error();
    *out_info = snapshot(connection);
    return finish(error, diagnostic, VIREO_OK, saved_errno, true);
}

vireo_result_t vireo_tls_connection_close_request(vireo_tls_connection_t *connection,
    vireo_monotonic_ns_t now, vireo_monotonic_ns_t deadline, vireo_tls_connection_error_t *error)
{
    int saved_errno = errno;
    vireo_tls_connection_error_t diagnostic = {0};
    if (connection == NULL) {
        return finish(error, diagnostic, VIREO_RESULT_INVALID_ARGUMENT, saved_errno, false);
    }
    ERR_clear_error();
    if (connection->state != VIREO_TLS_HANDSHAKE_ESTABLISHED ||
        connection->io.state == VIREO_TLS_IO_DISABLED || connection->close.state != VIREO_TLS_CLOSE_NONE) {
        return finish(error, diagnostic, VIREO_RESULT_BUSY, saved_errno, true);
    }
    if (connection->io.state == VIREO_TLS_IO_FAILED) {
        return finish(error, connection->io.failure_error, connection->io.failure_result, saved_errno, true);
    }
    connection->close = (vireo_tls_close_storage_t){.state = VIREO_TLS_CLOSE_DRAINING,
        .deadline_ns = deadline, .last_now_ns = now};
    return finish(error, diagnostic, VIREO_OK, saved_errno, true);
}

/**
 * @brief 在活跃关闭阶段提交唯一首错并关闭网络调度
 *
 * @param[in,out] connection 必需存活串行owner，调用前close active。
 * @param[in] result 本次非OK原生失败或TIMEOUT。
 * @param[in] diagnostic 已完成分类/捕获的独立值诊断。
 *
 * @note 调用者保证只在首错前调用；清两块暂存，保留FIFO、不释放资源、不改握手历史。
 *     清shutdown_wait使终态没有后续重试，网络门禁由close FAILED统一生效。
 */
static void fail(vireo_tls_connection_t *connection, vireo_result_t result,
    vireo_tls_connection_error_t diagnostic)
{
    connection->close.state = VIREO_TLS_CLOSE_FAILED;
    connection->close.failure_result = result;
    connection->close.failure_error = diagnostic;
    connection->close.shutdown_wait = VIREO_TLS_IO_WAIT_NONE;
    vireo_tls_io_clear_scratch(&connection->io);
}

/**
 * @brief 在紧邻原生分类之后消费本次错误队列
 *
 * @param[in,out] diagnostic 必需局部诊断；只写首原因及是否多原因。
 *
 * @retval true 本次队列至少有一个明确malloc failure。
 * @retval false 没有明确OOM，不猜测原因。
 *
 * @note 不存字符串/库地址；SYSCALL仍由外层优先真实errno，不因OOM改类。
 */
static bool capture(vireo_tls_connection_error_t *diagnostic)
{
    bool oom = false;
    unsigned long code;
    while ((code = ERR_get_error()) != 0) {
        if (diagnostic->openssl_error_code == 0) { diagnostic->openssl_error_code = (uint64_t)code; }
        else { diagnostic->has_more_errors = true; }
        if (ERR_GET_REASON(code) == ERR_R_MALLOC_FAILURE) { oom = true; }
    }
    return oom;
}

/**
 * @brief 执行一次原生关闭，不在返回后插入其他OpenSSL调用
 *
 * @param[in] context 生产不使用，可空。
 * @param[in,out] native 必需存活串行SSL，外层已完成信号/时间门禁。
 *
 * @return 原始SSL_shutdown结果，0/1正常，负数由外层紧邻get_error。
 *
 * @note 不接管fd，不等待；外层即时保存errno并负责分类/首错发布。
 */
static int native_shutdown(void *context, SSL *native)
{ (void)context; return SSL_shutdown(native); }

vireo_result_t vireo_tls_connection_close_with_ops(vireo_tls_connection_t *connection,
    vireo_monotonic_ns_t now, size_t max_bytes, vireo_tls_close_progress_t *out_progress,
    vireo_tls_connection_error_t *error, vireo_tls_close_ops_t const *ops)
{
    int saved_errno = errno;
    vireo_tls_connection_error_t diagnostic = {0};
    if (connection == NULL || out_progress == NULL || ops == NULL || ops->shutdown == NULL ||
        ops->io.sigpipe_ignored == NULL || ops->io.read_ex == NULL || ops->io.write_ex == NULL ||
        ops->io.get_error == NULL) {
        return finish(error, diagnostic, VIREO_RESULT_INVALID_ARGUMENT, saved_errno, false);
    }
    if (max_bytes == 0) { return finish(error, diagnostic, VIREO_RESULT_RANGE, saved_errno, false); }
    ERR_clear_error();
    vireo_tls_close_storage_t *close = &connection->close;
    if (close->state == VIREO_TLS_CLOSE_NONE) {
        return finish(error, diagnostic, VIREO_RESULT_BUSY, saved_errno, true);
    }
    vireo_tls_close_progress_t progress = {.stop_reason = VIREO_TLS_CLOSE_STOP_ERROR};
    if (!active(close->state)) {
        progress.stop_reason = close->state == VIREO_TLS_CLOSE_COMPLETE ?
            VIREO_TLS_CLOSE_STOP_COMPLETE : VIREO_TLS_CLOSE_STOP_ERROR;
        progress.info = snapshot(connection);
        *out_progress = progress;
        return finish(error, close->failure_error, close->failure_result, saved_errno, true);
    }
    if (now < close->last_now_ns) {
        return finish(error, diagnostic, VIREO_RESULT_RANGE, saved_errno, true);
    }
    if (now >= close->deadline_ns) {
        diagnostic.stage = VIREO_TLS_CONNECTION_STAGE_CLOSE_DEADLINE;
        close->last_now_ns = now;
        fail(connection, VIREO_RESULT_TIMEOUT, diagnostic);
        progress.info = snapshot(connection);
        *out_progress = progress;
        return finish(error, diagnostic, VIREO_RESULT_TIMEOUT, saved_errno, true);
    }
    vireo_tls_close_info_t next = snapshot(connection);
    vireo_tls_io_storage_t *io = &connection->io;
    bool writing = next.operation == VIREO_TLS_IO_OPERATION_WRITE;
    size_t retry = writing ? io->write_retry_bytes :
        (next.operation == VIREO_TLS_IO_OPERATION_READ ? io->read_retry_bytes : 0);
    if (retry > max_bytes) {
        return finish(error, diagnostic, VIREO_RESULT_RANGE, saved_errno, true);
    }
    vireo_result_t result = VIREO_OK;
    progress.stop_reason = VIREO_TLS_CLOSE_STOP_PROGRESS;
    if (next.needs_consume) { progress.stop_reason = VIREO_TLS_CLOSE_STOP_NEED_CONSUME; }
    else if (next.operation != VIREO_TLS_IO_OPERATION_SHUTDOWN) {
        vireo_tls_io_budget_t budget = {max_bytes, 1};
        vireo_tls_io_progress_t moved = {0};
        result = vireo_tls_connection_io_closing_with_ops(connection, &budget, &moved, &diagnostic, writing, &ops->io);
        if (result != VIREO_OK && io->state != VIREO_TLS_IO_FAILED) {
            /* 只有一个原生预算，故信号前拒绝不可能隐含已发生前缀。 */
            return finish(error, diagnostic, result, saved_errno, true);
        }
        progress.native_called = moved.native_calls != 0;
        progress.read_bytes = writing ? 0 : moved.bytes;
        progress.write_bytes = writing ? moved.bytes : 0;
        if (result != VIREO_OK) {
            fail(connection, result, diagnostic);
            progress.stop_reason = VIREO_TLS_CLOSE_STOP_ERROR;
        } else if (io->read_eof && close->local_notify_sent) {
            close->state = VIREO_TLS_CLOSE_COMPLETE;
        } else if (moved.stop_reason == VIREO_TLS_IO_STOP_WOULD_BLOCK) {
            progress.stop_reason = VIREO_TLS_CLOSE_STOP_WANT;
        }
    } else {
        bool ignored = false;
        int queried = ops->io.sigpipe_ignored(ops->io.context, &ignored);
        int query_errno = errno;
        if (queried != 0 || !ignored) {
            diagnostic.stage = VIREO_TLS_CONNECTION_STAGE_SIGNAL_POLICY;
            diagnostic.system_errno = queried == -1 ? query_errno : 0;
            result = queried == -1 ? VIREO_RESULT_IO :
                (queried != 0 ? VIREO_RESULT_INTERNAL : VIREO_RESULT_INVALID_ARGUMENT);
            return finish(error, diagnostic, result, saved_errno, true);
        }
        ERR_clear_error();
        errno = 0;
        int returned = ops->shutdown(ops->io.context, connection->native);
        int native_errno = errno;
        int classification = returned < 0 ?
            ops->io.get_error(ops->io.context, connection->native, returned) : SSL_ERROR_NONE;
        /* 此前不得调用任何其他OpenSSL函数；0是成功的第一阶段，不能get_error。 */
        bool oom = capture(&diagnostic);
        progress.native_called = true;
        close->state = VIREO_TLS_CLOSE_NOTIFYING;
        if (returned == 0 || returned == 1) {
            close->local_notify_sent = true;
            close->shutdown_wait = VIREO_TLS_IO_WAIT_NONE;
            close->state = returned == 1 ? VIREO_TLS_CLOSE_COMPLETE : VIREO_TLS_CLOSE_WAIT_PEER;
            if (returned == 1) {
                io->read_eof = true;
                io->read_retry_bytes = 0;
                io->read_wait = VIREO_TLS_IO_WAIT_NONE;
            }
            diagnostic = (vireo_tls_connection_error_t){0};
        } else if (returned < 0 && (classification == SSL_ERROR_WANT_READ || classification == SSL_ERROR_WANT_WRITE)) {
            close->shutdown_wait = classification == SSL_ERROR_WANT_READ ?
                VIREO_TLS_IO_WAIT_READ : VIREO_TLS_IO_WAIT_WRITE;
            progress.stop_reason = VIREO_TLS_CLOSE_STOP_WANT;
            diagnostic = (vireo_tls_connection_error_t){0};
        } else {
            diagnostic.stage = VIREO_TLS_CONNECTION_STAGE_CLOSE;
            if (returned < 0 && classification == SSL_ERROR_SYSCALL) {
                result = VIREO_RESULT_IO; diagnostic.system_errno = native_errno;
            } else if (returned < 0 && classification == SSL_ERROR_SSL) {
                result = oom ? VIREO_RESULT_NO_MEMORY : VIREO_RESULT_PROTOCOL;
            } else if (returned < 0 && classification == SSL_ERROR_ZERO_RETURN) {
                result = VIREO_RESULT_PROTOCOL;
            } else { result = VIREO_RESULT_INTERNAL; }
            fail(connection, result, diagnostic);
            progress.stop_reason = VIREO_TLS_CLOSE_STOP_ERROR;
        }
    }
    close->last_now_ns = now;
    if (close->state == VIREO_TLS_CLOSE_COMPLETE) {
        vireo_tls_io_clear_scratch(io);
        progress.stop_reason = VIREO_TLS_CLOSE_STOP_COMPLETE;
    }
    progress.info = snapshot(connection);
    *out_progress = progress;
    return finish(error, diagnostic, result, saved_errno, true);
}

vireo_result_t vireo_tls_connection_close_step_at(vireo_tls_connection_t *connection,
    vireo_monotonic_ns_t now, size_t max_bytes, vireo_tls_close_progress_t *out_progress,
    vireo_tls_connection_error_t *error)
{
    vireo_tls_close_ops_t ops = {vireo_tls_io_native_ops, native_shutdown};
    return vireo_tls_connection_close_with_ops(connection, now, max_bytes, out_progress, error, &ops);
}
