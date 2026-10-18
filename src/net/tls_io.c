/*
- PROJECT : VIREO
- FILE    : tls_io.c
- AUTHOR  : bitofux
- DATE    : 2026-10-17
- BRIEF   : 此模块负责：固定明文FIFO、稳定原生重试、独立失败与纯flow建议
 */
#define _POSIX_C_SOURCE 200809L
#include "tls_connection_internal.h"

#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/err.h>
#include <vireo/base/checked.h>

/**
 * @brief 提交独立诊断并恢复入口errno
 * @param[out] error 可空独立输出。
 * @param[in] diagnostic 已保存的本次诊断值。
 * @param[in] result 已确定的返回分类。
 * @param[in] saved_errno 外层入口errno。
 * @return 原result，不清库队列，纯参数拒绝可保持旧原因。
 * @note 不保存任何caller地址，不分配或执行网络。
 */
static vireo_result_t finish(vireo_tls_connection_error_t *error,
    vireo_tls_connection_error_t diagnostic, vireo_result_t result, int saved_errno)
{
    if (error != NULL) { *error = diagnostic; }
    errno = saved_errno;
    return result;
}

/**
 * @brief 清本次库队列再提交诊断
 * @param[out] error 可空独立输出。
 * @param[in] diagnostic 清理前已保存的值诊断。
 * @param[in] result 本次分类。
 * @param[in] saved_errno 外层入口errno。
 * @return 原result，errno恢复为入口值。
 * @note 仅适用通过基本参数/预算检查之后；不改变主报告。
 */
static vireo_result_t done(vireo_tls_connection_error_t *error,
    vireo_tls_connection_error_t diagnostic, vireo_result_t result, int saved_errno)
{
    ERR_clear_error();
    return finish(error, diagnostic, result, saved_errno);
}

/**
 * @brief 分类完成后消费本次错误队列并保存独立原因
 * @param[in,out] error 非空本次局部诊断，stage已设置。
 * @retval true 队列含明确malloc failure。
 * @retval false 没有明确OOM，不猜造库原因。
 * @note 只有SSL类错误可依据true改变结果；SYSCALL优先保存即时errno。
 */
static bool capture(vireo_tls_connection_error_t *error)
{
    bool oom = false;
    unsigned long code;
    while ((code = ERR_get_error()) != 0) {
        if (error->openssl_error_code == 0) { error->openssl_error_code = (uint64_t)code; }
        else { error->has_more_errors = true; }
        if (ERR_GET_REASON(code) == ERR_R_MALLOC_FAILURE) { oom = true; }
    }
    return oom;
}

/**
 * @brief 申请单个固定暂存字节区
 * @param[in] context 生产不用，允许NULL。
 * @param[in] size 正字节数。
 * @return malloc唯一owner或NULL；成功交给原deallocate配对。
 * @note 不初始化字节；外层保持errno，失败不发布应用资源。
 */
static void *allocate(void *context, size_t size) { (void)context; return malloc(size); }
/**
 * @brief 配对释放固定暂存
 * @param[in] context 生产不用，允许NULL。
 * @param[in] pointer 本allocator取得的唯一非空区域，释放后不可访问。
 * @note 无失败返回；errno由公共外层恢复。
 */
static void deallocate(void *context, void *pointer) { (void)context; free(pointer); }
/**
 * @brief 通过公开buffer入口建立固定FIFO
 * @param[in] context 生产不用，允许NULL。
 * @param[in] size 已通过本层容量预算检查的正字节数。
 * @param[in,out] out 必需独立空owner，成功发布。
 * @retval VIREO_OK 完整取得buffer owner。
 * @retval VIREO_RESULT_NO_MEMORY 公开buffer资源申请失败，空owner保持。
 * @note 其他参数结果由本层已检查不变量排除；不使用base私有布局。
 */
static vireo_result_t buffer_create(void *context, size_t size, vireo_buffer_t **out)
{ (void)context; return vireo_buffer_create(size, out); }
/**
 * @brief 通过公开buffer入口配对释放FIFO
 * @param[in] context 生产不用，允许NULL。
 * @param[in,out] owner 非空独立owner，资源释放并置NULL。
 * @note 仅内部清理调用，已结束全部view；公开destroy在此不可能拒绝。
 */
static void buffer_destroy(void *context, vireo_buffer_t **owner)
{ (void)context; (void)vireo_buffer_destroy(owner); }

/**
 * @brief 归一化本SSL的重试及EOF策略，不修改共享SSL_CTX
 * @param[in] context 生产不用，允许NULL。
 * @param[in,out] native 非空本连接SSL owner，串行调用。
 * @retval true 原生getter确认完整策略。
 * @retval false getter不满足策略；caller回滚固定缓冲资源。
 * @note 无网络/申请，禁partial/moving/ignoreEOF，开AUTO_RETRY并关闭read_ahead。
 */
static bool prepare(void *context, SSL *native)
{
    (void)context;
    long disabled = SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER;
    (void)SSL_clear_mode(native, disabled);
    (void)SSL_set_mode(native, SSL_MODE_AUTO_RETRY);
    SSL_set_read_ahead(native, 0);
    SSL_set_quiet_shutdown(native, 0);
    (void)SSL_clear_options(native, SSL_OP_IGNORE_UNEXPECTED_EOF);
    return (SSL_get_mode(native) & disabled) == 0 &&
        (SSL_get_mode(native) & SSL_MODE_AUTO_RETRY) != 0 && SSL_get_read_ahead(native) == 0 &&
        (SSL_get_options(native) & SSL_OP_IGNORE_UNEXPECTED_EOF) == 0 &&
        SSL_get_quiet_shutdown(native) == 0;
}

static vireo_tls_io_config_ops_t const config_ops = {
    NULL, allocate, deallocate, buffer_create, buffer_destroy, prepare
};

/** 可处理部分候选；逆序释放，buffer遵循公开owner合同，scratch使用原配对allocator。 */
void vireo_tls_io_release(vireo_tls_io_storage_t *io)
{
    vireo_tls_io_config_ops_t resources = io->resources;
    if (io->write_scratch != NULL) { resources.deallocate(resources.context, io->write_scratch); }
    if (io->read_scratch != NULL) { resources.deallocate(resources.context, io->read_scratch); }
    if (io->write_buffer != NULL) { resources.buffer_destroy(resources.context, &io->write_buffer); }
    if (io->read_buffer != NULL) { resources.buffer_destroy(resources.context, &io->read_buffer); }
    *io = (vireo_tls_io_storage_t){0};
}

/**
 * @brief 共用固定资源构造，按入口阶段一次发布PREPARED或OPEN
 *
 * @param[in,out] connection 存活串行对象，失败保持原I/O资源及握手/期限状态。
 * @param[in] options 独立稳定配置，成功值复制。
 * @param[out] error 可空独立诊断，外层同公共合同。
 * @param[in] ops 完整本模块资源表，成功后按值保活至资源释放。
 * @param[in] preparing true只允许首次握手前；false沿旧握手后configure。
 *
 * @return 沿公共prepare/configure分类，无部分发布。
 * @note 无网络；SSL策略设置沿原配置规则，不承诺native逐字节回滚。保持errno。
 */
static vireo_result_t io_setup(vireo_tls_connection_t *connection,
    vireo_tls_io_options_t const *options, vireo_tls_connection_error_t *error,
    vireo_tls_io_config_ops_t const *ops, bool preparing)
{
    int saved_errno = errno;
    vireo_tls_connection_error_t diagnostic = {0};
    if (connection == NULL || options == NULL || ops == NULL || ops->allocate == NULL ||
        ops->deallocate == NULL || ops->buffer_create == NULL || ops->buffer_destroy == NULL ||
        ops->prepare == NULL) {
        return finish(error, diagnostic, VIREO_RESULT_INVALID_ARGUMENT, saved_errno);
    }
    size_t total = 0;
    vireo_result_t result = vireo_checked_size_add(options->read_capacity, options->write_capacity, &total);
    if (result == VIREO_OK) {
        result = vireo_checked_size_add(total, 2 * VIREO_TLS_IO_SCRATCH_BYTES, &total);
    }
    if (result != VIREO_OK) { return finish(error, diagnostic, result, saved_errno); }
    if (options->read_capacity == 0 || options->write_capacity == 0 || options->max_buffer_bytes == 0 ||
        options->max_read_unit_bytes == 0 || options->read_low >= options->read_high ||
        options->write_low >= options->write_high) {
        return finish(error, diagnostic, VIREO_RESULT_RANGE, saved_errno);
    }
    if (total > options->max_buffer_bytes || options->max_buffer_bytes > VIREO_TLS_IO_MAX_BUFFER_BYTES ||
        options->max_read_unit_bytes > options->read_capacity ||
        options->read_low < options->max_read_unit_bytes - 1 ||
        options->read_high > options->read_capacity || options->write_high > options->write_capacity) {
        return finish(error, diagnostic, VIREO_RESULT_RANGE, saved_errno);
    }
    ERR_clear_error();
    bool stage_allowed = preparing
        ? connection->state == VIREO_TLS_HANDSHAKE_INITIAL && !connection->handshake_native_attempted
        : connection->state == VIREO_TLS_HANDSHAKE_ESTABLISHED;
    if (!stage_allowed || connection->io.state != VIREO_TLS_IO_DISABLED) {
        return done(error, diagnostic, VIREO_RESULT_BUSY, saved_errno);
    }
    diagnostic.stage = VIREO_TLS_CONNECTION_STAGE_CONFIGURE_IO;
    vireo_tls_io_storage_t candidate = {.options = *options, .buffer_bytes = total, .resources = *ops};
    result = ops->buffer_create(ops->context, options->read_capacity, &candidate.read_buffer);
    if (result == VIREO_OK) {
        result = ops->buffer_create(ops->context, options->write_capacity, &candidate.write_buffer);
    }
    if (result == VIREO_OK) {
        candidate.read_scratch = ops->allocate(ops->context, VIREO_TLS_IO_SCRATCH_BYTES);
        if (candidate.read_scratch == NULL) { result = VIREO_RESULT_NO_MEMORY; }
    }
    if (result == VIREO_OK) {
        candidate.write_scratch = ops->allocate(ops->context, VIREO_TLS_IO_SCRATCH_BYTES);
        if (candidate.write_scratch == NULL) { result = VIREO_RESULT_NO_MEMORY; }
    }
    if (result == VIREO_OK && !ops->prepare(ops->context, connection->native)) {
        bool oom = capture(&diagnostic);
        result = oom ? VIREO_RESULT_NO_MEMORY : VIREO_RESULT_INTERNAL;
    }
    if (result == VIREO_OK) {
        candidate.state = preparing ? VIREO_TLS_IO_PREPARED : VIREO_TLS_IO_OPEN;
        connection->io = candidate;
        diagnostic = (vireo_tls_connection_error_t){0};
    } else {
        vireo_tls_io_release(&candidate);
    }
    return done(error, diagnostic, result, saved_errno);
}

vireo_result_t vireo_tls_connection_io_configure_with_ops(vireo_tls_connection_t *connection,
    vireo_tls_io_options_t const *options, vireo_tls_connection_error_t *error,
    vireo_tls_io_config_ops_t const *ops)
{ return io_setup(connection, options, error, ops, false); }

vireo_result_t vireo_tls_connection_io_prepare_with_ops(vireo_tls_connection_t *connection,
    vireo_tls_io_options_t const *options, vireo_tls_connection_error_t *error,
    vireo_tls_io_config_ops_t const *ops)
{ return io_setup(connection, options, error, ops, true); }

vireo_result_t vireo_tls_connection_io_configure(vireo_tls_connection_t *connection,
    vireo_tls_io_options_t const *options, vireo_tls_connection_error_t *error)
{ return vireo_tls_connection_io_configure_with_ops(connection, options, error, &config_ops); }

vireo_result_t vireo_tls_connection_io_prepare(vireo_tls_connection_t *connection,
    vireo_tls_io_options_t const *options, vireo_tls_connection_error_t *error)
{ return vireo_tls_connection_io_prepare_with_ops(connection, options, error, &config_ops); }

/**
 * @brief 通过公开快照取得已配置FIFO占用
 * @param[in] buffer 非空存活且本对象独占的buffer。
 * @return 当前可读字节，不授予任何数据地址或未来容量权限。
 * @note 调用者保证owner不变量；不分配、不改view/errno。
 */
static size_t readable(vireo_buffer_t const *buffer)
{
    vireo_buffer_info_t info = {0};
    (void)vireo_buffer_inspect(buffer, &info);
    return info.readable_size;
}

vireo_result_t vireo_tls_connection_io_inspect(vireo_tls_connection_t const *connection,
    vireo_tls_io_info_t *out_info, vireo_tls_connection_error_t *error)
{
    int saved_errno = errno;
    vireo_tls_connection_error_t diagnostic = {0};
    if (connection == NULL || out_info == NULL) {
        return finish(error, diagnostic, VIREO_RESULT_INVALID_ARGUMENT, saved_errno);
    }
    ERR_clear_error();
    vireo_tls_io_storage_t const *io = &connection->io;
    vireo_tls_io_info_t info = {
        .state = io->state, .read_eof = io->read_eof, .options = io->options,
        .buffer_bytes = io->buffer_bytes, .read_retry_bytes = io->read_retry_bytes,
        .write_retry_bytes = io->write_retry_bytes,
        .read_wait = io->read_wait, .write_wait = io->write_wait
    };
    if (io->read_buffer != NULL) {
        (void)vireo_buffer_inspect(io->read_buffer, &info.read_buffer);
        (void)vireo_buffer_inspect(io->write_buffer, &info.write_buffer);
    }
    info.read_size = info.read_buffer.readable_size;
    info.write_size = info.write_buffer.readable_size;
    *out_info = info;
    return done(error, diagnostic, VIREO_OK, saved_errno);
}

vireo_result_t vireo_tls_connection_read_peek(vireo_tls_connection_t const *connection,
    uint8_t const **out_data, size_t *out_size, vireo_tls_connection_error_t *error)
{
    int saved_errno = errno;
    vireo_tls_connection_error_t diagnostic = {0};
    if (connection == NULL || out_data == NULL || out_size == NULL) {
        return finish(error, diagnostic, VIREO_RESULT_INVALID_ARGUMENT, saved_errno);
    }
    ERR_clear_error();
    vireo_result_t result = (connection->io.state == VIREO_TLS_IO_DISABLED ||
        connection->io.state == VIREO_TLS_IO_PREPARED) ? VIREO_RESULT_BUSY :
        vireo_buffer_peek(connection->io.read_buffer, out_data, out_size);
    return done(error, diagnostic, result, saved_errno);
}

vireo_result_t vireo_tls_connection_read_consume(vireo_tls_connection_t *connection,
    size_t size, vireo_tls_connection_error_t *error)
{
    int saved_errno = errno;
    vireo_tls_connection_error_t diagnostic = {0};
    if (connection == NULL) {
        return finish(error, diagnostic, VIREO_RESULT_INVALID_ARGUMENT, saved_errno);
    }
    ERR_clear_error();
    vireo_result_t result = (connection->io.state == VIREO_TLS_IO_DISABLED ||
        connection->io.state == VIREO_TLS_IO_PREPARED) ? VIREO_RESULT_BUSY :
        vireo_buffer_consume(connection->io.read_buffer, size);
    return done(error, diagnostic, result, saved_errno);
}

vireo_result_t vireo_tls_connection_enqueue(vireo_tls_connection_t *connection,
    uint8_t const *data, size_t size, vireo_tls_connection_error_t *error)
{
    int saved_errno = errno;
    vireo_tls_connection_error_t diagnostic = {0};
    if (connection == NULL || (size != 0 && data == NULL)) {
        return finish(error, diagnostic, VIREO_RESULT_INVALID_ARGUMENT, saved_errno);
    }
    ERR_clear_error();
    if (connection->close.state != VIREO_TLS_CLOSE_NONE) {
        return done(error, connection->close.failure_error,
            connection->close.state == VIREO_TLS_CLOSE_FAILED ? connection->close.failure_result : VIREO_RESULT_BUSY,
            saved_errno);
    }
    vireo_tls_io_storage_t *io = &connection->io;
    if (io->state == VIREO_TLS_IO_DISABLED || io->state == VIREO_TLS_IO_PREPARED) {
        return done(error, diagnostic, VIREO_RESULT_BUSY, saved_errno);
    }
    if (io->state == VIREO_TLS_IO_FAILED) {
        return done(error, io->failure_error, io->failure_result, saved_errno);
    }
    size_t total = 0;
    vireo_result_t result = vireo_checked_size_add(readable(io->write_buffer), size, &total);
    if (result == VIREO_OK && total > io->options.write_capacity) { result = VIREO_RESULT_RANGE; }
    if (result == VIREO_OK) {
        vireo_buffer_info_t info;
        (void)vireo_buffer_inspect(io->write_buffer, &info);
        if (size > info.tail_space) { (void)vireo_buffer_compact(io->write_buffer); }
        result = vireo_buffer_append(io->write_buffer, data, size);
    }
    return done(error, diagnostic, result, saved_errno);
}

/**
 * @brief 实际原生前只读查询SIGPIPE进程策略
 * @param[in] context 生产不用，允许NULL。
 * @param[out] out_ignored 必需局部bool，系统成功才写。
 * @retval 0 查询成功，bool区分是否SIG_IGN。
 * @retval -1 系统查询失败，errno由外层即时保存。
 * @note 不修改disposition、mask、pending，不触OpenSSL队列。
 */
static int sigpipe_ignored(void *context, bool *out_ignored)
{
    (void)context;
    struct sigaction action;
    int result = sigaction(SIGPIPE, NULL, &action);
    if (result == 0) { *out_ignored = action.sa_handler == SIG_IGN; }
    return result;
}
/**
 * @brief 一次原生读取到稳定read暂存
 * @param[in] context 生产不用，允许NULL。
 * @param[in,out] native 存活串行SSL。
 * @param[in,out] data 长度size的自有可写字节区，WANT跨调用保活。
 * @param[in] size 正数，最多16KiB；重试不变。
 * @param[out] out_size 独立局部确认长度，成功才可信。
 * @retval 1 成功，外层检查确认长度。
 * @retval 0 失败/等待，外层先保存errno再立即分类。
 * @note 不在原生返回与分类之间插入任何OpenSSL操作。
 */
static int read_ex(void *context, SSL *native, void *data, size_t size, size_t *out_size)
{ (void)context; return SSL_read_ex(native, data, size, out_size); }
/**
 * @brief 一次原生发送稳定write快照
 * @param[in] context 生产不用，允许NULL。
 * @param[in,out] native 存活串行SSL。
 * @param[in] data 长度size的自有只读字节区，WANT跨调用保活。
 * @param[in] size 正数，最多16KiB；重试不变。
 * @param[out] out_size 独立局部确认长度，成功才可信。
 * @retval 1 成功，外层检查确认长度。
 * @retval 0 失败/等待，外层先保存errno再立即分类。
 * @note 不在原生返回与分类之间插入任何OpenSSL操作。
 */
static int write_ex(void *context, SSL *native, void const *data, size_t size, size_t *out_size)
{ (void)context; return SSL_write_ex(native, data, size, out_size); }
/**
 * @brief 紧邻同线程原生失败进行SSL_get_error分类
 * @param[in] context 生产不用，允许NULL。
 * @param[in] native 上次原生操作的同一SSL。
 * @param[in] returned 该次原始返回值，不转换。
 * @return 原生SSL_ERROR分类，外层处理支持范围。
 * @note errno必须已保存；回调可改变errno，但不得在分类前触库队列。
 */
static int get_error(void *context, SSL *native, int returned)
{ (void)context; return SSL_get_error(native, returned); }
vireo_tls_io_ops_t const vireo_tls_io_native_ops = {NULL, sigpipe_ignored, read_ex, write_ex, get_error};

/**
 * @brief 保存独立应用首fatal并停止本地续调度
 * @param[in,out] io 非空OPEN存储，本次才第一次fatal。
 * @param[in] result 非OK原生失败分类。
 * @param[in] diagnostic 清理前保存的值诊断。
 * @note 不改握手四态/缓存，不释放明文；快照留到destroy，不再网络重试。
 */
static void fail(vireo_tls_io_storage_t *io, vireo_result_t result,
    vireo_tls_connection_error_t diagnostic)
{
    io->state = VIREO_TLS_IO_FAILED;
    io->failure_result = result;
    io->failure_error = diagnostic;
    io->resume_read = false;
    io->resume_write = false;
}

/** 两个正值取小，避免不必要的带符号窄化。 */
static size_t smaller(size_t left, size_t right) { return left < right ? left : right; }

/**
 * @brief 同一有界驱动核心，网络确认不回滚，原生前拒绝不提交主报告
 * @param[in,out] connection 已完成握手并配置的独占对象。
 * @param[in] budget 稳定正预算；重试长度在原生/信号查询前校验。
 * @param[out] out_progress 独立输出，只在正常停止/已发生原生调用时提交。
 * @param[out] error 可空独立诊断。
 * @param[in] writing true发送，false接收。
 * @param[in] ops 完整短借表，原生失败后只允许保存errno再紧邻分类。
 * @return 正常停止OK；参数/信号拒绝可恢复，原生fatal永久首错。
 * @note read/write独立暂存；优先write WANT，再read WANT_WRITE；read WANT_READ不锁send。
 */
static vireo_result_t io_drive(vireo_tls_connection_t *connection,
    vireo_tls_io_budget_t const *budget, vireo_tls_io_progress_t *out_progress,
    vireo_tls_connection_error_t *error, bool writing, vireo_tls_io_ops_t const *ops, bool closing)
{
    int saved_errno = errno;
    vireo_tls_connection_error_t diagnostic = {0};
    if (connection == NULL || budget == NULL || out_progress == NULL || ops == NULL || ops->sigpipe_ignored == NULL ||
        ops->read_ex == NULL || ops->write_ex == NULL || ops->get_error == NULL) {
        return finish(error, diagnostic, VIREO_RESULT_INVALID_ARGUMENT, saved_errno);
    }
    if (budget->max_bytes == 0 || budget->max_native_calls == 0) {
        return finish(error, diagnostic, VIREO_RESULT_RANGE, saved_errno);
    }
    if (!closing && connection->close.state != VIREO_TLS_CLOSE_NONE) {
        return done(error, connection->close.failure_error,
            connection->close.state == VIREO_TLS_CLOSE_FAILED ? connection->close.failure_result : VIREO_RESULT_BUSY,
            saved_errno);
    }
    vireo_tls_io_storage_t *io = &connection->io;
    size_t *retry = writing ? &io->write_retry_bytes : &io->read_retry_bytes;
    vireo_tls_io_wait_t *wait = writing ? &io->write_wait : &io->read_wait;
    if (io->state == VIREO_TLS_IO_OPEN && *retry > budget->max_bytes) {
        return finish(error, diagnostic, VIREO_RESULT_RANGE, saved_errno);
    }
    ERR_clear_error();
    if (io->state == VIREO_TLS_IO_DISABLED || io->state == VIREO_TLS_IO_PREPARED) {
        return done(error, diagnostic, VIREO_RESULT_BUSY, saved_errno);
    }
    vireo_tls_io_progress_t progress = {0, 0, VIREO_TLS_IO_STOP_ERROR, VIREO_TLS_IO_WAIT_NONE};
    if (io->state == VIREO_TLS_IO_FAILED) {
        *out_progress = progress;
        return done(error, io->failure_error, io->failure_result, saved_errno);
    }
    if ((!writing && io->write_retry_bytes != 0) ||
        (writing && io->read_wait == VIREO_TLS_IO_WAIT_WRITE)) {
        progress.stop_reason = VIREO_TLS_IO_STOP_RETRY_OTHER;
        *out_progress = progress;
        return done(error, diagnostic, VIREO_OK, saved_errno);
    }
    bool *resume = writing ? &io->resume_write : &io->resume_read;
    uint8_t *scratch = writing ? io->write_scratch : io->read_scratch;
    vireo_buffer_t *buffer = writing ? io->write_buffer : io->read_buffer;
    vireo_result_t result = VIREO_OK;
    for (;;) {
        size_t queued = readable(buffer);
        if (!writing && io->read_eof) { progress.stop_reason = VIREO_TLS_IO_STOP_PEER_EOF; *resume = false; break; }
        if (*retry == 0 && (writing ? queued == 0 : queued == io->options.read_capacity)) {
            progress.stop_reason = writing ? VIREO_TLS_IO_STOP_BUFFER_EMPTY : VIREO_TLS_IO_STOP_BUFFER_FULL;
            *resume = false; break;
        }
        if (!closing && !writing && *retry == 0 && (io->read_pressure || io->write_pressure)) {
            progress.stop_reason = VIREO_TLS_IO_STOP_FLOW_PAUSED; *resume = false; break;
        }
        if (progress.bytes == budget->max_bytes || progress.native_calls == budget->max_native_calls) {
            progress.stop_reason = progress.bytes == budget->max_bytes ?
                VIREO_TLS_IO_STOP_BYTE_BUDGET : VIREO_TLS_IO_STOP_CALL_BUDGET;
            *resume = true; break;
        }
        size_t length = *retry;
        if (length == 0) {
            length = smaller(budget->max_bytes - progress.bytes, VIREO_TLS_IO_SCRATCH_BYTES);
            length = smaller(length, writing ? queued : io->options.read_capacity - queued);
        }
        /* 任何新请求只在信号策略通过后才锁定，拒绝不制造虚假pending。 */
        bool ignored = false;
        int queried = ops->sigpipe_ignored(ops->context, &ignored);
        int query_errno = errno;
        if (queried != 0 || !ignored) {
            diagnostic.stage = VIREO_TLS_CONNECTION_STAGE_SIGNAL_POLICY;
            diagnostic.system_errno = queried == -1 ? query_errno : 0;
            result = queried == -1 ? VIREO_RESULT_IO :
                (queried != 0 ? VIREO_RESULT_INTERNAL : VIREO_RESULT_INVALID_ARGUMENT);
            if (progress.native_calls != 0) { progress.stop_reason = VIREO_TLS_IO_STOP_ERROR; *out_progress = progress; }
            return done(error, diagnostic, result, saved_errno);
        }
        if (*retry == 0) {
            if (writing) {
                uint8_t const *data; size_t size;
                (void)vireo_buffer_peek(buffer, &data, &size);
                memcpy(scratch, data, length);
            }
            *retry = length;
        }
        ERR_clear_error();
        errno = 0;
        size_t confirmed = 0;
        int returned = writing ? ops->write_ex(ops->context, connection->native, scratch, length, &confirmed) :
            ops->read_ex(ops->context, connection->native, scratch, length, &confirmed);
        int native_errno = errno;
        int classification = returned != 1 ? ops->get_error(ops->context, connection->native, returned) : SSL_ERROR_NONE;
        /* 现在才可触碰库队列/getter或提交本层状态。 */
        ++progress.native_calls;
        *resume = false;
        diagnostic.stage = writing ? VIREO_TLS_CONNECTION_STAGE_SEND : VIREO_TLS_CONNECTION_STAGE_RECEIVE;
        bool oom = capture(&diagnostic);
        if (returned == 1 && confirmed > 0 && confirmed <= length && (!writing || confirmed == length)) {
            if (writing) { result = vireo_buffer_consume(buffer, confirmed); }
            else {
                vireo_buffer_info_t info;
                (void)vireo_buffer_inspect(buffer, &info);
                if (info.tail_space < confirmed) { (void)vireo_buffer_compact(buffer); }
                result = vireo_buffer_append(buffer, scratch, confirmed);
            }
            *retry = 0; *wait = VIREO_TLS_IO_WAIT_NONE;
            if (result != VIREO_OK) { result = VIREO_RESULT_INTERNAL; }
            else {
                progress.bytes += confirmed;
                diagnostic = (vireo_tls_connection_error_t){0};
                continue;
            }
        } else if (returned == 0 && (classification == SSL_ERROR_WANT_READ || classification == SSL_ERROR_WANT_WRITE)) {
            *wait = classification == SSL_ERROR_WANT_READ ? VIREO_TLS_IO_WAIT_READ : VIREO_TLS_IO_WAIT_WRITE;
            progress.wait = *wait;
            progress.stop_reason = VIREO_TLS_IO_STOP_WOULD_BLOCK;
            diagnostic = (vireo_tls_connection_error_t){0};
            break;
        } else if (returned == 0 && classification == SSL_ERROR_ZERO_RETURN && !writing) {
            io->read_eof = true; *retry = 0; *wait = VIREO_TLS_IO_WAIT_NONE;
            progress.stop_reason = VIREO_TLS_IO_STOP_PEER_EOF;
            diagnostic = (vireo_tls_connection_error_t){0};
            break;
        } else if (returned == 0 && classification == SSL_ERROR_SYSCALL) {
            result = VIREO_RESULT_IO; diagnostic.system_errno = native_errno;
        } else if (returned == 0 && classification == SSL_ERROR_SSL) {
            result = oom ? VIREO_RESULT_NO_MEMORY : VIREO_RESULT_PROTOCOL;
        } else if (returned == 0 && classification == SSL_ERROR_ZERO_RETURN) {
            result = VIREO_RESULT_PROTOCOL;
        } else { result = VIREO_RESULT_INTERNAL; }
        fail(io, result, diagnostic);
        progress.stop_reason = VIREO_TLS_IO_STOP_ERROR;
        break;
    }
    *out_progress = progress;
    return done(error, diagnostic, result, saved_errno);
}

vireo_result_t vireo_tls_connection_io_with_ops(vireo_tls_connection_t *connection,
    vireo_tls_io_budget_t const *budget, vireo_tls_io_progress_t *out_progress,
    vireo_tls_connection_error_t *error, bool writing, vireo_tls_io_ops_t const *ops)
{ return io_drive(connection, budget, out_progress, error, writing, ops, false); }

vireo_result_t vireo_tls_connection_io_closing_with_ops(vireo_tls_connection_t *connection,
    vireo_tls_io_budget_t const *budget, vireo_tls_io_progress_t *out_progress,
    vireo_tls_connection_error_t *error, bool writing, vireo_tls_io_ops_t const *ops)
{ return io_drive(connection, budget, out_progress, error, writing, ops, true); }

vireo_result_t vireo_tls_connection_receive(vireo_tls_connection_t *connection,
    vireo_tls_io_budget_t const *budget, vireo_tls_io_progress_t *out_progress, vireo_tls_connection_error_t *error)
{ return vireo_tls_connection_io_with_ops(connection, budget, out_progress, error, false, &vireo_tls_io_native_ops); }

vireo_result_t vireo_tls_connection_send(vireo_tls_connection_t *connection,
    vireo_tls_io_budget_t const *budget, vireo_tls_io_progress_t *out_progress, vireo_tls_connection_error_t *error)
{ return vireo_tls_connection_io_with_ops(connection, budget, out_progress, error, true, &vireo_tls_io_native_ops); }

/** 唯一迟滞更新点，等号按明确阈值处理；中间区保留历史。 */
static bool pressure(bool current, size_t size, size_t low, size_t high)
{ return size >= high ? true : (size <= low ? false : current); }

vireo_result_t vireo_tls_connection_flow_refresh(vireo_tls_connection_t *connection,
    vireo_tls_io_flow_t *out_flow, vireo_tls_connection_error_t *error)
{
    int saved_errno = errno;
    vireo_tls_connection_error_t diagnostic = {0};
    if (connection == NULL || out_flow == NULL) {
        return finish(error, diagnostic, VIREO_RESULT_INVALID_ARGUMENT, saved_errno);
    }
    ERR_clear_error();
    if (connection->close.state != VIREO_TLS_CLOSE_NONE) {
        return done(error, diagnostic, VIREO_RESULT_BUSY, saved_errno);
    }
    vireo_tls_io_storage_t *io = &connection->io;
    vireo_tls_io_flow_t flow = {0};
    if (io->state != VIREO_TLS_IO_DISABLED && io->state != VIREO_TLS_IO_PREPARED) {
        size_t read_size = readable(io->read_buffer), write_size = readable(io->write_buffer);
        io->read_pressure = pressure(io->read_pressure, read_size, io->options.read_low, io->options.read_high);
        io->write_pressure = pressure(io->write_pressure, write_size, io->options.write_low, io->options.write_high);
        flow.read_pressure = io->read_pressure; flow.write_pressure = io->write_pressure;
        if (io->state == VIREO_TLS_IO_OPEN) {
            flow.application_read_enabled = !io->read_eof && !io->read_pressure && !io->write_pressure &&
                io->write_retry_bytes == 0 && io->read_wait != VIREO_TLS_IO_WAIT_WRITE;
            if (io->write_retry_bytes != 0 || io->read_wait == VIREO_TLS_IO_WAIT_WRITE) {
                bool writing = io->write_retry_bytes != 0;
                flow.priority_retry = writing ? VIREO_TLS_IO_OPERATION_WRITE : VIREO_TLS_IO_OPERATION_READ;
                vireo_tls_io_wait_t wait = writing ? io->write_wait : io->read_wait;
                flow.want_read = wait == VIREO_TLS_IO_WAIT_READ;
                flow.want_write = wait == VIREO_TLS_IO_WAIT_WRITE;
            } else {
                flow.want_read = flow.application_read_enabled;
                flow.want_write = write_size != 0;
                flow.resume_read = flow.application_read_enabled &&
                    (io->resume_read || SSL_pending(connection->native) > 0);
                flow.resume_write = write_size != 0 && io->resume_write;
            }
        }
    }
    *out_flow = flow;
    return done(error, diagnostic, VIREO_OK, saved_errno);
}
