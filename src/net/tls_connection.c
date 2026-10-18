/*
- PROJECT : VIREO
- FILE    : tls_connection.c
- AUTHOR  : bitofux
- DATE    : 2026-10-17
- BRIEF   : 此模块负责：
- -- 服务器SSL资源、NOCLOSE借用、非阻塞握手状态与配对回滚
 */
#define _POSIX_C_SOURCE 200809L
#include "tls_connection_internal.h"
#include "tls_context_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <openssl/err.h>

_Static_assert(sizeof(unsigned long) <= sizeof(uint64_t), "OpenSSL error code must fit uint64_t");

/** 标准配对allocator；errno由公共外层恢复。 */
static void *system_allocate(void *context, size_t bytes)
{
    (void)context;
    return malloc(bytes);
}

/** 只释放本层唯一区域。 */
static void system_deallocate(void *context, void *pointer)
{
    (void)context;
    free(pointer);
}

/** 只读查询，不修改flags，不隐式重试。 */
static int system_get_flags(void *context, int fd, int command)
{
    (void)context;
    return fcntl(fd, command);
}

/** SO_TYPE查询使用独立局部值，系统成功后才发布。 */
static int system_socket_type(void *context, int fd, int *out_type)
{
    (void)context;
    int type = 0;
    socklen_t size = (socklen_t)sizeof(type);
    int result = getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &size);
    if (result == 0) {
        *out_type = type;
    }
    return result;
}

/** 只确认已连接，不保存peer地址或输出可能含敏感信息的端点。 */
static int system_peer_connected(void *context, int fd)
{
    (void)context;
    struct sockaddr_storage peer;
    socklen_t size = (socklen_t)sizeof(peer);
    return getpeername(fd, (struct sockaddr *)&peer, &size);
}

/** SSL_new取得自身native context引用，不保存Vireo包装地址。 */
static SSL *system_create_native(void *context, SSL_CTX *native_context)
{
    (void)context;
    return SSL_new(native_context);
}

/** 新BIO只借socket；SSL_free/BIO_free均不close借用fd。 */
static BIO *system_create_bio(void *context, int borrowed_fd)
{
    (void)context;
    return BIO_new_socket(borrowed_fd, BIO_NOCLOSE);
}

static vireo_tls_connection_ops_t const system_ops = {
    NULL, system_allocate, system_deallocate, system_get_flags, system_socket_type,
    system_peer_connected, system_create_native, system_create_bio
};

/** 只查询进程策略，不设置handler、mask或pending；成功后才发布bool。 */
static int system_sigpipe_ignored(void *context, bool *out_ignored)
{
    (void)context;
    struct sigaction action;
    int result = sigaction(SIGPIPE, NULL, &action);
    if (result == 0) {
        *out_ignored = action.sa_handler == SIG_IGN;
    }
    return result;
}

/** 调用数边界为一次库握手，内部密码计算/网络字节量由OpenSSL决定。 */
static int system_do_handshake(void *context, SSL *native)
{
    (void)context;
    return SSL_do_handshake(native);
}

/** 与上次原生调用同线程紧邻，不得在外层插入任何其他OpenSSL函数。 */
static int system_handshake_error(void *context, SSL *native, int returned)
{
    (void)context;
    return SSL_get_error(native, returned);
}

static vireo_tls_handshake_ops_t const system_handshake_ops = {
    NULL, system_sigpipe_ignored, system_do_handshake, system_handshake_error
};

/** 保存独立诊断并恢复入口errno；纯参数拒绝不触库队列。 */
static vireo_result_t finish(vireo_tls_connection_error_t *error,
    vireo_tls_connection_error_t diagnostic, vireo_result_t result, int saved_errno)
{
    if (error != NULL) {
        *error = diagnostic;
    }
    errno = saved_errno;
    return result;
}

/**
 * @brief 立即消费本次库原因，避免随后资源清理覆盖主诊断
 *
 * @param[in,out] diagnostic
 *     当前局部诊断，stage已设置，首码与多码事实独立保存。
 * @param[in] fallback
 *     无明确OOM时的保守分类。
 *
 * @return
 *     明确malloc failure为NO_MEMORY，否则保留fallback。
 *
 * @note 不保存错误字符串，不猜测system_errno；调用前旧队列已清。
 */
static vireo_result_t capture(vireo_tls_connection_error_t *diagnostic, vireo_result_t fallback)
{
    bool no_memory = false;
    unsigned long code;
    while ((code = ERR_get_error()) != 0) {
        if (diagnostic->openssl_error_code == 0) {
            diagnostic->openssl_error_code = (uint64_t)code;
        } else {
            diagnostic->has_more_errors = true;
        }
        if (ERR_GET_REASON(code) == ERR_R_MALLOC_FAILURE) {
            no_memory = true;
        }
    }
    return no_memory ? VIREO_RESULT_NO_MEMORY : fallback;
}

/** 完整表先验验证，任何回调前拒绝缺项。 */
static bool ops_valid(vireo_tls_connection_ops_t const *ops)
{
    return ops != NULL && ops->allocate != NULL && ops->deallocate != NULL &&
        ops->get_flags != NULL && ops->socket_type != NULL && ops->peer_connected != NULL &&
        ops->create_native != NULL && ops->create_bio != NULL;
}

/**
 * @brief 按固定顺序只读验证socket资格，系统失败即时保存原errno
 *
 * @param[in] ops
 *     已验证完整表，调用期间稳定。
 * @param[in] fd
 *     非负且caller保证唯一管理的借用数值。
 * @param[in,out] diagnostic
 *     已设VALIDATE_FD，系统失败才写system_errno。
 *
 * @return
 *     合规OK、成功查询但形态不符INVALID_ARGUMENT、原生失败IO。
 *
 * @note 不close/dup/改flags，不重试EINTR；瞬时查询不证明长期fd身份。
 */
static vireo_result_t validate_fd(vireo_tls_connection_ops_t const *ops, int fd,
    vireo_tls_connection_error_t *diagnostic)
{
    int flags = ops->get_flags(ops->context, fd, F_GETFL);
    if (flags == -1) {
        diagnostic->system_errno = errno;
        return VIREO_RESULT_IO;
    }
    if ((flags & O_NONBLOCK) == 0) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    flags = ops->get_flags(ops->context, fd, F_GETFD);
    if (flags == -1) {
        diagnostic->system_errno = errno;
        return VIREO_RESULT_IO;
    }
    if ((flags & FD_CLOEXEC) == 0) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    int type = 0;
    if (ops->socket_type(ops->context, fd, &type) == -1) {
        diagnostic->system_errno = errno;
        return VIREO_RESULT_IO;
    }
    if (type != SOCK_STREAM) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    if (ops->peer_connected(ops->context, fd) == -1) {
        diagnostic->system_errno = errno;
        return VIREO_RESULT_IO;
    }
    return VIREO_OK;
}

/**
 * @brief 以native getters验证固定服务器策略与NOCLOSE绑定
 *
 * @param[in] connection
 *     非空存活控制块；仅本核心串行读取，native允许NULL以检查防御路径。
 *
 * @retval true
 *     本层预算/借用数值与native服务器角色、TLS策略及BIO配置均成立。
 * @retval false
 *     至少一个不变量不符，无输出或资源变更。
 *
 * @note 先验证控制块再取BIO；只读库配置，不查询外部fd存活或身份。
 */
static bool policy_valid(vireo_tls_connection_t const *connection)
{
    SSL *native = connection->native;
    if (native == NULL || connection->borrowed_fd < 0 ||
        connection->max_wrapper_bytes < sizeof(*connection) ||
        connection->max_wrapper_bytes > VIREO_TLS_CONNECTION_MAX_WRAPPER_BYTES) {
        return false;
    }
    BIO *read_bio = SSL_get_rbio(native);
    BIO *write_bio = SSL_get_wbio(native);
    return read_bio != NULL && write_bio == read_bio &&
        BIO_get_close(read_bio) == BIO_NOCLOSE &&
        SSL_get_rfd(native) == connection->borrowed_fd &&
        SSL_get_wfd(native) == connection->borrowed_fd &&
        SSL_get_min_proto_version(native) == TLS1_3_VERSION &&
        SSL_get_max_proto_version(native) == TLS1_3_VERSION &&
        SSL_is_server(native) == 1 && SSL_get_max_early_data(native) == 0 &&
        SSL_get_num_tickets(native) == 0 &&
        (SSL_get_options(native) & SSL_OP_NO_TICKET) != 0 &&
        SSL_get_verify_mode(native) == SSL_VERIFY_NONE;
}

/**
 * @brief 在固定资源策略通过后核本层状态与真实完成状态的一致性
 *
 * @param[in] connection
 *     native非空且policy_valid通过的存活对象，串行短借。
 *
 * @return
 *     四态、等待方向、首错存储与native完成状态同时合规才为true。
 *
 * @note 首次WANT_READ可能仍处库before，不能据此断言本层从未尝试握手。
 *     应用fatal可使OpenSSL离开init_finished；独立首错存在时ESTABLISHED仍为握手历史。
 */
static bool lifecycle_valid(vireo_tls_connection_t const *connection)
{
    if (!connection->deadline_armed &&
        (connection->deadline_ns != 0 || connection->last_now_ns != 0)) {
        return false;
    }
    bool failed = connection->state == VIREO_TLS_HANDSHAKE_FAILED;
    if (failed) {
        bool timeout = connection->failure_result == VIREO_RESULT_TIMEOUT &&
            connection->failure_error.stage == VIREO_TLS_CONNECTION_STAGE_DEADLINE &&
            connection->deadline_armed && connection->last_now_ns >= connection->deadline_ns &&
            connection->failure_error.system_errno == 0 &&
            connection->failure_error.openssl_error_code == 0 &&
            !connection->failure_error.has_more_errors;
        bool native_failure = connection->handshake_native_attempted &&
            (connection->failure_result == VIREO_RESULT_IO ||
             connection->failure_result == VIREO_RESULT_PROTOCOL ||
             connection->failure_result == VIREO_RESULT_NO_MEMORY ||
             connection->failure_result == VIREO_RESULT_INTERNAL) &&
            connection->failure_error.stage == VIREO_TLS_CONNECTION_STAGE_HANDSHAKE;
        return connection->wait == VIREO_TLS_HANDSHAKE_WAIT_NONE && (timeout || native_failure);
    }
    if (connection->failure_result != VIREO_OK ||
        connection->failure_error.stage != VIREO_TLS_CONNECTION_STAGE_NONE ||
        connection->failure_error.system_errno != 0 ||
        connection->failure_error.openssl_error_code != 0 ||
        connection->failure_error.has_more_errors) {
        return false;
    }
    switch (connection->state) {
    case VIREO_TLS_HANDSHAKE_INITIAL:
        return !connection->handshake_native_attempted &&
            connection->wait == VIREO_TLS_HANDSHAKE_WAIT_NONE &&
            SSL_in_before(connection->native) == 1 &&
            SSL_is_init_finished(connection->native) == 0;
    case VIREO_TLS_HANDSHAKE_HANDSHAKING:
        return connection->handshake_native_attempted &&
            (!connection->deadline_armed || connection->last_now_ns < connection->deadline_ns) &&
            (connection->wait == VIREO_TLS_HANDSHAKE_WAIT_READ ||
                connection->wait == VIREO_TLS_HANDSHAKE_WAIT_WRITE) &&
            SSL_is_init_finished(connection->native) == 0;
    case VIREO_TLS_HANDSHAKE_ESTABLISHED: {
        bool application_failed = connection->io.state == VIREO_TLS_IO_FAILED &&
            (connection->io.failure_result == VIREO_RESULT_IO ||
             connection->io.failure_result == VIREO_RESULT_PROTOCOL ||
             connection->io.failure_result == VIREO_RESULT_NO_MEMORY ||
             connection->io.failure_result == VIREO_RESULT_INTERNAL) &&
            (connection->io.failure_error.stage == VIREO_TLS_CONNECTION_STAGE_RECEIVE ||
             connection->io.failure_error.stage == VIREO_TLS_CONNECTION_STAGE_SEND);
        return connection->handshake_native_attempted &&
            connection->wait == VIREO_TLS_HANDSHAKE_WAIT_NONE &&
            (SSL_is_init_finished(connection->native) == 1 || application_failed ||
                (connection->close.state >= VIREO_TLS_CLOSE_DRAINING &&
                 connection->close.state <= VIREO_TLS_CLOSE_FAILED));
    }
    default:
        return false;
    }
}

/**
 * @brief 逆序释放实际已取得的SSL与包装，保留socket唯一关闭者
 *
 * @param[in] connection
 *     本层唯一未发布候选或结束全部使用的对象，native可为NULL。
 *
 * @note 先复制allocator表，SSL_free释放NOCLOSE BIO及native引用；随后配对释放包装，
 *     不再访问已释放对象。无失败返回，主诊断必须由caller事先保存。
 */
static void release_connection(vireo_tls_connection_t *connection)
{
    vireo_tls_connection_ops_t ops = connection->ops;
    vireo_tls_io_release(&connection->io);
    SSL_free(connection->native);
    ops.deallocate(ops.context, connection);
}

vireo_result_t vireo_tls_connection_create_with_ops(vireo_tls_context_t const *context,
    vireo_tls_connection_options_t const *options, int borrowed_fd,
    vireo_tls_connection_t **out_connection, vireo_tls_connection_error_t *error,
    vireo_tls_connection_ops_t const *ops)
{
    int saved_errno = errno;
    vireo_tls_connection_error_t diagnostic = {VIREO_TLS_CONNECTION_STAGE_NONE, 0, 0, false};
    if (context == NULL || options == NULL || out_connection == NULL ||
        *out_connection != NULL || borrowed_fd < 0 || options->max_wrapper_bytes == 0 ||
        !ops_valid(ops)) {
        return finish(error, diagnostic, VIREO_RESULT_INVALID_ARGUMENT, saved_errno);
    }
    if (options->max_wrapper_bytes < sizeof(vireo_tls_connection_t) ||
        options->max_wrapper_bytes > VIREO_TLS_CONNECTION_MAX_WRAPPER_BYTES) {
        return finish(error, diagnostic, VIREO_RESULT_RANGE, saved_errno);
    }
    ERR_clear_error();
    diagnostic.stage = VIREO_TLS_CONNECTION_STAGE_VALIDATE_FD;
    vireo_result_t result = validate_fd(ops, borrowed_fd, &diagnostic);
    vireo_tls_connection_t *candidate = NULL;
    if (result != VIREO_OK) {
        goto done;
    }
    diagnostic.stage = VIREO_TLS_CONNECTION_STAGE_VALIDATE_CONTEXT;
    vireo_tls_context_info_t context_info;
    vireo_tls_context_error_t context_error;
    result = vireo_tls_context_inspect(context, &context_info, &context_error);
    if (result != VIREO_OK) {
        diagnostic.openssl_error_code = context_error.openssl_error_code;
        diagnostic.has_more_errors = context_error.has_more_errors;
        goto done;
    }
    diagnostic.stage = VIREO_TLS_CONNECTION_STAGE_ALLOCATE_WRAPPER;
    candidate = ops->allocate(ops->context, sizeof(*candidate));
    if (candidate == NULL) {
        result = VIREO_RESULT_NO_MEMORY;
        goto done;
    }
    *candidate = (vireo_tls_connection_t){
        .native = NULL, .borrowed_fd = borrowed_fd,
        .max_wrapper_bytes = options->max_wrapper_bytes, .ops = *ops,
        .state = VIREO_TLS_HANDSHAKE_INITIAL, .wait = VIREO_TLS_HANDSHAKE_WAIT_NONE,
        .failure_result = VIREO_OK,
        .failure_error = {VIREO_TLS_CONNECTION_STAGE_NONE, 0, 0, false}
    };
    diagnostic.stage = VIREO_TLS_CONNECTION_STAGE_CREATE_NATIVE;
    candidate->native = ops->create_native(ops->context, context->native);
    if (candidate->native == NULL) {
        result = capture(&diagnostic, VIREO_RESULT_INTERNAL);
        goto done;
    }
    diagnostic.stage = VIREO_TLS_CONNECTION_STAGE_BIND_FD;
    BIO *bio = ops->create_bio(ops->context, borrowed_fd);
    if (bio == NULL) {
        result = capture(&diagnostic, VIREO_RESULT_INTERNAL);
        goto done;
    }
    /* 新SSL无旧BIO；同一个BIO交给双向SSL，按SSL_set_bio规则仅移交一个拥有引用。 */
    SSL_set_bio(candidate->native, bio, bio);
    SSL_set_accept_state(candidate->native);
    diagnostic.stage = VIREO_TLS_CONNECTION_STAGE_INSPECT;
    if (!policy_valid(candidate) || !lifecycle_valid(candidate)) {
        result = capture(&diagnostic, VIREO_RESULT_INTERNAL);
        goto done;
    }
    *out_connection = candidate;
    candidate = NULL;
    diagnostic = (vireo_tls_connection_error_t){VIREO_TLS_CONNECTION_STAGE_NONE, 0, 0, false};
done:
    if (candidate != NULL) {
        release_connection(candidate);
    }
    ERR_clear_error();
    return finish(error, diagnostic, result, saved_errno);
}

vireo_result_t vireo_tls_connection_create_server(vireo_tls_context_t const *context,
    vireo_tls_connection_options_t const *options, int borrowed_fd,
    vireo_tls_connection_t **out_connection, vireo_tls_connection_error_t *error)
{
    return vireo_tls_connection_create_with_ops(context, options, borrowed_fd,
        out_connection, error, &system_ops);
}

vireo_result_t vireo_tls_connection_inspect(vireo_tls_connection_t const *connection,
    vireo_tls_connection_info_t *out_info, vireo_tls_connection_error_t *error)
{
    int saved_errno = errno;
    vireo_tls_connection_error_t diagnostic = {VIREO_TLS_CONNECTION_STAGE_NONE, 0, 0, false};
    if (connection == NULL || out_info == NULL) {
        return finish(error, diagnostic, VIREO_RESULT_INVALID_ARGUMENT, saved_errno);
    }
    ERR_clear_error();
    if (!policy_valid(connection) || !lifecycle_valid(connection)) {
        diagnostic.stage = VIREO_TLS_CONNECTION_STAGE_INSPECT;
        vireo_result_t result = capture(&diagnostic, VIREO_RESULT_INTERNAL);
        ERR_clear_error();
        return finish(error, diagnostic, result, saved_errno);
    }
    vireo_tls_connection_info_t info = {VIREO_TLS_CONTEXT_PROTOCOL_1_3,
        VIREO_TLS_CONTEXT_PROTOCOL_1_3, true,
        connection->handshake_native_attempted,
        connection->state == VIREO_TLS_HANDSHAKE_ESTABLISHED, true,
        sizeof(*connection), connection->max_wrapper_bytes, connection->state, connection->wait};
    *out_info = info;
    ERR_clear_error();
    return finish(error, diagnostic, VIREO_OK, saved_errno);
}

/**
 * @brief 共享带/不带期限的单步核心，所有原生入口受同一门禁
 * @param[in,out] connection 串行存活owner，先校验配置与生命周期。
 * @param[in] timed true使用now并要求arm；false在已arm活跃对象上拒绝。
 * @param[in] now 显式同域入口时间，未使用时为0；不自行读取时钟。
 * @param[out] out_info 必需独立报告，沿公共超时/原生/拒绝提交合同。
 * @param[out] error 可空独立诊断，不保存地址。
 * @param[in] ops 完整单次短借表，真正原生时紧邻分类。
 * @return 沿两个公共step的离散结果与首错缓存合同。
 * @note 到期零ops调用；未到期复用同一原生与错误处理，保持errno/队列顺序。
 */
static vireo_result_t handshake_drive(vireo_tls_connection_t *connection,
    bool timed, vireo_monotonic_ns_t now,
    vireo_tls_handshake_info_t *out_info, vireo_tls_connection_error_t *error,
    vireo_tls_handshake_ops_t const *ops)
{
    int saved_errno = errno;
    vireo_tls_connection_error_t diagnostic = {VIREO_TLS_CONNECTION_STAGE_NONE, 0, 0, false};
    if (connection == NULL || out_info == NULL || ops == NULL ||
        ops->sigpipe_ignored == NULL || ops->do_handshake == NULL || ops->get_error == NULL) {
        return finish(error, diagnostic, VIREO_RESULT_INVALID_ARGUMENT, saved_errno);
    }
    ERR_clear_error();
    if (!policy_valid(connection) || !lifecycle_valid(connection)) {
        diagnostic.stage = VIREO_TLS_CONNECTION_STAGE_INSPECT;
        (void)capture(&diagnostic, VIREO_RESULT_INTERNAL);
        ERR_clear_error();
        return finish(error, diagnostic, VIREO_RESULT_INTERNAL, saved_errno);
    }
    vireo_tls_handshake_info_t info = {connection->state, connection->wait, false};
    if (connection->state == VIREO_TLS_HANDSHAKE_ESTABLISHED ||
        connection->state == VIREO_TLS_HANDSHAKE_FAILED) {
        *out_info = info;
        ERR_clear_error();
        return finish(error, connection->failure_error, connection->failure_result, saved_errno);
    }
    if (timed != connection->deadline_armed) {
        ERR_clear_error();
        return finish(error, diagnostic, VIREO_RESULT_BUSY, saved_errno);
    }
    if (timed && now < connection->last_now_ns) {
        ERR_clear_error();
        return finish(error, diagnostic, VIREO_RESULT_RANGE, saved_errno);
    }
    if (timed && now >= connection->deadline_ns) {
        diagnostic.stage = VIREO_TLS_CONNECTION_STAGE_DEADLINE;
        connection->last_now_ns = now;
        connection->state = VIREO_TLS_HANDSHAKE_FAILED;
        connection->wait = VIREO_TLS_HANDSHAKE_WAIT_NONE;
        connection->failure_result = VIREO_RESULT_TIMEOUT;
        connection->failure_error = diagnostic;
        *out_info = (vireo_tls_handshake_info_t){VIREO_TLS_HANDSHAKE_FAILED,
            VIREO_TLS_HANDSHAKE_WAIT_NONE, false};
        ERR_clear_error();
        return finish(error, diagnostic, VIREO_RESULT_TIMEOUT, saved_errno);
    }
    bool ignored = false;
    int query_result = ops->sigpipe_ignored(ops->context, &ignored);
    int query_errno = errno;
    if (query_result != 0 || !ignored) {
        diagnostic.stage = VIREO_TLS_CONNECTION_STAGE_SIGNAL_POLICY;
        diagnostic.system_errno = query_result == -1 ? query_errno : 0;
        ERR_clear_error();
        return finish(error, diagnostic, query_result == -1 ? VIREO_RESULT_IO :
            (query_result != 0 ? VIREO_RESULT_INTERNAL : VIREO_RESULT_INVALID_ARGUMENT), saved_errno);
    }
    /* 只读查询不应触库；这里再次清队列，严格保证原生入口没有陈旧原因。 */
    ERR_clear_error();
    connection->handshake_native_attempted = true;
    if (timed) { connection->last_now_ns = now; }
    errno = 0;
    int returned = ops->do_handshake(ops->context, connection->native);
    int native_errno = errno;
    int native_error = returned <= 0 ?
        ops->get_error(ops->context, connection->native, returned) : SSL_ERROR_NONE;
    /* 分类已完成，此时才允许消费错误队列或调用任何getter。 */
    diagnostic.stage = VIREO_TLS_CONNECTION_STAGE_HANDSHAKE;
    vireo_result_t captured = capture(&diagnostic, VIREO_RESULT_PROTOCOL);
    vireo_result_t result = VIREO_RESULT_INTERNAL;
    connection->wait = VIREO_TLS_HANDSHAKE_WAIT_NONE;
    if (returned == 1 && SSL_is_init_finished(connection->native) == 1) {
        result = VIREO_OK;
        connection->state = VIREO_TLS_HANDSHAKE_ESTABLISHED;
    } else if (returned <= 0 &&
        (native_error == SSL_ERROR_WANT_READ || native_error == SSL_ERROR_WANT_WRITE)) {
        result = VIREO_OK;
        connection->state = VIREO_TLS_HANDSHAKE_HANDSHAKING;
        connection->wait = native_error == SSL_ERROR_WANT_READ ?
            VIREO_TLS_HANDSHAKE_WAIT_READ : VIREO_TLS_HANDSHAKE_WAIT_WRITE;
    } else if (returned <= 0 && native_error == SSL_ERROR_SYSCALL) {
        result = VIREO_RESULT_IO;
        diagnostic.system_errno = native_errno;
    } else if (returned <= 0 && native_error == SSL_ERROR_ZERO_RETURN) {
        result = VIREO_RESULT_PROTOCOL;
    } else if (returned <= 0 && native_error == SSL_ERROR_SSL) {
        result = captured;
    }
    if (result == VIREO_OK && (!policy_valid(connection) || !lifecycle_valid(connection))) {
        result = VIREO_RESULT_INTERNAL;
    }
    if (result == VIREO_OK) {
        /* 只在真实握手成功且策略/生命周期均通过后开放原有四资源；不重新申请。 */
        if (connection->state == VIREO_TLS_HANDSHAKE_ESTABLISHED &&
            connection->io.state == VIREO_TLS_IO_PREPARED) {
            connection->io.state = VIREO_TLS_IO_OPEN;
        }
        diagnostic = (vireo_tls_connection_error_t){VIREO_TLS_CONNECTION_STAGE_NONE, 0, 0, false};
    } else {
        connection->state = VIREO_TLS_HANDSHAKE_FAILED;
        connection->wait = VIREO_TLS_HANDSHAKE_WAIT_NONE;
        connection->failure_result = result;
        connection->failure_error = diagnostic;
    }
    *out_info = (vireo_tls_handshake_info_t){connection->state, connection->wait, true};
    ERR_clear_error();
    return finish(error, diagnostic, result, saved_errno);
}

vireo_result_t vireo_tls_connection_handshake_with_ops(vireo_tls_connection_t *connection,
    vireo_tls_handshake_info_t *out_info, vireo_tls_connection_error_t *error,
    vireo_tls_handshake_ops_t const *ops)
{
    return handshake_drive(connection, false, 0, out_info, error, ops);
}

vireo_result_t vireo_tls_connection_handshake_at_with_ops(vireo_tls_connection_t *connection,
    vireo_monotonic_ns_t now, vireo_tls_handshake_info_t *out_info,
    vireo_tls_connection_error_t *error, vireo_tls_handshake_ops_t const *ops)
{
    return handshake_drive(connection, true, now, out_info, error, ops);
}

vireo_result_t vireo_tls_connection_handshake_step(vireo_tls_connection_t *connection,
    vireo_tls_handshake_info_t *out_info, vireo_tls_connection_error_t *error)
{
    return vireo_tls_connection_handshake_with_ops(connection, out_info, error, &system_handshake_ops);
}

vireo_result_t vireo_tls_connection_handshake_step_at(vireo_tls_connection_t *connection,
    vireo_monotonic_ns_t now, vireo_tls_handshake_info_t *out_info,
    vireo_tls_connection_error_t *error)
{
    return vireo_tls_connection_handshake_at_with_ops(connection, now, out_info, error,
        &system_handshake_ops);
}

vireo_result_t vireo_tls_connection_handshake_deadline_arm(vireo_tls_connection_t *connection,
    vireo_monotonic_ns_t now, vireo_monotonic_ns_t deadline, vireo_tls_connection_error_t *error)
{
    int saved_errno = errno;
    vireo_tls_connection_error_t diagnostic = {VIREO_TLS_CONNECTION_STAGE_NONE, 0, 0, false};
    if (connection == NULL) {
        return finish(error, diagnostic, VIREO_RESULT_INVALID_ARGUMENT, saved_errno);
    }
    ERR_clear_error();
    if (!policy_valid(connection) || !lifecycle_valid(connection)) {
        diagnostic.stage = VIREO_TLS_CONNECTION_STAGE_INSPECT;
        ERR_clear_error();
        return finish(error, diagnostic, VIREO_RESULT_INTERNAL, saved_errno);
    }
    if (connection->state != VIREO_TLS_HANDSHAKE_INITIAL || connection->deadline_armed) {
        ERR_clear_error();
        return finish(error, diagnostic, VIREO_RESULT_BUSY, saved_errno);
    }
    connection->deadline_armed = true;
    connection->deadline_ns = deadline;
    connection->last_now_ns = now;
    ERR_clear_error();
    return finish(error, diagnostic, VIREO_OK, saved_errno);
}

vireo_result_t vireo_tls_connection_handshake_deadline_inspect(vireo_tls_connection_t const *connection,
    vireo_tls_handshake_deadline_info_t *out_info, vireo_tls_connection_error_t *error)
{
    int saved_errno = errno;
    vireo_tls_connection_error_t diagnostic = {VIREO_TLS_CONNECTION_STAGE_NONE, 0, 0, false};
    if (connection == NULL || out_info == NULL) {
        return finish(error, diagnostic, VIREO_RESULT_INVALID_ARGUMENT, saved_errno);
    }
    ERR_clear_error();
    if (!policy_valid(connection) || !lifecycle_valid(connection)) {
        diagnostic.stage = VIREO_TLS_CONNECTION_STAGE_INSPECT;
        ERR_clear_error();
        return finish(error, diagnostic, VIREO_RESULT_INTERNAL, saved_errno);
    }
    *out_info = (vireo_tls_handshake_deadline_info_t){connection->deadline_armed,
        connection->deadline_ns, connection->last_now_ns};
    ERR_clear_error();
    return finish(error, diagnostic, VIREO_OK, saved_errno);
}

vireo_result_t vireo_tls_connection_destroy(vireo_tls_connection_t **connection,
    vireo_tls_connection_error_t *error)
{
    int saved_errno = errno;
    vireo_tls_connection_error_t diagnostic = {VIREO_TLS_CONNECTION_STAGE_NONE, 0, 0, false};
    if (connection == NULL) {
        return finish(error, diagnostic, VIREO_RESULT_INVALID_ARGUMENT, saved_errno);
    }
    if (*connection != NULL) {
        ERR_clear_error();
        release_connection(*connection);
        *connection = NULL;
        ERR_clear_error();
    }
    return finish(error, diagnostic, VIREO_OK, saved_errno);
}
