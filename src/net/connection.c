/*
- PROJECT : VIREO
- FILE    : connection.c
- AUTHOR  : bitofux
- DATE    : 2026-10-03
- BRIEF   : 此模块负责：
- -- 受检资源构造、只读 socket 验证及成功后的所有权发布
- -- 失败逆序回滚、单次关闭与完整清理
- -- 原始字节接收双预算、部分进度与只读借用失效边界
- -- 显式方向的有界帧识别、CRC 与不消费的只读批次
- -- 完整写队列追加、预算发送与确认前缀消费
- -- 单 loop 绑定成功发布、在途保护和安全解除
- -- 双迟滞水位、半帧恢复约束和显式关注同步
- -- 永久关闭意图与显式排空阶段，不代替上层资源释放
 */
#include "connection_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vireo/base/checked.h>

struct vireo_connection {
    int owned_fd;
    vireo_buffer_t *read_buffer;
    vireo_buffer_t *write_buffer;
    size_t buffer_capacity_bytes;
    size_t max_buffer_bytes;
    bool read_eof;
    vireo_connection_ops_t ops;
    vireo_connection_loop_ops_t loop_ops;
    vireo_event_loop_t *borrowed_loop;
    bool loop_attached;
    vireo_event_loop_handle_t loop_handle;
    uint32_t loop_interests;
    vireo_connection_callback_t callback;
    void *callback_context;
    bool callback_active;
    bool flow_enabled;
    bool read_pressure;
    bool write_pressure;
    vireo_connection_flow_options_t flow_options;
    vireo_connection_close_state_t close_state;
    vireo_connection_close_mode_t close_mode;
    vireo_connection_close_reason_t close_reason;
};

/**
 * @brief 分配控制块
 *
 * @param[in] context
 *     未使用的借用上下文。
 * @param[in] bytes
 *     控制块字节数。
 *
 * @return 新 malloc owner 或 NULL。
 *
 * @note 与 system_deallocate 配对，失败不取得资源。
 */
static void *system_allocate(void *context, size_t bytes)
{
    (void)context;
    return malloc(bytes);
}

/**
 * @brief 释放本层控制块
 *
 * @param[in] context
 *     未使用的借用上下文。
 * @param[in] memory
 *     system_allocate 取得的唯一 owner，调用后失效。
 *
 * @note 不拥有 context；errno 由最外层恢复。
 */
static void system_deallocate(void *context, void *memory)
{
    (void)context;
    free(memory);
}

/**
 * @brief 查询 socket flags
 *
 * @param[in] context
 *     未使用的借用上下文。
 * @param[in] fd
 *     调用期间借用的 socket。
 * @param[in] command
 *     F_GETFL 或 F_GETFD。
 *
 * @return 系统 flags 或 -1。
 *
 * @note 仅一次只读查询，失败保留原 errno，不修改属性。
 */
static int system_get_flags(void *context, int fd, int command)
{
    (void)context;
    return fcntl(fd, command);
}

/**
 * @brief 查询 socket 类型
 *
 * @param[in] context
 *     未使用的借用上下文。
 * @param[in] fd
 *     调用期间借用的 socket。
 * @param[out] out_type
 *     非空有效 int，接收系统类型。
 *
 * @return 系统调用 0 或 -1。
 *
 * @note 单次 SO_TYPE 查询，失败保留原 errno，不修改属性。
 */
static int system_socket_type(void *context, int fd, int *out_type)
{
    socklen_t length = (socklen_t)sizeof(*out_type);
    (void)context;
    return getsockopt(fd, SOL_SOCKET, SO_TYPE, out_type, &length);
}

/**
 * @brief 验证已连接 peer
 *
 * @param[in] context
 *     未使用的借用上下文。
 * @param[in] fd
 *     调用期间借用的 socket。
 *
 * @return 系统调用 0 或 -1。
 *
 * @note 单次 getpeername，地址仅局部使用，失败保留原 errno。
 */
static int system_peer_connected(void *context, int fd)
{
    struct sockaddr_storage address;
    socklen_t length = (socklen_t)sizeof(address);
    (void)context;
    return getpeername(fd, (struct sockaddr *)&address, &length);
}

/**
 * @brief 关闭独占 socket
 *
 * @param[in] context
 *     未使用的借用上下文。
 * @param[in] fd
 *     connection 独占 fd；调用后不得再操作旧编号。
 *
 * @return 系统调用 0 或 -1。
 *
 * @note 单次 close，包含 EINTR 在内均不重试，失败原 errno 留给上层。
 */
static int system_close(void *context, int fd)
{
    (void)context;
    return close(fd);
}

/**
 * @brief 通过公共合同创建 buffer
 *
 * @param[in] context
 *     未使用的借用上下文。
 * @param[in] capacity
 *     已验收的正容量。
 * @param[in,out] out
 *     独立空 buffer owner；成功接管，失败保持。
 *
 * @return 公共 buffer_create 结果。
 *
 * @note 不接触旧模块私有布局或分配器。
 */
static vireo_result_t system_create_buffer(void *context, size_t capacity, vireo_buffer_t **out)
{
    (void)context;
    return vireo_buffer_create(capacity, out);
}

/**
 * @brief 通过公共合同释放 buffer
 *
 * @param[in] context
 *     未使用的借用上下文。
 * @param[in,out] owner
 *     已取得的合法唯一 buffer owner，成功被消费。
 *
 * @note 仅合法 owner 调用；公共 destroy 在该前置下必定成功。
 */
static void system_destroy_buffer(void *context, vireo_buffer_t **owner)
{
    (void)context;
    (void)vireo_buffer_destroy(owner);
}

/**
 * @brief 单次非阻塞接收，原始返回及 errno 交给预算层
 *
 * @param[in] context
 *     未使用的借用上下文。
 * @param[in] fd
 *     connection 独占 socket，调用期间借用。
 * @param[out] bytes
 *     有效栈暂存区，至少 request 字节，不保存或接管。
 * @param[in] request
 *     1..4096，预算层已保证可追加。
 * @param[in] flags
 *     MSG_DONTWAIT，不修改 fd 属性。
 *
 * @return
 *     recv 原 ssize_t，正值进度、0 EOF、-1 原 errno。
 *
 * @note 不自动重试、不关闭；本模块不支持强制取消。
 */
static ssize_t system_receive(void *context, int fd, void *bytes, size_t request, int flags)
{
    (void)context;
    return recv(fd, bytes, request, flags);
}

/**
 * @brief 单次发送借用的只读字节，数量和 errno 原样交预算层
 *
 * @param[in] context
 *     未使用的上下文。
 * @param[in] fd
 *     本对象独占 socket，调用期间借用。
 * @param[in] bytes
 *     至少 request 个可读字节，只借用到返回。
 * @param[in] request
 *     已验收的 1..4096 字节。
 * @param[in] flags
 *     MSG_DONTWAIT|MSG_NOSIGNAL，不改全局信号设置。
 *
 * @return 系统正进度或 -1/原 errno。
 *
 * @note 不保存输入、重试或关闭。
 */
static ssize_t system_send(void *context, int fd, void const *bytes, size_t request, int flags)
{
    (void)context;
    return send(fd, bytes, request, flags);
}

static vireo_connection_ops_t const system_ops = {
    NULL, system_allocate, system_deallocate, system_get_flags, system_socket_type,
    system_peer_connected, system_close, system_create_buffer, system_destroy_buffer,
    system_receive, system_send
};

/**
 * @brief 写可空诊断并恢复入口 errno
 *
 * @param[out] error
 *     可空独立诊断。
 * @param[in] result
 *     待返回分类。
 * @param[in] stage
 *     已确定阶段。
 * @param[in] cause
 *     IO 原 errno，否则为 0。
 * @param[in] saved_errno
 *     入口 errno。
 *
 * @return result 原值。
 *
 * @note 资源清理须在调用前完成；诊断不影响结果或所有权。
 */
static vireo_result_t finish(vireo_connection_error_t *error, vireo_result_t result,
                             vireo_connection_stage_t stage, int cause, int saved_errno)
{
    if (error != NULL) {
        *error = (vireo_connection_error_t){stage, cause};
    }
    errno = saved_errno;
    return result;
}

/**
 * @brief 逆序释放已取得内存，不关闭尚未转移的调用者 socket
 *
 * @param[in,out] connection
 *     本模块已分配控制块，buffer owner 可为空；调用后该指针失效。
 *
 * @note ops 按值保存后释放控制，失败原因由调用者预先保存。
 */
static void release_memory(vireo_connection_t *connection)
{
    vireo_connection_ops_t ops = connection->ops;
    if (connection->write_buffer != NULL) {
        ops.destroy_buffer(ops.context, &connection->write_buffer);
    }
    if (connection->read_buffer != NULL) {
        ops.destroy_buffer(ops.context, &connection->read_buffer);
    }
    ops.deallocate(ops.context, connection);
}

/**
 * @brief 通过公开合同严格登记，不借用 loop 私有实现
 *
 * @param[in] context
 *     未使用的借用 context。
 * @param[in,out] loop
 *     存活借用对象。
 * @param[in] registration
 *     调用期间有效的固定绑定。
 * @param[in,out] out_handle
 *     独立全零输入，成功发布数值身份。
 * @param[out] error
 *     可空独立诊断。
 *
 * @return 公共 ADD 原结果。
 *
 * @note 无重试，依赖保持 errno 与失败输出。
 */
static vireo_result_t system_loop_add(void *context, vireo_event_loop_t *loop,
                                     vireo_event_loop_registration_t const *registration,
                                     vireo_event_loop_handle_t *out_handle,
                                     vireo_event_loop_error_t *error)
{
    (void)context;
    return vireo_event_loop_add(loop, registration, out_handle, error);
}

/**
 * @brief 通过公开合同严格替换关注
 *
 * @param[in] context
 *     未使用的借用 context。
 * @param[in,out] loop
 *     存活借用对象。
 * @param[in] handle
 *     当前有效注册数值副本。
 * @param[in] interests
 *     已校验的三项目关注位。
 * @param[out] error
 *     可空独立诊断。
 *
 * @return 公共 MOD 原结果。
 *
 * @note 失败保持旧关注，未重试。
 */
static vireo_result_t system_loop_mod(void *context, vireo_event_loop_t *loop,
                                     vireo_event_loop_handle_t handle, uint32_t interests,
                                     vireo_event_loop_error_t *error)
{
    (void)context;
    return vireo_event_loop_mod(loop, handle, interests, error);
}

/**
 * @brief 通过公开合同严格注销
 *
 * @param[in] context
 *     未使用的借用 context。
 * @param[in,out] loop
 *     存活借用对象。
 * @param[in,out] handle
 *     独立有效身份，成功清零。
 * @param[out] error
 *     可空独立诊断。
 *
 * @return 公共 DEL 原结果。
 *
 * @note 失败不结束注册借用或重试。
 */
static vireo_result_t system_loop_del(void *context, vireo_event_loop_t *loop,
                                     vireo_event_loop_handle_t *handle,
                                     vireo_event_loop_error_t *error)
{
    (void)context;
    return vireo_event_loop_del(loop, handle, error);
}

static vireo_connection_loop_ops_t const system_loop_ops = {
    NULL, system_loop_add, system_loop_mod, system_loop_del
};

vireo_result_t vireo_connection_create_with_ops(vireo_connection_options_t const *options,
                                                int *fd_owner,
                                                vireo_connection_ops_t const *ops,
                                                vireo_connection_t **out_connection,
                                                vireo_connection_error_t *error)
{
    int saved_errno = errno;
    size_t capacity_bytes = 0;
    if (options == NULL || fd_owner == NULL || out_connection == NULL ||
        *fd_owner < 0 || *out_connection != NULL || ops == NULL ||
        ops->allocate == NULL || ops->deallocate == NULL || ops->get_flags == NULL ||
        ops->socket_type == NULL || ops->peer_connected == NULL || ops->close_fd == NULL ||
        ops->create_buffer == NULL || ops->destroy_buffer == NULL || ops->receive == NULL ||
        ops->send_bytes == NULL) {
        return finish(error, VIREO_RESULT_INVALID_ARGUMENT,
                      VIREO_CONNECTION_STAGE_NONE, 0, saved_errno);
    }
    vireo_result_t result = vireo_checked_size_add(options->read_capacity,
                                                  options->write_capacity, &capacity_bytes);
    if (result != VIREO_OK) {
        return finish(error, result, VIREO_CONNECTION_STAGE_NONE, 0, saved_errno);
    }
    if (options->read_capacity == 0 || options->write_capacity == 0 ||
        options->read_capacity > VIREO_BUFFER_MAX_CAPACITY ||
        options->write_capacity > VIREO_BUFFER_MAX_CAPACITY || options->max_buffer_bytes == 0 ||
        options->max_buffer_bytes > VIREO_CONNECTION_MAX_BUFFER_BYTES ||
        capacity_bytes > options->max_buffer_bytes) {
        return finish(error, VIREO_RESULT_RANGE, VIREO_CONNECTION_STAGE_NONE, 0, saved_errno);
    }

    int flags = ops->get_flags(ops->context, *fd_owner, F_GETFL);
    if (flags < 0) {
        return finish(error, VIREO_RESULT_IO, VIREO_CONNECTION_STAGE_VALIDATE_FD,
                      errno, saved_errno);
    }
    if ((flags & O_NONBLOCK) == 0) {
        return finish(error, VIREO_RESULT_INVALID_ARGUMENT,
                      VIREO_CONNECTION_STAGE_NONE, 0, saved_errno);
    }
    flags = ops->get_flags(ops->context, *fd_owner, F_GETFD);
    if (flags < 0) {
        return finish(error, VIREO_RESULT_IO, VIREO_CONNECTION_STAGE_VALIDATE_FD,
                      errno, saved_errno);
    }
    if ((flags & FD_CLOEXEC) == 0) {
        return finish(error, VIREO_RESULT_INVALID_ARGUMENT,
                      VIREO_CONNECTION_STAGE_NONE, 0, saved_errno);
    }
    int type = 0;
    if (ops->socket_type(ops->context, *fd_owner, &type) < 0) {
        return finish(error, VIREO_RESULT_IO, VIREO_CONNECTION_STAGE_VALIDATE_FD,
                      errno, saved_errno);
    }
    if (type != SOCK_STREAM) {
        return finish(error, VIREO_RESULT_INVALID_ARGUMENT,
                      VIREO_CONNECTION_STAGE_NONE, 0, saved_errno);
    }
    if (ops->peer_connected(ops->context, *fd_owner) < 0) {
        return finish(error, VIREO_RESULT_IO, VIREO_CONNECTION_STAGE_VALIDATE_FD,
                      errno, saved_errno);
    }

    vireo_connection_t *candidate = ops->allocate(ops->context, sizeof(*candidate));
    if (candidate == NULL) {
        return finish(error, VIREO_RESULT_NO_MEMORY,
                      VIREO_CONNECTION_STAGE_ALLOCATE_CONTROL, 0, saved_errno);
    }
    *candidate = (vireo_connection_t){
        .owned_fd = -1, .buffer_capacity_bytes = capacity_bytes,
        .max_buffer_bytes = options->max_buffer_bytes, .ops = *ops,
        .loop_ops = system_loop_ops
    };
    result = ops->create_buffer(ops->context, options->read_capacity, &candidate->read_buffer);
    if (result != VIREO_OK) {
        release_memory(candidate);
        return finish(error, result, VIREO_CONNECTION_STAGE_CREATE_READ_BUFFER, 0, saved_errno);
    }
    result = ops->create_buffer(ops->context, options->write_capacity, &candidate->write_buffer);
    if (result != VIREO_OK) {
        release_memory(candidate);
        return finish(error, result, VIREO_CONNECTION_STAGE_CREATE_WRITE_BUFFER, 0, saved_errno);
    }
    candidate->owned_fd = *fd_owner;
    *fd_owner = -1;
    *out_connection = candidate;
    return finish(error, VIREO_OK, VIREO_CONNECTION_STAGE_NONE, 0, saved_errno);
}

vireo_result_t vireo_connection_create(vireo_connection_options_t const *options,
                                       int *fd_owner, vireo_connection_t **out_connection,
                                       vireo_connection_error_t *error)
{
    return vireo_connection_create_with_ops(options, fd_owner, &system_ops, out_connection, error);
}

vireo_result_t vireo_connection_create_with_loop_ops(
    vireo_connection_options_t const *options, int *fd_owner,
    vireo_connection_loop_ops_t const *loop_ops, vireo_connection_t **out_connection,
    vireo_connection_error_t *error)
{
    int saved_errno = errno;
    if (out_connection == NULL || *out_connection != NULL || loop_ops == NULL ||
        loop_ops->add == NULL || loop_ops->mod == NULL || loop_ops->del == NULL) {
        return finish(error, VIREO_RESULT_INVALID_ARGUMENT,
                      VIREO_CONNECTION_STAGE_NONE, 0, saved_errno);
    }
    vireo_connection_t *candidate = NULL;
    vireo_result_t result = vireo_connection_create_with_ops(
        options, fd_owner, &system_ops, &candidate, error);
    if (result == VIREO_OK) {
        candidate->loop_ops = *loop_ops;
        *out_connection = candidate;
    }
    errno = saved_errno;
    return result;
}

vireo_result_t vireo_connection_inspect(vireo_connection_t const *connection,
                                        vireo_connection_info_t *out_info)
{
    if (connection == NULL || out_info == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    vireo_connection_info_t candidate = {0};
    vireo_result_t result = vireo_buffer_inspect(connection->read_buffer, &candidate.read_buffer);
    if (result != VIREO_OK) {
        return result;
    }
    result = vireo_buffer_inspect(connection->write_buffer, &candidate.write_buffer);
    if (result != VIREO_OK) {
        return result;
    }
    candidate.buffer_capacity_bytes = connection->buffer_capacity_bytes;
    candidate.max_buffer_bytes = connection->max_buffer_bytes;
    candidate.read_eof = connection->read_eof;
    candidate.loop_attached = connection->loop_attached;
    candidate.loop_interests = connection->loop_interests;
    candidate.callback_active = connection->callback_active;
    candidate.flow_enabled = connection->flow_enabled;
    candidate.read_pressure = connection->read_pressure;
    candidate.write_pressure = connection->write_pressure;
    candidate.flow_options = connection->flow_options;
    candidate.close_state = connection->close_state;
    candidate.close_mode = connection->close_mode;
    candidate.close_reason = connection->close_reason;
    *out_info = candidate;
    return VIREO_OK;
}

/**
 * @brief 提交合法接收的统计，最后恢复 errno 和诊断
 *
 * @param[out] out_info
 *     已验收的独立非空输出。
 * @param[in] info
 *     本轮已取得计数与停止原因，按值借用到返回。
 * @param[out] error
 *     可空独立诊断。
 * @param[in] result
 *     本轮结果。
 * @param[in] cause
 *     IO 原 errno，其余为 0。
 * @param[in] saved_errno
 *     入口 errno。
 *
 * @return
 *     result 原值。
 *
 * @note 不回滚已经从 socket 取走的字节，调用前须完成 append 或记录内部异常。
 */
static vireo_result_t receive_finish(vireo_connection_receive_info_t *out_info,
                                     vireo_connection_receive_info_t info,
                                     vireo_connection_error_t *error,
                                     vireo_result_t result, int cause, int saved_errno)
{
    *out_info = info;
    return finish(error, result,
                  result == VIREO_OK ? VIREO_CONNECTION_STAGE_NONE : VIREO_CONNECTION_STAGE_RECEIVE,
                  cause, saved_errno);
}

vireo_result_t vireo_connection_receive(vireo_connection_t *connection,
                                        vireo_connection_receive_budget_t const *budget,
                                        vireo_connection_receive_info_t *out_info,
                                        vireo_connection_error_t *error)
{
    int saved_errno = errno;
    if (connection == NULL || budget == NULL || out_info == NULL) {
        return finish(error, VIREO_RESULT_INVALID_ARGUMENT,
                      VIREO_CONNECTION_STAGE_NONE, 0, saved_errno);
    }
    if (budget->max_bytes == 0 || budget->max_syscalls == 0) {
        return finish(error, VIREO_RESULT_RANGE, VIREO_CONNECTION_STAGE_NONE, 0, saved_errno);
    }
    vireo_connection_receive_info_t info = {0, 0, VIREO_CONNECTION_RECEIVE_STOP_ERROR};
    if (connection->close_state != VIREO_CONNECTION_CLOSE_OPEN) {
        return finish(error, VIREO_RESULT_BUSY, VIREO_CONNECTION_STAGE_NONE, 0, saved_errno);
    }
    /* compact 的成功空操作也结束旧 view；仅一次搬移，且在任何 recv 前回收头部空洞。 */
    if (vireo_buffer_compact(connection->read_buffer) != VIREO_OK) {
        return receive_finish(out_info, info, error, VIREO_RESULT_INTERNAL, 0, saved_errno);
    }
    if (connection->read_eof) {
        info.stop_reason = VIREO_CONNECTION_RECEIVE_STOP_EOF;
        return receive_finish(out_info, info, error, VIREO_OK, 0, saved_errno);
    }
    vireo_buffer_info_t buffer_info;
    if (vireo_buffer_inspect(connection->read_buffer, &buffer_info) != VIREO_OK) {
        return receive_finish(out_info, info, error, VIREO_RESULT_INTERNAL, 0, saved_errno);
    }
    uint8_t scratch[4096];
    for (;;) {
        if (info.received_bytes == budget->max_bytes) {
            info.stop_reason = VIREO_CONNECTION_RECEIVE_STOP_BYTE_BUDGET;
            break;
        }
        if (buffer_info.tail_space == 0) {
            info.stop_reason = VIREO_CONNECTION_RECEIVE_STOP_BUFFER_FULL;
            break;
        }
        if (info.recv_calls == budget->max_syscalls) {
            info.stop_reason = VIREO_CONNECTION_RECEIVE_STOP_CALL_BUDGET;
            break;
        }
        size_t request = budget->max_bytes - info.received_bytes;
        if (request > buffer_info.tail_space) {
            request = buffer_info.tail_space;
        }
        if (request > sizeof(scratch)) {
            request = sizeof(scratch);
        }
        /* 两计数均先受预算约束；request<=4096 可安全比较 ssize_t，无零长度 recv。 */
        ++info.recv_calls;
        ssize_t n = connection->ops.receive(connection->ops.context, connection->owned_fd,
                                             scratch, request, MSG_DONTWAIT);
        if (n < -1 || n > (ssize_t)request) {
            return receive_finish(out_info, info, error, VIREO_RESULT_INTERNAL, 0, saved_errno);
        }
        if (n == -1) {
            int cause = errno;
            if (cause == EAGAIN || cause == EWOULDBLOCK) {
                info.stop_reason = VIREO_CONNECTION_RECEIVE_STOP_WOULD_BLOCK;
                break;
            }
            return receive_finish(out_info, info, error, VIREO_RESULT_IO, cause, saved_errno);
        }
        if (n == 0) {
            connection->read_eof = true;
            info.stop_reason = VIREO_CONNECTION_RECEIVE_STOP_EOF;
            break;
        }
        size_t received = (size_t)n;
        if (vireo_checked_size_add(info.received_bytes, received,
                                   &info.received_bytes) != VIREO_OK ||
            vireo_buffer_append(connection->read_buffer, scratch, received) != VIREO_OK) {
            return receive_finish(out_info, info, error, VIREO_RESULT_INTERNAL, 0, saved_errno);
        }
        buffer_info.tail_space -= received;
    }
    return receive_finish(out_info, info, error, VIREO_OK, 0, saved_errno);
}

vireo_result_t vireo_connection_read_peek(vireo_connection_t const *connection,
                                          uint8_t const **out_data, size_t *out_size)
{
    if (connection == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    return vireo_buffer_peek(connection->read_buffer, out_data, out_size);
}

vireo_result_t vireo_connection_read_consume(vireo_connection_t *connection, size_t size)
{
    if (connection == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    return vireo_buffer_consume(connection->read_buffer, size);
}

/**
 * @brief 提交帧统计和独立诊断，恢复入口 errno
 *
 * @param[out] out_info
 *     已开始解析时非空；前置拒绝传 NULL 以保持统计。
 * @param[in] info
 *     本轮有效前缀与停止原因。
 * @param[out] error
 *     可空独立诊断。
 * @param[in] result
 *     本轮分类。
 * @param[in] issue
 *     framing 原因。
 * @param[in] codec_issue
 *     仅 CODEC 时提供具体规则。
 * @param[in] saved_errno
 *     入口值。
 *
 * @return result 原值。
 *
 * @note 不改变 connection，不回滚已输出的有效前缀记录。
 */
static vireo_result_t frame_finish(vireo_connection_frame_info_t *out_info,
                                   vireo_connection_frame_info_t info,
                                   vireo_connection_frame_error_t *error,
                                   vireo_result_t result, vireo_connection_frame_issue_t issue,
                                   vireo_protocol_codec_issue_t codec_issue, int saved_errno)
{
    if (out_info != NULL) {
        *out_info = info;
    }
    if (error != NULL) {
        *error = (vireo_connection_frame_error_t){issue, codec_issue};
    }
    errno = saved_errno;
    return result;
}

vireo_result_t vireo_connection_frames_peek(vireo_connection_t const *connection,
                                            vireo_connection_frame_options_t const *options,
                                            vireo_connection_frame_budget_t const *budget,
                                            vireo_connection_frame_view_t *views,
                                            size_t view_capacity,
                                            vireo_connection_frame_info_t *out_info,
                                            vireo_connection_frame_error_t *error)
{
    int saved_errno = errno;
    vireo_connection_frame_info_t info = {0, 0, VIREO_CONNECTION_FRAME_STOP_ERROR};
    vireo_connection_frame_issue_t const none = VIREO_CONNECTION_FRAME_ISSUE_NONE;
    vireo_protocol_codec_issue_t const codec_none = VIREO_PROTOCOL_CODEC_ISSUE_NONE;
    size_t const header_size = (size_t)VIREO_PROTOCOL_HEADER_SIZE;
    if (connection == NULL || options == NULL || budget == NULL || views == NULL ||
        out_info == NULL || (options->direction != VIREO_CONNECTION_FRAME_REQUEST &&
                            options->direction != VIREO_CONNECTION_FRAME_RESPONSE)) {
        return frame_finish(NULL, info, error, VIREO_RESULT_INVALID_ARGUMENT,
                            none, codec_none, saved_errno);
    }
    vireo_buffer_info_t buffer_info;
    size_t protocol_max = 0;
    if (vireo_buffer_inspect(connection->read_buffer, &buffer_info) != VIREO_OK ||
        vireo_checked_u64_to_size((uint64_t)VIREO_PROTOCOL_MAX_BODY_SIZE,
                                  &protocol_max) != VIREO_OK ||
        vireo_checked_size_add(header_size, protocol_max, &protocol_max) != VIREO_OK) {
        return frame_finish(out_info, info, error, VIREO_RESULT_INTERNAL,
                            none, codec_none, saved_errno);
    }
    if (view_capacity == 0 || budget->max_messages == 0 || budget->max_bytes == 0 ||
        options->max_frame_bytes < header_size ||
        options->max_frame_bytes > buffer_info.capacity ||
        options->max_frame_bytes > protocol_max || budget->max_bytes < options->max_frame_bytes ||
        (connection->flow_enabled &&
         options->max_frame_bytes > connection->flow_options.max_frame_bytes)) {
        return frame_finish(NULL, info, error, VIREO_RESULT_RANGE, none, codec_none, saved_errno);
    }
    uint8_t const *bytes = NULL;
    size_t readable = 0;
    if (vireo_buffer_peek(connection->read_buffer, &bytes, &readable) != VIREO_OK) {
        return frame_finish(out_info, info, error, VIREO_RESULT_INTERNAL,
                            none, codec_none, saved_errno);
    }
    for (;;) {
        if (info.frame_count == budget->max_messages) {
            info.stop_reason = VIREO_CONNECTION_FRAME_STOP_MESSAGE_BUDGET;
            break;
        }
        if (info.frame_count == view_capacity) {
            info.stop_reason = VIREO_CONNECTION_FRAME_STOP_OUTPUT_FULL;
            break;
        }
        size_t remaining = readable - info.frame_bytes;
        if (remaining == 0) {
            info.stop_reason = connection->read_eof ? VIREO_CONNECTION_FRAME_STOP_EOF :
                                                     VIREO_CONNECTION_FRAME_STOP_NEED_MORE;
            break;
        }
        size_t byte_budget = budget->max_bytes - info.frame_bytes;
        if (byte_budget < header_size) {
            info.stop_reason = VIREO_CONNECTION_FRAME_STOP_BYTE_BUDGET;
            break;
        }
        if (remaining < header_size) {
            if (!connection->read_eof) {
                info.stop_reason = VIREO_CONNECTION_FRAME_STOP_NEED_MORE;
                break;
            }
            return frame_finish(out_info, info, error, VIREO_RESULT_PROTOCOL,
                                VIREO_CONNECTION_FRAME_ISSUE_TRUNCATED, codec_none, saved_errno);
        }
        uint8_t const *wire = bytes + info.frame_bytes;
        vireo_protocol_header_t header;
        vireo_protocol_codec_issue_t codec_issue = codec_none;
        vireo_result_t result = vireo_protocol_header_decode(wire, remaining,
                                                            &header, &codec_issue);
        if (result == VIREO_OK) {
            result = options->direction == VIREO_CONNECTION_FRAME_REQUEST ?
                vireo_protocol_request_header_validate(&header, &codec_issue) :
                vireo_protocol_response_header_validate(&header, &codec_issue);
        }
        if (result != VIREO_OK) {
            return frame_finish(out_info, info, error,
                                result == VIREO_RESULT_PROTOCOL ? result : VIREO_RESULT_INTERNAL,
                                result == VIREO_RESULT_PROTOCOL ?
                                    VIREO_CONNECTION_FRAME_ISSUE_CODEC : none,
                                result == VIREO_RESULT_PROTOCOL ? codec_issue : codec_none,
                                saved_errno);
        }
        size_t body_size = 0;
        size_t wire_size = 0;
        if (vireo_checked_u64_to_size((uint64_t)header.body_len, &body_size) != VIREO_OK ||
            vireo_checked_size_add(header_size, body_size, &wire_size) != VIREO_OK) {
            return frame_finish(out_info, info, error, VIREO_RESULT_INTERNAL,
                                none, codec_none, saved_errno);
        }
        if (wire_size > options->max_frame_bytes) {
            return frame_finish(out_info, info, error, VIREO_RESULT_PROTOCOL,
                                VIREO_CONNECTION_FRAME_ISSUE_FRAME_TOO_LARGE,
                                codec_none, saved_errno);
        }
        if (wire_size > byte_budget) {
            info.stop_reason = VIREO_CONNECTION_FRAME_STOP_BYTE_BUDGET;
            break;
        }
        if (wire_size > remaining) {
            if (!connection->read_eof) {
                info.stop_reason = VIREO_CONNECTION_FRAME_STOP_NEED_MORE;
                break;
            }
            return frame_finish(out_info, info, error, VIREO_RESULT_PROTOCOL,
                                VIREO_CONNECTION_FRAME_ISSUE_TRUNCATED, codec_none, saved_errno);
        }
        uint8_t const *body = body_size == 0 ? NULL : wire + header_size;
        result = vireo_protocol_frame_crc32c_verify(wire, header_size, body,
                                                     body_size, &codec_issue);
        if (result != VIREO_OK) {
            return frame_finish(out_info, info, error,
                                result == VIREO_RESULT_PROTOCOL ? result : VIREO_RESULT_INTERNAL,
                                result == VIREO_RESULT_PROTOCOL ?
                                    VIREO_CONNECTION_FRAME_ISSUE_CODEC : none,
                                result == VIREO_RESULT_PROTOCOL ? codec_issue : codec_none,
                                saved_errno);
        }
        size_t prefix_bytes = 0;
        if (vireo_checked_size_add(info.frame_bytes, wire_size, &prefix_bytes) != VIREO_OK) {
            return frame_finish(out_info, info, error, VIREO_RESULT_INTERNAL,
                                none, codec_none, saved_errno);
        }
        /* wire_size<=remaining/byte_budget，count<两项上限；写入恰一条有效记录。 */
        views[info.frame_count] =
            (vireo_connection_frame_view_t){header, body, body_size, wire_size};
        ++info.frame_count;
        info.frame_bytes = prefix_bytes;
    }
    return frame_finish(out_info, info, error, VIREO_OK, none, codec_none, saved_errno);
}

vireo_result_t vireo_connection_write_enqueue(vireo_connection_t *connection,
                                              uint8_t const *bytes, size_t size,
                                              vireo_connection_error_t *error)
{
    int saved_errno = errno;
    if (connection == NULL || (size != 0 && bytes == NULL)) {
        return finish(error, VIREO_RESULT_INVALID_ARGUMENT,
                      VIREO_CONNECTION_STAGE_NONE, 0, saved_errno);
    }
    vireo_buffer_info_t buffer_info;
    if (vireo_buffer_inspect(connection->write_buffer, &buffer_info) != VIREO_OK) {
        return finish(error, VIREO_RESULT_INTERNAL, VIREO_CONNECTION_STAGE_ENQUEUE, 0, saved_errno);
    }
    size_t pending = 0;
    vireo_result_t result = vireo_checked_size_add(buffer_info.readable_size, size, &pending);
    if (result != VIREO_OK) {
        return finish(error, result, VIREO_CONNECTION_STAGE_NONE, 0, saved_errno);
    }
    if (size > buffer_info.capacity) {
        return finish(error, VIREO_RESULT_RANGE, VIREO_CONNECTION_STAGE_NONE, 0, saved_errno);
    }
    if (pending > buffer_info.capacity) {
        return finish(error, VIREO_RESULT_BUSY, VIREO_CONNECTION_STAGE_NONE, 0, saved_errno);
    }
    if (connection->close_state != VIREO_CONNECTION_CLOSE_OPEN) {
        return finish(error, VIREO_RESULT_BUSY, VIREO_CONNECTION_STAGE_NONE, 0, saved_errno);
    }
    /* 所有普通拒绝在整理前；输入与 write 分配不重叠，合法 append 必定容纳。 */
    if ((size > buffer_info.tail_space &&
         vireo_buffer_compact(connection->write_buffer) != VIREO_OK) ||
        vireo_buffer_append(connection->write_buffer, bytes, size) != VIREO_OK) {
        return finish(error, VIREO_RESULT_INTERNAL, VIREO_CONNECTION_STAGE_ENQUEUE, 0, saved_errno);
    }
    return finish(error, VIREO_OK, VIREO_CONNECTION_STAGE_NONE, 0, saved_errno);
}

/**
 * @brief 提交实际发送进度并恢复诊断/errno
 *
 * @param[out] out_info
 *     已验收的独立非空统计。
 * @param[in] info
 *     本轮真实确认数量、尝试次数与原因。
 * @param[out] error
 *     可空独立诊断。
 * @param[in] result
 *     本轮分类。
 * @param[in] cause
 *     IO 原 errno，否则 0。
 * @param[in] saved_errno
 *     入口值。
 *
 * @return result 原值。
 *
 * @note 不回滚已经送入内核的字节。
 */
static vireo_result_t send_finish(vireo_connection_send_info_t *out_info,
                                  vireo_connection_send_info_t info,
                                  vireo_connection_error_t *error,
                                  vireo_result_t result, int cause, int saved_errno)
{
    *out_info = info;
    return finish(error, result,
                  result == VIREO_OK ? VIREO_CONNECTION_STAGE_NONE : VIREO_CONNECTION_STAGE_SEND,
                  cause, saved_errno);
}

vireo_result_t vireo_connection_send(vireo_connection_t *connection,
                                    vireo_connection_send_budget_t const *budget,
                                    vireo_connection_send_info_t *out_info,
                                    vireo_connection_error_t *error)
{
    int saved_errno = errno;
    if (connection == NULL || budget == NULL || out_info == NULL) {
        return finish(error, VIREO_RESULT_INVALID_ARGUMENT,
                      VIREO_CONNECTION_STAGE_NONE, 0, saved_errno);
    }
    if (budget->max_bytes == 0 || budget->max_syscalls == 0) {
        return finish(error, VIREO_RESULT_RANGE, VIREO_CONNECTION_STAGE_NONE, 0, saved_errno);
    }
    if (connection->close_state == VIREO_CONNECTION_CLOSE_READY) {
        return finish(error, VIREO_RESULT_BUSY, VIREO_CONNECTION_STAGE_NONE, 0, saved_errno);
    }
    vireo_connection_send_info_t info = {0, 0, VIREO_CONNECTION_SEND_STOP_ERROR};
    for (;;) {
        uint8_t const *bytes = NULL;
        size_t pending = 0;
        if (vireo_buffer_peek(connection->write_buffer, &bytes, &pending) != VIREO_OK) {
            return send_finish(out_info, info, error, VIREO_RESULT_INTERNAL, 0, saved_errno);
        }
        if (pending == 0) {
            info.stop_reason = VIREO_CONNECTION_SEND_STOP_EMPTY;
            break;
        }
        if (info.sent_bytes == budget->max_bytes) {
            info.stop_reason = VIREO_CONNECTION_SEND_STOP_BYTE_BUDGET;
            break;
        }
        if (info.send_calls == budget->max_syscalls) {
            info.stop_reason = VIREO_CONNECTION_SEND_STOP_CALL_BUDGET;
            break;
        }
        size_t request = budget->max_bytes - info.sent_bytes;
        if (request > pending) {
            request = pending;
        }
        if (request > 4096) {
            request = 4096;
        }
        ++info.send_calls;
        ssize_t n = connection->ops.send_bytes(connection->ops.context, connection->owned_fd,
                                                bytes, request, MSG_DONTWAIT | MSG_NOSIGNAL);
        if (n < -1 || n == 0 || n > (ssize_t)request) {
            return send_finish(out_info, info, error, VIREO_RESULT_INTERNAL, 0, saved_errno);
        }
        if (n == -1) {
            int cause = errno;
            if (cause == EAGAIN || cause == EWOULDBLOCK) {
                info.stop_reason = VIREO_CONNECTION_SEND_STOP_WOULD_BLOCK;
                break;
            }
            return send_finish(out_info, info, error, VIREO_RESULT_IO, cause, saved_errno);
        }
        size_t sent = (size_t)n;
        /* 正 n 已是内核进度；先记录，再消费恰 n。消费后旧局部借用结束。 */
        if (vireo_checked_size_add(info.sent_bytes, sent, &info.sent_bytes) != VIREO_OK ||
            vireo_buffer_consume(connection->write_buffer, sent) != VIREO_OK) {
            return send_finish(out_info, info, error, VIREO_RESULT_INTERNAL, 0, saved_errno);
        }
    }
    return send_finish(out_info, info, error, VIREO_OK, 0, saved_errno);
}

vireo_result_t vireo_connection_destroy(vireo_connection_t **connection,
                                        vireo_connection_error_t *error)
{
    int saved_errno = errno;
    if (connection == NULL) {
        return finish(error, VIREO_RESULT_INVALID_ARGUMENT,
                      VIREO_CONNECTION_STAGE_NONE, 0, saved_errno);
    }
    if (*connection == NULL) {
        return finish(error, VIREO_OK, VIREO_CONNECTION_STAGE_NONE, 0, saved_errno);
    }
    vireo_connection_t *owned = *connection;
    if (owned->loop_attached || owned->callback_active) {
        return finish(error, VIREO_RESULT_BUSY, VIREO_CONNECTION_STAGE_NONE, 0, saved_errno);
    }
    int failed = owned->ops.close_fd(owned->ops.context, owned->owned_fd);
    int cause = failed < 0 ? errno : 0;
    release_memory(owned);
    *connection = NULL;
    return finish(error, failed < 0 ? VIREO_RESULT_IO : VIREO_OK,
                  failed < 0 ? VIREO_CONNECTION_STAGE_CLOSE_SOCKET : VIREO_CONNECTION_STAGE_NONE,
                  cause, saved_errno);
}

/**
 * @brief 提交独立绑定诊断并恢复入口 errno
 *
 * @param[out] error
 *     可空独立诊断。
 * @param[in] result
 *     本次原返回码。
 * @param[in] stage
 *     本项依赖失败阶段，本层拒绝为 NONE。
 * @param[in] dependency
 *     调用期借用的完整依赖诊断，可空表示归零。
 * @param[in] saved_errno
 *     入口 errno。
 *
 * @return result 原值。
 *
 * @note 不修改绑定或资源，成功总是清诊断。
 */
static vireo_result_t loop_finish(vireo_connection_loop_error_t *error,
                                  vireo_result_t result, vireo_connection_loop_stage_t stage,
                                  vireo_event_loop_error_t const *dependency, int saved_errno)
{
    if (error != NULL) {
        *error = (vireo_connection_loop_error_t){0};
        if (result != VIREO_OK && dependency != NULL) {
            error->stage = stage;
            error->loop_error = *dependency;
        }
    }
    errno = saved_errno;
    return result;
}

/* 已知三关注位；不把五就绪位误当可登记关注。 */
static bool valid_interests(uint32_t interests)
{
    uint32_t known = VIREO_EPOLL_INTEREST_READ | VIREO_EPOLL_INTEREST_WRITE |
                     VIREO_EPOLL_INTEREST_PEER_WRITE_CLOSED;
    return (interests & ~known) == 0;
}

/**
 * @brief 清本地绑定，不访问 loop、业务 context 或 owned fd
 *
 * @param[in,out] connection
 *     存活独占对象，已成功 DEL 或所属 loop 已实际销毁。
 *
 * @note callback_active 独立保持；self-detach 不提前结束在途借用。
 */
static void clear_binding(vireo_connection_t *connection)
{
    connection->borrowed_loop = NULL;
    connection->loop_attached = false;
    connection->loop_handle = (vireo_event_loop_handle_t){0};
    connection->loop_interests = 0;
    connection->callback = NULL;
    connection->callback_context = NULL;
    connection->flow_enabled = false;
    connection->read_pressure = false;
    connection->write_pressure = false;
    connection->flow_options = (vireo_connection_flow_options_t){0};
}

/**
 * @brief 用在途标记保护本对象，正常返回后才允许外层销毁
 *
 * @param[in] loop
 *     loop 分发时的借用对象，绑定已由其公开合同校验。
 * @param[in] handle
 *     当前注册身份副本，不转移所有权。
 * @param[in] fd
 *     loop 借用的本对象 socket；收发仍由 connection 接口完成。
 * @param[in] events
 *     已按当前关注过滤的五个项目就绪位。
 * @param[in,out] context
 *     注册期间存活的 connection 借用；在途 destroy/attach 会拒绝。
 *
 * @note self-detach 可清绑定，故先复制业务代码/context；之后不访问旧业务 context。
 *     回调须正常返回；标记只保护同 Reactor 重入，不发布或同步跨线程访问。
 */
static void dispatch_connection(vireo_event_loop_t *loop, vireo_event_loop_handle_t handle,
                                 int fd, uint32_t events, void *context)
{
    (void)loop;
    (void)handle;
    (void)fd;
    vireo_connection_t *connection = context;
    vireo_connection_callback_t callback = connection->callback;
    void *callback_context = connection->callback_context;
    connection->callback_active = true;
    callback(connection, events, callback_context);
    connection->callback_active = false;
}

vireo_result_t vireo_connection_attach(vireo_connection_t *connection,
                                       vireo_event_loop_t *loop, uint32_t interests,
                                       vireo_connection_callback_t callback, void *context,
                                       vireo_connection_loop_error_t *error)
{
    int saved_errno = errno;
    if (connection == NULL || loop == NULL || callback == NULL || !valid_interests(interests)) {
        return loop_finish(error, VIREO_RESULT_INVALID_ARGUMENT,
                           VIREO_CONNECTION_LOOP_STAGE_NONE, NULL, saved_errno);
    }
    if (connection->close_state != VIREO_CONNECTION_CLOSE_OPEN ||
        connection->loop_attached || connection->callback_active) {
        return loop_finish(error, VIREO_RESULT_BUSY,
                           VIREO_CONNECTION_LOOP_STAGE_NONE, NULL, saved_errno);
    }
    vireo_event_loop_registration_t registration = {
        connection->owned_fd, interests, dispatch_connection, connection
    };
    vireo_event_loop_handle_t handle = {0};
    vireo_event_loop_error_t dependency = {0};
    vireo_result_t result = connection->loop_ops.add(
        connection->loop_ops.context, loop, &registration, &handle, &dependency);
    if (result == VIREO_OK) {
        connection->borrowed_loop = loop;
        connection->loop_attached = true;
        connection->loop_handle = handle;
        connection->loop_interests = interests;
        connection->callback = callback;
        connection->callback_context = context;
    }
    return loop_finish(error, result, VIREO_CONNECTION_LOOP_STAGE_ATTACH,
                       &dependency, saved_errno);
}

vireo_result_t vireo_connection_set_interests(vireo_connection_t *connection,
                                              uint32_t interests,
                                              vireo_connection_loop_error_t *error)
{
    int saved_errno = errno;
    if (connection == NULL || !valid_interests(interests)) {
        return loop_finish(error, VIREO_RESULT_INVALID_ARGUMENT,
                           VIREO_CONNECTION_LOOP_STAGE_NONE, NULL, saved_errno);
    }
    if (connection->close_state != VIREO_CONNECTION_CLOSE_OPEN) {
        return loop_finish(error, VIREO_RESULT_BUSY,
                           VIREO_CONNECTION_LOOP_STAGE_NONE, NULL, saved_errno);
    }
    if (!connection->loop_attached) {
        return loop_finish(error, VIREO_RESULT_NOT_FOUND,
                           VIREO_CONNECTION_LOOP_STAGE_NONE, NULL, saved_errno);
    }
    if (connection->flow_enabled) {
        return loop_finish(error, VIREO_RESULT_BUSY,
                           VIREO_CONNECTION_LOOP_STAGE_NONE, NULL, saved_errno);
    }
    vireo_event_loop_error_t dependency = {0};
    vireo_result_t result = connection->loop_ops.mod(
        connection->loop_ops.context, connection->borrowed_loop,
        connection->loop_handle, interests, &dependency);
    if (result == VIREO_OK) {
        connection->loop_interests = interests;
    }
    return loop_finish(error, result, VIREO_CONNECTION_LOOP_STAGE_UPDATE,
                       &dependency, saved_errno);
}

vireo_result_t vireo_connection_detach(vireo_connection_t *connection,
                                       vireo_connection_loop_error_t *error)
{
    int saved_errno = errno;
    if (connection == NULL) {
        return loop_finish(error, VIREO_RESULT_INVALID_ARGUMENT,
                           VIREO_CONNECTION_LOOP_STAGE_NONE, NULL, saved_errno);
    }
    if (!connection->loop_attached) {
        return loop_finish(error, VIREO_OK, VIREO_CONNECTION_LOOP_STAGE_NONE, NULL, saved_errno);
    }
    /* 先借局部身份，失败不会让本地元数据出现半清空。 */
    vireo_event_loop_handle_t handle = connection->loop_handle;
    vireo_event_loop_error_t dependency = {0};
    vireo_result_t result = connection->loop_ops.del(
        connection->loop_ops.context, connection->borrowed_loop, &handle, &dependency);
    if (result == VIREO_OK) {
        clear_binding(connection);
    }
    return loop_finish(error, result, VIREO_CONNECTION_LOOP_STAGE_DETACH,
                       &dependency, saved_errno);
}

vireo_result_t vireo_connection_forget_destroyed_loop(vireo_connection_t *connection,
                                                      vireo_connection_loop_error_t *error)
{
    int saved_errno = errno;
    if (connection == NULL) {
        return loop_finish(error, VIREO_RESULT_INVALID_ARGUMENT,
                           VIREO_CONNECTION_LOOP_STAGE_NONE, NULL, saved_errno);
    }
    if (connection->callback_active) {
        return loop_finish(error, VIREO_RESULT_BUSY,
                           VIREO_CONNECTION_LOOP_STAGE_NONE, NULL, saved_errno);
    }
    /* loop 已由 caller 实际销毁；只丢弃本地副本，不解引用悬空借用。 */
    clear_binding(connection);
    return loop_finish(error, VIREO_OK, VIREO_CONNECTION_LOOP_STAGE_NONE, NULL, saved_errno);
}

/**
 * @brief 由总占用和旧压力计算迟滞，不改对象
 *
 * @param[in] occupied
 *     已由公开 buffer 观察得到的未消费字节数。
 * @param[in] low
 *     已验证的解除阈值。
 * @param[in] high
 *     已验证的锁定阈值，严格大于 low。
 * @param[in] pressure
 *     上次成功提交的锁存；重配置传 false。
 *
 * @return 新压力；中间区间保留旧状态。
 */
static bool flow_pressure(size_t occupied, size_t low, size_t high, bool pressure)
{
    return pressure ? occupied > low : occupied >= high;
}

/**
 * @brief 形成完整候选关注，必要 MOD 成功后一次发布策略
 *
 * @param[in,out] connection
 *     已绑定存活 loop 的独占对象。
 * @param[in] options
 *     已验证的配置，成功复制，不保存输入地址。
 * @param[in] info
 *     同 Reactor 的完整公开观察快照。
 * @param[in] reset
 *     重配置时从未锁状态初始化；刷新保留中间区间旧压力。
 * @param[in] stage
 *     MOD 失败时的本层诊断阶段。
 * @param[out] error
 *     可空独立完整诊断。
 * @param[in] saved_errno
 *     公共入口 errno。
 *
 * @return 不需 MOD 时 OK，否则原依赖分类；失败保持全部旧策略。
 *
 * @note 不修改任何字节；无变化关注仍可提交变化的压力锁存。
 */
static vireo_result_t flow_apply(vireo_connection_t *connection,
                                 vireo_connection_flow_options_t const *options,
                                 vireo_connection_info_t const *info, bool reset,
                                 vireo_connection_loop_stage_t stage,
                                 vireo_connection_loop_error_t *error, int saved_errno)
{
    bool read_pressure = flow_pressure(info->read_buffer.readable_size,
        options->read_low, options->read_high, !reset && connection->read_pressure);
    bool write_pressure = flow_pressure(info->write_buffer.readable_size,
        options->write_low, options->write_high, !reset && connection->write_pressure);
    uint32_t interests = 0;
    if (!info->read_eof && !read_pressure && !write_pressure) {
        interests = VIREO_EPOLL_INTEREST_READ | VIREO_EPOLL_INTEREST_PEER_WRITE_CLOSED;
    }
    if (info->write_buffer.readable_size != 0) {
        interests |= VIREO_EPOLL_INTEREST_WRITE;
    }
    if (interests != connection->loop_interests) {
        vireo_event_loop_error_t dependency = {0};
        vireo_result_t result = connection->loop_ops.mod(
            connection->loop_ops.context, connection->borrowed_loop,
            connection->loop_handle, interests, &dependency);
        if (result != VIREO_OK) {
            return loop_finish(error, result, stage, &dependency, saved_errno);
        }
    }
    connection->flow_options = *options;
    connection->flow_enabled = true;
    connection->read_pressure = read_pressure;
    connection->write_pressure = write_pressure;
    connection->loop_interests = interests;
    return loop_finish(error, VIREO_OK, VIREO_CONNECTION_LOOP_STAGE_NONE, NULL, saved_errno);
}

vireo_result_t vireo_connection_flow_configure(
    vireo_connection_t *connection, vireo_connection_flow_options_t const *options,
    vireo_connection_loop_error_t *error)
{
    int saved_errno = errno;
    if (connection == NULL || options == NULL) {
        return loop_finish(error, VIREO_RESULT_INVALID_ARGUMENT,
                           VIREO_CONNECTION_LOOP_STAGE_NONE, NULL, saved_errno);
    }
    if (connection->close_state != VIREO_CONNECTION_CLOSE_OPEN) {
        return loop_finish(error, VIREO_RESULT_BUSY,
                           VIREO_CONNECTION_LOOP_STAGE_NONE, NULL, saved_errno);
    }
    if (!connection->loop_attached) {
        return loop_finish(error, VIREO_RESULT_NOT_FOUND,
                           VIREO_CONNECTION_LOOP_STAGE_NONE, NULL, saved_errno);
    }
    vireo_connection_info_t info;
    size_t protocol_max = 0;
    if (vireo_connection_inspect(connection, &info) != VIREO_OK ||
        vireo_checked_u64_to_size((uint64_t)VIREO_PROTOCOL_MAX_BODY_SIZE,
                                  &protocol_max) != VIREO_OK ||
        vireo_checked_size_add((size_t)VIREO_PROTOCOL_HEADER_SIZE,
                                protocol_max, &protocol_max) != VIREO_OK) {
        return loop_finish(error, VIREO_RESULT_INTERNAL,
                           VIREO_CONNECTION_LOOP_STAGE_NONE, NULL, saved_errno);
    }
    /* 先验证帧正下界，随后 max_frame_bytes-1 不会下溢。 */
    if (options->max_frame_bytes < (size_t)VIREO_PROTOCOL_HEADER_SIZE ||
        options->max_frame_bytes > info.read_buffer.capacity ||
        options->max_frame_bytes > protocol_max ||
        options->read_low < options->max_frame_bytes - 1 ||
        options->read_low >= options->read_high ||
        options->read_high > info.read_buffer.capacity ||
        options->write_low >= options->write_high ||
        options->write_high > info.write_buffer.capacity) {
        return loop_finish(error, VIREO_RESULT_RANGE,
                           VIREO_CONNECTION_LOOP_STAGE_NONE, NULL, saved_errno);
    }
    return flow_apply(connection, options, &info, true,
                      VIREO_CONNECTION_LOOP_STAGE_FLOW_CONFIGURE, error, saved_errno);
}

vireo_result_t vireo_connection_flow_refresh(vireo_connection_t *connection,
                                             vireo_connection_loop_error_t *error)
{
    int saved_errno = errno;
    if (connection == NULL) {
        return loop_finish(error, VIREO_RESULT_INVALID_ARGUMENT,
                           VIREO_CONNECTION_LOOP_STAGE_NONE, NULL, saved_errno);
    }
    if (connection->close_state != VIREO_CONNECTION_CLOSE_OPEN) {
        return loop_finish(error, VIREO_RESULT_BUSY,
                           VIREO_CONNECTION_LOOP_STAGE_NONE, NULL, saved_errno);
    }
    if (!connection->loop_attached || !connection->flow_enabled) {
        return loop_finish(error, VIREO_RESULT_NOT_FOUND,
                           VIREO_CONNECTION_LOOP_STAGE_NONE, NULL, saved_errno);
    }
    vireo_connection_info_t info;
    if (vireo_connection_inspect(connection, &info) != VIREO_OK) {
        return loop_finish(error, VIREO_RESULT_INTERNAL,
                           VIREO_CONNECTION_LOOP_STAGE_NONE, NULL, saved_errno);
    }
    return flow_apply(connection, &connection->flow_options, &info, false,
                      VIREO_CONNECTION_LOOP_STAGE_FLOW_REFRESH, error, saved_errno);
}

vireo_result_t vireo_connection_flow_disable(vireo_connection_t *connection,
                                             vireo_connection_loop_error_t *error)
{
    int saved_errno = errno;
    if (connection == NULL) {
        return loop_finish(error, VIREO_RESULT_INVALID_ARGUMENT,
                           VIREO_CONNECTION_LOOP_STAGE_NONE, NULL, saved_errno);
    }
    if (connection->close_state != VIREO_CONNECTION_CLOSE_OPEN) {
        return loop_finish(error, VIREO_RESULT_BUSY,
                           VIREO_CONNECTION_LOOP_STAGE_NONE, NULL, saved_errno);
    }
    connection->flow_enabled = false;
    connection->read_pressure = false;
    connection->write_pressure = false;
    connection->flow_options = (vireo_connection_flow_options_t){0};
    return loop_finish(error, VIREO_OK, VIREO_CONNECTION_LOOP_STAGE_NONE, NULL, saved_errno);
}

/**
 * @brief 按永久模式更新逻辑阶段，必要 MOD 成功后提交关注
 *
 * @param[in,out] connection
 *     已合法提交关闭意图的存活对象，绑定 loop 必须仍存活。
 * @param[in] stage
 *     必要 MOD 失败对应的关闭诊断阶段。
 * @param[out] error
 *     可空独立完整诊断。
 * @param[in] saved_errno
 *     公共入口 errno。
 *
 * @return 不需 MOD 为 OK，否则原依赖分类。
 *
 * @note 逻辑阶段先于 MOD 发布；失败不能把已关闭对象重新变成 OPEN。
 */
static vireo_result_t close_sync(vireo_connection_t *connection,
                                 vireo_connection_loop_stage_t stage,
                                 vireo_connection_loop_error_t *error, int saved_errno)
{
    vireo_buffer_info_t info;
    if (vireo_buffer_inspect(connection->write_buffer, &info) != VIREO_OK) {
        return loop_finish(error, VIREO_RESULT_INTERNAL,
                           VIREO_CONNECTION_LOOP_STAGE_NONE, NULL, saved_errno);
    }
    bool draining = connection->close_mode == VIREO_CONNECTION_CLOSE_MODE_DRAIN &&
                    info.readable_size != 0;
    connection->close_state = draining ? VIREO_CONNECTION_CLOSE_DRAINING :
                                        VIREO_CONNECTION_CLOSE_READY;
    uint32_t interests = draining ? VIREO_EPOLL_INTEREST_WRITE : 0;
    if (connection->loop_attached && interests != connection->loop_interests) {
        vireo_event_loop_error_t dependency = {0};
        vireo_result_t result = connection->loop_ops.mod(
            connection->loop_ops.context, connection->borrowed_loop,
            connection->loop_handle, interests, &dependency);
        if (result != VIREO_OK) {
            return loop_finish(error, result, stage, &dependency, saved_errno);
        }
        connection->loop_interests = interests;
    }
    return loop_finish(error, VIREO_OK, VIREO_CONNECTION_LOOP_STAGE_NONE, NULL, saved_errno);
}

vireo_result_t vireo_connection_request_close(
    vireo_connection_t *connection, vireo_connection_close_mode_t mode,
    vireo_connection_close_reason_t reason, vireo_connection_loop_error_t *error)
{
    int saved_errno = errno;
    if (connection == NULL ||
        (mode != VIREO_CONNECTION_CLOSE_MODE_DRAIN &&
         mode != VIREO_CONNECTION_CLOSE_MODE_IMMEDIATE) ||
        reason < VIREO_CONNECTION_CLOSE_REASON_APPLICATION ||
        reason > VIREO_CONNECTION_CLOSE_REASON_RESOURCE_LIMIT) {
        return loop_finish(error, VIREO_RESULT_INVALID_ARGUMENT,
                           VIREO_CONNECTION_LOOP_STAGE_NONE, NULL, saved_errno);
    }
    if (connection->close_mode == VIREO_CONNECTION_CLOSE_MODE_IMMEDIATE &&
        mode == VIREO_CONNECTION_CLOSE_MODE_DRAIN) {
        return loop_finish(error, VIREO_RESULT_BUSY,
                           VIREO_CONNECTION_LOOP_STAGE_NONE, NULL, saved_errno);
    }
    if (connection->close_state == VIREO_CONNECTION_CLOSE_OPEN) {
        connection->close_reason = reason;
        connection->close_state = mode == VIREO_CONNECTION_CLOSE_MODE_DRAIN ?
            VIREO_CONNECTION_CLOSE_DRAINING : VIREO_CONNECTION_CLOSE_READY;
    }
    connection->close_mode = mode;
    if (mode == VIREO_CONNECTION_CLOSE_MODE_IMMEDIATE) {
        connection->close_state = VIREO_CONNECTION_CLOSE_READY;
    }
    return close_sync(connection, VIREO_CONNECTION_LOOP_STAGE_REQUEST_CLOSE, error, saved_errno);
}

vireo_result_t vireo_connection_close_refresh(vireo_connection_t *connection,
                                              vireo_connection_loop_error_t *error)
{
    int saved_errno = errno;
    if (connection == NULL) {
        return loop_finish(error, VIREO_RESULT_INVALID_ARGUMENT,
                           VIREO_CONNECTION_LOOP_STAGE_NONE, NULL, saved_errno);
    }
    if (connection->close_state == VIREO_CONNECTION_CLOSE_OPEN) {
        return loop_finish(error, VIREO_RESULT_NOT_FOUND,
                           VIREO_CONNECTION_LOOP_STAGE_NONE, NULL, saved_errno);
    }
    return close_sync(connection, VIREO_CONNECTION_LOOP_STAGE_CLOSE_REFRESH, error, saved_errno);
}
