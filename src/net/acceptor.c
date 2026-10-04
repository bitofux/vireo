/*
- PROJECT : VIREO
- FILE    : acceptor.c
- AUTHOR  : bitofux
- DATE    : 2026-10-04
- BRIEF   : 此模块负责：
- -- 预配置监听 fd 的只读查询、固定控制预算与最后发布
- -- 失败双 owner 保持、单次 close 消费与入口 errno 恢复
- -- accept4 双预算、部分进度与客户 fd 即时移交
- -- public loop 借用绑定与业务回调在途保护
 */
#define _GNU_SOURCE
#include "acceptor_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>

struct vireo_acceptor {
    int owned_fd;
    vireo_acceptor_info_t info;
    vireo_acceptor_ops_t ops;
    vireo_event_loop_t *borrowed_loop;
    vireo_event_loop_handle_t loop_handle;
    vireo_acceptor_callback_t callback;
    void *callback_context;
};

/**
 * @brief 申请本层唯一固定控制块
 *
 * @param[in] context
 *     默认表无状态，忽略。
 * @param[in] bytes
 *     已检查预算的正申请大小。
 *
 * @return malloc 原指针或 NULL。
 *
 * @note 不接管 fd；成功内存由同表 deallocate 释放。
 */
static void *system_allocate(void *context, size_t bytes)
{
    (void)context;
    return malloc(bytes);
}

/**
 * @brief 释放同表取得的控制块
 *
 * @param[in] context
 *     默认表无状态，忽略。
 * @param[in] memory
 *     已结束内部使用的唯一 malloc 指针。
 *
 * @note 不再访问释放后的对象；fd 清理须已完成，errno 由外层恢复。
 */
static void system_deallocate(void *context, void *memory)
{
    (void)context;
    free(memory);
}

/**
 * @brief 单次只读查询 fd 属性
 *
 * @param[in] context
 *     默认表无状态，忽略。
 * @param[in] fd
 *     构造期间借用的调用者 fd。
 * @param[in] command
 *     仅 F_GETFL 或 F_GETFD。
 *
 * @return fcntl 原属性值或 -1，失败保留原 errno。
 *
 * @note 不修改属性或所有权，不自动重试。
 */
static int system_get_flags(void *context, int fd, int command)
{
    (void)context;
    return fcntl(fd, command);
}

/**
 * @brief 单次只读查询 socket 类型或监听状态
 *
 * @param[in] context
 *     默认表无状态，忽略。
 * @param[in] fd
 *     构造期间借用的调用者 fd。
 * @param[in] option
 *     仅 SO_TYPE 或 SO_ACCEPTCONN。
 * @param[out] value
 *     非空局部 int 输出，失败时不使用。
 * @param[in,out] length
 *     非空局部长度，入口为 sizeof(int)，成功后由上层验证。
 *
 * @return getsockopt 原 0 或 -1，失败保留原 errno。
 *
 * @note 不设置 socket 选项，不自动重试。
 */
static int system_get_option(void *context, int fd, int option, int *value, socklen_t *length)
{
    (void)context;
    return getsockopt(fd, SOL_SOCKET, option, value, length);
}

/**
 * @brief 对已接管 listener 单次 close
 *
 * @param[in] context
 *     默认表无状态，忽略。
 * @param[in] fd
 *     已结束所有使用的唯一监听 fd。
 *
 * @return close 原 0 或 -1，失败保留原 errno。
 *
 * @note Linux fd 消费语义由外层销毁处理；不重试可能已复用的整数。
 */
static int system_close(void *context, int fd)
{
    (void)context;
    return close(fd);
}

/**
 * @brief 单次取得新客户 fd，直接请求所需属性
 *
 * @param[in] context
 *     默认表无状态，忽略。
 * @param[in] listener_fd
 *     当前对象唯一拥有的非阻塞 listener。
 * @param[in] flags
 *     SOCK_NONBLOCK|SOCK_CLOEXEC。
 *
 * @return accept4 原非负新 fd 或 -1，失败保留原 errno。
 *
 * @note 不取地址、不重试、不 fallback，成功 fd 由外层立即发布给调用者。
 */
static int system_accept(void *context, int listener_fd, int flags)
{
    (void)context;
    return accept4(listener_fd, NULL, NULL, flags);
}

/**
 * @brief 通过封板公共入口单次登记，不保存输入地址
 *
 * @param[in] context
 *     默认无状态，忽略。
 * @param[in,out] loop
 *     存活借用 loop。
 * @param[in] registration
 *     独立局部绑定，fd/代码/context 由上层管理。
 * @param[in,out] handle
 *     独立局部空身份，成功才发布。
 * @param[out] error
 *     独立局部完整依赖诊断。
 *
 * @return 公共 ADD 原结果。
 *
 * @note 不读取旧私有头或布局，不自动重试/接管资源。
 */
static vireo_result_t system_loop_add(void *context, vireo_event_loop_t *loop,
                                      vireo_event_loop_registration_t const *registration,
                                      vireo_event_loop_handle_t *handle,
                                      vireo_event_loop_error_t *error)
{
    (void)context;
    return vireo_event_loop_add(loop, registration, handle, error);
}

/**
 * @brief 通过封板公共入口单次替换 READ 关注
 *
 * @param[in] context
 *     默认无状态，忽略。
 * @param[in,out] loop
 *     存活借用 loop。
 * @param[in] handle
 *     当前隐藏注册身份副本。
 * @param[in] interests
 *     READ 或零。
 * @param[out] error
 *     独立局部完整依赖诊断。
 *
 * @return 公共 MOD 原结果。
 *
 * @note 同值也 MOD，不调整上层策略或重试。
 */
static vireo_result_t system_loop_mod(void *context, vireo_event_loop_t *loop,
                                      vireo_event_loop_handle_t handle, uint32_t interests,
                                      vireo_event_loop_error_t *error)
{
    (void)context;
    return vireo_event_loop_mod(loop, handle, interests, error);
}

/**
 * @brief 通过封板公共入口单次注销
 *
 * @param[in] context
 *     默认无状态，忽略。
 * @param[in,out] loop
 *     存活借用 loop。
 * @param[in,out] handle
 *     当前身份的独立局部副本，成功清零。
 * @param[out] error
 *     独立局部完整依赖诊断。
 *
 * @return 公共 DEL 原结果。
 *
 * @note 不关闭 listener 或业务资源，失败不转换/重试。
 */
static vireo_result_t system_loop_del(void *context, vireo_event_loop_t *loop,
                                      vireo_event_loop_handle_t *handle,
                                      vireo_event_loop_error_t *error)
{
    (void)context;
    return vireo_event_loop_del(loop, handle, error);
}

static vireo_acceptor_ops_t const system_ops = {
    NULL, system_allocate, system_deallocate, system_get_flags, system_get_option, system_close,
    system_accept, system_loop_add, system_loop_mod, system_loop_del
};

/**
 * @brief 提交独立诊断并恢复最外层入口 errno
 *
 * @param[in] result
 *     已确定的结果分类。
 * @param[in] stage
 *     此次结果来源阶段。
 * @param[in] cause
 *     IO 原 errno，其他分类为 0。
 * @param[out] error
 *     可空独立诊断。
 * @param[in] saved_errno
 *     最外层入口值。
 *
 * @return result 原值。
 *
 * @note 不操作资源，不根据当前 errno 推断结果。
 */
static vireo_result_t finish(vireo_result_t result, vireo_acceptor_stage_t stage, int cause,
                             vireo_acceptor_error_t *error, int saved_errno)
{
    if (error != NULL) {
        *error = (vireo_acceptor_error_t){stage, cause};
    }
    errno = saved_errno;
    return result;
}

/**
 * @brief 按固定顺序查询借用 fd，不改变属性或所有权
 *
 * @param[in] ops
 *     完整只读依赖表，context 在调用期间存活。
 * @param[in] fd
 *     调用者拥有的非负 fd，0 合法。
 * @param[out] cause
 *     非空独立局部值，仅 IO 时写原 errno。
 *
 * @return OK、属性不符 INVALID_ARGUMENT、查询失败 IO 或长度异常 INTERNAL。
 *
 * @note 每项一次，不 retry；输出长度检查先于使用 getsockopt 返回值。
 */
static vireo_result_t validate_fd(vireo_acceptor_ops_t const *ops, int fd, int *cause)
{
    int flags = ops->get_flags(ops->context, fd, F_GETFL);
    if (flags < 0) {
        *cause = errno;
        return VIREO_RESULT_IO;
    }
    if ((flags & O_NONBLOCK) == 0) return VIREO_RESULT_INVALID_ARGUMENT;
    flags = ops->get_flags(ops->context, fd, F_GETFD);
    if (flags < 0) {
        *cause = errno;
        return VIREO_RESULT_IO;
    }
    if ((flags & FD_CLOEXEC) == 0) return VIREO_RESULT_INVALID_ARGUMENT;
    int const options[] = {SO_TYPE, SO_ACCEPTCONN};
    for (size_t i = 0; i < sizeof(options) / sizeof(options[0]); ++i) {
        int value = 0;
        socklen_t length = (socklen_t)sizeof(value);
        if (ops->get_option(ops->context, fd, options[i], &value, &length) < 0) {
            *cause = errno;
            return VIREO_RESULT_IO;
        }
        if (length != (socklen_t)sizeof(value)) return VIREO_RESULT_INTERNAL;
        if ((i == 0 && value != SOCK_STREAM) || (i == 1 && value == 0)) {
            return VIREO_RESULT_INVALID_ARGUMENT;
        }
    }
    return VIREO_OK;
}

vireo_result_t vireo_acceptor_create_with_ops(vireo_acceptor_options_t const *options,
                                             int *fd_owner, vireo_acceptor_ops_t const *ops,
                                             vireo_acceptor_t **out_acceptor,
                                             vireo_acceptor_error_t *error)
{
    int const saved_errno = errno;
    if (options == NULL || fd_owner == NULL || *fd_owner < 0 || out_acceptor == NULL ||
        *out_acceptor != NULL || options->max_memory_bytes == 0 || ops == NULL ||
        ops->allocate == NULL || ops->deallocate == NULL || ops->get_flags == NULL ||
        ops->get_option == NULL || ops->close_fd == NULL || ops->accept_client == NULL ||
        ops->loop_add == NULL || ops->loop_mod == NULL || ops->loop_del == NULL) {
        return finish(VIREO_RESULT_INVALID_ARGUMENT, VIREO_ACCEPTOR_STAGE_NONE, 0,
                      error, saved_errno);
    }
    size_t const bytes = sizeof(vireo_acceptor_t);
    if (options->max_memory_bytes > VIREO_ACCEPTOR_MAX_MEMORY ||
        options->max_memory_bytes < bytes) {
        return finish(VIREO_RESULT_RANGE, VIREO_ACCEPTOR_STAGE_NONE, 0, error, saved_errno);
    }
    int cause = 0;
    vireo_result_t const result = validate_fd(ops, *fd_owner, &cause);
    if (result != VIREO_OK) {
        return finish(result, result == VIREO_RESULT_INVALID_ARGUMENT ? VIREO_ACCEPTOR_STAGE_NONE :
                      VIREO_ACCEPTOR_STAGE_VALIDATE_FD, cause, error, saved_errno);
    }
    vireo_acceptor_t *acceptor = ops->allocate(ops->context, bytes);
    if (acceptor == NULL) {
        return finish(VIREO_RESULT_NO_MEMORY, VIREO_ACCEPTOR_STAGE_ALLOCATE_CONTROL, 0,
                      error, saved_errno);
    }
    *acceptor = (vireo_acceptor_t){
        .owned_fd = *fd_owner,
        .info = {.allocation_bytes = bytes, .max_memory_bytes = options->max_memory_bytes},
        .ops = *ops
    };
    *fd_owner = -1;
    *out_acceptor = acceptor;
    return finish(VIREO_OK, VIREO_ACCEPTOR_STAGE_NONE, 0, error, saved_errno);
}

vireo_result_t vireo_acceptor_create(vireo_acceptor_options_t const *options,
                                    int *fd_owner, vireo_acceptor_t **out_acceptor,
                                    vireo_acceptor_error_t *error)
{
    return vireo_acceptor_create_with_ops(options, fd_owner, &system_ops, out_acceptor, error);
}

vireo_result_t vireo_acceptor_inspect(vireo_acceptor_t const *acceptor,
                                     vireo_acceptor_info_t *out_info)
{
    if (acceptor == NULL || out_info == NULL) return VIREO_RESULT_INVALID_ARGUMENT;
    *out_info = acceptor->info;
    return VIREO_OK;
}

vireo_result_t vireo_acceptor_destroy(vireo_acceptor_t **owner, vireo_acceptor_error_t *error)
{
    int const saved_errno = errno;
    if (owner == NULL) {
        return finish(VIREO_RESULT_INVALID_ARGUMENT, VIREO_ACCEPTOR_STAGE_NONE, 0,
                      error, saved_errno);
    }
    if (*owner == NULL) return finish(VIREO_OK, VIREO_ACCEPTOR_STAGE_NONE, 0, error, saved_errno);
    vireo_acceptor_t *acceptor = *owner;
    if (acceptor->info.loop_attached || acceptor->info.callback_active) {
        return finish(VIREO_RESULT_BUSY, VIREO_ACCEPTOR_STAGE_NONE, 0, error, saved_errno);
    }
    vireo_acceptor_ops_t const ops = acceptor->ops;
    int const result = ops.close_fd(ops.context, acceptor->owned_fd);
    int const cause = result < 0 ? errno : 0;
    ops.deallocate(ops.context, acceptor);
    *owner = NULL;
    return finish(result < 0 ? VIREO_RESULT_IO : VIREO_OK,
                  result < 0 ? VIREO_ACCEPTOR_STAGE_CLOSE_LISTENER : VIREO_ACCEPTOR_STAGE_NONE,
                  cause, error, saved_errno);
}

/**
 * @brief 判断本项已接受的可跳接入错误集合
 *
 * @param[in] cause
 *     本次负返回后立即保存的 errno。
 *
 * @retval true
 *     坏接入或 Linux 文档列出的待处理网络错误，可计预算后继续下一次。
 * @retval false
 *     其余分类交由外层分别处理空队列或立即 IO。
 *
 * @note 仅分类整数，不自行重试或推断 listener 的存活状态。
 */
static bool transient_accept_error(int cause)
{
    switch (cause) {
    case ECONNABORTED:
    case ENETDOWN:
    case EPROTO:
    case ENOPROTOOPT:
    case EHOSTDOWN:
    case ENONET:
    case EHOSTUNREACH:
    case EOPNOTSUPP:
    case ENETUNREACH:
        return true;
    default:
        return false;
    }
}

vireo_result_t vireo_acceptor_accept_batch(vireo_acceptor_t *acceptor,
                                          vireo_acceptor_accept_budget_t const *budget,
                                          int *fd_owners, size_t capacity,
                                          vireo_acceptor_accept_info_t *out_info,
                                          vireo_acceptor_error_t *error)
{
    int const saved_errno = errno;
    if (acceptor == NULL || budget == NULL || fd_owners == NULL || out_info == NULL ||
        capacity == 0 || budget->max_accepts == 0 || budget->max_syscalls == 0) {
        return finish(VIREO_RESULT_INVALID_ARGUMENT, VIREO_ACCEPTOR_STAGE_NONE, 0,
                      error, saved_errno);
    }
    if (capacity > VIREO_ACCEPTOR_MAX_BATCH || budget->max_accepts > VIREO_ACCEPTOR_MAX_BATCH) {
        return finish(VIREO_RESULT_RANGE, VIREO_ACCEPTOR_STAGE_NONE, 0, error, saved_errno);
    }
    size_t const limit = budget->max_accepts < capacity ? budget->max_accepts : capacity;
    for (size_t i = 0; i < limit; ++i) {
        if (fd_owners[i] != -1) {
            return finish(VIREO_RESULT_INVALID_ARGUMENT, VIREO_ACCEPTOR_STAGE_NONE, 0,
                          error, saved_errno);
        }
    }
    vireo_acceptor_accept_info_t info = {0, 0, 0, VIREO_ACCEPTOR_ACCEPT_BATCH_FULL};
    for (;;) {
        if (info.accepted_count == limit) {
            info.stop_reason = VIREO_ACCEPTOR_ACCEPT_BATCH_FULL;
            break;
        }
        if (info.accept_calls == budget->max_syscalls) {
            info.stop_reason = VIREO_ACCEPTOR_ACCEPT_CALL_BUDGET;
            break;
        }
        /* 各次递增前都有严格上界；成功取得新 fd 后没有可失败步骤阻隔发布。 */
        ++info.accept_calls;
        int const fd = acceptor->ops.accept_client(acceptor->ops.context, acceptor->owned_fd,
                                                   SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (fd >= 0) {
            fd_owners[info.accepted_count] = fd;
            ++info.accepted_count;
            continue;
        }
        int const cause = errno;
        if (cause == EAGAIN || cause == EWOULDBLOCK) {
            info.stop_reason = VIREO_ACCEPTOR_ACCEPT_WOULD_BLOCK;
            break;
        }
        if (transient_accept_error(cause)) {
            ++info.transient_errors;
            continue;
        }
        info.stop_reason = VIREO_ACCEPTOR_ACCEPT_IO_ERROR;
        *out_info = info;
        return finish(VIREO_RESULT_IO, VIREO_ACCEPTOR_STAGE_ACCEPT_CLIENT, cause,
                      error, saved_errno);
    }
    *out_info = info;
    return finish(VIREO_OK, VIREO_ACCEPTOR_STAGE_NONE, 0, error, saved_errno);
}

/**
 * @brief 提交绑定独立诊断，保持最外层 errno
 *
 * @param[in] result
 *     本层或依赖确定的分类。
 * @param[in] stage
 *     NONE 或对应依赖操作阶段。
 * @param[in] original
 *     依赖失败时的完整原诊断，本层拒绝/成功为 NULL。
 * @param[out] error
 *     可空独立输出。
 * @param[in] saved_errno
 *     最外层入口值。
 *
 * @return result 原分类。
 *
 * @note 不访问 loop/业务资源，不根据当前 errno 改写原原因。
 */
static vireo_result_t loop_finish(vireo_result_t result, vireo_acceptor_loop_stage_t stage,
                                  vireo_event_loop_error_t const *original,
                                  vireo_acceptor_loop_error_t *error, int saved_errno)
{
    if (error != NULL) {
        *error = (vireo_acceptor_loop_error_t){
            .stage = stage,
            .loop_error = original != NULL ? *original : (vireo_event_loop_error_t){0}
        };
    }
    errno = saved_errno;
    return result;
}

/**
 * @brief 清本地绑定但保持当前回调在途标记
 *
 * @param[in,out] acceptor
 *     已成功 DEL 或正确 loop 已彻底销毁的存活对象。
 *
 * @note 不访问旧 loop/业务 context，不关闭 listener；self-detach 不提前解除保护。
 */
static void clear_binding(vireo_acceptor_t *acceptor)
{
    acceptor->borrowed_loop = NULL;
    acceptor->loop_handle = (vireo_event_loop_handle_t){0};
    acceptor->callback = NULL;
    acceptor->callback_context = NULL;
    acceptor->info.loop_attached = false;
    acceptor->info.read_enabled = false;
}

/**
 * @brief 复制业务借用并在正常回调返回后结束在途保护
 *
 * @param[in] loop
 *     公共分发已验证的当前 loop，仅回调期间借用。
 * @param[in] handle
 *     当前数值身份，不增加所有权。
 * @param[in] fd
 *     本对象 listener 的借用整数，业务仍用本模块入口。
 * @param[in] events
 *     已按当前 READ 开关过滤的就绪位，ERROR/HANGUP 始终保留。
 * @param[in,out] context
 *     存活 acceptor 借用，在途 destroy/attach/forget 会拒绝。
 *
 * @note 先复制代码/context 以允许 self-detach；回调后不访问旧业务 context。
 *     业务须正常返回；标记保护 Reactor 重入，不同步跨线程或修复违约回调。
 */
static void dispatch_acceptor(vireo_event_loop_t *loop, vireo_event_loop_handle_t handle,
                              int fd, uint32_t events, void *context)
{
    (void)loop;
    (void)handle;
    (void)fd;
    vireo_acceptor_t *acceptor = context;
    vireo_acceptor_callback_t const callback = acceptor->callback;
    void *callback_context = acceptor->callback_context;
    acceptor->info.callback_active = true;
    callback(acceptor, events, callback_context);
    acceptor->info.callback_active = false;
}

vireo_result_t vireo_acceptor_attach(vireo_acceptor_t *acceptor, vireo_event_loop_t *loop,
                                    bool read_enabled, vireo_acceptor_callback_t callback,
                                    void *context, vireo_acceptor_loop_error_t *error)
{
    int const saved_errno = errno;
    if (acceptor == NULL || loop == NULL || callback == NULL) {
        return loop_finish(VIREO_RESULT_INVALID_ARGUMENT, VIREO_ACCEPTOR_LOOP_STAGE_NONE,
                           NULL, error, saved_errno);
    }
    if (acceptor->info.loop_attached || acceptor->info.callback_active) {
        return loop_finish(VIREO_RESULT_BUSY, VIREO_ACCEPTOR_LOOP_STAGE_NONE,
                           NULL, error, saved_errno);
    }
    vireo_event_loop_registration_t const registration = {
        acceptor->owned_fd, read_enabled ? VIREO_EPOLL_INTEREST_READ : 0,
        dispatch_acceptor, acceptor
    };
    vireo_event_loop_handle_t handle = {0};
    vireo_event_loop_error_t original = {0};
    vireo_result_t const result = acceptor->ops.loop_add(acceptor->ops.context, loop,
                                                        &registration, &handle, &original);
    if (result != VIREO_OK) {
        return loop_finish(result, VIREO_ACCEPTOR_LOOP_STAGE_ATTACH, &original,
                           error, saved_errno);
    }
    acceptor->borrowed_loop = loop;
    acceptor->loop_handle = handle;
    acceptor->callback = callback;
    acceptor->callback_context = context;
    acceptor->info.loop_attached = true;
    acceptor->info.read_enabled = read_enabled;
    return loop_finish(VIREO_OK, VIREO_ACCEPTOR_LOOP_STAGE_NONE, NULL, error, saved_errno);
}

vireo_result_t vireo_acceptor_set_read_enabled(vireo_acceptor_t *acceptor, bool read_enabled,
                                               vireo_acceptor_loop_error_t *error)
{
    int const saved_errno = errno;
    if (acceptor == NULL) {
        return loop_finish(VIREO_RESULT_INVALID_ARGUMENT, VIREO_ACCEPTOR_LOOP_STAGE_NONE,
                           NULL, error, saved_errno);
    }
    if (!acceptor->info.loop_attached) {
        return loop_finish(VIREO_RESULT_NOT_FOUND, VIREO_ACCEPTOR_LOOP_STAGE_NONE,
                           NULL, error, saved_errno);
    }
    vireo_event_loop_error_t original = {0};
    vireo_result_t const result = acceptor->ops.loop_mod(acceptor->ops.context,
        acceptor->borrowed_loop, acceptor->loop_handle,
        read_enabled ? VIREO_EPOLL_INTEREST_READ : 0, &original);
    if (result != VIREO_OK) {
        return loop_finish(result, VIREO_ACCEPTOR_LOOP_STAGE_UPDATE, &original,
                           error, saved_errno);
    }
    acceptor->info.read_enabled = read_enabled;
    return loop_finish(VIREO_OK, VIREO_ACCEPTOR_LOOP_STAGE_NONE, NULL, error, saved_errno);
}

vireo_result_t vireo_acceptor_detach(vireo_acceptor_t *acceptor,
                                    vireo_acceptor_loop_error_t *error)
{
    int const saved_errno = errno;
    if (acceptor == NULL) {
        return loop_finish(VIREO_RESULT_INVALID_ARGUMENT, VIREO_ACCEPTOR_LOOP_STAGE_NONE,
                           NULL, error, saved_errno);
    }
    if (!acceptor->info.loop_attached) {
        return loop_finish(VIREO_OK, VIREO_ACCEPTOR_LOOP_STAGE_NONE, NULL, error, saved_errno);
    }
    vireo_event_loop_handle_t handle = acceptor->loop_handle;
    vireo_event_loop_error_t original = {0};
    vireo_result_t const result = acceptor->ops.loop_del(acceptor->ops.context,
        acceptor->borrowed_loop, &handle, &original);
    if (result != VIREO_OK) {
        return loop_finish(result, VIREO_ACCEPTOR_LOOP_STAGE_DETACH, &original,
                           error, saved_errno);
    }
    clear_binding(acceptor);
    return loop_finish(VIREO_OK, VIREO_ACCEPTOR_LOOP_STAGE_NONE, NULL, error, saved_errno);
}

vireo_result_t vireo_acceptor_forget_destroyed_loop(vireo_acceptor_t *acceptor,
                                                   vireo_acceptor_loop_error_t *error)
{
    int const saved_errno = errno;
    if (acceptor == NULL) {
        return loop_finish(VIREO_RESULT_INVALID_ARGUMENT, VIREO_ACCEPTOR_LOOP_STAGE_NONE,
                           NULL, error, saved_errno);
    }
    if (acceptor->info.callback_active) {
        return loop_finish(VIREO_RESULT_BUSY, VIREO_ACCEPTOR_LOOP_STAGE_NONE,
                           NULL, error, saved_errno);
    }
    clear_binding(acceptor);
    return loop_finish(VIREO_OK, VIREO_ACCEPTOR_LOOP_STAGE_NONE, NULL, error, saved_errno);
}
