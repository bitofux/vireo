/*
 * PROJECT : VIREO
 * FILE    : notifier.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-13
 * BRIEF   : 固定 eventfd 资源、一次通知/消费及 Linux 一次关闭
 */
#include "notifier_internal.h"

#include <errno.h>
#include <stdlib.h>
#include <sys/eventfd.h>
#include <unistd.h>

_Static_assert(sizeof(uint64_t) == 8, "Linux eventfd requires an eight-byte value");

struct vireo_notifier {
    vireo_notifier_info_t info; /**< 固定资源值；fd 唯一 owned，非负且 0 合法。 */
    vireo_notifier_ops_t ops; /**< 配对操作按值复制，context 借用至最终释放。 */
};

/**
 * @brief
 *     默认控制块申请适配。
 *
 * @param[in] context
 *     未使用，可为 NULL。
 * @param[in] size
 *     已经预算验证的正控制块字节数。
 *
 * @return
 *     malloc owned 区域，失败 NULL；对齐继承 malloc。
 *
 * @note
 *     外层保存恢复 errno，配对 deallocate 负责释放。
 */
static void *notifier_allocate(void *context, size_t size)
{
    (void)context;
    return malloc(size);
}

/**
 * @brief
 *     配对消费用户态控制块。
 *
 * @param[in] context
 *     未使用，可为 NULL。
 * @param[in] memory
 *     默认 allocate 取得的唯一 owned 块，本调用消费。
 *
 * @note
 *     无失败返回，不关闭 fd；外层保持 errno。
 */
static void notifier_deallocate(void *context, void *memory)
{
    (void)context;
    free(memory);
}

/**
 * @brief
 *     按外层固定参数取得 Linux eventfd。
 *
 * @param[in] context
 *     未使用，可为 NULL。
 * @param[in] initval
 *     固定为 0，初始没有提示。
 * @param[in] flags
 *     固定 EFD_NONBLOCK|EFD_CLOEXEC，无 EFD_SEMAPHORE。
 *
 * @return
 *     非负 owned fd，失败 -1 并设置 errno。
 *
 * @note
 *     创建参数一次传给内核，不通过后续 fcntl 设置标志，不重试。
 */
static int notifier_create_fd(void *context, unsigned int initval, int flags)
{
    (void)context;
    return eventfd(initval, flags);
}

/**
 * @brief
 *     一次消费对象唯一拥有的 Linux fd。
 *
 * @param[in] context
 *     未使用，可为 NULL。
 * @param[in] fd
 *     有效非负 owned fd，全部借用/访问已经结束。
 *
 * @return
 *     close 的 0 或 -1/errno，外层不重试。
 *
 * @note
 *     Linux 有效 fd 失败也消费，外层始终释放控制块。
 */
static int notifier_close_fd(void *context, int fd)
{
    (void)context;
    return close(fd);
}

/**
 * @brief
 *     一次原生 read，仅写外层栈上候选计数。
 *
 * @param[in] context
 *     未使用，可空。
 * @param[in] fd
 *     存活对象 owned fd，本次只借。
 * @param[out] bytes
 *     外层独占可写候选，至少 size 字节，地址不保存。
 * @param[in] size
 *     固定 8 字节。
 *
 * @return
 *     原生字节数或 -1/errno，不重试。
 *
 * @note
 *     无共享用户态可变状态；外层保持 errno、诊断及主输出发布责任。
 */
static ssize_t notifier_read_fd(void *context, int fd, void *bytes, size_t size)
{
    (void)context;
    return read(fd, bytes, size);
}

/**
 * @brief
 *     一次原生 write，输入只借到本次返回。
 *
 * @param[in] context
 *     未使用，可空。
 * @param[in] fd
 *     存活对象 owned fd，本次只借。
 * @param[in] bytes
 *     外层固定 uint64 的 1，至少 size 个稳定可读字节。
 * @param[in] size
 *     固定 8 字节。
 *
 * @return
 *     原生字节数或 -1/errno，不重试。
 *
 * @note
 *     不申请或接管 caller 数据，外层保持 errno 与独立结果/诊断。
 */
static ssize_t notifier_write_fd(void *context, int fd, void const *bytes, size_t size)
{
    (void)context;
    return write(fd, bytes, size);
}

static vireo_notifier_ops_t const notifier_default_ops = {
    NULL, notifier_allocate, notifier_deallocate, notifier_create_fd, notifier_close_fd,
    notifier_read_fd, notifier_write_fd
};

/**
 * @brief
 *     覆盖可空独立诊断，不发布主输出。
 *
 * @param[out] out
 *     可空独占可写诊断，地址不保存。
 * @param[in] stage
 *     本次错误阶段，正常及前置拒绝 NONE。
 * @param[in] cause
 *     已保存的系统 errno，没有系统错误为 0。
 *
 * @note
 *     纯值赋值，不读取或修改 errno，不取得任何资源。
 */
static void notifier_error_set(vireo_notifier_error_t *out,
    vireo_notifier_stage_t stage, int cause)
{
    if (out != NULL) {
        *out = (vireo_notifier_error_t){stage, cause};
    }
}

vireo_result_t vireo_notifier_create_with_ops(vireo_notifier_options_t const *options,
    vireo_notifier_ops_t const *ops, vireo_notifier_t **out_notifier,
    vireo_notifier_error_t *out_error)
{
    int const saved_errno = errno;
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    vireo_notifier_t *candidate = NULL;

    notifier_error_set(out_error, VIREO_NOTIFIER_STAGE_NONE, 0);
    if (options == NULL || ops == NULL || out_notifier == NULL ||
        *out_notifier != NULL || options->max_memory_bytes == 0 ||
        ops->allocate == NULL || ops->deallocate == NULL ||
        ops->create == NULL || ops->close == NULL || ops->read == NULL || ops->write == NULL) {
        goto done;
    }
    if (options->max_memory_bytes > VIREO_NOTIFIER_MAX_ALLOCATION_BYTES ||
        options->max_memory_bytes < sizeof(*candidate)) {
        result = VIREO_RESULT_RANGE;
        goto done;
    }
    candidate = ops->allocate(ops->context, sizeof(*candidate));
    if (candidate == NULL) {
        notifier_error_set(out_error, VIREO_NOTIFIER_STAGE_ALLOCATE_CONTROL, 0);
        result = VIREO_RESULT_NO_MEMORY;
        goto done;
    }
    candidate->ops = *ops;
    int const fd = ops->create(ops->context, 0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (fd < 0) {
        notifier_error_set(out_error, VIREO_NOTIFIER_STAGE_CREATE, errno);
        ops->deallocate(ops->context, candidate);
        result = VIREO_RESULT_IO;
        goto done;
    }
    candidate->info = (vireo_notifier_info_t){fd, sizeof(*candidate),
        options->max_memory_bytes};
    *out_notifier = candidate;
    result = VIREO_OK;
done:
    errno = saved_errno;
    return result;
}

vireo_result_t vireo_notifier_create(vireo_notifier_options_t const *options,
    vireo_notifier_t **out_notifier, vireo_notifier_error_t *out_error)
{
    return vireo_notifier_create_with_ops(options, &notifier_default_ops,
        out_notifier, out_error);
}

vireo_result_t vireo_notifier_inspect(vireo_notifier_t const *notifier,
    vireo_notifier_info_t *out_info)
{
    if (notifier == NULL || out_info == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    *out_info = notifier->info;
    return VIREO_OK;
}

vireo_result_t vireo_notifier_notify(vireo_notifier_t *notifier,
    vireo_notifier_notify_outcome_t *out_outcome, vireo_notifier_error_t *out_error)
{
    int const saved_errno = errno;
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    notifier_error_set(out_error, VIREO_NOTIFIER_STAGE_NONE, 0);
    if (notifier == NULL || out_outcome == NULL) {
        goto done;
    }
    uint64_t const one = 1;
    ssize_t const size = notifier->ops.write(notifier->ops.context, notifier->info.fd,
        &one, sizeof(one));
    if (size == (ssize_t)sizeof(one)) {
        *out_outcome = VIREO_NOTIFIER_NOTIFY_INCREMENTED;
        result = VIREO_OK;
    } else if (size == -1) {
        int const cause = errno;
        if (cause == EAGAIN || cause == EWOULDBLOCK) {
            *out_outcome = VIREO_NOTIFIER_NOTIFY_ALREADY_PENDING;
            result = VIREO_OK;
        } else {
            notifier_error_set(out_error, VIREO_NOTIFIER_STAGE_NOTIFY, cause);
            result = VIREO_RESULT_IO;
        }
    } else {
        notifier_error_set(out_error, VIREO_NOTIFIER_STAGE_NOTIFY, 0);
        result = VIREO_RESULT_INTERNAL;
    }
done:
    errno = saved_errno;
    return result;
}

vireo_result_t vireo_notifier_consume(vireo_notifier_t *notifier,
    uint64_t *out_count, vireo_notifier_error_t *out_error)
{
    int const saved_errno = errno;
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    notifier_error_set(out_error, VIREO_NOTIFIER_STAGE_NONE, 0);
    if (notifier == NULL || out_count == NULL) {
        goto done;
    }
    uint64_t candidate = 0;
    ssize_t const size = notifier->ops.read(notifier->ops.context, notifier->info.fd,
        &candidate, sizeof(candidate));
    if (size == (ssize_t)sizeof(candidate) && candidate != 0) {
        *out_count = candidate;
        result = VIREO_OK;
    } else if (size == -1) {
        int const cause = errno;
        if (cause == EAGAIN || cause == EWOULDBLOCK) {
            *out_count = 0;
            result = VIREO_OK;
        } else {
            notifier_error_set(out_error, VIREO_NOTIFIER_STAGE_CONSUME, cause);
            result = VIREO_RESULT_IO;
        }
    } else {
        notifier_error_set(out_error, VIREO_NOTIFIER_STAGE_CONSUME, 0);
        result = VIREO_RESULT_INTERNAL;
    }
done:
    errno = saved_errno;
    return result;
}

vireo_result_t vireo_notifier_destroy(vireo_notifier_t **owner,
    vireo_notifier_error_t *out_error)
{
    int const saved_errno = errno;
    vireo_result_t result = VIREO_OK;
    notifier_error_set(out_error, VIREO_NOTIFIER_STAGE_NONE, 0);
    if (owner == NULL) {
        result = VIREO_RESULT_INVALID_ARGUMENT;
        goto done;
    }
    if (*owner != NULL) {
        vireo_notifier_t *notifier = *owner;
        vireo_notifier_ops_t const ops = notifier->ops;
        if (ops.close(ops.context, notifier->info.fd) < 0) {
            notifier_error_set(out_error, VIREO_NOTIFIER_STAGE_CLOSE, errno);
            result = VIREO_RESULT_IO;
        }
        ops.deallocate(ops.context, notifier);
        *owner = NULL;
    }
done:
    errno = saved_errno;
    return result;
}
