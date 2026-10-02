/*
 * PROJECT : VIREO
 * FILE    : epoll.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-02
 * BRIEF   : 此模块负责：
 * -- 受检创建、观测和消费式销毁 Linux epoll 资源
 * IMPLEMENTATION : 先取得用户态内存，再创建实例，最后发布；创建回滚无 fd。
 * -- 原生布局只留在实现内；等待整批预检后按值提交到调用者数组。
 * -- 注册不新增用户态资源；一次 ctl，无自动 retry 或操作转换。
 */
#include <vireo/net/epoll.h>
#include <vireo/base/checked.h>
#include "epoll_internal.h"

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <unistd.h>

_Static_assert(65536 <= INT_MAX, "event capacity must fit epoll maxevents");

struct vireo_epoll {
    int epoll_fd;                    /* 唯一拥有的实例 fd，零也有效。 */
    struct epoll_event *events;       /* 固定内部等待工作区，只读本次返回的前 count 项。 */
    vireo_epoll_info_t info;          /* 创建时受检并固定的数值。 */
    vireo_epoll_ops_t ops;            /* 回滚/销毁所需配对操作，按值复制。 */
};

/**
 * @brief 标准控制块/工作区分配适配
 * @param[in] context 未使用，可为 NULL。
 * @param[in] size 已受检的正申请字节数。
 * @return malloc 取得的 owned 区域或 NULL；最终由配对 deallocate 释放。
 * @note 对齐继承 malloc；errno 由外层保存恢复，无共享状态。
 */
static void *vireo_epoll_allocate(void *context, size_t size)
{
    (void)context;
    return malloc(size);
}

/**
 * @brief 配对释放本实例的用户态内存
 * @param[in] context 未使用，可为 NULL。
 * @param[in] memory allocate 取得的 owned 地址，本调用消费。
 * @note free 无返回值；errno 由外层保存恢复，不负责内核 fd。
 */
static void vireo_epoll_deallocate(void *context, void *memory)
{
    (void)context;
    free(memory);
}

/**
 * @brief 取得 Linux 实例 fd
 * @param[in] context 未使用，可为 NULL。
 * @param[in] flags 外层固定为 EPOLL_CLOEXEC。
 * @return 非负 owned fd，或 -1 并设置 errno。
 * @note 由对象 close 配对消费，无自动重试或额外 fd 复制。
 */
static int vireo_epoll_create_fd(void *context, int flags)
{
    (void)context;
    return epoll_create1(flags);
}

/**
 * @brief 一次关闭对象唯一持有的实例 fd
 * @param[in] context 未使用，可为 NULL。
 * @param[in] fd 非负且有效的 owned fd，本调用消费。
 * @retval 0 关闭成功。
 * @retval -1 底层错误由 errno 报告，Linux 失败含 EINTR 不重试。
 * @note 外层仍清理用户态内存，不以错误重新取得所有权。
 */
static int vireo_epoll_close_fd(void *context, int fd)
{
    (void)context;
    return close(fd);
}

/**
 * @brief 将一次注册操作交给内核
 * @param[in] context 未使用，可为 NULL。
 * @param[in] epfd 对象持有的实例 fd，仅借用。
 * @param[in] operation ADD/MOD/DEL，由外层选择。
 * @param[in] fd 上层持有的非负目标 fd，仅借用。
 * @param[in] event 栈上原生输入，仅调用期间借用；DEL 为 NULL。
 * @retval 0 内核操作成功。
 * @retval -1 失败并设置 errno，外层立即保存诊断，不转换或重试。
 * @note 无用户态分配或所有权交接；外层恢复调用者 errno。
 */
static int vireo_epoll_control_fd(void *context, int epfd, int operation, int fd,
                                 struct epoll_event *event)
{
    (void)context;
    return epoll_ctl(epfd, operation, fd, event);
}

/**
 * @brief 一次原生等待，输出只写入对象持有的工作区
 * @param[in] context 未使用，可 NULL。
 * @param[in] epfd 对象持有的实例 fd，仅借用。
 * @param[out] events 存活可写的内部数组，至少 maxevents 项。
 * @param[in] maxevents 已证明正且不超过固定数组容量。
 * @param[in] timeout_ms -1、0 或正毫秒，由外层验证。
 * @return 0..maxevents 就绪数量，或 -1/errno；无自动重试。
 * @note 不取得或消费资源，外层保存诊断并恢复入口 errno。
 */
static int vireo_epoll_wait_fd(void *context, int epfd, struct epoll_event *events,
                              int maxevents, int timeout_ms)
{
    (void)context;
    return epoll_wait(epfd, events, maxevents, timeout_ms);
}

static vireo_epoll_ops_t const vireo_epoll_default_ops = {
    NULL, vireo_epoll_allocate, vireo_epoll_deallocate,
    vireo_epoll_create_fd, vireo_epoll_close_fd, vireo_epoll_control_fd,
    vireo_epoll_wait_fd
};

/* 诊断是允许改变的独立输出，主输出发布只在完整成功后发生。 */
static void vireo_epoll_error_set(vireo_epoll_error_t *out,
                                 vireo_epoll_stage_t stage, int cause)
{
    if (out != NULL) {
        *out = (vireo_epoll_error_t){stage, cause};
    }
}

vireo_result_t vireo_epoll_create_with_ops(vireo_epoll_options_t const *options,
                                          vireo_epoll_ops_t const *ops,
                                          vireo_epoll_t **out_epoll,
                                          vireo_epoll_error_t *out_error)
{
    int const saved_errno = errno;
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    size_t events_bytes = 0;
    size_t allocation_bytes = 0;
    vireo_epoll_t *candidate = NULL;

    vireo_epoll_error_set(out_error, VIREO_EPOLL_STAGE_NONE, 0);
    if (options == NULL || ops == NULL || out_epoll == NULL ||
        *out_epoll != NULL || ops->allocate == NULL || ops->deallocate == NULL ||
        ops->create == NULL || ops->close == NULL || ops->control == NULL ||
        ops->wait == NULL ||
        options->event_capacity == 0 ||
        options->max_memory_bytes == 0) {
        goto done;
    }
    result = vireo_checked_size_mul(options->event_capacity,
                                    sizeof(struct epoll_event), &events_bytes);
    if (result != VIREO_OK) {
        goto done;
    }
    result = vireo_checked_size_add(sizeof(*candidate), events_bytes, &allocation_bytes);
    if (result != VIREO_OK) {
        goto done;
    }
    if (options->event_capacity > VIREO_EPOLL_MAX_EVENTS ||
        options->max_memory_bytes > VIREO_EPOLL_MAX_MEMORY ||
        allocation_bytes > options->max_memory_bytes) {
        result = VIREO_RESULT_RANGE;
        goto done;
    }

    candidate = ops->allocate(ops->context, sizeof(*candidate));
    if (candidate == NULL) {
        vireo_epoll_error_set(out_error, VIREO_EPOLL_STAGE_ALLOCATE_CONTROL, 0);
        result = VIREO_RESULT_NO_MEMORY;
        goto done;
    }
    candidate->ops = *ops;
    candidate->events = ops->allocate(ops->context, events_bytes);
    if (candidate->events == NULL) {
        vireo_epoll_error_set(out_error, VIREO_EPOLL_STAGE_ALLOCATE_EVENTS, 0);
        result = VIREO_RESULT_NO_MEMORY;
        goto rollback_control;
    }
    candidate->epoll_fd = ops->create(ops->context, EPOLL_CLOEXEC);
    if (candidate->epoll_fd < 0) {
        vireo_epoll_error_set(out_error, VIREO_EPOLL_STAGE_CREATE, errno);
        result = VIREO_RESULT_IO;
        goto rollback_events;
    }
    candidate->info = (vireo_epoll_info_t){options->event_capacity, events_bytes,
                                         allocation_bytes, options->max_memory_bytes};
    *out_epoll = candidate;
    result = VIREO_OK;
    goto done;

rollback_events:
    ops->deallocate(ops->context, candidate->events);
rollback_control:
    ops->deallocate(ops->context, candidate);
done:
    errno = saved_errno;
    return result;
}

vireo_result_t vireo_epoll_create(vireo_epoll_options_t const *options,
                                 vireo_epoll_t **out_epoll,
                                 vireo_epoll_error_t *out_error)
{
    return vireo_epoll_create_with_ops(options, &vireo_epoll_default_ops,
                                      out_epoll, out_error);
}

vireo_result_t vireo_epoll_inspect(vireo_epoll_t const *epoll,
                                  vireo_epoll_info_t *out_info)
{
    if (epoll == NULL || out_info == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    *out_info = epoll->info;
    return VIREO_OK;
}

/**
 * @brief 在共用前置校验后执行一次注册原语
 * @param[in] epoll 借用对象，NULL 时拒绝。
 * @param[in] fd 借用目标 fd，负值时拒绝。
 * @param[in] registration ADD/MOD 必需稳定输入；DEL 为 NULL。
 * @param[in] operation 外层固定的 ADD/MOD/DEL，不接受调用者未知操作。
 * @param[in] stage 对应的系统失败诊断阶段。
 * @param[out] out_error 可空独立诊断；前置失败/成功为 NONE/0。
 * @retval VIREO_OK 一次内核操作成功。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 前置参数或未知项目关注位非法。
 * @retval VIREO_RESULT_IO 一次系统失败，保存原始 errno。
 * @note 栈输入按值转换，只设置 LT 三关注位与 data.u64；无资源交接。
 *     DEL 不构造有效事件；所有路径恢复入口 errno，不读旧批次或影子状态。
 */
static vireo_result_t vireo_epoll_control(vireo_epoll_t *epoll, int fd,
                                         vireo_epoll_registration_t const *registration,
                                         int operation, vireo_epoll_stage_t stage,
                                         vireo_epoll_error_t *out_error)
{
    int const saved_errno = errno;
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    struct epoll_event event = {0};
    uint32_t const known = VIREO_EPOLL_INTEREST_READ | VIREO_EPOLL_INTEREST_WRITE |
                           VIREO_EPOLL_INTEREST_PEER_WRITE_CLOSED;
    vireo_epoll_error_set(out_error, VIREO_EPOLL_STAGE_NONE, 0);
    if (epoll == NULL || fd < 0) {
        goto done;
    }
    if (operation != EPOLL_CTL_DEL) {
        if (registration == NULL || (registration->interests & ~known) != 0) {
            goto done;
        }
        if ((registration->interests & VIREO_EPOLL_INTEREST_READ) != 0) {
            event.events |= EPOLLIN;
        }
        if ((registration->interests & VIREO_EPOLL_INTEREST_WRITE) != 0) {
            event.events |= EPOLLOUT;
        }
        if ((registration->interests & VIREO_EPOLL_INTEREST_PEER_WRITE_CLOSED) != 0) {
            event.events |= EPOLLRDHUP;
        }
        event.data.u64 = registration->token;
    }
    if (epoll->ops.control(epoll->ops.context, epoll->epoll_fd, operation, fd,
                           operation == EPOLL_CTL_DEL ? NULL : &event) < 0) {
        vireo_epoll_error_set(out_error, stage, errno);
        result = VIREO_RESULT_IO;
    } else {
        result = VIREO_OK;
    }
done:
    errno = saved_errno;
    return result;
}

vireo_result_t vireo_epoll_add(vireo_epoll_t *epoll, int fd,
                              vireo_epoll_registration_t const *registration,
                              vireo_epoll_error_t *out_error)
{
    return vireo_epoll_control(epoll, fd, registration, EPOLL_CTL_ADD,
                               VIREO_EPOLL_STAGE_ADD, out_error);
}

vireo_result_t vireo_epoll_mod(vireo_epoll_t *epoll, int fd,
                              vireo_epoll_registration_t const *registration,
                              vireo_epoll_error_t *out_error)
{
    return vireo_epoll_control(epoll, fd, registration, EPOLL_CTL_MOD,
                               VIREO_EPOLL_STAGE_MOD, out_error);
}

vireo_result_t vireo_epoll_del(vireo_epoll_t *epoll, int fd,
                              vireo_epoll_error_t *out_error)
{
    return vireo_epoll_control(epoll, fd, NULL, EPOLL_CTL_DEL,
                               VIREO_EPOLL_STAGE_DEL, out_error);
}

/* 两遍处理避免后项异常时已经发布半批；容量先 clamp，再做有界 int 窄化。 */
vireo_result_t vireo_epoll_wait(vireo_epoll_t *epoll, int timeout_ms,
                               vireo_epoll_event_t *out_events, size_t out_capacity,
                               size_t *out_count, vireo_epoll_error_t *out_error)
{
    int const saved_errno = errno;
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    uint32_t const known = EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLERR | EPOLLHUP;
    vireo_epoll_error_set(out_error, VIREO_EPOLL_STAGE_NONE, 0);
    if (epoll == NULL || out_events == NULL || out_count == NULL ||
        out_capacity == 0 || timeout_ms < -1) {
        goto done;
    }
    size_t const capacity = out_capacity < epoll->info.event_capacity
                                ? out_capacity : epoll->info.event_capacity;
    int const count = epoll->ops.wait(epoll->ops.context, epoll->epoll_fd,
                                      epoll->events, (int)capacity, timeout_ms);
    if (count == -1) {
        vireo_epoll_error_set(out_error, VIREO_EPOLL_STAGE_WAIT, errno);
        result = VIREO_RESULT_IO;
        goto done;
    }
    if (count < 0 || (size_t)count > capacity) {
        goto invalid_batch;
    }
    for (size_t i = 0; i < (size_t)count; ++i) {
        if ((epoll->events[i].events & ~known) != 0) {
            goto invalid_batch;
        }
    }
    for (size_t i = 0; i < (size_t)count; ++i) {
        uint32_t const native = epoll->events[i].events;
        uint32_t bits = 0;
        if ((native & EPOLLIN) != 0) bits |= VIREO_EPOLL_EVENT_READ;
        if ((native & EPOLLOUT) != 0) bits |= VIREO_EPOLL_EVENT_WRITE;
        if ((native & EPOLLRDHUP) != 0) bits |= VIREO_EPOLL_EVENT_PEER_WRITE_CLOSED;
        if ((native & EPOLLERR) != 0) bits |= VIREO_EPOLL_EVENT_ERROR;
        if ((native & EPOLLHUP) != 0) bits |= VIREO_EPOLL_EVENT_HANGUP;
        out_events[i] = (vireo_epoll_event_t){epoll->events[i].data.u64, bits};
    }
    *out_count = (size_t)count;
    result = VIREO_OK;
    goto done;
invalid_batch:
    vireo_epoll_error_set(out_error, VIREO_EPOLL_STAGE_WAIT, 0);
    result = VIREO_RESULT_INTERNAL;
done:
    errno = saved_errno;
    return result;
}

/* close 报错也消费，先复制操作表，避免 free 控制块后读取配对回调。 */
vireo_result_t vireo_epoll_destroy(vireo_epoll_t **epoll,
                                  vireo_epoll_error_t *out_error)
{
    int const saved_errno = errno;
    vireo_result_t result = VIREO_OK;
    vireo_epoll_error_set(out_error, VIREO_EPOLL_STAGE_NONE, 0);
    if (epoll == NULL) {
        result = VIREO_RESULT_INVALID_ARGUMENT;
    } else if (*epoll != NULL) {
        vireo_epoll_t *object = *epoll;
        vireo_epoll_ops_t const ops = object->ops;
        if (ops.close(ops.context, object->epoll_fd) < 0) {
            vireo_epoll_error_set(out_error, VIREO_EPOLL_STAGE_CLOSE, errno);
            result = VIREO_RESULT_IO;
        }
        ops.deallocate(ops.context, object->events);
        ops.deallocate(ops.context, object);
        *epoll = NULL;
    }
    errno = saved_errno;
    return result;
}
