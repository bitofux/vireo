/*
- PROJECT : VIREO
- FILE    : event_loop.c
- AUTHOR  : bitofux
- DATE    : 2026-10-03
- BRIEF   : 此模块负责：
- -- 通过 epoll 公共合同取得资源，扣除本层字节后传递预算
- -- 全成功发布、逆序释放与关闭错误后的 owner 消费
- -- 固定注册绑定、空闲链与不复用数值身份校验
- -- 有限批次分发、持续运行与原子停止/内部 pipe 唤醒
 */
#define _GNU_SOURCE
#include <vireo/net/event_loop.h>
#include "event_loop_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <vireo/base/checked.h>

/* 低 16 位能表达 0..65535，容量硬限使槽索引无需额外映射。 */
#define SLOT_MASK UINT64_C(65535)
#define SERIAL_MAX (UINT64_MAX >> 16)

/** 不暴露给下游的固定记录；空闲链与活跃记录互斥。 */
typedef struct registration_record {
    vireo_event_loop_registration_t registration; /**< 活跃时的固定借用绑定。 */
    uint64_t token;   /**< 当前注册数值，空闲时为零。 */
    size_t next_free; /**< 仅空闲时有效，capacity 为链尾。 */
    bool active;     /**< 内核 ADD 成功后置 true，DEL 成功后清空。 */
} registration_record_t;

/** 仅 stop_requested 跨线程变化；发布后 fd/ops 不变，其他可变字段仅属 Reactor。 */
struct vireo_event_loop {
    vireo_epoll_t *epoll;             /**< 唯一拥有的公共 epoll 对象。 */
    vireo_epoll_event_t *events;      /**< 固定值数组；创建时未填充。 */
    registration_record_t *records;  /**< 唯一拥有的固定记录数组。 */
    size_t free_head;                /**< 首空闲索引或 capacity 链尾。 */
    uint64_t last_serial;            /**< 已发放序号，不回退；系统 ADD 失败可消耗。 */
    bool run_active;                 /**< 覆盖整次运行，仅防 Reactor 同线程重入。 */
    _Atomic bool stop_requested;     /**< 原子退出意图，false 到 true，不复位。 */
    int read_fd;                     /**< 独占内部 pipe 读端，-1 表示尚未取得。 */
    int write_fd;                    /**< 独占内部 pipe 写端，所有请求者结束后才关闭。 */
    vireo_event_loop_info_t info;    /**< 资源数值与当前注册计数。 */
    vireo_event_loop_ops_t ops;      /**< 按值资源表，其 context 借用至最后清理。 */
};

/* 此全局原子只分配身份；对象停止原子不发布注册或保护销毁。 */
static _Atomic uint64_t identity_counter = 0;

/**
 * @brief 默认申请基本对齐的本层资源
 *
 * @param[in] context
 *     未使用，可为空。
 * @param[in] size
 *     已验证的正申请字节数。
 *
 * @retval NULL
 *     malloc 失败，没有转移资源。
 * @return 非 NULL 时转移真实内存，须通过配对 deallocate 释放。
 *
 * @note 只适配标准分配器，外层负责 errno 保持。
 */
static void *default_allocate(void *context, size_t size)
{
    (void)context;
    return malloc(size);
}

/**
 * @brief 默认释放本层取得的完整分配
 *
 * @param[in] context
 *     未使用，可为空。
 * @param[in] memory
 *     配对取得的真实分配，消费其所有权。
 *
 * @note 不报告失败，返回后旧借用失效；外层负责 errno 保持。
 */
static void default_deallocate(void *context, void *memory)
{
    (void)context;
    free(memory);
}

/**
 * @brief 默认通过公共接口创建自有 epoll
 *
 * @param[in] context
 *     未使用，可为空。
 * @param[in] options
 *     调用期借用，容量与扣除本层申请后的正预算。
 * @param[in,out] owner
 *     独立空 owner，成功时转移 epoll 所有权。
 * @param[out] error
 *     独立非空诊断，接收公共 epoll 的原始阶段/errno。
 *
 * @return 公共 epoll_create 的完整结果，失败保持空 owner。
 *
 * @note 不引用 epoll 私有头或布局；底层按其公开合同回滚并保持 errno。
 */
static vireo_result_t default_create_epoll(void *context,
                                          vireo_epoll_options_t const *options,
                                          vireo_epoll_t **owner, vireo_epoll_error_t *error)
{
    (void)context;
    return vireo_epoll_create(options, owner, error);
}

/**
 * @brief 默认按公共合同观察自有 epoll 的实际申请
 *
 * @param[in] context
 *     未使用，可为空。
 * @param[in] epoll
 *     存活对象，调用期借用，owner 保持。
 * @param[out] info
 *     独立非空输出，成功时提交快照。
 *
 * @return 公共 epoll_inspect 结果；本层已成立的前置条件应使其成功。
 *
 * @note 不读写 errno，不授予底层资源借用。
 */
static vireo_result_t default_inspect_epoll(void *context, vireo_epoll_t const *epoll,
                                           vireo_epoll_info_t *info)
{
    (void)context;
    return vireo_epoll_inspect(epoll, info);
}

/**
 * @brief 默认按公共接口消费自有 epoll
 *
 * @param[in] context
 *     未使用，可为空。
 * @param[in,out] owner
 *     独立唯一 owner；关闭报错也清空并消费。
 * @param[out] error
 *     独立非空诊断，接收关闭原始阶段/errno。
 *
 * @return 公共 epoll_destroy 的结果，不提供旧对象重试权限。
 *
 * @note 调用一次，由底层负责 close 与自身内存；本层仍须释放自己的资源。
 */
static vireo_result_t default_destroy_epoll(void *context, vireo_epoll_t **owner,
                                           vireo_epoll_error_t *error)
{
    (void)context;
    return vireo_epoll_destroy(owner, error);
}

/**
 * @brief 通过公共 ADD 建立内核关注
 *
 * @param[in] context
 *     未使用，可为空。
 * @param[in,out] epoll
 *     本层存活自有对象，借用到返回。
 * @param[in] fd
 *     非负客户端描述符，只借用。
 * @param[in] registration
 *     合法关注与 token，调用期借用。
 * @param[out] error
 *     非空独立原诊断。
 *
 * @return 公共 epoll_add 的原结果，不转换或重试。
 *
 * @note 外层负责状态提交与入口 errno 保持。
 */
static vireo_result_t default_add_epoll(void *context, vireo_epoll_t *epoll, int fd,
                                       vireo_epoll_registration_t const *registration,
                                       vireo_epoll_error_t *error)
{
    (void)context;
    return vireo_epoll_add(epoll, fd, registration, error);
}

/**
 * @brief 通过公共 MOD 全替换内核关注，失败保持原值
 *
 * @param[in] context
 *     未使用，可为空。
 * @param[in,out] epoll
 *     本层存活对象，借用到返回。
 * @param[in] fd
 *     当前注册的借用描述符。
 * @param[in] registration
 *     合法关注与当前 token，调用期借用。
 * @param[out] error
 *     非空独立原诊断。
 *
 * @return 公共 epoll_mod 的原结果，不 fallback 或重试。
 *
 * @note 外层只在成功时提交本地关注，保持入口 errno。
 */
static vireo_result_t default_mod_epoll(void *context, vireo_epoll_t *epoll, int fd,
                                       vireo_epoll_registration_t const *registration,
                                       vireo_epoll_error_t *error)
{
    (void)context;
    return vireo_epoll_mod(epoll, fd, registration, error);
}

/**
 * @brief 通过公共 DEL 注销内核关注，不消费客户端资源
 *
 * @param[in] context
 *     未使用，可为空。
 * @param[in,out] epoll
 *     本层存活对象，借用到返回。
 * @param[in] fd
 *     当前注册的借用描述符。
 * @param[out] error
 *     非空独立原诊断。
 *
 * @return 公共 epoll_del 原结果，不吞缺失错误或重试。
 *
 * @note 外层成功后结束注册借用，保持入口 errno。
 */
static vireo_result_t default_del_epoll(void *context, vireo_epoll_t *epoll, int fd,
                                       vireo_epoll_error_t *error)
{
    (void)context;
    return vireo_epoll_del(epoll, fd, error);
}

/**
 * @brief 通过公共 wait 取得本层固定工作区的值批次
 *
 * @param[in] context
 *     未使用，可为空。
 * @param[in,out] epoll
 *     本层存活自有对象，借用到返回。
 * @param[out] events
 *     本层独占且真实具有 capacity 个位置的值数组。
 * @param[in] capacity
 *     已验证的正批次上限。
 * @param[in] timeout_ms
 *     -1、0 或正相对毫秒，只等待一次。
 * @param[out] count
 *     非空独立计数，仅依赖成功时提交。
 * @param[out] error
 *     非空独立诊断，接收底层阶段和原 errno。
 *
 * @return
 *     公共 epoll_wait 原结果，无自动重试或注册变更。
 *
 * @note 仅值复制，不引用 epoll 私有布局；外层负责身份校验及 errno 保持。
 */
static vireo_result_t default_wait_epoll(void *context, vireo_epoll_t *epoll,
                                        vireo_epoll_event_t *events, size_t capacity,
                                        int timeout_ms, size_t *count, vireo_epoll_error_t *error)
{
    (void)context;
    return vireo_epoll_wait(epoll, timeout_ms, events, capacity, count, error);
}

/**
 * @brief 原子设置属性并取得非阻塞内部通知通道
 *
 * @param[in] context
 *     未使用，可为空。
 * @param[out] fds
 *     非空两项输出，成功交付读端/写端唯一所有权；失败不交付资源。
 *
 * @return
 *     pipe2 的 0 或 -1；失败原因在 errno，外层负责保存与回滚。
 *
 * @note 两端均 NONBLOCK/CLOEXEC，不是任务或 completion 通道。
 */
static int default_create_pipe(void *context, int fds[2])
{
    (void)context;
    return pipe2(fds, O_NONBLOCK | O_CLOEXEC);
}

/**
 * @brief 一次读取通知提示，保留真实短进度或错误
 *
 * @param[in] context
 *     未使用，可为空。
 * @param[in] fd
 *     存活的独占非阻塞读端。
 * @param[out] buffer
 *     独立可写区域，至少 size 字节。
 * @param[in] size
 *     本层已证明的正有界容量。
 *
 * @return
 *     read 的原始 ssize_t；-1 原因在 errno，不重试。
 *
 * @note 仅 Reactor 调用；外层判定 EOF/过期提示，恢复入口 errno。
 */
static ssize_t default_read_pipe(void *context, int fd, void *buffer, size_t size)
{
    (void)context;
    return read(fd, buffer, size);
}

/**
 * @brief 一次提交非阻塞通知，保留真实进度和错误
 *
 * @param[in] context
 *     未使用，可为空。
 * @param[in] fd
 *     存活的非阻塞写端，调用期间读端保持打开。
 * @param[in] buffer
 *     独立稳定字节，至少 size 字节，仅调用期间借用。
 * @param[in] size
 *     本实现固定为一字节。
 *
 * @return
 *     write 的原始 ssize_t；-1 原因在 errno，不重试。
 *
 * @note 可由多个合法请求者并发调用；生命周期前置保证没有关闭读端的 SIGPIPE 路径。
 */
static ssize_t default_write_pipe(void *context, int fd, void const *buffer, size_t size)
{
    (void)context;
    return write(fd, buffer, size);
}

/**
 * @brief 消费一个内部描述符，不重试 Linux close
 *
 * @param[in] context
 *     未使用，可为空。
 * @param[in] fd
 *     非负 owned fd，全部借用结束后调用。
 *
 * @return
 *     close 的 0 或 -1；错误含 EINTR 也视为已消费，原 errno 由外层读取。
 *
 * @note 不操作客户端描述符，不以旧数值重试。
 */
static int default_close_pipe(void *context, int fd)
{
    (void)context;
    return close(fd);
}

static vireo_event_loop_ops_t const default_ops = {
    NULL, default_allocate, default_deallocate, default_create_epoll,
    default_inspect_epoll, default_destroy_epoll,
    default_add_epoll, default_mod_epoll, default_del_epoll, default_wait_epoll,
    default_create_pipe, default_read_pipe, default_write_pipe, default_close_pipe
};

vireo_event_loop_ops_t vireo_event_loop_default_ops(void)
{
    return default_ops;
}

/**
 * @brief 发放一次不复用身份，溢出前停止而非回绕
 *
 * @param[in,out] counter
 *     存活原子身份源，调用期借用，多个独立创建可并发使用。
 * @param[out] out_id
 *     独立非空输出，仅成功提交。
 *
 * @retval VIREO_OK
 *     CAS 成功并取得非零唯一身份。
 * @retval VIREO_RESULT_OVERFLOW
 *     已达 UINT64_MAX，源与输出保持。
 *
 * @note relaxed 只需要计数唯一性，不能发布其他对象内容；不保证 lock-free 或有界重试。
 *     不分配、不操作 errno，身份取得后的创建失败不会归还数值。
 */
static vireo_result_t claim_identity(_Atomic uint64_t *counter, uint64_t *out_id)
{
    uint64_t current = atomic_load_explicit(counter, memory_order_relaxed);
    for (;;) {
        if (current == UINT64_MAX) {
            return VIREO_RESULT_OVERFLOW;
        }
        if (atomic_compare_exchange_weak_explicit(counter, &current, current + 1,
                                                 memory_order_relaxed, memory_order_relaxed)) {
            *out_id = current + 1;
            return VIREO_OK;
        }
    }
}

/* 诊断允许改写；主要 owner 的提交时机由调用方控制。 */
static void set_error(vireo_event_loop_error_t *out, vireo_event_loop_stage_t stage,
                      vireo_epoll_error_t epoll_error)
{
    if (out != NULL) {
        *out = (vireo_event_loop_error_t){.stage = stage, .epoll_error = epoll_error};
    }
}

/**
 * @brief 记录本层系统原因，依赖诊断清零
 *
 * @param[out] out
 *     可空独立诊断。
 * @param[in] stage
 *     本层通知或资源失败阶段。
 * @param[in] cause
 *     原始 errno；本层不变量异常为零。
 *
 * @note 只写诊断，不修改主输出或线程 errno。
 */
static void set_system_error(vireo_event_loop_error_t *out, vireo_event_loop_stage_t stage,
                             int cause)
{
    set_error(out, stage, (vireo_epoll_error_t){VIREO_EPOLL_STAGE_NONE, 0});
    if (out != NULL) out->system_errno = cause;
}

/**
 * @brief 尽力消费所有资源，以首个关闭错误为诊断
 *
 * @param[in] loop
 *     非 NULL 唯一候选，epoll 存活，pipe 端点可为 -1；所有借用已经结束。
 * @param[out] error
 *     非 NULL 独立诊断，每次完整覆盖，首错不被后续清理污染。
 *
 * @return
 *     首个关闭失败结果；全部资源均消费，旧 loop 不可再访问。
 *
 * @note 先销毁 epoll watch，再关闭写/读端，最后逆序释放三个 heap 块。
 *     控制块释放前复制 ops；每个 fd 只关闭一次，外层负责 owner/errno。
 */
static vireo_result_t release_resources(vireo_event_loop_t *loop,
                                        vireo_event_loop_error_t *error)
{
    vireo_event_loop_ops_t const ops = loop->ops;
    vireo_epoll_error_t dependency = {VIREO_EPOLL_STAGE_NONE, 0};
    vireo_result_t result = ops.destroy_epoll(ops.context, &loop->epoll, &dependency);
    set_error(error, result == VIREO_OK ? VIREO_EVENT_LOOP_STAGE_NONE :
              VIREO_EVENT_LOOP_STAGE_DESTROY_EPOLL, dependency);
    int const fds[2] = {loop->write_fd, loop->read_fd};
    vireo_event_loop_stage_t const stages[2] = {
        VIREO_EVENT_LOOP_STAGE_CLOSE_WRITE, VIREO_EVENT_LOOP_STAGE_CLOSE_READ
    };
    for (size_t i = 0; i < 2; ++i) {
        if (fds[i] >= 0 && ops.close_pipe(ops.context, fds[i]) == -1) {
            int const cause = errno;
            if (result == VIREO_OK) {
                result = VIREO_RESULT_IO;
                set_system_error(error, stages[i], cause);
            }
        }
    }
    ops.deallocate(ops.context, loop->records);
    ops.deallocate(ops.context, loop->events);
    ops.deallocate(ops.context, loop);
    return result;
}

vireo_result_t vireo_event_loop_create_with_counter(
    vireo_event_loop_options_t const *options, vireo_event_loop_ops_t const *ops,
    _Atomic uint64_t *counter, vireo_event_loop_t **out_loop, vireo_event_loop_error_t *out_error)
{
    int const saved_errno = errno;
    vireo_epoll_error_t const no_error = {VIREO_EPOLL_STAGE_NONE, 0};
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    set_error(out_error, VIREO_EVENT_LOOP_STAGE_NONE, no_error);
    if (options == NULL || out_loop == NULL || *out_loop != NULL ||
        options->event_capacity == 0 || options->registration_capacity == 0 ||
        options->max_memory_bytes == 0 || ops == NULL || counter == NULL ||
        ops->allocate == NULL || ops->deallocate == NULL || ops->create_epoll == NULL ||
        ops->inspect_epoll == NULL || ops->destroy_epoll == NULL || ops->add_epoll == NULL ||
        ops->mod_epoll == NULL || ops->del_epoll == NULL || ops->wait_epoll == NULL ||
        ops->create_pipe == NULL || ops->read_pipe == NULL || ops->write_pipe == NULL ||
        ops->close_pipe == NULL) {
        goto done;
    }

    size_t events_bytes;
    size_t registrations_bytes;
    size_t loop_bytes;
    result = vireo_checked_size_mul(options->event_capacity, sizeof(vireo_epoll_event_t),
                                    &events_bytes);
    if (result != VIREO_OK) {
        goto done;
    }
    result = vireo_checked_size_mul(options->registration_capacity, sizeof(registration_record_t),
                                    &registrations_bytes);
    if (result != VIREO_OK) {
        goto done;
    }
    result = vireo_checked_size_add(sizeof(vireo_event_loop_t), events_bytes, &loop_bytes);
    if (result == VIREO_OK) {
        result = vireo_checked_size_add(loop_bytes, registrations_bytes, &loop_bytes);
    }
    if (result != VIREO_OK) {
        goto done;
    }
    /* 必须先证明扣除后仍为正数，才把剩余预算交给独立依赖。 */
    if (options->event_capacity > VIREO_EVENT_LOOP_MAX_EVENTS ||
        options->registration_capacity > VIREO_EVENT_LOOP_MAX_REGISTRATIONS ||
        options->max_memory_bytes > VIREO_EVENT_LOOP_MAX_MEMORY ||
        loop_bytes >= options->max_memory_bytes) {
        result = VIREO_RESULT_RANGE;
        goto done;
    }
    uint64_t loop_id;
    result = claim_identity(counter, &loop_id);
    if (result != VIREO_OK) {
        set_error(out_error, VIREO_EVENT_LOOP_STAGE_ISSUE_ID, no_error);
        goto done;
    }
    vireo_event_loop_ops_t const resources = *ops;
    vireo_epoll_options_t const epoll_options = {
        options->event_capacity, options->max_memory_bytes - loop_bytes
    };
    vireo_event_loop_t *candidate = resources.allocate(resources.context, sizeof(*candidate));
    if (candidate == NULL) {
        set_error(out_error, VIREO_EVENT_LOOP_STAGE_ALLOCATE_CONTROL, no_error);
        result = VIREO_RESULT_NO_MEMORY;
        goto done;
    }
    vireo_epoll_event_t *events = resources.allocate(resources.context, events_bytes);
    if (events == NULL) {
        resources.deallocate(resources.context, candidate);
        set_error(out_error, VIREO_EVENT_LOOP_STAGE_ALLOCATE_EVENTS, no_error);
        result = VIREO_RESULT_NO_MEMORY;
        goto done;
    }
    registration_record_t *records = resources.allocate(resources.context, registrations_bytes);
    if (records == NULL) {
        resources.deallocate(resources.context, events);
        resources.deallocate(resources.context, candidate);
        set_error(out_error, VIREO_EVENT_LOOP_STAGE_ALLOCATE_REGISTRATIONS, no_error);
        result = VIREO_RESULT_NO_MEMORY;
        goto done;
    }
    /* 不依赖全零字节作为空函数指针表示；逐记录用 C 初始化建立空闲链。 */
    for (size_t i = 0; i < options->registration_capacity; ++i) {
        records[i] = (registration_record_t){.next_free = i + 1};
    }
    *candidate = (vireo_event_loop_t){
        .epoll = NULL, .events = events, .records = records, .free_head = 0,
        .read_fd = -1, .write_fd = -1,
        .ops = resources,
        .info = {.event_capacity = options->event_capacity, .events_bytes = events_bytes,
                 .loop_allocation_bytes = loop_bytes, .loop_id = loop_id,
                 .registration_capacity = options->registration_capacity,
                 .registrations_bytes = registrations_bytes,
                 .available_count = options->registration_capacity,
                 .max_memory_bytes = options->max_memory_bytes}
    };

    atomic_init(&candidate->stop_requested, false);

    /* 本层分配先完成，避免普通创建失败需关闭已经取得的系统资源。 */
    vireo_epoll_error_t dependency_error = no_error;
    result = resources.create_epoll(resources.context, &epoll_options, &candidate->epoll,
                                    &dependency_error);
    if (result != VIREO_OK) {
        resources.deallocate(resources.context, records);
        resources.deallocate(resources.context, events);
        resources.deallocate(resources.context, candidate);
        set_error(out_error, VIREO_EVENT_LOOP_STAGE_CREATE_EPOLL, dependency_error);
        goto done;
    }

    vireo_epoll_info_t epoll_info = {0};
    size_t total_bytes = 0;
    if (resources.inspect_epoll(resources.context, candidate->epoll, &epoll_info) != VIREO_OK ||
        epoll_info.event_capacity != epoll_options.event_capacity ||
        epoll_info.max_memory_bytes != epoll_options.max_memory_bytes ||
        epoll_info.events_bytes == 0 || epoll_info.allocation_bytes <= epoll_info.events_bytes ||
        epoll_info.allocation_bytes > epoll_options.max_memory_bytes ||
        vireo_checked_size_add(loop_bytes, epoll_info.allocation_bytes, &total_bytes) != VIREO_OK) {
        /* 默认依赖满足前置条件时应成功；异常不允许发布不可信预算快照。 */
        vireo_event_loop_error_t cleanup;
        (void)release_resources(candidate, &cleanup);
        set_error(out_error, VIREO_EVENT_LOOP_STAGE_INSPECT_EPOLL, cleanup.epoll_error);
        result = VIREO_RESULT_INTERNAL;
        goto done;
    }
    candidate->info.epoll_allocation_bytes = epoll_info.allocation_bytes;
    candidate->info.allocation_bytes = total_bytes;
    int fds[2];
    if (resources.create_pipe(resources.context, fds) == -1) {
        int const cause = errno;
        vireo_event_loop_error_t cleanup;
        (void)release_resources(candidate, &cleanup);
        set_system_error(out_error, VIREO_EVENT_LOOP_STAGE_WAKE_CREATE, cause);
        result = VIREO_RESULT_IO;
        goto done;
    }
    candidate->read_fd = fds[0];
    candidate->write_fd = fds[1];
    vireo_epoll_registration_t const wake = {VIREO_EPOLL_INTEREST_READ, 0};
    result = resources.add_epoll(resources.context, candidate->epoll, fds[0], &wake,
                                 &dependency_error);
    if (result != VIREO_OK) {
        /* ADD 主因保留；先关闭局部 pipe，随后回滚原有 epoll/heap。 */
        (void)resources.close_pipe(resources.context, fds[1]);
        (void)resources.close_pipe(resources.context, fds[0]);
        candidate->read_fd = candidate->write_fd = -1;
        vireo_event_loop_error_t cleanup;
        (void)release_resources(candidate, &cleanup);
        set_error(out_error, VIREO_EVENT_LOOP_STAGE_WAKE_REGISTER, dependency_error);
        goto done;
    }
    *out_loop = candidate;
    result = VIREO_OK;

done:
    errno = saved_errno;
    return result;
}

vireo_result_t vireo_event_loop_create_with_ops(vireo_event_loop_options_t const *options,
                                               vireo_event_loop_ops_t const *ops,
                                               vireo_event_loop_t **out_loop,
                                               vireo_event_loop_error_t *out_error)
{
    return vireo_event_loop_create_with_counter(options, ops, &identity_counter,
                                                out_loop, out_error);
}

vireo_result_t vireo_event_loop_create(vireo_event_loop_options_t const *options,
                                      vireo_event_loop_t **out_loop,
                                      vireo_event_loop_error_t *out_error)
{
    return vireo_event_loop_create_with_ops(options, &default_ops, out_loop, out_error);
}

vireo_result_t vireo_event_loop_inspect(vireo_event_loop_t const *loop,
                                       vireo_event_loop_info_t *out_info)
{
    if (loop == NULL || out_info == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    vireo_event_loop_info_t snapshot = loop->info;
    snapshot.stop_requested = atomic_load_explicit(&loop->stop_requested, memory_order_acquire);
    *out_info = snapshot;
    return VIREO_OK;
}

vireo_result_t vireo_event_loop_destroy(vireo_event_loop_t **loop,
                                       vireo_event_loop_error_t *out_error)
{
    int const saved_errno = errno;
    vireo_epoll_error_t dependency_error = {VIREO_EPOLL_STAGE_NONE, 0};
    set_error(out_error, VIREO_EVENT_LOOP_STAGE_NONE, dependency_error);
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    if (loop == NULL) {
        goto done;
    }
    result = VIREO_OK;
    if (*loop != NULL) {
        if ((*loop)->run_active) {
            result = VIREO_RESULT_BUSY;
            goto done;
        }
        vireo_event_loop_error_t cleanup;
        result = release_resources(*loop, &cleanup);
        *loop = NULL;
        if (out_error != NULL) *out_error = cleanup;
    }
done:
    errno = saved_errno;
    return result;
}

/* 三位输入与五位就绪结果不同，未知注册位在调用内核前拒绝。 */
static bool valid_interests(uint32_t interests)
{
    uint32_t const known = VIREO_EPOLL_INTEREST_READ | VIREO_EPOLL_INTEREST_WRITE |
                           VIREO_EPOLL_INTEREST_PEER_WRITE_CLOSED;
    return (interests & ~known) == 0;
}

/**
 * @brief 在访问记录前逐级证明身份域、槽边界及当前活跃 token
 *
 * @param[in] loop
 *     存活对象或 NULL，调用期借用。
 * @param[in] handle
 *     数值身份，不解引用外部指针。
 * @param[out] out_index
 *     非空内部输出，仅成功提交已证明在界内的索引。
 *
 * @return 空/过期 NOT_FOUND，畸形/跨域 INVALID_ARGUMENT，越界 RANGE，否则 OK。
 *
 * @note 无分配/系统调用/errno 操作；只在当前活跃且 token 完整相等时返回。
 */
static vireo_result_t find_registration(vireo_event_loop_t const *loop,
                                        vireo_event_loop_handle_t handle, size_t *out_index)
{
    if (loop == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    if (handle.loop_id == 0 && handle.token == 0) {
        return VIREO_RESULT_NOT_FOUND;
    }
    if (handle.loop_id != loop->info.loop_id || handle.token == 0 || (handle.token >> 16) == 0) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    size_t index = (size_t)(handle.token & SLOT_MASK);
    if (index >= loop->info.registration_capacity) {
        return VIREO_RESULT_RANGE;
    }
    if (!loop->records[index].active || loop->records[index].token != handle.token) {
        return VIREO_RESULT_NOT_FOUND;
    }
    *out_index = index;
    return VIREO_OK;
}

vireo_result_t vireo_event_loop_add(vireo_event_loop_t *loop,
                                    vireo_event_loop_registration_t const *registration,
                                    vireo_event_loop_handle_t *out_handle,
                                    vireo_event_loop_error_t *out_error)
{
    int const saved_errno = errno;
    vireo_epoll_error_t error = {VIREO_EPOLL_STAGE_NONE, 0};
    set_error(out_error, VIREO_EVENT_LOOP_STAGE_NONE, error);
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    if (loop == NULL || registration == NULL || out_handle == NULL ||
        out_handle->loop_id != 0 || out_handle->token != 0 || registration->fd < 0 ||
        registration->callback == NULL || !valid_interests(registration->interests)) {
        goto done;
    }
    for (size_t i = 0; i < loop->info.registration_capacity; ++i) {
        if (loop->records[i].active && loop->records[i].registration.fd == registration->fd) {
            result = VIREO_RESULT_BUSY;
            goto done;
        }
    }
    if (loop->free_head == loop->info.registration_capacity) {
        result = VIREO_RESULT_BUSY;
        goto done;
    }
    if (loop->last_serial == SERIAL_MAX) {
        result = VIREO_RESULT_OVERFLOW;
        goto done;
    }
    size_t const index = loop->free_head;
    /* 已证明 serial <= 2^48-1，index <= 65535；组合后可由 uint64_t 完整表示。 */
    ++loop->last_serial;
    uint64_t const token = (loop->last_serial << 16) | (uint64_t)index;
    vireo_epoll_registration_t const input = {registration->interests, token};
    result = loop->ops.add_epoll(loop->ops.context, loop->epoll, registration->fd, &input, &error);
    if (result != VIREO_OK) {
        set_error(out_error, VIREO_EVENT_LOOP_STAGE_ADD, error);
        goto done;
    }
    registration_record_t *record = &loop->records[index];
    loop->free_head = record->next_free;
    *record = (registration_record_t){
        .registration = *registration, .token = token, .active = true
    };
    ++loop->info.registered_count;
    --loop->info.available_count;
    *out_handle = (vireo_event_loop_handle_t){loop->info.loop_id, token};
done:
    errno = saved_errno;
    return result;
}

vireo_result_t vireo_event_loop_mod(vireo_event_loop_t *loop, vireo_event_loop_handle_t handle,
                                    uint32_t interests, vireo_event_loop_error_t *out_error)
{
    int const saved_errno = errno;
    vireo_epoll_error_t error = {VIREO_EPOLL_STAGE_NONE, 0};
    set_error(out_error, VIREO_EVENT_LOOP_STAGE_NONE, error);
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    if (!valid_interests(interests)) {
        goto done;
    }
    size_t index;
    result = find_registration(loop, handle, &index);
    if (result != VIREO_OK) {
        goto done;
    }
    registration_record_t *record = &loop->records[index];
    vireo_epoll_registration_t const input = {interests, record->token};
    result = loop->ops.mod_epoll(loop->ops.context, loop->epoll, record->registration.fd,
                                &input, &error);
    if (result == VIREO_OK) {
        record->registration.interests = interests;
    } else {
        set_error(out_error, VIREO_EVENT_LOOP_STAGE_MOD, error);
    }
done:
    errno = saved_errno;
    return result;
}

vireo_result_t vireo_event_loop_del(vireo_event_loop_t *loop, vireo_event_loop_handle_t *handle,
                                    vireo_event_loop_error_t *out_error)
{
    int const saved_errno = errno;
    vireo_epoll_error_t error = {VIREO_EPOLL_STAGE_NONE, 0};
    set_error(out_error, VIREO_EVENT_LOOP_STAGE_NONE, error);
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    if (handle == NULL) {
        goto done;
    }
    size_t index;
    result = find_registration(loop, *handle, &index);
    if (result != VIREO_OK) {
        goto done;
    }
    registration_record_t *record = &loop->records[index];
    result = loop->ops.del_epoll(loop->ops.context, loop->epoll, record->registration.fd, &error);
    if (result != VIREO_OK) {
        set_error(out_error, VIREO_EVENT_LOOP_STAGE_DEL, error);
        goto done;
    }
    *record = (registration_record_t){.next_free = loop->free_head};
    loop->free_head = index;
    --loop->info.registered_count;
    ++loop->info.available_count;
    *handle = (vireo_event_loop_handle_t){0};
done:
    errno = saved_errno;
    return result;
}

vireo_result_t vireo_event_loop_registration_inspect(
    vireo_event_loop_t const *loop, vireo_event_loop_handle_t handle,
    vireo_event_loop_registration_t *out_registration)
{
    if (out_registration == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    size_t index;
    vireo_result_t result = find_registration(loop, handle, &index);
    if (result == VIREO_OK) {
        *out_registration = loop->records[index].registration;
    }
    return result;
}

vireo_result_t vireo_event_loop_advance_serial_for_test(vireo_event_loop_t *loop, uint64_t serial)
{
    if (loop == NULL || serial < loop->last_serial || serial > SERIAL_MAX) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    if (loop->info.registered_count != 0) {
        return VIREO_RESULT_BUSY;
    }
    loop->last_serial = serial;
    return VIREO_OK;
}

vireo_result_t vireo_event_loop_resolve_token(vireo_event_loop_t const *loop, uint64_t token,
                                             vireo_event_loop_handle_t *out_handle,
                                             vireo_event_loop_registration_t *out_registration)
{
    if (loop == NULL || out_handle == NULL || out_registration == NULL) {
        return VIREO_RESULT_INVALID_ARGUMENT;
    }
    vireo_event_loop_handle_t handle = {loop->info.loop_id, token};
    size_t index;
    vireo_result_t result = find_registration(loop, handle, &index);
    if (result == VIREO_OK) {
        *out_handle = handle;
        *out_registration = loop->records[index].registration;
    }
    return result;
}

/**
 * @brief 按当前关注过滤普通就绪位，始终保留错误和挂断
 *
 * @param[in] interests
 *     当前有效注册的三已知关注位。
 * @param[in] events
 *     已全批检查的五已知就绪位。
 *
 * @return
 *     允许向当前绑定交付的位组合，零表示无需调用。
 *
 * @note 显式映射关注与输出，不能依赖两组宏碰巧具有相同数值；不修改对象或 errno。
 */
static uint32_t filter_events(uint32_t interests, uint32_t events)
{
    uint32_t mask = VIREO_EPOLL_EVENT_ERROR | VIREO_EPOLL_EVENT_HANGUP;
    if ((interests & VIREO_EPOLL_INTEREST_READ) != 0) {
        mask |= VIREO_EPOLL_EVENT_READ;
    }
    if ((interests & VIREO_EPOLL_INTEREST_WRITE) != 0) {
        mask |= VIREO_EPOLL_EVENT_WRITE;
    }
    if ((interests & VIREO_EPOLL_INTEREST_PEER_WRITE_CLOSED) != 0) {
        mask |= VIREO_EPOLL_EVENT_PEER_WRITE_CLOSED;
    }
    return events & mask;
}

/**
 * @brief 复用已受在途保护的工作区处理一轮
 *
 * @param[in,out] loop
 *     存活且 run_active 为 true，由 Reactor 独占；允许合法并发停止请求。
 * @param[in] timeout_ms
 *     已验证的 -1/0/正毫秒。
 * @param[out] out_info
 *     非空独立候选统计，仅成功提交客户项计数。
 * @param[out] out_error
 *     可空独立诊断。
 *
 * @return
 *     OK 完整一轮或入口已停止；等待/预检/控制读失败零客户回调，统计保持。
 *
 * @note 不清在途标记，不恢复外层 errno。全批基础验证先于控制读取和客户分发；
 *     当前批次即使收到停止仍完成，控制项不进入客户记录表或四计数。
 */
static vireo_result_t run_round(vireo_event_loop_t *loop, int timeout_ms,
                               vireo_event_loop_run_info_t *out_info,
                               vireo_event_loop_error_t *out_error)
{
    vireo_epoll_error_t const no_error = {VIREO_EPOLL_STAGE_NONE, 0};
    vireo_event_loop_run_info_t stats = {0};
    if (atomic_load_explicit(&loop->stop_requested, memory_order_acquire)) {
        *out_info = stats;
        return VIREO_OK;
    }
    size_t count = 0;
    vireo_epoll_error_t dependency_error = no_error;
    vireo_result_t result = loop->ops.wait_epoll(loop->ops.context, loop->epoll, loop->events,
                                                loop->info.event_capacity, timeout_ms,
                                                &count, &dependency_error);
    if (result != VIREO_OK) {
        set_error(out_error, VIREO_EVENT_LOOP_STAGE_WAIT, dependency_error);
        return result;
    }
    if (count > loop->info.event_capacity) {
        set_error(out_error, VIREO_EVENT_LOOP_STAGE_WAIT, no_error);
        return VIREO_RESULT_INTERNAL;
    }
    uint32_t const known = VIREO_EPOLL_EVENT_READ | VIREO_EPOLL_EVENT_WRITE |
                           VIREO_EPOLL_EVENT_PEER_WRITE_CLOSED | VIREO_EPOLL_EVENT_ERROR |
                           VIREO_EPOLL_EVENT_HANGUP;
    bool wake = false;
    for (size_t i = 0; i < count; ++i) {
        vireo_epoll_event_t const event = loop->events[i];
        if ((event.events & ~known) != 0) {
            set_error(out_error, VIREO_EVENT_LOOP_STAGE_WAIT, no_error);
            return VIREO_RESULT_INTERNAL;
        }
        if (event.token == 0) {
            if (event.events != VIREO_EPOLL_EVENT_READ) {
                set_system_error(out_error, VIREO_EVENT_LOOP_STAGE_WAKE_READ, 0);
                return VIREO_RESULT_INTERNAL;
            }
            wake = true;
        } else if ((event.token >> 16) == 0 ||
                   (event.token & SLOT_MASK) >= loop->info.registration_capacity) {
            set_error(out_error, VIREO_EVENT_LOOP_STAGE_DISPATCH, no_error);
            return VIREO_RESULT_INTERNAL;
        }
    }
    if (wake) {
        /* 提示可能合并或过期；只读一次，不让连续请求者造成无界 drain。 */
        unsigned char buffer[64];
        ssize_t const n = loop->ops.read_pipe(loop->ops.context, loop->read_fd,
                                              buffer, sizeof(buffer));
        int const cause = errno;
        if (n == -1 && cause != EAGAIN && cause != EWOULDBLOCK) {
            set_system_error(out_error, VIREO_EVENT_LOOP_STAGE_WAKE_READ, cause);
            return VIREO_RESULT_IO;
        }
        if (n < -1 || n == 0 || n > (ssize_t)sizeof(buffer)) {
            set_system_error(out_error, VIREO_EVENT_LOOP_STAGE_WAKE_READ, 0);
            return VIREO_RESULT_INTERNAL;
        }
    }
    for (size_t i = 0; i < count; ++i) {
        vireo_epoll_event_t const event = loop->events[i];
        if (event.token == 0) continue;
        ++stats.ready_count;
        size_t const index = (size_t)(event.token & SLOT_MASK);
        registration_record_t const *record = &loop->records[index];
        if (!record->active || record->token != event.token) {
            ++stats.stale_count;
            continue;
        }
        vireo_event_loop_registration_t const binding = record->registration;
        uint32_t const events = filter_events(binding.interests, event.events);
        if (events == 0) {
            ++stats.filtered_count;
            continue;
        }
        vireo_event_loop_handle_t const handle = {loop->info.loop_id, event.token};
        /* 仅取当前绑定；回调可注销并复用槽，之后不再读取 record/context。 */
        binding.callback(loop, handle, binding.fd, events, binding.context);
        ++stats.dispatched_count;
    }
    *out_info = stats;
    return VIREO_OK;
}

vireo_result_t vireo_event_loop_run_once(vireo_event_loop_t *loop, int timeout_ms,
                                        vireo_event_loop_run_info_t *out_info,
                                        vireo_event_loop_error_t *out_error)
{
    int const saved_errno = errno;
    set_system_error(out_error, VIREO_EVENT_LOOP_STAGE_NONE, 0);
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    if (loop != NULL && out_info != NULL && timeout_ms >= -1) {
        if (loop->run_active) {
            result = VIREO_RESULT_BUSY;
        } else {
            loop->run_active = true;
            result = run_round(loop, timeout_ms, out_info, out_error);
            loop->run_active = false;
        }
    }
    errno = saved_errno;
    return result;
}

vireo_result_t vireo_event_loop_run(vireo_event_loop_t *loop,
                                   vireo_event_loop_error_t *out_error)
{
    int const saved_errno = errno;
    set_system_error(out_error, VIREO_EVENT_LOOP_STAGE_NONE, 0);
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    if (loop != NULL) {
        if (loop->run_active) {
            result = VIREO_RESULT_BUSY;
        } else {
            loop->run_active = true;
            result = VIREO_OK;
            while (!atomic_load_explicit(&loop->stop_requested, memory_order_acquire)) {
                vireo_event_loop_run_info_t stats;
                result = run_round(loop, -1, &stats, out_error);
                if (result != VIREO_OK) break;
            }
            loop->run_active = false;
        }
    }
    errno = saved_errno;
    return result;
}

vireo_result_t vireo_event_loop_request_stop(vireo_event_loop_t *loop,
                                            vireo_event_loop_error_t *out_error)
{
    int const saved_errno = errno;
    set_system_error(out_error, VIREO_EVENT_LOOP_STAGE_NONE, 0);
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    if (loop != NULL) {
        /* 不仅读 false 到 true 时通知：前次通知 IO 后，重复调用仍可补发。 */
        atomic_store_explicit(&loop->stop_requested, true, memory_order_release);
        unsigned char const byte = 1;
        ssize_t const n = loop->ops.write_pipe(loop->ops.context, loop->write_fd, &byte, 1);
        int const cause = errno;
        result = VIREO_OK;
        if (n == -1 && cause != EAGAIN && cause != EWOULDBLOCK) {
            set_system_error(out_error, VIREO_EVENT_LOOP_STAGE_STOP_NOTIFY, cause);
            result = VIREO_RESULT_IO;
        } else if (n != 1 && n != -1) {
            set_system_error(out_error, VIREO_EVENT_LOOP_STAGE_STOP_NOTIFY, 0);
            result = VIREO_RESULT_INTERNAL;
        }
    }
    errno = saved_errno;
    return result;
}
