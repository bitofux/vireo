/*
- PROJECT : VIREO
- FILE    : event_loop_internal.h
- AUTHOR  : bitofux
- DATE    : 2026-10-03
- BRIEF   : 此模块负责：
- -- 仅供 event loop 实现与本模块故障测试的公共依赖适配
 */
#ifndef VIREO_NET_EVENT_LOOP_INTERNAL_H
#define VIREO_NET_EVENT_LOOP_INTERNAL_H

#include <vireo/net/event_loop.h>
#include <stdatomic.h>
#include <sys/types.h>

/** 按值复制；context 与回调代码借用至回滚/销毁，不是下游自定义 backend 合同。 */
typedef struct vireo_event_loop_ops {
    /** 可空回调上下文，全部资源清理结束前须保持存活。 */
    void *context;

    /** malloc 等价，返回基本对齐的真实分配或 NULL。 */
    void *(*allocate)(void *context, size_t size);

    /** 配对释放，不报告失败，不访问已经释放的块。 */
    void (*deallocate)(void *context, void *memory);

    /** 公共 epoll_create 等价：成功交付真实唯一对象，失败保持空 owner。 */
    vireo_result_t (*create_epoll)(void *context, vireo_epoll_options_t const *options,
                                  vireo_epoll_t **owner, vireo_epoll_error_t *error);

    /** 公共 epoll_inspect 等价；测试可注入异常快照，不能提供伪造对象地址。 */
    vireo_result_t (*inspect_epoll)(void *context, vireo_epoll_t const *epoll,
                                   vireo_epoll_info_t *info);

    /** 公共 epoll_destroy 等价，IO 仍消费对象；测试须真实释放其底层资源。 */
    vireo_result_t (*destroy_epoll)(void *context, vireo_epoll_t **owner,
                                   vireo_epoll_error_t *error);
    /** 公共 ADD 等价，系统失败不留下成功 watch；输入仅调用期借用。 */
    vireo_result_t (*add_epoll)(void *context, vireo_epoll_t *epoll, int fd,
                               vireo_epoll_registration_t const *registration,
                               vireo_epoll_error_t *error);

    /** 公共 MOD 等价，失败不改变原关注/token。 */
    vireo_result_t (*mod_epoll)(void *context, vireo_epoll_t *epoll, int fd,
                               vireo_epoll_registration_t const *registration,
                               vireo_epoll_error_t *error);

    /** 公共 DEL 等价，失败不由适配层静默转为成功。 */
    vireo_result_t (*del_epoll)(void *context, vireo_epoll_t *epoll, int fd,
                               vireo_epoll_error_t *error);

    /** 公共 wait 等价，失败保持数组/count；测试可注入有界值或异常计数，不越界写入。 */
    vireo_result_t (*wait_epoll)(void *context, vireo_epoll_t *epoll,
                                vireo_epoll_event_t *events, size_t capacity, int timeout_ms,
                                size_t *count, vireo_epoll_error_t *error);
    /** pipe2(NONBLOCK|CLOEXEC) 等价；0 交付两个真实 owned fd，-1 不交付/不修改输出。 */
    int (*create_pipe)(void *context, int fds[2]);
    /** 一次非阻塞 read 等价；只写 capacity 内存，保留 errno，无自动重试。 */
    ssize_t (*read_pipe)(void *context, int fd, void *buffer, size_t capacity);
    /** 一次一字节 write 等价；可并发，context/代码及 fd 借用须存活，无隐藏非原子状态。 */
    ssize_t (*write_pipe)(void *context, int fd, void const *buffer, size_t size);
    /** Linux close 等价；0/-1 均消费 fd，测试注入须实际关闭，只调用一次。 */
    int (*close_pipe)(void *context, int fd);
} vireo_event_loop_ops_t;

/**
 * @brief 取得默认系统适配表的值副本，仅本实现和本模块测试使用
 *
 * @return
 *     完整有效表，context 为 NULL；可在测试中替换本模块窄回调。
 *
 * @note 不分配，不读写 errno，不授予下游自定义 backend 公共合同。
 */
vireo_event_loop_ops_t vireo_event_loop_default_ops(void);

/**
 * @brief 以指定本层资源表创建，仅供本实现和本模块测试
 *
 * @param[in] options
 *     公共选项，继承公共 create 前置条件。
 * @param[in] ops
 *     非 NULL、十三回调均非 NULL；表只借用到返回并按值复制，上下文须存活到最后清理。
 * @param[in,out] out_loop
 *     独立空 owner，继承公共 create 输出与所有权。
 * @param[out] out_error
 *     可空独立诊断，继承公共 create 语义。
 *
 * @retval VIREO_OK
 *     完整发布唯一 owner。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     表非法或公共参数非法。
 * @retval VIREO_RESULT_OVERFLOW
 *     本层数组/总量不可表示或身份源耗尽。
 * @retval VIREO_RESULT_RANGE
 *     硬限或预算不足。
 * @retval VIREO_RESULT_NO_MEMORY
 *     两层之一用户态申请失败。
 * @retval VIREO_RESULT_IO
 *     epoll 创建/内部注册或 pipe 创建系统失败。
 * @retval VIREO_RESULT_INTERNAL
 *     依赖观察违反公共不变量，回滚后不发布。
 *
 * @note create 为 reactor-only，全部路径保持 errno；发布后的通知适配须支持并发。
 *     只有本模块 private seam，
 *     不引用其他模块私有头或布局；资源按表配对，异常快照测试不证明现实依赖会违反合同。
 */
vireo_result_t vireo_event_loop_create_with_ops(vireo_event_loop_options_t const *options,
                                               vireo_event_loop_ops_t const *ops,
                                               vireo_event_loop_t **out_loop,
                                               vireo_event_loop_error_t *out_error);


/**
 * @brief 使用调用期借用的身份源创建，仅本模块耗尽/并发边界测试使用
 *
 * @param[in] options
 *     公共选项，继承 create 前置条件。
 * @param[in] ops
 *     合法本层资源表，内容按值复制，上下文存活到最后清理。
 * @param[in,out] counter
 *     非 NULL、有效的原子 uint64_t 已初始化计数器，仅借到返回；存最近发放身份，
 *     测试须以独立对象隔离身份域，不覆盖生产全局计数。
 * @param[in,out] out_loop
 *     独立空 owner，成功接管对象。
 * @param[out] out_error
 *     可空独立诊断。
 *
 * @return 公共 create 全部结果；耗尽 OVERFLOW/ISSUE_ID，不分配，失败输出保持。
 *
 * @note 只替换身份源，不保存源指针；资源、预算、errno 与清理继承公共 create。
 */
vireo_result_t vireo_event_loop_create_with_counter(
    vireo_event_loop_options_t const *options, vireo_event_loop_ops_t const *ops,
    _Atomic uint64_t *counter, vireo_event_loop_t **out_loop, vireo_event_loop_error_t *out_error);

/**
 * @brief 空表中前移发放序号，只用于本模块耗尽边界测试
 *
 * @param[in,out] loop
 *     非 NULL 存活空表，调用期独占借用。
 * @param[in] serial
 *     不低于当前序号且不超过 2^48-1。
 *
 * @return 非法输入 INVALID_ARGUMENT，在用 BUSY，否则 OK；失败保持，errno 不变。
 *
 * @note 不回退、不改生产全局身份，不是下游接口。
 */
vireo_result_t vireo_event_loop_advance_serial_for_test(vireo_event_loop_t *loop, uint64_t serial);

/**
 * @brief 按本 loop 的内核 token 解析当前有效绑定，仅本模块与测试使用
 *
 * @param[in] loop
 *     非 NULL 存活对象，Reactor 独占借用。
 * @param[in] token
 *     内核保存的不透明值，必须属于此 loop。
 * @param[out] out_handle
 *     非 NULL 独立身份输出。
 * @param[out] out_registration
 *     非 NULL 独立绑定输出，值副本不延长借用。
 *
 * @return OK 提交两输出，非法/过期/越界继承注册校验结果，失败全部保持。
 *
 * @note 无分配/调用回调/系统等待，不读写 errno；不是公共 loop wait。
 */
vireo_result_t vireo_event_loop_resolve_token(vireo_event_loop_t const *loop, uint64_t token,
                                             vireo_event_loop_handle_t *out_handle,
                                             vireo_event_loop_registration_t *out_registration);

#endif /* VIREO_NET_EVENT_LOOP_INTERNAL_H */
