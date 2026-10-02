/*
 * PROJECT : VIREO
 * FILE    : epoll_internal.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-02
 * BRIEF   : 此模块负责：
 * -- 仅供 epoll 实现和本模块测试的资源操作 seam
 */
#ifndef VIREO_NET_EPOLL_INTERNAL_H
#define VIREO_NET_EPOLL_INTERNAL_H

#include <vireo/net/epoll.h>
#include <sys/epoll.h>

/** 按值复制的内部表；context 借用到回滚或销毁，不能用于下游自定义分配器。 */
typedef struct vireo_epoll_ops {
    void *context; /**< 可空回调上下文，全部资源释放前保持存活。 */
    void *(*allocate)(void *context, size_t size); /**< malloc 等价，支持控制块基本对齐。 */
    void (*deallocate)(void *context, void *memory); /**< 配对释放，无可报告失败。 */
    int (*create)(void *context, int flags); /**< epoll_create1 等价；失败 -1/errno。 */
    int (*close)(void *context, int fd); /**< Linux close 等价；失败也释放有效 fd，不重试。 */
    int (*control)(void *context, int epfd, int operation, int fd,
                   struct epoll_event *event); /**< epoll_ctl 等价；DEL 的 event 为 NULL。 */
    int (*wait)(void *context, int epfd, struct epoll_event *events,
                int maxevents, int timeout_ms); /**< epoll_wait 等价；只写至多 maxevents 项。 */
} vireo_epoll_ops_t;

/**
 * @brief 按指定资源表创建，仅供本实现和故障测试
 * @param[in] options 公共选项，继承公共 create 前置条件。
 * @param[in] ops 非 NULL，六回调均非 NULL；表仅调用期间借用并按值复制，
 *     context 与函数代码须存活到失败回滚或最终 destroy。
 * @param[in,out] out_epoll 独立空 owner，继承公共 create 输出与所有权。
 * @param[out] out_error 可空独立诊断，继承公共 create 语义。
 * @retval VIREO_OK 已发布唯一 owner。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 操作表非法或公共参数非法。
 * @retval VIREO_RESULT_OVERFLOW 数组或总量不可表示。
 * @retval VIREO_RESULT_RANGE 硬限或预算不足。
 * @retval VIREO_RESULT_NO_MEMORY 用户态分配失败。
 * @retval VIREO_RESULT_IO 实例创建失败。
 * @note 所有路径保持 errno；表/输入/输出互不重叠，资源按表配对逆序释放。
 *     reactor-only，无内部锁；没有新增公共自定义 allocator 合同。
 */
vireo_result_t vireo_epoll_create_with_ops(vireo_epoll_options_t const *options,
                                          vireo_epoll_ops_t const *ops,
                                          vireo_epoll_t **out_epoll,
                                          vireo_epoll_error_t *out_error);

#endif /* VIREO_NET_EPOLL_INTERNAL_H */
