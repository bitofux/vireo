/*
 * PROJECT : VIREO
 * FILE    : notifier_internal.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-13
 * BRIEF   : 仅供本核心实现及资源故障测试的配对操作 seam
 */
#ifndef VIREO_THREAD_NOTIFIER_INTERNAL_H
#define VIREO_THREAD_NOTIFIER_INTERNAL_H

#include <vireo/thread/notifier.h>
#include <sys/types.h>

/** 按值复制的 own private 表，不是下游自定义 allocator 合同。 */
typedef struct vireo_notifier_ops {
    void *context; /**< 可空借用上下文，配对回滚或销毁前必须存活。 */
    void *(*allocate)(void *context, size_t size); /**< malloc 等价，NULL 为失败。 */
    void (*deallocate)(void *context, void *memory); /**< 配对 free，无可报告失败。 */
    int (*create)(void *context, unsigned int initval, int flags); /**< eventfd 等价，-1/errno。 */
    int (*close)(void *context, int fd); /**< Linux close 等价；错误仍消费有效 fd。 */
    ssize_t (*read)(void *context, int fd, void *bytes, size_t size); /**< read 等价，最多写 size 字节。 */
    ssize_t (*write)(void *context, int fd, void const *bytes, size_t size); /**< write 等价，仅调用时借用。 */
} vireo_notifier_ops_t;

/**
 * @brief
 *     使用配对资源表创建，仅供本实现和确定性故障测试。
 *
 * @param[in] options
 *     继承公共 create 选项与借用前置。
 * @param[in] ops
 *     必需稳定可读表，六回调非空；表按值复制，函数和 context 存活至回滚/销毁。
 *     并发 I/O 的 context 由提供者同步，不能从默认表安全外推测试表线程安全。
 * @param[out] out_notifier
 *     继承公共 create 空 owner 与不重叠合同。
 * @param[out] out_error
 *     继承公共 create 可空诊断合同。
 *
 * @return
 *     继承公共 create 结果及保持规则，非法表额外返回 INVALID_ARGUMENT。
 *
 * @note
 *     创建/销毁排除全部访问，全程禁 POSIX 取消，全部路径保持 errno。
 *     回调等价原生资源约定，对象不保存表地址；禁止下游包含本头或依赖布局。
 */
vireo_result_t vireo_notifier_create_with_ops(vireo_notifier_options_t const *options,
    vireo_notifier_ops_t const *ops, vireo_notifier_t **out_notifier,
    vireo_notifier_error_t *out_error);

#endif /* VIREO_THREAD_NOTIFIER_INTERNAL_H */
