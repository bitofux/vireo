/*
- PROJECT : VIREO
- FILE    : acceptor_internal.h
- AUTHOR  : bitofux
- DATE    : 2026-10-04
- BRIEF   : 此模块负责：
- -- 仅本模块测试的逐对象查询、分配与关闭故障注入
- -- 逐对象 accept4 故障分类与真实新 fd 交接
- -- 逐对象公开 loop 接口与不改变注册的失败注入
 */
#ifndef VIREO_NET_ACCEPTOR_INTERNAL_H
#define VIREO_NET_ACCEPTOR_INTERNAL_H

#include <sys/socket.h>
#include <vireo/net/acceptor.h>

/**
 * 完整表按值复制，context 借用到 destroy 返回；不属于公共 API，无全局可变 hooks。
 * allocate/deallocate 遵守 malloc/free，查询遵守 fcntl/getsockopt 的只读返回约定；
 * close_fd 在实际 Linux close 消费 fd 后可注入 -1/errno，不得谎报消费而泄漏 fd。
 * accept_client 遵守 accept4：成功交出全新唯一 owned fd，失败 -1/errno 无新 fd；
 * flags 为 NONBLOCK|CLOEXEC，不得伪造已有 fd 或保存调用者输出，也不提供 fallback。
 * loop_add/mod/del 遵守公开 loop 合同；失败保持登记/输出，成功调用真实 public 入口。
 * 不允许在 hook 内重入或消费调用者 owner，不保证修复违约 hook 或损坏对象。
 */
typedef struct vireo_acceptor_ops {
    void *context;
    void *(*allocate)(void *context, size_t bytes);
    void (*deallocate)(void *context, void *memory);
    int (*get_flags)(void *context, int fd, int command);
    int (*get_option)(void *context, int fd, int option, int *value, socklen_t *length);
    int (*close_fd)(void *context, int fd);
    int (*accept_client)(void *context, int listener_fd, int flags);
    vireo_result_t (*loop_add)(void *context, vireo_event_loop_t *loop,
                               vireo_event_loop_registration_t const *registration,
                               vireo_event_loop_handle_t *handle, vireo_event_loop_error_t *error);
    vireo_result_t (*loop_mod)(void *context, vireo_event_loop_t *loop,
                               vireo_event_loop_handle_t handle, uint32_t interests,
                               vireo_event_loop_error_t *error);
    vireo_result_t (*loop_del)(void *context, vireo_event_loop_t *loop,
                               vireo_event_loop_handle_t *handle, vireo_event_loop_error_t *error);
} vireo_acceptor_ops_t;

/**
 * @brief 用完整逐对象依赖表构造，仅供本模块测试
 *
 * @param[in] options
 *     公共显式预算，调用期间借用。
 * @param[in,out] fd_owner
 *     公共独立监听 fd owner。
 * @param[in] ops
 *     非空完整表，成功按值复制；context 覆盖对象生命期。
 * @param[in,out] out_acceptor
 *     公共空 owner，成功才发布。
 * @param[out] error
 *     可空公共诊断。
 *
 * @return 公共构造结果；表缺失或不完整为 INVALID_ARGUMENT。
 *
 * @note 全部所有权、失败保持与 errno 合同同公共入口，不依赖旧模块私有头。
 */
vireo_result_t vireo_acceptor_create_with_ops(vireo_acceptor_options_t const *options,
                                             int *fd_owner, vireo_acceptor_ops_t const *ops,
                                             vireo_acceptor_t **out_acceptor,
                                             vireo_acceptor_error_t *error);

#endif /* VIREO_NET_ACCEPTOR_INTERNAL_H */
