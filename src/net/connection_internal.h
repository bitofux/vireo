/*
- PROJECT : VIREO
- FILE    : connection_internal.h
- AUTHOR  : bitofux
- DATE    : 2026-10-03
- BRIEF   : 此模块负责：
- -- connection 自有资源的私有故障注入边界；不授予下游布局依赖
- -- 逐对象 recv/send 操作表用于确定短进度、系统失败与异常数量测试
 */
#ifndef VIREO_NET_CONNECTION_INTERNAL_H
#define VIREO_NET_CONNECTION_INTERNAL_H

#include <vireo/net/connection.h>
#include <sys/types.h>

/**
 * 仅本模块测试使用，逐对象按值复制，无全局可变 hooks；context 借用至 destroy 返回。
 * 所有函数必需非空；分配遵守 malloc/free 配对语义，失败不取得资源。
 * 查询/关闭遵守对应系统调用的 0/-1 或 flags/-1 与 errno 语义，不隐式重试。
 * buffer hooks 只包装公共 create/destroy，遵守其结果/owner 合同，禁止引用旧私有布局。
 * receive 遵守 recv 数量/errno 语义；异常数量仅用于本模块验证 INTERNAL 防御，不越界写入。
 * send_bytes 遵守 send 数量/errno 语义，仅调用期间借用 readonly 输入，不保存。
 * 此 seam 不属于公共 API，不允许把内部大小作为 buffer 预算。
 */
typedef struct vireo_connection_ops {
    void *context;
    void *(*allocate)(void *context, size_t bytes);
    void (*deallocate)(void *context, void *memory);
    int (*get_flags)(void *context, int fd, int command);
    int (*socket_type)(void *context, int fd, int *out_type);
    int (*peer_connected)(void *context, int fd);
    int (*close_fd)(void *context, int fd);
    vireo_result_t (*create_buffer)(void *context, size_t capacity, vireo_buffer_t **out);
    void (*destroy_buffer)(void *context, vireo_buffer_t **owner);
    ssize_t (*receive)(void *context, int fd, void *bytes, size_t request, int flags);
    ssize_t (*send_bytes)(void *context, int fd, void const *bytes, size_t request, int flags);
} vireo_connection_ops_t;

/**
 * @brief 使用完整的私有依赖表创建；公开构造调用固定系统实现
 *
 * @param[in] options
 *     公共容量合同。
 * @param[in,out] fd_owner
 *     公共 fd 交接合同。
 * @param[in] ops
 *     非空完整表；复制函数/context，context 生命周期覆盖对象，不转移其所有权。
 * @param[in,out] out_connection
 *     公共唯一 owner 合同。
 * @param[out] error
 *     可空公共诊断。
 *
 * @return 公共 create 结果；ops 不完整为 INVALID_ARGUMENT。
 *
 * @note errno 保持，失败两个 owner 保持；只用于本模块测试。
 */
vireo_result_t vireo_connection_create_with_ops(vireo_connection_options_t const *options,
                                                int *fd_owner,
                                                vireo_connection_ops_t const *ops,
                                                vireo_connection_t **out_connection,
                                                vireo_connection_error_t *error);

/**
 * 仅本模块绑定测试的逐对象依赖表，遵守公开 loop 的成功发布/失败保持合同。
 * 函数完整且非空，context 借用至 connection 销毁；不引用 loop 私有布局或 backend。
 * 与资源/I/O seam 分离，旧测试及公开构造固定使用公共 loop 默认函数。
 */
typedef struct vireo_connection_loop_ops {
    void *context;
    vireo_result_t (*add)(void *context, vireo_event_loop_t *loop,
                          vireo_event_loop_registration_t const *registration,
                          vireo_event_loop_handle_t *out_handle, vireo_event_loop_error_t *error);
    vireo_result_t (*mod)(void *context, vireo_event_loop_t *loop,
                          vireo_event_loop_handle_t handle, uint32_t interests,
                          vireo_event_loop_error_t *error);
    vireo_result_t (*del)(void *context, vireo_event_loop_t *loop,
                          vireo_event_loop_handle_t *handle, vireo_event_loop_error_t *error);
} vireo_connection_loop_ops_t;

/**
 * @brief 使用独立的完整 loop 依赖表创建，资源构造仍走固定系统实现
 *
 * @param[in] options
 *     公共配置，仅借用到返回。
 * @param[in,out] fd_owner
 *     公共 fd 成功交接、失败保持合同。
 * @param[in] loop_ops
 *     非空完整表，函数/context 按值复制，context 须覆盖对象生命周期。
 * @param[in,out] out_connection
 *     独立唯一 owner，入口须空；只有完整成功才发布。
 * @param[out] error
 *     可空公共资源诊断。
 *
 * @return 公共 create 结果；不完整 loop 表在查询/分配前 INVALID_ARGUMENT。
 *
 * @note 仅 own module 测试；不转移 context，保持入口 errno。
 */
vireo_result_t vireo_connection_create_with_loop_ops(
    vireo_connection_options_t const *options, int *fd_owner,
    vireo_connection_loop_ops_t const *loop_ops, vireo_connection_t **out_connection,
    vireo_connection_error_t *error);

#endif /* VIREO_NET_CONNECTION_INTERNAL_H */
