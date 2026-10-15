/*
- PROJECT : VIREO
- FILE    : tcp_server_internal.h
- AUTHOR  : bitofux
- DATE    : 2026-10-04
- BRIEF   : 此模块负责：
- -- 仅本模块测试使用的逐对象公共依赖与申请故障表
 */
#ifndef VIREO_NET_TCP_SERVER_INTERNAL_H
#define VIREO_NET_TCP_SERVER_INTERNAL_H

#include <vireo/net/tcp_server.h>

/**
 * 完整表按值复制，context 借用至 destroy 返回，无全局可变 hooks，不属于下游 API。
 * allocate/free 成对；create 成功取得完整空资源，失败保持 owner。
 * inspect 可污染数值/拒绝，不能变更实际资源；销毁调用公开依赖，loop OK/IO 必须真实消费，
 * pool 拒绝必须保持，构造回滚的空 pool 必须成功释放，loop 只能 OK/消费型 IO。
 * 不偷偷注册/运行/发停止请求/收纳连接，不导入旧 private 头或布局；违约不保证恢复。
 */
typedef struct vireo_tcp_server_ops {
    void *context;
    void *(*allocate)(void *context, size_t bytes);
    void (*deallocate)(void *context, void *memory);
    vireo_result_t (*create_loop)(void *context, vireo_event_loop_options_t const *options,
                                  vireo_event_loop_t **owner, vireo_event_loop_error_t *error);
    vireo_result_t (*inspect_loop)(void *context, vireo_event_loop_t const *loop,
                                   vireo_event_loop_info_t *info);
    vireo_result_t (*destroy_loop)(void *context, vireo_event_loop_t **owner,
                                   vireo_event_loop_error_t *error);
    vireo_result_t (*create_pool)(void *context, vireo_connection_pool_options_t const *options,
                                  vireo_connection_pool_t **owner,
                                  vireo_connection_pool_error_t *error);
    vireo_result_t (*inspect_pool)(void *context, vireo_connection_pool_t const *pool,
                                   vireo_connection_pool_info_t *info);
    vireo_result_t (*destroy_pool)(void *context, vireo_connection_pool_t **owner,
                                   vireo_connection_pool_error_t *error);
} vireo_tcp_server_ops_t;

/**
 * @brief 使用完整逐对象表构造，仅本模块测试
 *
 * @param[in] options
 *     公共显式选项，调用期借用。
 * @param[in] ops
 *     非空完整表，按值复制；context 保持至资源销毁。
 * @param[in,out] out_server
 *     公共独立空 owner。
 * @param[out] error
 *     可空独立公共诊断。
 *
 * @return
 *     沿公共构造合同；表缺失/不完整为 INVALID_ARGUMENT。
 *
 * @note 保持入口 errno，禁止与旧模块 private seam 接线。
 */
vireo_result_t vireo_tcp_server_create_with_ops(vireo_tcp_server_options_t const *options,
                                               vireo_tcp_server_ops_t const *ops,
                                               vireo_tcp_server_t **out_server,
                                               vireo_tcp_server_error_t *error);

/**
 * @brief 本核心辅助容量创建测试 seam，复用原完整逐对象依赖表
 *
 * @param[in] options
 *     原公共四项选项。
 * @param[in] auxiliary_capacity
 *     原新公共入口的正辅助项数。
 * @param[in] ops
 *     原完整本核心表，按值复制；context 借用至销毁。
 * @param[in,out] out_server
 *     独立入口 NULL owner。
 * @param[out] error
 *     原可空完整资源诊断。
 *
 * @return
 *     沿新公共创建合同；表缺失/不完整 INVALID_ARGUMENT。
 *
 * @note
 *     只允许本 server 的测试使用，不属于下游合同，不读取其他核心私有头。
 *     创建/回滚/消费沿原表约束，所有路径保持入口 errno。
 */
vireo_result_t vireo_tcp_server_create_with_auxiliary_ops(
    vireo_tcp_server_options_t const *options, size_t auxiliary_capacity,
    vireo_tcp_server_ops_t const *ops, vireo_tcp_server_t **out_server,
    vireo_tcp_server_error_t *error);

/** 本层监听依赖表，完整按值复制；只调用旧模块公共 API，不拥有借用 context。
 *  inspect 不改变对象；ADD/MOD/DEL 失败保持状态；forget 仅在 loop 真实消费后调用，
 *  有效此前绑定的对象必须成功；destroy OK/IO 必须真实消费。违约不保证恢复。
 */
typedef struct vireo_tcp_server_listener_ops {
    void *context;
    vireo_result_t (*inspect)(void *, vireo_acceptor_t const *, vireo_acceptor_info_t *);
    vireo_result_t (*attach)(void *, vireo_acceptor_t *, vireo_event_loop_t *, bool,
                            vireo_acceptor_callback_t, void *, vireo_acceptor_loop_error_t *);
    vireo_result_t (*set_read)(void *, vireo_acceptor_t *, bool, vireo_acceptor_loop_error_t *);
    vireo_result_t (*detach)(void *, vireo_acceptor_t *, vireo_acceptor_loop_error_t *);
    vireo_result_t (*forget)(void *, vireo_acceptor_t *);
    vireo_result_t (*destroy)(void *, vireo_acceptor_t **, vireo_acceptor_error_t *);
} vireo_tcp_server_listener_ops_t;

/** 完整双表测试构造；缺项 INVALID_ARGUMENT，其他公共构造/errno 合同相同。 */
vireo_result_t vireo_tcp_server_create_with_all_ops(vireo_tcp_server_options_t const *options,
                                                   vireo_tcp_server_ops_t const *ops,
                                                   vireo_tcp_server_listener_ops_t const *listener_ops,
                                                   vireo_tcp_server_t **out_server,
                                                   vireo_tcp_server_error_t *error);

/** 本层完整逐对象客户表：只调用旧模块 public API，失败保持/消费沿原合同。
 *  context 借用至 destroy，表按值复制；运行/接入回调不由 wrapper 偷偷执行。
 *  close_fd 仅0或-1，destroy/release OK/IO真实消费，不能伪造 owner；违约不保证恢复。
 */
typedef struct vireo_tcp_server_client_ops {
    void *context;
    vireo_result_t (*accept)(void *, vireo_acceptor_t *, vireo_acceptor_accept_budget_t const *,
                             int *, size_t, vireo_acceptor_accept_info_t *, vireo_acceptor_error_t *);
    vireo_result_t (*create)(void *, vireo_connection_options_t const *, int *, vireo_connection_t **,
                             vireo_connection_error_t *);
    vireo_result_t (*inspect)(void *, vireo_connection_t const *, vireo_connection_info_t *);
    vireo_result_t (*adopt)(void *, vireo_connection_pool_t *, vireo_connection_t **,
                            vireo_connection_pool_lease_t *, vireo_connection_pool_operation_error_t *);
    vireo_result_t (*lookup)(void *, vireo_connection_pool_t const *, vireo_connection_pool_lease_t,
                             vireo_connection_t **);
    vireo_result_t (*attach)(void *, vireo_connection_t *, vireo_event_loop_t *, uint32_t,
                             vireo_connection_callback_t, void *, vireo_connection_loop_error_t *);
    vireo_result_t (*detach)(void *, vireo_connection_t *, vireo_connection_loop_error_t *);
    vireo_result_t (*release)(void *, vireo_connection_pool_t *, vireo_connection_pool_lease_t *,
                              vireo_connection_pool_operation_error_t *);
    vireo_result_t (*destroy)(void *, vireo_connection_t **, vireo_connection_error_t *);
    int (*close_fd)(void *, int);
    vireo_result_t (*receive)(void *, vireo_connection_t *, vireo_connection_receive_budget_t const *,
                               vireo_connection_receive_info_t *, vireo_connection_error_t *);
    vireo_result_t (*read_peek)(void *, vireo_connection_t const *, uint8_t const **, size_t *);
    vireo_result_t (*read_consume)(void *, vireo_connection_t *, size_t);
    vireo_result_t (*write_enqueue)(void *, vireo_connection_t *, uint8_t const *, size_t,
                                     vireo_connection_error_t *);
    vireo_result_t (*send)(void *, vireo_connection_t *, vireo_connection_send_budget_t const *,
                            vireo_connection_send_info_t *, vireo_connection_error_t *);
    vireo_result_t (*frames_peek)(void *, vireo_connection_t const *,
        vireo_connection_frame_options_t const *, vireo_connection_frame_budget_t const *,
        vireo_connection_frame_view_t *, size_t, vireo_connection_frame_info_t *,
        vireo_connection_frame_error_t *);
    vireo_result_t (*set_interests)(void *, vireo_connection_t *,
        uint32_t, vireo_connection_loop_error_t *);
    vireo_result_t (*flow_configure)(void *, vireo_connection_t *,
        vireo_connection_flow_options_t const *, vireo_connection_loop_error_t *);
    vireo_result_t (*flow_refresh)(void *, vireo_connection_t *,
        vireo_connection_loop_error_t *);
    vireo_result_t (*flow_disable)(void *, vireo_connection_t *,
        vireo_connection_loop_error_t *);
    vireo_result_t (*request_close)(void *, vireo_connection_t *,
        vireo_connection_close_mode_t, vireo_connection_close_reason_t,
        vireo_connection_loop_error_t *);
    vireo_result_t (*close_refresh)(void *, vireo_connection_t *,
        vireo_connection_loop_error_t *);
} vireo_tcp_server_client_ops_t;

/** 测试构造：三表完整按值复制；NULL base/listener 表选系统表，client 表必须完整。 */
vireo_result_t vireo_tcp_server_create_with_client_ops(vireo_tcp_server_options_t const *options,
    vireo_tcp_server_ops_t const *base_ops, vireo_tcp_server_listener_ops_t const *listener_ops,
    vireo_tcp_server_client_ops_t const *client_ops, vireo_tcp_server_t **out_server,
    vireo_tcp_server_error_t *error);

/** 只供本模块测试的单次公开等待桥接；成功沿真实通知/统计，失败不得先执行通知。
 * 完整按值保存，context 借用至 destroy；不暴露旧模块 private backend。 */
typedef struct vireo_tcp_server_scheduler_ops {
    void *context;
    vireo_result_t (*run_once)(void *, vireo_event_loop_t *, int,
        vireo_event_loop_run_info_t *, vireo_event_loop_error_t *);
} vireo_tcp_server_scheduler_ops_t;

/** 独立等待 seam 构造；NULL 旧表选系统桥接，scheduler 必需完整，其他沿公共 create。 */
vireo_result_t vireo_tcp_server_create_with_scheduler_ops(vireo_tcp_server_options_t const *,
    vireo_tcp_server_ops_t const *, vireo_tcp_server_listener_ops_t const *,
    vireo_tcp_server_client_ops_t const *, vireo_tcp_server_scheduler_ops_t const *,
    vireo_tcp_server_t **, vireo_tcp_server_error_t *);

/** 本层停止桥接表，发布后不可变；context须支持并发调用并活至全部请求者结束。
 * 只桥接公开loop，不读旧private；测试错误必须先真实提交意图，不能伪造消费。
 */
typedef struct vireo_tcp_server_stop_ops {
    void *context;
    vireo_result_t (*request_stop)(void *, vireo_event_loop_t *, vireo_event_loop_error_t *);
} vireo_tcp_server_stop_ops_t;

/** 独立停止seam构造，旧表NULL选系统；scheduler/stop完整按值保存。 */
vireo_result_t vireo_tcp_server_create_with_run_ops(vireo_tcp_server_options_t const *,
    vireo_tcp_server_ops_t const *, vireo_tcp_server_listener_ops_t const *,
    vireo_tcp_server_client_ops_t const *, vireo_tcp_server_scheduler_ops_t const *,
    vireo_tcp_server_stop_ops_t const *, vireo_tcp_server_t **, vireo_tcp_server_error_t *);

/** 自有测试的队列尝试前故障门，仅本server模块；OK后仍执行真实queue_append。
 * 无状态长期保存或生产backend合同，不授予下游布局/句柄或并发权。
 */
typedef vireo_result_t (*vireo_tcp_server_close_queue_gate_t)(void *context,
    vireo_tcp_server_t *server, vireo_connection_pool_lease_t lease);
vireo_result_t vireo_tcp_server_close_batch_with_gate(vireo_tcp_server_t *server,
    vireo_connection_close_mode_t mode, vireo_tcp_server_close_batch_budget_t const *budget,
    vireo_tcp_server_close_batch_result_t *out_results, size_t result_capacity,
    vireo_tcp_server_close_batch_info_t *out_info, vireo_tcp_server_close_batch_error_t *error,
    vireo_tcp_server_close_queue_gate_t gate, void *gate_context);

/** 本核心单次辅助操作seam；只调用公开loop，context仅借至该操作返回。
 *  ADD/DEL失败须保资源与handle，inspect只读；成功须真实取得/消费登记。
 *  不持久保存表，不授予下游私有loop/布局访问，不把模型原因当内核故障。 */
typedef struct vireo_tcp_server_auxiliary_ops {
    void *context;
    vireo_result_t (*inspect)(void *, vireo_event_loop_t const *, vireo_event_loop_handle_t,
        vireo_event_loop_registration_t *);
    vireo_result_t (*add)(void *, vireo_event_loop_t *, vireo_event_loop_registration_t const *,
        vireo_event_loop_handle_t *, vireo_event_loop_error_t *);
    vireo_result_t (*del)(void *, vireo_event_loop_t *, vireo_event_loop_handle_t *,
        vireo_event_loop_error_t *);
} vireo_tcp_server_auxiliary_ops_t;

/** 仅本核心组合实际辅助容量和公开等待seam；scheduler/context沿原寿命合同。
 * 无下游私有头、用户回调或生产公共扩展，其他沿显式容量create。 */
vireo_result_t vireo_tcp_server_create_with_auxiliary_scheduler_ops(
    vireo_tcp_server_options_t const *, size_t, vireo_tcp_server_scheduler_ops_t const *,
    vireo_tcp_server_t **, vireo_tcp_server_error_t *);

/** 仅本server测试，完整表必需；其他沿公共register/errno合同。 */
vireo_result_t vireo_tcp_server_auxiliary_read_register_with_ops(vireo_tcp_server_t *, int,
    vireo_event_loop_handle_t *, vireo_tcp_server_auxiliary_error_t *,
    vireo_tcp_server_auxiliary_ops_t const *);
/** 仅本server测试，完整表必需；其他沿公共unregister/errno合同。 */
vireo_result_t vireo_tcp_server_auxiliary_read_unregister_with_ops(vireo_tcp_server_t *,
    vireo_event_loop_handle_t *, vireo_tcp_server_auxiliary_error_t *,
    vireo_tcp_server_auxiliary_ops_t const *);

/** 本 server 的取出前故障门，不持久保存；仅模型失败，无损坏布局或内核故障证明。
 * gate 只观察 server/租约/已取数，不改资源，返回非 OK 时不撤销当前待办。
 * NULL 为生产路径，成功仍执行真实 queue_remove；context 仅借到本次返回。 */
typedef vireo_result_t (*vireo_tcp_server_poll_queue_gate_t)(void *context,
    vireo_tcp_server_t const *server, vireo_connection_pool_lease_t client, size_t selected);
vireo_result_t vireo_tcp_server_poll_ready_once_with_gate(vireo_tcp_server_t *server,
    int timeout_ms, size_t max_clients, vireo_tcp_server_ready_client_t *out_clients,
    size_t client_capacity, vireo_tcp_server_poll_report_t *report,
    vireo_tcp_server_poll_queue_gate_t gate, void *context);


/**
 * @brief
 *     本server新监听等待变体的只读取出前故障门，未新增持久hook。
 *
 * @param[in] gate
 *     可空原本核心poll gate，只观察客户/已取数，失败不撤当前待办。
 * @param[in,out] context
 *     可空短借上下文，稳定至返回，不保存或修改外组件私有状态。
 *
 * @return
 *     公共新poll分类及真实前缀；成功wait后gate失败仍保listener事件。
 *
 * @note
 *     其他参数沿新公共入口，完整表/旧依赖寿命沿原合同，保持errno。
 *     只本server测试使用，下游不得包含此头或取得隐藏loop。
 */
vireo_result_t vireo_tcp_server_poll_with_listener_once_with_gate(vireo_tcp_server_t *server,
    int timeout_ms, size_t max_clients, vireo_tcp_server_ready_client_t *out_clients,
    size_t client_capacity, vireo_tcp_server_listener_poll_report_t *report,
    vireo_tcp_server_poll_queue_gate_t gate, void *context);

#endif /* VIREO_NET_TCP_SERVER_INTERNAL_H */
