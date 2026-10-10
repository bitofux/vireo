/*
 * PROJECT : VIREO
 * FILE    : client_deadline_expired_close_internal.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-10
 * BRIEF   : 此模块负责：
 * -- 限定本层的历史到期匹配后显式单次关闭并保留部分失败诊断私有布局或测试依赖
 * -- 仅本模块实现及测试使用，不供下游依赖布局
 */
#ifndef VIREO_NET_CLIENT_DEADLINE_EXPIRED_CLOSE_INTERNAL_H
#define VIREO_NET_CLIENT_DEADLINE_EXPIRED_CLOSE_INTERNAL_H

#include <vireo/net/client_deadline.h>

/**
 * @brief 同步执行一次关闭依赖，不拥有或保存参数
 *
 * @param[in,out] server
 *     当前客户所属存活 server，同 Reactor 短借到返回。
 * @param[in] client
 *     已由原历史检查核验的当前完整租约，依赖仍沿公开在途保护。
 * @param[in] mode
 *     已校验的 DRAIN／IMMEDIATE。
 * @param[in] reason
 *     已校验的既有非 NONE 理由。
 * @param[out] error
 *     必需独立诊断，每次完整发布逻辑字段；不保存地址。
 * @param[in,out] context
 *     可空同步短借 context，正常返回，不长期保存或任意改变资源生命周期。
 *
 * @return
 *     依赖原分类；可改变 errno，由外层恢复。
 *
 * @note
 *     native 仅调 public client_request_close；own test 明确区分模拟失败与真实 MOD。
 */
typedef vireo_result_t (*vireo_client_deadline_close_fn)(vireo_tcp_server_t *server,
                                                         vireo_connection_pool_lease_t client,
                                                         vireo_connection_close_mode_t mode,
                                                         vireo_connection_close_reason_t reason,
                                                         vireo_tcp_server_client_error_t *error,
                                                         void *context);

/**
 * @brief 与公开入口共用控制流，仅替换一次本层关闭依赖
 *
 * @param[in,out] server
 *     同公开入口，短借且不拥有。
 * @param[in] binding
 *     同公开普通完整值。
 * @param[in] expired
 *     同公开真实历史值，只借到返回。
 * @param[in] mode
 *     同公开显式关闭模式。
 * @param[in] reason
 *     同公开显式既有理由。
 * @param[out] out_error
 *     同公开可空独立诊断，每路径覆盖。
 * @param[in] close_client
 *     必需同步依赖，NULL 基本 INVALID，不保存函数地址。
 * @param[in,out] context
 *     可空短借，不保存、不拥有。
 *
 * @return
 *     同公开分类／部分状态，依赖原样返回；所有路径入口 errno 保持。
 *
 * @note
 *     只本层源／测试可用，不是新的公共业务 callback 或 owned 资源合同。
 */
vireo_result_t vireo_client_deadline_request_close_expired_runtime(
    vireo_tcp_server_t *server, vireo_client_deadline_binding_t binding,
    vireo_timer_wheel_expired_t const *expired, vireo_connection_close_mode_t mode,
    vireo_connection_close_reason_t reason, vireo_client_deadline_close_error_t *out_error,
    vireo_client_deadline_close_fn close_client, void *context);

#endif /* VIREO_NET_CLIENT_DEADLINE_EXPIRED_CLOSE_INTERNAL_H */
