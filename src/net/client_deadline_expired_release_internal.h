/*
 * PROJECT : VIREO
 * FILE    : client_deadline_expired_release_internal.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-10
 * BRIEF   : 此模块负责：
 * -- 限定本层的当前 READY 客户单次归还及按消费事实清绑定私有布局或测试依赖
 * -- 仅本模块实现及测试使用，不供下游依赖布局
 */
#ifndef VIREO_NET_CLIENT_DEADLINE_EXPIRED_RELEASE_INTERNAL_H
#define VIREO_NET_CLIENT_DEADLINE_EXPIRED_RELEASE_INTERNAL_H

#include <vireo/net/client_deadline.h>

/**
 * @brief 同步执行一次归还依赖，local 客户租约的清零事实表示消费
 *
 * @param[in,out] server
 *     存活 server，同 Reactor 短借。
 * @param[in,out] client
 *     必需局部当前租约，依赖沿公开 release 合同改变／清零。
 * @param[out] error
 *     必需独立完整原诊断，每次发布，不保存地址。
 * @param[in,out] context
 *     可空同步短借，不拥有或保存。
 *
 * @return
 *     原分类，消费和非消费错误须符合公开归还合同；外层恢复入口 errno。
 *
 * @note
 *     native 只用 public release；own test 合成返回不冒实际内核 DEL／close 故障。
 */
typedef vireo_result_t (*vireo_client_deadline_release_fn)(vireo_tcp_server_t *server,
                                                           vireo_connection_pool_lease_t *client,
                                                           vireo_tcp_server_client_error_t *error,
                                                           void *context);

/**
 * @brief 与公开入口共用控制流，只替代本层一次归还依赖
 *
 * @param[in,out] server
 *     同公开入口，全部客户字节借用已结束。
 * @param[in,out] binding
 *     同公开独立关联地址。
 * @param[in] expired
 *     同公开可信历史值，只短借。
 * @param[out] out_report
 *     同公开必需独立报告。
 * @param[in] release_client
 *     必需同步依赖，NULL 基本 INVALID，不保存函数地址。
 * @param[in,out] context
 *     可空同步短借，不拥有／保存。
 *
 * @return
 *     同公开原分类和消费规则，全部路径入口 errno 保持。
 *
 * @note
 *     不是新的公共业务 callback 或资源所有者；不绕过原 READY／身份检查。
 */
vireo_result_t vireo_client_deadline_release_ready_expired_runtime(
    vireo_tcp_server_t *server, vireo_client_deadline_binding_t *binding,
    vireo_timer_wheel_expired_t const *expired, vireo_client_deadline_release_report_t *out_report,
    vireo_client_deadline_release_fn release_client, void *context);

#endif /* VIREO_NET_CLIENT_DEADLINE_EXPIRED_RELEASE_INTERNAL_H */
