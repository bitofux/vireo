/*
 * PROJECT : VIREO
 * FILE    : client_deadline_serve_internal.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-10
 * BRIEF   : 此模块负责：
 * -- 限定本层的公开双采样、等待规划、有限服务及有界推进私有布局或测试依赖
 * -- 仅本模块实现及测试使用，不供下游依赖布局
 */
#ifndef VIREO_CLIENT_DEADLINE_SERVE_INTERNAL_H
#define VIREO_CLIENT_DEADLINE_SERVE_INTERNAL_H

#include <vireo/net/client_deadline_serve.h>

/** 仅本次短借的采样依赖；生产入口固定为公开原生 clock。 */
typedef struct vireo_client_deadline_serve_runtime {
    vireo_result_t (*monotonic_now)(vireo_monotonic_ns_t *, vireo_clock_error_t *, void *);
    /**< 遵公开 clock 输出/诊断合同，测试可明确模拟前后失败。 */
    void *context; /**< 可空，只传给本次采样，不保存。 */
} vireo_client_deadline_serve_runtime_t;

/**
 * @brief
 *     同公开编排控制流，仅替换本层采样依赖
 *
 * @param[in,out] server
 *     非空存活 server，仅本次短借，原服务前置、在途和自动模式合同仍适用。
 * @param[in,out] wheel
 *     非空存活且已 prepare 的轮，所属 Reactor 独占，起点与真实采样同域。
 * @param[in] options
 *     非空原服务选项，入口复制；timeout_ms 在本入口为非负毫秒上限，拒绝 -1。
 * @param[in] advance_budget
 *     两个显式正 size_t 上限，均不超过 65536，按值传入且无默认。
 * @param[in,out] wire_workspace
 *     非空原响应工作区，长度和借用沿原服务合同。
 * @param[in] workspace_capacity
 *     原响应工作区字节数，交原服务入口校验。
 * @param[in] handler
 *     非空、有界、非阻塞且正常返回的原同步 handler。
 * @param[in,out] context
 *     可空，仅借到返回，不保存业务指针或请求视图。
 * @param[out] out_turns
 *     非空原客户结果数组，只写原服务的真实前缀。
 * @param[in] turn_capacity
 *     原数组条数，交原服务入口校验。
 * @param[out] out_clients
 *     非空原新客户租约数组，有效入口前缀须逻辑全零，沿原服务合同。
 * @param[in] client_capacity
 *     原数组条数，交原服务入口校验。
 * @param[out] out_report
 *     必需独立可写报告，每路径覆盖逻辑字段；NULL 无法发布时仍拒绝。
 * @param[in] runtime
 *     必需非空短借调用表，monotonic_now 必需；函数和 context 只本次采样使用，不保存。
 *
 * @retval VIREO_OK
 *     原服务及推进成功；可能没有实际等待、没有业务动作或尚未追上轮目标。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址或 handler 为 NULL、上限为负或推进预算为零；基本检查优先。
 * @retval VIREO_RESULT_RANGE
 *     推进预算超硬限；另原样返回依赖范围错误。
 * @retval VIREO_RESULT_NOT_FOUND
 *     轮未 prepare；另原样返回依赖错误。
 * @retval VIREO_RESULT_CANCELLED
 *     轮预先已停止，在采样之前拒绝；也可在服务完成后因轮停止而推进失败。
 * @retval other
 *     clock、planner、serve 或 advance 原失败分类，原诊断和真实进度保留。
 *
 * @note
 *     仅本模块实现／测试可用，模拟失败不是实际内核故障，不向下游公开。
 * @note
 *     顺序固定为轮准备/停止检查、前 clock、plan、serve、后 clock、advance。
 *     原服务配置、容量和入口空租约校验交原服务，可能在采样/规划之后拒绝。
 * @note
 *     阶段与返回结果界定之前成功字段；失败阶段自身的失败输出不作为成功值。
 *     原服务拒绝未发布时 serve_info 保初始化逻辑零，失败但已发布时保真实前缀。
 *     serve_called 不代表实际等待；serve_completed 只代表原 serve 返回 OK。
 * @note
 *     服务失败立即返回，不后采样或推进。后段失败保服务已完成动作和数组前缀。
 *     原服务监听同步、客户 IO、准入及自动归还的副作用不回滚，新客户仍归 server 拥有。
 *     caller 据原统计和诊断处理客户与失败，不自动重试或吞错误；所有路径保持 errno。
 * @note
 *     server 已停止仍沿原合法服务零业务 OK，之后推进未停止轮；不联动停止或清理。
 *     本层不分配、持续运行、领取通知、登记 timer、选择期限或关闭/归还客户。
 * @note
 *     同 server/wheel Reactor-only，地址存活、对齐、独立、不重叠、不指 errno。
 *     handler 可按公开合同登记/取消/重排或 begin 停止轮；不得递归本编排、消费通知、
 *     推进、执行停机 step 或销毁借用轮，同 server 原可变操作在途规则保持。
 *     callback 条数与原等待上限不承诺耗时或硬实时，caller 在返回后处理到期通知。
 */
vireo_result_t vireo_client_deadline_serve_once_runtime(
    vireo_tcp_server_t *server, vireo_timer_wheel_t *wheel,
    vireo_tcp_server_serve_options_t const *options,
    vireo_timer_wheel_advance_budget_t advance_budget, uint8_t *wire_workspace,
    size_t workspace_capacity, vireo_tcp_server_sync_handler_t handler, void *context,
    vireo_tcp_server_turn_result_t *out_turns, size_t turn_capacity,
    vireo_connection_pool_lease_t *out_clients, size_t client_capacity,
    vireo_client_deadline_serve_report_t *out_report,
    vireo_client_deadline_serve_runtime_t const *runtime);

#endif /* VIREO_CLIENT_DEADLINE_SERVE_INTERNAL_H */
