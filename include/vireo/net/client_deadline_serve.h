/*
 * PROJECT : VIREO
 * FILE    : client_deadline_serve.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-10
 * BRIEF   : 此模块负责：
 * -- 公开双采样、等待规划、有限服务及有界推进
 * -- 只依赖已采用公开合同，保持资源、输出与 errno 的既有边界
 */
#ifndef VIREO_NET_CLIENT_DEADLINE_SERVE_H
#define VIREO_NET_CLIENT_DEADLINE_SERVE_H

#include <vireo/net/tcp_server.h>
#include <vireo/net/timer_loop.h>
#include <vireo/timer/wheel_advance.h>

/** 本入口独立阶段，不扩展或重排绑定动作的阶段编号。 */
typedef enum vireo_client_deadline_serve_stage {
    VIREO_CLIENT_DEADLINE_SERVE_NONE = 0, /**< 成功或基本参数拒绝，结合返回结果区分。 */
    VIREO_CLIENT_DEADLINE_SERVE_CHECK_WHEEL = 1,  /**< 公开准备或停止观测失败。 */
    VIREO_CLIENT_DEADLINE_SERVE_CLOCK_BEFORE = 2, /**< 服务前采样失败。 */
    VIREO_CLIENT_DEADLINE_SERVE_PLAN_WAIT = 3,    /**< 等待规划失败。 */
    VIREO_CLIENT_DEADLINE_SERVE_SERVICE = 4, /**< 原服务入口返回失败，可能已有进度。 */
    VIREO_CLIENT_DEADLINE_SERVE_CLOCK_AFTER = 5, /**< 服务成功后的采样失败。 */
    VIREO_CLIENT_DEADLINE_SERVE_ADVANCE = 6      /**< 后采样成功，但推进失败。 */
} vireo_client_deadline_serve_stage_t;

/** 每路径发布的独立值报告；未完成字段逻辑零，不承诺 padding 或事务回滚。 */
typedef struct vireo_client_deadline_serve_report {
    vireo_client_deadline_serve_stage_t stage; /**< 当前失败阶段，成功 NONE。 */
    vireo_monotonic_ns_t before_now_ns; /**< 前采样成功的同域 ns，0 仍为有限时间。 */
    vireo_timer_loop_wait_plan_t wait_plan; /**< 原等待计划，不等于实际内核等待时长。 */
    bool serve_called;    /**< 是否调用原 serve；不保证 wait 或没有副作用。 */
    bool serve_completed; /**< 原 serve 是否返回 OK；停止对象也可以为 true。 */
    vireo_tcp_server_serve_info_t serve_info; /**< 原服务已发布的统计及真实客户前缀。 */
    vireo_monotonic_ns_t after_now_ns; /**< 后采样成功的同域 ns，0 无哨兵含义。 */
    vireo_timer_wheel_advance_report_t advance; /**< 推进成功的报告，预算耗尽也可成功。 */
    vireo_clock_error_t clock_error;            /**< 采样失败的原阶段和系统 errno。 */
    vireo_tcp_server_serve_error_t serve_error; /**< 原服务主因及补同步次错诊断。 */
} vireo_client_deadline_serve_report_t;

/**
 * @brief 采样并规划等待，服务一次后再次采样和有界推进
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
vireo_result_t vireo_client_deadline_serve_once(
    vireo_tcp_server_t *server, vireo_timer_wheel_t *wheel,
    vireo_tcp_server_serve_options_t const *options,
    vireo_timer_wheel_advance_budget_t advance_budget, uint8_t *wire_workspace,
    size_t workspace_capacity, vireo_tcp_server_sync_handler_t handler, void *context,
    vireo_tcp_server_turn_result_t *out_turns, size_t turn_capacity,
    vireo_connection_pool_lease_t *out_clients, size_t client_capacity,
    vireo_client_deadline_serve_report_t *out_report);

#endif /* VIREO_NET_CLIENT_DEADLINE_SERVE_H */
