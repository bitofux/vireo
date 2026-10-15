/*
 * PROJECT : VIREO
 * FILE    : async_pending_recovery.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-15
 * BRIEF   : pending消费后的流控与排队，显式阶段续接
 */
#ifndef VIREO_NET_ASYNC_PENDING_RECOVERY_H
#define VIREO_NET_ASYNC_PENDING_RECOVERY_H
#include <vireo/net/async_request_head.h>

/** 仅1～3可输入；NONE/DONE仅表示报告未验证/全部完成，不自动回绕。 */
typedef enum vireo_async_pending_recovery_step {
    VIREO_ASYNC_PENDING_STEP_NONE = 0,
    VIREO_ASYNC_PENDING_STEP_CONSUME = 1,
    VIREO_ASYNC_PENDING_STEP_REFRESH = 2,
    VIREO_ASYNC_PENDING_STEP_SCHEDULE = 3,
    VIREO_ASYNC_PENDING_STEP_DONE = 4
} vireo_async_pending_recovery_step_t;
/** 本层独立诊断阶段，不改变原head/server阶段。 */
typedef enum vireo_async_pending_recovery_stage {
    VIREO_ASYNC_PENDING_RECOVERY_NONE = 0,
    VIREO_ASYNC_PENDING_RECOVERY_CHECK_PENDING = 1,
    VIREO_ASYNC_PENDING_RECOVERY_CONSUME = 2,
    VIREO_ASYNC_PENDING_RECOVERY_REFRESH = 3,
    VIREO_ASYNC_PENDING_RECOVERY_SCHEDULE = 4
} vireo_async_pending_recovery_stage_t;
/** 每可写路径完整发布的真实进度，不拥有资源，不认证caller阶段历史。 */
typedef struct vireo_async_pending_recovery_report {
    vireo_async_pending_recovery_stage_t stage; /**< 主错阶段，成功/基本拒绝NONE。 */
    vireo_async_pending_recovery_step_t next_step; /**< 纯校验通过后指尚未成功阶段，成功DONE。 */
    vireo_connection_pool_lease_t client; /**< 纯校验通过后保原完整身份，清pending后仍可续接。 */
    bool consume_called; /**< 是否实际调用一次原resume_consume。 */
    vireo_result_t consume_result; /**< consume_called时原返回，未调用逻辑零。 */
    vireo_async_request_head_report_t consume_report; /**< 原16字段/消费前快照，不虚报新peek/submit。 */
    bool refresh_called; /**< 是否实际一次原flow刷新。 */
    vireo_result_t refresh_result; /**< refresh_called时原返回，未调用逻辑零。 */
    vireo_tcp_server_client_error_t refresh_error; /**< 原flow独立诊断，不覆盖consume报告。 */
    bool schedule_called; /**< 是否实际一次原去重FIFO排队。 */
    vireo_result_t schedule_result; /**< schedule_called时原返回，未调用逻辑零。 */
    vireo_tcp_server_client_error_t schedule_error; /**< 原schedule独立诊断。 */
} vireo_async_pending_recovery_report_t;

/**
 * @brief
 *     从caller明确起点执行原消费→flow刷新→排队，首错停并保存下一步。
 *
 * @param[in,out] server
 *     必需存活root，原run外Reactor串行安全点，不额外inspect或接管资源。
 * @param[in] client
 *     原完整租约，非空pool_id/generation须非零，slot0合法；caller保历史来源。
 * @param[in,out] pending
 *     必需每完整客户唯一记录；CONSUME有效非空且关联匹配，后两起点须逻辑空。
 * @param[in] resume_from
 *     仅CONSUME/REFRESH/SCHEDULE；caller保证前阶段已经真正完成，不能跳过义务。
 * @param[out] report
 *     必需独立输出，每可写路径发布；跨次保client/next，不以空记录认证历史。
 *
 * @retval VIREO_OK
 *     经过阶段均成功，stage NONE/next DONE；不保证任务执行或响应完成。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需NULL/非法起点/畸形client或pending/非空pending关联与client不一致。
 * @retval VIREO_RESULT_NOT_FOUND
 *     全零client或CONSUME空pending；原旧身份/未绑定/未flow等也透传。
 * @retval VIREO_RESULT_BUSY
 *     REFRESH/SCHEDULE遇有效非空pending；其他在途或closing沿原依赖。
 *
 * @return
 *     原依赖错误及诊断透传；首错不调用后段，next停未成功阶段。
 *
 * @note
 *     顺序为基本、client数值、pending公开形态、非空关联、起点资格，再调用资源。
 *     纯校验失败next NONE/client零；基本stage NONE，其他纯错CHECK_PENDING。
 *     合法非空pending须有效公开metadata及32..16777248帧长，deadline0/MAX有限不筛选。
 * @note
 *     消费前结束旧读借用，原输入须未另行receive/consume/release/改写；原resume成功
 *     清pending后，不因flow/schedule错误填回。REFRESH/SCHEDULE跳过已成功阶段，不能重消费。
 *     不查task/inflight当前性，不发号/构造/提交，不重投/回滚/自动清理或内部重试。
 * @note
 *     原closing/stop可consume，closing后flow可BUSY，未绑定/flow可NOT_FOUND，均保真实前缀。
 *     关闭策略caller另行处理，不恢复OPEN或已停止loop，不忙重试；旧身份NOT_FOUND不当成功。
 * @note
 *     每经过阶段最多1次公开调用；本层无申请/owner/持久cursor/callback/运行锁，不承诺硬实时。
 *     全调用禁POSIX取消，同资源Reactor串行，输入/report/errno独立有效对齐不重叠。
 *     所有路径保持入口errno；残留task/completion、新客户准备、取消及完整停机均另行处理。
 */
vireo_result_t vireo_async_client_resume_pending(vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, vireo_async_request_pending_t *pending,
    vireo_async_pending_recovery_step_t resume_from, vireo_async_pending_recovery_report_t *report);
#endif /* VIREO_NET_ASYNC_PENDING_RECOVERY_H */
