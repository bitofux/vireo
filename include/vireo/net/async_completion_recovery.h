/*
 * PROJECT : VIREO
 * FILE    : async_completion_recovery.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-15
 * BRIEF   : 已入队响应的关注续接与独立完成结果释放
 */
#ifndef VIREO_NET_ASYNC_COMPLETION_RECOVERY_H
#define VIREO_NET_ASYNC_COMPLETION_RECOVERY_H
#include <vireo/net/tcp_server.h>
#include <vireo/thread/completion.h>

/** 仅REFRESH/DESTROY可输入，NONE/DONE仅报告。 */
typedef enum vireo_async_completion_recovery_step {
    VIREO_ASYNC_COMPLETION_STEP_NONE = 0,
    VIREO_ASYNC_COMPLETION_STEP_REFRESH = 1,
    VIREO_ASYNC_COMPLETION_STEP_DESTROY = 2,
    VIREO_ASYNC_COMPLETION_STEP_DONE = 3
} vireo_async_completion_recovery_step_t;

/** 本层独立错误来源，旧server/completion阶段保持。 */
typedef enum vireo_async_completion_recovery_stage {
    VIREO_ASYNC_COMPLETION_RECOVERY_NONE = 0,
    VIREO_ASYNC_COMPLETION_RECOVERY_CHECK_METADATA = 1,
    VIREO_ASYNC_COMPLETION_RECOVERY_INSPECT_COMPLETION = 2,
    VIREO_ASYNC_COMPLETION_RECOVERY_MATCH_COMPLETION = 3,
    VIREO_ASYNC_COMPLETION_RECOVERY_REFRESH = 4,
    VIREO_ASYNC_COMPLETION_RECOVERY_DESTROY = 5
} vireo_async_completion_recovery_stage_t;

/** 每可写路径完整发布，不拥有资源，也不认证caller历史。 */
typedef struct vireo_async_completion_recovery_report {
    vireo_async_completion_recovery_stage_t stage; /**< 主错位置，成功/基本拒绝NONE。 */
    vireo_async_completion_recovery_step_t next_step; /**< 完整匹配后为未成功动作，成功DONE。 */
    vireo_completion_metadata_t metadata; /**< 仅completion_inspected时为实际对象快照。 */
    bool completion_inspected; /**< 本次inspect成功，后续匹配失败仍true。 */
    bool refresh_called; /**< 是否实际一次原flow刷新。 */
    vireo_result_t refresh_result; /**< refresh_called时原返回，未调用逻辑零。 */
    vireo_tcp_server_client_error_t client_error; /**< 本次原flow完整诊断。 */
    bool destroy_called; /**< 是否实际一次原completion_destroy。 */
    vireo_result_t destroy_result; /**< destroy_called时原返回。 */
    bool completion_consumed; /**< destroy调用后owner是否实际清NULL。 */
} vireo_async_completion_recovery_report_t;

/**
 * @brief
 *     核对已入队响应的原结果，显式补刷新并释放独立completion。
 *
 * @param[in,out] server
 *     必需存活资源根，原run外/observer安全窗口Reactor串行，只借至返回。
 * @param[in] expected
 *     同一原结果的完整metadata；含request7值/result/status共9逻辑数值。
 * @param[in,out] completion_owner
 *     必需原独占非空剩余owner，所有操作和借用已结束；成功销毁清NULL。
 * @param[in] resume_from
 *     仅REFRESH/DESTROY；DESTROY须已刷新或caller明确放弃该客户发送恢复。
 * @param[out] report
 *     必需独立可写事实报告，不保活，不重叠owner/输入/资源/errno。
 *
 * @retval VIREO_OK
 *     经过动作均成功，stage NONE/next DONE，不保证已发送或对端收到。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需NULL、非法起点、无效expected或完整快照不相等。
 * @retval VIREO_RESULT_NOT_FOUND
 *     空owner；旧客户/未绑定/未flow等沿原依赖，不自动视为成功。
 *
 * @return
 *     原依赖首错及诊断透传，后段不执行，不内部重试。
 *
 * @note
 *     caller依据同一项未篡改报告确认登记已结束、响应已确认入队及当前owner来源。
 *     聚合入队数/旧last_response/仅metadata相等不能认证当前残留或payload来源。
 *     不能由已移交或已销毁裸指针重造owner；不处理未消费/未入队残留。
 * @note
 *     基本/空owner/expected公开形态→inspect→完整9值匹配，再执行起点动作。
 *     匹配前next NONE；inspect成功即发布实际metadata，匹配后next才为起点。
 *     deadline为有限MONOTONIC纳秒，0/MAX正常值，不采样或筛选；不比较padding。
 * @note
 *     REFRESH从request.route导出完整客户租约，一次flow成功后才destroy。
 *     closing BUSY、旧代NF等保completion；caller先解释，再决定恢复或关闭政策。
 *     DESTROY不lookup客户，但server仍须存活；不丢弃写区或自动关闭。
 *     已停止server的机械刷新不恢复loop分发，不承诺后续发送。
 * @note
 *     原写FIFO已独立复制帧，释放completion不丢已入队字节；本层不编码/enqueue/send/
 *     schedule、consume/take登记、取消或查询store/queue/notifier，不回滚已刷新关注。
 *     合法completion原destroy正常仅OK，无自然销毁失败或损坏同步恢复承诺。
 * @note
 *     每经过动作一次，无本层申请/持久状态/回调/锁，不保证硬实时。
 *     全调用禁POSIX取消，地址独立存活有效对齐，所有受控路径保持入口errno。
 *     next只说明未成功位置，不要求无条件重试；其余资源/发送恢复由caller负责。
 */
vireo_result_t vireo_async_completion_resume_enqueued(vireo_tcp_server_t *server,
    vireo_completion_metadata_t expected, vireo_completion_t **completion_owner,
    vireo_async_completion_recovery_step_t resume_from, vireo_async_completion_recovery_report_t *report);
#endif /* VIREO_NET_ASYNC_COMPLETION_RECOVERY_H */
