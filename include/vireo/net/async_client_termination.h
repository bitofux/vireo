/*
 * PROJECT : VIREO
 * FILE    : async_client_termination.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-15
 * BRIEF   : 显式客户终止与有界历史登记清退
 */
#ifndef VIREO_NET_ASYNC_CLIENT_TERMINATION_H
#define VIREO_NET_ASYNC_CLIENT_TERMINATION_H
#include <vireo/net/inflight_client_cleanup.h>

/** 独立恢复起点，NONE/DONE仅用于报告，不作为输入。 */
typedef enum vireo_async_client_termination_step {
    VIREO_ASYNC_CLIENT_TERMINATION_STEP_NONE = 0, /**< 前置尚未通过，不授权跳步。 */
    VIREO_ASYNC_CLIENT_TERMINATION_STEP_CLOSE = 1, /**< 从永久关闭意图开始。 */
    VIREO_ASYNC_CLIENT_TERMINATION_STEP_RELEASE = 2, /**< 关闭已确认，仅归还及清退。 */
    VIREO_ASYNC_CLIENT_TERMINATION_STEP_CLEANUP = 3, /**< 客户已消费，仅续扫历史登记。 */
    VIREO_ASYNC_CLIENT_TERMINATION_STEP_DONE = 4 /**< 扫至容量，非worker完成通知。 */
} vireo_async_client_termination_step_t;

/** 仅本入口的错误来源，不改变原模块枚举。 */
typedef enum vireo_async_client_termination_stage {
    VIREO_ASYNC_CLIENT_TERMINATION_NONE = 0, /**< 成功或本层基本拒绝。 */
    VIREO_ASYNC_CLIENT_TERMINATION_CHECK_STORE = 1, /**< 表观测或游标范围拒绝。 */
    VIREO_ASYNC_CLIENT_TERMINATION_CLOSE_CLIENT = 2, /**< 关闭意图错误，后段未调用。 */
    VIREO_ASYNC_CLIENT_TERMINATION_RELEASE_CLIENT = 3, /**< 归还错误，结合consumed辨义务。 */
    VIREO_ASYNC_CLIENT_TERMINATION_CLEAN_INFLIGHT = 4 /**< 清退错误，原报告保留槽进度。 */
} vireo_async_client_termination_stage_t;

/** 每可写路径完整发布的本次事实，不拥有或保活任何资源。 */
typedef struct vireo_async_client_termination_report {
    vireo_async_client_termination_stage_t stage; /**< 首错来源，成功为NONE。 */
    vireo_async_client_termination_step_t next_step; /**< 前置通过后有效，DONE不表示worker退出。 */
    vireo_connection_pool_lease_t client; /**< 前置通过后保存原完整历史租约，不是当前性证明。 */
    bool close_called; /**< 本次是否调用关闭意图入口。 */
    vireo_result_t close_result; /**< close_called时有效，不认证整体完成。 */
    bool release_called; /**< 本次是否尝试归还客户。 */
    vireo_result_t release_result; /**< release_called时的原返回，包括消费型IO。 */
    bool client_consumed; /**< 仅本次归还后的局部租约已全零。 */
    vireo_tcp_server_client_error_t client_error; /**< 最后一次网络步骤的原诊断，未调用逻辑零。 */
    bool cleanup_called; /**< 本次是否执行一次有界清退。 */
    vireo_result_t cleanup_result; /**< cleanup_called时的原返回。 */
    vireo_inflight_client_cleanup_report_t cleanup_report; /**< 原槽游标/预算及部分取消、移除进度。 */
} vireo_async_client_termination_report_t;

/**
 * @brief
 *     对caller明确放弃的客户执行关闭、归还及一次有界清退。
 *
 * @param[in,out] server
 *     必需存活资源根，仅Reactor串行安全窗口调用，结束全部本客户借用。
 * @param[in,out] store
 *     必需存活表，不保存server；跨次须使用同表及同一原完整客户身份。
 * @param[in] client
 *     原完整pool/slot/generation按值身份，slot为0合法，不保活、不清外部副本。
 * @param[in] reason
 *     原六个非NONE关闭理由之一；所有起点均校验，首次理由沿原合同保持。
 * @param[in] from
 *     CLOSE、RELEASE或CLEANUP；后两项须有同项已完成前段的真实历史。
 * @param[in] begin_index
 *     CLOSE/RELEASE须为0；CLEANUP为0..store.capacity，不回绕。
 * @param[in] max_slots
 *     正size_t且最多65536，空槽和其他客户槽也计检查预算。
 * @param[out] report
 *     必需独立报告，每可写路径发布，地址有效对齐、不重叠资源或errno存储。
 *
 * @retval VIREO_OK
 *     本次步骤成功；预算用尽仍为OK/next=CLEANUP，扫至容量为DONE。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需NULL、非法起点/理由、零预算、前两起点begin非0或半空客户身份。
 * @retval VIREO_RESULT_NOT_FOUND
 *     全零客户或原网络步骤发现旧身份，不自动当成功或转去清退。
 * @retval VIREO_RESULT_RANGE
 *     max_slots超过65536或begin超过实际表容量；跨域/客户槽范围沿依赖返回。
 * @retval VIREO_RESULT_INTERNAL
 *     依赖不变量异常，不提供损坏对象或违约替身的通用恢复。
 * @return
 *     原公开观测、关闭、归还或清退首错，无内部重试/回滚。
 *
 * @note
 *     顺序：基本地址/枚举/零预算/初始cursor兼容→预算上限→客户形态→
 *     公开表观测/游标范围→指定起点。前置未通过next=NONE/client逻辑零，
 *     观测及游标拒绝可发布CHECK_STORE；未调用的结果零值不是成功证据。
 * @note
 *     CLOSE固定IMMEDIATE，caller明确放弃未发字节及未来响应；不因EOF/HUP/任意IO自动关闭。
 *     关闭MOD失败可已永久提交意图，next仍CLOSE，停止本次后段；重复同步沿原合同。
 *     RELEASE用局部租约，按归还后全零判断消费：即使IO也next=CLEANUP但立即保错返回；
 *     未消费错误留RELEASE，已解绑等真实状态不回滚。合法OK须消费，其他旧租约副本不改写。
 * @note
 *     CLEANUP仅已确认归还的历史身份使用，不额外查询客户；caller不得伪造跳步。
 *     仅一次原028-11扫描，失败槽及已取消/已移除前缀保留，下次用原next_index；
 *     本次未调用清退时从0起。共享cancel影响原共享组，不等worker已观察或退出。
 *     client_consumed只描述本次release，CLEANUP起点的false不表示历史客户仍存活。
 * @note
 *     无新增申请、持久状态或默认；不send/等待、处理pending/残留task/completion/timer，
 *     不消费队列或join/完整停机。caller另行刷新监听压力并处理迟到结果及外部副本。
 *     全调用禁POSIX线程取消，所有路径保持入口errno；动作数预算不保证硬实时。
 */
vireo_result_t vireo_async_client_terminate_once(vireo_tcp_server_t *server,
    vireo_inflight_store_t *store, vireo_connection_pool_lease_t client,
    vireo_connection_close_reason_t reason, vireo_async_client_termination_step_t from,
    size_t begin_index, size_t max_slots, vireo_async_client_termination_report_t *report);
#endif /* VIREO_NET_ASYNC_CLIENT_TERMINATION_H */
