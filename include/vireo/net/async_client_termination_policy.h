/*
 * PROJECT : VIREO
 * FILE    : async_client_termination_policy.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-15
 * BRIEF   : 从原异步驱动主错误来源生成只读终止建议
 */
#ifndef VIREO_NET_ASYNC_CLIENT_TERMINATION_POLICY_H
#define VIREO_NET_ASYNC_CLIENT_TERMINATION_POLICY_H
#include <vireo/net/async_client_drive.h>

/** 纯数值建议，不拥有资源，也不证明客户当前性或可安全重试。 */
typedef struct vireo_async_client_termination_plan {
    bool terminate_recommended; /**< 严格主来源匹配才true，false仅表示本规则不建议自动终止。 */
    vireo_connection_close_reason_t reason; /**< false为NONE；true仅PROTOCOL或IO，不执行关闭。 */
} vireo_async_client_termination_plan_t;

/**
 * @brief
 *     读取同次异步驱动的主返回及报告，生成有限的终止建议。
 *
 * @param[in] drive_result
 *     同一次driver的原返回，仅接受当前13个公开result注册值。
 * @param[in] drive_report
 *     必需、真实同次且未篡改的原报告，driver stage须为原0～10注册值。
 * @param[out] out_plan
 *     必需独立输出，成功一次覆盖两个逻辑字段；失败保持整个输出。
 *
 * @retval VIREO_OK
 *     分类完成，不代表原驱动成功、客户健康或已经执行终止。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需NULL、未知result或未知driver阶段；不认证全部报告字段一致性。
 *
 * @note
 *     主PROTOCOL且PEEK_FRAME/frame_peek_called/server FRAMES_PEEK匹配，建议PROTOCOL。
 *     主IO且RECEIVE/receive_called/server RECEIVE/connection RECEIVE匹配，
 *     或SEND/send_called/server SEND/connection SEND匹配，并且原socket errno为正且非EINTR，建议IO。
 *     只看主client_error，不从入口errno、末刷新次错或旧事件位推断socket故障。
 * @note
 *     其他合法输入成功输出false/NONE，包括EOF、EINTR、提交/刷新错误、满或锁竞争，
 *     以及来源字段不满足全部条件。false不授予重试、继续业务或零副作用保证。
 *     caller保证同项来源；本入口不重新核客户、解析codec issue或认证所有19字段。
 * @note
 *     不保存输入指针、不采样、申请、I/O、关闭、清退或操作任何资源；只短借至返回。
 *     caller采纳建议时在原Reactor安全点显式调用033-12，保存原驱动及终止各自进度。
 *     EOF优雅结束、自动服务接线、pending/残留资源和全停机不在本项。
 * @note
 *     输入/输出有效独立对齐，不重叠彼此或errno存储；仅保证逻辑字段，不冻结padding/ABI。
 *     不读取或修改errno，所有路径保持入口值。独立输出纯值thread-safe，
 *     共享存储及跨线程发布由caller同步，不扩大server/store的Reactor权限。
 */
vireo_result_t vireo_async_client_termination_classify(vireo_result_t drive_result,
    vireo_async_client_drive_report_t const *drive_report, vireo_async_client_termination_plan_t *out_plan);
#endif /* VIREO_NET_ASYNC_CLIENT_TERMINATION_POLICY_H */
