/*
 * PROJECT : VIREO
 * FILE    : async_ready_recovery.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-15
 * BRIEF   : 已取出客户的显式范围、有限重排和真实恢复下标
 */
#ifndef VIREO_NET_ASYNC_READY_RECOVERY_H
#define VIREO_NET_ASYNC_READY_RECOVERY_H
#include <vireo/net/tcp_server.h>

/** 独立恢复阶段，不改变任何旧枚举。 */
typedef enum vireo_async_ready_recovery_stage {
    VIREO_ASYNC_READY_RECOVERY_NONE = 0,
    VIREO_ASYNC_READY_RECOVERY_SCHEDULE = 1
} vireo_async_ready_recovery_stage_t;
/** 本次停止原因；预算正常停止不证明范围已经处理完。 */
typedef enum vireo_async_ready_recovery_stop {
    VIREO_ASYNC_READY_RECOVERY_STOP_NONE = 0,
    VIREO_ASYNC_READY_RECOVERY_COMPLETE = 1,
    VIREO_ASYNC_READY_RECOVERY_BUDGET = 2,
    VIREO_ASYNC_READY_RECOVERY_ERROR = 3
} vireo_async_ready_recovery_stop_t;
/** 所有可写路径完整发布的数值进度；不拥有或保活客户。 */
typedef struct vireo_async_ready_recovery_report {
    vireo_async_ready_recovery_stage_t stage; /**< 依赖失败为SCHEDULE，成功/基本拒绝NONE。 */
    vireo_async_ready_recovery_stop_t stop_reason; /**< COMPLETE/BUDGET/ERROR；基本拒绝NONE。 */
    size_t attempted_count; /**< 实际schedule调用数，包含失败当前项，≤budget。 */
    size_t scheduled_count; /**< 返回OK的调用数，含已有位置，非队列净增长。 */
    size_t next_index; /**< 有效范围后从begin起；仅OK前进，错误停失败项。 */
    vireo_connection_pool_lease_t last_client; /**< 最后一次尝试的完整租约，无尝试逻辑零。 */
    vireo_tcp_server_client_error_t client_error; /**< 最后一次调用原诊断，无尝试逻辑零。 */
} vireo_async_ready_recovery_report_t;

/**
 * @brief
 *     按caller选择的ready后缀，最多预算次公开schedule，首错交还恢复下标。
 *
 * @param[in,out] server
 *     必需存活资源根，原run外Reactor串行安全点，不取得资源所有权。
 * @param[in] ready
 *     稳定只读原ready有效前缀；count非零必需，0可NULL，不保存地址。
 * @param[in] ready_count
 *     实际有效元素数0..65535，不是容量或字节数。
 * @param[in] begin_index
 *     caller明确选择的起点，0..ready_count；失败当前项须先按原进度恢复。
 * @param[in] max_clients
 *     正size_t调用预算≤65535，无默认，按索引最多一次schedule/项。
 * @param[out] report
 *     必需独立报告，每可写路径完整发布，跨次使用next_index需保持原数组语义。
 *
 * @retval VIREO_OK
 *     COMPLETE或BUDGET正常停止；仅安排后续驱动机会，不代表请求执行完成。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需server/report为NULL、count非零配NULL ready，或零预算。
 * @retval VIREO_RESULT_RANGE
 *     count/预算超过65535或begin大于count；原lookup越界也透传。
 *
 * @return
 *     每次公开schedule原错透传，包含旧租约NOT_FOUND，不跳过或当成功。
 *
 * @note
 *     基本/范围拒绝报告逻辑零，输入和资源保持；有效范围next从begin起。
 *     空范围OK/COMPLETE且零尝试，不访问元素或额外inspect。只有OK才增加成功数/next；
 *     到count优先COMPLETE，否则用尽预算BUDGET；首错ERROR、next停失败项，保成功前缀。
 *     原FIFO已有位置重复OK且不移位，scheduled_count不是新增位置数。无内部重试/回滚。
 * @note
 *     只使用完整lease，历史events不重新注入或代表当前就绪；caller保原事件并处理异常。
 *     一般可从原report的unprocessed_begin恢复后缀；失败当前项/已转移task、pending、
 *     已结束登记/已enqueue响应和所有残留owner均由caller先按真实进度处理，不能重放旧轮。
 *     本入口不驱动、提交、读写、刷新、取消、销毁或关闭/join；无运行申请/长期状态。
 * @note
 *     沿原schedule允许closing/暂未绑定及已停止server机械排队，不恢复loop运行；
 *     在途/lookup等沿原依赖错误，不新增inspect/stop拒绝或整段递归检测。
 *     全调用禁POSIX取消，所有输入/report/errno地址独立有效对齐不重叠，所有路径保持errno。
 */
vireo_result_t vireo_async_service_reschedule_ready(vireo_tcp_server_t *server,
    vireo_tcp_server_ready_client_t const *ready, size_t ready_count, size_t begin_index,
    size_t max_clients, vireo_async_ready_recovery_report_t *report);
#endif /* VIREO_NET_ASYNC_READY_RECOVERY_H */
