/*
 * PROJECT : VIREO
 * FILE    : async_admission.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-14
 * BRIEF   : 有界接入准备、完整客户前缀与失败恢复责任
 */
#ifndef VIREO_NET_ASYNC_ADMISSION_H
#define VIREO_NET_ASYNC_ADMISSION_H
#include <vireo/net/tcp_server.h>

/** 独立阶段，不改变原server/flow/round枚举。 */
typedef enum vireo_async_admission_stage {
    VIREO_ASYNC_ADMISSION_NONE = 0,
    VIREO_ASYNC_ADMISSION_VALIDATE_OPTIONS = 1,
    VIREO_ASYNC_ADMISSION_CHECK_SERVER = 2,
    VIREO_ASYNC_ADMISSION_ADMIT = 3,
    VIREO_ASYNC_ADMISSION_FLOW = 4,
    VIREO_ASYNC_ADMISSION_SCHEDULE = 5
} vireo_async_admission_stage_t;

/** 已实际尝试准备的每客户值；called区分未调用的逻辑零。 */
typedef struct vireo_async_admission_turn {
    vireo_connection_pool_lease_t client; /**< 原完整新租约，不拥有或保活fd/connection。 */
    bool flow_called; /**< 本次实际尝试一次流控配置，失败项也计入前缀。 */
    vireo_result_t flow_result; /**< 原配置结果，不等客户已排队或已处理请求。 */
    vireo_tcp_server_client_error_t flow_error; /**< 独立原流控主因/清理诊断。 */
    bool schedule_called; /**< 仅flow OK后一次显式排FIFO。 */
    vireo_result_t schedule_result; /**< 原排队结果，不内部重试。 */
    vireo_tcp_server_client_error_t schedule_error; /**< 原排队诊断，不覆盖flow报告。 */
} vireo_async_admission_turn_t;

/** 每可写路径发布真实进度；资源始终server owns，不因报告失效而释放。 */
typedef struct vireo_async_admission_report {
    vireo_async_admission_stage_t stage; /**< 主错步骤；全部OK/基本拒绝NONE。 */
    size_t effective_max_accepts; /**< 双数组容量与max_accepts三者min，基本拒绝0。 */
    bool admit_called; /**< 已实际调用一次原有界admit，即使零次accept。 */
    vireo_result_t admit_result; /**< 原批次结果，仅called时有来源意义。 */
    vireo_tcp_server_admit_info_t admission; /**< 原accepted/admitted/rejected/calls/transient/stop。 */
    vireo_tcp_server_client_error_t admit_error; /**< 原接入及失败当前客户清理诊断。 */
    size_t turn_count; /**< 实际flow尝试数，包含失败当前项，≤admitted。 */
    size_t initialized_count; /**< 本次flow返回OK项数，失败仍可有成功前缀。 */
    size_t scheduled_count; /**< 本次schedule返回OK项数，不等请求/任务处理数。 */
    size_t unprocessed_begin; /**< 等于turn_count；clients此下标至admitted尚未准备。 */
} vireo_async_admission_report_t;

/**
 * @brief
 *     一次有界接入，再逐新客户配置流控并显式排FIFO，保完整前缀/错误后缀。
 *
 * @param[in,out] server
 *     必需存活唯一网络根，原run之外Reactor串行安全点；资源继续由server拥有。
 * @param[in] connection_options
 *     必需原三数值，入口复制；read/write/预算均正，受检合计后按公开上限验证。
 * @param[in] flow_options
 *     必需原五字节水位，入口复制；整帧32..min(read容量,协议整帧上限)。
 * @param[in] budget
 *     必需双正size_t，max_accepts≤65535；syscalls沿原任意正值，无默认。
 * @param[out] clients
 *     独立数值数组，有效min前缀三字段须逻辑零；保存全部admitted租约，包括错误后缀。
 * @param[in] client_capacity
 *     正size_t≤65535，与turn_capacity/max_accepts取min；未写尾保持。
 * @param[out] turns
 *     独立可写数组，只写实际flow尝试前缀；不要求入口零，未写尾保持。
 * @param[in] turn_capacity
 *     正size_t≤65535，不重叠其他地址/资源，不默认扩大批次。
 * @param[out] report
 *     必需独立完整报告，每可写路径发布；失败不能忽略admitted前缀。
 *
 * @retval VIREO_OK
 *     有限准备完成，包括原EAGAIN、名额/额度/批次/调用预算正常停止；未驱动任务。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需NULL/零接入预算或数组容量/有效租约目标非空，数组及资源保持。
 * @retval VIREO_RESULT_RANGE
 *     数量、connection/flow公开范围或互容不足（含零connection数值）；无新accept。
 * @retval VIREO_RESULT_OVERFLOW
 *     read+write不可表示，优先数值上限；其他受检/身份耗尽原错透传。
 * @retval VIREO_RESULT_CANCELLED
 *     前置观察server已停止，不接新客户，不解除永久停止。
 * @retval VIREO_RESULT_BUSY
 *     六有限在途/running或旧自动准入已启用；不自动disable或混合两套策略。
 * @return
 *     inspect/admit/flow/schedule原错透传；执行后保真实资源/前缀，不回滚或重试。
 *
 * @note
 *     基本/数量/有效空租约→受检connection/flow互容→公开server观察→一次admit。
 *     原admit非OK不再配置任何已发布客户；OK后首flow/schedule错停批。
 *     clients[0:admitted)全部仍在server；turns[0:turn_count)含失败当前项，
 *     clients[unprocessed_begin:admitted)尚未准备，caller显式恢复或归还。
 *     flow成功而排队失败仍保flow状态，不自动DEL/close/清租约或忽略未处理客户。
 *
 * @note
 *     返回后caller先为完整新租约建唯一pending/配置记录，再调用033-03轮次。
 *     本项不调用配置provider、不wait/recv/submit/send/消费提示或结果、不自动响应。
 *     不控制监听READ/压力策略，不依历史listener_last_events判断当前就绪。
 *     controller安排接入时机；本层无长期对象/申请，原admit仍会申请connection/buffer。
 *
 * @note
 *     无默认/扩容/内部重试/资源回滚，不承诺硬实时或完全非阻塞。
 *     stop观察非跨线程屏障，晚到停止不抢占已开始批次，保真实进度。
 *     同资源Reactor-only、全调用禁POSIX取消；所有地址有效独立对齐不重叠。
 *     不存指针或借出loop/connection owner；全部受控路径保持入口errno。
 */
vireo_result_t vireo_async_admission_once(vireo_tcp_server_t *server,
    vireo_connection_options_t const *connection_options, vireo_connection_flow_options_t const *flow_options,
    vireo_tcp_server_admit_budget_t const *budget, vireo_connection_pool_lease_t *clients, size_t client_capacity,
    vireo_async_admission_turn_t *turns, size_t turn_capacity, vireo_async_admission_report_t *report);
#endif /* VIREO_NET_ASYNC_ADMISSION_H */
