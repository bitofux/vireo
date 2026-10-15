/*
 * PROJECT : VIREO
 * FILE    : async_service.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-15
 * BRIEF   : 有界异步服务轮、caller工作区与真实前缀
 */
#ifndef VIREO_NET_ASYNC_SERVICE_H
#define VIREO_NET_ASYNC_SERVICE_H
#include <vireo/net/async_round.h>
#include <vireo/net/async_admission.h>
#include <vireo/net/async_admission_pressure.h>
#include <vireo/net/completion_response_dispatch.h>

/** 本组合独立阶段，所有旧枚举保持。 */
typedef enum vireo_async_service_stage {
    VIREO_ASYNC_SERVICE_NONE = 0,
    VIREO_ASYNC_SERVICE_VALIDATE = 1,
    VIREO_ASYNC_SERVICE_PRE_PRESSURE = 2,
    VIREO_ASYNC_SERVICE_POLL = 3,
    VIREO_ASYNC_SERVICE_LISTENER_EVENT = 4,
    VIREO_ASYNC_SERVICE_DISPATCH = 5,
    VIREO_ASYNC_SERVICE_CLIENTS = 6,
    VIREO_ASYNC_SERVICE_ADMIT = 7,
    VIREO_ASYNC_SERVICE_POST_PRESSURE = 8
} vireo_async_service_stage_t;

/** caller显式预算；入口复制值，不保存地址，无默认或隐式扩容。 */
typedef struct vireo_async_service_options {
    int timeout_ms; /**< 非负等待上限，毫秒；已有待办由poll强制0。 */
    size_t max_clients; /**< 正客户数≤65535，与两个客户数组容量取min。 */
    vireo_connection_options_t connection; /**< 下一批接入三字节选项，受检read+write。 */
    vireo_connection_flow_options_t flow; /**< 下一批五字节水位，沿公开connection互容。 */
    vireo_tcp_server_admit_budget_t admit; /**< 正接入数≤65535，syscall为任意正size_t。 */
    size_t max_completion_items; /**< 正完成领取尝试数≤65536。 */
    size_t max_response_frame_bytes; /**< 整帧上限32..16777248字节。 */
    size_t max_response_batch_bytes; /**< 正批次字节≤64MiB且≥单帧上限，沿030保守条数。 */
} vireo_async_service_options_t;

/** 全部caller持有，仅借至返回；四数组独立有效、不重叠，未写尾保持。 */
typedef struct vireo_async_service_workspace {
    vireo_tcp_server_ready_client_t *ready; /**< 本次全部已取客户前缀，失败也保留。 */
    size_t ready_capacity; /**< 正元素数≤65535，不是字节。 */
    vireo_async_round_turn_t *turns; /**< 实际配置尝试前缀，含失败当前项。 */
    size_t turn_capacity; /**< 正元素数≤65535。 */
    vireo_connection_pool_lease_t *clients; /**< 全部新admitted；有效min前缀入口逻辑零。 */
    size_t client_capacity; /**< 正元素数≤65535，未用尾不检查。 */
    vireo_async_admission_turn_t *admission_turns; /**< 实际新客户准备前缀，可能少于admitted。 */
    size_t admission_turn_capacity; /**< 正元素数≤65535。 */
    uint8_t *response_bytes; /**< 独立可写scratch，失败内容可改，无owner转移。 */
    size_t response_capacity; /**< 字节容量，至少响应单帧上限。 */
} vireo_async_service_workspace_t;

/** 每可写路径发布；按called解释嵌套值，资源owner由独立输出承接。 */
typedef struct vireo_async_service_report {
    vireo_async_service_stage_t stage; /**< 主错阶段，全成功/基本拒绝NONE。 */
    bool pre_pressure_called; /**< 是否尝试入口压力刷新。 */
    vireo_async_admission_pressure_report_t pre_pressure_report; /**< 原真实开关/额度/诊断。 */
    bool poll_called; /**< 是否实际一次同次监听等待。 */
    vireo_tcp_server_listener_poll_report_t poll_report; /**< 原poll前缀和仅本次监听位。 */
    bool dispatch_called; /**< 是否一次已有完成响应分发。 */
    vireo_completion_response_dispatch_report_t dispatch_report; /**< 原真实消费/入队/续通知前缀。 */
    vireo_async_round_report_t clients; /**< 本入口组装的客户进度形状，未调用旧round。 */
    bool admission_called; /**< 是否正常本轮READ后一次有界接入准备。 */
    vireo_async_admission_report_t admission_report; /**< 全部admitted与实际准备/排队前缀。 */
    bool post_pressure_called; /**< pre成功后退出时一次末刷新。 */
    vireo_result_t post_pressure_result; /**< 独立次错；仅此前OK才升为主错。 */
    vireo_async_admission_pressure_report_t post_pressure_report; /**< 原真实末刷新进度/诊断。 */
} vireo_async_service_report_t;

/**
 * @brief
 *     前压力→同次poll→旧完成响应→冻结客户驱动→本轮READ接入→末压力。
 *
 * @param[in,out] server
 *     必需资源根，原run外Reactor串行安全窗口，不保存或保活。
 * @param[in,out] store
 *     必需在途表，真实登记/结束不可回滚。
 * @param[in,out] pool
 *     必需已装配池，管理由caller串行，worker独立执行task。
 * @param[in,out] notifier
 *     必需提示资源，producer可按原合同并发通知。
 * @param[in,out] queue
 *     必需完成队列，本Reactor唯一consumer。
 * @param[in] expected_handle
 *     完整辅助登记身份，caller保证与server/notifier/queue对应。
 * @param[in] options
 *     必需八字段显式预算，入口按值复制。
 * @param[in,out] workspace
 *     必需十字段描述，入口复制描述，不保存四数组/scratch地址。
 * @param[in] configure
 *     原有界非阻塞配置回调；只填配置/自身context，不操作借用资源。
 * @param[in,out] configure_context
 *     可空短借；返回配置的pending须按完整租约唯一且稳定至driver返回。
 * @param[in] resolve
 *     原有界非阻塞wire描述回调；只填描述/自身context，不操作借用资源。
 * @param[in,out] resolve_context
 *     可空短借，caller提供历史原请求关联，不从operation猜wire语义。
 * @param[out] remaining_task
 *     必需独占owner地址，入口NULL，未转移task残留交caller。
 * @param[out] remaining_completion
 *     必需独占owner地址，入口NULL，未销毁completion残留交caller。
 * @param[out] report
 *     必需独立报告，所有可写路径完整发布，含真实失败前缀/次错。
 *
 * @retval VIREO_OK
 *     本轮完成，不证明工作/响应已全部完成；新客户仅后续轮驱动。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需NULL/空回调/负等待/零数量或双接入预算/非空owner或有效新租约目标/半空handle。
 * @retval VIREO_RESULT_RANGE
 *     数量、connection/flow互容、响应范围/批次或scratch不足。
 * @retval VIREO_RESULT_OVERFLOW
 *     受检connection合计不可表示，先于其数值硬限。
 * @retval VIREO_RESULT_NOT_FOUND
 *     全零handle或原资源不存在。
 * @retval VIREO_RESULT_CANCELLED
 *     pre观测停止或poll已停止；后段停止可保已发生进度。
 * @retval VIREO_RESULT_IO
 *     本次listener ERROR/HANGUP（即使READ）优先停止业务，原事件仍保留。
 *
 * @return
 *     其他依赖/回调原错透传；异常监听位INTERNAL，无内部重试。
 *
 * @note
 *     先基本/数量/有效空租约，再connection受检运算/flow/响应范围，最后handle形态。
 *     pre失败不post；pre成功后受控退出恰一次post，主错优先、末错独立。
 *     poll成功但stopped时本组合CANCELLED；停止快照不构成跨线程屏障。
 *     客户报告poll部分来自实际03306，turn_count含失败项，unprocessed_begin给未处理后缀。
 *     caller保存所有ready/admitted身份及失败后缀，处理恢复后才决定下一轮。
 *
 * @note
 *     完成分发先于本轮提交，返回后caller先保存新请求header/metadata再下轮resolve；
 *     本轮无第二次分发。仅成功driver且needs_reschedule时一次排尾，不在本轮重驱动。
 *     已移交task不退款重投；已结束登记/已入队响应不得重消费/重enqueue。
 *     无回滚、重放、自动销毁/关闭/归还/join或完整停机；双残留owner由caller恢复。
 *
 * @note
 *     全调用禁POSIX取消；所有地址/context/数组/owner/report/errno独立有效不重叠。
 *     回调正常返回，不递归服务/消费/驱动、poll/accept/release或销毁借用资源。
 *     本层无长期资源/申请/锁，原task复制/admit仍可能申请，不承诺硬实时或公平。
 *     所有受控路径保持入口errno，不自动实施deadline/cancel或业务命令策略。
 */
vireo_result_t vireo_async_service_once(vireo_tcp_server_t *server, vireo_inflight_store_t *store,
    vireo_thread_pool_t *pool, vireo_notifier_t *notifier, vireo_completion_queue_t *queue,
    vireo_event_loop_handle_t expected_handle, vireo_async_service_options_t const *options,
    vireo_async_service_workspace_t const *workspace, vireo_async_round_configure_fn configure,
    void *configure_context, vireo_completion_response_resolve_fn resolve, void *resolve_context,
    vireo_task_t **remaining_task, vireo_completion_t **remaining_completion, vireo_async_service_report_t *report);
#endif /* VIREO_NET_ASYNC_SERVICE_H */
