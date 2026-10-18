/* 有界TLS异步服务；一次等待、两个前缀和不可逆提交。 */
#ifndef VIREO_NET_ASYNC_SERVICE_TLS_H
#define VIREO_NET_ASYNC_SERVICE_TLS_H
#include <vireo/net/async_round_tls.h>
#include <vireo/net/completion_response_dispatch_tls.h>

/** 本组合独立阶段，沿真实首次失败解释嵌套报告。 */
typedef enum vireo_async_service_tls_stage {
    VIREO_ASYNC_SERVICE_TLS_NONE = 0,
    VIREO_ASYNC_SERVICE_TLS_VALIDATE,
    VIREO_ASYNC_SERVICE_TLS_CHECK_SERVER,
    VIREO_ASYNC_SERVICE_TLS_PRE_PRESSURE,
    VIREO_ASYNC_SERVICE_TLS_POLL,
    VIREO_ASYNC_SERVICE_TLS_LISTENER_EVENT,
    VIREO_ASYNC_SERVICE_TLS_DISPATCH,
    VIREO_ASYNC_SERVICE_TLS_CLIENTS,
    VIREO_ASYNC_SERVICE_TLS_CHECK_ADMISSION,
    VIREO_ASYNC_SERVICE_TLS_ADMIT,
    VIREO_ASYNC_SERVICE_TLS_POST_PRESSURE
} vireo_async_service_tls_stage_t;

/** caller显式值副本，无默认/扩容或额外预算。 */
typedef struct vireo_async_service_tls_options {
    vireo_async_round_tls_options_t round; /**< 非负timeout、正客户上限和关闭稳定字节预算。 */
    vireo_tcp_server_admit_budget_t admit; /**< 正accept/syscall双预算，数量最多65535。 */
    size_t max_completion_items; /**< 正领取尝试上限，最多65536。 */
    size_t max_response_frame_bytes; /**< 整帧上限32..16777248字节。 */
    size_t max_response_batch_bytes; /**< 正批次上限≤64MiB且≥单帧上限。 */
} vireo_async_service_tls_options_t;

/** 独立caller工作区，仅借至返回，未写尾保持。 */
typedef struct vireo_async_service_tls_workspace {
    vireo_tcp_server_ready_client_t *ready; /**< 本poll已撤取全部前缀，错误也保留。 */
    size_t ready_capacity; /**< 正元素数≤65535，与max_clients/turn_capacity取min。 */
    vireo_async_round_tls_turn_t *turns; /**< 实际客户尝试前缀，含首失败项。 */
    size_t turn_capacity; /**< 正元素数≤65535。 */
    vireo_connection_pool_lease_t *clients; /**< 全部新租约；min容量/accept预算的潜在前缀入口全零。 */
    size_t client_capacity; /**< 正元素数≤65535，限制新接入，不扩大原accept调用预算。 */
    uint8_t *response_bytes; /**< 可写独立编码scratch，失败允许修改，不转移owner。 */
    size_t response_capacity; /**< 字节容量，至少max_response_frame_bytes。 */
} vireo_async_service_tls_workspace_t;

/** 每可写路径发布；called区分未运行零值和实际运行。 */
typedef struct vireo_async_service_tls_report {
    vireo_async_service_tls_stage_t stage; /**< 首主错阶段；成功/基本拒绝NONE。 */
    vireo_tcp_server_tls_error_t validation_error; /**< pre之前TLS根验证原因。 */
    bool entry_checked; /**< 已尝试入口server/stop观察。 */
    bool stopped; /**< 入口、poll或接入前观察到永久停止；非跨线程屏障。 */
    size_t effective_max_clients; /**< 一次poll冻结K，三个上限取min。 */
    bool pre_pressure_called; /**< 已尝试前容量刷新，不表示真实MOD。 */
    vireo_tcp_server_tls_admission_info_t pre_pressure; /**< 原三容量与实际READ。 */
    vireo_tcp_server_listener_error_t pre_pressure_error; /**< 原前刷新MOD原因。 */
    bool poll_called; /**< 实际一次TLS期限感知poll尝试。 */
    vireo_tcp_server_tls_poll_report_t poll; /**< 本wait监听位/时间/due/完整selected及剩余Q。 */
    vireo_tcp_server_tls_error_t poll_error; /**< 原poll主次原因，selected可能已发布。 */
    bool dispatch_called; /**< 实际一次旧完成分发尝试。 */
    vireo_completion_response_dispatch_tls_report_t dispatch; /**< 原消费/入队/续通知完整前缀。 */
    bool clients_called; /**< 实际处理冻结批次，零项也可能调用。 */
    vireo_async_round_tls_report_t clients; /**< 仅处理批次的报告，无第二次poll；失败后缀看此处。 */
    bool admission_checked; /**< 客户成功后、仅本wait READ时已尝试第二次stop观察。 */
    bool admission_called; /**< 实际一次有限TLS接入尝试，不保证accept。 */
    vireo_tcp_server_tls_admit_info_t admission; /**< 完整accepted/admitted/rejected前缀和额度停止。 */
    vireo_tcp_server_tls_error_t admission_error; /**< 原接入主因/首清理错。 */
    bool post_pressure_called; /**< 前刷新成功后受控退出恰一次末刷新。 */
    vireo_result_t post_pressure_result; /**< 独立末错，仅此前OK才成为主错。 */
    vireo_tcp_server_tls_admission_info_t post_pressure; /**< 原末刷新实际三容量/READ。 */
    vireo_tcp_server_listener_error_t post_pressure_error; /**< 原末刷新完整原因，不覆盖业务主因。 */
} vireo_async_service_tls_report_t;

/**
 * @brief 前压力→一次TLS poll→监听检查→已有完成→冻结客户→READ准入→末压力
 * @param[in,out] server 必需存活TLS根、已绑定listener，原run外同Reactor串行安全点。
 * @param[in,out] store 必需存活在途表，原身份登记/结束不可逆。
 * @param[in,out] pool 必需存活worker池，caller串行管理；worker只持独立task。
 * @param[in,out] notifier 必需对应提示源，producer可依原合同并发notify。
 * @param[in,out] queue 必需对应完成队列，本Reactor唯一consumer。
 * @param[in] expected_handle 完整未篡改辅助身份，caller保证对应server/notifier/queue。
 * @param[in] options 必需五字段显式预算，入口值复制，TLS根固定FIFO配置保持。
 * @param[in,out] workspace 必需八字段独立数组/scratch描述，入口值复制，不保存地址。
 * @param[in] configure 必需原TLS有界配置callback，仅应用客户调用，pending按完整租约唯一。
 * @param[in,out] configure_context 可空短借；所给pending/cancel活到对应driver返回。
 * @param[in] resolve 必需原有界描述callback，只写descriptor/自身context，不操作借用资源。
 * @param[in,out] resolve_context 可空短借；caller提供此前已保存的原请求关联。
 * @param[out] remaining_task 必需独占入口NULL；失败未移交task归caller。
 * @param[out] remaining_completion 必需独占入口NULL；失败未销毁completion归caller。
 * @param[out] report 必需独立报告，每条可写路径完整发布，保主次错及真实前缀。
 * @retval VIREO_OK 一次有限服务完成，不证明worker/响应均已完成，新客户下轮才握手。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 必需NULL/空callback/负等待/零数量或预算/非空owner、有效新租约或半空handle。
 * @retval VIREO_RESULT_RANGE 数量/关闭稳定预算/响应额度或scratch不兼容，未poll/消费/accept。
 * @retval VIREO_RESULT_NOT_FOUND 全零handle、缺listener/当前租约或原资源缺失。
 * @retval VIREO_RESULT_BUSY RAW根/同根在途，或原pending/worker/队列有限拒绝。
 * @retval VIREO_RESULT_CANCELLED 入口或poll/接入前观察到停止；晚stop沿原阶段保真实进度。
 * @retval VIREO_RESULT_TIMEOUT 原握手/关闭到期，未自动归还客户。
 * @retval VIREO_RESULT_IO 本wait监听ERROR/HANGUP优先停止分发/客户/准入，或原依赖IO失败。
 * @retval VIREO_RESULT_INTERNAL 异常监听位/selected越界，或原依赖不变量破坏。
 * @return 其他公开依赖/配置/描述原错透传，无内部重试。
 * @note 所有纯数值/owner/潜在空租约及TLS稳定预算在任何MOD/wait/消费前验证；
 *     入口stop不MOD/poll。pre失败不post；pre成功后受控退出恰一次post，首主因优先。
 *     一次poll撤取最多K=min(max_clients,ready_capacity,turn_capacity)。失败保全部selected；
 *     未调用clients时整个selected由caller接管，否则失败项及unprocessed_begin后缀由caller恢复。
 *     FIFO remaining_count不含已取后缀。新admitted全在server，caller先建立每租约pending再下轮。
 * @note 完成分发先于新task，caller在返回后保存每个移交header/metadata再下轮resolve；
 *     握手建立仅排下轮，应用单帧/关闭单步，不在同轮重驱动。已移交/消费不得重投，
 *     已结束inflight不得重消费，已入队响应即使刷新错也不得重复enqueue，只补刷新/发送。
 *     失败双残留owner及真实selected/admitted前缀均需caller处置；本层不销毁/回滚。
 * @note 无整轮锁/长期状态；所有callback有界正常返回，不递归/poll/accept/release或销毁借用资源。
 *     禁POSIX取消；地址独立稳定有效对齐不重叠，保持入口errno。TLS观察清线程库错误队列。
 *     不自动业务期限/cancel、关闭请求/尾部消费/release、DRAIN或join；不承诺硬实时。
 */
vireo_result_t vireo_async_service_tls_once(vireo_tcp_server_t *server,vireo_inflight_store_t *store,
    vireo_thread_pool_t *pool,vireo_notifier_t *notifier,vireo_completion_queue_t *queue,
    vireo_event_loop_handle_t expected_handle,vireo_async_service_tls_options_t const *options,
    vireo_async_service_tls_workspace_t const *workspace,vireo_async_round_tls_configure_fn configure,
    void *configure_context,vireo_completion_response_resolve_fn resolve,void *resolve_context,
    vireo_task_t **remaining_task,vireo_completion_t **remaining_completion,vireo_async_service_tls_report_t *report);
#endif /* VIREO_NET_ASYNC_SERVICE_TLS_H */
