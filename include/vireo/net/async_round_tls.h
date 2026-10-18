/* 有界TLS异步客户轮；RAW轮次及其报告保持。 */
#ifndef VIREO_NET_ASYNC_ROUND_TLS_H
#define VIREO_NET_ASYNC_ROUND_TLS_H
#include <vireo/net/async_client_drive_tls.h>

/** 一轮数值副本，无默认/隐式扩容。 */
typedef struct vireo_async_round_tls_options {
    int timeout_ms; /**< 非负毫秒；有待办或due时原poll缩短等待。 */
    size_t max_clients; /**< 1..65535，与两个输出数组容量取min。 */
    size_t close_max_bytes; /**< 正关闭单步字节，至少两FIFO最小稳定请求的最大值。 */
} vireo_async_round_tls_options_t;

/** 仅APPLICATION才配置，指针借至对应driver返回，不保存。 */
typedef struct vireo_async_round_tls_config {
    vireo_async_client_drive_options_t options; /**< 原五数值，TLS真实容量规则。 */
    vireo_async_client_drive_tls_budget_t budget; /**< 此客户独立收发native预算。 */
    vireo_task_cancel_t *cancel; /**< 可空来源强引用，caller保活、不消费。 */
    vireo_async_request_pending_t *pending; /**< 每完整租约唯一稳定caller gate，不能指向callback栈。 */
} vireo_async_round_tls_config_t;

/**
 * @brief 为一个应用客户提供独立配置，返回后才驱动
 * @param[in,out] context 可空caller短借配置；保证同步和稳定地址。
 * @param[in] client 原完整租约与事件值，events=0也可为缓存待办。
 * @param[out] out 先typed零的配置；非OK时不读取半成品。
 * @retval VIREO_OK 配置沿原driver校验；不表示已经提交。
 * @return 其他原分类停批，不自动重试或清理。
 * @note 正常返回、有界非阻塞、不递归或操作/销毁同根资源，不返回栈内指针。
 */
typedef vireo_result_t (*vireo_async_round_tls_configure_fn)(void *context,
    vireo_tcp_server_ready_client_t client, vireo_async_round_tls_config_t *out);

/** 组合首错位置；成功与基本参数拒绝NONE。 */
typedef enum vireo_async_round_tls_stage {
    VIREO_ASYNC_ROUND_TLS_NONE = 0,
    VIREO_ASYNC_ROUND_TLS_VALIDATE,
    VIREO_ASYNC_ROUND_TLS_POLL,
    VIREO_ASYNC_ROUND_TLS_LOOKUP,
    VIREO_ASYNC_ROUND_TLS_INSPECT,
    VIREO_ASYNC_ROUND_TLS_HANDSHAKE,
    VIREO_ASYNC_ROUND_TLS_CONFIGURE,
    VIREO_ASYNC_ROUND_TLS_DRIVE,
    VIREO_ASYNC_ROUND_TLS_CLOSE,
    VIREO_ASYNC_ROUND_TLS_SCHEDULE
} vireo_async_round_tls_stage_t;

/** 一个实际尝试客户的值；未走分支typed零，没有owner或body借用。 */
typedef struct vireo_async_round_tls_turn {
    vireo_tcp_server_ready_client_t client; /**< 已从FIFO取出的完整lease/events。 */
    vireo_tcp_server_tls_turn_path_t path; /**< 真实HANDSHAKE/APPLICATION/CLOSE；lookup失败NONE。 */
    vireo_async_round_tls_stage_t stage; /**< 此项主错步骤，成功NONE。 */
    vireo_result_t result; /**< 此项实际主返回。 */
    vireo_tcp_server_tls_error_t lookup_error; /**< TLS借用原诊断。 */
    vireo_tls_connection_error_t tls_error; /**< 分派状态观察原诊断。 */
    bool handshake_called; /**< 实际一次公开握手步骤。 */
    vireo_tcp_server_tls_handshake_info_t handshake; /**< 原握手及关注提交前缀。 */
    vireo_tcp_server_tls_error_t handshake_error; /**< 原握手主/次诊断。 */
    bool configure_called; /**< 应用分支一次配置尝试。 */
    vireo_result_t configure_result; /**< called时原callback结果。 */
    bool drive_called; /**< 配置OK后一次034-16驱动。 */
    vireo_async_client_drive_tls_report_t drive_report; /**< 原单帧移交/消费/IO及final主次错误。 */
    bool close_called; /**< 实际一次已请求关闭step，包括终态观察。 */
    vireo_tcp_server_tls_close_step_info_t close; /**< 原关闭/期限/同步事实。 */
    vireo_tcp_server_tls_close_error_t close_error; /**< 原关闭完整主/次诊断。 */
    bool schedule_called; /**< 握手建立或成功缓存续处理后一次排尾。 */
    vireo_result_t schedule_result; /**< 原排尾返回，不内部重试。 */
    vireo_tcp_server_client_error_t schedule_error; /**< 原排尾独立诊断。 */
} vireo_async_round_tls_turn_t;

/** 完整poll已取前缀与实际turn前缀独立；失败后caller须处理两者。 */
typedef struct vireo_async_round_tls_report {
    vireo_async_round_tls_stage_t stage; /**< 本轮首错步骤。 */
    size_t effective_max_clients; /**< max_clients与两个容量取min，基本拒绝0。 */
    vireo_tcp_server_tls_error_t validation_error; /**< 根TLS配置公开观察错误。 */
    bool poll_called; /**< 实际一次期限感知poll尝试。 */
    vireo_result_t poll_result; /**< called时原poll返回。 */
    vireo_tcp_server_tls_poll_report_t poll_report; /**< 原selected/剩余FIFO/监听/due/采时事实。 */
    vireo_tcp_server_tls_error_t poll_error; /**< 原等待/扫描主次原因。 */
    size_t turn_count; /**< 实际尝试数，包括lookup或阶段失败项。 */
    size_t handshake_calls; /**< 真实握手边界调用数，失败也计。 */
    size_t drive_calls; /**< 真实应用driver调用数。 */
    size_t close_calls; /**< 真实关闭step调用数。 */
    size_t requeued_count; /**< schedule返回OK次数，不等新增唯一Q项数。 */
    size_t unprocessed_begin; /**< =turn_count；到selected_count的已取后缀尚未尝试。 */
} vireo_async_round_tls_report_t;

/**
 * @brief 一次TLS期限poll冻结批次，逐客户只推进一个真实协议阶段
 * @param[in,out] server 必需存活TLS根，已绑定listener；原run外Reactor串行安全点。
 * @param[in,out] store 必需原inflight表，准入/退款/身份规则沿单客户驱动。
 * @param[in,out] pool 必需固定worker池，提交与其他池管理caller串行。
 * @param[in] options 必需三数值配置，入口复制；关闭预算在poll前核验。
 * @param[in] configure 必需有界非阻塞配置callback，只在APPLICATION分支调用一次。
 * @param[in,out] context 可空caller短借；pending/cancel来源保证活到对应driver返回。
 * @param[out] ready 独立可写数组，保留poll实际已撤取的全部前缀，未写尾保持。
 * @param[in] ready_capacity 正元素容量1..65535，不是字节。
 * @param[out] turns 独立可写数组，只写turn_count前缀，包括失败当前项；未写尾保持。
 * @param[in] turn_capacity 正元素容量1..65535，限制本轮客户数。
 * @param[out] remaining_task 必需独占入口NULL，未移交的失败task归caller处置。
 * @param[out] report 必需独立值报告，每条可写路径覆盖，失败仍须查完整前缀。
 * @retval VIREO_OK 本有限轮完成，含原poll预stop的零turn；不承诺worker或响应已完成。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 必需NULL/空callback/负timeout/零数量/非空owner。
 * @retval VIREO_RESULT_RANGE 数量超65535或关闭预算不足；其他范围沿原阶段。
 * @retval VIREO_RESULT_BUSY RAW根/同根在途，或原driver/pending/队列有限拒绝。
 * @retval VIREO_RESULT_NOT_FOUND 根缺listener/旧客户代际或原阶段资格缺失。
 * @retval VIREO_RESULT_TIMEOUT 原握手/关闭期限到期，未自动清理客户。
 * @return 其余公开依赖分类透传，首错停批，实际前缀不回滚。
 * @note K=min(max_clients,ready_capacity,turn_capacity)，一次poll已撤取最多K项。
 *     每项先公开borrow/inspect；未建立做一次handshake，建立后排下轮、不立即提交。
 *     已建立且close NONE才configure/034-16 driver；成功缓存续处理才排尾。
 *     已请求关闭只一次close step，不自动request/消费尾部/release。
 * @note ready[0:selected_count)已离开原FIFO；turns[0:turn_count)实际尝试，含首失败项。
 *     caller负责失败项和ready[unprocessed_begin:selected_count)；poll失败时turn_count=0。
 *     原FIFO remaining_count不包含这个已取后缀；不能只看Q或无条件重排/重放任务。
 *     每项真实移交的header/metadata须分别保存，pending恢复与残留owner沿原合同。
 * @note 不accept/分发completion/自动响应/业务期限取消/完整服务或join，无本层长期对象。
 *     不新增整轮锁或递归检测；callback限制由caller保证。禁POSIX取消，地址独立稳定对齐
 *     且不重叠。保持入口errno，不改进程信号；TLS公开观察清本线程OpenSSL错误队列。
 */
vireo_result_t vireo_async_round_tls_once(vireo_tcp_server_t *server, vireo_inflight_store_t *store,
    vireo_thread_pool_t *pool, vireo_async_round_tls_options_t const *options,
    vireo_async_round_tls_configure_fn configure, void *context, vireo_tcp_server_ready_client_t *ready,
    size_t ready_capacity, vireo_async_round_tls_turn_t *turns, size_t turn_capacity,
    vireo_task_t **remaining_task, vireo_async_round_tls_report_t *report);
/**
 * @brief 处理caller已经取出的完整TLS就绪批次，复用原轮次三阶段内核且不再poll
 * @param[in,out] server 必需存活TLS根，原run外同Reactor串行安全点。
 * @param[in,out] store 必需存活在途表，沿单客户原登记/移交合同。
 * @param[in,out] pool 必需存活worker池，caller串行管理。
 * @param[in] close_max_bytes 正关闭单步预算，至少两FIFO最小稳定请求的最大值。
 * @param[in] configure 必需原有界配置callback，只在APPLICATION分支执行。
 * @param[in,out] context 可空短借；pending/cancel必须按原合同保活。
 * @param[in] ready 独立只读数组，只读ready_count前缀；必须源于该根公开poll且尚未处理。
 * @param[in] ready_count 元素数0..65535，必须不超过turn_capacity，不截断或再次撤取FIFO。
 * @param[out] turns 独立可写数组，只写turn_count前缀，含首失败项；未写尾保持。
 * @param[in] turn_capacity 元素容量1..65535，足够容纳整个输入批次。
 * @param[out] remaining_task 必需独占入口NULL；失败残留task归caller显式恢复/清理。
 * @param[out] report 必需独立报告；poll_called=false、poll字段全零，effective_max_clients=ready_count。
 * @retval VIREO_OK 整个输入批次已尝试，包括零项；不证明worker或响应已完成。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 必需NULL、零容量/关闭预算或非空owner。
 * @retval VIREO_RESULT_RANGE 数量超限、输出不足或关闭预算不足，未处理任何输入项。
 * @retval VIREO_RESULT_BUSY RAW根/同根阶段在途，或原driver/pending有限拒绝。
 * @retval VIREO_RESULT_NOT_FOUND 当前客户代际失效或其他原资源缺失。
 * @retval VIREO_RESULT_TIMEOUT 原握手/关闭期限到期，客户仍归server。
 * @return 其他依赖/配置原错透传；阶段、真实进度/主次原因沿once。
 * @note 不检查事件来源的历史，也不替caller去重；caller保证同根未篡改身份及串行安全点。
 *     首错停批，unprocessed_begin=turn_count，ready此下标到ready_count仍由caller恢复。
 *     已移交task/已消费帧不能重放，pending先按原合同恢复；无自动排回完整输入批次。
 *     不接入/消费completion/自动请求关闭/尾部消费/release。保持errno，禁POSIX取消；
 *     地址独立稳定不重叠，回调限制和TLS错误队列语义沿once。
 */
vireo_result_t vireo_async_round_tls_process_ready(vireo_tcp_server_t *server,vireo_inflight_store_t *store,
    vireo_thread_pool_t *pool,size_t close_max_bytes,vireo_async_round_tls_configure_fn configure,void *context,
    vireo_tcp_server_ready_client_t const *ready,size_t ready_count,vireo_async_round_tls_turn_t *turns,
    size_t turn_capacity,vireo_task_t **remaining_task,vireo_async_round_tls_report_t *report);
#endif /* VIREO_NET_ASYNC_ROUND_TLS_H */
