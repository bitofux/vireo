/* TLS异步单客户组合；旧RAW入口及报告保持。 */
#ifndef VIREO_NET_ASYNC_CLIENT_DRIVE_TLS_H
#define VIREO_NET_ASYNC_CLIENT_DRIVE_TLS_H
#include <vireo/net/async_client_drive.h>
#include <vireo/net/tcp_server_tls.h>

/** 两方向独立正预算，每方向至多调用一次，不补充。 */
typedef struct vireo_async_client_drive_tls_budget {
    vireo_tls_io_budget_t receive; /**< 明文接收字节/native调用上限。 */
    vireo_tls_io_budget_t send; /**< 旧FIFO发送字节/native调用上限。 */
} vireo_async_client_drive_tls_budget_t;

/** 只描述本组合主错误，成功及基本参数拒绝为NONE。 */
typedef enum vireo_async_client_drive_tls_stage {
    VIREO_ASYNC_CLIENT_DRIVE_TLS_NONE = 0,
    VIREO_ASYNC_CLIENT_DRIVE_TLS_CHECK_PENDING,
    VIREO_ASYNC_CLIENT_DRIVE_TLS_CHECK_SERVER,
    VIREO_ASYNC_CLIENT_DRIVE_TLS_CHECK_CLIENT,
    VIREO_ASYNC_CLIENT_DRIVE_TLS_CHECK_BUDGET,
    VIREO_ASYNC_CLIENT_DRIVE_TLS_PRE_REFRESH,
    VIREO_ASYNC_CLIENT_DRIVE_TLS_RECEIVE,
    VIREO_ASYNC_CLIENT_DRIVE_TLS_PEEK_FRAME,
    VIREO_ASYNC_CLIENT_DRIVE_TLS_SUBMIT,
    VIREO_ASYNC_CLIENT_DRIVE_TLS_SEND,
    VIREO_ASYNC_CLIENT_DRIVE_TLS_FLOW,
    VIREO_ASYNC_CLIENT_DRIVE_TLS_FINAL_REFRESH,
    VIREO_ASYNC_CLIENT_DRIVE_TLS_FINAL_INSPECT
} vireo_async_client_drive_tls_stage_t;

/** 每可写路径typed发布，零值不代表已调用；无body指针或owner。 */
typedef struct vireo_async_client_drive_tls_report {
    vireo_async_client_drive_tls_stage_t stage; /**< 主错误位置。 */
    bool pre_refresh_called; /**< 实际一次pre同步尝试。 */
    vireo_tcp_server_tls_flow_info_t pre_flow; /**< 真实TLS flow/关注/恢复排队事实。 */
    vireo_tcp_server_tls_application_error_t pre_error; /**< pre独立完整诊断。 */
    bool receive_called; /**< 实际调用一次receive，FAILED也可调用。 */
    bool receive_reported; /**< native边界确实发布合法报告。 */
    vireo_tls_io_progress_t receive; /**< 本次接收真实前缀，reported才有效。 */
    bool frame_peek_called; /**< 实际一次REQUEST查看。 */
    vireo_connection_frame_info_t frame_info; /**< 原framing统计及停止原因。 */
    bool request_header_available; /**< 完整首帧header已按值保存。 */
    vireo_protocol_header_t request_header; /**< 原wire header，不保存view。 */
    bool head_called; /**< 原031入口实际调用一次。 */
    vireo_async_request_head_report_t head_report; /**< 原移交/退款/消费责任。 */
    bool send_called; /**< 实际一次发送尝试，可能先于接收。 */
    bool send_reported; /**< 发送报告确实发布且满足预算。 */
    vireo_tls_io_progress_t send; /**< 原发送真实前缀。 */
    bool final_refresh_called; /**< pre成功后的唯一末同步尝试。 */
    vireo_result_t final_refresh_result; /**< called才有效，主错优先。 */
    vireo_tcp_server_tls_flow_info_t final_flow; /**< 末同步关注/恢复排队事实。 */
    vireo_tcp_server_tls_application_error_t final_error; /**< 独立末同步主/次原因。 */
    bool final_inspect_called; /**< 前步骤全OK才观察最终read缓存。 */
    vireo_tcp_server_tls_error_t lookup_error; /**< 原公开TLS借用错误。 */
    vireo_tls_connection_error_t tls_error; /**< 主TLS检查/flow/IO错误。 */
    vireo_tcp_server_client_error_t client_error; /**< 本层peek诊断，提交原因在head_report。 */
    bool needs_reschedule; /**< 全OK且真实移交/消费后仍有read缓存，可能仅半帧。 */
    bool pending_retained; /**< 合法入口pending或本次031消费义务尚存。 */
} vireo_async_client_drive_tls_report_t;

/**
 * @brief Reactor安全点内有界驱动一个已建立TLS异步客户，至多移交一个首帧
 *
 * @param[in,out] server 必需存活TLS根，Reactor独占安全点短借。
 * @param[in] client 当前完整客户租约，caller保证本轮生命期。
 * @param[in,out] store 必需原inflight登记表，容量/准入沿031。
 * @param[in,out] pool 必需固定worker池，提交与其他管理caller串行。
 * @param[in] options 必需原五数值配置；operation不自动映射command，deadline不在本层执行。
 * @param[in] budget 必需独立TLS收发预算，入口按值复制。
 * @param[in] cancel 可空来源强引用，借至返回，不消费或自动取消。
 * @param[in,out] pending 此完整客户唯一消费gate，入口逻辑空；非空先原resume。
 * @param[out] remaining_task 必需入口NULL独占owner，失败未移交task归caller。
 * @param[out] report 必需独立值报告，每条可写路径覆盖，失败仍查真实前缀。
 * @return OK包括无完整帧；依赖分类与首因透传，具体范围/恢复见下述合同。
 *
 * @note
 * 必需server/store/pool/options/budget/pending/remaining_task/report；remaining_task入口NULL。
 * client为当前完整租约，已附着TLS且握手ESTABLISHED、close NONE、IO OPEN或FAILED。
 * 同server串行，无processing/driving/scheduling/serving/shutdown/closing在途；禁止混用同步消费。
 * options复用原五数值合同，但max_frame_bytes受TLS read_capacity/max_read_unit_bytes限制。
 * 每方向max_bytes至少min(各FIFO容量,16384)及当前锁定重试长度，max_native_calls正。
 * cancel可空，只短借；所有输入/输出/资源独立有效对齐且不重叠，caller禁POSIX取消。
 *
 * 基本/范围→pending→server六在途/stop→TLS资格→容量预算→一次pre刷新。
 * WRITE锁定优先send，随后允许时receive；READ-WANT_WRITE仍续原read，禁止改做send。
 * 缓存首帧即使新读暂停仍可提交；header按值复制并结束view使用后调用原031一次。
 * 尚未send且flow允许才发送旧FIFO，不等待本任务/完成；每方向最多一次，预算不重置。
 * FAILED以原receive重现缓存首错、零native且不提交。
 *
 * pre失败不final；pre成功后首业务错跳过后续数据，但仍一次公开TLS final刷新。
 * 主错优先，final_result/error独立；公开刷新可排TLS恢复工作，不承诺失败后零排队。
 * 已收/发/移交/消费不回滚；移交后消费失败保留pending，仅原resume消费，禁止重提。
 * final失败也不重放head；成功且本首帧移交/消费后仍有缓存才给needs_reschedule，caller显式排尾。
 * BUSY不可无条件重排；剩余task由caller处置，任务未移交时源首帧保留。
 *
 * OK包括无完整帧，不证明worker/响应完成。NULL/零预算/非空owner/畸形pending为INVALID_ARGUMENT；
 * 帧/task/容量/native字节下限不兼容为RANGE；非空pending/在途/RAW/未握手/关闭为BUSY；
 * stop为CANCELLED，旧代/未附着为NOT_FOUND；其余依赖分类透传，失败查看真实前缀。
 * 无本层长期资源、等待、自动schedule、期限执行、完成消费或关闭归还；031可能申请task。
 * 保持入口errno，不改进程信号；TLS公开调用清本线程OpenSSL错误队列，沿原稳定SIGPIPE前置。
 */
vireo_result_t vireo_async_client_drive_tls_once(vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, vireo_inflight_store_t *store, vireo_thread_pool_t *pool,
    vireo_async_client_drive_options_t const *options, vireo_async_client_drive_tls_budget_t const *budget,
    vireo_task_cancel_t *cancel, vireo_async_request_pending_t *pending, vireo_task_t **remaining_task,
    vireo_async_client_drive_tls_report_t *report);
#endif /* VIREO_NET_ASYNC_CLIENT_DRIVE_TLS_H */
