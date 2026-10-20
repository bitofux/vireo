/* PROJECT : VIREO
 * FILE : auth_service.h
 * AUTHOR : bitofux
 * DATE : 2026-10-20
 * BRIEF : Reactor认证服务轮、持久恢复凭据及有限连接清理。 */
#ifndef VIREO_NET_AUTH_SERVICE_H
#define VIREO_NET_AUTH_SERVICE_H
#include <vireo/net/auth_request_rejection.h>
#include <vireo/service/auth_failure_audit.h>
#include <vireo/net/auth_response_consumer.h>
#include <vireo/net/notifier_server.h>
#include <vireo/net/inflight_client_cleanup.h>

/** Reactor独占owner；所有依赖须更长寿，不拥有worker或数据库。 */
typedef struct vireo_auth_service vireo_auth_service_t;
/** 长期借用关联；queue仅含同一operation注册表的可信认证结果。 */
typedef struct vireo_auth_service_resources {
    vireo_tcp_server_t *server; /**< TLS根，已绑定listener、无客户、预留一辅助槽；本层独占客户调度/释放。 */
    vireo_inflight_store_t *store; /**< 本服务专用在途表，入口空。 */
    vireo_thread_pool_t *workers; /**< 已配置/启动/放行的固定池，callback执行context/service/publish。 */
    vireo_auth_login_admission_t *admission; /**< 同Reactor全服务LOGIN额度。 */
    vireo_auth_sessions_t *sessions; /**< 属于此server的固定身份表。 */
    vireo_completion_queue_t *queue; /**< 已prepare的专用队列，producer寿命由caller同步。 */
    vireo_notifier_t *notifier; /**< 对应queue的存活提示源，创建时本层注册、销毁时注销。 */
    vireo_auth_failure_audit_t *audit; /**< 可NULL；只借至producer退出，一次非阻塞offer。 */
} vireo_auth_service_resources_t;
/** 显式固定预算；没有隐式TTL、扩容、worker启动或后台管理线程。 */
typedef struct vireo_auth_service_options {
    size_t max_clients; /**< 每轮客户选择/清理扫描各最多此数，1..server容量。 */
    vireo_tcp_server_admit_budget_t admit; /**< 每轮accept与syscall正预算，数量≤server容量。 */
    size_t max_completions; /**< 每轮pop/consumer尝试最多1..65536；达到预算补提示。 */
    size_t cleanup_slots; /**< 每个待释放客户每轮扫描inflight最多1..65536槽。 */
    vireo_tls_io_budget_t receive, send; /**< 每客户各一次有界TLS调用；字节至少min(FIFO容量,16384)。 */
    size_t task_allocation_budget; /**< 正且≤64MiB，原完整认证帧task预算。 */
    size_t max_client_requests; /**< 正且≤store容量，沿旧准入。 */
    uint32_t register_operation, login_operation; /**< 与worker/consumer一致的非零不同标签。 */
    uint64_t request_timeout_ns; /**< 正MONOTONIC时长，deadline=提交前now+时长，溢出拒绝。 */
    size_t max_memory_bytes; /**< 本对象/槽/ready/接入数组申请预算，1..64MiB。 */
    uint32_t logout_operation, resume_operation; /**< 四标签显式非零且不同。 */
} vireo_auth_service_options_t;
/** 每轮事实，无秘密/借用指针；客户局部失败记录后关闭，基础设施错误才返回非OK。 */
typedef struct vireo_auth_service_report {
    bool quiescing, stopped, poll_called; /**< 停止新任务、server永久stop及实际poll分别报告。 */
    size_t admitted, client_turns, submitted, rejected, completions, released; /**< 本次各不可逆成功前缀。 */
    bool response_blocked; /**< 已take结果或拒绝仍待FIFO空间；本轮继续驱动客户发送。 */
    vireo_result_t first_client_result; /**< 首客户局部错误，0不代表没有关闭。 */
    vireo_connection_pool_lease_t first_failed_client; /**< 对应完整历史身份。 */
    vireo_result_t post_pressure_result; /**< 主错独立的末监听刷新错误。 */
    vireo_auth_request_head_report_t head; /**< 最后一次head/resume真实报告。 */
    vireo_auth_request_rejection_report_t rejection; /**< 最后一次拒绝step报告。 */
    vireo_auth_response_consumer_report_t consumer; /**< 最后一次专用consumer报告。 */
    vireo_tcp_server_tls_poll_report_t poll; /**< 本次poll前缀；即使失败selected仍由对象保存。 */
    vireo_tcp_server_tls_error_t tls_error; /**< poll/握手/接入原诊断。 */
} vireo_auth_service_report_t;
/**
 * @brief 固定分配状态及工作区，最后注册通知源，发布唯一服务owner
 * @param[in] resources
 *     必需七项存活关联及可NULL audit，复制指针长期借至destroy；创建时排除所有并发访问。
 * @param[in] options
 *     必需显式固定配置，复制值；TLS读区和max_read_unit≥156、写区≥104。
 * @param[out] owner
 *     必需独占空owner地址，失败保持；成功由destroy释放。
 * @retval VIREO_OK
 *     已完整初始化并注册notifier，未启动线程或接客户。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需NULL/非空owner/零配置或相同operation。
 * @retval VIREO_RESULT_RANGE
 *     预算/容量不兼容或超硬限。
 * @retval VIREO_RESULT_BUSY
 *     server已有客户/在途、store非空、池未放行或依赖有限竞争。
 * @retval VIREO_RESULT_OVERFLOW
 *     固定申请量不可表示。
 * @retval VIREO_RESULT_NO_MEMORY
 *     申请失败。
 * @return 其他公开观察/注册原错误透传。
 * @note Reactor-only、禁POSIX取消，保持errno；全部地址独立有效对齐。
 *     caller保证资源配对，独占server客户/辅助源/store消费，不外部释放客户或篡改凭据。
 *     worker仍只借task/DB和queue/notifier，应用callback及其失败收尾由启动层提供。
 */
vireo_result_t vireo_auth_service_create(vireo_auth_service_resources_t const *resources,
    vireo_auth_service_options_t const *options, vireo_auth_service_t **owner);
/**
 * @brief 消费已有认证结果，执行一次有限TLS服务轮并保留恢复进度
 * @param[in,out] service
 *     必需存活独占对象，依赖均须存活且按原合同可用。
 * @param[in] timeout_ms
 *     本轮一次poll等待上限0..1000毫秒；已有本地进度不等待。
 * @param[out] report
 *     必需独立报告，每可写路径覆盖；失败前缀不回滚。
 * @retval VIREO_OK
 *     有限轮完成，客户局部错误可已关闭；不证明所有worker退出或对端收到。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需NULL或负等待。
 * @retval VIREO_RESULT_RANGE
 *     等待超过1000毫秒，保证通知异常时仍周期检查队列。
 * @return 采时/公共基础设施错误原样返回；已选未处理客户及owner保留在对象，下次继续。
 * @note 每轮预算与通知count无关，任何一轮都主动try_pop；满FIFO保owner/凭据，
 *     继续网络发送，下一轮只恢复未完成阶段。其他客户数据/握手错误标记disconnect；
 *     已提交/已消费/已enqueue绝不重放。非认证command作为协议错误关闭，不送认证head。
 *     每客户至多一认证首帧，先send稳定WRITE retry，再READ retry/允许的新读，再head，
 *     最多一次尾send并末flow刷新。EOF须在缓存帧处理后且本客户无inflight/待写/结果时才释放。
 *     quiesce禁新接入/任务，仍处理原消费/拒绝/发送；server_stop则有界放弃/清理旧客户和结果。
 *     本层不执行SQL/KDF/等待队列/阻塞join，不设自动慢端时限；caller可disconnect慢端。
 *     真实UTC用于Session过期及拒绝审计原样本；可信MONOTONIC产生deadline，两者不能互换。
 *     Reactor-only、禁POSIX取消，所有路径保持errno；SIGPIPE须由进程预设SIG_IGN。
 */
vireo_result_t vireo_auth_service_once(vireo_auth_service_t *service, int timeout_ms,
    vireo_auth_service_report_t *report);
/**
 * @brief 永久停止新accept和新认证提交，已有结果与发送仍由once推进
 * @param[in,out] service
 *     必需独占存活服务；仅改变本对象意图，实际listener由下一once同步。
 * @retval VIREO_OK
 *     quiescing=true，重复调用幂等。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     service为NULL。
 * @note 不是server_stop或worker join；caller在消费持续运行时关闭任务提交，确认worker
 *     不再发布后才join/销毁依赖。Reactor-only、禁POSIX取消，保持errno。
 */
vireo_result_t vireo_auth_service_quiesce(vireo_auth_service_t *service);
/**
 * @brief 标记一个完整当前服务租约断连，后续once按cleanup预算结束义务并归还
 * @param[in,out] service
 *     必需存活独占对象，不立即释放或消费。
 * @param[in] client
 *     服务持有的完整当前租约，不能用旧代断开复用槽新客户。
 * @retval VIREO_OK
 *     已标记关闭，重复标记幂等。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     service为NULL。
 * @retval VIREO_RESULT_NOT_FOUND
 *     非本服务当前完整租约或空/越界身份，保持新客户。
 * @note 先abort未提交候选、清理取消登记/残留task，再forget并release；已提交SQL不回滚。
 *     Reactor-only、禁POSIX取消，保持errno；不承诺发送剩余响应或正常TLS关闭通知。
 */
vireo_result_t vireo_auth_service_disconnect(vireo_auth_service_t *service,
    vireo_connection_pool_lease_t client);
/**
 * @brief 无在用客户/结果/selected后注销通知并释放对象
 * @param[in,out] owner
 *     必需独占owner地址，*owner可NULL；成功清NULL，失败保剩余资源和owner。
 * @retval VIREO_OK
 *     本服务借用结束，依赖资源及其owner不销毁。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     owner为NULL。
 * @retval VIREO_RESULT_BUSY
 *     仍有客户/恢复结果/selected义务，须继续once或显式disconnect。
 * @return 原通知注销错误透传，失败保owner可再收尾。
 * @note caller先停止producer并join后再destroy，不能从空queue推定没有未来结果。
 *     Reactor-only、禁POSIX取消，保持errno；无自动join、stop或依赖析构。
 */
vireo_result_t vireo_auth_service_destroy(vireo_auth_service_t **owner);
#endif
