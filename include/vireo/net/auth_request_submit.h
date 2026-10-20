/* PROJECT: VIREO — Reactor认证请求的TLS资格、LOGIN准入与完整帧任务投递。 */
#ifndef VIREO_NET_AUTH_REQUEST_SUBMIT_H
#define VIREO_NET_AUTH_REQUEST_SUBMIT_H

#include <vireo/net/async_request.h>
#include <vireo/net/auth_session.h>
#include <vireo/service/auth_task.h>
#include <vireo/net/tcp_server_tls.h>
#include <vireo/protocol/auth_request.h>
#include <vireo/service/auth_login_admission.h>

/** 普通调用配置；显式提供，不默认注册内部operation或Session TTL。 */
typedef struct vireo_auth_request_submit_options {
    size_t task_allocation_budget; /**< 正且<=task MAX，计控制块与wire或56字节VAL1。 */
    size_t max_client_requests; /**< 正客户在途上限，实际容量资格沿原submit。 */
    uint32_t register_operation; /**< 非零内部注册标签，与login_operation不同。 */
    uint32_t login_operation; /**< 非零内部登录标签，由worker装配约定。 */
    uint64_t deadline_ns; /**< 同域MONOTONIC绝对纳秒，0/MAX均有限，不自动执行超时。 */
    uint32_t logout_operation, resume_operation; /**< 四标签显式非零且不同。 */
} vireo_auth_request_submit_options_t;

/** 本层独立主错位置，不修改旧stage编号，也不是wire status。 */
typedef enum vireo_auth_request_submit_stage {
    VIREO_AUTH_REQUEST_SUBMIT_NONE = 0,
    VIREO_AUTH_REQUEST_SUBMIT_DECODE = 1,
    VIREO_AUTH_REQUEST_SUBMIT_TRANSPORT = 2,
    VIREO_AUTH_REQUEST_SUBMIT_PEER = 3,
    VIREO_AUTH_REQUEST_SUBMIT_ADMISSION = 4,
    VIREO_AUTH_REQUEST_SUBMIT_QUEUE = 5,
    VIREO_AUTH_REQUEST_SUBMIT_SESSION = 6
} vireo_auth_request_submit_stage_t;

/** 无秘密、借用指针或owner的真实阶段报告；逻辑零不表示已调用或准入。 */
typedef struct vireo_auth_request_submit_report {
    vireo_auth_request_submit_stage_t stage; /**< 首主错，成功/基本拒绝NONE。 */
    vireo_auth_request_issue_t request_issue; /**< parser原分类，无输入内容。 */
    bool input_validated; /**< 完整认证schema/字符规则已通过。 */
    vireo_command_t command; /**< input_validated后为四认证命令之一。 */
    uint32_t sequence; /**< input_validated后为原非零序号。 */
    size_t frame_bytes; /**< input_validated后为完整wire长度，原帧未消费。 */
    bool transport_called; /**< 已尝试server/当前租约/TLS只读资格检查。 */
    bool transport_ready; /**< 本次检查确认安全点、TLS建立/io OPEN/close NONE。 */
    vireo_tcp_server_tls_error_t lookup_error; /**< 原server TLS借用诊断。 */
    vireo_tls_connection_error_t tls_error; /**< 原TLS状态查询诊断。 */
    bool peer_called; /**< 仅LOGIN，已尝试一次当前租约的真实peer查询。 */
    vireo_connection_peer_t peer; /**< peer查询OK才有效；不含端口或fd。 */
    vireo_tcp_server_client_error_t peer_error; /**< 原peer独立诊断。 */
    bool admission_called; /**< 已实际调用一次LOGIN三维check。 */
    bool admission_decided; /**< check返回OK，decision是有效判定。 */
    vireo_rate_limit_decision_t decision; /**< decided才可读outcome，零不代表准入。 */
    bool login_charged; /**< 本次确已ADMITTED并扣费，下游错误不清除/退款。 */
    bool submit_called; /**< 已进入一次发号/任务复制/try_submit路径。 */
    vireo_async_request_report_t submit_report; /**< 原发号/复制/登记/移交/撤销事实。 */
    size_t task_payload_bytes; /**< LOGOUT56，其余完整wire；不是网络frame_bytes。 */
    bool session_checked, trusted_identity_attached;
} vireo_auth_request_submit_report_t;

/**
 * @brief 校验一个完整认证请求并检查当前TLS；LOGIN获准后一次复制、登记及尝试提交
 * @param[in,out] server 必需存活网络根，Reactor安全点独占短借，不在sync handler内调用。
 * @param[in] client 完整当前租约；caller保证wire来自该客户当前读区且本次调用内不变。
 * @param[in,out] store 必需原inflight表，登记/撤销/清理责任沿031。
 * @param[in,out] pool 必需固定池，管理与提交caller串行，worker可并发领取独立task。
 * @param[in,out] admission 必需全服务LOGIN限流器，Reactor串行；REGISTER也须非NULL但不调用。
 * @param[in] now 当前Reactor在本次准入前采样的同域非递减MONOTONIC纳秒，不来自客户端。
 * @param[in,out] sessions 必需对应server的固定表；LOGOUT查绑定，RESUME发号后先记水位。
 * @param[in] utc 本轮可信UTC毫秒，LOGOUT核绑定到期；不是客户端数据。
 * @param[in] wire 必需连续只读单帧，包含32字节header；借至返回，不接管/保存。
 * @param[in] wire_size 实际精确帧长；必须恰好一个认证请求，不接受半帧/尾随帧。
 * @param[in] options 必需完整有效配置，入口复制；不得以wire command隐式代替内部operation注册。
 * @param[in] cancel 可NULL；非NULL须caller强引用保活到返回，来源owner不消费。
 * @param[in,out] remaining_task 必需独占入口NULL的owner；本次创建未转移task交回caller。
 * @param[out] report 必需独立报告；每可写路径覆盖，所有真实前缀保留。
 * @retval VIREO_OK 原task提交成功；不证明worker执行、密码正确或客户端收到响应。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 必需NULL、非空remaining、零预算/限额/operation、
 *         四operation有重复，或下层租约/时间等参数不合法。
 * @retval VIREO_RESULT_RANGE task预算超MAX，或原依赖范围不合法。
 * @retval VIREO_RESULT_PROTOCOL 完整认证帧/schema/字符非法，不调用后续阶段。
 * @retval VIREO_RESULT_BUSY RAW/未建立/非OPEN/关闭/在途，或LOGIN被THROTTLED/CAPACITY，
 *         或原submit压力；须检查stage与有效decision，不可无条件重新调用。
 * @retval VIREO_RESULT_CANCELLED 前置观察server停止，或下层pool/queue永久停止。
 * @retval VIREO_RESULT_NOT_FOUND 当前客户不存在/旧代际，或真实peer非IP等依赖拒绝。
 * @retval VIREO_RESULT_IO peer系统查询等原错误，原诊断不等于外层errno。
 * @return 其他公开依赖错误透传，包括OVERFLOW/NO_MEMORY/INTERNAL；不内部恢复或重试。
 * @note 顺序：参数/预算→041-10 decode→server安全点/当前TLS状态→仅LOGIN真实peer→
 *       一次三维check→ADMITTED才031 copy/try_submit。REGISTER直接选择注册operation。
 *       LOGOUT先查当前完整租约/handle再封装可信user/session；RESUME发号后先note水位，
 *       然后复制/登记/投递；失败不退水位。LOGOUT本地过期TIMEOUT，缺失NOT_FOUND，撤销CANCELLED。
 * @note TLS须真实ESTABLISHED、io OPEN且close NONE；不进行握手/网络I/O/采时。
 *       stop是单次观察而非同步屏障；晚到停止或队列/KDF/DB错误不退已扣尝试额度。
 * @note 一次尝试至多调用一次；本入口不持防重状态。返回后源帧始终未消费；
 *       caller必须先保存报告并完成消费/拒绝或恢复义务。已扣或已转移后，禁止把同帧
 *       再交本入口；队列满也不把remaining_task作为下次新尝试重新登记。
 * @note task所有权仅看submit_report.task_transferred，非OK也可能已转移；
 *       未转移的owner及原撤销残留按嵌套报告处理。本层不destroy/退款/响应/绑定Session。
 * @note 无自有堆分配；局部VAL1创建区用后擦除。worker仅持完整wire或可信VAL1独立副本，
 *       不持此处server/TLS/peer借用或fd。旧通用driver不会自动调用本入口。
 * @note 所有地址有效对齐且涉及写入不重叠，不指向errno；输入至返回不可修改。
 *       同资源Reactor-only、禁POSIX取消，所有路径保持入口errno；原复制/引用不保证硬实时。
 */
vireo_result_t vireo_auth_request_copy_try_submit(vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, vireo_inflight_store_t *store, vireo_thread_pool_t *pool,
    vireo_auth_login_admission_t *admission, vireo_monotonic_ns_t now, vireo_auth_sessions_t *sessions, uint64_t utc,
    uint8_t const *wire, size_t wire_size, vireo_auth_request_submit_options_t const *options,
    vireo_task_cancel_t *cancel, vireo_task_t **remaining_task,
    vireo_auth_request_submit_report_t *report);

#endif /* VIREO_NET_AUTH_REQUEST_SUBMIT_H */
