/* PROJECT: VIREO; FILE: auth_response_consumer.h; AUTHOR: bitofux; DATE: 2026-10-20. */
#ifndef VIREO_NET_AUTH_RESPONSE_CONSUMER_H
#define VIREO_NET_AUTH_RESPONSE_CONSUMER_H
#include <vireo/net/auth_session.h>
#include <vireo/net/inflight_completion.h>
#include <vireo/net/tcp_server_tls.h>
#include <vireo/service/auth_completion.h>
#include <vireo/protocol/auth_response.h>
/** 原提交端同一操作注册表，无默认。 */
typedef struct vireo_auth_response_consumer_options {
    uint32_t register_operation, login_operation; /**< 非零且不同。 */
    uint32_t logout_operation, resume_operation; /**< 四标签显式非零且不同。 */
} vireo_auth_response_consumer_options_t;
typedef enum vireo_auth_response_consumer_state {
    VIREO_AUTH_CONSUMER_EMPTY = 0,
    VIREO_AUTH_CONSUMER_NEEDS_ENQUEUE = 1,
    VIREO_AUTH_CONSUMER_NEEDS_BIND = 2,
    VIREO_AUTH_CONSUMER_NEEDS_REFRESH = 3,
    VIREO_AUTH_CONSUMER_READY = 4
} vireo_auth_response_consumer_state_t;
/** caller唯一恢复凭据，不含token；不能篡改/复制重放，同客户最多一个在途凭据。 */
typedef struct vireo_auth_response_consumer_receipt {
    vireo_auth_response_consumer_state_t state; /**< EMPTY零初始化；READY只ack。 */
    vireo_completion_metadata_t metadata; /**< 原结果工作事实，不因wire过期状态改写。 */
    vireo_inflight_completion_match_t match; /**< 原take前合法完整快照，不保活客户。 */
    vireo_command_t command; /**< 原四认证命令之一。 */
    vireo_status_t wire_status; /**< 原建议或首次enqueue前过期/屏障降级状态。 */
    vireo_auth_session_ticket_t ticket; /**< LOGIN/RESUME候选/已提交短handle；无bearer。 */
    bool ticket_pending; /**< true时caller必须commit/abort/forget，不能丢凭据。 */
    bool effect_applied; /**< 原LOGOUT效果已应用，即使尚未take/匹配客户。 */
    vireo_completion_metadata_t effect_metadata; /**< 原owner完整关联快照。 */
    vireo_auth_logout_identity_t effect_target;
} vireo_auth_response_consumer_receipt_t;
typedef enum vireo_auth_response_consumer_stage {
    VIREO_AUTH_CONSUMER_NONE = 0, VIREO_AUTH_CONSUMER_DECODE = 1,
    VIREO_AUTH_CONSUMER_MATCH = 2, VIREO_AUTH_CONSUMER_TRANSPORT = 3,
    VIREO_AUTH_CONSUMER_RESERVE = 4, VIREO_AUTH_CONSUMER_ENCODE = 5,
    VIREO_AUTH_CONSUMER_ENQUEUE = 6, VIREO_AUTH_CONSUMER_BIND = 7,
    VIREO_AUTH_CONSUMER_REFRESH = 8, VIREO_AUTH_CONSUMER_DESTROY = 9
} vireo_auth_response_consumer_stage_t;
/** 每可写路径发布；called区分未调用的零值与实际成功。报告无敏感token。 */
typedef struct vireo_auth_response_consumer_report {
    vireo_auth_response_consumer_stage_t stage;
    bool consume_called; /**< 本次是否沿028核对/take/迟到清理。 */
    vireo_inflight_completion_consume_report_t consumption; /**< 同次原报告。 */
    bool frame_encoded, enqueue_called, enqueued, bound, refresh_called;
    size_t frame_bytes;
    vireo_auth_response_consumer_state_t state; /**< 返回时恢复位置。 */
    vireo_tcp_server_client_error_t enqueue_error;
    vireo_tcp_server_tls_error_t lookup_error;
    vireo_tcp_server_tls_application_error_t tls_error;
    vireo_tcp_server_tls_flow_info_t flow;
} vireo_auth_response_consumer_report_t;
/**
 * @brief 专用消费caller已从队列领取的一个认证结果，回包/绑定且支持失败前缀恢复
 * @param[in,out] server 存活Reactor资源根；服务轮返回或合法安全窗口，禁POSIX取消。
 * @param[in,out] store 原请求登记表，只在EMPTY初次走028。正常迟到只销毁，不绑定/发送。
 * @param[in,out] sessions 对应server存活表；串行退出可标撤销候选，不能丢失候选票据。
 * @param[in,out] owner caller唯一completion owner；恢复必须是同一个原结果，不能重发布。
 * @param[in] options 与提交端相同的四个非零不同认证标签，短借。
 * @param[in] now_utc_ms caller本次可信UTC毫秒；首次enqueue前LOGIN过期返回SESSION_EXPIRED，RESUME过期/尚未生效为AUTHENTICATION_FAILED。
 * @param[in,out] receipt 必需独占零初始化凭据；失败后须保留，不能再走generic consume。
 * @param[out] report 必需独立报告，未调用的零值不是运行证据。
 * @return OK表示正常迟到已清理或响应完整入FIFO/绑定/刷新/结果销毁；不表示发送或收到。
 *         INVALID_ARGUMENT参数/凭据/关联异常；PROTOCOL内部payload异常；
 *         BUSY/RANGE写区不足或随机碰撞/同步在途；IO随机/关注异常；
 *         NOT_FOUND旧客户或已空owner；CANCELLED首次enqueue前server停止；其他原错误透传。
 * @note EMPTY先专用decode/标签检查、COMMITTED/UNKNOWN退出效果，再028核对/take；callback保存match后编码发送。
 *       初次前置拒绝保登记/owner。take后失败保owner+receipt，恢复不take第二次。
 *       LOGIN/RESUME先reserve；整帧enqueue成功先记NEEDS_BIND，再commit，最后TLS flow refresh。
 *       commit在合法串行不变式下无失败点；enqueue前不改active。后续成功LOGIN按FIFO
 *       入队顺序替换active；旧handle不能授权。REGISTER/失败响应不替换现有绑定；LOGOUT效果独立按SQL Session撤销全部匹配绑定。
 * @note 仅TLS1.3已建立且IO OPEN/close NONE/loop已附着可新enqueue。停止/关闭前置拒绝。
 *       已入队后不能再enqueue或改wire状态，只补bind/refresh/destroy；成功后ack。
 *       receipt不含token；原completion/局部decoded/response/104字节scratch分别擦除。
 *       无本层申请/等待/网络send；一次RAND可能初始化，扫描及复制有界非硬实时。
 * @note 原工作commit/rc不改；已提交但到消费时过期不回token，不撤销数据库Session。
 *       恢复绑定前和首次enqueue重试前检查全局cutoff及原有效期，不续期/重发token。
 *       退出效果receipt独立于交付状态，迟到/客户断开/登记丢失/abandon均先应用且只应用一次。
 *       UNKNOWN保守本地失效但不保证DB已撤销；未来新恢复仍可查库。无外部DB撤销广播/文件鉴权。
 *       所有资源/存储/errno独立不重叠，借用至返回，保持errno，Reactor-only。
 */
vireo_result_t vireo_auth_response_consumer_step(vireo_tcp_server_t *server,
    vireo_inflight_store_t *store, vireo_auth_sessions_t *sessions, vireo_completion_t **owner,
    vireo_auth_response_consumer_options_t const *options, uint64_t now_utc_ms,
    vireo_auth_response_consumer_receipt_t *receipt, vireo_auth_response_consumer_report_t *report);
/** READY且owner已NULL后caller使用；只清凭据，不清active或FIFO；其他状态BUSY。 */
vireo_result_t vireo_auth_response_consumer_acknowledge(vireo_completion_t const *owner,
    vireo_auth_response_consumer_receipt_t *receipt);
/**
 * @brief 显式放弃可信认证结果，abort未提交候选并销毁owner/清凭据
 * @note EMPTY且owner为空返回NOT_FOUND；EMPTY有owner也先解码应用退出效果再销毁。
 *       不代替处理尚未take的登记，caller仍须按原任务metadata清登记；其他恢复态核完整metadata。已入FIFO/绑定不回滚；
 *       caller须按报告选择继续发送或关闭并forget，不能将abandon当撤销已发token。
 *       所有地址必需，原owner可NULL；无pending或旧票据NF可继续清理；保持errno。
 */
vireo_result_t vireo_auth_response_consumer_abandon(vireo_auth_sessions_t *sessions,
    vireo_completion_t **owner, vireo_auth_response_consumer_receipt_t *receipt);
#endif
