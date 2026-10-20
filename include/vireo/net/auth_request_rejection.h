/* PROJECT: VIREO — 已消费认证拒绝的单帧响应及关注恢复。 */
#ifndef VIREO_NET_AUTH_REQUEST_REJECTION_H
#define VIREO_NET_AUTH_REQUEST_REJECTION_H
#include <vireo/net/auth_request_head.h>

/** 每客户唯一响应凭据；字段只读，只通过本模块推进，零初始化。 */
typedef enum vireo_auth_request_rejection_state {
    VIREO_AUTH_REQUEST_REJECTION_EMPTY = 0,
    VIREO_AUTH_REQUEST_REJECTION_NEEDS_ENQUEUE = 1,
    VIREO_AUTH_REQUEST_REJECTION_NEEDS_REFRESH = 2,
    VIREO_AUTH_REQUEST_REJECTION_READY = 3
} vireo_auth_request_rejection_state_t;

/** 无秘密、资源指针或owner，不保活客户；不得复制后建立第二响应路径。 */
typedef struct vireo_auth_request_rejection_receipt {
    vireo_auth_request_rejection_state_t state; /**< 入队与刷新独立，READY仍阻止重复响应。 */
    vireo_connection_pool_lease_t client; /**< 原完整租约，不允许换成复用槽的新代。 */
    vireo_command_t command; /**< 原四认证命令。 */
    uint32_t sequence; /**< 原非零序号。 */
    vireo_status_t status; /**< 显式按原处理阶段映射，绝不强转内部result。 */
} vireo_auth_request_rejection_receipt_t;

typedef enum vireo_auth_request_rejection_stage {
    VIREO_AUTH_REQUEST_REJECTION_NONE = 0,
    VIREO_AUTH_REQUEST_REJECTION_CHECK_HEAD = 1,
    VIREO_AUTH_REQUEST_REJECTION_CHECK_RECEIPT = 2,
    VIREO_AUTH_REQUEST_REJECTION_CHECK_TRANSPORT = 3,
    VIREO_AUTH_REQUEST_REJECTION_ENCODE = 4,
    VIREO_AUTH_REQUEST_REJECTION_ENQUEUE = 5,
    VIREO_AUTH_REQUEST_REJECTION_REFRESH = 6
} vireo_auth_request_rejection_stage_t;

/** 本次调用的真实前缀；未调用项为逻辑零，不能据零推断成功。 */
typedef struct vireo_auth_request_rejection_report {
    vireo_auth_request_rejection_stage_t stage; /**< 主错所在边界。 */
    vireo_auth_request_rejection_receipt_t receipt; /**< 返回时状态快照，不能作为第二门禁。 */
    bool frame_encoded; /**< 本次编码了32字节空body拒绝帧。 */
    bool enqueue_called; /**< 本次尝试一次整帧入队。 */
    bool enqueued; /**< 本次enqueue返回OK；历史入队以receipt状态为准。 */
    bool refresh_called; /**< 本次尝试一次TLS真实关注刷新。 */
    vireo_tcp_server_client_error_t enqueue_error; /**< 原enqueue诊断。 */
    vireo_tcp_server_tls_error_t lookup_error; /**< 原TLS短借诊断。 */
    vireo_tcp_server_tls_flow_info_t flow; /**< refresh_called时有效的真实刷新报告。 */
    vireo_tcp_server_tls_application_error_t error; /**< TLS资格/刷新主次原因。 */
} vireo_auth_request_rejection_report_t;

/**
 * @brief 将已消费且未移交任务的认证拒绝编码入队，失败后按凭据只恢复未完成阶段
 *
 * @param[in,out] server
 *     必需存活TLS根，Reactor安全点串行短借；无同根其他处理阶段在途。
 * @param[in] head
 *     必需原唯一CONSUMED凭据；原帧已消费、submit_result非OK且任务未移交。
 *     从首次调用至acknowledge保持原值与唯一性，禁止先ack或替换/重放源帧。
 * @param[in,out] receipt
 *     必需每客户唯一、零初始化响应凭据；失败可推进，禁止手工清空重发。
 * @param[out] report
 *     必需独立可写报告；每可写路径覆盖，不保存输入/资源指针。
 *
 * @retval VIREO_OK
 *     拒绝帧已完整复制进唯一TLS写FIFO，真实关注/续调度已刷新；不证明send或收到。
 * @retval VIREO_RESULT_NOT_FOUND
 *     EMPTY head、原提交OK、任务已移交、已READY，或原客户已失效；不自动清空凭据。
 * @retval VIREO_RESULT_BUSY
 *     原帧未消费、非安全点、TLS未就绪/关闭或公开依赖有限保护。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需NULL、凭据形态错误、非认证command或两凭据身份/映射状态不一致。
 * @retval VIREO_RESULT_CANCELLED
 *     入队前观察到server停止；已入队恢复仅刷新，不因停止重发。
 * @retval VIREO_RESULT_RANGE
 *     原TLS写FIFO空余/容量不足；不部分复制，保持NEEDS_ENQUEUE。
 * @return
 *     其他公开观察/codec/enqueue/refresh原错透传；所有路径保持入口errno。
 *
 * @note 映射：DECODE+PROTOCOL为BAD_REQUEST；ADMISSION+BUSY且有效THROTTLED为
 *     RATE_LIMITED、CAPACITY为OVERLOADED；QUEUE+BUSY为OVERLOADED；CANCELLED为
 *     UNAVAILABLE；其他已知非OK为INTERNAL_ERROR。不暴露错误文本、密码、token或SQL。
 *     响应仅RESPONSE、原command/sequence、handles0、body0，显式codec及CRC。
 * @note EMPTY→NEEDS_ENQUEUE→NEEDS_REFRESH→READY。enqueue成功立即保存NEEDS_REFRESH，
 *     再调用flow_refresh；刷新失败后再次step绝不enqueue。READY重复step无网络动作。
 *     enqueue失败保原阶段；caller须按原诊断选择有界恢复或关闭，禁止无界忙重试。
 * @note 本层不消费/提交/退款/destroy/结束登记。caller仍须处理或转存原task/登记残留，
 *     保持head门禁直到显式ack。任务已移交即使submit返回非OK也绝不产生拒绝。
 * @note 无申请、锁、native TLS收发或采时；固定32字节栈工作区，无秘密副本。
 *     所有地址有效对齐且写区独立、不重叠资源/输入/errno；同资源Reactor-only，禁POSIX取消。
 *     原公开TLS观察会清本线程OpenSSL错误队列。不自动flush/close或安装生产driver。
 */
vireo_result_t vireo_auth_request_rejection_step(vireo_tcp_server_t *server,
    vireo_auth_request_head_receipt_t const *head, vireo_auth_request_rejection_receipt_t *receipt,
    vireo_auth_request_rejection_report_t *report);

/**
 * @brief caller接管原清理义务且响应READY后，一次清空原首帧与响应两凭据
 *
 * @param[in,out] head
 *     必需原唯一CONSUMED凭据；caller须先完成或显式转存残留task/登记恢复责任。
 * @param[in,out] receipt
 *     必需原唯一READY凭据，身份和映射须与head一致；两地址独立。
 *
 * @retval VIREO_OK
 *     两凭据清为逻辑零，允许处理下一首帧；原已入队字节继续归TLS FIFO。
 * @retval VIREO_RESULT_BUSY
 *     尚待消费、入队或刷新；两凭据保持。
 * @retval VIREO_RESULT_NOT_FOUND
 *     空凭据、原任务已移交或原submit成功；两凭据保持。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     NULL、畸形或不匹配；两凭据保持。
 *
 * @note 只确认交接，不证明已发送/对端收到，不释放task/登记/客户。全部路径保持errno。
 *     同资源Reactor-only，禁POSIX取消；不提供跨绕过调用、篡改或跨进程的恰好一次。
 *     客户明确归还后才可保存诊断并弃置无法完成的凭据，不得修改租约恢复到新客户。
 */
vireo_result_t vireo_auth_request_rejection_acknowledge(vireo_auth_request_head_receipt_t *head,
    vireo_auth_request_rejection_receipt_t *receipt);
#endif /* VIREO_NET_AUTH_REQUEST_REJECTION_H */
