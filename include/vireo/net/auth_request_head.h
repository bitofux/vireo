/*
 * PROJECT : VIREO
 * FILE    : auth_request_head.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-20
 * BRIEF   : 认证首帧一次处理、消费恢复与无秘密处理凭据
 */
#ifndef VIREO_NET_AUTH_REQUEST_HEAD_H
#define VIREO_NET_AUTH_REQUEST_HEAD_H
#include <vireo/net/auth_request_submit.h>

/** 每客户唯一凭据的生命周期；消费完成仍保持门禁，直到caller确认后续义务。 */
typedef enum vireo_auth_request_head_state {
    VIREO_AUTH_REQUEST_HEAD_EMPTY = 0, /**< 尚无处理记录，可识别一个新首帧。 */
    VIREO_AUTH_REQUEST_HEAD_NEEDS_CONSUME = 1, /**< 已处理，原首帧仍须消费，禁止再提交。 */
    VIREO_AUTH_REQUEST_HEAD_CONSUMED = 2 /**< 原帧已消费，结果/清理/响应义务待caller接管确认。 */
} vireo_auth_request_head_state_t;

/** caller零初始化，每客户唯一且禁止复制后作为第二门禁；字段只读，不拥有资源或秘密。 */
typedef struct vireo_auth_request_head_receipt {
    vireo_auth_request_head_state_t state; /**< 本次处理与消费进度；只能经本API推进。 */
    vireo_connection_pool_lease_t client; /**< 原完整租约，不保活客户，恢复不接受替代租约。 */
    size_t frame_bytes; /**< 原完整首帧字节数，32..认证帧MAX。 */
    vireo_command_t command; /**< framing已验证的命令；schema失败时也保留，不证明认证合法。 */
    uint32_t sequence; /**< framing已验证的非零序号，供后续拒绝响应关联。 */
    vireo_result_t submit_result; /**< 一次认证入口的原返回值，不因消费恢复改变。 */
    vireo_auth_request_submit_report_t submit_report; /**< 原schema/TLS/peer/扣费/task/撤销事实。 */
} vireo_auth_request_head_receipt_t;

/** 本层主错位置，不是wire状态码。 */
typedef enum vireo_auth_request_head_stage {
    VIREO_AUTH_REQUEST_HEAD_NONE = 0, /**< 成功或基本参数拒绝。 */
    VIREO_AUTH_REQUEST_HEAD_CHECK_RECEIPT = 1, /**< 凭据形态/非空门禁。 */
    VIREO_AUTH_REQUEST_HEAD_PEEK_FRAME = 2, /**< 首帧识别或framing失败。 */
    VIREO_AUTH_REQUEST_HEAD_PEEK_BYTES = 3, /**< 连续原始字节借用失败。 */
    VIREO_AUTH_REQUEST_HEAD_SUBMIT = 4, /**< 一次认证入口失败，消费另报。 */
    VIREO_AUTH_REQUEST_HEAD_CONSUME = 5 /**< 原帧消费失败，只可恢复消费。 */
} vireo_auth_request_head_stage_t;

/** 每可写路径覆盖，所有快照无借用地址、task owner或密码。 */
typedef struct vireo_auth_request_head_report {
    vireo_auth_request_head_stage_t stage; /**< 当前调用主错位置。 */
    bool frame_peek_called; /**< 本次尝试过一次REQUEST首帧识别。 */
    vireo_connection_frame_info_t frame_info; /**< 原空/半帧/EOF/预算停止事实。 */
    bool read_peek_called; /**< 本次尝试过一次原读区借用。 */
    vireo_tcp_server_client_error_t frame_error; /**< 原首帧/读区独立诊断。 */
    bool submit_called; /**< 本次确实调用认证提交入口，恢复/门禁拒绝为false。 */
    bool receipt_committed; /**< 本次在消费前保存过凭据，包括未扣费/未移交的拒绝。 */
    bool consume_called; /**< 本次确实尝试一次原帧消费。 */
    vireo_result_t consume_result; /**< 仅consume_called时有效，不覆盖认证主错。 */
    vireo_tcp_server_client_error_t consume_error; /**< 原消费诊断。 */
    vireo_auth_request_head_receipt_t receipt; /**< 返回时凭据快照；消费成功仍保全部处理结果。 */
} vireo_auth_request_head_report_t;

/**
 * @brief 识别一个认证首帧，尝试处理一次，保存凭据后一次消费原帧
 *
 * @param[in,out] server
 *     必需网络根，Reactor安全点独占借用，不在sync handler或服务轮内部重入。
 * @param[in] client
 *     当前完整客户租约；caller须将此客户所有认证处理统一经过同一receipt。
 * @param[in,out] store
 *     必需在途表，原登记/撤销/清理合同保持。
 * @param[in,out] pool
 *     必需固定池，caller串行管理/提交，worker可并发领取独立task。
 * @param[in,out] admission
 *     必需原LOGIN限流器；REGISTER不扣登录额度。
 * @param[in] now
 *     当前Reactor采样的同域非递减MONOTONIC纳秒，不从客户端取时。
 * @param[in,out] sessions
 *     必需对应server的固定表，原认证submit核LOGOUT身份并记RESUME水位。
 * @param[in] utc
 *     本轮可信UTC毫秒，只借数值，不来自客户端。
 * @param[in] options
 *     必需完整四标签配置，基本值/预算先验证；期限0/MAX均为有限值。
 * @param[in] cancel
 *     可NULL；非NULL的原强引用须保活至返回，不转移来源owner。
 * @param[in,out] receipt
 *     必需独立唯一零初始化凭据；非空时不peek/扣费/提交，保持原值并返回BUSY。
 * @param[in,out] remaining_task
 *     必需入口NULL的独占owner，原未移交task交回caller，凭据不代管或销毁。
 * @param[out] report
 *     必需独立报告，每可写路径覆盖；submit与consume主次错独立。
 *
 * @retval VIREO_OK
 *     无完整首帧而未处理，或认证提交及原帧消费均成功；不表示密码正确/响应已发送。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需NULL、非空task、畸形receipt、零预算/限额/operation或四operation有重复。
 * @retval VIREO_RESULT_RANGE
 *     task预算超MAX，或原客户读容量/flow/其他依赖范围不合法。
 * @retval VIREO_RESULT_BUSY
 *     已有非空receipt，或原认证入口压力/限流/TLS资格拒绝。
 * @return
 *     其他公开依赖原错透传。认证非OK始终保主错，消费错误另报；认证OK时消费错为主错。
 *
 * @note 一次REQUEST frames_peek（预算1帧/156字节）→read_peek→041-11一次→提交凭据→
 *       结束全部body/raw借用→consume一次。任何完整framing帧一旦调用041-11，即使schema
 *       失败、未扣费或未移交，也保存凭据并尝试消费。framing失败/半帧不消费、不生成凭据。
 *       上游负责认证命令分发；不将普通业务帧送本入口，非认证命令会按schema拒绝并消费。
 * @note task移交仅看receipt.submit_report.submit_report.task_transferred，错误码不能替代；
 *       下游错误不退LOGIN费用。残留task及inflight撤销义务独立于源消费，caller按原报告处理。
 *       凭据保留command/sequence及所有处理结果，供后续错误响应/清理接管，无secret span。
 * @note 消费成功仅推进CONSUMED，不清凭据；caller处理或转存结果/清理/响应义务后显式
 *       acknowledge，才允许下一首帧。消费失败只可resume_consume，不可重放认证入口。
 *       NEEDS_CONSUME期间禁止另行receive/consume/改写读区；所有旧读借用使用须在入口前结束。
 *       客户明确归还后caller可保存审计事实并弃置凭据；NOT_FOUND不等于已消费。
 * @note 同资源Reactor-only、禁POSIX取消；地址有效对齐且写区独立不重叠资源/输入/errno。
 *       不保存借用、不额外复制密码、无本层分配；所有路径保持errno。不recv、刷新flow、
 *       自动响应/关闭/退款/重试/destroy/绑定Session；旧通用driver不会自动选择本入口。
 */
vireo_result_t vireo_auth_request_submit_read_head(vireo_tcp_server_t *server,
    vireo_connection_pool_lease_t client, vireo_inflight_store_t *store, vireo_thread_pool_t *pool,
    vireo_auth_login_admission_t *admission, vireo_monotonic_ns_t now, vireo_auth_sessions_t *sessions, uint64_t utc,
    vireo_auth_request_submit_options_t const *options, vireo_task_cancel_t *cancel,
    vireo_auth_request_head_receipt_t *receipt, vireo_task_t **remaining_task,
    vireo_auth_request_head_report_t *report);

/**
 * @brief 仅恢复原凭据的首帧消费，不解析、扣费、发号或提交
 * @param[in,out] server
 *     原存活根，可已stop/closing；只按原完整租约消费。
 * @param[in,out] receipt
 *     必需原唯一凭据，NEEDS_CONSUME才消费；源稳定/借用限制沿首帧入口。
 * @param[out] report
 *     必需独立可写报告，返回时保存凭据和本次消费真实结果。
 * @retval VIREO_OK
 *     本次消费成功并推进CONSUMED；原submit_result和报告保持。
 * @retval VIREO_RESULT_NOT_FOUND
 *     EMPTY/已CONSUMED无消费动作，或原租约已失效；始终保持凭据。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需NULL或凭据形态不合法，凭据保持。
 * @return
 *     其他consume原错透传，失败保NEEDS_CONSUME；不按旧submit_result重报历史主错。
 * @note 不查inflight，完成已take仍可恢复；不自动释放凭据，不重试/退款/关闭。
 *       同资源Reactor-only、禁POSIX取消，独立有效地址，所有路径保持errno。
 */
vireo_result_t vireo_auth_request_head_resume_consume(vireo_tcp_server_t *server,
    vireo_auth_request_head_receipt_t *receipt, vireo_auth_request_head_report_t *report);

/**
 * @brief caller确认已经接管处理结果及后续义务后，清空已消费凭据
 * @param[in,out] receipt
 *     必需独占凭据；caller须先处理/转存残留task、登记恢复及拒绝响应等义务。
 * @retval VIREO_OK
 *     CONSUMED凭据清为全逻辑零，允许下一帧；不执行任何资源清理或响应。
 * @retval VIREO_RESULT_BUSY
 *     NEEDS_CONSUME，保持凭据，不能提前解除防重。
 * @retval VIREO_RESULT_NOT_FOUND
 *     EMPTY，保持原值，没有消费或任务动作。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     NULL或凭据形态错误，保持原值。
 * @note 本接口无法验证caller是否完成外部义务；保存结果后才调用。禁止用复制/篡改凭据绕过
 *       门禁，不承诺跨绕过调用或跨进程的恰好一次。Reactor-only，禁POSIX取消，保持errno。
 */
vireo_result_t vireo_auth_request_head_acknowledge(vireo_auth_request_head_receipt_t *receipt);
#endif /* VIREO_NET_AUTH_REQUEST_HEAD_H */
