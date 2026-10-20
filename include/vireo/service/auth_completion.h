/* PROJECT : VIREO
 * FILE : auth_completion.h
 * AUTHOR : bitofux
 * DATE : 2026-10-20
 * BRIEF : 认证结果的专用内部completion投影、回投及拥有型解码。
 */
#ifndef VIREO_SERVICE_AUTH_COMPLETION_H
#define VIREO_SERVICE_AUTH_COMPLETION_H
#include <vireo/service/auth_task.h>
#include <vireo/service/auth_task_context.h>
#include <vireo/service/auth_failure_audit.h>
#include <vireo/thread/completion_publish.h>

/** 内部固定投影大小，不是线协议body schema或C结构大小。 */
#define VIREO_AUTH_COMPLETION_PAYLOAD_BYTES ((size_t)88) /* VAC1 */
#define VIREO_AUTH_COMPLETION_SESSION_BYTES ((size_t)120) /* VAC2 */

/** 专用提交事实，显式映射repository枚举，不按返回码猜测。 */
typedef enum vireo_auth_commit {
    VIREO_AUTH_NOT_COMMITTED = 0, /**< 未确认业务提交，写事务未提交；RESUME只读成功另由resume_validated表示。 */
    VIREO_AUTH_COMMITTED = 1, /**< 已确认提交，即使内部工作结果非OK仍发布成功身份。 */
    VIREO_AUTH_COMMIT_UNKNOWN = 2 /**< 提交确认不足，无身份/token，禁止自动重放。 */
} vireo_auth_commit_t;

/** caller独占的解码结果，含敏感token；不能直接序列化或写日志。 */
typedef struct vireo_auth_completion_outcome {
    vireo_completion_metadata_t metadata; /**< 原请求、工作rc与状态建议，非发送进度。 */
    vireo_command_t command; /**< 四认证命令，由专用内部payload记录。 */
    vireo_auth_commit_t commit; /**< 真实三态提交，不因取消/迟到/清理错误改写。 */
    uint64_t user_id; /**< REGISTER/LOGIN提交或RESUME验证成功非零；LOGOUT零。 */
    uint64_t root_node_id; /**< 仅REGISTER COMMITTED非零。 */
    uint64_t session_id; /**< LOGIN提交或RESUME验证成功非零，不是wire session_handle。 */
    uint64_t audit_id; /**< 写事务成功审计；重复LOGOUT成功可零；RESUME为零。 */
    uint64_t issued_at_ms; /**< LOGIN提交或RESUME验证成功时有效UTC毫秒，0合法。 */
    uint64_t expires_at_ms; /**< LOGIN提交或RESUME验证成功，严格大于issued。 */
    vireo_session_token_t token; /**< 仅LOGIN COMMITTED时的独立拥有型副本，全部位模式合法。 */
    bool resume_validated; /**< 只读恢复成功，commit仍NOT_COMMITTED，无token/审计。 */
    vireo_auth_logout_identity_t logout_target; /**< 可信任务快照，非授权。 */
    uint64_t revoked_at_ms; /**< 仅LOGOUT COMMITTED有效。 */
    bool already_revoked; /**< 重复成功时audit_id=0。 */
} vireo_auth_completion_outcome_t;

/** 本层真实前缀和原发布报告，不能代替completion owner值或业务提交报告。 */
typedef struct vireo_auth_completion_publish_report {
    bool result_validated; /**< 业务投影完整通过，尚不表示已交接。 */
    bool task_matched; /**< task完整metadata与结果逐逻辑字段匹配，command/sequence亦核对。 */
    bool publish_called; /**< 实际调用过一次公开copy_wait_publish。 */
    vireo_completion_publish_report_t publication; /**< 该次原发布阶段/交接/通知事实。 */
} vireo_auth_completion_publish_report_t;

/**
 * @brief 短借认证结果，构造内部投影并沿现有worker发布入口交接、通知一次
 *
 * @param[in] task
 *     必需存活原task，短借至返回，不移动或销毁。
 * @param[in] result
 *     必需原执行结果，只读短借，不清除或转移token；command/完整metadata必须有效。
 * @param[in] allocation_budget
 *     显式正completion申请预算，至多原MAX_ALLOCATION_BYTES，含控制块与88/120字节投影。
 * @param[in,out] queue
 *     必需存活且prepared的对应完成队列，只借至返回。
 * @param[in,out] notifier
 *     必需存活且与queue对应的通知对象，只借至返回。
 * @param[out] remaining
 *     必需独占空owner地址；未交接的已创建对象留caller，必须保存/处理，不能丢弃。
 * @param[out] report
 *     必需独立报告，每可写路径覆盖真实前缀，地址不保存。
 *
 * @retval VIREO_OK
 *     已交接并通知，不表示认证成功、发送或Session已绑定。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需NULL、非空owner、零预算、畸形业务事实/关联或未知内部结果。
 * @retval VIREO_RESULT_PROTOCOL
 *     原task帧非法或命令/sequence不匹配结果。
 * @retval VIREO_RESULT_RANGE
 *     原completion预算超限或不足。
 * @retval VIREO_RESULT_OVERFLOW
 *     原completion受检申请量不可表示。
 * @retval VIREO_RESULT_NO_MEMORY
 *     原completion申请失败，原业务结果仍完整保留。
 * @retval VIREO_RESULT_NOT_FOUND
 *     原完成队列未prepare，若已创建则owner留remaining。
 * @retval VIREO_RESULT_CANCELLED
 *     原队列关闭拒绝，若已创建则owner留remaining。
 * @retval VIREO_RESULT_INTERNAL
 *     原队列或通知同步异常，按原报告处理真实交接事实。
 * @retval VIREO_RESULT_IO
 *     交接后的通知失败；不能重新入队或重新认证。
 *
 * @note COMMITTED建议OK，UNKNOWN建议INTERNAL_ERROR；未提交的SERVICE LOGIN/RESUME/LOGOUT的NOT_FOUND
 *       为AUTHENTICATION_FAILED，SERVICE REGISTER用户名冲突为USER_EXISTS，
 *       DECODE/PROTOCOL为BAD_REQUEST；其余TIMEOUT/BUSY/CANCELLED映射TIMEOUT/BUSY/UNAVAILABLE，
 *       其他已知错误统一INTERNAL_ERROR。metadata仍保原工作rc，不与本函数返回混同。
 * @note 只传必要提交/身份/时间/token，repo/error/cleanup_pending责任仍由原worker保存处理。
 *       任一cleanup_pending均不可丢repo；可先保存事实/收尾再清result。本函数不管理repo。
 * @note 内部VAC1（REGISTER/LOGIN 88字节）或VAC2（RESUME/LOGOUT 120字节）仅供下列专用decode；禁止作为wire body交旧generic response sender。
 *       VAC2无token，保留可信退出目标和独立只读valid；不执行wire编码或Session绑定。与其他结果类型须由可信调度区分，magic不认证来源。
 * @note 可能分配/等待，整个调用POSIX取消须禁用，只供worker；consumer须腾空间再join。
 *       原publication.transferred决定所有权，非OK也可能已交接；未交接可处理remaining，
 *       已交接只修复通知/消费。每结果只调用一次，不提供跨调用防重，不自动重试。
 * @note 临时投影返回前擦除，原result不变；caller交付/保存清理义务后再clear原result。
 *       全部存储独立不重叠且不指errno，保持errno；共享寿命/管理由caller同步。
 */
vireo_result_t vireo_auth_completion_publish(vireo_task_t const *task,
    vireo_auth_task_result_t const *result, size_t allocation_budget,
    vireo_completion_queue_t *queue, vireo_notifier_t *notifier,
    vireo_completion_t **remaining, vireo_auth_completion_publish_report_t *report);

/**
 * @brief 从专用内部completion校验并解码独立拥有型认证结果
 *
 * @param[in] completion
 *     必需存活、来自可信认证发布调度的completion，短借至返回，不消费或销毁。
 * @param[out] out
 *     必需独占输出，成功才覆盖；caller先处理旧token/交付义务，失败保持整个旧值。
 *
 * @retval VIREO_OK
 *     独立结果已发布；不证明客户当前性、Session未过期/撤销或已经绑定。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需NULL。
 * @retval VIREO_RESULT_PROTOCOL
 *     payload大小/magic/命令/提交编码/字段不变量或metadata状态配对非法。
 *
 * @note 保持errno；无分配/I/O，局部含token临时值返回前擦除，旧completion仍由caller管理。
 *       输入/输出/errno独立，借用期间不移动/销毁输入；独立输出可并发，共享存储须同步。
 */
vireo_result_t vireo_auth_completion_decode(vireo_completion_t const *completion,
    vireo_auth_completion_outcome_t *out);

/**
 * @brief 交付/观察结束后安全擦除整个拥有型解码结果，允许重复调用
 *
 * @param[in,out] outcome
 *     必需独占存活值，caller先处理token交付，不与errno重叠。
 *
 * @retval VIREO_OK
 *     整块全零；不撤销持久Session或清除其他副本。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     outcome为NULL。
 *
 * @note 无分配/I/O，保持errno；独立对象可并发，同对象访问须同步。
 */
vireo_result_t vireo_auth_completion_outcome_clear(vireo_auth_completion_outcome_t *outcome);
/**
 * @brief 从可信已匹配结果生成失败事件；不改变业务提交或原响应投影。
 *
 * @param[in] result 必需已有可信执行结果，只借至返回，不改变原结果。
 * @param[in] context 必需完整可信上下文，非零ID、metadata/operation/deadline须匹配。
 * @param[out] event 必需独立输出，只有OK才覆盖，其他返回保持整个旧值。
 * @retval VIREO_OK 已复用原状态投影生成独立六字段失败事件。
 * @retval VIREO_RESULT_NOT_FOUND COMMITTED/UNKNOWN/有效恢复或成功，无独立失败事件。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 必需NULL、形态非法或上下文不匹配。
 * @note worker在publish/clear前调用一次；不访问DB/随机源或改变提交事实。
 *     全部地址有效、对齐、不重叠且不指向errno；局部敏感投影统一擦除，保持errno。
 */
vireo_result_t vireo_auth_failure_event_from_task(vireo_auth_task_result_t const *result,
    vireo_auth_task_context_t const *context, vireo_auth_failure_event_t *event);
#endif
