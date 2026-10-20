/*
 * PROJECT : VIREO
 * FILE    : auth_task.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-20
 * BRIEF   : worker自有认证task与可信服务端上下文的同步执行适配。
 */
#ifndef VIREO_SERVICE_AUTH_TASK_H
#define VIREO_SERVICE_AUTH_TASK_H

#include <vireo/protocol/auth_request.h>
#include <vireo/service/auth_service.h>
#include <vireo/thread/task.h>

/* 独立值，不是来源证明；只能由可信Reactor从完整租约/handle查得。 */
typedef struct vireo_auth_logout_identity {
    uint64_t user_id;
    uint64_t session_id;
} vireo_auth_logout_identity_t;


/** 服务端装配产生的值快照；不是wire格式或来源证明，禁止从客户端反序列化。 */
typedef struct vireo_auth_task_context {
    vireo_task_metadata_t metadata; /**< 必须逐逻辑字段匹配task，包括operation/deadline。 */
    unsigned char request_id[16]; /**< 服务端生成的非全零审计事件ID，不是sequence或重放key。 */
    uint64_t now_ns; /**< 执行前同域MONOTONIC纳秒新鲜样本，只用于软期限检查。 */
    uint64_t occurred_at_ms; /**< 服务端UTC epoch毫秒；REGISTER/LOGOUT事件时间、LOGIN签发时间或RESUME核验时间，0合法。 */
    uint64_t expires_at_ms; /**< LOGIN绝对UTC到期时间，须大于occurred；其他命令忽略。 */
    uint64_t latency_us; /**< service调用前耗时快照，不包含本次KDF/DB执行。 */
} vireo_auth_task_context_t;

/** 必须与Reactor提交端采用相同的操作注册表；没有隐式默认值。 */
typedef struct vireo_auth_task_options {
    uint32_t register_operation; /**< 非零REGISTER内部操作标签，与LOGIN不同。 */
    uint32_t login_operation; /**< 非零LOGIN内部操作标签，与REGISTER不同。 */
    uint32_t pool_timeout_ms; /**< 每次DB pool等待0..60000毫秒，非整请求硬期限。 */
    uint32_t logout_operation, resume_operation; /**< 非零且四标签两两不同。 */
} vireo_auth_task_options_t;

/** 最后到达的执行阶段；SERVICE表示已调用一次service，不能自动重放。 */
typedef enum vireo_auth_task_stage {
    VIREO_AUTH_TASK_NONE = 0, /**< 必需地址或执行依赖非法，尚未读取task。 */
    VIREO_AUTH_TASK_CONTEXT = 1, /**< options、可信值或完整task关联校验。 */
    VIREO_AUTH_TASK_DECODE = 2, /**< 从task自有完整帧重新解析。 */
    VIREO_AUTH_TASK_MATCH = 3, /**< wire命令/sequence与task操作/route核对。 */
    VIREO_AUTH_TASK_CANCEL = 4, /**< 执行前一次协作取消观察。 */
    VIREO_AUTH_TASK_DEADLINE = 5, /**< 执行前一次软期限检查。 */
    VIREO_AUTH_TASK_SERVICE = 6 /**< 已进入同步service；提交和清理事实在各报告中。 */
} vireo_auth_task_stage_t;

/** caller独占的拥有型结果；含敏感token，禁止日志、memcpy上网或作为completion字节。 */
typedef struct vireo_auth_task_result {
    vireo_auth_task_stage_t stage; /**< 最后到达阶段，SERVICE同时是本次调用事实。 */
    vireo_result_t result; /**< 本次返回码副本；不能代替commit或cleanup_pending。 */
    vireo_task_metadata_t metadata; /**< inspect成功后保存task完整路由快照，不保活客户。 */
    vireo_command_t command; /**< decode成功后保存四认证命令之一，其他路径为0。 */
    vireo_auth_request_issue_t request_issue; /**< decode分类，不包含输入或wire status。 */
    vireo_mysql_registration_report_t registration; /**< REGISTER原始提交/清理报告，其他路径零。 */
    vireo_auth_login_result_t login; /**< LOGIN原始拥有型结果；COMMITTED即使非OK也保留token。 */
    vireo_mysql_session_identity_t resume_identity; /**< 仅完整只读验证成功发布。 */
    vireo_mysql_session_report_t resume_report; /**< cleanup_pending义务不得丢。 */
    vireo_auth_logout_identity_t logout_target; /**< 可信快照，不是新授权。 */
    vireo_mysql_logout_report_t logout_report; /**< 真实提交三态。 */
    vireo_mysql_user_repository_error_t error; /**< service原始去敏诊断；未调用时零。 */
} vireo_auth_task_result_t;

/**
 * @brief 在当前OS worker核验task与可信上下文，并同步调用至多一次认证service
 *
 * @param[in] task
 *     必需存活task，只借至返回；REGISTER/LOGIN/RESUME为原完整wire；LOGOUT为可信Reactor创建的VAL1封装，不消费或销毁。
 * @param[in] context
 *     必需可信服务端快照，只借至返回；caller保证事件ID来源/唯一性、时钟域及新鲜度。
 * @param[in] options
 *     必需存活注册表和pool等待参数，只借至返回。
 * @param[in,out] repository
 *     必需由当前OS worker创建且无残留清理的repository，短借、同对象串行。
 * @param[in,out] gate
 *     必需全服务共享存活KDF gate，短借；本函数不创建或关闭。
 * @param[in] verifier
 *     必需已发布只读LOGIN验证器，包括REGISTER调用；短借，不逐请求重建。
 * @param[in,out] out
 *     必需独占结果存储；必需地址齐备后安全擦旧值，caller须已处理旧交付及清理责任。
 *
 * @retval VIREO_OK
 *     service确认提交或RESUME只读验证成功且本次清理完成；仍须按命令读取原始报告。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址NULL、无效操作注册表/审计ID或context不匹配完整task metadata。
 * @retval VIREO_RESULT_RANGE
 *     pool等待超过60000毫秒或LOGIN到期时间不晚于签发时间；也可能由service返回。
 * @retval VIREO_RESULT_PROTOCOL
 *     完整帧非法、sequence或command/operation不匹配，或service报告数据非法。
 * @retval VIREO_RESULT_CANCELLED
 *     执行前观察到取消，或service依赖关闭；以stage区分是否已调用。
 * @retval VIREO_RESULT_TIMEOUT
 *     now_ns >= deadline_ns时未调用service，或service某次pool等待超时。
 * @retval VIREO_RESULT_NOT_FOUND
 *     service统一认证拒绝；不区分缺失/错密/禁用。
 * @retval VIREO_RESULT_BUSY
 *     service的gate、pool或repository不可用。
 * @retval VIREO_RESULT_NO_MEMORY
 *     service计算或数据库资源分配失败。
 * @retval VIREO_RESULT_IO
 *     service安全随机源失败。
 * @retval VIREO_RESULT_DATABASE
 *     service数据库或清理失败；COMMITTED仍成立，UNKNOWN禁止自动重放。
 * @retval VIREO_RESULT_INTERNAL
 *     service内部依赖失败。
 *
 * @note 必需地址有NULL时保持out；其余正常返回均发布当前阶段/事实，保持errno。
 *       无动态分配，不持有网络对象；同步service可能阻塞。所有地址/存储互不重叠且不指errno。
 * @note context只验证形态和关联，不能认证调用者来源；TLS与LOGIN一次准入由可信上游保证，
 *       不因metadata匹配而认证用户，不重复准入。DEVICE仍仅是客户端标签，不作可信身份。
 * @note 只在service前检查取消/期限，执行中不抢断；提交后即使过期/取消也保留真实结果。
 *       每次调用都可能执行，caller每个task只能调一次，不得以返回错误自动重试。
 * @note task由thread_pool在callback后销毁并擦除；手动执行由caller结束借用后destroy。
 *       输出独立于task，读取/交付后用result_clear擦除；lookup/transaction/registration/resume/logout任一
 *       cleanup_pending时须保存repository并在同worker完成destroy，不能丢弃owner继续服务。
 * @note 独立task/result/repository可并发共享gate/verifier；生命周期由caller同步。
 *       不管理repository、不回投completion、不编码成功响应、不绑定Session，不支持异步取消/longjmp。
 */
vireo_result_t vireo_auth_task_execute(vireo_task_t const *task,
    vireo_auth_task_context_t const *context, vireo_auth_task_options_t const *options,
    vireo_mysql_user_repository_t *repository, vireo_auth_password_gate_t *gate,
    vireo_auth_login_verifier_t const *verifier, vireo_auth_task_result_t *out);

/**
 * @brief 交付/诊断处理结束后安全擦除整个认证task结果，可重复调用
 *
 * @param[in,out] result
 *     必需独占存活值，caller先保存提交及清理事实，不与errno重叠。
 *
 * @retval VIREO_OK
 *     全部存储已清零；不撤销Session、不销毁repository，也不清除其他副本。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     result为NULL。
 *
 * @note 无分配/I/O，保持errno；独立值可并发，同值访问需外部同步。
 */
vireo_result_t vireo_auth_task_result_clear(vireo_auth_task_result_t *result);

/**
 * Reactor-only：可信metadata的operation必须等于显式非零logout_operation；
 * wire恰32字节合法LOGOUT且sequence匹配，identity两字段非零，不证明其真实来源。
 * 必需wire/identity/out；*out入口NULL。budget正且<=task MAX；cancel可NULL且保活。
 * 先验证再创建56字节VAL1拥有型task；所有失败保持空out，不发号/登记/提交。
 * 原task错误透传，非法参数INVALID_ARGUMENT、畸形wire/关联PROTOCOL；保持errno。
 * 输入只借至返回，局部区擦除；成功caller owns且须destroy或真实交接一次。
 */
vireo_result_t vireo_auth_task_create_logout(vireo_task_metadata_t metadata,
    uint32_t logout_operation, uint8_t const *wire, size_t wire_size,
    vireo_auth_logout_identity_t const *identity, size_t allocation_budget,
    vireo_task_cancel_t *cancel, vireo_task_t **out);

/**
 * task/输出必需，expected_command只能是四认证命令，须caller按可信operation映射。
 * LOGOUT借VAL1后原wire并输出独立trusted目标；其余借原wire并输出零目标。
 * 严格核形态、命令/sequence；失败保持view/identity，issue每次重置，保持errno。
 * 返回INVALID_ARGUMENT/PROTOCOL或公开task查询错误；不消费task，无分配/I/O。
 * 借用只在task未修改/销毁期间有效，不能保留跨所有权交接。
 */
vireo_result_t vireo_auth_task_borrow_request(vireo_task_t const *task,
    vireo_command_t expected_command, vireo_auth_request_view_t *view,
    vireo_auth_logout_identity_t *identity, vireo_auth_request_issue_t *issue);


/** 显式四标签注册表校验及operation映射；无效表/未知operation返回0，保持errno，无I/O。 */
vireo_command_t vireo_auth_task_command(vireo_auth_task_options_t const *options, uint32_t operation);
#endif /* VIREO_SERVICE_AUTH_TASK_H */
