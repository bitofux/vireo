/*
 * PROJECT : VIREO
 * FILE    : auth_worker.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-20
 * BRIEF   : 同OS worker的一次认证执行及可保留的失败清理责任。
 */
#ifndef VIREO_SERVICE_AUTH_WORKER_H
#define VIREO_SERVICE_AUTH_WORKER_H
#include <vireo/service/auth_task_context.h>
#include <vireo/service/auth_completion.h>

/** 当前OS worker独占的一次执行owner；不拥有task，不允许跨线程移动。 */
typedef struct vireo_auth_worker vireo_auth_worker_t;

/** 全部长期短借关联，须活到本对象destroy清空owner；不转移依赖所有权。 */
typedef struct vireo_auth_worker_resources {
    vireo_mysql_runtime_t *runtime; /**< 已由管理端创建的存活MySQL根。 */
    vireo_mysql_pool_t *database; /**< 同runtime已装配数据库池，不由本层补槽。 */
    vireo_auth_password_gate_t *gate; /**< 全服务共享KDF gate。 */
    vireo_auth_login_verifier_t const *verifier; /**< 已发布只读验证器，寿命覆盖worker。 */
    vireo_completion_queue_t *queue; /**< 本认证注册表的专用完成队列，consumer须持续运行。 */
    vireo_notifier_t *notifier; /**< 对应queue的存活提示源。 */
    vireo_auth_failure_audit_t *audit; /**< 可NULL；去敏失败事件队列，只借至worker退出。 */
} vireo_auth_worker_resources_t;

/** 无默认时限或隐式扩容；与可信提交端采用同一注册表/固定请求时长。 */
typedef struct vireo_auth_worker_options {
    vireo_auth_task_options_t execution; /**< 四认证命令不同非零operation，pool等待≤60000ms。 */
    vireo_password_policy_t password; /**< 复制给repository，run创建repository时由原入口验证。 */
    uint64_t request_timeout_ns; /**< 正固定时长；received=可信task.deadline减此值，不能来自客户端。 */
    uint64_t session_lifetime_ms; /**< 正显式LOGIN寿命，UTC加法溢出由context报告。 */
    size_t completion_allocation_budget; /**< 正且≤completion硬限，原入口检查实际所需字节。 */
    size_t max_memory_bytes; /**< 本控制块预算，正且≤64MiB，不含DB/KDF/task/completion。 */
} vireo_auth_worker_options_t;

/** 单次清理尝试；返回码与实际owner是否已消费分别观察，不包含token。 */
typedef struct vireo_auth_worker_cleanup_report {
    bool repository_called; /**< 本次是否尝试一次repository destroy。 */
    vireo_result_t repository_result; /**< 上述原结果，不覆盖其他阶段。 */
    vireo_mysql_user_repository_error_t repository_error; /**< 上述原去敏诊断。 */
    bool detach_called; /**< 仅repository owner已NULL时尝试guard detach。 */
    vireo_result_t detach_result; /**< 本次原detach结果。 */
    bool completion_called; /**< 是否尝试destroy本层未交接的completion，绝不触碰已交接对象。 */
    vireo_result_t completion_result; /**< 本次原completion destroy结果。 */
    bool repository_pending, thread_pending, completion_pending; /**< 返回时各实际owner仍非NULL。 */
} vireo_auth_worker_cleanup_report_t;

/** 一次run保存的真实进度；重入拒绝返回相同快照，不表示再次调用依赖。 */
typedef struct vireo_auth_worker_report {
    bool attempted; /**< run已永久消耗一次机会，即使前置检查失败也不复用。 */
    bool task_validated; /**< 完整帧、sequence/operation、可信deadline时长关系通过。 */
    vireo_task_metadata_t metadata; /**< inspect成功后保存的独立历史请求值。 */
    vireo_command_t command; /**< decode成功的认证命令；不证明用户身份。 */
    vireo_result_t work_result; /**< 前置/采样/认证原结果，与发布及清理结果分开。 */
    vireo_auth_task_stage_t work_stage; /**< execute原阶段；execute未调用时为CONTEXT。 */
    vireo_auth_request_issue_t request_issue; /**< 前置解析原诊断。 */
    bool attach_called, repository_called, capture_called, execute_called; /**< 各依赖是否实际调用一次。 */
    vireo_mysql_error_t attach_error; /**< attach原去敏诊断。 */
    vireo_auth_context_error_t context_error; /**< 可信采样原诊断。 */
    vireo_mysql_user_repository_error_t work_error; /**< repository create或execute原去敏诊断。 */
    vireo_mysql_registration_report_t registration; /**< 原注册三态及清理事实，不含凭据。 */
    vireo_mysql_credentials_report_t lookup; /**< 原LOGIN查询清理事实，不含PHC。 */
    vireo_mysql_login_report_t transaction; /**< 原LOGIN事务三态及清理事实，不含token。 */
    vireo_auth_worker_cleanup_report_t cleanup; /**< run发布前的那一次资源清理尝试。 */
    bool publish_called; /**< 已通过task前置才尝试一次专用发布，包括前置资源/采样失败。 */
    vireo_result_t publish_result; /**< 专用publish原返回，不代表业务提交。 */
    vireo_auth_completion_publish_report_t publication; /**< 原真实交接/通知报告。 */
    bool completion_pending; /**< run返回时对象保存未交接的completion；destroy显式丢弃。 */
    vireo_mysql_session_identity_t resume_identity; /**< 只读核验的独立身份，不是提交事实。 */
    vireo_mysql_session_report_t resume_report; /**< 原valid和清理义务。 */
    vireo_auth_logout_identity_t logout_target; /**< Reactor可信快照，非客户端指定。 */
    vireo_mysql_logout_report_t logout_report; /**< 原退出三态、审计及清理事实。 */
} vireo_auth_worker_report_t;

/**
 * @brief 在当前OS worker创建一次执行和清理owner，尚不attach或执行任务
 *
 * @param[in] resources
 *     必需六项存活关联，复制指针借至destroy；caller保证配对与寿命。
 * @param[in] options
 *     必需显式配置，复制值；password策略由run的repository create验证。
 * @param[out] owner
 *     必需独占空owner地址；成功由同一OS worker调用run/destroy。
 *
 * @retval VIREO_OK
 *     已分配完整控制块，没有线程/DB子资源或业务动作。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需NULL、非空owner、零时长/预算或零/相同operation。
 * @retval VIREO_RESULT_RANGE
 *     pool等待/完成申请/对象预算超硬限，或对象预算不足。
 * @retval VIREO_RESULT_NO_MEMORY
 *     固定控制块分配失败，owner保持。
 *
 * @note 全路径保持errno；无线程创建，不是thread_pool callback本身。
 *       不支持已在该OS线程attach其他MySQL guard时run，不管理外部guard。
 *       地址独立有效且不重叠；当前线程绑定由pthread_self记录，不能跨线程移交。
 */
vireo_result_t vireo_auth_worker_create(vireo_auth_worker_resources_t const *resources,
    vireo_auth_worker_options_t const *options, vireo_auth_worker_t **owner);

/**
 * @brief 核验完整task，至多执行一次认证，清理DB资源后发布原业务事实
 *
 * @param[in,out] worker
 *     必需当前创建OS线程的独占存活owner；一次run后只能destroy。
 * @param[in] task
 *     必需可信TLS/准入端提交的完整帧，只借至返回，不保存地址，不销毁。
 * @param[out] report
 *     必需独立去敏快照，基本拒绝零；重复run返回已保存的原快照。
 *
 * @retval VIREO_OK
 *     工作、当次DB资源清理及完成交接/通知均成功；仍需destroy对象。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需NULL、跨线程调用或task命令/sequence/operation关联不匹配。
 * @retval VIREO_RESULT_BUSY
 *     本owner已尝试run，未再次执行或发布；也可能是依赖原结果。
 * @retval VIREO_RESULT_PROTOCOL
 *     完整task帧解析失败，未attach/执行/发布。
 * @retval VIREO_RESULT_RANGE
 *     task.deadline小于固定timeout，或原依赖拒绝范围。
 * @return 原工作首错优先，其次资源清理首错，再次publish原错；原业务拒绝亦非OK。
 *
 * @note 顺序：task前置→attach→repository create→可信采样→execute一次→
 *       repository destroy一次→owner已空才detach→publish一次→擦局部context/result。
 *       前置通过后的attach/create/capture失败产生匹配该task的未提交失败投影。
 *       cleanup非OK不改写COMMITTED或UNKNOWN，也不自动重放/再次入队。
 * @note 可信received仅由deadline减同一固定timeout恢复提交采样，不是首字节时间；
 *       caller必须保证task来源和该政策一致，普通metadata不能自行证明信任。
 * @note run后不保存task/密码/token结果；未交接completion自身仍含敏感独立投影。
 *       非OK同样读取原publication与pending；destroy只丢弃未交接结果并清剩余资源。
 *       没有完成项时上游仍有inflight义务，启动管理方须监控失败并关闭/清退客户。
 * @note 同OS worker串行、全调用POSIX取消禁用；可能等待DB/KDF/完成队列，consumer须
 *       并行腾空间，唯一Reactor不可阻塞join。保持errno，不访问网络对象。
 */
vireo_result_t vireo_auth_worker_run(vireo_auth_worker_t *worker, vireo_task_t const *task,
    vireo_auth_worker_report_t *report);

/**
 * @brief 同OS worker逐项清理剩余owner，全部消费后擦对象、free并清NULL
 *
 * @param[in,out] owner
 *     必需独占owner地址，*owner允许NULL；非空时仅创建OS线程调用。
 * @param[out] report
 *     必需独立可写输出，每次覆盖本次尝试和返回时owner事实。
 *
 * @retval VIREO_OK
 *     本次清理全部成功；空owner幂等成功。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需NULL或跨线程，owner保持，无资源动作。
 * @return repository、detach、completion清理的首个原错误；非OK也可能已清空owner。
 *
 * @note 每项至多一次；repository owner未空绝不detach，即使其错误已经报告。
 *       未交接completion只destroy，不补发布或通知；已交接对象不再归本层。
 *       剩余任何owner时保对象，caller须在同OS worker继续收尾；不允许丢owner后
 *       退出callback/线程，不以join代替清理，不保证损坏同步一般可恢复。
 *       启动层必须决定无法清理时的驻留/故障升级政策，本层不自旋或强行跨线程释放。
 * @note 不执行认证/COMMIT、不等待队列容量；DB清理可能阻塞。POSIX取消禁用，保持errno。
 *       依赖仍须存活；独立worker可并发，同owner及报告访问需外部同步。
 */
vireo_result_t vireo_auth_worker_destroy(vireo_auth_worker_t **owner,
    vireo_auth_worker_cleanup_report_t *report);
#endif
