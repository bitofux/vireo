/* MySQL用户业务适配器：同worker账户/Session查询、注册/登录事务与清理责任。 */
#ifndef VIREO_PERSISTENCE_MYSQL_USER_REPOSITORY_H
#define VIREO_PERSISTENCE_MYSQL_USER_REPOSITORY_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <vireo/persistence/mysql_pool.h>
#include <vireo/security/password.h>
#include <vireo/security/session_token.h>

/** @brief 当前OS线程唯一owner，借用guard/pool；内部保存未完成清理责任。 */
typedef struct vireo_mysql_user_repository vireo_mysql_user_repository_t;

typedef enum vireo_mysql_registration_commit {
    VIREO_MYSQL_REGISTRATION_NOT_COMMITTED, /**< 未进入COMMIT execute；可能仍须清理未提交事务。 */
    VIREO_MYSQL_REGISTRATION_COMMITTED, /**< 已收到COMMIT成功响应，后续清理错误也保持。 */
    VIREO_MYSQL_REGISTRATION_UNKNOWN /**< COMMIT已进入execute但未得到完整成功确认。 */
} vireo_mysql_registration_commit_t;

typedef enum vireo_mysql_registration_conflict {
    VIREO_MYSQL_REGISTRATION_CONFLICT_NONE,
    VIREO_MYSQL_REGISTRATION_USERNAME_CONFLICT, /**< users INSERT执行返回1062。 */
    VIREO_MYSQL_REGISTRATION_REQUEST_CONFLICT /**< audit INSERT执行返回1062，不等于业务重放成功。 */
} vireo_mysql_registration_conflict_t;

typedef enum vireo_mysql_user_repository_stage {
    VIREO_MYSQL_USER_REPOSITORY_STAGE_NONE,
    VIREO_MYSQL_USER_REPOSITORY_STAGE_VALIDATE,
    VIREO_MYSQL_USER_REPOSITORY_STAGE_ALLOCATE,
    VIREO_MYSQL_USER_REPOSITORY_STAGE_ACQUIRE,
    VIREO_MYSQL_USER_REPOSITORY_STAGE_BORROW,
    VIREO_MYSQL_USER_REPOSITORY_STAGE_BEGIN,
    VIREO_MYSQL_USER_REPOSITORY_STAGE_USER,
    VIREO_MYSQL_USER_REPOSITORY_STAGE_ROOT,
    VIREO_MYSQL_USER_REPOSITORY_STAGE_AUDIT,
    VIREO_MYSQL_USER_REPOSITORY_STAGE_COMMIT,
    VIREO_MYSQL_USER_REPOSITORY_STAGE_ROLLBACK,
    VIREO_MYSQL_USER_REPOSITORY_STAGE_STATEMENT_CLOSE,
    VIREO_MYSQL_USER_REPOSITORY_STAGE_RELEASE,
    VIREO_MYSQL_USER_REPOSITORY_STAGE_ACCOUNT, /**< 登录锁行/状态与验密快照核验。 */
    VIREO_MYSQL_USER_REPOSITORY_STAGE_SESSION, /**< 创建Session。 */
    VIREO_MYSQL_USER_REPOSITORY_STAGE_LOGIN_UPDATE, /**< 单调更新用户登录时间。 */
    VIREO_MYSQL_USER_REPOSITORY_STAGE_CREDENTIALS, /**< 按身份key读取并校验凭据快照。 */
    VIREO_MYSQL_USER_REPOSITORY_STAGE_SESSION_LOOKUP, /**< 按digest核会话和账户有效性。 */
    VIREO_MYSQL_USER_REPOSITORY_STAGE_LOGOUT_USER, /**< 退出事务先锁用户。 */
    VIREO_MYSQL_USER_REPOSITORY_STAGE_LOGOUT_SESSION, /**< 再锁会话核属主/状态/时间。 */
    VIREO_MYSQL_USER_REPOSITORY_STAGE_SESSION_REVOKE /**< 写入当前会话撤销。 */
} vireo_mysql_user_repository_stage_t;

/** @brief 调用期只读短借；不含明文密码、SQL或任意审计detail。 */
typedef struct vireo_mysql_registration_input {
    const char *username; /**< 1..256字节；数据库再核合法utf8mb4及1..64字符。 */
    size_t username_length; /**< 精确字节数，不要求尾NUL。 */
    const void *username_key; /**< 上游规范化身份，1..256字节，按二进制唯一。 */
    size_t username_key_length; /**< 不在本层转小写/trim/Unicode归一化。 */
    const char *password_hash; /**< 1..127字节canonical PHC，不要求尾NUL。 */
    size_t password_hash_length; /**< inspect且m/t须等于create时策略，不执行KDF。 */
    unsigned char request_id[16]; /**< 固定16字节且至少一字节非零；不是业务幂等key。 */
    uint64_t occurred_at_ms; /**< caller显式UTC epoch毫秒，用于user/root/audit初始时间。 */
    uint64_t latency_us; /**< caller采集到调用前的请求耗时快照；不含本次DB执行。 */
} vireo_mysql_registration_input_t;

/** @brief 每次先重置；非OK也必须读取commit和cleanup_pending，不能只看返回码。 */
typedef struct vireo_mysql_registration_report {
    vireo_mysql_registration_commit_t commit; /**< 初始NOT_COMMITTED，UNKNOWN不推测成功。 */
    vireo_mysql_registration_conflict_t conflict; /**< 仅相应INSERT执行的1062分类。 */
    uint64_t user_id; /**< 仅COMMITTED非零，含后续清理失败；其他情况0。 */
    uint64_t root_node_id; /**< 同上；不能用AUTO_INCREMENT缺口推断失败或回滚。 */
    uint64_t audit_id; /**< 同上。 */
    bool rollback_confirmed; /**< 收到ROLLBACK完整成功响应的事实，与清理结果分开。 */
    bool cleanup_pending; /**< repo仍持有lease或statement，须同线程destroy，不能再register。 */
} vireo_mysql_registration_report_t;

/** @brief 无SQL/原始文本/用户名/PHC；主因与首清理错误独立保存。 */
typedef struct vireo_mysql_user_repository_error {
    vireo_mysql_user_repository_stage_t stage; /**< 首失败阶段，成功NONE。 */
    vireo_mysql_error_t database; /**< 首因来自statement时的无文本诊断。 */
    vireo_mysql_pool_error_t pool; /**< 首因来自pool时的无文本诊断。 */
    vireo_result_t cleanup_result; /**< 首清理失败，不覆盖主因；无则OK。 */
    vireo_mysql_user_repository_stage_t cleanup_stage; /**< 首清理失败阶段，无则NONE。 */
    vireo_mysql_error_t cleanup_database; /**< 首清理失败来自statement时的数值诊断。 */
    vireo_mysql_pool_error_t cleanup_pool; /**< 首清理失败来自pool时的数值诊断。 */
} vireo_mysql_user_repository_error_t;

/**
 * @brief 为当前数据库worker创建轻量repository；不借连接、不执行SQL。
 * @param thread 必需当前线程有效guard，须与pool同runtime，借用至destroy完成。
 * @param pool 必需存活共享pool，借用至destroy完成，不转移owner。
 * @param policy 必需合法password策略，复制值；注册只接收同create m/t的PHC。
 * @param out_repository 必需初值NULL的唯一owner地址；失败保持。
 * @param error 可NULL，每次重置。
 * @return OK；INVALID_ARGUMENT地址/guard/runtime/策略错误；NO_MEMORY申请失败。
 * @note 本头入口均保持errno；地址须存活、对齐、互不重叠且不指向errno。
 * 同一对象仅创建OS线程串行使用，不可跨线程交接；不保活guard/pool。
 */
vireo_result_t vireo_mysql_user_repository_create(vireo_mysql_thread_t *thread,
    vireo_mysql_pool_t *pool, const vireo_password_policy_t *policy,
    vireo_mysql_user_repository_t **out_repository, vireo_mysql_user_repository_error_t *error);

/**
 * @brief 借自己的一份pool lease，原子创建active user、active root与REGISTER成功审计。
 * @param repository 必需当前创建线程的存活对象，无残留lease/statement。
 * @param input 必需调用期不变输入；先检查地址/字节界/非零request_id/PHC再借池。
 * @param timeout_ms pool等待0..60000ms；不保证SQL或整次操作硬期限。
 * @param out_report 必需独占输出，每次先重置，包括非法参数或失败。
 * @param error 可NULL，每次先重置；首因优先于清理失败。
 * @return OK仅确认COMMIT并完成清理；INVALID_ARGUMENT/RANGE/PROTOCOL输入拒绝；
 * BUSY残留清理或池无容量；TIMEOUT/CANCELLED/NO_MEMORY/OVERFLOW/INTERNAL沿底层；
 * DATABASE语句失败、唯一冲突或内部固定SQL结果形状不符。
 * @note 工作者同步阻塞入口，不在Reactor执行；先在事务外生成PHC。
 * username字符数和UTF8由数据库核验；username_key由上游规范化，二者关系不在本层推导。
 * 固定SET autocommit=0/user/root/audit/COMMIT；所有值参数化，审计detail固定空。
 * 失败先销毁statement，再尝试显式ROLLBACK；未确认提交/回滚的连接DISCARD。
 * COMMIT进入execute后非OK即UNKNOWN，禁止自动重放；之后ROLLBACK不能消除此未知。
 * 已确认COMMIT后即使close/reset/release失败，COMMITTED和三个ID也须保留。
 * 若cleanup_pending，owner保存全部剩余责任；下一次register只返回BUSY，须destroy。
 * 数据库须已迁移且保持既定schema，无不受控trigger/DDL；本入口不提供漂移审计。
 */
vireo_result_t vireo_mysql_user_repository_register(vireo_mysql_user_repository_t *repository,
    const vireo_mysql_registration_input_t *input, uint32_t timeout_ms,
    vireo_mysql_registration_report_t *out_report, vireo_mysql_user_repository_error_t *error);

/** @brief 登录事务事实；与函数返回码分开，语义与注册三态相同。 */
typedef enum vireo_mysql_login_commit {
    VIREO_MYSQL_LOGIN_NOT_COMMITTED, /**< 未进入COMMIT execute，未提交事务可能仍待清理。 */
    VIREO_MYSQL_LOGIN_COMMITTED, /**< 已确认提交，之后清理失败也保持。 */
    VIREO_MYSQL_LOGIN_UNKNOWN /**< COMMIT execute已开始，未获完整成功确认；禁止自动重放。 */
} vireo_mysql_login_commit_t;
/** @brief 内部原因，不直接用作外部认证响应或授权依据。 */
typedef enum vireo_mysql_login_issue {
    VIREO_MYSQL_LOGIN_ISSUE_NONE,
    VIREO_MYSQL_LOGIN_USER_NOT_FOUND,
    VIREO_MYSQL_LOGIN_USER_DISABLED,
    VIREO_MYSQL_LOGIN_PASSWORD_CHANGED,
    VIREO_MYSQL_LOGIN_TIME_BEFORE_USER,
    VIREO_MYSQL_LOGIN_DIGEST_CONFLICT,
    VIREO_MYSQL_LOGIN_REQUEST_CONFLICT,
    VIREO_MYSQL_LOGIN_UNEXPECTED_RESULT
} vireo_mysql_login_issue_t;
/** @brief 可信服务已经在事务外验密/生成token；本层只借PHC快照，存储digest。 */
typedef struct vireo_mysql_login_input {
    uint64_t user_id; /**< 非零持久用户ID。 */
    const char *verified_password_hash; /**< 事务外验密所用的精确PHC快照，调用期只读短借。 */
    size_t verified_password_hash_length; /**< 1..127字节，inspect允许策略范围内的历史成本。 */
    vireo_session_token_digest_t token_digest; /**< 内嵌32字节摘要，所有位模式合法；不是bearer。 */
    uint64_t issued_at_ms; /**< caller显式UTC epoch毫秒，须不早于用户创建；也是audit时间。 */
    uint64_t expires_at_ms; /**< 必须严格大于issued，无隐式TTL计算或wall clock读取。 */
    unsigned char request_id[16]; /**< 固定非零事件ID，唯一(request_id,LOGIN)不是业务幂等。 */
    uint64_t latency_us; /**< 调用前请求耗时快照，不含本次数据库执行。 */
} vireo_mysql_login_input_t;
/** @brief 每次先重置；非OK也须检查commit及cleanup_pending。 */
typedef struct vireo_mysql_login_report {
    vireo_mysql_login_commit_t commit; /**< 初始NOT_COMMITTED，清理不改写COMMITTED/UNKNOWN。 */
    vireo_mysql_login_issue_t issue; /**< 初始NONE；拒绝/冲突/固定SQL形状问题。 */
    uint64_t session_id; /**< 只在COMMITTED发布，成功后清理失败仍保留。 */
    uint64_t audit_id; /**< 同上，审计target/session均为同次Session。 */
    bool rollback_confirmed; /**< 实际收到ROLLBACK成功响应，后续close失败也保持。 */
    bool cleanup_pending; /**< R仍拥有statement/lease，须同线程destroy，不能register/login。 */
} vireo_mysql_login_report_t;
/**
 * @brief 在用户行锁下核对active/已验密PHC快照，原子写Session、用户时间与LOGIN成功审计。
 * @param repository 当前创建OS线程存活R，无残留owner；沿用create/destroy生命周期。
 * @param input 必需调用期不变；caller须已真实验密并生成token/digest，本入口不证明验密。
 * @param timeout_ms pool等待0..60000ms，不约束SQL/行锁等待/整个调用的硬期限。
 * @param out_report 必需独占值，每次先清零，包括失败；IDs只确认COMMIT才发布。
 * @param error 可NULL，每次重置；沿用首因与首清理错误优先级，无输入/原始错误文本。
 * @return OK确认提交且清理完成；NOT_FOUND为无用户/disabled/PHC变化（由issue区分，
 * 外部服务统一映射认证失败）；RANGE为长度/时间/timeout越界或issued早于用户创建；
 * INVALID_ARGUMENT地址/guard/零user或request错误；PROTOCOL非法PHC；
 * DATABASE为SQL/摘要或审计唯一冲突/固定结果形状；其他资源错误沿底层。
 * @note 先inspect输入PHC，允许策略内历史m/t，不执行KDF；caller须保留原token并仅按确认
 * 提交事实决定发放；UNKNOWN不得自动重放/再生成token假定上次失败。只存digest不存bearer。
 * @note SELECT FOR UPDATE后精确比较PHC快照；写active Session、last_seen=issued；
 * last_login/updated均取原值与issued的最大值，UPDATE changed rows=0也是合法成功。
 * 审计LOGIN=2/SESSION=2/OK=0、detail空；失败与COMMIT未知/成功后清理错误沿注册规则。
 * @note 同R串行、保持errno、地址不重叠、worker阻塞、schema无不受控trigger/DDL、
 * 无重试/重连/自动refill/线程取消。完整查用户/验密服务、失败审计、撤销/授权另属消费者。
 */
vireo_result_t vireo_mysql_user_repository_login(vireo_mysql_user_repository_t *repository,
    const vireo_mysql_login_input_t *input, uint32_t timeout_ms,
    vireo_mysql_login_report_t *out_report, vireo_mysql_user_repository_error_t *error);

/**
 * @brief 同创建线程销毁对象；结束残留statement，DISCARD残留lease，绝不重放业务或COMMIT。
 * @param repository 必需唯一owner地址，空owner幂等OK。
 * @param error 可NULL，每次重置，保存首清理失败。
 * @return OK全部释放；INVALID_ARGUMENT地址/线程/guard错误，owner保持；
 * BUSY/DATABASE/INTERNAL等底层清理错误；资源未全部消费则owner保持，全部消费则清NULL。
 * @note 非OK也检查owner是否已清NULL，不能重复销毁已消费对象。
 * pool与guard须一直存活；先在worker内destroy，再detach/join，最后管理方destroy pool/runtime。
 * 同步设施异常不保证一般恢复或强行释放；不得丢弃仍非NULL的owner。
 */
vireo_result_t vireo_mysql_user_repository_destroy(vireo_mysql_user_repository_t **repository,
    vireo_mysql_user_repository_error_t *error);

/** @brief 账户状态快照；NONE仅用于未发布/已清除的凭据值。 */
typedef enum vireo_mysql_user_status {
    VIREO_MYSQL_USER_STATUS_NONE = 0, /**< 无可用账户快照。 */
    VIREO_MYSQL_USER_STATUS_ACTIVE = 1, /**< 查询时账户active，不代表认证或之后仍有效。 */
    VIREO_MYSQL_USER_STATUS_DISABLED = 2 /**< 查询时账户disabled，服务不得据此发放凭据。 */
} vireo_mysql_user_status_t;

/** @brief caller拥有的验密材料副本；不借用R/连接，不得记录或发往客户端。 */
typedef struct vireo_mysql_user_credentials {
    uint64_t user_id; /**< OK查询后的非零持久ID；未发布为0。 */
    vireo_mysql_user_status_t status; /**< OK为ACTIVE/DISABLED；未发布为NONE。 */
    char password_hash[VIREO_PASSWORD_ENCODED_CAPACITY]; /**< PHC内嵌副本，成功补NUL，余部为零。 */
    size_t password_hash_length; /**< 精确PHC长度1..127，不含NUL；未发布为0。 */
} vireo_mysql_user_credentials_t;

/** @brief 查询输出及资源清理事实；每次先清零。 */
typedef struct vireo_mysql_credentials_report {
    bool found; /**< 仅完整读取及清理均成功时为true；不是验密或授权结果。 */
    bool cleanup_pending; /**< R仍持有statement/lease，须同worker destroy，不能再查询/注册/登录。 */
} vireo_mysql_credentials_report_t;

/**
 * @brief 按二进制username_key查询拥有型ID/状态/PHC快照，全部清理成功才发布。
 *
 * @param[in] repository
 *     必需当前创建OS线程存活R；同对象串行调用，guard/pool须存活。
 * @param[in] username_key
 *     必需调用期只读字节区，借至返回；允许NUL，不做大小写/空白/Unicode规范化。
 * @param[in] username_key_length
 *     精确1..256字节，必须与注册时上游规范化政策一致。
 * @param[in] timeout_ms
 *     池等待0..60000ms，不约束SQL或整个调用的硬期限。
 * @param[in,out] out_credentials
 *     必需独占输出；入口显式清除旧内容，非OK保持全零，OK才发布完整副本。
 * @param[out] out_report
 *     必需独占报告，每次重置；即使失败也须读cleanup_pending。
 * @param[out] error
 *     可NULL，每次重置；保存首因及首清理错误，无key/PHC/原始SQL错误文本。
 *
 * @retval VIREO_OK
 *     唯一账户快照与PHC格式/策略获准，found=true且已归还连接；不代表验密成功。
 * @retval VIREO_RESULT_NOT_FOUND
 *     没有此key，found=false；对外认证响应由服务统一。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址/当前guard错误。
 * @retval VIREO_RESULT_RANGE
 *     key长度/等待越界，或存储PHC成本超过复制的max_verify策略。
 * @retval VIREO_RESULT_PROTOCOL
 *     存储PHC不是获准的canonical密码记录。
 * @retval VIREO_RESULT_DATABASE
 *     SQL/读取/关闭失败或固定结果行形状无效。
 * @retval VIREO_RESULT_BUSY
 *     R有残留owner或池暂不可用。
 * @retval VIREO_RESULT_TIMEOUT
 *     池等待超时。
 * @retval VIREO_RESULT_CANCELLED
 *     池已关闭。
 * @retval VIREO_RESULT_NO_MEMORY
 *     底层statement内存申请失败。
 * @retval VIREO_RESULT_INTERNAL
 *     底层资源同步等内部错误。
 *
 * @note 输入/输出地址须存活、对齐、互不重叠且不指向errno；所有路径保持errno。
 * @note disabled也返回内部快照；服务检查status再决定验密/统一失败响应。
 *     不执行KDF，不写业务表/审计，不开启写事务、不重试/自动补槽。只读也可能阻塞worker。
 * @note PHC按历史成本inspect；结果可在连接归还后验密。验密成功后仍须由login行锁重核
 *     active/同PHC快照，查询结果本身不是授权依据。用完须clear，其他副本由caller清理。
 */
vireo_result_t vireo_mysql_user_repository_find_credentials(vireo_mysql_user_repository_t *repository,
    const void *username_key, size_t username_key_length, uint32_t timeout_ms,
    vireo_mysql_user_credentials_t *out_credentials, vireo_mysql_credentials_report_t *out_report,
    vireo_mysql_user_repository_error_t *error);

/**
 * @brief 以volatile字节写清除当前凭据对象的全部存储，允许重复调用。
 *
 * @param[in,out] credentials
 *     必需独占可写值，不得指向errno；不借用数据库对象、不free。
 *
 * @retval VIREO_OK
 *     当前对象全部字节清零；不清其他副本、不撤销账户或Session。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     credentials为NULL。
 *
 * @note 保持errno，无分配/I/O；独立值thread-safe，共享值须外部同步；不能保证清除
 *     编译器/底层驱动/系统可能产生的全部历史副本，不可替代访问控制。
 */
vireo_result_t vireo_mysql_user_credentials_clear(vireo_mysql_user_credentials_t *credentials);
/** @brief 内部失效原因；不直接映射外部响应，不表示可授权身份。 */
typedef enum vireo_mysql_session_issue {
    VIREO_MYSQL_SESSION_ISSUE_NONE,
    VIREO_MYSQL_SESSION_NOT_FOUND,
    VIREO_MYSQL_SESSION_REVOKED,
    VIREO_MYSQL_SESSION_USER_DISABLED,
    VIREO_MYSQL_SESSION_NOT_YET_VALID,
    VIREO_MYSQL_SESSION_EXPIRED
} vireo_mysql_session_issue_t;

/** @brief 完整查询成功后caller拥有的身份快照，无token/digest/数据库借用。 */
typedef struct vireo_mysql_session_identity {
    uint64_t session_id; /**< 成功非零持久会话ID；非OK为0。 */
    uint64_t user_id; /**< 成功非零持久用户ID；非OK为0。 */
    uint64_t issued_at_ms; /**< 签发UTC epoch毫秒；成功允许0。 */
    uint64_t expires_at_ms; /**< 绝对到期UTC epoch毫秒，严格大于issued；now等于此值无效。 */
} vireo_mysql_session_identity_t;

/** @brief 每次重置；业务失效与资源故障分别报告。 */
typedef struct vireo_mysql_session_report {
    bool valid; /**< 仅返回OK且已关闭语句/归还连接时true；不是文件权限证明。 */
    vireo_mysql_session_issue_t issue; /**< NOT_FOUND的内部原因；其余NONE，清理错误不覆盖既有失效原因。 */
    bool cleanup_pending; /**< R仍有statement/lease，所有业务方法BUSY，须同worker destroy。 */
} vireo_mysql_session_report_t;

/**
 * @brief 按摘要与显式时间只读核Session/账户，全部读取及清理成功才发布身份。
 * @param[in] repository
 *     必需当前创建OS线程的存活R；guard/pool存活，同对象串行使用。
 * @param[in] token_digest
 *     必需完整32字节摘要，调用期只读短借；全部位模式（包括全零）合法，不接原token。
 * @param[in] now_ms
 *     caller显式UTC epoch毫秒；需issued<=now<expires，允许0..UINT64_MAX，不读取隐藏时钟。
 * @param[in] timeout_ms
 *     池等待0..60000毫秒，不保证SQL/整次调用硬期限。
 * @param[out] out_identity
 *     必需独占可写输出，每次先全清零；非OK不发布任何身份。
 * @param[out] out_report
 *     必需独占报告，每次重置；非OK也须读取cleanup_pending，issue仅内部诊断。
 * @param[out] error
 *     可NULL，每次重置；首因/首清理分别保存，无token/digest/原始SQL文本。
 * @retval VIREO_OK
 *     唯一合法行、会话active未撤销、账户active、时间有效，valid=true且资源已归还。
 * @retval VIREO_RESULT_NOT_FOUND
 *     缺失/撤销/账户禁用/签发前/过期，valid=false；issue给内部原因，身份全零。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址/guard/OS线程错误。
 * @retval VIREO_RESULT_RANGE
 *     池等待越界。
 * @retval VIREO_RESULT_DATABASE
 *     SQL/读取/关闭或固定行形状错误，包括NULL、坏数字、状态/时间关系不符。
 * @retval VIREO_RESULT_BUSY
 *     R残留清理或池耗尽。
 * @retval VIREO_RESULT_TIMEOUT
 *     池等待到期。
 * @retval VIREO_RESULT_CANCELLED
 *     池已关闭。
 * @retval VIREO_RESULT_NO_MEMORY
 *     底层资源内存分配失败。
 * @retval VIREO_RESULT_INTERNAL
 *     底层资源同步等内部失败；其他资源错误沿底层。
 * @note 所有地址存活、对齐、互不重叠且不指向errno；所有路径保持errno。
 *     身份是独立普通值；调用者同步后可交接，不依赖连接或R生命周期。
 * @note 固定SELECT/JOIN的一次读视图，不写last_seen/审计、不续期/撤销、不重试/refill。
 *     多重失效优先级为撤销、账户禁用、签发前、过期；先核整行形状及唯一性。
 * @note 快照之后可能撤销/禁用；本接口不提供跨后续业务操作的原子授权。
 *     文件属主权限、连接绑定/缓存、敏感写事务内重核及统一对外响应由消费者负责。
 */
vireo_result_t vireo_mysql_user_repository_find_session(vireo_mysql_user_repository_t *repository,
    const vireo_session_token_digest_t *token_digest, uint64_t now_ms, uint32_t timeout_ms,
    vireo_mysql_session_identity_t *out_identity, vireo_mysql_session_report_t *out_report,
    vireo_mysql_user_repository_error_t *error);
/** @brief 退出提交事实；UNKNOWN禁止自动重放，不把效果收敛当原请求回执。 */
typedef enum vireo_mysql_logout_commit {
    VIREO_MYSQL_LOGOUT_NOT_COMMITTED,
    VIREO_MYSQL_LOGOUT_COMMITTED,
    VIREO_MYSQL_LOGOUT_UNKNOWN
} vireo_mysql_logout_commit_t;
/** @brief 内部退出拒绝原因，不直接作为对外响应或授权依据。 */
typedef enum vireo_mysql_logout_issue {
    VIREO_MYSQL_LOGOUT_ISSUE_NONE,
    VIREO_MYSQL_LOGOUT_USER_NOT_FOUND,
    VIREO_MYSQL_LOGOUT_SESSION_NOT_FOUND,
    VIREO_MYSQL_LOGOUT_OWNER_MISMATCH,
    VIREO_MYSQL_LOGOUT_TIME_BEFORE_ISSUED,
    VIREO_MYSQL_LOGOUT_REQUEST_CONFLICT,
    VIREO_MYSQL_LOGOUT_UNEXPECTED_RESULT
} vireo_mysql_logout_issue_t;
/** @brief 可信服务已确认的身份与事件；无token/摘要/SQL，调用期只读短借。 */
typedef struct vireo_mysql_logout_input {
    uint64_t user_id; /**< 非零持久用户ID，不能从未认证客户端数值直接信任。 */
    uint64_t session_id; /**< 非零持久会话ID，不是网络短handle。 */
    unsigned char request_id[16]; /**< 至少一字节非零；审计唯一事件ID，不是完整幂等回执key。 */
    uint64_t occurred_at_ms; /**< caller显式UTC epoch毫秒；须不早于会话issued。 */
    uint64_t latency_us; /**< 调用前耗时快照，微秒；不含本次数据库执行。 */
} vireo_mysql_logout_input_t;
/** @brief 每次重置；非OK也必须读commit与cleanup_pending。 */
typedef struct vireo_mysql_logout_report {
    vireo_mysql_logout_commit_t commit; /**< 默认NOT_COMMITTED，确认COMMIT才COMMITTED。 */
    vireo_mysql_logout_issue_t issue; /**< 内部领域/固定SQL异常分类，无则NONE。 */
    uint64_t session_id; /**< 仅COMMITTED发布，否则0。 */
    uint64_t audit_id; /**< 仅首次撤销COMMITTED有新ID；已撤销确认或非COMMITTED均0。 */
    uint64_t revoked_at_ms; /**< 仅COMMITTED发布；重复保留首次值，可为0。 */
    bool already_revoked; /**< 仅COMMITTED时说明锁行时已撤销；不创建重复审计。 */
    bool rollback_confirmed; /**< 已收到完整ROLLBACK成功响应，独立于其后清理。 */
    bool cleanup_pending; /**< R仍有statement/lease，五业务方法BUSY，须同worker destroy。 */
} vireo_mysql_logout_report_t;

/**
 * @brief 核属主后原子撤销一个Session并写LOGOUT成功审计，重复退出保持首次事实。
 * @param[in] repository
 *     必需创建OS线程的存活R，同对象串行；guard/pool借用存活。
 * @param[in] input
 *     必需只读完整值；服务已验证身份，非零user/session/request_id；本层再核Session属主。
 * @param[in] timeout_ms
 *     池等待0..60000毫秒，不是SQL/行锁/整次事务硬期限。
 * @param[out] out_report
 *     必需独占输出，每次重置；非OK也检查提交事实和未消费资源。
 * @param[out] error
 *     可NULL，每次重置，保存首因/首清理数值诊断，无凭据或原始SQL文本。
 * @retval VIREO_OK
 *     COMMIT确认且清理成功；首次撤销与成功审计一起落库，或已撤销状态得到确认。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址/OS线程/guard错误、零user/session/request_id。
 * @retval VIREO_RESULT_RANGE
 *     等待越界，或occurred早于issued（该分支尝试回滚）。
 * @retval VIREO_RESULT_NOT_FOUND
 *     无user/session或属主不符；内部issue区分，尝试回滚。
 * @retval VIREO_RESULT_DATABASE
 *     SQL失败/固定行或DML形状错误/审计唯一冲突，提交事实另读commit。
 * @retval VIREO_RESULT_BUSY
 *     R残留清理或池无容量。
 * @retval VIREO_RESULT_TIMEOUT
 *     池等待到期。
 * @retval VIREO_RESULT_CANCELLED
 *     池已关闭。
 * @retval VIREO_RESULT_NO_MEMORY
 *     底层内存分配失败。
 * @retval VIREO_RESULT_INTERNAL
 *     底层同步等内部失败；其他资源错误沿底层。
 * @note 地址存活、对齐、互不重叠且不指向errno；所有路径保持errno，同步阻塞worker入口。
 * @note 固定user→session锁顺序；disabled账户/expired会话也可撤销；occurred>=issued，
 *     不改变last_seen/expiry/user时间。已撤销保留原revoked_at，跳UPDATE/审计但仍确认COMMIT。
 * @note 审计固定LOGOUT=3、SESSION=2、OK=0、空detail；仅其INSERT执行1062分类REQUEST_CONFLICT。
 *     COMMIT execute已开始未获确认则UNKNOWN，不重试；重复效果收敛不提供原请求恢复回执。
 * @note COMMITTED后close/release失败也保持全部已提交字段；其他状态ID/时间/重复标志不发布。
 *     未提交时先结束statement再尝试ROLLBACK；owner未消费则留R，五业务方法共享门禁。
 * @note 不接原token，不自动解绑连接/撤销其他会话/广播缓存；可信身份来源与网络动作由调用方负责。
 */
vireo_result_t vireo_mysql_user_repository_logout(vireo_mysql_user_repository_t *repository,
    const vireo_mysql_logout_input_t *input, uint32_t timeout_ms,
    vireo_mysql_logout_report_t *out_report, vireo_mysql_user_repository_error_t *error);
typedef struct vireo_mysql_auth_failure_input {
    unsigned char request_id[16];
    uint64_t occurred_at_ms, latency_us;
    uint16_t action, status;
    uint8_t origin;
} vireo_mysql_auth_failure_input_t;
typedef enum vireo_mysql_auth_failure_commit {
    VIREO_MYSQL_AUTH_FAILURE_NOT_COMMITTED = 0,
    VIREO_MYSQL_AUTH_FAILURE_COMMITTED,
    VIREO_MYSQL_AUTH_FAILURE_UNKNOWN
} vireo_mysql_auth_failure_commit_t;
typedef struct vireo_mysql_auth_failure_report {
    vireo_mysql_auth_failure_commit_t commit;
    uint64_t audit_id; /* 仅COMMITTED非零；与函数rc分开。 */
    bool cleanup_pending; /* 同线程repository清理义务，不得丢失。 */
} vireo_mysql_auth_failure_report_t;

/**
 * @brief 在独立事务中追加一条无身份的固定失败审计
 * @param[in,out] repository 必需创建OS线程的存活owner，入口无statement/lease残留。
 * @param[in] input 必需独立值；ID非零、action1..4、失败status白名单、origin1/2。
 * @param[out] report 必需独立报告，覆盖commit/audit_id/cleanup_pending；非OK也可能COMMITTED/UNKNOWN。
 * @param[out] error 可NULL独立去敏诊断，覆盖首因/清理结果，不含原生错误文本。
 * @retval VIREO_OK COMMIT已确认且本次资源清理成功。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 必需地址、同线程owner或输入形态非法。
 * @retval VIREO_RESULT_BUSY 原owner有残留或独立pool无立即可用连接，不等待(0ms)。
 * @retval VIREO_RESULT_CANCELLED 独立pool已关闭。
 * @retval VIREO_RESULT_DATABASE SQL/结果形态失败，包括唯一(request_id,action)冲突。
 * @return 其他公共pool/statement错误原样透传，保实际残留供同线程destroy。
 * @note SET autocommit=0→固定六参数INSERT→COMMIT；只确定未提交才尝试ROLLBACK。
 *     actor/target为NULL、target_type0；detail仅source=reactor/worker，不接用户名/IP/token/任意文本。
 *     本入口可阻塞SQL，只供专用writer；不改业务表、不重放、不支持POSIX取消或硬期限。
 *     基本可写输出覆盖；地址有效对齐、互不重叠且不指向errno，保持errno。
 */
vireo_result_t vireo_mysql_user_repository_append_auth_failure(
    vireo_mysql_user_repository_t *repository,
    vireo_mysql_auth_failure_input_t const *input,
    vireo_mysql_auth_failure_report_t *report,
    vireo_mysql_user_repository_error_t *error);


#endif
