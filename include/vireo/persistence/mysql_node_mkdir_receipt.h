/*
 * PROJECT : VIREO
 * FILE    : mysql_node_mkdir_receipt.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-23
 * BRIEF   : 持久成功回执与原子目录创建合同。
 */
#ifndef VIREO_PERSISTENCE_MYSQL_NODE_MKDIR_RECEIPT_H
#define VIREO_PERSISTENCE_MYSQL_NODE_MKDIR_RECEIPT_H
#include <vireo/persistence/mysql_node_repository.h>

/** @brief 用户/命令作用域的逻辑操作键，精确16字节且非全零。 */
#define VIREO_MYSQL_NODE_MKDIR_KEY_BYTES ((size_t)16)
/** @brief 本版不可变请求及成功结果格式，数据库仅开放1。 */
#define VIREO_MYSQL_NODE_MKDIR_RECEIPT_FORMAT UINT16_C(1)

/** @brief 已建立的逻辑成功事实，与本次COMMIT及函数rc分别判断。 */
typedef enum vireo_mysql_node_mkdir_effect {
    VIREO_MYSQL_NODE_MKDIR_EFFECT_NONE = 0, /**< 本次未建立可发布的成功事实，不证明历史未成功。 */
    VIREO_MYSQL_NODE_MKDIR_EFFECT_CREATED, /**< 本次完整COMMIT确认，新目录/审计/回执一起提交。 */
    VIREO_MYSQL_NODE_MKDIR_EFFECT_RECOVERED /**< 当前授权下匹配已提交回执；本次未执行COMMIT。 */
} vireo_mysql_node_mkdir_effect_t;

/** @brief 同键重试保持parent/name/key，执行事件request_id独立于该键。 */
typedef struct vireo_mysql_node_mkdir_once_input {
    uint64_t parent_id; /**< 非零原父ID，0不表示根；命中回执时不要求父现在仍存在。 */
    const unsigned char *name; /**< 必需稳定只读短借字节；不要求尾NUL，不保存此指针。 */
    size_t name_length; /**< 1..255字节；本层核DDL，生产UTF-8/控制字符/NFC由可信上游核。 */
    unsigned char idempotency_key[VIREO_MYSQL_NODE_MKDIR_KEY_BYTES]; /**< 非全零，稳定逻辑身份。 */
    unsigned char request_id[16]; /**< 非全零可信全局审计事件ID，仅新建分支使用，不是客户端键。 */
} vireo_mysql_node_mkdir_once_input_t;

/** @brief 三个独立维度：本次提交、历史成功事实、资源清理；不能只看rc。 */
typedef struct vireo_mysql_node_mkdir_once_report {
    vireo_mysql_node_mkdir_commit_t commit; /**< 仅本次事务：默认NOT_COMMITTED，UNKNOWN不能猜回滚。 */
    vireo_mysql_node_mkdir_effect_t effect; /**< NONE/CREATED/RECOVERED；已发布事实不被清理失败清除。 */
    vireo_mysql_node_issue_t issue; /**< 沿旧领域诊断，另含IDEMPOTENCY_CONFLICT/RECEIPT_INVALID。 */
    uint64_t node_id; /**< effect非NONE才非零，历史原创建ID，不保证当前仍活动。 */
    uint64_t audit_id; /**< effect非NONE才非零，原成功审计ID；恢复不追加成功审计。 */
    unsigned char idempotency_key[VIREO_MYSQL_NODE_MKDIR_KEY_BYTES]; /**< effect非NONE才复制原键，其余全零。 */
    bool rollback_confirmed; /**< 本次收到了ROLLBACK成功响应；不撤销已恢复的历史成功事实。 */
    bool cleanup_pending; /**< repo仍持statement/lease，同worker destroy后才能结束guard/pool。 */
} vireo_mysql_node_mkdir_once_report_t;

/**
 * @brief 原子创建目录/成功审计/回执，或在当前身份有效时恢复原成功结果
 *
 * 只以用户/命令0x0403/键锁读回执；匹配parent与完整name字节才恢复。无回执时
 * 才验证当前活动父与占名并执行新建，不调用旧公开mkdir后另补回执。
 *
 * @param[in,out] repository
 *     必需创建OS worker串行持有的存活node repo，无残留owner；guard/pool保活。
 * @param[in] actor
 *     必需可信非零持久user/session，借至返回；每次事务重核，不接受wire handle充当身份。
 * @param[in] input
 *     必需稳定独立输入及name短借，parent非零、两个16字节身份非全零；不保存地址。
 * @param[in] timeout_ms
 *     池等待0..60000毫秒，不约束SQL、行锁、COMMIT或整次调用；无内部业务重试。
 * @param[out] report
 *     必需独立独占输出，入口重置；返回非OK仍须读commit/effect/cleanup_pending。
 * @param[out] error
 *     可NULL独立去敏首因/首清理诊断；新回执阶段追加于旧stage枚举末尾。
 *
 * @retval VIREO_OK
 *     CREATED或RECOVERED且全部清理完成；恢复分支commit=NOT_COMMITTED且rollback_confirmed。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址/创建线程/零身份/零父/全零键或事件ID错误。
 * @retval VIREO_RESULT_RANGE
 *     名字长度或池等待越界，在读取name之前检查长度。
 * @retval VIREO_RESULT_PROTOCOL
 *     名字含NUL、斜杠或为单点/双点，不执行SQL；不以此替代产品名字校验。
 * @retval VIREO_RESULT_NOT_FOUND
 *     AUTH_REJECTED为当前身份失效；NODE_NOT_FOUND为无回执时父不可见/非活动/非目录。
 * @retval VIREO_RESULT_DATABASE
 *     已验证占名NAME_CONFLICT、同键改载荷IDEMPOTENCY_CONFLICT、回执形状RECEIPT_INVALID，
 *     或SQL/提交/清理错误。原生1062本身不等于领域冲突；提交与历史事实另读报告。
 * @retval VIREO_RESULT_BUSY
 *     repo有残留owner或池无空闲连接。
 * @retval VIREO_RESULT_TIMEOUT
 *     池等待到期；不证明同键历史没有成功，SQL锁等待错误沿DATABASE。
 * @retval VIREO_RESULT_CANCELLED
 *     pool关闭或依赖损坏门禁，不表示已撤销历史提交。
 * @retval VIREO_RESULT_NO_MEMORY
 *     依赖分配失败，无部分成功输出；原有已发布事实按报告保留。
 * @retval VIREO_RESULT_IO
 *     原生UTC采样失败，errno保存于error.system_errno。
 * @retval VIREO_RESULT_OVERFLOW
 *     UTC换算或依赖计数不可表示。
 * @retval VIREO_RESULT_INTERNAL
 *     UTC形状或依赖同步错误。
 *
 * @note 输出：CREATED只随本次COMMITTED发布；RECOVERED在完整回执行关闭、锁后UTC及载荷
 *     匹配后发布，本次无COMMIT。此后ROLLBACK/close/release失败均保留成功事实；其余node/
 *     audit/key全零。UNKNOWN的effect为NONE，不根据DISCARD或后续ROLLBACK猜测提交。
 * @note 所有权/生命周期：全部地址存活、对齐、互不覆盖且不指向errno；输出按值独立。
 *     不发布SQL视图或ACTIVE node DTO，不拥有fd，不新增线程/私有可变长堆对象。
 * @note 线程安全：同repo创建worker串行；user直接X→当前Session S→完整键回执X，
 *     未命中再parent X→live_name X。普通锁读观察当前已提交事实，不用快照/跳锁判不存在。
 *     锁可阻塞、死锁或超时；同用户串行的吞吐代价已明确，不声称一般死锁自由。
 * @note 时间：恢复/载荷冲突在回执关闭后采UTC，核issued<=now<expires才判定；无回执
 *     新建按旧mkdir在必要锁后及三个INSERT关闭后各采一次UTC重核，再COMMIT。
 *     检查点之后仍可过期，不保证发送或收到响应时Session仍有效；不刷新last_seen。
 * @note 清理：NOT_COMMITTED尝试ROLLBACK；UNKNOWN只DISCARD、不重放；已提交事实不受
 *     清理rc影响。剩余owner保留repo，后续业务BUSY，须同worker destroy；所有路径保持errno。
 * @note 边界：schema已追加v9且无不受控trigger/DDL/回执UPDATE或DELETE；仅成功缓存，
 *     无TTL，无自动重试、NFC库、ACL、祖先可达性、物理目录、失败审计或网络接线。
 */
vireo_result_t vireo_mysql_node_repository_mkdir_once(vireo_mysql_node_repository_t *repository,
    const vireo_mysql_node_actor_t *actor, const vireo_mysql_node_mkdir_once_input_t *input,
    uint32_t timeout_ms, vireo_mysql_node_mkdir_once_report_t *report, vireo_mysql_node_error_t *error);
#endif
