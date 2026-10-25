/*
 * PROJECT : VIREO
 * FILE    : mysql_node_remove_receipt.h
 * BRIEF   : NODE_REMOVE 一次性软删除持久回执。
 */
#ifndef VIREO_PERSISTENCE_MYSQL_NODE_REMOVE_RECEIPT_H
#define VIREO_PERSISTENCE_MYSQL_NODE_REMOVE_RECEIPT_H
#include <vireo/persistence/mysql_node_repository.h>

/** @brief 用户/命令0x0404作用域的稳定逻辑操作键，精确16字节非全零。 */
#define VIREO_MYSQL_NODE_REMOVE_KEY_BYTES ((size_t)16)
/** @brief 回执格式1，独立于schema迁移版本11。 */
#define VIREO_MYSQL_NODE_REMOVE_RECEIPT_FORMAT UINT16_C(1)

/** @brief 历史成功事实，独立于本次commit、返回码和清理责任。 */
typedef enum vireo_mysql_node_remove_effect {
    VIREO_MYSQL_NODE_REMOVE_EFFECT_NONE = 0, /**< 未发布成功事实，不证明历史未成功。 */
    VIREO_MYSQL_NODE_REMOVE_EFFECT_APPLIED = 1, /**< 本次COMMIT完整响应已确认。 */
    VIREO_MYSQL_NODE_REMOVE_EFFECT_RECOVERED = 2 /**< 当前身份获准恢复匹配的历史成功，本次无新业务写。 */
} vireo_mysql_node_remove_effect_t;

/** @brief 同键必须保持node_id；request_id独立标识本次可信执行事件。 */
typedef struct vireo_mysql_node_remove_once_input {
    uint64_t node_id; /**< 非零目标ID；历史恢复不要求当前节点仍活动或存在。 */
    unsigned char idempotency_key[VIREO_MYSQL_NODE_REMOVE_KEY_BYTES]; /**< 非全零；跨重连/重试保持。 */
    unsigned char request_id[16]; /**< 必需非全零事件ID；仅首次分支写action7审计。 */
} vireo_mysql_node_remove_once_input_t;

/** @brief 独立值报告；非OK仍必须分别判断commit、effect和cleanup_pending。 */
typedef struct vireo_mysql_node_remove_once_report {
    vireo_mysql_node_soft_delete_commit_t commit; /**< 仅本次NOT_COMMITTED/COMMITTED/UNKNOWN。 */
    vireo_mysql_node_remove_effect_t effect; /**< 已发布事实不会因后续清理失败被清零。 */
    vireo_mysql_node_issue_t issue; /**< 当前领域分类，不能由原生1062单独推导冲突。 */
    uint64_t node_id; /**< effect非NONE时历史成功目标，其余为零。 */
    uint64_t audit_id; /**< effect非NONE时首次成功审计ID，其余为零。 */
    uint64_t deleted_at_ms; /**< 历史max(首次UTC1,源updated_at_ms)；可为0或晚于重试时钟。 */
    bool rollback_confirmed; /**< 本次收到ROLLBACK成功响应，不否定历史成功。 */
    bool cleanup_pending; /**< repo仍持statement/lease；创建worker须继续destroy。 */
} vireo_mysql_node_remove_once_report_t;

/**
 * @brief 原子软删除、对象引用递减、审计及成功回执，或只恢复原成功事实
 *
 * 先重核当前user/session并锁读user/command0x0404/key完整回执。命中时严格核字段
 * 形状、唯一性及node_id，返回RECOVERED；不重新删除、减引用或追加审计。
 * 未命中才执行旧soft_delete的根保护、祖先链、空目录/对象引用检查及两次UTC。
 * 节点DELETED、文件ref_count减一、action7审计和不可变回执在同一事务提交。
 *
 * @param[in,out] repository 必需创建OS worker独占串行repo，thread/pool存活。
 * @param[in] actor 必需可信非零持久user/session；wire handle不能代替，借至返回。
 * @param[in] input 必需稳定独立值；node_id及两个16字节身份均非零，不保存地址。
 * @param[in] timeout_ms 池等待0..60000毫秒；不限制SQL、行锁、COMMIT或整次调用。
 * @param[out] report 必需独立独占输出，入口重置；失败后仍读取commit/effect/cleanup_pending。
 * @param[out] error 可NULL独立去敏首因/首清理诊断，无SQL、原键或路径。
 *
 * @retval VIREO_OK APPLIED或RECOVERED且清理完成；恢复commit=NOT_COMMITTED且rollback_confirmed。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 必需地址/创建线程/零身份/全零键或事件错误。
 * @retval VIREO_RESULT_RANGE 等待越界或ANCESTRY_LIMIT（含根最多256项）。
 * @retval VIREO_RESULT_NOT_FOUND AUTH_REJECTED为当前身份失效；NODE_NOT_FOUND为未命中回执且源不可见。
 * @retval VIREO_RESULT_DATABASE ROOT_UNDELETABLE/DIRECTORY_NOT_EMPTY/TREE_INVALID/
 *     OBJECT_REFERENCE_INVALID/IDEMPOTENCY_CONFLICT/RECEIPT_INVALID，或SQL、结果形状、提交/清理错误。
 * @retval VIREO_RESULT_BUSY repo残留owner、pool无连接或清理仍受阻。
 * @retval VIREO_RESULT_TIMEOUT pool等待到期，不证明历史未成功。
 * @retval VIREO_RESULT_CANCELLED pool关闭或依赖门禁，不表示撤销历史提交。
 * @retval VIREO_RESULT_NO_MEMORY 依赖分配失败。
 * @retval VIREO_RESULT_IO UTC原生失败，原errno记录于error.system_errno。
 * @retval VIREO_RESULT_OVERFLOW UTC换算或依赖计数不可表示。
 * @retval VIREO_RESULT_INTERNAL UTC形状或依赖同步错误。
 *
 * @note APPLIED仅在COMMIT完整响应确认后发布；COMMIT已开始未确认时UNKNOWN、effect=NONE，
 *     结果身份全零，只DISCARD不重放。调用者用原key后续恢复，不能把NOT_COMMITTED当历史失败。
 *     RECOVERED在整行/唯一性/close、当前授权UTC和载荷匹配后发布，再ROLLBACK结束读取；
 *     后续ROLLBACK/close/release失败仍保留历史事实，残留资源由原worker继续destroy。
 * @note 全部地址须存活、对齐、互不覆盖且不指向errno；输入仅借至返回，报告无SQL视图逸出。
 *     同repo仅创建worker串行；锁序user X→session S→receipt X→source X→ancestors S→
 *     children/object X。相同用户目录写串行；回执无TTL、更新或删除，UTC回退允许历史时间更晚。
 * @note 不递归、不物理删除对象、不取消上传、不实现恢复节点或GC；保留旧soft_delete合同。
 *     SQL可阻塞，失败非整体取消；不提供一般死锁自由或掉电耐久证明。所有路径保持errno。
 */
vireo_result_t vireo_mysql_node_repository_soft_delete_once(
    vireo_mysql_node_repository_t *repository,
    const vireo_mysql_node_actor_t *actor,
    const vireo_mysql_node_remove_once_input_t *input,
    uint32_t timeout_ms,
    vireo_mysql_node_remove_once_report_t *report,
    vireo_mysql_node_error_t *error);

#endif
