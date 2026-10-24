/*
 * PROJECT : VIREO
 * FILE    : mysql_node_move_receipt.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-24
 * BRIEF   : 同事务持久MOVE成功回执与完整载荷历史恢复。
 */
#ifndef VIREO_PERSISTENCE_MYSQL_NODE_MOVE_RECEIPT_H
#define VIREO_PERSISTENCE_MYSQL_NODE_MOVE_RECEIPT_H
#include <vireo/persistence/mysql_node_repository.h>

/** @brief 用户/命令0x0405作用域的稳定逻辑操作键，精确16字节非全零。 */
#define VIREO_MYSQL_NODE_MOVE_KEY_BYTES ((size_t)16)
/** @brief MOVE回执完整载荷与历史结果格式1；与schema版本10分开判断。 */
#define VIREO_MYSQL_NODE_MOVE_RECEIPT_FORMAT UINT16_C(1)

/** @brief 逻辑成功事实，独立于本次COMMIT、函数rc和资源清理。 */
typedef enum vireo_mysql_node_move_effect {
    VIREO_MYSQL_NODE_MOVE_EFFECT_NONE = 0, /**< 未建立可发布成功事实，不证明历史未成功。 */
    VIREO_MYSQL_NODE_MOVE_EFFECT_APPLIED = 1, /**< 本次完整提交成功，含首次同父同名不变操作。 */
    VIREO_MYSQL_NODE_MOVE_EFFECT_RECOVERED = 2 /**< 当前有效身份匹配历史回执，本次没有COMMIT或新业务写。 */
} vireo_mysql_node_move_effect_t;

/** @brief 同键必须保持源/最终父/完整名字；request_id单独表示可信执行事件。 */
typedef struct vireo_mysql_node_move_once_input {
    uint64_t node_id; /**< 非零原源ID；命中回执时不要求当前仍活动或存在。 */
    uint64_t new_parent_id; /**< 非零最终父ID；命中回执时不重新检查其当前位置或状态。 */
    const unsigned char *name; /**< 必需稳定只读name_length字节，短借至返回，不要求尾NUL。 */
    size_t name_length; /**< 1..255字节；本层只核DDL名字条件，UTF8/NAME/NFC由可信上游核。 */
    unsigned char idempotency_key[VIREO_MYSQL_NODE_MOVE_KEY_BYTES]; /**< 非全零逻辑键，重试保持完整载荷。 */
    unsigned char request_id[16]; /**< 必需非全零可信全局事件ID，仅首次成功分支写审计。 */
} vireo_mysql_node_move_once_input_t;

/** @brief 独立成功身份报告；不发布当前节点快照或历史changed猜测。 */
typedef struct vireo_mysql_node_move_once_report {
    vireo_mysql_node_move_commit_t commit; /**< 仅本次NOT_COMMITTED/COMMITTED/UNKNOWN，复用旧move枚举。 */
    vireo_mysql_node_move_effect_t effect; /**< NONE/APPLIED/RECOVERED；已发布事实不因清理失败消失。 */
    vireo_mysql_node_issue_t issue; /**< 复用已有领域枚举，幂等冲突在本命令另比较源ID。 */
    uint64_t node_id; /**< effect非NONE时原成功源ID；不保证当前仍在目标位置或活动。 */
    uint64_t audit_id; /**< effect非NONE时原成功审计ID；恢复不追加成功审计。 */
    unsigned char idempotency_key[VIREO_MYSQL_NODE_MOVE_KEY_BYTES]; /**< effect非NONE时原键，其余全零。 */
    bool rollback_confirmed; /**< 本次已收到ROLLBACK成功响应，不否定历史成功。 */
    bool cleanup_pending; /**< repo仍持statement/lease，需创建worker继续destroy后才释放依赖。 */
} vireo_mysql_node_move_once_report_t;

/**
 * @brief 同事务持久移动/改名、审计和成功回执，或恢复匹配的历史成功
 *
 * 以user/command0x0405/key锁读完整回执；先有回执再比较source/parent/name字节。
 * 无回执才检查当前节点、根、两条祖先链和占名，不能包装旧公开move提交后补回执。
 * 首次同父同名仍检查树及占名，跳过UPDATE但写审计/回执并COMMIT。
 *
 * @param[in,out] repository
 *     必需创建OS worker独占串行repo，guard/pool存活，无残留子owner。
 * @param[in] actor
 *     必需可信非零持久user/session，借至返回；当前事务重核，wire handle不能代替。
 * @param[in] input
 *     必需稳定独立请求，两个ID非零、name有效、两个16字节身份非全零；不保存地址。
 * @param[in] timeout_ms
 *     池等待0..60000毫秒，仅控制acquire，不限制SQL、行锁、COMMIT或整次调用。
 * @param[out] report
 *     必需独立独占输出，入口全部重置；非OK仍须分别读取commit/effect/cleanup_pending。
 * @param[out] error
 *     可NULL独立去敏首因/首清理报告，无SQL、名字或路径；复用旧stage和error布局。
 *
 * @retval VIREO_OK
 *     APPLIED或RECOVERED且清理全部完成；恢复commit=NOT_COMMITTED且rollback_confirmed。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址/创建线程/零user或session/零源或父/全零键或事件身份错误。
 * @retval VIREO_RESULT_RANGE
 *     长度或等待越界；或ANCESTRY_LIMIT，任一祖先链超过256项仍未到根。
 * @retval VIREO_RESULT_PROTOCOL
 *     名字含NUL、斜杠或完整点/双点，不执行SQL；不代替产品UTF8/NAME/NFC校验。
 * @retval VIREO_RESULT_NOT_FOUND
 *     AUTH_REJECTED为当前身份失效；无回执分支NODE_NOT_FOUND为源/目标不可见或不可用。
 * @retval VIREO_RESULT_DATABASE
 *     ROOT_IMMOVABLE/MOVE_CYCLE/TREE_INVALID/NAME_CONFLICT/IDEMPOTENCY_CONFLICT/
 *     RECEIPT_INVALID，或SQL/固定结果/COMMIT/清理错误；原生1062不能独自证明领域冲突。
 * @retval VIREO_RESULT_BUSY
 *     repo残留owner或pool无可用连接。
 * @retval VIREO_RESULT_TIMEOUT
 *     pool等待到期；不证明历史未成功，SQL锁等待错误沿DATABASE。
 * @retval VIREO_RESULT_CANCELLED
 *     pool关闭或依赖损坏门禁，不表示撤销历史提交。
 * @retval VIREO_RESULT_NO_MEMORY
 *     依赖分配失败，既有已发布成功事实按report保留。
 * @retval VIREO_RESULT_IO
 *     原生UTC采样失败，原始errno记录于error.system_errno。
 * @retval VIREO_RESULT_OVERFLOW
 *     UTC换算或依赖计数不可表示。
 * @retval VIREO_RESULT_INTERNAL
 *     UTC形状或依赖同步错误。
 *
 * @note 发布：APPLIED仅在COMMIT完整响应确认后发布；UNKNOWN时effect=NONE且结果身份全零。
 *     RECOVERED仅在回执整行/唯一性/close、锁后UTC及完整载荷匹配后发布，再ROLLBACK结束读取。
 *     之后ROLLBACK/close/release非OK不清除成功事实，NOT_COMMITTED也不证明历史未提交。
 * @note 所有权/生命周期：全部地址存活、对齐、互不覆盖且不指向errno；输入只借至返回。
 *     输出按值独立，无SQL视图逸出、fd所有权、线程创建或新私有可变长堆对象。
 * @note 同repo创建worker串行。锁序user直接X→当前Session S→完整键回执X；未命中再源X→
 *     目标父X→源旧父链S→目标父链S→完整live_name X。每链含根最多256项，不扫描后代。
 *     所有树writer遵守user先锁；可能阻塞/死锁/超时，无自动业务重试或一般死锁自由保证。
 * @note 时间：合法回执完整关闭后采UTC，先核issued<=now<expires再判载荷冲突/恢复。
 *     无回执按旧move在必要锁读后及UPDATE/审计/回执关闭后各重核；SQL/形状错误不被时间拒绝掩盖。
 *     第一次UTC用于审计/回执时间；真变化updated=max(第一次UTC,旧updated)，不变操作不改节点时间。
 *     当前时间检查不保证发送或收到响应时Session仍有效，不刷新last_seen。
 * @note 清理：NOT_COMMITTED尝试ROLLBACK；UNKNOWN只DISCARD，不用后续断连接果猜回滚。
 *     残留owner保repo并拒绝后续业务，必须同worker destroy；各路径保持errno和首因优先。
 * @note 边界：schema至少追加v10且无不受控trigger/DDL/回执UPDATE或DELETE；无TTL/失败缓存。
 *     无覆盖/版本比较/ACL/NFC库/物理CAS/引用数修改/网络接线；旧move不是安全恢复入口。
 */
vireo_result_t vireo_mysql_node_repository_move_once(vireo_mysql_node_repository_t *repository,
    const vireo_mysql_node_actor_t *actor, const vireo_mysql_node_move_once_input_t *input,
    uint32_t timeout_ms, vireo_mysql_node_move_once_report_t *report, vireo_mysql_node_error_t *error);
#endif
