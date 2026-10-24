/*
 * PROJECT : VIREO
 * FILE    : directory_move.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-24
 * BRIEF   : 同worker校验最终名字并交付可恢复移动业务结果。
 */
#ifndef VIREO_SERVICE_DIRECTORY_MOVE_H
#define VIREO_SERVICE_DIRECTORY_MOVE_H
#include <stdbool.h>
#include <stdint.h>
#include <vireo/service/directory_name.h>
#include <vireo/persistence/mysql_node_move_receipt.h>

/** @brief 清理和报告关系核验后的可交付分类，独立于原始仓库成功事实。 */
typedef enum vireo_directory_move_outcome {
    VIREO_DIRECTORY_MOVE_NONE = 0, /**< 技术错误、未决提交、清理失败或报告矛盾，不交付普通业务结果。 */
    VIREO_DIRECTORY_MOVE_APPLIED = 1, /**< 当前确认提交成功，包含首次同父同名不变操作。 */
    VIREO_DIRECTORY_MOVE_RECOVERED = 2, /**< 当前身份下恢复原成功ID/键，不证明当前节点位置或活动性。 */
    VIREO_DIRECTORY_MOVE_INVALID_NAME = 3, /**< 本地确认长度/UTF8/NAME/NFC拒绝，没有访问仓库。 */
    VIREO_DIRECTORY_MOVE_UNAUTHORIZED = 4, /**< 仓库明确拒绝当前持久身份且回滚/清理完整。 */
    VIREO_DIRECTORY_MOVE_NOT_FOUND = 5, /**< 无回执分支的源或活动目录目标不可见/不可用，不区分属主。 */
    VIREO_DIRECTORY_MOVE_ROOT_IMMOVABLE = 6, /**< 当前有效身份下不能移动或改名本用户根。 */
    VIREO_DIRECTORY_MOVE_NAME_CONFLICT = 7, /**< 锁读确认目标名称被其他节点占用，不依据原生1062猜测。 */
    VIREO_DIRECTORY_MOVE_CYCLE = 8, /**< 仓库确认本次移动将产生目录环。 */
    VIREO_DIRECTORY_MOVE_ANCESTRY_LIMIT = 9, /**< 祖先链含根最多256项预算不足，未提交。 */
    VIREO_DIRECTORY_MOVE_IDEMPOTENCY_CONFLICT = 10 /**< 同用户/命令/键已提交的源/父/完整名字不同。 */
} vireo_directory_move_outcome_t;

/** @brief caller独占的独立数值结果，不持有repo、名字或需销毁的资源。 */
typedef struct vireo_directory_move_result {
    vireo_directory_move_outcome_t outcome; /**< 仅APPLIED/RECOVERED可读取下列可交付ID/键。 */
    vireo_directory_name_issue_t name_issue; /**< 仅INVALID_NAME时为四种明确名字拒绝之一，其余NONE。 */
    uint64_t node_id; /**< 成功时等于input.node_id及原回执源ID，其余0；不是当前位置快照。 */
    unsigned char idempotency_key[VIREO_MYSQL_NODE_MOVE_KEY_BYTES]; /**< 成功原键；其余全零。 */
    bool repository_called; /**< 本次是否调用唯一一次move_once；false时下列字段全零。 */
    vireo_result_t repository_result; /**< 仓库原始rc，保留，不被服务返回值覆盖。 */
    vireo_mysql_node_move_once_report_t repository; /**< 原始commit/effect/IDs/key/issue及清理责任，非OK也保留。 */
} vireo_directory_move_result_t;

/**
 * @brief 检查最终名字已经是NFC，至多调用一次move_once并核验可交付结果
 *
 * @param[in,out] repository
 *     必需存活repo，同创建OS worker串行；guard/pool保活，服务不接管或销毁。
 *     本地拒绝不访问opaque repo，不能据此证明repo线程资格或持久身份有效。
 * @param[in] actor
 *     必需非零可信持久user/session，仅借至返回；不得信任客户端提供的持久身份。
 * @param[in] input
 *     必需稳定完整原载荷，源/最终父非零，name非NULL，长度1..255，逻辑键和事件ID非全零。
 *     输入和name仅短借至返回，无尾NUL要求；request_id由可信上游独立生成，
 *     不从客户端幂等键、sequence或短handle派生，本服务不采随机数。
 * @param[in] timeout_ms
 *     池等待0..60000毫秒，不是名字检查、SQL、锁、COMMIT或整个服务的硬deadline。
 * @param[out] result
 *     必需独立独占值；必需地址齐备后先清零。复用前caller先处理旧结果的残留owner责任。
 * @param[out] error
 *     可NULL独立去敏数值诊断；地址齐备后清零，调用仓库时始终提供非NULL局部诊断。
 *
 * @retval VIREO_OK
 *     仅完整APPLIED或RECOVERED，可交付node_id等于原源ID，原键一致，清理完整。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需指针缺失、零可信身份/源/父或全零键/事件；或下层创建线程等资格拒绝，outcome=NONE。
 * @retval VIREO_RESULT_RANGE
 *     名字长度拒绝时INVALID_NAME/LENGTH；等待越界为NONE；确认链预算拒绝为ANCESTRY_LIMIT；
 *     或原技术/首清理RANGE，只能结合outcome判断。
 * @retval VIREO_RESULT_PROTOCOL
 *     本地UTF8/SYNTAX/NOT_NFC拒绝为INVALID_NAME；若首清理原错为PROTOCOL仍为NONE。
 * @retval VIREO_RESULT_NOT_FOUND
 *     仅回滚与清理完整的UNAUTHORIZED或NOT_FOUND，原始成功身份全零。
 * @retval VIREO_RESULT_DATABASE
 *     已确认ROOT_IMMOVABLE/NAME_CONFLICT/CYCLE/IDEMPOTENCY_CONFLICT，或SQL/坏树/
 *     坏回执/未知提交等技术失败NONE；不能仅凭rc映射成CONFLICT。
 * @retval VIREO_RESULT_INTERNAL
 *     可交付报告关系矛盾、名字依赖返回矛盾、清理完整时repo返回PROTOCOL、首清理NOT_FOUND，
 *     或pending伴随原OK/NOT_FOUND/确认领域拒绝；outcome=NONE。
 * @retval VIREO_RESULT_NO_MEMORY
 *     Unicode/仓库分配或首清理失败，NONE；不是非法名字。
 * @retval VIREO_RESULT_OVERFLOW
 *     Unicode/UTC等表示或首清理失败，NONE。
 * @retval VIREO_RESULT_BUSY
 *     仓库残留owner、池忙或首清理BUSY，NONE；不授权自动重试。
 * @retval VIREO_RESULT_TIMEOUT
 *     池等待或首清理超时，NONE；不证明历史未成功。
 * @retval VIREO_RESULT_CANCELLED
 *     池关闭/依赖门禁或首清理取消，NONE；不撤销原成功。
 * @retval VIREO_RESULT_IO
 *     原生UTC等或首清理错误，NONE。
 * @return 首清理错误优先，其中NOT_FOUND提升INTERNAL；其余结合outcome和原始仓库事实判断。
 *
 * @note 输出与次序：必需地址缺失保持result/error；齐备后清输出，先核可信身份/源/父/
 *     非零键/事件、timeout，再调用既有名字校验，最后至多一次move_once。长度检查先于
 *     读取name。合法名字才由仓库同事务重核当前授权；非法名字即使Session已过期亦不
 *     先探测数据库，本地拒绝只描述请求自带字节。源等于最终父不在此层猜测目录环。
 * @note 名字：直接复用directory_name_validate，拒绝非NFC，不改写/截断/trim/casefold。
 *     名字依赖只接受OK/NONE、RANGE/LENGTH、PROTOCOL/UTF8或SYNTAX或NOT_NFC；
 *     技术返回仅NO_MEMORY/OVERFLOW/INTERNAL且issue NONE；其他关系返回INTERNAL/NONE且不调用仓库。
 * @note 原repo rc/report/error独立保留；首清理错误或pending阻止交付成功及普通拒绝。
 *     pending遇原OK/NOT_FOUND或上述五类领域拒绝提升INTERNAL，其余原技术错误保持。
 *     APPLIED要求COMMITTED/APPLIED/issue NONE/源ID一致/非零audit/原键/无rollback；
 *     RECOVERED要求NOT_COMMITTED/RECOVERED/其余成功关系一致/确认rollback。
 *     普通拒绝要求NOT_COMMITTED/NONE/零node/audit/key/确认rollback及精确rc/issue对应。
 *     TREE_INVALID、RECEIPT_INVALID、原生1062与无领域issue的SQL错误保持NONE。
 * @note 清理失败时可交付ID/key清零，repository中已确认APPLIED/RECOVERED事实保持。
 *     UNKNOWN不改成未发生，不自动重放、换键、补SQL或ROLLBACK；caller必须同worker
 *     处理cleanup_pending并保活依赖。恢复原成功不证明当前树位置，需要另发STAT/LIST观察。
 * @note 无服务对象、缓存、锁、时钟或内部重试；名字库内部可分配，SQL可阻塞。
 *     全部输入输出有效对齐、互不覆盖且不指向errno，不保存地址。同repo原worker串行，
 *     独立repo可并行，保持errno；不承诺异步取消安全、signal-safe或硬实时。
 *     不拥有客户fd/TLS/Session表，不编解码wire、不改迁移、不增加授权探测或失败审计SQL。
 */
vireo_result_t vireo_directory_service_move(vireo_mysql_node_repository_t *repository,
    const vireo_mysql_node_actor_t *actor, const vireo_mysql_node_move_once_input_t *input,
    uint32_t timeout_ms, vireo_directory_move_result_t *result, vireo_mysql_node_error_t *error);
#endif
