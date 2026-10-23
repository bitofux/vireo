/* PROJECT : VIREO; FILE : directory_mkdir.h; AUTHOR : bitofux;
 * DATE : 2026-10-23; BRIEF : 同worker可恢复目录创建服务。 */
#ifndef VIREO_SERVICE_DIRECTORY_MKDIR_H
#define VIREO_SERVICE_DIRECTORY_MKDIR_H
#include <stdbool.h>
#include <stdint.h>
#include <vireo/service/directory_name.h>
#include <vireo/persistence/mysql_node_mkdir_receipt.h>

/** @brief 完整校验/清理后可交付的业务分类，不等于rc、wire或原始提交事实。 */
typedef enum vireo_directory_mkdir_outcome {
    VIREO_DIRECTORY_MKDIR_NONE = 0, /**< 基础设施/清理/未决或矛盾报告，不能发布普通业务结果。 */
    VIREO_DIRECTORY_MKDIR_CREATED = 1, /**< 当前确认提交新目录/审计/回执。 */
    VIREO_DIRECTORY_MKDIR_RECOVERED = 2, /**< 当前授权下恢复历史成功；不保证节点现在仍活动。 */
    VIREO_DIRECTORY_MKDIR_INVALID_NAME = 3, /**< 仅本地确定的长度/UTF-8/NAME/NFC拒绝，未调用repo。 */
    VIREO_DIRECTORY_MKDIR_UNAUTHORIZED = 4, /**< repo明确当前身份拒绝且回滚/清理完整。 */
    VIREO_DIRECTORY_MKDIR_PARENT_NOT_FOUND = 5, /**< 无回执时当前可见活动目录父不可用。 */
    VIREO_DIRECTORY_MKDIR_NAME_CONFLICT = 6, /**< repo锁读确认占名，不凭1062猜测。 */
    VIREO_DIRECTORY_MKDIR_IDEMPOTENCY_CONFLICT = 7 /**< 已提交同键对应的parent/name不同。 */
} vireo_directory_mkdir_outcome_t;

/** @brief caller独占的独立值，不拥有repo、名字、连接或其他需销毁资源。 */
typedef struct vireo_directory_mkdir_result {
    vireo_directory_mkdir_outcome_t outcome; /**< 仅CREATED/RECOVERED可取下列交付ID/键。 */
    vireo_directory_name_issue_t name_issue; /**< 仅INVALID_NAME时为四种明确名字拒绝之一。 */
    uint64_t node_id; /**< 可交付成功才非零；其他为0，历史原ID。 */
    unsigned char idempotency_key[VIREO_MYSQL_NODE_MKDIR_KEY_BYTES]; /**< 成功原键，其余全零。 */
    bool repository_called; /**< 最多一次mkdir_once；false时下列仓库事实全零。 */
    vireo_result_t repository_result; /**< repo原始rc，不能被service清理优先或关系核验覆盖。 */
    vireo_mysql_node_mkdir_once_report_t repository; /**< 原始commit/effect/IDs/key/清理；失败也保留。 */
} vireo_directory_mkdir_result_t;

/**
 * @brief 核验NFC名字后至多一次调用mkdir_once，分离历史成功事实与本次可交付结果
 *
 * @param[in,out] repository
 *     必需存活repo，同其创建OS worker串行；guard/pool保活，不接管或销毁。
 *     本地拒绝不访问opaque repo，不能借此证明repo线程资格或数据库授权。
 * @param[in] actor
 *     必需可信非零持久user/session，仅借至返回，不接受客户端指定的持久身份。
 * @param[in] input
 *     必需稳定输入，复用02的parent/name/length/key/request_id合同。
 *     parent非零，key及request_id非全零；后者由可信上游为执行事件独立生成，
 *     不能从客户端键、sequence或短handle派生。本层不生成随机数或保存地址。
 * @param[in] timeout_ms
 *     池等待0..60000毫秒；不包含名字校验、SQL锁或COMMIT的硬deadline。
 * @param[out] result
 *     必需独立独占值，必需地址齐备后先清零；复用前caller先处理旧repo清理责任。
 * @param[out] error
 *     可NULL独立数值诊断；地址齐备后清零。本层始终使用局部诊断检查首清理错误。
 *
 * @retval VIREO_OK
 *     仅CREATED或RECOVERED；原始rc/report/ID/key/清理关系完整一致。
 * @retval VIREO_RESULT_RANGE
 *     名字长度拒绝时INVALID_NAME/LENGTH；timeout越界时NONE；或原下层技术错误。
 * @retval VIREO_RESULT_PROTOCOL
 *     本地名字拒绝时INVALID_NAME及明确issue；不会因分配失败报告非法路径。
 * @retval VIREO_RESULT_NOT_FOUND
 *     仅UNAUTHORIZED或PARENT_NOT_FOUND，要求NOT_COMMITTED/NONE/零结果/确认回滚。
 * @retval VIREO_RESULT_DATABASE
 *     两种已确认冲突，或原SQL/未知提交/坏回执等基础设施错误；须联合读outcome。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需指针NULL、可信身份/父/两个身份数组非法，或repo拒绝线程等前置条件。
 * @retval VIREO_RESULT_INTERNAL
 *     可交付路径报告矛盾、下层返回PROTOCOL、首清理NOT_FOUND，或异常依赖结果。
 * @retval VIREO_RESULT_NO_MEMORY
 *     Unicode或仓库分配失败，或首清理NO_MEMORY，outcome=NONE。
 * @retval VIREO_RESULT_OVERFLOW
 *     Unicode/UTC等表示失败，或首清理OVERFLOW，outcome=NONE。
 * @retval VIREO_RESULT_BUSY
 *     repo残留门禁/池满或首清理BUSY，outcome=NONE，不授权自动重试。
 * @retval VIREO_RESULT_TIMEOUT
 *     pool等待或首清理到期，outcome=NONE，不证明没有提交。
 * @retval VIREO_RESULT_CANCELLED
 *     pool关闭/依赖门禁或首清理CANCELLED，outcome=NONE，不撤销已提交事实。
 * @retval VIREO_RESULT_IO
 *     UTC等原生错误或首清理IO，outcome=NONE。
 * @return 首清理错误优先，NOT_FOUND提升INTERNAL；不得把技术故障投影为普通业务拒绝。
 *
 * @note 必需指针缺失不修改result/error；齐备后清输出，再核身份/父/非零键/事件/
 *     timeout，然后名字，最后repo。name为NULL是参数错误；长度失败先于读取名字。
 *     本地INVALID_NAME不执行SQL，即使该Session在DB已过期亦不先探测身份；该结果只描述
 *     请求自带字节，不泄露持久私有事实。合法名字才由02在同事务重核当前授权。
 *     名字回调须满足OK/NONE、RANGE/LENGTH、PROTOCOL/UTF8或SYNTAX或NOT_NFC，
 *     其他技术错误仅issue NONE；矛盾关系INTERNAL/NONE且不调用repo。
 * @note 原repo rc/report/error逐值保存；清理错或pending不得交付成功/普通拒绝。
 *     pending且原为OK/NOT_FOUND或领域冲突时返回INTERNAL；其他原技术错误保持。
 *     成功门禁：CREATED=COMMITTED/CREATED/非零node及audit/原键/issue NONE/无rollback；
 *     RECOVERED=NOT_COMMITTED/RECOVERED/同样非零原结果/原键/issue NONE/确认rollback。
 *     领域拒绝另要求NOT_COMMITTED/NONE/零node/audit/key/确认rollback，且rc与issue匹配。
 * @note 清理失败时outcome=NONE、可交付ID/key清零，但repository中的CREATED/RECOVERED
 *     等既有事实保持。UNKNOWN不能改成未发生；服务不自动ROLLBACK、重放或换键。
 *     调用方必须同worker处理cleanup_pending；释放完成后后续有效请求仍使用原载荷/键。
 * @note 全部输入/输出有效对齐互不重叠且不指向errno；短借至返回，不拥有fd/connection/
 *     TLS/Session表，不编码wire、不访问043/044私有实现，不写独立失败审计或新增SQL。
 *     同repo原worker同步串行，独立repo可并行；保持errno，无服务时钟/锁/缓存/内部重试。
 */
vireo_result_t vireo_directory_service_mkdir(vireo_mysql_node_repository_t *repository,
    const vireo_mysql_node_actor_t *actor, const vireo_mysql_node_mkdir_once_input_t *input,
    uint32_t timeout_ms, vireo_directory_mkdir_result_t *result, vireo_mysql_node_error_t *error);
#endif
