/*
 * PROJECT : VIREO
 * FILE    : directory_root.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-22
 * BRIEF   : 同worker根ID查询的可交付业务结果与原始清理事实。
 */
#ifndef VIREO_SERVICE_DIRECTORY_ROOT_H
#define VIREO_SERVICE_DIRECTORY_ROOT_H
#include <stdbool.h>
#include <stdint.h>
#include <vireo/persistence/mysql_node_repository.h>

/** @brief 根发现可交付类别；没有普通节点NOT_FOUND，不是wire状态。 */
typedef enum vireo_directory_root_outcome {
    VIREO_DIRECTORY_ROOT_NONE = 0, /**< 失败或清理不完整，不得交付根或普通业务拒绝。 */
    VIREO_DIRECTORY_ROOT_FOUND = 1, /**< 授权读取/根关联/资源清理完整，root_node_id有效。 */
    VIREO_DIRECTORY_ROOT_UNAUTHORIZED = 2 /**< 明确AUTH_REJECTED且清理完整，合并身份拒绝。 */
} vireo_directory_root_outcome_t;

/** @brief caller持有的独立值；不拥有repo，不是completion，禁止直接序列化。 */
typedef struct vireo_directory_root_result {
    vireo_directory_root_outcome_t outcome; /**< 仅FOUND提供ID，NONE不等于普通NOT_FOUND。 */
    uint64_t root_node_id; /**< FOUND非零真实根ID，其余0；不提供持续授权凭据。 */
    bool repository_called; /**< 是否进入一次get_root；不证明一定执行过SQL。 */
    vireo_result_t repository_result; /**< called时的原始rc，不随service错误提升改写。 */
    vireo_mysql_node_report_t repository; /**< called时的原始报告；非OK仍须读取cleanup_pending。 */
} vireo_directory_root_result_t;

/**
 * @brief 在当前worker查可信身份的真实根，只在完整清理后发布ID
 *
 * @param[in,out] repository
 *     必需存活、同当前OS worker创建的repo，guard/pool保活，无残留子owner。
 *     短借不接管/销毁/替换，同repo串行，opaque线程资格由042实际调用检查。
 * @param[in] actor
 *     必需服务端可信绑定生产的非零user/session持久身份，只借至返回。
 *     普通结构体不是身份凭证，不接受客户端指定；042仍在事务中重核。
 * @param[in] timeout_ms
 *     池等待0..60000毫秒，不约束SQL、行锁或整个同步调用时长。
 * @param[out] result
 *     必需独占独立输出；必需地址齐备后先全清零，调用后保存原rc/报告。
 *     caller覆盖旧值前已履行上次repo残留责任；清零结果不释放资源。
 * @param[out] error
 *     可NULL独立去敏诊断，地址齐备后重置；调用后保存下层原始首因/首清理。
 *     即使NULL也用局部诊断检查清理，不输出SQL/名字/凭据或任意文本。
 *
 * @retval VIREO_OK
 *     FOUND/非零根ID；完整回滚/清理、found=true/issue=NONE且根关联合法。
 * @retval VIREO_RESULT_NOT_FOUND
 *     仅UNAUTHORIZED；原AUTH_REJECTED、found=false且回滚/清理完整。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需NULL或actor任一ID为0，或042的线程/guard等前置拒绝。
 * @retval VIREO_RESULT_RANGE
 *     timeout_ms超过60000时不调用repo；其余下层范围错误原样返回。
 * @retval VIREO_RESULT_DATABASE
 *     SQL/行形状/缺活动根或首清理DATABASE，NONE/根0，不自动修根。
 * @retval VIREO_RESULT_BUSY
 *     下层残留门禁/池无容量或首清理BUSY，不是自动重试许可。
 * @retval VIREO_RESULT_TIMEOUT
 *     池等待或首清理TIMEOUT，不承诺SQL已抢断。
 * @retval VIREO_RESULT_CANCELLED
 *     pool关闭或首清理CANCELLED；不隐式重试。
 * @retval VIREO_RESULT_NO_MEMORY
 *     下层分配或首清理NO_MEMORY；本层不分配heap。
 * @retval VIREO_RESULT_IO
 *     下层采时等I/O或首清理IO失败。
 * @retval VIREO_RESULT_OVERFLOW
 *     下层UTC换算或首清理OVERFLOW。
 * @retval VIREO_RESULT_INTERNAL
 *     成功/身份拒绝报告或根关联矛盾，OK/NOT_FOUND却pending，首清理NOT_FOUND，
 *     或原下层INTERNAL；NONE/根0。
 * @return 其他首清理错误优先，否则其他下层错误原样返回；均NONE/根0。
 *
 * @note 任一必需NULL时保持result/error；齐备后先清输出再校验值。
 *     全部地址有效对齐、互不重叠且不指向errno；输入稳定至返回。
 *     合法值时至多一次042公开get_root，called不等于SQL一定执行。
 * @note 原rc/report/error先保存；首清理错误非OK优先，清理NOT_FOUND提升INTERNAL。
 *     无首清理错但pending时，原基础设施rc保持，原OK/NOT_FOUND提升INTERNAL。
 *     仅无清理错且不pending，OK或NOT_FOUND才可进入业务结果门禁。
 * @note FOUND根门禁：id非零、owner等于actor.user_id、无parent且parent_id=0、
 *     name_length=0、kind=DIRECTORY、size=0、has_object_hash=false，
 *     found=true、issue=NONE、rollback_confirmed=true；否则INTERNAL。
 *     042负责其余节点行/时间/未用数组合同，本层不复制完整metadata给上游。
 * @note UNAUTHORIZED仅原NOT_FOUND、found=false、issue=AUTH_REJECTED、rollback已确认；
 *     NODE_NOT_FOUND/ROOT_INVARIANT等矛盾组合INTERNAL。原DATABASE/ROOT_INVARIANT保持，
 *     将来wire应投影INTERNAL_ERROR，此函数不编码或依赖wire。
 * @note 非OK仍检查repository.cleanup_pending，由原worker按042清理或升级故障。
 *     服务不销毁repo，不改原首因掩盖清理，不拥有fd/Session表/owner，不写审计或last_seen。
 * @note 同repo在创建worker同步串行，独立repo可并行；保持入口errno。
 *     无本层heap/锁/时钟/缓存/重试；不支持POSIX异步取消/longjmp。
 *     只表示读取判断时点授权，不保证读后撤销广播、持续授权或未来FIFO可撤回。
 */
vireo_result_t vireo_directory_service_root(vireo_mysql_node_repository_t *repository,
    const vireo_mysql_node_actor_t *actor, uint32_t timeout_ms,
    vireo_directory_root_result_t *result, vireo_mysql_node_error_t *error);
#endif
