/*
- PROJECT : VIREO
- FILE    : directory_service.h
- AUTHOR  : bitofux
- DATE    : 2026-10-22
- BRIEF   : 同worker节点读取与可交付业务结果，保持数据库清理责任。
 */
#ifndef VIREO_SERVICE_DIRECTORY_SERVICE_H
#define VIREO_SERVICE_DIRECTORY_SERVICE_H

#include <stdbool.h>
#include <stdint.h>
#include <vireo/persistence/mysql_node_repository.h>

/** @brief 一次STAT可交付的业务类别；不是wire状态或授权票据。 */
typedef enum vireo_directory_stat_outcome {
    VIREO_DIRECTORY_STAT_NONE = 0, /**< 尚未调用、调用失败或清理不完整；不得交付节点或普通业务拒绝。 */
    VIREO_DIRECTORY_STAT_FOUND = 1, /**< 事务授权、读取及清理完整成功，node有效。 */
    VIREO_DIRECTORY_STAT_UNAUTHORIZED = 2, /**< 底层明确AUTH_REJECTED且清理完成，统一身份拒绝。 */
    VIREO_DIRECTORY_STAT_NOT_FOUND = 3 /**< 底层明确NODE_NOT_FOUND且清理完成，合并不存在/他人/非ACTIVE。 */
} vireo_directory_stat_outcome_t;

/**
 * @brief caller拥有的独立STAT结果；仅内部使用，禁止直接序列化C结构体。
 * @note name仍为原始字节；本层不承诺UTF-8、规范化、CAS存在性或后续授权有效。
 */
typedef struct vireo_directory_stat_result {
    vireo_directory_stat_outcome_t outcome; /**< 仅FOUND允许读取node；NONE不能映射为普通NOT_FOUND。 */
    vireo_mysql_node_value_t node; /**< 按042独立值合同复制；非FOUND整对象清零，不借repo/SQL内存。 */
    bool repository_called; /**< 是否实际调用过一次底层stat；false时其余repository字段全零。 */
    vireo_result_t repository_result; /**< 底层原返回码；仅called为true有效，不随service清理错误提升而改写。 */
    vireo_mysql_node_report_t repository; /**< 原始内部报告；非OK也读cleanup_pending，业务继续前须履行责任。 */
} vireo_directory_stat_result_t;

/**
 * @brief 在当前worker读取一个授权节点，分离可交付业务结果与基础设施失败
 *
 * @param[in,out] repository
 *     必需存活且同当前OS worker创建的节点repo，短借，不接管、销毁或替换。
 *     guard/pool保活；同对象串行；opaque线程资格由下层在实际调用时检查。
 * @param[in] actor
 *     必需服务端可信连接绑定生产的非零user/session持久身份，只借至返回。
 *     结构体不证明身份可信；不得由客户端指定；数据库仍在同一事务中重核。
 * @param[in] node_id
 *     必需非零持久节点ID；根也须传真实ID，0不表示当前目录或根。
 * @param[in] timeout_ms
 *     pool等待0..60000毫秒；不是SQL、行锁或整次调用的硬期限。
 * @param[out] result
 *     必需独占独立输出；必需地址齐备后先全清零，再按实际调用填报告。
 *     caller复用前已处理旧报告中的repo资源责任；覆盖值不清理资源。
 * @param[out] error
 *     可NULL；地址齐备后重置，保存下层去敏首因/首清理数值诊断。
 *     即使传NULL，本层也用局部诊断检查清理；不输出SQL、名字、token或文本。
 *
 * @retval VIREO_OK
 *     outcome为FOUND且node有效；底层found/rollback/issue及身份关联一致，清理无错无残留。
 * @retval VIREO_RESULT_NOT_FOUND
 *     outcome为UNAUTHORIZED或NOT_FOUND；底层明确相应issue，回滚确认、清理无错无残留。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址NULL、actor身份或node_id为0，或下层线程/guard等前置拒绝。
 * @retval VIREO_RESULT_RANGE
 *     timeout_ms超过60000；SQL前拒绝。其他下层范围错误原样返回。
 * @retval VIREO_RESULT_DATABASE
 *     SQL、持久行形状或清理失败；outcome为NONE，node为零。
 * @retval VIREO_RESULT_BUSY
 *     repo残留门禁、pool无容量，或下层首清理结果为BUSY；不构成自动重试许可。
 * @retval VIREO_RESULT_TIMEOUT
 *     pool等待到期或首清理结果为TIMEOUT；不表示SQL被抢断。
 * @retval VIREO_RESULT_CANCELLED
 *     pool已关闭或首清理结果为CANCELLED；无内部重试。
 * @retval VIREO_RESULT_NO_MEMORY
 *     底层资源分配失败，或首清理失败为NO_MEMORY。
 * @retval VIREO_RESULT_IO
 *     下层UTC采样等I/O失败，或首清理失败为IO。
 * @retval VIREO_RESULT_OVERFLOW
 *     下层UTC换算不可表示，或首清理失败为OVERFLOW。
 * @retval VIREO_RESULT_INTERNAL
 *     下层内部失败，或可交付路径的返回码/报告/ID关联出现矛盾。
 * @return 其他下层首清理错误原样返回；所有非OK/NOT_FOUND路径outcome=NONE，node全零。
 *
 * @note 任一必需地址NULL时不改result/error；齐备后先清输出，再校验值。
 *     全部地址有效、对齐、互不重叠且不指向errno，输入稳定至返回。
 *     合法值时至多一次repo stat；无服务自有heap/锁/owner，无隐式时钟或重试。
 * @note 错误优先级：保存原repo返回/报告；首清理错误非OK优先成为service返回，
 *     但首清理错误若为NOT_FOUND则返回INTERNAL，以保留NOT_FOUND仅用于完整业务拒绝。
 *     不将清理故障降为普通业务拒绝；outcome=NONE，node全零。
 *     无首清理错但pending时，底层原基础设施错误保持；若原返回为OK/NOT_FOUND则INTERNAL。
 *     可交付FOUND要求found=true、issue=NONE、rollback_confirmed、节点id/owner匹配请求。
 *     可交付拒绝要求found=false、rollback_confirmed及两个明确issue之一；矛盾返回INTERNAL。
 * @note 返回非OK仍须检查repository.cleanup_pending，原repo资源由caller在原worker清理；
 *     此函数不调用destroy、不改变repo所有权、不修改下层主因以掩盖清理错。
 *     result不是completion，不含route/代际/请求实例；未来task桥接负责这些事实。
 * @note worker同步阻塞，同repo串行，独立repo可并行；保持入口errno。
 *     不支持POSIX异步取消/longjmp，不接fd/connection/TLS，不编码wire，不写审计。
 *     只提供读取判断时点的授权，不提供ACL、祖先可达性、CAS或持续有效承诺。
 */
vireo_result_t vireo_directory_service_stat(vireo_mysql_node_repository_t *repository,
    const vireo_mysql_node_actor_t *actor, uint64_t node_id, uint32_t timeout_ms,
    vireo_directory_stat_result_t *result, vireo_mysql_node_error_t *error);

#endif
