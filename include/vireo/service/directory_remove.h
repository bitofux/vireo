/*
 * PROJECT : VIREO
 * FILE    : directory_remove.h
 * BRIEF   : 同步 NODE_REMOVE 服务及清理后可交付结果。
 */
#ifndef VIREO_SERVICE_DIRECTORY_REMOVE_H
#define VIREO_SERVICE_DIRECTORY_REMOVE_H
#include <stdbool.h>
#include <stdint.h>
#include <vireo/persistence/mysql_node_remove_receipt.h>

/** @brief 清理完整且仓库事实一致后才能交付的NODE_REMOVE领域结果。 */
typedef enum vireo_directory_remove_outcome {
    VIREO_DIRECTORY_REMOVE_NONE =
        0, /**< 技术错误、UNKNOWN、清理不完整或报告矛盾；不交付业务结果。 */
    VIREO_DIRECTORY_REMOVE_APPLIED = 1, /**< 本次COMMIT已确认，且清理完整。 */
    VIREO_DIRECTORY_REMOVE_RECOVERED = 2, /**< 当前可信身份恢复了同键历史成功；没有重做删除。 */
    VIREO_DIRECTORY_REMOVE_UNAUTHORIZED = 3, /**< 精确NOT_FOUND/AUTH_REJECTED配对且回滚确认。 */
    VIREO_DIRECTORY_REMOVE_NOT_FOUND = 4, /**< 精确NOT_FOUND/NODE_NOT_FOUND配对且回滚确认。 */
    VIREO_DIRECTORY_REMOVE_ROOT_UNDELETABLE =
        5, /**< 精确DATABASE/ROOT_UNDELETABLE配对且回滚确认。 */
    VIREO_DIRECTORY_REMOVE_DIRECTORY_NOT_EMPTY =
        6, /**< 精确DATABASE/DIRECTORY_NOT_EMPTY配对且回滚确认。 */
    VIREO_DIRECTORY_REMOVE_OBJECT_REFERENCE_INVALID =
        7, /**< 精确DATABASE/OBJECT_REFERENCE_INVALID配对且回滚确认。 */
    VIREO_DIRECTORY_REMOVE_IDEMPOTENCY_CONFLICT =
        8, /**< 精确DATABASE/IDEMPOTENCY_CONFLICT配对且回滚确认。 */
    VIREO_DIRECTORY_REMOVE_RECEIPT_INVALID = 9, /**< 精确DATABASE/RECEIPT_INVALID配对且回滚确认。 */
    VIREO_DIRECTORY_REMOVE_ANCESTRY_LIMIT = 10 /**< 精确RANGE/ANCESTRY_LIMIT配对且回滚确认。 */
} vireo_directory_remove_outcome_t;

/**
 * @brief 独立可交付结果与未改写的repository提交、历史及清理事实。
 *
 * 所有字段均为值，不拥有repository资源。失败时outcome为NONE且可交付业务字段归零；
 * repository_called为true后，repository_result和repository保留原始调用事实。
 */
typedef struct vireo_directory_remove_result {
    vireo_directory_remove_outcome_t outcome; /**< 清理完整且关系有效时的成功或明确拒绝分类。 */
    uint64_t node_id;       /**< 仅APPLIED/RECOVERED时为成功回执目标ID，否则为0。 */
    uint64_t audit_id;      /**< 仅APPLIED/RECOVERED时为首次成功审计ID，否则为0。 */
    uint64_t deleted_at_ms; /**< 仅成功时为历史删除时间；0是合法时间值。 */
    unsigned char
        idempotency_key[VIREO_MYSQL_NODE_REMOVE_KEY_BYTES]; /**< 成功时复制原输入键，其他结果全零。
                                                             */
    bool repository_called;           /**< 本次是否进入唯一一次repository调用。 */
    vireo_result_t repository_result; /**< repository原始rc，不被service返回值改写。 */
    vireo_mysql_node_remove_once_report_t repository; /**< repository原始report；失败时也保留。 */
} vireo_directory_remove_result_t;

/**
 * @brief 最多调用一次soft_delete_once，仅在清理完整且报告一致后交付领域结果。
 *
 * @param[in,out] repository 必需存活repository；须由其创建OS worker串行使用，本函数不接管或销毁。
 * @param[in] actor 必需可信且user_id/session_id非零；仅借用至返回，不能来自未验证客户端字段。
 * @param[in] input 必需稳定值：node_id、16字节幂等键和request_id均非零；仅借用至返回。
 * @param[in] timeout_ms repository连接池等待预算，范围0..60000毫秒；不是SQL或整次调用期限。
 * @param[out] result 必需独占输出。result地址有效时入口先清零，即使其他参数无效也保持清零。
 * @param[out] error
 * 可NULL的独立数值诊断；result地址有效后入口清零，实际调用repository时提供局部诊断。
 *
 * @retval VIREO_OK 仅清理完整且报告一致的APPLIED或RECOVERED。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 * 必需地址、可信身份、node_id、键或事件ID无效；outcome为NONE。
 * @retval VIREO_RESULT_RANGE timeout越界，或精确RANGE/ANCESTRY_LIMIT领域拒绝。
 * @retval VIREO_RESULT_NOT_FOUND 精确NOT_FOUND/AUTH_REJECTED或NOT_FOUND/NODE_NOT_FOUND领域拒绝。
 * @retval VIREO_RESULT_DATABASE 精确软删除领域拒绝或repository原始数据库错误。
 * @retval VIREO_RESULT_INTERNAL 报告矛盾、清理NOT_FOUND或pending伴随可交付成功/明确拒绝。
 * @retval 其他repository错误 保留技术rc；若首清理错误存在，则首清理错误优先。
 *
 * @note
 * 仅精确rc/issue组合能产生领域outcome，所有拒绝还必须是NOT_COMMITTED、无effect、零结果ID且确认rollback。
 *     cleanup_result非OK时优先返回清理错误，清理NOT_FOUND提升为INTERNAL；cleanup_pending阻止交付。
 *     UNKNOWN和未分类SQL错误不推断成功或失败、不自动重放，原report仍可供同worker清理/后续恢复。
 * @note 输入、输出必须有效对齐、互不覆盖且不指向errno；输出由调用者独占，函数不分配或保存地址。
 *     同一repository只可在创建它的worker上串行调用；互不关联的repository可并行。errno原值保持。
 *     不递归删除、不物理删除对象、不做GC/恢复、不实现wire状态映射、异步worker或内部重试。
 */
vireo_result_t vireo_directory_service_remove(vireo_mysql_node_repository_t *repository,
                                              const vireo_mysql_node_actor_t *actor,
                                              const vireo_mysql_node_remove_once_input_t *input,
                                              uint32_t timeout_ms,
                                              vireo_directory_remove_result_t *result,
                                              vireo_mysql_node_error_t *error);

#endif
