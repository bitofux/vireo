/* PROJECT: VIREO; FILE: directory_stat_completion.h; DATE: 2026-10-22. */
#ifndef VIREO_SERVICE_DIRECTORY_STAT_COMPLETION_H
#define VIREO_SERVICE_DIRECTORY_STAT_COMPLETION_H
#include <vireo/service/directory_stat_task.h>
#include <vireo/thread/completion_publish.h>

/** @brief VDC1内部前缀40字节，后接已编码完整response；不是网络body。 */
#define VIREO_DIRECTORY_STAT_COMPLETION_PREFIX_SIZE ((size_t)40)
/** @brief 内部最大payload为40+393；不是sizeof(outcome)。 */
#define VIREO_DIRECTORY_STAT_COMPLETION_PAYLOAD_MAX ((size_t)433)

/** @brief 解码后独立拥有值；actor只在进程内使用，禁止整块写入网络。 */
typedef struct vireo_directory_stat_completion_outcome {
    vireo_completion_metadata_t metadata; /**< 完整请求/原执行rc/精确状态建议。 */
    vireo_mysql_node_actor_t actor; /**< 原task可信身份；Reactor发送前仍重核当前绑定。 */
    uint64_t requested_node_id; /**< 原请求非零节点，错误响应也保留以核关联。 */
    uint32_t request_session_handle; /**< 原请求非零handle；非OK wire中的handle仍为0。 */
    vireo_node_stat_response_t response; /**< 独立解析的既有协议值，无输入借用。 */
} vireo_directory_stat_completion_outcome_t;

/** @brief 专用投影验证与原交接报告；布尔事实不替代真实owner值。 */
typedef struct vireo_directory_stat_completion_publish_report {
    bool task_matched; /**< task/完整metadata、身份、node、handle逐逻辑字段一致。 */
    bool result_validated; /**< 执行阶段、rc、service清理及业务字段配对合法。 */
    bool publish_called; /**< 实际调用一次公开copy_wait_publish。 */
    vireo_completion_publish_report_t publication; /**< 本次原交接/保留/通知事实。 */
} vireo_directory_stat_completion_publish_report_t;

/**
 * @brief 显式投影结果，复制VDC1并沿既有完成队列交接、通知一次
 * @param[in] task 必需原存活task，短借至返回；不销毁。
 * @param[in] stat_operation 非零预期操作标签，须与task/result一致。
 * @param[in] result 必需原执行结果，或worker资源失败合成的CONTEXT结果；不修改。
 * @param[in] allocation_budget 正且不超completion硬限，含控制块及72..433字节内部payload。
 * @param[in,out] queue 必需prepared存活专用队列，consumer持续腾空间。
 * @param[in,out] notifier 必需同队列配对存活通知源，只借至返回。
 * @param[out] remaining 必需独占空owner；失败若未交接，已创建对象留此处，caller负责destroy。
 * @param[out] report 必需独立报告，每可写路径覆盖真实进度。
 * @retval VIREO_OK 已交接并通知，不代表业务OK、已发送或客户仍有效。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 必需NULL/非空remaining/零配置、未知rc或矛盾执行结果。
 * @retval VIREO_RESULT_PROTOCOL 原task非法或关联不一致。
 * @return 原预算/分配/队列/通知错误透传；非OK也可能已经交接，须看publication。
 * @note 映射：完整FOUND→OK；完整身份拒绝→UNAUTHORIZED；不可见节点→NOT_FOUND；
 *     清理错误/残留一律INTERNAL_ERROR；其余TIMEOUT/BUSY/CANCELLED→TIMEOUT/BUSY/UNAVAILABLE，
 *     其他已知内部失败→INTERNAL_ERROR。绝不输出DB_ERROR、repo报告或C布局。
 *     metadata.result保原执行rc；纯读取无COMMITTED/UNKNOWN分支，不生成审计ID/token。
 * @note 调用者须先完成其外层repo destroy/guard detach；外层清理失败时不调用本函数，
 *     原worker保留owner并向管理层报告未交付。service自身曾清理失败则按上述错误投影。
 * @note VDC1：magic4/reserved4/actor两u64/node u64/原handle u32/frame_size u32/完整response。
 *     非OK完整wire恰32字节，不含身份；整个VDC1只能专用decode，不能交generic网络sender。
 * @note 保持errno；可能分配/等待，仅worker且POSIX取消禁用；consumer先drain再join，最后无条件drain。
 *     原transferred决定所有权；已交接通知失败只能修通知/消费，不能重投/重做SQL。
 *     每结果只调用一次；地址独立不重叠、不指errno，依赖保活至返回。
 */
vireo_result_t vireo_directory_stat_completion_publish(vireo_task_t const *task,
    uint32_t stat_operation, vireo_directory_stat_task_result_t const *result, size_t allocation_budget,
    vireo_completion_queue_t *queue, vireo_notifier_t *notifier,
    vireo_completion_t **remaining, vireo_directory_stat_completion_publish_report_t *report);

/**
 * @brief 校验VDC1/元数据及完整response，发布独立值，不发送或改变Session
 * @param[in] completion 必需稳定存活专用结果，短借，不移动/消费。
 * @param[in] stat_operation 必需非零可信标签，metadata.operation须匹配。
 * @param[out] out 必需独立输出，成功才覆盖；失败整个对象含padding保持。
 * @retval VIREO_OK 精确长度/reserved/非零身份与原关联/CRC/schema/status配对通过。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 必需NULL或stat_operation=0。
 * @retval VIREO_RESULT_PROTOCOL 畸形内部payload、原关联、未知rc或状态配对矛盾。
 * @return 原公开completion查询错误透传。
 * @note 保持errno，无申请/I/O；先核72..433总长及32..393声明再加法/读帧。
 *     核seq、OK句柄/节点与原请求一致、status等于metadata建议，错误body仍为空。
 *     metadata.result可与INTERNAL_ERROR配对表示service清理失败，不能仅按rc猜业务。
 *     来源由专用调度保证；magic非认证，Reactor仍核当前inflight、绑定及期限。
 *     独立输出可并发，同对象须外部同步；地址独立不重叠、不指errno。
 */
vireo_result_t vireo_directory_stat_completion_decode(vireo_completion_t const *completion,
    uint32_t stat_operation, vireo_directory_stat_completion_outcome_t *out);
#endif
