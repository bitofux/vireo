/* PROJECT : VIREO; FILE : directory_root_completion.h;
 * AUTHOR : bitofux; DATE : 2026-10-22; BRIEF : 独立根结果投影、回投与专用解码。 */
#ifndef VIREO_SERVICE_DIRECTORY_ROOT_COMPLETION_H
#define VIREO_SERVICE_DIRECTORY_ROOT_COMPLETION_H
#include <vireo/service/directory_root_task.h>
#include <vireo/thread/completion_publish.h>

/** @brief VRC1内部前缀32字节，只在进程内使用。 */
#define VIREO_DIRECTORY_ROOT_COMPLETION_PREFIX_SIZE ((size_t)32)
/** @brief 内部最大payload为32+44=76，最小32+32=64。 */
#define VIREO_DIRECTORY_ROOT_COMPLETION_PAYLOAD_MAX ((size_t)76)

/** @brief 无借用的独立值；actor及原handle只供进程内重核，不整块发送。 */
typedef struct vireo_directory_root_completion_outcome {
    vireo_completion_metadata_t metadata; /**< 原完整请求、原执行rc和精确status建议。 */
    vireo_mysql_node_actor_t actor;       /**< 原task身份；未来Reactor仍核当前绑定。 */
    uint32_t request_session_handle;      /**< 原非零请求handle；错误wire仍为0。 */
    vireo_node_root_response_t response; /**< 原完整响应解析值；无requested_node_id。 */
} vireo_directory_root_completion_outcome_t;

/** @brief 本次真实进度；布尔值不取代实际owner/原交接报告。 */
typedef struct vireo_directory_root_completion_publish_report {
    bool task_matched; /**< task与result.input全部逻辑字段已匹配。 */
    bool result_validated; /**< 阶段/rc/service及原清理事实配对合法，响应编码成功。 */
    bool publish_called; /**< 已调用一次公开copy_wait_publish。 */
    vireo_completion_publish_report_t
        publication; /**< 原created/transferred/remaining/notify事实。 */
} vireo_directory_root_completion_publish_report_t;

/**
 * @brief 核原task与结果并投影，复制VRC1、等待交接并通知一次
 * @param[in] task
 *     必需稳定原task，短借，不销毁。
 * @param[in] root_operation
 *     非零可信预期标签。
 * @param[in] result
 *     必需原执行结果；资源前置失败可为匹配CONTEXT+非OK，原事实不改。
 * @param[in] allocation_budget
 *     正且不超completion硬限，含控制块及64或76字节payload。
 * @param[in,out] queue
 *     必需prepared专用队列，consumer须持续腾空间。
 * @param[in,out] notifier
 *     必需同队列通知源，caller保活并保证配对。
 * @param[out] remaining
 *     必需独占空owner，未交接失败时caller须处理已创建对象。
 * @param[out] report
 *     必需独立报告，非NULL时入口重置，保存真实前缀。
 *
 * @retval VIREO_OK
 *     已交接并提示，不证明业务OK、已经发送或当前绑定仍有效。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需NULL/非空remaining/零配置、未知rc或矛盾结果。
 * @retval VIREO_RESULT_PROTOCOL
 *     原task非法或逻辑关联不匹配。
 * @return 预算/分配/队列/通知错误沿原码；非OK也可能已交接，须看原transferred。
 *
 * @note FOUND→OK，完整AUTH_REJECTED→UNAUTHORIZED；清理首错/pending历史→INTERNAL_ERROR。
 *     无清理故障时BUSY/TIMEOUT/CANCELLED/NO_MEMORY→BUSY/TIMEOUT/UNAVAILABLE/OVERLOADED，
 *     其余已定义非OK→INTERNAL_ERROR。无普通NOT_FOUND，未知内部rc不发布。
 * @note VRC1=magic4/reserved4零/actor两u64/原handle u32/frame_size u32/完整32或44字节response。
 *     原task全部metadata/actor/seq/handle匹配，错误wire的root/handle0；不包含SQL/诊断。
 *     只可专用decode，禁止整块交generic sender；原执行rc保留在completion metadata。
 * @note caller须先完成原worker外层清理，本函数无repo不能证明当前资源已释放。
 *     service的pending是历史快照：即使后来destroy成功也只能投INTERNAL_ERROR，不篡改原事实。
 *     仅可等待worker、POSIX取消禁用；可能分配/阻塞，consumer先drain再join并最终drain。
 *     已交接通知失败只修通知/消费，绝不重投或重做SQL；每结果只publish一次。
 *     保持errno，地址独立有效不指errno，依赖借至返回且由caller保活。
 */
vireo_result_t vireo_directory_root_completion_publish(
    const vireo_task_t *task, uint32_t root_operation,
    const vireo_directory_root_task_result_t *result, size_t allocation_budget,
    vireo_completion_queue_t *queue, vireo_notifier_t *notifier, vireo_completion_t **remaining,
    vireo_directory_root_completion_publish_report_t *report);

/**
 * @brief 严格校验VRC1及已有响应，发布独立值，不发送或修改Session
 * @param[in] completion
 *     必需稳定专用completion，短借，不移动/消费。
 * @param[in] root_operation
 *     非零可信标签，须与metadata.operation相同。
 * @param[out] out
 *     必需独立输出，仅成功覆盖，失败全部含padding保持。
 *
 * @retval VIREO_OK
 *     长度/reserved/身份/原关联/CRC/schema/rc-status配对通过。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需NULL或零operation。
 * @retval VIREO_RESULT_PROTOCOL
 *     畸形内部payload、未知rc、关联或状态配对错误。
 * @return 原completion查询错误透传。
 *
 * @note 先核总长64或76、frame_size32或44，再精确32+size；只在有界长度内读取。
 *     seq等于metadata请求，status等于建议，OK的handle等于原非零handle且root非零。
 *     OK→OK，NOT_FOUND→UNAUTHORIZED；BUSY/TIMEOUT/CANCELLED/NO_MEMORY各对应正常建议
 *     或INTERNAL_ERROR；其余已知非OK只能INTERNAL_ERROR；不存在wire NOT_FOUND配对。
 *     本层不证明来源/当前inflight/绑定/期限，也不能从completion反推清理owner状态。
 *     无申请/I/O/采时，保持errno；稳定借用、独立输出可并发，地址不重叠不指errno。
 */
vireo_result_t vireo_directory_root_completion_decode(
    const vireo_completion_t *completion, uint32_t root_operation,
    vireo_directory_root_completion_outcome_t *out);
#endif
