/* PROJECT : VIREO; FILE : directory_mkdir_completion.h;
 * AUTHOR : bitofux; DATE : 2026-10-24; BRIEF : 独立目录创建结果投影、回投与专用解码。 */
#ifndef VIREO_SERVICE_DIRECTORY_MKDIR_COMPLETION_H
#define VIREO_SERVICE_DIRECTORY_MKDIR_COMPLETION_H
#include <vireo/service/directory_mkdir_task.h>
#include <vireo/thread/completion_publish.h>

/** @brief VMC1内部前缀48字节，只在进程内使用。 */
#define VIREO_DIRECTORY_MKDIR_COMPLETION_PREFIX_SIZE ((size_t)48)
/** @brief 内部最大payload为48+64=112，最小48+32=80。 */
#define VIREO_DIRECTORY_MKDIR_COMPLETION_PAYLOAD_MAX ((size_t)112)

/** @brief 无借用的独立值；actor及原handle只供进程内重核，不整块发送。 */
typedef struct vireo_directory_mkdir_completion_outcome {
    vireo_completion_metadata_t metadata; /**< 原完整请求、原执行rc和精确status建议。 */
    vireo_mysql_node_actor_t actor;       /**< 原task身份；未来Reactor仍核当前绑定。 */
    uint32_t request_session_handle;      /**< 原非零请求handle；错误wire仍为0。 */
    unsigned char request_idempotency_key[16]; /**< 原非零逻辑键；错误wire的键仍为零。 */
    vireo_node_mkdir_response_t response; /**< 原完整响应解析值；成功原node/key或零错误值。 */
} vireo_directory_mkdir_completion_outcome_t;

/** @brief 本次真实进度；布尔值不取代实际owner/原交接报告。 */
typedef struct vireo_directory_mkdir_completion_publish_report {
    bool task_matched; /**< task与result.input全部逻辑字段已匹配。 */
    bool result_validated; /**< 阶段/rc/service及原清理事实配对合法，响应编码成功。 */
    bool publish_called; /**< 已调用一次公开copy_wait_publish。 */
    vireo_completion_publish_report_t
        publication; /**< 原created/transferred/remaining/notify事实。 */
} vireo_directory_mkdir_completion_publish_report_t;

/**
 * @brief 核原task与结果并投影，复制VMC1、等待交接并通知一次
 * @param[in] task
 *     必需稳定原task，短借，不销毁。
 * @param[in] mkdir_operation
 *     非零可信预期标签。
 * @param[in] result
 *     必需原执行结果；资源前置失败可为匹配CONTEXT+非OK，原事实不改。
 * @param[in] allocation_budget
 *     正且不超completion硬限，含控制块及80或112字节payload。
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
 * @note 核完整原metadata/actor/handle/seq/parent/name有效字节/key，原service关系矛盾不发布。
 *     CREATED/RECOVERED→OK；INVALID_NAME/NOT_NFC→INVALID_PATH；UNAUTHORIZED→UNAUTHORIZED；
 *     PARENT_NOT_FOUND→NOT_FOUND；两显式冲突→CONFLICT。历史清理错/pending→INTERNAL_ERROR。
 *     NONE技术DATABASE→DB_ERROR，BUSY/TIMEOUT/CANCELLED/NO_MEMORY各沿常规建议，余→INTERNAL_ERROR。
 *     非OK不证明未提交；保存raw commit/effect，UNKNOWN或1062不推定冲突、不重放。
 * @note VMC1=magic4/reserved4零/actor两u64/原handle u32/frame_size u32/原key16/完整32或64响应。
 *     错误wire node/handle/key零；原execute rc在metadata。只可专用decode，不整块发送。
 *     raw RECOVERED在ROLLBACK清理失败时可未确认rollback；历史成功ID仍保留，不能发OK。
 * @note caller须先完成原worker外层清理，本函数无repo不能证明当前资源已释放。
 *     service的pending是历史快照：即使后来destroy成功也只能投INTERNAL_ERROR，不篡改原事实。
 *     仅可等待worker、POSIX取消禁用；可能分配/阻塞，consumer先drain再join并最终drain。
 *     已交接通知失败只修通知/消费，绝不重投或重做SQL；每结果只publish一次。
 *     保持errno，地址独立有效不指errno，依赖借至返回且由caller保活。
 */
vireo_result_t vireo_directory_mkdir_completion_publish(
    const vireo_task_t *task, uint32_t mkdir_operation,
    const vireo_directory_mkdir_task_result_t *result, size_t allocation_budget,
    vireo_completion_queue_t *queue, vireo_notifier_t *notifier, vireo_completion_t **remaining,
    vireo_directory_mkdir_completion_publish_report_t *report);

/**
 * @brief 严格校验VMC1及已有响应，发布独立值，不发送或修改Session
 * @param[in] completion
 *     必需稳定专用completion，短借，不移动/消费。
 * @param[in] mkdir_operation
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
 * @note 先核总长80或112、frame_size32或64，再精确48+size，原key非零。
 *     seq/status匹配metadata，OK非零node、原handle/key相等；CRC与schema均核。
 *     OK→OK；PROTOCOL→INVALID_PATH或INTERNAL；RANGE只INTERNAL；NOT_FOUND→UNAUTHORIZED/NOT_FOUND或INTERNAL；
 *     DATABASE→CONFLICT/DB_ERROR或INTERNAL；BUSY/TIMEOUT/CANCELLED/NO_MEMORY各为常规建议或INTERNAL；
 *     其他已知非OK只INTERNAL_ERROR。publisher另核完整业务关系，未知rc拒绝。
 *     本层不证明来源/当前inflight/绑定/期限，也不能从completion反推清理owner状态。
 *     无申请/I/O/采时，保持errno；稳定借用、独立输出可并发，地址不重叠不指errno。
 */
vireo_result_t vireo_directory_mkdir_completion_decode(
    const vireo_completion_t *completion, uint32_t mkdir_operation,
    vireo_directory_mkdir_completion_outcome_t *out);
#endif
