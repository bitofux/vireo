/*
 * PROJECT : VIREO
 * FILE    : completion_publish.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-14
 * BRIEF   : worker独立响应复制、等待回投和交接后通知
 */
#ifndef VIREO_THREAD_COMPLETION_PUBLISH_H
#define VIREO_THREAD_COMPLETION_PUBLISH_H

#include <vireo/thread/completion_queue.h>
#include <vireo/thread/notifier.h>

/** 本入口的主失败阶段，独立于队列、通知和工作结果枚举。 */
typedef enum vireo_completion_publish_stage {
    VIREO_COMPLETION_PUBLISH_NONE = 0, /**< 成功或基本参数拒绝。 */
    VIREO_COMPLETION_PUBLISH_INSPECT_TASK = 1, /**< 公开读取原任务。 */
    VIREO_COMPLETION_PUBLISH_MAKE_METADATA = 2, /**< 构造完成描述。 */
    VIREO_COMPLETION_PUBLISH_CREATE_COMPLETION = 3, /**< 复制独立响应对象。 */
    VIREO_COMPLETION_PUBLISH_PUSH_QUEUE = 4, /**< 等待交接；原错误优先通知错误。 */
    VIREO_COMPLETION_PUBLISH_NOTIFY = 5 /**< 已交接后的一次提示失败。 */
} vireo_completion_publish_stage_t;

/**
 * @brief
 *     本调用真实进度的独立值报告，不拥有或保活资源。
 *
 * @note
 *     每可写路径发布；未调用的逻辑零值不是运行证据。
 *     created/transferred表示本次曾发生，不能推断返回时对象仍未消费。
 *     push错误优先，notify的结果和原诊断仍独立保存；不回滚已发生步骤。
 */
typedef struct vireo_completion_publish_report {
    vireo_completion_publish_stage_t stage; /**< 主错误的阶段，成功NONE。 */
    bool task_inspected; /**< 原task inspect成功后才true。 */
    vireo_task_metadata_t request_metadata; /**< task_inspected时有效的原完整请求值。 */
    bool completion_created; /**< 本次曾完整构造独立completion。 */
    bool push_called; /**< 本次是否调用一次wait_push。 */
    vireo_result_t push_result; /**< push_called时有效的原返回。 */
    vireo_completion_queue_transfer_report_t queue_report; /**< 同次原交接报告。 */
    bool completion_transferred; /**< 原报告确认本次身份已交队列。 */
    bool completion_retained; /**< 返回时remaining持本次未交接对象。 */
    bool notify_called; /**< 确认交接后是否调用一次notify。 */
    vireo_result_t notify_result; /**< notify_called时有效的原返回。 */
    vireo_notifier_notify_outcome_t notify_outcome; /**< notify_called且OK时才有效。 */
    vireo_notifier_error_t notify_error; /**< 同次原通知诊断，不是本层stage。 */
} vireo_completion_publish_report_t;

/**
 * @brief
 *     复制task的完整请求描述和显式响应，等待交接后通知一次。
 *
 * @param[in] task
 *     必需存活task，const短借至返回，不移动/销毁或保存指针。
 * @param[in] result
 *     caller显式提供的已定义工作结果，允许失败，不是本函数返回值。
 * @param[in] suggested_status
 *     caller显式提供的已注册协议建议，不自动与result配对。
 * @param[in] data
 *     稳定可读响应字节，非零payload_size须非NULL，零长度不读取。
 *     可来自仍有效task借用，复制完成后不再读取或保存地址。
 * @param[in] payload_size
 *     size_t响应字节数，可为0；不解释wire、schema或内嵌指针。
 * @param[in] allocation_budget
 *     正size_t预算≤VIREO_COMPLETION_MAX_ALLOCATION_BYTES，只计本次
 *     completion控制块＋响应字节；沿公开受检计算，不计其他资源。
 * @param[in,out] queue
 *     必需存活已prepare完成队列，借至返回；多producer可并发。
 * @param[in,out] notifier
 *     必需存活通知对象，借至返回，caller保证与queue对应。
 * @param[out] remaining
 *     必需独占owner地址，入口NULL；创建后未交接的失败把对象交caller。
 *     caller须公开destroy或明确后续处理，本入口不自动清理或再提交。
 * @param[out] report
 *     必需独立可写报告，每可写路径发布，地址只借至返回。
 *
 * @retval VIREO_OK
 *     构造/交接/提示完成，remaining为NULL；不表示工作成功或已经发送。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需NULL、零预算、非空remaining、非零字节配NULL，或原元数据
 *     构造拒绝工作result/status；基本校验先于任何依赖。
 * @retval VIREO_RESULT_OVERFLOW
 *     原create_copy受检申请字节不可表示，优先于限额检查，无新owner。
 * @retval VIREO_RESULT_RANGE
 *     原create_copy的预算超限或不足，无新owner。
 * @retval VIREO_RESULT_NO_MEMORY
 *     原create_copy申请失败，无半对象。
 * @retval VIREO_RESULT_NOT_FOUND
 *     queue尚未prepare，已创建对象交remaining，不通知。
 * @retval VIREO_RESULT_CANCELLED
 *     queue原收尾或关闭拒绝，已创建对象交remaining，不通知。
 * @retval VIREO_RESULT_INTERNAL
 *     原queue同步异常或notify异常，按报告承担实际交接及残留义务。
 * @retval VIREO_RESULT_IO
 *     queue成功交接后的notify系统失败，原errno在notify_error中。
 *
 * @note
 *     顺序为inspect→metadata_make→create_copy→wait_push→notify，其他公开
 *     依赖错误原样返回。全路径保持入口errno，报告保真实前缀，失败不保证
 *     队列/通知状态全部保持；基本拒绝保持remaining入口值。
 *     只看原queue_report.transferred决定所有权；即使push非OK但已交接，
 *     仍notify一次，push原错优先，通知原错独立报告。未交接不notify。
 *     转移后不再读取或销毁原对象；consumer可能在notify之前就已清理它。
 * @note
 *     仅允许等待的worker使用，整个调用POSIX取消须已禁用，不用于Reactor、
 *     signal handler。申请及wait_push可能阻塞，无超时、公平或硬实时保证。
 *     多producer须有独立输出/task借用，共享context/寿命由caller同步。
 *     task、data、owner/report、queue/notifier及errno存储不得非法重叠；
 *     借用不保活，create/prepare/destroy必须排除全部在途访问。
 * @note
 *     consumer须配合腾空间再join，producer结束后无条件最后drain。
 *     通知失败须caller主动调度或明确收尾，不能重新入队；不内部重试、
 *     回滚、销毁残留、读取网络、自动检查期限/取消或映射响应描述。
 */
vireo_result_t vireo_completion_copy_wait_publish(vireo_task_t const *task,
    vireo_result_t result, vireo_status_t suggested_status, void const *data,
    size_t payload_size, size_t allocation_budget, vireo_completion_queue_t *queue,
    vireo_notifier_t *notifier, vireo_completion_t **remaining,
    vireo_completion_publish_report_t *report);

#endif /* VIREO_THREAD_COMPLETION_PUBLISH_H */
