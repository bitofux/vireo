/* PROJECT : VIREO
 * FILE : auth_task_context.h
 * AUTHOR : bitofux
 * DATE : 2026-10-20
 * BRIEF : 在worker从服务端随机源和两个时钟生成认证执行上下文。
 */
#ifndef VIREO_SERVICE_AUTH_TASK_CONTEXT_H
#define VIREO_SERVICE_AUTH_TASK_CONTEXT_H
#include <vireo/base/clock.h>
#include <vireo/service/auth_task.h>

/** 本次采样首错阶段；不表示业务已开始或数据库状态。 */
typedef enum vireo_auth_context_stage {
    VIREO_AUTH_CONTEXT_NONE = 0, /**< 成功或必需地址/LOGIN寿命拒绝。 */
    VIREO_AUTH_CONTEXT_TASK = 1, /**< 原task inspect/借用。 */
    VIREO_AUTH_CONTEXT_DECODE = 2, /**< 独立完整帧解析。 */
    VIREO_AUTH_CONTEXT_RANDOM = 3, /**< 16字节CSPRNG失败或产生被政策排除的全零值。 */
    VIREO_AUTH_CONTEXT_UTC = 4, /**< CLOCK_REALTIME原生采样或形态/毫秒转换失败。 */
    VIREO_AUTH_CONTEXT_EXPIRY = 5, /**< UTC签发时间加显式LOGIN寿命不可表示。 */
    VIREO_AUTH_CONTEXT_MONOTONIC = 6, /**< 最后一次公开单调时钟采样失败。 */
    VIREO_AUTH_CONTEXT_LATENCY = 7 /**< received_at_ns晚于最后样本，不做无符号减法。 */
} vireo_auth_context_stage_t;

/** 独立去敏诊断；不保存秘密、对象指针或OpenSSL错误文本。 */
typedef struct vireo_auth_context_error {
    vireo_auth_context_stage_t stage; /**< 首错位置，成功/基本拒绝为NONE。 */
    int system_errno; /**< 仅REALTIME返回-1时保存原errno，其他为0。 */
    vireo_clock_error_t monotonic_error; /**< 原公开monotonic诊断；未采样为零。 */
    vireo_auth_request_issue_t request_issue; /**< 原帧解析诊断；不包含输入。 */
} vireo_auth_context_error_t;

/**
 * @brief 为task采样可信事件ID、UTC/expiry、执行前MONOTONIC和入站以来耗时
 *
 * @param[in] task
 *     必需存活task，短借至返回；必须已由可信TLS/一次LOGIN准入路径提交完整帧。
 * @param[in] received_at_ns
 *     caller为此task记录的可信入站同域MONOTONIC纳秒，不能晚于本次最后样本。
 * @param[in] session_lifetime_ms
 *     显式LOGIN寿命毫秒，1..UINT64_MAX且UTC相加须可表示；其他命令忽略，expires=0。
 * @param[in] options
 *     必需四标签注册表，与提交端相同；以operation选择wire/VAL1解析模式，不保存借用。
 * @param[out] out
 *     必需独占context，只在完整成功时发布；失败保持整个旧值，不保留地址。
 * @param[out] error
 *     可NULL独立诊断，每次覆盖；不与其他存储或errno重叠。
 *
 * @retval VIREO_OK
 *     输出已完整匹配task metadata；ID非全零，但不承诺数学意义全局无碰撞。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     task/options/out为NULL或注册表无效。
 * @retval VIREO_RESULT_RANGE
 *     LOGIN寿命为0，或received_at_ns晚于当前样本。
 * @retval VIREO_RESULT_PROTOCOL
 *     task不满足对应认证wire或LOGOUT VAL1形态。
 * @retval VIREO_RESULT_IO
 *     CSPRNG失败/全零、REALTIME失败或公开monotonic采样IO失败。
 * @retval VIREO_RESULT_OVERFLOW
 *     UTC毫秒、LOGIN到期或原monotonic转换不可表示。
 * @retval VIREO_RESULT_INTERNAL
 *     原生clock返回约定/时间形态异常，或原公开clock内部失败。
 *
 * @note 顺序为task/帧/寿命→一次RAND_priv_bytes(16)→一次REALTIME→受检expiry→
 *       一次公开monotonic→非负差/1000截断为微秒→发布。无重试、默认TTL或时钟回拨修正。
 *       REALTIME秒须非负，纳秒0..999999999；UTC向下取整毫秒，0合法。
 * @note 保持errno；worker/允许阻塞的装配上下文使用，随机源可能初始化/阻塞。
 *       received来源/与task关联由caller保证，本入口不能证明该普通数值的来源。
 *       不延长task期限、不调用service、准入或DB，不提供跨时钟原子快照。
 * @note 生命周期/并发：所有对象独立不重叠，task借用期间不移动/销毁；独立输出可并发，
 *       依赖和共享存储寿命由caller同步。不接客户fd、connection或网络状态。
 */
vireo_result_t vireo_auth_task_context_capture(vireo_task_t const *task,
    vireo_monotonic_ns_t received_at_ns, uint64_t session_lifetime_ms,
    vireo_auth_task_options_t const *options,
    vireo_auth_task_context_t *out, vireo_auth_context_error_t *error);
#endif
