/*
 * PROJECT : VIREO
 * FILE    : client_deadline_request.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-10
 * BRIEF   : 此模块负责：
 * -- 显式请求固定总期限登记、查询及取消
 * -- 只依赖已采用公开合同，保持资源、输出与 errno 的既有边界
 */
#ifndef VIREO_NET_CLIENT_DEADLINE_REQUEST_H
#define VIREO_NET_CLIENT_DEADLINE_REQUEST_H

#include <vireo/net/client_deadline.h>

/** caller 普通数值记录，不拥有或保活资源，不作为 wire ABI。
 * 全逻辑零为空；非空须完整 binding、sequence 非零及 started < deadline。
 * caller 保证真实请求关联，不手改字段或旁路 rearm 此 timer。 */
typedef struct vireo_client_deadline_request {
    vireo_client_deadline_binding_t binding; /**< 完整客户及 timer 身份，标识此登记实例。 */
    uint32_t request_sequence; /**< 已验证请求的非零协议标签，不是唯一代际身份。 */
    vireo_monotonic_ns_t started_ns;  /**< caller 明确选择的同域新鲜开始纳秒。 */
    vireo_monotonic_ns_t deadline_ns; /**< checked 开始＋正总长的固定纳秒快照。 */
} vireo_client_deadline_request_t;

/** 独立请求诊断，不修改旧 client_deadline 阶段，不是 wire 状态或重试指令。 */
typedef enum vireo_client_deadline_request_stage {
    VIREO_CLIENT_DEADLINE_REQUEST_NONE = 0, /**< 成功或本层基本形态／空身份拒绝。 */
    VIREO_CLIENT_DEADLINE_REQUEST_CHECK_CLIENT = 1, /**< 公开客户当前性核验拒绝。 */
    VIREO_CLIENT_DEADLINE_REQUEST_CHECK_OPEN = 2,   /**< 登记客户不是 OPEN。 */
    VIREO_CLIENT_DEADLINE_REQUEST_CHECK_TIMER = 3, /**< 轮观测、停止或固定期限不一致。 */
    VIREO_CLIENT_DEADLINE_REQUEST_CHECK_TIME = 4,     /**< 时间倒退或受检加法拒绝。 */
    VIREO_CLIENT_DEADLINE_REQUEST_REGISTER_TIMER = 5, /**< 公开登记拒绝。 */
    VIREO_CLIENT_DEADLINE_REQUEST_CANCEL_TIMER = 6    /**< 公开取消拒绝，记录保持。 */
} vireo_client_deadline_request_stage_t;

/**
 * @brief 以显式开始和正总时长登记固定请求期限并保存完整记录
 *
 * @param[in] server
 *     非空存活 server，短借到返回；客户须当前 OPEN。
 * @param[in,out] wheel
 *     非空存活已 prepare 且未停止轮，沿原容量及预算。
 * @param[in] client
 *     完整当前客户租约，不是异步任务身份。
 * @param[in] request_sequence
 *     已验证请求的非零 uint32 协议标签，由 caller 保证对应此客户。
 * @param[in] started_ns
 *     同域新鲜 CLOCK_MONOTONIC 纳秒，至少轮最近成功 advance 样本。
 * @param[in] total_timeout_ns
 *     正 uint64 纳秒长度，无默认；受检相加及量化不回绕或截限。
 * @param[in,out] out_request
 *     必需独立 caller 记录，入口逻辑全零；全部成功才提交四字段。
 * @param[out] out_stage
 *     可空独立诊断，每路径覆盖，成功 NONE。
 *
 * @retval VIREO_OK
 *     完整登记并提交记录，登记后无可失败步骤。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需 NULL、畸形客户、零 sequence／总长或输出非空。
 * @retval VIREO_RESULT_NOT_FOUND
 *     空／旧客户或轮未 prepare；其余依赖错误原样返回。
 * @retval VIREO_RESULT_BUSY
 *     当前客户不为 OPEN，或合法登记遇轮满。
 * @retval VIREO_RESULT_CANCELLED
 *     轮停止，检查先于时间与加法。
 * @retval VIREO_RESULT_RANGE
 *     开始早于轮样本，或依赖所属槽越界。
 * @retval VIREO_RESULT_OVERFLOW
 *     开始＋总长、量化边界或登记发序不可表示。
 *
 * @note
 *     基本参数→客户当前→OPEN→prepare／stop→时间→加法→登记→数值提交。
 *     失败整个记录及资源保持；无申请、采样、网络、业务回调或重试。
 * @note
 *     总期限固定，不因字节活动延长；sequence 可复用而完整 timer 不同，不限制同客户重复标签。
 *     业务起点及完成由 caller 明确选择，不抢占同步 handler、不新增请求池或异步 inflight。
 * @note
 *     所有对象同 Reactor；地址短借、独立存活对齐、非重叠、非自有存储且非 errno。
 *     本头所有路径保持入口 errno；成功只保证逻辑字段，不承诺 padding 或 ABI。
 */
vireo_result_t vireo_client_deadline_request_start(
    vireo_tcp_server_t const *server, vireo_timer_wheel_t *wheel,
    vireo_connection_pool_lease_t client, uint32_t request_sequence,
    vireo_monotonic_ns_t started_ns, vireo_duration_ns_t total_timeout_ns,
    vireo_client_deadline_request_t *out_request, vireo_client_deadline_request_stage_t *out_stage);

/**
 * @brief 核验当前双方及固定期限后，只读返回精确纳秒到期判断
 *
 * @param[in] server
 *     非空存活 server，当前 closing 客户仍允许查询。
 * @param[in] wheel
 *     非空存活所属轮；停止轮仍可查询，ready 未领取身份仍活跃。
 * @param[in] request
 *     必需完整记录，只借到返回；不手改字段或旁路重排此 timer。
 * @param[in] now_ns
 *     同域新鲜纳秒，不早于记录开始或轮最近成功推进样本。
 * @param[out] out_expired
 *     必需独立 bool，全部成功才覆盖；等号到期，失败保持全部字节。
 * @param[out] out_stage
 *     可空独立诊断，每路径覆盖，成功 NONE。
 *
 * @retval VIREO_OK
 *     写 bool(now >= 固定 deadline)，到期仍 OK，不消费 timer 或通知。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需 NULL、半空／畸形记录，或轮内期限与保存快照不一致。
 * @retval VIREO_RESULT_NOT_FOUND
 *     空记录、旧客户或已取消／已领取 timer、未 prepare；不把旧值当成功。
 * @retval VIREO_RESULT_RANGE
 *     now 早于开始或轮样本，或依赖槽越界；其余依赖错误原样返回。
 *
 * @note
 *     基本形态→客户当前→timer 当前／期限一致→轮进度→时间→bool。
 *     全程只读，不刷新、推进、领取、回复、取消、关闭或自动归还；失败记录与资源保持。
 * @note
 *     0／UINT64_MAX 是有限时间，不作空哨兵；正时长要求 started < deadline。
 *     同 Reactor，地址短借、独立有效对齐、非重叠、非自有存储且非 errno；保持 errno。
 */
vireo_result_t vireo_client_deadline_request_check(
    vireo_tcp_server_t const *server, vireo_timer_wheel_t const *wheel,
    vireo_client_deadline_request_t const *request, vireo_monotonic_ns_t now_ns, bool *out_expired,
    vireo_client_deadline_request_stage_t *out_stage);

/**
 * @brief 取消活跃请求 timer，成功后清整个记录
 *
 * @param[in,out] wheel
 *     非空存活所属轮，停止后仍允许取消。
 * @param[in,out] request
 *     必需完整 caller 记录；客户已归还仍可取消，不核验客户或期限当前性。
 * @param[out] out_stage
 *     可空独立阶段，每路径覆盖；成功 NONE，依赖拒绝 CANCEL_TIMER。
 *
 * @retval VIREO_OK
 *     原 timer 注销，整个记录逻辑零；旧副本不会自动清零。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需 NULL、畸形或半空记录；依赖所属错误原分类返回。
 * @retval VIREO_RESULT_NOT_FOUND
 *     空记录或 timer 已失活／旧代，保持记录、不自动视为成功。
 *
 * @note
 *     不自动撤回外部表、完成请求、发送响应、关闭客户或取消其他 timer。
 *     失败记录及轮保持，无回滚或重试；同 Reactor，独立短借存储，全部路径保持 errno。
 */
vireo_result_t vireo_client_deadline_request_cancel(
    vireo_timer_wheel_t *wheel, vireo_client_deadline_request_t *request,
    vireo_client_deadline_request_stage_t *out_stage);

#endif
