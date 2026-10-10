/*
 * PROJECT : VIREO
 * FILE    : client_deadline_idle.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-10
 * BRIEF   : 此模块负责：
 * -- 根据实际传输字节刷新显式空闲期限
 * -- 只依赖已采用公开合同，保持资源、输出与 errno 的既有边界
 */
#ifndef VIREO_NET_CLIENT_DEADLINE_IDLE_H
#define VIREO_NET_CLIENT_DEADLINE_IDLE_H

#include <vireo/net/client_deadline.h>

/** caller 普通数值记录，不拥有或保活资源，不作为 wire ABI。
 * 两字段逻辑全零为空；非空须完整 binding 与正 interval，半空无效。
 * 不手改字段或旁路重排此 timer；复制值不延长客户或 timer 存活。 */
typedef struct vireo_client_deadline_idle {
    vireo_client_deadline_binding_t binding; /**< 完整客户与 timer 身份，刷新保持键。 */
    vireo_duration_ns_t idle_timeout_ns; /**< 正 uint64 纳秒空闲长度，无默认或哨兵。 */
} vireo_client_deadline_idle_t;

/**
 * @brief 核验当前 OPEN 客户及轮时间后，以 now＋空闲长度登记并保存记录
 *
 * @param[in] server
 *     非空存活 server，只短借；当前客户必须 OPEN。
 * @param[in,out] wheel
 *     非空存活且已 prepare 的未停止轮，沿原固定容量及预算。
 * @param[in] client
 *     完整当前客户租约，空值 NOT_FOUND，畸形 INVALID_ARGUMENT。
 * @param[in] now_ns
 *     caller 提供的同域新鲜单调纳秒，至少为轮最近成功 advance 的样本。
 * @param[in] idle_timeout_ns
 *     正纳秒长度；不读取配置或选择默认，不是完整请求总期限。
 * @param[in,out] out_idle
 *     必需独立 caller 记录，入口逻辑全零；仅全部成功后提交。
 * @param[out] out_stage
 *     可空独立诊断，每路径覆盖；成功 NONE，状态／时间阶段为 10／11。
 *
 * @retval VIREO_OK
 *     timer 已登记并保存完整关联，没有登记后可失败步骤。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址 NULL、零长度、畸形客户或输出非空。
 * @retval VIREO_RESULT_BUSY
 *     当前客户不是 OPEN，或公开登记容量已满。
 * @retval VIREO_RESULT_RANGE
 *     now 早于轮样本，或依赖所属槽越界。
 * @retval VIREO_RESULT_OVERFLOW
 *     加法、量化边界或身份发序不可表示，不回绕或截限。
 * @retval VIREO_RESULT_NOT_FOUND
 *     空／旧客户或未 prepare；其他依赖错误同样原样返回。
 * @retval VIREO_RESULT_CANCELLED
 *     轮已停止，停止检查先于时间运算。
 *
 * @note
 *     顺序为基本参数→当前客户→OPEN→prepared／停止→时间→公开登记。
 *     失败整个记录及资源保持，无申请、采样、服务、回调、推进、关闭或重试。
 * @note
 *     同 Reactor；所有地址独立、存活、对齐、不重叠、不在自有资源内、非 errno。
 *     地址只短借到返回。所有路径保持入口 errno，成功不承诺 padding。
 */
vireo_result_t vireo_client_deadline_idle_start(vireo_tcp_server_t const *server,
                                                vireo_timer_wheel_t *wheel,
                                                vireo_connection_pool_lease_t client,
                                                vireo_monotonic_ns_t now_ns,
                                                vireo_duration_ns_t idle_timeout_ns,
                                                vireo_client_deadline_idle_t *out_idle,
                                                vireo_client_deadline_stage_t *out_stage);

/**
 * @brief 实际传输字节进展时，受检计算新期限并保持完整 timer 身份重排
 *
 * @param[in] server
 *     非空存活 server；记录客户须仍当前且 OPEN。
 * @param[in,out] wheel
 *     非空存活所属轮，已 prepare 且未停止；不遍历记录表。
 * @param[in] idle
 *     必需完整记录；整个记录在所有路径保持，不手改或旁路 rearm 此 timer。
 * @param[in] now_ns
 *     同域新鲜活动观测纳秒，不早于轮样本及原 deadline－interval。
 *     原期限小于 interval 为 INVALID_ARGUMENT；now≥原期限为 TIMEOUT。
 * @param[in] received_bytes
 *     同客户实际公开接收进度，caller 保证来源未篡改；零碎字节也算活动。
 * @param[in] sent_bytes
 *     同客户实际公开发送进度；入队或就绪位不是发送，两计数不相加。
 * @param[out] out_stage
 *     可空独立诊断，每路径覆盖；成功 NONE，依赖失败原阶段。
 *
 * @retval VIREO_OK
 *     全核验后 0／0 不动；任一正进展以 now＋interval 重排，身份不变。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址 NULL、半空／畸形记录或原期限小于 interval。
 * @retval VIREO_RESULT_NOT_FOUND
 *     空记录、旧客户、旧／已领取 timer 或未 prepare；不自动当成功。
 * @retval VIREO_RESULT_BUSY
 *     当前客户不为 OPEN，即使存在此前传输进展也不续期。
 * @retval VIREO_RESULT_CANCELLED
 *     轮已停止，先于时间判断，0／0 也拒绝。
 * @retval VIREO_RESULT_RANGE
 *     样本早于轮进度或原活动时间，或依赖槽越界。
 * @retval VIREO_RESULT_TIMEOUT
 *     到达原精确纳秒期限，即使量化通知尚未发现也不续活。
 * @retval VIREO_RESULT_OVERFLOW
 *     新期限或量化边界不可表示；其他依赖错误原样返回。
 *
 * @note
 *     先基本形态、当前客户及 OPEN，再 timer 当前性、轮停止、时间，最后活动判断。
 *     0／0、失败及原身份在全部路径保持；正活动成功只改变轮内期限／链位。
 * @note
 *     使用实际返回的字节前缀，不以 IO 结果 OK、EAGAIN、排队或就绪推测活动。
 *     显式 now 是观测时间；观测已晚于期限则保守拒绝，不猜测更早内核到达时间。
 *     零碎或单向字节能续期，不能替代慢请求总期限、完整请求闲置或业务策略。
 * @note
 *     无申请／时钟／网络／业务动作；失败资源保持，无回滚或重试。
 *     同 Reactor，短借独立有效对齐非重叠地址、非自有资源且非 errno；所有路径保持 errno。
 */
vireo_result_t vireo_client_deadline_idle_refresh(vireo_tcp_server_t const *server,
                                                  vireo_timer_wheel_t *wheel,
                                                  vireo_client_deadline_idle_t const *idle,
                                                  vireo_monotonic_ns_t now_ns,
                                                  size_t received_bytes, size_t sent_bytes,
                                                  vireo_client_deadline_stage_t *out_stage);

/**
 * @brief 取消仍活跃的 timer，成功后清空整个传输空闲记录
 *
 * @param[in,out] wheel
 *     非空存活所属轮，停止后仍允许取消。
 * @param[in,out] idle
 *     必需完整 caller 记录；不查询客户当前性，客户已归还亦可取消。
 * @param[out] out_stage
 *     可空独立诊断，每路径覆盖，成功 NONE，依赖失败 CANCEL_TIMER。
 *
 * @retval VIREO_OK
 *     原 timer 注销且整个记录逻辑全零，副本不自动清零。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址 NULL、半空或畸形记录；所属依赖错误原样返回。
 * @retval VIREO_RESULT_NOT_FOUND
 *     空记录或 timer 已注销／旧代；失败保持整个记录，不当成功。
 *
 * @note
 *     不关闭或归还客户、不撤回外部记录表；所有失败保持记录及轮，所有路径保持 errno。
 *     同 Reactor；地址短借、独立存活对齐、非重叠、非自有资源且非 errno。
 *     若其他入口只清空 idle.binding，caller 须据消费事实清整个记录后才能再次使用。
 */
vireo_result_t vireo_client_deadline_idle_cancel(vireo_timer_wheel_t *wheel,
                                                 vireo_client_deadline_idle_t *idle,
                                                 vireo_client_deadline_stage_t *out_stage);

#endif
