/* PROJECT : VIREO
 * FILE : auth_service_deadline.h
 * AUTHOR : bitofux
 * DATE : 2026-10-23
 * BRIEF : 显式启用认证服务的连接期限，不改变原四/五/六命令构造合同。 */
#ifndef VIREO_NET_AUTH_SERVICE_DEADLINE_H
#define VIREO_NET_AUTH_SERVICE_DEADLINE_H
#include <vireo/net/auth_service.h>
#include <vireo/timer/wheel_advance.h>

/** 正时长及固定工作/内存预算；无默认、禁用哨兵或后台线程。 */
typedef struct vireo_auth_service_deadline_options {
    uint64_t unauthenticated_timeout_ns; /**< TLS建立到成功绑定LOGIN/RESUME；任何输入不续期。 */
    uint64_t frame_timeout_ns; /**< 首个TLS明文字节到整帧收齐的总时长；后续字节不续期。 */
    uint64_t authenticated_idle_timeout_ns; /**< 成功绑定后开始；仅成功移交worker的完整请求续期。 */
    vireo_timer_wheel_advance_budget_t advance; /**< 每个推进点的正tick/node预算，均≤65536。 */
    size_t max_expired; /**< 每个推进点最多领取1..65536通知；每once至多两个推进点。 */
    size_t max_memory_bytes; /**< 反查表独立申请预算，正且≤64MiB，不含原service和wheel。 */
} vireo_auth_service_deadline_options_t;

/**
 * @brief 在接客前为现有认证服务启用三类连接期限，长期独占借用时间轮
 * @param[in,out] service
 *     必需存活服务，无客户/selected且未quiesce；可用于原四/五/六命令factory。
 * @param[in,out] wheel
 *     必需已prepare、未停止且空的专用轮，容量至少server.connection_capacity。
 *     caller创建/销毁，寿命覆盖service；借用期间禁止外部登记、推进、领取或停止此轮。
 * @param[in] options
 *     必需显式正时长/预算，复制值，不保存地址。
 * @retval VIREO_OK
 *     固定反查表已分配，后续运行无新定时器内存申请；每建立连接最多一个timer。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需NULL或零配置。
 * @retval VIREO_RESULT_BUSY
 *     已启用、有客户/selected、已quiesce或轮已有登记。
 * @retval VIREO_RESULT_NOT_FOUND
 *     轮未prepare。
 * @retval VIREO_RESULT_RANGE
 *     工作/内存预算超限、不足或轮容量不足。
 * @retval VIREO_RESULT_OVERFLOW
 *     受检申请量不可表示。
 * @retval VIREO_RESULT_NO_MEMORY
 *     反查表申请失败。
 * @return 采时、轮观察/等待规划的其他原错误透传。
 * @note 失败service/wheel保持，所有路径保持errno；Reactor-only、禁POSIX取消。
 *     未调用本入口的旧服务保持原行为；生产装配显式启用。握手期限仍由TLS层管理，
 *     业务任务期限独立；到期只标closing，再走原取消/forget/release，不强停worker SQL。
 * @note once在无网络事件时仍推进，等待上限受下一tick约束；追赶未完成时不处理新业务。
 *     wheel向上量化，空闲回收最多增加一tick及有限调度/清理延迟；到期活动不能续命。
 *     成功LOGOUT/本地撤销/Session过期被有限扫描或请求检查发现后转入新的未认证期。
 *     收帧计时从Reactor首次取得TLS明文开始，完整前缀后的半帧同时计时；完整帧等待
 *     业务/写背压不算半帧。quiesce仍执行期限，server_stop继续原有界清理。
 *     任何发送、拒绝响应、畸形请求和零碎字节都不刷新空闲；本项不含独立慢写期限。
 */
vireo_result_t vireo_auth_service_enable_deadlines(vireo_auth_service_t *service,
    vireo_timer_wheel_t *wheel, vireo_auth_service_deadline_options_t const *options);
#endif
