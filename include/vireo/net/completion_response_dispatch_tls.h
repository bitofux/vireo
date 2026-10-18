/* TLS完成分发；复用原阶段枚举、resolve及身份消费。 */
#ifndef VIREO_NET_COMPLETION_RESPONSE_DISPATCH_TLS_H
#define VIREO_NET_COMPLETION_RESPONSE_DISPATCH_TLS_H
#include <vireo/net/completion_response_dispatch.h>
#include <vireo/net/completion_response_tls.h>

/** 按值真实前缀，不拥有或保活资源；末次响应与末次 pop 是不同时间点。 */
typedef struct vireo_completion_response_dispatch_tls_report {
    vireo_completion_response_dispatch_stage_t stage; /**< 主错阶段，成功/基本拒绝 NONE。 */
    size_t effective_max_items; /**< 消费前算出的安全领取尝试上限，条。 */
    size_t reserved_frame_bytes; /**< 安全条数乘单帧上限，字节，非实际入队量。 */
    bool dispatch_called; /**< 实际调用原安全点分发。 */
    size_t resolve_calls; /**< 实际描述回调次数，只计匹配交付。 */
    size_t response_calls; /**< 实际响应助手次数。 */
    size_t enqueued_responses; /**< 原助手报告确认入队的帧数，含后段失败。 */
    size_t enqueued_bytes; /**< 上述帧的整帧字节总量，含后段失败。 */
    vireo_result_t last_resolve_result; /**< resolve_calls 非零才表示运行结果。 */
    bool last_response_called; /**< 最后一次描述尝试是否随后调用响应助手。 */
    vireo_result_t last_response_result; /**< last_response_called 才表示运行结果。 */
    vireo_completion_response_tls_report_t last_response_report; /**< 最后描述尝试对应助手前缀。 */
    vireo_tcp_server_tls_error_t validation_error; /**< 消费前根TLS验证诊断。 */
    vireo_notifier_server_dispatch_report_t dispatch_report; /**< 原事件/消费/续通知报告。 */
} vireo_completion_response_dispatch_tls_report_t;

/**
 * @brief
 *     TLS安全点一次原就绪消费，按保守条数字节额度逐项描述、编码、入队和刷新。
 *
 * @param[in,out] server
 *     必需资源根，服务轮返回/原 observer 安全窗口，单 Reactor 使用。
 * @param[in] expected_handle
 *     未篡改完整辅助登记身份，caller 保证与 notifier/server/queue 对应。
 * @param[in,out] notifier
 *     必需原提示资源，短借，producer 可按原合同并发 notify。
 * @param[in,out] store
 *     必需原登记表，原消费链先结束登记再交付，不回滚。
 * @param[in,out] queue
 *     必需对应完成队列，单 consumer 串行消费，producer 可并发 push。
 * @param[in] max_items
 *     正条数上限，最多 65536，无默认，限制领取尝试及回调。
 * @param[in] max_frame_bytes
 *     单帧上限 32..16777248 字节，沿原响应助手。
 * @param[in] max_batch_bytes
 *     正批次额度，最多 64 MiB 且至少等于 max_frame_bytes，无默认。
 * @param[in,out] workspace
 *     必需独立可写 scratch，只借到返回，失败内容可改。
 * @param[in] workspace_size
 *     实际可写容量，至少 max_frame_bytes，逐项复用同一 scratch。
 * @param[in] resolve
 *     必需上述描述回调，原匹配交付时每项只调用一次。
 * @param[in,out] context
 *     可空独立短借回调上下文，不保存地址。
 * @param[out] remaining
 *     必需独占 owner 地址，入口 NULL；失败残留由 caller 显式恢复或清理。
 * @param[out] report
 *     必需独立可写报告，每可写路径发布真实前缀。
 *
 * @retval VIREO_OK
 *     无就绪无动作，或原批次成功；入队不保证 send/收到，预算停止不证明空队列。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需 NULL/空 resolve/非空 remaining/零条数或批次额度，或 expected 半空。
 * @retval VIREO_RESULT_RANGE
 *     条数/帧/批次范围不合法、批次小于单帧上限或 scratch 容量不足。
 * @retval VIREO_RESULT_NOT_FOUND
 *     expected 全零；其他旧身份等沿原依赖错误。
 * @retval VIREO_RESULT_CANCELLED
 *     入口公开观测到 server 已停止，不消费；后段停止也可透传并保部分进度。
 *
 * @retval VIREO_RESULT_BUSY
 *     RAW根或原TLS客户/阶段/有限资源拒绝。
 * @retval VIREO_RESULT_IO
 *     原TLS关注或notifier/loop失败；嵌套原因保持。
 *
 * @return
 *     其余公开依赖/描述回调原错透传；受检数值不可表示 OVERFLOW，无内部重试。
 *
 * @note
 *     基本/范围/expected 形态校验后，safe=min(max_items,max_batch_bytes/max_frame_bytes)，
 *     受检 reserved=safe*max_frame_bytes，再检查TLS根/inspect server，最后一次原 dispatch_ready。
 *     stop 快照不是跨线程屏障；原回调之前登记可能已经结束，后段失败保真实 owner。
 *     小帧或迟到清理也占一条机会，可能用不满字节预算，不动态追加或额外探空。
 *     原 EMPTY 不补提示；BUDGET/POP 未转移 BUSY 沿原链补一次，失败恢复由 caller 决定。
 *
 * @note
 *     实际入队按TLS助手 response.enqueued 统计，即使 refresh 失败；不得整段重放或再次 enqueue。
 *     未入队的残留也不能重走已结束的登记消费，caller 可用原 match 直接恢复助手。
 *     last_response_* 对应最后描述尝试，未调用时逻辑零；原 dispatch_report 末次 pop
 *     即使为空，也不会抹掉本层末次响应报告。主错阶段与原嵌套诊断均保留。
 *
 * @note
 *     TLS写FIFO不足沿ENQUEUE/RANGE，永久帧超容量沿CHECK_FRAME/RANGE；
 *     enqueued=true且刷新失败只补TLS flow_refresh/send，禁止重enqueue。
 *     last_response_report为完整TLS报告，原RAW分发/枚举/回调合同不变。
 *     全调用禁 POSIX 线程取消，地址/输出/context/资源/errno 有效对齐且独立不重叠。
 *     所有路径保持入口 errno，无本层申请/锁/持久 owner、服务循环/send/自动关闭/join。
 *     字节额度限制复制/CRC 工作量，不保证任意回调耗时、公平或硬实时。
 */
vireo_result_t vireo_completion_response_dispatch_tls_ready(vireo_tcp_server_t *server,
    vireo_event_loop_handle_t expected_handle, vireo_notifier_t *notifier,
    vireo_inflight_store_t *store, vireo_completion_queue_t *queue, size_t max_items,
    size_t max_frame_bytes, size_t max_batch_bytes, uint8_t *workspace, size_t workspace_size,
    vireo_completion_response_resolve_fn resolve, void *context,
    vireo_completion_t **remaining, vireo_completion_response_dispatch_tls_report_t *report);
#endif /* VIREO_NET_COMPLETION_RESPONSE_DISPATCH_TLS_H */
