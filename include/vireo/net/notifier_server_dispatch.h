/*
 * PROJECT : VIREO
 * FILE    : notifier_server_dispatch.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-14
 * BRIEF   : 服务安全点取就绪并复用有界完成消费，保真实进度
 */
#ifndef VIREO_NET_NOTIFIER_SERVER_DISPATCH_H
#define VIREO_NET_NOTIFIER_SERVER_DISPATCH_H
#include <vireo/net/notifier_completion.h>

/** 本入口独立阶段，不重排 server 或原消费链的阶段。 */
typedef enum vireo_notifier_server_dispatch_stage {
    VIREO_NOTIFIER_SERVER_DISPATCH_NONE = 0,
    VIREO_NOTIFIER_SERVER_DISPATCH_TAKE_READY = 1,
    VIREO_NOTIFIER_SERVER_DISPATCH_CHECK_READY = 2,
    VIREO_NOTIFIER_SERVER_DISPATCH_DISPATCH = 3
} vireo_notifier_server_dispatch_stage_t;

/** 按值记录本次真实前缀，不拥有或保活借用资源。 */
typedef struct vireo_notifier_server_dispatch_report {
    vireo_notifier_server_dispatch_stage_t stage; /**< 主错位置，成功/基本拒绝 NONE。 */
    bool ready_called; /**< 是否实际调用公开取就绪。 */
    bool ready_taken; /**< 取就绪返回 OK，server 的累计位已清除。 */
    vireo_tcp_server_auxiliary_event_t ready_event; /**< 原完整身份和就绪位。 */
    vireo_tcp_server_auxiliary_error_t ready_error; /**< 原取就绪诊断。 */
    bool dispatch_called; /**< 是否实际调用原消费链。 */
    vireo_result_t dispatch_result; /**< 原消费链返回；未调用逻辑零不是运行证据。 */
    vireo_notifier_completion_report_t dispatch_report; /**< 原消费/排空/补通知前缀。 */
} vireo_notifier_server_dispatch_report_t;

/**
 * @brief
 *     安全点一次取辅助就绪、匹配完整身份，再一次有界消费完成结果。
 *
 * @param[in,out] server
 *     必需存活 server，调用者在服务轮返回或原逐轮 observer 安全窗口调用。
 * @param[in] expected_handle
 *     未篡改的原完整注册身份；caller 保证来自此 notifier 在此 server 的登记。
 * @param[in,out] notifier
 *     必需存活且与登记关联的 notifier，只借至返回，不保存指针。
 * @param[in,out] store
 *     必需存活在途表，登记结束及取消引用释放沿原消费链。
 * @param[in,out] queue
 *     必需对应的完成队列，单 Reactor 串行消费，producer 可并发提交。
 * @param[in] max_items
 *     正 size_t 条数预算，最多 65536，沿原排空合同，无默认。
 * @param[in] deliver
 *     必需同步有界非阻塞回调，正常返回并结束所有短借。
 * @param[in,out] context
 *     可空回调上下文，只借至返回，不保存地址。
 * @param[out] remaining
 *     必需独占 owner 地址，入口 NULL；原排空转出的存活结果由 caller 负责。
 * @param[out] report
 *     必需独立可写报告，每可写路径完整发布真实前缀。
 *
 * @retval VIREO_OK
 *     无就绪时无动作，或原消费链成功；不证明队列永久空/worker 已回收。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需 NULL/空回调/非空 remaining/零预算，或 expected 两字段仅一项为零。
 * @retval VIREO_RESULT_RANGE
 *     条数预算超过 65536，不调用依赖。
 * @retval VIREO_RESULT_NOT_FOUND
 *     expected 全零，或取到的完整身份不匹配；后者已清累计位，不消费提示。
 * @retval VIREO_RESULT_IO
 *     取到 ERROR/HANGUP（包括同时 READ），不消费提示，原位保存在报告。
 * @retval VIREO_RESULT_INTERNAL
 *     取到零位或未知事件位，不消费提示；亦可能是公开依赖原错误。
 *
 * @return
 *     其余依赖及回调原错透传，不回滚、重放、自动销毁残留或内部重试。
 *
 * @note
 *     顺序为基本校验/预算/expected 形态，再一次 take；原 NOT_FOUND 归一 OK 无动作。
 *     take OK 已清 server 的 C 累计位，之后身份/事件或消费失败不恢复该位。
 *     先比完整身份，再检查零/未知位，再检查 ERROR/HANGUP；正常 READ 才消费。
 *     比较身份不认证 notifier/queue 指针配对，关联与借用寿命由 caller 保证。
 *     原取就绪在途 BUSY 透传，不绕过 server 的有限阶段保护。
 *
 * @note
 *     原 count=0 仍排空，不按 count 领取；EMPTY 不补通知，BUDGET 或 POP 阶段
 *     未转移 BUSY 沿原链补一次；不添加额外补通知或探空，可能多一次空唤醒。
 *     原主次错误和 remaining 完整保留；消费失败后 caller 显式恢复/再次调度，
 *     不能因 C 位已清而盲目等待新 READ，不自动重放已交付项。
 *     停止后允许处理旧标记，不恢复分发；关闭队列空 CANCELLED 不当作最后 drain。
 *
 * @note
 *     同资源 Reactor-only，全调用禁 POSIX 线程取消。回调沿原消费链限制，另不得
 *     递归本入口、注销/重绑源或销毁借用资源；条数预算不保证任意回调耗时。
 *     输入/输出/context/资源/errno 有效、对齐、独立不重叠；所有路径保持入口 errno。
 *     无本层申请/锁/新 owner，不自动运行服务、网络回写、期限/取消、关闭或 join。
 */
vireo_result_t vireo_notifier_server_dispatch_ready(vireo_tcp_server_t *server,
    vireo_event_loop_handle_t expected_handle, vireo_notifier_t *notifier,
    vireo_inflight_store_t *store, vireo_completion_queue_t *queue, size_t max_items,
    vireo_inflight_completion_deliver_fn deliver, void *context,
    vireo_completion_t **remaining, vireo_notifier_server_dispatch_report_t *report);
#endif /* VIREO_NET_NOTIFIER_SERVER_DISPATCH_H */
