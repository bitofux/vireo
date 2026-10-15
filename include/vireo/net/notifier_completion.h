/*
 * PROJECT : VIREO
 * FILE    : notifier_completion.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-13
 * BRIEF   : 一次提示消费、有界完成排空与条件续通知
 */
#ifndef VIREO_NET_NOTIFIER_COMPLETION_H
#define VIREO_NET_NOTIFIER_COMPLETION_H
#include <vireo/net/inflight_completion_drain.h>
#include <vireo/thread/notifier.h>

/** 本协调层主错误位置，不改变原注册/排空/notifier 阶段。 */
typedef enum vireo_notifier_completion_stage {
    VIREO_NOTIFIER_COMPLETION_NONE = 0, /**< 成功或基本参数拒绝。 */
    VIREO_NOTIFIER_COMPLETION_CONSUME_HINT = 1, /**< 一次原提示消费失败。 */
    VIREO_NOTIFIER_COMPLETION_DRAIN = 2, /**< 原排空主错误，优先于补提示错误。 */
    VIREO_NOTIFIER_COMPLETION_RENOTIFY = 3 /**< 排空 OK 后补提示失败。 */
} vireo_notifier_completion_stage_t;

/**
 * @brief
 *     独立单次进度报告，失败也发布，不拥有或保活结果/资源。
 *
 * @note
 *     未调用字段逻辑零不表示执行成功，须结合对应 called 标志读取。
 *     notification_count 仅 consume_called 且消费成功时有效，不等队列条数。
 *     renotify_needed 是续调度策略要求，不证明当前队列仍非空。
 */
typedef struct vireo_notifier_completion_report {
    vireo_notifier_completion_stage_t stage; /**< 本次主错误位置，成功/基本拒绝 NONE。 */
    bool consume_called; /**< 是否实际调用过一次原提示消费。 */
    uint64_t notification_count; /**< 成功消费的原累计值，0/MAX 沿原公开合同有效。 */
    vireo_notifier_error_t consume_error; /**< 一次原 consume 独立诊断，未调用逻辑零。 */
    bool drain_called; /**< 是否实际调用过一次有界排空。 */
    vireo_result_t drain_result; /**< 原排空返回，仅 drain_called 有效，不被补提示覆盖。 */
    vireo_inflight_completion_drain_report_t drain_report; /**< 原真实消费前缀与残留诊断。 */
    bool renotify_needed; /**< BUDGET 或 POP 未转移 BUSY 时为真。 */
    bool renotify_called; /**< 本次是否已实际尝试一次补提示。 */
    vireo_result_t renotify_result; /**< 原 notify 返回，仅 renotify_called 时有效。 */
    vireo_notifier_notify_outcome_t renotify_outcome; /**< 原成功 notify 结果，不承诺返回时可读。 */
    vireo_notifier_error_t renotify_error; /**< 原补提示诊断，主排空错误存在时也保留。 */
} vireo_notifier_completion_report_t;

/**
 * @brief
 *     一次 consume 提示后按预算排空，条件满足时一次补 notify，无内部重试。
 *
 * @param[in,out] notifier
 *     必需存活短借对象，同 consumer 串行 consume；producer 可并发 notify。
 * @param[in,out] store
 *     必需存活短借在途表，Reactor-only；登记结束沿原单项消费合同。
 * @param[in] server
 *     必需存活客户资源根，Reactor-only，只借至返回，不自动关闭或归还。
 * @param[in,out] queue
 *     必需存活完成队列，所有 pop 由单 Reactor 串行；producer 可并发提交。
 * @param[in] max_items
 *     正 size_t 条数预算，最多原 DRAIN_MAX_ITEMS=65536，无默认。
 * @param[in] deliver
 *     必需同步有界非阻塞回调，沿原消费/排空借用及正常返回规则。
 * @param[in,out] context
 *     可空短借回调上下文，不保存地址；寿命与同步由 caller 保证。
 * @param[out] remaining
 *     必需独占 owner 地址，入口值 NULL；原排空转出的仍存活结果交 caller。
 * @param[out] report
 *     必需独立、对齐、可写报告，每可写路径完整发布真实进度。
 *
 * @retval VIREO_OK
 *     原排空 OK，若需补提示也已 OK；不保证队列永久空/worker 已结束。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需 NULL/空回调、零预算或 remaining 非空，不消费提示/领取，保 owner。
 * @retval VIREO_RESULT_RANGE
 *     预算超过 65536，不消费提示/领取，保 owner。
 *
 * @return
 *     其他原依赖/回调错误按主错规则透传，不自动重试或把 CANCELLED 当安全排空。
 *
 * @note
 *     consume 非 OK 立即返回，不排空；原异常可能已消费计数，不回滚内核进度。
 *     consume OK 包含 count=0，仍排空，不按 count 领取；数据发布靠原 queue 同步。
 *     EMPTY 不补提示；正常 BUDGET 或 POP 阶段 BUSY 且未 transferred 时各补一次。
 *     不额外探空，BUDGET 可能实际已空，允许下一轮多一次空唤醒。
 *     notify ALREADY_PENDING 沿原 OK；其他排空错误不补提示，由 caller 明确恢复。
 *
 * @note
 *     排空非 OK 保其主返回/DRAIN 阶段，补提示失败单独保 renotify_result/error；
 *     排空 OK 时补提示非 OK 作为主错/RENOTIFY。真实登记结束/交付/销毁不回滚。
 *     补提示失败后 caller 必须明确再次调度、补提示或停机恢复，不能盲目等待新 READ。
 *     原回调是 void，caller 必须自行保存本报告/返回，不自动使 loop run 返回错误。
 *
 * @note
 *     remaining 沿原 drain 保真实存活 owner；不 repush/自动 destroy/重放回调。
 *     全调用由 caller 禁用 POSIX 线程取消；资源发布/寿命和独立存储同步由 caller 保证。
 *     同资源单 Reactor；回调不递归本入口/排空/消费，不 consume/destroy 借用 notifier，
 *     不 pop/destroy queue、不 destroy store/server、不动原结果 owner，正常结束短借后返回。
 *     条数预算不限制任意回调耗时，不承诺硬实时/公平或全部通知失败的无丢唤醒。
 *
 * @note
 *     输入/输出/context/自有资源/errno 须有效、对齐、存活、互不重叠；地址不保存。
 *     所有路径保持入口 errno；无本层申请/锁/新 owner/默认容量或预算/自动循环。
 *     不包装/注册 loop 回调，不修改 server 私有 loop，不采样/网络回写/取消/关闭/join。
 */
vireo_result_t vireo_notifier_completion_consume_and_drain(vireo_notifier_t *notifier,
    vireo_inflight_store_t *store, vireo_tcp_server_t const *server,
    vireo_completion_queue_t *queue, size_t max_items,
    vireo_inflight_completion_deliver_fn deliver, void *context,
    vireo_completion_t **remaining, vireo_notifier_completion_report_t *report);
#endif /* VIREO_NET_NOTIFIER_COMPLETION_H */
