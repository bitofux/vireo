/*
 * PROJECT : VIREO
 * FILE    : inflight_completion_drain.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-13
 * BRIEF   : Reactor 有界领取完成结果、复用单项消费与真实失败 owner 转出
 */
#ifndef VIREO_NET_INFLIGHT_COMPLETION_DRAIN_H
#define VIREO_NET_INFLIGHT_COMPLETION_DRAIN_H

#include <vireo/net/inflight_completion.h>
#include <vireo/thread/completion_queue.h>

/** 单次最大领取尝试条数，无默认；不表示队列容量或回调耗时上限。 */
#define VIREO_INFLIGHT_COMPLETION_DRAIN_MAX_ITEMS ((size_t)65536)

/** 批次主错误位置，与原队列及单项消费阶段独立。 */
typedef enum vireo_inflight_completion_drain_stage {
    VIREO_INFLIGHT_COMPLETION_DRAIN_NONE = 0, /**< 成功或基本参数拒绝。 */
    VIREO_INFLIGHT_COMPLETION_DRAIN_POP = 1, /**< 最后一次公开领取返回错误。 */
    VIREO_INFLIGHT_COMPLETION_DRAIN_CONSUME = 2 /**< 最后一次单项消费返回错误。 */
} vireo_inflight_completion_drain_stage_t;

/** 本调用的停止原因，不保活队列或承诺其此后状态。 */
typedef enum vireo_inflight_completion_drain_stop {
    VIREO_INFLIGHT_COMPLETION_DRAIN_NOT_STARTED = 0, /**< 基本拒绝，没有领取尝试。 */
    VIREO_INFLIGHT_COMPLETION_DRAIN_EMPTY = 1, /**< 一次领取观测 OPEN 空，不代表永久空。 */
    VIREO_INFLIGHT_COMPLETION_DRAIN_BUDGET = 2, /**< 用尽预算，没有额外探查队列。 */
    VIREO_INFLIGHT_COMPLETION_DRAIN_ERROR = 3 /**< 首依赖错误停止，前缀不回滚。 */
} vireo_inflight_completion_drain_stop_t;

/**
 * @brief
 *     独立的单批次真实进度，失败也发布；不拥有任何结果或响应地址。
 *
 * @note
 *     两嵌套报告只对应最后一次领取尝试，每次新尝试重新清零。
 *     只有 last_item_consume_called 为真，consume_report 才是实际消费报告。
 *     NULL 输出无法发布；未调用字段逻辑零不代表依赖已执行成功。
 */
typedef struct vireo_inflight_completion_drain_report {
    vireo_inflight_completion_drain_stage_t stage; /**< 主错误位置，成功/基本拒绝 NONE。 */
    vireo_inflight_completion_drain_stop_t stop_reason; /**< 本次正常结束或首错停止原因。 */
    size_t pop_calls; /**< 本次实际领取尝试数，0..max_items，单位条。 */
    size_t received; /**< 已发生 owner 转出数，含领取报错但 transferred=true 的项。 */
    size_t finished; /**< 单项消费返回 OK 的条数，含正常迟到清理。 */
    size_t delivered; /**< 实际回调返回 OK 的条数；后续消费错误也保留此进度。 */
    size_t late_cleaned; /**< 消费返回 OK 且 CLIENT_GONE/REQUEST_GONE 的条数。 */
    bool last_item_consume_called; /**< 最后一次领取尝试后是否真实调用单项消费。 */
    vireo_completion_queue_transfer_report_t queue_report; /**< 最后一次领取的原同步/转移报告。 */
    vireo_inflight_completion_consume_report_t consume_report; /**< 同次领取后的原消费报告。 */
} vireo_inflight_completion_drain_report_t;

/**
 * @brief
 *     单 Reactor 按显式条预算领取并消费结果，首错停止且交出仍存活的 owner。
 *
 * @param[in,out] store
 *     必需存活在途表，只借至返回；按单项合同结束登记，不请求取消。
 * @param[in] server
 *     必需存活客户资源根，Reactor-only，只借至返回，不自动归还客户。
 * @param[in,out] queue
 *     必需存活完成队列，只借至返回；caller 保证所有 pop 串行，producer 可并发。
 * @param[in] max_items
 *     正 size_t 条数预算，最多 65536，限制领取尝试及回调次数，无默认。
 * @param[in] deliver
 *     必需有界非阻塞同步回调，沿单项消费的短借/正常返回/禁止递归合同。
 * @param[in,out] context
 *     可空短借回调上下文，不保存；存活与同步由 caller 保证。
 * @param[out] remaining
 *     必需独占可写 owner 地址，入口值须 NULL；仍存活的已领取结果交 caller。
 *     全部旧操作/借用须结束，不与报告、资源、context、其他输出或 errno 重叠。
 * @param[out] report
 *     必需独立、对齐、可写输出，每可写路径发布，包含失败后的真实前缀。
 *
 * @retval VIREO_OK
 *     OPEN 空正常结束或用尽预算，remaining 为 NULL；不保证永久空或 worker 结束。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需 NULL/空回调、remaining 入口非空或预算为 0；不领取，保原 owner。
 * @retval VIREO_RESULT_RANGE
 *     预算超 65536；不领取，保原 owner，报告无运行进度。
 * @retval VIREO_RESULT_BUSY
 *     原公开领取竞争或消费依赖繁忙，立即停止，不内部重试。
 * @retval VIREO_RESULT_CANCELLED
 *     原队列已关闭且空或收尾终态，或原消费/回调取消；不推断已安全排空。
 *
 * @return
 *     其他队列/消费/回调错误原样返回，remaining 及 report 决定实际资源责任。
 *
 * @note
 *     每次只调用一次公开 try_pop；仅未转移的 OPEN 空 NOT_FOUND 转为 OK/EMPTY。
 *     领取非 OK 立即停止，即使已转移也不消费；已转出且存活的结果保 remaining。
 *     领取 OK 才调用一次单项消费；其非 OK 停止，先前结束登记/交付不回滚。
 *     回调非 OK 保 owner，而原登记可能已结束；不重入交付、重新入队或自动销毁。
 *     成功处理满预算后不额外探空；BUDGET 不能当作队列仍非空或已经空的证据。
 *
 * @note
 *     同 store/server 和所有 queue pop 均 Reactor-only；对象发布及寿命由 caller 同步。
 *     回调不得递归消费/排空、pop 或销毁借用 queue，不改变原 owner 存储，
 *     不销毁借用 store/server；可按公开合同操作其他记录/客户，结束借用后正常返回。
 *     不采样、读 notifier、自动网络回写/关闭、申请、join、回滚或内部重试。
 *     条数预算不限制回调耗时，不能终止任意阻塞回调或保证硬实时/公平。
 *
 * @note
 *     0 <= finished <= received <= pop_calls <= max_items；计数仅本次、不跨调用累计。
 *     delivered 计真实回调 OK，不等工作 result 为 OK；late_cleaned 是 finished 的子集。
 *     所有路径保持入口 errno，报告和 owner 的实际变化不承诺整体回滚。
 */
vireo_result_t vireo_inflight_store_drain_completions(vireo_inflight_store_t *store,
    vireo_tcp_server_t const *server, vireo_completion_queue_t *queue, size_t max_items,
    vireo_inflight_completion_deliver_fn deliver, void *context,
    vireo_completion_t **remaining, vireo_inflight_completion_drain_report_t *report);

#endif /* VIREO_NET_INFLIGHT_COMPLETION_DRAIN_H */
