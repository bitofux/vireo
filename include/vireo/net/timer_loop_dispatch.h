/*
 * PROJECT : VIREO
 * FILE    : timer_loop_dispatch.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-09
 * BRIEF   : 此模块负责：
 * -- 在显式条数预算内领取并同步交付到期值通知
 * -- 报告不可回滚的领取进度及唯一交付失败值
 */
#ifndef VIREO_NET_TIMER_LOOP_DISPATCH_H
#define VIREO_NET_TIMER_LOOP_DISPATCH_H

#include <vireo/timer/wheel_advance.h>

/** 单次成功领取和交付调用数的硬限，不是默认值或耗时保证。 */
#define VIREO_TIMER_LOOP_DISPATCH_MAX_EVENTS ((size_t)65536)

/** 本次停止的阶段，不是 wire 状态或重试指令。 */
typedef enum vireo_timer_loop_dispatch_stage {
    VIREO_TIMER_LOOP_DISPATCH_STAGE_NONE = 0, /**< 正常结束；空轮或预算耗尽也成功。 */
    VIREO_TIMER_LOOP_DISPATCH_STAGE_OBSERVE = 1, /**< 公开进度观测失败，未领取当前项。 */
    VIREO_TIMER_LOOP_DISPATCH_STAGE_TAKE = 2, /**< 公开领取失败，未交付当前项。 */
    VIREO_TIMER_LOOP_DISPATCH_STAGE_DELIVER = 3 /**< 回调失败，当前项已注销且保存历史值。 */
} vireo_timer_loop_dispatch_stage_t;

/** 完整数值报告；进入处理后失败也发布实际进度，不保活任何对象。 */
typedef struct vireo_timer_loop_dispatch_report {
    vireo_timer_loop_dispatch_stage_t stage; /**< 成功为 NONE，失败定位观测、领取或交付。 */
    size_t consumed_count; /**< 本次成功领取并注销的条数，最多 max_events。 */
    size_t delivered_count; /**< 本次交付函数返回 OK 的条数，不保证业务事务完成。 */
    bool has_failed_delivery; /**< 仅交付失败为 true，失败值此时有效。 */
    vireo_timer_wheel_expired_t failed_delivery; /**< 唯一失败交付的历史值；无失败时逻辑字段为零。 */
} vireo_timer_loop_dispatch_report_t;

/**
 * @brief 同步处理一个已经注销的到期历史值
 *
 * @param[in] expired
 *     非空、只读栈值，仅借到此次回调返回；可复制值，不得保存此地址。
 *     handle 已失效，不再授权查询、取消或重排原登记。
 * @param[in,out] context
 *     caller 自持的短借上下文，可为 NULL；适配层不保存或释放。
 *
 * @retval VIREO_OK
 *     此次交付返回成功；本层不判断业务事务是否完成。
 * @retval 其他非OK结果
 *     原样返回并停止消费，保存该历史值，不撤销领取或已有业务动作。
 *
 * @note
 *     必须有界、非阻塞并正常返回；不得执行 DB、文件或耗时 GC，不得 longjmp。
 * @note
 *     可合法登记、查询、取消、重排、观测或 begin 停止借用轮。
 *     不得递归消费或运行组合入口、推进、take、shutdown_step、销毁借用轮，
 *     也不得通过其他轮的嵌套消费扩大本次工作预算。
 * @note
 *     不得改写入口报告；副作用由 caller 负责，非 OK 不保证业务未执行。
 */
typedef vireo_result_t (*vireo_timer_loop_deliver_fn)(
    vireo_timer_wheel_expired_t const *expired, void *context);

/**
 * @brief 在条数预算内领取并同步交付，不采样、推进或运行网络循环
 *
 * @param[in,out] wheel
 *     非空、存活、已 prepare 的轮，只短借至返回；停止轮仍可消费已有 ready。
 * @param[in] max_events
 *     显式正条数预算，不超过硬限；限制成功领取数及回调次数，无默认。
 * @param[in] deliver
 *     非空、全程有效的同步交付函数，须遵守本头回调合同。
 * @param[in,out] context
 *     可空、全程有效的 caller 自持上下文，短借，不转移所有权。
 * @param[out] out_report
 *     必需非空、独立对齐可写的报告，短借至返回；入口值任意。
 *     不与轮资源、context 或其他参数存储重叠，不指 errno，不被回调修改。
 *
 * @retval VIREO_OK
 *     已无 ready 或成功领取达到预算；stage NONE，两计数相等，无失败事件。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址或函数 NULL，或预算为零；基本拒绝保持整个报告，不执行处理；另沿回调错误，此时 stage 为 DELIVER。
 * @retval VIREO_RESULT_RANGE
 *     预算超过硬限；基本拒绝保持整个报告。另沿公开领取或回调原错误。
 * @retval VIREO_RESULT_NOT_FOUND
 *     未 prepare 时观测失败；另沿依赖或回调原错误，用报告 stage 区分。
 * @retval 其他非OK结果
 *     观测、领取或回调错误原样返回，立即停止，不自动重试。
 *
 * @note
 *     基本校验通过后，成功和失败均完整发布报告逻辑字段，不承诺 padding。
 *     观测或领取失败时 consumed==delivered；交付失败时 consumed==delivered+1，
 *     has_failed_delivery=true 并保留唯一失败值，其余路径嵌套逻辑字段为零。
 * @note
 *     先公开观测 ready，空则 OK；非空后的 take 任何错误均返回，
 *     不将依赖或回调的 NOT_FOUND 吞成空轮。预算耗尽不额外观测剩余数量。
 * @note
 *     领取成功使原句柄全部副本失效，不能回滚注销或回调动作；caller 自行恢复。
 *     失败值不是有效控制权，重新交付仍须业务幂等性，适配层不保证安全重试。
 * @note
 *     回调可改变其他登记；新 ready 可使用剩余预算，取消/重排可提前结束。
 *     begin 停止不打断已有 ready 的交付；不处理未发现项，不承诺 FIFO、公平或入口集合。
 * @note
 *     同轮全部访问 Reactor-only，无并发或重入；全部借用存活至返回。
 *     工作量 O(max_events) 加实际回调工作，不提供抢占或硬实时保证。
 * @note
 *     全路径恢复入口 errno，包括回调修改 errno；不保存指针或创建 owned 资源。
 *     不分配、自动关闭连接、清理业务或执行停机 step。
 */
vireo_result_t vireo_timer_loop_dispatch(vireo_timer_wheel_t *wheel,
                                        size_t max_events,
                                        vireo_timer_loop_deliver_fn deliver,
                                        void *context,
                                        vireo_timer_loop_dispatch_report_t *out_report);

#endif /* VIREO_NET_TIMER_LOOP_DISPATCH_H */
