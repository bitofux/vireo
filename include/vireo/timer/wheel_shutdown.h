/*
 * PROJECT : VIREO
 * FILE    : wheel_shutdown.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-09
 * BRIEF   : 此模块负责：
 * -- 永久停止调度操作并观测收尾状态
 * -- 在显式槽预算内逐项注销剩余登记
 */
#ifndef VIREO_TIMER_WHEEL_SHUTDOWN_H
#define VIREO_TIMER_WHEEL_SHUTDOWN_H

#include <vireo/timer/wheel_registry.h>

/** 单次槽检查预算硬限，无默认值，不是时间刻度或性能承诺。 */
#define VIREO_TIMER_WHEEL_SHUTDOWN_MAX_SLOTS ((size_t)65536)

/** 独立生命周期快照，不持有资源或内部借用。 */
typedef struct vireo_timer_wheel_shutdown_info {
    bool stopping; /**< 是否已经永久停止新登记、重排与推进。 */
    size_t active_count; /**< 尚未归还的身份数，包含普通桶、pending 与 ready。 */
    bool finished; /**< stopping 且 active_count 为 0，不代表业务清理完成。 */
} vireo_timer_wheel_shutdown_info_t;

/** 单项停机取消值，不意味着到期、不转移业务资源。 */
typedef struct vireo_timer_wheel_shutdown_cancelled {
    vireo_timer_handle_t handle; /**< 归还前原身份；输出时全部副本已失效，仅历史记录。 */
    vireo_timer_wheel_timer_info_t timer; /**< 归还前原期限、累计到期刻度和数学桶位置。 */
} vireo_timer_wheel_shutdown_cancelled_t;

/** 一次收尾的工作量与数值结果，无内部指针。 */
typedef struct vireo_timer_wheel_shutdown_report {
    size_t scanned_slots; /**< 本次实际检查的物理登记槽数，包括空槽，不超过预算。 */
    bool has_cancelled; /**< 是否成功注销一项并发布 cancelled；每调用最多一项。 */
    vireo_timer_wheel_shutdown_cancelled_t cancelled; /**< 有事件时历史值，否则逻辑字段全零。 */
    size_t remaining_count; /**< 返回时 public owner 尚未归还身份数。 */
    bool finished; /**< 已停止且 remaining_count 为 0，不表示业务资源已处理。 */
} vireo_timer_wheel_shutdown_report_t;

/**
 * @brief 永久停止已准备轮的新登记、重排和推进
 *
 * @param[in,out] wheel
 *     非空、存活、已 prepare 的轮，所属 Reactor 独占。
 *
 * @retval VIREO_OK
 *     已进入停止状态；重复调用也成功，不重置任何处理进度或登记。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     wheel 为 NULL。
 * @retval VIREO_RESULT_NOT_FOUND
 *     此轮未 prepare。
 *
 * @note
 *     不注销节点、不改时间前沿、不采样；没有 resume，重新运行需新轮。
 * @note
 *     停止后的 register/rearm/advance 拒绝为 CANCELLED，原参数及 rearm 身份检查优先。
 * @note
 *     get/cancel/take_expired/各 inspect 继续可用；已准备再次 prepare 仍 BUSY。
 * @note
 *     本调用不释放业务资源或执行回调；全部归还后仍由 caller 调用 destroy。
 * @note
 *     失败轮状态保持，全路径保持 errno；只短借 wheel，不分配，全部访问 Reactor-only。
 */
vireo_result_t vireo_timer_wheel_shutdown_begin(vireo_timer_wheel_t *wheel);

/**
 * @brief 观测已准备轮的停止与登记收尾状态
 *
 * @param[in] wheel
 *     非空、存活、已 prepare 的轮，所属 Reactor 独占。
 * @param[out] out_info
 *     非空、对齐可写且独立的数值输出，短借至返回，不保活轮。
 *
 * @retval VIREO_OK
 *     写三个逻辑字段，尚未 begin 也可观测，finished 为 false。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址 NULL；另沿 public owner inspect 参数错误。
 * @retval VIREO_RESULT_NOT_FOUND
 *     此轮未 prepare。
 *
 * @note
 *     失败保持整个输出，所有路径保持 errno；不采样、不推进、不分配。
 * @note
 *     输出不在轮资源内、不重叠、不指 errno；同轮所有访问 Reactor-only。
 */
vireo_result_t vireo_timer_wheel_shutdown_inspect(vireo_timer_wheel_t const *wheel,
                                                 vireo_timer_wheel_shutdown_info_t *out_info);

/**
 * @brief 在显式槽预算内至多注销一项剩余登记
 *
 * @param[in,out] wheel
 *     非空、存活、已 prepare 且已 begin 停止的轮，所属 Reactor 独占。
 * @param[in] max_slots
 *     正物理槽检查预算，不超过 MAX_SLOTS；空槽与活跃槽均计数，无默认。
 * @param[out] out_report
 *     非空、对齐可写且独立的值输出，短借至返回；入口内容任意。
 *
 * @retval VIREO_OK
 *     发布工作量和收尾状态；预算不足或无事件也成功，可能尚未清空。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址 NULL 或预算为 0；另沿 public owner 校验/归还的身份错误。
 * @retval VIREO_RESULT_RANGE
 *     预算超过硬限；另沿 public owner 的越界身份错误。
 * @retval VIREO_RESULT_NOT_FOUND
 *     未 prepare；另沿 public owner 的失活身份错误。
 * @retval VIREO_RESULT_BUSY
 *     尚未 begin 停止。
 *
 * @note
 *     单向扫描固定登记表，工作 O(max_slots)，不承诺顺序或硬实时，不读其他模块私有布局。
 * @note
 *     归还成功才发布扫描位置/报告；失败恢复精确链位、计数、身份、扫描位置与整个输出。
 * @note
 *     空表重复调用 OK，0 扫描、无事件、finished=true；无事件时 cancelled 逻辑字段全零。
 * @note
 *     成功通知是停机取消，可能尚未到期；原 handle 已失效、不清 caller 的旧副本数值。
 * @note
 *     caller 负责业务清理；没有 I/O/回调/自动重试/分配，依赖错误原样返回，全路径保持 errno。
 * @note
 *     输出不在轮资源内、不与其重叠、不指 errno；全部访问 Reactor-only，无并发或重入。
 */
vireo_result_t vireo_timer_wheel_shutdown_step(vireo_timer_wheel_t *wheel, size_t max_slots,
                                              vireo_timer_wheel_shutdown_report_t *out_report);

#endif /* VIREO_TIMER_WHEEL_SHUTDOWN_H */
