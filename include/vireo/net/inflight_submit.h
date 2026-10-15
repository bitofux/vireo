/*
 * PROJECT : VIREO
 * FILE    : inflight_submit.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-13
 * BRIEF   : Reactor 限额登记与非阻塞任务交接的真实进度
 */
#ifndef VIREO_NET_INFLIGHT_SUBMIT_H
#define VIREO_NET_INFLIGHT_SUBMIT_H

#include <vireo/net/inflight_store.h>
#include <vireo/thread/thread_pool.h>

/** 本次编排错误所在阶段，与既有 inflight/pool 阶段分别解释。 */
typedef enum vireo_inflight_submit_stage {
    VIREO_INFLIGHT_SUBMIT_NONE = 0,
    VIREO_INFLIGHT_SUBMIT_INSPECT_TASK = 1,
    VIREO_INFLIGHT_SUBMIT_REGISTER_REQUEST = 2,
    VIREO_INFLIGHT_SUBMIT_SUBMIT_TASK = 3
} vireo_inflight_submit_stage_t;

/** 独立按值报告，不拥有资源；每可写路径发布，失败也可能有真实进度。 */
typedef struct vireo_inflight_submit_report {
    vireo_inflight_submit_stage_t stage; /**< 主错误阶段；成功及基本拒绝为 NONE。 */
    vireo_task_metadata_t metadata; /**< 转移前快照，仅 task_inspected 为真时有效。 */
    bool task_inspected; /**< 已成功取得 task 元数据，不表示任务仍归 caller。 */
    bool registration_committed; /**< 本调用曾成功插入记录，撤销后仍为真。 */
    bool record_retained; /**< 本调用登记最终仍在表中；不是全部表的观测。 */
    bool submit_called; /**< 实际调用过一次 pool 提交，资格失败也为真。 */
    vireo_thread_pool_submit_report_t pool_report; /**< 原依赖报告；transferred 决定归属。 */
    bool rollback_called; /**< 未转移失败时实际调用过一次 take。 */
    vireo_result_t rollback_result; /**< 原 take 结果；未调用时逻辑 OK，不代表执行成功。 */
    vireo_inflight_stage_t inflight_stage; /**< 原登记错误或已调用 take 的阶段。 */
} vireo_inflight_submit_report_t;

/**
 * @brief
 *     将已构造的唯一 task 限额登记后，一次尝试交给 pool。
 *
 * @param[in,out] store
 *     必需存活表，全部访问 Reactor-only，只短借至返回。
 * @param[in] server
 *     必需当前客户资源根，按 register_limited 的公开准入核验，只短借。
 * @param[in,out] pool
 *     必需存活池；本提交与同池全部管理由 caller 串行同步，worker 可并发领取。
 * @param[in] max_client_requests
 *     显式正请求条数，不超过表容量；caller 统一同客户限额策略。
 * @param[in,out] task_owner
 *     必需独占非空 owner，所有旧借用已结束；只在真实转移时清源。
 * @param[out] report
 *     必需独立存活可写报告，每可写路径覆盖，不重叠 owner、资源、输入或 errno。
 *
 * @retval VIREO_OK
 *     登记和提交成功，队列/worker 接管任务，登记保留；不保证执行或回投完成。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需 NULL 或零限额，优先空 task 检查；其他非法参数沿公开依赖返回。
 * @retval VIREO_RESULT_NOT_FOUND
 *     空 task 源，或公开客户/池依赖未找到。
 *
 * @return
 *     其他 inspect、register_limited 或 pool_try_submit 原错误，撤销错误不覆盖主错。
 *
 * @note
 *     顺序：基本参数/空源→公开 inspect→register_task_limited→一次 pool_try_submit。
 *     登记失败不调用 pool；未转移的提交失败仅一次公开 take 撤销本次登记。
 *     take 失败保留登记并独立报告，task 仍归 caller；不内部重试或自动清理。
 * @note
 *     pool_report.queue_report.transferred 为真时，即使提交报错也保留登记。
 *     此时源已清空，worker 可能已执行并销毁 task；不得使用旧裸指针或退款。
 *     report.metadata 提供恢复键，不保活客户、不认证后续回写资格。
 * @note
 *     不构造、发号、复制 payload、申请、保存资源指针、等待容量或新加锁。
 *     不自动检查期限、请求取消、销毁任务、消费 completion 或接网络。
 *     任务登记保存可选独立取消引用；未转移退款时 take 释放表份，已转移则保留。
 *     task 自有引用随原所有权移动，caller 的独立引用仍由 caller 管理。
 * @note
 *     表扫描有界 O(capacity)，队列一次 trylock；引用取得沿原原子合同可能竞争重试，不承诺无锁、公平、耗时上界或硬实时。
 *     server 停止快照不是跨线程屏障；报告仅本次进度，不冻结 worker 或其他拥有者。
 *     所有路径保持入口 errno；未调用报告字段逻辑零，成功只保证逻辑字段。
 */
vireo_result_t vireo_inflight_store_try_submit(vireo_inflight_store_t *store,
    vireo_tcp_server_t const *server, vireo_thread_pool_t *pool,
    size_t max_client_requests, vireo_task_t **task_owner,
    vireo_inflight_submit_report_t *report);

#endif
