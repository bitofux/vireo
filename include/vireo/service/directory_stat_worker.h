/* PROJECT: VIREO; FILE: directory_stat_worker.h; DATE: 2026-10-22. */
#ifndef VIREO_SERVICE_DIRECTORY_STAT_WORKER_H
#define VIREO_SERVICE_DIRECTORY_STAT_WORKER_H
#include <vireo/base/clock.h>
#include <vireo/service/directory_stat_completion.h>

/** @brief 当前创建OS worker独占的一次执行owner，禁止跨线程移交。 */
typedef struct vireo_directory_stat_worker vireo_directory_stat_worker_t;
/** @brief 长期借用依赖，须活到owner完全destroy，不拥有外部根/池/队列。 */
typedef struct vireo_directory_stat_worker_resources {
    vireo_mysql_runtime_t *runtime; /**< 存活MySQL根。 */
    vireo_mysql_pool_t *database; /**< 与runtime配对池。 */
    vireo_completion_queue_t *queue; /**< 对应STAT专用完成队列。 */
    vireo_notifier_t *notifier; /**< 同队列通知源。 */
} vireo_directory_stat_worker_resources_t;
/** @brief 复制的不变显式配置，不含认证/KDF/UTC/Session寿命。 */
typedef struct vireo_directory_stat_worker_options {
    vireo_directory_stat_task_options_t execution; /**< operation非零，pool等待≤60000ms。 */
    size_t completion_allocation_budget; /**< 正且≤completion申请硬限。 */
    size_t max_memory_bytes; /**< 控制块正预算≤64MiB；不含task/DB/completion。 */
} vireo_directory_stat_worker_options_t;
/** @brief 一次清理实际前缀；owner消费与rc分别观察。 */
typedef struct vireo_directory_stat_worker_cleanup_report {
    bool repository_called; /**< 本次是否尝试一次repo destroy。 */
    vireo_result_t repository_result; /**< 本次原rc。 */
    vireo_mysql_node_error_t repository_error; /**< 本次原去敏诊断。 */
    bool detach_called; /**< 仅repo owner已NULL时尝试detach一次。 */
    vireo_result_t detach_result; /**< 本次原rc。 */
    bool completion_called; /**< 是否destroy本层未交接completion一次。 */
    vireo_result_t completion_result; /**< 本次原rc。 */
    bool repository_pending, thread_pending, completion_pending; /**< 返回时实际owner是否仍非NULL。 */
} vireo_directory_stat_worker_cleanup_report_t;
/** @brief 单次run去敏快照，不含节点名字/hash、SQL或owner指针。 */
typedef struct vireo_directory_stat_worker_report {
    bool attempted, task_validated; /**< run机会已消耗/完整task前置通过。 */
    vireo_task_metadata_t metadata; /**< inspect成功后的独立原路由。 */
    vireo_result_t work_result; /**< 前置或execute原rc，与publish/cleanup分开。 */
    vireo_directory_stat_task_stage_t work_stage; /**< execute原阶段，前置失败为CONTEXT。 */
    vireo_node_stat_issue_t request_issue; /**< 原帧去敏诊断。 */
    bool attach_called, repository_called, clock_called, execute_called; /**< 各依赖调用事实。 */
    vireo_mysql_error_t attach_error; /**< 原attach诊断。 */
    vireo_mysql_node_error_t work_error; /**< repo create或service原诊断。 */
    vireo_clock_error_t clock_error; /**< 一次MONOTONIC采样诊断。 */
    vireo_directory_stat_outcome_t outcome; /**< 原service类别，不含node，非交付事实。 */
    vireo_mysql_node_report_t repository; /**< 原service repo报告，保cleanup_pending。 */
    vireo_directory_stat_worker_cleanup_report_t cleanup; /**< run后一次资源清理事实。 */
    bool publication_blocked_by_cleanup; /**< 外层清理非OK或owner残留，未发布任何结果。 */
    bool publish_called; /**< 通过task前置且外层清理完整后才尝试一次。 */
    vireo_result_t publish_result; /**< 原publish rc，不等工作rc。 */
    vireo_directory_stat_completion_publish_report_t publication; /**< 原交接与通知事实。 */
    bool completion_pending; /**< run返回时未交接completion仍归本owner。 */
} vireo_directory_stat_worker_report_t;

/**
 * @brief 当前OS worker创建单次owner，尚不attach/借库/执行业务
 * @param[in] resources 必需四项非NULL配对关联，复制指针借至destroy清owner。
 * @param[in] options 必需显式配置，复制值；预算不含外部依赖开销。
 * @param[out] owner 必需独占空地址，成功由创建线程run/destroy。
 * @retval VIREO_OK 控制块已发布，无DB子资源。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 必需NULL/非空owner/零operation或预算。
 * @retval VIREO_RESULT_RANGE 配置越硬限或控制块预算不足。
 * @retval VIREO_RESULT_NO_MEMORY 控制块分配失败，owner保持。
 * @note 保持errno，无线程创建；记录pthread_self，不支持线程已有其他MySQL guard时run。
 *     地址独立有效不重叠；共享依赖生存期由管理端同步，max_memory≤64MiB。
 */
vireo_result_t vireo_directory_stat_worker_create(vireo_directory_stat_worker_resources_t const *resources,
    vireo_directory_stat_worker_options_t const *options, vireo_directory_stat_worker_t **owner);

/**
 * @brief 核task→attach/repo→一次monotonic/execute→清理→一次回投
 * @param[in,out] worker 必需创建OS线程的独占owner，第一次run后只能destroy。
 * @param[in] task 必需可信VDS1，短借至返回，不保存/销毁；pool callback返回后由pool释放。
 * @param[out] report 必需独立去敏报告，基本拒绝零；重入返回原保存快照。
 * @retval VIREO_OK 工作、外层资源清理、交接与通知均成功，仍须destroy owner。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 必需NULL/跨线程或原依赖前置拒绝。
 * @retval VIREO_RESULT_BUSY 此owner已尝试run，不执行任何业务/发布；亦可能为原work错误。
 * @return work首错优先，其次外层cleanup首错，最后publish原错，真实报告分别保留。
 * @note 必需地址/创建线程检查失败不消耗run机会，也不改worker；通过后首次run即永久消耗，
 *     随后的task前置失败也不恢复机会；畸形task不attach、不执行、不发布。
 *     task通过后的attach/create/clock失败可合成匹配的CONTEXT错误结果；无DB副作用重试。
 *     repo destroy后仅owner空才detach；外层任一清理非OK或残留禁止发布，保留原owner，
 *     publication_blocked_by_cleanup=true；若rc为OK但仍有owner，按INTERNAL处理；
 *     管理端须锁存故障/清退inflight，不得假称已响应。
 *     service自身曾清理失败即使后续destroy成功，仍只发布INTERNAL_ERROR，无节点。
 * @note 全调用POSIX取消禁用；可能等待SQL/pool/完成队列，consumer先drain再join。
 *     不保留task/原节点结果，只保去敏报告及未消费owner；无网络/I/O路由或回调装配。
 *     保持errno，地址独立不重叠不指errno；不得跨线程销毁或自动重run。
 */
vireo_result_t vireo_directory_stat_worker_run(vireo_directory_stat_worker_t *worker,
    vireo_task_t const *task, vireo_directory_stat_worker_report_t *report);

/**
 * @brief 原OS worker仅清理残留/未交接completion并尝试释放owner，不再执行或发布
 * @param[in,out] owner 必需唯一owner地址；空owner幂等OK，存活对象须在创建线程。
 * @param[out] report 必需独立本次清理报告，每可写路径重置。
 * @retval VIREO_OK 本次所有清理成功、owner已NULL。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 必需NULL或跨线程；活owner保持。
 * @return 原首清理错误；失败仍须看*owner，可能已消费并清NULL。
 * @note 每owner本次至多尝试一次对应destroy/detach，按实际NULL决定可否释放控制块。
 *     仍有残留就保留owner，只能原worker再次destroy，不能靠report复制转移资源责任。
 *     无业务/再次发布/跨调用循环；未交接completion显式丢弃，已交接绝不触碰。
 *     保持errno，POSIX取消禁用；管理端保活依赖，有限重试耗尽的退出政策属后续runtime。
 */
vireo_result_t vireo_directory_stat_worker_destroy(vireo_directory_stat_worker_t **owner,
    vireo_directory_stat_worker_cleanup_report_t *report);
#endif
