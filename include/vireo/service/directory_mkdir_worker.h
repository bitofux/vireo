/* PROJECT : VIREO; FILE : directory_mkdir_worker.h;
 * AUTHOR : bitofux; DATE : 2026-10-24; BRIEF : 原OS worker单次执行与清理后回投。 */
#ifndef VIREO_SERVICE_DIRECTORY_MKDIR_WORKER_H
#define VIREO_SERVICE_DIRECTORY_MKDIR_WORKER_H
#include <vireo/base/clock.h>
#include <vireo/service/directory_mkdir_completion.h>

/** @brief 创建线程独占的单次执行owner；不创建OS线程，禁止跨线程移动。 */
typedef struct vireo_directory_mkdir_worker vireo_directory_mkdir_worker_t;

/** @brief 四项长期借用依赖须保活至worker owner完全destroy。 */
typedef struct vireo_directory_mkdir_worker_resources {
    vireo_mysql_runtime_t *runtime;  /**< 存活MySQL根，非本层owned。 */
    vireo_mysql_pool_t *database;    /**< 与runtime配对共享pool，不自动refill。 */
    vireo_completion_queue_t *queue; /**< preparedMKDIR专用完成队列，非本层owned。 */
    vireo_notifier_t *notifier;      /**< 与queue配对通知源，非本层owned。 */
} vireo_directory_mkdir_worker_resources_t;

/** @brief 创建时复制的不变显式配置。 */
typedef struct vireo_directory_mkdir_worker_options {
    vireo_directory_mkdir_task_options_t execution; /**< mkdir_operation非零，pool等待≤60000。 */
    size_t completion_allocation_budget; /**< 正且≤completion硬限，实际所需由create_copy核。 */
    size_t max_memory_bytes; /**< 控制块正预算≤64MiB，不计DB/task/completion外部资源。 */
} vireo_directory_mkdir_worker_options_t;

/** @brief 每次清理的原始事实；非OK与owner是否消费必须分别看。 */
typedef struct vireo_directory_mkdir_worker_cleanup_report {
    bool repository_called;                    /**< 本次尝试一次repo destroy。 */
    vireo_result_t repository_result;          /**< 上项原rc，called时有效。 */
    vireo_mysql_node_error_t repository_error; /**< 原去敏诊断。 */
    bool detach_called;                        /**< repo owner已NULL后才尝试一次detach。 */
    vireo_result_t detach_result;              /**< 上项原rc。 */
    bool completion_called;           /**< 本次是否销毁未交接completion一次。 */
    vireo_result_t completion_result; /**< 上项原rc。 */
    bool repository_pending;          /**< 返回时repo owner仍非NULL。 */
    bool thread_pending;              /**< 返回时guard owner仍非NULL。 */
    bool completion_pending;          /**< 返回时未交接completion owner仍非NULL。 */
} vireo_directory_mkdir_worker_cleanup_report_t;

/** @brief 单次run受控事实快照；含原提交ID/key，不可整块记日志；无actor/name/event/SQL/资源指针。 */
typedef struct vireo_directory_mkdir_worker_report {
    bool attempted;                 /**< 本owner首次run机会已永久消耗。 */
    bool task_validated;            /**< 完整可信封装前置通过。 */
    vireo_task_metadata_t metadata; /**< inspect成功后有效的原路由。 */
    vireo_result_t work_result;     /**< 前置或execute原rc，与cleanup/publish分开。 */
    vireo_directory_mkdir_task_stage_t work_stage; /**< execute阶段，资源前置失败为CONTEXT。 */
    vireo_node_mkdir_issue_t request_issue;        /**< 原去敏请求诊断。 */
    bool attach_called;                            /**< 实际调用一次attach。 */
    bool repository_called; /**< 实际调用一次repo create，不等于查询。 */
    bool random_called;     /**< 已调用一次RAND_priv_bytes等价操作。 */
    vireo_result_t random_result; /**< called时有效；原生非1或全零为IO，其余OK；不保存event。 */
    bool clock_called;                /**< 实际采一次MONOTONIC。 */
    bool execute_called;              /**< 实际进入一次task execute，不等于SQL执行。 */
    vireo_mysql_error_t attach_error; /**< attach原诊断。 */
    vireo_mysql_node_error_t work_error; /**< repo create或service原诊断。 */
    vireo_clock_error_t clock_error;     /**< MONOTONIC原诊断。 */
    vireo_directory_mkdir_result_t
        service; /**< 整个原03值；含原rc/commit/effect/IDs/key/清理快照。 */
    vireo_directory_mkdir_worker_cleanup_report_t cleanup; /**< run后一次原线程清理。 */
    bool publication_blocked_by_cleanup; /**< 外层清理非OK或owner残留，禁止publish。 */
    bool publish_called;           /**< task合法且外层清理完整后才尝试一次。 */
    vireo_result_t publish_result; /**< 原publish rc，与work_result不同。 */
    vireo_directory_mkdir_completion_publish_report_t publication; /**< 原交接/通知事实。 */
    bool completion_pending; /**< run返回时未交接completion仍归本owner。 */
} vireo_directory_mkdir_worker_report_t;

/**
 * @brief 原OS worker创建单次控制块，尚不attach/查询
 * @param[in] resources
 *     必需完整四依赖，复制指针借至destroy，不接管。
 * @param[in] options
 *     必需显式配置，复制值；预算只限控制块，非总请求内存上限。
 * @param[out] owner
 *     必需独占空地址，成功仅创建线程可run/destroy。
 *
 * @retval VIREO_OK
 *     单次owner发布，未创建DB子资源。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需NULL/非空owner或零operation/预算。
 * @retval VIREO_RESULT_RANGE
 *     pool等待/预算越界或控制块预算不足。
 * @retval VIREO_RESULT_NO_MEMORY
 *     控制块申请失败，owner保持。
 *
 * @note 无OS线程创建，记录pthread_self；run不能在已有其他MySQL guard的线程执行。
 *     保持errno；输入只借至返回，依赖由caller长期保活，独立worker可并发。
 *     地址有效对齐独立、不指errno；不登记/提交task或创建队列/通知源。
 */
vireo_result_t vireo_directory_mkdir_worker_create(
    const vireo_directory_mkdir_worker_resources_t *resources,
    const vireo_directory_mkdir_worker_options_t *options, vireo_directory_mkdir_worker_t **owner);

/**
 * @brief 核task→attach/repo→一次随机事件→新MONOTONIC/execute→清理门禁→一次publish
 * @param[in,out] worker
 *     必需创建线程独占owner，首次run后仅可destroy。
 * @param[in] task
 *     必需稳定可信VMT1，借至返回，不保存/销毁；池callback返回后由pool释放。
 * @param[out] report
 *     必需独立受控报告（含原ID/key）；非NULL先零，重run返回原快照。
 *
 * @retval VIREO_OK
 *     work/外层cleanup/publish全部OK，不证明网络交付，仍须destroy owner。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需NULL/跨线程拒绝或原依赖参数拒绝。
 * @retval VIREO_RESULT_BUSY
 *     同owner已attempted，不执行/发布；也可为原工作结果。
 * @return work首错优先，随后外层cleanup首错，最后publish原错；分别读报告。
 *
 * @note 基本地址/线程拒绝不消耗机会；通过后即永久attempted，畸形task也不恢复机会。
 *     畸形task不attach/执行/发布；task通过后的attach/repo/clock失败可合成匹配CONTEXT错误；随机失败为RANDOM/IO。
 *     先repo destroy一次，owner已NULL才detach一次；外层任一非OK或owner仍存活禁止publish。
 *     cleanup返回OK但owner残留按INTERNAL；阻断时管理层须故障锁存/清退inflight，不能静等响应。
 *     原service清理曾失败但外层成功，只可publish INTERNAL_ERROR，原事实不改。
 * @note 随机源仅调用一次RAND_priv_bytes(16)，返回1且非全零才可execute；其余IO，无重试/派生/降级。
 *     部分随机字节擦除；生成后才采新MONOTONIC。事件偶然等客户端键不额外拒绝。
 * @note POSIX取消禁用，可能等待随机源/SQL/pool/完成队列，无硬墙钟；consumer先腾空间再join。
 *     不重run/重试/补创建/补池，不保留task/name/actor/event；原service事实与未消费owner保留。
 *     未交接completion归worker，已交接绝不触碰；擦除所有局部事件/输入/结果，保持errno，地址独立不指errno。
 */
vireo_result_t vireo_directory_mkdir_worker_run(vireo_directory_mkdir_worker_t *worker,
                                                const vireo_task_t *task,
                                                vireo_directory_mkdir_worker_report_t *report);

/**
 * @brief 原线程只清理残留并尝试消费单次owner，不再执行业务/发布
 * @param[in,out] owner
 *     必需唯一owner地址，空owner幂等OK，活owner须创建线程访问。
 * @param[out] report
 *     必需独立本次清理报告，非NULL入口重置。
 *
 * @retval VIREO_OK
 *     本次清理全部成功且owner已NULL。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需NULL或跨线程，活owner保持。
 * @return 原首清理错误，仍须读取*owner；失败可能已消费并清NULL。
 *
 * @note 每子owner本次至多一次destroy/detach；repo空才detach，未交接completion显式丢弃。
 *     仅全部子owner空时擦除并释放控制块；有残留只许原线程再destroy，不移交给Reactor。
 *     无内部循环/重做SQL/重新publish；有限清理耗尽的生产runtime终止策略须后续明确。
 *     依赖保活、POSIX取消禁用，保持errno；地址独立有效不指errno。
 */
vireo_result_t vireo_directory_mkdir_worker_destroy(
    vireo_directory_mkdir_worker_t **owner, vireo_directory_mkdir_worker_cleanup_report_t *report);
#endif
