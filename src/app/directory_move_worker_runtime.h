/* PROJECT : VIREO; FILE : directory_move_worker_runtime.h;
 * AUTHOR : bitofux; DATE : 2026-10-25; BRIEF : 九命令应用私有runtime。 */
#ifndef VIREO_APP_DIRECTORY_MOVE_WORKER_RUNTIME_H
#define VIREO_APP_DIRECTORY_MOVE_WORKER_RUNTIME_H
#include "directory_mkdir_worker_runtime.h"
#include <vireo/service/directory_move_worker.h>

/** @brief MOVE永久故障位，与前五域独立；普通领域结果不直接置基础设施故障。 */
typedef enum vireo_directory_move_worker_fault {
    VIREO_DIRECTORY_MOVE_WORKER_FAULT_CREATE = 1u, /**< 创建失败，可能缺完成。 */
    VIREO_DIRECTORY_MOVE_WORKER_FAULT_TASK = 2u, /**< 可信task封装未通过。 */
    VIREO_DIRECTORY_MOVE_WORKER_FAULT_CLEANUP = 4u, /**< 历史/外层清理错或残留。 */
    VIREO_DIRECTORY_MOVE_WORKER_FAULT_PUBLISH = 8u, /**< 未发布/未转移/通知或交接错误。 */
    VIREO_DIRECTORY_MOVE_WORKER_FAULT_RESIDUAL = 16u, /**< 有限销毁仍有owner，真实_Exit。 */
    VIREO_DIRECTORY_MOVE_WORKER_FAULT_DISPATCH = 32u /**< inspect失败或未知operation。 */
} vireo_directory_move_worker_fault_t;
/** @brief 六次独立relaxed采样，不是全局同时快照，不发布伴随payload。 */
typedef struct vireo_directory_move_worker_faults {
    unsigned auth; /**< 原认证永久故障域。 */
    unsigned stat; /**< 原STAT永久故障域。 */
    unsigned root; /**< 原ROOT永久故障域。 */
    unsigned list; /**< 原LIST永久故障域。 */
    unsigned mkdir; /**< 原MKDIR永久故障域。 */
    unsigned move; /**< 新MOVE永久故障域。 */
} vireo_directory_move_worker_faults_t;
/** @brief 启动排他初始化并安全发布，活跃期间不可复制或重新初始化，无自有heap owner。 */
typedef struct vireo_directory_move_worker_runtime {
    vireo_directory_mkdir_worker_runtime_t *previous; /**< 完整八命令context长借至callback退出/join。 */
    vireo_directory_move_worker_resources_t resources; /**< 四依赖借用，独立MOVE queue。 */
    vireo_directory_move_worker_options_t options; /**< 按值不变配置，MOVE标签与前八互异。 */
    size_t destroy_attempts; /**< 原OS线程清理1..16次，生产3；非SQL重试或时间预算。 */
    atomic_uint faults; /**< 初值0，relaxed OR六位，无清零接口。 */
} vireo_directory_move_worker_runtime_t;

/**
 * @brief 核资源配对、九标签及前五域后，初始化混合callback上下文
 * @param[out] runtime
 *     必需独立未发布存储，失败整个保持，成功后不可复制/重初始化。
 * @param[in,out] previous
 *     必需完整已初始化八命令context，启动排他且五域faults为0；长借不接管。
 * @param[in] resources
 *     必需完整四依赖；runtime/database/notifier与原auth相同，queue与前五queue不同。
 * @param[in] options
 *     必需显式04配置，按值复制；operation非零互异，预算正且合法。
 * @param[in] destroy_attempts
 *     原线程清理1..16次，生产3，不重run、不重做SQL、不重新publish。
 * @retval VIREO_OK
 *     只发布配置与faults=0，未创建owner/线程或执行SQL。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需NULL、依赖缺失/配对不符、零或重复标签、零预算/次数。
 * @retval VIREO_RESULT_RANGE
 *     次数>16、pool等待>60000ms或预算超公开硬限。
 * @retval VIREO_RESULT_BUSY
 *     前五域已有永久故障，输出保持。
 * @retval VIREO_RESULT_INTERNAL
 *     atomic_uint非lock-free，输出保持。
 * @note 启动排他、保持errno、禁POSIX取消；地址有效对齐独立且不指errno。
 *     不拥有资源，无独立destroy；borrow活至所有callback结束及pool销毁。
 */
vireo_result_t vireo_directory_move_worker_runtime_init(
    vireo_directory_move_worker_runtime_t *runtime,
    vireo_directory_mkdir_worker_runtime_t *previous,
    const vireo_directory_move_worker_resources_t *resources,
    const vireo_directory_move_worker_options_t *options, size_t destroy_attempts);

/**
 * @brief 不等待采样全部六个故障域
 * @param[in] runtime
 *     必需安全发布的存活context和完整前层，短借且禁止并发结束寿命。
 * @param[out] out
 *     必需独立对齐输出，仅成功覆盖，失败整个含padding保持。
 * @retval VIREO_OK
 *     六域各取一次样本，全零不证明另一callback尚未出错。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需NULL，输出保持。
 * @return 前层采样意外错误透传，输出保持。
 * @note 多worker及单Reactor可并发；仅faults为可变原子。保持errno，无申请/I/O/等待。
 */
vireo_result_t vireo_directory_move_worker_runtime_inspect_faults(
    const vireo_directory_move_worker_runtime_t *runtime,
    vireo_directory_move_worker_faults_t *out);

/**
 * @brief 固定池原OS线程按operation分派九命令，MOVE单次run及有限清理
 * @param[in,out] context
 *     必需存活已发布runtime，借至全部callback退出/join及pool销毁。
 * @param[in] task
 *     必需pool短借task，不保存、移动、销毁，callback返回后由pool释放。
 * @retval VIREO_OK
 *     被选run和清理内部成功，不代表业务OK或送达。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需NULL，不能推断故障已锁存。
 * @retval VIREO_RESULT_CANCELLED
 *     入口六域任一故障，不执行业务/回投，由app清退inflight。
 * @retval VIREO_RESULT_PROTOCOL
 *     未知operation，锁MOVE DISPATCH，不尝试其他decoder。
 * @return inspect原错锁DISPATCH；原八命令委托previous；MOVE保create/run首错，否则destroy首错。
 * @note 六域先采样，operation路由后才decode；create一次/run至多一次。
 *     CLEANUP核work_error.cleanup_result、service.repository.cleanup_pending、run外层cleanup
 *     called/result/pending和publication_blocked_by_cleanup；原APPLIED/RECOVERED也不能清除历史故障。
 *     PUBLISH核called、rc及completion_transferred，转移后通知错同样锁位且绝不重投。
 *     完整清理交接的领域拒绝、random IO或技术DB_ERROR不单独置基础设施位。
 * @note owner非空才在原OS线程destroy至多配置次；任一destroy非OK或残留永久锁CLEANUP。
 *     次数耗尽仍有owner，先锁RESIDUAL再真实_Exit(EXIT_FAILURE)，不跨线程释放、不pthread_exit，
 *     无fatal hook。并发已进入的callback可自然完成；管理方分别close七queue后join及最终drain。
 *     正常返回保持errno，禁POSIX取消；可阻塞SQL/随机源/完成队列，无墙钟上限。
 */
vireo_result_t vireo_directory_move_worker_runtime_execute(void *context, const vireo_task_t *task);
#endif
