/* 应用私有合同：045-05；2026-10-24。 */
#ifndef VIREO_APP_DIRECTORY_MKDIR_WORKER_RUNTIME_H
#define VIREO_APP_DIRECTORY_MKDIR_WORKER_RUNTIME_H
#include "directory_list_worker_runtime.h"
#include <vireo/service/directory_mkdir_worker.h>
/** @brief 永久故障位；普通领域拒绝和已交接的技术DB_ERROR不直接置位。 */
typedef enum vireo_directory_mkdir_worker_fault {
    VIREO_DIRECTORY_MKDIR_WORKER_FAULT_CREATE=1u, /**< owner创建失败，缺完成。 */
    VIREO_DIRECTORY_MKDIR_WORKER_FAULT_TASK=2u, /**< task未通过可信封装检查。 */
    VIREO_DIRECTORY_MKDIR_WORKER_FAULT_CLEANUP=4u, /**< 历史/外层清理曾失败或有残留。 */
    VIREO_DIRECTORY_MKDIR_WORKER_FAULT_PUBLISH=8u, /**< 未调用/未交接/发布或通知失败。 */
    VIREO_DIRECTORY_MKDIR_WORKER_FAULT_RESIDUAL=16u, /**< 有限destroy后owner未空，真实_Exit。 */
    VIREO_DIRECTORY_MKDIR_WORKER_FAULT_DISPATCH=32u /**< inspect失败/未知operation。 */
} vireo_directory_mkdir_worker_fault_t;
/** @brief 五次独立relaxed采样，不是同时快照。 */
typedef struct vireo_directory_mkdir_worker_faults {
    unsigned auth,stat,root,list,mkdir; /**< 各域互不混用。 */
} vireo_directory_mkdir_worker_faults_t;
/** @brief 启动前排他初始化后安全发布；活跃期间禁止复制/重初始化，无自有堆owner。 */
typedef struct vireo_directory_mkdir_worker_runtime {
    vireo_directory_list_worker_runtime_t *previous; /**< 长借完整七命令context至全部callback退出/join。 */
    vireo_directory_mkdir_worker_resources_t resources; /**< 四借用依赖，独立mkdir queue，共享runtime/pool/notifier。 */
    vireo_directory_mkdir_worker_options_t options; /**< 按值复制，mkdir op与前七项互异。 */
    size_t destroy_attempts; /**< 原OS线程1..16次，仅清理非SQL重试，生产3。 */
    atomic_uint faults; /**< 初值0，relaxed OR六位，无伴随payload。 */
} vireo_directory_mkdir_worker_runtime_t;
/**
 * @brief 核资源配对与八标签，初始化固定池混合callback上下文
 * @param[out] runtime 必需独立未发布存储，失败整个存储保持；成功不可复制/重初始化。
 * @param[in,out] previous 必需已初始化七命令context，启动排他且四域faults为0；长期借用，不接管。
 * @param[in] resources 必需完整四依赖；runtime/database/notifier与前层auth相同，queue不同于前四queue，复制长借。
 * @param[in] options 必需显式04配置；复制为只读值，operation非零互异。
 * @param[in] destroy_attempts 原线程清理1..16次，生产3，不是SQL重试/时长。
 * @retval VIREO_OK 配置及faults=0已发布到输出，未创建owner/线程或SQL。
 * @retval VIREO_RESULT_INVALID_ARGUMENT NULL/缺依赖/配对不符/标签零或重复/零预算或次数。
 * @retval VIREO_RESULT_RANGE 次数>16、pool等待>60000ms或预算超公开硬限。
 * @retval VIREO_RESULT_BUSY 前层已有永久故障，输出保持。
 * @retval VIREO_RESULT_INTERNAL atomic_uint非lock-free，输出保持。
 * @note 启动排他、禁POSIX取消、保持errno，输入/输出独立有效对齐不指errno；局部探针成功后才写输出。
 * 不拥有依赖，无独立destroy；所有borrow活到callback全结束/join，caller负责安全发布及queue公开前置。
 */
vireo_result_t vireo_directory_mkdir_worker_runtime_init(vireo_directory_mkdir_worker_runtime_t *runtime,
    vireo_directory_list_worker_runtime_t *previous, const vireo_directory_mkdir_worker_resources_t *resources,
    const vireo_directory_mkdir_worker_options_t *options, size_t destroy_attempts);
/**
 * @brief 不等待采样五域故障
 * @param[in] runtime 必需已安全发布的存活context与全部前层，短借；禁止并发结束寿命。
 * @param[out] out 必需独立对齐值，成功覆盖，失败整个保持。
 * @retval VIREO_OK 五域各取得一次样本，全零不证明别的callback没在出错。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 必需NULL，输出保持。
 * @return 前层采样意外错误透传，输出保持。
 * @note 多worker/单Reactor可并发，仅faults可变原子；保持errno，无申请/I/O/等待或唤醒。
 */
vireo_result_t vireo_directory_mkdir_worker_runtime_inspect_faults(
    const vireo_directory_mkdir_worker_runtime_t *runtime,vireo_directory_mkdir_worker_faults_t *out);
/**
 * @brief 固定池原OS线程按operation路由八命令，MKDIR单次run与有限清理
 * @param[in,out] context 必需长期存活runtime，活至全部callback退出/join与pool销毁。
 * @param[in] task 必需pool短借task，不保存/修改/移动/销毁，回调返回后pool释放。
 * @retval VIREO_OK 被选run及清理内部成功，不证明业务响应送达。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 必需NULL，不能推断故障已锁存。
 * @retval VIREO_RESULT_CANCELLED 入口采样任域非零，不执行/不回投，app清退其inflight。
 * @retval VIREO_RESULT_PROTOCOL 未注册operation，锁DISPATCH，不尝试别的decoder。
 * @return inspect原错锁DISPATCH并透传；旧七命令调用前层；MKDIR保create/run首错，否则destroy首错。
 * @note 先采五域，再只按operation分发。MKDIR create一次/run至多一次；owner非空才原线程destroy至多配置次。
 * 已并发进入的callback可自然完成；错误/通知失败已交接不能重做SQL、换随机事件或重新publish。
 * @note TASK核task_validated；CLEANUP核04 work_error.cleanup_result、service.repository.cleanup_pending、外层called/result/pending及publication_blocked_by_cleanup。
 * 即使raw COMMITTED/CREATED或RECOVERED且后来释放成功，历史清理错误仍永久锁存，不因wire INTERNAL_ERROR清位。
 * PUBLISH核called/rc/真实transferred；通知错已转移也锁位。原生random IO/UNKNOWN等若清理交接完整，不单独置基础设施位。
 * @note destroy错误/实际残留永久CLEANUP；次数耗尽仍有owner先RESIDUAL再真实_Exit(EXIT_FAILURE)，不返回/不跨线程释放/不pthread_exit，无fatal hook。
 * 正常返回保持errno，POSIX取消禁用；可阻塞SQL/随机源/队列，次数有限无墙钟承诺。
 * 全服务故障分别关闭task与五完成queue后join，join后drain五queue并保留迟到LOGOUT；借用活至最后owner退出。
 */
vireo_result_t vireo_directory_mkdir_worker_runtime_execute(void *context,const vireo_task_t *task);
#endif
