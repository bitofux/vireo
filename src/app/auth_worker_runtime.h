/*
 * PROJECT : VIREO
 * FILE    : auth_worker_runtime.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-20
 * BRIEF   : 应用私有callback、原线程有限清理及永久故障锁存。
 */
#ifndef VIREO_APP_AUTH_WORKER_RUNTIME_H
#define VIREO_APP_AUTH_WORKER_RUNTIME_H
#include <stdatomic.h>
#include <vireo/service/auth_worker.h>

/** 应用私有故障位；可以组合，仅有无秘密类别，不是业务返回码或wire状态。 */
typedef enum vireo_auth_worker_fault {
    VIREO_AUTH_WORKER_FAULT_CREATE = 1u, /**< 一次执行owner创建失败，无结果交接。 */
    VIREO_AUTH_WORKER_FAULT_TASK = 2u, /**< 可信task关联/完整帧前置失败。 */
    VIREO_AUTH_WORKER_FAULT_CLEANUP = 4u, /**< 清理返回非OK或曾保留子owner，之后清空也不撤回故障。 */
    VIREO_AUTH_WORKER_FAULT_PUBLISH = 8u, /**< 未调用/未交接/回投或通知非OK，不能重投。 */
    VIREO_AUTH_WORKER_FAULT_RESIDUAL = 16u /**< destroy次数耗尽仍有owner，应用直接终止整个进程。 */
} vireo_auth_worker_fault_t;

/**
 * 应用私有、启动前排他初始化的固定context；不是新的公共ABI。
 * resources/options/destroy_attempts发布后只读；只有faults允许并发读/OR写。
 * context及借用依赖必须活到全部callback结束、join及pool销毁完成。
 * 不复制活跃context、不重置故障位；无独立malloc或destroy入口。
 */
typedef struct vireo_auth_worker_runtime {
    vireo_auth_worker_resources_t resources; /**< 六项配对借用副本；无server/connection/fd。 */
    vireo_auth_worker_options_t options; /**< 复制18的显式政策；须与Reactor注册表/timeout同源。 */
    size_t destroy_attempts; /**< run后同OS worker最多1..16次destroy；建议装配值3，不含run内清理。 */
    atomic_uint faults; /**< 初值0，只OR上述五位；无附带payload/首错时序，不靠它发布其他内存。 */
} vireo_auth_worker_runtime_t;

/**
 * @brief 启动前排他准备callback的固定context，尚不创建线程或执行认证
 * @param[out] runtime
 *     必需独立有效对齐存储，尚未发布/初始化；成功后不能再次初始化或复制。
 * @param[in] resources
 *     必需六项非NULL配对依赖，复制借用；caller保证原18的资源和寿命前置条件。
 * @param[in] options
 *     必需复制值，按18公开形态/上限检查；不保证分配、DB、KDF或repository策略可用。
 * @param[in] destroy_attempts
 *     显式1..16次，仅在原OS worker尝试destroy，建议传3；不是毫秒或重做业务次数。
 * @retval VIREO_OK
 *     四字段初始化，faults=0；没有owner/DB操作。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需NULL、资源缺项、零时长/预算、零/相同operation或零destroy次数。
 * @retval VIREO_RESULT_RANGE
 *     destroy次数>16或18已有公开范围超限。
 * @retval VIREO_RESULT_INTERNAL
 *     本平台atomic_uint非lock-free，拒绝发布；不能给Reactor增加隐藏等待锁。
 * @note 全路径保持errno，失败runtime保持；无线程安全发布的替代作用。
 *       初始检查使用局部atomic探针；成功才初始化runtime的原子字段。
 *       配置合法不保证后续运行成功；对象最小申请量仍由18的create检查。
 */
vireo_result_t vireo_auth_worker_runtime_init(vireo_auth_worker_runtime_t *runtime,
    vireo_auth_worker_resources_t const *resources, vireo_auth_worker_options_t const *options,
    size_t destroy_attempts);

/**
 * @brief 一次非等待读取永久故障位，不调用队列/notifier或采时
 * @param[in] runtime
 *     必需已安全发布的存活context，借至返回；不能并发重新初始化或销毁存储。
 * @param[out] out_faults
 *     必需独立unsigned输出；成功覆盖五位组合，0仅表示本次未观察到已锁存故障。
 * @retval VIREO_OK
 *     已取得一次relaxed原子快照，不证明所有worker健康或无在途动作。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需NULL，输出保持。
 * @note 保持errno；多worker/单Reactor可并发，无分配/I/O/等待。
 *       字段无伴随payload，relaxed足够；启动发布与join仍用原线程池同步。
 *       Reactor须在每轮前后检查，poll正等待至多1000ms；不是检测时延硬保证。
 */
vireo_result_t vireo_auth_worker_runtime_inspect_faults(vireo_auth_worker_runtime_t const *runtime,
    unsigned *out_faults);

/**
 * @brief 在固定池当前OS worker执行一次认证并完成清理，永久故障则锁存或终止进程
 * @param[in,out] context
 *     必需存活runtime；由pool configure短借，整体寿命覆盖pool，不能传其他类型。
 * @param[in] task
 *     必需该次pool短借task；不保存/修改/移动/销毁，由pool在正常返回后销毁。
 * @retval VIREO_OK
 *     原run及所有destroy成功，且入口没有故障；普通认证拒绝按原run返回非OK。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需NULL；不能由无效context推导故障通知已锁存。
 * @retval VIREO_RESULT_CANCELLED
 *     入口已观察到故障，仅跳过业务，无新owner/回投；上游须全服务清退inflight。
 * @return 正常返回时保原create/run首错，否则destroy首错；不按总rc判业务提交或owner。
 * @note create一次、run至多一次；随后同OS worker至多destroy_attempts次destroy，
 *       每次只在owner仍非NULL时调用。非OK但owner已空可正常返回；不重做SQL/COMMIT/发布。
 *       入口无故障的并发callback可能已经开始，允许各自完成一次，不抢断其他线程。
 * @note 清理和发布分开判故障：原task_validated为false锁存TASK；run的cleanup
 *       任一实际调用非OK/实际pending锁存CLEANUP；未publish、非OK或原completion_transferred
 *       为false锁存PUBLISH（TASK前置失败可同时有TASK/PUBLISH）。destroy非OK/保owner亦锁存CLEANUP。
 *       仅work_result非OK、提交UNKNOWN、普通业务拒绝不单独锁存基础设施故障；
 *       已交接而通知失败仍PUBLISH，绝不重投；已提交事实不因故障改写。
 * @note 次数耗尽仍非NULL：先OR RESIDUAL，再在此应用层调用_Exit(EXIT_FAILURE)，不返回callback，
 *       不运行atexit/stdio flush、不产生日志token或core；不是abort、pthread_exit或跨线程释放。
 *       此分支结束整个进程，丢弃所有在途响应；数据库已提交事务保持，UNKNOWN禁止自动重放。
 * @note 全调用POSIX取消禁用，保持正常返回errno；可阻塞DB/KDF/完成队列，仅worker使用。
 *       次数有界不保证时间有界，单次依赖可阻塞；故障位并不唤醒满队列，Reactor须执行关闭协议。
 *       严重残留的进程终止策略由应用负责，不能将本入口作为通用库回调使用。
 */
vireo_result_t vireo_auth_worker_runtime_execute(void *context, vireo_task_t const *task);
#endif
