/*
 * PROJECT : VIREO
 * FILE    : directory_root_worker_runtime.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-22
 * BRIEF   : 应用私有合同：混合固定池callback与ROOT未回投故障收尾。
 */
#ifndef VIREO_APP_DIRECTORY_ROOT_WORKER_RUNTIME_H
#define VIREO_APP_DIRECTORY_ROOT_WORKER_RUNTIME_H
#include "directory_stat_worker_runtime.h"
#include <vireo/service/directory_root_worker.h>

/** @brief ROOT及混合分发的永久故障位；业务NOT_FOUND/TIMEOUT/BUSY不是这些位。 */
typedef enum vireo_directory_root_worker_fault {
    VIREO_DIRECTORY_ROOT_WORKER_FAULT_CREATE = 1u, /**< ROOT执行owner创建失败，未回投。 */
    VIREO_DIRECTORY_ROOT_WORKER_FAULT_TASK = 2u, /**< ROOT可信task验证未通过。 */
    VIREO_DIRECTORY_ROOT_WORKER_FAULT_CLEANUP = 4u, /**< 清理非OK或曾有残留，后续恢复也不清位。 */
    VIREO_DIRECTORY_ROOT_WORKER_FAULT_PUBLISH = 8u, /**< 未调用/未交接/回投或通知报错。 */
    VIREO_DIRECTORY_ROOT_WORKER_FAULT_RESIDUAL = 16u, /**< 原线程有限destroy后仍有owner，终止进程。 */
    VIREO_DIRECTORY_ROOT_WORKER_FAULT_DISPATCH = 32u /**< task inspect失败/非六个已注册标签，未交业务。 */
} vireo_directory_root_worker_fault_t;

/** @brief 三个独立原子样本，不保证同时性；任一非零即进入全服务故障协议。 */
typedef struct vireo_directory_root_worker_faults {
    unsigned auth; /**< 原认证故障位独立样本。 */
    unsigned stat; /**< 前层STAT故障位独立样本。 */
    unsigned root; /**< 本层ROOT六故障位独立样本。 */
} vireo_directory_root_worker_faults_t;

/** @brief 启动前排他初始化并安全发布，活跃期间禁止复制/重初始化，无自有堆owner。 */
typedef struct vireo_directory_root_worker_runtime {
    vireo_directory_stat_worker_runtime_t *previous; /**< 长期借用已初始化原context；生命周期覆盖本context和所有callback。 */
    vireo_directory_root_worker_resources_t resources; /**< 四公开依赖复制借用，ROOT独立queue、共享notifier/runtime/database。 */
    vireo_directory_root_worker_options_t options; /**< 启动复制后只读；root_operation与四认证及STAT标签互异。 */
    size_t destroy_attempts; /**< run后原OS worker最多1..16次清理调用，建议3，不含run内清理。 */
    atomic_uint faults; /**< 初值0，仅relaxed OR六故障位；不发布任何附带payload。 */
} vireo_directory_root_worker_runtime_t;

/**
 * @brief 启动前验证混合注册表及资源配对，准备固定池callback上下文
 *
 * @param[out] runtime
 *     必需尚未初始化/发布的独立对齐存储；失败整个存储保持，成功后不得复制或重初始化。
 * @param[in,out] previous
 *     必需已成功初始化且faults为0的前层混合context；启动排他，复制指针长期借用，不接管。
 * @param[in] resources
 *     必需四项非NULL的ROOT依赖，复制借用；runtime/database/notifier须与previous的auth同指针，queue须与auth及STAT均不同。
 * @param[in] options
 *     必需显式03worker配置，复制；operation非零且与前层auth四标签及STAT标签互异。
 * @param[in] destroy_attempts
 *     原OS worker清理次数1..16，建议3，不是SQL重试次数或时长。
 *
 * @retval VIREO_OK
 *     固定字段初始化，faults=0；无worker owner、线程创建、attach、DB或回投动作。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需NULL、依赖缺项/配对不符、六标签重复/零、零预算或零次数。
 * @retval VIREO_RESULT_RANGE
 *     destroy次数>16、pool等待>60000ms或任一03已有预算硬限超出。
 * @retval VIREO_RESULT_BUSY
 *     前层auth或STAT已锁存故障，拒绝发布新的混合context。
 * @retval VIREO_RESULT_INTERNAL
 *     本平台atomic_uint非lock-free。
 *
 * @note 启动排他、禁POSIX取消，保持errno；局部原子探针检查成功后才写runtime。
 *     地址独立有效不重叠资源/输入/errno，不拥有依赖，无独立destroy；join后结束存储寿命。
 *     验证形态不证明资源存活/SQL成功/queue未满，caller仍负责原公开前置和安全发布。
 */
vireo_result_t vireo_directory_root_worker_runtime_init(vireo_directory_root_worker_runtime_t *runtime,
    vireo_directory_stat_worker_runtime_t *previous, vireo_directory_root_worker_resources_t const *resources,
    vireo_directory_root_worker_options_t const *options, size_t destroy_attempts);

/**
 * @brief 非等待采样认证、STAT与ROOT永久故障位，供Reactor每轮前后判断
 *
 * @param[in] runtime
 *     必需已安全发布的存活context及前层/原auth，借至返回，不可并发重初始化或结束寿命。
 * @param[out] out
 *     必需独立对齐值，成功覆盖三个位集合，失败整个对象保持。
 *
 * @retval VIREO_OK
 *     已取得三个独立relaxed样本；全零不证明其他callback没有正在产生故障。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需NULL，out保持。
 * @return 前层inspect意外错误透传，out保持。
 *
 * @note 允许多worker与单Reactor并发，只有faults为共享可变原子，保持errno，无申请/I/O/等待。
 *     caller每轮前后检查，poll正等待≤1000ms；不是故障检测硬时延保证，也不唤醒满队列。
 */
vireo_result_t vireo_directory_root_worker_runtime_inspect_faults(
    vireo_directory_root_worker_runtime_t const *runtime, vireo_directory_root_worker_faults_t *out);

/**
 * @brief 在固定池当前OS worker按唯一operation路由认证/STAT或一次ROOT，完成原线程清理
 *
 * @param[in,out] context
 *     必需存活混合runtime，由pool配置借用，活到全部callback返回、join及pool销毁。
 * @param[in] task
 *     必需pool短借拥有型task，本函数不保存/修改/移动/销毁；正常返回后由pool销毁。
 *
 * @retval VIREO_OK
 *     被选业务run及本层清理均成功；只表示内部执行，不保证业务响应已到客户端。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需NULL，不能推导故障已锁存。
 * @retval VIREO_RESULT_CANCELLED
 *     入口任一故障非零，跳过业务且不回投；全服务清退负责其inflight。
 * @retval VIREO_RESULT_PROTOCOL
 *     不是六个注册标签之一，锁存DISPATCH，不尝试另一decoder或SQL。
 * @return task inspect原错透传并锁存DISPATCH；前层认证/STAT callback结果透传；ROOT保create/run
 *     首错，否则destroy首错。非OK与业务拒绝/交接/owner是否消费分别判断。
 *
 * @note 先检查三域faults，再inspect并只按metadata.operation分发；不按magic猜格式。
 *     四认证及STAT分支原样调用前层STAT混合runtime；ROOT create一次/run至多一次，再原OS worker
 *     至多destroy_attempts次，仅owner仍非NULL才调用。已在执行的并发callback可自然完成。
 * @note TASK前置失败；外层publication_blocked_by_cleanup、实际cleanup非OK/pending，或
 *     service work_error.cleanup_result非OK/repository.cleanup_pending均锁存相应CLEANUP；
 *     未publish、publish非OK或未transferred锁存PUBLISH，通知失败已交接也不重投。
 *     destroy非OK/owner仍在/实际cleanup失败同样永久锁存CLEANUP。
 *     业务NOT_FOUND/UNAUTHORIZED及普通TIMEOUT/BUSY/SQL失败若清理和回投完整，不单独锁存。
 * @note destroy次数耗尽仍有owner：先OR RESIDUAL，然后应用层_Exit(EXIT_FAILURE)，不返回，
 *     不跨线程释放、不调用pthread_exit/longjmp、不重新SQL/回投，也不运行atexit/stdio flush。
 *     全调用POSIX取消禁用，正常返回保持errno；可阻塞DB/pool/队列，次数有限不保证时长有限。
 * @note 任一故障由app原放弃型协议扩为四队列：停止accept/提交并stop客户，独立确认task、
 *     auth completion、STAT completion、ROOT completion关闭成功再join，join后无条件drain三完成队列及取消task，
 *     清退inflight/镜像/连接后逆序销毁。未确认close/未join/残留不能安全释放时沿既有fatal退出。
 */
vireo_result_t vireo_directory_root_worker_runtime_execute(void *context, vireo_task_t const *task);
#endif
