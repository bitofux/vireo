/*
 * PROJECT : VIREO
 * FILE    : task_cancel.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-11
 * BRIEF   : 独立协作取消状态与共享强引用合同
 */

#ifndef VIREO_THREAD_TASK_CANCEL_H
#define VIREO_THREAD_TASK_CANCEL_H

#include <vireo/base/result.h>

#include <stdbool.h>
#include <stddef.h>

/**
 * @brief
 *     单个固定取消状态的申请字节上限，不含分配器开销或 RSS。
 */
#define VIREO_TASK_CANCEL_MAX_ALLOCATION_BYTES ((size_t)67108864)

/**
 * @brief
 *     永久取消标志的共享对象，每个 owner 持有一份强引用。
 *
 * @note
 *     创建初始一份引用，retain 新增一份；普通指针复制不增加引用。
 *     每次操作必须保留本份存活引用，不能从悬空或弱别名复活。
 * @note
 *     不同已持引用可并发操作；同一 owner 存储和跨线程发布由 caller 同步。
 *     不能同时使用和销毁本份引用，原子字段不保护任意非法指针。
 * @note
 *     不承诺 lock-free、公平或硬实时，不发布其他业务数据。
 *     不保活 task/客户，不执行业务取消、回滚、等待或强制线程中止。
 */
typedef struct vireo_task_cancel vireo_task_cancel_t;

/**
 * @brief
 *     创建初始未取消状态，完整初始化后发布一份强引用。
 *
 * @param[in] allocation_budget
 *     显式正字节预算，至多 MAX_ALLOCATION_BYTES，只计固定控制块请求量。
 * @param[out] out_cancel
 *     必需合法空 owner 地址，只借至返回，不保存，不与对象或 errno 重叠。
 *
 * @retval VIREO_OK
 *     输出获得一份引用，初始 requested=false。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     地址 NULL、输出非空或预算为零，整个输出保持。
 * @retval VIREO_RESULT_RANGE
 *     预算超限或不足以申请固定控制块，输出保持。
 * @retval VIREO_RESULT_NO_MEMORY
 *     申请失败，输出保持，无待释放残留。
 *
 * @note
 *     不设默认预算；不包含其他状态、引用或进程总量，不保证申请成功或非阻塞。
 * @note
 *     输出独占访问，成功后跨线程发布由 caller 同步；所有路径保持 errno。
 */
vireo_result_t vireo_task_cancel_create(size_t allocation_budget,
                                        vireo_task_cancel_t **out_cancel);

/**
 * @brief
 *     从已持有引用新增一份强引用，共享原取消标志，不复制或申请状态。
 *
 * @param[in] cancel
 *     必需、存活且本次调用期间受已有强引用保护的对象。
 * @param[out] out_cancel
 *     必需合法空 owner 地址，独占写入，不与对象/其他 owner/errno 重叠。
 *
 * @retval VIREO_OK
 *     原引用不消耗，输出取得同一对象的一份新增引用，包括已取消状态。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址 NULL 或输出非空，整个输出与本调用引用义务保持。
 * @retval VIREO_RESULT_OVERFLOW
 *     uint64 引用数已为最大值，不回绕、不增加引用，输出保持。
 *
 * @note
 *     与其他持有者操作 thread-safe；本份引用寿命与输出存储由 caller 保证。
 *     失败不冻结其他持有者的合法变化；不承诺等待上界，所有路径保持 errno。
 */
vireo_result_t vireo_task_cancel_retain(vireo_task_cancel_t *cancel,
                                        vireo_task_cancel_t **out_cancel);

/**
 * @brief
 *     永久请求协作取消，标志只能从 false 变 true。
 *
 * @param[in] cancel
 *     必需、存活且调用期间由本份强引用保护的对象，不消耗引用。
 *
 * @retval VIREO_OK
 *     标志为 true，重复调用同样成功；不证明 worker 已观察或停止。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     对象地址 NULL，不改变本调用资源。
 *
 * @note
 *     thread-safe，无 reset；不强制中断、等待、清理或触发 callback。
 *     与查询竞态时查询可见先前 false；不提供业务数据发布合同。
 * @note
 *     不主动等待 worker，不承诺 lock-free 或硬实时；所有路径保持 errno。
 */
vireo_result_t vireo_task_cancel_request(vireo_task_cancel_t *cancel);

/**
 * @brief
 *     观测取消请求，返回 OK 加 bool，不替使用者决定业务动作。
 *
 * @param[in] cancel
 *     必需、存活且调用期间由本份强引用保护的对象。
 * @param[out] out_requested
 *     必需合法独占 bool 输出，只借至返回，不与对象/owner/errno 重叠。
 *
 * @retval VIREO_OK
 *     完整写入本次观测；true 不表示任务已停止或完成回滚。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址 NULL，整个输出保持。
 *
 * @note
 *     thread-safe；相同观察者已见 true 后不会因 reset 回到 false。
 *     不返回 CANCELLED，不采样时间；所有路径保持 errno。
 */
vireo_result_t vireo_task_cancel_is_requested(vireo_task_cancel_t *cancel,
                                              bool *out_requested);

/**
 * @brief
 *     将一份引用从 source 移到空目标，成功清源，引用总数不变。
 *
 * @param[in,out] source
 *     必需合法 owner 地址，本份引用无在途操作或借用。
 * @param[in,out] destination
 *     必需、不同且合法的空 owner 地址；两个地址均在对象外、不指 errno。
 *
 * @retval VIREO_OK
 *     目标接管本份引用，源为 NULL，不增加或减少引用。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址 NULL、两地址相同或目标非空，两个输出保持。
 * @retval VIREO_RESULT_NOT_FOUND
 *     基本参数合法但源为空，两个输出保持。
 *
 * @note
 *     owner 存储和发布由 caller 同步，其他引用可继续操作共享对象。
 *     无申请、不构成原子交接；所有路径保持 errno。
 */
vireo_result_t vireo_task_cancel_move(vireo_task_cancel_t **source,
                                      vireo_task_cancel_t **destination);

/**
 * @brief
 *     释放本份强引用并清 owner，仅最后一份释放共享状态内存。
 *
 * @param[in,out] owner
 *     必需合法 owner 地址，在对象外、不指 errno；空值允许。
 *     非空时必须拥有一份引用，本份所有操作和借用已结束。
 *
 * @retval VIREO_OK
 *     本份引用释放且 owner=NULL，空值重复调用同样成功。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     owner 地址 NULL，不改变资源。
 *
 * @note
 *     与其他独立引用的操作 thread-safe，不影响其访问权，不自动请求取消。
 *     不清除旧裸指针副本；旧别名失去本份寿命保护，不得继续使用。
 * @note
 *     最后释放配对 free，不等待 worker 或业务清理；所有路径保持 errno。
 */
vireo_result_t vireo_task_cancel_destroy(vireo_task_cancel_t **owner);

#endif /* VIREO_THREAD_TASK_CANCEL_H */
