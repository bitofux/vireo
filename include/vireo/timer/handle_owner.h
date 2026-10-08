/*
 * PROJECT : VIREO
 * FILE    : handle_owner.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-08
 * BRIEF   : 此模块负责：
 * -- 在显式预算内登记固定容量 timer 身份
 * -- 发放、校验与归还非复用三字段句柄
 * -- 空表销毁与受检耗尽收尾
 */
#ifndef VIREO_TIMER_HANDLE_OWNER_H
#define VIREO_TIMER_HANDLE_OWNER_H

#include <vireo/timer/handle.h>

/** 每 owner 固定登记槽硬限，不是时间轮桶数。 */
#define VIREO_TIMER_HANDLE_OWNER_MAX_CAPACITY ((size_t)65536)
/** 控制块与完整登记表的总申请硬限，64 MiB，不是 RSS。 */
#define VIREO_TIMER_HANDLE_OWNER_MAX_MEMORY ((size_t)67108864)

/** 唯一拥有型身份管理对象；布局不公开，全部同对象操作 Reactor-only。 */
typedef struct vireo_timer_handle_owner vireo_timer_handle_owner_t;

/** 创建时短借并按值读取，不保存选项地址，没有默认值。 */
typedef struct vireo_timer_handle_owner_options {
    size_t capacity; /**< 正登记槽数量，不超过 MAX_CAPACITY，创建后固定。 */
    size_t max_memory_bytes; /**< 正总申请字节预算，不超过 MAX_MEMORY。 */
} vireo_timer_handle_owner_options_t;

/** 独立数值快照，无资源指针，不延长 owner 生命期。 */
typedef struct vireo_timer_handle_owner_info {
    uint64_t owner_id; /**< 本库实例进程内非零、不复用的管理身份。 */
    uint64_t last_generation; /**< 最后成功发放序号；从未发放为 0，MAX 时停发。 */
    size_t capacity; /**< 固定登记槽总数。 */
    size_t active_count; /**< 当前尚未归还的身份数量。 */
    size_t available_count; /**< capacity - active_count；耗尽时不保证能取得。 */
    size_t allocation_bytes; /**< 控制块和完整登记表请求字节之和。 */
    size_t max_memory_bytes; /**< 创建时 caller 指定的总申请预算。 */
} vireo_timer_handle_owner_info_t;

/**
 * @brief 在预算内创建空的身份登记 owner，全部成功后发布唯一所有权
 *
 * @param[in] options
 *     非 NULL、存活可读的选项；仅借到返回。
 * @param[in,out] out_owner
 *     独占、有效、对齐可写的拥有者地址，入口 *out_owner 必须为 NULL。
 *
 * @retval VIREO_OK
 *     取得完整空 owner，最终由 destroy 消费。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     参数为 NULL、入口 owner 非空，或任一选项为零。
 * @retval VIREO_RESULT_OVERFLOW
 *     登记表或总量不可表示，或本库实例进程 owner 身份耗尽。
 * @retval VIREO_RESULT_RANGE
 *     容量、预算超过硬限，或可表示的需求超过预算；恰等预算允许。
 * @retval VIREO_RESULT_NO_MEMORY
 *     任一内存申请失败；已经取得的内存逆序释放。
 *
 * @note
 *     顺序：参数→受检申请量→硬限/预算→身份→分配/初始化→发布；失败保持输出。
 * @note
 *     身份：原子发放非零 ID，不回绕、不复用；分配失败可消耗 ID，不撤回。
 * @note
 *     所有权：owner 只拥有本层内存，不含 payload、fd、callback 或业务间接资源。
 * @note
 *     地址：选项和输出独立、不重叠、不指向 errno 存储；输出地址不保存。
 * @note
 *     线程：Reactor-only；不同 Reactor 可独立创建，原子 ID 不同步同 owner 状态。
 * @note
 *     预算：不含分配器开销、页/RSS、全局预算或未来轮节点；无 lock-free/实时保证。
 * @note
 *     errno：所有路径保持入口值，无自动重试；身份非跨进程、持久或安全认证标识。
 */
vireo_result_t vireo_timer_handle_owner_create(vireo_timer_handle_owner_options_t const *options,
                                               vireo_timer_handle_owner_t **out_owner);

/**
 * @brief 读取独立数值快照，不授予内部存储借用
 *
 * @param[in] owner
 *     非 NULL、存活且由其 Reactor 独占的 owner，短借。
 * @param[out] out_info
 *     独立、有效、对齐可写的快照地址，不在 owner 资源内、不指向 errno。
 *
 * @retval VIREO_OK
 *     完整写出七个数值字段。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     任一参数为 NULL；失败保持整个输出对象。
 *
 * @note
 *     所有权：caller 保留输出，地址不保存，快照不延长 owner 生命期。
 * @note
 *     线程与 errno：Reactor-only，包括观测；不读取、保存或修改 errno。
 */
vireo_result_t vireo_timer_handle_owner_inspect(vireo_timer_handle_owner_t const *owner,
                                                vireo_timer_handle_owner_info_t *out_info);

/**
 * @brief 取得一个空闲登记槽并发放新的非零代次，不分配或搬移
 *
 * @param[in,out] owner
 *     非 NULL、存活且 Reactor 独占的 owner，保留所有权。
 * @param[out] out_handle
 *     独立、有效、对齐可写的 handle 地址，不在 owner 资源内、不指向 errno。
 *
 * @retval VIREO_OK
 *     提交一个新活跃三元组，active_count 增一，统一发放序号增一。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     任一参数为 NULL。
 * @retval VIREO_RESULT_OVERFLOW
 *     owner 序号已经为 UINT64_MAX，优先于满表，不回绕或重置。
 * @retval VIREO_RESULT_BUSY
 *     序号仍可用但没有空闲登记槽。
 *
 * @note
 *     输出：失败保持全部输出字节及 owner 状态；成功覆盖，caller 须保留未归还身份记录。
 * @note
 *     身份：owner_id 与 generation 非零，slot_index 小于 capacity；不承诺选择哪一空闲槽。
 * @note
 *     借用：只借输出地址到返回，不保存、不返回指针；句柄复制不新增资源或权限。
 * @note
 *     线程与 errno：Reactor-only；不读取、保存或修改 errno，无分配、I/O 或时间采样。
 */
vireo_result_t vireo_timer_handle_owner_acquire(vireo_timer_handle_owner_t *owner,
                                                vireo_timer_handle_t *out_handle);

/**
 * @brief 只校验三元组是否为此 owner 当前活跃登记，不执行 timer 动作
 *
 * @param[in] owner
 *     非 NULL、仍存活且 Reactor 独占的目标 owner，短借。
 * @param[in] handle
 *     已初始化的按值句柄；数值复制不延长 owner 生命期。
 *
 * @retval VIREO_OK
 *     身份匹配、槽在范围且活跃、代次为当前值。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     owner 为 NULL、句柄畸形或属于不同 owner。
 * @retval VIREO_RESULT_RANGE
 *     相同 owner 身份下 slot_index 不小于 capacity。
 * @retval VIREO_RESULT_NOT_FOUND
 *     全零句柄，或槽空闲，或 generation 不匹配。
 *
 * @note
 *     顺序：owner 地址→形态/全零→owner 身份→槽范围→活跃/代次；先数值检查再索引。
 * @note
 *     边界：无资源借用、权限认证或业务清理，成功不保证未来调用时仍活跃。
 * @note
 *     线程与 errno：Reactor-only；只读、不读取或修改 errno，无分配或 I/O。
 */
vireo_result_t vireo_timer_handle_owner_validate(vireo_timer_handle_owner_t const *owner,
                                                 vireo_timer_handle_t handle);

/**
 * @brief 归还匹配登记并清空传入句柄，全部该身份副本随之失效
 *
 * @param[in,out] owner
 *     非 NULL、存活且 Reactor 独占的 owner，保留所有权。
 * @param[in,out] handle
 *     独立、存活、对齐可写的句柄地址，不在 owner 资源内、不指向 errno。
 *
 * @retval VIREO_OK
 *     归还一次，active_count 减一，将传入句柄的三个逻辑字段清零。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     参数为 NULL、句柄畸形或跨 owner。
 * @retval VIREO_RESULT_RANGE
 *     相同 owner 身份下槽越界。
 * @retval VIREO_RESULT_NOT_FOUND
 *     全零、已归还或旧代次；不是幂等成功。
 *
 * @note
 *     输出：失败保持整个句柄和 owner 状态；成功不承诺 padding 清零。
 * @note
 *     生命周期：不关闭 fd、清理业务对象或解除轮节点；使用者先协调相关动作再归还身份。
 * @note
 *     借用：仅借到返回，不保存地址；其余副本数值不变，但不再通过活跃校验。
 * @note
 *     线程与 errno：Reactor-only；不读取、保存或修改 errno，无分配或 I/O。
 */
vireo_result_t vireo_timer_handle_owner_release(vireo_timer_handle_owner_t *owner,
                                                vireo_timer_handle_t *handle);

/**
 * @brief 释放空 owner 的自有内存，消费并清空唯一拥有者
 *
 * @param[in,out] owner
 *     独占、有效、对齐可写的拥有者地址，不在自有资源内、不指向 errno；*owner 可为 NULL。
 *
 * @retval VIREO_OK
 *     已销毁空 owner 并清 NULL，或入口为空的成功空操作。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     owner 地址为 NULL。
 * @retval VIREO_RESULT_BUSY
 *     存在未归还登记，保持拥有者、资源及全部状态。
 *
 * @note
 *     生命周期：调用者先停止同 owner 操作并归还全部身份；所有旧 owner 指针别名失效。
 * @note
 *     线程与 errno：Reactor-only；所有路径保持 errno，不自动取消或回调，不提供安全擦除。
 */
vireo_result_t vireo_timer_handle_owner_destroy(vireo_timer_handle_owner_t **owner);

#endif /* VIREO_TIMER_HANDLE_OWNER_H */
