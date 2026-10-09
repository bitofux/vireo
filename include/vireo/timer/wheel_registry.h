/*
 * PROJECT : VIREO
 * FILE    : wheel_registry.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-09
 * BRIEF   : 此模块负责：
 * -- 准备独立预算内的固定真实定时器登记资源
 * -- 将身份和期限链接到固定 dummy 时间桶
 * -- 查询、取消与显式重排，不推进或执行到期
 */
#ifndef VIREO_TIMER_WHEEL_REGISTRY_H
#define VIREO_TIMER_WHEEL_REGISTRY_H

#include <vireo/timer/wheel.h>
#include <vireo/timer/handle.h>

/** 最大活跃定时器容量，不是桶数或默认值。 */
#define VIREO_TIMER_WHEEL_REGISTRY_MAX_CAPACITY ((size_t)65536)
/** 节点表和身份 owner 的独立总请求预算硬限，不包含基础轮申请。 */
#define VIREO_TIMER_WHEEL_REGISTRY_MAX_MEMORY ((size_t)67108864)

/** 一次性准备的显式参数，不保存 caller 的选项地址。 */
typedef struct vireo_timer_wheel_registry_options {
    size_t capacity; /**< 正固定 timer 槽数，至销毁不变，不是桶数。 */
    size_t max_memory_bytes; /**< 正登记请求预算，包含完整节点表和身份 owner。 */
} vireo_timer_wheel_registry_options_t;

/** 独立数值快照，不返回内部资源、不保活轮。 */
typedef struct vireo_timer_wheel_registry_info {
    bool prepared; /**< 是否已经成功准备，未准备时其余五字段为 0。 */
    size_t capacity; /**< 固定 timer 总槽数。 */
    size_t active_count; /**< 尚未取消或领取的登记数，已发现项仍占用。 */
    size_t available_count; /**< capacity - active_count；身份耗尽时不保证可再登记。 */
    size_t allocation_bytes; /**< 完整节点表与公开 owner 实际请求之和，不含基础轮。 */
    size_t max_memory_bytes; /**< 一次 prepare 的显式登记预算，不是 RSS。 */
} vireo_timer_wheel_registry_info_t;

/** 一个当前登记的数值快照，无业务借用、资源或轮内地址。 */
typedef struct vireo_timer_wheel_timer_info {
    vireo_monotonic_ns_t deadline_ns; /**< caller 指定的原纳秒 deadline。 */
    vireo_timer_wheel_tick_t due_tick; /**< 受检向上量化的累计刻度，不是 generation。 */
    uint64_t bucket_index; /**< 数学桶位置，0..桶数-1，不是 handle.slot_index。 */
} vireo_timer_wheel_timer_info_t;

/**
 * @brief 一次性准备固定 timer 节点和身份 owner
 *
 * @param[in,out] wheel
 *     非空、存活的本层轮，所属 Reactor 独占，保留唯一所有权。
 * @param[in] options
 *     非空、存活、对齐可读参数；capacity 和预算均正，不设默认。
 *
 * @retval VIREO_OK
 *     完整提交空登记资源，之后登记、查询、取消与重排不分配节点。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址 NULL，或任一选项为 0。
 * @retval VIREO_RESULT_BUSY
 *     此轮已经准备；不扩容、重置 owner 或重新准备。
 * @retval VIREO_RESULT_OVERFLOW
 *     节点申请量不可表示，或身份 owner 创建耗尽；算术先于硬限。
 * @retval VIREO_RESULT_RANGE
 *     容量、登记预算超硬限，或完整节点与 owner 请求不能满足预算。
 * @retval VIREO_RESULT_NO_MEMORY
 *     节点或 owner 申请失败，临时资源回滚。
 *
 * @note
 *     先参数、准备状态、受检节点量和限额，再申请初始化节点，以剩余预算创建 owner。
 * @note
 *     失败保持原轮；失败创建 owner 可消耗非复用 ID，不撤回。所有路径保持入口 errno。
 * @note
 *     登记预算只节点表和 owner；基础 create 预算仍控制块和桶，不含 allocator 开销/RSS。
 * @note
 *     地址只短借至返回，独立不重叠、不在轮资源内、不指 errno；不保存业务指针或回调。
 * @note
 *     Reactor-only，初始化 O(capacity)，申请无硬实时保证；不采样或推进时间。
 */
vireo_result_t vireo_timer_wheel_prepare(vireo_timer_wheel_t *wheel,
                                        vireo_timer_wheel_registry_options_t const *options);

/**
 * @brief 观测登记资源数值，不查询实际到期或返回内部指针
 *
 * @param[in] wheel
 *     非空、存活的轮，所属 Reactor 独占。
 * @param[out] out_info
 *     非空、存活、对齐可写快照，不在轮资源内、不与轮重叠、不指 errno。
 *
 * @retval VIREO_OK
 *     写六个逻辑字段；未准备也成功，prepared=false，其余为 0。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址 NULL。
 * @retval VIREO_RESULT_OVERFLOW
 *     受检请求总量不可表示；合法已准备资源受预算保证不会到此边界。
 *
 * @note
 *     失败整个输出保持；只短借地址、不保活，不承诺 padding，所有路径保持 errno。
 * @note
 *     同轮 Reactor-only；只读 public owner 数值，不读取时钟或自动注销过期项。
 */
vireo_result_t vireo_timer_wheel_registry_inspect(vireo_timer_wheel_t const *wheel,
                                                 vireo_timer_wheel_registry_info_t *out_info);

/**
 * @brief 取得非复用身份并登记一个未来期限，链接到 dummy 桶
 *
 * @param[in,out] wheel
 *     非空、存活、已 prepare 的轮，所属 Reactor 独占。
 * @param[in] now_ns
 *     caller 提供的同域新鲜单调 ns，必须不小于 origin；不隐式采样。
 * @param[in] deadline_ns
 *     同域有限 ns，必须严格大于 now；不代表无限或默认值。
 * @param[in,out] out_handle
 *     非空、存活、对齐可写地址，入口三个字段必须全零，不在轮资源内、不指 errno。
 *
 * @retval VIREO_OK
 *     完整登记并发布活跃 handle，保存原 deadline 和向上量化 due_tick。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址 NULL，或输出不是全零；参数先于准备和时间判断。
 * @retval VIREO_RESULT_NOT_FOUND
 *     此轮未 prepare。
 * @retval VIREO_RESULT_RANGE
 *     now 小于 origin。
 * @retval VIREO_RESULT_TIMEOUT
 *     deadline 不大于 now，不登记或执行到期动作。
 * @retval VIREO_RESULT_OVERFLOW
 *     量化边界不可表示，或 owner 发序耗尽；后者优先于满表 BUSY。
 * @retval VIREO_RESULT_BUSY
 *     期限合法、发序未耗尽，但登记表已满。
 * @retval VIREO_RESULT_CANCELLED
 *     已 begin 停止；原基本参数/准备检查之后、时间与发序检查之前拒绝。
 *
 * @note
 *     失败整个输出和登记保持，所有路径保持 errno；成功不承诺 padding 或桶内顺序。
 * @note
 *     handle 是数值身份，不认证权限、不保活轮；caller 保留尚未取消或领取的记录。
 * @note
 *     若 due 不晚于已完成/正在访问刻度，直接成为待领取项；其余进入数学桶。
 * @note
 *     按值时间输入、短借输出；同轮 Reactor-only，无节点分配/I/O/回调或游标变更。
 */
vireo_result_t vireo_timer_wheel_register(vireo_timer_wheel_t *wheel,
                                         vireo_monotonic_ns_t now_ns,
                                         vireo_monotonic_ns_t deadline_ns,
                                         vireo_timer_handle_t *out_handle);

/**
 * @brief 根据当前身份读取原期限、量化刻度和桶位置
 *
 * @param[in] wheel
 *     非空、存活的轮，所属 Reactor 独占。
 * @param[in] handle
 *     已初始化的值句柄，复制不保活，不保证未来一直活跃。
 * @param[out] out_info
 *     非空、存活、对齐可写的独立快照，不在轮资源内、不指 errno。
 *
 * @retval VIREO_OK
 *     完整写三个逻辑字段；过了 deadline 也不自动失效或返回 TIMEOUT。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址 NULL、句柄畸形，或已准备轮的跨 owner 身份。
 * @retval VIREO_RESULT_RANGE
 *     已准备且同 owner 的槽号越界。
 * @retval VIREO_RESULT_NOT_FOUND
 *     未准备、全零、已取消或旧代次。
 *
 * @note
 *     先地址、形态、准备状态，再沿 owner 身份/槽范围/活跃代次校验，不先索引节点。
 * @note
 *     失败整个输出保持、成功不承诺 padding；快照无内部借用，地址只短借。
 * @note
 *     Reactor-only，不采样/执行到期，无分配/I/O，所有路径保持 errno。
 */
vireo_result_t vireo_timer_wheel_get(vireo_timer_wheel_t const *wheel,
                                    vireo_timer_handle_t handle,
                                    vireo_timer_wheel_timer_info_t *out_info);

/**
 * @brief 摘下当前节点、归还身份并清空传入句柄
 *
 * @param[in,out] wheel
 *     非空、存活的轮，所属 Reactor 独占，保留所有权。
 * @param[in,out] handle
 *     非空、存活、对齐可写的独立句柄地址，不在轮资源内、不指 errno。
 *
 * @retval VIREO_OK
 *     取消一次，清三个逻辑字段；所有原身份副本失效，不承诺 padding。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址 NULL、句柄畸形，或已准备轮的跨 owner。
 * @retval VIREO_RESULT_RANGE
 *     已准备且同 owner 的槽越界。
 * @retval VIREO_RESULT_NOT_FOUND
 *     未准备、全零、已取消或旧代次；不是重复成功。
 *
 * @note
 *     先校验、保存原邻位、摘链，再归还局部句柄；归还失败恢复原链位和全部登记。
 * @note
 *     失败整个输出保持，短借至返回；同轮独占且不重入，所有路径保持 errno。
 * @note
 *     无分配/I/O/回调/业务清理；不依赖 now，不自动延长或执行到期动作。
 */
vireo_result_t vireo_timer_wheel_cancel(vireo_timer_wheel_t *wheel,
                                       vireo_timer_handle_t *handle);

/**
 * @brief 显式替换当前登记期限和桶位置，保持原 handle
 *
 * @param[in,out] wheel
 *     非空、存活的轮，所属 Reactor 独占。
 * @param[in] handle
 *     当前活跃值句柄，重排不发新代次，所有该身份副本仍有效。
 * @param[in] now_ns
 *     显式同域新鲜 ns，不小于 origin；不采样或检测跨调用时间后退。
 * @param[in] deadline_ns
 *     新同域有限 ns，严格大于 now；由 caller 决定业务是否允许改变期限。
 *
 * @retval VIREO_OK
 *     替换原期限/量化刻度/桶位置，不改变 owner 发序或活跃数量。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     wheel NULL、畸形或已准备轮的跨 owner。
 * @retval VIREO_RESULT_NOT_FOUND
 *     未准备、全零、已取消或旧代次。
 * @retval VIREO_RESULT_RANGE
 *     同 owner 槽越界，或有效身份下 now 小于 origin。
 * @retval VIREO_RESULT_TIMEOUT
 *     有效身份下新 deadline 不大于 now。
 * @retval VIREO_RESULT_OVERFLOW
 *     新期限的量化边界不可表示。
 * @retval VIREO_RESULT_CANCELLED
 *     已 begin 停止；原身份校验之后、时间检查之前拒绝。
 *
 * @note
 *     身份校验先于时间；全部受检计算完成后才摘旧/插新，失败原期限和精确链位保持。
 * @note
 *     原期限已过不自动失效；本调用不规定空闲刷新或请求总 deadline 延长政策。
 * @note
 *     已发现项重排到未来会撤销原待领取通知，身份不变；新 due 不晚于访问前沿则直接待领取。
 * @note
 *     不承诺桶内顺序；Reactor-only，无分配/I/O/回调/游标推进，所有路径保持 errno。
 */
vireo_result_t vireo_timer_wheel_rearm(vireo_timer_wheel_t *wheel,
                                      vireo_timer_handle_t handle,
                                      vireo_monotonic_ns_t now_ns,
                                      vireo_monotonic_ns_t deadline_ns);

#endif /* VIREO_TIMER_WHEEL_REGISTRY_H */
