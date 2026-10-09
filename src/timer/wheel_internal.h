/*
 * PROJECT : VIREO
 * FILE    : wheel_internal.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-09
 * BRIEF   : 此模块负责：
 * -- 定义本层真实 dummy 桶与轮资源布局
 * -- 提供仅供本层测试的成对分配注入入口
 */
#ifndef VIREO_TIMER_WHEEL_INTERNAL_H
#define VIREO_TIMER_WHEEL_INTERNAL_H

#include <vireo/timer/wheel.h>
#include <vireo/timer/wheel_registry.h>
#include <vireo/timer/wheel_advance.h>
#include <vireo/timer/wheel_shutdown.h>
#include <vireo/timer/handle_owner.h>

/** 双向循环链接；桶数组元素是永久 dummy，节点内链接是真实 timer 成员。 */
typedef struct vireo_timer_wheel_link {
    struct vireo_timer_wheel_link *prev; /**< 环内前邻；dummy 空桶或空闲节点指向自己。 */
    struct vireo_timer_wheel_link *next; /**< 环内后邻；dummy 空桶或空闲节点指向自己。 */
} vireo_timer_wheel_link_t;

/** 本层成对分配策略，不能成为其他模块合同。 */
typedef struct vireo_timer_wheel_allocator {
    void *(*allocate)(size_t bytes, void *context); /**< 成功返回至少 bytes 字节、正确对齐的独占可写内存，NULL 失败。 */
    void (*deallocate)(void *memory, void *context); /**< 消费对应申请，不报告失败。 */
    void *context; /**< 仅借用至 destroy；不得处于轮自有资源内，生产 NULL。 */
} vireo_timer_wheel_allocator_t;

/** 固定 timer 节点，与公开 owner 的登记槽对应，不保存业务借用。 */
typedef struct vireo_timer_wheel_node {
    vireo_timer_wheel_link_t link; /**< 首成员；活跃时在桶/pending/ready之一，空闲时自环。 */
    vireo_timer_handle_t handle; /**< 活跃三元组，空闲时三字段全零。 */
    vireo_monotonic_ns_t deadline_ns; /**< 原 ns 期限，空闲时 0 仅作元数据初值。 */
    vireo_timer_wheel_tick_t due_tick; /**< 量化累计刻度，不是 generation 或 rounds。 */
    size_t bucket_index; /**< 数学桶索引，始终小于轮 bucket_count，非当前链归属。 */
    bool ready; /**< 是否已发现且在 ready 环；pending/普通桶/空闲为 false。 */
} vireo_timer_wheel_node_t;

struct vireo_timer_wheel {
    vireo_timer_wheel_geometry_t geometry; /**< 创建时按值保存的合法几何。 */
    vireo_timer_wheel_link_t *buckets; /**< 拥有固定 dummy 数组，每个头地址至 destroy 不变。 */
    size_t bucket_count; /**< 受检转换后的真实数组数量，与 geometry.bucket_count 等值。 */
    size_t allocation_bytes; /**< sizeof 控制块加完整桶数组的受检总请求字节。 */
    size_t max_memory_bytes; /**< 本轮创建时正预算。 */
    vireo_timer_wheel_allocator_t allocator; /**< 按值保存成对释放策略；context 不拥有。 */
    vireo_timer_handle_owner_t *owner; /**< prepare 后拥有 opaque 身份表，仅走 public API；NULL 未准备。 */
    vireo_timer_wheel_node_t *nodes; /**< prepare 后拥有固定节点表，不返回内部借用。 */
    size_t timer_capacity; /**< 固定节点数量，与 public owner 容量一致，不是桶数。 */
    size_t node_bytes; /**< 受检节点表请求字节，不含基础轮或 owner。 */
    size_t registry_budget; /**< 独立登记请求预算，包含节点表和 public owner。 */
    vireo_timer_wheel_link_t pending; /**< 内嵌 dummy；正在访问桶的未检查快照。 */
    vireo_timer_wheel_link_t ready; /**< 内嵌 dummy；已发现但仍活跃的通知。 */
    vireo_monotonic_ns_t latest_now_ns; /**< 最近成功 advance 的 now，初始 origin。 */
    vireo_timer_wheel_tick_t completed_tick; /**< 已完全检查刻度，初始 0，不回绕。 */
    bool processing; /**< 是否正在检查 completed_tick+1，不持久保存节点指针。 */
    size_t ready_count; /**< ready 环节点数，不超过 public owner 活跃数/容量。 */
    bool stopping; /**< 初始 false，begin 后永久 true，拒绝新登记/重排/推进。 */
    size_t shutdown_cursor; /**< 下一待扫描物理登记槽，初始 0，0..capacity，非时间游标。 */
};

/**
 * @brief 放置已摘下、自环且活跃的节点，无申请或可失败操作
 *
 * @param[in,out] wheel
 *     合法轮，owner 已活跃登记且节点数受容量约束。
 * @param[in,out] node
 *     已写完受检期限、刻度、桶，ready=false；不与轮控制重叠。
 *
 * @note
 *     due 不晚于 completed/正在访问刻度即入 ready，否则入数学桶。
 * @note
 *     只本层共享；不会推进游标，ready_count 加法由容量不变量保证可表示。
 */
void vireo_timer_wheel_place_node(vireo_timer_wheel_t *wheel, vireo_timer_wheel_node_t *node);

/** 本层隔离 factory：成功须返回按原 options public 创建的真实空 owner。 */
typedef vireo_result_t (*vireo_timer_wheel_owner_create_fn)(
    vireo_timer_handle_owner_options_t const *, vireo_timer_handle_owner_t **, void *);
/** 本层隔离 acquire：成功须经 public acquire，不篡改输出；失败保持 owner/output。 */
typedef vireo_result_t (*vireo_timer_wheel_owner_acquire_fn)(
    vireo_timer_handle_owner_t *, vireo_timer_handle_t *, void *);
/** 本层隔离 release：沿 public 归还/失败保持合同，不重入或操作轮链接。 */
typedef vireo_result_t (*vireo_timer_wheel_owner_release_fn)(
    vireo_timer_handle_owner_t *, vireo_timer_handle_t *, void *);

/** 三个入口仅 own 测试；函数须非 NULL，context 只借至返回，不保存，不是生产业务回调。 */
vireo_result_t vireo_timer_wheel_prepare_runtime(
    vireo_timer_wheel_t *wheel, vireo_timer_wheel_registry_options_t const *options,
    vireo_timer_wheel_owner_create_fn create_owner, void *context);
vireo_result_t vireo_timer_wheel_register_runtime(
    vireo_timer_wheel_t *wheel, vireo_monotonic_ns_t now_ns, vireo_monotonic_ns_t deadline_ns,
    vireo_timer_handle_t *out_handle, vireo_timer_wheel_owner_acquire_fn acquire, void *context);
vireo_result_t vireo_timer_wheel_cancel_runtime(
    vireo_timer_wheel_t *wheel, vireo_timer_handle_t *handle,
    vireo_timer_wheel_owner_release_fn release, void *context);
/** own 测试借用 release/context，沿 cancel_runtime 的失败保持合同，不保存。 */
vireo_result_t vireo_timer_wheel_take_expired_runtime(
    vireo_timer_wheel_t *wheel, vireo_timer_wheel_expired_t *out_expired,
    vireo_timer_wheel_owner_release_fn release, void *context);
/** own 测试短借 release/context，失败保持 owner/handle，不重入或操作轮链接。 */
vireo_result_t vireo_timer_wheel_shutdown_step_runtime(
    vireo_timer_wheel_t *wheel, size_t max_slots, vireo_timer_wheel_shutdown_report_t *out_report,
    vireo_timer_wheel_owner_release_fn release, void *context);

/**
 * @brief 采用隔离 allocator 执行同一构造路径，非公共 API
 *
 * @param[in] options
 *     遵守公共 create 合同。
 * @param[in,out] out_wheel
 *     遵守公共 create 的入口空拥有者合同。
 * @param[in] allocator
 *     非空、两个函数非空；按值保存，借用 context 必须存活至 destroy。
 *
 * @retval VIREO_OK
 *     完整发布初始化轮。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     公共参数或额外分配策略非法。
 * @retval VIREO_RESULT_RANGE
 *     受检窄化、硬限或预算不满足。
 * @retval VIREO_RESULT_OVERFLOW
 *     申请量不可表示。
 * @retval VIREO_RESULT_NO_MEMORY
 *     申请失败并逆序回滚。
 *
 * @note
 *     策略不得修改借用 options/output，申请与释放不能操作其他轮或发布半成品。
 * @note
 *     输出、errno、生命周期、线程沿 public create；fault 不冒真实系统 OOM。
 */
vireo_result_t vireo_timer_wheel_create_runtime(vireo_timer_wheel_options_t const *options,
                                               vireo_timer_wheel_t **out_wheel,
                                               vireo_timer_wheel_allocator_t const *allocator);

#endif /* VIREO_TIMER_WHEEL_INTERNAL_H */
