/*
 * PROJECT : VIREO
 * FILE    : task.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-11
 * BRIEF   : 独立 task 输入、数值路由与可选协作取消引用
 */

#ifndef VIREO_THREAD_TASK_H
#define VIREO_THREAD_TASK_H

#include <vireo/base/result.h>
#include <vireo/thread/task_cancel.h>

#include <stddef.h>
#include <stdint.h>

/**
 * @brief
 *     客户相关工作使用的数值路由快照。
 *
 * @note
 *     形态：四字段全零为空；非空 owner、generation、sequence 必须非零，
 *     slot 可取 0..SIZE_MAX；其余组合畸形。所有字段均无时间单位。
 * @note
 *     边界：不认证来源、容量、当前性或请求唯一性，不保活客户。
 *     不含指针或 fd，不是线协议格式，结构 padding 与 ABI 不作承诺。
 * @note
 *     同步：普通值复制不构成跨线程发布；共享存储与发布由调用者同步。
 */
typedef struct vireo_task_route {
    uint64_t client_owner_id; /**< 客户拥有域的数值身份，非空时 1..UINT64_MAX。 */
    size_t client_slot_index; /**< 客户槽数值，0..SIZE_MAX，不是 task queue 游标。 */
    uint64_t client_generation; /**< 客户槽代际快照，非空时 1..UINT64_MAX。 */
    uint32_t request_sequence; /**< 请求标签，非空时 1..UINT32_MAX，不保证唯一。 */
} vireo_task_route_t;

/**
 * @brief
 *     构造正常非空路由，只复制数值，不查询客户。
 *
 * @param[in] client_owner_id
 *     非零客户拥有域身份，来源真实性由调用者保证。
 * @param[in] client_slot_index
 *     客户槽数值，允许 0 与 SIZE_MAX，不核验实际容量。
 * @param[in] client_generation
 *     非零客户代际，不发放或核验当前代际。
 * @param[in] request_sequence
 *     非零请求标签；此限制仅针对本路由，不改变全局线协议规则。
 * @param[out] out_route
 *     必需、存活、正确对齐且可写的独占输出；只借至返回，不保存地址。
 *
 * @retval VIREO_OK
 *     完整发布四个逻辑字段，成功不保证 padding 内容。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     输出 NULL（优先），或 owner、generation、sequence 任一为零。
 *     失败保持整个输出对象，包括已有 padding 字节。
 *
 * @note
 *     无资源、阻塞或短进度，不保活、不自动重试；输出可为按值输入的原存储。
 * @note
 *     独立输出 thread-safe，同一输出访问由调用者同步；不得以 errno 为输出。
 * @note
 *     不读取、保存或修改 errno，所有路径保持入口 errno。
 */
vireo_result_t vireo_task_route_make(uint64_t client_owner_id, size_t client_slot_index,
                                     uint64_t client_generation, uint32_t request_sequence,
                                     vireo_task_route_t *out_route);

/**
 * @brief
 *     判断合法路由是否逻辑全零，不查询外部资源。
 *
 * @param[in] route
 *     已初始化的按值路由，允许逻辑空值。
 * @param[out] out_empty
 *     必需、存活、正确对齐且可写的独占 bool 输出，只借至返回，不保存。
 *
 * @retval VIREO_OK
 *     空值写 true，正常非空写 false；结果不表示客户活跃性。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     输出 NULL（优先）或路由畸形，整个输出保持。
 *
 * @note
 *     无资源或阻塞；独立输出 thread-safe，同一输出访问由调用者同步。
 * @note
 *     输出不得指向 errno；不读取、保存或修改 errno，所有路径保持入口值。
 */
vireo_result_t vireo_task_route_is_empty(vireo_task_route_t route, bool *out_empty);

/**
 * @brief
 *     逐逻辑字段比较两个合法路由，不比较 padding。
 *
 * @param[in] left
 *     已初始化的左侧按值路由，允许逻辑空值。
 * @param[in] right
 *     已初始化的右侧按值路由，允许逻辑空值。
 * @param[out] out_equal
 *     必需、存活、正确对齐且可写的独占 bool 输出，只借至返回，不保存。
 *
 * @retval VIREO_OK
 *     写入四字段相等结果，两个空值相等。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     输出 NULL（优先）或任一路由畸形，整个输出保持。
 *
 * @note
 *     相等仅是数值关系，不认证来源、当前性、请求唯一性或授权。
 * @note
 *     无资源或阻塞；独立输出 thread-safe，同一输出访问由调用者同步。
 * @note
 *     输出不得指向 errno；不读取、保存或修改 errno，所有路径保持入口值。
 */
vireo_result_t vireo_task_route_equal(vireo_task_route_t left, vireo_task_route_t right,
                                      bool *out_equal);

/**
 * @brief
 *     客户相关请求的独立工作描述，不持有输入 payload 或客户资源。
 *
 * @note
 *     有效形态：route 正常非空，实例号和操作标签非零；没有有效空 metadata。
 *     调用者保证同一完整客户租约生命期内实例号不复用，本模块不发号或认证。
 * @note
 *     时间：deadline 为同域 MONOTONIC 纳秒，不累计系统挂起时间；0/MAX 均有限。
 *     调用者负责来源、时间域与样本新鲜度，不能将墙钟或跨重启时间混入。
 * @note
 *     生命周期：普通值可复制、不保活，不构成跨线程发布；共享存储由调用者同步。
 *     仅逻辑字段有合同，不承诺 padding、ABI 或线协议布局。
 */
typedef struct vireo_task_metadata {
    vireo_task_route_t route; /**< 正常非空的完整客户路由，不拥有或核验客户。 */
    uint64_t request_instance_id; /**< 1..UINT64_MAX 的请求实例号，无时间单位。 */
    uint32_t operation; /**< 1..UINT32_MAX 的内部操作标签，不自动映射 wire command。 */
    uint64_t deadline_ns; /**< 0..UINT64_MAX 的有限 MONOTONIC 绝对纳秒期限。 */
} vireo_task_metadata_t;

/**
 * @brief
 *     按值构造元数据，不采样时间，允许保存已到期的期限。
 *
 * @param[in] route
 *     已初始化的正常非空路由，关联真实性由调用者保证。
 * @param[in] request_instance_id
 *     非零实例号；调用者保证同一完整客户租约生命期内不复用，不由本模块发号。
 * @param[in] operation
 *     非零内部操作标签，其注册与执行语义由使用者另定。
 * @param[in] deadline_ns
 *     同域 MONOTONIC 绝对纳秒期限；0/MAX 不表示未设置或无限。
 * @param[out] out_metadata
 *     必需、存活、正确对齐且可写的独占输出，只借至返回，不保存地址。
 *
 * @retval VIREO_OK
 *     完整发布四个逻辑字段，成功不保证 padding 内容。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     输出 NULL（优先）、route 空或畸形、实例号或操作标签为零。
 *     失败保持整个输出对象，包括已有 padding 字节。
 *
 * @note
 *     无资源、阻塞或短进度；按值输入允许输出回原 metadata 存储，不认证当前性。
 * @note
 *     独立输出 thread-safe；同一存储及跨线程发布由调用者同步，输出不得指 errno。
 * @note
 *     不读取、保存或修改 errno，所有路径保持入口值，不自动重试。
 */
vireo_result_t vireo_task_metadata_make(vireo_task_route_t route, uint64_t request_instance_id,
                                        uint32_t operation, uint64_t deadline_ns,
                                        vireo_task_metadata_t *out_metadata);

/**
 * @brief
 *     用显式同域 now 判断元数据期限是否到期，不执行任务或取消动作。
 *
 * @param[in] metadata
 *     已初始化的有效按值元数据，查询也要求 route、实例及操作形态有效。
 * @param[in] now_ns
 *     同域 MONOTONIC 纳秒样本，0..UINT64_MAX，来源与新鲜度由调用者负责。
 * @param[out] out_expired
 *     必需、存活、正确对齐且可写的独占 bool 输出，只借至返回，不保存。
 *
 * @retval VIREO_OK
 *     写入 now_ns >= deadline_ns；相等到期，到期仍为成功查询，不返回 TIMEOUT。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     输出 NULL（优先）或元数据形态无效，整个输出保持。
 *
 * @note
 *     不采样、延长或更新期限，不检查客户当前性，无资源或阻塞。
 * @note
 *     独立输出 thread-safe；共享存储由调用者同步，输出不得指 errno。
 * @note
 *     不读取、保存或修改 errno，所有路径保持入口值。
 */
vireo_result_t vireo_task_metadata_deadline_expired(vireo_task_metadata_t metadata,
                                                    uint64_t now_ns, bool *out_expired);

/**
 * @brief
 *     比较完整 route 和实例号是否相同，操作及期限不参与请求身份关系。
 *
 * @param[in] left
 *     已初始化的有效左侧按值元数据，所有字段形态均须有效。
 * @param[in] right
 *     已初始化的有效右侧按值元数据，所有字段形态均须有效。
 * @param[out] out_same
 *     必需、存活、正确对齐且可写的独占 bool 输出，只借至返回，不保存。
 *
 * @retval VIREO_OK
 *     写入完整 route 与实例号的相等关系，operation/deadline_ns 可不同。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     输出 NULL（优先）或任一元数据无效，整个输出保持。
 *
 * @note
 *     只比较数值，不认证请求因果关系、唯一性、客户当前性或授权；不保活资源。
 * @note
 *     无资源或阻塞；独立输出 thread-safe，共享存储由调用者同步，输出不得指 errno。
 * @note
 *     不读取、保存或修改 errno，所有路径保持入口值。
 */
vireo_result_t vireo_task_metadata_same_request(vireo_task_metadata_t left,
                                               vireo_task_metadata_t right, bool *out_same);

/**
 * @brief
 *     单个 task 控制块与 payload 的申请字节硬上限，不含分配器开销或 RSS。
 */
#define VIREO_TASK_MAX_ALLOCATION_BYTES ((size_t)67108864)

/**
 * @brief
 *     唯一拥有的独立输入对象，创建后无修改入口，不保活客户。
 *
 * @note
 *     不复制或依赖私有布局；创建复制 metadata 和 payload，原输入仍归调用者。
 *     可持一份取消强引用，关联创建后固定，共享标志可变化；不执行任务。
 *     不拥有队列、worker 或网络资源，不认证取消状态与请求的关联。
 * @note
 *     共享访问由调用者同步，move/destroy 前结束全部操作与借用。
 *     普通指针副本不产生第二所有者，move 不构成跨线程发布。
 */
typedef struct vireo_task vireo_task_t;

/**
 * @brief
 *     独立按值观测，不含资源借用指针，不承诺 padding 或 ABI。
 */
typedef struct vireo_task_info {
    vireo_task_metadata_t metadata; /**< 创建时复制的有效元数据，来源规则仍由 caller 保证。 */
    size_t payload_size; /**< 独立 payload 字节数，允许零。 */
    size_t allocated_bytes; /**< 控制块与 payload 实际申请字节数，不含 malloc 元数据或 RSS。 */
} vireo_task_info_t;

/**
 * @brief
 *     只读短借的完整 payload，不拥有或保活 task。
 */
typedef struct vireo_task_payload_view {
    unsigned char const *data; /**< 非空 payload 的只读地址；空 payload 为 NULL，禁止修改/free。 */
    size_t size; /**< 可读字节数；借用终止或 task 移动/销毁后不得使用该 view。 */
} vireo_task_payload_view_t;

/**
 * @brief
 *     受预算约束地复制独立输入，完整成功才发布唯一 owner。
 *
 * @param[in] metadata
 *     有效按值元数据，允许已到期；只核形态，不采样或认证客户/实例。
 * @param[in] data
 *     调用期间稳定可读的输入；非零 payload_size 必须非 NULL，零长度不读取。
 * @param[in] payload_size
 *     要复制的字节数，允许零，不解释协议或业务内容。
 * @param[in] allocation_budget
 *     显式正申请字节预算，不超过 VIREO_TASK_MAX_ALLOCATION_BYTES，计控制块与 payload。
 * @param[out] out_task
 *     必需、存活、对齐、可写且入口值为 NULL 的 owner 地址；只借至返回，不保存。
 *
 * @retval VIREO_OK
 *     完整复制 metadata/payload 后发布无取消关联的唯一 owner，原输入仍归调用者。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址 NULL、非空输出、无效 metadata、零预算或非零长度配 NULL 输入。
 * @retval VIREO_RESULT_OVERFLOW
 *     基本校验后，控制块加 payload 的申请量不可表示。
 * @retval VIREO_RESULT_RANGE
 *     受检计算后，预算超过硬上限或不足以覆盖实际申请量。
 * @retval VIREO_RESULT_NO_MEMORY
 *     申请失败，不发布对象或保留未拥有的输入。
 *
 * @note
 *     失败保持整个主输出与既有资源；不部分复制，不自动重试或发布诊断。
 * @note
 *     输出不与输入字节区重叠、不指 errno；实际输入可读性由调用者保证。
 *     申请和复制不承诺非阻塞或硬实时，成本与 payload 大小相关。
 * @note
 *     无内部同步；共享访问由调用者同步，所有路径保持入口 errno。
 */
vireo_result_t vireo_task_create_copy(vireo_task_metadata_t metadata, void const *data,
                                      size_t payload_size, size_t allocation_budget,
                                      vireo_task_t **out_task);

/**
 * @brief
 *     复制独立输入并持有一份共享取消强引用，完整成功才发布 task。
 *
 * @param[in] metadata
 *     有效按值元数据，允许已到期；不采样或认证请求/客户。
 * @param[in] data
 *     调用期间稳定可读输入，非零长度不能 NULL，零长度不读取。
 * @param[in] payload_size
 *     输入字节数，允许零；成功独立复制，不消费原输入。
 * @param[in] allocation_budget
 *     显式正预算，至多 MAX_ALLOCATION_BYTES，只计 task 控制块＋payload 请求量。
 * @param[in] cancel
 *     必需存活对象，来源强引用保护至返回，不消耗来源；允许已请求状态。
 * @param[out] out_task
 *     必需合法独占空 owner 地址，不与输入/对象/其他 owner/errno 重叠，只借至返回。
 *
 * @retval VIREO_OK
 *     完整发布唯一 task，持有同一 cancel 的一份新增引用；关联不可重绑。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址 NULL、非空输出、无效 metadata、零预算或非零长度配 NULL 输入。
 * @retval VIREO_RESULT_OVERFLOW
 *     受检控制块＋payload 不可表示，或校验预算后 retain 引用已耗尽。
 * @retval VIREO_RESULT_RANGE
 *     受检申请量之后，预算超过硬上限或不足，不取得引用或申请。
 * @retval VIREO_RESULT_NO_MEMORY
 *     retain 后 task 申请失败，释放临时引用，不发布半成品。
 *
 * @note
 *     顺序为基本/metadata→受检量→预算→公开 retain→申请→复制与发布。
 *     失败保持整个主输出及本调用引用义务；依赖错误原样返回，不自动重试或诊断。
 * @note
 *     预算不重复计独立创建的 cancel 块；opaque 控制块/sizeof 不冻结，紧预算可不足。
 *     其他持有者可合法请求/释放其引用，不承诺失败时整个共享状态冻结。
 * @note
 *     task 访问与跨线程发布由 caller 同步，申请/复制不承诺非阻塞或硬实时。
 *     不接 worker/队列，不自动执行取消或到期动作；所有路径保持 errno。
 */
vireo_result_t vireo_task_create_copy_with_cancel(vireo_task_metadata_t metadata,
    void const *data, size_t payload_size, size_t allocation_budget,
    vireo_task_cancel_t *cancel, vireo_task_t **out_task);

/**
 * @brief
 *     查询关联状态的当前取消请求；无关联同样成功并写 false。
 *
 * @param[in] task
 *     必需存活 task，调用期间由唯一 owner 保护且不得移动/销毁。
 * @param[out] out_requested
 *     必需合法独占 bool 输出，不与 task/资源/owner/errno 重叠，只借至返回。
 *
 * @retval VIREO_OK
 *     写本次观测或无状态 false；true 不表示任务已停止，不返回 CANCELLED。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址 NULL，整个输出保持。
 *
 * @note
 *     依赖错误透传；查询无申请、不采样或合并 deadline，不自动处理业务。
 *     独立 cancel 持有者可并发请求；task 寿命与存储由 caller 同步。
 *     失败输出保持，无自动重试；所有路径保持 errno。
 */
vireo_result_t vireo_task_is_cancel_requested(vireo_task_t const *task, bool *out_requested);

/**
 * @brief
 *     取得关联状态的一份独立强引用，所得引用可超过 task 寿命。
 *
 * @param[in] task
 *     必需存活 task，调用期间不得移动/销毁；不消费 task 所持引用。
 * @param[out] out_cancel
 *     必需合法独占空 owner 地址，不与 task/资源/owner/errno 重叠，只借至返回。
 *
 * @retval VIREO_OK
 *     输出一份新增强引用，由 caller 最终通过 cancel_destroy 释放。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址 NULL 或输出非空，整个输出与资源保持。
 * @retval VIREO_RESULT_NOT_FOUND
 *     基本参数有效但 task 无取消关联，输出保持。
 * @retval VIREO_RESULT_OVERFLOW
 *     关联状态引用计数耗尽，不回绕、不增加引用，输出保持。
 *
 * @note
 *     非裸指针借用，不复制状态，不申请内存，也不保证请求关联真实性。
 *     task 访问及输出存储/发布由 caller 同步，依赖错误原样返回。
 *     失败保持本调用引用义务，其他持有者可合法变化；所有路径保持 errno。
 */
vireo_result_t vireo_task_retain_cancel(vireo_task_t const *task,
                                       vireo_task_cancel_t **out_cancel);

/**
 * @brief
 *     观测有效 task 的创建快照，不借用其内部指针。
 *
 * @param[in] task
 *     必需、存活的 task，只借至返回，期间不得移动或销毁。
 * @param[out] out_info
 *     必需、合法独占输出，不与 task/字节区重叠，不指 errno，只借至返回。
 *
 * @retval VIREO_OK
 *     一次发布三个逻辑字段，所得值不因 task 后来销毁而失效。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址 NULL，整个输出保持。
 *
 * @note
 *     只读无申请，共享访问由调用者同步；所有路径保持 errno。
 */
vireo_result_t vireo_task_inspect(vireo_task_t const *task, vireo_task_info_t *out_info);

/**
 * @brief
 *     借用 task 的完整只读 payload，空 payload 返回 NULL/0。
 *
 * @param[in] task
 *     必需、存活的对象，调用者保证整个借用期间不移动或销毁。
 * @param[out] out_view
 *     必需、合法独占输出，不与 task/字节区重叠，不指 errno，只借至返回。
 *
 * @retval VIREO_OK
 *     一次发布只读地址和长度，不转移或新增所有权。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址 NULL，整个输出保持。
 *
 * @note
 *     借用不能修改/free 或保活对象；move/destroy 前结束全部借用，旧 view 随之失效。
 * @note
 *     无申请或内部同步，调用者负责借用/共享访问同步；所有路径保持 errno。
 */
vireo_result_t vireo_task_borrow_payload(vireo_task_t const *task,
                                        vireo_task_payload_view_t *out_view);

/**
 * @brief
 *     将唯一 task owner 移到空目标，成功清源，不复制 payload。
 *
 * @param[in,out] source
 *     必需、合法 owner 地址，源对象存在且其全部操作/借用已结束。
 * @param[in,out] destination
 *     必需、不同且合法的空 owner 地址，不能位于 task/字节区，不指 errno。
 *
 * @retval VIREO_OK
 *     目标取得同一对象及可选取消引用的唯一所有权，源清 NULL，不增减引用计数。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     地址 NULL、两地址相同或目标非空，两个 owner 与资源均保持。
 * @retval VIREO_RESULT_NOT_FOUND
 *     基本校验通过但源为空，两个 owner 保持。
 *
 * @note
 *     源 owner 地址也须在对象外且不指 errno；共享存储由调用者同步。
 *     不构成原子发布或线程安全交接，无申请，所有路径保持 errno。
 */
vireo_result_t vireo_task_move(vireo_task_t **source, vireo_task_t **destination);

/**
 * @brief
 *     释放唯一拥有的 task 并清 owner，空 owner 值可重复成功。
 *
 * @param[in,out] owner
 *     必需、合法可写 owner 地址，在对象/字节区外且不指 errno。
 *     非空时必须唯一拥有，所有操作与借用已结束。
 *
 * @retval VIREO_OK
 *     释放可选取消引用与 task 申请，owner 为 NULL；空值同样成功。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     owner 地址 NULL，不改变资源。
 *
 * @note
 *     所有旧裸指针别名失效，不会自动清除调用者保留的副本。
 * @note
 *     无内部同步、不自动执行或取消任务；所有路径保持 errno。
 */
vireo_result_t vireo_task_destroy(vireo_task_t **owner);

#endif /* VIREO_THREAD_TASK_H */
