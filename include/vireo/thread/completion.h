/*
 * PROJECT : VIREO
 * FILE    : completion.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-12
 * BRIEF   : 请求完成元数据与独立响应字节的唯一拥有合同
 */

#ifndef VIREO_THREAD_COMPLETION_H
#define VIREO_THREAD_COMPLETION_H

#include <vireo/protocol/protocol.h>
#include <vireo/thread/task.h>

/**
 * @brief
 *     一次工作结果的独立数值描述，不拥有响应数据或客户资源。
 *
 * @note
 *     request 必须是有效的 task 元数据；全零不是有效空值。
 *     result 只接受当前公开定义的内部分类，suggested_status 只接受已注册状态。
 *     两种分类由 caller 明确提供，不自动换算或强制业务配对。
 *
 * @note
 *     原 deadline 为同域 MONOTONIC 纳秒，0/MAX 均有限，允许记录已到期结果。
 *     不认证客户当前性、请求关联或权限，不保活 task，不保存指针或 fd。
 *     普通复制不建立跨线程发布关系；共享存储与发布由 caller 同步。
 *     只保证逻辑字段，不承诺 padding、ABI 或线协议格式。
 */
typedef struct vireo_completion_metadata {
    vireo_task_metadata_t request; /**< 原请求的完整独立描述，身份与时间语义沿 task 合同。 */
    vireo_result_t result; /**< 已定义的工作内部结果，不是本次构造函数返回值。 */
    vireo_status_t suggested_status; /**< 已注册的 16 bit 协议状态建议，不表示已经发送。 */
} vireo_completion_metadata_t;

/**
 * @brief
 *     验证完整形态后，一次发布请求描述和工作结果。
 *
 * @param[in] request
 *     有效的按值请求描述；实例号来源及不复用由 caller 保证。
 * @param[in] result
 *     当前已定义的内部结果；允许保存 DATABASE、CANCELLED 等失败分类。
 * @param[in] suggested_status
 *     当前已注册的协议建议，由 caller 选择，不自动与 result 配对。
 * @param[out] out_metadata
 *     必需存活、对齐、可写的独占输出，只借至返回；原内容不要求为空。
 *
 * @retval VIREO_OK
 *     三个逻辑字段已发布；仅表示构造成功，不表示记录的工作成功。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     输出 NULL（优先）、request 无效、result 未定义或协议建议未注册。
 *
 * @note
 *     失败保持整个输出和输入，所有路径保持入口 errno；无资源或部分进度。
 *     按值输入允许输出回原元数据存储；输出不得与 errno 存储非法重叠。
 *     不发号、采样、申请、重试、自动取消或执行业务动作，不认证来源真实性。
 *     不同输出 thread-safe；共享可写输出和跨线程发布由 caller 同步。
 */
vireo_result_t vireo_completion_metadata_make(vireo_task_metadata_t request,
    vireo_result_t result, vireo_status_t suggested_status,
    vireo_completion_metadata_t *out_metadata);

/**
 * @brief
 *     比较完整路由和请求实例号，不比较结果或其他非身份字段。
 *
 * @param[in] left
 *     已初始化的有效按值完成元数据，查询也验证全部三个字段。
 * @param[in] right
 *     已初始化的有效按值完成元数据。
 * @param[out] out_same
 *     必需存活、对齐、可写的独占 bool 地址，只借至返回。
 *
 * @retval VIREO_OK
 *     发布完整 route 加 request_instance_id 的数值相等关系。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     输出 NULL（优先）或任一元数据形态无效。
 *
 * @note
 *     忽略 operation、deadline_ns、result 和 suggested_status，不认证当前客户或权限。
 *     失败保持整个输出和输入，所有路径保持 errno；不申请或访问登记表。
 *     不同输出 thread-safe；共享存储与跨线程发布由 caller 同步。
 */
vireo_result_t vireo_completion_metadata_same_request(vireo_completion_metadata_t left,
    vireo_completion_metadata_t right, bool *out_same);

/**
 * @brief
 *     以显式时间样本判断原请求期限，不自动处理迟到结果。
 *
 * @param[in] metadata
 *     已初始化的有效按值完成元数据，允许原期限已经过去。
 * @param[in] now_ns
 *     同域 MONOTONIC 纳秒，caller 保证来源及新鲜度，不接受墙钟语义。
 * @param[out] out_expired
 *     必需存活、对齐、可写的独占 bool 地址，只借至返回。
 *
 * @retval VIREO_OK
 *     发布 now_ns >= request.deadline_ns，不将到期改成 TIMEOUT 返回。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     输出 NULL（优先）或元数据形态无效。
 *
 * @note
 *     0 与 UINT64_MAX 都是正常有限值，无无限哨兵；不采样、延期或发出到期动作。
 *     失败保持整个输出和输入，所有路径保持 errno；无算术溢出或资源副作用。
 *     不同输出 thread-safe；共享存储与跨线程发布由 caller 同步。
 */
vireo_result_t vireo_completion_metadata_deadline_expired(vireo_completion_metadata_t metadata,
    uint64_t now_ns, bool *out_expired);

/**
 * @brief
 *     单个完成对象的申请字节硬上限，只计控制块与响应字节。
 */
#define VIREO_COMPLETION_MAX_ALLOCATION_BYTES ((size_t)67108864)

/**
 * @brief
 *     唯一拥有完成元数据和响应字节副本，创建后无修改入口。
 *
 * @note
 *     原 metadata 和输入字节仍归 caller；不保活 task 或客户，不拥有队列或网络资源。
 *     字节复制不递归拥有指针指向的资源，不解释业务 DTO 或线协议格式。
 *     销毁只释放自有申请，不调用用户清理函数，不自动发送或决定迟到结果策略。
 * @note
 *     共享访问、寿命与跨线程发布由 caller 同步，普通指针复制不产生第二 owner。
 *     move/destroy 前结束全部操作和借用，不依赖 opaque 布局或 sizeof。
 */
typedef struct vireo_completion vireo_completion_t;

/**
 * @brief
 *     完成对象的独立按值快照，无资源借用指针，不承诺 padding 或 ABI。
 */
typedef struct vireo_completion_info {
    vireo_completion_metadata_t metadata; /**< 创建时复制的完整完成描述，不认证客户当前性。 */
    size_t payload_size; /**< 独立响应数据的字节数，允许零。 */
    size_t allocated_bytes; /**< 控制块与数据实际申请字节数，不含分配器开销或 RSS。 */
} vireo_completion_info_t;

/**
 * @brief
 *     只读短借的完整响应数据，不拥有或保活 completion。
 */
typedef struct vireo_completion_payload_view {
    unsigned char const *data; /**< 非空时只读地址，空时 NULL，禁止修改或 free。 */
    size_t size; /**< 可读字节数；借用结束或对象移动/销毁后不得使用此 view。 */
} vireo_completion_payload_view_t;

/**
 * @brief
 *     在显式预算内复制完成描述和响应字节，完整成功才发布唯一 owner。
 *
 * @param[in] metadata
 *     有效按值完成描述，允许工作失败或原请求已经到期，不采样或认证客户。
 * @param[in] data
 *     调用期间稳定可读的输入，非零 payload_size 必须非 NULL；零长度不读取。
 * @param[in] payload_size
 *     复制字节数，允许零；输入应为独立字节表示，不递归复制指针资源。
 * @param[in] allocation_budget
 *     显式正 size_t 申请预算，不超过 VIREO_COMPLETION_MAX_ALLOCATION_BYTES。
 *     只计控制块和响应字节，不是所有对象或全进程内存上限。
 * @param[out] out_completion
 *     必需存活、对齐、可写的独占 owner 地址，入口值为 NULL，只借至返回。
 *
 * @retval VIREO_OK
 *     已完整复制并发布唯一 owner；原输入未消费，无外部清理回调。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址 NULL、非空输出、无效 metadata、零预算或非零长度配 NULL 输入。
 * @retval VIREO_RESULT_OVERFLOW
 *     基本校验后控制块加数据的申请量不可表示，优先于预算限额检查。
 * @retval VIREO_RESULT_RANGE
 *     受检计算后预算超出硬上限或不足以覆盖实际申请量。
 * @retval VIREO_RESULT_NO_MEMORY
 *     申请失败，不发布半对象，不保留 caller 输入。
 *
 * @note
 *     失败保持整个主输出和既有资源，所有路径保持入口 errno，无诊断或自动重试。
 *     输出须在输入/对象外且不指 errno；输入可读性、独立表示与同步由 caller 保证。
 *     申请和复制不承诺非阻塞；成功只保证逻辑字段，不承诺 padding 或线协议布局。
 */
vireo_result_t vireo_completion_create_copy(vireo_completion_metadata_t metadata,
    void const *data, size_t payload_size, size_t allocation_budget,
    vireo_completion_t **out_completion);

/**
 * @brief
 *     发布完整独立快照，所得值可超过完成对象的寿命。
 *
 * @param[in] completion
 *     必需存活对象，只借至返回，期间不得移动或销毁。
 * @param[out] out_info
 *     必需存活、对齐、可写的独占输出，在对象/数据区外且不指 errno。
 *
 * @retval VIREO_OK
 *     一次发布三个逻辑字段，无内部借用地址。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址 NULL，整个输出保持。
 *
 * @note
 *     无申请或内部同步，共享访问由 caller 同步，所有路径保持 errno。
 */
vireo_result_t vireo_completion_inspect(vireo_completion_t const *completion,
    vireo_completion_info_t *out_info);

/**
 * @brief
 *     短借完整只读响应字节，空响应返回 NULL/0。
 *
 * @param[in] completion
 *     必需存活对象，借用期间不得移动或销毁。
 * @param[out] out_view
 *     必需存活、对齐、可写的独占输出，在对象/数据区外且不指 errno。
 *
 * @retval VIREO_OK
 *     发布只读地址和长度，不转移或增加所有权。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址 NULL，整个输出保持。
 *
 * @note
 *     view 不保活，move/destroy 前结束全部借用，旧地址随后失效，不自动清除副本。
 *     禁止修改或 free；无申请或内部同步，caller 保证寿命和发布，全部 errno 保持。
 */
vireo_result_t vireo_completion_borrow_payload(vireo_completion_t const *completion,
    vireo_completion_payload_view_t *out_view);

/**
 * @brief
 *     将唯一 owner 移入空目标，成功清源，不申请或复制响应数据。
 *
 * @param[in,out] source
 *     必需合法 owner 地址，源对象非空且全部操作/借用已结束。
 * @param[in,out] destination
 *     必需、不同的合法空 owner 地址。
 *
 * @retval VIREO_OK
 *     目标取得同一对象的唯一所有权，源清 NULL。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     地址 NULL、两地址相同或目标非空，两个 owner 与资源保持。
 * @retval VIREO_RESULT_NOT_FOUND
 *     基本校验通过但源为空，两个 owner 保持。
 *
 * @note
 *     两地址须在对象/数据区外且不指 errno；caller 同步，不构成跨线程发布。
 *     所有路径保持 errno，无诊断、自动重试或回滚。
 */
vireo_result_t vireo_completion_move(vireo_completion_t **source,
    vireo_completion_t **destination);

/**
 * @brief
 *     配对释放唯一拥有对象并清 owner，空指针值重复成功。
 *
 * @param[in,out] owner
 *     必需合法可写 owner 地址，在对象/数据区外且不指 errno。
 *     非空时须唯一拥有，所有操作和借用已结束。
 *
 * @retval VIREO_OK
 *     自有申请已释放，owner 清 NULL；入口空值也成功。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     owner 地址 NULL，不改变资源。
 *
 * @note
 *     不调用业务清理函数、不取消或发送；所有旧裸指针别名失效但不会自动清零。
 *     配对释放前擦除整块自有申请（控制块及响应字节）；原输入和其他副本仍由 caller 清理。
 *     擦除成本 O(allocated_bytes)，不承诺硬实时，不保证第三方或系统副本清除。
 *     无内部同步，caller 保证寿命，所有路径保持入口 errno。
 */
vireo_result_t vireo_completion_destroy(vireo_completion_t **owner);

#endif /* VIREO_THREAD_COMPLETION_H */
