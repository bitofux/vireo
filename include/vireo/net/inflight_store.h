/*
 * PROJECT : VIREO
 * FILE    : inflight_store.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-13
 * BRIEF   : Reactor 有界 inflight 记录表的资源与登记生命周期
 */
#ifndef VIREO_NET_INFLIGHT_STORE_H
#define VIREO_NET_INFLIGHT_STORE_H

#include <stddef.h>
#include <vireo/base/result.h>
#include <vireo/net/inflight.h>

#define VIREO_INFLIGHT_STORE_MAX_CAPACITY ((size_t)65536)
#define VIREO_INFLIGHT_STORE_MAX_ALLOCATION_BYTES ((size_t)67108864)

/** 唯一拥有容器内存；全部同表访问 Reactor-only，不向 worker 发布。 */
typedef struct vireo_inflight_store vireo_inflight_store_t;

/** 显式资源选项，创建期间短借，无默认或自动扩容。 */
typedef struct vireo_inflight_store_options {
    size_t capacity; /**< 正记录槽数，最多 65536，允许非 2 的幂。 */
    size_t max_memory_bytes; /**< 正容器申请预算，最多 64 MiB，不计 task/payload 或独立取消状态申请。 */
} vireo_inflight_store_options_t;

/** 独立按值快照；不返回内部槽地址，也不延长表的寿命。 */
typedef struct vireo_inflight_store_info {
    size_t capacity; /**< 创建时固定的记录槽数。 */
    size_t count; /**< 已登记且尚未取出的记录数，0..capacity，不是队列深度。 */
    size_t allocated_bytes; /**< 控制块加固定槽数组的实际申请字节数。 */
    size_t max_memory_bytes; /**< 创建时显式字节预算。 */
} vireo_inflight_store_info_t;

/**
 * @brief
 *     受检预分配固定容量的空记录表，完整初始化后发布唯一 owner。
 *
 * @param[in] options
 *     必需稳定选项，短借至返回；容量和预算均正且不超过公共上限。
 * @param[out] out_store
 *     必需独占空 owner 地址，入口值必须为 NULL，成功后由 caller 唯一拥有。
 *
 * @retval VIREO_OK
 *     创建成功，全部槽为空，count 为 0。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需 NULL、零容量/预算或非空创建目标。
 * @retval VIREO_RESULT_OVERFLOW
 *     槽数组乘法或控制块加法不可表示，优先于限额检查。
 * @retval VIREO_RESULT_RANGE
 *     可表示但容量/预算超限，或实际申请量超过预算。
 * @retval VIREO_RESULT_NO_MEMORY
 *     申请失败，没有发布半对象或残留申请。
 *
 * @note
 *     预算只计控制块与槽数组，不计 allocator 开销、RSS、task/payload 或全进程总量。
 *     私有布局/sizeof 不冻结，后续布局变化需要重新核算预算。
 * @note
 *     同表全部 Reactor-only；管理流程中的申请不承诺非阻塞。
 *     表不保存 server/queue/task 指针、不拥有 payload；任务登记可持取消强引用。
 * @note
 *     地址存活、正确对齐、独占且不重叠输入、资源或 errno；失败保持整个输出及资源。
 *     所有路径保持入口 errno，无阶段诊断、自动重试或业务清理。
 */
vireo_result_t vireo_inflight_store_create(vireo_inflight_store_options_t const *options,
    vireo_inflight_store_t **out_store);

/**
 * @brief
 *     观测当前表的独立四字段资源与登记数快照。
 *
 * @param[in] store
 *     必需存活表，仅短借至返回；本入口 Reactor-only。
 * @param[out] out_info
 *     必需独立可写值，允许覆盖已有值；快照不保活对象。
 *
 * @retval VIREO_OK
 *     四个逻辑字段已发布；不承诺结构体 padding。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址为 NULL。
 *
 * @note
 *     输出不重叠资源或 errno；失败保持整个输出和表，所有路径保持 errno。
 *     不申请、不暴露内部槽指针；登记数量不证明任务执行或客户当前性。
 */
vireo_result_t vireo_inflight_store_inspect(vireo_inflight_store_t const *store,
    vireo_inflight_store_info_t *out_info);

/**
 * @brief
 *     全部访问结束后配对释放自有空表，并清空唯一 owner。
 *
 * @param[in,out] owner
 *     必需独占 owner 地址；入口值 NULL 允许重复销毁。
 *
 * @retval VIREO_OK
 *     自有容器已释放，或入口值为空；返回时 *owner 为 NULL。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     owner 地址为 NULL。
 * @retval VIREO_RESULT_BUSY
 *     表内仍有记录，保留 owner 和完整表；须由 caller 显式取完。
 *
 * @note
 *     本入口 Reactor-only，先结束所有访问；其他裸指针副本不会自动清空。
 *     owner 地址不位于表内，也不与 errno 重叠；所有路径保持入口 errno。
 *     不自动移除记录、销毁 task/payload、关闭客户或处理业务。
 */
vireo_result_t vireo_inflight_store_destroy(vireo_inflight_store_t **owner);

/**
 * @brief
 *     核验当前客户与准入后保存完整请求数值记录。
 *
 * @param[in,out] store
 *     必需存活表，全部同表访问 Reactor-only，不向 worker 发布。
 * @param[in] server
 *     必需存活资源根，仅短借至返回，不保存或保活。
 * @param[in] metadata
 *     完整有效元数据；caller 保证同完整客户生命期 instance 历史不复用。
 *     deadline 为 MONOTONIC 绝对纳秒，0/MAX 有限，允许已到期值。
 * @param[out] stage
 *     可空独立阶段输出，每可写路径覆盖；成功及基本 NULL 拒绝为 NONE。
 *
 * @retval VIREO_OK
 *     表已复制完整 metadata，count 增一；不表示 task 已提交或开始执行。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需 NULL、metadata 形态无效或跨客户拥有域。
 * @retval VIREO_RESULT_NOT_FOUND
 *     客户已归还或代次已旧。
 * @retval VIREO_RESULT_RANGE
 *     同客户拥有域槽号超出实际容量。
 * @retval VIREO_RESULT_CANCELLED
 *     公开快照已观测到 server 停止。
 * @retval VIREO_RESULT_BUSY
 *     客户非 OPEN、表满或同完整客户的活跃 sequence/instance 任一重复。
 * @retval VIREO_RESULT_INTERNAL
 *     私有计数违反容量不变量；不修复表。
 *
 * @return
 *     其他公开依赖或受检计算错误原样返回。
 *
 * @note
 *     顺序：基本地址/metadata→当前客户→server 停止快照→OPEN→表→提交。
 *     停止快照不是跨线程停止屏障；同客户指完整 owner/slot/generation。
 *     全部可失败步骤先于提交，失败保持表与外部资源，无回滚或自动清理。
 * @note
 *     不发号、采样、检查期限、提交任务或接网络；无运行申请或扩容。
 *     数组检查有界 O(capacity)，公开依赖成本沿其合同，不承诺硬实时。
 *     stage 独立存活、对齐、不重叠资源或 errno；所有路径保持入口 errno。
 */
vireo_result_t vireo_inflight_store_register(vireo_inflight_store_t *store,
    vireo_tcp_server_t const *server, vireo_task_metadata_t metadata,
    vireo_inflight_stage_t *stage);

/**
 * @brief
 *     按完整 route 与 instance 查询原存储快照，不认证客户当前性。
 *
 * @param[in] store
 *     必需存活表，仅短借至返回，全部同表访问 Reactor-only。
 * @param[in] key
 *     完整有效 metadata；operation/deadline 不参与身份匹配，但仍须有效。
 * @param[out] out_record
 *     必需独立可写快照，允许覆盖已有值；成功返回原存储 metadata。
 * @param[out] stage
 *     可空独立诊断，每可写路径覆盖；成功及基本 NULL 拒绝为 NONE。
 *
 * @retval VIREO_OK
 *     找到并复制记录，表保持；只保证逻辑字段，不承诺 padding。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需 NULL 或完整 key 形态无效。
 * @retval VIREO_RESULT_NOT_FOUND
 *     没有该完整 route/instance 的记录。
 *
 * @return
 *     其他公开值校验/比较错误原样返回。
 *
 * @note
 *     客户断开或 server 停止后仍可查询，不采样或判断期限。
 *     不申请、不返回内部槽地址、不保活、不认证结果内容或回写权限。
 *     有界 O(capacity)，不重试；失败保持整个主输出与表，所有路径保持 errno。
 * @note
 *     两输出独立存活、对齐、互不重叠，也不重叠输入、资源或 errno。
 */
vireo_result_t vireo_inflight_store_get(vireo_inflight_store_t const *store,
    vireo_task_metadata_t key, vireo_task_metadata_t *out_record,
    vireo_inflight_stage_t *stage);

/**
 * @brief
 *     按完整 route 与 instance 取出原记录并显式结束一项登记。
 *
 * @param[in,out] store
 *     必需存活表，仅短借至返回，全部同表访问 Reactor-only。
 * @param[in] key
 *     完整有效 metadata；匹配关系与 get 相同。
 * @param[out] out_record
 *     必需独立可写快照，允许覆盖已有值；成功取出后由 caller 保存原值。
 * @param[out] stage
 *     可空独立诊断，每可写路径覆盖；成功及基本 NULL 拒绝为 NONE。
 *
 * @retval VIREO_OK
 *     原快照已发布，匹配槽清空且 count 减一；成功只保证逻辑字段。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需 NULL 或完整 key 形态无效。
 * @retval VIREO_RESULT_NOT_FOUND
 *     没有匹配记录，重复取出也不自动当成功。
 *
 * @return
 *     其他公开值/取消引用释放错误原样返回；私有计数不变量损坏为 INTERNAL。
 *
 * @note
 *     不要求客户仍存活；释放表所持可选取消引用并结束登记，不请求取消/销毁 task 或保证 worker 已结束。
 *     独立引用不随本次释放失效；不转出表引用，caller 所得仅 metadata。
 *     后续动作失败不自动放回，caller 保留快照处理；无隐式业务清理。
 *     全部可失败步骤先于修改，无运行申请、扩容或重试，有界 O(capacity)。
 *     失败保持整个主输出与表，所有路径保持入口 errno。
 * @note
 *     两输出独立存活、对齐、互不重叠，也不重叠输入、资源或 errno。
 */
vireo_result_t vireo_inflight_store_take(vireo_inflight_store_t *store,
    vireo_task_metadata_t key, vireo_task_metadata_t *out_record,
    vireo_inflight_stage_t *stage);

/**
 * @brief
 *     按完整客户数值统计尚未取出的历史登记，不核验客户当前性。
 *
 * @param[in] store
 *     必需存活表，短借至返回，全部同表访问 Reactor-only。
 * @param[in] client
 *     已初始化的完整客户租约值，按 owner/slot/generation 匹配；复制不保活。
 * @param[out] out_count
 *     必需独立可写 size_t 计数，单位请求条数，成功允许覆盖已有值。
 * @param[out] stage
 *     可空独立诊断，每可写路径覆盖；成功及基本形态拒绝为 NONE。
 *
 * @retval VIREO_OK
 *     发布 0..capacity 的登记数，有效但无匹配记录时为 0。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址 NULL 或客户形态畸形。
 * @retval VIREO_RESULT_NOT_FOUND
 *     客户值逻辑全零；不是无记录的正常非空身份。
 *
 * @return
 *     其他公开值校验或受检计算错误原样返回。
 *
 * @note
 *     不查询 server、槽实际容量或客户存活；归还、关闭、停止后的历史仍可计数。
 *     同槽新代、不同槽或拥有域分开统计；期限过去不退款，take 成功才移除。
 *     不采样、申请、扩容、返回内部地址或认证回写资格，有界 O(capacity)。
 * @note
 *     输出独立存活、对齐，彼此不重叠且不重叠输入、资源或 errno。
 *     失败保持整个主输出与表，所有路径保持入口 errno，无隐式清理或重试。
 */
vireo_result_t vireo_inflight_store_count_client(vireo_inflight_store_t const *store,
    vireo_connection_pool_lease_t client, size_t *out_count,
    vireo_inflight_stage_t *stage);

/**
 * @brief
 *     在原登记准入检查上，按本次显式客户限额决定是否提交一项。
 *
 * @param[in,out] store
 *     必需存活固定表，全部同表访问 Reactor-only，无运行申请或扩容。
 * @param[in] server
 *     必需存活客户资源根，仅短借至返回，不保存或保活。
 * @param[in] metadata
 *     完整有效元数据，caller 保证同完整客户生命期实例号历史不复用。
 * @param[in] max_client_requests
 *     本次显式正 size_t 登记条数上限，不超过 store.capacity，不保存为配置。
 * @param[out] stage
 *     可空独立诊断，每可写路径覆盖，成功及基本 NULL/零限额拒绝为 NONE。
 *
 * @retval VIREO_OK
 *     完整记录已提交，总 count 增一，该完整客户提交后计数不超过本次限额。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需 NULL、零限额、metadata 无效或客户跨拥有域。
 * @retval VIREO_RESULT_RANGE
 *     metadata 有效后检查到限额超过表容量，或同客户拥有域槽越界。
 * @retval VIREO_RESULT_NOT_FOUND
 *     客户已归还或代次已旧。
 * @retval VIREO_RESULT_CANCELLED
 *     公开快照已观测到 server 停止。
 * @retval VIREO_RESULT_BUSY
 *     客户非 OPEN、活跃标签冲突、客户计数达到本次限额或全表满。
 * @retval VIREO_RESULT_INTERNAL
 *     私有总计数违反容量不变量，不修复表。
 *
 * @return
 *     其他公开依赖或受检计算错误原样返回。
 *
 * @note
 *     顺序：基本地址/零限额→完整 metadata→限额范围→当前客户→停止→OPEN
 *     →活跃标签冲突/客户限额/总容量→受检计数→提交；所有可失败步骤先于修改。
 *     限额或容量拒绝为 CHECK_RECORD，其他阶段沿 register，原 0..6 数值不变。
 * @note
 *     caller 统一使用本入口并传一致策略；原 register 仍仅受全表容量约束。
 *     过去的较大限额或原登记可能使现有数超过本次限额，此时拒新项，不删旧项。
 *     take 成功才退登记名额，客户关闭、期限过去或 worker 领取都不自动退款。
 * @note
 *     有界 O(capacity)，不发号、采样、提交任务、自动取消、清理或回写。
 *     停止快照不是跨线程屏障；stage 独立存活、对齐，不重叠资源或 errno。
 *     失败保持表与外部资源，所有路径保持入口 errno，无重试或回滚。
 */
vireo_result_t vireo_inflight_store_register_limited(vireo_inflight_store_t *store,
    vireo_tcp_server_t const *server, vireo_task_metadata_t metadata,
    size_t max_client_requests, vireo_inflight_stage_t *stage);

/**
 * @brief
 *     从只借 task 登记元数据，并持有其可选取消关联的一份新增强引用。
 *
 * @param[in,out] store
 *     必需存活 Reactor 表，原固定容量/预算，运行不申请或扩容。
 * @param[in] server
 *     必需当前客户资源根，公开准入同 register_limited，只短借。
 * @param[in] task
 *     必需存活不可变 task，只借至返回，期间不得移动/销毁，不消费任何引用。
 * @param[in] max_client_requests
 *     显式正条数，不超过表容量；caller 统一限额策略。
 * @param[out] stage
 *     可空独立诊断，每可写路径覆盖，成功 NONE。
 *
 * @retval VIREO_OK
 *     metadata 已登记；有取消关联则表自持一份，无关联正常登记并保存 NULL。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需 NULL 或零限额，优先其他准入检查。
 * @retval VIREO_RESULT_OVERFLOW
 *     准入通过后关联引用已耗尽，或原受检计数失败；不登记。
 *
 * @return
 *     其他 task 观测/既有限额准入/引用取得错误原样返回。
 *
 * @note
 *     顺序：基本→公开 task_inspect→完整 metadata/限额范围/当前客户/停止/OPEN/
 *     冲突/客户额/容量/受检计数→公开 task_retain_cancel→一次逻辑登记。
 *     仅最后一步的 NOT_FOUND 表示无关联；其他错误不降级或留下半登记。
 * @note
 *     表引用配对由 take 释放；旧纯 metadata 登记始终无关联，不能事后重绑。
 *     不发号、检查期限、提交、请求取消或自动清理 task/客户/业务。
 *     新槽指针计容器实际申请量，独立 cancel 原申请量不重复计入预算。
 * @note
 *     表扫描有界 O(capacity)，引用取得沿已封板原子合同可能竞争重试。
 *     不等待 worker/队列容量，不承诺 lock-free、公平或耗时上界。
 *     输入/诊断独立存活、对齐、不重叠资源/errno；失败保持表及本调用引用义务，errno 保持。
 */
vireo_result_t vireo_inflight_store_register_task_limited(vireo_inflight_store_t *store,
    vireo_tcp_server_t const *server, vireo_task_t const *task, size_t max_client_requests,
    vireo_inflight_stage_t *stage);

/**
 * @brief
 *     按历史完整请求键取得一份独立取消强引用，不请求取消或结束登记。
 *
 * @param[in] store
 *     必需存活表，只借至返回，全部同表访问 Reactor-only。
 * @param[in] key
 *     完整有效 metadata；route/instance 匹配，operation/deadline 仍校验但不作键。
 * @param[out] out_cancel
 *     必需独占入口 NULL 引用 owner；成功 caller 自有，最终 cancel_destroy 配对。
 * @param[out] stage
 *     可空独立诊断，每可写路径覆盖，成功 NONE。
 *
 * @retval VIREO_OK
 *     输出一份新增引用，可超过记录/表/task 寿命，不认证客户或回写权限。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需 NULL、非空输出或无效完整 key，基本地址/非空输出优先。
 * @retval VIREO_RESULT_NOT_FOUND
 *     没有该记录，或记录没有取消关联；不当成功。
 * @retval VIREO_RESULT_OVERFLOW
 *     共享引用数耗尽，不回绕，输出仍 NULL、表不变。
 *
 * @return
 *     其他公开 key/比较/引用取得错误原样返回。
 *
 * @note
 *     缺记录 CHECK_RECORD，缺关联/取得失败 RETAIN_CANCEL，基本拒绝 NONE。
 *     不核验客户当前性、server 停止或期限；调用者可显式 request/query/destroy 所得引用。
 *     不申请、不返回槽指针、不移动表份，不冻结其他持有者的合法变化。
 * @note
 *     输出和诊断独立存活、对齐、不重叠输入、资源、彼此或 errno。
 *     失败保持整个主输出/表/本调用引用义务，所有路径保持入口 errno。
 *     引用取得沿原原子合同，不承诺竞争耗时上界；不内部重试业务。
 */
vireo_result_t vireo_inflight_store_retain_cancel(vireo_inflight_store_t const *store,
    vireo_task_metadata_t key, vireo_task_cancel_t **out_cancel, vireo_inflight_stage_t *stage);

#endif /* VIREO_NET_INFLIGHT_STORE_H */
