/*
 * PROJECT : VIREO
 * FILE    : client_deadline_store.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-10
 * BRIEF   : 此模块负责：
 * -- 固定容量数值记录保存、按完整身份查询及显式转出
 * -- 只依赖已采用公开合同，保持资源、输出与 errno 的既有边界
 */
#ifndef VIREO_NET_CLIENT_DEADLINE_STORE_H
#define VIREO_NET_CLIENT_DEADLINE_STORE_H

#include <vireo/net/client_deadline.h>

/** 显式容量与申请量硬限，不是默认值或延迟保证。 */
#define VIREO_CLIENT_DEADLINE_STORE_MAX_CAPACITY ((size_t)65536)
#define VIREO_CLIENT_DEADLINE_STORE_MAX_MEMORY ((size_t)64 * 1024 * 1024)

/** 唯一拥有本表申请，不拥有或保活任何 client、timer、server 或 wheel。 */
typedef struct vireo_client_deadline_store vireo_client_deadline_store_t;

/** 固定资源选项，无默认或运行期扩容。 */
typedef struct vireo_client_deadline_store_options {
    size_t capacity; /**< 正记录数，最多 MAX_CAPACITY，与 timer 槽容量独立。 */
    size_t max_memory_bytes; /**< 正请求字节预算，最多 MAX_MEMORY，仅控制块加完整数组。 */
} vireo_client_deadline_store_options_t;

/** 独立数值快照，不含内部地址或保活引用。 */
typedef struct vireo_client_deadline_store_info {
    size_t capacity; /**< 创建后不变的正记录槽数。 */
    size_t count;    /**< 当前保存记录数，0..capacity；不代表活跃 timer 数。 */
    size_t allocation_bytes; /**< 实际控制块与完整记录数组的受检请求总字节。 */
    size_t max_memory_bytes; /**< 创建时显式请求预算，不是 RSS。 */
} vireo_client_deadline_store_info_t;

/**
 * @brief 完整初始化固定空表后发布唯一 owner
 *
 * @param[in] options
 *     必需正容量及正字节预算；不含外部 timer、socket 或 allocator 开销。
 * @param[in,out] out_store
 *     必需独立拥有者地址，入口 *out_store 必须为 NULL。
 *
 * @retval VIREO_OK
 *     发布空表；创建后记录操作不申请。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址 NULL、入口 owner 非空或任一选项为零。
 * @retval VIREO_RESULT_OVERFLOW
 *     受检数组乘法或控制块加法不可表示，先于硬限检查。
 * @retval VIREO_RESULT_RANGE
 *     容量、预算超硬限或请求总量超过预算。
 * @retval VIREO_RESULT_NO_MEMORY
 *     申请失败，未发布任何资源。
 *
 * @note
 *     同表全部访问 Reactor-only，无并发或重入承诺，初始化 O(capacity)。
 * @note
 *     本头所有地址须独立存活对齐、不重叠、不在表自有内存内、非 errno；只短借到返回。
 *     所有失败保持整个主输出、表及外部资源；所有路径保持入口 errno。
 *     数值副本不保活资源，成功只承诺逻辑字段，不冻结 padding 或私有 ABI。
 */
vireo_result_t vireo_client_deadline_store_create(
    vireo_client_deadline_store_options_t const *options,
    vireo_client_deadline_store_t **out_store);

/**
 * @brief 只读观测固定资源与记录数量
 *
 * @param[in] store
 *     必需存活表，Reactor-only 短借。
 * @param[out] out_info
 *     必需独立数值输出，失败整个保持。
 *
 * @retval VIREO_OK
 *     提交四个逻辑字段，O(1)，不核验外部资源当前性。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址 NULL。
 *
 * @note
 *     地址、失败、errno 与线程沿 create 的统一说明，无内部借用或申请。
 */
vireo_result_t vireo_client_deadline_store_inspect(vireo_client_deadline_store_t const *store,
                                                   vireo_client_deadline_store_info_t *out_info);

/**
 * @brief 核验当前双方后复制绑定，完整 timer 身份为唯一键
 *
 * @param[in,out] store
 *     必需存活表，只拥有数值副本，不接管 timer。
 * @param[in] server
 *     必需存活 server，与表和轮同 Reactor，只借到返回，不保存指针。
 * @param[in] wheel
 *     必需存活轮，只借到返回；停止轮内活跃 timer 仍可核验。
 * @param[in] binding
 *     caller 保管的完整非空关联；因果关联仍由 caller 保证。
 * @param[out] out_stage
 *     可空独立诊断，每路径覆盖；本层拒绝 NONE，依赖沿既有 make，成功 NONE。
 *
 * @retval VIREO_OK
 *     保存完整数值副本，同客户不同 timer、不同 owner 或同槽不同代均可共存。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址 NULL、binding 半空或畸形；依赖拒绝原样返回。
 * @retval VIREO_RESULT_NOT_FOUND
 *     binding 全空；依赖客户或 timer 已旧代、注销、未 prepare 等原样返回。
 * @retval VIREO_RESULT_BUSY
 *     完整 timer 键重复或记录表满，先于外部客户／timer 当前核验。
 *
 * @note
 *     基本地址／形态／空身份→至多 capacity 项扫描重复与空槽→make→数值提交。
 *     依赖 RANGE 等错误原类透传，不覆盖已保存关联，无登记后回滚步骤。
 * @note
 *     保存失败不自动取消已登记 timer，caller 仍持原绑定并显式处理；复制值不保活。
 *     不限制每客户只有一个 timer，不认证关联，不选择期限或执行业务动作。
 * @note
 *     O(capacity)，无申请、I/O 或业务回调，不承诺 O(1)、公平或低延迟。
 *     地址、整失败保持、errno 与线程沿 create；诊断为独立例外，每路径覆盖。
 */
vireo_result_t vireo_client_deadline_store_save(vireo_client_deadline_store_t *store,
                                                vireo_tcp_server_t const *server,
                                                vireo_timer_wheel_t const *wheel,
                                                vireo_client_deadline_binding_t binding,
                                                vireo_client_deadline_stage_t *out_stage);

/**
 * @brief 按完整 timer 数值查询保存记录，不要求 timer 仍活跃
 *
 * @param[in] store
 *     必需存活表，只读短借。
 * @param[in] timer
 *     完整数值键；比较 owner、slot、generation，不将 slot 当作记录索引。
 * @param[out] out_binding
 *     必需独立普通值输出，入口可任意，失败整个保持。
 *
 * @retval VIREO_OK
 *     提交完整记录副本；不核验当前客户或 timer，不保活它们。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址 NULL 或 timer 形态畸形。
 * @retval VIREO_RESULT_NOT_FOUND
 *     空键或未找到完整键。
 *
 * @note
 *     至多扫描 capacity 项，无容量／跨 owner 资源检查，不调用轮或 server。
 *     地址、失败、errno、线程沿 create，无申请、I/O 或回调。
 */
vireo_result_t vireo_client_deadline_store_find(vireo_client_deadline_store_t const *store,
                                                vireo_timer_handle_t timer,
                                                vireo_client_deadline_binding_t *out_binding);

/**
 * @brief 按完整键转出并移除一条记录，供 caller 显式撤销或收尾
 *
 * @param[in,out] store
 *     必需存活表，成功减少 count；不注销外部 timer。
 * @param[in] timer
 *     完整数值键，当前或历史均允许。
 * @param[out] out_binding
 *     必需独立值输出，成功后由 caller 保管，失败整个保持。
 *
 * @retval VIREO_OK
 *     已转出并移除一条记录；此后 caller cancel 失败不会自动放回。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址 NULL 或 timer 畸形。
 * @retval VIREO_RESULT_NOT_FOUND
 *     空键或未找到，不把重复撤回当成功。
 *
 * @note
 *     不操作 timer/client；取出数值不等于取消资源或业务成功。
 *     O(capacity)，地址、整失败保持、errno 与线程沿 create。
 */
vireo_result_t vireo_client_deadline_store_withdraw(vireo_client_deadline_store_t *store,
                                                    vireo_timer_handle_t timer,
                                                    vireo_client_deadline_binding_t *out_binding);

/**
 * @brief 用未篡改公开到期通知的完整历史身份转出一条绑定
 *
 * @param[in,out] store
 *     必需存活表，成功移除一条记录。
 * @param[in] expired
 *     必需来自公开 take_expired／dispatch 的未篡改通知，短借，可用真实保存值副本。
 * @param[out] out_binding
 *     必需独立完整值输出；转出成功后 caller 用既有 check_expired 核验当前客户。
 *
 * @retval VIREO_OK
 *     完整历史 timer 匹配并转出；不查询已注销 timer 或客户，不执行业务动作。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址 NULL 或通知 handle 畸形。
 * @retval VIREO_RESULT_NOT_FOUND
 *     通知 handle 空或无匹配完整记录；重复消费不视为成功。
 *
 * @note
 *     只比较完整 handle，期限快照不参与身份匹配；caller 保证真实来源与因果关联。
 *     后续客户核验失败不撤销已经成功的取出，caller 仍拥有返回值并决定恢复。
 *     不保证业务一次成功、不认证来源、不重试、不取消另一代 timer。
 * @note
 *     O(capacity)，地址、整失败保持、errno 与线程沿 create；不得伪造停机取消为到期。
 */
vireo_result_t vireo_client_deadline_store_take_expired(
    vireo_client_deadline_store_t *store, vireo_timer_wheel_expired_t const *expired,
    vireo_client_deadline_binding_t *out_binding);

/**
 * @brief 只销毁空表并清空唯一 owner，不清理外部 timer 或客户
 *
 * @param[in,out] store
 *     必需拥有者地址；入口值 NULL 也成功，非空表保留。
 *
 * @retval VIREO_OK
 *     释放自有申请并清 NULL，所有旧表指针失效；没有外部资源动作。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址 NULL。
 * @retval VIREO_RESULT_BUSY
 *     仍有记录，不自动丢弃、取消 timer 或关闭客户。
 *
 * @note
 *     O(1)，同 Reactor 且无借用未结束；统一地址、失败与 errno 规则沿 create。
 */
vireo_result_t vireo_client_deadline_store_destroy(vireo_client_deadline_store_t **store);

#endif /* VIREO_NET_CLIENT_DEADLINE_STORE_H */
