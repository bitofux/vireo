/* 固定容量按键限流；计费额度与Session秘密token无关。 */
#ifndef VIREO_SECURITY_RATE_LIMITER_H
#define VIREO_SECURITY_RATE_LIMITER_H

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <vireo/base/clock.h>
#include <vireo/base/result.h>

#if CHAR_BIT != 8
#error "vireo_rate_limiter requires 8-bit bytes"
#endif

/** @brief 身份键精确字节数，全部位模式合法。 */
#define VIREO_RATE_LIMIT_KEY_BYTES 32
/** @brief 单对象记录硬上限。 */
#define VIREO_RATE_LIMIT_MAX_KEYS ((size_t)4096)
/** @brief 固定配置数硬上限。 */
#define VIREO_RATE_LIMIT_MAX_POLICIES ((size_t)16)
/** @brief 单次完整扣费维度硬上限。 */
#define VIREO_RATE_LIMIT_MAX_BATCH ((size_t)8)
/** @brief 容器申请预算硬上限，不计allocator开销/RSS。 */
#define VIREO_RATE_LIMIT_MAX_MEMORY_BYTES ((size_t)1048576)
/** @brief 单桶突发额度硬上限。 */
#define VIREO_RATE_LIMIT_MAX_BURST_TOKENS UINT32_C(1000000)
/** @brief 补充一个额度的间隔硬上限，1小时纳秒。 */
#define VIREO_RATE_LIMIT_MAX_REFILL_INTERVAL_NS UINT64_C(3600000000000)

/** @brief 唯一owner；对象操作由caller串行或外部同步，无内部锁/线程/fd。 */
typedef struct vireo_rate_limiter vireo_rate_limiter_t;

/** @brief 创建时复制的固定政策，无默认值或热变更。 */
typedef struct vireo_rate_limit_policy {
    uint32_t policy_id; /**< 非零唯一用途命名空间，不是用户id。 */
    uint32_t burst_tokens; /**< 初始/最大额度，1..1000000。 */
    vireo_duration_ns_t refill_interval_ns; /**< 每隔此正长度补1额度，最多1小时。 */
} vireo_rate_limit_policy_t;

/** @brief 固定资源选项，不自动扩容。 */
typedef struct vireo_rate_limiter_options {
    size_t max_keys; /**< 正记录容量，最多4096。 */
    size_t max_memory_bytes; /**< 正容器请求量预算，最多1MiB。 */
} vireo_rate_limiter_options_t;

/** @brief 一个扣费维度；同批(policy_id,key)不得重复。 */
typedef struct vireo_rate_limit_request {
    uint32_t policy_id; /**< 已创建的非零policy。 */
    unsigned char key[VIREO_RATE_LIMIT_KEY_BYTES]; /**< caller规范化的身份，精确32字节。 */
    uint32_t cost; /**< 本次正额度，最多对应burst。 */
} vireo_rate_limit_request_t;

/** @brief 正常判定结果；函数返回OK时仍须检查此枚举。 */
typedef enum vireo_rate_limit_outcome {
    VIREO_RATE_LIMIT_ADMITTED = 0, /**< 全部额度/记录可用，整批已扣。 */
    VIREO_RATE_LIMIT_THROTTLED = 1, /**< 任一额度不足，整批未扣。 */
    VIREO_RATE_LIMIT_CAPACITY = 2 /**< 额度足够但记录不足，整批未扣。 */
} vireo_rate_limit_outcome_t;

/** @brief caller拥有的独立值判定，不保活对象。 */
typedef struct vireo_rate_limit_decision {
    vireo_rate_limit_outcome_t outcome; /**< 正常三分支，不是协议状态。 */
    vireo_duration_ns_t retry_after_ns; /**< THROTTLED时最大额度恢复长度，其他0。 */
    size_t tracked_keys; /**< 本次完成后的实际占用数。 */
} vireo_rate_limit_decision_t;

/** @brief 不触发补充/回收的资源与时间水位快照。 */
typedef struct vireo_rate_limiter_info {
    size_t max_keys; /**< 创建容量。 */
    size_t tracked_keys; /**< 实际占用槽数，0..max_keys。 */
    size_t policy_count; /**< 创建配置数，1..16。 */
    size_t allocated_bytes; /**< 实际容器请求量，不含allocator/RSS。 */
    size_t max_memory_bytes; /**< 创建时的预算。 */
    vireo_monotonic_ns_t last_now; /**< 创建或最近合法check的同域时间，含正常拒绝。 */
} vireo_rate_limiter_info_t;

/**
 * @brief 受检核预算后一次申请固定表，复制配置并发布唯一空对象。
 * @param[in] options 必需只读正资源选项，借用至返回。
 * @param[in] policies 必需只读配置数组，借用至返回；非零id唯一。
 * @param[in] policy_count 配置条数，1..16；范围核对后才访问元素。
 * @param[in] now 同一单调域的起始时间，0和UINT64_MAX均有效。
 * @param[out] out_limiter 必需独占owner地址，入口值须NULL，成功才发布。
 * @retval VIREO_OK 已复制配置、空表及起始时间，caller拥有对象。
 * @retval VIREO_RESULT_INVALID_ARGUMENT NULL、非空输出、零资源/政策值或重复id。
 * @retval VIREO_RESULT_OVERFLOW 资源乘加无法表示，先于资源硬上限。
 * @retval VIREO_RESULT_RANGE 数值超硬上限或实际申请量超过预算。
 * @retval VIREO_RESULT_NO_MEMORY 一次申请失败，无残留资源。
 * @note 失败保持owner，所有路径保持errno；无自动重试。create可能分配/阻塞，
 *       在共享访问之前执行，不适合作为Reactor热路径。配置/owner互不重叠或指向errno。
 * @note 所有地址须存活/对齐；不冻结ABI/wire或私有布局，不提供跨进程总量。
 */
vireo_result_t vireo_rate_limiter_create(vireo_rate_limiter_options_t const *options,
    vireo_rate_limit_policy_t const *policies, size_t policy_count,
    vireo_monotonic_ns_t now, vireo_rate_limiter_t **out_limiter);

/**
 * @brief 先完整规划，全部额度和记录足够才一起扣费；初见键满额。
 * @param[in,out] limiter 必需有效对象，操作由caller独占或外部同步。
 * @param[in] now 同域非递减时间；相等允许，不能混用墙钟/重启时间域。
 * @param[in] requests 必需只读的完整批量，借用至返回，不保存地址。
 * @param[in] request_count 1..8，每项cost为1..对应burst。
 * @param[out] decision 必需独占输出，不与输入、对象或errno重叠。
 * @retval VIREO_OK 已判定，须按outcome分支；ADMITTED才扣费。
 * @retval VIREO_RESULT_INVALID_ARGUMENT NULL、零长度/id/cost、重复维度或时间后退。
 * @retval VIREO_RESULT_RANGE 批量超8或cost超burst。
 * @retval VIREO_RESULT_NOT_FOUND 非零policy_id未配置。
 * @note 先验证完整批量，再时间顺序。非OK保持整个对象/输出；合法check（含拒绝）
 *       推进last_now。THROTTLED/CAPACITY保持记录，不扣费/插入/回收，额度不足优先。
 * @note 非满桶保留补充余数；补满后丢弃多余额度和分数。仅可回收本批未引用、
 *       在now已补满的旧桶；无槽CAPACITY，不淘汰欠额或fail-open。
 * @note retry仅额度恢复提示，不预留额度/记录或保证下一次放行；只返回相对长度。
 * @note 保持errno；不分配/采时/IO/加锁/等待/回调，固定容量线性扫描，无硬实时保证。
 *       不识别身份、不选择业务额度、响应或KDF并发配额；不支持异步取消。
 */
vireo_result_t vireo_rate_limiter_check(vireo_rate_limiter_t *limiter,
    vireo_monotonic_ns_t now, vireo_rate_limit_request_t const *requests,
    size_t request_count, vireo_rate_limit_decision_t *decision);

/**
 * @brief 复制资源/时间水位快照，不推进时间或虚拟补充，不借出内部地址。
 * @param[in] limiter 必需存活对象，caller串行或外部同步。
 * @param[out] info 必需独占输出，不与对象或errno重叠。
 * @retval VIREO_OK 快照完整写入。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 必需地址NULL，保持输出。
 * @note 仅借至返回，无分配/IO，保持errno；快照不保证后续check一定成功。
 */
vireo_result_t vireo_rate_limiter_inspect(vireo_rate_limiter_t const *limiter,
    vireo_rate_limiter_info_t *info);

/**
 * @brief 所有访问结束后释放唯一owner，成功置NULL；空owner幂等。
 * @param[in,out] limiter 必需独占owner地址，*limiter允许NULL，不得指向errno。
 * @retval VIREO_OK 已释放/原本为空，*limiter为NULL。
 * @retval VIREO_RESULT_INVALID_ARGUMENT owner地址NULL。
 * @note 保持errno；caller先结束全部访问和借用，指针副本不保活对象。
 *       重建会重置欠额，不是运行中热更新或绕过限流的reset接口。
 */
vireo_result_t vireo_rate_limiter_destroy(vireo_rate_limiter_t **limiter);

#endif
