/* PROJECT: VIREO; FILE: auth_failure_audit.h; AUTHOR: bitofux; DATE: 2026-10-20.
 * 固定容量、双令牌桶、允许丢失的认证失败事件；不持网络或DB资源。 */
#ifndef VIREO_SERVICE_AUTH_FAILURE_AUDIT_H
#define VIREO_SERVICE_AUTH_FAILURE_AUDIT_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <vireo/base/result.h>

typedef enum vireo_auth_failure_origin {
    VIREO_AUTH_FAILURE_REACTOR = 1,
    VIREO_AUTH_FAILURE_WORKER = 2
} vireo_auth_failure_origin_t;

/* 全部独立值；origin决定request_id为零/非零，padding不序列化。 */
typedef struct vireo_auth_failure_event {
    unsigned char request_id[16]; /* Reactor全零；worker已有可信非零ID。 */
    uint64_t occurred_at_ms; /* 服务端UTC样本，不是写入时刻。 */
    uint64_t latency_us; /* 截止原采样点，非端到端；Reactor未建立样本为0。 */
    uint16_t action; /* schema1..4，不是wire command。 */
    uint16_t status; /* 原认证投影的十个失败status白名单。 */
    uint8_t origin; /* 1..2。 */
} vireo_auth_failure_event_t;

typedef struct vireo_auth_failure_audit vireo_auth_failure_audit_t;
typedef struct vireo_auth_failure_audit_options {
    size_t capacity; /* 1..1024；生产256。 */
    size_t max_memory_bytes; /* 整个队列申请预算，1..1MiB；生产64KiB。 */
    uint64_t burst; /* 1..256；生产8。 */
    uint64_t refill_ns; /* 1..60000000000；生产1000000000。 */
} vireo_auth_failure_audit_options_t;

typedef enum vireo_auth_failure_disposition {
    VIREO_AUTH_FAILURE_QUEUED = 1,
    VIREO_AUTH_FAILURE_DROP_RATE,
    VIREO_AUTH_FAILURE_DROP_FULL,
    VIREO_AUTH_FAILURE_DROP_CONTENTION,
    VIREO_AUTH_FAILURE_DROP_CLOSED,
    VIREO_AUTH_FAILURE_DROP_DISABLED
} vireo_auth_failure_disposition_t;

typedef enum vireo_auth_failure_close_reason {
    VIREO_AUTH_FAILURE_STOP = 1,
    VIREO_AUTH_FAILURE_DISABLE = 2
} vireo_auth_failure_close_reason_t;

typedef struct vireo_auth_failure_audit_info {
    size_t capacity, depth; /* mutex下的一致队列观察；不计writer手中至多1条。 */
    bool closed, disabled;
    uint64_t queued, taken, dropped_rate, dropped_full, dropped_contention;
    uint64_t dropped_closed, dropped_disabled, discarded_on_close;
    /* 独立原子观测模2^64；writer提交统计另在应用report，不靠这些数授权。 */
} vireo_auth_failure_audit_info_t;

/**
 * @brief 一次分配固定队列，准备互斥锁和单调条件变量
 * @param[in] options 必需独立只读配置；capacity1..1024，预算≤1MiB，burst1..256，refill1..60e9ns。
 * @param[in] now_ns 可信MONOTONIC初始纳秒，0合法；不能传客户端时间。
 * @param[out] owner 必需独占空owner地址；仅成功发布，失败保持。
 * @retval VIREO_OK 已完整初始化；未启动线程或访问DB。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 必需NULL或非空owner。
 * @retval VIREO_RESULT_RANGE 配置越界或固定分配超预算。
 * @retval VIREO_RESULT_NO_MEMORY 单次固定分配失败。
 * @retval VIREO_RESULT_INTERNAL 平台原子非lock-free或同步初始化失败。
 * @note 装配线程排他使用，失败逆序清理；保持errno。全部地址有效、对齐、互不重叠且不指向errno。
 */
vireo_result_t vireo_auth_failure_audit_create(
    vireo_auth_failure_audit_options_t const *options, uint64_t now_ns,
    vireo_auth_failure_audit_t **owner);

/**
 * @brief 多producer最多一次trylock，复制一条去敏事件或显式丢弃
 * @param[in,out] audit 必需存活已发布队列；借用持续至返回。
 * @param[in] event 必需独立纯值；action1..4，十个失败status，origin1/2；Reactor ID零、worker ID非零。
 * @param[in] now_ns 可信MONOTONIC纳秒，乱序保持桶时间高水位。
 * @param[out] disposition 必需独立输出；非OK保持，QUEUED说明字段复制已经结束。
 * @retval VIREO_OK 有效offer已分类；丢弃也是OK，不表示写入数据库。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 必需NULL或字段形态非法。
 * @retval VIREO_RESULT_INTERNAL 真实trylock返回EBUSY以外的同步错误。
 * @note 不等待锁、不分配、不访问随机源/DB。依次检查禁用/关闭/补充/速率/满；只成功入队收费。
 *     QUEUED后caller可立即修改/结束原event寿命；竞争只计丢弃，不补投。保持errno；地址独立有效。
 */
vireo_result_t vireo_auth_failure_audit_try_offer(
    vireo_auth_failure_audit_t *audit, vireo_auth_failure_event_t const *event,
    uint64_t now_ns, vireo_auth_failure_disposition_t *disposition);

/**
 * @brief 单writer等待非空和独立消费许可，take一条并擦除槽
 * @param[in,out] audit 必需存活队列；只允许一个consumer，禁止POSIX取消。
 * @param[out] event 必需独立存活输出；只有OK复制事件，所有非OK保持旧值。
 * @retval VIREO_OK 已取得独立事件并消费一个许可；不表示SQL执行或提交。
 * @retval VIREO_RESULT_NOT_FOUND 已关闭，未转移事件。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 必需NULL。
 * @retval VIREO_RESULT_OVERFLOW 单调定时等待截止值不可表示。
 * @retval VIREO_RESULT_INTERNAL 同步操作或原公开时钟失败。
 * @return 公开单调采时的其他原错误透传。
 * @note 空OPEN等待条件变量；有事件但无许可用MONOTONIC定时等待，醒来重查谓词。
 *     两桶独立信用、满桶丢弃余数；消费许可的界限不代表调度延后后的SQL开始时刻界限。
 *     close广播可唤醒空等和许可等待；保持errno。地址有效、对齐且互不重叠。
 */
vireo_result_t vireo_auth_failure_audit_wait_take(
    vireo_auth_failure_audit_t *audit, vireo_auth_failure_event_t *event);

/**
 * @brief 管理方或writer永久关闭，放弃未take积压并广播唤醒
 * @param[in,out] audit 必需存活对象；可以短暂等待mutex。
 * @param[in] reason STOP或DISABLE；已CLOSED可升级DISABLED，不重新开放。
 * @retval VIREO_OK 待取事件已清零并计入丢弃；重复关闭不重计。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 必需NULL或reason非法。
 * @retval VIREO_RESULT_INTERNAL mutex操作失败。
 * @note 不终止writer手中的至多一条，不join；以锁内线性化点与offer排序。保持errno。
 */
vireo_result_t vireo_auth_failure_audit_close(
    vireo_auth_failure_audit_t *audit, vireo_auth_failure_close_reason_t reason);

/**
 * @brief 观察去敏队列状态与模2^64统计
 * @param[in] audit 必需存活对象，观察期间依赖仍须存在。
 * @param[out] out 必需独立输出，非OK保持。
 * @retval VIREO_OK depth/state来自同一临界区；独立原子不承诺同瞬间快照。
 * @retval VIREO_RESULT_INVALID_ARGUMENT 必需NULL。
 * @retval VIREO_RESULT_INTERNAL 同步错误。
 * @note 可能短暂等锁；计数仅观测，不参与授权/信用/身份。保持errno；地址互不重叠。
 */
vireo_result_t vireo_auth_failure_audit_inspect(
    vireo_auth_failure_audit_t const *audit, vireo_auth_failure_audit_info_t *out);

/**
 * @brief 全部访问者退出后排他消耗已关闭owner
 * @param[in,out] owner 必需独占owner地址，*owner可NULL；全部释放才置NULL。
 * @retval VIREO_OK owner已消耗或原为空。
 * @retval VIREO_RESULT_INVALID_ARGUMENT owner为NULL。
 * @retval VIREO_RESULT_BUSY 队列尚未close。
 * @retval VIREO_RESULT_INTERNAL 同步资源销毁失败，保实际残留；仅允许再次destroy。
 * @note caller先close并join所有producer/consumer；不是自动join或跨线程关闭屏障。
 *     部分销毁保完成标志，不重复destroy已消耗资源。保持errno；禁POSIX取消。
 */
vireo_result_t vireo_auth_failure_audit_destroy(vireo_auth_failure_audit_t **owner);


#endif
