/* 有界MySQL连接池；原生连接只通过同线程独占租约短借。 */
#ifndef VIREO_PERSISTENCE_MYSQL_POOL_H
#define VIREO_PERSISTENCE_MYSQL_POOL_H
#include <vireo/persistence/mysql.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VIREO_MYSQL_POOL_CAPACITY_MAX ((size_t)64)
#define VIREO_MYSQL_POOL_WAITERS_MAX ((size_t)1024)
#define VIREO_MYSQL_POOL_MEMORY_MAX ((size_t)4194304)
#define VIREO_MYSQL_POOL_WAIT_MS_MAX UINT32_C(60000)

typedef struct vireo_mysql_pool vireo_mysql_pool_t;
/** 创建时短借并复制全部连接字符串；密码副本保留至destroy供显式refill使用。 */
typedef struct vireo_mysql_pool_options {
    vireo_mysql_connection_options_t connection; /**< 沿用独立连接的显式Unix socket/基线合同。 */
    size_t capacity; /**< 固定预建连接数1..64。 */
    size_t max_waiters; /**< 实际等待者上限0..1024，0仍允许立即借用。 */
    size_t max_memory_bytes; /**< 1..4MiB，仅控制块/槽/字符串，不含连接、原生资源、栈或RSS。 */
} vireo_mysql_pool_options_t;
/** 唯一权威token；普通复制只借身份，不复制归还责任。全零为空，池必须仍存活。 */
typedef struct vireo_mysql_lease {
    vireo_mysql_pool_t *owner; /**< 所属池。 */
    size_t slot; /**< 从0开始的槽索引。 */
    uint64_t generation; /**< 非零代际；UINT64_MAX本次仍有效，归还永久退休。 */
} vireo_mysql_lease_t;
typedef struct vireo_mysql_pool_acquisition {
    bool acquired; /**< 已提交lease，即使后续unlock失败也承担归还责任。 */
} vireo_mysql_pool_acquisition_t;
typedef struct vireo_mysql_pool_release {
    bool released; /**< 已消费权威lease，后续错误不能重复归还。 */
    bool reusable; /**< 曾发布IDLE的历史事实，不是返回时健康保证。 */
} vireo_mysql_pool_release_t;
typedef struct vireo_mysql_pool_refill {
    bool restored; /**< 曾发布一个新IDLE的历史事实。 */
} vireo_mysql_pool_refill_t;
typedef enum vireo_mysql_pool_disposition {
    VIREO_MYSQL_POOL_RECYCLE, /**< reset、选库、utf8mb4及基线恢复核验后复用。 */
    VIREO_MYSQL_POOL_DISCARD /**< 关闭，不重试业务或自动补槽。 */
} vireo_mysql_pool_disposition_t;
typedef enum vireo_mysql_pool_state {
    VIREO_MYSQL_POOL_OPEN, VIREO_MYSQL_POOL_CLOSED /**< 永久关闭。 */
} vireo_mysql_pool_state_t;
/** 同锁快照；六槽计数之和恒等capacity。无凭据/地址/无界累计统计。 */
typedef struct vireo_mysql_pool_info {
    vireo_mysql_pool_state_t state; /**< 池状态。 */
    size_t capacity; /**< 槽总数。 */
    size_t idle; /**< 可立即借用。 */
    size_t leased; /**< 已授予租约。 */
    size_t returning; /**< 锁外清场中。 */
    size_t vacant; /**< 缺连接，可显式refill。 */
    size_t refilling; /**< 锁外建连中。 */
    size_t retired; /**< 代际耗尽，永久不可补。 */
    size_t waiters; /**< 已登记等待者。 */
    size_t max_waiters; /**< 等待配额。 */
    size_t high_watermark; /**< 同时LEASED数的历史峰值。 */
    size_t allocated_bytes; /**< 池容器实际请求字节，不含独立connection wrapper。 */
} vireo_mysql_pool_info_t;
typedef enum vireo_mysql_pool_stage {
    VIREO_MYSQL_POOL_STAGE_NONE, VIREO_MYSQL_POOL_STAGE_ALLOCATE,
    VIREO_MYSQL_POOL_STAGE_INITIALIZE, VIREO_MYSQL_POOL_STAGE_LOCK,
    VIREO_MYSQL_POOL_STAGE_CLOCK, VIREO_MYSQL_POOL_STAGE_WAIT,
    VIREO_MYSQL_POOL_STAGE_SIGNAL, VIREO_MYSQL_POOL_STAGE_UNLOCK,
    VIREO_MYSQL_POOL_STAGE_OPEN, VIREO_MYSQL_POOL_STAGE_RESET,
    VIREO_MYSQL_POOL_STAGE_SESSION, VIREO_MYSQL_POOL_STAGE_CLEANUP,
    VIREO_MYSQL_POOL_STAGE_DESTROY
} vireo_mysql_pool_stage_t;
/** 每次先清零；不保存SQL、密码或原生错误文本；主失败优先于清理失败。 */
typedef struct vireo_mysql_pool_error {
    vireo_mysql_pool_stage_t stage; /**< 本层失败阶段。 */
    int pthread_code; /**< pthread直接返回值，不能当作errno读取。 */
    int system_error; /**< 仅POSIX调用的真实errno。 */
    vireo_mysql_error_t database; /**< 原生无文本诊断副本。 */
} vireo_mysql_pool_error_t;

/**
 * @brief 顺序预建全部连接，成功才发布唯一pool owner。
 * @param thread 当前线程attached guard；与池管理同runtime。
 * @param options 非NULL；connection选项沿用mysql.h。全部字符串被复制。
 * @param out_pool 非NULL且初值NULL；失败不写。
 * @param error 可NULL，先清零。
 * @return OK；INVALID_ARGUMENT零容量/预算或地址/guard/owner错误；OVERFLOW布局或登记溢出；
 * RANGE超硬界/预算；NO_MEMORY申请/初始化ENOMEM；DATABASE建连失败；INTERNAL同步失败。
 * @note 本头八入口均保持errno。所有地址须存活、对齐、互不覆盖且不指向errno。
 * pool创建发布/owner销毁须外部排他；共享操作内部同步。无pthread_cancel支持。
 * 回滚/destroy擦池自有字符串区，不承诺驱动/系统副本全部擦除。
 */
vireo_result_t vireo_mysql_pool_create(vireo_mysql_thread_t *thread,
    const vireo_mysql_pool_options_t *options, vireo_mysql_pool_t **out_pool,
    vireo_mysql_pool_error_t *error);
/**
 * @brief 借空闲槽，不ping/建连/执行业务SQL。
 * @param thread 当前OS线程同runtime guard；租约只能由该线程使用/归还。
 * @param pool 存活池。
 * @param timeout_ms 0..60000；0不等待。正值使用一次MONOTONIC绝对期限，虚假唤醒不延期。
 * @param out_lease 非NULL、初值全零；提交后即使非OK也写并转移责任。
 * @param out_acquisition 必需，每次先清零；acquired决定是否已授予。
 * @param error 可NULL，先清零。
 * @return OK；INVALID_ARGUMENT地址/guard/token；RANGE超期限界；BUSY无槽且零等/配额满；
 * TIMEOUT到期；OVERFLOW全槽退休；CANCELLED关闭/开始销毁；IO时钟；INTERNAL同步异常。
 * @note 初次有IDLE立即授予；等待唤醒后关闭优先，到期不再授予。无FIFO/无饥饿保证。
 * 等待期限不约束mutex调度、SQL、reset或refill总耗时，不供Reactor等待数据库。
 */
vireo_result_t vireo_mysql_pool_acquire(vireo_mysql_thread_t *thread,
    vireo_mysql_pool_t *pool, uint32_t timeout_ms, vireo_mysql_lease_t *out_lease,
    vireo_mysql_pool_acquisition_t *out_acquisition, vireo_mysql_pool_error_t *error);
/**
 * @brief 同租借线程检查身份后短借connection；允许关闭后的有效租约完成清理。
 * @param thread 当前线程同runtime guard。
 * @param pool 存活池。
 * @param lease 非空身份；形状检查后先查代际/状态，再查线程。
 * @param out_connection 非NULL，只有OK写；不是独立owner，不可覆盖待销毁owner。
 * @return OK；INVALID_ARGUMENT地址/形状/错池/线程/guard；NOT_FOUND已归还或过期；
 * CANCELLED同步销毁已开始；INTERNAL同步异常。
 * @note 短借不能connection_destroy（BUSY）；归还后裸指针失效，不能检测任意悬空指针。
 */
vireo_result_t vireo_mysql_pool_borrow(vireo_mysql_thread_t *thread,
    vireo_mysql_pool_t *pool, const vireo_mysql_lease_t *lease,
    vireo_mysql_connection_t **out_connection);
/**
 * @brief 消费租约后锁外清场，成功才发布IDLE；损坏/关闭/DISCARD则关闭连接。
 * @param thread 租借OS线程同runtime guard；全零lease允许NULL。
 * @param pool 存活池；全零lease允许NULL。
 * @param lease 唯一权威存储；提交RETURNING即清零，报告released=true。
 * @param disposition RECYCLE或DISCARD；先销毁所有statement/结束借用视图和SQL。
 * @param out_release 必需，每次先清零。全零lease幂等OK。
 * @param error 可NULL，先清零；清场失败保留首诊断并淘汰连接。
 * @return OK；INVALID_ARGUMENT地址/形状/线程/guard/枚举；NOT_FOUND旧身份；
 * BUSY仍有statement（保持token，即使关闭/损坏）；CANCELLED部分销毁；DATABASE清场；INTERNAL同步。
 * @note released=true即不可重归还。RECYCLE不替代业务COMMIT，不重试业务；MySQL在锁外。
 */
vireo_result_t vireo_mysql_pool_release(vireo_mysql_thread_t *thread,
    vireo_mysql_pool_t *pool, vireo_mysql_lease_t *lease,
    vireo_mysql_pool_disposition_t disposition, vireo_mysql_pool_release_t *out_release,
    vireo_mysql_pool_error_t *error);
/**
 * @brief 预约一个VACANT，锁外按自有配置建连一次，无后台重试。
 * @param thread 当前线程同runtime guard。
 * @param pool 存活池。
 * @param out_refill 必需，每次先清零；restored表示已发布IDLE。
 * @param error 可NULL，先清零。
 * @return OK；INVALID_ARGUMENT地址/guard；BUSY无VACANT；CANCELLED关闭/部分销毁；
 * OVERFLOW连接登记；NO_MEMORY申请；DATABASE建连；INTERNAL同步。
 * @note 建连中close会在锁外关闭新连接，回VACANT且restored=false/CANCELLED。
 */
vireo_result_t vireo_mysql_pool_refill(vireo_mysql_thread_t *thread,
    vireo_mysql_pool_t *pool, vireo_mysql_pool_refill_t *out_refill,
    vireo_mysql_pool_error_t *error);
/**
 * @brief 无需guard，同锁读取12字段快照，不做MySQL I/O。
 * @param pool 存活池。
 * @param out_info 非NULL，仅OK写。
 * @return OK；INVALID_ARGUMENT地址；CANCELLED部分销毁；INTERNAL同步。
 * @note thread-safe但并非无锁或硬实时；需与最终destroy外部排他。
 */
vireo_result_t vireo_mysql_pool_inspect(const vireo_mysql_pool_t *pool,
    vireo_mysql_pool_info_t *out_info);
/**
 * @brief 永久关闭并广播；不等待SQL、不关闭IDLE、不撤销有效租约。
 * @param pool 存活池。
 * @param out_closed 必需，先false；关闭提交/原已关闭则true，即使后续通知/unlock失败。
 * @param error 可NULL，先清零。
 * @return OK；INVALID_ARGUMENT地址；CANCELLED部分销毁；INTERNAL同步。
 * @note 由管理方协作退出/join全部worker，然后destroy；不支持异步取消。
 */
vireo_result_t vireo_mysql_pool_close(vireo_mysql_pool_t *pool,
    bool *out_closed, vireo_mysql_pool_error_t *error);
/**
 * @brief 静止管理上下文关闭剩余连接并分阶段销毁同步设施/擦凭据/清owner。
 * @param thread 当前同runtime guard；空owner允许NULL。
 * @param pool 非NULL唯一owner地址；空owner幂等OK，未最终free则保持owner。
 * @param error 可NULL，先清零。
 * @return OK；INVALID_ARGUMENT地址/guard；BUSY未关闭或有leased/returning/refilling/waiters；
 * INTERNAL同步销毁失败（保存进度，只能静止后继续destroy）。
 * @note 调用者必须停止/join所有潜在访问者，计数为零不构成并发destroy许可。
 * 同步异常不承诺一般恢复/强行free/死锁自由；按提交报告保留真实责任。
 */
vireo_result_t vireo_mysql_pool_destroy(vireo_mysql_thread_t *thread,
    vireo_mysql_pool_t **pool, vireo_mysql_pool_error_t *error);
#endif
