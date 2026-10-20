/*
 * PROJECT : VIREO
 * FILE    : mysql_migration.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-18
 * BRIEF   : 可信静态DDL目录的单库迁移；专用连接、版本校验和dirty失败停止。
 */
#ifndef VIREO_PERSISTENCE_MYSQL_MIGRATION_H
#define VIREO_PERSISTENCE_MYSQL_MIGRATION_H
#include <stdbool.h>
#include <stddef.h>
#include <vireo/persistence/mysql.h>

#define VIREO_MYSQL_MIGRATIONS_MAX 128 /**< 版本目录硬上限。 */
#define VIREO_MYSQL_MIGRATION_STEPS_MAX 64 /**< 每版本步骤上限。 */
#define VIREO_MYSQL_MIGRATION_TOTAL_STEPS_MAX 1024 /**< 全目录步骤上限。 */
#define VIREO_MYSQL_MIGRATION_SQL_BYTES_MAX 4194304 /**< 全目录SQL字节上限。 */

/** @brief 单条可信持久结构DDL的精确字节视图。 */
typedef struct vireo_mysql_migration_step {
    const char *sql; /**< 调用期只读短借；可信单条持久InnoDB结构DDL，无内嵌NUL。 */
    size_t sql_length; /**< 1..65536字节，不要求尾后NUL。 */
} vireo_mysql_migration_step_t;
/** @brief 一个不可改写的版本及其有序步骤。 */
typedef struct vireo_mysql_migration {
    uint32_t version; /**< 必须恰为数组索引+1，已发布版本不可修改。 */
    const vireo_mysql_migration_step_t *steps; /**< 非NULL有序数组，调用期间存活不变。 */
    size_t step_count; /**< 1..64，全部版本合计最多1024。 */
} vireo_mysql_migration_t;
/** @brief 首错误或清理错误阶段；不是SQL或业务操作码。 */
typedef enum vireo_mysql_migration_stage {
    VIREO_MYSQL_MIGRATION_STAGE_NONE, /**< 无失败阶段。 */
    VIREO_MYSQL_MIGRATION_STAGE_VALIDATE, /**< 检查全部输入，无数据库副作用。 */
    VIREO_MYSQL_MIGRATION_STAGE_HASH, /**< 计算目录hash和锁身份。 */
    VIREO_MYSQL_MIGRATION_STAGE_OPEN, /**< 打开自有专用连接。 */
    VIREO_MYSQL_MIGRATION_STAGE_LOCK, /**< 核当前库并尝试同库命名锁。 */
    VIREO_MYSQL_MIGRATION_STAGE_BOOTSTRAP, /**< 校验或建立版本表及其元数据形状。 */
    VIREO_MYSQL_MIGRATION_STAGE_HISTORY, /**< 逐行核对完整版本历史。 */
    VIREO_MYSQL_MIGRATION_STAGE_DIRTY, /**< 确认持久dirty记录。 */
    VIREO_MYSQL_MIGRATION_STAGE_STEP, /**< 顺序执行该版本DDL。 */
    VIREO_MYSQL_MIGRATION_STAGE_APPLIED, /**< 确认该版本完成标记。 */
    VIREO_MYSQL_MIGRATION_STAGE_UNLOCK, /**< 释放已取得的命名锁。 */
    VIREO_MYSQL_MIGRATION_STAGE_CLOSE /**< 关闭自有statement或连接。 */
} vireo_mysql_migration_stage_t;
/** @brief 无原始SQL/文本的逻辑诊断。 */
typedef enum vireo_mysql_migration_issue {
    VIREO_MYSQL_MIGRATION_ISSUE_NONE, /**< 无本层逻辑问题；仍可能有底层错误。 */
    VIREO_MYSQL_MIGRATION_ISSUE_DIRTY, /**< 存在未证明完成的dirty版本。 */
    VIREO_MYSQL_MIGRATION_ISSUE_CHECKSUM, /**< 历史校验值与当前精确目录不符。 */
    VIREO_MYSQL_MIGRATION_ISSUE_VERSION_AHEAD, /**< 数据库版本超过当前完整目录。 */
    VIREO_MYSQL_MIGRATION_ISSUE_HISTORY_SHAPE, /**< 历史缺口、状态或编码非法。 */
    VIREO_MYSQL_MIGRATION_ISSUE_METADATA_SHAPE, /**< 保留版本表的结构不兼容。 */
    VIREO_MYSQL_MIGRATION_ISSUE_UNTRACKED_SCHEMA, /**< 空历史或无历史但已有其他表或视图。 */
    VIREO_MYSQL_MIGRATION_ISSUE_UNEXPECTED_RESULT /**< 内部SQL返回的形状、行数或值不符合预期。 */
} vireo_mysql_migration_issue_t;
/** @brief 每次先清零；失败也可携带本次已确认进度，不推测丢失回复的提交。 */
typedef struct vireo_mysql_migration_report {
    bool history_validated; /**< 完整历史通过；false时零前缀不证明库为空。 */
    uint32_t applied_before; /**< 原已验证APPLIED连续前缀0..128。 */
    uint32_t applied_after; /**< 本次确认完成标记后的前缀，不推测断端提交。 */
    uint32_t migrations_applied; /**< 本次完成UPDATE成功响应数0..128。 */
    uint32_t steps_completed; /**< 本次DDL execute成功响应数0..1024，清理失败也保留。 */
    uint32_t failed_version; /**< 当前或可解析的失败版本；未知或目录全完成时为0。 */
    uint32_t failed_step; /**< STEP阶段1基步骤，其余0；不证明该步没有副作用。 */
    bool write_attempted; /**< 曾进入迁移写execute；不证明提交或回滚。 */
    bool ready; /**< 仅整个入口OK时true。 */
    bool connection_closed; /**< 已open的专用连接在本地完成关闭，不推导远端锁释放时刻。 */
} vireo_mysql_migration_report_t;
/** @brief 首失败与首清理失败的独立无秘密诊断值。 */
typedef struct vireo_mysql_migration_error {
    vireo_mysql_migration_stage_t stage; /**< 首失败阶段，成功NONE。 */
    vireo_mysql_migration_issue_t issue; /**< 逻辑原因，无则NONE。 */
    vireo_mysql_error_t database; /**< 首因的无文本原生码，无则零。 */
    vireo_result_t cleanup_result; /**< 首清理错误，无则OK，不覆盖主因。 */
    vireo_mysql_migration_stage_t cleanup_stage; /**< 首清理失败UNLOCK/CLOSE，无则NONE。 */
    vireo_mysql_error_t cleanup_database; /**< 首清理错误原生码，无则零。 */
} vireo_mysql_migration_error_t;

/**
 * @brief 在业务准入前或停写维护期间同步校验并应用完整静态迁移目录。
 *
 * 每版本SHA-256编码为ASCII域vireo.mysql.migration.v1加一个NUL、u32be版本、
 * u32be步骤数及每步u32be长度/精确字节。历史只能追加；dirty/hash不符/超前停止。
 * MySQL多条DDL不构成共同事务；无自动重试、回退、repair或清dirty。
 *
 * @param[in] thread
 *     必需当前OS线程同runtime有效guard；调用期间不可detach或结束runtime。
 * @param[in] connection
 *     必需显式options，字符串仅调用期短借；database须1..64字节，首a..z，
 *     其余a..z/0..9/下划线；账号须目标schema结构读写权限和充分元数据可见性。
 * @param[in] migrations
 *     只读短借完整目录，count为0允许NULL，否则必需；全目录SQL最多4MiB。
 *     仅可信CREATE TABLE/ALTER TABLE/CREATE INDEX；禁止TEMPORARY、跨库、
 *     更改事务/会话/锁、业务DML、操作版本表、IF NOT EXISTS或外部输入。
 *     这些是受审阅的目录前置，不提供SQL沙箱；每步须零marker、无结果。
 * @param[in] migration_count
 *     0..128，版本必须恰为1..count；空目录仍可建立空版本表。
 * @param[out] out_report
 *     必需caller独占值，每次先清零，失败也可更新确认进度。
 * @param[out] error
 *     可选caller独占无秘密诊断，每次重置；首因与首清理错误分开。
 *
 * @retval VIREO_OK
 *     目录全完成且正常解锁/关闭，ready=true；重复调用不重放已应用DDL。
 * @retval VIREO_RESULT_INVALID_ARGUMENT
 *     必需地址/guard/库名/数组/版本序列/SQL/NUL/空版本非法。
 * @retval VIREO_RESULT_RANGE
 *     目录/步骤/SQL或底层statement/结果超过硬界。
 * @retval VIREO_RESULT_OVERFLOW
 *     checked算术/窄化或底层计数不能表示。
 * @retval VIREO_RESULT_NO_MEMORY
 *     wrapper或EVP上下文申请失败。
 * @retval VIREO_RESULT_BUSY
 *     同库协作锁零等待未取得，不执行迁移写。
 * @retval VIREO_RESULT_CANCELLED
 *     底层损坏连接门禁，不自动重连。
 * @retval VIREO_RESULT_DATABASE
 *     数据库失败、元数据/历史不兼容、dirty/hash不符/版本超前或未知基线。
 * @retval VIREO_RESULT_INTERNAL
 *     EVP计算或本层不变量失败。
 *
 * @note 所有权：自开专用连接/语句并全部关闭，不借池，不发布owner，不保存caller地址。
 * @note 线程安全：各调用使用各自guard和连接；同规范库名只协调单mysqld协作者。
 *       不阻止旧业务/DBA写入，不提供在线滚动升级或分布式协调。
 * @note errno保持；所有地址须存活、对齐、互不覆盖且不指向errno。可能分配/阻塞，
 *       不在Reactor热路径运行；阶段socket超时不是整次迁移硬期限，不支持线程取消。
 * @note 首步前dirty INSERT须成功确认；DDL/完成标记回复未知时不推测提交或自动重放。
 *       命名锁在服务端观察连接结束后释放，本地关闭不证明远端立即释放。
 */
vireo_result_t vireo_mysql_migration_apply(vireo_mysql_thread_t *thread,
    const vireo_mysql_connection_options_t *connection,
    const vireo_mysql_migration_t *migrations, size_t migration_count,
    vireo_mysql_migration_report_t *out_report, vireo_mysql_migration_error_t *error);
#endif
