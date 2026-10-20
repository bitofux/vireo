/*
 * PROJECT : VIREO
 * FILE    : mysql_migration_internal.h
 * AUTHOR  : bitofux
 * DATE    : 2026-10-18
 * BRIEF   : 迁移器私有公共资源操作边界，供own失败模型；不暴露原生驱动布局。
 */
#ifndef VIREO_PERSISTENCE_MYSQL_MIGRATION_INTERNAL_H
#define VIREO_PERSISTENCE_MYSQL_MIGRATION_INTERNAL_H
#include <vireo/persistence/mysql_migration.h>
#include <vireo/persistence/mysql_statement.h>
/* 各资源回调保留对应038公共接口合同；表和回调调用期不可变，禁止返回伪造owner。 */
typedef struct vireo_mysql_migration_ops {
    vireo_result_t (*open)(vireo_mysql_thread_t *, const vireo_mysql_connection_options_t *, vireo_mysql_connection_t **, vireo_mysql_error_t *);
    vireo_result_t (*close)(vireo_mysql_thread_t *, vireo_mysql_connection_t **);
    vireo_result_t (*prepare)(vireo_mysql_thread_t *, vireo_mysql_connection_t *, const char *, size_t, const vireo_mysql_statement_limits_t *, vireo_mysql_statement_t **, vireo_mysql_error_t *);
    vireo_result_t (*inspect)(vireo_mysql_thread_t *, const vireo_mysql_statement_t *, vireo_mysql_statement_info_t *);
    vireo_result_t (*execute)(vireo_mysql_thread_t *, vireo_mysql_statement_t *, const vireo_mysql_parameter_t *, size_t, vireo_mysql_execution_t *, vireo_mysql_error_t *);
    vireo_result_t (*fetch)(vireo_mysql_thread_t *, vireo_mysql_statement_t *, vireo_mysql_fetch_outcome_t *, vireo_mysql_error_t *);
    vireo_result_t (*column)(vireo_mysql_thread_t *, const vireo_mysql_statement_t *, size_t, vireo_mysql_cell_view_t *);
    vireo_result_t (*destroy)(vireo_mysql_thread_t *, vireo_mysql_statement_t **, vireo_mysql_error_t *);
    vireo_result_t (*hash)(const vireo_mysql_migration_t *, unsigned char [32]);
} vireo_mysql_migration_ops_t;
/* 生产只读表，不支持运行时替换或共享可变注入状态。 */
extern const vireo_mysql_migration_ops_t vireo_mysql_migration_native_ops;
/* 同apply合同，额外ops必需完整且在调用期存活；只供本模块边界测试。 */
vireo_result_t vireo_mysql_migration_apply_with_ops(vireo_mysql_thread_t *,
    const vireo_mysql_connection_options_t *, const vireo_mysql_migration_t *, size_t,
    vireo_mysql_migration_report_t *, vireo_mysql_migration_error_t *, const vireo_mysql_migration_ops_t *);
/* 已验证目录项；out至少32字节且不重叠，成功才写入；不承诺单独保持errno。 */
vireo_result_t vireo_mysql_migration_hash(const vireo_mysql_migration_t *, unsigned char [32]);
/* 已验证规范NUL结尾库名；out至少63字节且不重叠，成功写入62字符加NUL。 */
vireo_result_t vireo_mysql_migration_lock_name(const char *, char [63]);
#endif
