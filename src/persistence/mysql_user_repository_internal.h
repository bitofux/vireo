#ifndef VIREO_PERSISTENCE_MYSQL_USER_REPOSITORY_INTERNAL_H
#define VIREO_PERSISTENCE_MYSQL_USER_REPOSITORY_INTERNAL_H
#include <vireo/persistence/mysql_user_repository.h>
#include <vireo/persistence/mysql_statement.h>

/* 每个对象复制的真实资源调用边界，仅own测试替换；不改全局表。 */
typedef struct vireo_mysql_user_repository_ops {
    void *(*allocate)(size_t);
    void (*release_memory)(void *);
    vireo_result_t (*acquire)(vireo_mysql_thread_t *, vireo_mysql_pool_t *, uint32_t,
        vireo_mysql_lease_t *, vireo_mysql_pool_acquisition_t *, vireo_mysql_pool_error_t *);
    vireo_result_t (*borrow)(vireo_mysql_thread_t *, vireo_mysql_pool_t *,
        const vireo_mysql_lease_t *, vireo_mysql_connection_t **);
    vireo_result_t (*release)(vireo_mysql_thread_t *, vireo_mysql_pool_t *,
        vireo_mysql_lease_t *, vireo_mysql_pool_disposition_t,
        vireo_mysql_pool_release_t *, vireo_mysql_pool_error_t *);
    vireo_result_t (*prepare)(vireo_mysql_thread_t *, vireo_mysql_connection_t *,
        const char *, size_t, const vireo_mysql_statement_limits_t *,
        vireo_mysql_statement_t **, vireo_mysql_error_t *);
    vireo_result_t (*execute)(vireo_mysql_thread_t *, vireo_mysql_statement_t *,
        const vireo_mysql_parameter_t *, size_t, vireo_mysql_execution_t *, vireo_mysql_error_t *);
    vireo_result_t (*close)(vireo_mysql_thread_t *, vireo_mysql_statement_t **, vireo_mysql_error_t *);
    vireo_result_t (*fetch)(vireo_mysql_thread_t *, vireo_mysql_statement_t *,
        vireo_mysql_fetch_outcome_t *, vireo_mysql_error_t *);
    vireo_result_t (*column)(vireo_mysql_thread_t *, const vireo_mysql_statement_t *,
        size_t, vireo_mysql_cell_view_t *);
} vireo_mysql_user_repository_ops_t;
extern const vireo_mysql_user_repository_ops_t vireo_mysql_user_repository_native_ops;
vireo_result_t vireo_mysql_user_repository_create_with_ops(vireo_mysql_thread_t *thread,
    vireo_mysql_pool_t *pool, const vireo_password_policy_t *policy,
    vireo_mysql_user_repository_t **out, vireo_mysql_user_repository_error_t *error,
    const vireo_mysql_user_repository_ops_t *ops);
#endif
