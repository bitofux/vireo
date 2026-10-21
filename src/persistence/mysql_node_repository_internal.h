/* PROJECT : VIREO; FILE : mysql_node_repository_internal.h;
 * AUTHOR : bitofux; DATE : 2026-10-21; BRIEF : 本模块独占故障边界，不修改全局ops。 */
#ifndef VIREO_PERSISTENCE_MYSQL_NODE_REPOSITORY_INTERNAL_H
#define VIREO_PERSISTENCE_MYSQL_NODE_REPOSITORY_INTERNAL_H
#include <time.h>
#include <vireo/persistence/mysql_node_repository.h>
#include <vireo/persistence/mysql_statement.h>
typedef struct vireo_mysql_node_ops {
    void *(*allocate)(size_t);
    void (*free_memory)(void *);
    vireo_result_t (*acquire)(vireo_mysql_thread_t *, vireo_mysql_pool_t *, uint32_t,
        vireo_mysql_lease_t *, vireo_mysql_pool_acquisition_t *, vireo_mysql_pool_error_t *);
    vireo_result_t (*borrow)(vireo_mysql_thread_t *, vireo_mysql_pool_t *,
        const vireo_mysql_lease_t *, vireo_mysql_connection_t **);
    vireo_result_t (*release)(vireo_mysql_thread_t *, vireo_mysql_pool_t *, vireo_mysql_lease_t *,
        vireo_mysql_pool_disposition_t, vireo_mysql_pool_release_t *, vireo_mysql_pool_error_t *);
    vireo_result_t (*prepare)(vireo_mysql_thread_t *, vireo_mysql_connection_t *, const char *,
        size_t, const vireo_mysql_statement_limits_t *, vireo_mysql_statement_t **, vireo_mysql_error_t *);
    vireo_result_t (*execute)(vireo_mysql_thread_t *, vireo_mysql_statement_t *,
        const vireo_mysql_parameter_t *, size_t, vireo_mysql_execution_t *, vireo_mysql_error_t *);
    vireo_result_t (*fetch)(vireo_mysql_thread_t *, vireo_mysql_statement_t *,
        vireo_mysql_fetch_outcome_t *, vireo_mysql_error_t *);
    vireo_result_t (*column)(vireo_mysql_thread_t *, const vireo_mysql_statement_t *,
        size_t, vireo_mysql_cell_view_t *);
    vireo_result_t (*close)(vireo_mysql_thread_t *, vireo_mysql_statement_t **, vireo_mysql_error_t *);
    int (*utc)(struct timespec *);
} vireo_mysql_node_ops_t;
extern const vireo_mysql_node_ops_t vireo_mysql_node_native_ops;
vireo_result_t vireo_mysql_node_repository_create_with_ops(vireo_mysql_thread_t *,
    vireo_mysql_pool_t *, vireo_mysql_node_repository_t **, vireo_mysql_node_error_t *,
    const vireo_mysql_node_ops_t *);
#endif
