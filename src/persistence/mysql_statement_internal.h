#ifndef VIREO_PERSISTENCE_MYSQL_STATEMENT_INTERNAL_H
#define VIREO_PERSISTENCE_MYSQL_STATEMENT_INTERNAL_H
#include "mysql_internal.h"
#include <vireo/persistence/mysql_statement.h>

/* 仅own测试替换，连接图存活期间不可变；生产不公开原生类型。 */
typedef struct vireo_mysql_statement_ops {
    MYSQL_STMT *(*init)(MYSQL *);
    int (*prepare)(MYSQL_STMT *, const char *, unsigned long);
    unsigned long (*param_count)(MYSQL_STMT *);
    unsigned int (*field_count)(MYSQL_STMT *);
    MYSQL_RES *(*metadata)(MYSQL_STMT *);
    unsigned int (*num_fields)(MYSQL_RES *);
    void (*metadata_free)(MYSQL_RES *);
    bool (*bind_param)(MYSQL_STMT *, MYSQL_BIND *);
    bool (*bind_result)(MYSQL_STMT *, MYSQL_BIND *);
    int (*execute)(MYSQL_STMT *);
    int (*fetch)(MYSQL_STMT *);
    bool (*free_result)(MYSQL_STMT *);
    bool (*reset)(MYSQL_STMT *);
    bool (*close)(MYSQL_STMT *);
    unsigned int (*stmt_errno)(MYSQL_STMT *);
    const char *(*stmt_sqlstate)(MYSQL_STMT *);
    unsigned int (*conn_errno)(MYSQL *);
    const char *(*conn_sqlstate)(MYSQL *);
    bool (*more_results)(MYSQL *);
    my_ulonglong (*affected_rows)(MYSQL_STMT *);
    my_ulonglong (*insert_id)(MYSQL_STMT *);
} vireo_mysql_statement_ops_t;

typedef union vireo_mysql_number {
    int64_t i64;
    uint64_t u64;
} vireo_mysql_number_t;
struct vireo_mysql_statement {
    vireo_mysql_connection_t *connection; /* pin，非创建guard。 */
    MYSQL_STMT *native;
    vireo_mysql_statement_limits_t limits;
    vireo_mysql_statement_info_t info;
    MYSQL_BIND parameters[VIREO_MYSQL_PARAMETERS_MAX];
    MYSQL_BIND columns[VIREO_MYSQL_COLUMNS_MAX];
    vireo_mysql_number_t numbers[VIREO_MYSQL_PARAMETERS_MAX];
    unsigned long parameter_lengths[VIREO_MYSQL_PARAMETERS_MAX];
    unsigned long column_lengths[VIREO_MYSQL_COLUMNS_MAX];
    bool parameter_nulls[VIREO_MYSQL_PARAMETERS_MAX];
    bool column_nulls[VIREO_MYSQL_COLUMNS_MAX];
    bool column_errors[VIREO_MYSQL_COLUMNS_MAX];
    unsigned char bytes[]; /* 参数区，随后max_columns个(cell+1)区。 */
};
/* 纯布局边界供own测试不可表示算术，无公共ABI。 */
vireo_result_t vireo_mysql_statement_layout(size_t parameters, size_t columns,
    size_t cell, size_t *out_bytes);
vireo_result_t vireo_mysql_statement_native_length(size_t value, unsigned long *out);
#endif
