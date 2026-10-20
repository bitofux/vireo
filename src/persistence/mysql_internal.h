#ifndef VIREO_PERSISTENCE_MYSQL_INTERNAL_H
#define VIREO_PERSISTENCE_MYSQL_INTERNAL_H

#include <vireo/persistence/mysql.h>
#include <mysql.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>

/* own边界表由runtime复制；生产表不可变，测试替换真实失败边界，非公共ABI。
 * allocate/release须配对且线程安全，allocate返回malloc对齐的未初始化块。 */
typedef struct vireo_mysql_ops {
    void *(*allocate)(size_t bytes);
    void (*release)(void *memory);
    int (*signal_read)(int, const struct sigaction *, struct sigaction *);
    int (*library_init)(int, char **, char **);
    void (*library_end)(void);
    bool (*thread_init)(void);
    void (*thread_end)(void);
    MYSQL *(*init)(MYSQL *);
    int (*options)(MYSQL *, enum mysql_option, const void *);
    MYSQL *(*connect)(MYSQL *, const char *, const char *, const char *,
        const char *, unsigned int, const char *, unsigned long);
    int (*query)(MYSQL *, const char *);
    MYSQL_RES *(*store_result)(MYSQL *);
} vireo_mysql_ops_t;

struct vireo_mysql_runtime {
    pthread_t creator; /* 只允许creator结束全局库。 */
    atomic_size_t guards; /* 含构造预约；计数只保活，不代替管理入口同步。 */
    atomic_size_t pools; /* 全空池仍保活runtime。 */
    atomic_size_t connections; /* guard detach后仍独立保活。 */
    vireo_mysql_ops_t ops; /* 不可变副本。 */
};
struct vireo_mysql_thread {
    vireo_mysql_runtime_t *runtime; /* 保活借用。 */
    pthread_t owner; /* 与TLS槽共同验证，OS线程身份不可转移。 */
};
typedef struct vireo_mysql_session_ops {
    int (*reset)(MYSQL *);
    int (*select_database)(MYSQL *, const char *);
    int (*charset)(MYSQL *, const char *);
} vireo_mysql_session_ops_t;
extern const vireo_mysql_session_ops_t vireo_mysql_session_native_ops;
struct vireo_mysql_pool;
struct vireo_mysql_statement;
struct vireo_mysql_statement_ops;
struct vireo_mysql_connection {
    vireo_mysql_runtime_t *runtime; /* 独立登记，不借创建guard。 */
    struct vireo_mysql_pool *pool; /* 一经发布，归属不可转移。 */
    size_t pool_slot;
    const vireo_mysql_session_ops_t *session_ops; /* 私有原生清场失败边界。 */
    MYSQL *native; /* 唯一原生资源，不公开借用。 */
    vireo_mysql_connection_info_t info; /* 成功时快照。 */
    size_t statement_count; /* 连接图外部排他，受检保活计数。 */
    struct vireo_mysql_statement *active_statement; /* 未读或失败待清理者。 */
    bool unusable; /* 单向损坏门禁。 */
    const struct vireo_mysql_statement_ops *statement_ops; /* 私有不可变失败边界。 */
};

bool vireo_mysql_connection_access(const vireo_mysql_thread_t *thread,
    const vireo_mysql_connection_t *connection);
bool vireo_mysql_pool_connection_access(const vireo_mysql_thread_t *thread,
    const vireo_mysql_connection_t *connection);
vireo_result_t vireo_mysql_validate_options(const vireo_mysql_connection_options_t *options);
vireo_result_t vireo_mysql_connection_restore(vireo_mysql_connection_t *connection,
    const char *database, vireo_mysql_error_t *error);
void vireo_mysql_connection_dispose(vireo_mysql_connection_t *connection);
bool vireo_mysql_valid_guard(const vireo_mysql_thread_t *thread);
extern const struct vireo_mysql_statement_ops vireo_mysql_statement_native_ops;
extern const vireo_mysql_ops_t vireo_mysql_native_ops;
vireo_result_t vireo_mysql_runtime_create_with_ops(vireo_mysql_runtime_t **out,
    vireo_mysql_error_t *error, const vireo_mysql_ops_t *ops);
#endif
