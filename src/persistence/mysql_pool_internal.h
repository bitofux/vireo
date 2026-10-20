#ifndef VIREO_PERSISTENCE_MYSQL_POOL_INTERNAL_H
#define VIREO_PERSISTENCE_MYSQL_POOL_INTERNAL_H
#include "mysql_internal.h"
#include <vireo/persistence/mysql_pool.h>
#include <time.h>
/* 私有own边界；生产副本不可变。注入须规定真实锁副作用。 */
typedef struct vireo_mysql_pool_ops {
    int (*mutex_init)(pthread_mutex_t *, const pthread_mutexattr_t *);
    int (*mutex_destroy)(pthread_mutex_t *);
    int (*lock)(pthread_mutex_t *);
    int (*unlock)(pthread_mutex_t *);
    int (*attr_init)(pthread_condattr_t *);
    int (*attr_clock)(pthread_condattr_t *, clockid_t);
    int (*attr_destroy)(pthread_condattr_t *);
    int (*cond_init)(pthread_cond_t *, const pthread_condattr_t *);
    int (*cond_destroy)(pthread_cond_t *);
    int (*wait)(pthread_cond_t *, pthread_mutex_t *, const struct timespec *);
    int (*broadcast)(pthread_cond_t *);
    int (*clock_now)(clockid_t, struct timespec *);
    vireo_result_t (*open)(vireo_mysql_thread_t *, const vireo_mysql_connection_options_t *,
        vireo_mysql_connection_t **, vireo_mysql_error_t *);
    vireo_result_t (*restore)(vireo_mysql_connection_t *, const char *, vireo_mysql_error_t *);
    void (*dispose)(vireo_mysql_connection_t *);
} vireo_mysql_pool_ops_t;
typedef enum vireo_mysql_slot_state {
    MYSQL_SLOT_IDLE, MYSQL_SLOT_LEASED, MYSQL_SLOT_RETURNING,
    MYSQL_SLOT_VACANT, MYSQL_SLOT_REFILLING, MYSQL_SLOT_RETIRED
} vireo_mysql_slot_state_t;
typedef struct vireo_mysql_pool_slot {
    vireo_mysql_slot_state_t state;
    uint64_t generation;
    pthread_t borrower;
    vireo_mysql_connection_t *connection;
} vireo_mysql_pool_slot_t;
struct vireo_mysql_pool {
    vireo_mysql_runtime_t *runtime;
    vireo_mysql_pool_ops_t ops;
    vireo_mysql_connection_options_t options;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    vireo_mysql_pool_slot_t *slots;
    char *strings;
    size_t string_bytes;
    size_t capacity, max_waiters, waiters, leased, high_watermark, allocated_bytes;
    vireo_mysql_pool_state_t state;
    bool destroying, cond_destroyed;
};
extern const vireo_mysql_pool_ops_t vireo_mysql_pool_native_ops;
vireo_result_t vireo_mysql_pool_create_with_ops(vireo_mysql_thread_t *thread,
    const vireo_mysql_pool_options_t *options, vireo_mysql_pool_t **out,
    vireo_mysql_pool_error_t *error, const vireo_mysql_pool_ops_t *ops);
#endif
