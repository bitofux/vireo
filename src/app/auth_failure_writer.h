/* PROJECT: VIREO; FILE: auth_failure_writer.h; AUTHOR: bitofux; DATE: 2026-10-20.
 * 应用私有owner；主线程start/join，repository及guard仅writer持有。 */
#ifndef VIREO_APP_AUTH_FAILURE_WRITER_H
#define VIREO_APP_AUTH_FAILURE_WRITER_H
#include <vireo/service/auth_failure_audit.h>
#include <vireo/persistence/mysql_user_repository.h>
#include <pthread.h>
typedef struct vireo_auth_failure_writer_report {
    bool created, joined, disabled;
    uint64_t committed, failed, unknown;
    vireo_result_t first_result;
} vireo_auth_failure_writer_report_t;
/* own测试替换依赖操作，不改变生产SQL目标或跨线程借用owner。 */
typedef struct vireo_auth_failure_writer_ops {
    void *context;
    vireo_result_t (*attach)(void *,vireo_mysql_runtime_t *,vireo_mysql_thread_t **);
    vireo_result_t (*create)(void *,vireo_mysql_thread_t *,vireo_mysql_pool_t *,vireo_mysql_user_repository_t **);
    vireo_result_t (*append)(void *,vireo_mysql_user_repository_t *,vireo_mysql_auth_failure_input_t const *,vireo_mysql_auth_failure_report_t *);
    vireo_result_t (*destroy)(void *,vireo_mysql_user_repository_t **);
    vireo_result_t (*detach)(void *,vireo_mysql_thread_t **);
    vireo_result_t (*random)(void *,unsigned char [16]);
    void (*stopped)(void *);
} vireo_auth_failure_writer_ops_t;
typedef struct vireo_auth_failure_writer {
    pthread_t thread;
    vireo_mysql_runtime_t *runtime;
    vireo_mysql_pool_t *pool;
    vireo_auth_failure_audit_t *queue;
    vireo_auth_failure_writer_ops_t ops;
    vireo_auth_failure_writer_report_t report; /* 仅writer写；join成功后main读取。 */
} vireo_auth_failure_writer_t;
/* start失败关闭queue、报告降级；writer不拥有三个借用。禁取消。 */
vireo_result_t vireo_auth_failure_writer_start(vireo_auth_failure_writer_t *writer,
    vireo_mysql_runtime_t *runtime,vireo_mysql_pool_t *pool,vireo_auth_failure_audit_t *queue);
/* caller先close；join失败保created&&!joined，禁止销毁依赖。 */
vireo_result_t vireo_auth_failure_writer_join(vireo_auth_failure_writer_t *writer);
vireo_result_t vireo_auth_failure_writer_start_with(vireo_auth_failure_writer_t *writer,
    vireo_mysql_runtime_t *runtime,vireo_mysql_pool_t *pool,vireo_auth_failure_audit_t *queue,
    vireo_auth_failure_writer_ops_t const *ops);
#endif
