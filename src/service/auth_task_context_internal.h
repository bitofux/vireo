/* PROJECT : VIREO
 * FILE : auth_task_context_internal.h
 * AUTHOR : bitofux
 * DATE : 2026-10-20
 * BRIEF : 仅本模块采样边界注入。
 */
#ifndef VIREO_SERVICE_AUTH_TASK_CONTEXT_INTERNAL_H
#define VIREO_SERVICE_AUTH_TASK_CONTEXT_INTERNAL_H
#include <vireo/service/auth_task_context.h>
#include <time.h>
/** 各函数只短借参数；random同RAND返回1，utc同gettime返回0/-1。 */
typedef struct vireo_auth_context_ops {
    int (*random)(void *, unsigned char [16]); /**< 一次生成16字节。 */
    int (*utc)(void *, struct timespec *); /**< 一次REALTIME样本。 */
    vireo_result_t (*monotonic)(void *, vireo_monotonic_ns_t *, vireo_clock_error_t *);
    /**< 一次公开monotonic语义采样，错误保持其输出。 */
    void *context; /**< 可空同步借用context，不保存。 */
} vireo_auth_context_ops_t;
/** 同公共capture，额外必需ops及三个函数，地址拒绝不调用依赖。 */
vireo_result_t vireo_auth_task_context_with(vireo_task_t const *task,
    vireo_monotonic_ns_t received_at_ns, uint64_t session_lifetime_ms,
    vireo_auth_task_options_t const *options,
    vireo_auth_task_context_t *out, vireo_auth_context_error_t *error,
    vireo_auth_context_ops_t const *ops);
#endif
