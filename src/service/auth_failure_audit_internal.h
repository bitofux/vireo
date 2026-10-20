#ifndef VIREO_AUTH_FAILURE_AUDIT_INTERNAL_H
#define VIREO_AUTH_FAILURE_AUDIT_INTERNAL_H
#include <vireo/service/auth_failure_audit.h>
#include <pthread.h>
/** 仅本组件测试的真实锁/等待观测；hook须不阻塞，不重入本对象。 */
vireo_result_t vireo_auth_failure_audit_test_lock(vireo_auth_failure_audit_t *audit, bool lock);
void vireo_auth_failure_audit_test_wait_hook(vireo_auth_failure_audit_t *audit,
    void (*hook)(void *), void *context);
/** 同一组件双桶共用的受检整数信用；非公共ABI。 */
typedef struct vireo_auth_failure_bucket { uint64_t tokens, remainder, last; } vireo_auth_failure_bucket_t;
void vireo_auth_failure_bucket_refill(vireo_auth_failure_bucket_t *bucket,
    uint64_t now, uint64_t burst, uint64_t interval);
#endif
