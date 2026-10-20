#ifndef VIREO_SECURITY_RATE_LIMITER_INTERNAL_H
#define VIREO_SECURITY_RATE_LIMITER_INTERNAL_H

#include <vireo/security/rate_limiter.h>
#include <stdbool.h>

/* own申请边界：create复制此表，context须存活到destroy；无可变全局故障开关。
 * allocate须满足malloc对齐/容量合同，release释放对应块。 */
typedef struct vireo_rate_limiter_allocator {
    void *context; /**< allocator使用者拥有，借用至对象销毁。 */
    void *(*allocate)(void *context, size_t bytes);
    void (*release)(void *context, void *memory);
} vireo_rate_limiter_allocator_t;

typedef struct vireo_rate_limit_entry {
    bool occupied; /**< 槽是否已存记录。 */
    size_t policy_index; /**< 对象自有固定配置的索引。 */
    unsigned char key[VIREO_RATE_LIMIT_KEY_BYTES]; /**< 本槽自有身份字节。 */
    uint32_t tokens; /**< 补充锚点时的整数余额。 */
    vireo_monotonic_ns_t anchor; /**< 未满时保留不足一个间隔的余量。 */
} vireo_rate_limit_entry_t;

struct vireo_rate_limiter {
    size_t max_keys;
    size_t tracked_keys;
    size_t policy_count;
    size_t allocated_bytes;
    size_t max_memory_bytes;
    vireo_monotonic_ns_t last_now;
    vireo_rate_limiter_allocator_t allocator;
    vireo_rate_limit_policy_t policies[VIREO_RATE_LIMIT_MAX_POLICIES];
    vireo_rate_limit_entry_t entries[];
};

vireo_result_t vireo_rate_limiter_create_with_allocator(vireo_rate_limiter_options_t const *options,
    vireo_rate_limit_policy_t const *policies, size_t policy_count, vireo_monotonic_ns_t now,
    vireo_rate_limiter_t **out_limiter, vireo_rate_limiter_allocator_t const *allocator);

#endif
