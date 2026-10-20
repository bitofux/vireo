#include "rate_limiter_internal.h"
#include <vireo/base/checked.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

/* 补充/重试乘法上界由已验证的policy硬上限保证，不对未来绝对时间做加法。 */
_Static_assert(VIREO_RATE_LIMIT_MAX_REFILL_INTERVAL_NS <=
    UINT64_MAX / VIREO_RATE_LIMIT_MAX_BURST_TOKENS, "rate limit duration bound");

typedef struct plan {
    size_t policy_index;
    size_t slot; /**< SIZE_MAX为尚未匹配/分配的槽，非时间哨兵。 */
    uint32_t tokens;
    vireo_monotonic_ns_t anchor;
} plan_t;

static void *native_allocate(void *context, size_t bytes) {
    (void)context;
    return malloc(bytes);
}

static void native_release(void *context, void *memory) {
    (void)context;
    free(memory);
}

static vireo_rate_limiter_allocator_t const native_allocator = {NULL, native_allocate, native_release};

vireo_result_t vireo_rate_limiter_create_with_allocator(vireo_rate_limiter_options_t const *options,
    vireo_rate_limit_policy_t const *policies, size_t policy_count, vireo_monotonic_ns_t now,
    vireo_rate_limiter_t **out_limiter, vireo_rate_limiter_allocator_t const *allocator) {
    int const saved_errno = errno;
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    size_t entry_bytes = 0, total = 0;
    if (options == NULL || policies == NULL || out_limiter == NULL || *out_limiter != NULL ||
        allocator == NULL || allocator->allocate == NULL || allocator->release == NULL ||
        options->max_keys == 0 || options->max_memory_bytes == 0 || policy_count == 0) { goto done; }
    result = vireo_checked_size_mul(options->max_keys, sizeof(vireo_rate_limit_entry_t), &entry_bytes);
    if (result != VIREO_OK) { goto done; }
    result = vireo_checked_size_add(sizeof(vireo_rate_limiter_t), entry_bytes, &total);
    if (result != VIREO_OK) { goto done; }
    result = VIREO_RESULT_RANGE;
    if (options->max_keys > VIREO_RATE_LIMIT_MAX_KEYS || policy_count > VIREO_RATE_LIMIT_MAX_POLICIES ||
        options->max_memory_bytes > VIREO_RATE_LIMIT_MAX_MEMORY_BYTES || total > options->max_memory_bytes) {
        goto done;
    }
    for (size_t i = 0; i < policy_count; ++i) {
        result = VIREO_RESULT_INVALID_ARGUMENT;
        if (policies[i].policy_id == 0 || policies[i].burst_tokens == 0 || policies[i].refill_interval_ns == 0) {
            goto done;
        }
        for (size_t j = 0; j < i; ++j) {
            if (policies[i].policy_id == policies[j].policy_id) { goto done; }
        }
        result = VIREO_RESULT_RANGE;
        if (policies[i].burst_tokens > VIREO_RATE_LIMIT_MAX_BURST_TOKENS ||
            policies[i].refill_interval_ns > VIREO_RATE_LIMIT_MAX_REFILL_INTERVAL_NS) { goto done; }
    }
    vireo_rate_limiter_t *temporary = allocator->allocate(allocator->context, total);
    result = VIREO_RESULT_NO_MEMORY;
    if (temporary == NULL) { goto done; }
    memset(temporary, 0, total);
    temporary->max_keys = options->max_keys;
    temporary->policy_count = policy_count;
    temporary->allocated_bytes = total;
    temporary->max_memory_bytes = options->max_memory_bytes;
    temporary->last_now = now;
    temporary->allocator = *allocator;
    for (size_t i = 0; i < policy_count; ++i) { temporary->policies[i] = policies[i]; }
    *out_limiter = temporary;
    result = VIREO_OK;
done:
    errno = saved_errno;
    return result;
}

vireo_result_t vireo_rate_limiter_create(vireo_rate_limiter_options_t const *options,
    vireo_rate_limit_policy_t const *policies, size_t policy_count,
    vireo_monotonic_ns_t now, vireo_rate_limiter_t **out_limiter) {
    return vireo_rate_limiter_create_with_allocator(options, policies, policy_count, now,
        out_limiter, &native_allocator);
}

/* entry.anchor<=last_now<=now；未满分支periods*interval<=elapsed，不会溢出。 */
static void refill(vireo_rate_limit_entry_t const *entry, vireo_rate_limit_policy_t const *policy,
    vireo_monotonic_ns_t now, plan_t *plan) {
    uint64_t const elapsed = now - entry->anchor;
    uint64_t const periods = elapsed / policy->refill_interval_ns;
    if (periods >= (uint64_t)(policy->burst_tokens - entry->tokens)) {
        plan->tokens = policy->burst_tokens;
        plan->anchor = now; /* 满桶不存额外分数，之后扣费从现在开始补充。 */
    } else {
        plan->tokens = entry->tokens + (uint32_t)periods;
        plan->anchor = entry->anchor + periods * policy->refill_interval_ns;
    }
}

static bool referenced(plan_t const *plans, size_t count, size_t slot) {
    for (size_t j = 0; j < count; ++j) {
        if (plans[j].slot == slot) { return true; }
    }
    return false;
}

vireo_result_t vireo_rate_limiter_check(vireo_rate_limiter_t *limiter, vireo_monotonic_ns_t now,
    vireo_rate_limit_request_t const *requests, size_t request_count,
    vireo_rate_limit_decision_t *decision) {
    int const saved_errno = errno;
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    plan_t plans[VIREO_RATE_LIMIT_MAX_BATCH] = {{0}};
    if (limiter == NULL || requests == NULL || decision == NULL || request_count == 0) { goto done; }
    if (request_count > VIREO_RATE_LIMIT_MAX_BATCH) { result = VIREO_RESULT_RANGE; goto done; }
    for (size_t j = 0; j < request_count; ++j) {
        if (requests[j].policy_id == 0 || requests[j].cost == 0) { goto done; }
        size_t p = 0;
        while (p < limiter->policy_count && limiter->policies[p].policy_id != requests[j].policy_id) { ++p; }
        if (p == limiter->policy_count) { result = VIREO_RESULT_NOT_FOUND; goto done; }
        if (requests[j].cost > limiter->policies[p].burst_tokens) { result = VIREO_RESULT_RANGE; goto done; }
        for (size_t k = 0; k < j; ++k) {
            if (plans[k].policy_index == p &&
                memcmp(requests[k].key, requests[j].key, VIREO_RATE_LIMIT_KEY_BYTES) == 0) { goto done; }
        }
        plans[j].policy_index = p;
        plans[j].slot = SIZE_MAX;
        plans[j].tokens = limiter->policies[p].burst_tokens;
        plans[j].anchor = now;
    }
    if (now < limiter->last_now) { goto done; }
    /* 先匹配整个批量，再考虑回收，防止抹掉批量后部所引用的已满记录。 */
    for (size_t i = 0; i < limiter->max_keys; ++i) {
        vireo_rate_limit_entry_t const *entry = &limiter->entries[i];
        if (!entry->occupied) { continue; }
        for (size_t j = 0; j < request_count; ++j) {
            if (entry->policy_index == plans[j].policy_index &&
                memcmp(entry->key, requests[j].key, VIREO_RATE_LIMIT_KEY_BYTES) == 0) {
                plans[j].slot = i;
                refill(entry, &limiter->policies[entry->policy_index], now, &plans[j]);
            }
        }
    }
    vireo_rate_limit_decision_t next = {VIREO_RATE_LIMIT_ADMITTED, 0, limiter->tracked_keys};
    size_t missing = 0;
    for (size_t j = 0; j < request_count; ++j) {
        if (plans[j].slot == SIZE_MAX) { ++missing; }
        if (plans[j].tokens < requests[j].cost) {
            uint64_t const interval = limiter->policies[plans[j].policy_index].refill_interval_ns;
            uint64_t const wait = (uint64_t)(requests[j].cost - plans[j].tokens) * interval -
                (now - plans[j].anchor);
            if (wait > next.retry_after_ns) { next.retry_after_ns = wait; }
        }
    }
    if (next.retry_after_ns != 0) { next.outcome = VIREO_RATE_LIMIT_THROTTLED; goto publish; }
    size_t candidates[VIREO_RATE_LIMIT_MAX_BATCH] = {0};
    size_t available = 0;
    for (size_t i = 0; i < limiter->max_keys && available < missing; ++i) {
        if (referenced(plans, request_count, i)) { continue; }
        vireo_rate_limit_entry_t const *entry = &limiter->entries[i];
        bool usable = !entry->occupied;
        if (entry->occupied) {
            plan_t virtual = {0};
            refill(entry, &limiter->policies[entry->policy_index], now, &virtual);
            usable = virtual.tokens == limiter->policies[entry->policy_index].burst_tokens;
        }
        if (usable) { candidates[available++] = i; }
    }
    if (available < missing) { next.outcome = VIREO_RATE_LIMIT_CAPACITY; goto publish; }
    size_t selected = 0;
    for (size_t j = 0; j < request_count; ++j) {
        if (plans[j].slot == SIZE_MAX) { plans[j].slot = candidates[selected++]; }
    }
    /* 从这里起没有可失败动作；所有配置/输入只读，所有槽地址已规划完毕。 */
    for (size_t j = 0; j < request_count; ++j) {
        vireo_rate_limit_entry_t *entry = &limiter->entries[plans[j].slot];
        if (!entry->occupied) { ++limiter->tracked_keys; }
        entry->occupied = true;
        entry->policy_index = plans[j].policy_index;
        memcpy(entry->key, requests[j].key, sizeof(entry->key));
        entry->tokens = plans[j].tokens - requests[j].cost;
        entry->anchor = plans[j].anchor;
    }
    next.tracked_keys = limiter->tracked_keys;
publish:
    limiter->last_now = now;
    *decision = next;
    result = VIREO_OK;
done:
    errno = saved_errno;
    return result;
}

vireo_result_t vireo_rate_limiter_inspect(vireo_rate_limiter_t const *limiter,
    vireo_rate_limiter_info_t *info) {
    int const saved_errno = errno;
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    if (limiter != NULL && info != NULL) {
        vireo_rate_limiter_info_t const next = {limiter->max_keys, limiter->tracked_keys,
            limiter->policy_count, limiter->allocated_bytes, limiter->max_memory_bytes, limiter->last_now};
        *info = next;
        result = VIREO_OK;
    }
    errno = saved_errno;
    return result;
}

vireo_result_t vireo_rate_limiter_destroy(vireo_rate_limiter_t **limiter) {
    int const saved_errno = errno;
    vireo_result_t result = VIREO_RESULT_INVALID_ARGUMENT;
    if (limiter != NULL) {
        if (*limiter != NULL) {
            vireo_rate_limiter_allocator_t const allocator = (*limiter)->allocator;
            allocator.release(allocator.context, *limiter);
            *limiter = NULL;
        }
        result = VIREO_OK;
    }
    errno = saved_errno;
    return result;
}
