#ifndef VIREO_RATE_LIMITER_TEST_H
#define VIREO_RATE_LIMITER_TEST_H
#include <vireo/security/rate_limiter.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition); exit(1); \
} } while (0)

static inline vireo_rate_limiter_t *make_limiter(size_t capacity,
    vireo_rate_limit_policy_t const *policies, size_t count, uint64_t now) {
    vireo_rate_limiter_options_t const options = {capacity, VIREO_RATE_LIMIT_MAX_MEMORY_BYTES};
    vireo_rate_limiter_t *limiter = NULL;
    errno = EDOM;
    CHECK(vireo_rate_limiter_create(&options, policies, count, now, &limiter) == VIREO_OK);
    CHECK(limiter != NULL && errno == EDOM);
    return limiter;
}

static inline vireo_rate_limit_request_t request_for(uint32_t policy, unsigned char key, uint32_t cost) {
    vireo_rate_limit_request_t request = {.policy_id = policy, .key = {0}, .cost = cost};
    request.key[31] = key; /* 共同31字节前缀包含NUL，不能按字符串截断。 */
    return request;
}

static inline vireo_rate_limit_decision_t check_at(vireo_rate_limiter_t *limiter, uint64_t now,
    vireo_rate_limit_request_t const *requests, size_t count, vireo_rate_limit_outcome_t outcome,
    uint64_t retry) {
    vireo_rate_limit_decision_t decision = {VIREO_RATE_LIMIT_CAPACITY, UINT64_MAX, SIZE_MAX};
    errno = EDOM;
    CHECK(vireo_rate_limiter_check(limiter, now, requests, count, &decision) == VIREO_OK);
    CHECK(decision.outcome == outcome && decision.retry_after_ns == retry && errno == EDOM);
    vireo_rate_limiter_info_t info;
    CHECK(vireo_rate_limiter_inspect(limiter, &info) == VIREO_OK && errno == EDOM);
    CHECK(info.last_now == now && info.tracked_keys == decision.tracked_keys);
    CHECK(info.tracked_keys <= info.max_keys && info.allocated_bytes <= info.max_memory_bytes);
    return decision;
}

#endif
