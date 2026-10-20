#include "rate_limiter_test.h"

static void entry_story(void) {
    vireo_rate_limit_policy_t const policies[] = {{1, 3, 10}, {2, 2, 20}};
    vireo_rate_limiter_t *limiter = make_limiter(2, policies, 2, 100);
    vireo_rate_limit_request_t requests[] = {request_for(1, 'A', 1), request_for(2, 'B', 1)};
    CHECK(check_at(limiter, 100, requests, 2, VIREO_RATE_LIMIT_ADMITTED, 0).tracked_keys == 2);
    requests[0].cost = 2;
    check_at(limiter, 100, requests, 2, VIREO_RATE_LIMIT_ADMITTED, 0);
    requests[0].cost = 1;
    check_at(limiter, 109, requests, 2, VIREO_RATE_LIMIT_THROTTLED, 11);
    check_at(limiter, 110, requests, 2, VIREO_RATE_LIMIT_THROTTLED, 10);
    check_at(limiter, 120, requests, 2, VIREO_RATE_LIMIT_ADMITTED, 0);
    vireo_rate_limit_request_t new_key = request_for(1, 'C', 1);
    check_at(limiter, 120, &new_key, 1, VIREO_RATE_LIMIT_CAPACITY, 0);
    check_at(limiter, 140, &new_key, 1, VIREO_RATE_LIMIT_ADMITTED, 0);
    requests[1].cost = 2;
    check_at(limiter, 140, &requests[1], 1, VIREO_RATE_LIMIT_THROTTLED, 20);
    CHECK(vireo_rate_limiter_destroy(&limiter) == VIREO_OK && limiter == NULL && errno == EDOM);
    CHECK(vireo_rate_limiter_destroy(&limiter) == VIREO_OK && errno == EDOM);
}

static void fractional_credit(void) {
    vireo_rate_limit_policy_t const policy = {1, 3, 10};
    vireo_rate_limiter_t *limiter = make_limiter(1, &policy, 1, 0);
    vireo_rate_limit_request_t request = request_for(1, 0, 3);
    check_at(limiter, 0, &request, 1, VIREO_RATE_LIMIT_ADMITTED, 0);
    request.cost = 1;
    for (uint64_t now = 1; now < 10; ++now) {
        check_at(limiter, now, &request, 1, VIREO_RATE_LIMIT_THROTTLED, 10 - now);
    }
    check_at(limiter, 15, &request, 1, VIREO_RATE_LIMIT_ADMITTED, 0);
    check_at(limiter, 19, &request, 1, VIREO_RATE_LIMIT_THROTTLED, 1);
    check_at(limiter, 20, &request, 1, VIREO_RATE_LIMIT_ADMITTED, 0);
    /* 100时已满；105消费时不能保留100到105的满桶分数。 */
    request.cost = 3;
    check_at(limiter, 105, &request, 1, VIREO_RATE_LIMIT_ADMITTED, 0);
    request.cost = 1;
    check_at(limiter, 110, &request, 1, VIREO_RATE_LIMIT_THROTTLED, 5);
    check_at(limiter, 115, &request, 1, VIREO_RATE_LIMIT_ADMITTED, 0);
    CHECK(vireo_rate_limiter_destroy(&limiter) == VIREO_OK);
}

static void complete_batch_and_reclaim(void) {
    vireo_rate_limit_policy_t const policy = {1, 2, 10};
    vireo_rate_limiter_t *limiter = make_limiter(2, &policy, 1, 0);
    vireo_rate_limit_request_t a = request_for(1, 'A', 2);
    vireo_rate_limit_request_t b = request_for(1, 'B', 1);
    vireo_rate_limit_request_t c = request_for(1, 'C', 1);
    check_at(limiter, 0, &a, 1, VIREO_RATE_LIMIT_ADMITTED, 0);
    check_at(limiter, 0, &b, 1, VIREO_RATE_LIMIT_ADMITTED, 0);
    vireo_rate_limit_request_t pair[] = {c, a};
    pair[1].cost = 1;
    /* 新C没有空间且旧A不足，必须优先额度拒绝，且不能插入C。 */
    check_at(limiter, 0, pair, 2, VIREO_RATE_LIMIT_THROTTLED, 10);
    check_at(limiter, 0, &c, 1, VIREO_RATE_LIMIT_CAPACITY, 0);
    b.cost = 2;
    check_at(limiter, 0, &b, 1, VIREO_RATE_LIMIT_THROTTLED, 10);
    /* 10时B满、A只有1；先请求C，后引用B，不得把B作为C的候选回收。 */
    pair[1] = b;
    check_at(limiter, 10, pair, 2, VIREO_RATE_LIMIT_CAPACITY, 0);
    b.cost = 1;
    check_at(limiter, 10, &b, 1, VIREO_RATE_LIMIT_ADMITTED, 0);
    a.cost = 1;
    check_at(limiter, 10, &a, 1, VIREO_RATE_LIMIT_ADMITTED, 0);
    check_at(limiter, 20, &c, 1, VIREO_RATE_LIMIT_ADMITTED, 0); /* 只回收满B。 */
    a.cost = 2;
    check_at(limiter, 20, &a, 1, VIREO_RATE_LIMIT_THROTTLED, 10);
    CHECK(vireo_rate_limiter_destroy(&limiter) == VIREO_OK);
    /* 两个新维度不能挤入同一槽；拒绝不得留下第一个新记录。 */
    limiter = make_limiter(1, &policy, 1, 0);
    pair[0] = request_for(1, 'A', 1);
    pair[1] = request_for(1, 'B', 1);
    CHECK(check_at(limiter, 0, pair, 2, VIREO_RATE_LIMIT_CAPACITY, 0).tracked_keys == 0);
    check_at(limiter, 0, &pair[0], 1, VIREO_RATE_LIMIT_ADMITTED, 0);
    CHECK(vireo_rate_limiter_destroy(&limiter) == VIREO_OK);
}

static void keys_policies_limits(void) {
    vireo_rate_limit_policy_t policies[VIREO_RATE_LIMIT_MAX_POLICIES];
    for (size_t i = 0; i < VIREO_RATE_LIMIT_MAX_POLICIES; ++i) {
        policies[i] = (vireo_rate_limit_policy_t){(uint32_t)(i + 1), 1, 1};
    }
    vireo_rate_limiter_t *limiter = make_limiter(VIREO_RATE_LIMIT_MAX_KEYS,
        policies, VIREO_RATE_LIMIT_MAX_POLICIES, 0);
    memset(policies, 0, sizeof(policies)); /* create必须复制配置。 */
    vireo_rate_limit_request_t requests[VIREO_RATE_LIMIT_MAX_BATCH];
    for (size_t i = 0; i < VIREO_RATE_LIMIT_MAX_BATCH; ++i) {
        requests[i] = request_for((uint32_t)(i + 1), 0, 1); /* 同key不同policy合法。 */
    }
    check_at(limiter, 0, requests, VIREO_RATE_LIMIT_MAX_BATCH, VIREO_RATE_LIMIT_ADMITTED, 0);
    check_at(limiter, 0, requests, VIREO_RATE_LIMIT_MAX_BATCH, VIREO_RATE_LIMIT_THROTTLED, 1);
    for (size_t i = 0; i < 32; ++i) {
        vireo_rate_limit_request_t request = request_for(16, 0, 1);
        request.key[i] = 1;
        check_at(limiter, 0, &request, 1, VIREO_RATE_LIMIT_ADMITTED, 0);
    }
    /* 填满所有4096槽，真实满表判断/回收，不只用模型验证硬容量。 */
    for (size_t i = 40; i < VIREO_RATE_LIMIT_MAX_KEYS; ++i) {
        vireo_rate_limit_request_t request = request_for(16, 0, 1);
        request.key[0] = 0xff;
        request.key[1] = (unsigned char)(i >> 8);
        request.key[2] = (unsigned char)i;
        check_at(limiter, 0, &request, 1, VIREO_RATE_LIMIT_ADMITTED, 0);
    }
    vireo_rate_limit_request_t new_key = request_for(16, 0xfe, 1);
    CHECK(check_at(limiter, 0, &new_key, 1, VIREO_RATE_LIMIT_CAPACITY, 0).tracked_keys == 4096);
    CHECK(check_at(limiter, 1, &new_key, 1, VIREO_RATE_LIMIT_ADMITTED, 0).tracked_keys == 4096);
    CHECK(vireo_rate_limiter_destroy(&limiter) == VIREO_OK);
}

static void time_extremes(void) {
    vireo_rate_limit_policy_t const policy = {1, VIREO_RATE_LIMIT_MAX_BURST_TOKENS,
        VIREO_RATE_LIMIT_MAX_REFILL_INTERVAL_NS};
    vireo_rate_limiter_t *limiter = make_limiter(1, &policy, 1, 0);
    vireo_rate_limit_request_t request = request_for(1, 0, policy.burst_tokens);
    check_at(limiter, 0, &request, 1, VIREO_RATE_LIMIT_ADMITTED, 0);
    check_at(limiter, 0, &request, 1, VIREO_RATE_LIMIT_THROTTLED, UINT64_C(3600000000000000000));
    check_at(limiter, UINT64_MAX, &request, 1, VIREO_RATE_LIMIT_ADMITTED, 0);
    check_at(limiter, UINT64_MAX, &request, 1, VIREO_RATE_LIMIT_THROTTLED, UINT64_C(3600000000000000000));
    CHECK(vireo_rate_limiter_destroy(&limiter) == VIREO_OK);
    vireo_rate_limit_policy_t const tiny = {1, 1, 10};
    limiter = make_limiter(1, &tiny, 1, UINT64_MAX - 5);
    request.cost = 1;
    check_at(limiter, UINT64_MAX - 5, &request, 1, VIREO_RATE_LIMIT_ADMITTED, 0);
    check_at(limiter, UINT64_MAX, &request, 1, VIREO_RATE_LIMIT_THROTTLED, 5);
    CHECK(vireo_rate_limiter_destroy(&limiter) == VIREO_OK);
}

int main(void) {
    entry_story();
    fractional_credit();
    complete_batch_and_reclaim();
    keys_policies_limits();
    time_extremes();
    puts("rate limiter: exact time/credit, complete batch, full-table safety, all key bytes/policies, actual 4096 slots and uint64 extremes passed");
    return 0;
}
