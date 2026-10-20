#include "rate_limiter_test.h"
#include <stdbool.h>

/* 独立表示：以纳秒服务量存分数余额，而非生产实现的tokens/anchor。
 * 参考表在成功提交时丢弃全部满桶；不复制生产槽回收顺序。
 * 固定seed有限回归序列，不是延期fuzz专项或随机安全证明。 */
enum { MODEL_CAPACITY = 16, MODEL_POLICIES = 4 };
typedef struct credit_record {
    bool occupied;
    uint32_t policy_id;
    unsigned char key[32];
    uint64_t credit;
    uint64_t sampled_at;
} credit_record_t;

typedef struct reference {
    vireo_rate_limit_policy_t policies[MODEL_POLICIES];
    credit_record_t records[MODEL_CAPACITY];
} reference_t;

static uint64_t random_step(uint64_t *state) {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    return *state;
}

static bool same(credit_record_t const *record, vireo_rate_limit_request_t const *request) {
    return record->occupied && record->policy_id == request->policy_id &&
        memcmp(record->key, request->key, 32) == 0;
}

static uint64_t current_credit(reference_t const *model, credit_record_t const *record, uint64_t now) {
    vireo_rate_limit_policy_t const *policy = &model->policies[record->policy_id - 1];
    uint64_t const maximum = (uint64_t)policy->burst_tokens * policy->refill_interval_ns;
    uint64_t const elapsed = now - record->sampled_at;
    return elapsed >= maximum - record->credit ? maximum : record->credit + elapsed;
}

static vireo_rate_limit_outcome_t reference_check(reference_t *model, uint64_t now,
    vireo_rate_limit_request_t const *requests, size_t count, uint64_t *retry) {
    uint64_t balances[VIREO_RATE_LIMIT_MAX_BATCH] = {0};
    *retry = 0;
    for (size_t j = 0; j < count; ++j) {
        vireo_rate_limit_policy_t const *policy = &model->policies[requests[j].policy_id - 1];
        balances[j] = (uint64_t)policy->burst_tokens * policy->refill_interval_ns;
        for (size_t i = 0; i < MODEL_CAPACITY; ++i) {
            if (same(&model->records[i], &requests[j])) {
                balances[j] = current_credit(model, &model->records[i], now);
            }
        }
        uint64_t const wanted = (uint64_t)requests[j].cost * policy->refill_interval_ns;
        if (balances[j] < wanted && wanted - balances[j] > *retry) { *retry = wanted - balances[j]; }
    }
    if (*retry != 0) { return VIREO_RATE_LIMIT_THROTTLED; }
    size_t required = count;
    for (size_t i = 0; i < MODEL_CAPACITY; ++i) {
        credit_record_t const *record = &model->records[i];
        if (!record->occupied) { continue; }
        vireo_rate_limit_policy_t const *policy = &model->policies[record->policy_id - 1];
        bool retained = current_credit(model, record, now) < (uint64_t)policy->burst_tokens * policy->refill_interval_ns;
        for (size_t j = 0; j < count; ++j) {
            if (same(record, &requests[j])) { retained = false; }
        }
        if (retained) { ++required; }
    }
    if (required > MODEL_CAPACITY) { return VIREO_RATE_LIMIT_CAPACITY; }
    for (size_t i = 0; i < MODEL_CAPACITY; ++i) {
        credit_record_t *record = &model->records[i];
        if (!record->occupied) { continue; }
        vireo_rate_limit_policy_t const *policy = &model->policies[record->policy_id - 1];
        if (current_credit(model, record, now) == (uint64_t)policy->burst_tokens * policy->refill_interval_ns) {
            record->occupied = false;
        }
    }
    for (size_t j = 0; j < count; ++j) {
        size_t slot = MODEL_CAPACITY;
        for (size_t i = 0; i < MODEL_CAPACITY; ++i) {
            if (same(&model->records[i], &requests[j])) { slot = i; break; }
        }
        if (slot == MODEL_CAPACITY) {
            for (size_t i = 0; i < MODEL_CAPACITY; ++i) {
                if (!model->records[i].occupied) { slot = i; break; }
            }
        }
        CHECK(slot < MODEL_CAPACITY);
        credit_record_t *record = &model->records[slot];
        record->occupied = true;
        record->policy_id = requests[j].policy_id;
        memcpy(record->key, requests[j].key, 32);
        record->credit = balances[j] - (uint64_t)requests[j].cost *
            model->policies[requests[j].policy_id - 1].refill_interval_ns;
        record->sampled_at = now;
    }
    return VIREO_RATE_LIMIT_ADMITTED;
}

static void run_sequence(uint64_t start, uint64_t seed) {
    reference_t model = {.policies = {{1, 3, 7}, {2, 8, 11}, {3, 17, 17}, {4, 2, 23}}};
    vireo_rate_limiter_t *limiter = make_limiter(MODEL_CAPACITY, model.policies, MODEL_POLICIES, start);
    uint64_t now = start;
    size_t outcomes[3] = {0};
    for (size_t iteration = 0; iteration < 20000; ++iteration) {
        now += iteration % 401 == 0 ? UINT64_C(1000) : random_step(&seed) % 5;
        size_t const count = (size_t)(random_step(&seed) % 8) + 1;
        vireo_rate_limit_request_t requests[VIREO_RATE_LIMIT_MAX_BATCH];
        for (size_t j = 0; j < count; ++j) {
            bool duplicate;
            do {
                uint32_t const policy = (uint32_t)(random_step(&seed) % MODEL_POLICIES) + 1;
                unsigned char const key = (unsigned char)(random_step(&seed) % 24);
                uint32_t const cost = (uint32_t)(random_step(&seed) % model.policies[policy - 1].burst_tokens) + 1;
                requests[j] = request_for(policy, key, cost);
                duplicate = false;
                for (size_t k = 0; k < j; ++k) {
                    if (requests[j].policy_id == requests[k].policy_id &&
                        memcmp(requests[j].key, requests[k].key, 32) == 0) { duplicate = true; }
                }
            } while (duplicate);
        }
        uint64_t retry = 0;
        vireo_rate_limit_outcome_t const expected = reference_check(&model, now, requests, count, &retry);
        check_at(limiter, now, requests, count, expected, retry);
        ++outcomes[expected];
    }
    CHECK(outcomes[0] > 100 && outcomes[1] > 100 && outcomes[2] > 100);
    CHECK(vireo_rate_limiter_destroy(&limiter) == VIREO_OK);
    printf("credit model start=%llu: admitted=%zu throttled=%zu capacity=%zu\n",
        (unsigned long long)start, outcomes[0], outcomes[1], outcomes[2]);
}

int main(void) {
    run_sequence(0, UINT64_C(0x213521ae0d5215));
    run_sequence(UINT64_MAX - UINT64_C(1000000), UINT64_C(0x51632ab201));
    puts("rate limiter model: 40000 fixed-seed batch comparisons against independent fractional-service credit representation passed");
    return 0;
}
