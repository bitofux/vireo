#include "rate_limiter_test.h"
#include "rate_limiter_internal.h"

typedef struct allocation_model {
    bool fail; /**< 是否注入申请失败。 */
    size_t allocations; /**< own边界调用数。 */
    size_t releases; /**< 成功owner释放数。 */
    size_t bytes; /**< 实际请求量。 */
} allocation_model_t;

static void *allocate(void *context, size_t bytes) {
    allocation_model_t *model = context;
    ++model->allocations;
    model->bytes = bytes;
    errno = ENOMEM;
    return model->fail ? NULL : malloc(bytes);
}

static void release(void *context, void *memory) {
    allocation_model_t *model = context;
    ++model->releases;
    CHECK(memory != NULL);
    free(memory);
    errno = EIO;
}

static void invalid_create(void) {
    allocation_model_t model = {0};
    vireo_rate_limiter_allocator_t allocator = {&model, allocate, release};
    vireo_rate_limiter_options_t options = {2, VIREO_RATE_LIMIT_MAX_MEMORY_BYTES};
    vireo_rate_limit_policy_t policies[2] = {{1, 3, 10}, {2, 2, 20}};
    vireo_rate_limiter_t *limiter = NULL;
    errno = EDOM;
#define CREATE(o, p, n, out, a, wanted) \
    CHECK(vireo_rate_limiter_create_with_allocator(o, p, n, 100, out, a) == wanted && errno == EDOM)
    CREATE(NULL, policies, 2, &limiter, &allocator, VIREO_RESULT_INVALID_ARGUMENT);
    CREATE(&options, NULL, 2, &limiter, &allocator, VIREO_RESULT_INVALID_ARGUMENT);
    CREATE(&options, policies, 2, NULL, &allocator, VIREO_RESULT_INVALID_ARGUMENT);
    CREATE(&options, policies, 2, &limiter, NULL, VIREO_RESULT_INVALID_ARGUMENT);
    CREATE(&options, policies, 0, &limiter, &allocator, VIREO_RESULT_INVALID_ARGUMENT);
    CREATE(&options, policies, SIZE_MAX, &limiter, &allocator, VIREO_RESULT_RANGE);
    allocator.allocate = NULL;
    CREATE(&options, policies, 2, &limiter, &allocator, VIREO_RESULT_INVALID_ARGUMENT);
    allocator.allocate = allocate;
    allocator.release = NULL;
    CREATE(&options, policies, 2, &limiter, &allocator, VIREO_RESULT_INVALID_ARGUMENT);
    allocator.release = release;
    options.max_keys = 0;
    CREATE(&options, policies, 2, &limiter, &allocator, VIREO_RESULT_INVALID_ARGUMENT);
    options.max_keys = SIZE_MAX;
    CREATE(&options, policies, 2, &limiter, &allocator, VIREO_RESULT_OVERFLOW);
    options.max_keys = SIZE_MAX / sizeof(vireo_rate_limit_entry_t);
    CREATE(&options, policies, 2, &limiter, &allocator, VIREO_RESULT_OVERFLOW);
    options.max_keys = VIREO_RATE_LIMIT_MAX_KEYS + 1;
    CREATE(&options, policies, 2, &limiter, &allocator, VIREO_RESULT_RANGE);
    options.max_keys = 2;
    options.max_memory_bytes = 0;
    CREATE(&options, policies, 2, &limiter, &allocator, VIREO_RESULT_INVALID_ARGUMENT);
    options.max_memory_bytes = 1;
    CREATE(&options, policies, 2, &limiter, &allocator, VIREO_RESULT_RANGE);
    options.max_memory_bytes = VIREO_RATE_LIMIT_MAX_MEMORY_BYTES + 1;
    CREATE(&options, policies, 2, &limiter, &allocator, VIREO_RESULT_RANGE);
    options.max_memory_bytes = VIREO_RATE_LIMIT_MAX_MEMORY_BYTES;
    policies[1].policy_id = 1;
    CREATE(&options, policies, 2, &limiter, &allocator, VIREO_RESULT_INVALID_ARGUMENT);
    policies[1].policy_id = 0;
    CREATE(&options, policies, 2, &limiter, &allocator, VIREO_RESULT_INVALID_ARGUMENT);
    policies[1].policy_id = 2;
    policies[1].burst_tokens = 0;
    CREATE(&options, policies, 2, &limiter, &allocator, VIREO_RESULT_INVALID_ARGUMENT);
    policies[1].burst_tokens = VIREO_RATE_LIMIT_MAX_BURST_TOKENS + 1;
    CREATE(&options, policies, 2, &limiter, &allocator, VIREO_RESULT_RANGE);
    policies[1].burst_tokens = 2;
    policies[1].refill_interval_ns = 0;
    CREATE(&options, policies, 2, &limiter, &allocator, VIREO_RESULT_INVALID_ARGUMENT);
    policies[1].refill_interval_ns = VIREO_RATE_LIMIT_MAX_REFILL_INTERVAL_NS + 1;
    CREATE(&options, policies, 2, &limiter, &allocator, VIREO_RESULT_RANGE);
    policies[1].refill_interval_ns = 20;
    CHECK(model.allocations == 0 && model.releases == 0 && limiter == NULL);
    model.fail = true;
    CREATE(&options, policies, 2, &limiter, &allocator, VIREO_RESULT_NO_MEMORY);
    CHECK(model.allocations == 1 && model.releases == 0 && limiter == NULL);
    model.fail = false;
    CREATE(&options, policies, 2, &limiter, &allocator, VIREO_OK);
    CHECK(model.allocations == 2 && model.releases == 0);
    vireo_rate_limiter_info_t info;
    CHECK(vireo_rate_limiter_inspect(limiter, &info) == VIREO_OK && errno == EDOM);
    CHECK(info.allocated_bytes == model.bytes && info.policy_count == 2 && info.last_now == 100);
    CHECK(info.tracked_keys == 0 && info.max_keys == 2);
    CREATE(&options, policies, 2, &limiter, &allocator, VIREO_RESULT_INVALID_ARGUMENT);
    vireo_rate_limit_request_t request = request_for(1, 0, 1);
    check_at(limiter, 100, &request, 1, VIREO_RATE_LIMIT_ADMITTED, 0);
    CHECK(model.allocations == 2); /* 热路径没有申请。 */
    size_t const exact_bytes = model.bytes;
    CHECK(vireo_rate_limiter_destroy(&limiter) == VIREO_OK && limiter == NULL && errno == EDOM);
    CHECK(model.releases == 1);
    CHECK(vireo_rate_limiter_destroy(&limiter) == VIREO_OK && model.releases == 1);
    options.max_memory_bytes = exact_bytes - 1;
    CREATE(&options, policies, 2, &limiter, &allocator, VIREO_RESULT_RANGE);
    CHECK(model.allocations == 2);
    options.max_memory_bytes = exact_bytes;
    CREATE(&options, policies, 2, &limiter, &allocator, VIREO_OK);
    /* allocator表按值保存，改变原表不能改变既有释放边界。 */
    allocator.release = NULL;
    CHECK(vireo_rate_limiter_destroy(&limiter) == VIREO_OK && model.releases == 2 && errno == EDOM);
#undef CREATE
}

static void rejected(vireo_rate_limiter_t *limiter, uint64_t now,
    vireo_rate_limit_request_t const *requests, size_t count, vireo_result_t wanted) {
    size_t const bytes = limiter->allocated_bytes;
    unsigned char *before = malloc(bytes);
    CHECK(before != NULL);
    memcpy(before, limiter, bytes);
    vireo_rate_limit_decision_t decision;
    memset(&decision, 0xa5, sizeof(decision));
    unsigned char output_before[sizeof(decision)];
    memcpy(output_before, &decision, sizeof(decision));
    errno = EDOM;
    CHECK(vireo_rate_limiter_check(limiter, now, requests, count, &decision) == wanted && errno == EDOM);
    CHECK(memcmp(before, limiter, bytes) == 0);
    CHECK(memcmp(output_before, &decision, sizeof(decision)) == 0);
    free(before);
}

static void validation_and_preservation(void) {
    vireo_rate_limit_policy_t const policy = {1, 3, 10};
    vireo_rate_limiter_t *limiter = make_limiter(2, &policy, 1, 100);
    vireo_rate_limit_request_t requests[] = {request_for(1, 'A', 1), request_for(1, 'B', 1)};
    rejected(limiter, 200, NULL, 1, VIREO_RESULT_INVALID_ARGUMENT);
    rejected(limiter, 200, requests, 0, VIREO_RESULT_INVALID_ARGUMENT);
    rejected(limiter, 200, requests, SIZE_MAX, VIREO_RESULT_RANGE);
    rejected(limiter, 99, requests, 2, VIREO_RESULT_INVALID_ARGUMENT);
    requests[1].policy_id = 2;
    rejected(limiter, 99, requests, 2, VIREO_RESULT_NOT_FOUND); /* 参数错误优先于时间。 */
    rejected(limiter, 200, requests, 2, VIREO_RESULT_NOT_FOUND);
    requests[1].policy_id = 0;
    rejected(limiter, 200, requests, 2, VIREO_RESULT_INVALID_ARGUMENT);
    requests[1] = requests[0];
    rejected(limiter, 200, requests, 2, VIREO_RESULT_INVALID_ARGUMENT);
    requests[1] = request_for(1, 'B', 0);
    rejected(limiter, 200, requests, 2, VIREO_RESULT_INVALID_ARGUMENT);
    requests[1].cost = 4;
    rejected(limiter, 200, requests, 2, VIREO_RESULT_RANGE);
    vireo_rate_limit_decision_t decision;
    errno = EDOM;
    CHECK(vireo_rate_limiter_check(NULL, 100, requests, 1, &decision) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_rate_limiter_check(limiter, 100, requests, 1, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    vireo_rate_limiter_info_t info;
    memset(&info, 0xa5, sizeof(info));
    unsigned char original[sizeof(info)];
    memcpy(original, &info, sizeof(info));
    CHECK(vireo_rate_limiter_inspect(NULL, &info) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(memcmp(original, &info, sizeof(info)) == 0);
    CHECK(vireo_rate_limiter_inspect(limiter, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_rate_limiter_destroy(NULL) == VIREO_RESULT_INVALID_ARGUMENT && errno == EDOM);
    requests[0].cost = 3;
    check_at(limiter, 100, requests, 1, VIREO_RATE_LIMIT_ADMITTED, 0);
    unsigned char *record_before = malloc(limiter->allocated_bytes);
    CHECK(record_before != NULL);
    memcpy(record_before, limiter, limiter->allocated_bytes);
    requests[0].cost = 1;
    check_at(limiter, 109, requests, 1, VIREO_RATE_LIMIT_THROTTLED, 1);
    ((vireo_rate_limiter_t *)(void *)record_before)->last_now = 109;
    CHECK(memcmp(record_before, limiter, limiter->allocated_bytes) == 0);
    rejected(limiter, 108, requests, 1, VIREO_RESULT_INVALID_ARGUMENT);
    free(record_before);
    CHECK(vireo_rate_limiter_destroy(&limiter) == VIREO_OK && errno == EDOM);
}

int main(void) {
    invalid_create();
    validation_and_preservation();
    puts("rate limiter failures: own allocation failure, exact budgets/overflow, copied allocator, zero hot allocations, complete object/output/errno preservation passed");
    return 0;
}
