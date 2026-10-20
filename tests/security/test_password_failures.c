#include "password_test.h"
#include "password_internal.h"

/* 本组件own RNG/KDF返回模型，明确不冒充真实内核或malloc故障。 */
typedef struct failure_model {
    size_t random_calls;
    size_t derive_calls;
    size_t expected_length;
    uint32_t memory;
    uint32_t iterations;
    int random_result;
    vireo_result_t derive_result;
} failure_model_t;

static int model_random(void *context, unsigned char *out, int length) {
    failure_model_t *model = context;
    ++model->random_calls;
    CHECK(length == 16);
    memset(out, 0, (size_t)length);
    errno = ENOSPC;
    return model->random_result;
}

static vireo_result_t model_derive(void *context, void const *password, size_t length,
    unsigned char const salt[16], uint32_t memory, uint32_t iterations, unsigned char tag[32]) {
    failure_model_t *model = context;
    CHECK(password != NULL && salt != NULL && length == model->expected_length);
    ++model->derive_calls;
    model->memory = memory;
    model->iterations = iterations;
    memset(tag, 0, 32); /* 即使失败已写局部结果，也不能提交caller输出。 */
    errno = ENOMEM;
    return model->derive_result;
}

static void rejected_create(vireo_password_policy_t const *policy, void const *password,
    size_t length, size_t capacity, vireo_result_t expected,
    vireo_password_runtime_t const *runtime) {
    char encoded[128];
    memset(encoded, 0x5a, sizeof(encoded));
    char before[128];
    memcpy(before, encoded, sizeof(before));
    size_t written = 987;
    errno = EDOM;
    CHECK(vireo_password_create_with_runtime(policy, password, length, encoded,
        capacity, &written, runtime) == expected);
    CHECK(errno == EDOM && written == 987 && memcmp(before, encoded, sizeof(before)) == 0);
}

static void parameter_and_failure_paths(void) {
    vireo_password_policy_t policy = VIREO_PASSWORD_POLICY_DEFAULT;
    failure_model_t model = {.expected_length = 1, .random_result = 1, .derive_result = VIREO_OK};
    vireo_password_runtime_t runtime = {&model, model_random, model_derive};
    rejected_create(NULL, "x", 1, 128, VIREO_RESULT_INVALID_ARGUMENT, &runtime);
    rejected_create(&policy, NULL, 1, 128, VIREO_RESULT_INVALID_ARGUMENT, &runtime);
    rejected_create(&policy, "x", 1, 128, VIREO_RESULT_INVALID_ARGUMENT, NULL);
    rejected_create(&policy, "x", 0, 128, VIREO_RESULT_RANGE, &runtime);
    rejected_create(&policy, "x", 1025, 128, VIREO_RESULT_RANGE, &runtime);
    rejected_create(&policy, "x", 1, 127, VIREO_RESULT_RANGE, &runtime);
    CHECK(model.random_calls == 0 && model.derive_calls == 0);
    char out[128];
    size_t length = 0;
    CHECK(vireo_password_hash_create(&policy, "x", 1, NULL, 128, &length) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_password_hash_create(&policy, "x", 1, out, 128, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    vireo_password_info_t info;
    CHECK(vireo_password_hash_inspect(&policy, NULL, 1, &info) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_password_hash_inspect(&policy, KNOWN_PHC, sizeof(KNOWN_PHC) - 1, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    bool matches = true;
    CHECK(vireo_password_hash_verify(NULL, "x", 1, KNOWN_PHC, sizeof(KNOWN_PHC) - 1, &matches) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_password_hash_verify(&policy, NULL, 1, KNOWN_PHC, sizeof(KNOWN_PHC) - 1, &matches) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_password_hash_verify(&policy, "x", 1, NULL, 1, &matches) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_password_hash_verify(&policy, "x", 1, KNOWN_PHC, sizeof(KNOWN_PHC) - 1, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_password_hash_verify(&policy, "x", 0, KNOWN_PHC, sizeof(KNOWN_PHC) - 1, &matches) == VIREO_RESULT_RANGE && matches);

    vireo_password_policy_t invalid[] = {
        {65535, 3, 262144, 10, 1024}, {262145, 3, 262144, 10, 1024},
        {65536, 2, 262144, 10, 1024}, {65536, 11, 262144, 10, 1024},
        {65536, 3, 65535, 10, 1024}, {65536, 3, 262145, 10, 1024},
        {65536, 3, 262144, 2, 1024}, {65536, 3, 262144, 11, 1024},
        {65536, 3, 262144, 10, 0}, {65536, 3, 262144, 10, 4097}
    };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
        rejected_create(&invalid[i], "x", 1, 128, VIREO_RESULT_INVALID_ARGUMENT, &runtime);
        CHECK(vireo_password_hash_inspect(&invalid[i], KNOWN_PHC, sizeof(KNOWN_PHC) - 1, &info) == VIREO_RESULT_INVALID_ARGUMENT);
        CHECK(vireo_password_hash_verify(&invalid[i], "x", 1, KNOWN_PHC,
            sizeof(KNOWN_PHC) - 1, &matches) == VIREO_RESULT_INVALID_ARGUMENT && matches);
    }
    CHECK(model.random_calls == 0 && model.derive_calls == 0);
    model.random_result = 0;
    rejected_create(&policy, "x", 1, 128, VIREO_RESULT_IO, &runtime);
    model.random_result = -1;
    rejected_create(&policy, "x", 1, 128, VIREO_RESULT_IO, &runtime);
    CHECK(model.random_calls == 2 && model.derive_calls == 0);
    model.random_result = 1;
    model.derive_result = VIREO_RESULT_NO_MEMORY;
    rejected_create(&policy, "x", 1, 128, VIREO_RESULT_NO_MEMORY, &runtime);
    model.derive_result = VIREO_RESULT_INTERNAL;
    rejected_create(&policy, "x", 1, 128, VIREO_RESULT_INTERNAL, &runtime);
    CHECK(model.random_calls == 4 && model.derive_calls == 2);
    model.derive_result = VIREO_RESULT_NO_MEMORY;
    errno = EILSEQ;
    CHECK(vireo_password_verify_with_runtime(&policy, "x", 1, KNOWN_PHC,
        sizeof(KNOWN_PHC) - 1, &matches, &runtime) == VIREO_RESULT_NO_MEMORY && matches && errno == EILSEQ);
    model.derive_result = VIREO_RESULT_INTERNAL;
    CHECK(vireo_password_verify_with_runtime(&policy, "x", 1, KNOWN_PHC,
        sizeof(KNOWN_PHC) - 1, &matches, &runtime) == VIREO_RESULT_INTERNAL && matches && errno == EILSEQ);
    CHECK(model.random_calls == 4 && model.derive_calls == 4);
}

static void costs_and_password_boundaries(void) {
    vireo_password_policy_t policy = VIREO_PASSWORD_POLICY_DEFAULT;
    failure_model_t model = {.expected_length = 1, .random_result = 1, .derive_result = VIREO_OK};
    vireo_password_runtime_t runtime = {&model, model_random, model_derive};
    char const *const rejected[] = {
        "$argon2id$v=19$m=262145,t=1,p=1$" PHC_SALT "$" PHC_TAG,
        "$argon2id$v=19$m=8,t=11,p=1$" PHC_SALT "$" PHC_TAG,
        "$argon2id$v=19$m=8,t=1,p=2$" PHC_SALT "$" PHC_TAG
    };
    for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); ++i) {
        bool matches = true;
        CHECK(vireo_password_verify_with_runtime(&policy, "x", 1, rejected[i], strlen(rejected[i]),
            &matches, &runtime) == (i == 2 ? VIREO_RESULT_PROTOCOL : VIREO_RESULT_RANGE));
        CHECK(matches && model.derive_calls == 0 && model.random_calls == 0);
    }
    char const maximum[] = "$argon2id$v=19$m=262144,t=10,p=1$" PHC_SALT "$" PHC_TAG;
    bool matches = true;
    errno = EIO;
    CHECK(vireo_password_verify_with_runtime(&policy, "x", 1, maximum, sizeof(maximum) - 1,
        &matches, &runtime) == VIREO_OK && !matches && errno == EIO);
    CHECK(model.derive_calls == 1 && model.memory == 262144 && model.iterations == 10);
    /* 上限只用own模型，不在测试中实际执行256MiB/10轮运算。 */
    policy.max_verify_memory_kib = 65536;
    CHECK(vireo_password_verify_with_runtime(&policy, "x", 1, maximum, sizeof(maximum) - 1,
        &matches, &runtime) == VIREO_RESULT_RANGE && model.derive_calls == 1);
    unsigned char password[4096];
    memset(password, 'x', sizeof(password));
    char encoded[128];
    size_t written = 0;
    model.expected_length = 1024;
    CHECK(vireo_password_create_with_runtime(&policy, password, 1024, encoded, sizeof(encoded),
        &written, &runtime) == VIREO_OK);
    CHECK(model.memory == 65536 && model.iterations == 3);
    rejected_create(&policy, password, 1025, 128, VIREO_RESULT_RANGE, &runtime);
    policy = (vireo_password_policy_t)VIREO_PASSWORD_POLICY_DEFAULT;
    policy.max_password_bytes = 4096;
    policy.create_memory_kib = 262144;
    policy.create_iterations = 10;
    model.expected_length = 4096;
    CHECK(vireo_password_create_with_runtime(&policy, password, sizeof(password), encoded,
        sizeof(encoded), &written, &runtime) == VIREO_OK);
    CHECK(model.memory == 262144 && model.iterations == 10);
    vireo_password_info_t info;
    CHECK(vireo_password_hash_inspect(&policy, encoded, written, &info) == VIREO_OK &&
        info.memory_kib == 262144 && info.iterations == 10);
    rejected_create(&policy, password, 4097, 128, VIREO_RESULT_RANGE, &runtime);
    policy.max_password_bytes = 1;
    model.expected_length = 1;
    CHECK(vireo_password_create_with_runtime(&policy, password, 1, encoded, sizeof(encoded),
        &written, &runtime) == VIREO_OK);
    rejected_create(&policy, password, 2, 128, VIREO_RESULT_RANGE, &runtime);
}

int main(void) {
    parameter_and_failure_paths();
    costs_and_password_boundaries();
    puts("password failures: RNG/KDF models, output/errno preservation, policy/cost/password boundaries passed");
    return 0;
}
