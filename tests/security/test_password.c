#include "password_test.h"
#include <argon2.h>

static void known_answer(void) {
    vireo_password_policy_t const policy = VIREO_PASSWORD_POLICY_DEFAULT;
    unsigned char const password[] = {'a', 0, 'b'};
    char const encoded[] = KNOWN_PHC;
    vireo_password_info_t info = {0};
    errno = EDOM;
    CHECK(vireo_password_hash_inspect(&policy, encoded, sizeof(encoded) - 1, &info) == VIREO_OK);
    CHECK(errno == EDOM && info.version == 19 && info.memory_kib == 8 &&
        info.iterations == 1 && info.parallelism == 1 && info.encoded_length == sizeof(encoded) - 1);
    bool matches = false;
    CHECK(vireo_password_hash_verify(&policy, password, sizeof(password), encoded,
        sizeof(encoded) - 1, &matches) == VIREO_OK && matches && errno == EDOM);
    CHECK(vireo_password_hash_verify(&policy, password, 1, encoded,
        sizeof(encoded) - 1, &matches) == VIREO_OK && !matches);
    unsigned char const wrong[] = {'a', 0, 'c'};
    CHECK(vireo_password_hash_verify(&policy, wrong, sizeof(wrong), encoded,
        sizeof(encoded) - 1, &matches) == VIREO_OK && !matches);
    /* 输入只分配精确长度；ASan可观察不依赖尾NUL的有界读取。 */
    char *exact = malloc(sizeof(encoded) - 1);
    CHECK(exact != NULL);
    memcpy(exact, encoded, sizeof(encoded) - 1);
    CHECK(vireo_password_hash_verify(&policy, password, sizeof(password), exact,
        sizeof(encoded) - 1, &matches) == VIREO_OK && matches);
    free(exact);
}

static void real_generation(void) {
    vireo_password_policy_t const policy = VIREO_PASSWORD_POLICY_DEFAULT;
    unsigned char const password[] = {'a', 0, 'b'};
    char first[160], second[128];
    memset(first, 0x5a, sizeof(first));
    size_t first_length = 0, second_length = 0;
    errno = ERANGE;
    CHECK(vireo_password_hash_create(&policy, password, sizeof(password), first,
        sizeof(first), &first_length) == VIREO_OK && errno == ERANGE);
    CHECK(first_length < 128 && first[first_length] == '\0' && first[first_length + 1] == 0x5a);
    CHECK(vireo_password_hash_create(&policy, password, sizeof(password), second,
        sizeof(second), &second_length) == VIREO_OK && errno == ERANGE);
    CHECK(first_length == second_length && strcmp(first, second) != 0);
    char const *salt1 = strchr(strchr(first + 1, '$') + 1, '$');
    salt1 = strchr(salt1 + 1, '$') + 1;
    char const *salt2 = strchr(strchr(second + 1, '$') + 1, '$');
    salt2 = strchr(salt2 + 1, '$') + 1;
    CHECK(memcmp(salt1, salt2, 22) != 0);
    vireo_password_info_t info;
    CHECK(vireo_password_hash_inspect(&policy, first, first_length, &info) == VIREO_OK);
    CHECK(info.memory_kib == 65536 && info.iterations == 3 && info.parallelism == 1);
    bool matches = false;
    CHECK(vireo_password_hash_verify(&policy, password, sizeof(password), first,
        first_length, &matches) == VIREO_OK && matches);
    /* 独立native便利入口读取生成结果，防止parser/encoder共同犯错而自洽。 */
    CHECK(argon2id_verify(first, password, sizeof(password)) == ARGON2_OK);
    CHECK(argon2id_verify(second, password, sizeof(password)) == ARGON2_OK);
    CHECK(memcmp(password, "a\0b", 3) == 0);
}

static void native_password_limit(void) {
    unsigned char password[4096];
    unsigned char salt[16];
    memset(salt, 0x42, sizeof(salt));
    for (size_t i = 0; i < sizeof(password); ++i) { password[i] = (unsigned char)(i & 255); }
    char encoded[128];
    CHECK(argon2id_hash_encoded(1, 8, 1, password, sizeof(password), salt,
        sizeof(salt), 32, encoded, sizeof(encoded)) == ARGON2_OK);
    vireo_password_policy_t policy = VIREO_PASSWORD_POLICY_DEFAULT;
    bool matches = false;
    errno = EDOM;
    CHECK(vireo_password_hash_verify(&policy, password, sizeof(password), encoded,
        strlen(encoded), &matches) == VIREO_RESULT_RANGE && !matches && errno == EDOM);
    policy.max_password_bytes = 4096;
    CHECK(vireo_password_hash_verify(&policy, password, sizeof(password), encoded,
        strlen(encoded), &matches) == VIREO_OK && matches && errno == EDOM);
    password[4095] ^= 1;
    CHECK(vireo_password_hash_verify(&policy, password, sizeof(password), encoded,
        strlen(encoded), &matches) == VIREO_OK && !matches);
}

static void expect_record(char const *encoded, size_t length, vireo_result_t expected) {
    vireo_password_policy_t const policy = VIREO_PASSWORD_POLICY_DEFAULT;
    vireo_password_info_t info;
    memset(&info, 0xa5, sizeof(info));
    unsigned char before[sizeof(info)];
    memcpy(before, &info, sizeof(info));
    errno = EILSEQ;
    CHECK(vireo_password_hash_inspect(&policy, encoded, length, &info) == expected);
    CHECK(errno == EILSEQ && memcmp(before, &info, sizeof(info)) == 0);
    bool matches = true;
    CHECK(vireo_password_hash_verify(&policy, "a", 1, encoded, length, &matches) == expected);
    CHECK(matches && errno == EILSEQ);
}

static void invalid_records(void) {
    char const *const malformed[] = {
        "$argon2i$v=19$m=8,t=1,p=1$" PHC_SALT "$" PHC_TAG,
        "$argon2id$v=16$m=8,t=1,p=1$" PHC_SALT "$" PHC_TAG,
        "$argon2id$m=8,t=1,p=1$" PHC_SALT "$" PHC_TAG,
        "$argon2id$v=19$m=8,t=1,p=2$" PHC_SALT "$" PHC_TAG,
        "$argon2id$v=19$m=08,t=1,p=1$" PHC_SALT "$" PHC_TAG,
        "$argon2id$v=19$m=8,t=01,p=1$" PHC_SALT "$" PHC_TAG,
        "$argon2id$v=19$m=+8,t=1,p=1$" PHC_SALT "$" PHC_TAG,
        "$argon2id$v=19$m=-8,t=1,p=1$" PHC_SALT "$" PHC_TAG,
        "$argon2id$v=19$m=4294967296,t=1,p=1$" PHC_SALT "$" PHC_TAG,
        "$argon2id$v=19$m=8,t=4294967296,p=1$" PHC_SALT "$" PHC_TAG,
        "$argon2id$v=19$t=1,m=8,p=1$" PHC_SALT "$" PHC_TAG,
        "$argon2id$v=19$m=8,t=1,t=1,p=1$" PHC_SALT "$" PHC_TAG,
        "$argon2id$v=19$m=8,t=1,p=1,x=1$" PHC_SALT "$" PHC_TAG,
        "$argon2id$v=19$m=8,t=1,p=1$" PHC_SALT "=$" PHC_TAG,
        KNOWN_PHC "$", KNOWN_PHC "\n"
    };
    for (size_t i = 0; i < sizeof(malformed) / sizeof(malformed[0]); ++i) {
        expect_record(malformed[i], strlen(malformed[i]), VIREO_RESULT_PROTOCOL);
    }
    char const *const excessive[] = {
        "$argon2id$v=19$m=7,t=1,p=1$" PHC_SALT "$" PHC_TAG,
        "$argon2id$v=19$m=0,t=1,p=1$" PHC_SALT "$" PHC_TAG,
        "$argon2id$v=19$m=8,t=0,p=1$" PHC_SALT "$" PHC_TAG,
        "$argon2id$v=19$m=262145,t=1,p=1$" PHC_SALT "$" PHC_TAG,
        "$argon2id$v=19$m=8,t=11,p=1$" PHC_SALT "$" PHC_TAG,
        "$argon2id$v=19$m=4294967295,t=1,p=1$" PHC_SALT "$" PHC_TAG
    };
    for (size_t i = 0; i < sizeof(excessive) / sizeof(excessive[0]); ++i) {
        expect_record(excessive[i], strlen(excessive[i]), VIREO_RESULT_RANGE);
    }
    char modified[] = KNOWN_PHC;
    size_t const length = sizeof(modified) - 1;
    for (size_t i = 1; i < length; ++i) { expect_record(modified, i, VIREO_RESULT_PROTOCOL); }
    for (size_t i = 0; i < length; ++i) {
        char const saved = modified[i];
        modified[i] = '\0';
        expect_record(modified, length, VIREO_RESULT_PROTOCOL);
        modified[i] = saved;
    }
    char *salt = strchr(strchr(strchr(modified + 1, '$') + 1, '$') + 1, '$') + 1;
    salt[21] = 'x'; /* w与x解码字节相同，x的未用位非零。 */
    expect_record(modified, length, VIREO_RESULT_PROTOCOL);
    memcpy(modified, KNOWN_PHC, sizeof(modified));
    modified[length - 1] = '1'; /* 0与1仅未用位不同。 */
    expect_record(modified, length, VIREO_RESULT_PROTOCOL);
    modified[length - 1] = '=';
    expect_record(modified, length, VIREO_RESULT_PROTOCOL);
    char overlong[128];
    memset(overlong, 'A', sizeof(overlong));
    expect_record(overlong, sizeof(overlong), VIREO_RESULT_RANGE);
    expect_record(modified, 0, VIREO_RESULT_RANGE);
}

int main(void) {
    known_answer();
    real_generation();
    native_password_limit();
    invalid_records();
    puts("password: known answer, real random/native interoperability, bounded malformed records passed");
    return 0;
}
