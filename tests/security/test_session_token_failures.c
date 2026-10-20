#include "session_token_test.h"
#include "session_token_internal.h"

static unsigned char const range_digest[32] = RANGE_DIGEST_BYTES;

enum boundary { RANDOM, ALLOCATE, INIT, DOMAIN, TOKEN, FINAL, LENGTH, SUCCESS };
typedef struct fixture {
    enum boundary failure; /**< 本次故障位置；其余边界使用真实EVP。 */
    int failure_return; /**< 故意包括0、-1、2，只有精确1才成功。 */
    unsigned int final_length; /**< 故意报告错误native长度。 */
    unsigned int calls[7]; /**< 各边界次数，证明首错停止与无重试。 */
    unsigned int frees; /**< 非空真实上下文恰好释放一次。 */
    unsigned int updates; /**< 当前上下文的domain/token先后顺序。 */
} fixture_t;

static int random_bytes(void *context, unsigned char *out, int length) {
    fixture_t *f = context;
    ++f->calls[RANDOM];
    CHECK(length == 32);
    for (int i = 0; i < length; ++i) { out[i] = (unsigned char)i; }
    errno = EIO;
    return f->failure == RANDOM ? f->failure_return : 1;
}

static EVP_MD_CTX *digest_new(void *context) {
    fixture_t *f = context;
    ++f->calls[ALLOCATE];
    errno = ENOMEM;
    return f->failure == ALLOCATE ? NULL : EVP_MD_CTX_new();
}

static void digest_free(void *context, EVP_MD_CTX *digest) {
    fixture_t *f = context;
    CHECK(digest != NULL);
    ++f->frees;
    EVP_MD_CTX_free(digest);
    errno = EIO;
}

static int digest_init(void *context, EVP_MD_CTX *digest) {
    fixture_t *f = context;
    ++f->calls[INIT];
    errno = EIO;
    return f->failure == INIT ? f->failure_return : EVP_DigestInit_ex(digest, EVP_sha256(), NULL);
}

static int digest_update(void *context, EVP_MD_CTX *digest, void const *data, size_t length) {
    fixture_t *f = context;
    enum boundary const stage = f->updates++ == 0 ? DOMAIN : TOKEN;
    ++f->calls[stage];
    if (stage == DOMAIN) {
        /* sizeof常量答案为23，memcmp也覆盖唯一NUL。 */
        static unsigned char const expected[] = "vireo/session-token/v1";
        CHECK(length == sizeof(expected) && length == 23);
        CHECK(memcmp(data, expected, length) == 0);
    } else {
        CHECK(length == 32 && f->updates == 2);
        unsigned char const *bytes = data;
        for (size_t i = 0; i < length; ++i) { CHECK(bytes[i] == (unsigned char)i); }
    }
    errno = EIO;
    return f->failure == stage ? f->failure_return : EVP_DigestUpdate(digest, data, length);
}

static int digest_final(void *context, EVP_MD_CTX *digest, unsigned char *out, unsigned int *length) {
    fixture_t *f = context;
    ++f->calls[FINAL];
    CHECK(f->updates == 2);
    errno = EIO;
    if (f->failure == FINAL) {
        memset(out, 0xcc, 32); /* 失败也可污染局部输出，不能泄漏到caller。 */
        *length = 32;
        return f->failure_return;
    }
    int const result = EVP_DigestFinal_ex(digest, out, length);
    if (f->failure == LENGTH) { ++f->calls[LENGTH]; *length = f->final_length; }
    return result;
}

static vireo_session_token_runtime_t runtime_for(fixture_t *f) {
    vireo_session_token_runtime_t const runtime = {
        f, random_bytes, digest_new, digest_free, digest_init, digest_update, digest_final
    };
    return runtime;
}

static void run_case(enum boundary failure, bool generate, int failure_return, unsigned int length) {
    fixture_t f = {.failure = failure, .failure_return = failure_return, .final_length = length};
    vireo_session_token_runtime_t const runtime = runtime_for(&f);
    vireo_session_token_t token;
    vireo_session_token_digest_t digest;
    for (size_t i = 0; i < sizeof(token.bytes); ++i) { token.bytes[i] = generate ? 0xa5 : (unsigned char)i; }
    memset(&digest, 0xa5, sizeof(digest));
    vireo_session_token_t const original_token = token;
    vireo_session_token_digest_t const original_digest = digest;
    vireo_result_t const expected = failure == SUCCESS ? VIREO_OK :
        failure == RANDOM ? VIREO_RESULT_IO :
        failure == ALLOCATE ? VIREO_RESULT_NO_MEMORY : VIREO_RESULT_INTERNAL;
    errno = EDOM;
    vireo_result_t const result = generate ?
        vireo_session_token_generate_with_runtime(&token, &digest, &runtime) :
        vireo_session_token_digest_with_runtime(&token, &digest, &runtime);
    CHECK(result == expected && errno == EDOM);
    for (size_t i = 0; i < sizeof(token.bytes); ++i) {
        CHECK(token.bytes[i] == (generate && failure == SUCCESS ? (unsigned char)i : original_token.bytes[i]));
    }
    CHECK(memcmp(digest.bytes, failure == SUCCESS ? range_digest : original_digest.bytes,
        sizeof(digest.bytes)) == 0);
    for (enum boundary stage = RANDOM; stage <= FINAL; ++stage) {
        unsigned int const wanted = stage == RANDOM ? (generate ? 1U : 0U) :
            stage <= failure ? 1U : 0U;
        CHECK(f.calls[stage] == wanted);
    }
    CHECK(f.frees == (failure > ALLOCATE ? 1U : 0U));
}

static void preconditions(void) {
    fixture_t f = {.failure = SUCCESS};
    vireo_session_token_runtime_t runtime = runtime_for(&f);
    vireo_session_token_t token = {{0}};
    vireo_session_token_digest_t digest = {{0}};
    errno = EDOM;
    CHECK(vireo_session_token_generate_with_runtime(NULL, &digest, &runtime) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_session_token_generate_with_runtime(&token, NULL, &runtime) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_session_token_digest_with_runtime(NULL, &digest, &runtime) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_session_token_digest_with_runtime(&token, NULL, &runtime) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_session_token_generate_with_runtime(&token, &digest, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_session_token_digest_with_runtime(&token, &digest, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    runtime.digest_free = NULL;
    CHECK(vireo_session_token_generate_with_runtime(&token, &digest, &runtime) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_session_token_digest_with_runtime(&token, &digest, &runtime) == VIREO_RESULT_INVALID_ARGUMENT);
    runtime = runtime_for(&f);
    runtime.random_bytes = NULL;
    CHECK(vireo_session_token_generate_with_runtime(&token, &digest, &runtime) == VIREO_RESULT_INVALID_ARGUMENT);
    for (size_t i = 0; i < 7; ++i) { CHECK(f.calls[i] == 0); }
    CHECK(f.frees == 0 && errno == EDOM);
}

int main(void) {
    int const rejected[] = {0, -1, 2};
    for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); ++i) {
        for (enum boundary failure = RANDOM; failure <= FINAL; ++failure) {
            run_case(failure, true, rejected[i], 32);
            if (failure != RANDOM) { run_case(failure, false, rejected[i], 32); }
        }
    }
    unsigned int const bad_lengths[] = {0, 31, 33, EVP_MAX_MD_SIZE};
    for (size_t i = 0; i < sizeof(bad_lengths) / sizeof(bad_lengths[0]); ++i) {
        run_case(LENGTH, true, 0, bad_lengths[i]);
        run_case(LENGTH, false, 0, bad_lengths[i]);
    }
    run_case(SUCCESS, true, 0, 32);
    run_case(SUCCESS, false, 0, 32);
    preconditions();
    puts("session token failures: own boundaries + real EVP, exact success checks, prefix/length, first-error stop, output/errno preservation, context release passed");
    return 0;
}
