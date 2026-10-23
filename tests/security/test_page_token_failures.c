#include "page_token_test_support.h"

int main(void) {
    CHECK(vireo_page_token_key_create(NULL), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_page_token_key_destroy(NULL), VIREO_RESULT_INVALID_ARGUMENT);
    vireo_page_token_key_t *empty = NULL;
    CHECK(vireo_page_token_key_destroy(&empty), VIREO_OK);
    for (enum failure f = ALLOCATE; f <= ID_ZERO; ++f) {
        scenario_t s = {.fail = f};
        vireo_page_token_runtime_t r = runtime(&s);
        vireo_page_token_key_t *key = NULL;
        vireo_result_t want = f == ALLOCATE
                                  ? VIREO_RESULT_NO_MEMORY
                                  : (f == FETCH ? VIREO_RESULT_INTERNAL : VIREO_RESULT_IO);
        CHECK(vireo_page_token_key_create_with_runtime(&key, &r), want);
        assert(key == NULL && s.owners == 0 && s.algorithms == 0 && s.contexts == 0 &&
               s.allocations == s.frees);
        assert(s.rng == (f == SECRET_RNG ? 1 : (f >= ID_RNG ? 2 : 0)));
    }
    scenario_t s = {0};
    vireo_page_token_runtime_t r = runtime(&s);
    vireo_page_token_key_t *key = NULL;
    CHECK(vireo_page_token_key_create_with_runtime(&key, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    vireo_page_token_runtime_t broken = r;
    broken.free_context = NULL;
    CHECK(vireo_page_token_key_create_with_runtime(&key, &broken), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_page_token_key_create_with_runtime(&key, &r), VIREO_OK);
    vireo_page_token_key_t *saved_key = key;
    CHECK(vireo_page_token_key_create_with_runtime(&key, &r), VIREO_RESULT_INVALID_ARGUMENT);
    assert(key == saved_key && s.allocations == 1);
    vireo_page_token_claims_t c = claims(), out, saved;
    vireo_page_token_t token, good, previous;
    CHECK(vireo_page_token_sign(key, &c, 1001, &good), VIREO_OK);
    for (enum failure f = CONTEXT; f <= FINAL_LENGTH; ++f) {
        s.fail = f;
        memset(&token, 0xa5, sizeof(token));
        previous = token;
        memset(&out, 0x5a, sizeof(out));
        memcpy(&saved, &out, sizeof(saved));
        vireo_result_t want = f == CONTEXT ? VIREO_RESULT_NO_MEMORY : VIREO_RESULT_INTERNAL;
        CHECK(vireo_page_token_sign(key, &c, 1001, &token), want);
        assert(!memcmp(&previous, &token, sizeof(token)) && s.contexts == 0);
        CHECK(vireo_page_token_verify(key, &c.context, &good, 1001, &out), want);
        assert(!memcmp(&saved, &out, sizeof(out)) && s.contexts == 0);
    }
    s.fail = NONE;
    CHECK(vireo_page_token_verify(key, &c.context, &good, 1001, &out), VIREO_OK);
    CHECK(vireo_page_token_key_destroy(&key), VIREO_OK);
    CHECK(vireo_page_token_key_destroy(&key), VIREO_OK);
    assert(key == NULL && s.owners == 0 && s.algorithms == 0 && s.contexts == 0 && s.frees == 1);
    printf(
        "PASS %zu page-token failure calls; partial RNG, EVP stages, output/errno and owner "
        "cleansing\n",
        checks);
    return 0;
}
