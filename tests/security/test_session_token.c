#include "session_token_test.h"

static unsigned char const range_digest[32] = RANGE_DIGEST_BYTES;
static unsigned char const zero_digest[32] = ZERO_DIGEST_BYTES;

static void vectors(void) {
    vireo_session_token_t token = {{0}};
    vireo_session_token_digest_t digest;
    errno = EDOM;
    CHECK(vireo_session_token_digest(&token, &digest) == VIREO_OK && errno == EDOM);
    CHECK(memcmp(digest.bytes, zero_digest, sizeof(zero_digest)) == 0);
    for (size_t i = 0; i < sizeof(token.bytes); ++i) { token.bytes[i] = (unsigned char)i; }
    vireo_session_token_t const original = token;
    CHECK(vireo_session_token_digest(&token, &digest) == VIREO_OK && errno == EDOM);
    CHECK(memcmp(digest.bytes, range_digest, sizeof(range_digest)) == 0);
    CHECK(memcmp(token.bytes, original.bytes, sizeof(token.bytes)) == 0);
    /* 每个输入字节都参与摘要，特别包括首字节NUL之后的内容。 */
    for (size_t i = 0; i < sizeof(token.bytes); ++i) {
        token.bytes[i] ^= 0x80;
        CHECK(vireo_session_token_digest(&token, &digest) == VIREO_OK && errno == EDOM);
        CHECK(memcmp(digest.bytes, range_digest, sizeof(range_digest)) != 0);
        token.bytes[i] ^= 0x80;
    }
}

static void comparison(void) {
    vireo_session_token_digest_t left = {{0}};
    memcpy(left.bytes, range_digest, sizeof(left.bytes));
    vireo_session_token_digest_t right = left;
    bool matches = false;
    errno = ERANGE;
    CHECK(vireo_session_token_digest_equal(&left, &right, &matches) == VIREO_OK && matches);
    CHECK(errno == ERANGE);
    matches = false;
    CHECK(vireo_session_token_digest_equal(&left, &left, &matches) == VIREO_OK && matches);
    for (size_t i = 0; i < sizeof(right.bytes); ++i) {
        right.bytes[i] ^= 0x01;
        matches = true;
        CHECK(vireo_session_token_digest_equal(&left, &right, &matches) == VIREO_OK && !matches);
        CHECK(errno == ERANGE);
        right.bytes[i] ^= 0x01;
    }
    CHECK(memcmp(left.bytes, range_digest, sizeof(left.bytes)) == 0);
}

static void generation_and_clear(void) {
    vireo_session_token_t first, second;
    vireo_session_token_digest_t first_digest, second_digest, recomputed;
    errno = EDOM;
    CHECK(vireo_session_token_generate(&first, &first_digest) == VIREO_OK && errno == EDOM);
    CHECK(vireo_session_token_generate(&second, &second_digest) == VIREO_OK && errno == EDOM);
    CHECK(memcmp(first.bytes, second.bytes, sizeof(first.bytes)) != 0);
    CHECK(vireo_session_token_digest(&first, &recomputed) == VIREO_OK && errno == EDOM);
    CHECK(memcmp(recomputed.bytes, first_digest.bytes, sizeof(recomputed.bytes)) == 0);
    CHECK(vireo_session_token_digest(&second, &recomputed) == VIREO_OK && errno == EDOM);
    CHECK(memcmp(recomputed.bytes, second_digest.bytes, sizeof(recomputed.bytes)) == 0);
    struct guarded {
        unsigned char before[8];
        vireo_session_token_t token;
        unsigned char after[8];
    } guarded;
    memset(&guarded, 0xa5, sizeof(guarded));
    guarded.token = first;
    CHECK(vireo_session_token_clear(&guarded.token) == VIREO_OK && errno == EDOM);
    unsigned char const zero[32] = {0};
    CHECK(memcmp(guarded.token.bytes, zero, sizeof(zero)) == 0);
    for (size_t i = 0; i < 8; ++i) {
        CHECK(guarded.before[i] == 0xa5 && guarded.after[i] == 0xa5);
    }
    CHECK(vireo_session_token_clear(&guarded.token) == VIREO_OK && errno == EDOM);
    CHECK(vireo_session_token_digest(&first, &recomputed) == VIREO_OK);
    CHECK(memcmp(recomputed.bytes, first_digest.bytes, sizeof(recomputed.bytes)) == 0);
    CHECK(vireo_session_token_digest(&guarded.token, &recomputed) == VIREO_OK);
    CHECK(memcmp(recomputed.bytes, zero_digest, sizeof(zero_digest)) == 0);
    CHECK(vireo_session_token_clear(&first) == VIREO_OK);
    CHECK(vireo_session_token_clear(&second) == VIREO_OK);
}

static void invalid_arguments(void) {
    vireo_session_token_t token;
    vireo_session_token_digest_t digest;
    memset(&token, 0xa5, sizeof(token));
    memset(&digest, 0x5a, sizeof(digest));
    vireo_session_token_t const token_before = token;
    vireo_session_token_digest_t const digest_before = digest;
    bool matches = true;
    errno = EDOM;
    CHECK(vireo_session_token_generate(NULL, &digest) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_session_token_generate(&token, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_session_token_generate(NULL, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_session_token_digest(NULL, &digest) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_session_token_digest(&token, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_session_token_digest(NULL, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_session_token_digest_equal(NULL, &digest, &matches) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(matches);
    matches = false;
    CHECK(vireo_session_token_digest_equal(&digest, NULL, &matches) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(!matches);
    CHECK(vireo_session_token_digest_equal(&digest, &digest, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_session_token_clear(NULL) == VIREO_RESULT_INVALID_ARGUMENT && errno == EDOM);
    CHECK(memcmp(token.bytes, token_before.bytes, sizeof(token.bytes)) == 0);
    CHECK(memcmp(digest.bytes, digest_before.bytes, sizeof(digest.bytes)) == 0);
}

int main(void) {
    vectors();
    comparison();
    generation_and_clear();
    invalid_arguments();
    puts("session token: independent v1 vectors, full-byte input/comparison, CSPRNG, clear/copies/guards, NULL/errno passed");
    return 0;
}
