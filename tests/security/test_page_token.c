#include "page_token_golden.h"
#include "page_token_test_support.h"

static void rejected(const vireo_page_token_key_t *key, const vireo_page_token_context_t *ctx,
                     const vireo_page_token_t *token, uint64_t now, vireo_result_t rc) {
    vireo_page_token_claims_t out, before;
    memset(&out, 0xa5, sizeof(out));
    memcpy(&before, &out, sizeof(before));
    CHECK(vireo_page_token_verify(key, ctx, token, now, &out), rc);
    assert(!memcmp(&out, &before, sizeof(out)));
}
static void put64(unsigned char *p, uint64_t n) {
    for (size_t i = 0; i < 8; ++i) {
        p[7 - i] = (unsigned char)(n >> (i * 8));
    }
}

int main(void) {
    scenario_t s = {0};
    vireo_page_token_runtime_t r = runtime(&s);
    vireo_page_token_key_t *key = NULL;
    CHECK(vireo_page_token_key_create_with_runtime(&key, &r), VIREO_OK);
    vireo_page_token_claims_t c = claims(), out;
    vireo_page_token_t token;
    CHECK(vireo_page_token_sign(key, &c, 1001, &token), VIREO_OK);
    assert(!memcmp(token.bytes, golden, sizeof(golden)));
    vireo_page_token_t independent = token;
    resign(key, &independent);
    assert(!memcmp(&token, &independent, sizeof(token)));
    for (size_t i = 0; i < 3; ++i) {
        CHECK(vireo_page_token_verify(key, &c.context, &token, 1001, &out), VIREO_OK);
        assert(out.after_id == 120 && out.issued_at_ms == 1000 && out.expires_at_ms == 601000 &&
               out.context.user_id == 7 && out.context.session_id == 8 &&
               out.context.directory_id == 42 && out.context.page_size == 2);
    }
    for (size_t i = 0; i < 96; ++i) {
        for (unsigned int bit = 0; bit < 8; ++bit) {
            vireo_page_token_t changed = token;
            changed.bytes[i] ^= (unsigned char)(1u << bit);
            rejected(key, &c.context, &changed, 1001, VIREO_RESULT_PROTOCOL);
        }
    }
    /* Valid MAC over malformed semantics exercises checks beyond authentication. */
    const size_t positions[] = {0, 1, 2, 3, 4, 7, 8, 16, 24, 40, 41, 42, 43, 44, 45, 46, 47};
    for (size_t i = 0; i < sizeof(positions) / sizeof(positions[0]); ++i) {
        vireo_page_token_t changed = token;
        changed.bytes[positions[i]] ^= 2;
        resign(key, &changed);
        rejected(key, &c.context, &changed, 1001, VIREO_RESULT_PROTOCOL);
    }
    for (size_t offset = 32; offset <= 56; offset += 8) {
        if (offset == 40) {
            continue;
        }
        vireo_page_token_t changed = token;
        put64(changed.bytes + offset, 0);
        resign(key, &changed);
        rejected(key, &c.context, &changed, 1001, VIREO_RESULT_PROTOCOL);
    }
    vireo_page_token_t overflow = token;
    put64(overflow.bytes + 48, UINT64_MAX);
    put64(overflow.bytes + 56, 599999 - 1);
    resign(key, &overflow);
    rejected(key, &c.context, &overflow, 1001, VIREO_RESULT_PROTOCOL);
    for (size_t i = 0; i < 4; ++i) {
        vireo_page_token_context_t ctx = c.context;
        if (i == 0) {
            ++ctx.user_id;
        } else if (i == 1) {
            ++ctx.session_id;
        } else if (i == 2) {
            ++ctx.directory_id;
        } else {
            ++ctx.page_size;
        }
        rejected(key, &ctx, &token, 1001, VIREO_RESULT_PROTOCOL);
    }
    rejected(key, &c.context, &token, 999, VIREO_RESULT_PROTOCOL);
    CHECK(vireo_page_token_verify(key, &c.context, &token, 1000, &out), VIREO_OK);
    CHECK(vireo_page_token_verify(key, &c.context, &token, 600999, &out), VIREO_OK);
    rejected(key, &c.context, &token, 601000, VIREO_RESULT_PROTOCOL);
    rejected(key, &c.context, &token, UINT64_MAX, VIREO_RESULT_PROTOCOL);
    for (size_t i = 0; i < 6; ++i) {
        vireo_page_token_claims_t invalid = c;
        if (i == 0) {
            invalid.context.user_id = 0;
        } else if (i == 1) {
            invalid.context.session_id = 0;
        } else if (i == 2) {
            invalid.context.directory_id = 0;
        } else if (i == 3) {
            invalid.context.page_size = 0;
        } else if (i == 4) {
            invalid.context.page_size = 65;
        } else {
            invalid.after_id = 0;
        }
        vireo_page_token_t out_token, before;
        memset(&out_token, 0xa5, sizeof(out_token));
        before = out_token;
        CHECK(vireo_page_token_sign(key, &invalid, 1001, &out_token),
              VIREO_RESULT_INVALID_ARGUMENT);
        assert(!memcmp(&before, &out_token, sizeof(before)));
        if (i < 5) {
            rejected(key, &invalid.context, &token, 1001, VIREO_RESULT_INVALID_ARGUMENT);
        }
    }
    for (size_t i = 0; i < 4; ++i) {
        vireo_page_token_claims_t invalid = c;
        vireo_result_t want = VIREO_RESULT_PROTOCOL;
        uint64_t now = 999;
        if (i == 1) {
            now = 601000;
        }
        if (i == 2) {
            ++invalid.expires_at_ms;
            want = VIREO_RESULT_INVALID_ARGUMENT;
        }
        if (i == 3) {
            invalid.issued_at_ms = UINT64_MAX;
            want = VIREO_RESULT_OVERFLOW;
        }
        vireo_page_token_t output, before;
        memset(&output, 0x5a, sizeof(output));
        before = output;
        CHECK(vireo_page_token_sign(key, &invalid, now, &output), want);
        assert(!memcmp(&output, &before, sizeof(output)));
    }
    CHECK(vireo_page_token_sign(NULL, &c, 1001, &independent), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_page_token_sign(key, NULL, 1001, &independent), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_page_token_sign(key, &c, 1001, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    rejected(NULL, &c.context, &token, 1001, VIREO_RESULT_INVALID_ARGUMENT);
    rejected(key, NULL, &token, 1001, VIREO_RESULT_INVALID_ARGUMENT);
    rejected(key, &c.context, NULL, 1001, VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_page_token_verify(key, &c.context, &token, 1001, NULL),
          VIREO_RESULT_INVALID_ARGUMENT);
    for (size_t i = 0; i < 8; ++i) {
        vireo_page_token_claims_t edge = {
            {UINT64_MAX, UINT64_MAX, UINT64_MAX, (uint16_t)((i & 1) ? 64 : 1)},
            (i & 2) ? UINT64_MAX : 1,
            (i & 4) ? UINT64_MAX - 600000 : 0,
            (i & 4) ? UINT64_MAX : 600000};
        CHECK(vireo_page_token_sign(key, &edge, edge.issued_at_ms, &independent), VIREO_OK);
        CHECK(
            vireo_page_token_verify(key, &edge.context, &independent, edge.expires_at_ms - 1, &out),
            VIREO_OK);
        assert(out.after_id == edge.after_id && out.expires_at_ms == edge.expires_at_ms);
    }
    /* Fixed-size untrusted input sweep, bounded and deterministic under sanitizers. */
    uint32_t state = 0x3c6ef372;
    for (size_t i = 0; i < 32768; ++i) {
        for (size_t j = 0; j < 96; ++j) {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            independent.bytes[j] = (unsigned char)state;
        }
        rejected(key, &c.context, &independent, 1001, VIREO_RESULT_PROTOCOL);
    }
    vireo_page_token_key_t *other = NULL;
    CHECK(vireo_page_token_key_create(&other), VIREO_OK);
    rejected(other, &c.context, &token, 1001, VIREO_RESULT_PROTOCOL);
    CHECK(vireo_page_token_key_destroy(&other), VIREO_OK);
    CHECK(vireo_page_token_key_destroy(&key), VIREO_OK);
    assert(s.owners == 0 && s.contexts == 0 && s.algorithms == 0);
    printf(
        "PASS %zu token checks; independent golden/HMAC, semantic MACs, context/time boundaries "
        "and 32768 untrusted inputs\n",
        checks);
    return 0;
}
