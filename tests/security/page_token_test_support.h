/* Public synthetic test material only; never print keys or token bytes. */
#ifndef PAGE_TOKEN_TEST_SUPPORT_H
#define PAGE_TOKEN_TEST_SUPPORT_H
#include <assert.h>
#include <errno.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/hmac.h>
#include <openssl/params.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "page_token_internal.h"

static size_t checks;
#define CHECK(call, want)                                                                  \
    do {                                                                                   \
        errno = EDOM;                                                                      \
        vireo_result_t got_ = (call);                                                      \
        if (got_ != (want)) {                                                              \
            fprintf(stderr, "line %d got %d want %d\n", __LINE__, (int)got_, (int)(want)); \
            abort();                                                                       \
        }                                                                                  \
        assert(errno == EDOM);                                                             \
        ++checks;                                                                          \
    } while (0)
static inline void zeroed(const void *p, size_t n) {
    const unsigned char *v = p;
    for (size_t i = 0; i < n; ++i) {
        assert(v[i] == 0);
    }
}

enum failure {
    NONE,
    ALLOCATE,
    FETCH,
    SECRET_RNG,
    ID_RNG,
    ID_ZERO,
    CONTEXT,
    INIT,
    DOMAIN_UPDATE,
    PAYLOAD_UPDATE,
    FINAL,
    FINAL_LENGTH
};
typedef struct scenario {
    enum failure fail;
    size_t owners, algorithms, contexts, allocations, frees, rng, updates, context_frees;
} scenario_t;
static inline void *test_allocate(void *c, size_t n) {
    scenario_t *s = c;
    errno = EIO;
    if (s->fail == ALLOCATE) {
        return NULL;
    }
    void *p = malloc(n);
    assert(p != NULL);
    ++s->owners;
    ++s->allocations;
    return p;
}
static inline void test_free(void *c, void *p) {
    scenario_t *s = c;
    zeroed(p, sizeof(vireo_page_token_key_t));
    assert(s->owners == 1 && s->algorithms == 0 && s->contexts == 0);
    --s->owners;
    ++s->frees;
    free(p);
    errno = EIO;
}
static inline EVP_MAC *test_fetch(void *c) {
    scenario_t *s = c;
    errno = EIO;
    if (s->fail == FETCH) {
        return NULL;
    }
    EVP_MAC *m = EVP_MAC_fetch(NULL, "HMAC", NULL);
    assert(m != NULL);
    ++s->algorithms;
    return m;
}
static inline void test_free_mac(void *c, EVP_MAC *m) {
    scenario_t *s = c;
    assert(s->algorithms == 1);
    --s->algorithms;
    EVP_MAC_free(m);
    errno = EIO;
}
static inline int test_random(void *c, unsigned char *p, int n) {
    scenario_t *s = c;
    ++s->rng;
    errno = EIO;
    assert(n == 32 || n == 4);
    /* Including partial output on RNG failure exercises the cleansing path. */
    memset(p, 0x69, (size_t)n);
    if ((n == 32 && s->fail == SECRET_RNG) || (n == 4 && s->fail == ID_RNG)) {
        return 0;
    }
    if (n == 32) {
        for (size_t i = 0; i < 32; ++i) {
            p[i] = (unsigned char)i;
        }
    } else {
        memset(p, 0, 4);
        if (s->fail != ID_ZERO) {
            p[3] = 3;
        }
    }
    return 1;
}
static inline EVP_MAC_CTX *test_context(void *c, EVP_MAC *m) {
    scenario_t *s = c;
    errno = EIO;
    s->updates = 0;
    if (s->fail == CONTEXT) {
        return NULL;
    }
    EVP_MAC_CTX *v = EVP_MAC_CTX_new(m);
    assert(v != NULL);
    ++s->contexts;
    return v;
}
static inline void test_context_free(void *c, EVP_MAC_CTX *m) {
    scenario_t *s = c;
    assert(s->contexts == 1);
    --s->contexts;
    ++s->context_frees;
    EVP_MAC_CTX_free(m);
    errno = EIO;
}
static inline int test_init(void *c, EVP_MAC_CTX *m, const unsigned char *key, size_t n) {
    scenario_t *s = c;
    errno = EIO;
    if (s->fail == INIT) {
        return 0;
    }
    char digest[] = "SHA256";
    OSSL_PARAM p[] = {OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest, 0),
                      OSSL_PARAM_construct_end()};
    return EVP_MAC_init(m, key, n, p);
}
static inline int test_update(void *c, EVP_MAC_CTX *m, const unsigned char *p, size_t n) {
    scenario_t *s = c;
    ++s->updates;
    errno = EIO;
    assert(n == (s->updates == 1 ? 24 : 64));
    if ((s->updates == 1 && s->fail == DOMAIN_UPDATE) ||
        (s->updates == 2 && s->fail == PAYLOAD_UPDATE)) {
        return 0;
    }
    return EVP_MAC_update(m, p, n);
}
static inline int test_final(void *c, EVP_MAC_CTX *m, unsigned char *p, size_t *n, size_t cap) {
    scenario_t *s = c;
    errno = EIO;
    assert(cap == 32);
    if (s->fail == FINAL) {
        memset(p, 0x77, cap);
        *n = cap;
        return 0;
    }
    int rc = EVP_MAC_final(m, p, n, cap);
    if (s->fail == FINAL_LENGTH) {
        *n = 31;
    }
    return rc;
}
static inline vireo_page_token_runtime_t runtime(scenario_t *s) {
    return (vireo_page_token_runtime_t){
        s,           test_allocate, test_free,         test_fetch, test_free_mac,
        test_random, test_context,  test_context_free, test_init,  test_update,
        test_final};
}
static inline vireo_page_token_claims_t claims(void) {
    return (vireo_page_token_claims_t){{7, 8, 42, 2}, 120, 1000, 601000};
}
/* One-shot independent HMAC API, not the production EVP_MAC path. */
static inline void resign(const vireo_page_token_key_t *key, vireo_page_token_t *token) {
    static const unsigned char domain[] = "vireo/node-list-page/v1";
    unsigned char input[24 + 64];
    unsigned int n = 0;
    memcpy(input, domain, 24);
    memcpy(input + 24, token->bytes, 64);
    assert(HMAC(EVP_sha256(), key->secret, 32, input, sizeof(input), token->bytes + 64, &n) !=
               NULL &&
           n == 32);
    OPENSSL_cleanse(input, sizeof(input));
}
#endif
