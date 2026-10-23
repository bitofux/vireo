/* PROJECT : VIREO; AUTHOR : bitofux; DATE : 2026-10-22;
 * BRIEF : 独立进程键、固定域HMAC-SHA256与受检整链时间。 */
#include <errno.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>
#include "page_token_internal.h"

static const unsigned char domain[] = "vireo/node-list-page/v1";
_Static_assert(sizeof(domain) == 24, "page token domain includes one NUL");
_Static_assert(VIREO_PAGE_TOKEN_BYTES == 96, "page token v1 bytes");

static void *native_allocate(void *c, size_t n) {
    (void)c;
    return malloc(n);
}
static void native_free(void *c, void *p) {
    (void)c;
    free(p);
}
static EVP_MAC *native_fetch(void *c) {
    (void)c;
    return EVP_MAC_fetch(NULL, "HMAC", NULL);
}
static void native_free_mac(void *c, EVP_MAC *m) {
    (void)c;
    EVP_MAC_free(m);
}
static int native_random(void *c, unsigned char *p, int n) {
    (void)c;
    return RAND_priv_bytes(p, n);
}
static EVP_MAC_CTX *native_new(void *c, EVP_MAC *m) {
    (void)c;
    return EVP_MAC_CTX_new(m);
}
static void native_free_context(void *c, EVP_MAC_CTX *m) {
    (void)c;
    EVP_MAC_CTX_free(m);
}
static int native_init(void *c, EVP_MAC_CTX *m, const unsigned char *p, size_t n) {
    (void)c;
    char digest[] = "SHA256";
    OSSL_PARAM params[] = {OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest, 0),
                           OSSL_PARAM_construct_end()};
    return EVP_MAC_init(m, p, n, params);
}
static int native_update(void *c, EVP_MAC_CTX *m, const unsigned char *p, size_t n) {
    (void)c;
    return EVP_MAC_update(m, p, n);
}
static int native_final(void *c, EVP_MAC_CTX *m, unsigned char *p, size_t *n, size_t cap) {
    (void)c;
    return EVP_MAC_final(m, p, n, cap);
}
static const vireo_page_token_runtime_t native_runtime = {
    NULL,       native_allocate,     native_free, native_fetch,  native_free_mac, native_random,
    native_new, native_free_context, native_init, native_update, native_final};

static void put(unsigned char *p, uint64_t value, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        p[n - 1 - i] = (unsigned char)(value >> (i * 8));
    }
}
static uint64_t get(const unsigned char *p, size_t n) {
    uint64_t value = 0;
    for (size_t i = 0; i < n; ++i) {
        value = (value << 8) | p[i];
    }
    return value;
}
static bool runtime_valid(const vireo_page_token_runtime_t *r) {
    return r != NULL && r->allocate != NULL && r->free_memory != NULL && r->fetch != NULL &&
           r->free_mac != NULL && r->random_bytes != NULL && r->new_context != NULL &&
           r->free_context != NULL && r->init != NULL && r->update != NULL && r->final != NULL;
}
static bool context_valid(const vireo_page_token_context_t *c) {
    return c != NULL && c->user_id != 0 && c->session_id != 0 && c->directory_id != 0 &&
           c->page_size >= 1 && c->page_size <= 64;
}

vireo_result_t vireo_page_token_key_create_with_runtime(vireo_page_token_key_t **out,
                                                        const vireo_page_token_runtime_t *r) {
    const int saved = errno;
    vireo_result_t rc = VIREO_RESULT_INVALID_ARGUMENT;
    vireo_page_token_key_t *key = NULL;
    unsigned char id[4] = {0};
    if (out == NULL || *out != NULL || !runtime_valid(r)) {
        goto done;
    }
    key = r->allocate(r->context, sizeof(*key));
    if (key == NULL) {
        rc = VIREO_RESULT_NO_MEMORY;
        goto done;
    }
    memset(key, 0, sizeof(*key));
    key->runtime = *r;
    key->algorithm = r->fetch(r->context);
    if (key->algorithm == NULL) {
        rc = VIREO_RESULT_INTERNAL;
        goto done;
    }
    rc = VIREO_RESULT_IO;
    if (r->random_bytes(r->context, key->secret, 32) != 1 ||
        r->random_bytes(r->context, id, 4) != 1) {
        goto done;
    }
    key->id = (uint32_t)get(id, sizeof(id));
    if (key->id == 0) {
        goto done;
    }
    *out = key;
    key = NULL;
    rc = VIREO_OK;
done:
    if (key != NULL) {
        OPENSSL_cleanse(key->secret, sizeof(key->secret));
        if (key->algorithm != NULL) {
            r->free_mac(r->context, key->algorithm);
        }
        OPENSSL_cleanse(key, sizeof(*key));
        r->free_memory(r->context, key);
    }
    OPENSSL_cleanse(id, sizeof(id));
    errno = saved;
    return rc;
}

vireo_result_t vireo_page_token_key_create(vireo_page_token_key_t **out) {
    return vireo_page_token_key_create_with_runtime(out, &native_runtime);
}

vireo_result_t vireo_page_token_key_destroy(vireo_page_token_key_t **key) {
    const int saved = errno;
    vireo_result_t rc = VIREO_RESULT_INVALID_ARGUMENT;
    if (key != NULL) {
        if (*key != NULL) {
            const vireo_page_token_runtime_t r = (*key)->runtime;
            OPENSSL_cleanse((*key)->secret, sizeof((*key)->secret));
            r.free_mac(r.context, (*key)->algorithm);
            OPENSSL_cleanse(*key, sizeof(**key));
            r.free_memory(r.context, *key);
            *key = NULL;
        }
        rc = VIREO_OK;
    }
    errno = saved;
    return rc;
}

/* MAC输出仅写本层暂存；ctx在全部成功/失败路径销毁。 */
static vireo_result_t calculate(const vireo_page_token_key_t *key, const unsigned char payload[64],
                                unsigned char out[32]) {
    const vireo_page_token_runtime_t *r = &key->runtime;
    EVP_MAC_CTX *ctx = r->new_context(r->context, key->algorithm);
    if (ctx == NULL) {
        return VIREO_RESULT_NO_MEMORY;
    }
    size_t size = 0;
    vireo_result_t rc = VIREO_RESULT_INTERNAL;
    if (r->init(r->context, ctx, key->secret, sizeof(key->secret)) == 1 &&
        r->update(r->context, ctx, domain, sizeof(domain)) == 1 &&
        r->update(r->context, ctx, payload, 64) == 1 &&
        r->final(r->context, ctx, out, &size, 32) == 1 && size == 32) {
        rc = VIREO_OK;
    }
    r->free_context(r->context, ctx);
    return rc;
}

vireo_result_t vireo_page_token_sign(const vireo_page_token_key_t *key,
                                     const vireo_page_token_claims_t *claims, uint64_t now,
                                     vireo_page_token_t *out) {
    const int saved = errno;
    vireo_result_t rc = VIREO_RESULT_INVALID_ARGUMENT;
    vireo_page_token_t candidate = {{0}};
    if (key == NULL || claims == NULL || out == NULL || !context_valid(&claims->context) ||
        claims->after_id == 0) {
        goto done;
    }
    if (claims->issued_at_ms > UINT64_MAX - VIREO_PAGE_TOKEN_TTL_MS) {
        rc = VIREO_RESULT_OVERFLOW;
        goto done;
    }
    if (claims->expires_at_ms != claims->issued_at_ms + VIREO_PAGE_TOKEN_TTL_MS) {
        goto done;
    }
    if (now < claims->issued_at_ms || now >= claims->expires_at_ms) {
        rc = VIREO_RESULT_PROTOCOL;
        goto done;
    }
    unsigned char *p = candidate.bytes;
    p[0] = 1;
    put(p + 4, key->id, 4);
    put(p + 8, claims->context.user_id, 8);
    put(p + 16, claims->context.session_id, 8);
    put(p + 24, claims->context.directory_id, 8);
    put(p + 32, claims->after_id, 8);
    put(p + 40, claims->context.page_size, 2);
    put(p + 48, claims->issued_at_ms, 8);
    put(p + 56, claims->expires_at_ms, 8);
    rc = calculate(key, p, p + 64);
    if (rc == VIREO_OK) {
        memcpy(out, &candidate, sizeof(candidate));
    }
done:
    OPENSSL_cleanse(&candidate, sizeof(candidate));
    errno = saved;
    return rc;
}

vireo_result_t vireo_page_token_verify(const vireo_page_token_key_t *key,
                                       const vireo_page_token_context_t *context,
                                       const vireo_page_token_t *token, uint64_t now,
                                       vireo_page_token_claims_t *out) {
    const int saved = errno;
    vireo_result_t rc = VIREO_RESULT_INVALID_ARGUMENT;
    unsigned char mac[32] = {0};
    vireo_page_token_claims_t c = {0};
    if (key == NULL || !context_valid(context) || token == NULL || out == NULL) {
        goto done;
    }
    const unsigned char *p = token->bytes;
    rc = calculate(key, p, mac);
    if (rc != VIREO_OK) {
        goto done;
    }
    rc = VIREO_RESULT_PROTOCOL;
    if (CRYPTO_memcmp(mac, p + 64, sizeof(mac)) != 0) {
        goto done;
    }
    if (p[0] != 1 || p[1] != 0 || get(p + 2, 2) != 0 || get(p + 4, 4) != key->id ||
        get(p + 42, 6) != 0 || get(p + 8, 8) != context->user_id ||
        get(p + 16, 8) != context->session_id || get(p + 24, 8) != context->directory_id ||
        get(p + 40, 2) != context->page_size) {
        goto done;
    }
    c.context = *context;
    c.after_id = get(p + 32, 8);
    c.issued_at_ms = get(p + 48, 8);
    c.expires_at_ms = get(p + 56, 8);
    if (c.after_id == 0 || c.issued_at_ms > UINT64_MAX - VIREO_PAGE_TOKEN_TTL_MS ||
        c.expires_at_ms != c.issued_at_ms + VIREO_PAGE_TOKEN_TTL_MS || now < c.issued_at_ms ||
        now >= c.expires_at_ms) {
        goto done;
    }
    memcpy(out, &c, sizeof(c));
    rc = VIREO_OK;
done:
    OPENSSL_cleanse(mac, sizeof(mac));
    OPENSSL_cleanse(&c, sizeof(c));
    errno = saved;
    return rc;
}
