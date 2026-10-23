#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <vireo/security/page_token.h>

typedef struct worker {
    const vireo_page_token_key_t *key;
    uint64_t id;
    size_t calls;
} worker_t;
static void *run(void *context) {
    worker_t *w = context;
    for (uint64_t i = 1; i <= 1000; ++i) {
        vireo_page_token_claims_t c = {{w->id, 8, 42, 64}, i, 1000, 601000}, out;
        vireo_page_token_t token;
        errno = EDOM;
        assert(vireo_page_token_sign(w->key, &c, 1001, &token) == VIREO_OK && errno == EDOM);
        assert(vireo_page_token_verify(w->key, &c.context, &token, 1001, &out) == VIREO_OK &&
               errno == EDOM);
        assert(out.context.user_id == w->id && out.after_id == i && out.expires_at_ms == 601000);
        ++c.context.session_id;
        assert(vireo_page_token_verify(w->key, &c.context, &token, 1001, &out) ==
                   VIREO_RESULT_PROTOCOL &&
               errno == EDOM);
        w->calls += 3;
    }
    return NULL;
}
int main(void) {
    vireo_page_token_key_t *key = NULL;
    errno = EDOM;
    assert(vireo_page_token_key_create(&key) == VIREO_OK && key != NULL && errno == EDOM);
    pthread_t threads[4];
    worker_t workers[4];
    for (size_t i = 0; i < 4; ++i) {
        workers[i] = (worker_t){key, i + 1, 0};
        assert(pthread_create(&threads[i], NULL, run, &workers[i]) == 0);
    }
    size_t calls = 0;
    for (size_t i = 0; i < 4; ++i) {
        assert(pthread_join(threads[i], NULL) == 0);
        calls += workers[i].calls;
    }
    assert(vireo_page_token_key_destroy(&key) == VIREO_OK && key == NULL && errno == EDOM);
    printf(
        "PASS %zu concurrent token calls; four OS workers, shared immutable key, independent EVP "
        "contexts, joined before destroy\n",
        calls);
    return 0;
}
