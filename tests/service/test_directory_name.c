/* PROJECT : VIREO; FILE : test_directory_name.c; AUTHOR : bitofux;
 * DATE : 2026-10-24; BRIEF : 独立字节样例、边界、owner故障及并发。 */
#include "directory_name_internal.h"
#include "directory_name_test_vectors.h"
#include <utf8proc.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static vireo_result_t expected_rc(vireo_directory_name_issue_t issue)
{
    return issue == VIREO_DIRECTORY_NAME_ISSUE_NONE ? VIREO_OK :
        issue == VIREO_DIRECTORY_NAME_ISSUE_LENGTH ? VIREO_RESULT_RANGE : VIREO_RESULT_PROTOCOL;
}
static void vectors(void)
{
    for (size_t i = 0; i < sizeof(name_vectors)/sizeof(name_vectors[0]); ++i) {
        const struct name_vector *v = &name_vectors[i];
        unsigned char original[256]; assert(v->length <= sizeof(original));
        memcpy(original, v->bytes, v->length);
        vireo_directory_name_issue_t issue = VIREO_DIRECTORY_NAME_ISSUE_LENGTH;
        errno = EDOM;
        vireo_result_t rc = vireo_directory_name_validate(v->bytes, v->length, &issue);
        if (rc != expected_rc(v->issue) || issue != v->issue) {
            fprintf(stderr, "%s: rc=%d issue=%d\n", v->label, (int)rc, (int)issue); abort();
        }
        assert(errno == EDOM && memcmp(original, v->bytes, v->length) == 0);
    }
}
struct fault { vireo_result_t rc; unsigned int mode, calls, released; };
static vireo_result_t normalize(void *ctx, const unsigned char *name, size_t n,
    unsigned char **owner, size_t *length)
{
    struct fault *f = ctx; ++f->calls; errno = ERANGE;
    if (f->rc != VIREO_OK) { return f->rc; }
    if (f->mode == 1) { return VIREO_OK; } /* 模拟依赖矛盾成功。 */
    *owner = malloc(n); assert(*owner != NULL); memcpy(*owner, name, n);
    *length = f->mode == 2 ? SIZE_MAX : n;
    if (f->mode == 3) { (*owner)[0] ^= 1; }
    return VIREO_OK;
}
static void release_owner(void *ctx, unsigned char *owner)
{
    struct fault *f = ctx; ++f->released; free(owner); errno = EIO;
}
static void faults(void)
{
    const vireo_result_t failures[] = {VIREO_RESULT_NO_MEMORY, VIREO_RESULT_OVERFLOW,
        VIREO_RESULT_INTERNAL, VIREO_RESULT_PROTOCOL, VIREO_RESULT_NOT_FOUND};
    for (size_t i = 0; i < sizeof(failures)/sizeof(failures[0]); ++i) {
        struct fault f = {.rc = failures[i]};
        vireo_directory_name_runtime_t rt = {&f, normalize, release_owner};
        vireo_directory_name_issue_t issue; errno = EDOM;
        vireo_result_t rc = vireo_directory_name_validate_with_runtime((const unsigned char *)"abc", 3, &issue, &rt);
        assert(rc == (i < 2 ? failures[i] : VIREO_RESULT_INTERNAL));
        assert(issue == VIREO_DIRECTORY_NAME_ISSUE_NONE && f.calls == 1 && f.released == 0 && errno == EDOM);
    }
    for (unsigned int mode = 0; mode <= 3; ++mode) {
        struct fault f = {.rc = VIREO_OK, .mode = mode};
        vireo_directory_name_runtime_t rt = {&f, normalize, release_owner};
        vireo_directory_name_issue_t issue; errno = EDOM;
        vireo_result_t rc = vireo_directory_name_validate_with_runtime((const unsigned char *)"abc", 3, &issue, &rt);
        assert(rc == (mode == 0 ? VIREO_OK : mode == 1 ? VIREO_RESULT_INTERNAL : VIREO_RESULT_PROTOCOL));
        assert(f.calls == 1 && f.released == (mode == 1 ? 0U : 1U) && errno == EDOM);
        assert(issue == (mode >= 2 ? VIREO_DIRECTORY_NAME_ISSUE_NOT_NFC : VIREO_DIRECTORY_NAME_ISSUE_NONE));
    }
    struct fault f = {0}; vireo_directory_name_runtime_t rt = {&f, normalize, release_owner};
    vireo_directory_name_issue_t issue = VIREO_DIRECTORY_NAME_ISSUE_UTF8;
    assert(vireo_directory_name_validate(NULL, 1, &issue) == VIREO_RESULT_INVALID_ARGUMENT);
    assert(issue == VIREO_DIRECTORY_NAME_ISSUE_UTF8);
    assert(vireo_directory_name_validate((const unsigned char *)"x", 1, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    assert(vireo_directory_name_validate_with_runtime((const unsigned char *)"x", 1, &issue, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    assert(issue == VIREO_DIRECTORY_NAME_ISSUE_UTF8);
    rt.release = NULL;
    assert(vireo_directory_name_validate_with_runtime((const unsigned char *)"x", 1, &issue, &rt) == VIREO_RESULT_INVALID_ARGUMENT);
    rt.release = release_owner;
    const size_t lengths[] = {0, 256, SIZE_MAX};
    for (size_t i = 0; i < 3; ++i) {
        assert(vireo_directory_name_validate_with_runtime((const unsigned char *)"x", lengths[i], &issue, &rt) == VIREO_RESULT_RANGE);
        assert(issue == VIREO_DIRECTORY_NAME_ISSUE_LENGTH && f.calls == 0);
    }
    const unsigned char *bad[] = {(const unsigned char *)".", (const unsigned char *)"\xff", (const unsigned char *)"/"};
    for (size_t i = 0; i < 3; ++i) {
        assert(vireo_directory_name_validate_with_runtime(bad[i], 1, &issue, &rt) == VIREO_RESULT_PROTOCOL);
        assert(f.calls == 0);
    }
}
static void *worker(void *ctx)
{
    (void)ctx;
    for (size_t i = 0; i < 50; ++i) { vectors(); }
    return NULL;
}
int main(void)
{
    assert(strcmp(utf8proc_version(), "2.9.0") == 0);
    assert(strcmp(utf8proc_unicode_version(), "15.1.0") == 0);
    vectors(); faults();
    /* 核实际库确有254->508扩张，validator不设255输出上限。 */
    unsigned char raw[254]; for (size_t i = 0; i < sizeof(raw); i += 2) { raw[i] = 0xcd; raw[i+1] = 0x84; }
    unsigned char *expanded = NULL;
    assert(utf8proc_map(raw, 254, &expanded, UTF8PROC_STABLE | UTF8PROC_COMPOSE) == 508);
    assert(expanded != NULL); free(expanded);
    pthread_t threads[4];
    for (size_t i = 0; i < 4; ++i) { assert(pthread_create(&threads[i], NULL, worker, NULL) == 0); }
    for (size_t i = 0; i < 4; ++i) { assert(pthread_join(threads[i], NULL) == 0); }
    printf("PASS 42 fixed vectors, ownership/fault/boundary/errno, 4 independent threads; utf8proc %s Unicode %s\n", utf8proc_version(), utf8proc_unicode_version());
    return 0;
}
