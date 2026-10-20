/*
 * PROJECT : VIREO
 * FILE    : test_auth_login_verifier_failures.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-19
 * BRIEF   : 本组件own边界验证失败回滚、擦除、准确依赖路由和并发只读使用。
 */
#define _POSIX_C_SOURCE 200809L
#include "auth_login_verifier_internal.h"
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char const phc[] = "$argon2id$v=19$m=65536,t=3,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
static size_t observations;
typedef struct fixture {
    bool allocation_failure;
    bool match;
    unsigned int bad_output;
    vireo_result_t random_result;
    vireo_result_t create_result;
    vireo_result_t verify_result;
    unsigned int allocations;
    unsigned int releases;
    unsigned int randoms;
    unsigned int creates;
    atomic_uint verifies;
    vireo_auth_password_gate_t *gate;
    char const *expected_record;
    size_t expected_length;
    pthread_barrier_t *entered;
    pthread_barrier_t *leave;
} fixture_t;

static void wait_barrier(pthread_barrier_t *barrier)
{
    int const result = pthread_barrier_wait(barrier);
    assert(result == 0 || result == PTHREAD_BARRIER_SERIAL_THREAD);
}

static void *allocate(void *context, size_t bytes)
{
    fixture_t *f = context; ++f->allocations; errno = EIO;
    assert(bytes == sizeof(vireo_auth_login_verifier_t));
    return f->allocation_failure ? NULL : malloc(bytes);
}

/* 释放前逐字节验证整个对象（包括padding与runtime）已清零；不读取其他组件私有布局。 */
static void deallocate(void *context, void *memory)
{
    fixture_t *f = context; ++f->releases; errno = EIO;
    unsigned char const *bytes = memory;
    for (size_t i = 0; i < sizeof(vireo_auth_login_verifier_t); ++i) { assert(bytes[i] == 0); }
    free(memory);
}

static vireo_result_t random_bytes(void *context, unsigned char out[32])
{
    fixture_t *f = context; ++f->randoms; errno = EIO;
    for (size_t i = 0; i < 32; ++i) { out[i] = (unsigned char)(i + 224); }
    return f->random_result;
}

static vireo_result_t create(void *context, vireo_auth_password_gate_t *gate,
    void const *password, size_t length, char *encoded, size_t capacity, size_t *written)
{
    fixture_t *f = context; ++f->creates; errno = EIO;
    assert(gate == f->gate && length == 64 && capacity == 128);
    assert(vireo_auth_password_validate(password, length) == VIREO_OK);
    char const expected[] = "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
    assert(!memcmp(password, expected, length));
    memcpy(encoded, phc, sizeof(phc)); *written = sizeof(phc) - 1;
    if (f->bad_output == 1) { *written = SIZE_MAX; }
    if (f->bad_output == 2) { *written = 0; }
    if (f->bad_output == 3) { encoded[*written] = 'x'; }
    if (f->bad_output == 4) { encoded[0] = '!'; }
    if (f->bad_output == 5) { strstr(encoded, ",t=3,")[3] = '4'; } /* 合法PHC，但生成成本不同。 */
    return f->create_result;
}

static vireo_result_t verify(void *context, vireo_auth_password_gate_t *gate,
    void const *password, size_t length, char const *encoded, size_t encoded_length, bool *matches)
{
    fixture_t *f = context;
    (void)atomic_fetch_add(&f->verifies, 1);
    assert(gate == f->gate && length == 8 && !memcmp(password, "password", 8));
    assert(encoded_length == f->expected_length && !memcmp(encoded, f->expected_record, encoded_length));
    if (f->entered != NULL) { wait_barrier(f->entered); wait_barrier(f->leave); }
    *matches = f->match; errno = EIO;
    return f->verify_result;
}

static vireo_auth_login_verifier_runtime_t runtime(fixture_t *f)
{
    return (vireo_auth_login_verifier_runtime_t){f, allocate, deallocate, random_bytes, create, verify};
}

static void created(fixture_t *f, vireo_auth_login_verifier_t **value, vireo_result_t expected)
{
    vireo_auth_login_verifier_runtime_t ops = runtime(f);
    errno = EDOM;
    assert(vireo_auth_login_verifier_create_with_runtime(f->gate, value, &ops) == expected);
    assert(errno == EDOM);
    memset(&ops, 0, sizeof(ops)); /* 对象不能借用栈上依赖表。 */
    assert((*value != NULL) == (expected == VIREO_OK));
    ++observations;
}

typedef struct concurrent_call {
    vireo_auth_login_verifier_t *value;
    fixture_t *fixture;
    bool result;
} concurrent_call_t;

static void *operate(void *context)
{
    concurrent_call_t *call = context;
    errno = EDOM;
    assert(vireo_auth_login_verifier_verify(call->value, call->fixture->gate, NULL,
        "password", 8, &call->result) == VIREO_OK);
    assert(!call->result && errno == EDOM);
    return NULL;
}

int main(void)
{
    vireo_auth_password_gate_options_t const options = VIREO_AUTH_PASSWORD_GATE_OPTIONS_DEFAULT;
    vireo_auth_password_gate_t *gate = NULL;
    assert(vireo_auth_password_gate_create(&options, &gate) == VIREO_OK);
    vireo_auth_login_verifier_t *value = NULL;
    fixture_t f = {.gate = gate, .match = true};
    atomic_init(&f.verifies, 0);
    vireo_auth_login_verifier_runtime_t ops = runtime(&f);
    errno = EDOM;
    assert(vireo_auth_login_verifier_create_with_runtime(gate, &value, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    assert(!value && errno == EDOM); ++observations;
    for (unsigned int missing = 0; missing < 5; ++missing) {
        ops = runtime(&f);
        if (missing == 0) { ops.allocate = NULL; }
        if (missing == 1) { ops.deallocate = NULL; }
        if (missing == 2) { ops.random = NULL; }
        if (missing == 3) { ops.create = NULL; }
        if (missing == 4) { ops.verify = NULL; }
        assert(vireo_auth_login_verifier_create_with_runtime(gate, &value, &ops) == VIREO_RESULT_INVALID_ARGUMENT);
        assert(!value && errno == EDOM); ++observations;
    }
    assert(f.allocations == 0 && f.randoms == 0 && f.creates == 0);
    f.allocation_failure = true; created(&f, &value, VIREO_RESULT_NO_MEMORY);
    assert(f.randoms == 0 && f.creates == 0 && f.releases == 0);
    f.allocation_failure = false; f.random_result = VIREO_RESULT_IO;
    created(&f, &value, VIREO_RESULT_IO); assert(f.creates == 0 && f.releases == 1);
    f.random_result = VIREO_OK;
    vireo_result_t const errors[] = {VIREO_RESULT_NO_MEMORY, VIREO_RESULT_BUSY,
        VIREO_RESULT_CANCELLED, VIREO_RESULT_IO, VIREO_RESULT_INTERNAL};
    for (size_t i = 0; i < sizeof(errors) / sizeof(errors[0]); ++i) {
        f.create_result = errors[i]; created(&f, &value, errors[i]);
    }
    f.create_result = VIREO_OK;
    for (unsigned int bad = 1; bad <= 5; ++bad) {
        f.bad_output = bad; created(&f, &value, VIREO_RESULT_INTERNAL);
    }
    f.bad_output = 0; created(&f, &value, VIREO_OK);
    assert(value->runtime.context == &f && value->runtime.verify == verify);
    f.expected_record = phc; f.expected_length = sizeof(phc) - 1;
    vireo_mysql_user_credentials_t credentials = {
        .user_id = 7, .status = VIREO_MYSQL_USER_STATUS_ACTIVE, .password_hash_length = sizeof(phc) - 1
    };
    memcpy(credentials.password_hash, phc, sizeof(phc));
    /* 用不同合法PHC字节区分真实/替代路由；不宣称模型tag与密码对应。 */
    credentials.password_hash[sizeof(phc) - 3] = 'B';
    for (unsigned int state = 0; state < 3; ++state) {
        vireo_mysql_user_credentials_t const *input = state == 0 ? NULL : &credentials;
        credentials.status = state == 2 ? VIREO_MYSQL_USER_STATUS_DISABLED : VIREO_MYSQL_USER_STATUS_ACTIVE;
        f.expected_record = input != NULL ? credentials.password_hash : phc;
        for (unsigned int match = 0; match < 2; ++match) {
            bool result = true; f.match = match != 0;
            unsigned int const calls = atomic_load(&f.verifies);
            errno = EDOM;
            assert(vireo_auth_login_verifier_verify(value, gate, input, "password", 8, &result) == VIREO_OK);
            assert(result == (state == 1 && match != 0) && errno == EDOM);
            assert(atomic_load(&f.verifies) == calls + 1); ++observations;
        }
        for (size_t i = 0; i < sizeof(errors) / sizeof(errors[0]); ++i) {
            f.verify_result = errors[i]; f.match = true;
            for (unsigned int initial = 0; initial < 2; ++initial) {
                bool result = initial != 0;
                errno = EDOM;
                assert(vireo_auth_login_verifier_verify(value, gate, input, "password", 8, &result) == errors[i]);
                assert(result == (initial != 0) && errno == EDOM); ++observations;
            }
        }
        f.verify_result = VIREO_OK;
    }
    unsigned int const calls = atomic_load(&f.verifies);
    bool result = true;
    assert(vireo_auth_login_verifier_verify(value, gate, NULL, "bad pass", 8, &result) == VIREO_RESULT_PROTOCOL);
    assert(result && atomic_load(&f.verifies) == calls); ++observations;

    /* 两OS线程同时借用同一个只读对象；用屏障确定在途，不依赖sleep或执行先后。 */
    pthread_barrier_t entered, leave;
    assert(pthread_barrier_init(&entered, NULL, 3) == 0 && pthread_barrier_init(&leave, NULL, 3) == 0);
    f.entered = &entered; f.leave = &leave; f.expected_record = phc;
    concurrent_call_t concurrent[2] = {{value, &f, true}, {value, &f, true}};
    pthread_t threads[2];
    for (size_t i = 0; i < 2; ++i) { assert(pthread_create(&threads[i], NULL, operate, &concurrent[i]) == 0); }
    wait_barrier(&entered);
    assert(atomic_load(&f.verifies) == calls + 2);
    wait_barrier(&leave);
    for (size_t i = 0; i < 2; ++i) { assert(pthread_join(threads[i], NULL) == 0); }
    assert(pthread_barrier_destroy(&entered) == 0 && pthread_barrier_destroy(&leave) == 0); ++observations;
    unsigned int const creates_before = f.creates, randoms_before = f.randoms;
    errno = EDOM;
    assert(vireo_auth_login_verifier_destroy(&value) == VIREO_OK && !value && errno == EDOM);
    assert(f.creates == creates_before && f.randoms == randoms_before && f.allocations == f.releases + 1);
    assert(vireo_auth_password_gate_close(gate) == VIREO_OK);
    assert(vireo_auth_password_gate_destroy(&gate) == VIREO_OK);
    printf("PASS %zu own login verification observations; rollback/wipe/routing/error preservation/read-only OS workers\n", observations);
    return 0;
}
