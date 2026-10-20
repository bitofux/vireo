/*
 * PROJECT : VIREO
 * FILE    : test_auth_password_failures.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-19
 * BRIEF   : 通过service自身依赖边界验证收费、失败输出和并发关闭。
 */
#define _POSIX_C_SOURCE 200809L
#include "auth_password_internal.h"
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char const ordinary[] = "abcdefgh";
static char const held[] = "Holding1";
static size_t observations;

typedef struct fixture {
    vireo_auth_password_gate_t *gate; /**< 借用当前被测owner；线程退出后才销毁。 */
    atomic_uint computations; /**< 多线程累加低层调用次数。 */
    atomic_uint inspections; /**< 公开inspect被调用次数，拒绝可观测。 */
    atomic_uint exchanges; /**< CAS调用次数，强制竞争耗尽的观测。 */
    bool no_memory; /**< 构造前设定，模拟对象分配失败。 */
    bool fail_cas; /**< 运算前设定，测试时保持不变，强制32次伪失败。 */
    bool match; /**< 假验密返回值，独立于返回错误。 */
    bool bad_output; /**< 模拟private依赖违反输出长度合同，包装不得越界发布。 */
    vireo_result_t result; /**< 低层返回码，所有路径都故意改errno/临时输出。 */
    unsigned int allocations; /**< manager-only分配次数。 */
    unsigned int frees; /**< manager-only释放次数。 */
    pthread_barrier_t entered; /**< held密码的计算已收费并进入低层。 */
    pthread_barrier_t leave; /**< manager检查期间冻结所有held运算。 */
} fixture_t;

typedef struct operation {
    fixture_t *fixture; /**< 同一长期借用测试上下文。 */
    uint32_t memory; /**< 0表示生成，否则验证该m记录。 */
    vireo_result_t result; /**< 所属线程写，join后manager读。 */
    bool matches; /**< 所属线程独占验密结果。 */
    char encoded[128]; /**< 所属线程独占PHC临时结果，不输出日志。 */
    size_t length; /**< 所属线程独占生成长度。 */
} operation_t;

/* 所有屏障同步都断言POSIX两种成功返回；无sleep猜测计算是否在途。 */
static void barrier(pthread_barrier_t *value)
{
    int const code = pthread_barrier_wait(value);
    assert(code == 0 || code == PTHREAD_BARRIER_SERIAL_THREAD);
}

/* 固定非秘密样例；只供格式/收费模型，不声称tag对应密码。 */
static size_t record(char out[128], uint32_t memory, uint32_t iterations)
{
    int const count = snprintf(out, 128, "$argon2id$v=19$m=%" PRIu32 ",t=%" PRIu32
        ",p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        memory, iterations);
    assert(count > 0 && count < 128);
    return (size_t)count;
}

static void *allocate(void *context, size_t size)
{
    fixture_t *f = context;
    ++f->allocations;
    errno = EIO;
    return f->no_memory ? NULL : malloc(size);
}

static void deallocate(void *context, void *memory)
{
    fixture_t *f = context;
    ++f->frees;
    errno = EIO;
    free(memory);
}

/* 每个低层调用先断言收费已完成；退出仍由包装层归还。 */
static void computing(fixture_t *f, void const *password, uint32_t memory)
{
    uint_least64_t const state = atomic_load(&f->gate->state);
    assert((state & 511) != 0 && ((state >> 9) & 2097151) >= memory);
    (void)atomic_fetch_add(&f->computations, 1);
    if (((char const *)password)[0] == 'H') {
        barrier(&f->entered);
        barrier(&f->leave);
    }
    errno = EIO;
}

static vireo_result_t create(void *context, vireo_password_policy_t const *p,
    void const *password, size_t length, char *out, size_t capacity, size_t *written)
{
    fixture_t *f = context;
    assert(p->create_memory_kib == 65536 && p->create_iterations == 3 && p->max_password_bytes == 64);
    assert(length == 8 && capacity == 128);
    computing(f, password, 65536);
    *written = record(out, 65536, 3);
    if (f->bad_output) { *written = SIZE_MAX; }
    return f->result;
}

static vireo_result_t inspect(void *context, vireo_password_policy_t const *p,
    char const *encoded, size_t length, vireo_password_info_t *info)
{
    fixture_t *f = context;
    (void)atomic_fetch_add(&f->inspections, 1);
    errno = EIO;
    return vireo_password_hash_inspect(p, encoded, length, info);
}

static vireo_result_t verify(void *context, vireo_password_policy_t const *p,
    void const *password, size_t length, char const *encoded, size_t encoded_length, bool *matches)
{
    fixture_t *f = context;
    assert(length == 8 && p->max_verify_memory_kib == 262144 && p->max_verify_iterations == 10);
    vireo_password_info_t info;
    assert(vireo_password_hash_inspect(p, encoded, encoded_length, &info) == VIREO_OK);
    computing(f, password, info.memory_kib);
    *matches = f->match;
    return f->result;
}

static bool exchange(void *context, atomic_uint_least64_t *state,
    uint_least64_t *expected, uint_least64_t desired)
{
    fixture_t *f = context;
    (void)atomic_fetch_add(&f->exchanges, 1);
    errno = EIO;
    if (f->fail_cas) { *expected = atomic_load(state); return false; }
    return atomic_compare_exchange_strong(state, expected, desired);
}

static vireo_auth_password_runtime_t runtime(fixture_t *f)
{
    return (vireo_auth_password_runtime_t){f, allocate, deallocate, create, inspect, verify, exchange};
}

static void opened(fixture_t *f)
{
    vireo_auth_password_gate_options_t options = VIREO_AUTH_PASSWORD_GATE_OPTIONS_DEFAULT;
    vireo_auth_password_runtime_t const ops = runtime(f);
    errno = EDOM;
    assert(vireo_auth_password_gate_create_with_runtime(&options, &f->gate, &ops) == VIREO_OK);
    assert(errno == EDOM);
    /* 构造复制配置及表，不能保存这两个栈对象的地址。 */
    options.max_parallel = 1;
    assert(f->gate->max_parallel == 2);
    ++observations;
}

static void finished(fixture_t *f)
{
    errno = EDOM;
    assert(vireo_auth_password_gate_close(f->gate) == VIREO_OK);
    assert(vireo_auth_password_gate_close(f->gate) == VIREO_OK);
    assert(vireo_auth_password_gate_destroy(&f->gate) == VIREO_OK && f->gate == NULL);
    assert(vireo_auth_password_gate_destroy(&f->gate) == VIREO_OK && errno == EDOM);
    assert(f->allocations == f->frees);
    ++observations;
}

/* create失败必须保留整个大缓冲区及长度，不能泄漏低层写入的临时值。 */
static void create_result(fixture_t *f, vireo_result_t expected)
{
    char out[160], before[160];
    size_t length = 777;
    memset(out, 0xa5, sizeof(out));
    memcpy(before, out, sizeof(out));
    errno = EDOM;
    assert(vireo_auth_password_hash_create(f->gate, ordinary, 8, out, sizeof(out), &length) == expected);
    assert(errno == EDOM);
    if (expected == VIREO_OK) {
        assert(length < 128 && out[length] == 0);
        assert(!memcmp(out + length + 1, before + length + 1, sizeof(out) - length - 1));
    } else {
        assert(length == 777 && !memcmp(out, before, sizeof(out)));
    }
    ++observations;
}

static void verify_result(fixture_t *f, uint32_t memory, uint32_t iterations, vireo_result_t expected)
{
    char phc[128];
    size_t const length = record(phc, memory, iterations);
    bool matches = !f->match;
    errno = EDOM;
    assert(vireo_auth_password_hash_verify(f->gate, ordinary, 8, phc, length, &matches) == expected);
    assert(errno == EDOM && matches == (expected == VIREO_OK ? f->match : !f->match));
    ++observations;
}

static void *operate(void *context)
{
    operation_t *op = context;
    errno = EDOM;
    if (op->memory == 0) {
        op->result = vireo_auth_password_hash_create(op->fixture->gate, held, 8,
            op->encoded, sizeof(op->encoded), &op->length);
    } else {
        char phc[128];
        size_t const length = record(phc, op->memory, 3);
        op->result = vireo_auth_password_hash_verify(op->fixture->gate, held, 8,
            phc, length, &op->matches);
    }
    assert(errno == EDOM);
    return NULL;
}

static void concurrent(uint32_t first, bool two, bool close_inflight)
{
    fixture_t f = {.result = VIREO_OK, .match = true};
    opened(&f);
    unsigned int const participants = two ? 3 : 2;
    assert(pthread_barrier_init(&f.entered, NULL, participants) == 0);
    assert(pthread_barrier_init(&f.leave, NULL, participants) == 0);
    operation_t ops[2] = {{.fixture = &f, .memory = first}, {.fixture = &f, .memory = 0}};
    pthread_t threads[2];
    size_t const count = two ? 2 : 1;
    for (size_t i = 0; i < count; ++i) { assert(pthread_create(&threads[i], NULL, operate, &ops[i]) == 0); }
    barrier(&f.entered);
    uint_least64_t const state = atomic_load(&f.gate->state);
    assert((state & 511) == count);
    assert(((state >> 9) & 2097151) == first + (two ? 65536 : 0));
    unsigned int calls = atomic_load(&f.computations);
    create_result(&f, two || first == 262144 ? VIREO_RESULT_BUSY : VIREO_OK);
    if (!two && first == 196608) {
        verify_result(&f, 65537, 3, VIREO_RESULT_BUSY); /* 差1KiB，槽仍有空余。 */
        verify_result(&f, 65536, 3, VIREO_OK); /* 恰好等于内存上限。 */
        calls += 2;
    }
    assert(atomic_load(&f.computations) == calls);
    if (close_inflight) {
        assert(vireo_auth_password_gate_close(f.gate) == VIREO_OK);
        assert(atomic_load(&f.gate->state) == (state | (UINT64_C(1) << 30)));
        create_result(&f, VIREO_RESULT_CANCELLED);
        verify_result(&f, 8, 1, VIREO_RESULT_CANCELLED);
        assert(atomic_load(&f.computations) == calls);
    }
    /* 在途期间只close，不以被禁止的destroy竞态验证BUSY。 */
    barrier(&f.leave);
    for (size_t i = 0; i < count; ++i) {
        assert(pthread_join(threads[i], NULL) == 0);
        assert(ops[i].result == VIREO_OK && (ops[i].memory == 0 || ops[i].matches));
    }
    assert(atomic_load(&f.gate->state) == (close_inflight ? UINT64_C(1) << 30 : 0));
    assert(pthread_barrier_destroy(&f.entered) == 0 && pthread_barrier_destroy(&f.leave) == 0);
    finished(&f);
    observations += 5;
}

static void construction(void)
{
    fixture_t f = {0};
    vireo_auth_password_runtime_t ops = runtime(&f);
    vireo_auth_password_gate_options_t options = VIREO_AUTH_PASSWORD_GATE_OPTIONS_DEFAULT;
    assert(vireo_auth_password_gate_create(NULL, &f.gate) == VIREO_RESULT_INVALID_ARGUMENT);
    assert(vireo_auth_password_gate_create(&options, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    assert(vireo_auth_password_gate_create_with_runtime(&options, &f.gate, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    ops.inspect = NULL;
    assert(vireo_auth_password_gate_create_with_runtime(&options, &f.gate, &ops) == VIREO_RESULT_INVALID_ARGUMENT);
    ops = runtime(&f);
    vireo_auth_password_gate_options_t const bad[] = {{0, 262144}, {257, 262144}, {1, 262143}, {1, 1048577}};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        assert(vireo_auth_password_gate_create_with_runtime(&bad[i], &f.gate, &ops) == VIREO_RESULT_RANGE && f.gate == NULL);
    }
    f.no_memory = true;
    errno = EDOM;
    assert(vireo_auth_password_gate_create_with_runtime(&options, &f.gate, &ops) == VIREO_RESULT_NO_MEMORY);
    assert(f.gate == NULL && errno == EDOM);
    f.no_memory = false;
    --f.allocations; /* 失败分配不需要配对free。 */
    options = (vireo_auth_password_gate_options_t){256, 1048576};
    assert(vireo_auth_password_gate_create_with_runtime(&options, &f.gate, &ops) == VIREO_OK);
    vireo_auth_password_gate_t *original = f.gate;
    assert(vireo_auth_password_gate_create(&options, &f.gate) == VIREO_RESULT_INVALID_ARGUMENT && f.gate == original);
    assert(vireo_auth_password_gate_destroy(&f.gate) == VIREO_RESULT_BUSY && f.gate == original);
    finished(&f);
    options = (vireo_auth_password_gate_options_t){1, 262144};
    assert(vireo_auth_password_gate_create(&options, &f.gate) == VIREO_OK);
    assert(vireo_auth_password_gate_close(f.gate) == VIREO_OK);
    assert(vireo_auth_password_gate_destroy(&f.gate) == VIREO_OK);
    assert(vireo_auth_password_gate_close(NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    assert(vireo_auth_password_gate_destroy(NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    observations += 15;
}

static void errors(void)
{
    fixture_t f = {.match = true};
    opened(&f);
    char out[128], phc[128];
    memset(out, 0xa5, sizeof(out));
    size_t written = 999;
    size_t const phc_length = record(phc, 8, 1);
    bool matches = false;
    errno = EDOM;
    assert(vireo_auth_password_hash_create(NULL, ordinary, 8, out, 128, &written) == VIREO_RESULT_INVALID_ARGUMENT);
    assert(vireo_auth_password_hash_create(f.gate, NULL, 8, out, 128, &written) == VIREO_RESULT_INVALID_ARGUMENT);
    assert(vireo_auth_password_hash_create(f.gate, ordinary, 8, NULL, 128, &written) == VIREO_RESULT_INVALID_ARGUMENT);
    assert(vireo_auth_password_hash_create(f.gate, ordinary, 8, out, 128, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    assert(vireo_auth_password_hash_create(f.gate, ordinary, 8, out, 127, &written) == VIREO_RESULT_RANGE);
    assert(vireo_auth_password_hash_create(f.gate, ordinary, 7, out, 128, &written) == VIREO_RESULT_RANGE);
    assert(vireo_auth_password_hash_create(f.gate, ordinary, SIZE_MAX, out, 128, &written) == VIREO_RESULT_RANGE);
    assert(vireo_auth_password_hash_create(f.gate, "abcd efgh", 9, out, 128, &written) == VIREO_RESULT_PROTOCOL);
    assert(vireo_auth_password_hash_verify(NULL, ordinary, 8, phc, phc_length, &matches) == VIREO_RESULT_INVALID_ARGUMENT);
    assert(vireo_auth_password_hash_verify(f.gate, NULL, 8, phc, phc_length, &matches) == VIREO_RESULT_INVALID_ARGUMENT);
    assert(vireo_auth_password_hash_verify(f.gate, ordinary, 8, NULL, phc_length, &matches) == VIREO_RESULT_INVALID_ARGUMENT);
    assert(vireo_auth_password_hash_verify(f.gate, ordinary, 8, phc, phc_length, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    assert(vireo_auth_password_hash_verify(f.gate, ordinary, 7, phc, phc_length, &matches) == VIREO_RESULT_RANGE);
    assert(vireo_auth_password_hash_verify(f.gate, ordinary, SIZE_MAX, phc, phc_length, &matches) == VIREO_RESULT_RANGE);
    assert(vireo_auth_password_hash_verify(f.gate, ordinary, 8, phc, 128, &matches) == VIREO_RESULT_RANGE);
    assert(vireo_auth_password_hash_verify(f.gate, ordinary, 8, phc, 0, &matches) == VIREO_RESULT_RANGE);
    assert(vireo_auth_password_hash_verify(f.gate, "abcd\0efg", 8, phc, phc_length, &matches) == VIREO_RESULT_PROTOCOL);
    assert(vireo_auth_password_hash_verify(f.gate, ordinary, 8, "bad", 3, &matches) == VIREO_RESULT_PROTOCOL);
    assert(errno == EDOM && written == 999 && !matches && (unsigned char)out[0] == 0xa5);
    verify_result(&f, 262145, 3, VIREO_RESULT_RANGE);
    verify_result(&f, 65536, 11, VIREO_RESULT_RANGE);
    assert(atomic_load(&f.computations) == 0 && atomic_load(&f.gate->state) == 0);
    vireo_result_t const failures[] = {VIREO_RESULT_IO, VIREO_RESULT_NO_MEMORY, VIREO_RESULT_INTERNAL};
    for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); ++i) {
        f.result = failures[i];
        create_result(&f, failures[i]);
        if (failures[i] != VIREO_RESULT_IO) { verify_result(&f, 65536, 3, failures[i]); }
        assert(atomic_load(&f.gate->state) == 0);
        f.result = VIREO_OK;
        create_result(&f, VIREO_OK);
        assert(atomic_load(&f.gate->state) == 0);
    }
    f.match = false;
    verify_result(&f, 8, 1, VIREO_OK);
    verify_result(&f, 262144, 10, VIREO_OK); /* 参数传递模型，未实际执行最大组合。 */
    f.bad_output = true;
    create_result(&f, VIREO_RESULT_INTERNAL);
    assert(atomic_load(&f.gate->state) == 0);
    f.bad_output = false;
    f.fail_cas = true;
    unsigned int const calls = atomic_load(&f.computations);
    unsigned int const before = atomic_load(&f.exchanges);
    create_result(&f, VIREO_RESULT_BUSY);
    assert(atomic_load(&f.exchanges) == before + 32 && atomic_load(&f.computations) == calls);
    assert(atomic_load(&f.gate->state) == 0);
    f.fail_cas = false;
    assert(vireo_auth_password_gate_close(f.gate) == VIREO_OK);
    create_result(&f, VIREO_RESULT_CANCELLED);
    verify_result(&f, 8, 1, VIREO_RESULT_CANCELLED);
    assert(vireo_auth_password_hash_verify(f.gate, "abcd efgh", 9, phc, phc_length, &matches) == VIREO_RESULT_PROTOCOL);
    assert(vireo_auth_password_hash_verify(f.gate, ordinary, 8, "bad", 3, &matches) == VIREO_RESULT_PROTOCOL);
    finished(&f);
    observations += 25;
}

/* 人工构造合法历史账本，仅验证字段边界；不伪称256次真实在途KDF。 */
static void packed_boundaries(void)
{
    fixture_t f = {.result = VIREO_OK, .match = true};
    vireo_auth_password_runtime_t const ops = runtime(&f);
    vireo_auth_password_gate_options_t const options = {256, 1048576};
    assert(vireo_auth_password_gate_create_with_runtime(&options, &f.gate, &ops) == VIREO_OK);
    uint_least64_t state = (UINT64_C(2048) << 9) + 256;
    atomic_store(&f.gate->state, state);
    verify_result(&f, 8, 1, VIREO_RESULT_BUSY);
    assert(atomic_load(&f.computations) == 0 && atomic_load(&f.gate->state) == state);
    state = (UINT64_C(2040) << 9) + 255;
    atomic_store(&f.gate->state, state);
    verify_result(&f, 8, 1, VIREO_OK);
    assert(atomic_load(&f.gate->state) == state);
    state = (UINT64_C(786432) << 9) + 3;
    atomic_store(&f.gate->state, state);
    verify_result(&f, 262144, 10, VIREO_OK);
    assert(atomic_load(&f.gate->state) == state);
    atomic_store(&f.gate->state, (UINT64_C(1048576) << 9) + 4);
    verify_result(&f, 8, 1, VIREO_RESULT_BUSY);
    /* 无任何真实借用/线程；归零人工账本后按公开生命周期清理。 */
    atomic_store(&f.gate->state, 0);
    finished(&f);
    observations += 4;
}

int main(void)
{
    construction();
    errors();
    concurrent(196608, true, true);
    concurrent(262144, false, false);
    concurrent(196608, false, false);
    packed_boundaries();
    printf("PASS %zu model observations; allocation/KDF failures, output/errno, exact/+1 KiB, two threads/close, 32 CAS refusals; no real maximum-cost KDF\n", observations);
    return 0;
}
