/*
- PROJECT : VIREO
- FILE    : test_connection_pool_lifecycle.c
- AUTHOR  : bitofux
- DATE    : 2026-10-04
- BRIEF   : 此模块负责：
- -- 真实公开基础池上的预算、空态计数与唯一 owner 测试
- -- 本模块依赖边界故障、发布时机、清理顺序和 errno 保持测试
 */
#include "net/connection_pool_internal.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned failures;
static unsigned groups;
#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition); \
        ++failures; \
    } \
} while (0)
#define REQUIRE(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "fixture failure %s:%d: %s\n", __FILE__, __LINE__, #condition); \
        exit(EXIT_FAILURE); \
    } \
} while (0)

static vireo_connection_pool_options_t const options = {3, 4096, 1024};

/** 每组独立上下文；基础池始终真实创建，只有明确故障点拒绝调用或污染数值副本。 */
typedef struct fixture {
    vireo_connection_pool_t **owner;
    int constructing;
    unsigned creates;
    unsigned inspections;
    unsigned destroys;
    unsigned allocations;
    unsigned fail_allocation;
    unsigned outer_live;
    unsigned storage_live;
    unsigned corrupt_snapshot;
    vireo_result_t create_result;
    vireo_result_t inspect_result;
    vireo_result_t destroy_result;
    vireo_pool_options_t received_options;
    void *control;
    void *index;
    char order[8];
    size_t released;
} fixture_t;

/* 依赖回调在最终发布前必须观察到 caller owner 仍为空。 */
static void check_publication(fixture_t const *f)
{
    if (f->constructing != 0) {
        CHECK(*f->owner == NULL);
    }
}

static void *tracked_allocate(void *context, size_t bytes)
{
    fixture_t *f = context;
    check_publication(f);
    ++f->allocations;
    errno = EDOM;
    if (f->allocations == f->fail_allocation) {
        return NULL;
    }
    void *memory = malloc(bytes);
    REQUIRE(memory != NULL);
    ++f->outer_live;
    if (f->allocations == 1) {
        f->control = memory;
    } else {
        CHECK(f->allocations == 2);
        f->index = memory;
    }
    return memory;
}

static void tracked_deallocate(void *context, void *memory)
{
    fixture_t *f = context;
    check_publication(f);
    CHECK(f->outer_live > 0);
    REQUIRE(f->released < sizeof(f->order) - 1);
    if (memory == f->index) {
        f->order[f->released++] = 'I';
        f->index = NULL;
    } else {
        CHECK(memory == f->control);
        f->order[f->released++] = 'C';
        f->control = NULL;
    }
    --f->outer_live;
    free(memory);
    errno = ERANGE;
}

static vireo_result_t tracked_create(void *context, vireo_pool_options_t const *opts,
                                     vireo_pool_t **out)
{
    fixture_t *f = context;
    check_publication(f);
    ++f->creates;
    f->received_options = *opts;
    errno = ENOSPC;
    if (f->create_result != VIREO_OK) {
        return f->create_result;
    }
    vireo_result_t result = vireo_pool_create(opts, out);
    if (result == VIREO_OK) {
        ++f->storage_live;
    }
    return result;
}

static vireo_result_t tracked_inspect(void *context, vireo_pool_t const *pool,
                                      vireo_pool_info_t *out)
{
    fixture_t *f = context;
    check_publication(f);
    ++f->inspections;
    errno = EIO;
    if (f->inspect_result != VIREO_OK) {
        return f->inspect_result;
    }
    vireo_result_t result = vireo_pool_inspect(pool, out);
    REQUIRE(result == VIREO_OK);
    switch (f->corrupt_snapshot) {
        case 0: break;
        case 1: out->pool_id = 0; break;
        case 2: ++out->layout.capacity; break;
        case 3: ++out->max_memory_bytes; break;
        case 4: out->allocation_bytes = SIZE_MAX; break;
        case 5: out->in_use_count = 1; break;
        case 6: out->available_count = 0; break;
        case 7: out->metadata_bytes = 0; break;
        case 8: out->last_generation = 1; break;
        case 9: ++out->pool_id; break;
        case 10: --out->allocation_bytes; break;
        case 11: --out->metadata_bytes; break;
        case 12: out->allocation_bytes = out->layout.storage_bytes; break;
        case 13: out->metadata_bytes = out->allocation_bytes; break;
        default: REQUIRE(0); break;
    }
    return result;
}

static vireo_result_t tracked_destroy(void *context, vireo_pool_t **owner)
{
    fixture_t *f = context;
    check_publication(f);
    ++f->destroys;
    errno = ENOTTY;
    if (f->destroy_result != VIREO_OK) {
        return f->destroy_result;
    }
    CHECK(f->storage_live == 1);
    vireo_result_t result = vireo_pool_destroy(owner);
    REQUIRE(result == VIREO_OK);
    --f->storage_live;
    REQUIRE(f->released < sizeof(f->order) - 1);
    f->order[f->released++] = 'B';
    return result;
}

static vireo_connection_pool_ops_t make_ops(fixture_t *f)
{
    return (vireo_connection_pool_ops_t){
        f, tracked_allocate, tracked_deallocate, tracked_create, tracked_inspect, tracked_destroy
    };
}

/* 保留调用入口 errno；失败时强制检查完整 owner 发布边界。 */
static vireo_result_t fixture_create(fixture_t *f, vireo_connection_pool_options_t const *opts,
                                     vireo_connection_pool_t **owner,
                                     vireo_connection_pool_error_t *error)
{
    vireo_connection_pool_ops_t ops = make_ops(f);
    f->owner = owner;
    f->constructing = 1;
    errno = E2BIG;
    vireo_result_t result = vireo_connection_pool_create_with_ops(opts, &ops, owner, error);
    CHECK(errno == E2BIG);
    f->constructing = 0;
    if (result != VIREO_OK) {
        CHECK(*owner == NULL);
    }
    return result;
}

static void fixture_cleanup(fixture_t *f, vireo_connection_pool_t **owner)
{
    vireo_connection_pool_error_t error = {VIREO_CONNECTION_POOL_STAGE_DESTROY_STORAGE};
    errno = E2BIG;
    CHECK(vireo_connection_pool_destroy(owner, &error) == VIREO_OK);
    CHECK(errno == E2BIG);
    CHECK(error.stage == VIREO_CONNECTION_POOL_STAGE_NONE);
    CHECK(*owner == NULL && f->storage_live == 0 && f->outer_live == 0);
}

static void test_public_lifecycle(void)
{
    ++groups;
    vireo_connection_pool_t *pool = NULL;
    vireo_connection_pool_info_t info;
    vireo_connection_pool_error_t error = {VIREO_CONNECTION_POOL_STAGE_ALLOCATE_INDEX};
    errno = E2BIG;
    REQUIRE(vireo_connection_pool_create(&options, &pool, &error) == VIREO_OK);
    CHECK(errno == E2BIG && error.stage == VIREO_CONNECTION_POOL_STAGE_NONE);
    CHECK(vireo_connection_pool_inspect(pool, &info) == VIREO_OK);
    CHECK(errno == E2BIG);
    CHECK(info.capacity == 3 && info.leased_slots == 0 && info.available_slots == 3);
    CHECK(info.index_bytes > 0 && info.container_allocation_bytes > info.index_bytes);
    CHECK(info.allocation_bytes == info.container_allocation_bytes + info.storage_allocation_bytes);
    CHECK(info.allocation_bytes <= info.max_memory_bytes && info.max_memory_bytes == 4096);
    vireo_connection_pool_t *original = pool;
    CHECK(vireo_connection_pool_create(&options, &pool, &error) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(errno == E2BIG && pool == original && error.stage == VIREO_CONNECTION_POOL_STAGE_NONE);
    CHECK(vireo_connection_pool_destroy(&pool, &error) == VIREO_OK);
    CHECK(errno == E2BIG && pool == NULL);
    CHECK(vireo_connection_pool_destroy(&pool, NULL) == VIREO_OK);
    CHECK(errno == E2BIG);
}

static void test_invalid_arguments(void)
{
    ++groups;
    fixture_t f = {0};
    vireo_connection_pool_ops_t ops = make_ops(&f);
    vireo_connection_pool_t *pool = NULL;
    vireo_connection_pool_error_t error = {VIREO_CONNECTION_POOL_STAGE_ALLOCATE_INDEX};
    vireo_connection_pool_info_t out;
    memset(&out, 0xa5, sizeof(out));
    unsigned char before[sizeof(out)];
    memcpy(before, &out, sizeof(out));
    errno = E2BIG;
    CHECK(vireo_connection_pool_create(NULL, &pool, &error) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(error.stage == VIREO_CONNECTION_POOL_STAGE_NONE && pool == NULL);
    CHECK(vireo_connection_pool_create(&options, NULL, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_connection_pool_destroy(NULL, &error) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_connection_pool_inspect(NULL, &out) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(memcmp(before, &out, sizeof(out)) == 0 && errno == E2BIG);
    CHECK(vireo_connection_pool_create_with_ops(&options, NULL, &pool, NULL) ==
          VIREO_RESULT_INVALID_ARGUMENT);
    ops.inspect_storage = NULL;
    CHECK(vireo_connection_pool_create_with_ops(&options, &ops, &pool, NULL) ==
          VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(errno == E2BIG && f.creates == 0 && f.allocations == 0);
    vireo_connection_pool_options_t zero = {0, 4096, 1024};
    CHECK(fixture_create(&f, &zero, &pool, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    zero = (vireo_connection_pool_options_t){3, 0, 1024};
    CHECK(fixture_create(&f, &zero, &pool, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(f.creates == 0 && f.allocations == 0);
}

static void test_capacity_and_hard_limits(void)
{
    ++groups;
    size_t const capacities[] = {1, VIREO_CONNECTION_POOL_MAX_CAPACITY};
    for (size_t i = 0; i < sizeof(capacities) / sizeof(capacities[0]); ++i) {
        vireo_connection_pool_options_t opts = {
            capacities[i], VIREO_CONNECTION_POOL_MAX_MEMORY, 1024
        };
        vireo_connection_pool_t *pool = NULL;
        vireo_connection_pool_info_t info;
        errno = E2BIG;
        REQUIRE(vireo_connection_pool_create(&opts, &pool, NULL) == VIREO_OK);
        CHECK(vireo_connection_pool_inspect(pool, &info) == VIREO_OK);
        CHECK(info.capacity == capacities[i] && info.available_slots == capacities[i]);
        CHECK(info.allocation_bytes <= opts.max_memory_bytes && info.leased_slots == 0);
        CHECK(vireo_connection_pool_destroy(&pool, NULL) == VIREO_OK && errno == E2BIG);
    }
    fixture_t f = {0};
    vireo_connection_pool_t *pool = NULL;
    vireo_connection_pool_options_t bad = {VIREO_CONNECTION_POOL_MAX_CAPACITY + 1, 4096, 1024};
    CHECK(fixture_create(&f, &bad, &pool, NULL) == VIREO_RESULT_RANGE);
    bad = (vireo_connection_pool_options_t){3, VIREO_CONNECTION_POOL_MAX_MEMORY + 1, 1024};
    CHECK(fixture_create(&f, &bad, &pool, NULL) == VIREO_RESULT_RANGE);
    bad = (vireo_connection_pool_options_t){SIZE_MAX, 4096, 1024};
    CHECK(fixture_create(&f, &bad, &pool, NULL) == VIREO_RESULT_OVERFLOW);
    CHECK(f.creates == 0 && f.allocations == 0);
}

/* 精确预算取实际公开报告，不能用基础池私有 sizeof 猜测成功阈值。 */
static void test_exact_budget(void)
{
    ++groups;
    fixture_t first = {0};
    vireo_connection_pool_t *pool = NULL;
    vireo_connection_pool_info_t info;
    REQUIRE(fixture_create(&first, &options, &pool, NULL) == VIREO_OK);
    REQUIRE(vireo_connection_pool_inspect(pool, &info) == VIREO_OK);
    CHECK(first.received_options.capacity == options.capacity);
    CHECK(first.received_options.max_memory_bytes ==
          options.max_memory_bytes - info.container_allocation_bytes);
    fixture_cleanup(&first, &pool);
    CHECK(strcmp(first.order, "BIC") == 0);
    fixture_t exact = {0};
    vireo_connection_pool_options_t opts = {3, info.allocation_bytes, 1024};
    REQUIRE(fixture_create(&exact, &opts, &pool, NULL) == VIREO_OK);
    vireo_connection_pool_info_t actual;
    REQUIRE(vireo_connection_pool_inspect(pool, &actual) == VIREO_OK);
    CHECK(actual.allocation_bytes == opts.max_memory_bytes);
    fixture_cleanup(&exact, &pool);
    fixture_t short_budget = {0};
    vireo_connection_pool_error_t error;
    --opts.max_memory_bytes;
    CHECK(fixture_create(&short_budget, &opts, &pool, &error) == VIREO_RESULT_RANGE);
    CHECK(error.stage == VIREO_CONNECTION_POOL_STAGE_CREATE_STORAGE);
    CHECK(short_budget.creates == 1 && short_budget.allocations == 0);
    CHECK(short_budget.storage_live == 0 && short_budget.destroys == 0);
    fixture_t no_remainder = {0};
    opts.max_memory_bytes = info.container_allocation_bytes;
    CHECK(fixture_create(&no_remainder, &opts, &pool, &error) == VIREO_RESULT_RANGE);
    CHECK(error.stage == VIREO_CONNECTION_POOL_STAGE_NONE && no_remainder.creates == 0);
}

static void test_dependency_failures(void)
{
    ++groups;
    vireo_result_t const results[] = {
        VIREO_RESULT_NO_MEMORY, VIREO_RESULT_OVERFLOW, VIREO_RESULT_RANGE
    };
    for (size_t i = 0; i < sizeof(results) / sizeof(results[0]); ++i) {
        fixture_t f = {0};
        f.create_result = results[i];
        vireo_connection_pool_t *pool = NULL;
        vireo_connection_pool_error_t error;
        CHECK(fixture_create(&f, &options, &pool, &error) == results[i]);
        CHECK(error.stage == VIREO_CONNECTION_POOL_STAGE_CREATE_STORAGE);
        CHECK(f.creates == 1 && f.inspections == 0 && f.allocations == 0 && f.destroys == 0);
    }
    fixture_t f = {0};
    f.inspect_result = VIREO_RESULT_INVALID_ARGUMENT;
    vireo_connection_pool_t *pool = NULL;
    vireo_connection_pool_error_t error;
    CHECK(fixture_create(&f, &options, &pool, &error) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(error.stage == VIREO_CONNECTION_POOL_STAGE_INSPECT_STORAGE);
    CHECK(f.allocations == 0 && f.storage_live == 0 && strcmp(f.order, "B") == 0);
}

static void test_snapshot_rejection(void)
{
    ++groups;
    for (unsigned corruption = 1; corruption <= 13; ++corruption) {
        /* 9..11 是仍合法但与原身份/申请不同，仅在对象发布后的观测中检查。 */
        if (corruption >= 9 && corruption <= 11) {
            continue;
        }
        fixture_t f = {0};
        f.corrupt_snapshot = corruption;
        vireo_connection_pool_t *pool = NULL;
        vireo_connection_pool_error_t error;
        CHECK(fixture_create(&f, &options, &pool, &error) == VIREO_RESULT_INTERNAL);
        CHECK(error.stage == VIREO_CONNECTION_POOL_STAGE_INSPECT_STORAGE);
        CHECK(f.storage_live == 0 && f.outer_live == 0 && f.allocations == 0);
        CHECK(f.destroys == 1 && strcmp(f.order, "B") == 0);
    }
}

static void test_outer_allocation_failures(void)
{
    ++groups;
    for (unsigned fail_at = 1; fail_at <= 2; ++fail_at) {
        fixture_t f = {0};
        f.fail_allocation = fail_at;
        vireo_connection_pool_t *pool = NULL;
        vireo_connection_pool_error_t error;
        CHECK(fixture_create(&f, &options, &pool, &error) == VIREO_RESULT_NO_MEMORY);
        CHECK(error.stage == (fail_at == 1 ? VIREO_CONNECTION_POOL_STAGE_ALLOCATE_CONTROL :
                                           VIREO_CONNECTION_POOL_STAGE_ALLOCATE_INDEX));
        CHECK(f.storage_live == 0 && f.outer_live == 0 && f.destroys == 1);
        CHECK(f.allocations == fail_at && f.inspections == 1);
        CHECK(strcmp(f.order, fail_at == 1 ? "B" : "CB") == 0);
    }
}

static void test_inspect_atomicity(void)
{
    ++groups;
    fixture_t f = {0};
    vireo_connection_pool_t *pool = NULL;
    REQUIRE(fixture_create(&f, &options, &pool, NULL) == VIREO_OK);
    vireo_connection_pool_info_t out;
    memset(&out, 0x5a, sizeof(out));
    unsigned char before[sizeof(out)];
    memcpy(before, &out, sizeof(out));
    errno = E2BIG;
    CHECK(vireo_connection_pool_inspect(pool, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    f.inspect_result = VIREO_RESULT_INVALID_ARGUMENT;
    CHECK(vireo_connection_pool_inspect(pool, &out) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(errno == E2BIG && memcmp(before, &out, sizeof(out)) == 0);
    f.inspect_result = VIREO_OK;
    for (unsigned corruption = 1; corruption <= 13; ++corruption) {
        f.corrupt_snapshot = corruption;
        CHECK(vireo_connection_pool_inspect(pool, &out) == VIREO_RESULT_INTERNAL);
        CHECK(errno == E2BIG && memcmp(before, &out, sizeof(out)) == 0);
    }
    f.corrupt_snapshot = 0;
    CHECK(vireo_connection_pool_inspect(pool, &out) == VIREO_OK && errno == E2BIG);
    CHECK(out.leased_slots == 0 && out.available_slots == 3);
    fixture_cleanup(&f, &pool);
}

/* BUSY 注入只证明本层保持，不冒充真实活连接或基础池并发销毁实验。 */
static void test_destroy_rejection(void)
{
    ++groups;
    fixture_t f = {0};
    vireo_connection_pool_t *pool = NULL;
    REQUIRE(fixture_create(&f, &options, &pool, NULL) == VIREO_OK);
    vireo_connection_pool_t *original = pool;
    vireo_connection_pool_info_t before;
    vireo_connection_pool_info_t after;
    REQUIRE(vireo_connection_pool_inspect(pool, &before) == VIREO_OK);
    f.destroy_result = VIREO_RESULT_BUSY;
    vireo_connection_pool_error_t error;
    errno = E2BIG;
    CHECK(vireo_connection_pool_destroy(&pool, &error) == VIREO_RESULT_BUSY);
    CHECK(errno == E2BIG && pool == original);
    CHECK(error.stage == VIREO_CONNECTION_POOL_STAGE_DESTROY_STORAGE);
    CHECK(f.outer_live == 2 && f.storage_live == 1 && f.released == 0 && f.destroys == 1);
    REQUIRE(vireo_connection_pool_inspect(pool, &after) == VIREO_OK);
    CHECK(after.allocation_bytes == before.allocation_bytes && after.capacity == before.capacity);
    f.destroy_result = VIREO_RESULT_INTERNAL;
    CHECK(vireo_connection_pool_destroy(&pool, NULL) == VIREO_RESULT_INTERNAL);
    CHECK(errno == E2BIG && pool == original && f.outer_live == 2 && f.storage_live == 1);
    f.destroy_result = VIREO_OK;
    fixture_cleanup(&f, &pool);
    CHECK(f.destroys == 3 && strcmp(f.order, "BIC") == 0);
}

static void test_ops_copy(void)
{
    ++groups;
    fixture_t f = {0};
    vireo_connection_pool_t *pool = NULL;
    vireo_connection_pool_ops_t ops = make_ops(&f);
    f.owner = &pool;
    f.constructing = 1;
    errno = E2BIG;
    REQUIRE(vireo_connection_pool_create_with_ops(&options, &ops, &pool, NULL) == VIREO_OK);
    CHECK(errno == E2BIG);
    f.constructing = 0;
    ops = (vireo_connection_pool_ops_t){0};
    vireo_connection_pool_info_t info;
    CHECK(vireo_connection_pool_inspect(pool, &info) == VIREO_OK && errno == E2BIG);
    fixture_cleanup(&f, &pool);
    CHECK(strcmp(f.order, "BIC") == 0);
}

static void test_optional_diagnosis(void)
{
    ++groups;
    fixture_t f = {0};
    f.fail_allocation = 2;
    vireo_connection_pool_t *pool = NULL;
    CHECK(fixture_create(&f, &options, &pool, NULL) == VIREO_RESULT_NO_MEMORY);
    CHECK(f.storage_live == 0 && f.outer_live == 0 && strcmp(f.order, "CB") == 0);
    vireo_connection_pool_error_t error = {VIREO_CONNECTION_POOL_STAGE_CREATE_STORAGE};
    errno = E2BIG;
    CHECK(vireo_connection_pool_destroy(&pool, &error) == VIREO_OK);
    CHECK(error.stage == VIREO_CONNECTION_POOL_STAGE_NONE && errno == E2BIG);
}

static void test_independent_and_repeated(void)
{
    ++groups;
    vireo_connection_pool_t *first = NULL;
    vireo_connection_pool_t *second = NULL;
    REQUIRE(vireo_connection_pool_create(&options, &first, NULL) == VIREO_OK);
    vireo_connection_pool_options_t const other = {5, 4096, 1024};
    REQUIRE(vireo_connection_pool_create(&other, &second, NULL) == VIREO_OK);
    CHECK(vireo_connection_pool_destroy(&first, NULL) == VIREO_OK);
    vireo_connection_pool_info_t info;
    CHECK(vireo_connection_pool_inspect(second, &info) == VIREO_OK);
    CHECK(info.capacity == 5 && info.available_slots == 5 && info.leased_slots == 0);
    CHECK(vireo_connection_pool_destroy(&second, NULL) == VIREO_OK);
    for (unsigned i = 0; i < 128; ++i) {
        fixture_t f = {0};
        REQUIRE(fixture_create(&f, &options, &first, NULL) == VIREO_OK);
        fixture_cleanup(&f, &first);
        CHECK(f.creates == 1 && f.allocations == 2 && f.destroys == 1);
        CHECK(strcmp(f.order, "BIC") == 0);
    }
}

int main(void)
{
    test_public_lifecycle();
    test_invalid_arguments();
    test_capacity_and_hard_limits();
    test_exact_budget();
    test_dependency_failures();
    test_snapshot_rejection();
    test_outer_allocation_failures();
    test_inspect_atomicity();
    test_destroy_rejection();
    test_ops_copy();
    test_optional_diagnosis();
    test_independent_and_repeated();
    printf("connection pool lifecycle: %u groups, %u failures\n", groups, failures);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
