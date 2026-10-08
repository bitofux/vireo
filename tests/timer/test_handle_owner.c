/*
 * PROJECT : VIREO
 * FILE    : test_handle_owner.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-08
 * BRIEF   : 此模块负责：
 * -- 验证真实登记、旧副本与跨 owner 拒绝及资源收尾
 * -- 用本模块隔离夹具验证预算、分配回滚与耗尽
 * -- 独立活跃集合核对与独立线程创建 owner 的身份唯一性
 */
#include <vireo/timer/handle_owner.h>
#include "timer/handle_owner_internal.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #condition); \
        return 1; \
    } \
} while (0)

/** 本模块隔离申请记录；仅存活内存可出现在 pointers 中。 */
typedef struct allocation_probe {
    size_t calls; /**< 已尝试申请次数。 */
    size_t fail_at; /**< 第几次申请返回 NULL，0 不注入。 */
    size_t live; /**< 尚未释放的成功申请数量。 */
    size_t frees; /**< 成对释放次数。 */
    void *pointers[8]; /**< 最多八次申请的存活地址，释放前置 NULL。 */
    size_t bytes[8]; /**< 对应申请字节，用于验证总量。 */
    bool reverse_order; /**< 所有释放是否从最后存活申请开始。 */
} allocation_probe_t;

/** 输出邻位及整个失败对象表示检查，不冻结生产 ABI。 */
typedef struct info_guard {
    uint64_t before; /**< 固定 11。 */
    vireo_timer_handle_owner_info_t value; /**< 被测数值快照输出。 */
    uint64_t after; /**< 固定 19。 */
} info_guard_t;

/** 句柄输出容器，仅测试独占。 */
typedef struct owner_handle_guard {
    uint64_t before; /**< 固定 11。 */
    vireo_timer_handle_t value; /**< 取得输出或非法归还输入。 */
    uint64_t after; /**< 固定 19。 */
} owner_handle_guard_t;

/** 各线程独占一个上下文，join 后主线程读；不共享同一 owner。 */
typedef struct creator_context {
    uint64_t ids[32]; /**< 本线程32次实际公共创建的非零身份。 */
    int failure; /**< 0 正常，1 表示入口或 errno 检查失败。 */
} creator_context_t;

static void *probe_allocate(size_t bytes, void *context) {
    allocation_probe_t *probe = context;
    size_t const index = probe->calls++;
    errno = ENOMEM;
    if (index >= 8 || probe->calls == probe->fail_at) {
        return NULL;
    }
    void *memory = malloc(bytes);
    probe->pointers[index] = memory;
    probe->bytes[index] = bytes;
    if (memory != NULL) {
        probe->live++;
    }
    return memory;
}

static void probe_deallocate(void *memory, void *context) {
    allocation_probe_t *probe = context;
    size_t found = SIZE_MAX;
    size_t last = SIZE_MAX;
    for (size_t i = 0; i < 8; i++) {
        if (probe->pointers[i] != NULL) {
            last = i;
            if (probe->pointers[i] == memory) {
                found = i;
            }
        }
    }
    if (found == SIZE_MAX || found != last) {
        probe->reverse_order = false;
    }
    if (found != SIZE_MAX) {
        probe->pointers[found] = NULL;
        probe->live--;
    }
    probe->frees++;
    free(memory);
    errno = EIO;
}

static vireo_timer_handle_owner_allocator_t strategy(allocation_probe_t *probe) {
    return (vireo_timer_handle_owner_allocator_t){probe_allocate, probe_deallocate, probe};
}

static vireo_timer_handle_owner_options_t options_for(size_t capacity) {
    return (vireo_timer_handle_owner_options_t){capacity, VIREO_TIMER_HANDLE_OWNER_MAX_MEMORY};
}

static int parameter_guards(void) {
    vireo_timer_handle_owner_t *owner = NULL;
    vireo_timer_handle_owner_options_t options = options_for(2);
    vireo_timer_handle_t handle = {7, 3, 9};
    unsigned char snapshot[sizeof(handle)];
    memcpy(snapshot, &handle, sizeof(handle));
    info_guard_t info = {11, {0}, 19};
    unsigned char info_snapshot[sizeof(info)];
    memcpy(info_snapshot, &info, sizeof(info));
    errno = EDOM;
    CHECK(vireo_timer_handle_owner_create(NULL, &owner) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_timer_handle_owner_create(&options, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(owner == NULL && errno == EDOM);
    CHECK(vireo_timer_handle_owner_inspect(NULL, &info.value) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(memcmp(info_snapshot, &info, sizeof(info)) == 0);
    CHECK(vireo_timer_handle_owner_acquire(NULL, &handle) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_timer_handle_owner_validate(NULL, handle) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_timer_handle_owner_release(NULL, &handle) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_timer_handle_owner_destroy(NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_timer_handle_owner_destroy(&owner) == VIREO_OK);
    CHECK(memcmp(snapshot, &handle, sizeof(handle)) == 0 && errno == EDOM);
    CHECK(vireo_timer_handle_owner_create(&options, &owner) == VIREO_OK);
    vireo_timer_handle_owner_t *same = owner;
    CHECK(vireo_timer_handle_owner_create(&options, &owner) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(owner == same);
    CHECK(vireo_timer_handle_owner_inspect(owner, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_timer_handle_owner_acquire(owner, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_timer_handle_owner_release(owner, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_timer_handle_owner_destroy(&owner) == VIREO_OK && owner == NULL && errno == EDOM);
    return 0;
}

static int budget_and_initialization(void) {
    allocation_probe_t probe = {.reverse_order = true};
    vireo_timer_handle_owner_allocator_t allocator = strategy(&probe);
    _Atomic uint64_t ids = ATOMIC_VAR_INIT(0);
    vireo_timer_handle_owner_t *owner = NULL;
    vireo_timer_handle_owner_options_t options = options_for(3);
    errno = EILSEQ;
    CHECK(vireo_timer_handle_owner_create_runtime(&options, &owner, &allocator, &ids) == VIREO_OK);
    CHECK(probe.calls == 2 && probe.live == 2 && errno == EILSEQ);
    info_guard_t out = {11, {0}, 19};
    CHECK(vireo_timer_handle_owner_inspect(owner, &out.value) == VIREO_OK);
    CHECK(out.before == 11 && out.after == 19 && out.value.owner_id == 1);
    CHECK(out.value.capacity == 3 && out.value.active_count == 0 && out.value.available_count == 3);
    CHECK(out.value.last_generation == 0 && out.value.max_memory_bytes == options.max_memory_bytes);
    size_t const exact = probe.bytes[0] + probe.bytes[1];
    CHECK(out.value.allocation_bytes == exact);
    CHECK(exact == sizeof(*owner) + 3 * sizeof(*owner->slots));
    for (size_t i = 0; i < 3; i++) {
        CHECK(!owner->slots[i].active && owner->slots[i].generation == 0);
    }
    CHECK(vireo_timer_handle_owner_destroy(&owner) == VIREO_OK && owner == NULL);
    CHECK(probe.live == 0 && probe.frees == 2 && probe.reverse_order && errno == EILSEQ);
    options.max_memory_bytes = exact - 1;
    CHECK(vireo_timer_handle_owner_create_runtime(&options, &owner, &allocator, &ids) == VIREO_RESULT_RANGE);
    CHECK(probe.calls == 2 && owner == NULL && atomic_load(&ids) == 1 && errno == EILSEQ);
    options.max_memory_bytes = exact;
    CHECK(vireo_timer_handle_owner_create_runtime(&options, &owner, &allocator, &ids) == VIREO_OK);
    CHECK(vireo_timer_handle_owner_inspect(owner, &out.value) == VIREO_OK && out.value.owner_id == 2);
    CHECK(out.value.allocation_bytes == exact && out.value.max_memory_bytes == exact);
    CHECK(vireo_timer_handle_owner_destroy(&owner) == VIREO_OK && probe.live == 0 && probe.reverse_order);
    CHECK(errno == EILSEQ);
    return 0;
}

static int option_rejection_order(void) {
    allocation_probe_t probe = {.reverse_order = true};
    vireo_timer_handle_owner_allocator_t allocator = strategy(&probe);
    _Atomic uint64_t ids = ATOMIC_VAR_INIT(0);
    vireo_timer_handle_owner_t *owner = NULL;
    /* 独立手写输入/结果表，不从生产检查函数生成期望。 */
    vireo_timer_handle_owner_options_t const cases[] = {
        {0, 1}, {1, 0}, {1, 1},
        {VIREO_TIMER_HANDLE_OWNER_MAX_CAPACITY + 1, VIREO_TIMER_HANDLE_OWNER_MAX_MEMORY},
        {1, VIREO_TIMER_HANDLE_OWNER_MAX_MEMORY + 1}, {SIZE_MAX, 1},
        {SIZE_MAX / sizeof(vireo_timer_handle_owner_slot_t), 1}, {SIZE_MAX, 0},
    };
    vireo_result_t const expected[] = {
        VIREO_RESULT_INVALID_ARGUMENT, VIREO_RESULT_INVALID_ARGUMENT, VIREO_RESULT_RANGE,
        VIREO_RESULT_RANGE, VIREO_RESULT_RANGE, VIREO_RESULT_OVERFLOW,
        VIREO_RESULT_OVERFLOW, VIREO_RESULT_INVALID_ARGUMENT,
    };
    errno = ERANGE;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        CHECK(vireo_timer_handle_owner_create_runtime(&cases[i], &owner, &allocator, &ids) == expected[i]);
        CHECK(owner == NULL && probe.calls == 0 && atomic_load(&ids) == 0 && errno == ERANGE);
    }
    vireo_timer_handle_owner_options_t options = options_for(1);
    CHECK(vireo_timer_handle_owner_create_runtime(&options, &owner, NULL, &ids) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_timer_handle_owner_create_runtime(&options, &owner, &allocator, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    allocator.allocate = NULL;
    CHECK(vireo_timer_handle_owner_create_runtime(&options, &owner, &allocator, &ids) == VIREO_RESULT_INVALID_ARGUMENT);
    allocator = strategy(&probe);
    allocator.deallocate = NULL;
    CHECK(vireo_timer_handle_owner_create_runtime(&options, &owner, &allocator, &ids) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(owner == NULL && probe.calls == 0 && errno == ERANGE);
    return 0;
}

static int allocation_rollback(void) {
    for (size_t failure = 1; failure <= 2; failure++) {
        allocation_probe_t probe = {.fail_at = failure, .reverse_order = true};
        vireo_timer_handle_owner_allocator_t allocator = strategy(&probe);
        _Atomic uint64_t ids = ATOMIC_VAR_INIT(0);
        vireo_timer_handle_owner_t *owner = NULL;
        vireo_timer_handle_owner_options_t options = options_for(2);
        errno = EDOM;
        CHECK(vireo_timer_handle_owner_create_runtime(&options, &owner, &allocator, &ids) == VIREO_RESULT_NO_MEMORY);
        CHECK(owner == NULL && probe.calls == failure && probe.live == 0 && probe.frees == failure - 1);
        CHECK(probe.reverse_order && errno == EDOM && atomic_load(&ids) == 1);
        probe.fail_at = 0;
        CHECK(vireo_timer_handle_owner_create_runtime(&options, &owner, &allocator, &ids) == VIREO_OK);
        vireo_timer_handle_owner_info_t info;
        CHECK(vireo_timer_handle_owner_inspect(owner, &info) == VIREO_OK && info.owner_id == 2);
        CHECK(info.last_generation == 0 && probe.live == 2);
        CHECK(vireo_timer_handle_owner_destroy(&owner) == VIREO_OK && owner == NULL);
        CHECK(probe.live == 0 && probe.frees == failure + 1 && probe.reverse_order && errno == EDOM);
    }
    return 0;
}

static int owner_identity_exhaustion(void) {
    allocation_probe_t probe = {.reverse_order = true};
    vireo_timer_handle_owner_allocator_t allocator = strategy(&probe);
    _Atomic uint64_t ids = ATOMIC_VAR_INIT(UINT64_MAX - 1);
    vireo_timer_handle_owner_options_t options = options_for(1);
    vireo_timer_handle_owner_t *owner = NULL;
    vireo_timer_handle_owner_t *other = NULL;
    errno = ERANGE;
    CHECK(vireo_timer_handle_owner_create_runtime(&options, &owner, &allocator, &ids) == VIREO_OK);
    vireo_timer_handle_owner_info_t info;
    CHECK(vireo_timer_handle_owner_inspect(owner, &info) == VIREO_OK && info.owner_id == UINT64_MAX);
    CHECK(atomic_load(&ids) == UINT64_MAX && probe.calls == 2);
    CHECK(vireo_timer_handle_owner_create_runtime(&options, &other, &allocator, &ids) == VIREO_RESULT_OVERFLOW);
    CHECK(other == NULL && probe.calls == 2 && probe.live == 2 && errno == ERANGE);
    CHECK(vireo_timer_handle_owner_destroy(&owner) == VIREO_OK && probe.live == 0 && errno == ERANGE);
    CHECK(vireo_timer_handle_owner_create_runtime(&options, &owner, &allocator, &ids) == VIREO_RESULT_OVERFLOW);
    CHECK(owner == NULL && probe.calls == 2 && atomic_load(&ids) == UINT64_MAX);
    return 0;
}

static int acquire_and_full(void) {
    vireo_timer_handle_owner_t *owner = NULL;
    vireo_timer_handle_owner_options_t options = options_for(2);
    CHECK(vireo_timer_handle_owner_create(&options, &owner) == VIREO_OK);
    vireo_timer_handle_t first = {0}, second = {0};
    errno = EILSEQ;
    CHECK(vireo_timer_handle_owner_acquire(owner, &first) == VIREO_OK);
    CHECK(vireo_timer_handle_owner_acquire(owner, &second) == VIREO_OK);
    CHECK(first.owner_id != 0 && first.owner_id == second.owner_id && first.slot_index != second.slot_index);
    CHECK(first.slot_index < 2 && second.slot_index < 2 && first.generation == 1 && second.generation == 2);
    CHECK(vireo_timer_handle_owner_validate(owner, first) == VIREO_OK);
    CHECK(vireo_timer_handle_owner_validate(owner, second) == VIREO_OK);
    owner_handle_guard_t out = {11, {7, 3, 9}, 19};
    unsigned char snapshot[sizeof(out)];
    memcpy(snapshot, &out, sizeof(out));
    unsigned char state[sizeof(*owner)];
    unsigned char slots[2 * sizeof(*owner->slots)];
    memcpy(state, owner, sizeof(state));
    memcpy(slots, owner->slots, sizeof(slots));
    CHECK(vireo_timer_handle_owner_acquire(owner, &out.value) == VIREO_RESULT_BUSY);
    CHECK(memcmp(snapshot, &out, sizeof(out)) == 0 && errno == EILSEQ);
    CHECK(memcmp(state, owner, sizeof(state)) == 0 && memcmp(slots, owner->slots, sizeof(slots)) == 0);
    vireo_timer_handle_owner_info_t info;
    CHECK(vireo_timer_handle_owner_inspect(owner, &info) == VIREO_OK);
    CHECK(info.active_count == 2 && info.available_count == 0 && info.last_generation == 2);
    CHECK(vireo_timer_handle_owner_release(owner, &first) == VIREO_OK);
    CHECK(vireo_timer_handle_owner_release(owner, &second) == VIREO_OK);
    CHECK(vireo_timer_handle_owner_destroy(&owner) == VIREO_OK && errno == EILSEQ);
    return 0;
}

static int validation_and_release_errors(void) {
    vireo_timer_handle_owner_t *owner = NULL;
    vireo_timer_handle_owner_options_t options = options_for(1);
    CHECK(vireo_timer_handle_owner_create(&options, &owner) == VIREO_OK);
    vireo_timer_handle_t current = {0};
    CHECK(vireo_timer_handle_owner_acquire(owner, &current) == VIREO_OK);
    vireo_timer_handle_t const cases[] = {
        {0}, {0, 0, 1}, {current.owner_id, 0, 0}, {0, SIZE_MAX, 0},
        {current.owner_id, 1, 1}, {current.owner_id, SIZE_MAX, UINT64_MAX},
        {current.owner_id, current.slot_index, 2},
    };
    vireo_result_t const results[] = {
        VIREO_RESULT_NOT_FOUND, VIREO_RESULT_INVALID_ARGUMENT, VIREO_RESULT_INVALID_ARGUMENT,
        VIREO_RESULT_INVALID_ARGUMENT, VIREO_RESULT_RANGE, VIREO_RESULT_RANGE, VIREO_RESULT_NOT_FOUND,
    };
    errno = EDOM;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        owner_handle_guard_t bad = {11, cases[i], 19};
        unsigned char snapshot[sizeof(bad)];
        memcpy(snapshot, &bad, sizeof(bad));
        CHECK(vireo_timer_handle_owner_validate(owner, bad.value) == results[i]);
        CHECK(vireo_timer_handle_owner_release(owner, &bad.value) == results[i]);
        CHECK(memcmp(snapshot, &bad, sizeof(bad)) == 0 && errno == EDOM);
        CHECK(vireo_timer_handle_owner_validate(owner, current) == VIREO_OK);
        vireo_timer_handle_owner_info_t info;
        CHECK(vireo_timer_handle_owner_inspect(owner, &info) == VIREO_OK);
        CHECK(info.active_count == 1 && info.available_count == 0 && info.last_generation == 1);
    }
    CHECK(vireo_timer_handle_owner_release(owner, &current) == VIREO_OK);
    CHECK(vireo_timer_handle_owner_destroy(&owner) == VIREO_OK && errno == EDOM);
    return 0;
}

static int actual_reuse_and_copies(void) {
    vireo_timer_handle_owner_t *owner = NULL;
    vireo_timer_handle_owner_options_t options = options_for(1);
    CHECK(vireo_timer_handle_owner_create(&options, &owner) == VIREO_OK);
    vireo_timer_handle_t current = {0};
    CHECK(vireo_timer_handle_owner_acquire(owner, &current) == VIREO_OK);
    vireo_timer_handle_t const saved = current;
    errno = ERANGE;
    CHECK(vireo_timer_handle_owner_release(owner, &current) == VIREO_OK);
    CHECK(current.owner_id == 0 && current.slot_index == 0 && current.generation == 0);
    CHECK(vireo_timer_handle_owner_validate(owner, saved) == VIREO_RESULT_NOT_FOUND);
    bool empty = true;
    CHECK(vireo_timer_handle_is_empty(saved, &empty) == VIREO_OK && !empty);
    CHECK(vireo_timer_handle_owner_release(owner, &current) == VIREO_RESULT_NOT_FOUND);
    CHECK(vireo_timer_handle_owner_acquire(owner, &current) == VIREO_OK);
    CHECK(current.slot_index == saved.slot_index && current.owner_id == saved.owner_id);
    CHECK(current.generation == 2 && saved.generation == 1);
    vireo_timer_handle_t old = saved;
    unsigned char snapshot[sizeof(old)];
    memcpy(snapshot, &old, sizeof(old));
    CHECK(vireo_timer_handle_owner_release(owner, &old) == VIREO_RESULT_NOT_FOUND);
    CHECK(memcmp(snapshot, &old, sizeof(old)) == 0 && errno == ERANGE);
    CHECK(vireo_timer_handle_owner_validate(owner, current) == VIREO_OK);
    CHECK(vireo_timer_handle_owner_release(owner, &current) == VIREO_OK);
    CHECK(vireo_timer_handle_owner_destroy(&owner) == VIREO_OK && errno == ERANGE);
    return 0;
}

static int cross_owner_and_recreation(void) {
    vireo_timer_handle_owner_t *a = NULL, *b = NULL;
    vireo_timer_handle_owner_options_t options = options_for(1);
    CHECK(vireo_timer_handle_owner_create(&options, &a) == VIREO_OK);
    CHECK(vireo_timer_handle_owner_create(&options, &b) == VIREO_OK);
    vireo_timer_handle_t handle = {0};
    CHECK(vireo_timer_handle_owner_acquire(a, &handle) == VIREO_OK);
    vireo_timer_handle_t saved = handle;
    vireo_timer_handle_owner_info_t info;
    CHECK(vireo_timer_handle_owner_inspect(b, &info) == VIREO_OK && info.owner_id != saved.owner_id);
    errno = EILSEQ;
    CHECK(vireo_timer_handle_owner_validate(b, saved) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_timer_handle_owner_release(b, &saved) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(saved.owner_id == handle.owner_id && saved.generation == handle.generation);
    /* 跨 owner 优先于其 SIZE_MAX 槽范围，不索引错误 owner。 */
    vireo_timer_handle_t wrong_range = saved;
    wrong_range.slot_index = SIZE_MAX;
    CHECK(vireo_timer_handle_owner_validate(b, wrong_range) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_timer_handle_owner_release(a, &handle) == VIREO_OK);
    CHECK(vireo_timer_handle_owner_destroy(&a) == VIREO_OK);
    CHECK(vireo_timer_handle_owner_create(&options, &a) == VIREO_OK);
    CHECK(vireo_timer_handle_owner_inspect(a, &info) == VIREO_OK && info.owner_id != saved.owner_id);
    CHECK(vireo_timer_handle_owner_validate(a, saved) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_timer_handle_owner_destroy(&a) == VIREO_OK);
    CHECK(vireo_timer_handle_owner_destroy(&b) == VIREO_OK && errno == EILSEQ);
    return 0;
}

static int busy_destroy_preserves_resources(void) {
    allocation_probe_t probe = {.reverse_order = true};
    vireo_timer_handle_owner_allocator_t allocator = strategy(&probe);
    _Atomic uint64_t ids = ATOMIC_VAR_INIT(0);
    vireo_timer_handle_owner_t *owner = NULL;
    vireo_timer_handle_owner_options_t options = options_for(1);
    CHECK(vireo_timer_handle_owner_create_runtime(&options, &owner, &allocator, &ids) == VIREO_OK);
    vireo_timer_handle_t handle = {0};
    CHECK(vireo_timer_handle_owner_acquire(owner, &handle) == VIREO_OK);
    vireo_timer_handle_owner_t *same = owner;
    errno = ERANGE;
    CHECK(vireo_timer_handle_owner_destroy(&owner) == VIREO_RESULT_BUSY);
    CHECK(owner == same && probe.live == 2 && probe.frees == 0 && errno == ERANGE);
    CHECK(vireo_timer_handle_owner_validate(owner, handle) == VIREO_OK);
    CHECK(vireo_timer_handle_owner_release(owner, &handle) == VIREO_OK);
    CHECK(vireo_timer_handle_owner_destroy(&owner) == VIREO_OK && owner == NULL);
    CHECK(probe.live == 0 && probe.frees == 2 && probe.reverse_order && errno == ERANGE);
    CHECK(vireo_timer_handle_owner_destroy(&owner) == VIREO_OK && errno == ERANGE);
    return 0;
}

static int generation_exhaustion_and_cleanup(void) {
    vireo_timer_handle_owner_t *owner = NULL;
    vireo_timer_handle_owner_options_t options = options_for(2);
    CHECK(vireo_timer_handle_owner_create(&options, &owner) == VIREO_OK);
    vireo_timer_handle_t first = {0}, last = {0};
    CHECK(vireo_timer_handle_owner_acquire(owner, &first) == VIREO_OK);
    /* 本模块真实私有布局的隔离边界夹具，不声称真实发放了 MAX-1 次。 */
    owner->last_generation = UINT64_MAX - 1;
    errno = EDOM;
    CHECK(vireo_timer_handle_owner_acquire(owner, &last) == VIREO_OK && last.generation == UINT64_MAX);
    owner_handle_guard_t out = {11, {7, 3, 9}, 19};
    unsigned char snapshot[sizeof(out)];
    memcpy(snapshot, &out, sizeof(out));
    CHECK(vireo_timer_handle_owner_acquire(owner, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_timer_handle_owner_acquire(owner, &out.value) == VIREO_RESULT_OVERFLOW);
    CHECK(memcmp(snapshot, &out, sizeof(out)) == 0 && errno == EDOM);
    CHECK(vireo_timer_handle_owner_validate(owner, first) == VIREO_OK);
    CHECK(vireo_timer_handle_owner_validate(owner, last) == VIREO_OK);
    CHECK(vireo_timer_handle_owner_release(owner, &first) == VIREO_OK);
    vireo_timer_handle_owner_info_t info;
    CHECK(vireo_timer_handle_owner_inspect(owner, &info) == VIREO_OK);
    CHECK(info.available_count == 1 && info.active_count == 1 && info.last_generation == UINT64_MAX);
    CHECK(vireo_timer_handle_owner_acquire(owner, &out.value) == VIREO_RESULT_OVERFLOW);
    CHECK(memcmp(snapshot, &out, sizeof(out)) == 0);
    CHECK(vireo_timer_handle_owner_release(owner, &last) == VIREO_OK);
    CHECK(vireo_timer_handle_owner_acquire(owner, &out.value) == VIREO_RESULT_OVERFLOW);
    CHECK(vireo_timer_handle_owner_destroy(&owner) == VIREO_OK && errno == EDOM);
    return 0;
}

static int independent_active_set_model(void) {
    vireo_timer_handle_owner_t *owner = NULL;
    vireo_timer_handle_owner_options_t options = options_for(4);
    CHECK(vireo_timer_handle_owner_create(&options, &owner) == VIREO_OK);
    bool active[4] = {false};
    vireo_timer_handle_t handles[4] = {{0}};
    uint64_t issued = 0;
    size_t count = 0;
    errno = EILSEQ;
    /* 确定性状态序列，独立集合不模拟生产空闲链；不是阶段1随机解析 fuzz。 */
    for (size_t step = 0; step < 400; step++) {
        if (step % 7 < 4) {
            owner_handle_guard_t out = {11, {7, 3, 9}, 19};
            unsigned char snapshot[sizeof(out)];
            memcpy(snapshot, &out, sizeof(out));
            vireo_result_t result = vireo_timer_handle_owner_acquire(owner, &out.value);
            if (count == 4) {
                CHECK(result == VIREO_RESULT_BUSY && memcmp(snapshot, &out, sizeof(out)) == 0);
            } else {
                CHECK(result == VIREO_OK && out.before == 11 && out.after == 19);
                CHECK(out.value.slot_index < 4 && !active[out.value.slot_index]);
                issued++;
                CHECK(out.value.generation == issued);
                handles[out.value.slot_index] = out.value;
                active[out.value.slot_index] = true;
                count++;
            }
        } else {
            size_t index = (step / 7) % 4;
            vireo_timer_handle_t saved = handles[index];
            CHECK(vireo_timer_handle_owner_release(owner, &handles[index]) ==
                  (active[index] ? VIREO_OK : VIREO_RESULT_NOT_FOUND));
            if (active[index]) {
                active[index] = false;
                count--;
                CHECK(vireo_timer_handle_owner_validate(owner, saved) == VIREO_RESULT_NOT_FOUND);
            }
        }
        vireo_timer_handle_owner_info_t info;
        CHECK(vireo_timer_handle_owner_inspect(owner, &info) == VIREO_OK);
        CHECK(info.active_count == count && info.available_count == 4 - count && info.last_generation == issued);
        for (size_t i = 0; i < 4; i++) {
            CHECK(vireo_timer_handle_owner_validate(owner, handles[i]) ==
                  (active[i] ? VIREO_OK : VIREO_RESULT_NOT_FOUND));
        }
        CHECK(errno == EILSEQ);
    }
    for (size_t i = 0; i < 4; i++) {
        if (active[i]) {
            CHECK(vireo_timer_handle_owner_release(owner, &handles[i]) == VIREO_OK);
        }
    }
    CHECK(vireo_timer_handle_owner_destroy(&owner) == VIREO_OK && errno == EILSEQ);
    return 0;
}

static void *create_independent_owners(void *context) {
    creator_context_t *result = context;
    for (size_t i = 0; i < 32; i++) {
        vireo_timer_handle_owner_t *owner = NULL;
        vireo_timer_handle_owner_options_t options = options_for(1);
        errno = EDOM;
        if (vireo_timer_handle_owner_create(&options, &owner) != VIREO_OK) {
            result->failure = 1;
            return NULL;
        }
        vireo_timer_handle_owner_info_t info;
        if (vireo_timer_handle_owner_inspect(owner, &info) != VIREO_OK || errno != EDOM) {
            result->failure = 1;
        } else {
            result->ids[i] = info.owner_id;
        }
        if (vireo_timer_handle_owner_destroy(&owner) != VIREO_OK || owner != NULL || errno != EDOM) {
            result->failure = 1;
        }
    }
    return NULL;
}

static int independent_creators_unique_ids(void) {
    pthread_t threads[4];
    creator_context_t contexts[4] = {0};
    size_t started = 0;
    for (; started < 4; started++) {
        if (pthread_create(&threads[started], NULL, create_independent_owners, &contexts[started]) != 0) {
            break;
        }
    }
    int join_failures = 0;
    for (size_t i = 0; i < started; i++) {
        join_failures += pthread_join(threads[i], NULL) != 0;
    }
    CHECK(started == 4 && join_failures == 0);
    for (size_t i = 0; i < 128; i++) {
        CHECK(contexts[i / 32].failure == 0 && contexts[i / 32].ids[i % 32] != 0);
        for (size_t j = 0; j < i; j++) {
            CHECK(contexts[i / 32].ids[i % 32] != contexts[j / 32].ids[j % 32]);
        }
    }
    return 0;
}

static int maximum_capacity(void) {
    vireo_timer_handle_owner_t *owner = NULL;
    vireo_timer_handle_owner_options_t options = options_for(VIREO_TIMER_HANDLE_OWNER_MAX_CAPACITY);
    CHECK(vireo_timer_handle_owner_create(&options, &owner) == VIREO_OK);
    vireo_timer_handle_owner_info_t info;
    CHECK(vireo_timer_handle_owner_inspect(owner, &info) == VIREO_OK);
    CHECK(info.capacity == VIREO_TIMER_HANDLE_OWNER_MAX_CAPACITY && info.available_count == info.capacity);
    CHECK(info.active_count == 0 && info.allocation_bytes <= options.max_memory_bytes);
    vireo_timer_handle_t *handles = malloc(info.capacity * sizeof(*handles));
    CHECK(handles != NULL);
    for (size_t i = 0; i < info.capacity; i++) {
        CHECK(vireo_timer_handle_owner_acquire(owner, &handles[i]) == VIREO_OK);
        CHECK(handles[i].owner_id == info.owner_id && handles[i].slot_index < info.capacity);
        CHECK(handles[i].generation == (uint64_t)i + 1);
    }
    vireo_timer_handle_t extra = {7, 3, 9};
    CHECK(vireo_timer_handle_owner_acquire(owner, &extra) == VIREO_RESULT_BUSY);
    CHECK(extra.owner_id == 7 && extra.slot_index == 3 && extra.generation == 9);
    for (size_t i = 0; i < info.capacity; i++) {
        CHECK(vireo_timer_handle_owner_validate(owner, handles[i]) == VIREO_OK);
        CHECK(vireo_timer_handle_owner_release(owner, &handles[i]) == VIREO_OK);
    }
    free(handles);
    CHECK(vireo_timer_handle_owner_inspect(owner, &info) == VIREO_OK);
    CHECK(info.active_count == 0 && info.available_count == info.capacity);
    CHECK(info.last_generation == VIREO_TIMER_HANDLE_OWNER_MAX_CAPACITY);
    CHECK(vireo_timer_handle_owner_destroy(&owner) == VIREO_OK && owner == NULL);
    return 0;
}

int main(void) {
    int failures = 0;
    failures += parameter_guards();
    failures += budget_and_initialization();
    failures += option_rejection_order();
    failures += allocation_rollback();
    failures += owner_identity_exhaustion();
    failures += acquire_and_full();
    failures += validation_and_release_errors();
    failures += actual_reuse_and_copies();
    failures += cross_owner_and_recreation();
    failures += busy_destroy_preserves_resources();
    failures += generation_exhaustion_and_cleanup();
    failures += independent_active_set_model();
    failures += independent_creators_unique_ids();
    failures += maximum_capacity();
    printf("timer handle owner: 14 groups, %d failures; model 400 steps; 4 creators/128 IDs; no wheel\n", failures);
    return failures == 0 ? 0 : 1;
}
