/*
 * PROJECT : VIREO
 * FILE    : test_thread_pool_lifecycle.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-12
 * BRIEF   : 固定未启动槽、受检资源与失败发布核验
 */

#include "thread/thread_pool_internal.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #condition); \
        return 1; \
    } \
} while (0)

/**
 * @brief
 *     本测试独占的真实块账；不增加 pool owner，也不包含线程资源。
 */
typedef struct allocation_trace {
    size_t attempts; /**< 包括返回 NULL 的尝试次数。 */
    size_t releases; /**< 配对释放调用次数。 */
    size_t requested_bytes; /**< 最近一次申请的正字节数。 */
    void *live; /**< 原 malloc 块的观测别名，释放后为 NULL。 */
    bool fail; /**< 本上下文是否注入 NULL，不代表系统真实 OOM。 */
    bool mismatch; /**< 错误配对或重复活跃申请的测试诊断。 */
} allocation_trace_t;

/**
 * @brief
 *     记录请求，真实申请并污染初始块，或者明确返回 NULL。
 *
 * @param[in,out] context
 *     独占 trace，存活至配对释放，不允许并发使用。
 * @param[in] bytes
 *     正受检请求字节数。
 *
 * @return
 *     真实足量块或 NULL；故意扰动 errno 以核恢复。
 */
static void *trace_allocate(void *context, size_t bytes) {
    allocation_trace_t *trace = context;
    ++trace->attempts;
    trace->requested_bytes = bytes;
    if (trace->live != NULL) { trace->mismatch = true; }
    trace->live = trace->fail ? NULL : malloc(bytes);
    if (trace->live != NULL) { memset(trace->live, 0xa5, bytes); }
    errno = ENOMEM;
    return trace->live;
}

/**
 * @brief
 *     核原块配对后真实释放，不释放 caller 的 trace。
 *
 * @param[in,out] context
 *     该块对应的独占 trace。
 * @param[in] allocation
 *     无访问的原始完整块。
 *
 * @note
 *     无失败返回；mismatch 仅记录测试不变量，故意扰动 errno。
 */
static void trace_deallocate(void *context, void *allocation) {
    allocation_trace_t *trace = context;
    ++trace->releases;
    if (allocation == NULL || allocation != trace->live) { trace->mismatch = true; }
    free(allocation);
    trace->live = NULL;
    errno = EILSEQ;
}

/**
 * @brief
 *     仅按本核心实际布局求当前测试需要的精确预算，不供下游依赖。
 */
static size_t required_bytes(size_t count) {
    return sizeof(vireo_thread_pool_t) + count * sizeof(vireo_thread_pool_worker_slot_t);
}

/**
 * @brief
 *     最小、非整齐槽数与硬上限；快照不依输入寿命或保活 pool。
 */
static int public_lifecycle(void) {
    size_t const counts[] = {1, 3, VIREO_THREAD_POOL_MAX_WORKERS};
    for (size_t i = 0; i < sizeof(counts) / sizeof(counts[0]); ++i) {
        vireo_thread_pool_options_t options = {
            counts[i], VIREO_THREAD_POOL_MAX_ALLOCATION_BYTES
        };
        vireo_thread_pool_t *pool = NULL;
        errno = EDOM;
        CHECK(vireo_thread_pool_create(&options, &pool) == VIREO_OK);
        CHECK(pool != NULL && errno == EDOM);
        options.worker_count = 0;
        options.max_memory_bytes = 0;
        vireo_thread_pool_info_t info;
        CHECK(vireo_thread_pool_inspect(pool, &info) == VIREO_OK && errno == EDOM);
        CHECK(info.worker_count == counts[i]);
        CHECK(info.allocated_bytes == required_bytes(counts[i]));
        CHECK(info.max_memory_bytes == VIREO_THREAD_POOL_MAX_ALLOCATION_BYTES);
        CHECK(vireo_thread_pool_destroy(&pool) == VIREO_OK && pool == NULL && errno == EDOM);
        CHECK(info.worker_count == counts[i] && info.allocated_bytes == required_bytes(counts[i]));
        CHECK(vireo_thread_pool_destroy(&pool) == VIREO_OK && errno == EDOM);
    }
    return 0;
}

/**
 * @brief
 *     基本非法与非空创建拒绝不夺走已有合法 owner。
 */
static int basic_guards(void) {
    vireo_thread_pool_options_t options = {3, 4096};
    vireo_thread_pool_t *pool = NULL;
    errno = ENOTTY;
    CHECK(vireo_thread_pool_create(NULL, &pool) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(pool == NULL && errno == ENOTTY);
    CHECK(vireo_thread_pool_create(&options, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_thread_pool_create(NULL, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    options.worker_count = 0;
    CHECK(vireo_thread_pool_create(&options, &pool) == VIREO_RESULT_INVALID_ARGUMENT);
    options.worker_count = 3;
    options.max_memory_bytes = 0;
    CHECK(vireo_thread_pool_create(&options, &pool) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(pool == NULL && errno == ENOTTY);
    options.max_memory_bytes = 4096;
    CHECK(vireo_thread_pool_create(&options, &pool) == VIREO_OK);
    vireo_thread_pool_t *original = pool;
    CHECK(vireo_thread_pool_create(&options, &pool) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(pool == original && errno == ENOTTY);
    vireo_thread_pool_info_t info;
    CHECK(vireo_thread_pool_inspect(pool, &info) == VIREO_OK && info.worker_count == 3);
    CHECK(vireo_thread_pool_destroy(&pool) == VIREO_OK && errno == ENOTTY);
    return 0;
}

/**
 * @brief
 *     精确预算可用、差一字节拒绝，均在申请前核预算。
 */
static int budget_boundary(void) {
    allocation_trace_t trace = {0};
    vireo_thread_pool_allocator_t const allocator = {&trace, trace_allocate, trace_deallocate};
    size_t const bytes = required_bytes(3);
    vireo_thread_pool_options_t options = {3, bytes - 1};
    vireo_thread_pool_t *pool = NULL;
    errno = ERANGE;
    CHECK(vireo_thread_pool_create_with_allocator(&options, &allocator, &pool) == VIREO_RESULT_RANGE);
    CHECK(pool == NULL && trace.attempts == 0 && errno == ERANGE);
    options.max_memory_bytes = bytes;
    CHECK(vireo_thread_pool_create_with_allocator(&options, &allocator, &pool) == VIREO_OK);
    CHECK(trace.attempts == 1 && trace.requested_bytes == bytes && errno == ERANGE);
    vireo_thread_pool_info_t info;
    CHECK(vireo_thread_pool_inspect(pool, &info) == VIREO_OK);
    CHECK(info.allocated_bytes == bytes && info.max_memory_bytes == bytes);
    CHECK(vireo_thread_pool_destroy(&pool) == VIREO_OK && errno == ERANGE);
    CHECK(trace.releases == 1 && trace.live == NULL && !trace.mismatch);
    return 0;
}

/**
 * @brief
 *     两项硬限与极小预算不触发分配 callback。
 */
static int hard_limits(void) {
    allocation_trace_t trace = {0};
    vireo_thread_pool_allocator_t const allocator = {&trace, trace_allocate, trace_deallocate};
    vireo_thread_pool_options_t options = {
        VIREO_THREAD_POOL_MAX_WORKERS + 1, VIREO_THREAD_POOL_MAX_ALLOCATION_BYTES
    };
    vireo_thread_pool_t *pool = NULL;
    errno = E2BIG;
    CHECK(vireo_thread_pool_create_with_allocator(&options, &allocator, &pool) == VIREO_RESULT_RANGE);
    options.worker_count = 1;
    options.max_memory_bytes = VIREO_THREAD_POOL_MAX_ALLOCATION_BYTES + 1;
    CHECK(vireo_thread_pool_create_with_allocator(&options, &allocator, &pool) == VIREO_RESULT_RANGE);
    options.max_memory_bytes = 1;
    CHECK(vireo_thread_pool_create_with_allocator(&options, &allocator, &pool) == VIREO_RESULT_RANGE);
    CHECK(pool == NULL && trace.attempts == 0 && trace.releases == 0 && errno == E2BIG);
    return 0;
}

/**
 * @brief
 *     乘法和可达加法溢出优先于槽数/预算硬限，不回绕申请。
 */
static int arithmetic_precedence(void) {
    allocation_trace_t trace = {0};
    vireo_thread_pool_allocator_t const allocator = {&trace, trace_allocate, trace_deallocate};
    size_t const slot_size = sizeof(vireo_thread_pool_worker_slot_t);
    CHECK(slot_size > 1);
    vireo_thread_pool_options_t options = {
        SIZE_MAX / slot_size + 1, VIREO_THREAD_POOL_MAX_ALLOCATION_BYTES + 1
    };
    vireo_thread_pool_t *pool = NULL;
    errno = EOVERFLOW;
    CHECK(vireo_thread_pool_create_with_allocator(&options, &allocator, &pool) == VIREO_RESULT_OVERFLOW);
    options.worker_count = SIZE_MAX / slot_size;
    if (sizeof(vireo_thread_pool_t) > SIZE_MAX % slot_size) {
        CHECK(vireo_thread_pool_create_with_allocator(&options, &allocator, &pool) == VIREO_RESULT_OVERFLOW);
    } else {
        /* 此布局没有可达的纯加法溢出边界，仍须在算术可表示后拒绝硬限。 */
        CHECK(vireo_thread_pool_create_with_allocator(&options, &allocator, &pool) == VIREO_RESULT_RANGE);
    }
    options.worker_count = SIZE_MAX;
    options.max_memory_bytes = 0;
    CHECK(vireo_thread_pool_create_with_allocator(&options, &allocator, &pool) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(pool == NULL && trace.attempts == 0 && trace.releases == 0 && errno == EOVERFLOW);
    return 0;
}

/**
 * @brief
 *     分配明确失败后无发布/释放不存在块；同 owner 可显式再创建。
 */
static int allocation_failure(void) {
    allocation_trace_t trace = {.fail = true};
    vireo_thread_pool_allocator_t const allocator = {&trace, trace_allocate, trace_deallocate};
    vireo_thread_pool_options_t const options = {3, 4096};
    vireo_thread_pool_t *pool = NULL;
    errno = EACCES;
    CHECK(vireo_thread_pool_create_with_allocator(&options, &allocator, &pool) == VIREO_RESULT_NO_MEMORY);
    CHECK(pool == NULL && trace.attempts == 1 && trace.releases == 0 && trace.live == NULL);
    CHECK(errno == EACCES && !trace.mismatch);
    trace.fail = false;
    CHECK(vireo_thread_pool_create_with_allocator(&options, &allocator, &pool) == VIREO_OK);
    CHECK(trace.attempts == 2 && trace.live == pool && errno == EACCES);
    CHECK(vireo_thread_pool_destroy(&pool) == VIREO_OK && errno == EACCES);
    CHECK(trace.releases == 1 && trace.live == NULL && !trace.mismatch);
    return 0;
}

/**
 * @brief
 *     缺失私有操作表在申请前拒绝；表只借至返回，pool 持自有副本。
 */
static int allocator_contract(void) {
    allocation_trace_t trace = {0};
    vireo_thread_pool_options_t const options = {3, 4096};
    vireo_thread_pool_allocator_t allocator = {&trace, trace_allocate, trace_deallocate};
    vireo_thread_pool_t *pool = NULL;
    errno = EINVAL;
    CHECK(vireo_thread_pool_create_with_allocator(&options, NULL, &pool) == VIREO_RESULT_INVALID_ARGUMENT);
    allocator.allocate = NULL;
    CHECK(vireo_thread_pool_create_with_allocator(&options, &allocator, &pool) == VIREO_RESULT_INVALID_ARGUMENT);
    allocator.allocate = trace_allocate;
    allocator.deallocate = NULL;
    CHECK(vireo_thread_pool_create_with_allocator(&options, &allocator, &pool) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(trace.attempts == 0 && pool == NULL && errno == EINVAL);
    allocator.deallocate = trace_deallocate;
    CHECK(vireo_thread_pool_create_with_allocator(&options, &allocator, &pool) == VIREO_OK);
    allocator.context = NULL;
    allocator.allocate = NULL;
    allocator.deallocate = NULL;
    CHECK(vireo_thread_pool_destroy(&pool) == VIREO_OK && errno == EINVAL);
    CHECK(trace.releases == 1 && trace.live == NULL && !trace.mismatch);
    return 0;
}

/**
 * @brief
 *     初始块非零仍全部未创建；不观察无有效值的 pthread 句柄。
 */
static int slot_initialization(void) {
    size_t const counts[] = {1, 3, VIREO_THREAD_POOL_MAX_WORKERS};
    for (size_t i = 0; i < sizeof(counts) / sizeof(counts[0]); ++i) {
        allocation_trace_t trace = {0};
        vireo_thread_pool_allocator_t const allocator = {&trace, trace_allocate, trace_deallocate};
        vireo_thread_pool_options_t const options = {counts[i], VIREO_THREAD_POOL_MAX_ALLOCATION_BYTES};
        vireo_thread_pool_t *pool = NULL;
        errno = EIO;
        CHECK(vireo_thread_pool_create_with_allocator(&options, &allocator, &pool) == VIREO_OK);
        CHECK(trace.live == pool && trace.requested_bytes == required_bytes(counts[i]));
        for (size_t slot = 0; slot < counts[i]; ++slot) {
            CHECK(!pool->workers[slot].thread_created);
        }
        CHECK(vireo_thread_pool_destroy(&pool) == VIREO_OK && errno == EIO);
        CHECK(trace.releases == 1 && trace.live == NULL && !trace.mismatch);
    }
    return 0;
}

/**
 * @brief
 *     非法观测保持包括 padding 的整输出；空销毁及 NULL 地址有明确分类。
 */
static int inspect_and_destroy_guards(void) {
    vireo_thread_pool_info_t info;
    unsigned char before[sizeof(info)];
    memset(&info, 0xa5, sizeof(info));
    memcpy(before, &info, sizeof(info));
    errno = EBADF;
    CHECK(vireo_thread_pool_inspect(NULL, &info) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(memcmp(before, &info, sizeof(info)) == 0 && errno == EBADF);
    CHECK(vireo_thread_pool_inspect(NULL, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_thread_pool_destroy(NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    vireo_thread_pool_t *pool = NULL;
    CHECK(vireo_thread_pool_destroy(&pool) == VIREO_OK && pool == NULL && errno == EBADF);
    vireo_thread_pool_options_t const options = {3, 4096};
    CHECK(vireo_thread_pool_create(&options, &pool) == VIREO_OK);
    CHECK(vireo_thread_pool_inspect(pool, NULL) == VIREO_RESULT_INVALID_ARGUMENT && errno == EBADF);
    CHECK(vireo_thread_pool_inspect(pool, &info) == VIREO_OK && info.worker_count == 3);
    CHECK(vireo_thread_pool_destroy(&pool) == VIREO_OK && errno == EBADF);
    return 0;
}

int main(void) {
    CHECK(public_lifecycle() == 0);
    CHECK(basic_guards() == 0);
    CHECK(budget_boundary() == 0);
    CHECK(hard_limits() == 0);
    CHECK(arithmetic_precedence() == 0);
    CHECK(allocation_failure() == 0);
    CHECK(allocator_contract() == 0);
    CHECK(slot_initialization() == 0);
    CHECK(inspect_and_destroy_guards() == 0);
    printf("test_thread_pool_lifecycle: 9 groups passed; no worker threads started\n");
    return 0;
}
