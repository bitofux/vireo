/*
 * PROJECT : VIREO
 * FILE    : test_buffer.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-01
 * BRIEF   : 此模块负责：
 * -- 验证字节序列、尾部容量、消费复用及失败状态保持
 * -- 用真实分配配合确定性故障验证创建回滚和唯一清理
 */
#include <vireo/base/buffer.h>
#include "base/buffer_internal.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

_Static_assert(VIREO_BUFFER_MAX_CAPACITY == 67108864, "per-object byte limit");

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #condition); \
        return 1; \
    } \
} while (0)

typedef struct allocation_fixture {
    size_t calls;
    size_t fail_at;
    size_t live;
    void *blocks[2];
    size_t sizes[2];
    size_t release_order[2];
    size_t releases;
    int invalid_release;
} allocation_fixture_t;

/**
 * @brief 在指定分配次数返回 NULL，其余委托真实 malloc
 * @param[in,out] context 借用存活 fixture，不跨线程使用。
 * @param[in] size 生产路径请求的正字节数。
 * @return 独立已填充 sentinel 的真实内存，或 NULL；所有权交给被测模块。
 * @note 故意修改 errno，使测试能检测公共入口是否恢复；不使用全局 hook。
 */
static void *allocate_recorded(void *context, size_t size) {
    allocation_fixture_t *fixture = context;
    ++fixture->calls;
    errno = ENOMEM;
    if (fixture->calls == fixture->fail_at || fixture->calls > 2) {
        return NULL;
    }
    void *memory = malloc(size);
    if (memory != NULL) {
        size_t index = fixture->calls - 1;
        fixture->blocks[index] = memory;
        fixture->sizes[index] = size;
        ++fixture->live;
        memset(memory, 0xA5, size);
    }
    return memory;
}

/**
 * @brief 核对配对与释放顺序后真实 free，错误也记录而不重复 free
 * @param[in,out] context 借用存活 fixture。
 * @param[in] memory 本 fixture 取得的存活内存，消费其所有权。
 * @note 修改 errno 以证明 destroy 和失败回滚恢复调用者值；不读取释放后地址。
 */
static void deallocate_recorded(void *context, void *memory) {
    allocation_fixture_t *fixture = context;
    for (size_t i = 0; i < 2; ++i) {
        if (fixture->blocks[i] != NULL && fixture->blocks[i] == memory) {
            fixture->release_order[fixture->releases++] = i;
            fixture->blocks[i] = NULL;
            --fixture->live;
            free(memory);
            errno = EIO;
            return;
        }
    }
    fixture->invalid_release = 1;
}

static vireo_buffer_allocator_t recorded_allocator(allocation_fixture_t *fixture) {
    return (vireo_buffer_allocator_t){.context = fixture,
        .allocate = allocate_recorded, .deallocate = deallocate_recorded};
}

/**
 * @brief 按公共观测和独立预期字节核对整个可读结果
 * @param[in] buffer 存活借用对象。
 * @param[in] expected 期望字节；size 为 0 时允许 NULL。
 * @param[in] size/capacity/tail 期望可读长度、容量及尾部空间。
 * @return 0 为通过，1 为失败。
 * @note 不依赖内部索引或结构体 padding；同时验证读接口保持 errno。
 */
static int expect_contents(vireo_buffer_t const *buffer, uint8_t const *expected,
                           size_t size, size_t capacity, size_t tail) {
    vireo_buffer_info_t info = {0};
    uint8_t const *data = (uint8_t const *)"sentinel";
    size_t actual_size = 999;
    errno = EACCES;
    CHECK(vireo_buffer_inspect(buffer, &info) == VIREO_OK);
    CHECK(vireo_buffer_peek(buffer, &data, &actual_size) == VIREO_OK);
    CHECK(errno == EACCES);
    CHECK(info.capacity == capacity && info.readable_size == size && info.tail_space == tail);
    CHECK(actual_size == size);
    if (size == 0) {
        CHECK(data == NULL);
    } else {
        CHECK(data != NULL && memcmp(data, expected, size) == 0);
    }
    return 0;
}

static int check_creation_arguments(void) {
    allocation_fixture_t fixture = {0};
    vireo_buffer_allocator_t allocator = recorded_allocator(&fixture);
    vireo_buffer_t *buffer = NULL;
    errno = EBUSY;
    CHECK(vireo_buffer_create(8, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_buffer_create_with_allocator(0, &allocator, &buffer) == VIREO_RESULT_RANGE);
    CHECK(vireo_buffer_create_with_allocator(VIREO_BUFFER_MAX_CAPACITY + 1,
                                              &allocator, &buffer) == VIREO_RESULT_RANGE);
    CHECK(vireo_buffer_create_with_allocator(SIZE_MAX, &allocator, &buffer) == VIREO_RESULT_RANGE);
    CHECK(errno == EBUSY && buffer == NULL && fixture.calls == 0);
    CHECK(vireo_buffer_create(0, &buffer) == VIREO_RESULT_RANGE);
    CHECK(vireo_buffer_create(8, &buffer) == VIREO_OK);
    vireo_buffer_t *saved = buffer;
    CHECK(vireo_buffer_create(8, &buffer) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(buffer == saved && errno == EBUSY);
    CHECK(expect_contents(buffer, NULL, 0, 8, 8) == 0);
    CHECK(vireo_buffer_destroy(&buffer) == VIREO_OK && buffer == NULL);
    return 0;
}

static int check_allocator_arguments(void) {
    allocation_fixture_t fixture = {0};
    vireo_buffer_allocator_t allocator = recorded_allocator(&fixture);
    vireo_buffer_t *buffer = NULL;
    errno = EBUSY;
    CHECK(vireo_buffer_create_with_allocator(8, NULL, &buffer) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_buffer_create_with_allocator(8, &allocator, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    allocator.allocate = NULL;
    CHECK(vireo_buffer_create_with_allocator(8, &allocator, &buffer) == VIREO_RESULT_INVALID_ARGUMENT);
    allocator = recorded_allocator(&fixture);
    allocator.deallocate = NULL;
    CHECK(vireo_buffer_create_with_allocator(8, &allocator, &buffer) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(buffer == NULL && fixture.calls == 0 && errno == EBUSY);
    return 0;
}

static int check_empty_and_destroy(void) {
    vireo_buffer_t *buffer = NULL;
    errno = EBUSY;
    CHECK(vireo_buffer_destroy(NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_buffer_destroy(&buffer) == VIREO_OK && errno == EBUSY);
    CHECK(vireo_buffer_create(1, &buffer) == VIREO_OK && errno == EBUSY);
    CHECK(expect_contents(buffer, NULL, 0, 1, 1) == 0);
    CHECK(vireo_buffer_append(buffer, NULL, 0) == VIREO_OK);
    CHECK(vireo_buffer_consume(buffer, 0) == VIREO_OK);
    CHECK(expect_contents(buffer, NULL, 0, 1, 1) == 0);
    errno = EBUSY;
    CHECK(vireo_buffer_destroy(&buffer) == VIREO_OK && buffer == NULL && errno == EBUSY);
    CHECK(vireo_buffer_destroy(&buffer) == VIREO_OK && errno == EBUSY);
    return 0;
}

static int check_inspect_failures(void) {
    vireo_buffer_info_t info = {.capacity = 123, .readable_size = 456, .tail_space = 789};
    vireo_buffer_t *buffer = NULL;
    CHECK(vireo_buffer_create(4, &buffer) == VIREO_OK);
    errno = EBUSY;
    CHECK(vireo_buffer_inspect(NULL, &info) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(info.capacity == 123 && info.readable_size == 456 && info.tail_space == 789);
    CHECK(vireo_buffer_inspect(buffer, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(errno == EBUSY);
    CHECK(vireo_buffer_destroy(&buffer) == VIREO_OK);
    return 0;
}

static int check_peek_failures(void) {
    vireo_buffer_t *buffer = NULL;
    uint8_t const sentinel[] = {7};
    uint8_t const *data = sentinel;
    size_t size = 999;
    CHECK(vireo_buffer_create(4, &buffer) == VIREO_OK);
    errno = EBUSY;
    CHECK(vireo_buffer_peek(NULL, &data, &size) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(data == sentinel && size == 999);
    CHECK(vireo_buffer_peek(buffer, NULL, &size) == VIREO_RESULT_INVALID_ARGUMENT && size == 999);
    CHECK(vireo_buffer_peek(buffer, &data, NULL) == VIREO_RESULT_INVALID_ARGUMENT && data == sentinel);
    CHECK(errno == EBUSY);
    CHECK(vireo_buffer_destroy(&buffer) == VIREO_OK);
    return 0;
}

static int check_binary_copy(void) {
    vireo_buffer_t *buffer = NULL;
    uint8_t input[] = {0x41, 0x00, 0xFF, 0x80, 0x42};
    uint8_t const expected[] = {0x41, 0x00, 0xFF, 0x80, 0x42, 0x43, 0x44};
    CHECK(vireo_buffer_create(8, &buffer) == VIREO_OK);
    errno = EBUSY;
    CHECK(vireo_buffer_append(buffer, input, sizeof(input)) == VIREO_OK && errno == EBUSY);
    CHECK(memcmp(input, expected, sizeof(input)) == 0);
    memset(input, 0, sizeof(input));
    CHECK(vireo_buffer_append(buffer, expected + 5, 2) == VIREO_OK);
    CHECK(expect_contents(buffer, expected, sizeof(expected), 8, 1) == 0);
    CHECK(vireo_buffer_destroy(&buffer) == VIREO_OK);
    return 0;
}

/* 首项没有compact：消耗的头部2字节不能掩盖尾部仅剩3字节的事实。 */
static int check_tail_exhaustion(void) {
    vireo_buffer_t *buffer = NULL;
    uint8_t const input[] = {'A', 0, 'B', 'C', 'D'};
    uint8_t const extra[] = {'E', 'F', 'G', 'H'};
    uint8_t const expected[] = {'B', 'C', 'D', 'E', 'F', 'G'};
    CHECK(vireo_buffer_create(8, &buffer) == VIREO_OK);
    CHECK(vireo_buffer_append(buffer, input, sizeof(input)) == VIREO_OK);
    CHECK(vireo_buffer_consume(buffer, 2) == VIREO_OK);
    CHECK(expect_contents(buffer, input + 2, 3, 8, 3) == 0);
    uint8_t const *saved = NULL;
    size_t size = 0;
    CHECK(vireo_buffer_peek(buffer, &saved, &size) == VIREO_OK);
    errno = EBUSY;
    CHECK(vireo_buffer_append(buffer, extra, 4) == VIREO_RESULT_RANGE && errno == EBUSY);
    CHECK(memcmp(saved, input + 2, size) == 0); /* 失败没有结束借用。 */
    CHECK(expect_contents(buffer, input + 2, 3, 8, 3) == 0);
    CHECK(vireo_buffer_append(buffer, extra, 3) == VIREO_OK);
    CHECK(expect_contents(buffer, expected, 6, 8, 0) == 0);
    CHECK(vireo_buffer_append(buffer, extra, 1) == VIREO_RESULT_RANGE);
    CHECK(vireo_buffer_append(buffer, NULL, 0) == VIREO_OK);
    CHECK(expect_contents(buffer, expected, 6, 8, 0) == 0);
    CHECK(vireo_buffer_destroy(&buffer) == VIREO_OK);
    return 0;
}

static int check_consume_and_reuse(void) {
    vireo_buffer_t *buffer = NULL;
    uint8_t const input[] = {1, 2, 3, 4};
    CHECK(vireo_buffer_create(4, &buffer) == VIREO_OK);
    CHECK(vireo_buffer_append(buffer, input, 4) == VIREO_OK);
    errno = EBUSY;
    CHECK(vireo_buffer_consume(buffer, 1) == VIREO_OK && errno == EBUSY);
    CHECK(expect_contents(buffer, input + 1, 3, 4, 0) == 0);
    CHECK(vireo_buffer_consume(buffer, 0) == VIREO_OK);
    CHECK(expect_contents(buffer, input + 1, 3, 4, 0) == 0);
    CHECK(vireo_buffer_consume(buffer, 3) == VIREO_OK);
    CHECK(expect_contents(buffer, NULL, 0, 4, 4) == 0);
    CHECK(vireo_buffer_append(buffer, input, 4) == VIREO_OK);
    CHECK(expect_contents(buffer, input, 4, 4, 0) == 0);
    CHECK(vireo_buffer_destroy(&buffer) == VIREO_OK);
    return 0;
}

/* 观察两次peek地址一致、部分消费后的偏移；成功变更后总是重新peek。 */
static int check_borrowed_views(void) {
    vireo_buffer_t *buffer = NULL;
    uint8_t const input[] = {4, 5, 6};
    uint8_t const *first = NULL;
    uint8_t const *second = NULL;
    size_t size = 0;
    CHECK(vireo_buffer_create(4, &buffer) == VIREO_OK);
    CHECK(vireo_buffer_append(buffer, input, 3) == VIREO_OK);
    CHECK(vireo_buffer_peek(buffer, &first, &size) == VIREO_OK && size == 3);
    CHECK(vireo_buffer_peek(buffer, &second, &size) == VIREO_OK && first == second);
    CHECK(vireo_buffer_consume(buffer, 1) == VIREO_OK);
    CHECK(vireo_buffer_peek(buffer, &second, &size) == VIREO_OK && size == 2);
    /* 固定分配地址仍存活，可比较地址，旧view已不再授权读取。 */
    CHECK(second == first + 1 && memcmp(second, input + 1, 2) == 0);
    CHECK(vireo_buffer_destroy(&buffer) == VIREO_OK);
    return 0;
}

static int check_append_and_consume_failures(void) {
    allocation_fixture_t fixture = {0};
    vireo_buffer_allocator_t allocator = recorded_allocator(&fixture);
    vireo_buffer_t *buffer = NULL;
    uint8_t const input[] = {1, 2, 3};
    uint8_t saved_bytes[8];
    CHECK(vireo_buffer_create_with_allocator(8, &allocator, &buffer) == VIREO_OK);
    CHECK(vireo_buffer_append(buffer, input, 3) == VIREO_OK);
    memcpy(saved_bytes, fixture.blocks[1], sizeof(saved_bytes));
    errno = EBUSY;
    CHECK(vireo_buffer_append(NULL, input, 1) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_buffer_append(NULL, NULL, 0) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_buffer_append(buffer, NULL, 1) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_buffer_append(buffer, input, 6) == VIREO_RESULT_RANGE);
    CHECK(vireo_buffer_consume(NULL, 0) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_buffer_consume(buffer, 4) == VIREO_RESULT_RANGE);
    CHECK(vireo_buffer_consume(buffer, SIZE_MAX) == VIREO_RESULT_RANGE);
    CHECK(errno == EBUSY && memcmp(saved_bytes, fixture.blocks[1], sizeof(saved_bytes)) == 0);
    CHECK(expect_contents(buffer, input, 3, 8, 5) == 0);
    CHECK(vireo_buffer_consume(buffer, 1) == VIREO_OK);
    errno = EBUSY;
    CHECK(vireo_buffer_consume(buffer, 3) == VIREO_RESULT_RANGE && errno == EBUSY);
    CHECK(expect_contents(buffer, input + 1, 2, 8, 5) == 0);
    CHECK(fixture.calls == 2);
    CHECK(vireo_buffer_destroy(&buffer) == VIREO_OK && fixture.live == 0);
    return 0;
}

/* 只有可表示性/容量通过才读取data；用真实1字节指针验证超大长度先拒绝。 */
static int check_arithmetic_boundaries(void) {
    vireo_buffer_t *buffer = NULL;
    uint8_t const byte = 0xFF;
    CHECK(vireo_buffer_create(1, &buffer) == VIREO_OK);
    errno = EBUSY;
    CHECK(vireo_buffer_append(buffer, &byte, SIZE_MAX) == VIREO_RESULT_RANGE && errno == EBUSY);
    CHECK(expect_contents(buffer, NULL, 0, 1, 1) == 0);
    CHECK(vireo_buffer_append(buffer, &byte, 1) == VIREO_OK);
    errno = EBUSY;
    CHECK(vireo_buffer_append(buffer, &byte, SIZE_MAX) == VIREO_RESULT_OVERFLOW && errno == EBUSY);
    CHECK(expect_contents(buffer, &byte, 1, 1, 0) == 0);
    CHECK(vireo_buffer_destroy(&buffer) == VIREO_OK);
    return 0;
}

static int check_hard_limit(void) {
    vireo_buffer_t *buffer = NULL;
    CHECK(vireo_buffer_create(VIREO_BUFFER_MAX_CAPACITY, &buffer) == VIREO_OK);
    CHECK(expect_contents(buffer, NULL, 0, VIREO_BUFFER_MAX_CAPACITY,
                          VIREO_BUFFER_MAX_CAPACITY) == 0);
    CHECK(vireo_buffer_destroy(&buffer) == VIREO_OK && buffer == NULL);
    return 0;
}

static int check_creation_failure_rollback(void) {
    for (size_t fail = 1; fail <= 2; ++fail) {
        allocation_fixture_t fixture = {.fail_at = fail};
        vireo_buffer_allocator_t allocator = recorded_allocator(&fixture);
        vireo_buffer_t *buffer = NULL;
        errno = EBUSY;
        CHECK(vireo_buffer_create_with_allocator(8, &allocator, &buffer) == VIREO_RESULT_NO_MEMORY);
        CHECK(errno == EBUSY && buffer == NULL && fixture.live == 0);
        CHECK(fixture.calls == fail && fixture.releases == fail - 1 && fixture.invalid_release == 0);
        if (fail == 2) {
            CHECK(fixture.release_order[0] == 0);
        }
        CHECK(vireo_buffer_destroy(&buffer) == VIREO_OK && errno == EBUSY);
        /* 故障清除后用同一合同新建，不是sticky失败或自动重试。 */
        fixture = (allocation_fixture_t){0};
        CHECK(vireo_buffer_create_with_allocator(8, &allocator, &buffer) == VIREO_OK);
        CHECK(vireo_buffer_destroy(&buffer) == VIREO_OK && fixture.live == 0);
    }
    return 0;
}

static int check_allocator_copy_and_release(void) {
    allocation_fixture_t fixture = {0};
    vireo_buffer_allocator_t allocator = recorded_allocator(&fixture);
    vireo_buffer_t *buffer = NULL;
    errno = EBUSY;
    CHECK(vireo_buffer_create_with_allocator(8, &allocator, &buffer) == VIREO_OK && errno == EBUSY);
    CHECK(fixture.calls == 2 && fixture.live == 2 && fixture.sizes[1] == 8);
    uint8_t const expected_unused[8] = {0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5};
    CHECK(memcmp(fixture.blocks[1], expected_unused, 8) == 0);
    allocator = (vireo_buffer_allocator_t){0}; /* 已发布对象按值保存原表。 */
    errno = EBUSY;
    CHECK(vireo_buffer_destroy(&buffer) == VIREO_OK && errno == EBUSY && buffer == NULL);
    CHECK(fixture.live == 0 && fixture.releases == 2 && fixture.invalid_release == 0);
    CHECK(fixture.release_order[0] == 1 && fixture.release_order[1] == 0);
    return 0;
}

static int check_repeated_reuse(void) {
    allocation_fixture_t fixture = {0};
    vireo_buffer_allocator_t allocator = recorded_allocator(&fixture);
    vireo_buffer_t *buffer = NULL;
    CHECK(vireo_buffer_create_with_allocator(1, &allocator, &buffer) == VIREO_OK);
    for (size_t i = 0; i < 100; ++i) {
        uint8_t byte = (uint8_t)i;
        CHECK(vireo_buffer_append(buffer, &byte, 1) == VIREO_OK);
        CHECK(expect_contents(buffer, &byte, 1, 1, 0) == 0);
        CHECK(vireo_buffer_append(buffer, &byte, 1) == VIREO_RESULT_RANGE);
        CHECK(vireo_buffer_consume(buffer, 1) == VIREO_OK);
        CHECK(expect_contents(buffer, NULL, 0, 1, 1) == 0);
    }
    CHECK(fixture.calls == 2 && fixture.live == 2);
    CHECK(vireo_buffer_destroy(&buffer) == VIREO_OK && fixture.live == 0);
    return 0;
}

static int check_independent_objects(void) {
    vireo_buffer_t *left = NULL;
    vireo_buffer_t *right = NULL;
    uint8_t const a[] = {1, 2};
    uint8_t const b[] = {3, 4, 5};
    CHECK(vireo_buffer_create(2, &left) == VIREO_OK);
    CHECK(vireo_buffer_create(3, &right) == VIREO_OK && left != right);
    CHECK(vireo_buffer_append(left, a, 2) == VIREO_OK);
    CHECK(vireo_buffer_append(right, b, 3) == VIREO_OK);
    CHECK(vireo_buffer_destroy(&left) == VIREO_OK);
    CHECK(expect_contents(right, b, 3, 3, 0) == 0);
    CHECK(vireo_buffer_destroy(&right) == VIREO_OK);
    return 0;
}

int main(void) {
    int (*const groups[])(void) = {
        check_creation_arguments, check_allocator_arguments, check_empty_and_destroy,
        check_inspect_failures, check_peek_failures, check_binary_copy,
        check_tail_exhaustion, check_consume_and_reuse, check_borrowed_views,
        check_append_and_consume_failures, check_arithmetic_boundaries, check_hard_limit,
        check_creation_failure_rollback, check_allocator_copy_and_release,
        check_repeated_reuse, check_independent_objects,
    };
    size_t failures = 0;
    size_t count = sizeof(groups) / sizeof(groups[0]);
    for (size_t i = 0; i < count; ++i) {
        failures += (size_t)groups[i]();
    }
    if (failures != 0) {
        fprintf(stderr, "test_buffer: %zu failed groups\n", failures);
        return EXIT_FAILURE;
    }
    printf("test_buffer: all %zu test groups passed\n", count);
    return EXIT_SUCCESS;
}
