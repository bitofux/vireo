/*
 * PROJECT : VIREO
 * FILE    : test_buffer_storage.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-01
 * BRIEF   : 此模块负责：
 * -- 显式整理/尾部预留的字节、边界与失败保持验证
 * -- 真实配对分配记录、确定增长失败及最终清理验证
 */
#include <vireo/base/buffer.h>
#include "base/buffer_internal.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(expression) do { if (!(expression)) { \
    fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #expression); return 1; \
} } while (0)

typedef struct allocation {
    void *memory;
    size_t size;
    size_t id;
} allocation_t;

typedef struct fixture {
    allocation_t live[3]; /* 对象 + 旧字节区 + 未交接的新字节区。 */
    size_t calls;
    size_t fail_call;
    size_t releases;
    size_t live_count;
    size_t data_bytes;
    size_t peak_data_bytes;
    size_t released_ids[32];
    uint8_t *data; /* 最近成功取得的字节区，仅用于本模块测试内部观测。 */
    bool invalid_release;
} fixture_t;

/* 真实分配全部填 A5：可核对扩容仅复制未读区，没有复制已消费前缀/尾部。 */
static void *allocate_recorded(void *context, size_t size) {
    fixture_t *fixture = context;
    fixture->calls++;
    errno = ENOMEM;
    if (fixture->calls == fixture->fail_call) {
        return NULL;
    }
    for (size_t slot = 0; slot < 3; slot++) {
        if (fixture->live[slot].memory == NULL) {
            void *memory = malloc(size);
            if (memory == NULL) {
                return NULL;
            }
            memset(memory, 0xA5, size);
            fixture->live[slot] = (allocation_t){memory, size, fixture->calls};
            fixture->live_count++;
            if (fixture->calls != 1) {
                fixture->data = memory;
                fixture->data_bytes += size;
                if (fixture->data_bytes > fixture->peak_data_bytes) {
                    fixture->peak_data_bytes = fixture->data_bytes;
                }
            }
            return memory;
        }
    }
    return NULL;
}

/* 不保存已释放地址：记录分配编号以验证交接/析构的准确配对。 */
static void deallocate_recorded(void *context, void *memory) {
    fixture_t *fixture = context;
    errno = EIO;
    for (size_t slot = 0; slot < 3; slot++) {
        allocation_t owned = fixture->live[slot];
        if (owned.memory == memory && memory != NULL) {
            if (fixture->releases < 32) {
                fixture->released_ids[fixture->releases] = owned.id;
            }
            fixture->releases++;
            fixture->live_count--;
            if (owned.id != 1) {
                fixture->data_bytes -= owned.size;
                if (fixture->data == memory) {
                    fixture->data = NULL;
                }
            }
            fixture->live[slot] = (allocation_t){0};
            free(memory);
            return;
        }
    }
    fixture->invalid_release = true;
}

static vireo_result_t create_recorded(size_t capacity, fixture_t *fixture,
                                       vireo_buffer_t **buffer) {
    vireo_buffer_allocator_t allocator = {
        .context = fixture, .allocate = allocate_recorded, .deallocate = deallocate_recorded,
    };
    return vireo_buffer_create_with_allocator(capacity, &allocator, buffer);
}

/* 所有公开观测都比较语义成员，不把 padding 当状态。 */
static int check_info(vireo_buffer_t *buffer, size_t capacity, size_t size, size_t tail) {
    vireo_buffer_info_t info = {0};
    CHECK(vireo_buffer_inspect(buffer, &info) == VIREO_OK);
    CHECK(info.capacity == capacity && info.readable_size == size && info.tail_space == tail);
    return 0;
}

static int check_bytes(vireo_buffer_t *buffer, uint8_t const *expected, size_t expected_size) {
    uint8_t const *view = NULL;
    size_t size = 0;
    CHECK(vireo_buffer_peek(buffer, &view, &size) == VIREO_OK);
    CHECK(size == expected_size);
    if (size == 0) {
        CHECK(view == NULL);
    } else {
        CHECK(view != NULL && memcmp(view, expected, size) == 0);
    }
    return 0;
}

static int destroy_recorded(vireo_buffer_t **buffer, fixture_t *fixture) {
    errno = EACCES;
    CHECK(vireo_buffer_destroy(buffer) == VIREO_OK);
    CHECK(errno == EACCES && *buffer == NULL);
    CHECK(fixture->live_count == 0 && fixture->data_bytes == 0);
    CHECK(!fixture->invalid_release);
    CHECK(vireo_buffer_destroy(buffer) == VIREO_OK);
    return 0;
}

static uint8_t const sample[8] = {0x41, 0x00, 0x42, 0x43, 0x44, 0x80, 0xFE, 0xFF};

static int check_null(void) {
    errno = EACCES;
    CHECK(vireo_buffer_compact(NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_buffer_reserve(NULL, 0) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_buffer_reserve(NULL, SIZE_MAX) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(errno == EACCES);
    return 0;
}

static int check_empty_compact(void) {
    fixture_t fixture = {0};
    vireo_buffer_t *buffer = NULL;
    CHECK(create_recorded(8, &fixture, &buffer) == VIREO_OK);
    errno = EACCES;
    CHECK(vireo_buffer_compact(buffer) == VIREO_OK && errno == EACCES);
    CHECK(check_info(buffer, 8, 0, 8) == 0);
    CHECK(check_bytes(buffer, NULL, 0) == 0);
    CHECK(fixture.calls == 2 && fixture.releases == 0);
    CHECK(destroy_recorded(&buffer, &fixture) == 0);
    return 0;
}

static int check_compact_at_start(void) {
    fixture_t fixture = {0};
    vireo_buffer_t *buffer = NULL;
    CHECK(create_recorded(8, &fixture, &buffer) == VIREO_OK);
    CHECK(vireo_buffer_append(buffer, sample, 5) == VIREO_OK);
    uint8_t snapshot[8];
    memcpy(snapshot, fixture.data, sizeof(snapshot));
    CHECK(vireo_buffer_compact(buffer) == VIREO_OK);
    CHECK(memcmp(snapshot, fixture.data, sizeof(snapshot)) == 0);
    CHECK(check_info(buffer, 8, 5, 3) == 0 && check_bytes(buffer, sample, 5) == 0);
    CHECK(fixture.calls == 2 && fixture.releases == 0);
    CHECK(destroy_recorded(&buffer, &fixture) == 0);
    return 0;
}

/* 长度 7 的源 [1,8) 与目的 [0,7) 重叠，memcpy 不能满足本场景。 */
static int check_overlapping_compact(void) {
    fixture_t fixture = {0};
    vireo_buffer_t *buffer = NULL;
    CHECK(create_recorded(8, &fixture, &buffer) == VIREO_OK);
    CHECK(vireo_buffer_append(buffer, sample, 8) == VIREO_OK);
    CHECK(vireo_buffer_consume(buffer, 1) == VIREO_OK);
    errno = EACCES;
    CHECK(vireo_buffer_compact(buffer) == VIREO_OK && errno == EACCES);
    CHECK(check_info(buffer, 8, 7, 1) == 0 && check_bytes(buffer, sample + 1, 7) == 0);
    CHECK(fixture.data[7] == sample[7]); /* 不宣称擦除旧内容。 */
    CHECK(fixture.calls == 2 && fixture.releases == 0);
    CHECK(vireo_buffer_append(buffer, sample, 1) == VIREO_OK);
    uint8_t const expected[8] = {0, 0x42, 0x43, 0x44, 0x80, 0xFE, 0xFF, 0x41};
    CHECK(check_bytes(buffer, expected, 8) == 0);
    CHECK(destroy_recorded(&buffer, &fixture) == 0);
    return 0;
}

static int check_disjoint_compact(void) {
    fixture_t fixture = {0};
    vireo_buffer_t *buffer = NULL;
    CHECK(create_recorded(8, &fixture, &buffer) == VIREO_OK);
    CHECK(vireo_buffer_append(buffer, sample, 8) == VIREO_OK);
    CHECK(vireo_buffer_consume(buffer, 6) == VIREO_OK);
    CHECK(vireo_buffer_compact(buffer) == VIREO_OK);
    CHECK(check_info(buffer, 8, 2, 6) == 0 && check_bytes(buffer, sample + 6, 2) == 0);
    CHECK(vireo_buffer_compact(buffer) == VIREO_OK);
    CHECK(check_bytes(buffer, sample + 6, 2) == 0 && fixture.calls == 2);
    CHECK(destroy_recorded(&buffer, &fixture) == 0);
    return 0;
}

/* tail 足够时不回收头部空洞；每次成功后重新 peek，绝不沿用旧借用。 */
static int check_reserve_no_change_cases(void) {
    size_t const requests[] = {0, 2, 3};
    for (size_t i = 0; i < sizeof(requests) / sizeof(requests[0]); i++) {
        fixture_t fixture = {0};
        vireo_buffer_t *buffer = NULL;
        CHECK(create_recorded(8, &fixture, &buffer) == VIREO_OK);
        CHECK(vireo_buffer_append(buffer, sample, 5) == VIREO_OK);
        CHECK(vireo_buffer_consume(buffer, 2) == VIREO_OK);
        uint8_t snapshot[8];
        memcpy(snapshot, fixture.data, sizeof(snapshot));
        errno = EACCES;
        CHECK(vireo_buffer_reserve(buffer, requests[i]) == VIREO_OK && errno == EACCES);
        CHECK(check_info(buffer, 8, 3, 3) == 0 && check_bytes(buffer, sample + 2, 3) == 0);
        uint8_t const *view = NULL;
        size_t size = 0;
        CHECK(vireo_buffer_peek(buffer, &view, &size) == VIREO_OK && view == fixture.data + 2);
        CHECK(memcmp(snapshot, fixture.data, sizeof(snapshot)) == 0);
        CHECK(fixture.calls == 2 && fixture.releases == 0);
        CHECK(destroy_recorded(&buffer, &fixture) == 0);
    }
    return 0;
}

static int check_reserve_compact_cases(void) {
    size_t const requests[] = {4, 5};
    for (size_t i = 0; i < sizeof(requests) / sizeof(requests[0]); i++) {
        fixture_t fixture = {0};
        vireo_buffer_t *buffer = NULL;
        CHECK(create_recorded(8, &fixture, &buffer) == VIREO_OK);
        CHECK(vireo_buffer_append(buffer, sample, 5) == VIREO_OK);
        CHECK(vireo_buffer_consume(buffer, 2) == VIREO_OK);
        errno = EACCES;
        CHECK(vireo_buffer_reserve(buffer, requests[i]) == VIREO_OK && errno == EACCES);
        CHECK(check_info(buffer, 8, 3, 5) == 0 && check_bytes(buffer, sample + 2, 3) == 0);
        uint8_t const *view = NULL;
        size_t size = 0;
        CHECK(vireo_buffer_peek(buffer, &view, &size) == VIREO_OK && view == fixture.data);
        CHECK(fixture.calls == 2 && fixture.releases == 0);
        CHECK(vireo_buffer_append(buffer, sample, requests[i]) == VIREO_OK);
        uint8_t const expected[8] = {0x42, 0x43, 0x44, 0x41, 0, 0x42, 0x43, 0x44};
        CHECK(check_bytes(buffer, expected, 3 + requests[i]) == 0);
        CHECK(destroy_recorded(&buffer, &fixture) == 0);
    }
    return 0;
}

static int check_full_growth(void) {
    fixture_t fixture = {0};
    vireo_buffer_t *buffer = NULL;
    CHECK(create_recorded(8, &fixture, &buffer) == VIREO_OK);
    CHECK(vireo_buffer_append(buffer, sample, 8) == VIREO_OK);
    errno = EACCES;
    CHECK(vireo_buffer_reserve(buffer, 1) == VIREO_OK && errno == EACCES);
    CHECK(check_info(buffer, 16, 8, 8) == 0 && check_bytes(buffer, sample, 8) == 0);
    CHECK(fixture.calls == 3 && fixture.releases == 1 && fixture.live_count == 2);
    CHECK(fixture.released_ids[0] == 2 && fixture.peak_data_bytes == 24);
    for (size_t i = 8; i < 16; i++) { CHECK(fixture.data[i] == 0xA5); }
    CHECK(destroy_recorded(&buffer, &fixture) == 0);
    CHECK(fixture.releases == 3 && fixture.released_ids[1] == 3 && fixture.released_ids[2] == 1);
    return 0;
}

static int check_partial_growth(void) {
    fixture_t fixture = {0};
    vireo_buffer_t *buffer = NULL;
    CHECK(create_recorded(8, &fixture, &buffer) == VIREO_OK);
    CHECK(vireo_buffer_append(buffer, sample, 5) == VIREO_OK);
    CHECK(vireo_buffer_consume(buffer, 2) == VIREO_OK);
    errno = EACCES;
    CHECK(vireo_buffer_reserve(buffer, 6) == VIREO_OK && errno == EACCES);
    CHECK(check_info(buffer, 16, 3, 13) == 0 && check_bytes(buffer, sample + 2, 3) == 0);
    for (size_t i = 3; i < 16; i++) { CHECK(fixture.data[i] == 0xA5); }
    CHECK(vireo_buffer_append(buffer, sample, 6) == VIREO_OK);
    uint8_t const expected[9] = {0x42, 0x43, 0x44, 0x41, 0, 0x42, 0x43, 0x44, 0x80};
    CHECK(check_bytes(buffer, expected, sizeof(expected)) == 0);
    CHECK(fixture.calls == 3 && fixture.releases == 1);
    CHECK(destroy_recorded(&buffer, &fixture) == 0);
    return 0;
}

static int check_large_request(void) {
    fixture_t fixture = {0};
    vireo_buffer_t *buffer = NULL;
    CHECK(create_recorded(8, &fixture, &buffer) == VIREO_OK);
    CHECK(vireo_buffer_append(buffer, sample, 5) == VIREO_OK);
    CHECK(vireo_buffer_consume(buffer, 2) == VIREO_OK);
    CHECK(vireo_buffer_reserve(buffer, 31) == VIREO_OK);
    CHECK(check_info(buffer, 34, 3, 31) == 0 && check_bytes(buffer, sample + 2, 3) == 0);
    CHECK(fixture.calls == 3 && fixture.peak_data_bytes == 42);
    CHECK(destroy_recorded(&buffer, &fixture) == 0);
    return 0;
}

static int check_empty_growth(void) {
    fixture_t fixture = {0};
    vireo_buffer_t *buffer = NULL;
    CHECK(create_recorded(1, &fixture, &buffer) == VIREO_OK);
    CHECK(vireo_buffer_reserve(buffer, 3) == VIREO_OK);
    CHECK(check_info(buffer, 3, 0, 3) == 0 && check_bytes(buffer, NULL, 0) == 0);
    CHECK(fixture.data[0] == 0xA5 && fixture.data[1] == 0xA5 && fixture.data[2] == 0xA5);
    CHECK(vireo_buffer_append(buffer, sample, 3) == VIREO_OK);
    CHECK(check_bytes(buffer, sample, 3) == 0 && fixture.calls == 3);
    CHECK(destroy_recorded(&buffer, &fixture) == 0);
    return 0;
}

/* 分配故障发生在存在头部空洞时：同时检测错误的“先 compact 再 allocate”。 */
static int check_failed_growth_retry(void) {
    fixture_t fixture = {0};
    vireo_buffer_t *buffer = NULL;
    CHECK(create_recorded(8, &fixture, &buffer) == VIREO_OK);
    CHECK(vireo_buffer_append(buffer, sample, 5) == VIREO_OK);
    CHECK(vireo_buffer_consume(buffer, 2) == VIREO_OK);
    uint8_t snapshot[8];
    memcpy(snapshot, fixture.data, sizeof(snapshot));
    uint8_t const *original_view = NULL;
    size_t original_size = 0;
    CHECK(vireo_buffer_peek(buffer, &original_view, &original_size) == VIREO_OK);
    fixture.fail_call = 3;
    errno = EACCES;
    CHECK(vireo_buffer_reserve(buffer, 6) == VIREO_RESULT_NO_MEMORY && errno == EACCES);
    CHECK(fixture.calls == 3 && fixture.releases == 0 && fixture.live_count == 2);
    CHECK(memcmp(snapshot, fixture.data, sizeof(snapshot)) == 0);
    CHECK(check_info(buffer, 8, 3, 3) == 0);
    CHECK(original_size == 3 && memcmp(original_view, sample + 2, 3) == 0);
    uint8_t const *view = NULL;
    size_t size = 0;
    CHECK(vireo_buffer_peek(buffer, &view, &size) == VIREO_OK);
    CHECK(view == original_view && size == original_size);
    fixture.fail_call = 0;
    errno = EACCES;
    CHECK(vireo_buffer_reserve(buffer, 6) == VIREO_OK && errno == EACCES);
    CHECK(check_info(buffer, 16, 3, 13) == 0 && check_bytes(buffer, sample + 2, 3) == 0);
    CHECK(fixture.calls == 4 && fixture.releases == 1 && fixture.released_ids[0] == 2);
    CHECK(destroy_recorded(&buffer, &fixture) == 0);
    CHECK(fixture.released_ids[1] == 4 && fixture.released_ids[2] == 1);
    return 0;
}

static int check_failure_after_growth(void) {
    fixture_t fixture = {0};
    vireo_buffer_t *buffer = NULL;
    CHECK(create_recorded(4, &fixture, &buffer) == VIREO_OK);
    CHECK(vireo_buffer_append(buffer, sample, 4) == VIREO_OK);
    CHECK(vireo_buffer_reserve(buffer, 4) == VIREO_OK);
    CHECK(vireo_buffer_append(buffer, sample + 4, 4) == VIREO_OK);
    CHECK(vireo_buffer_consume(buffer, 1) == VIREO_OK);
    uint8_t snapshot[8];
    memcpy(snapshot, fixture.data, sizeof(snapshot));
    uint8_t const *view = NULL;
    size_t size = 0;
    CHECK(vireo_buffer_peek(buffer, &view, &size) == VIREO_OK);
    fixture.fail_call = 4;
    CHECK(vireo_buffer_reserve(buffer, 2) == VIREO_RESULT_NO_MEMORY);
    CHECK(check_info(buffer, 8, 7, 0) == 0);
    CHECK(size == 7 && memcmp(view, sample + 1, 7) == 0);
    CHECK(memcmp(snapshot, fixture.data, sizeof(snapshot)) == 0);
    CHECK(fixture.releases == 1 && fixture.live_count == 2);
    CHECK(destroy_recorded(&buffer, &fixture) == 0);
    CHECK(fixture.released_ids[1] == 3 && fixture.released_ids[2] == 1);
    return 0;
}

static int check_numeric_rejections(void) {
    fixture_t fixture = {0};
    vireo_buffer_t *buffer = NULL;
    CHECK(create_recorded(8, &fixture, &buffer) == VIREO_OK);
    errno = EACCES;
    CHECK(vireo_buffer_reserve(buffer, SIZE_MAX) == VIREO_RESULT_RANGE && errno == EACCES);
    CHECK(vireo_buffer_append(buffer, sample, 5) == VIREO_OK);
    CHECK(vireo_buffer_consume(buffer, 2) == VIREO_OK);
    uint8_t snapshot[8];
    memcpy(snapshot, fixture.data, sizeof(snapshot));
    uint8_t const *view = NULL;
    size_t size = 0;
    CHECK(vireo_buffer_peek(buffer, &view, &size) == VIREO_OK);
    CHECK(vireo_buffer_reserve(buffer, SIZE_MAX) == VIREO_RESULT_OVERFLOW);
    CHECK(vireo_buffer_reserve(buffer, VIREO_BUFFER_MAX_CAPACITY) == VIREO_RESULT_RANGE);
    CHECK(vireo_buffer_reserve(buffer, VIREO_BUFFER_MAX_CAPACITY - 2) == VIREO_RESULT_RANGE);
    CHECK(errno == EACCES && fixture.calls == 2 && fixture.releases == 0);
    CHECK(check_info(buffer, 8, 3, 3) == 0);
    CHECK(memcmp(snapshot, fixture.data, sizeof(snapshot)) == 0);
    CHECK(size == 3 && memcmp(view, sample + 2, 3) == 0);
    CHECK(destroy_recorded(&buffer, &fixture) == 0);
    return 0;
}

static int check_exact_hard_limit(void) {
    fixture_t fixture = {0};
    vireo_buffer_t *buffer = NULL;
    CHECK(create_recorded(1, &fixture, &buffer) == VIREO_OK);
    CHECK(vireo_buffer_append(buffer, sample, 1) == VIREO_OK);
    CHECK(vireo_buffer_reserve(buffer, VIREO_BUFFER_MAX_CAPACITY - 1) == VIREO_OK);
    CHECK(check_info(buffer, VIREO_BUFFER_MAX_CAPACITY, 1, VIREO_BUFFER_MAX_CAPACITY - 1) == 0);
    CHECK(check_bytes(buffer, sample, 1) == 0);
    CHECK(fixture.data[VIREO_BUFFER_MAX_CAPACITY - 1] == 0xA5);
    CHECK(vireo_buffer_reserve(buffer, VIREO_BUFFER_MAX_CAPACITY - 1) == VIREO_OK);
    CHECK(vireo_buffer_reserve(buffer, VIREO_BUFFER_MAX_CAPACITY) == VIREO_RESULT_RANGE);
    CHECK(fixture.calls == 3 && fixture.peak_data_bytes == VIREO_BUFFER_MAX_CAPACITY + 1);
    CHECK(destroy_recorded(&buffer, &fixture) == 0);
    return 0;
}

/* 旧容量超过半硬限时必须裁剪翻倍目标；真实新旧区域同时存在并被记录。 */
static int check_growth_clamped(void) {
    fixture_t fixture = {0};
    vireo_buffer_t *buffer = NULL;
    size_t initial = VIREO_BUFFER_MAX_CAPACITY / 2 + 1;
    CHECK(create_recorded(initial, &fixture, &buffer) == VIREO_OK);
    CHECK(vireo_buffer_append(buffer, sample, 1) == VIREO_OK);
    CHECK(vireo_buffer_reserve(buffer, initial) == VIREO_OK);
    CHECK(check_info(buffer, VIREO_BUFFER_MAX_CAPACITY, 1, VIREO_BUFFER_MAX_CAPACITY - 1) == 0);
    CHECK(check_bytes(buffer, sample, 1) == 0);
    CHECK(fixture.calls == 3 && fixture.data_bytes == VIREO_BUFFER_MAX_CAPACITY);
    CHECK(fixture.peak_data_bytes == initial + VIREO_BUFFER_MAX_CAPACITY);
    CHECK(destroy_recorded(&buffer, &fixture) == 0);
    return 0;
}

static int check_repeated_growth_and_reuse(void) {
    fixture_t fixture = {0};
    vireo_buffer_t *buffer = NULL;
    CHECK(create_recorded(1, &fixture, &buffer) == VIREO_OK);
    uint8_t expected[256];
    size_t used = 0;
    for (size_t i = 0; i < sizeof(expected); i++) {
        expected[i] = (uint8_t)i;
        CHECK(vireo_buffer_reserve(buffer, 1) == VIREO_OK);
        CHECK(vireo_buffer_append(buffer, &expected[i], 1) == VIREO_OK);
        used++;
        CHECK(check_bytes(buffer, expected, used) == 0);
        CHECK(fixture.live_count == 2 && !fixture.invalid_release);
    }
    CHECK(check_info(buffer, 256, 256, 0) == 0);
    CHECK(fixture.calls == 10 && fixture.releases == 8 && fixture.peak_data_bytes == 384);
    CHECK(vireo_buffer_consume(buffer, sizeof(expected)) == VIREO_OK);
    CHECK(vireo_buffer_reserve(buffer, sizeof(expected)) == VIREO_OK);
    CHECK(vireo_buffer_append(buffer, expected, sizeof(expected)) == VIREO_OK);
    CHECK(check_bytes(buffer, expected, sizeof(expected)) == 0);
    CHECK(fixture.calls == 10 && fixture.releases == 8);
    CHECK(destroy_recorded(&buffer, &fixture) == 0);
    CHECK(fixture.releases == 10 && fixture.released_ids[9] == 1);
    return 0;
}

static int check_append_stays_explicit(void) {
    fixture_t fixture = {0};
    vireo_buffer_t *buffer = NULL;
    CHECK(create_recorded(8, &fixture, &buffer) == VIREO_OK);
    CHECK(vireo_buffer_append(buffer, sample, 5) == VIREO_OK);
    CHECK(vireo_buffer_consume(buffer, 2) == VIREO_OK);
    CHECK(vireo_buffer_append(buffer, sample, 4) == VIREO_RESULT_RANGE);
    CHECK(fixture.calls == 2 && fixture.releases == 0);
    CHECK(check_info(buffer, 8, 3, 3) == 0 && check_bytes(buffer, sample + 2, 3) == 0);
    CHECK(vireo_buffer_reserve(buffer, 4) == VIREO_OK);
    CHECK(vireo_buffer_append(buffer, sample, 4) == VIREO_OK);
    CHECK(vireo_buffer_append(buffer, sample, 2) == VIREO_RESULT_RANGE);
    CHECK(fixture.calls == 2 && fixture.releases == 0);
    CHECK(destroy_recorded(&buffer, &fixture) == 0);
    return 0;
}

int main(void) {
    int (*const tests[])(void) = {
        check_null, check_empty_compact, check_compact_at_start, check_overlapping_compact,
        check_disjoint_compact, check_reserve_no_change_cases, check_reserve_compact_cases,
        check_full_growth, check_partial_growth, check_large_request, check_empty_growth,
        check_failed_growth_retry, check_failure_after_growth, check_numeric_rejections,
        check_exact_hard_limit, check_growth_clamped, check_repeated_growth_and_reuse,
        check_append_stays_explicit,
    };
    size_t failures = 0;
    for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        if (tests[i]() != 0) { failures++; }
    }
    if (failures != 0) {
        fprintf(stderr, "test_buffer_storage: %zu failed groups\n", failures);
        return EXIT_FAILURE;
    }
    printf("test_buffer_storage: all %zu groups passed\n", sizeof(tests) / sizeof(tests[0]));
    return EXIT_SUCCESS;
}
