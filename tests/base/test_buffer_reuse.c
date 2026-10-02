/*
 * PROJECT : VIREO
 * FILE    : test_buffer_reuse.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-02
 * BRIEF   : 此模块负责：
 * -- 精确回缩、故障保持、双区峰值与最终清理验证
 * -- 独立环形字节队列作为连续 buffer 的逻辑序列参考
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
    bool object;
} allocation_t;

typedef struct fixture {
    allocation_t live[3]; /* 对象、旧区、交接前候选区。 */
    size_t calls;
    size_t fail_call;
    size_t failures;
    size_t releases;
    size_t live_count;
    size_t data_bytes;
    size_t peak_data_bytes;
    uint8_t *data; /* 仅本模块内部 seam 取得的当前区，不能提供给下游。 */
    bool invalid_release;
} fixture_t;

static void *allocate_recorded(void *context, size_t size) {
    fixture_t *fixture = context;
    fixture->calls++;
    errno = ENOMEM;
    if (fixture->calls == fixture->fail_call) {
        fixture->failures++;
        return NULL;
    }
    for (size_t i = 0; i < 3; i++) {
        if (fixture->live[i].memory == NULL) {
            void *memory = malloc(size);
            if (memory == NULL) {
                fixture->failures++;
                return NULL;
            }
            memset(memory, 0xA5, size);
            bool object = fixture->calls == 1;
            fixture->live[i] = (allocation_t){memory, size, object};
            fixture->live_count++;
            if (!object) {
                fixture->data = memory;
                fixture->data_bytes += size;
                if (fixture->data_bytes > fixture->peak_data_bytes) {
                    fixture->peak_data_bytes = fixture->data_bytes;
                }
            }
            return memory;
        }
    }
    fixture->failures++;
    return NULL;
}

static void deallocate_recorded(void *context, void *memory) {
    fixture_t *fixture = context;
    errno = EIO;
    for (size_t i = 0; i < 3; i++) {
        allocation_t owned = fixture->live[i];
        if (owned.memory == memory && memory != NULL) {
            fixture->releases++;
            fixture->live_count--;
            if (!owned.object) {
                fixture->data_bytes -= owned.size;
                if (fixture->data == memory) { fixture->data = NULL; }
            }
            fixture->live[i] = (allocation_t){0};
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

static int destroy_recorded(vireo_buffer_t **buffer, fixture_t *fixture) {
    errno = EDOM;
    CHECK(vireo_buffer_destroy(buffer) == VIREO_OK && *buffer == NULL && errno == EDOM);
    CHECK(fixture->live_count == 0 && fixture->data_bytes == 0 && !fixture->invalid_release);
    CHECK(fixture->releases == fixture->calls - fixture->failures);
    return 0;
}

static int check_info(vireo_buffer_t *buffer, size_t capacity, size_t readable, size_t tail) {
    vireo_buffer_info_t info = {0};
    CHECK(vireo_buffer_inspect(buffer, &info) == VIREO_OK);
    CHECK(info.capacity == capacity && info.readable_size == readable && info.tail_space == tail);
    return 0;
}

static int check_bytes(vireo_buffer_t *buffer, uint8_t const *expected, size_t count) {
    uint8_t const *view = NULL;
    size_t size = 0;
    CHECK(vireo_buffer_peek(buffer, &view, &size) == VIREO_OK && size == count);
    if (count == 0) { CHECK(view == NULL); }
    else { CHECK(view != NULL && memcmp(view, expected, count) == 0); }
    return 0;
}

static uint8_t const sample[] = {'A', 0, 'B', 0xFF, 'D', 'E', 'F'};

static int check_null_and_ranges(void) {
    errno = EDOM;
    CHECK(vireo_buffer_shrink(NULL, 0) == VIREO_RESULT_INVALID_ARGUMENT && errno == EDOM);
    fixture_t fixture = {0};
    vireo_buffer_t *buffer = NULL;
    CHECK(create_recorded(8, &fixture, &buffer) == VIREO_OK);
    CHECK(vireo_buffer_append(buffer, sample, 5) == VIREO_OK);
    CHECK(vireo_buffer_consume(buffer, 2) == VIREO_OK);
    uint8_t const *view = NULL;
    size_t size = 0;
    CHECK(vireo_buffer_peek(buffer, &view, &size) == VIREO_OK);
    uint8_t old[8];
    memcpy(old, fixture.data, sizeof(old));
    size_t const invalid[] = {0, 2, 9, VIREO_BUFFER_MAX_CAPACITY + 1, SIZE_MAX};
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        CHECK(vireo_buffer_shrink(buffer, invalid[i]) == VIREO_RESULT_RANGE && errno == EDOM);
        CHECK(check_info(buffer, 8, 3, 3) == 0);
        CHECK(memcmp(fixture.data, old, sizeof(old)) == 0 && memcmp(view, sample + 2, size) == 0);
        CHECK(fixture.calls == 2 && fixture.releases == 0);
    }
    CHECK(destroy_recorded(&buffer, &fixture) == 0);
    return 0;
}

static int check_same_capacity(void) {
    fixture_t fixture = {0};
    vireo_buffer_t *buffer = NULL;
    CHECK(create_recorded(8, &fixture, &buffer) == VIREO_OK);
    CHECK(vireo_buffer_append(buffer, sample, 5) == VIREO_OK);
    CHECK(vireo_buffer_consume(buffer, 2) == VIREO_OK);
    uint8_t old[8];
    memcpy(old, fixture.data, sizeof(old));
    fixture.fail_call = 3;
    errno = EDOM;
    CHECK(vireo_buffer_shrink(buffer, 8) == VIREO_OK && errno == EDOM);
    CHECK(check_info(buffer, 8, 3, 3) == 0 && check_bytes(buffer, sample + 2, 3) == 0);
    CHECK(memcmp(old, fixture.data, sizeof(old)) == 0 && fixture.calls == 2);
    CHECK(vireo_buffer_consume(buffer, 3) == VIREO_OK);
    CHECK(vireo_buffer_shrink(buffer, 8) == VIREO_OK && fixture.calls == 2);
    CHECK(check_info(buffer, 8, 0, 8) == 0);
    CHECK(destroy_recorded(&buffer, &fixture) == 0);
    return 0;
}

static int check_partial_shrink(void) {
    fixture_t fixture = {0};
    vireo_buffer_t *buffer = NULL;
    CHECK(create_recorded(8, &fixture, &buffer) == VIREO_OK);
    vireo_buffer_t *identity = buffer;
    CHECK(vireo_buffer_append(buffer, sample, 5) == VIREO_OK);
    CHECK(vireo_buffer_consume(buffer, 2) == VIREO_OK);
    errno = EDOM;
    CHECK(vireo_buffer_shrink(buffer, 4) == VIREO_OK && errno == EDOM && buffer == identity);
    CHECK(check_info(buffer, 4, 3, 1) == 0 && check_bytes(buffer, sample + 2, 3) == 0);
    CHECK(fixture.data[3] == 0xA5); /* 未复制已消费前缀或旧尾部。 */
    CHECK(fixture.calls == 3 && fixture.releases == 1 && fixture.live_count == 2);
    CHECK(fixture.data_bytes == 4 && fixture.peak_data_bytes == 12);
    CHECK(vireo_buffer_append(buffer, sample + 5, 1) == VIREO_OK);
    uint8_t const expected[] = {'B', 0xFF, 'D', 'E'};
    CHECK(check_bytes(buffer, expected, sizeof(expected)) == 0);
    CHECK(destroy_recorded(&buffer, &fixture) == 0);
    return 0;
}

static int check_exact_readable(void) {
    fixture_t fixture = {0};
    vireo_buffer_t *buffer = NULL;
    CHECK(create_recorded(8, &fixture, &buffer) == VIREO_OK);
    CHECK(vireo_buffer_append(buffer, sample, 5) == VIREO_OK);
    CHECK(vireo_buffer_consume(buffer, 2) == VIREO_OK);
    CHECK(vireo_buffer_shrink(buffer, 3) == VIREO_OK);
    CHECK(check_info(buffer, 3, 3, 0) == 0 && check_bytes(buffer, sample + 2, 3) == 0);
    CHECK(vireo_buffer_shrink(buffer, 2) == VIREO_RESULT_RANGE);
    CHECK(vireo_buffer_append(buffer, sample, 1) == VIREO_RESULT_RANGE);
    CHECK(vireo_buffer_shrink(buffer, 3) == VIREO_OK && fixture.calls == 3);
    CHECK(destroy_recorded(&buffer, &fixture) == 0);
    return 0;
}

static int check_empty_minimum(void) {
    fixture_t fixture = {0};
    vireo_buffer_t *buffer = NULL;
    CHECK(create_recorded(8, &fixture, &buffer) == VIREO_OK);
    CHECK(vireo_buffer_append(buffer, sample, sizeof(sample)) == VIREO_OK);
    CHECK(vireo_buffer_consume(buffer, sizeof(sample)) == VIREO_OK);
    CHECK(vireo_buffer_shrink(buffer, 1) == VIREO_OK);
    CHECK(check_info(buffer, 1, 0, 1) == 0 && check_bytes(buffer, NULL, 0) == 0);
    CHECK(fixture.data[0] == 0xA5 && fixture.peak_data_bytes == 9);
    CHECK(vireo_buffer_shrink(buffer, 0) == VIREO_RESULT_RANGE);
    CHECK(vireo_buffer_shrink(buffer, 1) == VIREO_OK && fixture.calls == 3);
    CHECK(vireo_buffer_append(buffer, sample, 1) == VIREO_OK);
    CHECK(check_bytes(buffer, sample, 1) == 0);
    CHECK(destroy_recorded(&buffer, &fixture) == 0);
    return 0;
}

static int check_failed_partial_retry(void) {
    fixture_t fixture = {0};
    vireo_buffer_t *buffer = NULL;
    CHECK(create_recorded(8, &fixture, &buffer) == VIREO_OK);
    CHECK(vireo_buffer_append(buffer, sample, 5) == VIREO_OK);
    CHECK(vireo_buffer_consume(buffer, 2) == VIREO_OK);
    uint8_t const *view = NULL;
    size_t size = 0;
    CHECK(vireo_buffer_peek(buffer, &view, &size) == VIREO_OK);
    uint8_t old[8];
    memcpy(old, fixture.data, sizeof(old));
    fixture.fail_call = fixture.calls + 1;
    errno = EDOM;
    CHECK(vireo_buffer_shrink(buffer, 3) == VIREO_RESULT_NO_MEMORY && errno == EDOM);
    CHECK(check_info(buffer, 8, 3, 3) == 0 && memcmp(view, sample + 2, size) == 0);
    CHECK(memcmp(old, fixture.data, sizeof(old)) == 0 && fixture.data_bytes == 8);
    CHECK(fixture.releases == 0 && fixture.live_count == 2);
    fixture.fail_call = 0;
    CHECK(vireo_buffer_shrink(buffer, 3) == VIREO_OK && errno == EDOM);
    CHECK(check_info(buffer, 3, 3, 0) == 0 && check_bytes(buffer, sample + 2, 3) == 0);
    CHECK(fixture.calls == 4 && fixture.failures == 1 && fixture.releases == 1);
    CHECK(destroy_recorded(&buffer, &fixture) == 0);
    return 0;
}

static int check_failed_empty(void) {
    fixture_t fixture = {0};
    vireo_buffer_t *buffer = NULL;
    CHECK(create_recorded(8, &fixture, &buffer) == VIREO_OK);
    fixture.fail_call = 3;
    errno = EDOM;
    CHECK(vireo_buffer_shrink(buffer, 1) == VIREO_RESULT_NO_MEMORY && errno == EDOM);
    CHECK(check_info(buffer, 8, 0, 8) == 0 && fixture.releases == 0);
    CHECK(vireo_buffer_append(buffer, sample, sizeof(sample)) == VIREO_OK);
    CHECK(check_bytes(buffer, sample, sizeof(sample)) == 0);
    CHECK(destroy_recorded(&buffer, &fixture) == 0);
    return 0;
}

static int check_failure_after_growth(void) {
    fixture_t fixture = {0};
    vireo_buffer_t *buffer = NULL;
    CHECK(create_recorded(4, &fixture, &buffer) == VIREO_OK);
    CHECK(vireo_buffer_reserve(buffer, 8) == VIREO_OK);
    CHECK(vireo_buffer_append(buffer, sample, sizeof(sample)) == VIREO_OK);
    CHECK(vireo_buffer_consume(buffer, 4) == VIREO_OK);
    fixture.fail_call = 4;
    CHECK(vireo_buffer_shrink(buffer, 3) == VIREO_RESULT_NO_MEMORY);
    CHECK(check_info(buffer, 8, 3, 1) == 0 && check_bytes(buffer, sample + 4, 3) == 0);
    CHECK(fixture.calls == 4 && fixture.releases == 1 && fixture.data_bytes == 8);
    CHECK(destroy_recorded(&buffer, &fixture) == 0);
    return 0;
}

static int check_reuse_cycles(void) {
    fixture_t fixture = {0};
    vireo_buffer_t *buffer = NULL;
    CHECK(create_recorded(1, &fixture, &buffer) == VIREO_OK);
    for (size_t i = 0; i < 100; i++) {
        CHECK(vireo_buffer_reserve(buffer, sizeof(sample)) == VIREO_OK);
        CHECK(vireo_buffer_append(buffer, sample, sizeof(sample)) == VIREO_OK);
        CHECK(vireo_buffer_consume(buffer, 4) == VIREO_OK);
        CHECK(vireo_buffer_shrink(buffer, 3) == VIREO_OK);
        CHECK(check_bytes(buffer, sample + 4, 3) == 0);
        CHECK(vireo_buffer_consume(buffer, 3) == VIREO_OK);
        CHECK(vireo_buffer_shrink(buffer, 1) == VIREO_OK);
        CHECK(check_info(buffer, 1, 0, 1) == 0 && fixture.live_count == 2);
    }
    CHECK(fixture.calls == 302 && fixture.releases == 300 && fixture.peak_data_bytes == 10);
    CHECK(destroy_recorded(&buffer, &fixture) == 0);
    return 0;
}

static int check_hard_limit_reuse(void) {
    fixture_t fixture = {0};
    vireo_buffer_t *buffer = NULL;
    CHECK(create_recorded(VIREO_BUFFER_MAX_CAPACITY, &fixture, &buffer) == VIREO_OK);
    CHECK(vireo_buffer_append(buffer, sample, 1) == VIREO_OK);
    CHECK(vireo_buffer_shrink(buffer, 1) == VIREO_OK);
    CHECK(check_info(buffer, 1, 1, 0) == 0 && check_bytes(buffer, sample, 1) == 0);
    CHECK(fixture.peak_data_bytes == VIREO_BUFFER_MAX_CAPACITY + 1);
    CHECK(vireo_buffer_consume(buffer, 1) == VIREO_OK);
    CHECK(vireo_buffer_reserve(buffer, 32) == VIREO_OK);
    CHECK(check_info(buffer, 32, 0, 32) == 0);
    CHECK(destroy_recorded(&buffer, &fixture) == 0);
    return 0;
}

/* 仅公开观测情景：没有实现连接背压、暂停 recv 或全局内存预算。 */
static int check_watermark_observations(void) {
    fixture_t fixture = {0};
    vireo_buffer_t *buffer = NULL;
    CHECK(create_recorded(32, &fixture, &buffer) == VIREO_OK);
    uint8_t bytes[16] = {0};
    size_t const high = 12, low = 4;
    CHECK(vireo_buffer_append(buffer, bytes, high) == VIREO_OK);
    vireo_buffer_info_t info = {0};
    CHECK(vireo_buffer_inspect(buffer, &info) == VIREO_OK && info.readable_size >= high);
    CHECK(vireo_buffer_shrink(buffer, high) == VIREO_OK);
    CHECK(vireo_buffer_inspect(buffer, &info) == VIREO_OK);
    CHECK(info.capacity == high && info.readable_size >= high); /* 回缩未降低队列水位。 */
    CHECK(vireo_buffer_consume(buffer, high - low) == VIREO_OK);
    CHECK(vireo_buffer_inspect(buffer, &info) == VIREO_OK);
    CHECK(info.readable_size <= low && info.capacity == high);
    CHECK(vireo_buffer_consume(buffer, low) == VIREO_OK);
    CHECK(vireo_buffer_shrink(buffer, 2) == VIREO_OK);
    CHECK(check_info(buffer, 2, 0, 2) == 0);
    CHECK(destroy_recorded(&buffer, &fixture) == 0);
    return 0;
}

#define MODEL_LIMIT ((size_t)4096)
#define SNAPSHOT_LIMIT ((size_t)8192)

/* 独立环形 FIFO，只使用逻辑字节次序；不读取实现索引或复用 checked 算法。 */
typedef struct model {
    uint8_t bytes[4096];
    size_t head;
    size_t count;
    size_t capacity;
    size_t tail_budget; /* 按公开操作后置条件维护，独立核对尾空观测。 */
} model_t;

static uint32_t next_random(uint32_t *state) {
    uint32_t value = *state;
    value ^= value << 13;
    value ^= value >> 17;
    value ^= value << 5;
    *state = value;
    return value;
}

static int check_model(vireo_buffer_t *buffer, model_t const *model, fixture_t const *fixture) {
    CHECK(check_info(buffer, model->capacity, model->count, model->tail_budget) == 0);
    uint8_t const *view = NULL;
    size_t size = 0;
    CHECK(vireo_buffer_peek(buffer, &view, &size) == VIREO_OK && size == model->count);
    if (size == 0) { CHECK(view == NULL); }
    else {
        CHECK(view != NULL);
        for (size_t i = 0; i < size; i++) {
            CHECK(view[i] == model->bytes[(model->head + i) % MODEL_LIMIT]);
        }
    }
    CHECK(model->capacity >= 1 && model->capacity <= VIREO_BUFFER_MAX_CAPACITY);
    CHECK(model->count <= model->capacity && model->tail_budget <= model->capacity - model->count);
    CHECK(fixture->live_count == 2 && fixture->data_bytes == model->capacity && !fixture->invalid_release);
    return 0;
}

static int run_model(uint32_t seed, size_t initial, size_t counters[10], size_t *errors) {
    fixture_t fixture = {0};
    vireo_buffer_t *buffer = NULL;
    CHECK(create_recorded(initial, &fixture, &buffer) == VIREO_OK);
    model_t model = {.capacity = initial, .tail_budget = initial};
    uint32_t random = seed;
    for (size_t step = 0; step < 5000; step++) {
        size_t op = (size_t)(next_random(&random) % 10);
        counters[op]++;
        CHECK(model.capacity <= SNAPSHOT_LIMIT);
        uint8_t old[8192];
        memcpy(old, fixture.data, model.capacity);
        uint8_t const *old_view = NULL;
        size_t old_size = 0;
        CHECK(vireo_buffer_peek(buffer, &old_view, &old_size) == VIREO_OK);
        model_t before = model;
        size_t releases = fixture.releases;
        vireo_result_t expected = VIREO_OK, result = VIREO_OK;
        errno = EDOM;
        if (op == 0) {
            uint8_t input[24];
            size_t length = (size_t)(next_random(&random) % 25);
            if (length > MODEL_LIMIT - model.count) { length = MODEL_LIMIT - model.count; }
            for (size_t i = 0; i < length; i++) { input[i] = (uint8_t)next_random(&random); }
            if (length > model.tail_budget) { expected = VIREO_RESULT_RANGE; }
            result = vireo_buffer_append(buffer, input, length);
            if (expected == VIREO_OK) {
                for (size_t i = 0; i < length; i++) {
                    model.bytes[(model.head + model.count + i) % MODEL_LIMIT] = input[i];
                }
                model.count += length;
                model.tail_budget -= length;
            }
        }
        if (op == 1) {
            size_t length = (size_t)next_random(&random) % (model.count + 2);
            expected = length > model.count ? VIREO_RESULT_RANGE : VIREO_OK;
            result = vireo_buffer_consume(buffer, length);
            if (expected == VIREO_OK) {
                model.head = (model.head + length) % MODEL_LIMIT;
                model.count -= length;
                if (model.count == 0) { model.tail_budget = model.capacity; }
            }
        } else if (op == 2) {
            result = vireo_buffer_compact(buffer);
            model.tail_budget = model.capacity - model.count;
        } else if (op == 3) {
            size_t request = (size_t)(next_random(&random) % 257);
            result = vireo_buffer_reserve(buffer, request);
            if (request > model.tail_budget) {
                if (model.count + request > model.capacity) {
                    vireo_buffer_info_t info = {0};
                    CHECK(vireo_buffer_inspect(buffer, &info) == VIREO_OK);
                    CHECK(info.capacity > model.capacity && info.capacity >= model.count + request);
                    model.capacity = info.capacity; /* 不把增长倍数算法复制为参考实现。 */
                }
                model.tail_budget = model.capacity - model.count;
            }
            CHECK(model.tail_budget >= request);
        } else if (op == 4) {
            size_t target = (size_t)next_random(&random) % (model.capacity + 2);
            expected = target == 0 || target > model.capacity || target < model.count
                ? VIREO_RESULT_RANGE : VIREO_OK;
            result = vireo_buffer_shrink(buffer, target);
            if (expected == VIREO_OK && target < model.capacity) {
                model.capacity = target;
                model.tail_budget = target - model.count;
            }
        } else if (op == 5) {
            result = vireo_buffer_peek(buffer, &old_view, &old_size);
        } else if (op == 6) {
            expected = VIREO_RESULT_RANGE;
            result = vireo_buffer_append(buffer, sample, model.tail_budget + 1);
        } else if (op == 7) {
            expected = model.count == 0 ? VIREO_RESULT_RANGE : VIREO_RESULT_OVERFLOW;
            result = vireo_buffer_reserve(buffer, SIZE_MAX);
        } else if (op == 8) {
            size_t target = model.count == 0 ? 1 : model.count;
            fixture.fail_call = fixture.calls + 1;
            expected = target < model.capacity ? VIREO_RESULT_NO_MEMORY : VIREO_OK;
            result = vireo_buffer_shrink(buffer, target);
            fixture.fail_call = 0;
        } else if (op == 9) {
            expected = VIREO_OK;
            result = vireo_buffer_consume(buffer, model.count);
            model.head = (model.head + model.count) % MODEL_LIMIT;
            model.count = 0;
            model.tail_budget = model.capacity;
        }
        if (result != expected || errno != EDOM || check_model(buffer, &model, &fixture) != 0) {
            fprintf(stderr, "model seed=%08x step=%zu op=%zu result=%d expected=%d\n",
                (unsigned int)seed, step, op, (int)result, (int)expected);
            return 1;
        }
        if (expected != VIREO_OK) {
            (*errors)++;
            CHECK(model.capacity == before.capacity && model.count == before.count);
            CHECK(fixture.releases == releases && memcmp(old, fixture.data, model.capacity) == 0);
            if (old_size != 0) {
                CHECK(old_view != NULL);
                for (size_t i = 0; i < old_size; i++) {
                    CHECK(old_view[i] == before.bytes[(before.head + i) % MODEL_LIMIT]);
                }
            }
        }
    }
    CHECK(destroy_recorded(&buffer, &fixture) == 0);
    return 0;
}

static int check_reference_sequences(void) {
    uint32_t const seeds[] = {UINT32_C(0x12345678), UINT32_C(0xC001D00D),
        UINT32_C(0xA5A5F00D), UINT32_C(0xDEADBEEF)};
    size_t const initial[] = {1, 7, 64, 127};
    size_t counters[10] = {0}, errors = 0;
    for (size_t i = 0; i < sizeof(seeds) / sizeof(seeds[0]); i++) {
        CHECK(run_model(seeds[i], initial[i], counters, &errors) == 0);
    }
    size_t total = 0;
    printf("buffer reference model: operations");
    for (size_t i = 0; i < 10; i++) {
        CHECK(counters[i] != 0);
        total += counters[i];
        printf(" %zu:%zu", i, counters[i]);
    }
    printf("; total=%zu, expected_errors=%zu\n", total, errors);
    CHECK(total == 20000 && errors != 0);
    return 0;
}

int main(void) {
    int (*const tests[])(void) = {
        check_null_and_ranges, check_same_capacity, check_partial_shrink, check_exact_readable,
        check_empty_minimum, check_failed_partial_retry, check_failed_empty,
        check_failure_after_growth, check_reuse_cycles, check_hard_limit_reuse,
        check_watermark_observations, check_reference_sequences,
    };
    size_t failures = 0;
    for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        if (tests[i]() != 0) { failures++; }
    }
    if (failures != 0) {
        fprintf(stderr, "test_buffer_reuse: %zu failed groups\n", failures);
        return EXIT_FAILURE;
    }
    printf("test_buffer_reuse: all %zu groups passed\n", sizeof(tests) / sizeof(tests[0]));
    return EXIT_SUCCESS;
}
