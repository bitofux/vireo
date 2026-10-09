/*
 * PROJECT : VIREO
 * FILE    : test_wheel_time.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-09
 * BRIEF   : 此模块负责：
 * -- 以手写期望验证 floor、ceil 和跨圈桶定位
 * -- 验证受检边界、失败输出、errno 与按值写回
 * -- 用小域逐边界枚举核对数学性质，不运行真实时间轮
 */
#include <vireo/timer/wheel_time.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #condition); \
        return 1; \
    } \
} while (0)

/** 几何输出的测试局部保护容器；字段均由本测试独占。 */
typedef struct geometry_guard {
    uint64_t before; /**< 固定 11，前邻位不得被写。 */
    vireo_timer_wheel_geometry_t value; /**< 被测三个几何字段，不拥有数组或轮。 */
    uint64_t after; /**< 固定 19，后邻位不得被写。 */
} geometry_guard_t;

/** 各 uint64 别名输出共用的测试容器，不是生产游标或计数器。 */
typedef struct u64_guard {
    uint64_t before; /**< 固定 11，无时间含义。 */
    uint64_t value; /**< tick/time/bucket 输出，单位按当前调用判断。 */
    uint64_t after; /**< 固定 19，无时间含义。 */
} u64_guard_t;

/** 独立手写的时间映射期望，不由被测函数生成。 */
typedef struct mapping_case {
    vireo_timer_wheel_geometry_t geometry; /**< 明确起点、ns 宽度及数学桶数。 */
    vireo_monotonic_ns_t input_time; /**< 显式 now 或 deadline，纳秒。 */
    vireo_timer_wheel_tick_t expected_tick; /**< 手写 floor 或 ceil 累计刻度。 */
    vireo_monotonic_ns_t boundary_time; /**< 对应刻度的手写绝对纳秒边界。 */
} mapping_case_t;

/** 手写还原边界案例，输入 tick 并非真实已推进刻度。 */
typedef struct boundary_case {
    vireo_timer_wheel_geometry_t geometry; /**< 合法几何值。 */
    vireo_timer_wheel_tick_t tick; /**< 累计刻度输入，无时间单位。 */
    vireo_monotonic_ns_t expected_time; /**< 精确绝对纳秒期望，独立手写。 */
} boundary_case_t;

/** 数学桶位置案例，不包含数组或身份登记槽。 */
typedef struct bucket_case {
    uint64_t count; /**< 正数学桶数，可为 MAX。 */
    vireo_timer_wheel_tick_t tick; /**< 累计刻度，跨圈仍不回绕。 */
    uint64_t expected; /**< 手写桶索引，小于 count。 */
} bucket_case_t;

static int parameter_guards(void) {
    vireo_timer_wheel_geometry_t const valid = {UINT64_MAX, 2, 4};
    vireo_timer_wheel_geometry_t const invalid = {UINT64_MAX, 0, 0};
    errno = EDOM;
    CHECK(vireo_timer_wheel_geometry_make(0, 1, 1, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_timer_wheel_geometry_make(0, 0, 0, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_timer_wheel_elapsed_tick(valid, 0, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_timer_wheel_deadline_tick(valid, UINT64_MAX, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_timer_wheel_tick_time(valid, UINT64_MAX, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_timer_wheel_bucket_index(valid, UINT64_MAX, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_timer_wheel_elapsed_tick(invalid, 0, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_timer_wheel_deadline_tick(invalid, 0, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_timer_wheel_tick_time(invalid, 0, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_timer_wheel_bucket_index(invalid, 0, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(errno == EDOM);
    return 0;
}

static int geometry_values(void) {
    vireo_timer_wheel_geometry_t const cases[] = {
        {0, 1, 1}, {1000, 100, 4}, {0, UINT64_MAX, UINT64_MAX},
        {UINT64_MAX, 1, 1}, {UINT64_MAX, UINT64_MAX, UINT64_MAX},
        {UINT64_C(1000000000), UINT64_C(100000000), 512},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        geometry_guard_t out = {11, {7, 8, 9}, 19};
        errno = EILSEQ;
        CHECK(vireo_timer_wheel_geometry_make(cases[i].origin_ns, cases[i].tick_ns,
                                              cases[i].bucket_count, &out.value) == VIREO_OK);
        CHECK(out.value.origin_ns == cases[i].origin_ns && out.value.tick_ns == cases[i].tick_ns);
        CHECK(out.value.bucket_count == cases[i].bucket_count);
        CHECK(out.before == 11 && out.after == 19 && errno == EILSEQ);
    }
    vireo_timer_wheel_geometry_t const invalid[] = {{0, 0, 1}, {0, 1, 0}, {UINT64_MAX, 0, 0}};
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        geometry_guard_t out;
        unsigned char snapshot[sizeof(out)];
        memset(&out, 0xA5, sizeof(out));
        memcpy(snapshot, &out, sizeof(out));
        errno = ERANGE;
        CHECK(vireo_timer_wheel_geometry_make(invalid[i].origin_ns, invalid[i].tick_ns,
                                              invalid[i].bucket_count, &out.value) == VIREO_RESULT_INVALID_ARGUMENT);
        CHECK(memcmp(snapshot, &out, sizeof(out)) == 0 && errno == ERANGE);
    }
    return 0;
}

static int elapsed_goldens(void) {
    mapping_case_t const cases[] = {
        {{1000, 100, 4}, 1000, 0, 1000}, {{1000, 100, 4}, 1099, 0, 1000},
        {{1000, 100, 4}, 1100, 1, 1100}, {{1000, 100, 4}, 1249, 2, 1200},
        {{1000, 100, 4}, 1400, 4, 1400}, {{1000, 100, 4}, 1901, 9, 1900},
        {{0, 1, 1}, UINT64_MAX, UINT64_MAX, UINT64_MAX},
        {{0, 2, 1}, UINT64_MAX, UINT64_MAX / 2, UINT64_MAX - 1},
        {{0, UINT64_MAX, 1}, UINT64_MAX - 1, 0, 0},
        {{0, UINT64_MAX, 1}, UINT64_MAX, 1, UINT64_MAX},
        {{UINT64_MAX - 1, 2, 4}, UINT64_MAX, 0, UINT64_MAX - 1},
        {{UINT64_MAX, UINT64_MAX, 1}, UINT64_MAX, 0, UINT64_MAX},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        u64_guard_t out = {11, 77, 19};
        errno = EDOM;
        CHECK(vireo_timer_wheel_elapsed_tick(cases[i].geometry, cases[i].input_time, &out.value) == VIREO_OK);
        CHECK(out.value == cases[i].expected_tick && out.before == 11 && out.after == 19);
        uint64_t boundary = 77;
        CHECK(vireo_timer_wheel_tick_time(cases[i].geometry, out.value, &boundary) == VIREO_OK);
        CHECK(boundary == cases[i].boundary_time && errno == EDOM);
    }
    return 0;
}

static int deadline_goldens(void) {
    mapping_case_t const cases[] = {
        {{1000, 100, 4}, 0, 0, 1000}, {{1000, 100, 4}, 999, 0, 1000},
        {{1000, 100, 4}, 1000, 0, 1000}, {{1000, 100, 4}, 1001, 1, 1100},
        {{1000, 100, 4}, 1100, 1, 1100}, {{1000, 100, 4}, 1250, 3, 1300},
        {{1000, 100, 4}, 1901, 10, 2000},
        {{0, 1, 1}, UINT64_MAX, UINT64_MAX, UINT64_MAX},
        {{0, 2, 4}, UINT64_MAX - 1, UINT64_MAX / 2, UINT64_MAX - 1},
        {{1, 2, 4}, UINT64_MAX, UINT64_MAX / 2, UINT64_MAX},
        {{0, UINT64_MAX, 1}, 1, 1, UINT64_MAX},
        {{0, UINT64_MAX, 1}, UINT64_MAX, 1, UINT64_MAX},
        {{UINT64_MAX, UINT64_MAX, UINT64_MAX}, UINT64_MAX, 0, UINT64_MAX},
        {{UINT64_C(1000000000), UINT64_C(100000000), 512}, UINT64_C(1250000000), 3, UINT64_C(1300000000)},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        u64_guard_t out = {11, 77, 19};
        errno = EILSEQ;
        CHECK(vireo_timer_wheel_deadline_tick(cases[i].geometry, cases[i].input_time, &out.value) == VIREO_OK);
        CHECK(out.value == cases[i].expected_tick && out.before == 11 && out.after == 19);
        uint64_t boundary = 77;
        CHECK(vireo_timer_wheel_tick_time(cases[i].geometry, out.value, &boundary) == VIREO_OK);
        CHECK(boundary == cases[i].boundary_time && errno == EILSEQ);
    }
    return 0;
}

static int exact_boundaries(void) {
    boundary_case_t const cases[] = {
        {{0, 1, 1}, 0, 0}, {{0, 1, 1}, UINT64_MAX, UINT64_MAX},
        {{1000, 100, 4}, 9, 1900}, {{0, UINT64_MAX, 1}, 1, UINT64_MAX},
        {{UINT64_MAX - 1, 1, 1}, 1, UINT64_MAX},
        {{1, 2, 1}, UINT64_MAX / 2, UINT64_MAX},
        {{UINT64_MAX, UINT64_MAX, 1}, 0, UINT64_MAX},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        u64_guard_t out = {11, 77, 19};
        errno = ERANGE;
        CHECK(vireo_timer_wheel_tick_time(cases[i].geometry, cases[i].tick, &out.value) == VIREO_OK);
        CHECK(out.value == cases[i].expected_time && out.before == 11 && out.after == 19 && errno == ERANGE);
    }
    return 0;
}

static int failure_outputs_and_recovery(void) {
    u64_guard_t out = {11, 77, 19};
    unsigned char snapshot[sizeof(out)];
    memcpy(snapshot, &out, sizeof(out));
    errno = EDOM;
    CHECK(vireo_timer_wheel_elapsed_tick((vireo_timer_wheel_geometry_t){1000, 100, 4}, 999,
                                         &out.value) == VIREO_RESULT_RANGE);
    CHECK(memcmp(snapshot, &out, sizeof(out)) == 0 && errno == EDOM);
    CHECK(vireo_timer_wheel_elapsed_tick((vireo_timer_wheel_geometry_t){UINT64_MAX, 1, 1}, 0,
                                         &out.value) == VIREO_RESULT_RANGE);
    CHECK(memcmp(snapshot, &out, sizeof(out)) == 0 && errno == EDOM);
    CHECK(vireo_timer_wheel_tick_time((vireo_timer_wheel_geometry_t){0, 2, 1}, UINT64_MAX,
                                      &out.value) == VIREO_RESULT_OVERFLOW);
    CHECK(memcmp(snapshot, &out, sizeof(out)) == 0 && errno == EDOM);
    CHECK(vireo_timer_wheel_tick_time((vireo_timer_wheel_geometry_t){1, 1, 1}, UINT64_MAX,
                                      &out.value) == VIREO_RESULT_OVERFLOW);
    CHECK(memcmp(snapshot, &out, sizeof(out)) == 0 && errno == EDOM);
    CHECK(vireo_timer_wheel_tick_time((vireo_timer_wheel_geometry_t){UINT64_MAX, 1, 1}, 1,
                                      &out.value) == VIREO_RESULT_OVERFLOW);
    CHECK(memcmp(snapshot, &out, sizeof(out)) == 0 && errno == EDOM);
    CHECK(vireo_timer_wheel_tick_time((vireo_timer_wheel_geometry_t){1000, 100, 4}, 3, &out.value) == VIREO_OK);
    CHECK(out.value == 1300 && out.before == 11 && out.after == 19 && errno == EDOM);
    return 0;
}

static int quantized_boundary_overflow(void) {
    vireo_timer_wheel_geometry_t const geometries[] = {
        {0, 2, 4}, {UINT64_MAX - 1, 2, 4}, {1, UINT64_MAX, 4}, {UINT64_MAX - 10, 6, 4},
    };
    for (size_t i = 0; i < sizeof(geometries) / sizeof(geometries[0]); i++) {
        u64_guard_t out = {11, 77, 19};
        unsigned char snapshot[sizeof(out)];
        memcpy(snapshot, &out, sizeof(out));
        errno = EILSEQ;
        CHECK(vireo_timer_wheel_deadline_tick(geometries[i], UINT64_MAX, &out.value) == VIREO_RESULT_OVERFLOW);
        CHECK(memcmp(snapshot, &out, sizeof(out)) == 0 && errno == EILSEQ);
        CHECK(vireo_timer_wheel_deadline_tick(geometries[i], geometries[i].origin_ns, &out.value) == VIREO_OK);
        CHECK(out.value == 0 && out.before == 11 && out.after == 19 && errno == EILSEQ);
    }
    return 0;
}

static int bucket_values_and_circles(void) {
    bucket_case_t const cases[] = {
        {4, 0, 0}, {4, 1, 1}, {4, 3, 3}, {4, 4, 0}, {4, 9, 1},
        {4, UINT64_MAX, 3}, {1, UINT64_MAX, 0},
        {UINT64_MAX, UINT64_MAX - 1, UINT64_MAX - 1}, {UINT64_MAX, UINT64_MAX, 0},
        {UINT64_MAX, 1, 1}, {512, 513, 1},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        /* 故意选不能还原正刻度的几何，证明单独桶定位不偷偷还原时间。 */
        vireo_timer_wheel_geometry_t const geometry = {UINT64_MAX, UINT64_MAX, cases[i].count};
        u64_guard_t out = {11, 77, 19};
        errno = ERANGE;
        CHECK(vireo_timer_wheel_bucket_index(geometry, cases[i].tick, &out.value) == VIREO_OK);
        CHECK(out.value == cases[i].expected && out.value < cases[i].count);
        CHECK(out.before == 11 && out.after == 19 && errno == ERANGE);
    }
    return 0;
}

static int shape_rejection(void) {
    vireo_timer_wheel_geometry_t const invalid[] = {
        {UINT64_MAX, 0, 1}, {UINT64_MAX, 1, 0}, {UINT64_MAX, 0, 0},
    };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        u64_guard_t out = {11, 77, 19};
        unsigned char snapshot[sizeof(out)];
        memcpy(snapshot, &out, sizeof(out));
        errno = EDOM;
        CHECK(vireo_timer_wheel_elapsed_tick(invalid[i], 0, &out.value) == VIREO_RESULT_INVALID_ARGUMENT);
        CHECK(memcmp(snapshot, &out, sizeof(out)) == 0 && errno == EDOM);
        CHECK(vireo_timer_wheel_deadline_tick(invalid[i], 0, &out.value) == VIREO_RESULT_INVALID_ARGUMENT);
        CHECK(memcmp(snapshot, &out, sizeof(out)) == 0 && errno == EDOM);
        CHECK(vireo_timer_wheel_tick_time(invalid[i], UINT64_MAX, &out.value) == VIREO_RESULT_INVALID_ARGUMENT);
        CHECK(memcmp(snapshot, &out, sizeof(out)) == 0 && errno == EDOM);
        CHECK(vireo_timer_wheel_bucket_index(invalid[i], UINT64_MAX, &out.value) == VIREO_RESULT_INVALID_ARGUMENT);
        CHECK(memcmp(snapshot, &out, sizeof(out)) == 0 && errno == EDOM);
    }
    return 0;
}

static int input_aliases(void) {
    vireo_timer_wheel_geometry_t geometry = {1000, 100, 4};
    errno = EILSEQ;
    CHECK(vireo_timer_wheel_geometry_make(geometry.origin_ns, geometry.tick_ns,
                                          geometry.bucket_count, &geometry) == VIREO_OK);
    CHECK(geometry.origin_ns == 1000 && geometry.tick_ns == 100 && geometry.bucket_count == 4);
    uint64_t value = 1249;
    CHECK(vireo_timer_wheel_elapsed_tick(geometry, value, &value) == VIREO_OK && value == 2);
    value = 1250;
    CHECK(vireo_timer_wheel_deadline_tick(geometry, value, &value) == VIREO_OK && value == 3);
    CHECK(vireo_timer_wheel_tick_time(geometry, value, &value) == VIREO_OK && value == 1300);
    value = 9;
    CHECK(vireo_timer_wheel_bucket_index(geometry, value, &value) == VIREO_OK && value == 1);
    CHECK(vireo_timer_wheel_elapsed_tick(geometry, 1901, &geometry.bucket_count) == VIREO_OK);
    CHECK(geometry.bucket_count == 9 && errno == EILSEQ);
    return 0;
}

static int independent_small_domain(void) {
    size_t points = 0;
    for (uint64_t width = 1; width <= 13; width++) {
        for (uint64_t buckets = 1; buckets <= 7; buckets++) {
            vireo_timer_wheel_geometry_t const geometry = {17, width, buckets};
            for (uint64_t offset = 0; offset <= 130; offset++) {
                uint64_t const now = 17 + offset;
                /* 逐边界累加求期望，不复用生产除余公式或函数。小域和已知上限无溢出。 */
                uint64_t floor_tick = 0;
                uint64_t floor_time = 17;
                while (floor_time + width <= now) {
                    floor_time += width;
                    floor_tick++;
                }
                uint64_t ceil_tick = floor_tick;
                uint64_t ceil_time = floor_time;
                if (ceil_time < now) {
                    ceil_time += width;
                    ceil_tick++;
                }
                uint64_t expected_bucket = 0;
                for (uint64_t t = 0; t < ceil_tick; t++) {
                    expected_bucket++;
                    if (expected_bucket == buckets) {
                        expected_bucket = 0;
                    }
                }
                errno = ERANGE;
                uint64_t actual_floor = UINT64_MAX;
                uint64_t actual_ceil = UINT64_MAX;
                uint64_t actual_time = UINT64_MAX;
                uint64_t actual_bucket = UINT64_MAX;
                CHECK(vireo_timer_wheel_elapsed_tick(geometry, now, &actual_floor) == VIREO_OK);
                CHECK(vireo_timer_wheel_deadline_tick(geometry, now, &actual_ceil) == VIREO_OK);
                CHECK(vireo_timer_wheel_tick_time(geometry, actual_ceil, &actual_time) == VIREO_OK);
                CHECK(vireo_timer_wheel_bucket_index(geometry, actual_ceil, &actual_bucket) == VIREO_OK);
                CHECK(actual_floor == floor_tick && actual_ceil == ceil_tick && actual_time == ceil_time);
                CHECK(actual_bucket == expected_bucket && actual_bucket < buckets);
                CHECK(floor_time <= now && actual_time >= now && actual_time - now < width);
                CHECK(errno == ERANGE);
                points++;
            }
        }
    }
    CHECK(points == 11921);
    return 0;
}

int main(void) {
    int failures = 0;
    failures += parameter_guards();
    failures += geometry_values();
    failures += elapsed_goldens();
    failures += deadline_goldens();
    failures += exact_boundaries();
    failures += failure_outputs_and_recovery();
    failures += quantized_boundary_overflow();
    failures += bucket_values_and_circles();
    failures += shape_rejection();
    failures += input_aliases();
    failures += independent_small_domain();
    printf("wheel time mapping: 11 groups, %d failures; independent 11921 points; no wheel allocation or advance\n", failures);
    return failures == 0 ? 0 : 1;
}
