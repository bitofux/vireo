/*
 * PROJECT : VIREO
 * FILE    : test_handle_values.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-08
 * BRIEF   : 此模块负责：
 * -- 验证三字段身份、空值和畸形拒绝
 * -- 验证代次边界、不回绕及失败输出保持
 * -- 区分数值复制示意与真实 owner 登记
 */

#include <vireo/timer/handle.h>

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

_Static_assert(sizeof(((vireo_timer_handle_t *)0)->owner_id) == sizeof(uint64_t),
               "owner value width");
_Static_assert(sizeof(((vireo_timer_handle_t *)0)->slot_index) == sizeof(size_t),
               "slot value width");
_Static_assert(sizeof(((vireo_timer_handle_t *)0)->generation) == sizeof(uint64_t),
               "generation value width");

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #condition); \
        return 1; \
    } \
} while (0)

/** @brief 句柄输出与无时间单位的相邻保护值；测试独占。 */
typedef struct handle_guard {
    uint64_t before; /**< 固定 11，检查前邻位未被写。 */
    vireo_timer_handle_t value; /**< 被测三字段输出，失败须保整个对象字节。 */
    uint64_t after; /**< 固定 19，检查后邻位未被写。 */
} handle_guard_t;

/** @brief bool 输出保护；value 不代表 timer 活跃状态。 */
typedef struct bool_guard {
    int before; /**< 固定 11，无身份或时间含义。 */
    bool value; /**< 空值或相等查询输出，失败保持入口值。 */
    int after; /**< 固定 19，无身份或时间含义。 */
} bool_guard_t;

/** @brief 代次数值输出保护，不是实际 owner counter。 */
typedef struct generation_guard {
    uint64_t before; /**< 固定 11，检查前邻位未变。 */
    uint64_t value; /**< 下一代输出或失败保持值 77。 */
    uint64_t after; /**< 固定 19，检查后邻位未变。 */
} generation_guard_t;

/** @brief 独立手写的身份相等期望，不由生产函数生成。 */
typedef struct equality_case {
    vireo_timer_handle_t left; /**< 左侧空或正常非空的数值句柄。 */
    vireo_timer_handle_t right; /**< 右侧句柄，分别改变 owner、槽或代次。 */
    bool expected; /**< 三字段数值关系，无资源权限语义。 */
} equality_case_t;

static int parameter_guards(void) {
    vireo_timer_handle_t const empty = {0};
    vireo_timer_handle_t const normal = {1, 0, 1};
    vireo_timer_handle_t const malformed = {0, 0, 1};
    errno = EDOM;
    CHECK(vireo_timer_handle_make(1, 0, 1, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_timer_handle_make(0, SIZE_MAX, 0, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(errno == EDOM);
    CHECK(vireo_timer_handle_is_empty(empty, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_timer_handle_is_empty(normal, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_timer_handle_is_empty(malformed, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_timer_handle_equal(empty, normal, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_timer_handle_equal(malformed, malformed, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(errno == EDOM);
    CHECK(vireo_timer_handle_next_generation(0, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    /* 必需输出拒绝优先，不能被同时存在的表示耗尽覆盖。 */
    CHECK(vireo_timer_handle_next_generation(UINT64_MAX, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(errno == EDOM);
    return 0;
}

static int make_golden_values(void) {
    vireo_timer_handle_t const cases[] = {
        {1, 0, 1}, {1, 1, 1}, {10, 3, 8},
        {UINT64_C(4294967296), 3, UINT64_C(4294967296)},
        {UINT64_MAX, 0, 1}, {1, SIZE_MAX, 1},
        {1, 0, UINT64_MAX}, {UINT64_MAX, SIZE_MAX, UINT64_MAX},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        handle_guard_t out = {11, {7, 5, 9}, 19};
        errno = EILSEQ;
        CHECK(vireo_timer_handle_make(cases[i].owner_id, cases[i].slot_index,
                                      cases[i].generation, &out.value) == VIREO_OK);
        CHECK(errno == EILSEQ);
        CHECK(out.value.owner_id == cases[i].owner_id);
        CHECK(out.value.slot_index == cases[i].slot_index);
        CHECK(out.value.generation == cases[i].generation);
        CHECK(out.before == 11 && out.after == 19);
        bool empty = true;
        CHECK(vireo_timer_handle_is_empty(out.value, &empty) == VIREO_OK && !empty);
        CHECK(errno == EILSEQ);
    }
    return 0;
}

static int make_failure_preserves_all_bytes(void) {
    vireo_timer_handle_t const cases[] = {
        {0, 0, 0}, {0, 0, 1}, {1, 0, 0},
        {0, SIZE_MAX, UINT64_MAX}, {UINT64_MAX, SIZE_MAX, 0},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        handle_guard_t out = {11, {4, 5, 6}, 19};
        unsigned char snapshot[sizeof(out)];
        memcpy(snapshot, &out, sizeof(out));
        errno = ERANGE;
        CHECK(vireo_timer_handle_make(cases[i].owner_id, cases[i].slot_index,
                                      cases[i].generation, &out.value) == VIREO_RESULT_INVALID_ARGUMENT);
        CHECK(errno == ERANGE);
        CHECK(memcmp(snapshot, &out, sizeof(out)) == 0);
        CHECK(vireo_timer_handle_make(10, 3, 8, &out.value) == VIREO_OK);
        CHECK(out.value.owner_id == 10 && out.value.slot_index == 3 && out.value.generation == 8);
        CHECK(errno == ERANGE);
    }
    return 0;
}

static int empty_value_queries(void) {
    vireo_timer_handle_t const empty = {0};
    vireo_timer_handle_t const normal = {UINT64_MAX, SIZE_MAX, UINT64_MAX};
    bool_guard_t out = {11, false, 19};
    errno = EDOM;
    CHECK(vireo_timer_handle_is_empty(empty, &out.value) == VIREO_OK && out.value);
    CHECK(vireo_timer_handle_is_empty(normal, &out.value) == VIREO_OK && !out.value);
    CHECK(vireo_timer_handle_equal(empty, empty, &out.value) == VIREO_OK && out.value);
    CHECK(vireo_timer_handle_equal(empty, normal, &out.value) == VIREO_OK && !out.value);
    CHECK(vireo_timer_handle_equal(normal, empty, &out.value) == VIREO_OK && !out.value);
    CHECK(out.before == 11 && out.after == 19 && errno == EDOM);
    /* 空空相等只是数值关系；本测试没有登记或取得 timer。 */
    return 0;
}

static int malformed_queries(void) {
    vireo_timer_handle_t const cases[] = {
        {0, 0, 1}, {1, 0, 0}, {0, 1, 0}, {0, SIZE_MAX, 0},
        {0, SIZE_MAX, UINT64_MAX}, {UINT64_MAX, SIZE_MAX, 0}, {0, 1, 1},
    };
    vireo_timer_handle_t const empty = {0};
    vireo_timer_handle_t const normal = {10, 3, 8};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        for (int initial = 0; initial < 2; initial++) {
            bool_guard_t out = {11, initial != 0, 19};
            unsigned char snapshot[sizeof(out)];
            memcpy(snapshot, &out, sizeof(out));
            errno = EILSEQ;
            CHECK(vireo_timer_handle_is_empty(cases[i], &out.value) == VIREO_RESULT_INVALID_ARGUMENT);
            CHECK(errno == EILSEQ && memcmp(snapshot, &out, sizeof(out)) == 0);
            CHECK(vireo_timer_handle_equal(cases[i], normal, &out.value) == VIREO_RESULT_INVALID_ARGUMENT);
            CHECK(vireo_timer_handle_equal(normal, cases[i], &out.value) == VIREO_RESULT_INVALID_ARGUMENT);
            CHECK(vireo_timer_handle_equal(empty, cases[i], &out.value) == VIREO_RESULT_INVALID_ARGUMENT);
            CHECK(vireo_timer_handle_equal(cases[i], empty, &out.value) == VIREO_RESULT_INVALID_ARGUMENT);
            CHECK(vireo_timer_handle_equal(cases[i], cases[i], &out.value) == VIREO_RESULT_INVALID_ARGUMENT);
            CHECK(errno == EILSEQ && memcmp(snapshot, &out, sizeof(out)) == 0);
        }
    }
    return 0;
}

static int equality_identity_fields(void) {
    equality_case_t const cases[] = {
        {{10, 3, 8}, {10, 3, 8}, true},
        {{10, 3, 8}, {11, 3, 8}, false},
        {{10, 3, 8}, {10, 4, 8}, false},
        {{10, 3, 8}, {10, 3, 9}, false},
        {{1, 0, 1}, {1, 0, 1}, true},
        {{1, 0, 1}, {1, SIZE_MAX, 1}, false},
        {{1, 0, 1}, {UINT64_C(4294967297), 0, 1}, false},
        {{1, 0, 1}, {1, 0, UINT64_C(4294967297)}, false},
#if SIZE_MAX > UINT32_MAX
        {{1, 1, 1}, {1, (size_t)UINT32_MAX + (size_t)2, 1}, false},
#endif
        {{UINT64_MAX, SIZE_MAX, UINT64_MAX}, {UINT64_MAX, SIZE_MAX, UINT64_MAX}, true},
        {{UINT64_MAX, SIZE_MAX, UINT64_MAX}, {UINT64_MAX, SIZE_MAX, UINT64_MAX - 1}, false},
        {{UINT64_MAX, SIZE_MAX, UINT64_MAX}, {UINT64_MAX - 1, SIZE_MAX, UINT64_MAX}, false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        bool_guard_t out = {11, !cases[i].expected, 19};
        errno = EDOM;
        CHECK(vireo_timer_handle_equal(cases[i].left, cases[i].right, &out.value) == VIREO_OK);
        CHECK(out.value == cases[i].expected && errno == EDOM);
        out.value = !cases[i].expected;
        CHECK(vireo_timer_handle_equal(cases[i].right, cases[i].left, &out.value) == VIREO_OK);
        CHECK(out.value == cases[i].expected && errno == EDOM);
        CHECK(out.before == 11 && out.after == 19);
    }
    return 0;
}

static int generation_boundaries(void) {
    struct { uint64_t last; uint64_t expected; } const cases[] = {
        {0, 1}, {1, 2}, {7, 8},
        {UINT64_C(4294967295), UINT64_C(4294967296)},
        {UINT64_C(4294967296), UINT64_C(4294967297)},
        {UINT64_MAX - 2, UINT64_MAX - 1}, {UINT64_MAX - 1, UINT64_MAX},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        generation_guard_t out = {11, 77, 19};
        errno = EILSEQ;
        CHECK(vireo_timer_handle_next_generation(cases[i].last, &out.value) == VIREO_OK);
        CHECK(out.value == cases[i].expected && out.before == 11 && out.after == 19);
        CHECK(errno == EILSEQ);
    }
    return 0;
}

static int generation_failure_recovery(void) {
    generation_guard_t out = {11, 77, 19};
    unsigned char snapshot[sizeof(out)];
    memcpy(snapshot, &out, sizeof(out));
    errno = ERANGE;
    CHECK(vireo_timer_handle_next_generation(UINT64_MAX, &out.value) == VIREO_RESULT_OVERFLOW);
    CHECK(errno == ERANGE && memcmp(snapshot, &out, sizeof(out)) == 0);
    CHECK(vireo_timer_handle_next_generation(0, &out.value) == VIREO_OK);
    CHECK(out.value == 1 && out.before == 11 && out.after == 19 && errno == ERANGE);

    uint64_t last = UINT64_MAX - 1;
    CHECK(vireo_timer_handle_next_generation(last, &last) == VIREO_OK && last == UINT64_MAX);
    CHECK(vireo_timer_handle_next_generation(last, &last) == VIREO_RESULT_OVERFLOW);
    CHECK(last == UINT64_MAX && errno == ERANGE);
    return 0;
}

static int value_copy_and_composition(void) {
    uint64_t last = 7;
    vireo_timer_handle_t original = {0};
    errno = EDOM;
    CHECK(vireo_timer_handle_next_generation(last, &last) == VIREO_OK && last == 8);
    CHECK(vireo_timer_handle_make(10, 3, last, &original) == VIREO_OK);
    vireo_timer_handle_t const saved = original;
    CHECK(vireo_timer_handle_next_generation(last, &last) == VIREO_OK && last == 9);
    /* 只是数值复用示意，未创建 owner、释放槽位或注册 timer。 */
    CHECK(vireo_timer_handle_make(original.owner_id, original.slot_index, last, &original) == VIREO_OK);
    bool equal = true;
    CHECK(vireo_timer_handle_equal(saved, original, &equal) == VIREO_OK && !equal);
    bool empty = true;
    CHECK(vireo_timer_handle_is_empty(saved, &empty) == VIREO_OK && !empty);
    CHECK(saved.owner_id == 10 && saved.slot_index == 3 && saved.generation == 8);

    vireo_timer_handle_t different_owner = {0};
    CHECK(vireo_timer_handle_make(11, 3, 9, &different_owner) == VIREO_OK);
    CHECK(vireo_timer_handle_equal(original, different_owner, &equal) == VIREO_OK && !equal);
    unsigned char snapshot[sizeof(original)];
    memcpy(snapshot, &original, sizeof(original));
    CHECK(vireo_timer_handle_make(original.owner_id, original.slot_index, 0,
                                  &original) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(errno == EDOM && memcmp(snapshot, &original, sizeof(original)) == 0);
    return 0;
}

int main(void) {
    int failures = 0;
    failures += parameter_guards();
    failures += make_golden_values();
    failures += make_failure_preserves_all_bytes();
    failures += empty_value_queries();
    failures += malformed_queries();
    failures += equality_identity_fields();
    failures += generation_boundaries();
    failures += generation_failure_recovery();
    failures += value_copy_and_composition();
    printf("timer handle values: 9 groups, %d failures; size_t bytes=%zu; no registry\n",
           failures, sizeof(size_t));
    return failures == 0 ? 0 : 1;
}
