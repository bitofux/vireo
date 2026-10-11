/*
 * PROJECT : VIREO
 * FILE    : test_task_route.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-11
 * BRIEF   : 路由形态、完整数值、失败保持及纯值边界验证
 */

#include <vireo/thread/task.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #condition); \
        return 1; \
    } \
} while (0)

static int null_outputs(void) {
    vireo_task_route_t const empty = {0};
    vireo_task_route_t const normal = {1, 0, 1, 1};
    vireo_task_route_t const malformed = {0, SIZE_MAX, 0, 0};
    errno = EDOM;
    CHECK(vireo_task_route_make(1, 0, 1, 1, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_task_route_make(0, SIZE_MAX, 0, 0, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_task_route_is_empty(empty, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_task_route_is_empty(normal, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_task_route_is_empty(malformed, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_task_route_equal(empty, normal, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_task_route_equal(malformed, malformed, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(errno == EDOM);
    return 0;
}

static int make_golden_values(void) {
    vireo_task_route_t const cases[] = {
        {1, 0, 1, 1}, {7, 2, 3, 11},
        {UINT64_C(4294967296), 0, UINT64_C(9223372036854775808), UINT32_C(2147483648)},
        {UINT64_MAX, 0, 1, 1}, {1, SIZE_MAX, 1, 1},
        {1, 0, UINT64_MAX, 1}, {1, 0, 1, UINT32_MAX},
        {UINT64_MAX, SIZE_MAX, UINT64_MAX, UINT32_MAX}
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        vireo_task_route_t guarded[3] = {{9, 8, 7, 6}, {0}, {5, 4, 3, 2}};
        unsigned char before[sizeof(guarded[0])];
        unsigned char after[sizeof(guarded[2])];
        memcpy(before, &guarded[0], sizeof(before));
        memcpy(after, &guarded[2], sizeof(after));
        errno = EILSEQ;
        CHECK(vireo_task_route_make(cases[i].client_owner_id, cases[i].client_slot_index,
                                    cases[i].client_generation, cases[i].request_sequence,
                                    &guarded[1]) == VIREO_OK);
        CHECK(guarded[1].client_owner_id == cases[i].client_owner_id);
        CHECK(guarded[1].client_slot_index == cases[i].client_slot_index);
        CHECK(guarded[1].client_generation == cases[i].client_generation);
        CHECK(guarded[1].request_sequence == cases[i].request_sequence);
        CHECK(memcmp(before, &guarded[0], sizeof(before)) == 0);
        CHECK(memcmp(after, &guarded[2], sizeof(after)) == 0);
        bool empty = true;
        CHECK(vireo_task_route_is_empty(guarded[1], &empty) == VIREO_OK && !empty);
        CHECK(errno == EILSEQ);
    }
    return 0;
}

static int all_zero_shapes(void) {
    /* 位序 owner/slot/generation/sequence，期望手写：0 空，13/15 正常。 */
    bool const valid[16] = {
        true, false, false, false, false, false, false, false,
        false, false, false, false, false, true, false, true
    };
    vireo_task_route_t const normal = {1, 0, 1, 1};
    for (unsigned int mask = 0; mask < 16; mask++) {
        vireo_task_route_t const route = {
            (mask & 1U) != 0 ? UINT64_MAX : 0,
            (mask & 2U) != 0 ? SIZE_MAX : 0,
            (mask & 4U) != 0 ? UINT64_MAX : 0,
            (mask & 8U) != 0 ? UINT32_MAX : 0
        };
        unsigned char input_before[sizeof(route)];
        memcpy(input_before, &route, sizeof(route));
        for (unsigned int initial = 0; initial < 2; initial++) {
            bool out[3] = {true, initial != 0, false};
            unsigned char snapshot[sizeof(out)];
            memcpy(snapshot, out, sizeof(out));
            errno = EDOM;
            vireo_result_t const result = vireo_task_route_is_empty(route, &out[1]);
            CHECK(errno == EDOM);
            if (valid[mask]) {
                CHECK(result == VIREO_OK && out[1] == (mask == 0));
                CHECK(out[0] && !out[2]);
            } else {
                CHECK(result == VIREO_RESULT_INVALID_ARGUMENT);
                CHECK(memcmp(snapshot, out, sizeof(out)) == 0);
                CHECK(vireo_task_route_equal(route, normal, &out[1]) == VIREO_RESULT_INVALID_ARGUMENT);
                CHECK(vireo_task_route_equal(normal, route, &out[1]) == VIREO_RESULT_INVALID_ARGUMENT);
                CHECK(vireo_task_route_equal(route, route, &out[1]) == VIREO_RESULT_INVALID_ARGUMENT);
                CHECK(memcmp(snapshot, out, sizeof(out)) == 0 && errno == EDOM);
            }
        }
        CHECK(memcmp(input_before, &route, sizeof(route)) == 0);
    }
    return 0;
}

static int make_failure_preserves_bytes(void) {
    /* 所有三非零字段的零值组合，slot=0/SIZE_MAX 各覆盖一次。 */
    for (unsigned int mask = 0; mask < 7; mask++) {
        for (unsigned int high_slot = 0; high_slot < 2; high_slot++) {
            vireo_task_route_t guarded[3];
            memset(guarded, 0xA5, sizeof(guarded));
            guarded[1] = (vireo_task_route_t){7, 5, 3, 11};
            unsigned char snapshot[sizeof(guarded)];
            memcpy(snapshot, guarded, sizeof(guarded));
            errno = ERANGE;
            CHECK(vireo_task_route_make((mask & 1U) != 0 ? UINT64_MAX : 0,
                                        high_slot != 0 ? SIZE_MAX : 0,
                                        (mask & 2U) != 0 ? UINT64_MAX : 0,
                                        (mask & 4U) != 0 ? UINT32_MAX : 0,
                                        &guarded[1]) == VIREO_RESULT_INVALID_ARGUMENT);
            CHECK(memcmp(snapshot, guarded, sizeof(guarded)) == 0 && errno == ERANGE);
            CHECK(vireo_task_route_make(7, 0, 3, 11, &guarded[1]) == VIREO_OK);
            CHECK(guarded[1].client_slot_index == 0 && errno == ERANGE);
        }
    }
    return 0;
}

static int equality_all_fields(void) {
    vireo_task_route_t const base = {7, 2, 3, 11};
    vireo_task_route_t const empty = {0};
    vireo_task_route_t const cases[] = {
        {7, 2, 3, 11}, {8, 2, 3, 11}, {7, 0, 3, 11},
        {7, 2, 4, 11}, {7, 2, 3, 12},
        {UINT64_MAX, 2, 3, 11}, {7, SIZE_MAX, 3, 11},
        {7, 2, UINT64_MAX, 11}, {7, 2, 3, UINT32_MAX}
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        bool out[3] = {true, i != 0, false};
        errno = EILSEQ;
        CHECK(vireo_task_route_equal(base, cases[i], &out[1]) == VIREO_OK);
        CHECK(out[1] == (i == 0));
        CHECK(vireo_task_route_equal(cases[i], base, &out[1]) == VIREO_OK);
        CHECK(out[1] == (i == 0));
        CHECK(vireo_task_route_equal(cases[i], cases[i], &out[1]) == VIREO_OK && out[1]);
        CHECK(out[0] && !out[2] && errno == EILSEQ);
    }
    bool value = false;
    errno = EDOM;
    CHECK(vireo_task_route_equal(empty, empty, &value) == VIREO_OK && value);
    CHECK(vireo_task_route_equal(empty, base, &value) == VIREO_OK && !value);
    CHECK(vireo_task_route_equal(base, empty, &value) == VIREO_OK && !value);
    CHECK(errno == EDOM);
    return 0;
}

static int logical_fields_ignore_padding(void) {
    vireo_task_route_t left;
    vireo_task_route_t right;
    memset(&left, 0xA5, sizeof(left));
    memset(&right, 0x5A, sizeof(right));
    left.client_owner_id = right.client_owner_id = UINT64_MAX;
    left.client_slot_index = right.client_slot_index = SIZE_MAX;
    left.client_generation = right.client_generation = UINT64_MAX;
    left.request_sequence = right.request_sequence = UINT32_MAX;
    bool equal = false;
    errno = EILSEQ;
    CHECK(vireo_task_route_equal(left, right, &equal) == VIREO_OK && equal);
    left.client_owner_id = right.client_owner_id = 0;
    left.client_slot_index = right.client_slot_index = 0;
    left.client_generation = right.client_generation = 0;
    left.request_sequence = right.request_sequence = 0;
    CHECK(vireo_task_route_is_empty(left, &equal) == VIREO_OK && equal);
    CHECK(vireo_task_route_is_empty(right, &equal) == VIREO_OK && equal);
    CHECK(vireo_task_route_equal(left, right, &equal) == VIREO_OK && equal);
    CHECK(errno == EILSEQ);
    /* 不要求该平台存在 padding；不同预填充验证仅逻辑字段决定关系。 */
    return 0;
}

static int by_value_writeback(void) {
    vireo_task_route_t route = {UINT64_MAX, SIZE_MAX, UINT64_MAX, UINT32_MAX};
    errno = EDOM;
    CHECK(vireo_task_route_make(route.client_owner_id, route.client_slot_index,
                                route.client_generation, route.request_sequence,
                                &route) == VIREO_OK);
    CHECK(route.client_owner_id == UINT64_MAX && route.client_slot_index == SIZE_MAX);
    CHECK(route.client_generation == UINT64_MAX && route.request_sequence == UINT32_MAX);
    CHECK(errno == EDOM);
    return 0;
}

static int numeric_copy_is_not_liveness(void) {
    vireo_task_route_t const original = {7, 0, 3, 11};
    vireo_task_route_t const copied = original;
    vireo_task_route_t const reused = {7, 0, 4, 11};
    bool equal = false;
    errno = EDOM;
    CHECK(vireo_task_route_equal(original, copied, &equal) == VIREO_OK && equal);
    CHECK(vireo_task_route_equal(copied, reused, &equal) == VIREO_OK && !equal);
    CHECK(vireo_task_route_is_empty(copied, &equal) == VIREO_OK && !equal);
    CHECK(errno == EDOM);
    /* 仅数值故事：没有创建/归还真实客户，不冒充网络复用验证。 */
    return 0;
}

int main(void) {
    CHECK(null_outputs() == 0);
    CHECK(make_golden_values() == 0);
    CHECK(all_zero_shapes() == 0);
    CHECK(make_failure_preserves_bytes() == 0);
    CHECK(equality_all_fields() == 0);
    CHECK(logical_fields_ignore_padding() == 0);
    CHECK(by_value_writeback() == 0);
    CHECK(numeric_copy_is_not_liveness() == 0);
    puts("task route: 8 groups passed");
    return 0;
}
