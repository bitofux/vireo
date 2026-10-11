/*
 * PROJECT : VIREO
 * FILE    : test_task_metadata.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-11
 * BRIEF   : 元数据完整形态、请求实例、有限期限与失败保持验证
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
    vireo_task_metadata_t const normal = {{7, 0, 3, 11}, 42, 1, 100};
    vireo_task_metadata_t const invalid = {0};
    errno = EDOM;
    CHECK(vireo_task_metadata_make(normal.route, 42, 1, 100, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_task_metadata_make(invalid.route, 0, 0, UINT64_MAX, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_task_metadata_deadline_expired(normal, 100, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_task_metadata_deadline_expired(invalid, 0, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_task_metadata_same_request(normal, normal, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_task_metadata_same_request(invalid, invalid, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(errno == EDOM);
    return 0;
}

static int make_golden_values(void) {
    vireo_task_metadata_t const cases[] = {
        {{1, 0, 1, 1}, 1, 1, 0},
        {{7, 2, 3, 11}, 42, 2, 100},
        {{UINT64_C(4294967296), SIZE_MAX, UINT64_C(9223372036854775808), UINT32_MAX},
         UINT64_C(9223372036854775808), UINT32_C(2147483648), UINT64_MAX},
        {{UINT64_MAX, SIZE_MAX, UINT64_MAX, UINT32_MAX}, UINT64_MAX, UINT32_MAX, UINT64_MAX}
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        vireo_task_metadata_t out[3] = {
            {{9, 8, 7, 6}, 5, 4, 3}, {{0}, 0, 0, 0}, {{1, 2, 3, 4}, 5, 6, 7}
        };
        unsigned char before[sizeof(out[0])];
        unsigned char after[sizeof(out[2])];
        memcpy(before, &out[0], sizeof(before));
        memcpy(after, &out[2], sizeof(after));
        errno = EILSEQ;
        CHECK(vireo_task_metadata_make(cases[i].route, cases[i].request_instance_id,
                                       cases[i].operation, cases[i].deadline_ns, &out[1]) == VIREO_OK);
        CHECK(out[1].route.client_owner_id == cases[i].route.client_owner_id);
        CHECK(out[1].route.client_slot_index == cases[i].route.client_slot_index);
        CHECK(out[1].route.client_generation == cases[i].route.client_generation);
        CHECK(out[1].route.request_sequence == cases[i].route.request_sequence);
        CHECK(out[1].request_instance_id == cases[i].request_instance_id);
        CHECK(out[1].operation == cases[i].operation && out[1].deadline_ns == cases[i].deadline_ns);
        CHECK(memcmp(before, &out[0], sizeof(before)) == 0);
        CHECK(memcmp(after, &out[2], sizeof(after)) == 0 && errno == EILSEQ);
    }
    return 0;
}

static int invalid_shape_matrix(void) {
    /* route 位序 owner/slot/generation/sequence；metadata 只允许正常非空13/15。 */
    bool const normal_route[16] = {
        false, false, false, false, false, false, false, false,
        false, false, false, false, false, true, false, true
    };
    vireo_task_metadata_t const normal = {{7, 0, 3, 11}, 42, 1, 100};
    for (unsigned int mask = 0; mask < 16; mask++) {
        for (unsigned int tags = 0; tags < 4; tags++) {
            vireo_task_metadata_t const input = {
                {(mask & 1U) != 0 ? UINT64_MAX : 0, (mask & 2U) != 0 ? SIZE_MAX : 0,
                 (mask & 4U) != 0 ? UINT64_MAX : 0, (mask & 8U) != 0 ? UINT32_MAX : 0},
                (tags & 1U) != 0 ? UINT64_MAX : 0,
                (tags & 2U) != 0 ? UINT32_MAX : 0, 0
            };
            bool const valid = normal_route[mask] && tags == 3;
            unsigned char input_snapshot[sizeof(input)];
            memcpy(input_snapshot, &input, sizeof(input));
            vireo_task_metadata_t out[3];
            memset(out, 0xA5, sizeof(out));
            unsigned char snapshot[sizeof(out)];
            memcpy(snapshot, out, sizeof(out));
            errno = ERANGE;
            vireo_result_t const result = vireo_task_metadata_make(input.route, input.request_instance_id,
                                                                   input.operation, input.deadline_ns,
                                                                   &out[1]);
            CHECK(errno == ERANGE);
            if (valid) {
                CHECK(result == VIREO_OK);
                CHECK(out[1].request_instance_id == UINT64_MAX && out[1].operation == UINT32_MAX);
                CHECK(out[1].deadline_ns == 0);
            } else {
                CHECK(result == VIREO_RESULT_INVALID_ARGUMENT);
                CHECK(memcmp(snapshot, out, sizeof(out)) == 0);
                for (unsigned int initial = 0; initial < 2; initial++) {
                    bool value[3] = {true, initial != 0, false};
                    unsigned char saved[sizeof(value)];
                    memcpy(saved, value, sizeof(value));
                    CHECK(vireo_task_metadata_deadline_expired(input, UINT64_MAX, &value[1]) ==
                          VIREO_RESULT_INVALID_ARGUMENT);
                    CHECK(vireo_task_metadata_same_request(input, normal, &value[1]) ==
                          VIREO_RESULT_INVALID_ARGUMENT);
                    CHECK(vireo_task_metadata_same_request(normal, input, &value[1]) ==
                          VIREO_RESULT_INVALID_ARGUMENT);
                    CHECK(vireo_task_metadata_same_request(input, input, &value[1]) ==
                          VIREO_RESULT_INVALID_ARGUMENT);
                    CHECK(memcmp(saved, value, sizeof(value)) == 0 && errno == ERANGE);
                }
            }
            CHECK(memcmp(input_snapshot, &input, sizeof(input)) == 0);
        }
    }
    return 0;
}

static int finite_deadline_table(void) {
    /* 每行显式now/deadline，期望手写；不从被测比较生成。 */
    uint64_t const times[][2] = {
        {0, 0}, {0, 1}, {1, 0}, {99, 100}, {100, 100}, {101, 100},
        {UINT64_MAX - UINT64_C(1), UINT64_MAX}, {UINT64_MAX, UINT64_MAX},
        {UINT64_MAX, 0}, {0, UINT64_MAX},
        {100, UINT64_C(4294967396)}, {UINT64_C(4294967396), 100}
    };
    bool const expected[] = {true, false, true, false, true, true, false, true, true, false, false, true};
    CHECK(sizeof(times) / sizeof(times[0]) == sizeof(expected) / sizeof(expected[0]));
    for (size_t i = 0; i < sizeof(times) / sizeof(times[0]); i++) {
        vireo_task_metadata_t const metadata = {{7, 0, 3, 11}, 42, 1, times[i][1]};
        unsigned char snapshot[sizeof(metadata)];
        memcpy(snapshot, &metadata, sizeof(metadata));
        bool value[3] = {true, !expected[i], false};
        errno = EILSEQ;
        CHECK(vireo_task_metadata_deadline_expired(metadata, times[i][0], &value[1]) == VIREO_OK);
        CHECK(value[1] == expected[i] && value[0] && !value[2] && errno == EILSEQ);
        CHECK(memcmp(snapshot, &metadata, sizeof(metadata)) == 0);
    }
    return 0;
}

static int same_request_table(void) {
    vireo_task_metadata_t const base = {{7, 2, 3, 11}, 42, 1, 100};
    vireo_task_metadata_t const cases[] = {
        {{7, 2, 3, 11}, 42, 1, 100}, {{8, 2, 3, 11}, 42, 1, 100},
        {{7, SIZE_MAX, 3, 11}, 42, 1, 100}, {{7, 2, 4, 11}, 42, 1, 100},
        {{7, 2, 3, 12}, 42, 1, 100}, {{7, 2, 3, 11}, 43, 1, 100},
        {{7, 2, 3, 11}, UINT64_MAX, 1, 100}, {{7, 2, 3, 11}, 42, UINT32_MAX, 100},
        {{7, 2, 3, 11}, 42, 1, 0}, {{7, 2, 3, 11}, 42, 2, UINT64_MAX},
        {{7, 2, 3, 11}, UINT64_C(4294967338), 1, 100}
    };
    bool const expected[] = {true, false, false, false, false, false, false, true, true, true, false};
    CHECK(sizeof(cases) / sizeof(cases[0]) == sizeof(expected) / sizeof(expected[0]));
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        bool value[3] = {true, !expected[i], false};
        errno = EDOM;
        CHECK(vireo_task_metadata_same_request(base, cases[i], &value[1]) == VIREO_OK);
        CHECK(value[1] == expected[i]);
        CHECK(vireo_task_metadata_same_request(cases[i], base, &value[1]) == VIREO_OK);
        CHECK(value[1] == expected[i]);
        CHECK(vireo_task_metadata_same_request(cases[i], cases[i], &value[1]) == VIREO_OK && value[1]);
        CHECK(value[0] && !value[2] && errno == EDOM);
    }
    return 0;
}

static int logical_fields_ignore_padding(void) {
    vireo_task_metadata_t left;
    vireo_task_metadata_t right;
    memset(&left, 0xA5, sizeof(left));
    memset(&right, 0x5A, sizeof(right));
    left.route.client_owner_id = right.route.client_owner_id = UINT64_MAX;
    left.route.client_slot_index = right.route.client_slot_index = SIZE_MAX;
    left.route.client_generation = right.route.client_generation = UINT64_MAX;
    left.route.request_sequence = right.route.request_sequence = UINT32_MAX;
    left.request_instance_id = right.request_instance_id = UINT64_MAX;
    left.operation = right.operation = 1;
    left.deadline_ns = right.deadline_ns = UINT64_MAX;
    bool same = false;
    errno = EILSEQ;
    CHECK(vireo_task_metadata_same_request(left, right, &same) == VIREO_OK && same);
    CHECK(vireo_task_metadata_deadline_expired(left, UINT64_MAX, &same) == VIREO_OK && same);
    CHECK(errno == EILSEQ);
    /* 不假设平台一定存在padding，仅逻辑字段参与身份比较。 */
    return 0;
}

static int by_value_writeback(void) {
    vireo_task_metadata_t value = {{UINT64_MAX, SIZE_MAX, UINT64_MAX, UINT32_MAX},
                                  UINT64_MAX, UINT32_MAX, UINT64_MAX};
    errno = EDOM;
    CHECK(vireo_task_metadata_make(value.route, value.request_instance_id, value.operation,
                                   value.deadline_ns, &value) == VIREO_OK);
    CHECK(value.route.client_owner_id == UINT64_MAX && value.route.client_slot_index == SIZE_MAX);
    CHECK(value.route.client_generation == UINT64_MAX && value.route.request_sequence == UINT32_MAX);
    CHECK(value.request_instance_id == UINT64_MAX && value.operation == UINT32_MAX);
    CHECK(value.deadline_ns == UINT64_MAX && errno == EDOM);
    return 0;
}

static int request_instance_story(void) {
    vireo_task_metadata_t const first = {{7, 0, 3, 11}, 42, 1, 100};
    vireo_task_metadata_t const next = {{7, 0, 3, 11}, 43, 1, 200};
    vireo_task_metadata_t const copied = first;
    bool value = false;
    errno = EDOM;
    CHECK(vireo_task_metadata_same_request(first, copied, &value) == VIREO_OK && value);
    CHECK(vireo_task_metadata_same_request(first, next, &value) == VIREO_OK && !value);
    CHECK(vireo_task_metadata_deadline_expired(copied, 100, &value) == VIREO_OK && value);
    CHECK(vireo_task_metadata_deadline_expired(next, 100, &value) == VIREO_OK && !value);
    CHECK(errno == EDOM);
    /* 手写不同实例，未运行发号器、真实客户或异步worker，不冒联调证据。 */
    return 0;
}

int main(void) {
    CHECK(null_outputs() == 0);
    CHECK(make_golden_values() == 0);
    CHECK(invalid_shape_matrix() == 0);
    CHECK(finite_deadline_table() == 0);
    CHECK(same_request_table() == 0);
    CHECK(logical_fields_ignore_padding() == 0);
    CHECK(by_value_writeback() == 0);
    CHECK(request_instance_story() == 0);
    puts("task metadata: 8 groups passed");
    return 0;
}
