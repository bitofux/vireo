/*
 * PROJECT : VIREO
 * FILE    : test_completion_metadata.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-12
 * BRIEF   : 完成分类、历史身份、有限期限及失败输出的公开合同验证
 */

#include <vireo/thread/completion.h>

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #condition); \
        return 1; \
    } \
} while (0)

static int null_outputs(void) {
    vireo_completion_metadata_t const good = {{{7, 0, 3, 11}, 42, 1, 100},
        VIREO_RESULT_DATABASE, VIREO_STATUS_DB_ERROR};
    vireo_completion_metadata_t const bad = {0};
    errno = EDOM;
    CHECK(vireo_completion_metadata_make(good.request, good.result,
        good.suggested_status, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_completion_metadata_make(bad.request, (vireo_result_t)INT_MAX,
        UINT16_MAX, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_completion_metadata_same_request(good, good, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_completion_metadata_same_request(bad, bad, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_completion_metadata_deadline_expired(good, 100, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_completion_metadata_deadline_expired(bad, 0, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(errno == EDOM);
    return 0;
}

static int golden_results_and_boundaries(void) {
    vireo_task_metadata_t const requests[] = {
        {{1, 0, 1, 1}, 1, 1, 0},
        {{7, 2, 3, 11}, 42, 2, 100},
        {{UINT64_MAX, SIZE_MAX, UINT64_MAX, UINT32_MAX}, UINT64_MAX, UINT32_MAX, UINT64_MAX}
    };
    /* 独立协议分类可以与每个内部结果组合，验证没有隐式数字映射/强制配对。 */
    vireo_status_t const statuses[] = {VIREO_STATUS_OK, VIREO_STATUS_ACCEPTED,
        VIREO_STATUS_DB_ERROR, VIREO_STATUS_TIMEOUT, VIREO_STATUS_TASK_CANCELLED};
    for (size_t i = 0; i < sizeof(requests) / sizeof(requests[0]); ++i) {
        for (int result = 0; result <= 12; ++result) {
            for (size_t j = 0; j < sizeof(statuses) / sizeof(statuses[0]); ++j) {
                vireo_completion_metadata_t out[3] = {0};
                unsigned char before[sizeof(out[0])];
                unsigned char after[sizeof(out[2])];
                memcpy(before, &out[0], sizeof(before));
                memcpy(after, &out[2], sizeof(after));
                errno = EILSEQ;
                CHECK(vireo_completion_metadata_make(requests[i], (vireo_result_t)result,
                    statuses[j], &out[1]) == VIREO_OK);
                CHECK(out[1].request.route.client_owner_id == requests[i].route.client_owner_id);
                CHECK(out[1].request.route.client_slot_index == requests[i].route.client_slot_index);
                CHECK(out[1].request.route.client_generation == requests[i].route.client_generation);
                CHECK(out[1].request.route.request_sequence == requests[i].route.request_sequence);
                CHECK(out[1].request.request_instance_id == requests[i].request_instance_id);
                CHECK(out[1].request.operation == requests[i].operation);
                CHECK(out[1].request.deadline_ns == requests[i].deadline_ns);
                CHECK(out[1].result == (vireo_result_t)result && out[1].suggested_status == statuses[j]);
                CHECK(memcmp(before, &out[0], sizeof(before)) == 0);
                CHECK(memcmp(after, &out[2], sizeof(after)) == 0 && errno == EILSEQ);
            }
        }
    }
    return 0;
}

static int complete_status_domain(void) {
    vireo_task_metadata_t const request = {{7, 0, 3, 11}, 42, 1, 100};
    vireo_completion_metadata_t value = {request, VIREO_OK, VIREO_STATUS_OK};
    size_t known_count = 0;
    /* 期望来自封板协议的注册区间，遍历完整16bit域，包含所有区间空隙。 */
    for (uint32_t n = 0; n <= UINT16_MAX; ++n) {
        bool const known = n <= 1 || (n >= 1001 && n <= 1008) ||
            (n >= 1101 && n <= 1108) || (n >= 1201 && n <= 1206) ||
            (n >= 1301 && n <= 1310) || (n >= 1390 && n <= 1393) ||
            (n >= 1901 && n <= 1908);
        unsigned char before[sizeof(value)];
        memcpy(before, &value, sizeof(before));
        errno = ERANGE;
        vireo_result_t const result = vireo_completion_metadata_make(request,
            VIREO_RESULT_DATABASE, (vireo_status_t)n, &value);
        CHECK(result == (known ? VIREO_OK : VIREO_RESULT_INVALID_ARGUMENT));
        if (known) {
            ++known_count;
            CHECK(value.result == VIREO_RESULT_DATABASE && value.suggested_status == (vireo_status_t)n);
        } else {
            CHECK(memcmp(before, &value, sizeof(before)) == 0);
        }
        CHECK(errno == ERANGE);
    }
    CHECK(known_count == 46);
    return 0;
}

static int invalid_shapes_keep_all_outputs(void) {
    vireo_completion_metadata_t const good = {{{7, 0, 3, 11}, 42, 1, 100},
        VIREO_RESULT_DATABASE, VIREO_STATUS_DB_ERROR};
    for (size_t kind = 0; kind < 10; ++kind) {
        vireo_completion_metadata_t bad = good;
        switch (kind) {
            case 0: bad = (vireo_completion_metadata_t){0}; break;
            case 1: bad.request.route.client_owner_id = 0; break;
            case 2: bad.request.route.client_generation = 0; break;
            case 3: bad.request.route.request_sequence = 0; break;
            case 4: bad.request.request_instance_id = 0; break;
            case 5: bad.request.operation = 0; break;
            case 6: bad.result = (vireo_result_t)-1; break;
            case 7: bad.result = (vireo_result_t)13; break;
            case 8: bad.result = (vireo_result_t)INT_MAX; break;
            case 9: bad.suggested_status = UINT16_MAX; break;
            default: return 1;
        }
        unsigned char input_before[sizeof(bad)];
        memcpy(input_before, &bad, sizeof(input_before));
        vireo_completion_metadata_t output = good;
        unsigned char output_before[sizeof(output)];
        memcpy(output_before, &output, sizeof(output_before));
        errno = EDOM;
        CHECK(vireo_completion_metadata_make(bad.request, bad.result,
            bad.suggested_status, &output) == VIREO_RESULT_INVALID_ARGUMENT);
        CHECK(memcmp(output_before, &output, sizeof(output_before)) == 0);
        for (size_t initial = 0; initial < 2; ++initial) {
            bool values[3] = {true, initial != 0, false};
            unsigned char bool_before[sizeof(values)];
            memcpy(bool_before, values, sizeof(bool_before));
            CHECK(vireo_completion_metadata_same_request(bad, good, &values[1]) == VIREO_RESULT_INVALID_ARGUMENT);
            CHECK(memcmp(bool_before, values, sizeof(bool_before)) == 0);
            CHECK(vireo_completion_metadata_same_request(good, bad, &values[1]) == VIREO_RESULT_INVALID_ARGUMENT);
            CHECK(memcmp(bool_before, values, sizeof(bool_before)) == 0);
            CHECK(vireo_completion_metadata_deadline_expired(bad, UINT64_MAX,
                &values[1]) == VIREO_RESULT_INVALID_ARGUMENT);
            CHECK(memcmp(bool_before, values, sizeof(bool_before)) == 0);
        }
        CHECK(memcmp(input_before, &bad, sizeof(input_before)) == 0 && errno == EDOM);
    }
    return 0;
}

static int request_identity_relations(void) {
    vireo_completion_metadata_t const good = {{{7, 0, 3, 11}, 42, 1, 100},
        VIREO_RESULT_DATABASE, VIREO_STATUS_DB_ERROR};
    bool const expected[] = {false, false, false, false, false, true, true, true, true};
    for (size_t field = 0; field < sizeof(expected) / sizeof(expected[0]); ++field) {
        vireo_completion_metadata_t other = good;
        switch (field) {
            case 0: other.request.route.client_owner_id = 8; break;
            case 1: other.request.route.client_slot_index = SIZE_MAX; break;
            case 2: other.request.route.client_generation = 4; break;
            case 3: other.request.route.request_sequence = UINT32_MAX; break;
            case 4: other.request.request_instance_id = 43; break;
            case 5: other.request.operation = UINT32_MAX; break;
            case 6: other.request.deadline_ns = UINT64_MAX; break;
            case 7: other.result = VIREO_RESULT_CANCELLED; break;
            case 8: other.suggested_status = VIREO_STATUS_TASK_CANCELLED; break;
            default: return 1;
        }
        bool same = !expected[field];
        errno = EILSEQ;
        CHECK(vireo_completion_metadata_same_request(good, other, &same) == VIREO_OK);
        CHECK(same == expected[field]);
        same = !expected[field];
        CHECK(vireo_completion_metadata_same_request(other, good, &same) == VIREO_OK);
        CHECK(same == expected[field]);
        CHECK(vireo_completion_metadata_same_request(other, other, &same) == VIREO_OK);
        CHECK(same && errno == EILSEQ);
    }
    return 0;
}

static int finite_deadline_boundaries(void) {
    uint64_t const times[][2] = {
        {0, 0}, {0, 1}, {1, 0}, {99, 100}, {100, 100}, {101, 100},
        {UINT64_MAX - UINT64_C(1), UINT64_MAX}, {UINT64_MAX, UINT64_MAX},
        {UINT64_MAX, 0}, {0, UINT64_MAX},
        {100, UINT64_C(4294967396)}, {UINT64_C(4294967396), 100}
    };
    bool const expected[] = {true, false, true, false, true, true, false, true, true, false, false, true};
    CHECK(sizeof(times) / sizeof(times[0]) == sizeof(expected) / sizeof(expected[0]));
    for (size_t i = 0; i < sizeof(expected) / sizeof(expected[0]); ++i) {
        vireo_task_metadata_t const request = {{7, 0, 3, 11}, 42, 1, times[i][1]};
        vireo_completion_metadata_t value;
        errno = EDOM;
        CHECK(vireo_completion_metadata_make(request, VIREO_OK, VIREO_STATUS_OK, &value) == VIREO_OK);
        unsigned char before[sizeof(value)];
        memcpy(before, &value, sizeof(before));
        bool outputs[3] = {true, !expected[i], false};
        CHECK(vireo_completion_metadata_deadline_expired(value, times[i][0], &outputs[1]) == VIREO_OK);
        CHECK(outputs[0] && outputs[1] == expected[i] && !outputs[2]);
        CHECK(memcmp(before, &value, sizeof(before)) == 0 && errno == EDOM);
    }
    return 0;
}

static int snapshot_survives_task_and_original_storage(void) {
    vireo_task_metadata_t const request = {{7, 0, 3, 11}, 42, 1, 100};
    unsigned char payload[] = {1, 2, 3};
    vireo_task_t *task = NULL;
    vireo_task_info_t info;
    vireo_completion_metadata_t value;
    errno = EILSEQ;
    CHECK(vireo_task_create_copy(request, payload, sizeof(payload), 4096, &task) == VIREO_OK);
    CHECK(vireo_task_inspect(task, &info) == VIREO_OK);
    CHECK(vireo_completion_metadata_make(info.metadata, VIREO_RESULT_DATABASE,
        VIREO_STATUS_INTERNAL_ERROR, &value) == VIREO_OK);
    info.metadata.request_instance_id = 43;
    payload[0] = 9;
    CHECK(vireo_task_destroy(&task) == VIREO_OK && task == NULL);
    CHECK(value.request.request_instance_id == 42 && value.result == VIREO_RESULT_DATABASE);
    CHECK(value.suggested_status == VIREO_STATUS_INTERNAL_ERROR);
    bool expired = false;
    CHECK(vireo_completion_metadata_deadline_expired(value, 100, &expired) == VIREO_OK && expired);
    bool same = false;
    CHECK(vireo_completion_metadata_same_request(value, value, &same) == VIREO_OK && same);
    CHECK(errno == EILSEQ);
    return 0;
}

static int by_value_replacement(void) {
    vireo_completion_metadata_t value = {{{UINT64_MAX, SIZE_MAX, UINT64_MAX, UINT32_MAX},
        UINT64_MAX, UINT32_MAX, UINT64_MAX}, VIREO_OK, VIREO_STATUS_OK};
    errno = ERANGE;
    CHECK(vireo_completion_metadata_make(value.request, VIREO_RESULT_CANCELLED,
        VIREO_STATUS_TASK_CANCELLED, &value) == VIREO_OK);
    CHECK(value.result == VIREO_RESULT_CANCELLED && value.request.deadline_ns == UINT64_MAX);
    CHECK(value.request.route.client_slot_index == SIZE_MAX);
    CHECK(value.suggested_status == VIREO_STATUS_TASK_CANCELLED && errno == ERANGE);
    return 0;
}

int main(void) {
    int (*const groups[])(void) = {null_outputs, golden_results_and_boundaries,
        complete_status_domain, invalid_shapes_keep_all_outputs, request_identity_relations,
        finite_deadline_boundaries, snapshot_survives_task_and_original_storage, by_value_replacement};
    for (size_t i = 0; i < sizeof(groups) / sizeof(groups[0]); ++i) {
        if (groups[i]() != 0) {
            return 1;
        }
    }
    puts("test_completion_metadata: all 8 test groups passed");
    return 0;
}
