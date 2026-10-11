/*
 * PROJECT : VIREO
 * FILE    : test_task_owned_input.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-11
 * BRIEF   : 独立输入、唯一拥有、受检预算与真实分配失败验证
 */

#include "thread/task_internal.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #condition); \
        return 1; \
    } \
} while (0)

/** @brief 仅测试使用的单活跃块观测；真实 malloc/free，不模拟成功内存。 */
typedef struct allocation_trace {
    size_t attempts; /**< allocate 调用次数，包含失败。 */
    size_t releases; /**< 配对 deallocate 调用次数。 */
    size_t requested_bytes; /**< 最近一次实际请求字节数。 */
    void *live; /**< 当前真实活跃块，只观测，不作为额外 owner。 */
    bool fail; /**< 本上下文是否让 allocate 返回 NULL。 */
    bool mismatch; /**< 重复申请或错误配对释放的观测标志。 */
} allocation_trace_t;

static void *trace_allocate(void *context, size_t bytes) {
    allocation_trace_t *trace = context;
    trace->attempts++;
    trace->requested_bytes = bytes;
    if (trace->live != NULL) {
        trace->mismatch = true;
    }
    trace->live = trace->fail ? NULL : malloc(bytes);
    errno = ENOMEM;
    return trace->live;
}

static void trace_deallocate(void *context, void *allocation) {
    allocation_trace_t *trace = context;
    trace->releases++;
    if (allocation == NULL || allocation != trace->live) {
        trace->mismatch = true;
    }
    free(allocation);
    trace->live = NULL;
    errno = EILSEQ;
}

static vireo_task_metadata_t metadata(void) {
    vireo_task_metadata_t const value = {{7, 0, 3, 11}, 42, 1, 100};
    return value;
}

static bool same_metadata(vireo_task_metadata_t a, vireo_task_metadata_t b) {
    return a.route.client_owner_id == b.route.client_owner_id &&
        a.route.client_slot_index == b.route.client_slot_index &&
        a.route.client_generation == b.route.client_generation &&
        a.route.request_sequence == b.route.request_sequence &&
        a.request_instance_id == b.request_instance_id && a.operation == b.operation &&
        a.deadline_ns == b.deadline_ns;
}

static int binary_copy(void) {
    unsigned char data[] = {0, 255, 17, 0, 128, 42};
    unsigned char const expected[] = {0, 255, 17, 0, 128, 42};
    vireo_task_metadata_t input = metadata();
    vireo_task_metadata_t const expected_metadata = input;
    vireo_task_t *task = NULL;
    errno = EDOM;
    CHECK(vireo_task_create_copy(input, data, sizeof(data), VIREO_TASK_MAX_ALLOCATION_BYTES,
                                 &task) == VIREO_OK && errno == EDOM);
    memset(data, 9, sizeof(data));
    input.operation = 99;
    input.deadline_ns = 0;
    vireo_task_info_t info;
    CHECK(vireo_task_inspect(task, &info) == VIREO_OK && errno == EDOM);
    CHECK(same_metadata(info.metadata, expected_metadata));
    CHECK(info.payload_size == sizeof(expected));
    CHECK(info.allocated_bytes == sizeof(vireo_task_t) + sizeof(expected));
    {
        vireo_task_payload_view_t view;
        CHECK(vireo_task_borrow_payload(task, &view) == VIREO_OK && errno == EDOM);
        CHECK(view.size == sizeof(expected) && view.data != data);
        CHECK(memcmp(view.data, expected, sizeof(expected)) == 0);
    }
    CHECK(vireo_task_destroy(&task) == VIREO_OK && task == NULL && errno == EDOM);
    CHECK(same_metadata(info.metadata, expected_metadata));
    return 0;
}

static int empty_payload(void) {
    unsigned char const ignored = 23;
    void const *const data[] = {NULL, &ignored};
    uint64_t const deadlines[] = {0, UINT64_MAX};
    for (size_t i = 0; i < 2; i++) {
        vireo_task_metadata_t input = metadata();
        input.deadline_ns = deadlines[i];
        vireo_task_t *task = NULL;
        errno = ERANGE;
        CHECK(vireo_task_create_copy(input, data[i], 0, sizeof(vireo_task_t), &task) == VIREO_OK);
        vireo_task_info_t info;
        CHECK(vireo_task_inspect(task, &info) == VIREO_OK);
        CHECK(info.payload_size == 0 && info.allocated_bytes == sizeof(vireo_task_t));
        CHECK(info.metadata.deadline_ns == deadlines[i]);
        {
            vireo_task_payload_view_t view = {&ignored, 9};
            CHECK(vireo_task_borrow_payload(task, &view) == VIREO_OK);
            CHECK(view.data == NULL && view.size == 0);
        }
        CHECK(vireo_task_destroy(&task) == VIREO_OK && task == NULL && errno == ERANGE);
    }
    return 0;
}

static int basic_guards(void) {
    unsigned char const byte = 1;
    vireo_task_t *task = NULL;
    errno = EDOM;
    CHECK(vireo_task_create_copy(metadata(), &byte, 1, 1024, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_task_create_copy(metadata(), &byte, SIZE_MAX, 0, &task) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_task_create_copy(metadata(), NULL, 1, 1024, &task) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(task == NULL && errno == EDOM);
    CHECK(vireo_task_create_copy(metadata(), &byte, 1, 1024, &task) == VIREO_OK);
    vireo_task_t *const original = task;
    CHECK(vireo_task_create_copy(metadata(), &byte, 1, 1024, &task) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(task == original && errno == EDOM);
    {
        vireo_task_payload_view_t view;
        CHECK(vireo_task_borrow_payload(task, &view) == VIREO_OK);
        CHECK(view.size == 1 && view.data[0] == byte);
    }
    CHECK(vireo_task_destroy(&task) == VIREO_OK && errno == EDOM);
    return 0;
}

static int invalid_metadata(void) {
    vireo_task_metadata_t cases[7];
    for (size_t i = 0; i < 7; i++) {
        cases[i] = metadata();
    }
    cases[0].route.client_owner_id = 0;
    cases[1].route.client_generation = 0;
    cases[2].route.request_sequence = 0;
    cases[3].request_instance_id = 0;
    cases[4].operation = 0;
    cases[5].route = (vireo_task_route_t){0};
    cases[6] = (vireo_task_metadata_t){0};
    for (size_t i = 0; i < 7; i++) {
        allocation_trace_t trace = {0};
        vireo_task_allocator_t const allocator = {&trace, trace_allocate, trace_deallocate};
        vireo_task_t *task = NULL;
        unsigned char const byte = 1;
        errno = EDOM;
        CHECK(vireo_task_create_copy_with_allocator(cases[i], &byte, SIZE_MAX, SIZE_MAX,
                                                    &allocator, &task) == VIREO_RESULT_INVALID_ARGUMENT);
        CHECK(task == NULL && trace.attempts == 0 && trace.releases == 0 && errno == EDOM);
    }
    return 0;
}

static int private_allocator_guards(void) {
    allocation_trace_t trace = {0};
    vireo_task_allocator_t cases[] = {
        {&trace, NULL, trace_deallocate}, {&trace, trace_allocate, NULL}
    };
    vireo_task_t *task = NULL;
    errno = EDOM;
    CHECK(vireo_task_create_copy_with_allocator(metadata(), NULL, 0, 1024, NULL, &task) ==
          VIREO_RESULT_INVALID_ARGUMENT);
    for (size_t i = 0; i < 2; i++) {
        CHECK(vireo_task_create_copy_with_allocator(metadata(), NULL, 0, 1024, &cases[i],
                                                    &task) == VIREO_RESULT_INVALID_ARGUMENT);
    }
    CHECK(task == NULL && trace.attempts == 0 && trace.releases == 0 && errno == EDOM);
    return 0;
}

static int budget_and_overflow(void) {
    allocation_trace_t trace = {0};
    vireo_task_allocator_t const allocator = {&trace, trace_allocate, trace_deallocate};
    unsigned char const data[] = {1, 0, 255};
    size_t const exact = sizeof(vireo_task_t) + sizeof(data);
    vireo_task_t *task = NULL;
    errno = EDOM;
    CHECK(vireo_task_create_copy_with_allocator(metadata(), data, SIZE_MAX, SIZE_MAX,
                                                &allocator, &task) == VIREO_RESULT_OVERFLOW);
    CHECK(vireo_task_create_copy_with_allocator(metadata(), data, sizeof(data), exact - 1,
                                                &allocator, &task) == VIREO_RESULT_RANGE);
    CHECK(vireo_task_create_copy_with_allocator(metadata(), NULL, 0, 1,
                                                &allocator, &task) == VIREO_RESULT_RANGE);
    CHECK(vireo_task_create_copy_with_allocator(metadata(), NULL, 0,
          VIREO_TASK_MAX_ALLOCATION_BYTES + 1, &allocator, &task) == VIREO_RESULT_RANGE);
    CHECK(task == NULL && trace.attempts == 0 && trace.releases == 0 && errno == EDOM);
    CHECK(vireo_task_create_copy_with_allocator(metadata(), data, sizeof(data), exact,
                                                &allocator, &task) == VIREO_OK);
    CHECK(trace.attempts == 1 && trace.requested_bytes == exact && errno == EDOM);
    vireo_task_info_t info;
    CHECK(vireo_task_inspect(task, &info) == VIREO_OK && info.allocated_bytes == exact);
    CHECK(vireo_task_destroy(&task) == VIREO_OK && errno == EDOM);
    CHECK(trace.releases == 1 && trace.live == NULL && !trace.mismatch);
    return 0;
}

static int allocation_failure(void) {
    allocation_trace_t trace = {0};
    trace.fail = true;
    vireo_task_allocator_t const allocator = {&trace, trace_allocate, trace_deallocate};
    unsigned char const data[] = {0, 255, 7};
    vireo_task_t *task = NULL;
    errno = ERANGE;
    CHECK(vireo_task_create_copy_with_allocator(metadata(), data, sizeof(data), 1024,
                                                &allocator, &task) == VIREO_RESULT_NO_MEMORY);
    CHECK(task == NULL && trace.attempts == 1 && trace.releases == 0 && trace.live == NULL);
    CHECK(trace.requested_bytes == sizeof(vireo_task_t) + sizeof(data) && errno == ERANGE);
    CHECK(data[0] == 0 && data[1] == 255 && data[2] == 7);
    trace.fail = false;
    CHECK(vireo_task_create_copy_with_allocator(metadata(), data, sizeof(data), 1024,
                                                &allocator, &task) == VIREO_OK && errno == ERANGE);
    CHECK(vireo_task_destroy(&task) == VIREO_OK && errno == ERANGE);
    CHECK(trace.attempts == 2 && trace.releases == 1 && !trace.mismatch);
    return 0;
}

static int query_failure_outputs(void) {
    unsigned char const byte = 1;
    vireo_task_info_t info = {metadata(), 77, 88};
    vireo_task_payload_view_t view = {&byte, 99};
    unsigned char info_before[sizeof(info)];
    unsigned char view_before[sizeof(view)];
    memcpy(info_before, &info, sizeof(info));
    memcpy(view_before, &view, sizeof(view));
    errno = EDOM;
    CHECK(vireo_task_inspect(NULL, &info) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_task_borrow_payload(NULL, &view) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(memcmp(info_before, &info, sizeof(info)) == 0);
    CHECK(memcmp(view_before, &view, sizeof(view)) == 0 && errno == EDOM);
    vireo_task_t *task = NULL;
    CHECK(vireo_task_create_copy(metadata(), &byte, 1, 1024, &task) == VIREO_OK);
    CHECK(vireo_task_inspect(task, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_task_borrow_payload(task, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_task_inspect(task, &info) == VIREO_OK && info.payload_size == 1);
    CHECK(vireo_task_destroy(&task) == VIREO_OK && errno == EDOM);
    return 0;
}

static int move_success(void) {
    allocation_trace_t trace = {0};
    vireo_task_allocator_t const allocator = {&trace, trace_allocate, trace_deallocate};
    unsigned char const data[] = {0, 255};
    vireo_task_t *source = NULL;
    vireo_task_t *destination = NULL;
    errno = EDOM;
    CHECK(vireo_task_create_copy_with_allocator(metadata(), data, sizeof(data), 1024,
                                                &allocator, &source) == VIREO_OK);
    CHECK(vireo_task_move(&source, &destination) == VIREO_OK);
    CHECK(source == NULL && destination != NULL && trace.attempts == 1 && errno == EDOM);
    {
        vireo_task_payload_view_t view;
        CHECK(vireo_task_borrow_payload(destination, &view) == VIREO_OK);
        CHECK(view.size == sizeof(data) && memcmp(view.data, data, sizeof(data)) == 0);
    }
    CHECK(vireo_task_destroy(&source) == VIREO_OK && trace.releases == 0);
    CHECK(vireo_task_destroy(&destination) == VIREO_OK && destination == NULL);
    CHECK(trace.releases == 1 && trace.live == NULL && !trace.mismatch && errno == EDOM);
    return 0;
}

static int move_invalid_preserves(void) {
    vireo_task_t *a = NULL;
    vireo_task_t *b = NULL;
    vireo_task_t *empty = NULL;
    errno = EDOM;
    CHECK(vireo_task_create_copy(metadata(), NULL, 0, 1024, &a) == VIREO_OK);
    CHECK(vireo_task_create_copy(metadata(), NULL, 0, 1024, &b) == VIREO_OK);
    vireo_task_t *const a_before = a;
    vireo_task_t *const b_before = b;
    CHECK(vireo_task_move(NULL, &empty) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_task_move(&a, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_task_move(&a, &a) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_task_move(&empty, &empty) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_task_move(&a, &b) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_task_move(&empty, &b) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(a == a_before && b == b_before && empty == NULL && errno == EDOM);
    CHECK(vireo_task_destroy(&a) == VIREO_OK);
    CHECK(vireo_task_destroy(&b) == VIREO_OK && errno == EDOM);
    return 0;
}

static int move_empty_source(void) {
    vireo_task_t *source = NULL;
    vireo_task_t *destination = NULL;
    errno = EDOM;
    CHECK(vireo_task_move(&source, &destination) == VIREO_RESULT_NOT_FOUND);
    CHECK(source == NULL && destination == NULL && errno == EDOM);
    return 0;
}

static int destroy_idempotent(void) {
    vireo_task_t *task = NULL;
    errno = EDOM;
    CHECK(vireo_task_destroy(NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_task_destroy(&task) == VIREO_OK && task == NULL);
    CHECK(vireo_task_create_copy(metadata(), NULL, 0, 1024, &task) == VIREO_OK);
    CHECK(vireo_task_destroy(&task) == VIREO_OK && task == NULL);
    CHECK(vireo_task_destroy(&task) == VIREO_OK && task == NULL && errno == EDOM);
    return 0;
}

static int allocator_table_copy(void) {
    allocation_trace_t trace = {0};
    vireo_task_allocator_t allocator = {&trace, trace_allocate, trace_deallocate};
    vireo_task_t *task = NULL;
    errno = EDOM;
    CHECK(vireo_task_create_copy_with_allocator(metadata(), NULL, 0, 1024,
                                                &allocator, &task) == VIREO_OK);
    allocator.context = NULL;
    allocator.allocate = NULL;
    allocator.deallocate = NULL;
    CHECK(vireo_task_destroy(&task) == VIREO_OK && task == NULL && errno == EDOM);
    CHECK(trace.attempts == 1 && trace.releases == 1 && !trace.mismatch && trace.live == NULL);
    return 0;
}

static int copy_from_borrow(void) {
    unsigned char const data[] = {255, 0, 17};
    vireo_task_t *first = NULL;
    vireo_task_t *second = NULL;
    errno = EDOM;
    CHECK(vireo_task_create_copy(metadata(), data, sizeof(data), 1024, &first) == VIREO_OK);
    {
        vireo_task_payload_view_t input;
        CHECK(vireo_task_borrow_payload(first, &input) == VIREO_OK);
        CHECK(vireo_task_create_copy(metadata(), input.data, input.size, 1024, &second) == VIREO_OK);
    }
    CHECK(vireo_task_destroy(&first) == VIREO_OK);
    {
        vireo_task_payload_view_t output;
        CHECK(vireo_task_borrow_payload(second, &output) == VIREO_OK);
        CHECK(output.size == sizeof(data) && memcmp(output.data, data, sizeof(data)) == 0);
    }
    CHECK(vireo_task_destroy(&second) == VIREO_OK && errno == EDOM);
    return 0;
}

int main(void) {
    int (*const groups[])(void) = {
        binary_copy, empty_payload, basic_guards, invalid_metadata, private_allocator_guards,
        budget_and_overflow, allocation_failure, query_failure_outputs, move_success,
        move_invalid_preserves, move_empty_source, destroy_idempotent, allocator_table_copy,
        copy_from_borrow
    };
    for (size_t i = 0; i < sizeof(groups) / sizeof(groups[0]); i++) {
        if (groups[i]() != 0) {
            return 1;
        }
    }
    printf("task owned input: %zu groups passed\n", sizeof(groups) / sizeof(groups[0]));
    return 0;
}
