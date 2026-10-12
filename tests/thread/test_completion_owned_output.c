/*
 * PROJECT : VIREO
 * FILE    : test_completion_owned_output.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-12
 * BRIEF   : 独立响应寿命、唯一交接、受检预算与真实分配失败验证
 */

#include "thread/completion_internal.h"

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

#define EXPECT(call, expected) do { \
    errno = EDOM; \
    CHECK((call) == (expected)); \
    CHECK(errno == EDOM); \
} while (0)

/* 仅本测试借给 own seam，检查申请、原块配对和失败前未申请。 */
typedef struct allocation_trace {
    size_t allocations;
    size_t releases;
    size_t bytes;
    void *live;
    bool fail;
    bool mismatch;
} allocation_trace_t;

static void *trace_allocate(void *context, size_t bytes) {
    allocation_trace_t *trace = context;
    trace->allocations++;
    trace->bytes = bytes;
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

static vireo_completion_metadata_t good_metadata(void) {
    vireo_completion_metadata_t const metadata = {{{7, 0, 3, 11}, 42, 2, 100},
        VIREO_RESULT_DATABASE, VIREO_STATUS_DB_ERROR};
    return metadata;
}

/* 独立逐字段期望，成功不要求 padding 相等。 */
static bool metadata_equal(vireo_completion_metadata_t a, vireo_completion_metadata_t b) {
    return a.request.route.client_owner_id == b.request.route.client_owner_id &&
        a.request.route.client_slot_index == b.request.route.client_slot_index &&
        a.request.route.client_generation == b.request.route.client_generation &&
        a.request.route.request_sequence == b.request.route.request_sequence &&
        a.request.request_instance_id == b.request.request_instance_id &&
        a.request.operation == b.request.operation && a.request.deadline_ns == b.request.deadline_ns &&
        a.result == b.result && a.suggested_status == b.suggested_status;
}

static int copy_and_snapshot(void) {
    unsigned char const expected[] = {0x41, 0, 0xff, 0x7f, 0x80};
    unsigned char *input = malloc(sizeof(expected));
    CHECK(input != NULL);
    memcpy(input, expected, sizeof(expected));
    vireo_completion_metadata_t metadata = good_metadata();
    vireo_completion_metadata_t const original = metadata;
    vireo_completion_t *owner = NULL;
    EXPECT(vireo_completion_create_copy(metadata, input, sizeof(expected), 4096, &owner), VIREO_OK);
    CHECK(owner != NULL && memcmp(input, expected, sizeof(expected)) == 0);
    vireo_completion_payload_view_t view = {0};
    EXPECT(vireo_completion_borrow_payload(owner, &view), VIREO_OK);
    CHECK(view.data != input && view.size == sizeof(expected));
    CHECK(memcmp(view.data, expected, sizeof(expected)) == 0);
    view = (vireo_completion_payload_view_t){0}; /* 借用结束，不跨 move/destroy 使用。 */
    memset(input, 0, sizeof(expected));
    free(input);
    metadata.request.request_instance_id = 99;
    metadata.result = VIREO_RESULT_CANCELLED;
    vireo_completion_info_t info = {0};
    EXPECT(vireo_completion_inspect(owner, &info), VIREO_OK);
    CHECK(metadata_equal(info.metadata, original) && info.payload_size == sizeof(expected));
    CHECK(info.allocated_bytes >= info.payload_size && info.allocated_bytes <= 4096);
    info.metadata.result = VIREO_OK;
    info.payload_size = 0;
    EXPECT(vireo_completion_inspect(owner, &info), VIREO_OK);
    CHECK(metadata_equal(info.metadata, original) && info.payload_size == sizeof(expected));
    EXPECT(vireo_completion_borrow_payload(owner, &view), VIREO_OK);
    CHECK(view.size == sizeof(expected) && memcmp(view.data, expected, sizeof(expected)) == 0);
    view = (vireo_completion_payload_view_t){0};
    EXPECT(vireo_completion_destroy(&owner), VIREO_OK);
    CHECK(owner == NULL && metadata_equal(info.metadata, original));
    CHECK(info.payload_size == sizeof(expected)); /* 独立快照可超过对象寿命。 */
    return 0;
}

static int empty_payload(void) {
    unsigned char const unused = 0x5a;
    void const *inputs[] = {NULL, &unused};
    for (size_t i = 0; i < sizeof(inputs) / sizeof(inputs[0]); ++i) {
        vireo_completion_metadata_t metadata = good_metadata();
        metadata.request.deadline_ns = i == 0 ? 0 : UINT64_MAX;
        vireo_completion_t *owner = NULL;
        EXPECT(vireo_completion_create_copy(metadata, inputs[i], 0, 4096, &owner), VIREO_OK);
        vireo_completion_info_t info = {0};
        EXPECT(vireo_completion_inspect(owner, &info), VIREO_OK);
        CHECK(info.payload_size == 0 && info.allocated_bytes > 0 && metadata_equal(info.metadata, metadata));
        vireo_completion_payload_view_t view = {&unused, 99};
        EXPECT(vireo_completion_borrow_payload(owner, &view), VIREO_OK);
        CHECK(view.data == NULL && view.size == 0);
        EXPECT(vireo_completion_destroy(&owner), VIREO_OK);
        EXPECT(vireo_completion_destroy(&owner), VIREO_OK);
        CHECK(owner == NULL);
    }
    return 0;
}

static int null_and_invalid_create(void) {
    vireo_completion_t *owner = NULL;
    vireo_completion_metadata_t const good = good_metadata();
    vireo_completion_metadata_t const bad = {0};
    unsigned char const data = 1;
    EXPECT(vireo_completion_create_copy(good, &data, 1, 4096, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_completion_create_copy(bad, NULL, SIZE_MAX, 0, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_completion_create_copy(good, NULL, 1, 4096, &owner), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_completion_create_copy(good, &data, SIZE_MAX, 0, &owner), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(owner == NULL);
    EXPECT(vireo_completion_create_copy(good, &data, 1, 4096, &owner), VIREO_OK);
    vireo_completion_t *const before = owner;
    EXPECT(vireo_completion_create_copy(good, &data, 1, 4096, &owner), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(owner == before);
    EXPECT(vireo_completion_destroy(&owner), VIREO_OK);
    EXPECT(vireo_completion_destroy(NULL), VIREO_RESULT_INVALID_ARGUMENT);
    return 0;
}

static int invalid_metadata(void) {
    allocation_trace_t trace = {0};
    vireo_completion_allocator_t const allocator = {&trace, trace_allocate, trace_deallocate};
    vireo_completion_metadata_t bad[5];
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        bad[i] = good_metadata();
    }
    bad[0] = (vireo_completion_metadata_t){0};
    bad[1].request.request_instance_id = 0;
    bad[2].request.route.client_generation = 0;
    bad[3].result = (vireo_result_t)13;
    bad[4].suggested_status = UINT16_MAX;
    unsigned char const data = 1;
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        vireo_completion_t *owner = NULL;
        unsigned char before[sizeof(bad[i])];
        memcpy(before, &bad[i], sizeof(before));
        EXPECT(vireo_completion_create_copy_with_allocator(bad[i], &data, SIZE_MAX, SIZE_MAX,
            &allocator, &owner), VIREO_RESULT_INVALID_ARGUMENT);
        CHECK(owner == NULL && memcmp(before, &bad[i], sizeof(before)) == 0);
    }
    CHECK(trace.allocations == 0 && trace.releases == 0 && trace.live == NULL && !trace.mismatch);
    return 0;
}

static int checked_budgets(void) {
    vireo_completion_t *owner = NULL;
    vireo_completion_metadata_t const metadata = good_metadata();
    EXPECT(vireo_completion_create_copy(metadata, NULL, 0, 4096, &owner), VIREO_OK);
    vireo_completion_info_t empty = {0};
    EXPECT(vireo_completion_inspect(owner, &empty), VIREO_OK);
    EXPECT(vireo_completion_destroy(&owner), VIREO_OK);
    unsigned char const data[] = {2, 0, 3};
    size_t const exact = empty.allocated_bytes + sizeof(data);
    EXPECT(vireo_completion_create_copy(metadata, data, sizeof(data), exact, &owner), VIREO_OK);
    vireo_completion_info_t info = {0};
    EXPECT(vireo_completion_inspect(owner, &info), VIREO_OK);
    CHECK(info.allocated_bytes == exact && info.payload_size == sizeof(data));
    EXPECT(vireo_completion_destroy(&owner), VIREO_OK);
    allocation_trace_t trace = {0};
    vireo_completion_allocator_t const allocator = {&trace, trace_allocate, trace_deallocate};
    EXPECT(vireo_completion_create_copy_with_allocator(metadata, data, sizeof(data), exact - 1,
        &allocator, &owner), VIREO_RESULT_RANGE);
    EXPECT(vireo_completion_create_copy_with_allocator(metadata, NULL, 0, 1,
        &allocator, &owner), VIREO_RESULT_RANGE);
    EXPECT(vireo_completion_create_copy_with_allocator(metadata, data, 1,
        VIREO_COMPLETION_MAX_ALLOCATION_BYTES + 1, &allocator, &owner), VIREO_RESULT_RANGE);
    EXPECT(vireo_completion_create_copy_with_allocator(metadata, data,
        VIREO_COMPLETION_MAX_ALLOCATION_BYTES, VIREO_COMPLETION_MAX_ALLOCATION_BYTES,
        &allocator, &owner), VIREO_RESULT_RANGE);
    EXPECT(vireo_completion_create_copy_with_allocator(metadata, data, SIZE_MAX, 4096,
        &allocator, &owner), VIREO_RESULT_OVERFLOW);
    EXPECT(vireo_completion_create_copy_with_allocator(metadata, data, SIZE_MAX, SIZE_MAX,
        &allocator, &owner), VIREO_RESULT_OVERFLOW);
    /* SIZE_MAX 的总申请量虽可表示，仍超预算，不得读这块小输入。 */
    EXPECT(vireo_completion_create_copy_with_allocator(metadata, data, SIZE_MAX - empty.allocated_bytes,
        SIZE_MAX, &allocator, &owner), VIREO_RESULT_RANGE);
    CHECK(owner == NULL && trace.allocations == 0 && trace.releases == 0 && trace.live == NULL);
    return 0;
}

static int allocation_failure_and_pairing(void) {
    allocation_trace_t trace = {0};
    vireo_completion_allocator_t allocator = {&trace, trace_allocate, trace_deallocate};
    vireo_completion_metadata_t const metadata = good_metadata();
    unsigned char const data[] = {1, 2, 0, 3};
    vireo_completion_t *owner = NULL;
    EXPECT(vireo_completion_create_copy_with_allocator(metadata, data, sizeof(data), 4096,
        NULL, &owner), VIREO_RESULT_INVALID_ARGUMENT);
    vireo_completion_allocator_t invalid = allocator;
    invalid.allocate = NULL;
    EXPECT(vireo_completion_create_copy_with_allocator(metadata, data, sizeof(data), 4096,
        &invalid, &owner), VIREO_RESULT_INVALID_ARGUMENT);
    invalid = allocator;
    invalid.deallocate = NULL;
    EXPECT(vireo_completion_create_copy_with_allocator(metadata, data, sizeof(data), 4096,
        &invalid, &owner), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(trace.allocations == 0 && owner == NULL);
    trace.fail = true;
    EXPECT(vireo_completion_create_copy_with_allocator(metadata, data, sizeof(data), 4096,
        &allocator, &owner), VIREO_RESULT_NO_MEMORY);
    CHECK(owner == NULL && trace.allocations == 1 && trace.releases == 0 && trace.live == NULL);
    CHECK(data[0] == 1 && data[2] == 0 && !trace.mismatch);
    trace.fail = false;
    EXPECT(vireo_completion_create_copy_with_allocator(metadata, data, sizeof(data), 4096,
        &allocator, &owner), VIREO_OK);
    vireo_completion_info_t info = {0};
    EXPECT(vireo_completion_inspect(owner, &info), VIREO_OK);
    CHECK(trace.allocations == 2 && trace.live == owner && info.allocated_bytes == trace.bytes);
    /* 操作表只借到构造返回，后续销毁必须使用已经复制的原配对表。 */
    allocator = (vireo_completion_allocator_t){0};
    vireo_completion_t *destination = NULL;
    vireo_completion_t *const original = owner;
    EXPECT(vireo_completion_move(&owner, &destination), VIREO_OK);
    CHECK(owner == NULL && destination == original && trace.allocations == 2 && trace.releases == 0);
    EXPECT(vireo_completion_destroy(&destination), VIREO_OK);
    EXPECT(vireo_completion_destroy(&destination), VIREO_OK);
    CHECK(destination == NULL && trace.allocations == 2 && trace.releases == 1 &&
        trace.live == NULL && !trace.mismatch);
    return 0;
}

static int owner_moves(void) {
    vireo_completion_t *source = NULL;
    vireo_completion_t *destination = NULL;
    EXPECT(vireo_completion_move(&source, &destination), VIREO_RESULT_NOT_FOUND);
    EXPECT(vireo_completion_move(&source, &source), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_completion_move(NULL, &destination), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_completion_move(&source, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_completion_create_copy(good_metadata(), NULL, 0, 4096, &source), VIREO_OK);
    EXPECT(vireo_completion_create_copy(good_metadata(), NULL, 0, 4096, &destination), VIREO_OK);
    vireo_completion_t *const old_source = source;
    vireo_completion_t *const old_destination = destination;
    EXPECT(vireo_completion_move(&source, &source), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_completion_move(&source, &destination), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(source == old_source && destination == old_destination);
    vireo_completion_t *empty = NULL;
    EXPECT(vireo_completion_move(&empty, &destination), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(empty == NULL && destination == old_destination);
    EXPECT(vireo_completion_destroy(&destination), VIREO_OK);
    EXPECT(vireo_completion_move(&source, &destination), VIREO_OK);
    CHECK(source == NULL && destination == old_source);
    EXPECT(vireo_completion_destroy(&source), VIREO_OK);
    EXPECT(vireo_completion_destroy(&destination), VIREO_OK);
    return 0;
}

static int observation_failures(void) {
    vireo_completion_info_t info;
    vireo_completion_payload_view_t view;
    unsigned char info_before[sizeof(info)], view_before[sizeof(view)];
    memset(&info, 0xa5, sizeof(info));
    memset(&view, 0x5a, sizeof(view));
    memcpy(info_before, &info, sizeof(info_before));
    memcpy(view_before, &view, sizeof(view_before));
    EXPECT(vireo_completion_inspect(NULL, &info), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_completion_borrow_payload(NULL, &view), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(memcmp(&info, info_before, sizeof(info_before)) == 0);
    CHECK(memcmp(&view, view_before, sizeof(view_before)) == 0);
    EXPECT(vireo_completion_inspect(NULL, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_completion_borrow_payload(NULL, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    unsigned char const data[] = {0x31, 0, 0x32};
    vireo_completion_t *owner = NULL;
    EXPECT(vireo_completion_create_copy(good_metadata(), data, sizeof(data), 4096, &owner), VIREO_OK);
    EXPECT(vireo_completion_inspect(owner, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_completion_borrow_payload(owner, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    vireo_completion_payload_view_t good = {0};
    EXPECT(vireo_completion_borrow_payload(owner, &good), VIREO_OK);
    CHECK(good.size == sizeof(data) && memcmp(good.data, data, sizeof(data)) == 0);
    good = (vireo_completion_payload_view_t){0};
    EXPECT(vireo_completion_destroy(&owner), VIREO_OK);
    return 0;
}

static int task_lifetime_chain(void) {
    vireo_task_t *task = NULL;
    vireo_task_metadata_t const request = good_metadata().request;
    unsigned char input[] = {0x61, 0, 0x62};
    unsigned char const response_expected[] = {0x61, 0, 0x62, 0x63};
    EXPECT(vireo_task_create_copy(request, input, sizeof(input), 4096, &task), VIREO_OK);
    memset(input, 0xff, sizeof(input));
    vireo_task_info_t task_info = {0};
    EXPECT(vireo_task_inspect(task, &task_info), VIREO_OK);
    vireo_completion_metadata_t metadata = {0};
    EXPECT(vireo_completion_metadata_make(task_info.metadata, VIREO_OK,
        VIREO_STATUS_OK, &metadata), VIREO_OK);
    vireo_task_payload_view_t input_view = {0};
    EXPECT(vireo_task_borrow_payload(task, &input_view), VIREO_OK);
    CHECK(input_view.size == 3);
    unsigned char response[sizeof(response_expected)];
    memcpy(response, input_view.data, input_view.size);
    response[3] = 0x63;
    input_view = (vireo_task_payload_view_t){0};
    vireo_completion_t *completion = NULL;
    EXPECT(vireo_completion_create_copy(metadata, response, sizeof(response), 4096, &completion), VIREO_OK);
    memset(response, 0, sizeof(response));
    EXPECT(vireo_task_destroy(&task), VIREO_OK);
    CHECK(task == NULL);
    vireo_completion_info_t info = {0};
    EXPECT(vireo_completion_inspect(completion, &info), VIREO_OK);
    CHECK(metadata_equal(info.metadata, metadata) && info.payload_size == sizeof(response_expected));
    vireo_completion_payload_view_t view = {0};
    EXPECT(vireo_completion_borrow_payload(completion, &view), VIREO_OK);
    CHECK(view.size == sizeof(response_expected) && memcmp(view.data, response_expected, sizeof(response_expected)) == 0);
    view = (vireo_completion_payload_view_t){0};
    EXPECT(vireo_completion_destroy(&completion), VIREO_OK);
    return 0;
}

int main(void) {
    int (*const groups[])(void) = {copy_and_snapshot, empty_payload, null_and_invalid_create,
        invalid_metadata, checked_budgets, allocation_failure_and_pairing, owner_moves,
        observation_failures, task_lifetime_chain};
    for (size_t i = 0; i < sizeof(groups) / sizeof(groups[0]); ++i) {
        if (groups[i]() != 0) {
            return 1;
        }
    }
    puts("completion owned output: 9 groups passed");
    return 0;
}
