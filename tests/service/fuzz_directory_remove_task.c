/* PROJECT : VIREO; FILE : fuzz_directory_remove_task.c; BRIEF : VRT1 input boundary. */
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <vireo/protocol/node_remove.h>
#include <vireo/service/directory_remove_task.h>
#include <vireo/thread/task.h>

enum { REMOVE_OPERATION = 109, MAX_INPUT = 392 };

int LLVMFuzzerTestOneInput(uint8_t const *data, size_t size);

static vireo_task_metadata_t metadata(void) {
    vireo_task_route_t route = {1, 0, 1, 11};
    vireo_task_metadata_t out;
    assert(vireo_task_metadata_make(route, 1, REMOVE_OPERATION, UINT64_MAX, &out) == VIREO_OK);
    return out;
}

static void valid_payload(unsigned char payload[88], uint32_t sequence) {
    vireo_node_remove_request_t request = {
        .sequence = sequence, .session_handle = 22, .node_id = 31, .idempotency_key = {1}};
    size_t size = 0;
    memset(payload, 0, 88);
    memcpy(payload, "VRT1", 4);
    payload[4] = payload[5] = payload[6] = payload[7] = 0;
    payload[15] = 1;
    payload[23] = 2;
    assert(vireo_node_remove_request_encode(&request, payload + 24, 64, &size) == VIREO_OK);
    assert(size == 64);
}

static void check(unsigned char const *bytes, size_t size, uint32_t operation, int expected) {
    vireo_task_metadata_t m = metadata();
    m.operation = operation;
    assert(vireo_task_metadata_make(m.route, m.request_instance_id, m.operation, m.deadline_ns,
                                   &m) == VIREO_OK);
    vireo_task_t *task = NULL;
    errno = EDOM;
    vireo_result_t create = vireo_task_create_copy(m, bytes, size, 4096, &task);
    assert(errno == EDOM);
    if (create != VIREO_OK) {
        assert(create == VIREO_RESULT_RANGE && task == NULL);
        return;
    }

    vireo_directory_remove_input_t out;
    vireo_directory_remove_input_t before;
    memset(&out, 0xa5, sizeof(out));
    memcpy(&before, &out, sizeof(out));
    vireo_node_remove_issue_t issue = VIREO_NODE_REMOVE_ISSUE_VALUE;
    errno = EDOM;
    vireo_result_t rc = vireo_directory_remove_task_read(task, REMOVE_OPERATION, &out, &issue);
    assert(errno == EDOM);
    if (expected == 1)
        assert(rc == VIREO_OK);
    if (expected == 0)
        assert(rc == VIREO_RESULT_PROTOCOL);
    if (rc != VIREO_OK) {
        assert(rc == VIREO_RESULT_PROTOCOL);
        assert(issue != VIREO_NODE_REMOVE_ISSUE_NONE);
        assert(memcmp(&before, &out, sizeof(out)) == 0);
    } else {
        assert(out.metadata.operation == REMOVE_OPERATION);
        assert(out.actor.user_id != 0 && out.actor.session_id != 0);
        assert(out.request.sequence == 11 && out.request.session_handle == 22);
        assert(out.request.node_id != 0 && out.request.idempotency_key[0] != 0);
        assert(issue == VIREO_NODE_REMOVE_ISSUE_NONE);
    }
    assert(vireo_task_destroy(&task) == VIREO_OK && task == NULL);
}

int LLVMFuzzerTestOneInput(uint8_t const *data, size_t size) {
    if (size > MAX_INPUT) {
        check(data, size, REMOVE_OPERATION, -1);
        return 0;
    }
    if (size > 1)
        check(data + 1, size - 1, REMOVE_OPERATION, -1);
    unsigned char structured[88];
    uint32_t operation = REMOVE_OPERATION;
    size_t length = sizeof(structured);
    unsigned mode = size == 0 ? 0U : data[0] % 9U;
    valid_payload(structured, mode == 5 ? 12U : 11U);
    switch (mode) {
        case 1: structured[0] ^= 1U; break;
        case 2: structured[4] = 1; break;
        case 3: memset(structured + 8, 0, 8); break;
        case 4: memset(structured + 16, 0, 8); break;
        case 5: structured[87] ^= 1U; break;
        case 6: length = 87; break;
        case 7: operation = REMOVE_OPERATION + 1U; break;
        case 8: structured[39] ^= 1U; break;
        default: break;
    }
    check(structured, length, operation, mode == 0 ? 1 : 0);
    return 0;
}
