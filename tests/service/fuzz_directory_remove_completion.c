/* PROJECT : VIREO; FILE : fuzz_directory_remove_completion.c; BRIEF : VMC1 input boundary. */
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <vireo/protocol/node_remove.h>
#include <vireo/service/directory_remove_completion.h>
#include <vireo/thread/completion.h>

enum { REMOVE_OPERATION = 109, MAX_INPUT = 153 };

int LLVMFuzzerTestOneInput(uint8_t const *data, size_t size);

static vireo_task_metadata_t request_metadata(void) {
    vireo_task_route_t route = {1, 0, 1, 11};
    vireo_task_metadata_t out;
    assert(vireo_task_metadata_make(route, 1, REMOVE_OPERATION, UINT64_MAX, &out) == VIREO_OK);
    return out;
}

static void put32(unsigned char *p, uint32_t value) {
    for (size_t i = 0; i < 4; ++i)
        p[i] = (unsigned char)(value >> ((3U - (unsigned)i) * 8U));
}

static void put64(unsigned char *p, uint64_t value) {
    for (size_t i = 0; i < 8; ++i)
        p[i] = (unsigned char)(value >> ((7U - (unsigned)i) * 8U));
}

static void valid_payload(unsigned char payload[120], size_t *out_size, uint32_t sequence) {
    vireo_node_remove_response_t response = {
        .status = VIREO_STATUS_OK, .sequence = sequence, .session_handle = 22, .node_id = 31,
        .idempotency_key = {1}};
    size_t frame_size = 0;
    memset(payload, 0, 120);
    memcpy(payload, "VMC1", 4);
    put64(payload + 8, 1);
    put64(payload + 16, 2);
    put32(payload + 24, 22);
    put64(payload + 32, 31);
    payload[40] = 1;
    assert(vireo_node_remove_response_encode(&response, payload + 56, 64, &frame_size) == VIREO_OK);
    assert(frame_size == 64);
    put32(payload + 28, (uint32_t)frame_size);
    *out_size = 56 + frame_size;
}

static void error_payload(unsigned char payload[88], size_t *out_size, uint32_t sequence) {
    vireo_node_remove_response_t response = {.status = VIREO_STATUS_DB_ERROR, .sequence = sequence};
    size_t frame_size = 0;
    memset(payload, 0, 88);
    memcpy(payload, "VMC1", 4);
    put64(payload + 8, 1);
    put64(payload + 16, 2);
    put32(payload + 24, 22);
    put64(payload + 32, 31);
    payload[40] = 1;
    assert(vireo_node_remove_response_encode(&response, payload + 56, 32, &frame_size) == VIREO_OK);
    assert(frame_size == 32);
    put32(payload + 28, (uint32_t)frame_size);
    *out_size = 56 + frame_size;
}

static void check(unsigned char const *bytes, size_t size, uint32_t operation,
                  vireo_result_t result, vireo_status_t status, int expected) {
    vireo_task_metadata_t request = request_metadata();
    vireo_completion_metadata_t metadata;
    request.operation = operation;
    assert(vireo_task_metadata_make(request.route, request.request_instance_id, operation,
                                   request.deadline_ns, &request) == VIREO_OK);
    assert(vireo_completion_metadata_make(request, result, status, &metadata) == VIREO_OK);
    vireo_completion_t *completion = NULL;
    errno = EDOM;
    vireo_result_t create = vireo_completion_create_copy(metadata, bytes, size, 4096, &completion);
    assert(errno == EDOM);
    if (create != VIREO_OK) {
        assert(create == VIREO_RESULT_RANGE && completion == NULL);
        return;
    }

    vireo_directory_remove_completion_outcome_t out;
    vireo_directory_remove_completion_outcome_t before;
    memset(&out, 0xa5, sizeof(out));
    memcpy(&before, &out, sizeof(out));
    errno = EDOM;
    vireo_result_t rc = vireo_directory_remove_completion_decode(completion, REMOVE_OPERATION, &out);
    assert(errno == EDOM);
    if (expected == 1)
        assert(rc == VIREO_OK);
    if (expected == 0)
        assert(rc == VIREO_RESULT_PROTOCOL);
    if (rc != VIREO_OK)
        assert(rc == VIREO_RESULT_PROTOCOL && memcmp(&before, &out, sizeof(out)) == 0);
    else {
        assert(out.actor.user_id == 1 && out.actor.session_id == 2);
        if (status == VIREO_STATUS_OK) {
            assert(out.request_session_handle == 22 && out.request_node_id == 31);
            assert(out.response.status == VIREO_STATUS_OK && out.response.node_id == 31);
            assert(out.response.idempotency_key[0] == 1);
        } else {
            assert(out.request_session_handle == 22 && out.request_node_id == 31);
            assert(out.response.status == status && out.response.session_handle == 0);
            assert(out.response.node_id == 0 && out.response.idempotency_key[0] == 0);
        }
    }
    assert(vireo_completion_destroy(&completion) == VIREO_OK && completion == NULL);
}

int LLVMFuzzerTestOneInput(uint8_t const *data, size_t size) {
    if (size > MAX_INPUT) {
        check(data, size, REMOVE_OPERATION, VIREO_OK, VIREO_STATUS_OK, -1);
        return 0;
    }
    if (size > 1)
        check(data + 1, size - 1, REMOVE_OPERATION, VIREO_OK, VIREO_STATUS_OK, -1);
    unsigned char structured[120];
    size_t structured_size = 0;
    unsigned mode = size == 0 ? 0U : data[0] % 13U;
    size_t length = 0;
    uint32_t operation = REMOVE_OPERATION;
    vireo_result_t result = VIREO_OK;
    vireo_status_t status = VIREO_STATUS_OK;
    valid_payload(structured, &structured_size, mode == 8 ? 12U : 11U);
    switch (mode) {
        case 1: structured[0] ^= 1U; break;
        case 2: structured[4] = 1; break;
        case 3: memset(structured + 8, 0, 8); break;
        case 4: memset(structured + 16, 0, 8); break;
        case 5: memset(structured + 24, 0, 4); break;
        case 6: memset(structured + 32, 0, 8); break;
        case 7: memset(structured + 40, 0, 16); break;
        case 8: structured[119] ^= 1U; break;
        case 9: length = 88; break;
        case 10: operation = REMOVE_OPERATION + 1U; break;
        case 11:
            result = VIREO_RESULT_DATABASE;
            status = VIREO_STATUS_DB_ERROR;
            error_payload(structured, &structured_size, 11);
            break;
        case 12: structured[39] ^= 1U; break;
        default: break;
    }
    check(structured, length ? length : structured_size, operation, result, status,
          mode == 0 || mode == 11 ? 1 : 0);
    return 0;
}
