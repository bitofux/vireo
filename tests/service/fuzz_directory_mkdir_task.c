/* PROJECT : VIREO; FILE : fuzz_directory_mkdir_task.c; AUTHOR : bitofux;
 * DATE : 2026-10-24; BRIEF : VMT1任意字节/结构化关联、输出保持与owner释放。 */
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <vireo/service/directory_mkdir_task.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

/** @brief 借用已核定8字节，按字节累积，无未对齐访问或越宽移位。 */
static uint64_t number(const unsigned char *p) {
    uint64_t n = 0;
    for (size_t i = 0; i < 8; ++i)
        n = n * UINT64_C(256) + p[i];
    return n;
}

/** @brief 写入调用者独占的8字节，不保存借用。 */
static void store(unsigned char *p, uint64_t n) {
    for (size_t i = 8; i > 0; --i) {
        p[i - 1] = (unsigned char)(n & UINT64_C(255));
        n >>= 8;
    }
}

/** @brief 生产合法opaque前的元数据；控制区至少32字节，无资源/外部身份承诺。 */
static vireo_task_metadata_t metadata(const unsigned char *p) {
    vireo_task_metadata_t m;
    const vireo_task_route_t route = {number(p) | 1, p[1], number(p + 8) | 1,
                                      (uint32_t)p[2] + 1};
    assert(vireo_task_metadata_make(route, number(p + 16) | 1, 400, number(p + 24), &m) ==
           VIREO_OK);
    return m;
}

/** @brief 独立包络预期；内层wire合法性明确依赖公开codec，不调用被测read。 */
static vireo_result_t expected(const unsigned char *p, size_t n, vireo_task_metadata_t m,
                               uint32_t op, vireo_node_mkdir_request_t *request) {
    if (!op)
        return VIREO_RESULT_INVALID_ARGUMENT;
    if (n < 93 || n > 347 || m.operation != op)
        return VIREO_RESULT_PROTOCOL;
    static const unsigned char prefix[8] = {'V', 'M', 'T', '1', 0, 0, 0, 0};
    if (memcmp(p, prefix, 8) || !number(p + 8) || !number(p + 16))
        return VIREO_RESULT_PROTOCOL;
    vireo_node_mkdir_issue_t issue;
    if (vireo_node_mkdir_request_decode(p + 24, n - 24, request, &issue) != VIREO_OK ||
        !request->session_handle || request->sequence != m.route.request_sequence)
        return VIREO_RESULT_PROTOCOL;
    return VIREO_OK;
}

/** @brief 本次输入复制为唯一owner；失败保持/errno、成功语义及销毁均须成立。 */
static void check(const unsigned char *p, size_t n, vireo_task_metadata_t m, uint32_t op) {
    assert(n <= VIREO_TASK_MAX_ALLOCATION_BYTES - 4096);
    vireo_task_t *owner = NULL;
    errno = EDOM;
    assert(vireo_task_create_copy(m, p, n, n + 4096, &owner) == VIREO_OK && owner &&
           errno == EDOM);
    vireo_node_mkdir_request_t request = {0};
    const vireo_result_t want = expected(p, n, m, op, &request);
    vireo_directory_mkdir_input_t out, before;
    memset(&out, 0xa5, sizeof(out));
    memcpy(&before, &out, sizeof(out));
    vireo_node_mkdir_issue_t issue = VIREO_NODE_MKDIR_ISSUE_VALUE;
    errno = EDOM;
    assert(vireo_directory_mkdir_task_read(owner, op, &out, &issue) == want && errno == EDOM);
    if (want != VIREO_OK) {
        assert(!memcmp(&out, &before, sizeof(out)));
        assert(op ? issue != VIREO_NODE_MKDIR_ISSUE_NONE
                  : issue == VIREO_NODE_MKDIR_ISSUE_NONE);
    } else {
        assert(issue == VIREO_NODE_MKDIR_ISSUE_NONE);
        assert(out.metadata.route.client_owner_id == m.route.client_owner_id &&
               out.metadata.route.client_slot_index == m.route.client_slot_index &&
               out.metadata.route.client_generation == m.route.client_generation &&
               out.metadata.route.request_sequence == m.route.request_sequence &&
               out.metadata.request_instance_id == m.request_instance_id &&
               out.metadata.operation == m.operation && out.metadata.deadline_ns == m.deadline_ns);
        assert(out.actor.user_id == number(p + 8) && out.actor.session_id == number(p + 16));
        assert(out.request.sequence == request.sequence &&
               out.request.session_handle == request.session_handle &&
               out.request.parent_id == request.parent_id &&
               out.request.name_length == request.name_length &&
               !memcmp(out.request.name, request.name, request.name_length) &&
               !memcmp(out.request.idempotency_key, request.idempotency_key, 16));
    }
    vireo_task_payload_view_t view;
    assert(vireo_task_borrow_payload(owner, &view) == VIREO_OK && view.size == n);
    assert(!n || !memcmp(view.data, p, n));
    errno = EDOM;
    assert(vireo_task_destroy(&owner) == VIREO_OK && !owner && errno == EDOM);
}

/** @brief 原样分支不修复输入；结构化分支每次至多破坏一个关联，触达深层门禁。 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    const unsigned char empty[32] = {0};
    const unsigned char *control = size >= 32 ? data : empty;
    vireo_task_metadata_t m = metadata(control);
    check(size >= 32 ? data + 32 : data, size >= 32 ? size - 32 : size, m,
          control[7] == 255 ? 0 : 400);
    if (size < 32)
        return 0;
    unsigned char bytes[348] = {'V', 'M', 'T', '1', 0, 0, 0, 0};
    store(bytes + 8, number(control + 8) | 1);
    store(bytes + 16, number(control + 16) | 1);
    const unsigned mutation = control[6] % 12U;
    vireo_node_mkdir_request_t r = {.sequence = m.route.request_sequence,
                                   .session_handle = (uint32_t)control[3] + 1,
                                   .parent_id = number(control + 8) | 1,
                                   .name_length = (size_t)(control[4] % 255U) + 1};
    memset(r.name, 'a' + control[5] % 26, r.name_length);
    memcpy(r.idempotency_key, control + 16, 16);
    r.idempotency_key[0] |= 1;
    if (mutation == 7)
        r.session_handle = 0;
    size_t length = 0;
    assert(vireo_node_mkdir_request_encode(&r, bytes + 24, 323, &length) == VIREO_OK);
    length += 24;
    uint32_t op = 400;
    switch (mutation) {
        case 1: bytes[0] ^= 1; break;
        case 2: bytes[4] = 1; break;
        case 3: memset(bytes + 8, 0, 8); break;
        case 4: memset(bytes + 16, 0, 8); break;
        case 5: op = 401; break;
        case 6: ++m.route.request_sequence; break;
        case 8: bytes[52] ^= 1; break; /* inner CRC */
        case 9: --length; break;
        case 10: bytes[length++] = 0; break;
        case 11: m.operation = 401; break;
        default: break;
    }
    check(bytes, length, m, op);
    return 0;
}
