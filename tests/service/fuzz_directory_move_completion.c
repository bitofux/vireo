/* PROJECT : VIREO; FILE : fuzz_directory_move_completion.c; AUTHOR : bitofux;
 * DATE : 2026-10-25; BRIEF : MVC1包络与metadata配对；内层依赖公开wire codec。 */
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <vireo/service/directory_move_completion.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

/** @brief 借用已核定8字节，通过乘加读取大端，无对齐要求。 */
static uint64_t number(const unsigned char *p) {
    uint64_t n = 0;
    for (size_t i = 0; i < 8; ++i)
        n = n * UINT64_C(256) + p[i];
    return n;
}

/** @brief 借用至少n字节，n仅4或8，写入低位的大端形式。 */
static void store(unsigned char *p, uint64_t value, size_t n) {
    for (size_t i = n; i > 0; --i) {
        p[i - 1] = (unsigned char)(value & UINT64_C(255));
        value >>= 8;
    }
}

/** @brief 已核定长度后按有效字节检查非零，不读取结构padding。 */
static bool nonzero(const unsigned char *p, size_t n) {
    for (size_t i = 0; i < n; ++i)
        if (p[i])
            return true;
    return false;
}

/* 声明式rc/status合同，独立于生产project()/pair()及被测decode。 */
static const struct {
    vireo_result_t result;
    vireo_status_t status;
} pairs[] = {
    {VIREO_OK, VIREO_STATUS_OK},
    {VIREO_RESULT_INVALID_ARGUMENT, VIREO_STATUS_INTERNAL_ERROR},
    {VIREO_RESULT_RANGE, VIREO_STATUS_CONFLICT},
    {VIREO_RESULT_RANGE, VIREO_STATUS_INTERNAL_ERROR},
    {VIREO_RESULT_OVERFLOW, VIREO_STATUS_INTERNAL_ERROR},
    {VIREO_RESULT_NO_MEMORY, VIREO_STATUS_OVERLOADED},
    {VIREO_RESULT_NO_MEMORY, VIREO_STATUS_INTERNAL_ERROR},
    {VIREO_RESULT_NOT_FOUND, VIREO_STATUS_UNAUTHORIZED},
    {VIREO_RESULT_NOT_FOUND, VIREO_STATUS_NOT_FOUND},
    {VIREO_RESULT_NOT_FOUND, VIREO_STATUS_INTERNAL_ERROR},
    {VIREO_RESULT_BUSY, VIREO_STATUS_BUSY},
    {VIREO_RESULT_BUSY, VIREO_STATUS_INTERNAL_ERROR},
    {VIREO_RESULT_TIMEOUT, VIREO_STATUS_TIMEOUT},
    {VIREO_RESULT_TIMEOUT, VIREO_STATUS_INTERNAL_ERROR},
    {VIREO_RESULT_CANCELLED, VIREO_STATUS_UNAVAILABLE},
    {VIREO_RESULT_CANCELLED, VIREO_STATUS_INTERNAL_ERROR},
    {VIREO_RESULT_IO, VIREO_STATUS_INTERNAL_ERROR},
    {VIREO_RESULT_PROTOCOL, VIREO_STATUS_INVALID_PATH},
    {VIREO_RESULT_PROTOCOL, VIREO_STATUS_INTERNAL_ERROR},
    {VIREO_RESULT_DATABASE, VIREO_STATUS_FORBIDDEN},
    {VIREO_RESULT_DATABASE, VIREO_STATUS_CONFLICT},
    {VIREO_RESULT_DATABASE, VIREO_STATUS_DB_ERROR},
    {VIREO_RESULT_DATABASE, VIREO_STATUS_INTERNAL_ERROR},
    {VIREO_RESULT_INTERNAL, VIREO_STATUS_INTERNAL_ERROR}
};

/** @brief 独立包络预期；只有内层完整响应schema依赖公开codec。 */
static vireo_result_t expected(const unsigned char *p, size_t n, vireo_completion_metadata_t m,
                               uint32_t op, vireo_node_move_response_t *response) {
    if (!op)
        return VIREO_RESULT_INVALID_ARGUMENT;
    if ((n != 88 && n != 120) || m.request.operation != op)
        return VIREO_RESULT_PROTOCOL;
    static const unsigned char prefix[8] = {'M', 'V', 'C', '1', 0, 0, 0, 0};
    if (memcmp(p, prefix, 8) || !number(p + 8) || !number(p + 16) ||
        !nonzero(p + 24, 4) || !number(p + 32) || !nonzero(p + 40, 16))
        return VIREO_RESULT_PROTOCOL;
    /* 固定总长只允许对应的内长，拒绝高字节非零，不对随机长度做加法。 */
    if (p[28] || p[29] || p[30] || p[31] != n - 56)
        return VIREO_RESULT_PROTOCOL;
    vireo_node_move_issue_t issue;
    if (vireo_node_move_response_decode(p + 56, n - 56, response, &issue) != VIREO_OK ||
        response->sequence != m.request.route.request_sequence ||
        response->status != m.suggested_status)
        return VIREO_RESULT_PROTOCOL;
    bool allowed = false;
    for (size_t i = 0; i < sizeof(pairs) / sizeof(pairs[0]); ++i)
        allowed |= pairs[i].result == m.result && pairs[i].status == response->status;
    if (!allowed)
        return VIREO_RESULT_PROTOCOL;
    if (response->status == VIREO_STATUS_OK) {
        unsigned char handle[4];
        store(handle, response->session_handle, 4);
        if (memcmp(handle, p + 24, 4) || response->node_id != number(p + 32) ||
            memcmp(response->idempotency_key, p + 40, 16))
            return VIREO_RESULT_PROTOCOL;
    }
    return VIREO_OK;
}

/** @brief 复制为合法opaque完成对象，再核关联、失败保持、errno及销毁。 */
static void check(const unsigned char *p, size_t n, vireo_completion_metadata_t m, uint32_t op) {
    assert(n <= VIREO_COMPLETION_MAX_ALLOCATION_BYTES - 4096);
    vireo_completion_t *owner = NULL;
    errno = EDOM;
    assert(vireo_completion_create_copy(m, p, n, n + 4096, &owner) == VIREO_OK && owner &&
           errno == EDOM);
    vireo_node_move_response_t r = {0};
    const vireo_result_t want = expected(p, n, m, op, &r);
    vireo_directory_move_completion_outcome_t out, before;
    memset(&out, 0xa5, sizeof(out));
    memcpy(&before, &out, sizeof(out));
    errno = EDOM;
    assert(vireo_directory_move_completion_decode(owner, op, &out) == want && errno == EDOM);
    if (want != VIREO_OK)
        assert(!memcmp(&before, &out, sizeof(out)));
    else {
        const vireo_task_metadata_t a = out.metadata.request, b = m.request;
        assert(a.route.client_owner_id == b.route.client_owner_id &&
               a.route.client_slot_index == b.route.client_slot_index &&
               a.route.client_generation == b.route.client_generation &&
               a.route.request_sequence == b.route.request_sequence &&
               a.request_instance_id == b.request_instance_id && a.operation == b.operation &&
               a.deadline_ns == b.deadline_ns && out.metadata.result == m.result &&
               out.metadata.suggested_status == m.suggested_status);
        unsigned char handle[4];
        store(handle, out.request_session_handle, 4);
        assert(out.actor.user_id == number(p + 8) && out.actor.session_id == number(p + 16) &&
               !memcmp(handle, p + 24, 4) && out.request_node_id == number(p + 32) &&
               !memcmp(out.request_idempotency_key, p + 40, 16));
        assert(out.response.sequence == r.sequence && out.response.status == r.status &&
               out.response.session_handle == r.session_handle && out.response.node_id == r.node_id &&
               !memcmp(out.response.idempotency_key, r.idempotency_key, 16));
    }
    vireo_completion_payload_view_t view;
    assert(vireo_completion_borrow_payload(owner, &view) == VIREO_OK && view.size == n);
    assert(!n || !memcmp(view.data, p, n));
    errno = EDOM;
    assert(vireo_completion_destroy(&owner) == VIREO_OK && !owner && errno == EDOM);
}

/* 独立注册状态全集；与十三种已知result交叉生成，不只抽取成功配对。 */
static const vireo_status_t statuses[] = {0,1001,1002,1004,1005,1006,1007,1008,1101,1201,
    1102,1203,1206,1901,1902,1904,1906,1907,1908};

/** @brief 原样payload与结构化合法内层两路；自洽变换不等于原请求认证。 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    const unsigned char empty[32] = {0};
    const unsigned char *p = size >= 32 ? data : empty;
    vireo_task_metadata_t request;
    const vireo_task_route_t route = {number(p) | 1, p[1], number(p + 8) | 1,
                                      (uint32_t)p[2] + 1};
    assert(vireo_task_metadata_make(route, number(p + 16) | 1, 400, number(p + 24), &request) ==
           VIREO_OK);
    vireo_completion_metadata_t m;
    assert(vireo_completion_metadata_make(request, (vireo_result_t)(p[4] % 13U),
           statuses[p[5] % (sizeof(statuses) / sizeof(statuses[0]))], &m) == VIREO_OK);
    check(size >= 32 ? data + 32 : data, size >= 32 ? size - 32 : size, m,
          p[7] == 255 ? 0 : 400);
    if (size < 32)
        return 0;
    unsigned char bytes[121] = {'M', 'V', 'C', '1', 0, 0, 0, 0};
    store(bytes + 8, number(p + 8) | 1, 8);
    store(bytes + 16, number(p + 16) | 1, 8);
    const uint32_t handle = (uint32_t)p[3] + 1;
    store(bytes + 24, handle, 4);
    const uint64_t source = number(p + 24) | 1;
    store(bytes + 32, source, 8);
    memcpy(bytes + 40, p + 16, 16);
    bytes[40] |= 1;
    vireo_node_move_response_t r = {.sequence = request.route.request_sequence,
                                  .status = m.suggested_status};
    if (r.status == VIREO_STATUS_OK) {
        r.session_handle = handle;
        r.node_id = source;
        memcpy(r.idempotency_key, bytes + 40, 16);
    }
    size_t length = 0;
    assert(vireo_node_move_response_encode(&r, bytes + 56, 64, &length) == VIREO_OK);
    store(bytes + 28, length, 4);
    length += 56;
    uint32_t op = 400;
    switch (p[6] % 24U) {
        case 1: bytes[0] ^= 1; break;
        case 2: bytes[4] = 1; break;
        case 3: memset(bytes + 8, 0, 8); break;
        case 4: memset(bytes + 16, 0, 8); break;
        case 5: memset(bytes + 24, 0, 4); break;
        case 6: memset(bytes + 40, 0, 16); break;
        case 7: bytes[31] ^= 1; break;
        case 8: bytes[55] ^= 2; break;
        case 9: ++m.request.route.request_sequence; break;
        case 10: m.request.operation = 401; break;
        case 11: op = 401; break;
        case 12: m.suggested_status = r.status == VIREO_STATUS_OK ? VIREO_STATUS_TIMEOUT : VIREO_STATUS_OK; break;
        case 13: m.result = m.result == VIREO_OK ? VIREO_RESULT_IO : VIREO_OK; break;
        case 14: --length; break;
        case 15: bytes[length++] = 0; break;
        case 16: memset(bytes + 32, 0, 8); break;
        case 17: bytes[39] ^= 2; break; /* 只改外层source，OK应拒绝。 */
        case 18: bytes[84] ^= 1; break; /* 内层CRC。 */
        case 19: bytes[24] ^= 2; break;
        case 20: bytes[8] ^= 2; break; /* 非零actor变化仍可结构自洽。 */
        case 21:
            if (r.status == VIREO_STATUS_OK) {
                r.node_id ^= 2;
                store(bytes + 32, r.node_id, 8);
            }
            break;
        case 22:
            if (r.status == VIREO_STATUS_OK) {
                r.idempotency_key[15] ^= 2;
                memcpy(bytes + 40, r.idempotency_key, 16);
            }
            break;
        case 23: bytes[28] = 1; break;
        default: break;
    }
    if ((p[6] % 24U == 21 || p[6] % 24U == 22) && r.status == VIREO_STATUS_OK) {
        size_t inner_size = 0;
        assert(vireo_node_move_response_encode(&r, bytes + 56, 64, &inner_size) == VIREO_OK);
        assert(inner_size + 56 == length);
    }
    check(bytes, length, m, op);
    return 0;
}
