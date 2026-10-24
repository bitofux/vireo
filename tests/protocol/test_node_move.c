/* PROJECT : VIREO; FILE : test_node_move.c; AUTHOR : bitofux; DATE : 2026-10-24;
 * BRIEF : 独立wire样例与协议合同边界，不执行移动业务。 */
#include <vireo/protocol/node_move.h>
#include <vireo/protocol/codec.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct golden {
    char const *name;
    bool response, valid;
    vireo_node_move_issue_t issue;
    size_t canonical, size;
    unsigned char wire[400];
} golden_t;
#include "node_move_test_vectors.h"

static unsigned long checks;
#define CHECK(expr) do { ++checks; if (!(expr)) { \
    fprintf(stderr, "line %d: %s\n", __LINE__, #expr); abort(); } } while (0)
#define CALL(expr, expected) do { errno = EDOM; vireo_result_t call_rc = (expr); \
    CHECK(call_rc == (expected)); CHECK(errno == EDOM); } while (0)

static bool zero(unsigned char const *p, size_t n) {
    for (size_t i = 0; i < n; ++i) if (p[i] != 0) return false;
    return true;
}

/* 只用公共CRC修复变异帧，golden的期望字节独立生成。 */
static void put32(unsigned char *p, uint32_t v) {
    for (unsigned i = 0; i < 4; ++i) p[i] = (unsigned char)(v >> (24U - 8U * i));
}
static void repair(unsigned char *wire, size_t n) {
    put32(wire + 12, (uint32_t)(n - 32));
    uint32_t crc;
    CALL(vireo_protocol_frame_crc32c_calculate(wire, 32, wire + 32, n - 32, &crc), VIREO_OK);
    put32(wire + 28, crc);
}

static bool allowed(unsigned status) {
    switch (status) {
    case 0: case 1001: case 1002: case 1004: case 1005: case 1006: case 1007: case 1008:
    case 1101: case 1102: case 1201: case 1203: case 1206: case 1901: case 1902:
    case 1904: case 1906: case 1907: case 1908: return true;
    default: return false;
    }
}

/* 每次拒绝均比较out所有字节（含padding），防止半发布。 */
static void rejected(bool response, unsigned char const *wire, size_t n, vireo_node_move_issue_t expected) {
    vireo_node_move_issue_t issue = VIREO_NODE_MOVE_ISSUE_NONE;
    if (response) {
        vireo_node_move_response_t out, old;
        memset(&out, 0xa5, sizeof out); memcpy(&old, &out, sizeof old);
        CALL(vireo_node_move_response_decode(wire, n, &out, &issue), VIREO_RESULT_PROTOCOL);
        CHECK(memcmp(&out, &old, sizeof out) == 0);
    } else {
        vireo_node_move_request_t out, old;
        memset(&out, 0xa5, sizeof out); memcpy(&old, &out, sizeof old);
        CALL(vireo_node_move_request_decode(wire, n, &out, &issue), VIREO_RESULT_PROTOCOL);
        CHECK(memcmp(&out, &old, sizeof out) == 0);
    }
    CHECK(issue != VIREO_NODE_MOVE_ISSUE_NONE);
    if (expected != VIREO_NODE_MOVE_ISSUE_NONE) {
        if (issue != expected) fprintf(stderr, "diagnostic: response=%d size=%zu actual=%d expected=%d\n",
                                      response, n, (int)issue, (int)expected);
        CHECK(issue == expected);
    }
}

static void expected_request(vireo_node_move_request_t const *q, golden_t const *canonical) {
    CHECK(q->sequence == 7 && q->session_handle == 9 && q->node_id == 20 && q->new_parent_id == 30);
    CHECK(q->new_name_length == canonical->size - 80);
    CHECK(memcmp(q->new_name, canonical->wire + 80, q->new_name_length) == 0);
    CHECK(zero(q->new_name + q->new_name_length, 255 - q->new_name_length));
    for (size_t j = 0; j < 16; ++j) CHECK(q->idempotency_key[j] == j + 1);
}

static void expected_response(vireo_node_move_response_t const *v, golden_t const *g) {
    unsigned const status = (unsigned)g->wire[10] * 256 + g->wire[11];
    CHECK(v->sequence == 7 && v->status == status);
    CHECK(v->session_handle == (status == 0 ? 9U : 0U));
    CHECK(v->node_id == (status == 0 ? 20U : 0U));
    for (size_t j = 0; j < 16; ++j) CHECK(v->idempotency_key[j] == (status == 0 ? j + 1 : 0));
}

static void vectors(void) {
    for (size_t i = 0; i < sizeof goldens / sizeof goldens[0]; ++i) {
        golden_t const *g = &goldens[i], *canonical = &goldens[g->canonical];
        unsigned char *input = malloc(g->size);
        CHECK(input != NULL); memcpy(input, g->wire, g->size);
        if (!g->valid) { rejected(g->response, input, g->size, g->issue); free(input); continue; }
        unsigned char wire[700], old[700]; size_t n = 999;
        memset(wire, 0xa5, sizeof wire); memcpy(old, wire, sizeof old);
        vireo_node_move_issue_t issue = VIREO_NODE_MOVE_ISSUE_VALUE;
        if (g->response) {
            vireo_node_move_response_t value;
            CALL(vireo_node_move_response_decode(input, g->size, &value, &issue), VIREO_OK);
            expected_response(&value, g); memset(input, 0, g->size); expected_response(&value, g);
            CALL(vireo_node_move_response_encode(&value, wire, g->size - 1, &n), VIREO_RESULT_RANGE);
            CHECK(n == 999 && memcmp(wire, old, sizeof wire) == 0);
            CALL(vireo_node_move_response_encode(&value, wire, g->size, &n), VIREO_OK);
        } else {
            vireo_node_move_request_t value;
            CALL(vireo_node_move_request_decode(input, g->size, &value, &issue), VIREO_OK);
            expected_request(&value, canonical); memset(input, 0, g->size); expected_request(&value, canonical);
            CALL(vireo_node_move_request_encode(&value, wire, g->size - 1, &n), VIREO_RESULT_RANGE);
            CHECK(n == 999 && memcmp(wire, old, sizeof wire) == 0);
            CALL(vireo_node_move_request_encode(&value, wire, g->size, &n), VIREO_OK);
        }
        CHECK(issue == VIREO_NODE_MOVE_ISSUE_NONE && n == g->size);
        CHECK(memcmp(wire, canonical->wire, n) == 0);
        CHECK(memcmp(wire + n, old + n, sizeof wire - n) == 0);
        free(input);
        for (size_t j = 0; j < g->size; ++j) {
            /* 实际长度分配使ASan能够发现截断帧的越界读取。 */
            input = malloc(j == 0 ? 1 : j); CHECK(input != NULL);
            memcpy(input, g->wire, j); rejected(g->response, input, j, VIREO_NODE_MOVE_ISSUE_NONE); free(input);
        }
        memcpy(wire, g->wire, g->size); wire[g->size] = 0;
        rejected(g->response, wire, g->size + 1, VIREO_NODE_MOVE_ISSUE_ENVELOPE);
        memcpy(wire + g->size, g->wire, g->size);
        rejected(g->response, wire, 2 * g->size, VIREO_NODE_MOVE_ISSUE_ENVELOPE);
        for (size_t j = 28; j < g->size; ++j) {
            for (unsigned bit = 0; bit < 8; ++bit) {
                memcpy(wire, g->wire, g->size); wire[j] ^= (unsigned char)(1U << bit);
                rejected(g->response, wire, g->size, VIREO_NODE_MOVE_ISSUE_CRC);
            }
        }
    }
}

static void bad_request(vireo_node_move_request_t const *q) {
    unsigned char wire[400], old[400]; memset(wire, 0xa5, sizeof wire); memcpy(old, wire, sizeof wire);
    size_t n = 999;
    CALL(vireo_node_move_request_encode(q, wire, 0, &n), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(n == 999 && memcmp(wire, old, sizeof wire) == 0);
    CALL(vireo_node_move_request_encode(q, wire, sizeof wire, &n), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(n == 999 && memcmp(wire, old, sizeof wire) == 0);
}
static void bad_response(vireo_node_move_response_t const *v) {
    unsigned char wire[400], old[400]; memset(wire, 0xa5, sizeof wire); memcpy(old, wire, sizeof wire);
    size_t n = 999;
    CALL(vireo_node_move_response_encode(v, wire, 0, &n), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(n == 999 && memcmp(wire, old, sizeof wire) == 0);
    CALL(vireo_node_move_response_encode(v, wire, sizeof wire, &n), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(n == 999 && memcmp(wire, old, sizeof wire) == 0);
}

static void names_and_host(void) {
    vireo_node_move_request_t base, q;
    vireo_node_move_response_t v, response;
    vireo_node_move_issue_t issue;
    CALL(vireo_node_move_request_decode(goldens[0].wire, goldens[0].size, &base, &issue), VIREO_OK);
#define BAD_Q(change) do { q = base; change; bad_request(&q); } while (0)
    BAD_Q(q.sequence = 0); BAD_Q(q.new_parent_id = 0); BAD_Q(q.node_id = 0); BAD_Q(q.new_name_length = 0);
    BAD_Q(q.new_name_length = SIZE_MAX); BAD_Q(q.new_name_length = 256);
    BAD_Q(memset(q.idempotency_key, 0, 16)); BAD_Q(q.new_name_length = 2; memcpy(q.new_name, "..", 2));
#undef BAD_Q
    unsigned char wire[400]; size_t n;
    /* 穷举单字节名，高位字节独自出现不是合法UTF-8。 */
    for (unsigned c = 0; c < 256; ++c) {
        q = base; q.new_name[0] = (unsigned char)c;
        bool const valid = c >= 32 && c < 127 && c != '/' && c != '.';
        if (!valid) { bad_request(&q); continue; }
        CALL(vireo_node_move_request_encode(&q, wire, sizeof wire, &n), VIREO_OK);
        CHECK(n == 81);
        CALL(vireo_node_move_request_decode(wire, n, &q, &issue), VIREO_OK);
        CHECK(q.new_name[0] == c && q.new_name_length == 1 && zero(q.new_name + 1, 254));
    }
    /* C1控制码虽编码合法仍拒绝，U+00A0允许。 */
    for (unsigned c = 0x80; c <= 0x9f; ++c) {
        q = base; q.new_name_length = 2; q.new_name[0] = 0xc2; q.new_name[1] = (unsigned char)c; bad_request(&q);
    }
    static unsigned char const unicode_names[][4] = {
        {0xc2,0xa0,0,0}, {0xe4,0xb8,0xad,0}, {0xed,0x9f,0xbf,0},
        {0xee,0x80,0x80,0}, {0xf4,0x8f,0xbf,0xbf}, {0x65,0xcc,0x81,0}
    };
    static size_t const lengths[] = {2,3,3,3,4,3};
    for (size_t j = 0; j < sizeof lengths / sizeof lengths[0]; ++j) {
        q = base; q.new_name_length = lengths[j]; memcpy(q.new_name, unicode_names[j], lengths[j]);
        CALL(vireo_node_move_request_encode(&q, wire, sizeof wire, &n), VIREO_OK);
        CALL(vireo_node_move_request_decode(wire, n, &q, &issue), VIREO_OK);
        CHECK(q.new_name_length == lengths[j] && memcmp(q.new_name, unicode_names[j], lengths[j]) == 0);
    }
    /* 全部合法字节长度、未用尾部忽略和整数/键上界。 */
    for (size_t len = 1; len <= 255; ++len) {
        q = base; q.new_name_length = len; memset(q.new_name, 'x', len); memset(q.new_name + len, 0xff, 255 - len);
        q.sequence = UINT32_MAX; q.session_handle = UINT32_MAX; q.new_parent_id = UINT64_MAX; q.node_id = UINT64_MAX;
        memset(q.idempotency_key, 0xff, 16);
        CALL(vireo_node_move_request_encode(&q, wire, sizeof wire, &n), VIREO_OK);
        CHECK(n == 80 + len);
        CALL(vireo_node_move_request_decode(wire, n, &q, &issue), VIREO_OK);
        CHECK(q.sequence == UINT32_MAX && q.session_handle == UINT32_MAX && q.new_parent_id == UINT64_MAX && q.node_id == UINT64_MAX);
        CHECK(q.new_name_length == len && zero(q.new_name + len, 255 - len));
    }
    for (size_t byte = 0; byte < 16; ++byte) {
        q = base; memset(q.idempotency_key, 0, 16); q.idempotency_key[byte] = 1;
        CALL(vireo_node_move_request_encode(&q, wire, sizeof wire, &n), VIREO_OK);
    }
    /* 相同源/目标ID在codec合法，防环留给事务。 */
    q = base; q.new_parent_id = q.node_id;
    CALL(vireo_node_move_request_encode(&q, wire, sizeof wire, &n), VIREO_OK);
    CALL(vireo_node_move_request_decode(wire, n, &q, &issue), VIREO_OK);
    CHECK(q.node_id == 20 && q.new_parent_id == 20);
    q = base; q.session_handle = 0;
    CALL(vireo_node_move_request_encode(&q, wire, sizeof wire, &n), VIREO_OK);
    CALL(vireo_node_move_request_decode(wire, n, &q, &issue), VIREO_OK); CHECK(q.session_handle == 0);
    CALL(vireo_node_move_response_decode(goldens[4].wire, 64, &response, &issue), VIREO_OK);
#define BAD_V(change) do { v = response; change; bad_response(&v); } while (0)
    BAD_V(v.sequence = 0); BAD_V(v.session_handle = 0); BAD_V(v.node_id = 0);
    BAD_V(memset(v.idempotency_key, 0, 16));
#undef BAD_V
    response = (vireo_node_move_response_t){.status = VIREO_STATUS_TIMEOUT, .sequence = 7};
#define BAD_V(change) do { v = response; change; bad_response(&v); } while (0)
    BAD_V(v.sequence = 0); BAD_V(v.session_handle = 1); BAD_V(v.node_id = 1);
    for (size_t j = 0; j < 16; ++j) { BAD_V(v.idempotency_key[j] = 1); }
#undef BAD_V
    v = (vireo_node_move_response_t){.sequence=UINT32_MAX, .session_handle=UINT32_MAX, .node_id=UINT64_MAX};
    memset(v.idempotency_key, 0xff, 16);
    CALL(vireo_node_move_response_encode(&v, wire, sizeof wire, &n), VIREO_OK);
    CALL(vireo_node_move_response_decode(wire, n, &v, &issue), VIREO_OK);
    CHECK(v.sequence == UINT32_MAX && v.session_handle == UINT32_MAX && v.node_id == UINT64_MAX);
}

static void headers(void) {
    unsigned char wire[400], old[400]; memset(old, 0xa5, sizeof old);
    /* 穷举宿主状态和错误帧全部16位状态，成功必须有body。 */
    for (unsigned s = 0; s <= UINT16_MAX; ++s) {
        vireo_node_move_response_t v = {.status=(uint16_t)s, .sequence=7};
        size_t n = 999; memset(wire, 0xa5, sizeof wire);
        bool const valid = s != 0 && allowed(s);
        CALL(vireo_node_move_response_encode(&v, wire, sizeof wire, &n), valid ? VIREO_OK : VIREO_RESULT_INVALID_ARGUMENT);
        if (valid) CHECK(n == 32);
        else CHECK(n == 999 && memcmp(wire, old, sizeof wire) == 0);
        memcpy(wire, goldens[5].wire, 32); wire[10] = (unsigned char)(s >> 8); wire[11] = (unsigned char)s; repair(wire, 32);
        if (valid) {
            vireo_node_move_issue_t issue;
            CALL(vireo_node_move_response_decode(wire, 32, &v, &issue), VIREO_OK);
            CHECK(v.status == s && issue == VIREO_NODE_MOVE_ISSUE_NONE);
            CHECK(v.session_handle == 0 && v.node_id == 0 && zero(v.idempotency_key, 16));
        } else rejected(true, wire, 32, VIREO_NODE_MOVE_ISSUE_NONE);
    }
    for (unsigned direction = 0; direction < 2; ++direction) {
        golden_t const *g = &goldens[direction == 0 ? 0 : 4];
        for (unsigned f = 0; f <= UINT16_MAX; ++f) {
            if (f == direction) continue;
            memcpy(wire, g->wire, g->size); wire[8] = (unsigned char)(f >> 8); wire[9] = (unsigned char)f; repair(wire, g->size);
            rejected(direction != 0, wire, g->size, VIREO_NODE_MOVE_ISSUE_NONE);
        }
        for (unsigned byte = 0; byte < 4; ++byte) {
            memcpy(wire, g->wire, g->size); wire[12 + byte] = 0xff;
            rejected(direction != 0, wire, g->size, VIREO_NODE_MOVE_ISSUE_NONE);
        }
    }
}

static void capacities_and_null(void) {
    unsigned char wire[400], old[400]; memset(old, 0xa5, sizeof old);
    for (size_t which = 0; which < 4; ++which) {
        golden_t const *g = &goldens[which == 0 ? 1 : which == 1 ? 2 : which == 2 ? 4 : 5];
        vireo_node_move_request_t q; vireo_node_move_response_t v; vireo_node_move_issue_t issue;
        if (g->response) CALL(vireo_node_move_response_decode(g->wire, g->size, &v, &issue), VIREO_OK);
        else CALL(vireo_node_move_request_decode(g->wire, g->size, &q, &issue), VIREO_OK);
        for (size_t cap = 0; cap <= sizeof wire; ++cap) {
            size_t n = 999; memcpy(wire, old, sizeof wire);
            vireo_result_t const expected = cap < g->size ? VIREO_RESULT_RANGE : VIREO_OK;
            if (g->response) CALL(vireo_node_move_response_encode(&v, wire, cap, &n), expected);
            else CALL(vireo_node_move_request_encode(&q, wire, cap, &n), expected);
            if (expected != VIREO_OK) CHECK(n == 999 && memcmp(wire, old, sizeof wire) == 0);
            else CHECK(n == g->size && memcmp(wire, g->wire, n) == 0 && memcmp(wire + n, old + n, sizeof wire - n) == 0);
        }
    }
    vireo_node_move_request_t q, old_q; vireo_node_move_response_t v, old_v;
    memset(&q, 0xa5, sizeof q); memcpy(&old_q, &q, sizeof q);
    memset(&v, 0xa5, sizeof v); memcpy(&old_v, &v, sizeof v);
    vireo_node_move_issue_t issue; size_t n = 999; memcpy(wire, old, sizeof wire);
#define NULL_DECODE(fn, object, before) do { \
    issue = VIREO_NODE_MOVE_ISSUE_VALUE; CALL(fn(NULL, 0, &object, &issue), VIREO_RESULT_INVALID_ARGUMENT); \
    CHECK(issue == VIREO_NODE_MOVE_ISSUE_NONE); \
    issue = VIREO_NODE_MOVE_ISSUE_VALUE; CALL(fn(wire, 0, NULL, &issue), VIREO_RESULT_INVALID_ARGUMENT); \
    CHECK(issue == VIREO_NODE_MOVE_ISSUE_NONE); \
    CALL(fn(wire, 0, &object, NULL), VIREO_RESULT_INVALID_ARGUMENT); CHECK(memcmp(&object, &before, sizeof object) == 0); \
} while (0)
    NULL_DECODE(vireo_node_move_request_decode, q, old_q);
    NULL_DECODE(vireo_node_move_response_decode, v, old_v);
#undef NULL_DECODE
#define NULL_ENCODE(fn, object) do { \
    CALL(fn(NULL, wire, sizeof wire, &n), VIREO_RESULT_INVALID_ARGUMENT); \
    CALL(fn(&object, NULL, sizeof wire, &n), VIREO_RESULT_INVALID_ARGUMENT); \
    CALL(fn(&object, wire, sizeof wire, NULL), VIREO_RESULT_INVALID_ARGUMENT); \
} while (0)
    NULL_ENCODE(vireo_node_move_request_encode, q);
    NULL_ENCODE(vireo_node_move_response_encode, v);
#undef NULL_ENCODE
    CHECK(n == 999 && memcmp(wire, old, sizeof wire) == 0);
}

static void large_inputs(void) {
    size_t const size = (size_t)1024 * 1024;
    unsigned char *wire = calloc(size, 1); CHECK(wire != NULL);
    memcpy(wire, goldens[0].wire, goldens[0].size);
    rejected(false, wire, size, VIREO_NODE_MOVE_ISSUE_ENVELOPE);
    rejected(true, wire, size, VIREO_NODE_MOVE_ISSUE_ENVELOPE);
    free(wire);
}

int main(void) {
    vectors(); names_and_host(); headers(); capacities_and_null(); large_inputs();
    printf("NODE_MOVE: %zu independent wire vectors; exhaustive u16 statuses/flags; %lu checks passed\n",
           sizeof goldens / sizeof goldens[0], checks);
    return 0;
}
