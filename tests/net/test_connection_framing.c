/*
- PROJECT : VIREO
- FILE    : test_connection_framing.c
- AUTHOR  : bitofux
- DATE    : 2026-10-04
- BRIEF   : 此模块负责：
- -- 通过真实 socketpair 与公开 receive 验证帧拆分、CRC 和双预算
- -- 验证只读批次、错误前缀输出、EOF 和显式消费的资源边界
 */
#define _GNU_SOURCE
#include <vireo/net/connection.h>

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static unsigned failures;
#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition); \
        ++failures; \
    } \
} while (0)
#define REQUIRE(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "%s:%d: required %s\n", __FILE__, __LINE__, #condition); \
        exit(2); \
    } \
} while (0)

typedef struct fixture {
    vireo_connection_t *connection;
    int peer;
    vireo_connection_frame_options_t options;
    vireo_connection_frame_budget_t budget;
    vireo_connection_frame_view_t views[8];
    vireo_connection_frame_info_t info;
    vireo_connection_frame_error_t error;
} fixture_t;

/* 公开构造与真实 peer；不读取 connection/buffer 私有布局。 */
static fixture_t fixture_create(size_t capacity)
{
    fixture_t f = {0};
    int sockets[2];
    REQUIRE(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, sockets) == 0);
    vireo_connection_options_t options = {capacity, 1, capacity + 1};
    REQUIRE(vireo_connection_create(&options, &sockets[0], &f.connection, NULL) == VIREO_OK);
    REQUIRE(sockets[0] == -1);
    f.peer = sockets[1];
    f.options = (vireo_connection_frame_options_t){VIREO_CONNECTION_FRAME_REQUEST, capacity};
    f.budget = (vireo_connection_frame_budget_t){8, SIZE_MAX};
    memset(f.views, 0xA5, sizeof(f.views));
    return f;
}

static void fixture_destroy(fixture_t *f)
{
    CHECK(vireo_connection_destroy(&f->connection, NULL) == VIREO_OK);
    CHECK(f->connection == NULL);
    CHECK(close(f->peer) == 0);
}

/* 小量确定字节通过内核流进入公开 receive，避免伪造 read_buffer 状态。 */
static void feed(fixture_t *f, uint8_t const *bytes, size_t size)
{
    size_t sent = 0;
    while (sent < size) {
        ssize_t n = send(f->peer, bytes + sent, size - sent, MSG_NOSIGNAL);
        REQUIRE(n > 0);
        sent += (size_t)n;
    }
    vireo_connection_receive_budget_t budget = {SIZE_MAX, 64};
    vireo_connection_receive_info_t info;
    REQUIRE(vireo_connection_receive(f->connection, &budget, &info, NULL) == VIREO_OK);
    REQUIRE(info.received_bytes == size);
}

static void observe_eof(fixture_t *f)
{
    REQUIRE(shutdown(f->peer, SHUT_WR) == 0);
    vireo_connection_receive_budget_t budget = {SIZE_MAX, 8};
    vireo_connection_receive_info_t info;
    REQUIRE(vireo_connection_receive(f->connection, &budget, &info, NULL) == VIREO_OK);
    REQUIRE(info.stop_reason == VIREO_CONNECTION_RECEIVE_STOP_EOF);
}

static vireo_protocol_header_t request_header(uint32_t sequence)
{
    vireo_protocol_header_t header = {0};
    header.command = VIREO_COMMAND_PING;
    header.sequence = sequence;
    header.status = VIREO_PROTOCOL_REQUEST_STATUS;
    return header;
}

/* 正确 wire 由封板公共 encode/calculate 构造，CRC 坏例在最终编码后改字节。 */
static size_t make_frame(uint8_t *wire, size_t capacity, vireo_protocol_header_t header,
                         uint8_t const *body, size_t body_size)
{
    REQUIRE(body_size <= VIREO_PROTOCOL_MAX_BODY_SIZE && capacity >= 32 + body_size);
    header.body_len = (uint32_t)body_size;
    header.crc32c = 0;
    REQUIRE(vireo_protocol_header_encode(&header, wire, capacity) == VIREO_OK);
    if (body_size != 0) {
        memcpy(wire + 32, body, body_size);
    }
    REQUIRE(vireo_protocol_frame_crc32c_calculate(wire, 32, body, body_size,
                                                 &header.crc32c) == VIREO_OK);
    REQUIRE(vireo_protocol_header_encode(&header, wire, capacity) == VIREO_OK);
    return 32 + body_size;
}

/* 每次解析验证 errno、原字节地址/内容、长度与头洞均未改变。 */
static void parse(fixture_t *f, size_t capacity, vireo_result_t result, size_t count,
                   size_t bytes, vireo_connection_frame_stop_t stop,
                   vireo_connection_frame_issue_t issue, vireo_protocol_codec_issue_t codec)
{
    vireo_connection_info_t before, after;
    uint8_t const *old_data, *new_data;
    size_t old_size, new_size;
    REQUIRE(vireo_connection_inspect(f->connection, &before) == VIREO_OK);
    REQUIRE(vireo_connection_read_peek(f->connection, &old_data, &old_size) == VIREO_OK);
    uint8_t snapshot[20000];
    REQUIRE(old_size <= sizeof(snapshot));
    if (old_size != 0) {
        memcpy(snapshot, old_data, old_size);
    }
    unsigned char old_views[sizeof(f->views)];
    memcpy(old_views, f->views, sizeof(old_views));
    f->error = (vireo_connection_frame_error_t){VIREO_CONNECTION_FRAME_ISSUE_TRUNCATED,
                                               VIREO_PROTOCOL_CODEC_ISSUE_CRC_MISMATCH};
    errno = E2BIG;
    CHECK(vireo_connection_frames_peek(f->connection, &f->options, &f->budget, f->views,
                                        capacity, &f->info, &f->error) == result);
    CHECK(errno == E2BIG);
    CHECK(f->info.frame_count == count && f->info.frame_bytes == bytes);
    CHECK(f->info.stop_reason == stop);
    CHECK(f->error.issue == issue && f->error.codec_issue == codec);
    REQUIRE(count <= sizeof(f->views) / sizeof(f->views[0]));
    size_t written = count * sizeof(f->views[0]);
    CHECK(memcmp((unsigned char const *)f->views + written, old_views + written,
                 sizeof(old_views) - written) == 0);
    REQUIRE(vireo_connection_inspect(f->connection, &after) == VIREO_OK);
    REQUIRE(vireo_connection_read_peek(f->connection, &new_data, &new_size) == VIREO_OK);
    CHECK(old_data == new_data && old_size == new_size);
    CHECK(before.read_buffer.capacity == after.read_buffer.capacity);
    CHECK(before.read_buffer.readable_size == after.read_buffer.readable_size);
    CHECK(before.read_buffer.tail_space == after.read_buffer.tail_space);
    CHECK(before.write_buffer.readable_size == after.write_buffer.readable_size);
    CHECK(before.read_eof == after.read_eof);
    if (old_size != 0) {
        CHECK(memcmp(old_data, snapshot, old_size) == 0);
    }
}

static void parse_ok(fixture_t *f, size_t capacity, size_t count, size_t bytes,
                      vireo_connection_frame_stop_t stop)
{
    parse(f, capacity, VIREO_OK, count, bytes, stop, VIREO_CONNECTION_FRAME_ISSUE_NONE,
          VIREO_PROTOCOL_CODEC_ISSUE_NONE);
}

static void test_empty_and_eof(void)
{
    fixture_t f = fixture_create(128);
    parse_ok(&f, 8, 0, 0, VIREO_CONNECTION_FRAME_STOP_NEED_MORE);
    observe_eof(&f);
    parse_ok(&f, 8, 0, 0, VIREO_CONNECTION_FRAME_STOP_EOF);
    fixture_destroy(&f);
}

/* 覆盖全部31种头内切点，补齐后按同一 sequence/body 精确识别。 */
static void test_every_header_split(void)
{
    uint8_t wire[35];
    uint8_t const body[] = {0, 1, 255};
    make_frame(wire, sizeof(wire), request_header(7), body, sizeof(body));
    for (size_t split = 1; split < 32; ++split) {
        fixture_t f = fixture_create(128);
        feed(&f, wire, split);
        parse_ok(&f, 8, 0, 0, VIREO_CONNECTION_FRAME_STOP_NEED_MORE);
        feed(&f, wire + split, sizeof(wire) - split);
        parse_ok(&f, 8, 1, 35, VIREO_CONNECTION_FRAME_STOP_NEED_MORE);
        CHECK(f.views[0].header.sequence == 7 && f.views[0].body_size == 3);
        CHECK(memcmp(f.views[0].body, body, 3) == 0);
        fixture_destroy(&f);
    }
}

static void test_body_splits(void)
{
    uint8_t wire[35];
    uint8_t const body[] = {5, 0, 8};
    make_frame(wire, sizeof(wire), request_header(2), body, 3);
    for (size_t split = 32; split < 35; ++split) {
        fixture_t f = fixture_create(128);
        feed(&f, wire, split);
        parse_ok(&f, 8, 0, 0, VIREO_CONNECTION_FRAME_STOP_NEED_MORE);
        feed(&f, wire + split, 35 - split);
        parse_ok(&f, 8, 1, 35, VIREO_CONNECTION_FRAME_STOP_NEED_MORE);
        CHECK(memcmp(f.views[0].body, body, 3) == 0);
        fixture_destroy(&f);
    }
}

static void test_sticky_and_partial_consumption(void)
{
    uint8_t wire[99];
    uint8_t const body[] = {1};
    for (uint32_t i = 0; i < 3; ++i) {
        make_frame(wire + (size_t)i * 33, 33, request_header(i + 1), body, 1);
    }
    fixture_t f = fixture_create(128);
    feed(&f, wire, 76); /* A/B完整，C只有10字节头。 */
    parse_ok(&f, 8, 2, 66, VIREO_CONNECTION_FRAME_STOP_NEED_MORE);
    CHECK(f.views[0].header.sequence == 1 && f.views[1].header.sequence == 2);
    CHECK(f.views[0].body != f.views[1].body);
    REQUIRE(vireo_connection_read_consume(f.connection, 33) == VIREO_OK);
    parse_ok(&f, 8, 1, 33, VIREO_CONNECTION_FRAME_STOP_NEED_MORE);
    CHECK(f.views[0].header.sequence == 2);
    REQUIRE(vireo_connection_read_consume(f.connection, 33) == VIREO_OK);
    feed(&f, wire + 76, 23);
    parse_ok(&f, 8, 1, 33, VIREO_CONNECTION_FRAME_STOP_NEED_MORE);
    CHECK(f.views[0].header.sequence == 3);
    fixture_destroy(&f);
}

static void test_empty_body_exact_capacity(void)
{
    uint8_t wire[32];
    make_frame(wire, 32, request_header(1), NULL, 0);
    fixture_t f = fixture_create(32);
    f.budget.max_bytes = 32;
    feed(&f, wire, 32);
    parse_ok(&f, 8, 1, 32, VIREO_CONNECTION_FRAME_STOP_NEED_MORE);
    CHECK(f.views[0].body == NULL && f.views[0].body_size == 0 && f.views[0].wire_size == 32);
    REQUIRE(vireo_connection_read_consume(f.connection, 32) == VIREO_OK);
    observe_eof(&f);
    parse_ok(&f, 8, 0, 0, VIREO_CONNECTION_FRAME_STOP_EOF);
    fixture_destroy(&f);
}

static void test_binary_large_body(void)
{
    uint8_t body[8193], wire[8225];
    for (size_t i = 0; i < sizeof(body); ++i) {
        body[i] = (uint8_t)(i % 256);
    }
    make_frame(wire, sizeof(wire), request_header(UINT32_MAX), body, sizeof(body));
    fixture_t f = fixture_create(10000);
    feed(&f, wire, sizeof(wire));
    parse_ok(&f, 8, 1, sizeof(wire), VIREO_CONNECTION_FRAME_STOP_NEED_MORE);
    CHECK(f.views[0].header.sequence == UINT32_MAX);
    CHECK(f.views[0].body_size == sizeof(body));
    CHECK(memcmp(f.views[0].body, body, sizeof(body)) == 0);
    fixture_destroy(&f);
}

static void test_message_and_output_budgets(void)
{
    uint8_t wire[64];
    make_frame(wire, 32, request_header(1), NULL, 0);
    make_frame(wire + 32, 32, request_header(2), NULL, 0);
    fixture_t f = fixture_create(128);
    feed(&f, wire, sizeof(wire));
    f.budget.max_messages = 1;
    parse_ok(&f, 8, 1, 32, VIREO_CONNECTION_FRAME_STOP_MESSAGE_BUDGET);
    parse_ok(&f, 1, 1, 32, VIREO_CONNECTION_FRAME_STOP_MESSAGE_BUDGET);
    f.budget.max_messages = SIZE_MAX;
    parse_ok(&f, 1, 1, 32, VIREO_CONNECTION_FRAME_STOP_OUTPUT_FULL);
    parse_ok(&f, 8, 2, 64, VIREO_CONNECTION_FRAME_STOP_NEED_MORE);
    fixture_destroy(&f);
}

static void test_byte_budget_and_whole_frames(void)
{
    uint8_t wire[70], body[3] = {0, 1, 2};
    make_frame(wire, 35, request_header(1), body, 3);
    make_frame(wire + 35, 35, request_header(2), body, 3);
    fixture_t f = fixture_create(128);
    feed(&f, wire, 70);
    f.options.max_frame_bytes = 35;
    size_t const budgets[] = {35, 64, 69, 70};
    for (size_t i = 0; i < 4; ++i) {
        f.budget.max_bytes = budgets[i];
        parse_ok(&f, 8, i == 3 ? 2 : 1, i == 3 ? 70 : 35,
                 i == 3 ? VIREO_CONNECTION_FRAME_STOP_NEED_MORE :
                          VIREO_CONNECTION_FRAME_STOP_BYTE_BUDGET);
    }
    fixture_destroy(&f);
}

static void test_output_tail_and_repeated_peek(void)
{
    uint8_t wire[33], body[1] = {99};
    make_frame(wire, 33, request_header(1), body, 1);
    fixture_t f = fixture_create(128);
    feed(&f, wire, 33);
    unsigned char tail[7 * sizeof(f.views[0])];
    memcpy(tail, &f.views[1], sizeof(tail));
    parse_ok(&f, 8, 1, 33, VIREO_CONNECTION_FRAME_STOP_NEED_MORE);
    uint8_t const *borrow = f.views[0].body;
    parse_ok(&f, 8, 1, 33, VIREO_CONNECTION_FRAME_STOP_NEED_MORE);
    CHECK(borrow == f.views[0].body && *borrow == 99);
    CHECK(memcmp(&f.views[1], tail, sizeof(tail)) == 0);
    CHECK(vireo_connection_read_consume(f.connection, 34) == VIREO_RESULT_RANGE);
    CHECK(*borrow == 99); /* 失败consume未结束借用。 */
    fixture_destroy(&f);
}

static void test_fixed_header_errors(void)
{
    vireo_protocol_codec_issue_t const issues[] = {
        VIREO_PROTOCOL_CODEC_ISSUE_INVALID_MAGIC, VIREO_PROTOCOL_CODEC_ISSUE_VERSION_MISMATCH,
        VIREO_PROTOCOL_CODEC_ISSUE_INVALID_HEADER_LENGTH, VIREO_PROTOCOL_CODEC_ISSUE_BODY_TOO_LARGE
    };
    for (size_t i = 0; i < 4; ++i) {
        uint8_t wire[32];
        make_frame(wire, 32, request_header(1), NULL, 0);
        if (i == 0) { wire[0] ^= 1; }
        if (i == 1) { wire[4] = 2; }
        if (i == 2) { wire[5] = 31; }
        if (i == 3) { wire[12] = 1; wire[15] = 1; }
        fixture_t f = fixture_create(128);
        feed(&f, wire, 32);
        parse(&f, 8, VIREO_RESULT_PROTOCOL, 0, 0, VIREO_CONNECTION_FRAME_STOP_ERROR,
              VIREO_CONNECTION_FRAME_ISSUE_CODEC, issues[i]);
        fixture_destroy(&f);
    }
}

static void test_request_semantic_errors(void)
{
    vireo_protocol_codec_issue_t const issues[] = {
        VIREO_PROTOCOL_CODEC_ISSUE_UNKNOWN_FLAGS, VIREO_PROTOCOL_CODEC_ISSUE_UNKNOWN_COMMAND,
        VIREO_PROTOCOL_CODEC_ISSUE_RESERVED_COMMAND, VIREO_PROTOCOL_CODEC_ISSUE_INVALID_SEQUENCE,
        VIREO_PROTOCOL_CODEC_ISSUE_REQUEST_HAS_RESPONSE_FLAG,
        VIREO_PROTOCOL_CODEC_ISSUE_REQUEST_HAS_MORE_FLAG,
        VIREO_PROTOCOL_CODEC_ISSUE_INVALID_REQUEST_STATUS
    };
    for (size_t i = 0; i < 7; ++i) {
        uint8_t wire[32];
        vireo_protocol_header_t h = request_header(1);
        if (i == 0) { h.flags = UINT16_C(0x8000); }
        if (i == 1) { h.command = UINT16_C(0xFFFF); }
        if (i == 2) { h.command = VIREO_COMMAND_STORAGE_PUT_RESERVED_FIRST; }
        if (i == 3) { h.sequence = 0; }
        if (i == 4) { h.flags = VIREO_PROTOCOL_FLAG_RESPONSE; }
        if (i == 5) { h.flags = VIREO_PROTOCOL_FLAG_MORE; }
        if (i == 6) { h.status = 1; }
        make_frame(wire, 32, h, NULL, 0);
        fixture_t f = fixture_create(128);
        feed(&f, wire, 32);
        parse(&f, 8, VIREO_RESULT_PROTOCOL, 0, 0, VIREO_CONNECTION_FRAME_STOP_ERROR,
              VIREO_CONNECTION_FRAME_ISSUE_CODEC, issues[i]);
        fixture_destroy(&f);
    }
}

static void test_response_mode_and_errors(void)
{
    for (unsigned i = 0; i < 4; ++i) {
        uint8_t wire[32];
        vireo_protocol_header_t h = request_header(1);
        h.flags = VIREO_PROTOCOL_FLAG_RESPONSE | VIREO_PROTOCOL_FLAG_MORE;
        h.status = 0;
        if (i == 1) { h.flags = 0; }
        if (i == 2) { h.status = UINT16_C(0xFFFF); }
        make_frame(wire, 32, h, NULL, 0);
        fixture_t f = fixture_create(128);
        if (i != 3) { f.options.direction = VIREO_CONNECTION_FRAME_RESPONSE; }
        feed(&f, wire, 32);
        if (i == 0) {
            parse_ok(&f, 8, 1, 32, VIREO_CONNECTION_FRAME_STOP_NEED_MORE);
        } else {
            vireo_protocol_codec_issue_t issue = i == 1 ?
                VIREO_PROTOCOL_CODEC_ISSUE_RESPONSE_MISSING_RESPONSE_FLAG : i == 2 ?
                VIREO_PROTOCOL_CODEC_ISSUE_UNKNOWN_RESPONSE_STATUS :
                VIREO_PROTOCOL_CODEC_ISSUE_REQUEST_HAS_RESPONSE_FLAG;
            parse(&f, 8, VIREO_RESULT_PROTOCOL, 0, 0, VIREO_CONNECTION_FRAME_STOP_ERROR,
                  VIREO_CONNECTION_FRAME_ISSUE_CODEC, issue);
        }
        fixture_destroy(&f);
    }
}

static void test_connection_limit_early(void)
{
    uint8_t wire[32];
    vireo_protocol_header_t h = request_header(1);
    h.body_len = 97; /* 129整帧，128区永远放不下；没有body也应立即拒绝。 */
    REQUIRE(vireo_protocol_header_encode(&h, wire, 32) == VIREO_OK);
    fixture_t f = fixture_create(128);
    feed(&f, wire, 32);
    parse(&f, 8, VIREO_RESULT_PROTOCOL, 0, 0, VIREO_CONNECTION_FRAME_STOP_ERROR,
          VIREO_CONNECTION_FRAME_ISSUE_FRAME_TOO_LARGE, VIREO_PROTOCOL_CODEC_ISSUE_NONE);
    f.options.max_frame_bytes = 32;
    parse(&f, 8, VIREO_RESULT_PROTOCOL, 0, 0, VIREO_CONNECTION_FRAME_STOP_ERROR,
          VIREO_CONNECTION_FRAME_ISSUE_FRAME_TOO_LARGE, VIREO_PROTOCOL_CODEC_ISSUE_NONE);
    fixture_destroy(&f);
}

static void test_crc_body_header_and_field(void)
{
    for (unsigned i = 0; i < 3; ++i) {
        uint8_t wire[33], body[1] = {4};
        make_frame(wire, 33, request_header(1), body, 1);
        wire[i == 0 ? 32 : i == 1 ? 18 : 31] ^= 1;
        fixture_t f = fixture_create(128);
        feed(&f, wire, 33);
        parse(&f, 8, VIREO_RESULT_PROTOCOL, 0, 0, VIREO_CONNECTION_FRAME_STOP_ERROR,
              VIREO_CONNECTION_FRAME_ISSUE_CODEC, VIREO_PROTOCOL_CODEC_ISSUE_CRC_MISMATCH);
        fixture_destroy(&f);
    }
}

static void test_valid_prefix_before_bad_crc(void)
{
    uint8_t wire[66], body[1] = {6};
    make_frame(wire, 33, request_header(1), body, 1);
    make_frame(wire + 33, 33, request_header(2), body, 1);
    wire[65] ^= 1;
    fixture_t f = fixture_create(128);
    feed(&f, wire, 66);
    unsigned char untouched[7 * sizeof(f.views[0])];
    memcpy(untouched, &f.views[1], sizeof(untouched));
    parse(&f, 8, VIREO_RESULT_PROTOCOL, 1, 33, VIREO_CONNECTION_FRAME_STOP_ERROR,
          VIREO_CONNECTION_FRAME_ISSUE_CODEC, VIREO_PROTOCOL_CODEC_ISSUE_CRC_MISMATCH);
    CHECK(f.views[0].header.sequence == 1 && *f.views[0].body == 6);
    CHECK(memcmp(&f.views[1], untouched, sizeof(untouched)) == 0);
    REQUIRE(vireo_connection_read_consume(f.connection, 33) == VIREO_OK);
    parse(&f, 8, VIREO_RESULT_PROTOCOL, 0, 0, VIREO_CONNECTION_FRAME_STOP_ERROR,
          VIREO_CONNECTION_FRAME_ISSUE_CODEC, VIREO_PROTOCOL_CODEC_ISSUE_CRC_MISMATCH);
    fixture_destroy(&f);
}

static void test_eof_partial_header_body_and_prefix(void)
{
    uint8_t wire[67], body[3] = {1, 2, 3};
    make_frame(wire, 32, request_header(1), NULL, 0);
    make_frame(wire + 32, 35, request_header(2), body, 3);
    size_t const sizes[] = {1, 31, 64, 66, 67};
    for (size_t i = 0; i < 5; ++i) {
        fixture_t f = fixture_create(128);
        feed(&f, wire, sizes[i]);
        observe_eof(&f);
        if (i == 4) {
            parse_ok(&f, 8, 2, 67, VIREO_CONNECTION_FRAME_STOP_EOF);
        } else {
            parse(&f, 8, VIREO_RESULT_PROTOCOL, i < 2 ? 0 : 1, i < 2 ? 0 : 32,
                  VIREO_CONNECTION_FRAME_STOP_ERROR, VIREO_CONNECTION_FRAME_ISSUE_TRUNCATED,
                  VIREO_PROTOCOL_CODEC_ISSUE_NONE);
        }
        fixture_destroy(&f);
    }
}

static void test_budget_defers_errors(void)
{
    uint8_t wire[64];
    make_frame(wire, 32, request_header(1), NULL, 0);
    make_frame(wire + 32, 32, request_header(2), NULL, 0);
    wire[32] = 0;
    fixture_t f = fixture_create(128);
    feed(&f, wire, 64);
    observe_eof(&f);
    f.budget.max_messages = 1;
    parse_ok(&f, 8, 1, 32, VIREO_CONNECTION_FRAME_STOP_MESSAGE_BUDGET);
    f.budget.max_messages = 8;
    f.options.max_frame_bytes = 32;
    f.budget.max_bytes = 32;
    parse_ok(&f, 8, 1, 32, VIREO_CONNECTION_FRAME_STOP_BYTE_BUDGET);
    f.budget.max_bytes = 64;
    parse(&f, 8, VIREO_RESULT_PROTOCOL, 1, 32, VIREO_CONNECTION_FRAME_STOP_ERROR,
          VIREO_CONNECTION_FRAME_ISSUE_CODEC, VIREO_PROTOCOL_CODEC_ISSUE_INVALID_MAGIC);
    fixture_destroy(&f);
}

/* 参数拒绝整体输出保持、已有借用保持；不比较有效记录的结构 padding。 */
static void test_parameter_rejection(void)
{
    fixture_t f = fixture_create(128);
    uint8_t wire[33], body[1] = {77};
    make_frame(wire, 33, request_header(1), body, 1);
    feed(&f, wire, 33);
    uint8_t const *borrow;
    size_t size;
    REQUIRE(vireo_connection_read_peek(f.connection, &borrow, &size) == VIREO_OK);
    for (unsigned i = 0; i < 13; ++i) {
        vireo_connection_frame_options_t options = f.options;
        vireo_connection_frame_budget_t budget = f.budget;
        size_t capacity = 8;
        memset(&f.info, 0x5A, sizeof(f.info));
        unsigned char saved_info[sizeof(f.info)], saved_views[sizeof(f.views)];
        memcpy(saved_info, &f.info, sizeof(saved_info));
        memcpy(saved_views, f.views, sizeof(saved_views));
        if (i == 5) { options.direction = (vireo_connection_frame_direction_t)99; }
        if (i == 6) { capacity = 0; }
        if (i == 7) { budget.max_messages = 0; }
        if (i == 8) { budget.max_bytes = 0; }
        if (i == 9) { options.max_frame_bytes = 31; }
        if (i == 10) { options.max_frame_bytes = 129; }
        if (i == 11) { options.max_frame_bytes = SIZE_MAX; }
        if (i == 12) { budget.max_bytes = 127; }
        errno = 0;
        CHECK(vireo_connection_frames_peek(i == 0 ? NULL : f.connection,
              i == 1 ? NULL : &options, i == 2 ? NULL : &budget,
              i == 3 ? NULL : f.views, capacity, i == 4 ? NULL : &f.info, &f.error) ==
              (i < 6 ? VIREO_RESULT_INVALID_ARGUMENT : VIREO_RESULT_RANGE));
        CHECK(errno == 0 && f.error.issue == VIREO_CONNECTION_FRAME_ISSUE_NONE);
        CHECK(f.error.codec_issue == VIREO_PROTOCOL_CODEC_ISSUE_NONE);
        CHECK(memcmp(saved_info, &f.info, sizeof(saved_info)) == 0);
        CHECK(memcmp(saved_views, f.views, sizeof(saved_views)) == 0);
        CHECK(size == 33 && memcmp(borrow, wire, 33) == 0);
    }
    fixture_destroy(&f);
}

static void test_capacity_and_protocol_boundaries(void)
{
    for (size_t capacity = 1; capacity < 32; capacity += 30) {
        fixture_t f = fixture_create(capacity);
        f.options.max_frame_bytes = 32;
        memset(&f.info, 0x5A, sizeof(f.info));
        unsigned char original[sizeof(f.info)];
        memcpy(original, &f.info, sizeof(original));
        CHECK(vireo_connection_frames_peek(f.connection, &f.options, &f.budget, f.views,
                                            8, &f.info, NULL) == VIREO_RESULT_RANGE);
        CHECK(memcmp(original, &f.info, sizeof(original)) == 0);
        fixture_destroy(&f);
    }
    /* 独立验证协议帧上限：读区略大于16MiB+32，不分配64MiB或构造巨body。 */
    size_t protocol_max = (size_t)VIREO_PROTOCOL_MAX_BODY_SIZE + 32;
    fixture_t f = fixture_create(protocol_max + 1);
    CHECK(vireo_connection_frames_peek(f.connection, &f.options, &f.budget, f.views,
                                        8, &f.info, NULL) == VIREO_RESULT_RANGE);
    f.options.max_frame_bytes = protocol_max;
    f.budget.max_bytes = protocol_max;
    parse_ok(&f, 8, 0, 0, VIREO_CONNECTION_FRAME_STOP_NEED_MORE);
    fixture_destroy(&f);
}

static void test_head_hole_null_diagnostic_and_two_connections(void)
{
    fixture_t a = fixture_create(128), b = fixture_create(128);
    uint8_t wire[66], one[1] = {1}, two[1] = {2};
    make_frame(wire, 33, request_header(1), one, 1);
    make_frame(wire + 33, 33, request_header(2), two, 1);
    feed(&a, wire, 66);
    feed(&b, wire, 33);
    REQUIRE(vireo_connection_read_consume(a.connection, 33) == VIREO_OK);
    parse_ok(&a, 8, 1, 33, VIREO_CONNECTION_FRAME_STOP_NEED_MORE);
    parse_ok(&b, 8, 1, 33, VIREO_CONNECTION_FRAME_STOP_NEED_MORE);
    CHECK(a.views[0].header.sequence == 2 && *a.views[0].body == 2);
    CHECK(b.views[0].header.sequence == 1 && *b.views[0].body == 1);
    CHECK(a.views[0].body != b.views[0].body);
    uint8_t const *b_borrow = b.views[0].body;
    errno = EDOM;
    CHECK(vireo_connection_frames_peek(a.connection, &a.options, &a.budget, a.views,
                                        8, &a.info, NULL) == VIREO_OK);
    CHECK(errno == EDOM && a.info.frame_count == 1);
    fixture_destroy(&a);
    CHECK(*b_borrow == 1);
    fixture_destroy(&b);
}

/* 头语义先于容量，容量先于EOF残帧；不完整body不得先核对CRC。 */
static void test_early_validation_and_deferred_crc(void)
{
    for (unsigned i = 0; i < 3; ++i) {
        fixture_t f = fixture_create(128);
        uint8_t wire[33], body[1] = {42};
        vireo_protocol_header_t header = request_header(1);
        if (i < 2) {
            header.body_len = 97;
            if (i == 0) { header.flags = UINT16_C(0x8000); }
            REQUIRE(vireo_protocol_header_encode(&header, wire, 32) == VIREO_OK);
        } else {
            make_frame(wire, 33, header, body, 1);
            wire[31] ^= 1;
        }
        feed(&f, wire, 32);
        if (i == 0) {
            parse(&f, 8, VIREO_RESULT_PROTOCOL, 0, 0, VIREO_CONNECTION_FRAME_STOP_ERROR,
                  VIREO_CONNECTION_FRAME_ISSUE_CODEC, VIREO_PROTOCOL_CODEC_ISSUE_UNKNOWN_FLAGS);
        } else if (i == 1) {
            observe_eof(&f);
            parse(&f, 8, VIREO_RESULT_PROTOCOL, 0, 0, VIREO_CONNECTION_FRAME_STOP_ERROR,
                  VIREO_CONNECTION_FRAME_ISSUE_FRAME_TOO_LARGE, VIREO_PROTOCOL_CODEC_ISSUE_NONE);
        } else {
            parse_ok(&f, 8, 0, 0, VIREO_CONNECTION_FRAME_STOP_NEED_MORE);
            feed(&f, wire + 32, 1);
            parse(&f, 8, VIREO_RESULT_PROTOCOL, 0, 0, VIREO_CONNECTION_FRAME_STOP_ERROR,
                  VIREO_CONNECTION_FRAME_ISSUE_CODEC, VIREO_PROTOCOL_CODEC_ISSUE_CRC_MISMATCH);
        }
        fixture_destroy(&f);
    }
}

static void test_repeated_frames_and_no_auto_close(void)
{
    fixture_t f = fixture_create(128);
    uint8_t wire[33], body[1] = {0};
    for (uint32_t i = 1; i <= 128; ++i) {
        body[0] = (uint8_t)i;
        make_frame(wire, 33, request_header(i), body, 1);
        feed(&f, wire, 33);
        parse_ok(&f, 8, 1, 33, VIREO_CONNECTION_FRAME_STOP_NEED_MORE);
        CHECK(*f.views[0].body == body[0] && f.views[0].header.sequence == i);
        REQUIRE(vireo_connection_read_consume(f.connection, 33) == VIREO_OK);
    }
    wire[32] ^= 1;
    feed(&f, wire, 33);
    errno = 0;
    CHECK(vireo_connection_frames_peek(f.connection, &f.options, &f.budget, f.views,
                                        8, &f.info, NULL) == VIREO_RESULT_PROTOCOL);
    CHECK(errno == 0 && f.info.frame_count == 0 && f.info.frame_bytes == 0);
    /* 坏帧未关socket，peer还可发送；调用者可显式丢弃，不由解析器偷偷重同步。 */
    REQUIRE(vireo_connection_read_consume(f.connection, 33) == VIREO_OK);
    wire[32] ^= 1;
    feed(&f, wire, 33);
    parse_ok(&f, 8, 1, 33, VIREO_CONNECTION_FRAME_STOP_NEED_MORE);
    fixture_destroy(&f);
}

static size_t fd_count(void)
{
    DIR *directory = opendir("/proc/self/fd");
    REQUIRE(directory != NULL);
    size_t count = 0;
    struct dirent *entry;
    while ((entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
            ++count;
        }
    }
    REQUIRE(closedir(directory) == 0);
    return count;
}

int main(void)
{
    size_t baseline = fd_count();
    void (*const tests[])(void) = {
        test_empty_and_eof, test_every_header_split, test_body_splits,
        test_sticky_and_partial_consumption, test_empty_body_exact_capacity,
        test_binary_large_body, test_message_and_output_budgets,
        test_byte_budget_and_whole_frames, test_output_tail_and_repeated_peek,
        test_fixed_header_errors, test_request_semantic_errors, test_response_mode_and_errors,
        test_connection_limit_early, test_crc_body_header_and_field,
        test_valid_prefix_before_bad_crc, test_eof_partial_header_body_and_prefix,
        test_budget_defers_errors, test_parameter_rejection,
        test_capacity_and_protocol_boundaries,
        test_head_hole_null_diagnostic_and_two_connections,
        test_early_validation_and_deferred_crc,
        test_repeated_frames_and_no_auto_close
    };
    size_t groups = sizeof(tests) / sizeof(tests[0]);
    for (size_t i = 0; i < groups; ++i) {
        tests[i]();
    }
    CHECK(fd_count() == baseline);
    printf("connection framing: %zu groups, %u failures\n", groups, failures);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
