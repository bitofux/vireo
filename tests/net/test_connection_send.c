/*
- PROJECT : VIREO
- FILE    : test_connection_send.c
- AUTHOR  : bitofux
- DATE    : 2026-10-04
- BRIEF   : 此模块负责：
- -- 真实 FIFO 排队/发送、预算、内核背压及读写借用独立性验证
- -- 本模块发送故障边界、资源配对及隔离进程 SIGPIPE 验证
 */
#define _GNU_SOURCE
#include <vireo/net/connection.h>
#include "net/connection_internal.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
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
    int owned_fd;
    bool public_api;
    size_t allocations, frees, buffers, destroys, closes;
    size_t calls, short_limit, fail_at;
    int fail_errno, anomaly;
    size_t requests[8];
    int flags[8];
} fixture_t;

static void *allocate_control(void *context, size_t bytes)
{
    fixture_t *f = context;
    ++f->allocations;
    return malloc(bytes);
}
static void free_control(void *context, void *memory)
{
    fixture_t *f = context;
    ++f->frees;
    free(memory);
}
static int get_flags(void *context, int fd, int command)
{
    (void)context;
    return fcntl(fd, command);
}
static int get_type(void *context, int fd, int *out_type)
{
    (void)context;
    socklen_t size = (socklen_t)sizeof(*out_type);
    return getsockopt(fd, SOL_SOCKET, SO_TYPE, out_type, &size);
}
static int get_peer(void *context, int fd)
{
    (void)context;
    struct sockaddr_storage peer;
    socklen_t size = (socklen_t)sizeof(peer);
    return getpeername(fd, (struct sockaddr *)&peer, &size);
}
static int close_socket(void *context, int fd)
{
    fixture_t *f = context;
    CHECK(fd == f->owned_fd);
    ++f->closes;
    return close(fd);
}
static vireo_result_t create_buffer(void *context, size_t capacity, vireo_buffer_t **out)
{
    fixture_t *f = context;
    ++f->buffers;
    return vireo_buffer_create(capacity, out);
}
static void destroy_buffer(void *context, vireo_buffer_t **owner)
{
    fixture_t *f = context;
    ++f->destroys;
    CHECK(vireo_buffer_destroy(owner) == VIREO_OK);
}
static ssize_t receive_bytes(void *context, int fd, void *bytes, size_t request, int flags)
{
    (void)context;
    return recv(fd, bytes, request, flags);
}

/**
 * @brief 记录预算层真实请求，必要时仅本模块注入数量/系统失败
 *
 * @param[in,out] context
 *     fixture 借用，逐对象计数与故障位置。
 * @param[in] fd
 *     fixture 对象独占的 socket。
 * @param[in] bytes
 *     本次有效只读借用；不保存、修改或跨返回使用。
 * @param[in] request
 *     原始正请求，<=4096。
 * @param[in] flags
 *     被测实现传入的两个必需 flags。
 *
 * @return 原 send 数量或确定注入结果。
 *
 * @note 限请求的短进度仍来自真实 send；异常数量不读超过实际请求的内存。
 */
static ssize_t send_bytes(void *context, int fd, void const *bytes, size_t request, int flags)
{
    fixture_t *f = context;
    CHECK(fd == f->owned_fd && request > 0 && request <= 4096);
    CHECK(flags == (MSG_DONTWAIT | MSG_NOSIGNAL));
    if (f->calls < 8) {
        f->requests[f->calls] = request;
        f->flags[f->calls] = flags;
    }
    ++f->calls;
    if (f->fail_at == f->calls) {
        errno = f->fail_errno;
        if (f->anomaly == 1) { return 0; }
        if (f->anomaly == 2) { return (ssize_t)request + 1; }
        if (f->anomaly == 3) { return -2; }
        return -1;
    }
    if (f->short_limit != 0 && request > f->short_limit) {
        request = f->short_limit;
    }
    return send(fd, bytes, request, flags);
}

/**
 * @brief 建立真实 stream，属性设置均在 owner 转移前
 *
 * @param[out] f
 *     调用者栈 fixture，须存活到销毁，private ops 借用其地址。
 * @param[in] capacity
 *     固定正写容量，读容量128。
 * @param[in] public_api
 *     true 使用正式构造/native sender，false 使用本模块逐对象 seam。
 * @param[in] small_socket
 *     true 在转移前设置小 SO_SNDBUF，用于真实 EAGAIN；不是进程配置。
 *
 * @note 私有 sender 不改变 fd 属性；不触及旧模块私有布局。
 */
static void fixture_create(fixture_t *f, size_t capacity, bool public_api, bool small_socket)
{
    *f = (fixture_t){0};
    int sockets[2];
    REQUIRE(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, sockets) == 0);
    if (small_socket) {
        int size = 1024;
        REQUIRE(setsockopt(sockets[0], SOL_SOCKET, SO_SNDBUF, &size, (socklen_t)sizeof(size)) == 0);
    }
    f->owned_fd = sockets[0];
    f->peer = sockets[1];
    f->public_api = public_api;
    vireo_connection_options_t options = {128, capacity, 128 + capacity};
    if (public_api) {
        REQUIRE(vireo_connection_create(&options, &sockets[0], &f->connection, NULL) == VIREO_OK);
    } else {
        vireo_connection_ops_t ops = {f, allocate_control, free_control, get_flags, get_type,
            get_peer, close_socket, create_buffer, destroy_buffer, receive_bytes, send_bytes};
        REQUIRE(vireo_connection_create_with_ops(&options, &sockets[0], &ops,
                                                  &f->connection, NULL) == VIREO_OK);
    }
    REQUIRE(sockets[0] == -1 && f->connection != NULL);
}

static void fixture_destroy(fixture_t *f)
{
    CHECK(vireo_connection_destroy(&f->connection, NULL) == VIREO_OK);
    CHECK(f->connection == NULL);
    if (f->peer >= 0) { CHECK(close(f->peer) == 0); }
    if (!f->public_api) {
        CHECK(f->allocations == 1 && f->frees == 1 && f->buffers == 2 && f->destroys == 2);
        CHECK(f->closes == 1);
    }
}

static vireo_connection_info_t state(fixture_t *f)
{
    vireo_connection_info_t info;
    REQUIRE(vireo_connection_inspect(f->connection, &info) == VIREO_OK);
    return info;
}

static void check_none(vireo_connection_error_t const *error)
{
    CHECK(error->stage == VIREO_CONNECTION_STAGE_NONE && error->system_errno == 0);
}

static void enqueue(fixture_t *f, void const *bytes, size_t size, vireo_result_t expected)
{
    vireo_connection_error_t error = {VIREO_CONNECTION_STAGE_SEND, EIO};
    vireo_connection_info_t before = state(f);
    errno = EDOM;
    CHECK(vireo_connection_write_enqueue(f->connection, bytes, size, &error) == expected);
    CHECK(errno == EDOM);
    check_none(&error);
    vireo_connection_info_t after = state(f);
    CHECK(before.read_buffer.readable_size == after.read_buffer.readable_size);
    CHECK(before.read_buffer.tail_space == after.read_buffer.tail_space);
    CHECK(before.read_eof == after.read_eof);
    CHECK(before.write_buffer.capacity == after.write_buffer.capacity);
    if (expected != VIREO_OK) {
        CHECK(before.write_buffer.readable_size == after.write_buffer.readable_size);
        CHECK(before.write_buffer.tail_space == after.write_buffer.tail_space);
    }
}

static vireo_connection_send_info_t transmit(fixture_t *f, size_t bytes, size_t calls,
                                            vireo_result_t result, size_t sent, size_t attempted,
                                            vireo_connection_send_stop_t stop, int cause)
{
    vireo_connection_send_budget_t budget = {bytes, calls};
    vireo_connection_send_info_t info;
    vireo_connection_error_t error = {VIREO_CONNECTION_STAGE_ENQUEUE, ENOMEM};
    vireo_connection_info_t before = state(f);
    errno = E2BIG;
    CHECK(vireo_connection_send(f->connection, &budget, &info, &error) == result);
    CHECK(errno == E2BIG);
    CHECK(info.sent_bytes == sent && info.send_calls == attempted && info.stop_reason == stop);
    CHECK(error.stage == (result == VIREO_OK ? VIREO_CONNECTION_STAGE_NONE :
                                              VIREO_CONNECTION_STAGE_SEND));
    CHECK(error.system_errno == cause);
    vireo_connection_info_t after = state(f);
    CHECK(before.write_buffer.readable_size == sent + after.write_buffer.readable_size);
    CHECK(before.read_buffer.readable_size == after.read_buffer.readable_size);
    CHECK(before.read_buffer.tail_space == after.read_buffer.tail_space);
    CHECK(before.read_eof == after.read_eof);
    return info;
}

/* 非阻塞读到当前可得的全部数据，调用者记录真实数量，避免等待制造测试挂起。 */
static size_t peer_drain(fixture_t *f, uint8_t *bytes, size_t capacity)
{
    size_t size = 0;
    while (size < capacity) {
        ssize_t n = recv(f->peer, bytes + size, capacity - size, MSG_DONTWAIT);
        if (n == -1) { REQUIRE(errno == EAGAIN || errno == EWOULDBLOCK); break; }
        REQUIRE(n > 0);
        size += (size_t)n;
    }
    return size;
}
static void peer_expect(fixture_t *f, void const *expected, size_t size)
{
    uint8_t bytes[20000];
    REQUIRE(size < sizeof(bytes));
    size_t actual = peer_drain(f, bytes, sizeof(bytes));
    CHECK(actual == size);
    if (actual == size && size != 0) { CHECK(memcmp(bytes, expected, size) == 0); }
}

static void test_empty_zero_and_copy(void)
{
    fixture_t f;
    fixture_create(&f, 8, false, false);
    transmit(&f, 8, 8, VIREO_OK, 0, 0, VIREO_CONNECTION_SEND_STOP_EMPTY, 0);
    enqueue(&f, NULL, 0, VIREO_OK);
    uint8_t bytes[] = {0, 255, 7};
    enqueue(&f, bytes, 3, VIREO_OK);
    memset(bytes, 9, 3);
    transmit(&f, 8, 8, VIREO_OK, 3, 1, VIREO_CONNECTION_SEND_STOP_EMPTY, 0);
    uint8_t const expected[] = {0, 255, 7};
    peer_expect(&f, expected, 3);
    CHECK(f.requests[0] == 3);
    fixture_destroy(&f);
}

static void test_full_busy_range_and_retry(void)
{
    fixture_t f;
    fixture_create(&f, 5, false, false);
    enqueue(&f, "ABCDE", 5, VIREO_OK);
    enqueue(&f, "F", 1, VIREO_RESULT_BUSY);
    enqueue(&f, "123456", 6, VIREO_RESULT_RANGE);
    enqueue(&f, NULL, 0, VIREO_OK);
    transmit(&f, 2, 1, VIREO_OK, 2, 1, VIREO_CONNECTION_SEND_STOP_BYTE_BUDGET, 0);
    enqueue(&f, "FG", 2, VIREO_OK);
    transmit(&f, SIZE_MAX, SIZE_MAX, VIREO_OK, 5, 1, VIREO_CONNECTION_SEND_STOP_EMPTY, 0);
    peer_expect(&f, "ABCDEFG", 7);
    CHECK(state(&f).write_buffer.tail_space == 5);
    fixture_destroy(&f);
}

static void test_overflow_and_rejection_before_read(void)
{
    fixture_t f;
    fixture_create(&f, 5, false, false);
    uint8_t dummy = 1;
    enqueue(&f, &dummy, SIZE_MAX, VIREO_RESULT_RANGE);
    enqueue(&f, "A", 1, VIREO_OK);
    enqueue(&f, &dummy, SIZE_MAX, VIREO_RESULT_OVERFLOW);
    enqueue(&f, &dummy, 6, VIREO_RESULT_RANGE);
    enqueue(&f, &dummy, 5, VIREO_RESULT_BUSY);
    transmit(&f, 8, 8, VIREO_OK, 1, 1, VIREO_CONNECTION_SEND_STOP_EMPTY, 0);
    peer_expect(&f, "A", 1);
    fixture_destroy(&f);
}

static void test_tail_hole_and_no_unneeded_compact(void)
{
    fixture_t f;
    fixture_create(&f, 8, false, false);
    enqueue(&f, "ABCDE", 5, VIREO_OK);
    transmit(&f, 2, 8, VIREO_OK, 2, 1, VIREO_CONNECTION_SEND_STOP_BYTE_BUDGET, 0);
    CHECK(state(&f).write_buffer.tail_space == 3);
    enqueue(&f, "FG", 2, VIREO_OK);
    CHECK(state(&f).write_buffer.tail_space == 1); /* 尾空够，头洞仍保留。 */
    enqueue(&f, "HIJK", 4, VIREO_RESULT_BUSY);
    CHECK(state(&f).write_buffer.tail_space == 1); /* 拒绝不能先compact。 */
    enqueue(&f, "HI", 2, VIREO_OK);
    CHECK(state(&f).write_buffer.tail_space == 1); /* 5待发+2：整理后tail1。 */
    transmit(&f, 8, 8, VIREO_OK, 7, 1, VIREO_CONNECTION_SEND_STOP_EMPTY, 0);
    peer_expect(&f, "ABCDEFGHI", 9);
    fixture_destroy(&f);
}

static void test_order_and_byte_call_empty_priority(void)
{
    fixture_t f;
    fixture_create(&f, 16, false, false);
    enqueue(&f, "AB", 2, VIREO_OK);
    enqueue(&f, "CD", 2, VIREO_OK);
    enqueue(&f, "EF", 2, VIREO_OK);
    transmit(&f, 2, 1, VIREO_OK, 2, 1, VIREO_CONNECTION_SEND_STOP_BYTE_BUDGET, 0);
    transmit(&f, 4, 1, VIREO_OK, 4, 1, VIREO_CONNECTION_SEND_STOP_EMPTY, 0);
    peer_expect(&f, "ABCDEF", 6);
    fixture_destroy(&f);
}

static void test_short_progress_and_call_budget(void)
{
    fixture_t f;
    fixture_create(&f, 8, false, false);
    f.short_limit = 1;
    enqueue(&f, "ABCDE", 5, VIREO_OK);
    transmit(&f, 8, 3, VIREO_OK, 3, 3, VIREO_CONNECTION_SEND_STOP_CALL_BUDGET, 0);
    transmit(&f, 8, 3, VIREO_OK, 2, 2, VIREO_CONNECTION_SEND_STOP_EMPTY, 0);
    peer_expect(&f, "ABCDE", 5);
    CHECK(f.requests[0] == 5 && f.requests[1] == 4 && f.requests[2] == 3);
    fixture_destroy(&f);
}

static void test_4096_bound_and_binary_order(void)
{
    fixture_t f;
    fixture_create(&f, 9000, false, false);
    uint8_t bytes[8193];
    for (size_t i = 0; i < sizeof(bytes); ++i) { bytes[i] = (uint8_t)(i % 256); }
    enqueue(&f, bytes, sizeof(bytes), VIREO_OK);
    transmit(&f, SIZE_MAX, SIZE_MAX, VIREO_OK, 8193, 3, VIREO_CONNECTION_SEND_STOP_EMPTY, 0);
    CHECK(f.requests[0] == 4096 && f.requests[1] == 4096 && f.requests[2] == 1);
    peer_expect(&f, bytes, sizeof(bytes));
    fixture_destroy(&f);
}

static void test_enqueue_parameter_rejection(void)
{
    fixture_t f;
    fixture_create(&f, 8, false, false);
    enqueue(&f, "AB", 2, VIREO_OK);
    vireo_connection_error_t error;
    errno = E2BIG;
    CHECK(vireo_connection_write_enqueue(NULL, (uint8_t const *)"A", 1, &error) ==
          VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(errno == E2BIG); check_none(&error);
    enqueue(&f, NULL, 1, VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(f.calls == 0 && state(&f).write_buffer.readable_size == 2);
    transmit(&f, 8, 8, VIREO_OK, 2, 1, VIREO_CONNECTION_SEND_STOP_EMPTY, 0);
    peer_expect(&f, "AB", 2);
    fixture_destroy(&f);
}

static void test_send_parameter_output_preservation(void)
{
    fixture_t f;
    fixture_create(&f, 8, false, false);
    enqueue(&f, "AB", 2, VIREO_OK);
    for (unsigned i = 0; i < 5; ++i) {
        vireo_connection_send_budget_t budget = {8, 8};
        if (i == 3) { budget.max_bytes = 0; }
        if (i == 4) { budget.max_syscalls = 0; }
        vireo_connection_send_info_t info;
        memset(&info, 0xA5, sizeof(info));
        unsigned char original[sizeof(info)];
        memcpy(original, &info, sizeof(info));
        vireo_connection_error_t error;
        errno = 0;
        CHECK(vireo_connection_send(i == 0 ? NULL : f.connection, i == 1 ? NULL : &budget,
                                     i == 2 ? NULL : &info, &error) ==
              (i < 3 ? VIREO_RESULT_INVALID_ARGUMENT : VIREO_RESULT_RANGE));
        CHECK(errno == 0 && memcmp(original, &info, sizeof(info)) == 0);
        check_none(&error);
        CHECK(f.calls == 0 && state(&f).write_buffer.readable_size == 2);
    }
    fixture_destroy(&f);
}

static void test_first_io_then_explicit_retry(void)
{
    int const causes[] = {EINTR, EIO, EPIPE, ECONNRESET};
    for (size_t i = 0; i < sizeof(causes) / sizeof(causes[0]); ++i) {
        fixture_t f;
        fixture_create(&f, 8, false, false);
        enqueue(&f, "ABCDE", 5, VIREO_OK);
        f.fail_at = 1; f.fail_errno = causes[i];
        transmit(&f, 8, 8, VIREO_RESULT_IO, 0, 1, VIREO_CONNECTION_SEND_STOP_ERROR, causes[i]);
        CHECK(f.calls == 1 && f.closes == 0);
        peer_expect(&f, NULL, 0);
        f.fail_at = 0;
        transmit(&f, 8, 8, VIREO_OK, 5, 1, VIREO_CONNECTION_SEND_STOP_EMPTY, 0);
        peer_expect(&f, "ABCDE", 5);
        fixture_destroy(&f);
    }
}

static void test_io_after_progress_keeps_suffix(void)
{
    int const causes[] = {EINTR, EPIPE, ECONNRESET};
    for (size_t i = 0; i < sizeof(causes) / sizeof(causes[0]); ++i) {
        fixture_t f;
        fixture_create(&f, 8, false, false);
        enqueue(&f, "ABCDE", 5, VIREO_OK);
        f.short_limit = 2; f.fail_at = 2; f.fail_errno = causes[i];
        transmit(&f, 8, 8, VIREO_RESULT_IO, 2, 2, VIREO_CONNECTION_SEND_STOP_ERROR, causes[i]);
        CHECK(f.calls == 2 && f.closes == 0);
        peer_expect(&f, "AB", 2);
        enqueue(&f, "FG", 2, VIREO_OK);
        f.fail_at = 0; f.short_limit = 0;
        transmit(&f, 8, 8, VIREO_OK, 5, 1, VIREO_CONNECTION_SEND_STOP_EMPTY, 0);
        peer_expect(&f, "CDEFG", 5);
        fixture_destroy(&f);
    }
}

static void test_injected_would_block(void)
{
    for (unsigned pass = 0; pass < 2; ++pass) {
        fixture_t f;
        fixture_create(&f, 8, false, false);
        enqueue(&f, "ABCDE", 5, VIREO_OK);
        f.fail_at = pass == 0 ? 1 : 2;
        f.fail_errno = pass == 0 ? EAGAIN : EWOULDBLOCK;
        f.short_limit = 2;
        transmit(&f, 8, 2, VIREO_OK, pass == 0 ? 0 : 2, pass == 0 ? 1 : 2,
                 VIREO_CONNECTION_SEND_STOP_WOULD_BLOCK, 0);
        peer_expect(&f, "AB", pass == 0 ? 0 : 2);
        f.fail_at = 0; f.short_limit = 0;
        transmit(&f, 8, 8, VIREO_OK, pass == 0 ? 5 : 3, 1, VIREO_CONNECTION_SEND_STOP_EMPTY, 0);
        peer_expect(&f, pass == 0 ? "ABCDE" : "CDE", pass == 0 ? 5 : 3);
        fixture_destroy(&f);
    }
}

static void test_zero_and_anomalous_counts(void)
{
    for (int anomaly = 1; anomaly <= 3; ++anomaly) {
        for (unsigned pass = 0; pass < 2; ++pass) {
            fixture_t f;
            fixture_create(&f, 8, false, false);
            enqueue(&f, "ABCDE", 5, VIREO_OK);
            f.short_limit = 2; f.fail_at = pass == 0 ? 1 : 2;
            f.fail_errno = ERANGE; f.anomaly = anomaly;
            transmit(&f, 8, 8, VIREO_RESULT_INTERNAL, pass == 0 ? 0 : 2, pass == 0 ? 1 : 2,
                     VIREO_CONNECTION_SEND_STOP_ERROR, 0);
            peer_expect(&f, "AB", pass == 0 ? 0 : 2);
            CHECK(f.closes == 0 && f.calls == (pass == 0 ? 1 : 2));
            f.fail_at = 0; f.short_limit = 0;
            transmit(&f, 8, 8, VIREO_OK, pass == 0 ? 5 : 3, 1,
                     VIREO_CONNECTION_SEND_STOP_EMPTY, 0);
            peer_expect(&f, pass == 0 ? "ABCDE" : "CDE", pass == 0 ? 5 : 3);
            fixture_destroy(&f);
        }
    }
}

/* 小SO_SNDBUF下真实EAGAIN，随后peer释放空间；总peer字节必须恰等原队列。 */
static void test_real_socket_backpressure_and_recovery(void)
{
    fixture_t f;
    fixture_create(&f, 16384, false, true);
    uint8_t bytes[16384], output[16384];
    for (size_t i = 0; i < sizeof(bytes); ++i) { bytes[i] = (uint8_t)(i % 251); }
    enqueue(&f, bytes, sizeof(bytes), VIREO_OK);
    vireo_connection_send_budget_t budget = {SIZE_MAX, SIZE_MAX};
    vireo_connection_send_info_t info;
    vireo_connection_error_t error;
    errno = E2BIG;
    CHECK(vireo_connection_send(f.connection, &budget, &info, &error) == VIREO_OK);
    CHECK(errno == E2BIG); check_none(&error);
    REQUIRE(info.sent_bytes > 0 && info.sent_bytes < sizeof(bytes));
    CHECK(info.stop_reason == VIREO_CONNECTION_SEND_STOP_WOULD_BLOCK);
    CHECK(info.send_calls == f.calls);
    CHECK(state(&f).write_buffer.readable_size == sizeof(bytes) - info.sent_bytes);
    transmit(&f, SIZE_MAX, SIZE_MAX, VIREO_OK, 0, 1, VIREO_CONNECTION_SEND_STOP_WOULD_BLOCK, 0);
    size_t received = peer_drain(&f, output, sizeof(output));
    CHECK(received == info.sent_bytes);
    size_t sent = info.sent_bytes;
    for (unsigned round = 0; sent < sizeof(bytes) && round < 64; ++round) {
        CHECK(vireo_connection_send(f.connection, &budget, &info, NULL) == VIREO_OK);
        REQUIRE(info.sent_bytes > 0);
        sent += info.sent_bytes;
        received += peer_drain(&f, output + received, sizeof(output) - received);
        CHECK(received == sent);
    }
    CHECK(sent == sizeof(bytes) && received == sizeof(bytes));
    CHECK(memcmp(bytes, output, sizeof(bytes)) == 0);
    CHECK(state(&f).write_buffer.readable_size == 0);
    fixture_destroy(&f);
}

static void test_read_borrow_survives_enqueue_and_send(void)
{
    fixture_t f;
    fixture_create(&f, 8, false, false);
    REQUIRE(send(f.peer, "ABC", 3, MSG_NOSIGNAL) == 3);
    vireo_connection_receive_budget_t budget = {128, 8};
    vireo_connection_receive_info_t info;
    REQUIRE(vireo_connection_receive(f.connection, &budget, &info, NULL) == VIREO_OK);
    uint8_t const *borrow;
    size_t size;
    REQUIRE(vireo_connection_read_peek(f.connection, &borrow, &size) == VIREO_OK);
    enqueue(&f, borrow, size, VIREO_OK);
    CHECK(size == 3 && memcmp(borrow, "ABC", 3) == 0);
    enqueue(&f, "123456", 6, VIREO_RESULT_BUSY);
    transmit(&f, 8, 8, VIREO_OK, 3, 1, VIREO_CONNECTION_SEND_STOP_EMPTY, 0);
    CHECK(memcmp(borrow, "ABC", 3) == 0);
    uint8_t const *current;
    size_t current_size;
    REQUIRE(vireo_connection_read_peek(f.connection, &current, &current_size) == VIREO_OK);
    CHECK(current == borrow && current_size == 3);
    peer_expect(&f, "ABC", 3);
    fixture_destroy(&f);
}

static void test_frame_body_enqueue_copies_before_read_consume(void)
{
    fixture_t f;
    fixture_create(&f, 8, false, false);
    uint8_t wire[35];
    vireo_protocol_header_t header = {0};
    header.command = VIREO_COMMAND_PING; header.sequence = 1; header.body_len = 3;
    REQUIRE(vireo_protocol_header_encode(&header, wire, sizeof(wire)) == VIREO_OK);
    memcpy(wire + 32, "ABC", 3);
    REQUIRE(vireo_protocol_frame_crc32c_calculate(wire, 32, wire + 32, 3, &header.crc32c) ==
            VIREO_OK);
    REQUIRE(vireo_protocol_header_encode(&header, wire, sizeof(wire)) == VIREO_OK);
    REQUIRE(send(f.peer, wire, sizeof(wire), MSG_NOSIGNAL) == (ssize_t)sizeof(wire));
    vireo_connection_receive_budget_t receive_budget = {128, 8};
    vireo_connection_receive_info_t receive_info;
    REQUIRE(vireo_connection_receive(f.connection, &receive_budget,
                                       &receive_info, NULL) == VIREO_OK);
    vireo_connection_frame_options_t options = {VIREO_CONNECTION_FRAME_REQUEST, 128};
    vireo_connection_frame_budget_t frame_budget = {2, 128};
    vireo_connection_frame_view_t view;
    vireo_connection_frame_info_t info;
    REQUIRE(vireo_connection_frames_peek(f.connection, &options, &frame_budget,
                                          &view, 1, &info, NULL) == VIREO_OK);
    REQUIRE(info.frame_count == 1 && view.body_size == 3);
    enqueue(&f, view.body, view.body_size, VIREO_OK);
    CHECK(memcmp(view.body, "ABC", 3) == 0);
    REQUIRE(vireo_connection_read_consume(f.connection, view.wire_size) == VIREO_OK);
    /* 此后不读取旧view，发送只能使用排队时复制的独立字节。 */
    transmit(&f, 8, 8, VIREO_OK, 3, 1, VIREO_CONNECTION_SEND_STOP_EMPTY, 0);
    peer_expect(&f, "ABC", 3);
    fixture_destroy(&f);
}

static void test_read_eof_keeps_write_direction(void)
{
    fixture_t f;
    fixture_create(&f, 8, false, false);
    REQUIRE(shutdown(f.peer, SHUT_WR) == 0);
    vireo_connection_receive_budget_t budget = {128, 8};
    vireo_connection_receive_info_t info;
    REQUIRE(vireo_connection_receive(f.connection, &budget, &info, NULL) == VIREO_OK);
    CHECK(info.stop_reason == VIREO_CONNECTION_RECEIVE_STOP_EOF);
    enqueue(&f, "OK", 2, VIREO_OK);
    transmit(&f, 8, 8, VIREO_OK, 2, 1, VIREO_CONNECTION_SEND_STOP_EMPTY, 0);
    peer_expect(&f, "OK", 2);
    CHECK(state(&f).read_eof);
    fixture_destroy(&f);
}

static void test_two_connections_and_no_cross_queue(void)
{
    fixture_t a, b;
    fixture_create(&a, 8, false, false); fixture_create(&b, 8, false, false);
    enqueue(&a, "AAAA", 4, VIREO_OK); enqueue(&b, "BB", 2, VIREO_OK);
    transmit(&a, 8, 8, VIREO_OK, 4, 1, VIREO_CONNECTION_SEND_STOP_EMPTY, 0);
    CHECK(b.calls == 0 && state(&b).write_buffer.readable_size == 2);
    peer_expect(&a, "AAAA", 4); peer_expect(&b, NULL, 0);
    fixture_destroy(&a);
    transmit(&b, 8, 8, VIREO_OK, 2, 1, VIREO_CONNECTION_SEND_STOP_EMPTY, 0);
    peer_expect(&b, "BB", 2); fixture_destroy(&b);
}

static void test_null_diagnostic_and_no_sticky_error(void)
{
    fixture_t f;
    fixture_create(&f, 8, false, false);
    errno = 0;
    CHECK(vireo_connection_write_enqueue(f.connection, (uint8_t const *)"ABCDE",
                                           5, NULL) == VIREO_OK);
    CHECK(errno == 0);
    f.short_limit = 2; f.fail_at = 2; f.fail_errno = EINTR;
    vireo_connection_send_budget_t budget = {8, 8};
    vireo_connection_send_info_t info;
    errno = 0;
    CHECK(vireo_connection_send(f.connection, &budget, &info, NULL) == VIREO_RESULT_IO);
    CHECK(errno == 0 && info.sent_bytes == 2 && info.send_calls == 2);
    CHECK(info.stop_reason == VIREO_CONNECTION_SEND_STOP_ERROR);
    peer_expect(&f, "AB", 2);
    f.fail_at = 0; f.short_limit = 0;
    enqueue(&f, "FG", 2, VIREO_OK);
    transmit(&f, 8, 8, VIREO_OK, 5, 1, VIREO_CONNECTION_SEND_STOP_EMPTY, 0);
    peer_expect(&f, "CDEFG", 5); fixture_destroy(&f);
}

static void test_repeated_cycles_and_pending_destroy(void)
{
    fixture_t f;
    fixture_create(&f, 8, false, false);
    for (uint32_t i = 0; i < 128; ++i) {
        uint8_t bytes[3] = {(uint8_t)i, 0, 255};
        enqueue(&f, bytes, 3, VIREO_OK);
        transmit(&f, 8, 8, VIREO_OK, 3, 1, VIREO_CONNECTION_SEND_STOP_EMPTY, 0);
        peer_expect(&f, bytes, 3);
    }
    CHECK(f.allocations == 1 && f.buffers == 2 && f.destroys == 0 && f.closes == 0);
    enqueue(&f, "pending", 7, VIREO_OK);
    fixture_destroy(&f); /* 不自动flush，待发字节在销毁时丢弃。 */
}

static volatile sig_atomic_t signal_calls;
static size_t fd_count(void);
static void signal_handler(int signal_number)
{
    (void)signal_number;
    ++signal_calls;
}

/* 只在隔离子进程安装信号状态，验证正式系统sender，不调用故障seam。 */
static void sigpipe_child(unsigned mode)
{
    failures = 0; signal_calls = 0;
    size_t baseline = fd_count();
    sigset_t blocked, empty;
    REQUIRE(sigemptyset(&empty) == 0 && sigemptyset(&blocked) == 0);
    REQUIRE(sigaddset(&blocked, SIGPIPE) == 0);
    struct sigaction action = {0};
    action.sa_handler = mode == 1 ? signal_handler : SIG_DFL;
    REQUIRE(sigemptyset(&action.sa_mask) == 0);
    REQUIRE(sigaction(SIGPIPE, &action, NULL) == 0);
    REQUIRE(sigprocmask(SIG_SETMASK, mode >= 2 ? &blocked : &empty, NULL) == 0);
    if (mode == 3) { REQUIRE(raise(SIGPIPE) == 0); }
    sigset_t pending, mask_before, mask_after;
    struct sigaction before, after;
    REQUIRE(sigaction(SIGPIPE, NULL, &before) == 0);
    REQUIRE(sigprocmask(SIG_SETMASK, NULL, &mask_before) == 0);
    fixture_t f;
    fixture_create(&f, 8, true, false);
    REQUIRE(close(f.peer) == 0); f.peer = -1;
    enqueue(&f, "AB", 2, VIREO_OK);
    transmit(&f, 8, 8, VIREO_RESULT_IO, 0, 1, VIREO_CONNECTION_SEND_STOP_ERROR, EPIPE);
    CHECK(state(&f).write_buffer.readable_size == 2 && signal_calls == 0);
    REQUIRE(sigaction(SIGPIPE, NULL, &after) == 0);
    REQUIRE(sigprocmask(SIG_SETMASK, NULL, &mask_after) == 0);
    REQUIRE(sigpending(&pending) == 0);
    CHECK(before.sa_handler == after.sa_handler && before.sa_flags == after.sa_flags);
    for (int n = 1; n < NSIG; ++n) {
        CHECK(sigismember(&before.sa_mask, n) == sigismember(&after.sa_mask, n));
        CHECK(sigismember(&mask_before, n) == sigismember(&mask_after, n));
    }
    CHECK(sigismember(&pending, SIGPIPE) == (mode == 3 ? 1 : 0));
    fixture_destroy(&f);
    CHECK(fd_count() == baseline);
    printf("SIGPIPE case %u: %u failures, EPIPE and fd baseline checked\n", mode, failures);
    exit(failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
}
static void test_real_epipe_and_sigpipe_states(void)
{
    char const *const cases[] = {"0", "1", "2", "3"};
    for (unsigned mode = 0; mode < 4; ++mode) {
        pid_t child = fork();
        REQUIRE(child >= 0);
        if (child == 0) {
            /* fork 后仅 exec/_exit；connection 构造/信号实验在新进程执行。 */
            execl("/proc/self/exe", "vireo_connection_send_test", "--sigpipe-case",
                  cases[mode], (char *)NULL);
            _exit(127);
        }
        int status;
        REQUIRE(waitpid(child, &status, 0) == child);
        CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    }
}

static size_t fd_count(void)
{
    DIR *directory = opendir("/proc/self/fd");
    REQUIRE(directory != NULL);
    size_t count = 0;
    struct dirent *entry;
    while ((entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) { ++count; }
    }
    REQUIRE(closedir(directory) == 0);
    return count;
}

int main(int argc, char **argv)
{
    if (argc == 3 && strcmp(argv[1], "--sigpipe-case") == 0 &&
        argv[2][0] >= '0' && argv[2][0] <= '3' && argv[2][1] == '\0') {
        sigpipe_child((unsigned)(argv[2][0] - '0'));
        return EXIT_FAILURE;
    }
    REQUIRE(argc == 1);
    size_t baseline = fd_count();
    void (*const tests[])(void) = {
        test_empty_zero_and_copy, test_full_busy_range_and_retry,
        test_overflow_and_rejection_before_read, test_tail_hole_and_no_unneeded_compact,
        test_order_and_byte_call_empty_priority, test_short_progress_and_call_budget,
        test_4096_bound_and_binary_order, test_enqueue_parameter_rejection,
        test_send_parameter_output_preservation, test_first_io_then_explicit_retry,
        test_io_after_progress_keeps_suffix, test_injected_would_block,
        test_zero_and_anomalous_counts, test_real_socket_backpressure_and_recovery,
        test_read_borrow_survives_enqueue_and_send,
        test_frame_body_enqueue_copies_before_read_consume, test_read_eof_keeps_write_direction,
        test_two_connections_and_no_cross_queue, test_null_diagnostic_and_no_sticky_error,
        test_repeated_cycles_and_pending_destroy, test_real_epipe_and_sigpipe_states
    };
    size_t groups = sizeof(tests) / sizeof(tests[0]);
    for (size_t i = 0; i < groups; ++i) { tests[i](); }
    CHECK(fd_count() == baseline);
    printf("connection send: %zu groups, %u failures; fd baseline checked\n", groups, failures);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
