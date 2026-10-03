/*
- PROJECT : VIREO
- FILE    : test_connection_receive.c
- AUTHOR  : bitofux
- DATE    : 2026-10-03
- BRIEF   : 此模块负责：
- -- 真实非阻塞字节接收、EOF、固定容量及只读借用/消费验证
- -- 本模块 recv 边界故障注入与部分进度、预算和资源配对验证
 */
#define _GNU_SOURCE
#include <vireo/net/connection.h>
#include "net/connection_internal.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
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
        fprintf(stderr, "fixture failure %s:%d: %s\n", __FILE__, __LINE__, #condition); \
        exit(EXIT_FAILURE); \
    } \
} while (0)

typedef struct fixture {
    unsigned allocations;
    unsigned frees;
    unsigned creates;
    unsigned destroys;
    unsigned closes;
    unsigned calls;
    size_t requests[256];
    int owned_fd;
    size_t short_limit;
    unsigned fail_at;
    int fail_errno;
    int anomalous;
} fixture_t;

/* 私有 seam 只计本层控制块和公共 buffer 生命周期，不访问任何旧模块 private。 */
/**
 * @brief 分配并计数本层控制块
 *
 * @param[in,out] context
 *     fixture 借用，记录申请次数。
 * @param[in] bytes
 *     控制块字节数。
 *
 * @return
 *     malloc owner 或 NULL。
 *
 * @note 与 tracked_free 配对，不申请其他资源。
 */
static void *tracked_allocate(void *context, size_t bytes)
{
    fixture_t *f = context;
    ++f->allocations;
    return malloc(bytes);
}

/**
 * @brief 释放并计数本层控制块
 *
 * @param[in,out] context
 *     fixture 借用，记录释放次数。
 * @param[in] memory
 *     配对取得的唯一 malloc owner，返回后失效。
 *
 * @note 不消费 fixture；仅 connection 释放路径使用。
 */
static void tracked_free(void *context, void *memory)
{
    fixture_t *f = context;
    ++f->frees;
    free(memory);
}

/**
 * @brief 查询真实 fd flags
 *
 * @param[in] context
 *     未使用的 fixture 借用。
 * @param[in] fd
 *     调用期间借用 socket。
 * @param[in] command
 *     F_GETFL 或 F_GETFD。
 *
 * @return
 *     fcntl 原 flags 或 -1。
 *
 * @note 只读一次查询，原 errno 交创建层。
 */
static int tracked_flags(void *context, int fd, int command)
{
    (void)context;
    return fcntl(fd, command);
}

/**
 * @brief 查询真实 socket 类型
 *
 * @param[in] context
 *     未使用的 fixture 借用。
 * @param[in] fd
 *     调用期间借用 socket。
 * @param[out] out_type
 *     有效 int 输出，SO_TYPE 查询目标。
 *
 * @return
 *     getsockopt 原 0 或 -1。
 *
 * @note 只读一次查询，不改属性，原 errno 交创建层。
 */
static int tracked_type(void *context, int fd, int *out_type)
{
    (void)context;
    socklen_t length = (socklen_t)sizeof(*out_type);
    return getsockopt(fd, SOL_SOCKET, SO_TYPE, out_type, &length);
}

/**
 * @brief 验证真实已连接 peer
 *
 * @param[in] context
 *     未使用的 fixture 借用。
 * @param[in] fd
 *     调用期间借用 socket。
 *
 * @return
 *     getpeername 原 0 或 -1。
 *
 * @note 地址仅局部，不保存或转移资源。
 */
static int tracked_peer(void *context, int fd)
{
    (void)context;
    struct sockaddr_storage address;
    socklen_t length = (socklen_t)sizeof(address);
    return getpeername(fd, (struct sockaddr *)&address, &length);
}

/**
 * @brief 关闭实际 fd 并核对所属 connection
 *
 * @param[in,out] context
 *     fixture 借用，记录关闭次数与原编号。
 * @param[in] fd
 *     connection 独占 socket，调用后不能再使用。
 *
 * @return
 *     close 原 0 或 -1。
 *
 * @note 仅单次 close，不重试，不消费 fixture。
 */
static int tracked_close(void *context, int fd)
{
    fixture_t *f = context;
    ++f->closes;
    CHECK(fd == f->owned_fd);
    return close(fd);
}

/**
 * @brief 计数并调用公共 buffer 创建
 *
 * @param[in,out] context
 *     fixture 借用，记录创建次数。
 * @param[in] capacity
 *     已验收正容量。
 * @param[in,out] out
 *     独立空 owner，按公共合同发布。
 *
 * @return
 *     公共 buffer_create 结果。
 *
 * @note 不接触旧模块 private 或额外分配器。
 */
static vireo_result_t tracked_buffer_create(void *context, size_t capacity, vireo_buffer_t **out)
{
    fixture_t *f = context;
    ++f->creates;
    return vireo_buffer_create(capacity, out);
}

/**
 * @brief 计数并消费合法公共 buffer owner
 *
 * @param[in,out] context
 *     fixture 借用，记录释放次数。
 * @param[in,out] owner
 *     合法唯一 buffer owner，公共 destroy 消费并清空。
 *
 * @note 不接触字节区或私有布局，fixture setup 违约立即失败。
 */
static void tracked_buffer_destroy(void *context, vireo_buffer_t **owner)
{
    fixture_t *f = context;
    ++f->destroys;
    REQUIRE(vireo_buffer_destroy(owner) == VIREO_OK);
}

/**
 * @brief 记录请求，按确定点注入错误或限制真实 recv 短进度
 *
 * @param[in,out] context
 *     fixture 借用，存活至 connection 销毁；不取得所有权。
 * @param[in] fd
 *     connection 独占 socket，必须匹配 fixture 原 fd。
 * @param[out] bytes
 *     本层有效暂存区；真实 recv 写入，异常数量注入不越界写入。
 * @param[in] request
 *     1..4096，记录后可进一步限短，不放大真实读取。
 * @param[in] flags
 *     必须精确 MSG_DONTWAIT。
 *
 * @return
 *     原 recv、确定 -1/errno，或故意不符合系统约定的异常数量。
 *
 * @note 注入失败不执行真实 recv，后续重试可验证内核仍保留未取得字节。
 */
static ssize_t tracked_receive(void *context, int fd, void *bytes, size_t request, int flags)
{
    fixture_t *f = context;
    CHECK(fd == f->owned_fd);
    CHECK(request > 0 && request <= 4096);
    CHECK(flags == MSG_DONTWAIT);
    REQUIRE(f->calls < sizeof(f->requests) / sizeof(f->requests[0]));
    f->requests[f->calls++] = request;
    if (f->calls == f->fail_at) {
        errno = f->fail_errno;
        if (f->anomalous > 0) {
            return (ssize_t)request + 1;
        }
        if (f->anomalous < 0) {
            return -2;
        }
        return -1;
    }
    if (f->short_limit != 0 && request > f->short_limit) {
        request = f->short_limit;
    }
    return recv(fd, bytes, request, flags);
}

/**
 * @brief 为旧测试提供完整私有表所需的默认发送入口
 *
 * @param[in] context
 *     未使用的 fixture 借用。
 * @param[in] fd
 *     本对象独占 socket，调用期间借用。
 * @param[in] bytes
 *     有效只读区域，至少 request 字节，仅借用到返回。
 * @param[in] request
 *     调用层验收的正长度。
 * @param[in] flags
 *     调用层传入的 send flags。
 *
 * @return send 原数量或 -1/errno。
 *
 * @note 旧测试不调用发送；不重试、保存输入或关闭。
 */
static ssize_t fixture_send(void *context, int fd, void const *bytes, size_t request, int flags)
{
    (void)context;
    return send(fd, bytes, request, flags);
}

/* 建立独立真实 stream，create 成功后只保留 peer owner；原 fd 仅 seam 用于身份断言。 */
/**
 * @brief 建立真实 socketpair 并完成 owner 转移
 *
 * @param[in] capacity
 *     小型正读容量，另有1字节独立写 buffer。
 * @param[out] peer
 *     有效输出，接收 peer fd owner，由 connection_release 关闭。
 * @param[in,out] f
 *     可空 fixture 借用；非空则启用本模块计数 seam，须覆盖对象生命期。
 *
 * @return
 *     新唯一 connection owner，最终由 connection_release 消费。
 *
 * @note socket 属性在 fixture 创建时指定，connection 只读查询。
 */
static vireo_connection_t *connection_create(size_t capacity, int *peer, fixture_t *f)
{
    int pair[2];
    REQUIRE(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, pair) == 0);
    int fd = pair[0];
    *peer = pair[1];
    vireo_connection_t *connection = NULL;
    vireo_connection_options_t options = {capacity, 1, capacity + 1};
    if (f == NULL) {
        REQUIRE(vireo_connection_create(&options, &fd, &connection, NULL) == VIREO_OK);
    } else {
        *f = (fixture_t){0};
        f->owned_fd = fd;
        vireo_connection_ops_t ops = {f, tracked_allocate, tracked_free, tracked_flags,
            tracked_type, tracked_peer, tracked_close, tracked_buffer_create,
            tracked_buffer_destroy, tracked_receive, fixture_send};
        REQUIRE(vireo_connection_create_with_ops(&options, &fd, &ops, &connection, NULL) ==
                VIREO_OK);
    }
    REQUIRE(connection != NULL && fd == -1);
    return connection;
}

/**
 * @brief 消费 connection 与独立 peer owner
 *
 * @param[in,out] connection
 *     有效唯一 connection owner，destroy 后置 NULL。
 * @param[in] peer
 *     fixture 仍拥有的 peer fd，单次关闭。
 * @param[in] f
 *     可空 fixture 借用，核对控制/buffer/关闭精确配对。
 *
 * @note 仅全部操作/借用结束后调用，不关闭已转移 fd 的副本。
 */
static void connection_release(vireo_connection_t **connection, int peer, fixture_t const *f)
{
    REQUIRE(vireo_connection_destroy(connection, NULL) == VIREO_OK);
    REQUIRE(close(peer) == 0);
    if (f != NULL) {
        CHECK(f->allocations == 1 && f->frees == 1 && f->creates == 2 && f->destroys == 2);
        CHECK(f->closes == 1);
    }
}

/* fixture 数据均远小于 socket 发送容量，无外部 IP、人工输入或等待。 */
/**
 * @brief 在独立 peer 发送有界测试字节
 *
 * @param[in] peer
 *     fixture 拥有的有效 stream peer。
 * @param[in] bytes
 *     借用稳定字节，size 非零时至少可读 size。
 * @param[in] size
 *     小型发送长度，0 不访问输入。
 *
 * @note 真实 MSG_NOSIGNAL send；不代替被测 connection 的 recv。
 */
static void peer_send(int peer, void const *bytes, size_t size)
{
    uint8_t const *data = bytes;
    size_t offset = 0;
    while (offset < size) {
        ssize_t n = send(peer, data + offset, size - offset, MSG_NOSIGNAL);
        REQUIRE(n > 0);
        offset += (size_t)n;
    }
}

/**
 * @brief 重新借用并核对全部未消费字节
 *
 * @param[in] connection
 *     存活连接，调用期间借用。
 * @param[in] expected
 *     期望只读字节，size 为0可空。
 * @param[in] size
 *     期望长度，成功时逐字节比较。
 *
 * @note 不保存 view，不读取上次操作之前的失效指针。
 */
static void check_bytes(vireo_connection_t const *connection, void const *expected, size_t size)
{
    uint8_t const *data = NULL;
    size_t actual = SIZE_MAX;
    CHECK(vireo_connection_read_peek(connection, &data, &actual) == VIREO_OK);
    CHECK(actual == size);
    if (size == 0) {
        CHECK(data == NULL);
    } else if (actual == size && data != NULL) {
        CHECK(memcmp(data, expected, size) == 0);
    } else {
        CHECK(data != NULL);
    }
}

static void check_info(vireo_connection_receive_info_t const *info, size_t bytes, size_t calls,
                       vireo_connection_receive_stop_t stop)
{
    CHECK(info->received_bytes == bytes);
    CHECK(info->recv_calls == calls);
    CHECK(info->stop_reason == stop);
}

static void check_none(vireo_connection_error_t const *error)
{
    CHECK(error->stage == VIREO_CONNECTION_STAGE_NONE && error->system_errno == 0);
}

static void test_empty_and_would_block(void)
{
    int peer;
    vireo_connection_t *connection = connection_create(8, &peer, NULL);
    check_bytes(connection, NULL, 0);
    vireo_connection_receive_budget_t budget = {8, 2};
    vireo_connection_receive_info_t info;
    vireo_connection_error_t error = {VIREO_CONNECTION_STAGE_CLOSE_SOCKET, EIO};
    errno = 0;
    CHECK(vireo_connection_receive(connection, &budget, &info, &error) == VIREO_OK);
    CHECK(errno == 0);
    check_info(&info, 0, 1, VIREO_CONNECTION_RECEIVE_STOP_WOULD_BLOCK);
    check_none(&error);
    check_bytes(connection, NULL, 0);
    vireo_connection_info_t state;
    CHECK(vireo_connection_inspect(connection, &state) == VIREO_OK);
    CHECK(!state.read_eof && state.read_buffer.tail_space == 8);
    CHECK(state.write_buffer.readable_size == 0 && state.write_buffer.capacity == 1);
    connection_release(&connection, peer, NULL);
}

static void test_real_byte_budget(void)
{
    int peer;
    vireo_connection_t *connection = connection_create(8, &peer, NULL);
    peer_send(peer, "ABCD", 4);
    vireo_connection_receive_budget_t budget = {2, 8};
    vireo_connection_receive_info_t info;
    errno = E2BIG;
    CHECK(vireo_connection_receive(connection, &budget, &info, NULL) == VIREO_OK);
    CHECK(errno == E2BIG);
    check_info(&info, 2, 1, VIREO_CONNECTION_RECEIVE_STOP_BYTE_BUDGET);
    check_bytes(connection, "AB", 2);
    CHECK(vireo_connection_receive(connection, &budget, &info, NULL) == VIREO_OK);
    check_info(&info, 2, 1, VIREO_CONNECTION_RECEIVE_STOP_BYTE_BUDGET);
    check_bytes(connection, "ABCD", 4);
    CHECK(vireo_connection_read_consume(connection, 4) == VIREO_OK);
    check_bytes(connection, NULL, 0);
    connection_release(&connection, peer, NULL);
}

static void test_full_preserves_kernel_remainder(void)
{
    int peer;
    fixture_t f;
    vireo_connection_t *connection = connection_create(3, &peer, &f);
    peer_send(peer, "ABCDE", 5);
    vireo_connection_receive_budget_t budget = {5, 8};
    vireo_connection_receive_info_t info;
    CHECK(vireo_connection_receive(connection, &budget, &info, NULL) == VIREO_OK);
    check_info(&info, 3, 1, VIREO_CONNECTION_RECEIVE_STOP_BUFFER_FULL);
    check_bytes(connection, "ABC", 3);
    CHECK(f.requests[0] == 3);
    CHECK(vireo_connection_receive(connection, &budget, &info, NULL) == VIREO_OK);
    check_info(&info, 0, 0, VIREO_CONNECTION_RECEIVE_STOP_BUFFER_FULL);
    CHECK(f.calls == 1);
    CHECK(vireo_connection_read_consume(connection, 3) == VIREO_OK);
    CHECK(vireo_connection_receive(connection, &budget, &info, NULL) == VIREO_OK);
    check_info(&info, 2, 2, VIREO_CONNECTION_RECEIVE_STOP_WOULD_BLOCK);
    check_bytes(connection, "DE", 2);
    connection_release(&connection, peer, &f);
}

static void test_stop_priority(void)
{
    for (unsigned i = 0; i < 3; ++i) {
        int peer;
        fixture_t f;
        vireo_connection_t *connection = connection_create(i == 2 ? 8 : 3, &peer, &f);
        peer_send(peer, "ABC", 3);
        vireo_connection_receive_budget_t budget = {i == 0 ? 3 : 4, 1};
        vireo_connection_receive_info_t info;
        CHECK(vireo_connection_receive(connection, &budget, &info, NULL) == VIREO_OK);
        vireo_connection_receive_stop_t stop = i == 0 ? VIREO_CONNECTION_RECEIVE_STOP_BYTE_BUDGET :
            (i == 1 ? VIREO_CONNECTION_RECEIVE_STOP_BUFFER_FULL :
                      VIREO_CONNECTION_RECEIVE_STOP_CALL_BUDGET);
        check_info(&info, 3, 1, stop);
        check_bytes(connection, "ABC", 3);
        connection_release(&connection, peer, &f);
    }
}

static void test_cross_chunk_binary(void)
{
    uint8_t bytes[8193];
    for (size_t i = 0; i < sizeof(bytes); ++i) {
        bytes[i] = (uint8_t)(i % 251);
    }
    int peer;
    fixture_t f;
    vireo_connection_t *connection = connection_create(9000, &peer, &f);
    peer_send(peer, bytes, sizeof(bytes));
    vireo_connection_receive_budget_t budget = {sizeof(bytes), 8};
    vireo_connection_receive_info_t info;
    CHECK(vireo_connection_receive(connection, &budget, &info, NULL) == VIREO_OK);
    check_info(&info, sizeof(bytes), 3, VIREO_CONNECTION_RECEIVE_STOP_BYTE_BUDGET);
    CHECK(f.requests[0] == 4096 && f.requests[1] == 4096 && f.requests[2] == 1);
    check_bytes(connection, bytes, sizeof(bytes));
    connection_release(&connection, peer, &f);
}

static void test_compact_and_receive(void)
{
    int peer;
    vireo_connection_t *connection = connection_create(6, &peer, NULL);
    peer_send(peer, "ABCDE", 5);
    vireo_connection_receive_budget_t first = {5, 8}, second = {10, 8};
    vireo_connection_receive_info_t info;
    REQUIRE(vireo_connection_receive(connection, &first, &info, NULL) == VIREO_OK);
    CHECK(vireo_connection_read_consume(connection, 2) == VIREO_OK);
    vireo_connection_info_t state;
    CHECK(vireo_connection_inspect(connection, &state) == VIREO_OK);
    CHECK(state.read_buffer.readable_size == 3 && state.read_buffer.tail_space == 1);
    peer_send(peer, "FGHI", 4);
    CHECK(vireo_connection_receive(connection, &second, &info, NULL) == VIREO_OK);
    check_info(&info, 3, 1, VIREO_CONNECTION_RECEIVE_STOP_BUFFER_FULL);
    check_bytes(connection, "CDEFGH", 6);
    CHECK(vireo_connection_read_consume(connection, 6) == VIREO_OK);
    CHECK(vireo_connection_receive(connection, &second, &info, NULL) == VIREO_OK);
    check_info(&info, 1, 2, VIREO_CONNECTION_RECEIVE_STOP_WOULD_BLOCK);
    check_bytes(connection, "I", 1);
    connection_release(&connection, peer, NULL);
}

static void test_eof_retains_bytes_and_fd(void)
{
    int peer;
    fixture_t f;
    vireo_connection_t *connection = connection_create(16, &peer, &f);
    peer_send(peer, "ABC", 3);
    REQUIRE(shutdown(peer, SHUT_WR) == 0);
    vireo_connection_receive_budget_t budget = {16, 8};
    vireo_connection_receive_info_t info;
    vireo_connection_error_t error;
    errno = E2BIG;
    CHECK(vireo_connection_receive(connection, &budget, &info, &error) == VIREO_OK);
    CHECK(errno == E2BIG);
    check_info(&info, 3, 2, VIREO_CONNECTION_RECEIVE_STOP_EOF);
    check_none(&error);
    check_bytes(connection, "ABC", 3);
    vireo_connection_info_t state;
    CHECK(vireo_connection_inspect(connection, &state) == VIREO_OK && state.read_eof);
    CHECK(state.write_buffer.readable_size == 0 && f.closes == 0);
    CHECK(fcntl(f.owned_fd, F_GETFD) >= 0);
    CHECK(vireo_connection_receive(connection, &budget, &info, NULL) == VIREO_OK);
    check_info(&info, 0, 0, VIREO_CONNECTION_RECEIVE_STOP_EOF);
    CHECK(f.calls == 2);
    CHECK(vireo_connection_read_consume(connection, 3) == VIREO_OK);
    check_bytes(connection, NULL, 0);
    CHECK(vireo_connection_inspect(connection, &state) == VIREO_OK && state.read_eof);
    CHECK(vireo_connection_receive(connection, &budget, &info, NULL) == VIREO_OK);
    CHECK(f.calls == 2);
    connection_release(&connection, peer, &f);
}

static void test_full_does_not_infer_eof(void)
{
    int peer;
    vireo_connection_t *connection = connection_create(3, &peer, NULL);
    peer_send(peer, "ABC", 3);
    REQUIRE(shutdown(peer, SHUT_WR) == 0);
    vireo_connection_receive_budget_t budget = {3, 8};
    vireo_connection_receive_info_t info;
    REQUIRE(vireo_connection_receive(connection, &budget, &info, NULL) == VIREO_OK);
    check_info(&info, 3, 1, VIREO_CONNECTION_RECEIVE_STOP_BYTE_BUDGET);
    vireo_connection_info_t state;
    CHECK(vireo_connection_inspect(connection, &state) == VIREO_OK && !state.read_eof);
    CHECK(vireo_connection_receive(connection, &budget, &info, NULL) == VIREO_OK);
    check_info(&info, 0, 0, VIREO_CONNECTION_RECEIVE_STOP_BUFFER_FULL);
    CHECK(vireo_connection_inspect(connection, &state) == VIREO_OK && !state.read_eof);
    REQUIRE(vireo_connection_read_consume(connection, 3) == VIREO_OK);
    CHECK(vireo_connection_receive(connection, &budget, &info, NULL) == VIREO_OK);
    check_info(&info, 0, 1, VIREO_CONNECTION_RECEIVE_STOP_EOF);
    CHECK(vireo_connection_inspect(connection, &state) == VIREO_OK && state.read_eof);
    connection_release(&connection, peer, NULL);
}

static void test_two_connection_identity(void)
{
    int a_peer, b_peer;
    uint8_t const a[] = {'A', 0, 1, 2}, b[] = {'B', 0, 3, 4};
    vireo_connection_t *first = connection_create(8, &a_peer, NULL);
    vireo_connection_t *second = connection_create(8, &b_peer, NULL);
    peer_send(b_peer, b, sizeof(b));
    peer_send(a_peer, a, sizeof(a));
    vireo_connection_receive_budget_t budget = {4, 8};
    vireo_connection_receive_info_t info;
    CHECK(vireo_connection_receive(first, &budget, &info, NULL) == VIREO_OK);
    check_bytes(first, a, sizeof(a));
    check_bytes(second, NULL, 0);
    CHECK(vireo_connection_receive(second, &budget, &info, NULL) == VIREO_OK);
    check_bytes(second, b, sizeof(b));
    uint8_t const *a_view = NULL, *b_view = NULL;
    size_t size;
    CHECK(vireo_connection_read_peek(first, &a_view, &size) == VIREO_OK);
    CHECK(vireo_connection_read_peek(second, &b_view, &size) == VIREO_OK);
    CHECK(a_view != b_view);
    CHECK(vireo_connection_read_consume(first, 2) == VIREO_OK);
    check_bytes(first, a + 2, 2);
    check_bytes(second, b, sizeof(b));
    connection_release(&first, a_peer, NULL);
    check_bytes(second, b, sizeof(b));
    connection_release(&second, b_peer, NULL);
}

static void test_invalid_receive_preserves_view_and_output(void)
{
    int peer;
    fixture_t f;
    vireo_connection_t *connection = connection_create(8, &peer, &f);
    peer_send(peer, "ABC", 3);
    vireo_connection_receive_budget_t budget = {3, 8};
    vireo_connection_receive_info_t info;
    REQUIRE(vireo_connection_receive(connection, &budget, &info, NULL) == VIREO_OK);
    REQUIRE(vireo_connection_read_consume(connection, 1) == VIREO_OK);
    uint8_t const *view = NULL;
    size_t size;
    REQUIRE(vireo_connection_read_peek(connection, &view, &size) == VIREO_OK);
    memset(&info, 0xa5, sizeof(info));
    unsigned char saved[sizeof(info)];
    memcpy(saved, &info, sizeof(info));
    unsigned calls = f.calls;
    vireo_connection_error_t error;
    errno = EDOM;
    CHECK(vireo_connection_receive(NULL, &budget, &info, &error) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(memcmp(saved, &info, sizeof(info)) == 0);
    CHECK(vireo_connection_receive(connection, NULL, &info, &error) ==
          VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(memcmp(saved, &info, sizeof(info)) == 0);
    CHECK(vireo_connection_receive(connection, &budget, NULL, &error) ==
          VIREO_RESULT_INVALID_ARGUMENT);
    vireo_connection_receive_budget_t zero = {0, 1};
    CHECK(vireo_connection_receive(connection, &zero, &info, &error) == VIREO_RESULT_RANGE);
    CHECK(memcmp(saved, &info, sizeof(info)) == 0);
    CHECK(errno == EDOM && f.calls == calls);
    check_none(&error);
    CHECK(size == 2 && memcmp(view, "BC", 2) == 0);
    vireo_connection_info_t state;
    CHECK(vireo_connection_inspect(connection, &state) == VIREO_OK);
    CHECK(state.read_buffer.readable_size == 2 && state.read_buffer.tail_space == 5);
    connection_release(&connection, peer, &f);
}

static void test_budget_edges(void)
{
    int peer;
    fixture_t f;
    vireo_connection_t *connection = connection_create(1, &peer, &f);
    vireo_connection_receive_budget_t invalid[] = {{0, 1}, {1, 0}};
    vireo_connection_receive_info_t info;
    unsigned char saved[sizeof(info)];
    memset(&info, 0x5a, sizeof(info));
    memcpy(saved, &info, sizeof(info));
    vireo_connection_error_t error;
    errno = E2BIG;
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
        CHECK(vireo_connection_receive(connection, &invalid[i], &info, &error) ==
              VIREO_RESULT_RANGE);
        CHECK(memcmp(saved, &info, sizeof(info)) == 0 && f.calls == 0 && errno == E2BIG);
        check_none(&error);
    }
    vireo_connection_receive_budget_t maximum = {SIZE_MAX, SIZE_MAX};
    peer_send(peer, "X", 1);
    CHECK(vireo_connection_receive(connection, &maximum, &info, NULL) == VIREO_OK);
    check_info(&info, 1, 1, VIREO_CONNECTION_RECEIVE_STOP_BUFFER_FULL);
    CHECK(f.requests[0] == 1 && errno == E2BIG);
    check_bytes(connection, "X", 1);
    CHECK(vireo_connection_read_consume(connection, 1) == VIREO_OK);
    CHECK(vireo_connection_receive(connection, &maximum, &info, NULL) == VIREO_OK);
    check_info(&info, 0, 1, VIREO_CONNECTION_RECEIVE_STOP_WOULD_BLOCK);
    connection_release(&connection, peer, &f);
}

static void test_peek_outputs_and_consume_edges(void)
{
    int peer;
    vireo_connection_t *connection = connection_create(8, &peer, NULL);
    peer_send(peer, "ABCDE", 5);
    vireo_connection_receive_budget_t budget = {5, 8};
    vireo_connection_receive_info_t info;
    REQUIRE(vireo_connection_receive(connection, &budget, &info, NULL) == VIREO_OK);
    uint8_t const *view = NULL;
    size_t size = 0;
    REQUIRE(vireo_connection_read_peek(connection, &view, &size) == VIREO_OK);
    uint8_t const *original = view;
    errno = E2BIG;
    CHECK(vireo_connection_read_peek(NULL, &view, &size) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_connection_read_peek(connection, NULL, &size) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_connection_read_peek(connection, &view, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(view == original && size == 5 && errno == E2BIG);
    CHECK(vireo_connection_read_consume(NULL, 1) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_connection_read_consume(connection, 6) == VIREO_RESULT_RANGE);
    CHECK(vireo_connection_read_consume(connection, SIZE_MAX) == VIREO_RESULT_RANGE);
    CHECK(memcmp(view, "ABCDE", 5) == 0 && errno == E2BIG);
    CHECK(vireo_connection_read_consume(connection, 0) == VIREO_OK);
    check_bytes(connection, "ABCDE", 5);
    CHECK(vireo_connection_read_consume(connection, 2) == VIREO_OK);
    check_bytes(connection, "CDE", 3);
    CHECK(vireo_connection_read_consume(connection, 3) == VIREO_OK);
    check_bytes(connection, NULL, 0);
    vireo_connection_info_t state;
    CHECK(vireo_connection_inspect(connection, &state) == VIREO_OK);
    CHECK(state.read_buffer.tail_space == 8 && !state.read_eof);
    CHECK(errno == E2BIG);
    connection_release(&connection, peer, NULL);
}

static void test_short_reads_and_call_budget(void)
{
    int peer;
    fixture_t f;
    vireo_connection_t *connection = connection_create(16, &peer, &f);
    peer_send(peer, "abcdef", 6);
    f.short_limit = 1;
    vireo_connection_receive_budget_t first = {6, 3}, second = {6, 8};
    vireo_connection_receive_info_t info;
    CHECK(vireo_connection_receive(connection, &first, &info, NULL) == VIREO_OK);
    check_info(&info, 3, 3, VIREO_CONNECTION_RECEIVE_STOP_CALL_BUDGET);
    CHECK(f.requests[0] == 6 && f.requests[1] == 5 && f.requests[2] == 4);
    check_bytes(connection, "abc", 3);
    CHECK(vireo_connection_receive(connection, &second, &info, NULL) == VIREO_OK);
    check_info(&info, 3, 4, VIREO_CONNECTION_RECEIVE_STOP_WOULD_BLOCK);
    check_bytes(connection, "abcdef", 6);
    connection_release(&connection, peer, &f);
}

static void test_io_before_progress(void)
{
    int const causes[] = {EINTR, EIO};
    for (size_t i = 0; i < sizeof(causes) / sizeof(causes[0]); ++i) {
        int peer;
        fixture_t f;
        vireo_connection_t *connection = connection_create(8, &peer, &f);
        peer_send(peer, "ABC", 3);
        f.fail_at = 1;
        f.fail_errno = causes[i];
        vireo_connection_receive_budget_t budget = {8, 8};
        vireo_connection_receive_info_t info;
        vireo_connection_error_t error;
        errno = E2BIG;
        CHECK(vireo_connection_receive(connection, &budget, &info, &error) == VIREO_RESULT_IO);
        CHECK(errno == E2BIG && f.calls == 1 && f.closes == 0);
        check_info(&info, 0, 1, VIREO_CONNECTION_RECEIVE_STOP_ERROR);
        CHECK(error.stage == VIREO_CONNECTION_STAGE_RECEIVE && error.system_errno == causes[i]);
        check_bytes(connection, NULL, 0);
        f.fail_at = 0;
        CHECK(vireo_connection_receive(connection, &budget, &info, NULL) == VIREO_OK);
        check_info(&info, 3, 2, VIREO_CONNECTION_RECEIVE_STOP_WOULD_BLOCK);
        check_bytes(connection, "ABC", 3);
        connection_release(&connection, peer, &f);
    }
}

static void test_io_after_progress(void)
{
    int const causes[] = {EINTR, ECONNRESET};
    for (size_t i = 0; i < sizeof(causes) / sizeof(causes[0]); ++i) {
        int peer;
        fixture_t f;
        vireo_connection_t *connection = connection_create(16, &peer, &f);
        peer_send(peer, "ABCDE", 5);
        f.short_limit = 2;
        f.fail_at = 2;
        f.fail_errno = causes[i];
        vireo_connection_receive_budget_t budget = {16, 8};
        vireo_connection_receive_info_t info;
        vireo_connection_error_t error;
        errno = E2BIG;
        CHECK(vireo_connection_receive(connection, &budget, &info, &error) == VIREO_RESULT_IO);
        CHECK(errno == E2BIG && f.calls == 2 && f.closes == 0);
        check_info(&info, 2, 2, VIREO_CONNECTION_RECEIVE_STOP_ERROR);
        CHECK(error.stage == VIREO_CONNECTION_STAGE_RECEIVE && error.system_errno == causes[i]);
        check_bytes(connection, "AB", 2);
        f.fail_at = 0;
        CHECK(vireo_connection_receive(connection, &budget, &info, NULL) == VIREO_OK);
        check_info(&info, 3, 3, VIREO_CONNECTION_RECEIVE_STOP_WOULD_BLOCK);
        check_bytes(connection, "ABCDE", 5);
        connection_release(&connection, peer, &f);
    }
}

static void test_would_block_after_progress(void)
{
    int peer;
    fixture_t f;
    vireo_connection_t *connection = connection_create(16, &peer, &f);
    peer_send(peer, "ABCDE", 5);
    f.short_limit = 2;
    f.fail_at = 2;
    f.fail_errno = EAGAIN;
    vireo_connection_receive_budget_t budget = {16, 2};
    vireo_connection_receive_info_t info;
    vireo_connection_error_t error = {VIREO_CONNECTION_STAGE_RECEIVE, EIO};
    errno = E2BIG;
    CHECK(vireo_connection_receive(connection, &budget, &info, &error) == VIREO_OK);
    check_info(&info, 2, 2, VIREO_CONNECTION_RECEIVE_STOP_WOULD_BLOCK);
    CHECK(errno == E2BIG && f.calls == 2);
    check_none(&error);
    check_bytes(connection, "AB", 2);
    connection_release(&connection, peer, &f);
}

static void test_internal_anomalies_keep_prior_progress(void)
{
    int const anomalies[] = {1, -1};
    for (size_t i = 0; i < sizeof(anomalies) / sizeof(anomalies[0]); ++i) {
        int peer;
        fixture_t f;
        vireo_connection_t *connection = connection_create(16, &peer, &f);
        peer_send(peer, "ABCDE", 5);
        f.short_limit = 2;
        f.fail_at = 2;
        f.fail_errno = EDOM;
        f.anomalous = anomalies[i];
        vireo_connection_receive_budget_t budget = {16, 8};
        vireo_connection_receive_info_t info;
        vireo_connection_error_t error;
        errno = E2BIG;
        CHECK(vireo_connection_receive(connection, &budget, &info, &error) ==
              VIREO_RESULT_INTERNAL);
        check_info(&info, 2, 2, VIREO_CONNECTION_RECEIVE_STOP_ERROR);
        CHECK(errno == E2BIG && error.stage == VIREO_CONNECTION_STAGE_RECEIVE);
        CHECK(error.system_errno == 0 && f.closes == 0);
        check_bytes(connection, "AB", 2);
        connection_release(&connection, peer, &f);
    }
}

static void test_null_diagnostic_on_io(void)
{
    int peer;
    fixture_t f;
    vireo_connection_t *connection = connection_create(8, &peer, &f);
    peer_send(peer, "ABCD", 4);
    f.short_limit = 2;
    f.fail_at = 2;
    f.fail_errno = EINTR;
    vireo_connection_receive_budget_t budget = {8, 8};
    vireo_connection_receive_info_t info;
    errno = 0;
    CHECK(vireo_connection_receive(connection, &budget, &info, NULL) == VIREO_RESULT_IO);
    check_info(&info, 2, 2, VIREO_CONNECTION_RECEIVE_STOP_ERROR);
    CHECK(errno == 0 && f.closes == 0);
    check_bytes(connection, "AB", 2);
    connection_release(&connection, peer, &f);
}

static void test_repeated_no_runtime_allocations(void)
{
    int peer;
    fixture_t f;
    vireo_connection_t *connection = connection_create(32, &peer, &f);
    vireo_connection_receive_budget_t budget = {8, 8};
    vireo_connection_receive_info_t info;
    for (unsigned i = 0; i < 128; ++i) {
        uint8_t bytes[8] = {(uint8_t)i, 0, 1, 2, 3, 4, 5, 255};
        peer_send(peer, bytes, sizeof(bytes));
        CHECK(vireo_connection_receive(connection, &budget, &info, NULL) == VIREO_OK);
        check_info(&info, 8, 1, VIREO_CONNECTION_RECEIVE_STOP_BYTE_BUDGET);
        check_bytes(connection, bytes, sizeof(bytes));
        CHECK(vireo_connection_read_consume(connection, sizeof(bytes)) == VIREO_OK);
        CHECK(f.allocations == 1 && f.creates == 2 && f.frees == 0 && f.destroys == 0);
    }
    CHECK(f.calls == 128);
    connection_release(&connection, peer, &f);
}

/* view 的逻辑失效按公共 buffer 契约证明；不故意读取已经失效的借用来制造测试。 */
static void test_repeek_after_zero_progress_compact(void)
{
    int peer;
    vireo_connection_t *connection = connection_create(8, &peer, NULL);
    peer_send(peer, "ABCDE", 5);
    vireo_connection_receive_budget_t budget = {5, 8};
    vireo_connection_receive_info_t info;
    REQUIRE(vireo_connection_receive(connection, &budget, &info, NULL) == VIREO_OK);
    REQUIRE(vireo_connection_read_consume(connection, 2) == VIREO_OK);
    check_bytes(connection, "CDE", 3);
    vireo_connection_info_t state;
    CHECK(vireo_connection_inspect(connection, &state) == VIREO_OK);
    CHECK(state.read_buffer.tail_space == 3);
    CHECK(vireo_connection_receive(connection, &budget, &info, NULL) == VIREO_OK);
    check_info(&info, 0, 1, VIREO_CONNECTION_RECEIVE_STOP_WOULD_BLOCK);
    CHECK(vireo_connection_inspect(connection, &state) == VIREO_OK);
    CHECK(state.read_buffer.tail_space == 5 && state.read_buffer.readable_size == 3);
    check_bytes(connection, "CDE", 3);
    connection_release(&connection, peer, NULL);
}

/**
 * @brief 观察进程当前 fd 数量
 *
 * @return
 *     包含临时目录自身的稳定 fd 计数。
 *
 * @note 每次关闭目录，使入口/退出计数可比较，不扫描外部进程。
 */
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
    struct test_case {
        char const *name;
        void (*run)(void);
    } const cases[] = {
        {"public empty peek and would block",
         test_empty_and_would_block},
        {"public real byte budget and remaining socket bytes",
         test_real_byte_budget},
        {"full buffer does not take or discard excess bytes",
         test_full_preserves_kernel_remainder},
        {"byte/full/call deterministic priority",
         test_stop_priority},
        {"4096 chunk boundary and exact binary content",
         test_cross_chunk_binary},
        {"consume head compact and receive in order",
         test_compact_and_receive},
        {"real EOF retains bytes and fd without further recv",
         test_eof_retains_bytes_and_fd},
        {"full buffer cannot infer EOF",
         test_full_does_not_infer_eof},
        {"two connection socket and buffer identities",
         test_two_connection_identity},
        {"parameter refusal preserves output and view",
         test_invalid_receive_preserves_view_and_output},
        {"zero budgets and SIZE_MAX positive budgets",
         test_budget_edges},
        {"peek output pairs and consume edge cases",
         test_peek_outputs_and_consume_edges},
        {"short reads bounded by syscall budget",
         test_short_reads_and_call_budget},
        {"IO before progress and explicit later retry",
         test_io_before_progress},
        {"IO after progress retains bytes and true counts",
         test_io_after_progress},
        {"observed EAGAIN priority after progress",
         test_would_block_after_progress},
        {"invalid native counts preserve prior progress",
         test_internal_anomalies_keep_prior_progress},
        {"NULL diagnostic preserves IO handling",
         test_null_diagnostic_on_io},
        {"128 receive consume cycles without resource creation",
         test_repeated_no_runtime_allocations},
        {"zero progress receive compacts and requires new peek",
         test_repeek_after_zero_progress_compact}
    };
    size_t baseline = fd_count();
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        unsigned previous = failures;
        cases[i].run();
        printf("%s: %s\n", cases[i].name, failures == previous ? "PASS" : "FAIL");
    }
    CHECK(fd_count() == baseline);
    printf("connection receive: %zu groups, %u failures; fd baseline checked\n",
           sizeof(cases) / sizeof(cases[0]), failures);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
