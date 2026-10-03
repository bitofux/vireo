/*
- PROJECT : VIREO
- FILE    : test_connection_pool_integration.c
- AUTHOR  : bitofux
- DATE    : 2026-10-04
- BRIEF   : 此模块负责：
- -- 仅通过公开合同验证同批事件失效、连接槽及 fd 复用
- -- 验证缓存帧续处理、写压力滞回、有界发送与安全关闭归还
 */
#define _GNU_SOURCE
#include <vireo/net/connection_pool.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static unsigned failures;
static unsigned groups;
static unsigned reused_fds;
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

typedef struct socket_fixture {
    vireo_connection_t *owner;
    int fd;
    int peer;
} socket_fixture_t;

static socket_fixture_t make_connection(void)
{
    int pair[2];
    REQUIRE(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, pair) == 0);
    socket_fixture_t fixture = {NULL, pair[0], pair[1]};
    vireo_connection_options_t const options = {128, 128, 256};
    int fd_owner = pair[0];
    REQUIRE(vireo_connection_create(&options, &fd_owner, &fixture.owner, NULL) == VIREO_OK);
    CHECK(fd_owner == -1);
    return fixture;
}

static vireo_connection_pool_t *make_pool(size_t capacity)
{
    vireo_connection_pool_t *pool = NULL;
    vireo_connection_pool_options_t const options = {capacity, 65536, capacity * 256};
    REQUIRE(vireo_connection_pool_create(&options, &pool, NULL) == VIREO_OK);
    return pool;
}

static vireo_event_loop_t *make_loop(void)
{
    vireo_event_loop_t *loop = NULL;
    vireo_event_loop_options_t const options = {4, 65536, 4};
    REQUIRE(vireo_event_loop_create(&options, &loop, NULL) == VIREO_OK);
    return loop;
}

static vireo_connection_t *lookup(vireo_connection_pool_t *pool,
                                  vireo_connection_pool_lease_t lease)
{
    vireo_connection_t *borrowed = NULL;
    REQUIRE(vireo_connection_pool_lookup(pool, lease, &borrowed) == VIREO_OK);
    return borrowed;
}

static vireo_connection_info_t inspect(vireo_connection_t *connection)
{
    vireo_connection_info_t info;
    REQUIRE(vireo_connection_inspect(connection, &info) == VIREO_OK);
    return info;
}

static vireo_event_loop_run_info_t run_once(vireo_event_loop_t *loop)
{
    vireo_event_loop_run_info_t info;
    errno = E2BIG;
    REQUIRE(vireo_event_loop_run_once(loop, 0, &info, NULL) == VIREO_OK);
    CHECK(errno == E2BIG);
    CHECK(info.ready_count == info.dispatched_count + info.stale_count + info.filtered_count);
    return info;
}

static void check_closed(int fd)
{
    errno = 0;
    CHECK(fcntl(fd, F_GETFD) == -1 && errno == EBADF);
}

static void check_empty(vireo_connection_pool_t *pool, size_t capacity)
{
    vireo_connection_pool_info_t info;
    REQUIRE(vireo_connection_pool_inspect(pool, &info) == VIREO_OK);
    CHECK(info.leased_slots == 0 && info.available_slots == capacity);
    CHECK(info.buffer_capacity_bytes == 0);
}

static unsigned fd_count(void)
{
    DIR *directory = opendir("/proc/self/fd");
    REQUIRE(directory != NULL);
    unsigned count = 0;
    struct dirent *entry;
    while ((entry = readdir(directory)) != NULL) {
        if (entry->d_name[0] != '.') {
            ++count;
        }
    }
    REQUIRE(closedir(directory) == 0);
    return count;
}

typedef struct batch_fixture batch_fixture_t;
typedef struct batch_client {
    batch_fixture_t *batch;
    unsigned index;
    vireo_connection_pool_lease_t lease;
    socket_fixture_t socket;
    char const *expected;
    unsigned calls;
} batch_client_t;

struct batch_fixture {
    vireo_connection_pool_t *pool;
    vireo_event_loop_t *loop;
    batch_client_t clients[2];
    vireo_connection_pool_lease_t expired;
    int retired_peer;
    unsigned replaced_index;
    bool replaced;
};

/* 不预测两个就绪项的顺序；第一项只注销、归还另一项的非在途连接。 */
static void batch_callback(vireo_connection_t *connection, uint32_t events, void *context)
{
    batch_client_t *client = context;
    batch_fixture_t *f = client->batch;
    CHECK(connection == lookup(f->pool, client->lease));
    CHECK((events & VIREO_EPOLL_EVENT_READ) != 0);
    ++client->calls;
    vireo_connection_receive_budget_t const budget = {128, 4};
    vireo_connection_receive_info_t progress;
    REQUIRE(vireo_connection_receive(connection, &budget, &progress, NULL) == VIREO_OK);
    uint8_t const *data;
    size_t size;
    REQUIRE(vireo_connection_read_peek(connection, &data, &size) == VIREO_OK);
    CHECK(size == strlen(client->expected) && progress.received_bytes == size);
    REQUIRE(size == strlen(client->expected));
    CHECK(memcmp(data, client->expected, size) == 0);
    REQUIRE(vireo_connection_read_consume(connection, size) == VIREO_OK);
    if (f->replaced) {
        return;
    }
    f->replaced = true;
    f->replaced_index = 1U - client->index;
    batch_client_t *other = &f->clients[f->replaced_index];
    f->expired = other->lease;
    int const retired_fd = other->socket.fd;
    f->retired_peer = other->socket.peer;
    REQUIRE(vireo_connection_detach(lookup(f->pool, other->lease), NULL) == VIREO_OK);
    REQUIRE(vireo_connection_pool_release(f->pool, &other->lease, NULL) == VIREO_OK);
    check_closed(retired_fd);
    /* 暂留旧 peer；新 socketpair 前仅客户 fd 被释放，实测同一 fd 数值复用。 */
    other->socket = make_connection();
    CHECK(other->socket.fd == retired_fd);
    if (other->socket.fd == retired_fd) {
        ++reused_fds;
    }
    other->expected = "new";
    REQUIRE(vireo_connection_pool_adopt(f->pool, &other->socket.owner, &other->lease, NULL) ==
            VIREO_OK);
    CHECK(other->socket.owner == NULL && other->lease.slot_index == f->expired.slot_index);
    CHECK(other->lease.generation > f->expired.generation);
    REQUIRE(vireo_connection_attach(lookup(f->pool, other->lease), f->loop,
                                   VIREO_EPOLL_INTEREST_READ, batch_callback, other, NULL) ==
            VIREO_OK);
}

static void test_batch_replacement(void)
{
    ++groups;
    for (unsigned round = 0; round < 16; ++round) {
        unsigned const baseline = fd_count();
        batch_fixture_t f = {0};
        f.pool = make_pool(2);
        f.loop = make_loop();
        for (unsigned i = 0; i < 2; ++i) {
            batch_client_t *client = &f.clients[i];
            client->batch = &f;
            client->index = i;
            client->socket = make_connection();
            client->expected = i == 0 ? "A0" : "B0";
            REQUIRE(vireo_connection_pool_adopt(f.pool, &client->socket.owner, &client->lease,
                                               NULL) == VIREO_OK);
            REQUIRE(vireo_connection_attach(lookup(f.pool, client->lease), f.loop,
                                           VIREO_EPOLL_INTEREST_READ, batch_callback, client,
                                           NULL) == VIREO_OK);
            REQUIRE(send(client->socket.peer, client->expected, 2, MSG_NOSIGNAL) == 2);
        }
        vireo_event_loop_run_info_t info = run_once(f.loop);
        CHECK(f.replaced && info.ready_count == 2 && info.dispatched_count == 1);
        CHECK(info.stale_count == 1 && info.filtered_count == 0);
        batch_client_t *replacement = &f.clients[f.replaced_index];
        CHECK(replacement->calls == 0);
        CHECK(inspect(lookup(f.pool, replacement->lease)).read_buffer.readable_size == 0);
        vireo_connection_t *out = NULL;
        CHECK(vireo_connection_pool_lookup(f.pool, f.expired, &out) == VIREO_RESULT_NOT_FOUND);
        CHECK(out == NULL);
        REQUIRE(send(replacement->socket.peer, "new", 3, MSG_NOSIGNAL) == 3);
        info = run_once(f.loop);
        CHECK(info.ready_count == 1 && info.dispatched_count == 1 && info.stale_count == 0);
        CHECK(f.clients[0].calls == 1 && f.clients[1].calls == 1);
        for (unsigned i = 0; i < 2; ++i) {
            batch_client_t *client = &f.clients[i];
            REQUIRE(vireo_connection_detach(lookup(f.pool, client->lease), NULL) == VIREO_OK);
            REQUIRE(vireo_connection_pool_release(f.pool, &client->lease, NULL) == VIREO_OK);
            check_closed(client->socket.fd);
            CHECK(close(client->socket.peer) == 0);
        }
        CHECK(close(f.retired_peer) == 0);
        check_empty(f.pool, 2);
        CHECK(vireo_event_loop_destroy(&f.loop, NULL) == VIREO_OK);
        CHECK(vireo_connection_pool_destroy(&f.pool, NULL) == VIREO_OK);
        CHECK(fd_count() == baseline);
    }
}

/* 只验证基础 framing/CRC 与字节回送，不模拟命令专属 body 或业务 handler。 */
static void encode_frame(uint8_t wire[36], uint32_t sequence, bool response,
                         uint8_t const body[4])
{
    vireo_protocol_header_t header = {0};
    header.command = VIREO_COMMAND_SERVER_INFO;
    header.flags = response ? VIREO_PROTOCOL_FLAG_RESPONSE : 0;
    header.status = response ? VIREO_STATUS_OK : VIREO_PROTOCOL_REQUEST_STATUS;
    header.body_len = 4;
    header.sequence = sequence;
    vireo_protocol_codec_issue_t issue;
    REQUIRE((response ? vireo_protocol_response_header_validate(&header, &issue) :
                        vireo_protocol_request_header_validate(&header, &issue)) == VIREO_OK);
    REQUIRE(vireo_protocol_header_encode(&header, wire, 36) == VIREO_OK);
    memcpy(wire + VIREO_PROTOCOL_HEADER_SIZE, body, 4);
    REQUIRE(vireo_protocol_frame_crc32c_calculate(wire, 36, body, 4, &header.crc32c) == VIREO_OK);
    REQUIRE(vireo_protocol_header_encode(&header, wire, 36) == VIREO_OK);
}

typedef struct stream_fixture {
    vireo_connection_pool_t *pool;
    vireo_connection_pool_lease_t lease;
    unsigned frames;
    unsigned read_calls;
    unsigned write_calls;
    size_t sent_bytes;
    bool closing;
} stream_fixture_t;

/* 调用者的显式缓存续处理；完成复制后再 consume，使所有旧 body 借用结束。 */
static void process_one_frame(stream_fixture_t *f, vireo_connection_t *connection)
{
    vireo_connection_frame_options_t const options = {VIREO_CONNECTION_FRAME_REQUEST, 64};
    vireo_connection_frame_budget_t const budget = {1, 64};
    vireo_connection_frame_view_t view;
    vireo_connection_frame_info_t progress;
    REQUIRE(vireo_connection_frames_peek(connection, &options, &budget, &view, 1,
                                         &progress, NULL) == VIREO_OK);
    REQUIRE(progress.frame_count == 1 && view.body_size == 4 && view.wire_size == 36);
    CHECK(progress.frame_bytes == 36 && view.header.sequence == f->frames + 1U);
    uint8_t response[36];
    encode_frame(response, view.header.sequence, true, view.body);
    REQUIRE(vireo_connection_write_enqueue(connection, response, sizeof(response), NULL) ==
            VIREO_OK);
    REQUIRE(vireo_connection_read_consume(connection, view.wire_size) == VIREO_OK);
    ++f->frames;
    REQUIRE(vireo_connection_flow_refresh(connection, NULL) == VIREO_OK);
}

static void stream_callback(vireo_connection_t *connection, uint32_t events, void *context)
{
    stream_fixture_t *f = context;
    CHECK(connection == lookup(f->pool, f->lease));
    CHECK((events & (VIREO_EPOLL_EVENT_ERROR | VIREO_EPOLL_EVENT_HANGUP)) == 0);
    if ((events & VIREO_EPOLL_EVENT_READ) != 0) {
        ++f->read_calls;
        vireo_connection_receive_budget_t const budget = {128, 4};
        vireo_connection_receive_info_t progress;
        REQUIRE(vireo_connection_receive(connection, &budget, &progress, NULL) == VIREO_OK);
        CHECK(progress.received_bytes == 72);
        CHECK(progress.stop_reason == VIREO_CONNECTION_RECEIVE_STOP_WOULD_BLOCK);
        process_one_frame(f, connection);
    }
    if ((events & VIREO_EPOLL_EVENT_WRITE) != 0) {
        ++f->write_calls;
        vireo_connection_send_budget_t const budget = {17, 1};
        vireo_connection_send_info_t progress;
        REQUIRE(vireo_connection_send(connection, &budget, &progress, NULL) == VIREO_OK);
        CHECK(progress.sent_bytes <= 17 && progress.send_calls <= 1);
        f->sent_bytes += progress.sent_bytes;
        REQUIRE((f->closing ? vireo_connection_close_refresh(connection, NULL) :
                              vireo_connection_flow_refresh(connection, NULL)) == VIREO_OK);
    }
}

static void test_frames_flow_and_drain(void)
{
    ++groups;
    unsigned const baseline = fd_count();
    stream_fixture_t f = {0};
    f.pool = make_pool(1);
    vireo_event_loop_t *loop = make_loop();
    socket_fixture_t socket = make_connection();
    REQUIRE(vireo_connection_pool_adopt(f.pool, &socket.owner, &f.lease, NULL) == VIREO_OK);
    vireo_connection_t *connection = lookup(f.pool, f.lease);
    REQUIRE(vireo_connection_attach(connection, loop, VIREO_EPOLL_INTEREST_READ,
                                   stream_callback, &f, NULL) == VIREO_OK);
    vireo_connection_flow_options_t const options = {64, 63, 96, 16, 64};
    REQUIRE(vireo_connection_flow_configure(connection, &options, NULL) == VIREO_OK);
    uint8_t const bodies[2][4] = {{'o', 'n', 'e', '!'}, {'t', 'w', 'o', '!'}};
    uint8_t requests[72];
    encode_frame(requests, 1, false, bodies[0]);
    encode_frame(requests + 36, 2, false, bodies[1]);
    REQUIRE(send(socket.peer, requests, sizeof(requests), MSG_NOSIGNAL) == 72);
    CHECK(run_once(loop).dispatched_count == 1);
    CHECK(f.read_calls == 1 && f.frames == 1 && f.write_calls == 0);
    CHECK(inspect(connection).read_buffer.readable_size == 36);
    /* socket 已排空；第二帧由上层继续处理，不等待新的 READ 事件。 */
    process_one_frame(&f, connection);
    vireo_connection_info_t info = inspect(connection);
    CHECK(info.read_buffer.readable_size == 0 && info.write_buffer.readable_size == 72);
    CHECK(info.write_pressure && info.loop_interests == VIREO_EPOLL_INTEREST_WRITE);
    for (unsigned i = 1; i <= 4; ++i) {
        CHECK(run_once(loop).dispatched_count == 1);
        info = inspect(connection);
        CHECK(info.write_buffer.readable_size == 72U - (size_t)i * 17U);
        CHECK(info.write_pressure == (i < 4));
        CHECK(((info.loop_interests & VIREO_EPOLL_INTEREST_READ) != 0) == (i == 4));
    }
    CHECK(f.write_calls == 4 && f.sent_bytes == 68);
    f.closing = true;
    REQUIRE(vireo_connection_request_close(connection, VIREO_CONNECTION_CLOSE_MODE_DRAIN,
                                          VIREO_CONNECTION_CLOSE_REASON_APPLICATION, NULL) ==
            VIREO_OK);
    info = inspect(connection);
    CHECK(info.close_state == VIREO_CONNECTION_CLOSE_DRAINING);
    CHECK(info.loop_interests == VIREO_EPOLL_INTEREST_WRITE);
    CHECK(run_once(loop).dispatched_count == 1);
    info = inspect(connection);
    CHECK(info.close_state == VIREO_CONNECTION_CLOSE_READY && info.loop_interests == 0);
    CHECK(f.read_calls == 1 && f.write_calls == 5 && f.sent_bytes == 72);
    vireo_connection_pool_lease_t const copy = f.lease;
    errno = E2BIG;
    CHECK(vireo_connection_pool_release(f.pool, &f.lease, NULL) == VIREO_RESULT_BUSY);
    CHECK(errno == E2BIG && f.lease.generation == copy.generation);
    CHECK(lookup(f.pool, copy) == connection);
    REQUIRE(vireo_connection_detach(connection, NULL) == VIREO_OK);
    REQUIRE(vireo_connection_pool_release(f.pool, &f.lease, NULL) == VIREO_OK);
    check_closed(socket.fd);
    uint8_t received[72];
    size_t size = 0;
    for (unsigned attempt = 0; attempt < 8 && size < sizeof(received); ++attempt) {
        ssize_t const result = recv(socket.peer, received + size, sizeof(received) - size,
                                    MSG_DONTWAIT);
        REQUIRE(result > 0);
        size += (size_t)result;
    }
    REQUIRE(size == sizeof(received));
    for (unsigned i = 0; i < 2; ++i) {
        uint8_t const *wire = received + (size_t)i * 36;
        vireo_protocol_header_t header;
        vireo_protocol_codec_issue_t issue;
        REQUIRE(vireo_protocol_header_decode(wire, 36, &header, &issue) == VIREO_OK);
        CHECK(vireo_protocol_response_header_validate(&header, &issue) == VIREO_OK);
        CHECK(vireo_protocol_frame_crc32c_verify(wire, 36, wire + 32, 4, &issue) == VIREO_OK);
        CHECK(header.sequence == i + 1U && header.body_len == 4);
        CHECK(memcmp(wire + 32, bodies[i], 4) == 0);
    }
    CHECK(close(socket.peer) == 0);
    check_empty(f.pool, 1);
    CHECK(vireo_event_loop_destroy(&loop, NULL) == VIREO_OK);
    CHECK(vireo_connection_pool_destroy(&f.pool, NULL) == VIREO_OK);
    CHECK(fd_count() == baseline);
}

int main(void)
{
    unsigned const baseline = fd_count();
    test_batch_replacement();
    test_frames_flow_and_drain();
    unsigned const final = fd_count();
    CHECK(final == baseline);
    printf("connection pool integration: %u groups, %u failures; "
           "same-fd reuse %u/16; fd %u -> %u\n",
           groups, failures, reused_fds, baseline, final);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
