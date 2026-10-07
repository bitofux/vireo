/*
- PROJECT : VIREO
- FILE    : test_tcp_server_integration.c
- AUTHOR  : bitofux
- DATE    : 2026-10-07
- BRIEF   : 此模块负责：
- -- 真实TCP包边界、有限缓存续处理与客户公平
- -- 背压、关闭、准入额度及槽位和fd复用隔离
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <vireo/net/sync_commands.h>
#include <vireo/protocol/codec.h>
#include <vireo/protocol/tlv.h>
#include "net/tcp_server_internal.h"

static unsigned failures, groups;
#define CHECK(c)                                                    \
    do {                                                            \
        if (!(c)) {                                                 \
            fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #c); \
            ++failures;                                             \
        }                                                           \
    } while (0)
#define REQUIRE(c)                                                          \
    do {                                                                    \
        if (!(c)) {                                                         \
            fprintf(stderr, "fixture %s:%d: %s\n", __FILE__, __LINE__, #c); \
            exit(EXIT_FAILURE);                                             \
        }                                                                   \
    } while (0)

static unsigned fd_count(void) {
    DIR *d = opendir("/proc/self/fd");
    REQUIRE(d != NULL);
    unsigned count = 0;
    struct dirent *entry;
    while ((entry = readdir(d)) != NULL)
        if (entry->d_name[0] != '.')
            ++count;
    REQUIRE(closedir(d) == 0);
    return count;
}
static vireo_tcp_server_sync_context_t cache(void) {
    vireo_tcp_server_sync_context_t c;
    uint8_t const version[] = "0.1.0";
    errno = EDOM;
    REQUIRE(vireo_tcp_server_sync_context_init(version, sizeof(version) - 1, &c) == VIREO_OK);
    CHECK(errno == EDOM);
    return c;
}
/* 先真实编码/CRC，再获取host header；负用例另改变基础语义以检查防御出口。 */
static size_t wire(uint8_t *out, vireo_protocol_header_t h, uint8_t const *body, size_t size) {
    REQUIRE(size <= 64);
    h.body_len = (uint32_t)size;
    REQUIRE(vireo_protocol_header_encode(&h, out, 32) == VIREO_OK);
    REQUIRE(vireo_protocol_frame_crc32c_calculate(out, 32, body, size, &h.crc32c) == VIREO_OK);
    REQUIRE(vireo_protocol_header_encode(&h, out, 32) == VIREO_OK);
    if (size)
        memcpy(out + 32, body, size);
    return 32 + size;
}
static void verify_info(uint8_t const *p, size_t size, uint8_t const *version,
                        size_t version_size) {
    vireo_tlv_rule_t const rules[] = {
        {VIREO_SYNC_TLV_PROTOCOL_VERSION, 2, 2, VIREO_TLV_VALUE_U16, true, false},
        {VIREO_SYNC_TLV_SERVER_VERSION, 1, 64, VIREO_TLV_VALUE_UTF8, true, false},
        {VIREO_SYNC_TLV_SUPPORTED_COMMANDS, 4, 4, VIREO_TLV_VALUE_BYTES, true, false}};
    uint8_t seen[3];
    vireo_tlv_issue_t issue;
    CHECK(vireo_tlv_schema_validate(p, size, rules, 3, VIREO_TLV_UNKNOWN_REJECT, seen, 3, &issue) ==
          VIREO_OK);
    vireo_tlv_reader_t reader;
    vireo_tlv_view_t v;
    uint16_t protocol;
    REQUIRE(vireo_tlv_reader_init(&reader, p, size) == VIREO_OK);
    REQUIRE(vireo_tlv_reader_next(&reader, &v, &issue) == VIREO_OK);
    CHECK(v.type == UINT16_C(0xF001) && vireo_tlv_view_read_u16(&v, &protocol) == VIREO_OK &&
          protocol == 1);
    REQUIRE(vireo_tlv_reader_next(&reader, &v, &issue) == VIREO_OK);
    CHECK(v.type == UINT16_C(0xF002) && v.length == version_size &&
          memcmp(v.value, version, version_size) == 0);
    REQUIRE(vireo_tlv_reader_next(&reader, &v, &issue) == VIREO_OK);
    REQUIRE(v.type == UINT16_C(0xF003) && v.length == 4);
    vireo_tlv_view_t const first = {v.type, v.value, 2};
    vireo_tlv_view_t const second = {v.type, v.value + 2, 2};
    uint16_t ping, info;
    CHECK(vireo_tlv_view_read_u16(&first, &ping) == VIREO_OK && ping == VIREO_COMMAND_PING);
    CHECK(vireo_tlv_view_read_u16(&second, &info) == VIREO_OK && info == VIREO_COMMAND_SERVER_INFO);
    CHECK(vireo_tlv_reader_next(&reader, &v, &issue) == VIREO_RESULT_NOT_FOUND &&
          reader.offset == size);
}

/* 测试拥有server和peer；lease只作身份，历史fd转移后不用于I/O。 */
typedef struct fixture {
    vireo_tcp_server_t *server;              /**< 唯一server owner，结束时销毁。 */
    int peers[2];                            /**< 测试端socket owner，-1表示未创建。 */
    vireo_connection_pool_lease_t leases[2]; /**< 当前客户数值身份，消费后不能再操作。 */
    struct sockaddr_in address;              /**< 回环临时端口，不固定外部地址。 */
    vireo_connection_options_t connection;   /**< 下一接入的固定双容量。 */
    vireo_connection_flow_options_t flow;    /**< 下一客户的显式迟滞阈值。 */
    vireo_tcp_server_sync_context_t context; /**< handler只读缓存，活到全部轮次结束。 */
    unsigned created;                        /**< bridge成功构造数量，最多16个。 */
    int accepted_fds[16];                    /**< 已转移fd历史值，仅整数比较。 */
    bool small_send_buffer; /**< 构造转移前缩小测试socket发送容量。 */
} fixture_t;
static vireo_result_t bridge_accept(void *context, vireo_acceptor_t *acceptor,
                                    vireo_acceptor_accept_budget_t const *budget, int *fds,
                                    size_t capacity, vireo_acceptor_accept_info_t *info,
                                    vireo_acceptor_error_t *error) {
    (void)context;
    return vireo_acceptor_accept_batch(acceptor, budget, fds, capacity, info, error);
}
static vireo_result_t bridge_create(void *context, vireo_connection_options_t const *options,
                                    int *fd_owner, vireo_connection_t **out_owner,
                                    vireo_connection_error_t *error) {
    fixture_t *f = context;
    int const raw = *fd_owner;
    if (f->small_send_buffer) {
        int size = 4096;
        REQUIRE(setsockopt(raw, SOL_SOCKET, SO_SNDBUF, &size, (socklen_t)sizeof(size)) == 0);
    }
    vireo_result_t result = vireo_connection_create(options, fd_owner, out_owner, error);
    if (result == VIREO_OK) {
        REQUIRE(f->created < 16);
        f->accepted_fds[f->created++] = raw;
    }
    return result;
}
static vireo_result_t bridge_inspect(void *context, vireo_connection_t const *connection,
                                     vireo_connection_info_t *info) {
    (void)context;
    return vireo_connection_inspect(connection, info);
}
static vireo_result_t bridge_adopt(void *context, vireo_connection_pool_t *pool,
                                   vireo_connection_t **owner, vireo_connection_pool_lease_t *lease,
                                   vireo_connection_pool_operation_error_t *error) {
    (void)context;
    return vireo_connection_pool_adopt(pool, owner, lease, error);
}
static vireo_result_t bridge_lookup(void *context, vireo_connection_pool_t const *pool,
                                    vireo_connection_pool_lease_t lease,
                                    vireo_connection_t **connection) {
    (void)context;
    return vireo_connection_pool_lookup(pool, lease, connection);
}
static vireo_result_t bridge_attach(void *context, vireo_connection_t *connection,
                                    vireo_event_loop_t *loop, uint32_t interests,
                                    vireo_connection_callback_t callback, void *callback_context,
                                    vireo_connection_loop_error_t *error) {
    (void)context;
    return vireo_connection_attach(connection, loop, interests, callback, callback_context, error);
}
static vireo_result_t bridge_detach(void *context, vireo_connection_t *connection,
                                    vireo_connection_loop_error_t *error) {
    (void)context;
    return vireo_connection_detach(connection, error);
}
static vireo_result_t bridge_release(void *context, vireo_connection_pool_t *pool,
                                     vireo_connection_pool_lease_t *lease,
                                     vireo_connection_pool_operation_error_t *error) {
    (void)context;
    return vireo_connection_pool_release(pool, lease, error);
}
static vireo_result_t bridge_destroy(void *context, vireo_connection_t **owner,
                                     vireo_connection_error_t *error) {
    (void)context;
    return vireo_connection_destroy(owner, error);
}
static int bridge_close_fd(void *context, int fd) {
    (void)context;
    return close(fd);
}
static vireo_result_t bridge_receive(void *context, vireo_connection_t *connection,
                                     vireo_connection_receive_budget_t const *budget,
                                     vireo_connection_receive_info_t *info,
                                     vireo_connection_error_t *error) {
    (void)context;
    return vireo_connection_receive(connection, budget, info, error);
}
static vireo_result_t bridge_read_peek(void *context, vireo_connection_t const *connection,
                                       uint8_t const **bytes, size_t *size) {
    (void)context;
    return vireo_connection_read_peek(connection, bytes, size);
}
static vireo_result_t bridge_read_consume(void *context, vireo_connection_t *connection,
                                          size_t size) {
    (void)context;
    return vireo_connection_read_consume(connection, size);
}
static vireo_result_t bridge_write_enqueue(void *context, vireo_connection_t *connection,
                                           uint8_t const *bytes, size_t size,
                                           vireo_connection_error_t *error) {
    (void)context;
    return vireo_connection_write_enqueue(connection, bytes, size, error);
}
static vireo_result_t bridge_send(void *context, vireo_connection_t *connection,
                                  vireo_connection_send_budget_t const *budget,
                                  vireo_connection_send_info_t *info,
                                  vireo_connection_error_t *error) {
    (void)context;
    return vireo_connection_send(connection, budget, info, error);
}
static vireo_result_t bridge_frames_peek(void *context, vireo_connection_t const *connection,
                                         vireo_connection_frame_options_t const *options,
                                         vireo_connection_frame_budget_t const *budget,
                                         vireo_connection_frame_view_t *frames, size_t capacity,
                                         vireo_connection_frame_info_t *info,
                                         vireo_connection_frame_error_t *error) {
    (void)context;
    return vireo_connection_frames_peek(connection, options, budget, frames, capacity, info, error);
}
static vireo_result_t bridge_set_interests(void *context, vireo_connection_t *connection,
                                           uint32_t interests,
                                           vireo_connection_loop_error_t *error) {
    (void)context;
    return vireo_connection_set_interests(connection, interests, error);
}
static vireo_result_t bridge_flow_configure(void *context, vireo_connection_t *connection,
                                            vireo_connection_flow_options_t const *options,
                                            vireo_connection_loop_error_t *error) {
    (void)context;
    return vireo_connection_flow_configure(connection, options, error);
}
static vireo_result_t bridge_flow_refresh(void *context, vireo_connection_t *connection,
                                          vireo_connection_loop_error_t *error) {
    (void)context;
    return vireo_connection_flow_refresh(connection, error);
}
static vireo_result_t bridge_flow_disable(void *context, vireo_connection_t *connection,
                                          vireo_connection_loop_error_t *error) {
    (void)context;
    return vireo_connection_flow_disable(connection, error);
}
static vireo_result_t bridge_request_close(void *context, vireo_connection_t *connection,
                                           vireo_connection_close_mode_t mode,
                                           vireo_connection_close_reason_t reason,
                                           vireo_connection_loop_error_t *error) {
    (void)context;
    return vireo_connection_request_close(connection, mode, reason, error);
}
static vireo_result_t bridge_close_refresh(void *context, vireo_connection_t *connection,
                                           vireo_connection_loop_error_t *error) {
    (void)context;
    return vireo_connection_close_refresh(connection, error);
}

static bool same(vireo_connection_pool_lease_t a, vireo_connection_pool_lease_t b) {
    return a.pool_id == b.pool_id && a.slot_index == b.slot_index && a.generation == b.generation;
}
/* 构造真实回环监听；observe只使用本server既有测试桥接。 */
static void start(fixture_t *f, size_t capacity, size_t buffer_budget, bool observe) {
    *f = (fixture_t){.peers = {-1, -1},
                     .connection = {256, 256, 512},
                     .flow = {96, 95, 192, 64, 192},
                     .context = cache()};
    vireo_tcp_server_options_t const options = {capacity, 4, 1048576, buffer_budget};
    vireo_tcp_server_client_ops_t const ops = {.context = f,
                                               .accept = bridge_accept,
                                               .create = bridge_create,
                                               .inspect = bridge_inspect,
                                               .adopt = bridge_adopt,
                                               .lookup = bridge_lookup,
                                               .attach = bridge_attach,
                                               .detach = bridge_detach,
                                               .release = bridge_release,
                                               .destroy = bridge_destroy,
                                               .close_fd = bridge_close_fd,
                                               .receive = bridge_receive,
                                               .read_peek = bridge_read_peek,
                                               .read_consume = bridge_read_consume,
                                               .write_enqueue = bridge_write_enqueue,
                                               .send = bridge_send,
                                               .frames_peek = bridge_frames_peek,
                                               .set_interests = bridge_set_interests,
                                               .flow_configure = bridge_flow_configure,
                                               .flow_refresh = bridge_flow_refresh,
                                               .flow_disable = bridge_flow_disable,
                                               .request_close = bridge_request_close,
                                               .close_refresh = bridge_close_refresh};

    REQUIRE((observe ? vireo_tcp_server_create_with_client_ops(&options, NULL, NULL, &ops,
                                                               &f->server, NULL)
                     : vireo_tcp_server_create(&options, &f->server, NULL)) == VIREO_OK);
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    REQUIRE(fd >= 0);
    f->address = (struct sockaddr_in){.sin_family = AF_INET, .sin_addr = {htonl(INADDR_LOOPBACK)}};
    REQUIRE(bind(fd, (struct sockaddr *)&f->address, (socklen_t)sizeof(f->address)) == 0);
    REQUIRE(listen(fd, 8) == 0);
    socklen_t length = sizeof(f->address);
    REQUIRE(getsockname(fd, (struct sockaddr *)&f->address, &length) == 0);
    vireo_acceptor_t *a = NULL;
    vireo_acceptor_options_t const ao = {4096};
    REQUIRE(vireo_acceptor_create(&ao, &fd, &a, NULL) == VIREO_OK && fd == -1);
    REQUIRE(vireo_tcp_server_adopt_listener(f->server, &a, NULL) == VIREO_OK && a == NULL);
    REQUIRE(vireo_tcp_server_bind_listener(f->server, true, NULL) == VIREO_OK);
}
static int connect_peer(fixture_t *f) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    REQUIRE(fd >= 0);
    struct timeval const timeout = {2, 0};
    int const one = 1;
    REQUIRE(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    REQUIRE(setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) == 0);
    REQUIRE(connect(fd, (struct sockaddr *)&f->address, sizeof(f->address)) == 0);
    return fd;
}
static void adopt_peer(fixture_t *f, unsigned k) {
    vireo_tcp_server_admit_budget_t const budget = {1, 4};
    vireo_tcp_server_admit_info_t info;
    REQUIRE(vireo_tcp_server_admit_batch(f->server, &f->connection, &budget, &f->leases[k], 1,
                                         &info, NULL) == VIREO_OK &&
            info.admitted_count == 1);
    REQUIRE(vireo_tcp_server_client_flow_configure(f->server, f->leases[k], &f->flow, NULL) ==
            VIREO_OK);
}
static void add_peer(fixture_t *f, unsigned k) {
    f->peers[k] = connect_peer(f);
    adopt_peer(f, k);
}
static vireo_tcp_server_client_info_t client(fixture_t *f, unsigned k) {
    vireo_tcp_server_client_info_t info;
    REQUIRE(vireo_tcp_server_client_inspect(f->server, f->leases[k], &info) == VIREO_OK);
    return info;
}
static vireo_tcp_server_info_t snapshot(fixture_t *f) {
    vireo_tcp_server_info_t info;
    REQUIRE(vireo_tcp_server_inspect(f->server, &info) == VIREO_OK);
    return info;
}
static void end(fixture_t *f) {
    for (unsigned k = 0; k < 2; ++k) {
        if (f->leases[k].pool_id != 0) {
            vireo_tcp_server_client_info_t info;
            vireo_result_t const r =
                vireo_tcp_server_client_inspect(f->server, f->leases[k], &info);
            if (r == VIREO_OK)
                REQUIRE(vireo_tcp_server_release_client(f->server, &f->leases[k], NULL) ==
                        VIREO_OK);
            else
                REQUIRE(r == VIREO_RESULT_NOT_FOUND);
        }
        if (f->peers[k] >= 0)
            REQUIRE(close(f->peers[k]) == 0);
    }
    REQUIRE(vireo_tcp_server_destroy(&f->server, NULL) == VIREO_OK && f->server == NULL);
}
static void transmit(int fd, uint8_t const *p, size_t n) {
    size_t sent = 0;
    while (sent < n) {
        ssize_t got = send(fd, p + sent, n - sent, MSG_NOSIGNAL);
        REQUIRE(got > 0);
        sent += (size_t)got;
    }
}
static void no_response(int fd) {
    uint8_t b;
    errno = 0;
    CHECK(recv(fd, &b, 1, MSG_DONTWAIT) == -1 && (errno == EAGAIN || errno == EWOULDBLOCK));
}
static size_t request(uint8_t *p, vireo_command_t command, uint32_t sequence) {
    return wire(p, (vireo_protocol_header_t){.command = command, .sequence = sequence}, NULL, 0);
}
static vireo_tcp_server_process_options_t const limits = {96, 114};
static vireo_tcp_server_drive_budget_t const allowance = {{256, 8}, {1, 96, 114}, {256, 8}};
static vireo_result_t round_once(fixture_t *f, size_t max_clients,
                                 vireo_tcp_server_drive_budget_t const *budget,
                                 vireo_tcp_server_turn_result_t *turns,
                                 vireo_tcp_server_round_info_t *info,
                                 vireo_tcp_server_round_error_t *error) {
    uint8_t workspace[114];
    vireo_tcp_server_round_budget_t const round = {max_clients};
    errno = EDOM;
    vireo_result_t const r = vireo_tcp_server_run_once(
        f->server, 100, &limits, budget, &round, workspace, sizeof(workspace),
        vireo_tcp_server_handle_sync_command, &f->context, turns, 2, info, error);
    CHECK(errno == EDOM);
    return r;
}
static void receive_pending(fixture_t *f, unsigned k, size_t expected) {
    vireo_connection_receive_budget_t const b = {256, 8};
    vireo_connection_receive_info_t info;
    REQUIRE(vireo_tcp_server_client_receive(f->server, f->leases[k], &b, &info, NULL) == VIREO_OK);
    REQUIRE(info.received_bytes == expected);
}
static void read_exact(int fd, uint8_t *p, size_t n) {
    size_t have = 0;
    while (have < n) {
        ssize_t got = recv(fd, p + have, n - have, 0);
        REQUIRE(got > 0);
        have += (size_t)got;
    }
}
static void response(int peer, vireo_command_t command, uint32_t sequence, vireo_status_t status,
                     uint8_t const *version, size_t version_size) {
    uint8_t encoded[32], body[82];
    vireo_protocol_header_t h;
    vireo_protocol_codec_issue_t issue;
    read_exact(peer, encoded, 32);
    REQUIRE(vireo_protocol_header_decode(encoded, 32, &h, &issue) == VIREO_OK &&
            h.body_len <= sizeof(body));
    read_exact(peer, body, h.body_len);
    CHECK(vireo_protocol_response_header_validate(&h, &issue) == VIREO_OK && h.command == command &&
          h.sequence == sequence && h.status == status && h.flags == VIREO_PROTOCOL_FLAG_RESPONSE &&
          h.session_handle == 0 && h.task_handle == 0);
    CHECK(vireo_protocol_frame_crc32c_verify(encoded, 32, h.body_len ? body : NULL, h.body_len,
                                             &issue) == VIREO_OK);
    if (command == VIREO_COMMAND_SERVER_INFO && status == VIREO_STATUS_OK)
        verify_info(body, h.body_len, version, version_size);
    else
        CHECK(h.body_len == 0);
}
/* 拆包按传入字节数观测，禁止以recv边界当帧边界。 */
static void fragmented_header(void) {
    ++groups;
    fixture_t f;
    start(&f, 2, 8192, false);
    add_peer(&f, 0);
    uint8_t bytes[32];
    REQUIRE(request(bytes, VIREO_COMMAND_PING, 101) == 32);
    size_t const ends[] = {1, 7, 31, 32};
    size_t offset = 0;
    for (unsigned k = 0; k < 4; ++k) {
        transmit(f.peers[0], bytes + offset, ends[k] - offset);
        vireo_tcp_server_turn_result_t turns[2];
        vireo_tcp_server_round_info_t info;
        REQUIRE(round_once(&f, 2, &allowance, turns, &info, NULL) == VIREO_OK);
        REQUIRE(info.turn_count == 1);
        CHECK(turns[0].info.receive.received_bytes == ends[k] - offset);
        CHECK(turns[0].info.process.handler_calls == (k == 3 ? 1u : 0u));
        CHECK(client(&f, 0).connection_info.read_buffer.readable_size == (k == 3 ? 0 : ends[k]));
        if (k != 3)
            no_response(f.peers[0]);
        offset = ends[k];
    }
    response(f.peers[0], VIREO_COMMAND_PING, 101, VIREO_STATUS_OK, NULL, 0);
    end(&f);
}
static void fragmented_body(void) {
    ++groups;
    fixture_t f;
    start(&f, 2, 8192, false);
    add_peer(&f, 0);
    uint8_t bytes[36], body[] = {1, 2, 3, 4};
    REQUIRE(wire(bytes,
                 (vireo_protocol_header_t){.command = VIREO_COMMAND_SERVER_INFO, .sequence = 102},
                 body, 4) == 36);
    size_t const ends[] = {32, 35, 36};
    size_t offset = 0;
    for (unsigned k = 0; k < 3; ++k) {
        transmit(f.peers[0], bytes + offset, ends[k] - offset);
        vireo_tcp_server_turn_result_t turns[2];
        vireo_tcp_server_round_info_t info;
        REQUIRE(round_once(&f, 2, &allowance, turns, &info, NULL) == VIREO_OK &&
                info.turn_count == 1);
        CHECK(turns[0].info.process.handler_calls == (k == 2 ? 1u : 0u));
        if (k != 2) {
            CHECK(turns[0].info.process.consumed_request_bytes == 0);
            no_response(f.peers[0]);
        }
        offset = ends[k];
    }
    response(f.peers[0], VIREO_COMMAND_SERVER_INFO, 102, VIREO_STATUS_BAD_REQUEST, NULL, 0);
    CHECK(client(&f, 0).connection_info.close_state == VIREO_CONNECTION_CLOSE_OPEN);
    end(&f);
}
static void coalesced_and_fair(void) {
    ++groups;
    fixture_t f;
    start(&f, 2, 8192, false);
    add_peer(&f, 0);
    add_peer(&f, 1);
    uint8_t busy[192], small[32];
    for (unsigned k = 0; k < 6; ++k)
        REQUIRE(request(busy + 32 * k, VIREO_COMMAND_PING, 200 + k) == 32);
    request(small, VIREO_COMMAND_SERVER_INFO, 900);
    transmit(f.peers[0], busy, sizeof(busy));
    transmit(f.peers[1], small, sizeof(small));
    /* 先将两个字节流完整接收，再显式按A/B排队；不依赖epoll通知排序。 */
    receive_pending(&f, 0, sizeof(busy));
    receive_pending(&f, 1, sizeof(small));
    REQUIRE(vireo_tcp_server_schedule_client(f.server, f.leases[0], NULL) == VIREO_OK);
    REQUIRE(vireo_tcp_server_schedule_client(f.server, f.leases[1], NULL) == VIREO_OK);
    REQUIRE(vireo_tcp_server_schedule_client(f.server, f.leases[0], NULL) == VIREO_OK);
    CHECK(snapshot(&f).pending_clients == 2);
    unsigned a = 0, b = 0;
    for (unsigned k = 0; k < 7; ++k) {
        vireo_tcp_server_turn_result_t turns[2];
        vireo_tcp_server_round_info_t info;
        REQUIRE(round_once(&f, 1, &allowance, turns, &info, NULL) == VIREO_OK);
        REQUIRE(info.turn_count == 1);
        CHECK(info.effective_timeout_ms == 0 && turns[0].info.process.handler_calls == 1);
        if (same(turns[0].client, f.leases[0])) {
            CHECK(k != 1);
            response(f.peers[0], VIREO_COMMAND_PING, 200 + a++, VIREO_STATUS_OK, NULL, 0);
        } else {
            CHECK(k == 1 && same(turns[0].client, f.leases[1]));
            ++b;
            response(f.peers[1], VIREO_COMMAND_SERVER_INFO, 900, VIREO_STATUS_OK,
                     (uint8_t const *)"0.1.0", 5);
            CHECK(client(&f, 0).connection_info.read_buffer.readable_size == 160);
        }
        CHECK(info.remaining_count <= 2);
    }
    CHECK(a == 6 && b == 1 && snapshot(&f).pending_clients == 0);
    no_response(f.peers[0]);
    no_response(f.peers[1]);
    end(&f);
}
static void half_frame_read_watermark(void) {
    ++groups;
    fixture_t f;
    start(&f, 2, 8192, false);
    f.flow.read_high = 128;
    add_peer(&f, 0);
    uint8_t bytes[160], body[64];
    memset(body, 0x42, sizeof(body));
    request(bytes, VIREO_COMMAND_PING, 301);
    request(bytes + 32, VIREO_COMMAND_PING, 302);
    wire(bytes + 64,
         (vireo_protocol_header_t){.command = VIREO_COMMAND_SERVER_INFO, .sequence = 303}, body,
         sizeof(body));
    transmit(f.peers[0], bytes, 159); /* 两完整前缀+最大合法帧只少1字节。 */
    receive_pending(&f, 0, 159);
    REQUIRE(vireo_tcp_server_client_flow_refresh(f.server, f.leases[0], NULL) == VIREO_OK);
    CHECK(client(&f, 0).connection_info.read_pressure &&
          !(client(&f, 0).connection_info.loop_interests & VIREO_EPOLL_EVENT_READ));
    REQUIRE(vireo_tcp_server_schedule_client(f.server, f.leases[0], NULL) == VIREO_OK);
    for (unsigned k = 0; k < 2; ++k) {
        vireo_tcp_server_turn_result_t turns[2];
        vireo_tcp_server_round_info_t info;
        REQUIRE(round_once(&f, 1, &allowance, turns, &info, NULL) == VIREO_OK &&
                info.turn_count == 1);
        CHECK(!turns[0].info.receive_called); /* 缓存处理不被读压力禁止。 */
        response(f.peers[0], VIREO_COMMAND_PING, 301 + k, VIREO_STATUS_OK, NULL, 0);
    }
    vireo_connection_info_t c = client(&f, 0).connection_info;
    CHECK(c.read_buffer.readable_size == 95 && !c.read_pressure &&
          (c.loop_interests & VIREO_EPOLL_EVENT_READ));
    transmit(f.peers[0], bytes + 159, 1);
    vireo_tcp_server_turn_result_t turns[2];
    vireo_tcp_server_round_info_t info;
    REQUIRE(round_once(&f, 1, &allowance, turns, &info, NULL) == VIREO_OK && info.turn_count == 1);
    CHECK(turns[0].info.process.consumed_request_bytes == 96);
    response(f.peers[0], VIREO_COMMAND_SERVER_INFO, 303, VIREO_STATUS_BAD_REQUEST, NULL, 0);
    end(&f);
}
static void malformed(unsigned variant) {
    ++groups;
    fixture_t f;
    start(&f, 2, 8192, false);
    add_peer(&f, 0);
    REQUIRE(vireo_tcp_server_set_auto_close_policy(f.server, true, NULL) == VIREO_OK);
    REQUIRE(vireo_tcp_server_set_auto_release_ready(f.server, true, NULL) == VIREO_OK);
    uint8_t bytes[32];
    request(bytes, VIREO_COMMAND_PING, 400 + variant);
    vireo_protocol_codec_issue_t const expected[] = {
        VIREO_PROTOCOL_CODEC_ISSUE_CRC_MISMATCH,
        VIREO_PROTOCOL_CODEC_ISSUE_INVALID_MAGIC,
        VIREO_PROTOCOL_CODEC_ISSUE_VERSION_MISMATCH,
        VIREO_PROTOCOL_CODEC_ISSUE_INVALID_HEADER_LENGTH,
        VIREO_PROTOCOL_CODEC_ISSUE_UNKNOWN_FLAGS,
        VIREO_PROTOCOL_CODEC_ISSUE_INVALID_SEQUENCE,
        VIREO_PROTOCOL_CODEC_ISSUE_UNKNOWN_COMMAND,
        VIREO_PROTOCOL_CODEC_ISSUE_REQUEST_HAS_RESPONSE_FLAG};
    switch (variant) {
        case 0:
            bytes[VIREO_PROTOCOL_CRC32C_OFFSET] ^= 1;
            break;
        case 1:
            bytes[VIREO_PROTOCOL_MAGIC_OFFSET] ^= 1;
            break;
        case 2:
            bytes[VIREO_PROTOCOL_VERSION_OFFSET] = 2;
            break;
        case 3:
            bytes[VIREO_PROTOCOL_HEADER_LENGTH_OFFSET] = 31;
            break;
        case 4:
            bytes[VIREO_PROTOCOL_FLAGS_OFFSET] = 0x80;
            break;
        case 5:
            memset(bytes + VIREO_PROTOCOL_SEQUENCE_OFFSET, 0, 4);
            break;
        case 6:
            bytes[VIREO_PROTOCOL_COMMAND_OFFSET] = 0x7f;
            break;
        case 7:
            bytes[VIREO_PROTOCOL_FLAGS_OFFSET + 1] = VIREO_PROTOCOL_FLAG_RESPONSE;
            break;
        default:
            REQUIRE(false);
    }
    transmit(f.peers[0], bytes, sizeof(bytes));
    vireo_tcp_server_turn_result_t turns[2];
    vireo_tcp_server_round_info_t info;
    vireo_tcp_server_round_error_t error;
    REQUIRE(round_once(&f, 1, &allowance, turns, &info, &error) == VIREO_RESULT_PROTOCOL &&
            info.turn_count == 1);
    CHECK(error.stage == VIREO_TCP_SERVER_ROUND_DRIVE &&
          turns[0].error.primary_stage == VIREO_TCP_SERVER_DRIVE_PROCESS);
    CHECK(turns[0].error.primary_error.primary.stage == VIREO_TCP_SERVER_CLIENT_FRAMES_PEEK &&
          turns[0].error.primary_error.primary.frame_error.codec_issue == expected[variant]);
    CHECK(turns[0].info.process.handler_calls == 0 &&
          turns[0].info.process.consumed_requests == 0 && turns[0].close_attempted &&
          !turns[0].release_attempted && info.remaining_count == 0);
    vireo_connection_info_t c = client(&f, 0).connection_info;
    CHECK(c.read_buffer.readable_size == 32 && c.close_state == VIREO_CONNECTION_CLOSE_READY &&
          c.close_reason == VIREO_CONNECTION_CLOSE_REASON_PROTOCOL &&
          snapshot(&f).connection_count == 1);
    no_response(f.peers[0]);
    end(&f);
}
static void valid_prefix_then_bad_crc(void) {
    ++groups;
    fixture_t f;
    start(&f, 2, 8192, false);
    add_peer(&f, 0);
    uint8_t bytes[64];
    request(bytes, VIREO_COMMAND_PING, 501);
    request(bytes + 32, VIREO_COMMAND_SERVER_INFO, 502);
    bytes[32 + VIREO_PROTOCOL_CRC32C_OFFSET] ^= 1;
    transmit(f.peers[0], bytes, sizeof(bytes));
    vireo_tcp_server_drive_budget_t budget = allowance;
    budget.process = (vireo_tcp_server_process_budget_t){2, 192, 228};
    vireo_tcp_server_turn_result_t turns[2];
    vireo_tcp_server_round_info_t info;
    REQUIRE(round_once(&f, 1, &budget, turns, &info, NULL) == VIREO_RESULT_PROTOCOL &&
            info.turn_count == 1);
    CHECK(turns[0].info.process.handler_calls == 1 &&
          turns[0].info.process.enqueued_response_bytes == 32 &&
          turns[0].info.process.consumed_request_bytes == 32 && !turns[0].info.send_called);
    vireo_connection_info_t c = client(&f, 0).connection_info;
    CHECK(c.read_buffer.readable_size == 32 && c.write_buffer.readable_size == 32 &&
          c.close_state == VIREO_CONNECTION_CLOSE_OPEN);
    vireo_connection_send_info_t sent;
    REQUIRE(vireo_tcp_server_client_send(f.server, f.leases[0], &allowance.send, &sent, NULL) ==
            VIREO_OK);
    CHECK(sent.sent_bytes == 32);
    response(f.peers[0], VIREO_COMMAND_PING, 501, VIREO_STATUS_OK, NULL, 0);
    no_response(f.peers[0]);
    end(&f);
}
static void eof_cached_requests(void) {
    ++groups;
    fixture_t f;
    start(&f, 2, 8192, false);
    add_peer(&f, 0);
    REQUIRE(vireo_tcp_server_set_auto_close_policy(f.server, true, NULL) == VIREO_OK);
    REQUIRE(vireo_tcp_server_set_auto_release_ready(f.server, true, NULL) == VIREO_OK);
    uint8_t bytes[96];
    for (unsigned k = 0; k < 3; ++k)
        request(bytes + k * 32, VIREO_COMMAND_PING, 600 + k);
    transmit(f.peers[0], bytes, sizeof(bytes));
    REQUIRE(shutdown(f.peers[0], SHUT_WR) == 0);
    for (unsigned k = 0; k < 3; ++k) {
        vireo_tcp_server_turn_result_t turns[2];
        vireo_tcp_server_round_info_t info;
        REQUIRE(round_once(&f, 1, &allowance, turns, &info, NULL) == VIREO_OK &&
                info.turn_count == 1);
        CHECK(turns[0].info.process.handler_calls == 1 && !turns[0].released);
        CHECK(client(&f, 0).connection_info.read_eof);
        if (k < 2)
            CHECK(!turns[0].close_attempted &&
                  client(&f, 0).connection_info.close_state == VIREO_CONNECTION_CLOSE_OPEN);
        else
            CHECK(turns[0].close_attempted && turns[0].close_requeued);
        response(f.peers[0], VIREO_COMMAND_PING, 600 + k, VIREO_STATUS_OK, NULL, 0);
    }
    CHECK(client(&f, 0).connection_info.close_reason == VIREO_CONNECTION_CLOSE_REASON_PEER_EOF);
    vireo_tcp_server_turn_result_t turns[2];
    vireo_tcp_server_round_info_t info;
    REQUIRE(round_once(&f, 1, &allowance, turns, &info, NULL) == VIREO_OK && info.turn_count == 1);
    CHECK(turns[0].released && !turns[0].info.receive_called && !turns[0].info.send_called &&
          snapshot(&f).connection_count == 0 && snapshot(&f).buffer_capacity_bytes == 0);
    uint8_t b;
    CHECK(recv(f.peers[0], &b, 1, 0) == 0);
    end(&f);
}
static void eof_partial_frame(bool body) {
    ++groups;
    fixture_t f;
    start(&f, 2, 8192, false);
    add_peer(&f, 0);
    uint8_t bytes[33], b = 1;
    wire(bytes, (vireo_protocol_header_t){.command = VIREO_COMMAND_PING, .sequence = 700},
         body ? &b : NULL, body ? 1 : 0);
    size_t const n = body ? 32u : 17u;
    transmit(f.peers[0], bytes, n);
    REQUIRE(shutdown(f.peers[0], SHUT_WR) == 0);
    vireo_tcp_server_turn_result_t turns[2];
    vireo_tcp_server_round_info_t info;
    REQUIRE(round_once(&f, 1, &allowance, turns, &info, NULL) == VIREO_RESULT_PROTOCOL &&
            info.turn_count == 1);
    CHECK(turns[0].info.process.handler_calls == 0 && client(&f, 0).connection_info.read_eof &&
          client(&f, 0).connection_info.read_buffer.readable_size == n);
    CHECK(turns[0].error.primary_error.primary.stage == VIREO_TCP_SERVER_CLIENT_FRAMES_PEEK);
    end(&f);
}
/* 实际未读TCP peer产生send EAGAIN；桥接不注入系统返回值。 */
static void slow_peer_backpressure(void) {
    ++groups;
    fixture_t f;
    start(&f, 2, 16384, true);
    f.small_send_buffer = true;
    f.connection = (vireo_connection_options_t){256, 4096, 4352};
    f.flow = (vireo_connection_flow_options_t){96, 95, 192, 512, 3072};
    add_peer(&f, 0);
    uint8_t filler[4096];
    memset(filler, 0x5a, sizeof(filler));
    vireo_connection_send_budget_t const send_budget = {4096, 8};
    size_t sent_total = 0;
    bool blocked = false;
    unsigned attempts = 0;
    for (; attempts < 512; ++attempts) {
        REQUIRE(vireo_tcp_server_client_write_enqueue(f.server, f.leases[0], filler, sizeof(filler),
                                                      NULL) == VIREO_OK);
        vireo_connection_send_info_t info;
        REQUIRE(vireo_tcp_server_client_send(f.server, f.leases[0], &send_budget, &info, NULL) ==
                VIREO_OK);
        sent_total += info.sent_bytes;
        if (info.stop_reason == VIREO_CONNECTION_SEND_STOP_WOULD_BLOCK) {
            blocked = true;
            break;
        }
        REQUIRE(client(&f, 0).connection_info.write_buffer.readable_size == 0);
    }
    REQUIRE(blocked);
    size_t const pending = client(&f, 0).connection_info.write_buffer.readable_size;
    REQUIRE(vireo_tcp_server_client_write_enqueue(f.server, f.leases[0], filler,
                                                  sizeof(filler) - pending, NULL) == VIREO_OK);
    REQUIRE(vireo_tcp_server_client_flow_refresh(f.server, f.leases[0], NULL) == VIREO_OK);
    vireo_connection_info_t c = client(&f, 0).connection_info;
    CHECK(c.write_pressure && !(c.loop_interests & VIREO_EPOLL_EVENT_READ) &&
          (c.loop_interests & VIREO_EPOLL_EVENT_WRITE));
    uint8_t ping[32];
    request(ping, VIREO_COMMAND_PING, 801);
    transmit(f.peers[0], ping, sizeof(ping));
    REQUIRE(vireo_tcp_server_schedule_client(f.server, f.leases[0], NULL) == VIREO_OK);
    vireo_tcp_server_turn_result_t turns[2];
    vireo_tcp_server_round_info_t info;
    REQUIRE(round_once(&f, 1, &allowance, turns, &info, NULL) == VIREO_OK && info.turn_count == 1);
    CHECK(!turns[0].info.receive_called && turns[0].info.process.handler_calls == 0);
    /* 客户开始读：先取此前已成功send的确定前缀，再有界等待WRITE排空。 */
    sent_total += turns[0].info.send.sent_bytes;
    size_t remaining_filler = client(&f, 0).connection_info.write_buffer.readable_size;
    size_t remaining = sent_total;
    while (remaining) {
        size_t const n = remaining < sizeof(filler) ? remaining : sizeof(filler);
        read_exact(f.peers[0], filler, n);
        for (size_t k = 0; k < n; ++k)
            CHECK(filler[k] == 0x5a);
        remaining -= n;
    }
    uint8_t drained[4128];
    size_t have = 0, calls = 0;
    bool cleared = false;
    for (unsigned k = 0; k < 64; ++k) {
        REQUIRE(round_once(&f, 1, &allowance, turns, &info, NULL) == VIREO_OK);
        if (info.turn_count) {
            size_t const n = turns[0].info.send.sent_bytes;
            REQUIRE(n <= sizeof(drained) - have);
            read_exact(f.peers[0], drained + have, n);
            have += n;
            calls += turns[0].info.process.handler_calls;
        }
        c = client(&f, 0).connection_info;
        if (!c.write_pressure && (c.loop_interests & VIREO_EPOLL_EVENT_READ)) {
            CHECK(c.write_buffer.readable_size <= f.flow.write_low);
            cleared = true;
        }
        if (calls == 1 && c.write_buffer.readable_size == 0)
            break;
    }
    REQUIRE(calls == 1 && have == remaining_filler + 32);
    CHECK(cleared && !c.write_pressure && c.read_buffer.readable_size == 0);
    for (size_t k = 0; k < remaining_filler; ++k)
        CHECK(drained[k] == 0x5a);
    vireo_protocol_header_t h;
    vireo_protocol_codec_issue_t issue;
    REQUIRE(vireo_protocol_header_decode(drained + remaining_filler, 32, &h, &issue) == VIREO_OK);
    CHECK(vireo_protocol_response_header_validate(&h, &issue) == VIREO_OK &&
          h.command == VIREO_COMMAND_PING && h.sequence == 801 && h.body_len == 0 &&
          h.status == VIREO_STATUS_OK);
    CHECK(vireo_protocol_frame_crc32c_verify(drained + remaining_filler, 32, NULL, 0, &issue) ==
          VIREO_OK);
    printf("real TCP backpressure: attempts=%u confirmed_sent=%zu pending=%zu resumed=yes\n",
           attempts + 1, sent_total, remaining_filler);
    end(&f);
}
static void slot_and_fd_reuse(void) {
    ++groups;
    fixture_t f;
    start(&f, 1, 8192, true);
    add_peer(&f, 0);
    uint8_t bytes[64];
    request(bytes, VIREO_COMMAND_PING, 901);
    request(bytes + 32, VIREO_COMMAND_PING, 902);
    transmit(f.peers[0], bytes, sizeof(bytes));
    receive_pending(&f, 0, sizeof(bytes));
    REQUIRE(vireo_tcp_server_schedule_client(f.server, f.leases[0], NULL) == VIREO_OK);
    vireo_tcp_server_turn_result_t turns[2];
    vireo_tcp_server_round_info_t info;
    REQUIRE(round_once(&f, 1, &allowance, turns, &info, NULL) == VIREO_OK && info.turn_count == 1);
    response(f.peers[0], VIREO_COMMAND_PING, 901, VIREO_STATUS_OK, NULL, 0);
    CHECK(client(&f, 0).queued && client(&f, 0).connection_info.read_buffer.readable_size == 32);
    vireo_connection_pool_lease_t const old = f.leases[0];
    int const old_fd = f.accepted_fds[0];
    /* 先建第二peer，保留第一peer fd；避免其close抢先占用更小整数。 */
    f.peers[1] = connect_peer(&f);
    REQUIRE(vireo_tcp_server_release_client(f.server, &f.leases[0], NULL) == VIREO_OK);
    CHECK(snapshot(&f).pending_clients == 0 && snapshot(&f).buffer_capacity_bytes == 0);
    adopt_peer(&f, 1);
    CHECK(f.created == 2 && f.accepted_fds[1] == old_fd);
    CHECK(f.leases[1].slot_index == old.slot_index && f.leases[1].generation != old.generation &&
          f.leases[1].pool_id == old.pool_id);
    vireo_tcp_server_client_info_t stale;
    memset(&stale, 0xa5, sizeof(stale));
    unsigned char saved[sizeof(stale)];
    memcpy(saved, &stale, sizeof(stale));
    CHECK(vireo_tcp_server_client_inspect(f.server, old, &stale) == VIREO_RESULT_NOT_FOUND &&
          memcmp(saved, &stale, sizeof(stale)) == 0);
    CHECK(vireo_tcp_server_schedule_client(f.server, old, NULL) == VIREO_RESULT_NOT_FOUND);
    CHECK(client(&f, 1).connection_info.read_buffer.readable_size == 0 && !client(&f, 1).queued);
    request(bytes, VIREO_COMMAND_SERVER_INFO, 903);
    transmit(f.peers[1], bytes, 32);
    REQUIRE(round_once(&f, 1, &allowance, turns, &info, NULL) == VIREO_OK && info.turn_count == 1);
    CHECK(same(turns[0].client, f.leases[1]) && turns[0].info.process.handler_calls == 1);
    response(f.peers[1], VIREO_COMMAND_SERVER_INFO, 903, VIREO_STATUS_OK, (uint8_t const *)"0.1.0",
             5);
    no_response(f.peers[1]);
    printf("real TCP reuse: fd=%d slot=%zu generation=%llu -> %llu\n", old_fd, old.slot_index,
           (unsigned long long)old.generation, (unsigned long long)f.leases[1].generation);
    end(&f);
}
static void admission_capacity(bool by_buffer) {
    ++groups;
    fixture_t f;
    start(&f, by_buffer ? 2 : 1, by_buffer ? 512 : 8192, false);
    f.peers[0] = connect_peer(&f);
    f.peers[1] = connect_peer(&f);
    vireo_tcp_server_admission_options_t const options = {f.connection, f.flow};
    REQUIRE(vireo_tcp_server_admission_configure(f.server, &options, NULL) == VIREO_OK);
    vireo_tcp_server_serve_options_t const so = {
        100, {96, 114}, {{256, 8}, {1, 96, 114}, {256, 8}}, {2}, {2, 4}};
    uint8_t workspace[114];
    vireo_tcp_server_turn_result_t turns[2];
    vireo_connection_pool_lease_t admitted[2] = {{0}};
    vireo_tcp_server_serve_info_t info;
    REQUIRE(vireo_tcp_server_serve_once(f.server, &so, workspace, sizeof(workspace),
                                        vireo_tcp_server_handle_sync_command, &f.context, turns, 2,
                                        admitted, 2, &info, NULL) == VIREO_OK);
    REQUIRE(info.admission.admitted_count == 1 && info.initialized_count == 1);
    f.leases[0] = admitted[0];
    vireo_tcp_server_info_t s = snapshot(&f);
    CHECK(!s.listener_read_enabled &&
          (by_buffer ? s.admission_buffer_limited : s.admission_connection_limited));
    REQUIRE(vireo_tcp_server_release_client(f.server, &f.leases[0], NULL) == VIREO_OK);
    CHECK(!snapshot(&f).listener_read_enabled); /* 旧显式release不隐式刷新监听。 */
    REQUIRE(vireo_tcp_server_admission_refresh(f.server, NULL) == VIREO_OK);
    CHECK(snapshot(&f).listener_read_enabled && snapshot(&f).buffer_capacity_bytes == 0);
    memset(admitted, 0, sizeof(admitted));
    REQUIRE(vireo_tcp_server_serve_once(f.server, &so, workspace, sizeof(workspace),
                                        vireo_tcp_server_handle_sync_command, &f.context, turns, 2,
                                        admitted, 2, &info, NULL) == VIREO_OK);
    REQUIRE(info.admission.admitted_count == 1 && info.initialized_count == 1);
    f.leases[1] = admitted[0];
    uint8_t bytes[32];
    request(bytes, VIREO_COMMAND_SERVER_INFO, by_buffer ? 1002 : 1001);
    transmit(f.peers[1], bytes, 32);
    vireo_tcp_server_round_info_t round;
    REQUIRE(round_once(&f, 1, &allowance, turns, &round, NULL) == VIREO_OK &&
            round.turn_count == 1);
    response(f.peers[1], VIREO_COMMAND_SERVER_INFO, by_buffer ? 1002 : 1001, VIREO_STATUS_OK,
             (uint8_t const *)"0.1.0", 5);
    end(&f);
}
static void close_stop_shutdown(void) {
    ++groups;
    fixture_t f;
    start(&f, 2, 8192, false);
    add_peer(&f, 0);
    add_peer(&f, 1);
    uint8_t response_wire[32];
    wire(response_wire,
         (vireo_protocol_header_t){.command = VIREO_COMMAND_PING,
                                   .sequence = 1101,
                                   .flags = VIREO_PROTOCOL_FLAG_RESPONSE,
                                   .status = VIREO_STATUS_OK},
         NULL, 0);
    for (unsigned k = 0; k < 2; ++k)
        REQUIRE(vireo_tcp_server_client_write_enqueue(f.server, f.leases[k], response_wire, 32,
                                                      NULL) == VIREO_OK);
    REQUIRE(vireo_tcp_server_set_listener_read_enabled(f.server, false, NULL) == VIREO_OK);
    vireo_tcp_server_close_batch_budget_t const budget = {1};
    vireo_tcp_server_close_batch_result_t rows[1];
    vireo_tcp_server_close_batch_info_t batch;
    for (unsigned k = 0; k < 2; ++k) {
        REQUIRE(vireo_tcp_server_close_batch(f.server, VIREO_CONNECTION_CLOSE_MODE_DRAIN, &budget,
                                             rows, 1, &batch, NULL) == VIREO_OK);
        CHECK(batch.scanned_slots == 1 && batch.processed_clients == 1 && rows[0].scheduled);
    }
    CHECK(snapshot(&f).connection_count == 2 && snapshot(&f).buffer_capacity_bytes == 1024);
    vireo_tcp_server_turn_result_t turns[2];
    vireo_tcp_server_round_info_t round;
    REQUIRE(round_once(&f, 2, &allowance, turns, &round, NULL) == VIREO_OK &&
            round.turn_count == 2);
    for (unsigned k = 0; k < 2; ++k) {
        response(f.peers[k], VIREO_COMMAND_PING, 1101, VIREO_STATUS_OK, NULL, 0);
        CHECK(client(&f, k).connection_info.close_state == VIREO_CONNECTION_CLOSE_READY &&
              client(&f, k).connection_info.close_reason ==
                  VIREO_CONNECTION_CLOSE_REASON_SERVER_STOP);
    }
    REQUIRE(vireo_tcp_server_request_stop(f.server, NULL) == VIREO_OK);
    unsigned char saved[sizeof(turns)];
    memset(turns, 0xa5, sizeof(turns));
    memcpy(saved, turns, sizeof(turns));
    REQUIRE(round_once(&f, 2, &allowance, turns, &round, NULL) == VIREO_OK);
    CHECK(round.turn_count == 0 && memcmp(saved, turns, sizeof(turns)) == 0 &&
          snapshot(&f).connection_count == 2);
    vireo_tcp_server_shutdown_budget_t const sb = {1};
    vireo_tcp_server_shutdown_result_t result[1];
    vireo_tcp_server_shutdown_info_t si;
    for (unsigned k = 0; k < 2; ++k) {
        REQUIRE(vireo_tcp_server_shutdown_batch(f.server, &sb, result, 1, &si, NULL) == VIREO_OK);
        CHECK(si.scanned_slots == 1 && si.released_clients == 1 && result[0].released);
    }
    CHECK(snapshot(&f).connection_count == 0 && snapshot(&f).buffer_capacity_bytes == 0);
    end(&f);
}
int main(void) {
    unsigned const before = fd_count();
    fragmented_header();
    fragmented_body();
    coalesced_and_fair();
    half_frame_read_watermark();
    for (unsigned k = 0; k < 8; ++k)
        malformed(k);
    valid_prefix_then_bad_crc();
    eof_cached_requests();
    eof_partial_frame(false);
    eof_partial_frame(true);
    slow_peer_backpressure();
    slot_and_fd_reuse();
    admission_capacity(false);
    admission_capacity(true);
    close_stop_shutdown();
    unsigned const after = fd_count();
    CHECK(before == after);
    printf("tcp server integration: %u groups, %u failures, fd %u -> %u\n", groups, failures,
           before, after);
    return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}
