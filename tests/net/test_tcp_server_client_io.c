/*
- PROJECT : VIREO
- FILE    : test_tcp_server_client_io.c
- AUTHOR  : bitofux
- DATE    : 2026-10-05
- BRIEF   : 此模块负责：
- -- 当前租约隔离、有界字节 FIFO 与短期只读借用
- -- 默认真实 TCP/Unix、慢接收端及原错误/进度传递
 */
#include "net/tcp_server_internal.h"
#include <dirent.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

static unsigned failures, groups;
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #c); ++failures; } } while (0)
#define REQUIRE(c) do { if (!(c)) { fprintf(stderr, "fixture %s:%d: %s\n", __FILE__, __LINE__, #c); exit(EXIT_FAILURE); } } while (0)
static vireo_tcp_server_options_t const server_options = {2, 2, 1048576, 16384};
static vireo_connection_options_t const connection_options = {8, 8, 16};
static vireo_connection_receive_budget_t const read_budget = {SIZE_MAX, 8};
static vireo_connection_send_budget_t const write_budget = {SIZE_MAX, 8};
static uint8_t const marker = 77;
static bool same(vireo_connection_pool_lease_t a, vireo_connection_pool_lease_t b)
{ return a.pool_id == b.pool_id && a.slot_index == b.slot_index && a.generation == b.generation; }
static bool empty(vireo_connection_pool_lease_t l)
{ return l.pool_id == 0 && l.slot_index == 0 && l.generation == 0; }
static unsigned fd_count(void)
{
    DIR *d = opendir("/proc/self/fd"); REQUIRE(d != NULL);
    unsigned n = 0; struct dirent *e;
    while ((e = readdir(d)) != NULL) if (e->d_name[0] != '.') ++n;
    REQUIRE(closedir(d) == 0); return n;
}
typedef struct fixture {
    vireo_tcp_server_t *server;
    vireo_connection_pool_lease_t clients[2];
    struct sockaddr_storage address;
    socklen_t length;
    int family, peers[2];
    unsigned lookups, receives, peeks, consumes, enqueues, sends;
    bool receive_io, send_io, partial, peek_fail, release_busy;
} fixture_t;
static vireo_result_t accept_client(void *ctx, vireo_acceptor_t *a,
    vireo_acceptor_accept_budget_t const *b, int *fds, size_t n,
    vireo_acceptor_accept_info_t *i, vireo_acceptor_error_t *e)
{ (void)ctx; return vireo_acceptor_accept_batch(a, b, fds, n, i, e); }
static vireo_result_t create_client(void *ctx, vireo_connection_options_t const *o, int *fd,
    vireo_connection_t **c, vireo_connection_error_t *e)
{ (void)ctx; return vireo_connection_create(o, fd, c, e); }
static vireo_result_t inspect_client(void *ctx, vireo_connection_t const *c, vireo_connection_info_t *i)
{ (void)ctx; return vireo_connection_inspect(c, i); }
static vireo_result_t adopt_client(void *ctx, vireo_connection_pool_t *p, vireo_connection_t **c,
    vireo_connection_pool_lease_t *l, vireo_connection_pool_operation_error_t *e)
{ (void)ctx; return vireo_connection_pool_adopt(p, c, l, e); }
static vireo_result_t lookup_client(void *ctx, vireo_connection_pool_t const *p,
    vireo_connection_pool_lease_t l, vireo_connection_t **c)
{ fixture_t *f = ctx; ++f->lookups; errno = E2BIG; return vireo_connection_pool_lookup(p, l, c); }
static vireo_result_t attach_client(void *ctx, vireo_connection_t *c, vireo_event_loop_t *p,
    uint32_t mask, vireo_connection_callback_t cb, void *cbctx, vireo_connection_loop_error_t *e)
{ (void)ctx; return vireo_connection_attach(c, p, mask, cb, cbctx, e); }
static vireo_result_t detach_client(void *ctx, vireo_connection_t *c, vireo_connection_loop_error_t *e)
{ (void)ctx; return vireo_connection_detach(c, e); }
static vireo_result_t release_client(void *ctx, vireo_connection_pool_t *p,
    vireo_connection_pool_lease_t *l, vireo_connection_pool_operation_error_t *e)
{ fixture_t *f = ctx; return f->release_busy ? VIREO_RESULT_BUSY : vireo_connection_pool_release(p, l, e); }
static vireo_result_t destroy_client(void *ctx, vireo_connection_t **c, vireo_connection_error_t *e)
{ (void)ctx; return vireo_connection_destroy(c, e); }
static int close_fd(void *ctx, int fd) { (void)ctx; return close(fd); }
static vireo_result_t receive_bytes(void *ctx, vireo_connection_t *c,
    vireo_connection_receive_budget_t const *b, vireo_connection_receive_info_t *i,
    vireo_connection_error_t *e)
{
    fixture_t *f = ctx; ++f->receives;
    if (!f->receive_io) return vireo_connection_receive(c, b, i, e);
    /* 先真实执行合法接收以结束旧 view；部分模式取两字节，再模拟下一次失败。
     * 注入层的最后 IO/计数不是内核 EINTR 重现，实际字节进度独立核对。 */
    vireo_connection_receive_budget_t const small = {2, 1};
    REQUIRE(vireo_connection_receive(c, f->partial ? &small : b, i, e) == VIREO_OK);
    if (f->partial) { REQUIRE(i->received_bytes == 2 && b->max_syscalls >= 2); ++i->recv_calls; }
    i->stop_reason = VIREO_CONNECTION_RECEIVE_STOP_ERROR;
    *e = (vireo_connection_error_t){VIREO_CONNECTION_STAGE_RECEIVE, EINTR};
    errno = ERANGE; return VIREO_RESULT_IO;
}
static vireo_result_t peek_bytes(void *ctx, vireo_connection_t const *c, uint8_t const **p, size_t *n)
{
    fixture_t *f = ctx; ++f->peeks;
    return f->peek_fail ? VIREO_RESULT_INTERNAL : vireo_connection_read_peek(c, p, n);
}
static vireo_result_t consume_bytes(void *ctx, vireo_connection_t *c, size_t n)
{ fixture_t *f = ctx; ++f->consumes; return vireo_connection_read_consume(c, n); }
static vireo_result_t enqueue_bytes(void *ctx, vireo_connection_t *c, uint8_t const *p,
    size_t n, vireo_connection_error_t *e)
{ fixture_t *f = ctx; ++f->enqueues; return vireo_connection_write_enqueue(c, p, n, e); }
static vireo_result_t send_bytes(void *ctx, vireo_connection_t *c,
    vireo_connection_send_budget_t const *b, vireo_connection_send_info_t *i,
    vireo_connection_error_t *e)
{
    fixture_t *f = ctx; ++f->sends;
    if (!f->send_io) return vireo_connection_send(c, b, i, e);
    if (f->partial) {
        vireo_connection_send_budget_t const small = {2, 1};
        REQUIRE(vireo_connection_send(c, &small, i, e) == VIREO_OK && i->sent_bytes == 2 && b->max_syscalls >= 2);
        ++i->send_calls;
    } else *i = (vireo_connection_send_info_t){.send_calls = 1};
    i->stop_reason = VIREO_CONNECTION_SEND_STOP_ERROR;
    *e = (vireo_connection_error_t){VIREO_CONNECTION_STAGE_SEND, EPIPE};
    errno = ERANGE; return VIREO_RESULT_IO;
}
static vireo_result_t frame_views(void *ctx, vireo_connection_t const *c,
    vireo_connection_frame_options_t const *o, vireo_connection_frame_budget_t const *b,
    vireo_connection_frame_view_t *v, size_t n, vireo_connection_frame_info_t *i,
    vireo_connection_frame_error_t *e)
{ (void)ctx; return vireo_connection_frames_peek(c, o, b, v, n, i, e); }
/** 只桥接公开 set_interests；不持有第二 owner、不扩展依赖策略。 */
static vireo_result_t policy_set_interests(void *ctx, vireo_connection_t *c,
    uint32_t interests, vireo_connection_loop_error_t *error)
{
    (void)ctx;
    return vireo_connection_set_interests(c, interests, error);
}
/** 只桥接公开 flow_configure；不持有第二 owner、不扩展依赖策略。 */
static vireo_result_t policy_flow_configure(void *ctx, vireo_connection_t *c,
    vireo_connection_flow_options_t const *options, vireo_connection_loop_error_t *error)
{
    (void)ctx;
    return vireo_connection_flow_configure(c, options, error);
}
/** 只桥接公开 flow_refresh；不持有第二 owner、不扩展依赖策略。 */
static vireo_result_t policy_flow_refresh(void *ctx, vireo_connection_t *c,
    vireo_connection_loop_error_t *error)
{
    (void)ctx;
    return vireo_connection_flow_refresh(c, error);
}
/** 只桥接公开 flow_disable；不持有第二 owner、不扩展依赖策略。 */
static vireo_result_t policy_flow_disable(void *ctx, vireo_connection_t *c,
    vireo_connection_loop_error_t *error)
{
    (void)ctx;
    return vireo_connection_flow_disable(c, error);
}
/** 只桥接公开 request_close；不持有第二 owner、不扩展依赖策略。 */
static vireo_result_t policy_request_close(void *ctx, vireo_connection_t *c,
    vireo_connection_close_mode_t mode,
    vireo_connection_close_reason_t reason, vireo_connection_loop_error_t *error)
{
    (void)ctx;
    return vireo_connection_request_close(c, mode, reason, error);
}
/** 只桥接公开 close_refresh；不持有第二 owner、不扩展依赖策略。 */
static vireo_result_t policy_close_refresh(void *ctx, vireo_connection_t *c,
    vireo_connection_loop_error_t *error)
{
    (void)ctx;
    return vireo_connection_close_refresh(c, error);
}

static vireo_tcp_server_client_ops_t ops(fixture_t *f)
{
    return (vireo_tcp_server_client_ops_t){f, accept_client, create_client, inspect_client,
        adopt_client, lookup_client, attach_client, detach_client, release_client, destroy_client,
        close_fd, receive_bytes, peek_bytes, consume_bytes, enqueue_bytes, send_bytes, frame_views,
        policy_set_interests, policy_flow_configure, policy_flow_refresh, policy_flow_disable, policy_request_close, policy_close_refresh};
}
static void start(fixture_t *f, int family, bool hooked, vireo_connection_options_t o, size_t count)
{
    static unsigned serial; f->family = family;
    if (hooked) {
        vireo_tcp_server_client_ops_t table = ops(f);
        REQUIRE(vireo_tcp_server_create_with_client_ops(&server_options, NULL, NULL, &table, &f->server, NULL) == VIREO_OK);
        memset(&table, 0, sizeof(table)); /* 对象完整按值复制。 */
    } else REQUIRE(vireo_tcp_server_create(&server_options, &f->server, NULL) == VIREO_OK);
    int fd = socket(family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0); REQUIRE(fd >= 0);
    if (family == AF_INET) {
        struct sockaddr_in a = {.sin_family = AF_INET, .sin_addr = {htonl(INADDR_LOOPBACK)}};
        f->length = (socklen_t)sizeof(a); REQUIRE(bind(fd, (struct sockaddr *)&a, f->length) == 0);
        REQUIRE(getsockname(fd, (struct sockaddr *)&f->address, &f->length) == 0);
    } else {
        struct sockaddr_un a = {.sun_family = AF_UNIX};
        int const n = snprintf(a.sun_path + 1, sizeof(a.sun_path) - 1, "vireo-byte-%ld-%u", (long)getpid(), ++serial);
        REQUIRE(n > 0 && (size_t)n < sizeof(a.sun_path) - 1);
        memcpy(&f->address, &a, sizeof(a)); f->length = (socklen_t)sizeof(a);
        REQUIRE(bind(fd, (struct sockaddr *)&f->address, f->length) == 0);
    }
    REQUIRE(listen(fd, 8) == 0);
    vireo_acceptor_options_t const aopts = {4096}; vireo_acceptor_t *a = NULL;
    REQUIRE(vireo_acceptor_create(&aopts, &fd, &a, NULL) == VIREO_OK);
    REQUIRE(vireo_tcp_server_adopt_listener(f->server, &a, NULL) == VIREO_OK && a == NULL);
    for (size_t k = 0; k < count; ++k) {
        f->peers[k] = socket(family, SOCK_STREAM | SOCK_CLOEXEC, 0); REQUIRE(f->peers[k] >= 0);
        struct timeval const timeout = {2, 0};
        REQUIRE(setsockopt(f->peers[k], SOL_SOCKET, SO_RCVTIMEO, &timeout, (socklen_t)sizeof(timeout)) == 0);
        REQUIRE(connect(f->peers[k], (struct sockaddr *)&f->address, f->length) == 0);
    }
    vireo_tcp_server_admit_budget_t const b = {count, count}; vireo_tcp_server_admit_info_t i;
    REQUIRE(vireo_tcp_server_admit_batch(f->server, &o, &b, f->clients, count, &i, NULL) == VIREO_OK && i.admitted_count == count);
}
static void end(fixture_t *f, size_t count)
{
    f->release_busy = false;
    for (size_t k = 0; k < count; ++k) {
        if (!empty(f->clients[k])) REQUIRE(vireo_tcp_server_release_client(f->server, &f->clients[k], NULL) == VIREO_OK);
        REQUIRE(close(f->peers[k]) == 0);
    }
    REQUIRE(vireo_tcp_server_destroy(&f->server, NULL) == VIREO_OK && f->server == NULL);
}
static vireo_tcp_server_client_info_t info(fixture_t *f, size_t n)
{ vireo_tcp_server_client_info_t i; REQUIRE(vireo_tcp_server_client_inspect(f->server, f->clients[n], &i) == VIREO_OK); return i; }
static void expect_read(fixture_t *f, size_t n, char const *bytes, size_t length)
{
    uint8_t const *p = NULL; size_t size = 0;
    REQUIRE(vireo_tcp_server_client_read_peek(f->server, f->clients[n], &p, &size, NULL) == VIREO_OK);
    CHECK(size == length && (length == 0 ? p == NULL : p != NULL && memcmp(p, bytes, length) == 0));
}
static void recv_exact(int fd, char const *expected, size_t size)
{
    char bytes[4096]; size_t offset = 0; REQUIRE(size <= sizeof(bytes));
    while (offset < size) { ssize_t const n = recv(fd, bytes + offset, size - offset, 0); REQUIRE(n > 0); offset += (size_t)n; }
    CHECK(memcmp(bytes, expected, size) == 0);
}
static void native_bytes(int family)
{
    ++groups; fixture_t f = {0}; start(&f, family, false, connection_options, 2);
    REQUIRE(send(f.peers[0], "abcde", 5, MSG_NOSIGNAL) == 5 && send(f.peers[1], "XYZ", 3, MSG_NOSIGNAL) == 3);
    vireo_connection_receive_budget_t const small = {2, 1}; vireo_connection_receive_info_t ri;
    errno = EDOM;
    REQUIRE(vireo_tcp_server_client_receive(f.server, f.clients[0], &small, &ri, NULL) == VIREO_OK && errno == EDOM);
    CHECK(ri.received_bytes == 2 && ri.recv_calls == 1 && ri.stop_reason == VIREO_CONNECTION_RECEIVE_STOP_BYTE_BUDGET);
    uint8_t const *view = NULL; size_t size = 0;
    REQUIRE(vireo_tcp_server_client_read_peek(f.server, f.clients[0], &view, &size, NULL) == VIREO_OK && size == 2);
    REQUIRE(vireo_tcp_server_client_receive(f.server, f.clients[1], &read_budget, &ri, NULL) == VIREO_OK);
    CHECK(ri.received_bytes == 3 && memcmp(view, "ab", 2) == 0); expect_read(&f, 1, "XYZ", 3);
    REQUIRE(vireo_tcp_server_client_write_enqueue(f.server, f.clients[0], view, size, NULL) == VIREO_OK);
    REQUIRE(vireo_tcp_server_client_read_consume(f.server, f.clients[0], size, NULL) == VIREO_OK);
    expect_read(&f, 0, "", 0);
    vireo_connection_send_budget_t const one = {1, 1}; vireo_connection_send_info_t si;
    REQUIRE(vireo_tcp_server_client_send(f.server, f.clients[0], &one, &si, NULL) == VIREO_OK);
    CHECK(si.sent_bytes == 1 && si.send_calls == 1 && si.stop_reason == VIREO_CONNECTION_SEND_STOP_BYTE_BUDGET);
    recv_exact(f.peers[0], "a", 1); CHECK(info(&f, 0).connection_info.write_buffer.readable_size == 1);
    REQUIRE(vireo_tcp_server_client_send(f.server, f.clients[0], &write_budget, &si, NULL) == VIREO_OK);
    CHECK(si.sent_bytes == 1 && si.stop_reason == VIREO_CONNECTION_SEND_STOP_EMPTY); recv_exact(f.peers[0], "b", 1);
    REQUIRE(vireo_tcp_server_client_receive(f.server, f.clients[0], &read_budget, &ri, NULL) == VIREO_OK && ri.received_bytes == 3);
    expect_read(&f, 0, "cde", 3); expect_read(&f, 1, "XYZ", 3);
    char copy[] = "123";
    REQUIRE(vireo_tcp_server_client_write_enqueue(f.server, f.clients[1], (uint8_t const *)copy, 3, NULL) == VIREO_OK);
    memset(copy, '9', 3);
    REQUIRE(vireo_tcp_server_client_send(f.server, f.clients[1], &write_budget, &si, NULL) == VIREO_OK); recv_exact(f.peers[1], "123", 3);
    vireo_tcp_server_info_t state; REQUIRE(vireo_tcp_server_inspect(f.server, &state) == VIREO_OK);
    CHECK(state.connection_count == 2 && state.buffer_capacity_bytes == 32 && state.registered_connections == 2);
    CHECK(info(&f, 1).connection_info.loop_interests == (VIREO_EPOLL_INTEREST_READ | VIREO_EPOLL_INTEREST_PEER_WRITE_CLOSED));
    end(&f, 2);
}
static unsigned calls(fixture_t const *f) { return f->receives + f->peeks + f->consumes + f->enqueues + f->sends; }
static void parameters(void)
{
    ++groups; fixture_t f = {0}; start(&f, AF_UNIX, true, connection_options, 1);
    vireo_connection_receive_info_t ri, before_r; vireo_connection_send_info_t si, before_s;
    memset(&ri, 0xa5, sizeof(ri)); memcpy(&before_r, &ri, sizeof(ri));
    memset(&si, 0xa5, sizeof(si)); memcpy(&before_s, &si, sizeof(si));
    vireo_connection_pool_lease_t l = f.clients[0]; vireo_tcp_server_client_error_t e;
    uint8_t const *p = &marker; size_t n = 99;
    for (unsigned k = 0; k < 3; ++k) {
        errno = EDOM;
        CHECK(vireo_tcp_server_client_receive(k == 0 ? NULL : f.server, l, k == 1 ? NULL : &read_budget, k == 2 ? NULL : &ri, &e) == VIREO_RESULT_INVALID_ARGUMENT && errno == EDOM);
        CHECK(vireo_tcp_server_client_send(k == 0 ? NULL : f.server, l, k == 1 ? NULL : &write_budget, k == 2 ? NULL : &si, &e) == VIREO_RESULT_INVALID_ARGUMENT && errno == EDOM);
        CHECK(vireo_tcp_server_client_read_peek(k == 0 ? NULL : f.server, l, k == 1 ? NULL : &p, k == 2 ? NULL : &n, &e) == VIREO_RESULT_INVALID_ARGUMENT && errno == EDOM);
        CHECK(e.primary.stage == VIREO_TCP_SERVER_CLIENT_NONE && e.cleanup_result == VIREO_OK);
    }
    for (unsigned k = 0; k < 2; ++k) {
        vireo_connection_receive_budget_t const rb = {k == 0 ? 0 : 1, k == 1 ? 0 : 1};
        vireo_connection_send_budget_t const sb = {rb.max_bytes, rb.max_syscalls}; errno = EDOM;
        CHECK(vireo_tcp_server_client_receive(f.server, l, &rb, &ri, &e) == VIREO_RESULT_RANGE && errno == EDOM);
        CHECK(vireo_tcp_server_client_send(f.server, l, &sb, &si, &e) == VIREO_RESULT_RANGE && errno == EDOM);
    }
    CHECK(vireo_tcp_server_client_write_enqueue(NULL, l, &marker, 1, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_tcp_server_client_write_enqueue(f.server, l, NULL, 1, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_tcp_server_client_read_consume(NULL, l, 0, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(calls(&f) == 0 && f.lookups == 1 && p == &marker && n == 99 &&
          memcmp(&ri, &before_r, sizeof(ri)) == 0 && memcmp(&si, &before_s, sizeof(si)) == 0);
    REQUIRE(vireo_tcp_server_client_write_enqueue(f.server, l, NULL, 0, NULL) == VIREO_OK);
    REQUIRE(vireo_tcp_server_client_read_consume(f.server, l, 0, NULL) == VIREO_OK);
    end(&f, 1);
    for (unsigned k = 0; k < 5; ++k) {
        vireo_tcp_server_client_ops_t table = ops(&f);
        if (k == 0) table.receive = NULL;
        if (k == 1) table.read_peek = NULL;
        if (k == 2) table.read_consume = NULL;
        if (k == 3) table.write_enqueue = NULL;
        if (k == 4) table.send = NULL;
        CHECK(vireo_tcp_server_create_with_client_ops(&server_options, NULL, NULL, &table, &f.server, NULL) == VIREO_RESULT_INVALID_ARGUMENT && f.server == NULL);
    }
}
static void identity(void)
{
    ++groups; fixture_t f = {0}; start(&f, AF_UNIX, true, connection_options, 1);
    vireo_connection_pool_lease_t const original = f.clients[0];
    vireo_connection_pool_lease_t bad[5] = {{0}, original, original, original, original};
    bad[1].pool_id = 0; bad[2].slot_index = 2; ++bad[3].generation;
    vireo_tcp_server_t *other = NULL; REQUIRE(vireo_tcp_server_create(&server_options, &other, NULL) == VIREO_OK);
    for (size_t k = 0; k < 5; ++k) {
        vireo_result_t const expected = k == 0 || k == 3 ? VIREO_RESULT_NOT_FOUND : k == 2 ? VIREO_RESULT_RANGE : VIREO_RESULT_INVALID_ARGUMENT;
        vireo_tcp_server_t *s = k == 4 ? other : f.server;
        vireo_connection_receive_info_t ri, old_r; vireo_connection_send_info_t si, old_s;
        memset(&ri, 0xa5, sizeof(ri)); memcpy(&old_r, &ri, sizeof(ri));
        memset(&si, 0xa5, sizeof(si)); memcpy(&old_s, &si, sizeof(si));
        uint8_t const *p = &marker; size_t n = 99; vireo_tcp_server_client_error_t e; errno = EDOM;
        CHECK(vireo_tcp_server_client_receive(s, bad[k], &read_budget, &ri, &e) == expected && e.primary.stage == VIREO_TCP_SERVER_CLIENT_LOOKUP);
        CHECK(vireo_tcp_server_client_read_peek(s, bad[k], &p, &n, &e) == expected);
        CHECK(vireo_tcp_server_client_read_consume(s, bad[k], 0, &e) == expected);
        CHECK(vireo_tcp_server_client_write_enqueue(s, bad[k], &marker, 1, &e) == expected);
        CHECK(vireo_tcp_server_client_send(s, bad[k], &write_budget, &si, &e) == expected && errno == EDOM);
        CHECK(p == &marker && n == 99 && memcmp(&ri, &old_r, sizeof(ri)) == 0 && memcmp(&si, &old_s, sizeof(si)) == 0);
    }
    CHECK(calls(&f) == 0);
    REQUIRE(vireo_tcp_server_destroy(&other, NULL) == VIREO_OK);
    REQUIRE(vireo_tcp_server_release_client(f.server, &f.clients[0], NULL) == VIREO_OK);
    int const peer2 = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0); REQUIRE(peer2 >= 0);
    REQUIRE(connect(peer2, (struct sockaddr *)&f.address, f.length) == 0);
    vireo_tcp_server_admit_budget_t const b = {1, 1}; vireo_tcp_server_admit_info_t ai;
    REQUIRE(vireo_tcp_server_admit_batch(f.server, &connection_options, &b, f.clients, 1, &ai, NULL) == VIREO_OK && !same(original, f.clients[0]));
    vireo_connection_receive_info_t ri; unsigned const old_calls = calls(&f);
    CHECK(vireo_tcp_server_client_receive(f.server, original, &read_budget, &ri, NULL) == VIREO_RESULT_NOT_FOUND && calls(&f) == old_calls);
    REQUIRE(send(peer2, "new", 3, MSG_NOSIGNAL) == 3);
    REQUIRE(vireo_tcp_server_client_receive(f.server, f.clients[0], &read_budget, &ri, NULL) == VIREO_OK); expect_read(&f, 0, "new", 3);
    REQUIRE(close(f.peers[0]) == 0); f.peers[0] = peer2; end(&f, 1);
}
static void boundaries_and_borrow(void)
{
    ++groups; fixture_t f = {0}; vireo_connection_options_t const o = {4, 4, 8}; start(&f, AF_UNIX, true, o, 1);
    REQUIRE(send(f.peers[0], "abcdE", 5, MSG_NOSIGNAL) == 5);
    vireo_connection_receive_info_t ri;
    REQUIRE(vireo_tcp_server_client_receive(f.server, f.clients[0], &read_budget, &ri, NULL) == VIREO_OK && ri.received_bytes == 4 && ri.stop_reason == VIREO_CONNECTION_RECEIVE_STOP_BUFFER_FULL);
    uint8_t const *p = NULL; size_t n = 0; vireo_tcp_server_client_error_t e;
    REQUIRE(vireo_tcp_server_client_read_peek(f.server, f.clients[0], &p, &n, NULL) == VIREO_OK);
    CHECK(vireo_tcp_server_client_read_consume(f.server, f.clients[0], 5, &e) == VIREO_RESULT_RANGE && e.primary.stage == VIREO_TCP_SERVER_CLIENT_READ_CONSUME && memcmp(p, "abcd", 4) == 0);
    CHECK(vireo_tcp_server_client_write_enqueue(f.server, f.clients[0], &marker, 5, &e) == VIREO_RESULT_RANGE);
    REQUIRE(vireo_tcp_server_client_write_enqueue(f.server, f.clients[0], p, n, NULL) == VIREO_OK);
    CHECK(vireo_tcp_server_client_write_enqueue(f.server, f.clients[0], &marker, 1, &e) == VIREO_RESULT_BUSY);
    CHECK(vireo_tcp_server_client_write_enqueue(f.server, f.clients[0], &marker, SIZE_MAX, &e) == VIREO_RESULT_OVERFLOW);
    CHECK(memcmp(p, "abcd", 4) == 0 && info(&f, 0).connection_info.write_buffer.readable_size == 4);
    vireo_connection_send_info_t si; vireo_connection_send_budget_t const one = {2, 1};
    REQUIRE(vireo_tcp_server_client_send(f.server, f.clients[0], &one, &si, NULL) == VIREO_OK); recv_exact(f.peers[0], "ab", 2);
    CHECK(memcmp(p, "abcd", 4) == 0); /* write 操作和 inspect 不结束合法 read 借用。 */
    REQUIRE(vireo_tcp_server_client_write_enqueue(f.server, f.clients[0], (uint8_t const *)"EF", 2, NULL) == VIREO_OK);
    REQUIRE(vireo_tcp_server_client_send(f.server, f.clients[0], &write_budget, &si, NULL) == VIREO_OK); recv_exact(f.peers[0], "cdEF", 4);
    REQUIRE(vireo_tcp_server_client_read_consume(f.server, f.clients[0], 0, NULL) == VIREO_OK);
    expect_read(&f, 0, "abcd", 4); /* 重新取得 view，不继续解引用被 consume0 结束的旧 p。 */
    REQUIRE(vireo_tcp_server_client_read_consume(f.server, f.clients[0], 2, NULL) == VIREO_OK);
    REQUIRE(vireo_tcp_server_client_receive(f.server, f.clients[0], &read_budget, &ri, NULL) == VIREO_OK && ri.received_bytes == 1);
    expect_read(&f, 0, "cdE", 3); /* 真实读 compact 保留前缀顺序。 */
    end(&f, 1);
}
static void eof_and_empty(void)
{
    ++groups; fixture_t f = {0}; start(&f, AF_UNIX, false, connection_options, 1);
    vireo_connection_receive_info_t ri; vireo_connection_send_info_t si;
    REQUIRE(vireo_tcp_server_client_receive(f.server, f.clients[0], &read_budget, &ri, NULL) == VIREO_OK);
    CHECK(ri.received_bytes == 0 && ri.recv_calls == 1 && ri.stop_reason == VIREO_CONNECTION_RECEIVE_STOP_WOULD_BLOCK);
    REQUIRE(vireo_tcp_server_client_send(f.server, f.clients[0], &write_budget, &si, NULL) == VIREO_OK);
    CHECK(si.sent_bytes == 0 && si.send_calls == 0 && si.stop_reason == VIREO_CONNECTION_SEND_STOP_EMPTY);
    REQUIRE(send(f.peers[0], "last", 4, MSG_NOSIGNAL) == 4 && shutdown(f.peers[0], SHUT_WR) == 0);
    REQUIRE(vireo_tcp_server_client_receive(f.server, f.clients[0], &read_budget, &ri, NULL) == VIREO_OK);
    CHECK(ri.received_bytes == 4 && ri.recv_calls == 2 && ri.stop_reason == VIREO_CONNECTION_RECEIVE_STOP_EOF);
    expect_read(&f, 0, "last", 4);
    REQUIRE(vireo_tcp_server_client_receive(f.server, f.clients[0], &read_budget, &ri, NULL) == VIREO_OK);
    CHECK(ri.received_bytes == 0 && ri.recv_calls == 0 && ri.stop_reason == VIREO_CONNECTION_RECEIVE_STOP_EOF);
    REQUIRE(vireo_tcp_server_client_write_enqueue(f.server, f.clients[0], (uint8_t const *)"reply", 5, NULL) == VIREO_OK);
    REQUIRE(vireo_tcp_server_client_send(f.server, f.clients[0], &write_budget, &si, NULL) == VIREO_OK); recv_exact(f.peers[0], "reply", 5);
    expect_read(&f, 0, "last", 4); CHECK(info(&f, 0).connection_info.read_eof);
    end(&f, 1);
}
static void failures_and_progress(void)
{
    ++groups;
    for (unsigned k = 0; k < 2; ++k) {
        fixture_t f = {0}; start(&f, AF_UNIX, true, connection_options, 1); f.partial = k != 0;
        if (f.partial) REQUIRE(send(f.peers[0], "abcd", 4, MSG_NOSIGNAL) == 4);
        f.receive_io = true; vireo_connection_receive_info_t ri; vireo_tcp_server_client_error_t e; errno = EDOM;
        CHECK(vireo_tcp_server_client_receive(f.server, f.clients[0], &read_budget, &ri, &e) == VIREO_RESULT_IO && errno == EDOM &&
              e.primary.stage == VIREO_TCP_SERVER_CLIENT_RECEIVE && e.primary.connection_error.stage == VIREO_CONNECTION_STAGE_RECEIVE &&
              e.primary.connection_error.system_errno == EINTR && e.cleanup_result == VIREO_OK && f.receives == 1);
        CHECK(ri.received_bytes == (f.partial ? 2 : 0) && ri.recv_calls == (f.partial ? 2 : 1));
        expect_read(&f, 0, f.partial ? "ab" : "", f.partial ? 2 : 0);
        f.receive_io = false;
        REQUIRE(vireo_tcp_server_client_receive(f.server, f.clients[0], &read_budget, &ri, NULL) == VIREO_OK);
        if (f.partial) expect_read(&f, 0, "abcd", 4);
        f.peek_fail = true; uint8_t const *p = &marker; size_t n = 99; errno = EDOM;
        CHECK(vireo_tcp_server_client_read_peek(f.server, f.clients[0], &p, &n, &e) == VIREO_RESULT_INTERNAL && p == &marker && n == 99 &&
              e.primary.stage == VIREO_TCP_SERVER_CLIENT_READ_PEEK && errno == EDOM); f.peek_fail = false;
        REQUIRE(vireo_tcp_server_client_write_enqueue(f.server, f.clients[0], (uint8_t const *)"WXYZ", 4, NULL) == VIREO_OK);
        f.send_io = true; vireo_connection_send_info_t si; errno = EDOM;
        CHECK(vireo_tcp_server_client_send(f.server, f.clients[0], &write_budget, &si, &e) == VIREO_RESULT_IO && errno == EDOM &&
              e.primary.stage == VIREO_TCP_SERVER_CLIENT_SEND && e.primary.connection_error.stage == VIREO_CONNECTION_STAGE_SEND &&
              e.primary.connection_error.system_errno == EPIPE && e.cleanup_result == VIREO_OK && f.sends == 1);
        CHECK(si.sent_bytes == (f.partial ? 2 : 0) && si.send_calls == (f.partial ? 2 : 1));
        if (f.partial) recv_exact(f.peers[0], "WX", 2);
        CHECK(info(&f, 0).connection_info.write_buffer.readable_size == (f.partial ? 2 : 4));
        f.send_io = false;
        REQUIRE(vireo_tcp_server_client_send(f.server, f.clients[0], &write_budget, &si, NULL) == VIREO_OK);
        recv_exact(f.peers[0], f.partial ? "YZ" : "WXYZ", f.partial ? 2 : 4);
        end(&f, 1);
    }
}
static void unbound_owned(void)
{
    ++groups; fixture_t f = {0}; start(&f, AF_UNIX, true, connection_options, 1);
    f.release_busy = true; vireo_connection_pool_lease_t const saved = f.clients[0];
    REQUIRE(vireo_tcp_server_release_client(f.server, &f.clients[0], NULL) == VIREO_RESULT_BUSY && same(saved, f.clients[0]));
    CHECK(!info(&f, 0).connection_info.loop_attached);
    REQUIRE(send(f.peers[0], "raw", 3, MSG_NOSIGNAL) == 3);
    vireo_connection_receive_info_t ri;
    REQUIRE(vireo_tcp_server_client_receive(f.server, f.clients[0], &read_budget, &ri, NULL) == VIREO_OK); expect_read(&f, 0, "raw", 3);
    REQUIRE(vireo_tcp_server_client_write_enqueue(f.server, f.clients[0], (uint8_t const *)"out", 3, NULL) == VIREO_OK);
    vireo_connection_send_info_t si; REQUIRE(vireo_tcp_server_client_send(f.server, f.clients[0], &write_budget, &si, NULL) == VIREO_OK);
    recv_exact(f.peers[0], "out", 3); end(&f, 1);
}
static void native_epipe(void)
{
    ++groups; fixture_t f = {0}; start(&f, AF_UNIX, false, connection_options, 1);
    REQUIRE(close(f.peers[0]) == 0); f.peers[0] = -1;
    REQUIRE(vireo_tcp_server_client_write_enqueue(f.server, f.clients[0], (uint8_t const *)"keep", 4, NULL) == VIREO_OK);
    vireo_connection_send_info_t si; vireo_tcp_server_client_error_t e; errno = EDOM;
    CHECK(vireo_tcp_server_client_send(f.server, f.clients[0], &write_budget, &si, &e) == VIREO_RESULT_IO && errno == EDOM &&
          e.primary.connection_error.system_errno == EPIPE && si.sent_bytes == 0 && si.send_calls == 1);
    CHECK(info(&f, 0).connection_info.write_buffer.readable_size == 4);
    REQUIRE(vireo_tcp_server_release_client(f.server, &f.clients[0], NULL) == VIREO_OK);
    REQUIRE(vireo_tcp_server_destroy(&f.server, NULL) == VIREO_OK);
}
static void slow_peer(void)
{
    ++groups; fixture_t f = {0}; vireo_connection_options_t const o = {8, 4096, 4104}; start(&f, AF_UNIX, false, o, 1);
    char data[4096]; memset(data, 'q', sizeof(data));
    vireo_connection_send_budget_t const b = {SIZE_MAX, 2}; vireo_connection_send_info_t si;
    size_t total = 0; bool blocked = false;
    for (size_t k = 0; k < 2048; ++k) {
        if (info(&f, 0).connection_info.write_buffer.readable_size == 0)
            REQUIRE(vireo_tcp_server_client_write_enqueue(f.server, f.clients[0], (uint8_t const *)data, sizeof(data), NULL) == VIREO_OK);
        REQUIRE(vireo_tcp_server_client_send(f.server, f.clients[0], &b, &si, NULL) == VIREO_OK);
        total += si.sent_bytes;
        if (si.stop_reason == VIREO_CONNECTION_SEND_STOP_WOULD_BLOCK) { blocked = true; break; }
    }
    CHECK(blocked && total > 0 && info(&f, 0).connection_info.write_buffer.readable_size > 0);
    size_t remaining = total;
    while (remaining != 0) {
        char bytes[4096]; size_t const request = remaining < sizeof(bytes) ? remaining : sizeof(bytes);
        ssize_t const n = recv(f.peers[0], bytes, request, 0); REQUIRE(n > 0);
        for (size_t k = 0; k < (size_t)n; ++k) CHECK(bytes[k] == 'q');
        remaining -= (size_t)n;
    }
    size_t const pending = info(&f, 0).connection_info.write_buffer.readable_size;
    REQUIRE(vireo_tcp_server_client_send(f.server, f.clients[0], &write_budget, &si, NULL) == VIREO_OK);
    CHECK(si.sent_bytes == pending && si.stop_reason == VIREO_CONNECTION_SEND_STOP_EMPTY);
    recv_exact(f.peers[0], data, pending); end(&f, 1);
}
int main(void)
{
    unsigned const before = fd_count();
    native_bytes(AF_INET); native_bytes(AF_UNIX); parameters(); identity(); boundaries_and_borrow();
    eof_and_empty(); failures_and_progress(); unbound_owned(); native_epipe(); slow_peer();
    unsigned const after = fd_count(); CHECK(before == after);
    printf("tcp_server client I/O: %u groups, %u failures; fd %u -> %u\n", groups, failures, before, after);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
