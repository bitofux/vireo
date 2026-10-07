/*
- PROJECT : VIREO
- FILE    : test_tcp_server_client_framing.c
- AUTHOR  : bitofux
- DATE    : 2026-10-05
- BRIEF   : 此模块负责：
- -- 当前租约帧前缀、预算边界与 body 短借用
- -- 默认真实 TCP/Unix、半包粘包和完整原帧诊断
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
static vireo_connection_options_t const connection_options = {256, 128, 384};
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
    unsigned frame_calls;
    int frame_mode;
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
{
    fixture_t *f = ctx; ++f->frame_calls;
    if (f->frame_mode == 1) { errno = ERANGE; return VIREO_RESULT_RANGE; }
    if (f->frame_mode == 2) {
        vireo_connection_frame_budget_t const one = {1, b->max_bytes};
        REQUIRE(vireo_connection_frames_peek(c, o, &one, v, n, i, e) == VIREO_OK && i->frame_count == 1);
        i->stop_reason = VIREO_CONNECTION_FRAME_STOP_ERROR;
        *e = (vireo_connection_frame_error_t){VIREO_CONNECTION_FRAME_ISSUE_NONE, VIREO_PROTOCOL_CODEC_ISSUE_NONE};
        errno = ERANGE; return VIREO_RESULT_INTERNAL;
    }
    vireo_result_t const result = vireo_connection_frames_peek(c, o, b, v, n, i, e);
    errno = ERANGE; return result;
}
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
static vireo_connection_frame_options_t const frame_options = {VIREO_CONNECTION_FRAME_REQUEST, 96};
static vireo_connection_frame_budget_t const frame_budget = {8, 768};
static vireo_protocol_header_t header(uint32_t sequence, bool response)
{
    vireo_protocol_header_t h = {0}; h.command = VIREO_COMMAND_PING; h.sequence = sequence;
    if (response) h.flags = VIREO_PROTOCOL_FLAG_RESPONSE;
    return h;
}
/* wire 与宿主布局分离；CRC 经已封板公共 codec 创建，坏包在编码后改变字节。 */
static size_t make_frame(uint8_t *wire, vireo_protocol_header_t h, char const *body, size_t size)
{
    REQUIRE(size <= 224); h.body_len = (uint32_t)size; h.crc32c = 0;
    REQUIRE(vireo_protocol_header_encode(&h, wire, 32) == VIREO_OK);
    if (size != 0) memcpy(wire + 32, body, size);
    REQUIRE(vireo_protocol_frame_crc32c_calculate(wire, 32, (uint8_t const *)body, size, &h.crc32c) == VIREO_OK);
    REQUIRE(vireo_protocol_header_encode(&h, wire, 32) == VIREO_OK); return 32 + size;
}
static void feed(fixture_t *f, size_t client, uint8_t const *bytes, size_t size)
{
    size_t offset = 0;
    while (offset < size) { ssize_t const n = send(f->peers[client], bytes + offset, size - offset, MSG_NOSIGNAL); REQUIRE(n > 0); offset += (size_t)n; }
    vireo_connection_receive_info_t i;
    REQUIRE(vireo_tcp_server_client_receive(f->server, f->clients[client], &read_budget, &i, NULL) == VIREO_OK && i.received_bytes == size);
}
static void eof(fixture_t *f)
{
    REQUIRE(shutdown(f->peers[0], SHUT_WR) == 0); vireo_connection_receive_info_t i;
    REQUIRE(vireo_tcp_server_client_receive(f->server, f->clients[0], &read_budget, &i, NULL) == VIREO_OK && i.stop_reason == VIREO_CONNECTION_RECEIVE_STOP_EOF);
}
static vireo_result_t peek(fixture_t *f, size_t client, vireo_connection_frame_options_t o,
    vireo_connection_frame_budget_t b, vireo_connection_frame_view_t *v, size_t cap,
    vireo_connection_frame_info_t *i, vireo_tcp_server_client_error_t *e)
{
    uint8_t const *p = NULL, *after = NULL; size_t n = 0, after_n = 0; uint8_t copy[256];
    REQUIRE(vireo_tcp_server_client_read_peek(f->server, f->clients[client], &p, &n, NULL) == VIREO_OK && n <= sizeof(copy));
    if (n != 0) memcpy(copy, p, n);
    errno = EDOM;
    vireo_result_t const result = vireo_tcp_server_client_frames_peek(f->server, f->clients[client], &o, &b, v, cap, i, e);
    CHECK(errno == EDOM);
    REQUIRE(vireo_tcp_server_client_read_peek(f->server, f->clients[client], &after, &after_n, NULL) == VIREO_OK);
    CHECK(after == p && after_n == n && (n == 0 || memcmp(p, copy, n) == 0));
    return result;
}
static void sentinel(vireo_connection_frame_view_t *v, size_t count)
{
    for (size_t k = 0; k < count; ++k) v[k] = (vireo_connection_frame_view_t){.body = &marker, .body_size = 99, .wire_size = 101};
}
static bool untouched(vireo_connection_frame_view_t const *v)
{ return v->body == &marker && v->body_size == 99 && v->wire_size == 101; }
/* 默认表真实接入；F1/F2完整加半头，明确处理→消费→重新取view的顺序。 */
static void native_story(int family)
{
    ++groups; fixture_t f = {0}; start(&f, family, false, connection_options, 1);
    uint8_t wire[128], third[32]; size_t n = make_frame(wire, header(1, false), "abc", 3);
    n += make_frame(wire + n, header(2, false), NULL, 0); REQUIRE(make_frame(third, header(3, false), NULL, 0) == 32);
    memcpy(wire + n, third, 12); feed(&f, 0, wire, n + 12);
    vireo_connection_frame_view_t v[4]; sentinel(v, 4); vireo_connection_frame_info_t i; vireo_tcp_server_client_error_t e;
    REQUIRE(peek(&f, 0, frame_options, frame_budget, v, 4, &i, &e) == VIREO_OK);
    CHECK(i.frame_count == 2 && i.frame_bytes == 67 && i.stop_reason == VIREO_CONNECTION_FRAME_STOP_NEED_MORE);
    CHECK(v[0].header.sequence == 1 && v[0].wire_size == 35 && v[0].body_size == 3 && memcmp(v[0].body, "abc", 3) == 0);
    CHECK(v[1].header.sequence == 2 && v[1].body == NULL && v[1].wire_size == 32 && untouched(&v[2]) && untouched(&v[3]));
    CHECK(e.primary.stage == VIREO_TCP_SERVER_CLIENT_NONE && e.primary.frame_error.issue == VIREO_CONNECTION_FRAME_ISSUE_NONE && e.cleanup_result == VIREO_OK);
    vireo_protocol_header_t const copied = v[0].header;
    REQUIRE(vireo_tcp_server_client_write_enqueue(f.server, f.clients[0], v[0].body, v[0].body_size, NULL) == VIREO_OK);
    REQUIRE(vireo_tcp_server_client_read_consume(f.server, f.clients[0], i.frame_bytes, NULL) == VIREO_OK);
    CHECK(copied.sequence == 1 && copied.body_len == 3); /* 独立header副本，无过期body解引用。 */
    sentinel(v, 4); REQUIRE(peek(&f, 0, frame_options, frame_budget, v, 4, &i, NULL) == VIREO_OK);
    CHECK(i.frame_count == 0 && i.stop_reason == VIREO_CONNECTION_FRAME_STOP_NEED_MORE && untouched(&v[0]));
    feed(&f, 0, third + 12, 20); REQUIRE(peek(&f, 0, frame_options, frame_budget, v, 4, &i, NULL) == VIREO_OK);
    CHECK(i.frame_count == 1 && i.frame_bytes == 32 && v[0].header.sequence == 3);
    vireo_connection_send_info_t si;
    REQUIRE(vireo_tcp_server_client_send(f.server, f.clients[0], &write_budget, &si, NULL) == VIREO_OK && si.sent_bytes == 3);
    char reply[3]; REQUIRE(recv(f.peers[0], reply, 3, MSG_WAITALL) == 3); CHECK(memcmp(reply, "abc", 3) == 0);
    vireo_tcp_server_info_t state; REQUIRE(vireo_tcp_server_inspect(f.server, &state) == VIREO_OK);
    CHECK(state.connection_count == 1 && state.buffer_capacity_bytes == 384 && state.registered_connections == 1);
    CHECK(info(&f, 0).connection_info.loop_interests == (VIREO_EPOLL_INTEREST_READ | VIREO_EPOLL_INTEREST_PEER_WRITE_CLOSED)); end(&f, 1);
}
static void partial_frame(void)
{
    ++groups; fixture_t f = {0}; start(&f, AF_UNIX, false, connection_options, 1);
    uint8_t wire[35]; REQUIRE(make_frame(wire, header(7, false), "xyz", 3) == 35);
    size_t const pieces[] = {7, 25, 2, 1}; size_t offset = 0;
    vireo_connection_frame_view_t v[2]; vireo_connection_frame_info_t i;
    for (size_t k = 0; k < 4; ++k) {
        feed(&f, 0, wire + offset, pieces[k]); offset += pieces[k]; sentinel(v, 2);
        REQUIRE(peek(&f, 0, frame_options, frame_budget, v, 2, &i, NULL) == VIREO_OK);
        CHECK(i.frame_count == (k == 3 ? 1U : 0U) && i.stop_reason == VIREO_CONNECTION_FRAME_STOP_NEED_MORE);
        CHECK(k == 3 ? v[0].wire_size == 35 && memcmp(v[0].body, "xyz", 3) == 0 : untouched(&v[0]));
    }
    vireo_connection_frame_view_t again[2]; REQUIRE(peek(&f, 0, frame_options, frame_budget, again, 2, &i, NULL) == VIREO_OK);
    CHECK(again[0].body == v[0].body && i.frame_count == 1); end(&f, 1);
}
static void parameters(void)
{
    ++groups; fixture_t f = {0}; start(&f, AF_UNIX, true, connection_options, 1);
    vireo_connection_frame_view_t v[2], before[2]; sentinel(v, 2); memcpy(before, v, sizeof(v));
    vireo_connection_frame_info_t i, old; memset(&i, 0xa5, sizeof(i)); memcpy(&old, &i, sizeof(i));
    vireo_tcp_server_client_error_t e;
    unsigned const lookups = f.lookups;
    for (unsigned k = 0; k < 5; ++k) {
        errno = EDOM;
        CHECK(vireo_tcp_server_client_frames_peek(k == 0 ? NULL : f.server, f.clients[0], k == 1 ? NULL : &frame_options,
            k == 2 ? NULL : &frame_budget, k == 3 ? NULL : v, 2, k == 4 ? NULL : &i, &e) == VIREO_RESULT_INVALID_ARGUMENT && errno == EDOM);
        CHECK(e.primary.stage == VIREO_TCP_SERVER_CLIENT_NONE && e.primary.frame_error.issue == VIREO_CONNECTION_FRAME_ISSUE_NONE && e.cleanup_result == VIREO_OK);
    }
    for (unsigned k = 0; k < 9; ++k) {
        vireo_connection_frame_options_t o = frame_options; vireo_connection_frame_budget_t b = frame_budget;
        size_t cap = 2; vireo_result_t const expected = k == 0 ? VIREO_RESULT_INVALID_ARGUMENT : VIREO_RESULT_RANGE;
        if (k == 0) o.direction = (vireo_connection_frame_direction_t)-1;
        if (k == 1) cap = 0;
        if (k == 2) b.max_messages = 0;
        if (k == 3) b.max_bytes = 0;
        if (k == 4) o.max_frame_bytes = 0;
        if (k == 5) o.max_frame_bytes = 31;
        if (k == 6) b.max_bytes = 95;
        if (k == 7) { o.max_frame_bytes = SIZE_MAX; b.max_bytes = SIZE_MAX; }
        if (k == 8) { o.max_frame_bytes = (size_t)VIREO_PROTOCOL_MAX_BODY_SIZE + 33; b.max_bytes = o.max_frame_bytes; }
        errno = EDOM;
        CHECK(vireo_tcp_server_client_frames_peek(f.server, f.clients[0], &o, &b, v, cap, &i, &e) == expected && errno == EDOM);
    }
    CHECK(f.frame_calls == 0 && f.lookups == lookups && memcmp(v, before, sizeof(v)) == 0 && memcmp(&i, &old, sizeof(i)) == 0);
    vireo_connection_frame_options_t o = frame_options; o.max_frame_bytes = 257;
    CHECK(peek(&f, 0, o, frame_budget, v, 2, &i, &e) == VIREO_RESULT_RANGE && e.primary.stage == VIREO_TCP_SERVER_CLIENT_FRAMES_PEEK);
    CHECK(memcmp(v, before, sizeof(v)) == 0 && memcmp(&i, &old, sizeof(i)) == 0 && f.frame_calls == 1); end(&f, 1);
    vireo_tcp_server_client_ops_t table = ops(&f); table.frames_peek = NULL; vireo_tcp_server_t *owner = NULL;
    CHECK(vireo_tcp_server_create_with_client_ops(&server_options, NULL, NULL, &table, &owner, NULL) == VIREO_RESULT_INVALID_ARGUMENT && owner == NULL);
}
static void identities(void)
{
    ++groups; fixture_t f = {0}, other = {0}; start(&f, AF_UNIX, true, connection_options, 1); start(&other, AF_UNIX, false, connection_options, 1);
    vireo_connection_pool_lease_t bad[5] = {{0}, {0, 0, 1}, f.clients[0], f.clients[0], other.clients[0]};
    bad[2].slot_index = 2; ++bad[3].generation;
    vireo_result_t const expected[] = {VIREO_RESULT_NOT_FOUND, VIREO_RESULT_INVALID_ARGUMENT, VIREO_RESULT_RANGE, VIREO_RESULT_NOT_FOUND, VIREO_RESULT_INVALID_ARGUMENT};
    for (size_t k = 0; k < 5; ++k) {
        vireo_connection_frame_view_t v[2], before[2]; sentinel(v, 2); memcpy(before, v, sizeof(v));
        vireo_connection_frame_info_t i, old; memset(&i, 0xa5, sizeof(i)); memcpy(&old, &i, sizeof(i)); vireo_tcp_server_client_error_t e;
        errno = EDOM; CHECK(vireo_tcp_server_client_frames_peek(f.server, bad[k], &frame_options, &frame_budget, v, 2, &i, &e) == expected[k] && errno == EDOM);
        CHECK(e.primary.stage == VIREO_TCP_SERVER_CLIENT_LOOKUP && memcmp(v, before, sizeof(v)) == 0 && memcmp(&i, &old, sizeof(i)) == 0 && f.frame_calls == 0);
    }
    vireo_connection_pool_lease_t const old_lease = f.clients[0];
    REQUIRE(vireo_tcp_server_release_client(f.server, &f.clients[0], NULL) == VIREO_OK && close(f.peers[0]) == 0);
    f.peers[0] = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0); REQUIRE(f.peers[0] >= 0);
    REQUIRE(connect(f.peers[0], (struct sockaddr *)&f.address, f.length) == 0);
    vireo_tcp_server_admit_budget_t const b = {1, 1}; vireo_tcp_server_admit_info_t ai;
    REQUIRE(vireo_tcp_server_admit_batch(f.server, &connection_options, &b, f.clients, 1, &ai, NULL) == VIREO_OK && ai.admitted_count == 1);
    CHECK(!same(old_lease, f.clients[0]) && old_lease.slot_index == f.clients[0].slot_index);
    uint8_t wire[32]; (void)make_frame(wire, header(99, false), NULL, 0); feed(&f, 0, wire, 32);
    vireo_connection_frame_view_t v[1]; vireo_connection_frame_info_t i;
    CHECK(vireo_tcp_server_client_frames_peek(f.server, old_lease, &frame_options, &frame_budget, v, 1, &i, NULL) == VIREO_RESULT_NOT_FOUND && f.frame_calls == 0);
    REQUIRE(peek(&f, 0, frame_options, frame_budget, v, 1, &i, NULL) == VIREO_OK); CHECK(v[0].header.sequence == 99);
    end(&f, 1); end(&other, 1);
}
/* 首帧真实有效，第二帧各类协议错；解析失败仍保留前缀、诊断、尾部与原读区。 */
static void bad_prefix(void)
{
    ++groups;
    for (unsigned k = 0; k < 6; ++k) {
        fixture_t f = {0}; start(&f, AF_UNIX, true, connection_options, 1); uint8_t wire[72];
        size_t const first = make_frame(wire, header(11, false), "ok", 2);
        size_t const second = make_frame(wire + first, header(12, false), "bad", 3);
        vireo_connection_frame_issue_t issue = VIREO_CONNECTION_FRAME_ISSUE_CODEC;
        if (k == 0) wire[first] = 'X';
        if (k == 1) wire[first + 32] ^= 1;
        if (k == 2) wire[first + 31] ^= 1;
        if (k == 3) wire[first + 8] = 0x80;
        if (k == 4) memset(wire + first + 16, 0, 4);
        if (k == 5) { wire[first + 12] = 0; wire[first + 13] = 0; wire[first + 14] = 1; wire[first + 15] = 0; issue = VIREO_CONNECTION_FRAME_ISSUE_FRAME_TOO_LARGE; }
        feed(&f, 0, wire, first + second);
        vireo_connection_frame_view_t v[3]; sentinel(v, 3); vireo_connection_frame_info_t i; vireo_tcp_server_client_error_t e;
        REQUIRE(peek(&f, 0, frame_options, frame_budget, v, 3, &i, &e) == VIREO_RESULT_PROTOCOL);
        CHECK(i.frame_count == 1 && i.frame_bytes == first && i.stop_reason == VIREO_CONNECTION_FRAME_STOP_ERROR && v[0].header.sequence == 11 && untouched(&v[1]) && untouched(&v[2]));
        CHECK(e.primary.stage == VIREO_TCP_SERVER_CLIENT_FRAMES_PEEK && e.primary.frame_error.issue == issue && e.primary.connection_error.stage == VIREO_CONNECTION_STAGE_NONE && e.primary.system_errno == 0 && e.cleanup_result == VIREO_OK);
        CHECK(issue != VIREO_CONNECTION_FRAME_ISSUE_CODEC || e.primary.frame_error.codec_issue != VIREO_PROTOCOL_CODEC_ISSUE_NONE);
        if (k == 1 || k == 2) CHECK(e.primary.frame_error.codec_issue == VIREO_PROTOCOL_CODEC_ISSUE_CRC_MISMATCH);
        REQUIRE(peek(&f, 0, frame_options, frame_budget, v, 3, &i, NULL) == VIREO_RESULT_PROTOCOL && i.frame_count == 1);
        REQUIRE(vireo_tcp_server_client_read_consume(f.server, f.clients[0], first, NULL) == VIREO_OK);
        sentinel(v, 3); REQUIRE(peek(&f, 0, frame_options, frame_budget, v, 3, &i, &e) == VIREO_RESULT_PROTOCOL);
        CHECK(i.frame_count == 0 && i.frame_bytes == 0 && untouched(&v[0]) && f.frame_calls == 3); end(&f, 1);
    }
}
static void directions(void)
{
    ++groups;
    for (unsigned k = 0; k < 2; ++k) {
        fixture_t f = {0}; start(&f, AF_UNIX, false, connection_options, 1); uint8_t wire[32];
        (void)make_frame(wire, header(20, k != 0), NULL, 0); feed(&f, 0, wire, 32);
        vireo_connection_frame_options_t o = {k == 0 ? VIREO_CONNECTION_FRAME_RESPONSE : VIREO_CONNECTION_FRAME_REQUEST, 32};
        vireo_connection_frame_view_t v[1]; vireo_connection_frame_info_t i; vireo_tcp_server_client_error_t e;
        CHECK(peek(&f, 0, o, frame_budget, v, 1, &i, &e) == VIREO_RESULT_PROTOCOL && i.frame_count == 0);
        o.direction = k == 0 ? VIREO_CONNECTION_FRAME_REQUEST : VIREO_CONNECTION_FRAME_RESPONSE;
        REQUIRE(peek(&f, 0, o, frame_budget, v, 1, &i, NULL) == VIREO_OK); CHECK(i.frame_count == 1 && v[0].header.sequence == 20); end(&f, 1);
    }
}
static void budgets(void)
{
    ++groups; fixture_t f = {0}; start(&f, AF_UNIX, false, connection_options, 1); uint8_t wire[105];
    (void)make_frame(wire, header(1, false), "abc", 3); (void)make_frame(wire + 35, header(2, false), "def", 3);
    (void)make_frame(wire + 70, header(3, false), "ghi", 3); wire[70] = 'X'; feed(&f, 0, wire, 105);
    vireo_connection_frame_options_t const o = {VIREO_CONNECTION_FRAME_REQUEST, 35};
    for (unsigned k = 0; k < 4; ++k) {
        vireo_connection_frame_budget_t b = {8, 280}; size_t cap = 4; vireo_connection_frame_stop_t stop;
        if (k == 0) { b.max_messages = 1; cap = 1; stop = VIREO_CONNECTION_FRAME_STOP_MESSAGE_BUDGET; }
        else if (k == 1) { cap = 1; stop = VIREO_CONNECTION_FRAME_STOP_OUTPUT_FULL; }
        else { b.max_bytes = k == 2 ? 64 : 67; stop = VIREO_CONNECTION_FRAME_STOP_BYTE_BUDGET; }
        vireo_connection_frame_view_t v[4]; sentinel(v, 4); vireo_connection_frame_info_t i;
        REQUIRE(peek(&f, 0, o, b, v, cap, &i, NULL) == VIREO_OK);
        CHECK(i.frame_count == 1 && i.frame_bytes == 35 && i.stop_reason == stop && untouched(&v[1]));
    }
    vireo_connection_frame_view_t v[4]; vireo_connection_frame_info_t i; vireo_connection_frame_budget_t const two = {2, 280};
    REQUIRE(peek(&f, 0, o, two, v, 4, &i, NULL) == VIREO_OK);
    CHECK(i.frame_count == 2 && i.frame_bytes == 70 && i.stop_reason == VIREO_CONNECTION_FRAME_STOP_MESSAGE_BUDGET);
    CHECK(peek(&f, 0, o, frame_budget, v, 4, &i, NULL) == VIREO_RESULT_PROTOCOL && i.frame_count == 2);
    end(&f, 1);
}
static void eof_cases(void)
{
    ++groups;
    for (unsigned k = 0; k < 4; ++k) {
        fixture_t f = {0}; start(&f, AF_UNIX, false, connection_options, 1); uint8_t wire[72];
        size_t n = make_frame(wire, header(1, false), NULL, 0); size_t const second = make_frame(wire + n, header(2, false), "xyz", 3);
        if (k == 0) n = 0;
        if (k == 2) n += 12;
        if (k == 3) n += second - 1;
        if (n != 0) feed(&f, 0, wire, n);
        eof(&f); vireo_connection_frame_view_t v[3]; sentinel(v, 3); vireo_connection_frame_info_t i; vireo_tcp_server_client_error_t e;
        vireo_result_t const expected = k >= 2 ? VIREO_RESULT_PROTOCOL : VIREO_OK;
        CHECK(peek(&f, 0, frame_options, frame_budget, v, 3, &i, &e) == expected);
        CHECK(i.frame_count == (k == 0 ? 0U : 1U) && i.frame_bytes == (k == 0 ? 0U : 32U) && untouched(&v[i.frame_count]));
        CHECK(k >= 2 ? i.stop_reason == VIREO_CONNECTION_FRAME_STOP_ERROR && e.primary.frame_error.issue == VIREO_CONNECTION_FRAME_ISSUE_TRUNCATED : i.stop_reason == VIREO_CONNECTION_FRAME_STOP_EOF);
        if (k != 0) {
            vireo_connection_frame_budget_t const one = {1, 96};
            REQUIRE(peek(&f, 0, frame_options, one, v, 3, &i, NULL) == VIREO_OK && i.stop_reason == VIREO_CONNECTION_FRAME_STOP_MESSAGE_BUDGET);
            REQUIRE(vireo_tcp_server_client_read_consume(f.server, f.clients[0], 32, NULL) == VIREO_OK);
            CHECK(peek(&f, 0, frame_options, frame_budget, v, 3, &i, &e) == expected && i.frame_count == 0);
        }
        end(&f, 1);
    }
}
static void borrow_isolation(void)
{
    ++groups; fixture_t f = {0}; start(&f, AF_UNIX, false, connection_options, 2); uint8_t wire[35];
    (void)make_frame(wire, header(1, false), "abc", 3); feed(&f, 0, wire, 35);
    vireo_connection_frame_view_t a[2], b[2]; vireo_connection_frame_info_t i;
    REQUIRE(peek(&f, 0, frame_options, frame_budget, a, 2, &i, NULL) == VIREO_OK);
    (void)make_frame(wire, header(2, false), "XYZ", 3); feed(&f, 1, wire, 35);
    REQUIRE(peek(&f, 1, frame_options, frame_budget, b, 2, &i, NULL) == VIREO_OK);
    CHECK(memcmp(a[0].body, "abc", 3) == 0 && memcmp(b[0].body, "XYZ", 3) == 0 && a[0].body != b[0].body);
    CHECK(vireo_tcp_server_client_read_consume(f.server, f.clients[0], 36, NULL) == VIREO_RESULT_RANGE && memcmp(a[0].body, "abc", 3) == 0);
    REQUIRE(vireo_tcp_server_client_write_enqueue(f.server, f.clients[0], a[0].body, 3, NULL) == VIREO_OK);
    vireo_connection_send_info_t si; REQUIRE(vireo_tcp_server_client_send(f.server, f.clients[0], &write_budget, &si, NULL) == VIREO_OK);
    CHECK(memcmp(a[0].body, "abc", 3) == 0 && info(&f, 0).connection_info.read_buffer.readable_size == 35);
    REQUIRE(vireo_tcp_server_client_read_consume(f.server, f.clients[1], 35, NULL) == VIREO_OK && memcmp(a[0].body, "abc", 3) == 0);
    REQUIRE(vireo_tcp_server_client_read_consume(f.server, f.clients[0], 0, NULL) == VIREO_OK);
    REQUIRE(peek(&f, 0, frame_options, frame_budget, a, 2, &i, NULL) == VIREO_OK); CHECK(memcmp(a[0].body, "abc", 3) == 0);
    vireo_connection_receive_info_t ri; REQUIRE(vireo_tcp_server_client_receive(f.server, f.clients[0], &read_budget, &ri, NULL) == VIREO_OK && ri.received_bytes == 0);
    REQUIRE(peek(&f, 0, frame_options, frame_budget, a, 2, &i, NULL) == VIREO_OK); CHECK(memcmp(a[0].body, "abc", 3) == 0);
    end(&f, 2); /* 不访问归还后的旧body，合法生命周期由caller遵守。 */
}
static void dependency_results(void)
{
    ++groups; fixture_t f = {0}; start(&f, AF_UNIX, true, connection_options, 1); uint8_t wire[64];
    (void)make_frame(wire, header(1, false), NULL, 0); (void)make_frame(wire + 32, header(2, false), NULL, 0); feed(&f, 0, wire, 64);
    vireo_connection_frame_view_t v[3], before[3]; sentinel(v, 3); memcpy(before, v, sizeof(v));
    vireo_connection_frame_info_t i, old; memset(&i, 0xa5, sizeof(i)); memcpy(&old, &i, sizeof(i)); vireo_tcp_server_client_error_t e;
    f.frame_mode = 1; CHECK(peek(&f, 0, frame_options, frame_budget, v, 3, &i, &e) == VIREO_RESULT_RANGE);
    CHECK(memcmp(v, before, sizeof(v)) == 0 && memcmp(&i, &old, sizeof(i)) == 0 && e.primary.stage == VIREO_TCP_SERVER_CLIENT_FRAMES_PEEK);
    f.frame_mode = 2; CHECK(peek(&f, 0, frame_options, frame_budget, v, 3, &i, &e) == VIREO_RESULT_INTERNAL);
    CHECK(i.frame_count == 1 && i.frame_bytes == 32 && i.stop_reason == VIREO_CONNECTION_FRAME_STOP_ERROR && untouched(&v[1]) && untouched(&v[2]));
    CHECK(e.primary.frame_error.issue == VIREO_CONNECTION_FRAME_ISSUE_NONE && e.primary.frame_error.codec_issue == VIREO_PROTOCOL_CODEC_ISSUE_NONE && e.cleanup.stage == VIREO_TCP_SERVER_CLIENT_NONE);
    f.frame_mode = 0; REQUIRE(peek(&f, 0, frame_options, frame_budget, v, 3, &i, &e) == VIREO_OK && i.frame_count == 2);
    CHECK(e.primary.stage == VIREO_TCP_SERVER_CLIENT_NONE && f.frame_calls == 3); end(&f, 1);
}
static void owned_states(void)
{
    ++groups; fixture_t small = {0}; vireo_connection_options_t const o = {31, 1, 32}; start(&small, AF_UNIX, false, o, 1);
    vireo_connection_frame_view_t v[2]; sentinel(v, 2); vireo_connection_frame_info_t i, old; memset(&i, 0xa5, sizeof(i)); memcpy(&old, &i, sizeof(i));
    vireo_connection_frame_options_t const min = {VIREO_CONNECTION_FRAME_REQUEST, 32};
    CHECK(peek(&small, 0, min, frame_budget, v, 2, &i, NULL) == VIREO_RESULT_RANGE && memcmp(&i, &old, sizeof(i)) == 0 && untouched(&v[0])); end(&small, 1);
    fixture_t f = {0}; start(&f, AF_UNIX, true, connection_options, 1); uint8_t wire[256]; char body[224]; memset(body, 'q', sizeof(body));
    REQUIRE(make_frame(wire, header(1, false), body, sizeof(body)) == 256); feed(&f, 0, wire, 256);
    f.release_busy = true; CHECK(vireo_tcp_server_release_client(f.server, &f.clients[0], NULL) == VIREO_RESULT_BUSY && !empty(f.clients[0]));
    CHECK(!info(&f, 0).connection_info.loop_attached);
    vireo_connection_frame_options_t const full = {VIREO_CONNECTION_FRAME_REQUEST, 256};
    REQUIRE(peek(&f, 0, full, frame_budget, v, 2, &i, NULL) == VIREO_OK);
    CHECK(i.frame_count == 1 && i.frame_bytes == 256 && v[0].body_size == 224 && memcmp(v[0].body, body, 224) == 0); end(&f, 1);
}
int main(void)
{
    unsigned const before = fd_count(); native_story(AF_INET); native_story(AF_UNIX); partial_frame(); parameters(); identities();
    bad_prefix(); directions(); budgets(); eof_cases(); borrow_isolation(); dependency_results(); owned_states();
    unsigned const after = fd_count(); CHECK(after == before);
    printf("tcp_server client framing: %u groups, %u failures, fd %u -> %u\n", groups, failures, before, after);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
