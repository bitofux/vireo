/*
- PROJECT : VIREO
- FILE    : test_tcp_server_sync_handler.c
- AUTHOR  : bitofux
- DATE    : 2026-10-05
- BRIEF   : 此模块负责：
- -- 同步 handler、响应 copy/CRC 与成功后消费
- -- 实际部分进度、保守资源边界与同 server 在途保护
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
    unsigned inspect_calls, enqueue_fail_at, consume_fail_at, inspect_fail_at;
    bool pretend_closing;
} fixture_t;
static vireo_result_t accept_client(void *ctx, vireo_acceptor_t *a,
    vireo_acceptor_accept_budget_t const *b, int *fds, size_t n,
    vireo_acceptor_accept_info_t *i, vireo_acceptor_error_t *e)
{ (void)ctx; return vireo_acceptor_accept_batch(a, b, fds, n, i, e); }
static vireo_result_t create_client(void *ctx, vireo_connection_options_t const *o, int *fd,
    vireo_connection_t **c, vireo_connection_error_t *e)
{ (void)ctx; return vireo_connection_create(o, fd, c, e); }
static vireo_result_t inspect_client(void *ctx, vireo_connection_t const *c, vireo_connection_info_t *i)
{
    fixture_t *f = ctx; ++f->inspect_calls;
    vireo_result_t const r = vireo_connection_inspect(c, i);
    if (r == VIREO_OK && f->inspect_fail_at == f->inspect_calls)
        i->write_buffer.readable_size = i->write_buffer.capacity + 1;
    if (r == VIREO_OK && f->pretend_closing) i->close_state = VIREO_CONNECTION_CLOSE_READY;
    return r;
}
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
{
    fixture_t *f = ctx; ++f->consumes;
    if (f->consume_fail_at == f->consumes) { errno = EINTR; return VIREO_RESULT_INTERNAL; }
    return vireo_connection_read_consume(c, n);
}
static vireo_result_t enqueue_bytes(void *ctx, vireo_connection_t *c, uint8_t const *p,
    size_t n, vireo_connection_error_t *e)
{
    fixture_t *f = ctx; ++f->enqueues;
    if (f->enqueue_fail_at == f->enqueues) {
        *e = (vireo_connection_error_t){VIREO_CONNECTION_STAGE_SEND, EPIPE};
        errno = EPIPE; return VIREO_RESULT_IO;
    }
    return vireo_connection_write_enqueue(c, p, n, e);
}
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

static vireo_tcp_server_process_options_t const limits = {96, 64};
static vireo_tcp_server_process_budget_t const allowance = {8, 768, 512};
typedef struct handler_context {
    unsigned calls, fail_at;
    vireo_result_t failure_result;
    int mode;
    uint32_t sequences[8];
} handler_context_t;
/* 测试回调只证明网络层 SINGLE 合同，不是生产 PING/schema 实现。 */
static vireo_result_t echo_reply(vireo_connection_frame_view_t const *request, uint8_t *body,
    size_t cap, vireo_tcp_server_reply_t *reply, void *ctx)
{
    handler_context_t *h = ctx; ++h->calls;
    if (h->calls <= 8) h->sequences[h->calls - 1] = request->header.sequence;
    CHECK(reply->status == VIREO_STATUS_OK && reply->body_size == 0 &&
          reply->session_handle == request->header.session_handle &&
          reply->task_handle == request->header.task_handle);
    if (h->fail_at == h->calls) { if (cap != 0) body[0] = 99; errno = EPIPE; return h->failure_result; }
    if (h->mode == 1) reply->status = (vireo_status_t)UINT16_MAX;
    if (h->mode == 2) { reply->body_size = cap + 1; return VIREO_OK; }
    if (h->mode == 3) {
        for (size_t i = 0; i < cap; ++i) body[i] = (uint8_t)(i % 251);
        reply->body_size = cap;
    } else {
        REQUIRE(request->body_size <= cap);
        if (request->body_size != 0) memcpy(body, request->body, request->body_size);
        reply->body_size = request->body_size;
    }
    if (request->header.sequence == 2) {
        reply->status = VIREO_STATUS_BAD_REQUEST; reply->session_handle = 44; reply->task_handle = 55;
    }
    errno = ERANGE; return VIREO_OK;
}
static vireo_result_t process(fixture_t *f, size_t client, vireo_tcp_server_process_options_t o,
    vireo_tcp_server_process_budget_t b, uint8_t *work, size_t cap, handler_context_t *h,
    vireo_tcp_server_process_info_t *i, vireo_tcp_server_client_error_t *e)
{
    errno = EDOM;
    vireo_result_t const r = vireo_tcp_server_client_process(f->server, f->clients[client], &o,
        &b, work, cap, echo_reply, h, i, e);
    CHECK(errno == EDOM);
    vireo_tcp_server_info_t state;
    REQUIRE(vireo_tcp_server_inspect(f->server, &state) == VIREO_OK);
    CHECK(!state.processing_active);
    return r;
}
static void zeros(vireo_tcp_server_process_info_t i)
{
    CHECK(i.handler_calls == 0 && i.consumed_requests == 0 && i.consumed_request_bytes == 0 &&
          i.enqueued_responses == 0 && i.enqueued_response_bytes == 0);
}
static void sent(fixture_t *f, size_t client, uint8_t *wire, size_t size)
{
    vireo_connection_send_info_t out;
    REQUIRE(vireo_tcp_server_client_send(f->server, f->clients[client], &write_budget, &out, NULL) == VIREO_OK);
    CHECK(out.sent_bytes == size); size_t n = 0;
    while (n < size) { ssize_t const r = recv(f->peers[client], wire + n, size - n, 0); REQUIRE(r > 0); n += (size_t)r; }
}
static void check_response(uint8_t const *wire, size_t size, uint32_t sequence,
    uint8_t const *body, size_t body_size, vireo_status_t status, uint32_t session, uint32_t task)
{
    vireo_protocol_header_t h; vireo_protocol_codec_issue_t issue;
    REQUIRE(size == 32 + body_size && vireo_protocol_header_decode(wire, size, &h, &issue) == VIREO_OK);
    CHECK(h.command == VIREO_COMMAND_PING && h.sequence == sequence &&
          h.flags == VIREO_PROTOCOL_FLAG_RESPONSE && h.status == status &&
          h.session_handle == session && h.task_handle == task && h.body_len == body_size);
    CHECK(vireo_protocol_response_header_validate(&h, &issue) == VIREO_OK);
    CHECK(vireo_protocol_frame_crc32c_verify(wire, size, body_size == 0 ? NULL : wire + 32,
        body_size, &issue) == VIREO_OK);
    CHECK(body_size == 0 || memcmp(wire + 32, body, body_size) == 0);
}
static void normal(int family)
{
    fixture_t f = {0}; start(&f, family, false, connection_options, 1);
    uint8_t input[70], work[80], output[70]; memset(work, marker, sizeof(work));
    vireo_protocol_header_t a = header(1, false); a.session_handle = 11; a.task_handle = 22;
    REQUIRE(make_frame(input, a, "abc", 3) == 35);
    REQUIRE(make_frame(input + 35, header(2, false), "XYZ", 3) == 35);
    feed(&f, 0, input, sizeof(input)); handler_context_t h = {0};
    vireo_tcp_server_process_info_t i; vireo_tcp_server_client_error_t e;
    CHECK(process(&f, 0, limits, allowance, work, sizeof(work), &h, &i, &e) == VIREO_OK);
    CHECK(i.handler_calls == 2 && i.consumed_requests == 2 && i.consumed_request_bytes == 70 &&
          i.enqueued_responses == 2 && i.enqueued_response_bytes == 70 && i.stop_reason == VIREO_TCP_SERVER_PROCESS_NEED_MORE);
    CHECK(h.sequences[0] == 1 && h.sequences[1] == 2 && e.primary.stage == VIREO_TCP_SERVER_CLIENT_NONE);
    CHECK(info(&f, 0).connection_info.read_buffer.readable_size == 0);
    for (size_t n = 64; n < sizeof(work); ++n) CHECK(work[n] == marker);
    memset(work, 0, sizeof(work)); /* 后续 workspace 改写不能改变已排队的响应副本。 */
    sent(&f, 0, output, sizeof(output));
    check_response(output, 35, 1, (uint8_t const *)"abc", 3, VIREO_STATUS_OK, 11, 22);
    check_response(output + 35, 35, 2, (uint8_t const *)"XYZ", 3, VIREO_STATUS_BAD_REQUEST, 44, 55);
    CHECK(info(&f, 0).connection_info.loop_interests == (VIREO_EPOLL_INTEREST_READ | VIREO_EPOLL_INTEREST_PEER_WRITE_CLOSED));
    end(&f, 1); ++groups;
}
static void half_and_eof(void)
{
    fixture_t f = {0}; start(&f, AF_INET, false, connection_options, 1);
    uint8_t frame[35], work[64], copy[64]; make_frame(frame, header(1, false), "abc", 3);
    memset(work, marker, sizeof(work)); memcpy(copy, work, sizeof(work));
    handler_context_t h = {0}; vireo_tcp_server_process_info_t i;
    for (unsigned k = 0; k < 3; ++k) {
        size_t const offset = k == 0 ? 0 : k == 1 ? 7 : 32;
        size_t const size = k == 0 ? 7 : k == 1 ? 25 : 2;
        feed(&f, 0, frame + offset, size);
        CHECK(process(&f, 0, limits, allowance, work, sizeof(work), &h, &i, NULL) == VIREO_OK);
        zeros(i); CHECK(i.stop_reason == VIREO_TCP_SERVER_PROCESS_NEED_MORE && memcmp(work, copy, sizeof(work)) == 0);
    }
    feed(&f, 0, frame + 34, 1); eof(&f);
    CHECK(process(&f, 0, limits, allowance, work, sizeof(work), &h, &i, NULL) == VIREO_OK);
    CHECK(i.consumed_requests == 1 && i.stop_reason == VIREO_TCP_SERVER_PROCESS_EOF);
    end(&f, 1); ++groups;
}
static void invalid_prefix(bool truncated)
{
    fixture_t f = {0}; start(&f, AF_UNIX, false, connection_options, 1);
    uint8_t wire[64], work[64]; make_frame(wire, header(1, false), NULL, 0);
    make_frame(wire + 32, header(3, false), NULL, 0);
    if (!truncated) wire[63] ^= 1;
    feed(&f, 0, wire, truncated ? 39 : 64); if (truncated) eof(&f);
    handler_context_t h = {0}; vireo_tcp_server_process_info_t i; vireo_tcp_server_client_error_t e;
    CHECK(process(&f, 0, limits, allowance, work, sizeof(work), &h, &i, &e) == VIREO_RESULT_PROTOCOL);
    CHECK(i.handler_calls == 1 && i.consumed_requests == 1 && i.enqueued_responses == 1 &&
          i.consumed_request_bytes == 32 && i.enqueued_response_bytes == 32 &&
          i.stop_reason == VIREO_TCP_SERVER_PROCESS_ERROR && e.primary.stage == VIREO_TCP_SERVER_CLIENT_FRAMES_PEEK);
    CHECK(truncated ? e.primary.frame_error.issue == VIREO_CONNECTION_FRAME_ISSUE_TRUNCATED :
          e.primary.frame_error.codec_issue == VIREO_PROTOCOL_CODEC_ISSUE_CRC_MISMATCH);
    CHECK(info(&f, 0).connection_info.read_buffer.readable_size == (truncated ? 7 : 32));
    end(&f, 1); ++groups;
}
static void budgets(void)
{
    for (unsigned mode = 0; mode < 3; ++mode) {
        fixture_t f = {0}; start(&f, AF_INET, true, connection_options, 1);
        uint8_t wire[64], work[64]; make_frame(wire, header(1, false), NULL, 0);
        make_frame(wire + 32, header(3, false), NULL, 0); wire[63] ^= 1; feed(&f, 0, wire, 64);
        vireo_tcp_server_process_budget_t b = allowance;
        if (mode == 0) b.max_messages = 1;
        if (mode == 1) b.max_request_bytes = 96;
        if (mode == 2) b.max_response_bytes = 64;
        handler_context_t h = {0}; vireo_tcp_server_process_info_t i;
        CHECK(process(&f, 0, limits, b, work, sizeof(work), &h, &i, NULL) == VIREO_OK);
        CHECK(i.consumed_requests == 1 && f.frame_calls == 1 &&
              i.stop_reason == (mode == 0 ? VIREO_TCP_SERVER_PROCESS_MESSAGE_BUDGET :
                  mode == 1 ? VIREO_TCP_SERVER_PROCESS_REQUEST_BUDGET : VIREO_TCP_SERVER_PROCESS_RESPONSE_BUDGET));
        CHECK(process(&f, 0, limits, allowance, work, sizeof(work), &h, &i, NULL) == VIREO_RESULT_PROTOCOL);
        zeros(i); end(&f, 1);
    }
    ++groups;
}
static void write_pressure(void)
{
    fixture_t f = {0}; start(&f, AF_INET, true, connection_options, 1);
    uint8_t frame[32], work[64], copy[64], pending[80]; memset(pending, 9, sizeof(pending));
    make_frame(frame, header(1, false), NULL, 0); feed(&f, 0, frame, 32);
    REQUIRE(vireo_tcp_server_client_write_enqueue(f.server, f.clients[0], pending, sizeof(pending), NULL) == VIREO_OK);
    memset(work, marker, sizeof(work)); memcpy(copy, work, sizeof(work));
    handler_context_t h = {0}; vireo_tcp_server_process_info_t i;
    CHECK(process(&f, 0, limits, allowance, work, sizeof(work), &h, &i, NULL) == VIREO_OK);
    zeros(i); CHECK(i.stop_reason == VIREO_TCP_SERVER_PROCESS_WRITE_FULL && h.calls == 0 &&
        memcmp(work, copy, sizeof(work)) == 0 && info(&f, 0).connection_info.read_buffer.readable_size == 32);
    uint8_t out[80]; sent(&f, 0, out, sizeof(out)); CHECK(memcmp(out, pending, sizeof(out)) == 0);
    CHECK(process(&f, 0, limits, allowance, work, sizeof(work), &h, &i, NULL) == VIREO_OK && i.consumed_requests == 1);
    end(&f, 1); ++groups;
}
static void rejection(void)
{
    fixture_t f = {0}; start(&f, AF_INET, true, connection_options, 1);
    uint8_t work[160], original[160]; memset(work, marker, sizeof(work)); memcpy(original, work, sizeof(work));
    handler_context_t h = {0}; vireo_tcp_server_process_info_t sentinel, i;
    memset(&sentinel, 0x5a, sizeof(sentinel));
    for (unsigned k = 0; k < 18; ++k) {
        vireo_tcp_server_process_options_t o = limits; vireo_tcp_server_process_budget_t b = allowance;
        vireo_connection_pool_lease_t lease = f.clients[0]; size_t cap = 64;
        if (k == 0) b.max_messages = 0;
        if (k == 1) b.max_request_bytes = 95;
        if (k == 2) b.max_response_bytes = 63;
        if (k == 3) o.max_request_frame_bytes = 31;
        if (k == 4) o.max_response_frame_bytes = SIZE_MAX;
        if (k == 5) cap = 63;
        if (k == 6) { o.max_request_frame_bytes = 257; b.max_request_bytes = 257; }
        if (k == 7) { o.max_response_frame_bytes = 129; b.max_response_bytes = 129; cap = 129; }
        if (k == 8) lease = (vireo_connection_pool_lease_t){0};
        if (k == 9) ++lease.pool_id;
        if (k == 10) lease.slot_index = 2;
        if (k == 11) ++lease.generation;
        i = sentinel; errno = EDOM;
        vireo_result_t const r = vireo_tcp_server_client_process(k == 12 ? NULL : f.server, lease,
            k == 13 ? NULL : &o, k == 14 ? NULL : &b, k == 15 ? NULL : work, cap,
            k == 16 ? NULL : echo_reply, &h, k == 17 ? NULL : &i, NULL);
        CHECK(r != VIREO_OK && errno == EDOM && memcmp(&i, &sentinel, sizeof(i)) == 0 &&
              memcmp(work, original, sizeof(work)) == 0 && h.calls == 0 && f.frame_calls == 0);
    }
    f.pretend_closing = true; i = sentinel;
    CHECK(process(&f, 0, limits, allowance, work, sizeof(work), &h, &i, NULL) == VIREO_RESULT_BUSY);
    CHECK(memcmp(&i, &sentinel, sizeof(i)) == 0 && memcmp(work, original, sizeof(work)) == 0);
    f.pretend_closing = false; end(&f, 1); ++groups;
}
static void handler_errors(void)
{
    for (unsigned mode = 0; mode < 4; ++mode) {
        fixture_t f = {0}; start(&f, AF_UNIX, false, connection_options, 1);
        uint8_t wire[64], work[64]; make_frame(wire, header(1, false), NULL, 0);
        make_frame(wire + 32, header(3, false), NULL, 0); feed(&f, 0, wire, sizeof(wire));
        handler_context_t h = {.fail_at = 2, .failure_result = mode == 0 ? VIREO_RESULT_IO : (vireo_result_t)99};
        if (mode >= 2) { h.fail_at = 0; h.mode = mode == 2 ? 1 : 2; }
        vireo_tcp_server_process_info_t i; vireo_tcp_server_client_error_t e;
        vireo_result_t const r = process(&f, 0, limits, allowance, work, sizeof(work), &h, &i, &e);
        CHECK(r == (mode == 0 ? VIREO_RESULT_IO : mode == 1 ? VIREO_RESULT_INTERNAL :
                    mode == 2 ? VIREO_RESULT_PROTOCOL : VIREO_RESULT_RANGE));
        CHECK(i.handler_calls == (mode < 2 ? 2 : 1) && i.enqueued_responses == (mode < 2 ? 1 : 0) &&
              i.consumed_requests == (mode < 2 ? 1 : 0) && i.stop_reason == VIREO_TCP_SERVER_PROCESS_ERROR);
        CHECK(e.primary.stage == (mode < 2 ? VIREO_TCP_SERVER_CLIENT_HANDLER : VIREO_TCP_SERVER_CLIENT_RESPONSE));
        if (mode < 2) CHECK(e.primary.handler_result == h.failure_result);
        if (mode == 2) CHECK(e.primary.response_codec_issue == VIREO_PROTOCOL_CODEC_ISSUE_UNKNOWN_RESPONSE_STATUS);
        CHECK(info(&f, 0).connection_info.read_buffer.readable_size == (mode < 2 ? 32 : 64));
        /* 明确再次调用才重新进入未消费请求，之前 handler 的调用副作用没有撤回。 */
        if (mode < 2) {
            h.fail_at = 0; vireo_tcp_server_process_budget_t const once = {1, SIZE_MAX, SIZE_MAX};
            CHECK(process(&f, 0, limits, once, work, sizeof(work), &h, &i, NULL) == VIREO_OK &&
                  i.consumed_requests == 1 && h.calls == 3);
        }
        end(&f, 1);
    }
    ++groups;
}
/* 故障来自本层公开 wrapper，依赖健康状态下不会自然出现这些两步提交异常。 */
static void dependency_failures(void)
{
    for (unsigned mode = 0; mode < 3; ++mode) {
        fixture_t f = {0}; start(&f, AF_INET, true, connection_options, 1);
        uint8_t wire[64], work[64]; make_frame(wire, header(1, false), NULL, 0);
        make_frame(wire + 32, header(3, false), NULL, 0); feed(&f, 0, wire, 64);
        if (mode == 0) f.enqueue_fail_at = 2;
        if (mode == 1) f.consume_fail_at = 2;
        if (mode == 2) { f.inspect_calls = 0; f.inspect_fail_at = 2; }
        handler_context_t h = {0}; vireo_tcp_server_process_info_t i; vireo_tcp_server_client_error_t e;
        CHECK(process(&f, 0, limits, allowance, work, sizeof(work), &h, &i, &e) ==
              (mode == 0 ? VIREO_RESULT_IO : VIREO_RESULT_INTERNAL));
        CHECK(i.consumed_requests == (mode == 2 ? 0 : 1) &&
              i.enqueued_responses == (mode == 0 ? 1 : mode == 1 ? 2 : 0));
        CHECK(e.primary.stage == (mode == 0 ? VIREO_TCP_SERVER_CLIENT_WRITE_ENQUEUE :
              mode == 1 ? VIREO_TCP_SERVER_CLIENT_READ_CONSUME : VIREO_TCP_SERVER_CLIENT_INSPECT));
        if (mode == 0) CHECK(e.primary.connection_error.system_errno == EPIPE &&
                            e.primary.connection_error.stage == VIREO_CONNECTION_STAGE_SEND);
        f.inspect_fail_at = 0;
        CHECK(info(&f, 0).connection_info.read_buffer.readable_size == (mode == 2 ? 64 : 32));
        /* consume 异常不重放，直接显式安全归还。 */
        end(&f, 1);
    }
    ++groups;
}

typedef struct guard_context { fixture_t *f, *nested; vireo_acceptor_t *spare; unsigned calls; } guard_context_t;
static vireo_result_t guarded_reply(vireo_connection_frame_view_t const *r, uint8_t *body,
    size_t cap, vireo_tcp_server_reply_t *reply, void *ctx)
{
    guard_context_t *g = ctx; fixture_t *f = g->f; ++g->calls;
    REQUIRE(r->body_size == 3 && cap >= 3); uint8_t copy[3]; memcpy(copy, r->body, 3);
    vireo_tcp_server_info_t state; CHECK(vireo_tcp_server_inspect(f->server, &state) == VIREO_OK && state.processing_active);
    uint8_t const *bytes = NULL; size_t size = 0;
    CHECK(vireo_tcp_server_client_read_peek(f->server, f->clients[0], &bytes, &size, NULL) == VIREO_OK && size == 35);
    vireo_connection_frame_view_t view; vireo_connection_frame_info_t parsed;
    CHECK(vireo_tcp_server_client_frames_peek(f->server, f->clients[0], &frame_options, &frame_budget,
        &view, 1, &parsed, NULL) == VIREO_OK && parsed.frame_count == 1);
    vireo_tcp_server_client_info_t snapshot; CHECK(vireo_tcp_server_client_inspect(f->server, f->clients[1], &snapshot) == VIREO_OK);
    unsigned const receives = f->receives, consumes = f->consumes, enqueues = f->enqueues, sends = f->sends;
    vireo_connection_receive_info_t ri, ricopy; memset(&ri, 77, sizeof(ri)); ricopy = ri;
    vireo_connection_send_info_t si, sicopy; memset(&si, 77, sizeof(si)); sicopy = si;
    CHECK(vireo_tcp_server_client_receive(f->server, f->clients[0], &read_budget, &ri, NULL) == VIREO_RESULT_BUSY);
    CHECK(vireo_tcp_server_client_send(f->server, f->clients[1], &write_budget, &si, NULL) == VIREO_RESULT_BUSY);
    CHECK(memcmp(&ri, &ricopy, sizeof(ri)) == 0 && memcmp(&si, &sicopy, sizeof(si)) == 0);
    CHECK(vireo_tcp_server_client_read_consume(f->server, f->clients[0], 0, NULL) == VIREO_RESULT_BUSY);
    CHECK(vireo_tcp_server_client_write_enqueue(f->server, f->clients[1], NULL, 0, NULL) == VIREO_RESULT_BUSY);
    vireo_connection_pool_lease_t lease = f->clients[0];
    CHECK(vireo_tcp_server_release_client(f->server, &lease, NULL) == VIREO_RESULT_BUSY && same(lease, f->clients[0]));
    lease = f->clients[1]; CHECK(vireo_tcp_server_release_client(f->server, &lease, NULL) == VIREO_RESULT_BUSY && same(lease, f->clients[1]));
    CHECK(f->receives == receives && f->consumes == consumes && f->enqueues == enqueues && f->sends == sends);
    vireo_acceptor_t *spare = g->spare;
    CHECK(vireo_tcp_server_adopt_listener(f->server, &spare, NULL) == VIREO_RESULT_BUSY && spare == g->spare);
    CHECK(vireo_tcp_server_bind_listener(f->server, true, NULL) == VIREO_RESULT_BUSY);
    CHECK(vireo_tcp_server_set_listener_read_enabled(f->server, false, NULL) == VIREO_RESULT_BUSY);
    CHECK(vireo_tcp_server_unbind_listener(f->server, NULL) == VIREO_RESULT_BUSY);
    vireo_connection_pool_lease_t output = {0}; vireo_tcp_server_admit_budget_t const b = {1, 1};
    vireo_tcp_server_admit_info_t ai, acopy; memset(&ai, 77, sizeof(ai)); acopy = ai;
    CHECK(vireo_tcp_server_admit_batch(f->server, &connection_options, &b, &output, 1, &ai, NULL) == VIREO_RESULT_BUSY);
    CHECK(empty(output) && memcmp(&ai, &acopy, sizeof(ai)) == 0);
    vireo_tcp_server_t *owner = f->server; CHECK(vireo_tcp_server_destroy(&owner, NULL) == VIREO_RESULT_BUSY && owner == f->server);
    uint8_t scratch[64]; memset(scratch, marker, sizeof(scratch)); handler_context_t h = {0};
    vireo_tcp_server_process_info_t pi, pcopy; memset(&pi, 77, sizeof(pi)); pcopy = pi;
    errno = EDOM;
    CHECK(vireo_tcp_server_client_process(f->server, f->clients[1], &limits, &allowance, scratch,
        sizeof(scratch), echo_reply, &h, &pi, NULL) == VIREO_RESULT_BUSY && errno == EDOM);
    CHECK(memcmp(&pi, &pcopy, sizeof(pi)) == 0 && h.calls == 0 && scratch[0] == marker);
    CHECK(process(g->nested, 0, limits, allowance, scratch, sizeof(scratch), &h, &pi, NULL) == VIREO_OK && pi.consumed_requests == 1);
    CHECK(vireo_tcp_server_inspect(f->server, &state) == VIREO_OK && state.processing_active);
    CHECK(memcmp(r->body, copy, 3) == 0); memcpy(body, copy, 3); reply->body_size = 3;
    errno = EPIPE; return VIREO_OK;
}
static void reentry(void)
{
    fixture_t f = {0}, other = {0}; start(&f, AF_INET, true, connection_options, 2);
    start(&other, AF_UNIX, false, connection_options, 1);
    uint8_t wire[35], work[64]; make_frame(wire, header(1, false), "abc", 3); feed(&f, 0, wire, 35);
    make_frame(wire, header(3, false), "XYZ", 3); feed(&f, 1, wire, 35); feed(&other, 0, wire, 35);
    int spare_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0); REQUIRE(spare_fd >= 0);
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr = {htonl(INADDR_LOOPBACK)}};
    REQUIRE(bind(spare_fd, (struct sockaddr *)&address, (socklen_t)sizeof(address)) == 0 && listen(spare_fd, 1) == 0);
    vireo_acceptor_t *spare = NULL; vireo_acceptor_options_t const ao = {4096};
    REQUIRE(vireo_acceptor_create(&ao, &spare_fd, &spare, NULL) == VIREO_OK);
    guard_context_t g = {&f, &other, spare, 0}; vireo_tcp_server_process_info_t i; errno = EDOM;
    CHECK(vireo_tcp_server_client_process(f.server, f.clients[0], &limits, &allowance, work, sizeof(work),
        guarded_reply, &g, &i, NULL) == VIREO_OK && errno == EDOM && g.calls == 1 && i.consumed_requests == 1);
    CHECK(info(&f, 1).connection_info.read_buffer.readable_size == 35 && info(&f, 1).connection_info.write_buffer.readable_size == 0);
    handler_context_t h = {0}; CHECK(process(&f, 1, limits, allowance, work, sizeof(work), &h, &i, NULL) == VIREO_OK && i.consumed_requests == 1);
    REQUIRE(vireo_acceptor_destroy(&spare, NULL) == VIREO_OK);
    end(&other, 1); end(&f, 2); ++groups;
}
static void capacity_and_identity(void)
{
    fixture_t f = {0}; start(&f, AF_UNIX, false, connection_options, 2);
    uint8_t wire[256], body[224], work[144], out[128]; memset(body, 1, sizeof(body)); memset(work, marker, sizeof(work));
    make_frame(wire, header(1, false), (char const *)body, sizeof(body)); feed(&f, 0, wire, sizeof(wire));
    make_frame(wire, header(3, false), "XYZ", 3); feed(&f, 1, wire, 35);
    vireo_tcp_server_process_options_t const big = {256, 128};
    vireo_tcp_server_process_budget_t const one = {1, 256, 128};
    handler_context_t h = {.mode = 3}; vireo_tcp_server_process_info_t i;
    CHECK(process(&f, 0, big, one, work, sizeof(work), &h, &i, NULL) == VIREO_OK &&
          i.consumed_request_bytes == 256 && i.enqueued_response_bytes == 128);
    for (size_t n = 128; n < sizeof(work); ++n) CHECK(work[n] == marker);
    uint8_t expected[96]; for (size_t n = 0; n < sizeof(expected); ++n) expected[n] = (uint8_t)(n % 251);
    memset(work, 0, sizeof(work)); sent(&f, 0, out, sizeof(out));
    check_response(out, sizeof(out), 1, expected, sizeof(expected), VIREO_STATUS_OK, 0, 0);
    CHECK(info(&f, 1).connection_info.read_buffer.readable_size == 35);
    vireo_connection_pool_lease_t const old = f.clients[0];
    REQUIRE(vireo_tcp_server_release_client(f.server, &f.clients[0], NULL) == VIREO_OK);
    REQUIRE(close(f.peers[0]) == 0);
    f.peers[0] = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0); REQUIRE(f.peers[0] >= 0);
    REQUIRE(connect(f.peers[0], (struct sockaddr *)&f.address, f.length) == 0);
    vireo_tcp_server_admit_budget_t const b = {1, 1}; vireo_tcp_server_admit_info_t ai;
    REQUIRE(vireo_tcp_server_admit_batch(f.server, &connection_options, &b, &f.clients[0], 1, &ai, NULL) == VIREO_OK && ai.admitted_count == 1);
    CHECK(old.slot_index == f.clients[0].slot_index && !same(old, f.clients[0]));
    vireo_tcp_server_process_info_t sentinel; memset(&sentinel, 77, sizeof(sentinel)); i = sentinel;
    CHECK(vireo_tcp_server_client_process(f.server, old, &limits, &allowance, work, sizeof(work), echo_reply,
        &h, &i, NULL) == VIREO_RESULT_NOT_FOUND && memcmp(&i, &sentinel, sizeof(i)) == 0);
    make_frame(wire, header(99, false), "Z", 1); feed(&f, 0, wire, 33); h = (handler_context_t){0};
    CHECK(process(&f, 0, limits, allowance, work, sizeof(work), &h, &i, NULL) == VIREO_OK && h.sequences[0] == 99);
    end(&f, 2); ++groups;
}
static void zero_body_limit(void)
{
    fixture_t f = {0}; start(&f, AF_INET, false, connection_options, 1);
    uint8_t wire[64], work[40]; memset(work, marker, sizeof(work));
    make_frame(wire, header(1, false), NULL, 0); make_frame(wire + 32, header(3, false), NULL, 0);
    feed(&f, 0, wire, sizeof(wire));
    vireo_tcp_server_process_options_t const o = {32, 32};
    vireo_tcp_server_process_budget_t const b = {2, SIZE_MAX, SIZE_MAX};
    handler_context_t h = {.mode = 3}; vireo_tcp_server_process_info_t i;
    CHECK(process(&f, 0, o, b, work, sizeof(work), &h, &i, NULL) == VIREO_OK &&
          i.handler_calls == 2 && i.consumed_request_bytes == 64 && i.enqueued_response_bytes == 64 &&
          i.stop_reason == VIREO_TCP_SERVER_PROCESS_MESSAGE_BUDGET);
    for (size_t n = 32; n < sizeof(work); ++n) CHECK(work[n] == marker);
    sent(&f, 0, wire, sizeof(wire));
    check_response(wire, 32, 1, NULL, 0, VIREO_STATUS_OK, 0, 0);
    check_response(wire + 32, 32, 3, NULL, 0, VIREO_STATUS_OK, 0, 0);
    end(&f, 1); ++groups;
    fixture_t small = {0}; vireo_connection_options_t const co = {31, 128, 159};
    start(&small, AF_UNIX, false, co, 1); memset(&i, 77, sizeof(i));
    vireo_tcp_server_process_info_t copy; memcpy(&copy, &i, sizeof(i)); h = (handler_context_t){0};
    CHECK(process(&small, 0, o, b, work, sizeof(work), &h, &i, NULL) == VIREO_RESULT_RANGE &&
          memcmp(&i, &copy, sizeof(i)) == 0 && h.calls == 0);
    end(&small, 1); ++groups;
}
int main(void)
{
    unsigned const before = fd_count();
    normal(AF_INET); normal(AF_UNIX); half_and_eof(); invalid_prefix(false); invalid_prefix(true);
    budgets(); write_pressure(); rejection(); handler_errors(); dependency_failures(); reentry(); capacity_and_identity(); zero_body_limit();
    unsigned const after = fd_count(); CHECK(before == after);
    printf("tcp_server sync handler: %u groups, %u failures, fd %u -> %u\n", groups, failures, before, after);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
