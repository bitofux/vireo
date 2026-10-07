/*
- PROJECT : VIREO
- FILE    : test_tcp_server_scheduling.c
- AUTHOR  : bitofux
- DATE    : 2026-10-05
- BRIEF   : 此模块负责：
- -- 真实 TCP/Unix 缓存轮转、通知去重、预算与失败前缀
- -- 归还/复用、整轮在途与实际资源预算
 */
#define _GNU_SOURCE
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
static vireo_tcp_server_options_t const server_options = {4, 8, 1048576, 16384};
static vireo_connection_options_t const conn_options = {256, 128, 384};
static vireo_connection_flow_options_t const flow = {96, 95, 192, 32, 96};
static vireo_tcp_server_process_options_t const limits = {96, 96};
static vireo_tcp_server_drive_budget_t const allowance = {
    {SIZE_MAX, 8}, {2, 192, 192}, {SIZE_MAX, 8}};
static vireo_tcp_server_round_budget_t const all_clients = {4};
static bool same(vireo_connection_pool_lease_t a, vireo_connection_pool_lease_t b) {
    return a.pool_id == b.pool_id && a.slot_index == b.slot_index && a.generation == b.generation;
}
static bool empty(vireo_connection_pool_lease_t a) {
    return a.pool_id == 0 && a.slot_index == 0 && a.generation == 0;
}
static unsigned fd_count(void) {
    DIR *d = opendir("/proc/self/fd");
    REQUIRE(d != NULL);
    unsigned n = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL)
        if (e->d_name[0] != '.')
            ++n;
    REQUIRE(closedir(d) == 0);
    return n;
}
typedef struct fixture {
    vireo_tcp_server_t *server;
    vireo_connection_pool_lease_t clients[4];
    int peers[4], raw_fds[4], family;
    vireo_connection_t *objects[4]; /* own public wrapper 短借用，仅测试人工通知/设置发送缓冲。 */
    vireo_connection_callback_t callbacks[4];
    void *callback_contexts[4];
    unsigned created, attached, wait_calls, handler_calls;
    int observed_timeout;
    bool wait_io, inject_events, detach_io, release_busy, release_io, fail_sync, probe_wait,
        probe_handler;
    uint32_t fail_sequence, sequences[32];
    struct sockaddr_storage address;
    socklen_t length;
    struct fixture *nested;
} fixture_t;
static void probe(fixture_t *f, bool in_handler);
static vireo_result_t handler(vireo_connection_frame_view_t const *req, uint8_t *body, size_t cap,
                              vireo_tcp_server_reply_t *reply, void *ctx);
static vireo_result_t wait_once(void *ctx, vireo_event_loop_t *loop, int timeout,
                                vireo_event_loop_run_info_t *info,
                                vireo_event_loop_error_t *error) {
    fixture_t *f = ctx;
    ++f->wait_calls;
    f->observed_timeout = timeout;
    if (f->probe_wait)
        probe(f, false);
    if (f->wait_io) { /* 等待边界注入；没有运行通知，不谎称真实信号中断。 */
        *error = (vireo_event_loop_error_t){.stage = VIREO_EVENT_LOOP_STAGE_WAIT,
                                            .epoll_error = {VIREO_EPOLL_STAGE_WAIT, EINTR}};
        errno = ERANGE;
        return VIREO_RESULT_IO;
    }
    if (f->inject_events) { /* 人工 adapter 通知用于 OR/去重；真实通知另独立测试。 */
        f->callbacks[0](f->objects[0], VIREO_EPOLL_EVENT_READ, f->callback_contexts[0]);
        f->callbacks[0](f->objects[0], VIREO_EPOLL_EVENT_WRITE, f->callback_contexts[0]);
        f->inject_events = false;
    }
    vireo_result_t const r = vireo_event_loop_run_once(loop, timeout, info, error);
    errno = ERANGE;
    return r;
}
static vireo_result_t create_client(void *ctx, vireo_connection_options_t const *o, int *fd,
                                    vireo_connection_t **owner, vireo_connection_error_t *error) {
    fixture_t *f = ctx;
    int const raw = *fd;
    vireo_result_t const r = vireo_connection_create(o, fd, owner, error);
    if (r == VIREO_OK) {
        unsigned const k = f->created++ % 4;
        f->objects[k] = *owner;
        f->raw_fds[k] = raw;
    }
    return r;
}
static vireo_result_t attach_client(void *ctx, vireo_connection_t *c, vireo_event_loop_t *l,
                                    uint32_t m, vireo_connection_callback_t cb, void *cbctx,
                                    vireo_connection_loop_error_t *error) {
    fixture_t *f = ctx;
    vireo_result_t const r = vireo_connection_attach(c, l, m, cb, cbctx, error);
    if (r == VIREO_OK) {
        unsigned const k = f->attached++ % 4;
        f->callbacks[k] = cb;
        f->callback_contexts[k] = cbctx;
    }
    return r;
}
static vireo_result_t detach_client(void *ctx, vireo_connection_t *c,
                                    vireo_connection_loop_error_t *error) {
    fixture_t *f = ctx;
    if (f->detach_io) {
        *error = (vireo_connection_loop_error_t){
            .stage = VIREO_CONNECTION_LOOP_STAGE_DETACH,
            .loop_error = {.stage = VIREO_EVENT_LOOP_STAGE_DEL,
                           .epoll_error = {VIREO_EPOLL_STAGE_DEL, EBADF}}};
        return VIREO_RESULT_IO;
    }
    return vireo_connection_detach(c, error);
}
static vireo_result_t release_client(void *ctx, vireo_connection_pool_t *pool,
                                     vireo_connection_pool_lease_t *lease,
                                     vireo_connection_pool_operation_error_t *error) {
    fixture_t *f = ctx;
    if (f->release_busy)
        return VIREO_RESULT_BUSY;
    vireo_result_t const r = vireo_connection_pool_release(pool, lease, error);
    if (r == VIREO_OK && f->release_io) { /* 真实消费后注入 IO，不能再次 close。 */
        error->stage = VIREO_CONNECTION_POOL_OPERATION_DESTROY_CONNECTION;
        error->connection_error =
            (vireo_connection_error_t){VIREO_CONNECTION_STAGE_CLOSE_SOCKET, EINTR};
        return VIREO_RESULT_IO;
    }
    return r;
}
static vireo_result_t refresh(void *ctx, vireo_connection_t *c,
                              vireo_connection_loop_error_t *error) {
    fixture_t *f = ctx;
    if (f->fail_sync) {
        *error = (vireo_connection_loop_error_t){
            .stage = VIREO_CONNECTION_LOOP_STAGE_FLOW_REFRESH,
            .loop_error = {.stage = VIREO_EVENT_LOOP_STAGE_MOD,
                           .epoll_error = {VIREO_EPOLL_STAGE_MOD, EBADF}}};
        return VIREO_RESULT_IO;
    }
    return vireo_connection_flow_refresh(c, error);
}
/** 只桥接已封板公开依赖，ctx 无资源所有权。 */
static vireo_result_t accept_client(void *ctx, vireo_acceptor_t *a,
                                    vireo_acceptor_accept_budget_t const *b, int *fds, size_t n,
                                    vireo_acceptor_accept_info_t *i, vireo_acceptor_error_t *e) {
    (void)ctx;
    return vireo_acceptor_accept_batch(a, b, fds, n, i, e);
}
/** 只桥接已封板公开依赖，ctx 无资源所有权。 */
static vireo_result_t inspect_client(void *ctx, vireo_connection_t const *c,
                                     vireo_connection_info_t *i) {
    (void)ctx;
    return vireo_connection_inspect(c, i);
}
/** 只桥接已封板公开依赖，ctx 无资源所有权。 */
static vireo_result_t adopt_client(void *ctx, vireo_connection_pool_t *p, vireo_connection_t **c,
                                   vireo_connection_pool_lease_t *l,
                                   vireo_connection_pool_operation_error_t *e) {
    (void)ctx;
    return vireo_connection_pool_adopt(p, c, l, e);
}
/** 只桥接已封板公开依赖，ctx 无资源所有权。 */
static vireo_result_t lookup_client(void *ctx, vireo_connection_pool_t const *p,
                                    vireo_connection_pool_lease_t l, vireo_connection_t **c) {
    (void)ctx;
    return vireo_connection_pool_lookup(p, l, c);
}
/** 只桥接已封板公开依赖，ctx 无资源所有权。 */
static vireo_result_t destroy_client(void *ctx, vireo_connection_t **c,
                                     vireo_connection_error_t *e) {
    (void)ctx;
    return vireo_connection_destroy(c, e);
}
/** 只桥接已封板公开依赖，ctx 无资源所有权。 */
static vireo_result_t receive_bytes(void *ctx, vireo_connection_t *c,
                                    vireo_connection_receive_budget_t const *b,
                                    vireo_connection_receive_info_t *i,
                                    vireo_connection_error_t *e) {
    (void)ctx;
    return vireo_connection_receive(c, b, i, e);
}
/** 只桥接已封板公开依赖，ctx 无资源所有权。 */
static vireo_result_t peek_bytes(void *ctx, vireo_connection_t const *c, uint8_t const **p,
                                 size_t *n) {
    (void)ctx;
    return vireo_connection_read_peek(c, p, n);
}
/** 只桥接已封板公开依赖，ctx 无资源所有权。 */
static vireo_result_t consume_bytes(void *ctx, vireo_connection_t *c, size_t n) {
    (void)ctx;
    return vireo_connection_read_consume(c, n);
}
/** 只桥接已封板公开依赖，ctx 无资源所有权。 */
static vireo_result_t enqueue_bytes(void *ctx, vireo_connection_t *c, uint8_t const *p, size_t n,
                                    vireo_connection_error_t *e) {
    (void)ctx;
    return vireo_connection_write_enqueue(c, p, n, e);
}
/** 只桥接已封板公开依赖，ctx 无资源所有权。 */
static vireo_result_t send_bytes(void *ctx, vireo_connection_t *c,
                                 vireo_connection_send_budget_t const *b,
                                 vireo_connection_send_info_t *i, vireo_connection_error_t *e) {
    (void)ctx;
    return vireo_connection_send(c, b, i, e);
}
/** 只桥接已封板公开依赖，ctx 无资源所有权。 */
static vireo_result_t frame_views(void *ctx, vireo_connection_t const *c,
                                  vireo_connection_frame_options_t const *o,
                                  vireo_connection_frame_budget_t const *b,
                                  vireo_connection_frame_view_t *v, size_t n,
                                  vireo_connection_frame_info_t *i,
                                  vireo_connection_frame_error_t *e) {
    (void)ctx;
    return vireo_connection_frames_peek(c, o, b, v, n, i, e);
}
/** 只桥接已封板公开依赖，ctx 无资源所有权。 */
static vireo_result_t set_interests(void *ctx, vireo_connection_t *c, uint32_t m,
                                    vireo_connection_loop_error_t *e) {
    (void)ctx;
    return vireo_connection_set_interests(c, m, e);
}
/** 只桥接已封板公开依赖，ctx 无资源所有权。 */
static vireo_result_t configure(void *ctx, vireo_connection_t *c,
                                vireo_connection_flow_options_t const *o,
                                vireo_connection_loop_error_t *e) {
    (void)ctx;
    return vireo_connection_flow_configure(c, o, e);
}
/** 只桥接已封板公开依赖，ctx 无资源所有权。 */
static vireo_result_t disable(void *ctx, vireo_connection_t *c, vireo_connection_loop_error_t *e) {
    (void)ctx;
    return vireo_connection_flow_disable(c, e);
}
/** 只桥接已封板公开依赖，ctx 无资源所有权。 */
static vireo_result_t request_close(void *ctx, vireo_connection_t *c,
                                    vireo_connection_close_mode_t m,
                                    vireo_connection_close_reason_t r,
                                    vireo_connection_loop_error_t *e) {
    (void)ctx;
    return vireo_connection_request_close(c, m, r, e);
}
/** 只桥接已封板公开依赖，ctx 无资源所有权。 */
static vireo_result_t close_refresh(void *ctx, vireo_connection_t *c,
                                    vireo_connection_loop_error_t *e) {
    (void)ctx;
    return vireo_connection_close_refresh(c, e);
}

static int close_fd(void *ctx, int fd) {
    (void)ctx;
    return close(fd);
}
static vireo_tcp_server_client_ops_t ops(fixture_t *f) {
    return (vireo_tcp_server_client_ops_t){f,
                                           accept_client,
                                           create_client,
                                           inspect_client,
                                           adopt_client,
                                           lookup_client,
                                           attach_client,
                                           detach_client,
                                           release_client,
                                           destroy_client,
                                           close_fd,
                                           receive_bytes,
                                           peek_bytes,
                                           consume_bytes,
                                           enqueue_bytes,
                                           send_bytes,
                                           frame_views,
                                           set_interests,
                                           configure,
                                           refresh,
                                           disable,
                                           request_close,
                                           close_refresh};
}
static int listener(fixture_t *f, int family) {
    static unsigned serial;
    int fd = socket(family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    REQUIRE(fd >= 0);
    f->family = family;
    if (family == AF_INET) {
        struct sockaddr_in a = {.sin_family = AF_INET, .sin_addr = {htonl(INADDR_LOOPBACK)}};
        f->length = (socklen_t)sizeof(a);
        REQUIRE(bind(fd, (struct sockaddr *)&a, f->length) == 0);
        REQUIRE(getsockname(fd, (struct sockaddr *)&f->address, &f->length) == 0);
    } else {
        struct sockaddr_un a = {.sun_family = AF_UNIX};
        int const n = snprintf(a.sun_path + 1, sizeof(a.sun_path) - 1, "vireo-scheduler-%ld-%u",
                               (long)getpid(), ++serial);
        REQUIRE(n > 0 && (size_t)n < sizeof(a.sun_path) - 1);
        memcpy(&f->address, &a, sizeof(a));
        f->length = (socklen_t)sizeof(a);
        REQUIRE(bind(fd, (struct sockaddr *)&f->address, f->length) == 0);
    }
    REQUIRE(listen(fd, 8) == 0);
    return fd;
}
static int connect_peer(fixture_t *f) {
    int fd = socket(f->family, SOCK_STREAM | SOCK_CLOEXEC, 0);
    REQUIRE(fd >= 0);
    struct timeval t = {2, 0};
    REQUIRE(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &t, (socklen_t)sizeof(t)) == 0);
    REQUIRE(connect(fd, (struct sockaddr *)&f->address, f->length) == 0);
    return fd;
}
static void start(fixture_t *f, int family, size_t count) {
    *f = (fixture_t){0};
    vireo_tcp_server_client_ops_t const c = ops(f);
    vireo_tcp_server_scheduler_ops_t const w = {f, wait_once};
    REQUIRE(vireo_tcp_server_create_with_scheduler_ops(&server_options, NULL, NULL, &c, &w,
                                                       &f->server, NULL) == VIREO_OK);
    int fd = listener(f, family);
    vireo_acceptor_t *a = NULL;
    vireo_acceptor_options_t const o = {4096};
    REQUIRE(vireo_acceptor_create(&o, &fd, &a, NULL) == VIREO_OK);
    REQUIRE(vireo_tcp_server_adopt_listener(f->server, &a, NULL) == VIREO_OK && a == NULL);
    for (size_t k = 0; k < count; ++k)
        f->peers[k] = connect_peer(f);
    if (count) {
        vireo_tcp_server_admit_budget_t const b = {count, count};
        vireo_tcp_server_admit_info_t i;
        REQUIRE(vireo_tcp_server_admit_batch(f->server, &conn_options, &b, f->clients, count, &i,
                                             NULL) == VIREO_OK &&
                i.admitted_count == count);
        for (size_t k = 0; k < count; ++k)
            REQUIRE(vireo_tcp_server_client_flow_configure(f->server, f->clients[k], &flow, NULL) ==
                    VIREO_OK);
    }
}
static void end(fixture_t *f, size_t count) {
    f->detach_io = false;
    f->release_busy = false;
    f->release_io = false;
    f->fail_sync = false;
    for (size_t k = 0; k < count; ++k) {
        if (!empty(f->clients[k]))
            REQUIRE(vireo_tcp_server_release_client(f->server, &f->clients[k], NULL) == VIREO_OK);
        REQUIRE(close(f->peers[k]) == 0);
    }
    REQUIRE(vireo_tcp_server_destroy(&f->server, NULL) == VIREO_OK);
}
static vireo_tcp_server_info_t state(fixture_t *f) {
    vireo_tcp_server_info_t i;
    REQUIRE(vireo_tcp_server_inspect(f->server, &i) == VIREO_OK);
    return i;
}
static vireo_tcp_server_client_info_t client(fixture_t *f, size_t k) {
    vireo_tcp_server_client_info_t i;
    REQUIRE(vireo_tcp_server_client_inspect(f->server, f->clients[k], &i) == VIREO_OK);
    return i;
}
static void schedule(fixture_t *f, size_t k) {
    errno = EDOM;
    REQUIRE(vireo_tcp_server_schedule_client(f->server, f->clients[k], NULL) == VIREO_OK);
    CHECK(errno == EDOM);
}
static void request(uint8_t *wire, uint32_t seq) {
    vireo_protocol_header_t h = {.command = VIREO_COMMAND_PING, .sequence = seq};
    REQUIRE(vireo_protocol_header_encode(&h, wire, 32) == VIREO_OK);
    REQUIRE(vireo_protocol_frame_crc32c_calculate(wire, 32, NULL, 0, &h.crc32c) == VIREO_OK);
    REQUIRE(vireo_protocol_header_encode(&h, wire, 32) == VIREO_OK);
}
static void transmit(fixture_t *f, size_t k, uint8_t const *p, size_t n) {
    size_t at = 0;
    while (at < n) {
        ssize_t const sent = send(f->peers[k], p + at, n - at, MSG_NOSIGNAL);
        REQUIRE(sent > 0);
        at += (size_t)sent;
    }
}
static void feed(fixture_t *f, size_t k, unsigned n, uint32_t first) {
    uint8_t p[256];
    REQUIRE(n <= 8);
    for (unsigned q = 0; q < n; ++q)
        request(p + (size_t)q * 32, first + q);
    transmit(f, k, p, (size_t)n * 32);
    vireo_connection_receive_info_t i;
    REQUIRE(vireo_tcp_server_client_receive(f->server, f->clients[k], &allowance.receive, &i,
                                            NULL) == VIREO_OK &&
            i.received_bytes == (size_t)n * 32);
}
static vireo_result_t round_at(fixture_t *f, int timeout, vireo_tcp_server_round_budget_t b,
                               size_t cap, vireo_tcp_server_turn_result_t *turns,
                               vireo_tcp_server_round_info_t *i,
                               vireo_tcp_server_round_error_t *e) {
    uint8_t workspace[96];
    errno = EDOM;
    vireo_result_t const r =
        vireo_tcp_server_run_once(f->server, timeout, &limits, &allowance, &b, workspace,
                                  sizeof(workspace), handler, f, turns, cap, i, e);
    CHECK(errno == EDOM);
    return r;
}
static vireo_result_t handler(vireo_connection_frame_view_t const *req, uint8_t *body, size_t cap,
                              vireo_tcp_server_reply_t *reply, void *ctx) {
    (void)body;
    (void)cap;
    fixture_t *f = ctx;
    if (f->handler_calls < 32)
        f->sequences[f->handler_calls] = req->header.sequence;
    ++f->handler_calls;
    reply->body_size = 0;
    if (f->probe_handler)
        probe(f, true);
    if (f->nested != NULL) {
        vireo_tcp_server_turn_result_t t[4];
        vireo_tcp_server_round_info_t i;
        CHECK(round_at(f->nested, 0, all_clients, 4, t, &i, NULL) == VIREO_OK && i.turn_count == 1);
        f->nested = NULL;
    }
    errno = ERANGE;
    if (req->header.sequence == f->fail_sequence) {
        f->fail_sync = true;
        return VIREO_RESULT_IO;
    }
    return VIREO_OK;
}
static void responses(fixture_t *f, size_t k, unsigned n, uint32_t first) {
    uint8_t p[256];
    size_t at = 0, length = (size_t)n * 32;
    REQUIRE(length <= sizeof(p));
    while (at < length) {
        ssize_t const got = recv(f->peers[k], p + at, length - at, 0);
        REQUIRE(got > 0);
        at += (size_t)got;
    }
    for (unsigned q = 0; q < n; ++q) {
        vireo_protocol_header_t h;
        vireo_protocol_codec_issue_t why;
        CHECK(vireo_protocol_header_decode(p + (size_t)q * 32, 32, &h, &why) == VIREO_OK);
        CHECK(h.sequence == first + q && h.command == VIREO_COMMAND_PING &&
              h.flags == VIREO_PROTOCOL_FLAG_RESPONSE && h.status == VIREO_STATUS_OK);
        CHECK(vireo_protocol_frame_crc32c_verify(p + (size_t)q * 32, 32, NULL, 0, &why) ==
              VIREO_OK);
    }
}
static void parameters(void) {
    ++groups;
    fixture_t f;
    start(&f, AF_UNIX, 1);
    schedule(&f, 0);
    for (unsigned k = 0; k < 14; ++k) {
        vireo_tcp_server_process_options_t o = limits;
        vireo_tcp_server_drive_budget_t d = allowance;
        vireo_tcp_server_round_budget_t b = all_clients;
        int timeout = 0;
        size_t cap = 4, wcap = 96;
        switch (k) {
            case 0:
                b.max_clients = 0;
                break;
            case 1:
                b.max_clients = 65536;
                break;
            case 2:
                cap = 0;
                break;
            case 3:
                cap = 65536;
                break;
            case 4:
                timeout = -2;
                break;
            case 5:
                o.max_request_frame_bytes = 31;
                break;
            case 6:
                wcap = 95;
                break;
            case 7:
                d.receive.max_bytes = 0;
                break;
            case 8:
                d.receive.max_syscalls = 0;
                break;
            case 9:
                d.send.max_bytes = 0;
                break;
            case 10:
                d.send.max_syscalls = 0;
                break;
            case 11:
                d.process.max_messages = 0;
                break;
            case 12:
                d.process.max_request_bytes = 95;
                break;
            default:
                d.process.max_response_bytes = 95;
                break;
        }
        uint8_t w[96], wb[96];
        memset(w, 0x91, sizeof(w));
        memcpy(wb, w, sizeof(w));
        vireo_tcp_server_turn_result_t t[4], tb[4];
        memset(t, 0x63, sizeof(t));
        memcpy(tb, t, sizeof(t));
        vireo_tcp_server_round_info_t i, ib;
        memset(&i, 0x42, sizeof(i));
        memcpy(&ib, &i, sizeof(i));
        errno = EDOM;
        CHECK(vireo_tcp_server_run_once(f.server, timeout, &o, &d, &b, w, wcap, handler, &f, t, cap,
                                        &i, NULL) ==
              (k == 4 ? VIREO_RESULT_INVALID_ARGUMENT : VIREO_RESULT_RANGE));
        CHECK(errno == EDOM && memcmp(w, wb, sizeof(w)) == 0 && memcmp(t, tb, sizeof(t)) == 0 &&
              memcmp(&i, &ib, sizeof(i)) == 0);
    }
    vireo_tcp_server_turn_result_t t[4];
    vireo_tcp_server_round_info_t i;
    uint8_t w[96];
    CHECK(vireo_tcp_server_run_once(f.server, 0, &limits, &allowance, &all_clients, w, 96, handler,
                                    &f, NULL, 4, &i, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_tcp_server_run_once(f.server, 0, &limits, &allowance, &all_clients, w, 96, handler,
                                    &f, t, 4, NULL, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(f.wait_calls == 0 && f.handler_calls == 0 && state(&f).pending_clients == 1);
    vireo_connection_pool_lease_t bad = f.clients[0];
    ++bad.generation;
    CHECK(vireo_tcp_server_schedule_client(f.server, bad, NULL) == VIREO_RESULT_NOT_FOUND);
    bad = f.clients[0];
    ++bad.pool_id;
    CHECK(vireo_tcp_server_schedule_client(f.server, bad, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    bad = f.clients[0];
    bad.slot_index = 4;
    CHECK(vireo_tcp_server_schedule_client(f.server, bad, NULL) == VIREO_RESULT_RANGE);
    CHECK(vireo_tcp_server_schedule_client(f.server, (vireo_connection_pool_lease_t){0}, NULL) ==
          VIREO_RESULT_NOT_FOUND);
    CHECK(state(&f).pending_clients == 1);
    end(&f, 1);
}
static void fairness(int family) {
    ++groups;
    fixture_t f;
    start(&f, family, 2);
    feed(&f, 0, 7, 1);
    feed(&f, 1, 1, 99);
    schedule(&f, 0);
    schedule(&f, 1);
    schedule(&f, 0);
    vireo_tcp_server_turn_result_t t[4];
    vireo_tcp_server_round_info_t i;
    REQUIRE(round_at(&f, -1, (vireo_tcp_server_round_budget_t){2}, 4, t, &i, NULL) == VIREO_OK);
    CHECK(i.turn_count == 2 && i.queued_before_wait == 2 && i.queued_after_wait == 2 &&
          i.requeued_count == 1 && i.remaining_count == 1 && i.effective_timeout_ms == 0);
    CHECK(same(t[0].client, f.clients[0]) && same(t[1].client, f.clients[1]) &&
          t[0].info.process.consumed_requests == 2 && t[1].info.process.consumed_requests == 1);
    CHECK(f.handler_calls == 3 && f.sequences[0] == 1 && f.sequences[1] == 2 &&
          f.sequences[2] == 99);
    for (unsigned q = 0; q < 3; ++q) {
        REQUIRE(round_at(&f, -1, all_clients, 4, t, &i, NULL) == VIREO_OK);
        CHECK(i.turn_count == 1 && same(t[0].client, f.clients[0]));
    }
    CHECK(f.handler_calls == 8 && state(&f).pending_clients == 0 &&
          client(&f, 0).connection_info.read_buffer.readable_size == 0);
    responses(&f, 0, 7, 1);
    responses(&f, 1, 1, 99);
    CHECK(f.wait_calls == 4);
    end(&f, 2);
}
static void caps_and_once(void) {
    ++groups;
    fixture_t f;
    start(&f, AF_UNIX, 3);
    for (size_t k = 0; k < 3; ++k) {
        feed(&f, k, 3, (uint32_t)(10 + k * 10));
        schedule(&f, k);
    }
    vireo_tcp_server_turn_result_t t[4];
    vireo_tcp_server_round_info_t i;
    CHECK(round_at(&f, 100, all_clients, 1, t, &i, NULL) == VIREO_OK && i.turn_count == 1 &&
          same(t[0].client, f.clients[0]) && i.remaining_count == 3);
    CHECK(round_at(&f, 100, (vireo_tcp_server_round_budget_t){1}, 4, t, &i, NULL) == VIREO_OK &&
          i.turn_count == 1 && same(t[0].client, f.clients[1]));
    CHECK(round_at(&f, 100, all_clients, 4, t, &i, NULL) == VIREO_OK && i.turn_count == 3 &&
          same(t[0].client, f.clients[2]) && same(t[1].client, f.clients[0]) &&
          same(t[2].client, f.clients[1]));
    CHECK(state(&f).pending_clients == 1);
    CHECK(round_at(&f, -1, all_clients, 4, t, &i, NULL) == VIREO_OK && i.turn_count == 1 &&
          i.remaining_count == 0);
    for (size_t k = 0; k < 3; ++k)
        responses(&f, k, 3, (uint32_t)(10 + k * 10));
    end(&f, 3);
}
static void native_events(void) {
    ++groups;
    fixture_t f;
    start(&f, AF_INET, 1);
    uint8_t p[32];
    request(p, 9);
    transmit(&f, 0, p, 32);
    vireo_tcp_server_turn_result_t t[4];
    vireo_tcp_server_round_info_t i;
    REQUIRE(round_at(&f, -1, all_clients, 4, t, &i, NULL) == VIREO_OK);
    CHECK(i.queued_before_wait == 0 && i.queued_after_wait == 1 && i.turn_count == 1 &&
          i.effective_timeout_ms == -1 && i.wait.dispatched_count == 1);
    CHECK((t[0].events & VIREO_EPOLL_EVENT_READ) != 0 && t[0].info.receive.received_bytes == 32 &&
          t[0].info.process.consumed_requests == 1);
    responses(&f, 0, 1, 9);
    CHECK(client(&f, 0).pending_events == 0 && !client(&f, 0).queued);
    end(&f, 1);
}
static void merge_events(void) {
    ++groups;
    fixture_t f;
    start(&f, AF_UNIX, 1);
    schedule(&f, 0);
    f.inject_events = true;
    vireo_tcp_server_turn_result_t t[4];
    vireo_tcp_server_round_info_t i;
    CHECK(round_at(&f, -1, all_clients, 4, t, &i, NULL) == VIREO_OK && i.queued_after_wait == 1 &&
          i.turn_count == 1);
    CHECK(t[0].events == (VIREO_EPOLL_EVENT_READ | VIREO_EPOLL_EVENT_WRITE) &&
          client(&f, 0).last_events == VIREO_EPOLL_EVENT_WRITE &&
          client(&f, 0).pending_events == 0);
    end(&f, 1);
}
static void waits(void) {
    ++groups;
    fixture_t f;
    start(&f, AF_UNIX, 1);
    schedule(&f, 0);
    f.wait_io = true;
    vireo_tcp_server_turn_result_t t[4], tb[4];
    memset(t, 0x22, sizeof(t));
    memcpy(tb, t, sizeof(t));
    vireo_tcp_server_round_info_t i, ib;
    memset(&i, 0x42, sizeof(i));
    memcpy(&ib, &i, sizeof(i));
    vireo_tcp_server_round_error_t e;
    CHECK(round_at(&f, -1, all_clients, 4, t, &i, &e) == VIREO_RESULT_IO &&
          e.stage == VIREO_TCP_SERVER_ROUND_WAIT && e.loop_error.epoll_error.system_errno == EINTR);
    CHECK(memcmp(t, tb, sizeof(t)) == 0 && memcmp(&i, &ib, sizeof(i)) == 0 &&
          state(&f).pending_clients == 1 && f.wait_calls == 1 && !state(&f).scheduling_active);
    f.wait_io = false;
    CHECK(round_at(&f, -1, all_clients, 4, t, &i, NULL) == VIREO_OK && i.turn_count == 1);
    CHECK(round_at(&f, 1, all_clients, 4, t, &i, NULL) == VIREO_OK && i.turn_count == 0 &&
          f.observed_timeout == 1 && i.effective_timeout_ms == 1);
    end(&f, 1);
}
static void failure_prefix(void) {
    ++groups;
    fixture_t f;
    start(&f, AF_UNIX, 3);
    feed(&f, 0, 1, 1);
    feed(&f, 1, 1, 9);
    feed(&f, 2, 1, 20);
    for (size_t k = 0; k < 3; ++k)
        schedule(&f, k);
    f.fail_sequence = 9;
    vireo_tcp_server_turn_result_t t[4], before[4];
    memset(t, 0x57, sizeof(t));
    memcpy(before, t, sizeof(t));
    vireo_tcp_server_round_info_t i;
    vireo_tcp_server_round_error_t e;
    CHECK(round_at(&f, 0, all_clients, 4, t, &i, &e) == VIREO_RESULT_IO && i.turn_count == 2 &&
          i.succeeded_count == 1 && i.failed_count == 1 && i.remaining_count == 1);
    CHECK(e.stage == VIREO_TCP_SERVER_ROUND_DRIVE && same(e.client, f.clients[1]) &&
          e.drive_error.primary_stage == VIREO_TCP_SERVER_DRIVE_PROCESS &&
          e.drive_error.sync_result == VIREO_RESULT_IO);
    CHECK(e.drive_error.sync_error.primary.loop_error.loop_error.epoll_error.system_errno ==
              EBADF &&
          t[1].error.primary_error.primary.handler_result == VIREO_RESULT_IO);
    CHECK(t[0].info.process.consumed_requests == 1 && t[1].info.process.handler_calls == 1 &&
          t[1].info.process.consumed_requests == 0 &&
          memcmp(t + 2, before + 2, 2 * sizeof(t[0])) == 0);
    CHECK(!client(&f, 1).queued && client(&f, 2).queued &&
          client(&f, 1).connection_info.read_buffer.readable_size == 32);
    f.fail_sync = false;
    f.fail_sequence = 0;
    CHECK(round_at(&f, 0, all_clients, 4, t, &i, NULL) == VIREO_OK && i.turn_count == 1 &&
          same(t[0].client, f.clients[2]));
    responses(&f, 0, 1, 1);
    responses(&f, 2, 1, 20);
    end(&f, 3);
}
static void client_rejection(void) {
    ++groups;
    fixture_t f;
    start(&f, AF_UNIX, 2);
    feed(&f, 0, 1, 1);
    schedule(&f, 0);
    schedule(&f, 1);
    REQUIRE(vireo_tcp_server_client_flow_disable(f.server, f.clients[1], NULL) == VIREO_OK);
    vireo_tcp_server_turn_result_t t[4];
    vireo_tcp_server_round_info_t i;
    CHECK(round_at(&f, 0, all_clients, 4, t, &i, NULL) == VIREO_RESULT_NOT_FOUND &&
          i.turn_count == 2 && t[0].result == VIREO_OK && t[1].result == VIREO_RESULT_NOT_FOUND &&
          !t[1].info.receive_called && !t[1].info.process_called);
    responses(&f, 0, 1, 1);
    end(&f, 2);
}
static void half_frames(void) {
    ++groups;
    fixture_t f;
    start(&f, AF_UNIX, 1);
    uint8_t p[96];
    request(p, 1);
    request(p + 32, 2);
    request(p + 64, 3); /* only first 16 bytes of third sent below */
    transmit(&f, 0, p, 80);
    vireo_connection_receive_info_t ri;
    REQUIRE(vireo_tcp_server_client_receive(f.server, f.clients[0], &allowance.receive, &ri,
                                            NULL) == VIREO_OK &&
            ri.received_bytes == 80);
    schedule(&f, 0);
    vireo_tcp_server_turn_result_t t[4];
    vireo_tcp_server_round_info_t i;
    CHECK(round_at(&f, 0, all_clients, 4, t, &i, NULL) == VIREO_OK && i.turn_count == 1 &&
          i.remaining_count == 1);
    CHECK(round_at(&f, -1, all_clients, 4, t, &i, NULL) == VIREO_OK && i.turn_count == 1 &&
          i.remaining_count == 0 &&
          t[0].info.process.stop_reason == VIREO_TCP_SERVER_PROCESS_NEED_MORE);
    CHECK(round_at(&f, 0, all_clients, 4, t, &i, NULL) == VIREO_OK && i.turn_count == 0);
    responses(&f, 0, 2, 1);
    end(&f, 1);
}
static void removal(void) {
    ++groups;
    fixture_t f;
    start(&f, AF_UNIX, 4);
    for (size_t k = 0; k < 4; ++k)
        schedule(&f, k);
    CHECK(state(&f).pending_clients == 4);
    f.detach_io = true;
    vireo_connection_pool_lease_t const old = f.clients[1];
    CHECK(vireo_tcp_server_release_client(f.server, &f.clients[1], NULL) == VIREO_RESULT_IO &&
          same(old, f.clients[1]) && state(&f).pending_clients == 4);
    f.detach_io = false;
    f.release_busy = true;
    CHECK(vireo_tcp_server_release_client(f.server, &f.clients[1], NULL) == VIREO_RESULT_BUSY &&
          state(&f).pending_clients == 4 && client(&f, 1).queued &&
          !client(&f, 1).connection_info.loop_attached);
    f.release_busy = false;
    CHECK(vireo_tcp_server_release_client(f.server, &f.clients[1], NULL) == VIREO_OK &&
          state(&f).pending_clients == 3);
    f.release_io = true;
    CHECK(vireo_tcp_server_release_client(f.server, &f.clients[0], NULL) == VIREO_RESULT_IO &&
          empty(f.clients[0]) && state(&f).pending_clients == 2);
    f.release_io = false;
    CHECK(vireo_tcp_server_release_client(f.server, &f.clients[3], NULL) == VIREO_OK &&
          state(&f).pending_clients == 1);
    CHECK(vireo_tcp_server_schedule_client(f.server, old, NULL) == VIREO_RESULT_NOT_FOUND);
    vireo_tcp_server_turn_result_t t[4];
    vireo_tcp_server_round_info_t i;
    CHECK(round_at(&f, -1, all_clients, 4, t, &i, NULL) == VIREO_OK && i.turn_count == 1 &&
          same(t[0].client, f.clients[2]) && i.remaining_count == 0);
    end(&f, 4);
}
static void reuse(void) {
    ++groups;
    fixture_t f;
    start(&f, AF_UNIX, 1);
    schedule(&f, 0);
    vireo_connection_pool_lease_t const old = f.clients[0];
    REQUIRE(vireo_tcp_server_release_client(f.server, &f.clients[0], NULL) == VIREO_OK);
    REQUIRE(close(f.peers[0]) == 0);
    f.peers[0] = connect_peer(&f);
    vireo_tcp_server_admit_budget_t const b = {1, 1};
    vireo_tcp_server_admit_info_t a;
    REQUIRE(vireo_tcp_server_admit_batch(f.server, &conn_options, &b, f.clients, 1, &a, NULL) ==
                VIREO_OK &&
            a.admitted_count == 1);
    CHECK(old.slot_index == f.clients[0].slot_index && old.generation != f.clients[0].generation &&
          !client(&f, 0).queued && state(&f).pending_clients == 0);
    CHECK(vireo_tcp_server_schedule_client(f.server, old, NULL) == VIREO_RESULT_NOT_FOUND);
    end(&f, 1);
}
static void probe(fixture_t *f, bool in_handler) {
    vireo_tcp_server_info_t const before = state(f);
    CHECK(before.scheduling_active && before.driving_active == in_handler &&
          before.processing_active == in_handler);
    vireo_connection_receive_info_t ri;
    vireo_connection_send_info_t si;
    vireo_tcp_server_process_info_t pi;
    vireo_tcp_server_drive_info_t di;
    vireo_tcp_server_round_info_t round_info;
    vireo_tcp_server_turn_result_t t[4];
    uint8_t w[96], data[1] = {0};
    vireo_connection_pool_lease_t lease = f->clients[0];
    vireo_connection_frame_view_t v;
    vireo_connection_frame_info_t fi;
    vireo_connection_frame_options_t const fo = {VIREO_CONNECTION_FRAME_REQUEST, 96};
    vireo_connection_frame_budget_t const fb = {1, 96};
    vireo_tcp_server_admit_info_t ai;
    vireo_connection_pool_lease_t out = {0};
#define BUSY(call) CHECK((call) == VIREO_RESULT_BUSY)
    BUSY(vireo_tcp_server_destroy(&f->server, NULL));
    BUSY(vireo_tcp_server_bind_listener(f->server, true, NULL));
    BUSY(vireo_tcp_server_unbind_listener(f->server, NULL));
    BUSY(vireo_tcp_server_set_listener_read_enabled(f->server, false, NULL));
    BUSY(vireo_tcp_server_admit_batch(
        f->server, &conn_options, &(vireo_tcp_server_admit_budget_t){1, 1}, &out, 1, &ai, NULL));
    BUSY(vireo_tcp_server_release_client(f->server, &lease, NULL));
    BUSY(vireo_tcp_server_client_receive(f->server, lease, &allowance.receive, &ri, NULL));
    BUSY(vireo_tcp_server_client_read_consume(f->server, lease, 0, NULL));
    BUSY(vireo_tcp_server_client_write_enqueue(f->server, lease, data, 1, NULL));
    BUSY(vireo_tcp_server_client_send(f->server, lease, &allowance.send, &si, NULL));
    /* 原 framing 是只读观察；在途允许，不能为了错误测试预期收紧旧合同。 */
    CHECK(vireo_tcp_server_client_frames_peek(f->server, lease, &fo, &fb, &v, 1, &fi, NULL) ==
          VIREO_OK);
    BUSY(vireo_tcp_server_client_process(f->server, lease, &limits, &allowance.process, w, 96,
                                         handler, f, &pi, NULL));
    BUSY(vireo_tcp_server_client_drive(f->server, lease, &limits, &allowance, w, 96, handler, f,
                                       &di, NULL));
    BUSY(vireo_tcp_server_schedule_client(f->server, lease, NULL));
    BUSY(vireo_tcp_server_run_once(f->server, 0, &limits, &allowance, &all_clients, w, 96, handler,
                                   f, t, 4, &round_info, NULL));
    BUSY(vireo_tcp_server_client_set_interests(f->server, lease, 0, NULL));
    BUSY(vireo_tcp_server_client_flow_configure(f->server, lease, &flow, NULL));
    BUSY(vireo_tcp_server_client_flow_refresh(f->server, lease, NULL));
    BUSY(vireo_tcp_server_client_flow_disable(f->server, lease, NULL));
    BUSY(vireo_tcp_server_client_request_close(f->server, lease,
                                               VIREO_CONNECTION_CLOSE_MODE_IMMEDIATE,
                                               VIREO_CONNECTION_CLOSE_REASON_APPLICATION, NULL));
    BUSY(vireo_tcp_server_client_close_refresh(f->server, lease, NULL));
#undef BUSY
    uint8_t const *p;
    size_t n;
    CHECK(vireo_tcp_server_client_read_peek(f->server, lease, &p, &n, NULL) == VIREO_OK);
    CHECK(state(f).pending_clients == before.pending_clients &&
          client(f, 0).connection_info.loop_attached);
}
static void reentry(void) {
    ++groups;
    fixture_t f, inner;
    start(&f, AF_UNIX, 1);
    start(&inner, AF_UNIX, 1);
    feed(&f, 0, 1, 1);
    feed(&inner, 0, 1, 2);
    schedule(&f, 0);
    schedule(&inner, 0);
    f.probe_wait = true;
    f.probe_handler = true;
    f.nested = &inner;
    vireo_tcp_server_turn_result_t t[4];
    vireo_tcp_server_round_info_t i;
    CHECK(round_at(&f, -1, all_clients, 4, t, &i, NULL) == VIREO_OK && i.turn_count == 1 &&
          f.nested == NULL);
    CHECK(!state(&f).scheduling_active && !state(&f).driving_active &&
          !state(&f).processing_active);
    responses(&f, 0, 1, 1);
    responses(&inner, 0, 1, 2);
    end(&f, 1);
    end(&inner, 1);
}
static void listener_only(void) {
    ++groups;
    fixture_t f;
    start(&f, AF_INET, 0);
    REQUIRE(vireo_tcp_server_bind_listener(f.server, true, NULL) == VIREO_OK);
    int const peer = connect_peer(&f);
    vireo_tcp_server_turn_result_t t[4];
    vireo_tcp_server_round_info_t i;
    CHECK(round_at(&f, -1, all_clients, 4, t, &i, NULL) == VIREO_OK && i.turn_count == 0 &&
          i.wait.dispatched_count == 1 && state(&f).connection_count == 0 &&
          (state(&f).listener_last_events & VIREO_EPOLL_EVENT_READ) != 0);
    REQUIRE(close(peer) == 0);
    end(&f, 0);
}
static void closing(void) {
    ++groups;
    fixture_t f;
    start(&f, AF_UNIX, 1);
    uint8_t p[100];
    memset(p, 11, sizeof(p));
    REQUIRE(vireo_tcp_server_client_write_enqueue(f.server, f.clients[0], p, sizeof(p), NULL) ==
            VIREO_OK);
    REQUIRE(vireo_tcp_server_client_request_close(
                f.server, f.clients[0], VIREO_CONNECTION_CLOSE_MODE_DRAIN,
                VIREO_CONNECTION_CLOSE_REASON_APPLICATION, NULL) == VIREO_OK);
    schedule(&f, 0);
    vireo_tcp_server_turn_result_t t[4];
    vireo_tcp_server_round_info_t i;
    CHECK(round_at(&f, 0, all_clients, 4, t, &i, NULL) == VIREO_OK && i.turn_count == 1 &&
          t[0].info.ready_to_release && !t[0].info.receive_called && !t[0].info.process_called &&
          t[0].info.send.sent_bytes == 100);
    CHECK(state(&f).connection_count == 1 && state(&f).buffer_capacity_bytes == 384 &&
          state(&f).pending_clients == 0);
    schedule(&f, 0);
    CHECK(round_at(&f, 0, all_clients, 4, t, &i, NULL) == VIREO_OK && i.turn_count == 1 &&
          t[0].info.ready_to_release && !t[0].info.send_called);
    end(&f, 1);
}
/* 已有缓存也每轮 poll0，真实新 READ 不被缓存轮转挡住。 */
static void pending_native(void) {
    ++groups;
    fixture_t f;
    start(&f, AF_UNIX, 2);
    feed(&f, 0, 7, 1);
    schedule(&f, 0);
    uint8_t p[32];
    request(p, 99);
    transmit(&f, 1, p, 32);
    vireo_tcp_server_turn_result_t t[4];
    vireo_tcp_server_round_info_t i;
    CHECK(round_at(&f, -1, (vireo_tcp_server_round_budget_t){1}, 4, t, &i, NULL) == VIREO_OK);
    CHECK(i.queued_before_wait == 1 && i.queued_after_wait == 2 && i.turn_count == 1 &&
          same(t[0].client, f.clients[0]) && i.remaining_count == 2 && i.effective_timeout_ms == 0);
    CHECK(round_at(&f, -1, (vireo_tcp_server_round_budget_t){1}, 4, t, &i, NULL) == VIREO_OK);
    CHECK(i.turn_count == 1 && same(t[0].client, f.clients[1]) &&
          (t[0].events & VIREO_EPOLL_EVENT_READ) != 0 && t[0].info.receive.received_bytes == 32);
    CHECK(f.handler_calls == 3 && f.sequences[2] == 99 && i.remaining_count == 1);
    responses(&f, 0, 2, 1);
    responses(&f, 1, 1, 99);
    end(&f, 2);
}

/* own wrapper 留存的 raw fd 只用于人工测试调小发送缓冲，不作为应用借用接口。 */
static void slow_writer(void) {
    ++groups;
    fixture_t f;
    start(&f, AF_UNIX, 1);
    feed(&f, 0, 1, 1);
    int const small = 4096;
    REQUIRE(setsockopt(f.raw_fds[0], SOL_SOCKET, SO_SNDBUF, &small, (socklen_t)sizeof(small)) == 0);
    uint8_t junk[128];
    memset(junk, 7, sizeof(junk));
    bool blocked = false;
    for (unsigned k = 0; k < 10000; ++k) {
        REQUIRE(vireo_tcp_server_client_write_enqueue(f.server, f.clients[0], junk, sizeof(junk),
                                                      NULL) == VIREO_OK);
        vireo_connection_send_info_t sent;
        REQUIRE(vireo_tcp_server_client_send(f.server, f.clients[0], &allowance.send, &sent,
                                             NULL) == VIREO_OK);
        if (sent.stop_reason == VIREO_CONNECTION_SEND_STOP_WOULD_BLOCK) {
            blocked = true;
            break;
        }
        REQUIRE(sent.sent_bytes == sizeof(junk));
    }
    REQUIRE(blocked);
    REQUIRE(vireo_tcp_server_client_flow_refresh(f.server, f.clients[0], NULL) == VIREO_OK);
    schedule(&f, 0);
    vireo_tcp_server_turn_result_t t[4];
    vireo_tcp_server_round_info_t i;
    CHECK(round_at(&f, 0, all_clients, 4, t, &i, NULL) == VIREO_OK && i.turn_count == 1 &&
          t[0].info.send.stop_reason == VIREO_CONNECTION_SEND_STOP_WOULD_BLOCK &&
          !t[0].info.needs_processing && i.remaining_count == 0 && f.handler_calls == 0);
    CHECK(round_at(&f, 0, all_clients, 4, t, &i, NULL) == VIREO_OK && i.turn_count == 0);
    uint8_t drain[4096];
    ssize_t n;
    while ((n = recv(f.peers[0], drain, sizeof(drain), MSG_DONTWAIT)) > 0) {
    }
    REQUIRE(n == -1 && (errno == EAGAIN || errno == EWOULDBLOCK));
    CHECK(round_at(&f, -1, all_clients, 4, t, &i, NULL) == VIREO_OK && i.turn_count == 1 &&
          (t[0].events & VIREO_EPOLL_EVENT_WRITE) != 0 && t[0].info.needs_processing &&
          i.remaining_count == 1);
    while ((n = recv(f.peers[0], drain, sizeof(drain), MSG_DONTWAIT)) > 0) {
    }
    REQUIRE(n == -1 && (errno == EAGAIN || errno == EWOULDBLOCK));
    CHECK(round_at(&f, -1, all_clients, 4, t, &i, NULL) == VIREO_OK && i.turn_count == 1 &&
          t[0].info.process.consumed_requests == 1 && f.handler_calls == 1 &&
          i.remaining_count == 0);
    responses(&f, 0, 1, 1);
    end(&f, 1);
}

static void exact_budget(void) {
    ++groups;
    vireo_tcp_server_t *s = NULL;
    vireo_tcp_server_options_t o = server_options;
    vireo_tcp_server_info_t i;
    REQUIRE(vireo_tcp_server_create(&o, &s, NULL) == VIREO_OK &&
            vireo_tcp_server_inspect(s, &i) == VIREO_OK);
    CHECK(i.pending_clients == 0 && !i.scheduling_active);
    size_t const total = i.allocation_bytes;
    REQUIRE(vireo_tcp_server_destroy(&s, NULL) == VIREO_OK);
    o.max_memory_bytes = total;
    CHECK(vireo_tcp_server_create(&o, &s, NULL) == VIREO_OK);
    REQUIRE(vireo_tcp_server_destroy(&s, NULL) == VIREO_OK);
    o.max_memory_bytes = total - 1;
    CHECK(vireo_tcp_server_create(&o, &s, NULL) == VIREO_RESULT_RANGE && s == NULL);
    o = (vireo_tcp_server_options_t){65535, 1, 67108864, 67108864};
    CHECK(vireo_tcp_server_create(&o, &s, NULL) == VIREO_OK);
    REQUIRE(vireo_tcp_server_inspect(s, &i) == VIREO_OK);
    CHECK(i.connection_capacity == 65535 && i.pending_clients == 0 &&
          i.available_connections == 65535);
    REQUIRE(vireo_tcp_server_destroy(&s, NULL) == VIREO_OK);
    vireo_tcp_server_scheduler_ops_t const incomplete = {0};
    CHECK(vireo_tcp_server_create_with_scheduler_ops(&server_options, NULL, NULL, NULL, NULL, &s,
                                                     NULL) == VIREO_RESULT_INVALID_ARGUMENT &&
          s == NULL);
    CHECK(vireo_tcp_server_create_with_scheduler_ops(&server_options, NULL, NULL, NULL, &incomplete,
                                                     &s, NULL) == VIREO_RESULT_INVALID_ARGUMENT &&
          s == NULL);
}
int main(void) {
    unsigned const before = fd_count();
    parameters();
    fairness(AF_INET);
    fairness(AF_UNIX);
    caps_and_once();
    native_events();
    merge_events();
    waits();
    failure_prefix();
    client_rejection();
    half_frames();
    removal();
    reuse();
    reentry();
    listener_only();
    closing();
    pending_native();
    slow_writer();
    exact_budget();
    unsigned const after = fd_count();
    CHECK(before == after);
    printf("test_tcp_server_scheduling: %u groups, %u failures, fd %u -> %u\n", groups, failures,
           before, after);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
