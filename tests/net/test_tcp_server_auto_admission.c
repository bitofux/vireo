/*
- PROJECT : VIREO
- FILE    : test_tcp_server_auto_admission.c
- AUTHOR  : bitofux
- DATE    : 2026-10-06
- BRIEF   : 此模块负责：
- -- 真实 TCP/Unix 自动准入、容量压力与预算/失败前缀
- -- 初始化owned失败、整次在途与实际资源预算
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
static vireo_tcp_server_options_t server_options = {4, 8, 1048576, 16384};
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
    unsigned mod_calls, flow_calls, accept_calls_total, create_calls, attach_calls, raw_closes;
    unsigned fail_mod_on, fail_flow_on, fail_accept_on, fail_create_on, fail_attach_on;
    bool probe_mod, probe_flow, probe_accept;
    uint32_t listener_injected_events;
    vireo_acceptor_t *listener_object;
    vireo_acceptor_callback_t listener_callback;
    void *listener_context;
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
    if (f->listener_injected_events) {
        f->listener_callback(f->listener_object, f->listener_injected_events, f->listener_context);
        f->listener_injected_events = 0;
    }
    vireo_result_t const r = vireo_event_loop_run_once(loop, timeout, info, error);
    errno = ERANGE;
    return r;
}
static vireo_result_t create_client(void *ctx, vireo_connection_options_t const *o, int *fd,
                                    vireo_connection_t **owner, vireo_connection_error_t *error) {
    fixture_t *f = ctx;
    ++f->create_calls;
    if (f->fail_create_on == f->create_calls) {
        *error = (vireo_connection_error_t){VIREO_CONNECTION_STAGE_ALLOCATE_CONTROL, 0};
        return VIREO_RESULT_NO_MEMORY;
    }
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
    ++f->attach_calls;
    if (f->fail_attach_on == f->attach_calls) {
        *error = (vireo_connection_loop_error_t){
            .stage = VIREO_CONNECTION_LOOP_STAGE_ATTACH,
            .loop_error = {.stage = VIREO_EVENT_LOOP_STAGE_ADD,
                           .epoll_error = {VIREO_EPOLL_STAGE_ADD, ENOMEM}}};
        return VIREO_RESULT_IO;
    }
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
    fixture_t *f = ctx;
    ++f->accept_calls_total;
    if (f->probe_accept)
        probe(f, false);
    if (f->fail_accept_on == f->accept_calls_total) {
        *i = (vireo_acceptor_accept_info_t){.accept_calls = 1,
                                            .stop_reason = VIREO_ACCEPTOR_ACCEPT_IO_ERROR};
        *e = (vireo_acceptor_error_t){VIREO_ACCEPTOR_STAGE_ACCEPT_CLIENT, EINTR};
        return VIREO_RESULT_IO;
    }
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
    fixture_t *f = ctx;
    ++f->flow_calls;
    if (f->probe_flow)
        probe(f, false);
    if (f->fail_flow_on == f->flow_calls) {
        *e = (vireo_connection_loop_error_t){
            .stage = VIREO_CONNECTION_LOOP_STAGE_FLOW_CONFIGURE,
            .loop_error = {.stage = VIREO_EVENT_LOOP_STAGE_MOD,
                           .epoll_error = {VIREO_EPOLL_STAGE_MOD, EBADF}}};
        return VIREO_RESULT_IO;
    }
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
    ++((fixture_t *)ctx)->raw_closes;
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
        int const n = snprintf(a.sun_path + 1, sizeof(a.sun_path) - 1,
                               "vireo-auto-admission-%ld-%u", (long)getpid(), ++serial);
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
static vireo_result_t listener_inspect(void *ctx, vireo_acceptor_t const *a,
                                       vireo_acceptor_info_t *i) {
    (void)ctx;
    return vireo_acceptor_inspect(a, i);
}
static vireo_result_t listener_attach(void *ctx, vireo_acceptor_t *a, vireo_event_loop_t *l,
                                      bool enabled, vireo_acceptor_callback_t cb, void *cbctx,
                                      vireo_acceptor_loop_error_t *e) {
    fixture_t *f = ctx;
    vireo_result_t const result = vireo_acceptor_attach(a, l, enabled, cb, cbctx, e);
    if (result == VIREO_OK) {
        f->listener_object = a;
        f->listener_callback = cb;
        f->listener_context = cbctx;
    }
    return result;
}
static vireo_result_t listener_read(void *ctx, vireo_acceptor_t *a, bool enabled,
                                    vireo_acceptor_loop_error_t *e) {
    fixture_t *f = ctx;
    ++f->mod_calls;
    if (f->probe_mod)
        probe(f, false);
    if (f->mod_calls == f->fail_mod_on) {
        *e = (vireo_acceptor_loop_error_t){
            .stage = VIREO_ACCEPTOR_LOOP_STAGE_UPDATE,
            .loop_error = {.stage = VIREO_EVENT_LOOP_STAGE_MOD,
                           .epoll_error = {VIREO_EPOLL_STAGE_MOD, EBADF}}};
        return VIREO_RESULT_IO;
    }
    return vireo_acceptor_set_read_enabled(a, enabled, e);
}
static vireo_result_t listener_detach(void *ctx, vireo_acceptor_t *a,
                                      vireo_acceptor_loop_error_t *e) {
    (void)ctx;
    return vireo_acceptor_detach(a, e);
}
static vireo_result_t listener_forget(void *ctx, vireo_acceptor_t *a) {
    (void)ctx;
    return vireo_acceptor_forget_destroyed_loop(a, NULL);
}
static vireo_result_t listener_destroy(void *ctx, vireo_acceptor_t **a, vireo_acceptor_error_t *e) {
    (void)ctx;
    return vireo_acceptor_destroy(a, e);
}
static vireo_tcp_server_listener_ops_t listener_ops(fixture_t *f) {
    return (vireo_tcp_server_listener_ops_t){f,
                                             listener_inspect,
                                             listener_attach,
                                             listener_read,
                                             listener_detach,
                                             listener_forget,
                                             listener_destroy};
}
static void start(fixture_t *f, int family, size_t count) {
    *f = (fixture_t){0};
    vireo_tcp_server_client_ops_t const c = ops(f);
    vireo_tcp_server_scheduler_ops_t const w = {f, wait_once};
    vireo_tcp_server_listener_ops_t const l = listener_ops(f);
    REQUIRE(vireo_tcp_server_create_with_scheduler_ops(&server_options, NULL, &l, &c, &w,
                                                       &f->server, NULL) == VIREO_OK);
    int fd = listener(f, family);
    vireo_acceptor_t *a = NULL;
    vireo_acceptor_options_t const o = {4096};
    REQUIRE(vireo_acceptor_create(&o, &fd, &a, NULL) == VIREO_OK);
    REQUIRE(vireo_tcp_server_adopt_listener(f->server, &a, NULL) == VIREO_OK && a == NULL);
    REQUIRE(vireo_tcp_server_bind_listener(f->server, true, NULL) == VIREO_OK);
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
    server_options = (vireo_tcp_server_options_t){4, 8, 1048576, 16384};
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

static vireo_tcp_server_admission_options_t const policy = {{256, 128, 384}, {96, 95, 192, 32, 96}};
static vireo_tcp_server_serve_options_t defaults(void) {
    return (vireo_tcp_server_serve_options_t){0, limits, allowance, all_clients, {4, 16}};
}
static void enable(fixture_t *f) {
    errno = EDOM;
    REQUIRE(vireo_tcp_server_admission_configure(f->server, &policy, NULL) == VIREO_OK);
    CHECK(errno == EDOM && state(f).admission_enabled && state(f).admission_pair_bytes == 384);
}
static vireo_result_t serve(fixture_t *f, vireo_tcp_server_serve_options_t o,
                            vireo_tcp_server_turn_result_t *t, size_t tn,
                            vireo_connection_pool_lease_t *c, size_t cn,
                            vireo_tcp_server_serve_info_t *i, vireo_tcp_server_serve_error_t *e) {
    uint8_t w[96];
    errno = EDOM;
    vireo_result_t const result =
        vireo_tcp_server_serve_once(f->server, &o, w, sizeof(w), handler, f, t, tn, c, cn, i, e);
    CHECK(errno == EDOM && !state(f).serving_active && !state(f).scheduling_active &&
          !state(f).processing_active && !state(f).driving_active);
    return result;
}
static void probe(fixture_t *f, bool in_handler) {
    vireo_tcp_server_info_t const before = state(f);
    CHECK(before.serving_active && before.processing_active == in_handler &&
          before.driving_active == in_handler);
    vireo_tcp_server_serve_options_t o = defaults();
    uint8_t w[96], data = 0;
    vireo_tcp_server_turn_result_t t[4];
    vireo_tcp_server_serve_info_t si;
    vireo_tcp_server_round_info_t ri;
    vireo_tcp_server_drive_info_t di;
    vireo_tcp_server_process_info_t pi;
    vireo_connection_receive_info_t recv;
    vireo_connection_send_info_t sent;
    vireo_connection_pool_lease_t c[4] = {{0}}, lease = f->clients[0];
    vireo_tcp_server_admit_info_t ai;
    uint8_t const *bytes;
    size_t n;
#define BUSY(call) CHECK((call) == VIREO_RESULT_BUSY)
    BUSY(vireo_tcp_server_destroy(&f->server, NULL));
    BUSY(vireo_tcp_server_admission_configure(f->server, &policy, NULL));
    BUSY(vireo_tcp_server_admission_refresh(f->server, NULL));
    BUSY(vireo_tcp_server_admission_disable(f->server, NULL));
    BUSY(vireo_tcp_server_bind_listener(f->server, true, NULL));
    BUSY(vireo_tcp_server_unbind_listener(f->server, NULL));
    BUSY(vireo_tcp_server_set_listener_read_enabled(f->server, false, NULL));
    BUSY(vireo_tcp_server_admit_batch(f->server, &conn_options, &o.admit, c, 4, &ai, NULL));
    BUSY(vireo_tcp_server_release_client(f->server, &lease, NULL));
    BUSY(vireo_tcp_server_client_receive(f->server, lease, &allowance.receive, &recv, NULL));
    BUSY(vireo_tcp_server_client_read_consume(f->server, lease, 0, NULL));
    BUSY(vireo_tcp_server_client_write_enqueue(f->server, lease, &data, 1, NULL));
    BUSY(vireo_tcp_server_client_send(f->server, lease, &allowance.send, &sent, NULL));
    BUSY(vireo_tcp_server_client_process(f->server, lease, &limits, &allowance.process, w, 96,
                                         handler, f, &pi, NULL));
    BUSY(vireo_tcp_server_client_drive(f->server, lease, &limits, &allowance, w, 96, handler, f,
                                       &di, NULL));
    BUSY(vireo_tcp_server_schedule_client(f->server, lease, NULL));
    BUSY(vireo_tcp_server_run_once(f->server, 0, &limits, &allowance, &all_clients, w, 96, handler,
                                   f, t, 4, &ri, NULL));
    BUSY(vireo_tcp_server_serve_once(f->server, &o, w, 96, handler, f, t, 4, c, 4, &si, NULL));
    BUSY(vireo_tcp_server_client_set_interests(f->server, lease, 0, NULL));
    BUSY(vireo_tcp_server_client_flow_configure(f->server, lease, &flow, NULL));
    BUSY(vireo_tcp_server_client_flow_refresh(f->server, lease, NULL));
    BUSY(vireo_tcp_server_client_flow_disable(f->server, lease, NULL));
    BUSY(vireo_tcp_server_client_request_close(f->server, lease,
                                               VIREO_CONNECTION_CLOSE_MODE_IMMEDIATE,
                                               VIREO_CONNECTION_CLOSE_REASON_APPLICATION, NULL));
    BUSY(vireo_tcp_server_client_close_refresh(f->server, lease, NULL));
#undef BUSY
    /* 观察允许；新准入期间可能尚无客户，因此只在存在当前lease时查看。 */
    if (!empty(lease)) {
        CHECK(vireo_tcp_server_client_read_peek(f->server, lease, &bytes, &n, NULL) == VIREO_OK);
        vireo_connection_frame_view_t v;
        vireo_connection_frame_info_t fi;
        vireo_connection_frame_options_t const fo = {VIREO_CONNECTION_FRAME_REQUEST, 96};
        vireo_connection_frame_budget_t const fb = {1, 96};
        CHECK(vireo_tcp_server_client_frames_peek(f->server, lease, &fo, &fb, &v, 1, &fi, NULL) ==
              VIREO_OK);
    }
    CHECK(state(f).connection_count == before.connection_count &&
          state(f).pending_clients == before.pending_clients);
}
static void config(void) {
    ++groups;
    fixture_t f;
    start(&f, AF_UNIX, 0);
    CHECK(vireo_tcp_server_admission_refresh(f.server, NULL) == VIREO_RESULT_NOT_FOUND);
    vireo_tcp_server_admission_options_t bad[12];
    for (size_t k = 0; k < 12; ++k)
        bad[k] = policy;
    bad[0].connection.read_capacity = 31;
    bad[1].connection.write_capacity = 31;
    bad[2].connection.max_buffer_bytes = 383;
    bad[3].connection.max_buffer_bytes = 0;
    bad[4].flow.max_frame_bytes = 31;
    bad[5].flow.max_frame_bytes = 257;
    bad[6].flow.read_low = 94;
    bad[7].flow.read_high = 95;
    bad[8].flow.read_high = 257;
    bad[9].flow.write_low = 96;
    bad[10].flow.write_high = 129;
    bad[11].flow.write_high = 0;
    for (size_t k = 0; k < 12; ++k) {
        errno = EDOM;
        CHECK(vireo_tcp_server_admission_configure(f.server, &bad[k], NULL) == VIREO_RESULT_RANGE);
        CHECK(errno == EDOM && !state(&f).admission_enabled && f.mod_calls == 0);
    }
    bad[0] = policy;
    bad[0].connection.read_capacity = SIZE_MAX;
    CHECK(vireo_tcp_server_admission_configure(f.server, &bad[0], NULL) == VIREO_RESULT_OVERFLOW);
    CHECK(vireo_tcp_server_admission_configure(f.server, NULL, NULL) ==
          VIREO_RESULT_INVALID_ARGUMENT);
    REQUIRE(vireo_tcp_server_unbind_listener(f.server, NULL) == VIREO_OK);
    CHECK(vireo_tcp_server_admission_configure(f.server, &policy, NULL) == VIREO_RESULT_NOT_FOUND);
    REQUIRE(vireo_tcp_server_bind_listener(f.server, false, NULL) == VIREO_OK);
    f.fail_mod_on = 1;
    vireo_tcp_server_listener_error_t err;
    CHECK(vireo_tcp_server_admission_configure(f.server, &policy, &err) == VIREO_RESULT_IO);
    CHECK(!state(&f).admission_enabled && !state(&f).listener_read_enabled &&
          err.acceptor_error.loop_error.epoll_error.system_errno == EBADF);
    f.fail_mod_on = 0;
    enable(&f);
    CHECK(f.mod_calls == 2);
    REQUIRE(vireo_tcp_server_admission_refresh(f.server, NULL) == VIREO_OK);
    CHECK(f.mod_calls == 2);
    vireo_tcp_server_admission_options_t copy = policy;
    REQUIRE(vireo_tcp_server_admission_configure(f.server, &copy, NULL) == VIREO_OK);
    copy.connection.read_capacity = 32;
    CHECK(state(&f).admission_connection_options.read_capacity == 256 && f.mod_calls == 2);
    CHECK(vireo_tcp_server_set_listener_read_enabled(f.server, false, NULL) == VIREO_RESULT_BUSY);
    REQUIRE(vireo_tcp_server_unbind_listener(f.server, NULL) == VIREO_OK);
    CHECK(!state(&f).admission_enabled && state(&f).admission_pair_bytes == 0);
    REQUIRE(vireo_tcp_server_admission_disable(f.server, NULL) == VIREO_OK);
    REQUIRE(vireo_tcp_server_bind_listener(f.server, false, NULL) == VIREO_OK);
    enable(&f);
    REQUIRE(vireo_tcp_server_admission_disable(f.server, NULL) == VIREO_OK);
    CHECK(state(&f).listener_read_enabled && !state(&f).admission_enabled);
    end(&f, 0);
}
static void automatic(int family) {
    ++groups;
    fixture_t f;
    start(&f, family, 0);
    enable(&f);
    f.peers[0] = connect_peer(&f);
    f.peers[1] = connect_peer(&f);
    uint8_t wire[32];
    request(wire, 10);
    transmit(&f, 0, wire, 32);
    request(wire, 20);
    transmit(&f, 1, wire, 32);
    vireo_tcp_server_turn_result_t t[4];
    vireo_connection_pool_lease_t c[4] = {{0}};
    vireo_tcp_server_serve_info_t i;
    vireo_tcp_server_serve_error_t e;
    vireo_tcp_server_serve_options_t o = defaults();
    o.timeout_ms = -1;
    CHECK(serve(&f, o, t, 4, c, 4, &i, &e) == VIREO_OK);
    CHECK(i.round.turn_count == 0 && i.admission_called && i.admission.admitted_count == 2 &&
          i.initialized_count == 2 && i.admission.accepted_count == 2 &&
          i.admission.accept_calls == 3 &&
          i.admission.stop_reason == VIREO_TCP_SERVER_ADMIT_WOULD_BLOCK && f.wait_calls == 1);
    f.clients[0] = c[0];
    f.clients[1] = c[1];
    CHECK(client(&f, 0).connection_info.flow_enabled && client(&f, 1).connection_info.flow_enabled);
    memset(c, 0, sizeof(c));
    o.timeout_ms = 0;
    CHECK(serve(&f, o, t, 4, c, 4, &i, NULL) == VIREO_OK && i.round.turn_count == 2 &&
          !i.admission_called && f.wait_calls == 2);
    responses(&f, 0, 1, 10);
    responses(&f, 1, 1, 20);
    CHECK(f.handler_calls == 2 && f.mod_calls == 0);
    end(&f, 2);
}
static void capacity(void) {
    ++groups;
    server_options.connection_capacity = 2;
    fixture_t f;
    start(&f, AF_UNIX, 2);
    enable(&f);
    CHECK(!state(&f).listener_read_enabled && state(&f).admission_connection_limited &&
          f.mod_calls == 1);
    int third = connect_peer(&f);
    vireo_connection_pool_lease_t c[4] = {{0}};
    vireo_tcp_server_turn_result_t t[4];
    vireo_tcp_server_serve_info_t i;
    CHECK(serve(&f, defaults(), t, 4, c, 4, &i, NULL) == VIREO_OK && !i.admission_called &&
          i.admission.accept_calls == 0);
    REQUIRE(vireo_tcp_server_client_read_consume(f.server, f.clients[0], 0, NULL) == VIREO_OK);
    CHECK(!state(&f).listener_read_enabled && state(&f).buffer_capacity_bytes == 768);
    REQUIRE(vireo_tcp_server_release_client(f.server, &f.clients[0], NULL) == VIREO_OK);
    CHECK(!state(&f).listener_read_enabled && f.mod_calls == 1);
    REQUIRE(close(f.peers[0]) == 0);
    f.peers[0] = third;
    CHECK(serve(&f, defaults(), t, 4, c, 4, &i, NULL) == VIREO_OK &&
          i.admission.admitted_count == 1 && i.initialized_count == 1);
    f.clients[0] = c[0];
    CHECK(!i.listener_read_enabled && f.mod_calls == 3);
    end(&f, 2);
}
static void buffer_limit(void) {
    ++groups;
    server_options.max_buffer_bytes = 1000;
    fixture_t f;
    start(&f, AF_UNIX, 2);
    enable(&f);
    CHECK(state(&f).admission_buffer_limited && !state(&f).admission_connection_limited &&
          !state(&f).listener_read_enabled);
    feed(&f, 0, 1, 1);
    REQUIRE(vireo_tcp_server_client_read_consume(f.server, f.clients[0], 32, NULL) == VIREO_OK);
    REQUIRE(vireo_tcp_server_admission_refresh(f.server, NULL) == VIREO_OK);
    CHECK(state(&f).admission_buffer_limited && !state(&f).listener_read_enabled);
    vireo_connection_pool_lease_t old = f.clients[0];
    f.release_io = true;
    CHECK(vireo_tcp_server_release_client(f.server, &f.clients[0], NULL) == VIREO_RESULT_IO &&
          empty(f.clients[0]));
    CHECK(!state(&f).listener_read_enabled && state(&f).buffer_capacity_bytes == 384);
    REQUIRE(vireo_tcp_server_admission_refresh(f.server, NULL) == VIREO_OK);
    CHECK(state(&f).listener_read_enabled);
    CHECK(vireo_tcp_server_schedule_client(f.server, old, NULL) == VIREO_RESULT_NOT_FOUND);
    f.release_io = false;
    end(&f, 2);
}
static void reconfiguration(void) {
    ++groups;
    server_options.max_buffer_bytes = 1000;
    fixture_t f;
    start(&f, AF_UNIX, 1);
    enable(&f);
    vireo_tcp_server_admission_options_t big = policy;
    big.connection.read_capacity = 600;
    big.connection.max_buffer_bytes = 728;
    f.fail_mod_on = 1;
    vireo_tcp_server_listener_error_t e;
    CHECK(vireo_tcp_server_admission_configure(f.server, &big, &e) == VIREO_RESULT_IO &&
          state(&f).admission_pair_bytes == 384 && state(&f).listener_read_enabled);
    f.fail_mod_on = 0;
    REQUIRE(vireo_tcp_server_admission_configure(f.server, &big, NULL) == VIREO_OK);
    CHECK(state(&f).admission_pair_bytes == 728 && !state(&f).listener_read_enabled &&
          client(&f, 0).connection_info.read_buffer.capacity == 256);
    REQUIRE(vireo_tcp_server_admission_disable(f.server, NULL) == VIREO_OK);
    CHECK(!state(&f).listener_read_enabled);
    REQUIRE(vireo_tcp_server_set_listener_read_enabled(f.server, true, NULL) == VIREO_OK);
    end(&f, 1);
}
static void parameters(void) {
    ++groups;
    fixture_t f;
    start(&f, AF_UNIX, 1);
    enable(&f);
    schedule(&f, 0);
    vireo_tcp_server_serve_options_t o = defaults(), bad[14];
    for (size_t k = 0; k < 14; ++k)
        bad[k] = o;
    bad[0].timeout_ms = -2;
    bad[1].admit.max_accepts = 0;
    bad[2].admit.max_accept_syscalls = 0;
    bad[3].admit.max_accepts = 65536;
    bad[4].round.max_clients = 0;
    bad[5].round.max_clients = 65536;
    bad[6].drive.receive.max_bytes = 0;
    bad[7].drive.send.max_syscalls = 0;
    bad[8].drive.process.max_messages = 0;
    bad[9].drive.process.max_request_bytes = 95;
    bad[10].process.max_request_frame_bytes = 97;
    bad[11].process.max_response_frame_bytes = 129;
    bad[12].process.max_request_frame_bytes = 31;
    bad[13].process.max_response_frame_bytes = SIZE_MAX;
    uint8_t w[256], original[256];
    memset(w, 0x43, sizeof(w));
    memcpy(original, w, sizeof(w));
    vireo_tcp_server_turn_result_t t[4], snapshot[4];
    memset(t, 0x53, sizeof(t));
    memcpy(snapshot, t, sizeof(t));
    vireo_tcp_server_serve_info_t i, copy;
    memset(&i, 0x62, sizeof(i));
    memcpy(&copy, &i, sizeof(i));
    vireo_connection_pool_lease_t c[4] = {{0}};
    for (size_t k = 0; k < 14; ++k) {
        errno = EDOM;
        vireo_result_t const result = vireo_tcp_server_serve_once(
            f.server, &bad[k], w, 256, handler, &f, t, 4, c, 4, &i, NULL);
        CHECK(result == (k < 3 ? VIREO_RESULT_INVALID_ARGUMENT : VIREO_RESULT_RANGE));
        CHECK(errno == EDOM && !memcmp(w, original, sizeof(w)) && !memcmp(t, snapshot, sizeof(t)) &&
              !memcmp(&i, &copy, sizeof(i)) && f.wait_calls == 0 && state(&f).pending_clients == 1);
    }
    c[0] = f.clients[0];
    CHECK(vireo_tcp_server_serve_once(f.server, &o, w, 256, handler, &f, t, 4, c, 4, &i, NULL) ==
          VIREO_RESULT_INVALID_ARGUMENT);
    memset(c, 0, sizeof(c));
    CHECK(vireo_tcp_server_serve_once(f.server, &o, w, 256, handler, &f, t, 0, c, 4, &i, NULL) ==
          VIREO_RESULT_RANGE);
    CHECK(vireo_tcp_server_serve_once(f.server, &o, w, 256, handler, &f, t, 4, c, 0, &i, NULL) ==
          VIREO_RESULT_RANGE);
    CHECK(vireo_tcp_server_serve_once(f.server, &o, w, 256, handler, &f, NULL, 4, c, 4, &i, NULL) ==
          VIREO_RESULT_INVALID_ARGUMENT);
    REQUIRE(vireo_tcp_server_admission_disable(f.server, NULL) == VIREO_OK);
    CHECK(vireo_tcp_server_serve_once(f.server, &o, w, 256, handler, &f, t, 4, c, 4, &i, NULL) ==
          VIREO_RESULT_NOT_FOUND);
    end(&f, 1);
}
static void waiting(void) {
    ++groups;
    server_options.connection_capacity = 2;
    fixture_t f;
    start(&f, AF_UNIX, 2);
    enable(&f);
    REQUIRE(vireo_tcp_server_release_client(f.server, &f.clients[0], NULL) == VIREO_OK);
    schedule(&f, 1);
    vireo_tcp_server_turn_result_t t[4], before[4];
    memset(t, 0x42, sizeof(t));
    memcpy(before, t, sizeof(t));
    vireo_connection_pool_lease_t c[4] = {{0}};
    vireo_tcp_server_serve_info_t i, copy;
    memset(&i, 0x52, sizeof(i));
    memcpy(&copy, &i, sizeof(i));
    vireo_tcp_server_serve_error_t e;
    f.fail_mod_on = 2;
    f.probe_mod = true; /* 入口同步期间旧三 active 均 false，仍须拒绝所有同对象修改。 */
    CHECK(serve(&f, defaults(), t, 4, c, 4, &i, &e) == VIREO_RESULT_IO &&
          e.stage == VIREO_TCP_SERVER_SERVE_PRE_SYNC);
    CHECK(f.wait_calls == 0 && !memcmp(t, before, sizeof(t)) && !memcmp(&i, &copy, sizeof(i)) &&
          state(&f).pending_clients == 1);
    f.fail_mod_on = 0;
    f.wait_io = true;
    CHECK(serve(&f, defaults(), t, 4, c, 4, &i, &e) == VIREO_RESULT_IO &&
          e.stage == VIREO_TCP_SERVER_SERVE_ROUND);
    CHECK(e.round_error.loop_error.epoll_error.system_errno == EINTR && f.wait_calls == 1 &&
          state(&f).listener_read_enabled && state(&f).pending_clients == 1 &&
          !memcmp(t, before, sizeof(t)) && !memcmp(&i, &copy, sizeof(i)));
    f.wait_io = false;
    f.probe_mod = false;
    CHECK(serve(&f, defaults(), t, 4, c, 4, &i, NULL) == VIREO_OK && i.round.turn_count == 1 &&
          i.round.effective_timeout_ms == 0);
    end(&f, 2);
}
static void flow_and_post_failure(void) {
    ++groups;
    fixture_t f;
    start(&f, AF_UNIX, 0);
    enable(&f);
    for (size_t k = 0; k < 4; ++k)
        f.peers[k] = connect_peer(&f);
    f.fail_flow_on = 4;
    f.fail_mod_on = 1;
    vireo_tcp_server_turn_result_t t[4];
    vireo_connection_pool_lease_t c[4] = {{0}};
    vireo_tcp_server_serve_info_t i;
    vireo_tcp_server_serve_error_t e;
    CHECK(serve(&f, defaults(), t, 4, c, 4, &i, &e) == VIREO_RESULT_IO &&
          e.stage == VIREO_TCP_SERVER_SERVE_INITIALIZE);
    CHECK(i.admission.admitted_count == 4 && i.admission.rejected_count == 0 &&
          i.initialized_count == 3 && same(e.client, c[3]) &&
          e.client_error.primary.stage == VIREO_TCP_SERVER_CLIENT_FLOW_CONFIGURE &&
          e.sync_result == VIREO_RESULT_IO &&
          e.sync_error.acceptor_error.loop_error.epoll_error.system_errno == EBADF);
    CHECK(state(&f).connection_count == 4 && state(&f).listener_read_enabled &&
          !state(&f).admission_read_desired);
    for (size_t k = 0; k < 4; ++k)
        f.clients[k] = c[k];
    CHECK(!client(&f, 3).connection_info.flow_enabled &&
          client(&f, 3).connection_info.loop_attached);
    f.fail_mod_on = 0;
    REQUIRE(vireo_tcp_server_admission_refresh(f.server, NULL) == VIREO_OK);
    REQUIRE(vireo_tcp_server_client_flow_configure(f.server, f.clients[3], &flow, NULL) ==
            VIREO_OK);
    CHECK(client(&f, 3).connection_info.flow_enabled && !state(&f).listener_read_enabled);
    end(&f, 4);
}
static void post_failure(void) {
    ++groups;
    fixture_t f;
    start(&f, AF_UNIX, 0);
    enable(&f);
    for (size_t k = 0; k < 4; ++k)
        f.peers[k] = connect_peer(&f);
    f.fail_mod_on = 1;
    vireo_tcp_server_turn_result_t t[4];
    vireo_connection_pool_lease_t c[4] = {{0}};
    vireo_tcp_server_serve_info_t i;
    vireo_tcp_server_serve_error_t e;
    CHECK(serve(&f, defaults(), t, 4, c, 4, &i, &e) == VIREO_RESULT_IO &&
          e.stage == VIREO_TCP_SERVER_SERVE_POST_SYNC && e.sync_result == VIREO_OK);
    CHECK(i.admission.admitted_count == 4 && i.initialized_count == 4 && i.sync_called &&
          i.listener_read_enabled);
    for (size_t k = 0; k < 4; ++k)
        f.clients[k] = c[k];
    f.fail_mod_on = 0;
    end(&f, 4);
}
static void setup_failure(unsigned kind) {
    ++groups;
    fixture_t f;
    start(&f, AF_UNIX, 0);
    enable(&f);
    f.peers[0] = connect_peer(&f);
    f.peers[1] = connect_peer(&f);
    if (kind == 0)
        f.fail_accept_on = 2;
    else if (kind == 1)
        f.fail_create_on = 2;
    else
        f.fail_attach_on = 2;
    vireo_tcp_server_turn_result_t t[4];
    vireo_connection_pool_lease_t c[4] = {{0}};
    vireo_tcp_server_serve_info_t i;
    vireo_tcp_server_serve_error_t e;
    CHECK(serve(&f, defaults(), t, 4, c, 4, &i, &e) ==
              (kind == 1 ? VIREO_RESULT_NO_MEMORY : VIREO_RESULT_IO) &&
          e.stage == VIREO_TCP_SERVER_SERVE_ADMIT);
    CHECK(i.admission.admitted_count == 1 && i.initialized_count == 1 &&
          i.admission.accept_calls == 2 && i.admission.rejected_count == (kind == 0 ? 0 : 1) &&
          !empty(c[0]) && empty(c[1]) && i.sync_called && state(&f).connection_count == 1);
    CHECK(e.client_error.primary.stage == (kind == 0   ? VIREO_TCP_SERVER_CLIENT_ACCEPT
                                           : kind == 1 ? VIREO_TCP_SERVER_CLIENT_CREATE
                                                       : VIREO_TCP_SERVER_CLIENT_ATTACH));
    CHECK(f.raw_closes == (kind == 1 ? 1 : 0));
    f.clients[0] = c[0];
    REQUIRE(close(f.peers[1]) == 0);
    end(&f, 1);
}
static void existing_failure(void) {
    ++groups;
    fixture_t f;
    start(&f, AF_UNIX, 2);
    enable(&f);
    feed(&f, 0, 1, 1);
    feed(&f, 1, 1, 9);
    schedule(&f, 0);
    schedule(&f, 1);
    int waiting_peer = connect_peer(&f);
    unsigned const accepts = f.accept_calls_total;
    f.fail_sequence = 9;
    vireo_tcp_server_turn_result_t t[4];
    vireo_connection_pool_lease_t c[4] = {{0}};
    vireo_tcp_server_serve_info_t i;
    vireo_tcp_server_serve_error_t e;
    CHECK(serve(&f, defaults(), t, 4, c, 4, &i, &e) == VIREO_RESULT_IO &&
          e.stage == VIREO_TCP_SERVER_SERVE_ROUND);
    CHECK(i.round.turn_count == 2 && i.round.succeeded_count == 1 && i.round.failed_count == 1 &&
          !i.admission_called && f.accept_calls_total == accepts && empty(c[0]) && i.sync_called);
    CHECK(e.round_error.drive_error.primary_error.primary.handler_result == VIREO_RESULT_IO &&
          e.round_error.drive_error.sync_result == VIREO_RESULT_IO);
    responses(&f, 0, 1, 1);
    REQUIRE(close(waiting_peer) == 0);
    end(&f, 2);
}
static void notifications(void) {
    ++groups;
    fixture_t f;
    start(&f, AF_UNIX, 0);
    enable(&f);
    vireo_tcp_server_turn_result_t t[4];
    vireo_tcp_server_round_info_t old;
    f.listener_injected_events = VIREO_EPOLL_EVENT_READ;
    CHECK(round_at(&f, 0, all_clients, 4, t, &old, NULL) == VIREO_OK &&
          state(&f).listener_last_events == VIREO_EPOLL_EVENT_READ && f.accept_calls_total == 0);
    vireo_connection_pool_lease_t c[4] = {{0}};
    vireo_tcp_server_serve_info_t i;
    vireo_tcp_server_serve_error_t e;
    CHECK(serve(&f, defaults(), t, 4, c, 4, &i, NULL) == VIREO_OK && !i.admission_called &&
          i.listener_events == 0);
    f.listener_injected_events =
        VIREO_EPOLL_EVENT_ERROR | VIREO_EPOLL_EVENT_HANGUP | VIREO_EPOLL_EVENT_READ;
    CHECK(serve(&f, defaults(), t, 4, c, 4, &i, &e) == VIREO_RESULT_IO &&
          e.stage == VIREO_TCP_SERVER_SERVE_LISTENER_EVENT &&
          e.listener_events == i.listener_events && !i.admission_called && i.sync_called &&
          f.accept_calls_total == 0);
    end(&f, 0);
}
static void budgets(void) {
    ++groups;
    fixture_t f;
    start(&f, AF_UNIX, 1);
    enable(&f);
    feed(&f, 0, 5, 1);
    schedule(&f, 0);
    f.peers[1] = connect_peer(&f);
    f.peers[2] = connect_peer(&f);
    f.peers[3] = connect_peer(&f);
    vireo_tcp_server_turn_result_t t[4];
    vireo_connection_pool_lease_t c[4] = {{0}};
    vireo_tcp_server_serve_info_t i;
    vireo_tcp_server_serve_options_t o = defaults();
    o.round.max_clients = 1;
    o.admit.max_accepts = 2;
    o.admit.max_accept_syscalls = 1;
    CHECK(serve(&f, o, t, 1, c, 4, &i, NULL) == VIREO_OK && i.round.turn_count == 1 &&
          i.round.requeued_count == 1 && i.admission.admitted_count == 1 &&
          i.admission.accept_calls == 1 &&
          i.admission.stop_reason == VIREO_TCP_SERVER_ADMIT_CALL_LIMIT);
    f.clients[1] = c[0];
    memset(c, 0, sizeof(c));
    o.admit.max_accept_syscalls = 16;
    CHECK(serve(&f, o, t, 1, c, 1, &i, NULL) == VIREO_OK && i.round.turn_count == 1 &&
          same(t[0].client, f.clients[0]) && i.admission.admitted_count == 1 &&
          i.admission.stop_reason == VIREO_TCP_SERVER_ADMIT_BATCH_LIMIT);
    f.clients[2] = c[0];
    memset(c, 0, sizeof(c));
    CHECK(serve(&f, o, t, 1, c, 4, &i, NULL) == VIREO_OK && i.admission.admitted_count == 1 &&
          i.admission.stop_reason == VIREO_TCP_SERVER_ADMIT_CONNECTION_LIMIT &&
          !i.listener_read_enabled);
    f.clients[3] = c[0];
    responses(&f, 0, 5, 1);
    end(&f, 4);
}
static void inflight(void) {
    ++groups;
    fixture_t f, nested;
    start(&nested, AF_UNIX, 1);
    feed(&nested, 0, 1, 30);
    schedule(&nested, 0);
    start(&f, AF_UNIX, 1);
    enable(&f);
    feed(&f, 0, 1, 1);
    schedule(&f, 0);
    f.nested = &nested;
    f.probe_wait = f.probe_handler = f.probe_accept = f.probe_flow = true;
    f.probe_mod = true;
    for (size_t k = 1; k < 4; ++k)
        f.peers[k] = connect_peer(&f);
    vireo_tcp_server_turn_result_t t[4];
    vireo_connection_pool_lease_t c[4] = {{0}};
    vireo_tcp_server_serve_info_t i;
    CHECK(serve(&f, defaults(), t, 4, c, 4, &i, NULL) == VIREO_OK && i.round.turn_count == 1 &&
          i.admission.admitted_count == 3);
    for (size_t k = 1; k < 4; ++k)
        f.clients[k] = c[k - 1];
    responses(&f, 0, 1, 1);
    responses(&nested, 0, 1, 30);
    f.probe_mod = f.probe_accept = f.probe_flow = f.probe_wait = f.probe_handler = false;
    /* 上一轮末尾暂停 MOD 已探测外层保护；解绑后重新绑定并配置仍保留满池暂停。 */
    REQUIRE(vireo_tcp_server_unbind_listener(f.server, NULL) == VIREO_OK);
    REQUIRE(vireo_tcp_server_bind_listener(f.server, false, NULL) == VIREO_OK);
    enable(&f);
    end(&f, 4);
    end(&nested, 1);
}
static void exact_budget(void) {
    ++groups;
    vireo_tcp_server_t *s = NULL;
    vireo_tcp_server_info_t i;
    REQUIRE(vireo_tcp_server_create(&server_options, &s, NULL) == VIREO_OK);
    REQUIRE(vireo_tcp_server_inspect(s, &i) == VIREO_OK);
    size_t total = i.allocation_bytes;
    REQUIRE(vireo_tcp_server_destroy(&s, NULL) == VIREO_OK);
    vireo_tcp_server_options_t o = server_options;
    o.max_memory_bytes = total;
    CHECK(vireo_tcp_server_create(&o, &s, NULL) == VIREO_OK);
    REQUIRE(vireo_tcp_server_destroy(&s, NULL) == VIREO_OK);
    --o.max_memory_bytes;
    CHECK(vireo_tcp_server_create(&o, &s, NULL) == VIREO_RESULT_RANGE && s == NULL);
    o = (vireo_tcp_server_options_t){65535, 1, VIREO_TCP_SERVER_MAX_MEMORY, 1024};
    REQUIRE(vireo_tcp_server_create(&o, &s, NULL) == VIREO_OK);
    REQUIRE(vireo_tcp_server_inspect(s, &i) == VIREO_OK);
    CHECK(i.connection_capacity == 65535 && i.available_connections == 65535 &&
          !i.admission_enabled && !i.serving_active);
    REQUIRE(vireo_tcp_server_destroy(&s, NULL) == VIREO_OK);
}
int main(void) {
    unsigned const before = fd_count();
    config();
    automatic(AF_INET);
    automatic(AF_UNIX);
    capacity();
    buffer_limit();
    reconfiguration();
    parameters();
    waiting();
    flow_and_post_failure();
    post_failure();
    setup_failure(0);
    setup_failure(1);
    setup_failure(2);
    existing_failure();
    notifications();
    budgets();
    inflight();
    exact_budget();
    unsigned const after = fd_count();
    CHECK(before == after);
    printf("test_tcp_server_auto_admission: %u groups, %u failures, fd %u -> %u\n", groups,
           failures, before, after);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
