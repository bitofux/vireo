/*
- PROJECT : VIREO
- FILE    : test_tcp_server_close_batch.c
- AUTHOR  : bitofux
- DATE    : 2026-10-07
- BRIEF   : 此模块负责：
- -- 有界批量关闭、独立游标与去重续项、真实响应排空
- -- 关闭/队列独立事实、部分失败与Reactor在途保护
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
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
static vireo_tcp_server_drive_budget_t allowance = {{SIZE_MAX, 8}, {2, 192, 192}, {SIZE_MAX, 8}};
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
    unsigned detach_calls, release_calls, cleanup_probes;
    bool probe_cleanup, fail_close_sync;
    unsigned close_calls, refresh_calls, fail_refresh_on;
    unsigned batch_lookup_calls, fail_batch_lookup_on, fail_batch_close_on, stop_batch_on;
    bool fail_before_close;
    int receive_errno, send_errno;
    bool partial_receive, partial_send, request_io, probe_request;
    bool fail_policy_inspect, fail_policy_lookup, bad_reply;
    vireo_result_t handler_return;
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
    ++f->detach_calls;
    if (f->probe_cleanup)
        probe(f, false);
    vireo_connection_info_t current;
    REQUIRE(vireo_connection_inspect(c, &current) == VIREO_OK);
    CHECK(!current.callback_active);
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
    ++f->release_calls;
    if (f->probe_cleanup)
        probe(f, false);
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
    ++f->refresh_calls;
    if (f->fail_sync || f->refresh_calls == f->fail_refresh_on) {
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
    fixture_t *f = ctx;
    if (f->fail_policy_inspect && f->refresh_calls >= 2) {
        vireo_tcp_server_info_t current;
        REQUIRE(vireo_tcp_server_inspect(f->server, &current) == VIREO_OK);
        if (current.scheduling_active && !current.driving_active)
            return VIREO_RESULT_IO;
    }
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
    fixture_t *f = ctx;
    if (f->fail_batch_lookup_on != 0) {
        vireo_tcp_server_info_t current;
        REQUIRE(vireo_tcp_server_inspect(f->server, &current) == VIREO_OK);
        if (current.closing_active && ++f->batch_lookup_calls == f->fail_batch_lookup_on)
            return VIREO_RESULT_NOT_FOUND;
    }
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
    fixture_t *f = ctx;
    if (f->receive_errno) {
        *i = (vireo_connection_receive_info_t){0};
        if (f->partial_receive) {
            vireo_connection_receive_budget_t one = {16, 1};
            REQUIRE(vireo_connection_receive(c, &one, i, NULL) == VIREO_OK);
        }
        ++i->recv_calls; /* 窄seam模拟下一次失败，保留之前真实接收。 */
        i->stop_reason = VIREO_CONNECTION_RECEIVE_STOP_ERROR;
        *e = (vireo_connection_error_t){VIREO_CONNECTION_STAGE_RECEIVE, f->receive_errno};
        errno = ERANGE;
        return VIREO_RESULT_IO;
    }
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
    fixture_t *f = ctx;
    if (f->send_errno) {
        *i = (vireo_connection_send_info_t){0};
        if (f->partial_send) {
            vireo_connection_send_budget_t one = {8, 1};
            REQUIRE(vireo_connection_send(c, &one, i, NULL) == VIREO_OK);
        }
        ++i->send_calls;
        i->stop_reason = VIREO_CONNECTION_SEND_STOP_ERROR;
        *e = (vireo_connection_error_t){VIREO_CONNECTION_STAGE_SEND, f->send_errno};
        errno = ERANGE;
        return VIREO_RESULT_IO;
    }
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
    fixture_t *f = ctx;
    ++f->close_calls;
    if (f->probe_request)
        probe(f, false);
    bool const fail = f->close_calls == f->fail_batch_close_on;
    vireo_result_t result = VIREO_OK;
    if (!(fail && f->fail_before_close))
        result = vireo_connection_request_close(c, m, r, e);
    if (f->close_calls == f->stop_batch_on)
        REQUIRE(vireo_tcp_server_request_stop(f->server, NULL) == VIREO_OK);
    if (result == VIREO_OK && (fail || f->request_io)) {
        /* own seam区分真实意图之前/之后失败，不冒充原生MOD故障。 */
        *e = (vireo_connection_loop_error_t){
            .stage = VIREO_CONNECTION_LOOP_STAGE_REQUEST_CLOSE,
            .loop_error = {.stage = VIREO_EVENT_LOOP_STAGE_MOD,
                           .epoll_error = {VIREO_EPOLL_STAGE_MOD, EIO}}};
        errno = ERANGE;
        return VIREO_RESULT_IO;
    }
    return result;
}
/** 只桥接已封板公开依赖，ctx 无资源所有权。 */
static vireo_result_t close_refresh(void *ctx, vireo_connection_t *c,
                                    vireo_connection_loop_error_t *e) {
    fixture_t *f = ctx;
    if (f->fail_close_sync) {
        *e = (vireo_connection_loop_error_t){
            .stage = VIREO_CONNECTION_LOOP_STAGE_CLOSE_REFRESH,
            .loop_error = {.stage = VIREO_EVENT_LOOP_STAGE_MOD,
                           .epoll_error = {VIREO_EPOLL_STAGE_MOD, EBADF}}};
        return VIREO_RESULT_IO;
    }
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
        int const n = snprintf(a.sun_path + 1, sizeof(a.sun_path) - 1, "vireo-close-batch-%ld-%u",
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
    f->fail_batch_lookup_on = f->fail_batch_close_on = f->stop_batch_on = 0;
    f->detach_io = false;
    f->release_busy = false;
    f->release_io = false;
    f->fail_sync = false;
    f->fail_close_sync = false;
    f->probe_cleanup = false;
    f->request_io = f->probe_request = f->fail_policy_inspect = f->fail_policy_lookup = false;
    f->receive_errno = f->send_errno = 0;
    for (size_t k = 0; k < count; ++k) {
        if (!empty(f->clients[k])) {
            vireo_tcp_server_client_info_t info;
            vireo_result_t const seen =
                vireo_tcp_server_client_inspect(f->server, f->clients[k], &info);
            if (seen == VIREO_RESULT_NOT_FOUND)
                f->clients[k] = (vireo_connection_pool_lease_t){0};
            else
                REQUIRE(seen == VIREO_OK && vireo_tcp_server_release_client(
                                                f->server, &f->clients[k], NULL) == VIREO_OK);
        }
        REQUIRE(close(f->peers[k]) == 0);
    }
    REQUIRE(vireo_tcp_server_destroy(&f->server, NULL) == VIREO_OK);
    server_options = (vireo_tcp_server_options_t){4, 8, 1048576, 16384};
    allowance = (vireo_tcp_server_drive_budget_t){{SIZE_MAX, 8}, {2, 192, 192}, {SIZE_MAX, 8}};
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
    if (f->bad_reply)
        reply->status = UINT16_MAX;
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
        return f->handler_return == VIREO_OK ? VIREO_RESULT_IO : f->handler_return;
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
/* 外部在途权限不能因内部共享释放而放宽；依赖钩子仅在真实安全点核对。 */
static vireo_result_t batch(fixture_t *f, vireo_connection_close_mode_t mode, size_t slots,
                            vireo_tcp_server_close_batch_result_t *rows, size_t cap,
                            vireo_tcp_server_close_batch_info_t *i,
                            vireo_tcp_server_close_batch_error_t *e) {
    vireo_tcp_server_close_batch_budget_t const b = {slots};
    errno = EDOM;
    vireo_result_t const r = vireo_tcp_server_close_batch(f->server, mode, &b, rows, cap, i, e);
    CHECK(errno == EDOM && !state(f).closing_active);
    return r;
}
/* 在真实等待/handler/request的保护点检查，不依赖旧模块私有布局。 */
static void probe(fixture_t *f, bool in_handler) {
    (void)in_handler;
    ++f->cleanup_probes;
    vireo_tcp_server_info_t const before = state(f);
    CHECK(before.closing_active || before.scheduling_active || before.serving_active ||
          before.shutdown_active);
    vireo_tcp_server_close_batch_result_t row = {.result = VIREO_RESULT_RANGE};
    vireo_tcp_server_close_batch_info_t info = {.next_slot = 99};
    vireo_tcp_server_close_batch_budget_t const budget = {1};
    CHECK(vireo_tcp_server_close_batch(f->server, VIREO_CONNECTION_CLOSE_MODE_DRAIN, &budget, &row,
                                       1, &info, NULL) == VIREO_RESULT_BUSY);
    CHECK(info.next_slot == 99 && row.result == VIREO_RESULT_RANGE &&
          state(f).close_next_slot == before.close_next_slot);
    CHECK(vireo_tcp_server_set_auto_close_policy(f->server, true, NULL) == VIREO_RESULT_BUSY);
    CHECK(vireo_tcp_server_set_auto_release_ready(f->server, true, NULL) == VIREO_RESULT_BUSY);
    CHECK(vireo_tcp_server_set_listener_read_enabled(f->server, false, NULL) == VIREO_RESULT_BUSY);
    CHECK(vireo_tcp_server_schedule_client(f->server, f->clients[0], NULL) == VIREO_RESULT_BUSY);
    CHECK(vireo_tcp_server_client_flow_configure(f->server, f->clients[0], &flow, NULL) ==
          VIREO_RESULT_BUSY);
    CHECK(vireo_tcp_server_client_request_close(
              f->server, f->clients[0], VIREO_CONNECTION_CLOSE_MODE_DRAIN,
              VIREO_CONNECTION_CLOSE_REASON_SERVER_STOP, NULL) == VIREO_RESULT_BUSY);
    CHECK(vireo_tcp_server_admission_configure(f->server, &policy, NULL) == VIREO_RESULT_BUSY);
    vireo_tcp_server_turn_result_t turn;
    vireo_tcp_server_round_info_t round_info = {.turn_count = 99};
    CHECK(round_at(f, 0, all_clients, 1, &turn, &round_info, NULL) == VIREO_RESULT_BUSY &&
          round_info.turn_count == 99);
    CHECK(vireo_tcp_server_client_read_consume(f->server, f->clients[0], 0, NULL) ==
          VIREO_RESULT_BUSY);
    CHECK(vireo_tcp_server_client_write_enqueue(f->server, f->clients[0], NULL, 0, NULL) ==
          VIREO_RESULT_BUSY);
    vireo_connection_receive_info_t receive;
    CHECK(vireo_tcp_server_client_receive(f->server, f->clients[0], &allowance.receive, &receive,
                                          NULL) == VIREO_RESULT_BUSY);
    vireo_connection_send_info_t send;
    CHECK(vireo_tcp_server_client_send(f->server, f->clients[0], &allowance.send, &send, NULL) ==
          VIREO_RESULT_BUSY);
    vireo_connection_pool_lease_t lease = f->clients[0];
    CHECK(vireo_tcp_server_release_client(f->server, &lease, NULL) == VIREO_RESULT_BUSY &&
          same(lease, f->clients[0]));
    vireo_tcp_server_t *owner = f->server;
    CHECK(vireo_tcp_server_destroy(&owner, NULL) == VIREO_RESULT_BUSY && owner == f->server);
}
static void empty_and_rejection(void) {
    ++groups;
    fixture_t f;
    start(&f, AF_UNIX, 0);
    vireo_tcp_server_close_batch_result_t rows[4];
    memset(rows, 0x5a, sizeof(rows));
    unsigned char old[sizeof(rows)];
    memcpy(old, rows, sizeof(rows));
    vireo_tcp_server_close_batch_info_t i;
    vireo_tcp_server_close_batch_error_t e;
    REQUIRE(batch(&f, VIREO_CONNECTION_CLOSE_MODE_DRAIN, 65535, rows, 4, &i, &e) == VIREO_OK);
    CHECK(i.scanned_slots == 0 && i.processed_clients == 0 && i.owned_clients == 0 &&
          i.next_slot == 0 && i.stop_reason == VIREO_TCP_SERVER_CLOSE_BATCH_EMPTY &&
          e.stage == VIREO_TCP_SERVER_CLOSE_BATCH_NONE && memcmp(old, rows, sizeof(rows)) == 0);
    for (unsigned k = 0; k < 4; ++k) {
        i.next_slot = 123;
        vireo_result_t const expected = k < 2 ? VIREO_RESULT_INVALID_ARGUMENT : VIREO_RESULT_RANGE;
        size_t slots = k == 0 ? 0 : k == 2 ? 65536 : 1;
        size_t cap = k == 1 ? 0 : k == 3 ? 65536 : 4;
        CHECK(batch(&f, VIREO_CONNECTION_CLOSE_MODE_DRAIN, slots, rows, cap, &i, &e) == expected);
        CHECK(i.next_slot == 123 && memcmp(old, rows, sizeof(rows)) == 0);
    }
    CHECK(batch(&f, VIREO_CONNECTION_CLOSE_MODE_NONE, 1, rows, 4, &i, &e) ==
          VIREO_RESULT_INVALID_ARGUMENT);
    vireo_tcp_server_close_batch_budget_t const b = {1};
    CHECK(vireo_tcp_server_close_batch(NULL, VIREO_CONNECTION_CLOSE_MODE_DRAIN, &b, rows, 4, &i,
                                       NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_tcp_server_close_batch(f.server, VIREO_CONNECTION_CLOSE_MODE_DRAIN, NULL, rows, 4,
                                       &i, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_tcp_server_close_batch(f.server, VIREO_CONNECTION_CLOSE_MODE_DRAIN, &b, NULL, 4, &i,
                                       NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_tcp_server_close_batch(f.server, VIREO_CONNECTION_CLOSE_MODE_DRAIN, &b, rows, 4,
                                       NULL, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    end(&f, 0);
}
static void sparse_cursor_and_capacity(bool small_output) {
    ++groups;
    fixture_t f;
    start(&f, AF_UNIX, 4);
    REQUIRE(vireo_tcp_server_release_client(f.server, &f.clients[1], NULL) == VIREO_OK);
    REQUIRE(vireo_tcp_server_release_client(f.server, &f.clients[3], NULL) == VIREO_OK);
    vireo_tcp_server_close_batch_result_t rows[4] = {0};
    rows[1].result = VIREO_RESULT_RANGE;
    vireo_tcp_server_close_batch_info_t i;
    REQUIRE(batch(&f, VIREO_CONNECTION_CLOSE_MODE_DRAIN, small_output ? 4 : 1, rows, 1, &i, NULL) ==
            VIREO_OK);
    CHECK(i.scanned_slots == 1 && i.processed_clients == 1 && i.next_slot == 1 &&
          same(rows[0].lease, f.clients[0]) && rows[1].result == VIREO_RESULT_RANGE &&
          i.stop_reason == (small_output ? VIREO_TCP_SERVER_CLOSE_BATCH_RESULT_CAPACITY
                                         : VIREO_TCP_SERVER_CLOSE_BATCH_SCAN_LIMIT));
    REQUIRE(batch(&f, VIREO_CONNECTION_CLOSE_MODE_DRAIN, 2, rows, 1, &i, NULL) == VIREO_OK);
    CHECK(i.scanned_slots == 2 && i.next_slot == 3 && same(rows[0].lease, f.clients[2]));
    CHECK(state(&f).pending_clients == 2 && state(&f).connection_count == 2);
    REQUIRE(batch(&f, VIREO_CONNECTION_CLOSE_MODE_DRAIN, 65535, rows, 4, &i, NULL) == VIREO_OK);
    CHECK(i.scanned_slots == 4 && i.processed_clients == 2 && i.next_slot == 3 &&
          i.scheduled_clients == 2 && state(&f).pending_clients == 2 &&
          state(&f).shutdown_next_slot == 0);
    vireo_tcp_server_turn_result_t t[4];
    vireo_tcp_server_round_info_t ri;
    REQUIRE(round_at(&f, 0, all_clients, 4, t, &ri, NULL) == VIREO_OK);
    CHECK(ri.turn_count == 2 && same(t[0].client, f.clients[0]) && same(t[1].client, f.clients[2]));
    end(&f, 4);
}
static void drain_real(int family) {
    ++groups;
    fixture_t f;
    start(&f, family, 2);
    uint8_t const payload[4] = {1, 2, 3, 4};
    REQUIRE(vireo_tcp_server_client_write_enqueue(f.server, f.clients[1], payload, 4, NULL) ==
            VIREO_OK);
    REQUIRE(vireo_tcp_server_set_auto_release_ready(f.server, true, NULL) == VIREO_OK);
    size_t const bytes = state(&f).buffer_capacity_bytes;
    vireo_tcp_server_close_batch_result_t rows[4];
    vireo_tcp_server_close_batch_info_t i;
    REQUIRE(batch(&f, VIREO_CONNECTION_CLOSE_MODE_DRAIN, 4, rows, 4, &i, NULL) == VIREO_OK);
    CHECK(i.processed_clients == 2 && i.owned_clients == 2 &&
          state(&f).buffer_capacity_bytes == bytes &&
          client(&f, 0).connection_info.close_state == VIREO_CONNECTION_CLOSE_READY &&
          client(&f, 1).connection_info.close_state == VIREO_CONNECTION_CLOSE_DRAINING &&
          client(&f, 1).connection_info.loop_interests == VIREO_EPOLL_EVENT_WRITE);
    vireo_tcp_server_turn_result_t t[4];
    vireo_tcp_server_round_info_t ri;
    vireo_tcp_server_round_budget_t const one = {1};
    REQUIRE(round_at(&f, 0, one, 4, t, &ri, NULL) == VIREO_OK);
    CHECK(t[0].released && same(t[0].client, f.clients[0]) && state(&f).connection_count == 1);
    allowance.send.max_bytes = 1;
    REQUIRE(round_at(&f, 0, one, 4, t, &ri, NULL) == VIREO_OK);
    CHECK(!t[0].released && client(&f, 1).connection_info.write_buffer.readable_size == 3);
    allowance.send.max_bytes = SIZE_MAX;
    REQUIRE(round_at(&f, 100, one, 4, t, &ri, NULL) == VIREO_OK);
    CHECK(t[0].released && state(&f).connection_count == 0 && state(&f).pending_clients == 0);
    uint8_t received[4];
    REQUIRE(recv(f.peers[1], received, sizeof(received), MSG_WAITALL) == 4);
    CHECK(memcmp(payload, received, 4) == 0 && fcntl(f.raw_fds[1], F_GETFD) == -1 &&
          errno == EBADF);
    end(&f, 2);
}
static void immediate_borrow_and_reason(void) {
    ++groups;
    fixture_t f;
    start(&f, AF_UNIX, 1);
    feed(&f, 0, 1, 41);
    uint8_t const *p;
    size_t n;
    REQUIRE(vireo_tcp_server_client_read_peek(f.server, f.clients[0], &p, &n, NULL) == VIREO_OK);
    uint8_t saved[32];
    REQUIRE(n == 32);
    memcpy(saved, p, n);
    REQUIRE(vireo_tcp_server_client_write_enqueue(f.server, f.clients[0], saved, n, NULL) ==
            VIREO_OK);
    REQUIRE(vireo_tcp_server_client_request_close(
                f.server, f.clients[0], VIREO_CONNECTION_CLOSE_MODE_DRAIN,
                VIREO_CONNECTION_CLOSE_REASON_APPLICATION, NULL) == VIREO_OK);
    vireo_tcp_server_close_batch_result_t row;
    vireo_tcp_server_close_batch_info_t i;
    REQUIRE(batch(&f, VIREO_CONNECTION_CLOSE_MODE_IMMEDIATE, 4, &row, 1, &i, NULL) == VIREO_OK);
    vireo_connection_info_t const c = client(&f, 0).connection_info;
    CHECK(c.close_state == VIREO_CONNECTION_CLOSE_READY &&
          c.close_mode == VIREO_CONNECTION_CLOSE_MODE_IMMEDIATE &&
          c.close_reason == VIREO_CONNECTION_CLOSE_REASON_APPLICATION &&
          c.read_buffer.readable_size == 32 && c.write_buffer.readable_size == 32 &&
          memcmp(p, saved, n) == 0 && f.handler_calls == 0);
    REQUIRE(batch(&f, VIREO_CONNECTION_CLOSE_MODE_DRAIN, 4, &row, 1, &i, NULL) ==
            VIREO_RESULT_BUSY);
    CHECK(row.close_attempted && !row.schedule_attempted && i.processed_clients == 1 &&
          i.next_slot == 1);
    end(&f, 1);
}
static void partial_failure(unsigned kind) {
    ++groups;
    fixture_t f;
    start(&f, AF_UNIX, 3);
    if (kind == 0)
        f.fail_batch_lookup_on = 2;
    else {
        f.fail_batch_close_on = 2;
        f.fail_before_close = kind == 1;
    }
    vireo_tcp_server_close_batch_result_t rows[4] = {0};
    rows[2].result = VIREO_RESULT_RANGE;
    vireo_tcp_server_close_batch_info_t i;
    vireo_tcp_server_close_batch_error_t e;
    CHECK(batch(&f, VIREO_CONNECTION_CLOSE_MODE_IMMEDIATE, 4, rows, 4, &i, &e) ==
          (kind == 0 ? VIREO_RESULT_NOT_FOUND : VIREO_RESULT_IO));
    CHECK(i.processed_clients == 2 && i.scanned_slots == 2 && i.next_slot == 2 &&
          i.owned_clients == 3 && i.scheduled_clients == 1 &&
          rows[2].result == VIREO_RESULT_RANGE && rows[0].scheduled && !rows[1].scheduled &&
          !rows[1].schedule_attempted && same(e.client, f.clients[1]) &&
          state(&f).pending_clients == 1);
    CHECK(client(&f, 0).connection_info.close_state == VIREO_CONNECTION_CLOSE_READY &&
          client(&f, 1).connection_info.close_state ==
              (kind == 2 ? VIREO_CONNECTION_CLOSE_READY : VIREO_CONNECTION_CLOSE_OPEN) &&
          client(&f, 2).connection_info.close_state == VIREO_CONNECTION_CLOSE_OPEN);
    if (kind != 0)
        CHECK(rows[1].close_attempted && e.stage == VIREO_TCP_SERVER_CLOSE_BATCH_REQUEST &&
              e.client_error.primary.loop_error.loop_error.epoll_error.system_errno == EIO);
    else
        CHECK(!rows[1].close_attempted && e.stage == VIREO_TCP_SERVER_CLOSE_BATCH_LOOKUP);
    f.fail_batch_lookup_on = f.fail_batch_close_on = 0;
    REQUIRE(batch(&f, VIREO_CONNECTION_CLOSE_MODE_IMMEDIATE, 1, rows, 4, &i, NULL) == VIREO_OK);
    CHECK(same(rows[0].lease, f.clients[2]) && i.next_slot == 3 && state(&f).pending_clients == 2);
    end(&f, 3);
}
typedef struct gate_context {
    fixture_t *f, *nested;
    unsigned calls, fail_on;
} gate_context_t;
static vireo_result_t gate(void *ctx, vireo_tcp_server_t *server,
                           vireo_connection_pool_lease_t lease) {
    gate_context_t *g = ctx;
    CHECK(server == g->f->server && !empty(lease) && state(g->f).closing_active);
    ++g->calls;
    probe(g->f, false);
    if (g->nested != NULL) {
        vireo_tcp_server_close_batch_result_t row;
        vireo_tcp_server_close_batch_info_t i;
        REQUIRE(batch(g->nested, VIREO_CONNECTION_CLOSE_MODE_IMMEDIATE, 1, &row, 1, &i, NULL) ==
                VIREO_OK);
        CHECK(row.scheduled && state(g->f).closing_active);
        g->nested = NULL;
    }
    return g->calls == g->fail_on ? VIREO_RESULT_INTERNAL : VIREO_OK;
}
static void queue_failure_and_nested(bool nested) {
    ++groups;
    fixture_t f, other;
    start(&f, AF_UNIX, 3);
    if (nested)
        start(&other, AF_UNIX, 1);
    gate_context_t g = {&f, nested ? &other : NULL, 0, 2};
    vireo_tcp_server_close_batch_result_t rows[4];
    vireo_tcp_server_close_batch_info_t i;
    vireo_tcp_server_close_batch_error_t e;
    vireo_tcp_server_close_batch_budget_t const b = {4};
    errno = EDOM;
    REQUIRE(vireo_tcp_server_close_batch_with_gate(f.server, VIREO_CONNECTION_CLOSE_MODE_IMMEDIATE,
                                                   &b, rows, 4, &i, &e, gate,
                                                   &g) == VIREO_RESULT_INTERNAL);
    CHECK(errno == EDOM && !state(&f).closing_active && i.next_slot == 2 &&
          i.processed_clients == 2 && rows[1].close_result == VIREO_OK &&
          rows[1].schedule_attempted && !rows[1].scheduled &&
          rows[1].schedule_result == VIREO_RESULT_INTERNAL &&
          e.stage == VIREO_TCP_SERVER_CLOSE_BATCH_QUEUE &&
          e.client_error.primary.stage == VIREO_TCP_SERVER_CLIENT_NONE &&
          client(&f, 1).connection_info.close_state == VIREO_CONNECTION_CLOSE_READY);
    REQUIRE(batch(&f, VIREO_CONNECTION_CLOSE_MODE_IMMEDIATE, 1, rows, 4, &i, NULL) == VIREO_OK);
    schedule(&f, 1);
    REQUIRE(vireo_tcp_server_set_auto_release_ready(f.server, true, NULL) == VIREO_OK);
    vireo_tcp_server_turn_result_t t[4];
    vireo_tcp_server_round_info_t ri;
    REQUIRE(round_at(&f, 0, all_clients, 4, t, &ri, NULL) == VIREO_OK);
    CHECK(ri.turn_count == 3 && same(t[0].client, f.clients[0]) &&
          same(t[1].client, f.clients[2]) && same(t[2].client, f.clients[1]) &&
          state(&f).connection_count == 0);
    end(&f, 3);
    if (nested)
        end(&other, 1);
}
static void stop_during_batch(void) {
    ++groups;
    fixture_t f;
    start(&f, AF_UNIX, 3);
    f.stop_batch_on = 1;
    f.probe_request = true;
    vireo_tcp_server_close_batch_result_t rows[4];
    vireo_tcp_server_close_batch_info_t i;
    REQUIRE(batch(&f, VIREO_CONNECTION_CLOSE_MODE_DRAIN, 4, rows, 4, &i, NULL) == VIREO_OK);
    CHECK(i.processed_clients == 3 && state(&f).stop_requested && state(&f).pending_clients == 3);
    i.next_slot = 99;
    rows[0].result = VIREO_RESULT_RANGE;
    CHECK(batch(&f, VIREO_CONNECTION_CLOSE_MODE_DRAIN, 1, rows, 4, &i, NULL) == VIREO_RESULT_BUSY &&
          i.next_slot == 99 && rows[0].result == VIREO_RESULT_RANGE);
    vireo_tcp_server_turn_result_t t[4];
    vireo_tcp_server_round_info_t ri;
    REQUIRE(round_at(&f, 0, all_clients, 4, t, &ri, NULL) == VIREO_OK);
    CHECK(ri.turn_count == 0 && state(&f).pending_clients == 3);
    vireo_tcp_server_shutdown_result_t released[4];
    vireo_tcp_server_shutdown_info_t si;
    vireo_tcp_server_shutdown_budget_t const b = {4};
    REQUIRE(vireo_tcp_server_shutdown_batch(f.server, &b, released, 4, &si, NULL) == VIREO_OK);
    CHECK(si.released_clients == 3 && state(&f).connection_count == 0 &&
          state(&f).pending_clients == 0);
    end(&f, 3);
}
static void in_flight_and_normal_response(void) {
    ++groups;
    fixture_t f;
    start(&f, AF_UNIX, 1);
    feed(&f, 0, 1, 90);
    schedule(&f, 0);
    enable(&f);
    f.probe_handler = f.probe_wait = true;
    vireo_tcp_server_turn_result_t t[4];
    vireo_connection_pool_lease_t c[4] = {{0}};
    vireo_tcp_server_serve_info_t i;
    REQUIRE(serve(&f, defaults(), t, 4, c, 4, &i, NULL) == VIREO_OK);
    CHECK(i.round.turn_count == 1 && f.cleanup_probes == 2 && !state(&f).closing_active);
    responses(&f, 0, 1, 90);
    f.probe_handler = f.probe_wait = false;
    end(&f, 1);
}
typedef struct observation {
    fixture_t *f;
    unsigned calls;
} observation_t;
static void observe(vireo_tcp_server_t *server, vireo_result_t result,
                    vireo_tcp_server_serve_info_t const *info,
                    vireo_tcp_server_turn_result_t const *turns,
                    vireo_connection_pool_lease_t const *clients,
                    vireo_tcp_server_serve_error_t const *error, void *ctx) {
    (void)clients;
    (void)error;
    observation_t *o = ctx;
    ++o->calls;
    CHECK(result == VIREO_OK && info->round.turn_count == 1 && state(o->f).running_active);
    vireo_tcp_server_t *owner = server;
    CHECK(vireo_tcp_server_destroy(&owner, NULL) == VIREO_RESULT_BUSY);
    if (o->calls <= 2) {
        vireo_tcp_server_close_batch_result_t row;
        vireo_tcp_server_close_batch_info_t i;
        REQUIRE(batch(o->f, VIREO_CONNECTION_CLOSE_MODE_DRAIN, 1, &row, 1, &i, NULL) == VIREO_OK);
        CHECK(same(row.lease, o->f->clients[o->calls - 1]) && row.scheduled);
    } else
        CHECK(turns[0].released);
    if (o->calls == 4)
        REQUIRE(vireo_tcp_server_request_stop(server, NULL) == VIREO_OK);
}
static void running_observer(void) {
    ++groups;
    fixture_t f;
    start(&f, AF_UNIX, 2);
    enable(&f);
    schedule(&f, 0);
    schedule(&f, 1);
    REQUIRE(vireo_tcp_server_set_auto_release_ready(f.server, true, NULL) == VIREO_OK);
    vireo_tcp_server_run_options_t const options = {limits, allowance, {1}, {4, 16}};
    uint8_t workspace[96];
    vireo_tcp_server_turn_result_t t[4];
    vireo_connection_pool_lease_t c[4] = {{0}};
    observation_t o = {&f, 0};
    errno = EDOM;
    REQUIRE(vireo_tcp_server_run(f.server, &options, workspace, 96, handler, &f, t, 4, c, 4,
                                 observe, &o, NULL) == VIREO_OK);
    CHECK(errno == EDOM && o.calls == 4 && state(&f).connection_count == 0 &&
          state(&f).listener_read_enabled && state(&f).admission_enabled &&
          !state(&f).running_active);
    end(&f, 2);
}
/* 跨批成员不是快照：推进的游标必须选择复用槽的新代际。 */
static void generation_reuse(void) {
    ++groups;
    fixture_t f;
    start(&f, AF_UNIX, 2);
    vireo_connection_pool_lease_t const old = f.clients[0];
    vireo_tcp_server_close_batch_result_t rows[4];
    vireo_tcp_server_close_batch_info_t i;
    REQUIRE(batch(&f, VIREO_CONNECTION_CLOSE_MODE_DRAIN, 1, rows, 4, &i, NULL) == VIREO_OK);
    REQUIRE(vireo_tcp_server_release_client(f.server, &f.clients[0], NULL) == VIREO_OK);
    CHECK(state(&f).pending_clients == 0 && state(&f).close_next_slot == 1);
    f.peers[2] = connect_peer(&f);
    vireo_tcp_server_admit_budget_t const budget = {1, 1};
    vireo_tcp_server_admit_info_t admitted;
    REQUIRE(vireo_tcp_server_admit_batch(f.server, &conn_options, &budget, &f.clients[2], 1,
                                         &admitted, NULL) == VIREO_OK &&
            admitted.admitted_count == 1);
    CHECK(old.slot_index == f.clients[2].slot_index && !same(old, f.clients[2]));
    vireo_tcp_server_client_info_t stale;
    CHECK(vireo_tcp_server_client_inspect(f.server, old, &stale) == VIREO_RESULT_NOT_FOUND);
    REQUIRE(batch(&f, VIREO_CONNECTION_CLOSE_MODE_DRAIN, 4, rows, 4, &i, NULL) == VIREO_OK);
    CHECK(i.scanned_slots == 4 && i.processed_clients == 2 && same(rows[0].lease, f.clients[1]) &&
          same(rows[1].lease, f.clients[2]) && state(&f).pending_clients == 2);
    end(&f, 3);
}
int main(void) {
    unsigned const before = fd_count();
    empty_and_rejection();
    sparse_cursor_and_capacity(false);
    sparse_cursor_and_capacity(true);
    drain_real(AF_UNIX);
    drain_real(AF_INET);
    immediate_borrow_and_reason();
    for (unsigned k = 0; k < 3; ++k)
        partial_failure(k);
    queue_failure_and_nested(false);
    queue_failure_and_nested(true);
    stop_during_batch();
    in_flight_and_normal_response();
    running_observer();
    generation_reuse();
    unsigned const after = fd_count();
    CHECK(before == after);
    printf("tcp_server close batch: %u groups, %u failures, fd %u -> %u\n", groups, failures,
           before, after);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
