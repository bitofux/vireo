/*
- PROJECT : VIREO
- FILE    : test_tcp_server_close_policy.c
- AUTHOR  : bitofux
- DATE    : 2026-10-06
- BRIEF   : 此模块负责：
- -- EOF缓存先处理、策略来源分类、永久意图及有限续调度
- -- 驱动/策略/末同步独立错误、在途保护和真实socket资源
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
    if (f->fail_policy_lookup && f->refresh_calls >= 2) {
        vireo_tcp_server_info_t current;
        REQUIRE(vireo_tcp_server_inspect(f->server, &current) == VIREO_OK);
        if (current.scheduling_active && !current.driving_active)
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
    vireo_result_t const result = vireo_connection_request_close(c, m, r, e);
    if (result == VIREO_OK && f->request_io) { /* 真实永久意图后模拟IO，不冒充原生MOD故障。 */
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
        int const n = snprintf(a.sun_path + 1, sizeof(a.sun_path) - 1, "vireo-close-policy-%ld-%u",
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
static void mode(fixture_t *f, bool enabled) {
    errno = EDOM;
    REQUIRE(vireo_tcp_server_set_auto_close_policy(f->server, enabled, NULL) == VIREO_OK);
    CHECK(errno == EDOM && state(f).auto_close_policy == enabled);
}
static void auto_release(fixture_t *f) {
    REQUIRE(vireo_tcp_server_set_auto_release_ready(f->server, true, NULL) == VIREO_OK);
}
static void probe(fixture_t *f, bool in_handler) {
    ++f->cleanup_probes;
    vireo_tcp_server_info_t const s = state(f);
    CHECK(s.scheduling_active || s.shutdown_active || s.serving_active);
    CHECK(!in_handler || (s.processing_active && s.driving_active));
    errno = EDOM;
    CHECK(vireo_tcp_server_set_auto_close_policy(f->server, !s.auto_close_policy, NULL) ==
          VIREO_RESULT_BUSY);
    CHECK(errno == EDOM && state(f).auto_close_policy == s.auto_close_policy);
    CHECK(vireo_tcp_server_set_auto_release_ready(f->server, false, NULL) == VIREO_RESULT_BUSY);
    vireo_tcp_server_t *owner = f->server;
    CHECK(vireo_tcp_server_destroy(&owner, NULL) == VIREO_RESULT_BUSY && owner == f->server);
    vireo_connection_pool_lease_t lease = f->clients[0];
    CHECK(vireo_tcp_server_release_client(f->server, &lease, NULL) == VIREO_RESULT_BUSY &&
          same(lease, f->clients[0]));
}
static void closing(fixture_t *f, size_t k, vireo_connection_close_mode_t m) {
    REQUIRE(vireo_tcp_server_client_request_close(f->server, f->clients[k], m,
                                                  VIREO_CONNECTION_CLOSE_REASON_APPLICATION,
                                                  NULL) == VIREO_OK);
}
static void closed_lease(fixture_t *f, size_t k) {
    vireo_tcp_server_client_info_t i, saved;
    memset(&i, 0x5a, sizeof(i));
    saved = i;
    CHECK(vireo_tcp_server_client_inspect(f->server, f->clients[k], &i) == VIREO_RESULT_NOT_FOUND);
    CHECK(memcmp(&i, &saved, sizeof(i)) == 0);
    errno = 0;
    CHECK(fcntl(f->raw_fds[k], F_GETFD) == -1 && errno == EBADF);
}
static void defaults_and_explicit(void) {
    ++groups;
    fixture_t f;
    start(&f, AF_UNIX, 1);
    CHECK(!state(&f).auto_close_policy && !state(&f).auto_release_ready);
    vireo_tcp_server_client_error_t e;
    errno = EDOM;
    CHECK(vireo_tcp_server_set_auto_close_policy(NULL, true, &e) == VIREO_RESULT_INVALID_ARGUMENT &&
          errno == EDOM && e.primary.stage == VIREO_TCP_SERVER_CLIENT_NONE);
    REQUIRE(shutdown(f.peers[0], SHUT_WR) == 0);
    schedule(&f, 0);
    vireo_tcp_server_turn_result_t t[4];
    vireo_tcp_server_round_info_t i;
    REQUIRE(round_at(&f, 0, all_clients, 4, t, &i, NULL) == VIREO_OK);
    CHECK(!t[0].close_checked && !t[0].close_attempted && f.close_calls == 0 &&
          client(&f, 0).connection_info.read_eof &&
          client(&f, 0).connection_info.close_state == VIREO_CONNECTION_CLOSE_OPEN);
    mode(&f, true);
    mode(&f, true);
    uint8_t w[96];
    vireo_tcp_server_drive_info_t di;
    REQUIRE(vireo_tcp_server_client_drive(f.server, f.clients[0], &limits, &allowance, w, 96,
                                          handler, &f, &di, NULL) == VIREO_OK);
    CHECK(f.close_calls == 0 &&
          client(&f, 0).connection_info.close_state == VIREO_CONNECTION_CLOSE_OPEN);
    mode(&f, false);
    CHECK(!state(&f).auto_release_ready && state(&f).pending_clients == 0);
    end(&f, 1);
}
static void eof_empty(int family) {
    ++groups;
    fixture_t f;
    start(&f, family, 1);
    mode(&f, true);
    auto_release(&f);
    f.probe_request = true;
    REQUIRE(shutdown(f.peers[0], SHUT_WR) == 0);
    schedule(&f, 0);
    vireo_tcp_server_turn_result_t t[4], old[4];
    memset(t, 0x5a, sizeof(t));
    memcpy(old, t, sizeof(t));
    vireo_tcp_server_round_info_t i;
    REQUIRE(round_at(&f, 0, all_clients, 4, t, &i, NULL) == VIREO_OK);
    CHECK(i.turn_count == 1 && i.close_attempted_count == 1 && i.close_requeued_count == 1 &&
          i.requeued_count == 0 && i.remaining_count == 1 && t[0].close_checked &&
          t[0].close_attempted && t[0].close_result == VIREO_OK && t[0].close_requeued &&
          !t[0].info.ready_to_release && !t[0].info.needs_processing && !t[0].release_attempted &&
          f.close_calls == 1 && f.cleanup_probes == 1 && state(&f).connection_count == 1 &&
          memcmp(t + 1, old + 1, sizeof(t) - sizeof(t[0])) == 0);
    vireo_connection_info_t c = client(&f, 0).connection_info;
    CHECK(c.close_state == VIREO_CONNECTION_CLOSE_READY &&
          c.close_mode == VIREO_CONNECTION_CLOSE_MODE_DRAIN &&
          c.close_reason == VIREO_CONNECTION_CLOSE_REASON_PEER_EOF);
    mode(&f, false); /* 关闭开关不回滚已提交意图；归还开关仍独立。 */
    f.probe_request = false;
    REQUIRE(round_at(&f, 0, all_clients, 4, t, &i, NULL) == VIREO_OK);
    CHECK(t[0].info.ready_to_release && t[0].released && !t[0].close_checked &&
          i.released_count == 1 && f.close_calls == 1 && state(&f).connection_count == 0);
    closed_lease(&f, 0);
    REQUIRE(round_at(&f, 0, all_clients, 4, t, &i, NULL) == VIREO_OK && i.turn_count == 0);
    end(&f, 1);
}
static void cached_eof_fairness(void) {
    ++groups;
    fixture_t f;
    start(&f, AF_UNIX, 2);
    mode(&f, true);
    auto_release(&f);
    feed(&f, 0, 3, 10);
    REQUIRE(shutdown(f.peers[0], SHUT_WR) == 0);
    allowance.process.max_messages = 1;
    schedule(&f, 0);
    schedule(&f, 1);
    vireo_tcp_server_turn_result_t t[4];
    vireo_tcp_server_round_info_t i;
    vireo_tcp_server_round_budget_t one = {1};
    REQUIRE(round_at(&f, 0, one, 1, t, &i, NULL) == VIREO_OK);
    CHECK(same(t[0].client, f.clients[0]) && t[0].info.needs_processing && !t[0].close_attempted &&
          client(&f, 0).connection_info.read_eof &&
          client(&f, 0).connection_info.read_buffer.readable_size == 64 &&
          client(&f, 0).connection_info.close_state == VIREO_CONNECTION_CLOSE_OPEN);
    REQUIRE(round_at(&f, 0, one, 1, t, &i, NULL) == VIREO_OK);
    CHECK(same(t[0].client, f.clients[1]) && !t[0].close_attempted && i.remaining_count == 1);
    REQUIRE(round_at(&f, 0, one, 1, t, &i, NULL) == VIREO_OK && !t[0].close_attempted);
    REQUIRE(round_at(&f, 0, one, 1, t, &i, NULL) == VIREO_OK);
    CHECK(t[0].close_attempted && t[0].close_requeued && !t[0].released && f.handler_calls == 3 &&
          f.sequences[0] == 10 && f.sequences[1] == 11 && f.sequences[2] == 12);
    responses(&f, 0, 3, 10);
    REQUIRE(round_at(&f, 0, one, 1, t, &i, NULL) == VIREO_OK && t[0].released);
    closed_lease(&f, 0);
    end(&f, 2);
}
static void eof_pending_drain(void) {
    ++groups;
    fixture_t f;
    start(&f, AF_INET, 1);
    mode(&f, true);
    auto_release(&f);
    feed(&f, 0, 1, 20);
    REQUIRE(shutdown(f.peers[0], SHUT_WR) == 0);
    allowance.send.max_bytes = 1;
    schedule(&f, 0);
    vireo_tcp_server_turn_result_t t[4];
    vireo_tcp_server_round_info_t i;
    REQUIRE(round_at(&f, 0, all_clients, 4, t, &i, NULL) == VIREO_OK);
    vireo_connection_info_t c = client(&f, 0).connection_info;
    CHECK(t[0].close_attempted && !t[0].close_requeued && !t[0].released &&
          c.close_state == VIREO_CONNECTION_CLOSE_DRAINING && c.write_buffer.readable_size == 31 &&
          c.loop_interests == VIREO_EPOLL_INTEREST_WRITE && i.remaining_count == 0);
    allowance.send.max_bytes = SIZE_MAX;
    REQUIRE(round_at(&f, 100, all_clients, 4, t, &i, NULL) == VIREO_OK);
    CHECK(i.turn_count == 1 && t[0].info.send.sent_bytes == 31 && t[0].info.ready_to_release &&
          t[0].released && !t[0].close_attempted && f.close_calls == 1);
    responses(&f, 0, 1, 20);
    end(&f, 1);
}
static void write_blocked_eof_cache(void) {
    ++groups;
    fixture_t f;
    start(&f, AF_UNIX, 1);
    mode(&f, true);
    auto_release(&f);
    feed(&f, 0, 2, 40);
    REQUIRE(shutdown(f.peers[0], SHUT_WR) == 0);
    vireo_connection_receive_info_t ri;
    REQUIRE(vireo_tcp_server_client_receive(f.server, f.clients[0], &allowance.receive, &ri,
                                            NULL) == VIREO_OK);
    int small = 4096;
    REQUIRE(setsockopt(f.raw_fds[0], SOL_SOCKET, SO_SNDBUF, &small, sizeof(small)) == 0);
    uint8_t raw[128] = {0};
    bool blocked = false;
    for (unsigned n = 0; n < 4096 && !blocked; ++n) {
        REQUIRE(vireo_tcp_server_client_write_enqueue(f.server, f.clients[0], raw, 128, NULL) ==
                VIREO_OK);
        vireo_connection_send_info_t si;
        REQUIRE(vireo_tcp_server_client_send(f.server, f.clients[0], &allowance.send, &si, NULL) ==
                VIREO_OK);
        blocked = si.sent_bytes == 0;
        REQUIRE(blocked || si.sent_bytes == 128);
    }
    REQUIRE(blocked);
    REQUIRE(vireo_tcp_server_client_flow_refresh(f.server, f.clients[0], NULL) == VIREO_OK);
    schedule(&f, 0);
    vireo_tcp_server_turn_result_t t[4];
    vireo_tcp_server_round_info_t i;
    REQUIRE(round_at(&f, 0, all_clients, 4, t, &i, NULL) == VIREO_OK);
    CHECK(!t[0].close_attempted && !t[0].info.needs_processing && i.remaining_count == 0 &&
          client(&f, 0).connection_info.read_buffer.readable_size == 64 &&
          client(&f, 0).connection_info.close_state == VIREO_CONNECTION_CLOSE_OPEN);
    for (;;) {
        ssize_t n = recv(f.peers[0], raw, sizeof(raw), MSG_DONTWAIT);
        if (n < 0) {
            REQUIRE(errno == EAGAIN || errno == EWOULDBLOCK);
            break;
        }
        REQUIRE(n > 0);
    }
    REQUIRE(round_at(&f, 100, all_clients, 4, t, &i, NULL) == VIREO_OK);
    CHECK(t[0].info.send.sent_bytes == 128 && t[0].info.needs_processing && !t[0].close_attempted);
    size_t at = 0;
    while (at < 128) {
        ssize_t n = recv(f.peers[0], raw + at, 128 - at, 0);
        REQUIRE(n > 0);
        at += (size_t)n;
    }
    REQUIRE(round_at(&f, 0, all_clients, 4, t, &i, NULL) == VIREO_OK);
    CHECK(f.handler_calls == 2 && t[0].close_requeued && !t[0].released);
    responses(&f, 0, 2, 40);
    REQUIRE(round_at(&f, 0, all_clients, 4, t, &i, NULL) == VIREO_OK && t[0].released);
    end(&f, 1);
}
static void protocol_failure(bool prefix) {
    ++groups;
    fixture_t f;
    start(&f, AF_UNIX, 1);
    mode(&f, true);
    auto_release(&f);
    uint8_t p[40];
    request(p, 50);
    if (prefix) {
        memset(p + 32, 0, 8);
        transmit(&f, 0, p, 40);
        REQUIRE(shutdown(f.peers[0], SHUT_WR) == 0);
        allowance.process.max_messages = 1;
    } else {
        p[24] ^= 1; /* 改头但保留原CRC，是真实请求帧校验失败。 */
        transmit(&f, 0, p, 32);
    }
    schedule(&f, 0);
    vireo_tcp_server_turn_result_t t[4];
    vireo_tcp_server_round_info_t i;
    vireo_tcp_server_round_error_t e;
    if (prefix) {
        REQUIRE(round_at(&f, 0, all_clients, 4, t, &i, &e) == VIREO_OK);
        CHECK(t[0].info.needs_processing && !t[0].close_attempted && f.handler_calls == 1);
        responses(&f, 0, 1, 50);
    }
    REQUIRE(round_at(&f, 0, all_clients, 4, t, &i, &e) == VIREO_RESULT_PROTOCOL);
    CHECK(e.stage == VIREO_TCP_SERVER_ROUND_DRIVE && t[0].result == VIREO_RESULT_PROTOCOL &&
          t[0].error.primary_stage == VIREO_TCP_SERVER_DRIVE_PROCESS &&
          t[0].error.primary_error.primary.stage == VIREO_TCP_SERVER_CLIENT_FRAMES_PEEK &&
          t[0].close_attempted && t[0].close_result == VIREO_OK && !t[0].close_requeued &&
          !t[0].release_attempted && i.failed_count == 1 && i.close_attempted_count == 1 &&
          state(&f).pending_clients == 0 && state(&f).connection_count == 1 && f.close_calls == 1);
    CHECK(client(&f, 0).connection_info.close_state == VIREO_CONNECTION_CLOSE_READY &&
          client(&f, 0).connection_info.close_reason == VIREO_CONNECTION_CLOSE_REASON_PROTOCOL);
    end(&f, 1);
}
static void socket_failure(bool sending, int code) {
    ++groups;
    fixture_t f;
    start(&f, AF_UNIX, 1);
    mode(&f, true);
    auto_release(&f);
    if (sending) {
        feed(&f, 0, 1, 60);
        f.send_errno = code;
        f.partial_send = code != EINTR;
    } else {
        uint8_t p[32];
        request(p, 60);
        transmit(&f, 0, p, 32);
        f.receive_errno = code;
        f.partial_receive = code != EINTR;
    }
    schedule(&f, 0);
    vireo_tcp_server_turn_result_t t[4];
    vireo_tcp_server_round_info_t i;
    vireo_tcp_server_round_error_t e;
    REQUIRE(round_at(&f, 0, all_clients, 4, t, &i, &e) == VIREO_RESULT_IO);
    CHECK(e.stage == VIREO_TCP_SERVER_ROUND_DRIVE && i.failed_count == 1 && t[0].close_checked &&
          t[0].close_attempted == (code != EINTR) && t[0].close_result == VIREO_OK &&
          t[0].error.primary_error.primary.connection_error.system_errno == code &&
          !t[0].close_requeued && !t[0].release_attempted && i.remaining_count == 0 &&
          state(&f).connection_count == 1 && f.close_calls == (code == EINTR ? 0u : 1u));
    vireo_connection_info_t c = client(&f, 0).connection_info;
    CHECK(c.close_state ==
          (code == EINTR ? VIREO_CONNECTION_CLOSE_OPEN : VIREO_CONNECTION_CLOSE_READY));
    if (sending)
        CHECK(t[0].info.send.sent_bytes == (code == EINTR ? 0u : 8u) &&
              c.write_buffer.readable_size == (code == EINTR ? 32u : 24u));
    else
        CHECK(t[0].info.receive.received_bytes == (code == EINTR ? 0u : 16u) &&
              c.read_buffer.readable_size == (code == EINTR ? 0u : 16u));
    end(&f, 1);
}
static void draining_upgrade(void) {
    ++groups;
    fixture_t f;
    start(&f, AF_UNIX, 1);
    mode(&f, true);
    uint8_t p[16] = {0};
    REQUIRE(vireo_tcp_server_client_write_enqueue(f.server, f.clients[0], p, sizeof(p), NULL) ==
            VIREO_OK);
    closing(&f, 0, VIREO_CONNECTION_CLOSE_MODE_DRAIN);
    f.close_calls = 0;
    f.send_errno = EPIPE;
    f.partial_send = true;
    schedule(&f, 0);
    vireo_tcp_server_turn_result_t t[4];
    vireo_tcp_server_round_info_t i;
    REQUIRE(round_at(&f, 0, all_clients, 4, t, &i, NULL) == VIREO_RESULT_IO);
    vireo_connection_info_t c = client(&f, 0).connection_info;
    CHECK(t[0].close_attempted && f.close_calls == 1 &&
          c.close_state == VIREO_CONNECTION_CLOSE_READY &&
          c.close_mode == VIREO_CONNECTION_CLOSE_MODE_IMMEDIATE &&
          c.close_reason == VIREO_CONNECTION_CLOSE_REASON_APPLICATION &&
          c.write_buffer.readable_size == 8);
    end(&f, 1);
}
static void excluded_failure(unsigned source) {
    ++groups;
    fixture_t f;
    start(&f, AF_UNIX, 1);
    mode(&f, true);
    feed(&f, 0, 1, 70);
    if (source < 2) {
        f.fail_sequence = 70;
        f.handler_return = source == 0 ? VIREO_RESULT_IO : VIREO_RESULT_PROTOCOL;
    } else if (source == 2)
        f.bad_reply = true;
    else if (source == 3)
        f.fail_sync = true;
    else
        f.fail_refresh_on = 2;
    schedule(&f, 0);
    vireo_tcp_server_turn_result_t t[4];
    vireo_tcp_server_round_info_t i;
    vireo_tcp_server_round_error_t e;
    vireo_result_t expected = source == 1 || source == 2 ? VIREO_RESULT_PROTOCOL : VIREO_RESULT_IO;
    REQUIRE(round_at(&f, 0, all_clients, 4, t, &i, &e) == expected);
    CHECK(t[0].close_checked && !t[0].close_attempted && t[0].close_result == VIREO_OK &&
          f.close_calls == 0 &&
          client(&f, 0).connection_info.close_state == VIREO_CONNECTION_CLOSE_OPEN &&
          e.stage == VIREO_TCP_SERVER_ROUND_DRIVE && !t[0].release_attempted);
    if (source < 2)
        CHECK(t[0].error.primary_error.primary.stage == VIREO_TCP_SERVER_CLIENT_HANDLER &&
              t[0].error.sync_result == VIREO_RESULT_IO);
    if (source == 2)
        CHECK(t[0].error.primary_error.primary.stage == VIREO_TCP_SERVER_CLIENT_RESPONSE);
    if (source == 4)
        responses(&f, 0, 1, 70);
    end(&f, 1);
}
static void strategy_failure(unsigned kind) {
    ++groups;
    fixture_t f;
    start(&f, AF_UNIX, 1);
    mode(&f, true);
    auto_release(&f);
    REQUIRE(shutdown(f.peers[0], SHUT_WR) == 0);
    f.fail_policy_inspect = kind == 0;
    f.fail_policy_lookup = kind == 1;
    f.request_io = kind == 2;
    schedule(&f, 0);
    vireo_tcp_server_turn_result_t t[4];
    vireo_tcp_server_round_info_t i;
    vireo_tcp_server_round_error_t e;
    vireo_result_t expected = kind == 1 ? VIREO_RESULT_NOT_FOUND : VIREO_RESULT_IO;
    REQUIRE(round_at(&f, 0, all_clients, 4, t, &i, &e) == expected);
    CHECK(i.succeeded_count == 1 && i.failed_count == 0 &&
          e.stage == VIREO_TCP_SERVER_ROUND_CLOSE && t[0].result == VIREO_OK &&
          t[0].close_checked && t[0].close_attempted == (kind == 2) &&
          t[0].close_result == expected && e.close_result == expected && !t[0].close_requeued &&
          !t[0].release_attempted && i.remaining_count == 0 && state(&f).connection_count == 1);
    if (kind == 2)
        CHECK(t[0].close_error.primary.loop_error.loop_error.epoll_error.system_errno == EIO);
    f.fail_policy_inspect = f.fail_policy_lookup = f.request_io = false;
    CHECK(client(&f, 0).connection_info.close_state ==
          (kind == 2 ? VIREO_CONNECTION_CLOSE_READY : VIREO_CONNECTION_CLOSE_OPEN));
    schedule(&f, 0); /* 修复由调用者明确安排，失败没有隐式回队。 */
    REQUIRE(round_at(&f, 0, all_clients, 4, t, &i, NULL) == VIREO_OK);
    if (kind == 2)
        CHECK(t[0].released && f.close_calls == 1);
    else
        CHECK(t[0].close_requeued && t[0].close_attempted);
    end(&f, 1);
}
static void serve_multiple_errors(void) {
    ++groups;
    fixture_t f;
    start(&f, AF_UNIX, 4);
    enable(&f);
    mode(&f, true);
    auto_release(&f);
    CHECK(!state(&f).listener_read_enabled);
    closing(&f, 0, VIREO_CONNECTION_CLOSE_MODE_IMMEDIATE);
    f.close_calls = 0;
    schedule(&f, 0);
    schedule(&f, 1);
    schedule(&f, 2);
    f.receive_errno = ECONNRESET;
    f.fail_refresh_on = 2;
    f.request_io = true;
    f.fail_mod_on = f.mod_calls + 1;
    vireo_tcp_server_turn_result_t t[4];
    vireo_connection_pool_lease_t c[4] = {{0}};
    vireo_tcp_server_serve_info_t i;
    vireo_tcp_server_serve_error_t e;
    REQUIRE(serve(&f, defaults(), t, 4, c, 4, &i, &e) == VIREO_RESULT_IO);
    CHECK(i.round.turn_count == 2 && t[0].released && t[1].result == VIREO_RESULT_IO &&
          t[1].error.primary_stage == VIREO_TCP_SERVER_DRIVE_RECEIVE &&
          t[1].error.primary_error.primary.connection_error.system_errno == ECONNRESET &&
          t[1].error.sync_result == VIREO_RESULT_IO && t[1].close_result == VIREO_RESULT_IO &&
          t[1].close_attempted && !t[1].released &&
          e.round_error.stage == VIREO_TCP_SERVER_ROUND_DRIVE &&
          e.round_error.close_result == VIREO_RESULT_IO && e.sync_result == VIREO_RESULT_IO &&
          i.round.remaining_count == 1 && state(&f).connection_count == 3 &&
          i.admission.admitted_count == 0);
    f.fail_mod_on = f.fail_refresh_on = 0;
    end(&f, 4);
}
static void rejection_wait_stop(void) {
    ++groups;
    fixture_t f;
    start(&f, AF_UNIX, 1);
    enable(&f);
    mode(&f, true);
    schedule(&f, 0);
    vireo_tcp_server_turn_result_t t[4], old[4];
    vireo_tcp_server_round_info_t i, saved;
    memset(t, 0x5a, sizeof(t));
    memcpy(old, t, sizeof(t));
    memset(&i, 0x5a, sizeof(i));
    saved = i;
    CHECK(round_at(&f, -2, all_clients, 4, t, &i, NULL) == VIREO_RESULT_INVALID_ARGUMENT &&
          memcmp(t, old, sizeof(t)) == 0 && memcmp(&i, &saved, sizeof(i)) == 0);
    f.wait_io = true;
    CHECK(round_at(&f, 0, all_clients, 4, t, &i, NULL) == VIREO_RESULT_IO &&
          memcmp(t, old, sizeof(t)) == 0 && memcmp(&i, &saved, sizeof(i)) == 0 &&
          state(&f).pending_clients == 1 && f.close_calls == 0);
    f.wait_io = false;
    REQUIRE(vireo_tcp_server_request_stop(f.server, NULL) == VIREO_OK);
    REQUIRE(round_at(&f, 0, all_clients, 4, t, &i, NULL) == VIREO_OK);
    CHECK(i.turn_count == 0 && i.close_attempted_count == 0 && i.close_requeued_count == 0 &&
          memcmp(t, old, sizeof(t)) == 0 && state(&f).pending_clients == 1);
    vireo_tcp_server_serve_info_t si;
    vireo_connection_pool_lease_t c[4] = {{0}};
    REQUIRE(serve(&f, defaults(), t, 4, c, 4, &si, NULL) == VIREO_OK);
    CHECK(si.round.turn_count == 0 && f.close_calls == 0 && memcmp(t, old, sizeof(t)) == 0);
    mode(&f, false);
    end(&f, 1);
}
static void shutdown_independent(void) {
    ++groups;
    fixture_t f;
    start(&f, AF_UNIX, 1);
    mode(&f, true);
    REQUIRE(vireo_tcp_server_request_stop(f.server, NULL) == VIREO_OK);
    f.probe_cleanup = true;
    vireo_tcp_server_shutdown_budget_t b = {4};
    vireo_tcp_server_shutdown_result_t out[4];
    vireo_tcp_server_shutdown_info_t i;
    REQUIRE(vireo_tcp_server_shutdown_batch(f.server, &b, out, 4, &i, NULL) == VIREO_OK);
    CHECK(i.released_clients == 1 && f.close_calls == 0 && f.cleanup_probes == 2 &&
          state(&f).connection_count == 0);
    end(&f, 1);
}
typedef struct observation {
    fixture_t *f;
    unsigned calls;
    bool failure;
} observation_t;
static void observe(vireo_tcp_server_t *server, vireo_result_t result,
                    vireo_tcp_server_serve_info_t const *info,
                    vireo_tcp_server_turn_result_t const *turns,
                    vireo_connection_pool_lease_t const *clients,
                    vireo_tcp_server_serve_error_t const *error, void *ctx) {
    (void)clients;
    observation_t *o = ctx;
    ++o->calls;
    CHECK(state(o->f).running_active && !state(o->f).serving_active &&
          vireo_tcp_server_destroy(&server, NULL) == VIREO_RESULT_BUSY);
    if (o->failure) {
        CHECK(result == VIREO_RESULT_IO && info->round.turn_count == 1 &&
              turns[0].close_attempted && turns[0].close_result == VIREO_RESULT_IO &&
              error->round_error.stage == VIREO_TCP_SERVER_ROUND_DRIVE);
        REQUIRE(vireo_tcp_server_request_stop(server, NULL) == VIREO_OK);
    } else {
        CHECK(result == VIREO_OK && info->round.turn_count == 1);
        if (o->calls == 1) {
            CHECK(!turns[0].close_checked && same(turns[0].client, o->f->clients[0]));
            mode(o->f, true);
            schedule(o->f, 0);
        } else if (o->calls <= 3)
            CHECK(turns[0].close_requeued && !turns[0].released);
        else
            CHECK(turns[0].released && turns[0].info.ready_to_release);
        if (o->calls == 5)
            REQUIRE(vireo_tcp_server_request_stop(server, NULL) == VIREO_OK);
    }
    errno = ERANGE;
}
static void running_modes(bool failure) {
    ++groups;
    fixture_t f;
    size_t count = failure ? 1u : 2u;
    start(&f, AF_UNIX, count);
    enable(&f);
    auto_release(&f);
    for (size_t k = 0; k < count; ++k) {
        REQUIRE(shutdown(f.peers[k], SHUT_WR) == 0);
        schedule(&f, k);
    }
    if (failure) {
        mode(&f, true);
        f.receive_errno = ECONNRESET;
        f.request_io = true;
    }
    vireo_tcp_server_run_options_t options = {limits, allowance, {1}, {1, 4}};
    uint8_t w[96];
    vireo_tcp_server_turn_result_t t[4];
    vireo_connection_pool_lease_t c[4] = {{0}};
    vireo_tcp_server_run_error_t e;
    observation_t o = {&f, 0, failure};
    errno = EDOM;
    vireo_result_t r =
        vireo_tcp_server_run(f.server, &options, w, 96, handler, &f, t, 4, c, 4, observe, &o, &e);
    CHECK(r == (failure ? VIREO_RESULT_IO : VIREO_OK) && errno == EDOM &&
          state(&f).stop_requested && !state(&f).running_active && o.calls == (failure ? 1u : 5u));
    if (failure)
        CHECK(e.stage == VIREO_TCP_SERVER_RUN_SERVE && e.round_available &&
              e.serve_error.round_error.stage == VIREO_TCP_SERVER_ROUND_DRIVE &&
              state(&f).connection_count == 1);
    else
        CHECK(state(&f).connection_count == 0 && state(&f).pending_clients == 0);
    end(&f, count);
}
static void successful_handler_and_nested(void) {
    ++groups;
    fixture_t f, nested;
    start(&nested, AF_UNIX, 1);
    mode(&nested, true);
    feed(&nested, 0, 1, 90);
    schedule(&nested, 0);
    start(&f, AF_UNIX, 1);
    mode(&f, true);
    feed(&f, 0, 1, 80);
    schedule(&f, 0);
    f.nested = &nested;
    f.probe_handler = f.probe_wait = true;
    vireo_tcp_server_turn_result_t t[4];
    vireo_tcp_server_round_info_t i;
    REQUIRE(round_at(&f, 0, all_clients, 4, t, &i, NULL) == VIREO_OK);
    CHECK(t[0].close_checked && !t[0].close_attempted && f.cleanup_probes == 2 &&
          f.handler_calls == 1 && nested.handler_calls == 1);
    responses(&f, 0, 1, 80);
    responses(&nested, 0, 1, 90);
    f.probe_handler = f.probe_wait = false;
    end(&f, 1);
    end(&nested, 1);
}
/* ERROR/HANGUP 是事件提示，不能凭通知推断recv EOF或收发失败。 */
static void notification_and_independent_release(void) {
    ++groups;
    fixture_t f;
    start(&f, AF_UNIX, 1);
    mode(&f, true);
    f.callbacks[0](f.objects[0], VIREO_EPOLL_EVENT_ERROR | VIREO_EPOLL_EVENT_HANGUP,
                   f.callback_contexts[0]);
    vireo_tcp_server_turn_result_t t[4];
    vireo_tcp_server_round_info_t i;
    REQUIRE(round_at(&f, 0, all_clients, 4, t, &i, NULL) == VIREO_OK);
    CHECK(t[0].close_checked && !t[0].close_attempted &&
          (t[0].events & VIREO_EPOLL_EVENT_HANGUP) != 0 && f.close_calls == 0 &&
          client(&f, 0).connection_info.close_state == VIREO_CONNECTION_CLOSE_OPEN);
    REQUIRE(shutdown(f.peers[0], SHUT_WR) == 0);
    schedule(&f, 0);
    REQUIRE(round_at(&f, 0, all_clients, 4, t, &i, NULL) == VIREO_OK);
    CHECK(t[0].close_requeued && !state(&f).auto_release_ready && !t[0].released);
    REQUIRE(round_at(&f, 0, all_clients, 4, t, &i, NULL) == VIREO_OK);
    CHECK(t[0].info.ready_to_release && !t[0].release_attempted && !t[0].close_attempted &&
          i.remaining_count == 0 && state(&f).connection_count == 1 && f.close_calls == 1);
    end(&f, 1);
}
int main(void) {
    unsigned before = fd_count();
    defaults_and_explicit();
    notification_and_independent_release();
    eof_empty(AF_UNIX);
    eof_empty(AF_INET);
    cached_eof_fairness();
    eof_pending_drain();
    write_blocked_eof_cache();
    protocol_failure(false);
    protocol_failure(true);
    socket_failure(false, ECONNRESET);
    socket_failure(true, EPIPE);
    socket_failure(false, EINTR);
    socket_failure(true, EINTR);
    draining_upgrade();
    for (unsigned k = 0; k < 5; ++k)
        excluded_failure(k);
    for (unsigned k = 0; k < 3; ++k)
        strategy_failure(k);
    serve_multiple_errors();
    rejection_wait_stop();
    shutdown_independent();
    running_modes(false);
    running_modes(true);
    successful_handler_and_nested();
    unsigned after = fd_count();
    CHECK(before == after);
    printf("tcp_server close policy: %u groups, %u failures, fd %u -> %u\n", groups, failures,
           before, after);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
