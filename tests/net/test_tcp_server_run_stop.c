/*
- PROJECT : VIREO
- FILE    : test_tcp_server_run_stop.c
- AUTHOR  : bitofux
- DATE    : 2026-10-06
- BRIEF   : 此模块负责：
- -- 连续运行、逐轮借用/递归边界与永久停止真实唤醒
- -- 当前轮完成、首错误优先、固定结果复用与消费资源边界
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdatomic.h>
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
typedef struct wait_gate {
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    bool entered;
} wait_gate_t;
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
    wait_gate_t *gate;
    _Atomic unsigned stop_calls;
    bool stop_fault, stop_on_accept, stop_on_handler;
    unsigned stop_on_wait;

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
    if (f->gate != NULL) {
        REQUIRE(pthread_mutex_lock(&f->gate->mutex) == 0);
        f->gate->entered = true;
        REQUIRE(pthread_cond_signal(&f->gate->condition) == 0);
        REQUIRE(pthread_mutex_unlock(&f->gate->mutex) == 0);
    }
    if (f->stop_on_wait == f->wait_calls)
        REQUIRE(vireo_tcp_server_request_stop(f->server, NULL) == VIREO_OK);

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
    if (f->stop_on_accept) REQUIRE(vireo_tcp_server_request_stop(f->server, NULL) == VIREO_OK);
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
/** 本层停止seam只调用public loop；注入IO前先真实提交意图，不读Reactor状态。 */
static vireo_result_t stop_bridge(void *ctx, vireo_event_loop_t *loop,
    vireo_event_loop_error_t *error) {
    fixture_t *f = ctx;
    atomic_fetch_add_explicit(&f->stop_calls, 1, memory_order_relaxed);
    vireo_result_t const result = vireo_event_loop_request_stop(loop, error);
    if (result == VIREO_OK && f->stop_fault) {
        *error = (vireo_event_loop_error_t){.stage = VIREO_EVENT_LOOP_STAGE_STOP_NOTIFY,
            .system_errno = EINTR};
        errno = ERANGE;
        return VIREO_RESULT_IO;
    }
    return result;
}
static void start(fixture_t *f, int family, size_t count) {
    *f = (fixture_t){0};
    atomic_init(&f->stop_calls, 0);
    vireo_tcp_server_client_ops_t const c = ops(f);
    vireo_tcp_server_scheduler_ops_t const w = {f, wait_once};
    vireo_tcp_server_listener_ops_t const l = listener_ops(f);
    vireo_tcp_server_stop_ops_t const stop = {f, stop_bridge};
    REQUIRE(vireo_tcp_server_create_with_run_ops(&server_options, NULL, &l, &c, &w, &stop,
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
    if (f->stop_on_handler) REQUIRE(vireo_tcp_server_request_stop(f->server, NULL) == VIREO_OK);
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


typedef struct observation {
    fixture_t *fixture;
    unsigned calls, stop_after;
    bool release, operations, recurse, disable_policy, unbind_policy, next_peer, nested_run;
    vireo_tcp_server_run_options_t *mutate_options;
    vireo_result_t result;
    vireo_tcp_server_serve_info_t info;
    vireo_tcp_server_serve_error_t error;
    vireo_connection_pool_lease_t saved[4];
    size_t saved_count;
} observation_t;
static vireo_tcp_server_run_options_t run_defaults(void) {
    return (vireo_tcp_server_run_options_t){limits, allowance, all_clients, {4, 16}};
}
static void observe(vireo_tcp_server_t *server, vireo_result_t result,
    vireo_tcp_server_serve_info_t const *info, vireo_tcp_server_turn_result_t const *turns,
    vireo_connection_pool_lease_t const *clients, vireo_tcp_server_serve_error_t const *error,
    void *ctx) {
    observation_t *o = ctx;
    fixture_t *f = o->fixture;
    ++o->calls;
    vireo_tcp_server_info_t snapshot = state(f);
    CHECK(server == f->server && snapshot.running_active && !snapshot.serving_active &&
        !snapshot.scheduling_active && !snapshot.driving_active && !snapshot.processing_active);
    CHECK(info->sync_called && info->round.turn_count <= 4 && info->admission.admitted_count <= 4);
    o->result = result; o->info = *info; o->error = *error;
    for (size_t k = 0; k < info->round.turn_count; ++k)
        CHECK(turns[k].result == VIREO_OK || result != VIREO_OK);
    for (size_t k = 0; k < info->admission.admitted_count; ++k) {
        REQUIRE(o->saved_count < 4);
        o->saved[o->saved_count++] = clients[k];
        CHECK(!empty(clients[k]));
        if (o->release) {
            vireo_connection_pool_lease_t copy = clients[k];
            CHECK(vireo_tcp_server_release_client(server, &copy, NULL) == VIREO_OK && empty(copy));
        }
    }
    if (o->recurse) {
        uint8_t w[96]; vireo_tcp_server_turn_result_t t[4];
        vireo_connection_pool_lease_t c[4] = {{0}};
        vireo_tcp_server_serve_info_t si; vireo_tcp_server_round_info_t ri;
        vireo_tcp_server_run_options_t ro = run_defaults();
        vireo_tcp_server_serve_options_t so = defaults();
        CHECK(vireo_tcp_server_run(server, &ro, w, 96, handler, f, t, 4, c, 4,
            observe, o, NULL) == VIREO_RESULT_BUSY);
        CHECK(vireo_tcp_server_run_once(server, 0, &limits, &allowance, &all_clients,
            w, 96, handler, f, t, 4, &ri, NULL) == VIREO_RESULT_BUSY);
        CHECK(vireo_tcp_server_serve_once(server, &so, w, 96, handler, f, t, 4, c, 4,
            &si, NULL) == VIREO_RESULT_BUSY);
        CHECK(vireo_tcp_server_destroy(&f->server, NULL) == VIREO_RESULT_BUSY && server == f->server);
    }
    if (o->operations) {
        uint8_t const *bytes; size_t count;
        CHECK(vireo_tcp_server_client_read_peek(server, f->clients[0], &bytes, &count, NULL) == VIREO_OK);
        CHECK(vireo_tcp_server_client_read_consume(server, f->clients[0], 0, NULL) == VIREO_OK);
        CHECK(vireo_tcp_server_client_write_enqueue(server, f->clients[0], NULL, 0, NULL) == VIREO_OK);
        CHECK(vireo_tcp_server_client_flow_refresh(server, f->clients[0], NULL) == VIREO_OK);
        CHECK(vireo_tcp_server_schedule_client(server, f->clients[0], NULL) == VIREO_OK);
        CHECK(vireo_tcp_server_admission_refresh(server, NULL) == VIREO_OK);
        vireo_connection_pool_lease_t copy = f->clients[0];
        CHECK(vireo_tcp_server_release_client(server, &copy, NULL) == VIREO_OK && empty(copy));
        f->clients[0] = copy;
    }
    if (o->nested_run) {
        fixture_t nested; start(&nested, AF_UNIX, 0);
        REQUIRE(vireo_tcp_server_request_stop(nested.server, NULL) == VIREO_OK);
        uint8_t w[96]; vireo_tcp_server_turn_result_t t[4];
        vireo_connection_pool_lease_t c[4] = {{0}};
        vireo_tcp_server_run_options_t ro = run_defaults();
        CHECK(vireo_tcp_server_run(nested.server, &ro, w, 96, handler, &nested, t, 4, c, 4,
            observe, o, NULL) == VIREO_OK);
        end(&nested, 0);
    }
    if (o->mutate_options != NULL) *o->mutate_options = (vireo_tcp_server_run_options_t){0};
    if (o->next_peer && o->calls == 1) f->peers[1] = connect_peer(f);
    if (o->disable_policy) CHECK(vireo_tcp_server_admission_disable(server, NULL) == VIREO_OK);
    if (o->unbind_policy) CHECK(vireo_tcp_server_unbind_listener(server, NULL) == VIREO_OK);
    if (o->stop_after != 0 && o->calls == o->stop_after)
        CHECK(vireo_tcp_server_request_stop(server, NULL) == VIREO_OK);
    errno = ERANGE;
}
static vireo_result_t execute(fixture_t *f, vireo_tcp_server_run_options_t *options,
    observation_t *observer, vireo_tcp_server_run_error_t *error) {
    uint8_t workspace[96]; vireo_tcp_server_turn_result_t turns[4];
    vireo_connection_pool_lease_t clients[4] = {{0}};
    observer->fixture = f;
    errno = EDOM;
    vireo_result_t const result = vireo_tcp_server_run(f->server, options, workspace, 96,
        handler, f, turns, 4, clients, 4, observe, observer, error);
    CHECK(errno == EDOM && !state(f).running_active && !state(f).serving_active);
    return result;
}
static void parameter_rejections(void) {
    ++groups;
    fixture_t f; start(&f, AF_UNIX, 0); enable(&f);
    vireo_tcp_server_run_options_t o = run_defaults();
    vireo_tcp_server_turn_result_t t[4], saved[4]; memset(t, 0x5a, sizeof(t)); memcpy(saved, t, sizeof(t));
    uint8_t w[96], old[96]; memset(w, 0x6b, sizeof(w)); memcpy(old, w, sizeof(w));
    vireo_connection_pool_lease_t c[4] = {{0}};
    observation_t ob = {.fixture = &f};
    vireo_tcp_server_run_error_t e;
#define CALL(S,O,W,WC,H,T,TC,C,CC,CB) vireo_tcp_server_run(S,O,W,WC,H,&f,T,TC,C,CC,CB,&ob,&e)
    errno = EDOM;
    CHECK(CALL(NULL,&o,w,96,handler,t,4,c,4,observe) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(CALL(f.server,NULL,w,96,handler,t,4,c,4,observe) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(CALL(f.server,&o,NULL,96,handler,t,4,c,4,observe) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(CALL(f.server,&o,w,96,NULL,t,4,c,4,observe) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(CALL(f.server,&o,w,96,handler,NULL,4,c,4,observe) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(CALL(f.server,&o,w,96,handler,t,4,NULL,4,observe) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(CALL(f.server,&o,w,96,handler,t,4,c,4,NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(CALL(f.server,&o,w,95,handler,t,4,c,4,observe) == VIREO_RESULT_RANGE);
    CHECK(CALL(f.server,&o,w,96,handler,t,0,c,4,observe) == VIREO_RESULT_RANGE);
    CHECK(CALL(f.server,&o,w,96,handler,t,4,c,65536,observe) == VIREO_RESULT_RANGE);
    o.admit.max_accept_syscalls = 0;
    CHECK(CALL(f.server,&o,w,96,handler,t,4,c,4,observe) == VIREO_RESULT_INVALID_ARGUMENT);
    o = run_defaults(); o.drive.receive.max_bytes = 0;
    CHECK(CALL(f.server,&o,w,96,handler,t,4,c,4,observe) == VIREO_RESULT_RANGE);
    o = run_defaults(); c[0].pool_id = 1;
    CHECK(CALL(f.server,&o,w,96,handler,t,4,c,4,observe) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(e.stage == VIREO_TCP_SERVER_RUN_NONE && !e.round_available && errno == EDOM);
    CHECK(!memcmp(w,old,96) && !memcmp(t,saved,sizeof(t)) && c[0].pool_id == 1 &&
        f.wait_calls == 0 && ob.calls == 0 && !state(&f).running_active);
#undef CALL
    end(&f,0);
}
static void stopped_no_policy(void) {
    ++groups;
    fixture_t f; start(&f,AF_UNIX,0);
    vireo_event_loop_error_t cause;
    errno=EDOM;
    CHECK(vireo_tcp_server_request_stop(NULL,&cause)==VIREO_RESULT_INVALID_ARGUMENT && errno==EDOM);
    CHECK(cause.stage==VIREO_EVENT_LOOP_STAGE_NONE && cause.system_errno==0);
    CHECK(vireo_tcp_server_request_stop(f.server,NULL)==VIREO_OK);
    CHECK(vireo_tcp_server_request_stop(f.server,&cause)==VIREO_OK && errno==EDOM);
    CHECK(state(&f).stop_requested && !state(&f).running_active);
    vireo_tcp_server_run_options_t o=run_defaults(); observation_t ob={0};
    CHECK(execute(&f,&o,&ob,NULL)==VIREO_OK && !ob.calls && !f.wait_calls);
    o.admit.max_accepts=0;
    CHECK(execute(&f,&o,&ob,NULL)==VIREO_RESULT_INVALID_ARGUMENT);
    end(&f,0);
}
static void stopped_finite(void) {
    ++groups;
    fixture_t f; start(&f,AF_INET,1); enable(&f); feed(&f,0,1,19); schedule(&f,0);
    REQUIRE(vireo_tcp_server_request_stop(f.server,NULL)==VIREO_OK);
    uint8_t w[96], ws[96]; memset(w,0x6a,96);memcpy(ws,w,96);
    vireo_tcp_server_turn_result_t t[4], ts[4];memset(t,0x5a,sizeof(t));memcpy(ts,t,sizeof(t));
    vireo_connection_pool_lease_t c[4]={{0}},cs[4];memcpy(cs,c,sizeof(c));
    vireo_tcp_server_round_info_t ri; vireo_tcp_server_serve_info_t si;
    memset(&ri,0x5a,sizeof(ri)); memset(&si,0x5a,sizeof(si));
    CHECK(vireo_tcp_server_run_once(f.server,-1,&limits,&allowance,&all_clients,w,96,handler,&f,t,4,&ri,NULL)==VIREO_OK);
    vireo_tcp_server_serve_options_t o=defaults();o.timeout_ms=-1;
    CHECK(vireo_tcp_server_serve_once(f.server,&o,w,96,handler,&f,t,4,c,4,&si,NULL)==VIREO_OK);
    CHECK(ri.turn_count==0 && ri.wait.ready_count==0 && si.round.turn_count==0 && !si.sync_called && !si.admission_called);
    CHECK(!memcmp(w,ws,96) && !memcmp(t,ts,sizeof(t)) && !memcmp(c,cs,sizeof(c)));
    CHECK(state(&f).pending_clients==1 && state(&f).connection_count==1 && !f.handler_calls && !f.wait_calls);
    CHECK(client(&f,0).connection_info.read_buffer.readable_size==32);
    CHECK(vireo_tcp_server_destroy(&f.server,NULL)==VIREO_RESULT_BUSY);
    o.admit.max_accepts=0;
    CHECK(vireo_tcp_server_serve_once(f.server,&o,w,96,handler,&f,t,4,c,4,&si,NULL)==VIREO_RESULT_INVALID_ARGUMENT);
    end(&f,1);
}
static void buffered_rounds(void) {
    ++groups;
    fixture_t f;start(&f,AF_UNIX,1);enable(&f);feed(&f,0,3,101);schedule(&f,0);
    f.probe_wait=true;f.probe_handler=true;
    vireo_tcp_server_run_options_t o=run_defaults();o.drive.process=(vireo_tcp_server_process_budget_t){1,96,96};
    observation_t ob={.stop_after=3,.recurse=true,.nested_run=true};
    vireo_tcp_server_run_error_t e;
    CHECK(execute(&f,&o,&ob,&e)==VIREO_OK && ob.calls==3 && f.handler_calls==3 && f.wait_calls==3);
    CHECK(f.observed_timeout==0 && ob.info.round.turn_count==1 && e.stage==VIREO_TCP_SERVER_RUN_NONE);
    CHECK(state(&f).stop_requested && state(&f).connection_count==1);
    responses(&f,0,3,101); end(&f,1);
}
static void callback_operations(void) {
    ++groups;
    fixture_t f;start(&f,AF_INET,1);enable(&f);feed(&f,0,1,151);schedule(&f,0);
    vireo_tcp_server_run_options_t o=run_defaults();observation_t ob={.stop_after=1,.operations=true,.recurse=true};
    CHECK(execute(&f,&o,&ob,NULL)==VIREO_OK && ob.calls==1);
    CHECK(state(&f).connection_count==0 && state(&f).pending_clients==0);
    responses(&f,0,1,151);end(&f,1);
}
static void automatic_reuse(int family, bool release) {
    ++groups;
    fixture_t f;start(&f,family,0);enable(&f);f.peers[0]=connect_peer(&f);
    vireo_tcp_server_run_options_t o=run_defaults();o.admit.max_accepts=1;
    observation_t ob={.stop_after=2,.next_peer=true,.release=release,.mutate_options=&o};
    CHECK(execute(&f,&o,&ob,NULL)==VIREO_OK && ob.calls==2 && ob.saved_count==2 && f.wait_calls==2);
    CHECK(state(&f).connection_count==(release?0:2) && f.observed_timeout==-1);
    CHECK(!same(ob.saved[0],ob.saved[1]));
    if (!release) {f.clients[0]=ob.saved[0];f.clients[1]=ob.saved[1];}
    end(&f,2);
}
static void policy_changed(bool unbind) {
    ++groups;
    fixture_t f;start(&f,AF_UNIX,1);enable(&f);schedule(&f,0);
    vireo_tcp_server_run_options_t o=run_defaults();observation_t ob={.disable_policy=!unbind,.unbind_policy=unbind};
    vireo_tcp_server_run_error_t e;
    CHECK(execute(&f,&o,&ob,&e)==VIREO_RESULT_NOT_FOUND && ob.calls==1 && f.wait_calls==1);
    CHECK(e.stage==VIREO_TCP_SERVER_RUN_SERVE && !e.round_available && !e.round_info.sync_called);
    CHECK(!state(&f).running_active && !state(&f).admission_enabled);
    end(&f,1);
}
static void before_wait_fail(void) {
    ++groups;
    fixture_t f;start(&f,AF_INET,1);enable(&f);schedule(&f,0);f.wait_io=true;
    vireo_tcp_server_run_options_t o=run_defaults();observation_t ob={0};vireo_tcp_server_run_error_t e;
    CHECK(execute(&f,&o,&ob,&e)==VIREO_RESULT_IO && ob.calls==0 && f.wait_calls==1);
    CHECK(e.stage==VIREO_TCP_SERVER_RUN_SERVE && !e.round_available &&
        e.serve_error.round_error.loop_error.epoll_error.system_errno==EINTR);
    CHECK(state(&f).pending_clients==1);end(&f,1);
}
static void error_round(unsigned kind) {
    ++groups;
    fixture_t f;start(&f,AF_UNIX,kind==0?1:0);enable(&f);
    if(kind==0){feed(&f,0,1,211);schedule(&f,0);f.fail_sequence=211;f.stop_on_handler=true;}
    else if(kind==1)f.listener_injected_events=VIREO_EPOLL_EVENT_ERROR;
    else {f.peers[0]=connect_peer(&f);f.fail_flow_on=1;}
    /* 人工通知场景必须非阻塞public wait，停止意图让真正wait立即返回。 */
    if(kind==1)f.stop_on_wait=1;
    vireo_tcp_server_run_options_t o=run_defaults();observation_t ob={.stop_after=1};vireo_tcp_server_run_error_t e;
    CHECK(execute(&f,&o,&ob,&e)==VIREO_RESULT_IO && ob.calls==1 && ob.result==VIREO_RESULT_IO);
    CHECK(e.round_available && e.round_info.sync_called && state(&f).stop_requested && !state(&f).running_active);
    if(kind==0){CHECK(ob.info.round.failed_count==1 && ob.info.round.turn_count==1 && f.handler_calls==1);
        CHECK(e.serve_error.round_error.drive_error.primary_error.primary.handler_result==VIREO_RESULT_IO);}
    else if(kind==1){CHECK(e.serve_error.stage==VIREO_TCP_SERVER_SERVE_LISTENER_EVENT &&
        e.serve_error.listener_events==VIREO_EPOLL_EVENT_ERROR && f.accept_calls_total==0);}
    else {CHECK(ob.saved_count==1 && ob.info.admission.admitted_count==1 && ob.info.initialized_count==0);
        CHECK(e.serve_error.stage==VIREO_TCP_SERVER_SERVE_INITIALIZE && same(e.serve_error.client,ob.saved[0]));f.clients[0]=ob.saved[0];}
    end(&f,kind==1?0:1);
}
static void stop_current_admission(void) {
    ++groups;
    fixture_t f;start(&f,AF_INET,0);enable(&f);f.peers[0]=connect_peer(&f);f.peers[1]=connect_peer(&f);
    f.stop_on_accept=true;
    vireo_tcp_server_run_options_t o=run_defaults();o.admit.max_accepts=2;
    observation_t ob={0};
    CHECK(execute(&f,&o,&ob,NULL)==VIREO_OK && ob.calls==1 && ob.saved_count==2 && ob.info.initialized_count==2);
    CHECK(state(&f).stop_requested && f.wait_calls==1 && state(&f).connection_count==2);
    f.clients[0]=ob.saved[0];f.clients[1]=ob.saved[1];end(&f,2);
}
static void stop_notify_error(void) {
    ++groups;
    fixture_t f;start(&f,AF_UNIX,0);f.stop_fault=true;
    errno=EDOM;vireo_event_loop_error_t e;
    CHECK(vireo_tcp_server_request_stop(f.server,&e)==VIREO_RESULT_IO && errno==EDOM);
    CHECK(e.stage==VIREO_EVENT_LOOP_STAGE_STOP_NOTIFY && e.system_errno==EINTR && state(&f).stop_requested);
    f.stop_fault=false;
    CHECK(vireo_tcp_server_request_stop(f.server,NULL)==VIREO_OK && atomic_load(&f.stop_calls)==2);
    vireo_tcp_server_run_options_t o=run_defaults();observation_t ob={0};
    CHECK(execute(&f,&o,&ob,NULL)==VIREO_OK && ob.calls==0);end(&f,0);
}
/* Thread tests access only immutable server pointer + independently synchronized gate/control.
 * Reactor owns all fixture/client/observer state; main reads it only after join. */
typedef struct threaded_run {fixture_t *fixture;vireo_result_t result;observation_t observer;} threaded_run_t;
static void *runner(void *ctx) {
    threaded_run_t *t=ctx;vireo_tcp_server_run_options_t o=run_defaults();
    t->result=execute(t->fixture,&o,&t->observer,NULL);return NULL;
}
typedef struct requester {vireo_tcp_server_t *server;vireo_result_t result;int saved;} requester_t;
static void *requester(void *ctx) {
    requester_t *r=ctx;errno=ECHILD;r->result=vireo_tcp_server_request_stop(r->server,NULL);r->saved=errno;return NULL;
}
static void pre_sync_failure(void) {
    ++groups;
    server_options.connection_capacity=1;
    fixture_t f;start(&f,AF_UNIX,1);enable(&f);
    CHECK(!state(&f).listener_read_enabled);
    REQUIRE(vireo_tcp_server_release_client(f.server,&f.clients[0],NULL)==VIREO_OK);
    f.fail_mod_on=f.mod_calls+1;
    vireo_tcp_server_run_options_t o=run_defaults();observation_t ob={0};vireo_tcp_server_run_error_t e;
    CHECK(execute(&f,&o,&ob,&e)==VIREO_RESULT_IO && ob.calls==0 && f.wait_calls==0);
    CHECK(!e.round_available && e.serve_error.stage==VIREO_TCP_SERVER_SERVE_PRE_SYNC &&
        e.serve_error.listener_error.acceptor_error.loop_error.epoll_error.system_errno==EBADF);
    CHECK(!state(&f).listener_read_enabled && state(&f).admission_read_desired);
    end(&f,1);
}
static void terminal_sync_failure(bool dual) {
    ++groups;
    server_options.connection_capacity=1;
    fixture_t f;start(&f,AF_INET,0);enable(&f);f.peers[0]=connect_peer(&f);
    f.fail_mod_on=1;if(dual)f.fail_flow_on=1;
    vireo_tcp_server_run_options_t o=run_defaults();observation_t ob={.stop_after=1};vireo_tcp_server_run_error_t e;
    CHECK(execute(&f,&o,&ob,&e)==VIREO_RESULT_IO && ob.calls==1 && ob.saved_count==1);
    CHECK(e.round_available && e.round_info.admission.admitted_count==1 && state(&f).stop_requested);
    if(dual)CHECK(e.serve_error.stage==VIREO_TCP_SERVER_SERVE_INITIALIZE &&
        e.serve_error.sync_result==VIREO_RESULT_IO &&
        e.serve_error.sync_error.acceptor_error.loop_error.epoll_error.system_errno==EBADF);
    else CHECK(e.serve_error.stage==VIREO_TCP_SERVER_SERVE_POST_SYNC &&
        e.serve_error.listener_error.acceptor_error.loop_error.epoll_error.system_errno==EBADF);
    f.clients[0]=ob.saved[0];end(&f,1);
}
static void complete_current_turns(void) {
    ++groups;
    fixture_t f;start(&f,AF_INET,2);enable(&f);
    feed(&f,0,1,301);feed(&f,1,1,302);schedule(&f,0);schedule(&f,1);
    f.peers[2]=connect_peer(&f);f.stop_on_handler=true;
    vireo_tcp_server_run_options_t o=run_defaults();o.admit.max_accepts=1;
    observation_t ob={0};
    CHECK(execute(&f,&o,&ob,NULL)==VIREO_OK && ob.calls==1 && f.handler_calls==2 && f.wait_calls==1);
    CHECK(ob.info.round.turn_count==2 && ob.info.round.succeeded_count==2 &&
        ob.saved_count==1 && ob.info.initialized_count==1 && state(&f).connection_count==3);
    CHECK(state(&f).stop_requested);f.clients[2]=ob.saved[0];
    responses(&f,0,1,301);responses(&f,1,1,302);end(&f,3);
}
static void wait_error_beats_stop(void) {
    ++groups;
    fixture_t f;start(&f,AF_UNIX,0);enable(&f);f.stop_on_wait=1;f.wait_io=true;
    vireo_tcp_server_run_options_t o=run_defaults();observation_t ob={0};vireo_tcp_server_run_error_t e;
    CHECK(execute(&f,&o,&ob,&e)==VIREO_RESULT_IO && ob.calls==0 && f.wait_calls==1);
    CHECK(!e.round_available && state(&f).stop_requested &&
        e.serve_error.round_error.loop_error.epoll_error.system_errno==EINTR);
    end(&f,0);
}
static void stopped_run_outputs(void) {
    ++groups;
    fixture_t f;start(&f,AF_UNIX,0);REQUIRE(vireo_tcp_server_request_stop(f.server,NULL)==VIREO_OK);
    uint8_t w[96],ws[96];memset(w,0x6a,96);memcpy(ws,w,96);
    vireo_tcp_server_turn_result_t t[4],ts[4];memset(t,0x5a,sizeof(t));memcpy(ts,t,sizeof(t));
    vireo_connection_pool_lease_t c[4]={{0}};c[3].pool_id=9;
    vireo_tcp_server_run_options_t o=run_defaults();o.admit.max_accepts=1;
    observation_t ob={.fixture=&f};vireo_tcp_server_run_error_t e;
    errno=EDOM;
    CHECK(vireo_tcp_server_run(f.server,&o,w,96,handler,&f,t,4,c,4,observe,&ob,&e)==VIREO_OK && errno==EDOM);
    CHECK(!memcmp(w,ws,96) && !memcmp(t,ts,sizeof(t)) && c[3].pool_id==9 && empty(c[0]) &&
        ob.calls==0 && f.wait_calls==0 && e.stage==VIREO_TCP_SERVER_RUN_NONE && !e.round_available);
    end(&f,0);
}
static void concurrent_stop(void) {
    ++groups;
    fixture_t f;start(&f,AF_INET,0);enable(&f);
    wait_gate_t gate={.mutex=PTHREAD_MUTEX_INITIALIZER,.condition=PTHREAD_COND_INITIALIZER};f.gate=&gate;
    threaded_run_t run={.fixture=&f};pthread_t rt,st[4];requester_t req[4];
    REQUIRE(pthread_create(&rt,NULL,runner,&run)==0);
    REQUIRE(pthread_mutex_lock(&gate.mutex)==0);
    while(!gate.entered)REQUIRE(pthread_cond_wait(&gate.condition,&gate.mutex)==0);
    REQUIRE(pthread_mutex_unlock(&gate.mutex)==0);
    for(size_t k=0;k<4;++k){req[k]=(requester_t){.server=f.server};REQUIRE(pthread_create(&st[k],NULL,requester,&req[k])==0);}
    for(size_t k=0;k<4;++k){REQUIRE(pthread_join(st[k],NULL)==0);CHECK(req[k].result==VIREO_OK && req[k].saved==ECHILD);}
    REQUIRE(pthread_join(rt,NULL)==0);
    CHECK(run.result==VIREO_OK && run.observer.calls==1 && f.wait_calls==1 && f.observed_timeout==-1);
    CHECK(atomic_load(&f.stop_calls)==4 && state(&f).stop_requested && !state(&f).running_active);
    f.gate=NULL;REQUIRE(pthread_cond_destroy(&gate.condition)==0);REQUIRE(pthread_mutex_destroy(&gate.mutex)==0);end(&f,0);
}
static void exact_control_budget(void) {
    ++groups;
    fixture_t f;start(&f,AF_UNIX,0);vireo_tcp_server_info_t i=state(&f);
    size_t const listener_bytes=i.listener_allocation_bytes;
    size_t const exact=i.allocation_bytes-listener_bytes;end(&f,0);
    vireo_tcp_server_options_t o=server_options;o.max_memory_bytes=exact;
    vireo_tcp_server_t *s=NULL;CHECK(vireo_tcp_server_create(&o,&s,NULL)==VIREO_OK);
    CHECK(vireo_tcp_server_destroy(&s,NULL)==VIREO_OK);
    --o.max_memory_bytes;CHECK(vireo_tcp_server_create(&o,&s,NULL)==VIREO_RESULT_RANGE && s==NULL);
}
int main(void) {
    unsigned const before=fd_count();
    parameter_rejections();stopped_no_policy();stopped_finite();buffered_rounds();callback_operations();
    automatic_reuse(AF_INET,false);automatic_reuse(AF_UNIX,true);
    policy_changed(false);policy_changed(true);before_wait_fail();
    error_round(0);error_round(1);error_round(2);stop_current_admission();stop_notify_error();
    pre_sync_failure();terminal_sync_failure(false);terminal_sync_failure(true);complete_current_turns();
    wait_error_beats_stop();stopped_run_outputs();concurrent_stop();exact_control_budget();
    unsigned const after=fd_count();CHECK(before==after);
    printf("test_tcp_server_run_stop: %u groups, %u failures, fd %u -> %u\n",groups,failures,before,after);
    return failures==0?EXIT_SUCCESS:EXIT_FAILURE;
}
