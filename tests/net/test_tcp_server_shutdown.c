/*
- PROJECT : VIREO
- FILE    : test_tcp_server_shutdown.c
- AUTHOR  : bitofux
- DATE    : 2026-10-06
- BRIEF   : 此模块负责：
- -- 停止后槽预算、游标、公平清理与真实部分进度
- -- 严格注销/消费归还、错误资源保持与整批重入保护
 */
#define _POSIX_C_SOURCE 200809L
#include "net/tcp_server_internal.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static unsigned failures, groups;
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #c); ++failures; } } while (0)
#define REQUIRE(c) do { if (!(c)) { fprintf(stderr, "fixture %s:%d: %s\n", __FILE__, __LINE__, #c); exit(EXIT_FAILURE); } } while (0)
static vireo_tcp_server_options_t const server_options = {3, 2, 1048576, 1024};
static vireo_connection_options_t const connection_options = {128, 128, 256};
static vireo_tcp_server_admit_budget_t const admit_budget = {3, 8};
static bool empty(vireo_connection_pool_lease_t l) { return l.pool_id == 0 && l.slot_index == 0 && l.generation == 0; }
static bool same(vireo_connection_pool_lease_t a, vireo_connection_pool_lease_t b)
{ return a.pool_id == b.pool_id && a.slot_index == b.slot_index && a.generation == b.generation; }
static unsigned fd_count(void)
{
    DIR *d = opendir("/proc/self/fd"); REQUIRE(d != NULL);
    unsigned n = 0; struct dirent *e;
    while ((e = readdir(d)) != NULL) if (e->d_name[0] != '.') ++n;
    REQUIRE(closedir(d) == 0); return n;
}
typedef struct listener {
    vireo_acceptor_t *owner;
    struct sockaddr_storage address;
    socklen_t length;
    int family;
} listener_t;
static listener_t listener_create(int family)
{
    static unsigned serial; listener_t a = {.family = family};
    int fd = socket(family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0); REQUIRE(fd >= 0);
    if (family == AF_INET) {
        struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr = {htonl(INADDR_LOOPBACK)}};
        a.length = (socklen_t)sizeof(address);
        REQUIRE(bind(fd, (struct sockaddr *)&address, a.length) == 0);
        REQUIRE(getsockname(fd, (struct sockaddr *)&a.address, &a.length) == 0);
    } else {
        struct sockaddr_un address = {.sun_family = AF_UNIX};
        int const n = snprintf(address.sun_path + 1, sizeof(address.sun_path) - 1,
                               "vireo-admit-%ld-%u", (long)getpid(), ++serial);
        REQUIRE(n > 0 && (size_t)n < sizeof(address.sun_path) - 1);
        a.length = (socklen_t)sizeof(address); memcpy(&a.address, &address, sizeof(address));
        REQUIRE(bind(fd, (struct sockaddr *)&a.address, a.length) == 0);
    }
    REQUIRE(listen(fd, 16) == 0);
    vireo_acceptor_options_t const options = {4096};
    REQUIRE(vireo_acceptor_create(&options, &fd, &a.owner, NULL) == VIREO_OK && fd == -1);
    return a;
}
static int connect_peer(listener_t const *a)
{
    int const fd = socket(a->family, SOCK_STREAM | SOCK_CLOEXEC, 0); REQUIRE(fd >= 0);
    REQUIRE(connect(fd, (struct sockaddr const *)&a->address, a->length) == 0); return fd;
}
typedef struct fixture {
    vireo_tcp_server_t *owner;
    vireo_event_loop_t *loop; /* 本核心公开 wrapper 捕获的测试借用，驱动返回后才释放。 */
    unsigned accepts, creates, adopts, lookups, attaches, detaches, releases, destroys, closes;
    unsigned fail_create, fail_adopt, fail_lookup, fail_attach, transients;
    int accept_errno;
    bool detach_io, release_busy, release_io, destroy_io, close_io, active, inspect_fail, corrupt_info;
    unsigned control_allocations, control_frees;
    int last_fd;
    vireo_connection_t *objects[3]; /* 仅公开 adopt wrapper 捕获的短借用，不成为 owner。 */
    vireo_connection_pool_lease_t clients[3];
    int peers[3];
    struct sockaddr_storage address;
    socklen_t address_length;
    int family;
    unsigned fail_detach_on, fail_release_on, probe_calls;
    bool probe_detach, probe_release, probe_wait, probe_receive, probe_listener;
    struct fixture *nested;
} fixture_t;
static void probe_batch(fixture_t *f);
static void reject_batch(fixture_t *f);
static vireo_result_t accept_client(void *ctx, vireo_acceptor_t *a,
    vireo_acceptor_accept_budget_t const *b, int *fds, size_t n,
    vireo_acceptor_accept_info_t *i, vireo_acceptor_error_t *e)
{
    fixture_t *f = ctx; ++f->accepts;
    if (f->accept_errno != 0) {
        *i = (vireo_acceptor_accept_info_t){.accept_calls = 1, .stop_reason = VIREO_ACCEPTOR_ACCEPT_IO_ERROR};
        *e = (vireo_acceptor_error_t){VIREO_ACCEPTOR_STAGE_ACCEPT_CLIENT, f->accept_errno};
        errno = E2BIG; return VIREO_RESULT_IO;
    }
    size_t const injected = f->transients < b->max_syscalls ? f->transients : b->max_syscalls;
    f->transients = 0;
    if (injected == b->max_syscalls) {
        *i = (vireo_acceptor_accept_info_t){.accept_calls = injected, .transient_errors = injected,
                                         .stop_reason = VIREO_ACCEPTOR_ACCEPT_CALL_BUDGET};
        return VIREO_OK;
    }
    vireo_acceptor_accept_budget_t const remaining = {b->max_accepts, b->max_syscalls - injected};
    vireo_result_t const r = vireo_acceptor_accept_batch(a, &remaining, fds, n, i, e);
    i->accept_calls += injected; i->transient_errors += injected;
    if (i->accepted_count != 0) f->last_fd = fds[0];
    return r;
}
static vireo_result_t create_connection(void *ctx, vireo_connection_options_t const *o, int *fd,
    vireo_connection_t **c, vireo_connection_error_t *e)
{
    fixture_t *f = ctx; ++f->creates;
    if (f->creates == f->fail_create) {
        *e = (vireo_connection_error_t){VIREO_CONNECTION_STAGE_CREATE_READ_BUFFER, 0};
        return VIREO_RESULT_NO_MEMORY;
    }
    return vireo_connection_create(o, fd, c, e);
}
static vireo_result_t inspect_connection(void *ctx, vireo_connection_t const *c, vireo_connection_info_t *i)
{
    fixture_t *f = ctx;
    if (f->inspect_fail) return VIREO_RESULT_INTERNAL;
    vireo_result_t const r = vireo_connection_inspect(c, i);
    if (r == VIREO_OK) { if (f->active) i->callback_active = true; if (f->corrupt_info) ++i->buffer_capacity_bytes; }
    return r;
}
static vireo_result_t adopt_connection(void *ctx, vireo_connection_pool_t *p, vireo_connection_t **c,
    vireo_connection_pool_lease_t *l, vireo_connection_pool_operation_error_t *e)
{
    fixture_t *f = ctx; ++f->adopts;
    if (f->adopts == f->fail_adopt) {
        e->stage = VIREO_CONNECTION_POOL_OPERATION_ACQUIRE_SLOT; return VIREO_RESULT_BUSY;
    }
    vireo_connection_t *borrow = *c;
    vireo_result_t const r = vireo_connection_pool_adopt(p, c, l, e);
    if (r == VIREO_OK) { REQUIRE(l->slot_index < 3); f->objects[l->slot_index] = borrow; }
    return r;
}
static vireo_result_t lookup_connection(void *ctx, vireo_connection_pool_t const *p,
    vireo_connection_pool_lease_t l, vireo_connection_t **c)
{
    fixture_t *f = ctx; ++f->lookups;
    if (f->lookups == f->fail_lookup) return VIREO_RESULT_INTERNAL;
    return vireo_connection_pool_lookup(p, l, c);
}
static vireo_result_t attach_connection(void *ctx, vireo_connection_t *c, vireo_event_loop_t *p,
    uint32_t mask, vireo_connection_callback_t cb, void *cbctx, vireo_connection_loop_error_t *e)
{
    fixture_t *f = ctx; ++f->attaches;
    if (f->attaches == f->fail_attach) {
        *e = (vireo_connection_loop_error_t){VIREO_CONNECTION_LOOP_STAGE_ATTACH,
            {VIREO_EVENT_LOOP_STAGE_ADD, {VIREO_EPOLL_STAGE_ADD, ENOSPC}, EIO}};
        return VIREO_RESULT_IO;
    }
    return vireo_connection_attach(c, p, mask, cb, cbctx, e);
}
static vireo_result_t detach_connection(void *ctx, vireo_connection_t *c, vireo_connection_loop_error_t *e)
{
    fixture_t *f = ctx; ++f->detaches;
    if (f->probe_detach) { f->probe_detach = false; probe_batch(f); }
    if (f->detach_io || f->detaches == f->fail_detach_on) {
        *e = (vireo_connection_loop_error_t){VIREO_CONNECTION_LOOP_STAGE_DETACH,
            {VIREO_EVENT_LOOP_STAGE_DEL, {VIREO_EPOLL_STAGE_DEL, EBADF}, EIO}};
        return VIREO_RESULT_IO;
    }
    vireo_result_t const r = vireo_connection_detach(c, e); errno = E2BIG; return r;
}
static vireo_result_t release_connection(void *ctx, vireo_connection_pool_t *p,
    vireo_connection_pool_lease_t *l, vireo_connection_pool_operation_error_t *e)
{
    fixture_t *f = ctx; ++f->releases;
    if (f->probe_release) { f->probe_release = false; probe_batch(f); }
    if (f->release_busy || f->releases == f->fail_release_on) return VIREO_RESULT_BUSY;
    vireo_result_t const r = vireo_connection_pool_release(p, l, e);
    REQUIRE(r == VIREO_OK && empty(*l));
    errno = E2BIG;
    if (!f->release_io) return r;
    *e = (vireo_connection_pool_operation_error_t){VIREO_CONNECTION_POOL_OPERATION_DESTROY_CONNECTION,
        {VIREO_CONNECTION_STAGE_CLOSE_SOCKET, EINTR}};
    return VIREO_RESULT_IO;
}
static vireo_result_t destroy_connection(void *ctx, vireo_connection_t **c, vireo_connection_error_t *e)
{
    fixture_t *f = ctx; ++f->destroys;
    vireo_result_t const r = vireo_connection_destroy(c, e); REQUIRE(r == VIREO_OK && *c == NULL);
    if (!f->destroy_io) return r;
    *e = (vireo_connection_error_t){VIREO_CONNECTION_STAGE_CLOSE_SOCKET, EIO}; return VIREO_RESULT_IO;
}
static int close_fd(void *ctx, int fd)
{
    fixture_t *f = ctx; ++f->closes; REQUIRE(close(fd) == 0);
    if (!f->close_io) return 0;
    errno = EINTR; return -1;
}
/* 新增完整字节表只适配本核心 fixture，不改变既有准入场景。 */
static vireo_result_t receive_bytes(void *ctx, vireo_connection_t *c,
    vireo_connection_receive_budget_t const *b, vireo_connection_receive_info_t *i,
    vireo_connection_error_t *e)
{
    fixture_t *f = ctx;
    if (f->probe_receive) { f->probe_receive = false; reject_batch(f); }
    return vireo_connection_receive(c, b, i, e);
}
static vireo_result_t read_bytes(void *ctx, vireo_connection_t const *c, uint8_t const **p, size_t *n)
{ (void)ctx; return vireo_connection_read_peek(c, p, n); }
static vireo_result_t consume_bytes(void *ctx, vireo_connection_t *c, size_t n)
{ (void)ctx; return vireo_connection_read_consume(c, n); }
static vireo_result_t enqueue_bytes(void *ctx, vireo_connection_t *c, uint8_t const *p,
    size_t n, vireo_connection_error_t *e)
{ (void)ctx; return vireo_connection_write_enqueue(c, p, n, e); }
static vireo_result_t send_bytes(void *ctx, vireo_connection_t *c,
    vireo_connection_send_budget_t const *b, vireo_connection_send_info_t *i, vireo_connection_error_t *e)
{ (void)ctx; return vireo_connection_send(c, b, i, e); }
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

static vireo_tcp_server_client_ops_t client_ops(fixture_t *f)
{
    return (vireo_tcp_server_client_ops_t){f, accept_client, create_connection, inspect_connection,
        adopt_connection, lookup_connection, attach_connection, detach_connection, release_connection,
        destroy_connection, close_fd, receive_bytes, read_bytes, consume_bytes, enqueue_bytes, send_bytes, frame_views,
        policy_set_interests, policy_flow_configure, policy_flow_refresh, policy_flow_disable, policy_request_close, policy_close_refresh};
}
static void *allocate(void *ctx, size_t n) { ++((fixture_t *)ctx)->control_allocations; return malloc(n); }
static void deallocate(void *ctx, void *p) { ++((fixture_t *)ctx)->control_frees; free(p); }
static vireo_result_t create_loop(void *ctx, vireo_event_loop_options_t const *o,
    vireo_event_loop_t **p, vireo_event_loop_error_t *e)
{
    fixture_t *f = ctx; vireo_result_t const r = vireo_event_loop_create(o, p, e);
    if (r == VIREO_OK) f->loop = *p;
    return r;
}
static vireo_result_t inspect_loop(void *ctx, vireo_event_loop_t const *p, vireo_event_loop_info_t *i)
{ (void)ctx; return vireo_event_loop_inspect(p, i); }
static vireo_result_t destroy_loop(void *ctx, vireo_event_loop_t **p, vireo_event_loop_error_t *e)
{ fixture_t *f = ctx; vireo_result_t const r = vireo_event_loop_destroy(p, e); f->loop = NULL; return r; }
static vireo_result_t create_pool(void *ctx, vireo_connection_pool_options_t const *o,
    vireo_connection_pool_t **p, vireo_connection_pool_error_t *e)
{ (void)ctx; return vireo_connection_pool_create(o, p, e); }
static vireo_result_t inspect_pool(void *ctx, vireo_connection_pool_t const *p, vireo_connection_pool_info_t *i)
{ (void)ctx; return vireo_connection_pool_inspect(p, i); }
static vireo_result_t destroy_pool(void *ctx, vireo_connection_pool_t **p, vireo_connection_pool_error_t *e)
{ (void)ctx; return vireo_connection_pool_destroy(p, e); }
static vireo_result_t wait_once(void *ctx, vireo_event_loop_t *loop, int timeout,
    vireo_event_loop_run_info_t *i, vireo_event_loop_error_t *e)
{
    fixture_t *f = ctx;
    if (f->probe_wait) { f->probe_wait = false; reject_batch(f); }
    return vireo_event_loop_run_once(loop, timeout, i, e);
}
static vireo_result_t li_inspect(void *ctx, vireo_acceptor_t const *a, vireo_acceptor_info_t *i)
{ (void)ctx; return vireo_acceptor_inspect(a, i); }
static vireo_result_t li_attach(void *ctx, vireo_acceptor_t *a, vireo_event_loop_t *loop,
    bool read, vireo_acceptor_callback_t cb, void *cc, vireo_acceptor_loop_error_t *e)
{ (void)ctx; return vireo_acceptor_attach(a, loop, read, cb, cc, e); }
static vireo_result_t li_read(void *ctx, vireo_acceptor_t *a, bool read, vireo_acceptor_loop_error_t *e)
{
    fixture_t *f = ctx;
    if (f->probe_listener) {
        f->probe_listener = false;
        vireo_tcp_server_info_t observed;
        REQUIRE(vireo_tcp_server_inspect(f->owner, &observed) == VIREO_OK);
        CHECK(observed.serving_active && !observed.scheduling_active && !observed.driving_active && !observed.processing_active);
        reject_batch(f);
    }
    return vireo_acceptor_set_read_enabled(a, read, e);
}
static vireo_result_t li_detach(void *ctx, vireo_acceptor_t *a, vireo_acceptor_loop_error_t *e)
{ (void)ctx; return vireo_acceptor_detach(a, e); }
static vireo_result_t li_forget(void *ctx, vireo_acceptor_t *a)
{ (void)ctx; return vireo_acceptor_forget_destroyed_loop(a, NULL); }
static vireo_result_t li_destroy(void *ctx, vireo_acceptor_t **a, vireo_acceptor_error_t *e)
{ (void)ctx; return vireo_acceptor_destroy(a, e); }
static void create(fixture_t *f, vireo_tcp_server_options_t options)
{
    vireo_tcp_server_ops_t b = {f, allocate, deallocate, create_loop, inspect_loop, destroy_loop,
                                create_pool, inspect_pool, destroy_pool};
    vireo_tcp_server_client_ops_t c = client_ops(f);
    vireo_tcp_server_listener_ops_t const l = {f, li_inspect, li_attach, li_read, li_detach, li_forget, li_destroy};
    vireo_tcp_server_scheduler_ops_t const w = {f, wait_once};
    REQUIRE(vireo_tcp_server_create_with_scheduler_ops(&options, &b, &l, &c, &w, &f->owner, NULL) == VIREO_OK);
    memset(&c, 0, sizeof(c)); /* 逐对象按值复制，不借用临时表。 */
}
static vireo_tcp_server_info_t info(vireo_tcp_server_t *server)
{ vireo_tcp_server_info_t i; REQUIRE(vireo_tcp_server_inspect(server, &i) == VIREO_OK); return i; }
static void adopt_listener(vireo_tcp_server_t *server, listener_t *a)
{ REQUIRE(vireo_tcp_server_adopt_listener(server, &a->owner, NULL) == VIREO_OK && a->owner == NULL); }

static vireo_connection_flow_options_t const flow = {32, 31, 96, 16, 96};
static vireo_tcp_server_process_options_t const limits = {32, 32};
static vireo_tcp_server_drive_budget_t const drive_budget = {{128, 2}, {1, 32, 32}, {128, 2}};
static vireo_tcp_server_round_budget_t const round_budget = {3};
static vireo_tcp_server_shutdown_budget_t const all_slots = {3};
static void start(fixture_t *f, int family, size_t count)
{
    *f = (fixture_t){0};
    create(f, server_options);
    listener_t a = listener_create(family);
    f->address = a.address; f->address_length = a.length; f->family = family;
    adopt_listener(f->owner, &a);
    REQUIRE(vireo_tcp_server_bind_listener(f->owner, true, NULL) == VIREO_OK);
    for (size_t k = 0; k < count; ++k) f->peers[k] = connect_peer(&a);
    if (count != 0) {
        vireo_tcp_server_admit_info_t i;
        REQUIRE(vireo_tcp_server_admit_batch(f->owner, &connection_options, &admit_budget,
            f->clients, count, &i, NULL) == VIREO_OK && i.admitted_count == count);
    }
}
static void end(fixture_t *f, size_t count)
{
    f->detach_io = f->release_busy = f->release_io = f->active = f->inspect_fail = false;
    f->fail_lookup = f->fail_detach_on = f->fail_release_on = 0;
    f->probe_detach = f->probe_release = f->probe_wait = f->probe_receive = f->probe_listener = false;
    for (size_t k = 0; k < count; ++k) {
        vireo_result_t const r = vireo_tcp_server_release_client(f->owner, &f->clients[k], NULL);
        CHECK(r == VIREO_OK || r == VIREO_RESULT_NOT_FOUND);
        REQUIRE(close(f->peers[k]) == 0);
    }
    REQUIRE(vireo_tcp_server_destroy(&f->owner, NULL) == VIREO_OK && f->owner == NULL);
}
static void stop(fixture_t *f)
{
    errno = EDOM;
    REQUIRE(vireo_tcp_server_request_stop(f->owner, NULL) == VIREO_OK);
    CHECK(errno == EDOM && info(f->owner).stop_requested);
}
static vireo_result_t batch(fixture_t *f, size_t slots, vireo_tcp_server_shutdown_result_t *rows,
    size_t cap, vireo_tcp_server_shutdown_info_t *i, vireo_tcp_server_client_error_t *e)
{
    vireo_tcp_server_shutdown_budget_t const b = {slots};
    errno = EDOM;
    vireo_result_t const r = vireo_tcp_server_shutdown_batch(f->owner, &b, rows, cap, i, e);
    CHECK(errno == EDOM);
    return r;
}
static vireo_connection_pool_lease_t at(fixture_t const *f, size_t slot)
{
    for (size_t k = 0; k < 3; ++k)
        if (!empty(f->clients[k]) && f->clients[k].slot_index == slot) return f->clients[k];
    REQUIRE(false);
    return (vireo_connection_pool_lease_t){0};
}
static void reject_batch(fixture_t *f)
{
    ++f->probe_calls;
    REQUIRE(vireo_tcp_server_request_stop(f->owner, NULL) == VIREO_OK);
    vireo_tcp_server_info_t const s = info(f->owner);
    CHECK(s.running_active || s.processing_active || s.driving_active || s.scheduling_active || s.serving_active);
    vireo_tcp_server_shutdown_result_t row, oldrow;
    vireo_tcp_server_shutdown_info_t i, oldi;
    memset(&row, 0x6d, sizeof(row)); memcpy(&oldrow, &row, sizeof(row));
    memset(&i, 0x4a, sizeof(i)); memcpy(&oldi, &i, sizeof(i));
    CHECK(batch(f, 3, &row, 1, &i, NULL) == VIREO_RESULT_BUSY);
    CHECK(memcmp(&row, &oldrow, sizeof(row)) == 0 && memcmp(&i, &oldi, sizeof(i)) == 0);
}
static vireo_result_t handler(vireo_connection_frame_view_t const *request, uint8_t *body,
    size_t cap, vireo_tcp_server_reply_t *reply, void *context)
{
    (void)request; (void)body; (void)cap;
    fixture_t *f = context;
    reject_batch(f);
    reply->body_size = 0;
    return VIREO_OK;
}
static void observer(vireo_tcp_server_t *server, vireo_result_t result,
    vireo_tcp_server_serve_info_t const *i, vireo_tcp_server_turn_result_t const *turns,
    vireo_connection_pool_lease_t const *clients, vireo_tcp_server_serve_error_t const *e, void *context)
{
    (void)result; (void)i; (void)turns; (void)clients; (void)e;
    fixture_t *f = context;
    REQUIRE(server == f->owner);
    vireo_tcp_server_info_t const s = info(server);
    CHECK(s.running_active && !s.processing_active && !s.driving_active && !s.scheduling_active && !s.serving_active);
    reject_batch(f);
    /* 原轮末 observer 释放窗口仍允许，不因新增 batch 扩大 running 的拒绝。 */
    if (!empty(f->clients[0])) CHECK(vireo_tcp_server_release_client(server, &f->clients[0], NULL) == VIREO_OK);
}
static void probe_batch(fixture_t *f)
{
    ++f->probe_calls;
    vireo_tcp_server_info_t const s = info(f->owner);
    CHECK(s.shutdown_active && !s.running_active && s.shutdown_next_slot < s.connection_capacity);
    vireo_tcp_server_client_info_t c;
    CHECK(vireo_tcp_server_client_inspect(f->owner, f->clients[0], &c) == VIREO_OK);
    uint8_t const *bytes = NULL; size_t n = 99;
    CHECK(vireo_tcp_server_client_read_peek(f->owner, f->clients[0], &bytes, &n, NULL) == VIREO_OK && n == 0);
    vireo_connection_frame_options_t const fo = {VIREO_CONNECTION_FRAME_REQUEST, 32};
    vireo_connection_frame_budget_t const fb = {1, 32};
    vireo_connection_frame_view_t view;
    vireo_connection_frame_info_t fi;
    CHECK(vireo_tcp_server_client_frames_peek(f->owner, f->clients[0], &fo, &fb, &view, 1, &fi, NULL) == VIREO_OK);
    vireo_connection_receive_info_t ri;
    vireo_connection_send_info_t si;
    vireo_tcp_server_process_info_t pi;
    vireo_tcp_server_drive_info_t di;
    vireo_tcp_server_round_info_t round;
    vireo_tcp_server_serve_info_t serve;
    vireo_tcp_server_turn_result_t turns[3];
    vireo_connection_pool_lease_t leases[3] = {{0}};
    uint8_t workspace[32] = {0};
    vireo_connection_pool_lease_t lease = f->clients[0];
    CHECK(vireo_tcp_server_release_client(f->owner, &lease, NULL) == VIREO_RESULT_BUSY && same(lease, f->clients[0]));
    CHECK(vireo_tcp_server_destroy(&f->owner, NULL) == VIREO_RESULT_BUSY && f->owner != NULL);
    vireo_tcp_server_shutdown_result_t row;
    vireo_tcp_server_shutdown_info_t bi;
    CHECK(vireo_tcp_server_shutdown_batch(f->owner, &all_slots, &row, 1, &bi, NULL) == VIREO_RESULT_BUSY);
    CHECK(vireo_tcp_server_bind_listener(f->owner, true, NULL) == VIREO_RESULT_BUSY);
    CHECK(vireo_tcp_server_set_listener_read_enabled(f->owner, false, NULL) == VIREO_RESULT_BUSY);
    CHECK(vireo_tcp_server_unbind_listener(f->owner, NULL) == VIREO_RESULT_BUSY);
    listener_t extra = listener_create(AF_UNIX);
    CHECK(vireo_tcp_server_adopt_listener(f->owner, &extra.owner, NULL) == VIREO_RESULT_BUSY && extra.owner != NULL);
    REQUIRE(vireo_acceptor_destroy(&extra.owner, NULL) == VIREO_OK);
    vireo_tcp_server_admit_info_t ai;
    CHECK(vireo_tcp_server_admit_batch(f->owner, &connection_options, &admit_budget, leases, 3, &ai, NULL) == VIREO_RESULT_BUSY);
    CHECK(vireo_tcp_server_client_receive(f->owner, lease, &drive_budget.receive, &ri, NULL) == VIREO_RESULT_BUSY);
    CHECK(vireo_tcp_server_client_read_consume(f->owner, lease, 0, NULL) == VIREO_RESULT_BUSY);
    CHECK(vireo_tcp_server_client_write_enqueue(f->owner, lease, workspace, 1, NULL) == VIREO_RESULT_BUSY);
    CHECK(vireo_tcp_server_client_send(f->owner, lease, &drive_budget.send, &si, NULL) == VIREO_RESULT_BUSY);
    CHECK(vireo_tcp_server_client_process(f->owner, lease, &limits, &drive_budget.process,
        workspace, sizeof(workspace), handler, f, &pi, NULL) == VIREO_RESULT_BUSY);
    CHECK(vireo_tcp_server_client_drive(f->owner, lease, &limits, &drive_budget,
        workspace, sizeof(workspace), handler, f, &di, NULL) == VIREO_RESULT_BUSY);
    CHECK(vireo_tcp_server_client_set_interests(f->owner, lease, 0, NULL) == VIREO_RESULT_BUSY);
    CHECK(vireo_tcp_server_client_flow_configure(f->owner, lease, &flow, NULL) == VIREO_RESULT_BUSY);
    CHECK(vireo_tcp_server_client_flow_refresh(f->owner, lease, NULL) == VIREO_RESULT_BUSY);
    CHECK(vireo_tcp_server_client_flow_disable(f->owner, lease, NULL) == VIREO_RESULT_BUSY);
    CHECK(vireo_tcp_server_client_request_close(f->owner, lease, VIREO_CONNECTION_CLOSE_MODE_IMMEDIATE,
        VIREO_CONNECTION_CLOSE_REASON_SERVER_STOP, NULL) == VIREO_RESULT_BUSY);
    CHECK(vireo_tcp_server_client_close_refresh(f->owner, lease, NULL) == VIREO_RESULT_BUSY);
    CHECK(vireo_tcp_server_schedule_client(f->owner, lease, NULL) == VIREO_RESULT_BUSY);
    vireo_tcp_server_admission_options_t const ao = {connection_options, flow};
    CHECK(vireo_tcp_server_admission_configure(f->owner, &ao, NULL) == VIREO_RESULT_BUSY);
    CHECK(vireo_tcp_server_admission_refresh(f->owner, NULL) == VIREO_RESULT_BUSY);
    CHECK(vireo_tcp_server_admission_disable(f->owner, NULL) == VIREO_RESULT_BUSY);
    CHECK(vireo_tcp_server_run_once(f->owner, 0, &limits, &drive_budget, &round_budget,
        workspace, sizeof(workspace), handler, f, turns, 3, &round, NULL) == VIREO_RESULT_BUSY);
    vireo_tcp_server_serve_options_t const so = {0, limits, drive_budget, round_budget, admit_budget};
    CHECK(vireo_tcp_server_serve_once(f->owner, &so, workspace, sizeof(workspace), handler, f,
        turns, 3, leases, 3, &serve, NULL) == VIREO_RESULT_BUSY);
    vireo_tcp_server_run_options_t const ro = {limits, drive_budget, round_budget, admit_budget};
    CHECK(vireo_tcp_server_run(f->owner, &ro, workspace, sizeof(workspace), handler, f,
        turns, 3, leases, 3, observer, f, NULL) == VIREO_RESULT_BUSY);
    CHECK(vireo_tcp_server_request_stop(f->owner, NULL) == VIREO_OK);
    if (f->nested != NULL) {
        CHECK(batch(f->nested, 3, &row, 1, &bi, NULL) == VIREO_OK && bi.remaining_clients == 0);
        f->nested = NULL;
    }
}
static void empty_and_parameters(void)
{
    ++groups;
    fixture_t f; start(&f, AF_UNIX, 0);
    vireo_tcp_server_shutdown_result_t rows[3], oldrows[3];
    vireo_tcp_server_shutdown_info_t i, oldi;
    memset(rows, 0x5a, sizeof(rows)); memcpy(oldrows, rows, sizeof(rows));
    memset(&i, 0x6b, sizeof(i)); memcpy(&oldi, &i, sizeof(i));
    CHECK(batch(&f, 3, rows, 3, &i, NULL) == VIREO_RESULT_BUSY);
    CHECK(memcmp(rows, oldrows, sizeof(rows)) == 0 && memcmp(&i, &oldi, sizeof(i)) == 0);
    stop(&f);
    CHECK(batch(&f, 3, rows, 3, &i, NULL) == VIREO_OK && i.scanned_slots == 0 && i.attempted_clients == 0 && i.released_clients == 0 && i.remaining_clients == 0 && i.next_slot == 0 && i.stop_reason == VIREO_TCP_SERVER_SHUTDOWN_COMPLETE);
    CHECK(memcmp(rows, oldrows, sizeof(rows)) == 0);
    CHECK(batch(&f, 1, rows, 1, &i, NULL) == VIREO_OK && i.scanned_slots == 0);
    ++groups;
    for (unsigned k = 0; k < 10; ++k) {
        vireo_tcp_server_shutdown_budget_t b = {3};
        if (k == 4) b.max_slots = 0;
        if (k == 5) b.max_slots = SIZE_MAX;
        if (k == 8) b.max_slots = 65536;
        memcpy(&i, &oldi, sizeof(i)); memcpy(rows, oldrows, sizeof(rows)); errno = EDOM;
        vireo_tcp_server_client_error_t e = {.primary.stage = VIREO_TCP_SERVER_CLIENT_RELEASE};
        vireo_result_t const r = vireo_tcp_server_shutdown_batch(k == 0 ? NULL : f.owner,
            k == 1 ? NULL : &b, k == 2 ? NULL : rows, k == 6 ? 0 : k == 7 ? 65536 : k == 9 ? SIZE_MAX : 3,
            k == 3 ? NULL : &i, &e);
        CHECK(r == (k == 5 || k >= 7 ? VIREO_RESULT_RANGE : VIREO_RESULT_INVALID_ARGUMENT));
        CHECK(errno == EDOM && memcmp(rows, oldrows, sizeof(rows)) == 0 && memcmp(&i, &oldi, sizeof(i)) == 0);
        CHECK(e.primary.stage == VIREO_TCP_SERVER_CLIENT_NONE && e.cleanup_result == VIREO_OK);
    }
    end(&f, 0);
}
static void normal(int family, bool native)
{
    ++groups;
    fixture_t f;
    if (native) {
        f = (fixture_t){0};
        REQUIRE(vireo_tcp_server_create(&server_options, &f.owner, NULL) == VIREO_OK);
        listener_t a = listener_create(family); adopt_listener(f.owner, &a);
        REQUIRE(vireo_tcp_server_bind_listener(f.owner, true, NULL) == VIREO_OK);
        for (size_t k = 0; k < 3; ++k) f.peers[k] = connect_peer(&a);
        vireo_tcp_server_admit_info_t ai;
        REQUIRE(vireo_tcp_server_admit_batch(f.owner, &connection_options, &admit_budget, f.clients, 3, &ai, NULL) == VIREO_OK && ai.admitted_count == 3);
    } else start(&f, family, 3);
    for (size_t k = 0; k < 3; ++k) REQUIRE(vireo_tcp_server_schedule_client(f.owner, f.clients[k], NULL) == VIREO_OK);
    stop(&f);
    vireo_tcp_server_shutdown_result_t rows[4]; memset(rows, 0x6a, sizeof(rows));
    unsigned char tail[sizeof(rows[3])]; memcpy(tail, &rows[3], sizeof(tail));
    vireo_tcp_server_shutdown_info_t i;
    vireo_tcp_server_client_error_t e;
    unsigned const before = fd_count();
    CHECK(batch(&f, 3, rows, 4, &i, &e) == VIREO_OK);
    CHECK(i.scanned_slots == 3 && i.attempted_clients == 3 && i.released_clients == 3 && i.remaining_clients == 0 && i.next_slot == 0 && i.stop_reason == VIREO_TCP_SERVER_SHUTDOWN_COMPLETE);
    for (size_t k = 0; k < 3; ++k) CHECK(rows[k].released && rows[k].result == VIREO_OK && same(rows[k].lease, at(&f, k)));
    CHECK(memcmp(tail, &rows[3], sizeof(tail)) == 0 && e.primary.stage == VIREO_TCP_SERVER_CLIENT_NONE);
    vireo_tcp_server_info_t const s = info(f.owner);
    CHECK(s.connection_count == 0 && s.registered_connections == 0 && s.available_connections == 3 && s.buffer_capacity_bytes == 0 && s.pending_clients == 0);
    CHECK(s.listener_owned && s.listener_bound && s.stop_requested && !s.shutdown_active && s.shutdown_next_slot == 0);
    CHECK(fd_count() + 3 == before);
    if (!native) CHECK(f.detaches == 3 && f.releases == 3 && f.control_allocations == 1 && f.control_frees == 0);
    vireo_tcp_server_client_info_t ci;
    CHECK(vireo_tcp_server_client_inspect(f.owner, f.clients[0], &ci) == VIREO_RESULT_NOT_FOUND);
    end(&f, 3);
}
static void sparse_and_capacity(void)
{
    ++groups;
    fixture_t f; start(&f, AF_UNIX, 3);
    for (size_t k = 0; k < 2; ++k) { vireo_connection_pool_lease_t lease = at(&f, k); REQUIRE(vireo_tcp_server_release_client(f.owner, &lease, NULL) == VIREO_OK); }
    stop(&f);
    vireo_tcp_server_shutdown_result_t row;
    memset(&row, 0x6b, sizeof(row)); unsigned char old[sizeof(row)]; memcpy(old, &row, sizeof(old));
    vireo_tcp_server_shutdown_info_t i;
    for (size_t k = 0; k < 2; ++k) {
        CHECK(batch(&f, 1, &row, 1, &i, NULL) == VIREO_OK);
        CHECK(i.scanned_slots == 1 && i.attempted_clients == 0 && i.remaining_clients == 1 && i.next_slot == k + 1 && i.stop_reason == VIREO_TCP_SERVER_SHUTDOWN_SLOT_BUDGET);
        CHECK(memcmp(old, &row, sizeof(old)) == 0);
    }
    CHECK(batch(&f, 1, &row, 1, &i, NULL) == VIREO_OK && i.scanned_slots == 1 && i.released_clients == 1 && i.next_slot == 0 && i.remaining_clients == 0);
    end(&f, 3);
    ++groups;
    start(&f, AF_UNIX, 3); stop(&f);
    CHECK(batch(&f, 3, &row, 1, &i, NULL) == VIREO_OK && i.scanned_slots == 1 && i.attempted_clients == 1 && i.next_slot == 1 && i.stop_reason == VIREO_TCP_SERVER_SHUTDOWN_RESULT_CAPACITY);
    CHECK(batch(&f, 1, &row, 1, &i, NULL) == VIREO_OK && i.scanned_slots == 1 && i.next_slot == 2 && i.stop_reason == VIREO_TCP_SERVER_SHUTDOWN_SLOT_BUDGET);
    CHECK(batch(&f, 65535, &row, 1, &i, NULL) == VIREO_OK && i.scanned_slots == 1 && i.remaining_clients == 0 && i.next_slot == 0);
    end(&f, 3);
}
static void detach_and_release_errors(void)
{
    ++groups;
    fixture_t f; start(&f, AF_UNIX, 3); stop(&f);
    for (size_t k = 0; k < 3; ++k) REQUIRE(vireo_tcp_server_schedule_client(f.owner, f.clients[k], NULL) == VIREO_OK);
    f.fail_detach_on = 2;
    vireo_tcp_server_shutdown_result_t rows[3]; memset(rows, 0x5e, sizeof(rows));
    unsigned char tail[sizeof(rows[2])]; memcpy(tail, &rows[2], sizeof(tail));
    vireo_tcp_server_shutdown_info_t i;
    vireo_tcp_server_client_error_t e;
    CHECK(batch(&f, 3, rows, 3, &i, &e) == VIREO_RESULT_IO);
    CHECK(i.scanned_slots == 2 && i.attempted_clients == 2 && i.released_clients == 1 && i.remaining_clients == 2 && i.next_slot == 2 && i.stop_reason == VIREO_TCP_SERVER_SHUTDOWN_ERROR);
    CHECK(rows[0].released && !rows[1].released && same(rows[1].lease, at(&f, 1)) && memcmp(tail, &rows[2], sizeof(tail)) == 0);
    CHECK(rows[1].result == VIREO_RESULT_IO && rows[1].error.primary.stage == VIREO_TCP_SERVER_CLIENT_DETACH);
    CHECK(e.primary.stage == VIREO_TCP_SERVER_CLIENT_DETACH && e.primary.loop_error.loop_error.epoll_error.system_errno == EBADF && e.primary.loop_error.loop_error.system_errno == EIO);
    vireo_tcp_server_client_info_t c;
    CHECK(vireo_tcp_server_client_inspect(f.owner, rows[1].lease, &c) == VIREO_OK && c.connection_info.loop_attached && c.queued);
    CHECK(info(f.owner).buffer_capacity_bytes == 512 && info(f.owner).pending_clients == 2 && info(f.owner).registered_connections == 2 && !info(f.owner).shutdown_active);
    CHECK(vireo_tcp_server_destroy(&f.owner, NULL) == VIREO_RESULT_BUSY && f.owner != NULL);
    CHECK(batch(&f, 1, rows, 1, &i, NULL) == VIREO_OK && same(rows[0].lease, at(&f, 2)) && i.remaining_clients == 1 && i.next_slot == 0);
    CHECK(batch(&f, 3, rows, 3, &i, NULL) == VIREO_OK && i.scanned_slots == 2 && i.remaining_clients == 0 && i.next_slot == 2);
    end(&f, 3);
    ++groups;
    start(&f, AF_UNIX, 1); stop(&f); f.release_busy = true;
    REQUIRE(vireo_tcp_server_schedule_client(f.owner, f.clients[0], NULL) == VIREO_OK);
    CHECK(batch(&f, 3, rows, 3, &i, NULL) == VIREO_RESULT_BUSY && i.released_clients == 0 && i.remaining_clients == 1 && !rows[0].released);
    CHECK(vireo_tcp_server_client_inspect(f.owner, f.clients[0], &c) == VIREO_OK && !c.connection_info.loop_attached && c.queued);
    CHECK(info(f.owner).registered_connections == 0 && info(f.owner).buffer_capacity_bytes == 256);
    unsigned const detaches = f.detaches;
    f.release_busy = false;
    CHECK(batch(&f, 3, rows, 3, &i, NULL) == VIREO_OK && i.remaining_clients == 0 && f.detaches == detaches && rows[0].released);
    end(&f, 1);
    ++groups;
    start(&f, AF_UNIX, 2); stop(&f); f.release_io = true;
    unsigned const before = fd_count();
    CHECK(batch(&f, 3, rows, 3, &i, &e) == VIREO_RESULT_IO && i.attempted_clients == 1 && i.released_clients == 1 && i.remaining_clients == 1 && rows[0].released);
    CHECK(rows[0].result == VIREO_RESULT_IO && rows[0].error.primary.pool_error.connection_error.system_errno == EINTR);
    CHECK(e.primary.stage == VIREO_TCP_SERVER_CLIENT_RELEASE && e.primary.pool_error.stage == VIREO_CONNECTION_POOL_OPERATION_DESTROY_CONNECTION && e.primary.pool_error.connection_error.system_errno == EINTR);
    CHECK(fd_count() + 1 == before && info(f.owner).buffer_capacity_bytes == 256);
    int const reuse_guard = open("/dev/null", O_RDONLY | O_CLOEXEC); REQUIRE(reuse_guard >= 0);
    CHECK(batch(&f, 3, rows, 3, &i, NULL) == VIREO_RESULT_IO && i.remaining_clients == 0 && rows[0].released);
    CHECK(batch(&f, 3, rows, 3, &i, NULL) == VIREO_OK && i.attempted_clients == 0 && f.releases == 2);
    CHECK(fcntl(reuse_guard, F_GETFD) >= 0);
    REQUIRE(close(reuse_guard) == 0);
    end(&f, 2);
}
static void inspect_and_callback_errors(void)
{
    for (unsigned k = 0; k < 3; ++k) {
        ++groups;
        fixture_t f; start(&f, AF_UNIX, 1); stop(&f);
        if (k == 0) f.fail_lookup = f.lookups + 1;
        if (k == 1) f.inspect_fail = true;
        if (k == 2) f.active = true; /* public snapshot 桥接注入；不伪造真实在途线程。 */
        vireo_tcp_server_shutdown_result_t row;
        vireo_tcp_server_shutdown_info_t i;
        vireo_tcp_server_client_error_t e;
        CHECK(batch(&f, 3, &row, 1, &i, &e) == (k == 2 ? VIREO_RESULT_BUSY : VIREO_RESULT_INTERNAL));
        CHECK(i.attempted_clients == 1 && i.released_clients == 0 && i.remaining_clients == 1 && !row.released && f.detaches == 0 && f.releases == 0);
        CHECK(e.primary.stage == (k == 0 ? VIREO_TCP_SERVER_CLIENT_LOOKUP : k == 1 ? VIREO_TCP_SERVER_CLIENT_INSPECT : VIREO_TCP_SERVER_CLIENT_NONE));
        end(&f, 1);
    }
}
static void guard_and_nested(bool after_detach)
{
    ++groups;
    fixture_t f, g; start(&f, AF_UNIX, 1); start(&g, AF_UNIX, 1); stop(&f); stop(&g);
    f.nested = &g;
    f.probe_detach = !after_detach; f.probe_release = after_detach;
    vireo_tcp_server_shutdown_result_t row;
    vireo_tcp_server_shutdown_info_t i;
    CHECK(batch(&f, 3, &row, 1, &i, NULL) == VIREO_OK && i.remaining_clients == 0 && f.probe_calls == 1 && info(g.owner).connection_count == 0);
    CHECK(!info(f.owner).shutdown_active);
    end(&f, 1); end(&g, 1);
}
static void abandon_buffers(void)
{
    ++groups;
    fixture_t f; start(&f, AF_UNIX, 3);
    uint8_t const marker = 77;
    for (size_t k = 0; k < 3; ++k) {
        REQUIRE(send(f.peers[k], &marker, 1, MSG_NOSIGNAL) == 1);
        vireo_connection_receive_info_t ri;
        REQUIRE(vireo_tcp_server_client_receive(f.owner, f.clients[k], &drive_budget.receive, &ri, NULL) == VIREO_OK && ri.received_bytes == 1);
        REQUIRE(vireo_tcp_server_client_write_enqueue(f.owner, f.clients[k], &marker, 1, NULL) == VIREO_OK);
        if (k != 0) REQUIRE(vireo_tcp_server_client_request_close(f.owner, f.clients[k], k == 1 ? VIREO_CONNECTION_CLOSE_MODE_DRAIN : VIREO_CONNECTION_CLOSE_MODE_IMMEDIATE, VIREO_CONNECTION_CLOSE_REASON_SERVER_STOP, NULL) == VIREO_OK);
        vireo_tcp_server_client_info_t ci;
        REQUIRE(vireo_tcp_server_client_inspect(f.owner, f.clients[k], &ci) == VIREO_OK);
        CHECK(ci.connection_info.close_state == (k == 0 ? VIREO_CONNECTION_CLOSE_OPEN : k == 1 ? VIREO_CONNECTION_CLOSE_DRAINING : VIREO_CONNECTION_CLOSE_READY));
    }
    stop(&f);
    vireo_tcp_server_shutdown_result_t rows[3]; vireo_tcp_server_shutdown_info_t i;
    CHECK(batch(&f, 3, rows, 3, &i, NULL) == VIREO_OK && i.released_clients == 3);
    for (size_t k = 0; k < 3; ++k) { uint8_t b = 0; CHECK(recv(f.peers[k], &b, 1, MSG_DONTWAIT) == 0); }
    end(&f, 3);
}
static void execution_guards(void)
{
    ++groups;
    fixture_t f; start(&f, AF_UNIX, 1);
    uint8_t wire[32]; vireo_protocol_header_t h = {.command = VIREO_COMMAND_PING, .sequence = 1};
    REQUIRE(vireo_protocol_header_encode(&h, wire, sizeof(wire)) == VIREO_OK);
    REQUIRE(vireo_protocol_frame_crc32c_calculate(wire, sizeof(wire), NULL, 0, &h.crc32c) == VIREO_OK);
    REQUIRE(vireo_protocol_header_encode(&h, wire, sizeof(wire)) == VIREO_OK);
    REQUIRE(send(f.peers[0], wire, sizeof(wire), MSG_NOSIGNAL) == (ssize_t)sizeof(wire));
    vireo_connection_receive_info_t ri;
    REQUIRE(vireo_tcp_server_client_receive(f.owner, f.clients[0], &drive_budget.receive, &ri, NULL) == VIREO_OK && ri.received_bytes == 32);
    vireo_tcp_server_process_info_t pi;
    CHECK(vireo_tcp_server_client_process(f.owner, f.clients[0], &limits, &drive_budget.process, wire, sizeof(wire), handler, &f, &pi, NULL) == VIREO_OK && f.probe_calls == 1);
    end(&f, 1);
    ++groups;
    start(&f, AF_UNIX, 1);
    REQUIRE(vireo_tcp_server_client_flow_configure(f.owner, f.clients[0], &flow, NULL) == VIREO_OK);
    f.probe_receive = true;
    vireo_tcp_server_drive_info_t di;
    CHECK(vireo_tcp_server_client_drive(f.owner, f.clients[0], &limits, &drive_budget, wire, sizeof(wire), handler, &f, &di, NULL) == VIREO_OK && f.probe_calls == 1);
    end(&f, 1);
    ++groups;
    start(&f, AF_UNIX, 0); f.probe_wait = true;
    vireo_tcp_server_turn_result_t turns[3]; vireo_tcp_server_round_info_t round;
    CHECK(vireo_tcp_server_run_once(f.owner, 0, &limits, &drive_budget, &round_budget, wire, sizeof(wire), handler, &f, turns, 3, &round, NULL) == VIREO_OK && f.probe_calls == 1);
    end(&f, 0);
    ++groups;
    start(&f, AF_UNIX, 0);
    vireo_tcp_server_admission_options_t const ao = {connection_options, flow};
    REQUIRE(vireo_tcp_server_admission_configure(f.owner, &ao, NULL) == VIREO_OK);
    /* 已满客户但旧显式准入不隐式刷新，serve pre-sync 独立窗口才暂停 READ。 */
    listener_t const endpoint = {.address = f.address, .length = f.address_length, .family = f.family};
    for (size_t k = 0; k < 3; ++k) f.peers[k] = connect_peer(&endpoint);
    vireo_tcp_server_admit_info_t ai;
    REQUIRE(vireo_tcp_server_admit_batch(f.owner, &connection_options, &admit_budget,
        f.clients, 3, &ai, NULL) == VIREO_OK && ai.admitted_count == 3);
    f.probe_listener = true;
    vireo_tcp_server_serve_options_t const so = {0, limits, drive_budget, round_budget, admit_budget};
    vireo_tcp_server_serve_info_t serve;
    vireo_connection_pool_lease_t clients[3] = {{0}};
    CHECK(vireo_tcp_server_serve_once(f.owner, &so, wire, sizeof(wire), handler, &f,
        turns, 3, clients, 3, &serve, NULL) == VIREO_OK && f.probe_calls == 1);
    CHECK(!info(f.owner).serving_active);
    end(&f, 3);
}
static void run_observer_guard(void)
{
    ++groups;
    fixture_t f; start(&f, AF_UNIX, 1);
    REQUIRE(vireo_tcp_server_client_flow_configure(f.owner, f.clients[0], &flow, NULL) == VIREO_OK);
    vireo_tcp_server_admission_options_t const ao = {connection_options, flow};
    REQUIRE(vireo_tcp_server_admission_configure(f.owner, &ao, NULL) == VIREO_OK);
    f.probe_wait = true;
    uint8_t wire[32]; vireo_tcp_server_turn_result_t turns[3]; vireo_connection_pool_lease_t clients[3] = {{0}};
    vireo_tcp_server_run_options_t const ro = {limits, drive_budget, round_budget, admit_budget};
    CHECK(vireo_tcp_server_run(f.owner, &ro, wire, sizeof(wire), handler, &f, turns, 3, clients, 3, observer, &f, NULL) == VIREO_OK && f.probe_calls == 2);
    CHECK(!info(f.owner).running_active && info(f.owner).connection_count == 0);
    end(&f, 1);
}
static void maximum_batch_parameters(void)
{
    ++groups;
    fixture_t f; start(&f, AF_UNIX, 1); stop(&f);
    vireo_tcp_server_shutdown_result_t *rows = calloc(VIREO_TCP_SERVER_MAX_CONNECTIONS, sizeof(*rows));
    REQUIRE(rows != NULL);
    rows[1].lease = (vireo_connection_pool_lease_t){77, 88, 99};
    vireo_tcp_server_shutdown_info_t i;
    CHECK(batch(&f, VIREO_TCP_SERVER_MAX_CONNECTIONS, rows, VIREO_TCP_SERVER_MAX_CONNECTIONS, &i, NULL) == VIREO_OK);
    CHECK(i.attempted_clients == 1 && i.released_clients == 1 && i.remaining_clients == 0 && i.scanned_slots <= 3);
    CHECK(rows[0].released && same(rows[1].lease, (vireo_connection_pool_lease_t){77, 88, 99}));
    CHECK(f.control_allocations == 1 && f.control_frees == 0);
    free(rows); end(&f, 1);
}
static void allocation_boundary(void)
{
    ++groups;
    vireo_tcp_server_t *server = NULL;
    REQUIRE(vireo_tcp_server_create(&server_options, &server, NULL) == VIREO_OK);
    size_t const total = info(server).allocation_bytes;
    REQUIRE(vireo_tcp_server_destroy(&server, NULL) == VIREO_OK);
    vireo_tcp_server_options_t o = server_options; o.max_memory_bytes = total;
    CHECK(vireo_tcp_server_create(&o, &server, NULL) == VIREO_OK && info(server).allocation_bytes == total);
    REQUIRE(vireo_tcp_server_destroy(&server, NULL) == VIREO_OK);
    o.max_memory_bytes = total - 1;
    CHECK(vireo_tcp_server_create(&o, &server, NULL) == VIREO_RESULT_RANGE && server == NULL);
}
int main(void)
{
    unsigned const before = fd_count();
    empty_and_parameters();
    normal(AF_UNIX, false); normal(AF_INET, false); normal(AF_UNIX, true); normal(AF_INET, true);
    sparse_and_capacity(); detach_and_release_errors(); inspect_and_callback_errors();
    guard_and_nested(false); guard_and_nested(true); abandon_buffers(); execution_guards();
    run_observer_guard(); maximum_batch_parameters(); allocation_boundary();
    unsigned const after = fd_count(); CHECK(before == after);
    printf("tcp_server shutdown: %u groups, %u failures; fd %u -> %u\n", groups, failures, before, after);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
