/*
- PROJECT : VIREO
- FILE    : test_tcp_server_admission.c
- AUTHOR  : bitofux
- DATE    : 2026-10-05
- BRIEF   : 此模块负责：
- -- 有界准入、固定容量账、成功前缀与逐阶段当前 owner 清理
- -- 默认公共装配、观察、严格 DEL 与消费型 IO 归还
 */
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
static vireo_tcp_server_admit_budget_t const budget = {3, 8};
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
    int last_fd;
} fixture_t;
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
    return vireo_connection_pool_adopt(p, c, l, e);
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
    if (f->detach_io) {
        *e = (vireo_connection_loop_error_t){VIREO_CONNECTION_LOOP_STAGE_DETACH,
            {VIREO_EVENT_LOOP_STAGE_DEL, {VIREO_EPOLL_STAGE_DEL, EBADF}, EIO}};
        return VIREO_RESULT_IO;
    }
    return vireo_connection_detach(c, e);
}
static vireo_result_t release_connection(void *ctx, vireo_connection_pool_t *p,
    vireo_connection_pool_lease_t *l, vireo_connection_pool_operation_error_t *e)
{
    fixture_t *f = ctx; ++f->releases;
    if (f->release_busy) return VIREO_RESULT_BUSY;
    vireo_result_t const r = vireo_connection_pool_release(p, l, e);
    REQUIRE(r == VIREO_OK && empty(*l));
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
{ (void)ctx; return vireo_connection_receive(c, b, i, e); }
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
static void *allocate(void *ctx, size_t n) { (void)ctx; return malloc(n); }
static void deallocate(void *ctx, void *p) { (void)ctx; free(p); }
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
static void create(fixture_t *f, vireo_tcp_server_options_t options)
{
    vireo_tcp_server_ops_t b = {f, allocate, deallocate, create_loop, inspect_loop, destroy_loop,
                                create_pool, inspect_pool, destroy_pool};
    vireo_tcp_server_client_ops_t c = client_ops(f);
    REQUIRE(vireo_tcp_server_create_with_client_ops(&options, &b, NULL, &c, &f->owner, NULL) == VIREO_OK);
    memset(&c, 0, sizeof(c)); /* 逐对象按值复制。 */
}
static vireo_tcp_server_info_t info(vireo_tcp_server_t *server)
{ vireo_tcp_server_info_t i; REQUIRE(vireo_tcp_server_inspect(server, &i) == VIREO_OK); return i; }
static void adopt_listener(vireo_tcp_server_t *server, listener_t *a)
{ REQUIRE(vireo_tcp_server_adopt_listener(server, &a->owner, NULL) == VIREO_OK && a->owner == NULL); }
static void native_public(int family)
{
    ++groups; vireo_tcp_server_t *server = NULL;
    vireo_tcp_server_options_t options = server_options; options.connection_capacity = 2; options.max_buffer_bytes = 512;
    REQUIRE(vireo_tcp_server_create(&options, &server, NULL) == VIREO_OK);
    listener_t a = listener_create(family); adopt_listener(server, &a);
    REQUIRE(vireo_tcp_server_bind_listener(server, false, NULL) == VIREO_OK); /* 暂停仍可显式准入。 */
    int peers[3]; for (size_t i = 0; i < 3; ++i) peers[i] = connect_peer(&a);
    vireo_connection_pool_lease_t leases[4] = {{0}, {0}, {0}, {77, 88, 99}};
    vireo_tcp_server_admit_info_t progress; vireo_tcp_server_client_error_t e;
    errno = EDOM;
    REQUIRE(vireo_tcp_server_admit_batch(server, &connection_options, &budget, leases, 4, &progress, &e) == VIREO_OK && errno == EDOM);
    CHECK(progress.accepted_count == 2 && progress.admitted_count == 2 && progress.rejected_count == 0 &&
          progress.accept_calls == 2 && progress.stop_reason == VIREO_TCP_SERVER_ADMIT_CONNECTION_LIMIT);
    CHECK(empty(leases[2]) && leases[3].pool_id == 77 && leases[3].slot_index == 88 && leases[3].generation == 99);
    CHECK(e.primary.stage == VIREO_TCP_SERVER_CLIENT_NONE && e.cleanup_result == VIREO_OK);
    vireo_tcp_server_info_t const state = info(server);
    CHECK(state.connection_count == 2 && state.registered_connections == 2 && state.available_connections == 0 &&
          state.buffer_capacity_bytes == 512 && state.client_slots_bytes > 0 && state.server_allocation_bytes > state.client_slots_bytes);
    vireo_tcp_server_t *const before = server;
    CHECK(vireo_tcp_server_destroy(&server, NULL) == VIREO_RESULT_BUSY && server == before);
    vireo_connection_pool_lease_t const old = leases[0];
    REQUIRE(vireo_tcp_server_release_client(server, &leases[0], NULL) == VIREO_OK && empty(leases[0]));
    vireo_tcp_server_client_info_t ci;
    CHECK(vireo_tcp_server_client_inspect(server, old, &ci) == VIREO_RESULT_NOT_FOUND);
    vireo_connection_pool_lease_t next = {0}; vireo_tcp_server_admit_budget_t const one = {1, 1};
    REQUIRE(vireo_tcp_server_admit_batch(server, &connection_options, &one, &next, 1, &progress, NULL) == VIREO_OK);
    CHECK(progress.admitted_count == 1 && !same(old, next));
    REQUIRE(vireo_tcp_server_client_inspect(server, next, &ci) == VIREO_OK);
    CHECK(ci.connection_info.loop_attached && ci.connection_info.loop_interests ==
          (VIREO_EPOLL_INTEREST_READ | VIREO_EPOLL_INTEREST_PEER_WRITE_CLOSED) && ci.last_events == 0);
    REQUIRE(vireo_tcp_server_release_client(server, &next, NULL) == VIREO_OK);
    REQUIRE(vireo_tcp_server_release_client(server, &leases[1], NULL) == VIREO_OK);
    REQUIRE(vireo_tcp_server_destroy(&server, NULL) == VIREO_OK);
    for (size_t i = 0; i < 3; ++i) REQUIRE(close(peers[i]) == 0);
}
static void parameters(void)
{
    ++groups; fixture_t f = {0}; create(&f, server_options); listener_t a = listener_create(AF_INET);
    vireo_connection_pool_lease_t l[3] = {{0}};
    vireo_tcp_server_admit_info_t p, saved; memset(&p, 0xa5, sizeof(p)); memcpy(&saved, &p, sizeof(p));
    CHECK(vireo_tcp_server_admit_batch(f.owner, &connection_options, &budget, l, 3, &p, NULL) == VIREO_RESULT_NOT_FOUND);
    adopt_listener(f.owner, &a);
    for (unsigned k = 0; k < 13; ++k) {
        vireo_connection_options_t o = connection_options; vireo_tcp_server_admit_budget_t b = budget;
        size_t n = 3; vireo_result_t expected = VIREO_RESULT_INVALID_ARGUMENT;
        if (k == 5) b.max_accepts = 0;
        if (k == 6) b.max_accept_syscalls = 0;
        if (k == 7) { n = 0; expected = VIREO_RESULT_RANGE; }
        if (k == 8) { b.max_accepts = VIREO_TCP_SERVER_MAX_CONNECTIONS + 1; expected = VIREO_RESULT_RANGE; }
        if (k == 9) { o.read_capacity = 0; expected = VIREO_RESULT_RANGE; }
        if (k == 10) { o.read_capacity = SIZE_MAX; expected = VIREO_RESULT_OVERFLOW; }
        if (k == 11) { o.read_capacity = 1024; o.max_buffer_bytes = 2048; expected = VIREO_RESULT_RANGE; }
        if (k == 12) l[1].generation = 1;
        errno = EDOM;
        vireo_result_t const r = vireo_tcp_server_admit_batch(k == 0 ? NULL : f.owner,
            k == 1 ? NULL : &o, k == 2 ? NULL : &b, k == 3 ? NULL : l, n, k == 4 ? NULL : &p, NULL);
        CHECK(r == expected && errno == EDOM && memcmp(&p, &saved, sizeof(p)) == 0 && f.accepts == 0);
        l[1] = (vireo_connection_pool_lease_t){0};
    }
    CHECK(vireo_tcp_server_release_client(NULL, &l[0], NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_tcp_server_release_client(f.owner, NULL, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_tcp_server_release_client(f.owner, &l[0], NULL) == VIREO_RESULT_NOT_FOUND);
    REQUIRE(vireo_tcp_server_destroy(&f.owner, NULL) == VIREO_OK);
    for (unsigned k = 0; k < 11; ++k) {
        vireo_tcp_server_client_ops_t o = client_ops(&f);
        switch (k) {
        case 0:o.accept=NULL;break;case 1:o.create=NULL;break;case 2:o.inspect=NULL;break;
        case 3:o.adopt=NULL;break;case 4:o.lookup=NULL;break;case 5:o.attach=NULL;break;
        case 6:o.detach=NULL;break;case 7:o.release=NULL;break;case 8:o.destroy=NULL;break;
        case 9:o.close_fd=NULL;break;default:break;
        }
        CHECK(vireo_tcp_server_create_with_client_ops(&server_options, NULL, NULL, k == 10 ? NULL : &o,
                                                       &f.owner, NULL) == VIREO_RESULT_INVALID_ARGUMENT && f.owner == NULL);
    }
}
static void stops(void)
{
    ++groups; fixture_t f = {0}; vireo_tcp_server_options_t o = server_options; o.max_buffer_bytes = 256;
    create(&f, o); listener_t a = listener_create(AF_INET); adopt_listener(f.owner, &a);
    vireo_connection_pool_lease_t l[3] = {{0}}; vireo_tcp_server_admit_info_t p;
    REQUIRE(vireo_tcp_server_admit_batch(f.owner, &connection_options, &budget, l, 3, &p, NULL) == VIREO_OK);
    CHECK(p.stop_reason == VIREO_TCP_SERVER_ADMIT_WOULD_BLOCK && p.accept_calls == 1 && p.accepted_count == 0);
    int const peer1 = connect_peer(&a), peer2 = connect_peer(&a);
    REQUIRE(vireo_tcp_server_admit_batch(f.owner, &connection_options, &budget, l, 3, &p, NULL) == VIREO_OK);
    CHECK(p.admitted_count == 1 && p.accept_calls == 1 && p.stop_reason == VIREO_TCP_SERVER_ADMIT_BUFFER_LIMIT);
    unsigned const calls = f.accepts;
    vireo_connection_pool_lease_t more[2] = {{0}};
    REQUIRE(vireo_tcp_server_admit_batch(f.owner, &connection_options, &budget, more, 2, &p, NULL) == VIREO_OK);
    CHECK(p.accept_calls == 0 && f.accepts == calls && p.stop_reason == VIREO_TCP_SERVER_ADMIT_BUFFER_LIMIT);
    REQUIRE(vireo_tcp_server_release_client(f.owner, &l[0], NULL) == VIREO_OK);
    vireo_tcp_server_admit_budget_t const one = {1, 1};
    REQUIRE(vireo_tcp_server_admit_batch(f.owner, &connection_options, &one, more, 1, &p, NULL) == VIREO_OK);
    CHECK(p.admitted_count == 1 && p.stop_reason == VIREO_TCP_SERVER_ADMIT_BATCH_LIMIT);
    REQUIRE(vireo_tcp_server_release_client(f.owner, &more[0], NULL) == VIREO_OK);
    REQUIRE(close(peer1) == 0 && close(peer2) == 0);
    REQUIRE(vireo_tcp_server_destroy(&f.owner, NULL) == VIREO_OK);
}
static void call_budget_and_errors(void)
{
    ++groups;
    for (unsigned k = 0; k < 5; ++k) {
        fixture_t f = {0}; create(&f, server_options); listener_t a = listener_create(AF_INET); adopt_listener(f.owner, &a);
        int const peer = connect_peer(&a);
        vireo_connection_pool_lease_t l[3] = {{0}}; vireo_tcp_server_admit_info_t p; vireo_tcp_server_client_error_t e;
        vireo_tcp_server_admit_budget_t b = budget;
        if (k == 0) b.max_accept_syscalls = 1;
        if (k == 1) { f.transients = 2; b.max_accept_syscalls = 2; }
        if (k == 2) f.transients = 2;
        if (k == 3) f.accept_errno = EINTR;
        if (k == 4) f.accept_errno = EMFILE;
        errno = EDOM;
        vireo_result_t const r = vireo_tcp_server_admit_batch(f.owner, &connection_options, &b, l, 3, &p, &e);
        CHECK(errno == EDOM);
        if (k >= 3) CHECK(r == VIREO_RESULT_IO && f.accepts == 1 && p.accept_calls == 1 &&
            p.admitted_count == 0 && p.stop_reason == VIREO_TCP_SERVER_ADMIT_ERROR &&
            e.primary.stage == VIREO_TCP_SERVER_CLIENT_ACCEPT && e.primary.acceptor_error.system_errno == f.accept_errno);
        else {
            CHECK(r == VIREO_OK);
            if (k == 0) CHECK(p.admitted_count == 1 && p.accept_calls == 1 && p.stop_reason == VIREO_TCP_SERVER_ADMIT_CALL_LIMIT);
            if (k == 1) CHECK(p.admitted_count == 0 && p.accept_calls == 2 && p.transient_errors == 2 && p.stop_reason == VIREO_TCP_SERVER_ADMIT_CALL_LIMIT);
            if (k == 2) CHECK(p.admitted_count == 1 && p.accept_calls == 4 && p.transient_errors == 2 && p.stop_reason == VIREO_TCP_SERVER_ADMIT_WOULD_BLOCK);
            if (p.admitted_count != 0) REQUIRE(vireo_tcp_server_release_client(f.owner, &l[0], NULL) == VIREO_OK);
        }
        REQUIRE(close(peer) == 0); REQUIRE(vireo_tcp_server_destroy(&f.owner, NULL) == VIREO_OK);
    }
}
static void setup_failures(void)
{
    ++groups;
    for (unsigned k = 0; k < 8; ++k) {
        fixture_t f = {0}; create(&f, server_options); listener_t a = listener_create(AF_INET); adopt_listener(f.owner, &a);
        int const peer1 = connect_peer(&a), peer2 = connect_peer(&a);
        unsigned const kind = k % 4;
        if (kind == 0) { f.fail_create = 2; f.close_io = k >= 4; }
        if (kind == 1) { f.fail_adopt = 2; f.destroy_io = k >= 4; }
        if (kind == 2) { f.fail_lookup = 2; f.release_io = k >= 4; }
        if (kind == 3) { f.fail_attach = 2; f.release_io = k >= 4; }
        vireo_connection_pool_lease_t l[3] = {{0}}; vireo_tcp_server_admit_info_t p; vireo_tcp_server_client_error_t e;
        errno = EDOM;
        vireo_result_t const r = vireo_tcp_server_admit_batch(f.owner, &connection_options, &budget, l, 3, &p, &e);
        CHECK(errno == EDOM && p.accepted_count == 2 && p.admitted_count == 1 && p.rejected_count == 1 &&
              p.accept_calls == 2 && p.stop_reason == VIREO_TCP_SERVER_ADMIT_ERROR && !empty(l[0]) && empty(l[1]) && empty(l[2]));
        CHECK(info(f.owner).connection_count == 1 && info(f.owner).registered_connections == 1 && info(f.owner).buffer_capacity_bytes == 256);
        CHECK(fcntl(f.last_fd, F_GETFD) == -1 && errno == EBADF);
        if (kind == 0) CHECK(r == VIREO_RESULT_NO_MEMORY && f.closes == 1 && e.primary.stage == VIREO_TCP_SERVER_CLIENT_CREATE &&
                            e.primary.connection_error.stage == VIREO_CONNECTION_STAGE_CREATE_READ_BUFFER);
        if (kind == 1) CHECK(r == VIREO_RESULT_BUSY && f.destroys == 1 && e.primary.stage == VIREO_TCP_SERVER_CLIENT_ADOPT &&
                            e.primary.pool_error.stage == VIREO_CONNECTION_POOL_OPERATION_ACQUIRE_SLOT);
        if (kind == 2) CHECK(r == VIREO_RESULT_INTERNAL && f.releases == 1 && e.primary.stage == VIREO_TCP_SERVER_CLIENT_LOOKUP);
        if (kind == 3) CHECK(r == VIREO_RESULT_IO && f.releases == 1 && e.primary.stage == VIREO_TCP_SERVER_CLIENT_ATTACH &&
                            e.primary.loop_error.stage == VIREO_CONNECTION_LOOP_STAGE_ATTACH &&
                            e.primary.loop_error.loop_error.epoll_error.system_errno == ENOSPC && e.primary.loop_error.loop_error.system_errno == EIO);
        CHECK(e.cleanup_result == (k >= 4 ? VIREO_RESULT_IO : VIREO_OK));
        if (k >= 4) {
            if (kind == 0) CHECK(e.cleanup.stage == VIREO_TCP_SERVER_CLIENT_CLOSE_PENDING_FD && e.cleanup.system_errno == EINTR);
            if (kind == 1) CHECK(e.cleanup.stage == VIREO_TCP_SERVER_CLIENT_DESTROY_PENDING && e.cleanup.connection_error.system_errno == EIO);
            if (kind >= 2) CHECK(e.cleanup.stage == VIREO_TCP_SERVER_CLIENT_RELEASE && e.cleanup.pool_error.connection_error.system_errno == EINTR);
        }
        f.release_io = false;
        REQUIRE(vireo_tcp_server_release_client(f.owner, &l[0], NULL) == VIREO_OK);
        REQUIRE(close(peer1) == 0 && close(peer2) == 0);
        REQUIRE(vireo_tcp_server_destroy(&f.owner, NULL) == VIREO_OK);
    }
}
static void release_stages(void)
{
    ++groups; fixture_t f = {0}; create(&f, server_options); listener_t a = listener_create(AF_INET); adopt_listener(f.owner, &a);
    int const peer = connect_peer(&a); vireo_connection_pool_lease_t l = {0}; vireo_tcp_server_admit_info_t p;
    REQUIRE(vireo_tcp_server_admit_batch(f.owner, &connection_options, &budget, &l, 1, &p, NULL) == VIREO_OK);
    vireo_connection_pool_lease_t const old = l; vireo_tcp_server_client_error_t e;
    f.active = true; CHECK(vireo_tcp_server_release_client(f.owner, &l, &e) == VIREO_RESULT_BUSY && same(l, old) && f.detaches == 0);
    f.active = false; f.detach_io = true; errno = EDOM;
    CHECK(vireo_tcp_server_release_client(f.owner, &l, &e) == VIREO_RESULT_IO && errno == EDOM && same(l, old) &&
          e.primary.stage == VIREO_TCP_SERVER_CLIENT_DETACH && e.primary.loop_error.loop_error.epoll_error.system_errno == EBADF);
    CHECK(info(f.owner).registered_connections == 1 && info(f.owner).buffer_capacity_bytes == 256 && f.releases == 0);
    f.detach_io = false; f.release_busy = true;
    CHECK(vireo_tcp_server_release_client(f.owner, &l, &e) == VIREO_RESULT_BUSY && same(l, old));
    CHECK(info(f.owner).registered_connections == 0 && info(f.owner).connection_count == 1 && info(f.owner).buffer_capacity_bytes == 256);
    vireo_tcp_server_client_info_t ci; REQUIRE(vireo_tcp_server_client_inspect(f.owner, l, &ci) == VIREO_OK && !ci.connection_info.loop_attached);
    f.release_busy = false; f.release_io = true; errno = EDOM;
    CHECK(vireo_tcp_server_release_client(f.owner, &l, &e) == VIREO_RESULT_IO && errno == EDOM && empty(l) &&
          e.primary.stage == VIREO_TCP_SERVER_CLIENT_RELEASE && e.primary.pool_error.connection_error.system_errno == EINTR);
    CHECK(f.detaches == 2 && f.releases == 2 && info(f.owner).connection_count == 0 && info(f.owner).buffer_capacity_bytes == 0);
    CHECK(vireo_tcp_server_release_client(f.owner, &l, NULL) == VIREO_RESULT_NOT_FOUND);
    CHECK(vireo_tcp_server_client_inspect(f.owner, old, &ci) == VIREO_RESULT_NOT_FOUND);
    REQUIRE(close(peer) == 0); REQUIRE(vireo_tcp_server_destroy(&f.owner, NULL) == VIREO_OK);
}
static void observation_and_identity(void)
{
    ++groups; fixture_t f = {0}; create(&f, server_options); listener_t a = listener_create(AF_UNIX); adopt_listener(f.owner, &a);
    int const peer = connect_peer(&a); vireo_connection_pool_lease_t l = {0}; vireo_tcp_server_admit_info_t p;
    REQUIRE(vireo_tcp_server_admit_batch(f.owner, &connection_options, &budget, &l, 1, &p, NULL) == VIREO_OK);
    REQUIRE(send(peer, "old", 3, MSG_NOSIGNAL) == 3);
    vireo_event_loop_run_info_t run;
    REQUIRE(vireo_event_loop_run_once(f.loop, 1000, &run, NULL) == VIREO_OK);
    vireo_tcp_server_client_info_t ci;
    REQUIRE(vireo_tcp_server_client_inspect(f.owner, l, &ci) == VIREO_OK);
    CHECK(run.dispatched_count == 1 && ci.last_events == VIREO_EPOLL_EVENT_READ && ci.connection_info.read_buffer.readable_size == 0);
    vireo_connection_pool_lease_t bad[3] = {l, l, l}; bad[0].pool_id = 0; bad[1].slot_index = server_options.connection_capacity; bad[2].generation += 1;
    vireo_result_t const expected[3] = {VIREO_RESULT_INVALID_ARGUMENT, VIREO_RESULT_RANGE, VIREO_RESULT_NOT_FOUND};
    for (size_t k = 0; k < 3; ++k) {
        vireo_tcp_server_client_info_t saved; memset(&ci, 0xa5, sizeof(ci)); memcpy(&saved, &ci, sizeof(ci)); errno = EDOM;
        CHECK(vireo_tcp_server_client_inspect(f.owner, bad[k], &ci) == expected[k] && memcmp(&ci, &saved, sizeof(ci)) == 0 && errno == EDOM);
        vireo_connection_pool_lease_t const old = bad[k];
        CHECK(vireo_tcp_server_release_client(f.owner, &bad[k], NULL) == expected[k] &&
              same(old, bad[k]) && errno == EDOM && f.detaches == 0 && f.releases == 0);
    }
    vireo_tcp_server_t *other = NULL; REQUIRE(vireo_tcp_server_create(&server_options, &other, NULL) == VIREO_OK);
    CHECK(vireo_tcp_server_client_inspect(other, l, &ci) == VIREO_RESULT_INVALID_ARGUMENT);
    vireo_connection_pool_lease_t foreign = l;
    CHECK(vireo_tcp_server_release_client(other, &foreign, NULL) == VIREO_RESULT_INVALID_ARGUMENT && same(foreign, l));
    REQUIRE(vireo_tcp_server_destroy(&other, NULL) == VIREO_OK);
    for (unsigned k = 0; k < 2; ++k) {
        f.inspect_fail = k == 0; f.corrupt_info = k == 1;
        vireo_tcp_server_client_info_t saved; memset(&ci, 0xa5, sizeof(ci)); memcpy(&saved, &ci, sizeof(ci)); errno = EDOM;
        CHECK(vireo_tcp_server_client_inspect(f.owner, l, &ci) == VIREO_RESULT_INTERNAL && memcmp(&ci, &saved, sizeof(ci)) == 0 && errno == EDOM);
    }
    f.inspect_fail = true; f.corrupt_info = false;
    vireo_connection_pool_lease_t const kept = l;
    CHECK(vireo_tcp_server_release_client(f.owner, &l, NULL) == VIREO_RESULT_INTERNAL &&
          same(kept, l) && f.detaches == 0 && f.releases == 0);
    f.inspect_fail = false;
    REQUIRE(vireo_tcp_server_release_client(f.owner, &l, NULL) == VIREO_OK);
    REQUIRE(close(peer) == 0); REQUIRE(vireo_tcp_server_destroy(&f.owner, NULL) == VIREO_OK);
}
int main(void)
{
    unsigned const before = fd_count();
    native_public(AF_INET); native_public(AF_UNIX); parameters(); stops(); call_budget_and_errors();
    setup_failures(); release_stages(); observation_and_identity();
    unsigned const after = fd_count(); CHECK(before == after);
    printf("tcp_server admission: %u groups, %u failures; fd %u -> %u\n", groups, failures, before, after);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
