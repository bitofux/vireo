/*
- PROJECT : VIREO
- FILE    : test_tcp_server_listener.c
- AUTHOR  : bitofux
- DATE    : 2026-10-04
- BRIEF   : 此模块负责：
- -- 监听 owner、真实预算、严格登记与失败保持
- -- TCP/Unix 只观察通知，以及整体消费清理与双错诊断
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

static unsigned failures;
static unsigned groups;
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #c); ++failures; } } while (0)
#define REQUIRE(c) do { if (!(c)) { fprintf(stderr, "fixture %s:%d: %s\n", __FILE__, __LINE__, #c); exit(EXIT_FAILURE); } } while (0)
static vireo_tcp_server_options_t const options = {3, 2, 1048576, 4096};

typedef struct fixture {
    vireo_tcp_server_t *owner;
    vireo_event_loop_t *loop; /* 仅本层公开 wrapper 捕获的测试借用，无下游 getter。 */
    vireo_acceptor_t *listener;
    vireo_acceptor_callback_t callback;
    void *callback_context;
    unsigned adds, mods, dels, loop_destroys, listener_destroys, forgets;
    unsigned corrupt;
    bool active, inspect_fail, add_fail, mod_fail, del_fail, pool_busy, loop_io, listener_io;
    char order[32];
    size_t order_size;
} fixture_t;

static void record(fixture_t *f, char c)
{
    REQUIRE(f->order_size + 1 < sizeof(f->order));
    f->order[f->order_size++] = c;
    f->order[f->order_size] = '\0';
    errno = E2BIG;
}
static void *allocate(void *ctx, size_t n) { (void)ctx; return malloc(n); }
static void deallocate(void *ctx, void *p) { record(ctx, 'F'); free(p); }
static vireo_result_t create_loop(void *ctx, vireo_event_loop_options_t const *o,
                                  vireo_event_loop_t **p, vireo_event_loop_error_t *e)
{
    fixture_t *f = ctx;
    vireo_result_t const r = vireo_event_loop_create(o, p, e);
    if (r == VIREO_OK) f->loop = *p;
    return r;
}
static vireo_result_t inspect_loop(void *ctx, vireo_event_loop_t const *p, vireo_event_loop_info_t *i)
{ (void)ctx; return vireo_event_loop_inspect(p, i); }
static vireo_result_t destroy_loop(void *ctx, vireo_event_loop_t **p, vireo_event_loop_error_t *e)
{
    fixture_t *f = ctx;
    record(f, 'l'); ++f->loop_destroys;
    vireo_result_t const r = vireo_event_loop_destroy(p, e);
    REQUIRE(r == VIREO_OK && *p == NULL);
    f->loop = NULL;
    if (!f->loop_io) return r;
    *e = (vireo_event_loop_error_t){VIREO_EVENT_LOOP_STAGE_DESTROY_EPOLL,
        {VIREO_EPOLL_STAGE_CLOSE, EINTR}, EIO};
    return VIREO_RESULT_IO;
}
static vireo_result_t create_pool(void *ctx, vireo_connection_pool_options_t const *o,
                                  vireo_connection_pool_t **p, vireo_connection_pool_error_t *e)
{ (void)ctx; return vireo_connection_pool_create(o, p, e); }
static vireo_result_t inspect_pool(void *ctx, vireo_connection_pool_t const *p,
                                   vireo_connection_pool_info_t *i)
{ (void)ctx; return vireo_connection_pool_inspect(p, i); }
static vireo_result_t destroy_pool(void *ctx, vireo_connection_pool_t **p,
                                   vireo_connection_pool_error_t *e)
{
    fixture_t *f = ctx;
    record(f, 'p');
    if (f->pool_busy) return VIREO_RESULT_BUSY;
    return vireo_connection_pool_destroy(p, e);
}
static vireo_result_t inspect_listener(void *ctx, vireo_acceptor_t const *p, vireo_acceptor_info_t *i)
{
    fixture_t *f = ctx;
    if (f->inspect_fail) return VIREO_RESULT_INTERNAL;
    vireo_result_t const r = vireo_acceptor_inspect(p, i);
    if (r != VIREO_OK) return r;
    switch (f->corrupt) {
    case 1: i->allocation_bytes = 0; break;
    case 2: i->max_memory_bytes = 0; break;
    case 3: i->allocation_bytes = SIZE_MAX; break;
    case 4: i->max_memory_bytes = VIREO_ACCEPTOR_MAX_MEMORY + 1; break;
    case 5: i->read_enabled = true; i->loop_attached = false; break;
    case 6: ++i->allocation_bytes; break;
    case 7: --i->max_memory_bytes; break;
    case 8: i->loop_attached = !i->loop_attached; break;
    default: break;
    }
    if (f->active) i->callback_active = true;
    errno = ERANGE;
    return r;
}
static void binding_cause(vireo_acceptor_loop_error_t *e, unsigned kind)
{
    e->stage = kind == 1 ? VIREO_ACCEPTOR_LOOP_STAGE_ATTACH :
        kind == 2 ? VIREO_ACCEPTOR_LOOP_STAGE_UPDATE : VIREO_ACCEPTOR_LOOP_STAGE_DETACH;
    e->loop_error = (vireo_event_loop_error_t){
        kind == 1 ? VIREO_EVENT_LOOP_STAGE_ADD : kind == 2 ? VIREO_EVENT_LOOP_STAGE_MOD : VIREO_EVENT_LOOP_STAGE_DEL,
        {kind == 1 ? VIREO_EPOLL_STAGE_ADD : kind == 2 ? VIREO_EPOLL_STAGE_MOD : VIREO_EPOLL_STAGE_DEL, EBADF}, EIO};
    errno = E2BIG;
}
static vireo_result_t attach(void *ctx, vireo_acceptor_t *a, vireo_event_loop_t *l,
                             bool enabled, vireo_acceptor_callback_t cb, void *cbctx,
                             vireo_acceptor_loop_error_t *e)
{
    fixture_t *f = ctx; ++f->adds;
    if (f->add_fail) { binding_cause(e, 1); return VIREO_RESULT_IO; }
    vireo_result_t const r = vireo_acceptor_attach(a, l, enabled, cb, cbctx, e);
    if (r == VIREO_OK) { f->listener = a; f->callback = cb; f->callback_context = cbctx; }
    return r;
}
static vireo_result_t set_read(void *ctx, vireo_acceptor_t *a, bool enabled, vireo_acceptor_loop_error_t *e)
{
    fixture_t *f = ctx; ++f->mods;
    if (f->mod_fail) { binding_cause(e, 2); return VIREO_RESULT_IO; }
    return vireo_acceptor_set_read_enabled(a, enabled, e);
}
static vireo_result_t detach(void *ctx, vireo_acceptor_t *a, vireo_acceptor_loop_error_t *e)
{
    fixture_t *f = ctx; ++f->dels;
    if (f->del_fail) { binding_cause(e, 3); return VIREO_RESULT_IO; }
    return vireo_acceptor_detach(a, e);
}
static vireo_result_t forget(void *ctx, vireo_acceptor_t *a)
{
    fixture_t *f = ctx; record(f, 'g'); ++f->forgets;
    REQUIRE(f->loop == NULL); /* 真实消费而非 stop/BUSY，且驱动已返回。 */
    return vireo_acceptor_forget_destroyed_loop(a, NULL);
}
static vireo_result_t destroy_listener(void *ctx, vireo_acceptor_t **a, vireo_acceptor_error_t *e)
{
    fixture_t *f = ctx; record(f, 'a'); ++f->listener_destroys;
    vireo_result_t const r = vireo_acceptor_destroy(a, e);
    REQUIRE(r == VIREO_OK && *a == NULL);
    f->listener = NULL;
    if (!f->listener_io) return r;
    *e = (vireo_acceptor_error_t){VIREO_ACCEPTOR_STAGE_CLOSE_LISTENER, ENOSPC};
    return VIREO_RESULT_IO;
}
static vireo_tcp_server_ops_t base_ops(fixture_t *f)
{
    return (vireo_tcp_server_ops_t){f, allocate, deallocate, create_loop, inspect_loop,
        destroy_loop, create_pool, inspect_pool, destroy_pool};
}
static vireo_tcp_server_listener_ops_t listener_ops(fixture_t *f)
{
    return (vireo_tcp_server_listener_ops_t){f, inspect_listener, attach, set_read, detach, forget, destroy_listener};
}
static void create(fixture_t *f, vireo_tcp_server_options_t o)
{
    vireo_tcp_server_ops_t b = base_ops(f);
    vireo_tcp_server_listener_ops_t a = listener_ops(f);
    REQUIRE(vireo_tcp_server_create_with_all_ops(&o, &b, &a, &f->owner, NULL) == VIREO_OK);
    memset(&b, 0, sizeof(b)); memset(&a, 0, sizeof(a)); /* 按值复制，非表地址借用。 */
}
static vireo_tcp_server_info_t info(fixture_t *f)
{
    vireo_tcp_server_info_t i;
    errno = EDOM;
    REQUIRE(vireo_tcp_server_inspect(f->owner, &i) == VIREO_OK && errno == EDOM);
    return i;
}
static unsigned fd_count(void)
{
    DIR *d = opendir("/proc/self/fd"); REQUIRE(d != NULL);
    unsigned n = 0; struct dirent *e;
    while ((e = readdir(d)) != NULL) if (e->d_name[0] != '.') ++n;
    REQUIRE(closedir(d) == 0); return n;
}
typedef struct listener_fixture {
    vireo_acceptor_t *owner;
    int original_fd;
    struct sockaddr_storage address;
    socklen_t length;
    int family;
} listener_fixture_t;
static listener_fixture_t listener_create(int family)
{
    static unsigned serial;
    listener_fixture_t a = {.family = family};
    int fd = socket(family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0); REQUIRE(fd >= 0);
    a.original_fd = fd;
    if (family == AF_INET) {
        struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr = {htonl(INADDR_LOOPBACK)}};
        a.length = (socklen_t)sizeof(address);
        REQUIRE(bind(fd, (struct sockaddr *)&address, a.length) == 0);
        REQUIRE(getsockname(fd, (struct sockaddr *)&a.address, &a.length) == 0);
    } else {
        struct sockaddr_un address = {.sun_family = AF_UNIX};
        int const n = snprintf(address.sun_path + 1, sizeof(address.sun_path) - 1,
                               "vireo-server-m2-%ld-%u", (long)getpid(), ++serial);
        REQUIRE(n > 0 && (size_t)n < sizeof(address.sun_path) - 1);
        a.length = (socklen_t)sizeof(address);
        memcpy(&a.address, &address, sizeof(address));
        REQUIRE(bind(fd, (struct sockaddr *)&a.address, a.length) == 0);
    }
    REQUIRE(listen(fd, 8) == 0);
    vireo_acceptor_options_t const o = {VIREO_ACCEPTOR_MAX_MEMORY};
    REQUIRE(vireo_acceptor_create(&o, &fd, &a.owner, NULL) == VIREO_OK && fd == -1);
    return a;
}
static void adopt(fixture_t *f, listener_fixture_t *a)
{
    errno = EDOM;
    REQUIRE(vireo_tcp_server_adopt_listener(f->owner, &a->owner, NULL) == VIREO_OK &&
            a->owner == NULL && errno == EDOM);
}
static bool binding_zero(vireo_tcp_server_listener_error_t e)
{
    return e.stage == VIREO_TCP_SERVER_LISTENER_NONE && e.acceptor_error.stage == VIREO_ACCEPTOR_LOOP_STAGE_NONE &&
        e.acceptor_error.loop_error.stage == VIREO_EVENT_LOOP_STAGE_NONE &&
        e.acceptor_error.loop_error.epoll_error.stage == VIREO_EPOLL_STAGE_NONE &&
        e.acceptor_error.loop_error.epoll_error.system_errno == 0 && e.acceptor_error.loop_error.system_errno == 0;
}
/* 不经测试依赖表的公共装配，核对默认监听桥接与整体 forget/销毁。 */
static void public_lifecycle(void)
{
    ++groups;
    vireo_tcp_server_t *server = NULL;
    REQUIRE(vireo_tcp_server_create(&options, &server, NULL) == VIREO_OK);
    listener_fixture_t a = listener_create(AF_INET);
    vireo_tcp_server_info_t before, after;
    REQUIRE(vireo_tcp_server_inspect(server, &before) == VIREO_OK);
    errno = EDOM;
    REQUIRE(vireo_tcp_server_adopt_listener(server, &a.owner, NULL) == VIREO_OK &&
            a.owner == NULL && errno == EDOM);
    REQUIRE(vireo_tcp_server_inspect(server, &after) == VIREO_OK);
    CHECK(after.listener_owned && !after.listener_bound &&
          after.allocation_bytes == before.allocation_bytes + after.listener_allocation_bytes);
    vireo_tcp_server_listener_error_t e;
    REQUIRE(vireo_tcp_server_bind_listener(server, true, &e) == VIREO_OK && binding_zero(e));
    REQUIRE(vireo_tcp_server_set_listener_read_enabled(server, false, &e) == VIREO_OK && binding_zero(e));
    REQUIRE(vireo_tcp_server_set_listener_read_enabled(server, false, NULL) == VIREO_OK);
    REQUIRE(vireo_tcp_server_unbind_listener(server, &e) == VIREO_OK && binding_zero(e));
    REQUIRE(vireo_tcp_server_bind_listener(server, false, NULL) == VIREO_OK);
    vireo_tcp_server_error_t resource;
    memset(&resource, 0xa5, sizeof(resource)); errno = EDOM;
    REQUIRE(vireo_tcp_server_destroy(&server, &resource) == VIREO_OK && server == NULL && errno == EDOM);
    CHECK(resource.stage == VIREO_TCP_SERVER_STAGE_NONE && resource.acceptor_error.system_errno == 0 &&
          resource.cleanup_result == VIREO_OK && resource.cleanup_acceptor_error.system_errno == 0);
    CHECK(fcntl(a.original_fd, F_GETFD) == -1 && errno == EBADF);
}

static void parameters(void)
{
    ++groups; fixture_t f = {0}; create(&f, options);
    vireo_acceptor_t *empty = NULL;
    CHECK(vireo_tcp_server_adopt_listener(NULL, &empty, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_tcp_server_adopt_listener(f.owner, NULL, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_tcp_server_adopt_listener(f.owner, &empty, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    vireo_tcp_server_listener_error_t e;
    for (unsigned k = 0; k < 3; ++k) {
        memset(&e, 0xa5, sizeof(e)); errno = EDOM;
        vireo_result_t r = k == 0 ? vireo_tcp_server_bind_listener(NULL, true, &e) :
            k == 1 ? vireo_tcp_server_set_listener_read_enabled(NULL, true, &e) : vireo_tcp_server_unbind_listener(NULL, &e);
        CHECK(r == VIREO_RESULT_INVALID_ARGUMENT && binding_zero(e) && errno == EDOM);
        memset(&e, 0xa5, sizeof(e)); errno = EDOM;
        r = k == 0 ? vireo_tcp_server_bind_listener(f.owner, true, &e) :
            k == 1 ? vireo_tcp_server_set_listener_read_enabled(f.owner, true, &e) : vireo_tcp_server_unbind_listener(f.owner, &e);
        CHECK(r == VIREO_RESULT_NOT_FOUND && binding_zero(e) && errno == EDOM);
    }
    CHECK(f.adds == 0 && f.mods == 0 && f.dels == 0);
    REQUIRE(vireo_tcp_server_destroy(&f.owner, NULL) == VIREO_OK);
    for (unsigned k = 0; k < 7; ++k) {
        vireo_tcp_server_ops_t b = base_ops(&f);
        vireo_tcp_server_listener_ops_t a = listener_ops(&f);
        switch (k) {
        case 0: a.inspect = NULL; break; case 1: a.attach = NULL; break;
        case 2: a.set_read = NULL; break; case 3: a.detach = NULL; break;
        case 4: a.forget = NULL; break; case 5: a.destroy = NULL; break; default: break;
        }
        CHECK(vireo_tcp_server_create_with_all_ops(&options, &b, k == 6 ? NULL : &a, &f.owner, NULL) ==
              VIREO_RESULT_INVALID_ARGUMENT && f.owner == NULL);
    }
}
static void budget(void)
{
    ++groups; fixture_t f = {0}; create(&f, options);
    size_t const base = info(&f).allocation_bytes;
    REQUIRE(vireo_tcp_server_destroy(&f.owner, NULL) == VIREO_OK);
    listener_fixture_t a = listener_create(AF_INET);
    vireo_acceptor_info_t ai; REQUIRE(vireo_acceptor_inspect(a.owner, &ai) == VIREO_OK);
    for (unsigned k = 0; k < 2; ++k) {
        vireo_tcp_server_options_t o = options;
        o.max_memory_bytes = base + ai.allocation_bytes - (k == 0 ? 1 : 0);
        f = (fixture_t){0}; create(&f, o);
        vireo_acceptor_t *const before = a.owner;
        errno = EDOM;
        vireo_result_t const r = vireo_tcp_server_adopt_listener(f.owner, &a.owner, NULL);
        CHECK(errno == EDOM);
        if (k == 0) CHECK(r == VIREO_RESULT_RANGE && a.owner == before && !info(&f).listener_owned);
        else {
            CHECK(r == VIREO_OK && a.owner == NULL);
            vireo_tcp_server_info_t const i = info(&f);
            CHECK(i.allocation_bytes == o.max_memory_bytes && i.listener_allocation_bytes == ai.allocation_bytes &&
                  ai.max_memory_bytes > o.max_memory_bytes && i.listener_owned && !i.listener_bound);
        }
        REQUIRE(vireo_tcp_server_destroy(&f.owner, NULL) == VIREO_OK);
    }
    CHECK(fcntl(a.original_fd, F_GETFD) == -1 && errno == EBADF);
}
static void ignore(vireo_acceptor_t *a, uint32_t events, void *ctx) { (void)a; (void)events; (void)ctx; }
static void state_rejections(void)
{
    ++groups; fixture_t f = {0}; create(&f, options);
    listener_fixture_t a = listener_create(AF_INET);
    vireo_event_loop_options_t const o = {1, 1048576, 1}; vireo_event_loop_t *loop = NULL;
    REQUIRE(vireo_event_loop_create(&o, &loop, NULL) == VIREO_OK);
    REQUIRE(vireo_acceptor_attach(a.owner, loop, true, ignore, NULL, NULL) == VIREO_OK);
    vireo_acceptor_t *const before = a.owner;
    CHECK(vireo_tcp_server_adopt_listener(f.owner, &a.owner, NULL) == VIREO_RESULT_BUSY && a.owner == before);
    REQUIRE(vireo_acceptor_detach(a.owner, NULL) == VIREO_OK);
    REQUIRE(vireo_event_loop_destroy(&loop, NULL) == VIREO_OK);
    f.active = true;
    CHECK(vireo_tcp_server_adopt_listener(f.owner, &a.owner, NULL) == VIREO_RESULT_BUSY && a.owner == before);
    f.active = false; adopt(&f, &a);
    listener_fixture_t other = listener_create(AF_INET);
    CHECK(vireo_tcp_server_adopt_listener(f.owner, &other.owner, NULL) == VIREO_RESULT_BUSY && other.owner != NULL);
    REQUIRE(vireo_acceptor_destroy(&other.owner, NULL) == VIREO_OK);
    CHECK(vireo_tcp_server_set_listener_read_enabled(f.owner, true, NULL) == VIREO_RESULT_NOT_FOUND);
    CHECK(vireo_tcp_server_unbind_listener(f.owner, NULL) == VIREO_OK && f.dels == 0);
    REQUIRE(vireo_tcp_server_bind_listener(f.owner, false, NULL) == VIREO_OK);
    CHECK(vireo_tcp_server_bind_listener(f.owner, true, NULL) == VIREO_RESULT_BUSY && f.adds == 1);
    REQUIRE(vireo_tcp_server_destroy(&f.owner, NULL) == VIREO_OK);
    CHECK(strcmp(f.order, "plgaF") == 0 && f.dels == 0);
}
static void snapshots(void)
{
    ++groups; fixture_t f = {0}; create(&f, options);
    listener_fixture_t a = listener_create(AF_INET);
    for (unsigned k = 1; k <= 5; ++k) {
        f.corrupt = k; vireo_tcp_server_error_t e; errno = EDOM;
        CHECK(vireo_tcp_server_adopt_listener(f.owner, &a.owner, &e) == VIREO_RESULT_INTERNAL &&
              a.owner != NULL && e.stage == VIREO_TCP_SERVER_STAGE_INSPECT_LISTENER && errno == EDOM);
    }
    f.corrupt = 0; f.inspect_fail = true;
    CHECK(vireo_tcp_server_adopt_listener(f.owner, &a.owner, NULL) == VIREO_RESULT_INTERNAL && a.owner != NULL);
    f.inspect_fail = false; adopt(&f, &a);
    for (unsigned k = 1; k <= 9; ++k) {
        f.corrupt = k == 9 ? 0 : k; f.inspect_fail = k == 9;
        vireo_tcp_server_info_t out, saved; memset(&out, 0xa5, sizeof(out)); memcpy(&saved, &out, sizeof(out));
        errno = EDOM;
        CHECK(vireo_tcp_server_inspect(f.owner, &out) == VIREO_RESULT_INTERNAL &&
              memcmp(&out, &saved, sizeof(out)) == 0 && errno == EDOM);
    }
    f.corrupt = 0; f.inspect_fail = false;
    REQUIRE(vireo_tcp_server_destroy(&f.owner, NULL) == VIREO_OK);
}
static void binding_failures(void)
{
    ++groups; fixture_t f = {0}; create(&f, options);
    listener_fixture_t a = listener_create(AF_INET); adopt(&f, &a);
    vireo_tcp_server_listener_error_t e;
    f.add_fail = true; errno = EDOM;
    CHECK(vireo_tcp_server_bind_listener(f.owner, true, &e) == VIREO_RESULT_IO && errno == EDOM);
    CHECK(e.stage == VIREO_TCP_SERVER_LISTENER_BIND && e.acceptor_error.stage == VIREO_ACCEPTOR_LOOP_STAGE_ATTACH &&
          e.acceptor_error.loop_error.stage == VIREO_EVENT_LOOP_STAGE_ADD &&
          e.acceptor_error.loop_error.epoll_error.stage == VIREO_EPOLL_STAGE_ADD &&
          e.acceptor_error.loop_error.epoll_error.system_errno == EBADF && e.acceptor_error.loop_error.system_errno == EIO);
    CHECK(info(&f).listener_owned && !info(&f).listener_bound && f.adds == 1);
    f.add_fail = false; REQUIRE(vireo_tcp_server_bind_listener(f.owner, true, &e) == VIREO_OK && binding_zero(e));
    f.callback(f.listener, VIREO_EPOLL_EVENT_ERROR | VIREO_EPOLL_EVENT_HANGUP, f.callback_context); /* 模拟观察，不冒充内核通知。 */
    f.mod_fail = true; errno = EDOM;
    CHECK(vireo_tcp_server_set_listener_read_enabled(f.owner, false, &e) == VIREO_RESULT_IO && errno == EDOM);
    CHECK(e.stage == VIREO_TCP_SERVER_LISTENER_UPDATE && e.acceptor_error.stage == VIREO_ACCEPTOR_LOOP_STAGE_UPDATE &&
          e.acceptor_error.loop_error.stage == VIREO_EVENT_LOOP_STAGE_MOD &&
          e.acceptor_error.loop_error.epoll_error.stage == VIREO_EPOLL_STAGE_MOD &&
          e.acceptor_error.loop_error.epoll_error.system_errno == EBADF && e.acceptor_error.loop_error.system_errno == EIO);
    CHECK(info(&f).listener_read_enabled && info(&f).listener_last_events == (VIREO_EPOLL_EVENT_ERROR | VIREO_EPOLL_EVENT_HANGUP));
    f.mod_fail = false;
    REQUIRE(vireo_tcp_server_set_listener_read_enabled(f.owner, true, &e) == VIREO_OK && binding_zero(e));
    CHECK(f.mods == 2); /* 同值仍一次 MOD。 */
    f.del_fail = true; errno = EDOM;
    CHECK(vireo_tcp_server_unbind_listener(f.owner, &e) == VIREO_RESULT_IO && errno == EDOM);
    CHECK(e.stage == VIREO_TCP_SERVER_LISTENER_UNBIND && e.acceptor_error.stage == VIREO_ACCEPTOR_LOOP_STAGE_DETACH &&
          e.acceptor_error.loop_error.stage == VIREO_EVENT_LOOP_STAGE_DEL &&
          e.acceptor_error.loop_error.epoll_error.stage == VIREO_EPOLL_STAGE_DEL &&
          e.acceptor_error.loop_error.epoll_error.system_errno == EBADF && e.acceptor_error.loop_error.system_errno == EIO);
    CHECK(info(&f).listener_bound && f.dels == 1);
    /* DEL 失败后不逐个重试，整体消费 loop 即可合法 forget/close。 */
    REQUIRE(vireo_tcp_server_destroy(&f.owner, NULL) == VIREO_OK);
    CHECK(f.dels == 1 && strcmp(f.order, "plgaF") == 0 && f.forgets == 1 && f.listener_destroys == 1);
}
static void native_notifications(int family)
{
    ++groups; fixture_t f = {0}; create(&f, options);
    listener_fixture_t a = listener_create(family); adopt(&f, &a);
    REQUIRE(vireo_tcp_server_bind_listener(f.owner, true, NULL) == VIREO_OK);
    int const client = socket(family, SOCK_STREAM | SOCK_CLOEXEC, 0); REQUIRE(client >= 0);
    REQUIRE(connect(client, (struct sockaddr *)&a.address, a.length) == 0);
    vireo_event_loop_run_info_t progress;
    errno = EDOM;
    REQUIRE(vireo_event_loop_run_once(f.loop, 1000, &progress, NULL) == VIREO_OK && errno == EDOM);
    CHECK(progress.dispatched_count == 1 && info(&f).listener_last_events == VIREO_EPOLL_EVENT_READ &&
          info(&f).connection_count == 0 && info(&f).buffer_capacity_bytes == 0);
    REQUIRE(vireo_tcp_server_set_listener_read_enabled(f.owner, false, NULL) == VIREO_OK);
    REQUIRE(vireo_event_loop_run_once(f.loop, 0, &progress, NULL) == VIREO_OK);
    CHECK(progress.ready_count == 0 && !info(&f).listener_read_enabled);
    REQUIRE(vireo_tcp_server_set_listener_read_enabled(f.owner, true, NULL) == VIREO_OK);
    REQUIRE(vireo_event_loop_run_once(f.loop, 1000, &progress, NULL) == VIREO_OK);
    CHECK(progress.dispatched_count == 1); /* 同一未接入队列再次 READ，未自动 accept。 */
    REQUIRE(vireo_tcp_server_unbind_listener(f.owner, NULL) == VIREO_OK);
    CHECK(!info(&f).listener_bound && !info(&f).listener_read_enabled && info(&f).listener_last_events == 0);
    REQUIRE(vireo_tcp_server_unbind_listener(f.owner, NULL) == VIREO_OK && f.dels == 1);
    REQUIRE(vireo_tcp_server_bind_listener(f.owner, false, NULL) == VIREO_OK);
    CHECK(info(&f).listener_last_events == 0 && info(&f).listener_bound && !info(&f).listener_read_enabled);
    REQUIRE(close(client) == 0);
    REQUIRE(vireo_tcp_server_destroy(&f.owner, NULL) == VIREO_OK);
    CHECK(fcntl(a.original_fd, F_GETFD) == -1 && errno == EBADF);
}
static void cleanup_refusal(void)
{
    ++groups; fixture_t f = {0}; create(&f, options);
    listener_fixture_t a = listener_create(AF_INET); adopt(&f, &a);
    REQUIRE(vireo_tcp_server_bind_listener(f.owner, true, NULL) == VIREO_OK);
    vireo_tcp_server_t *const before = f.owner; vireo_tcp_server_error_t e;
    f.active = true; errno = EDOM;
    CHECK(vireo_tcp_server_destroy(&f.owner, &e) == VIREO_RESULT_BUSY && errno == EDOM &&
          f.owner == before && f.order_size == 0 && e.stage == VIREO_TCP_SERVER_STAGE_NONE);
    f.active = false; f.inspect_fail = true;
    CHECK(vireo_tcp_server_destroy(&f.owner, &e) == VIREO_RESULT_INTERNAL && f.owner == before && f.order_size == 0 &&
          e.stage == VIREO_TCP_SERVER_STAGE_INSPECT_LISTENER);
    f.inspect_fail = false; f.pool_busy = true; errno = EDOM;
    CHECK(vireo_tcp_server_destroy(&f.owner, &e) == VIREO_RESULT_BUSY && errno == EDOM && f.owner == before &&
          e.stage == VIREO_TCP_SERVER_STAGE_DESTROY_POOL && f.loop_destroys == 0 && f.forgets == 0);
    CHECK(info(&f).listener_bound && fcntl(a.original_fd, F_GETFD) >= 0);
    f.pool_busy = false; f.order_size = 0; f.order[0] = '\0';
    REQUIRE(vireo_tcp_server_destroy(&f.owner, NULL) == VIREO_OK);
    CHECK(strcmp(f.order, "plgaF") == 0);
}
static void cleanup_errors(void)
{
    ++groups;
    for (unsigned k = 0; k < 4; ++k) {
        fixture_t f = {0}; create(&f, options); listener_fixture_t a = listener_create(AF_INET); adopt(&f, &a);
        REQUIRE(vireo_tcp_server_bind_listener(f.owner, true, NULL) == VIREO_OK);
        f.loop_io = k != 1; f.listener_io = k != 0;
        vireo_tcp_server_error_t e; memset(&e, 0xa5, sizeof(e)); errno = EDOM;
        CHECK(vireo_tcp_server_destroy(&f.owner, k == 3 ? NULL : &e) == VIREO_RESULT_IO &&
              errno == EDOM && f.owner == NULL && strcmp(f.order, "plgaF") == 0);
        CHECK(f.loop_destroys == 1 && f.listener_destroys == 1 && f.forgets == 1 && f.dels == 0);
        if (k == 0 || k == 2) {
            CHECK(e.stage == VIREO_TCP_SERVER_STAGE_DESTROY_LOOP &&
                  e.loop_error.stage == VIREO_EVENT_LOOP_STAGE_DESTROY_EPOLL &&
                  e.loop_error.epoll_error.stage == VIREO_EPOLL_STAGE_CLOSE &&
                  e.loop_error.epoll_error.system_errno == EINTR && e.loop_error.system_errno == EIO);
            CHECK(e.cleanup_result == (k == 2 ? VIREO_RESULT_IO : VIREO_OK));
            if (k == 2) CHECK(e.cleanup_stage == VIREO_TCP_SERVER_STAGE_DESTROY_LISTENER &&
                             e.cleanup_acceptor_error.stage == VIREO_ACCEPTOR_STAGE_CLOSE_LISTENER &&
                             e.cleanup_acceptor_error.system_errno == ENOSPC);
        }
        if (k == 1) CHECK(e.stage == VIREO_TCP_SERVER_STAGE_DESTROY_LISTENER &&
                          e.acceptor_error.stage == VIREO_ACCEPTOR_STAGE_CLOSE_LISTENER &&
                          e.acceptor_error.system_errno == ENOSPC && e.cleanup_result == VIREO_OK);
        CHECK(fcntl(a.original_fd, F_GETFD) == -1 && errno == EBADF);
        CHECK(vireo_tcp_server_destroy(&f.owner, NULL) == VIREO_OK && f.listener_destroys == 1);
    }
}
int main(void)
{
    unsigned const before = fd_count();
    public_lifecycle(); parameters(); budget(); state_rejections(); snapshots(); binding_failures();
    native_notifications(AF_INET); native_notifications(AF_UNIX); cleanup_refusal(); cleanup_errors();
    unsigned const after = fd_count(); CHECK(before == after);
    printf("tcp_server listener: %u groups, %u failures; fd %u -> %u\n", groups, failures, before, after);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
