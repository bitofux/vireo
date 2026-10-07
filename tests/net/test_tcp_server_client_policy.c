/*
- PROJECT : VIREO
- FILE    : test_tcp_server_client_policy.c
- AUTHOR  : bitofux
- DATE    : 2026-10-05
- BRIEF   : 此模块负责：
- -- 当前租约策略、水位迟滞与永久关闭协作
- -- 真实 TCP 占用、受控描述符故障及 handler 在途保护
 */
#define _GNU_SOURCE
#include "net/tcp_server_internal.h"
#include <fcntl.h>
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
    bool release_busy;
    int raw_fds[2];
    vireo_connection_t *objects[2];
    unsigned created, policy_calls[6];
    int fault_operation;
    bool detach_io;
} fixture_t;
static vireo_result_t accept_client(void *ctx, vireo_acceptor_t *a,
    vireo_acceptor_accept_budget_t const *b, int *fds, size_t n,
    vireo_acceptor_accept_info_t *i, vireo_acceptor_error_t *e)
{ (void)ctx; return vireo_acceptor_accept_batch(a, b, fds, n, i, e); }
static vireo_result_t create_client(void *ctx, vireo_connection_options_t const *o, int *fd,
    vireo_connection_t **c, vireo_connection_error_t *e)
{
    fixture_t *f = ctx;
    int const raw = *fd;
    vireo_result_t const r = vireo_connection_create(o, fd, c, e);
    if (r == VIREO_OK) {
        size_t const k = f->created++ % 2;
        f->raw_fds[k] = raw; f->objects[k] = *c;
    }
    return r;
}
static vireo_result_t inspect_client(void *ctx, vireo_connection_t const *c, vireo_connection_info_t *i)
{ (void)ctx; return vireo_connection_inspect(c, i); }
static vireo_result_t adopt_client(void *ctx, vireo_connection_pool_t *p, vireo_connection_t **c,
    vireo_connection_pool_lease_t *l, vireo_connection_pool_operation_error_t *e)
{ (void)ctx; return vireo_connection_pool_adopt(p, c, l, e); }
static vireo_result_t lookup_client(void *ctx, vireo_connection_pool_t const *p,
    vireo_connection_pool_lease_t l, vireo_connection_t **c)
{ (void)ctx; errno = E2BIG; return vireo_connection_pool_lookup(p, l, c); }
static vireo_result_t attach_client(void *ctx, vireo_connection_t *c, vireo_event_loop_t *p,
    uint32_t mask, vireo_connection_callback_t cb, void *cbctx, vireo_connection_loop_error_t *e)
{ (void)ctx; return vireo_connection_attach(c, p, mask, cb, cbctx, e); }
static vireo_result_t detach_client(void *ctx, vireo_connection_t *c, vireo_connection_loop_error_t *e)
{
    fixture_t *f = ctx;
    if (f->detach_io) {
        *e = (vireo_connection_loop_error_t){.stage = VIREO_CONNECTION_LOOP_STAGE_DETACH,
            .loop_error = {.stage = VIREO_EVENT_LOOP_STAGE_DEL,
                .epoll_error = {VIREO_EPOLL_STAGE_DEL, EINTR}}};
        return VIREO_RESULT_IO;
    }
    return vireo_connection_detach(c, e);
}
static vireo_result_t release_client(void *ctx, vireo_connection_pool_t *p,
    vireo_connection_pool_lease_t *l, vireo_connection_pool_operation_error_t *e)
{ fixture_t *f = ctx; return f->release_busy ? VIREO_RESULT_BUSY : vireo_connection_pool_release(p, l, e); }
static vireo_result_t destroy_client(void *ctx, vireo_connection_t **c, vireo_connection_error_t *e)
{ (void)ctx; return vireo_connection_destroy(c, e); }
static int close_fd(void *ctx, int fd) { (void)ctx; return close(fd); }
static vireo_result_t receive_bytes(void *ctx, vireo_connection_t *c,
    vireo_connection_receive_budget_t const *b, vireo_connection_receive_info_t *i,
    vireo_connection_error_t *e)
{ (void)ctx; return vireo_connection_receive(c, b, i, e); }
static vireo_result_t peek_bytes(void *ctx, vireo_connection_t const *c, uint8_t const **p, size_t *n)
{ (void)ctx; return vireo_connection_read_peek(c, p, n); }
static vireo_result_t consume_bytes(void *ctx, vireo_connection_t *c, size_t n)
{ (void)ctx; return vireo_connection_read_consume(c, n); }
static vireo_result_t enqueue_bytes(void *ctx, vireo_connection_t *c, uint8_t const *p,
    size_t n, vireo_connection_error_t *e)
{ (void)ctx; return vireo_connection_write_enqueue(c, p, n, e); }
static vireo_result_t send_bytes(void *ctx, vireo_connection_t *c,
    vireo_connection_send_budget_t const *b, vireo_connection_send_info_t *i,
    vireo_connection_error_t *e)
{ (void)ctx; return vireo_connection_send(c, b, i, e); }
static vireo_result_t frame_views(void *ctx, vireo_connection_t const *c,
    vireo_connection_frame_options_t const *o, vireo_connection_frame_budget_t const *b,
    vireo_connection_frame_view_t *v, size_t n, vireo_connection_frame_info_t *i,
    vireo_connection_frame_error_t *e)
{ (void)ctx; return vireo_connection_frames_peek(c, o, b, v, n, i, e); }
/* 故障夹具临时违背隐藏 fd 的外部禁用规则，不能作为合法应用做法：
 * 保留同一 open-file-description，移去原 fd 使真实 MOD 得到 EBADF，
 * 立即 dup3 恢复同一 fd/key 后关闭临时副本。借用不逃逸到生产接口。
 * 不读 connection/loop 私有布局，不修改封板 seam 或生产系统状态。 */
static int fault_begin(fixture_t *f, vireo_connection_t *c, int operation)
{
    ++f->policy_calls[operation - 1];
    if (f->fault_operation != operation) return -1;
    for (size_t k = 0; k < 2; ++k) if (f->objects[k] == c) {
        int const backup = fcntl(f->raw_fds[k], F_DUPFD_CLOEXEC, 0);
        REQUIRE(backup >= 0 && close(f->raw_fds[k]) == 0);
        return backup;
    }
    REQUIRE(false); return -1;
}
static void fault_end(fixture_t *f, vireo_connection_t *c, int backup)
{
    if (backup >= 0) {
        bool found = false;
        for (size_t k = 0; k < 2; ++k) if (f->objects[k] == c) {
            REQUIRE(dup3(backup, f->raw_fds[k], O_CLOEXEC) == f->raw_fds[k]);
            found = true; break;
        }
        REQUIRE(found && close(backup) == 0);
    }
    errno = ERANGE; /* 最外层必须恢复 caller 的入口值，不能泄漏 wrapper 的 errno。 */
}
/** 只桥接公开 set_interests；不持有第二 owner、不扩展依赖策略。 */
static vireo_result_t policy_set_interests(void *ctx, vireo_connection_t *c,
    uint32_t interests, vireo_connection_loop_error_t *error)
{
    fixture_t *f = ctx;
    int const backup = fault_begin(f, c, 1);
    vireo_result_t const result = vireo_connection_set_interests(c, interests, error);
    fault_end(f, c, backup);
    return result;
}
/** 只桥接公开 flow_configure；不持有第二 owner、不扩展依赖策略。 */
static vireo_result_t policy_flow_configure(void *ctx, vireo_connection_t *c,
    vireo_connection_flow_options_t const *options, vireo_connection_loop_error_t *error)
{
    fixture_t *f = ctx;
    int const backup = fault_begin(f, c, 2);
    vireo_result_t const result = vireo_connection_flow_configure(c, options, error);
    fault_end(f, c, backup);
    return result;
}
/** 只桥接公开 flow_refresh；不持有第二 owner、不扩展依赖策略。 */
static vireo_result_t policy_flow_refresh(void *ctx, vireo_connection_t *c,
    vireo_connection_loop_error_t *error)
{
    fixture_t *f = ctx;
    int const backup = fault_begin(f, c, 3);
    vireo_result_t const result = vireo_connection_flow_refresh(c, error);
    fault_end(f, c, backup);
    return result;
}
/** 只桥接公开 flow_disable；不持有第二 owner、不扩展依赖策略。 */
static vireo_result_t policy_flow_disable(void *ctx, vireo_connection_t *c,
    vireo_connection_loop_error_t *error)
{
    fixture_t *f = ctx;
    int const backup = fault_begin(f, c, 4);
    vireo_result_t const result = vireo_connection_flow_disable(c, error);
    fault_end(f, c, backup);
    return result;
}
/** 只桥接公开 request_close；不持有第二 owner、不扩展依赖策略。 */
static vireo_result_t policy_request_close(void *ctx, vireo_connection_t *c,
    vireo_connection_close_mode_t mode,
    vireo_connection_close_reason_t reason, vireo_connection_loop_error_t *error)
{
    fixture_t *f = ctx;
    int const backup = fault_begin(f, c, 5);
    vireo_result_t const result = vireo_connection_request_close(c, mode, reason, error);
    fault_end(f, c, backup);
    return result;
}
/** 只桥接公开 close_refresh；不持有第二 owner、不扩展依赖策略。 */
static vireo_result_t policy_close_refresh(void *ctx, vireo_connection_t *c,
    vireo_connection_loop_error_t *error)
{
    fixture_t *f = ctx;
    int const backup = fault_begin(f, c, 6);
    vireo_result_t const result = vireo_connection_close_refresh(c, error);
    fault_end(f, c, backup);
    return result;
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
static uint32_t const reading = VIREO_EPOLL_INTEREST_READ | VIREO_EPOLL_INTEREST_PEER_WRITE_CLOSED;
static vireo_connection_flow_options_t const flow = {96, 95, 192, 32, 96};
static void configured(fixture_t *f)
{
    errno = EDOM;
    REQUIRE(vireo_tcp_server_client_flow_configure(f->server, f->clients[0], &flow, NULL) == VIREO_OK);
    CHECK(errno == EDOM);
}
static void feed(fixture_t *f, size_t k, uint8_t const *bytes, size_t size)
{
    size_t offset = 0;
    while (offset < size) {
        ssize_t const n = send(f->peers[k], bytes + offset, size - offset, MSG_NOSIGNAL);
        REQUIRE(n > 0); offset += (size_t)n;
    }
    vireo_connection_receive_info_t i;
    REQUIRE(vireo_tcp_server_client_receive(f->server, f->clients[k], &read_budget, &i, NULL) == VIREO_OK);
    REQUIRE(i.received_bytes == size);
}
static void queue(fixture_t *f, size_t size)
{
    uint8_t bytes[128]; memset(bytes, 91, sizeof(bytes)); REQUIRE(size <= sizeof(bytes));
    REQUIRE(vireo_tcp_server_client_write_enqueue(f->server, f->clients[0], bytes, size, NULL) == VIREO_OK);
}
static void sent(fixture_t *f, size_t size)
{
    vireo_connection_send_budget_t const b = {size, 4}; vireo_connection_send_info_t i;
    REQUIRE(vireo_tcp_server_client_send(f->server, f->clients[0], &b, &i, NULL) == VIREO_OK);
    REQUIRE(i.sent_bytes == size);
    uint8_t bytes[128]; size_t offset = 0;
    while (offset < size) {
        ssize_t const n = recv(f->peers[0], bytes, size - offset, 0);
        REQUIRE(n > 0);
        for (ssize_t k = 0; k < n; ++k) CHECK(bytes[k] == 91);
        offset += (size_t)n;
    }
}
static vireo_result_t operation(fixture_t *f, vireo_connection_pool_lease_t l, unsigned k,
    vireo_tcp_server_client_error_t *e)
{
    switch (k) {
    case 0:return vireo_tcp_server_client_set_interests(f->server, l, reading, e);
    case 1:return vireo_tcp_server_client_flow_configure(f->server, l, &flow, e);
    case 2:return vireo_tcp_server_client_flow_refresh(f->server, l, e);
    case 3:return vireo_tcp_server_client_flow_disable(f->server, l, e);
    case 4:return vireo_tcp_server_client_request_close(f->server, l,
        VIREO_CONNECTION_CLOSE_MODE_DRAIN, VIREO_CONNECTION_CLOSE_REASON_APPLICATION, e);
    default:return vireo_tcp_server_client_close_refresh(f->server, l, e);
    }
}
static void clean_error(vireo_tcp_server_client_error_t const *e)
{
    CHECK(e->primary.stage == VIREO_TCP_SERVER_CLIENT_NONE);
    CHECK(e->primary.loop_error.stage == VIREO_CONNECTION_LOOP_STAGE_NONE);
    CHECK(e->primary.loop_error.loop_error.stage == VIREO_EVENT_LOOP_STAGE_NONE);
    CHECK(e->primary.loop_error.loop_error.epoll_error.system_errno == 0);
    CHECK(e->primary.system_errno == 0 && e->primary.connection_error.system_errno == 0);
    CHECK(e->cleanup_result == VIREO_OK && e->cleanup.stage == VIREO_TCP_SERVER_CLIENT_NONE);
}
static void mod_error(vireo_tcp_server_client_error_t const *e,
    vireo_tcp_server_client_stage_t stage, vireo_connection_loop_stage_t nested)
{
    CHECK(e->primary.stage == stage && e->primary.loop_error.stage == nested);
    CHECK(e->primary.loop_error.loop_error.stage == VIREO_EVENT_LOOP_STAGE_MOD);
    CHECK(e->primary.loop_error.loop_error.epoll_error.stage == VIREO_EPOLL_STAGE_MOD);
    CHECK(e->primary.loop_error.loop_error.epoll_error.system_errno == EBADF);
    CHECK(e->primary.loop_error.loop_error.system_errno == 0);
    CHECK(e->primary.system_errno == 0 && e->primary.connection_error.system_errno == 0);
    CHECK(e->cleanup_result == VIREO_OK && e->cleanup.stage == VIREO_TCP_SERVER_CLIENT_NONE);
}
static void parameters_and_identity(void)
{
    ++groups; fixture_t f = {0}; start(&f, AF_INET, true, connection_options, 2);
    vireo_tcp_server_client_error_t e;
    for (unsigned k = 0; k < 6; ++k) {
        fixture_t null = {0}; memset(&e, 0xA5, sizeof(e)); errno = EDOM;
        CHECK(operation(&null, f.clients[0], k, &e) == VIREO_RESULT_INVALID_ARGUMENT && errno == EDOM);
        clean_error(&e);
        vireo_connection_pool_lease_t bad = f.clients[0]; ++bad.pool_id;
        CHECK(operation(&f, bad, k, &e) == VIREO_RESULT_INVALID_ARGUMENT);
        CHECK(e.primary.stage == VIREO_TCP_SERVER_CLIENT_LOOKUP);
        bad = f.clients[0]; bad.slot_index = 2;
        CHECK(operation(&f, bad, k, &e) == VIREO_RESULT_RANGE);
        bad = (vireo_connection_pool_lease_t){0};
        CHECK(operation(&f, bad, k, &e) == VIREO_RESULT_NOT_FOUND);
        bad = f.clients[0]; ++bad.generation;
        CHECK(operation(&f, bad, k, &e) == VIREO_RESULT_NOT_FOUND);
        CHECK(f.policy_calls[k] == 0);
    }
    CHECK(vireo_tcp_server_client_flow_configure(f.server, f.clients[0], NULL, &e) == VIREO_RESULT_INVALID_ARGUMENT);
    clean_error(&e);
    CHECK(vireo_tcp_server_client_set_interests(f.server, f.clients[0], UINT32_MAX, &e) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(e.primary.stage == VIREO_TCP_SERVER_CLIENT_SET_INTERESTS);
    CHECK(vireo_tcp_server_client_flow_refresh(f.server, f.clients[0], &e) == VIREO_RESULT_NOT_FOUND);
    CHECK(vireo_tcp_server_client_close_refresh(f.server, f.clients[0], &e) == VIREO_RESULT_NOT_FOUND);
    CHECK(vireo_tcp_server_client_set_interests(f.server, f.clients[0], 0, NULL) == VIREO_OK);
    CHECK(info(&f, 0).connection_info.loop_interests == 0);
    CHECK(info(&f, 1).connection_info.loop_interests == reading);
    end(&f, 2);
}
static void thresholds(void)
{
    ++groups; fixture_t f = {0}; start(&f, AF_INET, true, connection_options, 1);
    configured(&f);
    for (unsigned k = 0; k < 11; ++k) {
        vireo_connection_flow_options_t o = flow;
        switch (k) {
        case 0:o.max_frame_bytes=31;break;case 1:o.max_frame_bytes=257;break;
        case 2:o.max_frame_bytes=SIZE_MAX;break;case 3:o.read_low=94;break;
        case 4:o.read_low=o.read_high;break;case 5:o.read_high=257;break;
        case 6:o.read_high=0;break;case 7:o.write_low=o.write_high;break;
        case 8:o.write_high=129;break;case 9:o.write_low=SIZE_MAX;break;
        default:o.write_high=0;break;
        }
        errno = EDOM;
        CHECK(vireo_tcp_server_client_flow_configure(f.server, f.clients[0], &o, NULL) == VIREO_RESULT_RANGE && errno == EDOM);
        vireo_connection_info_t i = info(&f, 0).connection_info;
        CHECK(i.flow_enabled && i.flow_options.max_frame_bytes == 96 && i.flow_options.read_low == 95 && i.loop_interests == reading);
    }
    vireo_connection_flow_options_t o = {256,255,256,0,128};
    CHECK(vireo_tcp_server_client_flow_configure(f.server, f.clients[0], &o, NULL) == VIREO_OK);
    o = (vireo_connection_flow_options_t){32,31,32,0,1};
    CHECK(vireo_tcp_server_client_flow_configure(f.server, f.clients[0], &o, NULL) == VIREO_OK);
    end(&f, 1);
    f = (fixture_t){0}; start(&f, AF_INET, false, (vireo_connection_options_t){31,8,39}, 1);
    CHECK(vireo_tcp_server_client_flow_configure(f.server, f.clients[0], &o, NULL) == VIREO_RESULT_RANGE);
    end(&f, 1);
}
static void read_hysteresis(void)
{
    ++groups; fixture_t f = {0}; start(&f, AF_INET, true, connection_options, 2);
    uint8_t bytes[224]; memset(bytes, 7, sizeof(bytes)); configured(&f);
    feed(&f, 0, bytes, sizeof(bytes));
    CHECK(!info(&f, 0).connection_info.read_pressure); /* I/O 没有隐式刷新。 */
    uint8_t const *borrow = NULL; size_t size = 0;
    REQUIRE(vireo_tcp_server_client_read_peek(f.server, f.clients[0], &borrow, &size, NULL) == VIREO_OK && size == 224);
    CHECK(vireo_tcp_server_client_flow_refresh(f.server, f.clients[0], NULL) == VIREO_OK);
    CHECK(info(&f, 0).connection_info.read_pressure && info(&f, 0).connection_info.loop_interests == 0);
    CHECK(borrow[0] == 7 && borrow[223] == 7); /* policy 不结束借用。 */
    CHECK(info(&f, 1).connection_info.loop_interests == reading && !info(&f, 1).connection_info.flow_enabled);
    REQUIRE(vireo_tcp_server_client_read_consume(f.server, f.clients[0], 64, NULL) == VIREO_OK);
    CHECK(vireo_tcp_server_client_flow_refresh(f.server, f.clients[0], NULL) == VIREO_OK);
    CHECK(info(&f, 0).connection_info.read_pressure && info(&f, 0).connection_info.read_buffer.readable_size == 160);
    /* 相同配置重置锁存，160<high 从未锁状态计算。 */
    configured(&f); CHECK(!info(&f, 0).connection_info.read_pressure);
    feed(&f, 0, bytes, 32);
    CHECK(vireo_tcp_server_client_flow_refresh(f.server, f.clients[0], NULL) == VIREO_OK);
    CHECK(info(&f, 0).connection_info.read_pressure); /* 恰 high。 */
    REQUIRE(vireo_tcp_server_client_read_consume(f.server, f.clients[0], 97, NULL) == VIREO_OK);
    CHECK(vireo_tcp_server_client_flow_refresh(f.server, f.clients[0], NULL) == VIREO_OK);
    CHECK(!info(&f, 0).connection_info.read_pressure && info(&f, 0).connection_info.loop_interests == reading); /* 恰 low。 */
    end(&f, 2);
}
static void write_hysteresis(void)
{
    ++groups; fixture_t f = {0}; start(&f, AF_INET, true, connection_options, 1); configured(&f);
    queue(&f, 100); CHECK(info(&f, 0).connection_info.loop_interests == reading);
    REQUIRE(vireo_tcp_server_client_flow_refresh(f.server, f.clients[0], NULL) == VIREO_OK);
    CHECK(info(&f, 0).connection_info.write_pressure && info(&f, 0).connection_info.loop_interests == VIREO_EPOLL_INTEREST_WRITE);
    uint8_t bytes[224]; memset(bytes, 8, sizeof(bytes));
    feed(&f, 0, bytes, sizeof(bytes)); /* READ 暂停仍允许显式 receive。 */
    f.fault_operation = 3;
    REQUIRE(vireo_tcp_server_client_flow_refresh(f.server, f.clients[0], NULL) == VIREO_OK);
    CHECK(info(&f, 0).connection_info.read_pressure); /* 同 WRITE mask 不 MOD，仍提交压力。 */
    REQUIRE(vireo_tcp_server_client_read_consume(f.server, f.clients[0], 224, NULL) == VIREO_OK);
    REQUIRE(vireo_tcp_server_client_flow_refresh(f.server, f.clients[0], NULL) == VIREO_OK);
    CHECK(!info(&f, 0).connection_info.read_pressure);
    f.fault_operation = 0;
    sent(&f, 40); REQUIRE(vireo_tcp_server_client_flow_refresh(f.server, f.clients[0], NULL) == VIREO_OK);
    CHECK(info(&f, 0).connection_info.write_pressure && info(&f, 0).connection_info.write_buffer.readable_size == 60);
    sent(&f, 28); REQUIRE(vireo_tcp_server_client_flow_refresh(f.server, f.clients[0], NULL) == VIREO_OK);
    CHECK(!info(&f, 0).connection_info.write_pressure && info(&f, 0).connection_info.loop_interests == (reading | VIREO_EPOLL_INTEREST_WRITE));
    sent(&f, 32); CHECK(info(&f, 0).connection_info.loop_interests == (reading | VIREO_EPOLL_INTEREST_WRITE));
    REQUIRE(vireo_tcp_server_client_flow_refresh(f.server, f.clients[0], NULL) == VIREO_OK);
    CHECK(info(&f, 0).connection_info.loop_interests == reading); end(&f, 1);
}
static void disable_and_no_mod(void)
{
    ++groups; fixture_t f = {0}; start(&f, AF_INET, true, connection_options, 1);
    vireo_tcp_server_client_error_t e;
    /* 真正需要相同 mask MOD 的 manual 会得到 EBADF；flow 相同 mask 无 syscall 而成功。 */
    f.fault_operation = 1; errno = EDOM;
    CHECK(vireo_tcp_server_client_set_interests(f.server, f.clients[0], reading, &e) == VIREO_RESULT_IO && errno == EDOM);
    mod_error(&e, VIREO_TCP_SERVER_CLIENT_SET_INTERESTS, VIREO_CONNECTION_LOOP_STAGE_UPDATE);
    CHECK(info(&f, 0).connection_info.loop_interests == reading);
    f.fault_operation = 2; configured(&f); CHECK(info(&f, 0).connection_info.flow_enabled);
    f.fault_operation = 3;
    CHECK(vireo_tcp_server_client_flow_refresh(f.server, f.clients[0], &e) == VIREO_OK); clean_error(&e);
    CHECK(vireo_tcp_server_client_set_interests(f.server, f.clients[0], 0, NULL) == VIREO_RESULT_BUSY);
    f.fault_operation = 0; queue(&f, 100);
    REQUIRE(vireo_tcp_server_client_flow_refresh(f.server, f.clients[0], NULL) == VIREO_OK);
    f.fault_operation = 4;
    CHECK(vireo_tcp_server_client_flow_disable(f.server, f.clients[0], &e) == VIREO_OK); clean_error(&e);
    vireo_connection_info_t i = info(&f, 0).connection_info;
    CHECK(!i.flow_enabled && !i.write_pressure && i.flow_options.max_frame_bytes == 0 && i.loop_interests == VIREO_EPOLL_INTEREST_WRITE);
    CHECK(vireo_tcp_server_client_flow_disable(f.server, f.clients[0], NULL) == VIREO_OK);
    f.fault_operation = 0;
    CHECK(vireo_tcp_server_client_set_interests(f.server, f.clients[0], reading, NULL) == VIREO_OK); end(&f, 1);
}
static void flow_failures(void)
{
    ++groups; fixture_t f = {0}; start(&f, AF_INET, true, connection_options, 1); queue(&f, 100);
    vireo_tcp_server_client_error_t e; f.fault_operation = 2; errno = EDOM;
    CHECK(vireo_tcp_server_client_flow_configure(f.server, f.clients[0], &flow, &e) == VIREO_RESULT_IO && errno == EDOM);
    mod_error(&e, VIREO_TCP_SERVER_CLIENT_FLOW_CONFIGURE, VIREO_CONNECTION_LOOP_STAGE_FLOW_CONFIGURE);
    CHECK(!info(&f, 0).connection_info.flow_enabled && info(&f, 0).connection_info.loop_interests == reading);
    f.fault_operation = 0; configured(&f); sent(&f, 68); /* 恰 low32，仍是旧锁存。 */
    f.fault_operation = 3; errno = EDOM;
    CHECK(vireo_tcp_server_client_flow_refresh(f.server, f.clients[0], &e) == VIREO_RESULT_IO && errno == EDOM);
    mod_error(&e, VIREO_TCP_SERVER_CLIENT_FLOW_REFRESH, VIREO_CONNECTION_LOOP_STAGE_FLOW_REFRESH);
    CHECK(info(&f, 0).connection_info.write_pressure && info(&f, 0).connection_info.loop_interests == VIREO_EPOLL_INTEREST_WRITE);
    CHECK(info(&f, 0).connection_info.write_buffer.readable_size == 32); /* 不回滚 send。 */
    f.fault_operation = 0;
    CHECK(vireo_tcp_server_client_flow_refresh(f.server, f.clients[0], &e) == VIREO_OK); clean_error(&e);
    CHECK(!info(&f, 0).connection_info.write_pressure); end(&f, 1);
}
static void eof_policy(void)
{
    ++groups; fixture_t f = {0}; start(&f, AF_INET, false, connection_options, 1); configured(&f);
    uint8_t const byte = 88; feed(&f, 0, &byte, 1); REQUIRE(shutdown(f.peers[0], SHUT_WR) == 0);
    vireo_connection_receive_info_t r;
    REQUIRE(vireo_tcp_server_client_receive(f.server, f.clients[0], &read_budget, &r, NULL) == VIREO_OK);
    CHECK(r.stop_reason == VIREO_CONNECTION_RECEIVE_STOP_EOF && info(&f, 0).connection_info.read_eof);
    queue(&f, 1); CHECK(info(&f, 0).connection_info.loop_interests == reading);
    REQUIRE(vireo_tcp_server_client_flow_refresh(f.server, f.clients[0], NULL) == VIREO_OK);
    CHECK(info(&f, 0).connection_info.loop_interests == VIREO_EPOLL_INTEREST_WRITE && info(&f, 0).connection_info.read_buffer.readable_size == 1);
    sent(&f, 1); REQUIRE(vireo_tcp_server_client_flow_refresh(f.server, f.clients[0], NULL) == VIREO_OK);
    CHECK(info(&f, 0).connection_info.loop_interests == 0 && info(&f, 0).connection_info.close_state == VIREO_CONNECTION_CLOSE_OPEN);
    end(&f, 1);
}
static void drain_lifecycle(void)
{
    ++groups; fixture_t f = {0}; start(&f, AF_INET, true, connection_options, 1); configured(&f); queue(&f, 100);
    REQUIRE(vireo_tcp_server_client_request_close(f.server, f.clients[0], VIREO_CONNECTION_CLOSE_MODE_DRAIN,
        VIREO_CONNECTION_CLOSE_REASON_APPLICATION, NULL) == VIREO_OK);
    CHECK(info(&f, 0).connection_info.close_state == VIREO_CONNECTION_CLOSE_DRAINING);
    CHECK(info(&f, 0).connection_info.flow_enabled && info(&f, 0).connection_info.loop_interests == VIREO_EPOLL_INTEREST_WRITE);
    vireo_connection_receive_info_t r, saved; memset(&r, 0xA5, sizeof(r)); saved = r;
    CHECK(vireo_tcp_server_client_receive(f.server, f.clients[0], &read_budget, &r, NULL) == VIREO_RESULT_BUSY && memcmp(&r, &saved, sizeof(r)) == 0);
    uint8_t const byte = 1;
    CHECK(vireo_tcp_server_client_write_enqueue(f.server, f.clients[0], &byte, 1, NULL) == VIREO_RESULT_BUSY);
    for (unsigned k = 0; k < 4; ++k) CHECK(operation(&f, f.clients[0], k, NULL) == VIREO_RESULT_BUSY);
    sent(&f, 40); REQUIRE(vireo_tcp_server_client_close_refresh(f.server, f.clients[0], NULL) == VIREO_OK);
    CHECK(info(&f, 0).connection_info.close_state == VIREO_CONNECTION_CLOSE_DRAINING);
    sent(&f, 60); CHECK(info(&f, 0).connection_info.close_state == VIREO_CONNECTION_CLOSE_DRAINING);
    REQUIRE(vireo_tcp_server_client_close_refresh(f.server, f.clients[0], NULL) == VIREO_OK);
    CHECK(info(&f, 0).connection_info.close_state == VIREO_CONNECTION_CLOSE_READY && info(&f, 0).connection_info.loop_interests == 0);
    vireo_tcp_server_info_t s; REQUIRE(vireo_tcp_server_inspect(f.server, &s) == VIREO_OK);
    CHECK(s.connection_count == 1 && s.buffer_capacity_bytes == 384);
    CHECK(vireo_tcp_server_destroy(&f.server, NULL) == VIREO_RESULT_BUSY && f.server != NULL);
    vireo_connection_send_info_t w, old; memset(&w, 0xA5, sizeof(w)); old = w;
    CHECK(vireo_tcp_server_client_send(f.server, f.clients[0], &write_budget, &w, NULL) == VIREO_RESULT_BUSY && memcmp(&w, &old, sizeof(w)) == 0);
    end(&f, 1);
}
static void close_failures_and_upgrade(void)
{
    ++groups; fixture_t f = {0}; start(&f, AF_INET, true, connection_options, 1); queue(&f, 40);
    vireo_tcp_server_client_error_t e; f.fault_operation = 5; errno = EDOM;
    CHECK(vireo_tcp_server_client_request_close(f.server, f.clients[0], VIREO_CONNECTION_CLOSE_MODE_DRAIN,
        VIREO_CONNECTION_CLOSE_REASON_IO, &e) == VIREO_RESULT_IO && errno == EDOM);
    mod_error(&e, VIREO_TCP_SERVER_CLIENT_REQUEST_CLOSE, VIREO_CONNECTION_LOOP_STAGE_REQUEST_CLOSE);
    vireo_connection_info_t i = info(&f, 0).connection_info;
    CHECK(i.close_state == VIREO_CONNECTION_CLOSE_DRAINING && i.close_reason == VIREO_CONNECTION_CLOSE_REASON_IO && i.loop_interests == reading);
    CHECK(vireo_tcp_server_client_write_enqueue(f.server, f.clients[0], NULL, 0, NULL) == VIREO_RESULT_BUSY);
    f.fault_operation = 0; REQUIRE(vireo_tcp_server_client_close_refresh(f.server, f.clients[0], &e) == VIREO_OK); clean_error(&e);
    sent(&f, 40); f.fault_operation = 6;
    CHECK(vireo_tcp_server_client_close_refresh(f.server, f.clients[0], &e) == VIREO_RESULT_IO);
    mod_error(&e, VIREO_TCP_SERVER_CLIENT_CLOSE_REFRESH, VIREO_CONNECTION_LOOP_STAGE_CLOSE_REFRESH);
    CHECK(info(&f, 0).connection_info.close_state == VIREO_CONNECTION_CLOSE_READY && info(&f, 0).connection_info.loop_interests == VIREO_EPOLL_INTEREST_WRITE);
    f.fault_operation = 0;
    REQUIRE(vireo_tcp_server_client_close_refresh(f.server, f.clients[0], NULL) == VIREO_OK);
    CHECK(vireo_tcp_server_client_request_close(f.server, f.clients[0], VIREO_CONNECTION_CLOSE_MODE_IMMEDIATE,
        VIREO_CONNECTION_CLOSE_REASON_PROTOCOL, NULL) == VIREO_OK);
    CHECK(info(&f, 0).connection_info.close_mode == VIREO_CONNECTION_CLOSE_MODE_IMMEDIATE && info(&f, 0).connection_info.close_reason == VIREO_CONNECTION_CLOSE_REASON_IO);
    f.fault_operation = 6; /* READY/0 同 mask，故障 fd 下也无需 MOD。 */
    CHECK(vireo_tcp_server_client_close_refresh(f.server, f.clients[0], &e) == VIREO_OK); clean_error(&e);
    f.fault_operation = 5;
    CHECK(vireo_tcp_server_client_request_close(f.server, f.clients[0], VIREO_CONNECTION_CLOSE_MODE_IMMEDIATE,
        VIREO_CONNECTION_CLOSE_REASON_APPLICATION, &e) == VIREO_OK); clean_error(&e);
    f.fault_operation = 0;
    CHECK(vireo_tcp_server_client_request_close(f.server, f.clients[0], VIREO_CONNECTION_CLOSE_MODE_DRAIN,
        VIREO_CONNECTION_CLOSE_REASON_APPLICATION, NULL) == VIREO_RESULT_BUSY);
    end(&f, 1);
}
static void close_variants(void)
{
    ++groups;
    for (unsigned k = 0; k < 3; ++k) {
        fixture_t f = {0}; start(&f, AF_INET, false, connection_options, 1);
        CHECK(vireo_tcp_server_client_request_close(f.server, f.clients[0], VIREO_CONNECTION_CLOSE_MODE_NONE,
            VIREO_CONNECTION_CLOSE_REASON_APPLICATION, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
        CHECK(vireo_tcp_server_client_request_close(f.server, f.clients[0], VIREO_CONNECTION_CLOSE_MODE_DRAIN,
            VIREO_CONNECTION_CLOSE_REASON_NONE, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
        CHECK(vireo_tcp_server_client_request_close(f.server, f.clients[0], (vireo_connection_close_mode_t)99,
            (vireo_connection_close_reason_t)99, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
        CHECK(info(&f, 0).connection_info.close_state == VIREO_CONNECTION_CLOSE_OPEN);
        if (k != 0) queue(&f, 2);
        vireo_connection_close_mode_t const m = k == 1 ? VIREO_CONNECTION_CLOSE_MODE_DRAIN : VIREO_CONNECTION_CLOSE_MODE_IMMEDIATE;
        REQUIRE(vireo_tcp_server_client_request_close(f.server, f.clients[0], m, VIREO_CONNECTION_CLOSE_REASON_SERVER_STOP, NULL) == VIREO_OK);
        if (k == 1) REQUIRE(vireo_tcp_server_client_request_close(f.server, f.clients[0], VIREO_CONNECTION_CLOSE_MODE_IMMEDIATE,
            VIREO_CONNECTION_CLOSE_REASON_RESOURCE_LIMIT, NULL) == VIREO_OK);
        CHECK(info(&f, 0).connection_info.close_state == VIREO_CONNECTION_CLOSE_READY && info(&f, 0).connection_info.write_buffer.readable_size == (k == 0 ? 0U : 2U));
        REQUIRE(vireo_tcp_server_client_request_close(f.server, f.clients[0], VIREO_CONNECTION_CLOSE_MODE_IMMEDIATE,
            VIREO_CONNECTION_CLOSE_REASON_PEER_EOF, NULL) == VIREO_OK);
        CHECK(info(&f, 0).connection_info.close_reason == VIREO_CONNECTION_CLOSE_REASON_SERVER_STOP);
        end(&f, 1);
    }
}
static void release_failure_states(void)
{
    ++groups; fixture_t f = {0}; start(&f, AF_INET, true, connection_options, 1); configured(&f);
    vireo_connection_pool_lease_t const lease = f.clients[0];
    REQUIRE(vireo_tcp_server_client_request_close(f.server, lease, VIREO_CONNECTION_CLOSE_MODE_IMMEDIATE,
        VIREO_CONNECTION_CLOSE_REASON_APPLICATION, NULL) == VIREO_OK);
    f.detach_io = true;
    CHECK(vireo_tcp_server_release_client(f.server, &f.clients[0], NULL) == VIREO_RESULT_IO && same(f.clients[0], lease));
    CHECK(info(&f, 0).connection_info.loop_attached && info(&f, 0).connection_info.flow_enabled);
    f.detach_io = false; f.release_busy = true;
    CHECK(vireo_tcp_server_release_client(f.server, &f.clients[0], NULL) == VIREO_RESULT_BUSY && same(f.clients[0], lease));
    vireo_connection_info_t i = info(&f, 0).connection_info;
    CHECK(!i.loop_attached && !i.flow_enabled && i.close_state == VIREO_CONNECTION_CLOSE_READY);
    CHECK(vireo_tcp_server_client_close_refresh(f.server, lease, NULL) == VIREO_OK);
    CHECK(vireo_tcp_server_client_request_close(f.server, lease, VIREO_CONNECTION_CLOSE_MODE_IMMEDIATE,
        VIREO_CONNECTION_CLOSE_REASON_IO, NULL) == VIREO_OK);
    vireo_tcp_server_info_t s; REQUIRE(vireo_tcp_server_inspect(f.server, &s) == VIREO_OK);
    CHECK(s.connection_count == 1 && s.registered_connections == 0 && s.buffer_capacity_bytes == 384);
    f.release_busy = false; end(&f, 1);
    f = (fixture_t){0}; start(&f, AF_INET, true, connection_options, 1); configured(&f);
    f.release_busy = true;
    CHECK(vireo_tcp_server_release_client(f.server, &f.clients[0], NULL) == VIREO_RESULT_BUSY);
    CHECK(vireo_tcp_server_client_set_interests(f.server, f.clients[0], reading, NULL) == VIREO_RESULT_NOT_FOUND);
    CHECK(vireo_tcp_server_client_flow_configure(f.server, f.clients[0], &flow, NULL) == VIREO_RESULT_NOT_FOUND);
    CHECK(vireo_tcp_server_client_flow_disable(f.server, f.clients[0], NULL) == VIREO_OK);
    CHECK(vireo_tcp_server_client_request_close(f.server, f.clients[0], VIREO_CONNECTION_CLOSE_MODE_DRAIN,
        VIREO_CONNECTION_CLOSE_REASON_APPLICATION, NULL) == VIREO_OK);
    end(&f, 1);
    /* 消费型真实 close EBADF：先合法 DEL（via release 的 BUSY），再移去 fd；
     * 不打开任何可复用 fd，直接消费 owner。仅故障夹具，不是 caller 合同许可。 */
    f = (fixture_t){0}; start(&f, AF_INET, true, connection_options, 1); configured(&f);
    f.release_busy = true;
    CHECK(vireo_tcp_server_release_client(f.server, &f.clients[0], NULL) == VIREO_RESULT_BUSY);
    f.release_busy = false; vireo_connection_pool_lease_t const stale = f.clients[0];
    REQUIRE(close(f.raw_fds[0]) == 0); vireo_tcp_server_client_error_t e;
    CHECK(vireo_tcp_server_release_client(f.server, &f.clients[0], &e) == VIREO_RESULT_IO && empty(f.clients[0]));
    CHECK(e.primary.stage == VIREO_TCP_SERVER_CLIENT_RELEASE &&
        e.primary.pool_error.stage == VIREO_CONNECTION_POOL_OPERATION_DESTROY_CONNECTION &&
        e.primary.pool_error.connection_error.system_errno == EBADF);
    REQUIRE(vireo_tcp_server_inspect(f.server, &s) == VIREO_OK);
    CHECK(s.connection_count == 0 && s.buffer_capacity_bytes == 0);
    for (unsigned k = 0; k < 6; ++k) CHECK(operation(&f, stale, k, NULL) == VIREO_RESULT_NOT_FOUND);
    end(&f, 1);
}
static void reused_slot(void)
{
    ++groups; fixture_t f = {0}; start(&f, AF_INET, true, connection_options, 2);
    vireo_connection_pool_lease_t const stale = f.clients[0];
    REQUIRE(vireo_tcp_server_release_client(f.server, &f.clients[0], NULL) == VIREO_OK);
    REQUIRE(close(f.peers[0]) == 0);
    f.peers[0] = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0); REQUIRE(f.peers[0] >= 0);
    REQUIRE(connect(f.peers[0], (struct sockaddr *)&f.address, f.length) == 0);
    vireo_tcp_server_admit_budget_t const b = {1,1}; vireo_tcp_server_admit_info_t i;
    REQUIRE(vireo_tcp_server_admit_batch(f.server, &connection_options, &b, &f.clients[0], 1, &i, NULL) == VIREO_OK && i.admitted_count == 1);
    CHECK(f.clients[0].slot_index == stale.slot_index && f.clients[0].generation != stale.generation);
    for (unsigned k = 0; k < 6; ++k) CHECK(operation(&f, stale, k, NULL) == VIREO_RESULT_NOT_FOUND);
    CHECK(info(&f, 0).connection_info.close_state == VIREO_CONNECTION_CLOSE_OPEN && info(&f, 0).connection_info.loop_interests == reading);
    end(&f, 2);
}
static void request_bytes(uint8_t wire[32])
{
    vireo_protocol_header_t h = {0}; h.command = VIREO_COMMAND_PING; h.sequence = 1;
    REQUIRE(vireo_protocol_header_encode(&h, wire, 32) == VIREO_OK);
    REQUIRE(vireo_protocol_frame_crc32c_calculate(wire, 32, NULL, 0, &h.crc32c) == VIREO_OK);
    REQUIRE(vireo_protocol_header_encode(&h, wire, 32) == VIREO_OK);
}
typedef struct handler_data { fixture_t *fixture; unsigned calls; bool check_busy; } handler_data_t;
static vireo_result_t reply(vireo_connection_frame_view_t const *request, uint8_t *body,
    size_t capacity, vireo_tcp_server_reply_t *description, void *context)
{
    (void)body; (void)capacity; handler_data_t *h = context; ++h->calls;
    CHECK(request->wire_size == 32); description->body_size = 0;
    if (h->check_busy) {
        fixture_t *f = h->fixture; vireo_tcp_server_client_error_t e;
        for (unsigned k = 0; k < 6; ++k) {
            unsigned const before = f->policy_calls[k]; errno = EDOM;
            CHECK(operation(f, f->clients[0], k, &e) == VIREO_RESULT_BUSY && errno == EDOM);
            clean_error(&e);
            CHECK(operation(f, f->clients[1], k, NULL) == VIREO_RESULT_BUSY);
            CHECK(f->policy_calls[k] == before);
        }
        vireo_tcp_server_client_info_t i;
        CHECK(vireo_tcp_server_client_inspect(f->server, f->clients[0], &i) == VIREO_OK);
        vireo_tcp_server_info_t s; REQUIRE(vireo_tcp_server_inspect(f->server, &s) == VIREO_OK);
        CHECK(s.processing_active);
    }
    errno = ERANGE; return VIREO_OK;
}
static void processing_policy(void)
{
    ++groups; fixture_t f = {0}; start(&f, AF_INET, true, connection_options, 2); configured(&f);
    uint8_t request[32], workspace[128], saved_work[128]; request_bytes(request); feed(&f, 0, request, 32);
    memset(workspace, 0xA5, sizeof(workspace)); memcpy(saved_work, workspace, sizeof(workspace));
    vireo_tcp_server_process_info_t p, saved; memset(&p, 0xA5, sizeof(p)); saved = p;
    vireo_tcp_server_process_options_t o = {97, 128};
    vireo_tcp_server_process_budget_t const b = {1,256,128};
    handler_data_t h = {&f,0,true}; errno = EDOM;
    CHECK(vireo_tcp_server_client_process(f.server, f.clients[0], &o, &b, workspace, sizeof(workspace), reply, &h, &p, NULL) == VIREO_RESULT_RANGE && errno == EDOM);
    CHECK(h.calls == 0 && memcmp(&p, &saved, sizeof(p)) == 0 && memcmp(workspace, saved_work, sizeof(workspace)) == 0);
    vireo_connection_frame_options_t const over = {VIREO_CONNECTION_FRAME_REQUEST,97};
    vireo_connection_frame_budget_t const fb = {1,97};
    vireo_connection_frame_info_t fi, saved_fi; memset(&fi, 0xA5, sizeof(fi)); saved_fi = fi;
    vireo_connection_frame_view_t view, saved_view; memset(&view, 0xA5, sizeof(view)); saved_view = view;
    CHECK(vireo_tcp_server_client_frames_peek(f.server, f.clients[0], &over, &fb, &view, 1, &fi, NULL) == VIREO_RESULT_RANGE);
    CHECK(memcmp(&fi, &saved_fi, sizeof(fi)) == 0 && memcmp(&view, &saved_view, sizeof(view)) == 0);
    o.max_request_frame_bytes = 96; errno = EDOM;
    CHECK(vireo_tcp_server_client_process(f.server, f.clients[0], &o, &b, workspace, sizeof(workspace), reply, &h, &p, NULL) == VIREO_OK && errno == EDOM);
    CHECK(h.calls == 1 && p.consumed_requests == 1 && p.enqueued_responses == 1 && p.enqueued_response_bytes == 32);
    CHECK(info(&f, 0).connection_info.loop_interests == reading); /* process 不 MOD。 */
    CHECK(vireo_tcp_server_client_flow_refresh(f.server, f.clients[0], NULL) == VIREO_OK);
    CHECK(info(&f, 0).connection_info.loop_interests == (reading | VIREO_EPOLL_INTEREST_WRITE));
    REQUIRE(vireo_tcp_server_client_request_close(f.server, f.clients[0], VIREO_CONNECTION_CLOSE_MODE_DRAIN,
        VIREO_CONNECTION_CLOSE_REASON_APPLICATION, NULL) == VIREO_OK);
    saved = p; memcpy(saved_work, workspace, sizeof(workspace));
    CHECK(vireo_tcp_server_client_process(f.server, f.clients[0], &o, &b, workspace, sizeof(workspace), reply, &h, &p, NULL) == VIREO_RESULT_BUSY);
    CHECK(h.calls == 1 && memcmp(&p, &saved, sizeof(p)) == 0 && memcmp(workspace, saved_work, sizeof(workspace)) == 0);
    /* 关闭仍可查看/消费读缓存；用独立第二客户证明其状态不改变。 */
    uint8_t const *borrow = NULL; size_t size = 99;
    CHECK(vireo_tcp_server_client_read_peek(f.server, f.clients[0], &borrow, &size, NULL) == VIREO_OK && size == 0);
    CHECK(vireo_tcp_server_client_read_consume(f.server, f.clients[0], 0, NULL) == VIREO_OK);
    CHECK(info(&f, 1).connection_info.close_state == VIREO_CONNECTION_CLOSE_OPEN);
    end(&f, 2);
}
static void budget_and_complete_table(void)
{
    ++groups; vireo_tcp_server_t *owner = NULL; vireo_tcp_server_info_t s;
    REQUIRE(vireo_tcp_server_create(&server_options, &owner, NULL) == VIREO_OK);
    REQUIRE(vireo_tcp_server_inspect(owner, &s) == VIREO_OK);
    REQUIRE(vireo_tcp_server_destroy(&owner, NULL) == VIREO_OK);
    vireo_tcp_server_options_t o = server_options; o.max_memory_bytes = s.allocation_bytes;
    CHECK(vireo_tcp_server_create(&o, &owner, NULL) == VIREO_OK);
    REQUIRE(vireo_tcp_server_destroy(&owner, NULL) == VIREO_OK);
    --o.max_memory_bytes;
    CHECK(vireo_tcp_server_create(&o, &owner, NULL) == VIREO_RESULT_RANGE && owner == NULL);
    fixture_t f = {0};
    for (unsigned k = 0; k < 6; ++k) {
        vireo_tcp_server_client_ops_t table = ops(&f);
        switch (k) {
        case 0:table.set_interests=NULL;break;case 1:table.flow_configure=NULL;break;
        case 2:table.flow_refresh=NULL;break;case 3:table.flow_disable=NULL;break;
        case 4:table.request_close=NULL;break;default:table.close_refresh=NULL;break;
        }
        CHECK(vireo_tcp_server_create_with_client_ops(&server_options, NULL, NULL, &table, &owner, NULL) == VIREO_RESULT_INVALID_ARGUMENT && owner == NULL);
    }
}
int main(void)
{
    unsigned const before = fd_count();
    parameters_and_identity(); thresholds(); read_hysteresis(); write_hysteresis();
    disable_and_no_mod(); flow_failures(); eof_policy(); drain_lifecycle();
    close_failures_and_upgrade(); close_variants(); release_failure_states();
    reused_slot(); processing_policy(); budget_and_complete_table();
    unsigned const after = fd_count(); CHECK(after == before);
    printf("tcp_server client policy: %u groups, %u failures, fd %u->%u\n", groups, failures, before, after);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
