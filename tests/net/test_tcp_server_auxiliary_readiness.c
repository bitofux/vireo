/*
 * PROJECT : VIREO
 * FILE    : test_tcp_server_auxiliary_readiness.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-14
 * BRIEF   : 自有server真实服务轮、LT提示、身份防误删及本核心故障保持
 */
#define _GNU_SOURCE
#include "net/tcp_server_internal.h"
#include <vireo/net/notifier_server.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #c); exit(1); } } while (0)
#define EXPECT(call, result) do { errno = EDOM; CHECK((call) == (result)); CHECK(errno == EDOM); } while (0)
_Static_assert(VIREO_TCP_SERVER_AUXILIARY_NONE == 0 && VIREO_TCP_SERVER_AUXILIARY_CHECK_BINDING == 1 &&
    VIREO_TCP_SERVER_AUXILIARY_REGISTER == 2 && VIREO_TCP_SERVER_AUXILIARY_UNREGISTER == 3, "new stages");
/** 仅本server测试的公开桥接模型，所有资源借用至本组结束。 */
typedef struct fixture {
    vireo_tcp_server_t *server; /**< 唯一server owner。 */
    vireo_notifier_t *notifier; /**< 独立notifier owner，先解除注册借用。 */
    vireo_event_loop_handle_t handle; /**< 原登记身份，成功DEL清空。 */
    vireo_event_loop_t *loop; /**< 本核心add/wait短借获得；不向生产caller暴露。 */
    vireo_event_loop_registration_t registration; /**< 公开登记值，仅模型注入原回调用。 */
    unsigned add_calls, del_calls, inspect_calls, wait_calls, probes, observer_calls; /**< 实际次数。 */
    bool fail_add, fail_del, fail_inspect, probe_wait; /**< 依赖边界模型失败/在途核验。 */
} fixture_t;
static vireo_tcp_server_options_t const options = {4, 8, 1048576, 16384};
static vireo_tcp_server_process_options_t const process = {96, 96};
static vireo_tcp_server_drive_budget_t const drive = {{SIZE_MAX, 8}, {2, 192, 192}, {SIZE_MAX, 8}};
static vireo_tcp_server_round_budget_t const round_budget = {4};
static bool same(vireo_event_loop_handle_t a, vireo_event_loop_handle_t b) {
    return a.loop_id == b.loop_id && a.token == b.token;
}
static size_t fds(void) {
    DIR *d = opendir("/proc/self/fd"); CHECK(d != NULL); size_t n = 0;
    struct dirent *e; while ((e = readdir(d)) != NULL) if (e->d_name[0] != '.') ++n;
    CHECK(closedir(d) == 0); return n;
}
static vireo_result_t handler(vireo_connection_frame_view_t const *q, uint8_t *bytes,
    size_t capacity, vireo_tcp_server_reply_t *reply, void *ctx) {
    (void)q; (void)bytes; (void)capacity; (void)reply; (void)ctx;
    CHECK(false); return VIREO_RESULT_INTERNAL; /* 空客户fixture，不应调用业务。 */
}
static vireo_result_t inspect_source(void *ctx, vireo_event_loop_t const *loop,
    vireo_event_loop_handle_t h, vireo_event_loop_registration_t *r) {
    fixture_t *f = ctx; ++f->inspect_calls; errno = ENOSPC;
    if (f->fail_inspect) return VIREO_RESULT_INTERNAL;
    return vireo_event_loop_registration_inspect(loop, h, r);
}
static vireo_result_t add_source(void *ctx, vireo_event_loop_t *loop,
    vireo_event_loop_registration_t const *r, vireo_event_loop_handle_t *h, vireo_event_loop_error_t *e) {
    fixture_t *f = ctx; ++f->add_calls; errno = ENOSPC;
    if (f->fail_add) { *e = (vireo_event_loop_error_t){.stage = VIREO_EVENT_LOOP_STAGE_ADD,
        .epoll_error = {VIREO_EPOLL_STAGE_ADD, ENOMEM}}; return VIREO_RESULT_IO; }
    vireo_result_t result = vireo_event_loop_add(loop, r, h, e);
    if (result == VIREO_OK) { f->loop = loop; f->registration = *r; }
    return result;
}
static vireo_result_t del_source(void *ctx, vireo_event_loop_t *loop,
    vireo_event_loop_handle_t *h, vireo_event_loop_error_t *e) {
    fixture_t *f = ctx; ++f->del_calls; errno = ENOSPC;
    if (f->fail_del) { *e = (vireo_event_loop_error_t){.stage = VIREO_EVENT_LOOP_STAGE_DEL,
        .epoll_error = {VIREO_EPOLL_STAGE_DEL, EIO}}; return VIREO_RESULT_IO; }
    return vireo_event_loop_del(loop, h, e);
}
static vireo_tcp_server_auxiliary_ops_t aux_ops(fixture_t *f) {
    return (vireo_tcp_server_auxiliary_ops_t){f, inspect_source, add_source, del_source};
}
static void probe(fixture_t *f) {
    vireo_notifier_info_t n; EXPECT(vireo_notifier_inspect(f->notifier, &n), VIREO_OK);
    vireo_event_loop_handle_t h = {0}, old = f->handle;
    vireo_tcp_server_auxiliary_event_t out; memset(&out, 0xa5, sizeof out);
    unsigned char saved[sizeof out]; memcpy(saved, &out, sizeof out);
    EXPECT(vireo_tcp_server_auxiliary_read_register(f->server, n.fd, &h, NULL), VIREO_RESULT_BUSY);
    EXPECT(vireo_tcp_server_auxiliary_read_unregister(f->server, &old, NULL), VIREO_RESULT_BUSY); CHECK(same(old, f->handle));
    EXPECT(vireo_tcp_server_auxiliary_read_take_ready(f->server, &out, NULL), VIREO_RESULT_BUSY);
    CHECK(memcmp(saved, &out, sizeof out) == 0 && !h.token); ++f->probes;
}
static vireo_result_t wait_once(void *ctx, vireo_event_loop_t *loop, int timeout,
    vireo_event_loop_run_info_t *i, vireo_event_loop_error_t *e) {
    fixture_t *f = ctx; ++f->wait_calls; f->loop = loop;
    if (f->probe_wait) probe(f);
    vireo_result_t result = vireo_event_loop_run_once(loop, timeout, i, e);
    if (f->probe_wait) probe(f);
    errno = ENOSPC; return result;
}
static void setup(fixture_t *f, size_t extra, bool custom_wait) {
    *f = (fixture_t){0};
    if (custom_wait) { vireo_tcp_server_scheduler_ops_t const ops = {f, wait_once};
        EXPECT(vireo_tcp_server_create_with_auxiliary_scheduler_ops(&options, extra, &ops, &f->server, NULL), VIREO_OK);
    } else if (extra) EXPECT(vireo_tcp_server_create_with_auxiliary_capacity(&options, extra, &f->server, NULL), VIREO_OK);
    else EXPECT(vireo_tcp_server_create(&options, &f->server, NULL), VIREO_OK);
    vireo_notifier_options_t const n = {4096}; EXPECT(vireo_notifier_create(&n, &f->notifier, NULL), VIREO_OK);
}
static void bind_fixture(fixture_t *f) {
    vireo_notifier_info_t n; EXPECT(vireo_notifier_inspect(f->notifier, &n), VIREO_OK);
    vireo_tcp_server_auxiliary_ops_t const ops = aux_ops(f);
    EXPECT(vireo_tcp_server_auxiliary_read_register_with_ops(f->server, n.fd, &f->handle, NULL, &ops), VIREO_OK);
    CHECK(f->registration.interests == VIREO_EPOLL_INTEREST_READ && f->registration.context == f->server);
}
static vireo_tcp_server_info_t state(fixture_t *f) {
    vireo_tcp_server_info_t i; EXPECT(vireo_tcp_server_inspect(f->server, &i), VIREO_OK); return i;
}
static void cleanup(fixture_t *f) {
    if (f->handle.token) EXPECT(vireo_tcp_server_auxiliary_read_unregister(f->server, &f->handle, NULL), VIREO_OK);
    EXPECT(vireo_tcp_server_destroy(&f->server, NULL), VIREO_OK);
    EXPECT(vireo_notifier_destroy(&f->notifier, NULL), VIREO_OK);
}
static void notify(fixture_t *f) {
    vireo_notifier_notify_outcome_t out; EXPECT(vireo_notifier_notify(f->notifier, &out, NULL), VIREO_OK);
    CHECK(out == VIREO_NOTIFIER_NOTIFY_INCREMENTED);
}
static vireo_tcp_server_round_info_t run_once(fixture_t *f, int timeout) {
    uint8_t workspace[96]; vireo_tcp_server_turn_result_t turns[4]; vireo_tcp_server_round_info_t i;
    EXPECT(vireo_tcp_server_run_once(f->server, timeout, &process, &drive, &round_budget,
        workspace, sizeof workspace, handler, NULL, turns, 4, &i, NULL), VIREO_OK); return i;
}
static void real_lt(void) {
    fixture_t f; setup(&f, 1, false); bind_fixture(&f); notify(&f); notify(&f);
    (void)run_once(&f, 500); CHECK(state(&f).auxiliary_pending_events == VIREO_EPOLL_EVENT_READ);
    (void)run_once(&f, 0); CHECK(state(&f).auxiliary_pending_events == VIREO_EPOLL_EVENT_READ);
    vireo_tcp_server_auxiliary_event_t out; EXPECT(vireo_tcp_server_auxiliary_read_take_ready(f.server, &out, NULL), VIREO_OK);
    CHECK(same(out.handle, f.handle) && out.events == VIREO_EPOLL_EVENT_READ && !state(&f).auxiliary_pending_events);
    unsigned char saved[sizeof out]; memcpy(saved, &out, sizeof out);
    EXPECT(vireo_tcp_server_auxiliary_read_take_ready(f.server, &out, NULL), VIREO_RESULT_NOT_FOUND); CHECK(!memcmp(saved, &out, sizeof out));
    (void)run_once(&f, 0); /* 取出只清C标记；内核仍READ，LT再次分发。 */
    CHECK(state(&f).auxiliary_pending_events == VIREO_EPOLL_EVENT_READ);
    EXPECT(vireo_tcp_server_auxiliary_read_take_ready(f.server, &out, NULL), VIREO_OK);
    uint64_t count; EXPECT(vireo_notifier_consume(f.notifier, &count, NULL), VIREO_OK); CHECK(count == 2);
    (void)run_once(&f, 0); CHECK(!state(&f).auxiliary_pending_events); cleanup(&f);
}
static void basic_and_capacity(void) {
    fixture_t f; setup(&f, 0, false); vireo_notifier_info_t n; EXPECT(vireo_notifier_inspect(f.notifier, &n), VIREO_OK);
    vireo_event_loop_handle_t h = {0}; vireo_tcp_server_auxiliary_error_t e;
    EXPECT(vireo_tcp_server_auxiliary_read_register(f.server, n.fd, &h, &e), VIREO_RESULT_NOT_FOUND);
    EXPECT(vireo_tcp_server_auxiliary_read_register(NULL, n.fd, &h, &e), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_tcp_server_auxiliary_read_register(f.server, -1, &h, &e), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_tcp_server_auxiliary_read_register(f.server, n.fd, NULL, &e), VIREO_RESULT_INVALID_ARGUMENT);
    h = (vireo_event_loop_handle_t){1, 0};
    EXPECT(vireo_tcp_server_auxiliary_read_register(f.server, n.fd, &h, &e), VIREO_RESULT_INVALID_ARGUMENT); CHECK(h.loop_id == 1 && !h.token);
    EXPECT(vireo_tcp_server_auxiliary_read_unregister(NULL, &h, &e), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_tcp_server_auxiliary_read_unregister(f.server, NULL, &e), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_tcp_server_auxiliary_read_take_ready(f.server, NULL, &e), VIREO_RESULT_INVALID_ARGUMENT);
    vireo_tcp_server_auxiliary_event_t out = {{1, 2}, 32};
    EXPECT(vireo_tcp_server_auxiliary_read_take_ready(NULL, &out, &e), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(out.handle.loop_id == 1 && out.events == 32 && e.stage == 0); cleanup(&f);
}
static void single_and_identity(void) {
    fixture_t f, other; setup(&f, 2, false); setup(&other, 1, false); bind_fixture(&f); bind_fixture(&other);
    vireo_notifier_info_t n; EXPECT(vireo_notifier_inspect(f.notifier, &n), VIREO_OK); vireo_event_loop_handle_t h = {0};
    EXPECT(vireo_tcp_server_auxiliary_read_register(f.server, n.fd, &h, NULL), VIREO_RESULT_BUSY);
    h = other.handle; EXPECT(vireo_tcp_server_auxiliary_read_unregister(f.server, &h, NULL), VIREO_RESULT_INVALID_ARGUMENT); CHECK(same(h, other.handle));
    h = (vireo_event_loop_handle_t){0}; EXPECT(vireo_tcp_server_auxiliary_read_unregister(f.server, &h, NULL), VIREO_RESULT_NOT_FOUND);
    h = (vireo_event_loop_handle_t){f.handle.loop_id, 0}; EXPECT(vireo_tcp_server_auxiliary_read_unregister(f.server, &h, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    h = (vireo_event_loop_handle_t){f.handle.loop_id, UINT64_MAX}; EXPECT(vireo_tcp_server_auxiliary_read_unregister(f.server, &h, NULL), VIREO_RESULT_RANGE);
    h = f.handle; EXPECT(vireo_tcp_server_auxiliary_read_unregister(f.server, &f.handle, NULL), VIREO_OK);
    bind_fixture(&f); CHECK(!same(h, f.handle)); EXPECT(vireo_tcp_server_auxiliary_read_unregister(f.server, &h, NULL), VIREO_RESULT_NOT_FOUND);
    CHECK(state(&f).auxiliary_read_bound); cleanup(&f); cleanup(&other);
}
static void failures_hold_state(void) {
    fixture_t f; setup(&f, 1, false); vireo_tcp_server_auxiliary_ops_t ops = aux_ops(&f);
    vireo_notifier_info_t n; EXPECT(vireo_notifier_inspect(f.notifier, &n), VIREO_OK); vireo_tcp_server_auxiliary_error_t e;
    f.fail_add = true;
    EXPECT(vireo_tcp_server_auxiliary_read_register_with_ops(f.server, n.fd, &f.handle, &e, &ops), VIREO_RESULT_IO);
    CHECK(!f.handle.token && !state(&f).auxiliary_read_bound && e.stage == VIREO_TCP_SERVER_AUXILIARY_REGISTER && e.loop_error.epoll_error.system_errno == ENOMEM);
    f.fail_add = false; bind_fixture(&f); notify(&f); (void)run_once(&f, 500);
    vireo_event_loop_handle_t h = f.handle; uint32_t pending = state(&f).auxiliary_pending_events;
    f.fail_inspect = true;
    EXPECT(vireo_tcp_server_auxiliary_read_unregister_with_ops(f.server, &f.handle, &e, &ops), VIREO_RESULT_INTERNAL);
    CHECK(!f.del_calls && same(h, f.handle) && state(&f).auxiliary_pending_events == pending);
    f.fail_inspect = false; f.fail_del = true;
    EXPECT(vireo_tcp_server_auxiliary_read_unregister_with_ops(f.server, &f.handle, &e, &ops), VIREO_RESULT_IO);
    CHECK(f.del_calls == 1 && same(h, f.handle) && state(&f).auxiliary_pending_events == pending && e.loop_error.epoll_error.system_errno == EIO);
    f.fail_del = false; EXPECT(vireo_tcp_server_auxiliary_read_unregister_with_ops(f.server, &f.handle, &e, &ops), VIREO_OK);
    CHECK(!state(&f).auxiliary_pending_events && !state(&f).auxiliary_read_bound); cleanup(&f);
}
static void ignore_other_registration(vireo_event_loop_t *loop, vireo_event_loop_handle_t h,
    int fd, uint32_t events, void *ctx) { (void)loop; (void)h; (void)fd; (void)events; (void)ctx; }
static void protect_other_registration(void) {
    fixture_t f; setup(&f, 2, false); bind_fixture(&f); int pipes[2]; CHECK(pipe2(pipes, O_NONBLOCK | O_CLOEXEC) == 0);
    /* 本核心隔离测试临时借用公开loop建第二登记；恢复后再inspect，不冒充生产通用辅助表。 */
    vireo_event_loop_registration_t const r = {pipes[0], VIREO_EPOLL_INTEREST_READ, ignore_other_registration, NULL};
    vireo_event_loop_handle_t h = {0}; EXPECT(vireo_event_loop_add(f.loop, &r, &h, NULL), VIREO_OK);
    vireo_event_loop_handle_t old = h; vireo_tcp_server_auxiliary_ops_t const ops = aux_ops(&f);
    EXPECT(vireo_tcp_server_auxiliary_read_unregister_with_ops(f.server, &h, NULL, &ops), VIREO_RESULT_NOT_FOUND);
    CHECK(!f.del_calls && same(h, old)); vireo_event_loop_registration_t observed;
    EXPECT(vireo_event_loop_registration_inspect(f.loop, h, &observed), VIREO_OK); CHECK(observed.fd == pipes[0]);
    EXPECT(vireo_event_loop_del(f.loop, &h, NULL), VIREO_OK); CHECK(close(pipes[0]) == 0 && close(pipes[1]) == 0);
    CHECK(state(&f).auxiliary_read_bound); cleanup(&f);
}
static void model_or_and_stale(void) {
    fixture_t f; setup(&f, 1, false); bind_fixture(&f);
    vireo_event_loop_registration_t old = f.registration; vireo_event_loop_handle_t old_handle = f.handle;
    /* 人工模型只验证合并和旧回调防护；真实READ/HUP另组验证。 */
    old.callback(f.loop, f.handle, old.fd, VIREO_EPOLL_EVENT_READ, old.context);
    old.callback(f.loop, f.handle, old.fd, VIREO_EPOLL_EVENT_ERROR | VIREO_EPOLL_EVENT_HANGUP, old.context);
    CHECK(state(&f).auxiliary_pending_events == (VIREO_EPOLL_EVENT_READ | VIREO_EPOLL_EVENT_ERROR | VIREO_EPOLL_EVENT_HANGUP));
    EXPECT(vireo_tcp_server_auxiliary_read_unregister(f.server, &f.handle, NULL), VIREO_OK); bind_fixture(&f);
    old.callback(f.loop, old_handle, old.fd, VIREO_EPOLL_EVENT_READ, old.context); CHECK(!state(&f).auxiliary_pending_events);
    cleanup(&f);
}
static void real_pipe_hup(void) {
    fixture_t f; setup(&f, 1, false); int p[2]; CHECK(pipe2(p, O_NONBLOCK | O_CLOEXEC) == 0);
    EXPECT(vireo_tcp_server_auxiliary_read_register(f.server, p[0], &f.handle, NULL), VIREO_OK);
    CHECK(write(p[1], "x", 1) == 1 && close(p[1]) == 0); (void)run_once(&f, 500);
    vireo_tcp_server_auxiliary_event_t out; EXPECT(vireo_tcp_server_auxiliary_read_take_ready(f.server, &out, NULL), VIREO_OK);
    CHECK((out.events & VIREO_EPOLL_EVENT_READ) && (out.events & VIREO_EPOLL_EVENT_HANGUP));
    EXPECT(vireo_tcp_server_auxiliary_read_unregister(f.server, &f.handle, NULL), VIREO_OK); CHECK(close(p[0]) == 0); cleanup(&f);
}
static void active_wait(void) {
    fixture_t f; setup(&f, 1, true); bind_fixture(&f); f.probe_wait = true; notify(&f);
    (void)run_once(&f, 500); CHECK(f.probes == 2 && f.wait_calls == 1 && state(&f).auxiliary_pending_events == VIREO_EPOLL_EVENT_READ); cleanup(&f);
}
static void setup_admission(fixture_t *f, struct sockaddr_in *out_address) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0); CHECK(fd >= 0);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_addr = {htonl(INADDR_LOOPBACK)}};
    CHECK(bind(fd, (struct sockaddr *)&a, (socklen_t)sizeof a) == 0 && listen(fd, 4) == 0);
    if (out_address != NULL) { socklen_t length = (socklen_t)sizeof *out_address;
        CHECK(getsockname(fd, (struct sockaddr *)out_address, &length) == 0); }
    vireo_acceptor_options_t const o = {4096}; vireo_acceptor_t *owner = NULL;
    EXPECT(vireo_acceptor_create(&o, &fd, &owner, NULL), VIREO_OK);
    EXPECT(vireo_tcp_server_adopt_listener(f->server, &owner, NULL), VIREO_OK);
    EXPECT(vireo_tcp_server_bind_listener(f->server, true, NULL), VIREO_OK);
    vireo_tcp_server_admission_options_t const policy = {{256, 128, 384}, {96, 95, 192, 32, 96}};
    EXPECT(vireo_tcp_server_admission_configure(f->server, &policy, NULL), VIREO_OK);
}
static void real_serve(void) {
    fixture_t f; setup(&f, 1, true); setup_admission(&f, NULL); bind_fixture(&f); f.probe_wait = true; notify(&f);
    vireo_tcp_server_serve_options_t const o = {500, process, drive, round_budget, {4, 16}};
    uint8_t w[96]; vireo_tcp_server_turn_result_t turns[4]; vireo_connection_pool_lease_t clients[4] = {0}; vireo_tcp_server_serve_info_t info;
    EXPECT(vireo_tcp_server_serve_once(f.server, &o, w, sizeof w, handler, NULL, turns, 4, clients, 4, &info, NULL), VIREO_OK);
    CHECK(f.wait_calls == 1 && f.probes == 2 && !info.listener_events && !info.admission.admitted_count);
    CHECK(state(&f).auxiliary_pending_events == VIREO_EPOLL_EVENT_READ);
    vireo_tcp_server_auxiliary_event_t out; EXPECT(vireo_tcp_server_auxiliary_read_take_ready(f.server, &out, NULL), VIREO_OK);
    uint64_t count; EXPECT(vireo_notifier_consume(f.notifier, &count, NULL), VIREO_OK); CHECK(count == 1); cleanup(&f);
}
static void observer(vireo_tcp_server_t *s, vireo_result_t result, vireo_tcp_server_serve_info_t const *i,
    vireo_tcp_server_turn_result_t const *turns, vireo_connection_pool_lease_t const *clients,
    vireo_tcp_server_serve_error_t const *error, void *ctx) {
    (void)i; (void)turns; (void)clients; (void)error; fixture_t *f = ctx; CHECK(s == f->server && result == VIREO_OK); ++f->observer_calls;
    vireo_tcp_server_info_t current = state(f); CHECK(current.running_active && !current.serving_active && !current.scheduling_active);
    vireo_tcp_server_auxiliary_event_t out; EXPECT(vireo_tcp_server_auxiliary_read_take_ready(s, &out, NULL), VIREO_OK);
    CHECK(out.events & VIREO_EPOLL_EVENT_READ);
    EXPECT(vireo_notifier_server_unregister(s, &f->handle, NULL), VIREO_OK);
    EXPECT(vireo_notifier_server_register(s, f->notifier, &f->handle, NULL), VIREO_OK);
    EXPECT(vireo_tcp_server_request_stop(s, NULL), VIREO_OK);
}
static void observer_window(void) {
    fixture_t f; setup(&f, 1, false); setup_admission(&f, NULL); bind_fixture(&f); notify(&f);
    vireo_tcp_server_run_options_t const o = {process, drive, round_budget, {4, 16}};
    uint8_t w[96]; vireo_tcp_server_turn_result_t turns[4]; vireo_connection_pool_lease_t clients[4] = {0};
    EXPECT(vireo_tcp_server_run(f.server, &o, w, sizeof w, handler, NULL, turns, 4, clients, 4, observer, &f, NULL), VIREO_OK);
    CHECK(f.observer_calls == 1); cleanup(&f);
}
static void stopped_mechanical(void) {
    fixture_t f; setup(&f, 1, false); bind_fixture(&f); notify(&f); (void)run_once(&f, 500);
    EXPECT(vireo_tcp_server_request_stop(f.server, NULL), VIREO_OK);
    vireo_tcp_server_auxiliary_event_t out; EXPECT(vireo_tcp_server_auxiliary_read_take_ready(f.server, &out, NULL), VIREO_OK);
    EXPECT(vireo_notifier_server_unregister(f.server, &f.handle, NULL), VIREO_OK);
    EXPECT(vireo_notifier_server_register(f.server, f.notifier, &f.handle, NULL), VIREO_OK);
    (void)run_once(&f, 0); CHECK(!state(&f).auxiliary_pending_events); /* 已停止不分发，即使eventfd仍READ。 */
    uint64_t count; EXPECT(vireo_notifier_consume(f.notifier, &count, NULL), VIREO_OK); CHECK(count == 1); cleanup(&f);
}
static void full_clients_keep_auxiliary(void) {
    fixture_t f; setup(&f, 1, false); struct sockaddr_in address; setup_admission(&f, &address);
    int peers[4]; vireo_connection_pool_lease_t clients[4] = {0};
    for (size_t k = 0; k < 4; ++k) {
        peers[k] = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0); CHECK(peers[k] >= 0);
        CHECK(connect(peers[k], (struct sockaddr *)&address, (socklen_t)sizeof address) == 0);
    }
    vireo_connection_options_t const connection = {256, 128, 384};
    vireo_tcp_server_admit_budget_t const budget = {4, 8}; vireo_tcp_server_admit_info_t admitted;
    EXPECT(vireo_tcp_server_admit_batch(f.server, &connection, &budget, clients, 4, &admitted, NULL), VIREO_OK);
    CHECK(admitted.admitted_count == 4 && state(&f).registered_connections == 4 && !state(&f).available_connections);
    /* 满客户池以后才登记辅助源，原监听槽和客户槽保持完整。 */
    bind_fixture(&f); notify(&f); (void)run_once(&f, 500);
    vireo_tcp_server_auxiliary_event_t out; EXPECT(vireo_tcp_server_auxiliary_read_take_ready(f.server, &out, NULL), VIREO_OK);
    CHECK(out.events == VIREO_EPOLL_EVENT_READ && state(&f).registered_connections == 4);
    for (size_t k = 0; k < 4; ++k) {
        EXPECT(vireo_tcp_server_release_client(f.server, &clients[k], NULL), VIREO_OK); CHECK(close(peers[k]) == 0);
    }
    cleanup(&f);
}
static void real_add_failure(void) {
    fixture_t f; setup(&f, 1, false);
    char path[] = "/tmp/vireo-029-04-regular-XXXXXX"; int fd = mkstemp(path); CHECK(fd >= 0); CHECK(unlink(path) == 0);
    vireo_tcp_server_auxiliary_error_t e;
    /* Linux epoll不支持普通文件；真实ADD拒绝，不破坏一个已注册借用fd。 */
    EXPECT(vireo_tcp_server_auxiliary_read_register(f.server, fd, &f.handle, &e), VIREO_RESULT_IO);
    CHECK(!f.handle.loop_id && !f.handle.token && !state(&f).auxiliary_read_bound &&
        e.stage == VIREO_TCP_SERVER_AUXILIARY_REGISTER && e.loop_error.epoll_error.system_errno == EPERM);
    CHECK(fcntl(fd, F_GETFD) >= 0 && close(fd) == 0); bind_fixture(&f); cleanup(&f);
}

static void incomplete_seams(void) {
    fixture_t f; setup(&f, 1, false); vireo_tcp_server_auxiliary_ops_t ops = aux_ops(&f); ops.del = NULL;
    vireo_notifier_info_t n; EXPECT(vireo_notifier_inspect(f.notifier, &n), VIREO_OK);
    EXPECT(vireo_tcp_server_auxiliary_read_register_with_ops(f.server, n.fd, &f.handle, NULL, &ops), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_tcp_server_auxiliary_read_unregister_with_ops(f.server, &f.handle, NULL, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(!f.add_calls && !f.inspect_calls && !f.del_calls); cleanup(&f);
}
int main(void) {
    CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL) == 0);
    void (*const cases[])(void) = {real_lt, basic_and_capacity, single_and_identity, failures_hold_state,
        protect_other_registration, model_or_and_stale, real_pipe_hup, active_wait, real_serve, observer_window, stopped_mechanical, full_clients_keep_auxiliary, real_add_failure, incomplete_seams};
    for (size_t k = 0; k < sizeof cases / sizeof cases[0]; ++k) { size_t n = fds(); cases[k](); CHECK(fds() == n); }
    puts("server auxiliary readiness: 14 groups passed"); return 0;
}
