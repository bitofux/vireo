/*
 * PROJECT : VIREO
 * FILE    : test_tcp_server_tls_auxiliary.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-18
 * BRIEF   : TLS根辅助容量/原子交接回滚与真实notifier安全点提示通路
 */
#define _GNU_SOURCE
#include "net/tcp_server_internal.h"
#include "tls_context_fixtures.h"
#include <vireo/net/notifier_server.h>
#include <vireo/net/notifier_server_dispatch.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define CHECK(c) do { if (!(c)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #c); abort(); } } while (0)
#define EXPECT(call, want) do { errno = EDOM; vireo_result_t const got_ = (call); \
    if (got_ != (want)) fprintf(stderr, "result=%d expected=%d\n", (int)got_, (int)(want)); \
    CHECK(got_ == (want)); CHECK(errno == EDOM); } while (0)
static unsigned groups;
static vireo_tcp_server_options_t const root = {4, 8, 1048576, 32768};
static vireo_tcp_server_tls_options_t const tls = {
    {4096, 4096, 40960, 128, 127, 4096, 0, 4096}, 4096, UINT64_C(5000000000), 163840
};
static size_t fds(void)
{
    DIR *d = opendir("/proc/self/fd"); CHECK(d != NULL); size_t n = 0;
    struct dirent *item;
    while ((item = readdir(d)) != NULL) if (item->d_name[0] != '.') ++n;
    CHECK(closedir(d) == 0); return n;
}
static vireo_tls_context_t *context(void)
{
    vireo_tls_context_options_t const o = {fixture_leaf, sizeof fixture_leaf - 1,
        fixture_key, sizeof fixture_key - 1, 4096};
    vireo_tls_context_t *c = NULL;
    EXPECT(vireo_tls_context_create_server(&o, &c, NULL), VIREO_OK); return c;
}
static vireo_tcp_server_t *make(size_t aux)
{
    vireo_tls_context_t *c = context(); vireo_tcp_server_t *s = NULL;
    if (aux == 0) EXPECT(vireo_tcp_server_create_tls(&root, &tls, &c, &s, NULL), VIREO_OK);
    else EXPECT(vireo_tcp_server_create_tls_with_auxiliary_capacity(&root, &tls, aux, &c, &s, NULL), VIREO_OK);
    CHECK(c == NULL); return s;
}
static vireo_tcp_server_info_t inspect(vireo_tcp_server_t const *s)
{
    vireo_tcp_server_info_t i = {0}; EXPECT(vireo_tcp_server_inspect(s, &i), VIREO_OK); return i;
}
static void compatibility(void)
{
    vireo_tcp_server_t *a = make(0), *b = make(7);
    vireo_tcp_server_info_t const ai = inspect(a), bi = inspect(b);
    CHECK(ai.registration_capacity == 5 && ai.auxiliary_registration_capacity == 0);
    CHECK(bi.registration_capacity == 12 && bi.auxiliary_registration_capacity == 7);
    CHECK(ai.connection_capacity == bi.connection_capacity && bi.connection_count == 0);
    CHECK(ai.server_allocation_bytes == bi.server_allocation_bytes && ai.pool_allocation_bytes == bi.pool_allocation_bytes);
    CHECK(bi.loop_allocation_bytes > ai.loop_allocation_bytes);
    CHECK(bi.allocation_bytes - ai.allocation_bytes == bi.loop_allocation_bytes - ai.loop_allocation_bytes);
    vireo_tcp_server_tls_info_t ti;
    EXPECT(vireo_tcp_server_tls_inspect(b, &ti, NULL), VIREO_OK);
    CHECK(ti.resource_bytes == 0 && bi.allocation_bytes == bi.server_allocation_bytes +
        bi.loop_allocation_bytes + bi.pool_allocation_bytes + ti.context_wrapper_bytes);
    vireo_notifier_options_t const no = {4096}; vireo_notifier_t *n = NULL;
    EXPECT(vireo_notifier_create(&no, &n, NULL), VIREO_OK);
    vireo_event_loop_handle_t h = {0};
    EXPECT(vireo_notifier_server_register(a, n, &h, NULL), VIREO_RESULT_NOT_FOUND);
    CHECK(h.loop_id == 0 && h.token == 0);
    EXPECT(vireo_notifier_destroy(&n, NULL), VIREO_OK);
    EXPECT(vireo_tcp_server_destroy(&a, NULL), VIREO_OK);
    EXPECT(vireo_tcp_server_destroy(&b, NULL), VIREO_OK); ++groups;
}
static void reject(vireo_tcp_server_options_t const *o, size_t aux, vireo_result_t want)
{
    vireo_tls_context_t *c = context(), *const original = c; vireo_tcp_server_t *s = NULL;
    vireo_tcp_server_tls_error_t e; memset(&e, 0xa5, sizeof e);
    EXPECT(vireo_tcp_server_create_tls_with_auxiliary_capacity(o, &tls, aux, &c, &s, &e), want);
    CHECK(c == original && s == NULL);
    CHECK(e.stage == (aux == 0 || o == NULL ? VIREO_TCP_SERVER_TLS_NONE : VIREO_TCP_SERVER_TLS_CREATE_SERVER));
    vireo_tls_context_info_t ci; EXPECT(vireo_tls_context_inspect(c, &ci, NULL), VIREO_OK);
    EXPECT(vireo_tls_context_destroy(&c, NULL), VIREO_OK);
}
static void invalid_and_limits(void)
{
    reject(&root, 0, VIREO_RESULT_INVALID_ARGUMENT);
    reject(NULL, 1, VIREO_RESULT_INVALID_ARGUMENT);
    reject(&root, SIZE_MAX, VIREO_RESULT_OVERFLOW);
    reject(&root, SIZE_MAX - 4, VIREO_RESULT_OVERFLOW);
    reject(&root, SIZE_MAX - 5, VIREO_RESULT_RANGE);
    reject(&root, 65532, VIREO_RESULT_RANGE);
    vireo_tcp_server_options_t o = root; o.connection_capacity = 65535;
    reject(&o, 1, VIREO_RESULT_RANGE);
    vireo_tls_context_t *c = context(), *const original = c; vireo_tcp_server_t *s = make(1), *const old = s;
    EXPECT(vireo_tcp_server_create_tls_with_auxiliary_capacity(&root, &tls, 1, &c, &s, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(c == original && s == old);
    EXPECT(vireo_tcp_server_create_tls_with_auxiliary_capacity(&root, &tls, 1, &c, NULL, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_tcp_server_create_tls_with_auxiliary_capacity(&root, &tls, 1, NULL, &s, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_tcp_server_create_tls_with_auxiliary_capacity(&root, NULL, 1, &c, &s, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_tcp_server_destroy(&s, NULL), VIREO_OK);
    EXPECT(vireo_tls_context_destroy(&c, NULL), VIREO_OK);
    o = root; o.max_memory_bytes = VIREO_TCP_SERVER_MAX_MEMORY;
    c = context();
    EXPECT(vireo_tcp_server_create_tls_with_auxiliary_capacity(&o, &tls, 65531, &c, &s, NULL), VIREO_OK);
    CHECK(c == NULL && inspect(s).registration_capacity == 65536);
    EXPECT(vireo_tcp_server_destroy(&s, NULL), VIREO_OK); ++groups;
}
static void exact_budget(void)
{
    vireo_tcp_server_t *s = make(1024); size_t const bytes = inspect(s).allocation_bytes;
    EXPECT(vireo_tcp_server_destroy(&s, NULL), VIREO_OK);
    vireo_tcp_server_options_t o = root; o.max_memory_bytes = bytes;
    vireo_tls_context_t *c = context();
    EXPECT(vireo_tcp_server_create_tls_with_auxiliary_capacity(&o, &tls, 1024, &c, &s, NULL), VIREO_OK);
    CHECK(c == NULL && inspect(s).allocation_bytes == bytes);
    EXPECT(vireo_tcp_server_destroy(&s, NULL), VIREO_OK);
    --o.max_memory_bytes; reject(&o, 1024, VIREO_RESULT_RANGE); ++groups;
}

/** 仅本server公开资源边界故障，真实释放走依赖public API。 */
typedef struct model {
    unsigned fault; /**< 1申请，2loop创建，3loop观察，4pool创建，5pool观察。 */
    unsigned allocations, frees, loops, pools;
    bool cleanup_error;
    size_t registrations;
    char order[32];
    size_t steps;
} model_t;
static void mark(model_t *m, char ch) { CHECK(m->steps + 1 < sizeof m->order); m->order[m->steps++] = ch; }
static void *allocate(void *ctx, size_t bytes)
{ model_t *m = ctx; mark(m, 'A'); if (m->fault == 1) return NULL; ++m->allocations; return malloc(bytes); }
static void release(void *ctx, void *p)
{ model_t *m = ctx; mark(m, 'F'); ++m->frees; free(p); }
static vireo_result_t loop_create(void *ctx, vireo_event_loop_options_t const *o,
    vireo_event_loop_t **p, vireo_event_loop_error_t *e)
{
    model_t *m = ctx; mark(m, 'L'); m->registrations = o->registration_capacity;
    if (m->fault == 2) { *e = (vireo_event_loop_error_t){.stage = VIREO_EVENT_LOOP_STAGE_WAKE_CREATE,
        .system_errno = EMFILE}; return VIREO_RESULT_IO; }
    return vireo_event_loop_create(o, p, e);
}
static vireo_result_t loop_inspect(void *ctx, vireo_event_loop_t const *p, vireo_event_loop_info_t *i)
{ model_t *m = ctx; mark(m, 'I'); return m->fault == 3 ? VIREO_RESULT_INTERNAL : vireo_event_loop_inspect(p, i); }
static vireo_result_t loop_destroy(void *ctx, vireo_event_loop_t **p, vireo_event_loop_error_t *e)
{
    model_t *m = ctx; mark(m, 'l'); ++m->loops; CHECK(vireo_event_loop_destroy(p, e) == VIREO_OK);
    if (m->cleanup_error) { *e = (vireo_event_loop_error_t){.stage = VIREO_EVENT_LOOP_STAGE_DESTROY_EPOLL,
        .system_errno = EINTR}; return VIREO_RESULT_IO; }
    return VIREO_OK;
}
static vireo_result_t pool_create(void *ctx, vireo_connection_pool_options_t const *o,
    vireo_connection_pool_t **p, vireo_connection_pool_error_t *e)
{
    model_t *m = ctx; mark(m, 'P');
    if (m->fault == 4) { *e = (vireo_connection_pool_error_t){.stage = VIREO_CONNECTION_POOL_STAGE_CREATE_STORAGE};
        return VIREO_RESULT_NO_MEMORY; }
    return vireo_connection_pool_create(o, p, e);
}
static vireo_result_t pool_inspect(void *ctx, vireo_connection_pool_t const *p, vireo_connection_pool_info_t *i)
{ model_t *m = ctx; mark(m, 'J'); return m->fault == 5 ? VIREO_RESULT_INTERNAL : vireo_connection_pool_inspect(p, i); }
static vireo_result_t pool_destroy(void *ctx, vireo_connection_pool_t **p, vireo_connection_pool_error_t *e)
{ model_t *m = ctx; mark(m, 'p'); ++m->pools; return vireo_connection_pool_destroy(p, e); }
static void rollback(void)
{
    char const *const orders[] = {"", "A", "ALF", "ALIlF", "ALIPlF", "ALIPJplF"};
    vireo_result_t const results[] = {VIREO_OK, VIREO_RESULT_NO_MEMORY, VIREO_RESULT_IO,
        VIREO_RESULT_INTERNAL, VIREO_RESULT_NO_MEMORY, VIREO_RESULT_INTERNAL};
    for (unsigned k = 1; k <= 6; ++k) {
        model_t m = {.fault = k == 6 ? 4 : k, .cleanup_error = k == 6};
        vireo_tcp_server_ops_t const ops = {&m, allocate, release, loop_create, loop_inspect,
            loop_destroy, pool_create, pool_inspect, pool_destroy};
        vireo_tls_context_t *c = context(), *const original = c; vireo_tcp_server_t *s = NULL;
        size_t const before = fds(); vireo_tcp_server_tls_error_t e;
        EXPECT(vireo_tcp_server_create_tls_with_auxiliary_ops(&root, &tls, 7, &c, &ops, &s, &e), results[m.fault]);
        CHECK(c == original && s == NULL && e.stage == VIREO_TCP_SERVER_TLS_CREATE_SERVER);
        CHECK(strcmp(m.order, orders[m.fault]) == 0 && m.allocations == m.frees && fds() == before);
        CHECK(m.loops == (m.fault >= 3 ? 1U : 0U) && m.pools == (m.fault == 5 ? 1U : 0U));
        if (m.fault >= 2) CHECK(m.registrations == 12);
        if (k == 6) CHECK(e.server_error.cleanup_result == VIREO_RESULT_IO &&
            e.server_error.cleanup_loop_error.system_errno == EINTR);
        if (k == 2) CHECK(e.server_error.loop_error.system_errno == EMFILE);
        EXPECT(vireo_tls_context_destroy(&c, NULL), VIREO_OK); ++groups;
    }
}
static struct sockaddr_in listener(vireo_tcp_server_t *s)
{
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0); CHECK(fd >= 0);
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_addr = {htonl(INADDR_LOOPBACK)}};
    CHECK(bind(fd, (struct sockaddr *)&addr, (socklen_t)sizeof addr) == 0);
    socklen_t size = (socklen_t)sizeof addr;
    CHECK(getsockname(fd, (struct sockaddr *)&addr, &size) == 0 && listen(fd, 8) == 0);
    vireo_acceptor_options_t const o = {4096}; vireo_acceptor_t *a = NULL;
    EXPECT(vireo_acceptor_create(&o, &fd, &a, NULL), VIREO_OK); CHECK(fd == -1);
    EXPECT(vireo_tcp_server_adopt_listener(s, &a, NULL), VIREO_OK); CHECK(a == NULL);
    EXPECT(vireo_tcp_server_bind_listener(s, true, NULL), VIREO_OK); return addr;
}
static void notify(vireo_notifier_t *n)
{
    vireo_notifier_notify_outcome_t out;
    EXPECT(vireo_notifier_notify(n, &out, NULL), VIREO_OK); CHECK(out == VIREO_NOTIFIER_NOTIFY_INCREMENTED);
}
static vireo_tcp_server_tls_poll_report_t poll_once(vireo_tcp_server_t *s, int timeout)
{
    vireo_tcp_server_ready_client_t ready[4]; vireo_tcp_server_tls_poll_report_t report;
    EXPECT(vireo_tcp_server_tls_poll_ready_once(s, timeout, 4, ready, 4, &report, NULL), VIREO_OK); return report;
}
static vireo_result_t unexpected_delivery(void *ctx, vireo_completion_t const *c, vireo_inflight_completion_match_t match)
{ (void)ctx; (void)c; (void)match; CHECK(false); return VIREO_RESULT_INTERNAL; }
static void real_readiness(bool active_handshake)
{
    vireo_tcp_server_t *s = make(7); struct sockaddr_in const addr = listener(s);
    int peer = -1; vireo_connection_pool_lease_t client = {0};
    if (active_handshake) {
        peer = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0); CHECK(peer >= 0);
        CHECK(connect(peer, (struct sockaddr const *)&addr, (socklen_t)sizeof addr) == 0);
        vireo_tcp_server_admit_budget_t const b = {1, 2}; vireo_tcp_server_tls_admit_info_t admitted;
        EXPECT(vireo_tcp_server_tls_admit_batch(s, &b, &client, 1, &admitted, NULL), VIREO_OK);
        CHECK(admitted.admission.admitted_count == 1);
        CHECK(poll_once(s, 0).poll.selected_count == 1);
        vireo_tcp_server_tls_handshake_info_t hi;
        EXPECT(vireo_tcp_server_client_tls_handshake_step(s, client, &hi, NULL), VIREO_OK);
        CHECK(hi.step_called && hi.handshake_reported && !hi.application_ready);
    }
    vireo_notifier_options_t const no = {4096}; vireo_notifier_t *n = NULL, *second = NULL;
    EXPECT(vireo_notifier_create(&no, &n, NULL), VIREO_OK);
    EXPECT(vireo_notifier_create(&no, &second, NULL), VIREO_OK);
    vireo_event_loop_handle_t h = {0}, other = {0};
    EXPECT(vireo_notifier_server_register(s, n, &h, NULL), VIREO_OK);
    EXPECT(vireo_notifier_server_register(s, second, &other, NULL), VIREO_RESULT_BUSY);
    CHECK(other.loop_id == 0 && other.token == 0);
    EXPECT(vireo_notifier_destroy(&second, NULL), VIREO_OK);
    notify(n); notify(n);
    vireo_tcp_server_tls_poll_report_t const waited = poll_once(s, 500);
    CHECK(waited.poll.selected_count == 0 && waited.has_deadline == active_handshake);
    CHECK(inspect(s).connection_count == (active_handshake ? 1U : 0U));
    vireo_tcp_server_auxiliary_event_t event;
    EXPECT(vireo_tcp_server_auxiliary_read_take_ready(s, &event, NULL), VIREO_OK);
    CHECK(event.handle.loop_id == h.loop_id && event.handle.token == h.token && event.events == VIREO_EPOLL_EVENT_READ);
    EXPECT(vireo_tcp_server_auxiliary_read_take_ready(s, &event, NULL), VIREO_RESULT_NOT_FOUND);
    (void)poll_once(s, 0); CHECK(inspect(s).auxiliary_pending_events == VIREO_EPOLL_EVENT_READ);

    /* 真实空完成队列证明两次提示不等两条结果，并复用原安全点消费链。 */
    vireo_inflight_store_options_t const io = {2, 4096}; vireo_inflight_store_t *store = NULL;
    vireo_completion_queue_options_t const qo = {2, 4096}; vireo_completion_queue_t *queue = NULL;
    EXPECT(vireo_inflight_store_create(&io, &store), VIREO_OK);
    EXPECT(vireo_completion_queue_create(&qo, &queue), VIREO_OK);
    vireo_completion_t *remaining = NULL; vireo_notifier_server_dispatch_report_t dr;
    EXPECT(vireo_notifier_server_dispatch_ready(s, h, n, store, queue, 1,
        unexpected_delivery, NULL, &remaining, &dr), VIREO_OK);
    CHECK(dr.ready_taken && dr.dispatch_called && dr.dispatch_report.notification_count == 2);
    CHECK(dr.dispatch_report.drain_called && dr.dispatch_report.drain_report.received == 0 &&
        dr.dispatch_report.drain_report.stop_reason == VIREO_INFLIGHT_COMPLETION_DRAIN_EMPTY && remaining == NULL);
    (void)poll_once(s, 0); CHECK(inspect(s).auxiliary_pending_events == 0);
    EXPECT(vireo_notifier_server_dispatch_ready(s, h, n, store, queue, 1,
        unexpected_delivery, NULL, &remaining, &dr), VIREO_OK);
    CHECK(dr.ready_called && !dr.ready_taken && !dr.dispatch_called);
    EXPECT(vireo_inflight_store_destroy(&store), VIREO_OK);
    EXPECT(vireo_completion_queue_destroy(&queue), VIREO_OK);

    vireo_event_loop_handle_t wrong = h; ++wrong.token;
    EXPECT(vireo_notifier_server_unregister(s, &wrong, NULL), VIREO_RESULT_NOT_FOUND);
    CHECK(inspect(s).auxiliary_read_bound);
    EXPECT(vireo_tcp_server_request_stop(s, NULL), VIREO_OK);
    EXPECT(vireo_notifier_server_unregister(s, &h, NULL), VIREO_OK); CHECK(h.token == 0 && h.loop_id == 0);
    if (active_handshake) { EXPECT(vireo_tcp_server_release_client(s, &client, NULL), VIREO_OK); CHECK(close(peer) == 0); }
    EXPECT(vireo_tcp_server_destroy(&s, NULL), VIREO_OK);
    notify(n); uint64_t count = 0; EXPECT(vireo_notifier_consume(n, &count, NULL), VIREO_OK); CHECK(count == 1);
    EXPECT(vireo_notifier_destroy(&n, NULL), VIREO_OK); ++groups;
}
static void borrowed_fd_after_root_destroy(void)
{
    vireo_tcp_server_t *s = make(1); vireo_notifier_t *n = NULL;
    vireo_notifier_options_t const no = {4096}; EXPECT(vireo_notifier_create(&no, &n, NULL), VIREO_OK);
    vireo_event_loop_handle_t h = {0}; EXPECT(vireo_notifier_server_register(s, n, &h, NULL), VIREO_OK);
    EXPECT(vireo_tcp_server_destroy(&s, NULL), VIREO_OK); /* loop销毁结束借用，fd仍归notifier。 */
    notify(n); uint64_t count = 0; EXPECT(vireo_notifier_consume(n, &count, NULL), VIREO_OK); CHECK(count == 1);
    EXPECT(vireo_notifier_destroy(&n, NULL), VIREO_OK); ++groups;
}
int main(void)
{
    struct sigaction action = {0}; action.sa_handler = SIG_IGN;
    CHECK(sigemptyset(&action.sa_mask) == 0 && sigaction(SIGPIPE, &action, NULL) == 0);
    size_t const before = fds();
    compatibility(); invalid_and_limits(); exact_budget(); rollback();
    real_readiness(false); real_readiness(true); borrowed_fd_after_root_destroy();
    size_t const after = fds(); CHECK(after == before);
    printf("TLS auxiliary: %u groups, fd %zu -> %zu\n", groups, before, after); return 0;
}
