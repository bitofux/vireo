/*
 * PROJECT : VIREO
 * FILE    : test_notifier_server_registration.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-14
 * BRIEF   : notifier/server真实配对及本接线层公开依赖故障；不读取其他私有头
 */
#define _GNU_SOURCE
#include "notifier_server_internal.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #c); exit(1); } } while (0)
#define EXPECT(call, result) do { errno = EDOM; CHECK((call) == (result)); CHECK(errno == EDOM); } while (0)
_Static_assert(VIREO_NOTIFIER_SERVER_NONE == 0 && VIREO_NOTIFIER_SERVER_INSPECT_NOTIFIER == 1 &&
    VIREO_NOTIFIER_SERVER_REGISTER == 2 && VIREO_NOTIFIER_SERVER_UNREGISTER == 3, "independent stages");
/** 本层调用记录，资源仅借至组结束；不伪造真实内核错误。 */
typedef struct model {
    unsigned inspect_calls, bind_calls, unbind_calls; /**< 实际公开依赖尝试数。 */
    unsigned fail; /**< 1观察、2登记、3注销的模型拒绝，0真实依赖。 */
    int fd; /**< 真实inspect值，验证传参，无所有权。 */
} model_t;
static bool same(vireo_event_loop_handle_t a, vireo_event_loop_handle_t b) {
    return a.loop_id == b.loop_id && a.token == b.token;
}
static size_t fds(void) {
    DIR *d = opendir("/proc/self/fd"); CHECK(d != NULL); size_t n = 0;
    struct dirent *e; while ((e = readdir(d)) != NULL) if (e->d_name[0] != '.') ++n;
    CHECK(closedir(d) == 0); return n;
}
static vireo_tcp_server_t *server(size_t capacity) {
    vireo_tcp_server_options_t const o = {2, 4, 1048576, 16384}; vireo_tcp_server_t *s = NULL;
    if (capacity) EXPECT(vireo_tcp_server_create_with_auxiliary_capacity(&o, capacity, &s, NULL), VIREO_OK);
    else EXPECT(vireo_tcp_server_create(&o, &s, NULL), VIREO_OK);
    return s;
}
static vireo_notifier_t *notifier(void) {
    vireo_notifier_options_t const o = {4096}; vireo_notifier_t *n = NULL;
    EXPECT(vireo_notifier_create(&o, &n, NULL), VIREO_OK); return n;
}
static vireo_result_t inspect(void *ctx, vireo_notifier_t const *n, vireo_notifier_info_t *i) {
    model_t *m = ctx; ++m->inspect_calls; errno = ENOSPC;
    if (m->fail == 1) return VIREO_RESULT_INTERNAL;
    vireo_result_t r = vireo_notifier_inspect(n, i); if (r == VIREO_OK) m->fd = i->fd; return r;
}
static vireo_result_t bind_source(void *ctx, vireo_tcp_server_t *s, int fd,
    vireo_event_loop_handle_t *h, vireo_tcp_server_auxiliary_error_t *e) {
    model_t *m = ctx; ++m->bind_calls; CHECK(fd == m->fd); errno = ENOSPC;
    if (m->fail == 2) { *e = (vireo_tcp_server_auxiliary_error_t){
        VIREO_TCP_SERVER_AUXILIARY_REGISTER, {.stage = VIREO_EVENT_LOOP_STAGE_ADD,
            .epoll_error = {VIREO_EPOLL_STAGE_ADD, ENOMEM}}}; return VIREO_RESULT_IO; }
    return vireo_tcp_server_auxiliary_read_register(s, fd, h, e);
}
static vireo_result_t unbind_source(void *ctx, vireo_tcp_server_t *s,
    vireo_event_loop_handle_t *h, vireo_tcp_server_auxiliary_error_t *e) {
    model_t *m = ctx; ++m->unbind_calls; errno = ENOSPC;
    if (m->fail == 3) { *e = (vireo_tcp_server_auxiliary_error_t){
        VIREO_TCP_SERVER_AUXILIARY_UNREGISTER, {.stage = VIREO_EVENT_LOOP_STAGE_DEL,
            .epoll_error = {VIREO_EPOLL_STAGE_DEL, EIO}}}; return VIREO_RESULT_IO; }
    return vireo_tcp_server_auxiliary_read_unregister(s, h, e);
}
static vireo_notifier_server_ops_t const ops = {inspect, bind_source, unbind_source};
static void pair(void) {
    vireo_tcp_server_t *s = server(2); vireo_notifier_t *n = notifier();
    vireo_event_loop_handle_t h = {0}; vireo_notifier_server_error_t e; memset(&e, 0xa5, sizeof e);
    EXPECT(vireo_notifier_server_register(s, n, &h, &e), VIREO_OK);
    CHECK(h.loop_id && h.token && e.stage == 0 && e.server_error.stage == 0);
    vireo_tcp_server_info_t i; EXPECT(vireo_tcp_server_inspect(s, &i), VIREO_OK);
    CHECK(i.auxiliary_read_bound && i.auxiliary_registration_capacity == 2 && !i.auxiliary_pending_events);
    vireo_event_loop_handle_t old = h, other = {0};
    EXPECT(vireo_notifier_server_register(s, n, &other, &e), VIREO_RESULT_BUSY); CHECK(same(other, (vireo_event_loop_handle_t){0}));
    EXPECT(vireo_notifier_server_unregister(s, &h, &e), VIREO_OK); CHECK(!h.loop_id && !h.token);
    EXPECT(vireo_notifier_server_unregister(s, &old, &e), VIREO_RESULT_NOT_FOUND); CHECK(old.loop_id && old.token);
    EXPECT(vireo_notifier_server_register(s, n, &h, NULL), VIREO_OK); CHECK(!same(h, old));
    EXPECT(vireo_notifier_server_unregister(s, &h, NULL), VIREO_OK);
    EXPECT(vireo_tcp_server_destroy(&s, NULL), VIREO_OK); EXPECT(vireo_notifier_destroy(&n, NULL), VIREO_OK);
}
static void missing_capacity(void) {
    vireo_tcp_server_t *s = server(0); vireo_notifier_t *n = notifier(); vireo_event_loop_handle_t h = {0};
    vireo_notifier_server_error_t e;
    EXPECT(vireo_notifier_server_register(s, n, &h, &e), VIREO_RESULT_NOT_FOUND);
    CHECK(e.stage == VIREO_NOTIFIER_SERVER_REGISTER && e.server_error.stage == VIREO_TCP_SERVER_AUXILIARY_CHECK_BINDING);
    EXPECT(vireo_tcp_server_destroy(&s, NULL), VIREO_OK); EXPECT(vireo_notifier_destroy(&n, NULL), VIREO_OK);
}
static void basic(void) {
    vireo_tcp_server_t *s = server(1); vireo_notifier_t *n = notifier(); model_t m = {0};
    vireo_event_loop_handle_t h = {0}; vireo_notifier_server_error_t e;
    EXPECT(vireo_notifier_server_register_with_ops(NULL, n, &h, &e, &ops, &m), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_notifier_server_register_with_ops(s, NULL, &h, &e, &ops, &m), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_notifier_server_register_with_ops(s, n, NULL, &e, &ops, &m), VIREO_RESULT_INVALID_ARGUMENT);
    h = (vireo_event_loop_handle_t){1, 0};
    EXPECT(vireo_notifier_server_register_with_ops(s, n, &h, &e, &ops, &m), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(same(h, (vireo_event_loop_handle_t){1, 0})); h = (vireo_event_loop_handle_t){0};
    vireo_notifier_server_ops_t bad = ops; bad.bind = NULL;
    EXPECT(vireo_notifier_server_register_with_ops(s, n, &h, &e, &bad, &m), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_notifier_server_unregister_with_ops(s, NULL, &e, &ops, &m), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_notifier_server_unregister_with_ops(NULL, &h, &e, &ops, &m), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_notifier_server_unregister_with_ops(s, &h, &e, NULL, &m), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(!m.inspect_calls && !m.bind_calls && !m.unbind_calls && e.stage == 0 && e.server_error.stage == 0);
    EXPECT(vireo_tcp_server_destroy(&s, NULL), VIREO_OK); EXPECT(vireo_notifier_destroy(&n, NULL), VIREO_OK);
}
static void inspect_failure(void) {
    vireo_tcp_server_t *s = server(1); vireo_notifier_t *n = notifier(); model_t m = {.fail = 1};
    vireo_event_loop_handle_t h = {0}; vireo_notifier_server_error_t e;
    EXPECT(vireo_notifier_server_register_with_ops(s, n, &h, &e, &ops, &m), VIREO_RESULT_INTERNAL);
    CHECK(m.inspect_calls == 1 && !m.bind_calls && !h.token && e.stage == VIREO_NOTIFIER_SERVER_INSPECT_NOTIFIER && !e.server_error.stage);
    EXPECT(vireo_tcp_server_destroy(&s, NULL), VIREO_OK); EXPECT(vireo_notifier_destroy(&n, NULL), VIREO_OK);
}
static void bind_failure(void) {
    vireo_tcp_server_t *s = server(1); vireo_notifier_t *n = notifier(); model_t m = {.fail = 2};
    vireo_event_loop_handle_t h = {0}; vireo_notifier_server_error_t e;
    EXPECT(vireo_notifier_server_register_with_ops(s, n, &h, &e, &ops, &m), VIREO_RESULT_IO);
    CHECK(m.inspect_calls == 1 && m.bind_calls == 1 && !h.token && e.stage == VIREO_NOTIFIER_SERVER_REGISTER &&
        e.server_error.loop_error.epoll_error.system_errno == ENOMEM);
    vireo_tcp_server_info_t i; EXPECT(vireo_tcp_server_inspect(s, &i), VIREO_OK); CHECK(!i.auxiliary_read_bound);
    EXPECT(vireo_tcp_server_destroy(&s, NULL), VIREO_OK); EXPECT(vireo_notifier_destroy(&n, NULL), VIREO_OK);
}
static void unbind_failure(void) {
    vireo_tcp_server_t *s = server(1); vireo_notifier_t *n = notifier(); model_t m = {0};
    vireo_event_loop_handle_t h = {0}; vireo_notifier_server_error_t e;
    EXPECT(vireo_notifier_server_register_with_ops(s, n, &h, &e, &ops, &m), VIREO_OK);
    vireo_event_loop_handle_t old = h; m.fail = 3;
    EXPECT(vireo_notifier_server_unregister_with_ops(s, &h, &e, &ops, &m), VIREO_RESULT_IO);
    CHECK(same(h, old) && m.unbind_calls == 1 && e.stage == VIREO_NOTIFIER_SERVER_UNREGISTER &&
        e.server_error.loop_error.epoll_error.system_errno == EIO);
    vireo_tcp_server_info_t i; EXPECT(vireo_tcp_server_inspect(s, &i), VIREO_OK); CHECK(i.auxiliary_read_bound);
    m.fail = 0; EXPECT(vireo_notifier_server_unregister_with_ops(s, &h, &e, &ops, &m), VIREO_OK);
    EXPECT(vireo_tcp_server_destroy(&s, NULL), VIREO_OK); EXPECT(vireo_notifier_destroy(&n, NULL), VIREO_OK);
}
static void destroy_ends_borrow(void) {
    vireo_tcp_server_t *s = server(1); vireo_notifier_t *n = notifier(); vireo_event_loop_handle_t h = {0};
    EXPECT(vireo_notifier_server_register(s, n, &h, NULL), VIREO_OK);
    vireo_notifier_info_t i; EXPECT(vireo_notifier_inspect(n, &i), VIREO_OK);
    EXPECT(vireo_tcp_server_destroy(&s, NULL), VIREO_OK); CHECK(fcntl(i.fd, F_GETFD) >= 0);
    vireo_notifier_notify_outcome_t outcome; uint64_t count;
    EXPECT(vireo_notifier_notify(n, &outcome, NULL), VIREO_OK); EXPECT(vireo_notifier_consume(n, &count, NULL), VIREO_OK); CHECK(count == 1);
    EXPECT(vireo_notifier_destroy(&n, NULL), VIREO_OK);
}
static void fd_zero(void) {
    pid_t p = fork(); CHECK(p >= 0);
    if (!p) {
        CHECK(close(0) == 0); vireo_notifier_t *n = notifier(); vireo_notifier_info_t i;
        EXPECT(vireo_notifier_inspect(n, &i), VIREO_OK); CHECK(i.fd == 0);
        vireo_tcp_server_t *s = server(1); vireo_event_loop_handle_t h = {0};
        EXPECT(vireo_notifier_server_register(s, n, &h, NULL), VIREO_OK);
        EXPECT(vireo_notifier_server_unregister(s, &h, NULL), VIREO_OK);
        EXPECT(vireo_tcp_server_destroy(&s, NULL), VIREO_OK); EXPECT(vireo_notifier_destroy(&n, NULL), VIREO_OK); _exit(0);
    }
    int status; CHECK(waitpid(p, &status, 0) == p && WIFEXITED(status) && WEXITSTATUS(status) == 0);
}
int main(void) {
    CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL) == 0);
    void (*const cases[])(void) = {pair, missing_capacity, basic, inspect_failure, bind_failure, unbind_failure, destroy_ends_borrow, fd_zero};
    for (size_t k = 0; k < sizeof cases / sizeof cases[0]; ++k) { size_t n = fds(); cases[k](); CHECK(fds() == n); }
    puts("notifier server registration: 8 groups passed"); return 0;
}
