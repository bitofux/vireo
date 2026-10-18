/*
 * PROJECT : VIREO
 * FILE    : test_tcp_server_poll_ready.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-14
 * BRIEF   : 真实等待后的安全窗口、固定FIFO和有界取出前缀
 */
#define _GNU_SOURCE
#include "net/tcp_server_internal.h" /* 仅被测server的故障seam。 */
#include <vireo/net/async_request_head.h>
#include <vireo/net/notifier_server.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <sched.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); abort(); } } while (0)
#define EXPECT(x, y) do { errno = EDOM; vireo_result_t const result_ = (x); CHECK(result_ == (y) && errno == EDOM); } while (0)

/** 全部由测试Reactor拥有；没有把网络资源或server发布给worker。 */
typedef struct fixture {
    vireo_tcp_server_t *server; /**< 唯一资源根owner，销毁前归还全部客户。 */
    vireo_connection_pool_lease_t clients[3]; /**< 当前完整数值租约，不拥有fd。 */
    int peers[3]; /**< 每个已接入客户的对端fd owner。 */
    size_t count; /**< clients/peers有效前缀，最大3。 */
    struct sockaddr_in address; /**< 临时loopback端点，仅main使用。 */
    size_t waits; /**< scheduler实际调用次数，非epoll事件数。 */
    int timeout; /**< 最近一次桥接等待的毫秒参数。 */
    bool wait_io; /**< 只模拟等待无回调的EINTR错误，不发送真实信号。 */
    bool probe; /**< 本次等待内检查同server在途保护。 */
    bool stop_during_wait; /**< 等待桥接先调用公开永久停止，模拟前置观察后的停止。 */
    size_t fail_at; /**< gate拒绝的已取数；SIZE_MAX表示不拒绝。 */
} fixture_t;
/** 唯一worker仅借用独立输入；manager在join后读取普通count。 */
typedef struct execution {
    uint8_t expected[33]; /**< 启动前固定的完整输入副本，生命周期到pool销毁。 */
    size_t count; /**< 只有一个worker写实际非空请求次数；join之后main读取。 */
    pthread_barrier_t entered; /**< 空预热task已被领取，manager确认queue锁已释放。 */
    pthread_barrier_t release; /**< manager在提交后允许预热回调返回；不抢占worker。 */
} execution_t;
static vireo_connection_options_t const connection = {256, 128, 384};
static vireo_connection_flow_options_t const flow = {64, 63, 192, 32, 96};
static vireo_tcp_server_process_options_t const limits = {64, 64};
static vireo_tcp_server_drive_budget_t const drive = {{64, 2}, {1, 64, 64}, {64, 2}};
static bool same(vireo_connection_pool_lease_t a, vireo_connection_pool_lease_t b) {
    return a.pool_id == b.pool_id && a.slot_index == b.slot_index && a.generation == b.generation;
}
static unsigned fd_count(void) {
    DIR *d = opendir("/proc/self/fd"); CHECK(d != NULL); unsigned n = 0; struct dirent *p;
    while ((p = readdir(d)) != NULL) if (p->d_name[0] != '.') ++n;
    CHECK(closedir(d) == 0); return n;
}
static vireo_tcp_server_info_t state(fixture_t *f) {
    vireo_tcp_server_info_t info; EXPECT(vireo_tcp_server_inspect(f->server, &info), VIREO_OK); return info;
}
static vireo_result_t wait_once(void *context, vireo_event_loop_t *loop, int timeout,
    vireo_event_loop_run_info_t *info, vireo_event_loop_error_t *error) {
    fixture_t *f = context; ++f->waits; f->timeout = timeout;
    if (f->probe) {
        vireo_tcp_server_ready_client_t output = {0}, old = output;
        vireo_tcp_server_poll_report_t report;
        EXPECT(vireo_tcp_server_poll_ready_once(f->server, 0, 1, &output, 1, &report), VIREO_RESULT_BUSY);
        CHECK(report.stage == VIREO_TCP_SERVER_POLL_CHECK_SERVER && !report.wait_called);
        CHECK(memcmp(&output, &old, sizeof old) == 0);
        EXPECT(vireo_tcp_server_schedule_client(f->server, f->clients[0], NULL), VIREO_RESULT_BUSY);
        vireo_connection_pool_lease_t lease = f->clients[0];
        EXPECT(vireo_tcp_server_release_client(f->server, &lease, NULL), VIREO_RESULT_BUSY);
        CHECK(same(lease, f->clients[0]));
        vireo_tcp_server_t *owner = f->server;
        EXPECT(vireo_tcp_server_destroy(&owner, NULL), VIREO_RESULT_BUSY); CHECK(owner == f->server);
        CHECK(state(f).scheduling_active);
    }
    if (f->stop_during_wait) EXPECT(vireo_tcp_server_request_stop(f->server, NULL), VIREO_OK);
    if (f->wait_io) {
        *error = (vireo_event_loop_error_t){.stage = VIREO_EVENT_LOOP_STAGE_WAIT,
            .epoll_error = {VIREO_EPOLL_STAGE_WAIT, EINTR}};
        errno = ERANGE; return VIREO_RESULT_IO;
    }
    vireo_result_t const result = vireo_event_loop_run_once(loop, timeout, info, error);
    errno = ERANGE; return result;
}
static int connect_peer(fixture_t *f) {
    int const fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0); CHECK(fd >= 0);
    CHECK(connect(fd, (struct sockaddr *)&f->address, sizeof f->address) == 0); return fd;
}
static void admit(fixture_t *f, int peer) {
    CHECK(f->count < 3); vireo_tcp_server_admit_budget_t const budget = {1, 2}; vireo_tcp_server_admit_info_t info;
    EXPECT(vireo_tcp_server_admit_batch(f->server, &connection, &budget, &f->clients[f->count], 1, &info, NULL), VIREO_OK);
    CHECK(info.admitted_count == 1);
    EXPECT(vireo_tcp_server_client_flow_configure(f->server, f->clients[f->count], &flow, NULL), VIREO_OK);
    f->peers[f->count++] = peer;
}
static void prepare(fixture_t *f, size_t count) {
    *f = (fixture_t){.fail_at = SIZE_MAX};
    vireo_tcp_server_options_t const options = {3, 8, 1048576, 4096};
    vireo_tcp_server_scheduler_ops_t const scheduler = {f, wait_once};
    EXPECT(vireo_tcp_server_create_with_auxiliary_scheduler_ops(&options, 1, &scheduler, &f->server, NULL), VIREO_OK);
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0); CHECK(fd >= 0);
    f->address = (struct sockaddr_in){.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    CHECK(bind(fd, (struct sockaddr *)&f->address, sizeof f->address) == 0 && listen(fd, 4) == 0);
    socklen_t length = sizeof f->address;
    CHECK(getsockname(fd, (struct sockaddr *)&f->address, &length) == 0);
    vireo_acceptor_t *listener = NULL; vireo_acceptor_options_t const options_a = {4096};
    EXPECT(vireo_acceptor_create(&options_a, &fd, &listener, NULL), VIREO_OK);
    EXPECT(vireo_tcp_server_adopt_listener(f->server, &listener, NULL), VIREO_OK);
    for (size_t k = 0; k < count; ++k) admit(f, connect_peer(f));
}
static void finish(fixture_t *f) {
    for (size_t k = 0; k < f->count; ++k) {
        EXPECT(vireo_tcp_server_release_client(f->server, &f->clients[k], NULL), VIREO_OK);
        CHECK(close(f->peers[k]) == 0);
    }
    EXPECT(vireo_tcp_server_destroy(&f->server, NULL), VIREO_OK); CHECK(f->server == NULL);
}
static vireo_tcp_server_poll_report_t poll_clients(fixture_t *f, int timeout, size_t max,
    vireo_tcp_server_ready_client_t *out, size_t cap) {
    vireo_tcp_server_poll_report_t report;
    EXPECT(vireo_tcp_server_poll_ready_once(f->server, timeout, max, out, cap, &report), VIREO_OK);
    CHECK(report.stage == VIREO_TCP_SERVER_POLL_NONE && !state(f).scheduling_active); return report;
}
static void send_all(int fd, uint8_t const *bytes, size_t count) {
    size_t sent = 0; while (sent < count) { ssize_t const n = send(fd, bytes + sent, count - sent, MSG_NOSIGNAL); CHECK(n > 0); sent += (size_t)n; }
}
static void parameters(void) {
    fixture_t f; prepare(&f, 1); EXPECT(vireo_tcp_server_schedule_client(f.server, f.clients[0], NULL), VIREO_OK);
    vireo_tcp_server_ready_client_t out[2], old[2]; memset(out, 0xA5, sizeof out); memcpy(old, out, sizeof old);
    vireo_tcp_server_poll_report_t report;
    EXPECT(vireo_tcp_server_poll_ready_once(NULL, 0, 1, out, 2, &report), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(report.stage == VIREO_TCP_SERVER_POLL_NONE && !report.wait_called);
    EXPECT(vireo_tcp_server_poll_ready_once(f.server, -1, 1, out, 2, &report), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_tcp_server_poll_ready_once(f.server, 0, 0, out, 2, &report), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_tcp_server_poll_ready_once(f.server, 0, 1, out, 0, &report), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_tcp_server_poll_ready_once(f.server, 0, 1, NULL, 2, &report), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_tcp_server_poll_ready_once(f.server, 0, 1, out, 2, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_tcp_server_poll_ready_once(f.server, 0, 65536, out, 2, &report), VIREO_RESULT_RANGE);
    EXPECT(vireo_tcp_server_poll_ready_once(f.server, 0, 1, out, 65536, &report), VIREO_RESULT_RANGE);
    CHECK(memcmp(old, out, sizeof old) == 0 && f.waits == 0 && state(&f).pending_clients == 1);
    report = poll_clients(&f, INT_MAX, 65535, out, 2); CHECK(report.selected_count == 1 && report.effective_timeout_ms == 0);
    CHECK(same(out[0].client, f.clients[0]) && memcmp(&old[1], &out[1], sizeof out[1]) == 0);
    finish(&f);
}
static void fifo_budget(void) {
    fixture_t f; prepare(&f, 3); size_t const order[4] = {2, 0, 1, 0};
    for (size_t k = 0; k < 4; ++k) EXPECT(vireo_tcp_server_schedule_client(f.server, f.clients[order[k]], NULL), VIREO_OK);
    vireo_tcp_server_ready_client_t out[3], old[3]; memset(out, 0xA6, sizeof out); memcpy(old, out, sizeof old);
    vireo_tcp_server_poll_report_t report = poll_clients(&f, 20, 1, out, 3);
    CHECK(report.queued_before_wait == 3 && report.queued_after_wait == 3 && report.selected_count == 1 && report.remaining_count == 2);
    CHECK(same(out[0].client, f.clients[2]) && out[0].events == 0 && f.timeout == 0);
    CHECK(memcmp(&old[1], &out[1], 2 * sizeof out[1]) == 0);
    EXPECT(vireo_tcp_server_schedule_client(f.server, f.clients[2], NULL), VIREO_OK);
    report = poll_clients(&f, 20, 3, out, 1); CHECK(report.selected_count == 1 && same(out[0].client, f.clients[0]));
    report = poll_clients(&f, 20, 3, out, 3);
    CHECK(report.selected_count == 2 && same(out[0].client, f.clients[1]) && same(out[1].client, f.clients[2]));
    CHECK(report.remaining_count == 0);
    report = poll_clients(&f, 0, 3, out, 3); CHECK(report.wait_called && report.selected_count == 0 && report.wait.ready_count == 0);
    finish(&f);
}
static void tcp_events_and_safe_io(void) {
    fixture_t f; prepare(&f, 1);
    EXPECT(vireo_tcp_server_client_flow_disable(f.server, f.clients[0], NULL), VIREO_OK);
    EXPECT(vireo_tcp_server_client_set_interests(f.server, f.clients[0], VIREO_EPOLL_EVENT_READ | VIREO_EPOLL_EVENT_WRITE | VIREO_EPOLL_EVENT_PEER_WRITE_CLOSED, NULL), VIREO_OK);
    uint8_t const data[] = {7, 0, 9}; send_all(f.peers[0], data, sizeof data);
    EXPECT(vireo_tcp_server_schedule_client(f.server, f.clients[0], NULL), VIREO_OK);
    vireo_tcp_server_ready_client_t out[2];
    vireo_tcp_server_poll_report_t report = poll_clients(&f, 1000, 2, out, 2);
    CHECK(report.selected_count == 1 && report.queued_before_wait == 1 && report.queued_after_wait == 1);
    CHECK((out[0].events & (VIREO_EPOLL_EVENT_READ | VIREO_EPOLL_EVENT_WRITE)) == (VIREO_EPOLL_EVENT_READ | VIREO_EPOLL_EVENT_WRITE));
    vireo_tcp_server_client_info_t info;
    EXPECT(vireo_tcp_server_client_inspect(f.server, out[0].client, &info), VIREO_OK);
    CHECK(!info.queued && info.pending_events == 0 && info.connection_info.read_buffer.readable_size == 0);
    vireo_connection_receive_budget_t const budget = {3, 2}; vireo_connection_receive_info_t received;
    EXPECT(vireo_tcp_server_client_receive(f.server, out[0].client, &budget, &received, NULL), VIREO_OK); CHECK(received.received_bytes == 3);
    uint8_t const *bytes; size_t size;
    EXPECT(vireo_tcp_server_client_read_peek(f.server, out[0].client, &bytes, &size, NULL), VIREO_OK);
    CHECK(size == 3 && memcmp(bytes, data, 3) == 0);
    EXPECT(vireo_tcp_server_client_read_consume(f.server, out[0].client, 3, NULL), VIREO_OK);
    EXPECT(vireo_tcp_server_client_write_enqueue(f.server, out[0].client, data, 3, NULL), VIREO_OK);
    vireo_connection_send_budget_t const sb = {3, 2}; vireo_connection_send_info_t sent;
    EXPECT(vireo_tcp_server_client_send(f.server, out[0].client, &sb, &sent, NULL), VIREO_OK); CHECK(sent.sent_bytes == 3);
    struct pollfd peer = {f.peers[0], POLLIN, 0}; CHECK(poll(&peer, 1, 1000) == 1);
    uint8_t echo[3]; CHECK(recv(f.peers[0], echo, 3, MSG_WAITALL) == 3 && memcmp(echo, data, 3) == 0);
    finish(&f);
}
static void listener_and_auxiliary(void) {
    fixture_t f; prepare(&f, 0); EXPECT(vireo_tcp_server_bind_listener(f.server, true, NULL), VIREO_OK);
    vireo_notifier_t *notifier = NULL; vireo_notifier_options_t const options = {4096};
    EXPECT(vireo_notifier_create(&options, &notifier, NULL), VIREO_OK);
    vireo_event_loop_handle_t handle = {0}; EXPECT(vireo_notifier_server_register(f.server, notifier, &handle, NULL), VIREO_OK);
    vireo_notifier_notify_outcome_t outcome; EXPECT(vireo_notifier_notify(notifier, &outcome, NULL), VIREO_OK);
    int const peer = connect_peer(&f); vireo_tcp_server_ready_client_t out;
    vireo_tcp_server_poll_report_t report = poll_clients(&f, 1000, 1, &out, 1);
    CHECK(report.selected_count == 0 && report.wait.ready_count == 2);
    vireo_tcp_server_info_t info = state(&f);
    CHECK(info.connection_count == 0 && (info.listener_last_events & VIREO_EPOLL_EVENT_READ) != 0 && (info.auxiliary_pending_events & VIREO_EPOLL_EVENT_READ) != 0);
    uint64_t count; EXPECT(vireo_notifier_consume(notifier, &count, NULL), VIREO_OK); CHECK(count == 1);
    vireo_tcp_server_auxiliary_event_t ready;
    EXPECT(vireo_tcp_server_auxiliary_read_take_ready(f.server, &ready, NULL), VIREO_OK);
    CHECK(ready.events == VIREO_EPOLL_EVENT_READ && ready.handle.loop_id == handle.loop_id && ready.handle.token == handle.token);
    EXPECT(vireo_tcp_server_auxiliary_read_take_ready(f.server, &ready, NULL), VIREO_RESULT_NOT_FOUND);
    admit(&f, peer); CHECK(state(&f).connection_count == 1);
    EXPECT(vireo_notifier_server_unregister(f.server, &handle, NULL), VIREO_OK);
    EXPECT(vireo_notifier_destroy(&notifier, NULL), VIREO_OK); finish(&f);
}
static void wait_failure(void) {
    fixture_t f; prepare(&f, 1); EXPECT(vireo_tcp_server_schedule_client(f.server, f.clients[0], NULL), VIREO_OK);
    f.wait_io = true; vireo_tcp_server_ready_client_t out, old; memset(&out, 0xAC, sizeof out); memcpy(&old, &out, sizeof out);
    vireo_tcp_server_poll_report_t report;
    EXPECT(vireo_tcp_server_poll_ready_once(f.server, 30, 1, &out, 1, &report), VIREO_RESULT_IO);
    CHECK(report.stage == VIREO_TCP_SERVER_POLL_WAIT && report.wait_called && report.selected_count == 0 && report.remaining_count == 1);
    CHECK(report.loop_error.epoll_error.system_errno == EINTR && report.wait.ready_count == 0);
    CHECK(memcmp(&out, &old, sizeof out) == 0 && !state(&f).scheduling_active);
    f.wait_io = false; report = poll_clients(&f, 0, 1, &out, 1); CHECK(report.selected_count == 1);
    finish(&f);
}
static vireo_result_t queue_gate(void *context, vireo_tcp_server_t const *server,
    vireo_connection_pool_lease_t client, size_t selected) {
    fixture_t *f = context; CHECK(server == f->server && client.pool_id != 0);
    errno = ERANGE; return selected == f->fail_at ? VIREO_RESULT_INTERNAL : VIREO_OK;
}
static void queue_failure_prefix(void) {
    fixture_t f; prepare(&f, 3);
    for (size_t k = 0; k < 3; ++k) EXPECT(vireo_tcp_server_schedule_client(f.server, f.clients[k], NULL), VIREO_OK);
    vireo_tcp_server_ready_client_t out[3], old[3]; memset(out, 0xAD, sizeof out); memcpy(old, out, sizeof old);
    vireo_tcp_server_poll_report_t report; f.fail_at = 0;
    EXPECT(vireo_tcp_server_poll_ready_once_with_gate(f.server, 0, 3, out, 3, &report, queue_gate, &f), VIREO_RESULT_INTERNAL);
    CHECK(report.selected_count == 0 && report.remaining_count == 3 && memcmp(old, out, sizeof old) == 0);
    f.fail_at = 1;
    EXPECT(vireo_tcp_server_poll_ready_once_with_gate(f.server, 0, 3, out, 3, &report, queue_gate, &f), VIREO_RESULT_INTERNAL);
    CHECK(report.stage == VIREO_TCP_SERVER_POLL_QUEUE && report.selected_count == 1 && report.remaining_count == 2);
    CHECK(same(out[0].client, f.clients[0]) && memcmp(&out[1], &old[1], 2 * sizeof out[1]) == 0);
    EXPECT(vireo_tcp_server_schedule_client(f.server, out[0].client, NULL), VIREO_OK);
    report = poll_clients(&f, 0, 3, out, 3); CHECK(report.selected_count == 3);
    CHECK(same(out[0].client, f.clients[1]) && same(out[1].client, f.clients[2]) && same(out[2].client, f.clients[0]));
    finish(&f);
}
static void in_flight(void) {
    fixture_t f; prepare(&f, 1); f.probe = true;
    EXPECT(vireo_tcp_server_schedule_client(f.server, f.clients[0], NULL), VIREO_OK);
    vireo_tcp_server_ready_client_t out; vireo_tcp_server_poll_report_t report = poll_clients(&f, 0, 1, &out, 1);
    CHECK(report.selected_count == 1 && f.waits == 1);
    EXPECT(vireo_tcp_server_schedule_client(f.server, out.client, NULL), VIREO_OK); finish(&f);
}
static vireo_result_t no_request(vireo_connection_frame_view_t const *request, uint8_t *bytes,
    size_t size, vireo_tcp_server_reply_t *reply, void *context) {
    (void)request; (void)bytes; (void)size; (void)reply; (void)context; CHECK(false); return VIREO_RESULT_INTERNAL;
}
static void observer(vireo_tcp_server_t *server, vireo_result_t result,
    vireo_tcp_server_serve_info_t const *info, vireo_tcp_server_turn_result_t const *turns,
    vireo_connection_pool_lease_t const *clients, vireo_tcp_server_serve_error_t const *error, void *context) {
    (void)turns; (void)clients; (void)error; fixture_t *f = context; CHECK(result == VIREO_OK && info->round.turn_count == 1 && server == f->server);
    vireo_tcp_server_ready_client_t out = {0}; vireo_tcp_server_poll_report_t report;
    EXPECT(vireo_tcp_server_poll_ready_once(server, 0, 1, &out, 1, &report), VIREO_RESULT_BUSY);
    CHECK(!report.wait_called); EXPECT(vireo_tcp_server_request_stop(server, NULL), VIREO_OK);
}
static void run_reentry(void) {
    fixture_t f; prepare(&f, 1); EXPECT(vireo_tcp_server_bind_listener(f.server, true, NULL), VIREO_OK);
    vireo_tcp_server_admission_options_t const admission = {connection, flow};
    EXPECT(vireo_tcp_server_admission_configure(f.server, &admission, NULL), VIREO_OK);
    EXPECT(vireo_tcp_server_schedule_client(f.server, f.clients[0], NULL), VIREO_OK);
    vireo_tcp_server_run_options_t const options = {limits, drive, {1}, {1, 2}};
    uint8_t scratch[64]; vireo_tcp_server_turn_result_t turn; vireo_connection_pool_lease_t client = {0};
    EXPECT(vireo_tcp_server_run(f.server, &options, scratch, sizeof scratch, no_request, NULL, &turn, 1, &client, 1, observer, &f, NULL), VIREO_OK);
    finish(&f);
}
static void stopped(void) {
    fixture_t f; prepare(&f, 1); EXPECT(vireo_tcp_server_schedule_client(f.server, f.clients[0], NULL), VIREO_OK);
    EXPECT(vireo_tcp_server_request_stop(f.server, NULL), VIREO_OK);
    vireo_tcp_server_ready_client_t out, old; memset(&out, 0xAE, sizeof out); memcpy(&old, &out, sizeof out);
    vireo_tcp_server_poll_report_t report = poll_clients(&f, 1000, 1, &out, 1);
    CHECK(report.stopped && !report.wait_called && report.selected_count == 0 && report.queued_before_wait == 1 && report.remaining_count == 1 && f.waits == 0);
    CHECK(memcmp(&out, &old, sizeof out) == 0);
    EXPECT(vireo_tcp_server_poll_ready_once(f.server, -1, 1, &out, 1, &report), VIREO_RESULT_INVALID_ARGUMENT);
    finish(&f);
    prepare(&f, 1); f.stop_during_wait = true;
    EXPECT(vireo_tcp_server_schedule_client(f.server, f.clients[0], NULL), VIREO_OK);
    report = poll_clients(&f, 0, 1, &out, 1);
    CHECK(!report.stopped && report.wait_called && report.selected_count == 1 && report.wait.ready_count == 0 && state(&f).stop_requested);
    finish(&f);
}
static void slot_reuse(void) {
    fixture_t f; prepare(&f, 3); /* 占满，归还后唯一空槽必为旧客户槽，不依赖候选分配顺序。 */
    EXPECT(vireo_tcp_server_schedule_client(f.server, f.clients[0], NULL), VIREO_OK);
    vireo_tcp_server_ready_client_t out; (void)poll_clients(&f, 0, 1, &out, 1); vireo_connection_pool_lease_t old = out.client;
    EXPECT(vireo_tcp_server_release_client(f.server, &f.clients[0], NULL), VIREO_OK); CHECK(close(f.peers[0]) == 0);
    f.peers[0] = connect_peer(&f);
    vireo_tcp_server_admit_budget_t const ab = {1, 2}; vireo_tcp_server_admit_info_t ai;
    EXPECT(vireo_tcp_server_admit_batch(f.server, &connection, &ab, &f.clients[0], 1, &ai, NULL), VIREO_OK);
    CHECK(ai.admitted_count == 1);
    EXPECT(vireo_tcp_server_client_flow_configure(f.server, f.clients[0], &flow, NULL), VIREO_OK);
    CHECK(old.pool_id == f.clients[0].pool_id && old.slot_index == f.clients[0].slot_index && old.generation != f.clients[0].generation);
    vireo_connection_receive_budget_t const budget = {64, 2}; vireo_connection_receive_info_t info;
    memset(&info, 0xAF, sizeof info); vireo_connection_receive_info_t saved; memcpy(&saved, &info, sizeof info);
    EXPECT(vireo_tcp_server_client_receive(f.server, old, &budget, &info, NULL), VIREO_RESULT_NOT_FOUND);
    CHECK(memcmp(&info, &saved, sizeof info) == 0);
    EXPECT(vireo_tcp_server_schedule_client(f.server, f.clients[0], NULL), VIREO_OK);
    (void)poll_clients(&f, 0, 1, &out, 1); CHECK(same(out.client, f.clients[0]) && out.events == 0); finish(&f);
}
static vireo_result_t execute(void *context, vireo_task_t const *task) {
    execution_t *execution = context; vireo_task_payload_view_t view;
    EXPECT(vireo_task_borrow_payload(task, &view), VIREO_OK);
    if (view.size == 0) {
        int n = pthread_barrier_wait(&execution->entered); CHECK(n == 0 || n == PTHREAD_BARRIER_SERIAL_THREAD);
        n = pthread_barrier_wait(&execution->release); CHECK(n == 0 || n == PTHREAD_BARRIER_SERIAL_THREAD);
        return VIREO_OK;
    }
    CHECK(view.size == sizeof execution->expected && memcmp(view.data, execution->expected, view.size) == 0);
    ++execution->count; return VIREO_OK;
}
static void safe_async_submit(void) {
    fixture_t f; prepare(&f, 1); execution_t execution = {0};
    CHECK(pthread_barrier_init(&execution.entered, NULL, 2) == 0 && pthread_barrier_init(&execution.release, NULL, 2) == 0);
    vireo_protocol_header_t header = {.command = VIREO_COMMAND_NODE_STAT, .body_len = 1, .sequence = 47};
    execution.expected[32] = 0xA5;
    EXPECT(vireo_protocol_header_encode(&header, execution.expected, 32), VIREO_OK);
    EXPECT(vireo_protocol_frame_crc32c_calculate(execution.expected, 32, execution.expected + 32, 1, &header.crc32c), VIREO_OK);
    EXPECT(vireo_protocol_header_encode(&header, execution.expected, 32), VIREO_OK);
    vireo_inflight_store_t *store = NULL; vireo_inflight_store_options_t const so = {2, 65536};
    EXPECT(vireo_inflight_store_create(&so, &store), VIREO_OK);
    vireo_task_queue_t *tasks = NULL; vireo_task_queue_options_t const qo = {2, 65536};
    EXPECT(vireo_task_queue_create(&qo, &tasks), VIREO_OK); EXPECT(vireo_task_queue_prepare_wait(tasks), VIREO_OK);
    vireo_thread_pool_t *pool = NULL; vireo_thread_pool_options_t const po = {1, 65536};
    EXPECT(vireo_thread_pool_create(&po, &pool), VIREO_OK);
    vireo_thread_pool_configuration_t const config = {tasks, execute, &execution};
    EXPECT(vireo_thread_pool_configure(pool, &config, NULL), VIREO_OK);
    /* 独立纯值预热task不代表真实客户；停驻在回调，排除合法trylock竞争的测试偶然性。 */
    vireo_task_route_t route; vireo_task_metadata_t warm_metadata; vireo_task_t *warm = NULL;
    EXPECT(vireo_task_route_make(UINT64_MAX, 0, 1, 1, &route), VIREO_OK);
    EXPECT(vireo_task_metadata_make(route, 1, 1, UINT64_MAX, &warm_metadata), VIREO_OK);
    EXPECT(vireo_task_create_copy(warm_metadata, NULL, 0, 4096, &warm), VIREO_OK);
    vireo_task_queue_transfer_report_t transfer; EXPECT(vireo_task_queue_try_push(tasks, &warm, &transfer), VIREO_OK);
    vireo_thread_pool_report_t pr; EXPECT(vireo_thread_pool_start(pool, &pr), VIREO_OK); EXPECT(vireo_thread_pool_enable_execution(pool, &pr), VIREO_OK);
    int n = pthread_barrier_wait(&execution.entered); CHECK(n == 0 || n == PTHREAD_BARRIER_SERIAL_THREAD);
    send_all(f.peers[0], execution.expected, sizeof execution.expected);
    vireo_tcp_server_ready_client_t ready; vireo_tcp_server_poll_report_t report = poll_clients(&f, 1000, 1, &ready, 1);
    CHECK(report.selected_count == 1 && (ready.events & VIREO_EPOLL_EVENT_READ) != 0);
    vireo_connection_receive_budget_t const rb = {33, 2}; vireo_connection_receive_info_t ri;
    EXPECT(vireo_tcp_server_client_receive(f.server, ready.client, &rb, &ri, NULL), VIREO_OK); CHECK(ri.received_bytes == 33);
    vireo_async_request_pending_t pending = {0}; vireo_task_t *remaining = NULL; vireo_async_request_head_report_t hr;
    EXPECT(vireo_async_request_submit_read_head(f.server, ready.client, store, pool, 64, 4096, 2, 1, UINT64_MAX, NULL, &pending, &remaining, &hr), VIREO_OK);
    CHECK(hr.submit_report.task_transferred && hr.consume_called && !hr.pending_retained && remaining == NULL);
    n = pthread_barrier_wait(&execution.release); CHECK(n == 0 || n == PTHREAD_BARRIER_SERIAL_THREAD);
    vireo_thread_pool_shutdown_report_t shutdown;
    /* 放行预热worker后，公开close/回收观察允许trylock竞争BUSY；有界重试同DRAIN意图。
     * 不放松任务恰一次/结果/owner/fd断言，也不把BUSY当作已join。 */
    vireo_result_t retired = VIREO_RESULT_BUSY;
    for (unsigned attempt = 0; attempt < 10000 && retired == VIREO_RESULT_BUSY; ++attempt) {
        errno = EDOM;
        retired = vireo_thread_pool_shutdown_and_join(pool, VIREO_TASK_QUEUE_DRAIN, &shutdown);
        CHECK(errno == EDOM);
        if (retired == VIREO_RESULT_BUSY) CHECK(sched_yield() == 0);
    }
    CHECK(retired == VIREO_OK);
    CHECK(execution.count == 1);
    vireo_thread_pool_worker_result_t result; EXPECT(vireo_thread_pool_inspect_worker_result(pool, 0, &result), VIREO_OK); CHECK(result.result == VIREO_OK);
    vireo_task_metadata_t taken;
    EXPECT(vireo_inflight_store_take(store, hr.pending_snapshot.metadata, &taken, NULL), VIREO_OK);
    EXPECT(vireo_thread_pool_destroy(&pool), VIREO_OK); EXPECT(vireo_task_queue_destroy(&tasks), VIREO_OK);
    EXPECT(vireo_inflight_store_destroy(&store), VIREO_OK);
    CHECK(pthread_barrier_destroy(&execution.entered) == 0 && pthread_barrier_destroy(&execution.release) == 0); finish(&f);
}
int main(void) {
    int previous; CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previous) == 0);
    void (*const tests[])(void) = {parameters, fifo_budget, tcp_events_and_safe_io, listener_and_auxiliary,
        wait_failure, queue_failure_prefix, in_flight, run_reentry, stopped, slot_reuse, safe_async_submit};
    for (size_t k = 0; k < sizeof tests / sizeof tests[0]; ++k) {
        unsigned const before = fd_count(); tests[k](); CHECK(fd_count() == before);
    }
    CHECK(pthread_setcancelstate(previous, NULL) == 0);
    puts("tcp_server poll ready: 11 groups, 0 failures"); return EXIT_SUCCESS;
}
