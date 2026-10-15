/*
 * PROJECT : VIREO
 * FILE    : test_async_eof_finish.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-15
 * BRIEF   : EOF缓存异步请求、真实回投和客户范围DRAIN的公开集成验证
 */
#define _GNU_SOURCE
#include <vireo/net/async_client_drive.h>
#include <vireo/net/completion_response.h>
#include <vireo/thread/completion_publish.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); abort(); } } while (0)
#define EXPECT(x, y) do { errno = EDOM; vireo_result_t const result_ = (x); CHECK(result_ == (y) && errno == EDOM); } while (0)
#define LOCK_ATTEMPTS 100000U

/** 固定worker长期短借资源；不含server、客户或网络fd。 */
typedef struct worker {
    vireo_completion_queue_t *outputs; /**< manager拥有的完成队列，借至join。 */
    vireo_notifier_t *notifier; /**< manager拥有的提示源，借至join。 */
    pthread_barrier_t entered; /**< 首任务已领取但尚未产生响应的会合点。 */
    pthread_barrier_t release; /**< Reactor完成缓存提交后才放行首任务。 */
    pthread_barrier_t published_all; /**< 第二项发布后会合，排空时producer不再写队列。 */
    unsigned int seen[2]; /**< 每标签执行次数，仅worker写、join后manager查。 */
    vireo_completion_publish_report_t reports[2]; /**< 每项原回投进度，join后查。 */
} worker_t;
/** Reactor数值账本，不保活客户，不从内部operation猜测wire字段。 */
typedef struct request_entry {
    vireo_task_metadata_t metadata; /**< 真实成功移交后的完整请求身份及期限。 */
    vireo_completion_response_descriptor_t descriptor; /**< 原请求command/flags/session/task快照。 */
} request_entry_t;
/** 测试caller唯一持有所有owner与恢复义务；不是新增生产容器或策略。 */
typedef struct world {
    vireo_tcp_server_t *server; /**< Reactor资源根，销毁前归还客户。 */
    vireo_connection_pool_lease_t client; /**< 唯一当前完整租约，消费后清零。 */
    int peer; /**< 请求端独占fd；SHUT_WR后继续接收。 */
    vireo_inflight_store_t *store; /**< Reactor登记表，销毁前count须为0。 */
    vireo_task_queue_t *tasks; /**< pool专用固定输入队列owner。 */
    vireo_thread_pool_t *pool; /**< 单个真实joinable worker，客户归还后才join。 */
    vireo_completion_queue_t *outputs; /**< 单consumer固定回投队列owner。 */
    vireo_notifier_t *notifier; /**< 仅提示，不用count代表完成项数量。 */
    worker_t worker; /**< 原位同步对象和pool长期借用context。 */
    request_entry_t entries[2]; /**< Reactor保存原请求身份/描述，tag1及tag2。 */
    vireo_async_request_pending_t pending; /**< 同客户唯一消费gate，成功消费清零。 */
    vireo_task_t *remaining_task; /**< 未移交task的显式残留，入口NULL。 */
    vireo_completion_t *remaining; /**< 领取后未销毁completion的唯一owner。 */
    size_t unsettled_responses; /**< 测试账本：已移交但尚未确认enqueue的响应义务。 */
    uint8_t scratch[64]; /**< 编码scratch，不是长期响应存储。 */
    vireo_completion_response_report_t last_response; /**< 同次交付原报告，区分已入队与未入队。 */
} world_t;

static void meet(pthread_barrier_t *barrier) {
    int const result = pthread_barrier_wait(barrier);
    CHECK(result == 0 || result == PTHREAD_BARRIER_SERIAL_THREAD);
}
static bool same(vireo_task_metadata_t a, vireo_task_metadata_t b) {
    bool equal; EXPECT(vireo_task_metadata_same_request(a, b, &equal), VIREO_OK);
    return equal && a.operation == b.operation && a.deadline_ns == b.deadline_ns;
}
static vireo_result_t execute(void *context, vireo_task_t const *task) {
    worker_t *w = context; vireo_task_payload_view_t view;
    EXPECT(vireo_task_borrow_payload(task, &view), VIREO_OK); CHECK(view.size == 35);
    unsigned int const tag = view.data[32]; CHECK(tag == 1 || tag == 2); CHECK(w->seen[tag - 1]++ == 0);
    if (tag == 1) { meet(&w->entered); meet(&w->release); }
    vireo_protocol_header_t header; vireo_protocol_codec_issue_t issue;
    EXPECT(vireo_protocol_header_decode(view.data, view.size, &header, &issue), VIREO_OK);
    EXPECT(vireo_protocol_request_header_validate(&header, &issue), VIREO_OK);
    EXPECT(vireo_protocol_frame_crc32c_verify(view.data, 32, view.data + 32, 3, &issue), VIREO_OK);
    CHECK(header.body_len == 3 && header.sequence == 100U + tag && view.data[33] == 0 && view.data[34] == 0xA5);
    uint8_t const response[3] = {(uint8_t)(tag ^ 0x5A), 0x5A, 0xFF};
    vireo_completion_t *remaining = NULL;
    EXPECT(vireo_completion_copy_wait_publish(task, VIREO_OK, VIREO_STATUS_OK,
        response, sizeof response, 4096, w->outputs, w->notifier, &remaining, &w->reports[tag - 1]), VIREO_OK);
    CHECK(remaining == NULL);
    if (tag == 2) meet(&w->published_all);
    return VIREO_OK;
}
static void prepare(world_t *w, size_t write_capacity) {
    *w = (world_t){.peer = -1};
    vireo_tcp_server_options_t const so = {1, 2, 1048576, 1024};
    EXPECT(vireo_tcp_server_create(&so, &w->server, NULL), VIREO_OK);
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0); CHECK(fd >= 0);
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    CHECK(bind(fd, (struct sockaddr *)&address, sizeof address) == 0 && listen(fd, 4) == 0);
    socklen_t length = sizeof address; CHECK(getsockname(fd, (struct sockaddr *)&address, &length) == 0);
    vireo_acceptor_t *listener = NULL; vireo_acceptor_options_t const ao = {4096};
    EXPECT(vireo_acceptor_create(&ao, &fd, &listener, NULL), VIREO_OK);
    EXPECT(vireo_tcp_server_adopt_listener(w->server, &listener, NULL), VIREO_OK);
    w->peer = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0); CHECK(w->peer >= 0);
    CHECK(connect(w->peer, (struct sockaddr *)&address, sizeof address) == 0);
    vireo_connection_options_t const connection = {128, write_capacity, 256};
    vireo_tcp_server_admit_budget_t const ab = {1, 2}; vireo_tcp_server_admit_info_t admitted;
    EXPECT(vireo_tcp_server_admit_batch(w->server, &connection, &ab, &w->client, 1, &admitted, NULL), VIREO_OK);
    CHECK(admitted.admitted_count == 1);
    vireo_connection_flow_options_t const flow = {64, 63, 128, 0, write_capacity};
    EXPECT(vireo_tcp_server_client_flow_configure(w->server, w->client, &flow, NULL), VIREO_OK);
    vireo_inflight_store_options_t const io = {2, 65536};
    vireo_task_queue_options_t const tq = {2, 65536}; vireo_completion_queue_options_t const cq = {2, 65536};
    vireo_notifier_options_t const no = {4096}; vireo_thread_pool_options_t const po = {1, 65536};
    EXPECT(vireo_inflight_store_create(&io, &w->store), VIREO_OK);
    EXPECT(vireo_task_queue_create(&tq, &w->tasks), VIREO_OK); EXPECT(vireo_task_queue_prepare_wait(w->tasks), VIREO_OK);
    EXPECT(vireo_completion_queue_create(&cq, &w->outputs), VIREO_OK); EXPECT(vireo_completion_queue_prepare_wait(w->outputs), VIREO_OK);
    EXPECT(vireo_notifier_create(&no, &w->notifier, NULL), VIREO_OK);
    w->worker.outputs = w->outputs; w->worker.notifier = w->notifier;
    CHECK(pthread_barrier_init(&w->worker.entered, NULL, 2) == 0);
    CHECK(pthread_barrier_init(&w->worker.release, NULL, 2) == 0);
    CHECK(pthread_barrier_init(&w->worker.published_all, NULL, 2) == 0);
    EXPECT(vireo_thread_pool_create(&po, &w->pool), VIREO_OK);
    vireo_thread_pool_configuration_t const configuration = {w->tasks, execute, &w->worker};
    EXPECT(vireo_thread_pool_configure(w->pool, &configuration, NULL), VIREO_OK);
    vireo_thread_pool_report_t report; EXPECT(vireo_thread_pool_start(w->pool, &report), VIREO_OK);
    /* 先装配/启动停驻线程；首项提交前放行，真实竞争仅由caller查报告恢复。 */
    EXPECT(vireo_thread_pool_enable_execution(w->pool, &report), VIREO_OK);
}
static void encode(uint8_t *wire, unsigned int tag) {
    vireo_protocol_header_t header = {.command = VIREO_COMMAND_NODE_STAT,
      .body_len = 3, .sequence = 100U + tag, .session_handle = 200U + tag, .task_handle = 300U + tag};
    wire[32] = (uint8_t)tag; wire[33] = 0; wire[34] = 0xA5;
    EXPECT(vireo_protocol_header_encode(&header, wire, 32), VIREO_OK);
    EXPECT(vireo_protocol_frame_crc32c_calculate(wire, 32, wire + 32, 3, &header.crc32c), VIREO_OK);
    EXPECT(vireo_protocol_header_encode(&header, wire, 32), VIREO_OK);
}
static vireo_connection_info_t inspect(world_t *w) {
    vireo_tcp_server_client_info_t info; EXPECT(vireo_tcp_server_client_inspect(w->server, w->client, &info), VIREO_OK);
    return info.connection_info;
}
static size_t records(world_t *w) {
    size_t count; EXPECT(vireo_inflight_store_count_client(w->store, w->client, &count, NULL), VIREO_OK); return count;
}
/** 测试caller条件，不是生产API；登记清零之外还检查其唯一外部义务。 */
static bool can_drain(world_t *w) {
    vireo_connection_info_t const info = inspect(w);
    return info.read_eof && info.read_buffer.readable_size == 0 && records(w) == 0 &&
      w->pending.frame_bytes == 0 && !w->remaining_task && !w->remaining && w->unsettled_responses == 0;
}
static void half_close(world_t *w, bool with_requests) {
    if (with_requests) {
        uint8_t wire[70]; encode(wire, 1); encode(wire + 35, 2);
        size_t sent = 0;
        while (sent < sizeof wire) { ssize_t n = send(w->peer, wire + sent, sizeof wire - sent, MSG_NOSIGNAL); CHECK(n > 0); sent += (size_t)n; }
    }
    CHECK(shutdown(w->peer, SHUT_WR) == 0);
    for (size_t i = 0; i < 8; ++i) {
        vireo_tcp_server_ready_client_t ready[1]; vireo_tcp_server_poll_report_t poll_report;
        EXPECT(vireo_tcp_server_poll_ready_once(w->server, 1000, 1, ready, 1, &poll_report), VIREO_OK);
        vireo_connection_receive_budget_t const budget = {128, 8}; vireo_connection_receive_info_t received;
        EXPECT(vireo_tcp_server_client_receive(w->server, w->client, &budget, &received, NULL), VIREO_OK);
        vireo_connection_info_t const info = inspect(w);
        if (info.read_eof) {
            CHECK(info.read_buffer.readable_size == (with_requests ? 70U : 0U));
            CHECK(info.close_state == VIREO_CONNECTION_CLOSE_OPEN); return;
        }
    }
    CHECK(false);
}
static void submit_cached(world_t *w, unsigned int tag) {
    vireo_async_client_drive_options_t const options = {64, 4096, 2, 9, UINT64_MAX};
    vireo_async_client_drive_budget_t const budget = {{128, 8}, {7, 1}};
    for (size_t i = 0; i < LOCK_ATTEMPTS; ++i) {
        vireo_async_client_drive_report_t report; errno = EDOM;
        vireo_result_t const result = vireo_async_client_drive_once(w->server, w->client, w->store, w->pool,
          &options, &budget, NULL, &w->pending, &w->remaining_task, &report); CHECK(errno == EDOM);
        CHECK(!report.receive_called && report.request_header_available && report.request_header.sequence == 100U + tag);
        if (result == VIREO_OK) {
            CHECK(report.head_report.submit_report.task_transferred && report.head_report.consume_called &&
              report.head_report.consume_result == VIREO_OK && !w->remaining_task && !report.pending_retained);
            w->entries[tag - 1] = (request_entry_t){report.head_report.submit_report.metadata,
              {report.request_header.command, report.request_header.flags, report.request_header.session_handle, report.request_header.task_handle}};
            ++w->unsettled_responses; CHECK(report.needs_reschedule == (tag == 1)); return;
        }
        /* 唯一可恢复预提交竞争；检查未转移/已退款，显式销毁本次task副本再试同源。 */
        vireo_inflight_submit_report_t const submission = report.head_report.submit_report.submit_report;
        CHECK(result == VIREO_RESULT_BUSY && submission.submit_called && !submission.record_retained &&
          submission.pool_report.queue_called && !submission.pool_report.queue_report.transferred &&
          submission.pool_report.queue_report.stage == VIREO_TASK_QUEUE_STAGE_LOCK &&
          submission.pool_report.queue_report.pthread_error == EBUSY && !report.head_report.consume_called && w->pending.frame_bytes == 0);
        EXPECT(vireo_task_destroy(&w->remaining_task), VIREO_OK); sched_yield();
    }
    CHECK(false);
}
static vireo_result_t deliver(void *context, vireo_completion_t const *completion, vireo_inflight_completion_match_t match) {
    world_t *w = context; unsigned int const tag = match.metadata.route.request_sequence - 100U;
    CHECK(tag == 1 || tag == 2); CHECK(same(match.metadata, w->entries[tag - 1].metadata));
    vireo_result_t const result = vireo_completion_response_enqueue(w->server, completion, match,
      w->entries[tag - 1].descriptor, 64, w->scratch, sizeof w->scratch, &w->last_response);
    if (w->last_response.enqueued) { CHECK(w->unsettled_responses > 0); --w->unsettled_responses; }
    return result;
}
static vireo_inflight_completion_consume_report_t consume(world_t *w, vireo_result_t expected) {
    vireo_completion_queue_transfer_report_t transfer;
    EXPECT(vireo_completion_queue_try_pop(w->outputs, &w->remaining, &transfer), VIREO_OK); CHECK(transfer.transferred);
    vireo_inflight_completion_consume_report_t report;
    EXPECT(vireo_inflight_store_consume_completion(w->store, w->server, &w->remaining, deliver, w, &report), expected);
    CHECK(report.record_consumed && report.delivery_called); return report;
}
static void send_existing(world_t *w) {
    vireo_connection_send_budget_t const budget = {7, 1}; vireo_connection_send_info_t report;
    EXPECT(vireo_tcp_server_client_send(w->server, w->client, &budget, &report, NULL), VIREO_OK);
    CHECK(report.sent_bytes > 0 && report.sent_bytes <= 7 && report.send_calls <= 1);
}
static void verify_peer(world_t *w, bool with_requests) {
    uint8_t wire[70]; size_t const wanted = with_requests ? sizeof wire : 0; size_t received = 0;
    for (size_t i = 0; received < wanted && i < 8; ++i) {
        struct pollfd p = {.fd = w->peer, .events = POLLIN}; CHECK(poll(&p, 1, 1000) == 1);
        ssize_t n = recv(w->peer, wire + received, wanted - received, MSG_DONTWAIT); CHECK(n > 0); received += (size_t)n;
    }
    CHECK(received == wanted);
    for (unsigned int tag = 1; with_requests && tag <= 2; ++tag) {
        uint8_t const *frame = wire + (tag - 1) * 35; vireo_protocol_header_t header; vireo_protocol_codec_issue_t issue;
        EXPECT(vireo_protocol_header_decode(frame, 35, &header, &issue), VIREO_OK);
        EXPECT(vireo_protocol_response_header_validate(&header, &issue), VIREO_OK);
        EXPECT(vireo_protocol_frame_crc32c_verify(frame, 32, frame + 32, 3, &issue), VIREO_OK);
        CHECK(header.command == VIREO_COMMAND_NODE_STAT && header.flags == VIREO_PROTOCOL_FLAG_RESPONSE &&
          header.status == VIREO_STATUS_OK && header.body_len == 3 && header.sequence == 100U + tag &&
          header.session_handle == 200U + tag && header.task_handle == 300U + tag);
        uint8_t const expected[2][3] = {{0x5B, 0x5A, 0xFF}, {0x58, 0x5A, 0xFF}};
        CHECK(!memcmp(frame + 32, expected[tag - 1], 3));
    }
    /* READY本身不关闭fd，且无多余响应；实际release才收到最终EOF。 */
    uint8_t extra; CHECK(recv(w->peer, &extra, 1, MSG_DONTWAIT) == -1 && (errno == EAGAIN || errno == EWOULDBLOCK));
}
static void finish_client(world_t *w, bool with_requests) {
    CHECK(can_drain(w)); size_t const queued = inspect(w).write_buffer.readable_size;
    EXPECT(vireo_tcp_server_client_request_close(w->server, w->client, VIREO_CONNECTION_CLOSE_MODE_DRAIN,
      VIREO_CONNECTION_CLOSE_REASON_PEER_EOF, NULL), VIREO_OK);
    CHECK(inspect(w).close_state == (queued ? VIREO_CONNECTION_CLOSE_DRAINING : VIREO_CONNECTION_CLOSE_READY));
    size_t sent = 0;
    for (size_t i = 0; inspect(w).write_buffer.readable_size != 0 && i < 16; ++i) {
        CHECK(inspect(w).close_state == VIREO_CONNECTION_CLOSE_DRAINING);
        size_t const before = inspect(w).write_buffer.readable_size; send_existing(w);
        sent += before - inspect(w).write_buffer.readable_size;
        EXPECT(vireo_tcp_server_client_close_refresh(w->server, w->client, NULL), VIREO_OK);
        vireo_connection_info_t const info = inspect(w);
        CHECK(info.close_state == (info.write_buffer.readable_size ? VIREO_CONNECTION_CLOSE_DRAINING : VIREO_CONNECTION_CLOSE_READY));
    }
    vireo_connection_info_t const info = inspect(w);
    CHECK(sent == queued && info.write_buffer.readable_size == 0 && info.close_state == VIREO_CONNECTION_CLOSE_READY &&
      info.close_reason == VIREO_CONNECTION_CLOSE_REASON_PEER_EOF && info.loop_interests == 0);
    verify_peer(w, with_requests);
    vireo_thread_pool_info_t pool_info; EXPECT(vireo_thread_pool_inspect(w->pool, &pool_info), VIREO_OK);
    CHECK(pool_info.joined_count == 0 && !pool_info.stop_requested); /* 客户收尾先于全局join。 */
    vireo_connection_pool_lease_t const old = w->client;
    EXPECT(vireo_tcp_server_release_client(w->server, &w->client, NULL), VIREO_OK);
    CHECK(w->client.pool_id == 0 && w->client.slot_index == 0 && w->client.generation == 0);
    vireo_tcp_server_client_info_t snapshot;
    EXPECT(vireo_tcp_server_client_inspect(w->server, old, &snapshot), VIREO_RESULT_NOT_FOUND);
    struct pollfd p = {.fd = w->peer, .events = POLLIN}; CHECK(poll(&p, 1, 1000) == 1);
    uint8_t extra; CHECK(recv(w->peer, &extra, 1, MSG_DONTWAIT) == 0);
}
static void cleanup(world_t *w, bool with_requests) {
    CHECK(w->client.pool_id == 0 && !w->remaining && !w->remaining_task && w->pending.frame_bytes == 0);
    bool closed = false;
    for (size_t i = 0; i < LOCK_ATTEMPTS; ++i) {
        vireo_task_queue_close_report_t report; errno = EDOM;
        vireo_result_t const result = vireo_task_queue_close(w->tasks, VIREO_TASK_QUEUE_DRAIN, &report); CHECK(errno == EDOM);
        if (result == VIREO_OK) { closed = true; break; }
        CHECK(result == VIREO_RESULT_BUSY && !report.changed && report.stage == VIREO_TASK_QUEUE_STAGE_LOCK && report.pthread_error == EBUSY);
        sched_yield();
    }
    CHECK(closed); bool joined = false;
    for (size_t i = 0; i < LOCK_ATTEMPTS; ++i) {
        vireo_thread_pool_report_t report; errno = EDOM;
        vireo_result_t const result = vireo_thread_pool_stop_and_join(w->pool, &report); CHECK(errno == EDOM);
        if (result == VIREO_OK) { CHECK(report.joined_count == 1); joined = true; break; }
        CHECK(result == VIREO_RESULT_BUSY && report.stage == VIREO_THREAD_POOL_STAGE_CHECK_QUEUE &&
          !report.stop_requested && report.joined_count == 0 && report.pthread_error == 0); sched_yield();
    }
    CHECK(joined);
    vireo_thread_pool_worker_result_t worker_result;
    EXPECT(vireo_thread_pool_inspect_worker_result(w->pool, 0, &worker_result), VIREO_OK);
    CHECK(worker_result.result == VIREO_OK && worker_result.pthread_error == 0);
    for (size_t i = 0; i < 2; ++i) {
        CHECK(w->worker.seen[i] == (with_requests ? 1U : 0U));
        if (with_requests) CHECK(w->worker.reports[i].completion_transferred && w->worker.reports[i].notify_called &&
          same(w->worker.reports[i].request_metadata, w->entries[i].metadata));
    }
    /* 全局资源销毁另需join后的最后drain；不是前面客户DRAIN的门槛。 */
    uint64_t hints; EXPECT(vireo_notifier_consume(w->notifier, &hints, NULL), VIREO_OK);
    vireo_completion_queue_close_report_t cr; EXPECT(vireo_completion_queue_close(w->outputs, &cr), VIREO_OK);
    vireo_completion_t *owner = NULL; vireo_completion_queue_transfer_report_t qr;
    EXPECT(vireo_completion_queue_try_pop(w->outputs, &owner, &qr), VIREO_RESULT_CANCELLED); CHECK(!owner && !qr.transferred);
    EXPECT(vireo_thread_pool_destroy(&w->pool), VIREO_OK); EXPECT(vireo_task_queue_destroy(&w->tasks), VIREO_OK);
    CHECK(pthread_barrier_destroy(&w->worker.entered) == 0);
    CHECK(pthread_barrier_destroy(&w->worker.release) == 0);
    CHECK(pthread_barrier_destroy(&w->worker.published_all) == 0);
    EXPECT(vireo_completion_queue_destroy(&w->outputs), VIREO_OK); EXPECT(vireo_notifier_destroy(&w->notifier, NULL), VIREO_OK);
    EXPECT(vireo_inflight_store_destroy(&w->store), VIREO_OK); EXPECT(vireo_tcp_server_destroy(&w->server, NULL), VIREO_OK);
    CHECK(close(w->peer) == 0);
}
static void responses_after_eof(bool full) {
    world_t w; prepare(&w, full ? 64U : 128U); half_close(&w, true); CHECK(!can_drain(&w));
    submit_cached(&w, 1); meet(&w.worker.entered);
    CHECK(records(&w) == 1 && inspect(&w).read_buffer.readable_size == 35 && !can_drain(&w));
    submit_cached(&w, 2);
    CHECK(records(&w) == 2 && inspect(&w).read_buffer.readable_size == 0 && !can_drain(&w));
    CHECK(inspect(&w).close_state == VIREO_CONNECTION_CLOSE_OPEN);
    meet(&w.worker.release); meet(&w.worker.published_all);
    uint64_t hints; EXPECT(vireo_notifier_consume(w.notifier, &hints, NULL), VIREO_OK); CHECK(hints == 2);
    (void)consume(&w, VIREO_OK); CHECK(records(&w) == 1 && !can_drain(&w));
    if (full) {
        vireo_inflight_completion_consume_report_t const report = consume(&w, VIREO_RESULT_BUSY);
        CHECK(records(&w) == 0 && w.remaining && w.unsettled_responses == 1 && !w.last_response.enqueued &&
          w.last_response.stage == VIREO_COMPLETION_RESPONSE_ENQUEUE && !can_drain(&w));
        CHECK(inspect(&w).close_state == VIREO_CONNECTION_CLOSE_OPEN);
        for (size_t i = 0; i < 5; ++i) send_existing(&w);
        CHECK(inspect(&w).write_buffer.readable_size == 0);
        EXPECT(vireo_tcp_server_client_flow_refresh(w.server, w.client, NULL), VIREO_OK);
        /* 原登记已结束：直接用同项match重做确认未入队响应，禁止再次consume。 */
        EXPECT(deliver(&w, w.remaining, report.match), VIREO_OK); CHECK(w.last_response.enqueued);
        CHECK(!can_drain(&w)); EXPECT(vireo_completion_destroy(&w.remaining), VIREO_OK);
    } else (void)consume(&w, VIREO_OK);
    CHECK(records(&w) == 0 && w.unsettled_responses == 0 && !w.remaining && can_drain(&w));
    finish_client(&w, true); cleanup(&w, true);
}
static void empty_eof(void) {
    world_t w; prepare(&w, 64); half_close(&w, false); CHECK(can_drain(&w));
    finish_client(&w, false); cleanup(&w, false);
}
static size_t fds(void) {
    DIR *directory = opendir("/proc/self/fd"); CHECK(directory); size_t count = 0; struct dirent *entry;
    while ((entry = readdir(directory)) != NULL) if (entry->d_name[0] != '.') ++count;
    CHECK(closedir(directory) == 0); return count;
}
int main(void) {
    int old_state; CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &old_state) == 0);
    for (size_t i = 0; i < 3; ++i) {
        size_t const before = fds(); if (i == 2) empty_eof(); else responses_after_eof(i == 1);
        CHECK(fds() == before);
    }
    puts("async EOF finish: 3 groups passed"); return 0;
}
