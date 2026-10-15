/*
 * PROJECT : VIREO
 * FILE    : test_async_client_drive.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-14
 * BRIEF   : 真实poll/单客户driver/worker/响应链及本接线层公开故障模型
 */
#define _GNU_SOURCE
#include "net/async_client_drive_internal.h"
#include <vireo/net/completion_response_dispatch.h>
#include <vireo/net/notifier_server.h>
#include <vireo/thread/completion_publish.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); abort(); } } while (0)
#define EXPECT(x, y) do { errno = EDOM; vireo_result_t const result_ = (x); CHECK(result_ == (y) && errno == EDOM); } while (0)
#define LIMIT 1000000U

/** 每项caller保存原输入关联，数字快照不保活客户。 */
typedef struct entry {
    bool valid; /**< 原实际移交后登记；历史记录，不等当前inflight。 */
    vireo_task_metadata_t metadata; /**< 原完整key/operation/deadline。 */
    vireo_protocol_header_t header; /**< driver保存的原wire头，不从operation猜command/handles。 */
    unsigned resolved; /**< 描述回调实际次数，非peer已收到计数。 */
} entry_t;
/** pool长期借用的独立worker上下文，绝无网络fd/server。 */
typedef struct worker {
    vireo_completion_queue_t *outputs; /**< caller拥有的结果队列，借至pool销毁。 */
    vireo_notifier_t *notifier; /**< 借至全部producer结束，提示不等结果数。 */
    pthread_barrier_t entered; /**< 空预热task已领取，会合排除trylock测试偶然性。 */
    pthread_barrier_t release; /**< caller允许预热回调返回，停止不抢占回调。 */
    atomic_uint published; /**< 本次helper返回后发布数量，非join证明。 */
    bool hold_first; /**< 预热释放前固定，仅tag1发布后再会合，验证满表重试时无queue锁竞争。 */
    vireo_completion_publish_report_t reports[9]; /**< 每tag独立写，main仅join后读取。 */
} worker_t;
/** 测试Reactor/串行manager唯一拥有的实际组合。 */
typedef struct world {
    vireo_tcp_server_t *server; /**< 真实TCP资源root owner，预留1辅助项。 */
    vireo_connection_pool_lease_t client; /**< 当前完整租约，归还清零。 */
    int peer; /**< 对端socket owner，-1为空。 */
    struct sockaddr_in address; /**< 临时loopback端点，非全局配置。 */
    vireo_inflight_store_t *store; /**< 固定记录owner，结束后显式清空。 */
    vireo_task_queue_t *tasks; /**< 专用于此pool的queue owner，预热后可试提交。 */
    vireo_thread_pool_t *pool; /**< 固定一个真实worker，管理main串行。 */
    vireo_completion_queue_t *outputs; /**< caller唯一consumer，容量8。 */
    vireo_notifier_t *notifier; /**< eventfd owner，先注销再销毁。 */
    vireo_event_loop_handle_t handle; /**< 完整辅助注册值，非fd owner。 */
    worker_t worker; /**< 原位长期context，pool销毁后结束barrier。 */
    bool released; /**< main已释放预热回调，防第二次会合死锁。 */
    unsigned submitted; /**< 测试已确认真实数据task移交数量，不含预热。 */
    entry_t entries[9]; /**< 原header/key账本，只main修改。 */
    vireo_async_request_pending_t pending; /**< 此完整客户唯一消费gate，main独占。 */
    vireo_task_t *remaining; /**< 未交接task的caller owner，不能丢弃。 */
    vireo_completion_t *remaining_completion; /**< 分发失败返回的caller owner。 */
    uint8_t scratch[64]; /**< 原响应编码scratch，只main使用。 */
} world_t;
/** 只本新driver的公开依赖模型，不修改任何外模块布局。 */
typedef struct fault {
    world_t *world; /**< 短借当前真实组合，只main使用。 */
    unsigned refresh_calls; /**< 本次实际pre/final调用次序。 */
    unsigned inspect_calls; /**< 当前客户观察次数。 */
    unsigned receive_calls; /**< 此边界尝试次数。 */
    unsigned head_calls; /**< 031边界尝试次数。 */
    unsigned send_calls; /**< 此边界尝试次数。 */
    unsigned fail_refresh; /**< 0不拒绝，1预/2末，模拟MOD错误无资源变更。 */
    unsigned fail_inspect; /**< 0不拒绝，1入口/2预刷新后/3最终。 */
    bool receive_io; /**< 接收无进度IO模型。 */
    bool send_io; /**< 发送无进度IO模型。 */
    bool frames_bad; /**< 原view尺寸异常模型，不伪造真实协议包。 */
    bool consume_busy; /**< 真实copy移交后不消费，合法pending保源的BUSY模型。 */
    bool transferred_error; /**< 真实head成功后独立INTERNAL模型，不重发task。 */
    bool active; /**< server有限在途只读快照模型。 */
    bool stop; /**< server永久停止只读快照模型。 */
} fault_t;
static vireo_connection_options_t const connection = {256, 128, 384};
static vireo_connection_flow_options_t const flow = {64, 63, 192, 32, 96};
static vireo_async_client_drive_options_t const options = {64, 4096, 8, 9, UINT64_MAX};
static vireo_async_client_drive_budget_t const budget = {{128, 8}, {128, 8}};
static void meet(pthread_barrier_t *barrier) {
    int const n = pthread_barrier_wait(barrier); CHECK(n == 0 || n == PTHREAD_BARRIER_SERIAL_THREAD);
}
static unsigned fd_count(void) {
    DIR *d = opendir("/proc/self/fd"); CHECK(d != NULL); unsigned n = 0; struct dirent *p;
    while ((p = readdir(d)) != NULL) if (p->d_name[0] != '.') ++n;
    CHECK(closedir(d) == 0); return n;
}
static bool same(vireo_task_metadata_t a, vireo_task_metadata_t b) {
    bool equal; EXPECT(vireo_task_metadata_same_request(a, b, &equal), VIREO_OK);
    return equal && a.operation == b.operation && a.deadline_ns == b.deadline_ns;
}
static vireo_tcp_server_client_info_t client_info(world_t *w) {
    vireo_tcp_server_client_info_t info; EXPECT(vireo_tcp_server_client_inspect(w->server, w->client, &info), VIREO_OK); return info;
}
static vireo_result_t execute(void *context, vireo_task_t const *task) {
    worker_t *worker = context; vireo_task_payload_view_t view;
    EXPECT(vireo_task_borrow_payload(task, &view), VIREO_OK);
    if (view.size == 0) { meet(&worker->entered); meet(&worker->release); return VIREO_OK; }
    CHECK(view.size == 35 && view.data[32] >= 1 && view.data[32] <= 8);
    unsigned const tag = view.data[32]; vireo_protocol_header_t header; vireo_protocol_codec_issue_t issue;
    EXPECT(vireo_protocol_header_decode(view.data, view.size, &header, &issue), VIREO_OK);
    EXPECT(vireo_protocol_request_header_validate(&header, &issue), VIREO_OK);
    EXPECT(vireo_protocol_frame_crc32c_verify(view.data, 32, view.data + 32, 3, &issue), VIREO_OK);
    CHECK(header.sequence == 100 + tag && view.data[33] == 0 && view.data[34] == 0xA5);
    uint8_t bytes[3] = {(uint8_t)(tag ^ 0x5AU), 0x5A, 0xFF}; vireo_completion_t *remaining = NULL;
    EXPECT(vireo_completion_copy_wait_publish(task, VIREO_OK, VIREO_STATUS_OK, bytes, 3, 4096,
        worker->outputs, worker->notifier, &remaining, &worker->reports[tag]), VIREO_OK);
    CHECK(remaining == NULL); (void)atomic_fetch_add_explicit(&worker->published, 1, memory_order_release);
    if (worker->hold_first && tag == 1) { meet(&worker->entered); meet(&worker->release); }
    return VIREO_OK;
}
static void add_client(world_t *w) {
    CHECK(w->peer == -1 && w->client.pool_id == 0);
    w->peer = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0); CHECK(w->peer >= 0);
    CHECK(connect(w->peer, (struct sockaddr *)&w->address, sizeof w->address) == 0);
    vireo_tcp_server_admit_budget_t const b = {1, 2}; vireo_tcp_server_admit_info_t info;
    EXPECT(vireo_tcp_server_admit_batch(w->server, &connection, &b, &w->client, 1, &info, NULL), VIREO_OK); CHECK(info.admitted_count == 1);
    EXPECT(vireo_tcp_server_client_flow_configure(w->server, w->client, &flow, NULL), VIREO_OK);
}
static void prepare(world_t *w, size_t capacity) {
    *w = (world_t){.peer = -1}; atomic_init(&w->worker.published, 0);
    vireo_tcp_server_options_t const so = {1, 4, 1048576, 1024};
    EXPECT(vireo_tcp_server_create_with_auxiliary_capacity(&so, 1, &w->server, NULL), VIREO_OK);
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0); CHECK(fd >= 0);
    w->address = (struct sockaddr_in){.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    CHECK(bind(fd, (struct sockaddr *)&w->address, sizeof w->address) == 0 && listen(fd, 4) == 0);
    socklen_t size = sizeof w->address; CHECK(getsockname(fd, (struct sockaddr *)&w->address, &size) == 0);
    vireo_acceptor_t *listener = NULL; vireo_acceptor_options_t const ao = {4096};
    EXPECT(vireo_acceptor_create(&ao, &fd, &listener, NULL), VIREO_OK);
    EXPECT(vireo_tcp_server_adopt_listener(w->server, &listener, NULL), VIREO_OK); add_client(w);
    vireo_inflight_store_options_t const io = {8, 65536}; EXPECT(vireo_inflight_store_create(&io, &w->store), VIREO_OK);
    vireo_task_queue_options_t const tq = {capacity, 65536}; EXPECT(vireo_task_queue_create(&tq, &w->tasks), VIREO_OK);
    EXPECT(vireo_task_queue_prepare_wait(w->tasks), VIREO_OK);
    vireo_completion_queue_options_t const cq = {8, 65536}; EXPECT(vireo_completion_queue_create(&cq, &w->outputs), VIREO_OK);
    EXPECT(vireo_completion_queue_prepare_wait(w->outputs), VIREO_OK);
    vireo_notifier_options_t const no = {4096}; EXPECT(vireo_notifier_create(&no, &w->notifier, NULL), VIREO_OK);
    EXPECT(vireo_notifier_server_register(w->server, w->notifier, &w->handle, NULL), VIREO_OK);
    w->worker.outputs = w->outputs; w->worker.notifier = w->notifier;
    CHECK(pthread_barrier_init(&w->worker.entered, NULL, 2) == 0 && pthread_barrier_init(&w->worker.release, NULL, 2) == 0);
    vireo_thread_pool_options_t const po = {1, 65536}; EXPECT(vireo_thread_pool_create(&po, &w->pool), VIREO_OK);
    vireo_thread_pool_configuration_t const config = {w->tasks, execute, &w->worker};
    EXPECT(vireo_thread_pool_configure(w->pool, &config, NULL), VIREO_OK);
    /* 独立纯值空输入预热，不假装当前网络客户；保证worker已释queue锁并停在callback。 */
    vireo_task_route_t route; vireo_task_metadata_t metadata; vireo_task_t *warm = NULL;
    EXPECT(vireo_task_route_make(UINT64_MAX, 0, 1, 1, &route), VIREO_OK);
    EXPECT(vireo_task_metadata_make(route, 1, 1, UINT64_MAX, &metadata), VIREO_OK);
    EXPECT(vireo_task_create_copy(metadata, NULL, 0, 4096, &warm), VIREO_OK);
    vireo_task_queue_transfer_report_t qr; EXPECT(vireo_task_queue_try_push(w->tasks, &warm, &qr), VIREO_OK);
    vireo_thread_pool_report_t pr; EXPECT(vireo_thread_pool_start(w->pool, &pr), VIREO_OK);
    EXPECT(vireo_thread_pool_enable_execution(w->pool, &pr), VIREO_OK); meet(&w->worker.entered);
}
static void release_worker(world_t *w) {
    if (!w->released) { meet(&w->worker.release); w->released = true; }
}
static void published(world_t *w) {
    for (size_t i = 0; i < LIMIT; ++i) {
        if (atomic_load_explicit(&w->worker.published, memory_order_acquire) == w->submitted) return;
        sched_yield();
    }
    CHECK(false);
}
/** 仅测试caller恢复关闭锁/回收前观测竞争；实际停止或join错误仍失败。 */
static vireo_result_t shutdown_pool(vireo_thread_pool_t *pool,vireo_thread_pool_shutdown_report_t *report) {
    int const saved=errno;
    for (size_t i=0;i<1000000;++i) {
        vireo_result_t const result=vireo_thread_pool_shutdown_and_join(pool,VIREO_TASK_QUEUE_DRAIN,report);
        bool const close_busy=result==VIREO_RESULT_BUSY && report->stage==VIREO_THREAD_POOL_SHUTDOWN_STAGE_CLOSE_QUEUE &&
            report->close_called && !report->join_called && !report->close_report.changed &&
            report->close_report.stage==VIREO_TASK_QUEUE_STAGE_LOCK && report->close_report.pthread_error==EBUSY;
        bool const inspect_busy=result==VIREO_RESULT_BUSY && report->stage==VIREO_THREAD_POOL_SHUTDOWN_STAGE_JOIN_WORKERS &&
            report->close_called && report->join_called && report->close_report.stage==VIREO_TASK_QUEUE_STAGE_NONE &&
            report->close_report.pthread_error==0 && report->pool_report.stage==VIREO_THREAD_POOL_STAGE_CHECK_QUEUE &&
            !report->pool_report.stop_requested && report->pool_report.joined_count==0 && report->pool_report.pthread_error==0;
        bool const retry=close_busy || inspect_busy;
        if (!retry) {
            if (result!=VIREO_OK) fprintf(stderr,"shutdown result=%d stage=%d close=%d changed=%d lockstage=%d pthread=%d join=%d\n",
                (int)result,(int)report->stage,(int)report->close_called,(int)report->close_report.changed,
                (int)report->close_report.stage,report->close_report.pthread_error,(int)report->join_called);
            errno=saved; return result;
        }
        if (i==0) fputs("test caller: confirmed close/queue-inspect contention before worker stop/join, bounded retry\n",stderr);
        sched_yield();
    }
    errno=saved; return VIREO_RESULT_BUSY;
}
static void finish(world_t *w) {
    if (w->pending.frame_bytes != 0) {
        vireo_async_request_head_report_t report; EXPECT(vireo_async_request_resume_consume(w->server, &w->pending, &report), VIREO_OK);
    }
    EXPECT(vireo_task_destroy(&w->remaining), VIREO_OK); EXPECT(vireo_completion_destroy(&w->remaining_completion), VIREO_OK);
    release_worker(w); published(w); /* 本组至多2结果，8槽保证无满等待；不把published当join。 */
    vireo_thread_pool_shutdown_report_t report;
    EXPECT(shutdown_pool(w->pool, &report), VIREO_OK);
    vireo_thread_pool_worker_result_t wr; EXPECT(vireo_thread_pool_inspect_worker_result(w->pool, 0, &wr), VIREO_OK); CHECK(wr.result == VIREO_OK);
    vireo_completion_queue_close_report_t cr; EXPECT(vireo_completion_queue_close(w->outputs, &cr), VIREO_OK);
    for (;;) {
        vireo_completion_t *result = NULL; vireo_completion_queue_transfer_report_t qr;
        vireo_result_t r = vireo_completion_queue_try_pop(w->outputs, &result, &qr);
        if (r == VIREO_RESULT_CANCELLED) break;
        CHECK(r == VIREO_OK && qr.transferred); EXPECT(vireo_completion_destroy(&result), VIREO_OK);
    }
    for (size_t tag = 1; tag <= 8; ++tag) if (w->entries[tag].valid) {
        vireo_task_metadata_t metadata; vireo_result_t r = vireo_inflight_store_take(w->store, w->entries[tag].metadata, &metadata, NULL);
        CHECK(r == VIREO_OK || r == VIREO_RESULT_NOT_FOUND);
        CHECK(w->worker.reports[tag].completion_transferred && w->worker.reports[tag].notify_called);
    }
    EXPECT(vireo_thread_pool_destroy(&w->pool), VIREO_OK); EXPECT(vireo_task_queue_destroy(&w->tasks), VIREO_OK);
    EXPECT(vireo_completion_queue_destroy(&w->outputs), VIREO_OK); EXPECT(vireo_inflight_store_destroy(&w->store), VIREO_OK);
    EXPECT(vireo_notifier_server_unregister(w->server, &w->handle, NULL), VIREO_OK);
    EXPECT(vireo_notifier_destroy(&w->notifier, NULL), VIREO_OK);
    EXPECT(vireo_tcp_server_release_client(w->server, &w->client, NULL), VIREO_OK);
    CHECK(close(w->peer) == 0); EXPECT(vireo_tcp_server_destroy(&w->server, NULL), VIREO_OK);
    CHECK(pthread_barrier_destroy(&w->worker.entered) == 0 && pthread_barrier_destroy(&w->worker.release) == 0);
}
static vireo_protocol_header_t encode(uint8_t *wire, unsigned tag) {
    vireo_protocol_header_t h = {.command = tag == 2 ? VIREO_COMMAND_UPLOAD_STATUS : VIREO_COMMAND_NODE_STAT,
        .flags = tag == 2 ? VIREO_PROTOCOL_FLAG_LONG_COMMAND : 0, .body_len = 3, .sequence = 100 + tag,
        .session_handle = 0x12340000U + tag, .task_handle = 0x56780000U + tag};
    wire[32] = (uint8_t)tag; wire[33] = 0; wire[34] = 0xA5;
    EXPECT(vireo_protocol_header_encode(&h, wire, 32), VIREO_OK);
    EXPECT(vireo_protocol_frame_crc32c_calculate(wire, 32, wire + 32, 3, &h.crc32c), VIREO_OK);
    EXPECT(vireo_protocol_header_encode(&h, wire, 32), VIREO_OK); return h;
}
static void send_all(world_t *w, uint8_t const *data, size_t size) {
    size_t n = 0; while (n < size) { ssize_t k = send(w->peer, data + n, size - n, MSG_NOSIGNAL); CHECK(k > 0); n += (size_t)k; }
}
static vireo_tcp_server_poll_report_t poll_ready(world_t *w) {
    vireo_tcp_server_ready_client_t ready[1]; vireo_tcp_server_poll_report_t report;
    EXPECT(vireo_tcp_server_poll_ready_once(w->server, 1000, 1, ready, 1, &report), VIREO_OK); return report;
}
static void book(world_t *w, vireo_async_client_drive_report_t report) {
    if (!report.head_report.submit_report.task_transferred) return;
    CHECK(report.request_header_available); unsigned const tag = report.request_header.sequence - 100;
    CHECK(tag >= 1 && tag <= 8 && !w->entries[tag].valid);
    /* 与测试输入的独立预设核对，不能只让响应与driver报告互相证明。 */
    CHECK(report.request_header.command == (tag == 2 ? VIREO_COMMAND_UPLOAD_STATUS : VIREO_COMMAND_NODE_STAT));
    CHECK(report.request_header.flags == (tag == 2 ? VIREO_PROTOCOL_FLAG_LONG_COMMAND : 0));
    CHECK(report.request_header.session_handle == 0x12340000U + tag && report.request_header.task_handle == 0x56780000U + tag);
    CHECK(report.request_header.body_len == 3 && report.head_report.submit_report.metadata.route.request_sequence == 100 + tag);
    w->entries[tag] = (entry_t){true, report.head_report.submit_report.metadata, report.request_header, 0}; ++w->submitted;
}
static vireo_async_client_drive_report_t drive_once(world_t *w, vireo_result_t expected) {
    vireo_async_client_drive_report_t report;
    EXPECT(vireo_async_client_drive_once(w->server, w->client, w->store, w->pool, &options, &budget,
        NULL, &w->pending, &w->remaining, &report), expected); book(w, report); return report;
}
static vireo_result_t resolve(void *context, vireo_completion_t const *completion,
    vireo_inflight_completion_match_t match, vireo_completion_response_descriptor_t *descriptor) {
    world_t *w = context; vireo_completion_info_t info; EXPECT(vireo_completion_inspect(completion, &info), VIREO_OK);
    CHECK(same(info.metadata.request, match.metadata));
    for (size_t tag = 1; tag <= 8; ++tag) if (w->entries[tag].valid && same(w->entries[tag].metadata, match.metadata)) {
        vireo_protocol_header_t const h = w->entries[tag].header; ++w->entries[tag].resolved;
        *descriptor = (vireo_completion_response_descriptor_t){h.command, h.flags, h.session_handle, h.task_handle}; return VIREO_OK;
    }
    CHECK(false); return VIREO_RESULT_NOT_FOUND;
}
static void respond(world_t *w, unsigned count) {
    release_worker(w); published(w); unsigned finished = 0;
    for (size_t i = 0; i < 20 && finished < count; ++i) {
        (void)poll_ready(w); vireo_completion_response_dispatch_report_t report;
        EXPECT(vireo_completion_response_dispatch_ready(w->server, w->handle, w->notifier, w->store, w->outputs,
            1, 64, 64, w->scratch, sizeof w->scratch, resolve, w, &w->remaining_completion, &report), VIREO_OK);
        finished += (unsigned)report.dispatch_report.dispatch_report.drain_report.finished;
    }
    CHECK(finished == count && w->remaining_completion == NULL);
    vireo_async_client_drive_report_t report = drive_once(w, VIREO_OK);
    CHECK(report.send_called && report.send.sent_bytes == (size_t)count * 35 && !report.head_called);
    uint8_t bytes[70]; size_t received = 0;
    for (size_t i = 0; received < (size_t)count * 35 && i < 8; ++i) {
        struct pollfd fd = {w->peer, POLLIN, 0}; CHECK(poll(&fd, 1, 1000) == 1);
        ssize_t n = recv(w->peer, bytes + received, (size_t)count * 35 - received, MSG_DONTWAIT); CHECK(n > 0); received += (size_t)n;
    }
    CHECK(received == (size_t)count * 35);
    for (unsigned k = 0; k < count; ++k) {
        unsigned const tag = k + 1; vireo_protocol_header_t h; vireo_protocol_codec_issue_t issue;
        EXPECT(vireo_protocol_header_decode(bytes + k * 35, 32, &h, &issue), VIREO_OK);
        EXPECT(vireo_protocol_frame_crc32c_verify(bytes + k * 35, 32, bytes + k * 35 + 32, 3, &issue), VIREO_OK);
        vireo_protocol_header_t const original = w->entries[tag].header;
        CHECK(h.command == original.command && h.sequence == original.sequence && h.session_handle == original.session_handle && h.task_handle == original.task_handle);
        CHECK(h.flags == (uint16_t)(original.flags | VIREO_PROTOCOL_FLAG_RESPONSE) && h.status == VIREO_STATUS_OK && h.body_len == 3);
        CHECK(bytes[k * 35 + 32] == (uint8_t)(tag ^ 0x5AU) && bytes[k * 35 + 33] == 0x5A && bytes[k * 35 + 34] == 0xFF && w->entries[tag].resolved == 1);
    }
}
static vireo_result_t model_server(void *context, vireo_tcp_server_t const *s, vireo_tcp_server_info_t *info) {
    fault_t *f = context; vireo_result_t r = vireo_tcp_server_inspect(s, info);
    if (r == VIREO_OK) { if (f->active) info->scheduling_active = true; if (f->stop) info->stop_requested = true; }
    return r;
}
static vireo_result_t model_inspect(void *context, vireo_tcp_server_t const *s,
    vireo_connection_pool_lease_t c, vireo_tcp_server_client_info_t *info) {
    fault_t *f = context; ++f->inspect_calls; errno = ERANGE;
    if (f->fail_inspect == f->inspect_calls) return VIREO_RESULT_IO;
    return vireo_tcp_server_client_inspect(s, c, info);
}
static vireo_result_t model_refresh(void *context, vireo_tcp_server_t *s,
    vireo_connection_pool_lease_t c, vireo_tcp_server_client_error_t *error) {
    fault_t *f = context; ++f->refresh_calls; errno = ERANGE;
    if (f->fail_refresh == f->refresh_calls) {
        *error = (vireo_tcp_server_client_error_t){.primary.stage = VIREO_TCP_SERVER_CLIENT_FLOW_REFRESH,
            .primary.loop_error.loop_error.epoll_error.system_errno = EBADF}; return VIREO_RESULT_IO;
    }
    return vireo_tcp_server_client_flow_refresh(s, c, error);
}
static vireo_result_t model_receive(void *context, vireo_tcp_server_t *s, vireo_connection_pool_lease_t c,
    vireo_connection_receive_budget_t const *b, vireo_connection_receive_info_t *info, vireo_tcp_server_client_error_t *error) {
    fault_t *f = context; ++f->receive_calls; errno = ERANGE;
    if (f->receive_io) {
        *error = (vireo_tcp_server_client_error_t){.primary.stage = VIREO_TCP_SERVER_CLIENT_RECEIVE,
            .primary.connection_error.system_errno = ECONNRESET}; return VIREO_RESULT_IO;
    }
    return vireo_tcp_server_client_receive(s, c, b, info, error);
}
static vireo_result_t model_frames(void *context, vireo_tcp_server_t const *s, vireo_connection_pool_lease_t c,
    vireo_connection_frame_options_t const *o, vireo_connection_frame_budget_t const *b,
    vireo_connection_frame_view_t *views, size_t capacity, vireo_connection_frame_info_t *info, vireo_tcp_server_client_error_t *error) {
    fault_t *f = context;
    vireo_result_t r = vireo_tcp_server_client_frames_peek(s, c, o, b, views, capacity, info, error);
    if (r == VIREO_OK && info->frame_count != 0 && f->frames_bad) views[0].wire_size = o->max_frame_bytes + 1;
    return r;
}
static vireo_result_t model_head(void *context, vireo_tcp_server_t *s, vireo_connection_pool_lease_t c,
    vireo_inflight_store_t *store, vireo_thread_pool_t *pool, size_t cap, size_t allocation, size_t limit,
    uint32_t operation, uint64_t deadline, vireo_task_cancel_t *cancel, vireo_async_request_pending_t *pending,
    vireo_task_t **owner, vireo_async_request_head_report_t *report) {
    fault_t *f = context; ++f->head_calls;
    if (f->consume_busy) {
        /* 模拟031在consume前拒绝：真实公开copy/登记/移交，原读区完全不消费。 */
        vireo_connection_frame_options_t const fo = {VIREO_CONNECTION_FRAME_REQUEST, cap};
        vireo_connection_frame_budget_t const fb = {1, cap}; vireo_connection_frame_view_t view;
        vireo_connection_frame_info_t fi; vireo_tcp_server_client_error_t error;
        CHECK(vireo_tcp_server_client_frames_peek(s, c, &fo, &fb, &view, 1, &fi, &error) == VIREO_OK && fi.frame_count == 1);
        uint8_t const *data; size_t size; CHECK(vireo_tcp_server_client_read_peek(s, c, &data, &size, NULL) == VIREO_OK && size == 35);
        *report = (vireo_async_request_head_report_t){.stage = VIREO_ASYNC_REQUEST_HEAD_CONSUME,
            .frame_peek_called = true, .frame_info = fi, .frame_found = true, .frame_bytes = 35,
            .read_peek_called = true, .submit_called = true};
        report->submit_result = vireo_async_request_copy_try_submit(s, c, store, pool, data, 35, cap,
            allocation, limit, operation, deadline, cancel, owner, &report->submit_report);
        CHECK(report->submit_result == VIREO_OK && report->submit_report.task_transferred);
        *pending = (vireo_async_request_pending_t){report->submit_report.metadata, 35};
        report->pending_committed = true; report->pending_retained = true; report->pending_snapshot = *pending;
        report->consume_called = true; report->consume_result = VIREO_RESULT_BUSY;
        report->consume_error.primary.stage = VIREO_TCP_SERVER_CLIENT_READ_CONSUME;
        errno = ERANGE; return VIREO_RESULT_BUSY;
    }
    vireo_result_t r = vireo_async_request_submit_read_head(s, c, store, pool, cap, allocation, limit,
        operation, deadline, cancel, pending, owner, report);
    if (r == VIREO_OK && f->transferred_error) {
        CHECK(report->submit_report.task_transferred && report->consume_called && report->consume_result == VIREO_OK);
        /* 仅模型诊断：真实owner已交接，模仿队列提交后解锁异常沿公开报告上返。 */
        report->stage = VIREO_ASYNC_REQUEST_HEAD_SUBMIT;
        report->submit_result = VIREO_RESULT_INTERNAL;
        report->submit_report.stage = VIREO_ASYNC_REQUEST_SUBMIT;
        report->submit_report.submit_report.stage = VIREO_INFLIGHT_SUBMIT_SUBMIT_TASK;
        report->submit_report.submit_report.pool_report.stage = VIREO_THREAD_POOL_SUBMIT_STAGE_SUBMIT_QUEUE;
        report->submit_report.submit_report.pool_report.queue_report.stage = VIREO_TASK_QUEUE_STAGE_UNLOCK;
        report->submit_report.submit_report.pool_report.queue_report.pthread_error = EINVAL;
        errno = ERANGE; return VIREO_RESULT_INTERNAL;
    }
    return r;
}
static vireo_result_t model_send(void *context, vireo_tcp_server_t *s, vireo_connection_pool_lease_t c,
    vireo_connection_send_budget_t const *b, vireo_connection_send_info_t *info, vireo_tcp_server_client_error_t *error) {
    fault_t *f = context; ++f->send_calls; errno = ERANGE;
    if (f->send_io) {
        *error = (vireo_tcp_server_client_error_t){.primary.stage = VIREO_TCP_SERVER_CLIENT_SEND,
            .primary.connection_error.system_errno = EPIPE}; return VIREO_RESULT_IO;
    }
    return vireo_tcp_server_client_send(s, c, b, info, error);
}
static vireo_async_client_drive_ops_t const model_ops = {
    model_server, model_inspect, model_refresh, model_receive, model_frames, model_head, model_send
};
static vireo_async_client_drive_report_t model_drive(fault_t *f, vireo_result_t expected) {
    world_t *w = f->world; vireo_async_client_drive_report_t report;
    EXPECT(vireo_async_client_drive_with_ops(w->server, w->client, w->store, w->pool, &options, &budget,
        NULL, &w->pending, &w->remaining, &report, &model_ops, f), expected); book(w, report); return report;
}
static void parameters(void) {
    world_t w; prepare(&w, 8); vireo_async_client_drive_report_t r;
    EXPECT(vireo_async_client_drive_once(NULL, w.client, w.store, w.pool, &options, &budget, NULL, &w.pending, &w.remaining, &r), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_async_client_drive_once(w.server, w.client, w.store, w.pool, &options, &budget, NULL, &w.pending, &w.remaining, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    vireo_async_client_drive_options_t o = options;
    o.operation = 0; EXPECT(vireo_async_client_drive_once(w.server, w.client, w.store, w.pool, &o, &budget, NULL, &w.pending, &w.remaining, &r), VIREO_RESULT_INVALID_ARGUMENT);
    o = options; o.max_frame_bytes = 31;
    EXPECT(vireo_async_client_drive_once(w.server, w.client, w.store, w.pool, &o, &budget, NULL, &w.pending, &w.remaining, &r), VIREO_RESULT_RANGE);
    o = options; o.task_allocation_budget = 67108865;
    EXPECT(vireo_async_client_drive_once(w.server, w.client, w.store, w.pool, &o, &budget, NULL, &w.pending, &w.remaining, &r), VIREO_RESULT_RANGE);
    o = options; o.max_frame_bytes = 65;
    EXPECT(vireo_async_client_drive_once(w.server, w.client, w.store, w.pool, &o, &budget, NULL, &w.pending, &w.remaining, &r), VIREO_RESULT_RANGE);
    vireo_async_client_drive_budget_t b = budget; b.receive.max_syscalls = 0;
    EXPECT(vireo_async_client_drive_once(w.server, w.client, w.store, w.pool, &options, &b, NULL, &w.pending, &w.remaining, &r), VIREO_RESULT_INVALID_ARGUMENT);
    b = budget; b.send.max_bytes = 0;
    EXPECT(vireo_async_client_drive_once(w.server, w.client, w.store, w.pool, &options, &b, NULL, &w.pending, &w.remaining, &r), VIREO_RESULT_INVALID_ARGUMENT);
    fault_t f = {.world = &w}; vireo_async_client_drive_ops_t broken = model_ops; broken.head = NULL;
    EXPECT(vireo_async_client_drive_with_ops(w.server, w.client, w.store, w.pool, &options, &budget, NULL,
        &w.pending, &w.remaining, &r, &broken, &f), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(!r.pre_refresh_called && f.inspect_calls == 0 && client_info(&w).connection_info.read_buffer.readable_size == 0); finish(&w);
}
static void roundtrip(void) {
    world_t w; prepare(&w, 8); uint8_t wire[35]; (void)encode(wire, 1); send_all(&w, wire, 35);
    CHECK(poll_ready(&w).selected_count == 1);
    vireo_async_client_drive_report_t report = drive_once(&w, VIREO_OK);
    CHECK(report.receive.received_bytes == 35 && report.request_header_available && report.head_called && report.pre_refresh_called && report.final_refresh_called && report.final_inspect_called);
    CHECK(report.head_report.submit_report.task_transferred && report.send.sent_bytes == 0 && !report.pending_retained && !report.needs_reschedule);
    memset(wire, 0xDD, sizeof wire); respond(&w, 1); finish(&w);
}
static void sticky_and_reschedule(void) {
    world_t w; prepare(&w, 8); uint8_t wire[70]; (void)encode(wire, 1); (void)encode(wire + 35, 2); send_all(&w, wire, 70);
    CHECK(poll_ready(&w).selected_count == 1);
    vireo_async_client_drive_report_t report = drive_once(&w, VIREO_OK);
    CHECK(report.receive.received_bytes == 70 && w.submitted == 1 && report.needs_reschedule && client_info(&w).connection_info.read_buffer.readable_size == 35);
    CHECK(!client_info(&w).queued); EXPECT(vireo_tcp_server_schedule_client(w.server, w.client, NULL), VIREO_OK);
    vireo_tcp_server_poll_report_t q = poll_ready(&w); CHECK(q.selected_count == 1 && q.effective_timeout_ms == 0);
    report = drive_once(&w, VIREO_OK); CHECK(w.submitted == 2 && !report.needs_reschedule && report.request_header.command == VIREO_COMMAND_UPLOAD_STATUS);
    CHECK(w.entries[1].metadata.request_instance_id != w.entries[2].metadata.request_instance_id);
    respond(&w, 2); finish(&w);
}
static void partial_and_budgets(void) {
    world_t w; prepare(&w, 8); uint8_t wire[35]; (void)encode(wire, 1); send_all(&w, wire, 5);
    CHECK(poll_ready(&w).selected_count == 1);
    vireo_async_client_drive_budget_t b = {{5, 1}, {1, 1}}; vireo_async_client_drive_report_t report;
    EXPECT(vireo_async_client_drive_once(w.server, w.client, w.store, w.pool, &options, &b, NULL, &w.pending, &w.remaining, &report), VIREO_OK);
    CHECK(report.receive.received_bytes == 5 && report.receive.recv_calls == 1 && !report.head_called && !report.needs_reschedule);
    send_all(&w, wire + 5, 30); (void)poll_ready(&w); report = drive_once(&w, VIREO_OK); CHECK(w.submitted == 1 && report.receive.received_bytes == 30);
    uint8_t old[3] = {1, 2, 3}; EXPECT(vireo_tcp_server_client_write_enqueue(w.server, w.client, old, 3, NULL), VIREO_OK);
    EXPECT(vireo_async_client_drive_once(w.server, w.client, w.store, w.pool, &options, &b, NULL, &w.pending, &w.remaining, &report), VIREO_OK);
    CHECK(report.send.sent_bytes == 1 && report.send.send_calls == 1 && client_info(&w).connection_info.write_buffer.readable_size == 2);
    finish(&w);
}
static void eof(void) {
    world_t w; prepare(&w, 8); CHECK(shutdown(w.peer, SHUT_WR) == 0); (void)poll_ready(&w);
    vireo_async_client_drive_report_t report = drive_once(&w, VIREO_OK);
    CHECK(!report.head_called && client_info(&w).connection_info.read_eof && client_info(&w).connection_info.close_state == VIREO_CONNECTION_CLOSE_OPEN);
    report = drive_once(&w, VIREO_OK); CHECK(!report.receive_called && !report.needs_reschedule); finish(&w);
    prepare(&w, 8); uint8_t wire[35]; (void)encode(wire, 1); send_all(&w, wire, 5); CHECK(shutdown(w.peer, SHUT_WR) == 0); (void)poll_ready(&w);
    report = drive_once(&w, VIREO_RESULT_PROTOCOL);
    CHECK(report.stage == VIREO_ASYNC_CLIENT_DRIVE_PEEK_FRAME && !report.head_called && !report.send_called && report.final_refresh_called && client_info(&w).connection_info.read_buffer.readable_size == 5);
    finish(&w);
}
static void pressure(void) {
    world_t w; prepare(&w, 8); uint8_t padding[96] = {0}, wire[35]; (void)encode(wire, 1); send_all(&w, wire, 35);
    EXPECT(vireo_tcp_server_client_write_enqueue(w.server, w.client, padding, 96, NULL), VIREO_OK);
    vireo_async_client_drive_report_t report = drive_once(&w, VIREO_OK);
    CHECK(!report.receive_called && !report.head_called && report.send.sent_bytes == 96 && !client_info(&w).connection_info.write_pressure);
    report = drive_once(&w, VIREO_OK); CHECK(report.receive_called && w.submitted == 1); finish(&w);
    prepare(&w, 8); (void)encode(wire, 1); send_all(&w, wire, 35);
    vireo_connection_receive_budget_t const b = {128, 8}; vireo_connection_receive_info_t ri;
    EXPECT(vireo_tcp_server_client_receive(w.server, w.client, &b, &ri, NULL), VIREO_OK); CHECK(ri.received_bytes == 35);
    EXPECT(vireo_tcp_server_client_write_enqueue(w.server, w.client, padding, 96, NULL), VIREO_OK);
    report = drive_once(&w, VIREO_OK); CHECK(!report.receive_called && report.head_called && report.send.sent_bytes == 96 && w.submitted == 1); finish(&w);
    prepare(&w, 8); uint8_t backlog[210];
    for (unsigned tag = 1; tag <= 6; ++tag) (void)encode(backlog + (tag - 1) * 35, tag);
    send_all(&w, backlog, sizeof backlog);
    vireo_connection_receive_budget_t const bulk = {210, 8};
    EXPECT(vireo_tcp_server_client_receive(w.server, w.client, &bulk, &ri, NULL), VIREO_OK); CHECK(ri.received_bytes == 210);
    report = drive_once(&w, VIREO_OK);
    CHECK(!report.receive_called && report.head_called && report.needs_reschedule && client_info(&w).connection_info.read_pressure);
    CHECK(client_info(&w).connection_info.read_buffer.readable_size == 175 && w.submitted == 1); finish(&w);
}
static void pre_and_post_refresh(void) {
    world_t w; prepare(&w, 8); fault_t f = {.world = &w, .fail_refresh = 1};
    vireo_async_client_drive_report_t report = model_drive(&f, VIREO_RESULT_IO);
    CHECK(report.stage == VIREO_ASYNC_CLIENT_DRIVE_PRE_REFRESH && report.pre_refresh_called && !report.final_refresh_called && f.refresh_calls == 1 && f.receive_calls == 0); finish(&w);
    prepare(&w, 8); uint8_t wire[35]; (void)encode(wire, 1); send_all(&w, wire, 35); f = (fault_t){.world = &w, .fail_refresh = 2};
    report = model_drive(&f, VIREO_RESULT_IO);
    CHECK(report.stage == VIREO_ASYNC_CLIENT_DRIVE_FINAL_REFRESH && report.head_report.submit_report.task_transferred && report.head_report.consume_result == VIREO_OK && !report.pending_retained);
    CHECK(report.final_refresh_result == VIREO_RESULT_IO && !report.final_inspect_called && !report.needs_reschedule && w.submitted == 1);
    report = drive_once(&w, VIREO_OK); CHECK(!report.head_called && w.submitted == 1); finish(&w);
}
static void receive_and_secondary(void) {
    world_t w; prepare(&w, 8); fault_t f = {.world = &w, .receive_io = true, .fail_refresh = 2};
    vireo_async_client_drive_report_t report = model_drive(&f, VIREO_RESULT_IO);
    CHECK(report.stage == VIREO_ASYNC_CLIENT_DRIVE_RECEIVE && !report.frame_peek_called && !report.send_called && report.final_refresh_called);
    CHECK(report.client_error.primary.connection_error.system_errno == ECONNRESET && report.final_refresh_error.primary.loop_error.loop_error.epoll_error.system_errno == EBADF);
    CHECK(report.final_refresh_result == VIREO_RESULT_IO); finish(&w);
}
static void send_and_inspect(void) {
    world_t w; prepare(&w, 8); uint8_t bytes[3] = {1, 2, 3};
    EXPECT(vireo_tcp_server_client_write_enqueue(w.server, w.client, bytes, 3, NULL), VIREO_OK);
    fault_t f = {.world = &w, .send_io = true}; vireo_async_client_drive_report_t report = model_drive(&f, VIREO_RESULT_IO);
    CHECK(report.stage == VIREO_ASYNC_CLIENT_DRIVE_SEND && report.send_called && report.final_refresh_called && client_info(&w).connection_info.write_buffer.readable_size == 3); finish(&w);
    prepare(&w, 8); f = (fault_t){.world = &w, .fail_inspect = 2}; report = model_drive(&f, VIREO_RESULT_IO);
    CHECK(report.stage == VIREO_ASYNC_CLIENT_DRIVE_CHECK_CLIENT && report.final_refresh_called && !report.receive_called); finish(&w);
    prepare(&w, 8); f = (fault_t){.world = &w, .fail_inspect = 3}; report = model_drive(&f, VIREO_RESULT_IO);
    CHECK(report.stage == VIREO_ASYNC_CLIENT_DRIVE_FINAL_INSPECT && report.final_inspect_called && !report.needs_reschedule); finish(&w);
}
static void shape_and_pending(void) {
    world_t w; prepare(&w, 8); uint8_t wire[35]; (void)encode(wire, 1); send_all(&w, wire, 35);
    fault_t f = {.world = &w, .frames_bad = true}; vireo_async_client_drive_report_t report = model_drive(&f, VIREO_RESULT_INTERNAL);
    CHECK(report.stage == VIREO_ASYNC_CLIENT_DRIVE_PEEK_FRAME && !report.request_header_available && !report.head_called && report.final_refresh_called);
    f = (fault_t){.world = &w, .consume_busy = true}; report = model_drive(&f, VIREO_RESULT_BUSY);
    CHECK(report.head_report.submit_report.task_transferred && report.pending_retained && !report.send_called && report.final_refresh_called && w.submitted == 1);
    vireo_async_request_pending_t saved; memcpy(&saved, &w.pending, sizeof saved);
    f = (fault_t){.world = &w}; report = model_drive(&f, VIREO_RESULT_BUSY);
    CHECK(report.stage == VIREO_ASYNC_CLIENT_DRIVE_CHECK_PENDING && report.pending_retained && f.inspect_calls == 0 && f.refresh_calls == 0 && memcmp(&saved, &w.pending, sizeof saved) == 0);
    vireo_async_request_head_report_t recovered; EXPECT(vireo_async_request_resume_consume(w.server, &w.pending, &recovered), VIREO_OK);
    CHECK(!recovered.submit_called && recovered.consume_called && w.pending.frame_bytes == 0);
    report = drive_once(&w, VIREO_OK); CHECK(!report.head_called && w.submitted == 1); finish(&w);
    prepare(&w, 8); w.pending.frame_bytes = 1; f = (fault_t){.world = &w}; report = model_drive(&f, VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(report.stage == VIREO_ASYNC_CLIENT_DRIVE_CHECK_PENDING && f.inspect_calls == 0 && f.refresh_calls == 0 && w.pending.frame_bytes == 1);
    w.pending = (vireo_async_request_pending_t){0}; finish(&w);
}
static void transferred_error(void) {
    world_t w; prepare(&w, 8); uint8_t wire[35]; (void)encode(wire, 1); send_all(&w, wire, 35);
    fault_t f = {.world = &w, .transferred_error = true}; vireo_async_client_drive_report_t report = model_drive(&f, VIREO_RESULT_INTERNAL);
    CHECK(report.stage == VIREO_ASYNC_CLIENT_DRIVE_SUBMIT && report.head_report.submit_report.task_transferred && report.head_report.consume_result == VIREO_OK && !report.pending_retained);
    CHECK(!report.send_called && report.final_refresh_called && w.remaining == NULL && w.submitted == 1);
    CHECK(report.head_report.submit_result == VIREO_RESULT_INTERNAL &&
        report.head_report.submit_report.submit_report.pool_report.queue_report.transferred &&
        report.head_report.submit_report.submit_report.pool_report.queue_report.pthread_error == EINVAL);
    report = drive_once(&w, VIREO_OK); CHECK(!report.head_called && w.submitted == 1); finish(&w);
}
static void stop_state_and_identity(void) {
    world_t w; prepare(&w, 8); fault_t f = {.world = &w, .active = true};
    vireo_async_client_drive_report_t report = model_drive(&f, VIREO_RESULT_BUSY); CHECK(report.stage == VIREO_ASYNC_CLIENT_DRIVE_CHECK_SERVER && !report.pre_refresh_called);
    EXPECT(vireo_tcp_server_request_stop(w.server, NULL), VIREO_OK); report = drive_once(&w, VIREO_RESULT_CANCELLED); CHECK(!report.pre_refresh_called); finish(&w);
    prepare(&w, 8); vireo_connection_pool_lease_t old = w.client;
    EXPECT(vireo_tcp_server_release_client(w.server, &w.client, NULL), VIREO_OK); CHECK(close(w.peer) == 0); w.peer = -1; add_client(&w);
    CHECK(old.pool_id == w.client.pool_id && old.slot_index == w.client.slot_index && old.generation != w.client.generation);
    EXPECT(vireo_async_client_drive_once(w.server, old, w.store, w.pool, &options, &budget, NULL, &w.pending, &w.remaining, &report), VIREO_RESULT_NOT_FOUND);
    CHECK(!report.pre_refresh_called);
    EXPECT(vireo_tcp_server_client_flow_disable(w.server, w.client, NULL), VIREO_OK);
    report = drive_once(&w, VIREO_RESULT_NOT_FOUND); CHECK(!report.pre_refresh_called);
    EXPECT(vireo_tcp_server_client_flow_configure(w.server, w.client, &flow, NULL), VIREO_OK);
    EXPECT(vireo_tcp_server_client_request_close(w.server, w.client, VIREO_CONNECTION_CLOSE_MODE_IMMEDIATE, VIREO_CONNECTION_CLOSE_REASON_APPLICATION, NULL), VIREO_OK);
    report = drive_once(&w, VIREO_RESULT_BUSY); CHECK(!report.pre_refresh_called); finish(&w);
}
static void allocation_limit_and_bad_crc(void) {
    world_t w; prepare(&w, 8); uint8_t wire[35]; (void)encode(wire, 1); send_all(&w, wire, 35);
    vireo_async_client_drive_options_t o = options; o.task_allocation_budget = 1;
    vireo_async_client_drive_report_t report;
    EXPECT(vireo_async_client_drive_once(w.server, w.client, w.store, w.pool, &o, &budget, NULL, &w.pending, &w.remaining, &report), VIREO_RESULT_RANGE);
    CHECK(report.request_header_available && report.head_called && report.head_report.submit_report.metadata_created && !report.head_report.submit_report.task_created);
    CHECK(report.final_refresh_called && w.remaining == NULL && client_info(&w).connection_info.read_buffer.readable_size == 35);
    o = options; o.max_client_requests = 9;
    EXPECT(vireo_async_client_drive_once(w.server, w.client, w.store, w.pool, &o, &budget, NULL, &w.pending, &w.remaining, &report), VIREO_RESULT_RANGE);
    CHECK(w.remaining != NULL && !report.head_report.submit_report.task_transferred && !report.pending_retained);
    EXPECT(vireo_task_destroy(&w.remaining), VIREO_OK); finish(&w);
    prepare(&w, 8); (void)encode(wire, 1); wire[34] ^= 1; send_all(&w, wire, 35);
    report = drive_once(&w, VIREO_RESULT_PROTOCOL); CHECK(!report.head_called && report.final_refresh_called && client_info(&w).connection_info.read_buffer.readable_size == 35); finish(&w);
}
static void queue_full(void) {
    world_t w; prepare(&w, 1); w.worker.hold_first = true; uint8_t wire[35]; (void)encode(wire, 1); send_all(&w, wire, 35); (void)drive_once(&w, VIREO_OK);
    (void)encode(wire, 2); send_all(&w, wire, 35); vireo_async_client_drive_report_t report = drive_once(&w, VIREO_RESULT_BUSY);
    CHECK(report.receive.received_bytes == 35 && !report.head_report.submit_report.task_transferred && !report.head_report.submit_report.submit_report.record_retained && w.remaining != NULL);
    CHECK(!report.pending_retained && !report.send_called && !report.needs_reschedule && client_info(&w).connection_info.read_buffer.readable_size == 35);
    EXPECT(vireo_task_destroy(&w.remaining), VIREO_OK); release_worker(&w); published(&w); meet(&w.worker.entered);
    report = drive_once(&w, VIREO_OK); CHECK(report.head_report.submit_report.task_transferred && w.submitted == 2);
    meet(&w.worker.release); respond(&w, 2); finish(&w);
}
int main(void) {
    int previous; CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previous) == 0);
    void (*const tests[])(void) = {parameters, roundtrip, sticky_and_reschedule, partial_and_budgets,
        eof, pressure, pre_and_post_refresh, receive_and_secondary, send_and_inspect, shape_and_pending,
        transferred_error, stop_state_and_identity, allocation_limit_and_bad_crc, queue_full};
    for (size_t i = 0; i < sizeof tests / sizeof tests[0]; ++i) { unsigned const before = fd_count(); tests[i](); CHECK(fd_count() == before); }
    CHECK(pthread_setcancelstate(previous, NULL) == 0); puts("async client drive: 14 groups, 0 failures"); return EXIT_SUCCESS;
}
