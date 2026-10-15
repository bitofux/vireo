/*
 * PROJECT : VIREO
 * FILE    : test_async_shutdown.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-15
 * BRIEF   : 公开停机、历史客户清退、独占管理join与迟到完成的配对销毁
 */
#define _GNU_SOURCE
#include <vireo/net/async_client_termination.h>
#include <vireo/net/inflight_submit.h>
#include <vireo/net/notifier_completion.h>
#include <vireo/net/notifier_loop.h>
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
#define LOCK_ATTEMPTS 100000U

/** worker只借线程资源，不持有server、连接、store或fd。 */
typedef struct worker_context {
    vireo_completion_queue_t *outputs; /**< 唯一owner在fixture，借至全部worker join。 */
    vireo_notifier_t *notifier; /**< 回投后提示，借至全部worker join。 */
    size_t active_count; /**< 启动前固定的实际执行标签数，0..2。 */
    pthread_barrier_t entered; /**< active全部已领取、尚未产生完成项。 */
    pthread_barrier_t release; /**< 清退客户/登记/pending后才放行协作返回。 */
    unsigned int seen[4]; /**< 不同任务独立元素写，join后main读取。 */
    vireo_completion_publish_report_t reports[2]; /**< active每项原回投进度，join后读取。 */
} worker_context_t;
/** 管理权从main独占移交，本线程不访问网络资源或完成队列。 */
typedef struct manager_context {
    vireo_thread_pool_t *pool; /**< 本线程独占的pool管理借用，main期间不操作pool。 */
    vireo_notifier_t *notifier; /**< 完成管理后额外提示，借至本线程join。 */
    pthread_barrier_t entered; /**< main确认管理权已移交后放行worker。 */
    atomic_bool done; /**< 所有报告写完/通知后release发布，main acquire读取。 */
    vireo_result_t result; /**< 原stop_and_join最终返回，done后才读。 */
    vireo_thread_pool_report_t report; /**< 原累计创建/停止/join进度，done后才读。 */
} manager_context_t;
/** 全部owner及Reactor账本，非生产容器；入口无pending/残留且无timer。 */
typedef struct fixture {
    vireo_tcp_server_t *server; /**< 主线程Reactor资源根，保留到最后迟到消费后。 */
    vireo_connection_pool_lease_t client; /**< 当前完整客户租约，消费后本副本显式清零。 */
    int peer; /**< 唯一真实TCP对端fd，-1为空，末尾核无响应且EOF。 */
    vireo_inflight_store_t *store; /**< 容量6，按1槽预算清退含空槽。 */
    vireo_task_queue_t *tasks; /**< 容量2输入owner，关闭后取回pending。 */
    vireo_thread_pool_t *pool; /**< 固定1或2worker owner，管理权移交后main不访问。 */
    vireo_completion_queue_t *outputs; /**< 容量1，全部producer结束前保持OPEN。 */
    vireo_notifier_t *notifier; /**< 唯一eventfd owner，注册和管理线程借用结束后销毁。 */
    vireo_event_loop_t *wake_loop; /**< 仅提示的独立Reactor loop，不受server stop影响。 */
    vireo_event_loop_handle_t handle; /**< 原完整notifier注册身份，DEL后清零。 */
    size_t wake_calls; /**< 单Reactor真实READ回调数，不等完成项数。 */
    worker_context_t worker; /**< 原位barrier和worker长期借用context。 */
    manager_context_t manager; /**< 原位管理context，本线程join后才结束借用。 */
    vireo_task_metadata_t metadata[4]; /**< 各已移交请求的完整纯值快照。 */
    vireo_task_cancel_t *cancels[4]; /**< caller独立强引用，登记/task释放不消费此份。 */
    unsigned int completed_mask; /**< Reactor已实际销毁的迟到结果标签位图。 */
} fixture_t;
static void meet(pthread_barrier_t *barrier) {
    int const result = pthread_barrier_wait(barrier);
    CHECK(result == 0 || result == PTHREAD_BARRIER_SERIAL_THREAD);
}
static bool same(vireo_task_metadata_t a, vireo_task_metadata_t b) {
    bool equal; EXPECT(vireo_task_metadata_same_request(a, b, &equal), VIREO_OK);
    return equal && a.operation == b.operation && a.deadline_ns == b.deadline_ns;
}
static vireo_result_t execute(void *context, vireo_task_t const *task) {
    worker_context_t *w = context; vireo_task_payload_view_t view;
    EXPECT(vireo_task_borrow_payload(task, &view), VIREO_OK); CHECK(view.size == 1);
    unsigned int const tag = view.data[0]; CHECK(tag >= 1 && tag <= w->active_count);
    CHECK(w->seen[tag - 1]++ == 0); meet(&w->entered); meet(&w->release);
    bool requested; EXPECT(vireo_task_is_cancel_requested(task, &requested), VIREO_OK); CHECK(requested);
    vireo_completion_t *remaining = NULL;
    EXPECT(vireo_completion_copy_wait_publish(task, VIREO_RESULT_CANCELLED, VIREO_STATUS_OK,
      NULL, 0, 4096, w->outputs, w->notifier, &remaining, &w->reports[tag - 1]), VIREO_OK);
    CHECK(remaining == NULL);
    /* 工作取消已在completion中记录；发布步骤完成，executor自身正常返回。 */
    return VIREO_OK;
}
static void observe(vireo_event_loop_t *loop, vireo_event_loop_handle_t handle,
    int fd, uint32_t events, void *context) {
    fixture_t *f = context; CHECK(loop == f->wake_loop && fd >= 0);
    CHECK(handle.loop_id == f->handle.loop_id && handle.token == f->handle.token);
    CHECK(events == VIREO_EPOLL_EVENT_READ); ++f->wake_calls;
}
static void setup(fixture_t *f, size_t active_count) {
    *f = (fixture_t){.peer = -1}; f->worker.active_count = active_count;
    size_t const workers = active_count ? active_count : 1;
    vireo_tcp_server_options_t const so = {1, 2, 1048576, 128};
    EXPECT(vireo_tcp_server_create(&so, &f->server, NULL), VIREO_OK);
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0); CHECK(fd >= 0);
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    CHECK(bind(fd, (struct sockaddr *)&address, sizeof address) == 0 && listen(fd, 4) == 0);
    socklen_t length = sizeof address; CHECK(getsockname(fd, (struct sockaddr *)&address, &length) == 0);
    vireo_acceptor_options_t const ao = {4096}; vireo_acceptor_t *listener = NULL;
    EXPECT(vireo_acceptor_create(&ao, &fd, &listener, NULL), VIREO_OK);
    EXPECT(vireo_tcp_server_adopt_listener(f->server, &listener, NULL), VIREO_OK);
    f->peer = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0); CHECK(f->peer >= 0);
    CHECK(connect(f->peer, (struct sockaddr *)&address, sizeof address) == 0);
    vireo_connection_options_t const co = {64, 64, 128};
    vireo_tcp_server_admit_budget_t const ab = {1, 2}; vireo_tcp_server_admit_info_t admitted;
    EXPECT(vireo_tcp_server_admit_batch(f->server, &co, &ab, &f->client, 1, &admitted, NULL), VIREO_OK);
    CHECK(admitted.admitted_count == 1);
    uint8_t const discard[] = {0x41, 0x42, 0x43};
    EXPECT(vireo_tcp_server_client_write_enqueue(f->server, f->client, discard, sizeof discard, NULL), VIREO_OK);
    vireo_inflight_store_options_t const io = {6, 65536}; vireo_task_queue_options_t const tq = {2, 65536};
    vireo_completion_queue_options_t const cq = {1, 65536}; vireo_notifier_options_t const no = {4096};
    EXPECT(vireo_inflight_store_create(&io, &f->store), VIREO_OK);
    EXPECT(vireo_task_queue_create(&tq, &f->tasks), VIREO_OK); EXPECT(vireo_task_queue_prepare_wait(f->tasks), VIREO_OK);
    EXPECT(vireo_completion_queue_create(&cq, &f->outputs), VIREO_OK); EXPECT(vireo_completion_queue_prepare_wait(f->outputs), VIREO_OK);
    EXPECT(vireo_notifier_create(&no, &f->notifier, NULL), VIREO_OK);
    vireo_event_loop_options_t const lo = {2, 65536, 1};
    EXPECT(vireo_event_loop_create(&lo, &f->wake_loop, NULL), VIREO_OK);
    EXPECT(vireo_notifier_loop_register(f->wake_loop, f->notifier, observe, f, &f->handle, NULL), VIREO_OK);
    f->worker.outputs = f->outputs; f->worker.notifier = f->notifier;
    CHECK(pthread_barrier_init(&f->worker.entered, NULL, (unsigned int)active_count + 1) == 0);
    CHECK(pthread_barrier_init(&f->worker.release, NULL, (unsigned int)active_count + 1) == 0);
    CHECK(pthread_barrier_init(&f->manager.entered, NULL, 2) == 0); atomic_init(&f->manager.done, false);
    vireo_thread_pool_options_t const po = {workers, 65536};
    EXPECT(vireo_thread_pool_create(&po, &f->pool), VIREO_OK);
    vireo_thread_pool_configuration_t const configuration = {f->tasks, execute, &f->worker};
    EXPECT(vireo_thread_pool_configure(f->pool, &configuration, NULL), VIREO_OK);
    vireo_thread_pool_report_t report; EXPECT(vireo_thread_pool_start(f->pool, &report), VIREO_OK);
    EXPECT(vireo_thread_pool_enable_execution(f->pool, &report), VIREO_OK);
}
static void submit(fixture_t *f, unsigned int tag) {
    EXPECT(vireo_inflight_metadata_make_next(f->server, f->client, tag, 9, UINT64_MAX, &f->metadata[tag - 1], NULL), VIREO_OK);
    EXPECT(vireo_task_cancel_create(4096, &f->cancels[tag - 1]), VIREO_OK);
    uint8_t const payload = (uint8_t)tag; vireo_task_t *owner = NULL;
    EXPECT(vireo_task_create_copy_with_cancel(f->metadata[tag - 1], &payload, 1, 4096, f->cancels[tag - 1], &owner), VIREO_OK);
    for (size_t i = 0; i < LOCK_ATTEMPTS; ++i) {
        vireo_inflight_submit_report_t report; errno = EDOM;
        vireo_result_t const result = vireo_inflight_store_try_submit(f->store, f->server, f->pool, 4, &owner, &report); CHECK(errno == EDOM);
        if (result == VIREO_OK) { CHECK(!owner && report.record_retained && report.pool_report.queue_report.transferred); return; }
        CHECK(result == VIREO_RESULT_BUSY && owner && report.submit_called && !report.record_retained && report.rollback_called &&
          report.rollback_result == VIREO_OK && report.pool_report.queue_called && !report.pool_report.queue_report.transferred &&
          report.pool_report.queue_report.stage == VIREO_TASK_QUEUE_STAGE_LOCK && report.pool_report.queue_report.pthread_error == EBUSY);
        sched_yield(); /* 测试caller仅恢复明确预移交LOCK竞争，不改变公开try一次合同。 */
    }
    CHECK(false);
}
static void close_tasks(fixture_t *f) {
    for (size_t i = 0; i < LOCK_ATTEMPTS; ++i) {
        vireo_task_queue_close_report_t report; errno = EDOM;
        vireo_result_t const result = vireo_task_queue_close(f->tasks, VIREO_TASK_QUEUE_CANCEL_PENDING, &report); CHECK(errno == EDOM);
        if (result == VIREO_OK) { CHECK(report.changed); return; }
        CHECK(result == VIREO_RESULT_BUSY && !report.changed && report.stage == VIREO_TASK_QUEUE_STAGE_LOCK && report.pthread_error == EBUSY);
        sched_yield();
    }
    CHECK(false);
}
static void stop_and_retire(fixture_t *f, size_t total) {
    /* 在stop前构造额外任务，stop后只核准入拒绝，不把旧客户当作取消原因。 */
    vireo_task_metadata_t metadata;
    EXPECT(vireo_inflight_metadata_make_next(f->server, f->client, 99, 9, UINT64_MAX, &metadata, NULL), VIREO_OK);
    vireo_task_t *rejected = NULL; EXPECT(vireo_task_create_copy(metadata, NULL, 0, 4096, &rejected), VIREO_OK);
    EXPECT(vireo_tcp_server_request_stop(f->server, NULL), VIREO_OK);
    vireo_tcp_server_info_t server_info; EXPECT(vireo_tcp_server_inspect(f->server, &server_info), VIREO_OK);
    CHECK(server_info.stop_requested && server_info.connection_count == 1);
    /* 停止server后，独立提示loop仍真实分发READ，consumer无需恢复server。 */
    vireo_notifier_notify_outcome_t outcome; EXPECT(vireo_notifier_notify(f->notifier, &outcome, NULL), VIREO_OK);
    vireo_event_loop_run_info_t wake; EXPECT(vireo_event_loop_run_once(f->wake_loop, 0, &wake, NULL), VIREO_OK);
    CHECK(wake.dispatched_count == 1 && f->wake_calls == 1);
    uint64_t hint; EXPECT(vireo_notifier_consume(f->notifier, &hint, NULL), VIREO_OK); CHECK(hint == 1);
    vireo_inflight_submit_report_t submission;
    EXPECT(vireo_inflight_store_try_submit(f->store, f->server, f->pool, 4, &rejected, &submission), VIREO_RESULT_CANCELLED);
    CHECK(rejected && submission.task_inspected && !submission.registration_committed && !submission.submit_called);
    EXPECT(vireo_task_destroy(&rejected), VIREO_OK); close_tasks(f);
    vireo_connection_pool_lease_t const old = f->client;
    vireo_async_client_termination_step_t step = VIREO_ASYNC_CLIENT_TERMINATION_STEP_CLOSE;
    size_t cursor = 0, removed = 0, requested = 0;
    for (size_t i = 0; i < 6; ++i) {
        vireo_async_client_termination_report_t report;
        EXPECT(vireo_async_client_terminate_once(f->server, f->store, old, VIREO_CONNECTION_CLOSE_REASON_SERVER_STOP,
          step, cursor, 1, &report), VIREO_OK);
        CHECK(report.cleanup_called && report.cleanup_report.scanned_slots == 1 && report.cleanup_report.next_index == cursor + 1);
        CHECK(report.close_called == (i == 0) && report.release_called == (i == 0) && report.client_consumed == (i == 0));
        if (i == 0) f->client = (vireo_connection_pool_lease_t){0}; /* 原接口不改其他租约副本。 */
        removed += report.cleanup_report.removed_records; requested += report.cleanup_report.cancel_requests;
        cursor = report.cleanup_report.next_index; step = report.next_step;
        CHECK(step == (i == 5 ? VIREO_ASYNC_CLIENT_TERMINATION_STEP_DONE : VIREO_ASYNC_CLIENT_TERMINATION_STEP_CLEANUP));
    }
    CHECK(removed == total && requested == total);
    size_t count; EXPECT(vireo_inflight_store_count_client(f->store, old, &count, NULL), VIREO_OK); CHECK(count == 0);
    vireo_tcp_server_client_info_t client_info;
    EXPECT(vireo_tcp_server_client_inspect(f->server, old, &client_info), VIREO_RESULT_NOT_FOUND);
    EXPECT(vireo_tcp_server_inspect(f->server, &server_info), VIREO_OK);
    CHECK(server_info.stop_requested && server_info.connection_count == 0 && server_info.registered_connections == 0);
    for (size_t i = 0; i < total; ++i) {
        bool cancelled; EXPECT(vireo_task_cancel_is_requested(f->cancels[i], &cancelled), VIREO_OK); CHECK(cancelled);
    }
    struct pollfd p = {.fd = f->peer, .events = POLLIN}; CHECK(poll(&p, 1, 1000) == 1);
    uint8_t byte; CHECK(recv(f->peer, &byte, 1, MSG_DONTWAIT) == 0); /* 明确放弃的FIFO未send。 */
}
static void take_pending(fixture_t *f, unsigned int tag) {
    for (size_t i = 0; i < LOCK_ATTEMPTS; ++i) {
        vireo_task_t *owner = NULL; vireo_task_queue_transfer_report_t report; errno = EDOM;
        vireo_result_t const result = vireo_task_queue_try_take_cancelled(f->tasks, &owner, &report); CHECK(errno == EDOM);
        if (result == VIREO_RESULT_BUSY) {
            CHECK(!owner && !report.transferred && report.stage == VIREO_TASK_QUEUE_STAGE_LOCK && report.pthread_error == EBUSY);
            sched_yield(); continue;
        }
        if (tag == 0) { CHECK(result == VIREO_RESULT_NOT_FOUND && !owner && !report.transferred); return; }
        CHECK(result == VIREO_OK && owner && report.transferred);
        vireo_task_info_t info; EXPECT(vireo_task_inspect(owner, &info), VIREO_OK); CHECK(same(info.metadata, f->metadata[tag - 1]));
        bool cancelled; EXPECT(vireo_task_is_cancel_requested(owner, &cancelled), VIREO_OK); CHECK(cancelled);
        EXPECT(vireo_task_destroy(&owner), VIREO_OK); CHECK(!owner); return;
    }
    CHECK(false);
}
static void *manage(void *context) {
    manager_context_t *m = context; int old_state; CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &old_state) == 0);
    meet(&m->entered);
    bool finished = false;
    for (size_t i = 0; i < LOCK_ATTEMPTS; ++i) {
        errno = EDOM; m->result = vireo_thread_pool_stop_and_join(m->pool, &m->report); CHECK(errno == EDOM);
        if (m->result != VIREO_RESULT_BUSY) { finished = true; break; }
        CHECK(m->report.stage == VIREO_THREAD_POOL_STAGE_CHECK_QUEUE && !m->report.stop_requested &&
          m->report.joined_count == 0 && m->report.pthread_error == 0); sched_yield();
    }
    CHECK(finished && m->result == VIREO_OK && m->report.created_count == m->report.joined_count);
    vireo_notifier_notify_outcome_t outcome; EXPECT(vireo_notifier_notify(m->notifier, &outcome, NULL), VIREO_OK);
    atomic_store_explicit(&m->done, true, memory_order_release); return NULL;
}
static vireo_result_t forbidden_delivery(void *context, vireo_completion_t const *completion, vireo_inflight_completion_match_t match) {
    (void)context; (void)completion; (void)match;
    CHECK(false); return VIREO_RESULT_INTERNAL; /* 旧客户结果必须只清理，不授回写权限。 */
}
static void check_late(fixture_t *f, vireo_inflight_completion_consume_report_t report) {
    CHECK(report.disposition == VIREO_INFLIGHT_COMPLETION_CLIENT_GONE && report.completion_inspected &&
      !report.record_consumed && !report.delivery_called && report.destroy_called && report.completion_consumed);
    vireo_completion_metadata_t const metadata = report.completion_metadata;
    unsigned int const tag = metadata.request.route.request_sequence;
    CHECK(tag >= 1 && tag <= f->worker.active_count && same(metadata.request, f->metadata[tag - 1]));
    CHECK(metadata.result == VIREO_RESULT_CANCELLED && metadata.suggested_status == VIREO_STATUS_OK);
    unsigned int const bit = 1U << (tag - 1); CHECK(!(f->completed_mask & bit)); f->completed_mask |= bit;
}
static void consume_during_join(fixture_t *f) {
    size_t const needed = f->worker.active_count > 1 ? f->worker.active_count - 1 : 0;
    size_t consumed = 0; bool done = false;
    for (size_t turn = 0; turn < 100; ++turn) {
        done = atomic_load_explicit(&f->manager.done, memory_order_acquire);
        if (done) break;
        vireo_event_loop_run_info_t wait;
        EXPECT(vireo_event_loop_run_once(f->wake_loop, 100, &wait, NULL), VIREO_OK);
        if (consumed < needed) {
            vireo_completion_t *remaining = NULL; vireo_notifier_completion_report_t report; errno = EDOM;
            vireo_result_t const result = vireo_notifier_completion_consume_and_drain(f->notifier, f->store,
              f->server, f->outputs, 1, forbidden_delivery, NULL, &remaining, &report); CHECK(errno == EDOM && !remaining);
            if (result == VIREO_RESULT_BUSY) {
                CHECK(report.drain_report.stage == VIREO_INFLIGHT_COMPLETION_DRAIN_POP && report.drain_report.received == 0 &&
                  report.drain_report.queue_report.stage == VIREO_COMPLETION_QUEUE_TRANSFER_LOCK &&
                  report.drain_report.queue_report.pthread_error == EBUSY && !report.drain_report.queue_report.transferred &&
                  report.renotify_called && report.renotify_result == VIREO_OK);
            } else {
                CHECK(result == VIREO_OK && report.drain_report.finished <= 1 && report.drain_report.delivered == 0);
                if (report.drain_report.finished) { CHECK(report.drain_report.late_cleaned == 1); check_late(f, report.drain_report.consume_report); ++consumed; }
            }
        } else {
            /* 本fixture明确只余至多1项，容量1容得下，特意留给join后的最后drain。
             * 通用服务未知剩余基数，不能据count/hint停止consumer。 */
            uint64_t hints; EXPECT(vireo_notifier_consume(f->notifier, &hints, NULL), VIREO_OK);
        }
    }
    CHECK(done && consumed == needed);
}
static void final_drain(fixture_t *f, size_t active_count) {
    CHECK(f->manager.result == VIREO_OK && f->manager.report.stop_requested);
    vireo_completion_queue_info_t info; EXPECT(vireo_completion_queue_inspect(f->outputs, &info), VIREO_OK);
    CHECK(!info.closed && info.count == (active_count ? 1U : 0U));
    vireo_completion_queue_close_report_t close_report;
    EXPECT(vireo_completion_queue_close(f->outputs, &close_report), VIREO_OK); CHECK(close_report.changed);
    vireo_completion_t *remaining = NULL; vireo_inflight_completion_drain_report_t report;
    if (active_count) {
        EXPECT(vireo_inflight_store_drain_completions(f->store, f->server, f->outputs, 1,
          forbidden_delivery, NULL, &remaining, &report), VIREO_OK);
        CHECK(!remaining && report.finished == 1 && report.late_cleaned == 1 && report.delivered == 0);
        check_late(f, report.consume_report);
    }
    EXPECT(vireo_inflight_store_drain_completions(f->store, f->server, f->outputs, 1,
      forbidden_delivery, NULL, &remaining, &report), VIREO_RESULT_CANCELLED);
    CHECK(report.stage == VIREO_INFLIGHT_COMPLETION_DRAIN_POP && report.pop_calls == 1 && report.received == 0 &&
      !report.queue_report.transferred && report.queue_report.stage == VIREO_COMPLETION_QUEUE_TRANSFER_NONE &&
      report.queue_report.pthread_error == 0 && !remaining);
    CHECK(f->completed_mask == (active_count ? (1U << active_count) - 1U : 0U));
    uint64_t hints; EXPECT(vireo_notifier_consume(f->notifier, &hints, NULL), VIREO_OK);
}
static void destroy(fixture_t *f, size_t total) {
    size_t const workers = f->worker.active_count ? f->worker.active_count : 1;
    for (size_t i = 0; i < workers; ++i) {
        vireo_thread_pool_worker_result_t result;
        EXPECT(vireo_thread_pool_inspect_worker_result(f->pool, i, &result), VIREO_OK);
        CHECK(result.result == VIREO_OK && result.pthread_error == 0);
    }
    for (size_t i = 0; i < 4; ++i) CHECK(f->worker.seen[i] == (i < f->worker.active_count ? 1U : 0U));
    for (size_t i = 0; i < f->worker.active_count; ++i)
        CHECK(f->worker.reports[i].completion_transferred && f->worker.reports[i].notify_called &&
          same(f->worker.reports[i].request_metadata, f->metadata[i]));
    EXPECT(vireo_notifier_loop_unregister(f->wake_loop, &f->handle, NULL), VIREO_OK);
    CHECK(f->handle.loop_id == 0 && f->handle.token == 0);
    EXPECT(vireo_event_loop_destroy(&f->wake_loop, NULL), VIREO_OK);
    EXPECT(vireo_thread_pool_destroy(&f->pool), VIREO_OK); EXPECT(vireo_task_queue_destroy(&f->tasks), VIREO_OK);
    EXPECT(vireo_completion_queue_destroy(&f->outputs), VIREO_OK); EXPECT(vireo_notifier_destroy(&f->notifier, NULL), VIREO_OK);
    for (size_t i = 0; i < total; ++i) EXPECT(vireo_task_cancel_destroy(&f->cancels[i]), VIREO_OK);
    EXPECT(vireo_inflight_store_destroy(&f->store), VIREO_OK); EXPECT(vireo_tcp_server_destroy(&f->server, NULL), VIREO_OK);
    CHECK(pthread_barrier_destroy(&f->worker.entered) == 0 && pthread_barrier_destroy(&f->worker.release) == 0);
    CHECK(pthread_barrier_destroy(&f->manager.entered) == 0 && close(f->peer) == 0);
}
static void shutdown_case(size_t active_count) {
    fixture_t f; setup(&f, active_count);
    for (size_t i = 0; i < active_count; ++i) submit(&f, (unsigned int)i + 1);
    if (active_count) meet(&f.worker.entered);
    size_t const total = active_count ? active_count + 2 : 0;
    for (size_t i = active_count; i < total; ++i) submit(&f, (unsigned int)i + 1);
    stop_and_retire(&f, total);
    for (size_t i = active_count; i < total; ++i) take_pending(&f, (unsigned int)i + 1);
    take_pending(&f, 0);
    /* 此后main不操作pool；pthread_create发布context并移交全部管理权。 */
    f.manager.pool = f.pool; f.manager.notifier = f.notifier;
    pthread_t manager; CHECK(pthread_create(&manager, NULL, manage, &f.manager) == 0);
    meet(&f.manager.entered); if (active_count) meet(&f.worker.release);
    consume_during_join(&f);
    /* Reactor消费阶段结束，测试进入最终管理段；仅此时join管理线程本身。 */
    CHECK(pthread_join(manager, NULL) == 0);
    CHECK(f.wake_calls > 0 || active_count == 0); final_drain(&f, active_count); destroy(&f, total);
}
static size_t fd_count(void) {
    DIR *directory = opendir("/proc/self/fd"); CHECK(directory); size_t count = 0; struct dirent *entry;
    while ((entry = readdir(directory)) != NULL) if (entry->d_name[0] != '.') ++count;
    CHECK(closedir(directory) == 0); return count;
}
int main(void) {
    int old_state; CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &old_state) == 0);
    for (size_t active = 0; active <= 2; ++active) { size_t const before = fd_count(); shutdown_case(active); CHECK(fd_count() == before); }
    puts("async shutdown: 3 groups passed"); return 0;
}
