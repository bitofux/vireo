/*
 * PROJECT : VIREO
 * FILE    : test_client_deadline_request_integration.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-10
 * BRIEF   : 此模块负责：
 * -- 验证请求完成、到期、失败及身份复用的公开完整链验证
 * -- 只依赖已采用公开合同，保持资源、输出与 errno 的既有边界
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vireo/net/client_deadline_idle.h>
#include <vireo/net/client_deadline_request.h>
#include <vireo/net/client_deadline_serve.h>
#include <vireo/net/client_deadline_store.h>
#include <vireo/net/timer_loop_dispatch.h>
#include <vireo/protocol/codec.h>
#include <vireo/timer/wheel_shutdown.h>

#define CHECK(e)                                                    \
    do {                                                            \
        if (!(e)) {                                                 \
            fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #e); \
            return false;                                           \
        }                                                           \
    } while (0)
#define CALL(e, result)         \
    do {                        \
        errno = EDOM;           \
        CHECK((e) == (result)); \
        CHECK(errno == EDOM);   \
    } while (0)

/** 测试资源账；数值副本不拥有客户或 timer。 */
typedef struct fixture {
    vireo_tcp_server_t *server;               /**< 唯一 server owner，cleanup 销毁。 */
    vireo_timer_wheel_t *wheel;               /**< 唯一已准备轮，显式容量四。 */
    vireo_client_deadline_store_t *store;     /**< 只拥有容量二数值表。 */
    vireo_connection_pool_lease_t clients[2]; /**< 当前租约副本，消费后显式清零。 */
    int peers[2];                             /**< 测试对端 fd owner，-1 无资源。 */
    vireo_client_deadline_request_t requests[2]; /**< 独立请求控制值，领取后保留历史。 */
    vireo_client_deadline_idle_t idle; /**< 可刷新闲置值，与请求总期限独立。 */
    struct sockaddr_in address;        /**< loopback 临时端点，不是产品地址合同。 */
    int listener_fd;                   /**< 构造期 owner，转移后 -1。 */
    vireo_acceptor_t *listener;        /**< 构造期 owner，转移后 NULL。 */
    vireo_monotonic_ns_t origin;       /**< 当前测试轮的单调 ns 起点。 */
    size_t handler_calls;              /**< 本 fixture 同步 handler 调用数。 */
    uint32_t last_sequence;            /**< 最后实际 handler 的协议标签，仅观察。 */
} fixture_t;

static bool same_timer(vireo_timer_handle_t a, vireo_timer_handle_t b) {
    return a.owner_id == b.owner_id && a.slot_index == b.slot_index && a.generation == b.generation;
}
static bool sample(vireo_monotonic_ns_t *now) {
    CALL(vireo_clock_monotonic_now(now, NULL), VIREO_OK);
    return true;
}
/** 有界零 body 响应；只观察已验证帧，不模拟耗时 worker。 */
static vireo_result_t handler(vireo_connection_frame_view_t const *request, uint8_t *body,
                              size_t capacity, vireo_tcp_server_reply_t *reply, void *context) {
    fixture_t *f = context;
    (void)body;
    (void)capacity;
    ++f->handler_calls;
    f->last_sequence = request->header.sequence;
    reply->body_size = 0;
    return VIREO_OK;
}
/** 测试单轮调用者：使用产品021-08编排，保存实际准入租约，无自动消费。 */
static bool step(fixture_t *f, int cap, vireo_client_deadline_serve_report_t *trace) {
    vireo_tcp_server_serve_options_t const options = {.timeout_ms = cap,
                                                      .process = {96, 96},
                                                      .drive = {{256, 4}, {2, 192, 192}, {128, 4}},
                                                      .round = {2},
                                                      .admit = {2, 4}};
    uint8_t workspace[96];
    vireo_tcp_server_turn_result_t turns[2];
    vireo_connection_pool_lease_t admitted[2] = {0};
    CALL(vireo_client_deadline_serve_once(
             f->server, f->wheel, &options, (vireo_timer_wheel_advance_budget_t){64, 64}, workspace,
             sizeof workspace, handler, f, turns, 2, admitted, 2, trace),
         VIREO_OK);
    CHECK(trace->stage == VIREO_CLIENT_DEADLINE_SERVE_NONE && trace->serve_completed);
    CHECK(trace->after_now_ns >= trace->before_now_ns);
    CHECK(trace->wait_plan.timeout_ms >= 0 && trace->wait_plan.timeout_ms <= cap);
    CHECK(trace->advance.ticks_started <= 64 && trace->advance.nodes_examined <= 64);
    for (size_t i = 0; i < trace->serve_info.admission.admitted_count; ++i) {
        size_t j = 0;
        while (j < 2 && f->clients[j].pool_id != 0)
            ++j;
        CHECK(j < 2);
        f->clients[j] = admitted[i];
    }
    return true;
}
/**
 * @brief 构造固定测试资源，失败后保留已发布owner供统一cleanup
 *
 * @param[in,out] f
 *     独立存活fixture，入口无资源；拥有者字段仅测试持有。
 *
 * @return
 *     完整构造true，断言失败false；已取得资源仍在f内。
 *
 * @note
 *     同线程，构造调用依公开失败合同；统一清理不伪称初始化事务成功。
 */
static bool setup(fixture_t *f) {
    *f = (fixture_t){.peers = {-1, -1}, .listener_fd = -1};
    vireo_tcp_server_options_t const options = {2, 3, VIREO_TCP_SERVER_MAX_MEMORY, 768};
    CHECK(vireo_tcp_server_create(&options, &f->server, NULL) == VIREO_OK);
    f->listener_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    CHECK(f->listener_fd >= 0);
    f->address.sin_family = AF_INET;
    f->address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(bind(f->listener_fd, (struct sockaddr const *)&f->address, sizeof f->address) == 0);
    CHECK(listen(f->listener_fd, 4) == 0);
    socklen_t length = sizeof f->address;
    CHECK(getsockname(f->listener_fd, (struct sockaddr *)&f->address, &length) == 0);
    vireo_acceptor_options_t const listener_options = {VIREO_ACCEPTOR_MAX_MEMORY};
    CHECK(vireo_acceptor_create(&listener_options, &f->listener_fd, &f->listener, NULL) ==
          VIREO_OK);
    CHECK(vireo_tcp_server_adopt_listener(f->server, &f->listener, NULL) == VIREO_OK);
    CHECK(vireo_tcp_server_bind_listener(f->server, true, NULL) == VIREO_OK);
    vireo_tcp_server_admission_options_t const admission = {{256, 128, 384}, {96, 95, 192, 32, 96}};
    CHECK(vireo_tcp_server_admission_configure(f->server, &admission, NULL) == VIREO_OK);
    CHECK(sample(&f->origin));
    vireo_timer_wheel_options_t const wheel = {{f->origin, UINT64_C(10000000), 8},
                                               VIREO_TIMER_WHEEL_MAX_MEMORY};
    vireo_timer_wheel_registry_options_t const registry = {4,
                                                           VIREO_TIMER_WHEEL_REGISTRY_MAX_MEMORY};
    CHECK(vireo_timer_wheel_create(&wheel, &f->wheel) == VIREO_OK);
    CHECK(vireo_timer_wheel_prepare(f->wheel, &registry) == VIREO_OK);
    vireo_client_deadline_store_options_t const store = {2, VIREO_CLIENT_DEADLINE_STORE_MAX_MEMORY};
    CHECK(vireo_client_deadline_store_create(&store, &f->store) == VIREO_OK);
    return true;
}

/**
 * @brief 建立一条回环连接并通过公开单轮准入保存客户租约
 *
 * @param[in,out] f
 *     存活fixture，轮须原生时间域且未停止。
 * @param[in] i
 *     测试客户索引0或1，槽和对端入口空。
 *
 * @return
 *     接入完成true，有限64轮未完成或系统拒绝false。
 *
 * @note
 *     socket所有权保存在fixture；服务已发生的准入或字节动作不回滚。
 */
static bool connect_peer(fixture_t *f, size_t i) {
    CHECK(f->peers[i] == -1 && f->clients[i].pool_id == 0);
    f->peers[i] = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    CHECK(f->peers[i] >= 0);
    CHECK(connect(f->peers[i], (struct sockaddr const *)&f->address, sizeof f->address) == 0);
    vireo_client_deadline_serve_report_t trace;
    for (size_t n = 0; n < 64 && f->clients[i].pool_id == 0; ++n)
        CHECK(step(f, 20, &trace));
    CHECK(f->clients[i].pool_id != 0);
    return true;
}

/** 只重建空轮；合成算例与原生时间场景明确分开。 */
/**
 * @brief 只重建空轮并保存新几何起点
 *
 * @param[in,out] f
 *     表无旧轮记录、轮无活跃身份的独立fixture。
 * @param[in] origin
 *     显式纳秒起点，合成算例与原生域分开。
 * @param[in] tick
 *     正纳秒刻度间隔。
 * @param[in] capacity
 *     正登记槽数，沿公开硬限，本测试只1或4。
 *
 * @return
 *     完全重建true，断言失败false且f保已发布owner。
 *
 * @note
 *     先destroy空轮，再create/prepare；此测试步骤不对外承诺事务回滚。
 */
static bool reset_wheel(fixture_t *f, uint64_t origin, uint64_t tick, size_t capacity) {
    CALL(vireo_timer_wheel_destroy(&f->wheel), VIREO_OK);
    vireo_timer_wheel_options_t const options = {{origin, tick, 8}, VIREO_TIMER_WHEEL_MAX_MEMORY};
    vireo_timer_wheel_registry_options_t const registry = {capacity,
                                                           VIREO_TIMER_WHEEL_REGISTRY_MAX_MEMORY};
    CALL(vireo_timer_wheel_create(&options, &f->wheel), VIREO_OK);
    CALL(vireo_timer_wheel_prepare(f->wheel, &registry), VIREO_OK);
    f->origin = origin;
    return true;
}
static bool start(fixture_t *f, size_t i, size_t client, uint32_t sequence, uint64_t now,
                  uint64_t duration, bool save) {
    CALL(vireo_client_deadline_request_start(f->server, f->wheel, f->clients[client], sequence, now,
                                             duration, &f->requests[i], NULL),
         VIREO_OK);
    if (save)
        CALL(vireo_client_deadline_store_save(f->store, f->server, f->wheel, f->requests[i].binding,
                                              NULL),
             VIREO_OK);
    return true;
}
static bool advance(fixture_t *f, uint64_t now, size_t ready) {
    vireo_timer_wheel_advance_report_t report;
    CALL(vireo_timer_wheel_advance(f->wheel, now, (vireo_timer_wheel_advance_budget_t){64, 64},
                                   &report),
         VIREO_OK);
    CHECK(report.progress.caught_up && report.progress.ready_count == ready);
    return true;
}
static bool counts(fixture_t *f, size_t clients, size_t timers, size_t records) {
    vireo_tcp_server_info_t server;
    vireo_timer_wheel_registry_info_t wheel;
    vireo_client_deadline_store_info_t store;
    CALL(vireo_tcp_server_inspect(f->server, &server), VIREO_OK);
    CALL(vireo_timer_wheel_registry_inspect(f->wheel, &wheel), VIREO_OK);
    CALL(vireo_client_deadline_store_inspect(f->store, &store), VIREO_OK);
    CHECK(server.connection_count == clients && wheel.active_count == timers &&
          store.count == records);
    CHECK(server.buffer_capacity_bytes == clients * 384);
    return true;
}
static bool complete(fixture_t *f, size_t i) {
    vireo_client_deadline_binding_t taken;
    CALL(vireo_client_deadline_store_withdraw(f->store, f->requests[i].binding.timer, &taken),
         VIREO_OK);
    CHECK(same_timer(taken.timer, f->requests[i].binding.timer));
    CALL(vireo_client_deadline_request_cancel(f->wheel, &f->requests[i], NULL), VIREO_OK);
    CHECK(f->requests[i].binding.client.pool_id == 0 &&
          f->requests[i].binding.timer.owner_id == 0 && f->requests[i].request_sequence == 0 &&
          f->requests[i].started_ns == 0 && f->requests[i].deadline_ns == 0);
    return true;
}
/** 至多两次通知的测试交付账；历史地址不逃逸，只保存值副本。 */
typedef struct delivery_context {
    fixture_t *fixture;           /**< dispatch 期间短借资源根。 */
    bool act;                     /**< 测试显式选择 IMMEDIATE 与 READY 归还。 */
    vireo_result_t forced_result; /**< 转出后的应用错误模型，非内核故障。 */
    size_t calls;                 /**< 已调用次数，上限二，不是成功次数。 */
    vireo_client_deadline_binding_t taken[2]; /**< 已转出值，失败也保留供恢复。 */
    vireo_timer_wheel_expired_t history[2];   /**< 可信公开通知的历史值副本。 */
    vireo_client_deadline_release_report_t release[2]; /**< 原归还消费事实，不自动清其它副本。 */
} delivery_context_t;

/** 单项历史客户动作；不使用已注销 timer 查询当前性。 */
/**
 * @brief 以可信历史事件对当前客户执行一次测试显式关闭和归还
 *
 * @param[in,out] f
 *     短借存活资源根，同Reactor且server不在处理回调中。
 * @param[in,out] binding
 *     独立历史关联，归还消费时原API清零。
 * @param[in] event
 *     未篡改公开到期值，短借到返回。
 * @param[out] report
 *     独立原归还报告，只有归还被调用后才有本次结果。
 *
 * @return
 *     原依赖结果，不吞NOT_FOUND或部分IO。
 *
 * @note
 *     仅根据client_consumed清fixture当前租约副本；关闭晚失败不回滚。
 */
static vireo_result_t act(fixture_t *f, vireo_client_deadline_binding_t *binding,
                          vireo_timer_wheel_expired_t const *event,
                          vireo_client_deadline_release_report_t *report) {
    vireo_connection_pool_lease_t const original = binding->client;
    vireo_result_t result = vireo_client_deadline_request_close_expired(
        f->server, *binding, event, VIREO_CONNECTION_CLOSE_MODE_IMMEDIATE,
        VIREO_CONNECTION_CLOSE_REASON_APPLICATION, NULL);
    if (result != VIREO_OK)
        return result;
    result = vireo_client_deadline_release_ready_expired(f->server, binding, event, report);
    if (report->client_consumed) {
        for (size_t j = 0; j < 2; ++j)
            if (f->clients[j].pool_id == original.pool_id &&
                f->clients[j].slot_index == original.slot_index &&
                f->clients[j].generation == original.generation)
                f->clients[j] = (vireo_connection_pool_lease_t){0};
    }
    return result;
}
/** 只匹配、转出及选择单客户动作；无等待、推进、递归或全池扫描。 */
/**
 * @brief 有界测试交付：完整身份和固定期限匹配、表转出、当前客户核验
 *
 * @param[in] event
 *     dispatch提供的历史值，地址只短借；保存值不保存地址。
 * @param[in,out] context
 *     独立delivery_context，短借fixture，最多两条存储。
 *
 * @return
 *     依赖或应用模型原结果；只有全部选择的动作成功才OK。
 *
 * @note
 *     失败保转出值和历史；不等待、推进、递归dispatch或销毁借用对象。
 *     forced_result是应用模型，不是内核故障或产品自动策略。
 */
static vireo_result_t deliver(vireo_timer_wheel_expired_t const *event, void *context) {
    delivery_context_t *d = context;
    fixture_t *f = d->fixture;
    if (d->calls >= 2)
        return VIREO_RESULT_INTERNAL;
    size_t const index = d->calls++;
    d->history[index] = *event;
    size_t request = 0;
    while (request < 2 && !same_timer(f->requests[request].binding.timer, event->handle))
        ++request;
    if (request == 2 || f->requests[request].deadline_ns != event->timer.deadline_ns)
        return VIREO_RESULT_INVALID_ARGUMENT;
    vireo_result_t result =
        vireo_client_deadline_store_take_expired(f->store, event, &d->taken[index]);
    if (result != VIREO_OK)
        return result;
    if (d->forced_result != VIREO_OK)
        return d->forced_result;
    vireo_tcp_server_client_info_t client;
    result = vireo_client_deadline_check_expired(f->server, d->taken[index], event, &client, NULL);
    if (result != VIREO_OK || !d->act)
        return result;
    return act(f, &d->taken[index], event, &d->release[index]);
}
static bool dispatch(fixture_t *f, delivery_context_t *d, size_t budget, vireo_result_t result,
                     vireo_timer_loop_dispatch_report_t *report) {
    CALL(vireo_timer_loop_dispatch(f->wheel, budget, deliver, d, report), result);
    CHECK(report->consumed_count <= budget && report->delivered_count <= report->consumed_count);
    return true;
}
static bool cancel_not_found(fixture_t *f, size_t i) {
    vireo_client_deadline_request_t before;
    memcpy(&before, &f->requests[i], sizeof before);
    CALL(vireo_client_deadline_request_cancel(f->wheel, &f->requests[i], NULL),
         VIREO_RESULT_NOT_FOUND);
    CHECK(memcmp(&before, &f->requests[i], sizeof before) == 0);
    return true;
}
/**
 * @brief 结束全部测试借用后按三账清理已取得资源
 *
 * @param[in,out] f
 *     存活fixture，可为部分setup结果，无并发或回调在途。
 *
 * @return
 *     全部预期资源清理成功true，异常拒绝false。
 *
 * @note
 *     先撤表/取消未消费身份，再destroy表轮、归还客户、close对端和destroyserver。
 *     清理时NF仅表示本测试已知身份可已领取，不更改产品取消失败合同。
 */
static bool cleanup(fixture_t *f) {
    for (size_t i = 0; i < 2; ++i) {
        if (f->requests[i].binding.timer.owner_id != 0 && f->wheel != NULL) {
            if (f->store != NULL) {
                vireo_client_deadline_binding_t taken;
                vireo_result_t result = vireo_client_deadline_store_withdraw(
                    f->store, f->requests[i].binding.timer, &taken);
                CHECK(result == VIREO_OK || result == VIREO_RESULT_NOT_FOUND);
            }
            vireo_result_t result =
                vireo_client_deadline_request_cancel(f->wheel, &f->requests[i], NULL);
            CHECK(result == VIREO_OK || result == VIREO_RESULT_NOT_FOUND);
        }
    }
    if (f->idle.binding.timer.owner_id != 0 && f->wheel != NULL)
        CHECK(vireo_client_deadline_idle_cancel(f->wheel, &f->idle, NULL) == VIREO_OK);
    CHECK(vireo_client_deadline_store_destroy(&f->store) == VIREO_OK);
    CHECK(vireo_timer_wheel_destroy(&f->wheel) == VIREO_OK);
    for (size_t i = 0; i < 2; ++i) {
        if (f->clients[i].pool_id != 0)
            CHECK(vireo_tcp_server_release_client(f->server, &f->clients[i], NULL) == VIREO_OK);
        if (f->peers[i] >= 0)
            CHECK(close(f->peers[i]) == 0);
    }
    if (f->listener_fd >= 0)
        CHECK(close(f->listener_fd) == 0);
    CHECK(vireo_acceptor_destroy(&f->listener, NULL) == VIREO_OK);
    CHECK(vireo_tcp_server_destroy(&f->server, NULL) == VIREO_OK);
    return true;
}

/** 精确到期与向上 tick 边界分离，历史核验在 take 后仍能成功。 */
static bool exact_history(fixture_t *f) {
    CHECK(connect_peer(f, 0) && reset_wheel(f, 100, 10, 4) && start(f, 0, 0, 7, 100, 71, true));
    bool expired = false;
    CALL(vireo_client_deadline_request_check(f->server, f->wheel, &f->requests[0], 171, &expired,
                                             NULL),
         VIREO_OK);
    CHECK(expired && advance(f, 179, 0));
    delivery_context_t d = {.fixture = f, .act = true};
    vireo_timer_loop_dispatch_report_t report;
    CHECK(dispatch(f, &d, 1, VIREO_OK, &report) && report.consumed_count == 0 &&
          counts(f, 1, 1, 1));
    CHECK(advance(f, 180, 1) && dispatch(f, &d, 1, VIREO_OK, &report));
    CHECK(report.consumed_count == 1 && report.delivered_count == 1 &&
          d.release[0].client_consumed);
    CHECK(d.history[0].timer.deadline_ns == 171 && d.history[0].timer.due_tick == 8);
    CHECK(cancel_not_found(f, 0) && counts(f, 0, 0, 0));
    return true;
}
static bool completed_ready(fixture_t *f) {
    CHECK(connect_peer(f, 0) && reset_wheel(f, 100, 10, 4) && start(f, 0, 0, 7, 100, 20, true));
    CHECK(advance(f, 120, 1) && complete(f, 0));
    delivery_context_t d = {.fixture = f, .act = true};
    vireo_timer_loop_dispatch_report_t report;
    CHECK(dispatch(f, &d, 2, VIREO_OK, &report) && report.consumed_count == 0 && d.calls == 0);
    CHECK(counts(f, 1, 0, 0));
    return true;
}
static bool repeated_sequence_budget(fixture_t *f) {
    CHECK(connect_peer(f, 0) && connect_peer(f, 1) && reset_wheel(f, 100, 10, 4));
    CHECK(start(f, 0, 0, 7, 100, 20, true) && start(f, 1, 1, 7, 100, 20, true));
    CHECK(!same_timer(f->requests[0].binding.timer, f->requests[1].binding.timer));
    CHECK(advance(f, 120, 2));
    delivery_context_t d = {.fixture = f, .act = true};
    vireo_timer_loop_dispatch_report_t report;
    CHECK(dispatch(f, &d, 1, VIREO_OK, &report) && report.consumed_count == 1 && d.calls == 1);
    CHECK(counts(f, 1, 1, 1));
    CHECK(dispatch(f, &d, 1, VIREO_OK, &report) && report.consumed_count == 1 && d.calls == 2);
    CHECK(!same_timer(d.history[0].handle, d.history[1].handle) && counts(f, 0, 0, 0));
    return true;
}
static bool save_failure(fixture_t *f) {
    CHECK(connect_peer(f, 0) && reset_wheel(f, 100, 10, 4));
    CALL(vireo_client_deadline_store_destroy(&f->store), VIREO_OK);
    vireo_client_deadline_store_options_t const options = {1,
                                                           VIREO_CLIENT_DEADLINE_STORE_MAX_MEMORY};
    CALL(vireo_client_deadline_store_create(&options, &f->store), VIREO_OK);
    CHECK(start(f, 0, 0, 7, 100, 20, true) && start(f, 1, 0, 8, 100, 40, false));
    CALL(vireo_client_deadline_store_save(f->store, f->server, f->wheel, f->requests[1].binding,
                                          NULL),
         VIREO_RESULT_BUSY);
    CHECK(counts(f, 1, 2, 1));
    CALL(vireo_client_deadline_request_cancel(f->wheel, &f->requests[1], NULL), VIREO_OK);
    CHECK(counts(f, 1, 1, 1) && complete(f, 0) && advance(f, 150, 0) && counts(f, 1, 0, 0));
    return true;
}
static bool failed_delivery(fixture_t *f) {
    CHECK(connect_peer(f, 0) && reset_wheel(f, 100, 10, 4) && start(f, 0, 0, 7, 100, 20, true));
    CHECK(advance(f, 120, 1));
    delivery_context_t d = {.fixture = f, .forced_result = VIREO_RESULT_IO};
    vireo_timer_loop_dispatch_report_t report;
    CHECK(dispatch(f, &d, 1, VIREO_RESULT_IO, &report));
    CHECK(report.stage == VIREO_TIMER_LOOP_DISPATCH_STAGE_DELIVER && report.consumed_count == 1 &&
          report.delivered_count == 0 && report.has_failed_delivery &&
          same_timer(report.failed_delivery.handle, d.history[0].handle));
    CHECK(counts(f, 1, 0, 0) && cancel_not_found(f, 0));
    vireo_timer_loop_dispatch_report_t next;
    CHECK(dispatch(f, &d, 1, VIREO_OK, &next) && next.consumed_count == 0 && d.calls == 1);
    CALL(act(f, &d.taken[0], &report.failed_delivery, &d.release[0]), VIREO_OK);
    CHECK(d.release[0].client_consumed && counts(f, 0, 0, 0));
    return true;
}
static bool stale_client(fixture_t *f) {
    CHECK(connect_peer(f, 0) && connect_peer(f, 1) && reset_wheel(f, 100, 10, 4));
    CHECK(start(f, 0, 0, 7, 100, 20, true));
    vireo_connection_pool_lease_t const old_client = f->clients[0];
    CALL(vireo_tcp_server_release_client(f->server, &f->clients[0], NULL), VIREO_OK);
    CHECK(close(f->peers[0]) == 0);
    f->peers[0] = -1;
    /* 不用原生编排推进合成轮；直接公开准入，只有一个空客户槽。 */
    f->peers[0] = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    CHECK(f->peers[0] >= 0 &&
          connect(f->peers[0], (struct sockaddr const *)&f->address, sizeof f->address) == 0);
    vireo_connection_options_t const options = {256, 128, 384};
    vireo_tcp_server_admit_budget_t const budget = {1, 1};
    vireo_tcp_server_admit_info_t info;
    CALL(vireo_tcp_server_admit_batch(f->server, &options, &budget, &f->clients[0], 1, &info, NULL),
         VIREO_OK);
    CHECK(info.admitted_count == 1 && f->clients[0].slot_index == old_client.slot_index &&
          f->clients[0].generation != old_client.generation);
    CHECK(advance(f, 120, 1));
    delivery_context_t d = {.fixture = f, .act = true};
    vireo_timer_loop_dispatch_report_t report;
    CHECK(dispatch(f, &d, 1, VIREO_RESULT_NOT_FOUND, &report));
    CHECK(report.has_failed_delivery && report.consumed_count == 1 && report.delivered_count == 0);
    vireo_tcp_server_client_info_t current;
    CALL(vireo_tcp_server_client_inspect(f->server, f->clients[0], &current), VIREO_OK);
    CHECK(current.connection_info.close_state == VIREO_CONNECTION_CLOSE_OPEN &&
          !d.release[0].release_called);
    CHECK(cancel_not_found(f, 0) && counts(f, 2, 0, 0));
    return true;
}
static bool timer_reuse(fixture_t *f) {
    CHECK(connect_peer(f, 0) && reset_wheel(f, 100, 10, 1) && start(f, 0, 0, 7, 100, 20, true));
    vireo_client_deadline_request_t const old_request = f->requests[0];
    CHECK(advance(f, 120, 1));
    vireo_timer_wheel_expired_t old_event;
    CALL(vireo_timer_wheel_take_expired(f->wheel, &old_event), VIREO_OK);
    vireo_client_deadline_binding_t old_binding;
    CALL(vireo_client_deadline_store_take_expired(f->store, &old_event, &old_binding), VIREO_OK);
    f->requests[0] = (vireo_client_deadline_request_t){0};
    CHECK(start(f, 0, 0, 7, 120, 30, true));
    CHECK(f->requests[0].binding.timer.slot_index == old_request.binding.timer.slot_index &&
          f->requests[0].binding.timer.generation != old_request.binding.timer.generation);
    vireo_client_deadline_binding_t out, before;
    memset(&out, 0xa5, sizeof out);
    memcpy(&before, &out, sizeof before);
    CALL(vireo_client_deadline_store_take_expired(f->store, &old_event, &out),
         VIREO_RESULT_NOT_FOUND);
    CHECK(memcmp(&out, &before, sizeof out) == 0 && counts(f, 1, 1, 1));
    bool expired = true;
    CALL(
        vireo_client_deadline_request_check(f->server, f->wheel, &old_request, 120, &expired, NULL),
        VIREO_RESULT_NOT_FOUND);
    CHECK(expired && complete(f, 0));
    return true;
}
static bool idle_does_not_extend_request(fixture_t *f) {
    CHECK(connect_peer(f, 0) && reset_wheel(f, 100, 10, 4) && start(f, 0, 0, 7, 100, 40, true));
    CALL(vireo_client_deadline_idle_start(f->server, f->wheel, f->clients[0], 100, 100, &f->idle,
                                          NULL),
         VIREO_OK);
    uint8_t const byte = 42;
    CHECK(send(f->peers[0], &byte, 1, MSG_NOSIGNAL) == 1);
    vireo_connection_receive_info_t info;
    vireo_connection_receive_budget_t const budget = {64, 4};
    CALL(vireo_tcp_server_client_receive(f->server, f->clients[0], &budget, &info, NULL), VIREO_OK);
    CHECK(info.received_bytes == 1);
    CALL(vireo_client_deadline_idle_refresh(f->server, f->wheel, &f->idle, 130, info.received_bytes,
                                            0, NULL),
         VIREO_OK);
    vireo_timer_wheel_timer_info_t timer;
    CALL(vireo_timer_wheel_get(f->wheel, f->idle.binding.timer, &timer), VIREO_OK);
    CHECK(timer.deadline_ns == 230 && f->requests[0].deadline_ns == 140 && advance(f, 140, 1));
    delivery_context_t d = {.fixture = f, .act = true};
    vireo_timer_loop_dispatch_report_t report;
    CHECK(dispatch(f, &d, 1, VIREO_OK, &report) && counts(f, 0, 1, 0));
    /* 客户归还不自动取消独立 idle 身份。 */
    CALL(vireo_client_deadline_idle_cancel(f->wheel, &f->idle, NULL), VIREO_OK);
    CHECK(counts(f, 0, 0, 0));
    return true;
}
static bool stopped_ready_future(fixture_t *f) {
    CHECK(connect_peer(f, 0) && connect_peer(f, 1) && reset_wheel(f, 100, 10, 4));
    CHECK(start(f, 0, 0, 7, 100, 20, true) && start(f, 1, 1, 8, 100, 100, true) &&
          advance(f, 120, 1));
    CALL(vireo_timer_wheel_shutdown_begin(f->wheel), VIREO_OK);
    bool expired = true;
    CALL(vireo_client_deadline_request_check(f->server, f->wheel, &f->requests[1], 120, &expired,
                                             NULL),
         VIREO_OK);
    CHECK(!expired);
    delivery_context_t d = {.fixture = f, .act = true};
    vireo_timer_loop_dispatch_report_t report;
    CHECK(dispatch(f, &d, 1, VIREO_OK, &report) && counts(f, 1, 1, 1));
    vireo_timer_wheel_shutdown_report_t stopped;
    CALL(vireo_timer_wheel_shutdown_step(f->wheel, 4, &stopped), VIREO_OK);
    CHECK(stopped.has_cancelled && stopped.finished && stopped.remaining_count == 0 &&
          same_timer(stopped.cancelled.handle, f->requests[1].binding.timer));
    vireo_client_deadline_binding_t binding;
    CALL(vireo_client_deadline_store_withdraw(f->store, stopped.cancelled.handle, &binding),
         VIREO_OK);
    CHECK(cancel_not_found(f, 1) && counts(f, 1, 0, 0));
    CHECK(dispatch(f, &d, 1, VIREO_OK, &report) && report.consumed_count == 0 && d.calls == 1);
    return true;
}

/** 真实CRC请求先保留在公开读缓冲，视图借用结束后才进行可变操作。 */
/**
 * @brief 真实发送并公开CRC核验完整PING帧，仅复制协议标签
 *
 * @param[in,out] f
 *     当前客户0和对端均存活，短借到返回。
 * @param[out] sequence
 *     独立uint32输出，成功复制非零标签，不保存客户字节视图。
 *
 * @return
 *     有限帧完全接收并验证true，否则断言false。
 *
 * @note
 *     返回前结束frame/body借用，之后caller才可处理或消费读缓冲。
 */
static bool receive_request(fixture_t *f, uint32_t *sequence) {
    uint8_t wire[32];
    vireo_protocol_header_t h = {.command = VIREO_COMMAND_PING, .sequence = 7};
    CHECK(vireo_protocol_header_encode(&h, wire, sizeof wire) == VIREO_OK);
    CHECK(vireo_protocol_frame_crc32c_calculate(wire, sizeof wire, NULL, 0, &h.crc32c) == VIREO_OK);
    CHECK(vireo_protocol_header_encode(&h, wire, sizeof wire) == VIREO_OK);
    CHECK(send(f->peers[0], wire, sizeof wire, MSG_NOSIGNAL) == (ssize_t)sizeof wire);
    vireo_connection_receive_budget_t const budget = {64, 4};
    vireo_connection_receive_info_t received;
    CALL(vireo_tcp_server_client_receive(f->server, f->clients[0], &budget, &received, NULL),
         VIREO_OK);
    CHECK(received.received_bytes == sizeof wire);
    vireo_connection_frame_options_t const options = {VIREO_CONNECTION_FRAME_REQUEST, 96};
    vireo_connection_frame_budget_t const frame_budget = {1, 96};
    vireo_connection_frame_view_t frame;
    vireo_connection_frame_info_t info;
    CALL(vireo_tcp_server_client_frames_peek(f->server, f->clients[0], &options, &frame_budget,
                                             &frame, 1, &info, NULL),
         VIREO_OK);
    CHECK(info.frame_count == 1 && frame.header.sequence == 7);
    *sequence = frame.header.sequence;
    return true;
}
static bool native_completion(fixture_t *f) {
    CHECK(connect_peer(f, 0));
    uint32_t sequence;
    CHECK(receive_request(f, &sequence));
    uint64_t now;
    CHECK(sample(&now) && start(f, 0, 0, sequence, now, UINT64_C(3000000000), true));
    CALL(vireo_tcp_server_schedule_client(f->server, f->clients[0], NULL), VIREO_OK);
    vireo_client_deadline_serve_report_t trace;
    for (size_t i = 0; i < 64 && f->handler_calls == 0; ++i)
        CHECK(step(f, 10, &trace));
    CHECK(f->handler_calls == 1 && f->last_sequence == sequence);
    /* 显式 send 不依赖缓存是否已刷新；有限排队或已发送均保持原合同。 */
    vireo_connection_send_budget_t const budget = {128, 4};
    vireo_connection_send_info_t sent;
    CALL(vireo_tcp_server_client_send(f->server, f->clients[0], &budget, &sent, NULL), VIREO_OK);
    uint8_t wire[32];
    size_t used = 0;
    for (size_t i = 0; i < 8 && used < sizeof wire; ++i) {
        struct pollfd p = {.fd = f->peers[0], .events = POLLIN};
        CHECK(poll(&p, 1, 100) == 1 && (p.revents & POLLIN) != 0);
        ssize_t n = recv(f->peers[0], wire + used, sizeof wire - used, 0);
        CHECK(n > 0);
        used += (size_t)n;
    }
    CHECK(used == sizeof wire);
    vireo_protocol_header_t header;
    vireo_protocol_codec_issue_t issue;
    CHECK(vireo_protocol_header_decode(wire, sizeof wire, &header, &issue) == VIREO_OK);
    CHECK(header.sequence == sequence && header.command == VIREO_COMMAND_PING &&
          (header.flags & VIREO_PROTOCOL_FLAG_RESPONSE) != 0 && header.body_len == 0);
    CHECK(vireo_protocol_frame_crc32c_verify(wire, sizeof wire, NULL, 0, &issue) == VIREO_OK);
    CHECK(complete(f, 0) && counts(f, 1, 0, 0));
    delivery_context_t d = {.fixture = f};
    vireo_timer_loop_dispatch_report_t report;
    CHECK(dispatch(f, &d, 1, VIREO_OK, &report) && d.calls == 0);
    return true;
}
static bool native_expiry(fixture_t *f) {
    CHECK(connect_peer(f, 0));
    uint32_t sequence;
    CHECK(receive_request(f, &sequence));
    uint64_t now;
    CHECK(sample(&now));
    /* 测试caller明确选择仍待完成的数值控制实例，不模拟worker或抢占handler。 */
    CHECK(start(f, 0, 0, sequence, now, UINT64_C(1000000), true));
    CALL(vireo_tcp_server_client_read_consume(f->server, f->clients[0], 32, NULL), VIREO_OK);
    vireo_client_deadline_serve_report_t trace;
    uint64_t limit;
    CALL(vireo_clock_deadline_after(now, UINT64_C(3000000000), &limit), VIREO_OK);
    bool ready = false;
    for (size_t i = 0; i < 256 && !ready; ++i) {
        CHECK(step(f, 20, &trace));
        ready = trace.advance.progress.ready_count == 1;
        CHECK(trace.after_now_ns < limit);
    }
    CHECK(ready && f->handler_calls == 0);
    bool expired = false;
    CALL(vireo_client_deadline_request_check(f->server, f->wheel, &f->requests[0],
                                             trace.after_now_ns, &expired, NULL),
         VIREO_OK);
    CHECK(expired && trace.after_now_ns >= f->requests[0].deadline_ns);
    delivery_context_t d = {.fixture = f, .act = true};
    vireo_timer_loop_dispatch_report_t report;
    CHECK(dispatch(f, &d, 1, VIREO_OK, &report));
    CHECK(d.history[0].timer.deadline_ns == f->requests[0].deadline_ns &&
          report.consumed_count == 1 && report.delivered_count == 1 &&
          d.release[0].client_consumed);
    CHECK(cancel_not_found(f, 0) && counts(f, 0, 0, 0));
    return true;
}
/** 静态场景表，仅测试驱动。 */
typedef struct test_case {
    char const *name;         /**< 静态标签，无资源所有权。 */
    bool (*run)(fixture_t *); /**< 同步短借fixture，返回断言结果。 */
} test_case_t;
int main(void) {
    test_case_t const cases[] = {{"exact_history", exact_history},
                                 {"completed_ready", completed_ready},
                                 {"repeated_sequence_budget", repeated_sequence_budget},
                                 {"save_failure", save_failure},
                                 {"failed_delivery", failed_delivery},
                                 {"stale_client", stale_client},
                                 {"timer_reuse", timer_reuse},
                                 {"idle_does_not_extend_request", idle_does_not_extend_request},
                                 {"stopped_ready_future", stopped_ready_future},
                                 {"native_completion", native_completion},
                                 {"native_expiry", native_expiry}};
    size_t failed = 0;
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
        fixture_t f = {.peers = {-1, -1}, .listener_fd = -1};
        bool ok = setup(&f);
        if (ok)
            ok = cases[i].run(&f);
        if (!cleanup(&f))
            ok = false;
        printf("request integration %s: %s\n", cases[i].name, ok ? "PASS" : "FAIL");
        if (!ok)
            ++failed;
    }
    printf("request integration: %zu groups, %zu failed\n", sizeof cases / sizeof cases[0], failed);
    return failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
