/*
 * PROJECT : VIREO
 * FILE    : test_timer_loop_integration.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-09
 * BRIEF   : 此模块负责：
 * -- 连续验证等待、网络一轮、发现和交付的预算与失败语义
 * -- 区分混合可控时间和完整 native 证据，验证独立停止及收尾
 */
#include "net/timer_loop_internal.h"
#include <vireo/net/timer_loop_dispatch.h>
#include <vireo/timer/wheel_shutdown.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #condition); \
        return 1; \
    } \
} while (0)
#define EXPECT(expression, expected) do { \
    errno = EDOM; \
    CHECK((expression) == (expected)); \
    CHECK(errno == EDOM); \
} while (0)

/** 固定测试资源的唯一拥有者，所有借用在 teardown 前结束。 */
typedef struct fixture {
    vireo_event_loop_t *loop; /**< 测试拥有；网络回调只短借。 */
    vireo_timer_wheel_t *wheel; /**< 测试拥有；调用者显式停机归还身份后销毁。 */
    int sockets[2]; /**< 测试拥有两个非阻塞 fd，成功 DEL 后 close。 */
    vireo_event_loop_handle_t registration; /**< 注册身份，DEL 清零，不拥有客户端 fd。 */
} fixture_t;

/** 网络回调的有限公开轮动作，不解释为连接/请求策略。 */
typedef enum network_action { NETWORK_NONE = 0, NETWORK_STOP, NETWORK_REARM } network_action_t;

/** 真实网络回调的注册期上下文。 */
typedef struct network_probe {
    vireo_timer_wheel_t *wheel; /**< fixture 持有，注册期间借用。 */
    size_t calls; /**< 实际网络回调次数。 */
    bool invalid; /**< 事件、非阻塞 recv 或公开单项动作不符合预期。 */
    network_action_t action; /**< 只首回调执行 STOP 或 REARM。 */
    vireo_timer_handle_t victim; /**< REARM 使用的活跃身份副本，不保存节点地址。 */
} network_probe_t;

/** 本模块时钟 seam，网络依赖仍调用真实公开 loop。 */
typedef struct clock_state {
    vireo_monotonic_ns_t now_ns; /**< 固定数值模型时间，不冒真实采样。 */
    size_t clock_calls; /**< 本层采样适配的调用次数。 */
    size_t loop_calls; /**< 桥接真实 loop 的次数，失败后不重试。 */
    size_t fail_clock_at; /**< 指定第几次采样返回 IO，0 禁用。 */
    int timeout_seen; /**< 真正传入公开 loop 的非负毫秒。 */
} clock_state_t;

/** 同步交付只检查历史身份、复制值及可选一次停止。 */
typedef struct delivery_probe {
    vireo_timer_wheel_t *wheel; /**< fixture 拥有，整个消费短借。 */
    size_t calls; /**< 实际交付函数调用数，不是耗时。 */
    size_t fail_at; /**< 指定第几次交付 IO，0 禁用。 */
    vireo_timer_wheel_expired_t events[4]; /**< 只复制前四条，不保留回调栈地址。 */
    bool invalid; /**< 回调时旧身份仍活跃或停止失败。 */
    bool stop_wheel; /**< 首交付是否调用公开 shutdown_begin。 */
} delivery_probe_t;

static bool same_handle(vireo_timer_handle_t a, vireo_timer_handle_t b)
{
    return a.owner_id == b.owner_id && a.slot_index == b.slot_index && a.generation == b.generation;
}

/**
 * @brief 用真实非阻塞读和有限单项动作观察网络进度
 *
 * @param[in] loop
 *     注册所属短借 loop，回调不销毁。
 * @param[in] handle
 *     当前注册数值副本，不用于清理。
 * @param[in] fd
 *     fixture 拥有的非阻塞 socket，仅一次 recv。
 * @param[in] events
 *     公开 epoll 就绪位，预期 READ。
 * @param[in,out] context
 *     注册期间存活的 network_probe，只首调用执行选定动作。
 *
 * @note
 *     非阻塞且正常返回，不递归组合/消费，不关闭借用 fd。
 */
static void network_read(vireo_event_loop_t *loop, vireo_event_loop_handle_t handle,
                          int fd, uint32_t events, void *context)
{
    (void)loop; (void)handle;
    network_probe_t *p = context; ++p->calls;
    char value = 0;
    if ((events & VIREO_EPOLL_EVENT_READ) == 0 || recv(fd, &value, 1, 0) != 1 || value != 'x') {
        p->invalid = true;
    }
    if (p->calls == 1) {
        vireo_result_t result = VIREO_OK;
        if (p->action == NETWORK_STOP) {
            result = vireo_timer_wheel_shutdown_begin(p->wheel);
        } else if (p->action == NETWORK_REARM) {
            result = vireo_timer_wheel_rearm(p->wheel, p->victim, 110, 150);
        }
        if (result != VIREO_OK) { p->invalid = true; }
    }
    errno = EILSEQ;
}

/**
 * @brief 创建固定轮、loop 和 socketpair，注册短借上下文
 *
 * @param[in,out] f
 *     零初始化的唯一测试拥有者。
 * @param[in,out] net
 *     存活至成功 DEL 的上下文，设置其 wheel 借用。
 * @param[in] origin
 *     显式纳秒起点。
 * @param[in] tick
 *     正刻度纳秒，混合模型用 10，native 用 1。
 *
 * @retval 0
 *     装配成功，fixture 持有全部资源。
 * @retval 1
 *     断言失败，终止本场景。
 *
 * @note
 *     三个登记槽、四桶，不用任何其他模块 private。
 */
static int setup(fixture_t *f, network_probe_t *net,
                 vireo_monotonic_ns_t origin, vireo_duration_ns_t tick)
{
    vireo_event_loop_options_t loop_options = {
        .event_capacity = 4, .max_memory_bytes = VIREO_EVENT_LOOP_MAX_MEMORY, .registration_capacity = 2
    };
    vireo_timer_wheel_options_t wheel_options = {
        .geometry = { .origin_ns = origin, .tick_ns = tick, .bucket_count = 4 },
        .max_memory_bytes = VIREO_TIMER_WHEEL_MAX_MEMORY
    };
    vireo_timer_wheel_registry_options_t registry = {
        .capacity = 3, .max_memory_bytes = VIREO_TIMER_WHEEL_REGISTRY_MAX_MEMORY
    };
    EXPECT(vireo_event_loop_create(&loop_options, &f->loop, NULL), VIREO_OK);
    EXPECT(vireo_timer_wheel_create(&wheel_options, &f->wheel), VIREO_OK);
    EXPECT(vireo_timer_wheel_prepare(f->wheel, &registry), VIREO_OK);
    CHECK(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, f->sockets) == 0);
    net->wheel = f->wheel;
    vireo_event_loop_registration_t registration = {
        .fd = f->sockets[0], .interests = VIREO_EPOLL_EVENT_READ,
        .callback = network_read, .context = net
    };
    EXPECT(vireo_event_loop_add(f->loop, &registration, &f->registration, NULL), VIREO_OK);
    return 0;
}

/**
 * @brief 结束注册/客户端借用并清空轮后销毁全部 owned 资源
 *
 * @param[in,out] f
 *     成功 setup 的唯一拥有者；成功后对象和注册身份清空。
 *
 * @retval 0
 *     所有资源成对释放。
 * @retval 1
 *     清理断言失败。
 *
 * @note
 *     所有回调已返回；不把销毁 loop 当客户端 close 或业务完成。
 */
static int teardown(fixture_t *f)
{
    EXPECT(vireo_event_loop_del(f->loop, &f->registration, NULL), VIREO_OK);
    CHECK(close(f->sockets[0]) == 0 && close(f->sockets[1]) == 0);
    EXPECT(vireo_timer_wheel_shutdown_begin(f->wheel), VIREO_OK);
    vireo_timer_wheel_shutdown_report_t stopped;
    do {
        EXPECT(vireo_timer_wheel_shutdown_step(f->wheel, 3, &stopped), VIREO_OK);
    } while (!stopped.finished);
    EXPECT(vireo_timer_wheel_destroy(&f->wheel), VIREO_OK);
    EXPECT(vireo_event_loop_destroy(&f->loop, NULL), VIREO_OK);
    CHECK(f->loop == NULL && f->wheel == NULL);
    return 0;
}

/**
 * @brief 提供可控单调数值或指定一次采样错误
 *
 * @param[out] out_now
 *     独立值输出，失败不写。
 * @param[out] out_error
 *     非空独立 clock 诊断，按原公开字段填写。
 * @param[in,out] context
 *     非空 clock_state，计数并读取固定 now。
 *
 * @return
 *     指定 IO 或 OK，不冒真实 syscall 故障。
 *
 * @note
 *     不修改轮；刻意改 errno 检验外层恢复。
 */
static vireo_result_t model_now(vireo_monotonic_ns_t *out_now,
                                vireo_clock_error_t *out_error, void *context)
{
    clock_state_t *s = context; ++s->clock_calls; errno = ERANGE;
    if (s->clock_calls == s->fail_clock_at) {
        *out_error = (vireo_clock_error_t){ .stage = VIREO_CLOCK_STAGE_READ, .system_errno = EIO };
        return VIREO_RESULT_IO;
    }
    *out_now = s->now_ns; *out_error = (vireo_clock_error_t){0};
    return VIREO_OK;
}

/**
 * @brief 桥接真实公开网络一轮并记录实际传入等待
 *
 * @param[in,out] loop
 *     fixture 拥有的短借 loop。
 * @param[in] timeout_ms
 *     规划产生的非负毫秒，实际传入原入口。
 * @param[out] out_info
 *     公开 loop 的独立成功报告。
 * @param[out] out_error
 *     公开 loop 的独立诊断。
 * @param[in,out] context
 *     非空 clock_state，记录次数和 timeout。
 *
 * @return
 *     原 loop 结果，无重试或统计伪造。
 */
static vireo_result_t real_loop(vireo_event_loop_t *loop, int timeout_ms,
                                vireo_event_loop_run_info_t *out_info,
                                vireo_event_loop_error_t *out_error, void *context)
{
    clock_state_t *s = context; ++s->loop_calls; s->timeout_seen = timeout_ms;
    return vireo_event_loop_run_once(loop, timeout_ms, out_info, out_error);
}

static vireo_timer_loop_runtime_t runtime(clock_state_t *s)
{
    return (vireo_timer_loop_runtime_t){ .monotonic_now = model_now, .run_loop = real_loop, .context = s };
}

/**
 * @brief 用历史值检查注销并执行可选一次停止
 *
 * @param[in] expired
 *     注销后的只读栈值，至多复制前四条。
 * @param[in,out] context
 *     非空存活 delivery_probe，不保存事件地址。
 *
 * @retval VIREO_OK
 *     检查成功且未指定本次失败。
 * @retval VIREO_RESULT_IO
 *     指定本次失败，已经注销仍不可回滚。
 * @retval VIREO_RESULT_INTERNAL
 *     历史身份或停止动作不符合预期。
 *
 * @note
 *     有界且非阻塞，只公开 get/可选 begin，不消费/推进或销毁借用轮。
 */
static vireo_result_t deliver(vireo_timer_wheel_expired_t const *expired, void *context)
{
    delivery_probe_t *p = context;
    if (p->calls < 4) { p->events[p->calls] = *expired; }
    ++p->calls; errno = EILSEQ;
    vireo_timer_wheel_timer_info_t timer;
    if (vireo_timer_wheel_get(p->wheel, expired->handle, &timer) != VIREO_RESULT_NOT_FOUND) {
        p->invalid = true;
    }
    if (p->stop_wheel && p->calls == 1 && vireo_timer_wheel_shutdown_begin(p->wheel) != VIREO_OK) {
        p->invalid = true;
    }
    if (p->invalid) { return VIREO_RESULT_INTERNAL; }
    return p->calls == p->fail_at ? VIREO_RESULT_IO : VIREO_OK;
}

/**
 * @brief 给下一真实网络轮准备一个字节
 *
 * @param[in] f
 *     持有存活 socketpair 的 fixture，仅借用。
 *
 * @retval 0
 *     严格一次非阻塞 send 成功。
 * @retval 1
 *     断言失败。
 *
 * @note
 *     不循环等待或重试，MSG_NOSIGNAL 避免测试进程的信号副作用。
 */
static int send_byte(fixture_t const *f)
{
    CHECK(send(f->sockets[1], "x", 1, MSG_NOSIGNAL) == 1);
    return 0;
}

/**
 * @brief 在固定数值时间构造若干待发现项并可选公开发现
 *
 * @param[in,out] f
 *     origin100/tick10 的已 prepare 测试轮。
 * @param[in,out] handles
 *     count 个入口全零的独立身份。
 * @param[in] count
 *     1 至 3，全部期限110。
 * @param[in] discover
 *     是否立即在数值时刻110公开推进发现。
 *
 * @retval 0
 *     全部登记和所选发现成功。
 * @retval 1
 *     断言失败。
 *
 * @note
 *     这是受控时间模型，不冒真实 clock。
 */
static int timers(fixture_t *f, vireo_timer_handle_t *handles, size_t count, bool discover)
{
    for (size_t i = 0; i < count; ++i) {
        EXPECT(vireo_timer_wheel_register(f->wheel, 100, 110, &handles[i]), VIREO_OK);
    }
    if (discover) {
        vireo_timer_wheel_advance_report_t report;
        EXPECT(vireo_timer_wheel_advance(f->wheel, 110,
            ((vireo_timer_wheel_advance_budget_t){ .max_ticks = 1, .max_nodes = 3 }), &report), VIREO_OK);
        CHECK(report.progress.ready_count == count);
    }
    return 0;
}

static int test_pending_network_and_budgets(void)
{
    fixture_t f = {0}; network_probe_t net = {0}; CHECK(setup(&f, &net, 100, 10) == 0);
    vireo_timer_handle_t h[2] = {0}; CHECK(timers(&f, h, 2, false) == 0);
    vireo_timer_handle_t future = {0};
    EXPECT(vireo_timer_wheel_register(f.wheel, 100, 150, &future), VIREO_OK);
    clock_state_t clock = { .now_ns = 110 }; vireo_timer_loop_runtime_t ops = runtime(&clock);
    vireo_timer_loop_run_options_t options = { .max_wait_ms = 9, .advance_budget = {1, 1} };
    delivery_probe_t delivery = { .wheel = f.wheel };
    for (size_t round = 0; round < 3; ++round) {
        CHECK(send_byte(&f) == 0);
        vireo_timer_loop_run_report_t report; vireo_timer_loop_diagnostic_t diagnostic;
        EXPECT(vireo_timer_loop_run_once_runtime(f.loop, f.wheel, &options, &report, &diagnostic, &ops), VIREO_OK);
        CHECK(report.wait_plan.timeout_ms == 0 && clock.timeout_seen == 0);
        CHECK(report.loop.dispatched_count == 1 && net.calls == round + 1 && !net.invalid);
        CHECK(report.advance.nodes_examined == 1 && report.advance.ticks_started == (round == 0 ? 1 : 0));
        CHECK(report.advance.progress.processing == (round != 2));
        vireo_timer_loop_dispatch_report_t dispatched;
        EXPECT(vireo_timer_loop_dispatch(f.wheel, 1, deliver, &delivery, &dispatched), VIREO_OK);
        CHECK(dispatched.consumed_count <= 1 && dispatched.delivered_count == dispatched.consumed_count);
    }
    /* 不假设 future 节点与两条到期项的桶内顺序；最后可能仍剩一条 ready。 */
    vireo_timer_loop_dispatch_report_t tail;
    EXPECT(vireo_timer_loop_dispatch(f.wheel, 1, deliver, &delivery, &tail), VIREO_OK);
    CHECK(delivery.calls == 2 && !delivery.invalid && clock.clock_calls == 6 && clock.loop_calls == 3);
    CHECK(!same_handle(delivery.events[0].handle, delivery.events[1].handle));
    vireo_timer_wheel_timer_info_t timer;
    EXPECT(vireo_timer_wheel_get(f.wheel, future, &timer), VIREO_OK); CHECK(timer.deadline_ns == 150);
    vireo_timer_loop_wait_plan_t plan;
    EXPECT(vireo_timer_loop_plan_wait(f.wheel, 110, 9, &plan), VIREO_OK);
    CHECK(plan.timeout_ms == 1 && !plan.timer_work_pending && plan.has_tick_deadline && plan.tick_deadline_ns == 120);
    return teardown(&f);
}

static int test_delivery_failure_next_round(void)
{
    fixture_t f = {0}; network_probe_t net = {0}; CHECK(setup(&f, &net, 100, 10) == 0);
    vireo_timer_handle_t h[3] = {0}; CHECK(timers(&f, h, 3, false) == 0);
    clock_state_t clock = { .now_ns = 110 }; vireo_timer_loop_runtime_t ops = runtime(&clock);
    vireo_timer_loop_run_options_t options = { .max_wait_ms = 9, .advance_budget = {1, 3} };
    vireo_timer_loop_run_report_t report; vireo_timer_loop_diagnostic_t diagnostic;
    CHECK(send_byte(&f) == 0);
    EXPECT(vireo_timer_loop_run_once_runtime(f.loop, f.wheel, &options, &report, &diagnostic, &ops), VIREO_OK);
    CHECK(report.advance.progress.ready_count == 3);
    delivery_probe_t delivery = { .wheel = f.wheel, .fail_at = 2 };
    vireo_timer_loop_dispatch_report_t dispatched;
    EXPECT(vireo_timer_loop_dispatch(f.wheel, 3, deliver, &delivery, &dispatched), VIREO_RESULT_IO);
    CHECK(dispatched.stage == VIREO_TIMER_LOOP_DISPATCH_STAGE_DELIVER && dispatched.has_failed_delivery);
    CHECK(dispatched.consumed_count == 2 && dispatched.delivered_count == 1 && delivery.calls == 2);
    vireo_timer_wheel_expired_t failed = dispatched.failed_delivery;
    CHECK(same_handle(failed.handle, delivery.events[1].handle));
    CHECK(send_byte(&f) == 0);
    EXPECT(vireo_timer_loop_run_once_runtime(f.loop, f.wheel, &options, &report, &diagnostic, &ops), VIREO_OK);
    CHECK(report.wait_plan.timer_work_pending && clock.timeout_seen == 0 && net.calls == 2);
    CHECK(report.advance.progress.ready_count == 1);
    EXPECT(vireo_timer_loop_dispatch(f.wheel, 3, deliver, &delivery, &dispatched), VIREO_OK);
    CHECK(dispatched.consumed_count == 1 && dispatched.delivered_count == 1 && delivery.calls == 3 && !delivery.invalid);
    CHECK(!same_handle(failed.handle, delivery.events[2].handle) && !dispatched.has_failed_delivery);
    return teardown(&f);
}

static int test_late_clock_failure_recovery_choice(void)
{
    fixture_t f = {0}; network_probe_t net = {0}; CHECK(setup(&f, &net, 100, 10) == 0);
    vireo_timer_handle_t h[2] = {0}; CHECK(timers(&f, h, 2, true) == 0);
    clock_state_t clock = { .now_ns = 110, .fail_clock_at = 2 }; vireo_timer_loop_runtime_t ops = runtime(&clock);
    vireo_timer_loop_run_options_t options = { .max_wait_ms = 9, .advance_budget = {1, 1} };
    vireo_timer_loop_run_report_t report; memset(&report, 0xa5, sizeof(report));
    unsigned char old[sizeof(report)]; memcpy(old, &report, sizeof(old));
    vireo_timer_loop_diagnostic_t diagnostic;
    CHECK(send_byte(&f) == 0);
    EXPECT(vireo_timer_loop_run_once_runtime(f.loop, f.wheel, &options, &report, &diagnostic, &ops), VIREO_RESULT_IO);
    CHECK(memcmp(old, &report, sizeof(old)) == 0 && net.calls == 1 && !net.invalid);
    CHECK(diagnostic.stage == VIREO_TIMER_LOOP_STAGE_CLOCK_AFTER && diagnostic.loop_completed);
    CHECK(diagnostic.clock_error.stage == VIREO_CLOCK_STAGE_READ && diagnostic.clock_error.system_errno == EIO);
    CHECK(clock.clock_calls == 2 && clock.loop_calls == 1);
    char byte; CHECK(recv(f.sockets[0], &byte, 1, 0) == -1 && (errno == EAGAIN || errno == EWOULDBLOCK));
    vireo_timer_wheel_progress_t progress;
    EXPECT(vireo_timer_wheel_progress_inspect(f.wheel, &progress), VIREO_OK);
    CHECK(progress.ready_count == 2 && progress.latest_now_ns == 110);
    /* caller 明确选择独立消费旧 ready，不是产品自动恢复或重放网络。 */
    delivery_probe_t delivery = { .wheel = f.wheel }; vireo_timer_loop_dispatch_report_t dispatched;
    EXPECT(vireo_timer_loop_dispatch(f.wheel, 2, deliver, &delivery, &dispatched), VIREO_OK);
    CHECK(delivery.calls == 2 && !delivery.invalid && dispatched.delivered_count == 2);
    return teardown(&f);
}

static int test_network_stop_late_failure_and_cleanup(void)
{
    fixture_t f = {0}; network_probe_t net = { .action = NETWORK_STOP };
    CHECK(setup(&f, &net, 100, 10) == 0);
    vireo_timer_handle_t due = {0}; CHECK(timers(&f, &due, 1, true) == 0);
    vireo_timer_handle_t future = {0}; EXPECT(vireo_timer_wheel_register(f.wheel, 110, 150, &future), VIREO_OK);
    clock_state_t clock = { .now_ns = 110 }; vireo_timer_loop_runtime_t ops = runtime(&clock);
    vireo_timer_loop_run_options_t options = { .max_wait_ms = 9, .advance_budget = {1, 1} };
    vireo_timer_loop_run_report_t report; memset(&report, 0xa5, sizeof(report));
    unsigned char old[sizeof(report)]; memcpy(old, &report, sizeof(old)); vireo_timer_loop_diagnostic_t diagnostic;
    CHECK(send_byte(&f) == 0);
    EXPECT(vireo_timer_loop_run_once_runtime(f.loop, f.wheel, &options, &report, &diagnostic, &ops), VIREO_RESULT_CANCELLED);
    CHECK(memcmp(old, &report, sizeof(old)) == 0 && diagnostic.stage == VIREO_TIMER_LOOP_STAGE_ADVANCE && diagnostic.loop_completed);
    CHECK(net.calls == 1 && !net.invalid);
    delivery_probe_t delivery = { .wheel = f.wheel }; vireo_timer_loop_dispatch_report_t dispatched;
    EXPECT(vireo_timer_loop_dispatch(f.wheel, 1, deliver, &delivery, &dispatched), VIREO_OK);
    CHECK(delivery.calls == 1 && same_handle(delivery.events[0].handle, due));
    vireo_timer_wheel_t *saved = f.wheel;
    EXPECT(vireo_timer_wheel_destroy(&f.wheel), VIREO_RESULT_BUSY); CHECK(f.wheel == saved);
    vireo_timer_loop_wait_plan_t plan; memset(&plan, 0xa5, sizeof(plan));
    unsigned char previous[sizeof(plan)]; memcpy(previous, &plan, sizeof(previous));
    EXPECT(vireo_timer_loop_plan_wait(f.wheel, 0, 9, &plan), VIREO_RESULT_CANCELLED);
    CHECK(memcmp(previous, &plan, sizeof(previous)) == 0);
    vireo_timer_wheel_shutdown_report_t stopped; size_t total_scanned = 0; size_t cancelled_count = 0;
    do {
        EXPECT(vireo_timer_wheel_shutdown_step(f.wheel, 1, &stopped), VIREO_OK);
        CHECK(stopped.scanned_slots <= 1); total_scanned += stopped.scanned_slots;
        if (stopped.has_cancelled) {
            ++cancelled_count;
            CHECK(same_handle(stopped.cancelled.handle, future) && stopped.cancelled.timer.deadline_ns == 150);
        }
        CHECK(total_scanned <= 3);
    } while (!stopped.finished);
    CHECK(stopped.remaining_count == 0 && cancelled_count == 1 && delivery.calls == 1 && !delivery.invalid);
    return teardown(&f);
}

static int test_delivery_stop_network_independent(void)
{
    fixture_t f = {0}; network_probe_t net = {0}; CHECK(setup(&f, &net, 100, 10) == 0);
    vireo_timer_handle_t h[2] = {0}; CHECK(timers(&f, h, 2, true) == 0);
    delivery_probe_t delivery = { .wheel = f.wheel, .stop_wheel = true };
    vireo_timer_loop_dispatch_report_t dispatched;
    EXPECT(vireo_timer_loop_dispatch(f.wheel, 3, deliver, &delivery, &dispatched), VIREO_OK);
    CHECK(dispatched.delivered_count == 2 && delivery.calls == 2 && !delivery.invalid);
    clock_state_t clock = { .now_ns = 110 }; vireo_timer_loop_runtime_t ops = runtime(&clock);
    vireo_timer_loop_run_options_t options = { .max_wait_ms = 9, .advance_budget = {1, 1} };
    vireo_timer_loop_run_report_t report; vireo_timer_loop_diagnostic_t diagnostic;
    CHECK(send_byte(&f) == 0);
    EXPECT(vireo_timer_loop_run_once_runtime(f.loop, f.wheel, &options, &report, &diagnostic, &ops), VIREO_RESULT_CANCELLED);
    CHECK(!diagnostic.loop_completed && diagnostic.stage == VIREO_TIMER_LOOP_STAGE_CHECK_WHEEL);
    CHECK(clock.clock_calls == 0 && clock.loop_calls == 0 && net.calls == 0);
    vireo_event_loop_run_info_t network;
    EXPECT(vireo_event_loop_run_once(f.loop, 0, &network, NULL), VIREO_OK);
    CHECK(network.dispatched_count == 1 && net.calls == 1 && !net.invalid);
    return teardown(&f);
}

static int test_stopped_loop_still_discovers(void)
{
    fixture_t f = {0}; network_probe_t net = {0}; CHECK(setup(&f, &net, 100, 10) == 0);
    vireo_timer_handle_t h[2] = {0}; CHECK(timers(&f, h, 2, false) == 0);
    EXPECT(vireo_event_loop_request_stop(f.loop, NULL), VIREO_OK);
    clock_state_t clock = { .now_ns = 110 }; vireo_timer_loop_runtime_t ops = runtime(&clock);
    vireo_timer_loop_run_options_t options = { .max_wait_ms = 0, .advance_budget = {1, 3} };
    vireo_timer_loop_run_report_t report; vireo_timer_loop_diagnostic_t diagnostic;
    EXPECT(vireo_timer_loop_run_once_runtime(f.loop, f.wheel, &options, &report, &diagnostic, &ops), VIREO_OK);
    CHECK(report.loop.ready_count == 0 && report.loop.dispatched_count == 0 && report.loop.stale_count == 0 && report.loop.filtered_count == 0);
    CHECK(diagnostic.loop_completed && clock.clock_calls == 2 && clock.loop_calls == 1 && net.calls == 0);
    CHECK(report.advance.progress.ready_count == 2);
    delivery_probe_t delivery = { .wheel = f.wheel }; vireo_timer_loop_dispatch_report_t dispatched;
    EXPECT(vireo_timer_loop_dispatch(f.wheel, 2, deliver, &delivery, &dispatched), VIREO_OK);
    CHECK(dispatched.delivered_count == 2 && !delivery.invalid);
    return teardown(&f);
}

static int test_consumer_basic_rejection_after_round(void)
{
    fixture_t f = {0}; network_probe_t net = {0}; CHECK(setup(&f, &net, 100, 10) == 0);
    vireo_timer_handle_t h = {0}; CHECK(timers(&f, &h, 1, false) == 0);
    clock_state_t clock = { .now_ns = 110 }; vireo_timer_loop_runtime_t ops = runtime(&clock);
    vireo_timer_loop_run_options_t options = { .max_wait_ms = 0, .advance_budget = {1, 1} };
    vireo_timer_loop_run_report_t report; vireo_timer_loop_diagnostic_t diagnostic;
    CHECK(send_byte(&f) == 0);
    EXPECT(vireo_timer_loop_run_once_runtime(f.loop, f.wheel, &options, &report, &diagnostic, &ops), VIREO_OK);
    delivery_probe_t delivery = { .wheel = f.wheel };
    vireo_timer_loop_dispatch_report_t dispatched; memset(&dispatched, 0xa5, sizeof(dispatched));
    unsigned char old[sizeof(dispatched)]; memcpy(old, &dispatched, sizeof(old));
    EXPECT(vireo_timer_loop_dispatch(f.wheel, 0, deliver, &delivery, &dispatched), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(memcmp(old, &dispatched, sizeof(old)) == 0 && delivery.calls == 0 && net.calls == 1);
    vireo_timer_wheel_timer_info_t timer;
    EXPECT(vireo_timer_wheel_get(f.wheel, h, &timer), VIREO_OK);
    EXPECT(vireo_timer_loop_dispatch(f.wheel, 1, deliver, &delivery, &dispatched), VIREO_OK);
    CHECK(delivery.calls == 1 && !delivery.invalid);
    return teardown(&f);
}

static int test_network_rearm_withdraws_ready(void)
{
    fixture_t f = {0}; network_probe_t net = { .action = NETWORK_REARM };
    CHECK(setup(&f, &net, 100, 10) == 0);
    vireo_timer_handle_t h = {0}; CHECK(timers(&f, &h, 1, true) == 0); net.victim = h;
    clock_state_t clock = { .now_ns = 110 }; vireo_timer_loop_runtime_t ops = runtime(&clock);
    vireo_timer_loop_run_options_t options = { .max_wait_ms = 9, .advance_budget = {1, 1} };
    vireo_timer_loop_run_report_t report; vireo_timer_loop_diagnostic_t diagnostic;
    CHECK(send_byte(&f) == 0);
    EXPECT(vireo_timer_loop_run_once_runtime(f.loop, f.wheel, &options, &report, &diagnostic, &ops), VIREO_OK);
    CHECK(report.wait_plan.timeout_ms == 0 && report.advance.progress.ready_count == 0 && !net.invalid);
    delivery_probe_t delivery = { .wheel = f.wheel }; vireo_timer_loop_dispatch_report_t dispatched;
    EXPECT(vireo_timer_loop_dispatch(f.wheel, 1, deliver, &delivery, &dispatched), VIREO_OK);
    CHECK(delivery.calls == 0);
    vireo_timer_wheel_timer_info_t timer;
    EXPECT(vireo_timer_wheel_get(f.wheel, h, &timer), VIREO_OK); CHECK(timer.deadline_ns == 150);
    clock.now_ns = 150; options.advance_budget.max_ticks = 4;
    CHECK(send_byte(&f) == 0);
    EXPECT(vireo_timer_loop_run_once_runtime(f.loop, f.wheel, &options, &report, &diagnostic, &ops), VIREO_OK);
    CHECK(net.calls == 2 && report.advance.ticks_started == 4 && report.advance.progress.ready_count == 1);
    EXPECT(vireo_timer_loop_dispatch(f.wheel, 1, deliver, &delivery, &dispatched), VIREO_OK);
    CHECK(delivery.calls == 1 && same_handle(delivery.events[0].handle, h) && !delivery.invalid);
    CHECK(delivery.events[0].timer.deadline_ns == 150 && delivery.events[0].timer.due_tick == 5);
    return teardown(&f);
}

static int test_native_three_entries_and_time_debt(void)
{
    vireo_monotonic_ns_t sample;
    EXPECT(vireo_clock_monotonic_now(&sample, NULL), VIREO_OK); CHECK(sample > 0);
    fixture_t f = {0}; network_probe_t net = {0}; CHECK(setup(&f, &net, sample - 1, 1) == 0);
    vireo_timer_handle_t h = {0};
    EXPECT(vireo_timer_wheel_register(f.wheel, sample - 1, sample, &h), VIREO_OK);
    CHECK(send_byte(&f) == 0);
    vireo_timer_loop_run_options_t options = { .max_wait_ms = 0, .advance_budget = {1, 1} };
    vireo_timer_loop_run_report_t report; vireo_timer_loop_diagnostic_t diagnostic;
    EXPECT(vireo_timer_loop_run_once(f.loop, f.wheel, &options, &report, &diagnostic), VIREO_OK);
    CHECK(net.calls == 1 && !net.invalid && report.advance.progress.ready_count == 1);
    vireo_timer_loop_wait_plan_t plan;
    EXPECT(vireo_timer_loop_plan_wait(f.wheel, report.after_now_ns, 0, &plan), VIREO_OK);
    CHECK(plan.timer_work_pending);
    delivery_probe_t delivery = { .wheel = f.wheel }; vireo_timer_loop_dispatch_report_t dispatched;
    EXPECT(vireo_timer_loop_dispatch(f.wheel, 1, deliver, &delivery, &dispatched), VIREO_OK);
    CHECK(dispatched.delivered_count == 1 && delivery.calls == 1 && !delivery.invalid);
    vireo_timer_wheel_progress_t progress;
    EXPECT(vireo_timer_wheel_progress_inspect(f.wheel, &progress), VIREO_OK);
    CHECK(progress.ready_count == 0);
    vireo_timer_wheel_tick_t elapsed;
    EXPECT(vireo_timer_wheel_elapsed_tick(((vireo_timer_wheel_geometry_t){sample - 1, 1, 4}),
            report.after_now_ns, &elapsed), VIREO_OK);
    EXPECT(vireo_timer_loop_plan_wait(f.wheel, report.after_now_ns, 9, &plan), VIREO_OK);
    CHECK(plan.timer_work_pending == (progress.completed_tick < elapsed));
    CHECK(plan.timeout_ms == (plan.timer_work_pending ? 0 : 9));
    printf("native integration: ready consumed=1, remaining elapsed ticks=%llu\n",
            (unsigned long long)(elapsed - progress.completed_tick));
    return teardown(&f);
}

int main(void)
{
    int failures = 0;
    failures += test_pending_network_and_budgets();
    failures += test_delivery_failure_next_round();
    failures += test_late_clock_failure_recovery_choice();
    failures += test_network_stop_late_failure_and_cleanup();
    failures += test_delivery_stop_network_independent();
    failures += test_stopped_loop_still_discovers();
    failures += test_consumer_basic_rejection_after_round();
    failures += test_network_rearm_withdraws_ready();
    failures += test_native_three_entries_and_time_debt();
    printf("timer loop integration: 9 groups, %d failures; 8 mixed-clock cases, 1 full native case\n", failures);
    return failures == 0 ? 0 : 1;
}
