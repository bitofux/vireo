/*
- PROJECT : VIREO
- FILE    : test_connection_flow.c
- AUTHOR  : bitofux
- DATE    : 2026-10-04
- BRIEF   : 此模块负责：
- -- 真实固定双 buffer 占用、迟滞阈值、半帧恢复与 EOF 的关注合同
- -- 必要 MOD、失败保留、显式重试和模式生命周期
 */
#define _GNU_SOURCE
#include <vireo/net/connection.h>
#include "net/connection_internal.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static unsigned failures;
#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition); \
        ++failures; \
    } \
} while (0)
#define REQUIRE(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "%s:%d: required %s\n", __FILE__, __LINE__, #condition); \
        exit(2); \
    } \
} while (0)

#define INPUT (VIREO_EPOLL_INTEREST_READ | VIREO_EPOLL_INTEREST_PEER_WRITE_CLOSED)
#define OUTPUT VIREO_EPOLL_INTEREST_WRITE
static vireo_connection_flow_options_t const policy = {64, 63, 96, 32, 96};

/* 地址在全部借用期固定；只包装公共 loop，不访问旧模块私有布局。 */
typedef struct fixture {
    vireo_connection_t *connection;
    vireo_event_loop_t *loop;
    vireo_event_loop_handle_t handle;
    int peer, fail_mod;
    size_t mods, calls;
    uint32_t events;
    bool callback_refresh;
} fixture_t;

/* 独立按值快照，不延长 read 借用。 */
static vireo_connection_info_t state(fixture_t const *f)
{
    vireo_connection_info_t info;
    REQUIRE(vireo_connection_inspect(f->connection, &info) == VIREO_OK);
    return info;
}

static vireo_result_t add_binding(void *context, vireo_event_loop_t *loop,
                                  vireo_event_loop_registration_t const *registration,
                                  vireo_event_loop_handle_t *handle,
                                  vireo_event_loop_error_t *error)
{
    fixture_t *f = context;
    vireo_result_t result = vireo_event_loop_add(loop, registration, handle, error);
    if (result == VIREO_OK) f->handle = *handle;
    return result;
}

/* 失败没有内核更新；调用过程中本地状态仍须与真实登记的旧关注一致。 */
static vireo_result_t mod_binding(void *context, vireo_event_loop_t *loop,
                                  vireo_event_loop_handle_t handle, uint32_t interests,
                                  vireo_event_loop_error_t *error)
{
    fixture_t *f = context;
    vireo_event_loop_registration_t registration;
    REQUIRE(vireo_event_loop_registration_inspect(loop, handle, &registration) == VIREO_OK);
    CHECK(registration.interests == state(f).loop_interests);
    ++f->mods;
    errno = EDOM;
    if (f->fail_mod != 0) {
        if (error != NULL) {
            *error = (vireo_event_loop_error_t){0};
            error->stage = VIREO_EVENT_LOOP_STAGE_MOD;
            error->epoll_error.stage = VIREO_EPOLL_STAGE_MOD;
            error->epoll_error.system_errno = f->fail_mod;
        }
        return VIREO_RESULT_IO;
    }
    return vireo_event_loop_mod(loop, handle, interests, error);
}

static vireo_result_t del_binding(void *context, vireo_event_loop_t *loop,
                                  vireo_event_loop_handle_t *handle,
                                  vireo_event_loop_error_t *error)
{
    (void)context;
    return vireo_event_loop_del(loop, handle, error);
}

/* 默认只观察；指定动作验证策略可在自己的回调内刷新/禁用/重新配置。 */
static void on_ready(vireo_connection_t *connection, uint32_t events, void *context)
{
    fixture_t *f = context;
    CHECK(connection == f->connection && state(f).callback_active);
    ++f->calls;
    f->events = events;
    if (f->callback_refresh) {
        uint8_t const byte = 'X';
        REQUIRE(vireo_connection_write_enqueue(connection, &byte, 1, NULL) == VIREO_OK);
        errno = E2BIG;
        REQUIRE(vireo_connection_flow_refresh(connection, NULL) == VIREO_OK);
        CHECK(errno == E2BIG && state(f).loop_interests == (INPUT | OUTPUT));
        REQUIRE(vireo_connection_flow_disable(connection, NULL) == VIREO_OK);
        REQUIRE(vireo_connection_flow_configure(connection, &policy, NULL) == VIREO_OK);
        CHECK(state(f).callback_active);
    }
}

static void setup_capacity(fixture_t *f, size_t read_capacity, size_t write_capacity)
{
    *f = (fixture_t){0};
    int pair[2];
    REQUIRE(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, pair) == 0);
    f->peer = pair[1];
    vireo_connection_options_t options = {
        read_capacity, write_capacity, read_capacity + write_capacity
    };
    vireo_connection_loop_ops_t ops = {f, add_binding, mod_binding, del_binding};
    REQUIRE(vireo_connection_create_with_loop_ops(&options, &pair[0], &ops,
                                                  &f->connection, NULL) == VIREO_OK);
    CHECK(pair[0] == -1 && !state(f).flow_enabled);
    vireo_event_loop_options_t loop_options = {8, 65536, 4};
    REQUIRE(vireo_event_loop_create(&loop_options, &f->loop, NULL) == VIREO_OK);
    REQUIRE(vireo_connection_attach(f->connection, f->loop, INPUT,
                                     on_ready, f, NULL) == VIREO_OK);
}

static void setup(fixture_t *f)
{
    setup_capacity(f, 128, 128);
}

static void cleanup(fixture_t *f)
{
    REQUIRE(vireo_connection_detach(f->connection, NULL) == VIREO_OK);
    CHECK(!state(f).flow_enabled);
    REQUIRE(vireo_connection_destroy(&f->connection, NULL) == VIREO_OK);
    if (f->loop != NULL) REQUIRE(vireo_event_loop_destroy(&f->loop, NULL) == VIREO_OK);
    REQUIRE(close(f->peer) == 0);
}

/* 小量真实数据只从 peer 进入公开 receive，不伪造 buffer 长度。 */
static void feed(fixture_t *f, uint8_t const *bytes, size_t size)
{
    REQUIRE(send(f->peer, bytes, size, MSG_NOSIGNAL) == (ssize_t)size);
    vireo_connection_receive_budget_t budget = {size, 8};
    vireo_connection_receive_info_t info;
    REQUIRE(vireo_connection_receive(f->connection, &budget, &info, NULL) == VIREO_OK);
    CHECK(info.received_bytes == size);
}

static void enqueue(fixture_t *f, size_t size)
{
    uint8_t bytes[128];
    REQUIRE(size <= sizeof(bytes));
    memset(bytes, 'W', sizeof(bytes));
    REQUIRE(vireo_connection_write_enqueue(f->connection, bytes, size, NULL) == VIREO_OK);
}

/* send 真实消耗已确认前缀，peer 单独读出并核对，没有假造发送进度。 */
static void drain(fixture_t *f, size_t size)
{
    vireo_connection_send_budget_t budget = {size, 8};
    vireo_connection_send_info_t info;
    errno = E2BIG;
    REQUIRE(vireo_connection_send(f->connection, &budget, &info, NULL) == VIREO_OK);
    CHECK(info.sent_bytes == size && errno == E2BIG);
    uint8_t bytes[128];
    REQUIRE(size <= sizeof(bytes));
    REQUIRE(recv(f->peer, bytes, size, 0) == (ssize_t)size);
    for (size_t i = 0; i < size; ++i) CHECK(bytes[i] == 'W');
}

/* 每次成功刷新同时核对真实登记；带脏诊断验证所有成员清零。 */
static void refresh(fixture_t *f, uint32_t mask, bool read_pressure, bool write_pressure)
{
    vireo_connection_loop_error_t error;
    memset(&error, 0xa5, sizeof(error));
    errno = E2BIG;
    REQUIRE(vireo_connection_flow_refresh(f->connection, &error) == VIREO_OK);
    CHECK(errno == E2BIG && error.stage == VIREO_CONNECTION_LOOP_STAGE_NONE);
    CHECK(error.loop_error.stage == VIREO_EVENT_LOOP_STAGE_NONE);
    CHECK(error.loop_error.system_errno == 0 && error.loop_error.epoll_error.system_errno == 0);
    vireo_connection_info_t info = state(f);
    CHECK(info.flow_enabled && info.loop_interests == mask);
    CHECK(info.read_pressure == read_pressure && info.write_pressure == write_pressure);
    vireo_event_loop_registration_t registration;
    REQUIRE(vireo_event_loop_registration_inspect(f->loop, f->handle,
                                                   &registration) == VIREO_OK);
    CHECK(registration.interests == mask);
}

static void configure(fixture_t *f)
{
    errno = E2BIG;
    REQUIRE(vireo_connection_flow_configure(f->connection, &policy, NULL) == VIREO_OK);
    CHECK(errno == E2BIG && state(f).flow_enabled);
}

/* NULL、未绑定、禁用和全部五值的边界拒绝均不得发起 MOD 或发布候选。 */
static void test_parameters(void)
{
    fixture_t f;
    setup(&f);
    vireo_connection_loop_error_t error;
    errno = E2BIG;
    CHECK(vireo_connection_flow_configure(NULL, &policy, &error) ==
          VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_connection_flow_configure(f.connection, NULL, NULL) ==
          VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_connection_flow_refresh(NULL, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_connection_flow_disable(NULL, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_connection_flow_refresh(f.connection, NULL) == VIREO_RESULT_NOT_FOUND);
    CHECK(errno == E2BIG);
    vireo_connection_flow_options_t invalid[] = {
        {0, 63, 96, 32, 96}, {31, 63, 96, 32, 96}, {129, 128, 128, 32, 96},
        {SIZE_MAX, SIZE_MAX, SIZE_MAX, 32, 96}, {64, 62, 96, 32, 96},
        {64, 96, 96, 32, 96}, {64, 100, 96, 32, 96}, {64, 63, 129, 32, 96},
        {64, 63, 96, 0, 0}, {64, 63, 96, 96, 96}, {64, 63, 96, 97, 96},
        {64, 63, 96, 32, 129}
    };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
        memset(&error, 0xa5, sizeof(error));
        CHECK(vireo_connection_flow_configure(f.connection, &invalid[i], &error) ==
              VIREO_RESULT_RANGE);
        CHECK(errno == E2BIG && !state(&f).flow_enabled && state(&f).loop_interests == INPUT);
        CHECK(error.stage == VIREO_CONNECTION_LOOP_STAGE_NONE);
        CHECK(error.loop_error.epoll_error.system_errno == 0 && f.mods == 0);
    }
    configure(&f);
    CHECK(vireo_connection_flow_configure(f.connection, &invalid[4], NULL) == VIREO_RESULT_RANGE);
    CHECK(state(&f).flow_options.read_low == 63 && f.mods == 0);
    REQUIRE(vireo_connection_detach(f.connection, NULL) == VIREO_OK);
    CHECK(vireo_connection_flow_configure(f.connection, &policy, NULL) == VIREO_RESULT_NOT_FOUND);
    CHECK(vireo_connection_flow_refresh(f.connection, NULL) == VIREO_RESULT_NOT_FOUND);
    CHECK(vireo_connection_flow_disable(f.connection, NULL) == VIREO_OK);
    cleanup(&f);
}

/* 最小帧/容量、精确 full 阈值和零写低水位；小于头的旧对象仍可 raw receive。 */
static void test_capacity_edges(void)
{
    fixture_t f;
    setup_capacity(&f, 32, 1);
    vireo_connection_flow_options_t options = {32, 31, 32, 0, 1};
    REQUIRE(vireo_connection_flow_configure(f.connection, &options, NULL) == VIREO_OK);
    uint8_t bytes[32] = {0};
    feed(&f, bytes, 32);
    enqueue(&f, 1);
    refresh(&f, OUTPUT, true, true);
    drain(&f, 1);
    refresh(&f, 0, true, false);
    REQUIRE(vireo_connection_read_consume(f.connection, 1) == VIREO_OK);
    refresh(&f, INPUT, false, false);
    cleanup(&f);
    setup_capacity(&f, 31, 1);
    CHECK(vireo_connection_flow_configure(f.connection, &options, NULL) == VIREO_RESULT_RANGE);
    feed(&f, bytes, 1);
    CHECK(state(&f).read_buffer.readable_size == 1 && !state(&f).flow_enabled);
    cleanup(&f);
}

/* 写压力：恰 high 锁，区间保持，恰 low 解锁；空队列撤 WRITE。 */
static void test_write_hysteresis(void)
{
    fixture_t f;
    setup(&f);
    configure(&f);
    enqueue(&f, 95);
    CHECK(state(&f).loop_interests == INPUT && !state(&f).write_pressure);
    refresh(&f, INPUT | OUTPUT, false, false);
    vireo_event_loop_run_info_t info;
    REQUIRE(vireo_event_loop_run_once(f.loop, 0, &info, NULL) == VIREO_OK);
    CHECK(f.calls == 1 && (f.events & VIREO_EPOLL_EVENT_WRITE) != 0);
    CHECK(state(&f).write_buffer.readable_size == 95); /* 包装不自动发送。 */
    enqueue(&f, 1);
    refresh(&f, OUTPUT, false, true);
    drain(&f, 63);
    refresh(&f, OUTPUT, false, true); /* pending=33，仍压力。 */
    drain(&f, 1);
    refresh(&f, INPUT | OUTPUT, false, false);
    drain(&f, 32);
    refresh(&f, INPUT, false, false);
    size_t mods = f.mods;
    refresh(&f, INPUT, false, false);
    CHECK(f.mods == mods);
    REQUIRE(vireo_event_loop_run_once(f.loop, 0, &info, NULL) == VIREO_OK);
    CHECK(info.ready_count == 0 && f.calls == 1); /* 空 WRITE 不再反复就绪。 */
    cleanup(&f);
}

/* 读压力和 head hole：阈值使用 readable_size，不能误用连续 tail_space。 */
static void test_read_hysteresis(void)
{
    fixture_t f;
    setup(&f);
    configure(&f);
    uint8_t bytes[96] = {0};
    feed(&f, bytes, 95);
    refresh(&f, INPUT, false, false);
    feed(&f, bytes, 1);
    refresh(&f, 0, true, false);
    REQUIRE(vireo_connection_read_consume(f.connection, 32) == VIREO_OK);
    refresh(&f, 0, true, false); /* readable=64，tail_space 仍仅 32。 */
    REQUIRE(vireo_connection_read_consume(f.connection, 1) == VIREO_OK);
    refresh(&f, INPUT, false, false); /* 恰 read_low。 */
    CHECK(state(&f).read_buffer.tail_space == 32);
    cleanup(&f);
}

/* 正确 CRC 的两帧通过公共 codec 构造；业务仅在验证后消费完整前缀。 */
static void make_frame(uint8_t wire[64], uint32_t sequence)
{
    vireo_protocol_header_t header = {0};
    header.command = VIREO_COMMAND_PING;
    header.sequence = sequence;
    header.status = VIREO_PROTOCOL_REQUEST_STATUS;
    header.body_len = 32;
    memset(wire + 32, (int)sequence, 32);
    REQUIRE(vireo_protocol_header_encode(&header, wire, 64) == VIREO_OK);
    REQUIRE(vireo_protocol_frame_crc32c_calculate(wire, 32, wire + 32, 32,
                                                  &header.crc32c) == VIREO_OK);
    REQUIRE(vireo_protocol_header_encode(&header, wire, 64) == VIREO_OK);
}

static void test_half_frame_recovery(void)
{
    fixture_t f;
    setup(&f);
    configure(&f);
    uint8_t wire[128];
    make_frame(wire, 1);
    make_frame(wire + 64, 2);
    feed(&f, wire, 100); /* 完整 64 + 合法半帧 36。 */
    refresh(&f, 0, true, false);
    vireo_connection_frame_options_t options = {VIREO_CONNECTION_FRAME_REQUEST, 64};
    vireo_connection_frame_budget_t budget = {8, 128};
    vireo_connection_frame_view_t views[2];
    vireo_connection_frame_info_t frames;
    REQUIRE(vireo_connection_frames_peek(f.connection, &options, &budget,
                                          views, 2, &frames, NULL) == VIREO_OK);
    CHECK(frames.frame_count == 1 && frames.frame_bytes == 64);
    CHECK(frames.stop_reason == VIREO_CONNECTION_FRAME_STOP_NEED_MORE);
    REQUIRE(vireo_connection_read_consume(f.connection, 64) == VIREO_OK);
    refresh(&f, INPUT, false, false);
    REQUIRE(send(f.peer, wire + 100, 28, MSG_NOSIGNAL) == 28);
    vireo_event_loop_run_info_t run;
    REQUIRE(vireo_event_loop_run_once(f.loop, 0, &run, NULL) == VIREO_OK);
    CHECK(f.calls == 1 && (f.events & VIREO_EPOLL_EVENT_READ) != 0);
    vireo_connection_receive_budget_t receive_budget = {128, 8};
    vireo_connection_receive_info_t received;
    REQUIRE(vireo_connection_receive(f.connection, &receive_budget, &received, NULL) == VIREO_OK);
    CHECK(received.received_bytes == 28);
    REQUIRE(vireo_connection_frames_peek(f.connection, &options, &budget,
                                          views, 2, &frames, NULL) == VIREO_OK);
    CHECK(frames.frame_count == 1 && views[0].header.sequence == 2);
    CHECK(views[0].body_size == 32 && views[0].body[0] == 2);
    cleanup(&f);
}

/* 初配、重配、刷新失败都不提前发布；失败后的 send 真进度绝不回滚。 */
static void test_mod_failure(int cause)
{
    fixture_t f;
    setup(&f);
    enqueue(&f, 100);
    f.fail_mod = cause;
    vireo_connection_loop_error_t error;
    errno = E2BIG;
    CHECK(vireo_connection_flow_configure(f.connection, &policy, &error) == VIREO_RESULT_IO);
    CHECK(errno == E2BIG && f.mods == 1 && !state(&f).flow_enabled);
    CHECK(error.stage == VIREO_CONNECTION_LOOP_STAGE_FLOW_CONFIGURE);
    CHECK(error.loop_error.stage == VIREO_EVENT_LOOP_STAGE_MOD);
    CHECK(error.loop_error.epoll_error.stage == VIREO_EPOLL_STAGE_MOD);
    CHECK(error.loop_error.epoll_error.system_errno == cause);
    CHECK(state(&f).loop_interests == INPUT && state(&f).write_buffer.readable_size == 100);
    f.fail_mod = 0;
    configure(&f);
    refresh(&f, OUTPUT, false, true);
    vireo_connection_flow_options_t new_options = {64, 63, 96, 0, 128};
    f.fail_mod = cause;
    CHECK(vireo_connection_flow_configure(f.connection, &new_options, &error) == VIREO_RESULT_IO);
    CHECK(state(&f).flow_options.write_high == 96 && state(&f).write_pressure);
    CHECK(state(&f).loop_interests == OUTPUT);
    drain(&f, 68); /* 真正发出 68，待发 32，旧压力仍锁着。 */
    size_t mods = f.mods;
    errno = E2BIG;
    CHECK(vireo_connection_flow_refresh(f.connection, &error) == VIREO_RESULT_IO);
    CHECK(errno == E2BIG && f.mods == mods + 1);
    CHECK(error.stage == VIREO_CONNECTION_LOOP_STAGE_FLOW_REFRESH);
    CHECK(error.loop_error.epoll_error.system_errno == cause);
    CHECK(state(&f).write_pressure && state(&f).write_buffer.readable_size == 32);
    CHECK(state(&f).loop_interests == OUTPUT);
    CHECK(vireo_connection_flow_refresh(f.connection, NULL) == VIREO_RESULT_IO);
    CHECK(f.mods == mods + 2 && errno == E2BIG);
    f.fail_mod = 0;
    refresh(&f, INPUT | OUTPUT, false, false);
    drain(&f, 32);
    refresh(&f, INPUT, false, false);
    cleanup(&f);
}

/* 两压力交叠时 mask 可不变；无需 MOD 也必须提交锁存更新。 */
static void test_same_mask_and_reset(void)
{
    fixture_t f;
    setup(&f);
    configure(&f);
    uint8_t bytes[96] = {0};
    feed(&f, bytes, 96);
    enqueue(&f, 96);
    refresh(&f, OUTPUT, true, true);
    size_t mods = f.mods;
    drain(&f, 64);
    refresh(&f, OUTPUT, true, false);
    CHECK(f.mods == mods);
    REQUIRE(vireo_connection_read_consume(f.connection, 33) == VIREO_OK);
    refresh(&f, INPUT | OUTPUT, false, false);
    enqueue(&f, 64);
    refresh(&f, OUTPUT, false, true);
    drain(&f, 46); /* 待发 50 在中间，锁存继续保持。 */
    refresh(&f, OUTPUT, false, true);
    configure(&f); /* 同阈值显式重新配置从未锁初始化，50 < high。 */
    CHECK(!state(&f).write_pressure && state(&f).loop_interests == (INPUT | OUTPUT));
    cleanup(&f);
}

static void test_eof(void)
{
    fixture_t f;
    setup(&f);
    configure(&f);
    uint8_t bytes[3] = {'A', 'B', 'C'};
    feed(&f, bytes, 3);
    REQUIRE(shutdown(f.peer, SHUT_WR) == 0);
    vireo_connection_receive_budget_t budget = {128, 8};
    vireo_connection_receive_info_t received;
    REQUIRE(vireo_connection_receive(f.connection, &budget, &received, NULL) == VIREO_OK);
    CHECK(state(&f).read_eof && state(&f).loop_interests == INPUT);
    enqueue(&f, 3);
    refresh(&f, OUTPUT, false, false);
    drain(&f, 3);
    refresh(&f, 0, false, false);
    CHECK(state(&f).read_buffer.readable_size == 3 && state(&f).read_eof);
    cleanup(&f);
}

static void test_mode_lifecycle(void)
{
    fixture_t f;
    setup(&f);
    configure(&f);
    CHECK(vireo_connection_set_interests(f.connection, 0, NULL) == VIREO_RESULT_BUSY);
    CHECK(vireo_connection_set_interests(f.connection, UINT32_MAX, NULL) ==
          VIREO_RESULT_INVALID_ARGUMENT);
    enqueue(&f, 100);
    refresh(&f, OUTPUT, false, true);
    size_t mods = f.mods;
    errno = E2BIG;
    REQUIRE(vireo_connection_flow_disable(f.connection, NULL) == VIREO_OK);
    REQUIRE(vireo_connection_flow_disable(f.connection, NULL) == VIREO_OK);
    CHECK(errno == E2BIG && f.mods == mods && state(&f).loop_interests == OUTPUT);
    CHECK(!state(&f).write_pressure && state(&f).flow_options.max_frame_bytes == 0);
    REQUIRE(vireo_connection_set_interests(f.connection, INPUT, NULL) == VIREO_OK);
    configure(&f);
    REQUIRE(vireo_connection_detach(f.connection, NULL) == VIREO_OK);
    CHECK(!state(&f).flow_enabled && !state(&f).write_pressure);
    REQUIRE(vireo_connection_attach(f.connection, f.loop, INPUT, on_ready, &f, NULL) == VIREO_OK);
    CHECK(!state(&f).flow_enabled);
    configure(&f);
    REQUIRE(vireo_event_loop_destroy(&f.loop, NULL) == VIREO_OK);
    CHECK(state(&f).flow_enabled); /* 仅安全观察，不刷新悬空 loop。 */
    REQUIRE(vireo_connection_forget_destroyed_loop(f.connection, NULL) == VIREO_OK);
    CHECK(!state(&f).flow_enabled && !state(&f).read_pressure && !state(&f).write_pressure);
    CHECK(state(&f).flow_options.read_high == 0 && state(&f).write_buffer.readable_size == 100);
    cleanup(&f);
}

/* 启用期 framing 上限拒绝必须原字节保持全部输出；流操作保持现有 read 借用。 */
static void test_frame_limit_and_borrow(void)
{
    fixture_t f;
    setup(&f);
    uint8_t wire[64];
    make_frame(wire, 1);
    feed(&f, wire, 64);
    uint8_t const *borrow;
    size_t size;
    REQUIRE(vireo_connection_read_peek(f.connection, &borrow, &size) == VIREO_OK);
    CHECK(size == 64);
    configure(&f);
    refresh(&f, INPUT, false, false);
    CHECK(memcmp(borrow, wire, 64) == 0);
    vireo_connection_frame_options_t options = {VIREO_CONNECTION_FRAME_REQUEST, 65};
    vireo_connection_frame_budget_t budget = {8, 128};
    vireo_connection_frame_view_t views[2];
    vireo_connection_frame_info_t info;
    memset(views, 0xa5, sizeof(views));
    memset(&info, 0xa5, sizeof(info));
    unsigned char old_views[sizeof(views)], old_info[sizeof(info)];
    memcpy(old_views, views, sizeof(views));
    memcpy(old_info, &info, sizeof(info));
    errno = E2BIG;
    CHECK(vireo_connection_frames_peek(f.connection, &options, &budget,
                                        views, 2, &info, NULL) == VIREO_RESULT_RANGE);
    CHECK(errno == E2BIG && memcmp(views, old_views, sizeof(views)) == 0);
    CHECK(memcmp(&info, old_info, sizeof(info)) == 0 && memcmp(borrow, wire, 64) == 0);
    options.max_frame_bytes = 64;
    REQUIRE(vireo_connection_frames_peek(f.connection, &options, &budget,
                                          views, 2, &info, NULL) == VIREO_OK);
    CHECK(info.frame_count == 1 && views[0].body == borrow + 32);
    REQUIRE(vireo_connection_flow_disable(f.connection, NULL) == VIREO_OK);
    options.max_frame_bytes = 65;
    REQUIRE(vireo_connection_frames_peek(f.connection, &options, &budget,
                                          views, 2, &info, NULL) == VIREO_OK);
    CHECK(memcmp(borrow, wire, 64) == 0);
    cleanup(&f);
}

static void test_callback(void)
{
    fixture_t f;
    setup(&f);
    configure(&f);
    f.callback_refresh = true;
    REQUIRE(send(f.peer, "R", 1, MSG_NOSIGNAL) == 1);
    vireo_event_loop_run_info_t info;
    REQUIRE(vireo_event_loop_run_once(f.loop, 0, &info, NULL) == VIREO_OK);
    CHECK(f.calls == 1 && !state(&f).callback_active);
    CHECK(state(&f).write_buffer.readable_size == 1 && state(&f).flow_enabled);
    cleanup(&f);
}

static void test_independent_connections(void)
{
    fixture_t a, b;
    setup(&a);
    setup(&b);
    configure(&a);
    configure(&b);
    enqueue(&a, 100);
    refresh(&a, OUTPUT, false, true);
    refresh(&b, INPUT, false, false);
    CHECK(b.mods == 0 && state(&b).write_buffer.readable_size == 0);
    REQUIRE(send(b.peer, "B", 1, MSG_NOSIGNAL) == 1);
    vireo_event_loop_run_info_t info;
    REQUIRE(vireo_event_loop_run_once(b.loop, 0, &info, NULL) == VIREO_OK);
    CHECK(b.calls == 1 && (b.events & VIREO_EPOLL_EVENT_READ) != 0 && a.calls == 0);
    cleanup(&a);
    cleanup(&b);
}

static size_t fd_count(void)
{
    DIR *directory = opendir("/proc/self/fd");
    REQUIRE(directory != NULL);
    size_t count = 0;
    struct dirent *entry;
    while ((entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) ++count;
    }
    REQUIRE(closedir(directory) == 0);
    return count;
}

int main(void)
{
    size_t baseline = fd_count();
    test_parameters();
    test_capacity_edges();
    test_write_hysteresis();
    test_read_hysteresis();
    test_half_frame_recovery();
    test_mod_failure(EINTR);
    test_mod_failure(EIO);
    test_mod_failure(ENOMEM);
    test_same_mask_and_reset();
    test_eof();
    test_mode_lifecycle();
    test_frame_limit_and_borrow();
    test_callback();
    test_independent_connections();
    CHECK(fd_count() == baseline);
    printf("connection flow: 14 groups, %u failures; fd baseline checked\n", failures);
    return failures == 0 ? 0 : 1;
}
