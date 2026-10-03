/*
- PROJECT : VIREO
- FILE    : test_connection_close.c
- AUTHOR  : bitofux
- DATE    : 2026-10-04
- BRIEF   : 此模块负责：
- -- 永久关闭、已有队列排空、真实发送和上层安全释放
- -- MOD/DEL 故障、关闭期状态守卫和在途借用
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
    bool callback_close;
    int fail_del;
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
    fixture_t *f = context;
    if (f->fail_del != 0) {
        if (error != NULL) {
            *error = (vireo_event_loop_error_t){0};
            error->stage = VIREO_EVENT_LOOP_STAGE_DEL;
            error->epoll_error.stage = VIREO_EPOLL_STAGE_DEL;
            error->epoll_error.system_errno = f->fail_del;
        }
        return VIREO_RESULT_IO;
    }
    return vireo_event_loop_del(loop, handle, error);
}

/* 在真实回调中请求排空并注销，确认 active 独立保护到正常返回。 */
static void on_ready(vireo_connection_t *connection, uint32_t events, void *context)
{
    fixture_t *f = context;
    CHECK(connection == f->connection && state(f).callback_active);
    ++f->calls;
    f->events = events;
    if (f->callback_close) {
        REQUIRE(vireo_connection_request_close(connection, VIREO_CONNECTION_CLOSE_MODE_DRAIN,
            VIREO_CONNECTION_CLOSE_REASON_APPLICATION, NULL) == VIREO_OK);
        CHECK(state(f).close_state == VIREO_CONNECTION_CLOSE_DRAINING);
        REQUIRE(vireo_connection_detach(connection, NULL) == VIREO_OK);
        CHECK(state(f).callback_active && !state(f).loop_attached);
        CHECK(vireo_connection_destroy(&f->connection, NULL) == VIREO_RESULT_BUSY);
        CHECK(vireo_connection_attach(connection, f->loop, INPUT,
                                        on_ready, f, NULL) == VIREO_RESULT_BUSY);
        CHECK(vireo_connection_forget_destroyed_loop(connection, NULL) == VIREO_RESULT_BUSY);
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

static void configure(fixture_t *f)
{
    errno = E2BIG;
    REQUIRE(vireo_connection_flow_configure(f->connection, &policy, NULL) == VIREO_OK);
    CHECK(errno == E2BIG && state(f).flow_enabled);
}

/* 检查逻辑阶段与真实登记，不把 READY 当成 fd 已关闭。 */
static void closed(fixture_t *f, vireo_connection_close_state_t expected, uint32_t mask)
{
    CHECK(state(f).close_state == expected && state(f).loop_interests == mask);
    if (state(f).loop_attached) {
        vireo_event_loop_registration_t registration;
        REQUIRE(vireo_event_loop_registration_inspect(f->loop, f->handle,
                                                       &registration) == VIREO_OK);
        CHECK(registration.interests == mask);
    }
}

static void request(fixture_t *f, vireo_connection_close_mode_t mode)
{
    errno = E2BIG;
    REQUIRE(vireo_connection_request_close(f->connection, mode,
        VIREO_CONNECTION_CLOSE_REASON_SERVER_STOP, NULL) == VIREO_OK);
    CHECK(errno == E2BIG && state(f).close_mode == mode);
}

static void sync_close(fixture_t *f)
{
    vireo_connection_loop_error_t error;
    memset(&error, 0xa5, sizeof(error));
    errno = E2BIG;
    REQUIRE(vireo_connection_close_refresh(f->connection, &error) == VIREO_OK);
    CHECK(errno == E2BIG && error.stage == VIREO_CONNECTION_LOOP_STAGE_NONE);
    CHECK(error.loop_error.stage == VIREO_EVENT_LOOP_STAGE_NONE);
    CHECK(error.loop_error.system_errno == 0 && error.loop_error.epoll_error.system_errno == 0);
}

static void test_parameters(void)
{
    fixture_t f;
    setup(&f);
    CHECK(state(&f).close_state == VIREO_CONNECTION_CLOSE_OPEN);
    CHECK(state(&f).close_mode == VIREO_CONNECTION_CLOSE_MODE_NONE);
    CHECK(state(&f).close_reason == VIREO_CONNECTION_CLOSE_REASON_NONE);
    vireo_connection_loop_error_t error;
    errno = E2BIG;
    CHECK(vireo_connection_request_close(NULL, VIREO_CONNECTION_CLOSE_MODE_DRAIN,
        VIREO_CONNECTION_CLOSE_REASON_APPLICATION, &error) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_connection_close_refresh(NULL, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_connection_close_refresh(f.connection, NULL) == VIREO_RESULT_NOT_FOUND);
    vireo_connection_close_mode_t modes[] = {
        VIREO_CONNECTION_CLOSE_MODE_NONE, (vireo_connection_close_mode_t)3,
        (vireo_connection_close_mode_t)-1
    };
    for (size_t i = 0; i < sizeof(modes) / sizeof(modes[0]); ++i) {
        CHECK(vireo_connection_request_close(f.connection, modes[i],
            VIREO_CONNECTION_CLOSE_REASON_APPLICATION, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    }
    vireo_connection_close_reason_t reasons[] = {
        VIREO_CONNECTION_CLOSE_REASON_NONE, (vireo_connection_close_reason_t)7,
        (vireo_connection_close_reason_t)-1
    };
    for (size_t i = 0; i < sizeof(reasons) / sizeof(reasons[0]); ++i) {
        memset(&error, 0xa5, sizeof(error));
        CHECK(vireo_connection_request_close(f.connection, VIREO_CONNECTION_CLOSE_MODE_DRAIN,
            reasons[i], &error) == VIREO_RESULT_INVALID_ARGUMENT);
        CHECK(error.stage == VIREO_CONNECTION_LOOP_STAGE_NONE);
        CHECK(error.loop_error.epoll_error.system_errno == 0);
    }
    CHECK(errno == E2BIG && f.mods == 0 && state(&f).close_state == VIREO_CONNECTION_CLOSE_OPEN);
    cleanup(&f);
}

static void test_unbound(void)
{
    fixture_t f;
    setup(&f);
    REQUIRE(vireo_connection_detach(f.connection, NULL) == VIREO_OK);
    enqueue(&f, 100);
    request(&f, VIREO_CONNECTION_CLOSE_MODE_DRAIN);
    closed(&f, VIREO_CONNECTION_CLOSE_DRAINING, 0);
    drain(&f, 40);
    sync_close(&f);
    closed(&f, VIREO_CONNECTION_CLOSE_DRAINING, 0);
    drain(&f, 60);
    CHECK(state(&f).close_state == VIREO_CONNECTION_CLOSE_DRAINING);
    sync_close(&f);
    closed(&f, VIREO_CONNECTION_CLOSE_READY, 0);
    CHECK(f.mods == 0);
    CHECK(vireo_connection_attach(f.connection, f.loop, INPUT,
                                    on_ready, &f, NULL) == VIREO_RESULT_BUSY);
    cleanup(&f);
}

static void test_empty_drain(void)
{
    fixture_t f;
    setup(&f);
    request(&f, VIREO_CONNECTION_CLOSE_MODE_DRAIN);
    closed(&f, VIREO_CONNECTION_CLOSE_READY, 0);
    CHECK(f.mods == 1);
    request(&f, VIREO_CONNECTION_CLOSE_MODE_DRAIN);
    sync_close(&f);
    CHECK(f.mods == 1);
    CHECK(vireo_connection_destroy(&f.connection, NULL) == VIREO_RESULT_BUSY);
    cleanup(&f);
}

static void test_drain(void)
{
    fixture_t f;
    setup(&f);
    configure(&f);
    enqueue(&f, 100);
    request(&f, VIREO_CONNECTION_CLOSE_MODE_DRAIN);
    closed(&f, VIREO_CONNECTION_CLOSE_DRAINING, OUTPUT);
    CHECK(state(&f).flow_enabled && !state(&f).write_pressure);
    vireo_event_loop_run_info_t info;
    REQUIRE(vireo_event_loop_run_once(f.loop, 0, &info, NULL) == VIREO_OK);
    CHECK(f.calls == 1 && (f.events & VIREO_EPOLL_EVENT_WRITE) != 0);
    CHECK(state(&f).write_buffer.readable_size == 100);
    drain(&f, 40);
    sync_close(&f);
    closed(&f, VIREO_CONNECTION_CLOSE_DRAINING, OUTPUT);
    CHECK(f.mods == 1);
    drain(&f, 60);
    CHECK(state(&f).close_state == VIREO_CONNECTION_CLOSE_DRAINING);
    sync_close(&f);
    closed(&f, VIREO_CONNECTION_CLOSE_READY, 0);
    CHECK(f.mods == 2);
    REQUIRE(vireo_event_loop_run_once(f.loop, 0, &info, NULL) == VIREO_OK);
    CHECK(info.ready_count == 0 && f.calls == 1);
    cleanup(&f);
}

static void test_immediate(void)
{
    fixture_t f;
    setup(&f);
    uint8_t bytes[] = {'R', 'E', 'A', 'D'};
    feed(&f, bytes, sizeof(bytes));
    enqueue(&f, 100);
    uint8_t const *borrow;
    size_t size;
    REQUIRE(vireo_connection_read_peek(f.connection, &borrow, &size) == VIREO_OK);
    request(&f, VIREO_CONNECTION_CLOSE_MODE_IMMEDIATE);
    closed(&f, VIREO_CONNECTION_CLOSE_READY, 0);
    CHECK(state(&f).write_buffer.readable_size == 100 && size == sizeof(bytes));
    CHECK(memcmp(borrow, bytes, sizeof(bytes)) == 0);
    uint8_t peer_byte;
    CHECK(recv(f.peer, &peer_byte, 1, 0) == -1 && errno == EAGAIN);
    CHECK(vireo_connection_destroy(&f.connection, NULL) == VIREO_RESULT_BUSY);
    REQUIRE(vireo_connection_detach(f.connection, NULL) == VIREO_OK);
    CHECK(state(&f).close_state == VIREO_CONNECTION_CLOSE_READY);
    REQUIRE(vireo_connection_destroy(&f.connection, NULL) == VIREO_OK);
    CHECK(recv(f.peer, &peer_byte, 1, 0) == 0); /* 真 close 直到主动 destroy。 */
    REQUIRE(vireo_event_loop_destroy(&f.loop, NULL) == VIREO_OK);
    REQUIRE(close(f.peer) == 0);
}

static void test_upgrade_and_first_reason(void)
{
    fixture_t f;
    setup(&f);
    enqueue(&f, 100);
    REQUIRE(vireo_connection_request_close(f.connection, VIREO_CONNECTION_CLOSE_MODE_DRAIN,
        VIREO_CONNECTION_CLOSE_REASON_PEER_EOF, NULL) == VIREO_OK);
    for (int reason = 1; reason <= 6; ++reason) {
        REQUIRE(vireo_connection_request_close(f.connection, VIREO_CONNECTION_CLOSE_MODE_DRAIN,
            (vireo_connection_close_reason_t)reason, NULL) == VIREO_OK);
        CHECK(state(&f).close_reason == VIREO_CONNECTION_CLOSE_REASON_PEER_EOF);
    }
    CHECK(f.mods == 1);
    request(&f, VIREO_CONNECTION_CLOSE_MODE_IMMEDIATE);
    closed(&f, VIREO_CONNECTION_CLOSE_READY, 0);
    CHECK(state(&f).write_buffer.readable_size == 100);
    CHECK(state(&f).close_reason == VIREO_CONNECTION_CLOSE_REASON_PEER_EOF);
    CHECK(vireo_connection_request_close(f.connection, VIREO_CONNECTION_CLOSE_MODE_DRAIN,
        VIREO_CONNECTION_CLOSE_REASON_IO, NULL) == VIREO_RESULT_BUSY);
    CHECK(state(&f).close_mode == VIREO_CONNECTION_CLOSE_MODE_IMMEDIATE && f.mods == 2);
    request(&f, VIREO_CONNECTION_CLOSE_MODE_IMMEDIATE);
    CHECK(f.mods == 2);
    cleanup(&f);
}

/* 拒绝路径不消费 read borrow，不写统计，不隐式恢复普通关注权威。 */
static void test_guards(void)
{
    fixture_t f;
    setup(&f);
    configure(&f);
    uint8_t bytes[] = {'R'};
    feed(&f, bytes, 1);
    uint8_t const *borrow;
    size_t size;
    REQUIRE(vireo_connection_read_peek(f.connection, &borrow, &size) == VIREO_OK);
    request(&f, VIREO_CONNECTION_CLOSE_MODE_IMMEDIATE);
    vireo_connection_receive_budget_t rb = {128, 8};
    vireo_connection_receive_info_t ri;
    vireo_connection_send_budget_t sb = {128, 8};
    vireo_connection_send_info_t si;
    memset(&ri, 0xa5, sizeof(ri));
    memset(&si, 0xa5, sizeof(si));
    unsigned char old_ri[sizeof(ri)], old_si[sizeof(si)];
    memcpy(old_ri, &ri, sizeof(ri)); memcpy(old_si, &si, sizeof(si));
    errno = E2BIG;
    CHECK(vireo_connection_receive(f.connection, &rb, &ri, NULL) == VIREO_RESULT_BUSY);
    CHECK(vireo_connection_send(f.connection, &sb, &si, NULL) == VIREO_RESULT_BUSY);
    CHECK(memcmp(&ri, old_ri, sizeof(ri)) == 0 && memcmp(&si, old_si, sizeof(si)) == 0);
    CHECK(vireo_connection_write_enqueue(f.connection, bytes, 1, NULL) == VIREO_RESULT_BUSY);
    CHECK(vireo_connection_write_enqueue(f.connection, NULL, 0, NULL) == VIREO_RESULT_BUSY);
    CHECK(vireo_connection_set_interests(f.connection, INPUT, NULL) == VIREO_RESULT_BUSY);
    CHECK(vireo_connection_flow_configure(f.connection, &policy, NULL) == VIREO_RESULT_BUSY);
    CHECK(vireo_connection_flow_refresh(f.connection, NULL) == VIREO_RESULT_BUSY);
    CHECK(vireo_connection_flow_disable(f.connection, NULL) == VIREO_RESULT_BUSY);
    CHECK(vireo_connection_attach(f.connection, f.loop, INPUT,
                                    on_ready, &f, NULL) == VIREO_RESULT_BUSY);
    CHECK(errno == E2BIG && size == 1 && *borrow == 'R' && f.mods == 1);
    rb.max_bytes = 0; sb.max_syscalls = 0;
    CHECK(vireo_connection_receive(f.connection, &rb, &ri, NULL) == VIREO_RESULT_RANGE);
    CHECK(vireo_connection_send(f.connection, &sb, &si, NULL) == VIREO_RESULT_RANGE);
    CHECK(vireo_connection_set_interests(f.connection, UINT32_MAX, NULL) ==
          VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_connection_flow_configure(f.connection, NULL, NULL) ==
          VIREO_RESULT_INVALID_ARGUMENT);
    REQUIRE(vireo_connection_read_consume(f.connection, 0) == VIREO_OK);
    REQUIRE(vireo_connection_read_consume(f.connection, 1) == VIREO_OK);
    cleanup(&f);
}

/* 真实 send 已交出全部字节，再 MOD 拒绝；READY 不能回滚，旧 WRITE 保持。 */
static void test_mod_failure(int cause)
{
    fixture_t f;
    setup(&f);
    enqueue(&f, 100);
    f.fail_mod = cause;
    vireo_connection_loop_error_t error;
    errno = E2BIG;
    CHECK(vireo_connection_request_close(f.connection, VIREO_CONNECTION_CLOSE_MODE_DRAIN,
        VIREO_CONNECTION_CLOSE_REASON_SERVER_STOP, &error) == VIREO_RESULT_IO);
    CHECK(errno == E2BIG && state(&f).close_state == VIREO_CONNECTION_CLOSE_DRAINING);
    CHECK(error.stage == VIREO_CONNECTION_LOOP_STAGE_REQUEST_CLOSE);
    CHECK(error.loop_error.stage == VIREO_EVENT_LOOP_STAGE_MOD);
    CHECK(error.loop_error.epoll_error.system_errno == cause && f.mods == 1);
    closed(&f, VIREO_CONNECTION_CLOSE_DRAINING, INPUT);
    CHECK(vireo_connection_write_enqueue(f.connection, NULL, 0, NULL) == VIREO_RESULT_BUSY);
    f.fail_mod = 0;
    sync_close(&f);
    closed(&f, VIREO_CONNECTION_CLOSE_DRAINING, OUTPUT);
    drain(&f, 100);
    f.fail_mod = cause;
    errno = E2BIG;
    CHECK(vireo_connection_close_refresh(f.connection, &error) == VIREO_RESULT_IO);
    CHECK(errno == E2BIG && error.stage == VIREO_CONNECTION_LOOP_STAGE_CLOSE_REFRESH);
    CHECK(error.loop_error.epoll_error.stage == VIREO_EPOLL_STAGE_MOD);
    CHECK(error.loop_error.epoll_error.system_errno == cause && f.mods == 3);
    closed(&f, VIREO_CONNECTION_CLOSE_READY, OUTPUT);
    CHECK(state(&f).write_buffer.readable_size == 0);
    CHECK(vireo_connection_close_refresh(f.connection, NULL) == VIREO_RESULT_IO);
    CHECK(f.mods == 4 && errno == E2BIG);
    f.fail_mod = 0;
    request(&f, VIREO_CONNECTION_CLOSE_MODE_DRAIN);
    closed(&f, VIREO_CONNECTION_CLOSE_READY, 0);
    CHECK(state(&f).close_reason == VIREO_CONNECTION_CLOSE_REASON_SERVER_STOP);
    cleanup(&f);
}

static void test_no_mod_and_flow_priority(void)
{
    fixture_t f;
    setup(&f);
    enqueue(&f, 100);
    configure(&f); /* 写压力使原 flow mask 只有 WRITE。 */
    CHECK(state(&f).write_pressure && state(&f).loop_interests == OUTPUT);
    size_t mods = f.mods;
    request(&f, VIREO_CONNECTION_CLOSE_MODE_DRAIN);
    sync_close(&f);
    CHECK(f.mods == mods && state(&f).write_pressure);
    drain(&f, 68);
    sync_close(&f);
    CHECK(f.mods == mods && state(&f).write_pressure); /* 旧快照保持，关闭仍只 WRITE。 */
    drain(&f, 32);
    sync_close(&f);
    closed(&f, VIREO_CONNECTION_CLOSE_READY, 0);
    cleanup(&f);
}

static void test_eof_drain(void)
{
    fixture_t f;
    setup(&f);
    REQUIRE(shutdown(f.peer, SHUT_WR) == 0);
    vireo_connection_receive_budget_t budget = {128, 8};
    vireo_connection_receive_info_t received;
    REQUIRE(vireo_connection_receive(f.connection, &budget, &received, NULL) == VIREO_OK);
    CHECK(state(&f).read_eof && state(&f).close_state == VIREO_CONNECTION_CLOSE_OPEN);
    enqueue(&f, 3);
    REQUIRE(vireo_connection_request_close(f.connection, VIREO_CONNECTION_CLOSE_MODE_DRAIN,
        VIREO_CONNECTION_CLOSE_REASON_PEER_EOF, NULL) == VIREO_OK);
    drain(&f, 3);
    sync_close(&f);
    closed(&f, VIREO_CONNECTION_CLOSE_READY, 0);
    cleanup(&f);
}

static void test_callback(void)
{
    fixture_t f;
    setup(&f);
    enqueue(&f, 1);
    f.callback_close = true;
    REQUIRE(send(f.peer, "R", 1, MSG_NOSIGNAL) == 1);
    vireo_event_loop_run_info_t info;
    REQUIRE(vireo_event_loop_run_once(f.loop, 0, &info, NULL) == VIREO_OK);
    CHECK(f.calls == 1 && !state(&f).callback_active && !state(&f).loop_attached);
    CHECK(state(&f).close_state == VIREO_CONNECTION_CLOSE_DRAINING);
    drain(&f, 1);
    sync_close(&f);
    cleanup(&f);
}

static void test_del_failure_and_forget(void)
{
    fixture_t f;
    setup(&f);
    enqueue(&f, 1);
    request(&f, VIREO_CONNECTION_CLOSE_MODE_IMMEDIATE);
    f.fail_del = EINTR;
    vireo_connection_loop_error_t error;
    CHECK(vireo_connection_detach(f.connection, &error) == VIREO_RESULT_IO);
    CHECK(error.stage == VIREO_CONNECTION_LOOP_STAGE_DETACH);
    CHECK(state(&f).loop_attached && state(&f).write_buffer.readable_size == 1);
    CHECK(vireo_connection_destroy(&f.connection, NULL) == VIREO_RESULT_BUSY);
    REQUIRE(vireo_event_loop_destroy(&f.loop, NULL) == VIREO_OK);
    REQUIRE(vireo_connection_forget_destroyed_loop(f.connection, NULL) == VIREO_OK);
    CHECK(!state(&f).loop_attached && state(&f).close_state == VIREO_CONNECTION_CLOSE_READY);
    CHECK(state(&f).close_reason == VIREO_CONNECTION_CLOSE_REASON_SERVER_STOP);
    sync_close(&f);
    cleanup(&f);
}

/* 关闭不妨碍纯帧观察或合法借用；CRC wire 仍由封板公共 codec 构造。 */
static void test_frame_borrow(void)
{
    fixture_t f;
    setup(&f);
    uint8_t wire[64] = {0};
    vireo_protocol_header_t header = {0};
    header.command = VIREO_COMMAND_PING;
    header.sequence = 1;
    header.status = VIREO_PROTOCOL_REQUEST_STATUS;
    header.body_len = 32;
    REQUIRE(vireo_protocol_header_encode(&header, wire, 64) == VIREO_OK);
    REQUIRE(vireo_protocol_frame_crc32c_calculate(wire, 32, wire + 32, 32,
                                                  &header.crc32c) == VIREO_OK);
    REQUIRE(vireo_protocol_header_encode(&header, wire, 64) == VIREO_OK);
    feed(&f, wire, 64);
    configure(&f);
    vireo_connection_frame_options_t options = {VIREO_CONNECTION_FRAME_REQUEST, 64};
    vireo_connection_frame_budget_t budget = {1, 64};
    vireo_connection_frame_view_t view;
    vireo_connection_frame_info_t info;
    REQUIRE(vireo_connection_frames_peek(f.connection, &options, &budget,
                                          &view, 1, &info, NULL) == VIREO_OK);
    uint8_t const *borrow = view.body;
    request(&f, VIREO_CONNECTION_CLOSE_MODE_IMMEDIATE);
    sync_close(&f);
    REQUIRE(vireo_connection_frames_peek(f.connection, &options, &budget,
                                          &view, 1, &info, NULL) == VIREO_OK);
    CHECK(info.frame_count == 1 && view.body == borrow && *borrow == 0);
    REQUIRE(vireo_connection_detach(f.connection, NULL) == VIREO_OK);
    CHECK(*borrow == 0 && !state(&f).flow_enabled);
    REQUIRE(vireo_connection_read_consume(f.connection, 64) == VIREO_OK);
    cleanup(&f);
}

static void test_independent(void)
{
    fixture_t a, b;
    setup(&a); setup(&b);
    request(&a, VIREO_CONNECTION_CLOSE_MODE_IMMEDIATE);
    uint8_t byte = 'B';
    feed(&b, &byte, 1);
    enqueue(&b, 1);
    drain(&b, 1);
    CHECK(state(&b).close_state == VIREO_CONNECTION_CLOSE_OPEN);
    CHECK(state(&b).close_reason == VIREO_CONNECTION_CLOSE_REASON_NONE && b.mods == 0);
    cleanup(&a); cleanup(&b);
}

/* 有界地填满实际 socket 发送缓冲；不从外部别名操作 connection 拥有的 fd。 */
static void test_would_block(void)
{
    fixture_t f;
    setup(&f);
    bool blocked = false;
    vireo_connection_send_budget_t budget = {128, 2};
    vireo_connection_send_info_t info;
    for (size_t i = 0; i < 4096; ++i) {
        if (state(&f).write_buffer.readable_size == 0) enqueue(&f, 128);
        REQUIRE(vireo_connection_send(f.connection, &budget, &info, NULL) == VIREO_OK);
        if (info.stop_reason == VIREO_CONNECTION_SEND_STOP_WOULD_BLOCK) {
            blocked = true;
            break;
        }
    }
    REQUIRE(blocked && state(&f).write_buffer.readable_size != 0);
    request(&f, VIREO_CONNECTION_CLOSE_MODE_DRAIN);
    size_t pending = state(&f).write_buffer.readable_size;
    REQUIRE(vireo_connection_send(f.connection, &budget, &info, NULL) == VIREO_OK);
    CHECK(info.sent_bytes == 0 && info.stop_reason == VIREO_CONNECTION_SEND_STOP_WOULD_BLOCK);
    sync_close(&f);
    CHECK(state(&f).close_state == VIREO_CONNECTION_CLOSE_DRAINING);
    CHECK(state(&f).write_buffer.readable_size == pending);
    request(&f, VIREO_CONNECTION_CLOSE_MODE_IMMEDIATE);
    CHECK(state(&f).close_state == VIREO_CONNECTION_CLOSE_READY);
    CHECK(state(&f).write_buffer.readable_size == pending);
    cleanup(&f);
}

static void test_send_error(void)
{
    fixture_t f;
    setup(&f);
    enqueue(&f, 3);
    request(&f, VIREO_CONNECTION_CLOSE_MODE_DRAIN);
    REQUIRE(shutdown(f.peer, SHUT_RD) == 0);
    vireo_connection_send_budget_t budget = {128, 8};
    vireo_connection_send_info_t info;
    vireo_connection_error_t error;
    errno = E2BIG;
    CHECK(vireo_connection_send(f.connection, &budget, &info, &error) == VIREO_RESULT_IO);
    CHECK(errno == E2BIG && error.system_errno == EPIPE);
    CHECK(info.sent_bytes == 0 && info.send_calls == 1);
    CHECK(state(&f).close_state == VIREO_CONNECTION_CLOSE_DRAINING);
    CHECK(state(&f).write_buffer.readable_size == 3);
    request(&f, VIREO_CONNECTION_CLOSE_MODE_IMMEDIATE);
    CHECK(state(&f).close_reason == VIREO_CONNECTION_CLOSE_REASON_SERVER_STOP);
    cleanup(&f);
}

/* 升级失败也不可退回发送；未发字节与首原因保持，显式补同步收尾。 */
static void test_upgrade_failure(void)
{
    fixture_t f;
    setup(&f);
    enqueue(&f, 3);
    request(&f, VIREO_CONNECTION_CLOSE_MODE_DRAIN);
    f.fail_mod = EINTR;
    vireo_connection_loop_error_t error;
    errno = E2BIG;
    CHECK(vireo_connection_request_close(f.connection, VIREO_CONNECTION_CLOSE_MODE_IMMEDIATE,
        VIREO_CONNECTION_CLOSE_REASON_IO, &error) == VIREO_RESULT_IO);
    CHECK(errno == E2BIG && error.stage == VIREO_CONNECTION_LOOP_STAGE_REQUEST_CLOSE);
    closed(&f, VIREO_CONNECTION_CLOSE_READY, OUTPUT);
    CHECK(state(&f).close_mode == VIREO_CONNECTION_CLOSE_MODE_IMMEDIATE);
    CHECK(state(&f).close_reason == VIREO_CONNECTION_CLOSE_REASON_SERVER_STOP);
    CHECK(state(&f).write_buffer.readable_size == 3);
    vireo_connection_send_budget_t budget = {128, 8};
    vireo_connection_send_info_t info = {11, 22, VIREO_CONNECTION_SEND_STOP_EMPTY};
    CHECK(vireo_connection_send(f.connection, &budget, &info, NULL) == VIREO_RESULT_BUSY);
    CHECK(info.sent_bytes == 11 && info.send_calls == 22);
    CHECK(vireo_connection_request_close(f.connection, VIREO_CONNECTION_CLOSE_MODE_DRAIN,
        VIREO_CONNECTION_CLOSE_REASON_IO, NULL) == VIREO_RESULT_BUSY);
    f.fail_mod = 0;
    sync_close(&f);
    closed(&f, VIREO_CONNECTION_CLOSE_READY, 0);
    CHECK(state(&f).write_buffer.readable_size == 3);
    cleanup(&f);
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
    test_unbound();
    test_empty_drain();
    test_drain();
    test_immediate();
    test_upgrade_and_first_reason();
    test_guards();
    test_mod_failure(EINTR);
    test_mod_failure(EIO);
    test_mod_failure(ENOMEM);
    test_no_mod_and_flow_priority();
    test_eof_drain();
    test_callback();
    test_del_failure_and_forget();
    test_frame_borrow();
    test_independent();
    test_would_block();
    test_send_error();
    test_upgrade_failure();
    CHECK(fd_count() == baseline);
    printf("connection close: 19 groups, %u failures; fd baseline checked\n", failures);
    return failures == 0 ? 0 : 1;
}
