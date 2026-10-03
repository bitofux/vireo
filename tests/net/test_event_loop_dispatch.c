/*
- PROJECT : VIREO
- FILE    : test_event_loop_dispatch.c
- AUTHOR  : bitofux
- DATE    : 2026-10-03
- BRIEF   : 此模块负责：
- -- 真实公共 epoll 的一轮等待、LT 分发与资源恢复
- -- 独立有序批次验证当前绑定、关注变更、借用和在途保护
 */
#define _GNU_SOURCE
#include <vireo/net/event_loop.h>
#include "net/event_loop_internal.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static unsigned failures;
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #c); \
    ++failures; } } while (0)
#define REQUIRE(c) do { if (!(c)) { CHECK(c); return; } } while (0)

typedef struct fixture {
    unsigned allocations;
    unsigned releases;
    unsigned waits;
    size_t received_capacity;
    int received_timeout;
    bool scripted;
    bool fill_capacity;
    vireo_epoll_event_t batch[8];
    size_t count;
    vireo_result_t wait_result;
    vireo_epoll_error_t wait_error;
    unsigned reject; /* 1 MOD / 2 DEL，拒绝时不改变真实内核关注。 */
    vireo_event_loop_t **waiting_owner; /* 仅测试等待适配内部的同线程在途保护。 */
} fixture_t;

typedef struct observed {
    vireo_event_loop_t *loop;
    vireo_event_loop_handle_t handle;
    int fd;
    size_t calls;
    uint32_t bits[8];
    char bytes[8];
    bool read_byte;
} observed_t;

static void clear_error(vireo_event_loop_error_t e)
{
    CHECK(e.stage == VIREO_EVENT_LOOP_STAGE_NONE && e.system_errno == 0);
    CHECK(e.epoll_error.stage == VIREO_EPOLL_STAGE_NONE && e.epoll_error.system_errno == 0);
}

static void stats(vireo_event_loop_run_info_t info, size_t ready, size_t dispatched,
                  size_t stale, size_t filtered)
{
    CHECK(info.ready_count == ready && info.dispatched_count == dispatched);
    CHECK(info.stale_count == stale && info.filtered_count == filtered);
    CHECK(info.ready_count == info.dispatched_count + info.stale_count + info.filtered_count);
}

/* 独立输出的全部字节要保持，不能只比较某个字段或外层运行计数。 */
static void busy_probe(vireo_event_loop_t **owner)
{
    vireo_event_loop_t *original = *owner;
    vireo_event_loop_run_info_t info;
    unsigned char saved[sizeof(info)];
    memset(&info, 0xA5, sizeof(info)); memcpy(saved, &info, sizeof(info));
    vireo_event_loop_error_t error;
    errno = EACCES;
    CHECK(vireo_event_loop_run_once(original, 0, &info, &error) == VIREO_RESULT_BUSY);
    CHECK(memcmp(saved, &info, sizeof(info)) == 0 && errno == EACCES);
    clear_error(error);
    CHECK(vireo_event_loop_run_once(original, 0, &info, NULL) == VIREO_RESULT_BUSY);
    CHECK(memcmp(saved, &info, sizeof(info)) == 0 && errno == EACCES);
    CHECK(vireo_event_loop_run_once(original, -2, &info, &error) ==
          VIREO_RESULT_INVALID_ARGUMENT);
    clear_error(error);
    CHECK(vireo_event_loop_destroy(owner, &error) == VIREO_RESULT_BUSY);
    CHECK(*owner == original && errno == EACCES); clear_error(error);
    CHECK(vireo_event_loop_destroy(owner, NULL) == VIREO_RESULT_BUSY);
    CHECK(*owner == original && errno == EACCES);
    vireo_event_loop_info_t resources;
    CHECK(vireo_event_loop_inspect(original, &resources) == VIREO_OK);
}

static void *allocate(void *context, size_t size)
{
    fixture_t *f = context; ++f->allocations;
    return malloc(size);
}

static void deallocate(void *context, void *memory)
{
    fixture_t *f = context; ++f->releases;
    free(memory);
}

static vireo_result_t create_epoll(void *context, vireo_epoll_options_t const *options,
                                  vireo_epoll_t **owner, vireo_epoll_error_t *error)
{
    (void)context;
    return vireo_epoll_create(options, owner, error);
}

static vireo_result_t inspect_epoll(void *context, vireo_epoll_t const *epoll,
                                   vireo_epoll_info_t *info)
{
    (void)context;
    return vireo_epoll_inspect(epoll, info);
}

static vireo_result_t destroy_epoll(void *context, vireo_epoll_t **owner,
                                   vireo_epoll_error_t *error)
{
    (void)context;
    return vireo_epoll_destroy(owner, error);
}

static vireo_result_t add_epoll(void *context, vireo_epoll_t *epoll, int fd,
                               vireo_epoll_registration_t const *input, vireo_epoll_error_t *error)
{
    (void)context;
    return vireo_epoll_add(epoll, fd, input, error);
}

static vireo_result_t mod_epoll(void *context, vireo_epoll_t *epoll, int fd,
                               vireo_epoll_registration_t const *input, vireo_epoll_error_t *error)
{
    fixture_t *f = context;
    if (f->reject == 1) {
        *error = (vireo_epoll_error_t){VIREO_EPOLL_STAGE_MOD, ENOENT};
        errno = ERANGE; return VIREO_RESULT_IO;
    }
    return vireo_epoll_mod(epoll, fd, input, error);
}

static vireo_result_t del_epoll(void *context, vireo_epoll_t *epoll, int fd,
                               vireo_epoll_error_t *error)
{
    fixture_t *f = context;
    if (f->reject == 2) {
        *error = (vireo_epoll_error_t){VIREO_EPOLL_STAGE_DEL, ENOENT};
        errno = ERANGE; return VIREO_RESULT_IO;
    }
    return vireo_epoll_del(epoll, fd, error);
}

/* 默认真的等待；脚本只复制容量内的值，异常 count 不伴随越界写。 */
static vireo_result_t wait_epoll(void *context, vireo_epoll_t *epoll,
                                vireo_epoll_event_t *events, size_t capacity, int timeout_ms,
                                size_t *count, vireo_epoll_error_t *error)
{
    fixture_t *f = context; ++f->waits;
    f->received_capacity = capacity; f->received_timeout = timeout_ms;
    if (f->waiting_owner != NULL) busy_probe(f->waiting_owner);
    errno = ENOTTY;
    if (f->wait_result != VIREO_OK) {
        *error = f->wait_error;
        return f->wait_result;
    }
    if (!f->scripted) return vireo_epoll_wait(epoll, timeout_ms, events, capacity, count, error);
    if (f->fill_capacity) {
        for (size_t i = 0; i < capacity; ++i) events[i] = f->batch[0];
        *count = capacity;
    } else {
        size_t n = f->count < 8 ? f->count : 8;
        if (n > capacity) n = capacity;
        for (size_t i = 0; i < n; ++i) events[i] = f->batch[i];
        *count = f->count;
    }
    *error = (vireo_epoll_error_t){VIREO_EPOLL_STAGE_NONE, 0};
    return VIREO_OK;
}

static bool make_loop(fixture_t *f, size_t events, size_t registrations, vireo_event_loop_t **owner)
{
    vireo_event_loop_ops_t ops = vireo_event_loop_default_ops();
    ops.context = f;
    ops.allocate = allocate;
    ops.deallocate = deallocate;
    ops.create_epoll = create_epoll;
    ops.inspect_epoll = inspect_epoll;
    ops.destroy_epoll = destroy_epoll;
    ops.add_epoll = add_epoll;
    ops.mod_epoll = mod_epoll;
    ops.del_epoll = del_epoll;
    ops.wait_epoll = wait_epoll;
    vireo_event_loop_options_t options = {events, VIREO_EVENT_LOOP_MAX_MEMORY, registrations};
    vireo_result_t result = vireo_event_loop_create_with_ops(&options, &ops, owner, NULL);
    CHECK(result == VIREO_OK && *owner != NULL && f->allocations == 3);
    return result == VIREO_OK;
}

static void observe(vireo_event_loop_t *loop, vireo_event_loop_handle_t handle, int fd,
                    uint32_t events, void *context)
{
    observed_t *o = context;
    CHECK(loop == o->loop && fd == o->fd);
    CHECK(handle.loop_id == o->handle.loop_id && handle.token == o->handle.token);
    if (o->calls < 8) {
        o->bits[o->calls] = events;
        if (o->read_byte) CHECK(read(fd, &o->bytes[o->calls], 1) == 1);
    }
    ++o->calls;
    errno = EDOM;
}

static bool add_observed(vireo_event_loop_t *loop, int fd, uint32_t interests, observed_t *o)
{
    o->loop = loop; o->fd = fd;
    vireo_event_loop_registration_t input = {fd, interests, observe, o};
    vireo_result_t result = vireo_event_loop_add(loop, &input, &o->handle, NULL);
    CHECK(result == VIREO_OK);
    return result == VIREO_OK;
}

static bool pair(int channel[2])
{
    int result = socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, channel);
    CHECK(result == 0);
    return result == 0;
}

static vireo_event_loop_run_info_t run(vireo_event_loop_t *loop, int timeout)
{
    vireo_event_loop_run_info_t info = {0}; vireo_event_loop_error_t error;
    errno = EACCES;
    CHECK(vireo_event_loop_run_once(loop, timeout, &info, &error) == VIREO_OK);
    CHECK(errno == EACCES); clear_error(error);
    return info;
}

static void close_loop(fixture_t *f, vireo_event_loop_t **loop)
{
    CHECK(f->allocations == 3 && f->releases == 0);
    CHECK(vireo_event_loop_destroy(loop, NULL) == VIREO_OK);
    CHECK(*loop == NULL && f->releases == 3);
}

static void arguments_empty(void)
{
    fixture_t f = {0}; vireo_event_loop_t *loop = NULL;
    REQUIRE(make_loop(&f, 4, 4, &loop));
    vireo_event_loop_run_info_t info; unsigned char saved[sizeof(info)];
    memset(&info, 0x5A, sizeof(info)); memcpy(saved, &info, sizeof(info));
    vireo_event_loop_error_t error; errno = EACCES;
    CHECK(vireo_event_loop_run_once(NULL, 0, &info, &error) == VIREO_RESULT_INVALID_ARGUMENT);
    clear_error(error);
    CHECK(vireo_event_loop_run_once(loop, 0, NULL, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    int invalid[] = {-2, INT_MIN};
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
        CHECK(vireo_event_loop_run_once(loop, invalid[i], &info, &error) ==
              VIREO_RESULT_INVALID_ARGUMENT);
        clear_error(error);
        CHECK(memcmp(saved, &info, sizeof(info)) == 0 && errno == EACCES);
    }
    CHECK(f.waits == 0);
    stats(run(loop, 0), 0, 0, 0, 0);
    stats(run(loop, 1), 0, 0, 0, 0);
    CHECK(f.waits == 2 && f.received_capacity == 4 && f.received_timeout == 1);
    f.scripted = true;
    stats(run(loop, -1), 0, 0, 0, 0);
    stats(run(loop, INT_MAX), 0, 0, 0, 0); /* 最大超时只验证转发，不真的阻塞。 */
    CHECK(f.received_timeout == INT_MAX);
    errno = EACCES;
    CHECK(vireo_event_loop_run_once(loop, 0, &info, NULL) == VIREO_OK && errno == EACCES);
    stats(info, 0, 0, 0, 0);
    close_loop(&f, &loop);
}

/* LT 未读完就会下一轮继续可读；每回调仅取一个字节并验证原顺序。 */
static void real_lt_read(void)
{
    fixture_t f = {0}; vireo_event_loop_t *loop = NULL; int channel[2];
    REQUIRE(make_loop(&f, 4, 4, &loop)); REQUIRE(pair(channel));
    observed_t o = {.read_byte = true};
    REQUIRE(add_observed(loop, channel[0], VIREO_EPOLL_INTEREST_READ, &o));
    CHECK(write(channel[1], "abcd", 4) == 4);
    for (int i = 0; i < 4; ++i) stats(run(loop, i == 0 ? -1 : 0), 1, 1, 0, 0);
    CHECK(o.calls == 4 && memcmp(o.bytes, "abcd", 4) == 0);
    for (size_t i = 0; i < 4; ++i) CHECK(o.bits[i] == VIREO_EPOLL_EVENT_READ);
    stats(run(loop, 0), 0, 0, 0, 0);
    CHECK(vireo_event_loop_del(loop, &o.handle, NULL) == VIREO_OK);
    close_loop(&f, &loop); CHECK(close(channel[0]) == 0 && close(channel[1]) == 0);
}

static void real_write_peer_close(void)
{
    fixture_t f = {0}; vireo_event_loop_t *loop = NULL; int channel[2];
    REQUIRE(make_loop(&f, 4, 4, &loop)); REQUIRE(pair(channel)); observed_t o = {0};
    REQUIRE(add_observed(loop, channel[0], VIREO_EPOLL_INTEREST_WRITE, &o));
    stats(run(loop, -1), 1, 1, 0, 0);
    CHECK(o.bits[0] == VIREO_EPOLL_EVENT_WRITE);
    CHECK(vireo_event_loop_mod(loop, o.handle, VIREO_EPOLL_INTEREST_READ |
          VIREO_EPOLL_INTEREST_PEER_WRITE_CLOSED, NULL) == VIREO_OK);
    CHECK(shutdown(channel[1], SHUT_WR) == 0);
    stats(run(loop, 0), 1, 1, 0, 0);
    CHECK((o.bits[1] & VIREO_EPOLL_EVENT_PEER_WRITE_CLOSED) != 0);
    CHECK((o.bits[1] & VIREO_EPOLL_EVENT_WRITE) == 0);
    char byte; CHECK(read(channel[0], &byte, 1) == 0);
    CHECK(vireo_event_loop_del(loop, &o.handle, NULL) == VIREO_OK);
    close_loop(&f, &loop); CHECK(close(channel[0]) == 0 && close(channel[1]) == 0);
}

static size_t null_callbacks;

static void null_callback(vireo_event_loop_t *loop, vireo_event_loop_handle_t handle, int fd,
                          uint32_t events, void *context)
{
    CHECK(loop != NULL && handle.loop_id != 0 && handle.token != 0);
    CHECK(fd >= 0 && events == VIREO_EPOLL_EVENT_READ && context == NULL);
    ++null_callbacks;
}

static void null_context(void)
{
    fixture_t f = {.scripted = true, .count = 1}; vireo_event_loop_t *loop = NULL; int channel[2];
    REQUIRE(make_loop(&f, 4, 4, &loop)); REQUIRE(pair(channel));
    vireo_event_loop_handle_t handle = {0};
    vireo_event_loop_registration_t input = {channel[0], 1, null_callback, NULL};
    REQUIRE(vireo_event_loop_add(loop, &input, &handle, NULL) == VIREO_OK);
    f.batch[0] = (vireo_epoll_event_t){handle.token, 1};
    stats(run(loop, 0), 1, 1, 0, 0); CHECK(null_callbacks == 1);
    close_loop(&f, &loop); CHECK(close(channel[0]) == 0 && close(channel[1]) == 0);
}

static void real_zero_interest_hangup(void)
{
    fixture_t f = {0}; vireo_event_loop_t *loop = NULL; int channel[2];
    REQUIRE(make_loop(&f, 4, 4, &loop)); REQUIRE(pipe2(channel, O_NONBLOCK | O_CLOEXEC) == 0);
    observed_t o = {0}; REQUIRE(add_observed(loop, channel[0], 0, &o));
    CHECK(close(channel[1]) == 0);
    stats(run(loop, 0), 1, 1, 0, 0);
    CHECK(o.bits[0] == VIREO_EPOLL_EVENT_HANGUP);
    CHECK(vireo_event_loop_del(loop, &o.handle, NULL) == VIREO_OK);
    close_loop(&f, &loop); CHECK(close(channel[0]) == 0);
}

/* 8 个关注组合乘 32 个就绪组合，预期表不从生产函数计算。 */
static void filter_combinations(void)
{
    uint32_t const allowed[] = {24, 25, 26, 27, 28, 29, 30, 31};
    fixture_t f = {.scripted = true, .count = 1}; vireo_event_loop_t *loop = NULL; int channel[2];
    REQUIRE(make_loop(&f, 4, 4, &loop)); REQUIRE(pair(channel)); observed_t o = {0};
    REQUIRE(add_observed(loop, channel[0], 0, &o));
    for (uint32_t interest = 0; interest < 8; ++interest) {
        CHECK(vireo_event_loop_mod(loop, o.handle, interest, NULL) == VIREO_OK);
        for (uint32_t bits = 0; bits < 32; ++bits) {
            o.calls = 0; o.bits[0] = UINT32_MAX;
            f.batch[0] = (vireo_epoll_event_t){o.handle.token, bits};
            uint32_t expected = bits & allowed[interest];
            stats(run(loop, 0), 1, expected != 0 ? 1 : 0, 0, expected == 0 ? 1 : 0);
            CHECK(o.calls == (expected != 0 ? 1U : 0U));
            CHECK(o.bits[0] == (expected != 0 ? expected : UINT32_MAX));
        }
    }
    CHECK(f.waits == 256);
    CHECK(vireo_event_loop_del(loop, &o.handle, NULL) == VIREO_OK);
    close_loop(&f, &loop); CHECK(close(channel[0]) == 0 && close(channel[1]) == 0);
}

/* 每个失败下一轮都成功，验证在途状态清理、诊断可空及严格一次调用。 */
static void wait_failures(void)
{
    int const causes[] = {EINTR, EBADF, EINVAL, EFAULT, ENOMEM, EIO};
    fixture_t f = {.scripted = true, .count = 1}; vireo_event_loop_t *loop = NULL;
    int channel[2]; REQUIRE(make_loop(&f, 4, 4, &loop)); REQUIRE(pair(channel));
    observed_t o = {0}; REQUIRE(add_observed(loop, channel[0], 1, &o));
    f.batch[0] = (vireo_epoll_event_t){o.handle.token, 1};
    for (size_t i = 0; i < sizeof(causes) / sizeof(causes[0]); ++i) {
        for (unsigned diagnostic = 0; diagnostic < 2; ++diagnostic) {
            vireo_event_loop_run_info_t info; unsigned char saved[sizeof(info)];
            memset(&info, 0xA5, sizeof(info)); memcpy(saved, &info, sizeof(info));
            vireo_event_loop_error_t error;
            f.wait_result = VIREO_RESULT_IO;
            f.wait_error = (vireo_epoll_error_t){VIREO_EPOLL_STAGE_WAIT, causes[i]};
            unsigned before = f.waits; size_t callbacks_before = o.calls; errno = EACCES;
            CHECK(vireo_event_loop_run_once(loop, -1, &info, diagnostic ? &error : NULL) ==
                  VIREO_RESULT_IO);
            CHECK(memcmp(saved, &info, sizeof(info)) == 0 && errno == EACCES);
            CHECK(f.waits == before + 1 && o.calls == callbacks_before);
            if (diagnostic) {
                CHECK(error.stage == VIREO_EVENT_LOOP_STAGE_WAIT);
                CHECK(error.epoll_error.stage == VIREO_EPOLL_STAGE_WAIT);
                CHECK(error.epoll_error.system_errno == causes[i]);
            }
            f.wait_result = VIREO_OK; stats(run(loop, 0), 1, 1, 0, 0);
        }
    }
    f.wait_result = VIREO_RESULT_INTERNAL;
    f.wait_error = (vireo_epoll_error_t){VIREO_EPOLL_STAGE_WAIT, 0};
    vireo_event_loop_run_info_t info = {7, 8, 9, 10}; vireo_event_loop_error_t error;
    CHECK(vireo_event_loop_run_once(loop, 0, &info, &error) == VIREO_RESULT_INTERNAL);
    CHECK(info.ready_count == 7 && info.dispatched_count == 8 && info.stale_count == 9 &&
          info.filtered_count == 10);
    CHECK(error.stage == VIREO_EVENT_LOOP_STAGE_WAIT && error.epoll_error.system_errno == 0);
    f.wait_result = VIREO_OK; stats(run(loop, 0), 1, 1, 0, 0);
    close_loop(&f, &loop); CHECK(close(channel[0]) == 0 && close(channel[1]) == 0);
}

/* 好事件排在坏事件之前也必须零回调，避免副作用发生后才报整轮失败。 */
static void abnormal_batches(void)
{
    fixture_t f = {.scripted = true}; vireo_event_loop_t *loop = NULL; int channel[2];
    REQUIRE(make_loop(&f, 4, 4, &loop)); REQUIRE(pair(channel)); observed_t o = {0};
    REQUIRE(add_observed(loop, channel[0], VIREO_EPOLL_INTEREST_READ, &o));
    for (unsigned fault = 0; fault < 7; ++fault) {
        for (size_t position = 0; position < 2; ++position) {
            f.count = 2;
            f.batch[0] = f.batch[1] = (vireo_epoll_event_t){o.handle.token, 1};
            vireo_event_loop_stage_t stage = VIREO_EVENT_LOOP_STAGE_DISPATCH;
            switch (fault) {
            case 0: f.count = 5; stage = VIREO_EVENT_LOOP_STAGE_WAIT; break;
            case 1: f.count = SIZE_MAX; stage = VIREO_EVENT_LOOP_STAGE_WAIT; break;
            case 2: f.batch[position].events = 32; stage = VIREO_EVENT_LOOP_STAGE_WAIT; break;
            case 3: f.batch[position].events = UINT32_MAX;
                    stage = VIREO_EVENT_LOOP_STAGE_WAIT; break;
            case 4: f.batch[position].token = 0;
                    f.batch[position].events = VIREO_EPOLL_EVENT_HANGUP;
                    stage = VIREO_EVENT_LOOP_STAGE_WAKE_READ; break;
            case 5: f.batch[position].token = 1; break;
            case 6: f.batch[position].token = UINT64_C(65536) | UINT64_C(4); break;
            default: CHECK(false); break;
            }
            vireo_event_loop_run_info_t info; unsigned char saved[sizeof(info)];
            memset(&info, 0x5A, sizeof(info)); memcpy(saved, &info, sizeof(info));
            vireo_event_loop_error_t error; size_t calls = o.calls; errno = EACCES;
            CHECK(vireo_event_loop_run_once(loop, 0, &info, &error) == VIREO_RESULT_INTERNAL);
            CHECK(o.calls == calls && memcmp(saved, &info, sizeof(info)) == 0 && errno == EACCES);
            CHECK(error.stage == stage && error.epoll_error.stage == VIREO_EPOLL_STAGE_NONE &&
                  error.epoll_error.system_errno == 0);
            f.count = 0; stats(run(loop, 0), 0, 0, 0, 0);
        }
    }
    CHECK(o.calls == 0);
    CHECK(vireo_event_loop_del(loop, &o.handle, NULL) == VIREO_OK);
    close_loop(&f, &loop); CHECK(close(channel[0]) == 0 && close(channel[1]) == 0);
}

static void stale_values(void)
{
    fixture_t f = {.scripted = true, .count = 2}; vireo_event_loop_t *loop = NULL; int channel[2];
    REQUIRE(make_loop(&f, 4, 4, &loop)); REQUIRE(pair(channel)); observed_t o = {0};
    REQUIRE(add_observed(loop, channel[0], 1, &o));
    f.batch[0] = (vireo_epoll_event_t){o.handle.token, 1};
    CHECK(vireo_event_loop_del(loop, &o.handle, NULL) == VIREO_OK);
    f.batch[1] = (vireo_epoll_event_t){UINT64_C(65536) | UINT64_C(3), 31};
    stats(run(loop, 0), 2, 0, 2, 0); CHECK(o.calls == 0);
    close_loop(&f, &loop); CHECK(close(channel[0]) == 0 && close(channel[1]) == 0);
}

typedef struct mutator {
    fixture_t *fixture;
    vireo_event_loop_handle_t a;
    vireo_event_loop_handle_t b;
    unsigned action; /* 1 DEL B / 2 MOD B / 3 DEL A / 4 REPLACE B / 5 ADD C / 6 MOD A。 */
    uint32_t interests;
    size_t calls;
    int a_fd;
    int b_fd;
    int replacement[2];
    observed_t *old_context;
    observed_t *new_context;
    vireo_result_t result;
    vireo_event_loop_error_t error;
} mutator_t;

/* 变更都走公共 loop，旧 context 在成功 DEL 后才释放；当前 A 的 context 始终存活。 */
static void mutate(vireo_event_loop_t *loop, vireo_event_loop_handle_t handle, int fd,
                   uint32_t events, void *context)
{
    mutator_t *m = context;
    CHECK(handle.token == m->a.token && fd == m->a_fd && events == VIREO_EPOLL_EVENT_READ);
    ++m->calls;
    switch (m->action) {
    case 1: m->result = vireo_event_loop_del(loop, &m->b, &m->error); break;
    case 2: m->result = vireo_event_loop_mod(loop, m->b, m->interests, &m->error); break;
    case 3: m->result = vireo_event_loop_del(loop, &m->a, &m->error); break;
    case 4:
        m->result = vireo_event_loop_del(loop, &m->b, &m->error);
        CHECK(m->result == VIREO_OK);
        if (m->result != VIREO_OK) break;
        free(m->old_context); m->old_context = NULL;
        CHECK(close(m->b_fd) == 0);
        CHECK(dup3(m->replacement[0], m->b_fd, O_CLOEXEC) == m->b_fd);
        CHECK(close(m->replacement[0]) == 0); m->replacement[0] = -1;
        CHECK(add_observed(loop, m->b_fd, 1, m->new_context));
        break;
    case 5: CHECK(add_observed(loop, m->replacement[0], 1, m->new_context)); break;
    case 6: m->result = vireo_event_loop_mod(loop, m->a, 0, &m->error); break;
    default: CHECK(false); break;
    }
    CHECK(m->fixture->allocations == 3 && m->fixture->releases == 0);
    errno = EDOM;
}

static bool add_mutator(vireo_event_loop_t *loop, int fd, mutator_t *m)
{
    m->a_fd = fd;
    vireo_event_loop_registration_t input = {fd, 1, mutate, m};
    vireo_result_t result = vireo_event_loop_add(loop, &input, &m->a, NULL);
    CHECK(result == VIREO_OK); return result == VIREO_OK;
}

static void same_batch_del(void)
{
    fixture_t f = {.scripted = true, .count = 2}; vireo_event_loop_t *loop = NULL;
    int a[2], b[2]; REQUIRE(make_loop(&f, 4, 4, &loop)); REQUIRE(pair(a)); REQUIRE(pair(b));
    mutator_t m = {.fixture = &f, .action = 1}; observed_t ob = {0};
    REQUIRE(add_mutator(loop, a[0], &m));
    REQUIRE(add_observed(loop, b[0], 1, &ob)); m.b = ob.handle;
    f.batch[0] = (vireo_epoll_event_t){m.a.token, 1};
    f.batch[1] = (vireo_epoll_event_t){m.b.token, 1};
    stats(run(loop, 0), 2, 1, 1, 0); CHECK(m.calls == 1 && ob.calls == 0 && m.result == VIREO_OK);
    vireo_event_loop_registration_t binding;
    CHECK(vireo_event_loop_registration_inspect(loop, ob.handle, &binding) ==
          VIREO_RESULT_NOT_FOUND);
    close_loop(&f, &loop);
    CHECK(close(a[0]) == 0 && close(a[1]) == 0 && close(b[0]) == 0 && close(b[1]) == 0);
}

static void same_batch_mod(void)
{
    uint32_t const interests[] = {1, 0, 0}; uint32_t const bits[] = {3, 3, 31};
    uint32_t const expected[] = {1, 0, 24};
    for (size_t i = 0; i < 3; ++i) {
        fixture_t f = {.scripted = true, .count = 2}; vireo_event_loop_t *loop = NULL;
        int a[2], b[2]; REQUIRE(make_loop(&f, 4, 4, &loop)); REQUIRE(pair(a)); REQUIRE(pair(b));
        mutator_t m = {.fixture = &f, .action = 2, .interests = interests[i]}; observed_t ob = {0};
        REQUIRE(add_mutator(loop, a[0], &m)); REQUIRE(add_observed(loop, b[0], 7, &ob));
        m.b = ob.handle;
        f.batch[0] = (vireo_epoll_event_t){m.a.token, 1};
        f.batch[1] = (vireo_epoll_event_t){m.b.token, bits[i]};
        stats(run(loop, 0), 2, expected[i] ? 2 : 1, 0, expected[i] ? 0 : 1);
        CHECK(m.result == VIREO_OK && m.calls == 1 && ob.calls == (expected[i] ? 1U : 0U));
        if (expected[i]) CHECK(ob.bits[0] == expected[i]);
        close_loop(&f, &loop);
        CHECK(close(a[0]) == 0 && close(a[1]) == 0 && close(b[0]) == 0 && close(b[1]) == 0);
    }
}

static void failed_mutations(void)
{
    for (unsigned reject = 1; reject <= 2; ++reject) {
        fixture_t f = {.scripted = true, .count = 2, .reject = reject};
        vireo_event_loop_t *loop = NULL; int a[2], b[2];
        REQUIRE(make_loop(&f, 4, 4, &loop)); REQUIRE(pair(a)); REQUIRE(pair(b));
        mutator_t m = {.fixture = &f, .action = reject == 1 ? 2U : 1U}; observed_t ob = {0};
        REQUIRE(add_mutator(loop, a[0], &m)); REQUIRE(add_observed(loop, b[0], 1, &ob));
        m.b = ob.handle;
        f.batch[0] = (vireo_epoll_event_t){m.a.token, 1};
        f.batch[1] = (vireo_epoll_event_t){m.b.token, 1};
        stats(run(loop, 0), 2, 2, 0, 0);
        CHECK(m.result == VIREO_RESULT_IO && m.error.epoll_error.system_errno == ENOENT);
        CHECK(m.error.stage ==
              (reject == 1 ? VIREO_EVENT_LOOP_STAGE_MOD : VIREO_EVENT_LOOP_STAGE_DEL));
        CHECK(ob.calls == 1 && m.b.token == ob.handle.token);
        vireo_event_loop_registration_t binding;
        CHECK(vireo_event_loop_registration_inspect(loop, m.b, &binding) == VIREO_OK);
        CHECK(binding.interests == 1 && binding.context == &ob);
        close_loop(&f, &loop);
        CHECK(close(a[0]) == 0 && close(a[1]) == 0 && close(b[0]) == 0 && close(b[1]) == 0);
    }
}

static void self_changes(void)
{
    for (unsigned action = 3; action <= 6; action += 3) {
        fixture_t f = {.scripted = true, .count = 2}; vireo_event_loop_t *loop = NULL; int a[2];
        REQUIRE(make_loop(&f, 4, 4, &loop)); REQUIRE(pair(a));
        mutator_t m = {.fixture = &f, .action = action}; REQUIRE(add_mutator(loop, a[0], &m));
        f.batch[0] = f.batch[1] = (vireo_epoll_event_t){m.a.token, 1};
        stats(run(loop, 0), 2, 1, action == 3 ? 1 : 0, action == 6 ? 1 : 0);
        CHECK(m.result == VIREO_OK && m.calls == 1);
        close_loop(&f, &loop); CHECK(close(a[0]) == 0 && close(a[1]) == 0);
    }
}

/* 同一批内真正注销/关闭/dup3 复用同 fd 与槽；ASan 验证不访问已释放的旧 B context。 */
static void reuse_fd_slot(void)
{
    fixture_t f = {.scripted = true, .count = 2}; vireo_event_loop_t *loop = NULL;
    int a[2], b[2]; REQUIRE(make_loop(&f, 4, 2, &loop)); REQUIRE(pair(a)); REQUIRE(pair(b));
    observed_t *old = calloc(1, sizeof(*old)); REQUIRE(old != NULL);
    observed_t current = {.read_byte = true};
    mutator_t m = {.fixture = &f, .action = 4, .b_fd = b[0],
                  .old_context = old, .new_context = &current};
    REQUIRE(pair(m.replacement)); REQUIRE(add_mutator(loop, a[0], &m));
    REQUIRE(add_observed(loop, b[0], 1, old)); m.b = old->handle;
    uint64_t old_token = old->handle.token;
    CHECK(write(b[1], "old", 3) == 3 && write(m.replacement[1], "new", 3) == 3);
    f.batch[0] = (vireo_epoll_event_t){m.a.token, 1};
    f.batch[1] = (vireo_epoll_event_t){old_token, 1};
    stats(run(loop, 0), 2, 1, 1, 0);
    CHECK(current.calls == 0 && m.old_context == NULL && current.fd == b[0]);
    CHECK(current.handle.token != old_token);
    CHECK((current.handle.token & UINT64_C(65535)) == (old_token & UINT64_C(65535)));
    f.scripted = false;
    stats(run(loop, 0), 1, 1, 0, 0); CHECK(current.calls == 1 && current.bytes[0] == 'n');
    close_loop(&f, &loop);
    CHECK(close(a[0]) == 0 && close(a[1]) == 0 && close(b[0]) == 0 && close(b[1]) == 0);
    CHECK(close(m.replacement[1]) == 0);
}

static void callback_add(void)
{
    fixture_t f = {.scripted = true, .count = 1}; vireo_event_loop_t *loop = NULL; int a[2];
    REQUIRE(make_loop(&f, 4, 2, &loop)); REQUIRE(pair(a)); observed_t current = {.read_byte = true};
    mutator_t m = {.fixture = &f, .action = 5, .new_context = &current};
    REQUIRE(pair(m.replacement)); REQUIRE(add_mutator(loop, a[0], &m));
    CHECK(write(m.replacement[1], "c", 1) == 1);
    f.batch[0] = (vireo_epoll_event_t){m.a.token, 1};
    stats(run(loop, 0), 1, 1, 0, 0); CHECK(current.calls == 0);
    f.scripted = false; stats(run(loop, 0), 1, 1, 0, 0);
    CHECK(current.calls == 1 && current.bytes[0] == 'c');
    close_loop(&f, &loop);
    CHECK(close(a[0]) == 0 && close(a[1]) == 0);
    CHECK(close(m.replacement[0]) == 0 && close(m.replacement[1]) == 0);
}

typedef struct guard_context {
    vireo_event_loop_t **owner;
    fixture_t *fixture;
    size_t calls;
} guard_context_t;

static void guard_callback(vireo_event_loop_t *loop, vireo_event_loop_handle_t handle, int fd,
                           uint32_t events, void *context)
{
    guard_context_t *g = context; (void)fd;
    CHECK(loop == *g->owner && events == 1); ++g->calls;
    busy_probe(g->owner);
    vireo_event_loop_registration_t binding;
    CHECK(vireo_event_loop_registration_inspect(loop, handle, &binding) == VIREO_OK);
    CHECK(binding.context == g && g->fixture->waits == 1 && g->fixture->releases == 0);
    errno = EDOM;
}

static void reentry_callback(void)
{
    fixture_t f = {.scripted = true, .count = 2}; vireo_event_loop_t *loop = NULL;
    int a[2], b[2]; REQUIRE(make_loop(&f, 4, 4, &loop)); REQUIRE(pair(a)); REQUIRE(pair(b));
    guard_context_t g = {&loop, &f, 0}; vireo_event_loop_handle_t handle = {0};
    vireo_event_loop_registration_t input = {a[0], 1, guard_callback, &g};
    REQUIRE(vireo_event_loop_add(loop, &input, &handle, NULL) == VIREO_OK);
    observed_t ob = {0}; REQUIRE(add_observed(loop, b[0], 1, &ob));
    f.batch[0] = (vireo_epoll_event_t){handle.token, 1};
    f.batch[1] = (vireo_epoll_event_t){ob.handle.token, 1};
    stats(run(loop, 0), 2, 2, 0, 0); CHECK(g.calls == 1 && ob.calls == 1);
    f.count = 0; stats(run(loop, 0), 0, 0, 0, 0);
    close_loop(&f, &loop);
    CHECK(close(a[0]) == 0 && close(a[1]) == 0 && close(b[0]) == 0 && close(b[1]) == 0);
}

static void reentry_wait(void)
{
    fixture_t f = {.scripted = true}; vireo_event_loop_t *loop = NULL;
    REQUIRE(make_loop(&f, 4, 4, &loop)); f.waiting_owner = &loop;
    stats(run(loop, 0), 0, 0, 0, 0); CHECK(f.waits == 1 && f.releases == 0);
    f.waiting_owner = NULL; stats(run(loop, 0), 0, 0, 0, 0);
    close_loop(&f, &loop);
}

typedef struct nested_context {
    vireo_event_loop_t **outer;
    vireo_event_loop_t *inner;
    size_t calls;
    bool enter_inner;
} nested_context_t;

static void nested_callback(vireo_event_loop_t *loop, vireo_event_loop_handle_t handle, int fd,
                            uint32_t events, void *context)
{
    nested_context_t *n = context; (void)handle; (void)fd;
    CHECK(events == 1); ++n->calls;
    if (n->enter_inner) {
        CHECK(loop == *n->outer);
        stats(run(n->inner, 0), 1, 1, 0, 0);
    } else {
        CHECK(loop == n->inner); busy_probe(n->outer);
    }
    errno = EDOM;
}

static void nested_loops(void)
{
    fixture_t a = {.scripted = true, .count = 2}, b = {.scripted = true, .count = 1};
    vireo_event_loop_t *outer = NULL, *inner = NULL; int channels[3][2];
    REQUIRE(make_loop(&a, 4, 4, &outer)); REQUIRE(make_loop(&b, 4, 4, &inner));
    for (size_t i = 0; i < 3; ++i) REQUIRE(pair(channels[i]));
    nested_context_t n = {&outer, inner, 0, true}, m = {&outer, inner, 0, false};
    vireo_event_loop_handle_t ha = {0}, hb = {0};
    vireo_event_loop_registration_t ra = {channels[0][0], 1, nested_callback, &n};
    vireo_event_loop_registration_t rb = {channels[1][0], 1, nested_callback, &m};
    REQUIRE(vireo_event_loop_add(outer, &ra, &ha, NULL) == VIREO_OK);
    REQUIRE(vireo_event_loop_add(inner, &rb, &hb, NULL) == VIREO_OK);
    observed_t other = {0}; REQUIRE(add_observed(outer, channels[2][0], 1, &other));
    a.batch[0] = (vireo_epoll_event_t){ha.token, 1};
    a.batch[1] = (vireo_epoll_event_t){other.handle.token, 1};
    b.batch[0] = (vireo_epoll_event_t){hb.token, 1};
    stats(run(outer, 0), 2, 2, 0, 0);
    CHECK(n.calls == 1 && m.calls == 1 && other.calls == 1 && a.waits == 1 && b.waits == 1);
    close_loop(&a, &outer); close_loop(&b, &inner);
    for (size_t i = 0; i < 3; ++i) CHECK(close(channels[i][0]) == 0 && close(channels[i][1]) == 0);
}

/* 容量 1 时用真实就绪验证分批且不假定顺序；硬上限时重复值验证全部有界计数。 */
static void capacity_bounds(void)
{
    fixture_t f = {0}; vireo_event_loop_t *loop = NULL; int channels[2][2];
    REQUIRE(make_loop(&f, 1, 2, &loop));
    observed_t o[2] = {{.read_byte = true}, {.read_byte = true}};
    for (size_t i = 0; i < 2; ++i) {
        REQUIRE(pair(channels[i])); REQUIRE(add_observed(loop, channels[i][0], 1, &o[i]));
        CHECK(write(channels[i][1], "x", 1) == 1);
    }
    stats(run(loop, 0), 1, 1, 0, 0); stats(run(loop, 0), 1, 1, 0, 0);
    CHECK(o[0].calls == 1 && o[1].calls == 1 && f.received_capacity == 1);
    stats(run(loop, 0), 0, 0, 0, 0); close_loop(&f, &loop);
    for (size_t i = 0; i < 2; ++i) CHECK(close(channels[i][0]) == 0 && close(channels[i][1]) == 0);

    f = (fixture_t){.scripted = true, .fill_capacity = true}; observed_t big = {0};
    REQUIRE(make_loop(&f, VIREO_EVENT_LOOP_MAX_EVENTS, 1, &loop)); REQUIRE(pair(channels[0]));
    REQUIRE(add_observed(loop, channels[0][0], 1, &big));
    f.batch[0] = (vireo_epoll_event_t){big.handle.token, 1};
    stats(run(loop, 0), VIREO_EVENT_LOOP_MAX_EVENTS, VIREO_EVENT_LOOP_MAX_EVENTS, 0, 0);
    CHECK(big.calls == VIREO_EVENT_LOOP_MAX_EVENTS && f.waits == 1);
    close_loop(&f, &loop); CHECK(close(channels[0][0]) == 0 && close(channels[0][1]) == 0);
}

static size_t fd_count(void)
{
    DIR *dir = opendir("/proc/self/fd"); CHECK(dir != NULL);
    if (dir == NULL) return SIZE_MAX;
    int own = dirfd(dir); size_t count = 0; struct dirent *entry; errno = 0;
    while ((entry = readdir(dir)) != NULL) {
        char *end; long value = strtol(entry->d_name, &end, 10);
        if (*entry->d_name != '\0' && *end == '\0' && value >= 0 && value != own) ++count;
    }
    CHECK(errno == 0); CHECK(closedir(dir) == 0); return count;
}

int main(void)
{
    void (*const tests[])(void) = {arguments_empty, real_lt_read, real_write_peer_close,
        real_zero_interest_hangup, null_context, filter_combinations, wait_failures,
        abnormal_batches,
        stale_values, same_batch_del, same_batch_mod, failed_mutations, self_changes,
        reuse_fd_slot, callback_add, reentry_callback, reentry_wait, nested_loops, capacity_bounds};
    for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); ++i) {
        size_t baseline = fd_count(); tests[i](); CHECK(fd_count() == baseline);
    }
    if (failures != 0) {
        fprintf(stderr, "test_event_loop_dispatch: %u failures\n", failures); return EXIT_FAILURE;
    }
    puts("test_event_loop_dispatch: 19 groups passed (256 masks, 12 IO injections, "
         "14 abnormal batches, 65536-item bound)");
    return EXIT_SUCCESS;
}
