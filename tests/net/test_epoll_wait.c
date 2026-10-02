/*
 * PROJECT : VIREO
 * FILE    : test_epoll_wait.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-02
 * BRIEF   : 此模块负责：
 * -- 验证公共等待的有界值批次、真实就绪和失败输出保持
 * -- 确定注入只验证返回分支，不冒称真实信号中断或系统耗尽
 */
#define _GNU_SOURCE
#include <vireo/net/epoll.h>
#include "net/epoll_internal.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static unsigned failures;
#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition); \
    ++failures; } } while (0)
#define REQUIRE(condition) do { if (!(condition)) { CHECK(condition); return; } } while (0)

typedef struct fixture {
    vireo_epoll_t *owner;
    int epfd;
    unsigned allocations;
    unsigned releases;
    unsigned live;
    unsigned calls;
    int last_capacity;
    int last_timeout;
    int synthetic;
    int returned;
    int cause;
    struct epoll_event samples[4];
} fixture_t;

static void *allocate(void *context, size_t size)
{
    fixture_t *f = context;
    ++f->allocations;
    void *memory = malloc(size);
    if (memory != NULL) ++f->live;
    return memory;
}

static void deallocate(void *context, void *memory)
{
    fixture_t *f = context;
    CHECK(f->live > 0);
    --f->live;
    ++f->releases;
    free(memory);
    errno = ERANGE;
}

static int create_fd(void *context, int flags)
{
    fixture_t *f = context;
    f->epfd = epoll_create1(flags);
    return f->epfd;
}

static int close_fd(void *context, int fd)
{
    fixture_t *f = context;
    CHECK(fd == f->epfd);
    f->epfd = -1;
    return close(fd);
}

static int control_fd(void *context, int epfd, int operation, int fd,
                       struct epoll_event *event)
{
    fixture_t *f = context;
    CHECK(epfd == f->epfd);
    return epoll_ctl(epfd, operation, fd, event);
}

/* 正常入口使用真实内核；异常入口绝不写超传入容量，失败也改 scratch。 */
static int wait_fd(void *context, int epfd, struct epoll_event *events,
                   int maxevents, int timeout_ms)
{
    fixture_t *f = context;
    CHECK(epfd == f->epfd && maxevents > 0 && events != NULL);
    ++f->calls;
    f->last_capacity = maxevents;
    f->last_timeout = timeout_ms;
    if (!f->synthetic) return epoll_wait(epfd, events, maxevents, timeout_ms);
    int written = f->returned > 0 ? f->returned : 1;
    if (written > maxevents) written = maxevents;
    for (int i = 0; i < written; ++i) events[i] = f->samples[(size_t)i % 4];
    errno = f->cause;
    return f->returned;
}

static int start(fixture_t *f, size_t capacity)
{
    *f = (fixture_t){.epfd = -1};
    vireo_epoll_options_t const options = {capacity, VIREO_EPOLL_MAX_MEMORY};
    vireo_epoll_ops_t const ops = {
        f, allocate, deallocate, create_fd, close_fd, control_fd, wait_fd
    };
    vireo_result_t result = vireo_epoll_create_with_ops(&options, &ops, &f->owner, NULL);
    CHECK(result == VIREO_OK);
    return result == VIREO_OK;
}

static void finish(fixture_t *f)
{
    errno = EACCES;
    CHECK(vireo_epoll_destroy(&f->owner, NULL) == VIREO_OK);
    CHECK(errno == EACCES && f->owner == NULL && f->epfd == -1);
    CHECK(f->allocations == 2 && f->releases == 2 && f->live == 0);
}

static int pair_open(int pair[2])
{
    int result = socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, pair);
    CHECK(result == 0);
    return result == 0;
}

static void pair_close(int pair[2])
{
    CHECK(close(pair[0]) == 0);
    CHECK(close(pair[1]) == 0);
}

static void watch(fixture_t *f, int fd, uint32_t interests, uint64_t token)
{
    vireo_epoll_registration_t const registration = {interests, token};
    CHECK(vireo_epoll_add(f->owner, fd, &registration, NULL) == VIREO_OK);
}

static void ready(fixture_t *f, int timeout_ms, uint64_t token, uint32_t required,
                   uint32_t forbidden)
{
    vireo_epoll_event_t events[3];
    unsigned char saved[sizeof(events)];
    memset(events, 0xa5, sizeof(events));
    memcpy(saved, events, sizeof(events));
    size_t count = SIZE_MAX;
    vireo_epoll_error_t error = {VIREO_EPOLL_STAGE_CLOSE, EIO};
    errno = EACCES;
    CHECK(vireo_epoll_wait(f->owner, timeout_ms, events, 3, &count, &error) == VIREO_OK);
    CHECK(count == 1 && errno == EACCES);
    CHECK(error.stage == VIREO_EPOLL_STAGE_NONE && error.system_errno == 0);
    if (count == 1) {
        CHECK(events[0].token == token);
        CHECK((events[0].events & required) == required);
        CHECK((events[0].events & forbidden) == 0);
        CHECK(memcmp(&events[1], saved + sizeof(events[0]), 2 * sizeof(events[0])) == 0);
    }
}

/* 排除目录流自身，不把观察工具的占用当作实例泄漏。 */
static size_t fd_count(void)
{
    DIR *dir = opendir("/proc/self/fd");
    CHECK(dir != NULL);
    if (dir == NULL) return SIZE_MAX;
    int const own = dirfd(dir);
    size_t count = 0;
    struct dirent *entry;
    errno = 0;
    while ((entry = readdir(dir)) != NULL) {
        char *end;
        long value = strtol(entry->d_name, &end, 10);
        if (*entry->d_name != '\0' && *end == '\0' && value >= 0 && value != own) ++count;
    }
    CHECK(errno == 0 && closedir(dir) == 0);
    return count;
}

static void arguments(void)
{
    fixture_t f;
    REQUIRE(start(&f, 2));
    vireo_epoll_event_t events[2];
    unsigned char saved[sizeof(events)];
    memset(events, 0x5a, sizeof(events));
    memcpy(saved, events, sizeof(events));
    size_t count = 71;
    vireo_epoll_error_t error;
    for (unsigned mode = 0; mode < 2; ++mode) {
        vireo_epoll_error_t *diag = mode == 0 ? &error : NULL;
        errno = EACCES;
        CHECK(vireo_epoll_wait(NULL, 0, events, 2, &count, diag) == VIREO_RESULT_INVALID_ARGUMENT);
        CHECK(vireo_epoll_wait(f.owner, 0, NULL, 2, &count, diag) == VIREO_RESULT_INVALID_ARGUMENT);
        CHECK(vireo_epoll_wait(f.owner, 0, events, 2, NULL, diag) == VIREO_RESULT_INVALID_ARGUMENT);
        CHECK(vireo_epoll_wait(f.owner, 0, events, 0, &count, diag) == VIREO_RESULT_INVALID_ARGUMENT);
        CHECK(vireo_epoll_wait(f.owner, -2, events, 2, &count, diag) == VIREO_RESULT_INVALID_ARGUMENT);
        CHECK(vireo_epoll_wait(f.owner, INT_MIN, events, 2, &count, diag) == VIREO_RESULT_INVALID_ARGUMENT);
        CHECK(errno == EACCES && count == 71 && f.calls == 0);
        CHECK(memcmp(saved, events, sizeof(events)) == 0);
        if (diag != NULL) CHECK(error.stage == VIREO_EPOLL_STAGE_NONE && error.system_errno == 0);
    }
    finish(&f);
}

static void empty_and_timeouts(void)
{
    fixture_t f;
    REQUIRE(start(&f, 2));
    vireo_epoll_event_t events[2];
    unsigned char saved[sizeof(events)];
    memset(events, 0xa5, sizeof(events));
    memcpy(saved, events, sizeof(events));
    size_t count = 72;
    vireo_epoll_error_t error;
    errno = EACCES;
    CHECK(vireo_epoll_wait(f.owner, 0, events, 2, &count, &error) == VIREO_OK);
    CHECK(count == 0 && errno == EACCES && f.last_timeout == 0);
    CHECK(memcmp(saved, events, sizeof(events)) == 0);
    struct timespec before, after;
    REQUIRE(clock_gettime(CLOCK_MONOTONIC, &before) == 0);
    CHECK(vireo_epoll_wait(f.owner, 2, events, 2, &count, &error) == VIREO_OK);
    REQUIRE(clock_gettime(CLOCK_MONOTONIC, &after) == 0);
    int64_t const elapsed = ((int64_t)after.tv_sec - (int64_t)before.tv_sec) * INT64_C(1000000000)
                             + ((int64_t)after.tv_nsec - (int64_t)before.tv_nsec);
    CHECK(elapsed >= INT64_C(2000000)); /* 只查最低等待，不要求调度上界。 */
    CHECK(count == 0 && error.stage == VIREO_EPOLL_STAGE_NONE && error.system_errno == 0);
    CHECK(errno == EACCES && f.last_timeout == 2 && f.calls == 2);
    CHECK(memcmp(saved, events, sizeof(events)) == 0);
    /* -1/INT_MAX 只注入空返回，避免用真实无限空等待挂住进程。 */
    f.synthetic = 1;
    f.cause = EIO;
    int const timeouts[] = {-1, 0, 1, INT_MAX};
    for (size_t i = 0; i < sizeof(timeouts) / sizeof(timeouts[0]); ++i) {
        count = 73;
        CHECK(vireo_epoll_wait(f.owner, timeouts[i], events, 2, &count, NULL) == VIREO_OK);
        CHECK(count == 0 && f.last_timeout == timeouts[i] && errno == EACCES);
        CHECK(memcmp(saved, events, sizeof(events)) == 0);
    }
    finish(&f);
}

static void capacity_limits(void)
{
    size_t const internal[] = {1, 4, VIREO_EPOLL_MAX_EVENTS};
    size_t const external[] = {1, 2, 4, VIREO_EPOLL_MAX_EVENTS, VIREO_EPOLL_MAX_EVENTS + 1};
    /* 所有传入容量都有真实完整caller数组，不用虚假的SIZE_MAX存储违反前置。 */
    vireo_epoll_event_t *events = malloc((VIREO_EPOLL_MAX_EVENTS + 1) * sizeof(*events));
    REQUIRE(events != NULL);
    for (size_t i = 0; i < sizeof(internal) / sizeof(internal[0]); ++i) {
        fixture_t f;
        if (!start(&f, internal[i])) { free(events); return; }
        f.synthetic = 1;
        for (size_t j = 0; j < sizeof(external) / sizeof(external[0]); ++j) {
            size_t count = 7;
            errno = EACCES;
            CHECK(vireo_epoll_wait(f.owner, 0, events, external[j], &count, NULL) == VIREO_OK);
            size_t const expected = internal[i] < external[j] ? internal[i] : external[j];
            CHECK(f.last_capacity == (int)expected && count == 0 && errno == EACCES);
        }
        CHECK(f.calls == 5);
        finish(&f);
    }
    free(events);
}

static void all_result_combinations(void)
{
    uint32_t const native[5] = {EPOLLIN, EPOLLOUT, EPOLLRDHUP, EPOLLERR, EPOLLHUP};
    uint32_t const public_bits[5] = {
        VIREO_EPOLL_EVENT_READ, VIREO_EPOLL_EVENT_WRITE, VIREO_EPOLL_EVENT_PEER_WRITE_CLOSED,
        VIREO_EPOLL_EVENT_ERROR, VIREO_EPOLL_EVENT_HANGUP
    };
    uint64_t const tokens[4] = {0, UINT64_C(0x8000000000000000),
                               UINT64_C(0x123456789abcdef0), UINT64_MAX};
    fixture_t f;
    REQUIRE(start(&f, 4));
    f.synthetic = 1;
    f.returned = 4;
    f.cause = EIO;
    for (unsigned combination = 0; combination < 32; ++combination) {
        uint32_t expected = 0, flags = 0;
        for (unsigned bit = 0; bit < 5; ++bit) {
            if ((combination & (1u << bit)) != 0) {
                expected |= public_bits[bit];
                flags |= native[bit];
            }
        }
        for (size_t i = 0; i < 4; ++i) {
            f.samples[i].events = flags;
            f.samples[i].data.u64 = tokens[i];
        }
        vireo_epoll_event_t events[5];
        unsigned char saved[sizeof(events)];
        memset(events, 0xa5, sizeof(events));
        memcpy(saved, events, sizeof(events));
        size_t count = 99;
        errno = EACCES;
        CHECK(vireo_epoll_wait(f.owner, 0, events, 5, &count, NULL) == VIREO_OK);
        CHECK(count == 4 && errno == EACCES && f.last_capacity == 4);
        for (size_t i = 0; i < 4; ++i) CHECK(events[i].token == tokens[i] && events[i].events == expected);
        CHECK(memcmp(&events[4], saved + 4 * sizeof(events[0]), sizeof(events[0])) == 0);
    }
    CHECK(f.calls == 32);
    finish(&f);
}

static void real_read_tokens_and_lt(void)
{
    fixture_t f;
    REQUIRE(start(&f, 2));
    int pair[2];
    REQUIRE(pair_open(pair));
    watch(&f, pair[0], VIREO_EPOLL_INTEREST_READ, 0);
    CHECK(send(pair[1], "abc", 3, MSG_NOSIGNAL) == 3);
    ready(&f, -1, 0, VIREO_EPOLL_EVENT_READ, VIREO_EPOLL_EVENT_WRITE);
    char byte = 0;
    CHECK(recv(pair[0], &byte, 1, 0) == 1 && byte == 'a');
    uint64_t const tokens[] = {UINT64_C(0x8000000000000000),
                               UINT64_C(0x123456789abcdef0), UINT64_MAX};
    for (size_t i = 0; i < sizeof(tokens) / sizeof(tokens[0]); ++i) {
        vireo_epoll_registration_t reg = {VIREO_EPOLL_INTEREST_READ, tokens[i]};
        CHECK(vireo_epoll_mod(f.owner, pair[0], &reg, NULL) == VIREO_OK);
        reg.token = 1; /* 改原输入不改变内核保存值，未读残留仍 LT 通知。 */
        ready(&f, 0, tokens[i], VIREO_EPOLL_EVENT_READ, VIREO_EPOLL_EVENT_WRITE);
    }
    char remaining[2];
    CHECK(recv(pair[0], remaining, 2, 0) == 2 && memcmp(remaining, "bc", 2) == 0);
    CHECK(recv(pair[0], &byte, 1, 0) == -1 && errno == EAGAIN);
    vireo_epoll_event_t event = {99, 31};
    size_t count = 7;
    CHECK(vireo_epoll_wait(f.owner, 0, &event, 1, &count, NULL) == VIREO_OK && count == 0);
    CHECK(event.token == 99 && event.events == 31);
    CHECK(vireo_epoll_del(f.owner, pair[0], NULL) == VIREO_OK);
    pair_close(pair);
    finish(&f);
}

static void real_write(void)
{
    fixture_t f;
    REQUIRE(start(&f, 2));
    int pair[2];
    REQUIRE(pair_open(pair));
    watch(&f, pair[0], VIREO_EPOLL_INTEREST_WRITE, UINT64_MAX);
    ready(&f, 0, UINT64_MAX, VIREO_EPOLL_EVENT_WRITE, VIREO_EPOLL_EVENT_READ);
    CHECK(send(pair[0], "x", 1, MSG_NOSIGNAL) == 1);
    char byte = 0;
    CHECK(recv(pair[1], &byte, 1, 0) == 1 && byte == 'x');
    CHECK(vireo_epoll_mod(f.owner, pair[0], &(vireo_epoll_registration_t){0, 99}, NULL) == VIREO_OK);
    size_t count = 4;
    vireo_epoll_event_t event;
    CHECK(vireo_epoll_wait(f.owner, 0, &event, 1, &count, NULL) == VIREO_OK && count == 0);
    pair_close(pair);
    finish(&f);
}

static void real_half_close(void)
{
    fixture_t f;
    REQUIRE(start(&f, 2));
    int pair[2];
    REQUIRE(pair_open(pair));
    watch(&f, pair[0], VIREO_EPOLL_INTEREST_READ | VIREO_EPOLL_INTEREST_PEER_WRITE_CLOSED, 42);
    CHECK(send(pair[1], "z", 1, MSG_NOSIGNAL) == 1);
    CHECK(shutdown(pair[1], SHUT_WR) == 0);
    ready(&f, 0, 42, VIREO_EPOLL_EVENT_READ | VIREO_EPOLL_EVENT_PEER_WRITE_CLOSED,
          VIREO_EPOLL_EVENT_HANGUP);
    char byte = 0;
    CHECK(recv(pair[0], &byte, 1, 0) == 1 && byte == 'z');
    CHECK(recv(pair[0], &byte, 1, 0) == 0);
    /* READ 可以是EOF，半关闭仍允许本端发送。 */
    ready(&f, 0, 42, VIREO_EPOLL_EVENT_READ | VIREO_EPOLL_EVENT_PEER_WRITE_CLOSED, 0);
    CHECK(send(pair[0], "y", 1, MSG_NOSIGNAL) == 1);
    CHECK(recv(pair[1], &byte, 1, 0) == 1 && byte == 'y');
    pair_close(pair);
    finish(&f);
}

static void real_zero_interest_hup(void)
{
    fixture_t f;
    REQUIRE(start(&f, 1));
    int pair[2];
    REQUIRE(pair_open(pair));
    watch(&f, pair[0], 0, UINT64_MAX);
    CHECK(send(pair[1], "h", 1, MSG_NOSIGNAL) == 1);
    CHECK(close(pair[1]) == 0);
    ready(&f, 0, UINT64_MAX, VIREO_EPOLL_EVENT_HANGUP, VIREO_EPOLL_EVENT_WRITE);
    char byte = 0;
    CHECK(recv(pair[0], &byte, 1, 0) == 1 && byte == 'h');
    CHECK(recv(pair[0], &byte, 1, 0) == 0);
    CHECK(close(pair[0]) == 0);
    finish(&f);
}

static void real_zero_interest_error(void)
{
    fixture_t f;
    REQUIRE(start(&f, 1));
    int pipefd[2];
    REQUIRE(pipe2(pipefd, O_NONBLOCK | O_CLOEXEC) == 0);
    watch(&f, pipefd[1], 0, 0);
    CHECK(close(pipefd[0]) == 0);
    ready(&f, 0, 0, VIREO_EPOLL_EVENT_ERROR, VIREO_EPOLL_EVENT_READ);
    /* 不写断管道，避免把SIGPIPE策略带入本项。 */
    CHECK(close(pipefd[1]) == 0);
    finish(&f);
}

static void batched_streams(void)
{
    size_t const internal[] = {1, 2, 4};
    size_t const external[] = {4, 1, 2};
    for (size_t mode = 0; mode < 3; ++mode) {
        fixture_t f;
        REQUIRE(start(&f, internal[mode]));
        int pairs[3][2];
        for (size_t i = 0; i < 3; ++i) {
            REQUIRE(pair_open(pairs[i]));
            watch(&f, pairs[i][0], VIREO_EPOLL_INTEREST_READ, UINT64_C(1001) + (uint64_t)i);
            char byte = (char)('a' + (int)i);
            CHECK(send(pairs[i][1], &byte, 1, MSG_NOSIGNAL) == 1);
        }
        unsigned seen = 0;
        unsigned rounds = 0;
        size_t const bound = internal[mode] < external[mode] ? internal[mode] : external[mode];
        while (seen != 7 && rounds++ < 6) {
            vireo_epoll_event_t events[4];
            unsigned char saved[sizeof(events)];
            memset(events, 0xa5, sizeof(events));
            memcpy(saved, events, sizeof(events));
            size_t count = 99;
            CHECK(vireo_epoll_wait(f.owner, 0, events, external[mode], &count, NULL) == VIREO_OK);
            CHECK(count > 0 && count <= bound && f.last_capacity == (int)bound);
            if (count > bound) break;
            CHECK(memcmp((unsigned char *)events + count * sizeof(events[0]),
                         saved + count * sizeof(events[0]), sizeof(events) - count * sizeof(events[0])) == 0);
            for (size_t i = 0; i < count; ++i) {
                CHECK(events[i].token >= 1001 && events[i].token <= 1003);
                if (events[i].token < 1001 || events[i].token > 1003) continue;
                size_t const slot = (size_t)(events[i].token - 1001);
                CHECK((seen & (1u << slot)) == 0);
                CHECK((events[i].events & VIREO_EPOLL_EVENT_READ) != 0);
                char byte = 0;
                CHECK(recv(pairs[slot][0], &byte, 1, 0) == 1 && byte == (char)('a' + (int)slot));
                seen |= 1u << slot;
            }
        }
        CHECK(seen == 7);
        for (size_t i = 0; i < 3; ++i) pair_close(pairs[i]);
        finish(&f);
    }
}

static void value_lifetime(void)
{
    fixture_t f;
    REQUIRE(start(&f, 1));
    int pair[2];
    REQUIRE(pair_open(pair));
    watch(&f, pair[0], VIREO_EPOLL_INTEREST_READ, 111);
    CHECK(send(pair[1], "c", 1, MSG_NOSIGNAL) == 1);
    vireo_epoll_event_t first = {0};
    size_t first_count = 0;
    CHECK(vireo_epoll_wait(f.owner, 0, &first, 1, &first_count, NULL) == VIREO_OK);
    CHECK(first_count == 1 && first.token == 111);
    unsigned char saved[sizeof(first)];
    memcpy(saved, &first, sizeof(first));
    CHECK(vireo_epoll_mod(f.owner, pair[0], &(vireo_epoll_registration_t){VIREO_EPOLL_INTEREST_READ, 222}, NULL) == VIREO_OK);
    ready(&f, 0, 222, VIREO_EPOLL_EVENT_READ, 0);
    CHECK(memcmp(saved, &first, sizeof(first)) == 0 && first_count == 1);
    CHECK(vireo_epoll_del(f.owner, pair[0], NULL) == VIREO_OK);
    /* 数值仍可保存，不能据此访问已销毁对象。 */
    size_t count = 9;
    vireo_epoll_event_t empty;
    CHECK(vireo_epoll_wait(f.owner, 0, &empty, 1, &count, NULL) == VIREO_OK && count == 0);
    finish(&f);
    CHECK(memcmp(saved, &first, sizeof(first)) == 0 && first_count == 1);
    char byte = 0;
    CHECK(recv(pair[0], &byte, 1, 0) == 1 && byte == 'c');
    pair_close(pair);
}

static void injected_system_errors(void)
{
    int const causes[] = {EINTR, EBADF, EINVAL, EFAULT, ENOMEM, EIO};
    fixture_t f;
    REQUIRE(start(&f, 2));
    int pair[2];
    REQUIRE(pair_open(pair));
    watch(&f, pair[0], VIREO_EPOLL_INTEREST_READ, 81);
    CHECK(send(pair[1], "e", 1, MSG_NOSIGNAL) == 1);
    vireo_epoll_info_t before, after;
    CHECK(vireo_epoll_inspect(f.owner, &before) == VIREO_OK);
    f.synthetic = 1;
    f.returned = -1;
    f.samples[0].events = EPOLLIN;
    for (size_t i = 0; i < sizeof(causes) / sizeof(causes[0]); ++i) {
        for (unsigned mode = 0; mode < 2; ++mode) {
            f.cause = causes[i];
            vireo_epoll_event_t events[2];
            unsigned char saved[sizeof(events)];
            memset(events, 0xa5, sizeof(events));
            memcpy(saved, events, sizeof(events));
            size_t count = 82;
            vireo_epoll_error_t error = {VIREO_EPOLL_STAGE_CLOSE, EIO};
            unsigned const calls = f.calls;
            errno = EACCES;
            CHECK(vireo_epoll_wait(f.owner, 7, events, 2, &count, mode == 0 ? &error : NULL) == VIREO_RESULT_IO);
            CHECK(f.calls == calls + 1 && f.last_timeout == 7 && errno == EACCES);
            CHECK(count == 82 && memcmp(saved, events, sizeof(events)) == 0);
            if (mode == 0) CHECK(error.stage == VIREO_EPOLL_STAGE_WAIT && error.system_errno == causes[i]);
            CHECK(vireo_epoll_inspect(f.owner, &after) == VIREO_OK);
            CHECK(before.event_capacity == after.event_capacity && before.allocation_bytes == after.allocation_bytes);
            CHECK(f.allocations == 2 && f.live == 2 && f.releases == 0);
        }
    }
    f.synthetic = 0;
    ready(&f, 0, 81, VIREO_EPOLL_EVENT_READ, 0); /* 错误后仍可等待原watch。 */
    CHECK(vireo_epoll_del(f.owner, pair[0], NULL) == VIREO_OK);
    pair_close(pair);
    finish(&f);
}

static void invalid_batches(void)
{
    fixture_t f;
    REQUIRE(start(&f, 2));
    f.synthetic = 1;
    f.cause = EIO;
    /* 无越界写：只返回错误计数，或让第二条异常以证明第一条也未交付。 */
    int const counts[] = {-2, INT_MIN, 3, INT_MAX, 2, 2, 2, 2, 2};
    uint32_t const unknown[] = {EPOLLPRI, EPOLLET, EPOLLONESHOT, UINT32_C(0x08000000), UINT32_MAX};
    for (size_t i = 0; i < sizeof(counts) / sizeof(counts[0]); ++i) {
        f.returned = counts[i];
        f.samples[0] = (struct epoll_event){.events = EPOLLIN, .data.u64 = 83};
        f.samples[1] = (struct epoll_event){.events = i < 4 ? EPOLLOUT : unknown[i - 4], .data.u64 = 84};
        for (unsigned mode = 0; mode < 2; ++mode) {
            vireo_epoll_event_t events[3];
            unsigned char saved[sizeof(events)];
            memset(events, 0x5a, sizeof(events));
            memcpy(saved, events, sizeof(events));
            size_t count = 85;
            vireo_epoll_error_t error;
            errno = EACCES;
            unsigned const calls = f.calls;
            CHECK(vireo_epoll_wait(f.owner, 0, events, 3, &count, mode == 0 ? &error : NULL) == VIREO_RESULT_INTERNAL);
            CHECK(count == 85 && memcmp(saved, events, sizeof(events)) == 0);
            CHECK(errno == EACCES && f.calls == calls + 1);
            if (mode == 0) CHECK(error.stage == VIREO_EPOLL_STAGE_WAIT && error.system_errno == 0);
        }
    }
    f.returned = 1;
    vireo_epoll_event_t event;
    size_t count = 0;
    CHECK(vireo_epoll_wait(f.owner, 0, &event, 1, &count, NULL) == VIREO_OK);
    CHECK(count == 1 && event.token == 83 && event.events == VIREO_EPOLL_EVENT_READ);
    finish(&f);
}

/* 仅测试seam人为破坏内部fd，真实内核EBADF；调用者没有这种公开能力。 */
static void real_closed_instance_fd(void)
{
    fixture_t f;
    REQUIRE(start(&f, 2));
    CHECK(close(f.epfd) == 0);
    vireo_epoll_event_t events[2];
    unsigned char saved[sizeof(events)];
    memset(events, 0xa5, sizeof(events));
    memcpy(saved, events, sizeof(events));
    size_t count = 99;
    vireo_epoll_error_t error;
    errno = EACCES;
    CHECK(vireo_epoll_wait(f.owner, 0, events, 2, &count, &error) == VIREO_RESULT_IO);
    CHECK(error.stage == VIREO_EPOLL_STAGE_WAIT && error.system_errno == EBADF);
    CHECK(errno == EACCES && count == 99 && memcmp(saved, events, sizeof(events)) == 0);
    CHECK(f.calls == 1 && f.allocations == 2 && f.live == 2);
    /* 两次close之间不取得任何新fd；销毁显式报错但仍消费两块内存。 */
    CHECK(vireo_epoll_destroy(&f.owner, &error) == VIREO_RESULT_IO);
    CHECK(error.stage == VIREO_EPOLL_STAGE_CLOSE && error.system_errno == EBADF);
    CHECK(f.owner == NULL && f.epfd == -1 && f.live == 0 && f.releases == 2 && errno == EACCES);
}

static void production_zero_instance_fd(void)
{
    pid_t const child = fork();
    REQUIRE(child >= 0);
    if (child == 0) {
        if (close(STDIN_FILENO) != 0) _exit(10);
        vireo_epoll_t *owner = NULL;
        vireo_epoll_options_t const options = {2, VIREO_EPOLL_MAX_MEMORY};
        errno = EACCES;
        if (vireo_epoll_create(&options, &owner, NULL) != VIREO_OK || errno != EACCES) _exit(11);
        if (fcntl(STDIN_FILENO, F_GETFD) < 0) _exit(12); /* 最低空fd0由实例取得。 */
        int pair[2];
        if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, pair) != 0) _exit(13);
        vireo_epoll_registration_t const reg = {VIREO_EPOLL_INTEREST_READ, UINT64_MAX};
        if (vireo_epoll_add(owner, pair[0], &reg, NULL) != VIREO_OK) _exit(14);
        if (send(pair[1], "p", 1, MSG_NOSIGNAL) != 1) _exit(15);
        vireo_epoll_event_t event;
        size_t count = 9;
        vireo_epoll_error_t error;
        errno = EACCES;
        if (vireo_epoll_wait(owner, -1, &event, 1, &count, &error) != VIREO_OK || count != 1 ||
            event.token != UINT64_MAX || (event.events & VIREO_EPOLL_EVENT_READ) == 0 ||
            error.stage != VIREO_EPOLL_STAGE_NONE || error.system_errno != 0 || errno != EACCES) _exit(16);
        if (vireo_epoll_destroy(&owner, NULL) != VIREO_OK || owner != NULL || errno != EACCES) _exit(17);
        if (fcntl(STDIN_FILENO, F_GETFD) != -1 || errno != EBADF) _exit(18);
        char byte = 0;
        if (recv(pair[0], &byte, 1, 0) != 1 || byte != 'p') _exit(19);
        if (close(pair[0]) != 0 || close(pair[1]) != 0) _exit(20);
        _exit(0);
    }
    int status = 0;
    CHECK(waitpid(child, &status, 0) == child);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

int main(void)
{
    size_t const baseline = fd_count();
    void (*groups[])(void) = {
        arguments, empty_and_timeouts, capacity_limits, all_result_combinations,
        real_read_tokens_and_lt, real_write, real_half_close,
        real_zero_interest_hup, real_zero_interest_error, batched_streams,
        value_lifetime, injected_system_errors, invalid_batches, real_closed_instance_fd,
        production_zero_instance_fd
    };
    for (size_t i = 0; i < sizeof(groups) / sizeof(groups[0]); ++i) groups[i]();
    CHECK(fd_count() == baseline);
    if (failures != 0) {
        fprintf(stderr, "test_epoll_wait: %u failures\n", failures);
        return EXIT_FAILURE;
    }
    puts("test_epoll_wait: all 15 test groups passed, 12 system and 18 invalid-batch injections, fd baseline restored");
    return EXIT_SUCCESS;
}
