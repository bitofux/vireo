/*
 * PROJECT : VIREO
 * FILE    : test_epoll_registration.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-02
 * BRIEF   : 此模块负责：
 * -- 验证 LT 注册、token 替换、严格错误和客户端 fd 借用
 * -- 原生零超时 wait 只作本模块观察，不提供公共等待接口
 */
#define _GNU_SOURCE
#include <vireo/net/epoll.h>
#include "net/epoll_internal.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

static unsigned failures;
#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition); \
    ++failures; } } while (0)
#define REQUIRE(condition) do { if (!(condition)) { CHECK(condition); return; } } while (0)

typedef struct fixture {
    vireo_epoll_t *owner;
    int epfd;
    int injected_error;
    unsigned allocations;
    unsigned live;
    unsigned releases;
    unsigned calls;
    int last_operation;
    int last_fd;
    int event_present;
    struct epoll_event event;
} fixture_t;

/* 故障表只捕获调用与注入返回，正常路径始终使用真实内核集合。 */
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
    ++f->calls;
    f->last_operation = operation;
    f->last_fd = fd;
    f->event_present = event != NULL;
    if (event != NULL) f->event = *event;
    if (f->injected_error != 0) {
        errno = f->injected_error;
        return -1;
    }
    return epoll_ctl(epfd, operation, fd, event);
}

/* 等待项只要求旧夹具配齐操作表，注册 oracle 仍独立使用原生零超时观察。 */
static int wait_fd(void *context, int epfd, struct epoll_event *events,
                   int maxevents, int timeout_ms)
{
    (void)context;
    return epoll_wait(epfd, events, maxevents, timeout_ms);
}

static int start(fixture_t *f, size_t capacity)
{
    *f = (fixture_t){.epfd = -1};
    vireo_epoll_options_t options = {capacity, VIREO_EPOLL_MAX_MEMORY};
    vireo_epoll_ops_t ops = {f, allocate, deallocate, create_fd, close_fd, control_fd, wait_fd};
    vireo_result_t result = vireo_epoll_create_with_ops(&options, &ops, &f->owner, NULL);
    CHECK(result == VIREO_OK);
    return result == VIREO_OK;
}

static void finish(fixture_t *f)
{
    CHECK(vireo_epoll_destroy(&f->owner, NULL) == VIREO_OK);
    CHECK(f->owner == NULL && f->epfd == -1 && f->live == 0);
    CHECK(f->allocations == 2 && f->releases == 2);
}

/* 默认使用本地非阻塞 stream socket，避免网络地址、sleep 与外部服务。 */
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

static int observe(fixture_t const *f, struct epoll_event *events, int count)
{
    int result = epoll_wait(f->epfd, events, count, 0);
    CHECK(result >= 0);
    return result;
}

static void expect_event(fixture_t const *f, uint64_t token, uint32_t bits)
{
    struct epoll_event event = {0};
    int count = observe(f, &event, 1);
    CHECK(count == 1);
    if (count == 1) {
        CHECK(event.data.u64 == token);
        CHECK((event.events & bits) == bits);
    }
}

/* 排除观察目录的自身 fd；不把目录扫描造成的瞬时占用计为泄漏。 */
static size_t fd_count(void)
{
    DIR *dir = opendir("/proc/self/fd");
    CHECK(dir != NULL);
    if (dir == NULL) return SIZE_MAX;
    int own = dirfd(dir);
    size_t count = 0;
    struct dirent *entry;
    errno = 0;
    while ((entry = readdir(dir)) != NULL) {
        char *end;
        long value = strtol(entry->d_name, &end, 10);
        if (*entry->d_name != '\0' && *end == '\0' && value >= 0 && value != own) ++count;
    }
    CHECK(errno == 0);
    CHECK(closedir(dir) == 0);
    return count;
}

static void arguments(void)
{
    fixture_t f;
    REQUIRE(start(&f, 1));
    int pair[2];
    REQUIRE(pair_open(pair));
    vireo_epoll_registration_t const reg = {VIREO_EPOLL_INTEREST_READ, 1};
    vireo_epoll_error_t error = {VIREO_EPOLL_STAGE_CLOSE, EIO};
    errno = EACCES;
    CHECK(vireo_epoll_add(NULL, pair[0], &reg, &error) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_epoll_mod(NULL, pair[0], &reg, &error) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_epoll_del(NULL, pair[0], &error) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_epoll_add(f.owner, -1, &reg, &error) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_epoll_mod(f.owner, -1, &reg, &error) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_epoll_del(f.owner, -1, &error) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_epoll_add(f.owner, pair[0], NULL, &error) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_epoll_mod(f.owner, pair[0], NULL, &error) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(error.stage == VIREO_EPOLL_STAGE_NONE && error.system_errno == 0);
    CHECK(f.calls == 0 && f.allocations == 2 && errno == EACCES);
    CHECK(vireo_epoll_add(NULL, -1, NULL, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_epoll_mod(NULL, -1, NULL, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_epoll_del(NULL, -1, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(errno == EACCES && f.calls == 0);
    pair_close(pair);
    finish(&f);
}

static void interest_mapping(void)
{
    /* 独立原生预期表，明确未混入 ET/ONESHOT/EXCLUSIVE 或 ERR/HUP 输入位。 */
    uint32_t const native[] = {0, EPOLLIN, EPOLLOUT, EPOLLIN | EPOLLOUT,
                              EPOLLRDHUP, EPOLLIN | EPOLLRDHUP,
                              EPOLLOUT | EPOLLRDHUP, EPOLLIN | EPOLLOUT | EPOLLRDHUP};
    fixture_t f;
    REQUIRE(start(&f, 1));
    int pair[2];
    REQUIRE(pair_open(pair));
    for (uint32_t i = 0; i < 8; ++i) {
        vireo_epoll_registration_t reg = {i, UINT64_MAX - i};
        vireo_epoll_error_t error = {VIREO_EPOLL_STAGE_CLOSE, EIO};
        errno = EACCES;
        CHECK(vireo_epoll_add(f.owner, pair[0], &reg, &error) == VIREO_OK);
        CHECK(f.last_operation == EPOLL_CTL_ADD && f.last_fd == pair[0] && f.event_present);
        CHECK(f.event.events == native[i] && f.event.data.u64 == reg.token);
        CHECK(error.stage == VIREO_EPOLL_STAGE_NONE && error.system_errno == 0 && errno == EACCES);
        reg = (vireo_epoll_registration_t){7 - i, UINT64_C(0x123456789abcdef0)};
        CHECK(vireo_epoll_mod(f.owner, pair[0], &reg, NULL) == VIREO_OK);
        CHECK(f.last_operation == EPOLL_CTL_MOD && f.event.events == native[7 - i]);
        CHECK(f.event.data.u64 == reg.token && errno == EACCES);
        CHECK(vireo_epoll_del(f.owner, pair[0], &error) == VIREO_OK);
        CHECK(f.last_operation == EPOLL_CTL_DEL && !f.event_present);
        CHECK(error.stage == VIREO_EPOLL_STAGE_NONE && error.system_errno == 0 && errno == EACCES);
    }
    CHECK(f.calls == 24 && f.allocations == 2 && f.live == 2);
    pair_close(pair);
    finish(&f);
}

static void unknown_interests(void)
{
    fixture_t f;
    REQUIRE(start(&f, 1));
    int pair[2];
    REQUIRE(pair_open(pair));
    vireo_epoll_registration_t reg = {VIREO_EPOLL_INTEREST_READ, 77};
    REQUIRE(vireo_epoll_add(f.owner, pair[0], &reg, NULL) == VIREO_OK);
    REQUIRE(write(pair[1], "abc", 3) == 3);
    uint32_t const masks[] = {8, UINT32_C(0x80000000), UINT32_MAX, EPOLLET, EPOLLONESHOT};
    unsigned calls = f.calls;
    for (size_t i = 0; i < sizeof(masks) / sizeof(masks[0]); ++i) {
        reg = (vireo_epoll_registration_t){masks[i], 88};
        vireo_epoll_error_t error = {VIREO_EPOLL_STAGE_ADD, EIO};
        errno = EACCES;
        CHECK(vireo_epoll_add(f.owner, pair[0], &reg, &error) == VIREO_RESULT_INVALID_ARGUMENT);
        CHECK(vireo_epoll_mod(f.owner, pair[0], &reg, &error) == VIREO_RESULT_INVALID_ARGUMENT);
        CHECK(error.stage == VIREO_EPOLL_STAGE_NONE && error.system_errno == 0);
        CHECK(errno == EACCES && f.calls == calls);
    }
    expect_event(&f, 77, EPOLLIN); /* 拒绝错误输入后原关注与 token 保留。 */
    CHECK(vireo_epoll_del(f.owner, pair[0], NULL) == VIREO_OK);
    pair_close(pair);
    finish(&f);
}

static void lt_and_tokens(void)
{
    fixture_t f;
    REQUIRE(start(&f, 1));
    int pair[2];
    REQUIRE(pair_open(pair));
    vireo_epoll_registration_t reg = {VIREO_EPOLL_INTEREST_READ, 0};
    REQUIRE(vireo_epoll_add(f.owner, pair[0], &reg, NULL) == VIREO_OK);
    reg.token = 9; /* 改原输入不改内核保存值。 */
    REQUIRE(write(pair[1], "old", 3) == 3);
    expect_event(&f, 0, EPOLLIN);
    char bytes[3];
    REQUIRE(read(pair[0], bytes, 1) == 1);
    CHECK(bytes[0] == 'o');
    expect_event(&f, 0, EPOLLIN); /* 未读尽，LT 不等待新的写入。 */
    uint64_t const tokens[] = {UINT64_C(0x8000000000000000),
                               UINT64_C(0x0123456789abcdef), UINT64_MAX};
    for (size_t i = 0; i < 3; ++i) {
        reg.token = tokens[i];
        errno = EACCES;
        CHECK(vireo_epoll_mod(f.owner, pair[0], &reg, NULL) == VIREO_OK);
        CHECK(errno == EACCES);
        expect_event(&f, tokens[i], EPOLLIN);
    }
    REQUIRE(read(pair[0], bytes + 1, 2) == 2);
    CHECK(memcmp(bytes, "old", 3) == 0);
    CHECK(read(pair[0], bytes, 3) == -1 && errno == EAGAIN);
    struct epoll_event event;
    CHECK(observe(&f, &event, 1) == 0);
    CHECK(vireo_epoll_del(f.owner, pair[0], NULL) == VIREO_OK);
    pair_close(pair);
    finish(&f);
}

static void mod_replaces_and_del(void)
{
    fixture_t f;
    REQUIRE(start(&f, 1));
    int pair[2];
    REQUIRE(pair_open(pair));
    vireo_epoll_registration_t reg = {VIREO_EPOLL_INTEREST_WRITE, 111};
    REQUIRE(vireo_epoll_add(f.owner, pair[0], &reg, NULL) == VIREO_OK);
    expect_event(&f, 111, EPOLLOUT);
    reg = (vireo_epoll_registration_t){VIREO_EPOLL_INTEREST_READ, 222};
    REQUIRE(vireo_epoll_mod(f.owner, pair[0], &reg, NULL) == VIREO_OK);
    struct epoll_event event;
    CHECK(observe(&f, &event, 1) == 0); /* 可写仍成立，但旧 WRITE 已被替换。 */
    REQUIRE(write(pair[1], "x", 1) == 1);
    expect_event(&f, 222, EPOLLIN);
    reg = (vireo_epoll_registration_t){VIREO_EPOLL_INTEREST_WRITE, 333};
    REQUIRE(vireo_epoll_mod(f.owner, pair[0], &reg, NULL) == VIREO_OK);
    REQUIRE(observe(&f, &event, 1) == 1);
    CHECK(event.data.u64 == 333 && (event.events & EPOLLOUT) != 0);
    CHECK((event.events & EPOLLIN) == 0); /* socket 仍有未读字节，旧 READ 已被移除。 */
    CHECK(vireo_epoll_del(f.owner, pair[0], NULL) == VIREO_OK);
    CHECK(observe(&f, &event, 1) == 0);
    CHECK(fcntl(pair[0], F_GETFD) >= 0);
    char byte;
    CHECK(read(pair[0], &byte, 1) == 1 && byte == 'x');
    pair_close(pair);
    finish(&f);
}

static void strict_errors(void)
{
    fixture_t f;
    REQUIRE(start(&f, 1));
    int pair[2];
    REQUIRE(pair_open(pair));
    vireo_epoll_registration_t reg = {VIREO_EPOLL_INTEREST_WRITE, 11};
    vireo_epoll_error_t error;
    errno = EACCES;
    CHECK(vireo_epoll_mod(f.owner, pair[0], &reg, &error) == VIREO_RESULT_IO);
    CHECK(error.stage == VIREO_EPOLL_STAGE_MOD && error.system_errno == ENOENT && errno == EACCES);
    CHECK(vireo_epoll_del(f.owner, pair[0], &error) == VIREO_RESULT_IO);
    CHECK(error.stage == VIREO_EPOLL_STAGE_DEL && error.system_errno == ENOENT && errno == EACCES);
    REQUIRE(vireo_epoll_add(f.owner, pair[0], &reg, &error) == VIREO_OK);
    reg = (vireo_epoll_registration_t){VIREO_EPOLL_INTEREST_READ, 22};
    CHECK(vireo_epoll_add(f.owner, pair[0], &reg, &error) == VIREO_RESULT_IO);
    CHECK(error.stage == VIREO_EPOLL_STAGE_ADD && error.system_errno == EEXIST && errno == EACCES);
    expect_event(&f, 11, EPOLLOUT); /* 重复 ADD 没有隐式 MOD 原项。 */
    CHECK(f.calls == 4);
    CHECK(vireo_epoll_del(f.owner, pair[0], &error) == VIREO_OK);
    CHECK(error.stage == VIREO_EPOLL_STAGE_NONE && error.system_errno == 0);
    CHECK(vireo_epoll_del(f.owner, pair[0], &error) == VIREO_RESULT_IO);
    CHECK(error.stage == VIREO_EPOLL_STAGE_DEL && error.system_errno == ENOENT);
    CHECK(f.calls == 6);
    pair_close(pair);
    finish(&f);
}

static void real_system_errors(void)
{
    fixture_t f;
    REQUIRE(start(&f, 1));
    vireo_epoll_registration_t const reg = {VIREO_EPOLL_INTEREST_READ, 1};
    vireo_epoll_error_t error;
    char name[] = "/tmp/vireo-epoll-registration-XXXXXX";
    int regular = mkstemp(name);
    REQUIRE(regular >= 0);
    CHECK(unlink(name) == 0);
    errno = EACCES;
    CHECK(vireo_epoll_add(f.owner, regular, &reg, &error) == VIREO_RESULT_IO);
    CHECK(error.stage == VIREO_EPOLL_STAGE_ADD && error.system_errno == EPERM && errno == EACCES);
    CHECK(vireo_epoll_add(f.owner, f.epfd, &reg, &error) == VIREO_RESULT_IO);
    CHECK(error.stage == VIREO_EPOLL_STAGE_ADD && error.system_errno == EINVAL && errno == EACCES);
    CHECK(close(regular) == 0);
    errno = EACCES;
    CHECK(vireo_epoll_add(f.owner, regular, &reg, &error) == VIREO_RESULT_IO);
    CHECK(error.stage == VIREO_EPOLL_STAGE_ADD && error.system_errno == EBADF && errno == EACCES);
    CHECK(vireo_epoll_mod(f.owner, regular, &reg, &error) == VIREO_RESULT_IO);
    CHECK(error.stage == VIREO_EPOLL_STAGE_MOD && error.system_errno == EBADF && errno == EACCES);
    CHECK(vireo_epoll_del(f.owner, regular, &error) == VIREO_RESULT_IO);
    CHECK(error.stage == VIREO_EPOLL_STAGE_DEL && error.system_errno == EBADF && errno == EACCES);
    CHECK(f.calls == 5);
    finish(&f);
}

static void injected_errors(void)
{
    fixture_t f;
    REQUIRE(start(&f, 1));
    int pair[2];
    REQUIRE(pair_open(pair));
    vireo_epoll_registration_t reg = {VIREO_EPOLL_INTEREST_READ, 456};
    REQUIRE(vireo_epoll_add(f.owner, pair[0], &reg, NULL) == VIREO_OK);
    REQUIRE(write(pair[1], "y", 1) == 1);
    reg = (vireo_epoll_registration_t){VIREO_EPOLL_INTEREST_WRITE, 789};
    int const causes[] = {EINTR, ENOMEM, ENOSPC, EBADF, EPERM, EINVAL, EIO};
    vireo_epoll_stage_t const stages[] = {VIREO_EPOLL_STAGE_ADD, VIREO_EPOLL_STAGE_MOD,
                                         VIREO_EPOLL_STAGE_DEL};
    vireo_epoll_t *original = f.owner;
    vireo_epoll_info_t before, after;
    REQUIRE(vireo_epoll_inspect(f.owner, &before) == VIREO_OK);
    for (size_t i = 0; i < 7; ++i) {
        f.injected_error = causes[i];
        for (size_t op = 0; op < 3; ++op) {
            for (size_t diagnostic = 0; diagnostic < 2; ++diagnostic) {
                unsigned calls = f.calls;
                vireo_epoll_error_t error = {VIREO_EPOLL_STAGE_NONE, 0};
                vireo_epoll_error_t *out = diagnostic == 0 ? &error : NULL;
                errno = EACCES;
                vireo_result_t result;
                if (op == 0) result = vireo_epoll_add(f.owner, pair[0], &reg, out);
                else if (op == 1) result = vireo_epoll_mod(f.owner, pair[0], &reg, out);
                else result = vireo_epoll_del(f.owner, pair[0], out);
                CHECK(result == VIREO_RESULT_IO && errno == EACCES);
                CHECK(f.calls == calls + 1 && f.owner == original);
                if (out != NULL) CHECK(error.stage == stages[op] && error.system_errno == causes[i]);
                expect_event(&f, 456, EPOLLIN);
                CHECK(vireo_epoll_inspect(f.owner, &after) == VIREO_OK);
                CHECK(after.event_capacity == before.event_capacity && after.events_bytes == before.events_bytes);
                CHECK(after.allocation_bytes == before.allocation_bytes && after.max_memory_bytes == before.max_memory_bytes);
                CHECK(f.allocations == 2 && f.releases == 0 && f.live == 2);
            }
        }
    }
    f.injected_error = 0;
    CHECK(vireo_epoll_mod(f.owner, pair[0], &reg, NULL) == VIREO_OK);
    expect_event(&f, 789, EPOLLOUT);
    CHECK(vireo_epoll_del(f.owner, pair[0], NULL) == VIREO_OK);
    pair_close(pair);
    finish(&f);
    puts("epoll registration: 42 injected failures, one call each, no fallback/retry, original watch retained");
}

static void zero_interest_hup(void)
{
    fixture_t f;
    REQUIRE(start(&f, 1));
    int pair[2];
    REQUIRE(pair_open(pair));
    vireo_epoll_registration_t const reg = {0, UINT64_MAX};
    REQUIRE(vireo_epoll_add(f.owner, pair[0], &reg, NULL) == VIREO_OK);
    REQUIRE(write(pair[1], "z", 1) == 1);
    struct epoll_event event;
    CHECK(observe(&f, &event, 1) == 0); /* 零关注没有显式 READ。 */
    CHECK(close(pair[1]) == 0);
    expect_event(&f, UINT64_MAX, EPOLLHUP);
    char byte;
    CHECK(read(pair[0], &byte, 1) == 1 && byte == 'z');
    CHECK(read(pair[0], &byte, 1) == 0);
    CHECK(vireo_epoll_del(f.owner, pair[0], NULL) == VIREO_OK);
    CHECK(close(pair[0]) == 0);
    finish(&f);
}

static void zero_interest_err(void)
{
    fixture_t f;
    REQUIRE(start(&f, 1));
    int pipefd[2];
    REQUIRE(pipe2(pipefd, O_NONBLOCK | O_CLOEXEC) == 0);
    vireo_epoll_registration_t const reg = {0, 0};
    REQUIRE(vireo_epoll_add(f.owner, pipefd[1], &reg, NULL) == VIREO_OK);
    struct epoll_event event;
    CHECK(observe(&f, &event, 1) == 0);
    CHECK(close(pipefd[0]) == 0);
    expect_event(&f, 0, EPOLLERR); /* 不写断管道，避免 SIGPIPE 改变测试进程。 */
    CHECK(vireo_epoll_del(f.owner, pipefd[1], NULL) == VIREO_OK);
    CHECK(close(pipefd[1]) == 0);
    finish(&f);
}

static void peer_half_close(void)
{
    fixture_t f;
    REQUIRE(start(&f, 1));
    int pair[2];
    REQUIRE(pair_open(pair));
    vireo_epoll_registration_t const reg = {VIREO_EPOLL_INTEREST_PEER_WRITE_CLOSED, 123};
    REQUIRE(vireo_epoll_add(f.owner, pair[0], &reg, NULL) == VIREO_OK);
    REQUIRE(write(pair[1], "a", 1) == 1);
    REQUIRE(shutdown(pair[1], SHUT_WR) == 0);
    expect_event(&f, 123, EPOLLRDHUP);
    char byte;
    CHECK(read(pair[0], &byte, 1) == 1 && byte == 'a');
    CHECK(read(pair[0], &byte, 1) == 0);
    CHECK(write(pair[0], "b", 1) == 1); /* 对端停写后，本端发送方向仍可用。 */
    CHECK(read(pair[1], &byte, 1) == 1 && byte == 'b');
    CHECK(vireo_epoll_del(f.owner, pair[0], NULL) == VIREO_OK);
    pair_close(pair);
    finish(&f);
}

static void capacity_and_independent_streams(void)
{
    fixture_t f;
    REQUIRE(start(&f, 1));
    int pairs[3][2];
    for (size_t i = 0; i < 3; ++i) {
        REQUIRE(pair_open(pairs[i]));
        vireo_epoll_registration_t reg = {VIREO_EPOLL_INTEREST_READ, UINT64_C(1000) + i};
        REQUIRE(vireo_epoll_add(f.owner, pairs[i][0], &reg, NULL) == VIREO_OK);
        char byte = (char)('a' + (int)i);
        REQUIRE(write(pairs[i][1], &byte, 1) == 1);
    }
    unsigned seen = 0;
    for (size_t round = 0; round < 3; ++round) {
        struct epoll_event event;
        REQUIRE(observe(&f, &event, 1) == 1);
        REQUIRE(event.data.u64 >= 1000 && event.data.u64 < 1003);
        size_t i = (size_t)(event.data.u64 - 1000);
        CHECK((seen & (1U << i)) == 0);
        seen |= 1U << i;
        char buffer;
        CHECK(read(pairs[i][0], &buffer, 1) == 1);
        CHECK(buffer == (char)('a' + (int)i));
    }
    CHECK(seen == 7U && f.allocations == 2 && f.releases == 0);
    vireo_epoll_info_t info;
    CHECK(vireo_epoll_inspect(f.owner, &info) == VIREO_OK && info.event_capacity == 1);
    for (size_t i = 0; i < 3; ++i) {
        CHECK(vireo_epoll_del(f.owner, pairs[i][0], NULL) == VIREO_OK);
        pair_close(pairs[i]);
    }
    finish(&f);
    puts("epoll registration: capacity 1, three watches, all tokens and stream bytes independently matched");
}

static void borrowed_fd_properties(void)
{
    fixture_t f;
    REQUIRE(start(&f, 1));
    int pair[2];
    REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0); /* 明确保持阻塞且非 CLOEXEC。 */
    int before_fd = fcntl(pair[0], F_GETFD);
    int before_status = fcntl(pair[0], F_GETFL);
    REQUIRE(before_fd >= 0 && before_status >= 0);
    vireo_epoll_registration_t reg = {VIREO_EPOLL_INTEREST_WRITE, 1};
    REQUIRE(vireo_epoll_add(f.owner, pair[0], &reg, NULL) == VIREO_OK);
    CHECK(fcntl(pair[0], F_GETFD) == before_fd && fcntl(pair[0], F_GETFL) == before_status);
    reg.interests = 0;
    CHECK(vireo_epoll_mod(f.owner, pair[0], &reg, NULL) == VIREO_OK);
    CHECK(vireo_epoll_del(f.owner, pair[0], NULL) == VIREO_OK);
    CHECK(fcntl(pair[0], F_GETFD) == before_fd && fcntl(pair[0], F_GETFL) == before_status);
    REQUIRE(vireo_epoll_add(f.owner, pair[0], &reg, NULL) == VIREO_OK);
    finish(&f); /* 仍注册时销毁实例，不关闭/改变客户端 fd。 */
    CHECK(fcntl(pair[0], F_GETFD) == before_fd && fcntl(pair[0], F_GETFL) == before_status);
    CHECK(write(pair[0], "k", 1) == 1);
    char byte;
    CHECK(read(pair[1], &byte, 1) == 1 && byte == 'k');
    pair_close(pair);
}

static void fd_reuse(void)
{
    fixture_t f;
    REQUIRE(start(&f, 1));
    int old[2];
    REQUIRE(pair_open(old));
    int number = old[0];
    vireo_epoll_registration_t reg = {VIREO_EPOLL_INTEREST_READ, 111};
    REQUIRE(vireo_epoll_add(f.owner, number, &reg, NULL) == VIREO_OK);
    REQUIRE(write(old[1], "o", 1) == 1);
    struct epoll_event cached;
    REQUIRE(observe(&f, &cached, 1) == 1);
    CHECK(cached.data.u64 == 111);
    REQUIRE(vireo_epoll_del(f.owner, number, NULL) == VIREO_OK);
    pair_close(old);
    int fresh[2];
    REQUIRE(pair_open(fresh));
    if (fresh[0] != number) {
        /* 若另一端先取得旧数值，先搬走它，再安全 dup2 新监视端。 */
        if (fresh[1] == number) {
            int moved = fcntl(fresh[1], F_DUPFD_CLOEXEC, number + 1);
            REQUIRE(moved >= 0);
            CHECK(close(fresh[1]) == 0);
            fresh[1] = moved;
        }
        REQUIRE(dup2(fresh[0], number) == number);
        CHECK(close(fresh[0]) == 0);
        fresh[0] = number;
    }
    vireo_epoll_error_t error;
    errno = EACCES;
    CHECK(vireo_epoll_del(f.owner, number, &error) == VIREO_RESULT_IO);
    CHECK(error.stage == VIREO_EPOLL_STAGE_DEL && error.system_errno == ENOENT && errno == EACCES);
    reg.token = 222;
    REQUIRE(vireo_epoll_add(f.owner, number, &reg, NULL) == VIREO_OK);
    REQUIRE(write(fresh[1], "n", 1) == 1);
    expect_event(&f, 222, EPOLLIN);
    CHECK(cached.data.u64 == 111); /* 旧批次副本不会自动变成新身份，上层必须辨别。 */
    char byte;
    CHECK(read(number, &byte, 1) == 1 && byte == 'n');
    CHECK(vireo_epoll_del(f.owner, number, NULL) == VIREO_OK);
    pair_close(fresh);
    finish(&f);
}

static void zero_fd_and_production(void)
{
    pid_t child = fork();
    REQUIRE(child >= 0);
    if (child == 0) {
        unsigned before = failures;
        (void)close(STDIN_FILENO);
        int pair[2];
        CHECK(pair_open(pair));
        CHECK(pair[0] == 0);
        vireo_epoll_t *owner = NULL;
        vireo_epoll_options_t options = {1, VIREO_EPOLL_MAX_MEMORY};
        CHECK(vireo_epoll_create(&options, &owner, NULL) == VIREO_OK);
        vireo_epoll_registration_t const reg = {0, UINT64_MAX};
        errno = EACCES;
        CHECK(vireo_epoll_add(owner, pair[0], &reg, NULL) == VIREO_OK);
        CHECK(vireo_epoll_mod(owner, pair[0], &reg, NULL) == VIREO_OK);
        CHECK(vireo_epoll_del(owner, pair[0], NULL) == VIREO_OK);
        CHECK(errno == EACCES);
        CHECK(vireo_epoll_destroy(&owner, NULL) == VIREO_OK);
        CHECK(fcntl(pair[0], F_GETFD) >= 0);
        pair_close(pair);
        _exit(failures == before ? 0 : 1);
    }
    int status = 0;
    CHECK(waitpid(child, &status, 0) == child);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

int main(void)
{
    size_t baseline = fd_count();
    void (*const groups[])(void) = {
        arguments, interest_mapping, unknown_interests, lt_and_tokens,
        mod_replaces_and_del, strict_errors, real_system_errors, injected_errors,
        zero_interest_hup, zero_interest_err, peer_half_close,
        capacity_and_independent_streams, borrowed_fd_properties, fd_reuse,
        zero_fd_and_production
    };
    for (size_t i = 0; i < sizeof(groups) / sizeof(groups[0]); ++i) groups[i]();
    CHECK(fd_count() == baseline);
    if (failures != 0) {
        fprintf(stderr, "test_epoll_registration: %u failures\n", failures);
        return EXIT_FAILURE;
    }
    puts("test_epoll_registration: all 15 test groups passed, fd baseline restored");
    return EXIT_SUCCESS;
}
