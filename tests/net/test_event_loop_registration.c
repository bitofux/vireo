/*
- PROJECT : VIREO
- FILE    : test_event_loop_registration.c
- AUTHOR  : bitofux
- DATE    : 2026-10-03
- BRIEF   : 此模块负责：
- -- 验证固定注册绑定、严格失败事务及旧身份拒绝
- -- 用真实公共 epoll、独立活动集合及并发创建观察资源和身份
 */
#define _GNU_SOURCE
#include <vireo/net/event_loop.h>
#include "net/event_loop_internal.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

static unsigned failures;
static unsigned callbacks;
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #c); \
    ++failures; } } while (0)
#define REQUIRE(c) do { if (!(c)) { CHECK(c); return; } } while (0)

typedef struct fixture {
    vireo_epoll_t *observed; /* 仅本测试借用真实公共对象，不包含旧模块 private 头。 */
    unsigned allocations;
    unsigned releases;
    unsigned calls[3];
    unsigned reject; /* 1 ADD / 2 MOD / 3 DEL，失败不先执行内核操作。 */
    int cause;
    int close_error;
    unsigned fail_allocation;
    bool reuse_control;
    void *control;
    uint64_t last_token;
} fixture_t;

static vireo_event_loop_options_t options(size_t events, size_t registrations)
{
    return (vireo_event_loop_options_t){events, VIREO_EVENT_LOOP_MAX_MEMORY, registrations};
}

static void callback_a(vireo_event_loop_t *loop, vireo_event_loop_handle_t handle, int fd,
                       uint32_t events, void *context)
{
    (void)loop; (void)handle; (void)fd; (void)events; (void)context;
    ++callbacks;
}

static void callback_b(vireo_event_loop_t *loop, vireo_event_loop_handle_t handle, int fd,
                       uint32_t events, void *context)
{
    callback_a(loop, handle, fd, events, context);
}

/* 普通路径物理配对 malloc/free；地址复用场景只保留控制块供下一次独占借出。 */
static void *allocate(void *context, size_t size)
{
    fixture_t *f = context;
    ++f->allocations;
    errno = ENOMEM;
    if (f->allocations == f->fail_allocation) {
        return NULL;
    }
    if (f->reuse_control && f->allocations % 3 == 1) {
        if (f->control == NULL) {
            f->control = malloc(size);
        }
        return f->control;
    }
    return malloc(size);
}

static void deallocate(void *context, void *memory)
{
    fixture_t *f = context;
    ++f->releases;
    if (!f->reuse_control || memory != f->control) {
        free(memory);
    }
    errno = ERANGE;
}

static vireo_result_t create_epoll(void *context, vireo_epoll_options_t const *input,
                                  vireo_epoll_t **owner, vireo_epoll_error_t *error)
{
    fixture_t *f = context;
    vireo_result_t result = vireo_epoll_create(input, owner, error);
    if (result == VIREO_OK) {
        f->observed = *owner;
    }
    return result;
}

static vireo_result_t inspect_epoll(void *context, vireo_epoll_t const *epoll,
                                   vireo_epoll_info_t *info)
{
    (void)context;
    return vireo_epoll_inspect(epoll, info);
}

/* 真实释放 epoll 后才模拟消费式 IO，不把注入当实际 close 系统失败。 */
static vireo_result_t destroy_epoll(void *context, vireo_epoll_t **owner,
                                   vireo_epoll_error_t *error)
{
    fixture_t *f = context;
    vireo_result_t result = vireo_epoll_destroy(owner, error);
    f->observed = NULL;
    if (f->close_error != 0) {
        *error = (vireo_epoll_error_t){VIREO_EPOLL_STAGE_CLOSE, f->close_error};
        errno = EDOM;
        return VIREO_RESULT_IO;
    }
    return result;
}

static vireo_result_t add_epoll(void *context, vireo_epoll_t *epoll, int fd,
                               vireo_epoll_registration_t const *input, vireo_epoll_error_t *error)
{
    fixture_t *f = context;
    /* 内部唤醒 watch 不属于客户登记 oracle，创建失败由新测试验证。 */
    if (input->token == 0) return vireo_epoll_add(epoll, fd, input, error);
    ++f->calls[0]; f->last_token = input->token;
    if (f->reject == 1) {
        *error = (vireo_epoll_error_t){VIREO_EPOLL_STAGE_ADD, f->cause};
        errno = EDOM;
        return VIREO_RESULT_IO;
    }
    return vireo_epoll_add(epoll, fd, input, error);
}

static vireo_result_t mod_epoll(void *context, vireo_epoll_t *epoll, int fd,
                               vireo_epoll_registration_t const *input, vireo_epoll_error_t *error)
{
    fixture_t *f = context;
    ++f->calls[1];
    if (f->reject == 2) {
        *error = (vireo_epoll_error_t){VIREO_EPOLL_STAGE_MOD, f->cause};
        errno = EDOM;
        return VIREO_RESULT_IO;
    }
    return vireo_epoll_mod(epoll, fd, input, error);
}

static vireo_result_t del_epoll(void *context, vireo_epoll_t *epoll, int fd,
                               vireo_epoll_error_t *error)
{
    fixture_t *f = context;
    ++f->calls[2];
    if (f->reject == 3) {
        *error = (vireo_epoll_error_t){VIREO_EPOLL_STAGE_DEL, f->cause};
        errno = EDOM;
        return VIREO_RESULT_IO;
    }
    return vireo_epoll_del(epoll, fd, error);
}

/* 生命周期/登记回归仍只通过已封板公共 wait，当前测试不实际分发。 */
static vireo_result_t wait_epoll(void *context, vireo_epoll_t *epoll,
                                vireo_epoll_event_t *events, size_t capacity, int timeout_ms,
                                size_t *count, vireo_epoll_error_t *error)
{
    (void)context;
    return vireo_epoll_wait(epoll, timeout_ms, events, capacity, count, error);
}

static vireo_event_loop_ops_t ops(fixture_t *f)
{
    vireo_event_loop_ops_t resources = vireo_event_loop_default_ops();
    resources.context = f;
    resources.allocate = allocate;
    resources.deallocate = deallocate;
    resources.create_epoll = create_epoll;
    resources.inspect_epoll = inspect_epoll;
    resources.destroy_epoll = destroy_epoll;
    resources.add_epoll = add_epoll;
    resources.mod_epoll = mod_epoll;
    resources.del_epoll = del_epoll;
    resources.wait_epoll = wait_epoll;
    return resources;
}

static vireo_event_loop_registration_t registration(int fd, uint32_t interests, void *context)
{
    return (vireo_event_loop_registration_t){fd, interests, callback_a, context};
}

static bool same_binding(vireo_event_loop_registration_t a, vireo_event_loop_registration_t b)
{
    return a.fd == b.fd && a.interests == b.interests && a.callback == b.callback &&
           a.context == b.context;
}

static void clear_error(vireo_event_loop_error_t error)
{
    CHECK(error.stage == VIREO_EVENT_LOOP_STAGE_NONE && error.system_errno == 0);
    CHECK(error.epoll_error.stage == VIREO_EPOLL_STAGE_NONE && error.epoll_error.system_errno == 0);
}

static void counts(vireo_event_loop_t *loop, size_t capacity, size_t active)
{
    vireo_event_loop_info_t info;
    CHECK(vireo_event_loop_inspect(loop, &info) == VIREO_OK);
    CHECK(info.registration_capacity == capacity && info.registered_count == active);
    CHECK(info.available_count == capacity - active);
}

/* 排除 /proc 目录流自身，逐场景核对真实 fd 基线而非依赖 LSan 检测描述符。 */
static size_t fd_count(void)
{
    DIR *directory = opendir("/proc/self/fd");
    CHECK(directory != NULL);
    if (directory == NULL) return SIZE_MAX;
    int own = dirfd(directory); size_t count = 0; struct dirent *entry;
    errno = 0;
    while ((entry = readdir(directory)) != NULL) {
        char *end; long number = strtol(entry->d_name, &end, 10);
        if (*entry->d_name != '\0' && *end == '\0' && number >= 0 && number != own) ++count;
    }
    CHECK(errno == 0); CHECK(closedir(directory) == 0);
    return count;
}

static void arguments(void)
{
    fixture_t f = {0}; vireo_event_loop_t *loop = NULL;
    vireo_event_loop_options_t o = options(1, 2); vireo_event_loop_ops_t resources = ops(&f);
    REQUIRE(vireo_event_loop_create_with_ops(&o, &resources, &loop, NULL) == VIREO_OK);
    int pair[2]; REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    vireo_event_loop_registration_t input = registration(pair[0], 1, NULL), output;
    vireo_event_loop_handle_t h = {0}; vireo_event_loop_error_t error;
    errno = EACCES;
    CHECK(vireo_event_loop_add(NULL, &input, &h, &error) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_event_loop_add(loop, NULL, &h, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_event_loop_add(loop, &input, NULL, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    for (unsigned fault = 0; fault < 4; ++fault) {
        vireo_event_loop_registration_t bad = input;
        if (fault == 0) bad.fd = -1;
        if (fault == 1) bad.interests = UINT32_MAX;
        if (fault == 2) bad.callback = NULL;
        if (fault == 3) h.token = 1;
        CHECK(vireo_event_loop_add(loop, &bad, &h, &error) == VIREO_RESULT_INVALID_ARGUMENT);
        CHECK(h.loop_id == 0 && h.token == (fault == 3 ? 1U : 0U));
        clear_error(error);
    }
    h = (vireo_event_loop_handle_t){0};
    CHECK(vireo_event_loop_del(loop, NULL, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_event_loop_del(loop, &h, &error) == VIREO_RESULT_NOT_FOUND);
    CHECK(vireo_event_loop_mod(NULL, h, 0, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_event_loop_mod(loop, h, UINT32_MAX, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    memset(&output, 0xA5, sizeof(output)); unsigned char saved[sizeof(output)];
    memcpy(saved, &output, sizeof(output));
    CHECK(vireo_event_loop_registration_inspect(loop, h, &output) == VIREO_RESULT_NOT_FOUND);
    CHECK(memcmp(saved, &output, sizeof(output)) == 0);
    CHECK(vireo_event_loop_registration_inspect(loop, h, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(f.calls[0] == 0 && f.calls[1] == 0 && f.calls[2] == 0 && errno == EACCES);
    counts(loop, 2, 0);
    CHECK(vireo_event_loop_destroy(&loop, NULL) == VIREO_OK);
    CHECK(close(pair[0]) == 0 && close(pair[1]) == 0);
}

static void capacity_and_arithmetic(void)
{
    size_t values[] = {0, 1, VIREO_EVENT_LOOP_MAX_REGISTRATIONS,
                       VIREO_EVENT_LOOP_MAX_REGISTRATIONS + 1, SIZE_MAX};
    vireo_result_t expected[] = {VIREO_RESULT_INVALID_ARGUMENT, VIREO_OK, VIREO_OK,
                                 VIREO_RESULT_RANGE, VIREO_RESULT_OVERFLOW};
    for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); ++i) {
        fixture_t f = {0}; vireo_event_loop_t *loop = NULL; vireo_event_loop_ops_t resources = ops(&f);
        vireo_event_loop_options_t o = options(1, values[i]);
        if (values[i] == SIZE_MAX) o.max_memory_bytes = 1;
        errno = EACCES;
        CHECK(vireo_event_loop_create_with_ops(&o, &resources, &loop, NULL) == expected[i]);
        CHECK(errno == EACCES);
        if (expected[i] == VIREO_OK) {
            counts(loop, values[i], 0);
            CHECK(vireo_event_loop_destroy(&loop, NULL) == VIREO_OK);
            CHECK(f.allocations == 3 && f.releases == 3);
        } else CHECK(loop == NULL && f.allocations == 0);
    }
    fixture_t f = {0}; vireo_event_loop_t *loop = NULL;
    vireo_event_loop_ops_t resources = ops(&f); vireo_event_loop_options_t o = options(1, 1);
    REQUIRE(vireo_event_loop_create_with_ops(&o, &resources, &loop, NULL) == VIREO_OK);
    vireo_event_loop_info_t info; CHECK(vireo_event_loop_inspect(loop, &info) == VIREO_OK);
    size_t unit = info.registrations_bytes;
    CHECK(vireo_event_loop_destroy(&loop, NULL) == VIREO_OK);
    REQUIRE(unit > 0); o.registration_capacity = SIZE_MAX / unit; o.max_memory_bytes = 1;
    unsigned allocations = f.allocations;
    CHECK(vireo_event_loop_create_with_ops(&o, &resources, &loop, NULL) == VIREO_RESULT_OVERFLOW);
    CHECK(loop == NULL && f.allocations == allocations);
}

/* 输入值复制和零关注均真实登记；随后只改关注，代码/context/token 不变。 */
static void fixed_binding_and_interests(void)
{
    fixture_t f = {0}; vireo_event_loop_t *loop = NULL; vireo_event_loop_ops_t resources = ops(&f);
    vireo_event_loop_options_t o = options(1, 1);
    REQUIRE(vireo_event_loop_create_with_ops(&o, &resources, &loop, NULL) == VIREO_OK);
    int pair[2]; REQUIRE(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, pair) == 0);
    int context = 42;
    for (uint32_t interest = 0; interest < 8; ++interest) {
        vireo_event_loop_registration_t input = registration(pair[0], interest, &context);
        vireo_event_loop_registration_t original = input, observed;
        vireo_event_loop_handle_t h = {0}; vireo_event_loop_error_t error;
        errno = EACCES;
        REQUIRE(vireo_event_loop_add(loop, &input, &h, &error) == VIREO_OK);
        clear_error(error); uint64_t token = h.token;
        input = registration(-1, UINT32_MAX, NULL); input.callback = callback_b;
        CHECK(vireo_event_loop_registration_inspect(loop, h, &observed) == VIREO_OK);
        CHECK(same_binding(original, observed));
        CHECK(vireo_event_loop_mod(loop, h, 7 - interest, &error) == VIREO_OK);
        clear_error(error);
        CHECK(vireo_event_loop_registration_inspect(loop, h, &observed) == VIREO_OK);
        original.interests = 7 - interest;
        CHECK(same_binding(original, observed) && h.token == token);
        CHECK(vireo_event_loop_del(loop, &h, &error) == VIREO_OK);
        clear_error(error); CHECK(h.loop_id == 0 && h.token == 0 && errno == EACCES);
    }
    CHECK(f.allocations == 3 && f.releases == 0 && callbacks == 0);
    CHECK(vireo_event_loop_destroy(&loop, NULL) == VIREO_OK);
    CHECK(close(pair[0]) == 0 && close(pair[1]) == 0);
}

/* 批次容量 1 不限制三个 watch；WRITE 开关通过真实公开 wait 观察，不执行回调。 */
static void kernel_readiness_and_counts(void)
{
    fixture_t f = {0}; vireo_event_loop_t *loop = NULL; vireo_event_loop_ops_t resources = ops(&f);
    vireo_event_loop_options_t o = options(1, 3);
    REQUIRE(vireo_event_loop_create_with_ops(&o, &resources, &loop, NULL) == VIREO_OK);
    int pairs[3][2]; vireo_event_loop_handle_t h[3] = {{0}};
    for (size_t i = 0; i < 3; ++i) {
        REQUIRE(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, pairs[i]) == 0);
        vireo_event_loop_registration_t input = registration(pairs[i][0], 1, NULL);
        REQUIRE(vireo_event_loop_add(loop, &input, &h[i], NULL) == VIREO_OK);
    }
    counts(loop, 3, 3);
    vireo_event_loop_handle_t duplicate = {0};
    vireo_event_loop_registration_t input = registration(pairs[0][0], 0, NULL);
    unsigned adds = f.calls[0];
    CHECK(vireo_event_loop_add(loop, &input, &duplicate, NULL) == VIREO_RESULT_BUSY);
    int extra[2]; REQUIRE(pipe(extra) == 0); input.fd = extra[0];
    CHECK(vireo_event_loop_add(loop, &input, &duplicate, NULL) == VIREO_RESULT_BUSY);
    CHECK(f.calls[0] == adds && duplicate.token == 0);
    for (size_t i = 0; i < 3; ++i) CHECK(write(pairs[i][1], "x", 1) == 1);
    bool seen[3] = {false};
    for (size_t round = 0; round < 9; ++round) {
        vireo_epoll_event_t event; size_t count = 0;
        REQUIRE(vireo_epoll_wait(f.observed, 0, &event, 1, &count, NULL) == VIREO_OK);
        if (count == 1) for (size_t i = 0; i < 3; ++i) {
            if (event.token == h[i].token) {
                seen[i] = true; CHECK((event.events & VIREO_EPOLL_EVENT_READ) != 0);
                char byte; CHECK(read(pairs[i][0], &byte, 1) == 1 && byte == 'x');
            }
        }
    }
    CHECK(seen[0] && seen[1] && seen[2]);
    CHECK(vireo_event_loop_mod(loop, h[0], VIREO_EPOLL_INTEREST_WRITE, NULL) == VIREO_OK);
    vireo_epoll_event_t event; size_t count;
    REQUIRE(vireo_epoll_wait(f.observed, 0, &event, 1, &count, NULL) == VIREO_OK);
    CHECK(count == 1 && event.token == h[0].token && (event.events & VIREO_EPOLL_EVENT_WRITE) != 0);
    CHECK(vireo_event_loop_mod(loop, h[0], 0, NULL) == VIREO_OK);
    CHECK(vireo_epoll_wait(f.observed, 0, &event, 1, &count, NULL) == VIREO_OK && count == 0);
    /* 零关注仍保留 watch，关闭对端后真实 HANGUP 能返还当前 token。 */
    CHECK(close(pairs[0][1]) == 0); pairs[0][1] = -1;
    CHECK(vireo_epoll_wait(f.observed, 0, &event, 1, &count, NULL) == VIREO_OK);
    CHECK(count == 1 && event.token == h[0].token && (event.events & VIREO_EPOLL_EVENT_HANGUP) != 0);
    CHECK(f.allocations == 3 && f.releases == 0);
    CHECK(vireo_event_loop_destroy(&loop, NULL) == VIREO_OK);
    for (size_t i = 0; i < 3; ++i) {
        CHECK(close(pairs[i][0]) == 0);
        if (pairs[i][1] >= 0) CHECK(close(pairs[i][1]) == 0);
    }
    CHECK(close(extra[0]) == 0 && close(extra[1]) == 0);
}

static void rejected_handles(void)
{
    fixture_t f = {0}; vireo_event_loop_t *loop = NULL, *other = NULL;
    vireo_event_loop_ops_t resources = ops(&f); vireo_event_loop_options_t o = options(1, 2);
    REQUIRE(vireo_event_loop_create_with_ops(&o, &resources, &loop, NULL) == VIREO_OK);
    REQUIRE(vireo_event_loop_create(&o, &other, NULL) == VIREO_OK);
    int pair[2]; REQUIRE(pipe(pair) == 0);
    vireo_event_loop_registration_t input = registration(pair[0], 1, NULL), output;
    vireo_event_loop_handle_t h = {0}; REQUIRE(vireo_event_loop_add(loop, &input, &h, NULL) == VIREO_OK);
    vireo_event_loop_info_t other_info; CHECK(vireo_event_loop_inspect(other, &other_info) == VIREO_OK);
    vireo_event_loop_handle_t bad[] = {{0}, {0, h.token}, {h.loop_id, 0}, {h.loop_id, 1},
        {other_info.loop_id, h.token}, {h.loop_id, (h.token & ~UINT64_C(65535)) | 2},
        {h.loop_id, h.token + UINT64_C(65536)}};
    vireo_result_t expected[] = {VIREO_RESULT_NOT_FOUND, VIREO_RESULT_INVALID_ARGUMENT,
        VIREO_RESULT_INVALID_ARGUMENT, VIREO_RESULT_INVALID_ARGUMENT, VIREO_RESULT_INVALID_ARGUMENT,
        VIREO_RESULT_RANGE, VIREO_RESULT_NOT_FOUND};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        memset(&output, 0xA5, sizeof(output)); unsigned char saved[sizeof(output)];
        memcpy(saved, &output, sizeof(output)); vireo_event_loop_handle_t copy = bad[i];
        vireo_event_loop_error_t error; errno = EACCES;
        CHECK(vireo_event_loop_registration_inspect(loop, bad[i], &output) == expected[i]);
        CHECK(memcmp(saved, &output, sizeof(output)) == 0);
        CHECK(vireo_event_loop_mod(loop, bad[i], 0, &error) == expected[i]); clear_error(error);
        CHECK(vireo_event_loop_del(loop, &copy, &error) == expected[i]); clear_error(error);
        CHECK(copy.loop_id == bad[i].loop_id && copy.token == bad[i].token && errno == EACCES);
    }
    CHECK(f.calls[1] == 0 && f.calls[2] == 0);
    CHECK(vireo_event_loop_registration_inspect(other, h, &output) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_event_loop_destroy(&loop, NULL) == VIREO_OK);
    CHECK(vireo_event_loop_destroy(&other, NULL) == VIREO_OK);
    CHECK(close(pair[0]) == 0 && close(pair[1]) == 0);
}

/* 先 DEL 再 close，强制复用同一槽和 fd 数值；旧按值批次仍含旧 token。 */
static void stale_batch_and_fd_reuse(void)
{
    fixture_t f = {0}; vireo_event_loop_t *loop = NULL; vireo_event_loop_ops_t resources = ops(&f);
    vireo_event_loop_options_t o = options(1, 1);
    REQUIRE(vireo_event_loop_create_with_ops(&o, &resources, &loop, NULL) == VIREO_OK);
    int old[2]; REQUIRE(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, old) == 0);
    int first_context = 1, second_context = 2;
    vireo_event_loop_registration_t input = registration(old[0], 1, &first_context);
    vireo_event_loop_handle_t h = {0}; REQUIRE(vireo_event_loop_add(loop, &input, &h, NULL) == VIREO_OK);
    vireo_event_loop_handle_t saved_handle = h;
    CHECK(write(old[1], "a", 1) == 1);
    vireo_epoll_event_t saved_event; size_t count;
    REQUIRE(vireo_epoll_wait(f.observed, 0, &saved_event, 1, &count, NULL) == VIREO_OK && count == 1);
    CHECK(vireo_event_loop_del(loop, &h, NULL) == VIREO_OK);
    CHECK(close(old[0]) == 0 && close(old[1]) == 0);
    int fresh[2]; REQUIRE(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, fresh) == 0);
    CHECK(fresh[0] == old[0]); input = registration(fresh[0], 1, &second_context);
    input.callback = callback_b;
    REQUIRE(vireo_event_loop_add(loop, &input, &h, NULL) == VIREO_OK);
    CHECK(h.token != saved_handle.token);
    vireo_event_loop_registration_t output;
    CHECK(vireo_event_loop_registration_inspect(loop, saved_handle, &output) == VIREO_RESULT_NOT_FOUND);
    vireo_event_loop_handle_t resolved = {77, 99}; unsigned char saved[sizeof(output)];
    memset(&output, 0xA5, sizeof(output)); memcpy(saved, &output, sizeof(output));
    CHECK(vireo_event_loop_resolve_token(loop, saved_event.token, &resolved, &output) ==
          VIREO_RESULT_NOT_FOUND);
    CHECK(resolved.loop_id == 77 && resolved.token == 99 && memcmp(saved, &output, sizeof(output)) == 0);
    CHECK(write(fresh[1], "b", 1) == 1);
    vireo_epoll_event_t event;
    REQUIRE(vireo_epoll_wait(f.observed, 0, &event, 1, &count, NULL) == VIREO_OK && count == 1);
    CHECK(vireo_event_loop_resolve_token(loop, event.token, &resolved, &output) == VIREO_OK);
    CHECK(resolved.token == h.token && same_binding(input, output));
    char byte; CHECK(read(output.fd, &byte, 1) == 1 && byte == 'b');
    CHECK(saved_event.token == saved_handle.token && callbacks == 0);
    CHECK(vireo_event_loop_destroy(&loop, NULL) == VIREO_OK);
    CHECK(close(fresh[0]) == 0 && close(fresh[1]) == 0);
}

/* 不访问已释放对象指针；复用 allocator 控制块时，用旧数值 handle 验证身份域。 */
static void same_address_new_identity(void)
{
    fixture_t f = {.reuse_control = true}; vireo_event_loop_t *loop = NULL;
    vireo_event_loop_ops_t resources = ops(&f); vireo_event_loop_options_t o = options(1, 1);
    REQUIRE(vireo_event_loop_create_with_ops(&o, &resources, &loop, NULL) == VIREO_OK);
    uintptr_t address = (uintptr_t)loop;
    int pair[2]; REQUIRE(pipe(pair) == 0);
    vireo_event_loop_registration_t input = registration(pair[0], 1, NULL), output;
    vireo_event_loop_handle_t old = {0}, fresh = {0};
    REQUIRE(vireo_event_loop_add(loop, &input, &old, NULL) == VIREO_OK);
    CHECK(vireo_event_loop_destroy(&loop, NULL) == VIREO_OK);
    REQUIRE(vireo_event_loop_create_with_ops(&o, &resources, &loop, NULL) == VIREO_OK);
    CHECK((uintptr_t)loop == address);
    REQUIRE(vireo_event_loop_add(loop, &input, &fresh, NULL) == VIREO_OK);
    CHECK(old.loop_id != fresh.loop_id && old.token == fresh.token);
    CHECK(vireo_event_loop_registration_inspect(loop, old, &output) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_event_loop_destroy(&loop, NULL) == VIREO_OK);
    CHECK(f.allocations == 6 && f.releases == 6); free(f.control);
    CHECK(close(pair[0]) == 0 && close(pair[1]) == 0);
}

/* 7 个原因 × 3 控制入口 × 有/无诊断，旧记录/输出必须保持；解除故障后成功。 */
static void control_failures(void)
{
    int causes[] = {EINTR, EBADF, ENOENT, EEXIST, EPERM, ENOMEM, ENOSPC};
    for (unsigned operation = 1; operation <= 3; ++operation) {
        for (size_t cause = 0; cause < sizeof(causes) / sizeof(causes[0]); ++cause) {
            for (unsigned diagnostic = 0; diagnostic < 2; ++diagnostic) {
                fixture_t f = {0}; vireo_event_loop_t *loop = NULL;
                vireo_event_loop_ops_t resources = ops(&f); vireo_event_loop_options_t o = options(1, 2);
                REQUIRE(vireo_event_loop_create_with_ops(&o, &resources, &loop, NULL) == VIREO_OK);
                int pair[2]; REQUIRE(pipe(pair) == 0); int context = 17;
                vireo_event_loop_registration_t input = registration(pair[0], 1, &context), observed;
                vireo_event_loop_handle_t h = {0};
                if (operation != 1) REQUIRE(vireo_event_loop_add(loop, &input, &h, NULL) == VIREO_OK);
                vireo_event_loop_handle_t saved = h;
                f.reject = operation; f.cause = causes[cause]; vireo_event_loop_error_t error;
                unsigned before = f.calls[operation - 1]; errno = EACCES;
                vireo_result_t result = operation == 1 ?
                    vireo_event_loop_add(loop, &input, &h, diagnostic != 0 ? &error : NULL) :
                    operation == 2 ? vireo_event_loop_mod(loop, h, 2, diagnostic != 0 ? &error : NULL) :
                    vireo_event_loop_del(loop, &h, diagnostic != 0 ? &error : NULL);
                CHECK(result == VIREO_RESULT_IO && errno == EACCES);
                CHECK(h.loop_id == saved.loop_id && h.token == saved.token);
                CHECK(f.calls[operation - 1] == before + 1 && f.allocations == 3 && f.releases == 0);
                if (diagnostic != 0) {
                    CHECK(error.stage == (operation == 1 ? VIREO_EVENT_LOOP_STAGE_ADD :
                          operation == 2 ? VIREO_EVENT_LOOP_STAGE_MOD : VIREO_EVENT_LOOP_STAGE_DEL));
                    CHECK(error.epoll_error.stage == (operation == 1 ? VIREO_EPOLL_STAGE_ADD :
                          operation == 2 ? VIREO_EPOLL_STAGE_MOD : VIREO_EPOLL_STAGE_DEL));
                    CHECK(error.epoll_error.system_errno == causes[cause]);
                }
                counts(loop, 2, operation == 1 ? 0U : 1U);
                if (operation != 1) {
                    CHECK(vireo_event_loop_registration_inspect(loop, h, &observed) == VIREO_OK);
                    CHECK(same_binding(input, observed));
                }
                uint64_t failed_token = f.last_token; f.reject = 0;
                if (operation == 1) {
                    CHECK(vireo_event_loop_add(loop, &input, &h, NULL) == VIREO_OK);
                    CHECK(h.token != failed_token);
                } else if (operation == 2) {
                    CHECK(vireo_event_loop_mod(loop, h, 2, NULL) == VIREO_OK);
                    CHECK(vireo_event_loop_registration_inspect(loop, h, &observed) == VIREO_OK);
                    input.interests = 2; CHECK(same_binding(input, observed));
                } else CHECK(vireo_event_loop_del(loop, &h, NULL) == VIREO_OK);
                CHECK(errno == EACCES);
                CHECK(vireo_event_loop_destroy(&loop, NULL) == VIREO_OK && f.releases == 3);
                CHECK(close(pair[0]) == 0 && close(pair[1]) == 0);
            }
        }
    }
}

/* 实际内核 EPERM；再由测试适配借用移除 watch，制造真实 ENOENT，表不能静默丢失。 */
static void real_kernel_errors(void)
{
    fixture_t f = {0}; vireo_event_loop_t *loop = NULL; vireo_event_loop_ops_t resources = ops(&f);
    vireo_event_loop_options_t o = options(1, 1);
    REQUIRE(vireo_event_loop_create_with_ops(&o, &resources, &loop, NULL) == VIREO_OK);
    int regular = open("/dev/null", O_RDONLY | O_CLOEXEC); REQUIRE(regular >= 0);
    vireo_event_loop_registration_t input = registration(regular, 1, NULL), output;
    vireo_event_loop_handle_t h = {0}; vireo_event_loop_error_t error;
    errno = EACCES;
    CHECK(vireo_event_loop_add(loop, &input, &h, &error) == VIREO_RESULT_IO);
    CHECK(error.epoll_error.system_errno == EPERM && h.token == 0 && errno == EACCES);
    CHECK(close(regular) == 0);
    int pair[2]; REQUIRE(pipe(pair) == 0); input.fd = pair[0];
    REQUIRE(vireo_event_loop_add(loop, &input, &h, NULL) == VIREO_OK);
    CHECK(vireo_epoll_del(f.observed, pair[0], NULL) == VIREO_OK);
    vireo_event_loop_handle_t saved = h;
    CHECK(vireo_event_loop_mod(loop, h, 0, &error) == VIREO_RESULT_IO);
    CHECK(error.epoll_error.system_errno == ENOENT);
    CHECK(vireo_event_loop_del(loop, &h, &error) == VIREO_RESULT_IO);
    CHECK(error.epoll_error.system_errno == ENOENT && h.token == saved.token);
    CHECK(vireo_event_loop_registration_inspect(loop, h, &output) == VIREO_OK);
    CHECK(same_binding(input, output)); counts(loop, 1, 1);
    CHECK(vireo_event_loop_destroy(&loop, NULL) == VIREO_OK);
    CHECK(fcntl(pair[0], F_GETFD) >= 0 && close(pair[0]) == 0 && close(pair[1]) == 0);
}

static void active_destroy_and_borrow(void)
{
    for (unsigned fail_close = 0; fail_close < 2; ++fail_close) {
        fixture_t f = {.close_error = fail_close != 0 ? EINTR : 0};
        vireo_event_loop_t *loop = NULL; vireo_event_loop_ops_t resources = ops(&f);
        vireo_event_loop_options_t o = options(1, 1);
        REQUIRE(vireo_event_loop_create_with_ops(&o, &resources, &loop, NULL) == VIREO_OK);
        int pair[2]; REQUIRE(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, pair) == 0);
        int fd_flags = fcntl(pair[0], F_GETFD), status_flags = fcntl(pair[0], F_GETFL), context = 11;
        vireo_event_loop_registration_t input = registration(pair[0], 1, &context);
        vireo_event_loop_handle_t h = {0};
        REQUIRE(vireo_event_loop_add(loop, &input, &h, NULL) == VIREO_OK);
        CHECK(vireo_event_loop_mod(loop, h, 0, NULL) == VIREO_OK);
        vireo_event_loop_error_t error; errno = EACCES;
        CHECK(vireo_event_loop_destroy(&loop, &error) == (fail_close != 0 ? VIREO_RESULT_IO : VIREO_OK));
        CHECK(loop == NULL && errno == EACCES && f.releases == 3 && f.calls[2] == 0);
        if (fail_close != 0) CHECK(error.epoll_error.system_errno == EINTR);
        CHECK(context == 11 && callbacks == 0);
        CHECK(fcntl(pair[0], F_GETFD) == fd_flags && fcntl(pair[0], F_GETFL) == status_flags);
        CHECK(write(pair[1], "x", 1) == 1); char byte; CHECK(read(pair[0], &byte, 1) == 1 && byte == 'x');
        CHECK(vireo_event_loop_destroy(&loop, NULL) == VIREO_OK && f.releases == 3);
        CHECK(close(pair[0]) == 0 && close(pair[1]) == 0);
    }
}

static void serial_exhaustion(void)
{
    fixture_t f = {0}; vireo_event_loop_t *loop = NULL; vireo_event_loop_ops_t resources = ops(&f);
    vireo_event_loop_options_t o = options(1, 2); uint64_t max = UINT64_MAX >> 16;
    REQUIRE(vireo_event_loop_create_with_ops(&o, &resources, &loop, NULL) == VIREO_OK);
    CHECK(vireo_event_loop_advance_serial_for_test(loop, max + 1) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_event_loop_advance_serial_for_test(loop, max - 1) == VIREO_OK);
    CHECK(vireo_event_loop_advance_serial_for_test(loop, 0) == VIREO_RESULT_INVALID_ARGUMENT);
    int pair[2]; REQUIRE(pipe(pair) == 0);
    vireo_event_loop_registration_t input = registration(pair[0], 1, NULL);
    vireo_event_loop_handle_t h = {0}, second = {0};
    REQUIRE(vireo_event_loop_add(loop, &input, &h, NULL) == VIREO_OK);
    CHECK((h.token >> 16) == max);
    CHECK(vireo_event_loop_advance_serial_for_test(loop, max) == VIREO_RESULT_BUSY);
    input.fd = pair[1]; errno = EACCES;
    CHECK(vireo_event_loop_add(loop, &input, &second, NULL) == VIREO_RESULT_OVERFLOW);
    CHECK(second.token == 0 && f.calls[0] == 1 && errno == EACCES);
    CHECK(vireo_event_loop_mod(loop, h, 0, NULL) == VIREO_OK);
    CHECK(vireo_event_loop_del(loop, &h, NULL) == VIREO_OK);
    CHECK(vireo_event_loop_add(loop, &input, &second, NULL) == VIREO_RESULT_OVERFLOW);
    counts(loop, 2, 0);
    CHECK(vireo_event_loop_destroy(&loop, NULL) == VIREO_OK);
    CHECK(close(pair[0]) == 0 && close(pair[1]) == 0);
}

/* 独立测试身份域，不覆盖全局生产计数；耗尽先于申请，OOM 允许消耗身份。 */
static void identity_exhaustion_and_failure(void)
{
    _Atomic uint64_t counter = UINT64_MAX - 1;
    fixture_t f = {0}; vireo_event_loop_t *loop = NULL; vireo_event_loop_ops_t resources = ops(&f);
    vireo_event_loop_options_t o = options(1, 1);
    REQUIRE(vireo_event_loop_create_with_counter(&o, &resources, &counter, &loop, NULL) == VIREO_OK);
    vireo_event_loop_info_t info; CHECK(vireo_event_loop_inspect(loop, &info) == VIREO_OK);
    CHECK(info.loop_id == UINT64_MAX && atomic_load(&counter) == UINT64_MAX);
    CHECK(vireo_event_loop_destroy(&loop, NULL) == VIREO_OK);
    unsigned allocations = f.allocations; vireo_event_loop_error_t error; errno = EACCES;
    CHECK(vireo_event_loop_create_with_counter(&o, &resources, &counter, &loop, &error) ==
          VIREO_RESULT_OVERFLOW);
    CHECK(loop == NULL && f.allocations == allocations && errno == EACCES);
    CHECK(error.stage == VIREO_EVENT_LOOP_STAGE_ISSUE_ID && error.epoll_error.system_errno == 0);
    CHECK(vireo_event_loop_create_with_counter(&o, &resources, NULL, &loop, NULL) ==
          VIREO_RESULT_INVALID_ARGUMENT);
    atomic_store(&counter, 0); f = (fixture_t){.fail_allocation = 1}; resources = ops(&f);
    CHECK(vireo_event_loop_create_with_counter(&o, &resources, &counter, &loop, NULL) ==
          VIREO_RESULT_NO_MEMORY);
    CHECK(loop == NULL && atomic_load(&counter) == 1 && f.releases == 0);
    f = (fixture_t){0}; resources = ops(&f);
    REQUIRE(vireo_event_loop_create_with_counter(&o, &resources, &counter, &loop, NULL) == VIREO_OK);
    CHECK(vireo_event_loop_inspect(loop, &info) == VIREO_OK && info.loop_id == 2);
    CHECK(vireo_event_loop_destroy(&loop, NULL) == VIREO_OK);
}

/* oracle 只保存客户端活动集合和历史 handle，不复制空闲链或 token 编码。 */
static void independent_model(void)
{
    fixture_t f = {0}; vireo_event_loop_t *loop = NULL; vireo_event_loop_ops_t resources = ops(&f);
    vireo_event_loop_options_t o = options(1, 4);
    REQUIRE(vireo_event_loop_create_with_ops(&o, &resources, &loop, NULL) == VIREO_OK);
    int pairs[8][2], contexts[8]; bool active[8] = {false};
    vireo_event_loop_handle_t handles[8] = {{0}}, stale[8] = {{0}};
    uint32_t interest[8] = {0}; size_t live = 0; unsigned rejected = 0; uint32_t state = 9817;
    for (size_t i = 0; i < 8; ++i) {
        REQUIRE(pipe(pairs[i]) == 0); contexts[i] = (int)i;
    }
    for (size_t step = 0; step < 6000; ++step) {
        state = state * UINT32_C(1664525) + UINT32_C(1013904223);
        size_t i = (size_t)((state >> 16) % 8); unsigned operation = (state >> 24) % 3;
        uint32_t bits = (state >> 8) % 8; vireo_result_t expected, actual;
        errno = EACCES;
        if (operation == 0) {
            vireo_event_loop_handle_t candidate = {0};
            vireo_event_loop_registration_t input = registration(pairs[i][0], bits, &contexts[i]);
            expected = active[i] || live == 4 ? VIREO_RESULT_BUSY : VIREO_OK;
            actual = vireo_event_loop_add(loop, &input, &candidate, NULL);
            if (expected == VIREO_OK && actual == VIREO_OK) {
                for (size_t j = 0; j < 8; ++j) if (active[j]) CHECK(candidate.token != handles[j].token);
                active[i] = true; ++live; handles[i] = candidate; interest[i] = bits;
            } else CHECK(candidate.loop_id == 0 && candidate.token == 0);
        } else if (operation == 1) {
            expected = active[i] ? VIREO_OK : VIREO_RESULT_NOT_FOUND;
            actual = vireo_event_loop_mod(loop, handles[i], bits, NULL);
            if (expected == VIREO_OK && actual == VIREO_OK) interest[i] = bits;
        } else {
            expected = active[i] ? VIREO_OK : VIREO_RESULT_NOT_FOUND;
            vireo_event_loop_handle_t before = handles[i], copy = before;
            actual = vireo_event_loop_del(loop, &copy, NULL);
            if (expected == VIREO_OK && actual == VIREO_OK) {
                active[i] = false; --live; stale[i] = before;
                CHECK(copy.loop_id == 0 && copy.token == 0);
            } else CHECK(copy.loop_id == before.loop_id && copy.token == before.token);
        }
        CHECK(actual == expected && errno == EACCES);
        if (expected != VIREO_OK) ++rejected;
        counts(loop, 4, live);
        for (size_t j = 0; j < 8; ++j) {
            vireo_event_loop_registration_t output;
            CHECK(vireo_event_loop_registration_inspect(loop, handles[j], &output) ==
                  (active[j] ? VIREO_OK : VIREO_RESULT_NOT_FOUND));
            if (active[j]) {
                CHECK(output.fd == pairs[j][0] && output.interests == interest[j]);
                CHECK(output.context == &contexts[j] && output.callback == callback_a);
            }
            if (stale[j].token != 0) CHECK(vireo_event_loop_registration_inspect(loop, stale[j], &output) ==
                                         VIREO_RESULT_NOT_FOUND);
        }
        CHECK(f.allocations == 3 && f.releases == 0);
    }
    printf("event_loop registration model: 6000 steps, %u expected rejections\n", rejected);
    CHECK(vireo_event_loop_destroy(&loop, NULL) == VIREO_OK);
    for (size_t i = 0; i < 8; ++i) CHECK(close(pairs[i][0]) == 0 && close(pairs[i][1]) == 0);
}

static void client_fd_zero(void)
{
    pid_t child = fork(); REQUIRE(child >= 0);
    if (child == 0) {
        failures = 0; vireo_event_loop_t *loop = NULL; vireo_event_loop_options_t o = options(1, 1);
        /* 先确保 0 已占用，避免随后 dup2 意外替换自有 epoll fd。 */
        if (fcntl(0, F_GETFD) == -1 && open("/dev/null", O_RDONLY) != 0) _exit(1);
        if (vireo_event_loop_create(&o, &loop, NULL) != VIREO_OK) _exit(1);
        int pair[2]; if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0) _exit(1);
        CHECK(dup2(pair[0], 0) == 0); if (pair[0] != 0) CHECK(close(pair[0]) == 0);
        vireo_event_loop_registration_t input = registration(0, 1, NULL);
        vireo_event_loop_handle_t h = {0};
        CHECK(vireo_event_loop_add(loop, &input, &h, NULL) == VIREO_OK);
        CHECK(vireo_event_loop_destroy(&loop, NULL) == VIREO_OK && fcntl(0, F_GETFD) >= 0);
        CHECK(write(pair[1], "x", 1) == 1); char byte; CHECK(read(0, &byte, 1) == 1 && byte == 'x');
        CHECK(close(0) == 0 && close(pair[1]) == 0);
        _exit(failures == 0 ? 0 : 1);
    }
    int status; CHECK(waitpid(child, &status, 0) == child);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

enum { THREADS = 4, PER_THREAD = 128 };
typedef struct worker {
    _Atomic bool *start;
    uint64_t ids[PER_THREAD];
    unsigned errors;
} worker_t;

/* 每线程独占自己的 loop 和输出；不在 worker 中修改主线程的断言计数。 */
static void *create_worker(void *context)
{
    worker_t *w = context;
    while (!atomic_load_explicit(w->start, memory_order_acquire)) sched_yield();
    for (size_t i = 0; i < PER_THREAD; ++i) {
        vireo_event_loop_t *loop = NULL; vireo_event_loop_options_t o = options(1, 1);
        vireo_event_loop_info_t info;
        errno = EACCES;
        if (vireo_event_loop_create(&o, &loop, NULL) != VIREO_OK) { ++w->errors; continue; }
        if (vireo_event_loop_inspect(loop, &info) != VIREO_OK) ++w->errors;
        else w->ids[i] = info.loop_id;
        if (vireo_event_loop_destroy(&loop, NULL) != VIREO_OK || errno != EACCES) ++w->errors;
    }
    return NULL;
}

enum { IDENTITY_JOIN_FAILURE_EXIT = 79 };

/* join 未确认结束时，不能读取结果或返回仍被线程借用的局部上下文。 */
static void join_identity_worker_or_exit(pthread_t thread, bool injected)
{
    int const result = injected ? EINVAL : pthread_join(thread, NULL);
    if (result != 0) {
        fprintf(stderr, "registration: thread join failed (%d), terminating test process\n",
                result);
        _Exit(injected ? IDENTITY_JOIN_FAILURE_EXIT : EXIT_FAILURE);
    }
}

static void concurrent_identities_case(unsigned fail_join_at)
{
    _Atomic bool start = false; worker_t workers[THREADS] = {0}; pthread_t threads[THREADS];
    size_t created = 0;
    for (; created < THREADS; ++created) {
        workers[created].start = &start;
        int result = pthread_create(&threads[created], NULL, create_worker, &workers[created]);
        CHECK(result == 0); if (result != 0) break;
    }
    atomic_store_explicit(&start, true, memory_order_release);
    for (size_t i = 0; i < created; ++i)
        join_identity_worker_or_exit(threads[i], i + 1 == fail_join_at);
    for (size_t i = 0; i < created; ++i) {
        CHECK(workers[i].errors == 0);
        for (size_t j = 0; j < PER_THREAD; ++j) {
            CHECK(workers[i].ids[j] != 0);
            for (size_t k = 0; k < i * PER_THREAD + j; ++k)
                CHECK(workers[i].ids[j] != workers[k / PER_THREAD].ids[k % PER_THREAD]);
        }
    }
}

static void concurrent_identities(void)
{
    concurrent_identities_case(0);
}

/* 每个 join 位置都经真实线程启动；明确退出不能误算为正常资源清理。 */
static void identity_join_failures(void)
{
    for (unsigned position = 1; position <= THREADS; ++position) {
        pid_t child = fork(); REQUIRE(child >= 0);
        if (child == 0) {
            concurrent_identities_case(position);
            _Exit(99); /* 意外返回或未到达注入位置，父进程须判失败。 */
        }
        int status = 0;
        pid_t waited;
        do { waited = waitpid(child, &status, 0); } while (waited == -1 && errno == EINTR);
        CHECK(waited == child && WIFEXITED(status) &&
              WEXITSTATUS(status) == IDENTITY_JOIN_FAILURE_EXIT);
    }
    puts("registration: 4 thread join failures terminate without returning borrowed context");
}

int main(void)
{
    void (*groups[])(void) = {
        arguments, capacity_and_arithmetic, fixed_binding_and_interests,
        kernel_readiness_and_counts, rejected_handles, stale_batch_and_fd_reuse,
        same_address_new_identity, control_failures, real_kernel_errors,
        active_destroy_and_borrow, serial_exhaustion, identity_exhaustion_and_failure,
        independent_model, client_fd_zero, concurrent_identities, identity_join_failures
    };
    size_t baseline = fd_count();
    for (size_t i = 0; i < sizeof(groups) / sizeof(groups[0]); ++i) {
        groups[i](); CHECK(fd_count() == baseline);
    }
    CHECK(callbacks == 0);
    if (failures != 0) { fprintf(stderr, "test_event_loop_registration: %u failures\n", failures); return 1; }
    puts("test_event_loop_registration: 16 groups passed "
         "(42 injected ctl failures, 512 concurrent IDs)");
    return 0;
}
