/*
- PROJECT : VIREO
- FILE    : test_event_loop_run_stop.c
- AUTHOR  : bitofux
- DATE    : 2026-10-03
- BRIEF   : 此模块负责：
- -- 真实阻塞等待、跨线程停止、通知合并与完整批次退出
- -- 确定故障验证停止部分提交、创建回滚、首错与 fd 配对清理
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static unsigned failures;
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #c); \
    ++failures; } } while (0)
#define REQUIRE(c) do { if (!(c)) { CHECK(c); return; } } while (0)

typedef struct fixture {
    int fds[2];
    unsigned allocations;
    unsigned releases;
    unsigned creates;
    unsigned closes;
    int close_order[2];
    int create_error;
    int add_error;
    int epoll_close_error;
    int close_errors[2];
    int write_error;
    int read_error;
    bool fake_write;
    bool fake_read;
    ssize_t write_result;
    ssize_t read_result;
    _Atomic unsigned writes;
    unsigned reads;
    unsigned waits;
    bool scripted;
    vireo_epoll_event_t batch[4];
    size_t count;
    unsigned fail_wait_at;
    bool guard_wait;
    bool stop_in_wait;
    size_t read_capacity;
    vireo_event_loop_t **owner;
} fixture_t;

/* 独立资源计数只由创建/销毁线程访问，通知计数支持多个请求者。 */
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

/* 创建失败不交付 fd；成功保留数值仅供本模块测试观察属性及物理关闭。 */
static int create_pipe(void *context, int fds[2])
{
    fixture_t *f = context; ++f->creates;
    if (f->create_error != 0) { errno = f->create_error; return -1; }
    int result = pipe2(fds, O_NONBLOCK | O_CLOEXEC);
    if (result == 0) { f->fds[0] = fds[0]; f->fds[1] = fds[1]; }
    return result;
}

static vireo_result_t add_epoll(void *context, vireo_epoll_t *epoll, int fd,
                               vireo_epoll_registration_t const *reg, vireo_epoll_error_t *error)
{
    fixture_t *f = context;
    if (reg->token == 0 && f->add_error != 0) {
        *error = (vireo_epoll_error_t){VIREO_EPOLL_STAGE_ADD, f->add_error};
        errno = EDOM; return VIREO_RESULT_IO;
    }
    return vireo_epoll_add(epoll, fd, reg, error);
}

/* 消费式失败先真实释放，再报告注入原因；不伪称内核 close 实际失败。 */
static vireo_result_t destroy_epoll(void *context, vireo_epoll_t **epoll,
                                   vireo_epoll_error_t *error)
{
    fixture_t *f = context;
    vireo_result_t result = vireo_epoll_destroy(epoll, error);
    if (f->epoll_close_error != 0) {
        *error = (vireo_epoll_error_t){VIREO_EPOLL_STAGE_CLOSE, f->epoll_close_error};
        return VIREO_RESULT_IO;
    }
    return result;
}

static int close_pipe(void *context, int fd)
{
    fixture_t *f = context;
    unsigned index = fd == f->fds[1] ? 0U : 1U;
    if (f->closes < 2) f->close_order[f->closes] = fd;
    ++f->closes;
    int result = close(fd);
    if (f->close_errors[index] != 0) { errno = f->close_errors[index]; return -1; }
    return result;
}

/* 通知配置在启动线程前固定；只有 writes 计数会被多个请求者同时修改。 */
static ssize_t write_pipe(void *context, int fd, void const *buffer, size_t size)
{
    fixture_t *f = context;
    (void)atomic_fetch_add_explicit(&f->writes, 1, memory_order_relaxed);
    if (f->fake_write) { errno = f->write_error; return f->write_result; }
    return write(fd, buffer, size);
}

static ssize_t read_pipe(void *context, int fd, void *buffer, size_t size)
{
    fixture_t *f = context; ++f->reads; f->read_capacity = size;
    if (f->fake_read) { errno = f->read_error; return f->read_result; }
    return read(fd, buffer, size);
}

/* 在途保护同时覆盖等待和回调，输出用逐字节独立 sentinel 检查。 */
static void guard(vireo_event_loop_t **owner)
{
    vireo_event_loop_t *saved_owner = *owner;
    vireo_event_loop_run_info_t info;
    unsigned char saved[sizeof(info)];
    memset(&info, 0xA5, sizeof(info)); memcpy(saved, &info, sizeof(info));
    vireo_event_loop_error_t error;
    errno = EACCES;
    CHECK(vireo_event_loop_run(*owner, &error) == VIREO_RESULT_BUSY);
    CHECK(vireo_event_loop_run_once(*owner, 0, &info, NULL) == VIREO_RESULT_BUSY);
    CHECK(memcmp(saved, &info, sizeof(info)) == 0);
    CHECK(vireo_event_loop_destroy(owner, &error) == VIREO_RESULT_BUSY);
    CHECK(*owner == saved_owner && errno == EACCES);
}

static vireo_result_t wait_epoll(void *context, vireo_epoll_t *epoll,
                                vireo_epoll_event_t *events, size_t capacity, int timeout_ms,
                                size_t *count, vireo_epoll_error_t *error)
{
    fixture_t *f = context; ++f->waits;
    if (f->guard_wait) guard(f->owner);
    if (f->stop_in_wait) CHECK(vireo_event_loop_request_stop(*f->owner, NULL) == VIREO_OK);
    if (f->waits == f->fail_wait_at) {
        *error = (vireo_epoll_error_t){VIREO_EPOLL_STAGE_WAIT, EINTR};
        errno = EDOM; return VIREO_RESULT_IO;
    }
    if (!f->scripted) return vireo_epoll_wait(epoll, timeout_ms, events, capacity, count, error);
    if (f->count <= capacity && f->count <= 4) {
        for (size_t i = 0; i < f->count; ++i) events[i] = f->batch[i];
    }
    *count = f->count;
    *error = (vireo_epoll_error_t){VIREO_EPOLL_STAGE_NONE, 0};
    return VIREO_OK;
}

static vireo_event_loop_ops_t resources(fixture_t *f)
{
    atomic_init(&f->writes, 0);
    f->fds[0] = f->fds[1] = -1;
    vireo_event_loop_ops_t ops = vireo_event_loop_default_ops();
    ops.context = f; ops.allocate = allocate; ops.deallocate = deallocate;
    ops.create_pipe = create_pipe; ops.close_pipe = close_pipe;
    ops.write_pipe = write_pipe; ops.read_pipe = read_pipe;
    ops.add_epoll = add_epoll; ops.destroy_epoll = destroy_epoll; ops.wait_epoll = wait_epoll;
    return ops;
}

static bool make(fixture_t *f, size_t capacity, vireo_event_loop_t **owner)
{
    f->owner = owner;
    vireo_event_loop_ops_t ops = resources(f);
    vireo_event_loop_options_t options = {capacity, VIREO_EVENT_LOOP_MAX_MEMORY, 4};
    vireo_result_t result = vireo_event_loop_create_with_ops(&options, &ops, owner, NULL);
    CHECK(result == VIREO_OK);
    return result == VIREO_OK;
}

static bool stopped(vireo_event_loop_t *loop)
{
    vireo_event_loop_info_t info;
    CHECK(vireo_event_loop_inspect(loop, &info) == VIREO_OK);
    return info.stop_requested;
}

static void clean_error(vireo_event_loop_error_t e)
{
    CHECK(e.stage == VIREO_EVENT_LOOP_STAGE_NONE && e.system_errno == 0);
    CHECK(e.epoll_error.stage == VIREO_EPOLL_STAGE_NONE && e.epoll_error.system_errno == 0);
}

static void empty(vireo_event_loop_run_info_t info)
{
    CHECK(info.ready_count == 0 && info.dispatched_count == 0 &&
          info.stale_count == 0 && info.filtered_count == 0);
}

/* 每组用真实 /proc fd 集合大小约束资源配对，不以 LSan 代替 fd 观察。 */
static size_t fd_count(void)
{
    DIR *dir = opendir("/proc/self/fd");
    CHECK(dir != NULL); if (dir == NULL) return SIZE_MAX;
    int own = dirfd(dir); size_t count = 0; struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        char *end; long fd = strtol(entry->d_name, &end, 10);
        if (*entry->d_name != '\0' && *end == '\0' && fd >= 0 && fd != own) ++count;
    }
    CHECK(closedir(dir) == 0); return count;
}

static void arguments(void)
{
    vireo_event_loop_error_t e; errno = EACCES;
    CHECK(vireo_event_loop_run(NULL, &e) == VIREO_RESULT_INVALID_ARGUMENT); clean_error(e);
    CHECK(vireo_event_loop_request_stop(NULL, &e) == VIREO_RESULT_INVALID_ARGUMENT);
    clean_error(e); CHECK(errno == EACCES);
    CHECK(vireo_event_loop_run(NULL, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_event_loop_request_stop(NULL, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
}

static void properties(void)
{
    fixture_t f = {0}; vireo_event_loop_t *loop = NULL; size_t baseline = fd_count();
    REQUIRE(make(&f, 1, &loop)); CHECK(fd_count() == baseline + 3);
    for (size_t i = 0; i < 2; ++i) {
        CHECK((fcntl(f.fds[i], F_GETFL) & O_NONBLOCK) != 0);
        CHECK((fcntl(f.fds[i], F_GETFD) & FD_CLOEXEC) != 0);
    }
    CHECK(!stopped(loop)); CHECK(vireo_event_loop_destroy(&loop, NULL) == VIREO_OK);
    CHECK(f.allocations == 3 && f.releases == 3 && f.closes == 2);
    CHECK(f.close_order[0] == f.fds[1] && f.close_order[1] == f.fds[0]);
}

static void stop_before_run(void)
{
    fixture_t f = {0}; vireo_event_loop_t *loop = NULL; REQUIRE(make(&f, 1, &loop));
    vireo_event_loop_error_t e; errno = EACCES;
    CHECK(vireo_event_loop_request_stop(loop, &e) == VIREO_OK); clean_error(e);
    CHECK(stopped(loop)); CHECK(vireo_event_loop_request_stop(loop, NULL) == VIREO_OK);
    CHECK(atomic_load(&f.writes) == 2);
    for (unsigned i = 0; i < 3; ++i) {
        CHECK(vireo_event_loop_run(loop, &e) == VIREO_OK); clean_error(e);
        vireo_event_loop_run_info_t info;
        memset(&info, 0xA5, sizeof(info));
        CHECK(vireo_event_loop_run_once(loop, -1, &info, &e) == VIREO_OK);
        empty(info); clean_error(e);
    }
    CHECK(f.waits == 0 && errno == EACCES);
    CHECK(vireo_event_loop_destroy(&loop, NULL) == VIREO_OK);
}

static void notification_failures(void)
{
    int causes[] = {EINTR, EBADF, ENOMEM, EIO, EPIPE};
    for (size_t i = 0; i < sizeof(causes) / sizeof(causes[0]); ++i) {
        for (unsigned diag = 0; diag < 2; ++diag) {
            fixture_t f = {.fake_write = true, .write_result = -1, .write_error = causes[i]};
            vireo_event_loop_t *loop = NULL; REQUIRE(make(&f, 2, &loop));
            vireo_event_loop_error_t e; errno = EACCES;
            CHECK(vireo_event_loop_request_stop(loop, diag ? &e : NULL) == VIREO_RESULT_IO);
            CHECK(errno == EACCES && atomic_load(&f.writes) == 1 && stopped(loop));
            if (diag) {
                CHECK(e.stage == VIREO_EVENT_LOOP_STAGE_STOP_NOTIFY && e.system_errno == causes[i]);
                CHECK(e.epoll_error.stage == VIREO_EPOLL_STAGE_NONE);
            }
            f.fake_write = false;
            CHECK(vireo_event_loop_request_stop(loop, &e) == VIREO_OK); clean_error(e);
            CHECK(atomic_load(&f.writes) == 2); CHECK(vireo_event_loop_run(loop, NULL) == VIREO_OK);
            CHECK(f.waits == 0); CHECK(vireo_event_loop_destroy(&loop, NULL) == VIREO_OK);
        }
    }
}

static void notification_progress(void)
{
    ssize_t progress[] = {0, 2, -2, -1};
    for (size_t i = 0; i < 4; ++i) {
        fixture_t f = {.fake_write = true, .write_result = progress[i], .write_error = EAGAIN};
        vireo_event_loop_t *loop = NULL; REQUIRE(make(&f, 1, &loop));
        vireo_event_loop_error_t e; errno = EACCES;
        CHECK(vireo_event_loop_request_stop(loop, &e) ==
              (i == 3 ? VIREO_OK : VIREO_RESULT_INTERNAL));
        CHECK(stopped(loop) && errno == EACCES && atomic_load(&f.writes) == 1);
        if (i == 3) clean_error(e); else CHECK(e.system_errno == 0);
        CHECK(vireo_event_loop_destroy(&loop, NULL) == VIREO_OK);
    }
}

static void full_pipe(void)
{
    fixture_t f = {0}; vireo_event_loop_t *loop = NULL; REQUIRE(make(&f, 1, &loop));
    int capacity = fcntl(f.fds[1], F_GETPIPE_SZ); REQUIRE(capacity > 0);
    for (int i = 0; i < capacity + 2; ++i) {
        CHECK(vireo_event_loop_request_stop(loop, NULL) == VIREO_OK);
    }
    unsigned char byte; CHECK(read(f.fds[0], &byte, 1) == 1 && byte == 1);
    CHECK(stopped(loop)); CHECK(vireo_event_loop_run(loop, NULL) == VIREO_OK);
    CHECK(f.waits == 0); CHECK(vireo_event_loop_destroy(&loop, NULL) == VIREO_OK);
    printf("run_stop: real notification saturation capacity=%d\n", capacity);
}

static void creation_failures(void)
{
    for (unsigned fault = 0; fault < 2; ++fault) {
        for (unsigned diag = 0; diag < 2; ++diag) {
            fixture_t f = {.create_error = fault == 0 ? EMFILE : 0,
                          .add_error = fault == 1 ? ENOSPC : 0,
                          .epoll_close_error = EINTR, .close_errors = {EIO, EBADF}};
            vireo_event_loop_t *loop = NULL; vireo_event_loop_ops_t ops = resources(&f);
            vireo_event_loop_options_t options = {2, VIREO_EVENT_LOOP_MAX_MEMORY, 4};
            vireo_event_loop_error_t e; errno = EACCES;
            CHECK(vireo_event_loop_create_with_ops(&options, &ops, &loop, diag ? &e : NULL) ==
                  VIREO_RESULT_IO);
            CHECK(loop == NULL && f.allocations == 3 && f.releases == 3 && errno == EACCES);
            CHECK(f.closes == (fault == 0 ? 0U : 2U));
            if (diag) {
                CHECK(e.stage == (fault == 0 ? VIREO_EVENT_LOOP_STAGE_WAKE_CREATE :
                                  VIREO_EVENT_LOOP_STAGE_WAKE_REGISTER));
                CHECK(e.system_errno == (fault == 0 ? EMFILE : 0));
                CHECK(e.epoll_error.system_errno == (fault == 0 ? 0 : ENOSPC));
            }
        }
    }
}

static void close_failures(void)
{
    for (unsigned fault = 0; fault < 3; ++fault) {
        for (unsigned diag = 0; diag < 2; ++diag) {
            fixture_t f = {0}; vireo_event_loop_t *loop = NULL; REQUIRE(make(&f, 1, &loop));
            f.epoll_close_error = fault == 0 ? EINTR : 0;
            f.close_errors[0] = fault < 2 ? EIO : 0; f.close_errors[1] = EBADF;
            vireo_event_loop_error_t e; errno = EACCES;
            CHECK(vireo_event_loop_destroy(&loop, diag ? &e : NULL) == VIREO_RESULT_IO);
            CHECK(loop == NULL && f.closes == 2 && f.releases == 3 && errno == EACCES);
            CHECK(f.close_order[0] == f.fds[1] && f.close_order[1] == f.fds[0]);
            if (diag) {
                vireo_event_loop_stage_t expected[] = {VIREO_EVENT_LOOP_STAGE_DESTROY_EPOLL,
                    VIREO_EVENT_LOOP_STAGE_CLOSE_WRITE, VIREO_EVENT_LOOP_STAGE_CLOSE_READ};
                CHECK(e.stage == expected[fault]);
                CHECK(e.system_errno == (fault == 0 ? 0 : fault == 1 ? EIO : EBADF));
                CHECK(e.epoll_error.system_errno == (fault == 0 ? EINTR : 0));
            }
            CHECK(vireo_event_loop_destroy(&loop, &e) == VIREO_OK); clean_error(e);
        }
    }
}

typedef struct callbacks {
    fixture_t *fixture;
    unsigned count;
    bool stop;
    bool probe;
    int channel[2];
} callbacks_t;

/* 固定脚本能证明 A 请求停止后 B 仍执行，不依赖内核的不同 fd 返回顺序。 */
static void callback(vireo_event_loop_t *loop, vireo_event_loop_handle_t handle, int fd,
                     uint32_t events, void *context)
{
    callbacks_t *c = context; (void)handle;
    CHECK(events == VIREO_EPOLL_EVENT_READ && fd == c->channel[0]);
    ++c->count;
    if (c->probe) guard(c->fixture->owner);
    if (c->stop) CHECK(vireo_event_loop_request_stop(loop, NULL) == VIREO_OK);
    if (c->probe) guard(c->fixture->owner);
    CHECK(c->fixture->allocations == 3 && c->fixture->releases == 0);
    errno = EDOM;
}

static bool register_callback(vireo_event_loop_t *loop, callbacks_t *c,
                              vireo_event_loop_handle_t *handle)
{
    if (pipe2(c->channel, O_NONBLOCK | O_CLOEXEC) != 0) { CHECK(false); return false; }
    vireo_event_loop_registration_t reg = {c->channel[0], VIREO_EPOLL_INTEREST_READ, callback, c};
    vireo_result_t result = vireo_event_loop_add(loop, &reg, handle, NULL);
    CHECK(result == VIREO_OK); return result == VIREO_OK;
}

static void close_callback(callbacks_t *c)
{
    CHECK(close(c->channel[0]) == 0 && close(c->channel[1]) == 0);
}

static void complete_batch(void)
{
    for (unsigned once = 0; once < 2; ++once) {
        fixture_t f = {.scripted = true}; vireo_event_loop_t *loop = NULL;
        REQUIRE(make(&f, 4, &loop)); callbacks_t a = {.fixture = &f, .stop = true, .probe = true};
        callbacks_t b = {.fixture = &f}; vireo_event_loop_handle_t ha = {0}, hb = {0};
        REQUIRE(register_callback(loop, &a, &ha)); REQUIRE(register_callback(loop, &b, &hb));
        f.count = 2; f.batch[0] = (vireo_epoll_event_t){ha.token, 1};
        f.batch[1] = (vireo_epoll_event_t){hb.token, 1}; errno = EACCES;
        if (once) {
            vireo_event_loop_run_info_t info;
            CHECK(vireo_event_loop_run_once(loop, -1, &info, NULL) == VIREO_OK);
            CHECK(info.ready_count == 2 && info.dispatched_count == 2 &&
                  info.stale_count == 0 && info.filtered_count == 0);
        } else CHECK(vireo_event_loop_run(loop, NULL) == VIREO_OK);
        CHECK(a.count == 1 && b.count == 1 && f.waits == 1 && stopped(loop) && errno == EACCES);
        CHECK(vireo_event_loop_del(loop, &ha, NULL) == VIREO_OK);
        CHECK(vireo_event_loop_del(loop, &hb, NULL) == VIREO_OK);
        CHECK(vireo_event_loop_destroy(&loop, NULL) == VIREO_OK);
        close_callback(&a); close_callback(&b);
    }
}

static void control_count(void)
{
    fixture_t f = {.scripted = true}; vireo_event_loop_t *loop = NULL;
    REQUIRE(make(&f, 4, &loop)); callbacks_t c = {.fixture = &f};
    vireo_event_loop_handle_t handle = {0}; REQUIRE(register_callback(loop, &c, &handle));
    f.count = 3; f.batch[0] = (vireo_epoll_event_t){0, 1};
    f.batch[1] = (vireo_epoll_event_t){handle.token, 1}; f.batch[2] = (vireo_epoll_event_t){0, 1};
    vireo_event_loop_run_info_t info; errno = EACCES;
    CHECK(vireo_event_loop_run_once(loop, 0, &info, NULL) == VIREO_OK);
    CHECK(info.ready_count == 1 && info.dispatched_count == 1 && f.reads == 1);
    CHECK(f.read_capacity == 64);
    CHECK(c.count == 1 && !stopped(loop) && errno == EACCES); /* 控制项过期 EAGAIN 正常。 */
    CHECK(vireo_event_loop_destroy(&loop, NULL) == VIREO_OK); close_callback(&c);
}

static void control_read_failures(void)
{
    ssize_t progress[] = {-1, 0, 65, -2, -1, 1};
    for (size_t i = 0; i < 6; ++i) {
        fixture_t f = {.scripted = true, .fake_read = true, .read_result = progress[i],
                      .read_error = i == 4 ? EAGAIN : EINTR};
        vireo_event_loop_t *loop = NULL; REQUIRE(make(&f, 4, &loop));
        callbacks_t c = {.fixture = &f}; vireo_event_loop_handle_t h = {0};
        REQUIRE(register_callback(loop, &c, &h)); f.count = 2;
        f.batch[0] = (vireo_epoll_event_t){h.token, 1}; f.batch[1] = (vireo_epoll_event_t){0, 1};
        vireo_event_loop_run_info_t info; unsigned char saved[sizeof(info)];
        memset(&info, 0xA5, sizeof(info)); memcpy(saved, &info, sizeof(info));
        vireo_event_loop_error_t e; errno = EACCES;
        vireo_result_t expected = i >= 4 ? VIREO_OK : i == 0 ? VIREO_RESULT_IO :
                                   VIREO_RESULT_INTERNAL;
        CHECK(vireo_event_loop_run_once(loop, 0, &info, &e) == expected);
        CHECK(f.reads == 1 && errno == EACCES);
        if (i >= 4) { CHECK(c.count == 1 && info.ready_count == 1); clean_error(e); }
        else {
            CHECK(c.count == 0 && memcmp(saved, &info, sizeof(info)) == 0);
            CHECK(e.stage == VIREO_EVENT_LOOP_STAGE_WAKE_READ);
            CHECK(e.system_errno == (i == 0 ? EINTR : 0));
        }
        f.count = 0; CHECK(vireo_event_loop_run_once(loop, 0, &info, NULL) == VIREO_OK);
        CHECK(vireo_event_loop_destroy(&loop, NULL) == VIREO_OK); close_callback(&c);
    }
}

static void control_shapes(void)
{
    uint32_t bits[] = {0, 2, 4, 8, 16, 3, 32};
    for (size_t i = 0; i < 7; ++i) {
        fixture_t f = {.scripted = true}; vireo_event_loop_t *loop = NULL;
        REQUIRE(make(&f, 4, &loop)); callbacks_t c = {.fixture = &f};
        vireo_event_loop_handle_t h = {0}; REQUIRE(register_callback(loop, &c, &h));
        f.count = 2; f.batch[0] = (vireo_epoll_event_t){h.token, 1};
        f.batch[1] = (vireo_epoll_event_t){0, bits[i]};
        vireo_event_loop_run_info_t info; unsigned char saved[sizeof(info)];
        memset(&info, 0xA5, sizeof(info)); memcpy(saved, &info, sizeof(info));
        vireo_event_loop_error_t e;
        CHECK(vireo_event_loop_run_once(loop, 0, &info, &e) == VIREO_RESULT_INTERNAL);
        CHECK(c.count == 0 && f.reads == 0 && memcmp(saved, &info, sizeof(info)) == 0);
        CHECK(e.stage == (i == 6 ? VIREO_EVENT_LOOP_STAGE_WAIT : VIREO_EVENT_LOOP_STAGE_WAKE_READ));
        CHECK(e.system_errno == 0);
        CHECK(vireo_event_loop_destroy(&loop, NULL) == VIREO_OK); close_callback(&c);
    }
}

static void error_after_progress(void)
{
    fixture_t f = {.scripted = true, .fail_wait_at = 2}; vireo_event_loop_t *loop = NULL;
    REQUIRE(make(&f, 4, &loop)); callbacks_t c = {.fixture = &f};
    vireo_event_loop_handle_t h = {0}; REQUIRE(register_callback(loop, &c, &h));
    f.count = 1; f.batch[0] = (vireo_epoll_event_t){h.token, 1};
    vireo_event_loop_error_t e; errno = EACCES;
    CHECK(vireo_event_loop_run(loop, &e) == VIREO_RESULT_IO);
    CHECK(c.count == 1 && f.waits == 2 && errno == EACCES && !stopped(loop));
    CHECK(e.stage == VIREO_EVENT_LOOP_STAGE_WAIT && e.epoll_error.system_errno == EINTR);
    c.stop = true; CHECK(vireo_event_loop_run(loop, NULL) == VIREO_OK);
    CHECK(c.count == 2 && f.waits == 3 && stopped(loop));
    CHECK(vireo_event_loop_destroy(&loop, NULL) == VIREO_OK); close_callback(&c);
}

static void wait_guard(void)
{
    fixture_t f = {.guard_wait = true, .fail_wait_at = 1}; vireo_event_loop_t *loop = NULL;
    REQUIRE(make(&f, 2, &loop)); CHECK(vireo_event_loop_run(loop, NULL) == VIREO_RESULT_IO);
    CHECK(f.waits == 1 && !stopped(loop)); CHECK(vireo_event_loop_destroy(&loop, NULL) == VIREO_OK);
}

/* stop 在本轮检查之后、真正进入等待之前到达，pipe 必须保留该通知；
 * 若同次等待报告失败则不能用停止状态把 IO 吞成成功。 */
static void wait_window(void)
{
    for (unsigned fail = 0; fail < 2; ++fail) {
        fixture_t f = {.stop_in_wait = true, .fail_wait_at = fail ? 1U : 0U};
        vireo_event_loop_t *loop = NULL; REQUIRE(make(&f, 1, &loop));
        vireo_event_loop_error_t e; errno = EACCES;
        CHECK(vireo_event_loop_run(loop, &e) == (fail ? VIREO_RESULT_IO : VIREO_OK));
        CHECK(f.waits == 1 && stopped(loop) && atomic_load(&f.writes) == 1 && errno == EACCES);
        if (fail) CHECK(e.stage == VIREO_EVENT_LOOP_STAGE_WAIT &&
                        e.epoll_error.system_errno == EINTR);
        else { CHECK(f.reads == 1); clean_error(e); }
        CHECK(vireo_event_loop_run(loop, NULL) == VIREO_OK && f.waits == 1);
        CHECK(vireo_event_loop_destroy(&loop, NULL) == VIREO_OK);
    }
}

/* 私有观测 fd 仅测试构造提示，标记保持 false，以真实 read 验证一次最多 64 字节。 */
static void bounded_read(void)
{
    fixture_t f = {0}; vireo_event_loop_t *loop = NULL; REQUIRE(make(&f, 1, &loop));
    unsigned char bytes[128]; memset(bytes, 1, sizeof(bytes));
    REQUIRE(write(f.fds[1], bytes, sizeof(bytes)) == (ssize_t)sizeof(bytes));
    for (unsigned i = 0; i < 2; ++i) {
        vireo_event_loop_run_info_t info;
        CHECK(vireo_event_loop_run_once(loop, 0, &info, NULL) == VIREO_OK); empty(info);
        CHECK(f.reads == i + 1 && f.read_capacity == 64 && !stopped(loop));
    }
    vireo_event_loop_run_info_t info;
    CHECK(vireo_event_loop_run_once(loop, 0, &info, NULL) == VIREO_OK); empty(info);
    CHECK(f.reads == 2 && f.waits == 3);
    CHECK(vireo_event_loop_destroy(&loop, NULL) == VIREO_OK);
}

typedef struct worker {
    vireo_event_loop_t *loop;
    _Atomic int tid;
    vireo_result_t result;
    vireo_event_loop_error_t error;
    int final_errno;
    bool once;
    vireo_event_loop_run_info_t info;
} worker_t;

/* 工作线程只保存自己的结果，主线程 join 后再比较，不竞争全局测试 failures。 */
static void *run_worker(void *context)
{
    worker_t *w = context;
    atomic_store_explicit(&w->tid, gettid(), memory_order_release);
    errno = EACCES;
    w->result = w->once ? vireo_event_loop_run_once(w->loop, -1, &w->info, &w->error) :
                         vireo_event_loop_run(w->loop, &w->error);
    w->final_errno = errno;
    return NULL;
}

/* 观察真实内核 epoll 睡眠，2 秒单调期限只用于测试失败保护，未用 sleep 猜时序。 */
static bool sleeping(worker_t *w)
{
    struct timespec start, now;
    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) return false;
    do {
        int tid = atomic_load_explicit(&w->tid, memory_order_acquire);
        if (tid > 0) {
            char path[96], state[128];
            int n = snprintf(path, sizeof(path), "/proc/self/task/%d/wchan", tid);
            if (n > 0 && (size_t)n < sizeof(path)) {
                FILE *file = fopen(path, "r");
                if (file != NULL) {
                    char *read_state = fgets(state, sizeof(state), file);
                    int closed = fclose(file);
                    if (closed == 0 && read_state != NULL && strstr(state, "ep_poll") != NULL) {
                        return true;
                    }
                }
            }
        }
        (void)sched_yield();
        if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return false;
    } while (now.tv_sec - start.tv_sec < 2);
    return false;
}

/* 仅测试线程启动/等待的确定故障；计数和配置只由调用线程访问。 */
typedef struct thread_fixture {
    unsigned create_calls;
    unsigned created;
    unsigned join_calls;
    unsigned joined;
    unsigned fail_create_at;
    unsigned fail_join_at;
} thread_fixture_t;

enum { JOIN_FAILURE_EXIT = 77, STOP_FAILURE_EXIT = 78 };

static int create_thread(thread_fixture_t *f, pthread_t *thread,
                         void *(*entry)(void *), void *context)
{
    ++f->create_calls;
    if (f->create_calls == f->fail_create_at) {
        errno = EDOM; /* pthread 的直接返回码不能从 errno 获取。 */
        return EAGAIN;
    }
    int const result = pthread_create(thread, NULL, entry, context);
    if (result == 0) ++f->created;
    return result;
}

/* 无法证明借用结束时不能返回局部上下文；子进程回归验证明确退出。 */
static void join_thread_or_exit(thread_fixture_t *f, pthread_t thread)
{
    ++f->join_calls;
    bool const injected = f->join_calls == f->fail_join_at;
    int const result = injected ? EINVAL : pthread_join(thread, NULL);
    if (result != 0) {
        fprintf(stderr, "run_stop: thread join failed (%d), terminating test process\n", result);
        _Exit(injected ? JOIN_FAILURE_EXIT : EXIT_FAILURE);
    }
    ++f->joined;
}

/* 清理不能在通知失败后无期限 join；保持局部上下文至进程结束。 */
static void stop_or_exit(vireo_event_loop_t *loop)
{
    if (vireo_event_loop_request_stop(loop, NULL) != VIREO_OK) {
        fputs("run_stop: cleanup stop failed, terminating test process\n", stderr);
        _Exit(STOP_FAILURE_EXIT);
    }
}

static int blocked_stop_case(bool once, thread_fixture_t *threads)
{
    fixture_t f = {0}; vireo_event_loop_t *loop = NULL;
    if (!make(&f, 1, &loop)) return ENOMEM;
    worker_t w = {.loop = loop, .once = once}; atomic_init(&w.tid, 0);
    pthread_t thread;
    int const result = create_thread(threads, &thread, run_worker, &w);
    if (result == 0) {
        CHECK(sleeping(&w)); /* 确认已经阻塞，不仅仅来到适配入口。 */
        errno = EBUSY; stop_or_exit(loop); CHECK(errno == EBUSY);
        join_thread_or_exit(threads, thread);
        CHECK(w.result == VIREO_OK && w.final_errno == EACCES); clean_error(w.error);
        if (once) empty(w.info);
        CHECK(f.waits == 1 && f.reads == 1 && atomic_load(&f.writes) == 1 && stopped(loop));
    } else {
        CHECK(f.waits == 0 && atomic_load(&f.writes) == 0 && !stopped(loop));
    }
    CHECK(vireo_event_loop_destroy(&loop, NULL) == VIREO_OK && loop == NULL);
    CHECK(f.releases == 3 && f.closes == 2);
    return result;
}

static void blocked_stop(void)
{
    for (unsigned once = 0; once < 2; ++once) {
        thread_fixture_t threads = {0};
        CHECK(blocked_stop_case(once != 0, &threads) == 0);
        CHECK(threads.create_calls == 1 && threads.created == 1 && threads.joined == 1);
    }
    puts("run_stop: 2 real sleeping epoll waiters woken (capacity 1)");
}

typedef struct requester {
    vireo_event_loop_t *loop;
    _Atomic bool *start;
    unsigned errors;
} requester_t;

static void *request_worker(void *context)
{
    requester_t *r = context;
    while (!atomic_load_explicit(r->start, memory_order_acquire)) (void)sched_yield();
    for (unsigned i = 0; i < 256; ++i) {
        vireo_event_loop_error_t e; errno = EACCES;
        if (vireo_event_loop_request_stop(r->loop, &e) != VIREO_OK || errno != EACCES ||
            e.stage != VIREO_EVENT_LOOP_STAGE_NONE || e.system_errno != 0) ++r->errors;
    }
    return NULL;
}

static int concurrent_requests_case(thread_fixture_t *thread_state)
{
    fixture_t f = {0}; vireo_event_loop_t *loop = NULL;
    if (!make(&f, 1, &loop)) return ENOMEM;
    worker_t w = {.loop = loop}; atomic_init(&w.tid, 0);
    _Atomic bool start; atomic_init(&start, false);
    requester_t requests[4]; pthread_t threads[4];
    pthread_t reactor;
    int result = create_thread(thread_state, &reactor, run_worker, &w);
    if (result == 0) {
        CHECK(sleeping(&w));
        size_t created = 0;
        for (; created < 4; ++created) {
            requests[created] = (requester_t){loop, &start, 0};
            result = create_thread(thread_state, &threads[created], request_worker,
                                   &requests[created]);
            if (result != 0) break;
        }
        /* 部分启动失败仍须放行已有请求者；零请求者时显式通知阻塞 Reactor。 */
        atomic_store_explicit(&start, true, memory_order_release);
        if (result != 0) stop_or_exit(loop);
        for (size_t i = 0; i < created; ++i) {
            join_thread_or_exit(thread_state, threads[i]); CHECK(requests[i].errors == 0);
        }
        join_thread_or_exit(thread_state, reactor);
        CHECK(w.result == VIREO_OK && w.final_errno == EACCES); clean_error(w.error);
        CHECK(atomic_load(&f.writes) == created * 256 + (result != 0 ? 1U : 0U));
        CHECK(stopped(loop));
    } else {
        CHECK(f.waits == 0 && atomic_load(&f.writes) == 0 && !stopped(loop));
    }
    CHECK(vireo_event_loop_destroy(&loop, NULL) == VIREO_OK && loop == NULL);
    CHECK(f.releases == 3 && f.closes == 2);
    return result; /* 清理保留原 pthread_create 返回码，即使 errno 被后续动作改变。 */
}

static void concurrent_requests(void)
{
    thread_fixture_t threads = {0};
    CHECK(concurrent_requests_case(&threads) == 0);
    CHECK(threads.create_calls == 5 && threads.created == 5 && threads.joined == 5);
    puts("run_stop: 4 requesters / 1024 requests, all joined before destruction");
}

/* 在每个启动位置拒绝一次，余下线程真实创建/join，不仅检查返回码。 */
static void thread_start_failures(void)
{
    for (unsigned once = 0; once < 2; ++once) {
        size_t baseline = fd_count(); thread_fixture_t threads = {.fail_create_at = 1};
        CHECK(blocked_stop_case(once != 0, &threads) == EAGAIN);
        CHECK(threads.create_calls == 1 && threads.created == 0 && threads.joined == 0);
        CHECK(fd_count() == baseline);
    }
    for (unsigned position = 1; position <= 5; ++position) {
        size_t baseline = fd_count(); thread_fixture_t threads = {.fail_create_at = position};
        CHECK(concurrent_requests_case(&threads) == EAGAIN);
        CHECK(threads.create_calls == position && threads.created == position - 1);
        CHECK(threads.join_calls == threads.created && threads.joined == threads.created);
        CHECK(fd_count() == baseline);
    }
    puts("run_stop: 7 thread startup failures, started threads joined and resources released");
}

/* fork 仅在先前全部线程 join 后执行；失败子进程不得带着在途借用返回。 */
static void thread_join_failures(void)
{
    for (unsigned scenario = 0; scenario < 7; ++scenario) {
        pid_t child = fork(); REQUIRE(child >= 0);
        if (child == 0) {
            thread_fixture_t threads = {.fail_join_at = scenario < 2 ? 1U : scenario - 1};
            if (scenario < 2) (void)blocked_stop_case(scenario != 0, &threads);
            else (void)concurrent_requests_case(&threads);
            _Exit(99); /* 失败后返回就是缺陷，不能碰巧以正常测试失败码通过。 */
        }
        int status = 0;
        pid_t waited;
        do { waited = waitpid(child, &status, 0); } while (waited == -1 && errno == EINTR);
        CHECK(waited == child && WIFEXITED(status) && WEXITSTATUS(status) == JOIN_FAILURE_EXIT);
    }
    puts("run_stop: 7 thread join failures terminate safely without returning borrowed context");
}

int main(void)
{
    void (*groups[])(void) = {arguments, properties, stop_before_run, notification_failures,
        notification_progress, full_pipe, creation_failures, close_failures, complete_batch,
        control_count, control_read_failures, control_shapes, error_after_progress, wait_guard,
        wait_window, bounded_read, blocked_stop, concurrent_requests,
        thread_start_failures, thread_join_failures};
    for (size_t i = 0; i < sizeof(groups) / sizeof(groups[0]); ++i) {
        size_t before = fd_count(); groups[i](); CHECK(fd_count() == before);
    }
    if (failures != 0) { fprintf(stderr, "test_event_loop_run_stop: %u failures\n", failures);
        return EXIT_FAILURE; }
    puts("test_event_loop_run_stop: 20 groups passed");
    return EXIT_SUCCESS;
}
