/*
 * PROJECT : VIREO
 * FILE    : test_epoll_lifecycle.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-02
 * BRIEF   : 此模块负责：
 * -- 验证 epoll 资源、预算、发布与失败消费合同
 */
#define _POSIX_C_SOURCE 200809L
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
#include <sys/epoll.h>
#include <sys/wait.h>
#include <unistd.h>

static unsigned failures;
#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition); \
    ++failures; } } while (0)
#define REQUIRE(condition) do { if (!(condition)) { CHECK(condition); return; } } while (0)

typedef struct fixture {
    size_t allocations;
    size_t fail_allocation;
    size_t releases;
    size_t live;
    size_t sizes[2];
    void *blocks[2];
    unsigned create_calls;
    unsigned close_calls;
    int create_error;
    int close_error;
    int fd;
    int replacement;
    char order[16];
    size_t order_size;
    vireo_epoll_t **owner;
} fixture_t;

static vireo_epoll_options_t const default_options = {64, VIREO_EPOLL_MAX_MEMORY};

/* 只在测试顺序日志中记录资源操作，不模拟生产内核集合或控制块布局。 */
static void record(fixture_t *f, char step)
{
    CHECK(f->order_size + 1 < sizeof(f->order));
    if (f->order_size + 1 < sizeof(f->order)) {
        f->order[f->order_size++] = step;
        f->order[f->order_size] = '\0';
    }
}

/* 每次成功都真实 malloc；故障不制造内存，跟踪真实配对 free 和发布时点。 */
static void *allocate(void *context, size_t size)
{
    fixture_t *f = context;
    CHECK(f->owner != NULL && *f->owner == NULL);
    ++f->allocations;
    record(f, f->allocations == 1 ? 'a' : 'b');
    errno = ENOMEM;
    if (f->allocations == f->fail_allocation) {
        return NULL;
    }
    CHECK(f->allocations <= 2);
    if (f->allocations > 2) {
        return NULL;
    }
    void *memory = malloc(size);
    f->blocks[f->allocations - 1] = memory;
    f->sizes[f->allocations - 1] = size;
    if (memory != NULL) {
        ++f->live;
    }
    return memory;
}

/* 在释放前判别所属块，移除记录再 free，不读已释放控制块或悬空地址。 */
static void deallocate(void *context, void *memory)
{
    fixture_t *f = context;
    size_t index = 2;
    for (size_t i = 0; i < 2; ++i) {
        if (f->blocks[i] == memory && memory != NULL) {
            index = i;
        }
    }
    CHECK(index < 2);
    if (index < 2) {
        record(f, index == 0 ? 'A' : 'B');
        f->blocks[index] = NULL;
        --f->live;
        ++f->releases;
        free(memory);
    }
    errno = ERANGE; /* 后续清理必须不能覆盖主要诊断或外层 errno。 */
}

/* 正常入口真实 epoll_create1，失败入口仅注入明确 errno，不伪称系统耗尽。 */
static int create_fd(void *context, int flags)
{
    fixture_t *f = context;
    CHECK(f->owner != NULL && *f->owner == NULL);
    CHECK(flags == EPOLL_CLOEXEC);
    ++f->create_calls;
    record(f, 'e');
    if (f->create_error != 0) {
        errno = f->create_error;
        return -1;
    }
    f->fd = epoll_create1(flags);
    return f->fd;
}

/* 先真实关闭，再在同一数值 fd 上打开替代文件并报错，证明不能二次 close。 */
static int close_fd(void *context, int fd)
{
    fixture_t *f = context;
    ++f->close_calls;
    record(f, 'c');
    CHECK(fd == f->fd);
    CHECK(close(fd) == 0);
    f->fd = -1;
    if (f->close_error != 0) {
        int fresh = open("/dev/null", O_RDONLY | O_CLOEXEC);
        CHECK(fresh >= 0);
        if (fresh >= 0 && fresh != fd) {
            CHECK(dup2(fresh, fd) == fd);
            CHECK(close(fresh) == 0);
            fresh = fd;
        }
        f->replacement = fresh;
        errno = f->close_error;
        return -1;
    }
    return 0;
}

/* 生命周期夹具只适配新增必要回调，不在这里重复注册测试。 */
static int control_fd(void *context, int epfd, int operation, int fd,
                       struct epoll_event *event)
{
    (void)context;
    return epoll_ctl(epfd, operation, fd, event);
}

static int wait_fd(void *context, int epfd, struct epoll_event *events,
                   int maxevents, int timeout_ms)
{
    (void)context;
    return epoll_wait(epfd, events, maxevents, timeout_ms);
}

static vireo_epoll_ops_t make_ops(fixture_t *f, vireo_epoll_t **owner)
{
    f->fd = -1;
    f->replacement = -1;
    f->owner = owner;
    return (vireo_epoll_ops_t){f, allocate, deallocate, create_fd, close_fd, control_fd, wait_fd};
}

/* /proc 读数排除当前目录流本身，避免把观察工具的 fd 当成资源泄漏。 */
static size_t fd_count(void)
{
    DIR *dir = opendir("/proc/self/fd");
    CHECK(dir != NULL);
    if (dir == NULL) {
        return SIZE_MAX;
    }
    int own = dirfd(dir);
    size_t count = 0;
    struct dirent *entry;
    errno = 0;
    while ((entry = readdir(dir)) != NULL) {
        char *end;
        long value = strtol(entry->d_name, &end, 10);
        if (*entry->d_name != '\0' && *end == '\0' && value >= 0 && value != own) {
            ++count;
        }
    }
    CHECK(errno == 0);
    CHECK(closedir(dir) == 0);
    return count;
}

static void public_arguments(void)
{
    vireo_epoll_t *owner = NULL;
    vireo_epoll_error_t error = {VIREO_EPOLL_STAGE_CLOSE, EIO};
    errno = EACCES;
    CHECK(vireo_epoll_create(NULL, &owner, &error) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(owner == NULL && error.stage == VIREO_EPOLL_STAGE_NONE && error.system_errno == 0);
    CHECK(errno == EACCES);
    CHECK(vireo_epoll_create(&default_options, NULL, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_epoll_destroy(NULL, &error) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(error.stage == VIREO_EPOLL_STAGE_NONE && error.system_errno == 0);
    CHECK(vireo_epoll_destroy(&owner, &error) == VIREO_OK);
    CHECK(owner == NULL && errno == EACCES);
    REQUIRE(vireo_epoll_create(&default_options, &owner, NULL) == VIREO_OK);
    vireo_epoll_t *original = owner;
    CHECK(vireo_epoll_create(&default_options, &owner, &error) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(owner == original && errno == EACCES);
    CHECK(vireo_epoll_destroy(&owner, NULL) == VIREO_OK);
    CHECK(owner == NULL && errno == EACCES);
}

static void inspect_contract(void)
{
    vireo_epoll_t *owner = NULL;
    vireo_epoll_info_t info;
    unsigned char saved[sizeof(info)];
    memset(&info, 0xA5, sizeof(info));
    memcpy(saved, &info, sizeof(info));
    errno = EACCES;
    CHECK(vireo_epoll_inspect(NULL, &info) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(memcmp(saved, &info, sizeof(info)) == 0 && errno == EACCES);
    REQUIRE(vireo_epoll_create(&default_options, &owner, NULL) == VIREO_OK);
    CHECK(vireo_epoll_inspect(owner, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_epoll_inspect(owner, &info) == VIREO_OK);
    CHECK(info.event_capacity == 64 && info.events_bytes == 64 * sizeof(struct epoll_event));
    CHECK(info.allocation_bytes > info.events_bytes);
    CHECK(info.allocation_bytes <= info.max_memory_bytes && errno == EACCES);
    vireo_epoll_info_t copy = info;
    CHECK(vireo_epoll_destroy(&owner, NULL) == VIREO_OK);
    CHECK(copy.event_capacity == 64 && copy.max_memory_bytes == VIREO_EPOLL_MAX_MEMORY);
}

static void capacity_boundaries(void)
{
    size_t const values[] = {0, 1, VIREO_EPOLL_MAX_EVENTS, VIREO_EPOLL_MAX_EVENTS + 1};
    vireo_result_t const results[] = {VIREO_RESULT_INVALID_ARGUMENT, VIREO_OK,
                                     VIREO_OK, VIREO_RESULT_RANGE};
    size_t baseline = fd_count();
    for (size_t i = 0; i < 4; ++i) {
        vireo_epoll_t *owner = NULL;
        fixture_t f = {0};
        vireo_epoll_ops_t ops = make_ops(&f, &owner);
        vireo_epoll_options_t options = {values[i], VIREO_EPOLL_MAX_MEMORY};
        errno = EACCES;
        CHECK(vireo_epoll_create_with_ops(&options, &ops, &owner, NULL) == results[i]);
        if (results[i] == VIREO_OK) {
            vireo_epoll_info_t info;
            CHECK(vireo_epoll_inspect(owner, &info) == VIREO_OK);
            CHECK(info.event_capacity == values[i]);
            CHECK(info.events_bytes == values[i] * sizeof(struct epoll_event));
            CHECK(info.allocation_bytes == f.sizes[0] + f.sizes[1]);
            CHECK(vireo_epoll_destroy(&owner, NULL) == VIREO_OK);
            CHECK(f.close_calls == 1 && strcmp(f.order, "abecBA") == 0);
        } else {
            CHECK(owner == NULL && f.allocations == 0 && f.create_calls == 0);
        }
        CHECK(errno == EACCES && f.live == 0);
    }
    CHECK(fd_count() == baseline);
}

static void arithmetic_boundaries(void)
{
    /* 第一个输入乘法不可表示；第二个积可表示，但加控制块后越界。 */
    size_t const values[] = {SIZE_MAX, SIZE_MAX / sizeof(struct epoll_event)};
    for (size_t i = 0; i < 2; ++i) {
        vireo_epoll_t *owner = NULL;
        fixture_t f = {0};
        vireo_epoll_ops_t ops = make_ops(&f, &owner);
        vireo_epoll_options_t options = {values[i], 1};
        vireo_epoll_error_t error;
        errno = EACCES;
        CHECK(vireo_epoll_create_with_ops(&options, &ops, &owner, &error) == VIREO_RESULT_OVERFLOW);
        CHECK(owner == NULL && f.allocations == 0 && f.create_calls == 0);
        CHECK(error.stage == VIREO_EPOLL_STAGE_NONE && error.system_errno == 0 && errno == EACCES);
    }
}

static void budget_boundaries(void)
{
    vireo_epoll_t *owner = NULL;
    REQUIRE(vireo_epoll_create(&default_options, &owner, NULL) == VIREO_OK);
    vireo_epoll_info_t info;
    CHECK(vireo_epoll_inspect(owner, &info) == VIREO_OK);
    CHECK(vireo_epoll_destroy(&owner, NULL) == VIREO_OK);
    size_t const budgets[] = {0, 1, info.allocation_bytes - 1, info.allocation_bytes,
                              VIREO_EPOLL_MAX_MEMORY, VIREO_EPOLL_MAX_MEMORY + 1};
    vireo_result_t const results[] = {VIREO_RESULT_INVALID_ARGUMENT, VIREO_RESULT_RANGE,
        VIREO_RESULT_RANGE, VIREO_OK, VIREO_OK, VIREO_RESULT_RANGE};
    for (size_t i = 0; i < 6; ++i) {
        fixture_t f = {0};
        vireo_epoll_ops_t ops = make_ops(&f, &owner);
        vireo_epoll_options_t options = {64, budgets[i]};
        errno = EACCES;
        CHECK(vireo_epoll_create_with_ops(&options, &ops, &owner, NULL) == results[i]);
        if (results[i] == VIREO_OK) {
            CHECK(vireo_epoll_inspect(owner, &info) == VIREO_OK);
            CHECK(info.max_memory_bytes == budgets[i]);
            CHECK(info.allocation_bytes == f.sizes[0] + f.sizes[1]);
            CHECK(vireo_epoll_destroy(&owner, NULL) == VIREO_OK);
        } else {
            CHECK(owner == NULL && f.allocations == 0);
        }
        CHECK(f.live == 0 && errno == EACCES);
    }
}

static void allocation_failure(size_t fail_at, char const *order,
                               vireo_epoll_stage_t stage)
{
    vireo_epoll_t *owner = NULL;
    fixture_t f = {0};
    f.fail_allocation = fail_at;
    vireo_epoll_ops_t ops = make_ops(&f, &owner);
    vireo_epoll_error_t error;
    size_t baseline = fd_count();
    errno = EACCES;
    CHECK(vireo_epoll_create_with_ops(&default_options, &ops, &owner, &error) == VIREO_RESULT_NO_MEMORY);
    CHECK(owner == NULL && f.allocations == fail_at && f.releases == fail_at - 1);
    CHECK(f.create_calls == 0 && f.close_calls == 0 && f.live == 0);
    CHECK(strcmp(f.order, order) == 0 && error.stage == stage && error.system_errno == 0);
    CHECK(errno == EACCES && fd_count() == baseline);
}

static void control_failure(void)
{
    allocation_failure(1, "a", VIREO_EPOLL_STAGE_ALLOCATE_CONTROL);
}

static void events_failure(void)
{
    allocation_failure(2, "abA", VIREO_EPOLL_STAGE_ALLOCATE_EVENTS);
}

static void creation_failures(void)
{
    int const causes[] = {EMFILE, ENFILE, ENOMEM, EINVAL, EINTR};
    size_t baseline = fd_count();
    for (size_t i = 0; i < sizeof(causes) / sizeof(causes[0]); ++i) {
        vireo_epoll_t *owner = NULL;
        fixture_t f = {0};
        f.create_error = causes[i];
        vireo_epoll_ops_t ops = make_ops(&f, &owner);
        vireo_epoll_error_t error;
        errno = EACCES;
        CHECK(vireo_epoll_create_with_ops(&default_options, &ops, &owner, &error) == VIREO_RESULT_IO);
        CHECK(owner == NULL && f.allocations == 2 && f.releases == 2 && f.live == 0);
        CHECK(f.create_calls == 1 && f.close_calls == 0 && strcmp(f.order, "abeBA") == 0);
        CHECK(error.stage == VIREO_EPOLL_STAGE_CREATE && error.system_errno == causes[i]);
        CHECK(errno == EACCES);
    }
    CHECK(fd_count() == baseline);
}

static void cloexec_and_release(void)
{
    vireo_epoll_t *owner = NULL;
    fixture_t f = {0};
    vireo_epoll_ops_t ops = make_ops(&f, &owner);
    size_t baseline = fd_count();
    vireo_epoll_error_t error = {VIREO_EPOLL_STAGE_CLOSE, EIO};
    REQUIRE(vireo_epoll_create_with_ops(&default_options, &ops, &owner, &error) == VIREO_OK);
    REQUIRE(owner != NULL && f.fd >= 0);
    CHECK(error.stage == VIREO_EPOLL_STAGE_NONE && error.system_errno == 0);
    int flags = fcntl(f.fd, F_GETFD);
    CHECK(flags >= 0 && (flags & FD_CLOEXEC) != 0);
    CHECK(fd_count() == baseline + 1);
    int old_fd = f.fd;
    errno = EACCES;
    CHECK(vireo_epoll_destroy(&owner, &error) == VIREO_OK);
    CHECK(owner == NULL && f.live == 0 && f.close_calls == 1 && f.releases == 2);
    CHECK(errno == EACCES && error.stage == VIREO_EPOLL_STAGE_NONE);
    CHECK(fcntl(old_fd, F_GETFD) == -1 && errno == EBADF);
    CHECK(fd_count() == baseline);
}

static void options_and_ops_copy(void)
{
    vireo_epoll_t *owner = NULL;
    fixture_t f = {0};
    vireo_epoll_ops_t ops = make_ops(&f, &owner);
    vireo_epoll_options_t options = default_options;
    REQUIRE(vireo_epoll_create_with_ops(&options, &ops, &owner, NULL) == VIREO_OK);
    options.event_capacity = 1;
    options.max_memory_bytes = 1;
    ops = (vireo_epoll_ops_t){0}; /* 原始表可结束生命期，context仍保留到销毁。 */
    vireo_epoll_info_t info;
    CHECK(vireo_epoll_inspect(owner, &info) == VIREO_OK);
    CHECK(info.event_capacity == 64 && info.max_memory_bytes == VIREO_EPOLL_MAX_MEMORY);
    CHECK(vireo_epoll_destroy(&owner, NULL) == VIREO_OK);
    CHECK(f.live == 0 && f.close_calls == 1 && strcmp(f.order, "abecBA") == 0);
}

static void close_errors_and_reuse(void)
{
    int const causes[] = {EINTR, EIO, EBADF};
    size_t baseline = fd_count();
    for (size_t i = 0; i < 3; ++i) {
        vireo_epoll_t *owner = NULL;
        fixture_t f = {0};
        f.close_error = causes[i];
        vireo_epoll_ops_t ops = make_ops(&f, &owner);
        vireo_epoll_error_t error;
        REQUIRE(vireo_epoll_create_with_ops(&default_options, &ops, &owner, NULL) == VIREO_OK);
        int old_fd = f.fd;
        errno = EACCES;
        CHECK(vireo_epoll_destroy(&owner, &error) == VIREO_RESULT_IO);
        CHECK(owner == NULL && f.close_calls == 1 && f.live == 0 && f.releases == 2);
        CHECK(error.stage == VIREO_EPOLL_STAGE_CLOSE && error.system_errno == causes[i]);
        CHECK(errno == EACCES && strcmp(f.order, "abecBA") == 0);
        CHECK(f.replacement == old_fd && fcntl(f.replacement, F_GETFD) >= 0);
        errno = EACCES;
        CHECK(vireo_epoll_destroy(&owner, &error) == VIREO_OK);
        CHECK(error.stage == VIREO_EPOLL_STAGE_NONE && error.system_errno == 0);
        CHECK(f.close_calls == 1 && errno == EACCES);
        CHECK(fcntl(f.replacement, F_GETFD) >= 0); /* 重复 destroy 不触碰新资源。 */
        CHECK(close(f.replacement) == 0);
    }
    CHECK(fd_count() == baseline);
}

static void null_diagnostics(void)
{
    size_t baseline = fd_count();
    for (size_t i = 0; i < 4; ++i) {
        vireo_epoll_t *owner = NULL;
        fixture_t f = {0};
        if (i < 2) {
            f.fail_allocation = i + 1;
        } else if (i == 2) {
            f.create_error = EMFILE;
        } else {
            f.close_error = EINTR;
        }
        vireo_epoll_ops_t ops = make_ops(&f, &owner);
        errno = EACCES;
        vireo_result_t result = vireo_epoll_create_with_ops(&default_options, &ops, &owner, NULL);
        CHECK(result == (i < 2 ? VIREO_RESULT_NO_MEMORY : (i == 2 ? VIREO_RESULT_IO : VIREO_OK)));
        if (i == 3) {
            CHECK(vireo_epoll_destroy(&owner, NULL) == VIREO_RESULT_IO);
            CHECK(fcntl(f.replacement, F_GETFD) >= 0);
            CHECK(close(f.replacement) == 0);
        }
        CHECK(owner == NULL && f.live == 0);
        CHECK(errno == EACCES);
    }
    CHECK(fd_count() == baseline);
}

static void zero_fd(void)
{
    /* 只在独立子进程关闭stdin，不修改测试父进程的描述符或创建后对象。 */
    pid_t child = fork();
    REQUIRE(child >= 0);
    if (child == 0) {
        unsigned before = failures;
        (void)close(STDIN_FILENO);
        vireo_epoll_t *owner = NULL;
        fixture_t f = {0};
        vireo_epoll_ops_t ops = make_ops(&f, &owner);
        errno = EACCES;
        CHECK(vireo_epoll_create_with_ops(&default_options, &ops, &owner, NULL) == VIREO_OK);
        CHECK(f.fd == 0 && errno == EACCES);
        CHECK(vireo_epoll_destroy(&owner, NULL) == VIREO_OK);
        CHECK(owner == NULL && f.close_calls == 1 && f.live == 0 && errno == EACCES);
        _exit(failures == before ? 0 : 1);
    }
    int status = 0;
    CHECK(waitpid(child, &status, 0) == child);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void repeated_lifecycles(void)
{
    size_t baseline = fd_count();
    for (size_t i = 0; i < 128; ++i) {
        vireo_epoll_t *first = NULL;
        vireo_epoll_t *second = NULL;
        vireo_epoll_options_t options = {i + 1, VIREO_EPOLL_MAX_MEMORY};
        errno = EACCES;
        REQUIRE(vireo_epoll_create(&options, &first, NULL) == VIREO_OK);
        REQUIRE(vireo_epoll_create(&options, &second, NULL) == VIREO_OK);
        CHECK(first != second && errno == EACCES);
        CHECK(fd_count() == baseline + 2);
        errno = EACCES;
        CHECK(vireo_epoll_destroy(&first, NULL) == VIREO_OK);
        CHECK(vireo_epoll_inspect(second, &(vireo_epoll_info_t){0}) == VIREO_OK);
        CHECK(vireo_epoll_destroy(&second, NULL) == VIREO_OK);
        CHECK(first == NULL && second == NULL && errno == EACCES);
        CHECK(fd_count() == baseline);
    }
    puts("epoll lifecycle: 128 rounds, two independent production instances, fd baseline restored");
}

static void invalid_ops(void)
{
    vireo_epoll_t *owner = NULL;
    fixture_t f = {0};
    vireo_epoll_ops_t const valid = make_ops(&f, &owner);
    errno = EACCES;
    CHECK(vireo_epoll_create_with_ops(&default_options, NULL, &owner, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    for (size_t i = 0; i < 6; ++i) {
        vireo_epoll_ops_t ops = valid;
        if (i == 0) ops.allocate = NULL;
        if (i == 1) ops.deallocate = NULL;
        if (i == 2) ops.create = NULL;
        if (i == 3) ops.close = NULL;
        if (i == 4) ops.control = NULL;
        if (i == 5) ops.wait = NULL;
        CHECK(vireo_epoll_create_with_ops(&default_options, &ops, &owner, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
        CHECK(owner == NULL && f.allocations == 0 && f.create_calls == 0 && errno == EACCES);
    }
}

static void unrelated_fd_kept(void)
{
    int external = open("/dev/null", O_RDONLY | O_CLOEXEC);
    REQUIRE(external >= 0);
    vireo_epoll_t *owner = NULL;
    REQUIRE(vireo_epoll_create(&default_options, &owner, NULL) == VIREO_OK);
    CHECK(vireo_epoll_destroy(&owner, NULL) == VIREO_OK);
    CHECK(fcntl(external, F_GETFD) >= 0);
    CHECK(close(external) == 0);
}

int main(void)
{
    void (*const groups[])(void) = {
        public_arguments, inspect_contract, capacity_boundaries, arithmetic_boundaries,
        budget_boundaries, control_failure, events_failure, creation_failures,
        cloexec_and_release, options_and_ops_copy, close_errors_and_reuse, null_diagnostics,
        zero_fd, repeated_lifecycles, invalid_ops, unrelated_fd_kept
    };
    for (size_t i = 0; i < sizeof(groups) / sizeof(groups[0]); ++i) {
        groups[i]();
    }
    if (failures != 0) {
        fprintf(stderr, "test_epoll_lifecycle: %u failures\n", failures);
        return EXIT_FAILURE;
    }
    puts("test_epoll_lifecycle: all 16 test groups passed");
    return EXIT_SUCCESS;
}
