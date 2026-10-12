/*
 * PROJECT : VIREO
 * FILE    : test_notifier_lifecycle.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-13
 * BRIEF   : 真实 eventfd 资源与确定性配对故障核验，不冒通知协议验证
 */
#define _POSIX_C_SOURCE 200809L
#include "thread/notifier_internal.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition); return 1; \
} } while (0)
#define EXPECT(call, expected) do { errno = E2BIG; \
    vireo_result_t const actual_result = (call); \
    CHECK(actual_result == (expected)); CHECK(errno == E2BIG); \
} while (0)

/** 单实例测试账本，context 借到回滚或销毁，非生产指标。 */
typedef struct resource_trace {
    size_t allocation_calls; /**< allocate 实际调用数。 */
    size_t free_calls; /**< 配对释放实际调用数。 */
    size_t create_calls; /**< 构造 fd 回调调用数。 */
    size_t close_calls; /**< close 回调调用数，失败也只能一次。 */
    size_t requested_bytes; /**< 最后一次申请字节数。 */
    void *live; /**< 测试 allocator 仍拥有的唯一实际 malloc 块。 */
    bool fail_allocate; /**< 下一申请是否确定返回 NULL。 */
    bool bad_free; /**< 配对地址不符的粘性错误。 */
    bool bad_close; /**< 真实 close 失败的粘性错误，不等于模拟报告。 */
    int create_errno; /**< 非零则构造回报 -1/该 errno，不取得 fd。 */
    int close_errno; /**< 非零则先真实关闭后回报 -1/该 errno。 */
    int last_fd; /**< 最近取得的 fd 数值，不保活。 */
    int last_flags; /**< 最近构造标志，验证固定 NONBLOCK/CLOEXEC。 */
    unsigned int last_initval; /**< 最近初始计数输入，必须为 0。 */
} resource_trace_t;

/* 故意扰动 errno，外层必须保持入口值；NULL 为真实申请失败分支。 */
static void *trace_allocate(void *context, size_t size)
{
    resource_trace_t *trace = context;
    ++trace->allocation_calls;
    trace->requested_bytes = size;
    errno = EACCES;
    if (trace->fail_allocate) {
        return NULL;
    }
    trace->live = malloc(size);
    return trace->live;
}

/* 地址必须与实际申请配对；释放后的 errno 不能污染系统失败诊断。 */
static void trace_deallocate(void *context, void *memory)
{
    resource_trace_t *trace = context;
    ++trace->free_calls;
    if (trace->live != memory || memory == NULL) {
        trace->bad_free = true;
    } else {
        free(memory);
        trace->live = NULL;
    }
    errno = EIO;
}

/* 成功使用真实 eventfd，失败不取得 fd；并非真实系统配额耗尽。 */
static int trace_create(void *context, unsigned int initval, int flags)
{
    resource_trace_t *trace = context;
    ++trace->create_calls;
    trace->last_flags = flags;
    trace->last_initval = initval;
    if (trace->create_errno != 0) {
        errno = trace->create_errno;
        return -1;
    }
    trace->last_fd = eventfd(initval, flags);
    return trace->last_fd;
}

/* 实际释放 fd 后才模拟错误，核验 Linux 消费语义而不制造泄漏。 */
static int trace_close(void *context, int fd)
{
    resource_trace_t *trace = context;
    ++trace->close_calls;
    int const result = close(fd);
    if (result != 0) {
        trace->bad_close = true;
        return result;
    }
    if (trace->close_errno != 0) {
        errno = trace->close_errno;
        return -1;
    }
    return 0;
}

/* 首项故障表适配本核心新增原生 I/O；本测试不调用新公共入口。 */
static ssize_t trace_read(void *context, int fd, void *bytes, size_t size)
{
    (void)context;
    return read(fd, bytes, size);
}

static ssize_t trace_write(void *context, int fd, void const *bytes, size_t size)
{
    (void)context;
    return write(fd, bytes, size);
}

static vireo_notifier_ops_t trace_ops(resource_trace_t *trace)
{
    return (vireo_notifier_ops_t){trace, trace_allocate, trace_deallocate,
        trace_create, trace_close, trace_read, trace_write};
}

/* 同一进程资源数量，计入本次目录句柄；前后同口径比较。 */
static size_t fd_count(void)
{
    DIR *directory = opendir("/proc/self/fd");
    if (directory == NULL) {
        return SIZE_MAX;
    }
    size_t count = 0;
    errno = 0;
    struct dirent *entry = NULL;
    while ((entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
            ++count;
        }
    }
    int const cause = errno;
    int const close_result = closedir(directory);
    return cause == 0 && close_result == 0 ? count : SIZE_MAX;
}

static int real_resource_properties(void)
{
    vireo_notifier_options_t const options = {4096};
    vireo_notifier_t *owner = NULL;
    vireo_notifier_error_t error = {VIREO_NOTIFIER_STAGE_CLOSE, EIO};
    EXPECT(vireo_notifier_create(&options, &owner, &error), VIREO_OK);
    CHECK(owner != NULL && error.stage == VIREO_NOTIFIER_STAGE_NONE && error.system_errno == 0);
    vireo_notifier_info_t info = {0};
    EXPECT(vireo_notifier_inspect(owner, &info), VIREO_OK);
    CHECK(info.fd >= 0 && info.allocated_bytes > 0 && info.allocated_bytes <= 4096);
    CHECK(info.max_memory_bytes == 4096);
    int const status_flags = fcntl(info.fd, F_GETFL);
    int const descriptor_flags = fcntl(info.fd, F_GETFD);
    CHECK(status_flags >= 0 && (status_flags & O_NONBLOCK) != 0);
    CHECK(descriptor_flags >= 0 && (descriptor_flags & FD_CLOEXEC) != 0);
    /* 仅测试内核 oracle：空计数非阻塞读失败；不是公开消费入口。 */
    uint64_t counter = UINT64_MAX;
    CHECK(read(info.fd, &counter, sizeof(counter)) == -1 && errno == EAGAIN);
    CHECK(counter == UINT64_MAX);
    EXPECT(vireo_notifier_destroy(&owner, &error), VIREO_OK);
    CHECK(owner == NULL && error.stage == VIREO_NOTIFIER_STAGE_NONE && error.system_errno == 0);
    CHECK(fcntl(info.fd, F_GETFD) == -1 && errno == EBADF);
    EXPECT(vireo_notifier_destroy(&owner, &error), VIREO_OK);
    return 0;
}

static int independent_values(void)
{
    vireo_notifier_options_t options = {4096};
    unsigned char original[sizeof(options)];
    memcpy(original, &options, sizeof(options));
    vireo_notifier_t *owner = NULL;
    EXPECT(vireo_notifier_create(&options, &owner, NULL), VIREO_OK);
    CHECK(memcmp(&options, original, sizeof(options)) == 0);
    options.max_memory_bytes = 1;
    vireo_notifier_info_t first = {0};
    EXPECT(vireo_notifier_inspect(owner, &first), VIREO_OK);
    vireo_notifier_info_t second = {-1, 0, 0};
    EXPECT(vireo_notifier_inspect(owner, &second), VIREO_OK);
    CHECK(first.fd == second.fd && first.allocated_bytes == second.allocated_bytes);
    CHECK(second.max_memory_bytes == 4096);
    second = (vireo_notifier_info_t){-1, 1, 2};
    EXPECT(vireo_notifier_inspect(owner, &second), VIREO_OK);
    CHECK(second.fd == first.fd && second.max_memory_bytes == first.max_memory_bytes);
    EXPECT(vireo_notifier_destroy(&owner, NULL), VIREO_OK);
    CHECK(first.fd == second.fd && first.allocated_bytes == second.allocated_bytes);
    return 0;
}

static int invalid_parameters(void)
{
    vireo_notifier_options_t options = {4096};
    vireo_notifier_t *owner = NULL;
    vireo_notifier_error_t error = {VIREO_NOTIFIER_STAGE_CLOSE, EIO};
    EXPECT(vireo_notifier_create(NULL, &owner, &error), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(owner == NULL && error.stage == VIREO_NOTIFIER_STAGE_NONE && error.system_errno == 0);
    EXPECT(vireo_notifier_create(&options, NULL, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    options.max_memory_bytes = 0;
    EXPECT(vireo_notifier_create(&options, &owner, &error), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(owner == NULL);
    EXPECT(vireo_notifier_destroy(NULL, &error), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(error.stage == VIREO_NOTIFIER_STAGE_NONE && error.system_errno == 0);
    EXPECT(vireo_notifier_destroy(NULL, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    vireo_notifier_info_t info;
    memset(&info, 0xa5, sizeof(info));
    unsigned char original[sizeof(info)];
    memcpy(original, &info, sizeof(info));
    EXPECT(vireo_notifier_inspect(NULL, &info), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(memcmp(original, &info, sizeof(info)) == 0);
    EXPECT(vireo_notifier_inspect(NULL, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    options.max_memory_bytes = 4096;
    EXPECT(vireo_notifier_create(&options, &owner, &error), VIREO_OK);
    vireo_notifier_t *original_owner = owner;
    EXPECT(vireo_notifier_create(&options, &owner, &error), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(owner == original_owner && error.stage == VIREO_NOTIFIER_STAGE_NONE && error.system_errno == 0);
    EXPECT(vireo_notifier_inspect(owner, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_notifier_destroy(&owner, &error), VIREO_OK);
    return 0;
}

static int budget_boundaries(void)
{
    vireo_notifier_options_t options = {VIREO_NOTIFIER_MAX_ALLOCATION_BYTES};
    vireo_notifier_t *owner = NULL;
    EXPECT(vireo_notifier_create(&options, &owner, NULL), VIREO_OK);
    vireo_notifier_info_t info = {0};
    EXPECT(vireo_notifier_inspect(owner, &info), VIREO_OK);
    size_t const exact = info.allocated_bytes;
    CHECK(exact > 1 && exact <= VIREO_NOTIFIER_MAX_ALLOCATION_BYTES);
    EXPECT(vireo_notifier_destroy(&owner, NULL), VIREO_OK);
    options.max_memory_bytes = exact;
    EXPECT(vireo_notifier_create(&options, &owner, NULL), VIREO_OK);
    EXPECT(vireo_notifier_destroy(&owner, NULL), VIREO_OK);
    size_t const denied[] = {1, exact - 1, VIREO_NOTIFIER_MAX_ALLOCATION_BYTES + 1, SIZE_MAX};
    resource_trace_t trace = {0};
    vireo_notifier_ops_t const ops = trace_ops(&trace);
    for (size_t i = 0; i < sizeof(denied) / sizeof(denied[0]); ++i) {
        options.max_memory_bytes = denied[i];
        vireo_notifier_error_t error = {VIREO_NOTIFIER_STAGE_CREATE, EIO};
        EXPECT(vireo_notifier_create_with_ops(&options, &ops, &owner, &error), VIREO_RESULT_RANGE);
        CHECK(owner == NULL && trace.allocation_calls == 0 && trace.create_calls == 0);
        CHECK(error.stage == VIREO_NOTIFIER_STAGE_NONE && error.system_errno == 0);
    }
    return 0;
}

static int allocation_failure(void)
{
    resource_trace_t trace = {0};
    trace.fail_allocate = true;
    vireo_notifier_ops_t const ops = trace_ops(&trace);
    vireo_notifier_options_t const options = {4096};
    vireo_notifier_t *owner = NULL;
    vireo_notifier_error_t error = {0};
    EXPECT(vireo_notifier_create_with_ops(&options, &ops, &owner, &error), VIREO_RESULT_NO_MEMORY);
    CHECK(owner == NULL && trace.allocation_calls == 1 && trace.requested_bytes > 0);
    CHECK(trace.live == NULL && trace.create_calls == 0 && trace.free_calls == 0 && trace.close_calls == 0);
    CHECK(error.stage == VIREO_NOTIFIER_STAGE_ALLOCATE_CONTROL && error.system_errno == 0);
    return 0;
}

static int creation_failures(void)
{
    int const causes[] = {EMFILE, ENFILE, ENODEV, ENOMEM, EINVAL, EINTR};
    size_t const before = fd_count();
    CHECK(before != SIZE_MAX);
    for (size_t i = 0; i < sizeof(causes) / sizeof(causes[0]); ++i) {
        resource_trace_t trace = {0};
        trace.create_errno = causes[i];
        vireo_notifier_ops_t const ops = trace_ops(&trace);
        vireo_notifier_options_t const options = {4096};
        vireo_notifier_t *owner = NULL;
        vireo_notifier_error_t error = {0};
        EXPECT(vireo_notifier_create_with_ops(&options, &ops, &owner, &error), VIREO_RESULT_IO);
        CHECK(owner == NULL && trace.live == NULL && !trace.bad_free);
        CHECK(trace.allocation_calls == 1 && trace.create_calls == 1 && trace.free_calls == 1);
        CHECK(trace.close_calls == 0 && trace.last_initval == 0);
        CHECK(trace.last_flags == (EFD_NONBLOCK | EFD_CLOEXEC));
        CHECK(error.stage == VIREO_NOTIFIER_STAGE_CREATE && error.system_errno == causes[i]);
    }
    CHECK(fd_count() == before);
    return 0;
}

static int close_failure_consumption(void)
{
    int const causes[] = {EINTR, EIO, ENOSPC};
    size_t const before = fd_count();
    CHECK(before != SIZE_MAX);
    for (size_t i = 0; i < sizeof(causes) / sizeof(causes[0]); ++i) {
        resource_trace_t trace = {0};
        trace.close_errno = causes[i];
        vireo_notifier_ops_t const ops = trace_ops(&trace);
        vireo_notifier_options_t const options = {4096};
        vireo_notifier_t *owner = NULL;
        vireo_notifier_error_t error = {0};
        EXPECT(vireo_notifier_create_with_ops(&options, &ops, &owner, &error), VIREO_OK);
        int const fd = trace.last_fd;
        EXPECT(vireo_notifier_destroy(&owner, &error), VIREO_RESULT_IO);
        CHECK(owner == NULL && trace.live == NULL && !trace.bad_free && !trace.bad_close);
        CHECK(trace.close_calls == 1 && trace.free_calls == 1);
        CHECK(error.stage == VIREO_NOTIFIER_STAGE_CLOSE && error.system_errno == causes[i]);
        CHECK(fcntl(fd, F_GETFD) == -1 && errno == EBADF);
        EXPECT(vireo_notifier_destroy(&owner, &error), VIREO_OK);
        CHECK(trace.close_calls == 1 && trace.free_calls == 1);
        CHECK(error.stage == VIREO_NOTIFIER_STAGE_NONE && error.system_errno == 0);
    }
    CHECK(fd_count() == before);
    return 0;
}

static int null_diagnostics(void)
{
    resource_trace_t trace = {0};
    vireo_notifier_ops_t const ops = trace_ops(&trace);
    vireo_notifier_options_t const options = {4096};
    vireo_notifier_t *owner = NULL;
    trace.fail_allocate = true;
    EXPECT(vireo_notifier_create_with_ops(&options, &ops, &owner, NULL), VIREO_RESULT_NO_MEMORY);
    trace.fail_allocate = false;
    trace.create_errno = EMFILE;
    EXPECT(vireo_notifier_create_with_ops(&options, &ops, &owner, NULL), VIREO_RESULT_IO);
    trace.create_errno = 0;
    trace.close_errno = EINTR;
    EXPECT(vireo_notifier_create_with_ops(&options, &ops, &owner, NULL), VIREO_OK);
    EXPECT(vireo_notifier_destroy(&owner, NULL), VIREO_RESULT_IO);
    CHECK(owner == NULL && trace.live == NULL && trace.close_calls == 1 && trace.free_calls == 2);
    CHECK(!trace.bad_free && !trace.bad_close);
    return 0;
}

static int operation_table_validation(void)
{
    resource_trace_t trace = {0};
    vireo_notifier_ops_t const valid = trace_ops(&trace);
    vireo_notifier_options_t const options = {4096};
    vireo_notifier_t *owner = NULL;
    vireo_notifier_error_t error = {VIREO_NOTIFIER_STAGE_CLOSE, EIO};
    EXPECT(vireo_notifier_create_with_ops(&options, NULL, &owner, &error), VIREO_RESULT_INVALID_ARGUMENT);
    for (size_t i = 0; i < 6; ++i) {
        vireo_notifier_ops_t invalid = valid;
        if (i == 0) { invalid.allocate = NULL; }
        if (i == 1) { invalid.deallocate = NULL; }
        if (i == 2) { invalid.create = NULL; }
        if (i == 3) { invalid.close = NULL; }
        if (i == 4) { invalid.read = NULL; }
        if (i == 5) { invalid.write = NULL; }
        EXPECT(vireo_notifier_create_with_ops(&options, &invalid, &owner, &error), VIREO_RESULT_INVALID_ARGUMENT);
        CHECK(owner == NULL && error.stage == VIREO_NOTIFIER_STAGE_NONE && error.system_errno == 0);
    }
    CHECK(trace.allocation_calls == 0 && trace.create_calls == 0);
    return 0;
}

static int operation_table_copy(void)
{
    resource_trace_t trace = {0};
    vireo_notifier_ops_t ops = trace_ops(&trace);
    vireo_notifier_options_t const options = {4096};
    vireo_notifier_t *owner = NULL;
    EXPECT(vireo_notifier_create_with_ops(&options, &ops, &owner, NULL), VIREO_OK);
    CHECK(trace.last_initval == 0 && trace.last_flags == (EFD_NONBLOCK | EFD_CLOEXEC));
    ops = (vireo_notifier_ops_t){0};
    EXPECT(vireo_notifier_destroy(&owner, NULL), VIREO_OK);
    CHECK(trace.close_calls == 1 && trace.free_calls == 1 && trace.live == NULL);
    CHECK(!trace.bad_free && !trace.bad_close && ops.context == NULL);
    return 0;
}

static int repeated_resources(void)
{
    size_t const before = fd_count();
    CHECK(before != SIZE_MAX);
    vireo_notifier_options_t const options = {4096};
    for (size_t i = 0; i < 64; ++i) {
        vireo_notifier_t *first = NULL;
        vireo_notifier_t *second = NULL;
        EXPECT(vireo_notifier_create(&options, &first, NULL), VIREO_OK);
        EXPECT(vireo_notifier_create(&options, &second, NULL), VIREO_OK);
        vireo_notifier_info_t a = {0};
        vireo_notifier_info_t b = {0};
        EXPECT(vireo_notifier_inspect(first, &a), VIREO_OK);
        EXPECT(vireo_notifier_inspect(second, &b), VIREO_OK);
        CHECK(a.fd != b.fd && first != second && fd_count() == before + 2);
        EXPECT(vireo_notifier_destroy(&first, NULL), VIREO_OK);
        CHECK(fcntl(b.fd, F_GETFD) >= 0);
        EXPECT(vireo_notifier_destroy(&second, NULL), VIREO_OK);
        CHECK(fd_count() == before);
    }
    return 0;
}

/* 只在单线程 fork 子进程关闭 stdin，父进程用户标准输入不改变。 */
static int child_fd_zero(void)
{
    (void)close(STDIN_FILENO);
    vireo_notifier_options_t const options = {4096};
    vireo_notifier_t *owner = NULL;
    EXPECT(vireo_notifier_create(&options, &owner, NULL), VIREO_OK);
    vireo_notifier_info_t info = {-1, 0, 0};
    EXPECT(vireo_notifier_inspect(owner, &info), VIREO_OK);
    CHECK(info.fd == STDIN_FILENO);
    EXPECT(vireo_notifier_destroy(&owner, NULL), VIREO_OK);
    CHECK(owner == NULL && fcntl(STDIN_FILENO, F_GETFD) == -1 && errno == EBADF);
    return 0;
}

static int fd_zero(void)
{
    pid_t const child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        /* fork 后新创建自己的对象，不复用继承的 notifier；_exit 不跑子进程 LSan。 */
        _exit(child_fd_zero());
    }
    int status = 0;
    CHECK(waitpid(child, &status, 0) == child);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    return 0;
}

int main(void)
{
    int previous_cancel_state = 0;
    CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previous_cancel_state) == 0);
    int (*const tests[])(void) = {real_resource_properties, independent_values,
        invalid_parameters, budget_boundaries, allocation_failure, creation_failures,
        close_failure_consumption, null_diagnostics, operation_table_validation,
        operation_table_copy, repeated_resources, fd_zero};
    for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); ++i) {
        CHECK(tests[i]() == 0);
    }
    CHECK(pthread_setcancelstate(previous_cancel_state, NULL) == 0);
    puts("notifier lifecycle: 12 groups passed");
    return 0;
}
