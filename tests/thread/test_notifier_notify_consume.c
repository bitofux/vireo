/*
 * PROJECT : VIREO
 * FILE    : test_notifier_notify_consume.c
 * AUTHOR  : bitofux
 * DATE    : 2026-10-13
 * BRIEF   : 真实合并/饱和/MPSC 与一次 I/O 故障保持，未接 queue 或网络
 */
#define _POSIX_C_SOURCE 200809L
#include "thread/notifier_internal.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdbool.h>
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

/** 单线程故障表账本；并发组使用默认操作，不共享本表。 */
typedef struct io_trace {
    int fd; /**< 本表取得的真实 fd，销毁后数值不保活。 */
    size_t read_calls; /**< 一次 consume 的原生回调调用数。 */
    size_t write_calls; /**< 一次 notify 的原生回调调用数。 */
    bool inject_read; /**< 是否用指定返回替代 read 结果。 */
    bool inject_write; /**< 是否用指定返回替代 write 结果。 */
    ssize_t read_return; /**< 注入原生字节数或负返回。 */
    ssize_t write_return; /**< 注入原生字节数或负返回。 */
    int read_errno; /**< 注入读取原因，不代表真实系统故障。 */
    int write_errno; /**< 注入写入原因，不代表真实系统故障。 */
    uint64_t read_value; /**< 未执行真实读取时写入候选的注入值。 */
    uint64_t last_write; /**< 保存固定通知输入，须为 1。 */
    bool actual_read; /**< 注入前先执行一次真实 read，核验不可回滚消费。 */
    bool actual_write; /**< 注入前先执行一次真实 write，核验不可回滚增量。 */
    bool bad_parameters; /**< fd/size/initval/flags 不符合约定的粘性记录。 */
} io_trace_t;

static void *io_allocate(void *context, size_t size)
{
    (void)context;
    return malloc(size);
}

static void io_deallocate(void *context, void *memory)
{
    (void)context;
    free(memory);
}

static int io_create(void *context, unsigned int initval, int flags)
{
    io_trace_t *trace = context;
    if (initval != 0 || flags != (EFD_NONBLOCK | EFD_CLOEXEC)) {
        trace->bad_parameters = true;
    }
    trace->fd = eventfd(initval, flags);
    return trace->fd;
}

static int io_close(void *context, int fd)
{
    io_trace_t *trace = context;
    if (fd != trace->fd) {
        trace->bad_parameters = true;
    }
    return close(fd);
}

/* 即使注入异常长度，也只写候选的八字节；不会按伪返回越界。 */
static ssize_t io_read(void *context, int fd, void *bytes, size_t size)
{
    io_trace_t *trace = context;
    ++trace->read_calls;
    if (fd != trace->fd || size != sizeof(uint64_t)) {
        trace->bad_parameters = true;
        errno = EINVAL;
        return -1;
    }
    if (!trace->inject_read) {
        return read(fd, bytes, size);
    }
    if (trace->actual_read) {
        ssize_t const native_result = read(fd, bytes, size);
        if (native_result != (ssize_t)size) {
            trace->bad_parameters = true;
        }
    } else {
        memcpy(bytes, &trace->read_value, sizeof(trace->read_value));
    }
    errno = trace->read_errno;
    return trace->read_return;
}

/* 固定输入先按值保存，实际进度组才先执行一次 write，不内部重试。 */
static ssize_t io_write(void *context, int fd, void const *bytes, size_t size)
{
    io_trace_t *trace = context;
    ++trace->write_calls;
    if (fd != trace->fd || size != sizeof(uint64_t)) {
        trace->bad_parameters = true;
        errno = EINVAL;
        return -1;
    }
    memcpy(&trace->last_write, bytes, sizeof(trace->last_write));
    if (!trace->inject_write) {
        return write(fd, bytes, size);
    }
    if (trace->actual_write) {
        ssize_t const native_result = write(fd, bytes, size);
        if (native_result != (ssize_t)size) {
            trace->bad_parameters = true;
        }
    }
    errno = trace->write_errno;
    return trace->write_return;
}

static vireo_notifier_ops_t io_ops(io_trace_t *trace)
{
    return (vireo_notifier_ops_t){trace, io_allocate, io_deallocate, io_create, io_close,
        io_read, io_write};
}

static int real_merge_empty(void)
{
    vireo_notifier_options_t const options = {4096};
    vireo_notifier_t *owner = NULL;
    EXPECT(vireo_notifier_create(&options, &owner, NULL), VIREO_OK);
    uint64_t count = UINT64_MAX;
    vireo_notifier_error_t error = {VIREO_NOTIFIER_STAGE_CLOSE, EIO};
    EXPECT(vireo_notifier_consume(owner, &count, &error), VIREO_OK);
    CHECK(count == 0 && error.stage == VIREO_NOTIFIER_STAGE_NONE && error.system_errno == 0);
    for (size_t i = 0; i < 37; ++i) {
        vireo_notifier_notify_outcome_t outcome = VIREO_NOTIFIER_NOTIFY_ALREADY_PENDING;
        EXPECT(vireo_notifier_notify(owner, &outcome, &error), VIREO_OK);
        CHECK(outcome == VIREO_NOTIFIER_NOTIFY_INCREMENTED);
        CHECK(error.stage == VIREO_NOTIFIER_STAGE_NONE && error.system_errno == 0);
    }
    EXPECT(vireo_notifier_consume(owner, &count, &error), VIREO_OK);
    CHECK(count == 37);
    EXPECT(vireo_notifier_consume(owner, &count, NULL), VIREO_OK);
    CHECK(count == 0);
    EXPECT(vireo_notifier_destroy(&owner, NULL), VIREO_OK);
    return 0;
}

static int real_saturation(void)
{
    io_trace_t trace = {0};
    vireo_notifier_ops_t const ops = io_ops(&trace);
    vireo_notifier_options_t const options = {4096};
    vireo_notifier_t *owner = NULL;
    EXPECT(vireo_notifier_create_with_ops(&options, &ops, &owner, NULL), VIREO_OK);
    /* 本核心 private oracle 设置真实边界；公共 notify 没有任意加数入口。 */
    uint64_t const seed = UINT64_MAX - 2;
    CHECK(write(trace.fd, &seed, sizeof(seed)) == (ssize_t)sizeof(seed));
    vireo_notifier_notify_outcome_t outcome = VIREO_NOTIFIER_NOTIFY_ALREADY_PENDING;
    EXPECT(vireo_notifier_notify(owner, &outcome, NULL), VIREO_OK);
    CHECK(outcome == VIREO_NOTIFIER_NOTIFY_INCREMENTED);
    vireo_notifier_error_t error = {VIREO_NOTIFIER_STAGE_NOTIFY, EIO};
    EXPECT(vireo_notifier_notify(owner, &outcome, &error), VIREO_OK);
    CHECK(outcome == VIREO_NOTIFIER_NOTIFY_ALREADY_PENDING);
    CHECK(error.stage == VIREO_NOTIFIER_STAGE_NONE && error.system_errno == 0);
    CHECK(trace.write_calls == 2 && trace.last_write == 1);
    struct pollfd ready = {trace.fd, POLLIN | POLLOUT, 0};
    CHECK(poll(&ready, 1, 0) == 1);
    CHECK((ready.revents & POLLIN) != 0 && (ready.revents & POLLOUT) == 0);
    uint64_t count = 0;
    EXPECT(vireo_notifier_consume(owner, &count, NULL), VIREO_OK);
    CHECK(count == UINT64_MAX - 1);
    EXPECT(vireo_notifier_consume(owner, &count, NULL), VIREO_OK);
    CHECK(count == 0);
    EXPECT(vireo_notifier_notify(owner, &outcome, NULL), VIREO_OK);
    CHECK(outcome == VIREO_NOTIFIER_NOTIFY_INCREMENTED);
    EXPECT(vireo_notifier_consume(owner, &count, NULL), VIREO_OK);
    CHECK(count == 1 && !trace.bad_parameters);
    EXPECT(vireo_notifier_destroy(&owner, NULL), VIREO_OK);
    return 0;
}

static int invalid_parameters(void)
{
    io_trace_t trace = {0};
    vireo_notifier_ops_t const ops = io_ops(&trace);
    vireo_notifier_options_t const options = {4096};
    vireo_notifier_t *owner = NULL;
    EXPECT(vireo_notifier_create_with_ops(&options, &ops, &owner, NULL), VIREO_OK);
    vireo_notifier_notify_outcome_t outcome = (vireo_notifier_notify_outcome_t)77;
    unsigned char original[sizeof(outcome)];
    memcpy(original, &outcome, sizeof(outcome));
    uint64_t count = UINT64_C(0xfefdfcfbfaf9f8f7);
    vireo_notifier_error_t error = {VIREO_NOTIFIER_STAGE_NOTIFY, EIO};
    EXPECT(vireo_notifier_notify(NULL, &outcome, &error), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(memcmp(original, &outcome, sizeof(outcome)) == 0);
    CHECK(error.stage == VIREO_NOTIFIER_STAGE_NONE && error.system_errno == 0);
    EXPECT(vireo_notifier_notify(owner, NULL, &error), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_notifier_notify(NULL, NULL, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_notifier_consume(NULL, &count, &error), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(count == UINT64_C(0xfefdfcfbfaf9f8f7));
    EXPECT(vireo_notifier_consume(owner, NULL, &error), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_notifier_consume(NULL, NULL, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(trace.read_calls == 0 && trace.write_calls == 0 && !trace.bad_parameters);
    EXPECT(vireo_notifier_destroy(&owner, NULL), VIREO_OK);
    return 0;
}

static int io_errors_once(void)
{
    int const causes[] = {EINTR, EIO, EBADF, EINVAL, EFAULT};
    io_trace_t trace = {0};
    trace.inject_read = true;
    trace.inject_write = true;
    trace.read_return = -1;
    trace.write_return = -1;
    vireo_notifier_ops_t const ops = io_ops(&trace);
    vireo_notifier_options_t const options = {4096};
    vireo_notifier_t *owner = NULL;
    EXPECT(vireo_notifier_create_with_ops(&options, &ops, &owner, NULL), VIREO_OK);
    for (size_t i = 0; i < sizeof(causes) / sizeof(causes[0]); ++i) {
        trace.read_errno = causes[i];
        trace.write_errno = causes[i];
        vireo_notifier_notify_outcome_t outcome = (vireo_notifier_notify_outcome_t)77;
        uint64_t count = UINT64_MAX;
        vireo_notifier_error_t error = {0};
        EXPECT(vireo_notifier_notify(owner, &outcome, &error), VIREO_RESULT_IO);
        CHECK(outcome == (vireo_notifier_notify_outcome_t)77);
        CHECK(error.stage == VIREO_NOTIFIER_STAGE_NOTIFY && error.system_errno == causes[i]);
        EXPECT(vireo_notifier_consume(owner, &count, &error), VIREO_RESULT_IO);
        CHECK(count == UINT64_MAX && error.stage == VIREO_NOTIFIER_STAGE_CONSUME);
        CHECK(error.system_errno == causes[i] && trace.read_calls == i + 1 && trace.write_calls == i + 1);
    }
    CHECK(trace.last_write == 1 && !trace.bad_parameters);
    EXPECT(vireo_notifier_destroy(&owner, NULL), VIREO_OK);
    return 0;
}

static int abnormal_returns(void)
{
    ssize_t const returns[] = {-2, 0, 1, 7, 9};
    io_trace_t trace = {0};
    trace.inject_read = true;
    trace.inject_write = true;
    trace.read_value = 23;
    trace.read_errno = EIO;
    trace.write_errno = EIO;
    vireo_notifier_ops_t const ops = io_ops(&trace);
    vireo_notifier_options_t const options = {4096};
    vireo_notifier_t *owner = NULL;
    EXPECT(vireo_notifier_create_with_ops(&options, &ops, &owner, NULL), VIREO_OK);
    for (size_t i = 0; i < sizeof(returns) / sizeof(returns[0]); ++i) {
        trace.read_return = returns[i];
        trace.write_return = returns[i];
        vireo_notifier_notify_outcome_t outcome = (vireo_notifier_notify_outcome_t)77;
        unsigned char original[sizeof(outcome)];
        memcpy(original, &outcome, sizeof(outcome));
        uint64_t count = UINT64_MAX;
        vireo_notifier_error_t error = {0};
        EXPECT(vireo_notifier_notify(owner, &outcome, &error), VIREO_RESULT_INTERNAL);
        CHECK(memcmp(original, &outcome, sizeof(outcome)) == 0);
        CHECK(error.stage == VIREO_NOTIFIER_STAGE_NOTIFY && error.system_errno == 0);
        EXPECT(vireo_notifier_consume(owner, &count, &error), VIREO_RESULT_INTERNAL);
        CHECK(count == UINT64_MAX && error.stage == VIREO_NOTIFIER_STAGE_CONSUME && error.system_errno == 0);
        CHECK(trace.read_calls == i + 1 && trace.write_calls == i + 1);
    }
    CHECK(!trace.bad_parameters);
    EXPECT(vireo_notifier_destroy(&owner, NULL), VIREO_OK);
    return 0;
}

static int raw_read_values(void)
{
    io_trace_t trace = {0};
    trace.inject_read = true;
    trace.read_return = 8;
    vireo_notifier_ops_t const ops = io_ops(&trace);
    vireo_notifier_options_t const options = {4096};
    vireo_notifier_t *owner = NULL;
    EXPECT(vireo_notifier_create_with_ops(&options, &ops, &owner, NULL), VIREO_OK);
    uint64_t const values[] = {1, 37, UINT64_MAX - 1, UINT64_MAX};
    for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); ++i) {
        trace.read_value = values[i];
        uint64_t count = 0;
        EXPECT(vireo_notifier_consume(owner, &count, NULL), VIREO_OK);
        CHECK(count == values[i]); /* MAX 仅保留原值，不冒真实内核 AIO 溢出。 */
    }
    trace.read_value = 0;
    uint64_t count = 91;
    vireo_notifier_error_t error = {0};
    EXPECT(vireo_notifier_consume(owner, &count, &error), VIREO_RESULT_INTERNAL);
    CHECK(count == 91 && error.stage == VIREO_NOTIFIER_STAGE_CONSUME && error.system_errno == 0);
    CHECK(trace.read_calls == 5 && !trace.bad_parameters);
    EXPECT(vireo_notifier_destroy(&owner, NULL), VIREO_OK);
    return 0;
}

static int eagain_and_null_diagnostics(void)
{
    io_trace_t trace = {0};
    trace.inject_read = true;
    trace.inject_write = true;
    trace.read_return = -1;
    trace.write_return = -1;
    trace.read_errno = EAGAIN;
    trace.write_errno = EAGAIN;
    vireo_notifier_ops_t const ops = io_ops(&trace);
    vireo_notifier_options_t const options = {4096};
    vireo_notifier_t *owner = NULL;
    EXPECT(vireo_notifier_create_with_ops(&options, &ops, &owner, NULL), VIREO_OK);
    vireo_notifier_notify_outcome_t outcome = VIREO_NOTIFIER_NOTIFY_INCREMENTED;
    uint64_t count = UINT64_MAX;
    vireo_notifier_error_t error = {VIREO_NOTIFIER_STAGE_CLOSE, EIO};
    EXPECT(vireo_notifier_notify(owner, &outcome, &error), VIREO_OK);
    CHECK(outcome == VIREO_NOTIFIER_NOTIFY_ALREADY_PENDING && error.stage == VIREO_NOTIFIER_STAGE_NONE);
    EXPECT(vireo_notifier_consume(owner, &count, &error), VIREO_OK);
    CHECK(count == 0 && error.stage == VIREO_NOTIFIER_STAGE_NONE && error.system_errno == 0);
    trace.write_errno = EINTR;
    trace.read_errno = EINTR;
    EXPECT(vireo_notifier_notify(owner, &outcome, NULL), VIREO_RESULT_IO);
    EXPECT(vireo_notifier_consume(owner, &count, NULL), VIREO_RESULT_IO);
    CHECK(outcome == VIREO_NOTIFIER_NOTIFY_ALREADY_PENDING && count == 0);
    CHECK(trace.read_calls == 2 && trace.write_calls == 2 && !trace.bad_parameters);
    EXPECT(vireo_notifier_destroy(&owner, NULL), VIREO_OK);
    return 0;
}

static int actual_progress_not_rolled_back(void)
{
    io_trace_t trace = {0};
    vireo_notifier_ops_t const ops = io_ops(&trace);
    vireo_notifier_options_t const options = {4096};
    vireo_notifier_t *owner = NULL;
    EXPECT(vireo_notifier_create_with_ops(&options, &ops, &owner, NULL), VIREO_OK);
    trace.inject_write = true;
    trace.actual_write = true;
    trace.write_return = 7;
    vireo_notifier_notify_outcome_t outcome = (vireo_notifier_notify_outcome_t)77;
    EXPECT(vireo_notifier_notify(owner, &outcome, NULL), VIREO_RESULT_INTERNAL);
    CHECK(outcome == (vireo_notifier_notify_outcome_t)77 && trace.write_calls == 1);
    uint64_t count = 0;
    EXPECT(vireo_notifier_consume(owner, &count, NULL), VIREO_OK);
    CHECK(count == 1); /* 外层失败不能撤销已经发生的内核增量。 */
    trace.inject_write = false;
    EXPECT(vireo_notifier_notify(owner, &outcome, NULL), VIREO_OK);
    trace.inject_read = true;
    trace.actual_read = true;
    trace.read_return = 7;
    count = 91;
    EXPECT(vireo_notifier_consume(owner, &count, NULL), VIREO_RESULT_INTERNAL);
    CHECK(count == 91);
    trace.inject_read = false;
    EXPECT(vireo_notifier_consume(owner, &count, NULL), VIREO_OK);
    CHECK(count == 0 && !trace.bad_parameters); /* 已消费的提示不自动放回。 */
    EXPECT(vireo_notifier_destroy(&owner, NULL), VIREO_OK);
    return 0;
}

static int fd_zero(void)
{
    pid_t const child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        (void)close(STDIN_FILENO);
        vireo_notifier_options_t const options = {4096};
        vireo_notifier_t *owner = NULL;
        if (vireo_notifier_create(&options, &owner, NULL) != VIREO_OK) { _exit(1); }
        vireo_notifier_info_t info = {-1, 0, 0};
        vireo_notifier_notify_outcome_t outcome = VIREO_NOTIFIER_NOTIFY_ALREADY_PENDING;
        uint64_t count = 0;
        bool const valid = vireo_notifier_inspect(owner, &info) == VIREO_OK && info.fd == 0 &&
            vireo_notifier_notify(owner, &outcome, NULL) == VIREO_OK &&
            outcome == VIREO_NOTIFIER_NOTIFY_INCREMENTED &&
            vireo_notifier_consume(owner, &count, NULL) == VIREO_OK && count == 1;
        vireo_result_t const destroyed = vireo_notifier_destroy(&owner, NULL);
        /* 隔离新建对象，_exit 不跑独立子进程 LSan，父进程标准输入不变。 */
        _exit(valid && destroyed == VIREO_OK && owner == NULL ? 0 : 1);
    }
    int status = 0;
    CHECK(waitpid(child, &status, 0) == child);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    return 0;
}

/** 只供真实 MPSC 组共享，notifier 在全部 join 后才销毁。 */
typedef struct parallel_state {
    vireo_notifier_t *notifier; /**< 创建后发布的借用对象，线程全结束前存活。 */
    atomic_bool go; /**< release/acquire 起跑标志，不是生产 notifier 锁。 */
    atomic_size_t done; /**< producer 完成本组循环的数量，不等于线程已 join。 */
    atomic_bool failed; /**< 任一 producer 观察到合同异常的粘性标志。 */
} parallel_state_t;

/** 各 producer 独立参数，pthread_create 之前填好并保持到 join。 */
typedef struct producer_argument {
    parallel_state_t *shared; /**< 借用共享测试状态，寿命覆盖线程。 */
    size_t writes; /**< 本 producer 固定通知次数，不是实际成功累计。 */
} producer_argument_t;

static void *producer(void *context)
{
    producer_argument_t const *argument = context;
    parallel_state_t *shared = argument->shared;
    int previous_cancel_state = 0;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previous_cancel_state) != 0) {
        atomic_store_explicit(&shared->failed, true, memory_order_release);
        atomic_fetch_add_explicit(&shared->done, 1, memory_order_release);
        return NULL;
    }
    while (!atomic_load_explicit(&shared->go, memory_order_acquire)) { (void)sched_yield(); }
    for (size_t i = 0; i < argument->writes; ++i) {
        vireo_notifier_notify_outcome_t outcome = VIREO_NOTIFIER_NOTIFY_ALREADY_PENDING;
        vireo_notifier_error_t error = {0};
        errno = ERANGE;
        if (vireo_notifier_notify(shared->notifier, &outcome, &error) != VIREO_OK ||
            outcome != VIREO_NOTIFIER_NOTIFY_INCREMENTED || errno != ERANGE ||
            error.stage != VIREO_NOTIFIER_STAGE_NONE || error.system_errno != 0) {
            atomic_store_explicit(&shared->failed, true, memory_order_release);
            break;
        }
        vireo_notifier_info_t info = {0};
        if (vireo_notifier_inspect(shared->notifier, &info) != VIREO_OK ||
            info.fd < 0 || info.allocated_bytes == 0 || info.max_memory_bytes != 4096 || errno != ERANGE) {
            atomic_store_explicit(&shared->failed, true, memory_order_release);
            break;
        }
    }
    atomic_fetch_add_explicit(&shared->done, 1, memory_order_release);
    if (pthread_setcancelstate(previous_cancel_state, NULL) != 0) {
        atomic_store_explicit(&shared->failed, true, memory_order_release);
    }
    return NULL;
}

static int native_mpsc(bool consume_concurrently)
{
    vireo_notifier_options_t const options = {4096};
    vireo_notifier_t *owner = NULL;
    EXPECT(vireo_notifier_create(&options, &owner, NULL), VIREO_OK);
    parallel_state_t shared;
    shared.notifier = owner;
    atomic_init(&shared.go, false);
    atomic_init(&shared.done, 0);
    atomic_init(&shared.failed, false);
    pthread_t threads[4];
    producer_argument_t arguments[4];
    size_t created = 0;
    for (size_t i = 0; i < 4; ++i) {
        arguments[i] = (producer_argument_t){&shared, 1000};
        if (pthread_create(&threads[i], NULL, producer, &arguments[i]) != 0) {
            atomic_store_explicit(&shared.failed, true, memory_order_release);
            break;
        }
        ++created;
    }
    atomic_store_explicit(&shared.go, true, memory_order_release);
    uint64_t total = 0;
    uint64_t const expected = (uint64_t)created * 1000;
    bool valid = true;
    if (consume_concurrently) {
        size_t turns = 0;
        while (total < expected && turns < 1000000) {
            uint64_t count = 0;
            errno = E2BIG;
            if (vireo_notifier_consume(owner, &count, NULL) != VIREO_OK || errno != E2BIG ||
                count > expected - total) {
                valid = false;
                break;
            }
            total += count;
            ++turns;
            if (count == 0) { (void)sched_yield(); }
            if (atomic_load_explicit(&shared.failed, memory_order_acquire)) {
                valid = false;
                break;
            }
        }
        if (total != expected) { valid = false; }
    }
    for (size_t i = 0; i < created; ++i) { CHECK(pthread_join(threads[i], NULL) == 0); }
    if (!consume_concurrently) {
        EXPECT(vireo_notifier_consume(owner, &total, NULL), VIREO_OK);
    }
    CHECK(valid && total == expected && created == 4);
    CHECK(atomic_load_explicit(&shared.done, memory_order_acquire) == 4);
    CHECK(!atomic_load_explicit(&shared.failed, memory_order_acquire));
    uint64_t empty = UINT64_MAX;
    EXPECT(vireo_notifier_consume(owner, &empty, NULL), VIREO_OK);
    CHECK(empty == 0);
    EXPECT(vireo_notifier_destroy(&owner, NULL), VIREO_OK);
    return 0;
}

static int producers_then_consume(void) { return native_mpsc(false); }
static int simultaneous_mpsc(void) { return native_mpsc(true); }

static size_t fd_count(void)
{
    DIR *directory = opendir("/proc/self/fd");
    if (directory == NULL) { return SIZE_MAX; }
    size_t count = 0;
    errno = 0;
    struct dirent *entry = NULL;
    while ((entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) { ++count; }
    }
    int const cause = errno;
    int const closed = closedir(directory);
    return cause == 0 && closed == 0 ? count : SIZE_MAX;
}

int main(void)
{
    int previous_cancel_state = 0;
    CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previous_cancel_state) == 0);
    size_t const before = fd_count();
    CHECK(before != SIZE_MAX);
    int (*const tests[])(void) = {real_merge_empty, real_saturation, invalid_parameters,
        io_errors_once, abnormal_returns, raw_read_values, eagain_and_null_diagnostics,
        actual_progress_not_rolled_back, fd_zero, producers_then_consume, simultaneous_mpsc};
    for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); ++i) { CHECK(tests[i]() == 0); }
    CHECK(fd_count() == before);
    CHECK(pthread_setcancelstate(previous_cancel_state, NULL) == 0);
    puts("notifier notify/consume: 11 groups passed (8 producer threads created/joined)");
    return 0;
}
