/* PROJECT : VIREO -- M3 短进度/状态/信号/多线程合同；不测试未实现的轮转。 */
#define _GNU_SOURCE
#include <vireo/base/log.h>
#include <base/log_internal.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #condition); return 1; \
} } while (0)

typedef struct fixture {
    char directory[128], file[160], capture[160];
} fixture_t;

static int read_file(char const *path, char **out, size_t *out_size);

static int fixture_start(fixture_t *fixture) {
    (void)snprintf(fixture->directory, sizeof(fixture->directory), "/tmp/vireo-log-emit-XXXXXX");
    CHECK(mkdtemp(fixture->directory) != NULL);
    CHECK(snprintf(fixture->file, sizeof(fixture->file), "%s/vireo.log", fixture->directory) > 0);
    CHECK(snprintf(fixture->capture, sizeof(fixture->capture), "%s/stderr.log", fixture->directory) > 0);
    return 0;
}

static int fixture_end(fixture_t const *fixture) {
    CHECK(unlink(fixture->file) == 0 || errno == ENOENT);
    CHECK(unlink(fixture->capture) == 0 || errno == ENOENT);
    CHECK(rmdir(fixture->directory) == 0);
    return 0;
}

static size_t fd_count(void) {
    DIR *directory = opendir("/proc/self/fd");
    if (directory == NULL) { return SIZE_MAX; }
    size_t count = 0;
    struct dirent *entry;
    while ((entry = readdir(directory)) != NULL) {
        if (entry->d_name[0] != '.') { ++count; }
    }
    (void)closedir(directory);
    return count - 1; /* 排除 scanner 自己的 fd。 */
}

static vireo_log_record_t record_normal(void) {
    return (vireo_log_record_t){.level = VIREO_LOG_LEVEL_INFO,
        .module = {(uint8_t const *)"storage", 7}, .connection_id = 42,
        .generation = 7, .sequence = 103,
        .message = {(uint8_t const *)"A\nB\0C", 5}};
}

static char const golden[] =
    "2026-10-01T10:20:30.123456789Z level=INFO tid=4127 module=\"storage\""
    " connection_id=42 generation=7 sequence=103 request_id=\"\" task_id=\"\""
    " message=\"A\\nB\\x00C\"\n";

/* 此表只由串行测试设置；write/time callback 在单 logger 的 mutex 内运行。 */
static struct {
    fixture_t const *fixture;
    int file_fd, stderr_fd;
    int file_error, stderr_error, time_error, init_error, lock_error, unlock_error, destroy_error;
    int open_error, sync_error;
    bool invalid_time, invalid_tid, zero, oversized;
    unsigned file_calls, stderr_calls, time_calls, closes, allocated, freed, inits, destroyed;
    unsigned interrupt_at, continuous_interrupts, file_fail_after;
    size_t chunk;
    char order[32768];
    size_t order_size;
} fault;

static void fault_reset(fixture_t const *fixture) {
    memset(&fault, 0, sizeof(fault));
    fault.fixture = fixture;
    fault.file_fd = -1;
    fault.stderr_fd = -1;
}

static void *allocate_test(size_t size) {
    ++fault.allocated;
    return vireo_log_system_ops.allocate(size);
}

static void free_test(void *pointer) {
    ++fault.freed;
    vireo_log_system_ops.deallocate(pointer);
}

/* 可控捕获目标仅替代 dup seam：返回独占可写 fd，不控制真实 fd2。 */
static int duplicate_test(void) {
    fault.stderr_fd = open(fault.fixture->capture, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    return fault.stderr_fd;
}

static int open_file_test(int directory_fd) {
    if (fault.open_error != 0) { errno = fault.open_error; return -1; }
    fault.file_fd = vireo_log_system_ops.open_file(directory_fd);
    return fault.file_fd;
}

static int sync_test(int fd) {
    if (fault.sync_error != 0) { errno = fault.sync_error; return -1; }
    return vireo_log_system_ops.sync_file(fd);
}

static int close_test(int fd) {
    ++fault.closes;
    return vireo_log_system_ops.close_fd(fd);
}

static int init_test(pthread_mutex_t *mutex) {
    ++fault.inits;
    return fault.init_error != 0 ? fault.init_error : vireo_log_system_ops.init_mutex(mutex);
}

static int destroy_test(pthread_mutex_t *mutex) {
    ++fault.destroyed;
    int code = vireo_log_system_ops.destroy_mutex(mutex);
    return code != 0 ? code : fault.destroy_error; /* 即使注入报错也已实际销毁。 */
}

static int lock_test(pthread_mutex_t *mutex) {
    return fault.lock_error != 0 ? fault.lock_error : vireo_log_system_ops.lock_mutex(mutex);
}

static int unlock_test(pthread_mutex_t *mutex) {
    int code = vireo_log_system_ops.unlock_mutex(mutex);
    return code != 0 ? code : fault.unlock_error; /* 注入报错仍释放真实 mutex。 */
}

static int time_test(vireo_log_timestamp_t *out_time) {
    ++fault.time_calls;
    if (fault.time_error != 0) { errno = fault.time_error; return -1; }
    *out_time = (vireo_log_timestamp_t){2026, 10, 1, 10, 20, 30, UINT32_C(123456789)};
    if (fault.invalid_time) { out_time->month = 0; }
    return 0;
}

static uint64_t tid_test(void) { return fault.invalid_tid ? 0 : UINT64_C(4127); }

static ssize_t write_test(int fd, void const *data, size_t size) {
    bool file = fd == fault.file_fd;
    unsigned call = file ? ++fault.file_calls : ++fault.stderr_calls;
    if (fault.order_size < sizeof(fault.order)) { fault.order[fault.order_size++] = file ? 'F' : 'S'; }
    if (file && (call == fault.interrupt_at || fault.continuous_interrupts != 0)) {
        if (fault.continuous_interrupts != 0) { --fault.continuous_interrupts; }
        errno = EINTR;
        return -1;
    }
    int cause = file ? fault.file_error : fault.stderr_error;
    if (cause != 0 && (!file || call > fault.file_fail_after)) { errno = cause; return -1; }
    if (file && fault.zero) { return 0; }
    if (file && fault.oversized) { return (ssize_t)(size + 1); }
    if (fault.chunk != 0 && size > fault.chunk) { size = fault.chunk; }
    return vireo_log_system_ops.write_fd(fd, data, size);
}

static vireo_log_ops_t test_ops(void) {
    vireo_log_ops_t ops = vireo_log_system_ops;
    ops.allocate = allocate_test; ops.deallocate = free_test;
    ops.duplicate_stderr = duplicate_test; ops.open_file = open_file_test; ops.close_fd = close_test;
    ops.sync_file = sync_test;
    ops.init_mutex = init_test; ops.destroy_mutex = destroy_test;
    ops.lock_mutex = lock_test; ops.unlock_mutex = unlock_test;
    ops.read_time = time_test; ops.thread_id = tid_test; ops.write_fd = write_test;
    return ops;
}

static int create_test(fixture_t const *fixture, unsigned sinks, vireo_log_t **logger) {
    vireo_log_options_t options = {.directory = (sinks & 1U) != 0 ? fixture->directory : NULL,
        .to_stderr = (sinks & 2U) != 0, .max_file_size_bytes = VIREO_LOG_MIN_FILE_SIZE_BYTES};
    vireo_log_ops_t ops = test_ops();
    errno = EBUSY;
    CHECK(vireo_log_create_with_ops(&options, logger, NULL, &ops) == VIREO_OK);
    CHECK(errno == EBUSY);
    return 0;
}

static int expect_content(char const *path, char const *expected, size_t size) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    CHECK(fd >= 0);
    char buffer[4096];
    CHECK(size < sizeof(buffer));
    ssize_t count = read(fd, buffer, sizeof(buffer));
    CHECK(count >= 0 && (size_t)count == size && memcmp(buffer, expected, size) == 0);
    CHECK(close(fd) == 0);
    return 0;
}

static int emit_expected(vireo_log_t *logger, vireo_log_record_t const *record,
                         vireo_result_t result, vireo_log_sink_t sink,
                         vireo_log_stage_t stage, int cause) {
    vireo_log_error_t error = {VIREO_LOG_SINK_STDERR, VIREO_LOG_STAGE_OPEN_FILE, ENOSPC};
    errno = EACCES;
    CHECK(vireo_log_emit(logger, record, &error) == result);
    CHECK(errno == EACCES);
    CHECK(error.sink == sink && error.stage == stage && error.system_errno == cause);
    return 0;
}

static int finish_test(fixture_t const *fixture, vireo_log_t **logger, size_t baseline) {
    errno = EDOM;
    CHECK(vireo_log_destroy(logger, NULL) == VIREO_OK && *logger == NULL && errno == EDOM);
    CHECK(fault.allocated == fault.freed && fault.destroyed == 1);
    CHECK(fd_count() == baseline);
    return fixture_end(fixture);
}

static int check_combinations(void) {
    for (unsigned sinks = 1; sinks <= 3; ++sinks) {
        fixture_t fixture; CHECK(fixture_start(&fixture) == 0); fault_reset(&fixture);
        size_t baseline = fd_count(); vireo_log_t *logger = NULL;
        CHECK(create_test(&fixture, sinks, &logger) == 0);
        vireo_log_record_t record = record_normal();
        CHECK(emit_expected(logger, &record, VIREO_OK, VIREO_LOG_SINK_NONE, VIREO_LOG_STAGE_NONE, 0) == 0);
        if ((sinks & 1U) != 0) { CHECK(expect_content(fixture.file, golden, sizeof(golden) - 1) == 0); }
        if ((sinks & 2U) != 0) { CHECK(expect_content(fixture.capture, golden, sizeof(golden) - 1) == 0); }
        CHECK(fault.order_size == (sinks == 3 ? 2U : 1U));
        if (sinks == 3) { CHECK(memcmp(fault.order, "FS", 2) == 0); }
        CHECK(finish_test(&fixture, &logger, baseline) == 0);
    }
    return 0;
}

static int check_arguments(void) {
    fixture_t fixture; CHECK(fixture_start(&fixture) == 0); fault_reset(&fixture);
    size_t baseline = fd_count(); vireo_log_t *logger = NULL;
    CHECK(create_test(&fixture, 3, &logger) == 0);
    vireo_log_record_t record = record_normal();
    CHECK(emit_expected(NULL, &record, VIREO_RESULT_INVALID_ARGUMENT, VIREO_LOG_SINK_NONE, VIREO_LOG_STAGE_VALIDATE, 0) == 0);
    CHECK(emit_expected(logger, NULL, VIREO_RESULT_INVALID_ARGUMENT, VIREO_LOG_SINK_NONE, VIREO_LOG_STAGE_VALIDATE, 0) == 0);
    record.level = (vireo_log_level_t)999;
    CHECK(emit_expected(logger, &record, VIREO_RESULT_INVALID_ARGUMENT, VIREO_LOG_SINK_NONE, VIREO_LOG_STAGE_VALIDATE, 0) == 0);
    record = record_normal(); record.message.data = NULL;
    CHECK(emit_expected(logger, &record, VIREO_RESULT_INVALID_ARGUMENT, VIREO_LOG_SINK_NONE, VIREO_LOG_STAGE_VALIDATE, 0) == 0);
    record = record_normal(); record.message.size = VIREO_LOG_MAX_MESSAGE_SIZE + 1;
    CHECK(emit_expected(logger, &record, VIREO_RESULT_RANGE, VIREO_LOG_SINK_NONE, VIREO_LOG_STAGE_VALIDATE, 0) == 0);
    CHECK(fault.time_calls == 0 && fault.file_calls == 0 && fault.stderr_calls == 0);
    CHECK(expect_content(fixture.file, "", 0) == 0);
    record = record_normal();
    CHECK(emit_expected(logger, &record, VIREO_OK, VIREO_LOG_SINK_NONE, VIREO_LOG_STAGE_NONE, 0) == 0);
    return finish_test(&fixture, &logger, baseline);
}

static int check_collection(void) {
    fixture_t fixture; CHECK(fixture_start(&fixture) == 0); fault_reset(&fixture);
    size_t baseline = fd_count(); vireo_log_t *logger = NULL; CHECK(create_test(&fixture, 3, &logger) == 0);
    vireo_log_record_t record = record_normal(); fault.time_error = EOVERFLOW;
    CHECK(emit_expected(logger, &record, VIREO_RESULT_IO, VIREO_LOG_SINK_NONE, VIREO_LOG_STAGE_CLOCK, EOVERFLOW) == 0);
    fault.time_error = 0; fault.invalid_tid = true;
    CHECK(emit_expected(logger, &record, VIREO_RESULT_INTERNAL, VIREO_LOG_SINK_NONE, VIREO_LOG_STAGE_THREAD_ID, 0) == 0);
    fault.invalid_tid = false; fault.invalid_time = true;
    CHECK(emit_expected(logger, &record, VIREO_RESULT_RANGE, VIREO_LOG_SINK_NONE, VIREO_LOG_STAGE_FORMAT, 0) == 0);
    CHECK(fault.file_calls == 0 && fault.stderr_calls == 0);
    fault.invalid_time = false;
    CHECK(emit_expected(logger, &record, VIREO_OK, VIREO_LOG_SINK_NONE, VIREO_LOG_STAGE_NONE, 0) == 0);
    CHECK(expect_content(fixture.file, golden, sizeof(golden) - 1) == 0);
    return finish_test(&fixture, &logger, baseline);
}

static int check_short_interrupted(void) {
    fixture_t fixture; CHECK(fixture_start(&fixture) == 0); fault_reset(&fixture);
    size_t baseline = fd_count(); vireo_log_t *logger = NULL; CHECK(create_test(&fixture, 3, &logger) == 0);
    fault.chunk = 7; fault.interrupt_at = 2;
    vireo_log_record_t record = record_normal();
    CHECK(emit_expected(logger, &record, VIREO_OK, VIREO_LOG_SINK_NONE, VIREO_LOG_STAGE_NONE, 0) == 0);
    CHECK(expect_content(fixture.file, golden, sizeof(golden) - 1) == 0);
    CHECK(expect_content(fixture.capture, golden, sizeof(golden) - 1) == 0);
    CHECK(fault.file_calls == fault.stderr_calls + 1 && fault.file_calls > 2);
    for (size_t i = 0; i < fault.order_size; ++i) { CHECK(fault.order[i] == (i < fault.file_calls ? 'F' : 'S')); }
    return finish_test(&fixture, &logger, baseline);
}

static int check_maximum_line(void) {
    fixture_t fixture; CHECK(fixture_start(&fixture) == 0); fault_reset(&fixture);
    size_t baseline = fd_count(); vireo_log_t *logger = NULL; CHECK(create_test(&fixture, 3, &logger) == 0);
    uint8_t bytes[VIREO_LOG_MAX_MESSAGE_SIZE]; memset(bytes, 0xFF, sizeof(bytes));
    vireo_log_record_t record = {.level = VIREO_LOG_LEVEL_ERROR, .module = {bytes, VIREO_LOG_MAX_MODULE_SIZE},
        .request_id = {bytes, VIREO_LOG_MAX_ID_SIZE}, .task_id = {bytes, VIREO_LOG_MAX_ID_SIZE},
        .message = {bytes, sizeof(bytes)}, .connection_id = UINT64_MAX, .generation = UINT64_MAX, .sequence = UINT32_MAX};
    vireo_log_timestamp_t timestamp; CHECK(time_test(&timestamp) == 0);
    char expected[VIREO_LOG_MAX_LINE_SIZE + 1]; size_t expected_size;
    CHECK(vireo_log_format(&record, &timestamp, UINT64_C(4127), expected, sizeof(expected), &expected_size) == VIREO_OK);
    fault.chunk = 1024;
    CHECK(emit_expected(logger, &record, VIREO_OK, VIREO_LOG_SINK_NONE, VIREO_LOG_STAGE_NONE, 0) == 0);
    char *file, *capture; size_t file_size, capture_size;
    CHECK(read_file(fixture.file, &file, &file_size) == 0 && read_file(fixture.capture, &capture, &capture_size) == 0);
    CHECK(file_size == expected_size && capture_size == expected_size && expected_size > 16000);
    CHECK(memcmp(file, expected, expected_size) == 0 && memcmp(capture, expected, expected_size) == 0);
    free(file); free(capture);
    return finish_test(&fixture, &logger, baseline);
}

/* 终止型错误都只尝试一次；下次跳过 file，但始终报告其原有首错。 */
static int check_terminal_errors(void) {
    int const causes[] = {EAGAIN, EWOULDBLOCK, ENOSPC, EDQUOT, EPIPE, EBADF, EIO};
    for (size_t i = 0; i < sizeof(causes) / sizeof(causes[0]) + 2; ++i) {
        fixture_t fixture; CHECK(fixture_start(&fixture) == 0); fault_reset(&fixture);
        size_t baseline = fd_count(); vireo_log_t *logger = NULL; CHECK(create_test(&fixture, 3, &logger) == 0);
        int cause = i < sizeof(causes) / sizeof(causes[0]) ? causes[i] : EIO;
        fault.file_error = i < sizeof(causes) / sizeof(causes[0]) ? cause : 0;
        fault.zero = i == sizeof(causes) / sizeof(causes[0]);
        fault.oversized = i == sizeof(causes) / sizeof(causes[0]) + 1;
        vireo_log_record_t record = record_normal();
        CHECK(emit_expected(logger, &record, VIREO_RESULT_IO, VIREO_LOG_SINK_FILE, VIREO_LOG_STAGE_WRITE, cause) == 0);
        fault.file_error = 0; fault.zero = false; fault.oversized = false;
        CHECK(emit_expected(logger, &record, VIREO_RESULT_IO, VIREO_LOG_SINK_FILE, VIREO_LOG_STAGE_WRITE, cause) == 0);
        CHECK(fault.file_calls == 1 && fault.stderr_calls == 2);
        CHECK(expect_content(fixture.file, "", 0) == 0);
        char twice[sizeof(golden) * 2]; size_t length = sizeof(golden) - 1;
        memcpy(twice, golden, length); memcpy(twice + length, golden, length);
        CHECK(expect_content(fixture.capture, twice, length * 2) == 0);
        CHECK(finish_test(&fixture, &logger, baseline) == 0);
    }
    return 0;
}

static int check_interruption_budget(void) {
    fixture_t fixture; CHECK(fixture_start(&fixture) == 0); fault_reset(&fixture);
    size_t baseline = fd_count(); vireo_log_t *logger = NULL; CHECK(create_test(&fixture, 3, &logger) == 0);
    fault.continuous_interrupts = 100;
    vireo_log_record_t record = record_normal();
    CHECK(emit_expected(logger, &record, VIREO_RESULT_IO, VIREO_LOG_SINK_FILE, VIREO_LOG_STAGE_WRITE, EINTR) == 0);
    CHECK(fault.file_calls == 17 && fault.stderr_calls == 1);
    CHECK(expect_content(fixture.capture, golden, sizeof(golden) - 1) == 0);
    return finish_test(&fixture, &logger, baseline);
}

static int check_partial_failure(void) {
    fixture_t fixture; CHECK(fixture_start(&fixture) == 0); fault_reset(&fixture);
    size_t baseline = fd_count(); vireo_log_t *logger = NULL; CHECK(create_test(&fixture, 3, &logger) == 0);
    fault.file_error = ENOSPC; fault.file_fail_after = 1; fault.chunk = 7;
    vireo_log_record_t record = record_normal();
    CHECK(emit_expected(logger, &record, VIREO_RESULT_IO, VIREO_LOG_SINK_FILE, VIREO_LOG_STAGE_WRITE, ENOSPC) == 0);
    CHECK(expect_content(fixture.file, golden, 7) == 0);
    CHECK(expect_content(fixture.capture, golden, sizeof(golden) - 1) == 0);
    CHECK(fault.file_calls == 2);
    return finish_test(&fixture, &logger, baseline);
}

static int check_first_error(void) {
    for (unsigned scenario = 0; scenario < 3; ++scenario) {
        fixture_t fixture; CHECK(fixture_start(&fixture) == 0); fault_reset(&fixture);
        size_t baseline = fd_count(); vireo_log_t *logger = NULL; CHECK(create_test(&fixture, 3, &logger) == 0);
        fault.stderr_error = EPIPE; fault.file_error = scenario == 1 ? ENOSPC : 0;
        vireo_log_record_t record = record_normal();
        vireo_log_sink_t sink = scenario == 1 ? VIREO_LOG_SINK_FILE : VIREO_LOG_SINK_STDERR;
        int cause = scenario == 1 ? ENOSPC : EPIPE;
        CHECK(emit_expected(logger, &record, VIREO_RESULT_IO, sink, VIREO_LOG_STAGE_WRITE, cause) == 0);
        if (scenario == 2) { fault.file_error = EDQUOT; sink = VIREO_LOG_SINK_FILE; cause = EDQUOT; }
        CHECK(emit_expected(logger, &record, VIREO_RESULT_IO, sink, VIREO_LOG_STAGE_WRITE, cause) == 0);
        CHECK(fault.stderr_calls == 1 && fault.file_calls == (scenario == 1 ? 1U : 2U));
        if (scenario == 2 || scenario == 1) {
            unsigned calls = fault.file_calls;
            CHECK(emit_expected(logger, &record, VIREO_RESULT_IO, sink, VIREO_LOG_STAGE_WRITE, cause) == 0);
            CHECK(fault.file_calls == calls && fault.stderr_calls == 1);
        }
        CHECK(finish_test(&fixture, &logger, baseline) == 0);
    }
    return 0;
}

static int check_null_diagnostic(void) {
    for (unsigned optional = 0; optional < 2; ++optional) {
        fixture_t fixture; CHECK(fixture_start(&fixture) == 0); fault_reset(&fixture);
        size_t baseline = fd_count(); vireo_log_t *logger = NULL; CHECK(create_test(&fixture, 3, &logger) == 0);
        fault.file_error = ENOSPC; vireo_log_record_t record = record_normal(); vireo_log_error_t error;
        for (unsigned i = 0; i < 2; ++i) {
            errno = EACCES;
            CHECK(vireo_log_emit(logger, &record, optional == 0 ? NULL : &error) == VIREO_RESULT_IO);
            CHECK(errno == EACCES);
            if (optional != 0) { CHECK(error.sink == VIREO_LOG_SINK_FILE && error.system_errno == ENOSPC); }
        }
        CHECK(fault.file_calls == 1 && fault.stderr_calls == 2);
        CHECK(finish_test(&fixture, &logger, baseline) == 0);
    }
    return 0;
}

static int check_mutex_errors(void) {
    fixture_t fixture; CHECK(fixture_start(&fixture) == 0); fault_reset(&fixture);
    size_t baseline = fd_count(); vireo_log_t *logger = NULL;
    vireo_log_options_t options = {fixture.directory, true, VIREO_LOG_MIN_FILE_SIZE_BYTES};
    vireo_log_ops_t ops = test_ops(); vireo_log_error_t error;
    fault.init_error = EAGAIN; errno = EACCES;
    CHECK(vireo_log_create_with_ops(&options, &logger, &error, &ops) == VIREO_RESULT_INTERNAL);
    CHECK(logger == NULL && errno == EACCES && error.stage == VIREO_LOG_STAGE_INIT_MUTEX && error.system_errno == EAGAIN);
    CHECK(fault.freed == 1 && fault.destroyed == 0 && fault.closes == 0 && fd_count() == baseline);
    fault_reset(&fixture); CHECK(create_test(&fixture, 3, &logger) == 0);
    vireo_log_record_t record = record_normal(); fault.lock_error = EDEADLK;
    CHECK(emit_expected(logger, &record, VIREO_RESULT_INTERNAL, VIREO_LOG_SINK_NONE, VIREO_LOG_STAGE_LOCK, EDEADLK) == 0);
    CHECK(fault.time_calls == 0 && fault.file_calls == 0); fault.lock_error = 0; fault.unlock_error = EPERM;
    CHECK(emit_expected(logger, &record, VIREO_RESULT_INTERNAL, VIREO_LOG_SINK_NONE, VIREO_LOG_STAGE_UNLOCK, EPERM) == 0);
    CHECK(expect_content(fixture.file, golden, sizeof(golden) - 1) == 0);
    fault.file_error = ENOSPC;
    CHECK(emit_expected(logger, &record, VIREO_RESULT_IO, VIREO_LOG_SINK_FILE, VIREO_LOG_STAGE_WRITE, ENOSPC) == 0);
    fault.unlock_error = 0; fault.destroy_error = EBUSY; errno = EDOM;
    CHECK(vireo_log_destroy(&logger, &error) == VIREO_RESULT_INTERNAL && logger == NULL && errno == EDOM);
    CHECK(error.stage == VIREO_LOG_STAGE_DESTROY_MUTEX && error.system_errno == EBUSY);
    CHECK(fault.closes == 3 && fault.destroyed == 1 && fault.allocated == fault.freed && fd_count() == baseline);
    return fixture_end(&fixture);
}

static int check_missing_ops(void) {
    fixture_t fixture; CHECK(fixture_start(&fixture) == 0); fault_reset(&fixture);
    vireo_log_options_t options = {fixture.directory, false, VIREO_LOG_MIN_FILE_SIZE_BYTES};
    for (unsigned i = 0; i < 7; ++i) {
        vireo_log_ops_t ops = test_ops(); vireo_log_t *logger = NULL;
        switch (i) {
            case 0: ops.init_mutex = NULL; break; case 1: ops.destroy_mutex = NULL; break;
            case 2: ops.lock_mutex = NULL; break; case 3: ops.unlock_mutex = NULL; break;
            case 4: ops.read_time = NULL; break; case 5: ops.thread_id = NULL; break;
            default: ops.write_fd = NULL; break;
        }
        CHECK(vireo_log_create_with_ops(&options, &logger, NULL, &ops) == VIREO_RESULT_INVALID_ARGUMENT);
        CHECK(logger == NULL && fault.allocated == 0);
    }
    return fixture_end(&fixture);
}

/* 已初始化 mutex 的获取失败回滚，以及清理第一错误不能被 mutex 错误覆盖。 */
static int check_mutex_cleanup_priority(void) {
    fixture_t fixture; CHECK(fixture_start(&fixture) == 0); fault_reset(&fixture);
    size_t baseline = fd_count(); vireo_log_t *logger = NULL;
    vireo_log_options_t options = {fixture.directory, true, VIREO_LOG_MIN_FILE_SIZE_BYTES};
    vireo_log_ops_t ops = test_ops(); vireo_log_error_t error;
    fault.open_error = ENOSPC; fault.destroy_error = EBUSY; errno = EACCES;
    CHECK(vireo_log_create_with_ops(&options, &logger, &error, &ops) == VIREO_RESULT_IO);
    CHECK(logger == NULL && errno == EACCES && error.stage == VIREO_LOG_STAGE_OPEN_FILE && error.system_errno == ENOSPC);
    CHECK(fault.inits == 1 && fault.destroyed == 1 && fault.closes == 2 && fault.freed == 1 && fd_count() == baseline);
    fault_reset(&fixture); CHECK(create_test(&fixture, 3, &logger) == 0);
    fault.sync_error = EIO; fault.destroy_error = EBUSY; errno = EDOM;
    CHECK(vireo_log_destroy(&logger, &error) == VIREO_RESULT_IO && logger == NULL && errno == EDOM);
    CHECK(error.sink == VIREO_LOG_SINK_FILE && error.stage == VIREO_LOG_STAGE_SYNC_FILE && error.system_errno == EIO);
    CHECK(fault.destroyed == 1 && fault.closes == 3 && fault.freed == 1 && fd_count() == baseline);
    return fixture_end(&fixture);
}

/* fork 隔离 fd2 与信号设置；新 logger 在 child 中创建/消费，不使用继承对象。 */
static int signal_child(unsigned scenario) {
    int descriptors[2]; CHECK(pipe2(descriptors, O_CLOEXEC) == 0);
    CHECK(dup2(descriptors[1], STDERR_FILENO) == STDERR_FILENO);
    CHECK(close(descriptors[1]) == 0 && close(descriptors[0]) == 0);
    struct sigaction action = {0}; action.sa_handler = scenario == 2 ? SIG_IGN : SIG_DFL;
    CHECK(sigemptyset(&action.sa_mask) == 0 && sigaction(SIGPIPE, &action, NULL) == 0);
    sigset_t set, original, pending; CHECK(sigemptyset(&set) == 0 && sigaddset(&set, SIGPIPE) == 0);
    bool previously_blocked = scenario == 1 || scenario == 3;
    CHECK(pthread_sigmask(previously_blocked ? SIG_BLOCK : SIG_UNBLOCK, &set, &original) == 0);
    if (scenario == 1) { CHECK(raise(SIGPIPE) == 0); }
    vireo_log_t *logger = NULL; vireo_log_options_t options = {NULL, true, 0};
    CHECK(vireo_log_create(&options, &logger, NULL) == VIREO_OK);
    vireo_log_record_t record = record_normal();
    CHECK(emit_expected(logger, &record, VIREO_RESULT_IO, VIREO_LOG_SINK_STDERR, VIREO_LOG_STAGE_WRITE, EPIPE) == 0);
    CHECK(sigpending(&pending) == 0 && sigismember(&pending, SIGPIPE) == (scenario == 1 ? 1 : 0));
    sigset_t current; CHECK(pthread_sigmask(SIG_SETMASK, NULL, &current) == 0);
    CHECK(sigismember(&current, SIGPIPE) == (previously_blocked ? 1 : 0));
    struct sigaction actual; CHECK(sigaction(SIGPIPE, NULL, &actual) == 0 && actual.sa_handler == action.sa_handler);
    CHECK(vireo_log_destroy(&logger, NULL) == VIREO_OK && logger == NULL);
    if (scenario == 1) { struct timespec const zero = {0}; CHECK(sigtimedwait(&set, NULL, &zero) == SIGPIPE); }
    CHECK(pthread_sigmask(SIG_SETMASK, &original, NULL) == 0);
    return 0;
}

static int check_sigpipe(void) {
    for (unsigned scenario = 0; scenario < 4; ++scenario) {
        pid_t child = fork(); CHECK(child >= 0);
        if (child == 0) { _exit(signal_child(scenario)); }
        int status; CHECK(waitpid(child, &status, 0) == child);
        CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    }
    return 0;
}

/* 仅在串行 fork 子进程内观察真实 safe-write；不伪造返回值或发送信号。 */
static unsigned partial_pipe_calls, partial_pipe_shorts;
static size_t partial_pipe_requested, partial_pipe_written;
static volatile sig_atomic_t partial_pipe_handler_calls;

static void partial_pipe_handler(int signal_number) {
    (void)signal_number;
    partial_pipe_handler_calls = 1;
}

static ssize_t write_partial_pipe(int fd, void const *data, size_t size) {
    ssize_t count = vireo_log_system_ops.write_fd(fd, data, size);
    ++partial_pipe_calls;
    if (count > 0 && (size_t)count < size) {
        ++partial_pipe_shorts;
        partial_pipe_requested = size;
        partial_pipe_written = (size_t)count;
    }
    return count;
}

static int partial_pipe_child(int read_fd, int write_fd, int capacity, unsigned scenario) {
    (void)alarm(10); /* 包括故障退出/等待的有界保护；只有本子进程。 */
    CHECK(close(read_fd) == 0);
    CHECK(dup2(write_fd, STDERR_FILENO) == STDERR_FILENO && close(write_fd) == 0);
    struct sigaction action = {0};
    action.sa_handler = scenario == 2 ? SIG_IGN : scenario == 4 ? partial_pipe_handler : SIG_DFL;
    CHECK(sigemptyset(&action.sa_mask) == 0 && sigaction(SIGPIPE, &action, NULL) == 0);
    sigset_t set, initial, expected, pending, current;
    CHECK(sigemptyset(&set) == 0 && sigaddset(&set, SIGPIPE) == 0);
    bool previously_blocked = scenario == 1 || scenario == 3;
    CHECK(pthread_sigmask(previously_blocked ? SIG_BLOCK : SIG_UNBLOCK, &set, &initial) == 0);
    sigset_t other;
    CHECK(sigemptyset(&other) == 0 && sigaddset(&other, SIGUSR1) == 0);
    CHECK(pthread_sigmask(SIG_BLOCK, &other, NULL) == 0);
    if (scenario == 1) { CHECK(raise(SIGPIPE) == 0); } /* 仅调用前的旧pending。 */
    CHECK(pthread_sigmask(SIG_SETMASK, NULL, &expected) == 0);
    size_t baseline = fd_count(); CHECK(baseline != SIZE_MAX);
    vireo_log_ops_t ops = vireo_log_system_ops; ops.write_fd = write_partial_pipe;
    vireo_log_options_t options = {NULL, true, 0}; vireo_log_t *logger = NULL;
    CHECK(vireo_log_create_with_ops(&options, &logger, NULL, &ops) == VIREO_OK);
    uint8_t message[VIREO_LOG_MAX_MESSAGE_SIZE]; memset(message, 0xFF, sizeof(message));
    vireo_log_record_t record = record_normal();
    record.message = (vireo_log_span_t){message, sizeof(message)};
    CHECK(emit_expected(logger, &record, VIREO_RESULT_IO, VIREO_LOG_SINK_STDERR,
                        VIREO_LOG_STAGE_WRITE, EPIPE) == 0);
    CHECK(partial_pipe_shorts == 1 && partial_pipe_calls == 2);
    CHECK(partial_pipe_requested > (size_t)capacity && partial_pipe_written == (size_t)capacity);
    CHECK(sigpending(&pending) == 0 && sigismember(&pending, SIGPIPE) == (scenario == 1 ? 1 : 0));
    CHECK(pthread_sigmask(SIG_SETMASK, NULL, &current) == 0);
    for (int signal_number = 1; signal_number < NSIG; ++signal_number) {
        CHECK(sigismember(&current, signal_number) == sigismember(&expected, signal_number));
    }
    struct sigaction actual;
    CHECK(sigaction(SIGPIPE, NULL, &actual) == 0 && actual.sa_handler == action.sa_handler);
    CHECK(partial_pipe_handler_calls == 0);
    CHECK(emit_expected(logger, &record, VIREO_RESULT_IO, VIREO_LOG_SINK_STDERR,
                        VIREO_LOG_STAGE_WRITE, EPIPE) == 0);
    errno = EDOM;
    CHECK(vireo_log_emit(logger, &record, NULL) == VIREO_RESULT_IO && errno == EDOM);
    CHECK(partial_pipe_calls == 2); /* sticky FAILED：不重写已接受的半行。 */
    CHECK(vireo_log_destroy(&logger, NULL) == VIREO_OK && logger == NULL && errno == EDOM);
    CHECK(fd_count() == baseline);
    if (scenario == 1) {
        struct timespec const zero = {0}; CHECK(sigtimedwait(&set, NULL, &zero) == SIGPIPE);
    }
    CHECK(pthread_sigmask(SIG_SETMASK, &initial, NULL) == 0);
    return 0;
}

static int check_sigpipe_partial(void) {
    size_t baseline = fd_count(); CHECK(baseline != SIZE_MAX);
    for (unsigned scenario = 0; scenario < 5; ++scenario) {
        int descriptors[2]; CHECK(pipe2(descriptors, O_CLOEXEC) == 0);
        int capacity = fcntl(descriptors[1], F_SETPIPE_SZ, 4096); CHECK(capacity == 4096);
        pid_t child = fork(); CHECK(child >= 0);
        if (child == 0) { _exit(partial_pipe_child(descriptors[0], descriptors[1], capacity, scenario)); }
        CHECK(close(descriptors[1]) == 0);
        struct pollfd observed = {.fd = descriptors[0], .events = POLLIN};
        int ready;
        do { ready = poll(&observed, 1, 5000); } while (ready < 0 && errno == EINTR);
        /* 不排空pipe：可读确认实际写出字节，再关闭最后读端，使阻塞write结束。 */
        CHECK(close(descriptors[0]) == 0);
        int status; pid_t waited;
        do { waited = waitpid(child, &status, 0); } while (waited < 0 && errno == EINTR);
        CHECK(waited == child && ready == 1 && (observed.revents & POLLIN) != 0);
        CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
        CHECK(fd_count() == baseline);
    }
    return 0;
}

static int check_real_nonblocking(void) {
    pid_t child = fork(); CHECK(child >= 0);
    if (child == 0) {
        int descriptors[2]; if (pipe2(descriptors, O_CLOEXEC | O_NONBLOCK) != 0) { _exit(1); }
        char bytes[4096]; memset(bytes, 'x', sizeof(bytes));
        while (write(descriptors[1], bytes, sizeof(bytes)) > 0) {}
        if (errno != EAGAIN || dup2(descriptors[1], STDERR_FILENO) < 0) { _exit(1); }
        vireo_log_t *logger = NULL; vireo_log_options_t options = {NULL, true, 0};
        if (vireo_log_create(&options, &logger, NULL) != VIREO_OK) { _exit(1); }
        vireo_log_record_t record = record_normal(); vireo_log_error_t error; errno = EDOM;
        if (vireo_log_emit(logger, &record, &error) != VIREO_RESULT_IO || error.system_errno != EAGAIN || errno != EDOM) { _exit(1); }
        if (vireo_log_destroy(&logger, NULL) != VIREO_OK || close(descriptors[0]) != 0 || close(descriptors[1]) != 0) { _exit(1); }
        _exit(0);
    }
    int status; CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    return 0;
}

enum { THREADS = 4, PER_THREAD = 150 };
typedef struct thread_input {
    vireo_log_t *logger;
    unsigned index;
    int result;
    uint64_t tid;
} thread_input_t;

static void *emit_thread(void *pointer) {
    thread_input_t *input = pointer; input->tid = (uint64_t)gettid();
    for (unsigned i = 0; i < PER_THREAD; ++i) {
        vireo_log_record_t record = record_normal(); record.sequence = input->index * PER_THREAD + i + 1;
        char message[64]; int length = snprintf(message, sizeof(message), "thread=%u item=%u", input->index, i);
        if (length < 0 || (size_t)length >= sizeof(message)) { input->result = 1; return NULL; }
        record.message = (vireo_log_span_t){(uint8_t const *)message, (size_t)length};
        vireo_log_error_t error; errno = EDOM;
        if (vireo_log_emit(input->logger, &record, &error) != VIREO_OK || errno != EDOM ||
            error.stage != VIREO_LOG_STAGE_NONE || error.sink != VIREO_LOG_SINK_NONE || error.system_errno != 0) {
            input->result = 1; return NULL;
        }
    }
    return NULL;
}

static int read_file(char const *path, char **out, size_t *out_size) {
    int fd = open(path, O_RDONLY | O_CLOEXEC); CHECK(fd >= 0);
    struct stat info; CHECK(fstat(fd, &info) == 0 && info.st_size >= 0 && info.st_size < 1048576);
    size_t size = (size_t)info.st_size; char *buffer = malloc(size + 1); CHECK(buffer != NULL);
    size_t offset = 0;
    while (offset < size) { ssize_t count = read(fd, buffer + offset, size - offset); CHECK(count > 0); offset += (size_t)count; }
    buffer[size] = '\0'; CHECK(close(fd) == 0); *out = buffer; *out_size = size; return 0;
}

/* 使用真实时间/TID/锁/write，短写 seam 每次最多11字节，扩大竞争窗口；无 sleep 猜测。 */
static ssize_t write_concurrent(int fd, void const *data, size_t size) {
    return vireo_log_system_ops.write_fd(fd, data, size > 11 ? 11 : size);
}

static int check_concurrent(void) {
    fixture_t fixture; CHECK(fixture_start(&fixture) == 0); fault_reset(&fixture);
    size_t baseline = fd_count();
    vireo_log_ops_t ops = vireo_log_system_ops;
    ops.duplicate_stderr = duplicate_test; ops.write_fd = write_concurrent;
    vireo_log_options_t options = {fixture.directory, true, VIREO_LOG_MIN_FILE_SIZE_BYTES};
    vireo_log_t *logger = NULL; CHECK(vireo_log_create_with_ops(&options, &logger, NULL, &ops) == VIREO_OK);
    pthread_t threads[THREADS]; thread_input_t inputs[THREADS];
    unsigned started = 0;
    for (; started < THREADS; ++started) {
        inputs[started] = (thread_input_t){.logger = logger, .index = started};
        if (pthread_create(&threads[started], NULL, emit_thread, &inputs[started]) != 0) { break; }
    }
    for (unsigned i = 0; i < started; ++i) { CHECK(pthread_join(threads[i], NULL) == 0); }
    CHECK(started == THREADS);
    for (unsigned i = 0; i < THREADS; ++i) { CHECK(inputs[i].result == 0 && inputs[i].tid > 0); }
    CHECK(vireo_log_destroy(&logger, NULL) == VIREO_OK && logger == NULL && fd_count() == baseline);
    char *file, *capture; size_t file_size, capture_size;
    CHECK(read_file(fixture.file, &file, &file_size) == 0 && read_file(fixture.capture, &capture, &capture_size) == 0);
    CHECK(file_size == capture_size && memcmp(file, capture, file_size) == 0);
    bool seen[THREADS * PER_THREAD]; memset(seen, 0, sizeof(seen));
    unsigned counts[THREADS] = {0}; char *cursor = file; unsigned lines = 0;
    while (*cursor != '\0') {
        char *end = strchr(cursor, '\n'); CHECK(end != NULL); *end = '\0';
        CHECK(strlen(cursor) > 30 && cursor[4] == '-' && cursor[10] == 'T' && cursor[19] == '.' && cursor[29] == 'Z');
        char *sequence = strstr(cursor, " sequence="); char *tid = strstr(cursor, " tid=");
        char *message = strstr(cursor, " message=\"thread="); CHECK(sequence != NULL && tid != NULL && message != NULL);
        unsigned value, index, item; unsigned long long observed_tid; int used = 0;
        CHECK(sscanf(sequence, " sequence=%u", &value) == 1 && value > 0 && value <= THREADS * PER_THREAD);
        CHECK(!seen[value - 1]); seen[value - 1] = true;
        CHECK(sscanf(tid, " tid=%llu", &observed_tid) == 1);
        CHECK(sscanf(message, " message=\"thread=%u item=%u\"%n", &index, &item, &used) == 2);
        CHECK(used > 0 && message[used] == '\0' && index < THREADS && item < PER_THREAD);
        CHECK(value == index * PER_THREAD + item + 1 && observed_tid == inputs[index].tid);
        /* 重建整条合法记录，防止仅 seq/message 正确却存在其他字节交错的漏检。 */
        unsigned year, month, day, hour, minute, second, nano; int prefix_size = 0;
        CHECK(sscanf(cursor, "%4u-%2u-%2uT%2u:%2u:%2u.%9uZ%n", &year, &month, &day,
                     &hour, &minute, &second, &nano, &prefix_size) == 7 && prefix_size == 30);
        CHECK(year >= 1970 && year <= 9999 && month <= 12 && day <= 31 && hour <= 23 && minute <= 59 && second <= 59);
        vireo_log_timestamp_t timestamp = {(uint16_t)year, (uint8_t)month, (uint8_t)day,
            (uint8_t)hour, (uint8_t)minute, (uint8_t)second, nano};
        vireo_log_record_t expected_record = record_normal(); expected_record.sequence = value;
        char expected_message[64]; int message_size = snprintf(expected_message, sizeof(expected_message), "thread=%u item=%u", index, item);
        CHECK(message_size > 0 && (size_t)message_size < sizeof(expected_message));
        expected_record.message = (vireo_log_span_t){(uint8_t const *)expected_message, (size_t)message_size};
        char expected_line[1024]; size_t expected_size;
        CHECK(vireo_log_format(&expected_record, &timestamp, (uint64_t)observed_tid, expected_line, sizeof(expected_line), &expected_size) == VIREO_OK);
        CHECK(expected_size > 0 && expected_line[expected_size - 1] == '\n'); expected_line[expected_size - 1] = '\0';
        CHECK(strcmp(cursor, expected_line) == 0);
        CHECK(item == counts[index]); ++counts[index]; ++lines; cursor = end + 1;
    }
    CHECK(lines == THREADS * PER_THREAD);
    for (unsigned i = 0; i < THREADS; ++i) { CHECK(counts[i] == PER_THREAD); }
    free(file); free(capture); return fixture_end(&fixture);
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--sigpipe-partial") == 0) {
        int code = check_sigpipe_partial();
        if (code == 0) { puts("test_log_emit: real positive-short-write SIGPIPE 5 scenarios passed"); }
        return code;
    }
    /* 专项只运行无 fork 的真实多线程路径，适合 TSan；不是另一套假实现。 */
    if (argc == 2 && strcmp(argv[1], "--concurrent") == 0) {
        int code = check_concurrent(); if (code == 0) { puts("test_log_emit: concurrent 600 records passed"); } return code;
    }
    int (*const checks[])(void) = {check_combinations, check_arguments, check_collection,
        check_short_interrupted, check_maximum_line, check_terminal_errors, check_interruption_budget,
        check_partial_failure, check_first_error, check_null_diagnostic, check_mutex_errors,
        check_missing_ops, check_mutex_cleanup_priority, check_sigpipe, check_sigpipe_partial,
        check_real_nonblocking, check_concurrent};
    for (size_t i = 0; i < sizeof(checks) / sizeof(checks[0]); ++i) { if (checks[i]() != 0) { return 1; } }
    puts("test_log_emit: 17 groups passed (600 concurrent records, short writes, faults and SIGPIPE)");
    return 0;
}
