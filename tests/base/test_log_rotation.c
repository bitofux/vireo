/* PROJECT : VIREO -- M4 flush/单归档/部分失败/同锁并发，临时目录精确清理。 */
#define _GNU_SOURCE
#include <vireo/base/log.h>
#include <base/log_internal.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #condition); return 1; \
} } while (0)

typedef struct fixture {
    char directory[128], file[160], archive[160], capture[160], other[160];
} fixture_t;

static int fixture_start(fixture_t *fixture) {
    (void)snprintf(fixture->directory, sizeof(fixture->directory), "/tmp/vireo-log-rotation-XXXXXX");
    CHECK(mkdtemp(fixture->directory) != NULL);
    CHECK(snprintf(fixture->file, sizeof(fixture->file), "%s/%s", fixture->directory, VIREO_LOG_FILE_NAME) > 0);
    CHECK(snprintf(fixture->archive, sizeof(fixture->archive), "%s/%s", fixture->directory, VIREO_LOG_ARCHIVE_NAME) > 0);
    CHECK(snprintf(fixture->capture, sizeof(fixture->capture), "%s/stderr.log", fixture->directory) > 0);
    CHECK(snprintf(fixture->other, sizeof(fixture->other), "%s/untouched", fixture->directory) > 0);
    return 0;
}

static int fixture_end(fixture_t const *fixture) {
    char const *paths[] = {fixture->file, fixture->archive, fixture->capture, fixture->other};
    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); ++i) {
        CHECK(unlink(paths[i]) == 0 || errno == ENOENT);
    }
    CHECK(rmdir(fixture->directory) == 0);
    return 0;
}

static size_t fd_count(void) {
    DIR *directory = opendir("/proc/self/fd");
    if (directory == NULL) { return SIZE_MAX; }
    size_t count = 0;
    struct dirent *entry;
    while ((entry = readdir(directory)) != NULL) { if (entry->d_name[0] != '.') { ++count; } }
    (void)closedir(directory);
    return count - 1;
}

static int read_file(char const *path, char **out, size_t *out_size) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    CHECK(fd >= 0);
    struct stat info; CHECK(fstat(fd, &info) == 0 && info.st_size >= 0);
    size_t size = (size_t)info.st_size;
    CHECK(size < (size_t)UINT64_C(4194304));
    char *data = malloc(size + 1); CHECK(data != NULL);
    size_t offset = 0;
    while (offset < size) {
        ssize_t count = read(fd, data + offset, size - offset);
        CHECK(count > 0); offset += (size_t)count;
    }
    data[size] = '\0'; CHECK(close(fd) == 0);
    *out = data; *out_size = size;
    return 0;
}

static int expect_content(char const *path, char const *wanted, size_t size) {
    char *data = NULL; size_t found = 0;
    CHECK(read_file(path, &data, &found) == 0);
    bool same = found == size && memcmp(data, wanted, size) == 0;
    free(data); CHECK(same);
    return 0;
}

static int set_size(char const *path, uint64_t size) {
    int fd = open(path, O_WRONLY | O_CLOEXEC); CHECK(fd >= 0);
    CHECK(ftruncate(fd, (off_t)size) == 0); CHECK(close(fd) == 0);
    return 0;
}

static int make_file(char const *path, char const *text) {
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600); CHECK(fd >= 0);
    size_t size = strlen(text);
    CHECK(write(fd, text, size) == (ssize_t)size); CHECK(close(fd) == 0);
    return 0;
}

static vireo_log_record_t record_normal(void) {
    return (vireo_log_record_t){.level = VIREO_LOG_LEVEL_INFO,
        .module = {(uint8_t const *)"storage", 7}, .connection_id = 42, .generation = 7,
        .sequence = 103, .message = {(uint8_t const *)"A\nB\0C", 5}};
}

static char const golden[] =
    "2026-10-01T10:20:30.123456789Z level=INFO tid=4127 module=\"storage\""
    " connection_id=42 generation=7 sequence=103 request_id=\"\" task_id=\"\""
    " message=\"A\\nB\\x00C\"\n";

/* 设置仅在串行阶段；回调计数/跟踪在同一logger锁内，并发运行期间不改注入状态。 */
static struct {
    fixture_t const *fixture;
    int original_fd, current_fd, new_fd, stderr_fd;
    vireo_log_stage_t failure;
    int cause, stderr_error, file_error, lock_error, unlock_error;
    unsigned syncs, new_syncs, renames, opens, inspections, file_writes, stderr_writes, closes;
    unsigned old_closes, new_closes, invalid_new, conflict;
    bool negative_size, wrong_owner, wrong_source, cleanup_error;
    char events[128]; size_t event_size;
} fault;

static void event(char value) {
    if (fault.event_size < sizeof(fault.events)) { fault.events[fault.event_size++] = value; }
}

static void reset(fixture_t const *fixture) {
    memset(&fault, 0, sizeof(fault)); fault.fixture = fixture;
    fault.original_fd = -1; fault.current_fd = -1; fault.new_fd = -1; fault.stderr_fd = -1;
    fault.cause = EIO;
}

static bool fail_at(vireo_log_stage_t stage) {
    if (fault.failure != stage) { return false; }
    errno = fault.cause; return true;
}

static int duplicate_test(void) {
    fault.stderr_fd = open(fault.fixture->capture, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    return fault.stderr_fd;
}

static int open_file_test(int directory_fd) {
    fault.original_fd = vireo_log_system_ops.open_file(directory_fd);
    fault.current_fd = fault.original_fd;
    return fault.original_fd;
}

static int inspect_test(int fd, struct stat *info) {
    ++fault.inspections; event('I');
    if (fail_at(fd == fault.new_fd ? VIREO_LOG_STAGE_CHECK_NEW_FILE : VIREO_LOG_STAGE_FILE_SIZE)) { return -1; }
    int result = vireo_log_system_ops.inspect_file(fd, info);
    if (result == 0) {
        if (fault.negative_size && fd != fault.new_fd) { info->st_size = (off_t)-1; }
        if (fd == fault.new_fd && fault.invalid_new != 0) {
            if (fault.invalid_new == 1) { info->st_mode |= S_IWOTH; }
            else { info->st_size = 1; }
        }
    }
    return result;
}

static int entry_test(int directory_fd, bool archive, struct stat *info) {
    event(archive ? 'A' : 'C');
    if (fail_at(archive ? VIREO_LOG_STAGE_CHECK_ARCHIVE : VIREO_LOG_STAGE_CHECK_CURRENT_ENTRY)) { return -1; }
    int result = vireo_log_system_ops.inspect_entry(directory_fd, archive, info);
    if (result == 0 && archive && fault.wrong_owner) {
        info->st_uid = geteuid() == (uid_t)0 ? (uid_t)1 : (uid_t)0;
    }
    if (result == 0 && !archive && fault.wrong_source) { info->st_mode |= S_IWOTH; }
    return result;
}

static int sync_test(int fd) {
    ++fault.syncs; event('Y');
    if (fd == fault.new_fd) { ++fault.new_syncs; }
    return fail_at(VIREO_LOG_STAGE_SYNC_FILE) ? -1 : vireo_log_system_ops.sync_file(fd);
}

static int rename_test(int directory_fd) {
    ++fault.renames; event('R');
    return fail_at(VIREO_LOG_STAGE_RENAME_FILE) ? -1 : vireo_log_system_ops.rename_file(directory_fd);
}

static int open_new_test(int directory_fd) {
    ++fault.opens; event('N');
    if (fail_at(VIREO_LOG_STAGE_OPEN_NEW_FILE)) { return -1; }
    if (fault.conflict == 1) {
        if (make_file(fault.fixture->file, "racer") != 0) { errno = EIO; return -1; }
    } else if (fault.conflict == 2 && symlink(fault.fixture->other, fault.fixture->file) != 0) {
        return -1;
    }
    fault.new_fd = vireo_log_system_ops.open_new_file(directory_fd);
    if (fault.new_fd >= 0) { fault.current_fd = fault.new_fd; }
    return fault.new_fd;
}

static int close_test(int fd) {
    ++fault.closes; event('X');
    if (fd == fault.original_fd) { ++fault.old_closes; }
    if (fd == fault.new_fd) { ++fault.new_closes; }
    int result = vireo_log_system_ops.close_fd(fd); /* 注入失败也实际消费fd。 */
    if (result != 0) { return result; }
    if (fd == fault.original_fd && fail_at(VIREO_LOG_STAGE_CLOSE_OLD_FILE)) { return -1; }
    if (fd == fault.new_fd && fault.cleanup_error) { errno = EIO; return -1; }
    return 0;
}

static int lock_test(pthread_mutex_t *mutex) {
    return fault.lock_error != 0 ? fault.lock_error : vireo_log_system_ops.lock_mutex(mutex);
}

static int unlock_test(pthread_mutex_t *mutex) {
    int result = vireo_log_system_ops.unlock_mutex(mutex);
    return result != 0 ? result : fault.unlock_error;
}

static int time_test(vireo_log_timestamp_t *out_time) {
    *out_time = (vireo_log_timestamp_t){2026, 10, 1, 10, 20, 30, UINT32_C(123456789)};
    return 0;
}
static uint64_t tid_test(void) { return UINT64_C(4127); }

static ssize_t write_test(int fd, void const *data, size_t size) {
    bool file = fd == fault.current_fd;
    if (file) { ++fault.file_writes; } else { ++fault.stderr_writes; }
    event(file ? 'F' : 'S');
    int error = file ? fault.file_error : fault.stderr_error;
    if (error != 0) { errno = error; return -1; }
    return vireo_log_system_ops.write_fd(fd, data, size);
}

static vireo_log_ops_t test_ops(void) {
    vireo_log_ops_t ops = vireo_log_system_ops;
    ops.duplicate_stderr = duplicate_test; ops.open_file = open_file_test;
    ops.inspect_file = inspect_test; ops.inspect_entry = entry_test; ops.sync_file = sync_test;
    ops.rename_file = rename_test; ops.open_new_file = open_new_test; ops.close_fd = close_test;
    ops.lock_mutex = lock_test; ops.unlock_mutex = unlock_test;
    ops.read_time = time_test; ops.thread_id = tid_test; ops.write_fd = write_test;
    return ops;
}

static int create_test(fixture_t const *fixture, unsigned sinks, vireo_log_t **logger) {
    vireo_log_options_t options = {.directory = (sinks & 1U) != 0 ? fixture->directory : NULL,
        .to_stderr = (sinks & 2U) != 0, .max_file_size_bytes = VIREO_LOG_MIN_FILE_SIZE_BYTES};
    vireo_log_ops_t ops = test_ops();
    CHECK(vireo_log_create_with_ops(&options, logger, NULL, &ops) == VIREO_OK);
    fault.inspections = 0; fault.event_size = 0;
    return 0;
}

static int expect_error(vireo_log_error_t const *error, vireo_log_sink_t sink,
                        vireo_log_stage_t stage, int cause) {
    CHECK(error->sink == sink && error->stage == stage && error->system_errno == cause);
    return 0;
}

static int flush_expected(vireo_log_t *logger, vireo_result_t result,
                          vireo_log_sink_t sink, vireo_log_stage_t stage, int cause) {
    vireo_log_error_t error = {VIREO_LOG_SINK_STDERR, VIREO_LOG_STAGE_WRITE, 999};
    errno = EDOM; CHECK(vireo_log_flush(logger, &error) == result && errno == EDOM);
    return expect_error(&error, sink, stage, cause);
}

static int emit_expected(vireo_log_t *logger, vireo_result_t result,
                         vireo_log_sink_t sink, vireo_log_stage_t stage, int cause) {
    vireo_log_record_t record = record_normal(); vireo_log_error_t error = {0};
    errno = EDOM; CHECK(vireo_log_emit(logger, &record, &error) == result && errno == EDOM);
    return expect_error(&error, sink, stage, cause);
}

static int finish(fixture_t const *fixture, vireo_log_t **logger, size_t baseline) {
    fault.failure = VIREO_LOG_STAGE_NONE; fault.cleanup_error = false; fault.unlock_error = 0;
    errno = EDOM; CHECK(vireo_log_destroy(logger, NULL) == VIREO_OK && *logger == NULL && errno == EDOM);
    CHECK(fd_count() == baseline); return fixture_end(fixture);
}

static int check_flush_combinations(void) {
    CHECK(flush_expected(NULL, VIREO_RESULT_INVALID_ARGUMENT, VIREO_LOG_SINK_NONE, VIREO_LOG_STAGE_VALIDATE, 0) == 0);
    errno = EBUSY; CHECK(vireo_log_flush(NULL, NULL) == VIREO_RESULT_INVALID_ARGUMENT && errno == EBUSY);
    for (unsigned sinks = 1; sinks <= 3; ++sinks) {
        fixture_t fixture; CHECK(fixture_start(&fixture) == 0); reset(&fixture);
        size_t baseline = fd_count(); vireo_log_t *logger = NULL;
        CHECK(create_test(&fixture, sinks, &logger) == 0);
        CHECK(flush_expected(logger, VIREO_OK, VIREO_LOG_SINK_NONE, VIREO_LOG_STAGE_NONE, 0) == 0);
        CHECK(vireo_log_flush(logger, NULL) == VIREO_OK);
        CHECK(fault.syncs == ((sinks & 1U) != 0 ? 2U : 0U));
        CHECK(fault.file_writes == 0 && fault.stderr_writes == 0 && fault.inspections == 0);
        CHECK(fault.renames == 0 && fault.opens == 0);
        CHECK(finish(&fixture, &logger, baseline) == 0);
    }
    return 0;
}

static int check_flush_failure(void) {
    fixture_t fixture; CHECK(fixture_start(&fixture) == 0); reset(&fixture);
    size_t baseline = fd_count(); vireo_log_t *logger = NULL;
    CHECK(create_test(&fixture, 3, &logger) == 0);
    fault.failure = VIREO_LOG_STAGE_SYNC_FILE; fault.cause = ENOSPC;
    CHECK(flush_expected(logger, VIREO_RESULT_IO, VIREO_LOG_SINK_FILE, VIREO_LOG_STAGE_SYNC_FILE, ENOSPC) == 0);
    fault.failure = VIREO_LOG_STAGE_NONE;
    CHECK(flush_expected(logger, VIREO_RESULT_IO, VIREO_LOG_SINK_FILE, VIREO_LOG_STAGE_SYNC_FILE, ENOSPC) == 0);
    errno = EDOM; CHECK(vireo_log_flush(logger, NULL) == VIREO_RESULT_IO && errno == EDOM);
    CHECK(emit_expected(logger, VIREO_RESULT_IO, VIREO_LOG_SINK_FILE, VIREO_LOG_STAGE_SYNC_FILE, ENOSPC) == 0);
    CHECK(fault.syncs == 1 && fault.inspections == 0 && fault.file_writes == 0);
    CHECK(expect_content(fixture.file, "", 0) == 0);
    CHECK(expect_content(fixture.capture, golden, sizeof(golden) - 1) == 0);
    return finish(&fixture, &logger, baseline);
}

static int check_cached_priority(void) {
    fixture_t fixture; CHECK(fixture_start(&fixture) == 0); reset(&fixture);
    size_t baseline = fd_count(); vireo_log_t *logger = NULL;
    CHECK(create_test(&fixture, 3, &logger) == 0);
    fault.stderr_error = EPIPE;
    CHECK(emit_expected(logger, VIREO_RESULT_IO, VIREO_LOG_SINK_STDERR, VIREO_LOG_STAGE_WRITE, EPIPE) == 0);
    CHECK(flush_expected(logger, VIREO_RESULT_IO, VIREO_LOG_SINK_STDERR, VIREO_LOG_STAGE_WRITE, EPIPE) == 0);
    CHECK(fault.syncs == 1); /* stderr已失败不阻止健康file同步。 */
    fault.failure = VIREO_LOG_STAGE_SYNC_FILE; fault.cause = EDQUOT;
    CHECK(flush_expected(logger, VIREO_RESULT_IO, VIREO_LOG_SINK_FILE, VIREO_LOG_STAGE_SYNC_FILE, EDQUOT) == 0);
    fault.failure = VIREO_LOG_STAGE_NONE; fault.stderr_error = 0;
    CHECK(emit_expected(logger, VIREO_RESULT_IO, VIREO_LOG_SINK_FILE, VIREO_LOG_STAGE_SYNC_FILE, EDQUOT) == 0);
    CHECK(fault.file_writes == 1 && fault.stderr_writes == 1 && fault.syncs == 2);
    return finish(&fixture, &logger, baseline);
}

static int check_write_failure_flush(void) {
    fixture_t fixture; CHECK(fixture_start(&fixture) == 0); reset(&fixture);
    size_t baseline = fd_count(); vireo_log_t *logger = NULL;
    CHECK(create_test(&fixture, 3, &logger) == 0); fault.file_error = ENOSPC;
    CHECK(emit_expected(logger, VIREO_RESULT_IO, VIREO_LOG_SINK_FILE, VIREO_LOG_STAGE_WRITE, ENOSPC) == 0);
    fault.file_error = 0;
    CHECK(flush_expected(logger, VIREO_RESULT_IO, VIREO_LOG_SINK_FILE, VIREO_LOG_STAGE_WRITE, ENOSPC) == 0);
    CHECK(fault.syncs == 0); return finish(&fixture, &logger, baseline);
}

static int check_flush_mutex(void) {
    fixture_t fixture; CHECK(fixture_start(&fixture) == 0); reset(&fixture);
    size_t baseline = fd_count(); vireo_log_t *logger = NULL;
    CHECK(create_test(&fixture, 1, &logger) == 0);
    fault.lock_error = EDEADLK;
    CHECK(flush_expected(logger, VIREO_RESULT_INTERNAL, VIREO_LOG_SINK_NONE, VIREO_LOG_STAGE_LOCK, EDEADLK) == 0);
    CHECK(fault.syncs == 0); fault.lock_error = 0; fault.unlock_error = EPERM;
    CHECK(flush_expected(logger, VIREO_RESULT_INTERNAL, VIREO_LOG_SINK_NONE, VIREO_LOG_STAGE_UNLOCK, EPERM) == 0);
    fault.failure = VIREO_LOG_STAGE_SYNC_FILE; fault.cause = EIO;
    CHECK(flush_expected(logger, VIREO_RESULT_IO, VIREO_LOG_SINK_FILE, VIREO_LOG_STAGE_SYNC_FILE, EIO) == 0);
    CHECK(fault.syncs == 2); return finish(&fixture, &logger, baseline);
}

static int check_threshold(void) {
    fixture_t fixture; CHECK(fixture_start(&fixture) == 0); reset(&fixture);
    size_t baseline = fd_count(); vireo_log_t *logger = NULL;
    CHECK(create_test(&fixture, 3, &logger) == 0);
    CHECK(set_size(fixture.file, VIREO_LOG_MIN_FILE_SIZE_BYTES - (uint64_t)(sizeof(golden) - 1)) == 0);
    struct stat before, after, archive;
    CHECK(fstat(fault.original_fd, &before) == 0);
    CHECK(emit_expected(logger, VIREO_OK, VIREO_LOG_SINK_NONE, VIREO_LOG_STAGE_NONE, 0) == 0);
    CHECK(stat(fixture.file, &after) == 0 && (uint64_t)after.st_size == VIREO_LOG_MIN_FILE_SIZE_BYTES);
    CHECK(after.st_ino == before.st_ino && fault.renames == 0 && fault.syncs == 0);
    CHECK(lstat(fixture.archive, &archive) == -1 && errno == ENOENT);
    fault.event_size = 0;
    CHECK(emit_expected(logger, VIREO_OK, VIREO_LOG_SINK_NONE, VIREO_LOG_STAGE_NONE, 0) == 0);
    CHECK(fault.event_size == 10 && memcmp(fault.events, "ICAYRNIXFS", 10) == 0);
    CHECK(stat(fixture.file, &after) == 0 && stat(fixture.archive, &archive) == 0);
    CHECK(archive.st_ino == before.st_ino && after.st_ino != before.st_ino);
    CHECK((uint64_t)archive.st_size == VIREO_LOG_MIN_FILE_SIZE_BYTES);
    CHECK(fault.old_closes == 1 && fault.new_closes == 0 && fault.opens == 1 && fault.renames == 1);
    CHECK((fcntl(fault.new_fd, F_GETFD) & FD_CLOEXEC) != 0);
    CHECK((fcntl(fault.new_fd, F_GETFL) & O_APPEND) != 0 && (after.st_mode & 0777) == 0640);
    char *data = NULL; size_t size = 0; CHECK(read_file(fixture.archive, &data, &size) == 0);
    CHECK(memcmp(data + size - (sizeof(golden) - 1), golden, sizeof(golden) - 1) == 0); free(data);
    CHECK(expect_content(fixture.file, golden, sizeof(golden) - 1) == 0);
    CHECK(fd_count() == baseline + 3);
    return finish(&fixture, &logger, baseline);
}

static int check_existing_oversize(void) {
    fixture_t fixture; CHECK(fixture_start(&fixture) == 0); reset(&fixture);
    CHECK(make_file(fixture.file, "original") == 0);
    CHECK(set_size(fixture.file, VIREO_LOG_MIN_FILE_SIZE_BYTES + 123) == 0);
    size_t baseline = fd_count(); vireo_log_t *logger = NULL;
    CHECK(create_test(&fixture, 1, &logger) == 0);
    CHECK(emit_expected(logger, VIREO_OK, VIREO_LOG_SINK_NONE, VIREO_LOG_STAGE_NONE, 0) == 0);
    struct stat archive; CHECK(stat(fixture.archive, &archive) == 0);
    CHECK((uint64_t)archive.st_size == VIREO_LOG_MIN_FILE_SIZE_BYTES + 123);
    CHECK(expect_content(fixture.file, golden, sizeof(golden) - 1) == 0);
    return finish(&fixture, &logger, baseline);
}

static int check_repeated_rotation(void) {
    fixture_t fixture; CHECK(fixture_start(&fixture) == 0); reset(&fixture);
    CHECK(make_file(fixture.archive, "older history") == 0);
    int held = open(fixture.archive, O_RDONLY | O_CLOEXEC); CHECK(held >= 0);
    size_t baseline = fd_count(); vireo_log_t *logger = NULL;
    CHECK(create_test(&fixture, 1, &logger) == 0);
    CHECK(set_size(fixture.file, VIREO_LOG_MIN_FILE_SIZE_BYTES) == 0);
    CHECK(emit_expected(logger, VIREO_OK, VIREO_LOG_SINK_NONE, VIREO_LOG_STAGE_NONE, 0) == 0);
    struct stat info; CHECK(fstat(held, &info) == 0 && info.st_nlink == 0); /* 仅替换明确归档。 */
    CHECK(close(held) == 0); --baseline;
    CHECK(stat(fixture.file, &info) == 0); ino_t second = info.st_ino;
    CHECK(set_size(fixture.file, VIREO_LOG_MIN_FILE_SIZE_BYTES) == 0);
    CHECK(emit_expected(logger, VIREO_OK, VIREO_LOG_SINK_NONE, VIREO_LOG_STAGE_NONE, 0) == 0);
    CHECK(stat(fixture.archive, &info) == 0 && info.st_ino == second);
    CHECK(fault.renames == 2 && fault.opens == 2 && fault.old_closes == 1);
    char *data = NULL; size_t size = 0; CHECK(read_file(fixture.archive, &data, &size) == 0);
    CHECK((uint64_t)size == VIREO_LOG_MIN_FILE_SIZE_BYTES && memcmp(data, golden, sizeof(golden) - 1) == 0);
    free(data); CHECK(expect_content(fixture.file, golden, sizeof(golden) - 1) == 0);
    return finish(&fixture, &logger, baseline);
}

static int check_runtime_size(void) {
    for (unsigned kind = 0; kind < 3; ++kind) {
        fixture_t fixture; CHECK(fixture_start(&fixture) == 0); reset(&fixture);
        size_t baseline = fd_count(); vireo_log_t *logger = NULL;
        CHECK(create_test(&fixture, 3, &logger) == 0);
        int cause = kind == 0 ? EBADF : kind == 1 ? EFBIG : EPERM;
        if (kind == 0) { fault.failure = VIREO_LOG_STAGE_FILE_SIZE; fault.cause = cause; }
        else if (kind == 1) { fault.negative_size = true; }
        else { CHECK(chmod(fixture.file, 0666) == 0); }
        CHECK(emit_expected(logger, VIREO_RESULT_IO, VIREO_LOG_SINK_FILE, VIREO_LOG_STAGE_FILE_SIZE, cause) == 0);
        CHECK(fault.file_writes == 0 && fault.renames == 0 && fault.syncs == 0);
        CHECK(expect_content(fixture.capture, golden, sizeof(golden) - 1) == 0);
        CHECK(finish(&fixture, &logger, baseline) == 0);
    }
    return 0;
}

static int check_stage_failures(void) {
    vireo_log_stage_t const stages[] = {VIREO_LOG_STAGE_CHECK_CURRENT_ENTRY, VIREO_LOG_STAGE_CHECK_ARCHIVE,
        VIREO_LOG_STAGE_SYNC_FILE, VIREO_LOG_STAGE_RENAME_FILE, VIREO_LOG_STAGE_OPEN_NEW_FILE,
        VIREO_LOG_STAGE_CHECK_NEW_FILE, VIREO_LOG_STAGE_CLOSE_OLD_FILE};
    int const causes[] = {EACCES, EACCES, EINTR, ENOSPC, EMFILE, EIO, EINTR};
    for (size_t i = 0; i < sizeof(stages) / sizeof(stages[0]); ++i) {
        fixture_t fixture; CHECK(fixture_start(&fixture) == 0); reset(&fixture);
        size_t baseline = fd_count(); vireo_log_t *logger = NULL;
        CHECK(create_test(&fixture, 3, &logger) == 0);
        CHECK(set_size(fixture.file, VIREO_LOG_MIN_FILE_SIZE_BYTES) == 0);
        fault.failure = stages[i]; fault.cause = causes[i];
        CHECK(emit_expected(logger, VIREO_RESULT_IO, VIREO_LOG_SINK_FILE, stages[i], causes[i]) == 0);
        CHECK(fd_count() == baseline + 3 && fault.file_writes == 0 && fault.stderr_writes == 1);
        if (stages[i] == VIREO_LOG_STAGE_OPEN_NEW_FILE) {
            CHECK(access(fixture.file, F_OK) == -1 && errno == ENOENT);
            struct stat old; CHECK(fstat(fault.original_fd, &old) == 0 && old.st_nlink == 1);
            struct stat archive; CHECK(stat(fixture.archive, &archive) == 0 && old.st_ino == archive.st_ino);
        }
        if (stages[i] == VIREO_LOG_STAGE_CHECK_NEW_FILE) { CHECK(fault.new_closes == 1 && fault.old_closes == 0); }
        if (stages[i] == VIREO_LOG_STAGE_CLOSE_OLD_FILE) {
            CHECK(fault.old_closes == 1 && fault.new_closes == 0 && fcntl(fault.new_fd, F_GETFD) >= 0);
            CHECK(expect_content(fixture.file, "", 0) == 0);
        }
        unsigned inspections = fault.inspections, syncs = fault.syncs, opens = fault.opens, renames = fault.renames;
        fault.failure = VIREO_LOG_STAGE_NONE;
        CHECK(emit_expected(logger, VIREO_RESULT_IO, VIREO_LOG_SINK_FILE, stages[i], causes[i]) == 0);
        CHECK(flush_expected(logger, VIREO_RESULT_IO, VIREO_LOG_SINK_FILE, stages[i], causes[i]) == 0);
        errno = EDOM; CHECK(vireo_log_flush(logger, NULL) == VIREO_RESULT_IO && errno == EDOM);
        CHECK(fault.inspections == inspections && fault.syncs == syncs && fault.opens == opens && fault.renames == renames);
        CHECK(fault.stderr_writes == 2 && fault.file_writes == 0);
        CHECK(finish(&fixture, &logger, baseline) == 0);
    }
    return 0;
}

static int check_new_file_policy(void) {
    for (unsigned kind = 1; kind <= 2; ++kind) {
        fixture_t fixture; CHECK(fixture_start(&fixture) == 0); reset(&fixture);
        size_t baseline = fd_count(); vireo_log_t *logger = NULL;
        CHECK(create_test(&fixture, 3, &logger) == 0);
        CHECK(set_size(fixture.file, VIREO_LOG_MIN_FILE_SIZE_BYTES) == 0);
        fault.invalid_new = kind; fault.cleanup_error = true;
        CHECK(emit_expected(logger, VIREO_RESULT_IO, VIREO_LOG_SINK_FILE, VIREO_LOG_STAGE_CHECK_NEW_FILE, EPERM) == 0);
        CHECK(fault.new_closes == 1 && fault.old_closes == 0 && fd_count() == baseline + 3);
        CHECK(expect_content(fixture.file, "", 0) == 0); /* 新检查首错不被close错误覆盖。 */
        CHECK(finish(&fixture, &logger, baseline) == 0);
    }
    return 0;
}

static int check_archive_policy(void) {
    mode_t const forbidden_modes[] = {0700, 0620, 0604, 0602};
    for (unsigned kind = 0; kind < 10; ++kind) {
        fixture_t fixture; CHECK(fixture_start(&fixture) == 0); reset(&fixture);
        CHECK(make_file(fixture.other, "untouched") == 0);
        if (kind == 0) { CHECK(symlink(fixture.other, fixture.archive) == 0); }
        else if (kind == 1) { CHECK(mkfifo(fixture.archive, 0600) == 0); }
        else if (kind == 2) { CHECK(mkdir(fixture.archive, 0700) == 0); }
        else if (kind == 3) { CHECK(link(fixture.other, fixture.archive) == 0); }
        else { CHECK(make_file(fixture.archive, "old") == 0); }
        if (kind == 4) { CHECK(chmod(fixture.archive, 0666) == 0); }
        if (kind == 5) { fault.wrong_owner = true; }
        if (kind >= 6) { CHECK(chmod(fixture.archive, forbidden_modes[kind - 6]) == 0); }
        size_t baseline = fd_count(); vireo_log_t *logger = NULL;
        CHECK(create_test(&fixture, 3, &logger) == 0);
        CHECK(set_size(fixture.file, VIREO_LOG_MIN_FILE_SIZE_BYTES) == 0);
        CHECK(emit_expected(logger, VIREO_RESULT_IO, VIREO_LOG_SINK_FILE, VIREO_LOG_STAGE_CHECK_ARCHIVE, EPERM) == 0);
        CHECK(fault.renames == 0 && fault.opens == 0 && fault.syncs == 0);
        CHECK(expect_content(fixture.other, "untouched", 9) == 0);
        struct stat info; CHECK(lstat(fixture.archive, &info) == 0);
        if (kind == 0) { CHECK(S_ISLNK(info.st_mode)); }
        if (kind == 1) { CHECK(S_ISFIFO(info.st_mode)); }
        if (kind == 2) { CHECK(S_ISDIR(info.st_mode)); CHECK(rmdir(fixture.archive) == 0); }
        CHECK(finish(&fixture, &logger, baseline) == 0);
    }
    return 0;
}

static int check_source_identity(void) {
    for (unsigned kind = 0; kind < 3; ++kind) {
        fixture_t fixture; CHECK(fixture_start(&fixture) == 0); reset(&fixture);
        size_t baseline = fd_count(); vireo_log_t *logger = NULL;
        CHECK(create_test(&fixture, 3, &logger) == 0);
        CHECK(set_size(fixture.file, VIREO_LOG_MIN_FILE_SIZE_BYTES) == 0);
        if (kind < 2) {
            CHECK(rename(fixture.file, fixture.other) == 0);
            if (kind == 0) { CHECK(make_file(fixture.file, "replacement") == 0); }
            else { CHECK(symlink(fixture.other, fixture.file) == 0); }
        } else { fault.wrong_source = true; }
        CHECK(emit_expected(logger, VIREO_RESULT_IO, VIREO_LOG_SINK_FILE, VIREO_LOG_STAGE_CHECK_CURRENT_ENTRY, EPERM) == 0);
        CHECK(fault.renames == 0 && fault.file_writes == 0);
        if (kind == 0) { CHECK(expect_content(fixture.file, "replacement", 11) == 0); }
        CHECK(finish(&fixture, &logger, baseline) == 0);
    }
    return 0;
}

static int check_source_links(void) {
    fixture_t fixture; CHECK(fixture_start(&fixture) == 0); reset(&fixture);
    size_t baseline = fd_count(); vireo_log_t *logger = NULL;
    CHECK(create_test(&fixture, 3, &logger) == 0);
    CHECK(link(fixture.file, fixture.other) == 0);
    CHECK(emit_expected(logger, VIREO_RESULT_IO, VIREO_LOG_SINK_FILE, VIREO_LOG_STAGE_FILE_SIZE, EPERM) == 0);
    CHECK(fault.file_writes == 0 && fault.renames == 0); return finish(&fixture, &logger, baseline);
}

static int check_exclusive_create(void) {
    for (unsigned kind = 1; kind <= 2; ++kind) {
        fixture_t fixture; CHECK(fixture_start(&fixture) == 0); reset(&fixture);
        CHECK(make_file(fixture.other, "untouched") == 0);
        size_t baseline = fd_count(); vireo_log_t *logger = NULL;
        CHECK(create_test(&fixture, 3, &logger) == 0);
        CHECK(set_size(fixture.file, VIREO_LOG_MIN_FILE_SIZE_BYTES) == 0); fault.conflict = kind;
        CHECK(emit_expected(logger, VIREO_RESULT_IO, VIREO_LOG_SINK_FILE, VIREO_LOG_STAGE_OPEN_NEW_FILE, EEXIST) == 0);
        CHECK(fault.old_closes == 0 && fault.new_closes == 0 && fd_count() == baseline + 3);
        CHECK(expect_content(fixture.other, "untouched", 9) == 0);
        if (kind == 1) { CHECK(expect_content(fixture.file, "racer", 5) == 0); }
        else { struct stat info; CHECK(lstat(fixture.file, &info) == 0 && S_ISLNK(info.st_mode)); }
        CHECK(finish(&fixture, &logger, baseline) == 0);
    }
    return 0;
}

static int check_null_diagnostic(void) {
    fixture_t fixture; CHECK(fixture_start(&fixture) == 0); reset(&fixture);
    size_t baseline = fd_count(); vireo_log_t *logger = NULL;
    CHECK(create_test(&fixture, 3, &logger) == 0);
    CHECK(set_size(fixture.file, VIREO_LOG_MIN_FILE_SIZE_BYTES) == 0);
    fault.failure = VIREO_LOG_STAGE_OPEN_NEW_FILE; fault.cause = EMFILE;
    vireo_log_record_t record = record_normal();
    errno = EDOM; CHECK(vireo_log_emit(logger, &record, NULL) == VIREO_RESULT_IO && errno == EDOM);
    fault.failure = VIREO_LOG_STAGE_NONE;
    CHECK(flush_expected(logger, VIREO_RESULT_IO, VIREO_LOG_SINK_FILE, VIREO_LOG_STAGE_OPEN_NEW_FILE, EMFILE) == 0);
    CHECK(expect_content(fixture.capture, golden, sizeof(golden) - 1) == 0);
    CHECK(fault.file_writes == 0 && fault.opens == 1); return finish(&fixture, &logger, baseline);
}

static int check_ops_validation(void) {
    fixture_t fixture; CHECK(fixture_start(&fixture) == 0); reset(&fixture);
    size_t baseline = fd_count(); vireo_log_options_t options = {fixture.directory, false, VIREO_LOG_MIN_FILE_SIZE_BYTES};
    for (unsigned kind = 0; kind < 3; ++kind) {
        vireo_log_ops_t ops = test_ops(); vireo_log_t *logger = NULL;
        if (kind == 0) { ops.inspect_entry = NULL; }
        else if (kind == 1) { ops.rename_file = NULL; }
        else { ops.open_new_file = NULL; }
        CHECK(vireo_log_create_with_ops(&options, &logger, NULL, &ops) == VIREO_RESULT_INVALID_ARGUMENT);
        CHECK(logger == NULL && fd_count() == baseline && access(fixture.file, F_OK) == -1 && errno == ENOENT);
    }
    vireo_log_ops_t ops = test_ops(); vireo_log_t *logger = NULL;
    CHECK(vireo_log_create_with_ops(&options, &logger, NULL, &ops) == VIREO_OK);
    ops.inspect_entry = NULL; ops.rename_file = NULL; ops.open_new_file = NULL;
    CHECK(set_size(fixture.file, VIREO_LOG_MIN_FILE_SIZE_BYTES) == 0);
    CHECK(emit_expected(logger, VIREO_OK, VIREO_LOG_SINK_NONE, VIREO_LOG_STAGE_NONE, 0) == 0); /* 表已按值复制。 */
    return finish(&fixture, &logger, baseline);
}

static int check_stderr_only_failure(void) {
    fixture_t fixture; CHECK(fixture_start(&fixture) == 0); reset(&fixture);
    size_t baseline = fd_count(); vireo_log_t *logger = NULL;
    CHECK(create_test(&fixture, 2, &logger) == 0); fault.stderr_error = EPIPE;
    CHECK(emit_expected(logger, VIREO_RESULT_IO, VIREO_LOG_SINK_STDERR, VIREO_LOG_STAGE_WRITE, EPIPE) == 0);
    fault.stderr_error = 0;
    CHECK(flush_expected(logger, VIREO_RESULT_IO, VIREO_LOG_SINK_STDERR, VIREO_LOG_STAGE_WRITE, EPIPE) == 0);
    CHECK(fault.syncs == 0 && fault.inspections == 0 && fault.renames == 0);
    return finish(&fixture, &logger, baseline);
}

static int check_invalid_before_rotation(void) {
    fixture_t fixture; CHECK(fixture_start(&fixture) == 0); reset(&fixture);
    size_t baseline = fd_count(); vireo_log_t *logger = NULL;
    CHECK(create_test(&fixture, 3, &logger) == 0);
    CHECK(set_size(fixture.file, VIREO_LOG_MIN_FILE_SIZE_BYTES) == 0);
    vireo_log_record_t record = record_normal(); record.message.size = VIREO_LOG_MAX_MESSAGE_SIZE + 1;
    vireo_log_error_t error = {0}; errno = EDOM;
    CHECK(vireo_log_emit(logger, &record, &error) == VIREO_RESULT_RANGE && errno == EDOM);
    CHECK(expect_error(&error, VIREO_LOG_SINK_NONE, VIREO_LOG_STAGE_VALIDATE, 0) == 0);
    CHECK(fault.inspections == 0 && fault.renames == 0 && fault.file_writes == 0 && fault.stderr_writes == 0);
    CHECK(emit_expected(logger, VIREO_OK, VIREO_LOG_SINK_NONE, VIREO_LOG_STAGE_NONE, 0) == 0);
    CHECK(fault.renames == 1); return finish(&fixture, &logger, baseline);
}

static int check_rotation_umask(void) {
    fixture_t fixture; CHECK(fixture_start(&fixture) == 0); reset(&fixture);
    size_t baseline = fd_count(); vireo_log_t *logger = NULL;
    CHECK(create_test(&fixture, 1, &logger) == 0);
    CHECK(set_size(fixture.file, VIREO_LOG_MIN_FILE_SIZE_BYTES) == 0);
    mode_t previous = umask(0077);
    int result = emit_expected(logger, VIREO_OK, VIREO_LOG_SINK_NONE, VIREO_LOG_STAGE_NONE, 0);
    (void)umask(previous); CHECK(result == 0);
    struct stat current, archive; CHECK(stat(fixture.file, &current) == 0 && stat(fixture.archive, &archive) == 0);
    CHECK((current.st_mode & 0777) == 0600 && (archive.st_mode & 0777) == 0640);
    CHECK(expect_content(fixture.file, golden, sizeof(golden) - 1) == 0);
    return finish(&fixture, &logger, baseline);
}

static ssize_t write_chunk(int fd, void const *data, size_t size) {
    return vireo_log_system_ops.write_fd(fd, data, size > 13 ? 13 : size);
}

typedef struct worker {
    vireo_log_t *logger;
    pthread_barrier_t *barrier;
    unsigned index;
    uint64_t tid;
    int failed;
    bool flusher;
    bool expect_file_failure; /* 启动前发布，线程只读；诊断仍各调用局部拥有。 */
} worker_t;

static void *run_worker(void *argument) {
    worker_t *worker = argument;
    worker->tid = (uint64_t)gettid();
    int code = pthread_barrier_wait(worker->barrier);
    if (code != 0 && code != PTHREAD_BARRIER_SERIAL_THREAD) { worker->failed = 1; return NULL; }
    if (worker->flusher) {
        /* 等每个writer首行：健康场景两个flusher共200次sync全验证新fd。 */
        code = pthread_barrier_wait(worker->barrier);
        if (code != 0 && code != PTHREAD_BARRIER_SERIAL_THREAD) { worker->failed = 1; return NULL; }
    }
    for (unsigned i = 0; i < 100; ++i) {
        vireo_log_error_t error = {0}; vireo_result_t result;
        errno = EDOM;
        if (worker->flusher) { result = vireo_log_flush(worker->logger, &error); }
        else {
            vireo_log_record_t record = record_normal();
            record.sequence = worker->index * 100U + i + 1U;
            result = vireo_log_emit(worker->logger, &record, &error);
        }
        if (errno != EDOM) { worker->failed = 1; }
        if (worker->expect_file_failure) {
            if (result != VIREO_RESULT_IO || error.sink != VIREO_LOG_SINK_FILE ||
                error.stage != VIREO_LOG_STAGE_FILE_SIZE || error.system_errno != ENOSPC) { worker->failed = 1; }
        } else if (result != VIREO_OK || error.sink != VIREO_LOG_SINK_NONE ||
                   error.stage != VIREO_LOG_STAGE_NONE || error.system_errno != 0) { worker->failed = 1; }
        if (!worker->flusher && i == 0) {
            code = pthread_barrier_wait(worker->barrier);
            if (code != 0 && code != PTHREAD_BARRIER_SERIAL_THREAD) { worker->failed = 1; }
        }
        if (worker->failed) { break; }
    }
    return NULL;
}

static int check_concurrent_scenario(bool fail_file) {
    fixture_t fixture; CHECK(fixture_start(&fixture) == 0); reset(&fixture);
    size_t baseline = fd_count(); vireo_log_t *logger = NULL;
    vireo_log_options_t options = {fixture.directory, true, VIREO_LOG_MIN_FILE_SIZE_BYTES};
    vireo_log_ops_t ops = test_ops();
    ops.read_time = vireo_log_system_ops.read_time; ops.thread_id = vireo_log_system_ops.thread_id;
    ops.write_fd = write_chunk; ops.lock_mutex = vireo_log_system_ops.lock_mutex;
    ops.unlock_mutex = vireo_log_system_ops.unlock_mutex;
    CHECK(vireo_log_create_with_ops(&options, &logger, NULL, &ops) == VIREO_OK);
    fault.inspections = 0;
    if (fail_file) { fault.failure = VIREO_LOG_STAGE_FILE_SIZE; fault.cause = ENOSPC; }
    else { CHECK(set_size(fixture.file, VIREO_LOG_MIN_FILE_SIZE_BYTES) == 0); }
    pthread_barrier_t barrier; CHECK(pthread_barrier_init(&barrier, NULL, 6) == 0);
    pthread_t threads[6]; worker_t workers[6];
    for (unsigned i = 0; i < 6; ++i) {
        workers[i] = (worker_t){.logger = logger, .barrier = &barrier, .index = i,
            .flusher = i >= 4, .expect_file_failure = fail_file};
        CHECK(pthread_create(&threads[i], NULL, run_worker, &workers[i]) == 0);
    }
    for (unsigned i = 0; i < 6; ++i) { CHECK(pthread_join(threads[i], NULL) == 0 && workers[i].failed == 0); }
    CHECK(pthread_barrier_destroy(&barrier) == 0);
    if (fail_file) {
        CHECK(fault.inspections == 1 && fault.renames == 0 && fault.opens == 0 && fault.syncs == 0);
    } else {
        CHECK(fault.renames == 1 && fault.opens == 1 && fault.syncs == 201 && fault.new_syncs == 200);
    }
    CHECK(vireo_log_destroy(&logger, NULL) == VIREO_OK);
    CHECK(fd_count() == baseline);
    char *data = NULL, *capture = NULL; size_t size = 0, capture_size = 0;
    CHECK(read_file(fixture.file, &data, &size) == 0 && read_file(fixture.capture, &capture, &capture_size) == 0);
    if (fail_file) {
        CHECK(size == 0); free(data); data = capture; size = capture_size; capture = NULL;
    } else { CHECK(size == capture_size && memcmp(data, capture, size) == 0); }
    bool seen[400] = {false}; unsigned previous[4] = {0}; size_t offset = 0; unsigned lines = 0;
    while (offset < size) {
        char *end = memchr(data + offset, '\n', size - offset); CHECK(end != NULL);
        size_t line_size = (size_t)(end - (data + offset)) + 1;
        unsigned year, month, day, hour, minute, second, nanosecond, sequence;
        unsigned long long tid;
        CHECK(sscanf(data + offset,
            "%u-%u-%uT%u:%u:%u.%uZ level=INFO tid=%llu module=\"storage\" connection_id=42 generation=7 sequence=%u",
            &year, &month, &day, &hour, &minute, &second, &nanosecond, &tid, &sequence) == 9);
        CHECK(sequence >= 1 && sequence <= 400 && !seen[sequence - 1]); seen[sequence - 1] = true;
        unsigned index = (sequence - 1U) / 100U;
        CHECK((uint64_t)tid == workers[index].tid && sequence > previous[index]); previous[index] = sequence;
        CHECK(year >= 1970 && year <= 9999 && month <= 12 && day <= 31 &&
              hour <= 23 && minute <= 59 && second <= 59 && nanosecond <= 999999999);
        vireo_log_timestamp_t timestamp = {(uint16_t)year, (uint8_t)month, (uint8_t)day,
            (uint8_t)hour, (uint8_t)minute, (uint8_t)second, (uint32_t)nanosecond};
        vireo_log_record_t record = record_normal(); record.sequence = (uint32_t)sequence;
        char expected[VIREO_LOG_MAX_LINE_SIZE + 1]; size_t expected_size = 0;
        CHECK(vireo_log_format(&record, &timestamp, (uint64_t)tid, expected, sizeof(expected), &expected_size) == VIREO_OK);
        CHECK(expected_size == line_size && memcmp(data + offset, expected, line_size) == 0);
        offset += line_size; ++lines;
    }
    CHECK(lines == 400); free(data); free(capture);
    struct stat archive;
    if (fail_file) { CHECK(lstat(fixture.archive, &archive) == -1 && errno == ENOENT); }
    else { CHECK(stat(fixture.archive, &archive) == 0 && (uint64_t)archive.st_size == VIREO_LOG_MIN_FILE_SIZE_BYTES); }
    return fixture_end(&fixture);
}

static int check_concurrent(void) { return check_concurrent_scenario(false); }
static int check_concurrent_failure(void) { return check_concurrent_scenario(true); }

/* 在关键变更之前等待两个flush已进入真实lock回调；不在变更之后用测试锁
 * 发布logger状态，状态/新fd的可见性仍只能由logger自己的mutex保证。 */
typedef struct transition_control {
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    unsigned warmups, arrivals;
    bool gate, abort, fail_file;
} transition_control_t;

typedef struct transition_worker {
    transition_control_t *control;
    vireo_log_t *logger;
    bool flusher, announce;
    int failed;
} transition_worker_t;

static _Thread_local transition_worker_t *transition_worker;

/* 调用者持有control mutex；有界等待也使回归缺锁等错误不会永久挂住测试。 */
static int transition_wait(transition_control_t *control, unsigned phase) {
    struct timespec deadline;
    if (clock_gettime(CLOCK_REALTIME, &deadline) != 0) { return errno; }
    deadline.tv_sec += 10;
    while (!control->abort && (phase == 0 ? control->warmups < 2 :
           phase == 1 ? !control->gate : control->arrivals < 2)) {
        int code = pthread_cond_timedwait(&control->condition, &control->mutex, &deadline);
        if (code != 0) {
            control->abort = true;
            (void)pthread_cond_broadcast(&control->condition);
            return code;
        }
    }
    return control->abort ? ECANCELED : 0;
}

static int transition_gate(void) {
    transition_control_t *control = transition_worker->control;
    int code = pthread_mutex_lock(&control->mutex);
    if (code != 0) { errno = code; return -1; }
    control->gate = true;
    (void)pthread_cond_broadcast(&control->condition);
    code = transition_wait(control, 2);
    int unlock_code = pthread_mutex_unlock(&control->mutex);
    if (code == 0) { code = unlock_code; }
    if (code != 0) { errno = code; return -1; }
    return 0;
}

static int transition_lock(pthread_mutex_t *mutex) {
    transition_worker_t *worker = transition_worker;
    if (worker != NULL && worker->announce) {
        transition_control_t *control = worker->control;
        int code = pthread_mutex_lock(&control->mutex);
        if (code != 0) { return code; }
        ++control->arrivals;
        worker->announce = false;
        (void)pthread_cond_broadcast(&control->condition);
        code = pthread_mutex_unlock(&control->mutex);
        if (code != 0) { return code; }
    }
    return vireo_log_system_ops.lock_mutex(mutex);
}

static int transition_inspect(int fd, struct stat *info) {
    if (transition_worker != NULL && !transition_worker->flusher &&
        transition_worker->control->fail_file && transition_gate() != 0) { return -1; }
    return inspect_test(fd, info);
}

static int transition_open(int directory_fd) {
    if (transition_gate() != 0) { return -1; }
    return open_new_test(directory_fd);
}

static void *run_transition_worker(void *argument) {
    transition_worker_t *worker = argument;
    transition_control_t *control = worker->control;
    transition_worker = worker;
    if (worker->flusher) {
        /* 两个线程确实先对旧fd完成一次flush，再参加跨过切换点的调用。 */
        worker->failed = flush_expected(worker->logger, VIREO_OK,
            VIREO_LOG_SINK_NONE, VIREO_LOG_STAGE_NONE, 0);
    }
    int code = pthread_mutex_lock(&control->mutex);
    if (code == 0) {
        if (worker->failed) { control->abort = true; }
        if (worker->flusher) { ++control->warmups; }
        (void)pthread_cond_broadcast(&control->condition);
        code = transition_wait(control, worker->flusher ? 1U : 0U);
        int unlock_code = pthread_mutex_unlock(&control->mutex);
        if (code == 0) { code = unlock_code; }
    }
    if (code != 0) { worker->failed = 1; }
    if (!worker->failed) {
        vireo_result_t result = control->fail_file ? VIREO_RESULT_IO : VIREO_OK;
        vireo_log_sink_t sink = control->fail_file ? VIREO_LOG_SINK_FILE : VIREO_LOG_SINK_NONE;
        vireo_log_stage_t stage = control->fail_file ? VIREO_LOG_STAGE_FILE_SIZE : VIREO_LOG_STAGE_NONE;
        int cause = control->fail_file ? ENOSPC : 0;
        if (worker->flusher) {
            worker->announce = true;
            worker->failed = flush_expected(worker->logger, result, sink, stage, cause);
        } else { worker->failed = emit_expected(worker->logger, result, sink, stage, cause); }
    }
    transition_worker = NULL;
    return NULL;
}

static int check_transition_overlap(bool fail_file) {
    fixture_t fixture; CHECK(fixture_start(&fixture) == 0); reset(&fixture);
    size_t baseline = fd_count(); vireo_log_t *logger = NULL;
    vireo_log_options_t options = {fixture.directory, true, VIREO_LOG_MIN_FILE_SIZE_BYTES};
    vireo_log_ops_t ops = test_ops();
    ops.inspect_file = transition_inspect; ops.open_new_file = transition_open;
    ops.lock_mutex = transition_lock; ops.unlock_mutex = vireo_log_system_ops.unlock_mutex;
    ops.write_fd = write_chunk; /* 固定时间/TID便于逐字节golden；真实短写和锁保留。 */
    CHECK(vireo_log_create_with_ops(&options, &logger, NULL, &ops) == VIREO_OK);
    fault.inspections = 0;
    if (fail_file) { fault.failure = VIREO_LOG_STAGE_FILE_SIZE; fault.cause = ENOSPC; }
    else { CHECK(set_size(fixture.file, VIREO_LOG_MIN_FILE_SIZE_BYTES) == 0); }
    transition_control_t control = {.fail_file = fail_file};
    CHECK(pthread_mutex_init(&control.mutex, NULL) == 0);
    CHECK(pthread_cond_init(&control.condition, NULL) == 0);
    pthread_t threads[3]; transition_worker_t workers[3]; unsigned started = 0;
    for (unsigned i = 0; i < 3; ++i) {
        workers[i] = (transition_worker_t){.control = &control, .logger = logger, .flusher = i != 0};
        if (pthread_create(&threads[i], NULL, run_transition_worker, &workers[i]) != 0) {
            CHECK(pthread_mutex_lock(&control.mutex) == 0);
            control.abort = true; CHECK(pthread_cond_broadcast(&control.condition) == 0);
            CHECK(pthread_mutex_unlock(&control.mutex) == 0);
            break;
        }
        ++started;
    }
    int failed = started != 3;
    for (unsigned i = 0; i < started; ++i) {
        CHECK(pthread_join(threads[i], NULL) == 0);
        if (workers[i].failed) { failed = 1; }
    }
    CHECK(pthread_cond_destroy(&control.condition) == 0);
    CHECK(pthread_mutex_destroy(&control.mutex) == 0);
    CHECK(!failed && control.gate && !control.abort && control.warmups == 2 && control.arrivals == 2);
    if (fail_file) {
        CHECK(fault.inspections == 1 && fault.syncs == 2 && fault.new_syncs == 0);
        CHECK(fault.renames == 0 && fault.opens == 0 && fault.old_closes == 0);
        CHECK(expect_content(fixture.file, "", 0) == 0);
        CHECK(access(fixture.archive, F_OK) == -1 && errno == ENOENT);
    } else {
        CHECK(fault.syncs == 5 && fault.new_syncs == 2 && fault.renames == 1 && fault.opens == 1);
        CHECK(fault.old_closes == 1 && fault.new_closes == 0);
        struct stat archive; CHECK(stat(fixture.archive, &archive) == 0);
        CHECK((uint64_t)archive.st_size == VIREO_LOG_MIN_FILE_SIZE_BYTES);
        CHECK(expect_content(fixture.file, golden, sizeof(golden) - 1) == 0);
    }
    CHECK(expect_content(fixture.capture, golden, sizeof(golden) - 1) == 0);
    CHECK(fd_count() == baseline + 3);
    return finish(&fixture, &logger, baseline);
}

static int check_rotation_overlap(void) { return check_transition_overlap(false); }
static int check_failure_overlap(void) { return check_transition_overlap(true); }

static int observe_rotation(void) {
    fixture_t fixture; CHECK(fixture_start(&fixture) == 0); reset(&fixture);
    size_t baseline = fd_count(); vireo_log_t *logger = NULL;
    CHECK(create_test(&fixture, 3, &logger) == 0);
    CHECK(set_size(fixture.file, VIREO_LOG_MIN_FILE_SIZE_BYTES) == 0);
    printf("M4 observation: fd baseline=%zu, live=%zu, old=%d\n", baseline, fd_count(), fault.original_fd);
    CHECK(emit_expected(logger, VIREO_OK, VIREO_LOG_SINK_NONE, VIREO_LOG_STAGE_NONE, 0) == 0);
    printf("M4 observation: new=%d, old close count=%u, live=%zu\n", fault.new_fd, fault.old_closes, fd_count());
    CHECK(flush_expected(logger, VIREO_OK, VIREO_LOG_SINK_NONE, VIREO_LOG_STAGE_NONE, 0) == 0);
    CHECK(finish(&fixture, &logger, baseline) == 0);
    printf("M4 observation: cleanup fd=%zu, original stderr valid=%s\n", fd_count(), fcntl(STDERR_FILENO, F_GETFD) >= 0 ? "yes" : "no");
    return 0;
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--concurrent") == 0) {
        int result = check_concurrent();
        if (result == 0) { result = check_concurrent_failure(); }
        if (result == 0) { result = check_rotation_overlap(); }
        if (result == 0) { result = check_failure_overlap(); }
        if (result == 0) { puts("log rotation: concurrent healthy/FAILED 400+400 records; controlled rotation/first-failure overlap 1+1 records, two flushers passed"); }
        return result;
    }
    if (argc == 2 && strcmp(argv[1], "--observe") == 0) { return observe_rotation(); }
    if (argc != 1) { return 2; }
    mode_t original_umask = umask(0027);
    int (*const tests[])(void) = {check_flush_combinations, check_flush_failure, check_cached_priority,
        check_write_failure_flush, check_flush_mutex, check_threshold, check_existing_oversize,
        check_repeated_rotation, check_runtime_size, check_stage_failures, check_new_file_policy,
        check_archive_policy, check_source_identity, check_source_links, check_exclusive_create,
        check_null_diagnostic, check_ops_validation, check_stderr_only_failure,
        check_invalid_before_rotation, check_rotation_umask, check_concurrent, check_concurrent_failure,
        check_rotation_overlap, check_failure_overlap};
    int result = 0;
    for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); ++i) {
        if (tests[i]() != 0) { result = 1; break; }
    }
    (void)umask(original_umask);
    if (result == 0) { printf("log rotation: %zu groups passed\n", sizeof(tests) / sizeof(tests[0])); }
    return result;
}
