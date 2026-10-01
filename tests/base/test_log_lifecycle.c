/* PROJECT : VIREO -- 008-02 生命周期、真实文件与确定性资源故障测试。 */
#define _POSIX_C_SOURCE 200809L

#include <vireo/base/config.h>
#include <vireo/base/log.h>
#include <base/log_internal.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #condition); \
        return 1; \
    } \
} while (0)

_Static_assert(VIREO_LOG_DIRECTORY_CAPACITY == VIREO_CONFIG_PATH_CAPACITY, "directory compatibility");
_Static_assert(VIREO_LOG_MIN_FILE_SIZE_BYTES == VIREO_CONFIG_MIN_LOG_FILE_SIZE_BYTES, "minimum compatibility");
_Static_assert(VIREO_LOG_MAX_FILE_SIZE_BYTES == VIREO_CONFIG_MAX_LOG_FILE_SIZE_BYTES, "maximum compatibility");

typedef struct fixture {
    char directory[128];
    char file[256];
} fixture_t;

/* 仅统计进程现有 fd，不把扫描 /proc 自己的目录 fd 算入结果。 */
static size_t fd_count(void) {
    DIR *stream = opendir("/proc/self/fd");
    if (stream == NULL) {
        return SIZE_MAX;
    }
    int scan_fd = dirfd(stream);
    size_t count = 0;
    struct dirent *entry;
    while ((entry = readdir(stream)) != NULL) {
        char *end = NULL;
        long number = strtol(entry->d_name, &end, 10);
        if (end != entry->d_name && *end == '\0' && number != scan_fd) {
            ++count;
        }
    }
    if (closedir(stream) != 0) {
        return SIZE_MAX;
    }
    return count;
}

static int fixture_start(fixture_t *fixture) {
    strcpy(fixture->directory, "/tmp/vireo-log-lifecycle-XXXXXX");
    CHECK(mkdtemp(fixture->directory) != NULL);
    int length = snprintf(fixture->file, sizeof(fixture->file), "%s/%s",
                          fixture->directory, VIREO_LOG_FILE_NAME);
    CHECK(length > 0 && (size_t)length < sizeof(fixture->file));
    return 0;
}

/* 只回收本测试明确创建的固定文件和已知空目录，不递归清理任何用户路径。 */
static int fixture_finish(fixture_t const *fixture) {
    int result = unlink(fixture->file);
    CHECK(result == 0 || errno == ENOENT);
    CHECK(rmdir(fixture->directory) == 0);
    return 0;
}

static vireo_log_options_t file_options(fixture_t const *fixture, bool stderr_enabled) {
    return (vireo_log_options_t){.directory = fixture->directory, .to_stderr = stderr_enabled,
                                .max_file_size_bytes = VIREO_LOG_MIN_FILE_SIZE_BYTES};
}

static bool error_none(vireo_log_error_t const *error) {
    return error->sink == VIREO_LOG_SINK_NONE && error->stage == VIREO_LOG_STAGE_NONE &&
           error->system_errno == 0;
}

/* 每个故障测试串行维护自己的状态；生产系统表只读，不被修改。 */
typedef struct fault_state {
    vireo_log_stage_t fail_stage;
    int fail_errno;
    unsigned int close_fail_mask; /* file=1, stderr=2, directory=4；实际 close 后返回错误。 */
    int close_errno;
    int sync_errno;
    bool bad_owner;
    bool bad_links;
    bool reuse_after_close;
    int replacement_fd;
    int file_fd;
    int stderr_fd;
    int directory_fd;
    size_t allocations;
    size_t frees;
    size_t syncs;
    size_t closes;
    char events[128];
    size_t event_size;
    char const *owned_directory;
    size_t directory_size;
} fault_state_t;

static fault_state_t fault;

static void reset_fault(void) {
    fault = (fault_state_t){.fail_errno = ENOSPC, .close_errno = EIO,
                           .file_fd = -1, .stderr_fd = -1, .directory_fd = -1,
                           .replacement_fd = -1};
}

static void event(char tag) {
    if (fault.event_size + 1 < sizeof(fault.events)) {
        fault.events[fault.event_size++] = tag;
        fault.events[fault.event_size] = '\0';
    }
}

static bool fail_at(vireo_log_stage_t stage) {
    if (fault.fail_stage != stage) {
        return false;
    }
    errno = fault.fail_errno;
    return true;
}

static void *test_allocate(size_t size) {
    event('A');
    ++fault.allocations;
    if (fail_at(VIREO_LOG_STAGE_ALLOCATE)) {
        errno = ENOMEM;
        return NULL;
    }
    return vireo_log_system_ops.allocate(size);
}

static void test_deallocate(void *pointer) {
    event('R');
    ++fault.frees;
    vireo_log_system_ops.deallocate(pointer);
}

static int test_duplicate_stderr(void) {
    event('S');
    if (fail_at(VIREO_LOG_STAGE_DUP_STDERR)) {
        return -1;
    }
    fault.stderr_fd = vireo_log_system_ops.duplicate_stderr();
    return fault.stderr_fd;
}

static int test_inspect_stderr(int fd) {
    event('s');
    return fail_at(VIREO_LOG_STAGE_CHECK_STDERR) ? -1 : vireo_log_system_ops.inspect_stderr(fd);
}

static int test_open_directory(char const *directory) {
    event('D');
    fault.owned_directory = directory;
    fault.directory_size = strlen(directory);
    if (fail_at(VIREO_LOG_STAGE_OPEN_DIRECTORY)) {
        return -1;
    }
    fault.directory_fd = vireo_log_system_ops.open_directory(directory);
    return fault.directory_fd;
}

static int test_open_file(int directory_fd) {
    event('F');
    if (fail_at(VIREO_LOG_STAGE_OPEN_FILE)) {
        return -1;
    }
    fault.file_fd = vireo_log_system_ops.open_file(directory_fd);
    return fault.file_fd;
}

static int test_inspect_file(int fd, struct stat *info) {
    event('f');
    if (fail_at(VIREO_LOG_STAGE_CHECK_FILE)) {
        return -1;
    }
    int result = vireo_log_system_ops.inspect_file(fd, info);
    if (result == 0 && fault.bad_owner) {
        info->st_uid = geteuid() == 0 ? (uid_t)1 : (uid_t)0;
    }
    if (result == 0 && fault.bad_links) {
        info->st_nlink = 2;
    }
    return result;
}

static int test_sync_file(int fd) {
    event('Y');
    ++fault.syncs;
    if (fault.sync_errno != 0) {
        errno = fault.sync_errno;
        return -1;
    }
    return vireo_log_system_ops.sync_file(fd);
}

/* 返回故障前先真实释放 fd，忠实模拟 Linux close 的消费语义。 */
static int test_close_fd(int fd) {
    unsigned int mask = fd == fault.file_fd ? 1U : (fd == fault.stderr_fd ? 2U : 4U);
    event(mask == 1U ? 'X' : (mask == 2U ? 'T' : 'Z'));
    ++fault.closes;
    int result = vireo_log_system_ops.close_fd(fd);
    if (result == 0 && (fault.close_fail_mask & mask) != 0) {
        if (fault.reuse_after_close && mask == 1U) {
            fault.replacement_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
        }
        errno = fault.close_errno;
        return -1;
    }
    return result;
}

static vireo_log_ops_t test_ops(void) {
    return (vireo_log_ops_t){.allocate = test_allocate, .deallocate = test_deallocate,
                            .duplicate_stderr = test_duplicate_stderr, .inspect_stderr = test_inspect_stderr,
                            .open_directory = test_open_directory, .open_file = test_open_file,
                            .inspect_file = test_inspect_file, .sync_file = test_sync_file, .close_fd = test_close_fd,
                            .init_mutex = vireo_log_system_ops.init_mutex,
                            .destroy_mutex = vireo_log_system_ops.destroy_mutex,
                            .lock_mutex = vireo_log_system_ops.lock_mutex,
                            .unlock_mutex = vireo_log_system_ops.unlock_mutex,
                            .read_time = vireo_log_system_ops.read_time,
                            .thread_id = vireo_log_system_ops.thread_id,
                            .write_fd = vireo_log_system_ops.write_fd,
                            .inspect_entry = vireo_log_system_ops.inspect_entry,
                            .rename_file = vireo_log_system_ops.rename_file,
                            .open_new_file = vireo_log_system_ops.open_new_file};
}

static int check_sink_combinations(void) {
    for (unsigned int combination = 1; combination <= 3; ++combination) {
        fixture_t fixture;
        CHECK(fixture_start(&fixture) == 0);
        size_t baseline = fd_count();
        CHECK(baseline != SIZE_MAX);
        bool file_enabled = (combination & 1U) != 0;
        vireo_log_options_t options = file_options(&fixture, (combination & 2U) != 0);
        if (!file_enabled) {
            options.directory = NULL;
            options.max_file_size_bytes = UINT64_MAX; /* 未启用 file，必须忽略此值。 */
        }
        vireo_log_t *logger = NULL;
        vireo_log_error_t error = {.stage = VIREO_LOG_STAGE_VALIDATE, .system_errno = 99};
        reset_fault();
        vireo_log_ops_t ops = test_ops();
        errno = EDOM;
        CHECK(vireo_log_create_with_ops(&options, &logger, &error, &ops) == VIREO_OK);
        CHECK(logger != NULL && error_none(&error) && errno == EDOM);
        CHECK(fd_count() == baseline + (file_enabled ? 2U : 0U) + (options.to_stderr ? 1U : 0U));
        CHECK(fault.allocations == 1 && fault.frees == 0);
        if (combination == 3) {
            CHECK(strcmp(fault.events, "ASsDFf") == 0);
        }
        errno = EACCES;
        CHECK(vireo_log_destroy(&logger, &error) == VIREO_OK);
        CHECK(logger == NULL && error_none(&error) && errno == EACCES);
        CHECK(fault.frees == 1 && fault.syncs == (file_enabled ? 1U : 0U));
        CHECK(fd_count() == baseline);
        CHECK(fcntl(STDERR_FILENO, F_GETFD) >= 0);
        CHECK(fixture_finish(&fixture) == 0);
    }
    return 0;
}

static int check_arguments(void) {
    vireo_log_options_t options = {.to_stderr = true};
    vireo_log_t *logger = NULL;
    vireo_log_error_t error;
    errno = EBUSY;
    CHECK(vireo_log_create(NULL, &logger, &error) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(logger == NULL && error.stage == VIREO_LOG_STAGE_VALIDATE && errno == EBUSY);
    CHECK(vireo_log_create(&options, NULL, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(errno == EBUSY);
    CHECK(vireo_log_create(&options, &logger, NULL) == VIREO_OK);
    vireo_log_t *original = logger;
    CHECK(vireo_log_create(&options, &logger, &error) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(logger == original && error.stage == VIREO_LOG_STAGE_VALIDATE);
    CHECK(vireo_log_destroy(&logger, NULL) == VIREO_OK && logger == NULL);
    options.to_stderr = false;
    CHECK(vireo_log_create(&options, &logger, &error) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(logger == NULL && error.stage == VIREO_LOG_STAGE_VALIDATE);
    CHECK(vireo_log_destroy(NULL, &error) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(error.stage == VIREO_LOG_STAGE_VALIDATE && errno == EBUSY);
    CHECK(vireo_log_destroy(&logger, &error) == VIREO_OK && error_none(&error));
    CHECK(vireo_log_destroy(&logger, NULL) == VIREO_OK);
    return 0;
}

static int check_invalid_paths(void) {
    char const *paths[] = {"", "relative", "/tmp\n", "/tmp\t", "/tmp\177"};
    size_t baseline = fd_count();
    CHECK(baseline != SIZE_MAX);
    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); ++i) {
        vireo_log_options_t options = {.directory = paths[i], .to_stderr = true,
                                      .max_file_size_bytes = VIREO_LOG_MIN_FILE_SIZE_BYTES};
        vireo_log_t *logger = NULL;
        vireo_log_error_t error;
        reset_fault();
        vireo_log_ops_t ops = test_ops();
        errno = EDOM;
        CHECK(vireo_log_create_with_ops(&options, &logger, &error, &ops) == VIREO_RESULT_INVALID_ARGUMENT);
        CHECK(logger == NULL && fault.allocations == 0 && errno == EDOM);
        CHECK(error.sink == VIREO_LOG_SINK_FILE && error.stage == VIREO_LOG_STAGE_VALIDATE);
        CHECK(error.system_errno == 0 && fd_count() == baseline);
    }
    return 0;
}

static int check_path_limits(void) {
    char path[VIREO_LOG_DIRECTORY_CAPACITY + 1];
    memset(path, 'a', sizeof(path));
    path[0] = '/';
    vireo_log_options_t options = {.directory = path, .max_file_size_bytes = VIREO_LOG_MIN_FILE_SIZE_BYTES};
    vireo_log_ops_t ops = test_ops();
    vireo_log_t *logger = NULL;
    vireo_log_error_t error;
    reset_fault();
    CHECK(vireo_log_create_with_ops(&options, &logger, &error, &ops) == VIREO_RESULT_RANGE);
    CHECK(fault.allocations == 0 && logger == NULL);
    path[VIREO_LOG_DIRECTORY_CAPACITY] = '\0';
    CHECK(vireo_log_create_with_ops(&options, &logger, &error, &ops) == VIREO_RESULT_RANGE);
    CHECK(fault.allocations == 0);
    path[VIREO_LOG_DIRECTORY_CAPACITY - 1] = '\0';
    fault.fail_stage = VIREO_LOG_STAGE_OPEN_DIRECTORY;
    fault.fail_errno = ENOENT;
    CHECK(vireo_log_create_with_ops(&options, &logger, &error, &ops) == VIREO_RESULT_IO);
    CHECK(error.stage == VIREO_LOG_STAGE_OPEN_DIRECTORY && error.system_errno == ENOENT);
    CHECK(fault.allocations == 1 && fault.frees == 1 && logger == NULL);
    CHECK(fault.directory_size == VIREO_LOG_DIRECTORY_CAPACITY - 1);
    return 0;
}

static int check_thresholds(void) {
    fixture_t fixture;
    CHECK(fixture_start(&fixture) == 0);
    uint64_t values[] = {VIREO_LOG_MIN_FILE_SIZE_BYTES, VIREO_LOG_MAX_FILE_SIZE_BYTES,
                         0, VIREO_LOG_MIN_FILE_SIZE_BYTES - 1,
                         VIREO_LOG_MAX_FILE_SIZE_BYTES + 1, UINT64_MAX};
    vireo_log_options_t options = file_options(&fixture, false);
    for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); ++i) {
        options.max_file_size_bytes = values[i];
        vireo_log_t *logger = NULL;
        vireo_log_error_t error;
        vireo_result_t expected = i < 2 ? VIREO_OK : VIREO_RESULT_RANGE;
        CHECK(vireo_log_create(&options, &logger, &error) == expected);
        if (expected == VIREO_OK) {
            CHECK(logger != NULL && vireo_log_destroy(&logger, NULL) == VIREO_OK);
        } else {
            CHECK(logger == NULL && error.stage == VIREO_LOG_STAGE_VALIDATE && error.system_errno == 0);
        }
    }
    CHECK(fixture_finish(&fixture) == 0);
    return 0;
}

static int check_copy_and_trailing_slashes(void) {
    fixture_t fixture;
    CHECK(fixture_start(&fixture) == 0);
    char path[256];
    CHECK(snprintf(path, sizeof(path), "%s///", fixture.directory) > 0);
    vireo_log_options_t options = {.directory = path, .max_file_size_bytes = VIREO_LOG_MIN_FILE_SIZE_BYTES};
    vireo_log_t *logger = NULL;
    reset_fault();
    vireo_log_ops_t ops = test_ops();
    CHECK(vireo_log_create_with_ops(&options, &logger, NULL, &ops) == VIREO_OK);
    CHECK(fault.owned_directory != path && strcmp(fault.owned_directory, fixture.directory) == 0);
    memset(path, 'Q', sizeof(path));
    options = (vireo_log_options_t){0};
    ops = (vireo_log_ops_t){0}; /* 对象必须使用拷贝的表，不依赖调用者局部表。 */
    CHECK(strcmp(fault.owned_directory, fixture.directory) == 0);
    CHECK(vireo_log_destroy(&logger, NULL) == VIREO_OK && logger == NULL);
    CHECK(fault.frees == 1 && fixture_finish(&fixture) == 0);
    return 0;
}

static int check_create_faults(void) {
    vireo_log_stage_t stages[] = {VIREO_LOG_STAGE_ALLOCATE, VIREO_LOG_STAGE_DUP_STDERR,
                                  VIREO_LOG_STAGE_CHECK_STDERR, VIREO_LOG_STAGE_OPEN_DIRECTORY,
                                  VIREO_LOG_STAGE_OPEN_FILE, VIREO_LOG_STAGE_CHECK_FILE};
    for (size_t i = 0; i < sizeof(stages) / sizeof(stages[0]); ++i) {
        fixture_t fixture;
        CHECK(fixture_start(&fixture) == 0);
        size_t baseline = fd_count();
        CHECK(baseline != SIZE_MAX);
        vireo_log_options_t options = file_options(&fixture, true);
        vireo_log_t *logger = NULL;
        vireo_log_error_t error;
        vireo_log_ops_t ops = test_ops();
        reset_fault();
        fault.fail_stage = stages[i];
        errno = EACCES;
        vireo_result_t expected = i == 0 ? VIREO_RESULT_NO_MEMORY : VIREO_RESULT_IO;
        CHECK(vireo_log_create_with_ops(&options, &logger, &error, &ops) == expected);
        CHECK(logger == NULL && errno == EACCES && error.stage == stages[i]);
        CHECK(error.system_errno == (i == 0 ? ENOMEM : ENOSPC));
        CHECK(fault.allocations == 1 && fault.frees == (i == 0 ? 0U : 1U));
        CHECK(fault.syncs == 0 && fd_count() == baseline);
        if (i == 0) {
            CHECK(error.sink == VIREO_LOG_SINK_NONE && strcmp(fault.events, "A") == 0);
        } else {
            CHECK(error.sink == (i <= 2 ? VIREO_LOG_SINK_STDERR : VIREO_LOG_SINK_FILE));
        }
        if (i == 5) {
            CHECK(strcmp(fault.events, "ASsDFfXZTR") == 0);
        }
        CHECK(fixture_finish(&fixture) == 0);
    }
    return 0;
}

static int check_primary_error_survives_rollback(void) {
    fixture_t fixture;
    CHECK(fixture_start(&fixture) == 0);
    size_t baseline = fd_count();
    CHECK(baseline != SIZE_MAX);
    vireo_log_options_t options = file_options(&fixture, true);
    vireo_log_t *logger = NULL;
    vireo_log_error_t error;
    vireo_log_ops_t ops = test_ops();
    reset_fault();
    fault.fail_stage = VIREO_LOG_STAGE_CHECK_FILE;
    fault.fail_errno = ENOSPC;
    fault.close_fail_mask = 7;
    fault.close_errno = EINTR;
    errno = EBUSY;
    CHECK(vireo_log_create_with_ops(&options, &logger, &error, &ops) == VIREO_RESULT_IO);
    CHECK(logger == NULL && errno == EBUSY && error.stage == VIREO_LOG_STAGE_CHECK_FILE);
    CHECK(error.system_errno == ENOSPC && fault.closes == 3 && fault.frees == 1);
    CHECK(strcmp(fault.events, "ASsDFfXZTR") == 0 && fd_count() == baseline);
    CHECK(fixture_finish(&fixture) == 0);
    return 0;
}

static int check_destroy_faults(void) {
    unsigned int masks[] = {0, 1, 2, 4, 7};
    vireo_log_stage_t stages[] = {VIREO_LOG_STAGE_SYNC_FILE, VIREO_LOG_STAGE_CLOSE_FILE,
                                  VIREO_LOG_STAGE_CLOSE_STDERR, VIREO_LOG_STAGE_CLOSE_DIRECTORY,
                                  VIREO_LOG_STAGE_CLOSE_FILE};
    for (size_t i = 0; i < sizeof(masks) / sizeof(masks[0]); ++i) {
        fixture_t fixture;
        CHECK(fixture_start(&fixture) == 0);
        size_t baseline = fd_count();
        CHECK(baseline != SIZE_MAX);
        vireo_log_options_t options = file_options(&fixture, true);
        vireo_log_t *logger = NULL;
        vireo_log_error_t error;
        vireo_log_ops_t ops = test_ops();
        reset_fault();
        CHECK(vireo_log_create_with_ops(&options, &logger, &error, &ops) == VIREO_OK);
        fault.close_fail_mask = masks[i];
        if (i == 0) {
            fault.sync_errno = ENOSPC;
            fault.close_fail_mask = 7; /* sync 首错必须压过全部 close 错误。 */
        }
        errno = ERANGE;
        CHECK(vireo_log_destroy(&logger, &error) == VIREO_RESULT_IO);
        CHECK(logger == NULL && errno == ERANGE && error.stage == stages[i]);
        CHECK(error.sink == (i == 2 ? VIREO_LOG_SINK_STDERR : VIREO_LOG_SINK_FILE));
        CHECK(error.system_errno == (i == 0 ? ENOSPC : EIO));
        CHECK(fault.syncs == 1 && fault.closes == 3 && fault.frees == 1);
        CHECK(strcmp(fault.events, "ASsDFfYXTZR") == 0 && fd_count() == baseline);
        CHECK(vireo_log_destroy(&logger, &error) == VIREO_OK && error_none(&error));
        CHECK(fault.frees == 1 && fixture_finish(&fixture) == 0);
    }
    return 0;
}

static int check_no_close_retry(void) {
    fixture_t fixture;
    CHECK(fixture_start(&fixture) == 0);
    size_t baseline = fd_count();
    CHECK(baseline != SIZE_MAX);
    vireo_log_options_t options = file_options(&fixture, true);
    vireo_log_t *logger = NULL;
    vireo_log_error_t error;
    vireo_log_ops_t ops = test_ops();
    reset_fault();
    CHECK(vireo_log_create_with_ops(&options, &logger, NULL, &ops) == VIREO_OK);
    fault.close_fail_mask = 1;
    fault.close_errno = EINTR;
    fault.reuse_after_close = true;
    CHECK(vireo_log_destroy(&logger, &error) == VIREO_RESULT_IO);
    CHECK(logger == NULL && error.stage == VIREO_LOG_STAGE_CLOSE_FILE && error.system_errno == EINTR);
    CHECK(fault.closes == 3 && fault.frees == 1);
    CHECK(fault.replacement_fd == fault.file_fd && fcntl(fault.replacement_fd, F_GETFD) >= 0);
    CHECK(fd_count() == baseline + 1);
    CHECK(close(fault.replacement_fd) == 0 && fd_count() == baseline);
    CHECK(fixture_finish(&fixture) == 0);
    return 0;
}

static int check_optional_error(void) {
    for (unsigned int variant = 0; variant < 2; ++variant) {
        fixture_t fixture;
        CHECK(fixture_start(&fixture) == 0);
        size_t baseline = fd_count();
        CHECK(baseline != SIZE_MAX);
        vireo_log_options_t options = file_options(&fixture, true);
        vireo_log_t *logger = NULL;
        vireo_log_error_t error;
        vireo_log_error_t *out_error = variant == 0 ? NULL : &error;
        vireo_log_ops_t ops = test_ops();
        reset_fault();
        fault.fail_stage = VIREO_LOG_STAGE_CHECK_FILE;
        CHECK(vireo_log_create_with_ops(&options, &logger, out_error, &ops) == VIREO_RESULT_IO);
        CHECK(logger == NULL && fault.closes == 3 && fault.frees == 1 && fd_count() == baseline);
        CHECK(strcmp(fault.events, "ASsDFfXZTR") == 0);
        reset_fault();
        CHECK(vireo_log_create_with_ops(&options, &logger, out_error, &ops) == VIREO_OK);
        fault.sync_errno = ENOSPC;
        fault.close_fail_mask = 7;
        CHECK(vireo_log_destroy(&logger, out_error) == VIREO_RESULT_IO);
        CHECK(logger == NULL && fault.closes == 3 && fault.frees == 1 && fd_count() == baseline);
        CHECK(strcmp(fault.events, "ASsDFfYXTZR") == 0);
        CHECK(fixture_finish(&fixture) == 0);
    }
    return 0;
}

static int check_flags_and_fd_release(void) {
    fixture_t fixture;
    CHECK(fixture_start(&fixture) == 0);
    vireo_log_options_t options = file_options(&fixture, true);
    vireo_log_t *logger = NULL;
    reset_fault();
    vireo_log_ops_t ops = test_ops();
    int original_stderr_flags = fcntl(STDERR_FILENO, F_GETFD);
    CHECK(original_stderr_flags >= 0);
    CHECK(vireo_log_create_with_ops(&options, &logger, NULL, &ops) == VIREO_OK);
    int descriptors[] = {fault.file_fd, fault.stderr_fd, fault.directory_fd};
    for (size_t i = 0; i < sizeof(descriptors) / sizeof(descriptors[0]); ++i) {
        int descriptor_flags = fcntl(descriptors[i], F_GETFD);
        CHECK(descriptor_flags >= 0 && (descriptor_flags & FD_CLOEXEC) != 0);
    }
    CHECK(fcntl(STDERR_FILENO, F_GETFD) == original_stderr_flags);
    int file_flags = fcntl(fault.file_fd, F_GETFL);
    CHECK(file_flags >= 0 && (file_flags & O_ACCMODE) == O_WRONLY && (file_flags & O_APPEND) != 0);
    struct stat info;
    CHECK(fstat(fault.directory_fd, &info) == 0 && S_ISDIR(info.st_mode));
    CHECK(fstat(fault.file_fd, &info) == 0 && S_ISREG(info.st_mode));
    CHECK(vireo_log_destroy(&logger, NULL) == VIREO_OK);
    for (size_t i = 0; i < sizeof(descriptors) / sizeof(descriptors[0]); ++i) {
        errno = 0;
        CHECK(fcntl(descriptors[i], F_GETFD) == -1 && errno == EBADF);
    }
    CHECK(fcntl(STDERR_FILENO, F_GETFD) == original_stderr_flags);
    CHECK(fixture_finish(&fixture) == 0);
    return 0;
}

static int check_existing_file_preserved(void) {
    fixture_t fixture;
    CHECK(fixture_start(&fixture) == 0);
    int fd = open(fixture.file, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, (mode_t)0600);
    CHECK(fd >= 0 && write(fd, "preserve", 8) == 8 && close(fd) == 0);
    vireo_log_options_t options = file_options(&fixture, false);
    vireo_log_t *logger = NULL;
    CHECK(vireo_log_create(&options, &logger, NULL) == VIREO_OK);
    CHECK(vireo_log_destroy(&logger, NULL) == VIREO_OK);
    fd = open(fixture.file, O_RDONLY | O_CLOEXEC);
    char bytes[9] = {0};
    CHECK(fd >= 0 && read(fd, bytes, sizeof(bytes)) == 8 && close(fd) == 0);
    CHECK(strcmp(bytes, "preserve") == 0 && fixture_finish(&fixture) == 0);
    return 0;
}

static int check_missing_and_non_directory(void) {
    fixture_t fixture;
    CHECK(fixture_start(&fixture) == 0);
    char missing[256];
    CHECK(snprintf(missing, sizeof(missing), "%s/missing", fixture.directory) > 0);
    vireo_log_options_t options = file_options(&fixture, false);
    options.directory = missing;
    vireo_log_t *logger = NULL;
    vireo_log_error_t error;
    size_t baseline = fd_count();
    CHECK(baseline != SIZE_MAX);
    CHECK(vireo_log_create(&options, &logger, &error) == VIREO_RESULT_IO);
    CHECK(logger == NULL && error.stage == VIREO_LOG_STAGE_OPEN_DIRECTORY && error.system_errno == ENOENT);
    int fd = open(fixture.file, O_CREAT | O_WRONLY | O_CLOEXEC, (mode_t)0600);
    CHECK(fd >= 0 && close(fd) == 0);
    options.directory = fixture.file;
    CHECK(vireo_log_create(&options, &logger, &error) == VIREO_RESULT_IO);
    CHECK(logger == NULL && error.stage == VIREO_LOG_STAGE_OPEN_DIRECTORY && error.system_errno == ENOTDIR);
    CHECK(fd_count() == baseline && fixture_finish(&fixture) == 0);
    return 0;
}

static int check_file_symlink(void) {
    fixture_t fixture;
    CHECK(fixture_start(&fixture) == 0);
    CHECK(symlink("/dev/null", fixture.file) == 0);
    vireo_log_options_t options = file_options(&fixture, true);
    vireo_log_t *logger = NULL;
    vireo_log_error_t error;
    size_t baseline = fd_count();
    CHECK(baseline != SIZE_MAX);
    CHECK(vireo_log_create(&options, &logger, &error) == VIREO_RESULT_IO);
    CHECK(logger == NULL && error.stage == VIREO_LOG_STAGE_OPEN_FILE && error.system_errno == ELOOP);
    struct stat info;
    CHECK(lstat(fixture.file, &info) == 0 && S_ISLNK(info.st_mode));
    CHECK(fd_count() == baseline && fixture_finish(&fixture) == 0);
    return 0;
}

static int check_directory_symlink(void) {
    fixture_t fixture;
    CHECK(fixture_start(&fixture) == 0);
    char alias[256];
    char with_slashes[260];
    CHECK(snprintf(alias, sizeof(alias), "%s/alias", fixture.directory) > 0);
    CHECK(snprintf(with_slashes, sizeof(with_slashes), "%s///", alias) > 0);
    CHECK(symlink(fixture.directory, alias) == 0);
    vireo_log_options_t options = file_options(&fixture, true);
    options.directory = with_slashes;
    vireo_log_t *logger = NULL;
    vireo_log_error_t error;
    size_t baseline = fd_count();
    CHECK(baseline != SIZE_MAX);
    CHECK(vireo_log_create(&options, &logger, &error) == VIREO_RESULT_IO);
    CHECK(logger == NULL && error.stage == VIREO_LOG_STAGE_OPEN_DIRECTORY && error.system_errno != 0);
    CHECK(fd_count() == baseline && unlink(alias) == 0 && fixture_finish(&fixture) == 0);
    return 0;
}

static int check_fifo_and_directory_file(void) {
    fixture_t fixture;
    CHECK(fixture_start(&fixture) == 0);
    CHECK(mkfifo(fixture.file, (mode_t)0600) == 0);
    int reader = open(fixture.file, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    CHECK(reader >= 0);
    size_t baseline = fd_count();
    CHECK(baseline != SIZE_MAX);
    vireo_log_options_t options = file_options(&fixture, true);
    vireo_log_t *logger = NULL;
    vireo_log_error_t error;
    CHECK(vireo_log_create(&options, &logger, &error) == VIREO_RESULT_IO);
    CHECK(logger == NULL && error.stage == VIREO_LOG_STAGE_CHECK_FILE && error.system_errno == 0);
    CHECK(fd_count() == baseline && close(reader) == 0 && unlink(fixture.file) == 0);
    CHECK(mkdir(fixture.file, (mode_t)0700) == 0);
    CHECK(vireo_log_create(&options, &logger, &error) == VIREO_RESULT_IO);
    CHECK(logger == NULL && error.stage == VIREO_LOG_STAGE_OPEN_FILE);
    CHECK(rmdir(fixture.file) == 0 && fixture_finish(&fixture) == 0);
    return 0;
}

static int check_file_permissions(void) {
    mode_t modes[] = {0644, 0660, 0700};
    for (size_t i = 0; i < sizeof(modes) / sizeof(modes[0]); ++i) {
        fixture_t fixture;
        CHECK(fixture_start(&fixture) == 0);
        int fd = open(fixture.file, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, (mode_t)0600);
        CHECK(fd >= 0 && close(fd) == 0 && chmod(fixture.file, modes[i]) == 0);
        vireo_log_options_t options = file_options(&fixture, false);
        vireo_log_t *logger = NULL;
        vireo_log_error_t error;
        CHECK(vireo_log_create(&options, &logger, &error) == VIREO_RESULT_IO);
        CHECK(logger == NULL && error.stage == VIREO_LOG_STAGE_CHECK_FILE && error.system_errno == 0);
        struct stat info;
        CHECK(stat(fixture.file, &info) == 0 && (info.st_mode & (mode_t)0777) == modes[i]);
        CHECK(fixture_finish(&fixture) == 0);
    }
    return 0;
}

static int check_umask(void) {
    fixture_t fixture;
    CHECK(fixture_start(&fixture) == 0);
    vireo_log_options_t options = file_options(&fixture, false);
    vireo_log_t *logger = NULL;
    mode_t original = umask((mode_t)0077);
    vireo_result_t result = vireo_log_create(&options, &logger, NULL);
    (void)umask(original);
    CHECK(result == VIREO_OK);
    struct stat info;
    CHECK(stat(fixture.file, &info) == 0 && (info.st_mode & (mode_t)0777) == (mode_t)0600);
    CHECK(vireo_log_destroy(&logger, NULL) == VIREO_OK && fixture_finish(&fixture) == 0);
    return 0;
}

static int check_hardlink_and_owner(void) {
    fixture_t fixture;
    CHECK(fixture_start(&fixture) == 0);
    int fd = open(fixture.file, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, (mode_t)0600);
    CHECK(fd >= 0 && close(fd) == 0);
    char alias[256];
    CHECK(snprintf(alias, sizeof(alias), "%s/hardlink", fixture.directory) > 0);
    CHECK(link(fixture.file, alias) == 0);
    vireo_log_options_t options = file_options(&fixture, false);
    vireo_log_t *logger = NULL;
    vireo_log_error_t error;
    CHECK(vireo_log_create(&options, &logger, &error) == VIREO_RESULT_IO);
    CHECK(logger == NULL && error.stage == VIREO_LOG_STAGE_CHECK_FILE && error.system_errno == 0);
    CHECK(unlink(alias) == 0);
    for (unsigned int variant = 0; variant < 2; ++variant) {
        reset_fault();
        fault.bad_owner = variant == 0;
        fault.bad_links = variant == 1;
        vireo_log_ops_t ops = test_ops();
        CHECK(vireo_log_create_with_ops(&options, &logger, &error, &ops) == VIREO_RESULT_IO);
        CHECK(logger == NULL && error.stage == VIREO_LOG_STAGE_CHECK_FILE && error.system_errno == 0);
        CHECK(fault.closes == 2 && fault.frees == 1);
    }
    CHECK(fixture_finish(&fixture) == 0);
    return 0;
}

static int run_child(int (*body)(void)) {
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        _exit(body() == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
    }
    int status = 0;
    CHECK(waitpid(child, &status, 0) == child);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == EXIT_SUCCESS);
    return 0;
}

static int child_closed_stderr(void) {
    fixture_t fixture;
    CHECK(fixture_start(&fixture) == 0 && close(STDERR_FILENO) == 0);
    size_t baseline = fd_count();
    CHECK(baseline != SIZE_MAX);
    vireo_log_options_t options = file_options(&fixture, true);
    vireo_log_t *logger = NULL;
    vireo_log_error_t error;
    errno = EDOM;
    CHECK(vireo_log_create(&options, &logger, &error) == VIREO_RESULT_IO);
    CHECK(logger == NULL && error.stage == VIREO_LOG_STAGE_DUP_STDERR && error.system_errno == EBADF);
    CHECK(errno == EDOM);
    CHECK(access(fixture.file, F_OK) == -1 && errno == ENOENT && fd_count() == baseline);
    options.to_stderr = false;
    CHECK(vireo_log_create(&options, &logger, NULL) == VIREO_OK); /* fd2 可由内部目录合法拥有。 */
    CHECK(vireo_log_destroy(&logger, NULL) == VIREO_OK && fd_count() == baseline);
    CHECK(fixture_finish(&fixture) == 0);
    return 0;
}

static int child_readonly_stderr(void) {
    int fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    CHECK(fd >= 0 && dup2(fd, STDERR_FILENO) == STDERR_FILENO && close(fd) == 0);
    size_t baseline = fd_count();
    CHECK(baseline != SIZE_MAX);
    vireo_log_options_t options = {.to_stderr = true};
    vireo_log_t *logger = NULL;
    vireo_log_error_t error;
    CHECK(vireo_log_create(&options, &logger, &error) == VIREO_RESULT_IO);
    CHECK(logger == NULL && error.stage == VIREO_LOG_STAGE_CHECK_STDERR && error.system_errno == EBADF);
    CHECK(fd_count() == baseline);
    return 0;
}

static int child_stderr_destination(void) {
    int pipe_fds[2];
    CHECK(pipe(pipe_fds) == 0);
    CHECK(dup2(pipe_fds[1], STDERR_FILENO) == STDERR_FILENO && close(pipe_fds[1]) == 0);
    vireo_log_options_t options = {.to_stderr = true};
    vireo_log_t *logger = NULL;
    reset_fault();
    vireo_log_ops_t ops = test_ops();
    CHECK(vireo_log_create_with_ops(&options, &logger, NULL, &ops) == VIREO_OK);
    int other = open("/dev/null", O_WRONLY | O_CLOEXEC);
    CHECK(other >= 0 && dup2(other, STDERR_FILENO) == STDERR_FILENO && close(other) == 0);
    /* 仅测试观察私有 fd 的目的地；这不是新增公共 emit/write API。 */
    CHECK(write(fault.stderr_fd, "Z", 1) == 1);
    char byte = 0;
    CHECK(read(pipe_fds[0], &byte, 1) == 1 && byte == 'Z');
    CHECK(vireo_log_destroy(&logger, NULL) == VIREO_OK && logger == NULL);
    CHECK(read(pipe_fds[0], &byte, 1) == 0 && close(pipe_fds[0]) == 0);
    CHECK(fcntl(STDERR_FILENO, F_GETFD) >= 0);
    return 0;
}

static int check_closed_stderr(void) { return run_child(child_closed_stderr); }
static int check_readonly_stderr(void) { return run_child(child_readonly_stderr); }
static int check_stderr_destination(void) { return run_child(child_stderr_destination); }

static int check_repeated_lifecycle(void) {
    fixture_t fixture;
    CHECK(fixture_start(&fixture) == 0);
    size_t baseline = fd_count();
    CHECK(baseline != SIZE_MAX);
    vireo_log_options_t options = file_options(&fixture, true);
    for (size_t i = 0; i < 128; ++i) {
        vireo_log_t *logger = NULL;
        CHECK(vireo_log_create(&options, &logger, NULL) == VIREO_OK);
        CHECK(vireo_log_destroy(&logger, NULL) == VIREO_OK && logger == NULL);
        CHECK(fd_count() == baseline);
    }
    CHECK(fixture_finish(&fixture) == 0);
    return 0;
}

static int check_errno_and_config_derivation(void) {
    fixture_t fixture;
    CHECK(fixture_start(&fixture) == 0);
    vireo_config_t config;
    CHECK(vireo_config_defaults(&config) == VIREO_OK);
    strcpy(config.log_dir, fixture.directory);
    vireo_config_error_t config_error;
    CHECK(vireo_config_validate(&config, &config_error) == VIREO_OK);
    vireo_log_options_t options = {.directory = config.log_dir, .to_stderr = config.log_to_stderr,
                                  .max_file_size_bytes = config.log_max_file_size_bytes};
    int sentinels[] = {0, EACCES, ERANGE};
    for (size_t i = 0; i < sizeof(sentinels) / sizeof(sentinels[0]); ++i) {
        vireo_log_t *logger = NULL;
        vireo_log_error_t error;
        errno = sentinels[i];
        CHECK(vireo_log_create(&options, &logger, &error) == VIREO_OK && errno == sentinels[i]);
        CHECK(error_none(&error));
        CHECK(vireo_log_destroy(&logger, &error) == VIREO_OK && errno == sentinels[i]);
        CHECK(logger == NULL && error_none(&error));
        options.max_file_size_bytes = 0;
        CHECK(vireo_log_create(&options, &logger, &error) == VIREO_RESULT_RANGE && errno == sentinels[i]);
        CHECK(logger == NULL && error.system_errno == 0);
        options.max_file_size_bytes = config.log_max_file_size_bytes;
    }
    CHECK(fixture_finish(&fixture) == 0);
    return 0;
}

static int check_private_ops_validation(void) {
    vireo_log_options_t options = {.to_stderr = true};
    vireo_log_t *logger = NULL;
    vireo_log_error_t error;
    reset_fault();
    CHECK(vireo_log_create_with_ops(&options, &logger, &error, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    vireo_log_ops_t ops = test_ops();
    ops.close_fd = NULL;
    CHECK(vireo_log_create_with_ops(&options, &logger, &error, &ops) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(logger == NULL && error.stage == VIREO_LOG_STAGE_VALIDATE && fault.allocations == 0);
    return 0;
}

/* 为系统调用证据运行一条真实双 sink 生命周期；不接触任何实际服务日志目录。 */
static int observe_lifecycle(void) {
    fixture_t fixture;
    CHECK(fixture_start(&fixture) == 0);
    size_t before = fd_count();
    CHECK(before != SIZE_MAX);
    printf("OBSERVE before fd_count=%zu directory=%s\n", before, fixture.directory);
    CHECK(fflush(stdout) == 0);
    vireo_log_options_t options = file_options(&fixture, true);
    vireo_log_t *logger = NULL;
    CHECK(vireo_log_create(&options, &logger, NULL) == VIREO_OK);
    printf("OBSERVE created fd_count=%zu\n", fd_count());
    CHECK(fflush(stdout) == 0);
    CHECK(vireo_log_destroy(&logger, NULL) == VIREO_OK && logger == NULL);
    size_t after = fd_count();
    CHECK(after == before);
    printf("OBSERVE destroyed fd_count=%zu logger=NULL original_stderr_open=%d\n",
           after, fcntl(STDERR_FILENO, F_GETFD) >= 0 ? 1 : 0);
    CHECK(fixture_finish(&fixture) == 0);
    return 0;
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--observe") == 0) {
        return observe_lifecycle() == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
    }
    if (argc != 1) {
        return EXIT_FAILURE;
    }
    int (*const groups[])(void) = {
        check_sink_combinations, check_arguments, check_invalid_paths, check_path_limits,
        check_thresholds, check_copy_and_trailing_slashes, check_create_faults,
        check_primary_error_survives_rollback, check_destroy_faults, check_no_close_retry,
        check_optional_error, check_flags_and_fd_release, check_existing_file_preserved,
        check_missing_and_non_directory, check_file_symlink, check_directory_symlink,
        check_fifo_and_directory_file, check_file_permissions, check_umask, check_hardlink_and_owner,
        check_closed_stderr, check_readonly_stderr, check_stderr_destination,
        check_repeated_lifecycle, check_errno_and_config_derivation, check_private_ops_validation,
    };
    int failures = 0;
    for (size_t i = 0; i < sizeof(groups) / sizeof(groups[0]); ++i) {
        failures += groups[i]();
    }
    if (failures != 0) {
        fprintf(stderr, "test_log_lifecycle: %d test groups failed\n", failures);
        return EXIT_FAILURE;
    }
    printf("test_log_lifecycle: all %zu test groups passed\n", sizeof(groups) / sizeof(groups[0]));
    return EXIT_SUCCESS;
}
