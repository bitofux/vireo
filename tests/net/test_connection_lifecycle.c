/*
- PROJECT : VIREO
- FILE    : test_connection_lifecycle.c
- AUTHOR  : bitofux
- DATE    : 2026-10-03
- BRIEF   : 此模块负责：
- -- 真实 socket 生命周期与公共容量/输出/errno 合同测试
- -- 本模块边界故障注入、回滚顺序与单次关闭资源配对
 */
#define _GNU_SOURCE
#include <vireo/net/connection.h>
#include "net/connection_internal.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

static unsigned failures;
#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition); \
        ++failures; \
    } \
} while (0)
/* 基础 fixture 创建失败立即结束；不让后续使用无效地址掩盖根因。 */
#define REQUIRE(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "fixture failure %s:%d: %s\n", __FILE__, __LINE__, #condition); \
        exit(EXIT_FAILURE); \
    } \
} while (0)

static vireo_connection_options_t const options = {4096, 8192, 12288};

typedef struct fixture {
    int *fd_owner;
    vireo_connection_t **connection_owner;
    int original_fd;
    unsigned queries;
    unsigned fail_query;
    int query_errno;
    unsigned allocations;
    unsigned control_live;
    int fail_control;
    unsigned creates;
    unsigned fail_buffer;
    unsigned buffer_live;
    vireo_buffer_t *read_buffer;
    vireo_buffer_t *write_buffer;
    unsigned closes;
    int close_errno;
    int reuse_on_close;
    int replacement_fd;
    char release_order[8];
    size_t release_count;
} fixture_t;

static void pair_create(int pair[2])
{
    REQUIRE(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, pair) == 0);
}

static void check_unpublished(fixture_t const *f)
{
    CHECK(*f->fd_owner == f->original_fd);
    CHECK(*f->connection_owner == NULL);
}

static void *tracked_allocate(void *context, size_t bytes)
{
    fixture_t *f = context;
    check_unpublished(f);
    ++f->allocations;
    errno = EDOM;
    if (f->fail_control != 0) {
        return NULL;
    }
    void *memory = malloc(bytes);
    REQUIRE(memory != NULL);
    ++f->control_live;
    return memory;
}

static void tracked_deallocate(void *context, void *memory)
{
    fixture_t *f = context;
    CHECK(f->control_live == 1);
    CHECK(f->buffer_live == 0);
    --f->control_live;
    f->release_order[f->release_count++] = 'C';
    free(memory);
    errno = ERANGE;
}

static int query_failure(fixture_t *f)
{
    check_unpublished(f);
    ++f->queries;
    if (f->queries == f->fail_query) {
        errno = f->query_errno;
        return 1;
    }
    return 0;
}

static int tracked_flags(void *context, int fd, int command)
{
    fixture_t *f = context;
    CHECK(command == (f->queries == 0 ? F_GETFL : F_GETFD));
    return query_failure(f) != 0 ? -1 : fcntl(fd, command);
}

static int tracked_type(void *context, int fd, int *out_type)
{
    fixture_t *f = context;
    socklen_t length = (socklen_t)sizeof(*out_type);
    CHECK(f->queries == 2);
    return query_failure(f) != 0 ? -1 :
        getsockopt(fd, SOL_SOCKET, SO_TYPE, out_type, &length);
}

static int tracked_peer(void *context, int fd)
{
    fixture_t *f = context;
    struct sockaddr_storage address;
    socklen_t length = (socklen_t)sizeof(address);
    CHECK(f->queries == 3);
    return query_failure(f) != 0 ? -1 :
        getpeername(fd, (struct sockaddr *)&address, &length);
}

static int tracked_close(void *context, int fd)
{
    fixture_t *f = context;
    CHECK(fd == f->original_fd);
    CHECK(*f->fd_owner == -1);
    CHECK(*f->connection_owner != NULL);
    ++f->closes;
    f->release_order[f->release_count++] = 'X';
    REQUIRE(close(fd) == 0);
    if (f->reuse_on_close != 0) {
        f->replacement_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
        REQUIRE(f->replacement_fd >= 0);
        REQUIRE(f->replacement_fd == fd);
    }
    errno = f->close_errno;
    return f->close_errno != 0 ? -1 : 0;
}

static vireo_result_t tracked_buffer_create(void *context, size_t capacity, vireo_buffer_t **out)
{
    fixture_t *f = context;
    check_unpublished(f);
    CHECK(*out == NULL);
    ++f->creates;
    if (f->creates == f->fail_buffer) {
        errno = ENOMEM;
        return VIREO_RESULT_NO_MEMORY;
    }
    vireo_result_t result = vireo_buffer_create(capacity, out);
    REQUIRE(result == VIREO_OK);
    if (f->creates == 1) {
        f->read_buffer = *out;
    } else {
        f->write_buffer = *out;
        CHECK(f->write_buffer != f->read_buffer);
    }
    ++f->buffer_live;
    return result;
}

static void tracked_buffer_destroy(void *context, vireo_buffer_t **owner)
{
    fixture_t *f = context;
    CHECK(f->buffer_live > 0);
    CHECK(*owner == f->read_buffer || *owner == f->write_buffer);
    f->release_order[f->release_count++] = *owner == f->write_buffer ? 'W' : 'R';
    REQUIRE(vireo_buffer_destroy(owner) == VIREO_OK);
    CHECK(*owner == NULL);
    --f->buffer_live;
    errno = EACCES;
}

/**
 * @brief M1 不执行接收，提供完整私有表所需的系统入口
 *
 * @param[in] context
 *     未使用的 fixture 借用。
 * @param[in] fd
 *     connection 独占 socket，调用期间借用。
 * @param[out] bytes
 *     有效暂存区，至少 request 字节。
 * @param[in] request
 *     调用层验收的正长度。
 * @param[in] flags
 *     本层传入的 recv flags。
 *
 * @return
 *     recv 原数量或 -1/errno。
 *
 * @note 不重试或关闭，M1 只验构造与销毁，不调用此入口。
 */
static ssize_t fixture_receive(void *context, int fd, void *bytes, size_t request, int flags)
{
    (void)context;
    return recv(fd, bytes, request, flags);
}

/**
 * @brief 为旧测试提供完整私有表所需的默认发送入口
 *
 * @param[in] context
 *     未使用的 fixture 借用。
 * @param[in] fd
 *     本对象独占 socket，调用期间借用。
 * @param[in] bytes
 *     有效只读区域，至少 request 字节，仅借用到返回。
 * @param[in] request
 *     调用层验收的正长度。
 * @param[in] flags
 *     调用层传入的 send flags。
 *
 * @return send 原数量或 -1/errno。
 *
 * @note 旧测试不调用发送；不重试、保存输入或关闭。
 */
static ssize_t fixture_send(void *context, int fd, void const *bytes, size_t request, int flags)
{
    (void)context;
    return send(fd, bytes, request, flags);
}

static vireo_connection_ops_t fixture_ops(fixture_t *f, int *fd,
                                         vireo_connection_t **connection)
{
    *f = (fixture_t){0};
    f->fd_owner = fd;
    f->connection_owner = connection;
    f->original_fd = *fd;
    f->replacement_fd = -1;
    return (vireo_connection_ops_t){f, tracked_allocate, tracked_deallocate, tracked_flags,
        tracked_type, tracked_peer, tracked_close, tracked_buffer_create, tracked_buffer_destroy,
        fixture_receive, fixture_send};
}

static void check_error(vireo_connection_error_t const *error,
                        vireo_connection_stage_t stage, int cause)
{
    CHECK(error->stage == stage);
    CHECK(error->system_errno == cause);
}

static size_t fd_count(void)
{
    DIR *directory = opendir("/proc/self/fd");
    REQUIRE(directory != NULL);
    size_t count = 0;
    struct dirent *entry;
    while ((entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
            ++count;
        }
    }
    REQUIRE(closedir(directory) == 0);
    return count;
}

static void test_public_lifecycle(void)
{
    int pair[2];
    pair_create(pair);
    int fd = pair[0];
    int original = fd;
    int original_flags = fcntl(fd, F_GETFL);
    int original_fd_flags = fcntl(fd, F_GETFD);
    vireo_connection_t *connection = NULL;
    vireo_connection_error_t error = {VIREO_CONNECTION_STAGE_CLOSE_SOCKET, EIO};
    errno = E2BIG;
    CHECK(vireo_connection_create(&options, &fd, &connection, &error) == VIREO_OK);
    CHECK(errno == E2BIG);
    REQUIRE(connection != NULL);
    CHECK(fd == -1);
    check_error(&error, VIREO_CONNECTION_STAGE_NONE, 0);
    CHECK(fcntl(original, F_GETFL) == original_flags);
    CHECK(fcntl(original, F_GETFD) == original_fd_flags);
    vireo_connection_info_t info;
    memset(&info, 0xa5, sizeof(info));
    errno = ENOTTY;
    CHECK(vireo_connection_inspect(connection, &info) == VIREO_OK);
    CHECK(errno == ENOTTY);
    CHECK(info.read_buffer.capacity == 4096 && info.read_buffer.readable_size == 0);
    CHECK(info.read_buffer.tail_space == 4096);
    CHECK(info.write_buffer.capacity == 8192 && info.write_buffer.readable_size == 0);
    CHECK(info.write_buffer.tail_space == 8192);
    CHECK(info.buffer_capacity_bytes == 12288 && info.max_buffer_bytes == 12288);
    CHECK(!info.read_eof);
    errno = ECHILD;
    CHECK(vireo_connection_destroy(&connection, &error) == VIREO_OK);
    CHECK(connection == NULL && errno == ECHILD);
    check_error(&error, VIREO_CONNECTION_STAGE_NONE, 0);
    CHECK(fcntl(original, F_GETFD) == -1 && errno == EBADF);
    CHECK(fcntl(pair[1], F_GETFD) >= 0);
    errno = EINTR;
    CHECK(vireo_connection_destroy(&connection, NULL) == VIREO_OK && errno == EINTR);
    REQUIRE(close(pair[1]) == 0);
}

static void test_invalid_arguments(void)
{
    int pair[2];
    pair_create(pair);
    int fd = pair[0];
    vireo_connection_t *connection = NULL;
    vireo_connection_error_t error;
    errno = E2BIG;
    CHECK(vireo_connection_create(NULL, &fd, &connection, &error) ==
          VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_connection_create(&options, NULL, &connection, NULL) ==
          VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_connection_create(&options, &fd, NULL, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(errno == E2BIG && fd == pair[0] && connection == NULL);
    int negative = -1;
    CHECK(vireo_connection_create(&options, &negative, &connection, &error) ==
          VIREO_RESULT_INVALID_ARGUMENT);
    check_error(&error, VIREO_CONNECTION_STAGE_NONE, 0);
    CHECK(negative == -1 && errno == E2BIG);
    CHECK(vireo_connection_create(&options, &fd, &connection, NULL) == VIREO_OK);
    vireo_connection_t *original = connection;
    int other = pair[1];
    CHECK(vireo_connection_create(&options, &other, &connection, &error) ==
          VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(connection == original && other == pair[1] && errno == E2BIG);
    check_error(&error, VIREO_CONNECTION_STAGE_NONE, 0);
    CHECK(vireo_connection_destroy(NULL, &error) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(errno == E2BIG);
    check_error(&error, VIREO_CONNECTION_STAGE_NONE, 0);
    CHECK(vireo_connection_destroy(&connection, NULL) == VIREO_OK);
    REQUIRE(close(pair[1]) == 0);
}

static void test_failed_inspect(void)
{
    int pair[2];
    pair_create(pair);
    int fd = pair[0];
    vireo_connection_t *connection = NULL;
    REQUIRE(vireo_connection_create(&options, &fd, &connection, NULL) == VIREO_OK);
    unsigned char snapshot[sizeof(vireo_connection_info_t)];
    vireo_connection_info_t info;
    memset(&info, 0x5a, sizeof(info));
    memcpy(snapshot, &info, sizeof(info));
    errno = EDOM;
    CHECK(vireo_connection_inspect(NULL, &info) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(memcmp(snapshot, &info, sizeof(info)) == 0);
    CHECK(vireo_connection_inspect(connection, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(errno == EDOM);
    REQUIRE(vireo_connection_destroy(&connection, NULL) == VIREO_OK);
    REQUIRE(close(pair[1]) == 0);
}

static void test_capacity_rejection(void)
{
    vireo_connection_options_t const cases[] = {
        {0, 1, 2}, {1, 0, 2}, {1, 1, 0}, {4096, 8192, 12287},
        {1, 1, VIREO_CONNECTION_MAX_BUFFER_BYTES + 1},
        {VIREO_BUFFER_MAX_CAPACITY + 1, 1, VIREO_CONNECTION_MAX_BUFFER_BYTES},
        {1, VIREO_BUFFER_MAX_CAPACITY + 1, VIREO_CONNECTION_MAX_BUFFER_BYTES},
        {VIREO_BUFFER_MAX_CAPACITY, 1, VIREO_CONNECTION_MAX_BUFFER_BYTES},
        {SIZE_MAX, 1, 2}, {1, SIZE_MAX, 2}
    };
    int pair[2];
    pair_create(pair);
    int fd = pair[0];
    vireo_connection_t *connection = NULL;
    fixture_t f;
    vireo_connection_ops_t ops = fixture_ops(&f, &fd, &connection);
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        vireo_connection_error_t error;
        errno = E2BIG;
        vireo_result_t expected = i >= 8 ? VIREO_RESULT_OVERFLOW : VIREO_RESULT_RANGE;
        CHECK(vireo_connection_create_with_ops(&cases[i], &fd, &ops, &connection, &error) ==
              expected);
        CHECK(errno == E2BIG && connection == NULL && fd == pair[0]);
        CHECK(f.queries == 0 && f.allocations == 0 && f.creates == 0 && f.closes == 0);
        check_error(&error, VIREO_CONNECTION_STAGE_NONE, 0);
    }
    REQUIRE(close(pair[0]) == 0);
    REQUIRE(close(pair[1]) == 0);
}

static void test_capacity_acceptance(void)
{
    int pair[2];
    pair_create(pair);
    int fd = pair[0];
    vireo_connection_t *connection = NULL;
    vireo_connection_options_t small = {1, 1, 2};
    REQUIRE(vireo_connection_create(&small, &fd, &connection, NULL) == VIREO_OK);
    vireo_connection_info_t info;
    CHECK(vireo_connection_inspect(connection, &info) == VIREO_OK);
    CHECK(info.buffer_capacity_bytes == 2 && info.read_buffer.capacity == 1);
    REQUIRE(vireo_connection_destroy(&connection, NULL) == VIREO_OK);
    REQUIRE(close(pair[1]) == 0);
    pair_create(pair);
    fd = pair[0];
    fixture_t f;
    vireo_connection_ops_t ops = fixture_ops(&f, &fd, &connection);
    f.fail_control = 1;
    vireo_connection_options_t maximum = {
        VIREO_CONNECTION_MAX_BUFFER_BYTES - 1, 1, VIREO_CONNECTION_MAX_BUFFER_BYTES
    };
    errno = E2BIG;
    CHECK(vireo_connection_create_with_ops(&maximum, &fd, &ops, &connection, NULL) ==
          VIREO_RESULT_NO_MEMORY);
    CHECK(f.queries == 4 && f.allocations == 1 && f.creates == 0 && f.closes == 0);
    CHECK(fd == pair[0] && connection == NULL && errno == E2BIG);
    REQUIRE(close(pair[0]) == 0);
    REQUIRE(close(pair[1]) == 0);
}

static void test_query_failures(void)
{
    int const causes[] = {EBADF, EINTR, ENOTSOCK, ENOTCONN};
    for (unsigned i = 1; i <= 4; ++i) {
        int pair[2];
        pair_create(pair);
        int fd = pair[0];
        vireo_connection_t *connection = NULL;
        fixture_t f;
        vireo_connection_ops_t ops = fixture_ops(&f, &fd, &connection);
        f.fail_query = i;
        f.query_errno = causes[i - 1];
        vireo_connection_error_t error;
        errno = E2BIG;
        CHECK(vireo_connection_create_with_ops(&options, &fd, &ops, &connection, &error) ==
              VIREO_RESULT_IO);
        CHECK(f.queries == i && f.allocations == 0 && f.creates == 0 && f.closes == 0);
        CHECK(fd == pair[0] && connection == NULL && errno == E2BIG);
        check_error(&error, VIREO_CONNECTION_STAGE_VALIDATE_FD, causes[i - 1]);
        CHECK(fcntl(fd, F_GETFD) >= 0);
        REQUIRE(close(pair[0]) == 0);
        REQUIRE(close(pair[1]) == 0);
    }
}

static void test_allocation_rollback(void)
{
    char const *const orders[] = {"", "C", "RC"};
    vireo_connection_stage_t const stages[] = {VIREO_CONNECTION_STAGE_ALLOCATE_CONTROL,
        VIREO_CONNECTION_STAGE_CREATE_READ_BUFFER, VIREO_CONNECTION_STAGE_CREATE_WRITE_BUFFER};
    for (unsigned i = 0; i < 3; ++i) {
        int pair[2];
        pair_create(pair);
        int fd = pair[0];
        vireo_connection_t *connection = NULL;
        fixture_t f;
        vireo_connection_ops_t ops = fixture_ops(&f, &fd, &connection);
        f.fail_control = i == 0 ? 1 : 0;
        f.fail_buffer = i;
        vireo_connection_error_t error;
        errno = E2BIG;
        CHECK(vireo_connection_create_with_ops(&options, &fd, &ops, &connection, &error) ==
              VIREO_RESULT_NO_MEMORY);
        CHECK(fd == pair[0] && connection == NULL && errno == E2BIG);
        CHECK(f.queries == 4 && f.allocations == 1 && f.creates == i && f.closes == 0);
        CHECK(f.control_live == 0 && f.buffer_live == 0);
        CHECK(strcmp(f.release_order, orders[i]) == 0);
        check_error(&error, stages[i], 0);
        CHECK(fcntl(fd, F_GETFD) >= 0);
        /* 同一个 caller fd 在修正条件后仍可成功接管；失败没有改 socket。 */
        REQUIRE(vireo_connection_create(&options, &fd, &connection, NULL) == VIREO_OK);
        REQUIRE(vireo_connection_destroy(&connection, NULL) == VIREO_OK);
        REQUIRE(close(pair[1]) == 0);
    }
}

static void test_tracked_success(void)
{
    int pair[2];
    pair_create(pair);
    int fd = pair[0];
    vireo_connection_t *connection = NULL;
    fixture_t f;
    vireo_connection_ops_t ops = fixture_ops(&f, &fd, &connection);
    errno = E2BIG;
    REQUIRE(vireo_connection_create_with_ops(&options, &fd, &ops, &connection, NULL) == VIREO_OK);
    CHECK(fd == -1 && errno == E2BIG);
    CHECK(f.queries == 4 && f.allocations == 1 && f.creates == 2);
    CHECK(f.control_live == 1 && f.buffer_live == 2 && f.closes == 0);
    /* 对象已经按值保存 ops，调用者修改表不得改变后续释放路径。 */
    ops.close_fd = NULL;
    ops.destroy_buffer = NULL;
    vireo_connection_info_t info;
    CHECK(vireo_connection_inspect(connection, &info) == VIREO_OK);
    CHECK(info.read_buffer.capacity == 4096 && info.write_buffer.capacity == 8192);
    vireo_connection_error_t error;
    CHECK(vireo_connection_destroy(&connection, &error) == VIREO_OK);
    CHECK(errno == E2BIG && connection == NULL);
    CHECK(strcmp(f.release_order, "XWRC") == 0);
    CHECK(f.closes == 1 && f.control_live == 0 && f.buffer_live == 0);
    check_error(&error, VIREO_CONNECTION_STAGE_NONE, 0);
    CHECK(vireo_connection_destroy(&connection, &error) == VIREO_OK);
    CHECK(f.closes == 1 && errno == E2BIG);
    REQUIRE(close(pair[1]) == 0);
}

static void test_close_failure(void)
{
    int const causes[] = {EINTR, EIO};
    for (size_t i = 0; i < sizeof(causes) / sizeof(causes[0]); ++i) {
        int pair[2];
        pair_create(pair);
        int fd = pair[0];
        vireo_connection_t *connection = NULL;
        fixture_t f;
        vireo_connection_ops_t ops = fixture_ops(&f, &fd, &connection);
        f.close_errno = causes[i];
        f.reuse_on_close = 1;
        REQUIRE(vireo_connection_create_with_ops(&options, &fd, &ops, &connection, NULL) ==
                VIREO_OK);
        vireo_connection_error_t error;
        errno = E2BIG;
        CHECK(vireo_connection_destroy(&connection, &error) == VIREO_RESULT_IO);
        CHECK(errno == E2BIG && connection == NULL && fd == -1);
        check_error(&error, VIREO_CONNECTION_STAGE_CLOSE_SOCKET, causes[i]);
        CHECK(f.closes == 1 && f.control_live == 0 && f.buffer_live == 0);
        CHECK(strcmp(f.release_order, "XWRC") == 0);
        CHECK(fcntl(f.replacement_fd, F_GETFD) >= 0);
        CHECK(vireo_connection_destroy(&connection, NULL) == VIREO_OK);
        CHECK(f.closes == 1 && fcntl(f.replacement_fd, F_GETFD) >= 0);
        REQUIRE(close(f.replacement_fd) == 0);
        REQUIRE(close(pair[1]) == 0);
    }
}

static void check_real_rejection(int fd, vireo_result_t result, int cause)
{
    int original = fd;
    int flags = fcntl(fd, F_GETFL);
    int fd_flags = fcntl(fd, F_GETFD);
    vireo_connection_t *connection = NULL;
    vireo_connection_error_t error;
    errno = E2BIG;
    CHECK(vireo_connection_create(&options, &fd, &connection, &error) == result);
    CHECK(errno == E2BIG && fd == original && connection == NULL);
    check_error(&error, result == VIREO_RESULT_IO ? VIREO_CONNECTION_STAGE_VALIDATE_FD :
                VIREO_CONNECTION_STAGE_NONE, cause);
    CHECK(fcntl(fd, F_GETFL) == flags);
    CHECK(fcntl(fd, F_GETFD) == fd_flags);
}

static void test_missing_flags_and_type(void)
{
    int pair[2];
    REQUIRE(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) == 0);
    check_real_rejection(pair[0], VIREO_RESULT_INVALID_ARGUMENT, 0);
    REQUIRE(close(pair[0]) == 0);
    REQUIRE(close(pair[1]) == 0);
    REQUIRE(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, pair) == 0);
    check_real_rejection(pair[0], VIREO_RESULT_INVALID_ARGUMENT, 0);
    REQUIRE(close(pair[0]) == 0);
    REQUIRE(close(pair[1]) == 0);
    REQUIRE(socketpair(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, pair) == 0);
    check_real_rejection(pair[0], VIREO_RESULT_INVALID_ARGUMENT, 0);
    REQUIRE(close(pair[0]) == 0);
    REQUIRE(close(pair[1]) == 0);
}

static void test_non_socket_and_closed_fd(void)
{
    int pipes[2];
    REQUIRE(pipe2(pipes, O_NONBLOCK | O_CLOEXEC) == 0);
    check_real_rejection(pipes[0], VIREO_RESULT_IO, ENOTSOCK);
    REQUIRE(close(pipes[0]) == 0);
    REQUIRE(close(pipes[1]) == 0);
    int regular = open("/dev/null", O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    REQUIRE(regular >= 0);
    check_real_rejection(regular, VIREO_RESULT_IO, ENOTSOCK);
    REQUIRE(close(regular) == 0);
    int fd = regular;
    vireo_connection_t *connection = NULL;
    vireo_connection_error_t error;
    errno = E2BIG;
    CHECK(vireo_connection_create(&options, &fd, &connection, &error) == VIREO_RESULT_IO);
    CHECK(fd == regular && connection == NULL && errno == E2BIG);
    check_error(&error, VIREO_CONNECTION_STAGE_VALIDATE_FD, EBADF);
}

static void test_unconnected_and_listener(void)
{
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    REQUIRE(fd >= 0);
    check_real_rejection(fd, VIREO_RESULT_IO, ENOTCONN);
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    REQUIRE(bind(fd, (struct sockaddr *)&address, (socklen_t)sizeof(address)) == 0);
    REQUIRE(listen(fd, 1) == 0);
    check_real_rejection(fd, VIREO_RESULT_IO, ENOTCONN);
    REQUIRE(close(fd) == 0);
}

static void test_independent_and_repeated(void)
{
    size_t before = fd_count();
    for (unsigned i = 0; i < 128; ++i) {
        int a[2], b[2];
        pair_create(a);
        pair_create(b);
        int fd_a = a[0], fd_b = b[0];
        vireo_connection_t *first = NULL, *second = NULL;
        vireo_connection_options_t different = {3, 5, 10};
        REQUIRE(vireo_connection_create(&options, &fd_a, &first, NULL) == VIREO_OK);
        REQUIRE(vireo_connection_create(&different, &fd_b, &second, NULL) == VIREO_OK);
        CHECK(first != second && fd_a == -1 && fd_b == -1);
        REQUIRE(vireo_connection_destroy(&first, NULL) == VIREO_OK);
        CHECK(fcntl(b[0], F_GETFD) >= 0 && fcntl(b[1], F_GETFD) >= 0);
        vireo_connection_info_t info;
        CHECK(vireo_connection_inspect(second, &info) == VIREO_OK);
        CHECK(info.buffer_capacity_bytes == 8 && info.max_buffer_bytes == 10);
        CHECK(info.read_buffer.capacity == 3 && info.write_buffer.capacity == 5);
        REQUIRE(vireo_connection_destroy(&second, NULL) == VIREO_OK);
        REQUIRE(close(a[1]) == 0);
        REQUIRE(close(b[1]) == 0);
    }
    CHECK(fd_count() == before);
}

/* 新进程内验证 fd=0；返回 main 正常退出，保留 sanitizer 结束检查。 */
static int fd_zero_case(void)
{
    size_t before = fd_count();
    int original_flags = fcntl(0, F_GETFD);
    REQUIRE(original_flags >= 0 || errno == EBADF);
    int saved_stdin = -1;
    if (original_flags >= 0) {
        saved_stdin = fcntl(0, F_DUPFD_CLOEXEC, 3);
        REQUIRE(saved_stdin >= 0);
    }
    int pair[2];
    pair_create(pair);
    if (pair[0] != 0) {
        REQUIRE(dup2(pair[0], 0) == 0);
        REQUIRE(close(pair[0]) == 0);
    }
    /* dup2 会清 CLOEXEC；fixture 先设置，再由 connection 只读验证。 */
    REQUIRE(fcntl(0, F_SETFD, FD_CLOEXEC) == 0);
    int fd = 0;
    vireo_connection_t *connection = NULL;
    errno = E2BIG;
    CHECK(vireo_connection_create(&options, &fd, &connection, NULL) == VIREO_OK);
    CHECK(fd == -1 && connection != NULL && errno == E2BIG);
    CHECK(vireo_connection_destroy(&connection, NULL) == VIREO_OK);
    CHECK(connection == NULL && errno == E2BIG);
    CHECK(fcntl(0, F_GETFD) == -1 && errno == EBADF);
    REQUIRE(close(pair[1]) == 0);
    if (saved_stdin >= 0) {
        REQUIRE(dup2(saved_stdin, 0) == 0);
        REQUIRE(fcntl(0, F_SETFD, original_flags) == 0);
        REQUIRE(close(saved_stdin) == 0);
    }
    CHECK(fd_count() == before);
    printf("fd zero exec case: %u failures, owners and fd baseline checked\n", failures);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

static void test_fd_zero(void)
{
    pid_t child = fork();
    REQUIRE(child >= 0);
    if (child == 0) {
        /* fork 后只 exec/_exit；connection 操作在重新启动的进程执行。 */
        execl("/proc/self/exe", "vireo_connection_lifecycle_test", "--fd-zero-case",
              (char *)NULL);
        _exit(127);
    }
    int status = 0;
    pid_t waited;
    do {
        waited = waitpid(child, &status, 0);
    } while (waited < 0 && errno == EINTR);
    CHECK(waited == child && WIFEXITED(status) && WEXITSTATUS(status) == EXIT_SUCCESS);
}

static void test_private_ops_validation(void)
{
    int pair[2];
    pair_create(pair);
    int fd = pair[0];
    vireo_connection_t *connection = NULL;
    fixture_t f;
    vireo_connection_ops_t ops = fixture_ops(&f, &fd, &connection);
    vireo_connection_error_t error;
    errno = E2BIG;
    CHECK(vireo_connection_create_with_ops(&options, &fd, NULL, &connection, &error) ==
          VIREO_RESULT_INVALID_ARGUMENT);
    ops.close_fd = NULL;
    CHECK(vireo_connection_create_with_ops(&options, &fd, &ops, &connection, &error) ==
          VIREO_RESULT_INVALID_ARGUMENT);
    ops.close_fd = tracked_close;
    ops.receive = NULL;
    CHECK(vireo_connection_create_with_ops(&options, &fd, &ops, &connection, &error) ==
          VIREO_RESULT_INVALID_ARGUMENT);
    ops.receive = fixture_receive;
    ops.send_bytes = NULL;
    CHECK(vireo_connection_create_with_ops(&options, &fd, &ops, &connection, &error) ==
          VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(errno == E2BIG && fd == pair[0] && connection == NULL);
    CHECK(f.queries == 0 && f.allocations == 0);
    check_error(&error, VIREO_CONNECTION_STAGE_NONE, 0);
    REQUIRE(close(pair[0]) == 0);
    REQUIRE(close(pair[1]) == 0);
}

static void test_failure_without_diagnostic(void)
{
    for (unsigned i = 0; i < 3; ++i) {
        int pair[2];
        pair_create(pair);
        int fd = pair[0];
        vireo_connection_t *connection = NULL;
        fixture_t f;
        vireo_connection_ops_t ops = fixture_ops(&f, &fd, &connection);
        f.fail_query = i == 0 ? 4 : 0;
        f.query_errno = EINTR;
        f.fail_buffer = i == 1 ? 2 : 0;
        f.close_errno = i == 2 ? EINTR : 0;
        errno = E2BIG;
        vireo_result_t result = vireo_connection_create_with_ops(
            &options, &fd, &ops, &connection, NULL);
        CHECK(errno == E2BIG);
        if (i < 2) {
            CHECK(result == (i == 0 ? VIREO_RESULT_IO : VIREO_RESULT_NO_MEMORY));
            CHECK(fd == pair[0] && connection == NULL && f.closes == 0);
            CHECK(f.control_live == 0 && f.buffer_live == 0);
            CHECK(strcmp(f.release_order, i == 0 ? "" : "RC") == 0);
            REQUIRE(close(pair[0]) == 0);
        } else {
            REQUIRE(result == VIREO_OK);
            CHECK(fd == -1 && connection != NULL);
            CHECK(vireo_connection_destroy(&connection, NULL) == VIREO_RESULT_IO);
            CHECK(errno == E2BIG && connection == NULL && f.closes == 1);
            CHECK(f.control_live == 0 && f.buffer_live == 0);
            CHECK(strcmp(f.release_order, "XWRC") == 0);
        }
        REQUIRE(close(pair[1]) == 0);
    }
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--fd-zero-case") == 0) {
        return fd_zero_case();
    }
    REQUIRE(argc == 1);
    struct test_case {
        char const *name;
        void (*run)(void);
    } const cases[] = {
        {"public lifecycle and errno", test_public_lifecycle},
        {"invalid arguments and owners", test_invalid_arguments},
        {"failed inspect preserves all bytes", test_failed_inspect},
        {"capacity rejection precedes resources", test_capacity_rejection},
        {"minimum allocation and maximum validation", test_capacity_acceptance},
        {"four query failures without retry", test_query_failures},
        {"three construction failures and reverse rollback", test_allocation_rollback},
        {"distinct buffers and resource release order", test_tracked_success},
        {"close errors consume owner and never close reused fd", test_close_failure},
        {"real missing flags and datagram", test_missing_flags_and_type},
        {"real non socket and closed fd", test_non_socket_and_closed_fd},
        {"real unconnected socket and listener", test_unconnected_and_listener},
        {"independent instances and 128 paired repetitions", test_independent_and_repeated},
        {"fd zero transfer after exec", test_fd_zero},
        {"private dependency validation", test_private_ops_validation},
        {"failure cleanup with optional diagnostic omitted", test_failure_without_diagnostic}
    };
    size_t before = fd_count();
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        unsigned previous = failures;
        cases[i].run();
        printf("%s: %s\n", cases[i].name, failures == previous ? "PASS" : "FAIL");
    }
    CHECK(fd_count() == before);
    printf("connection lifecycle: %zu groups, %u failures\n",
           sizeof(cases) / sizeof(cases[0]), failures);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
