/*
- PROJECT : VIREO
- FILE    : test_acceptor_lifecycle.c
- AUTHOR  : bitofux
- DATE    : 2026-10-04
- BRIEF   : 此模块负责：
- -- 真实 IPv4/AF_UNIX listener、fd=0 与资源基线测试
- -- 查询、分配、发布和消费型 close IO 的本层边界验证
 */
#define _GNU_SOURCE
#include "net/acceptor_internal.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

static unsigned failures;
static unsigned groups;
static unsigned unix_names;
#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition); \
        ++failures; \
    } \
} while (0)
#define REQUIRE(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "fixture failure %s:%d: %s\n", __FILE__, __LINE__, #condition); \
        exit(EXIT_FAILURE); \
    } \
} while (0)

static vireo_acceptor_options_t const options = {4096};

static int make_listener(int family)
{
    int const fd = socket(family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    REQUIRE(fd >= 0);
    if (family == AF_INET) {
        struct sockaddr_in address = {0};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        REQUIRE(bind(fd, (struct sockaddr const *)&address, (socklen_t)sizeof(address)) == 0);
    } else {
        REQUIRE(family == AF_UNIX);
        struct sockaddr_un address = {0};
        address.sun_family = AF_UNIX;
        int const n = snprintf(address.sun_path + 1, sizeof(address.sun_path) - 1,
                               "vireo-acceptor-%ld-%u", (long)getpid(), ++unix_names);
        REQUIRE(n > 0 && (size_t)n < sizeof(address.sun_path) - 1);
        /* Linux abstract namespace；没有 filesystem socket 文件或 unlink 责任。 */
        REQUIRE(bind(fd, (struct sockaddr const *)&address, (socklen_t)sizeof(address)) == 0);
    }
    REQUIRE(listen(fd, 8) == 0);
    return fd;
}

static unsigned fd_count(void)
{
    DIR *directory = opendir("/proc/self/fd");
    REQUIRE(directory != NULL);
    unsigned count = 0;
    struct dirent *entry;
    while ((entry = readdir(directory)) != NULL) {
        if (entry->d_name[0] != '.') ++count;
    }
    REQUIRE(closedir(directory) == 0);
    return count;
}

static void check_closed(int fd)
{
    errno = 0;
    CHECK(fcntl(fd, F_GETFD) == -1 && errno == EBADF);
}

typedef struct fixture {
    int fd_owner;
    int original_fd;
    vireo_acceptor_t *owner;
    bool constructing;
    bool allocation_failure;
    bool closed;
    unsigned queries;
    unsigned fail_query;
    unsigned bad_length;
    unsigned allocations;
    unsigned deallocations;
    unsigned closes;
    unsigned live;
    int query_errno;
    int close_errno;
    int replacement_fd;
    char order[3];
} fixture_t;

static fixture_t make_fixture(void)
{
    fixture_t f = {0};
    f.fd_owner = make_listener(AF_INET);
    f.original_fd = f.fd_owner;
    f.query_errno = EIO;
    f.replacement_fd = -1;
    return f;
}

static void check_publication(fixture_t const *f)
{
    if (f->constructing) {
        CHECK(f->owner == NULL && f->fd_owner == f->original_fd);
    }
}

static void *tracked_allocate(void *context, size_t bytes)
{
    fixture_t *f = context;
    check_publication(f);
    CHECK(f->queries == 4 && f->live == 0);
    ++f->allocations;
    errno = ENOMEM;
    if (f->allocation_failure) return NULL;
    void *memory = malloc(bytes);
    REQUIRE(memory != NULL);
    ++f->live;
    return memory;
}

static void tracked_deallocate(void *context, void *memory)
{
    fixture_t *f = context;
    CHECK(f->closed && f->live == 1 && f->closes == 1 && f->owner == memory);
    f->order[1] = 'F';
    --f->live;
    ++f->deallocations;
    free(memory);
    errno = ERANGE;
}

static bool refuse_query(fixture_t *f, int fd)
{
    check_publication(f);
    CHECK(fd == f->original_fd && f->allocations == 0 && f->closes == 0);
    ++f->queries;
    errno = f->query_errno;
    return f->queries == f->fail_query;
}

static int tracked_flags(void *context, int fd, int command)
{
    fixture_t *f = context;
    if (refuse_query(f, fd)) return -1;
    CHECK(command == (f->queries == 1 ? F_GETFL : F_GETFD));
    return fcntl(fd, command);
}

static int tracked_option(void *context, int fd, int option, int *value, socklen_t *length)
{
    fixture_t *f = context;
    if (refuse_query(f, fd)) return -1;
    CHECK(option == (f->queries == 3 ? SO_TYPE : SO_ACCEPTCONN));
    CHECK(*length == (socklen_t)sizeof(*value));
    int const result = getsockopt(fd, SOL_SOCKET, option, value, length);
    REQUIRE(result == 0);
    if (f->queries == f->bad_length) --*length;
    return result;
}

/* 先真实关闭；错误与立即复用都是本模块 seam，不是内核 close 失败复现。 */
static int tracked_close(void *context, int fd)
{
    fixture_t *f = context;
    CHECK(!f->constructing && f->owner != NULL && f->live == 1 && f->fd_owner == -1);
    CHECK(fd == f->original_fd && f->closes == 0);
    ++f->closes;
    f->order[0] = 'L';
    REQUIRE(close(fd) == 0);
    f->closed = true;
    if (f->close_errno != 0) {
        f->replacement_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
        REQUIRE(f->replacement_fd == fd);
        errno = f->close_errno;
        return -1;
    }
    return 0;
}

/* 生命周期测试不接入客户，只为新增的完整逐对象表接好本层接口。 */
static int unused_accept(void *context, int listener_fd, int flags)
{
    (void)context;
    (void)listener_fd;
    (void)flags;
    errno = EIO;
    return -1;
}

/* 只通过已封板 loop 的公开入口补齐本模块依赖表。 */
static vireo_result_t tracked_loop_add(void *context, vireo_event_loop_t *loop,
    vireo_event_loop_registration_t const *registration, vireo_event_loop_handle_t *handle,
    vireo_event_loop_error_t *error)
{
    (void)context;
    return vireo_event_loop_add(loop, registration, handle, error);
}

static vireo_result_t tracked_loop_mod(void *context, vireo_event_loop_t *loop,
    vireo_event_loop_handle_t handle, uint32_t interests, vireo_event_loop_error_t *error)
{
    (void)context;
    return vireo_event_loop_mod(loop, handle, interests, error);
}

static vireo_result_t tracked_loop_del(void *context, vireo_event_loop_t *loop,
    vireo_event_loop_handle_t *handle, vireo_event_loop_error_t *error)
{
    (void)context;
    return vireo_event_loop_del(loop, handle, error);
}

static vireo_acceptor_ops_t make_ops(fixture_t *f)
{
    return (vireo_acceptor_ops_t){
        f, tracked_allocate, tracked_deallocate, tracked_flags, tracked_option, tracked_close,
        unused_accept, tracked_loop_add, tracked_loop_mod, tracked_loop_del
    };
}

static vireo_result_t fixture_create(fixture_t *f, vireo_acceptor_options_t const *opts,
                                     vireo_acceptor_error_t *error)
{
    vireo_acceptor_ops_t ops = make_ops(f);
    f->constructing = true;
    errno = E2BIG;
    vireo_result_t const result = vireo_acceptor_create_with_ops(opts, &f->fd_owner, &ops,
                                                               &f->owner, error);
    CHECK(errno == E2BIG);
    f->constructing = false;
    if (result != VIREO_OK) {
        CHECK(f->fd_owner == f->original_fd && f->owner == NULL);
        CHECK(f->closes == 0 && f->deallocations == 0 && f->live == 0);
        CHECK(fcntl(f->original_fd, F_GETFD) >= 0);
    }
    return result;
}

static void fixture_cleanup(fixture_t *f)
{
    if (f->owner != NULL) {
        errno = E2BIG;
        CHECK(vireo_acceptor_destroy(&f->owner, NULL) == VIREO_OK && errno == E2BIG);
        CHECK(f->closes == 1 && f->deallocations == 1 && f->live == 0);
        CHECK(strcmp(f->order, "LF") == 0);
    } else if (f->fd_owner >= 0) {
        CHECK(close(f->fd_owner) == 0);
        f->fd_owner = -1;
    }
}

static void test_public_lifecycle(int family)
{
    ++groups;
    int fd_owner = make_listener(family);
    int const original_fd = fd_owner;
    int const file_flags = fcntl(fd_owner, F_GETFL);
    int const descriptor_flags = fcntl(fd_owner, F_GETFD);
    vireo_acceptor_t *acceptor = NULL;
    vireo_acceptor_error_t error = {VIREO_ACCEPTOR_STAGE_CLOSE_LISTENER, EIO};
    errno = E2BIG;
    REQUIRE(vireo_acceptor_create(&options, &fd_owner, &acceptor, &error) == VIREO_OK);
    CHECK(errno == E2BIG && fd_owner == -1 && acceptor != NULL);
    CHECK(error.stage == VIREO_ACCEPTOR_STAGE_NONE && error.system_errno == 0);
    CHECK(fcntl(original_fd, F_GETFL) == file_flags);
    CHECK(fcntl(original_fd, F_GETFD) == descriptor_flags);
    vireo_acceptor_info_t info;
    REQUIRE(vireo_acceptor_inspect(acceptor, &info) == VIREO_OK);
    CHECK(errno == E2BIG && info.allocation_bytes > 0 && info.allocation_bytes <= 4096);
    CHECK(info.max_memory_bytes == 4096);
    CHECK(vireo_acceptor_destroy(&acceptor, &error) == VIREO_OK);
    CHECK(errno == E2BIG && acceptor == NULL && error.stage == VIREO_ACCEPTOR_STAGE_NONE);
    CHECK(vireo_acceptor_destroy(&acceptor, NULL) == VIREO_OK && errno == E2BIG);
    check_closed(original_fd);
}

static void test_invalid_arguments(void)
{
    ++groups;
    fixture_t f = make_fixture();
    vireo_acceptor_error_t error;
    int negative = -1;
    errno = E2BIG;
    CHECK(vireo_acceptor_create(NULL, &f.fd_owner, &f.owner, &error) ==
          VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_acceptor_create(&options, NULL, &f.owner, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_acceptor_create(&options, &negative, &f.owner, NULL) ==
          VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_acceptor_create(&options, &f.fd_owner, NULL, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(vireo_acceptor_destroy(NULL, &error) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(errno == E2BIG && f.owner == NULL && f.fd_owner == f.original_fd);
    CHECK(error.stage == VIREO_ACCEPTOR_STAGE_NONE && error.system_errno == 0);
    REQUIRE(fixture_create(&f, &options, NULL) == VIREO_OK);
    int other = make_listener(AF_INET);
    int const copy = other;
    vireo_acceptor_t *original = f.owner;
    errno = E2BIG;
    CHECK(vireo_acceptor_create(&options, &other, &f.owner, &error) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(errno == E2BIG && f.owner == original && other == copy);
    CHECK(close(other) == 0);
    fixture_cleanup(&f);
}

static void test_budget(void)
{
    ++groups;
    fixture_t f = make_fixture();
    REQUIRE(fixture_create(&f, &options, NULL) == VIREO_OK);
    vireo_acceptor_info_t info;
    REQUIRE(vireo_acceptor_inspect(f.owner, &info) == VIREO_OK);
    fixture_cleanup(&f);
    size_t const budgets[] = {0, 1, info.allocation_bytes - 1, info.allocation_bytes,
                             VIREO_ACCEPTOR_MAX_MEMORY, VIREO_ACCEPTOR_MAX_MEMORY + 1, SIZE_MAX};
    vireo_result_t const expected[] = {VIREO_RESULT_INVALID_ARGUMENT, VIREO_RESULT_RANGE,
        VIREO_RESULT_RANGE, VIREO_OK, VIREO_OK, VIREO_RESULT_RANGE, VIREO_RESULT_RANGE};
    for (size_t i = 0; i < sizeof(budgets) / sizeof(budgets[0]); ++i) {
        f = make_fixture();
        vireo_acceptor_options_t const opts = {budgets[i]};
        CHECK(fixture_create(&f, &opts, NULL) == expected[i]);
        CHECK(f.queries == (expected[i] == VIREO_OK ? 4U : 0U));
        if (f.owner != NULL) {
            REQUIRE(vireo_acceptor_inspect(f.owner, &info) == VIREO_OK);
            CHECK(info.allocation_bytes <= budgets[i] && info.max_memory_bytes == budgets[i]);
        }
        fixture_cleanup(&f);
    }
}

static void test_missing_flags(void)
{
    ++groups;
    for (unsigned which = 0; which < 2; ++which) {
        fixture_t f = make_fixture();
        if (which == 0) {
            int flags = fcntl(f.fd_owner, F_GETFL);
            REQUIRE(flags >= 0 && fcntl(f.fd_owner, F_SETFL, flags & ~O_NONBLOCK) == 0);
        } else {
            REQUIRE(fcntl(f.fd_owner, F_SETFD, 0) == 0);
        }
        vireo_acceptor_error_t error;
        CHECK(fixture_create(&f, &options, &error) == VIREO_RESULT_INVALID_ARGUMENT);
        CHECK(f.queries == which + 1 && f.allocations == 0);
        CHECK(error.stage == VIREO_ACCEPTOR_STAGE_NONE && error.system_errno == 0);
        fixture_cleanup(&f);
    }
}

static void test_wrong_socket_state(void)
{
    ++groups;
    int const types[] = {SOCK_STREAM, SOCK_DGRAM, SOCK_SEQPACKET};
    for (size_t i = 0; i < sizeof(types) / sizeof(types[0]); ++i) {
        int owner = socket(AF_UNIX, types[i] | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        REQUIRE(owner >= 0);
        int const original = owner;
        vireo_acceptor_t *acceptor = NULL;
        vireo_acceptor_error_t error;
        errno = E2BIG;
        CHECK(vireo_acceptor_create(&options, &owner, &acceptor, &error) ==
              VIREO_RESULT_INVALID_ARGUMENT);
        CHECK(errno == E2BIG && owner == original && acceptor == NULL);
        CHECK(error.stage == VIREO_ACCEPTOR_STAGE_NONE && error.system_errno == 0);
        CHECK(close(owner) == 0);
    }
}

static void test_non_socket_and_closed(void)
{
    ++groups;
    for (unsigned closed = 0; closed < 2; ++closed) {
        int owner = open("/dev/null", O_RDONLY | O_NONBLOCK | O_CLOEXEC);
        REQUIRE(owner >= 0);
        int const original = owner;
        if (closed != 0) REQUIRE(close(owner) == 0);
        vireo_acceptor_t *acceptor = NULL;
        vireo_acceptor_error_t error;
        errno = E2BIG;
        CHECK(vireo_acceptor_create(&options, &owner, &acceptor, &error) == VIREO_RESULT_IO);
        CHECK(errno == E2BIG && acceptor == NULL && owner == original);
        CHECK(error.stage == VIREO_ACCEPTOR_STAGE_VALIDATE_FD);
        CHECK(error.system_errno == (closed != 0 ? EBADF : ENOTSOCK));
        if (closed == 0) CHECK(close(owner) == 0);
    }
}

static void test_query_failures(void)
{
    ++groups;
    int const errors[] = {EINTR, EIO};
    for (size_t i = 0; i < sizeof(errors) / sizeof(errors[0]); ++i) {
        for (unsigned query = 1; query <= 4; ++query) {
            fixture_t f = make_fixture();
            f.fail_query = query;
            f.query_errno = errors[i];
            vireo_acceptor_error_t error;
            CHECK(fixture_create(&f, &options, &error) == VIREO_RESULT_IO);
            CHECK(f.queries == query && f.allocations == 0);
            CHECK(error.stage == VIREO_ACCEPTOR_STAGE_VALIDATE_FD &&
                  error.system_errno == errors[i]);
            fixture_cleanup(&f);
        }
    }
}

static void test_query_lengths(void)
{
    ++groups;
    for (unsigned query = 3; query <= 4; ++query) {
        fixture_t f = make_fixture();
        f.bad_length = query;
        vireo_acceptor_error_t error;
        CHECK(fixture_create(&f, &options, &error) == VIREO_RESULT_INTERNAL);
        CHECK(f.queries == query && f.allocations == 0);
        CHECK(error.stage == VIREO_ACCEPTOR_STAGE_VALIDATE_FD && error.system_errno == 0);
        fixture_cleanup(&f);
    }
}

static void test_allocation_failure(void)
{
    ++groups;
    fixture_t f = make_fixture();
    f.allocation_failure = true;
    vireo_acceptor_error_t error;
    CHECK(fixture_create(&f, &options, &error) == VIREO_RESULT_NO_MEMORY);
    CHECK(error.stage == VIREO_ACCEPTOR_STAGE_ALLOCATE_CONTROL && error.system_errno == 0);
    CHECK(f.queries == 4 && f.allocations == 1);
    fixture_cleanup(&f);
}

static void test_ops_copy_and_publication(void)
{
    ++groups;
    fixture_t f = make_fixture();
    vireo_acceptor_ops_t ops = make_ops(&f);
    f.constructing = true;
    errno = E2BIG;
    REQUIRE(vireo_acceptor_create_with_ops(&options, &f.fd_owner, &ops, &f.owner, NULL) == VIREO_OK);
    CHECK(errno == E2BIG && f.fd_owner == -1);
    f.constructing = false;
    ops = (vireo_acceptor_ops_t){0};
    fixture_cleanup(&f);
}

static void test_close_consumption(void)
{
    ++groups;
    int const errors[] = {EINTR, EIO};
    for (size_t i = 0; i < sizeof(errors) / sizeof(errors[0]); ++i) {
        fixture_t f = make_fixture();
        f.close_errno = errors[i];
        REQUIRE(fixture_create(&f, &options, NULL) == VIREO_OK);
        vireo_acceptor_error_t error;
        errno = E2BIG;
        CHECK(vireo_acceptor_destroy(&f.owner, &error) == VIREO_RESULT_IO);
        CHECK(errno == E2BIG && f.owner == NULL && f.fd_owner == -1 && f.live == 0);
        CHECK(error.stage == VIREO_ACCEPTOR_STAGE_CLOSE_LISTENER && error.system_errno == errors[i]);
        CHECK(f.closes == 1 && f.deallocations == 1 && strcmp(f.order, "LF") == 0);
        CHECK(vireo_acceptor_destroy(&f.owner, &error) == VIREO_OK && errno == E2BIG);
        CHECK(error.stage == VIREO_ACCEPTOR_STAGE_NONE && error.system_errno == 0);
        CHECK(f.closes == 1 && fcntl(f.replacement_fd, F_GETFD) >= 0);
        CHECK(close(f.replacement_fd) == 0);
    }
}

static void test_optional_diagnosis(void)
{
    ++groups;
    fixture_t f = make_fixture();
    f.fail_query = 3;
    CHECK(fixture_create(&f, &options, NULL) == VIREO_RESULT_IO);
    fixture_cleanup(&f);
    f = make_fixture();
    f.close_errno = EIO;
    REQUIRE(fixture_create(&f, &options, NULL) == VIREO_OK);
    errno = E2BIG;
    CHECK(vireo_acceptor_destroy(&f.owner, NULL) == VIREO_RESULT_IO && errno == E2BIG);
    CHECK(f.owner == NULL && f.live == 0 && f.closes == 1);
    CHECK(close(f.replacement_fd) == 0);
}

static void test_inspect_output(void)
{
    ++groups;
    vireo_acceptor_info_t info;
    memset(&info, 0xa5, sizeof(info));
    unsigned char before[sizeof(info)];
    memcpy(before, &info, sizeof(info));
    errno = E2BIG;
    CHECK(vireo_acceptor_inspect(NULL, &info) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(memcmp(before, &info, sizeof(info)) == 0 && errno == E2BIG);
    fixture_t f = make_fixture();
    REQUIRE(fixture_create(&f, &options, NULL) == VIREO_OK);
    CHECK(vireo_acceptor_inspect(f.owner, NULL) == VIREO_RESULT_INVALID_ARGUMENT && errno == E2BIG);
    fixture_cleanup(&f);
}

static void test_independent_and_repeated(void)
{
    ++groups;
    fixture_t first = make_fixture();
    fixture_t second = make_fixture();
    REQUIRE(fixture_create(&first, &options, NULL) == VIREO_OK);
    REQUIRE(fixture_create(&second, &options, NULL) == VIREO_OK);
    fixture_cleanup(&first);
    vireo_acceptor_info_t info;
    CHECK(vireo_acceptor_inspect(second.owner, &info) == VIREO_OK);
    CHECK(fcntl(second.original_fd, F_GETFD) >= 0);
    fixture_cleanup(&second);
    for (unsigned i = 0; i < 128; ++i) {
        fixture_t f = make_fixture();
        REQUIRE(fixture_create(&f, &options, NULL) == VIREO_OK);
        fixture_cleanup(&f);
    }
}

static void test_incomplete_ops(void)
{
    ++groups;
    fixture_t f = make_fixture();
    errno = E2BIG;
    CHECK(vireo_acceptor_create_with_ops(&options, &f.fd_owner, NULL, &f.owner, NULL) ==
          VIREO_RESULT_INVALID_ARGUMENT);
    for (unsigned i = 0; i < 9; ++i) {
        vireo_acceptor_ops_t ops = make_ops(&f);
        if (i == 0) ops.allocate = NULL;
        if (i == 1) ops.deallocate = NULL;
        if (i == 2) ops.get_flags = NULL;
        if (i == 3) ops.get_option = NULL;
        if (i == 4) ops.close_fd = NULL;
        if (i == 5) ops.accept_client = NULL;
        if (i == 6) ops.loop_add = NULL;
        if (i == 7) ops.loop_mod = NULL;
        if (i == 8) ops.loop_del = NULL;
        CHECK(vireo_acceptor_create_with_ops(&options, &f.fd_owner, &ops, &f.owner, NULL) ==
              VIREO_RESULT_INVALID_ARGUMENT);
        CHECK(errno == E2BIG && f.fd_owner == f.original_fd && f.owner == NULL);
    }
    CHECK(f.queries == 0 && f.allocations == 0 && f.closes == 0);
    fixture_cleanup(&f);
}

static int fd_zero_case(void)
{
    (void)close(STDIN_FILENO);
    unsigned const baseline = fd_count();
    int fd_owner = make_listener(AF_INET);
    REQUIRE(fd_owner == 0);
    vireo_acceptor_t *owner = NULL;
    errno = E2BIG;
    CHECK(vireo_acceptor_create(&options, &fd_owner, &owner, NULL) == VIREO_OK);
    CHECK(errno == E2BIG && fd_owner == -1 && owner != NULL);
    CHECK(vireo_acceptor_destroy(&owner, NULL) == VIREO_OK && errno == E2BIG);
    CHECK(owner == NULL);
    check_closed(0);
    CHECK(fd_count() == baseline);
    printf("acceptor fd0 exec: %u failures, ownership/errno/fd checked\n", failures);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

static void test_fd_zero_exec(void)
{
    ++groups;
    pid_t const child = fork();
    REQUIRE(child >= 0);
    if (child == 0) {
        /* fork 后只 async-signal-safe close/exec/_exit；构造在新 exec 的 main 内。 */
        (void)close(STDIN_FILENO);
        execl("/proc/self/exe", "vireo_acceptor_lifecycle_test", "--fd-zero", (char *)NULL);
        _exit(127);
    }
    int status;
    REQUIRE(waitpid(child, &status, 0) == child);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--fd-zero") == 0) return fd_zero_case();
    unsigned const baseline = fd_count();
    test_public_lifecycle(AF_INET);
    test_public_lifecycle(AF_UNIX);
    test_invalid_arguments();
    test_budget();
    test_missing_flags();
    test_wrong_socket_state();
    test_non_socket_and_closed();
    test_query_failures();
    test_query_lengths();
    test_allocation_failure();
    test_ops_copy_and_publication();
    test_close_consumption();
    test_optional_diagnosis();
    test_inspect_output();
    test_independent_and_repeated();
    test_incomplete_ops();
    test_fd_zero_exec();
    unsigned const final = fd_count();
    CHECK(final == baseline);
    printf("acceptor lifecycle: %u groups, %u failures; fd %u -> %u\n",
           groups, failures, baseline, final);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
