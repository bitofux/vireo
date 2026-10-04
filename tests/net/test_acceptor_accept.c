/*
- PROJECT : VIREO
- FILE    : test_acceptor_accept.c
- AUTHOR  : bitofux
- DATE    : 2026-10-04
- BRIEF   : 此模块负责：
- -- 真实 TCP/AF_UNIX 接入、双预算、客户 fd 转移和独立资源清理
- -- 本层 accept 故障下的部分进度、网络错误预算与拒绝输出保持
 */
#define _GNU_SOURCE
#include "net/acceptor_internal.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
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

typedef struct fixture {
    vireo_acceptor_t *owner;
    int listener;
    int family;
    struct sockaddr_storage address;
    socklen_t address_size;
    bool injected;
    bool running;
    unsigned allocations;
    unsigned frees;
    unsigned closes;
    size_t calls;
    int script[32]; /* 0 调真实 accept4；正 errno 注入一次负返回，不产生 fd。 */
    size_t script_size;
    size_t script_next;
} fixture_t;

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

static void *tracked_allocate(void *context, size_t bytes)
{
    fixture_t *f = context;
    CHECK(!f->running);
    ++f->allocations;
    return malloc(bytes);
}

static void tracked_free(void *context, void *memory)
{
    fixture_t *f = context;
    CHECK(!f->running && f->closes == 1);
    ++f->frees;
    free(memory);
    errno = ERANGE;
}

static int tracked_flags(void *context, int fd, int command)
{
    (void)context;
    return fcntl(fd, command);
}

static int tracked_option(void *context, int fd, int option, int *value, socklen_t *length)
{
    (void)context;
    return getsockopt(fd, SOL_SOCKET, option, value, length);
}

static int tracked_close(void *context, int fd)
{
    fixture_t *f = context;
    CHECK(!f->running && fd == f->listener && f->closes == 0);
    ++f->closes;
    return close(fd);
}

/* success 必须取真实新 socket，errno 污染证明正返回不以 errno 判错。 */
static int tracked_accept(void *context, int listener_fd, int flags)
{
    fixture_t *f = context;
    CHECK(f->running && listener_fd == f->listener);
    CHECK(flags == (SOCK_NONBLOCK | SOCK_CLOEXEC));
    CHECK(f->allocations == 1 && f->frees == 0 && f->closes == 0);
    ++f->calls;
    if (f->script_next < f->script_size) {
        int const cause = f->script[f->script_next++];
        if (cause != 0) {
            errno = cause;
            return -1;
        }
    }
    int const fd = accept4(listener_fd, NULL, NULL, flags);
    if (fd >= 0) errno = ERANGE;
    return fd;
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

/* 测试准备端点；接管之后 listener 仅作本层 seam 的身份断言。 */
static void fixture_init(fixture_t *f, int family, bool injected)
{
    *f = (fixture_t){0};
    f->family = family;
    f->injected = injected;
    f->listener = socket(family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    REQUIRE(f->listener >= 0);
    if (family == AF_INET) {
        struct sockaddr_in address = {0};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        REQUIRE(bind(f->listener, (struct sockaddr const *)&address,
                     (socklen_t)sizeof(address)) == 0);
    } else {
        REQUIRE(family == AF_UNIX);
        struct sockaddr_un address = {0};
        address.sun_family = AF_UNIX;
        int const n = snprintf(address.sun_path + 1, sizeof(address.sun_path) - 1,
                               "vireo-accept-%ld-%u", (long)getpid(), ++unix_names);
        REQUIRE(n > 0 && (size_t)n < sizeof(address.sun_path) - 1);
        REQUIRE(bind(f->listener, (struct sockaddr const *)&address,
                     (socklen_t)sizeof(address)) == 0);
    }
    REQUIRE(listen(f->listener, 8) == 0);
    f->address_size = (socklen_t)sizeof(f->address);
    REQUIRE(getsockname(f->listener, (struct sockaddr *)&f->address, &f->address_size) == 0);
    int fd_owner = f->listener;
    vireo_acceptor_options_t const options = {4096};
    vireo_acceptor_ops_t const ops = {
        f, tracked_allocate, tracked_free, tracked_flags, tracked_option, tracked_close,
        tracked_accept, tracked_loop_add, tracked_loop_mod, tracked_loop_del
    };
    errno = E2BIG;
    vireo_result_t const result = injected ?
        vireo_acceptor_create_with_ops(&options, &fd_owner, &ops, &f->owner, NULL) :
        vireo_acceptor_create(&options, &fd_owner, &f->owner, NULL);
    REQUIRE(result == VIREO_OK && f->owner != NULL && fd_owner == -1);
    CHECK(errno == E2BIG);
}

static void fixture_destroy(fixture_t *f)
{
    errno = E2BIG;
    CHECK(vireo_acceptor_destroy(&f->owner, NULL) == VIREO_OK);
    CHECK(errno == E2BIG && f->owner == NULL);
    if (f->injected) CHECK(f->allocations == 1 && f->frees == 1 && f->closes == 1);
}

/* 每个 peer 先送不同字节；逐客户验证队列前缀与数据归属，不只数 fd。 */
static int connect_peer(fixture_t const *f, unsigned char byte)
{
    int const fd = socket(f->family, SOCK_STREAM | SOCK_CLOEXEC, 0);
    REQUIRE(fd >= 0);
    REQUIRE(connect(fd, (struct sockaddr const *)&f->address, f->address_size) == 0);
    REQUIRE(send(fd, &byte, 1, MSG_NOSIGNAL) == 1);
    return fd;
}

static void check_client(int fd, unsigned char expected)
{
    REQUIRE(fd >= 0);
    CHECK((fcntl(fd, F_GETFL) & O_NONBLOCK) != 0);
    CHECK((fcntl(fd, F_GETFD) & FD_CLOEXEC) != 0);
    int type = 0;
    socklen_t size = (socklen_t)sizeof(type);
    CHECK(getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &size) == 0 && type == SOCK_STREAM);
    struct sockaddr_storage peer;
    socklen_t peer_size = (socklen_t)sizeof(peer);
    CHECK(getpeername(fd, (struct sockaddr *)&peer, &peer_size) == 0);
    struct pollfd ready = {fd, POLLIN, 0};
    REQUIRE(poll(&ready, 1, 1000) == 1 && (ready.revents & POLLIN) != 0);
    unsigned char byte = 0;
    CHECK(recv(fd, &byte, 1, MSG_DONTWAIT) == 1 && byte == expected);
}

static void close_owner(int *owner)
{
    REQUIRE(*owner >= 0);
    CHECK(close(*owner) == 0);
    *owner = -1;
}

static vireo_result_t batch(fixture_t *f, vireo_acceptor_accept_budget_t const *budget,
                             int *owners, size_t capacity, vireo_acceptor_accept_info_t *info,
                             vireo_acceptor_error_t *error)
{
    unsigned const allocations = f->allocations;
    unsigned const frees = f->frees;
    unsigned const closes = f->closes;
    size_t const before = f->calls;
    f->running = true;
    errno = E2BIG;
    vireo_result_t const result = vireo_acceptor_accept_batch(f->owner, budget, owners, capacity,
                                                            info, error);
    CHECK(errno == E2BIG);
    f->running = false;
    CHECK(f->allocations == allocations && f->frees == frees && f->closes == closes);
    if (result == VIREO_OK || result == VIREO_RESULT_IO) {
        if (f->injected) CHECK(f->calls - before == info->accept_calls);
        CHECK(info->accepted_count + info->transient_errors <= info->accept_calls);
    }
    return result;
}

static void check_info(vireo_acceptor_accept_info_t const *info, size_t accepted, size_t calls,
                        size_t transient, vireo_acceptor_accept_stop_t reason)
{
    CHECK(info->accepted_count == accepted && info->accept_calls == calls);
    CHECK(info->transient_errors == transient && info->stop_reason == reason);
}

static void test_tcp_remaining_and_tail(void)
{
    ++groups;
    fixture_t f;
    fixture_init(&f, AF_INET, false);
    int peers[4];
    for (unsigned i = 0; i < 4; ++i) peers[i] = connect_peer(&f, (unsigned char)(20U + i));
    int guard = open("/dev/null", O_RDONLY | O_CLOEXEC);
    REQUIRE(guard >= 0);
    int first[3] = {-1, -1, guard};
    vireo_acceptor_accept_budget_t budget = {2, SIZE_MAX};
    vireo_acceptor_accept_info_t info;
    vireo_acceptor_error_t error;
    CHECK(batch(&f, &budget, first, 3, &info, &error) == VIREO_OK);
    check_info(&info, 2, 2, 0, VIREO_ACCEPTOR_ACCEPT_BATCH_FULL);
    CHECK(first[2] == guard && error.stage == VIREO_ACCEPTOR_STAGE_NONE);
    int second[2] = {-1, -1};
    budget.max_accepts = 4;
    CHECK(batch(&f, &budget, second, 2, &info, NULL) == VIREO_OK);
    check_info(&info, 2, 2, 0, VIREO_ACCEPTOR_ACCEPT_BATCH_FULL);
    int empty = -1;
    CHECK(batch(&f, &budget, &empty, 1, &info, NULL) == VIREO_OK);
    check_info(&info, 0, 1, 0, VIREO_ACCEPTOR_ACCEPT_WOULD_BLOCK);
    CHECK(empty == -1);
    fixture_destroy(&f);
    for (unsigned i = 0; i < 2; ++i) {
        check_client(first[i], (unsigned char)(20U + i));
        check_client(second[i], (unsigned char)(22U + i));
        close_owner(&first[i]);
        close_owner(&second[i]);
    }
    for (unsigned i = 0; i < 4; ++i) close_owner(&peers[i]);
    close_owner(&guard);
}

static void test_unix_public(void)
{
    ++groups;
    fixture_t f;
    fixture_init(&f, AF_UNIX, false);
    int peers[3];
    for (unsigned i = 0; i < 3; ++i) peers[i] = connect_peer(&f, (unsigned char)(30U + i));
    int owners[4] = {-1, -1, -1, -1};
    vireo_acceptor_accept_budget_t const budget = {4, 8};
    vireo_acceptor_accept_info_t info;
    CHECK(batch(&f, &budget, owners, 4, &info, NULL) == VIREO_OK);
    check_info(&info, 3, 4, 0, VIREO_ACCEPTOR_ACCEPT_WOULD_BLOCK);
    CHECK(owners[3] == -1);
    for (unsigned i = 0; i < 3; ++i) {
        check_client(owners[i], (unsigned char)(30U + i));
        close_owner(&owners[i]);
        close_owner(&peers[i]);
    }
    fixture_destroy(&f);
}

static void test_empty_repeat(void)
{
    ++groups;
    fixture_t f;
    fixture_init(&f, AF_INET, true);
    int owner = -1;
    vireo_acceptor_accept_budget_t const budget = {1, SIZE_MAX};
    for (unsigned i = 0; i < 3; ++i) {
        vireo_acceptor_accept_info_t info;
        vireo_acceptor_error_t error = {VIREO_ACCEPTOR_STAGE_ACCEPT_CLIENT, EIO};
        CHECK(batch(&f, &budget, &owner, 1, &info, &error) == VIREO_OK);
        check_info(&info, 0, 1, 0, VIREO_ACCEPTOR_ACCEPT_WOULD_BLOCK);
        CHECK(owner == -1 && error.stage == VIREO_ACCEPTOR_STAGE_NONE && error.system_errno == 0);
    }
    fixture_destroy(&f);
}

static void test_call_budget_and_queue(void)
{
    ++groups;
    fixture_t f;
    fixture_init(&f, AF_INET, true);
    int peers[2];
    for (unsigned i = 0; i < 2; ++i) peers[i] = connect_peer(&f, (unsigned char)(40U + i));
    vireo_acceptor_accept_budget_t const budget = {2, 1};
    for (unsigned i = 0; i < 3; ++i) {
        int owners[2] = {-1, -1};
        vireo_acceptor_accept_info_t info;
        CHECK(batch(&f, &budget, owners, 2, &info, NULL) == VIREO_OK);
        if (i < 2) {
            check_info(&info, 1, 1, 0, VIREO_ACCEPTOR_ACCEPT_CALL_BUDGET);
            check_client(owners[0], (unsigned char)(40U + i));
            close_owner(&owners[0]);
        } else check_info(&info, 0, 1, 0, VIREO_ACCEPTOR_ACCEPT_WOULD_BLOCK);
        CHECK(owners[1] == -1);
    }
    close_owner(&peers[0]);
    close_owner(&peers[1]);
    fixture_destroy(&f);
}

static void test_boundary_priority(void)
{
    ++groups;
    fixture_t f;
    fixture_init(&f, AF_INET, true);
    int peer = connect_peer(&f, 50);
    f.script[0] = 0;
    f.script[1] = EMFILE;
    f.script_size = 2;
    int owner = -1;
    vireo_acceptor_accept_budget_t const budget = {1, 1};
    vireo_acceptor_accept_info_t info;
    CHECK(batch(&f, &budget, &owner, 1, &info, NULL) == VIREO_OK);
    check_info(&info, 1, 1, 0, VIREO_ACCEPTOR_ACCEPT_BATCH_FULL);
    CHECK(f.script_next == 1);
    check_client(owner, 50);
    close_owner(&owner);
    CHECK(batch(&f, &budget, &owner, 1, &info, NULL) == VIREO_RESULT_IO);
    check_info(&info, 0, 1, 0, VIREO_ACCEPTOR_ACCEPT_IO_ERROR);
    close_owner(&peer);
    fixture_destroy(&f);
}

static void test_partial_io(void)
{
    ++groups;
    int const causes[] = {EINTR, EIO, EMFILE, ENFILE, ENOMEM, ENOBUFS, EBADF, ENOSYS, EPERM, EINVAL};
    for (size_t i = 0; i < sizeof(causes) / sizeof(causes[0]); ++i) {
        fixture_t f;
        fixture_init(&f, AF_INET, true);
        int peers[2];
        for (unsigned j = 0; j < 2; ++j) peers[j] = connect_peer(&f, (unsigned char)(60U + j));
        f.script[2] = causes[i];
        f.script_size = 4;
        int owners[4] = {-1, -1, -1, -1};
        vireo_acceptor_accept_budget_t const budget = {4, 8};
        vireo_acceptor_accept_info_t info;
        vireo_acceptor_error_t error;
        CHECK(batch(&f, &budget, owners, 4, &info, &error) == VIREO_RESULT_IO);
        check_info(&info, 2, 3, 0, VIREO_ACCEPTOR_ACCEPT_IO_ERROR);
        CHECK(error.stage == VIREO_ACCEPTOR_STAGE_ACCEPT_CLIENT &&
              error.system_errno == causes[i]);
        CHECK(owners[2] == -1 && owners[3] == -1 && f.script_next == 3);
        int next = -1;
        CHECK(batch(&f, &budget, &next, 1, &info, &error) == VIREO_OK);
        check_info(&info, 0, 1, 0, VIREO_ACCEPTOR_ACCEPT_WOULD_BLOCK);
        CHECK(error.stage == VIREO_ACCEPTOR_STAGE_NONE && error.system_errno == 0);
        for (unsigned j = 0; j < 2; ++j) {
            check_client(owners[j], (unsigned char)(60U + j));
            close_owner(&owners[j]);
            close_owner(&peers[j]);
        }
        fixture_destroy(&f);
    }
}

static void test_first_io_optional_error(void)
{
    ++groups;
    fixture_t f;
    fixture_init(&f, AF_INET, true);
    f.script[0] = EINTR;
    f.script[1] = EAGAIN;
    f.script_size = 2;
    int owners[2] = {-1, -1};
    vireo_acceptor_accept_budget_t const budget = {2, 3};
    vireo_acceptor_accept_info_t info;
    memset(&info, 0xa5, sizeof(info));
    CHECK(batch(&f, &budget, owners, 2, &info, NULL) == VIREO_RESULT_IO);
    check_info(&info, 0, 1, 0, VIREO_ACCEPTOR_ACCEPT_IO_ERROR);
    CHECK(f.script_next == 1 && owners[0] == -1 && owners[1] == -1);
    CHECK(batch(&f, &budget, owners, 2, &info, NULL) == VIREO_OK);
    check_info(&info, 0, 1, 0, VIREO_ACCEPTOR_ACCEPT_WOULD_BLOCK);
    fixture_destroy(&f);
}

static void test_all_transient_errors(void)
{
    ++groups;
    int const causes[] = {ECONNABORTED, ENETDOWN, EPROTO, ENOPROTOOPT, EHOSTDOWN, ENONET,
                          EHOSTUNREACH, EOPNOTSUPP, ENETUNREACH};
    fixture_t f;
    fixture_init(&f, AF_INET, true);
    int peer = connect_peer(&f, 70);
    memcpy(f.script, causes, sizeof(causes));
    f.script[10] = EWOULDBLOCK;
    f.script_size = 11;
    int owners[2] = {-1, -1};
    vireo_acceptor_accept_budget_t const budget = {2, SIZE_MAX};
    vireo_acceptor_accept_info_t info;
    vireo_acceptor_error_t error;
    CHECK(batch(&f, &budget, owners, 2, &info, &error) == VIREO_OK);
    check_info(&info, 1, 11, 9, VIREO_ACCEPTOR_ACCEPT_WOULD_BLOCK);
    CHECK(error.stage == VIREO_ACCEPTOR_STAGE_NONE && error.system_errno == 0);
    CHECK(owners[1] == -1 && f.script_next == 11);
    check_client(owners[0], 70);
    close_owner(&owners[0]);
    close_owner(&peer);
    fixture_destroy(&f);
}

static void test_transient_budget(void)
{
    ++groups;
    fixture_t f;
    fixture_init(&f, AF_INET, true);
    int const script[] = {EPROTO, ECONNABORTED, ENETDOWN, EIO};
    memcpy(f.script, script, sizeof(script));
    f.script_size = 4;
    int owners[2] = {-1, -1};
    vireo_acceptor_accept_budget_t const budget = {2, 3};
    vireo_acceptor_accept_info_t info;
    CHECK(batch(&f, &budget, owners, 2, &info, NULL) == VIREO_OK);
    check_info(&info, 0, 3, 3, VIREO_ACCEPTOR_ACCEPT_CALL_BUDGET);
    CHECK(f.script_next == 3 && owners[0] == -1 && owners[1] == -1);
    CHECK(batch(&f, &budget, owners, 2, &info, NULL) == VIREO_RESULT_IO);
    check_info(&info, 0, 1, 0, VIREO_ACCEPTOR_ACCEPT_IO_ERROR);
    fixture_destroy(&f);
}

static void test_mixed_progress_limit(void)
{
    ++groups;
    fixture_t f;
    fixture_init(&f, AF_UNIX, true);
    int peers[2];
    for (unsigned i = 0; i < 2; ++i) peers[i] = connect_peer(&f, (unsigned char)(80U + i));
    int const script[] = {ECONNABORTED, 0, EPROTO, 0, EIO};
    memcpy(f.script, script, sizeof(script));
    f.script_size = 5;
    int owners[2] = {-1, -1};
    vireo_acceptor_accept_budget_t const budget = {2, 4};
    vireo_acceptor_accept_info_t info;
    CHECK(batch(&f, &budget, owners, 2, &info, NULL) == VIREO_OK);
    check_info(&info, 2, 4, 2, VIREO_ACCEPTOR_ACCEPT_BATCH_FULL);
    CHECK(f.script_next == 4);
    for (unsigned i = 0; i < 2; ++i) {
        check_client(owners[i], (unsigned char)(80U + i));
        close_owner(&owners[i]);
        close_owner(&peers[i]);
    }
    fixture_destroy(&f);
}

static void test_would_block_partial(void)
{
    ++groups;
    int const causes[] = {EAGAIN, EWOULDBLOCK};
    for (size_t i = 0; i < sizeof(causes) / sizeof(causes[0]); ++i) {
        fixture_t f;
        fixture_init(&f, AF_INET, true);
        int peer = connect_peer(&f, 90);
        f.script[1] = causes[i];
        f.script_size = 2;
        int owners[2] = {-1, -1};
        vireo_acceptor_accept_budget_t const budget = {2, 2};
        vireo_acceptor_accept_info_t info;
        CHECK(batch(&f, &budget, owners, 2, &info, NULL) == VIREO_OK);
        check_info(&info, 1, 2, 0, VIREO_ACCEPTOR_ACCEPT_WOULD_BLOCK);
        CHECK(owners[1] == -1);
        check_client(owners[0], 90);
        close_owner(&owners[0]);
        close_owner(&peer);
        fixture_destroy(&f);
    }
}

static void test_invalid_outputs(void)
{
    ++groups;
    fixture_t f;
    fixture_init(&f, AF_INET, true);
    int guard = open("/dev/null", O_RDONLY | O_CLOEXEC);
    REQUIRE(guard >= 0);
    for (unsigned which = 0; which < 10; ++which) {
        int owners[3] = {-1, -1, guard};
        if (which == 7) owners[0] = guard;
        if (which == 8) owners[1] = -2;
        if (which == 9) owners[1] = guard;
        vireo_acceptor_accept_info_t info;
        memset(&info, 0xa5, sizeof(info));
        unsigned char before[sizeof(info)];
        memcpy(before, &info, sizeof(info));
        int owners_before[3];
        memcpy(owners_before, owners, sizeof(owners));
        vireo_acceptor_accept_budget_t budget = {2, 4};
        if (which == 5) budget.max_accepts = 0;
        if (which == 6) budget.max_syscalls = 0;
        vireo_acceptor_error_t error = {VIREO_ACCEPTOR_STAGE_ACCEPT_CLIENT, EIO};
        f.running = true;
        errno = E2BIG;
        CHECK(vireo_acceptor_accept_batch(which == 0 ? NULL : f.owner,
            which == 1 ? NULL : &budget, which == 2 ? NULL : owners, which == 3 ? 0 : 3,
            which == 4 ? NULL : &info, &error) == VIREO_RESULT_INVALID_ARGUMENT);
        CHECK(errno == E2BIG);
        f.running = false;
        CHECK(memcmp(before, &info, sizeof(info)) == 0);
        CHECK(memcmp(owners_before, owners, sizeof(owners)) == 0 && f.calls == 0);
        CHECK(error.stage == VIREO_ACCEPTOR_STAGE_NONE && error.system_errno == 0);
    }
    close_owner(&guard);
    fixture_destroy(&f);
}

static void test_range(void)
{
    ++groups;
    fixture_t f;
    fixture_init(&f, AF_INET, true);
    size_t const values[] = {VIREO_ACCEPTOR_MAX_BATCH + 1, SIZE_MAX};
    for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); ++i) {
        for (unsigned which = 0; which < 2; ++which) {
            int owner = -1;
            vireo_acceptor_accept_info_t info;
            memset(&info, 0xa5, sizeof(info));
            unsigned char before[sizeof(info)];
            memcpy(before, &info, sizeof(info));
            vireo_acceptor_accept_budget_t const budget = {which == 0 ? values[i] : 1, SIZE_MAX};
            CHECK(batch(&f, &budget, &owner, which == 0 ? 1 : values[i], &info, NULL) ==
                  VIREO_RESULT_RANGE);
            CHECK(owner == -1 && memcmp(before, &info, sizeof(info)) == 0 && f.calls == 0);
        }
    }
    fixture_destroy(&f);
}

static void test_maximum_prefix(void)
{
    ++groups;
    fixture_t f;
    fixture_init(&f, AF_INET, true);
    size_t const capacity = VIREO_ACCEPTOR_MAX_BATCH;
    int *memory = malloc((capacity + 2) * sizeof(*memory));
    REQUIRE(memory != NULL);
    memory[0] = 123;
    memory[capacity + 1] = 456;
    int *owners = memory + 1;
    for (size_t i = 0; i < capacity; ++i) owners[i] = -1;
    vireo_acceptor_accept_budget_t const budget = {capacity, SIZE_MAX};
    vireo_acceptor_accept_info_t info;
    CHECK(batch(&f, &budget, owners, capacity, &info, NULL) == VIREO_OK);
    check_info(&info, 0, 1, 0, VIREO_ACCEPTOR_ACCEPT_WOULD_BLOCK);
    owners[capacity - 1] = -2;
    unsigned char before[sizeof(info)];
    memcpy(before, &info, sizeof(info));
    CHECK(batch(&f, &budget, owners, capacity, &info, NULL) == VIREO_RESULT_INVALID_ARGUMENT);
    CHECK(memcmp(before, &info, sizeof(info)) == 0 && f.calls == 1);
    for (size_t i = 0; i < capacity - 1; ++i) CHECK(owners[i] == -1);
    CHECK(owners[capacity - 1] == -2 && memory[0] == 123 && memory[capacity + 1] == 456);
    free(memory);
    fixture_destroy(&f);
}

static void test_destroy_after_partial_io(void)
{
    ++groups;
    fixture_t f;
    fixture_init(&f, AF_INET, true);
    int peer = connect_peer(&f, 100);
    f.script[1] = EMFILE;
    f.script_size = 2;
    int owners[2] = {-1, -1};
    vireo_acceptor_accept_budget_t const budget = {2, 8};
    vireo_acceptor_accept_info_t info;
    CHECK(batch(&f, &budget, owners, 2, &info, NULL) == VIREO_RESULT_IO);
    check_info(&info, 1, 2, 0, VIREO_ACCEPTOR_ACCEPT_IO_ERROR);
    fixture_destroy(&f);
    check_client(owners[0], 100);
    close_owner(&owners[0]);
    close_owner(&peer);
    CHECK(owners[1] == -1);
}

static void test_independent_and_cycles(void)
{
    ++groups;
    fixture_t first;
    fixture_t second;
    fixture_init(&first, AF_INET, true);
    fixture_init(&second, AF_UNIX, true);
    fixture_t *const fixtures[] = {&first, &second};
    vireo_acceptor_accept_budget_t const budget = {1, 1};
    for (unsigned i = 0; i < 40; ++i) {
        for (size_t j = 0; j < 2; ++j) {
            int peer = connect_peer(fixtures[j], (unsigned char)i);
            int owner = -1;
            vireo_acceptor_accept_info_t info;
            CHECK(batch(fixtures[j], &budget, &owner, 1, &info, NULL) == VIREO_OK);
            check_info(&info, 1, 1, 0, VIREO_ACCEPTOR_ACCEPT_BATCH_FULL);
            check_client(owner, (unsigned char)i);
            close_owner(&owner);
            close_owner(&peer);
        }
    }
    CHECK(first.calls == 40 && second.calls == 40);
    fixture_destroy(&first);
    fixture_destroy(&second);
}

static int fd_zero_case(void)
{
    (void)close(STDIN_FILENO);
    unsigned const baseline = fd_count();
    int placeholder = open("/dev/null", O_RDONLY | O_CLOEXEC);
    REQUIRE(placeholder == 0);
    fixture_t f;
    fixture_init(&f, AF_INET, false);
    int peer = connect_peer(&f, 110);
    close_owner(&placeholder);
    int owner = -1;
    vireo_acceptor_accept_budget_t const budget = {1, 1};
    vireo_acceptor_accept_info_t info;
    CHECK(batch(&f, &budget, &owner, 1, &info, NULL) == VIREO_OK);
    check_info(&info, 1, 1, 0, VIREO_ACCEPTOR_ACCEPT_BATCH_FULL);
    REQUIRE(owner == 0);
    fixture_destroy(&f);
    check_client(owner, 110);
    close_owner(&owner);
    close_owner(&peer);
    CHECK(fd_count() == baseline);
    printf("acceptor accept fd0 exec: %u failures; flags/data/ownership/fd checked\n", failures);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

static void test_fd_zero_exec(void)
{
    ++groups;
    pid_t const child = fork();
    REQUIRE(child >= 0);
    if (child == 0) {
        execl("/proc/self/exe", "vireo_acceptor_accept_test", "--fd-zero", (char *)NULL);
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
    test_tcp_remaining_and_tail();
    test_unix_public();
    test_empty_repeat();
    test_call_budget_and_queue();
    test_boundary_priority();
    test_partial_io();
    test_first_io_optional_error();
    test_all_transient_errors();
    test_transient_budget();
    test_mixed_progress_limit();
    test_would_block_partial();
    test_invalid_outputs();
    test_range();
    test_maximum_prefix();
    test_destroy_after_partial_io();
    test_independent_and_cycles();
    test_fd_zero_exec();
    unsigned const final = fd_count();
    CHECK(final == baseline);
    printf("acceptor accept: %u groups, %u failures; fd %u -> %u\n",
           groups, failures, baseline, final);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
