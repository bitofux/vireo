/*
- PROJECT : VIREO
- FILE    : test_acceptor_loop_binding.c
- AUTHOR  : bitofux
- DATE    : 2026-10-04
- BRIEF   : 此模块负责：
- -- 真实 loop 的监听通知、暂停接入、在途保护与旧批次身份失效
- -- 逐对象公开依赖故障、完整诊断及整体销毁后的本地解绑
 */
#define _GNU_SOURCE
#include "net/acceptor_internal.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/un.h>
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
#define EXPECT(expression, expected) do { \
    errno = E2BIG; \
    CHECK((expression) == (expected)); \
    CHECK(errno == E2BIG); \
} while (0)

typedef struct fixture {
    vireo_acceptor_t *owner;
    int listener;
    int family;
    struct sockaddr_storage address;
    socklen_t address_size;
    bool injected;
    unsigned allocations;
    unsigned frees;
    unsigned closes;
    unsigned adds;
    unsigned mods;
    unsigned dels;
    unsigned callbacks;
    uint32_t events;
    uint32_t last_interests;
    vireo_result_t fail_add;
    vireo_result_t fail_mod;
    vireo_result_t fail_del;
    vireo_event_loop_registration_t registration;
    vireo_event_loop_handle_t handle;
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

static void *allocate(void *context, size_t bytes)
{
    fixture_t *f = context;
    ++f->allocations;
    return malloc(bytes);
}

static void deallocate(void *context, void *memory)
{
    fixture_t *f = context;
    ++f->frees;
    free(memory);
    errno = ERANGE;
}

static int get_flags(void *context, int fd, int command)
{
    (void)context;
    return fcntl(fd, command);
}

static int get_option(void *context, int fd, int option, int *value, socklen_t *size)
{
    (void)context;
    return getsockopt(fd, SOL_SOCKET, option, value, size);
}

static int close_listener(void *context, int fd)
{
    fixture_t *f = context;
    CHECK(fd == f->listener && f->closes == 0);
    ++f->closes;
    return close(fd);
}

static int accept_client(void *context, int fd, int flags)
{
    fixture_t *f = context;
    CHECK(fd == f->listener && flags == (SOCK_NONBLOCK | SOCK_CLOEXEC));
    return accept4(fd, NULL, NULL, flags);
}

/* 失败在真实调用之前注入，不消费 handle、不改变原注册。 */
static vireo_result_t dependency_failure(vireo_result_t result,
    vireo_event_loop_stage_t stage, vireo_epoll_stage_t epoll_stage,
    vireo_event_loop_error_t *error)
{
    if (error != NULL) {
        *error = result == VIREO_RESULT_IO ? (vireo_event_loop_error_t){
            .stage = stage, .epoll_error = {epoll_stage, EINTR}, .system_errno = 0
        } : (vireo_event_loop_error_t){0};
    }
    errno = ERANGE;
    return result;
}

static vireo_result_t loop_add(void *context, vireo_event_loop_t *loop,
    vireo_event_loop_registration_t const *registration, vireo_event_loop_handle_t *handle,
    vireo_event_loop_error_t *error)
{
    fixture_t *f = context;
    ++f->adds;
    CHECK(registration->fd == f->listener && registration->context == f->owner);
    if (f->fail_add != VIREO_OK) {
        return dependency_failure(f->fail_add, VIREO_EVENT_LOOP_STAGE_ADD,
                                  VIREO_EPOLL_STAGE_ADD, error);
    }
    vireo_result_t const result = vireo_event_loop_add(loop, registration, handle, error);
    if (result == VIREO_OK) {
        f->registration = *registration;
        f->handle = *handle;
        f->last_interests = registration->interests;
    }
    errno = ERANGE;
    return result;
}

static vireo_result_t loop_mod(void *context, vireo_event_loop_t *loop,
    vireo_event_loop_handle_t handle, uint32_t interests, vireo_event_loop_error_t *error)
{
    fixture_t *f = context;
    ++f->mods;
    CHECK(handle.loop_id == f->handle.loop_id && handle.token == f->handle.token);
    if (f->fail_mod != VIREO_OK) {
        return dependency_failure(f->fail_mod, VIREO_EVENT_LOOP_STAGE_MOD,
                                  VIREO_EPOLL_STAGE_MOD, error);
    }
    vireo_result_t const result = vireo_event_loop_mod(loop, handle, interests, error);
    if (result == VIREO_OK) f->last_interests = interests;
    errno = ERANGE;
    return result;
}

static vireo_result_t loop_del(void *context, vireo_event_loop_t *loop,
    vireo_event_loop_handle_t *handle, vireo_event_loop_error_t *error)
{
    fixture_t *f = context;
    ++f->dels;
    CHECK(handle->loop_id == f->handle.loop_id && handle->token == f->handle.token);
    if (f->fail_del != VIREO_OK) {
        return dependency_failure(f->fail_del, VIREO_EVENT_LOOP_STAGE_DEL,
                                  VIREO_EPOLL_STAGE_DEL, error);
    }
    vireo_result_t const result = vireo_event_loop_del(loop, handle, error);
    errno = ERANGE;
    return result;
}

static void fixture_init(fixture_t *f, int family, bool injected)
{
    *f = (fixture_t){.family = family, .injected = injected};
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
                               "vireo-binding-%ld-%u", (long)getpid(), ++unix_names);
        REQUIRE(n > 0 && (size_t)n < sizeof(address.sun_path) - 1);
        REQUIRE(bind(f->listener, (struct sockaddr const *)&address,
                     (socklen_t)sizeof(address)) == 0);
    }
    REQUIRE(listen(f->listener, 8) == 0);
    f->address_size = (socklen_t)sizeof(f->address);
    REQUIRE(getsockname(f->listener, (struct sockaddr *)&f->address, &f->address_size) == 0);
    vireo_acceptor_ops_t const ops = {
        f, allocate, deallocate, get_flags, get_option, close_listener, accept_client,
        loop_add, loop_mod, loop_del
    };
    vireo_acceptor_options_t const options = {4096};
    int fd_owner = f->listener;
    errno = E2BIG;
    vireo_result_t const result = injected ?
        vireo_acceptor_create_with_ops(&options, &fd_owner, &ops, &f->owner, NULL) :
        vireo_acceptor_create(&options, &fd_owner, &f->owner, NULL);
    REQUIRE(result == VIREO_OK && f->owner != NULL && fd_owner == -1);
    CHECK(errno == E2BIG);
}

static void fixture_destroy(fixture_t *f)
{
    EXPECT(vireo_acceptor_destroy(&f->owner, NULL), VIREO_OK);
    CHECK(f->owner == NULL);
    if (f->injected) CHECK(f->allocations == 1 && f->frees == 1 && f->closes == 1);
}

static vireo_event_loop_t *make_loop(size_t registrations)
{
    vireo_event_loop_t *loop = NULL;
    vireo_event_loop_options_t const options = {8, 1048576, registrations};
    REQUIRE(vireo_event_loop_create(&options, &loop, NULL) == VIREO_OK);
    return loop;
}

static int connect_peer(fixture_t const *f)
{
    int const fd = socket(f->family, SOCK_STREAM | SOCK_CLOEXEC, 0);
    REQUIRE(fd >= 0);
    REQUIRE(connect(fd, (struct sockaddr const *)&f->address, f->address_size) == 0);
    unsigned char const byte = 73;
    REQUIRE(send(fd, &byte, 1, MSG_NOSIGNAL) == 1);
    return fd;
}

static void accept_one(fixture_t *f)
{
    vireo_acceptor_accept_budget_t const budget = {1, 1};
    vireo_acceptor_accept_info_t info;
    int client = -1;
    EXPECT(vireo_acceptor_accept_batch(f->owner, &budget, &client, 1, &info, NULL), VIREO_OK);
    REQUIRE(client >= 0 && info.accepted_count == 1 && info.accept_calls == 1);
    CHECK((fcntl(client, F_GETFL) & O_NONBLOCK) != 0);
    CHECK((fcntl(client, F_GETFD) & FD_CLOEXEC) != 0);
    struct pollfd ready = {client, POLLIN, 0};
    REQUIRE(poll(&ready, 1, 1000) == 1 && (ready.revents & POLLIN) != 0);
    unsigned char byte = 0;
    CHECK(recv(client, &byte, 1, MSG_DONTWAIT) == 1 && byte == 73);
    CHECK(close(client) == 0);
}

static void check_state(fixture_t *f, bool bound, bool active, bool read)
{
    vireo_acceptor_info_t info;
    EXPECT(vireo_acceptor_inspect(f->owner, &info), VIREO_OK);
    CHECK(info.loop_attached == bound && info.callback_active == active);
    CHECK(info.read_enabled == read && info.allocation_bytes <= info.max_memory_bytes);
}

static void notification(vireo_acceptor_t *acceptor, uint32_t events, void *context)
{
    fixture_t *f = context;
    CHECK(acceptor == f->owner);
    ++f->callbacks;
    f->events = events;
    check_state(f, true, true, true);
    CHECK((events & VIREO_EPOLL_EVENT_READ) != 0);
    accept_one(f);
    errno = ERANGE;
}

static vireo_event_loop_run_info_t run_once(vireo_event_loop_t *loop, int timeout)
{
    vireo_event_loop_run_info_t info;
    EXPECT(vireo_event_loop_run_once(loop, timeout, &info, NULL), VIREO_OK);
    return info;
}

static void check_clear(vireo_acceptor_loop_error_t const *error)
{
    CHECK(error->stage == VIREO_ACCEPTOR_LOOP_STAGE_NONE);
    CHECK(error->loop_error.stage == VIREO_EVENT_LOOP_STAGE_NONE);
    CHECK(error->loop_error.epoll_error.stage == VIREO_EPOLL_STAGE_NONE);
    CHECK(error->loop_error.epoll_error.system_errno == 0 && error->loop_error.system_errno == 0);
}

static void test_native(int family)
{
    ++groups;
    fixture_t f;
    fixture_init(&f, family, false);
    vireo_event_loop_t *loop = make_loop(2);
    vireo_acceptor_loop_error_t error;
    EXPECT(vireo_acceptor_attach(f.owner, loop, true, notification, &f, &error), VIREO_OK);
    check_clear(&error);
    check_state(&f, true, false, true);
    int const peer = connect_peer(&f);
    vireo_event_loop_run_info_t const info = run_once(loop, 1000);
    CHECK(info.ready_count == 1 && info.dispatched_count == 1 && f.callbacks == 1);
    CHECK(info.stale_count == 0 && info.filtered_count == 0);
    check_state(&f, true, false, true);
    EXPECT(vireo_acceptor_detach(f.owner, &error), VIREO_OK);
    check_clear(&error);
    CHECK(close(peer) == 0);
    fixture_destroy(&f);
    EXPECT(vireo_event_loop_destroy(&loop, NULL), VIREO_OK);
}

static void test_pause_and_strict_mod(void)
{
    ++groups;
    fixture_t f;
    fixture_init(&f, AF_INET, true);
    vireo_event_loop_t *loop = make_loop(1);
    EXPECT(vireo_acceptor_attach(f.owner, loop, false, notification, &f, NULL), VIREO_OK);
    CHECK(f.adds == 1 && f.last_interests == 0);
    int peer = connect_peer(&f);
    CHECK(run_once(loop, 0).dispatched_count == 0 && f.callbacks == 0);
    accept_one(&f); /* 暂停只影响通知，直接接入仍合法。 */
    CHECK(close(peer) == 0);
    EXPECT(vireo_acceptor_set_read_enabled(f.owner, false, NULL), VIREO_OK);
    CHECK(f.mods == 1 && f.last_interests == 0);
    peer = connect_peer(&f);
    EXPECT(vireo_acceptor_set_read_enabled(f.owner, true, NULL), VIREO_OK);
    EXPECT(vireo_acceptor_set_read_enabled(f.owner, true, NULL), VIREO_OK);
    CHECK(f.mods == 3 && f.last_interests == VIREO_EPOLL_INTEREST_READ);
    CHECK(run_once(loop, 1000).dispatched_count == 1 && f.callbacks == 1);
    EXPECT(vireo_acceptor_set_read_enabled(f.owner, false, NULL), VIREO_OK);
    check_state(&f, true, false, false);
    EXPECT(vireo_acceptor_detach(f.owner, NULL), VIREO_OK);
    EXPECT(vireo_acceptor_detach(f.owner, NULL), VIREO_OK);
    CHECK(f.dels == 1 && f.allocations == 1 && f.frees == 0 && f.closes == 0);
    CHECK(close(peer) == 0);
    fixture_destroy(&f);
    EXPECT(vireo_event_loop_destroy(&loop, NULL), VIREO_OK);
}

typedef struct active_context {
    fixture_t *f;
    vireo_event_loop_t **loop_owner;
    vireo_event_loop_t *other_loop;
} active_context_t;

static void guarded_callback(vireo_acceptor_t *acceptor, uint32_t events, void *context)
{
    active_context_t *c = context;
    fixture_t *f = c->f;
    CHECK(acceptor == f->owner && (events & VIREO_EPOLL_EVENT_READ) != 0);
    ++f->callbacks;
    check_state(f, true, true, true);
    vireo_acceptor_t *original = f->owner;
    vireo_acceptor_error_t error;
    EXPECT(vireo_acceptor_destroy(&f->owner, &error), VIREO_RESULT_BUSY);
    CHECK(f->owner == original && error.stage == VIREO_ACCEPTOR_STAGE_NONE);
    CHECK(error.system_errno == 0);
    EXPECT(vireo_event_loop_destroy(c->loop_owner, NULL), VIREO_RESULT_BUSY);
    vireo_event_loop_run_info_t stats = {17, 18, 19, 20};
    EXPECT(vireo_event_loop_run_once(*c->loop_owner, 0, &stats, NULL), VIREO_RESULT_BUSY);
    CHECK(stats.ready_count == 17 && stats.dispatched_count == 18);
    CHECK(run_once(c->other_loop, 0).ready_count == 0);
    EXPECT(vireo_acceptor_set_read_enabled(acceptor, false, NULL), VIREO_OK);
    accept_one(f);
    EXPECT(vireo_acceptor_detach(acceptor, NULL), VIREO_OK);
    check_state(f, false, true, false);
    EXPECT(vireo_acceptor_destroy(&f->owner, NULL), VIREO_RESULT_BUSY);
    EXPECT(vireo_acceptor_attach(acceptor, *c->loop_owner, true, notification, f, NULL),
           VIREO_RESULT_BUSY);
    EXPECT(vireo_acceptor_attach(acceptor, c->other_loop, true, notification, f, NULL),
           VIREO_RESULT_BUSY);
    /* 在途先拒绝，不把存活 loop 谎称为已销毁。 */
    EXPECT(vireo_acceptor_forget_destroyed_loop(acceptor, NULL), VIREO_RESULT_BUSY);
    CHECK(f->owner == original && f->closes == 0 && f->frees == 0 && f->adds == 1);
}

static void test_callback_lifetime(void)
{
    ++groups;
    fixture_t f;
    fixture_init(&f, AF_INET, true);
    vireo_event_loop_t *loop = make_loop(1);
    vireo_event_loop_t *other_loop = make_loop(1);
    active_context_t context = {&f, &loop, other_loop};
    EXPECT(vireo_acceptor_attach(f.owner, loop, true, guarded_callback, &context, NULL), VIREO_OK);
    int const peer = connect_peer(&f);
    CHECK(run_once(loop, 1000).dispatched_count == 1 && f.callbacks == 1);
    check_state(&f, false, false, false);
    EXPECT(vireo_acceptor_attach(f.owner, other_loop, false, notification, &f, NULL), VIREO_OK);
    EXPECT(vireo_acceptor_detach(f.owner, NULL), VIREO_OK);
    CHECK(close(peer) == 0);
    fixture_destroy(&f);
    EXPECT(vireo_event_loop_destroy(&loop, NULL), VIREO_OK);
    EXPECT(vireo_event_loop_destroy(&other_loop, NULL), VIREO_OK);
}

static void test_argument_and_bound_rejection(void)
{
    ++groups;
    fixture_t f;
    fixture_init(&f, AF_INET, true);
    vireo_event_loop_t *loop = make_loop(1);
    vireo_acceptor_loop_error_t error;
    EXPECT(vireo_acceptor_attach(NULL, loop, true, notification, &f, &error),
           VIREO_RESULT_INVALID_ARGUMENT);
    check_clear(&error);
    EXPECT(vireo_acceptor_attach(f.owner, NULL, true, notification, &f, NULL),
           VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_acceptor_attach(f.owner, loop, true, NULL, NULL, NULL),
           VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_acceptor_set_read_enabled(NULL, true, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_acceptor_detach(NULL, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_acceptor_forget_destroyed_loop(NULL, NULL), VIREO_RESULT_INVALID_ARGUMENT);
    EXPECT(vireo_acceptor_set_read_enabled(f.owner, true, &error), VIREO_RESULT_NOT_FOUND);
    check_clear(&error);
    EXPECT(vireo_acceptor_detach(f.owner, NULL), VIREO_OK);
    EXPECT(vireo_acceptor_forget_destroyed_loop(f.owner, NULL), VIREO_OK);
    CHECK(f.adds == 0 && f.mods == 0 && f.dels == 0);
    EXPECT(vireo_acceptor_attach(f.owner, loop, false, notification, NULL, NULL), VIREO_OK);
    EXPECT(vireo_acceptor_attach(f.owner, loop, true, notification, &f, &error), VIREO_RESULT_BUSY);
    check_clear(&error);
    vireo_acceptor_t *original = f.owner;
    EXPECT(vireo_acceptor_destroy(&f.owner, NULL), VIREO_RESULT_BUSY);
    CHECK(f.owner == original && f.adds == 1 && f.closes == 0 && f.frees == 0);
    check_state(&f, true, false, false);
    EXPECT(vireo_acceptor_detach(f.owner, NULL), VIREO_OK);
    fixture_destroy(&f);
    EXPECT(vireo_event_loop_destroy(&loop, NULL), VIREO_OK);
}

static void test_registration_capacity(void)
{
    ++groups;
    fixture_t first, second;
    fixture_init(&first, AF_INET, true);
    fixture_init(&second, AF_UNIX, true);
    vireo_event_loop_t *loop = make_loop(1);
    EXPECT(vireo_acceptor_attach(first.owner, loop, false, notification, &first, NULL), VIREO_OK);
    vireo_acceptor_loop_error_t error;
    EXPECT(vireo_acceptor_attach(second.owner, loop, false, notification, &second, &error),
           VIREO_RESULT_BUSY);
    CHECK(error.stage == VIREO_ACCEPTOR_LOOP_STAGE_ATTACH);
    CHECK(error.loop_error.stage == VIREO_EVENT_LOOP_STAGE_NONE);
    check_state(&second, false, false, false);
    vireo_event_loop_info_t info;
    EXPECT(vireo_event_loop_inspect(loop, &info), VIREO_OK);
    CHECK(info.registered_count == 1 && info.available_count == 0);
    EXPECT(vireo_acceptor_detach(first.owner, NULL), VIREO_OK);
    EXPECT(vireo_acceptor_attach(second.owner, loop, true, notification, &second, NULL), VIREO_OK);
    int const peer = connect_peer(&second);
    CHECK(run_once(loop, 1000).dispatched_count == 1 && second.callbacks == 1);
    CHECK(close(peer) == 0);
    EXPECT(vireo_acceptor_detach(second.owner, NULL), VIREO_OK);
    fixture_destroy(&first);
    fixture_destroy(&second);
    EXPECT(vireo_event_loop_destroy(&loop, NULL), VIREO_OK);
}

static void check_original(vireo_acceptor_loop_error_t const *error,
    vireo_acceptor_loop_stage_t stage, vireo_event_loop_stage_t loop_stage,
    vireo_epoll_stage_t epoll_stage)
{
    CHECK(error->stage == stage && error->loop_error.stage == loop_stage);
    CHECK(error->loop_error.epoll_error.stage == epoll_stage);
    CHECK(error->loop_error.epoll_error.system_errno == EINTR);
    CHECK(error->loop_error.system_errno == 0);
}

static void test_dependency_failures(void)
{
    ++groups;
    fixture_t f;
    fixture_init(&f, AF_INET, true);
    vireo_event_loop_t *loop = make_loop(1);
    vireo_acceptor_loop_error_t error;
    f.fail_add = VIREO_RESULT_IO;
    EXPECT(vireo_acceptor_attach(f.owner, loop, true, notification, &f, &error), VIREO_RESULT_IO);
    check_original(&error, VIREO_ACCEPTOR_LOOP_STAGE_ATTACH,
                   VIREO_EVENT_LOOP_STAGE_ADD, VIREO_EPOLL_STAGE_ADD);
    CHECK(f.adds == 1);
    check_state(&f, false, false, false);
    f.fail_add = VIREO_RESULT_OVERFLOW;
    EXPECT(vireo_acceptor_attach(f.owner, loop, false, notification, &f, NULL),
           VIREO_RESULT_OVERFLOW);
    CHECK(f.adds == 2);
    f.fail_add = VIREO_OK;
    EXPECT(vireo_acceptor_attach(f.owner, loop, false, notification, &f, &error), VIREO_OK);
    check_clear(&error);
    f.fail_mod = VIREO_RESULT_IO;
    EXPECT(vireo_acceptor_set_read_enabled(f.owner, true, &error), VIREO_RESULT_IO);
    check_original(&error, VIREO_ACCEPTOR_LOOP_STAGE_UPDATE,
                   VIREO_EVENT_LOOP_STAGE_MOD, VIREO_EPOLL_STAGE_MOD);
    check_state(&f, true, false, false);
    CHECK(f.mods == 1 && f.last_interests == 0);
    int const peer = connect_peer(&f);
    CHECK(run_once(loop, 0).dispatched_count == 0);
    f.fail_mod = VIREO_OK;
    EXPECT(vireo_acceptor_set_read_enabled(f.owner, true, NULL), VIREO_OK);
    f.fail_mod = VIREO_RESULT_IO;
    EXPECT(vireo_acceptor_set_read_enabled(f.owner, false, NULL), VIREO_RESULT_IO);
    CHECK(f.mods == 3 && f.last_interests == VIREO_EPOLL_INTEREST_READ);
    check_state(&f, true, false, true);
    f.fail_del = VIREO_RESULT_IO;
    EXPECT(vireo_acceptor_detach(f.owner, &error), VIREO_RESULT_IO);
    check_original(&error, VIREO_ACCEPTOR_LOOP_STAGE_DETACH,
                   VIREO_EVENT_LOOP_STAGE_DEL, VIREO_EPOLL_STAGE_DEL);
    CHECK(f.dels == 1 && f.closes == 0 && f.frees == 0);
    EXPECT(vireo_acceptor_destroy(&f.owner, NULL), VIREO_RESULT_BUSY);
    /* 失败 DEL 后原身份/代码/context 仍有效，真实事件仍分发。 */
    CHECK(run_once(loop, 1000).dispatched_count == 1 && f.callbacks == 1);
    f.fail_del = VIREO_OK;
    EXPECT(vireo_acceptor_detach(f.owner, &error), VIREO_OK);
    CHECK(f.dels == 2 && f.allocations == 1);
    check_clear(&error);
    CHECK(close(peer) == 0);
    fixture_destroy(&f);
    EXPECT(vireo_event_loop_destroy(&loop, NULL), VIREO_OK);
}

static void test_forget_actual_destroyed_loop(void)
{
    ++groups;
    fixture_t f;
    fixture_init(&f, AF_INET, true);
    vireo_event_loop_t *loop = make_loop(1);
    EXPECT(vireo_acceptor_attach(f.owner, loop, true, notification, &f, NULL), VIREO_OK);
    f.fail_del = VIREO_RESULT_IO;
    EXPECT(vireo_acceptor_detach(f.owner, NULL), VIREO_RESULT_IO);
    EXPECT(vireo_event_loop_request_stop(loop, NULL), VIREO_OK);
    EXPECT(vireo_event_loop_run(loop, NULL), VIREO_OK);
    /* stop/运行返回仍绑定；直到真正消费 loop 才满足 forget 前置。 */
    check_state(&f, true, false, true);
    EXPECT(vireo_acceptor_destroy(&f.owner, NULL), VIREO_RESULT_BUSY);
    EXPECT(vireo_event_loop_destroy(&loop, NULL), VIREO_OK);
    CHECK(loop == NULL);
    check_state(&f, true, false, true);
    EXPECT(vireo_acceptor_destroy(&f.owner, NULL), VIREO_RESULT_BUSY);
    unsigned const dels = f.dels;
    vireo_acceptor_loop_error_t error;
    EXPECT(vireo_acceptor_forget_destroyed_loop(f.owner, &error), VIREO_OK);
    check_clear(&error);
    CHECK(f.dels == dels && f.mods == 0 && f.closes == 0 && f.frees == 0);
    check_state(&f, false, false, false);
    EXPECT(vireo_acceptor_forget_destroyed_loop(f.owner, NULL), VIREO_OK);
    int const peer = connect_peer(&f);
    accept_one(&f);
    CHECK(close(peer) == 0);
    loop = make_loop(1);
    f.fail_del = VIREO_OK;
    EXPECT(vireo_acceptor_attach(f.owner, loop, false, notification, &f, NULL), VIREO_OK);
    EXPECT(vireo_acceptor_detach(f.owner, NULL), VIREO_OK);
    fixture_destroy(&f);
    EXPECT(vireo_event_loop_destroy(&loop, NULL), VIREO_OK);
}

typedef struct stale_context {
    fixture_t *f;
    struct stale_context *other;
    vireo_event_loop_t *loop;
    bool *rewired;
} stale_context_t;

/* 不依赖两个 listener 的原生返回顺序：第一个重登记另一个。 */
static void stale_callback(vireo_acceptor_t *acceptor, uint32_t events, void *context)
{
    stale_context_t *c = context;
    CHECK(acceptor == c->f->owner && (events & VIREO_EPOLL_EVENT_READ) != 0);
    ++c->f->callbacks;
    check_state(c->f, true, true, true);
    if (!*c->rewired) {
        *c->rewired = true;
        fixture_t *other = c->other->f;
        EXPECT(vireo_acceptor_detach(other->owner, NULL), VIREO_OK);
        EXPECT(vireo_acceptor_attach(other->owner, c->loop, true,
                                     stale_callback, c->other, NULL), VIREO_OK);
    }
    accept_one(c->f);
}

static void test_same_batch_stale_registration(void)
{
    ++groups;
    fixture_t first, second;
    fixture_init(&first, AF_INET, true);
    fixture_init(&second, AF_UNIX, true);
    vireo_event_loop_t *loop = make_loop(2);
    bool rewired = false;
    stale_context_t a = {&first, NULL, loop, &rewired};
    stale_context_t b = {&second, &a, loop, &rewired};
    a.other = &b;
    EXPECT(vireo_acceptor_attach(first.owner, loop, true, stale_callback, &a, NULL), VIREO_OK);
    EXPECT(vireo_acceptor_attach(second.owner, loop, true, stale_callback, &b, NULL), VIREO_OK);
    int const peer_a = connect_peer(&first);
    int const peer_b = connect_peer(&second);
    vireo_event_loop_run_info_t stats = run_once(loop, 1000);
    CHECK(rewired && stats.ready_count == 2 && stats.dispatched_count == 1);
    CHECK(stats.stale_count == 1 && stats.filtered_count == 0);
    CHECK(first.callbacks + second.callbacks == 1);
    stats = run_once(loop, 1000);
    CHECK(stats.ready_count == 1 && stats.dispatched_count == 1 && stats.stale_count == 0);
    CHECK(first.callbacks == 1 && second.callbacks == 1);
    CHECK(first.adds + second.adds == 3 && first.dels + second.dels == 1);
    EXPECT(vireo_acceptor_detach(first.owner, NULL), VIREO_OK);
    EXPECT(vireo_acceptor_detach(second.owner, NULL), VIREO_OK);
    CHECK(close(peer_a) == 0 && close(peer_b) == 0);
    fixture_destroy(&first);
    fixture_destroy(&second);
    EXPECT(vireo_event_loop_destroy(&loop, NULL), VIREO_OK);
}

static void exceptional_notification(vireo_acceptor_t *acceptor, uint32_t events, void *context)
{
    fixture_t *f = context;
    CHECK(acceptor == f->owner);
    check_state(f, true, true, false);
    ++f->callbacks;
    f->events = events;
}

static void test_adapter_exceptional_events(void)
{
    ++groups;
    fixture_t f;
    fixture_init(&f, AF_INET, true);
    vireo_event_loop_t *loop = make_loop(1);
    EXPECT(vireo_acceptor_attach(f.owner, loop, false, exceptional_notification, &f, NULL),
           VIREO_OK);
    /* 模拟已由 loop 过滤的异常通知；不声称内核 listener 真实触发此组合。 */
    uint32_t const events = VIREO_EPOLL_EVENT_ERROR | VIREO_EPOLL_EVENT_HANGUP;
    errno = E2BIG;
    f.registration.callback(loop, f.handle, f.listener, events, f.registration.context);
    CHECK(f.callbacks == 1 && f.events == events);
    check_state(&f, true, false, false);
    EXPECT(vireo_acceptor_detach(f.owner, NULL), VIREO_OK);
    fixture_destroy(&f);
    EXPECT(vireo_event_loop_destroy(&loop, NULL), VIREO_OK);
}

static void test_independent_cycles(void)
{
    ++groups;
    fixture_t first, second;
    fixture_init(&first, AF_INET, true);
    fixture_init(&second, AF_UNIX, true);
    vireo_event_loop_t *loop_a = make_loop(1);
    vireo_event_loop_t *loop_b = make_loop(1);
    for (unsigned i = 0; i < 32; ++i) {
        EXPECT(vireo_acceptor_attach(first.owner, loop_a, true, notification, &first, NULL), VIREO_OK);
        EXPECT(vireo_acceptor_attach(second.owner, loop_b, true, notification, &second, NULL), VIREO_OK);
        int const peer_a = connect_peer(&first);
        int const peer_b = connect_peer(&second);
        CHECK(run_once(loop_a, 1000).dispatched_count == 1);
        CHECK(run_once(loop_b, 1000).dispatched_count == 1);
        EXPECT(vireo_acceptor_set_read_enabled(first.owner, false, NULL), VIREO_OK);
        EXPECT(vireo_acceptor_set_read_enabled(second.owner, false, NULL), VIREO_OK);
        EXPECT(vireo_acceptor_detach(first.owner, NULL), VIREO_OK);
        EXPECT(vireo_acceptor_detach(second.owner, NULL), VIREO_OK);
        CHECK(close(peer_a) == 0 && close(peer_b) == 0);
    }
    CHECK(first.callbacks == 32 && second.callbacks == 32);
    CHECK(first.adds == 32 && first.mods == 32 && first.dels == 32);
    CHECK(second.adds == 32 && second.mods == 32 && second.dels == 32);
    CHECK(first.allocations == 1 && second.allocations == 1);
    CHECK(first.frees == 0 && second.frees == 0 && first.closes == 0 && second.closes == 0);
    fixture_destroy(&first);
    fixture_destroy(&second);
    EXPECT(vireo_event_loop_destroy(&loop_a, NULL), VIREO_OK);
    EXPECT(vireo_event_loop_destroy(&loop_b, NULL), VIREO_OK);
}

int main(void)
{
    unsigned const before = fd_count();
    test_native(AF_INET);
    test_native(AF_UNIX);
    test_pause_and_strict_mod();
    test_callback_lifetime();
    test_argument_and_bound_rejection();
    test_registration_capacity();
    test_dependency_failures();
    test_forget_actual_destroyed_loop();
    test_same_batch_stale_registration();
    test_adapter_exceptional_events();
    test_independent_cycles();
    unsigned const after = fd_count();
    CHECK(before == after);
    printf("acceptor loop binding: %u groups, %u failures, fd %u -> %u\n",
           groups, failures, before, after);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
